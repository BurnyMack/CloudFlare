import requests


class CloudFlare:

    def list_ruleset_id(url, zone_id, api_token):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        results = {}
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                for x in r.json()["result"]:
                    results[x["id"]] = x
                return results
            else:
                print(r.status_code, r.url, r.text, sep="\n")
        except Exception as e:
            print("An error has occurred: ", e, r.text, r.status_code, sep="\n")

    def list_rules(url, zone_id, api_token):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        results = {}
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                for x in r.json()["result"]["rules"]:
                    results[x["description"]] = x
                return results
            else:
                print(r.status_code, r.url, r.text, sep="\n")
        except Exception as e:
            print("An error has occurred: ", e, r.text, r.status_code, sep="\n")

    def update_rule(url, zone_id, api_token, ruleset_id, rule_id, payload):
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        try:
            r = requests.patch(url, headers=headers, json=payload)
            if r.status_code == 200:
                results = r.json()
                return results
            else:
                print(r.status_code, r.url, r.text, sep="\n")
        except Exception as e:
            print("An error has occurred: ", e, r.text, r.status_code, sep="\n")


def Main():

    # Define CONSTANTS
    ZONE_ID = "<ZONEID>"
    API_TOKEN = "<API_TOKEN>"
    BASE_ENDPOINT = f"https://api.cloudflare.com/client/v4"
    LIST_RULESET_ENDPOINT = f"/zones/{ZONE_ID}/rulesets"

    # List ALL RULESETS and get Custom RULESET ID
    RULESET_IDS = CloudFlare.list_ruleset_id(
        BASE_ENDPOINT + LIST_RULESET_ENDPOINT, ZONE_ID, API_TOKEN
    )
    for k, v in RULESET_IDS.items():
        if v["name"] == "default":
            CUSTOM_RULESET_ID = v["id"]

    # List RULES within Custom RULESETS and Get IP Blocklist Rule ID
    RULES = CloudFlare.list_rules(
        BASE_ENDPOINT + LIST_RULESET_ENDPOINT + "/" + CUSTOM_RULESET_ID,
        ZONE_ID,
        API_TOKEN,
    )
    IP_BLOCKLIST_ID = RULES["IP Block List"]["id"]

    # Update IP Blocklist
    UPDATE_RULE_ENDPOINT = (
        f"/zones/{ZONE_ID}/rulesets/{CUSTOM_RULESET_ID}/rules/{IP_BLOCKLIST_ID}"
    )
    EXPRESSION = "(ip.src eq 1.2.3.4)"
    payload = {
        "expression": EXPRESSION,
        "action": "block",
        "description": "IP Block List",
        "ref": IP_BLOCKLIST_ID,
        "id": IP_BLOCKLIST_ID,
        "enabled": True,
    }

    block_ip_address = CloudFlare.update_rule(
        BASE_ENDPOINT + UPDATE_RULE_ENDPOINT,
        ZONE_ID,
        API_TOKEN,
        CUSTOM_RULESET_ID,
        IP_BLOCKLIST_ID,
        payload,
    )
    print(block_ip_address)


if __name__ == "__main__":
    Main()
