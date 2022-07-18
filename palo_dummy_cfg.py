import datetime
import sys
from panos import policies, objects, firewall, network
import random
import argparse

config_start = datetime.datetime.now()

def num_as_ip(duplicates_flag):
    if duplicates_flag:
        return ".".join(str(random.choice([10,20,30,40,50,60,70,80,90,100])) for _ in range(4))
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def tag_generator(fw, tag_max, prefix_tag):
    if tag_max <= 0:
        return
    start = datetime.datetime.now()
    original_tags = objects.Tag().refreshall(fw, add=False)
    tags = [tag.name for tag in original_tags]
    DEVICE_TAG_MAX = 10000
    if len(tags) >= DEVICE_TAG_MAX:
        print("[!] Maximum number of tag objects reached [!]")
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    elif (len(tags) + int(tag_max) > DEVICE_TAG_MAX):
        print("I can only create {} tag(s)".format(DEVICE_TAG_MAX - len(tags)))
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    bulk_tags = []
    for i in range(1, int(tag_max) + 1):
        new_tag = objects.Tag(
            "{0}{1:03}".format(prefix_tag, i), "color{}".format(random.randint(1,17))
        )
        bulk_tags.append(new_tag)
        fw.add(new_tag)
    bulk_tags[0].create_similar()
    print(
        "= Creating {0} tag object(s) took: {1}".format(
            len(bulk_tags), datetime.datetime.now() - start
        )
    )

def device_address_max(fw):
    address_max = fw.op('show system state filter "cfg.general.max-address"')[0].text.lstrip('cfg.general.max-address: ').rstrip('\n')
    if 'x' in address_max:
        address_max = int(address_max, 16)
    return address_max

def address_generator(fw, add_max, prefix_address, tags, duplicates_flag):
    if add_max <= 0:
        return
    start = datetime.datetime.now()
    original_objects = objects.AddressObject.refreshall(fw, add=False)
    oo_names = [oo.name for oo in original_objects]
    device_add_max = device_address_max(fw)
    if len(oo_names) >= int(device_add_max):
        print("[!] Maximum number of address objects reached [!]")
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    elif (len(oo_names) + int(add_max) > int(device_add_max)):
        print("I can only create {} address(es)".format(int(device_add_max) - len(oo_names)))
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    bulk_objects = []
    # If there are now Tags configured, do not add them to objects
    if len(tags) >= 1:
        for num in range(1, int(add_max)+1):
            ao = objects.AddressObject(
                "{0}{1:03}".format(prefix_address, num), num_as_ip(duplicates_flag), tag=[random.choice(tags)]
            )
            bulk_objects.append(ao)
            fw.add(ao)
    else:
        for num in range(1, int(add_max)+1):
            ao = objects.AddressObject(
                "{0}{1:03}".format(prefix_address, num), num_as_ip(duplicates_flag)
            )
            bulk_objects.append(ao)
            fw.add(ao)
    bulk_objects[0].create_similar()
    print(
        "= Creating {0} address object(s) took: {1}".format(
            len(bulk_objects), datetime.datetime.now() - start
        )
    )

def device_group_max(fw):
    group_max = fw.op('show system state filter "cfg.general.max-address-group"')[0].text.lstrip('cfg.general.max-address-group: ').rstrip('\n')
    if 'x' in group_max:
        group_max = int(group_max, 16)
    return group_max

def group_generator(fw, grp_max, prefix_group, tags):
    if grp_max <= 0:
        return
    start = datetime.datetime.now()
    original_objects4groups = objects.AddressObject.refreshall(fw, add=False)
    adresy4groups = [oo.name for oo in original_objects4groups]
    device_grp_max = device_group_max(fw)
    original_groups4groups = objects.AddressGroup.refreshall(fw, add=False)
    oo_names = [oo.name for oo in original_groups4groups]
    max_group_members = fw.op('show system state filter "cfg.general.max-address-per-group"')[0].text.lstrip('cfg.general.max-address-per-group: ').rstrip('\n')
    if 'x' in max_group_members:
        max_group_members = int(max_group_members, 16)
    mgm = 0
    if len(adresy4groups) > max_group_members:
        mgm = max_group_members
    else:
        mgm = len(adresy4groups)
    if len(oo_names) >= int(device_grp_max):
        print("[!] Maximum number of address groups reached [!]")
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    elif (len(oo_names) + int(grp_max) > int(device_grp_max)):
        print("I can only create {} group(s)".format(int(device_grp_max) - len(oo_names)))
        print("Reverting to running configuration.")
        fw.revert_to_running_configuration()
        sys.exit()
    bulk_groups = []
    # If there are now Tags configured, do not add them to objects
    if len(tags) >= 1:
        for num in range(1, int(grp_max)+1):
            ao = objects.AddressGroup(
                "{0}{1:03}".format(prefix_group, num), random.sample(adresy4groups, k=random.randint(1, mgm)), tag=[random.choice(tags)]
            )
            bulk_groups.append(ao)
            fw.add(ao)
    else:
        for num in range(1, int(grp_max)+1):
            ao = objects.AddressGroup(
                "{0}{1:03}".format(prefix_group, num), random.sample(adresy4groups, k=random.randint(1, mgm))
            )
            bulk_groups.append(ao)
            fw.add(ao)
    bulk_groups[0].create_similar()
    print(
        "= Creating {0} address group(s) took: {1}".format(
            len(bulk_groups), datetime.datetime.now() - start
        )
    )

def device_service_max(fw):
    service_max = fw.op('show system state filter "cfg.general.max-service"')[0].text.lstrip('cfg.general.max-service: ').rstrip('\n')
    if 'x' in service_max:
        service_max = int(service_max, 16)
    return service_max

def service_generator(fw, svc_max, tags):
    if svc_max <= 0:
        return
    start = datetime.datetime.now()
    device_svc_max = device_service_max(fw)
    original_services = objects.ServiceObject.refreshall(fw, add=False)
    os_names = [os.name for os in original_services]
    if len(os_names) >= int(device_svc_max):
        print("[!] Maximum number of service objects reached [!]")
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    elif (len(os_names) + int(svc_max) > int(device_svc_max)):
        print("I can only create {} service(s)".format(int(device_svc_max) - len(os_names)))
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    bulk_objects = []
    # If there are now Tags configured, do not add them to objects
    if len(tags) >= 1:
        for num in range(1, int(svc_max)+1):
            protocol = random.choice(['tcp', 'udp'])
            port = random.randint(1, 65536)
            ao = objects.ServiceObject(
                "{}_{}".format(protocol, port), 
                "{}".format(protocol),
                destination_port = "{}".format(port),
                tag=[random.choice(tags)]
                )
            if (ao.name not in os_names) and (ao.name not in [bo.name for bo in bulk_objects]):
                bulk_objects.append(ao)
                fw.add(ao)
            else:
                print("{} already exists, skipping creation of the service.".format(ao.name))
    else:
        for num in range(1, int(svc_max)+1):
            protocol = random.choice(['tcp', 'udp'])
            port = random.randint(1, 65536)
            ao = objects.ServiceObject(
                "{}_{}".format(protocol, port), 
                "{}".format(protocol),
                destination_port = "{}".format(port)
                )
            if (ao.name not in os_names) and (ao.name not in [bo.name for bo in bulk_objects]):
                bulk_objects.append(ao)
                fw.add(ao)
            else:
                print("{} already exists, skipping creation of the service.".format(ao.name))
    bulk_objects[0].create_similar()
    print(
        "= Creating {0} service object(s) took: {1}".format(
            len(bulk_objects), datetime.datetime.now() - start
        )
    )

def device_service_grp_max(fw):
    service_grp_max = fw.op('show system state filter "cfg.general.max-service-group"')[0].text.lstrip('cfg.general.max-service-group: ').rstrip('\n')
    if 'x' in service_grp_max:
        service_grp_max = int(service_grp_max, 16)
    return service_grp_max

def service_group_generator(fw, grp_max, prefix_group, tags):
    if grp_max <= 0:
        return
    start = datetime.datetime.now()
    original_services4groups = objects.ServiceObject.refreshall(fw, add=False)
    svc4group = [os.name for os in original_services4groups]
    device_service_group_max = device_service_grp_max(fw)
    original_grp_services4groups = objects.ServiceGroup.refreshall(fw, add=False)
    og_names = [og.name for og in original_grp_services4groups]
    max_svc_group_members = fw.op('show system state filter "cfg.general.max-service-per-group"')[0].text.lstrip('cfg.general.max-service-per-group: ').rstrip('\n')
    if 'x' in max_svc_group_members:
        max_svc_group_members = int(max_svc_group_members, 16)
    mgm = 0
    if len(svc4group) > max_svc_group_members:
        mgm = max_svc_group_members
    else:
        mgm = len(svc4group)
    if len(og_names) >= int(device_service_group_max):
        print("[!] Maximum number of service groups reached [!]")
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    elif (len(og_names) + int(grp_max) > int(device_service_group_max)):
        print("I can only create {} service group(s)".format(int(device_service_group_max) - len(og_names)))
        print("Reverting to running configuration.")
        fw.revert_to_running_configuration()
        sys.exit()
    bulk_svc_groups = []
    # If there are now Tags configured, do not add them to objects
    if len(tags) >= 1:
        for num in range(1, int(grp_max)+1):
            sg = objects.ServiceGroup(
                "{0}{1:03}".format(prefix_group, num), random.sample(svc4group, k=random.randint(1, mgm)), tag=[random.choice(tags)]
            )
            bulk_svc_groups.append(sg)
            fw.add(sg)
    else:
        for num in range(1, int(grp_max)+1):
            sg = objects.ServiceGroup(
            "{0}{1:03}".format(prefix_group, num), random.sample(svc4group, k=random.randint(1, mgm))
            )
            bulk_svc_groups.append(sg)
            fw.add(sg)
    bulk_svc_groups[0].create_similar()
    print(
        "= Creating {0} service group(s) took: {1}".format(
            len(bulk_svc_groups), datetime.datetime.now() - start
        )
    )

def device_rule_max(fw):
    rule_max = fw.op('show system state filter "cfg.general.max-policy-rule"')[0].text.lstrip('cfg.general.max-policy-rule: ').rstrip('\n')
    if 'x' in rule_max:
        rule_max = int(rule_max, 16)
    return int(rule_max)

def rule_generator(fw, rule_max, tags, rulebase):
    if rule_max <= 0:
        return
    start = datetime.datetime.now()
    device_sec_rule_max = device_rule_max(fw)
    security_policy = policies.SecurityRule.refreshall(rulebase, add=False)
    oo_names = [oo.name for oo in security_policy]
    if len(oo_names) >= int(device_sec_rule_max):
        print("[!] Maximum number of security rules reached [!]")
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    elif (len(oo_names) + int(rule_max) > int(device_sec_rule_max)):
        print("I can only create {} secuirty rule(s)".format(int(device_sec_rule_max) - len(oo_names)))
        print("Reverting to running configuration...")
        fw.revert_to_running_configuration()
        sys.exit()
    original_objects = objects.AddressObject.refreshall(fw, add=False)
    original_groups = objects.AddressGroup.refreshall(fw, add=False)
    original_services = objects.ServiceObject.refreshall(fw, add=False)
    adresy = [oo.name for oo in original_objects]
    for og in original_groups:
        adresy.append(og.name)
    serwisy = [os.name for os in original_services]
    nowe_rulki = []
    if len(tags) >= 1:
        for i in range(1, int(rule_max)+1):
            rule_tag = random.choice(tags)
            parametry = {
                "name": "rule{}".format(i),
                "description": "Placeholder rule number {}".format(i),
                "fromzone": "any",
                "tozone": "any",
                "source": random.sample(adresy, k=random.randint(1, 5)),
                "destination": random.sample(adresy, k=random.randint(1, 5)),
                "service": random.sample(serwisy, k=random.randint(1, 5)),
                "application": "any",
                "action": "allow",
                "log_end": True,
                "tag": rule_tag.split(),
                "group_tag": rule_tag
            }
            new_rule = policies.SecurityRule(**parametry)
            rulebase.add(new_rule)
            nowe_rulki.append(new_rule)
    else:
        for i in range(1, int(rule_max)+1):
            parametry = {
                "name": "rule{}".format(i),
                "description": "Placeholder rule number {}".format(i),
                "fromzone": "any",
                "tozone": "any",
                "source": random.sample(adresy, k=random.randint(1, 5)),
                "destination": random.sample(adresy, k=random.randint(1, 5)),
                "service": random.sample(serwisy, k=random.randint(1, 5)),
                "application": "any",
                "action": "allow",
                "log_end": True,
            }
            new_rule = policies.SecurityRule(**parametry)
            rulebase.add(new_rule)
            nowe_rulki.append(new_rule)
    nowe_rulki[0].create_similar()
    print(
        "= Creating {0} security rule(s) took: {1}".format(
            len(nowe_rulki), datetime.datetime.now() - start
        )
    )

def get_tags(fw):
    tag_objects = objects.Tag().refreshall(fw, add=False)
    return [tag.name for tag in tag_objects]

def zone_generator(fw):
    new_zone = network.Zone(**{'mode': 'layer3', 'name': 'Test_Zone_L3'})
    fw.add(new_zone)
    new_zone.create()

def zone_picker(fw):
    zones = network.Zone.refreshall(fw, add=False)
    if len(zones) < 1:
        zone_generator(fw)
        return zone_picker(fw)
    else:
        for zone in zones:
            if (zone.mode == 'layer3') or (zone.mode == 'virtual-wire'):
                flag = True
                return zone.name
        if not flag:
            zone_generator(fw)
            return zone_picker(fw)

def nat_rule_generator(fw, rule_max, tags, rulebase):
    if rule_max <=0:
        return
    start = datetime.datetime.now()
    device_nat_rule_max = fw.op('show system state filter "cfg.general.max-nat-policy-rule"')[0].text.lstrip('cfg.general.max-nat-policy-rule: ').rstrip('\n')
    if 'x' in device_nat_rule_max:
        device_nat_rule_max = int(device_nat_rule_max, 16)
    nat_policy = policies.NatRule.refreshall(rulebase, add=False)
    rule_names = [n.name for n in nat_policy]
    if len(rule_names) >= int(device_nat_rule_max):
        print("Maximum number of NAT rules reached")
        print("Reverting to running configuration.")
        fw.revert_to_running_configuration()
        sys.exit()
    elif (len(rule_names) + int(rule_max) > int(device_nat_rule_max)):
        print("I can only create {} rule(s)".format(int(device_nat_rule_max) - len(rule_names)))
        print("Reverting to running configuration.")
        fw.revert_to_running_configuration()
        sys.exit()
    original_objects = objects.AddressObject.refreshall(fw, add=False)
    original_groups = objects.AddressGroup.refreshall(fw, add=False)
    original_services = objects.ServiceObject.refreshall(fw, add=False)
    adresy = [oo.name for oo in original_objects]
    for og in original_groups:
        adresy.append(og.name)
    serwisy = [os.name for os in original_services]
    new_nat_policy = []
    zone = [zone_picker(fw)]
    if len(tags) >= 1:
        for i in range(1, int(rule_max)+1):
            rule_tag = random.choice(tags)
            parameters = {'fromzone': ['any'],
                'tozone': zone,
                'service': random.choice(serwisy),
                'source': [random.choice(adresy)],
                'destination': [random.choice(adresy)],
                'source_translation_type': 'static-ip',
                'source_translation_static_translated_address': num_as_ip(False),
                'tag': rule_tag.split(),
                'group_tag': rule_tag,
                'name': "natrule{}".format(i)}
            new_nat_rule = policies.NatRule(**parameters)
            rulebase.add(new_nat_rule)
            new_nat_policy.append(new_nat_rule)
    else:
        for i in range(1, int(rule_max)+1):
            parameters = {'fromzone': ['any'],
                'tozone': [zone_picker(fw)],
                'service': random.choice(serwisy),
                'source': [random.choice(adresy)],
                'destination': [random.choice(adresy)],
                'source_translation_type': 'static-ip',
                'source_translation_static_translated_address': num_as_ip(False),
                'name': "natrule{}".format(i)}
            new_nat_rule = policies.NatRule(**parameters)
            rulebase.add(new_nat_rule)
            new_nat_policy.append(new_nat_rule)
    new_nat_policy[0].create_similar()
    print(
        "= Creating {0} nat rule(s) took: {1}".format(
            len(new_nat_policy), datetime.datetime.now() - start
        )
    )

def main(fw, tag_max, add_max, grp_max, svc_max, svc_grp_max, rule_max, nat_rule_max,
 prefix_tag, prefix_address, prefix_group, prefix_service, commit, revert, duplicates_flag):
    if revert:
        print("[+] Reverting to running configuration...")
        fw.revert_to_running_configuration()
        return
    rulebase = policies.Rulebase()
    fw.add(rulebase)
    tag_generator(fw, tag_max, prefix_tag)
    tags = get_tags(fw)
    address_generator(fw, add_max, prefix_address, tags, duplicates_flag)
    group_generator(fw, grp_max, prefix_group, tags)
    service_generator(fw, svc_max, tags)
    service_group_generator(fw, svc_grp_max, prefix_service, tags)
    rule_generator(fw, rule_max, tags, rulebase)
    nat_rule_generator(fw, nat_rule_max, tags, rulebase)
    if commit:
        print("[+] Commit in progress...")
        fw.commit(sync=True)
        print("[+] Commit finished.")

parser = argparse.ArgumentParser(description='PAN NGFW Placeholder Configuration Generator by FirewallOps')
parser.add_argument('host', help="Provide IP address of the Palo Alto Networks firewall.")
parser.add_argument('--user', default='admin', help="Provide a username. DEFAULT is admin.")
parser.add_argument('--password', default='admin', help="Provide a password. DEFAULT is admin.")
parser.add_argument('--tag', default=16, type=int, help="Provide a number of tag objects to create. DEFAULT is 16.")
parser.add_argument('--address', default=10, type=int, help="Provide a number of address objects to create. DEFAULT is 10.")
parser.add_argument('--group', default=0, type=int, help="Provide a number of address groups to create. DEFAULT is 0.")
parser.add_argument('--service', default=0, type=int, help="Provide a number of service objects to create. DEFAULT is 0.")
parser.add_argument('--servicegroup', default=0, type=int, help="Provide a number of service groups to create. DEFAULT is 0.")
parser.add_argument('--rule', default=0, type=int, help="Provide a number of security rules to create. DEFAULT is 0.")
parser.add_argument('--natrule', default=0, type=int, help="Provide a number of nat rules to create. DEFAULT is 0.")
parser.add_argument('--prefixtag', default="Tag", help="Provide a prefix for address objects names. DEFAULT is 'Tag'.")
parser.add_argument('--prefixaddress', default="PlaceholderAddress", help="Provide a prefix for address objects names. DEFAULT is 'PlaceholderAddress'.")
parser.add_argument('--prefixgroup', default="PlaceholderGroup", help="Provide a prefix for address groups names. DEFAULT is 'PlaceholderGroup'.")
parser.add_argument('--prefixservice', default="ServiceGroup", help="Provide a prefix for Service groups names. DEFAULT is 'ServiceGroup'.")
parser.add_argument('--commit', action='store_true', help="Select if you want to commit your changes to running configuration.")
parser.add_argument('--revert', action='store_true', help="Select if you want to revert your configuration to running configuration.")
parser.add_argument('--duplicates', action='store_true', help="Select if you want to create duplicate address objects.")
args = parser.parse_args()

PREFIX = "PlaceholderAddress"
print('[+] PAN NGFW Placeholder Configuration Generator by FirewallOps.')
fw = firewall.Firewall(args.host, args.user, args.password)
main(fw, args.tag ,args.address, args.group, args.service, args.servicegroup, args.rule, args.natrule, 
args.prefixtag, args.prefixaddress, args.prefixgroup, args.prefixservice, args.commit, args.revert, args.duplicates)
print("== Creating configuration took: {} ==".format(datetime.datetime.now() - config_start))
