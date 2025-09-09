import re, time
from defusedxml import ElementTree as ET
from django.core.exceptions import ValidationError
from netaddr import valid_mac, valid_ipv4, IPNetwork, AddrFormatError
from .string_checker import StringChecker
import re
from .uri_validate import URI


def parse_nmap(data):
    records = []
    headers = {}

    tree = ET.fromstring(data)
    tables = tree.findall("./prescript/script/table[@key='devices']/table")
    if tables:
        # we have a type-1 table
        for table in tables:
            record = {}
            elements = table.findall("./elem")
            parseElems(elements, headers, record)
            if record:
                records.append(record)
        return headers, records
    hosts = tree.findall("./host")
    if hosts:
        for host in hosts:
            recordCommon = {}
            addresses = host.findall("./address")
            for address in addresses:
                fieldName = 'address_' + address.get('addrtype')
                fieldValue = address.get('addr')
                addField(recordCommon, headers, fieldName, fieldValue)
            ports = host.findall('./ports/port')
            for port in ports:
                record = recordCommon.copy()
                addField(record, headers, 'portid', port.get('portid'))
                elements = port.findall("./script/elem")
                parseElems(elements, headers, record)
                elements = port.findall("./script/table/elem")
                parseElems(elements, headers, record)
                if record:
                    records.append(record)
        return headers, records


def parseElems(elements, headers, record):
    for element in elements:
        fieldName = element.get('key')
        fieldValue = element.text.strip()
        addField(record, headers, fieldName, fieldValue)


def addField(record, headers, fieldName, fieldValue):
    if not fieldName in headers:
        headers[fieldName] = len(headers)
    record[fieldName] = fieldValue


def parse_csv(reader):
    records = []
    headers = {}

    headerNr = 0
    for header in next(reader):
        header = header.strip()
        if header in headers:
            raise ValidationError(f'Duplicate or conflicting column header for "{header}"')
        headers[header] = headerNr
        headerNr += 1

    # Parse CSV rows into a list of dictionaries mapped from the column headers.
    for i, row in enumerate(reader, start=1):
        row = [col.strip() for col in row]
        record = dict(zip(headers.keys(), row))
        records.append(record)

    return headers, records


pattern = re.compile(r"\{([ a-zA-Z0-9_-]+)(:`([^`]+)`:`([^`]+)`(:`([^`]*)`)?)?\}")


def fillTemplate(template, context):
    if not template or len(template) == 0:
        return ""
    result = ""
    pos = 0
    length = len(template)
    match = pattern.search(template, pos)
    while match:
        span = match.span()
        idxStart = span[0]
        idxEnd = span[1]
        if idxStart > pos:
            result += template[pos:idxStart]
        columnName = match.group(1)
        data = getFromContext(context, columnName)
        subGroup = match.group(2)
        if subGroup:
            subRegex = match.group(3)
            subReplace = match.group(4)
            subIfNotFound = match.group(6)
            subMatch = re.search(subRegex, data)
            if subMatch:
                data = subMatch.expand(subReplace)
            elif subIfNotFound is not None:
                if subIfNotFound != '\\0':
                    data = subIfNotFound
            else:
                raise Exception('Regex "' + subRegex + '" found no matches in ' + columnName + ' ("' + data + '")')
        result += data
        pos = idxEnd
        match = pattern.search(template, pos)
    if length > pos:
        result += template[pos:]
    return result


def getFromContext(context, key):
    data = context.get(key)
    if not data:
        return ""
    return data


def get_ip(ip, netmask=24):
    if ip and valid_ipv4(ip):
        return f"{ip}/{netmask}"
    return None


def parse_ip(ip):
    try:
        parsed_ip = IPNetwork(ip)
        if parsed_ip.version != 4:
            parsed_ip = None
        return parsed_ip
    except AddrFormatError as e:
        return None



def get_mac(value):
    if value and valid_mac(value):
        return value
    return None


_TIMER_STACK = []
def time_start(name):
    _TIMER_STACK.append((name, time.time()))
def time_end():
    record = _TIMER_STACK.pop()
    name = record[0]
    start = record[1]
    end = time.time()
    duration = int(1000 * (end - start))
    indent = '  ' * len(_TIMER_STACK)
    print(f"{indent}  {name}: {duration} ms")


def validate_cpe(value):
    try:
        if value and len(value) >= 5:
            cpe_pattern = "^(cpe:2\\.3:[aho\\*\\-](:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#\\$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|\\}~]))+(\\?*|\\*?))|[\\*\\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!\"#\\$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^`\\{\\|\\}~]))+(\\?*|\\*?))|[\\*\\-])){4})|([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\\._\\-~%]*){0,6})$"
            if not re.match(cpe_pattern, value):
                raise ValidationError(f"Is not a valid CPE value")
    except re.error as e:
        raise ValidationError(f"Is not a valid regular expression.")


def validate_purl(value):
    try:
        if value and len(value) >= 7:
            purl_pattern = "^pkg:[A-Za-z\\.\\-\\+][A-Za-z0-9\\.\\-\\+]*/.+"
            if not re.match(purl_pattern, value):
                raise ValidationError(f"Is not a valid PURL value")
    except re.error as e:
        raise ValidationError(f"Is not a valid regular expression.")


def validate_fh(value):
    try:
        if value:
            hex_pattern = "^[0-9a-fA-F]{32,}$"
            if not re.match(hex_pattern, value):
                raise ValidationError(f"Is not a valid hexadecimal representation")
    except re.error as e:
        raise ValidationError(f"Is not a valid regular expression.")


def validate_uri(value):
    try:
        if value:
            if not re.match("^%s$" % URI, value, re.VERBOSE):
                raise ValidationError(f"Is not a valid URI")
    except re.error as e:
        raise ValidationError(f"Is not a valid regular expression.")

