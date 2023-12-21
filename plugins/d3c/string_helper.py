from dcim.choices import DeviceStatusChoices
from extras.models import CustomFieldChoiceSet
from .string_normalizer import StringNormalizer
from .string_checker import StringChecker
from .utils import time_start, time_end
import time


def disassebmle_role(general_role):
    """
    This function disassembles Device Roles used by a software called Asset Manager into the specific roles
    predefined during the initialization of the D3C-Plugin.
    """
    if not general_role:
        return None
    lowerCase = general_role.lower()
    if lowerCase == "io":
        return ["Sensor", "Actuator"]
    elif lowerCase == "hmi":
        return ["HMI Field", "Scada Client"]
    elif lowerCase == "gateway" or lowerCase == "ndevice":
        return ["Switch L2", "Switch L3", 'Firewall', 'Router', 'Gateway Koppler']
    elif lowerCase == "server":
        return ["Active Directory", "Server"]
    else:
        return None


def get_specific_role(current_role, general_role, add_curr_role=True):
    """
    Returns the specific roles given a general role.
    """
    result_role = disassebmle_role(general_role)
    result_list = [(0, current_role), ] if current_role else []
    if result_role:
        for idx, x in enumerate(result_role, 1):
            if idx != current_role:  # check for duplicates
                result_list.append((idx, x))
    return result_list


def check_choice(choices, value):
    value_lower = value.lower()
    for status in choices:
        if status[0] == value_lower:
            return status[0]
    return None


def router_choices(curr_value, value):
    """
    Returns the choices regarding the 'is_router' attribute based on a Device specified by a DeviceFinding.
    """
    cap_current_value = curr_value.capitalize() if curr_value else None

    result = [(0, cap_current_value)]

    if value.lower() in ['true', 'yes', 't', 'y']:
        result.append((1, 'Yes')) if curr_value != 'yes' else None
    elif value.lower() in ['false', 'no', 'f', 'n']:
        result.append((1, 'No')) if curr_value != 'no' else None
    elif value.lower() in ['maybe', 'may', 'm']:
        if curr_value == "yes":
            result.append((1, 'No'))
        elif curr_value == "no":
            result.append((1, 'Yes'))
        else:
            result.append((1, 'Yes'))
            result.append((2, 'No'))
    else:
        return None

    return result


def get_sug(rsp, string_normalizer, string_checker, device_attr, device_value, finding_value):
    """
    Controls the spell-checking and normalization step provided by the ApplyFinding Form.
    """
    if not finding_value or device_value == finding_value:
        return None

    if rsp:
        if device_attr == "Device Role":
            roles = get_specific_role(device_value, finding_value)
            if len(roles) > 1:
                return roles

        if device_attr == "Device Status":
            status = check_choice(DeviceStatusChoices.CHOICES, finding_value)
            return [(0, device_value), (1, status)] if status and status != device_value else None

        if device_attr == "Device Exposure":
            try:
                choice_set = CustomFieldChoiceSet.objects.get(name='d3c_exposure choices')
                exposure = check_choice(choice_set.choices, finding_value)
                return [(0, device_value), (1, exposure)] if exposure and exposure != device_value else None
            except Exception as e:
                return None

        if device_attr == "Router":
            is_router = router_choices(device_value, finding_value)
            return is_router if len(is_router) > 1 else None

        result_normalizer = string_normalizer.normalize(finding_value, device_attr)

        if result_normalizer:
            return [(0, device_value), (1, result_normalizer)] if result_normalizer != device_value else None
        elif string_checker:
            result_checker = string_checker.check_candidates(finding_value, 'all')
            if result_checker:
                result_list = [(0, device_value), ]
                for idx, x in enumerate(result_checker, 1):
                    if device_value != x:
                        result_list.append((idx, x))

                if len(result_list) == 1:
                    result_list = None

                return result_list
            else:
                return [(0, device_value), (1, finding_value)]

    return [(0, device_value), (1, str(finding_value))]


def init_spell_checker(corpus, special_character, whitespace):
    """ Initialization of the spell checker module. """
    return StringChecker(corpus_cols_to_use=corpus,
                         corpus_cols_spell_split=special_character,
                         corpus_cols_whitespace_split=whitespace)


