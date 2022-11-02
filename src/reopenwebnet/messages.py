TYPE_OTHER = 'OTHER'
TYPE_ACK = 'ACK'
TYPE_NACK = 'NACK'
TYPE_NORMAL = 'NORMAL' # command request or status response
TYPE_SHA1 = 'SHA1'
TYPE_SHA2 = 'SHA2'
TYPE_STATUS_REQUEST = 'STATUS_REQUEST'
TYPE_DIMENSION_REQUEST = 'DIMENSION_REQUEST'
TYPE_DIMENSION_READING = 'DIMENSION_READING'
TYPE_DIMENSION_WRITING = 'DIMENSION_WRITING'


def determine_type(tags):
    if tags == [ '#', '1' ]:
        return TYPE_ACK
    if tags == [ '#', '0' ]:
        return TYPE_NACK
    if tags == [ '98', '1' ]:
        return TYPE_SHA1
    if tags == [ '98', '2' ]:
        return TYPE_SHA2

    if len(tags) == 2:
        if tags[0][0] == '#':
            return TYPE_STATUS_REQUEST

    if len(tags) == 3:
        if not tags[0].startswith('#') and tags[1].startswith('#') and not tags[2].startswith('#'):
            return TYPE_NORMAL
        if tags[0].startswith('#') and not tags[1].startswith('#') and not tags[2].startswith('#'):
            return TYPE_DIMENSION_REQUEST

    if len(tags) > 3:
        if tags[0].startswith('#') and not tags[1].startswith('#') and tags[2].startswith('#'):
            return TYPE_DIMENSION_WRITING

    return TYPE_OTHER


class TagsMessage:
    def __init__(self, tags):
        self.tags = list(map(str, tags))
        self.value = str(self)
        self.type = determine_type(self.tags)

    def __str__(self):
        return "*" + "*".join(self.tags) + "##"

    def __eq__(self, other):
        return self.tags == other.tags

CMD_SESSION = TagsMessage(['99','9']) # OpenWeb message for opening a command session
EVENT_SESSION = TagsMessage(['99','1']) # OpenWeb message for opening an event session

ACK = TagsMessage(['#', 1])
NACK = TagsMessage(['#', 0])
SHA1 = TagsMessage([98, 1])
SHA2 = TagsMessage([98, 2])


def bad_message(data):
    raise Exception('Improperly formatted message:', data)


def parse_message(data):
    if not data.startswith("*"):
        raise Exception(f"data does not start with *: {data}")
    if not data.endswith("##"):
        raise Exception(f"data does not end with ##: {data}")

    return TagsMessage(data[1:-2].split("*"))


def parse_messages(data):
    if "##" not in data:
        return [], data

    parts = data.split("##")
    messages = list(map(lambda part: parse_message(part + '##'), parts[:-1]))

    if len(parts[-1]) == 0:
        return messages, None

    return messages, parts[-1]


def create_normal_message(who, what, where):
    return TagsMessage([who, what, where])

def create_status_request_message(who, where):
    return TagsMessage(['#%s'%(who), where])

def create_dimension_request_message(who, where, dimension):
    return TagsMessage(['#%s'%(who), where, dimension])

def create_writing_message(who, where, dimension, *args):
    return TagsMessage([who, where, dimension] + args)

