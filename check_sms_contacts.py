from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

apk = APK(r'c:\Users\x\Documents\trae_projects\apk\Stream0520.apk')
permissions = [p.lower() for p in apk.get_permissions()]

checks = ['read_contacts', 'write_contacts', 'read_sms', 'send_sms', 'receive_sms',
          'camera', 'record_audio', 'read_call_log', 'read_calendar',
          'body_sensors', 'activity_recognition']

print('=== 敏感权限声明检查 ===')
for c in checks:
    found = any(c in p for p in permissions)
    print(f'  {c:25s}: {"已声明" if found else "未声明"}')

print()
print('=== 全部已声明权限 ===')
for p in sorted(apk.get_permissions()):
    print(f'  {p}')

# Check ContentProvider queries for contacts/sms URIs
print()
print('=== ContentProvider 查询检查 ===')
dex_path = r'c:\Users\x\Documents\trae_projects\apk\stream_unpacked\classes.dex'
with open(dex_path, 'rb') as f:
    dex = DEX(f.read())

analysis = Analysis(dex)

content_uris = ['content://sms', 'content://mms', 'content://contacts',
                'content://com.android.contacts', 'content://call_log',
                'content://calendar']

for cls in dex.get_classes():
    for method in cls.get_methods():
        code = method.get_code()
        if code:
            for instr in code.get_bc().get_instructions():
                output = str(instr.get_output())
                for uri in content_uris:
                    if uri in output.lower():
                        print(f'  [ALERT] {cls.get_name()} -> {method.get_name()}: {output.strip()[:150]}')

# Check for getContentResolver + query pattern
print()
print('=== getContentResolver 调用检查 ===')
for cls in dex.get_classes():
    for method in cls.get_methods():
        code = method.get_code()
        if code:
            instructions = list(code.get_bc().get_instructions())
            for i, instr in enumerate(instructions):
                output = str(instr.get_output())
                if 'getContentResolver' in output:
                    ctx = []
                    for j in range(max(0,i-3), min(len(instructions), i+5)):
                        ctx.append(str(instructions[j].get_output()))
                    print(f'  {cls.get_name()} -> {method.get_name()}:')
                    for line in ctx:
                        print(f'    {line.strip()[:120]}')
                    print()

# Check Kuaishou weapon module for contacts
print('=== 快手 weapon 模块 READ_CONTACTS 上下文 ===')
for cls in dex.get_classes():
    if 'kuaishou/weapon' in cls.get_name().lower() and 'h1' in cls.get_name():
        for method in cls.get_methods():
            code = method.get_code()
            if code:
                for instr in code.get_bc().get_instructions():
                    output = str(instr.get_output())
                    if 'contact' in output.lower() or 'read_contacts' in output.lower():
                        print(f'  {method.get_name()}: {output.strip()[:150]}')