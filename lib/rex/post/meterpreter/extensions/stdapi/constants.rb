# frozen_string_literal: true
# -*- coding: binary -*-

###
#
# Windows Specific Constants
# --------------------------
#
# These are put into the global namespace for now
# so that they can be referenced globally.
#
###

##
#
# Net
#
##
AF_INET = 2
AF_INET6 = 23

##
#
# Permissions
#
##
DELETE                   = 0x00010000
READ_CONTROL             = 0x00020000
WRITE_DAC                = 0x00040000
WRITE_OWNER              = 0x00080000
SYNCHRONIZE              = 0x00100000
STANDARD_RIGHTS_REQUIRED = 0x000f0000
STANDARD_RIGHTS_READ     = READ_CONTROL
STANDARD_RIGHTS_WRITE    = READ_CONTROL
STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
STANDARD_RIGHTS_ALL      = 0x001f0000
SPECIFIC_RIGHTS_ALL      = 0x0000ffff
MAXIMUM_ALLOWED          = 0x02000000
GENERIC_READ             = 0x80000000
GENERIC_WRITE            = 0x40000000
GENERIC_EXECUTE          = 0x20000000
GENERIC_ALL              = 0x10000000

##
#
# Page Protections
#
##
PAGE_NOACCESS            = 0x00000001
PAGE_READONLY            = 0x00000002
PAGE_READWRITE           = 0x00000004
PAGE_WRITECOPY           = 0x00000008
PAGE_EXECUTE             = 0x00000010
PAGE_EXECUTE_READ        = 0x00000020
PAGE_EXECUTE_READWRITE   = 0x00000040
PAGE_EXECUTE_WRITECOPY   = 0x00000080
PAGE_GUARD               = 0x00000100
PAGE_NOCACHE             = 0x00000200
PAGE_WRITECOMBINE        = 0x00000400
MEM_COMMIT               = 0x00001000
MEM_RESERVE              = 0x00002000
MEM_DECOMMIT             = 0x00004000
MEM_RELEASE              = 0x00008000
MEM_FREE                 = 0x00010000
MEM_PRIVATE              = 0x00020000
MEM_MAPPED               = 0x00040000
MEM_RESET                = 0x00080000
MEM_TOP_DOWN             = 0x00100000
MEM_WRITE_WATCH          = 0x00200000
MEM_PHYSICAL             = 0x00400000
MEM_LARGE_PAGES          = 0x20000000
MEM_4MB_PAGES            = 0x80000000
SEC_FILE                 = 0x00800000
SEC_IMAGE                = 0x01000000
SEC_RESERVE              = 0x04000000
SEC_COMMIT               = 0x08000000
SEC_NOCACHE              = 0x10000000
MEM_IMAGE                = SEC_IMAGE

##
#
# Registry Permissions
#
##
KEY_QUERY_VALUE          = 0x00000001
KEY_SET_VALUE            = 0x00000002
KEY_CREATE_SUB_KEY       = 0x00000004
KEY_ENUMERATE_SUB_KEYS   = 0x00000008
KEY_NOTIFY               = 0x00000010
KEY_CREATE_LINK          = 0x00000020
KEY_WOW64_64KEY          = 0x00000100
KEY_WOW64_32KEY          = 0x00000200
KEY_READ                 = (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE |
              KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY) & ~SYNCHRONIZE
KEY_WRITE                = (STANDARD_RIGHTS_WRITE | KEY_SET_VALUE |
              KEY_CREATE_SUB_KEY) & ~SYNCHRONIZE
KEY_EXECUTE              = KEY_READ
KEY_ALL_ACCESS           = (STANDARD_RIGHTS_ALL | KEY_QUERY_VALUE |
              KEY_SET_VALUE | KEY_CREATE_SUB_KEY |
              KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY |
              KEY_CREATE_LINK) & ~SYNCHRONIZE

##
#
# Registry
#
##
HKEY_CLASSES_ROOT        = 0x80000000
HKEY_CURRENT_USER        = 0x80000001
HKEY_LOCAL_MACHINE       = 0x80000002
HKEY_USERS               = 0x80000003
HKEY_PERFORMANCE_DATA    = 0x80000004
HKEY_CURRENT_CONFIG      = 0x80000005
HKEY_DYN_DATA            = 0x80000006

REG_NONE                 = 0
REG_SZ                   = 1
REG_EXPAND_SZ            = 2
REG_BINARY               = 3
REG_DWORD                = 4
REG_DWORD_LITTLE_ENDIAN  = 4
REG_DWORD_BIG_ENDIAN     = 5
REG_LINK                 = 6
REG_MULTI_SZ             = 7

##
#
# Process Permissions
#
##
PROCESS_TERMINATE        = 0x00000001
PROCESS_CREATE_THREAD    = 0x00000002
PROCESS_SET_SESSIONID    = 0x00000004
PROCESS_VM_OPERATION     = 0x00000008
PROCESS_VM_READ          = 0x00000010
PROCESS_VM_WRITE         = 0x00000020
PROCESS_DUP_HANDLE       = 0x00000040
PROCESS_CREATE_PROCESS   = 0x00000080
PROCESS_SET_QUOTA        = 0x00000100
PROCESS_SET_INFORMATION  = 0x00000200
PROCESS_QUERY_INFORMATION = 0x00000400
PROCESS_SUSPEND_RESUME   = 0x00000800
PROCESS_ALL_ACCESS       = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF

##
#
# Thread Permissions
#
##
THREAD_TERMINATE            = 0x00000001
THREAD_SUSPEND_RESUME       = 0x00000002
THREAD_GET_CONTEXT          = 0x00000008
THREAD_SET_CONTEXT          = 0x00000010
THREAD_SET_INFORMATION      = 0x00000020
THREAD_QUERY_INFORMATION    = 0x00000040
THREAD_SET_THREAD_TOKEN     = 0x00000080
THREAD_IMPERSONATE          = 0x00000100
THREAD_DIRECT_IMPERSONATION = 0x00000200
THREAD_ALL_ACCESS           = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF

##
#
# Creation flags
#
##

CREATE_SUSPENDED            = 0x00000004

##
#
# Event Log
#
##
EVENTLOG_SEQUENTIAL_READ    = 0x00000001
EVENTLOG_SEEK_READ          = 0x00000002
EVENTLOG_FORWARDS_READ      = 0x00000004
EVENTLOG_BACKWARDS_READ     = 0x00000008

##
#
# Event Log
#
##
EWX_LOGOFF                  = 0
EWX_SHUTDOWN                = 0x00000001
EWX_REBOOT                  = 0x00000002
EWX_FORCE                   = 0x00000004
EWX_POWEROFF                = 0x00000008
EWX_FORCEIFHUNG             = 0x00000010

##
#
# Shutdown Reason Codes
#
##
SHTDN_REASON_MINOR_DC_PROMOTION             = 0x00000021
SHTDN_REASON_MAJOR_APPLICATION              = 0x00040000
SHTDN_REASON_MAJOR_HARDWARE                 = 0x00010000
SHTDN_REASON_FLAG_COMMENT_REQUIRED          = 0x01000000
SHTDN_REASON_FLAG_DIRTY_UI                  = 0x08000000
SHTDN_REASON_MINOR_UNSTABLE                 = 0x00000006
SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL    = 0x00000018
SHTDN_REASON_MINOR_ENVIRONMENT              = 0x00000000
SHTDN_REASON_MAJOR_LEGACY_API               = 0x00070000
SHTDN_REASON_MINOR_DC_DEMOTION              = 0x00000022
SHTDN_REASON_MINOR_SECURITYFIX              = 0x00000012
SHTDN_REASON_FLAG_CLEAN_UI                  = 0x04000000
SHTDN_REASON_MINOR_HOTFIX                   = 0x00000011
SHTDN_REASON_MINOR_CORDUNPLUGGED            = 0x00000000
SHTDN_REASON_MINOR_HOTFIX_UNINSTALL         = 0x00000017
SHTDN_REASON_FLAG_USER_DEFINED              = 0x40000000
SHTDN_REASON_MINOR_SYSTEMRESTORE            = 0x00000001
SHTDN_REASON_MINOR_OTHERDRIVER              = 0x00000000
SHTDN_REASON_MINOR_WMI                      = 0x00000015
SHTDN_REASON_MINOR_INSTALLATION             = 0x00000002
SHTDN_REASON_MINOR_BLUESCREEN               = 0x0000000F
SHTDN_REASON_MAJOR_SOFTWARE                 = 0x00030000
SHTDN_REASON_MINOR_NETWORKCARD              = 0x00000009
SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL    = 0x00000016
SHTDN_REASON_MINOR_SERVICEPACK              = 0x00000010
SHTDN_REASON_MINOR_UPGRADE                  = 0x00000003
SHTDN_REASON_FLAG_PLANNED                   = 0x80000000
SHTDN_REASON_MINOR_MMC                      = 0x00000019
SHTDN_REASON_MINOR_POWER_SUPPLY             = 0x00000000
SHTDN_REASON_MINOR_MAINTENANCE              = 0x00000001
SHTDN_REASON_VALID_BIT_MASK                 = 0x00000000
SHTDN_REASON_MAJOR_NONE                     = 0x00000000
SHTDN_REASON_MAJOR_POWER                    = 0x00060000
SHTDN_REASON_FLAG_DIRTY_PROBLEM_ID_REQUIRED = 0x02000000
SHTDN_REASON_MINOR_OTHER                    = 0x00000000
SHTDN_REASON_MINOR_PROCESSOR                = 0x00000008
SHTDN_REASON_MAJOR_OTHER                    = 0x00000000
SHTDN_REASON_MINOR_DISK                     = 0x00000007
SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY     = 0x00000014
SHTDN_REASON_MAJOR_OPERATINGSYSTEM          = 0x00020000
SHTDN_REASON_MINOR_HUNG                     = 0x00000005
SHTDN_REASON_MINOR_TERMSRV                  = 0x00000020
SHTDN_REASON_MINOR_NONE                     = 0x00000000
SHTDN_REASON_MINOR_RECONFIG                 = 0x00000004
SHTDN_REASON_MAJOR_SYSTEM                   = 0x00050000
SHTDN_REASON_MINOR_HARDWARE_DRIVER          = 0x00000000
SHTDN_REASON_MINOR_SECURITY                 = 0x00000013
SHTDN_REASON_DEFAULT                        = SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER

##
#
# Keyboard Mappings
#
##

VirtualKeyCodes = {
  1 => %w(LClick),
  2 => %w(RClick),
  3 => %w(Cancel),
  4 => %w(MClick),
  8 => %w(Back),
  9 => %w(Tab),
  10 => %w(Newline),
  12 => %w(Clear),
  13 => %w(Return),

  16 => %w(Shift),
  17 => %w(Ctrl),
  18 => %w(Alt),
  19 => %w(Pause),
  20 => %w(CapsLock),

  27 => %w(Esc),

  32 => %w(Space),
  33 => %w(Prior),
  34 => %w(Next),
  35 => %w(End),
  36 => %w(Home),
  37 => %w(Left),
  38 => %w(Up),
  39 => %w(Right),
  40 => %w(Down),
  41 => %w(Select),
  42 => %w(Print),
  43 => %w(Execute),
  44 => %w(Snapshot),
  45 => %w(Insert),
  46 => %w(Delete),
  47 => %w(Help),
  48 => %w{0 )},
  49 => %w(1 !),
  50 => %w(2 @),
  51 => %w(3 #),
  52 => %w(4 $),
  53 => %w(5 %),
  54 => %w(6 ^),
  55 => %w(7 &),
  56 => %w(8 *),
  57 => %w{9 (},
  65 => %w(a A),
  66 => %w(b B),
  67 => %w(c C),
  68 => %w(d D),
  69 => %w(e E),
  70 => %w(f F),
  71 => %w(g G),
  72 => %w(h H),
  73 => %w(i I),
  74 => %w(j J),
  75 => %w(k K),
  76 => %w(l L),
  77 => %w(m M),
  78 => %w(n N),
  79 => %w(o O),
  80 => %w(p P),
  81 => %w(q Q),
  82 => %w(r R),
  83 => %w(s S),
  84 => %w(t T),
  85 => %w(u U),
  86 => %w(v V),
  87 => %w(w W),
  88 => %w(x X),
  89 => %w(y Y),
  90 => %w(z Z),
  91 => %w(LWin),
  92 => %w(RWin),
  93 => %w(Apps),

  95 => %w(Sleep),
  96 => %w(N0),
  97 => %w(N1),
  98 => %w(N2),
  99 => %w(N3),
  100 => %w(N4),
  101 => %w(N5),
  102 => %w(N6),
  103 => %w(N7),
  104 => %w(N8),
  105 => %w(N9),
  106 => %w(Multiply),
  107 => %w(Add),
  108 => %w(Separator),
  109 => %w(Subtract),
  110 => %w(Decimal),
  111 => %w(Divide),
  112 => %w(F1),
  113 => %w(F2),
  114 => %w(F3),
  115 => %w(F4),
  116 => %w(F5),
  117 => %w(F6),
  118 => %w(F7),
  119 => %w(F8),
  120 => %w(F9),
  121 => %w(F10),
  122 => %w(F11),
  123 => %w(F12),
  124 => %w(F13),
  125 => %w(F14),
  126 => %w(F15),
  127 => %w(F16),
  128 => %w(F17),
  129 => %w(F18),
  130 => %w(F19),
  131 => %w(F20),
  132 => %w(F21),
  133 => %w(F22),
  134 => %w(F23),
  135 => %w(F24),
  144 => %w(NumLock),
  145 => %w(Scroll),
  160 => %w(LShift),
  161 => %w(RShift),
  162 => %w(LCtrl),
  163 => %w(RCtrl),
  164 => %w(LMenu),
  165 => %w(RMenu),
  166 => %w(Back),
  167 => %w(Forward),
  168 => %w(Refresh),
  169 => %w(Stop),
  170 => %w(Search),
  171 => %w(Favorites),
  172 => %w(Home),
  176 => %w(Forward),
  177 => %w(Reverse),
  178 => %w(Stop),
  179 => %w(Play),
  186 => %w(; :),
  187 => %w(= +),
  188 => %w(, <),
  189 => %w(- _),
  190 => %w(. >),
  191 => %w(/ ?),
  192 => %W(' ~),
  219 => %w([ {),
  220 => %w(\  |),
  221 => %w(] }),
  222 => %W(' Quotes)
}.freeze
