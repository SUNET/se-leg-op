import json
from urllib.parse import parse_qsl, urlparse

import pytest
import responses
from rq.worker import SimpleWorker

from se_leg_op.storage import OpStorageWrapper

TEST_CLIENT_ID = 'client1'
TEST_CLIENT_SECRET = 'secret'
TEST_REDIRECT_URI = 'https://client.example.com/redirect_uri'

TEST_USER_ID = '191010309845'

VETTING_RESULT_ENDPOINT = '/verisec/vetting-result'

EXTRA_CONFIG = {
    'PACKAGES': ['se_leg_op.plugins.verisec_vetting_process']
}

DEMO_RESPONSE_DATA = 'eyJ4NWMiOlsiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0VFVsS\
lJEaFVRME5CZEcxblFYZEpRa0ZuU1ZWQlRIUTFNWE5yYlVvMlIxVm1NbHByYTFOMm\
FrZFZXVEZrZUZsM1JGRlpTa3R2V2tsb2RtTk9RVkZGVEVKUlFYZG5XVTE0UTNwQlN\
rSm5UbFpDUVZsVVFXeE9SazFTU1hkRlFWbEVWbEZSU0VWM2JGUmtSemxxWVRKb2Rt\
SkhNSGhHUkVGVFFtZE9Wa0pIUlZSRGVsVXhUMVJGZUUxRE1EQlBSRUV5VFZJd2QwZ\
DNXVVJXVVZGTFJYaFNWMXBZU25Cak1sWnFTVVZhZVZwWGNHaEpSMVpLVWtOQ1FsRn\
FSVTVOUVhOSFFURlZSVU40VFVWV1IxWjZaRVJGWTAxQ2IwZEJNVlZGUVhoTlZGVnN\
Ua0pKUmxKR1ZURlJaMU5ZVG5wa1YyeDFXbmxDUkZGVVFXVkdkekI0VG5wQk1rMXFR\
WGRQUkVGNVRsUkNZVVozTUhsTlJFRXlUV3BCZDA5RVFYbE9WRUpoVFVkemVFTjZRV\
XBDWjA1V1FrRlpWRUZzVGtaTlVrbDNSVUZaUkZaUlVVaEZkMnhVWkVjNWFtRXlhSF\
ppUnpCNFNGUkJZa0puVGxaQ1FXOVVSa1phYkdOdGJIcGFWMDFuVW01S2JHRnRSV2R\
hVld4RlNVVkdRMDFSTUhkRGQxbEVWbEZSVEVWM1VsVmFXRTR3VFZKdmQwZEJXVVJX\
VVZGRVJYaEdSMk50Vm5GWlUwSnNVMVZSWjJNeWJHNWliV3gxV25wRFEwRlRTWGRFV\
VZsS1MyOWFTV2gyWTA1QlVVVkNRbEZCUkdkblJWQkJSRU5EUVZGdlEyZG5SVUpCU2\
pGTlRTOXBWelZDV0RoTVpteHFZVEZrZUU0MGEyNWpVRWd6VmpNNGEweDBXbVY1S3p\
GNmJTOTVjbGhVWVRWd1RqRmxjMjVzTVdGSGVVMHZUU3Q2T1ZaSFJuUkhNMU42V1c1\
UmNrdzVjVmd4YzBJMmVWVTBVMWxDTkVvM2JEbFRWVkpqYXpaaFVDdEtlRkYzU0hOc\
VRsUnZSRWg0VFhST1dsaFlUbGRQVUd4TlZYVjZjRkJXWTNKS1luTTNaemt4ZVRaU2\
JWQldWemhHUkRKT2IyMVlaSE5XVmtOaVJEZDRUVE0zYms1dk5VaHJjWGcyWmtKRk1\
VWjFaRTgyU0hseFVUQnFiVk1yVG1NM2RWbzBOVzVrTkc0NFRtOHdSMjAwYzFoWFdY\
QmFja0pqUmtaQ2FYTlpSa1ZVTldjemIwa3JWMFZyZDA1dmNrcERLMHhJZHk5dGFEa\
GxTVWQ2VnpZMGVGaFNRVkV6ZVRnNFpIUk9ibTlMUTJKVlRUazJPWFppTnpWTlZraH\
RPQzlqV1hSelFWUXZXRUpaYzJkeGFXUmtkakpEU1ZVMlNXcElNVFZhWkZseFR5dEV\
NVTF6UkdWWll6bEJUM1JqUTBGM1JVRkJZVTR3VFVoSmQwUm5XVVJXVWpCUVFWRklM\
MEpCVVVSQloySkJUVUYzUjBFeFZXUkZkMFZDTDNkUlEwMUJRWGRJZDFsRVZsSXdha\
0pDWjNkR2IwRlZZVzU1UzBRMU1YZEVhSHBoV0hreVoxQkRXbVpwVDJkV2RqVjNkMF\
ZuV1VSV1VqQm5Ra0Z6ZDBOVVFVaENaMVZ4UVhkUlJrTnFRV1JDWjA1V1NGRTBSVVp\
uVVZWaFVEUldTMkpLVVdGWFpqaDZkVzVpVFRJNGNDODBaMlYwZFhOM1JGRlpTa3R2\
V2tsb2RtTk9RVkZGVEVKUlFVUm5aMFZDUVV0dWFIbDZaM1JyVnpaemMwTlpRVFJWW\
jI1dVRqVjBVV1ZZUkZKUGVHNVVVVFF3VkVSUldXOUdabFZFVFVZNWN6VkZTRGRrZD\
JRM1MzVlZjelpHZVVwSVNUVnlVVEIxV0dWelNrcFROSFJIZGxkUlZHaExaR0o0U20\
5b2FHNWxkRm8yU1ZKa2JGTndVMWR4YTBSaEsxRTNTMWd3YlNzd1RGUnhibFF4ZEhW\
RFRVbHBjU3QyWTJ4eVUzcFVhSEZLUTJwMk9HSk5NVmMyUm5OcmNrYzVOWFUyZW5Ve\
lNtb3hSVE0zVlhGalFYQnNNWHB4Y2pRelVrRmxXV1ZzTmxNMGNUSm5jekpHUkdOQ2\
FXSkhTVXB2VGtsdWEwMVFRMUZhUWk5VFN5dFFSMnBqUVZsb1REWjVRakJPWWtNcmJ\
6Wk1WVFZXWm5oYU16YzBLMHR4UkdKcFpDODFTVE5XUkZkUVdESnJOelV2UWxKR01V\
dHNURkpWT0VkeFkwcFhNa3BuZFZVdlZHeEtWRUYwV1dwS04zUjFOR2xhYldaclNGW\
lpNRGhsWm1scGVsQkNSMGgyZDFVNE5IQkVRVmxWWVdZeldGZGllRW81T0QwdExTMH\
RMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0IiwiTFMwdExTMUNSVWRKVGlCRFJ\
WSlVTVVpKUTBGVVJTMHRMUzB0VFVsSlIwOUVRME5DUTBOblFYZEpRa0ZuU1ZWa2VF\
OURUVEJUYUZsSFUxSklOblZJVWsxWWFqbGlTMnRuVmpSM1JGRlpTa3R2V2tsb2RtT\
k9RVkZGVEVKUlFYZFZWRVZNVFVGclIwRXhWVVZDYUUxRFZUQlZlRVY2UVZKQ1owNV\
dRa0Z2VkVOc1dteGpiV3g2V2xkTloxRlZTWGhGYWtGUlFtZE9Wa0pCYzFSRFZWcDV\
XbGR3YUVsSFZrcFNSRVZhVFVKalIwRXhWVVZCZUUxUlZXeE9Ra2xHVW14ak0xRm5W\
VzA1ZG1SRFFrUlJWRUZsUm5jd2VFNTZRVEZOVkdONFRrUlJlVTVVU21GR2R6QjVUb\
nBCTVUxVVkzaE9SRkY1VGxSS1lVMUpSMFJOVVhOM1ExRlpSRlpSVVVkRmQwcFVVbF\
JGVTAxQ1FVZEJNVlZGUW5oTlNsVXpVblpaTW5SdllqSjRkRTFTVVhkRloxbEVWbEZ\
TYUVWM2N6Rk9WR3Q0VFZSQmRFNUVaM2RPYWtWa1RVSnpSMEV4VlVWRGFFMVZWbTFX\
ZVdGWVRteFplVUpIWTIxV2NWbFRRbXhUVlZGblVWVkplRVJVUVV4Q1owNVdRa0Z6V\
kVKR1VteGpNMUY0U0VSQllVSm5UbFpDUVUxVVJURktWRkZUUWxWU1ZrNVZTVVZzZW\
1NelZuQmliV05uVVRCRmQyZG5SV2xOUVRCSFExTnhSMU5KWWpORVVVVkNRVkZWUVV\
FMFNVSkVkMEYzWjJkRlMwRnZTVUpCVVVSVFZXaEhSRWhJY0hGb2NEbFBiVUV5Wmpo\
SWFrdElaQ3RLU2tSMFpYaHlWbEZsZEhsYWRXcGFabWxuT0ZWV05uazROVzVGWTBGM\
04wWm9NV3RGUnpsSk0wcElaUzlRVG0xQ1RDOTVPVTVoVW1KeGVYZG5VamhsZGxVd2\
JEVjNVMEpzWlhaSFpXeDZPVWdyYm1WSFZrVkdka3RyU0cxR1QzWnlOMlkzWXpWaVZ\
sZGhMMVZTZWxSdFEyWlhRVzlzUzNaWkswRjNTMnhKYTJSVVJURmxjSFJ1T0UwNU5E\
QlpSblpWVlV4Q2FFeGhSRk5hV0U1b2RuWTJSVnBVT1hjeWVGUlVORnA1U0hka09HW\
mhUR1pGZG5SSGN5c3hNMHR5UVdoMWRHRktTbGxaTmxoeE1FWnVPVkUzTVhOWUwzZz\
FWRGRrUnpWSmJsTnBSVkJaVG1kblZ6bHdVbFpyZURZeGJXUmljR2w2Tm5kaFIzTk9\
jazF2TUhkUGVWZzRMM2RtY0hSblVUZ3hRalJDVlc1TFZEZzVSak5PVDJnNVRUZGFT\
azQ1SzNOU2RGZ3dhMWRNVEZKYVUwNHJVbWN4V1hrM00wUTJPRUl3ZUVGblRVSkJRV\
WRxWjJkSVZFMUpTVUo2ZWtGUFFtZE9Wa2hST0VKQlpqaEZRa0ZOUTBGUldYZEZaMW\
xFVmxJd1ZFRlJTQzlDUVdkM1FtZEZRaTkzU1VKQlJFSlFRbWRuY2tKblJVWkNVV05\
DUVZGU1JFMUZSWGRRZDFsSlMzZFpRa0pSVlVoTlFVZEhUVEpvTUdSSVFUWk1lVGw1\
WWpJNU1Ga3lSbk5aVjBsNlRWTTFNRnBZVGpCTWJWcDVXbGR3YUZwWGJHdE1iVTUyW\
WxSdk5FNTZZek5NTWtacll6Tk5kbUl5VG5walJFRm1RbWRPVmtoVFRVVkhSRUZYWj\
BKVVMzTlBlVFZXT0U5alVHRXdOV2xvVURZNFJGYzJOMEY0TTJscVEwSjFRVmxFVmx\
Jd1owSkpSM2ROU1VkMFRVbEhjVUpuVlhGQmQxRkdRbXBEUW05RVFUUkNaMmR5UW1k\
RlJrSlJZME5CVWxsellVaFNNR05JVFRaTWVUbHFZMGhOZFdSSFZucGtRelZ0WTIxV\
2NWbFhWbkJhUXpWcVlqSXdkbGt6UW5wTU1teDFXa2RXTkV4dGFEQmlWM2QzV2tGWl\
NVdDNXVUpDVVZWSVFXZEpkMWRCZUZkV1IyaHdZM2xDYWxwWVNqQmhWMXB3V1RKR01\
GcFRRbTlaV0UxbldXMVdiR0pwUW5Cak0wNHhXbGRSWjBsSGJIVkpSMFpxV1RJNWVW\
cEhSblZaTWxWblpESnNNR0ZEUWpCaFIxVm5VbTVLYkdGdFJXZGFWV3hGU1VaU1JsV\
XhVV2RWUnpsellWZE9OVWxGVG5aaWJsSjVZakozZDFoUldVUldVakJtUWtaWmQxWk\
VRbE52UmtOblZHOWFUV0ZJVWpCalJHOTJURE5LZG1JelVtcFpWM2hvV1dwTmVFeHV\
VbXhqTTFGMVdtNUtiR0Z0Um14aFYxRjFXVEk1ZEU5cVp6Tk9lbU4yV1ZkU2VtTjVP\
V3BqYlhoNlRESmFlVnBYY0doYVYyeHJXRE5LZWxsV09YbGlNamt3V0RKT2FFeHRUb\
mxpUkVGa1FtZE9Wa2hSTkVWR1oxRlZZVzU1UzBRMU1YZEVhSHBoV0hreVoxQkRXbV\
pwVDJkV2RqVjNkMFJSV1VwTGIxcEphSFpqVGtGUlJVeENVVUZFWjJkSlFrRkhla2h\
yUld0V1JFMXhZMEVyUjFKVVFYWlhNazlYTVhSRVdtOUdiR3BOSzNjeFFYVlJlak00\
TUd0dFRXRnRRV3cwWml0SmJYY3pWWE5VTTBwb1dGQmFZVXBPVm05bWNWQkNUeTlHY\
Vc5dlR6bHRVRWxtT0dwTmVISjRUR1p0TDNBdk1tNDVTelE1VWxsM1oxSk9SSGRXZV\
ZjMU9XTXhTREJxZGtobFVIQm1ZVkowVUZNeWIzWXdaVWtyVVZOTmRtc3hOQzl3YUV\
sMkwySnJUbVFyTUU5V2NEQnhaMVJXVkZSM2QwRjJWVkZLTWxBNVkwUkxNMDlKYWpk\
SU1IWkthR2gzTjNWNE5qWm5UazFJWml0SmJrVlNjbUoxTUZOcE5YSlJaVzFUWVdaa\
FVWUlROazR3VVU1MFNsWkJZV1pTV1VSTkwwWlVUMlJRZFd4aWVHdGlhM1I1WW1wTm\
FVUlVkVW96VFhab2NVdDJOWHBEVWpodWIxbDNSVUpRVm5KbFVFRjJaelppZDJJd1N\
6RmhRMEZSYlRSSmMxZENRMHRHTkhRMmMzRnFjblpoY1M4emFsVnZLMDAyTlZSd01F\
RkxWRXR1TkVJNGJtMVVka2QyT1d4VU5GQm5jME5VZDNkWVlrbFZZMWMxY21aemJVV\
TVkMVp3VW1acFpVYzNSM2cyTW5sa1NGQnNTVkJyVkVOb1ZYcHpMMnB2YW5VNGMzbH\
JWbTV6YzBZeFdVUnhVV3huVFdFeVUzQXJhM2cxYVRkbGFXcFlNV1ZxWTBwb0szQnR\
kVkZVVVc1WWFqWnpSRXB5ZVRneFQzUnhSRTgzUkRkRWFHRlZTR1pIVEdsc2JWaDFj\
a0Z2YkhWcWJXeHNOVTFoWW1SQ1JYRXpSVFJVVkdWaWRuWTJWMU5PY0VWWmQxRXhVe\
XM0WlVVck9YTnNURzV0YUZJeVVsTk9jRmRIUkZFdmJGZDNSbTlCYzFSRGFrY3JaVG\
xtTlRkdFIxVnNiVk5sVlRaNlJWSkplR2xsUlZJM2QwMU5OMFZoY1ZkaFdXODJTbUp\
sVDJoMWMySmtWRlV2VEcxemVVRTRabHBaY0N0bmJpOUdUVGhYYkRobGFERnhhaTlI\
U1dOQlpFUkJTVTh6YXpodGNVRTVPSE5YVWpkTmVEVjJaMlJTVG1OdGNFTjBUMUY0Z\
UdscGFrTTNUVkppV1V0bFFtczBTRTkwV0hjNVpTMHRMUzB0UlU1RUlFTkZVbFJKUm\
tsRFFWUkZMUzB0TFMwPSIsIkxTMHRMUzFDUlVkSlRpQkRSVkpVU1VaSlEwRlVSUzB\
0TFMwdFRVbEpSMDE2UTBOQ1FuVm5RWGRKUWtGblNWVlFRalJ5VlhGR1JtbEhObWMy\
TjJFclkweERRa04xVkd0NFIxRjNSRkZaU2t0dldrbG9kbU5PUVZGRlRFSlJRWGRWV\
kVWTVRVRnJSMEV4VlVWQ2FFMURWVEJWZUVWNlFWSkNaMDVXUWtGdlZFTnNXbXhqYl\
d4NldsZE5aMUZWU1hoRmFrRlJRbWRPVmtKQmMxUkRWVnA1V2xkd2FFbEhWa3BTUkV\
WYVRVSmpSMEV4VlVWQmVFMVJWV3hPUWtsR1VteGpNMUZuVlcwNWRtUkRRa1JSVkVG\
bFJuY3dlRTU2UVRGTlZFRjRUa1JKTWsxRVFtRkdkekF3VG5wQk1VMVVRWGhPUkVre\
VRVUkNZVTFHUlhoRGVrRktRbWRPVmtKQldWUkJiRTVHVFZKTmQwVlJXVVJXVVZGTF\
JYZHdWMXBZU25Cak1sWnFTVVZHUTAxU1NYZEZRVmxFVmxGUlRFVjNiRWRqYlZaeFd\
WTkNiRk5WVVhoSFZFRllRbWRPVmtKQlRWUkZSa3BVVVZOQ1ZWcFlUakJKUmtwMllq\
TlJaMUV3UlhkblowbHBUVUV3UjBOVGNVZFRTV0l6UkZGRlFrRlJWVUZCTkVsRFJIZ\
EJkMmRuU1V0QmIwbERRVkZETm00MlNYWktZMDlKZVRsNU5IZzBXVnBzWTBSWlYwZE\
JUbHB1THpVNFlWRnhMeXR4THpKSlQyaGxjVWczY0daeFpqQXdSbkphYlZSR2VsaFJ\
WRWswYTI5UVZVOXdZV2RaVFVWVFJ6Wk5UR3huVnpkaGEwTnVRVE5XTldSMVJYWkhR\
a3BuUVZJMlJteGtZV2wzWkVoTmNWZENTMHhpTlhCMmIwTXlMM1ZqZWxOT2FXVXJjR\
VZwWkZGMWFpdFBhRFZOZDFWRFNsZDRORzR5Wmt4dlNrMVVVRFJNWWpGdWVFWlJXSH\
BEYWxKTlYwb3hkek53VFNzemJVUlpTbnAyVEVab1ZqSlZjamRSUWtGa1NtcEhSMUJ\
EY0hKRVpGSkZabnBoYm0wM1NtYzFiVVowWkhSaVRWQlFiMkpOVmtSTFVtbERkbVpZ\
VEdGMlJUUlZaWFZ3U2tZeVVtUm5OVE13ZEhCaFNrMWlObTBySzA5elJrMU9OSE5JY\
1RCSVZWbHBXVWwzWlhSa2JYaFpNMWN5WkhCTFNtcHRURGR3VUZCd2NtTndia2h4WT\
JrNVlUTk9NekpoYW1Oc2NGWmFOMk13YW1aMWQwTjNheXMyUlVaWlVrNXRRMnRMUld\
0TmNsTmxPSGR5T0hSMVNEUkdXWGRvVkZGRGMwWlJaVUZYVldGWGVsTnNNamxKWld4\
dGVETTRUM1FyWnpOaFZYYzRURnBzZEZwNlRWbG9ZV3N5TlRkaWVEUk1jV1p5TWpOb\
FpHcDZNbWMwTlM5RVJXczFTREl2ZW5OMlJVZHVkM0UzTTNoMGNFRktXbkphU0ZOeF\
ozVm5kMUJ4VEdoRGVFdHpPVE5oWW5WVGFFMWhjemt5UTB3M2FuVkJjRFJHYWxsNmF\
rSlRPRFZ4VVc1SWFIaFdSbnBwUjI5NWRuUlZWVE5aVXpaYVRtRmxPVFpMWW1kWE4w\
dHFaRGN5YVM5M1psVk9Ta3RrUmpKUlFVdFhTVXBaVERnd1lsRTViVEozSzNOTU5sU\
k9aQzkwVWtjelQxaFhTa2hFY0hKTFVsUlpTMmxYTW01YWVFUnZXRFJEYkhOT1RWZH\
FNbWxMVUdGSGRHSnNOblJ0V25CU1RGcDBhbk00Y3psc1FXbE9RbEZrTUZoeGRGUnp\
lWGx5THpNck9FRm1ibWh6SzBSSE5UVkJOQzg1TVVSa1lWaHNSRUUwVldKd2FscHdS\
RkZKUkVGUlFVSnZORWxDUVZSRFFpOXFRVTlDWjA1V1NGRTRRa0ZtT0VWQ1FVMURRV\
kZaZDBWbldVUldVakJVUVZGSUwwSkJaM2RDWjBWQ0wzZEpRa0Y2UTBKMVFWbEVWbE\
l3WjBKSlIzZE5TVWQwVFVsSGNVSm5WWEZCZDFGR1FtcERRbTlFUVRSQ1oyZHlRbWR\
GUmtKUlkwTkJVbGx6WVVoU01HTklUVFpNZVRscVkwaE5kV1JIVm5wa1F6VnRZMjFX\
Y1ZsWFZuQmFRelZxWWpJd2Rsa3pRbnBNTW14MVdrZFdORXh0YURCaVYzZDNXa0ZaU\
1V0M1dVSkNVVlZJUVdkSmQxZEJlRmRXUjJod1kzbENhbHBZU2pCaFYxcHdXVEpHTU\
ZwVFFtOVpXRTFuV1cxV2JHSnBRbkJqTTA0eFdsZFJaMGxIYkhWSlIwWnFXVEk1ZVZ\
wSFJuVlpNbFZuWkRKc01HRkRRakJoUjFWblVtNUtiR0Z0UldkYVZXeEZTVVpTUmxV\
eFVXZFZSemx6WVZkT05VbEZUblppYmxKNVlqSjNkMGhSV1VSV1VqQlBRa0paUlVaT\
mNYYzNUR3hZZHpWM09YSlViVXRGTDNKM1RtSnljMFJJWlV0TlFUQkhRMU54UjFOSl\
lqTkVVVVZDUTNkVlFVRTBTVU5CVVVKUFIwa3lXVFIxV0ZGbFFVMVRjM2RGVTNOSmM\
ySkdORkpzYTNaSlVXbEhRMlJyZDNRM1QzcHdabWxTWTA5UmJtdDRiVGx5YkhCa1VI\
UkROMDFoYWxaSk5tOTNkRnAzVkRaQ1UwY3dhbTE1VlVaTWFXaHdORlpDTURKV1RUQ\
XllR3RqV1hOVFJDODFPRllyUjJZdk1XbEZhbWRSWjI1T2FubzVXalZpVlZKSFZXbF\
FTemxVVjNKamFHazNSVEpOVEd4NVUyVklRVVZLVlZVeGRUVm9kMVV3Vmlzd2FGRTB\
VeXRGUlZwQ1dXWlBWalZYWVc5R2JXRXlXVmhHVkZOVFEwaDBlbTFISzA5TmFFbDBa\
MlYyU2taMEswOU1lVzFQVkdWM2RVWTNkalIyWTFCUVZubFZRamxwUldkaGQwVjNjR\
3BLUlVKMFlYaHJiVWxoU25ZMFNpOWpPVEpMUzBoalZFdDRjamhGWVZCbVQydzBkRE\
5WUTBodFVVeG5ia05GUnk4elNHNDJTMmRPYzBnMlVrTlBiVnB2YW1SVVpqVjJkMUZ\
hTWtJM1FXTmlWbTk2VlM5dWIwcGFNVzgyUXpSdlVuUTFVR3RVUldSVGJrRnRXRGh3\
WmpSTmJrNVlXVzE0VUhCWVJUZExiRVZoZWt4NE9YQnZRa2RXYjJKRGJqQllNMFlyT\
VVFMWNFVklabGs0VDNrdlJVOUxZek1yV25OM1Z6STVORUYxVjBOekwyNUliR0Z0Vj\
FCVEsycHhUa3RYTTNGcWFrNUxOa1phY3pjeVNVVkRkV1k1VDFOT05VSjJSSEpWYzF\
jME5HSXdXVFp2UjBsVlpYWlBkR1Y0UVZocFFsZFdVMHRVT1VkemIycHliRmt6Tmxn\
d1R6TXJiR3RyY1hSWE5HRmxZVEV4Y1dremIwZDZLemxwV0dOUVVXVmxSRGRyWjJac\
mMzcFRXVXRyYmpsWFFqRlpWR292YkhCYVZHeG1PVVJzZUVFMUt5dDFkVE5IY25CNE\
4zRlNaRU5zUldKRVpqVlJNa2hNU1ZOWFZuZHBjbTlqZVZOSGVtZzBkMEZEUmtocE5\
tbFJhbTV6Y201NlNIVTVOamhOZEU5dVRqWkdVWFE1ZWxCYWVHRlNXWEo2VEhCV0x6\
bDVlV0ZvT1dwWldYVk1Sa2xIYW1VcmVYcEJialZOT0U5U1ZqVndNVUYwUm5acVZGS\
m1TRFZ2UVQwOUxTMHRMUzFGVGtRZ1EwVlNWRWxHU1VOQlZFVXRMUzB0TFE9PSJdLC\
JhbGciOiJSUzI1NiJ9.\
eyJyZWYiOiI1VUlKbmVvellJWmE0cGRlNVczcUtIbmFURWFzakg0NTZodVJLSGlKW\
Gg0QThjdTBENkNRbktzU0dFTzdaS3JKIiwib3BhcXVlIjoiMXtcIm5vbmNlXCI6IF\
wiMTEzYjc3MWUtMjAwMi00MjVlLWE4YzctYmNmNDE0OTc3MDg4XCIsIFwidG9rZW5\
cIjogXCI5OTA5OTJkMC0wNzExLTRiNjQtOTQ2Yi1lNjQyM2RmNjFhYWRcIn0iLCJj\
b3VudHJ5IjoiU0UiLCJzc24iOiIxOTEwMTAzMDk4NDUifQ.\
gScVeQ-U9z8ZjxVxiWrxg4eq60LJvrABGAMqk54VuDMkRY0uD5X2R-AHe1uKH1H9\
uIFMPJHfPYUU153PrjS8rfZInDeT9m81do6WOrp1nwLT_sy_toZjGh2vmKjbZa4hz\
INGyZwlmaP6oBkl0N3GBvjMjnaOvEFeJnDxdRML0JCjsP7SsDmPFEttGLtNiVwxud\
u1S1DGM9mieUJBuQp5UHZZyOo-lock-1vx8qHN3p1znCCG_kRkhZUNADCqEJ1c50G\
QyKD1OWJrxY9ukmqInu2QIzmMkfTJ_v32htuFW9zYBh8yiAFHPSkyoFEgmNwkUFJ1\
oR76fgcy9uxtfBiyLw'

EXAMPLE_RESPONSE_DATA = 'eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlEa3pDQ0FudWdBd0lCQWdJRVBhVXFle\
kFOQmdrcWhraUc5dzBCQVFzRkFEQjZNUXN3Q1FZRFZRUUdFd0pUUlRFU01CQUdBMV\
VFQ0JNSlUzUnZZMnRvYjJ4dE1SSXdFQVlEVlFRSEV3bFRkRzlqYTJodmJHMHhFakF\
RQmdOVkJBb1RDVVp5WldwaElHVkpSREVOTUFzR0ExVUVDeE1FVkdWemRERWdNQjRH\
QTFVRUF4TVhSbkpsYW1FZ1pVbEVJRVJ2WTNWdFpXNTBZWFJwYjI0d0hoY05NVGN3T\
kRFek1UUTBOVFEyV2hjTk1UY3dOekV5TVRRME5UUTJXakI2TVFzd0NRWURWUVFHRX\
dKVFJURVNNQkFHQTFVRUNCTUpVM1J2WTJ0b2IyeHRNUkl3RUFZRFZRUUhFd2xUZEc\
5amEyaHZiRzB4RWpBUUJnTlZCQW9UQ1VaeVpXcGhJR1ZKUkRFTk1Bc0dBMVVFQ3hN\
RVZHVnpkREVnTUI0R0ExVUVBeE1YUm5KbGFtRWdaVWxFSUVSdlkzVnRaVzUwWVhSc\
GIyNHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDUy\
tBUnRjSTByZEhGVWtHMFRNcVpxSzByajVmQ3QyeldxWWtJYVdOb2ptZHZxa3ZsbTF\
jbm9idWlNOGY2endhbW5rMjNaOHA1OUQ1MzE0dVBrb1NWb2RoMEtHZGJzb2J1YVlk\
aXJ1Tkp4RUplRjkwcHJcL3Axa0VEQVFMRnA5UHFFV2N0OG5telg5YktKQzhvUm53N\
ExsVW9pYUhMMzRtdlJnSFZ3em42MXVNc2w0bzc4T0R6VEhGb3daZ3FURjRyM0VaZn\
lKQXZBT2dlYjhtYmJnaGtMR3ZpYXkyUlwvMDRlK3dwd0RpVTVhTkpMeW84UGdkTTJ\
VelwvQVRxTEQyVm9Vc1dpRW85Q3YzTVZVYWJ2eko3RHVmNFZDZmx2c0ZYRW03OEc4\
VzNwdmFVbDFIQ3FTM0kwRHBoR0dMdW9ydmN0VVY0ZFRZQ2g2QTZcL0tUUjBpSUNpZ\
EFcL0FnTUJBQUdqSVRBZk1CMEdBMVVkRGdRV0JCUVwvZ1JJa3puajZKejJDb1R0Sm\
pBNDdJQ1NFUWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUJcLzk3Q1lDQTROVW5\
2Y2RrbVVqc1wvNEgzY0F1d2xDQitZclBmeWMwVVNiTE4xV1pqSjM1ZFhaVmpzeG9h\
NlhQSnB6a1dLbENWek1hbTF0UGo3WnpcL0N0N3UrdmloaXdKMVVXRUVKZXpNa0YwT\
Th6d09EVHpEQjJZNlF0bTloOEhDek5OWUtYSldVTkFienNMcW5WMnMzTm4ySU1LOT\
VVRFdMUXBQbVJaS3lNTStjekVlckVBTithMTRRMDJLYTF1VEhkQzVyQ2NkTmNiNFZ\
pOG54WHg4ZXdPYXEwdWNyS1NiSEx6ajZqRVRvRWhLRjJTV2w1THVYUG9MYmM5NjFM\
c1BsSk1xMUs4Q2tLQU5Sc3pkWVBraUlNS3hWU0puVjNXdGFKWDdha0NFQUw1MGFKa\
npjWlFJWWlaczhEUWJWd20rU1dqTzNXMlRQMnAzM0t2bXp1dmphQT09Il19.\
eyJyZWYiOiIxMjM0LjU2NzguOTAxMi4zNDU2Iiwib3BhcXVlIjoiQUJDREVGR0hJS\
ktMTU5PUFJTVFVWV1hZWjAxMjM0NTY3ODkwMTIzNCIsInNzbiI6IjE5OTAxMDEwMT\
AxMCIsImNvdW50cnkiOiJTRSJ9.\
Wp_DuQcyuocGN7r-_Uj1jaJlVtYRjQ1UtWZegnWqeMtw2VpE6tL3qBX6MEDI055iy\
3FMKtiQOXByfAvubbWKlMs7iTBtk-e8wnRPckH-pizfCyG-ieaaix-zZ2f5UGltNp\
UEE4-Hk_on5qxwPt7s5flOfKCwYN5CDmTgmIsRkFWR_gLfjk_ySlyywPh8knoy5vn\
D6hJpe6OZotkojEPzTfQ4TsysIsf2i-Dj_9fAyl--UgMPT4JuHk3ddVNhq9JnB_j2\
M9EkYjM6ad_xEKldraS5xEJCVaEYa6oyBDzj9zUU61a71vp3C5uEi_yBA49Z6rxWE\
LhJjjgvjogq4TEQEQ'

EXAMPLE_RESPONSE_DATA_INVALID_UTF8 = 'eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlEa3pDQ0FudWdBd0lCQWdJRVBhVXFle\
kFOQmdrcWhraUc5dzBCQVFzRkFEQjZNUXN3Q1FZRFZRUUdFd0pUUlRFU01CQUdBMV\
VFQ0JNSlUzUnZZMnRvYjJ4dE1SSXdFQVlEVlFRSEV3bFRkRzlqYTJodmJHMHhFakF\
RQmdOVkJBb1RDVVp5WldwaElHVkpSREVOTUFzR0ExVUVDeE1FVkdWemRERWdNQjRH\
QTFVRUF4TVhSbkpsYW1FZ1pVbEVJRVJ2WTNWdFpXNTBZWFJwYjI0d0hoY05NVGN3T\
kRFek1UUTBOVFEyV2hjTk1UY3dOekV5TVRRME5UUTJXakI2TVFzd0NRWURWUVFHRX\
dKVFJURVNNQkFHQTFVRUNCTUpVM1J2WTJ0b2IyeHRNUkl3RUFZRFZRUUhFd2xUZEc\
5amEyaHZiRzB4RWpBUUJnTlZCQW9UQ1VaeVpXcGhJR1ZKUkRFTk1Bc0dBMVVFQ3hN\
RVZHVnpkREVnTUI0R0ExVUVBeE1YUm5KbGFtRWdaVWxFSUVSdlkzVnRaVzUwWVhSc\
GIyNHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDUy\
tBUnRjSTByZEhGVWtHMFRNcVpxSzByajVmQ3QyeldxWWtJYVdOb2ptZHZxa3ZsbTF\
jbm9idWlNOGY2endhbW5rMjNaOHA1OUQ1MzE0dVBrb1NWb2RoMEtHZGJzb2J1YVlk\
aXJ1Tkp4RUplRjkwcHJcL3Axa0VEQVFMRnA5UHFFV2N0OG5telg5YktKQzhvUm53N\
ExsVW9pYUhMMzRtdlJnSFZ3em42MXVNc2w0bzc4T0R6VEhGb3daZ3FURjRyM0VaZn\
lKQXZBT2dlYjhtYmJnaGtMR3ZpYXkyUlwvMDRlK3dwd0RpVTVhTkpMeW84UGdkTTJ\
VelwvQVRxTEQyVm9Vc1dpRW85Q3YzTVZVYWJ2eko3RHVmNFZDZmx2c0ZYRW03OEc4\
VzNwdmFVbDFIQ3FTM0kwRHBoR0dMdW9ydmN0VVY0ZFRZQ2g2QTZcL0tUUjBpSUNpZ\
EFcL0FnTUJBQUdqSVRBZk1CMEdBMVVkRGdRV0JCUVwvZ1JJa3puajZKejJDb1R0Sm\
pBNDdJQ1NFUWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUJcLzk3Q1lDQTROVW5\
2Y2RrbVVqc1wvNEgzY0F1d2xDQitZclBmeWMwVVNiTE4xV1pqSjM1ZFhaVmpzeG9h\
NlhQSnB6a1dLbENWek1hbTF0UGo3WnpcL0N0N3UrdmloaXdKMVVXRUVKZXpNa0YwT\
Th6d09EVHpEQjJZNlF0bTloOEhDek5OWUtYSldVTkFienNMcW5WMnMzTm4ySU1LOT\
VVRFdMUXBQbVJaS3lNTStjekVlckVBTithMTRRMDJLYTF1VEhkQzVyQ2NkTmNiNFZ\
pOG54WHg4ZXdPYXEwdWNyS1NiSEx6ajZqRVRvRWhLRjJTV2w1THVYUG9MYmM5NjFM\
c1BsSk1xMUs4Q2tLQU5Sc3pkWVBraUlNS3hWU0puVjNXdGFKWDdha0NFQUw1MGFKa\
npjWlFJWWlaczhEUWJWd20rU1dqTzNXMlRQMnAzM0t2bXp1dmphQT09Il19.\
eyJyZWYiOiIxMjM0LjU2NzguOTAxMi4zNDU2Iiwib3BhcXVlIjoiQUJDREVGR0hJS\
eyJyZWYiOiIxMjM0LjU2NzguOTAxMi4zNDU2Iiwib3BhcXVlIjoiQUJDREVGR0hJS\
AxMCIsImNvdW50cnkiOiJTRSJ9.\
Wp_DuQcyuocGN7r-_Uj1jaJlVtYRjQ1UtWZegnWqeMtw2VpE6tL3qBX6MEDI055iy\
3FMKtiQOXByfAvubbWKlMs7iTBtk-e8wnRPckH-pizfCyG-ieaaix-zZ2f5UGltNp\
UEE4-Hk_on5qxwPt7s5flOfKCwYN5CDmTgmIsRkFWR_gLfjk_ySlyywPh8knoy5vn\
D6hJpe6OZotkojEPzTfQ4TsysIsf2i-Dj_9fAyl--UgMPT4JuHk3ddVNhq9JnB_j2\
M9EkYjM6ad_xEKldraS5xEJCVaEYa6oyBDzj9zUU61a71vp3C5uEi_yBA49Z6rxWE\
LhJjjgvjogq4TEQEQ'

FREJA_CALLBACK_WRONG_X5C_CERT = "-----BEGIN CERTIFICATE-----\n"\
"MIIGODCCBCCgAwIBAgIUdxOCM0ShYGSRH6uHRMXj9bKkgV4wDQYJKoZIhvcNAQEL"\
"BQAwUTELMAkGA1UEBhMCU0UxEzARBgNVBAoTClZlcmlzZWMgQUIxEjAQBgNVBAsT"\
"CUZyZWphIGVJRDEZMBcGA1UEAxMQUlNBIFRlc3QgUm9vdCBDQTAeFw0xNzA1MTcx"\
"NDQyNTJaFw0yNzA1MTcxNDQyNTJaMIGDMQswCQYDVQQGEwJTRTESMBAGA1UEBxMJ"\
"U3RvY2tob2xtMRQwEgYDVQRhEws1NTkxMTAtNDgwNjEdMBsGA1UEChMUVmVyaXNl"\
"YyBGcmVqYSBlSUQgQUIxDTALBgNVBAsTBFRlc3QxHDAaBgNVBAMTE1JTQSBURVNU"\
"IElzc3VpbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSUhGD"\
"HHpqhp9OmA2f8HjKHd+JJDtexrVQetyZujZfig8UV6y85nEcAw7Fh1kEG9I3JHe/"\
"PNmBL/y9NaRbqywgR8evU0l5wSBlevGelz9H+neGVEFvKkHmFOvr7f7c5bVWa/UR"\
"zTmCfWAolKvY+AwKlIkdTE1eptn8M940YFvUULBhLaDSZXNhvv6EZT9w2xTT4ZyH"\
"wd8faLfEvtGs+13KrAhutaJJYY6Xq0Fn9Q71sX/x5T7dG5InSiEPYNggW9pRVkx6"\
"1mdbpiz6waGsNrMo0wOyX8/wfptgQ81B4BUnKT89F3NOh9M7ZJN9+sRtX0kWLLRZ"\
"SN+Rg1Yy73D68B0xAgMBAAGjggHTMIIBzzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0T"\
"AQH/BAgwBgEB/wIBADBPBggrBgEFBQcBAQRDMEEwPwYIKwYBBQUHMAGGM2h0dHA6"\
"Ly9yb290Y2FsYWIzMS50ZXN0LmZyZWphZWlkLmNvbTo4Nzc3L2Fkc3Mvb2NzcDAf"\
"BgNVHSMEGDAWgBTKsOy5V8OcPa05ihP68DW67Ax3ijCBuAYDVR0gBIGwMIGtMIGq"\
"BgUqAwQFBjCBoDA4BggrBgEFBQcCARYsaHR0cHM6Ly9jcHMudGVzdC5mcmVqYWVp"\
"ZC5jb20vY3BzL2luZGV4Lmh0bWwwZAYIKwYBBQUHAgIwWAxWVGhpcyBjZXJ0aWZp"\
"Y2F0ZSBoYXMgYmVlbiBpc3N1ZWQgIGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgRnJl"\
"amEgZUlEIFRFU1QgUG9saWN5IENvbnRyb2wwXQYDVR0fBFYwVDBSoFCgToZMaHR0"\
"cDovL3Jvb3RjYWxhYjMxLnRlc3QuZnJlamFlaWQuY29tOjg3NzcvYWRzcy9jcmxz"\
"L2ZyZWphZWlkX3JzYV9yb290X2NhLmNybDAdBgNVHQ4EFgQUanyKD51wDhzaXy2g"\
"PCZfiOgVv5wwDQYJKoZIhvcNAQELBQADggIBAGzHkEkVDMqcA+GRTAvW2OW1tDZo"\
"FljM+w1AuQz380kmMamAl4f+Imw3UsT3JhXPZaJNVofqPBO/FiooO9mPIf8jMxrx"\
"Lfm/p/2n9K49RYwgRNDwVyW59c1H0jvHePpfaRtPS2ov0eI+QSMvk14/phIv/bkN"\
"d+0OVp0qgTVTTwwAvUQJ2P9cDK3OIj7H0vJhhw7ux66gNMHf+InERrbu0Si5rQem"\
"SafaQTS6N0QNtJVAafRYDM/FTOdPulbxkbktybjMiDTuJ3MvhqKv5zCR8noYwEBP"\
"VrePAvg6bwb0K1aCAQm4IsWBCKF4t6sqjrvaq/3jUo+M65Tp0AKTKn4B8nmTvGv9"\
"lT4PgsCTwwXbIUcW5rfsmE9wVpRfieG7Gx62ydHPlIPkTChUzs/joju8sykVnssF"\
"1YDqQlgMa2Sp+kx5i7eijX1ejcJh+pmuQTQnXj6sDJry81OtqDO7D7DhaUHfGLil"\
"mXurAolujmll5MabdBEq3E4TTebvv6WSNpEYwQ1S+8eE+9slLnmhR2RSNpWGDQ/l"\
"WwFoAsTCjG+e9f57mGUlmSeU6zERIxieER7wMM7EaqWaYo6JbeOhusbdTU/LmsyA"\
"8fZYp+gn/FM8Wl8eh1qj/GIcAdDAIO3k8mqA98sWR7Mx5vgdRNcmpCtOQxxiijC7"\
"MRbYKeBk4HOtXw9e\n"\
"-----END CERTIFICATE-----"


@pytest.fixture
def authn_request_args():
    return {
        'client_id': TEST_CLIENT_ID,
        'redirect_uri': TEST_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid',
        'nonce': '113b771e-2002-425e-a8c7-bcf414977088',
        'state': 'state'
    }

@pytest.mark.usefixtures('inject_app', 'create_client_in_db')
class TestVettingResultEndpoint(object):
    @pytest.fixture
    def create_client_in_db(self, request):
        db_uri = request.instance.app.config['DB_URI']
        client_db = OpStorageWrapper(db_uri, 'clients')
        client_db[TEST_CLIENT_ID] = {
            'redirect_uris': [TEST_REDIRECT_URI],
            'client_secret': TEST_CLIENT_SECRET,
            'response_types': ['code']
        }
        self.app.provider.clients = client_db

@pytest.mark.usefixtures('inject_app')
class TestVettingResultEndpoint(object):

    def test_vetting_endpoint_with_missing_data(self):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT,
                                           content_type='application/jose')

        assert resp.data == b'missing or invalid JSON'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': 'not a valid JWS'},
    ])
    def test_vetting_endpoint_with_invalid_jws(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')

        assert resp.data == b'iaResponseData is not a JWS'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': EXAMPLE_RESPONSE_DATA},
    ])
    def test_vetting_endpoint_with_doc_example_jws_invalid_mime(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/x-www-form-urlencoded')

        assert resp.data == b'Invalid MIME'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': EXAMPLE_RESPONSE_DATA_INVALID_UTF8},
    ])
    def test_vetting_endpoint_with_doc_example_jws_invalid_utf8(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')

        assert resp.data == b'Incorrect UTF-8 in iaResponseData'
        assert resp.status_code == 400


    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': EXAMPLE_RESPONSE_DATA},
    ])
    def test_vetting_endpoint_with_doc_example_jws_invalid_signature(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')

        assert resp.data == b'Invalid signature'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': DEMO_RESPONSE_DATA},
    ])
    def test_vetting_endpoint_with_demo_jws_wrong_key(self, parameters):
        self.app.config['FREJA_CALLBACK_X5C_CERT'] = FREJA_CALLBACK_WRONG_X5C_CERT
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')

        assert resp.data == b'Invalid signature'
        assert resp.status_code == 400

    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': DEMO_RESPONSE_DATA},
    ])
    def test_vetting_endpoint_with_demo_jws_unknown_nonce(self, parameters):
        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')
        assert resp.data == b'Unknown nonce in verified JWS payload'
        assert resp.status_code == 400

    @responses.activate
    @pytest.mark.parametrize('parameters', [
        {'iaResponseData': DEMO_RESPONSE_DATA},
    ])
    def test_vetting_endpoint_with_demo_jws(self, authn_request_args, parameters):
        # This is more or less a copy of test_vetting_endpoint() in test_se_leg_vetting_process.py
        responses.add(responses.GET, TEST_REDIRECT_URI, status=200)
        nonce = authn_request_args['nonce']
        self.app.authn_requests[nonce] = authn_request_args

        token = '990992d0-0711-4b64-946b-e6423df61aad'

        resp = self.app.test_client().post(VETTING_RESULT_ENDPOINT, data=json.dumps(parameters),
                                           content_type='application/jose')
        assert resp.data == b'OK'
        assert resp.status_code == 200

        assert nonce not in self.app.authn_requests
        assert self.app.users[TEST_USER_ID]['identity'] == TEST_USER_ID

        # force sending response from message queue from http://python-rq.org/docs/testing/
        worker = SimpleWorker([self.app.authn_response_queue], connection=self.app.authn_response_queue.connection)
        worker.work(burst=True)

        # verify the authentication response has been sent to the client
        parsed_response = dict(parse_qsl(urlparse(responses.calls[0].request.url).query))
        assert 'code' in parsed_response
        assert parsed_response['state'] == authn_request_args['state']
        assert parsed_response['code'] in self.app.provider.authz_state.authorization_codes
        assert responses.calls[0].request.headers['Authorization'] == 'Bearer ' + token
