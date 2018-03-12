# -*- coding: utf-8 -*-

import sys
sys.path.append('../')
import ikev2.ikev2_class as ikev2

ike_instance = ikev2.epdg_ikev2('xxx.xxx.xxx.xxx')
print('Sending SA_INIT')
len = ike_instance.sa_init(51234, 500, True)
#len = 101
if(len > 100):
    print('Sending IKE_AUTH')
    ike_instance.sa_auth(51234, 4500, "xxxxxxxxxxxxxxx")
print('END')
