# -*- coding: utf-8 -*-

import ikev2.ikev2_class as ikev2

ike_instance = ikev2.epdg_ikev2('188.21.252.88')
#ike_instance = ikev2.epdg_ikev2('192.168.0.5', 51234, 500)
print('Sending SA_INIT')
len = ike_instance.sa_init(51234, 500, True)
#len = 101
if(len > 100):
    print('Sending IKE_AUTH')
    ike_instance.sa_auth(51237, 4500, "232012230093690")
    #ike_instance.sa_auth(51234, 4500, "232019876543210")
print('END')
