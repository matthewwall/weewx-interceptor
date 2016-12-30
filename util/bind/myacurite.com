; BIND data file for myacurite.com, for faking out the acurite smarthub
$       TTL604800
@       IN      SOA     dns.hubapi.myacurite.com. root.hubapi.myacurite.com. (
2016031904 ; Serial
    604800 ; Refresh
     86400 ; Retry
   2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@       IN      NS      dns.hubapi.myacurite.com.
@       IN      A       10.0.1.21
*       IN      A       10.0.1.21
*       IN      AAAA    ::1
