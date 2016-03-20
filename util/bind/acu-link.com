; BIND data file for acu-link.com, for faking out the acurite bridge
$       TTL604800
@       IN      SOA     dns.www.acu-link.com. root.www.acu-link.com. (
2016031904 ; Serial
    604800 ; Refresh
     86400 ; Retry
   2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@       IN      NS      dns.www.acu-link.com.
@       IN      A       10.0.1.21
*       IN      A       10.0.1.21
*       IN      AAAA    ::1
