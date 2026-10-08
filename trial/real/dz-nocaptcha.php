<?php
// The test forum's login asks for no captcha: in its settings and in the cached copy of them, changed in place.
$db = new mysqli('10.233.105.3', 'dz', $argv[1], 'dz');
$db->query("UPDATE pre_common_setting SET svalue='0' WHERE skey='seccodestatus'");
$row = $db->query("SELECT data FROM pre_common_syscache WHERE cname='setting'")->fetch_row();
$s = unserialize($row[0]);
echo "cached seccodestatus was ", var_export($s['seccodestatus'], true), "\n";
$s['seccodestatus'] = 0;
$st = $db->prepare("UPDATE pre_common_syscache SET data=? WHERE cname='setting'");
$data = serialize($s);
$st->bind_param('s', $data);
$st->execute();
echo "done\n";
