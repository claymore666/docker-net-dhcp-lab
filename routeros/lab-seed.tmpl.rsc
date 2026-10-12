# Imported once by the stock admin (blank password) over the mgmt address
# (lab #9): users and keys need a policy guest-exec lacks (M3). Every line
# is safe to run again after a partial run.
/import file-name=lab-baseline.rsc
:if ([:len [/user find name=lab]] = 0) do={/user add name=lab group=full password=[:rndstr length=32 from="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]}
:if ([:len [/user ssh-keys find user=lab]] = 0) do={/user ssh-keys import public-key-file=lab.pub user=lab}
/ip service disable [find name!=ssh dynamic=no]
/user set [find name=admin] disabled=yes
/system identity set name=lab-ready
