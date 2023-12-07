# sing-box 6 protocol 
- vless tcp reality
- vless grpc tls
- vmess ws +Argo tunnel
- vmess ws
- Hysteria2
- Tuic5

## install
```
bash <(curl -fsSL https://raw.githubusercontent.com/Ptechgithub/sing-box/main/install.sh)
```
![9](https://raw.githubusercontent.com/Ptechgithub/configs/main/media/9.jpg)
- پس از نصب اگر روش اول یعنی Bing self-signed را انتخاب کنید 5 پروتکل به عنوان خروجی دریافت میکنید که مورد پنجم همان تانل Argo است.
- پس از ریبوت شدن سرور host کانفیگ Argo تغییر میکند که میتواند از طریق منو ادرس جدید را بگیرید و در کانفیگ قبلی قرار دهید.
- فایل config-sing-box.json در مسیر 
/root/peyman/configs 
قرار دارد که میتونید روی خود نرم افزار sing-box استفاده کنید. با این کار نرم افزار به طور اتوماتیک به هر کدوم از کانفیگ ها که در لحظه سرعت و پینگ بهتری داشته باشه وصل میشه. و کانفیگ شما هم قطع نمیشه. مثل تصویر زیر:
- ![10](https://raw.githubusercontent.com/Ptechgithub/configs/main/media/10.jpg)

- ![13](https://raw.githubusercontent.com/Ptechgithub/configs/main/media/13.jpg)



### Clients
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNg/releases)
  - [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases)
  - [sing-box (SFA)](https://github.com/SagerNet/sing-box/releases)
- iOS
  - [FoXray](https://apps.apple.com/app/foxray/id6448898396)
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [sing-box (SFM)](https://github.com/SagerNet/sing-box/releases)
  - [Stash](https://apps.apple.com/app/stash/id1596063349)
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN/releases)
- Windows, Linux, macOS
  - [NekoRay](https://github.com/MatsuriDayo/nekoray/releases)
  - [Furious](https://github.com/LorenEteval/Furious/releases)
  
  .
  
  thanks : [yonggekkk](https://github.com/yonggekkk) for server config.


## Thanks for 🌟

[![Stargazers over time](https://starchart.cc/Ptechgithub/sing-box.svg)](https://starchart.cc/Ptechgithub/sing-box)
