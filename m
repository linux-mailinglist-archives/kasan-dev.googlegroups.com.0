Return-Path: <kasan-dev+bncBDO456PHTELBBY7B4C3AMGQEV657BIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 13FF896B7C0
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 12:05:25 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2781c2564edsf2075494fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 03:05:25 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725444323; x=1726049123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u0bZOwc35ygDHFWIi0hpQWGH0r2F9nRrQFdBfZjbMcY=;
        b=tXbcWdRDc2E21x+dU9xDQch5+fpjNc/CXMS3w3TTIEyF+kjTVd2A1qmLdgXu/6k5fQ
         szSa5iksG5ezQMdDYImHcioD+HIk2ka90jBbAOxF77bL7jG4iZXoqdMUyo0r7BTM7wg6
         3cHfBROArDVasFe2oEofsRJ0OmlUA1AN4GZQjjpAjKwJmUo5OVa8VMh+wEztN7EKf26V
         1T9PXhgSwhG+Bl3LH+0cw2Oa5AjeAhd6PbM9Labq5pKK7Xgr2MBAsvfKSSySlYBSFr6q
         eJzPDG/JB1/meoP/XgoToRla9Z4Z9GbpxWJiE9rjKWog9zv4bbtF1/zFNvRcy9VgJI62
         oukw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1725444323; x=1726049123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u0bZOwc35ygDHFWIi0hpQWGH0r2F9nRrQFdBfZjbMcY=;
        b=kjzcNpUWEs7HMO1fC6Q25OOFNlaLmr5Wq2h8aHaayWSTRHN5m3pdNotJ1DL8X4YM4T
         By7s9vHoC3L+LcEUSStw9+53kCAzSyS5wWhJb+vVNWAjn03mN+tGTTsFEf1kz8jq5HNQ
         UkOIOWMN/yskjJbB+iqzd3QdItTGO3hh4FciWWyOtRJOP2yhervp75IJUcYmRKOuAwTW
         gsaIbXo/4zQVH0tWVyohx6PC9zb9gHvojVreS1p51ESfW2x6OEC2YnG46XBD1grw8VKf
         AZjyun7DcRUw5uYVK7EpSy9QV+cDYgfsgxW+8I4Htl0BxiWXM4Ld4AbRIkUreO/HWdTh
         /Zbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725444323; x=1726049123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u0bZOwc35ygDHFWIi0hpQWGH0r2F9nRrQFdBfZjbMcY=;
        b=Kq3Sdr7QppCBu9n2+9kSVo83955AkNtuCebOqAjqClpHMnW3/Q4tjOBTjsjTTszN2c
         F4ykN/G3yMFzVytrPCzorVosW8IVMQ0+rkPib2Zt+s3MJwZTxvs0nSP6GNcr/PO/zhbh
         e5h6tW5d3MefqMYcSst5Xfl6xJbR3cVIAHFEg/HsTzBTkdirDhWEg39lHpwJbIF7TvF0
         Qdz5zlHUz9uIHAveTLCQ8DypqYvnQSgv9E/mFIH5b1ult4SdVVjNQ+nAXpXkAz77XVo7
         SehBlBXUTnQXW+yZyjgbCLOsQJSVSrigCKgz90Vs2y4naayVR2ujysLCxe9qEsm5QHxu
         qQTA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXu+zt4R3KdK57CRYbfjHjM5DMzgYgOP5dCLkPKcChNy30W7zR33Q6o69zVJnSrEta7xLL2zw==@lfdr.de
X-Gm-Message-State: AOJu0Yy1t+N2fvvzAxMozZ9llB7GddWJxZjaG8+PqCcP3rQfKDZsZXSB
	GcGn8cET/PXsXRHJAFz0egObL45xGKnKEyz4utR0mIeYXZ8ZeHx/
X-Google-Smtp-Source: AGHT+IFUmV7jWUjttfR1+kGHXKfPYldG5RtEOChk66x/0dP5j6TD6yfbtIeRdZW/+xjN8Cv6R9JIUQ==
X-Received: by 2002:a05:6870:fba8:b0:27b:5a02:f940 with SMTP id 586e51a60fabf-27b5a02fa8cmr684276fac.23.1725444323243;
        Wed, 04 Sep 2024 03:05:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:de17:b0:259:f021:752d with SMTP id
 586e51a60fabf-2778f0c190els573537fac.0.-pod-prod-07-us; Wed, 04 Sep 2024
 03:05:22 -0700 (PDT)
X-Received: by 2002:a05:6808:2386:b0:3da:a032:24c5 with SMTP id 5614622812f47-3df1c986d61mr16468014b6e.22.1725444321975;
        Wed, 04 Sep 2024 03:05:21 -0700 (PDT)
Date: Wed, 4 Sep 2024 03:05:21 -0700 (PDT)
From: hana soodi <hanasoodi668@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <cae5a464-1425-44c4-85a9-ae0c80f27c30n@googlegroups.com>
Subject: =?UTF-8?B?2KfYudmE2KfZhiBcINit2Kgg2LPYp9mK2KrZiNmK2Ko=?=
 =?UTF-8?B?2YMg2YHZiiDYp9mE2LPYudmI2K/ZitipIHx8OTcx?=
 =?UTF-8?B?NTUzMDMxODQ2fHwg2YjYp9mE2YPZiNmK2Ko=?=
 =?UTF-8?B?IF8g2YTZhNin2KzZh9in2K8g2KfZhNmF2YbYstmE2Yog?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_37538_1529907721.1725444321216"
X-Original-Sender: hanasoodi668@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_37538_1529907721.1725444321216
Content-Type: multipart/alternative; 
	boundary="----=_Part_37539_658047171.1725444321216"

------=_Part_37539_658047171.1725444321216
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2KXYsNinINmD2YbYqiDYqtix2LrYqCDZgdmKINin2YTYrdi12YjZhCDYudmE2Ykg2KPZiiDZhdmG
2KrYrNin2Kog2K3YqNmI2Kgg2KfZhNin2KzZh9in2LbYjCAgCiBodHRwczovL2xpbmt0ci5lZS9j
eXRvdGljX2RfbnVyCtit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTZhdiz2KrYrtiv2YUg2YTZ
hNin2KzZh9in2LYhINmF2LnZhNmI2YXYp9iqINmF2YfZhdipINmK2KzYqCDZhdi52LHZgdiq2YfY
pzoK2LPYp9mK2KrZiNiq2YrZgyAoQ3l0b3RlYykg2YfZiCDYp9mE2KfYs9mFINin2YTYqtis2KfY
sdmKINmE2K/ZiNin2KEg2KfZhNmF2YrYstmI2KjYsdmI2LPYqtmI2YQgKE1pc29wcm9zdG9sKdiM
INmI2YfZiCAK2K/ZiNin2KEg2YrZj9iz2KrYrtiv2YUg2YHZiiDZhdis2YXZiNi52Kkg2YXYqtmG
2YjYudipINmF2YYg2KfZhNit2KfZhNin2Kog2KfZhNi32KjZitip2Iwg2KjZhdinINmB2Yog2LDZ
hNmDINin2YTZiNmC2KfZitipINmF2YYg2YLYsdit2KkgCtin2YTZhdi52K/YqSDYp9mE2YbYp9iq
2KzYqSDYudmGINin2LPYqtiu2K/Yp9mFINin2YTYo9iv2YjZitipINin2YTZhdi22KfYr9ipINmE
2YTYp9mE2KrZh9in2KjYp9iqINi62YrYsSDYp9mE2LPYqtmK2LHZiNmK2K/ZitipIAooTlNBSURz
KdiMINmI2YPYsNmE2YMg2YHZiiDYp9mE2KXYrNmH2KfYtiDYp9mE2LfYqNmKLtmF2Kcg2YfZiCDY
s9in2YrYqtmI2KrZgyDYp9mE2KfZhdin2LHYp9iq2J8K2LPYp9mK2KrZiNiq2YMg2KfZhNin2YXY
p9ix2KfYqiDZh9mIINi52KjYp9ix2Kkg2LnZhiDYr9mI2KfYoSDZitit2KrZiNmKINi52YTZiSDY
p9mE2YXYp9iv2Kkg2KfZhNmB2LnYp9mE2Kkg2YXZitiy2YjYqNix2YjYs9iq2YjZhC4gCtmK2LPY
qtiu2K/ZhSDYs9in2YrYqtmI2KrZgyDZgdmKINil2KzYsdin2KEg2KfZhNil2KzZh9in2LYg2KfZ
hNi32KjZiti52Yog2YTZhNit2YXZhCDZgdmKINmF2LHYp9it2YQg2YXYqNmD2LHYqS4g2YrYudmF
2YQg2LPYp9mK2KrZiNiq2YMgCti52YYg2LfYsdmK2YIg2KrYrdmB2YrYsiDYudi22YTYp9iqINin
2YTYsdit2YUg2YTZhNiq2YLZhNi1INmI2KfZhNiq2K7ZhNi1INmF2YYg2KfZhNis2YbZitmGINmI
2KfZhNij2YbYs9is2Kkg2KfZhNmF2K3Ziti32Kkg2KjZhy4gCtmK2KrZiNmB2LEg2LPYp9mK2KrZ
iNiq2YMg2KfZhNiz2LnZiNiv2YrYqSDYudmE2Ykg2LTZg9mEINij2YLYsdin2LUg2KrYpNiu2LAg
2LnZhiDYt9ix2YrZgiDYp9mE2YHZhS4g2YrYrNioINin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjY
qtmDIArZiNmB2YLZi9inINmE2KrYudmE2YrZhdin2Kog2KfZhNi32KjZitioINmI2KfZhNis2LHY
udipINin2YTZhdit2K/Yr9ipLiDZgtivINmK2KrZhSDYqtmI2KzZitmHINin2YTZhtiz2KfYoSDY
p9mE2YTZiNin2KrZiiDZitix2LrYqNmGINmB2YogCtin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjY
qtmDINil2YTZiSDYp9mE2YLZitin2YUg2KjZgdit2YjYtdin2Kog2YjZgdit2YjYtdin2Kog2LfY
qNmK2Kkg2YLYqNmEINin2LPYqtiu2K/Yp9mF2Ycg2YTZhNiq2KPZg9ivINmF2YYgCtiz2YTYp9mF
2KrZh9mFINmI2YXZhNin2KHZhdiq2YfZhSDZhNmE2KfYs9iq2K7Yr9in2YUuI9mF2YjYs9mFX9in
2YTYp9mF2KfYsdin2KoKCjE4MTFiYzBmLTQ0OTYtNDYzMC1iOWQzLTM5NjZiNmQ5YzVhZi5qcGcK
2YPZitmBINmK2LnZhdmEINiz2KfZitiq2YjYqtmDINin2YTYp9mF2KfYsdin2KrYnwrYs9in2YrY
qtmI2KrZgyDYp9mE2KfZhdin2LHYp9iqINmH2Ygg2LnYqNin2LHYqSDYudmGINiv2YjYp9ihINmK
2K3YqtmI2Yog2LnZhNmJINin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqSDZhdmK2LLZiNio2LHZ
iNiz2KrZiNmELiAK2YrYudmF2YQg2LPYp9mK2KrZiNiq2YMg2LnZhiDYt9ix2YrZgiDYqtit2YHZ
itiyINi52LbZhNin2Kog2KfZhNix2K3ZhSDZhNmE2KfZhtmC2KjYp9i2INmI2KfZhNiq2YLZhNi1
2Iwg2YXZhdinINmK2KTYr9mKINil2YTZiSDYpdis2YfYp9i2IArYp9mE2K3ZhdmELiDYudmG2K8g
2KrZhtin2YjZhCDYs9in2YrYqtmI2KrZgyDYp9mE2KfZhdin2LHYp9iq2Iwg2YrYqtmFINin2LPY
qtiu2K/Yp9mF2Ycg2KjYtNmD2YQg2LnYp9iv2Kkg2YXYuSDYr9mI2KfYoSDYotiu2LEg2YrYs9mF
2YkgCtmF2YrZgdmK2KjYsdmK2LPYqtmI2YYuINmK2KrZhSDYqtmG2KfZiNmEINmF2YrZgdmK2KjY
sdmK2LPYqtmI2YYg2KPZiNmE2KfZiyDZhNiq2K3YttmK2LEg2KfZhNix2K3ZhSDZhNmE2KXYrNmH
2KfYttiMINir2YUg2YrYqtmFINiq2YbYp9mI2YQgCtiz2KfZitiq2YjYqtmDINmE2KrYs9mH2YrZ
hCDYp9mE2LnZhdmE2YrYqSDZiNil2YPZhdin2YQg2KfZhNil2KzZh9in2LYuCgrZitiq2YUg2KrZ
htin2YjZhCDYs9in2YrYqtmI2KrZgyDYp9mE2KfZhdin2LHYp9iqINi52YYg2LfYsdmK2YIg2KfZ
hNmB2YXYjCDZiNi52KfYr9ipINmF2Kcg2YrYqtmFINmI2LbYuSDYp9mE2KPZgtix2KfYtSDYqtit
2KogCtin2YTZhNiz2KfZhiDYo9mIINio2YrZhiDYp9mE2K7YryDZiNin2YTZhNir2KkuINmK2KzY
qCDYp9iq2KjYp9i5INiq2LnZhNmK2YXYp9iqINin2YTYt9io2YrYqCDYqNiv2YLYqSDYqNiu2LXZ
iNi1INin2YTYrNix2LnYqSAK2YjYp9mE2KrZiNmC2YrYqiDYp9mE2YXZhtin2LPYqCDZhNiq2YbY
p9mI2YQg2KfZhNiv2YjYp9ihLiDZitis2Kgg2KPZhiDZitiq2YUg2KfYs9iq2K7Yr9in2YUg2LPY
p9mK2KrZiNiq2YMg2KfZhNin2YXYp9ix2KfYqiDZgdmKIArYp9mE2KPYs9in2KjZiti5INin2YTY
o9mI2YTZiSDZhdmGINin2YTYrdmF2YQg2YjYqtit2Kog2KXYtNix2KfZgSDYt9io2YrYqCDZhdiu
2KrYtS4g2YLYryDZitiq2LfZhNioINin2YTYpdis2YfYp9i2INio2KfYs9iq2K7Yr9in2YUgCtiz
2KfZitiq2YjYqtmDINi52K/YqSDYo9mK2KfZhSDZiNmC2K8g2YrYrdiq2KfYrCDYp9mE2YXYsdmK
2LYg2KXZhNmJINmF2KrYp9io2LnYqSDYt9io2YrYqSDZhNmE2KrYo9mD2K8g2YXZhiDZhtis2KfY
rSDYp9mE2KXYrNmH2KfYtiAK2YjYudiv2YUg2YjYrNmI2K8g2YXYttin2LnZgdin2KouCgrZhdin
INmH2Yog2KfZhNin2LPYqtiu2K/Yp9mF2KfYqiDYp9mE2LTYp9im2LnYqSDYs9in2YrYqtmI2KrZ
gyDYp9mE2KXZhdin2LHYp9iq2J8K2KrZj9iz2KrYrtiv2YUg2LPYp9mK2KrZiNiq2YMg2KfZhNiz
2LnZiNiv2YrYqSDYqNi02YPZhCDYtNin2KbYuSDZgdmKINil2KzYsdin2KEg2KfZhNil2KzZh9in
2LYg2KfZhNi32KjZiiDZgdmKINit2KfZhNin2Kog2KfZhNit2YXZhCAK2LrZitixINin2YTZhdix
2LrZiNioINmB2YrZhy4g2YrZj9i52KrYqNixINiz2KfZitiq2YjYqtmDINin2YTYpdmF2KfYsdin
2Kog2KPYrdivINin2YTYrtmK2KfYsdin2Kog2KfZhNi32KjZitipINin2YTZhdiq2KfYrdipINmE
2YTZhtiz2KfYoSAK2KfZhNmE2YjYp9iq2Yog2YrZiNin2KzZh9mGINit2YXZhNmL2Kcg2LrZitix
INmF2LHYutmI2Kgg2YHZitmHINij2Ygg2LrZitixINmF2LPYqtit2KguINmK2Y/Ys9iq2K7Yr9mF
INiz2KfZitiq2YjYqtmDINin2YTYpdmF2KfYsdin2KogCtij2YrYttmL2Kcg2YHZiiDYrdin2YTY
p9iqINin2YTYpdis2YfYp9i2INin2YTYt9io2Yog2KfZhNiw2Yog2YrYqtmFINio2YbYp9ih2Ysg
2LnZhNmJINiq2YjYtdmK2Kkg2LfYqNmK2KnYjCDZhdir2YQg2YHZiiDYrdin2YTYp9iqIArYqti0
2YjZh9in2Kog2K7ZhNmC2YrYqSDZgdmKINin2YTYrNmG2YrZhiDYo9mIINiu2LfYsSDYudmE2Ykg
2LXYrdipINin2YTYo9mFLiDYqNin2YTYpdi22KfZgdipINil2YTZiSDYsNmE2YPYjCDZitmP2LPY
qtiu2K/ZhSAK2LPYp9mK2KrZiNiq2YMg2KfZhNil2YXYp9ix2KfYqiDZgdmKINio2LnYtiDYp9mE
2KPYrdmK2KfZhiDZhNil2YbZh9in2KEg2KfZhNit2YXZhCDZgdmKINit2KfZhNin2Kog2KfZhNit
2YXZhCDYrtin2LHYrCDYp9mE2LHYrdmFINij2YggCtin2YTYrdmF2YQg2KfZhNiw2Yog2YrYtNmD
2YQg2K7Yt9ix2YvYpyDYudmE2Ykg2K3Zitin2Kkg2KfZhNij2YUuCgrZhdmGINin2YTZhdmH2YUg
2KPZhiDZitiq2YUg2KfYs9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMg2KfZhNil2YXYp9ix2KfY
qiDYqtit2Kog2KXYtNix2KfZgSDYt9io2Yog2YjZiNmB2YLZi9inINmE2YTYqtmI2KzZitmH2KfY
qiAK2KfZhNi32KjZitipINin2YTZhdmG2KfYs9io2KkuCgoj2YXZiNiz2YVf2KfZhNil2YXYp9ix
2KfYqgoKMSDYr9io2YogMywzODYsOTQxINil2YXYp9ix2Kkg2K/YqNmKIDI1LjI2MzA1NsKwTiA1
NS4yOTcyMjLCsEUKMiDYo9io2YjYuNio2YogMSw4MDcsMDAwINil2YXYp9ix2Kkg2KfYqNmI2LjY
qNmKIDI0LjQ2NjY2N8KwTiA1NC4zNjY2NjfCsEUKMyDYp9mE2LTYp9ix2YLYqSAxLDI3NCw3NDkg
2KXZhdin2LHYqSDYp9mE2LTYp9ix2YLYqSAyNS4zNTc1wrBOIDU1LjM5MDgzM8KwRQo0INin2YTY
udmK2YYgNzY2LDkzNiDYpdmF2KfYsdipINin2KjZiNi42KjZiiAyNC4yMDc1wrBOIDU1Ljc0NDcy
MsKwRQo1INi52KzZhdin2YYgNDkwLDAzNSDYpdmF2KfYsdipINi52KzZhdin2YYgMjUuNDEzNjEx
wrBOIDU1LjQ0NTU1NsKwRQo2INix2KPYsyDYp9mE2K7ZitmF2KkgMTE1LDk0OSDYpdmF2KfYsdip
INix2KPYsyDYp9mE2K7ZitmF2KkgMjUuNzgzMzMzwrBOIDU1Ljk1wrBFCjcg2KfZhNmB2KzZitix
2KkgOTcsMjI2INil2YXYp9ix2Kkg2KfZhNmB2KzZitix2KkgMjUuMTIxOTI3wrBOIDU2LjM0Njg3
NsKwRQo4INin2YUg2KfZhNmC2YrZiNmK2YYgNjEsNzAwINil2YXYp9ix2Kkg2KPZhSDYp9mE2YLZ
itmI2YrZhiAyNS41NDQwOTXCsE4gNTUuNTUzMzA1wrBFCjkg2K/YqNinINin2YTZgdis2YrYsdip
IDQxLDAxNyDYpdmF2KfYsdipINin2YTZgdis2YrYsdipIDI1LjU5McKwTiA1Ni4yNsKwRQoxMCDY
rtmI2LHZgdmD2KfZhiAzOSwxNTEg2KXZhdin2LHYqSDYp9mE2LTYp9ix2YLYqSAyNS4zMzMzMzPC
sE4gNTYuMzXCsEUKMTEg2YPZhNio2KfYoSAzNyw1NDUg2KXZhdin2LHYqSDYp9mE2LTYp9ix2YLY
qSAyNS4wNzQxNjfCsE4gNTYuMzU1Mjc4wrBFCjEyINis2KjZhCDYudmE2YogMzEsNjM0INil2YXY
p9ix2Kkg2K/YqNmKIDI1LjAxMTI2wrBOIDU1LjA2MTE2wrBFCjEzINmF2K/ZitmG2Kkg2LLYp9mK
2K8gMjksMDk1INil2YXYp9ix2Kkg2KfYqNmI2LjYqNmKIDIzLjY1MjIyMsKwTiA1My42NTM2MTHC
sEUKMTQg2KfZhNix2YjZitizIDI1LDAwMCDYpdmF2KfYsdipINin2KjZiNi42KjZiiAyNC4xMDMz
MzPCsE4gNTIuNTgzNjExwrBFCjE1INmE2YrZiNinIDIwLDE5MiDYpdmF2KfYsdipINin2KjZiNi4
2KjZiiAyMy4xMzMzMzPCsE4gNTMuNzY2NjY3wrBFCjE2INin2YTYsNmK2K8gMjAsMTY1INil2YXY
p9ix2Kkg2KfZhNi02KfYsdmC2KkgMjUuMjgzMzMzwrBOIDU1Ljg4MzMzM8KwRQoxNyDYutmK2KfY
q9mKIDE0LDAyMiDYpdmF2KfYsdipINin2KjZiNi42KjZiiAyMy44NDI1wrBOIDUyLjgxwrBFCjE4
INin2YTYsdmF2LMgMTMsMDAwINil2YXYp9ix2Kkg2LHYo9izINin2YTYrtmK2YXYqSAyNS44Nzg4
ODnCsE4gNTYuMDIzNjExwrBFCjE5INiv2KjYpyDYp9mE2K3YtdmGIDEyLDU3MyDYpdmF2KfYsdip
INin2YTYtNin2LHZgtipIDI1LjYxODg4OcKwTiA1Ni4yNzMzMzPCsEUKMjAg2K3YqtinIDEyLDIw
MCDYpdmF2KfYsdipINiv2KjZiiAyNC43OTY2NjfCsE4gNTYuMTE3NcKwRQoyMSDYp9mE2YXYr9in
2YUgMTEsMTIwINil2YXYp9ix2Kkg2KfZhNi02KfYsdmC2KkgMjQuOTYxMzg5wrBOIDU1Ljc5MDI3
OMKwRQoK2KfZhNiz2LnZiNiv2YrYqSDYs9in2YrYqtmI2KrZgwoKCtin2YTYpdmF2KfYsdin2Kog
2LPYp9mK2KrZiNiq2YMKCgrYp9mE2YPZiNmK2Kog2LPYp9mK2KrZiNiq2YMKDQotLSAKWW91IHJl
Y2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29v
Z2xlIEdyb3VwcyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdy
b3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBr
YXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1
c3Npb24gb24gdGhlIHdlYiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQv
a2FzYW4tZGV2L2NhZTVhNDY0LTE0MjUtNDRjNC04NWE5LWFlMGM4MGYyN2MzMG4lNDBnb29nbGVn
cm91cHMuY29tLgo=
------=_Part_37539_658047171.1725444321216
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2KXYsNinINmD2YbYqiDYqtix2LrYqCDZgdmKINin2YTYrdi12YjZhCDYudmE2Ykg2KPZiiDZhdmG
2KrYrNin2Kog2K3YqNmI2Kgg2KfZhNin2KzZh9in2LbYjCDCoDxiciAvPsKgaHR0cHM6Ly9saW5r
dHIuZWUvY3l0b3RpY19kX251cjxiciAvPtit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTZhdiz
2KrYrtiv2YUg2YTZhNin2KzZh9in2LYhINmF2LnZhNmI2YXYp9iqINmF2YfZhdipINmK2KzYqCDZ
hdi52LHZgdiq2YfYpzo8YnIgLz7Ys9in2YrYqtmI2KrZitmDIChDeXRvdGVjKSDZh9mIINin2YTY
p9iz2YUg2KfZhNiq2KzYp9ix2Yog2YTYr9mI2KfYoSDYp9mE2YXZitiy2YjYqNix2YjYs9iq2YjZ
hCAoTWlzb3Byb3N0b2wp2Iwg2YjZh9mIINiv2YjYp9ihINmK2Y/Ys9iq2K7Yr9mFINmB2Yog2YXY
rNmF2YjYudipINmF2KrZhtmI2LnYqSDZhdmGINin2YTYrdin2YTYp9iqINin2YTYt9io2YrYqdiM
INio2YXYpyDZgdmKINiw2YTZgyDYp9mE2YjZgtin2YrYqSDZhdmGINmC2LHYrdipINin2YTZhdi5
2K/YqSDYp9mE2YbYp9iq2KzYqSDYudmGINin2LPYqtiu2K/Yp9mFINin2YTYo9iv2YjZitipINin
2YTZhdi22KfYr9ipINmE2YTYp9mE2KrZh9in2KjYp9iqINi62YrYsSDYp9mE2LPYqtmK2LHZiNmK
2K/ZitipIChOU0FJRHMp2Iwg2YjZg9iw2YTZgyDZgdmKINin2YTYpdis2YfYp9i2INin2YTYt9io
2You2YXYpyDZh9mIINiz2KfZitiq2YjYqtmDINin2YTYp9mF2KfYsdin2KrYnzxiciAvPtiz2KfZ
itiq2YjYqtmDINin2YTYp9mF2KfYsdin2Kog2YfZiCDYudio2KfYsdipINi52YYg2K/ZiNin2KEg
2YrYrdiq2YjZiiDYudmE2Ykg2KfZhNmF2KfYr9ipINin2YTZgdi52KfZhNipINmF2YrYstmI2KjY
sdmI2LPYqtmI2YQuINmK2LPYqtiu2K/ZhSDYs9in2YrYqtmI2KrZgyDZgdmKINil2KzYsdin2KEg
2KfZhNil2KzZh9in2LYg2KfZhNi32KjZiti52Yog2YTZhNit2YXZhCDZgdmKINmF2LHYp9it2YQg
2YXYqNmD2LHYqS4g2YrYudmF2YQg2LPYp9mK2KrZiNiq2YMg2LnZhiDYt9ix2YrZgiDYqtit2YHZ
itiyINi52LbZhNin2Kog2KfZhNix2K3ZhSDZhNmE2KrZgtmE2LUg2YjYp9mE2KrYrtmE2LUg2YXZ
hiDYp9mE2KzZhtmK2YYg2YjYp9mE2KPZhtiz2KzYqSDYp9mE2YXYrdmK2LfYqSDYqNmHLiDZitiq
2YjZgdixINiz2KfZitiq2YjYqtmDINin2YTYs9i52YjYr9mK2Kkg2LnZhNmJINi02YPZhCDYo9mC
2LHYp9i1INiq2KTYrtiwINi52YYg2LfYsdmK2YIg2KfZhNmB2YUuINmK2KzYqCDYp9iz2KrYrtiv
2KfZhSDYs9in2YrYqtmI2KrZgyDZiNmB2YLZi9inINmE2KrYudmE2YrZhdin2Kog2KfZhNi32KjZ
itioINmI2KfZhNis2LHYudipINin2YTZhdit2K/Yr9ipLiDZgtivINmK2KrZhSDYqtmI2KzZitmH
INin2YTZhtiz2KfYoSDYp9mE2YTZiNin2KrZiiDZitix2LrYqNmGINmB2Yog2KfYs9iq2K7Yr9in
2YUg2LPYp9mK2KrZiNiq2YMg2KXZhNmJINin2YTZgtmK2KfZhSDYqNmB2K3ZiNi12KfYqiDZiNmB
2K3ZiNi12KfYqiDYt9io2YrYqSDZgtio2YQg2KfYs9iq2K7Yr9in2YXZhyDZhNmE2KrYo9mD2K8g
2YXZhiDYs9mE2KfZhdiq2YfZhSDZiNmF2YTYp9ih2YXYqtmH2YUg2YTZhNin2LPYqtiu2K/Yp9mF
LiPZhdmI2LPZhV/Yp9mE2KfZhdin2LHYp9iqPGJyIC8+PGJyIC8+MTgxMWJjMGYtNDQ5Ni00NjMw
LWI5ZDMtMzk2NmI2ZDljNWFmLmpwZzxiciAvPtmD2YrZgSDZiti52YXZhCDYs9in2YrYqtmI2KrZ
gyDYp9mE2KfZhdin2LHYp9iq2J88YnIgLz7Ys9in2YrYqtmI2KrZgyDYp9mE2KfZhdin2LHYp9iq
INmH2Ygg2LnYqNin2LHYqSDYudmGINiv2YjYp9ihINmK2K3YqtmI2Yog2LnZhNmJINin2YTZhdin
2K/YqSDYp9mE2YHYudin2YTYqSDZhdmK2LLZiNio2LHZiNiz2KrZiNmELiDZiti52YXZhCDYs9in
2YrYqtmI2KrZgyDYudmGINi32LHZitmCINiq2K3ZgdmK2LIg2LnYttmE2KfYqiDYp9mE2LHYrdmF
INmE2YTYp9mG2YLYqNin2LYg2YjYp9mE2KrZgtmE2LXYjCDZhdmF2Kcg2YrYpNiv2Yog2KXZhNmJ
INil2KzZh9in2LYg2KfZhNit2YXZhC4g2LnZhtivINiq2YbYp9mI2YQg2LPYp9mK2KrZiNiq2YMg
2KfZhNin2YXYp9ix2KfYqtiMINmK2KrZhSDYp9iz2KrYrtiv2KfZhdmHINio2LTZg9mEINi52KfY
r9ipINmF2Lkg2K/ZiNin2KEg2KLYrtixINmK2LPZhdmJINmF2YrZgdmK2KjYsdmK2LPYqtmI2YYu
INmK2KrZhSDYqtmG2KfZiNmEINmF2YrZgdmK2KjYsdmK2LPYqtmI2YYg2KPZiNmE2KfZiyDZhNiq
2K3YttmK2LEg2KfZhNix2K3ZhSDZhNmE2KXYrNmH2KfYttiMINir2YUg2YrYqtmFINiq2YbYp9mI
2YQg2LPYp9mK2KrZiNiq2YMg2YTYqtiz2YfZitmEINin2YTYudmF2YTZitipINmI2KXZg9mF2KfZ
hCDYp9mE2KXYrNmH2KfYti48YnIgLz48YnIgLz7Zitiq2YUg2KrZhtin2YjZhCDYs9in2YrYqtmI
2KrZgyDYp9mE2KfZhdin2LHYp9iqINi52YYg2LfYsdmK2YIg2KfZhNmB2YXYjCDZiNi52KfYr9ip
INmF2Kcg2YrYqtmFINmI2LbYuSDYp9mE2KPZgtix2KfYtSDYqtit2Kog2KfZhNmE2LPYp9mGINij
2Ygg2KjZitmGINin2YTYrtivINmI2KfZhNmE2KvYqS4g2YrYrNioINin2KrYqNin2Lkg2KrYudmE
2YrZhdin2Kog2KfZhNi32KjZitioINio2K/ZgtipINio2K7YtdmI2LUg2KfZhNis2LHYudipINmI
2KfZhNiq2YjZgtmK2Kog2KfZhNmF2YbYp9iz2Kgg2YTYqtmG2KfZiNmEINin2YTYr9mI2KfYoS4g
2YrYrNioINij2YYg2YrYqtmFINin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjYqtmDINin2YTYp9mF
2KfYsdin2Kog2YHZiiDYp9mE2KPYs9in2KjZiti5INin2YTYo9mI2YTZiSDZhdmGINin2YTYrdmF
2YQg2YjYqtit2Kog2KXYtNix2KfZgSDYt9io2YrYqCDZhdiu2KrYtS4g2YLYryDZitiq2LfZhNio
INin2YTYpdis2YfYp9i2INio2KfYs9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMg2LnYr9ipINij
2YrYp9mFINmI2YLYryDZitit2KrYp9isINin2YTZhdix2YrYtiDYpdmE2Ykg2YXYqtin2KjYudip
INi32KjZitipINmE2YTYqtij2YPYryDZhdmGINmG2KzYp9itINin2YTYpdis2YfYp9i2INmI2LnY
r9mFINmI2KzZiNivINmF2LbYp9i52YHYp9iqLjxiciAvPjxiciAvPtmF2Kcg2YfZiiDYp9mE2KfY
s9iq2K7Yr9in2YXYp9iqINin2YTYtNin2KbYudipINiz2KfZitiq2YjYqtmDINin2YTYpdmF2KfY
sdin2KrYnzxiciAvPtiq2Y/Ys9iq2K7Yr9mFINiz2KfZitiq2YjYqtmDINin2YTYs9i52YjYr9mK
2Kkg2KjYtNmD2YQg2LTYp9im2Lkg2YHZiiDYpdis2LHYp9ihINin2YTYpdis2YfYp9i2INin2YTY
t9io2Yog2YHZiiDYrdin2YTYp9iqINin2YTYrdmF2YQg2LrZitixINin2YTZhdix2LrZiNioINmB
2YrZhy4g2YrZj9i52KrYqNixINiz2KfZitiq2YjYqtmDINin2YTYpdmF2KfYsdin2Kog2KPYrdiv
INin2YTYrtmK2KfYsdin2Kog2KfZhNi32KjZitipINin2YTZhdiq2KfYrdipINmE2YTZhtiz2KfY
oSDYp9mE2YTZiNin2KrZiiDZitmI2KfYrNmH2YYg2K3ZhdmE2YvYpyDYutmK2LEg2YXYsdi62YjY
qCDZgdmK2Ycg2KPZiCDYutmK2LEg2YXYs9iq2K3YqC4g2YrZj9iz2KrYrtiv2YUg2LPYp9mK2KrZ
iNiq2YMg2KfZhNil2YXYp9ix2KfYqiDYo9mK2LbZi9inINmB2Yog2K3Yp9mE2KfYqiDYp9mE2KXY
rNmH2KfYtiDYp9mE2LfYqNmKINin2YTYsNmKINmK2KrZhSDYqNmG2KfYodmLINi52YTZiSDYqtmI
2LXZitipINi32KjZitip2Iwg2YXYq9mEINmB2Yog2K3Yp9mE2KfYqiDYqti02YjZh9in2Kog2K7Z
hNmC2YrYqSDZgdmKINin2YTYrNmG2YrZhiDYo9mIINiu2LfYsSDYudmE2Ykg2LXYrdipINin2YTY
o9mFLiDYqNin2YTYpdi22KfZgdipINil2YTZiSDYsNmE2YPYjCDZitmP2LPYqtiu2K/ZhSDYs9in
2YrYqtmI2KrZgyDYp9mE2KXZhdin2LHYp9iqINmB2Yog2KjYudi2INin2YTYo9it2YrYp9mGINmE
2KXZhtmH2KfYoSDYp9mE2K3ZhdmEINmB2Yog2K3Yp9mE2KfYqiDYp9mE2K3ZhdmEINiu2KfYsdis
INin2YTYsdit2YUg2KPZiCDYp9mE2K3ZhdmEINin2YTYsNmKINmK2LTZg9mEINiu2LfYsdmL2Kcg
2LnZhNmJINit2YrYp9ipINin2YTYo9mFLjxiciAvPjxiciAvPtmF2YYg2KfZhNmF2YfZhSDYo9mG
INmK2KrZhSDYp9iz2KrYrtiv2KfZhSDYs9in2YrYqtmI2KrZgyDYp9mE2KXZhdin2LHYp9iqINiq
2K3YqiDYpdi02LHYp9mBINi32KjZiiDZiNmI2YHZgtmL2Kcg2YTZhNiq2YjYrNmK2YfYp9iqINin
2YTYt9io2YrYqSDYp9mE2YXZhtin2LPYqNipLjxiciAvPjxiciAvPiPZhdmI2LPZhV/Yp9mE2KXZ
hdin2LHYp9iqPGJyIC8+PGJyIC8+MTxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwv
c3Bhbj7Yr9io2Yo8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MywzODYs
OTQxPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtil2YXYp9ix2Kkg2K/Y
qNmKPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjI1LjI2MzA1NsKwTiA1
NS4yOTcyMjLCsEU8YnIgLz4yPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFu
Ptij2KjZiNi42KjZijxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj4xLDgw
NywwMDA8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+2KXZhdin2LHYqSDY
p9io2YjYuNio2Yo8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MjQuNDY2
NjY3wrBOIDU0LjM2NjY2N8KwRTxiciAvPjM8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsi
Pgk8L3NwYW4+2KfZhNi02KfYsdmC2Kk8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8
L3NwYW4+MSwyNzQsNzQ5PHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtil
2YXYp9ix2Kkg2KfZhNi02KfYsdmC2Kk8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8
L3NwYW4+MjUuMzU3NcKwTiA1NS4zOTA4MzPCsEU8YnIgLz40PHNwYW4gc3R5bGU9IndoaXRlLXNw
YWNlOiBwcmU7Ij4JPC9zcGFuPtin2YTYudmK2YY8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHBy
ZTsiPgk8L3NwYW4+NzY2LDkzNjxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bh
bj7YpdmF2KfYsdipINin2KjZiNi42KjZijxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+
CTwvc3Bhbj4yNC4yMDc1wrBOIDU1Ljc0NDcyMsKwRTxiciAvPjU8c3BhbiBzdHlsZT0id2hpdGUt
c3BhY2U6IHByZTsiPgk8L3NwYW4+2LnYrNmF2KfZhjxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTog
cHJlOyI+CTwvc3Bhbj40OTAsMDM1PHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9z
cGFuPtil2YXYp9ix2Kkg2LnYrNmF2KfZhjxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+
CTwvc3Bhbj4yNS40MTM2MTHCsE4gNTUuNDQ1NTU2wrBFPGJyIC8+NjxzcGFuIHN0eWxlPSJ3aGl0
ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7Ysdij2LMg2KfZhNiu2YrZhdipPHNwYW4gc3R5bGU9Indo
aXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjExNSw5NDk8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6
IHByZTsiPgk8L3NwYW4+2KXZhdin2LHYqSDYsdij2LMg2KfZhNiu2YrZhdipPHNwYW4gc3R5bGU9
IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjI1Ljc4MzMzM8KwTiA1NS45NcKwRTxiciAvPjc8
c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+2KfZhNmB2KzZitix2Kk8c3Bh
biBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+OTcsMjI2PHNwYW4gc3R5bGU9Indo
aXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtil2YXYp9ix2Kkg2KfZhNmB2KzZitix2Kk8c3BhbiBz
dHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MjUuMTIxOTI3wrBOIDU2LjM0Njg3NsKw
RTxiciAvPjg8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+2KfZhSDYp9mE
2YLZitmI2YrZhjxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj42MSw3MDA8
c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+2KXZhdin2LHYqSDYo9mFINin
2YTZgtmK2YjZitmGPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjI1LjU0
NDA5NcKwTiA1NS41NTMzMDXCsEU8YnIgLz45PHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7
Ij4JPC9zcGFuPtiv2KjYpyDYp9mE2YHYrNmK2LHYqTxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTog
cHJlOyI+CTwvc3Bhbj40MSwwMTc8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3Nw
YW4+2KXZhdin2LHYqSDYp9mE2YHYrNmK2LHYqTxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJl
OyI+CTwvc3Bhbj4yNS41OTHCsE4gNTYuMjbCsEU8YnIgLz4xMDxzcGFuIHN0eWxlPSJ3aGl0ZS1z
cGFjZTogcHJlOyI+CTwvc3Bhbj7YrtmI2LHZgdmD2KfZhjxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFj
ZTogcHJlOyI+CTwvc3Bhbj4zOSwxNTE8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8
L3NwYW4+2KXZhdin2LHYqSDYp9mE2LTYp9ix2YLYqTxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTog
cHJlOyI+CTwvc3Bhbj4yNS4zMzMzMzPCsE4gNTYuMzXCsEU8YnIgLz4xMTxzcGFuIHN0eWxlPSJ3
aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7Zg9mE2KjYp9ihPHNwYW4gc3R5bGU9IndoaXRlLXNw
YWNlOiBwcmU7Ij4JPC9zcGFuPjM3LDU0NTxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+
CTwvc3Bhbj7YpdmF2KfYsdipINin2YTYtNin2LHZgtipPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNl
OiBwcmU7Ij4JPC9zcGFuPjI1LjA3NDE2N8KwTiA1Ni4zNTUyNzjCsEU8YnIgLz4xMjxzcGFuIHN0
eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7YrNio2YQg2LnZhNmKPHNwYW4gc3R5bGU9
IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjMxLDYzNDxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFj
ZTogcHJlOyI+CTwvc3Bhbj7YpdmF2KfYsdipINiv2KjZijxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFj
ZTogcHJlOyI+CTwvc3Bhbj4yNS4wMTEyNsKwTiA1NS4wNjExNsKwRTxiciAvPjEzPHNwYW4gc3R5
bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtmF2K/ZitmG2Kkg2LLYp9mK2K88c3BhbiBz
dHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MjksMDk1PHNwYW4gc3R5bGU9IndoaXRl
LXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtil2YXYp9ix2Kkg2KfYqNmI2LjYqNmKPHNwYW4gc3R5bGU9
IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjIzLjY1MjIyMsKwTiA1My42NTM2MTHCsEU8YnIg
Lz4xNDxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7Yp9mE2LHZiNmK2LM8
c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MjUsMDAwPHNwYW4gc3R5bGU9
IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtil2YXYp9ix2Kkg2KfYqNmI2LjYqNmKPHNwYW4g
c3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjI0LjEwMzMzM8KwTiA1Mi41ODM2MTHC
sEU8YnIgLz4xNTxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7ZhNmK2YjY
pzxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj4yMCwxOTI8c3BhbiBzdHls
ZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+2KXZhdin2LHYqSDYp9io2YjYuNio2Yo8c3Bh
biBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MjMuMTMzMzMzwrBOIDUzLjc2NjY2
N8KwRTxiciAvPjE2PHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtin2YTY
sNmK2K88c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MjAsMTY1PHNwYW4g
c3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtil2YXYp9ix2Kkg2KfZhNi02KfYsdmC
2Kk8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MjUuMjgzMzMzwrBOIDU1
Ljg4MzMzM8KwRTxiciAvPjE3PHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFu
Pti62YrYp9ir2Yo8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MTQsMDIy
PHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPtil2YXYp9ix2Kkg2KfYqNmI
2LjYqNmKPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjIzLjg0MjXCsE4g
NTIuODHCsEU8YnIgLz4xODxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7Y
p9mE2LHZhdizPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFuPjEzLDAwMDxz
cGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7YpdmF2KfYsdipINix2KPYsyDY
p9mE2K7ZitmF2Kk8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHByZTsiPgk8L3NwYW4+MjUuODc4
ODg5wrBOIDU2LjAyMzYxMcKwRTxiciAvPjE5PHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7
Ij4JPC9zcGFuPtiv2KjYpyDYp9mE2K3YtdmGPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7
Ij4JPC9zcGFuPjEyLDU3MzxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7Y
pdmF2KfYsdipINin2YTYtNin2LHZgtipPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4J
PC9zcGFuPjI1LjYxODg4OcKwTiA1Ni4yNzMzMzPCsEU8YnIgLz4yMDxzcGFuIHN0eWxlPSJ3aGl0
ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7Yrdiq2Kc8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6IHBy
ZTsiPgk8L3NwYW4+MTIsMjAwPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFu
Ptil2YXYp9ix2Kkg2K/YqNmKPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4JPC9zcGFu
PjI0Ljc5NjY2N8KwTiA1Ni4xMTc1wrBFPGJyIC8+MjE8c3BhbiBzdHlsZT0id2hpdGUtc3BhY2U6
IHByZTsiPgk8L3NwYW4+2KfZhNmF2K/Yp9mFPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7
Ij4JPC9zcGFuPjExLDEyMDxzcGFuIHN0eWxlPSJ3aGl0ZS1zcGFjZTogcHJlOyI+CTwvc3Bhbj7Y
pdmF2KfYsdipINin2YTYtNin2LHZgtipPHNwYW4gc3R5bGU9IndoaXRlLXNwYWNlOiBwcmU7Ij4J
PC9zcGFuPjI0Ljk2MTM4OcKwTiA1NS43OTAyNzjCsEU8YnIgLz48YnIgLz7Yp9mE2LPYudmI2K/Z
itipINiz2KfZitiq2YjYqtmDPGJyIC8+PGJyIC8+PGJyIC8+2KfZhNil2YXYp9ix2KfYqiDYs9in
2YrYqtmI2KrZgzxiciAvPjxiciAvPjxiciAvPtin2YTZg9mI2YrYqiDYs9in2YrYqtmI2KrZgzxi
ciAvPg0KDQo8cD48L3A+CgotLSA8YnIgLz4KWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNh
dXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAmcXVvdDtrYXNhbi1k
ZXYmcXVvdDsgZ3JvdXAuPGJyIC8+ClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQg
c3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8gPGEgaHJlZj0i
bWFpbHRvOmthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tIj5rYXNhbi1kZXYr
dW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhpcyBkaXNj
dXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgPGEgaHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNv
bS9kL21zZ2lkL2thc2FuLWRldi9jYWU1YTQ2NC0xNDI1LTQ0YzQtODVhOS1hZTBjODBmMjdjMzBu
JTQwZ29vZ2xlZ3JvdXBzLmNvbT91dG1fbWVkaXVtPWVtYWlsJnV0bV9zb3VyY2U9Zm9vdGVyIj5o
dHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L2NhZTVhNDY0LTE0MjUt
NDRjNC04NWE5LWFlMGM4MGYyN2MzMG4lNDBnb29nbGVncm91cHMuY29tPC9hPi48YnIgLz4K
------=_Part_37539_658047171.1725444321216--

------=_Part_37538_1529907721.1725444321216--
