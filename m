Return-Path: <kasan-dev+bncBC46NCNX4YDRBJNSX23AMGQETRRB4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 456FD963404
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 23:39:51 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5df993bfe56sf3526eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 14:39:51 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724881190; x=1725485990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Nw/A5g3ZTDaO7QI1cftCaVtbVM9Aw5mnRpWNsaVOwQY=;
        b=Jelud3OOe6tLBkOfq9E14bZZPBEdoBXBbMAeMDaj5RRfX0iK4ZX1uvRoXoudI2CsjH
         4Ij+Qkgys4NtM6KVhMK0PhgsHhPDHkPPi1s32lh36Cr8JISFrYDGbqHnivAK85iGwa/e
         OWL1hJ/grFzI5brFfE4lDDwO+bI+MaZYiJcajvoKPTvksdZZJivN9FchimCaEIO/CNvk
         qmqK95AO0iUmGqbdrQaq+VmGd9SO3vy/80Hnnmf2ah3YyTWk4rUoGyniHT2wnlInTaca
         70juvmGShs3wsfpWqv53WTjRGVNndwG3q/r2anH3ljMhInN2B5laO3DnExdsroR3+3Sm
         hInA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724881190; x=1725485990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Nw/A5g3ZTDaO7QI1cftCaVtbVM9Aw5mnRpWNsaVOwQY=;
        b=ISlZRa09RLHJB1MgdnEv/pR64QC9lLros01SOkRUQf10wp52aM9CMR+kVbJeiO+Mam
         gISdeAUKnvC503J2Ky2mfG80wPthaz/91VqlsVcFTiyqAjqdnmbBc1W9R1snOM1HTtr2
         PblniOuaNOsVGQcdswBUlMEWuxf6inkyT+YKiv3JbWoZC18pl+0BJnHDxsQQrkZePFfV
         UEvRddQzikPmyX5mHk0EMB4guOw4rAQBVkpRUH0Ah3EJrVFqeY8ppPEf9RnbwbTOXqo1
         x3rzmHsOj6ynzJ9krk7dW++BisRkUWIDmtK2qAPXqdU1ujYkNEJkfvaOkOuqMiKoebE7
         DlCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724881190; x=1725485990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Nw/A5g3ZTDaO7QI1cftCaVtbVM9Aw5mnRpWNsaVOwQY=;
        b=McaOV3PnMDq3QAoeY16mTNrOnWbvuLfFdzidjNBMi5GzPw7+OvGJxRq2I7ZrB04KRr
         2MqVQ+gYW5s570z7LgAeF4I6ous/gzI3OOq/lN5Tj3Tkfb3hOBPnybV8xlOI3jWXLdT1
         ICvlVUYpwUDmRifUgmWKnnPCGr5dMnCmC7RwENrcuO4mctLFqjPSueN6+WJJPQH0OCi/
         dDTO9iDmLYOjAMYF99RCxAvrUhqkoEAik8IZ18F7d34upy+e51A01ZQyTAdVgOEnPw6v
         yA1kGp4yXsokY/XXtQRhWqeclERPDhZqBGRQN0RAfr7cdrF/mBCzyi0XZ8gFzFynaCtQ
         9nGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXrOgApaCQyb24izrV+xQjJlpCto15RqdysRzwy5U2glWqig5mddCBIrbK8N9GYobtLNkRgvA==@lfdr.de
X-Gm-Message-State: AOJu0YxCjzXtLPuWtJJa3zzaosv+/x0jRQlBegQPw/b+sLbGcmDszF25
	x2up+1/H5x5Quekb5bNxX5eqeKs0uFfWqSW0vV+QiAG01bcW5wUn
X-Google-Smtp-Source: AGHT+IG7+siQZGseukEks/Vig/gi6f0asgPlWZCV5e6zVsXkSBea1KQH7hUL65wTJ5O5UuEdIZJJ1Q==
X-Received: by 2002:a05:6820:994:b0:5df:81ed:2655 with SMTP id 006d021491bc7-5df97e8e8b9mr1352786eaf.1.1724881189991;
        Wed, 28 Aug 2024 14:39:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:c802:0:b0:5da:9f55:c669 with SMTP id 006d021491bc7-5df99283594ls257555eaf.2.-pod-prod-02-us;
 Wed, 28 Aug 2024 14:39:49 -0700 (PDT)
X-Received: by 2002:a05:6808:2004:b0:3d9:28e5:5865 with SMTP id 5614622812f47-3df05e381a9mr878363b6e.21.1724881188859;
        Wed, 28 Aug 2024 14:39:48 -0700 (PDT)
Date: Wed, 28 Aug 2024 14:39:48 -0700 (PDT)
From: Kerry Crook <crook9994@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <b0b05a31-7413-4362-ad0d-eff9221805bdn@googlegroups.com>
Subject: =?UTF-8?B?2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2LTYsdin2KE=?=
 =?UTF-8?B?INiv2LHYp9is2Kkg2YPZh9ix2KjYp9im2Yo=?=
 =?UTF-8?B?2Kkg2LPZiNix2YjZhiDYudio2LEg2KfZhA==?=
 =?UTF-8?B?2KXZhtiq2LHZhtiqINmB2Yog2KfZhNmD2Yg=?=
 =?UTF-8?B?2YrYqiDZiNin2YTZhdmF2YTZg9ipINin2YQ=?=
 =?UTF-8?B?2LnYsdio2YrYqSDYp9mE2LPYudmI2K/Zitip?=
 =?UTF-8?B?INmI2YLYt9ixINmI2KfZhNio2K3YsdmK2YY=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_10652_1221962077.1724881188200"
X-Original-Sender: crook9994@gmail.com
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

------=_Part_10652_1221962077.1724881188200
Content-Type: multipart/alternative; 
	boundary="----=_Part_10653_1740114418.1724881188200"

------=_Part_10653_1740114418.1724881188200
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2LTYsdin2KEg2K/Ysdin2KzYqSDZg9mH2LHY
qNin2KbZitipINiz2YjYsdmI2YYg2LnYqNixINin2YTYpdmG2KrYsdmG2Kog2YHZiiDYp9mE2YPZ
iNmK2KogCtmI2KfZhNmF2YXZhNmD2Kkg2KfZhNi52LHYqNmK2Kkg2KfZhNiz2LnZiNiv2YrYqSDZ
iNmC2LfYsSDZiNin2YTYqNit2LHZitmGCtin2KrYtdmEINio2KfZhNio2KfYpti5INi52KjYsSDY
p9mE2YjYp9iq2LMg2KfYqDogKzk3MSA1OCA2MjYgNzk4MSDYo9mIINiq2YjYp9i12YQg2LnYqNix
INin2YTYqtmE2YrYrNix2KfZhTogCkBUZXJyeWthbmVzIGh0dHBzOi8vdC5tZS8rQ09ocTJYdU5x
Y1F3TkdZeCDYs9mD2YjYqtixINmF2KrYrdix2YMg2YTZhNio2YrYuSDYudio2LEg2KfZhNil2YbY
qtix2YbYqiAK2LnYqNixINin2YTYpdmG2KrYsdmG2Kog2YHZiiDYp9mE2YPZiNmK2Kog2KfZhNmF
2YXZhNmD2Kkg2KfZhNi52LHYqNmK2Kkg2KfZhNiz2LnZiNiv2YrYqSDZgti32LEg2KfZhNio2K3Y
sdmK2YYg2KfZhNij2LHYr9mGINin2YTYpdmF2KfYsdin2KogCtin2YTYudix2KjZitipINin2YTZ
hdiq2K3Yr9ipINi52YXYp9mGINin2YTZitmF2YYg2KfZhNi52LHYp9mCINmF2LXYsSDYp9mE2YXY
utix2Kgg2KfZhNis2LLYp9im2LEg2YTZitio2YrYpyDYqtmI2YbYsyDZhNio2YbYp9mGINmG2YLY
r9mFIArZhdis2YXZiNi52Kkg2YjYp9iz2LnYqSDZhdmGINiz2YPZiNiq2LEg2KfZhNiq2YbZgtmE
INin2YTZg9mH2LHYqNin2KbZiiDZhNmE2KPYtNiu2KfYtSDYsNmI2Yog2KfZhNil2LnYp9mC2Kkg
2KPZiCDZhtmI2Lkg2YXZhiDZgtmK2YjYryAK2KfZhNit2LHZg9ipLiDZhtmC2K/ZhSDZhNi52YXZ
hNin2KbZhtinINmF2KzZhdmI2LnYqSDZiNin2LPYudipINmF2YYg2KfZhNmF2YjYr9mK2YTYp9iq
INiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEIC0g2YXYqtmI2LPYtyAK4oCL4oCL2KfZhNit2KzZhSDZ
iNmF2KrZitmGINmF2Kcg2YfZiiDYs9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPYqNmK2LHY
qdifCtiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin2YTZg9io2YrYsdiMINin2YTZhdi52LHZiNmB
INij2YrYttmL2Kcg2KjYp9iz2YUg2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNir2YLZitmE
INij2YggItin2YTZg9io2YrYsSLYjCDZh9mIIArZhdix2YPYqNin2Kog2YLZiNmK2Kkg2YjZhdiq
2YrZhtipINmF2LXZhdmF2Kkg2YTYp9iz2KrZiti52KfYqCDYp9mE2YXYs9iq2K7Yr9mF2YrZhiDY
p9mE2LDZitmGINmC2K8g2YrZg9mI2YYg2YTYr9mK2YfZhSDYp9it2KrZitin2KzYp9iqIArYqtmG
2YLZhCDZhdit2K/Yr9ipLiDYqtmFINiq2LXZhdmK2YUg2YfYsNmHINin2YTYs9mD2YjYqtixINmF
2YYg2KPYrNmEINin2YTYq9io2KfYqiDZiNin2YTZhdiq2KfZhtipINmI2KfZhNiq2YbZiNi52Iwg
2YXZhdinINmK2KzYudmE2YfYpyAK2YXZhtin2LPYqNipINmE2YTYp9iz2KrYrtiv2KfZhSDYp9mE
2K/Yp9iu2YTZiiDZiNin2YTYrtin2LHYrNmKLiDYpdmG2YfYpyDZhdir2KfZhNmK2Kkg2YTZhNij
2YHYsdin2K8g2KfZhNiw2YrZhiDZiti52KfZhtmI2YYg2YXZhiAK2K/Ysdis2KfYqiDZhdiq2YHY
p9mI2KrYqSDZhdmGINiq2K3Yr9mK2KfYqiDYp9mE2KrZhtmC2YQuCtin2YTZgdmE2KfYqtixCtmF
2Kcg2YfZiiDYs9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPYqNmK2LHYqdifCiDYqtmP2LnY
sdmBINin2YTYr9ix2KfYrNin2Kog2KfZhNio2K7Yp9ix2YrYqSDYp9mE2YPYqNmK2LHYqSDYp9mE
2YXYqtit2LHZg9ipINij2YrYttmL2Kcg2KjYp9iz2YUg2KfZhNiv2LHYp9is2KfYqiDYp9mE2KjY
rtin2LHZitipIArYp9mE2KvZgtmK2YTYqSDYo9mIICLYp9mE2YPYqNmK2LHYqSLYjCDZiNmH2Yog
2YXYsdmD2KjYp9iqINmC2YjZitipINmI2YXYqtmK2YbYqSDZhdi12YXZhdipINmE2KfYs9iq2YrY
udin2Kgg2KfZhNmF2LPYqtiu2K/ZhdmK2YYgCtin2YTYsNmK2YYg2YLYryDZitmD2YjZhiDZhNiv
2YrZh9mFINin2K3YqtmK2KfYrNin2Kog2K3YsdmD2YrYqSDZhdit2K/Yr9ipLiDYqtmFINiq2LXZ
hdmK2YUg2YfYsNmHINin2YTYr9ix2KfYrNin2Kog2KfZhNio2K7Yp9ix2YrYqSAK2YTYqtit2YLZ
itmCINin2YTYp9iz2KrZgtix2KfYsSDZiNin2YTZhdiq2KfZhtipINmI2KfZhNiq2YbZiNi52Iwg
2YXZhdinINmK2KzYudmE2YfYpyDZhdmG2KfYs9io2Kkg2YTZhNin2LPYqtiu2K/Yp9mFINin2YTY
r9in2K7ZhNmKIArZiNin2YTYrtin2LHYrNmKLiDZiNmH2Yog2YXYq9in2YTZitipINmE2YTYo9mB
2LHYp9ivINin2YTYsNmK2YYg2YrYudin2YbZiNmGINmF2YYg2K/Ysdis2KfYqiDZhdiq2YHYp9mI
2KrYqSDZhdmGINiq2K3Yr9mK2KfYqiDYp9mE2K3YsdmD2KkuCtin2YTZgdmE2KfYqtixCtil2LjZ
h9in2LEgMeKAkzE4INmF2YYgMzgg2YbYqtmK2KzYqQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBt
ZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJr
YXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3Ag
cmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1
YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiBvbiB0aGUg
d2ViIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvYjBi
MDVhMzEtNzQxMy00MzYyLWFkMGQtZWZmOTIyMTgwNWJkbiU0MGdvb2dsZWdyb3Vwcy5jb20uCg==
------=_Part_10653_1740114418.1724881188200
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2LTYsdin2KEg2K/Ysdin2KzYqSDZg9mH2LHY
qNin2KbZitipINiz2YjYsdmI2YYg2LnYqNixINin2YTYpdmG2KrYsdmG2Kog2YHZiiDYp9mE2YPZ
iNmK2Kog2YjYp9mE2YXZhdmE2YPYqSDYp9mE2LnYsdio2YrYqSDYp9mE2LPYudmI2K/ZitipINmI
2YLYt9ixINmI2KfZhNio2K3YsdmK2YY8YnIgLz48ZGl2Ptin2KrYtdmEINio2KfZhNio2KfYpti5
INi52KjYsSDYp9mE2YjYp9iq2LMg2KfYqDogKzk3MSA1OCA2MjYgNzk4MSDYo9mIINiq2YjYp9i1
2YQg2LnYqNixINin2YTYqtmE2YrYrNix2KfZhTogQFRlcnJ5a2FuZXMgaHR0cHM6Ly90Lm1lLytD
T2hxMlh1TnFjUXdOR1l4INiz2YPZiNiq2LEg2YXYqtit2LHZgyDZhNmE2KjZiti5INi52KjYsSDY
p9mE2KXZhtiq2LHZhtiqINi52KjYsSDYp9mE2KXZhtiq2LHZhtiqINmB2Yog2KfZhNmD2YjZitiq
INin2YTZhdmF2YTZg9ipINin2YTYudix2KjZitipINin2YTYs9i52YjYr9mK2Kkg2YLYt9ixINin
2YTYqNit2LHZitmGINin2YTYo9ix2K/ZhiDYp9mE2KXZhdin2LHYp9iqINin2YTYudix2KjZitip
INin2YTZhdiq2K3Yr9ipINi52YXYp9mGINin2YTZitmF2YYg2KfZhNi52LHYp9mCINmF2LXYsSDY
p9mE2YXYutix2Kgg2KfZhNis2LLYp9im2LEg2YTZitio2YrYpyDYqtmI2YbYsyDZhNio2YbYp9mG
INmG2YLYr9mFINmF2KzZhdmI2LnYqSDZiNin2LPYudipINmF2YYg2LPZg9mI2KrYsSDYp9mE2KrZ
htmC2YQg2KfZhNmD2YfYsdio2KfYptmKINmE2YTYo9i02K7Yp9i1INiw2YjZiiDYp9mE2KXYudin
2YLYqSDYo9mIINmG2YjYuSDZhdmGINmC2YrZiNivINin2YTYrdix2YPYqS4g2YbZgtiv2YUg2YTY
udmF2YTYp9im2YbYpyDZhdis2YXZiNi52Kkg2YjYp9iz2LnYqSDZhdmGINin2YTZhdmI2K/ZitmE
2KfYqiDYs9mD2YjYqtixINin2YTYqtmG2YLZhCAtINmF2KrZiNiz2Lcg4oCL4oCL2KfZhNit2KzZ
hSDZiNmF2KrZitmGINmF2Kcg2YfZiiDYs9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPYqNmK
2LHYqdifPGJyIC8+2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNmD2KjZitix2Iwg2KfZhNmF
2LnYsdmI2YEg2KPZiti22YvYpyDYqNin2LPZhSDYs9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE
2KvZgtmK2YQg2KPZiCAi2KfZhNmD2KjZitixItiMINmH2Ygg2YXYsdmD2KjYp9iqINmC2YjZitip
INmI2YXYqtmK2YbYqSDZhdi12YXZhdipINmE2KfYs9iq2YrYudin2Kgg2KfZhNmF2LPYqtiu2K/Z
hdmK2YYg2KfZhNiw2YrZhiDZgtivINmK2YPZiNmGINmE2K/ZitmH2YUg2KfYrdiq2YrYp9is2KfY
qiDYqtmG2YLZhCDZhdit2K/Yr9ipLiDYqtmFINiq2LXZhdmK2YUg2YfYsNmHINin2YTYs9mD2YjY
qtixINmF2YYg2KPYrNmEINin2YTYq9io2KfYqiDZiNin2YTZhdiq2KfZhtipINmI2KfZhNiq2YbZ
iNi52Iwg2YXZhdinINmK2KzYudmE2YfYpyDZhdmG2KfYs9io2Kkg2YTZhNin2LPYqtiu2K/Yp9mF
INin2YTYr9in2K7ZhNmKINmI2KfZhNiu2KfYsdis2YouINil2YbZh9inINmF2KvYp9mE2YrYqSDZ
hNmE2KPZgdix2KfYryDYp9mE2LDZitmGINmK2LnYp9mG2YjZhiDZhdmGINiv2LHYrNin2Kog2YXY
qtmB2KfZiNiq2Kkg2YXZhiDYqtit2K/Zitin2Kog2KfZhNiq2YbZgtmELjxiciAvPtin2YTZgdmE
2KfYqtixPGJyIC8+2YXYpyDZh9mKINiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin2YTZg9io2YrY
sdip2J88YnIgLz7CoNiq2Y/Yudix2YEg2KfZhNiv2LHYp9is2KfYqiDYp9mE2KjYrtin2LHZitip
INin2YTZg9io2YrYsdipINin2YTZhdiq2K3YsdmD2Kkg2KPZiti22YvYpyDYqNin2LPZhSDYp9mE
2K/Ysdin2KzYp9iqINin2YTYqNiu2KfYsdmK2Kkg2KfZhNir2YLZitmE2Kkg2KPZiCAi2KfZhNmD
2KjZitix2Kki2Iwg2YjZh9mKINmF2LHZg9io2KfYqiDZgtmI2YrYqSDZiNmF2KrZitmG2Kkg2YXY
tdmF2YXYqSDZhNin2LPYqtmK2LnYp9ioINin2YTZhdiz2KrYrtiv2YXZitmGINin2YTYsNmK2YYg
2YLYryDZitmD2YjZhiDZhNiv2YrZh9mFINin2K3YqtmK2KfYrNin2Kog2K3YsdmD2YrYqSDZhdit
2K/Yr9ipLiDYqtmFINiq2LXZhdmK2YUg2YfYsNmHINin2YTYr9ix2KfYrNin2Kog2KfZhNio2K7Y
p9ix2YrYqSDZhNiq2K3ZgtmK2YIg2KfZhNin2LPYqtmC2LHYp9ixINmI2KfZhNmF2KrYp9mG2Kkg
2YjYp9mE2KrZhtmI2LnYjCDZhdmF2Kcg2YrYrNi52YTZh9inINmF2YbYp9iz2KjYqSDZhNmE2KfY
s9iq2K7Yr9in2YUg2KfZhNiv2KfYrtmE2Yog2YjYp9mE2K7Yp9ix2KzZii4g2YjZh9mKINmF2KvY
p9mE2YrYqSDZhNmE2KPZgdix2KfYryDYp9mE2LDZitmGINmK2LnYp9mG2YjZhiDZhdmGINiv2LHY
rNin2Kog2YXYqtmB2KfZiNiq2Kkg2YXZhiDYqtit2K/Zitin2Kog2KfZhNit2LHZg9ipLjxiciAv
Ptin2YTZgdmE2KfYqtixPGJyIC8+2KXYuNmH2KfYsSAx4oCTMTgg2YXZhiAzOCDZhtiq2YrYrNip
PGJyIC8+PC9kaXY+DQoNCjxwPjwvcD4KCi0tIDxiciAvPgpZb3UgcmVjZWl2ZWQgdGhpcyBtZXNz
YWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICZxdW90
O2thc2FuLWRldiZxdW90OyBncm91cC48YnIgLz4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdy
b3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byA8
YSBocmVmPSJtYWlsdG86a2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20iPmth
c2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tPC9hPi48YnIgLz4KVG8gdmlldyB0
aGlzIGRpc2N1c3Npb24gb24gdGhlIHdlYiB2aXNpdCA8YSBocmVmPSJodHRwczovL2dyb3Vwcy5n
b29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L2IwYjA1YTMxLTc0MTMtNDM2Mi1hZDBkLWVmZjky
MjE4MDViZG4lNDBnb29nbGVncm91cHMuY29tP3V0bV9tZWRpdW09ZW1haWwmdXRtX3NvdXJjZT1m
b290ZXIiPmh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvYjBiMDVh
MzEtNzQxMy00MzYyLWFkMGQtZWZmOTIyMTgwNWJkbiU0MGdvb2dsZWdyb3Vwcy5jb208L2E+Ljxi
ciAvPgo=
------=_Part_10653_1740114418.1724881188200--

------=_Part_10652_1221962077.1724881188200--
