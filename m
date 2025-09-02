Return-Path: <kasan-dev+bncBDA2XNWCVILRBLUA3LCQMGQECW6VNDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DAFBB3F47D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 07:27:12 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-74381e1e0casf5682942a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 22:27:12 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756790830; x=1757395630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4B2ACVwsSSprzCoCyzcOcZ4a5IJXn/gv2eEGtuwaLzM=;
        b=HZcEATwvBrpZRnGhdb7YV4hUFwVOWyHR5pMc6zAVrsWgW/BQEpyD28W1/RMjT/kFns
         nKL1izdpv4AeJR56XHjkbZ1VeCgsezNRhgumW0DDPIHb4FXzNkrSW9H60uF3zTd2b5yz
         ztMflKnE8Aeh1LQUFDGQTStKAxLOTLAc3LmIbVJzrmK7Ts8mYdmXsgiSXjh1Ztdjdvs9
         5HGZ4Ucnf7V1XnprpaQ9hNwHcLep4PLp9qAlSlThOmV/mDYnwKnZJGxjqBCJZgB+6F52
         eI4G4T0KoNQtMxmPo5x4CGjGlgBoBzD42Uy5Qw8ehM825Q/PCiBYfbB4l8DOZ76Grjvs
         be2g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756790830; x=1757395630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4B2ACVwsSSprzCoCyzcOcZ4a5IJXn/gv2eEGtuwaLzM=;
        b=R1unHIiH4FcIowI29hoIHr0bB5FfP5GaJjl7mHLmfieOMKDYmQejGvJDbyJhlWyy9U
         zcAUlUsFjYO7j8qy+5J9ivHrvb0EmXDzmlvF6H8soWj+jDeYOpxaWgqf9mLpqHUAab/n
         ersf8jEEuVN8oZQyV3WmtGvn9QMT41Gk2uvwC4XaUBgmVELCzqWnzyppsd82jNBcdJCb
         s9S7ziT5jIeODrVLUA+6RV5+gQ6mDfOuDdznHP+0Ta3dxNRDOgjd7SpqFEgzu3lcIni9
         kwUPBRM6aAcxxa+cvYG85jTkCgENM0fdLGqdczSUKJD9UlRmoA/N3b0zviN68IHdRb0m
         W1Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756790830; x=1757395630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4B2ACVwsSSprzCoCyzcOcZ4a5IJXn/gv2eEGtuwaLzM=;
        b=eWSdx3vDcNEFomeclzZ9DB6JhQMCsezACSXbzD5WddJc1eQA4jTD/UF9oBpBC/+xiy
         amuHTtVJTXcwsEaZQZzM74naNZOmMmW4IfmctQP/vLbods1MSzMKL5MXnnyy44QQRmu0
         UJxDnBwQx1qU8hRC4OVRxkdQH5xq/LyaacRZco6RqNGMr/+vL3+czy7MexK8PAAzMP3j
         V5qGfJk5txJVBuGTsXr5gBI08SPOPGCNpmQTHaRViVTU+/1562056jn5xNuRZrnSRica
         rdkWvmHhlyscYhu+9rivZYyzsXV4uN1RQd35NZ3MgsvPV+jcRdT/PAYFNG7WBKYpkB9X
         sYqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCU48rpAc/YI5cY3jNMiIQaTu0Qdy+VjwNy+yiG0VWQiB+a6XTY/kgAHHBGP04E8ScV0yKdYZg==@lfdr.de
X-Gm-Message-State: AOJu0Yz5hkfzfx4C12Rz/GG5e0TOyEFpxe+1AHf05W2BKXGJvZwhjJRj
	no1h7ylP0YKfGufpxa1IIiE9MQv1EQc2E6B0IM1lYqOgOVe8jHvC2YhY
X-Google-Smtp-Source: AGHT+IGs7/Jd+ffuXCddLxmC2fJ67LFIpCYXXQw72BghlmpD1lJCBuT7q/YYl3xkmKZyndhRAgO99g==
X-Received: by 2002:a05:6830:34aa:b0:745:2822:6b69 with SMTP id 46e09a7af769-74569e8524amr5167707a34.27.1756790830547;
        Mon, 01 Sep 2025 22:27:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfAtFhABO0jtw1Egr9kqXTfWLqGN46aZpd9b0LdxN5C+Q==
Received: by 2002:a05:6820:26c3:b0:61b:3fc1:70f6 with SMTP id
 006d021491bc7-61e1241321fls338570eaf.2.-pod-prod-00-us-canary; Mon, 01 Sep
 2025 22:27:09 -0700 (PDT)
X-Received: by 2002:a05:6808:21a8:b0:437:b5a0:ca7b with SMTP id 5614622812f47-437f7d633f2mr5203166b6e.12.1756790829696;
        Mon, 01 Sep 2025 22:27:09 -0700 (PDT)
Date: Mon, 1 Sep 2025 22:27:08 -0700 (PDT)
From: =?UTF-8?B?2LPZitiv2Kkg2KzYr9ipINin2YTYs9i52YjYr9mK2Kk=?=
 <memosksaa@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <f88fbac3-0fba-4553-9597-d4f5dc971f40n@googlegroups.com>
In-Reply-To: <4c7a091b-8b8d-460d-be14-d40f9b46141dn@googlegroups.com>
References: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
 <89767b6b-298f-4668-8566-a7fdcf18be3bn@googlegroups.com>
 <4c7a091b-8b8d-460d-be14-d40f9b46141dn@googlegroups.com>
Subject: =?UTF-8?B?UmU6INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNix2YrYp9i2?=
 =?UTF-8?B?IDA1Mzc0NjY1MzkgI9in2YTYs9i52YjYr9mK2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_73764_1507784103.1756790828919"
X-Original-Sender: memosksaa@gmail.com
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

------=_Part_73764_1507784103.1756790828919
Content-Type: multipart/alternative; 
	boundary="----=_Part_73765_1190502520.1756790828919"

------=_Part_73765_1190502520.1756790828919
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YXZg9in2YYg2KjZiti5INiz2KfZitiq2YjYqtmK2YMgLyAwNTM4MTU5NzQ3IC8gIEN5dG90ZWMg
2KfZhNmD2YjZitiqIGFtYXpvbi5zYSAvLyAvLyAg2K/ZiNin2KEgCtin2YTYpdis2YfYp9i2INmB
2Yog2KfZhNix2YrYp9i2ICAg2KfZhNil2KzZh9in2LYg2KfZhNiv2YjYp9im2YogICDYp9mE2KPY
r9mI2YrYqSDYp9mE2LfYqNmK2Kkg2YTYpdmG2YfYp9ihINin2YTYrdmF2YQgICAK2YXZitiy2YjY
qNix2YjYs9iq2YjZhCAoTWlzb3Byb3N0b2wpICAg2LPYp9mK2KrZiNiq2YMgQ3l0b3RlYyAgINil
2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE2YXYqNmD2LEgICDYo9iv2YjZitipIArYp9mE2KXYrNmH
2KfYtiDYp9mE2KPZhdmG2KkgICDYp9mE2LnZhNin2Kwg2KfZhNiv2YjYp9im2Yog2YTZhNit2YXZ
hCDYutmK2LHYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYsdmK2KfYtiAvLyAKMDA5NjY1MzgxNTk3
NDcgLy8g2KjYp9mB2LbZhCDYs9i52LEg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNin2KzZ
h9in2LYg2KfZhNmF2YbYstmE2Yog2YTZhdmI2YLYuSDYp9mE2LHYs9mF2Yp8IArYp9mE2K/Zgdi5
INi52YbYryDYp9mE2KfYs9iq2YTYp9mFINmB2Yog2KfZhNix2YrYp9i2INmE2YTYqNmK2LkKCtiz
2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqSDDlyDYs9in2YrYqtmI2KrZgyDYqNin
2YTYsdmK2KfYtiDDlyDYs9in2YrYqtmI2KrZgyDYp9mE2K/Zhdin2YUgw5cg2LPYp9mK2KrZiNiq
2YMg2K7ZhdmK2LMg2YXYtNmK2LcgCsOXINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNmD2YjZitiq
IMOXINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNio2K3YsdmK2YYgw5cg2KPYr9mI2YrYqSDYpdis
2YfYp9i2INin2YTYrdmF2YQgw5cg2YXZitiy2YjYqNix2LPYqtmI2YQgw5cgCtij2LnYsdin2LYg
2KfZhNit2YXZhCDDlyDYs9in2YrYqtmI2KrZitmDINmB2Yog2YXZg9ipIMOXINi52YrYp9iv2KfY
qiDYp9is2YfYp9i2IMOXINiv2YPYqtmI2LHYqSDYp9is2YfYp9i2INmB2Yog2KfZhNiz2LnZiNiv
2YrYqSDDlyAK2K/Zg9iq2YjYsdipINin2KzZh9in2LYg2YHZiiDYp9mE2YPZiNmK2Kogw5cg2K/Z
g9iq2YjYsdipINin2KzZh9in2LYg2YHZiiDYp9mE2KjYrdix2YrZhiDDlyDYr9mD2KrZiNix2Kkg
2KfYrNmH2KfYtiDZgdmKINin2YTYpdmF2KfYsdin2KogCsOXINiv2YPYqtmI2LHYqSDDlyDYp9mE
2K/ZiNix2Kkg2KfZhNi02YfYsdmK2KkKCtmB2Yog2KfZhNiz2KjYqtiMIDMwINij2LrYs9i32LMg
MjAyNSDZgdmKINiq2YXYp9mFINin2YTYs9in2LnYqSAxMTowNzowOCDZhSBVVEMtN9iMINmD2KrY
qCDYs9mK2K/YqSDYrNiv2KkgCtin2YTYs9i52YjYr9mK2Kkg2LHYs9in2YTYqSDZhti12YfYpzoK
Cj4g2YXZg9in2YYg2KjZiti5INiz2KfZitiq2YjYqtmK2YMgLyAwNTM4MTU5NzQ3IC8gIEN5dG90
ZWMg2KfZhNmD2YjZitiqIGFtYXpvbi5zYSAvLyAvLyAg2K/ZiNin2KEgCj4g2KfZhNil2KzZh9in
2LYg2YHZiiDYp9mE2LHZitin2LYgICDYp9mE2KXYrNmH2KfYtiDYp9mE2K/ZiNin2KbZiiAgINin
2YTYo9iv2YjZitipINin2YTYt9io2YrYqSDZhNil2YbZh9in2KEg2KfZhNit2YXZhCAgIAo+INmF
2YrYstmI2KjYsdmI2LPYqtmI2YQgKE1pc29wcm9zdG9sKSAgINiz2KfZitiq2YjYqtmDIEN5dG90
ZWMgICDYpdmG2YfYp9ihINin2YTYrdmF2YQg2KfZhNmF2KjZg9ixICAg2KPYr9mI2YrYqSAKPiDY
p9mE2KXYrNmH2KfYtiDYp9mE2KPZhdmG2KkgICDYp9mE2LnZhNin2Kwg2KfZhNiv2YjYp9im2Yog
2YTZhNit2YXZhCDYutmK2LHYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYsdmK2KfYtiAvLyAwMDk2
NjUzODE1OTc0NyAKPiAvLyDYqNin2YHYttmEINiz2LnYsSDYrdio2YjYqCDYs9in2YrYqtmI2KrZ
gyDYp9mE2KfYrNmH2KfYtiDYp9mE2YXZhtiy2YTZiiDZhNmF2YjZgti5INin2YTYsdiz2YXZinwg
2KfZhNiv2YHYuSDYudmG2K8g2KfZhNin2LPYqtmE2KfZhSAKPiDZgdmKINin2YTYsdmK2KfYtiDZ
hNmE2KjZiti5Cj4g2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/ZitipIMOXINiz2KfZ
itiq2YjYqtmDINio2KfZhNix2YrYp9i2IMOXINiz2KfZitiq2YjYqtmDINin2YTYr9mF2KfZhSDD
lyDYs9in2YrYqtmI2KrZgyDYrtmF2YrYsyDZhdi02YrYtyAKPiDDlyDYs9in2YrYqtmI2KrZgyDZ
gdmKINin2YTZg9mI2YrYqiDDlyDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYqNit2LHZitmGIMOX
INij2K/ZiNmK2Kkg2KXYrNmH2KfYtiDYp9mE2K3ZhdmEIMOXINmF2YrYstmI2KjYsdiz2KrZiNmE
IMOXIAo+INij2LnYsdin2LYg2KfZhNit2YXZhCDDlyDYs9in2YrYqtmI2KrZitmDINmB2Yog2YXZ
g9ipIMOXINi52YrYp9iv2KfYqiDYp9is2YfYp9i2IMOXINiv2YPYqtmI2LHYqSDYp9is2YfYp9i2
INmB2Yog2KfZhNiz2LnZiNiv2YrYqSDDlyAKPiDYr9mD2KrZiNix2Kkg2KfYrNmH2KfYtiDZgdmK
INin2YTZg9mI2YrYqiDDlyDYr9mD2KrZiNix2Kkg2KfYrNmH2KfYtiDZgdmKINin2YTYqNit2LHZ
itmGIMOXINiv2YPYqtmI2LHYqSDYp9is2YfYp9i2INmB2Yog2KfZhNil2YXYp9ix2KfYqiAKPiDD
lyDYr9mD2KrZiNix2Kkgw5cg2KfZhNiv2YjYsdipINin2YTYtNmH2LHZitipCj4KPiDZgdmKINin
2YTYp9ir2YbZitmG2IwgMjUg2KPYutiz2LfYsyAyMDI1INmB2Yog2KrZhdin2YUg2KfZhNiz2KfY
udipIDQ6MDY6Mjkg2LUgVVRDLTfYjCDZg9iq2Kgg2LPYp9mK2KrZiNiq2YMgCj4g2KfZhNiz2LnZ
iNiv2YrZhyDYs9in2YrYqtmI2KrZgyDYqNiu2LXZhSAyMCUg2LHYs9in2YTYqSDZhti12YfYpzoK
Pgo+Pgo+PiDYr9mD2KrZiNix2Kkg2KfYrNmH2KfYtiDZgdmKINin2YTYs9i52YjYr9mK2YcgfCAw
MDk2NjUzODE1OTc0NyB82LnZitin2K/YqSDYs9in2YrYqtmI2KrZgyAKPj4KPj4gINiv2YPYqtmI
2LHYqSDZhtmK2LHZhdmK2YYg2YTZhNin2LPYqti02KfYsdin2Kog2KfZhNi32KjZitipCj4+INit
2KjZiNioINin2YTYp9is2YfYp9i2IOKAkyDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjY
r9mK2KkgIHwg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiAwMDk2NjUzODE1OTc0NyDigJMgCj4+
INin2LPYqti02KfYsdin2Kog2YjYudmE2KfYrCDYotmF2YYKPj4g2KrYudix2YHZiiDYudmE2Ykg
2YPZhCDZhdinINmK2YfZhdmDINi52YYg2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2Iwg2LPYp9mK
2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/ZitmHIAo+PiA8aHR0cHM6Ly9oYXlhdGFubmFzLmNv
bS8/c3JzbHRpZD1BZm1CT29vclhUdjZ3Y3RiWTdvQ2JkX3pSQk14TkRQbVQwRjVEUFJ3ek1pZkNN
Z0RETk5wMWNiVj4gCj4+INin2YTYsdmK2KfYttiMINis2K/YqdiMINmF2YPYqdiMINis2KfYstin
2YbYjCDZiNiu2YXZitizINmF2LTZiti32Iwg2YXYuSDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmG
INmE2YTYp9iz2KrYtNin2LHYp9iqINin2YTYt9io2YrYqSAKPj4g2YjYt9mE2Kgg2KfZhNi52YTY
p9isINio2LPYsdmK2Kkg2KrYp9mF2KkuCj4+INiq2K3YsNmK2LHYp9iqINmF2YfZhdipCj4+Cj4+
INmK2YXZhti5INin2LPYqtiu2K/Yp9mFINit2KjZiNioINiz2KfZitiq2YjYqtmDINmB2Yog2K3Y
p9mE2KfYqiDYp9mE2K3ZhdmEINin2YTZhdiq2YLYr9mFINio2LnYryDYp9mE2KPYs9io2YjYuSAx
MiDYpdmE2Kcg2KjYo9mF2LEgCj4+INin2YTYt9io2YrYqCDZiNin2YTYp9iz2KrZhdin2Lkg2KfZ
hNmKINiq2YjYrNmK2YfYp9iq2YcgLgo+Pgo+Pgo+PiAg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg
fCAwMDk2NjUzODE1OTc0NyAgfCDZgdmKINin2YTYs9i52YjYr9mK2Kkg4oCTINiv2YPYqtmI2LHY
qSDZhtmK2LHZhdmK2YYg2YTZhNin2LPYqti02KfYsdin2KogCj4+INin2YTYt9io2YrYqSDYp9mE
2KXYrNmH2KfYtiAgCj4+Cj4+INmB2Yog2KfZhNiz2YbZiNin2Kog2KfZhNij2K7Zitix2KnYjCDY
o9i12KjYrSDZhdmI2LbZiNi5INit2KjZiNioINin2YTYp9is2YfYp9i2INiz2KfZitiq2YjYqtmD
IAo+PiA8aHR0cHM6Ly9zYXVkaWVyc2FhLmNvbS8+INmB2Yog2KfZhNiz2LnZiNiv2YrYqSDZhdmG
INij2YPYq9ixINin2YTZhdmI2KfYttmK2Lkg2KfZhNiq2Yog2KrYqNit2Ksg2LnZhtmH2KcgCj4+
INin2YTYs9mK2K/Yp9iq2Iwg2K7Yp9i12Kkg2YHZiiDZhdiv2YYg2YXYq9mEINin2YTYsdmK2KfY
ttiMINis2K/YqdiMINmF2YPYqdiMINis2KfYstin2YbYjCDZiNiu2YXZitizINmF2LTZiti32Iwg
2YjZg9iw2YTZgyDZgdmKIAo+PiDZhdmG2KfYt9mCINin2YTYrtmE2YrYrCDZhdir2YQg2KfZhNio
2K3YsdmK2YYg2YjYp9mE2YPZiNmK2Kog2YjYp9mE2LTYp9ix2YLYqS4g2YbYuNix2YvYpyDZhNit
2LPYp9iz2YrYqSDYp9mE2YXZiNi22YjYuSDZiNij2YfZhdmK2KrZh9iMIAo+PiDYqtmC2K/ZhSDY
r9mD2KrZiNix2Kkg2YbZitix2YXZitmGINin2YTYr9i52YUg2KfZhNi32KjZiiDZiNin2YTYp9iz
2KrYtNin2LHYp9iqINin2YTZhdiq2K7Ytdi12Kkg2YTZhNmG2LPYp9ihINin2YTZhNmI2KfYqtmK
INmK2K3Yqtis2YYgCj4+INil2YTZiSDYp9mE2KrZiNis2YrZhyDYp9mE2LXYrdmK2K0g2YjYt9mE
2Kgg2KfZhNi52YTYp9isINmF2YYg2YXYtdiv2LEg2YXZiNir2YjZgtiMINi52KjYsSDYp9mE2KfY
qti12KfZhCDYudmE2Ykg2KfZhNix2YLZhTogMDA5NjY1MzgxNTk3NDcgCj4+IC4KPj4KPj4gLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4+Cj4+INmF2Kcg2YfZiiDYrdio2YjYqCDYs9in
2YrYqtmI2KrZgyDZhNmE2KfYrNmH2KfYttifCj4+Cj4+INit2KjZiNioINiz2KfZitiq2YjYqtmD
IChDeXRvdGVjKSDYqtit2KrZiNmKINi52YTZiSDYp9mE2YXYp9iv2Kkg2KfZhNmB2LnYp9mE2Kkg
2KfZhNmF2YrYstmI2KjYsdmI2LPYqtmI2YQgCj4+IChNaXNvcHJvc3RvbCnYjCDZiNmH2Yog2K/Z
iNin2KEg2YXYudiq2YXYryDYt9io2YrZi9inINmE2LnZhNin2Kwg2YLYsdit2Kkg2KfZhNmF2LnY
r9ipINmB2Yog2KfZhNij2LXZhNiMINmE2YPZhiDYp9mE2KPYqNit2KfYqyAKPj4g2KfZhNi32KjZ
itipINij2KvYqNiq2Kog2YHYp9i52YTZitiq2Ycg2YHZiiDYpdmG2YfYp9ihINin2YTYrdmF2YQg
2KfZhNmF2KjZg9ixIAo+PiA8aHR0cHM6Ly9oYXlhdGFubmFzLmNvbS8/c3JzbHRpZD1BZm1CT29v
OFpkTnZFWlVwZzNEZGZXdFpOVVJLQXB6V2dzWEhxd21nc0pkSEo2OFFVX3hnT3VnUz4gCj4+INiq
2K3YqiDYpdi02LHYp9mBINi32KjZii4KPj4g2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2YrYqtmF
INin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjYqtmDINmB2Yog2K3Yp9mE2KfYqiDYrtin2LXYqSDZ
iCDYqNis2LHYudin2Kog2YXYrdiv2K/YqSDZitmC2LHYsdmH2KcgCj4+INin2YTYt9io2YrYqNiM
INmF2Lkg2LbYsdmI2LHYqSDYp9mE2KrYo9mD2K8g2YXZhiDYrNmI2K/YqSDYp9mE2YXZhtiq2Kwg
2YjZhdi12K/YsdmHLgo+Pgo+PiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPj4KPj4g
2YXYqtmJINiq2LPYqtiu2K/ZhSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KXYrNmH2KfY
ttifCj4+ICAgIAo+PiAgICAtIAo+PiAgICAKPj4gICAg2KfZhNil2KzZh9in2LYg2KfZhNmF2KjZ
g9ixOiDYrdiq2Ykg2KfZhNij2LPYqNmI2LkgMTIg2YXZhiDYp9mE2K3ZhdmELgo+PiAgICAKPj4g
ICAgLSAKPj4gICAgCj4+ICAgINi52YbYryDZiNis2YjYryDYqti02YjZh9in2Kog2KzZhtmK2YbZ
itipINiu2LfZitix2KkuCj4+ICAgIAo+PiAgICAtIAo+PiAgICAKPj4gICAg2YHZiiDYrdin2YTY
p9iqINmI2YHYp9ipINin2YTYrNmG2YrZhiDYr9in2K7ZhCDYp9mE2LHYrdmFLgo+PiAgICAKPj4g
ICAgLSAKPj4gICAgCj4+ICAgINil2LDYpyDZg9in2YYg2KfZhNit2YXZhCDZiti02YPZhCDYrti3
2LHZi9inINi52YTZiSDYrdmK2KfYqSDYp9mE2KPZhS4KPj4gICAgCj4+ICAgIAo+PiDimqDvuI8g
2YXZhNin2K3YuNipOiDZhNinINmK2Y/Zhti12K0g2KjYp9iz2KrYrtiv2KfZhSDZh9iw2Ycg2KfZ
hNit2KjZiNioINiv2YjZhiDZhdiq2KfYqNi52Kkg2LfYqNmK2KnYjCDZhNiq2KzZhtioINin2YTZ
hdi22KfYudmB2KfYqi4KPj4KPj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4+Cj4+
INi32LHZitmC2Kkg2KfYs9iq2K7Yr9in2YUg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNin
2KzZh9in2LYKPj4KPj4g2KfZhNin2LPYqtiu2K/Yp9mFINmK2K7YqtmE2YEg2K3Ys9ioINi52YXY
sSDYp9mE2K3ZhdmEINmI2K3Yp9mE2Kkg2KfZhNmF2LHYo9ip2Iwg2YjZhNmD2YYg2YHZiiDYp9mE
2LnZhdmI2YU6Cj4+Cj4+ICAgIDEuIAo+PiAgICAKPj4gICAg2KfZhNis2LHYudipOiDZitit2K/Y
r9mH2Kcg2KfZhNi32KjZitioINmB2YLYt9iMINmI2LnYp9iv2Kkg2KrZg9mI2YYg2KjZitmGIDgw
MCDZhdmK2YPYsdmI2LrYsdin2YUg2YXZgtiz2YXYqSDYudmE2YkgCj4+ICAgINis2LHYudin2Kou
Cj4+ICAgIAo+PiAgICAyLiAKPj4gICAgCj4+ICAgINi32LHZitmC2Kkg2KfZhNiq2YbYp9mI2YQ6
INiq2YjYtti5INin2YTYrdio2YjYqCDYqtit2Kog2KfZhNmE2LPYp9mGINij2Ygg2YHZiiDYp9mE
2YXZh9io2YQuCj4+ICAgIAo+PiAgICAzLiAKPj4gICAgCj4+ICAgINin2YTZhdiq2KfYqNi52Kk6
INmK2KzYqCDZhdix2KfYrNi52Kkg2KfZhNi32KjZitioINio2LnYryAyNC00OCDYs9in2LnYqSDZ
hNmE2KrYo9mD2K8g2YXZhiDYp9mD2KrZhdin2YQg2KfZhNi52YXZhNmK2KkuCj4+ICAgIAo+PiAg
ICAKPj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4+Cj4+INin2YTYo9i52LHYp9i2
INin2YTZhdiq2YjZgti52Kkg2KjYudivINiq2YbYp9mI2YQg2KfZhNit2KjZiNioCj4+Cj4+ICAg
IC0gCj4+ICAgIAo+PiAgICDZhtiy2YrZgSDZhdmH2KjZhNmKINmK2LTYqNmHINin2YTYr9mI2LHY
qSDYp9mE2LTZh9ix2YrYqSDYo9mIINij2YPYq9ixINi62LLYp9ix2KkuCj4+ICAgIAo+PiAgICAt
IAo+PiAgICAKPj4gICAg2KrYtNmG2KzYp9iqINmI2KLZhNin2YUg2YHZiiDYo9iz2YHZhCDYp9mE
2KjYt9mGLgo+PiAgICAKPj4gICAgLSAKPj4gICAgCj4+ICAgINi62KvZitin2YYg2KPZiCDZgtmK
2KEuCj4+ICAgIAo+PiAgICAtIAo+PiAgICAKPj4gICAg2KXYs9mH2KfZhCDYrtmB2YrZgS4KPj4g
ICAgCj4+ICAgIAo+PiDYpdiw2Kcg2KfYs9iq2YXYsSDYp9mE2YbYstmK2YEg2KfZhNi02K/Zitiv
INij2Ygg2LjZh9ix2Kog2KPYudix2KfYtiDZhdir2YQg2KfZhNiv2YjYrtipINin2YTYrdin2K/Y
qdiMINmK2KzYqCDYp9mE2KrZiNis2Ycg2YHZiNix2YvYpyAKPj4g2YTZhNi32YjYp9ix2KYuCj4+
Cj4+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Pgo+PiDYrdio2YjYqCDYs9in2YrY
qtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2Ycg2YjYp9mE2KjYrdix2YrZhiDZiNin2YTZg9mI
2YrYqgo+Pgo+PiDYqtmG2KrYtNixINin2YTYrdin2KzYqSDYpdmE2Ykg2K3YqNmI2Kgg2KfZhNin
2KzZh9in2LYg2LPYp9mK2KrZiNiq2YMgPGh0dHBzOi8va3NhY3l0b3RlYy5jb20vPiDZgdmKIAo+
PiDYp9mE2LnYr9mK2K8g2YXZhiDYp9mE2YXYr9mGOgo+Pgo+PiAgICAtIAo+PiAgICAKPj4gICAg
2KfZhNix2YrYp9i2OiDYqtmI2KfYtdmEINmF2Lkg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDZ
hNmE2K3YtdmI2YQg2LnZhNmJINin2YTYudmE2KfYrCDYp9mE2KPYtdmE2YouCj4+ICAgIAo+PiAg
ICAtIAo+PiAgICAKPj4gICAg2KzYr9ipOiDYrtiv2YXYp9iqINi32KjZitipINio2LPYsdmK2Kkg
2KrYp9mF2Kkg2YXYuSDZhdiq2KfYqNi52KkuCj4+ICAgIAo+PiAgICAtIAo+PiAgICAKPj4gICAg
2YXZg9ipOiDYr9i52YUg2LfYqNmKINii2YXZhiDZhNmE2YbYs9in2KEg2KfZhNmE2YjYp9iq2Yog
2YrYrdiq2KzZhiDZhNil2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE2YXYqNmD2LEuCj4+ICAgIAo+
PiAgICAtIAo+PiAgICAKPj4gICAg2KzYp9iy2KfZhjog2KfYs9iq2LTYp9ix2KfYqiDYudio2LEg
2KfZhNmH2KfYqtmBINij2Ygg2KfZhNmI2KfYqtiz2KfYqC4KPj4gICAgCj4+ICAgIC0gCj4+ICAg
IAo+PiAgICDYrtmF2YrYsyDZhdi02YrYtzog2KrZiNmB2YrYsSDYp9mE2LnZhNin2Kwg2KfZhNij
2LXZhNmKINiq2K3YqiDYpdi02LHYp9mBINmF2KrYrti12LUuCj4+ICAgIAo+PiAgICAtIAo+PiAg
ICAKPj4gICAg2KfZhNi02KfYsdmC2Kkg2YjYp9mE2KjYrdix2YrZhiDZiNin2YTZg9mI2YrYqjog
2KXZhdmD2KfZhtmK2Kkg2KfZhNiq2YjYp9i12YQg2YTYt9mE2Kgg2KfZhNi52YTYp9isINmF2YYg
2YXYtdiv2LEg2YXZiNir2YjZgi4KPj4gICAgCj4+ICAgIAo+PiDwn5OeINix2YLZhSDYr9mD2KrZ
iNix2Kkg2YbYsdmF2YrZhiDZhNmE2KfYs9iq2YHYs9in2LE6IDAwOTY2NTM4MTU5NzQ3IAo+Pgo+
PiDZhNmF2KfYsNinINiq2K7Yqtin2LHZitmGINiv2YPYqtmI2LHYqSDZhtmK2LHZhdmK2YbYnwo+
Pgo+PiAgICAtIAo+PiAgICAKPj4gICAg2K7YqNix2Kkg2LfYqNmK2Kkg2YHZiiDZhdis2KfZhCDY
p9mE2YbYs9in2KEg2YjYp9mE2KrZiNmE2YrYry4KPj4gICAgCj4+ICAgIC0gCj4+ICAgIAo+PiAg
ICDYqtmI2YHZitixINiv2YjYp9ihINiz2KfZitiq2YjYqtmDINin2YTYo9i12YTZii4KPj4gICAg
Cj4+ICAgIC0gCj4+ICAgIAo+PiAgICDZhdiq2KfYqNi52Kkg2LTYrti12YrYqSDZhNmE2K3Yp9mE
2Kkg2YXZhiDYp9mE2KjYr9in2YrYqSDYrdiq2Ykg2KfZhNmG2YfYp9mK2KkuCj4+ICAgIAo+PiAg
ICAtIAo+PiAgICAKPj4gICAg2K7YtdmI2LXZitipINmI2LPYsdmK2Kkg2KrYp9mF2Kkg2YHZiiDY
p9mE2KrYudin2YXZhC4KPj4gICAgCj4+ICAgIAo+PiDYqNiv2KfYptmEINit2KjZiNioINiz2KfZ
itiq2YjYqtmDCj4+Cj4+INmB2Yog2KjYudi2INin2YTYrdin2YTYp9iq2Iwg2YLYryDZitmC2KrY
sditINin2YTYt9io2YrYqCDYqNiv2KfYptmEINij2K7YsdmJOgo+Pgo+PiAgICAtIAo+PiAgICAK
Pj4gICAg2KfZhNiq2YjYs9mK2Lkg2YjYp9mE2YPYrdiqINin2YTYrNix2KfYrdmKIChEJkMpLgo+
PiAgICAKPj4gICAgLSAKPj4gICAgCj4+ICAgINij2K/ZiNmK2Kkg2KrYrdiq2YjZiiDYudmE2Ykg
2YXZitmB2YrYqNix2YrYs9iq2YjZhiDZhdi5INmF2YrYstmI2KjYsdmI2LPYqtmI2YQuCj4+ICAg
IAo+PiAgICAtIAo+PiAgICAKPj4gICAg2KfZhNil2KzZh9in2LYg2KfZhNis2LHYp9it2Yog2KfZ
hNmF2KjYp9i02LEuCj4+ICAgIAo+PiDYo9iz2KbZhNipINi02KfYpti52KkKPj4KPj4gMS4g2YfZ
hCDZitmF2YPZhiDYtNix2KfYoSDYs9in2YrYqtmI2KrZgyDYqNiv2YjZhiDZiNi12YHYqSDZgdmK
INin2YTYs9i52YjYr9mK2KnYnwo+PiDYutin2YTYqNmL2Kcg2YTYp9iMINmI2YrYrNioINin2YTY
rdi12YjZhCDYudmE2YrZhyDZhdmGINmF2LXYr9ixINmF2YjYq9mI2YIg2KrYrdiqINil2LTYsdin
2YEg2LfYqNmKLgo+Pgo+PiAyLiDZg9mFINiq2LPYqti62LHZgiDYudmF2YTZitipINin2YTYp9is
2YfYp9i2INio2KfZhNit2KjZiNio2J8KPj4g2LnYp9iv2Kkg2YXZhiAyNCDYpdmE2YkgNDgg2LPY
p9i52Kkg2K3YqtmJINmK2YPYqtmF2YQg2KfZhNmG2LLZitmBINmI2KXYrtix2KfYrCDYp9mE2K3Z
hdmELgo+Pgo+PiAzLiDZh9mEINmK2LPYqNioINiz2KfZitiq2YjYqtmDINin2YTYudmC2YXYnwo+
PiDZhNin2Iwg2KXYsNinINiq2YUg2KfYs9iq2K7Yr9in2YXZhyDYqNi02YPZhCDYtdit2YrYrdiM
INmE2Kcg2YrYpNir2LEg2LnZhNmJINin2YTZgtiv2LHYqSDYp9mE2KXZhtis2KfYqNmK2Kkg2KfZ
hNmF2LPYqtmC2KjZhNmK2KkuCj4+Cj4+INiu2KfYqtmF2KkKPj4KPj4g2KXZhiDYrdio2YjYqCDY
p9mE2KfYrNmH2KfYtiDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2Ycg2KrZhdir
2YQg2K3ZhNmL2Kcg2LfYqNmK2YvYpyDZgdmKINit2KfZhNin2Kog2K7Yp9i12KnYjCDZhNmD2YYg
Cj4+INin2YTYo9mF2KfZhiDZitmD2YXZhiDZgdmKINin2LPYqti02KfYsdipINmF2K7Yqti12YrZ
hiDZhdir2YQg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDYp9mE2KrZiiDYqtmI2YHYsSDYp9mE
2K/YudmFINmI2KfZhNi52YTYp9isINmF2YYgCj4+INmF2LXYr9ixINmF2LbZhdmI2YbYjCDZhdi5
INmF2KrYp9io2LnYqSDYr9mC2YrZgtipINmI2LPYsdmK2Kkg2KrYp9mF2KkuCj4+INmE2YTYp9iz
2KrZgdiz2KfYsdin2Kog2KPZiCDYt9mE2Kgg2KfZhNi52YTYp9is2Iwg2KfYqti12YTZiiDYp9mE
2KLZhiDYudmE2Yk6IDAwOTY2NTM4MTU5NzQ3IC4KPj4KPj4g2KrYrdiw2YrYsdin2Kog2YXZh9mF
2KkKPj4KPj4g2YrZhdmG2Lkg2KfYs9iq2K7Yr9in2YUg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg
2YHZiiDYrdin2YTYp9iqINin2YTYrdmF2YQg2KfZhNmF2KrZgtiv2YUg2KjYudivINin2YTYo9iz
2KjZiNi5IDEyINil2YTYpyDYqNij2YXYsSAKPj4g2KfZhNi32KjZitioLgo+Pgo+PiDZhNinINiq
2LPYqtiu2K/ZhdmKINin2YTYrdio2YjYqCDYpdiw2Kcg2YPYp9mGINmE2K/ZitmDINit2LPYp9iz
2YrYqSDZhdmGINin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqS4KPj4KPj4g2YTYpyDYqtiq2YbY
p9mI2YTZiiDYo9mKINis2LHYudipINil2LbYp9mB2YrYqSDYqNiv2YjZhiDYp9iz2KrYtNin2LHY
qSDYt9io2YrYqS4KPj4KPj4KPj4gINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrY
qSDDlyDYs9in2YrYqtmI2KrZgyDYqNin2YTYsdmK2KfYtiDDlyDYs9in2YrYqtmI2KrZgyDYp9mE
2K/Zhdin2YUgw5cg2LPYp9mK2KrZiNiq2YMg2K7ZhdmK2LMgCj4+INmF2LTZiti3IMOXINiz2KfZ
itiq2YjYqtmDINmB2Yog2KfZhNmD2YjZitiqIMOXINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNio
2K3YsdmK2YYgw5cg2KPYr9mI2YrYqSDYpdis2YfYp9i2INin2YTYrdmF2YQgw5cgCj4+INmF2YrY
stmI2KjYsdiz2KrZiNmEIMOXINij2LnYsdin2LYg2KfZhNit2YXZhCDDlyDYs9in2YrYqtmI2KrZ
itmDINmB2Yog2YXZg9ipIMOXINi52YrYp9iv2KfYqiDYp9is2YfYp9i2IMOXINiv2YPYqtmI2LHY
qSDYp9is2YfYp9i2IAo+PiDZgdmKINin2YTYs9i52YjYr9mK2Kkgw5cg2K/Zg9iq2YjYsdipINin
2KzZh9in2LYg2YHZiiDYp9mE2YPZiNmK2Kogw5cg2K/Zg9iq2YjYsdipINin2KzZh9in2LYg2YHZ
iiDYp9mE2KjYrdix2YrZhiDDlyDYr9mD2KrZiNix2KkgCj4+INin2KzZh9in2LYg2YHZiiDYp9mE
2KXZhdin2LHYp9iqIMOXINiv2YPYqtmI2LHYqSDDlyDYp9mE2K/ZiNix2Kkg2KfZhNi02YfYsdmK
2KkKPj4KPj4KPj4NCg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3Ug
YXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRv
IHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZy
b20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vw
cy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2ds
ZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvZjg4ZmJhYzMtMGZiYS00NTUzLTk1OTctZDRmNWRjOTcx
ZjQwbiU0MGdvb2dsZWdyb3Vwcy5jb20uCg==
------=_Part_73765_1190502520.1756790828919
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<span dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 24pt; margin-bott=
om: 6pt;"><span style=3D"font-size: 23pt; font-family: Arial, sans-serif; c=
olor: rgb(68, 68, 68); background-color: transparent; font-weight: 700; fon=
t-variant-numeric: normal; font-variant-east-asian: normal; font-variant-al=
ternates: normal; vertical-align: baseline;">=D9=85=D9=83=D8=A7=D9=86 =D8=
=A8=D9=8A=D8=B9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 / 05381597=
47 /=C2=A0 Cytotec =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA=C2=A0</span><a href=
=3D"http://amazon.sa/" target=3D"_blank" rel=3D"nofollow" style=3D"color: r=
gb(26, 115, 232);"><span style=3D"font-size: 23pt; font-family: Arial, sans=
-serif; color: rgb(17, 85, 204); background-color: transparent; font-weight=
: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-=
variant-alternates: normal; text-decoration-line: underline; vertical-align=
: baseline;">amazon.sa</span></a></span><span dir=3D"rtl" style=3D"line-hei=
ght: 1.38; margin-top: 24pt; margin-bottom: 6pt;"><span style=3D"font-size:=
 23pt; font-family: Arial, sans-serif; color: rgb(68, 68, 68); background-c=
olor: transparent; font-weight: 700; font-variant-numeric: normal; font-var=
iant-east-asian: normal; font-variant-alternates: normal; vertical-align: b=
aseline;">=C2=A0// //=C2=A0 =D8=AF=D9=88=D8=A7=D8=A1 =D8=A7=D9=84=D8=A5=D8=
=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =C2=
=A0 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AF=D9=88=D8=
=A7=D8=A6=D9=8A =C2=A0 =D8=A7=D9=84=D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A7=D9=
=84=D8=B7=D8=A8=D9=8A=D8=A9 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=
=84=D8=AD=D9=85=D9=84 =C2=A0 =D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=
=B3=D8=AA=D9=88=D9=84 (Misoprostol) =C2=A0 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 Cytotec =C2=A0 =D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=
=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1 =C2=A0 =D8=A3=D8=AF=D9=
=88=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=
=A3=D9=85=D9=86=D8=A9 =C2=A0 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=
=84=D8=AF=D9=88=D8=A7=D8=A6=D9=8A =D9=84=D9=84=D8=AD=D9=85=D9=84 =D8=BA=D9=
=8A=D8=B1</span></span><span style=3D"font-size: 10pt; font-family: Arial, =
sans-serif; color: rgb(68, 68, 68); background-color: transparent; font-var=
iant-numeric: normal; font-variant-east-asian: normal; font-variant-alterna=
tes: normal; vertical-align: baseline;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 //=C2=A0</span>=
<span style=3D"font-size: 23pt; font-family: Arial, sans-serif; color: rgb(=
68, 68, 68); background-color: transparent; font-weight: 700; font-variant-=
numeric: normal; font-variant-east-asian: normal; font-variant-alternates: =
normal; vertical-align: baseline;">00966538159747=C2=A0</span><span style=
=3D"font-size: 10pt; font-family: Arial, sans-serif; color: rgb(68, 68, 68)=
; background-color: transparent; font-variant-numeric: normal; font-variant=
-east-asian: normal; font-variant-alternates: normal; vertical-align: basel=
ine;">// =D8=A8=D8=A7=D9=81=D8=B6=D9=84 =D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=
=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=A7=D8=
=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D9=85=D9=86=D8=B2=D9=84=D9=8A =D9=84=D9=
=85=D9=88=D9=82=D8=B9 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A| =D8=A7=D9=84=D8=
=AF=D9=81=D8=B9 =D8=B9=D9=86=D8=AF =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=84=D8=
=A7=D9=85 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =D9=84=D9=84=D8=
=A8=D9=8A=D8=B9</span><div style=3D"color: rgb(80, 0, 80);"><span style=3D"=
font-size: 10pt; font-family: Arial, sans-serif; color: rgb(68, 68, 68); ba=
ckground-color: transparent; font-variant-numeric: normal; font-variant-eas=
t-asian: normal; font-variant-alternates: normal; vertical-align: baseline;=
"><br /></span><span style=3D"font-size: 10pt; font-family: Arial, sans-ser=
if; color: rgb(68, 68, 68); background-color: transparent; font-variant-num=
eric: normal; font-variant-east-asian: normal; font-variant-alternates: nor=
mal; vertical-align: baseline;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =
=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =C3=97 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=
=D8=B6 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=
=D9=85=D8=A7=D9=85 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AE=
=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA =C3=97=
 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=
=D8=AD=D8=B1=D9=8A=D9=86 =C3=97 =D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A5=D8=AC=
=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =C3=97 =D9=85=D9=8A=D8=B2=
=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=84 =C3=97 =D8=A3=D8=B9=D8=B1=D8=A7=
=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=8A=D9=83 =D9=81=D9=8A =D9=85=D9=83=D8=A9 =C3=97 =D8=B9=D9=8A=D8=
=A7=D8=AF=D8=A7=D8=AA =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =C3=97 =D8=AF=D9=83=D8=
=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=
=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=
=88=D9=8A=D8=AA =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=
=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =C3=
=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=
=81=D9=8A =D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=A7=D8=AA =C3=97 =D8=AF=D9=
=83=D8=AA=D9=88=D8=B1=D8=A9 =C3=97 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=
=A7=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=A9</span></div><br /><div class=3D"gma=
il_quote"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=8A =D8=A7=D9=84=
=D8=B3=D8=A8=D8=AA=D8=8C 30 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025 =D9=81=D9=
=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9 11:07:08 =
=D9=85 UTC-7=D8=8C =D9=83=D8=AA=D8=A8 =D8=B3=D9=8A=D8=AF=D8=A9 =D8=AC=D8=AF=
=D8=A9 =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D8=B1=D8=B3=D8=A7=
=D9=84=D8=A9 =D9=86=D8=B5=D9=87=D8=A7:<br/></div><blockquote class=3D"gmail=
_quote" style=3D"margin: 0 0 0 0.8ex; border-right: 1px solid rgb(204, 204,=
 204); padding-right: 1ex;"><span dir=3D"rtl" style=3D"line-height:1.38;mar=
gin-top:24pt;margin-bottom:6pt"><span style=3D"font-size:23pt;font-family:A=
rial,sans-serif;color:rgb(68,68,68);background-color:transparent;font-weigh=
t:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=D9=85=D9=83=D8=A7=D9=86 =D8=
=A8=D9=8A=D8=B9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 / 05381597=
47 /=C2=A0 Cytotec =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA </span><a href=3D"h=
ttp://amazon.sa" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D=
"https://www.google.com/url?hl=3Dar&amp;q=3Dhttp://amazon.sa&amp;source=3Dg=
mail&amp;ust=3D1756877189235000&amp;usg=3DAOvVaw1GgWvoLpyIo4H_AZL5jti3"><sp=
an style=3D"font-size:23pt;font-family:Arial,sans-serif;color:rgb(17,85,204=
);background-color:transparent;font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;text-decorati=
on-line:underline;vertical-align:baseline">amazon.sa</span></a></span><span=
 dir=3D"rtl" style=3D"line-height:1.38;margin-top:24pt;margin-bottom:6pt"><=
span style=3D"font-size:23pt;font-family:Arial,sans-serif;color:rgb(68,68,6=
8);background-color:transparent;font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline">=C2=A0// //=C2=A0 =D8=AF=D9=88=D8=A7=D8=A1 =D8=A7=D9=84=D8=A5=
=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =
=C2=A0 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AF=D9=88=
=D8=A7=D8=A6=D9=8A =C2=A0 =D8=A7=D9=84=D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A7=
=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=
=D9=84=D8=AD=D9=85=D9=84 =C2=A0 =D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=
=D8=B3=D8=AA=D9=88=D9=84 (Misoprostol) =C2=A0 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 Cytotec =C2=A0 =D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=
=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1 =C2=A0 =D8=A3=D8=AF=
=D9=88=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=
=D8=A3=D9=85=D9=86=D8=A9 =C2=A0 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=
=D9=84=D8=AF=D9=88=D8=A7=D8=A6=D9=8A =D9=84=D9=84=D8=AD=D9=85=D9=84 =D8=BA=
=D9=8A=D8=B1</span></span><span style=3D"font-size:10pt;font-family:Arial,s=
ans-serif;color:rgb(68,68,68);background-color:transparent;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=
=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 // </span><span style=3D"font-s=
ize:23pt;font-family:Arial,sans-serif;color:rgb(68,68,68);background-color:=
transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">0096653=
8159747 </span><span style=3D"font-size:10pt;font-family:Arial,sans-serif;c=
olor:rgb(68,68,68);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline">// =D8=A8=D8=A7=D9=81=D8=B6=D9=84 =D8=B3=D8=B9=D8=B1 =D8=AD=D8=
=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=
=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D9=85=D9=86=D8=B2=D9=84=D9=8A =D9=
=84=D9=85=D9=88=D9=82=D8=B9 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A| =D8=A7=D9=
=84=D8=AF=D9=81=D8=B9 =D8=B9=D9=86=D8=AF =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=
=84=D8=A7=D9=85 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =D9=84=D9=
=84=D8=A8=D9=8A=D8=B9</span><span style=3D"font-size:10pt;font-family:Arial=
,sans-serif;color:rgb(68,68,68);background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline"><br></span><span style=3D"font-size:10pt;font-fam=
ily:Arial,sans-serif;color:rgb(68,68,68);background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =C3=97 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=A7=D9=84=D8=B1=D9=8A=
=D8=A7=D8=B6 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=
=D8=AF=D9=85=D8=A7=D9=85 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =
=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7 =C3=97 =D8=B3=D8=A7=D9=8A=
=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA =
=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=
=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =C3=97 =D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A5=
=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =C3=97 =D9=85=D9=8A=
=D8=B2=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=84 =C3=97 =D8=A3=D8=B9=D8=B1=
=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=8A=D9=83 =D9=81=D9=8A =D9=85=D9=83=D8=A9 =C3=97 =D8=B9=D9=
=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =C3=97 =D8=AF=D9=
=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=
=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =C3=97 =D8=AF=D9=83=D8=AA=D9=
=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D9=
=83=D9=88=D9=8A=D8=AA =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=
=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=
=86 =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=A7=D8=AA =C3=97 =
=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =C3=97 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=
=D8=A9 =D8=A7=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=A9</span><br><br><div class=
=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=8A =D8=A7=
=D9=84=D8=A7=D8=AB=D9=86=D9=8A=D9=86=D8=8C 25 =D8=A3=D8=BA=D8=B3=D8=B7=D8=
=B3 2025 =D9=81=D9=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=
=B9=D8=A9 4:06:29 =D8=B5 UTC-7=D8=8C =D9=83=D8=AA=D8=A8 =D8=B3=D8=A7=D9=8A=
=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=AE=D8=B5=D9=85 20% =D8=
=B1=D8=B3=D8=A7=D9=84=D8=A9 =D9=86=D8=B5=D9=87=D8=A7:<br></div><blockquote =
class=3D"gmail_quote" style=3D"margin:0 0 0 0.8ex;border-right:1px solid rg=
b(204,204,204);padding-right:1ex"><br><span dir=3D"rtl" style=3D"line-heigh=
t:1.44;margin-top:0pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font=
-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=AF=D9=83=D8=AA=
=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 | </span><span style=3D"font-size:12pt=
;font-family:Arial,sans-serif;color:rgb(51,51,51);font-weight:700;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline">00966538159747 </span><span style=3D"font-si=
ze:13pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:t=
ransparent;font-weight:700;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">|=D8=B9=
=D9=8A=D8=A7=D8=AF=D8=A9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=C2=A0</=
span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-=
bottom:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;c=
olor:rgb(73,80,87);background-color:transparent;font-weight:700;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline">=C2=A0=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=
=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=
=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9</span><span styl=
e=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);back=
ground-color:transparent;font-weight:700;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"><br></span><span style=3D"font-size:11.5pt;font-family:Arial,sans-ser=
if;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=
=A7=D8=AC=D9=87=D8=A7=D8=B6 =E2=80=93 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=C2=A0 =
| =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=
 </span><span style=3D"font-size:12pt;font-family:Arial,sans-serif;color:rg=
b(51,51,51);font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">0096653=
8159747 </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif=
;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline">=E2=80=93 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=
=B1=D8=A7=D8=AA =D9=88=D8=B9=D9=84=D8=A7=D8=AC =D8=A2=D9=85=D9=86</span><sp=
an style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,8=
7);background-color:transparent;font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"><br></span><span style=3D"font-size:11.5pt;font-family:Arial,s=
ans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline">=D8=AA=D8=B9=D8=B1=D9=81=D9=8A =D8=
=B9=D9=84=D9=89 =D9=83=D9=84 =D9=85=D8=A7 =D9=8A=D9=87=D9=85=D9=83 =D8=B9=
=D9=86 =D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =
=D8=8C </span><a href=3D"https://hayatannas.com/?srsltid=3DAfmBOoorXTv6wctb=
Y7oCbd_zRBMxNDPmT0F5DPRwzMifCMgDDNNp1cbV" rel=3D"nofollow" target=3D"_blank=
" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps:=
//hayatannas.com/?srsltid%3DAfmBOoorXTv6wctbY7oCbd_zRBMxNDPmT0F5DPRwzMifCMg=
DDNNp1cbV&amp;source=3Dgmail&amp;ust=3D1756877189235000&amp;usg=3DAOvVaw0Mi=
jdJlM4fkaoJaHB6IEEb"><span style=3D"font-size:11.5pt;font-family:Arial,sans=
-serif;color:rgb(255,152,0);background-color:transparent;font-weight:700;fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span>=
</a><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(=
73,80,87);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline"> =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=
=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=AC=D8=A7=D8=B2=D8=A7=D9=86=D8=
=8C =D9=88=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7=D8=8C =D9=85=D8=
=B9 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=
=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=
=84=D8=B7=D8=A8=D9=8A=D8=A9 =D9=88=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=
=84=D8=A7=D8=AC =D8=A8=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9.</s=
pan></p><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin-b=
ottom:4pt"><span style=3D"font-size:17pt;font-family:Arial,sans-serif;color=
:rgb(255,0,0);background-color:transparent;font-weight:700;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline">=D8=AA=D8=AD=D8=B0=D9=8A=D8=B1=D8=A7=D8=AA =D9=85=
=D9=87=D9=85=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height:1.38;ma=
rgin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-famil=
y:Arial,sans-serif;color:rgb(255,0,0);background-color:transparent;font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=D9=8A=D9=85=D9=86=D8=B9 =
=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=
=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=
=D9=85 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =D8=
=A5=D9=84=D8=A7 =D8=A8=D8=A3=D9=85=D8=B1 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=
=A8 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=85=D8=A7=D8=B9 =D8=A7=D9=84=D9=
=8A =D8=AA=D9=88=D8=AC=D9=8A=D9=87=D8=A7=D8=AA=D9=87 .</span></p><br><br><s=
pan dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin-bottom:2pt"=
><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(73,80=
,87);background-color:transparent;font-weight:700;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=C2=A0=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 | </span><span style=3D"font-size:12pt;font-family:Arial,sa=
ns-serif;color:rgb(51,51,51);font-weight:700;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">00966538159747 </span><span style=3D"font-size:11pt;font-family:A=
rial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weigh=
t:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=C2=A0| =D9=81=D9=8A =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =E2=80=93 =D8=AF=D9=83=D8=AA=D9=
=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=
=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=
=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=C2=A0=C2=A0</span></span><p =
dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><s=
pan style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,=
87);background-color:transparent;font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D9=86=D9=88=D8=A7=D8=AA =D8=
=A7=D9=84=D8=A3=D8=AE=D9=8A=D8=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD =D9=
=85=D9=88=D8=B6=D9=88=D8=B9 </span><a href=3D"https://saudiersaa.com/" rel=
=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"https://www.google.=
com/url?hl=3Dar&amp;q=3Dhttps://saudiersaa.com/&amp;source=3Dgmail&amp;ust=
=3D1756877189235000&amp;usg=3DAOvVaw3Zg4ByIvVbz950diMB91ou"><span style=3D"=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(255,152,0);backgrou=
nd-color:transparent;font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:=
11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:tr=
ansparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline"> =D9=81=
=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=85=D9=86 =D8=A3=
=D9=83=D8=AB=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B6=D9=8A=D8=B9 =D8=A7=
=D9=84=D8=AA=D9=8A =D8=AA=D8=A8=D8=AD=D8=AB =D8=B9=D9=86=D9=87=D8=A7 =D8=A7=
=D9=84=D8=B3=D9=8A=D8=AF=D8=A7=D8=AA=D8=8C =D8=AE=D8=A7=D8=B5=D8=A9 =D9=81=
=D9=8A =D9=85=D8=AF=D9=86 =D9=85=D8=AB=D9=84 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=
=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=AC=D8=A7=
=D8=B2=D8=A7=D9=86=D8=8C =D9=88=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=
=D8=B7=D8=8C =D9=88=D9=83=D8=B0=D9=84=D9=83 =D9=81=D9=8A =D9=85=D9=86=D8=A7=
=D8=B7=D9=82 =D8=A7=D9=84=D8=AE=D9=84=D9=8A=D8=AC =D9=85=D8=AB=D9=84 =D8=A7=
=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=83=D9=88=D9=8A=
=D8=AA =D9=88=D8=A7=D9=84=D8=B4=D8=A7=D8=B1=D9=82=D8=A9. =D9=86=D8=B8=D8=B1=
=D9=8B=D8=A7 =D9=84=D8=AD=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=
=D9=88=D8=B6=D9=88=D8=B9 =D9=88=D8=A3=D9=87=D9=85=D9=8A=D8=AA=D9=87=D8=8C =
=D8=AA=D9=82=D8=AF=D9=85 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=
=D8=B1=D9=85=D9=8A=D9=86 =D8=A7=D9=84=D8=AF=D8=B9=D9=85 =D8=A7=D9=84=D8=B7=
=D8=A8=D9=8A =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=84=D9=84=D9=86=
=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=AA=D9=8A =D9=8A=D8=AD=
=D8=AA=D8=AC=D9=86 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=AA=D9=88=D8=AC=D9=8A=
=D9=87 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=AD =D9=88=D8=B7=D9=84=D8=A8 =D8=A7=
=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=
=D9=88=D8=AB=D9=88=D9=82=D8=8C =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D8=A7=D8=AA=
=D8=B5=D8=A7=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85: </spa=
n><span style=3D"font-size:12pt;font-family:Arial,sans-serif;color:rgb(51,5=
1,51);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline">0096653815974=
7 </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color=
:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">.</span></p><p dir=3D"rtl" style=3D"line-height:1.=
38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=
=3D"line-height:1.44;margin-top:0pt;margin-bottom:2pt"><span style=3D"font-=
size:10pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=85=
=D8=A7 =D9=87=D9=8A =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=84=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6=D8=9F</span></span>=
<p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"=
><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,=
80,87);background-color:transparent;font-weight:700;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 (Cytotec) =D8=AA=D8=AD=D8=AA=D9=88=D9=8A =D8=B9=D9=84=D9=89 =D8=
=A7=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=
=A9 =D8=A7=D9=84=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=
=88=D9=84 (Misoprostol)=D8=8C =D9=88=D9=87=D9=8A =D8=AF=D9=88=D8=A7=D8=A1 =
=D9=85=D8=B9=D8=AA=D9=85=D8=AF =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=84=D8=B9=
=D9=84=D8=A7=D8=AC =D9=82=D8=B1=D8=AD=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AF=
=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D8=8C =D9=84=D9=83=D9=86=
 =D8=A7=D9=84=D8=A3=D8=A8=D8=AD=D8=A7=D8=AB =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=
=D8=A9 =D8=A3=D8=AB=D8=A8=D8=AA=D8=AA =D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=AA=
=D9=87 =D9=81=D9=8A </span><a href=3D"https://hayatannas.com/?srsltid=3DAfm=
BOoo8ZdNvEZUpg3DdfWtZNURKApzWgsXHqwmgsJdHJ68QU_xgOugS" rel=3D"nofollow" tar=
get=3D"_blank" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&a=
mp;q=3Dhttps://hayatannas.com/?srsltid%3DAfmBOoo8ZdNvEZUpg3DdfWtZNURKApzWgs=
XHqwmgsJdHJ68QU_xgOugS&amp;source=3Dgmail&amp;ust=3D1756877189235000&amp;us=
g=3DAOvVaw3K12mR8vrnquIh6giaEjFB"><span style=3D"font-size:11.5pt;font-fami=
ly:Arial,sans-serif;color:rgb(255,152,0);background-color:transparent;font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline">=D8=A5=D9=86=D9=87=D8=A7=
=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1<=
/span></a><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;colo=
r:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline"> =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=
=81 =D8=B7=D8=A8=D9=8A.</span><span style=3D"font-size:11.5pt;font-family:A=
rial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weigh=
t:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline"><br></span><span style=3D"fon=
t-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-c=
olor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D9=8A=
=D8=AA=D9=85 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=
=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=
=D8=A7=D8=B5=D8=A9 =D9=88 =D8=A8=D8=AC=D8=B1=D8=B9=D8=A7=D8=AA =D9=85=D8=AD=
=D8=AF=D8=AF=D8=A9 =D9=8A=D9=82=D8=B1=D8=B1=D9=87=D8=A7 =D8=A7=D9=84=D8=B7=
=D8=A8=D9=8A=D8=A8=D8=8C =D9=85=D8=B9 =D8=B6=D8=B1=D9=88=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=AA=D8=A3=D9=83=D8=AF =D9=85=D9=86 =D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=
=D9=84=D9=85=D9=86=D8=AA=D8=AC =D9=88=D9=85=D8=B5=D8=AF=D8=B1=D9=87.</span>=
</p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0=
pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0=
pt;margin-bottom:2pt"><span style=3D"font-size:10pt;font-family:Arial,sans-=
serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline">=D9=85=D8=AA=D9=89 =D8=AA=D8=B3=D8=AA=
=D8=AE=D8=AF=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=9F</span></span>=
<ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"lis=
t-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(7=
3,80,87);background-color:transparent;font-weight:700;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" sty=
le=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><=
span style=3D"font-size:11.5pt;background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">=D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=
=D9=84=D9=85=D8=A8=D9=83=D8=B1: =D8=AD=D8=AA=D9=89 =D8=A7=D9=84=D8=A3=D8=B3=
=D8=A8=D9=88=D8=B9 12 =D9=85=D9=86 =D8=A7=D9=84=D8=AD=D9=85=D9=84.</span><s=
pan style=3D"font-size:11.5pt;background-color:transparent;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"li=
st-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(=
73,80,87);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" st=
yle=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt">=
<span style=3D"font-size:11.5pt;background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">=D8=B9=D9=86=D8=AF =D9=88=D8=AC=D9=88=D8=AF =D8=
=AA=D8=B4=D9=88=D9=87=D8=A7=D8=AA =D8=AC=D9=86=D9=8A=D9=86=D9=8A=D8=A9 =D8=
=AE=D8=B7=D9=8A=D8=B1=D8=A9.</span><span style=3D"font-size:11.5pt;backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline"><br><br></span=
></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;fo=
nt-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p=
 dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:rig=
ht;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;backgr=
ound-color:transparent;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline">=D9=81=D9=8A=
 =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D9=88=D9=81=D8=A7=D8=A9 =D8=A7=D9=84=D8=AC=
=D9=86=D9=8A=D9=86 =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=D8=B1=D8=AD=D9=85.=
</span><span style=3D"font-size:11.5pt;background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" st=
yle=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;c=
olor:rgb(73,80,87);background-color:transparent;font-weight:700;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"present=
ation" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bot=
tom:12pt"><span style=3D"font-size:11.5pt;background-color:transparent;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline">=D8=A5=D8=B0=D8=A7 =D9=83=D8=A7=D9=86 =
=D8=A7=D9=84=D8=AD=D9=85=D9=84 =D9=8A=D8=B4=D9=83=D9=84 =D8=AE=D8=B7=D8=B1=
=D9=8B=D8=A7 =D8=B9=D9=84=D9=89 =D8=AD=D9=8A=D8=A7=D8=A9 =D8=A7=D9=84=D8=A3=
=D9=85.</span><span style=3D"font-size:11.5pt;background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline"><br><br></span></p></li></ul><p dir=
=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span=
 style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87)=
;background-color:transparent;font-weight:700;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline">=E2=9A=A0=EF=B8=8F =D9=85=D9=84=D8=A7=D8=AD=D8=B8=D8=A9: =D9=84=
=D8=A7 =D9=8A=D9=8F=D9=86=D8=B5=D8=AD =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=
=D8=A7=D9=85 =D9=87=D8=B0=D9=87 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AF=
=D9=88=D9=86 =D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9=
=D8=8C =D9=84=D8=AA=D8=AC=D9=86=D8=A8 =D8=A7=D9=84=D9=85=D8=B6=D8=A7=D8=B9=
=D9=81=D8=A7=D8=AA.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;marg=
in-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"lin=
e-height:1.44;margin-top:0pt;margin-bottom:2pt"><span style=3D"font-size:10=
pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transp=
arent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline">=D8=B7=D8=B1=
=D9=8A=D9=82=D8=A9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=
=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A7=
=D8=AC=D9=87=D8=A7=D8=B6</span></span><p dir=3D"rtl" style=3D"line-height:1=
.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font=
-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D9=8A=D8=AE=D8=AA=D9=84=D9=81 =D8=AD=
=D8=B3=D8=A8 =D8=B9=D9=85=D8=B1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D9=88=D8=AD=
=D8=A7=D9=84=D8=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A3=D8=A9=D8=8C =D9=88=D9=84=
=D9=83=D9=86 =D9=81=D9=8A =D8=A7=D9=84=D8=B9=D9=85=D9=88=D9=85:</span></p><=
ol style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"list=
-style-type:decimal;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb=
(73,80,87);background-color:transparent;font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" s=
tyle=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"=
><span style=3D"font-size:11.5pt;background-color:transparent;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline">=D8=A7=D9=84=D8=AC=D8=B1=D8=B9=D8=A9: =D9=8A=D8=
=AD=D8=AF=D8=AF=D9=87=D8=A7 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D9=81=D9=
=82=D8=B7=D8=8C =D9=88=D8=B9=D8=A7=D8=AF=D8=A9 =D8=AA=D9=83=D9=88=D9=86 =D8=
=A8=D9=8A=D9=86 800 =D9=85=D9=8A=D9=83=D8=B1=D9=88=D8=BA=D8=B1=D8=A7=D9=85 =
=D9=85=D9=82=D8=B3=D9=85=D8=A9 =D8=B9=D9=84=D9=89 =D8=AC=D8=B1=D8=B9=D8=A7=
=D8=AA.</span><span style=3D"font-size:11.5pt;background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"=
rtl" style=3D"list-style-type:decimal;font-size:11.5pt;font-family:Arial,sa=
ns-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=
=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-top:0pt=
;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=D8=B7=D8=B1=D9=8A=D9=82=D8=
=A9 =D8=A7=D9=84=D8=AA=D9=86=D8=A7=D9=88=D9=84: =D8=AA=D9=88=D8=B6=D8=B9 =
=D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AA=D8=AD=D8=AA =D8=A7=D9=84=D9=84=
=D8=B3=D8=A7=D9=86 =D8=A3=D9=88 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=87=D8=A8=
=D9=84.</span><span style=3D"font-size:11.5pt;background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"=
rtl" style=3D"list-style-type:decimal;font-size:11.5pt;font-family:Arial,sa=
ns-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=
=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-top:0pt=
;margin-bottom:12pt"><span style=3D"font-size:11.5pt;background-color:trans=
parent;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D9=85=D8=AA=D8=
=A7=D8=A8=D8=B9=D8=A9: =D9=8A=D8=AC=D8=A8 =D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=
=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D8=A8=D8=B9=D8=AF 24-48 =D8=B3=D8=
=A7=D8=B9=D8=A9 =D9=84=D9=84=D8=AA=D8=A3=D9=83=D8=AF =D9=85=D9=86 =D8=A7=D9=
=83=D8=AA=D9=85=D8=A7=D9=84 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9.</sp=
an><span style=3D"font-size:11.5pt;background-color:transparent;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline"><br><br></span></p></li></ol><p dir=3D"rtl" st=
yle=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><p=
 dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><s=
pan style=3D"font-size:10pt;font-family:&quot;Courier New&quot;,monospace;c=
olor:rgb(29,33,37);background-color:transparent;font-weight:700;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline">=D8=A7=D9=84=D8=A3=D8=B9=D8=B1=D8=A7=D8=B6 =D8=
=A7=D9=84=D9=85=D8=AA=D9=88=D9=82=D8=B9=D8=A9 =D8=A8=D8=B9=D8=AF =D8=AA=D9=
=86=D8=A7=D9=88=D9=84 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8</span></p><ul st=
yle=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-styl=
e-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,8=
7);background-color:transparent;font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"=
line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span s=
tyle=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline">=D9=86=D8=B2=D9=8A=D9=81 =D9=85=D9=87=D8=A8=D9=84=D9=8A =
=D9=8A=D8=B4=D8=A8=D9=87 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=
=D8=B4=D9=87=D8=B1=D9=8A=D8=A9 =D8=A3=D9=88 =D8=A3=D9=83=D8=AB=D8=B1 =D8=BA=
=D8=B2=D8=A7=D8=B1=D8=A9.</span><span style=3D"font-size:11.5pt;background-=
color:transparent;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline"><br><br></span></=
p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-=
family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p di=
r=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;=
margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=D8=AA=D8=B4=D9=
=86=D8=AC=D8=A7=D8=AA =D9=88=D8=A2=D9=84=D8=A7=D9=85 =D9=81=D9=8A =D8=A3=D8=
=B3=D9=81=D9=84 =D8=A7=D9=84=D8=A8=D8=B7=D9=86.</span><span style=3D"font-s=
ize:11.5pt;background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgroun=
d-color:transparent;font-weight:700;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;=
white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:=
1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font=
-size:11.5pt;background-color:transparent;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D8=BA=D8=AB=D9=8A=D8=A7=D9=86 =D8=A3=D9=88 =D9=82=D9=8A=D8=A1.</spa=
n><span style=3D"font-size:11.5pt;background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=
=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;colo=
r:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentati=
on" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom=
:12pt"><span style=3D"font-size:11.5pt;background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=A5=D8=B3=D9=87=D8=A7=D9=84 =D8=AE=D9=
=81=D9=8A=D9=81.</span><span style=3D"font-size:11.5pt;background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"><br><br></span></p></li></=
ul><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12=
pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(=
73,80,87);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D8=A5=D8=B0=D8=A7 =D8=A7=D8=B3=D8=AA=D9=85=D8=B1 =D8=
=A7=D9=84=D9=86=D8=B2=D9=8A=D9=81 =D8=A7=D9=84=D8=B4=D8=AF=D9=8A=D8=AF =D8=
=A3=D9=88 =D8=B8=D9=87=D8=B1=D8=AA =D8=A3=D8=B9=D8=B1=D8=A7=D8=B6 =D9=85=D8=
=AB=D9=84 =D8=A7=D9=84=D8=AF=D9=88=D8=AE=D8=A9 =D8=A7=D9=84=D8=AD=D8=A7=D8=
=AF=D8=A9=D8=8C =D9=8A=D8=AC=D8=A8 =D8=A7=D9=84=D8=AA=D9=88=D8=AC=D9=87 =D9=
=81=D9=88=D8=B1=D9=8B=D8=A7 =D9=84=D9=84=D8=B7=D9=88=D8=A7=D8=B1=D8=A6.</sp=
an></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-botto=
m:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.44;margin-to=
p:0pt;margin-bottom:2pt"><span style=3D"font-size:11pt;font-family:Arial,sa=
ns-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=
=88=D8=AF=D9=8A=D9=87 =D9=88=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=
=88=D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA</span></span><p dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font=
-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-co=
lor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=AA=D9=86=D8=AA=D8=B4=D8=B1 =D8=A7=D9=84=D8=AD=D8=A7=D8=AC=D8=A9 =D8=A5=D9=
=84=D9=89 </span><a href=3D"https://ksacytotec.com/" rel=3D"nofollow" targe=
t=3D"_blank" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&amp=
;q=3Dhttps://ksacytotec.com/&amp;source=3Dgmail&amp;ust=3D1756877189235000&=
amp;usg=3DAOvVaw2SAsVPUqDVtjUWGleHk1IF"><span style=3D"font-size:11.5pt;fon=
t-family:Arial,sans-serif;color:rgb(255,152,0);background-color:transparent=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=D8=AD=D8=A8=D9=88=
=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:11.5pt;font-family:Ar=
ial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=D8=
=B9=D8=AF=D9=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=AF=D9=86:</span></=
p><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"l=
ist-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb=
(73,80,87);background-color:transparent;font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" s=
tyle=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"=
><span style=3D"font-size:11.5pt;background-color:transparent;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline">=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6: =D8=AA=D9=
=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=
=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=
=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=84=D8=A3=D8=
=B5=D9=84=D9=8A.</span><span style=3D"font-size:11.5pt;background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"><br><br></span></p></li><l=
i dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family:Ar=
ial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl"=
 role=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-to=
p:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background-color:t=
ransparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline">=D8=AC=D8=AF=D8=A9: =D8=
=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=A8=D8=B3=D8=B1=D9=
=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=85=D8=B9 =D9=85=D8=AA=D8=A7=D8=A8=D8=
=B9=D8=A9.</span><span style=3D"font-size:11.5pt;background-color:transpare=
nt;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=
=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,s=
ans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=
=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-top:0pt=
;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=D9=85=D9=83=D8=A9: =D8=AF=D8=
=B9=D9=85 =D8=B7=D8=A8=D9=8A =D8=A2=D9=85=D9=86 =D9=84=D9=84=D9=86=D8=B3=D8=
=A7=D8=A1 =D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=AA=D9=8A =D9=8A=D8=AD=D8=AA=D8=
=AC=D9=86 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1.</span><span style=3D"font-size:11=
.5pt;background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"><=
br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-s=
ize:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-colo=
r:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline;white-=
space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;t=
ext-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:=
11.5pt;background-color:transparent;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"=
>=D8=AC=D8=A7=D8=B2=D8=A7=D9=86: =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81 =D8=A3=D9=88=
 =D8=A7=D9=84=D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8.</span><span style=3D"fon=
t-size:11.5pt;background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:di=
sc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgr=
ound-color:transparent;font-weight:700;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-heig=
ht:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"f=
ont-size:11.5pt;background-color:transparent;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7: =D8=AA=D9=88=
=D9=81=D9=8A=D8=B1 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=84=D8=A3=
=D8=B5=D9=84=D9=8A =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D9=85=
=D8=AA=D8=AE=D8=B5=D8=B5.</span><span style=3D"font-size:11.5pt;background-=
color:transparent;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline"><br><br></span></=
p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-=
family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p di=
r=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;=
margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=
=D8=B4=D8=A7=D8=B1=D9=82=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=
=D9=86 =D9=88=D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA: =D8=A5=D9=85=D9=83=D8=A7=
=D9=86=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=84=D8=B7=
=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=B5=
=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82.</span><span style=3D"font-size=
:11.5pt;background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
"><br><br></span></p></li></ul><p dir=3D"rtl" style=3D"line-height:1.38;mar=
gin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-family=
:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=F0=9F=93=9E =D8=B1=D9=82=
=D9=85 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D8=B1=D9=85=D9=8A=D9=86 =
=D9=84=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1: </span><span style=
=3D"font-size:12pt;font-family:Arial,sans-serif;color:rgb(51,51,51);font-we=
ight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline">00966538159747=C2=A0</span=
></p><br><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin-=
bottom:2pt"><span style=3D"font-size:10pt;font-family:Arial,sans-serif;colo=
r:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">=D9=84=D9=85=D8=A7=D8=B0=D8=A7 =D8=AA=D8=AE=D8=AA=
=D8=A7=D8=B1=D9=8A=D9=86 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=
=D8=B1=D9=85=D9=8A=D9=86=D8=9F</span></span><br><ul style=3D"margin-top:0px=
;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-size=
:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:t=
ransparent;font-weight:700;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline;white-spa=
ce:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text=
-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.=
5pt;background-color:transparent;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=AE=D8=A8=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9 =D9=81=D9=8A =D9=85=D8=AC=
=D8=A7=D9=84 =D8=A7=D9=84=D9=86=D8=B3=D8=A7=D8=A1 =D9=88=D8=A7=D9=84=D8=AA=
=D9=88=D9=84=D9=8A=D8=AF.</span><span style=3D"font-size:11.5pt;background-=
color:transparent;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline"><br><br></span></=
p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-=
family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p di=
r=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;=
margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=D8=AA=D9=88=D9=
=81=D9=8A=D8=B1 =D8=AF=D9=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A.</span><span style=3D"font-s=
ize:11.5pt;background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgroun=
d-color:transparent;font-weight:700;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;=
white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:=
1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font=
-size:11.5pt;background-color:transparent;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=B4=D8=AE=D8=B5=D9=8A=D8=A9 =
=D9=84=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D8=A8=D8=AF=
=D8=A7=D9=8A=D8=A9 =D8=AD=D8=AA=D9=89 =D8=A7=D9=84=D9=86=D9=87=D8=A7=D9=8A=
=D8=A9.</span><span style=3D"font-size:11.5pt;background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"=
rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,sans-=
serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"=
presentation" style=3D"line-height:1.38;text-align:right;margin-top:0pt;mar=
gin-bottom:12pt"><span style=3D"font-size:11.5pt;background-color:transpare=
nt;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">=D8=AE=D8=B5=D9=88=D8=B5=D9=8A=
=D8=A9 =D9=88=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A=
 =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84.</span><span style=3D"font-size=
:11.5pt;background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
"><br><br></span></p></li></ul><span dir=3D"rtl" style=3D"line-height:1.44;=
margin-top:0pt;margin-bottom:4pt"><span style=3D"font-size:17pt;font-family=
:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=D8=A8=D8=AF=D8=A7=D8=A6=D9=
=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</sp=
an></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bo=
ttom:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;col=
or:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline">=D9=81=D9=8A =D8=A8=D8=B9=D8=B6 =D8=A7=D9=84=D8=
=AD=D8=A7=D9=84=D8=A7=D8=AA=D8=8C =D9=82=D8=AF =D9=8A=D9=82=D8=AA=D8=B1=D8=
=AD =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D8=A8=D8=AF=D8=A7=D8=A6=D9=84 =D8=
=A3=D8=AE=D8=B1=D9=89:</span></p><ul style=3D"margin-top:0px;margin-bottom:=
0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-fa=
mily:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font=
-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=
=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;m=
argin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=
=AA=D9=88=D8=B3=D9=8A=D8=B9 =D9=88=D8=A7=D9=84=D9=83=D8=AD=D8=AA =D8=A7=D9=
=84=D8=AC=D8=B1=D8=A7=D8=AD=D9=8A (D&amp;C).</span><span style=3D"font-size=
:11.5pt;background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;fon=
t-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-c=
olor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline;whi=
te-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.3=
8;text-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-si=
ze:11.5pt;background-color:transparent;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">=D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=AA=D8=AD=D8=AA=D9=88=D9=8A =D8=B9=D9=
=84=D9=89 =D9=85=D9=8A=D9=81=D9=8A=D8=A8=D8=B1=D9=8A=D8=B3=D8=AA=D9=88=D9=
=86 =D9=85=D8=B9 =D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=
=88=D9=84.</span><span style=3D"font-size:11.5pt;background-color:transpare=
nt;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=
=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,s=
ans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=
=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-top:0pt=
;margin-bottom:12pt"><span style=3D"font-size:11.5pt;background-color:trans=
parent;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=A5=D8=AC=D9=
=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AC=D8=B1=D8=A7=D8=AD=D9=8A =D8=A7=D9=84=D9=
=85=D8=A8=D8=A7=D8=B4=D8=B1.</span></p></li></ul><span dir=3D"rtl" style=3D=
"line-height:1.44;margin-top:0pt;margin-bottom:4pt"><span style=3D"font-siz=
e:17pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:tr=
ansparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A3=D8=
=B3=D8=A6=D9=84=D8=A9 =D8=B4=D8=A7=D8=A6=D8=B9=D8=A9</span></span><p dir=3D=
"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span st=
yle=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);ba=
ckground-color:transparent;font-weight:700;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">1. =D9=87=D9=84 =D9=8A=D9=85=D9=83=D9=86 =D8=B4=D8=B1=D8=A7=D8=A1 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=AF=D9=88=D9=86 =D9=88=
=D8=B5=D9=81=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=
=D8=A9=D8=9F</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-s=
erif;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline"><br></span><span style=3D"font-size:11.5=
pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transp=
arent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline">=D8=BA=D8=A7=
=D9=84=D8=A8=D9=8B=D8=A7 =D9=84=D8=A7=D8=8C =D9=88=D9=8A=D8=AC=D8=A8 =D8=A7=
=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=8A=D9=87 =D9=85=D9=86 =D9=85=
=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82 =D8=AA=D8=AD=D8=AA =D8=A5=
=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A.</span></p><p dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font=
-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-co=
lor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">2. =
=D9=83=D9=85 =D8=AA=D8=B3=D8=AA=D8=BA=D8=B1=D9=82 =D8=B9=D9=85=D9=84=D9=8A=
=D8=A9 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=A8=D8=A7=D9=84=D8=AD=
=D8=A8=D9=88=D8=A8=D8=9F</span><span style=3D"font-size:11.5pt;font-family:=
Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weig=
ht:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline"><br></span><span style=3D"fo=
nt-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-=
color:transparent;font-weight:700;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=B9=D8=A7=D8=AF=D8=A9 =D9=85=D9=86 24 =D8=A5=D9=84=D9=89 48 =D8=B3=D8=A7=
=D8=B9=D8=A9 =D8=AD=D8=AA=D9=89 =D9=8A=D9=83=D8=AA=D9=85=D9=84 =D8=A7=D9=84=
=D9=86=D8=B2=D9=8A=D9=81 =D9=88=D8=A5=D8=AE=D8=B1=D8=A7=D8=AC =D8=A7=D9=84=
=D8=AD=D9=85=D9=84.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;marg=
in-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-family:=
Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weig=
ht:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline">3. =D9=87=D9=84 =D9=8A=D8=B3=
=D8=A8=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B9=
=D9=82=D9=85=D8=9F</span><span style=3D"font-size:11.5pt;font-family:Arial,=
sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline"><br></span><span style=3D"font-siz=
e:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:=
transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=84=
=D8=A7=D8=8C =D8=A5=D8=B0=D8=A7 =D8=AA=D9=85 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=
=D8=A7=D9=85=D9=87 =D8=A8=D8=B4=D9=83=D9=84 =D8=B5=D8=AD=D9=8A=D8=AD=D8=8C =
=D9=84=D8=A7 =D9=8A=D8=A4=D8=AB=D8=B1 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=82=
=D8=AF=D8=B1=D8=A9 =D8=A7=D9=84=D8=A5=D9=86=D8=AC=D8=A7=D8=A8=D9=8A=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=82=D8=A8=D9=84=D9=8A=D8=A9.</span></p><br=
><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin-bottom:4=
pt"><span style=3D"font-size:17pt;font-family:Arial,sans-serif;color:rgb(73=
,80,87);background-color:transparent;font-weight:700;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline">=D8=AE=D8=A7=D8=AA=D9=85=D8=A9</span></span><p dir=3D"rtl=
" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=
=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backg=
round-color:transparent;font-weight:700;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine">=D8=A5=D9=86 =D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=
=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 =D8=AA=D9=85=D8=AB=D9=84 =D8=AD=
=D9=84=D9=8B=D8=A7 =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=81=D9=8A =D8=AD=D8=A7=
=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9=D8=8C =D9=84=D9=83=D9=86 =D8=A7=
=D9=84=D8=A3=D9=85=D8=A7=D9=86 =D9=8A=D9=83=D9=85=D9=86 =D9=81=D9=8A =D8=A7=
=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D9=85=D8=AE=D8=AA=D8=B5=D9=8A=D9=86 =
=D9=85=D8=AB=D9=84 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=
=D9=85=D9=8A=D9=86 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D9=88=D9=81=D8=B1 =D8=A7=
=D9=84=D8=AF=D8=B9=D9=85 =D9=88=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=85=
=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D8=B6=D9=85=D9=88=D9=86=D8=8C =D9=85=
=D8=B9 =D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =
=D9=88=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9.</span><span style=
=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backg=
round-color:transparent;font-weight:700;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine"><br></span><span style=3D"font-size:11.5pt;font-family:Arial,sans-seri=
f;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline">=D9=84=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=
=D8=A7=D8=B1=D8=A7=D8=AA =D8=A3=D9=88 =D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=
=D9=84=D8=A7=D8=AC=D8=8C =D8=A7=D8=AA=D8=B5=D9=84=D9=8A =D8=A7=D9=84=D8=A2=
=D9=86 =D8=B9=D9=84=D9=89: </span><span style=3D"font-size:12pt;font-family=
:Arial,sans-serif;color:rgb(51,51,51);font-weight:700;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline">00966538159747 </span><span style=3D"font-size:11.5pt;fo=
nt-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">.</span></p><br><s=
pan dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin-bottom:4pt"=
><span style=3D"font-size:17pt;font-family:Arial,sans-serif;color:rgb(73,80=
,87);background-color:transparent;font-weight:700;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=D8=AA=D8=AD=D8=B0=D9=8A=D8=B1=D8=A7=D8=AA =D9=85=D9=87=D9=
=85=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:=
0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,s=
ans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline">=D9=8A=D9=85=D9=86=D8=B9 =D8=A7=D8=
=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=
=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=85 =D8=
=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =D8=A5=D9=84=
=D8=A7 =D8=A8=D8=A3=D9=85=D8=B1 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8.</span=
><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,=
80,87);background-color:transparent;font-weight:700;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline"><br><br></span></p><p dir=3D"rtl" style=3D"line-height:1.3=
8;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-f=
amily:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;fon=
t-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-variant-alternates:normal;vertical-align:baseline">=D9=84=D8=A7 =D8=AA=D8=
=B3=D8=AA=D8=AE=D8=AF=D9=85=D9=8A =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=
=A5=D8=B0=D8=A7 =D9=83=D8=A7=D9=86 =D9=84=D8=AF=D9=8A=D9=83 =D8=AD=D8=B3=D8=
=A7=D8=B3=D9=8A=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=
=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9.</span><span style=3D"font-size:11.=
5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:trans=
parent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline"><br><br></sp=
an></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-botto=
m:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:=
rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline">=D9=84=D8=A7 =D8=AA=D8=AA=D9=86=D8=A7=D9=88=D9=84=
=D9=8A =D8=A3=D9=8A =D8=AC=D8=B1=D8=B9=D8=A9 =D8=A5=D8=B6=D8=A7=D9=81=D9=8A=
=D8=A9 =D8=A8=D8=AF=D9=88=D9=86 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =
=D8=B7=D8=A8=D9=8A=D8=A9.</span></p><br><br><p dir=3D"rtl" style=3D"line-he=
ight:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt=
;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,=
212,218);font-weight:700;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline">=C2=A0=D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=
=B9=D9=88=D8=AF=D9=8A=D8=A9</span><span style=3D"font-size:11.5pt;font-fami=
ly:Arial,sans-serif;color:rgb(29,33,37);background-color:transparent;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;f=
ont-family:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,21=
2,218);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=A7=D9=84=D8=B1=D9=8A=D8=
=A7=D8=B6</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-seri=
f;color:rgb(29,33,37);background-color:transparent;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-=
align:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Arial,s=
ans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85</span><span styl=
e=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);back=
ground-color:transparent;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline"> </span><s=
pan style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,=
37);background-color:rgb(206,212,218);font-weight:700;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AE=
=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7</span><span style=3D"font-size:=
11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"> </span><span style=3D"fo=
nt-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-=
color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=
=D9=84=D9=83=D9=88=D9=8A=D8=AA</span><span style=3D"font-size:11.5pt;font-f=
amily:Arial,sans-serif;color:rgb(29,33,37);background-color:transparent;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline"> </span><span style=3D"font-size:11.5p=
t;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206=
,212,218);font-weight:700;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=
=D8=AD=D8=B1=D9=8A=D9=86</span><span style=3D"font-size:11.5pt;font-family:=
Arial,sans-serif;color:rgb(29,33,37);background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;font=
-family:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,2=
18);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=A3=
=D8=AF=D9=88=D9=8A=D8=A9 =D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=
=D9=85=D9=84</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-s=
erif;color:rgb(29,33,37);background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Aria=
l,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=C3=97 =D9=85=D9=8A=D8=B2=
=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=84</span><span style=3D"font-size:1=
1.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"> </span><span style=3D"fon=
t-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-c=
olor:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e">=C3=97 =D8=A3=D8=B9=D8=B1=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84</sp=
an><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(2=
9,33,37);background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;col=
or:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:700;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=8A=D9=83 =D9=81=D9=8A =D9=85=D9=83=D8=A9</span><span style=3D"font-size=
:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:t=
ransparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline"> </span><span style=3D"f=
ont-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background=
-color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine">=C3=97 =D8=B9=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D8=AC=D9=87=D8=A7=
=D8=B6</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;c=
olor:rgb(29,33,37);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans=
-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:70=
0;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=
=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=
=D8=B9=D9=88=D8=AF=D9=8A=D8=A9</span><span style=3D"font-size:11.5pt;font-f=
amily:Arial,sans-serif;color:rgb(29,33,37);background-color:transparent;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline"> </span><span style=3D"font-size:11.5p=
t;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206=
,212,218);font-weight:700;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =
=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=
=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA</span><span style=3D"font-size:=
11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"> </span><span style=3D"fo=
nt-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-=
color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86</span><span sty=
le=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);bac=
kground-color:transparent;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline"> </span><=
span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33=
,37);background-color:rgb(206,212,218);font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=
=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=
=A7=D8=AA</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-seri=
f;color:rgb(29,33,37);background-color:transparent;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-=
align:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Arial,s=
ans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=
=88=D8=B1=D8=A9</span><span style=3D"font-size:11.5pt;font-family:Arial,san=
s-serif;color:rgb(29,33,37);background-color:transparent;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline"> </span><span style=3D"font-size:11.5pt;font-family:A=
rial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=A7=D9=84=D8=
=AF=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=A9</span></p>=
<br><br></blockquote></div></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/f88fbac3-0fba-4553-9597-d4f5dc971f40n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/f88fbac3-0fba-4553-9597-d4f5dc971f40n%40googlegroups.com</a>.<br />

------=_Part_73765_1190502520.1756790828919--

------=_Part_73764_1507784103.1756790828919--
