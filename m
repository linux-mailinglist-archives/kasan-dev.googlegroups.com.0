Return-Path: <kasan-dev+bncBDA2XNWCVILRBDWNZ7CQMGQEK4H73TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D8D80B3D106
	for <lists+kasan-dev@lfdr.de>; Sun, 31 Aug 2025 08:07:11 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-31598225bc5sf2868824fac.3
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 23:07:11 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756620430; x=1757225230; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=TEg8IMuDQ93rFtvdLJOU1oTu4dXay5BgVgib7SyPWBI=;
        b=cpkQ3pq7Jy4PDHhXlJxq7QNJ31FK4Ses7eeBaqWS6lwPDv84p1QdyhHWCrPBizzwT6
         MZxy8C04mEuXjdE40pxNtnwBw7t2sOh+FhMhU4GJDx+qDMGBcmDHzNgVrCVOiG7IrZrk
         /ZB/2xBrMWYKjSqZGoKgQfFBPVchIYUvdzVCJVZGzUNAMF1wxsDpEc2bItb3j8Al/SIr
         2P8CURKFMKWYUwr1v4NaI+2gbogUKojfgcvw23F0UiGVtpRf7Co1+KGE0d02X2cvrO3L
         HsWFPeeobkGnFD39hMX4r5y81XWB3QHKjlr1pmcTmrrgVGGrgVdMpNdRYXYgvhKBEt4S
         oMzw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756620430; x=1757225230; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TEg8IMuDQ93rFtvdLJOU1oTu4dXay5BgVgib7SyPWBI=;
        b=luRPH2qSsGcOdkeN7CVcIk0tLwZlQrc2q5XpttFvn9eul3slui4x3cMHnXJwvyM378
         QysbFupJ8I2HUI6I7pGn64j29PCY0IGRa087LVjwOB5x4JnRnY2l8EbDxy51ziA4i7bt
         FSOSTZGUSLF1I3eGyQyZ7Ca5+bsafrBBEi7ttDEYubhYSKRDUMVzQgCME7BOdVSeo4s6
         E82i/cqaBVhCTFO5RjdlYtPb/vt+m4xvQc6k1BAhafFikW3nOog3Jn51wSwmB2/7b1QT
         n4ONPjjcaN+jpoex7K0GPHu63cq8af7J8AU46A0VCqO2n4mKK1rO8z2epEvLBnWZ+3bE
         cQrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756620430; x=1757225230;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=TEg8IMuDQ93rFtvdLJOU1oTu4dXay5BgVgib7SyPWBI=;
        b=hTUJgPElUzapyGhN2BM0+UgVI1PfK6+s12I6tCLTOnfYYG0YF3rHmXFuB6PEGW8gNC
         Gn2fyn3S0HK18Il5I6by5ZdGp8vVD8zGYn/KDdoat2OHPAimzOnG0ZFZLu1/w4DFbo6K
         dxjENpcEUGsYU/UCIhxhbr5Pz9oqxgqffFzyFHFSG8zDpfrkHoD3cB3X11NalilPqevm
         fH2Gp1lpIzhWx36ewX40461Xe8KDjPfVOWjei7TO1q5I10Mcosldi+iut25XHssfqdA3
         s6APnP4vcgNEnzIlBIF16fjYMxNt8/ydrjMxO0F4uXqEF8lnSeOm7Y7Aq0TEALzqm1rT
         R41w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWbr1nsFJFD5TR2EiERLshiKm5WZxSiRuaKahDD8bRMCOmCHfs3XOmyqSkMiIbrN8zeFonJGw==@lfdr.de
X-Gm-Message-State: AOJu0YyCaHiyoG2M7AjJYGAifjVUubmIgyvPSswzHqysfnSds3ZLTOUf
	UmBN9eRJsz4BFpWmGjXIksQXRmGT1BZQuNVzaNjfeuhU06oWd1DSsISz
X-Google-Smtp-Source: AGHT+IGbpicmWhhCpLUK0vhWE/romLNpGSPheJodpaa68+J5Mqdty/mWNVRMdYSfgM+PBdPAl1LgSg==
X-Received: by 2002:a05:6871:e803:b0:315:b073:2270 with SMTP id 586e51a60fabf-3196307ef52mr1688531fac.3.1756620430246;
        Sat, 30 Aug 2025 23:07:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcZODOt59kl3y34AN04CnA97rnbYNuVL1hCgdn8opqNRg==
Received: by 2002:a05:6870:1190:b0:306:e7d7:f921 with SMTP id
 586e51a60fabf-3159607d8d6ls161470fac.1.-pod-prod-08-us; Sat, 30 Aug 2025
 23:07:09 -0700 (PDT)
X-Received: by 2002:a05:6808:2287:b0:437:7b15:78bf with SMTP id 5614622812f47-437f7dd2db6mr2159471b6e.45.1756620429293;
        Sat, 30 Aug 2025 23:07:09 -0700 (PDT)
Date: Sat, 30 Aug 2025 23:07:08 -0700 (PDT)
From: =?UTF-8?B?2LPZitiv2Kkg2KzYr9ipINin2YTYs9i52YjYr9mK2Kk=?=
 <memosksaa@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <4c7a091b-8b8d-460d-be14-d40f9b46141dn@googlegroups.com>
In-Reply-To: <89767b6b-298f-4668-8566-a7fdcf18be3bn@googlegroups.com>
References: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
 <89767b6b-298f-4668-8566-a7fdcf18be3bn@googlegroups.com>
Subject: =?UTF-8?B?UmU6INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNix2YrYp9i2?=
 =?UTF-8?B?IDA1Mzc0NjY1MzkgI9in2YTYs9i52YjYr9mK2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_77274_787616438.1756620428640"
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

------=_Part_77274_787616438.1756620428640
Content-Type: multipart/alternative; 
	boundary="----=_Part_77275_1499132899.1756620428640"

------=_Part_77275_1499132899.1756620428640
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YXZg9in2YYg2KjZiti5INiz2KfZitiq2YjYqtmK2YMgLyAwNTM4MTU5NzQ3IC8gIEN5dG90ZWMg
2KfZhNmD2YjZitiqIGFtYXpvbi5zYSAvLyAvLyAg2K/ZiNin2KEgCtin2YTYpdis2YfYp9i2INmB
2Yog2KfZhNix2YrYp9i2ICAg2KfZhNil2KzZh9in2LYg2KfZhNiv2YjYp9im2YogICDYp9mE2KPY
r9mI2YrYqSDYp9mE2LfYqNmK2Kkg2YTYpdmG2YfYp9ihINin2YTYrdmF2YQgICAK2YXZitiy2YjY
qNix2YjYs9iq2YjZhCAoTWlzb3Byb3N0b2wpICAg2LPYp9mK2KrZiNiq2YMgQ3l0b3RlYyAgINil
2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE2YXYqNmD2LEgICDYo9iv2YjZitipIArYp9mE2KXYrNmH
2KfYtiDYp9mE2KPZhdmG2KkgICDYp9mE2LnZhNin2Kwg2KfZhNiv2YjYp9im2Yog2YTZhNit2YXZ
hCDYutmK2LHYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYsdmK2KfYtiAvLyAwMDk2NjUzODE1OTc0
NyAKLy8g2KjYp9mB2LbZhCDYs9i52LEg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNin2KzZ
h9in2LYg2KfZhNmF2YbYstmE2Yog2YTZhdmI2YLYuSDYp9mE2LHYs9mF2Yp8INin2YTYr9mB2Lkg
2LnZhtivINin2YTYp9iz2KrZhNin2YUgCtmB2Yog2KfZhNix2YrYp9i2INmE2YTYqNmK2LkK2LPY
p9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/ZitipIMOXINiz2KfZitiq2YjYqtmDINio2KfZ
hNix2YrYp9i2IMOXINiz2KfZitiq2YjYqtmDINin2YTYr9mF2KfZhSDDlyDYs9in2YrYqtmI2KrZ
gyDYrtmF2YrYsyDZhdi02YrYtyAKw5cg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2YPZiNmK2Kog
w5cg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2KjYrdix2YrZhiDDlyDYo9iv2YjZitipINil2KzZ
h9in2LYg2KfZhNit2YXZhCDDlyDZhdmK2LLZiNio2LHYs9iq2YjZhCDDlyAK2KPYudix2KfYtiDY
p9mE2K3ZhdmEIMOXINiz2KfZitiq2YjYqtmK2YMg2YHZiiDZhdmD2Kkgw5cg2LnZitin2K/Yp9iq
INin2KzZh9in2LYgw5cg2K/Zg9iq2YjYsdipINin2KzZh9in2LYg2YHZiiDYp9mE2LPYudmI2K/Z
itipIMOXIArYr9mD2KrZiNix2Kkg2KfYrNmH2KfYtiDZgdmKINin2YTZg9mI2YrYqiDDlyDYr9mD
2KrZiNix2Kkg2KfYrNmH2KfYtiDZgdmKINin2YTYqNit2LHZitmGIMOXINiv2YPYqtmI2LHYqSDY
p9is2YfYp9i2INmB2Yog2KfZhNil2YXYp9ix2KfYqiAKw5cg2K/Zg9iq2YjYsdipIMOXINin2YTY
r9mI2LHYqSDYp9mE2LTZh9ix2YrYqQoK2YHZiiDYp9mE2KfYq9mG2YrZhtiMIDI1INij2LrYs9i3
2LMgMjAyNSDZgdmKINiq2YXYp9mFINin2YTYs9in2LnYqSA0OjA2OjI5INi1IFVUQy032Iwg2YPY
qtioINiz2KfZitiq2YjYqtmDIArYp9mE2LPYudmI2K/ZitmHINiz2KfZitiq2YjYqtmDINio2K7Y
tdmFIDIwJSDYsdiz2KfZhNipINmG2LXZh9inOgoKPgo+INiv2YPYqtmI2LHYqSDYp9is2YfYp9i2
INmB2Yog2KfZhNiz2LnZiNiv2YrZhyB8IDAwOTY2NTM4MTU5NzQ3IHzYudmK2KfYr9ipINiz2KfZ
itiq2YjYqtmDIAo+Cj4gINiv2YPYqtmI2LHYqSDZhtmK2LHZhdmK2YYg2YTZhNin2LPYqti02KfY
sdin2Kog2KfZhNi32KjZitipCj4g2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg4oCTINiz2KfZitiq
2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqSAgfCDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmG
IDAwOTY2NTM4MTU5NzQ3IOKAkyAKPiDYp9iz2KrYtNin2LHYp9iqINmI2LnZhNin2Kwg2KLZhdmG
Cj4g2KrYudix2YHZiiDYudmE2Ykg2YPZhCDZhdinINmK2YfZhdmDINi52YYg2K3YqNmI2Kgg2KfZ
hNin2KzZh9in2LYg2Iwg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/ZitmHIAo+IDxo
dHRwczovL2hheWF0YW5uYXMuY29tLz9zcnNsdGlkPUFmbUJPb29yWFR2NndjdGJZN29DYmRfelJC
TXhORFBtVDBGNURQUnd6TWlmQ01nREROTnAxY2JWPiAKPiDYp9mE2LHZitin2LbYjCDYrNiv2KnY
jCDZhdmD2KnYjCDYrNin2LLYp9mG2Iwg2YjYrtmF2YrYsyDZhdi02YrYt9iMINmF2Lkg2K/Zg9iq
2YjYsdipINmG2YrYsdmF2YrZhiDZhNmE2KfYs9iq2LTYp9ix2KfYqiDYp9mE2LfYqNmK2KkgCj4g
2YjYt9mE2Kgg2KfZhNi52YTYp9isINio2LPYsdmK2Kkg2KrYp9mF2KkuCj4g2KrYrdiw2YrYsdin
2Kog2YXZh9mF2KkKPgo+INmK2YXZhti5INin2LPYqtiu2K/Yp9mFINit2KjZiNioINiz2KfZitiq
2YjYqtmDINmB2Yog2K3Yp9mE2KfYqiDYp9mE2K3ZhdmEINin2YTZhdiq2YLYr9mFINio2LnYryDY
p9mE2KPYs9io2YjYuSAxMiDYpdmE2Kcg2KjYo9mF2LEgCj4g2KfZhNi32KjZitioINmI2KfZhNin
2LPYqtmF2KfYuSDYp9mE2Yog2KrZiNis2YrZh9in2KrZhyAuCj4KPgo+ICDYrdio2YjYqCDYs9in
2YrYqtmI2KrZgyB8IDAwOTY2NTM4MTU5NzQ3ICB8INmB2Yog2KfZhNiz2LnZiNiv2YrYqSDigJMg
2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDZhNmE2KfYs9iq2LTYp9ix2KfYqiAKPiDYp9mE2LfY
qNmK2Kkg2KfZhNil2KzZh9in2LYgIAo+Cj4g2YHZiiDYp9mE2LPZhtmI2KfYqiDYp9mE2KPYrtmK
2LHYqdiMINij2LXYqNitINmF2YjYttmI2Lkg2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2LPYp9mK
2KrZiNiq2YMgCj4gPGh0dHBzOi8vc2F1ZGllcnNhYS5jb20vPiDZgdmKINin2YTYs9i52YjYr9mK
2Kkg2YXZhiDYo9mD2KvYsSDYp9mE2YXZiNin2LbZiti5INin2YTYqtmKINiq2KjYrdirINi52YbZ
h9inIAo+INin2YTYs9mK2K/Yp9iq2Iwg2K7Yp9i12Kkg2YHZiiDZhdiv2YYg2YXYq9mEINin2YTY
sdmK2KfYttiMINis2K/YqdiMINmF2YPYqdiMINis2KfYstin2YbYjCDZiNiu2YXZitizINmF2LTZ
iti32Iwg2YjZg9iw2YTZgyDZgdmKIAo+INmF2YbYp9i32YIg2KfZhNiu2YTZitisINmF2KvZhCDY
p9mE2KjYrdix2YrZhiDZiNin2YTZg9mI2YrYqiDZiNin2YTYtNin2LHZgtipLiDZhti42LHZi9in
INmE2K3Ys9in2LPZitipINin2YTZhdmI2LbZiNi5INmI2KPZh9mF2YrYqtmH2IwgCj4g2KrZgtiv
2YUg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDYp9mE2K/YudmFINin2YTYt9io2Yog2YjYp9mE
2KfYs9iq2LTYp9ix2KfYqiDYp9mE2YXYqtiu2LXYtdipINmE2YTZhtiz2KfYoSDYp9mE2YTZiNin
2KrZiiDZitit2KrYrNmGIAo+INil2YTZiSDYp9mE2KrZiNis2YrZhyDYp9mE2LXYrdmK2K0g2YjY
t9mE2Kgg2KfZhNi52YTYp9isINmF2YYg2YXYtdiv2LEg2YXZiNir2YjZgtiMINi52KjYsSDYp9mE
2KfYqti12KfZhCDYudmE2Ykg2KfZhNix2YLZhTogMDA5NjY1MzgxNTk3NDcgCj4gLgo+Cj4gLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4KPiDZhdinINmH2Yog2K3YqNmI2Kgg2LPYp9mK
2KrZiNiq2YMg2YTZhNin2KzZh9in2LbYnwo+Cj4g2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMgKEN5
dG90ZWMpINiq2K3YqtmI2Yog2LnZhNmJINin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqSDYp9mE
2YXZitiy2YjYqNix2YjYs9iq2YjZhCAKPiAoTWlzb3Byb3N0b2wp2Iwg2YjZh9mKINiv2YjYp9ih
INmF2LnYqtmF2K8g2LfYqNmK2YvYpyDZhNi52YTYp9isINmC2LHYrdipINin2YTZhdi52K/YqSDZ
gdmKINin2YTYo9i12YTYjCDZhNmD2YYg2KfZhNij2KjYrdin2KsgCj4g2KfZhNi32KjZitipINij
2KvYqNiq2Kog2YHYp9i52YTZitiq2Ycg2YHZiiDYpdmG2YfYp9ihINin2YTYrdmF2YQg2KfZhNmF
2KjZg9ixIAo+IDxodHRwczovL2hheWF0YW5uYXMuY29tLz9zcnNsdGlkPUFmbUJPb284WmROdkVa
VXBnM0RkZld0Wk5VUktBcHpXZ3NYSHF3bWdzSmRISjY4UVVfeGdPdWdTPiAKPiDYqtit2Kog2KXY
tNix2KfZgSDYt9io2YouCj4g2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2YrYqtmFINin2LPYqtiu
2K/Yp9mFINiz2KfZitiq2YjYqtmDINmB2Yog2K3Yp9mE2KfYqiDYrtin2LXYqSDZiCDYqNis2LHY
udin2Kog2YXYrdiv2K/YqSDZitmC2LHYsdmH2KcgCj4g2KfZhNi32KjZitio2Iwg2YXYuSDYttix
2YjYsdipINin2YTYqtij2YPYryDZhdmGINis2YjYr9ipINin2YTZhdmG2KrYrCDZiNmF2LXYr9ix
2YcuCj4KPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+INmF2KrZiSDYqtiz2KrY
rtiv2YUg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNil2KzZh9in2LbYnwo+ICAgIAo+ICAg
IC0gCj4gICAgCj4gICAg2KfZhNil2KzZh9in2LYg2KfZhNmF2KjZg9ixOiDYrdiq2Ykg2KfZhNij
2LPYqNmI2LkgMTIg2YXZhiDYp9mE2K3ZhdmELgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2LnZ
htivINmI2KzZiNivINiq2LTZiNmH2KfYqiDYrNmG2YrZhtmK2Kkg2K7Yt9mK2LHYqS4KPiAgICAK
PiAgICAtIAo+ICAgIAo+ICAgINmB2Yog2K3Yp9mE2KfYqiDZiNmB2KfYqSDYp9mE2KzZhtmK2YYg
2K/Yp9iu2YQg2KfZhNix2K3ZhS4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINil2LDYpyDZg9in
2YYg2KfZhNit2YXZhCDZiti02YPZhCDYrti32LHZi9inINi52YTZiSDYrdmK2KfYqSDYp9mE2KPZ
hS4KPiAgICAKPiAgICAKPiDimqDvuI8g2YXZhNin2K3YuNipOiDZhNinINmK2Y/Zhti12K0g2KjY
p9iz2KrYrtiv2KfZhSDZh9iw2Ycg2KfZhNit2KjZiNioINiv2YjZhiDZhdiq2KfYqNi52Kkg2LfY
qNmK2KnYjCDZhNiq2KzZhtioINin2YTZhdi22KfYudmB2KfYqi4KPgo+IC0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLQo+Cj4g2LfYsdmK2YLYqSDYp9iz2KrYrtiv2KfZhSDYrdio2YjYqCDY
s9in2YrYqtmI2KrZgyDZhNmE2KfYrNmH2KfYtgo+Cj4g2KfZhNin2LPYqtiu2K/Yp9mFINmK2K7Y
qtmE2YEg2K3Ys9ioINi52YXYsSDYp9mE2K3ZhdmEINmI2K3Yp9mE2Kkg2KfZhNmF2LHYo9ip2Iwg
2YjZhNmD2YYg2YHZiiDYp9mE2LnZhdmI2YU6Cj4KPiAgICAxLiAKPiAgICAKPiAgICDYp9mE2KzY
sdi52Kk6INmK2K3Yr9iv2YfYpyDYp9mE2LfYqNmK2Kgg2YHZgti32Iwg2YjYudin2K/YqSDYqtmD
2YjZhiDYqNmK2YYgODAwINmF2YrZg9ix2YjYutix2KfZhSDZhdmC2LPZhdipINi52YTZiSAKPiAg
ICDYrNix2LnYp9iqLgo+ICAgIAo+ICAgIDIuIAo+ICAgIAo+ICAgINi32LHZitmC2Kkg2KfZhNiq
2YbYp9mI2YQ6INiq2YjYtti5INin2YTYrdio2YjYqCDYqtit2Kog2KfZhNmE2LPYp9mGINij2Ygg
2YHZiiDYp9mE2YXZh9io2YQuCj4gICAgCj4gICAgMy4gCj4gICAgCj4gICAg2KfZhNmF2KrYp9io
2LnYqTog2YrYrNioINmF2LHYp9is2LnYqSDYp9mE2LfYqNmK2Kgg2KjYudivIDI0LTQ4INiz2KfY
udipINmE2YTYqtij2YPYryDZhdmGINin2YPYqtmF2KfZhCDYp9mE2LnZhdmE2YrYqS4KPiAgICAK
PiAgICAKPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+INin2YTYo9i52LHYp9i2
INin2YTZhdiq2YjZgti52Kkg2KjYudivINiq2YbYp9mI2YQg2KfZhNit2KjZiNioCj4KPiAgICAt
IAo+ICAgIAo+ICAgINmG2LLZitmBINmF2YfYqNmE2Yog2YrYtNio2Ycg2KfZhNiv2YjYsdipINin
2YTYtNmH2LHZitipINij2Ygg2KPZg9ir2LEg2LrYstin2LHYqS4KPiAgICAKPiAgICAtIAo+ICAg
IAo+ICAgINiq2LTZhtis2KfYqiDZiNii2YTYp9mFINmB2Yog2KPYs9mB2YQg2KfZhNio2LfZhi4K
PiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINi62KvZitin2YYg2KPZiCDZgtmK2KEuCj4gICAgCj4g
ICAgLSAKPiAgICAKPiAgICDYpdiz2YfYp9mEINiu2YHZitmBLgo+ICAgIAo+ICAgIAo+INil2LDY
pyDYp9iz2KrZhdixINin2YTZhtiy2YrZgSDYp9mE2LTYr9mK2K8g2KPZiCDYuNmH2LHYqiDYo9i5
2LHYp9i2INmF2KvZhCDYp9mE2K/ZiNiu2Kkg2KfZhNit2KfYr9ip2Iwg2YrYrNioINin2YTYqtmI
2KzZhyDZgdmI2LHZi9inIAo+INmE2YTYt9mI2KfYsdimLgo+Cj4gLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tCj4KPiDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjY
r9mK2Ycg2YjYp9mE2KjYrdix2YrZhiDZiNin2YTZg9mI2YrYqgo+Cj4g2KrZhtiq2LTYsSDYp9mE
2K3Yp9is2Kkg2KXZhNmJINit2KjZiNioINin2YTYp9is2YfYp9i2INiz2KfZitiq2YjYqtmDIDxo
dHRwczovL2tzYWN5dG90ZWMuY29tLz4g2YHZiiDYp9mE2LnYr9mK2K8gCj4g2YXZhiDYp9mE2YXY
r9mGOgo+Cj4gICAgLSAKPiAgICAKPiAgICDYp9mE2LHZitin2LY6INiq2YjYp9i12YQg2YXYuSDY
r9mD2KrZiNix2Kkg2YbZitix2YXZitmGINmE2YTYrdi12YjZhCDYudmE2Ykg2KfZhNi52YTYp9is
INin2YTYo9i12YTZii4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINis2K/YqTog2K7Yr9mF2KfY
qiDYt9io2YrYqSDYqNiz2LHZitipINiq2KfZhdipINmF2Lkg2YXYqtin2KjYudipLgo+ICAgIAo+
ICAgIC0gCj4gICAgCj4gICAg2YXZg9ipOiDYr9i52YUg2LfYqNmKINii2YXZhiDZhNmE2YbYs9in
2KEg2KfZhNmE2YjYp9iq2Yog2YrYrdiq2KzZhiDZhNil2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE
2YXYqNmD2LEuCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDYrNin2LLYp9mGOiDYp9iz2KrYtNin
2LHYp9iqINi52KjYsSDYp9mE2YfYp9iq2YEg2KPZiCDYp9mE2YjYp9iq2LPYp9ioLgo+ICAgIAo+
ICAgIC0gCj4gICAgCj4gICAg2K7ZhdmK2LMg2YXYtNmK2Lc6INiq2YjZgdmK2LEg2KfZhNi52YTY
p9isINin2YTYo9i12YTZiiDYqtit2Kog2KXYtNix2KfZgSDZhdiq2K7Ytdi1Lgo+ICAgIAo+ICAg
IC0gCj4gICAgCj4gICAg2KfZhNi02KfYsdmC2Kkg2YjYp9mE2KjYrdix2YrZhiDZiNin2YTZg9mI
2YrYqjog2KXZhdmD2KfZhtmK2Kkg2KfZhNiq2YjYp9i12YQg2YTYt9mE2Kgg2KfZhNi52YTYp9is
INmF2YYg2YXYtdiv2LEg2YXZiNir2YjZgi4KPiAgICAKPiAgICAKPiDwn5OeINix2YLZhSDYr9mD
2KrZiNix2Kkg2YbYsdmF2YrZhiDZhNmE2KfYs9iq2YHYs9in2LE6IDAwOTY2NTM4MTU5NzQ3IAo+
Cj4g2YTZhdin2LDYpyDYqtiu2KrYp9ix2YrZhiDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmG2J8K
Pgo+ICAgIC0gCj4gICAgCj4gICAg2K7YqNix2Kkg2LfYqNmK2Kkg2YHZiiDZhdis2KfZhCDYp9mE
2YbYs9in2KEg2YjYp9mE2KrZiNmE2YrYry4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINiq2YjZ
gdmK2LEg2K/ZiNin2KEg2LPYp9mK2KrZiNiq2YMg2KfZhNij2LXZhNmKLgo+ICAgIAo+ICAgIC0g
Cj4gICAgCj4gICAg2YXYqtin2KjYudipINi02K7YtdmK2Kkg2YTZhNit2KfZhNipINmF2YYg2KfZ
hNio2K/Yp9mK2Kkg2K3YqtmJINin2YTZhtmH2KfZitipLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4g
ICAg2K7YtdmI2LXZitipINmI2LPYsdmK2Kkg2KrYp9mF2Kkg2YHZiiDYp9mE2KrYudin2YXZhC4K
PiAgICAKPiAgICAKPiDYqNiv2KfYptmEINit2KjZiNioINiz2KfZitiq2YjYqtmDCj4KPiDZgdmK
INio2LnYtiDYp9mE2K3Yp9mE2KfYqtiMINmC2K8g2YrZgtiq2LHYrSDYp9mE2LfYqNmK2Kgg2KjY
r9in2KbZhCDYo9iu2LHZiToKPgo+ICAgIC0gCj4gICAgCj4gICAg2KfZhNiq2YjYs9mK2Lkg2YjY
p9mE2YPYrdiqINin2YTYrNix2KfYrdmKIChEJkMpLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg
2KPYr9mI2YrYqSDYqtit2KrZiNmKINi52YTZiSDZhdmK2YHZitio2LHZitiz2KrZiNmGINmF2Lkg
2YXZitiy2YjYqNix2YjYs9iq2YjZhC4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINin2YTYpdis
2YfYp9i2INin2YTYrNix2KfYrdmKINin2YTZhdio2KfYtNixLgo+ICAgIAo+INij2LPYptmE2Kkg
2LTYp9im2LnYqQo+Cj4gMS4g2YfZhCDZitmF2YPZhiDYtNix2KfYoSDYs9in2YrYqtmI2KrZgyDY
qNiv2YjZhiDZiNi12YHYqSDZgdmKINin2YTYs9i52YjYr9mK2KnYnwo+INi62KfZhNio2YvYpyDZ
hNin2Iwg2YjZitis2Kgg2KfZhNit2LXZiNmEINi52YTZitmHINmF2YYg2YXYtdiv2LEg2YXZiNir
2YjZgiDYqtit2Kog2KXYtNix2KfZgSDYt9io2YouCj4KPiAyLiDZg9mFINiq2LPYqti62LHZgiDY
udmF2YTZitipINin2YTYp9is2YfYp9i2INio2KfZhNit2KjZiNio2J8KPiDYudin2K/YqSDZhdmG
IDI0INil2YTZiSA0OCDYs9in2LnYqSDYrdiq2Ykg2YrZg9iq2YXZhCDYp9mE2YbYstmK2YEg2YjY
pdiu2LHYp9isINin2YTYrdmF2YQuCj4KPiAzLiDZh9mEINmK2LPYqNioINiz2KfZitiq2YjYqtmD
INin2YTYudmC2YXYnwo+INmE2KfYjCDYpdiw2Kcg2KrZhSDYp9iz2KrYrtiv2KfZhdmHINio2LTZ
g9mEINi12K3Zitit2Iwg2YTYpyDZitik2KvYsSDYudmE2Ykg2KfZhNmC2K/YsdipINin2YTYpdmG
2KzYp9io2YrYqSDYp9mE2YXYs9iq2YLYqNmE2YrYqS4KPgo+INiu2KfYqtmF2KkKPgo+INil2YYg
2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/Z
itmHINiq2YXYq9mEINit2YTZi9inINi32KjZitmL2Kcg2YHZiiDYrdin2YTYp9iqINiu2KfYtdip
2Iwg2YTZg9mGIAo+INin2YTYo9mF2KfZhiDZitmD2YXZhiDZgdmKINin2LPYqti02KfYsdipINmF
2K7Yqti12YrZhiDZhdir2YQg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDYp9mE2KrZiiDYqtmI
2YHYsSDYp9mE2K/YudmFINmI2KfZhNi52YTYp9isINmF2YYgCj4g2YXYtdiv2LEg2YXYttmF2YjZ
htiMINmF2Lkg2YXYqtin2KjYudipINiv2YLZitmC2Kkg2YjYs9ix2YrYqSDYqtin2YXYqS4KPiDZ
hNmE2KfYs9iq2YHYs9in2LHYp9iqINij2Ygg2LfZhNioINin2YTYudmE2KfYrNiMINin2KrYtdmE
2Yog2KfZhNii2YYg2LnZhNmJOiAwMDk2NjUzODE1OTc0NyAuCj4KPiDYqtit2LDZitix2KfYqiDZ
hdmH2YXYqQo+Cj4g2YrZhdmG2Lkg2KfYs9iq2K7Yr9in2YUg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq
2YMg2YHZiiDYrdin2YTYp9iqINin2YTYrdmF2YQg2KfZhNmF2KrZgtiv2YUg2KjYudivINin2YTY
o9iz2KjZiNi5IDEyINil2YTYpyDYqNij2YXYsSAKPiDYp9mE2LfYqNmK2KguCj4KPiDZhNinINiq
2LPYqtiu2K/ZhdmKINin2YTYrdio2YjYqCDYpdiw2Kcg2YPYp9mGINmE2K/ZitmDINit2LPYp9iz
2YrYqSDZhdmGINin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqS4KPgo+INmE2Kcg2KrYqtmG2KfZ
iNmE2Yog2KPZiiDYrNix2LnYqSDYpdi22KfZgdmK2Kkg2KjYr9mI2YYg2KfYs9iq2LTYp9ix2Kkg
2LfYqNmK2KkuCj4KPgo+ICDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2Kkgw5cg
2LPYp9mK2KrZiNiq2YMg2KjYp9mE2LHZitin2LYgw5cg2LPYp9mK2KrZiNiq2YMg2KfZhNiv2YXY
p9mFIMOXINiz2KfZitiq2YjYqtmDINiu2YXZitizIAo+INmF2LTZiti3IMOXINiz2KfZitiq2YjY
qtmDINmB2Yog2KfZhNmD2YjZitiqIMOXINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNio2K3YsdmK
2YYgw5cg2KPYr9mI2YrYqSDYpdis2YfYp9i2INin2YTYrdmF2YQgw5cgCj4g2YXZitiy2YjYqNix
2LPYqtmI2YQgw5cg2KPYudix2KfYtiDYp9mE2K3ZhdmEIMOXINiz2KfZitiq2YjYqtmK2YMg2YHZ
iiDZhdmD2Kkgw5cg2LnZitin2K/Yp9iqINin2KzZh9in2LYgw5cg2K/Zg9iq2YjYsdipINin2KzZ
h9in2LYgCj4g2YHZiiDYp9mE2LPYudmI2K/ZitipIMOXINiv2YPYqtmI2LHYqSDYp9is2YfYp9i2
INmB2Yog2KfZhNmD2YjZitiqIMOXINiv2YPYqtmI2LHYqSDYp9is2YfYp9i2INmB2Yog2KfZhNio
2K3YsdmK2YYgw5cg2K/Zg9iq2YjYsdipIAo+INin2KzZh9in2LYg2YHZiiDYp9mE2KXZhdin2LHY
p9iqIMOXINiv2YPYqtmI2LHYqSDDlyDYp9mE2K/ZiNix2Kkg2KfZhNi02YfYsdmK2KkKPgo+Cj4N
Cg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmli
ZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJl
IGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQg
YW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZp
ZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dp
ZC9rYXNhbi1kZXYvNGM3YTA5MWItOGI4ZC00NjBkLWJlMTQtZDQwZjliNDYxNDFkbiU0MGdvb2ds
ZWdyb3Vwcy5jb20uCg==
------=_Part_77275_1499132899.1756620428640
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<span dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 24pt; margin-bott=
om: 6pt;"><span style=3D"font-size: 23pt; font-family: Arial, sans-serif; c=
olor: rgb(68, 68, 68); background-color: transparent; font-weight: 700; fon=
t-variant-numeric: normal; font-variant-east-asian: normal; font-variant-al=
ternates: normal; font-variant-position: normal; font-variant-emoji: normal=
; vertical-align: baseline; white-space-collapse: preserve;">=D9=85=D9=83=
=D8=A7=D9=86 =D8=A8=D9=8A=D8=B9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=
=D9=83 / 0538159747 /=C2=A0 Cytotec =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA </=
span><a href=3D"http://amazon.sa"><span style=3D"font-size: 23pt; font-fami=
ly: Arial, sans-serif; color: rgb(17, 85, 204); background-color: transpare=
nt; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian=
: normal; font-variant-alternates: normal; font-variant-position: normal; f=
ont-variant-emoji: normal; text-decoration-line: underline; text-decoration=
-skip-ink: none; vertical-align: baseline; white-space-collapse: preserve;"=
>amazon.sa</span></a></span><span dir=3D"rtl" style=3D"line-height: 1.38; m=
argin-top: 24pt; margin-bottom: 6pt;"><span style=3D"font-size: 23pt; font-=
family: Arial, sans-serif; color: rgb(68, 68, 68); background-color: transp=
arent; font-weight: 700; font-variant-numeric: normal; font-variant-east-as=
ian: normal; font-variant-alternates: normal; font-variant-position: normal=
; font-variant-emoji: normal; vertical-align: baseline; white-space-collaps=
e: preserve;">=C2=A0// //=C2=A0 =D8=AF=D9=88=D8=A7=D8=A1 =D8=A7=D9=84=D8=A5=
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
=D9=8A=D8=B1</span></span><span style=3D"font-size: 10pt; font-family: Aria=
l, sans-serif; color: rgb(68, 68, 68); background-color: transparent; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; white-space-collapse: preserve;">=D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=
=B6 // </span><span style=3D"font-size: 23pt; font-family: Arial, sans-seri=
f; color: rgb(68, 68, 68); background-color: transparent; font-weight: 700;=
 font-variant-numeric: normal; font-variant-east-asian: normal; font-varian=
t-alternates: normal; font-variant-position: normal; font-variant-emoji: no=
rmal; vertical-align: baseline; white-space-collapse: preserve;">0096653815=
9747 </span><span style=3D"font-size: 10pt; font-family: Arial, sans-serif;=
 color: rgb(68, 68, 68); background-color: transparent; font-variant-numeri=
c: normal; font-variant-east-asian: normal; font-variant-alternates: normal=
; font-variant-position: normal; font-variant-emoji: normal; vertical-align=
: baseline; white-space-collapse: preserve;">// =D8=A8=D8=A7=D9=81=D8=B6=D9=
=84 =D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D9=
=85=D9=86=D8=B2=D9=84=D9=8A =D9=84=D9=85=D9=88=D9=82=D8=B9 =D8=A7=D9=84=D8=
=B1=D8=B3=D9=85=D9=8A| =D8=A7=D9=84=D8=AF=D9=81=D8=B9 =D8=B9=D9=86=D8=AF =
=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=84=D8=A7=D9=85 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B1=D9=8A=D8=A7=D8=B6 =D9=84=D9=84=D8=A8=D9=8A=D8=B9</span><span style=
=3D"font-size: 10pt; font-family: Arial, sans-serif; color: rgb(68, 68, 68)=
; background-color: transparent; font-variant-numeric: normal; font-variant=
-east-asian: normal; font-variant-alternates: normal; font-variant-position=
: normal; font-variant-emoji: normal; vertical-align: baseline; white-space=
-collapse: preserve;"><br /></span><span style=3D"font-size: 10pt; font-fam=
ily: Arial, sans-serif; color: rgb(68, 68, 68); background-color: transpare=
nt; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; white-space-collapse: preserve;">=D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=
=D9=88=D8=AF=D9=8A=D8=A9 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =
=D8=A8=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =C3=97 =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=
=D8=B7 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=
=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =C3=97 =
=D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=
=D8=AD=D9=85=D9=84 =C3=97 =D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=
=D9=88=D9=84 =C3=97 =D8=A3=D8=B9=D8=B1=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=
=D9=84 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 =D9=81=D9=8A=
 =D9=85=D9=83=D8=A9 =C3=97 =D8=B9=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D8=
=AC=D9=87=D8=A7=D8=B6 =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=
=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=
=8A=D8=A9 =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=
=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA =C3=97 =D8=AF=
=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =
=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =C3=97 =D8=AF=D9=83=D8=AA=D9=88=
=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A5=
=D9=85=D8=A7=D8=B1=D8=A7=D8=AA =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =
=C3=97 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=D8=B4=D9=87=D8=B1=
=D9=8A=D8=A9</span><br /><br /><div class=3D"gmail_quote"><div dir=3D"auto"=
 class=3D"gmail_attr">=D9=81=D9=8A =D8=A7=D9=84=D8=A7=D8=AB=D9=86=D9=8A=D9=
=86=D8=8C 25 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025 =D9=81=D9=8A =D8=AA=D9=85=
=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9 4:06:29 =D8=B5 UTC-7=D8=
=8C =D9=83=D8=AA=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D8=A8=D8=AE=D8=B5=D9=85 20% =D8=B1=D8=B3=D8=A7=D9=84=D8=A9 =D9=
=86=D8=B5=D9=87=D8=A7:<br/></div><blockquote class=3D"gmail_quote" style=3D=
"margin: 0 0 0 0.8ex; border-right: 1px solid rgb(204, 204, 204); padding-r=
ight: 1ex;"><br><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;=
margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans-ser=
if;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=
=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=
=AF=D9=8A=D9=87 | </span><span style=3D"font-size:12pt;font-family:Arial,sa=
ns-serif;color:rgb(51,51,51);font-weight:700;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">00966538159747 </span><span style=3D"font-size:13pt;font-family:A=
rial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weigh=
t:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">|=D8=B9=D9=8A=D8=A7=D8=AF=D8=
=A9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=C2=A0</span></span><p dir=3D=
"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span st=
yle=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);ba=
ckground-color:transparent;font-weight:700;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=C2=A0=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=
=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =
=D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9</span><span style=3D"font-size:11.5pt;=
font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transpare=
nt;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline"><br></span><span=
 style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87)=
;background-color:transparent;font-weight:700;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =E2=80=93 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=
=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=C2=A0 | =D8=AF=D9=83=D8=AA=D9=
=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 </span><span style=3D"=
font-size:12pt;font-family:Arial,sans-serif;color:rgb(51,51,51);font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">00966538159747 </span><span st=
yle=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);ba=
ckground-color:transparent;font-weight:700;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=E2=80=93 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D9=88=
=D8=B9=D9=84=D8=A7=D8=AC =D8=A2=D9=85=D9=86</span><span style=3D"font-size:=
11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:tr=
ansparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline"><br></spa=
n><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73=
,80,87);background-color:transparent;font-weight:700;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline">=D8=AA=D8=B9=D8=B1=D9=81=D9=8A =D8=B9=D9=84=D9=89 =D9=83=
=D9=84 =D9=85=D8=A7 =D9=8A=D9=87=D9=85=D9=83 =D8=B9=D9=86 =D8=AD=D8=A8=D9=
=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=8C </span><a href=
=3D"https://hayatannas.com/?srsltid=3DAfmBOoorXTv6wctbY7oCbd_zRBMxNDPmT0F5D=
PRwzMifCMgDDNNp1cbV" target=3D"_blank" rel=3D"nofollow" data-saferedirectur=
l=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps://hayatannas.com/?srs=
ltid%3DAfmBOoorXTv6wctbY7oCbd_zRBMxNDPmT0F5DPRwzMifCMgDDNNp1cbV&amp;source=
=3Dgmail&amp;ust=3D1756635883459000&amp;usg=3DAOvVaw1VqzS1-8YEG2OIIMVOM-96"=
><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(255=
,152,0);background-color:transparent;font-weight:700;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87</span></a><span style=3D"f=
ont-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=
=D9=83=D8=A9=D8=8C =D8=AC=D8=A7=D8=B2=D8=A7=D9=86=D8=8C =D9=88=D8=AE=D9=85=
=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7=D8=8C =D9=85=D8=B9 =D8=AF=D9=83=D8=AA=
=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=
=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=
=D8=A9 =D9=88=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A8=
=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9.</span></p><span dir=3D"r=
tl" style=3D"line-height:1.44;margin-top:0pt;margin-bottom:4pt"><span style=
=3D"font-size:17pt;font-family:Arial,sans-serif;color:rgb(255,0,0);backgrou=
nd-color:transparent;font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">=D8=AA=D8=AD=D8=B0=D9=8A=D8=B1=D8=A7=D8=AA =D9=85=D9=87=D9=85=D8=A9</span=
></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bott=
om:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color=
:rgb(255,0,0);background-color:transparent;font-weight:700;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline">=D9=8A=D9=85=D9=86=D8=B9 =D8=A7=D8=B3=D8=AA=D8=AE=
=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=
=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=85 =D8=A8=D8=B9=D8=AF =
=D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =D8=A5=D9=84=D8=A7 =D8=A8=D8=
=A3=D9=85=D8=B1 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D9=88=D8=A7=D9=84=D8=
=A7=D8=B3=D8=AA=D9=85=D8=A7=D8=B9 =D8=A7=D9=84=D9=8A =D8=AA=D9=88=D8=AC=D9=
=8A=D9=87=D8=A7=D8=AA=D9=87 .</span></p><br><br><span dir=3D"rtl" style=3D"=
line-height:1.44;margin-top:0pt;margin-bottom:2pt"><span style=3D"font-size=
:11pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:tra=
nsparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline">=C2=A0=D8=
=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 | </span><=
span style=3D"font-size:12pt;font-family:Arial,sans-serif;color:rgb(51,51,5=
1);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">00966538159747 <=
/span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(=
73,80,87);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=C2=A0| =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=
=AF=D9=8A=D8=A9 =E2=80=93 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=
=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=
=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=
=D9=87=D8=A7=D8=B6=C2=A0=C2=A0</span></span><p dir=3D"rtl" style=3D"line-he=
ight:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5p=
t;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transpa=
rent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">=D9=81=D9=8A =
=D8=A7=D9=84=D8=B3=D9=86=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=AE=D9=8A=
=D8=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD =D9=85=D9=88=D8=B6=D9=88=D8=B9 =
</span><a href=3D"https://saudiersaa.com/" target=3D"_blank" rel=3D"nofollo=
w" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps=
://saudiersaa.com/&amp;source=3Dgmail&amp;ust=3D1756635883459000&amp;usg=3D=
AOvVaw0pfa_GcC-aDB3SWop6anjg"><span style=3D"font-size:11.5pt;font-family:A=
rial,sans-serif;color:rgb(255,152,0);background-color:transparent;font-weig=
ht:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=
=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83</span></a><span style=3D"font-size:11.5pt;font-family:Arial,sans-=
serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=
=D9=88=D8=AF=D9=8A=D8=A9 =D9=85=D9=86 =D8=A3=D9=83=D8=AB=D8=B1 =D8=A7=D9=84=
=D9=85=D9=88=D8=A7=D8=B6=D9=8A=D8=B9 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=A8=
=D8=AD=D8=AB =D8=B9=D9=86=D9=87=D8=A7 =D8=A7=D9=84=D8=B3=D9=8A=D8=AF=D8=A7=
=D8=AA=D8=8C =D8=AE=D8=A7=D8=B5=D8=A9 =D9=81=D9=8A =D9=85=D8=AF=D9=86 =D9=
=85=D8=AB=D9=84 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=
=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=AC=D8=A7=D8=B2=D8=A7=D9=86=D8=8C =D9=
=88=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7=D8=8C =D9=88=D9=83=D8=
=B0=D9=84=D9=83 =D9=81=D9=8A =D9=85=D9=86=D8=A7=D8=B7=D9=82 =D8=A7=D9=84=D8=
=AE=D9=84=D9=8A=D8=AC =D9=85=D8=AB=D9=84 =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=
=8A=D9=86 =D9=88=D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA =D9=88=D8=A7=D9=84=D8=
=B4=D8=A7=D8=B1=D9=82=D8=A9. =D9=86=D8=B8=D8=B1=D9=8B=D8=A7 =D9=84=D8=AD=D8=
=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=B6=D9=88=D8=B9 =D9=
=88=D8=A3=D9=87=D9=85=D9=8A=D8=AA=D9=87=D8=8C =D8=AA=D9=82=D8=AF=D9=85 =D8=
=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=
=A7=D9=84=D8=AF=D8=B9=D9=85 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D9=88=D8=A7=D9=
=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=
=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=84=D9=84=D9=86=D8=B3=D8=A7=D8=A1 =D8=A7=D9=
=84=D9=84=D9=88=D8=A7=D8=AA=D9=8A =D9=8A=D8=AD=D8=AA=D8=AC=D9=86 =D8=A5=D9=
=84=D9=89 =D8=A7=D9=84=D8=AA=D9=88=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D8=B5=D8=
=AD=D9=8A=D8=AD =D9=88=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=
=AC =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82=D8=
=8C =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D8=A7=D8=AA=D8=B5=D8=A7=D9=84 =D8=B9=D9=
=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85: </span><span style=3D"font-size:1=
2pt;font-family:Arial,sans-serif;color:rgb(51,51,51);font-weight:700;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">00966538159747 </span><span style=3D"font=
-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-co=
lor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">.</=
span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bot=
tom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.44;margin-=
top:0pt;margin-bottom:2pt"><span style=3D"font-size:10pt;font-family:Arial,=
sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline">=D9=85=D8=A7 =D9=87=D9=8A =D8=AD=
=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=
=D8=A7=D8=AC=D9=87=D8=A7=D8=B6=D8=9F</span></span><p dir=3D"rtl" style=3D"l=
ine-height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size=
:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:t=
ransparent;font-weight:700;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=AD=
=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 (Cytotec) =D8=
=AA=D8=AD=D8=AA=D9=88=D9=8A =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D8=A7=D8=
=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9 =D8=A7=D9=84=D9=85=D9=
=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84 (Misoprostol)=D8=
=8C =D9=88=D9=87=D9=8A =D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D8=B9=D8=AA=D9=85=D8=
=AF =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=82=D8=
=B1=D8=AD=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AF=D8=A9 =D9=81=D9=8A =D8=A7=D9=
=84=D8=A3=D8=B5=D9=84=D8=8C =D9=84=D9=83=D9=86 =D8=A7=D9=84=D8=A3=D8=A8=D8=
=AD=D8=A7=D8=AB =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A3=D8=AB=D8=A8=D8=
=AA=D8=AA =D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=AA=D9=87 =D9=81=D9=8A </span><a=
 href=3D"https://hayatannas.com/?srsltid=3DAfmBOoo8ZdNvEZUpg3DdfWtZNURKApzW=
gsXHqwmgsJdHJ68QU_xgOugS" target=3D"_blank" rel=3D"nofollow" data-saferedir=
ecturl=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps://hayatannas.com=
/?srsltid%3DAfmBOoo8ZdNvEZUpg3DdfWtZNURKApzWgsXHqwmgsJdHJ68QU_xgOugS&amp;so=
urce=3Dgmail&amp;ust=3D1756635883459000&amp;usg=3DAOvVaw2wFEekQEXi4eXXU6Nlr=
qQj"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb=
(255,152,0);background-color:transparent;font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=
=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1</span></a><span style=3D"fon=
t-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-c=
olor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline"> =
=D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A.</span=
><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,=
80,87);background-color:transparent;font-weight:700;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline"><br></span><span style=3D"font-size:11.5pt;font-family:Ari=
al,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:=
700;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=
=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D9=8A=D8=AA=D9=85 =D8=A7=D8=B3=D8=AA=
=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=
=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9 =D9=88 =D8=
=A8=D8=AC=D8=B1=D8=B9=D8=A7=D8=AA =D9=85=D8=AD=D8=AF=D8=AF=D8=A9 =D9=8A=D9=
=82=D8=B1=D8=B1=D9=87=D8=A7 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8=D8=8C =D9=
=85=D8=B9 =D8=B6=D8=B1=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=D8=AA=D8=A3=D9=83=D8=
=AF =D9=85=D9=86 =D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=
=AC =D9=88=D9=85=D8=B5=D8=AF=D8=B1=D9=87.</span></p><p dir=3D"rtl" style=3D=
"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span di=
r=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin-bottom:2pt"><span=
 style=3D"font-size:10pt;font-family:Arial,sans-serif;color:rgb(73,80,87);b=
ackground-color:transparent;font-weight:700;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline">=D9=85=D8=AA=D9=89 =D8=AA=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D8=AD=D8=
=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=
=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=9F</span></span><ul style=3D"margin-top:0px;=
margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:=
11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:tr=
ansparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline;white-spac=
e:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-=
align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5=
pt;background-color:transparent;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=
=B1: =D8=AD=D8=AA=D9=89 =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =D9=
=85=D9=86 =D8=A7=D9=84=D8=AD=D9=85=D9=84.</span><span style=3D"font-size:11=
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
>=D8=B9=D9=86=D8=AF =D9=88=D8=AC=D9=88=D8=AF =D8=AA=D8=B4=D9=88=D9=87=D8=A7=
=D8=AA =D8=AC=D9=86=D9=8A=D9=86=D9=8A=D8=A9 =D8=AE=D8=B7=D9=8A=D8=B1=D8=A9.=
</span><span style=3D"font-size:11.5pt;background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" st=
yle=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;c=
olor:rgb(73,80,87);background-color:transparent;font-weight:700;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"present=
ation" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bot=
tom:0pt"><span style=3D"font-size:11.5pt;background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=
=AA =D9=88=D9=81=D8=A7=D8=A9 =D8=A7=D9=84=D8=AC=D9=86=D9=8A=D9=86 =D8=AF=D8=
=A7=D8=AE=D9=84 =D8=A7=D9=84=D8=B1=D8=AD=D9=85.</span><span style=3D"font-s=
ize:11.5pt;background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgroun=
d-color:transparent;font-weight:700;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;=
white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:=
1.38;text-align:right;margin-top:0pt;margin-bottom:12pt"><span style=3D"fon=
t-size:11.5pt;background-color:transparent;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=D8=A5=D8=B0=D8=A7 =D9=83=D8=A7=D9=86 =D8=A7=D9=84=D8=AD=D9=85=D9=
=84 =D9=8A=D8=B4=D9=83=D9=84 =D8=AE=D8=B7=D8=B1=D9=8B=D8=A7 =D8=B9=D9=84=D9=
=89 =D8=AD=D9=8A=D8=A7=D8=A9 =D8=A7=D9=84=D8=A3=D9=85.</span><span style=3D=
"font-size:11.5pt;background-color:transparent;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline"><br><br></span></p></li></ul><p dir=3D"rtl" style=3D"line-heigh=
t:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;f=
ont-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparen=
t;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline">=E2=9A=A0=EF=B8=
=8F =D9=85=D9=84=D8=A7=D8=AD=D8=B8=D8=A9: =D9=84=D8=A7 =D9=8A=D9=8F=D9=86=
=D8=B5=D8=AD =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D9=87=D8=B0=
=D9=87 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AF=D9=88=D9=86 =D9=85=D8=AA=
=D8=A7=D8=A8=D8=B9=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9=D8=8C =D9=84=D8=AA=D8=AC=
=D9=86=D8=A8 =D8=A7=D9=84=D9=85=D8=B6=D8=A7=D8=B9=D9=81=D8=A7=D8=AA.</span>=
</p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0=
pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0=
pt;margin-bottom:2pt"><span style=3D"font-size:10pt;font-family:Arial,sans-=
serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6</=
span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-=
bottom:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;c=
olor:rgb(73,80,87);background-color:transparent;font-weight:700;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline">=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=
=A7=D9=85 =D9=8A=D8=AE=D8=AA=D9=84=D9=81 =D8=AD=D8=B3=D8=A8 =D8=B9=D9=85=D8=
=B1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D9=88=D8=AD=D8=A7=D9=84=D8=A9 =D8=A7=D9=
=84=D9=85=D8=B1=D8=A3=D8=A9=D8=8C =D9=88=D9=84=D9=83=D9=86 =D9=81=D9=8A =D8=
=A7=D9=84=D8=B9=D9=85=D9=88=D9=85:</span></p><ol style=3D"margin-top:0px;ma=
rgin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:decimal;font-size=
:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:t=
ransparent;font-weight:700;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline;white-spa=
ce:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text=
-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.=
5pt;background-color:transparent;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=A7=D9=84=D8=AC=D8=B1=D8=B9=D8=A9: =D9=8A=D8=AD=D8=AF=D8=AF=D9=87=D8=A7 =
=D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D9=81=D9=82=D8=B7=D8=8C =D9=88=D8=B9=
=D8=A7=D8=AF=D8=A9 =D8=AA=D9=83=D9=88=D9=86 =D8=A8=D9=8A=D9=86 800 =D9=85=
=D9=8A=D9=83=D8=B1=D9=88=D8=BA=D8=B1=D8=A7=D9=85 =D9=85=D9=82=D8=B3=D9=85=
=D8=A9 =D8=B9=D9=84=D9=89 =D8=AC=D8=B1=D8=B9=D8=A7=D8=AA.</span><span style=
=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-=
type:decimal;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,=
87);background-color:transparent;font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D=
"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span =
style=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D9=84=D8=AA=D9=86=
=D8=A7=D9=88=D9=84: =D8=AA=D9=88=D8=B6=D8=B9 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=
=D8=A8 =D8=AA=D8=AD=D8=AA =D8=A7=D9=84=D9=84=D8=B3=D8=A7=D9=86 =D8=A3=D9=88=
 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=87=D8=A8=D9=84.</span><span style=3D"fo=
nt-size:11.5pt;background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:d=
ecimal;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);ba=
ckground-color:transparent;font-weight:700;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-=
height:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt"><span style=
=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=D8=A7=D9=84=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9: =D9=8A=D8=
=AC=D8=A8 =D9=85=D8=B1=D8=A7=D8=AC=D8=B9=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=
=8A=D8=A8 =D8=A8=D8=B9=D8=AF 24-48 =D8=B3=D8=A7=D8=B9=D8=A9 =D9=84=D9=84=D8=
=AA=D8=A3=D9=83=D8=AF =D9=85=D9=86 =D8=A7=D9=83=D8=AA=D9=85=D8=A7=D9=84 =D8=
=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A9.</span><span style=3D"font-size:11.=
5pt;background-color:transparent;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline"><b=
r><br></span></p></li></ol><p dir=3D"rtl" style=3D"line-height:1.38;margin-=
top:0pt;margin-bottom:0pt"></p><hr><p></p><p dir=3D"rtl" style=3D"line-heig=
ht:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:10pt;fon=
t-family:&quot;Courier New&quot;,monospace;color:rgb(29,33,37);background-c=
olor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=A7=D9=84=D8=A3=D8=B9=D8=B1=D8=A7=D8=B6 =D8=A7=D9=84=D9=85=D8=AA=D9=88=
=D9=82=D8=B9=D8=A9 =D8=A8=D8=B9=D8=AF =D8=AA=D9=86=D8=A7=D9=88=D9=84 =D8=A7=
=D9=84=D8=AD=D8=A8=D9=88=D8=A8</span></p><ul style=3D"margin-top:0px;margin=
-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt=
;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transpar=
ent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline;white-space:pre"=
><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:=
right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;bac=
kground-color:transparent;font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=86=D8=
=B2=D9=8A=D9=81 =D9=85=D9=87=D8=A8=D9=84=D9=8A =D9=8A=D8=B4=D8=A8=D9=87 =D8=
=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=
=A9 =D8=A3=D9=88 =D8=A3=D9=83=D8=AB=D8=B1 =D8=BA=D8=B2=D8=A7=D8=B1=D8=A9.</=
span><span style=3D"font-size:11.5pt;background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" styl=
e=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;col=
or:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentat=
ion" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-botto=
m:0pt"><span style=3D"font-size:11.5pt;background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=AA=D8=B4=D9=86=D8=AC=D8=A7=D8=AA =D9=
=88=D8=A2=D9=84=D8=A7=D9=85 =D9=81=D9=8A =D8=A3=D8=B3=D9=81=D9=84 =D8=A7=D9=
=84=D8=A8=D8=B7=D9=86.</span><span style=3D"font-size:11.5pt;background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline"><br><br></span></p><=
/li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-fam=
ily:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=
=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;m=
argin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=D8=BA=D8=AB=D9=
=8A=D8=A7=D9=86 =D8=A3=D9=88 =D9=82=D9=8A=D8=A1.</span><span style=3D"font-=
size:11.5pt;background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc=
;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgrou=
nd-color:transparent;font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height=
:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt"><span style=3D"fo=
nt-size:11.5pt;background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline">=D8=A5=D8=B3=D9=87=D8=A7=D9=84 =D8=AE=D9=81=D9=8A=D9=81.</span><sp=
an style=3D"font-size:11.5pt;background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline"><br><br></span></p></li></ul><p dir=3D"rtl" style=3D=
"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-si=
ze:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A5=
=D8=B0=D8=A7 =D8=A7=D8=B3=D8=AA=D9=85=D8=B1 =D8=A7=D9=84=D9=86=D8=B2=D9=8A=
=D9=81 =D8=A7=D9=84=D8=B4=D8=AF=D9=8A=D8=AF =D8=A3=D9=88 =D8=B8=D9=87=D8=B1=
=D8=AA =D8=A3=D8=B9=D8=B1=D8=A7=D8=B6 =D9=85=D8=AB=D9=84 =D8=A7=D9=84=D8=AF=
=D9=88=D8=AE=D8=A9 =D8=A7=D9=84=D8=AD=D8=A7=D8=AF=D8=A9=D8=8C =D9=8A=D8=AC=
=D8=A8 =D8=A7=D9=84=D8=AA=D9=88=D8=AC=D9=87 =D9=81=D9=88=D8=B1=D9=8B=D8=A7 =
=D9=84=D9=84=D8=B7=D9=88=D8=A7=D8=B1=D8=A6.</span></p><p dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span=
 dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin-bottom:2pt"><s=
pan style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(73,80,87=
);background-color:transparent;font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 =D9=88=
=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=83=D9=88=
=D9=8A=D8=AA</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-t=
op:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-family:Aria=
l,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">=D8=AA=D9=86=D8=AA=D8=B4=D8=B1 =
=D8=A7=D9=84=D8=AD=D8=A7=D8=AC=D8=A9 =D8=A5=D9=84=D9=89 </span><a href=3D"h=
ttps://ksacytotec.com/" target=3D"_blank" rel=3D"nofollow" data-saferedirec=
turl=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dhttps://ksacytotec.com/&=
amp;source=3Dgmail&amp;ust=3D1756635883459000&amp;usg=3DAOvVaw0O7hxmQ0mkggI=
rKh_Y3PlT"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;col=
or:rgb(255,152,0);background-color:transparent;font-weight:700;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=
=AC=D9=87=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a>=
<span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,8=
0,87);background-color:transparent;font-weight:700;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-=
align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=D8=B9=D8=AF=D9=8A=D8=AF =D9=85=
=D9=86 =D8=A7=D9=84=D9=85=D8=AF=D9=86:</span></p><ul style=3D"margin-top:0p=
x;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-siz=
e:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:=
transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline;white-sp=
ace:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;tex=
t-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11=
.5pt;background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6: =D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=
=D8=B9 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86 =D9=84=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A.</span><span =
style=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-s=
tyle-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,8=
0,87);background-color:transparent;font-weight:700;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-=
align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=
=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><sp=
an style=3D"font-size:11.5pt;background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">=D8=AC=D8=AF=D8=A9: =D8=AE=D8=AF=D9=85=D8=A7=D8=AA =
=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A8=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=
=D8=A9 =D9=85=D8=B9 =D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9.</span><span style=
=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-=
type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87)=
;background-color:transparent;font-weight:700;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"li=
ne-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span sty=
le=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline">=D9=85=D9=83=D8=A9: =D8=AF=D8=B9=D9=85 =D8=B7=D8=A8=D9=8A =
=D8=A2=D9=85=D9=86 =D9=84=D9=84=D9=86=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D9=84=
=D9=88=D8=A7=D8=AA=D9=8A =D9=8A=D8=AD=D8=AA=D8=AC=D9=86 =D9=84=D8=A5=D9=86=
=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=
=D9=83=D8=B1.</span><span style=3D"font-size:11.5pt;background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline"><br><br></span></p></li><li d=
ir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial=
,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:70=
0;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" ro=
le=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-top:0=
pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background-color:tran=
sparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=D8=AC=D8=A7=D8=B2=D8=A7=D9=
=86: =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=B9=D8=A8=D8=B1 =
=D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81 =D8=A3=D9=88 =D8=A7=D9=84=D9=88=D8=A7=
=D8=AA=D8=B3=D8=A7=D8=A8.</span><span style=3D"font-size:11.5pt;background-=
color:transparent;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline"><br><br></span></=
p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-=
family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p di=
r=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;=
margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=D8=AE=D9=85=D9=
=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7: =D8=AA=D9=88=D9=81=D9=8A=D8=B1 =D8=A7=
=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A =D8=AA=
=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5.=
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
tes:normal;vertical-align:baseline">=D8=A7=D9=84=D8=B4=D8=A7=D8=B1=D9=82=D8=
=A9 =D9=88=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=
=83=D9=88=D9=8A=D8=AA: =D8=A5=D9=85=D9=83=D8=A7=D9=86=D9=8A=D8=A9 =D8=A7=D9=
=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=84=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=
=B9=D9=84=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=
=AB=D9=88=D9=82.</span><span style=3D"font-size:11.5pt;background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"><br><br></span></p></li></=
ul><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12=
pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(=
73,80,87);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=F0=9F=93=9E =D8=B1=D9=82=D9=85 =D8=AF=D9=83=D8=AA=D9=
=88=D8=B1=D8=A9 =D9=86=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=
=AA=D9=81=D8=B3=D8=A7=D8=B1: </span><span style=3D"font-size:12pt;font-fami=
ly:Arial,sans-serif;color:rgb(51,51,51);font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">00966538159747=C2=A0</span></p><br><span dir=3D"rtl" s=
tyle=3D"line-height:1.44;margin-top:0pt;margin-bottom:2pt"><span style=3D"f=
ont-size:10pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-c=
olor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D9=84=D9=85=D8=A7=D8=B0=D8=A7 =D8=AA=D8=AE=D8=AA=D8=A7=D8=B1=D9=8A=D9=86 =
=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=
=D8=9F</span></span><br><ul style=3D"margin-top:0px;margin-bottom:0px"><li =
dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family:Aria=
l,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" r=
ole=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-top:=
0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline">=D8=AE=D8=A8=D8=B1=D8=A9 =
=D8=B7=D8=A8=D9=8A=D8=A9 =D9=81=D9=8A =D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=
=D9=86=D8=B3=D8=A7=D8=A1 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D9=84=D9=8A=D8=AF.<=
/span><span style=3D"font-size:11.5pt;background-color:transparent;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" sty=
le=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;co=
lor:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presenta=
tion" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bott=
om:0pt"><span style=3D"font-size:11.5pt;background-color:transparent;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">=D8=AA=D9=88=D9=81=D9=8A=D8=B1 =D8=AF=D9=
=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=
=A3=D8=B5=D9=84=D9=8A.</span><span style=3D"font-size:11.5pt;background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline"><br><br></span></p><=
/li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-fam=
ily:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=
=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;m=
argin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=D9=85=D8=AA=D8=
=A7=D8=A8=D8=B9=D8=A9 =D8=B4=D8=AE=D8=B5=D9=8A=D8=A9 =D9=84=D9=84=D8=AD=D8=
=A7=D9=84=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D8=A8=D8=AF=D8=A7=D9=8A=D8=A9 =D8=
=AD=D8=AA=D9=89 =D8=A7=D9=84=D9=86=D9=87=D8=A7=D9=8A=D8=A9.</span><span sty=
le=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-styl=
e-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,8=
7);background-color:transparent;font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"=
line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt"><span =
style=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=A9 =D9=88=D8=B3=D8=B1=
=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B9=
=D8=A7=D9=85=D9=84.</span><span style=3D"font-size:11.5pt;background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline"><br><br></span></p></li=
></ul><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin-bot=
tom:4pt"><span style=3D"font-size:17pt;font-family:Arial,sans-serif;color:r=
gb(73,80,87);background-color:transparent;font-weight:700;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">=D8=A8=D8=AF=D8=A7=D8=A6=D9=84 =D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></span><p dir=3D"rtl" =
style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D=
"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgrou=
nd-color:transparent;font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">=D9=81=D9=8A =D8=A8=D8=B9=D8=B6 =D8=A7=D9=84=D8=AD=D8=A7=D9=84=D8=A7=D8=
=AA=D8=8C =D9=82=D8=AF =D9=8A=D9=82=D8=AA=D8=B1=D8=AD =D8=A7=D9=84=D8=B7=D8=
=A8=D9=8A=D8=A8 =D8=A8=D8=AF=D8=A7=D8=A6=D9=84 =D8=A3=D8=AE=D8=B1=D9=89:</s=
pan></p><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" styl=
e=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;col=
or:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentat=
ion" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-botto=
m:0pt"><span style=3D"font-size:11.5pt;background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=A7=D9=84=D8=AA=D9=88=D8=B3=D9=8A=D8=B9=
 =D9=88=D8=A7=D9=84=D9=83=D8=AD=D8=AA =D8=A7=D9=84=D8=AC=D8=B1=D8=A7=D8=AD=
=D9=8A (D&amp;C).</span><span style=3D"font-size:11.5pt;background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"><br><br></span></p></li><=
li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family:A=
rial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weigh=
t:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl=
" role=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-t=
op:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">=D8=A3=D8=AF=D9=88=D9=
=8A=D8=A9 =D8=AA=D8=AD=D8=AA=D9=88=D9=8A =D8=B9=D9=84=D9=89 =D9=85=D9=8A=D9=
=81=D9=8A=D8=A8=D8=B1=D9=8A=D8=B3=D8=AA=D9=88=D9=86 =D9=85=D8=B9 =D9=85=D9=
=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84.</span><span styl=
e=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:nor=
mal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-=
align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style=
-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87=
);background-color:transparent;font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"l=
ine-height:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt"><span s=
tyle=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline">=D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=
=D8=AC=D8=B1=D8=A7=D8=AD=D9=8A =D8=A7=D9=84=D9=85=D8=A8=D8=A7=D8=B4=D8=B1.<=
/span></p></li></ul><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:=
0pt;margin-bottom:4pt"><span style=3D"font-size:17pt;font-family:Arial,sans=
-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D8=A3=D8=B3=D8=A6=D9=84=D8=A9 =D8=B4=
=D8=A7=D8=A6=D8=B9=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height:1=
.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font=
-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">1. =D9=87=D9=84 =D9=
=8A=D9=85=D9=83=D9=86 =D8=B4=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D8=A8=D8=AF=D9=88=D9=86 =D9=88=D8=B5=D9=81=D8=A9 =D9=81=D9=
=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=9F</span><span styl=
e=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);back=
ground-color:transparent;font-weight:700;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"><br></span><span style=3D"font-size:11.5pt;font-family:Arial,sans-ser=
if;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=BA=D8=A7=D9=84=D8=A8=D9=8B=D8=A7 =D9=
=84=D8=A7=D8=8C =D9=88=D9=8A=D8=AC=D8=A8 =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=
=84 =D8=B9=D9=84=D9=8A=D9=87 =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=
=D9=88=D8=AB=D9=88=D9=82 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =
=D8=B7=D8=A8=D9=8A.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;marg=
in-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-family:=
Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weig=
ht:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline">2. =D9=83=D9=85 =D8=AA=D8=B3=
=D8=AA=D8=BA=D8=B1=D9=82 =D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=
=D8=AC=D9=87=D8=A7=D8=B6 =D8=A8=D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8=D8=9F</=
span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb=
(73,80,87);background-color:transparent;font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline"><br></span><span style=3D"font-size:11.5pt;font-family=
:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=D8=B9=D8=A7=D8=AF=D8=A9 =
=D9=85=D9=86 24 =D8=A5=D9=84=D9=89 48 =D8=B3=D8=A7=D8=B9=D8=A9 =D8=AD=D8=AA=
=D9=89 =D9=8A=D9=83=D8=AA=D9=85=D9=84 =D8=A7=D9=84=D9=86=D8=B2=D9=8A=D9=81 =
=D9=88=D8=A5=D8=AE=D8=B1=D8=A7=D8=AC =D8=A7=D9=84=D8=AD=D9=85=D9=84.</span>=
</p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:1=
2pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb=
(73,80,87);background-color:transparent;font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">3. =D9=87=D9=84 =D9=8A=D8=B3=D8=A8=D8=A8 =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B9=D9=82=D9=85=D8=9F</span><=
span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80=
,87);background-color:transparent;font-weight:700;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline"><br></span><span style=3D"font-size:11.5pt;font-family:Arial=
,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:70=
0;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline">=D9=84=D8=A7=D8=8C =D8=A5=D8=B0=
=D8=A7 =D8=AA=D9=85 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D8=A8=
=D8=B4=D9=83=D9=84 =D8=B5=D8=AD=D9=8A=D8=AD=D8=8C =D9=84=D8=A7 =D9=8A=D8=A4=
=D8=AB=D8=B1 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=82=D8=AF=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=A5=D9=86=D8=AC=D8=A7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=
=D8=AA=D9=82=D8=A8=D9=84=D9=8A=D8=A9.</span></p><br><span dir=3D"rtl" style=
=3D"line-height:1.44;margin-top:0pt;margin-bottom:4pt"><span style=3D"font-=
size:17pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=AE=
=D8=A7=D8=AA=D9=85=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height:1=
.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font=
-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=A5=D9=86 =D8=AD=
=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=
=D8=AF=D9=8A=D9=87 =D8=AA=D9=85=D8=AB=D9=84 =D8=AD=D9=84=D9=8B=D8=A7 =D8=B7=
=D8=A8=D9=8A=D9=8B=D8=A7 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=
=D8=A7=D8=B5=D8=A9=D8=8C =D9=84=D9=83=D9=86 =D8=A7=D9=84=D8=A3=D9=85=D8=A7=
=D9=86 =D9=8A=D9=83=D9=85=D9=86 =D9=81=D9=8A =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=
=D8=B1=D8=A9 =D9=85=D8=AE=D8=AA=D8=B5=D9=8A=D9=86 =D9=85=D8=AB=D9=84 =D8=AF=
=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=A7=
=D9=84=D8=AA=D9=8A =D8=AA=D9=88=D9=81=D8=B1 =D8=A7=D9=84=D8=AF=D8=B9=D9=85 =
=D9=88=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=B5=D8=AF=
=D8=B1 =D9=85=D8=B6=D9=85=D9=88=D9=86=D8=8C =D9=85=D8=B9 =D9=85=D8=AA=D8=A7=
=D8=A8=D8=B9=D8=A9 =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=88=D8=B3=D8=B1=D9=8A=
=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9.</span><span style=3D"font-size:11.5pt;font=
-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline"><br></span><span sty=
le=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);bac=
kground-color:transparent;font-weight:700;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D9=84=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1=D8=A7=D8=AA =
=D8=A3=D9=88 =D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC=D8=8C =
=D8=A7=D8=AA=D8=B5=D9=84=D9=8A =D8=A7=D9=84=D8=A2=D9=86 =D8=B9=D9=84=D9=89:=
 </span><span style=3D"font-size:12pt;font-family:Arial,sans-serif;color:rg=
b(51,51,51);font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">0096653=
8159747 </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif=
;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline">.</span></p><br><span dir=3D"rtl" style=3D"l=
ine-height:1.44;margin-top:0pt;margin-bottom:4pt"><span style=3D"font-size:=
17pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:tran=
sparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=AA=D8=
=AD=D8=B0=D9=8A=D8=B1=D8=A7=D8=AA =D9=85=D9=87=D9=85=D8=A9</span></span><p =
dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><s=
pan style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,=
87);background-color:transparent;font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline">=D9=8A=D9=85=D9=86=D8=B9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=
=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =
=D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =
=D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=85 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=
=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =D8=A5=D9=84=D8=A7 =D8=A8=D8=A3=D9=85=D8=
=B1 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8.</span><span style=3D"font-size:11=
.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:tran=
sparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br></s=
pan></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bott=
om:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color=
:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">=D9=84=D8=A7 =D8=AA=D8=B3=D8=AA=D8=AE=D8=AF=D9=85=
=D9=8A =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=A5=D8=B0=D8=A7 =D9=83=D8=A7=
=D9=86 =D9=84=D8=AF=D9=8A=D9=83 =D8=AD=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D9=85=
=D9=86 =D8=A7=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=
=D9=84=D8=A9.</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-=
serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;font=
-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alterna=
tes:normal;vertical-align:baseline"><br><br></span></p><p dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font=
-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-co=
lor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=
=84=D8=A7 =D8=AA=D8=AA=D9=86=D8=A7=D9=88=D9=84=D9=8A =D8=A3=D9=8A =D8=AC=D8=
=B1=D8=B9=D8=A9 =D8=A5=D8=B6=D8=A7=D9=81=D9=8A=D8=A9 =D8=A8=D8=AF=D9=88=D9=
=86 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9.</s=
pan></p><br><br><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;mar=
gin-bottom:0pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-seri=
f;color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=C2=A0=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9<=
/span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rg=
b(29,33,37);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;=
color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:700;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D8=A8=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6</span><span style=3D"f=
ont-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline"> </span><span st=
yle=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);ba=
ckground-color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=
=D8=AF=D9=85=D8=A7=D9=85</span><span style=3D"font-size:11.5pt;font-family:=
Arial,sans-serif;color:rgb(29,33,37);background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;font=
-family:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,2=
18);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=
=D9=8A=D8=B7</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-s=
erif;color:rgb(29,33,37);background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Aria=
l,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=
=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA<=
/span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rg=
b(29,33,37);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;=
color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:700;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86</span><sp=
an style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,3=
7);background-color:transparent;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline"> </=
span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb=
(29,33,37);background-color:rgb(206,212,218);font-weight:700;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">=C3=97 =D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A5=D8=
=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84</span><span style=3D"f=
ont-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline"> </span><span st=
yle=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);ba=
ckground-color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline">=C3=97 =D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=
=D9=84</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;c=
olor:rgb(29,33,37);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans=
-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:70=
0;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline">=C3=97 =D8=A3=D8=B9=D8=B1=D8=A7=
=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84</span><span style=3D"font-size:11.5pt=
;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:transpar=
ent;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant=
-alternates:normal;vertical-align:baseline"> </span><span style=3D"font-siz=
e:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:=
rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 =D9=81=D9=8A =D9=85=
=D9=83=D8=A9</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-s=
erif;color:rgb(29,33,37);background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Aria=
l,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline">=C3=97 =D8=B9=D9=8A=D8=A7=
=D8=AF=D8=A7=D8=AA =D8=A7=D8=AC=D9=87=D8=A7=D8=B6</span><span style=3D"font=
-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-co=
lor:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;=
font-variant-alternates:normal;vertical-align:baseline"> </span><span style=
=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);backg=
round-color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=
=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9</sp=
an><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(2=
9,33,37);background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;col=
or:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:700;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9=
 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=
=D8=AA</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;c=
olor:rgb(29,33,37);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans=
-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:70=
0;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=
=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=
=D8=AD=D8=B1=D9=8A=D9=86</span><span style=3D"font-size:11.5pt;font-family:=
Arial,sans-serif;color:rgb(29,33,37);background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;font=
-family:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,2=
18);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=AF=
=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =
=D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=A7=D8=AA</span><span style=3D"font-=
size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline"> </span><span style=
=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);backg=
round-color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9</span><span style=3D"=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline"> </span><span s=
tyle=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);b=
ackground-color:rgb(206,212,218);font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline">=C3=97 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=D8=
=B4=D9=87=D8=B1=D9=8A=D8=A9</span></p><br><br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/4c7a091b-8b8d-460d-be14-d40f9b46141dn%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/4c7a091b-8b8d-460d-be14-d40f9b46141dn%40googlegroups.com</a>.<br />

------=_Part_77275_1499132899.1756620428640--

------=_Part_77274_787616438.1756620428640--
