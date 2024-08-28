Return-Path: <kasan-dev+bncBC46NCNX4YDRB55PX23AMGQETLBPDJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 22D5E9633F2
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 23:34:49 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5dca00b0cfcsf7412098eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 14:34:49 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724880887; x=1725485687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kE03sl0qecB9LUu+5oKZbQ/YoXbR1FfOla+/yMiIvaM=;
        b=CT3woAIi0XWXsQmQdwyEWKBfAiBN+VbiBBqFvW05Iff3yZFgunBbCGX0S9RkPEJFGi
         sQXzZOWWCJ8MPjP9t/wty3xs2fkpv82py5SWWC+o9Lf61tq5iU/NYWS56+n0BSspuWDn
         6I8Wbs6DMG7tNf/eYSitHvOD/2k2ItcgbI52lnWsCyLUhjx/YIReu7WkyGrevXvxBV3O
         374I9XsOSAAQu+k0kKrD9gkafmVKkfd4pq57OVSyIrzTQ6i4vfclcznqH3sNWC9B7pvo
         9GtDDsBWu4p/P2kFq8SFukWVgE5gr+1DCx8YtFg4rMLafZq6MEGzPo0dvBOT+ox6KC7F
         REng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724880887; x=1725485687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kE03sl0qecB9LUu+5oKZbQ/YoXbR1FfOla+/yMiIvaM=;
        b=TOh0fw98YAmIVWPwCQlaZwOo9N0cdlJ/A6GNJyBuUH61o/gcYHPYyeSWAPYoNKenQb
         LPqcYrG4efNOLvGLH3HV7BxzPezPc50yZVVo/qz2k3Mt9VbimmVs0ssCKD0hnSGF0u8I
         eJbk865YVVImD4tqlvns56vIWkrOAf7tHbrSRkW519WQ41ZqfktK1y/U2Ufm7Xi5d8rD
         /CuJC/gnrMI/0Zb8+7yaHGhXhN8SpZaxrOeR7JUjGmlR/pSE+4vxemxKUpu7mJeh5dsU
         iKgbHQfQ/Z9XEFLtFiw7D0kLoxKXL8BdEqpjWMbqxM1I3S9DvOcAur/1DW0x6e9w7zhX
         Oruw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724880887; x=1725485687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kE03sl0qecB9LUu+5oKZbQ/YoXbR1FfOla+/yMiIvaM=;
        b=ssYQyRuWI7vB77YCkI3MAef74uU+GJe+GXV8kXg319qHAvIY1Mna64PS0jgI5BtkG1
         BXOyimTTbzIJwS8GEEwiuvoLLCGfoYzXQezxvPlVRpLj5ncSXKlv5W9mmwGPdf578vur
         SJPeKn6hFYMK2BAt1ygOGNu3WCtBiwyVj1mwRvLGuq7ULLwjv+Rru75h8kCOFMknGSYv
         AbMkdZlaeQgkYKUk2vCeSt0rQbk+1NUtCWawnUzyrg6aLswGxTGgB3jyJAIsm/+FMBcN
         M6Kra30EXsLpLMXruWCD/I/I3CwHA8gSF7cWOYO0LxLnHnGVj3L94Ud3yDhqZc+4vCan
         w0gQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXra7+56mboLUHVDZR1mKClOV5v8LC4N+AgHNGg8mgJy8Qd6fnNM6TDEj4TMi66PZj6ZEYyKA==@lfdr.de
X-Gm-Message-State: AOJu0YwiQHYReale8e0eZMjEpJ2Tpe3UeQI29uT2RKGE2h8dmGIyv5Wl
	ZnHCJs3UAOY80tDMp3GukkiTvHp/6P+9Pm44VmSqCnsYgJudAyPL
X-Google-Smtp-Source: AGHT+IH97so+MSzLneqO+Qvcpq4v8B/ahfgdQ4r/lhLwGvs5/BiUFd0Q1MXtJLSJF2DOE6j/vJWnnw==
X-Received: by 2002:a05:6870:f623:b0:270:e0f:d75e with SMTP id 586e51a60fabf-277902e4fb4mr889476fac.44.1724880887258;
        Wed, 28 Aug 2024 14:34:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b90:b0:24f:d281:c6c2 with SMTP id
 586e51a60fabf-2778f5543a4ls517125fac.2.-pod-prod-09-us; Wed, 28 Aug 2024
 14:34:46 -0700 (PDT)
X-Received: by 2002:a05:6808:2393:b0:3db:fe8:f736 with SMTP id 5614622812f47-3df05d9b7d8mr808778b6e.6.1724880886234;
        Wed, 28 Aug 2024 14:34:46 -0700 (PDT)
Date: Wed, 28 Aug 2024 14:34:45 -0700 (PDT)
From: Kerry Crook <crook9994@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <1596b955-eeb8-4db3-bd17-fd1ff91ee4a4n@googlegroups.com>
Subject: =?UTF-8?B?2YjYp9iq2LPYp9ioICs5NzEgNTggNg==?=
 =?UTF-8?B?MjYgNzk4MSDYtNix2KfYoSDYs9mD2YjYqg==?=
 =?UTF-8?B?2LEg2YXYqtit2LHZgyDYudio2LEg2KfZhNil2YY=?=
 =?UTF-8?B?2KrYsdmG2Kog2YHZiiDYp9mE2YPZiNmK2Kog2KfZhA==?=
 =?UTF-8?B?2YXZhdmE2YPYqSDYp9mE2LnYsdio2YrYqSDYp9mE?=
 =?UTF-8?B?2LPYudmI2K/ZitipINmC2LfYsSDYp9mE2KjYrdix2Yo=?=
 =?UTF-8?B?2YYg2KfZhNij2LHYr9mGINin2YTYpdmF2KfYsdin?=
 =?UTF-8?B?2Kog2KfZhNi52LHYqNmK2Kkg2KfZhNmF2KrYrdiv2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_16596_874801248.1724880885429"
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

------=_Part_16596_874801248.1724880885429
Content-Type: multipart/alternative; 
	boundary="----=_Part_16597_1509757395.1724880885429"

------=_Part_16597_1509757395.1724880885429
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2KfYqti12YQg2KjYp9mE2KjYp9im2Lkg2LnYqNixINin2YTZiNin2KrYsyDYp9ioOiArOTcxIDU4
IDYyNiA3OTgxINij2Ygg2KrZiNin2LXZhCDYudio2LEg2KfZhNiq2YTZitis2LHYp9mFOiAKQFRl
cnJ5a2FuZXMgaHR0cHM6Ly90Lm1lLytDT2hxMlh1TnFjUXdOR1l4INiz2YPZiNiq2LEg2YXYqtit
2LHZgyDZhNmE2KjZiti5INi52KjYsSDYp9mE2KXZhtiq2LHZhtiqIArYudio2LEg2KfZhNil2YbY
qtix2YbYqiDZgdmKINin2YTZg9mI2YrYqiDYp9mE2YXZhdmE2YPYqSDYp9mE2LnYsdio2YrYqSDY
p9mE2LPYudmI2K/ZitipINmC2LfYsSDYp9mE2KjYrdix2YrZhiDYp9mE2KPYsdiv2YYg2KfZhNil
2YXYp9ix2KfYqiAK2KfZhNi52LHYqNmK2Kkg2KfZhNmF2KrYrdiv2Kkg2LnZhdin2YYg2KfZhNmK
2YXZhiDYp9mE2LnYsdin2YIg2YXYtdixINin2YTZhdi62LHYqCDYp9mE2KzYstin2KbYsSDZhNmK
2KjZitinINiq2YjZhtizINmE2KjZhtin2YYg2YbZgtiv2YUgCtmF2KzZhdmI2LnYqSDZiNin2LPY
udipINmF2YYg2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNmD2YfYsdio2KfYptmKINmE2YTY
o9i02K7Yp9i1INiw2YjZiiDYp9mE2KXYudin2YLYqSDYo9mIINmG2YjYuSDZhdmGINmC2YrZiNiv
IArYp9mE2K3YsdmD2KkuINmG2YLYr9mFINmE2LnZhdmE2KfYptmG2Kcg2YXYrNmF2YjYudipINmI
2KfYs9i52Kkg2YXZhiDYp9mE2YXZiNiv2YrZhNin2Kog2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg
LSDZhdiq2YjYs9i3IArigIvigIvYp9mE2K3YrNmFINmI2YXYqtmK2YYg2YXYpyDZh9mKINiz2YPZ
iNiq2LEg2KfZhNiq2YbZgtmEINin2YTZg9io2YrYsdip2J8K2LPZg9mI2KrYsSDYp9mE2KrZhtmC
2YQg2KfZhNmD2KjZitix2Iwg2KfZhNmF2LnYsdmI2YEg2KPZiti22YvYpyDYqNin2LPZhSDYs9mD
2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2KvZgtmK2YQg2KPZiCAi2KfZhNmD2KjZitixItiMINmH
2YggCtmF2LHZg9io2KfYqiDZgtmI2YrYqSDZiNmF2KrZitmG2Kkg2YXYtdmF2YXYqSDZhNin2LPY
qtmK2LnYp9ioINin2YTZhdiz2KrYrtiv2YXZitmGINin2YTYsNmK2YYg2YLYryDZitmD2YjZhiDZ
hNiv2YrZh9mFINin2K3YqtmK2KfYrNin2KogCtiq2YbZgtmEINmF2K3Yr9iv2KkuINiq2YUg2KrY
tdmF2YrZhSDZh9iw2Ycg2KfZhNiz2YPZiNiq2LEg2YXZhiDYo9is2YQg2KfZhNir2KjYp9iqINmI
2KfZhNmF2KrYp9mG2Kkg2YjYp9mE2KrZhtmI2LnYjCDZhdmF2Kcg2YrYrNi52YTZh9inIArZhdmG
2KfYs9io2Kkg2YTZhNin2LPYqtiu2K/Yp9mFINin2YTYr9in2K7ZhNmKINmI2KfZhNiu2KfYsdis
2YouINil2YbZh9inINmF2KvYp9mE2YrYqSDZhNmE2KPZgdix2KfYryDYp9mE2LDZitmGINmK2LnY
p9mG2YjZhiDZhdmGIArYr9ix2KzYp9iqINmF2KrZgdin2YjYqtipINmF2YYg2KrYrdiv2YrYp9iq
INin2YTYqtmG2YLZhC4K2KfZhNmB2YTYp9iq2LEK2YXYpyDZh9mKINiz2YPZiNiq2LEg2KfZhNiq
2YbZgtmEINin2YTZg9io2YrYsdip2J8KINiq2Y/Yudix2YEg2KfZhNiv2LHYp9is2KfYqiDYp9mE
2KjYrtin2LHZitipINin2YTZg9io2YrYsdipINin2YTZhdiq2K3YsdmD2Kkg2KPZiti22YvYpyDY
qNin2LPZhSDYp9mE2K/Ysdin2KzYp9iqINin2YTYqNiu2KfYsdmK2KkgCtin2YTYq9mC2YrZhNip
INij2YggItin2YTZg9io2YrYsdipItiMINmI2YfZiiDZhdix2YPYqNin2Kog2YLZiNmK2Kkg2YjZ
hdiq2YrZhtipINmF2LXZhdmF2Kkg2YTYp9iz2KrZiti52KfYqCDYp9mE2YXYs9iq2K7Yr9mF2YrZ
hiAK2KfZhNiw2YrZhiDZgtivINmK2YPZiNmGINmE2K/ZitmH2YUg2KfYrdiq2YrYp9is2KfYqiDY
rdix2YPZitipINmF2K3Yr9iv2KkuINiq2YUg2KrYtdmF2YrZhSDZh9iw2Ycg2KfZhNiv2LHYp9is
2KfYqiDYp9mE2KjYrtin2LHZitipIArZhNiq2K3ZgtmK2YIg2KfZhNin2LPYqtmC2LHYp9ixINmI
2KfZhNmF2KrYp9mG2Kkg2YjYp9mE2KrZhtmI2LnYjCDZhdmF2Kcg2YrYrNi52YTZh9inINmF2YbY
p9iz2KjYqSDZhNmE2KfYs9iq2K7Yr9in2YUg2KfZhNiv2KfYrtmE2YogCtmI2KfZhNiu2KfYsdis
2YouINmI2YfZiiDZhdir2KfZhNmK2Kkg2YTZhNij2YHYsdin2K8g2KfZhNiw2YrZhiDZiti52KfZ
htmI2YYg2YXZhiDYr9ix2KzYp9iqINmF2KrZgdin2YjYqtipINmF2YYg2KrYrdiv2YrYp9iqINin
2YTYrdix2YPYqS4K2KfZhNmB2YTYp9iq2LEK2KXYuNmH2KfYsSAx4oCTMTgg2YXZhiAzOCDZhtiq
2YrYrNipCg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1
YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vi
c2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQs
IHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20u
ClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgaHR0cHM6Ly9ncm91cHMu
Z29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi8xNTk2Yjk1NS1lZWI4LTRkYjMtYmQxNy1mZDFm
ZjkxZWU0YTRuJTQwZ29vZ2xlZ3JvdXBzLmNvbS4K
------=_Part_16597_1509757395.1724880885429
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2KfYqti12YQg2KjYp9mE2KjYp9im2Lkg2LnYqNixINin2YTZiNin2KrYsyDYp9ioOiArOTcxIDU4
IDYyNiA3OTgxINij2Ygg2KrZiNin2LXZhCDYudio2LEg2KfZhNiq2YTZitis2LHYp9mFOiBAVGVy
cnlrYW5lcyBodHRwczovL3QubWUvK0NPaHEyWHVOcWNRd05HWXgg2LPZg9mI2KrYsSDZhdiq2K3Y
sdmDINmE2YTYqNmK2Lkg2LnYqNixINin2YTYpdmG2KrYsdmG2Kog2LnYqNixINin2YTYpdmG2KrY
sdmG2Kog2YHZiiDYp9mE2YPZiNmK2Kog2KfZhNmF2YXZhNmD2Kkg2KfZhNi52LHYqNmK2Kkg2KfZ
hNiz2LnZiNiv2YrYqSDZgti32LEg2KfZhNio2K3YsdmK2YYg2KfZhNij2LHYr9mGINin2YTYpdmF
2KfYsdin2Kog2KfZhNi52LHYqNmK2Kkg2KfZhNmF2KrYrdiv2Kkg2LnZhdin2YYg2KfZhNmK2YXZ
hiDYp9mE2LnYsdin2YIg2YXYtdixINin2YTZhdi62LHYqCDYp9mE2KzYstin2KbYsSDZhNmK2KjZ
itinINiq2YjZhtizINmE2KjZhtin2YYg2YbZgtiv2YUg2YXYrNmF2YjYudipINmI2KfYs9i52Kkg
2YXZhiDYs9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPZh9ix2KjYp9im2Yog2YTZhNij2LTY
rtin2LUg2LDZiNmKINin2YTYpdi52KfZgtipINij2Ygg2YbZiNi5INmF2YYg2YLZitmI2K8g2KfZ
hNit2LHZg9ipLiDZhtmC2K/ZhSDZhNi52YXZhNin2KbZhtinINmF2KzZhdmI2LnYqSDZiNin2LPY
udipINmF2YYg2KfZhNmF2YjYr9mK2YTYp9iqINiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEIC0g2YXY
qtmI2LPYtyDigIvigIvYp9mE2K3YrNmFINmI2YXYqtmK2YYg2YXYpyDZh9mKINiz2YPZiNiq2LEg
2KfZhNiq2YbZgtmEINin2YTZg9io2YrYsdip2J88YnIgLz7Ys9mD2YjYqtixINin2YTYqtmG2YLZ
hCDYp9mE2YPYqNmK2LHYjCDYp9mE2YXYudix2YjZgSDYo9mK2LbZi9inINio2KfYs9mFINiz2YPZ
iNiq2LEg2KfZhNiq2YbZgtmEINin2YTYq9mC2YrZhCDYo9mIICLYp9mE2YPYqNmK2LEi2Iwg2YfZ
iCDZhdix2YPYqNin2Kog2YLZiNmK2Kkg2YjZhdiq2YrZhtipINmF2LXZhdmF2Kkg2YTYp9iz2KrZ
iti52KfYqCDYp9mE2YXYs9iq2K7Yr9mF2YrZhiDYp9mE2LDZitmGINmC2K8g2YrZg9mI2YYg2YTY
r9mK2YfZhSDYp9it2KrZitin2KzYp9iqINiq2YbZgtmEINmF2K3Yr9iv2KkuINiq2YUg2KrYtdmF
2YrZhSDZh9iw2Ycg2KfZhNiz2YPZiNiq2LEg2YXZhiDYo9is2YQg2KfZhNir2KjYp9iqINmI2KfZ
hNmF2KrYp9mG2Kkg2YjYp9mE2KrZhtmI2LnYjCDZhdmF2Kcg2YrYrNi52YTZh9inINmF2YbYp9iz
2KjYqSDZhNmE2KfYs9iq2K7Yr9in2YUg2KfZhNiv2KfYrtmE2Yog2YjYp9mE2K7Yp9ix2KzZii4g
2KXZhtmH2Kcg2YXYq9in2YTZitipINmE2YTYo9mB2LHYp9ivINin2YTYsNmK2YYg2YrYudin2YbZ
iNmGINmF2YYg2K/Ysdis2KfYqiDZhdiq2YHYp9mI2KrYqSDZhdmGINiq2K3Yr9mK2KfYqiDYp9mE
2KrZhtmC2YQuPGJyIC8+2KfZhNmB2YTYp9iq2LE8YnIgLz7ZhdinINmH2Yog2LPZg9mI2KrYsSDY
p9mE2KrZhtmC2YQg2KfZhNmD2KjZitix2KnYnzxiciAvPsKg2KrZj9i52LHZgSDYp9mE2K/Ysdin
2KzYp9iqINin2YTYqNiu2KfYsdmK2Kkg2KfZhNmD2KjZitix2Kkg2KfZhNmF2KrYrdix2YPYqSDY
o9mK2LbZi9inINio2KfYs9mFINin2YTYr9ix2KfYrNin2Kog2KfZhNio2K7Yp9ix2YrYqSDYp9mE
2KvZgtmK2YTYqSDYo9mIICLYp9mE2YPYqNmK2LHYqSLYjCDZiNmH2Yog2YXYsdmD2KjYp9iqINmC
2YjZitipINmI2YXYqtmK2YbYqSDZhdi12YXZhdipINmE2KfYs9iq2YrYudin2Kgg2KfZhNmF2LPY
qtiu2K/ZhdmK2YYg2KfZhNiw2YrZhiDZgtivINmK2YPZiNmGINmE2K/ZitmH2YUg2KfYrdiq2YrY
p9is2KfYqiDYrdix2YPZitipINmF2K3Yr9iv2KkuINiq2YUg2KrYtdmF2YrZhSDZh9iw2Ycg2KfZ
hNiv2LHYp9is2KfYqiDYp9mE2KjYrtin2LHZitipINmE2KrYrdmC2YrZgiDYp9mE2KfYs9iq2YLY
sdin2LEg2YjYp9mE2YXYqtin2YbYqSDZiNin2YTYqtmG2YjYudiMINmF2YXYpyDZitis2LnZhNmH
2Kcg2YXZhtin2LPYqNipINmE2YTYp9iz2KrYrtiv2KfZhSDYp9mE2K/Yp9iu2YTZiiDZiNin2YTY
rtin2LHYrNmKLiDZiNmH2Yog2YXYq9in2YTZitipINmE2YTYo9mB2LHYp9ivINin2YTYsNmK2YYg
2YrYudin2YbZiNmGINmF2YYg2K/Ysdis2KfYqiDZhdiq2YHYp9mI2KrYqSDZhdmGINiq2K3Yr9mK
2KfYqiDYp9mE2K3YsdmD2KkuPGJyIC8+2KfZhNmB2YTYp9iq2LE8YnIgLz7Ypdi42YfYp9ixIDHi
gJMxOCDZhdmGIDM4INmG2KrZitis2Kk8YnIgLz4NCg0KPHA+PC9wPgoKLS0gPGJyIC8+CllvdSBy
ZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdv
b2dsZSBHcm91cHMgJnF1b3Q7a2FzYW4tZGV2JnF1b3Q7IGdyb3VwLjxiciAvPgpUbyB1bnN1YnNj
cmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBz
ZW5kIGFuIGVtYWlsIHRvIDxhIGhyZWY9Im1haWx0bzprYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29v
Z2xlZ3JvdXBzLmNvbSI+a2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb208L2E+
LjxiciAvPgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiBvbiB0aGUgd2ViIHZpc2l0IDxhIGhyZWY9
Imh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvMTU5NmI5NTUtZWVi
OC00ZGIzLWJkMTctZmQxZmY5MWVlNGE0biU0MGdvb2dsZWdyb3Vwcy5jb20/dXRtX21lZGl1bT1l
bWFpbCZ1dG1fc291cmNlPWZvb3RlciI+aHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lk
L2thc2FuLWRldi8xNTk2Yjk1NS1lZWI4LTRkYjMtYmQxNy1mZDFmZjkxZWU0YTRuJTQwZ29vZ2xl
Z3JvdXBzLmNvbTwvYT4uPGJyIC8+Cg==
------=_Part_16597_1509757395.1724880885429--

------=_Part_16596_874801248.1724880885429--
