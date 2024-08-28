Return-Path: <kasan-dev+bncBC46NCNX4YDRBCNRX23AMGQESBZFC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 77D2C9633FB
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 23:37:14 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-27026b76562sf12842fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 14:37:14 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724881033; x=1725485833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LnKOOu1/FtKzOy1eCae//74eUrDfel4Utu3F0IV5RIE=;
        b=J/yMKhmMJJAP3GadorYc0oJDbk0XsS87QZkzUeNKViO3PeLKw8vWFVtdh35tiHYFn2
         rtfEpSiB09RqpBOiVoVlHKsMduCTT1/3jvbKOpvXyDyQZwzLPxcNJd2JkrDGPAIxYoz0
         R2aucgsXGvjYyy4bs9sfn0w3zeFK0DseNlSjUBrX4kKe1QBpHdTR+WfVo2mkZIuqVlj+
         RmWKU6WV3bAX98nJSOyzvoppogtF0//4gzF4KK74u03//SiGq4mOBKhPg7jRWOIP0yna
         37Rnpl7axnuyzZZg9ejvlYdWBalwBfm1N3lzYFxiBjxlLiajygcREJa9MewPSjKCc8nu
         wBag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724881033; x=1725485833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LnKOOu1/FtKzOy1eCae//74eUrDfel4Utu3F0IV5RIE=;
        b=lXrSMNAOmcFQA1YMpmEiLKqBCaTKO00atqUW91Lb8kbeUjQcd74/IOsgLlFVWxRkgy
         nJcFEAVfZbsDNSC13er+IE+DJC2/Y0ZLIeBI2noQT9K8Dgm61juR/CTfGEfhwbeOB+W/
         Dw3IyVCw8is4I2Ceh3eYU7BqNOaDZcq/VBjQt7FgjR+dftT6uPgMt3gu93lsHHvqpiZ5
         0QSZV71b411xXv7jAiqHXo+2ajOvim9s+6NdtkD3+evN1KzJDQ4wDprv0NmH2/tCiOt1
         GJrt7WfEBGmjMlKpN39yuIQWzPpQJYYURP/rDoUmGXH2+bFrEKg3QKkJM7DfBjQ72VHn
         pvfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724881033; x=1725485833;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LnKOOu1/FtKzOy1eCae//74eUrDfel4Utu3F0IV5RIE=;
        b=S7ot8RRthfSBuyKbQW0/dLJfrW164Q1eRQgQCwcOLWjOg+VRdL5zS6FhqPAUL/ZnnS
         0FUwD57dmiZ2P8cxcfKHNYuMJdfeyDpNv9r0ErGTm7HwIe+FdUKa/U1L5p5I10b6fAvU
         9NQeRwwI0QEFQomZ2oRq8Znr6dawGtqhfQhSucZF+KL4c8qQpjikVDLXeo6tryRTylEQ
         Al6NhsLohwB541iHuKeFrFwV+TV70+xOJpqBqyfH3Gu+W9BNKt5Li0e2JqM6g1BEHFdV
         pNn03g1mzDbAFpwR9TfXdlifdaGLoeum0IK1jg1U1N2cI4dFyWuvdJ2cELrUgiDtF6yb
         2JWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWckHNEUQS6p04VDtEKtWckuUqu4JDUMxtMyPw61l47mk9x9cAYiQ3vfvhhDBPQ4Wrp61hCug==@lfdr.de
X-Gm-Message-State: AOJu0YyiTUYA0j1fHgpUK7m+7+MjzrS28FasyQkSK9je7j91UBDWB1Yq
	kaiYeJ8dsc9ygvxfzJXM6uRjVHQC2eesVsG2Ffc8mgsEO2TQKOQc
X-Google-Smtp-Source: AGHT+IH4NWB1snF45UTulqc7qeu3pMvUU6GCU5O51WGUtkIQfKqZLvNCnRLa1x32iNzR97QopiBi4w==
X-Received: by 2002:a05:6870:4710:b0:270:6ec0:c00 with SMTP id 586e51a60fabf-277900c301emr1153715fac.12.1724881033209;
        Wed, 28 Aug 2024 14:37:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:a583:b0:25e:1ff1:3bb7 with SMTP id
 586e51a60fabf-2778f0a207els525120fac.0.-pod-prod-02-us; Wed, 28 Aug 2024
 14:37:12 -0700 (PDT)
X-Received: by 2002:a05:6808:221e:b0:3d2:271d:37cf with SMTP id 5614622812f47-3df05e5ff4bmr900384b6e.30.1724881031925;
        Wed, 28 Aug 2024 14:37:11 -0700 (PDT)
Date: Wed, 28 Aug 2024 14:37:11 -0700 (PDT)
From: Kerry Crook <crook9994@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <e669e95e-8696-40b5-98ea-385fc8c9ac35n@googlegroups.com>
Subject: =?UTF-8?B?2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2Kc=?=
 =?UTF-8?B?2LfZhNioINiz2YPZiNiq2LEg2YPZhw==?=
 =?UTF-8?B?2LHYqNin2KbZiiDZhdiq2K3YsdmDINi5?=
 =?UTF-8?B?2KjYsSDYp9mE2KXZhtiq2LHZhtiqIA==?=
 =?UTF-8?B?2YHZiiDYp9mE2YPZiNmK2Kog2KfZhNmF?=
 =?UTF-8?B?2YXZhNmD2Kkg2KfZhNi52LHYqNmK2Kk=?=
 =?UTF-8?B?INin2YTYs9i52YjYr9mK2Kkg2YLYt9ix?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_15420_1562076491.1724881031250"
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

------=_Part_15420_1562076491.1724881031250
Content-Type: multipart/alternative; 
	boundary="----=_Part_15421_91630578.1724881031250"

------=_Part_15421_91630578.1724881031250
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2KfYt9mE2Kgg2LPZg9mI2KrYsSDZg9mH2LHY
qNin2KbZiiDZhdiq2K3YsdmDINi52KjYsSDYp9mE2KXZhtiq2LHZhtiqINmB2Yog2KfZhNmD2YjZ
itiqIArYp9mE2YXZhdmE2YPYqSDYp9mE2LnYsdio2YrYqSDYp9mE2LPYudmI2K/ZitipINmC2LfY
sQrYp9iq2LXZhCDYqNin2YTYqNin2KbYuSDYudio2LEg2KfZhNmI2KfYqtizINin2Kg6ICs5NzEg
NTggNjI2IDc5ODEg2KPZiCDYqtmI2KfYtdmEINi52KjYsSDYp9mE2KrZhNmK2KzYsdin2YU6IApA
VGVycnlrYW5lcyBodHRwczovL3QubWUvK0NPaHEyWHVOcWNRd05HWXgg2LPZg9mI2KrYsSDZhdiq
2K3YsdmDINmE2YTYqNmK2Lkg2LnYqNixINin2YTYpdmG2KrYsdmG2KogCti52KjYsSDYp9mE2KXZ
htiq2LHZhtiqINmB2Yog2KfZhNmD2YjZitiqINin2YTZhdmF2YTZg9ipINin2YTYudix2KjZitip
INin2YTYs9i52YjYr9mK2Kkg2YLYt9ixINin2YTYqNit2LHZitmGINin2YTYo9ix2K/ZhiDYp9mE
2KXZhdin2LHYp9iqIArYp9mE2LnYsdio2YrYqSDYp9mE2YXYqtit2K/YqSDYudmF2KfZhiDYp9mE
2YrZhdmGINin2YTYudix2KfZgiDZhdi12LEg2KfZhNmF2LrYsdioINin2YTYrNiy2KfYptixINmE
2YrYqNmK2Kcg2KrZiNmG2LMg2YTYqNmG2KfZhiDZhtmC2K/ZhSAK2YXYrNmF2YjYudipINmI2KfY
s9i52Kkg2YXZhiDYs9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPZh9ix2KjYp9im2Yog2YTZ
hNij2LTYrtin2LUg2LDZiNmKINin2YTYpdi52KfZgtipINij2Ygg2YbZiNi5INmF2YYg2YLZitmI
2K8gCtin2YTYrdix2YPYqS4g2YbZgtiv2YUg2YTYudmF2YTYp9im2YbYpyDZhdis2YXZiNi52Kkg
2YjYp9iz2LnYqSDZhdmGINin2YTZhdmI2K/ZitmE2KfYqiDYs9mD2YjYqtixINin2YTYqtmG2YLZ
hCAtINmF2KrZiNiz2LcgCuKAi+KAi9in2YTYrdis2YUg2YjZhdiq2YrZhiDZhdinINmH2Yog2LPZ
g9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNmD2KjZitix2KnYnwrYs9mD2YjYqtixINin2YTYqtmG
2YLZhCDYp9mE2YPYqNmK2LHYjCDYp9mE2YXYudix2YjZgSDYo9mK2LbZi9inINio2KfYs9mFINiz
2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin2YTYq9mC2YrZhCDYo9mIICLYp9mE2YPYqNmK2LEi2Iwg
2YfZiCAK2YXYsdmD2KjYp9iqINmC2YjZitipINmI2YXYqtmK2YbYqSDZhdi12YXZhdipINmE2KfY
s9iq2YrYudin2Kgg2KfZhNmF2LPYqtiu2K/ZhdmK2YYg2KfZhNiw2YrZhiDZgtivINmK2YPZiNmG
INmE2K/ZitmH2YUg2KfYrdiq2YrYp9is2KfYqiAK2KrZhtmC2YQg2YXYrdiv2K/YqS4g2KrZhSDY
qti12YXZitmFINmH2LDZhyDYp9mE2LPZg9mI2KrYsSDZhdmGINij2KzZhCDYp9mE2KvYqNin2Kog
2YjYp9mE2YXYqtin2YbYqSDZiNin2YTYqtmG2YjYudiMINmF2YXYpyDZitis2LnZhNmH2KcgCtmF
2YbYp9iz2KjYqSDZhNmE2KfYs9iq2K7Yr9in2YUg2KfZhNiv2KfYrtmE2Yog2YjYp9mE2K7Yp9ix
2KzZii4g2KXZhtmH2Kcg2YXYq9in2YTZitipINmE2YTYo9mB2LHYp9ivINin2YTYsNmK2YYg2YrY
udin2YbZiNmGINmF2YYgCtiv2LHYrNin2Kog2YXYqtmB2KfZiNiq2Kkg2YXZhiDYqtit2K/Zitin
2Kog2KfZhNiq2YbZgtmELgrYp9mE2YHZhNin2KrYsQrZhdinINmH2Yog2LPZg9mI2KrYsSDYp9mE
2KrZhtmC2YQg2KfZhNmD2KjZitix2KnYnwog2KrZj9i52LHZgSDYp9mE2K/Ysdin2KzYp9iqINin
2YTYqNiu2KfYsdmK2Kkg2KfZhNmD2KjZitix2Kkg2KfZhNmF2KrYrdix2YPYqSDYo9mK2LbZi9in
INio2KfYs9mFINin2YTYr9ix2KfYrNin2Kog2KfZhNio2K7Yp9ix2YrYqSAK2KfZhNir2YLZitmE
2Kkg2KPZiCAi2KfZhNmD2KjZitix2Kki2Iwg2YjZh9mKINmF2LHZg9io2KfYqiDZgtmI2YrYqSDZ
iNmF2KrZitmG2Kkg2YXYtdmF2YXYqSDZhNin2LPYqtmK2LnYp9ioINin2YTZhdiz2KrYrtiv2YXZ
itmGIArYp9mE2LDZitmGINmC2K8g2YrZg9mI2YYg2YTYr9mK2YfZhSDYp9it2KrZitin2KzYp9iq
INit2LHZg9mK2Kkg2YXYrdiv2K/YqS4g2KrZhSDYqti12YXZitmFINmH2LDZhyDYp9mE2K/Ysdin
2KzYp9iqINin2YTYqNiu2KfYsdmK2KkgCtmE2KrYrdmC2YrZgiDYp9mE2KfYs9iq2YLYsdin2LEg
2YjYp9mE2YXYqtin2YbYqSDZiNin2YTYqtmG2YjYudiMINmF2YXYpyDZitis2LnZhNmH2Kcg2YXZ
htin2LPYqNipINmE2YTYp9iz2KrYrtiv2KfZhSDYp9mE2K/Yp9iu2YTZiiAK2YjYp9mE2K7Yp9ix
2KzZii4g2YjZh9mKINmF2KvYp9mE2YrYqSDZhNmE2KPZgdix2KfYryDYp9mE2LDZitmGINmK2LnY
p9mG2YjZhiDZhdmGINiv2LHYrNin2Kog2YXYqtmB2KfZiNiq2Kkg2YXZhiDYqtit2K/Zitin2Kog
2KfZhNit2LHZg9ipLgrYp9mE2YHZhNin2KrYsQrYpdi42YfYp9ixIDHigJMxOCDZhdmGIDM4INmG
2KrZitis2KkKDQotLSAKWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUg
c3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5z
dWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBp
dCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNv
bS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gb24gdGhlIHdlYiB2aXNpdCBodHRwczovL2dyb3Vw
cy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L2U2NjllOTVlLTg2OTYtNDBiNS05OGVhLTM4
NWZjOGM5YWMzNW4lNDBnb29nbGVncm91cHMuY29tLgo=
------=_Part_15421_91630578.1724881031250
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2YjYp9iq2LPYp9ioICs5NzEgNTggNjI2IDc5ODEg2KfYt9mE2Kgg2LPZg9mI2KrYsSDZg9mH2LHY
qNin2KbZiiDZhdiq2K3YsdmDINi52KjYsSDYp9mE2KXZhtiq2LHZhtiqINmB2Yog2KfZhNmD2YjZ
itiqINin2YTZhdmF2YTZg9ipINin2YTYudix2KjZitipINin2YTYs9i52YjYr9mK2Kkg2YLYt9ix
PGJyIC8+PGRpdj7Yp9iq2LXZhCDYqNin2YTYqNin2KbYuSDYudio2LEg2KfZhNmI2KfYqtizINin
2Kg6ICs5NzEgNTggNjI2IDc5ODEg2KPZiCDYqtmI2KfYtdmEINi52KjYsSDYp9mE2KrZhNmK2KzY
sdin2YU6IEBUZXJyeWthbmVzIGh0dHBzOi8vdC5tZS8rQ09ocTJYdU5xY1F3TkdZeCDYs9mD2YjY
qtixINmF2KrYrdix2YMg2YTZhNio2YrYuSDYudio2LEg2KfZhNil2YbYqtix2YbYqiDYudio2LEg
2KfZhNil2YbYqtix2YbYqiDZgdmKINin2YTZg9mI2YrYqiDYp9mE2YXZhdmE2YPYqSDYp9mE2LnY
sdio2YrYqSDYp9mE2LPYudmI2K/ZitipINmC2LfYsSDYp9mE2KjYrdix2YrZhiDYp9mE2KPYsdiv
2YYg2KfZhNil2YXYp9ix2KfYqiDYp9mE2LnYsdio2YrYqSDYp9mE2YXYqtit2K/YqSDYudmF2KfZ
hiDYp9mE2YrZhdmGINin2YTYudix2KfZgiDZhdi12LEg2KfZhNmF2LrYsdioINin2YTYrNiy2KfY
ptixINmE2YrYqNmK2Kcg2KrZiNmG2LMg2YTYqNmG2KfZhiDZhtmC2K/ZhSDZhdis2YXZiNi52Kkg
2YjYp9iz2LnYqSDZhdmGINiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin2YTZg9mH2LHYqNin2KbZ
iiDZhNmE2KPYtNiu2KfYtSDYsNmI2Yog2KfZhNil2LnYp9mC2Kkg2KPZiCDZhtmI2Lkg2YXZhiDZ
gtmK2YjYryDYp9mE2K3YsdmD2KkuINmG2YLYr9mFINmE2LnZhdmE2KfYptmG2Kcg2YXYrNmF2YjY
udipINmI2KfYs9i52Kkg2YXZhiDYp9mE2YXZiNiv2YrZhNin2Kog2LPZg9mI2KrYsSDYp9mE2KrZ
htmC2YQgLSDZhdiq2YjYs9i3IOKAi+KAi9in2YTYrdis2YUg2YjZhdiq2YrZhiDZhdinINmH2Yog
2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNmD2KjZitix2KnYnzxiciAvPtiz2YPZiNiq2LEg
2KfZhNiq2YbZgtmEINin2YTZg9io2YrYsdiMINin2YTZhdi52LHZiNmBINij2YrYttmL2Kcg2KjY
p9iz2YUg2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNir2YLZitmEINij2YggItin2YTZg9io
2YrYsSLYjCDZh9mIINmF2LHZg9io2KfYqiDZgtmI2YrYqSDZiNmF2KrZitmG2Kkg2YXYtdmF2YXY
qSDZhNin2LPYqtmK2LnYp9ioINin2YTZhdiz2KrYrtiv2YXZitmGINin2YTYsNmK2YYg2YLYryDZ
itmD2YjZhiDZhNiv2YrZh9mFINin2K3YqtmK2KfYrNin2Kog2KrZhtmC2YQg2YXYrdiv2K/YqS4g
2KrZhSDYqti12YXZitmFINmH2LDZhyDYp9mE2LPZg9mI2KrYsSDZhdmGINij2KzZhCDYp9mE2KvY
qNin2Kog2YjYp9mE2YXYqtin2YbYqSDZiNin2YTYqtmG2YjYudiMINmF2YXYpyDZitis2LnZhNmH
2Kcg2YXZhtin2LPYqNipINmE2YTYp9iz2KrYrtiv2KfZhSDYp9mE2K/Yp9iu2YTZiiDZiNin2YTY
rtin2LHYrNmKLiDYpdmG2YfYpyDZhdir2KfZhNmK2Kkg2YTZhNij2YHYsdin2K8g2KfZhNiw2YrZ
hiDZiti52KfZhtmI2YYg2YXZhiDYr9ix2KzYp9iqINmF2KrZgdin2YjYqtipINmF2YYg2KrYrdiv
2YrYp9iqINin2YTYqtmG2YLZhC48YnIgLz7Yp9mE2YHZhNin2KrYsTxiciAvPtmF2Kcg2YfZiiDY
s9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPYqNmK2LHYqdifPGJyIC8+wqDYqtmP2LnYsdmB
INin2YTYr9ix2KfYrNin2Kog2KfZhNio2K7Yp9ix2YrYqSDYp9mE2YPYqNmK2LHYqSDYp9mE2YXY
qtit2LHZg9ipINij2YrYttmL2Kcg2KjYp9iz2YUg2KfZhNiv2LHYp9is2KfYqiDYp9mE2KjYrtin
2LHZitipINin2YTYq9mC2YrZhNipINij2YggItin2YTZg9io2YrYsdipItiMINmI2YfZiiDZhdix
2YPYqNin2Kog2YLZiNmK2Kkg2YjZhdiq2YrZhtipINmF2LXZhdmF2Kkg2YTYp9iz2KrZiti52KfY
qCDYp9mE2YXYs9iq2K7Yr9mF2YrZhiDYp9mE2LDZitmGINmC2K8g2YrZg9mI2YYg2YTYr9mK2YfZ
hSDYp9it2KrZitin2KzYp9iqINit2LHZg9mK2Kkg2YXYrdiv2K/YqS4g2KrZhSDYqti12YXZitmF
INmH2LDZhyDYp9mE2K/Ysdin2KzYp9iqINin2YTYqNiu2KfYsdmK2Kkg2YTYqtit2YLZitmCINin
2YTYp9iz2KrZgtix2KfYsSDZiNin2YTZhdiq2KfZhtipINmI2KfZhNiq2YbZiNi52Iwg2YXZhdin
INmK2KzYudmE2YfYpyDZhdmG2KfYs9io2Kkg2YTZhNin2LPYqtiu2K/Yp9mFINin2YTYr9in2K7Z
hNmKINmI2KfZhNiu2KfYsdis2YouINmI2YfZiiDZhdir2KfZhNmK2Kkg2YTZhNij2YHYsdin2K8g
2KfZhNiw2YrZhiDZiti52KfZhtmI2YYg2YXZhiDYr9ix2KzYp9iqINmF2KrZgdin2YjYqtipINmF
2YYg2KrYrdiv2YrYp9iqINin2YTYrdix2YPYqS48YnIgLz7Yp9mE2YHZhNin2KrYsTxiciAvPtil
2LjZh9in2LEgMeKAkzE4INmF2YYgMzgg2YbYqtmK2KzYqTxiciAvPjwvZGl2Pg0KDQo8cD48L3A+
CgotLSA8YnIgLz4KWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vi
c2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAmcXVvdDtrYXNhbi1kZXYmcXVvdDsgZ3JvdXAu
PGJyIC8+ClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcg
ZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8gPGEgaHJlZj0ibWFpbHRvOmthc2FuLWRl
dit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tIj5rYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29v
Z2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3
ZWIgdmlzaXQgPGEgaHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2Fu
LWRldi9lNjY5ZTk1ZS04Njk2LTQwYjUtOThlYS0zODVmYzhjOWFjMzVuJTQwZ29vZ2xlZ3JvdXBz
LmNvbT91dG1fbWVkaXVtPWVtYWlsJnV0bV9zb3VyY2U9Zm9vdGVyIj5odHRwczovL2dyb3Vwcy5n
b29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L2U2NjllOTVlLTg2OTYtNDBiNS05OGVhLTM4NWZj
OGM5YWMzNW4lNDBnb29nbGVncm91cHMuY29tPC9hPi48YnIgLz4K
------=_Part_15421_91630578.1724881031250--

------=_Part_15420_1562076491.1724881031250--
