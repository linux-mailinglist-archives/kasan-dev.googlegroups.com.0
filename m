Return-Path: <kasan-dev+bncBDYPL74CXAOBB6UHWHCQMGQEPIAK3ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 595BFB33DB0
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:07:40 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30cce9bb2bbsf7305578fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 04:07:40 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756120059; x=1756724859; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=/lnJUv1t8GmugAzDjHPdNyLEYQfl0wXJoZXMAToNGSw=;
        b=lvEUR7c9XrApkG3m2fZs5Y+OwuUjokTInUunhvyfvedfvVrolThPbqBGHY60GT5ftB
         SBm0NKRzbbyC2QFMBr6kVfDhiOx5lGSi4WRO5K1+EWpwwa/yiXmS0VUYbdB2I3FSVccB
         Pvtz8htq9qIDMGaPKlcP5qgcsBTY2ml9RMvzi3zY7nubT8n0g0ckjrhgBPaMrM9Bd7uq
         ykVL/kE5NXkXJp8Yev4ceBG1G2jeLcB1ZtE/BZNTVchACNdMJHCTkTgjC5/MK4L1yUIX
         JCF906kHXzqz0/JtGPbhYfQL5APVFO1yjAuv4A8erehQ5XXtzVkBEtr+ChV37h7XbaSh
         CQTw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756120059; x=1756724859; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/lnJUv1t8GmugAzDjHPdNyLEYQfl0wXJoZXMAToNGSw=;
        b=gJhorAGaMskaeur9U7+r6ir0l6VrPRubK0GCzvRiCMR/4VD7z4sIDqygFOIOxpeqoC
         9Rf+PNwXfZThGCuyM5dSW3iIccjupMpqrvnfLRs13QCAdK8QgPWcIg+vnRAkw7e55uyL
         oTJePEkBaei1n28C+4RtcNBgG/edLzg1GE0aURntJTngXO2XmFDjJ7+e2qQ77e74W2mr
         Aw5RuQJ9Tt5DfDnwlal5B/WqS20jHbXNzRJ1xmeE/SMRhZtRO/mWwHGEUgk8ej3ikYvM
         v7nuS/5g8rz2DY4KneMnzUJSKyiKlGSblTE07slfIKSsJ98p4PEITXOHzt0nuC0QTFr8
         P2vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756120059; x=1756724859;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=/lnJUv1t8GmugAzDjHPdNyLEYQfl0wXJoZXMAToNGSw=;
        b=tGtTZ1huOZZTgNhZ2oeeFeeEnJodRUKKYPdabVsb2XTEsYVhAKTo+Zu1j4wO92PFnd
         DrMcdTs0aLN6nIPrLIyHplV67gEzs49qf5y3Nfn2TcHiM5vy5Ov4GUle/euZXjoeW05F
         bye3/6/AWTSe0V6UruoB+pRBgFnzHnxIroK1yPqGMgYz8bopoaQvptBi1aELT8G1SoW+
         b0DTPCkLrXggDXwm8xnhB78lwr1SlPokZsrU4Qcb7EU6ccqQK/Uo0Se3BlWPf83xz8lz
         DLYdYnHXAQNOx/Ye7LX3uG4G8k5/GAqDi7VznGIY0ibLj+M9W/CCoUOCkTb8E2OlYdwy
         MeOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWJ0oix/+TGO/PUM6yggFo/S09U8q5lhIdvR+5VIjakUZOWEY+0z6GWpxQ25nVmCIi1s0+OPg==@lfdr.de
X-Gm-Message-State: AOJu0YwBK3VyzvjeMwtheF6pjw2w+Ib4kOpfi9DPJzpYWnETPqLLgkIW
	nzDv1LN8qoWRhTX7H9HkDqoIdP8cVD48OC8tKBkX8bkG0fM3UOoQwF8N
X-Google-Smtp-Source: AGHT+IFyUNWAmzRepQEJ5UVtoHl7CDAd987lDhssNe6P4pV/nxpJsKacfAtT5AjVHifW1wsBFWom6A==
X-Received: by 2002:a05:6871:6507:b0:314:9683:3759 with SMTP id 586e51a60fabf-314dcee32cfmr5980062fac.50.1756120059073;
        Mon, 25 Aug 2025 04:07:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd79H6Oh+idHWfeaBmprlcBTHSN1EPu106tkHhs4VCO1Q==
Received: by 2002:a05:6870:8e10:b0:30b:bc0f:66c0 with SMTP id
 586e51a60fabf-314c1d90424ls177865fac.0.-pod-delta-01-us; Mon, 25 Aug 2025
 04:07:36 -0700 (PDT)
X-Received: by 2002:a05:6808:4f4e:b0:435:6e0b:5091 with SMTP id 5614622812f47-4378512e363mr2876572b6e.1.1756120056739;
        Mon, 25 Aug 2025 04:07:36 -0700 (PDT)
Date: Mon, 25 Aug 2025 04:07:35 -0700 (PDT)
From: =?UTF-8?B?2LPYp9mK2KrZiNiq2YMg2KfZhNiz2LnZiNiv2YrZhw==?=
 =?UTF-8?B?INiz2KfZitiq2YjYqtmDINio2K7YtdmFIDIwJQ==?=
 <mnalmagtereb@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <92070647-1fb6-422a-8d29-da9df9ac9437n@googlegroups.com>
In-Reply-To: <82ff5fe0-f77c-409c-8c44-780235f03404n@googlegroups.com>
References: <82ff5fe0-f77c-409c-8c44-780235f03404n@googlegroups.com>
Subject: =?UTF-8?Q?Re:_=D8=AD=D8=A8=D9=88=D8=A8_=D8=B3=D8=A7?=
 =?UTF-8?Q?=D9=8A=D8=AA=D9=88=D8=AA=D9=83_|_0096?= =?UTF-8?Q?6538159747_|?=
 =?UTF-8?Q?_=D9=81=D9=8A_=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_429088_753453065.1756120055975"
X-Original-Sender: mnalmagtereb@gmail.com
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

------=_Part_429088_753453065.1756120055975
Content-Type: multipart/alternative; 
	boundary="----=_Part_429089_2094134490.1756120055975"

------=_Part_429089_2094134490.1756120055975
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

Ctiv2YPYqtmI2LHYqSDYp9is2YfYp9i2INmB2Yog2KfZhNiz2LnZiNiv2YrZhyB8IDAwOTY2NTM4
MTU5NzQ3IHzYudmK2KfYr9ipINiz2KfZitiq2YjYqtmDIAoKINiv2YPYqtmI2LHYqSDZhtmK2LHZ
hdmK2YYg2YTZhNin2LPYqti02KfYsdin2Kog2KfZhNi32KjZitipCtit2KjZiNioINin2YTYp9is
2YfYp9i2IOKAkyDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KkgIHwg2K/Zg9iq
2YjYsdipINmG2YrYsdmF2YrZhiAwMDk2NjUzODE1OTc0NyDigJMgCtin2LPYqti02KfYsdin2Kog
2YjYudmE2KfYrCDYotmF2YYK2KrYudix2YHZiiDYudmE2Ykg2YPZhCDZhdinINmK2YfZhdmDINi5
2YYg2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2Iwg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPY
udmI2K/ZitmHIAo8aHR0cHM6Ly9oYXlhdGFubmFzLmNvbS8/c3JzbHRpZD1BZm1CT29vclhUdjZ3
Y3RiWTdvQ2JkX3pSQk14TkRQbVQwRjVEUFJ3ek1pZkNNZ0RETk5wMWNiVj4gCtin2YTYsdmK2KfY
ttiMINis2K/YqdiMINmF2YPYqdiMINis2KfYstin2YbYjCDZiNiu2YXZitizINmF2LTZiti32Iwg
2YXYuSDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmGINmE2YTYp9iz2KrYtNin2LHYp9iqINin2YTY
t9io2YrYqSAK2YjYt9mE2Kgg2KfZhNi52YTYp9isINio2LPYsdmK2Kkg2KrYp9mF2KkuCtiq2K3Y
sNmK2LHYp9iqINmF2YfZhdipCgrZitmF2YbYuSDYp9iz2KrYrtiv2KfZhSDYrdio2YjYqCDYs9in
2YrYqtmI2KrZgyDZgdmKINit2KfZhNin2Kog2KfZhNit2YXZhCDYp9mE2YXYqtmC2K/ZhSDYqNi5
2K8g2KfZhNij2LPYqNmI2LkgMTIg2KXZhNinINio2KPZhdixIArYp9mE2LfYqNmK2Kgg2YjYp9mE
2KfYs9iq2YXYp9i5INin2YTZiiDYqtmI2KzZitmH2KfYqtmHIC4KCgog2K3YqNmI2Kgg2LPYp9mK
2KrZiNiq2YMgfCAwMDk2NjUzODE1OTc0NyAgfCDZgdmKINin2YTYs9i52YjYr9mK2Kkg4oCTINiv
2YPYqtmI2LHYqSDZhtmK2LHZhdmK2YYg2YTZhNin2LPYqti02KfYsdin2KogCtin2YTYt9io2YrY
qSDYp9mE2KXYrNmH2KfYtiAgCgrZgdmKINin2YTYs9mG2YjYp9iqINin2YTYo9iu2YrYsdip2Iwg
2KPYtdio2K0g2YXZiNi22YjYuSDYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiDYs9in2YrYqtmI2KrZ
gyAKPGh0dHBzOi8vc2F1ZGllcnNhYS5jb20vPiDZgdmKINin2YTYs9i52YjYr9mK2Kkg2YXZhiDY
o9mD2KvYsSDYp9mE2YXZiNin2LbZiti5INin2YTYqtmKINiq2KjYrdirINi52YbZh9inIArYp9mE
2LPZitiv2KfYqtiMINiu2KfYtdipINmB2Yog2YXYr9mGINmF2KvZhCDYp9mE2LHZitin2LbYjCDY
rNiv2KnYjCDZhdmD2KnYjCDYrNin2LLYp9mG2Iwg2YjYrtmF2YrYsyDZhdi02YrYt9iMINmI2YPY
sNmE2YMg2YHZiiAK2YXZhtin2LfZgiDYp9mE2K7ZhNmK2Kwg2YXYq9mEINin2YTYqNit2LHZitmG
INmI2KfZhNmD2YjZitiqINmI2KfZhNi02KfYsdmC2KkuINmG2LjYsdmL2Kcg2YTYrdiz2KfYs9mK
2Kkg2KfZhNmF2YjYttmI2Lkg2YjYo9mH2YXZitiq2YfYjCAK2KrZgtiv2YUg2K/Zg9iq2YjYsdip
INmG2YrYsdmF2YrZhiDYp9mE2K/YudmFINin2YTYt9io2Yog2YjYp9mE2KfYs9iq2LTYp9ix2KfY
qiDYp9mE2YXYqtiu2LXYtdipINmE2YTZhtiz2KfYoSDYp9mE2YTZiNin2KrZiiDZitit2KrYrNmG
IArYpdmE2Ykg2KfZhNiq2YjYrNmK2Ycg2KfZhNi12K3ZititINmI2LfZhNioINin2YTYudmE2KfY
rCDZhdmGINmF2LXYr9ixINmF2YjYq9mI2YLYjCDYudio2LEg2KfZhNin2KrYtdin2YQg2LnZhNmJ
INin2YTYsdmC2YU6IDAwOTY2NTM4MTU5NzQ3IAouCgotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0KCtmF2Kcg2YfZiiDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KfYrNmH2KfYttif
CgrYrdio2YjYqCDYs9in2YrYqtmI2KrZgyAoQ3l0b3RlYykg2KrYrdiq2YjZiiDYudmE2Ykg2KfZ
hNmF2KfYr9ipINin2YTZgdi52KfZhNipINin2YTZhdmK2LLZiNio2LHZiNiz2KrZiNmEIAooTWlz
b3Byb3N0b2wp2Iwg2YjZh9mKINiv2YjYp9ihINmF2LnYqtmF2K8g2LfYqNmK2YvYpyDZhNi52YTY
p9isINmC2LHYrdipINin2YTZhdi52K/YqSDZgdmKINin2YTYo9i12YTYjCDZhNmD2YYg2KfZhNij
2KjYrdin2KsgCtin2YTYt9io2YrYqSDYo9ir2KjYqtiqINmB2KfYudmE2YrYqtmHINmB2Yog2KXZ
htmH2KfYoSDYp9mE2K3ZhdmEINin2YTZhdio2YPYsSAKPGh0dHBzOi8vaGF5YXRhbm5hcy5jb20v
P3Nyc2x0aWQ9QWZtQk9vbzhaZE52RVpVcGczRGRmV3RaTlVSS0Fweldnc1hIcXdtZ3NKZEhKNjhR
VV94Z091Z1M+IArYqtit2Kog2KXYtNix2KfZgSDYt9io2YouCtmB2Yog2KfZhNiz2LnZiNiv2YrY
qdiMINmK2KrZhSDYp9iz2KrYrtiv2KfZhSDYs9in2YrYqtmI2KrZgyDZgdmKINit2KfZhNin2Kog
2K7Yp9i12Kkg2Ygg2KjYrNix2LnYp9iqINmF2K3Yr9iv2Kkg2YrZgtix2LHZh9inIArYp9mE2LfY
qNmK2KjYjCDZhdi5INi22LHZiNix2Kkg2KfZhNiq2KPZg9ivINmF2YYg2KzZiNiv2Kkg2KfZhNmF
2YbYqtisINmI2YXYtdiv2LHZhy4KCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoK2YXY
qtmJINiq2LPYqtiu2K/ZhSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KXYrNmH2KfYttif
CiAgIAogICAtIAogICAKICAg2KfZhNil2KzZh9in2LYg2KfZhNmF2KjZg9ixOiDYrdiq2Ykg2KfZ
hNij2LPYqNmI2LkgMTIg2YXZhiDYp9mE2K3ZhdmELgogICAKICAgLSAKICAgCiAgINi52YbYryDZ
iNis2YjYryDYqti02YjZh9in2Kog2KzZhtmK2YbZitipINiu2LfZitix2KkuCiAgIAogICAtIAog
ICAKICAg2YHZiiDYrdin2YTYp9iqINmI2YHYp9ipINin2YTYrNmG2YrZhiDYr9in2K7ZhCDYp9mE
2LHYrdmFLgogICAKICAgLSAKICAgCiAgINil2LDYpyDZg9in2YYg2KfZhNit2YXZhCDZiti02YPZ
hCDYrti32LHZi9inINi52YTZiSDYrdmK2KfYqSDYp9mE2KPZhS4KICAgCiAgIArimqDvuI8g2YXZ
hNin2K3YuNipOiDZhNinINmK2Y/Zhti12K0g2KjYp9iz2KrYrtiv2KfZhSDZh9iw2Ycg2KfZhNit
2KjZiNioINiv2YjZhiDZhdiq2KfYqNi52Kkg2LfYqNmK2KnYjCDZhNiq2KzZhtioINin2YTZhdi2
2KfYudmB2KfYqi4KCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoK2LfYsdmK2YLYqSDY
p9iz2KrYrtiv2KfZhSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KfYrNmH2KfYtgoK2KfZ
hNin2LPYqtiu2K/Yp9mFINmK2K7YqtmE2YEg2K3Ys9ioINi52YXYsSDYp9mE2K3ZhdmEINmI2K3Y
p9mE2Kkg2KfZhNmF2LHYo9ip2Iwg2YjZhNmD2YYg2YHZiiDYp9mE2LnZhdmI2YU6CgogICAxLiAK
ICAgCiAgINin2YTYrNix2LnYqTog2YrYrdiv2K/Zh9inINin2YTYt9io2YrYqCDZgdmC2LfYjCDZ
iNi52KfYr9ipINiq2YPZiNmGINio2YrZhiA4MDAg2YXZitmD2LHZiNi62LHYp9mFINmF2YLYs9mF
2Kkg2LnZhNmJINis2LHYudin2KouCiAgIAogICAyLiAKICAgCiAgINi32LHZitmC2Kkg2KfZhNiq
2YbYp9mI2YQ6INiq2YjYtti5INin2YTYrdio2YjYqCDYqtit2Kog2KfZhNmE2LPYp9mGINij2Ygg
2YHZiiDYp9mE2YXZh9io2YQuCiAgIAogICAzLiAKICAgCiAgINin2YTZhdiq2KfYqNi52Kk6INmK
2KzYqCDZhdix2KfYrNi52Kkg2KfZhNi32KjZitioINio2LnYryAyNC00OCDYs9in2LnYqSDZhNmE
2KrYo9mD2K8g2YXZhiDYp9mD2KrZhdin2YQg2KfZhNi52YXZhNmK2KkuCiAgIAogICAKLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCgrYp9mE2KPYudix2KfYtiDYp9mE2YXYqtmI2YLYudip
INio2LnYryDYqtmG2KfZiNmEINin2YTYrdio2YjYqAoKICAgLSAKICAgCiAgINmG2LLZitmBINmF
2YfYqNmE2Yog2YrYtNio2Ycg2KfZhNiv2YjYsdipINin2YTYtNmH2LHZitipINij2Ygg2KPZg9ir
2LEg2LrYstin2LHYqS4KICAgCiAgIC0gCiAgIAogICDYqti02YbYrNin2Kog2YjYotmE2KfZhSDZ
gdmKINij2LPZgdmEINin2YTYqNi32YYuCiAgIAogICAtIAogICAKICAg2LrYq9mK2KfZhiDYo9mI
INmC2YrYoS4KICAgCiAgIC0gCiAgIAogICDYpdiz2YfYp9mEINiu2YHZitmBLgogICAKICAgCtil
2LDYpyDYp9iz2KrZhdixINin2YTZhtiy2YrZgSDYp9mE2LTYr9mK2K8g2KPZiCDYuNmH2LHYqiDY
o9i52LHYp9i2INmF2KvZhCDYp9mE2K/ZiNiu2Kkg2KfZhNit2KfYr9ip2Iwg2YrYrNioINin2YTY
qtmI2KzZhyDZgdmI2LHZi9inIArZhNmE2LfZiNin2LHYpi4KCi0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLQoK2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/ZitmH
INmI2KfZhNio2K3YsdmK2YYg2YjYp9mE2YPZiNmK2KoKCtiq2YbYqti02LEg2KfZhNit2KfYrNip
INil2YTZiSDYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiDYs9in2YrYqtmI2KrZgyA8aHR0cHM6Ly9r
c2FjeXRvdGVjLmNvbS8+INmB2Yog2KfZhNi52K/ZitivIArZhdmGINin2YTZhdiv2YY6CgogICAt
IAogICAKICAg2KfZhNix2YrYp9i2OiDYqtmI2KfYtdmEINmF2Lkg2K/Zg9iq2YjYsdipINmG2YrY
sdmF2YrZhiDZhNmE2K3YtdmI2YQg2LnZhNmJINin2YTYudmE2KfYrCDYp9mE2KPYtdmE2YouCiAg
IAogICAtIAogICAKICAg2KzYr9ipOiDYrtiv2YXYp9iqINi32KjZitipINio2LPYsdmK2Kkg2KrY
p9mF2Kkg2YXYuSDZhdiq2KfYqNi52KkuCiAgIAogICAtIAogICAKICAg2YXZg9ipOiDYr9i52YUg
2LfYqNmKINii2YXZhiDZhNmE2YbYs9in2KEg2KfZhNmE2YjYp9iq2Yog2YrYrdiq2KzZhiDZhNil
2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE2YXYqNmD2LEuCiAgIAogICAtIAogICAKICAg2KzYp9iy
2KfZhjog2KfYs9iq2LTYp9ix2KfYqiDYudio2LEg2KfZhNmH2KfYqtmBINij2Ygg2KfZhNmI2KfY
qtiz2KfYqC4KICAgCiAgIC0gCiAgIAogICDYrtmF2YrYsyDZhdi02YrYtzog2KrZiNmB2YrYsSDY
p9mE2LnZhNin2Kwg2KfZhNij2LXZhNmKINiq2K3YqiDYpdi02LHYp9mBINmF2KrYrti12LUuCiAg
IAogICAtIAogICAKICAg2KfZhNi02KfYsdmC2Kkg2YjYp9mE2KjYrdix2YrZhiDZiNin2YTZg9mI
2YrYqjog2KXZhdmD2KfZhtmK2Kkg2KfZhNiq2YjYp9i12YQg2YTYt9mE2Kgg2KfZhNi52YTYp9is
INmF2YYg2YXYtdiv2LEg2YXZiNir2YjZgi4KICAgCiAgIArwn5OeINix2YLZhSDYr9mD2KrZiNix
2Kkg2YbYsdmF2YrZhiDZhNmE2KfYs9iq2YHYs9in2LE6IDAwOTY2NTM4MTU5NzQ3IAoK2YTZhdin
2LDYpyDYqtiu2KrYp9ix2YrZhiDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmG2J8KCiAgIC0gCiAg
IAogICDYrtio2LHYqSDYt9io2YrYqSDZgdmKINmF2KzYp9mEINin2YTZhtiz2KfYoSDZiNin2YTY
qtmI2YTZitivLgogICAKICAgLSAKICAgCiAgINiq2YjZgdmK2LEg2K/ZiNin2KEg2LPYp9mK2KrZ
iNiq2YMg2KfZhNij2LXZhNmKLgogICAKICAgLSAKICAgCiAgINmF2KrYp9io2LnYqSDYtNiu2LXZ
itipINmE2YTYrdin2YTYqSDZhdmGINin2YTYqNiv2KfZitipINit2KrZiSDYp9mE2YbZh9in2YrY
qS4KICAgCiAgIC0gCiAgIAogICDYrti12YjYtdmK2Kkg2YjYs9ix2YrYqSDYqtin2YXYqSDZgdmK
INin2YTYqti52KfZhdmELgogICAKICAgCtio2K/Yp9im2YQg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq
2YMKCtmB2Yog2KjYudi2INin2YTYrdin2YTYp9iq2Iwg2YLYryDZitmC2KrYsditINin2YTYt9io
2YrYqCDYqNiv2KfYptmEINij2K7YsdmJOgoKICAgLSAKICAgCiAgINin2YTYqtmI2LPZiti5INmI
2KfZhNmD2K3YqiDYp9mE2KzYsdin2K3ZiiAoRCZDKS4KICAgCiAgIC0gCiAgIAogICDYo9iv2YjZ
itipINiq2K3YqtmI2Yog2LnZhNmJINmF2YrZgdmK2KjYsdmK2LPYqtmI2YYg2YXYuSDZhdmK2LLZ
iNio2LHZiNiz2KrZiNmELgogICAKICAgLSAKICAgCiAgINin2YTYpdis2YfYp9i2INin2YTYrNix
2KfYrdmKINin2YTZhdio2KfYtNixLgogICAK2KPYs9im2YTYqSDYtNin2KbYudipCgoxLiDZh9mE
INmK2YXZg9mGINi02LHYp9ihINiz2KfZitiq2YjYqtmDINio2K/ZiNmGINmI2LXZgdipINmB2Yog
2KfZhNiz2LnZiNiv2YrYqdifCti62KfZhNio2YvYpyDZhNin2Iwg2YjZitis2Kgg2KfZhNit2LXZ
iNmEINi52YTZitmHINmF2YYg2YXYtdiv2LEg2YXZiNir2YjZgiDYqtit2Kog2KXYtNix2KfZgSDY
t9io2YouCgoyLiDZg9mFINiq2LPYqti62LHZgiDYudmF2YTZitipINin2YTYp9is2YfYp9i2INio
2KfZhNit2KjZiNio2J8K2LnYp9iv2Kkg2YXZhiAyNCDYpdmE2YkgNDgg2LPYp9i52Kkg2K3YqtmJ
INmK2YPYqtmF2YQg2KfZhNmG2LLZitmBINmI2KXYrtix2KfYrCDYp9mE2K3ZhdmELgoKMy4g2YfZ
hCDZitiz2KjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2LnZgtmF2J8K2YTYp9iMINil2LDYpyDYqtmF
INin2LPYqtiu2K/Yp9mF2Ycg2KjYtNmD2YQg2LXYrdmK2K3YjCDZhNinINmK2KTYq9ixINi52YTZ
iSDYp9mE2YLYr9ix2Kkg2KfZhNil2YbYrNin2KjZitipINin2YTZhdiz2KrZgtio2YTZitipLgoK
2K7Yp9iq2YXYqQoK2KXZhiDYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiDYs9in2YrYqtmI2KrZgyDZ
gdmKINin2YTYs9i52YjYr9mK2Ycg2KrZhdir2YQg2K3ZhNmL2Kcg2LfYqNmK2YvYpyDZgdmKINit
2KfZhNin2Kog2K7Yp9i12KnYjCDZhNmD2YYgCtin2YTYo9mF2KfZhiDZitmD2YXZhiDZgdmKINin
2LPYqti02KfYsdipINmF2K7Yqti12YrZhiDZhdir2YQg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZ
hiDYp9mE2KrZiiDYqtmI2YHYsSDYp9mE2K/YudmFINmI2KfZhNi52YTYp9isINmF2YYgCtmF2LXY
r9ixINmF2LbZhdmI2YbYjCDZhdi5INmF2KrYp9io2LnYqSDYr9mC2YrZgtipINmI2LPYsdmK2Kkg
2KrYp9mF2KkuCtmE2YTYp9iz2KrZgdiz2KfYsdin2Kog2KPZiCDYt9mE2Kgg2KfZhNi52YTYp9is
2Iwg2KfYqti12YTZiiDYp9mE2KLZhiDYudmE2Yk6IDAwOTY2NTM4MTU5NzQ3IC4KCtiq2K3YsNmK
2LHYp9iqINmF2YfZhdipCgrZitmF2YbYuSDYp9iz2KrYrtiv2KfZhSDYrdio2YjYqCDYs9in2YrY
qtmI2KrZgyDZgdmKINit2KfZhNin2Kog2KfZhNit2YXZhCDYp9mE2YXYqtmC2K/ZhSDYqNi52K8g
2KfZhNij2LPYqNmI2LkgMTIg2KXZhNinINio2KPZhdixIArYp9mE2LfYqNmK2KguCgrZhNinINiq
2LPYqtiu2K/ZhdmKINin2YTYrdio2YjYqCDYpdiw2Kcg2YPYp9mGINmE2K/ZitmDINit2LPYp9iz
2YrYqSDZhdmGINin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqS4KCtmE2Kcg2KrYqtmG2KfZiNmE
2Yog2KPZiiDYrNix2LnYqSDYpdi22KfZgdmK2Kkg2KjYr9mI2YYg2KfYs9iq2LTYp9ix2Kkg2LfY
qNmK2KkuCgoKINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqSDDlyDYs9in2YrY
qtmI2KrZgyDYqNin2YTYsdmK2KfYtiDDlyDYs9in2YrYqtmI2KrZgyDYp9mE2K/Zhdin2YUgw5cg
2LPYp9mK2KrZiNiq2YMg2K7ZhdmK2LMg2YXYtNmK2Lcgw5cgCtiz2KfZitiq2YjYqtmDINmB2Yog
2KfZhNmD2YjZitiqIMOXINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNio2K3YsdmK2YYgw5cg2KPY
r9mI2YrYqSDYpdis2YfYp9i2INin2YTYrdmF2YQgw5cg2YXZitiy2YjYqNix2LPYqtmI2YQgw5cg
Ctij2LnYsdin2LYg2KfZhNit2YXZhCDDlyDYs9in2YrYqtmI2KrZitmDINmB2Yog2YXZg9ipIMOX
INi52YrYp9iv2KfYqiDYp9is2YfYp9i2IMOXINiv2YPYqtmI2LHYqSDYp9is2YfYp9i2INmB2Yog
2KfZhNiz2LnZiNiv2YrYqSDDlyAK2K/Zg9iq2YjYsdipINin2KzZh9in2LYg2YHZiiDYp9mE2YPZ
iNmK2Kogw5cg2K/Zg9iq2YjYsdipINin2KzZh9in2LYg2YHZiiDYp9mE2KjYrdix2YrZhiDDlyDY
r9mD2KrZiNix2Kkg2KfYrNmH2KfYtiDZgdmKINin2YTYpdmF2KfYsdin2Kogw5cgCtiv2YPYqtmI
2LHYqSDDlyDYp9mE2K/ZiNix2Kkg2KfZhNi02YfYsdmK2KkKCgrZgdmKINin2YTYp9ir2YbZitmG
2IwgMjUg2KPYutiz2LfYsyAyMDI1INmB2Yog2KrZhdin2YUg2KfZhNiz2KfYudipIDI6MDM6Mzkg
2YUgVVRDKzPYjCDZg9iq2Kgg2LPYp9mK2KrZiNiq2YMgCtin2YTYs9i52YjYr9mK2Ycg2LPYp9mK
2KrZiNiq2YMg2KjYrti12YUgMjAlINix2LPYp9mE2Kkg2YbYtdmH2Kc6Cgo+Cj4g2K/Zg9iq2YjY
sdipINin2KzZh9in2LYg2YHZiiDYp9mE2LPYudmI2K/ZitmHIHwgMDA5NjY1MzgxNTk3NDcgfNi5
2YrYp9iv2Kkg2LPYp9mK2KrZiNiq2YMgCj4KPiAg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDZ
hNmE2KfYs9iq2LTYp9ix2KfYqiDYp9mE2LfYqNmK2KkKPiDYrdio2YjYqCDYp9mE2KfYrNmH2KfY
tiDigJMg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LPYudmI2K/ZitipICB8INiv2YPYqtmI2LHY
qSDZhtmK2LHZhdmK2YYgMDA5NjY1MzgxNTk3NDcg4oCTIAo+INin2LPYqti02KfYsdin2Kog2YjY
udmE2KfYrCDYotmF2YYKPiDYqti52LHZgdmKINi52YTZiSDZg9mEINmF2Kcg2YrZh9mF2YMg2LnZ
hiDYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiDYjCDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i5
2YjYr9mK2YcgCj4gPGh0dHBzOi8vaGF5YXRhbm5hcy5jb20vP3Nyc2x0aWQ9QWZtQk9vb3JYVHY2
d2N0Ylk3b0NiZF96UkJNeE5EUG1UMEY1RFBSd3pNaWZDTWdERE5OcDFjYlY+IAo+INin2YTYsdmK
2KfYttiMINis2K/YqdiMINmF2YPYqdiMINis2KfYstin2YbYjCDZiNiu2YXZitizINmF2LTZiti3
2Iwg2YXYuSDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmGINmE2YTYp9iz2KrYtNin2LHYp9iqINin
2YTYt9io2YrYqSAKPiDZiNi32YTYqCDYp9mE2LnZhNin2Kwg2KjYs9ix2YrYqSDYqtin2YXYqS4K
PiDYqtit2LDZitix2KfYqiDZhdmH2YXYqQo+Cj4g2YrZhdmG2Lkg2KfYs9iq2K7Yr9in2YUg2K3Y
qNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYrdin2YTYp9iqINin2YTYrdmF2YQg2KfZhNmF2KrZ
gtiv2YUg2KjYudivINin2YTYo9iz2KjZiNi5IDEyINil2YTYpyDYqNij2YXYsSAKPiDYp9mE2LfY
qNmK2Kgg2YjYp9mE2KfYs9iq2YXYp9i5INin2YTZiiDYqtmI2KzZitmH2KfYqtmHIC4KPgo+Cj4g
INit2KjZiNioINiz2KfZitiq2YjYqtmDIHwgMDA5NjY1MzgxNTk3NDcgIHwg2YHZiiDYp9mE2LPY
udmI2K/ZitipIOKAkyDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmGINmE2YTYp9iz2KrYtNin2LHY
p9iqIAo+INin2YTYt9io2YrYqSDYp9mE2KXYrNmH2KfYtiAgCj4KPiDZgdmKINin2YTYs9mG2YjY
p9iqINin2YTYo9iu2YrYsdip2Iwg2KPYtdio2K0g2YXZiNi22YjYuSDYrdio2YjYqCDYp9mE2KfY
rNmH2KfYtiDYs9in2YrYqtmI2KrZgyAKPiA8aHR0cHM6Ly9zYXVkaWVyc2FhLmNvbS8+INmB2Yog
2KfZhNiz2LnZiNiv2YrYqSDZhdmGINij2YPYq9ixINin2YTZhdmI2KfYttmK2Lkg2KfZhNiq2Yog
2KrYqNit2Ksg2LnZhtmH2KcgCj4g2KfZhNiz2YrYr9in2KrYjCDYrtin2LXYqSDZgdmKINmF2K/Z
hiDZhdir2YQg2KfZhNix2YrYp9i22Iwg2KzYr9ip2Iwg2YXZg9ip2Iwg2KzYp9iy2KfZhtiMINmI
2K7ZhdmK2LMg2YXYtNmK2LfYjCDZiNmD2LDZhNmDINmB2YogCj4g2YXZhtin2LfZgiDYp9mE2K7Z
hNmK2Kwg2YXYq9mEINin2YTYqNit2LHZitmGINmI2KfZhNmD2YjZitiqINmI2KfZhNi02KfYsdmC
2KkuINmG2LjYsdmL2Kcg2YTYrdiz2KfYs9mK2Kkg2KfZhNmF2YjYttmI2Lkg2YjYo9mH2YXZitiq
2YfYjCAKPiDYqtmC2K/ZhSDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmGINin2YTYr9i52YUg2KfZ
hNi32KjZiiDZiNin2YTYp9iz2KrYtNin2LHYp9iqINin2YTZhdiq2K7Ytdi12Kkg2YTZhNmG2LPY
p9ihINin2YTZhNmI2KfYqtmKINmK2K3Yqtis2YYgCj4g2KXZhNmJINin2YTYqtmI2KzZitmHINin
2YTYtdit2YrYrSDZiNi32YTYqCDYp9mE2LnZhNin2Kwg2YXZhiDZhdi12K/YsSDZhdmI2KvZiNmC
2Iwg2LnYqNixINin2YTYp9iq2LXYp9mEINi52YTZiSDYp9mE2LHZgtmFOiAwMDk2NjUzODE1OTc0
NyAKPiAuCj4KPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+INmF2Kcg2YfZiiDY
rdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KfYrNmH2KfYttifCj4KPiDYrdio2YjYqCDYs9in
2YrYqtmI2KrZgyAoQ3l0b3RlYykg2KrYrdiq2YjZiiDYudmE2Ykg2KfZhNmF2KfYr9ipINin2YTZ
gdi52KfZhNipINin2YTZhdmK2LLZiNio2LHZiNiz2KrZiNmEIAo+IChNaXNvcHJvc3RvbCnYjCDZ
iNmH2Yog2K/ZiNin2KEg2YXYudiq2YXYryDYt9io2YrZi9inINmE2LnZhNin2Kwg2YLYsdit2Kkg
2KfZhNmF2LnYr9ipINmB2Yog2KfZhNij2LXZhNiMINmE2YPZhiDYp9mE2KPYqNit2KfYqyAKPiDY
p9mE2LfYqNmK2Kkg2KPYq9io2KrYqiDZgdin2LnZhNmK2KrZhyDZgdmKINil2YbZh9in2KEg2KfZ
hNit2YXZhCDYp9mE2YXYqNmD2LEgCj4gPGh0dHBzOi8vaGF5YXRhbm5hcy5jb20vP3Nyc2x0aWQ9
QWZtQk9vbzhaZE52RVpVcGczRGRmV3RaTlVSS0Fweldnc1hIcXdtZ3NKZEhKNjhRVV94Z091Z1M+
IAo+INiq2K3YqiDYpdi02LHYp9mBINi32KjZii4KPiDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDZ
itiq2YUg2KfYs9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMg2YHZiiDYrdin2YTYp9iqINiu2KfY
tdipINmIINio2KzYsdi52KfYqiDZhdit2K/Yr9ipINmK2YLYsdix2YfYpyAKPiDYp9mE2LfYqNmK
2KjYjCDZhdi5INi22LHZiNix2Kkg2KfZhNiq2KPZg9ivINmF2YYg2KzZiNiv2Kkg2KfZhNmF2YbY
qtisINmI2YXYtdiv2LHZhy4KPgo+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Cj4g
2YXYqtmJINiq2LPYqtiu2K/ZhSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KXYrNmH2KfY
ttifCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDYp9mE2KXYrNmH2KfYtiDYp9mE2YXYqNmD2LE6
INit2KrZiSDYp9mE2KPYs9io2YjYuSAxMiDZhdmGINin2YTYrdmF2YQuCj4gICAgCj4gICAgLSAK
PiAgICAKPiAgICDYudmG2K8g2YjYrNmI2K8g2KrYtNmI2YfYp9iqINis2YbZitmG2YrYqSDYrti3
2YrYsdipLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2YHZiiDYrdin2YTYp9iqINmI2YHYp9ip
INin2YTYrNmG2YrZhiDYr9in2K7ZhCDYp9mE2LHYrdmFLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4g
ICAg2KXYsNinINmD2KfZhiDYp9mE2K3ZhdmEINmK2LTZg9mEINiu2LfYsdmL2Kcg2LnZhNmJINit
2YrYp9ipINin2YTYo9mFLgo+ICAgIAo+ICAgIAo+IOKaoO+4jyDZhdmE2KfYrdi42Kk6INmE2Kcg
2YrZj9mG2LXYrSDYqNin2LPYqtiu2K/Yp9mFINmH2LDZhyDYp9mE2K3YqNmI2Kgg2K/ZiNmGINmF
2KrYp9io2LnYqSDYt9io2YrYqdiMINmE2KrYrNmG2Kgg2KfZhNmF2LbYp9i52YHYp9iqLgo+Cj4g
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4KPiDYt9ix2YrZgtipINin2LPYqtiu2K/Y
p9mFINit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTYp9is2YfYp9i2Cj4KPiDYp9mE2KfYs9iq
2K7Yr9in2YUg2YrYrtiq2YTZgSDYrdiz2Kgg2LnZhdixINin2YTYrdmF2YQg2YjYrdin2YTYqSDY
p9mE2YXYsdij2KnYjCDZiNmE2YPZhiDZgdmKINin2YTYudmF2YjZhToKPgo+ICAgIDEuIAo+ICAg
IAo+ICAgINin2YTYrNix2LnYqTog2YrYrdiv2K/Zh9inINin2YTYt9io2YrYqCDZgdmC2LfYjCDZ
iNi52KfYr9ipINiq2YPZiNmGINio2YrZhiA4MDAg2YXZitmD2LHZiNi62LHYp9mFINmF2YLYs9mF
2Kkg2LnZhNmJIAo+ICAgINis2LHYudin2KouCj4gICAgCj4gICAgMi4gCj4gICAgCj4gICAg2LfY
sdmK2YLYqSDYp9mE2KrZhtin2YjZhDog2KrZiNi22Lkg2KfZhNit2KjZiNioINiq2K3YqiDYp9mE
2YTYs9in2YYg2KPZiCDZgdmKINin2YTZhdmH2KjZhC4KPiAgICAKPiAgICAzLiAKPiAgICAKPiAg
ICDYp9mE2YXYqtin2KjYudipOiDZitis2Kgg2YXYsdin2KzYudipINin2YTYt9io2YrYqCDYqNi5
2K8gMjQtNDgg2LPYp9i52Kkg2YTZhNiq2KPZg9ivINmF2YYg2KfZg9iq2YXYp9mEINin2YTYudmF
2YTZitipLgo+ICAgIAo+ICAgIAo+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Cj4g
2KfZhNij2LnYsdin2LYg2KfZhNmF2KrZiNmC2LnYqSDYqNi52K8g2KrZhtin2YjZhCDYp9mE2K3Y
qNmI2KgKPgo+ICAgIC0gCj4gICAgCj4gICAg2YbYstmK2YEg2YXZh9io2YTZiiDZiti02KjZhyDY
p9mE2K/ZiNix2Kkg2KfZhNi02YfYsdmK2Kkg2KPZiCDYo9mD2KvYsSDYutiy2KfYsdipLgo+ICAg
IAo+ICAgIC0gCj4gICAgCj4gICAg2KrYtNmG2KzYp9iqINmI2KLZhNin2YUg2YHZiiDYo9iz2YHZ
hCDYp9mE2KjYt9mGLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2LrYq9mK2KfZhiDYo9mIINmC
2YrYoS4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINil2LPZh9in2YQg2K7ZgdmK2YEuCj4gICAg
Cj4gICAgCj4g2KXYsNinINin2LPYqtmF2LEg2KfZhNmG2LLZitmBINin2YTYtNiv2YrYryDYo9mI
INi42YfYsdiqINij2LnYsdin2LYg2YXYq9mEINin2YTYr9mI2K7YqSDYp9mE2K3Yp9iv2KnYjCDZ
itis2Kgg2KfZhNiq2YjYrNmHINmB2YjYsdmL2KcgCj4g2YTZhNi32YjYp9ix2KYuCj4KPiAtLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+INit2KjZiNioINiz2KfZitiq2YjYqtmDINmB
2Yog2KfZhNiz2LnZiNiv2YrZhyDZiNin2YTYqNit2LHZitmGINmI2KfZhNmD2YjZitiqCj4KPiDY
qtmG2KrYtNixINin2YTYrdin2KzYqSDYpdmE2Ykg2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2LPY
p9mK2KrZiNiq2YMgPGh0dHBzOi8va3NhY3l0b3RlYy5jb20vPiDZgdmKINin2YTYudiv2YrYryAK
PiDZhdmGINin2YTZhdiv2YY6Cj4KPiAgICAtIAo+ICAgIAo+ICAgINin2YTYsdmK2KfYtjog2KrZ
iNin2LXZhCDZhdi5INiv2YPYqtmI2LHYqSDZhtmK2LHZhdmK2YYg2YTZhNit2LXZiNmEINi52YTZ
iSDYp9mE2LnZhNin2Kwg2KfZhNij2LXZhNmKLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2KzY
r9ipOiDYrtiv2YXYp9iqINi32KjZitipINio2LPYsdmK2Kkg2KrYp9mF2Kkg2YXYuSDZhdiq2KfY
qNi52KkuCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDZhdmD2Kk6INiv2LnZhSDYt9io2Yog2KLZ
hdmGINmE2YTZhtiz2KfYoSDYp9mE2YTZiNin2KrZiiDZitit2KrYrNmGINmE2KXZhtmH2KfYoSDY
p9mE2K3ZhdmEINin2YTZhdio2YPYsS4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINis2KfYstin
2YY6INin2LPYqti02KfYsdin2Kog2LnYqNixINin2YTZh9in2KrZgSDYo9mIINin2YTZiNin2KrY
s9in2KguCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDYrtmF2YrYsyDZhdi02YrYtzog2KrZiNmB
2YrYsSDYp9mE2LnZhNin2Kwg2KfZhNij2LXZhNmKINiq2K3YqiDYpdi02LHYp9mBINmF2KrYrti1
2LUuCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDYp9mE2LTYp9ix2YLYqSDZiNin2YTYqNit2LHZ
itmGINmI2KfZhNmD2YjZitiqOiDYpdmF2YPYp9mG2YrYqSDYp9mE2KrZiNin2LXZhCDZhNi32YTY
qCDYp9mE2LnZhNin2Kwg2YXZhiDZhdi12K/YsSDZhdmI2KvZiNmCLgo+ICAgIAo+ICAgIAo+IPCf
k54g2LHZgtmFINiv2YPYqtmI2LHYqSDZhtix2YXZitmGINmE2YTYp9iz2KrZgdiz2KfYsTogMDA5
NjY1MzgxNTk3NDcgCj4KPiDZhNmF2KfYsNinINiq2K7Yqtin2LHZitmGINiv2YPYqtmI2LHYqSDZ
htmK2LHZhdmK2YbYnwo+Cj4gICAgLSAKPiAgICAKPiAgICDYrtio2LHYqSDYt9io2YrYqSDZgdmK
INmF2KzYp9mEINin2YTZhtiz2KfYoSDZiNin2YTYqtmI2YTZitivLgo+ICAgIAo+ICAgIC0gCj4g
ICAgCj4gICAg2KrZiNmB2YrYsSDYr9mI2KfYoSDYs9in2YrYqtmI2KrZgyDYp9mE2KPYtdmE2You
Cj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDZhdiq2KfYqNi52Kkg2LTYrti12YrYqSDZhNmE2K3Y
p9mE2Kkg2YXZhiDYp9mE2KjYr9in2YrYqSDYrdiq2Ykg2KfZhNmG2YfYp9mK2KkuCj4gICAgCj4g
ICAgLSAKPiAgICAKPiAgICDYrti12YjYtdmK2Kkg2YjYs9ix2YrYqSDYqtin2YXYqSDZgdmKINin
2YTYqti52KfZhdmELgo+ICAgIAo+ICAgIAo+INio2K/Yp9im2YQg2K3YqNmI2Kgg2LPYp9mK2KrZ
iNiq2YMKPgo+INmB2Yog2KjYudi2INin2YTYrdin2YTYp9iq2Iwg2YLYryDZitmC2KrYsditINin
2YTYt9io2YrYqCDYqNiv2KfYptmEINij2K7YsdmJOgo+Cj4gICAgLSAKPiAgICAKPiAgICDYp9mE
2KrZiNiz2YrYuSDZiNin2YTZg9it2Kog2KfZhNis2LHYp9it2YogKEQmQykuCj4gICAgCj4gICAg
LSAKPiAgICAKPiAgICDYo9iv2YjZitipINiq2K3YqtmI2Yog2LnZhNmJINmF2YrZgdmK2KjYsdmK
2LPYqtmI2YYg2YXYuSDZhdmK2LLZiNio2LHZiNiz2KrZiNmELgo+ICAgIAo+ICAgIC0gCj4gICAg
Cj4gICAg2KfZhNil2KzZh9in2LYg2KfZhNis2LHYp9it2Yog2KfZhNmF2KjYp9i02LEuCj4gICAg
Cj4g2KPYs9im2YTYqSDYtNin2KbYudipCj4KPiAxLiDZh9mEINmK2YXZg9mGINi02LHYp9ihINiz
2KfZitiq2YjYqtmDINio2K/ZiNmGINmI2LXZgdipINmB2Yog2KfZhNiz2LnZiNiv2YrYqdifCj4g
2LrYp9mE2KjZi9inINmE2KfYjCDZiNmK2KzYqCDYp9mE2K3YtdmI2YQg2LnZhNmK2Ycg2YXZhiDZ
hdi12K/YsSDZhdmI2KvZiNmCINiq2K3YqiDYpdi02LHYp9mBINi32KjZii4KPgo+IDIuINmD2YUg
2KrYs9iq2LrYsdmCINi52YXZhNmK2Kkg2KfZhNin2KzZh9in2LYg2KjYp9mE2K3YqNmI2KjYnwo+
INi52KfYr9ipINmF2YYgMjQg2KXZhNmJIDQ4INiz2KfYudipINit2KrZiSDZitmD2KrZhdmEINin
2YTZhtiy2YrZgSDZiNil2K7Ysdin2Kwg2KfZhNit2YXZhC4KPgo+IDMuINmH2YQg2YrYs9io2Kgg
2LPYp9mK2KrZiNiq2YMg2KfZhNi52YLZhdifCj4g2YTYp9iMINil2LDYpyDYqtmFINin2LPYqtiu
2K/Yp9mF2Ycg2KjYtNmD2YQg2LXYrdmK2K3YjCDZhNinINmK2KTYq9ixINi52YTZiSDYp9mE2YLY
r9ix2Kkg2KfZhNil2YbYrNin2KjZitipINin2YTZhdiz2KrZgtio2YTZitipLgo+Cj4g2K7Yp9iq
2YXYqQo+Cj4g2KXZhiDYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiDYs9in2YrYqtmI2KrZgyDZgdmK
INin2YTYs9i52YjYr9mK2Ycg2KrZhdir2YQg2K3ZhNmL2Kcg2LfYqNmK2YvYpyDZgdmKINit2KfZ
hNin2Kog2K7Yp9i12KnYjCDZhNmD2YYgCj4g2KfZhNij2YXYp9mGINmK2YPZhdmGINmB2Yog2KfY
s9iq2LTYp9ix2Kkg2YXYrtiq2LXZitmGINmF2KvZhCDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmG
INin2YTYqtmKINiq2YjZgdixINin2YTYr9i52YUg2YjYp9mE2LnZhNin2Kwg2YXZhiAKPiDZhdi1
2K/YsSDZhdi22YXZiNmG2Iwg2YXYuSDZhdiq2KfYqNi52Kkg2K/ZgtmK2YLYqSDZiNiz2LHZitip
INiq2KfZhdipLgo+INmE2YTYp9iz2KrZgdiz2KfYsdin2Kog2KPZiCDYt9mE2Kgg2KfZhNi52YTY
p9is2Iwg2KfYqti12YTZiiDYp9mE2KLZhiDYudmE2Yk6IDAwOTY2NTM4MTU5NzQ3IC4KPgo+INiq
2K3YsNmK2LHYp9iqINmF2YfZhdipCj4KPiDZitmF2YbYuSDYp9iz2KrYrtiv2KfZhSDYrdio2YjY
qCDYs9in2YrYqtmI2KrZgyDZgdmKINit2KfZhNin2Kog2KfZhNit2YXZhCDYp9mE2YXYqtmC2K/Z
hSDYqNi52K8g2KfZhNij2LPYqNmI2LkgMTIg2KXZhNinINio2KPZhdixIAo+INin2YTYt9io2YrY
qC4KPgo+INmE2Kcg2KrYs9iq2K7Yr9mF2Yog2KfZhNit2KjZiNioINil2LDYpyDZg9in2YYg2YTY
r9mK2YMg2K3Ys9in2LPZitipINmF2YYg2KfZhNmF2KfYr9ipINin2YTZgdi52KfZhNipLgo+Cj4g
2YTYpyDYqtiq2YbYp9mI2YTZiiDYo9mKINis2LHYudipINil2LbYp9mB2YrYqSDYqNiv2YjZhiDY
p9iz2KrYtNin2LHYqSDYt9io2YrYqS4KPgo+Cj4gINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz
2LnZiNiv2YrYqSDDlyDYs9in2YrYqtmI2KrZgyDYqNin2YTYsdmK2KfYtiDDlyDYs9in2YrYqtmI
2KrZgyDYp9mE2K/Zhdin2YUgw5cg2LPYp9mK2KrZiNiq2YMg2K7ZhdmK2LMgCj4g2YXYtNmK2Lcg
w5cg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2YPZiNmK2Kogw5cg2LPYp9mK2KrZiNiq2YMg2YHZ
iiDYp9mE2KjYrdix2YrZhiDDlyDYo9iv2YjZitipINil2KzZh9in2LYg2KfZhNit2YXZhCDDlyAK
PiDZhdmK2LLZiNio2LHYs9iq2YjZhCDDlyDYo9i52LHYp9i2INin2YTYrdmF2YQgw5cg2LPYp9mK
2KrZiNiq2YrZgyDZgdmKINmF2YPYqSDDlyDYudmK2KfYr9in2Kog2KfYrNmH2KfYtiDDlyDYr9mD
2KrZiNix2Kkg2KfYrNmH2KfYtiAKPiDZgdmKINin2YTYs9i52YjYr9mK2Kkgw5cg2K/Zg9iq2YjY
sdipINin2KzZh9in2LYg2YHZiiDYp9mE2YPZiNmK2Kogw5cg2K/Zg9iq2YjYsdipINin2KzZh9in
2LYg2YHZiiDYp9mE2KjYrdix2YrZhiDDlyDYr9mD2KrZiNix2KkgCj4g2KfYrNmH2KfYtiDZgdmK
INin2YTYpdmF2KfYsdin2Kogw5cg2K/Zg9iq2YjYsdipIMOXINin2YTYr9mI2LHYqSDYp9mE2LTZ
h9ix2YrYqQo+Cj4NCg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3Ug
YXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRv
IHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZy
b20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vw
cy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2ds
ZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvOTIwNzA2NDctMWZiNi00MjJhLThkMjktZGE5ZGY5YWM5
NDM3biU0MGdvb2dsZWdyb3Vwcy5jb20uCg==
------=_Part_429089_2094134490.1756120055975
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<br /><span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin=
-bottom: 4pt;"><span style=3D"font-size: 13pt; font-family: Arial, sans-ser=
if; color: rgb(73, 80, 87); background-color: transparent; font-weight: 700=
; font-variant-numeric: normal; font-variant-east-asian: normal; font-varia=
nt-alternates: normal; font-variant-position: normal; font-variant-emoji: n=
ormal; vertical-align: baseline; white-space-collapse: preserve;">=D8=AF=D9=
=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=
=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 | </span><span style=3D"font-=
size: 12pt; font-family: Arial, sans-serif; color: rgb(51, 51, 51); font-we=
ight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; f=
ont-variant-alternates: normal; font-variant-position: normal; font-variant=
-emoji: normal; vertical-align: baseline; white-space-collapse: preserve;">=
00966538159747 </span><span style=3D"font-size: 13pt; font-family: Arial, s=
ans-serif; color: rgb(73, 80, 87); background-color: transparent; font-weig=
ht: 700; font-variant-numeric: normal; font-variant-east-asian: normal; fon=
t-variant-alternates: normal; font-variant-position: normal; font-variant-e=
moji: normal; vertical-align: baseline; white-space-collapse: preserve;">|=
=D8=B9=D9=8A=D8=A7=D8=AF=D8=A9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=
=C2=A0</span></span><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: =
0pt; margin-bottom: 12pt;"><span style=3D"font-size: 11.5pt; font-family: A=
rial, sans-serif; color: rgb(73, 80, 87); background-color: transparent; fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;">=C2=A0=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=
=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=
=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9</span><span style=3D"font-size: 11.5pt; f=
ont-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color: tr=
ansparent; font-weight: 700; font-variant-numeric: normal; font-variant-eas=
t-asian: normal; font-variant-alternates: normal; font-variant-position: no=
rmal; font-variant-emoji: normal; vertical-align: baseline; white-space-col=
lapse: preserve;"><br /></span><span style=3D"font-size: 11.5pt; font-famil=
y: Arial, sans-serif; color: rgb(73, 80, 87); background-color: transparent=
; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; vertical-align: baseline; white-space-collapse: pr=
eserve;">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =E2=80=93 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=
=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=C2=A0 | =D8=AF=D9=83=D8=AA=D9=
=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 </span><span style=3D"=
font-size: 12pt; font-family: Arial, sans-serif; color: rgb(51, 51, 51); fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;">00966538159747 </span><span style=3D"font-size: 11.5pt; font-family: A=
rial, sans-serif; color: rgb(73, 80, 87); background-color: transparent; fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;">=E2=80=93 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D9=88=D8=
=B9=D9=84=D8=A7=D8=AC =D8=A2=D9=85=D9=86</span><span style=3D"font-size: 11=
.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); background-co=
lor: transparent; font-weight: 700; font-variant-numeric: normal; font-vari=
ant-east-asian: normal; font-variant-alternates: normal; font-variant-posit=
ion: normal; font-variant-emoji: normal; vertical-align: baseline; white-sp=
ace-collapse: preserve;"><br /></span><span style=3D"font-size: 11.5pt; fon=
t-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color: tran=
sparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-=
asian: normal; font-variant-alternates: normal; font-variant-position: norm=
al; font-variant-emoji: normal; vertical-align: baseline; white-space-colla=
pse: preserve;">=D8=AA=D8=B9=D8=B1=D9=81=D9=8A =D8=B9=D9=84=D9=89 =D9=83=D9=
=84 =D9=85=D8=A7 =D9=8A=D9=87=D9=85=D9=83 =D8=B9=D9=86 =D8=AD=D8=A8=D9=88=
=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=8C </span><a href=3D"=
https://hayatannas.com/?srsltid=3DAfmBOoorXTv6wctbY7oCbd_zRBMxNDPmT0F5DPRwz=
MifCMgDDNNp1cbV"><span style=3D"font-size: 11.5pt; font-family: Arial, sans=
-serif; color: rgb(255, 152, 0); background-color: transparent; font-weight=
: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-=
variant-alternates: normal; font-variant-position: normal; font-variant-emo=
ji: normal; vertical-align: baseline; white-space-collapse: preserve;">=D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=
=B9=D9=88=D8=AF=D9=8A=D9=87</span></a><span style=3D"font-size: 11.5pt; fon=
t-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color: tran=
sparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-=
asian: normal; font-variant-alternates: normal; font-variant-position: norm=
al; font-variant-emoji: normal; vertical-align: baseline; white-space-colla=
pse: preserve;"> =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=
=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=AC=D8=A7=D8=B2=D8=A7=D9=86=D8=8C =D9=
=88=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7=D8=8C =D9=85=D8=B9 =D8=
=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=
=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=
=B7=D8=A8=D9=8A=D8=A9 =D9=88=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=D8=
=A7=D8=AC =D8=A8=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9.</span></=
p><span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-bot=
tom: 4pt;"><span style=3D"font-size: 17pt; font-family: Arial, sans-serif; =
color: rgb(255, 0, 0); background-color: transparent; font-weight: 700; fon=
t-variant-numeric: normal; font-variant-east-asian: normal; font-variant-al=
ternates: normal; font-variant-position: normal; font-variant-emoji: normal=
; vertical-align: baseline; white-space-collapse: preserve;">=D8=AA=D8=AD=
=D8=B0=D9=8A=D8=B1=D8=A7=D8=AA =D9=85=D9=87=D9=85=D8=A9</span></span><p dir=
=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"=
><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: r=
gb(255, 0, 0); background-color: transparent; font-weight: 700; font-varian=
t-numeric: normal; font-variant-east-asian: normal; font-variant-alternates=
: normal; font-variant-position: normal; font-variant-emoji: normal; vertic=
al-align: baseline; white-space-collapse: preserve;">=D9=8A=D9=85=D9=86=D8=
=B9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=
=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=
=AF=D9=85 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =
=D8=A5=D9=84=D8=A7 =D8=A8=D8=A3=D9=85=D8=B1 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=
=D8=A8 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=85=D8=A7=D8=B9 =D8=A7=D9=84=
=D9=8A =D8=AA=D9=88=D8=AC=D9=8A=D9=87=D8=A7=D8=AA=D9=87 .</span></p><br /><=
br /><span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-=
bottom: 2pt;"><span style=3D"font-size: 11pt; font-family: Arial, sans-seri=
f; color: rgb(73, 80, 87); background-color: transparent; font-weight: 700;=
 font-variant-numeric: normal; font-variant-east-asian: normal; font-varian=
t-alternates: normal; font-variant-position: normal; font-variant-emoji: no=
rmal; vertical-align: baseline; white-space-collapse: preserve;">=C2=A0=D8=
=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 | </span><=
span style=3D"font-size: 12pt; font-family: Arial, sans-serif; color: rgb(5=
1, 51, 51); font-weight: 700; font-variant-numeric: normal; font-variant-ea=
st-asian: normal; font-variant-alternates: normal; font-variant-position: n=
ormal; font-variant-emoji: normal; vertical-align: baseline; white-space-co=
llapse: preserve;">00966538159747 </span><span style=3D"font-size: 11pt; fo=
nt-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color: tra=
nsparent; font-weight: 700; font-variant-numeric: normal; font-variant-east=
-asian: normal; font-variant-alternates: normal; font-variant-position: nor=
mal; font-variant-emoji: normal; vertical-align: baseline; white-space-coll=
apse: preserve;">=C2=A0| =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=
=D9=8A=D8=A9 =E2=80=93 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=
=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=
=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=
=87=D8=A7=D8=B6=C2=A0=C2=A0</span></span><p dir=3D"rtl" style=3D"line-heigh=
t: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><span style=3D"font-size: 1=
1.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); background-c=
olor: transparent; font-weight: 700; font-variant-numeric: normal; font-var=
iant-east-asian: normal; font-variant-alternates: normal; font-variant-posi=
tion: normal; font-variant-emoji: normal; vertical-align: baseline; white-s=
pace-collapse: preserve;">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D9=86=D9=88=D8=A7=
=D8=AA =D8=A7=D9=84=D8=A3=D8=AE=D9=8A=D8=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=
=D8=AD =D9=85=D9=88=D8=B6=D9=88=D8=B9 </span><a href=3D"https://saudiersaa.=
com/"><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; col=
or: rgb(255, 152, 0); background-color: transparent; font-weight: 700; font=
-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alt=
ernates: normal; font-variant-position: normal; font-variant-emoji: normal;=
 vertical-align: baseline; white-space-collapse: preserve;">=D8=AD=D8=A8=D9=
=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size: 11.5pt; font-fami=
ly: Arial, sans-serif; color: rgb(73, 80, 87); background-color: transparen=
t; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian:=
 normal; font-variant-alternates: normal; font-variant-position: normal; fo=
nt-variant-emoji: normal; vertical-align: baseline; white-space-collapse: p=
reserve;"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =
=D9=85=D9=86 =D8=A3=D9=83=D8=AB=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B6=
=D9=8A=D8=B9 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=A8=D8=AD=D8=AB =D8=B9=D9=86=
=D9=87=D8=A7 =D8=A7=D9=84=D8=B3=D9=8A=D8=AF=D8=A7=D8=AA=D8=8C =D8=AE=D8=A7=
=D8=B5=D8=A9 =D9=81=D9=8A =D9=85=D8=AF=D9=86 =D9=85=D8=AB=D9=84 =D8=A7=D9=
=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=
=A9=D8=8C =D8=AC=D8=A7=D8=B2=D8=A7=D9=86=D8=8C =D9=88=D8=AE=D9=85=D9=8A=D8=
=B3 =D9=85=D8=B4=D9=8A=D8=B7=D8=8C =D9=88=D9=83=D8=B0=D9=84=D9=83 =D9=81=D9=
=8A =D9=85=D9=86=D8=A7=D8=B7=D9=82 =D8=A7=D9=84=D8=AE=D9=84=D9=8A=D8=AC =D9=
=85=D8=AB=D9=84 =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=88=D8=A7=D9=
=84=D9=83=D9=88=D9=8A=D8=AA =D9=88=D8=A7=D9=84=D8=B4=D8=A7=D8=B1=D9=82=D8=
=A9. =D9=86=D8=B8=D8=B1=D9=8B=D8=A7 =D9=84=D8=AD=D8=B3=D8=A7=D8=B3=D9=8A=D8=
=A9 =D8=A7=D9=84=D9=85=D9=88=D8=B6=D9=88=D8=B9 =D9=88=D8=A3=D9=87=D9=85=D9=
=8A=D8=AA=D9=87=D8=8C =D8=AA=D9=82=D8=AF=D9=85 =D8=AF=D9=83=D8=AA=D9=88=D8=
=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=A7=D9=84=D8=AF=D8=B9=D9=
=85 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=
=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=
=A9 =D9=84=D9=84=D9=86=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=
=AA=D9=8A =D9=8A=D8=AD=D8=AA=D8=AC=D9=86 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=
=AA=D9=88=D8=AC=D9=8A=D9=87 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=AD =D9=88=D8=
=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=
=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82=D8=8C =D8=B9=D8=A8=D8=B1 =D8=
=A7=D9=84=D8=A7=D8=AA=D8=B5=D8=A7=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=
=B1=D9=82=D9=85: </span><span style=3D"font-size: 12pt; font-family: Arial,=
 sans-serif; color: rgb(51, 51, 51); font-weight: 700; font-variant-numeric=
: normal; font-variant-east-asian: normal; font-variant-alternates: normal;=
 font-variant-position: normal; font-variant-emoji: normal; vertical-align:=
 baseline; white-space-collapse: preserve;">00966538159747 </span><span sty=
le=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80,=
 87); background-color: transparent; font-weight: 700; font-variant-numeric=
: normal; font-variant-east-asian: normal; font-variant-alternates: normal;=
 font-variant-position: normal; font-variant-emoji: normal; vertical-align:=
 baseline; white-space-collapse: preserve;">.</span></p><p dir=3D"rtl" styl=
e=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 0pt;"></p><hr /><p>=
</p><span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-b=
ottom: 2pt;"><span style=3D"font-size: 10pt; font-family: Arial, sans-serif=
; color: rgb(73, 80, 87); background-color: transparent; font-weight: 700; =
font-variant-numeric: normal; font-variant-east-asian: normal; font-variant=
-alternates: normal; font-variant-position: normal; font-variant-emoji: nor=
mal; vertical-align: baseline; white-space-collapse: preserve;">=D9=85=D8=
=A7 =D9=87=D9=8A =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=84=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6=D8=9F</span></span><p =
dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12p=
t;"><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color=
: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-va=
riant-numeric: normal; font-variant-east-asian: normal; font-variant-altern=
ates: normal; font-variant-position: normal; font-variant-emoji: normal; ve=
rtical-align: baseline; white-space-collapse: preserve;">=D8=AD=D8=A8=D9=88=
=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 (Cytotec) =D8=AA=D8=AD=D8=
=AA=D9=88=D9=8A =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=
=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9 =D8=A7=D9=84=D9=85=D9=8A=D8=B2=D9=
=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84 (Misoprostol)=D8=8C =D9=88=D9=
=87=D9=8A =D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D8=B9=D8=AA=D9=85=D8=AF =D8=B7=D8=
=A8=D9=8A=D9=8B=D8=A7 =D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=82=D8=B1=D8=AD=D8=
=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AF=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=A3=D8=
=B5=D9=84=D8=8C =D9=84=D9=83=D9=86 =D8=A7=D9=84=D8=A3=D8=A8=D8=AD=D8=A7=D8=
=AB =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A3=D8=AB=D8=A8=D8=AA=D8=AA =D9=
=81=D8=A7=D8=B9=D9=84=D9=8A=D8=AA=D9=87 =D9=81=D9=8A </span><a href=3D"http=
s://hayatannas.com/?srsltid=3DAfmBOoo8ZdNvEZUpg3DdfWtZNURKApzWgsXHqwmgsJdHJ=
68QU_xgOugS"><span style=3D"font-size: 11.5pt; font-family: Arial, sans-ser=
if; color: rgb(255, 152, 0); background-color: transparent; font-weight: 70=
0; font-variant-numeric: normal; font-variant-east-asian: normal; font-vari=
ant-alternates: normal; font-variant-position: normal; font-variant-emoji: =
normal; vertical-align: baseline; white-space-collapse: preserve;">=D8=A5=
=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=
=D8=A8=D9=83=D8=B1</span></a><span style=3D"font-size: 11.5pt; font-family:=
 Arial, sans-serif; color: rgb(73, 80, 87); background-color: transparent; =
font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: no=
rmal; font-variant-alternates: normal; font-variant-position: normal; font-=
variant-emoji: normal; vertical-align: baseline; white-space-collapse: pres=
erve;"> =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=
=8A.</span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif=
; color: rgb(73, 80, 87); background-color: transparent; font-weight: 700; =
font-variant-numeric: normal; font-variant-east-asian: normal; font-variant=
-alternates: normal; font-variant-position: normal; font-variant-emoji: nor=
mal; vertical-align: baseline; white-space-collapse: preserve;"><br /></spa=
n><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: =
rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-vari=
ant-numeric: normal; font-variant-east-asian: normal; font-variant-alternat=
es: normal; font-variant-position: normal; font-variant-emoji: normal; vert=
ical-align: baseline; white-space-collapse: preserve;">=D9=81=D9=8A =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D9=8A=D8=AA=D9=85 =D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9=
 =D9=88 =D8=A8=D8=AC=D8=B1=D8=B9=D8=A7=D8=AA =D9=85=D8=AD=D8=AF=D8=AF=D8=A9=
 =D9=8A=D9=82=D8=B1=D8=B1=D9=87=D8=A7 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8=
=D8=8C =D9=85=D8=B9 =D8=B6=D8=B1=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=D8=AA=D8=A3=
=D9=83=D8=AF =D9=85=D9=86 =D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D9=85=D9=86=
=D8=AA=D8=AC =D9=88=D9=85=D8=B5=D8=AF=D8=B1=D9=87.</span></p><p dir=3D"rtl"=
 style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 0pt;"></p><hr =
/><p></p><span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; mar=
gin-bottom: 2pt;"><span style=3D"font-size: 10pt; font-family: Arial, sans-=
serif; color: rgb(73, 80, 87); background-color: transparent; font-weight: =
700; font-variant-numeric: normal; font-variant-east-asian: normal; font-va=
riant-alternates: normal; font-variant-position: normal; font-variant-emoji=
: normal; vertical-align: baseline; white-space-collapse: preserve;">=D9=85=
=D8=AA=D9=89 =D8=AA=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=
=D8=A7=D8=B6=D8=9F</span></span><ul style=3D"margin-top: 0px; margin-bottom=
: 0px; padding-inline-start: 48px;"><li dir=3D"rtl" style=3D"list-style-typ=
e: disc; font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, =
80, 87); background-color: transparent; font-weight: 700; font-variant-nume=
ric: normal; font-variant-east-asian: normal; font-variant-alternates: norm=
al; font-variant-position: normal; font-variant-emoji: normal; vertical-ali=
gn: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"presentation" style=
=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-bottom: 0=
pt;"><span style=3D"font-size: 11.5pt; background-color: transparent; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; text-wrap-mode: wrap;">=D8=A7=D9=84=D8=A5=D8=AC=
=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1: =D8=AD=D8=AA=D9=89=
 =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =D9=85=D9=86 =D8=A7=D9=84=D8=
=AD=D9=85=D9=84.</span><span style=3D"font-size: 11.5pt; background-color: =
transparent; font-variant-numeric: normal; font-variant-east-asian: normal;=
 font-variant-alternates: normal; font-variant-position: normal; font-varia=
nt-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;"><br /><b=
r /></span></p></li><li dir=3D"rtl" style=3D"list-style-type: disc; font-si=
ze: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); backgro=
und-color: transparent; font-weight: 700; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; wh=
ite-space: pre;"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:=
 1.38; text-align: right; margin-top: 0pt; margin-bottom: 0pt;"><span style=
=3D"font-size: 11.5pt; background-color: transparent; font-variant-numeric:=
 normal; font-variant-east-asian: normal; font-variant-alternates: normal; =
font-variant-position: normal; font-variant-emoji: normal; vertical-align: =
baseline; text-wrap-mode: wrap;">=D8=B9=D9=86=D8=AF =D9=88=D8=AC=D9=88=D8=
=AF =D8=AA=D8=B4=D9=88=D9=87=D8=A7=D8=AA =D8=AC=D9=86=D9=8A=D9=86=D9=8A=D8=
=A9 =D8=AE=D8=B7=D9=8A=D8=B1=D8=A9.</span><span style=3D"font-size: 11.5pt;=
 background-color: transparent; font-variant-numeric: normal; font-variant-=
east-asian: normal; font-variant-alternates: normal; font-variant-position:=
 normal; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mo=
de: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-style-=
type: disc; font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(7=
3, 80, 87); background-color: transparent; font-weight: 700; font-variant-n=
umeric: normal; font-variant-east-asian: normal; font-variant-alternates: n=
ormal; font-variant-position: normal; font-variant-emoji: normal; vertical-=
align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"presentation" st=
yle=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-bottom=
: 0pt;"><span style=3D"font-size: 11.5pt; background-color: transparent; fo=
nt-variant-numeric: normal; font-variant-east-asian: normal; font-variant-a=
lternates: normal; font-variant-position: normal; font-variant-emoji: norma=
l; vertical-align: baseline; text-wrap-mode: wrap;">=D9=81=D9=8A =D8=AD=D8=
=A7=D9=84=D8=A7=D8=AA =D9=88=D9=81=D8=A7=D8=A9 =D8=A7=D9=84=D8=AC=D9=86=D9=
=8A=D9=86 =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=D8=B1=D8=AD=D9=85.</span><s=
pan style=3D"font-size: 11.5pt; background-color: transparent; font-variant=
-numeric: normal; font-variant-east-asian: normal; font-variant-alternates:=
 normal; font-variant-position: normal; font-variant-emoji: normal; vertica=
l-align: baseline; text-wrap-mode: wrap;"><br /><br /></span></p></li><li d=
ir=3D"rtl" style=3D"list-style-type: disc; font-size: 11.5pt; font-family: =
Arial, sans-serif; color: rgb(73, 80, 87); background-color: transparent; f=
ont-weight: 700; font-variant-numeric: normal; font-variant-east-asian: nor=
mal; font-variant-alternates: normal; font-variant-position: normal; font-v=
ariant-emoji: normal; vertical-align: baseline; white-space: pre;"><p dir=
=3D"rtl" role=3D"presentation" style=3D"line-height: 1.38; text-align: righ=
t; margin-top: 0pt; margin-bottom: 12pt;"><span style=3D"font-size: 11.5pt;=
 background-color: transparent; font-variant-numeric: normal; font-variant-=
east-asian: normal; font-variant-alternates: normal; font-variant-position:=
 normal; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mo=
de: wrap;">=D8=A5=D8=B0=D8=A7 =D9=83=D8=A7=D9=86 =D8=A7=D9=84=D8=AD=D9=85=
=D9=84 =D9=8A=D8=B4=D9=83=D9=84 =D8=AE=D8=B7=D8=B1=D9=8B=D8=A7 =D8=B9=D9=84=
=D9=89 =D8=AD=D9=8A=D8=A7=D8=A9 =D8=A7=D9=84=D8=A3=D9=85.</span><span style=
=3D"font-size: 11.5pt; background-color: transparent; font-variant-numeric:=
 normal; font-variant-east-asian: normal; font-variant-alternates: normal; =
font-variant-position: normal; font-variant-emoji: normal; vertical-align: =
baseline; text-wrap-mode: wrap;"><br /><br /></span></p></li></ul><p dir=3D=
"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><s=
pan style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(=
73, 80, 87); background-color: transparent; font-weight: 700; font-variant-=
numeric: normal; font-variant-east-asian: normal; font-variant-alternates: =
normal; font-variant-position: normal; font-variant-emoji: normal; vertical=
-align: baseline; white-space-collapse: preserve;">=E2=9A=A0=EF=B8=8F =D9=
=85=D9=84=D8=A7=D8=AD=D8=B8=D8=A9: =D9=84=D8=A7 =D9=8A=D9=8F=D9=86=D8=B5=D8=
=AD =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D9=87=D8=B0=D9=87 =D8=
=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AF=D9=88=D9=86 =D9=85=D8=AA=D8=A7=D8=
=A8=D8=B9=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9=D8=8C =D9=84=D8=AA=D8=AC=D9=86=D8=
=A8 =D8=A7=D9=84=D9=85=D8=B6=D8=A7=D8=B9=D9=81=D8=A7=D8=AA.</span></p><p di=
r=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 0pt;"=
></p><hr /><p></p><span dir=3D"rtl" style=3D"line-height: 1.44; margin-top:=
 0pt; margin-bottom: 2pt;"><span style=3D"font-size: 10pt; font-family: Ari=
al, sans-serif; color: rgb(73, 80, 87); background-color: transparent; font=
-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal=
; font-variant-alternates: normal; font-variant-position: normal; font-vari=
ant-emoji: normal; vertical-align: baseline; white-space-collapse: preserve=
;">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=
=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=
=84=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6</span></span><p dir=3D"rtl" style=
=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><span style=
=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 8=
7); background-color: transparent; font-weight: 700; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;">=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=
=AE=D8=AF=D8=A7=D9=85 =D9=8A=D8=AE=D8=AA=D9=84=D9=81 =D8=AD=D8=B3=D8=A8 =D8=
=B9=D9=85=D8=B1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D9=88=D8=AD=D8=A7=D9=84=D8=
=A9 =D8=A7=D9=84=D9=85=D8=B1=D8=A3=D8=A9=D8=8C =D9=88=D9=84=D9=83=D9=86 =D9=
=81=D9=8A =D8=A7=D9=84=D8=B9=D9=85=D9=88=D9=85:</span></p><ol style=3D"marg=
in-top: 0px; margin-bottom: 0px; padding-inline-start: 48px;"><li dir=3D"rt=
l" style=3D"list-style-type: decimal; font-size: 11.5pt; font-family: Arial=
, sans-serif; color: rgb(73, 80, 87); background-color: transparent; font-w=
eight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; =
font-variant-alternates: normal; font-variant-position: normal; font-varian=
t-emoji: normal; vertical-align: baseline; white-space: pre;"><p dir=3D"rtl=
" role=3D"presentation" style=3D"line-height: 1.38; text-align: right; marg=
in-top: 0pt; margin-bottom: 0pt;"><span style=3D"font-size: 11.5pt; backgro=
und-color: transparent; font-variant-numeric: normal; font-variant-east-asi=
an: normal; font-variant-alternates: normal; font-variant-position: normal;=
 font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap=
;">=D8=A7=D9=84=D8=AC=D8=B1=D8=B9=D8=A9: =D9=8A=D8=AD=D8=AF=D8=AF=D9=87=D8=
=A7 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D9=81=D9=82=D8=B7=D8=8C =D9=88=D8=
=B9=D8=A7=D8=AF=D8=A9 =D8=AA=D9=83=D9=88=D9=86 =D8=A8=D9=8A=D9=86 800 =D9=
=85=D9=8A=D9=83=D8=B1=D9=88=D8=BA=D8=B1=D8=A7=D9=85 =D9=85=D9=82=D8=B3=D9=
=85=D8=A9 =D8=B9=D9=84=D9=89 =D8=AC=D8=B1=D8=B9=D8=A7=D8=AA.</span><span st=
yle=3D"font-size: 11.5pt; background-color: transparent; font-variant-numer=
ic: normal; font-variant-east-asian: normal; font-variant-alternates: norma=
l; font-variant-position: normal; font-variant-emoji: normal; vertical-alig=
n: baseline; text-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"=
rtl" style=3D"list-style-type: decimal; font-size: 11.5pt; font-family: Ari=
al, sans-serif; color: rgb(73, 80, 87); background-color: transparent; font=
-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal=
; font-variant-alternates: normal; font-variant-position: normal; font-vari=
ant-emoji: normal; vertical-align: baseline; white-space: pre;"><p dir=3D"r=
tl" role=3D"presentation" style=3D"line-height: 1.38; text-align: right; ma=
rgin-top: 0pt; margin-bottom: 0pt;"><span style=3D"font-size: 11.5pt; backg=
round-color: transparent; font-variant-numeric: normal; font-variant-east-a=
sian: normal; font-variant-alternates: normal; font-variant-position: norma=
l; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wr=
ap;">=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A7=D9=84=D8=AA=D9=86=D8=A7=D9=88=D9=
=84: =D8=AA=D9=88=D8=B6=D8=B9 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AA=
=D8=AD=D8=AA =D8=A7=D9=84=D9=84=D8=B3=D8=A7=D9=86 =D8=A3=D9=88 =D9=81=D9=8A=
 =D8=A7=D9=84=D9=85=D9=87=D8=A8=D9=84.</span><span style=3D"font-size: 11.5=
pt; background-color: transparent; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; text-wrap=
-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-sty=
le-type: decimal; font-size: 11.5pt; font-family: Arial, sans-serif; color:=
 rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-var=
iant-numeric: normal; font-variant-east-asian: normal; font-variant-alterna=
tes: normal; font-variant-position: normal; font-variant-emoji: normal; ver=
tical-align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"presentati=
on" style=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-=
bottom: 12pt;"><span style=3D"font-size: 11.5pt; background-color: transpar=
ent; font-variant-numeric: normal; font-variant-east-asian: normal; font-va=
riant-alternates: normal; font-variant-position: normal; font-variant-emoji=
: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=A7=D9=84=D9=
=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9: =D9=8A=D8=AC=D8=A8 =D9=85=D8=B1=D8=A7=D8=
=AC=D8=B9=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D8=A8=D8=B9=D8=AF 24-=
48 =D8=B3=D8=A7=D8=B9=D8=A9 =D9=84=D9=84=D8=AA=D8=A3=D9=83=D8=AF =D9=85=D9=
=86 =D8=A7=D9=83=D8=AA=D9=85=D8=A7=D9=84 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=
=8A=D8=A9.</span><span style=3D"font-size: 11.5pt; background-color: transp=
arent; font-variant-numeric: normal; font-variant-east-asian: normal; font-=
variant-alternates: normal; font-variant-position: normal; font-variant-emo=
ji: normal; vertical-align: baseline; text-wrap-mode: wrap;"><br /><br /></=
span></p></li></ol><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0=
pt; margin-bottom: 0pt;"></p><hr /><p></p><p dir=3D"rtl" style=3D"line-heig=
ht: 1.38; margin-top: 0pt; margin-bottom: 0pt;"><span style=3D"font-size: 1=
0pt; font-family: &quot;Courier New&quot;, monospace; color: rgb(29, 33, 37=
); background-color: transparent; font-weight: 700; font-variant-numeric: n=
ormal; font-variant-east-asian: normal; font-variant-alternates: normal; fo=
nt-variant-position: normal; font-variant-emoji: normal; vertical-align: ba=
seline; white-space-collapse: preserve;">=D8=A7=D9=84=D8=A3=D8=B9=D8=B1=D8=
=A7=D8=B6 =D8=A7=D9=84=D9=85=D8=AA=D9=88=D9=82=D8=B9=D8=A9 =D8=A8=D8=B9=D8=
=AF =D8=AA=D9=86=D8=A7=D9=88=D9=84 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8</sp=
an></p><ul style=3D"margin-top: 0px; margin-bottom: 0px; padding-inline-sta=
rt: 48px;"><li dir=3D"rtl" style=3D"list-style-type: disc; font-size: 11.5p=
t; font-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color=
: transparent; font-weight: 700; font-variant-numeric: normal; font-variant=
-east-asian: normal; font-variant-alternates: normal; font-variant-position=
: normal; font-variant-emoji: normal; vertical-align: baseline; white-space=
: pre;"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height: 1.38; te=
xt-align: right; margin-top: 0pt; margin-bottom: 0pt;"><span style=3D"font-=
size: 11.5pt; background-color: transparent; font-variant-numeric: normal; =
font-variant-east-asian: normal; font-variant-alternates: normal; font-vari=
ant-position: normal; font-variant-emoji: normal; vertical-align: baseline;=
 text-wrap-mode: wrap;">=D9=86=D8=B2=D9=8A=D9=81 =D9=85=D9=87=D8=A8=D9=84=
=D9=8A =D9=8A=D8=B4=D8=A8=D9=87 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=A9 =D8=A3=D9=88 =D8=A3=D9=83=D8=AB=D8=B1 =
=D8=BA=D8=B2=D8=A7=D8=B1=D8=A9.</span><span style=3D"font-size: 11.5pt; bac=
kground-color: transparent; font-variant-numeric: normal; font-variant-east=
-asian: normal; font-variant-alternates: normal; font-variant-position: nor=
mal; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: =
wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-style-type=
: disc; font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 8=
0, 87); background-color: transparent; font-weight: 700; font-variant-numer=
ic: normal; font-variant-east-asian: normal; font-variant-alternates: norma=
l; font-variant-position: normal; font-variant-emoji: normal; vertical-alig=
n: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"presentation" style=
=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-bottom: 0=
pt;"><span style=3D"font-size: 11.5pt; background-color: transparent; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; text-wrap-mode: wrap;">=D8=AA=D8=B4=D9=86=D8=AC=
=D8=A7=D8=AA =D9=88=D8=A2=D9=84=D8=A7=D9=85 =D9=81=D9=8A =D8=A3=D8=B3=D9=81=
=D9=84 =D8=A7=D9=84=D8=A8=D8=B7=D9=86.</span><span style=3D"font-size: 11.5=
pt; background-color: transparent; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; text-wrap=
-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-sty=
le-type: disc; font-size: 11.5pt; font-family: Arial, sans-serif; color: rg=
b(73, 80, 87); background-color: transparent; font-weight: 700; font-varian=
t-numeric: normal; font-variant-east-asian: normal; font-variant-alternates=
: normal; font-variant-position: normal; font-variant-emoji: normal; vertic=
al-align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"presentation"=
 style=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-bot=
tom: 0pt;"><span style=3D"font-size: 11.5pt; background-color: transparent;=
 font-variant-numeric: normal; font-variant-east-asian: normal; font-varian=
t-alternates: normal; font-variant-position: normal; font-variant-emoji: no=
rmal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=BA=D8=AB=D9=8A=
=D8=A7=D9=86 =D8=A3=D9=88 =D9=82=D9=8A=D8=A1.</span><span style=3D"font-siz=
e: 11.5pt; background-color: transparent; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; te=
xt-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"l=
ist-style-type: disc; font-size: 11.5pt; font-family: Arial, sans-serif; co=
lor: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font=
-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alt=
ernates: normal; font-variant-position: normal; font-variant-emoji: normal;=
 vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"presen=
tation" style=3D"line-height: 1.38; text-align: right; margin-top: 0pt; mar=
gin-bottom: 12pt;"><span style=3D"font-size: 11.5pt; background-color: tran=
sparent; font-variant-numeric: normal; font-variant-east-asian: normal; fon=
t-variant-alternates: normal; font-variant-position: normal; font-variant-e=
moji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=A5=D8=B3=
=D9=87=D8=A7=D9=84 =D8=AE=D9=81=D9=8A=D9=81.</span><span style=3D"font-size=
: 11.5pt; background-color: transparent; font-variant-numeric: normal; font=
-variant-east-asian: normal; font-variant-alternates: normal; font-variant-=
position: normal; font-variant-emoji: normal; vertical-align: baseline; tex=
t-wrap-mode: wrap;"><br /><br /></span></p></li></ul><p dir=3D"rtl" style=
=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><span style=
=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 8=
7); background-color: transparent; font-weight: 700; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;">=D8=A5=D8=B0=D8=A7 =D8=A7=D8=B3=
=D8=AA=D9=85=D8=B1 =D8=A7=D9=84=D9=86=D8=B2=D9=8A=D9=81 =D8=A7=D9=84=D8=B4=
=D8=AF=D9=8A=D8=AF =D8=A3=D9=88 =D8=B8=D9=87=D8=B1=D8=AA =D8=A3=D8=B9=D8=B1=
=D8=A7=D8=B6 =D9=85=D8=AB=D9=84 =D8=A7=D9=84=D8=AF=D9=88=D8=AE=D8=A9 =D8=A7=
=D9=84=D8=AD=D8=A7=D8=AF=D8=A9=D8=8C =D9=8A=D8=AC=D8=A8 =D8=A7=D9=84=D8=AA=
=D9=88=D8=AC=D9=87 =D9=81=D9=88=D8=B1=D9=8B=D8=A7 =D9=84=D9=84=D8=B7=D9=88=
=D8=A7=D8=B1=D8=A6.</span></p><p dir=3D"rtl" style=3D"line-height: 1.38; ma=
rgin-top: 0pt; margin-bottom: 0pt;"></p><hr /><p></p><span dir=3D"rtl" styl=
e=3D"line-height: 1.44; margin-top: 0pt; margin-bottom: 2pt;"><span style=
=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87)=
; background-color: transparent; font-weight: 700; font-variant-numeric: no=
rmal; font-variant-east-asian: normal; font-variant-alternates: normal; fon=
t-variant-position: normal; font-variant-emoji: normal; vertical-align: bas=
eline; white-space-collapse: preserve;">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=
=88=D8=AF=D9=8A=D9=87 =D9=88=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=
=88=D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA</span></span><p dir=3D"rtl" style=
=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><span style=
=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 8=
7); background-color: transparent; font-weight: 700; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;">=D8=AA=D9=86=D8=AA=D8=B4=D8=B1 =
=D8=A7=D9=84=D8=AD=D8=A7=D8=AC=D8=A9 =D8=A5=D9=84=D9=89 </span><a href=3D"h=
ttps://ksacytotec.com/"><span style=3D"font-size: 11.5pt; font-family: Aria=
l, sans-serif; color: rgb(255, 152, 0); background-color: transparent; font=
-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal=
; font-variant-alternates: normal; font-variant-position: normal; font-vari=
ant-emoji: normal; vertical-align: baseline; white-space-collapse: preserve=
;">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:=
 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); background=
-color: transparent; font-weight: 700; font-variant-numeric: normal; font-v=
ariant-east-asian: normal; font-variant-alternates: normal; font-variant-po=
sition: normal; font-variant-emoji: normal; vertical-align: baseline; white=
-space-collapse: preserve;"> =D9=81=D9=8A =D8=A7=D9=84=D8=B9=D8=AF=D9=8A=D8=
=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=AF=D9=86:</span></p><ul style=3D"mar=
gin-top: 0px; margin-bottom: 0px; padding-inline-start: 48px;"><li dir=3D"r=
tl" style=3D"list-style-type: disc; font-size: 11.5pt; font-family: Arial, =
sans-serif; color: rgb(73, 80, 87); background-color: transparent; font-wei=
ght: 700; font-variant-numeric: normal; font-variant-east-asian: normal; fo=
nt-variant-alternates: normal; font-variant-position: normal; font-variant-=
emoji: normal; vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" =
role=3D"presentation" style=3D"line-height: 1.38; text-align: right; margin=
-top: 0pt; margin-bottom: 0pt;"><span style=3D"font-size: 11.5pt; backgroun=
d-color: transparent; font-variant-numeric: normal; font-variant-east-asian=
: normal; font-variant-alternates: normal; font-variant-position: normal; f=
ont-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;"=
>=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6: =D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=
=85=D8=B9 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=
=8A=D9=86 =D9=84=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=
=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A.</span><sp=
an style=3D"font-size: 11.5pt; background-color: transparent; font-variant-=
numeric: normal; font-variant-east-asian: normal; font-variant-alternates: =
normal; font-variant-position: normal; font-variant-emoji: normal; vertical=
-align: baseline; text-wrap-mode: wrap;"><br /><br /></span></p></li><li di=
r=3D"rtl" style=3D"list-style-type: disc; font-size: 11.5pt; font-family: A=
rial, sans-serif; color: rgb(73, 80, 87); background-color: transparent; fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space: pre;"><p dir=3D=
"rtl" role=3D"presentation" style=3D"line-height: 1.38; text-align: right; =
margin-top: 0pt; margin-bottom: 0pt;"><span style=3D"font-size: 11.5pt; bac=
kground-color: transparent; font-variant-numeric: normal; font-variant-east=
-asian: normal; font-variant-alternates: normal; font-variant-position: nor=
mal; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: =
wrap;">=D8=AC=D8=AF=D8=A9: =D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=B7=D8=A8=D9=
=8A=D8=A9 =D8=A8=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=85=D8=
=B9 =D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9.</span><span style=3D"font-size: 1=
1.5pt; background-color: transparent; font-variant-numeric: normal; font-va=
riant-east-asian: normal; font-variant-alternates: normal; font-variant-pos=
ition: normal; font-variant-emoji: normal; vertical-align: baseline; text-w=
rap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-=
style-type: disc; font-size: 11.5pt; font-family: Arial, sans-serif; color:=
 rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-var=
iant-numeric: normal; font-variant-east-asian: normal; font-variant-alterna=
tes: normal; font-variant-position: normal; font-variant-emoji: normal; ver=
tical-align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"presentati=
on" style=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-=
bottom: 0pt;"><span style=3D"font-size: 11.5pt; background-color: transpare=
nt; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; text-wrap-mode: wrap;">=D9=85=D9=83=D8=
=A9: =D8=AF=D8=B9=D9=85 =D8=B7=D8=A8=D9=8A =D8=A2=D9=85=D9=86 =D9=84=D9=84=
=D9=86=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=AA=D9=8A =D9=8A=
=D8=AD=D8=AA=D8=AC=D9=86 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=
=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1.</span><span style=
=3D"font-size: 11.5pt; background-color: transparent; font-variant-numeric:=
 normal; font-variant-east-asian: normal; font-variant-alternates: normal; =
font-variant-position: normal; font-variant-emoji: normal; vertical-align: =
baseline; text-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl=
" style=3D"list-style-type: disc; font-size: 11.5pt; font-family: Arial, sa=
ns-serif; color: rgb(73, 80, 87); background-color: transparent; font-weigh=
t: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" ro=
le=3D"presentation" style=3D"line-height: 1.38; text-align: right; margin-t=
op: 0pt; margin-bottom: 0pt;"><span style=3D"font-size: 11.5pt; background-=
color: transparent; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=
=D8=AC=D8=A7=D8=B2=D8=A7=D9=86: =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81 =D8=A3=D9=88=
 =D8=A7=D9=84=D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8.</span><span style=3D"fon=
t-size: 11.5pt; background-color: transparent; font-variant-numeric: normal=
; font-variant-east-asian: normal; font-variant-alternates: normal; font-va=
riant-position: normal; font-variant-emoji: normal; vertical-align: baselin=
e; text-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=
=3D"list-style-type: disc; font-size: 11.5pt; font-family: Arial, sans-seri=
f; color: rgb(73, 80, 87); background-color: transparent; font-weight: 700;=
 font-variant-numeric: normal; font-variant-east-asian: normal; font-varian=
t-alternates: normal; font-variant-position: normal; font-variant-emoji: no=
rmal; vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"p=
resentation" style=3D"line-height: 1.38; text-align: right; margin-top: 0pt=
; margin-bottom: 0pt;"><span style=3D"font-size: 11.5pt; background-color: =
transparent; font-variant-numeric: normal; font-variant-east-asian: normal;=
 font-variant-alternates: normal; font-variant-position: normal; font-varia=
nt-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=AE=
=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7: =D8=AA=D9=88=D9=81=D9=8A=D8=B1=
 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A =
=D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D9=85=D8=AA=D8=AE=D8=B5=
=D8=B5.</span><span style=3D"font-size: 11.5pt; background-color: transpare=
nt; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; text-wrap-mode: wrap;"><br /><br /></spa=
n></p></li><li dir=3D"rtl" style=3D"list-style-type: disc; font-size: 11.5p=
t; font-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color=
: transparent; font-weight: 700; font-variant-numeric: normal; font-variant=
-east-asian: normal; font-variant-alternates: normal; font-variant-position=
: normal; font-variant-emoji: normal; vertical-align: baseline; white-space=
: pre;"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height: 1.38; te=
xt-align: right; margin-top: 0pt; margin-bottom: 12pt;"><span style=3D"font=
-size: 11.5pt; background-color: transparent; font-variant-numeric: normal;=
 font-variant-east-asian: normal; font-variant-alternates: normal; font-var=
iant-position: normal; font-variant-emoji: normal; vertical-align: baseline=
; text-wrap-mode: wrap;">=D8=A7=D9=84=D8=B4=D8=A7=D8=B1=D9=82=D8=A9 =D9=88=
=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=83=D9=88=
=D9=8A=D8=AA: =D8=A5=D9=85=D9=83=D8=A7=D9=86=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=
=D9=88=D8=A7=D8=B5=D9=84 =D9=84=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=
=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=
=D9=82.</span><span style=3D"font-size: 11.5pt; background-color: transpare=
nt; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; text-wrap-mode: wrap;"><br /><br /></spa=
n></p></li></ul><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt;=
 margin-bottom: 12pt;"><span style=3D"font-size: 11.5pt; font-family: Arial=
, sans-serif; color: rgb(73, 80, 87); background-color: transparent; font-w=
eight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; =
font-variant-alternates: normal; font-variant-position: normal; font-varian=
t-emoji: normal; vertical-align: baseline; white-space-collapse: preserve;"=
>=F0=9F=93=9E =D8=B1=D9=82=D9=85 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=
=86=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=
=A7=D8=B1: </span><span style=3D"font-size: 12pt; font-family: Arial, sans-=
serif; color: rgb(51, 51, 51); font-weight: 700; font-variant-numeric: norm=
al; font-variant-east-asian: normal; font-variant-alternates: normal; font-=
variant-position: normal; font-variant-emoji: normal; vertical-align: basel=
ine; white-space-collapse: preserve;">00966538159747=C2=A0</span></p><br />=
<span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-botto=
m: 2pt;"><span style=3D"font-size: 10pt; font-family: Arial, sans-serif; co=
lor: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font=
-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alt=
ernates: normal; font-variant-position: normal; font-variant-emoji: normal;=
 vertical-align: baseline; white-space-collapse: preserve;">=D9=84=D9=85=D8=
=A7=D8=B0=D8=A7 =D8=AA=D8=AE=D8=AA=D8=A7=D8=B1=D9=8A=D9=86 =D8=AF=D9=83=D8=
=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=9F</span></sp=
an><br /><ul style=3D"margin-top: 0px; margin-bottom: 0px; padding-inline-s=
tart: 48px;"><li dir=3D"rtl" style=3D"list-style-type: disc; font-size: 11.=
5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); background-col=
or: transparent; font-weight: 700; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; white-spa=
ce: pre;"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height: 1.38; =
text-align: right; margin-top: 0pt; margin-bottom: 0pt;"><span style=3D"fon=
t-size: 11.5pt; background-color: transparent; font-variant-numeric: normal=
; font-variant-east-asian: normal; font-variant-alternates: normal; font-va=
riant-position: normal; font-variant-emoji: normal; vertical-align: baselin=
e; text-wrap-mode: wrap;">=D8=AE=D8=A8=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9=
 =D9=81=D9=8A =D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=D9=86=D8=B3=D8=A7=D8=A1=
 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D9=84=D9=8A=D8=AF.</span><span style=3D"fon=
t-size: 11.5pt; background-color: transparent; font-variant-numeric: normal=
; font-variant-east-asian: normal; font-variant-alternates: normal; font-va=
riant-position: normal; font-variant-emoji: normal; vertical-align: baselin=
e; text-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=
=3D"list-style-type: disc; font-size: 11.5pt; font-family: Arial, sans-seri=
f; color: rgb(73, 80, 87); background-color: transparent; font-weight: 700;=
 font-variant-numeric: normal; font-variant-east-asian: normal; font-varian=
t-alternates: normal; font-variant-position: normal; font-variant-emoji: no=
rmal; vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"p=
resentation" style=3D"line-height: 1.38; text-align: right; margin-top: 0pt=
; margin-bottom: 0pt;"><span style=3D"font-size: 11.5pt; background-color: =
transparent; font-variant-numeric: normal; font-variant-east-asian: normal;=
 font-variant-alternates: normal; font-variant-position: normal; font-varia=
nt-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=AA=
=D9=88=D9=81=D9=8A=D8=B1 =D8=AF=D9=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A.</span><span style=
=3D"font-size: 11.5pt; background-color: transparent; font-variant-numeric:=
 normal; font-variant-east-asian: normal; font-variant-alternates: normal; =
font-variant-position: normal; font-variant-emoji: normal; vertical-align: =
baseline; text-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl=
" style=3D"list-style-type: disc; font-size: 11.5pt; font-family: Arial, sa=
ns-serif; color: rgb(73, 80, 87); background-color: transparent; font-weigh=
t: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" ro=
le=3D"presentation" style=3D"line-height: 1.38; text-align: right; margin-t=
op: 0pt; margin-bottom: 0pt;"><span style=3D"font-size: 11.5pt; background-=
color: transparent; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=
=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=B4=D8=AE=D8=B5=D9=8A=D8=A9 =D9=84=
=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D8=A8=D8=AF=D8=A7=
=D9=8A=D8=A9 =D8=AD=D8=AA=D9=89 =D8=A7=D9=84=D9=86=D9=87=D8=A7=D9=8A=D8=A9.=
</span><span style=3D"font-size: 11.5pt; background-color: transparent; fon=
t-variant-numeric: normal; font-variant-east-asian: normal; font-variant-al=
ternates: normal; font-variant-position: normal; font-variant-emoji: normal=
; vertical-align: baseline; text-wrap-mode: wrap;"><br /><br /></span></p><=
/li><li dir=3D"rtl" style=3D"list-style-type: disc; font-size: 11.5pt; font=
-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color: trans=
parent; font-weight: 700; font-variant-numeric: normal; font-variant-east-a=
sian: normal; font-variant-alternates: normal; font-variant-position: norma=
l; font-variant-emoji: normal; vertical-align: baseline; white-space: pre;"=
><p dir=3D"rtl" role=3D"presentation" style=3D"line-height: 1.38; text-alig=
n: right; margin-top: 0pt; margin-bottom: 12pt;"><span style=3D"font-size: =
11.5pt; background-color: transparent; font-variant-numeric: normal; font-v=
ariant-east-asian: normal; font-variant-alternates: normal; font-variant-po=
sition: normal; font-variant-emoji: normal; vertical-align: baseline; text-=
wrap-mode: wrap;">=D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=A9 =D9=88=D8=B3=D8=B1=
=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B9=
=D8=A7=D9=85=D9=84.</span><span style=3D"font-size: 11.5pt; background-colo=
r: transparent; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;"><br /=
><br /></span></p></li></ul><span dir=3D"rtl" style=3D"line-height: 1.44; m=
argin-top: 0pt; margin-bottom: 4pt;"><span style=3D"font-size: 17pt; font-f=
amily: Arial, sans-serif; color: rgb(73, 80, 87); background-color: transpa=
rent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asi=
an: normal; font-variant-alternates: normal; font-variant-position: normal;=
 font-variant-emoji: normal; vertical-align: baseline; white-space-collapse=
: preserve;">=D8=A8=D8=AF=D8=A7=D8=A6=D9=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></span><p dir=3D"rtl" style=3D"l=
ine-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><span style=3D"fon=
t-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); bac=
kground-color: transparent; font-weight: 700; font-variant-numeric: normal;=
 font-variant-east-asian: normal; font-variant-alternates: normal; font-var=
iant-position: normal; font-variant-emoji: normal; vertical-align: baseline=
; white-space-collapse: preserve;">=D9=81=D9=8A =D8=A8=D8=B9=D8=B6 =D8=A7=
=D9=84=D8=AD=D8=A7=D9=84=D8=A7=D8=AA=D8=8C =D9=82=D8=AF =D9=8A=D9=82=D8=AA=
=D8=B1=D8=AD =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D8=A8=D8=AF=D8=A7=D8=A6=
=D9=84 =D8=A3=D8=AE=D8=B1=D9=89:</span></p><ul style=3D"margin-top: 0px; ma=
rgin-bottom: 0px; padding-inline-start: 48px;"><li dir=3D"rtl" style=3D"lis=
t-style-type: disc; font-size: 11.5pt; font-family: Arial, sans-serif; colo=
r: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-v=
ariant-numeric: normal; font-variant-east-asian: normal; font-variant-alter=
nates: normal; font-variant-position: normal; font-variant-emoji: normal; v=
ertical-align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"presenta=
tion" style=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margi=
n-bottom: 0pt;"><span style=3D"font-size: 11.5pt; background-color: transpa=
rent; font-variant-numeric: normal; font-variant-east-asian: normal; font-v=
ariant-alternates: normal; font-variant-position: normal; font-variant-emoj=
i: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=A7=D9=84=D8=
=AA=D9=88=D8=B3=D9=8A=D8=B9 =D9=88=D8=A7=D9=84=D9=83=D8=AD=D8=AA =D8=A7=D9=
=84=D8=AC=D8=B1=D8=A7=D8=AD=D9=8A (D&amp;C).</span><span style=3D"font-size=
: 11.5pt; background-color: transparent; font-variant-numeric: normal; font=
-variant-east-asian: normal; font-variant-alternates: normal; font-variant-=
position: normal; font-variant-emoji: normal; vertical-align: baseline; tex=
t-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"li=
st-style-type: disc; font-size: 11.5pt; font-family: Arial, sans-serif; col=
or: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" role=3D"present=
ation" style=3D"line-height: 1.38; text-align: right; margin-top: 0pt; marg=
in-bottom: 0pt;"><span style=3D"font-size: 11.5pt; background-color: transp=
arent; font-variant-numeric: normal; font-variant-east-asian: normal; font-=
variant-alternates: normal; font-variant-position: normal; font-variant-emo=
ji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=A3=D8=AF=
=D9=88=D9=8A=D8=A9 =D8=AA=D8=AD=D8=AA=D9=88=D9=8A =D8=B9=D9=84=D9=89 =D9=85=
=D9=8A=D9=81=D9=8A=D8=A8=D8=B1=D9=8A=D8=B3=D8=AA=D9=88=D9=86 =D9=85=D8=B9 =
=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84.</span><=
span style=3D"font-size: 11.5pt; background-color: transparent; font-varian=
t-numeric: normal; font-variant-east-asian: normal; font-variant-alternates=
: normal; font-variant-position: normal; font-variant-emoji: normal; vertic=
al-align: baseline; text-wrap-mode: wrap;"><br /><br /></span></p></li><li =
dir=3D"rtl" style=3D"list-style-type: disc; font-size: 11.5pt; font-family:=
 Arial, sans-serif; color: rgb(73, 80, 87); background-color: transparent; =
font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: no=
rmal; font-variant-alternates: normal; font-variant-position: normal; font-=
variant-emoji: normal; vertical-align: baseline; white-space: pre;"><p dir=
=3D"rtl" role=3D"presentation" style=3D"line-height: 1.38; text-align: righ=
t; margin-top: 0pt; margin-bottom: 12pt;"><span style=3D"font-size: 11.5pt;=
 background-color: transparent; font-variant-numeric: normal; font-variant-=
east-asian: normal; font-variant-alternates: normal; font-variant-position:=
 normal; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mo=
de: wrap;">=D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AC=D8=
=B1=D8=A7=D8=AD=D9=8A =D8=A7=D9=84=D9=85=D8=A8=D8=A7=D8=B4=D8=B1.</span></p=
></li></ul><span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; m=
argin-bottom: 4pt;"><span style=3D"font-size: 17pt; font-family: Arial, san=
s-serif; color: rgb(73, 80, 87); background-color: transparent; font-weight=
: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-=
variant-alternates: normal; font-variant-position: normal; font-variant-emo=
ji: normal; vertical-align: baseline; white-space-collapse: preserve;">=D8=
=A3=D8=B3=D8=A6=D9=84=D8=A9 =D8=B4=D8=A7=D8=A6=D8=B9=D8=A9</span></span><p =
dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12p=
t;"><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color=
: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-va=
riant-numeric: normal; font-variant-east-asian: normal; font-variant-altern=
ates: normal; font-variant-position: normal; font-variant-emoji: normal; ve=
rtical-align: baseline; white-space-collapse: preserve;">1. =D9=87=D9=84 =
=D9=8A=D9=85=D9=83=D9=86 =D8=B4=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D8=A8=D8=AF=D9=88=D9=86 =D9=88=D8=B5=D9=81=D8=A9 =D9=81=
=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=9F</span><span s=
tyle=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 8=
0, 87); background-color: transparent; font-weight: 700; font-variant-numer=
ic: normal; font-variant-east-asian: normal; font-variant-alternates: norma=
l; font-variant-position: normal; font-variant-emoji: normal; vertical-alig=
n: baseline; white-space-collapse: preserve;"><br /></span><span style=3D"f=
ont-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); b=
ackground-color: transparent; font-weight: 700; font-variant-numeric: norma=
l; font-variant-east-asian: normal; font-variant-alternates: normal; font-v=
ariant-position: normal; font-variant-emoji: normal; vertical-align: baseli=
ne; white-space-collapse: preserve;">=D8=BA=D8=A7=D9=84=D8=A8=D9=8B=D8=A7 =
=D9=84=D8=A7=D8=8C =D9=88=D9=8A=D8=AC=D8=A8 =D8=A7=D9=84=D8=AD=D8=B5=D9=88=
=D9=84 =D8=B9=D9=84=D9=8A=D9=87 =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=
=85=D9=88=D8=AB=D9=88=D9=82 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=
=81 =D8=B7=D8=A8=D9=8A.</span></p><p dir=3D"rtl" style=3D"line-height: 1.38=
; margin-top: 0pt; margin-bottom: 12pt;"><span style=3D"font-size: 11.5pt; =
font-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color: t=
ransparent; font-weight: 700; font-variant-numeric: normal; font-variant-ea=
st-asian: normal; font-variant-alternates: normal; font-variant-position: n=
ormal; font-variant-emoji: normal; vertical-align: baseline; white-space-co=
llapse: preserve;">2. =D9=83=D9=85 =D8=AA=D8=B3=D8=AA=D8=BA=D8=B1=D9=82 =D8=
=B9=D9=85=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=
=A8=D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8=D8=9F</span><span style=3D"font-siz=
e: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); backgrou=
nd-color: transparent; font-weight: 700; font-variant-numeric: normal; font=
-variant-east-asian: normal; font-variant-alternates: normal; font-variant-=
position: normal; font-variant-emoji: normal; vertical-align: baseline; whi=
te-space-collapse: preserve;"><br /></span><span style=3D"font-size: 11.5pt=
; font-family: Arial, sans-serif; color: rgb(73, 80, 87); background-color:=
 transparent; font-weight: 700; font-variant-numeric: normal; font-variant-=
east-asian: normal; font-variant-alternates: normal; font-variant-position:=
 normal; font-variant-emoji: normal; vertical-align: baseline; white-space-=
collapse: preserve;">=D8=B9=D8=A7=D8=AF=D8=A9 =D9=85=D9=86 24 =D8=A5=D9=84=
=D9=89 48 =D8=B3=D8=A7=D8=B9=D8=A9 =D8=AD=D8=AA=D9=89 =D9=8A=D9=83=D8=AA=D9=
=85=D9=84 =D8=A7=D9=84=D9=86=D8=B2=D9=8A=D9=81 =D9=88=D8=A5=D8=AE=D8=B1=D8=
=A7=D8=AC =D8=A7=D9=84=D8=AD=D9=85=D9=84.</span></p><p dir=3D"rtl" style=3D=
"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><span style=3D"f=
ont-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); b=
ackground-color: transparent; font-weight: 700; font-variant-numeric: norma=
l; font-variant-east-asian: normal; font-variant-alternates: normal; font-v=
ariant-position: normal; font-variant-emoji: normal; vertical-align: baseli=
ne; white-space-collapse: preserve;">3. =D9=87=D9=84 =D9=8A=D8=B3=D8=A8=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B9=D9=82=D9=
=85=D8=9F</span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-=
serif; color: rgb(73, 80, 87); background-color: transparent; font-weight: =
700; font-variant-numeric: normal; font-variant-east-asian: normal; font-va=
riant-alternates: normal; font-variant-position: normal; font-variant-emoji=
: normal; vertical-align: baseline; white-space-collapse: preserve;"><br />=
</span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; co=
lor: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font=
-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alt=
ernates: normal; font-variant-position: normal; font-variant-emoji: normal;=
 vertical-align: baseline; white-space-collapse: preserve;">=D9=84=D8=A7=D8=
=8C =D8=A5=D8=B0=D8=A7 =D8=AA=D9=85 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=
=85=D9=87 =D8=A8=D8=B4=D9=83=D9=84 =D8=B5=D8=AD=D9=8A=D8=AD=D8=8C =D9=84=D8=
=A7 =D9=8A=D8=A4=D8=AB=D8=B1 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=82=D8=AF=D8=
=B1=D8=A9 =D8=A7=D9=84=D8=A5=D9=86=D8=AC=D8=A7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=
=84=D9=85=D8=B3=D8=AA=D9=82=D8=A8=D9=84=D9=8A=D8=A9.</span></p><br /><span =
dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-bottom: 4pt=
;"><span style=3D"font-size: 17pt; font-family: Arial, sans-serif; color: r=
gb(73, 80, 87); background-color: transparent; font-weight: 700; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;">=D8=AE=D8=A7=D8=AA=D9=
=85=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height: 1.38; margin-to=
p: 0pt; margin-bottom: 12pt;"><span style=3D"font-size: 11.5pt; font-family=
: Arial, sans-serif; color: rgb(73, 80, 87); background-color: transparent;=
 font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: n=
ormal; font-variant-alternates: normal; font-variant-position: normal; font=
-variant-emoji: normal; vertical-align: baseline; white-space-collapse: pre=
serve;">=D8=A5=D9=86 =D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=
=87=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=
=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 =D8=AA=D9=85=D8=AB=D9=84 =D8=
=AD=D9=84=D9=8B=D8=A7 =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=81=D9=8A =D8=AD=D8=
=A7=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9=D8=8C =D9=84=D9=83=D9=86 =D8=
=A7=D9=84=D8=A3=D9=85=D8=A7=D9=86 =D9=8A=D9=83=D9=85=D9=86 =D9=81=D9=8A =D8=
=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D9=85=D8=AE=D8=AA=D8=B5=D9=8A=D9=
=86 =D9=85=D8=AB=D9=84 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=
=B1=D9=85=D9=8A=D9=86 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D9=88=D9=81=D8=B1 =D8=
=A7=D9=84=D8=AF=D8=B9=D9=85 =D9=88=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=
=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D8=B6=D9=85=D9=88=D9=86=D8=8C =D9=
=85=D8=B9 =D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=AF=D9=82=D9=8A=D9=82=D8=
=A9 =D9=88=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9.</span><span st=
yle=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80=
, 87); background-color: transparent; font-weight: 700; font-variant-numeri=
c: normal; font-variant-east-asian: normal; font-variant-alternates: normal=
; font-variant-position: normal; font-variant-emoji: normal; vertical-align=
: baseline; white-space-collapse: preserve;"><br /></span><span style=3D"fo=
nt-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80, 87); ba=
ckground-color: transparent; font-weight: 700; font-variant-numeric: normal=
; font-variant-east-asian: normal; font-variant-alternates: normal; font-va=
riant-position: normal; font-variant-emoji: normal; vertical-align: baselin=
e; white-space-collapse: preserve;">=D9=84=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=
=B3=D8=A7=D8=B1=D8=A7=D8=AA =D8=A3=D9=88 =D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=
=B9=D9=84=D8=A7=D8=AC=D8=8C =D8=A7=D8=AA=D8=B5=D9=84=D9=8A =D8=A7=D9=84=D8=
=A2=D9=86 =D8=B9=D9=84=D9=89: </span><span style=3D"font-size: 12pt; font-f=
amily: Arial, sans-serif; color: rgb(51, 51, 51); font-weight: 700; font-va=
riant-numeric: normal; font-variant-east-asian: normal; font-variant-altern=
ates: normal; font-variant-position: normal; font-variant-emoji: normal; ve=
rtical-align: baseline; white-space-collapse: preserve;">00966538159747 </s=
pan><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color=
: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font-va=
riant-numeric: normal; font-variant-east-asian: normal; font-variant-altern=
ates: normal; font-variant-position: normal; font-variant-emoji: normal; ve=
rtical-align: baseline; white-space-collapse: preserve;">.</span></p><br />=
<span dir=3D"rtl" style=3D"line-height: 1.44; margin-top: 0pt; margin-botto=
m: 4pt;"><span style=3D"font-size: 17pt; font-family: Arial, sans-serif; co=
lor: rgb(73, 80, 87); background-color: transparent; font-weight: 700; font=
-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alt=
ernates: normal; font-variant-position: normal; font-variant-emoji: normal;=
 vertical-align: baseline; white-space-collapse: preserve;">=D8=AA=D8=AD=D8=
=B0=D9=8A=D8=B1=D8=A7=D8=AA =D9=85=D9=87=D9=85=D8=A9</span></span><p dir=3D=
"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"><s=
pan style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(=
73, 80, 87); background-color: transparent; font-weight: 700; font-variant-=
numeric: normal; font-variant-east-asian: normal; font-variant-alternates: =
normal; font-variant-position: normal; font-variant-emoji: normal; vertical=
-align: baseline; white-space-collapse: preserve;">=D9=8A=D9=85=D9=86=D8=B9=
 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=
=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=
=D9=85 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 12 =D8=
=A5=D9=84=D8=A7 =D8=A8=D8=A3=D9=85=D8=B1 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=
=A8.</span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif=
; color: rgb(73, 80, 87); background-color: transparent; font-weight: 700; =
font-variant-numeric: normal; font-variant-east-asian: normal; font-variant=
-alternates: normal; font-variant-position: normal; font-variant-emoji: nor=
mal; vertical-align: baseline; white-space-collapse: preserve;"><br /><br /=
></span></p><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; mar=
gin-bottom: 12pt;"><span style=3D"font-size: 11.5pt; font-family: Arial, sa=
ns-serif; color: rgb(73, 80, 87); background-color: transparent; font-weigh=
t: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; white-space-collapse: preserve;">=D9=
=84=D8=A7 =D8=AA=D8=B3=D8=AA=D8=AE=D8=AF=D9=85=D9=8A =D8=A7=D9=84=D8=AD=D8=
=A8=D9=88=D8=A8 =D8=A5=D8=B0=D8=A7 =D9=83=D8=A7=D9=86 =D9=84=D8=AF=D9=8A=D9=
=83 =D8=AD=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=
=A7=D8=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9.</span><span sty=
le=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(73, 80,=
 87); background-color: transparent; font-weight: 700; font-variant-numeric=
: normal; font-variant-east-asian: normal; font-variant-alternates: normal;=
 font-variant-position: normal; font-variant-emoji: normal; vertical-align:=
 baseline; white-space-collapse: preserve;"><br /><br /></span></p><p dir=
=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 12pt;"=
><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: r=
gb(73, 80, 87); background-color: transparent; font-weight: 700; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;">=D9=84=D8=A7 =D8=AA=
=D8=AA=D9=86=D8=A7=D9=88=D9=84=D9=8A =D8=A3=D9=8A =D8=AC=D8=B1=D8=B9=D8=A9 =
=D8=A5=D8=B6=D8=A7=D9=81=D9=8A=D8=A9 =D8=A8=D8=AF=D9=88=D9=86 =D8=A7=D8=B3=
=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9.</span></p><br /><b=
r /><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bott=
om: 0pt;"><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif;=
 color: rgb(29, 33, 37); background-color: rgb(206, 212, 218); font-weight:=
 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-v=
ariant-alternates: normal; font-variant-position: normal; font-variant-emoj=
i: normal; vertical-align: baseline; white-space-collapse: preserve;">=C2=
=A0=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=
=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9</span><span style=3D"font-size: 11.5pt; f=
ont-family: Arial, sans-serif; color: rgb(29, 33, 37); background-color: tr=
ansparent; font-variant-numeric: normal; font-variant-east-asian: normal; f=
ont-variant-alternates: normal; font-variant-position: normal; font-variant=
-emoji: normal; vertical-align: baseline; white-space-collapse: preserve;">=
 </span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; c=
olor: rgb(29, 33, 37); background-color: rgb(206, 212, 218); font-weight: 7=
00; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; white-space-collapse: preserve;">=C3=97 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=A7=D9=84=D8=B1=D9=8A=
=D8=A7=D8=B6</span><span style=3D"font-size: 11.5pt; font-family: Arial, sa=
ns-serif; color: rgb(29, 33, 37); background-color: transparent; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;"> </span><span style=
=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(29, 33, 3=
7); background-color: rgb(206, 212, 218); font-weight: 700; font-variant-nu=
meric: normal; font-variant-east-asian: normal; font-variant-alternates: no=
rmal; font-variant-position: normal; font-variant-emoji: normal; vertical-a=
lign: baseline; white-space-collapse: preserve;">=C3=97 =D8=B3=D8=A7=D9=8A=
=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85</span><span s=
tyle=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(29, 3=
3, 37); background-color: transparent; font-variant-numeric: normal; font-v=
ariant-east-asian: normal; font-variant-alternates: normal; font-variant-po=
sition: normal; font-variant-emoji: normal; vertical-align: baseline; white=
-space-collapse: preserve;"> </span><span style=3D"font-size: 11.5pt; font-=
family: Arial, sans-serif; color: rgb(29, 33, 37); background-color: rgb(20=
6, 212, 218); font-weight: 700; font-variant-numeric: normal; font-variant-=
east-asian: normal; font-variant-alternates: normal; font-variant-position:=
 normal; font-variant-emoji: normal; vertical-align: baseline; white-space-=
collapse: preserve;">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=
=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7</span><span style=3D"font-si=
ze: 11.5pt; font-family: Arial, sans-serif; color: rgb(29, 33, 37); backgro=
und-color: transparent; font-variant-numeric: normal; font-variant-east-asi=
an: normal; font-variant-alternates: normal; font-variant-position: normal;=
 font-variant-emoji: normal; vertical-align: baseline; white-space-collapse=
: preserve;"> </span><span style=3D"font-size: 11.5pt; font-family: Arial, =
sans-serif; color: rgb(29, 33, 37); background-color: rgb(206, 212, 218); f=
ont-weight: 700; font-variant-numeric: normal; font-variant-east-asian: nor=
mal; font-variant-alternates: normal; font-variant-position: normal; font-v=
ariant-emoji: normal; vertical-align: baseline; white-space-collapse: prese=
rve;">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=
=D9=84=D9=83=D9=88=D9=8A=D8=AA</span><span style=3D"font-size: 11.5pt; font=
-family: Arial, sans-serif; color: rgb(29, 33, 37); background-color: trans=
parent; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; white-space-collapse: preserve;"> </=
span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; colo=
r: rgb(29, 33, 37); background-color: rgb(206, 212, 218); font-weight: 700;=
 font-variant-numeric: normal; font-variant-east-asian: normal; font-varian=
t-alternates: normal; font-variant-position: normal; font-variant-emoji: no=
rmal; vertical-align: baseline; white-space-collapse: preserve;">=C3=97 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=D8=
=AD=D8=B1=D9=8A=D9=86</span><span style=3D"font-size: 11.5pt; font-family: =
Arial, sans-serif; color: rgb(29, 33, 37); background-color: transparent; f=
ont-variant-numeric: normal; font-variant-east-asian: normal; font-variant-=
alternates: normal; font-variant-position: normal; font-variant-emoji: norm=
al; vertical-align: baseline; white-space-collapse: preserve;"> </span><spa=
n style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(29=
, 33, 37); background-color: rgb(206, 212, 218); font-weight: 700; font-var=
iant-numeric: normal; font-variant-east-asian: normal; font-variant-alterna=
tes: normal; font-variant-position: normal; font-variant-emoji: normal; ver=
tical-align: baseline; white-space-collapse: preserve;">=C3=97 =D8=A3=D8=AF=
=D9=88=D9=8A=D8=A9 =D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=
=D9=84</span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-ser=
if; color: rgb(29, 33, 37); background-color: transparent; font-variant-num=
eric: normal; font-variant-east-asian: normal; font-variant-alternates: nor=
mal; font-variant-position: normal; font-variant-emoji: normal; vertical-al=
ign: baseline; white-space-collapse: preserve;"> </span><span style=3D"font=
-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(29, 33, 37); back=
ground-color: rgb(206, 212, 218); font-weight: 700; font-variant-numeric: n=
ormal; font-variant-east-asian: normal; font-variant-alternates: normal; fo=
nt-variant-position: normal; font-variant-emoji: normal; vertical-align: ba=
seline; white-space-collapse: preserve;">=C3=97 =D9=85=D9=8A=D8=B2=D9=88=D8=
=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=84</span><span style=3D"font-size: 11.5pt; f=
ont-family: Arial, sans-serif; color: rgb(29, 33, 37); background-color: tr=
ansparent; font-variant-numeric: normal; font-variant-east-asian: normal; f=
ont-variant-alternates: normal; font-variant-position: normal; font-variant=
-emoji: normal; vertical-align: baseline; white-space-collapse: preserve;">=
 </span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; c=
olor: rgb(29, 33, 37); background-color: rgb(206, 212, 218); font-weight: 7=
00; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; white-space-collapse: preserve;">=C3=97 =
=D8=A3=D8=B9=D8=B1=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84</span><span s=
tyle=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(29, 3=
3, 37); background-color: transparent; font-variant-numeric: normal; font-v=
ariant-east-asian: normal; font-variant-alternates: normal; font-variant-po=
sition: normal; font-variant-emoji: normal; vertical-align: baseline; white=
-space-collapse: preserve;"> </span><span style=3D"font-size: 11.5pt; font-=
family: Arial, sans-serif; color: rgb(29, 33, 37); background-color: rgb(20=
6, 212, 218); font-weight: 700; font-variant-numeric: normal; font-variant-=
east-asian: normal; font-variant-alternates: normal; font-variant-position:=
 normal; font-variant-emoji: normal; vertical-align: baseline; white-space-=
collapse: preserve;">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=
=83 =D9=81=D9=8A =D9=85=D9=83=D8=A9</span><span style=3D"font-size: 11.5pt;=
 font-family: Arial, sans-serif; color: rgb(29, 33, 37); background-color: =
transparent; font-variant-numeric: normal; font-variant-east-asian: normal;=
 font-variant-alternates: normal; font-variant-position: normal; font-varia=
nt-emoji: normal; vertical-align: baseline; white-space-collapse: preserve;=
"> </span><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif;=
 color: rgb(29, 33, 37); background-color: rgb(206, 212, 218); font-weight:=
 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-v=
ariant-alternates: normal; font-variant-position: normal; font-variant-emoj=
i: normal; vertical-align: baseline; white-space-collapse: preserve;">=C3=
=97 =D8=B9=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D8=AC=D9=87=D8=A7=D8=B6</sp=
an><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color:=
 rgb(29, 33, 37); background-color: transparent; font-variant-numeric: norm=
al; font-variant-east-asian: normal; font-variant-alternates: normal; font-=
variant-position: normal; font-variant-emoji: normal; vertical-align: basel=
ine; white-space-collapse: preserve;"> </span><span style=3D"font-size: 11.=
5pt; font-family: Arial, sans-serif; color: rgb(29, 33, 37); background-col=
or: rgb(206, 212, 218); font-weight: 700; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; wh=
ite-space-collapse: preserve;">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =
=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=
=D8=AF=D9=8A=D8=A9</span><span style=3D"font-size: 11.5pt; font-family: Ari=
al, sans-serif; color: rgb(29, 33, 37); background-color: transparent; font=
-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alt=
ernates: normal; font-variant-position: normal; font-variant-emoji: normal;=
 vertical-align: baseline; white-space-collapse: preserve;"> </span><span s=
tyle=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(29, 3=
3, 37); background-color: rgb(206, 212, 218); font-weight: 700; font-varian=
t-numeric: normal; font-variant-east-asian: normal; font-variant-alternates=
: normal; font-variant-position: normal; font-variant-emoji: normal; vertic=
al-align: baseline; white-space-collapse: preserve;">=C3=97 =D8=AF=D9=83=D8=
=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=
=84=D9=83=D9=88=D9=8A=D8=AA</span><span style=3D"font-size: 11.5pt; font-fa=
mily: Arial, sans-serif; color: rgb(29, 33, 37); background-color: transpar=
ent; font-variant-numeric: normal; font-variant-east-asian: normal; font-va=
riant-alternates: normal; font-variant-position: normal; font-variant-emoji=
: normal; vertical-align: baseline; white-space-collapse: preserve;"> </spa=
n><span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: =
rgb(29, 33, 37); background-color: rgb(206, 212, 218); font-weight: 700; fo=
nt-variant-numeric: normal; font-variant-east-asian: normal; font-variant-a=
lternates: normal; font-variant-position: normal; font-variant-emoji: norma=
l; vertical-align: baseline; white-space-collapse: preserve;">=C3=97 =D8=AF=
=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =
=D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86</span><span style=3D"font-size: =
11.5pt; font-family: Arial, sans-serif; color: rgb(29, 33, 37); background-=
color: transparent; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; vertical-align: baseline; white-space-collapse: pr=
eserve;"> </span><span style=3D"font-size: 11.5pt; font-family: Arial, sans=
-serif; color: rgb(29, 33, 37); background-color: rgb(206, 212, 218); font-=
weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal;=
 font-variant-alternates: normal; font-variant-position: normal; font-varia=
nt-emoji: normal; vertical-align: baseline; white-space-collapse: preserve;=
">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=A7=D8=AA</span><sp=
an style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rgb(2=
9, 33, 37); background-color: transparent; font-variant-numeric: normal; fo=
nt-variant-east-asian: normal; font-variant-alternates: normal; font-varian=
t-position: normal; font-variant-emoji: normal; vertical-align: baseline; w=
hite-space-collapse: preserve;"> </span><span style=3D"font-size: 11.5pt; f=
ont-family: Arial, sans-serif; color: rgb(29, 33, 37); background-color: rg=
b(206, 212, 218); font-weight: 700; font-variant-numeric: normal; font-vari=
ant-east-asian: normal; font-variant-alternates: normal; font-variant-posit=
ion: normal; font-variant-emoji: normal; vertical-align: baseline; white-sp=
ace-collapse: preserve;">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9</span>=
<span style=3D"font-size: 11.5pt; font-family: Arial, sans-serif; color: rg=
b(29, 33, 37); background-color: transparent; font-variant-numeric: normal;=
 font-variant-east-asian: normal; font-variant-alternates: normal; font-var=
iant-position: normal; font-variant-emoji: normal; vertical-align: baseline=
; white-space-collapse: preserve;"> </span><span style=3D"font-size: 11.5pt=
; font-family: Arial, sans-serif; color: rgb(29, 33, 37); background-color:=
 rgb(206, 212, 218); font-weight: 700; font-variant-numeric: normal; font-v=
ariant-east-asian: normal; font-variant-alternates: normal; font-variant-po=
sition: normal; font-variant-emoji: normal; vertical-align: baseline; white=
-space-collapse: preserve;">=C3=97 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=
=A7=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=A9</span></p><br /><br /><div class=3D=
"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=8A =D8=A7=D9=
=84=D8=A7=D8=AB=D9=86=D9=8A=D9=86=D8=8C 25 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2=
025 =D9=81=D9=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=
=A9 2:03:39 =D9=85 UTC+3=D8=8C =D9=83=D8=AA=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=AE=D8=B5=D9=85 20% =D8=B1=D8=
=B3=D8=A7=D9=84=D8=A9 =D9=86=D8=B5=D9=87=D8=A7:<br/></div><blockquote class=
=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-right: 1px solid rgb(=
204, 204, 204); padding-right: 1ex;"><br><span dir=3D"rtl" style=3D"line-he=
ight:1.44;margin-top:0pt;margin-bottom:4pt"><span style=3D"font-size:13pt;f=
ont-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparen=
t;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline">=D8=AF=D9=83=D8=
=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 | </span><span style=3D"font-size:1=
2pt;font-family:Arial,sans-serif;color:rgb(51,51,51);font-weight:700;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">00966538159747 </span><span style=3D"font=
-size:13pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-colo=
r:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline">|=D8=
=B9=D9=8A=D8=A7=D8=AF=D8=A9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=C2=
=A0</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;ma=
rgin-bottom:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-se=
rif;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">=C2=A0=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=
=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=
=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9</span><spa=
n style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87=
);background-color:transparent;font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline"><br></span><span style=3D"font-size:11.5pt;font-family:Arial,sa=
ns-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=
=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =E2=80=93 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=
=C2=A0 | =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=
=8A=D9=86 </span><span style=3D"font-size:12pt;font-family:Arial,sans-serif=
;color:rgb(51,51,51);font-weight:700;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
">00966538159747 </span><span style=3D"font-size:11.5pt;font-family:Arial,s=
ans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline">=E2=80=93 =D8=A7=D8=B3=D8=AA=D8=B4=
=D8=A7=D8=B1=D8=A7=D8=AA =D9=88=D8=B9=D9=84=D8=A7=D8=AC =D8=A2=D9=85=D9=86<=
/span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rg=
b(73,80,87);background-color:transparent;font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline"><br></span><span style=3D"font-size:11.5pt;font-famil=
y:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-we=
ight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline">=D8=AA=D8=B9=D8=B1=D9=81=
=D9=8A =D8=B9=D9=84=D9=89 =D9=83=D9=84 =D9=85=D8=A7 =D9=8A=D9=87=D9=85=D9=
=83 =D8=B9=D9=86 =D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=
=A7=D8=B6 =D8=8C </span><a href=3D"https://hayatannas.com/?srsltid=3DAfmBOo=
orXTv6wctbY7oCbd_zRBMxNDPmT0F5DPRwzMifCMgDDNNp1cbV" target=3D"_blank" rel=
=3D"nofollow" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&am=
p;q=3Dhttps://hayatannas.com/?srsltid%3DAfmBOoorXTv6wctbY7oCbd_zRBMxNDPmT0F=
5DPRwzMifCMgDDNNp1cbV&amp;source=3Dgmail&amp;ust=3D1756206440019000&amp;usg=
=3DAOvVaw32hMvd_aLzihSwiggun5lD"><span style=3D"font-size:11.5pt;font-famil=
y:Arial,sans-serif;color:rgb(255,152,0);background-color:transparent;font-w=
eight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=
=D9=87</span></a><span style=3D"font-size:11.5pt;font-family:Arial,sans-ser=
if;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline"> =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=
=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=AC=D8=A7=D8=B2=D8=
=A7=D9=86=D8=8C =D9=88=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7=D8=
=8C =D9=85=D8=B9 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=
=85=D9=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=
=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D9=88=D8=B7=D9=84=D8=A8 =D8=A7=D9=
=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A8=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=
=85=D8=A9.</span></p><span dir=3D"rtl" style=3D"line-height:1.44;margin-top=
:0pt;margin-bottom:4pt"><span style=3D"font-size:17pt;font-family:Arial,san=
s-serif;color:rgb(255,0,0);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D8=AA=D8=AD=D8=B0=D9=8A=D8=B1=D8=A7=
=D8=AA =D9=85=D9=87=D9=85=D8=A9</span></span><p dir=3D"rtl" style=3D"line-h=
eight:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5=
pt;font-family:Arial,sans-serif;color:rgb(255,0,0);background-color:transpa=
rent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">=D9=8A=D9=85=
=D9=86=D8=B9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=
=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=
=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=
=D9=82=D8=AF=D9=85 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=
=D8=B9 12 =D8=A5=D9=84=D8=A7 =D8=A8=D8=A3=D9=85=D8=B1 =D8=A7=D9=84=D8=B7=D8=
=A8=D9=8A=D8=A8 =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=85=D8=A7=D8=B9 =D8=
=A7=D9=84=D9=8A =D8=AA=D9=88=D8=AC=D9=8A=D9=87=D8=A7=D8=AA=D9=87 .</span></=
p><br><br><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;margin=
-bottom:2pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;col=
or:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline">=C2=A0=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 | </span><span style=3D"font-size:12pt;font-fam=
ily:Arial,sans-serif;color:rgb(51,51,51);font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">00966538159747 </span><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparen=
t;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline">=C2=A0| =D9=81=D9=
=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =E2=80=93 =D8=AF=D9=83=
=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=
=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=C2=A0=C2=A0</span><=
/span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom=
:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:r=
gb(73,80,87);background-color:transparent;font-weight:700;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D9=86=D9=88=D8=A7=D8=
=AA =D8=A7=D9=84=D8=A3=D8=AE=D9=8A=D8=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=
=AD =D9=85=D9=88=D8=B6=D9=88=D8=B9 </span><a href=3D"https://saudiersaa.com=
/" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.g=
oogle.com/url?hl=3Dar&amp;q=3Dhttps://saudiersaa.com/&amp;source=3Dgmail&am=
p;ust=3D1756206440019000&amp;usg=3DAOvVaw3m1cBvqxpOevL5K-9SF5vU"><span styl=
e=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(255,152,0);bac=
kground-color:transparent;font-weight:700;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-si=
ze:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline"> =D9=
=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=85=D9=86 =D8=
=A3=D9=83=D8=AB=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B6=D9=8A=D8=B9 =D8=
=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=A8=D8=AD=D8=AB =D8=B9=D9=86=D9=87=D8=A7 =D8=
=A7=D9=84=D8=B3=D9=8A=D8=AF=D8=A7=D8=AA=D8=8C =D8=AE=D8=A7=D8=B5=D8=A9 =D9=
=81=D9=8A =D9=85=D8=AF=D9=86 =D9=85=D8=AB=D9=84 =D8=A7=D9=84=D8=B1=D9=8A=D8=
=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=AC=D8=
=A7=D8=B2=D8=A7=D9=86=D8=8C =D9=88=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=
=8A=D8=B7=D8=8C =D9=88=D9=83=D8=B0=D9=84=D9=83 =D9=81=D9=8A =D9=85=D9=86=D8=
=A7=D8=B7=D9=82 =D8=A7=D9=84=D8=AE=D9=84=D9=8A=D8=AC =D9=85=D8=AB=D9=84 =D8=
=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=83=D9=88=D9=
=8A=D8=AA =D9=88=D8=A7=D9=84=D8=B4=D8=A7=D8=B1=D9=82=D8=A9. =D9=86=D8=B8=D8=
=B1=D9=8B=D8=A7 =D9=84=D8=AD=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D8=A7=D9=84=D9=
=85=D9=88=D8=B6=D9=88=D8=B9 =D9=88=D8=A3=D9=87=D9=85=D9=8A=D8=AA=D9=87=D8=
=8C =D8=AA=D9=82=D8=AF=D9=85 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=
=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=A7=D9=84=D8=AF=D8=B9=D9=85 =D8=A7=D9=84=D8=
=B7=D8=A8=D9=8A =D9=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=
=A7=D8=AA =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=A9 =D9=84=D9=84=D9=
=86=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=AA=D9=8A =D9=8A=D8=
=AD=D8=AA=D8=AC=D9=86 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=AA=D9=88=D8=AC=D9=
=8A=D9=87 =D8=A7=D9=84=D8=B5=D8=AD=D9=8A=D8=AD =D9=88=D8=B7=D9=84=D8=A8 =D8=
=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=
=85=D9=88=D8=AB=D9=88=D9=82=D8=8C =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D8=A7=D8=
=AA=D8=B5=D8=A7=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85: </=
span><span style=3D"font-size:12pt;font-family:Arial,sans-serif;color:rgb(5=
1,51,51);font-weight:700;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline">0096653815=
9747 </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;co=
lor:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">.</span></p><p dir=3D"rtl" style=3D"line-height=
:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" st=
yle=3D"line-height:1.44;margin-top:0pt;margin-bottom:2pt"><span style=3D"fo=
nt-size:10pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-co=
lor:transparent;font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=
=85=D8=A7 =D9=87=D9=8A =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D9=84=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6=D8=9F</span></sp=
an><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12=
pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(=
73,80,87);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 (Cytotec) =D8=AA=D8=AD=D8=AA=D9=88=D9=8A =D8=B9=D9=84=D9=89 =
=D8=A7=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=
=D8=A9 =D8=A7=D9=84=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=
=D9=88=D9=84 (Misoprostol)=D8=8C =D9=88=D9=87=D9=8A =D8=AF=D9=88=D8=A7=D8=
=A1 =D9=85=D8=B9=D8=AA=D9=85=D8=AF =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=84=D8=
=B9=D9=84=D8=A7=D8=AC =D9=82=D8=B1=D8=AD=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=
=AF=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D8=8C =D9=84=D9=83=D9=
=86 =D8=A7=D9=84=D8=A3=D8=A8=D8=AD=D8=A7=D8=AB =D8=A7=D9=84=D8=B7=D8=A8=D9=
=8A=D8=A9 =D8=A3=D8=AB=D8=A8=D8=AA=D8=AA =D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=
=AA=D9=87 =D9=81=D9=8A </span><a href=3D"https://hayatannas.com/?srsltid=3D=
AfmBOoo8ZdNvEZUpg3DdfWtZNURKApzWgsXHqwmgsJdHJ68QU_xgOugS" target=3D"_blank"=
 rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.com/url?hl=3Da=
r&amp;q=3Dhttps://hayatannas.com/?srsltid%3DAfmBOoo8ZdNvEZUpg3DdfWtZNURKApz=
WgsXHqwmgsJdHJ68QU_xgOugS&amp;source=3Dgmail&amp;ust=3D1756206440020000&amp=
;usg=3DAOvVaw23gw8wN9jWFgh8jhnslusq"><span style=3D"font-size:11.5pt;font-f=
amily:Arial,sans-serif;color:rgb(255,152,0);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=D8=A5=D9=86=D9=87=D8=
=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=
=B1</span></a><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;=
color:rgb(73,80,87);background-color:transparent;font-weight:700;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;vertical-align:baseline"> =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=
=D9=81 =D8=B7=D8=A8=D9=8A.</span><span style=3D"font-size:11.5pt;font-famil=
y:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-we=
ight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"><br></span><span style=3D"=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgroun=
d-color:transparent;font-weight:700;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"=
>=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D9=8A=
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
=84=D9=89 </span><a href=3D"https://ksacytotec.com/" target=3D"_blank" rel=
=3D"nofollow" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&am=
p;q=3Dhttps://ksacytotec.com/&amp;source=3Dgmail&amp;ust=3D1756206440020000=
&amp;usg=3DAOvVaw2uQrHStzC2S0QhslDgT5I_"><span style=3D"font-size:11.5pt;fo=
nt-family:Arial,sans-serif;color:rgb(255,152,0);background-color:transparen=
t;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline">=D8=AD=D8=A8=D9=
=88=D8=A8 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size:11.5pt;font-family=
:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline"> =D9=81=D9=8A =D8=A7=D9=84=
=D8=B9=D8=AF=D9=8A=D8=AF =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=AF=D9=86:</span=
></p><ul style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=
=3D"list-style-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;colo=
r:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentati=
on" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom=
:0pt"><span style=3D"font-size:11.5pt;background-color:transparent;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline">=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6: =D8=
=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=85=D8=B9 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=
=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=84=D9=84=D8=AD=D8=B5=D9=88=D9=
=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=84=D8=
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
al;font-variant-alternates:normal;vertical-align:baseline">=D8=AC=D8=AF=D8=
=A9: =D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=A8=D8=B3=
=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=85=D8=B9 =D9=85=D8=AA=D8=A7=
=D8=A8=D8=B9=D8=A9.</span><span style=3D"font-size:11.5pt;background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline"><br><br></span></p></li=
><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family=
:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-wei=
ght:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-var=
iant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"r=
tl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;margin=
-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;background-colo=
r:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=D9=85=D9=83=D8=A9: =
=D8=AF=D8=B9=D9=85 =D8=B7=D8=A8=D9=8A =D8=A2=D9=85=D9=86 =D9=84=D9=84=D9=86=
=D8=B3=D8=A7=D8=A1 =D8=A7=D9=84=D9=84=D9=88=D8=A7=D8=AA=D9=8A =D9=8A=D8=AD=
=D8=AA=D8=AC=D9=86 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=
=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1.</span><span style=3D"fon=
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
baseline">=D8=AC=D8=A7=D8=B2=D8=A7=D9=86: =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=
=B1=D8=A7=D8=AA =D8=B9=D8=A8=D8=B1 =D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81 =D8=
=A3=D9=88 =D8=A7=D9=84=D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8.</span><span sty=
le=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;font-variant-alternates:normal;vertical=
-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-styl=
e-type:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,8=
7);background-color:transparent;font-weight:700;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"=
line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span s=
tyle=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline">=D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7: =D8=
=AA=D9=88=D9=81=D9=8A=D8=B1 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=
=84=D8=A3=D8=B5=D9=84=D9=8A =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=
=81 =D9=85=D8=AA=D8=AE=D8=B5=D8=B5.</span><span style=3D"font-size:11.5pt;b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br=
></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11=
.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:tran=
sparent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline;white-space:=
pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-al=
ign:right;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5p=
t;background-color:transparent;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=A7=D9=84=D8=B4=D8=A7=D8=B1=D9=82=D8=A9 =D9=88=D8=A7=D9=84=D8=A8=D8=AD=D8=
=B1=D9=8A=D9=86 =D9=88=D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA: =D8=A5=D9=85=D9=
=83=D8=A7=D9=86=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=
=84=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D9=85=D9=86 =D9=
=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82.</span><span style=3D"=
font-size:11.5pt;background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline"><br><br></span></p></li></ul><p dir=3D"rtl" style=3D"line-height=
:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;fo=
nt-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=F0=9F=93=9E =D8=
=B1=D9=82=D9=85 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D8=B1=D9=85=D9=
=8A=D9=86 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1: </span><s=
pan style=3D"font-size:12pt;font-family:Arial,sans-serif;color:rgb(51,51,51=
);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline">00966538159747=C2=
=A0</span></p><br><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0p=
t;margin-bottom:2pt"><span style=3D"font-size:10pt;font-family:Arial,sans-s=
erif;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D9=84=D9=85=D8=A7=D8=B0=D8=A7 =D8=AA=D8=
=AE=D8=AA=D8=A7=D8=B1=D9=8A=D9=86 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=
=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=9F</span></span><br><ul style=3D"margi=
n-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgroun=
d-color:transparent;font-weight:700;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;=
white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:=
1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font=
-size:11.5pt;background-color:transparent;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline">=D8=AE=D8=A8=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9 =D9=81=D9=8A =D9=
=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=D9=86=D8=B3=D8=A7=D8=A1 =D9=88=D8=A7=D9=
=84=D8=AA=D9=88=D9=84=D9=8A=D8=AF.</span><span style=3D"font-size:11.5pt;ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br>=
</span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.=
5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:trans=
parent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline;white-space:p=
re"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-ali=
gn:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;=
background-color:transparent;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=AA=
=D9=88=D9=81=D9=8A=D8=B1 =D8=AF=D9=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A.</span><span style=
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
-align:baseline">=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=B4=D8=AE=D8=B5=D9=
=8A=D8=A9 =D9=84=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D8=
=A8=D8=AF=D8=A7=D9=8A=D8=A9 =D8=AD=D8=AA=D9=89 =D8=A7=D9=84=D9=86=D9=87=D8=
=A7=D9=8A=D8=A9.</span><span style=3D"font-size:11.5pt;background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"><br><br></span></p></li><l=
i dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-family:Ar=
ial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl"=
 role=3D"presentation" style=3D"line-height:1.38;text-align:right;margin-to=
p:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;background-color:=
transparent;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">=D8=AE=D8=B5=D9=88=D8=
=B5=D9=8A=D8=A9 =D9=88=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=
=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84.</span><span style=3D"=
font-size:11.5pt;background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline"><br><br></span></p></li></ul><span dir=3D"rtl" style=3D"line-hei=
ght:1.44;margin-top:0pt;margin-bottom:4pt"><span style=3D"font-size:17pt;fo=
nt-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=D8=A8=D8=AF=D8=A7=
=D8=A6=D9=84 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83</span></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt=
;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans=
-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D9=81=D9=8A =D8=A8=D8=B9=D8=B6 =D8=A7=
=D9=84=D8=AD=D8=A7=D9=84=D8=A7=D8=AA=D8=8C =D9=82=D8=AF =D9=8A=D9=82=D8=AA=
=D8=B1=D8=AD =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D8=A8=D8=AF=D8=A7=D8=A6=
=D9=84 =D8=A3=D8=AE=D8=B1=D9=89:</span></p><ul style=3D"margin-top:0px;marg=
in-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5=
pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transp=
arent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline;white-space:pr=
e"><p dir=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-alig=
n:right;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11.5pt;b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=
=D9=84=D8=AA=D9=88=D8=B3=D9=8A=D8=B9 =D9=88=D8=A7=D9=84=D9=83=D8=AD=D8=AA =
=D8=A7=D9=84=D8=AC=D8=B1=D8=A7=D8=AD=D9=8A (D&amp;C).</span><span style=3D"=
font-size:11.5pt;background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type=
:disc;font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);bac=
kground-color:transparent;font-weight:700;font-variant-numeric:normal;font-=
variant-east-asian:normal;font-variant-alternates:normal;vertical-align:bas=
eline;white-space:pre"><p dir=3D"rtl" role=3D"presentation" style=3D"line-h=
eight:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt"><span style=
=3D"font-size:11.5pt;background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=AA=D8=AD=D8=AA=D9=88=D9=
=8A =D8=B9=D9=84=D9=89 =D9=85=D9=8A=D9=81=D9=8A=D8=A8=D8=B1=D9=8A=D8=B3=D8=
=AA=D9=88=D9=86 =D9=85=D8=B9 =D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=
=B3=D8=AA=D9=88=D9=84.</span><span style=3D"font-size:11.5pt;background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline"><br><br></span></p><=
/li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11.5pt;font-fam=
ily:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-=
weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-=
variant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=
=3D"rtl" role=3D"presentation" style=3D"line-height:1.38;text-align:right;m=
argin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=
=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AC=D8=B1=D8=A7=D8=AD=D9=8A =D8=
=A7=D9=84=D9=85=D8=A8=D8=A7=D8=B4=D8=B1.</span></p></li></ul><span dir=3D"r=
tl" style=3D"line-height:1.44;margin-top:0pt;margin-bottom:4pt"><span style=
=3D"font-size:17pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backgro=
und-color:transparent;font-weight:700;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e">=D8=A3=D8=B3=D8=A6=D9=84=D8=A9 =D8=B4=D8=A7=D8=A6=D8=B9=D8=A9</span></sp=
an><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12=
pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(=
73,80,87);background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">1. =D9=87=D9=84 =D9=8A=D9=85=D9=83=D9=86 =D8=B4=D8=B1=
=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=AF=D9=88=
=D9=86 =D9=88=D8=B5=D9=81=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=
=D8=AF=D9=8A=D8=A9=D8=9F</span><span style=3D"font-size:11.5pt;font-family:=
Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-weig=
ht:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline"><br></span><span style=3D"fo=
nt-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-=
color:transparent;font-weight:700;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D8=BA=D8=A7=D9=84=D8=A8=D9=8B=D8=A7 =D9=84=D8=A7=D8=8C =D9=88=D9=8A=D8=AC=
=D8=A8 =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=8A=D9=87 =D9=85=
=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82 =D8=AA=D8=AD=
=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A.</span></p><p dir=
=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span=
 style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87)=
;background-color:transparent;font-weight:700;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline">2. =D9=83=D9=85 =D8=AA=D8=B3=D8=AA=D8=BA=D8=B1=D9=82 =D8=B9=D9=
=85=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=A8=D8=
=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8=D8=9F</span><span style=3D"font-size:11.5=
pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transp=
arent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;font-variant-alternates:normal;vertical-align:baseline"><br></span><s=
pan style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,=
87);background-color:transparent;font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline">=D8=B9=D8=A7=D8=AF=D8=A9 =D9=85=D9=86 24 =D8=A5=D9=84=D9=89 4=
8 =D8=B3=D8=A7=D8=B9=D8=A9 =D8=AD=D8=AA=D9=89 =D9=8A=D9=83=D8=AA=D9=85=D9=
=84 =D8=A7=D9=84=D9=86=D8=B2=D9=8A=D9=81 =D9=88=D8=A5=D8=AE=D8=B1=D8=A7=D8=
=AC =D8=A7=D9=84=D8=AD=D9=85=D9=84.</span></p><p dir=3D"rtl" style=3D"line-=
height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.=
5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color:trans=
parent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:=
normal;font-variant-alternates:normal;vertical-align:baseline">3. =D9=87=D9=
=84 =D9=8A=D8=B3=D8=A8=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=
=A7=D9=84=D8=B9=D9=82=D9=85=D8=9F</span><span style=3D"font-size:11.5pt;fon=
t-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;=
font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;=
font-variant-alternates:normal;vertical-align:baseline"><br></span><span st=
yle=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);ba=
ckground-color:transparent;font-weight:700;font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=D9=84=D8=A7=D8=8C =D8=A5=D8=B0=D8=A7 =D8=AA=D9=85 =D8=A7=D8=B3=D8=
=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D8=A8=D8=B4=D9=83=D9=84 =D8=B5=D8=AD=D9=
=8A=D8=AD=D8=8C =D9=84=D8=A7 =D9=8A=D8=A4=D8=AB=D8=B1 =D8=B9=D9=84=D9=89 =
=D8=A7=D9=84=D9=82=D8=AF=D8=B1=D8=A9 =D8=A7=D9=84=D8=A5=D9=86=D8=AC=D8=A7=
=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=82=D8=A8=D9=84=D9=8A=
=D8=A9.</span></p><br><span dir=3D"rtl" style=3D"line-height:1.44;margin-to=
p:0pt;margin-bottom:4pt"><span style=3D"font-size:17pt;font-family:Arial,sa=
ns-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline">=D8=AE=D8=A7=D8=AA=D9=85=D8=A9</span=
></span><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bott=
om:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color=
:rgb(73,80,87);background-color:transparent;font-weight:700;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">=D8=A5=D9=86 =D8=AD=D8=A8=D9=88=D8=A8 =D8=A7=D9=84=
=D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =
=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D9=87 =D8=AA=D9=85=
=D8=AB=D9=84 =D8=AD=D9=84=D9=8B=D8=A7 =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=81=
=D9=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9=D8=8C =D9=84=
=D9=83=D9=86 =D8=A7=D9=84=D8=A3=D9=85=D8=A7=D9=86 =D9=8A=D9=83=D9=85=D9=86 =
=D9=81=D9=8A =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D9=85=D8=AE=D8=AA=
=D8=B5=D9=8A=D9=86 =D9=85=D8=AB=D9=84 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =
=D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D9=88=
=D9=81=D8=B1 =D8=A7=D9=84=D8=AF=D8=B9=D9=85 =D9=88=D8=A7=D9=84=D8=B9=D9=84=
=D8=A7=D8=AC =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D8=B6=D9=85=D9=88=
=D9=86=D8=8C =D9=85=D8=B9 =D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=AF=D9=82=
=D9=8A=D9=82=D8=A9 =D9=88=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9.=
</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:r=
gb(73,80,87);background-color:transparent;font-weight:700;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline"><br></span><span style=3D"font-size:11.5pt;font-fami=
ly:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;font-w=
eight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline">=D9=84=D9=84=D8=A7=D8=B3=
=D8=AA=D9=81=D8=B3=D8=A7=D8=B1=D8=A7=D8=AA =D8=A3=D9=88 =D8=B7=D9=84=D8=A8 =
=D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC=D8=8C =D8=A7=D8=AA=D8=B5=D9=84=D9=8A =
=D8=A7=D9=84=D8=A2=D9=86 =D8=B9=D9=84=D9=89: </span><span style=3D"font-siz=
e:12pt;font-family:Arial,sans-serif;color:rgb(51,51,51);font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">00966538159747 </span><span style=3D"f=
ont-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
.</span></p><br><span dir=3D"rtl" style=3D"line-height:1.44;margin-top:0pt;=
margin-bottom:4pt"><span style=3D"font-size:17pt;font-family:Arial,sans-ser=
if;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=AA=D8=AD=D8=B0=D9=8A=D8=B1=D8=A7=D8=AA=
 =D9=85=D9=87=D9=85=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height:=
1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;fon=
t-family:Arial,sans-serif;color:rgb(73,80,87);background-color:transparent;=
font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;=
font-variant-alternates:normal;vertical-align:baseline">=D9=8A=D9=85=D9=86=
=D8=B9 =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=AD=D8=A8=D9=88=D8=A8 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AD=D8=A7=D9=84=
=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=AA=D9=82=
=D8=AF=D9=85 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A3=D8=B3=D8=A8=D9=88=D8=B9 =
12 =D8=A5=D9=84=D8=A7 =D8=A8=D8=A3=D9=85=D8=B1 =D8=A7=D9=84=D8=B7=D8=A8=D9=
=8A=D8=A8.</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-ser=
if;color:rgb(73,80,87);background-color:transparent;font-weight:700;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline"><br><br></span></p><p dir=3D"rtl" style=3D=
"line-height:1.38;margin-top:0pt;margin-bottom:12pt"><span style=3D"font-si=
ze:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=84=
=D8=A7 =D8=AA=D8=B3=D8=AA=D8=AE=D8=AF=D9=85=D9=8A =D8=A7=D9=84=D8=AD=D8=A8=
=D9=88=D8=A8 =D8=A5=D8=B0=D8=A7 =D9=83=D8=A7=D9=86 =D9=84=D8=AF=D9=8A=D9=83=
 =D8=AD=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=A7=
=D8=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9.</span><span style=
=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(73,80,87);backg=
round-color:transparent;font-weight:700;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine"><br><br></span></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top=
:0pt;margin-bottom:12pt"><span style=3D"font-size:11.5pt;font-family:Arial,=
sans-serif;color:rgb(73,80,87);background-color:transparent;font-weight:700=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline">=D9=84=D8=A7 =D8=AA=D8=AA=D9=86=D8=
=A7=D9=88=D9=84=D9=8A =D8=A3=D9=8A =D8=AC=D8=B1=D8=B9=D8=A9 =D8=A5=D8=B6=D8=
=A7=D9=81=D9=8A=D8=A9 =D8=A8=D8=AF=D9=88=D9=86 =D8=A7=D8=B3=D8=AA=D8=B4=D8=
=A7=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9.</span></p><br><br><p dir=3D"rtl" =
style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);backgroun=
d-color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line">=C2=A0=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9</span><span style=3D"font-size:1=
1.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"> </span><span style=3D"fon=
t-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-c=
olor:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=A7=D9=84=D8=
=B1=D9=8A=D8=A7=D8=B6</span><span style=3D"font-size:11.5pt;font-family:Ari=
al,sans-serif;color:rgb(29,33,37);background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;font-fa=
mily:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218)=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85</spa=
n><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29=
,33,37);background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;colo=
r:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:700;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D8=AE=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7</span><span style=
=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);backg=
round-color:transparent;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline"> </span><sp=
an style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,3=
7);background-color:rgb(206,212,218);font-weight:700;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=
=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA</span><span style=3D"font-size:=
11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"> </span><span style=3D"fo=
nt-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-=
color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=
=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86</span><span style=3D"font-size:11.5pt;=
font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:transpare=
nt;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline"> </span><span style=3D"font-size=
:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:r=
gb(206,212,218);font-weight:700;font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=C3=
=97 =D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=
=84=D8=AD=D9=85=D9=84</span><span style=3D"font-size:11.5pt;font-family:Ari=
al,sans-serif;color:rgb(29,33,37);background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;font-fa=
mily:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218)=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =D9=85=D9=
=8A=D8=B2=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=84</span><span style=3D"fo=
nt-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-=
color:transparent;font-variant-numeric:normal;font-variant-east-asian:norma=
l;font-variant-alternates:normal;vertical-align:baseline"> </span><span sty=
le=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);bac=
kground-color:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;=
font-variant-east-asian:normal;font-variant-alternates:normal;vertical-alig=
n:baseline">=C3=97 =D8=A3=D8=B9=D8=B1=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=
=D9=84</span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;c=
olor:rgb(29,33,37);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans=
-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:70=
0;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-a=
lternates:normal;vertical-align:baseline">=C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=8A=D9=83 =D9=81=D9=8A =D9=85=D9=83=D8=A9</span><span style=
=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);backg=
round-color:transparent;font-variant-numeric:normal;font-variant-east-asian=
:normal;font-variant-alternates:normal;vertical-align:baseline"> </span><sp=
an style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,3=
7);background-color:rgb(206,212,218);font-weight:700;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline">=C3=97 =D8=B9=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D8=AC=
=D9=87=D8=A7=D8=B6</span><span style=3D"font-size:11.5pt;font-family:Arial,=
sans-serif;color:rgb(29,33,37);background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;font-famil=
y:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=AF=D9=83=
=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9</span><span style=3D"font-size:1=
1.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline"> </span><span style=3D"fon=
t-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);background-c=
olor:rgb(206,212,218);font-weight:700;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=
=B6 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA</span><span style=3D"=
font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline"> </span><span s=
tyle=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(29,33,37);b=
ackground-color:rgb(206,212,218);font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=
=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86</sp=
an><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;color:rgb(2=
9,33,37);background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e"> </span><span style=3D"font-size:11.5pt;font-family:Arial,sans-serif;col=
or:rgb(29,33,37);background-color:rgb(206,212,218);font-weight:700;font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:=
normal;vertical-align:baseline">=C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9=
 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D9=85=D8=A7=
=D8=B1=D8=A7=D8=AA</span><span style=3D"font-size:11.5pt;font-family:Arial,=
sans-serif;color:rgb(29,33,37);background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;font-famil=
y:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,218);fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=AF=D9=83=
=D8=AA=D9=88=D8=B1=D8=A9</span><span style=3D"font-size:11.5pt;font-family:=
Arial,sans-serif;color:rgb(29,33,37);background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"> </span><span style=3D"font-size:11.5pt;font=
-family:Arial,sans-serif;color:rgb(29,33,37);background-color:rgb(206,212,2=
18);font-weight:700;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">=C3=97 =D8=A7=
=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=A7=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=A9</=
span></p><br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/92070647-1fb6-422a-8d29-da9df9ac9437n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/92070647-1fb6-422a-8d29-da9df9ac9437n%40googlegroups.com</a>.<br />

------=_Part_429089_2094134490.1756120055975--

------=_Part_429088_753453065.1756120055975--
