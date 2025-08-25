Return-Path: <kasan-dev+bncBDYPL74CXAOBBDEGWHCQMGQEJGK7P5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E0D29B33D9C
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:03:42 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-74381e1e0casf6787204a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 04:03:42 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756119821; x=1756724621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I+xXgT1Y4xVJoTfmdaCetij93emf8AKbSswCPnX0h3Y=;
        b=schftN9JjXvnz0iLFy2ZI3jotbRj+LpsbSwKDJxRNqPysiqDePS9/aTAi7f3Ev3koz
         0mKHVoTKcpGzeu2yL44+SXo2wBT9c08UgKLCgi/I9cvGSb8KOiU7IJMZSf5b/3exO1yu
         zbivBcQ082zFaP0HfH+JMlaKU289nWTr2nP1uLFsPOI54wg4fF8l5jtCSN3puGJfILi9
         GPwVn7HTT6YuNYehrsPEVwkkCxaJNyz/nvertWiap4MMDKpTCcSI2BaoeD120R/XDHi/
         vdQ3ASL8rBk87PQXTuZejvsu3Z1K5tJPohccuew/yg+MSUSUUFF84snswWLX7jb5fNiG
         TI7g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756119821; x=1756724621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I+xXgT1Y4xVJoTfmdaCetij93emf8AKbSswCPnX0h3Y=;
        b=QZ9qU0UfuYI7pWk02q36ILbSwA2H/pAtq9fA6q/cZTDqM5AXjKYwUHzv1HRTpQ0Z2e
         NBkBncfqu9NUd6ZRG14YLdI9XtRiwIyVjSaXYc3HFJsMOrpGPIDYw5caHAxP+VMbYLWm
         8ZOoW5zjVZ4fUDyke6j6M/Q0E6iWPSUcKRbkvDpeQoIt455FJk4mQkpu+Ld56qfalDuZ
         YlOcpZyNF1RZfaZNN8/ltQGGKlmPGE08IU2A1KI7MZOY+xTCY556yWosmmIqKtymvrVQ
         /YC5/GFiFg7dDuSlTQg21ZW3vfsU/M+4T+5PvbLMEFYrzLmIAdiScZ+DOxry2WrsIbn8
         cHqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756119821; x=1756724621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I+xXgT1Y4xVJoTfmdaCetij93emf8AKbSswCPnX0h3Y=;
        b=II+hCpPIZPdB83MmHBtjPI4p1gft90mhv0H+WmSQu7WFpOxiHwCsedy+2ulnfeP0kS
         o5m9MDztsvi9mlEohn0VJ70iGHwSjqK8CxWZFI92WhmsDBFUnIbP/rrLclehTnDK1id/
         TZDXzaAYZNVVUgbRs1bdeO1v8i2Y0BNp+BQZ5FKZv+zpnbZC15gZPaPBTVh1GyvlBrdJ
         NqJOMy49iUCJB17lx2QnpZO7jewJ4BbbUaEAV1AuSJv2UixftfTwNVqBcms6lrZtxqec
         w2nyVYzOTW+V9spoMYKJRumB8WE/m9GbDti+lPC8gvf+flXdlMEm4OP2GKDfz9vtInOz
         cCbg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCX8v95KkEhSGDQ5r2S3K24e6HD0U38kbZSewJcD9/anQA0i7Hd2CJme7tx0AUJiVDlzb7GAEg==@lfdr.de
X-Gm-Message-State: AOJu0YxwGdhdHu5I51fpDhD02nvmHrIcmExbUzFkyZsTsH4Q6MqbNIeY
	bewsivve1+9uHZLc2mr5EFDjc2D9Y+lQAik12N4pzR8m7lUkfaslSR7O
X-Google-Smtp-Source: AGHT+IGrVJ1CDRWUnMktAyRhIrH5D6FsKhZzUCIzWmCGnLEdRufdSc/LanM9YDzep+VenMezkdn/rw==
X-Received: by 2002:a05:6830:660d:b0:745:2822:6b69 with SMTP id 46e09a7af769-74528229d57mr943452a34.27.1756119821166;
        Mon, 25 Aug 2025 04:03:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe5xJ7u4G53heJCviehc7B5gS4ik5TOCOfJGVKTo6zxbA==
Received: by 2002:a05:6820:c091:b0:61d:947b:f708 with SMTP id
 006d021491bc7-61da8a87b4bls83166eaf.0.-pod-delta-02-us; Mon, 25 Aug 2025
 04:03:40 -0700 (PDT)
X-Received: by 2002:a05:6808:1925:b0:404:d8fb:b9a7 with SMTP id 5614622812f47-43785248a7bmr2527259b6e.2.1756119820080;
        Mon, 25 Aug 2025 04:03:40 -0700 (PDT)
Date: Mon, 25 Aug 2025 04:03:39 -0700 (PDT)
From: =?UTF-8?B?2LPYp9mK2KrZiNiq2YMg2KfZhNiz2LnZiNiv2YrZhw==?=
 =?UTF-8?B?INiz2KfZitiq2YjYqtmDINio2K7YtdmFIDIwJQ==?=
 <mnalmagtereb@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <82ff5fe0-f77c-409c-8c44-780235f03404n@googlegroups.com>
Subject: =?UTF-8?Q?_=D8=AD=D8=A8=D9=88=D8=A8_=D8=B3=D8=A7=D9=8A=D8=AA=D9=88?=
 =?UTF-8?Q?=D8=AA=D9=83_|_009665?= =?UTF-8?Q?38159747__|?=
 =?UTF-8?Q?_=D9=81=D9=8A_=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_511116_1301715377.1756119819196"
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

------=_Part_511116_1301715377.1756119819196
Content-Type: multipart/alternative; 
	boundary="----=_Part_511117_1676216054.1756119819196"

------=_Part_511117_1676216054.1756119819196
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
2LHYqSDDlyDYp9mE2K/ZiNix2Kkg2KfZhNi02YfYsdmK2KkKCi0tIApZb3UgcmVjZWl2ZWQgdGhp
cyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBz
ICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0
b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1
bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNp
dCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2LzgyZmY1ZmUwLWY3
N2MtNDA5Yy04YzQ0LTc4MDIzNWYwMzQwNG4lNDBnb29nbGVncm91cHMuY29tLgo=
------=_Part_511117_1676216054.1756119819196
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
=A7=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=A9</span></p><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/82ff5fe0-f77c-409c-8c44-780235f03404n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/82ff5fe0-f77c-409c-8c44-780235f03404n%40googlegroups.com</a>.<br />

------=_Part_511117_1676216054.1756119819196--

------=_Part_511116_1301715377.1756119819196--
