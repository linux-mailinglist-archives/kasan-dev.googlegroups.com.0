Return-Path: <kasan-dev+bncBC36BFVD6MNBBEVBQ3CQMGQERMYHNOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id CBB9EB29233
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Aug 2025 10:19:32 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-61bd4e3145fsf5131970eaf.2
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Aug 2025 01:19:32 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755418771; x=1756023571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F2WF0DLuvVJeoP2vO6N/Z47I74QtbGxkZedrmiiJeMM=;
        b=bQZlesCHRpSyjrbuzKEqwCbJ/K1WwSb2HMhl2qEOmaKUguGUEBvi8+QzE3r8hYnHU8
         RUsVbH5F2k/G/v52JnGrXR8DO39Ogr9gKJpZr2jG61hiTtIrlRTV7idfBS0CWzfV3Y0+
         I1ATXmRuMshsbTmy/DEzT7qIHIx0sTysuk1sVw6z3A9MhYqezha8FbWzTGJj1eup2l3+
         KS2RRicVVTvVgDDlTQ3EIJ6QlihLY95YyltQxZyk7nLP5pJuHReeJtJrUP77grRwqd8f
         CuXfAmf+NzYfXQwccmJ5DSnllRfwKqc0qXRbzq33GdQUuFdwohtL3l1igEgZdU4NHO8/
         yA/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755418771; x=1756023571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F2WF0DLuvVJeoP2vO6N/Z47I74QtbGxkZedrmiiJeMM=;
        b=W33UOBeEo1BJm5jhlh8wbKNRbRzNuGAdu7ekxOqbqjQW4PBnJB1dzLYVDmMAjg5Dq3
         MYr1VF9DEQ/Spz5lnwJ2uQQFDdobEdGbgaVmuFtY/fXBy07tTs3n8mNHCE0s65D4pJuF
         IfQRj02WaBGEamWHIBXKRMbGliuHfTAEO96474HGGC8ih0y6moarS0+DsnpkaOXbcTiA
         g8ELKye/bTfSgcMC7S8nZ+0Ag3pW5eDjNEdOTvG+cwIIEZr+IJ5ADIyKd4p03Z7lPN0a
         Y4GsMtsHED1WtxD8Ylk8XmbXHU+KxrAh1hgrUhiYv9QFphgav0fVJV/vA4jGVFFItpkw
         KRWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755418771; x=1756023571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F2WF0DLuvVJeoP2vO6N/Z47I74QtbGxkZedrmiiJeMM=;
        b=XMZAEhOeYZeGmIrz8j0rf1wro9ImFT55mJBO1WWCUKzlPYSXprGS+xKbQ/UsD3JPYf
         9LyW8N3izSO/LqNBxa2kv7QRSxj3KK9UqNijrE9Ys8xFJcU89YUv3icHlt/rqgep4gIO
         oUAEBEyDcidonre2CaGUzl02eutDDOuXo2tqKDqe6rTfiUuZEP6wJ5nM7e35roZlMF/J
         3Jo+sD8g83uciVVv5PhlaH2DIoO0UYwTnEgGOEHRNGwNsln5M6/1g8FxZhO2whXd0B+k
         qJR/6H+uzLCG8l2dmlyoz0k37fTakag2Bjqs68fyIDJ6PCPI2RI8OCM5kWzBNMTl3P9r
         mcgA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWUschFs2rkdmvVatWn9I+NDbwwn0983aX53e1kKZlN62If5AqZi3EJnw++QptCkvOADWbOJA==@lfdr.de
X-Gm-Message-State: AOJu0YxEfheE+t/UIWq5+dSCi55u2+msmMfjKzQIUzCQEfDtQ8bpkE+s
	xEJcL98+iNMpxvOBPF2tBmHWDqUJE9tB+7upM7X1vWIQI2UX9NzC9fKw
X-Google-Smtp-Source: AGHT+IGWXctjJ5e2QRW+oYctEUgghiqm7leDJ3TMx4XuJ8w9pNzLtmbH0gVR/d+L1fxNJghRsVtefA==
X-Received: by 2002:a05:6870:7a0c:b0:2ff:d8bb:fc26 with SMTP id 586e51a60fabf-310aaf27253mr5317564fac.35.1755418771072;
        Sun, 17 Aug 2025 01:19:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcEMEQJ9RyzwGxIFXaAJhaoCJ7mWW0IfEWGpphLFY/Xgw==
Received: by 2002:a05:6870:d152:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-30cceb68b39ls2122756fac.1.-pod-prod-05-us; Sun, 17 Aug 2025
 01:19:30 -0700 (PDT)
X-Received: by 2002:a05:6808:3093:b0:426:6b0e:e9b0 with SMTP id 5614622812f47-435f5df70e5mr2453699b6e.15.1755418770036;
        Sun, 17 Aug 2025 01:19:30 -0700 (PDT)
Date: Sun, 17 Aug 2025 01:19:29 -0700 (PDT)
From: =?UTF-8?B?2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg4oCT?=
 =?UTF-8?B?INmG2LPYqNipINmG2KzYp9itIDk12ao=?= <hayatannas967@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
Subject: =?UTF-8?B?2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2LHZitin2LYgMA==?=
 =?UTF-8?B?NTM3NDY2NTM5ICPYp9mE2LPYudmI2K/Zitip?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_193410_1403602685.1755418769242"
X-Original-Sender: hayatannas967@gmail.com
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

------=_Part_193410_1403602685.1755418769242
Content-Type: multipart/alternative; 
	boundary="----=_Part_193411_1618170486.1755418769242"

------=_Part_193411_1618170486.1755418769242
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

CgrYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYsdmK2KfYtiAwNTM3NDY2NTM5ICPYp9mE2LPYudmI
2K/ZitipINmE2YTYpdis2YfYp9i2INin2YTYotmF2YYg2YXYuSDYry4g2YbZitix2YXZitmGIHwg
fCAK2KfZhNix2YrYp9i2INis2K/YqSDZhdmD2Kkg2KfZhNiv2YXYp9mFCgrYp9mD2KrYtNmB2Yog
2YXYuSDYry4g2YbZitix2YXZitmG2Iwg2KfZhNmI2YPZitmEINin2YTYsdiz2YXZiiDZhNit2KjZ
iNioINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINmD2YrZgdmK2Kkg2KfZ
hNil2KzZh9in2LYgCtin2YTYt9io2Yog2KfZhNii2YXZhiDYqNin2LPYqtiu2K/Yp9mFINiz2KfZ
itiq2YjYqtmDIDIwMCAoTWlzb3Byb3N0b2wpINio2KXYtNix2KfZgSDYt9io2Yog2YjYs9ix2ZHZ
itipINiq2KfZhdipLiAK2KrZiNi12YrZhCDYs9ix2YrYuSDZgdmKINin2YTYsdmK2KfYttiMINis
2K/YqdiMINmF2YPYqdiMINin2YTYr9mF2KfZhSDZiNio2KfZgtmKINin2YTZhdiv2YYuIPCfk54g
MDUzNzQ2NjUzOQoK2YHZiiDYp9mE2LPZhtmI2KfYqiDYp9mE2KPYrtmK2LHYqdiMINij2LXYqNit
2Kog2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMgPGh0dHBzOi8va3NhY3l0b3RlYy5jb20vPiAKKE1p
c29wcm9zdG9sKSDYrtmK2KfYsdmL2Kcg2LfYqNmK2YvYpyDZhdi52LHZiNmB2YvYpyDZiNmB2LnZ
kdin2YTZi9inINmE2KXZhtmH2KfYoSDYp9mE2K3ZhdmEINin2YTZhdio2YPYsSDYqNi32LHZitmC
2Kkg2KLZhdmG2KkgCtiq2K3YqiDYpdi02LHYp9mBINmF2K7Yqti12YrZhi4g2YjZhdi5INin2YbY
qti02KfYsSDYp9mE2YXZhtiq2KzYp9iqINin2YTZhdmC2YTYr9ip2Iwg2KPYtdio2K0g2YXZhiDY
p9mE2LbYsdmI2LHZiiDYp9mE2K3YtdmI2YQg2LnZhNmJIArYp9mE2K/ZiNin2KEg2YXZhiDZhdi1
2K/YsSDZhdmI2KvZiNmCINmI2YXYudiq2YXYry4K2K8uINmG2YrYsdmF2YrZhtiMINio2LXZgdiq
2YfYpyDYp9mE2YjZg9mK2YQg2KfZhNix2LPZhdmKINmE2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg
2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2KrZgtiv2YUg2YTZg9mQINmF2YbYqtis2YvYpyAK2KPY
tdmE2YrZi9inINio2KzZiNiv2Kkg2YXYttmF2YjZhtip2Iwg2YXYuSDYp9iz2KrYtNin2LHYqSDY
t9io2YrYqSDZhdiq2K7Ytdi12Kkg2YjYs9ix2ZHZitipINiq2KfZhdipINmB2Yog2KfZhNiq2LnY
p9mF2YQg2YjYp9mE2KrZiNi12YrZhC4KCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoK
2YXYpyDZh9mIINiv2YjYp9ihINiz2KfZitiq2YjYqtmD2J8KCtiz2KfZitiq2YjYqtmDICjYp9mE
2YXYp9iv2Kkg2KfZhNmB2LnYp9mE2Kkg2YXZitiy2YjYqNix2YjYs9iq2YjZhCkg2K/ZiNin2KEg
2YXZj9i52KrZhdivINmB2Yog2KfZhNmF2KzYp9mEINin2YTYt9io2YrYjCDZiNmK2Y/Ys9iq2K7Y
r9mFIArYqNis2LHYudin2Kog2K/ZgtmK2YLYqSDZhNil2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE
2YXYqNmD2LHYjCDZiNi52YTYp9isINit2KfZhNin2Kog2LfYqNmK2Kkg2KPYrtix2Ykg2YXYq9mE
INmC2LHYrdipINin2YTZhdi52K/YqS4gCti52YbYryDYp9iz2KrYrtiv2KfZhdmHINmE2YTYpdis
2YfYp9i22Iwg2YrYudmF2YQg2LnZhNmJINiq2K3ZgdmK2LIg2KrZgtmE2LXYp9iqINin2YTYsdit
2YUg2YjYpdmB2LHYp9i6INmF2K3YqtmI2YrYp9iq2Ycg2K7ZhNin2YQg2YHYqtix2KkgCtmC2LXZ
itix2KnYjCDZhdmF2Kcg2YrYrNi52YTZhyDYrtmK2KfYsdmL2Kcg2YHYudin2YTZi9inINmI2KLZ
hdmG2YvYpyDYudmG2K8g2KXYtNix2KfZgSDYt9io2YrYqCDZhdiu2KrYtS4KCi0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLQoK2KPZh9mF2YrYqSDYp9mE2K3YtdmI2YQg2LnZhNmJINiz2KfZ
itiq2YjYqtmDINmF2YYg2YXYtdiv2LEg2YXZiNir2YjZggoK2YHZiiDYp9mE2LPYudmI2K/Zitip
2Iwg2KrYqtmI2KfYrNivINin2YTZg9ir2YrYsSDZhdmGINin2YTZgtmG2YjYp9iqINi62YrYsSDY
p9mE2YXZiNir2YjZgtipINin2YTYqtmKINiq2KjZiti5INmF2YbYqtis2KfYqiDZhdis2YfZiNmE
2KkgCtin2YTZhdi12K/YsSDZgtivINiq2KTYr9mKINil2YTZiSDZhdiu2KfYt9ixINi12K3Zitip
INis2LPZitmF2KkuCtivLiDZhtmK2LHZhdmK2YYg2KrYttmF2YYg2YTZgzoK4pyU77iPINit2KjZ
iNioINiz2KfZitiq2YjYqtmDINij2LXZhNmK2KkgMTAwJQrinJTvuI8g2KrYp9ix2YrYriDYtdmE
2KfYrdmK2Kkg2K3Yr9mK2KsK4pyU77iPINil2LHYtNin2K/Yp9iqINi32KjZitipINiv2YLZitmC
2Kkg2YTZhNin2LPYqtiu2K/Yp9mFCuKclO+4jyDYs9ix2ZHZitipINiq2KfZhdipINmB2Yog2KfZ
hNiq2YjYtdmK2YQK4pyU77iPINiv2LnZhSDZiNin2LPYqti02KfYsdipINi52YTZiSDZhdiv2KfY
sSDYp9mE2LPYp9i52KkKCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoK2YTZhdin2LDY
pyDYqtiu2KrYp9ix2YrZhiDYry4g2YbZitix2YXZitmG2J8KICAgCiAgIC0gCiAgIAogICDYp9mE
2K7YqNix2Kkg2KfZhNi32KjZitipOiDYry4g2YbZitix2YXZitmGINmF2KrYrti12LXYqSDZgdmK
INin2YTYp9iz2KrYtNin2LHYp9iqINin2YTYt9io2YrYqSDYp9mE2YbYs9in2KbZitip2Iwg2YjY
qtmC2K/ZhSDZhNmD2ZAgCiAgINiv2LnZhdmL2Kcg2YXZh9mG2YrZi9inINmC2KjZhCDZiNij2KvZ
htin2KEg2YjYqNi52K/Yp9iz2KrYrtiv2KfZhSDYs9in2YrYqtmI2KrZgyA8aHR0cHM6Ly9zYXVk
aWVyc2FhLmNvbS8+LgogICAKICAgLSAKICAgCiAgINin2YTYqtmI2LXZitmEINin2YTYs9ix2YrY
uTog2KrYuti32YrYqSDZhNis2YXZiti5INin2YTZhdiv2YYg2KfZhNiz2LnZiNiv2YrYqdiMINio
2YXYpyDZgdmKINiw2YTZgyDYp9mE2LHZitin2LbYjCDYrNiv2KnYjCDZhdmD2KnYjCAKICAg2KfZ
hNiv2YXYp9mF2Iwg2KfZhNiu2KjYsdiMINin2YTYt9in2KbZgSDZiNi62YrYsdmH2KcuCiAgIAog
ICAtIAogICAKICAg2K3Zhdin2YrYqSDYrti12YjYtdmK2KrZgzog2YrYqtmFINin2YTYqti62YTZ
itmBINio2LfYsdmK2YLYqSDYqti22YXZhiDYp9mE2LPYsdmR2YrYqSDYp9mE2YPYp9mF2YTYqS4K
ICAgCiAgIC0gCiAgIAogICDYp9mE2KrZiNmD2YrZhCDYp9mE2LHYs9mF2Yo6INi02LHYp9ih2YMg
2YrYqtmFINmF2KjYp9i02LHYqSDZhdmGINin2YTZhdi12K/YsSDYp9mE2YXYudiq2YXYr9iMINio
2LnZitiv2YvYpyDYudmGINin2YTZhdiu2KfYt9ixLgogICAKICAgCi0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLQoK2YPZitmB2YrYqSDYt9mE2Kgg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg
2YXZhiDYry4g2YbZitix2YXZitmGCiAgIAogICAxLiAKICAgCiAgINin2YTYqtmI2KfYtdmEINi5
2KjYsSDZiNin2KrYs9in2Kgg2LnZhNmJINin2YTYsdmC2YU6IPCfk54gMDUzNzQ2NjUzOQogICAK
ICAgMi4gCiAgIAogICDYtNix2K0g2KfZhNit2KfZhNipINin2YTYtdit2YrYqSDZiNmB2KrYsdip
INin2YTYrdmF2YQuCiAgIAogICAzLiAKICAgCiAgINin2LPYqtmE2KfZhSDYp9mE2KXYsdi02KfY
r9in2Kog2KfZhNi32KjZitipINin2YTZhdmG2KfYs9io2Kkg2YjYp9mE2KzYsdi52Kkg2KfZhNmF
2YjYtdmJINio2YfYpy4KICAgCiAgIDQuIAogICAKICAg2KfYs9iq2YTYp9mFINin2YTYrdio2YjY
qCDYrtmE2KfZhCDZgdiq2LHYqSDZgti12YrYsdipINi52KjYsSDYrtiv2YXYqSDYqtmI2LXZitmE
INii2YXZhtipINmI2LPYsdmK2KkuCiAgIAogICAKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tCgrYqtmG2KjZitmHINi32KjZiiDZhdmH2YUKICAgCiAgIC0gCiAgIAogICDZitis2Kgg2KfY
s9iq2K7Yr9in2YUg2LPYp9mK2KrZiNiq2YMg2YHZgti3INiq2K3YqiDYpdi02LHYp9mBINi32KjZ
iiDZhdiu2KrYtS4KICAgCiAgIC0gCiAgIAogICDZhNinINmK2Y/Zhti12K0g2KjYp9iz2KrYrtiv
2KfZhdmHINmB2Yog2K3Yp9mE2KfYqiDYp9mE2K3ZhdmEINin2YTZhdiq2KPYrtixLgogICAKICAg
LSAKICAgCiAgINmB2Yog2K3Yp9mEINmI2KzZiNivINij2YXYsdin2LYg2YXYstmF2YbYqSDYo9mI
INit2KfZhNin2Kog2K7Yp9i12KnYjCDZitis2Kgg2KfYs9iq2LTYp9ix2Kkg2KfZhNi32KjZitio
INmC2KjZhCDYp9mE2KfYs9iq2K7Yr9in2YUuCiAgIAogICAKLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tCgrYrtiv2YXYp9iqINil2LbYp9mB2YrYqSDZhdmGINivLiDZhtmK2LHZhdmK2YYK
ICAgCiAgIC0gCiAgIAogICDZhdiq2KfYqNi52Kkg2KfZhNit2KfZhNipINio2LnYryDYp9mE2KfY
s9iq2K7Yr9in2YUuCiAgIAogICAtIAogICAKICAg2KrZiNmB2YrYsSDZhdi52YTZiNmF2KfYqiDY
rdmI2YQg2KfZhNii2KvYp9ixINin2YTYrNin2YbYqNmK2Kkg2KfZhNi32KjZiti52YrYqSDZiNmD
2YrZgdmK2Kkg2KfZhNiq2LnYp9mF2YQg2YXYudmH2KcuCiAgIAogICAtIAogICAKICAg2KXYsdi0
2KfYryDYp9mE2YXYsdmK2LbYqSDYpdmE2Ykg2KPZgdi22YQg2YXZhdin2LHYs9in2Kog2KfZhNiz
2YTYp9mF2Kkg2KfZhNi32KjZitipLgogICAKICAgCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLQoK2K7ZhNin2LXYqQoK2KfYrtiq2YrYp9ixINin2YTZhdi12K/YsSDYp9mE2YXZiNir2YjZ
giDYudmG2K8g2LTYsdin2KEg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMgCjxodHRwczovL2dyb3Vw
cy5nb29nbGUuY29tL2EvY2hyb21pdW0ub3JnL2cvc2VjdXJpdHktZGV2L2MvcmhyUHBpdkNRR00v
bS9YaWhVQmlTTEFBQUo+IArZgdmKINin2YTYs9i52YjYr9mK2Kkg2YfZiCDYp9mE2LbZhdin2YYg
2KfZhNmI2K3ZitivINmE2LPZhNin2YXYqtmD2ZAuCtmF2Lkg2K8uINmG2YrYsdmF2YrZhtiMINiz
2KrYrdi12YTZitmGINi52YTZiSDYp9mE2YXZhtiq2Kwg2KfZhNij2LXZhNmK2Iwg2KfZhNil2LHY
tNin2K8g2KfZhNi32KjZiiDYp9mE2YXYqtiu2LXYtdiMINmI2KfZhNiq2YjYtdmK2YQgCtin2YTY
s9ix2Yog2KPZitmG2YXYpyDZg9mG2KrZkCDZgdmKINin2YTZhdmF2YTZg9ipLgoK8J+TniDZhNmE
2KrZiNin2LXZhCDZiNin2YTYt9mE2Kgg2LnYqNixINmI2KfYqtiz2KfYqDogMDUzNzQ2NjUzOQrY
p9mE2YXYr9mGINin2YTZhdi62LfYp9ipOiDYp9mE2LHZitin2LYg4oCTINis2K/YqSDigJMg2YXZ
g9ipIOKAkyDYp9mE2K/Zhdin2YUg4oCTINin2YTYrtio2LEg4oCTINin2YTYt9in2KbZgSDigJMg
2KfZhNmF2K/ZitmG2KkgCtin2YTZhdmG2YjYsdipIOKAkyDYo9io2YfYpyDigJMg2KzYp9iy2KfZ
hiDigJMg2KrYqNmI2YMuCgotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCiAKCtiz2KfZ
itiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINiz2KfZitiq2YjYqtmDINin2YTYsdmK
2KfYttiMINiz2KfZitiq2YjYqtmDINis2K/YqdiMINiz2KfZitiq2YjYqtmDINmF2YPYqdiMINiz
2KfZitiq2YjYqtmDIArYp9mE2K/Zhdin2YXYjCDYtNix2KfYoSDYs9in2YrYqtmI2KrZgyDZgdmK
INin2YTYs9i52YjYr9mK2KnYjCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KXYrNmH2KfY
ttiMINiz2KfZitiq2YjYqtmDINij2LXZhNmK2IwgCtiz2KfZitiq2YjYqtmDIDIwMNiMIE1pc29w
cm9zdG9sINin2YTYs9i52YjYr9mK2KnYjCDYs9in2YrYqtmI2KrZgyDYp9mE2YbZh9iv2YrYjCBo
dHRwczovL2tzYWN5dG90ZWMuY29tLyAK2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2K/Zg9iq2YjY
sdipINmG2YrYsdmF2YrZhiDYs9in2YrYqtmI2KrZgy4KCtiz2KfZitiq2YjYqtmDINmB2Yog2KfZ
hNiz2LnZiNiv2YrYqdiMINiz2KfZitiq2YjYqtmDINin2YTYsdmK2KfYttiMINiz2KfZitiq2YjY
qtmDINis2K/YqdiMINiz2KfZitiq2YjYqtmDINmF2YPYqdiMINiz2KfZitiq2YjYqtmDIArYp9mE
2K/Zhdin2YXYjCDYtNix2KfYoSDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnY
jCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KXYrNmH2KfYttiMINiz2KfZitiq2YjYqtmD
INij2LXZhNmK2IwgCtiz2KfZitiq2YjYqtmDIDIwMNiMIE1pc29wcm9zdG9sINin2YTYs9i52YjY
r9mK2KnYjCDYs9in2YrYqtmI2KrZgyDYp9mE2YbZh9iv2YrYjCDYp9mE2KXYrNmH2KfYtiDYp9mE
2LfYqNmKINmB2YogCtin2YTYs9i52YjYr9mK2KnYjCDYr9mD2KrZiNix2Kkg2YbZitix2YXZitmG
INiz2KfZitiq2YjYqtmDLgoKLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5
b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAu
ClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxz
IGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdy
b3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdv
b2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvNDEyZmZiNDItNjlhMi00ZDM0LTllYTUtNmFhNTNk
ZDU4NzExbiU0MGdvb2dsZWdyb3Vwcy5jb20uCg==
------=_Part_193411_1618170486.1755418769242
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 12pt; margin-bottom:=
 12pt;"><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; col=
or: rgb(0, 0, 0); background-color: transparent; font-variant-numeric: norm=
al; font-variant-east-asian: normal; font-variant-alternates: normal; font-=
variant-position: normal; font-variant-emoji: normal; vertical-align: basel=
ine; white-space-collapse: preserve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=
=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 0537466539 #=D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=84=D9=84=D8=A5=D8=AC=D9=87=
=D8=A7=D8=B6 =D8=A7=D9=84=D8=A2=D9=85=D9=86 =D9=85=D8=B9 =D8=AF. =D9=86=D9=
=8A=D8=B1=D9=85=D9=8A=D9=86 | | =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =D8=AC=
=D8=AF=D8=A9 =D9=85=D9=83=D8=A9 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85</span>=
</p><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 12pt; margin-bot=
tom: 12pt;"><span style=3D"font-size: 11pt; font-family: Arial, sans-serif;=
 color: rgb(0, 0, 0); background-color: transparent; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;">=D8=A7=D9=83=D8=AA=D8=B4=D9=81=D9=
=8A =D9=85=D8=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86=D8=8C =D8=A7=
=D9=84=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A =D9=84=
=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=
=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D9=83=D9=8A=
=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=
=D8=B7=D8=A8=D9=8A =D8=A7=D9=84=D8=A2=D9=85=D9=86 =D8=A8=D8=A7=D8=B3=D8=AA=
=D8=AE=D8=AF=D8=A7=D9=85 </span><span style=3D"font-size: 11pt; font-family=
: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transparent; fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200 (Misoprostol)</span><sp=
an style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, =
0, 0); background-color: transparent; font-variant-numeric: normal; font-va=
riant-east-asian: normal; font-variant-alternates: normal; font-variant-pos=
ition: normal; font-variant-emoji: normal; vertical-align: baseline; white-=
space-collapse: preserve;"> =D8=A8=D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=
=A8=D9=8A =D9=88=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9. =
=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=B3=D8=B1=D9=8A=D8=B9 =D9=81=D9=8A =D8=A7=
=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=
=D8=A9=D8=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =D9=88=D8=A8=D8=A7=D9=82=
=D9=8A =D8=A7=D9=84=D9=85=D8=AF=D9=86. =F0=9F=93=9E 0537466539</span></p><p=
 dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 12pt; margin-bottom: 1=
2pt;"><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; color=
: rgb(0, 0, 0); background-color: transparent; font-variant-numeric: normal=
; font-variant-east-asian: normal; font-variant-alternates: normal; font-va=
riant-position: normal; font-variant-emoji: normal; vertical-align: baselin=
e; white-space-collapse: preserve;">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D9=86=
=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=AE=D9=8A=D8=B1=D8=A9=D8=8C =D8=A3=
=D8=B5=D8=A8=D8=AD=D8=AA</span><a href=3D"https://ksacytotec.com/"><span st=
yle=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0)=
; background-color: transparent; font-variant-numeric: normal; font-variant=
-east-asian: normal; font-variant-alternates: normal; font-variant-position=
: normal; font-variant-emoji: normal; vertical-align: baseline; white-space=
-collapse: preserve;"> </span><span style=3D"font-size: 11pt; font-family: =
Arial, sans-serif; color: rgb(17, 85, 204); background-color: transparent; =
font-variant-numeric: normal; font-variant-east-asian: normal; font-variant=
-alternates: normal; font-variant-position: normal; font-variant-emoji: nor=
mal; text-decoration-line: underline; text-decoration-skip-ink: none; verti=
cal-align: baseline; white-space-collapse: preserve;">=D8=AD=D8=A8=D9=88=D8=
=A8 </span><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; =
color: rgb(17, 85, 204); background-color: transparent; font-weight: 700; f=
ont-variant-numeric: normal; font-variant-east-asian: normal; font-variant-=
alternates: normal; font-variant-position: normal; font-variant-emoji: norm=
al; text-decoration-line: underline; text-decoration-skip-ink: none; vertic=
al-align: baseline; white-space-collapse: preserve;">=D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"font-size: 11pt; font-family=
: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transparent; fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;"> (Misoprostol)</span><span style=3D"font-size: 11pt; font-family: Aria=
l, sans-serif; color: rgb(0, 0, 0); background-color: transparent; font-var=
iant-numeric: normal; font-variant-east-asian: normal; font-variant-alterna=
tes: normal; font-variant-position: normal; font-variant-emoji: normal; ver=
tical-align: baseline; white-space-collapse: preserve;"> =D8=AE=D9=8A=D8=A7=
=D8=B1=D9=8B=D8=A7 =D8=B7=D8=A8=D9=8A=D9=8B=D8=A7 =D9=85=D8=B9=D8=B1=D9=88=
=D9=81=D9=8B=D8=A7 =D9=88=D9=81=D8=B9=D9=91=D8=A7=D9=84=D9=8B=D8=A7 =D9=84=
=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=
=D9=85=D8=A8=D9=83=D8=B1 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=A2=D9=85=
=D9=86=D8=A9 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D9=85=D8=AE=
=D8=AA=D8=B5=D9=8A=D9=86. =D9=88=D9=85=D8=B9 =D8=A7=D9=86=D8=AA=D8=B4=D8=A7=
=D8=B1 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D9=85=
=D9=82=D9=84=D8=AF=D8=A9=D8=8C =D8=A3=D8=B5=D8=A8=D8=AD =D9=85=D9=86 =D8=A7=
=D9=84=D8=B6=D8=B1=D9=88=D8=B1=D9=8A =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =
=D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D9=86 =D9=85=
=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82 =D9=88=D9=85=D8=B9=D8=AA=
=D9=85=D8=AF.</span><span style=3D"font-size: 11pt; font-family: Arial, san=
s-serif; color: rgb(0, 0, 0); background-color: transparent; font-variant-n=
umeric: normal; font-variant-east-asian: normal; font-variant-alternates: n=
ormal; font-variant-position: normal; font-variant-emoji: normal; vertical-=
align: baseline; white-space-collapse: preserve;"><br /></span><span style=
=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); b=
ackground-color: transparent; font-weight: 700; font-variant-numeric: norma=
l; font-variant-east-asian: normal; font-variant-alternates: normal; font-v=
ariant-position: normal; font-variant-emoji: normal; vertical-align: baseli=
ne; white-space-collapse: preserve;">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86</span><span style=3D"font-size: 11pt; font-family: Arial, sans-serif=
; color: rgb(0, 0, 0); background-color: transparent; font-variant-numeric:=
 normal; font-variant-east-asian: normal; font-variant-alternates: normal; =
font-variant-position: normal; font-variant-emoji: normal; vertical-align: =
baseline; white-space-collapse: preserve;">=D8=8C =D8=A8=D8=B5=D9=81=D8=AA=
=D9=87=D8=A7 =D8=A7=D9=84=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=
=D9=85=D9=8A =D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=
=D8=8C =D8=AA=D9=82=D8=AF=D9=85 =D9=84=D9=83=D9=90 =D9=85=D9=86=D8=AA=D8=AC=
=D9=8B=D8=A7 =D8=A3=D8=B5=D9=84=D9=8A=D9=8B=D8=A7 =D8=A8=D8=AC=D9=88=D8=AF=
=D8=A9 =D9=85=D8=B6=D9=85=D9=88=D9=86=D8=A9=D8=8C =D9=85=D8=B9 =D8=A7=D8=B3=
=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9 =D9=85=D8=AA=D8=AE=
=D8=B5=D8=B5=D8=A9 =D9=88=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=
=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=88=D8=A7=
=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84.</span></p><p dir=3D"rtl" style=3D"lin=
e-height: 1.38; margin-top: 0pt; margin-bottom: 0pt;"></p><hr /><p></p><spa=
n dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 14pt; margin-bottom: =
4pt;"><span style=3D"font-size: 13pt; font-family: Arial, sans-serif; color=
: rgb(0, 0, 0); background-color: transparent; font-weight: 700; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;">=D9=85=D8=A7 =D9=87=
=D9=88 =D8=AF=D9=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83=
=D8=9F</span></span><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: =
12pt; margin-bottom: 12pt;"><span style=3D"font-size: 11pt; font-family: Ar=
ial, sans-serif; color: rgb(0, 0, 0); background-color: transparent; font-v=
ariant-numeric: normal; font-variant-east-asian: normal; font-variant-alter=
nates: normal; font-variant-position: normal; font-variant-emoji: normal; v=
ertical-align: baseline; white-space-collapse: preserve;">=D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 (=D8=A7=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=A7=D9=
=84=D9=81=D8=B9=D8=A7=D9=84=D8=A9 </span><span style=3D"font-size: 11pt; fo=
nt-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transp=
arent; font-weight: 700; font-variant-numeric: normal; font-variant-east-as=
ian: normal; font-variant-alternates: normal; font-variant-position: normal=
; font-variant-emoji: normal; vertical-align: baseline; white-space-collaps=
e: preserve;">=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=
=D9=84</span><span style=3D"font-size: 11pt; font-family: Arial, sans-serif=
; color: rgb(0, 0, 0); background-color: transparent; font-variant-numeric:=
 normal; font-variant-east-asian: normal; font-variant-alternates: normal; =
font-variant-position: normal; font-variant-emoji: normal; vertical-align: =
baseline; white-space-collapse: preserve;">) =D8=AF=D9=88=D8=A7=D8=A1 =D9=
=85=D9=8F=D8=B9=D8=AA=D9=85=D8=AF =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=AC=D8=
=A7=D9=84 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=8C =D9=88=D9=8A=D9=8F=D8=B3=D8=
=AA=D8=AE=D8=AF=D9=85 =D8=A8=D8=AC=D8=B1=D8=B9=D8=A7=D8=AA =D8=AF=D9=82=D9=
=8A=D9=82=D8=A9 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=
=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1=D8=8C =D9=88=D8=B9=D9=84=D8=
=A7=D8=AC =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=A3=D8=
=AE=D8=B1=D9=89 =D9=85=D8=AB=D9=84 =D9=82=D8=B1=D8=AD=D8=A9 =D8=A7=D9=84=D9=
=85=D8=B9=D8=AF=D8=A9. =D8=B9=D9=86=D8=AF =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=
=A7=D9=85=D9=87 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D9=8A=D8=
=B9=D9=85=D9=84 =D8=B9=D9=84=D9=89 =D8=AA=D8=AD=D9=81=D9=8A=D8=B2 =D8=AA=D9=
=82=D9=84=D8=B5=D8=A7=D8=AA =D8=A7=D9=84=D8=B1=D8=AD=D9=85 =D9=88=D8=A5=D9=
=81=D8=B1=D8=A7=D8=BA =D9=85=D8=AD=D8=AA=D9=88=D9=8A=D8=A7=D8=AA=D9=87 =D8=
=AE=D9=84=D8=A7=D9=84 =D9=81=D8=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=
=A9=D8=8C =D9=85=D9=85=D8=A7 =D9=8A=D8=AC=D8=B9=D9=84=D9=87 =D8=AE=D9=8A=D8=
=A7=D8=B1=D9=8B=D8=A7 =D9=81=D8=B9=D8=A7=D9=84=D9=8B=D8=A7 =D9=88=D8=A2=D9=
=85=D9=86=D9=8B=D8=A7 =D8=B9=D9=86=D8=AF =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=
=B7=D8=A8=D9=8A=D8=A8 =D9=85=D8=AE=D8=AA=D8=B5.</span></p><p dir=3D"rtl" st=
yle=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 0pt;"></p><hr /><=
p></p><span dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 14pt; margi=
n-bottom: 4pt;"><span style=3D"font-size: 13pt; font-family: Arial, sans-se=
rif; color: rgb(0, 0, 0); background-color: transparent; font-weight: 700; =
font-variant-numeric: normal; font-variant-east-asian: normal; font-variant=
-alternates: normal; font-variant-position: normal; font-variant-emoji: nor=
mal; vertical-align: baseline; white-space-collapse: preserve;">=D8=A3=D9=
=87=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=
=89 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=86 =D9=85=D8=B5=D8=
=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82</span></span><p dir=3D"rtl" style=
=3D"line-height: 1.38; margin-top: 12pt; margin-bottom: 12pt;"><span style=
=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); b=
ackground-color: transparent; font-variant-numeric: normal; font-variant-ea=
st-asian: normal; font-variant-alternates: normal; font-variant-position: n=
ormal; font-variant-emoji: normal; vertical-align: baseline; white-space-co=
llapse: preserve;">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=
=D8=A9=D8=8C =D8=AA=D8=AA=D9=88=D8=A7=D8=AC=D8=AF =D8=A7=D9=84=D9=83=D8=AB=
=D9=8A=D8=B1 =D9=85=D9=86 =D8=A7=D9=84=D9=82=D9=86=D9=88=D8=A7=D8=AA =D8=BA=
=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=82=D8=A9 =D8=A7=D9=84=
=D8=AA=D9=8A =D8=AA=D8=A8=D9=8A=D8=B9 =D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =
=D9=85=D8=AC=D9=87=D9=88=D9=84=D8=A9 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =
=D9=82=D8=AF =D8=AA=D8=A4=D8=AF=D9=8A =D8=A5=D9=84=D9=89 =D9=85=D8=AE=D8=A7=
=D8=B7=D8=B1 =D8=B5=D8=AD=D9=8A=D8=A9 =D8=AC=D8=B3=D9=8A=D9=85=D8=A9.</span=
><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb=
(0, 0, 0); background-color: transparent; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; wh=
ite-space-collapse: preserve;"><br /></span><span style=3D"font-size: 11pt;=
 font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: tra=
nsparent; font-weight: 700; font-variant-numeric: normal; font-variant-east=
-asian: normal; font-variant-alternates: normal; font-variant-position: nor=
mal; font-variant-emoji: normal; vertical-align: baseline; white-space-coll=
apse: preserve;">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><span s=
tyle=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0=
); background-color: transparent; font-variant-numeric: normal; font-varian=
t-east-asian: normal; font-variant-alternates: normal; font-variant-positio=
n: normal; font-variant-emoji: normal; vertical-align: baseline; white-spac=
e-collapse: preserve;"> =D8=AA=D8=B6=D9=85=D9=86 =D9=84=D9=83:</span><span =
style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, =
0); background-color: transparent; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; white-spa=
ce-collapse: preserve;"><br /></span><span style=3D"font-size: 11pt; font-f=
amily: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transparen=
t; font-variant-numeric: normal; font-variant-east-asian: normal; font-vari=
ant-alternates: normal; font-variant-position: normal; font-variant-emoji: =
normal; vertical-align: baseline; white-space-collapse: preserve;">=E2=9C=
=94=EF=B8=8F </span><span style=3D"font-size: 11pt; font-family: Arial, san=
s-serif; color: rgb(0, 0, 0); background-color: transparent; font-weight: 7=
00; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; white-space-collapse: preserve;">=D8=AD=
=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=
=D9=84=D9=8A=D8=A9 100%</span><span style=3D"font-size: 11pt; font-family: =
Arial, sans-serif; color: rgb(0, 0, 0); background-color: transparent; font=
-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal=
; font-variant-alternates: normal; font-variant-position: normal; font-vari=
ant-emoji: normal; vertical-align: baseline; white-space-collapse: preserve=
;"><br /></span><span style=3D"font-size: 11pt; font-family: Arial, sans-se=
rif; color: rgb(0, 0, 0); background-color: transparent; font-variant-numer=
ic: normal; font-variant-east-asian: normal; font-variant-alternates: norma=
l; font-variant-position: normal; font-variant-emoji: normal; vertical-alig=
n: baseline; white-space-collapse: preserve;">=E2=9C=94=EF=B8=8F </span><sp=
an style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, =
0, 0); background-color: transparent; font-weight: 700; font-variant-numeri=
c: normal; font-variant-east-asian: normal; font-variant-alternates: normal=
; font-variant-position: normal; font-variant-emoji: normal; vertical-align=
: baseline; white-space-collapse: preserve;">=D8=AA=D8=A7=D8=B1=D9=8A=D8=AE=
 =D8=B5=D9=84=D8=A7=D8=AD=D9=8A=D8=A9 =D8=AD=D8=AF=D9=8A=D8=AB</span><span =
style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, =
0); background-color: transparent; font-weight: 700; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;"><br /></span><span style=3D"font-=
size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background=
-color: transparent; font-variant-numeric: normal; font-variant-east-asian:=
 normal; font-variant-alternates: normal; font-variant-position: normal; fo=
nt-variant-emoji: normal; vertical-align: baseline; white-space-collapse: p=
reserve;">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size: 11pt; font-fa=
mily: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transparent=
; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; vertical-align: baseline; white-space-collapse: pr=
eserve;">=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=
=A9 =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=
=AF=D8=A7=D9=85</span><span style=3D"font-size: 11pt; font-family: Arial, s=
ans-serif; color: rgb(0, 0, 0); background-color: transparent; font-weight:=
 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-v=
ariant-alternates: normal; font-variant-position: normal; font-variant-emoj=
i: normal; vertical-align: baseline; white-space-collapse: preserve;"><br /=
></span><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; col=
or: rgb(0, 0, 0); background-color: transparent; font-variant-numeric: norm=
al; font-variant-east-asian: normal; font-variant-alternates: normal; font-=
variant-position: normal; font-variant-emoji: normal; vertical-align: basel=
ine; white-space-collapse: preserve;">=E2=9C=94=EF=B8=8F </span><span style=
=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); b=
ackground-color: transparent; font-weight: 700; font-variant-numeric: norma=
l; font-variant-east-asian: normal; font-variant-alternates: normal; font-v=
ariant-position: normal; font-variant-emoji: normal; vertical-align: baseli=
ne; white-space-collapse: preserve;">=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=
=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84<=
/span><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; color=
: rgb(0, 0, 0); background-color: transparent; font-weight: 700; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;"><br /></span><span st=
yle=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0)=
; background-color: transparent; font-variant-numeric: normal; font-variant=
-east-asian: normal; font-variant-alternates: normal; font-variant-position=
: normal; font-variant-emoji: normal; vertical-align: baseline; white-space=
-collapse: preserve;">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size: 1=
1pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color:=
 transparent; font-weight: 700; font-variant-numeric: normal; font-variant-=
east-asian: normal; font-variant-alternates: normal; font-variant-position:=
 normal; font-variant-emoji: normal; vertical-align: baseline; white-space-=
collapse: preserve;">=D8=AF=D8=B9=D9=85 =D9=88=D8=A7=D8=B3=D8=AA=D8=B4=D8=
=A7=D8=B1=D8=A9 =D8=B9=D9=84=D9=89 =D9=85=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=
=B3=D8=A7=D8=B9=D8=A9</span></p><p dir=3D"rtl" style=3D"line-height: 1.38; =
margin-top: 0pt; margin-bottom: 0pt;"></p><hr /><p></p><span dir=3D"rtl" st=
yle=3D"line-height: 1.38; margin-top: 14pt; margin-bottom: 4pt;"><span styl=
e=3D"font-size: 13pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); =
background-color: transparent; font-weight: 700; font-variant-numeric: norm=
al; font-variant-east-asian: normal; font-variant-alternates: normal; font-=
variant-position: normal; font-variant-emoji: normal; vertical-align: basel=
ine; white-space-collapse: preserve;">=D9=84=D9=85=D8=A7=D8=B0=D8=A7 =D8=AA=
=D8=AE=D8=AA=D8=A7=D8=B1=D9=8A=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86=D8=9F</span></span><ul style=3D"margin-top: 0px; margin-bottom: 0px;=
 padding-inline-start: 48px;"><li dir=3D"rtl" style=3D"list-style-type: dis=
c; font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); ba=
ckground-color: transparent; font-variant-numeric: normal; font-variant-eas=
t-asian: normal; font-variant-alternates: normal; font-variant-position: no=
rmal; font-variant-emoji: normal; vertical-align: baseline; white-space: pr=
e;"><p dir=3D"rtl" style=3D"line-height: 1.38; text-align: right; margin-to=
p: 12pt; margin-bottom: 0pt;" role=3D"presentation"><span style=3D"font-siz=
e: 11pt; background-color: transparent; font-weight: 700; font-variant-nume=
ric: normal; font-variant-east-asian: normal; font-variant-alternates: norm=
al; font-variant-position: normal; font-variant-emoji: normal; vertical-ali=
gn: baseline; text-wrap-mode: wrap;">=D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9</span><span style=3D"font-size: 11pt; =
background-color: transparent; font-variant-numeric: normal; font-variant-e=
ast-asian: normal; font-variant-alternates: normal; font-variant-position: =
normal; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mod=
e: wrap;">: =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=85=D8=AA=D8=AE=
=D8=B5=D8=B5=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=
=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=86=
=D8=B3=D8=A7=D8=A6=D9=8A=D8=A9=D8=8C =D9=88=D8=AA=D9=82=D8=AF=D9=85 =D9=84=
=D9=83=D9=90 =D8=AF=D8=B9=D9=85=D9=8B=D8=A7 =D9=85=D9=87=D9=86=D9=8A=D9=8B=
=D8=A7 =D9=82=D8=A8=D9=84 =D9=88=D8=A3=D8=AB=D9=86=D8=A7=D8=A1 =D9=88=D8=A8=
=D8=B9=D8=AF</span><a href=3D"https://saudiersaa.com/"><span style=3D"font-=
size: 11pt; color: rgb(17, 85, 204); background-color: transparent; font-va=
riant-numeric: normal; font-variant-east-asian: normal; font-variant-altern=
ates: normal; font-variant-position: normal; font-variant-emoji: normal; te=
xt-decoration-line: underline; text-decoration-skip-ink: none; vertical-ali=
gn: baseline; text-wrap-mode: wrap;">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=
=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"=
font-size: 11pt; background-color: transparent; font-variant-numeric: norma=
l; font-variant-east-asian: normal; font-variant-alternates: normal; font-v=
ariant-position: normal; font-variant-emoji: normal; vertical-align: baseli=
ne; text-wrap-mode: wrap;">.</span><span style=3D"font-size: 11pt; backgrou=
nd-color: transparent; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;=
"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-style-type: dis=
c; font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); ba=
ckground-color: transparent; font-variant-numeric: normal; font-variant-eas=
t-asian: normal; font-variant-alternates: normal; font-variant-position: no=
rmal; font-variant-emoji: normal; vertical-align: baseline; white-space: pr=
e;"><p dir=3D"rtl" style=3D"line-height: 1.38; text-align: right; margin-to=
p: 0pt; margin-bottom: 0pt;" role=3D"presentation"><span style=3D"font-size=
: 11pt; background-color: transparent; font-weight: 700; font-variant-numer=
ic: normal; font-variant-east-asian: normal; font-variant-alternates: norma=
l; font-variant-position: normal; font-variant-emoji: normal; vertical-alig=
n: baseline; text-wrap-mode: wrap;">=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=
=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=D8=B9</span><span style=3D"font-size: 11=
pt; background-color: transparent; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; text-wrap=
-mode: wrap;">: =D8=AA=D8=BA=D8=B7=D9=8A=D8=A9 =D9=84=D8=AC=D9=85=D9=8A=D8=
=B9 =D8=A7=D9=84=D9=85=D8=AF=D9=86 =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=
=8A=D8=A9=D8=8C =D8=A8=D9=85=D8=A7 =D9=81=D9=8A =D8=B0=D9=84=D9=83 </span><=
span style=3D"font-size: 11pt; background-color: transparent; font-weight: =
700; font-variant-numeric: normal; font-variant-east-asian: normal; font-va=
riant-alternates: normal; font-variant-position: normal; font-variant-emoji=
: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=A7=D9=84=D8=
=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=
=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=A7=D9=84=D8=AE=D8=A8=D8=
=B1=D8=8C =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=D9=81</span><span style=3D"font-si=
ze: 11pt; background-color: transparent; font-variant-numeric: normal; font=
-variant-east-asian: normal; font-variant-alternates: normal; font-variant-=
position: normal; font-variant-emoji: normal; vertical-align: baseline; tex=
t-wrap-mode: wrap;"> =D9=88=D8=BA=D9=8A=D8=B1=D9=87=D8=A7.</span><span styl=
e=3D"font-size: 11pt; background-color: transparent; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; text-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl"=
 style=3D"list-style-type: disc; font-size: 11pt; font-family: Arial, sans-=
serif; color: rgb(0, 0, 0); background-color: transparent; font-variant-num=
eric: normal; font-variant-east-asian: normal; font-variant-alternates: nor=
mal; font-variant-position: normal; font-variant-emoji: normal; vertical-al=
ign: baseline; white-space: pre;"><p dir=3D"rtl" style=3D"line-height: 1.38=
; text-align: right; margin-top: 0pt; margin-bottom: 0pt;" role=3D"presenta=
tion"><span style=3D"font-size: 11pt; background-color: transparent; font-w=
eight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; =
font-variant-alternates: normal; font-variant-position: normal; font-varian=
t-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=AD=D9=
=85=D8=A7=D9=8A=D8=A9 =D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=AA=D9=83</span><spa=
n style=3D"font-size: 11pt; background-color: transparent; font-variant-num=
eric: normal; font-variant-east-asian: normal; font-variant-alternates: nor=
mal; font-variant-position: normal; font-variant-emoji: normal; vertical-al=
ign: baseline; text-wrap-mode: wrap;">: =D9=8A=D8=AA=D9=85 =D8=A7=D9=84=D8=
=AA=D8=BA=D9=84=D9=8A=D9=81 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=D8=A9 =D8=AA=D8=
=B6=D9=85=D9=86 =D8=A7=D9=84=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=A7=D9=84=D9=
=83=D8=A7=D9=85=D9=84=D8=A9.</span><span style=3D"font-size: 11pt; backgrou=
nd-color: transparent; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;=
"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-style-type: dis=
c; font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); ba=
ckground-color: transparent; font-variant-numeric: normal; font-variant-eas=
t-asian: normal; font-variant-alternates: normal; font-variant-position: no=
rmal; font-variant-emoji: normal; vertical-align: baseline; white-space: pr=
e;"><p dir=3D"rtl" style=3D"line-height: 1.38; text-align: right; margin-to=
p: 0pt; margin-bottom: 12pt;" role=3D"presentation"><span style=3D"font-siz=
e: 11pt; background-color: transparent; font-weight: 700; font-variant-nume=
ric: normal; font-variant-east-asian: normal; font-variant-alternates: norm=
al; font-variant-position: normal; font-variant-emoji: normal; vertical-ali=
gn: baseline; text-wrap-mode: wrap;">=D8=A7=D9=84=D8=AA=D9=88=D9=83=D9=8A=
=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A</span><span style=3D"font-size:=
 11pt; background-color: transparent; font-variant-numeric: normal; font-va=
riant-east-asian: normal; font-variant-alternates: normal; font-variant-pos=
ition: normal; font-variant-emoji: normal; vertical-align: baseline; text-w=
rap-mode: wrap;">: =D8=B4=D8=B1=D8=A7=D8=A1=D9=83 =D9=8A=D8=AA=D9=85 =D9=85=
=D8=A8=D8=A7=D8=B4=D8=B1=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=
=D8=B1 =D8=A7=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=8C =D8=A8=D8=B9=D9=8A=
=D8=AF=D9=8B=D8=A7 =D8=B9=D9=86 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1.=
</span><span style=3D"font-size: 11pt; background-color: transparent; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; text-wrap-mode: wrap;"><br /><br /></span></p></l=
i></ul><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-b=
ottom: 0pt;"></p><hr /><p></p><span dir=3D"rtl" style=3D"line-height: 1.38;=
 margin-top: 14pt; margin-bottom: 4pt;"><span style=3D"font-size: 13pt; fon=
t-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transpa=
rent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asi=
an: normal; font-variant-alternates: normal; font-variant-position: normal;=
 font-variant-emoji: normal; vertical-align: baseline; white-space-collapse=
: preserve;">=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=B7=D9=84=D8=A8 =D8=AD=D8=A8=
=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=86 =D8=AF=
. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span></span><ol style=3D"margin-top=
: 0px; margin-bottom: 0px; padding-inline-start: 48px;"><li dir=3D"rtl" sty=
le=3D"list-style-type: decimal; font-size: 11pt; font-family: Arial, sans-s=
erif; color: rgb(0, 0, 0); background-color: transparent; font-variant-nume=
ric: normal; font-variant-east-asian: normal; font-variant-alternates: norm=
al; font-variant-position: normal; font-variant-emoji: normal; vertical-ali=
gn: baseline; white-space: pre;"><p dir=3D"rtl" style=3D"line-height: 1.38;=
 text-align: right; margin-top: 12pt; margin-bottom: 0pt;" role=3D"presenta=
tion"><span style=3D"font-size: 11pt; background-color: transparent; font-w=
eight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; =
font-variant-alternates: normal; font-variant-position: normal; font-varian=
t-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=A7=D9=
=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D8=B9=D8=A8=D8=B1 =D9=88=D8=A7=D8=AA=D8=
=B3=D8=A7=D8=A8</span><span style=3D"font-size: 11pt; background-color: tra=
nsparent; font-variant-numeric: normal; font-variant-east-asian: normal; fo=
nt-variant-alternates: normal; font-variant-position: normal; font-variant-=
emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;"> =D8=B9=D9=
=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85: </span><span style=3D"font-size: =
11pt; background-color: transparent; font-weight: 700; font-variant-numeric=
: normal; font-variant-east-asian: normal; font-variant-alternates: normal;=
 font-variant-position: normal; font-variant-emoji: normal; vertical-align:=
 baseline; text-wrap-mode: wrap;">=F0=9F=93=9E 0537466539</span><span style=
=3D"font-size: 11pt; background-color: transparent; font-weight: 700; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; text-wrap-mode: wrap;"><br /><br /></span></p></l=
i><li dir=3D"rtl" style=3D"list-style-type: decimal; font-size: 11pt; font-=
family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transpare=
nt; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" style=
=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-bottom: 0=
pt;" role=3D"presentation"><span style=3D"font-size: 11pt; background-color=
: transparent; font-variant-numeric: normal; font-variant-east-asian: norma=
l; font-variant-alternates: normal; font-variant-position: normal; font-var=
iant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=B4=
=D8=B1=D8=AD =D8=A7=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D8=A7=D9=84=D8=B5=D8=AD=
=D9=8A=D8=A9 =D9=88=D9=81=D8=AA=D8=B1=D8=A9 =D8=A7=D9=84=D8=AD=D9=85=D9=84.=
</span><span style=3D"font-size: 11pt; background-color: transparent; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; text-wrap-mode: wrap;"><br /><br /></span></p></l=
i><li dir=3D"rtl" style=3D"list-style-type: decimal; font-size: 11pt; font-=
family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transpare=
nt; font-variant-numeric: normal; font-variant-east-asian: normal; font-var=
iant-alternates: normal; font-variant-position: normal; font-variant-emoji:=
 normal; vertical-align: baseline; white-space: pre;"><p dir=3D"rtl" style=
=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-bottom: 0=
pt;" role=3D"presentation"><span style=3D"font-size: 11pt; background-color=
: transparent; font-variant-numeric: normal; font-variant-east-asian: norma=
l; font-variant-alternates: normal; font-variant-position: normal; font-var=
iant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;">=D8=A7=
=D8=B3=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF=
=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D9=86=
=D8=A7=D8=B3=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D8=AC=D8=B1=D8=B9=D8=A9 =D8=A7=
=D9=84=D9=85=D9=88=D8=B5=D9=89 =D8=A8=D9=87=D8=A7.</span><span style=3D"fon=
t-size: 11pt; background-color: transparent; font-variant-numeric: normal; =
font-variant-east-asian: normal; font-variant-alternates: normal; font-vari=
ant-position: normal; font-variant-emoji: normal; vertical-align: baseline;=
 text-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=
=3D"list-style-type: decimal; font-size: 11pt; font-family: Arial, sans-ser=
if; color: rgb(0, 0, 0); background-color: transparent; font-variant-numeri=
c: normal; font-variant-east-asian: normal; font-variant-alternates: normal=
; font-variant-position: normal; font-variant-emoji: normal; vertical-align=
: baseline; white-space: pre;"><p dir=3D"rtl" style=3D"line-height: 1.38; t=
ext-align: right; margin-top: 0pt; margin-bottom: 12pt;" role=3D"presentati=
on"><span style=3D"font-size: 11pt; background-color: transparent; font-var=
iant-numeric: normal; font-variant-east-asian: normal; font-variant-alterna=
tes: normal; font-variant-position: normal; font-variant-emoji: normal; ver=
tical-align: baseline; text-wrap-mode: wrap;">=D8=A7=D8=B3=D8=AA=D9=84=D8=
=A7=D9=85 =D8=A7=D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=AE=D9=84=D8=A7=D9=84 =D9=
=81=D8=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=A9 =D8=B9=D8=A8=D8=B1 =D8=
=AE=D8=AF=D9=85=D8=A9 =D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A2=D9=85=D9=86=D8=
=A9 =D9=88=D8=B3=D8=B1=D9=8A=D8=A9.</span><span style=3D"font-size: 11pt; b=
ackground-color: transparent; font-variant-numeric: normal; font-variant-ea=
st-asian: normal; font-variant-alternates: normal; font-variant-position: n=
ormal; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode=
: wrap;"><br /><br /></span></p></li></ol><p dir=3D"rtl" style=3D"line-heig=
ht: 1.38; margin-top: 0pt; margin-bottom: 0pt;"></p><hr /><p></p><span dir=
=3D"rtl" style=3D"line-height: 1.38; margin-top: 14pt; margin-bottom: 4pt;"=
><span style=3D"font-size: 13pt; font-family: Arial, sans-serif; color: rgb=
(0, 0, 0); background-color: transparent; font-weight: 700; font-variant-nu=
meric: normal; font-variant-east-asian: normal; font-variant-alternates: no=
rmal; font-variant-position: normal; font-variant-emoji: normal; vertical-a=
lign: baseline; white-space-collapse: preserve;">=D8=AA=D9=86=D8=A8=D9=8A=
=D9=87 =D8=B7=D8=A8=D9=8A =D9=85=D9=87=D9=85</span></span><ul style=3D"marg=
in-top: 0px; margin-bottom: 0px; padding-inline-start: 48px;"><li dir=3D"rt=
l" style=3D"list-style-type: disc; font-size: 11pt; font-family: Arial, san=
s-serif; color: rgb(0, 0, 0); background-color: transparent; font-variant-n=
umeric: normal; font-variant-east-asian: normal; font-variant-alternates: n=
ormal; font-variant-position: normal; font-variant-emoji: normal; vertical-=
align: baseline; white-space: pre;"><p dir=3D"rtl" style=3D"line-height: 1.=
38; text-align: right; margin-top: 12pt; margin-bottom: 0pt;" role=3D"prese=
ntation"><span style=3D"font-size: 11pt; background-color: transparent; fon=
t-variant-numeric: normal; font-variant-east-asian: normal; font-variant-al=
ternates: normal; font-variant-position: normal; font-variant-emoji: normal=
; vertical-align: baseline; text-wrap-mode: wrap;">=D9=8A=D8=AC=D8=A8 =D8=
=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=81=D9=82=D8=B7 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=
=81 =D8=B7=D8=A8=D9=8A =D9=85=D8=AE=D8=AA=D8=B5.</span><span style=3D"font-=
size: 11pt; background-color: transparent; font-variant-numeric: normal; fo=
nt-variant-east-asian: normal; font-variant-alternates: normal; font-varian=
t-position: normal; font-variant-emoji: normal; vertical-align: baseline; t=
ext-wrap-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"=
list-style-type: disc; font-size: 11pt; font-family: Arial, sans-serif; col=
or: rgb(0, 0, 0); background-color: transparent; font-variant-numeric: norm=
al; font-variant-east-asian: normal; font-variant-alternates: normal; font-=
variant-position: normal; font-variant-emoji: normal; vertical-align: basel=
ine; white-space: pre;"><p dir=3D"rtl" style=3D"line-height: 1.38; text-ali=
gn: right; margin-top: 0pt; margin-bottom: 0pt;" role=3D"presentation"><spa=
n style=3D"font-size: 11pt; background-color: transparent; font-variant-num=
eric: normal; font-variant-east-asian: normal; font-variant-alternates: nor=
mal; font-variant-position: normal; font-variant-emoji: normal; vertical-al=
ign: baseline; text-wrap-mode: wrap;">=D9=84=D8=A7 =D9=8A=D9=8F=D9=86=D8=B5=
=D8=AD =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D9=81=D9=8A =
=D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=
=D9=85=D8=AA=D8=A3=D8=AE=D8=B1.</span><span style=3D"font-size: 11pt; backg=
round-color: transparent; font-variant-numeric: normal; font-variant-east-a=
sian: normal; font-variant-alternates: normal; font-variant-position: norma=
l; font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wr=
ap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-style-type: =
disc; font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0);=
 background-color: transparent; font-variant-numeric: normal; font-variant-=
east-asian: normal; font-variant-alternates: normal; font-variant-position:=
 normal; font-variant-emoji: normal; vertical-align: baseline; white-space:=
 pre;"><p dir=3D"rtl" style=3D"line-height: 1.38; text-align: right; margin=
-top: 0pt; margin-bottom: 12pt;" role=3D"presentation"><span style=3D"font-=
size: 11pt; background-color: transparent; font-variant-numeric: normal; fo=
nt-variant-east-asian: normal; font-variant-alternates: normal; font-varian=
t-position: normal; font-variant-emoji: normal; vertical-align: baseline; t=
ext-wrap-mode: wrap;">=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =D9=88=D8=AC=D9=88=D8=
=AF =D8=A3=D9=85=D8=B1=D8=A7=D8=B6 =D9=85=D8=B2=D9=85=D9=86=D8=A9 =D8=A3=D9=
=88 =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=B5=D8=A9=D8=8C =D9=8A=D8=
=AC=D8=A8 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B7=D8=
=A8=D9=8A=D8=A8 =D9=82=D8=A8=D9=84 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=
=AF=D8=A7=D9=85.</span><span style=3D"font-size: 11pt; background-color: tr=
ansparent; font-variant-numeric: normal; font-variant-east-asian: normal; f=
ont-variant-alternates: normal; font-variant-position: normal; font-variant=
-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap;"><br /><br =
/></span></p></li></ul><p dir=3D"rtl" style=3D"line-height: 1.38; margin-to=
p: 0pt; margin-bottom: 0pt;"></p><hr /><p></p><span dir=3D"rtl" style=3D"li=
ne-height: 1.38; margin-top: 14pt; margin-bottom: 4pt;"><span style=3D"font=
-size: 13pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); backgroun=
d-color: transparent; font-weight: 700; font-variant-numeric: normal; font-=
variant-east-asian: normal; font-variant-alternates: normal; font-variant-p=
osition: normal; font-variant-emoji: normal; vertical-align: baseline; whit=
e-space-collapse: preserve;">=D8=AE=D8=AF=D9=85=D8=A7=D8=AA =D8=A5=D8=B6=D8=
=A7=D9=81=D9=8A=D8=A9 =D9=85=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86</span></span><ul style=3D"margin-top: 0px; margin-bottom: 0px; paddi=
ng-inline-start: 48px;"><li dir=3D"rtl" style=3D"list-style-type: disc; fon=
t-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); backgrou=
nd-color: transparent; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; white-space: pre;"><p=
 dir=3D"rtl" style=3D"line-height: 1.38; text-align: right; margin-top: 12p=
t; margin-bottom: 0pt;" role=3D"presentation"><span style=3D"font-size: 11p=
t; background-color: transparent; font-variant-numeric: normal; font-varian=
t-east-asian: normal; font-variant-alternates: normal; font-variant-positio=
n: normal; font-variant-emoji: normal; vertical-align: baseline; text-wrap-=
mode: wrap;">=D9=85=D8=AA=D8=A7=D8=A8=D8=B9=D8=A9 =D8=A7=D9=84=D8=AD=D8=A7=
=D9=84=D8=A9 =D8=A8=D8=B9=D8=AF =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=
=D8=A7=D9=85.</span><span style=3D"font-size: 11pt; background-color: trans=
parent; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; text-wrap-mode: wrap;"><br /><br /><=
/span></p></li><li dir=3D"rtl" style=3D"list-style-type: disc; font-size: 1=
1pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color:=
 transparent; font-variant-numeric: normal; font-variant-east-asian: normal=
; font-variant-alternates: normal; font-variant-position: normal; font-vari=
ant-emoji: normal; vertical-align: baseline; white-space: pre;"><p dir=3D"r=
tl" style=3D"line-height: 1.38; text-align: right; margin-top: 0pt; margin-=
bottom: 0pt;" role=3D"presentation"><span style=3D"font-size: 11pt; backgro=
und-color: transparent; font-variant-numeric: normal; font-variant-east-asi=
an: normal; font-variant-alternates: normal; font-variant-position: normal;=
 font-variant-emoji: normal; vertical-align: baseline; text-wrap-mode: wrap=
;">=D8=AA=D9=88=D9=81=D9=8A=D8=B1 =D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=
=AA =D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=A2=D8=AB=D8=A7=D8=B1 =D8=A7=D9=84=D8=
=AC=D8=A7=D9=86=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=B9=D9=
=8A=D8=A9 =D9=88=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D8=B9=D8=
=A7=D9=85=D9=84 =D9=85=D8=B9=D9=87=D8=A7.</span><span style=3D"font-size: 1=
1pt; background-color: transparent; font-variant-numeric: normal; font-vari=
ant-east-asian: normal; font-variant-alternates: normal; font-variant-posit=
ion: normal; font-variant-emoji: normal; vertical-align: baseline; text-wra=
p-mode: wrap;"><br /><br /></span></p></li><li dir=3D"rtl" style=3D"list-st=
yle-type: disc; font-size: 11pt; font-family: Arial, sans-serif; color: rgb=
(0, 0, 0); background-color: transparent; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; wh=
ite-space: pre;"><p dir=3D"rtl" style=3D"line-height: 1.38; text-align: rig=
ht; margin-top: 0pt; margin-bottom: 12pt;" role=3D"presentation"><span styl=
e=3D"font-size: 11pt; background-color: transparent; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; text-wrap-mode: wrap;">=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=84=
=D9=85=D8=B1=D9=8A=D8=B6=D8=A9 =D8=A5=D9=84=D9=89 =D8=A3=D9=81=D8=B6=D9=84 =
=D9=85=D9=85=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=B3=D9=84=D8=A7=
=D9=85=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9.</span><span style=3D"fon=
t-size: 11pt; background-color: transparent; font-variant-numeric: normal; =
font-variant-east-asian: normal; font-variant-alternates: normal; font-vari=
ant-position: normal; font-variant-emoji: normal; vertical-align: baseline;=
 text-wrap-mode: wrap;"><br /><br /></span></p></li></ul><p dir=3D"rtl" sty=
le=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 0pt;"></p><hr /><p=
></p><span dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 14pt; margin=
-bottom: 4pt;"><span style=3D"font-size: 13pt; font-family: Arial, sans-ser=
if; color: rgb(0, 0, 0); background-color: transparent; font-weight: 700; f=
ont-variant-numeric: normal; font-variant-east-asian: normal; font-variant-=
alternates: normal; font-variant-position: normal; font-variant-emoji: norm=
al; vertical-align: baseline; white-space-collapse: preserve;">=D8=AE=D9=84=
=D8=A7=D8=B5=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height: 1.38; =
margin-top: 12pt; margin-bottom: 12pt;"><span style=3D"font-size: 11pt; fon=
t-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transpa=
rent; font-variant-numeric: normal; font-variant-east-asian: normal; font-v=
ariant-alternates: normal; font-variant-position: normal; font-variant-emoj=
i: normal; vertical-align: baseline; white-space-collapse: preserve;">=D8=
=A7=D8=AE=D8=AA=D9=8A=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D8=
=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=82 =D8=B9=D9=86=D8=AF</span><a href=3D=
"https://groups.google.com/a/chromium.org/g/security-dev/c/rhrPpivCQGM/m/Xi=
hUBiSLAAAJ"><span style=3D"font-size: 11pt; font-family: Arial, sans-serif;=
 color: rgb(0, 0, 0); background-color: transparent; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;"> </span><span style=3D"font-size:=
 11pt; font-family: Arial, sans-serif; color: rgb(17, 85, 204); background-=
color: transparent; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; text-decoration-line: underline; text-decoration-s=
kip-ink: none; vertical-align: baseline; white-space-collapse: preserve;">=
=D8=B4=D8=B1=D8=A7=D8=A1 </span><span style=3D"font-size: 11pt; font-family=
: Arial, sans-serif; color: rgb(17, 85, 204); background-color: transparent=
; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: =
normal; font-variant-alternates: normal; font-variant-position: normal; fon=
t-variant-emoji: normal; text-decoration-line: underline; text-decoration-s=
kip-ink: none; vertical-align: baseline; white-space-collapse: preserve;">=
=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span><=
/a><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: r=
gb(0, 0, 0); background-color: transparent; font-variant-numeric: normal; f=
ont-variant-east-asian: normal; font-variant-alternates: normal; font-varia=
nt-position: normal; font-variant-emoji: normal; vertical-align: baseline; =
white-space-collapse: preserve;"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=
=88=D8=AF=D9=8A=D8=A9 =D9=87=D9=88 =D8=A7=D9=84=D8=B6=D9=85=D8=A7=D9=86 =D8=
=A7=D9=84=D9=88=D8=AD=D9=8A=D8=AF =D9=84=D8=B3=D9=84=D8=A7=D9=85=D8=AA=D9=
=83=D9=90.</span><span style=3D"font-size: 11pt; font-family: Arial, sans-s=
erif; color: rgb(0, 0, 0); background-color: transparent; font-variant-nume=
ric: normal; font-variant-east-asian: normal; font-variant-alternates: norm=
al; font-variant-position: normal; font-variant-emoji: normal; vertical-ali=
gn: baseline; white-space-collapse: preserve;"><br /></span><span style=3D"=
font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); backg=
round-color: transparent; font-variant-numeric: normal; font-variant-east-a=
sian: normal; font-variant-alternates: normal; font-variant-position: norma=
l; font-variant-emoji: normal; vertical-align: baseline; white-space-collap=
se: preserve;">=D9=85=D8=B9 </span><span style=3D"font-size: 11pt; font-fam=
ily: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transparent;=
 font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: n=
ormal; font-variant-alternates: normal; font-variant-position: normal; font=
-variant-emoji: normal; vertical-align: baseline; white-space-collapse: pre=
serve;">=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><span style=3D"f=
ont-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); backgr=
ound-color: transparent; font-variant-numeric: normal; font-variant-east-as=
ian: normal; font-variant-alternates: normal; font-variant-position: normal=
; font-variant-emoji: normal; vertical-align: baseline; white-space-collaps=
e: preserve;">=D8=8C =D8=B3=D8=AA=D8=AD=D8=B5=D9=84=D9=8A=D9=86 =D8=B9=D9=
=84=D9=89 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=
=84=D9=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=84=D8=
=B7=D8=A8=D9=8A =D8=A7=D9=84=D9=85=D8=AA=D8=AE=D8=B5=D8=B5=D8=8C =D9=88=D8=
=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A =D8=
=A3=D9=8A=D9=86=D9=85=D8=A7 =D9=83=D9=86=D8=AA=D9=90 =D9=81=D9=8A =D8=A7=D9=
=84=D9=85=D9=85=D9=84=D9=83=D8=A9.</span></p><p dir=3D"rtl" style=3D"line-h=
eight: 1.38; margin-top: 12pt; margin-bottom: 12pt;"><span style=3D"font-si=
ze: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-c=
olor: transparent; font-variant-numeric: normal; font-variant-east-asian: n=
ormal; font-variant-alternates: normal; font-variant-position: normal; font=
-variant-emoji: normal; vertical-align: baseline; white-space-collapse: pre=
serve;">=F0=9F=93=9E =D9=84=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=88=D8=
=A7=D9=84=D8=B7=D9=84=D8=A8 =D8=B9=D8=A8=D8=B1 =D9=88=D8=A7=D8=AA=D8=B3=D8=
=A7=D8=A8: </span><span style=3D"font-size: 11pt; font-family: Arial, sans-=
serif; color: rgb(0, 0, 0); background-color: transparent; font-weight: 700=
; font-variant-numeric: normal; font-variant-east-asian: normal; font-varia=
nt-alternates: normal; font-variant-position: normal; font-variant-emoji: n=
ormal; vertical-align: baseline; white-space-collapse: preserve;">053746653=
9</span><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; col=
or: rgb(0, 0, 0); background-color: transparent; font-weight: 700; font-var=
iant-numeric: normal; font-variant-east-asian: normal; font-variant-alterna=
tes: normal; font-variant-position: normal; font-variant-emoji: normal; ver=
tical-align: baseline; white-space-collapse: preserve;"><br /></span><span =
style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, =
0); background-color: transparent; font-weight: 700; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;">=D8=A7=D9=84=D9=85=D8=AF=D9=86 =
=D8=A7=D9=84=D9=85=D8=BA=D8=B7=D8=A7=D8=A9</span><span style=3D"font-size: =
11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color=
: transparent; font-variant-numeric: normal; font-variant-east-asian: norma=
l; font-variant-alternates: normal; font-variant-position: normal; font-var=
iant-emoji: normal; vertical-align: baseline; white-space-collapse: preserv=
e;">: =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =E2=80=93 =D8=AC=D8=AF=D8=A9 =E2=
=80=93 =D9=85=D9=83=D8=A9 =E2=80=93 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =
=E2=80=93 =D8=A7=D9=84=D8=AE=D8=A8=D8=B1 =E2=80=93 =D8=A7=D9=84=D8=B7=D8=A7=
=D8=A6=D9=81 =E2=80=93 =D8=A7=D9=84=D9=85=D8=AF=D9=8A=D9=86=D8=A9 =D8=A7=D9=
=84=D9=85=D9=86=D9=88=D8=B1=D8=A9 =E2=80=93 =D8=A3=D8=A8=D9=87=D8=A7 =E2=80=
=93 =D8=AC=D8=A7=D8=B2=D8=A7=D9=86 =E2=80=93 =D8=AA=D8=A8=D9=88=D9=83.</spa=
n></p><p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bo=
ttom: 0pt;"></p><hr /><p></p><span dir=3D"rtl" style=3D"line-height: 1.38; =
margin-top: 18pt; margin-bottom: 4pt;"><span style=3D"font-size: 17pt; font=
-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transpar=
ent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; white-space-collapse:=
 preserve;">=C2=A0</span></span><p dir=3D"rtl" style=3D"line-height: 1.38; =
margin-top: 12pt; margin-bottom: 12pt;"><span style=3D"font-size: 11pt; fon=
t-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transpa=
rent; font-variant-numeric: normal; font-variant-east-asian: normal; font-v=
ariant-alternates: normal; font-variant-position: normal; font-variant-emoj=
i: normal; vertical-align: baseline; white-space-collapse: preserve;">=D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=
=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=85=D9=83=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=B4=D8=B1=D8=A7=D8=A1 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=
=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=
=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=D8=
=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200=D8=8C Misoprostol =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D9=86=D9=87=D8=AF=D9=8A=D8=8C</span><a href=
=3D"https://ksacytotec.com/"><span style=3D"font-size: 11pt; font-family: A=
rial, sans-serif; color: rgb(0, 0, 0); background-color: transparent; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; white-space-collapse: preserve;"> </span><span st=
yle=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(17, 85, =
204); background-color: transparent; font-variant-numeric: normal; font-var=
iant-east-asian: normal; font-variant-alternates: normal; font-variant-posi=
tion: normal; font-variant-emoji: normal; text-decoration-line: underline; =
text-decoration-skip-ink: none; vertical-align: baseline; white-space-colla=
pse: preserve;">https://ksacytotec.com/</span></a><span style=3D"font-size:=
 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-colo=
r: transparent; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;"> =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =
=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83.</span></p><p dir=3D"rtl" style=
=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: 0pt;"><span style=3D=
"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); back=
ground-color: transparent; font-variant-numeric: normal; font-variant-east-=
asian: normal; font-variant-alternates: normal; font-variant-position: norm=
al; font-variant-emoji: normal; vertical-align: baseline; white-space-colla=
pse: preserve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=
=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=B3=D8=
=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=A9=D8=8C =D8=B3=D8=A7=D9=
=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=83=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =D8=B4=D8=
=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=
=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AD=D8=A8=D9=88=D8=
=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=D8=AC=D9=
=87=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=
=B5=D9=84=D9=8A=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200=D8=8C =
Misoprostol =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D9=86=D9=87=D8=AF=D9=8A=
=D8=8C =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=D8=A8=
=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =
=D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83.</span></p><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/412ffb42-69a2-4d34-9ea5-6aa53dd58711n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/412ffb42-69a2-4d34-9ea5-6aa53dd58711n%40googlegroups.com</a>.<br />

------=_Part_193411_1618170486.1755418769242--

------=_Part_193410_1403602685.1755418769242--
