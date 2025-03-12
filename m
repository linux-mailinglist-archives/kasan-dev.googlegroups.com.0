Return-Path: <kasan-dev+bncBCM4ZDFL6MFRBKEHYS7AMGQEU2FAQ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 56CCBA5D4D8
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Mar 2025 04:46:50 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5feb2ce9b27sf4642931eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Mar 2025 20:46:50 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741751209; x=1742356009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h4kdvgvFonjML4bh22uDQxPo0f1bFrLHffEaxysluno=;
        b=UhXg03oAdL095qJMpVcHxA5HYSROsS70EjqPJ5nW/0PnprRbisI3T9NqbCC9wABgKn
         h+ILuiFMWnnYfKJfC5rZIb1m5rbg3uh76DaAE45F/KBSXbB9ETa9zla9XJvIw5Weti/V
         AYSUCS0/CvYdYFYXJDtfpA8QvkeMOxPnw16qU2on9NgsPhYnxceH2GXZjX8rh+hss6gH
         NsxZHa4PyCLmb3o6dQpim3Eu04KYft5mE4bxn9s0cWI/4mUaYo5LRhUY/yVo5Hj1oZkz
         3Bv3nydlUAyjZleCzkeSvSBZwcFNPjgPeAi8GkWlvwkRjJBDzmV42yZ3E1cq4XKAhZWK
         tGhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741751209; x=1742356009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h4kdvgvFonjML4bh22uDQxPo0f1bFrLHffEaxysluno=;
        b=A97wV6lJLZisHy8lneSNzbgL1ZItVYQNI7nbEe0OLfsGe3bO0PQFqQ/FGv9WsntZKE
         Nyu576aGywrOFjRrbIQUG0Fp/vBMT8VCE9w5RFDa88Cu1QaniD2i0qPtz7C9ygItcprx
         bOxoEhgZoS/QsaFOaKUNE59cPCGDV90b774y6j7YPj3EdKXGoZ3xmxuftqjYDqm9JP0a
         fkwSX9ZXSfzubeO3C+mhMd2OCgyyTcAYUIysAZaraEOjCgefhUDG6dVPDj70lFMfuUgZ
         okb6h993eKedhAPD2YaJaIIfuFgot1k+nKE5O+zDUI+c2dkuWuJ96T9rU4JP2zGh7eeb
         vP5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXeCnwLYlb2rzjDc2lVjBejNttY8rkjpMzsIpYApMOmK4yK6UWR27hqMxgDd2PKgYYhT4HeBA==@lfdr.de
X-Gm-Message-State: AOJu0YwSM1Otr0UGM1BPA75iC7ckS4Gol/cMdafN1Z5Nzizuk74CAmQn
	+wvOMpf9xTvDtOk7GfRugqxf9tWhm8nwVmirxl3NAYtpabtUsoeW
X-Google-Smtp-Source: AGHT+IFEffBfGX4xTK93XboKQbMR/I3vQITDmuFjuKRpNei9DyE7Gey7R0AnP1eBuu0PZFfci+UWIg==
X-Received: by 2002:a05:6820:992:b0:601:af0a:20ca with SMTP id 006d021491bc7-601af0a214dmr4693849eaf.5.1741751208824;
        Tue, 11 Mar 2025 20:46:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEQcG2+/5IZZHMcr5b2ZYaWyFMCZK4Pve4Avy48AP/Cpw==
Received: by 2002:a4a:bb12:0:b0:601:15b5:c385 with SMTP id 006d021491bc7-60115b5c4b0ls589772eaf.1.-pod-prod-08-us;
 Tue, 11 Mar 2025 20:46:48 -0700 (PDT)
X-Received: by 2002:a05:6808:188f:b0:3f6:692c:d159 with SMTP id 5614622812f47-3f697c18f08mr11565220b6e.39.1741751207633;
        Tue, 11 Mar 2025 20:46:47 -0700 (PDT)
Date: Tue, 11 Mar 2025 20:46:46 -0700 (PDT)
From: =?UTF-8?B?2KfZh9mE2Kcg2KjZg9mF?= <zz.a1@hotmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <da1c2d3c-63e6-49aa-b59f-d8fbe554e4a4n@googlegroups.com>
Subject: =?UTF-8?Q?cytotec_abortion_009715620?=
 =?UTF-8?Q?51608_=D8=AD=D8=A8=D9=88=D8=A8_=D8=A7=D9=84?=
 =?UTF-8?Q?=D8=A7=D8=AC=D9=87=D8=A7=D8=B6_=D8=B3?=
 =?UTF-8?Q?=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_91892_1665337435.1741751206748"
X-Original-Sender: zz.a1@hotmail.com
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

------=_Part_91892_1665337435.1741751206748
Content-Type: multipart/alternative; 
	boundary="----=_Part_91893_1331847693.1741751206748"

------=_Part_91893_1331847693.1741751206748
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2KfYrdi12YQg2LnZhNmJINit2KjZiNioINiz2KfZitiq2YjYqtmK2YMg2KfZhNii2YYg2KjYo9iz
2LnYp9ixINmF2YbYp9iz2KjYqSDZiNio2LPZh9mI2YTYqSDZgdmKINmC2LfYsdiMINin2YTYs9i5
2YjYr9mK2KnYjCAK2KfZhNil2YXYp9ix2KfYqtiMINmI2KfZhNmD2YjZitiqISDYqtiz2KfYudiv
2YMg2KfZhNit2KjZiNioINmB2Yog2KXYrNmH2KfYtiDYp9mE2K3ZhdmEINio2LfYsdmK2YLYqSDY
otmF2YbYqSDZiNmB2LnYp9mE2KkuINmD2YQg2YXYpyAK2LnZhNmK2YMg2YfZiCDYp9mE2KfYqti1
2KfZhCDYqNmG2Kcg2KfZhNii2YYg2LnZhNmJINin2YTYsdmC2YUg8J+TniAgMDA5NzE1NjIwNTE2
MDggICDZhNiq2LfZhNioINit2KjZiNioINiz2KfZitiq2YjYqtmDLiAK2YTYpyDYr9in2LnZiiDZ
hNmE2YLZhNmC2Iwg2K3ZhNmDINmH2Ygg2KjYqNiz2KfYt9ipINij2YXYp9mF2YMuINin2KrYtdmE
INio2YbYpyDYp9mE2KLZhiEKCvCfjL/wn5S0INit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTY
qNmK2Lkg2YHZiiDZgti32LEg2YjYp9mE2KXZhdin2LHYp9iqIC0g2KfYt9mE2KjZh9inINin2YTY
otmGISDwn4y/MDA5NzE1NjIwNTE2MDgg8J+TniAK2YjYp9iq2LPYp9ioINin2LPYqtiu2K/Yp9mF
INit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2KrZhti42YrZgSDYp9mE2LHYrdmFIwoj2K3YqNmI
2Kgg2KfZhNin2KzZh9in2LYgIwrYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiAKI9it2KjZiNioINin
2YTYp9is2YfYp9i2ICMKI9in2KzZh9in2LYgIwoj2KfYrNmH2KfYtiDYp9mE2K3ZhdmEIwoj2K3Y
qNmI2Kgg2KfYrNmH2KfYtiMKI9it2KjZiNioINin2YTYp9is2YfYp9i2ICMK2K3YqNmI2Kgg2KfZ
hNin2KzZh9in2LYgCiPYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiAjCiPYp9is2YfYp9i2ICMKI9in
2KzZh9in2LYg2KfZhNit2YXZhCMKI9it2KjZiNioINin2KzZh9in2LYjCgrYt9ix2YrZgtipINin
2LPYqtiu2K/YpyPYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiAjCtit2KjZiNioINin2YTYp9is2YfY
p9i2IAoj2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYgIwoj2KfYrNmH2KfYtiAjCiPYp9is2YfYp9i2
INin2YTYrdmF2YQjCiPYrdio2YjYqCDYp9is2YfYp9i2IwrZhSDYrdio2YjYqCDYs9in2YrYqtmI
2KrZgyMKCtiz2KfZitiq2YjYqtmDICPZhdmK2LLZiNiq2KfZgyDYrdio2YjYqF/Ys9in2YrYqtmI
2KrZg1/Yp9mE2KfYtdmE2YrZhyDYrdio2YjYqCAj2LPYp9mK2KrZiNiq2YMgI9in2YTYp9i12YTZ
itmHINin2YTYp9mF2KfYsdin2KoKCtit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTYp9i12YTZ
itmHINmI2KfZhNiq2YLZhNmK2K8jCgrYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2KfYtdmE
2Yog2YjYp9mE2KrZgtmE2YrYryMKI9it2KjZiNioINin2YTYp9is2YfYp9i2ICMK2K3YqNmI2Kgg
2KfZhNin2KzZh9in2LYgCiPYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiAjCiPYp9is2YfYp9i2ICMK
I9in2KzZh9in2LYg2KfZhNit2YXZhCMKI9it2KjZiNioINin2KzZh9in2LYjCgrYt9ix2YrZgtip
X9in2LPYqtiu2K/Yp9mFX9it2KjZiNioX9iz2KfZitiq2YjYqtmDINi32LHZitmC2Kkg2KfYs9iq
2K7Yr9in2YUg2K3YqNmI2KggI9iz2KfZitiq2YjYqtmDX9mE2YTYp9is2YfYp9i2IwoK2LfYsdmK
2YLZh1/Yp9iz2KrYrtiv2KfZhV/Yrdio2YjYqF/Ys9in2YrYqtmI2KrZg1/ZgdmKX9in2YTYtNmH
2LFf2KfZhNin2YjZhNi32LHZitmC2Kkg2KfYs9iq2K7Yr9in2YUgI9it2KjZiNioINiz2KfZitiq
2YjYqtmDIArZhNmE2KfYrNmH2KfYtiDZgdmKINin2YTYtNmH2LEg2KfZhNin2YjZhA0KDQotLSAK
WW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0
aGUgR29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0
aGlzIGdyb3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFp
bCB0byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlz
IGRpc2N1c3Npb24gdmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2Fu
LWRldi9kYTFjMmQzYy02M2U2LTQ5YWEtYjU5Zi1kOGZiZTU1NGU0YTRuJTQwZ29vZ2xlZ3JvdXBz
LmNvbS4K
------=_Part_91893_1331847693.1741751206748
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2KfYrdi12YQg2LnZhNmJINit2KjZiNioINiz2KfZitiq2YjYqtmK2YMg2KfZhNii2YYg2KjYo9iz
2LnYp9ixINmF2YbYp9iz2KjYqSDZiNio2LPZh9mI2YTYqSDZgdmKINmC2LfYsdiMINin2YTYs9i5
2YjYr9mK2KnYjCDYp9mE2KXZhdin2LHYp9iq2Iwg2YjYp9mE2YPZiNmK2KohINiq2LPYp9i52K/Z
gyDYp9mE2K3YqNmI2Kgg2YHZiiDYpdis2YfYp9i2INin2YTYrdmF2YQg2KjYt9ix2YrZgtipINii
2YXZhtipINmI2YHYudin2YTYqS4g2YPZhCDZhdinINi52YTZitmDINmH2Ygg2KfZhNin2KrYtdin
2YQg2KjZhtinINin2YTYotmGINi52YTZiSDYp9mE2LHZgtmFIPCfk54gwqAwMDk3MTU2MjA1MTYw
OCDCoCDZhNiq2LfZhNioINit2KjZiNioINiz2KfZitiq2YjYqtmDLiDZhNinINiv2KfYudmKINmE
2YTZgtmE2YLYjCDYrdmE2YMg2YfZiCDYqNio2LPYp9i32Kkg2KPZhdin2YXZgy4g2KfYqti12YQg
2KjZhtinINin2YTYotmGITxiciAvPjxiciAvPvCfjL/wn5S0INit2KjZiNioINiz2KfZitiq2YjY
qtmDINmE2YTYqNmK2Lkg2YHZiiDZgti32LEg2YjYp9mE2KXZhdin2LHYp9iqIC0g2KfYt9mE2KjZ
h9inINin2YTYotmGISDwn4y/MDA5NzE1NjIwNTE2MDgg8J+TniDZiNin2KrYs9in2Kgg2KfYs9iq
2K7Yr9in2YUg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTYqtmG2LjZitmBINin2YTYsdit2YUj
PGJyIC8+I9it2KjZiNioINin2YTYp9is2YfYp9i2ICM8YnIgLz7Yrdio2YjYqCDYp9mE2KfYrNmH
2KfYtiA8YnIgLz4j2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYgIzxiciAvPiPYp9is2YfYp9i2ICM8
YnIgLz4j2KfYrNmH2KfYtiDYp9mE2K3ZhdmEIzxiciAvPiPYrdio2YjYqCDYp9is2YfYp9i2Izxi
ciAvPiPYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiAjPGJyIC8+2K3YqNmI2Kgg2KfZhNin2KzZh9in
2LYgPGJyIC8+I9it2KjZiNioINin2YTYp9is2YfYp9i2ICM8YnIgLz4j2KfYrNmH2KfYtiAjPGJy
IC8+I9in2KzZh9in2LYg2KfZhNit2YXZhCM8YnIgLz4j2K3YqNmI2Kgg2KfYrNmH2KfYtiM8YnIg
Lz48YnIgLz7Yt9ix2YrZgtipINin2LPYqtiu2K/YpyPYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiAj
PGJyIC8+2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYgPGJyIC8+I9it2KjZiNioINin2YTYp9is2YfY
p9i2ICM8YnIgLz4j2KfYrNmH2KfYtiAjPGJyIC8+I9in2KzZh9in2LYg2KfZhNit2YXZhCM8YnIg
Lz4j2K3YqNmI2Kgg2KfYrNmH2KfYtiM8YnIgLz7ZhSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyM8
YnIgLz48YnIgLz7Ys9in2YrYqtmI2KrZgyAj2YXZitiy2YjYqtin2YMg2K3YqNmI2Khf2LPYp9mK
2KrZiNiq2YNf2KfZhNin2LXZhNmK2Ycg2K3YqNmI2KggI9iz2KfZitiq2YjYqtmDICPYp9mE2KfY
tdmE2YrZhyDYp9mE2KfZhdin2LHYp9iqPGJyIC8+PGJyIC8+2K3YqNmI2Kgg2LPYp9mK2KrZiNiq
2YMg2KfZhNin2LXZhNmK2Ycg2YjYp9mE2KrZgtmE2YrYryM8YnIgLz48YnIgLz7Yrdio2YjYqCDY
s9in2YrYqtmI2KrZgyDYp9mE2KfYtdmE2Yog2YjYp9mE2KrZgtmE2YrYryM8YnIgLz4j2K3YqNmI
2Kgg2KfZhNin2KzZh9in2LYgIzxiciAvPtit2KjZiNioINin2YTYp9is2YfYp9i2IDxiciAvPiPY
rdio2YjYqCDYp9mE2KfYrNmH2KfYtiAjPGJyIC8+I9in2KzZh9in2LYgIzxiciAvPiPYp9is2YfY
p9i2INin2YTYrdmF2YQjPGJyIC8+I9it2KjZiNioINin2KzZh9in2LYjPGJyIC8+PGJyIC8+2LfY
sdmK2YLYqV/Yp9iz2KrYrtiv2KfZhV/Yrdio2YjYqF/Ys9in2YrYqtmI2KrZgyDYt9ix2YrZgtip
INin2LPYqtiu2K/Yp9mFINit2KjZiNioICPYs9in2YrYqtmI2KrZg1/ZhNmE2KfYrNmH2KfYtiM8
YnIgLz48YnIgLz7Yt9ix2YrZgtmHX9in2LPYqtiu2K/Yp9mFX9it2KjZiNioX9iz2KfZitiq2YjY
qtmDX9mB2Ypf2KfZhNi02YfYsV/Yp9mE2KfZiNmE2LfYsdmK2YLYqSDYp9iz2KrYrtiv2KfZhSAj
2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNin2KzZh9in2LYg2YHZiiDYp9mE2LTZh9ixINin
2YTYp9mI2YQNCg0KPHA+PC9wPgoKLS0gPGJyIC8+CllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2Ug
YmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgJnF1b3Q7a2Fz
YW4tZGV2JnF1b3Q7IGdyb3VwLjxiciAvPgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAg
YW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIDxhIGhy
ZWY9Im1haWx0bzprYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbSI+a2FzYW4t
ZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb208L2E+LjxiciAvPgpUbyB2aWV3IHRoaXMg
ZGlzY3Vzc2lvbiB2aXNpdCA8YSBocmVmPSJodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNn
aWQva2FzYW4tZGV2L2RhMWMyZDNjLTYzZTYtNDlhYS1iNTlmLWQ4ZmJlNTU0ZTRhNG4lNDBnb29n
bGVncm91cHMuY29tP3V0bV9tZWRpdW09ZW1haWwmdXRtX3NvdXJjZT1mb290ZXIiPmh0dHBzOi8v
Z3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvZGExYzJkM2MtNjNlNi00OWFhLWI1
OWYtZDhmYmU1NTRlNGE0biU0MGdvb2dsZWdyb3Vwcy5jb208L2E+LjxiciAvPgo=
------=_Part_91893_1331847693.1741751206748--

------=_Part_91892_1665337435.1741751206748--
