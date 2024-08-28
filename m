Return-Path: <kasan-dev+bncBC46NCNX4YDRBSFRX23AMGQERNAJ7QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EF50963400
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 23:38:18 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5d5c7700d4esf8416889eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 14:38:18 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724881097; x=1725485897; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qRCYRnVfoJwCIygx7Y9Evm/EtNeN4VIXp24OqCFUbyY=;
        b=PSS+OIiCGJHvqaX9gHzMZF2UvRDtlu30qoDpw9hpkFMUDMNiedEAIw6VMXVMHyvwd9
         ck8WFb2drBNw8G+hi19letNCEDYrIRqgX9IhzzEB494sXFGyBun650lVbXs+eYJSICO2
         4dGOaPH4n9Qx1VLuZ4ODU8cQliJX3HDNSjrnIIbrPhRyQ8UwZl8xTvBfS9800GN/uk+K
         YdczcesLVwwGIJ45CdVSTEA8EROPps41L92OTIEHwBqlzYxgRWdnXh3Znzkkyos7itot
         8wlTIHzDIoklg/cj8278zzB42x8ziv33gQJFNGAdw2F2xl1hdjd9CU43dRRxLYziiphZ
         KwVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1724881097; x=1725485897; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qRCYRnVfoJwCIygx7Y9Evm/EtNeN4VIXp24OqCFUbyY=;
        b=DcRM1R5RGBv8XY/9FL3fO6iiAUza2Psj1njV71IH3vZsqX2OmLLvhR4k2PybMXCFJh
         u6nMeBTidIcve7hCBgd291KX9Ux4KcecuxO29SetBI94l0wYV9DYVXrtyHtWFF53kXdg
         4JnZSc3TH40Of9JYwXiDXLD+erTh8+dqLXG5/byAtunDqUB/UJuYdRkVBVlaXelT6/Ku
         ryz+FQAfA1o3PuVRvTuQTkpmcLZLPaKv8P9QwLawUvXisfOcR+veefNweNW6WZ+LbUXS
         uM0AZXKItFOX/lUUpiDOV6j1NO5Vi3YaZemiAeWtUNVHrJ+JF0FxzZmOoMCqkyZlsuFG
         mYzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724881097; x=1725485897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qRCYRnVfoJwCIygx7Y9Evm/EtNeN4VIXp24OqCFUbyY=;
        b=adpsrG12vgYybuj6mQtfUz5J8zpesUS6g+Gs2SoQMV/fHjeNcdlnYQqxbVmA+Cglee
         QAoJwWP35qJv9GdfFJr4DBAtos6kZ2xd8rbAu9dpoz+UsbbtR62cTu13Omrw21O2BsQg
         53RrW5opCnKJEeXN8DcQsB0PU8Whx4V6WKwQIor7U1JghKi6PnKRuajJXGnMfOkNDIi5
         NNWRR9zlEPDbWjIkdBf9dgXGdooz/cbJKyIkakwMu5tt3Y7hI6HxDvcH5yGOIHLAPM10
         zPF0XMRCYKU/s6oARld10MoaDQlW82Necr+Rki4cZvGunNnqA62UvtRHFiH6HdH0ys2B
         h8mA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCUQRO/6VX4es1jjgx3YYqOGD4YS/XKDzl7SQSCydgjBrh90bhKXFZbpIvV61D2XKbzZy7L3HA==@lfdr.de
X-Gm-Message-State: AOJu0Ywl25MyW1IJdqGx2A3DTx3fzBdquUyqUFkTOFc2UXWn8WQLT2CW
	rExLyJ9emcpkt4mOW+r83PXym1E8seubgh0+z6ViL/SO/69tdEvc
X-Google-Smtp-Source: AGHT+IFeiIR2zuQdoRxZaLg0AchQBM+zWXCRfRwSAVl2OEkODydZlU4pxeiJ5uObLdePlJ84hddshA==
X-Received: by 2002:a05:6820:990:b0:5c6:8eb6:91b2 with SMTP id 006d021491bc7-5df97ebb172mr1247085eaf.1.1724881097104;
        Wed, 28 Aug 2024 14:38:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ca08:0:b0:5da:5cb5:1cb5 with SMTP id 006d021491bc7-5df992324e9ls275031eaf.2.-pod-prod-08-us;
 Wed, 28 Aug 2024 14:38:16 -0700 (PDT)
X-Received: by 2002:a05:6808:1692:b0:3de:13bf:3092 with SMTP id 5614622812f47-3df05d8557fmr809462b6e.24.1724881095927;
        Wed, 28 Aug 2024 14:38:15 -0700 (PDT)
Date: Wed, 28 Aug 2024 14:38:15 -0700 (PDT)
From: Kerry Crook <crook9994@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <51a9e87e-4355-4eb5-9b38-f2e5d1d12697n@googlegroups.com>
Subject: =?UTF-8?B?2LPYudixINiz2YPZiNiq2LEg2KfZhNiq?=
 =?UTF-8?B?2YbZgtmEINin2YTZg9mH2LHYqNin2KbZiiA=?=
 =?UTF-8?B?2LnYqNixINin2YTYpdmG2KrYsdmG2Kog?=
 =?UTF-8?B?2YHZiiDYp9mE2YPZiNmK2Kog2KfZhNmF2YU=?=
 =?UTF-8?B?2YTZg9ipINin2YTYudix2KjZitipINin?=
 =?UTF-8?B?2YTYs9i52YjYr9mK2Kkg2YLYt9ixINix2YI=?=
 =?UTF-8?B?2YUg2KfZhNmI2KfYqtiz2KfYqCArOTcxIDU4IDYyNiA3OTgx?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_19882_1343261357.1724881095277"
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

------=_Part_19882_1343261357.1724881095277
Content-Type: multipart/alternative; 
	boundary="----=_Part_19883_1896892212.1724881095277"

------=_Part_19883_1896892212.1724881095277
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2LPYudixINiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin2YTZg9mH2LHYqNin2KbZiiDYudio2LEg
2KfZhNil2YbYqtix2YbYqiDZgdmKINin2YTZg9mI2YrYqiDYp9mE2YXZhdmE2YPYqSDYp9mE2LnY
sdio2YrYqSDYp9mE2LPYudmI2K/ZitipIArZgti32LEg2LHZgtmFINin2YTZiNin2KrYs9in2Kgg
Kzk3MSA1OCA2MjYgNzk4MQrYp9iq2LXZhCDYqNin2YTYqNin2KbYuSDYudio2LEg2KfZhNmI2KfY
qtizINin2Kg6ICs5NzEgNTggNjI2IDc5ODEg2KPZiCDYqtmI2KfYtdmEINi52KjYsSDYp9mE2KrZ
hNmK2KzYsdin2YU6IApAVGVycnlrYW5lcyBodHRwczovL3QubWUvK0NPaHEyWHVOcWNRd05HWXgg
2LPZg9mI2KrYsSDZhdiq2K3YsdmDINmE2YTYqNmK2Lkg2LnYqNixINin2YTYpdmG2KrYsdmG2Kog
Cti52KjYsSDYp9mE2KXZhtiq2LHZhtiqINmB2Yog2KfZhNmD2YjZitiqINin2YTZhdmF2YTZg9ip
INin2YTYudix2KjZitipINin2YTYs9i52YjYr9mK2Kkg2YLYt9ixINin2YTYqNit2LHZitmGINin
2YTYo9ix2K/ZhiDYp9mE2KXZhdin2LHYp9iqIArYp9mE2LnYsdio2YrYqSDYp9mE2YXYqtit2K/Y
qSDYudmF2KfZhiDYp9mE2YrZhdmGINin2YTYudix2KfZgiDZhdi12LEg2KfZhNmF2LrYsdioINin
2YTYrNiy2KfYptixINmE2YrYqNmK2Kcg2KrZiNmG2LMg2YTYqNmG2KfZhiDZhtmC2K/ZhSAK2YXY
rNmF2YjYudipINmI2KfYs9i52Kkg2YXZhiDYs9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPZ
h9ix2KjYp9im2Yog2YTZhNij2LTYrtin2LUg2LDZiNmKINin2YTYpdi52KfZgtipINij2Ygg2YbZ
iNi5INmF2YYg2YLZitmI2K8gCtin2YTYrdix2YPYqS4g2YbZgtiv2YUg2YTYudmF2YTYp9im2YbY
pyDZhdis2YXZiNi52Kkg2YjYp9iz2LnYqSDZhdmGINin2YTZhdmI2K/ZitmE2KfYqiDYs9mD2YjY
qtixINin2YTYqtmG2YLZhCAtINmF2KrZiNiz2LcgCuKAi+KAi9in2YTYrdis2YUg2YjZhdiq2YrZ
hiDZhdinINmH2Yog2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNmD2KjZitix2KnYnwrYs9mD
2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPYqNmK2LHYjCDYp9mE2YXYudix2YjZgSDYo9mK2LbZ
i9inINio2KfYs9mFINiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin2YTYq9mC2YrZhCDYo9mIICLY
p9mE2YPYqNmK2LEi2Iwg2YfZiCAK2YXYsdmD2KjYp9iqINmC2YjZitipINmI2YXYqtmK2YbYqSDZ
hdi12YXZhdipINmE2KfYs9iq2YrYudin2Kgg2KfZhNmF2LPYqtiu2K/ZhdmK2YYg2KfZhNiw2YrZ
hiDZgtivINmK2YPZiNmGINmE2K/ZitmH2YUg2KfYrdiq2YrYp9is2KfYqiAK2KrZhtmC2YQg2YXY
rdiv2K/YqS4g2KrZhSDYqti12YXZitmFINmH2LDZhyDYp9mE2LPZg9mI2KrYsSDZhdmGINij2KzZ
hCDYp9mE2KvYqNin2Kog2YjYp9mE2YXYqtin2YbYqSDZiNin2YTYqtmG2YjYudiMINmF2YXYpyDZ
itis2LnZhNmH2KcgCtmF2YbYp9iz2KjYqSDZhNmE2KfYs9iq2K7Yr9in2YUg2KfZhNiv2KfYrtmE
2Yog2YjYp9mE2K7Yp9ix2KzZii4g2KXZhtmH2Kcg2YXYq9in2YTZitipINmE2YTYo9mB2LHYp9iv
INin2YTYsNmK2YYg2YrYudin2YbZiNmGINmF2YYgCtiv2LHYrNin2Kog2YXYqtmB2KfZiNiq2Kkg
2YXZhiDYqtit2K/Zitin2Kog2KfZhNiq2YbZgtmELgrYp9mE2YHZhNin2KrYsQrZhdinINmH2Yog
2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNmD2KjZitix2KnYnwog2KrZj9i52LHZgSDYp9mE
2K/Ysdin2KzYp9iqINin2YTYqNiu2KfYsdmK2Kkg2KfZhNmD2KjZitix2Kkg2KfZhNmF2KrYrdix
2YPYqSDYo9mK2LbZi9inINio2KfYs9mFINin2YTYr9ix2KfYrNin2Kog2KfZhNio2K7Yp9ix2YrY
qSAK2KfZhNir2YLZitmE2Kkg2KPZiCAi2KfZhNmD2KjZitix2Kki2Iwg2YjZh9mKINmF2LHZg9io
2KfYqiDZgtmI2YrYqSDZiNmF2KrZitmG2Kkg2YXYtdmF2YXYqSDZhNin2LPYqtmK2LnYp9ioINin
2YTZhdiz2KrYrtiv2YXZitmGIArYp9mE2LDZitmGINmC2K8g2YrZg9mI2YYg2YTYr9mK2YfZhSDY
p9it2KrZitin2KzYp9iqINit2LHZg9mK2Kkg2YXYrdiv2K/YqS4g2KrZhSDYqti12YXZitmFINmH
2LDZhyDYp9mE2K/Ysdin2KzYp9iqINin2YTYqNiu2KfYsdmK2KkgCtmE2KrYrdmC2YrZgiDYp9mE
2KfYs9iq2YLYsdin2LEg2YjYp9mE2YXYqtin2YbYqSDZiNin2YTYqtmG2YjYudiMINmF2YXYpyDZ
itis2LnZhNmH2Kcg2YXZhtin2LPYqNipINmE2YTYp9iz2KrYrtiv2KfZhSDYp9mE2K/Yp9iu2YTZ
iiAK2YjYp9mE2K7Yp9ix2KzZii4g2YjZh9mKINmF2KvYp9mE2YrYqSDZhNmE2KPZgdix2KfYryDY
p9mE2LDZitmGINmK2LnYp9mG2YjZhiDZhdmGINiv2LHYrNin2Kog2YXYqtmB2KfZiNiq2Kkg2YXZ
hiDYqtit2K/Zitin2Kog2KfZhNit2LHZg9ipLgrYp9mE2YHZhNin2KrYsQrYpdi42YfYp9ixIDHi
gJMxOCDZhdmGIDM4INmG2KrZitis2KkKDQotLSAKWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBi
ZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2
IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9wIHJlY2Vpdmlu
ZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVA
Z29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gb24gdGhlIHdlYiB2aXNp
dCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2LzUxYTllODdlLTQz
NTUtNGViNS05YjM4LWYyZTVkMWQxMjY5N24lNDBnb29nbGVncm91cHMuY29tLgo=
------=_Part_19883_1896892212.1724881095277
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2LPYudixINiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin2YTZg9mH2LHYqNin2KbZiiDYudio2LEg
2KfZhNil2YbYqtix2YbYqiDZgdmKINin2YTZg9mI2YrYqiDYp9mE2YXZhdmE2YPYqSDYp9mE2LnY
sdio2YrYqSDYp9mE2LPYudmI2K/ZitipINmC2LfYsSDYsdmC2YUg2KfZhNmI2KfYqtiz2KfYqCAr
OTcxIDU4IDYyNiA3OTgxPGJyIC8+PGRpdj7Yp9iq2LXZhCDYqNin2YTYqNin2KbYuSDYudio2LEg
2KfZhNmI2KfYqtizINin2Kg6ICs5NzEgNTggNjI2IDc5ODEg2KPZiCDYqtmI2KfYtdmEINi52KjY
sSDYp9mE2KrZhNmK2KzYsdin2YU6IEBUZXJyeWthbmVzIGh0dHBzOi8vdC5tZS8rQ09ocTJYdU5x
Y1F3TkdZeCDYs9mD2YjYqtixINmF2KrYrdix2YMg2YTZhNio2YrYuSDYudio2LEg2KfZhNil2YbY
qtix2YbYqiDYudio2LEg2KfZhNil2YbYqtix2YbYqiDZgdmKINin2YTZg9mI2YrYqiDYp9mE2YXZ
hdmE2YPYqSDYp9mE2LnYsdio2YrYqSDYp9mE2LPYudmI2K/ZitipINmC2LfYsSDYp9mE2KjYrdix
2YrZhiDYp9mE2KPYsdiv2YYg2KfZhNil2YXYp9ix2KfYqiDYp9mE2LnYsdio2YrYqSDYp9mE2YXY
qtit2K/YqSDYudmF2KfZhiDYp9mE2YrZhdmGINin2YTYudix2KfZgiDZhdi12LEg2KfZhNmF2LrY
sdioINin2YTYrNiy2KfYptixINmE2YrYqNmK2Kcg2KrZiNmG2LMg2YTYqNmG2KfZhiDZhtmC2K/Z
hSDZhdis2YXZiNi52Kkg2YjYp9iz2LnYqSDZhdmGINiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin
2YTZg9mH2LHYqNin2KbZiiDZhNmE2KPYtNiu2KfYtSDYsNmI2Yog2KfZhNil2LnYp9mC2Kkg2KPZ
iCDZhtmI2Lkg2YXZhiDZgtmK2YjYryDYp9mE2K3YsdmD2KkuINmG2YLYr9mFINmE2LnZhdmE2KfY
ptmG2Kcg2YXYrNmF2YjYudipINmI2KfYs9i52Kkg2YXZhiDYp9mE2YXZiNiv2YrZhNin2Kog2LPZ
g9mI2KrYsSDYp9mE2KrZhtmC2YQgLSDZhdiq2YjYs9i3IOKAi+KAi9in2YTYrdis2YUg2YjZhdiq
2YrZhiDZhdinINmH2Yog2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNmD2KjZitix2KnYnzxi
ciAvPtiz2YPZiNiq2LEg2KfZhNiq2YbZgtmEINin2YTZg9io2YrYsdiMINin2YTZhdi52LHZiNmB
INij2YrYttmL2Kcg2KjYp9iz2YUg2LPZg9mI2KrYsSDYp9mE2KrZhtmC2YQg2KfZhNir2YLZitmE
INij2YggItin2YTZg9io2YrYsSLYjCDZh9mIINmF2LHZg9io2KfYqiDZgtmI2YrYqSDZiNmF2KrZ
itmG2Kkg2YXYtdmF2YXYqSDZhNin2LPYqtmK2LnYp9ioINin2YTZhdiz2KrYrtiv2YXZitmGINin
2YTYsNmK2YYg2YLYryDZitmD2YjZhiDZhNiv2YrZh9mFINin2K3YqtmK2KfYrNin2Kog2KrZhtmC
2YQg2YXYrdiv2K/YqS4g2KrZhSDYqti12YXZitmFINmH2LDZhyDYp9mE2LPZg9mI2KrYsSDZhdmG
INij2KzZhCDYp9mE2KvYqNin2Kog2YjYp9mE2YXYqtin2YbYqSDZiNin2YTYqtmG2YjYudiMINmF
2YXYpyDZitis2LnZhNmH2Kcg2YXZhtin2LPYqNipINmE2YTYp9iz2KrYrtiv2KfZhSDYp9mE2K/Y
p9iu2YTZiiDZiNin2YTYrtin2LHYrNmKLiDYpdmG2YfYpyDZhdir2KfZhNmK2Kkg2YTZhNij2YHY
sdin2K8g2KfZhNiw2YrZhiDZiti52KfZhtmI2YYg2YXZhiDYr9ix2KzYp9iqINmF2KrZgdin2YjY
qtipINmF2YYg2KrYrdiv2YrYp9iqINin2YTYqtmG2YLZhC48YnIgLz7Yp9mE2YHZhNin2KrYsTxi
ciAvPtmF2Kcg2YfZiiDYs9mD2YjYqtixINin2YTYqtmG2YLZhCDYp9mE2YPYqNmK2LHYqdifPGJy
IC8+wqDYqtmP2LnYsdmBINin2YTYr9ix2KfYrNin2Kog2KfZhNio2K7Yp9ix2YrYqSDYp9mE2YPY
qNmK2LHYqSDYp9mE2YXYqtit2LHZg9ipINij2YrYttmL2Kcg2KjYp9iz2YUg2KfZhNiv2LHYp9is
2KfYqiDYp9mE2KjYrtin2LHZitipINin2YTYq9mC2YrZhNipINij2YggItin2YTZg9io2YrYsdip
ItiMINmI2YfZiiDZhdix2YPYqNin2Kog2YLZiNmK2Kkg2YjZhdiq2YrZhtipINmF2LXZhdmF2Kkg
2YTYp9iz2KrZiti52KfYqCDYp9mE2YXYs9iq2K7Yr9mF2YrZhiDYp9mE2LDZitmGINmC2K8g2YrZ
g9mI2YYg2YTYr9mK2YfZhSDYp9it2KrZitin2KzYp9iqINit2LHZg9mK2Kkg2YXYrdiv2K/YqS4g
2KrZhSDYqti12YXZitmFINmH2LDZhyDYp9mE2K/Ysdin2KzYp9iqINin2YTYqNiu2KfYsdmK2Kkg
2YTYqtit2YLZitmCINin2YTYp9iz2KrZgtix2KfYsSDZiNin2YTZhdiq2KfZhtipINmI2KfZhNiq
2YbZiNi52Iwg2YXZhdinINmK2KzYudmE2YfYpyDZhdmG2KfYs9io2Kkg2YTZhNin2LPYqtiu2K/Y
p9mFINin2YTYr9in2K7ZhNmKINmI2KfZhNiu2KfYsdis2YouINmI2YfZiiDZhdir2KfZhNmK2Kkg
2YTZhNij2YHYsdin2K8g2KfZhNiw2YrZhiDZiti52KfZhtmI2YYg2YXZhiDYr9ix2KzYp9iqINmF
2KrZgdin2YjYqtipINmF2YYg2KrYrdiv2YrYp9iqINin2YTYrdix2YPYqS48YnIgLz7Yp9mE2YHZ
hNin2KrYsTxiciAvPtil2LjZh9in2LEgMeKAkzE4INmF2YYgMzgg2YbYqtmK2KzYqTxiciAvPjwv
ZGl2Pg0KDQo8cD48L3A+CgotLSA8YnIgLz4KWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNh
dXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAmcXVvdDtrYXNhbi1k
ZXYmcXVvdDsgZ3JvdXAuPGJyIC8+ClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQg
c3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8gPGEgaHJlZj0i
bWFpbHRvOmthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tIj5rYXNhbi1kZXYr
dW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhpcyBkaXNj
dXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgPGEgaHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNv
bS9kL21zZ2lkL2thc2FuLWRldi81MWE5ZTg3ZS00MzU1LTRlYjUtOWIzOC1mMmU1ZDFkMTI2OTdu
JTQwZ29vZ2xlZ3JvdXBzLmNvbT91dG1fbWVkaXVtPWVtYWlsJnV0bV9zb3VyY2U9Zm9vdGVyIj5o
dHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2LzUxYTllODdlLTQzNTUt
NGViNS05YjM4LWYyZTVkMWQxMjY5N24lNDBnb29nbGVncm91cHMuY29tPC9hPi48YnIgLz4K
------=_Part_19883_1896892212.1724881095277--

------=_Part_19882_1343261357.1724881095277--
