Return-Path: <kasan-dev+bncBDO456PHTELBB26A6K2QMGQEL32D7ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D0BED951AB2
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 14:17:48 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5d8084d437csf5503927eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 05:17:48 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723637867; x=1724242667; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AOZPHcFc+flUEirG6p+7E7k99vBpuJvtMwm0Gu9dwnc=;
        b=Vk3rwTjseXSWbElVM0iRSG/bkYHVO2hXf/eIa3usWZhFdn77ZcVjT04ClNxHBU+CQj
         CtGCCq+f8+3gNijxuwVPpu9dTzJKXaIuGnFHZ+Qwl4yHIzzmCkZuUI4DWZbsWJpjShVr
         6xcR5iDFTLkb+xaehiYuOYZtAn3IRMEJt85zyleUgiqT4tLm/1wnHk5F48oR9rHKcIeB
         k1iL2jf3ljVIBsJUmVOI3hGO+Pi12UarujXsBSPUUcELMFoEJHpfjv2lR7fIUMF5VosM
         rKfQCwS+oXaQIa20CU1U7OJOjth0G6vWtge08AcFBH5tpxEdcFL3YTz4rCKtM7V4gcFx
         7YsQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723637867; x=1724242667; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AOZPHcFc+flUEirG6p+7E7k99vBpuJvtMwm0Gu9dwnc=;
        b=h3MnqGAzoyaXLNtBIhBce5oZlB3jEvcWBFVlKGjUtl1/YJvTqP/ngDGYbal4jB5HwT
         TeXKeYc2JXnQfiot5ehHZU/a0fJ2jpJj8g5rDIxNDYKD3mmm94WYV9F9mczuk2d4CUtX
         xjj7jck5AdTZA1oOkNHfIf+ATA6IlWemcY8zpf/qGHfS/jKX1IbeR8r+7HlbdvbrLWG/
         mmuANarYPPn76hUgFbKI00B5XF8iKM8ik/ECXqthLTCxSIQoxKOV7dqY10ORJt8w1veQ
         RAmcrKUhpCut1HTqyzGpRP5AFhjUWMgVTLArhjWpuOY8RfMVG/RiRbR+iCkZYtCOUh6i
         Jm2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723637867; x=1724242667;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AOZPHcFc+flUEirG6p+7E7k99vBpuJvtMwm0Gu9dwnc=;
        b=dZCI+DR6eCa1DV4itvE/5kR+ipD+ejsIBePBbCH2bVUnmiF2Eo2/XvK4W+lVLDIWf5
         hdCpjVtkKa+meXtgRoI0CmmSkPkp7MoaMShPz7SVbgG7y4BsE2QIHpGQ2zNlyUe/hzp6
         TIZ3xFmgmHfOvsOX84h9r79zE4GjHFUYb90wMGbqNTV5YJpZAy5GxEn/F7cxn6gjFbxG
         lDKq8arMSB6a1cCCruaMHBmhkHvjxLNW4RufvyUf+GGZSq1BlmfBYbwFFZRLR51ka0Ui
         tbJ+56HbXPgDmaqF2kXqDgSMWWXtVqBcTdgrsw5fS2zdsLieTTOddg8Iq5PQzZnADG8G
         mrRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWux6EaovH5aWKgtBn/zDvKxoUSjDk4By+JClVqB3D6P+svR/jPgqsXPmIBq2wuG8HPyWyPEgXBmqTlPVAVFs+6osi/LPyDlA==
X-Gm-Message-State: AOJu0Yw37lMAO4UtXxgax9lqtHmnW/TcpPu/DacXZg9f2WdAQQh4h0Po
	aEZAmo90PE+C2tSfmK6jSjEFlo7B45bZiQ9g9UhVVWaj/JQ8hv2D
X-Google-Smtp-Source: AGHT+IGDhV5F9anXDFhNC/0u6JgSK8C4m8qebG4gmZIgxDM2SlO4rY1KEf+9OVIgwsyA3W31zHk8Rg==
X-Received: by 2002:a05:6870:a413:b0:254:a09c:6ddf with SMTP id 586e51a60fabf-26fe5abefd6mr3040279fac.24.1723637867647;
        Wed, 14 Aug 2024 05:17:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9e47:b0:25a:6d0f:1a98 with SMTP id
 586e51a60fabf-269250706c1ls1719235fac.0.-pod-prod-08-us; Wed, 14 Aug 2024
 05:17:46 -0700 (PDT)
X-Received: by 2002:a05:6871:9c0a:b0:268:b62c:d075 with SMTP id 586e51a60fabf-26fe5c5a469mr74455fac.8.1723637866497;
        Wed, 14 Aug 2024 05:17:46 -0700 (PDT)
Date: Wed, 14 Aug 2024 05:17:45 -0700 (PDT)
From: hana soodi <hanasoodi668@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <2455c3f0-39db-4992-ba83-85b633d92febn@googlegroups.com>
Subject: =?UTF-8?B?2YXZitiy2YjYqtin2YMg2LPYp9mK2KrZiNiq2YrZgyDYp9mE?=
 =?UTF-8?B?2YLZiNmKINin2YTYrNio2KfYsSDZhNmE2KfYrNmH2KfYtiDYpw==?=
 =?UTF-8?B?2YTYq9in2YbZiNmKIDAwOTcxNTUzMDMxODQ=?=
 =?UTF-8?B?NiDYs9i52YjYr9mK2Kkg2KfZhNix2YrYp9i2INis2K/YqSA=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_52510_1406280975.1723637865125"
X-Original-Sender: hanasoodi668@gmail.com
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

------=_Part_52510_1406280975.1723637865125
Content-Type: multipart/alternative; 
	boundary="----=_Part_52511_1773327528.1723637865125"

------=_Part_52511_1773327528.1723637865125
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2LPYp9mK2KrZiNiq2YrZgyAoQ3l0b3RlYykg2YfZiCDYp9iz2YUg2KrYrNin2LHZiiDZhNiv2YjY
p9ihINmK2K3YqtmI2Yog2LnZhNmJINin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqSDZhdmK2LLZ
iNio2LHZiNiz2KrZiNmEIAooTWlzb3Byb3N0b2wpLiDZitmP2LPYqtiu2K/ZhSDZh9iw2Kcg2KfZ
hNiv2YjYp9ihINmB2Yog2KfZhNij2LPYp9izINmE2YTZiNmC2KfZitipINmF2YYg2YLYsdit2Kkg
2KfZhNmF2LnYr9ipINin2YTZhtin2KrYrNipIArYudmGINiq2YbYp9mI2YQg2YXYttin2K/Yp9iq
INin2YTYp9mE2KrZh9in2Kgg2LrZitixINin2YTYs9iq2YrYsdmI2YrYr9mK2KkgKE5TQUlEcykg
2YXYq9mEINin2YTYo9iz2KjYsdmK2YYgCtmI2KfZhNil2YrYqNmI2KjYsdmI2YHZitmGLiDZiti5
2YXZhCDZhdmK2LLZiNio2LHZiNiz2KrZiNmEINi52YYg2LfYsdmK2YIg2LLZitin2K/YqSDYpdmB
2LHYp9iyINin2YTZhdiu2KfYtyDZgdmKINin2YTZhdi52K/YqSDZiNiq2KvYqNmK2LcgCtil2YHY
sdin2LIg2KfZhNij2K3Zhdin2LbYjCDZhdmF2Kcg2YrYs9in2LnYryDZgdmKINit2YXYp9mK2Kkg
2KjYt9in2YbYqSAK2KfZhNmF2LnYr9ipLmh0dHBzOi8vbGlua3RyLmVlL2N5dG90aWNfZF9udXIK
Ctio2KfZhNil2LbYp9mB2Kkg2KXZhNmJINiw2YTZg9iMINmK2Y/Ys9iq2K7Yr9mFINiz2KfZitiq
2YjYqtmK2YMg2KjYtNmD2YQg2LTYp9im2Lkg2YHZiiDYp9mE2YXYrNin2YQg2KfZhNi32KjZiiDZ
hNij2LrYsdin2LYg2KPYrtix2YnYjCAK2YXYq9mEOgoK2KrYrdmB2YrYsiDYp9mE2YjZhNin2K/Y
qTog2YrZhdmD2YYg2KfYs9iq2K7Yr9in2YXZhyDZhNiq2YjYs9mK2Lkg2LnZhtmCINin2YTYsdit
2YUg2YjYqtit2YHZitiyINin2YTYqtmC2YTYtdin2Kog2YHZiiDYp9mE2K3Yp9mE2KfYqiAK2KfZ
hNiq2Yog2KrYqti32YTYqCDYqtit2LHZiti2INin2YTZiNmE2KfYr9ipLgoK2KfZhNil2KzZh9in
2LYg2KfZhNi32KjZijog2YrZj9iz2KrYrtiv2YUg2KjYp9mE2KrYstin2YXZhiDZhdi5INiv2YjY
p9ihINii2K7YsSDZitiz2YXZiSDZhdmK2YHZitio2LHZitiz2KrZiNmGIChNaWZlcHJpc3RvbmUp
IArZhNil2YbZh9in2KEg2KfZhNit2YXZhCDYutmK2LEg2KfZhNmF2LHYutmI2Kgg2YHZitmHINmB
2Yog2YXYsdin2K3ZhNmHINin2YTZhdio2YPYsdipLgoK2LnZhNin2Kwg2KfZhNil2KzZh9in2LYg
2LrZitixINin2YTZg9in2YXZhDog2YHZiiDYrdin2YTYqSDYrdiv2YjYqyDYpdis2YfYp9i2INi6
2YrYsSDZg9in2YXZhNiMINmK2YXZg9mGINin2LPYqtiu2K/Yp9mF2YcgCtmE2YTZhdiz2KfYudiv
2Kkg2YHZiiDYqtmB2LHZiti6INin2YTYsdit2YUg2YXZhiDYp9mE2KPZhtiz2KzYqSDYp9mE2YXY
qtio2YLZitipLgoK2YrYrNioINij2YYg2YrZj9iz2KrYrtiv2YUg2LPYp9mK2KrZiNiq2YrZgyDZ
gdmC2Lcg2KrYrdiqINil2LTYsdin2YEg2LfYqNmK2KjYjCDZhti42LHYp9mLINmE2KPZhiDZhNmH
INiq2KPYq9mK2LHYp9iqINmC2YjZitipINmI2YLYryAK2YrZg9mI2YYg2YTZhyDYotir2KfYsSDY
rNin2YbYqNmK2Kkg2K7Yt9mK2LHYqSDZgdmKINio2LnYtiDYp9mE2K3Yp9mE2KfYqi4K2KrZgtmE
2LXYp9iqINi02K/Zitiv2Kkg2YjYotmE2KfZhSDZgdmKINin2YTYqNi32YY6INmC2K8g2YrYs9io
2Kgg2LPYp9mK2KrZiNiq2YrZgyDYqtmC2YTYtdin2Kog2YLZiNmK2Kkg2YHZiiDYp9mE2LHYrdmF
INij2YggCtin2YTZhdi52K/YqdiMINmF2YXYpyDZitik2K/ZiiDYpdmE2Ykg2KLZhNin2YUg2LTY
r9mK2K/YqSDZgdmKINin2YTYqNi32YYuCgrZhtiy2YrZgSDZhdmB2LHYtzog2LnZhtivINin2LPY
qtiu2K/Yp9mF2Ycg2YTZhNil2KzZh9in2LbYjCDZgtivINmK2KTYr9mKINil2YTZiSDZhtiy2YrZ
gSDYrdin2K8uINmB2Yog2KjYudi2INin2YTYrdin2YTYp9iq2Iwg2YLYryAK2YrYqti32YTYqCDY
p9mE2KPZhdixINiq2K/YrtmE2YvYpyDYt9io2YrZi9inINil2LDYpyDZg9in2YYg2KfZhNmG2LLZ
itmBINmF2YHYsdi32YvYpyDYo9mIINin2LPYqtmF2LEg2YTZgdiq2LHYqSDYt9mI2YrZhNipLgoK
2KfZhNil2LPZh9in2YQg2YjYp9mE2LrYq9mK2KfZhjog2YXZhiDYp9mE2KLYq9in2LEg2KfZhNis
2KfZhtio2YrYqSDYp9mE2LTYp9im2LnYqSDZhNmE2K/ZiNin2KEg2KfZhNil2LPZh9in2YTYjCDY
p9mE2LrYq9mK2KfZhtiMIArZiNin2YTZgtmK2KEuCgrYqti02YjZh9in2Kog2KzZhtmK2YbZitip
OiDYpdiw2Kcg2KrZhSDYp9iz2KrYrtiv2KfZhSDYs9in2YrYqtmI2KrZitmDINiu2YTYp9mEINmB
2KrYsdipINin2YTYrdmF2YQg2YjZg9in2YYg2KfZhNil2KzZh9in2LYg2LrZitixIArZg9in2YXZ
hNiMINmB2KXZhiDZh9mG2KfZgyDYrti32LHZi9inINmF2YYg2K3Yr9mI2Ksg2KrYtNmI2YfYp9iq
INiu2YTZgtmK2Kkg2YHZiiDYp9mE2KzZhtmK2YYuCgrZgdi02YQg2KfZhNil2KzZh9in2LY6INmC
2K8g2YTYpyDZitmD2YjZhiDYp9mE2K/ZiNin2KEg2YHYudin2YTZi9inINmB2Yog2KjYudi2INin
2YTYrdin2YTYp9iq2Iwg2YXZhdinINmC2K8g2YrYpNiv2Yog2KXZhNmJIArYp9mE2K3Yp9is2Kkg
2KXZhNmJINiq2K/YrtmEINis2LHYp9it2YouCgrYp9mE2K3Ys9in2LPZitipOiDYqNi52LYg2KfZ
hNij2LTYrtin2LUg2YLYryDZitmD2YjZhtmI2YYg2K3Ys9in2LPZitmGINmE2YXZg9mI2YbYp9iq
INin2YTYr9mI2KfYodiMINmF2YXYpyDZgtivINmK2KTYr9mKINil2YTZiSAK2KrZgdin2LnZhNin
2Kog2KrYrdiz2LPZitipLgoK2YrYrNioINin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjYqtmK2YMg
2KrYrdiqINil2LTYsdin2YEg2LfYqNmK2Kgg2YXYrtiq2LXYjCDYrti12YjYtdmL2Kcg2LnZhtiv
INin2LPYqtiu2K/Yp9mF2Ycg2YTZhNil2KzZh9in2LbYjCAK2YTYttmF2KfZhiDYp9mE2LPZhNin
2YXYqSDZiNiq2KzZhtioINin2YTZhdi22KfYudmB2KfYqi7Yp9mE2KXYrNmH2KfYtiDZh9mIINil
2YbZh9in2KEg2KfZhNit2YXZhCDZgtio2YQg2KPZhiDZitiq2YXZg9mGINin2YTYrNmG2YrZhiDZ
hdmGIArYp9mE2LnZiti0INiu2KfYsdisINix2K3ZhSDYp9mE2KPZhS4g2YrZhdmD2YYg2KPZhiDZ
itit2K/YqyDYp9mE2KXYrNmH2KfYtiDYqNi02YPZhCDYt9io2YrYudmKICjZhdinINmK2Y/Yudix
2YEg2KjYp9mE2KXYrNmH2KfYtiAK2KfZhNiq2YTZgtin2KbZiikg2KPZiCDZitmF2YPZhiDYo9mG
INmK2KrZhSDYqNi02YPZhCDZhdiq2LnZhdivINmF2YYg2K7ZhNin2YQg2KfZhNil2KzYsdin2KHY
p9iqINin2YTYt9io2YrYqSAo2YXYpyDZitmP2LnYsdmBIArYqNin2YTYpdis2YfYp9i2INin2YTY
t9io2Yog2KPZiCDYp9mE2KXYrNmH2KfYtiDYp9mE2KzYsdin2K3ZiikuCgoxLiDYp9mE2KXYrNmH
2KfYtiDYp9mE2LfYqNmK2LnZijoK2KfZhNil2KzZh9in2LYg2KfZhNi32KjZiti52Yog2YfZiCDZ
gdmC2K/Yp9mGINin2YTYrdmF2YQg2KrZhNmC2KfYptmK2YvYpyDYr9mI2YYg2KrYr9iu2YQg2LfY
qNmK2Iwg2YjYudin2K/YqdmLINmK2K3Yr9irINmB2Yog2KfZhNir2YTYqyAK2KfZhNij2YjZhCDZ
hdmGINin2YTYrdmF2YQuINmK2K3Yr9irINio2LPYqNioINmF2KzZhdmI2LnYqSDZhdiq2YbZiNi5
2Kkg2YXZhiDYp9mE2KPYs9io2KfYqNiMINmF2YbZh9inINmF2LTYp9mD2YQg2YHZiiDYp9mE2KzZ
htmK2YbYjCAK2YXYq9mEINin2YTYudmK2YjYqCDYp9mE2K7ZhNmC2YrYqdiMINij2Ygg2YXYtNin
2YPZhCDZgdmKINin2YTYo9mFINmF2KvZhCDYtti52YEg2KfZhNix2K3ZhSDYo9mIINmF2LTZg9mE
2KfYqiDZh9ix2YXZiNmG2YrYqS4g2LnYp9iv2KnZiyAK2YXYpyDZitmD2YjZhiDZh9iw2Kcg2KfZ
hNmG2YjYuSDZhdmGINin2YTYpdis2YfYp9i2INi62YrYsSDZhdiq2YjZgti5INmI2LrYp9mE2KjZ
i9inINmF2Kcg2YrZg9mI2YYg2YTZhyDYqtij2KvZitixINmG2YHYs9mKINmD2KjZitixIArYudmE
2Ykg2KfZhNij2YUuCgoyLiDYp9mE2KXYrNmH2KfYtiDYp9mE2LfYqNmKOgrZitiq2YUg2KfZhNil
2KzZh9in2LYg2KfZhNi32KjZiiDYudmGINi32LHZitmCINiq2YbYp9mI2YQg2KPYr9mI2YrYqSDY
qtiz2KjYqCDYt9ix2K8g2KfZhNis2YbZitmGINmF2YYg2KfZhNix2K3ZhS4g2YrZj9iz2KrYrtiv
2YUg2YfYsNinIArYp9mE2YbZiNi5INmF2YYg2KfZhNil2KzZh9in2LYg2LnYp9iv2KnZiyDYrtmE
2KfZhCDYp9mE2KPYs9in2KjZiti5INin2YTYo9mI2YTZiSDZhdmGINin2YTYrdmF2YQuINin2YTY
o9iv2YjZitipINin2YTYtNin2KbYudipIArYp9mE2YXYs9iq2K7Yr9mF2Kkg2KrYtNmF2YQgItin
2YTZhdmK2YHZitio2LHZitiz2KrZiNmGIiDZiCLYp9mE2YXZitiy2YjYqNix2YjYs9iq2YjZhCLY
jCDYrdmK2Ksg2YrYudmF2YTYp9mGINmF2LnZi9inINi52YTZiSDYpdmG2YfYp9ihIArYp9mE2K3Z
hdmEINi52YYg2LfYsdmK2YIg2YXZhti5INmH2LHZhdmI2YYg2KfZhNio2LHZiNis2LPYqtix2YjZ
hiDYp9mE2LDZiiDZitit2KrYp9is2Ycg2KfZhNis2LPZhSDZhNmE2K3Zgdin2Lgg2LnZhNmJINin
2YTYrdmF2YTYjCDZiNmF2YYgCtir2YUg2KrYrdmB2YrYsiDYqtmC2YTYtdin2Kog2KfZhNix2K3Z
hSDZhNi32LHYryDYp9mE2KzZhtmK2YYuCgozLiDYp9mE2KXYrNmH2KfYtiDYp9mE2KzYsdin2K3Z
ijoK2YrYqtmFINin2YTYpdis2YfYp9i2INin2YTYrNix2KfYrdmKINmF2YYg2K7ZhNin2YQg2KXY
rNix2KfYodin2Kog2LfYqNmK2Kkg2KrZh9iv2YEg2KXZhNmJINil2LLYp9mE2Kkg2KfZhNis2YbZ
itmGINmF2YYg2KfZhNix2K3ZhS4gCtiq2LTZhdmEINmH2LDZhyDYp9mE2KXYrNix2KfYodin2Ko6
CgrYp9mE2LTZgdi3IChTdWN0aW9uIEFzcGlyYXRpb24pOiDZitiq2YUg2KfYs9iq2K7Yr9in2YUg
2KzZh9in2LIg2LTZgdi3INmE2KXYstin2YTYqSDYp9mE2KzZhtmK2YYg2YXZhiDYp9mE2LHYrdmF
LiAK2YrYqtmFINmH2LDYpyDYp9mE2YbZiNi5INmF2YYg2KfZhNil2KzZh9in2LYg2LnYp9iv2KnZ
iyDZgdmKINin2YTYo9iz2KfYqNmK2Lkg2KfZhNij2YjZhNmJINmF2YYg2KfZhNit2YXZhC4K2KfZ
hNiq2YjYs9mK2Lkg2YjYp9mE2YPYtNi3IChEaWxhdGlvbiBhbmQgQ3VyZXR0YWdlKTog2YrYqtmF
INiq2YjYs9mK2Lkg2LnZhtmCINin2YTYsdit2YUg2YjYp9iz2KrYrtiv2KfZhSDYo9iv2KfYqSAK
2KzYsdin2K3ZitipINmE2KXYstin2YTYqSDYp9mE2KPZhtiz2KzYqSDZhdmGINin2YTYsdit2YUu
INmK2KrZhSDZh9iw2Kcg2KfZhNmG2YjYuSDZhdmGINin2YTYpdis2YfYp9i2INmB2Yog2YjZgtiq
INmE2KfYrdmCINmF2YYgCtin2YTYrdmF2YQg2YXZgtin2LHZhtip2Ysg2KjYp9mE2LTZgdi3LgrY
p9mE2KrZiNiz2YrYuSDZiNin2YTYpdiu2YTYp9ihIChEaWxhdGlvbiBhbmQgRXZhY3VhdGlvbik6
INmK2Y/Ys9iq2K7Yr9mFINmH2LDYpyDYp9mE2KXYrNix2KfYoSDZgdmKINin2YTZhdix2KfYrdmE
IArYp9mE2YXYqtij2K7YsdipINmF2YYg2KfZhNit2YXZhCDZiNmK2KrYt9mE2Kgg2KrZiNiz2LnY
qSDYo9mD2KjYsSDZhNi52YbZgiDYp9mE2LHYrdmFINmE2KXYstin2YTYqSDYp9mE2KzZhtmK2YYg
2KjYp9iz2KrYrtiv2KfZhSAK2KfZhNij2K/ZiNin2Kog2KfZhNis2LHYp9it2YrYqSDZiNin2YTY
tNmB2LcuCjQuINin2YTYo9iz2KjYp9ioINmI2KfZhNiq2KjYudin2Ko6Ctij2LPYqNin2Kgg2KfZ
hNil2KzZh9in2LY6INiq2KrZhtmI2Lkg2KPYs9io2KfYqCDYp9mE2KXYrNmH2KfYtiDZiNiq2LTZ
hdmEINin2YTYuNix2YjZgSDYp9mE2LXYrdmK2Kkg2YTZhNij2YUgKNmF2KvZhCDYp9ix2KrZgdin
2Lkg2LbYuti3IArYp9mE2K/ZhSDYo9mIINin2YTYs9mD2LHZiinYjCDYp9mE2KrYudix2LYg2YTZ
hNi52YjYp9mF2YQg2KfZhNio2YrYptmK2Kkg2KfZhNi22KfYsdipICjZhdir2YQg2KfZhNil2LTY
udin2LnYp9iqINij2Ygg2KfZhNmF2YjYp9ivIArYp9mE2YPZitmF2YrYp9im2YrYqSnYjCDYo9mI
INi52K/ZhSDYp9mE2YLYr9ix2Kkg2LnZhNmJINin2YTYudmG2KfZitipINio2KfZhNis2YbZitmG
INmE2KPYs9io2KfYqCDYp9is2KrZhdin2LnZitipINij2Ygg2KfZgtiq2LXYp9iv2YrYqS4K2KfZ
hNiq2KjYudin2Ko6INmE2YTYpdis2YfYp9i2INii2KvYp9ixINmG2YHYs9mK2Kkg2YjYrNiz2K/Z
itipLiDZhdmGINin2YTZhtin2K3ZitipINin2YTYrNiz2K/Zitip2Iwg2YLYryDYqtmI2KfYrNmH
INin2YTZhdix2KPYqSAK2YXYttin2LnZgdin2Kog2YXYq9mEINin2YTZhtiy2YrZgSDYo9mIINin
2YTYudiv2YjZiS4g2YXZhiDYp9mE2YbYp9it2YrYqSDYp9mE2YbZgdiz2YrYqdiMINmC2K8g2KrY
tNi52LEg2KfZhNmF2LHYo9ipINio2KfZhNit2LLZhtiMIArYp9mE2LDZhtio2Iwg2KPZiCDYp9mE
2KfZg9iq2KbYp9ioLgo1LiDYp9mE2YLYp9mG2YjZhiDZiNin2YTYo9iu2YTYp9mCOgrYp9mE2KXY
rNmH2KfYtiDZhdmI2LbZiNi5INit2LPYp9izINmF2YYg2KfZhNmG2KfYrdmK2Kkg2KfZhNij2K7Z
hNin2YLZitipINmI2KfZhNiv2YrZhtmK2Kkg2YjYp9mE2YLYp9mG2YjZhtmK2KkuINiq2K7YqtmE
2YEg2KfZhNmC2YjYp9mG2YrZhiAK2K3ZiNmEINin2YTYudin2YTZhSDZgdmK2YXYpyDZitiq2LnZ
hNmCINio2LTYsdi52YrYqSDYp9mE2KXYrNmH2KfYti4g2YHZiiDYqNi52LYg2KfZhNiv2YjZhNiM
INmK2Y/Yudiq2KjYsSDYp9mE2KXYrNmH2KfYtiDYrdmC2YvYpyDZhdmGIArYrdmC2YjZgiDYp9mE
2YXYsdij2Kkg2YjZitiq2YUg2KrZgtiv2YrZhdmHINmD2K7Yr9mF2Kkg2LXYrdmK2KnYjCDYqNmK
2YbZhdinINmB2Yog2K/ZiNmEINij2K7YsdmJINmK2Y/Yudiq2KjYsSDYutmK2LEg2YLYp9mG2YjZ
htmKINij2YggCtmF2YLZitivINio2LTYr9ipLgoKNi4g2KfZhNmI2YLYp9mK2Kkg2YjYp9mE2K/Y
udmFOgrZhNmE2YjZgtin2YrYqSDZhdmGINit2KfZhNin2Kog2KfZhNil2KzZh9in2LYg2KfZhNiq
2YTZgtin2KbZitiMINmK2Y/Zhti12K0g2KjYp9mE2YXYqtin2KjYudipINin2YTYt9io2YrYqSDY
p9mE2YXYs9iq2YXYsdipINiu2YTYp9mEIArZgdiq2LHYqSDYp9mE2K3ZhdmEINmI2KfZhNit2YHY
p9i4INi52YTZiSDZhtmF2Lcg2K3Zitin2Kkg2LXYrdmKLiDZgdmKINit2KfZhNipINin2YTYpdis
2YfYp9i2INin2YTZhdiq2LnZhdiv2Iwg2YrZj9mG2LXYrSDYqNin2YTYrdi12YjZhCAK2LnZhNmJ
INiv2LnZhSDZhtmB2LPZiiDZiNin2KzYqtmF2KfYudmKINmE2KrYrtmB2YrZgSDYp9mE2KrYo9ir
2YrYsdin2Kog2KfZhNmG2YHYs9mK2Kkg2KfZhNiz2YTYqNmK2KkuCg0KLS0gCllvdSByZWNlaXZl
ZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBH
cm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBh
bmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4t
ZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9u
IG9uIHRoZSB3ZWIgdmlzaXQgaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2Fu
LWRldi8yNDU1YzNmMC0zOWRiLTQ5OTItYmE4My04NWI2MzNkOTJmZWJuJTQwZ29vZ2xlZ3JvdXBz
LmNvbS4K
------=_Part_52511_1773327528.1723637865125
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2LPYp9mK2KrZiNiq2YrZgyAoQ3l0b3RlYykg2YfZiCDYp9iz2YUg2KrYrNin2LHZiiDZhNiv2YjY
p9ihINmK2K3YqtmI2Yog2LnZhNmJINin2YTZhdin2K/YqSDYp9mE2YHYudin2YTYqSDZhdmK2LLZ
iNio2LHZiNiz2KrZiNmEIChNaXNvcHJvc3RvbCkuINmK2Y/Ys9iq2K7Yr9mFINmH2LDYpyDYp9mE
2K/ZiNin2KEg2YHZiiDYp9mE2KPYs9in2LMg2YTZhNmI2YLYp9mK2Kkg2YXZhiDZgtix2K3YqSDY
p9mE2YXYudiv2Kkg2KfZhNmG2KfYqtis2Kkg2LnZhiDYqtmG2KfZiNmEINmF2LbYp9iv2KfYqiDY
p9mE2KfZhNiq2YfYp9ioINi62YrYsSDYp9mE2LPYqtmK2LHZiNmK2K/ZitipIChOU0FJRHMpINmF
2KvZhCDYp9mE2KPYs9io2LHZitmGINmI2KfZhNil2YrYqNmI2KjYsdmI2YHZitmGLiDZiti52YXZ
hCDZhdmK2LLZiNio2LHZiNiz2KrZiNmEINi52YYg2LfYsdmK2YIg2LLZitin2K/YqSDYpdmB2LHY
p9iyINin2YTZhdiu2KfYtyDZgdmKINin2YTZhdi52K/YqSDZiNiq2KvYqNmK2Lcg2KXZgdix2KfY
siDYp9mE2KPYrdmF2KfYttiMINmF2YXYpyDZitiz2KfYudivINmB2Yog2K3Zhdin2YrYqSDYqNi3
2KfZhtipINin2YTZhdi52K/YqS5odHRwczovL2xpbmt0ci5lZS9jeXRvdGljX2RfbnVyPGJyIC8+
PGJyIC8+2KjYp9mE2KXYttin2YHYqSDYpdmE2Ykg2LDZhNmD2Iwg2YrZj9iz2KrYrtiv2YUg2LPY
p9mK2KrZiNiq2YrZgyDYqNi02YPZhCDYtNin2KbYuSDZgdmKINin2YTZhdis2KfZhCDYp9mE2LfY
qNmKINmE2KPYutix2KfYtiDYo9iu2LHZidiMINmF2KvZhDo8YnIgLz48YnIgLz7Yqtit2YHZitiy
INin2YTZiNmE2KfYr9ipOiDZitmF2YPZhiDYp9iz2KrYrtiv2KfZhdmHINmE2KrZiNiz2YrYuSDY
udmG2YIg2KfZhNix2K3ZhSDZiNiq2K3ZgdmK2LIg2KfZhNiq2YLZhNi12KfYqiDZgdmKINin2YTY
rdin2YTYp9iqINin2YTYqtmKINiq2KrYt9mE2Kgg2KrYrdix2YrYtiDYp9mE2YjZhNin2K/YqS48
YnIgLz48YnIgLz7Yp9mE2KXYrNmH2KfYtiDYp9mE2LfYqNmKOiDZitmP2LPYqtiu2K/ZhSDYqNin
2YTYqtiy2KfZhdmGINmF2Lkg2K/ZiNin2KEg2KLYrtixINmK2LPZhdmJINmF2YrZgdmK2KjYsdmK
2LPYqtmI2YYgKE1pZmVwcmlzdG9uZSkg2YTYpdmG2YfYp9ihINin2YTYrdmF2YQg2LrZitixINin
2YTZhdix2LrZiNioINmB2YrZhyDZgdmKINmF2LHYp9it2YTZhyDYp9mE2YXYqNmD2LHYqS48YnIg
Lz48YnIgLz7YudmE2KfYrCDYp9mE2KXYrNmH2KfYtiDYutmK2LEg2KfZhNmD2KfZhdmEOiDZgdmK
INit2KfZhNipINit2K/ZiNirINil2KzZh9in2LYg2LrZitixINmD2KfZhdmE2Iwg2YrZhdmD2YYg
2KfYs9iq2K7Yr9in2YXZhyDZhNmE2YXYs9in2LnYr9ipINmB2Yog2KrZgdix2YrYuiDYp9mE2LHY
rdmFINmF2YYg2KfZhNij2YbYs9is2Kkg2KfZhNmF2KrYqNmC2YrYqS48YnIgLz48YnIgLz7Zitis
2Kgg2KPZhiDZitmP2LPYqtiu2K/ZhSDYs9in2YrYqtmI2KrZitmDINmB2YLYtyDYqtit2Kog2KXY
tNix2KfZgSDYt9io2YrYqNiMINmG2LjYsdin2Ysg2YTYo9mGINmE2Ycg2KrYo9ir2YrYsdin2Kog
2YLZiNmK2Kkg2YjZgtivINmK2YPZiNmGINmE2Ycg2KLYq9in2LEg2KzYp9mG2KjZitipINiu2LfZ
itix2Kkg2YHZiiDYqNi52LYg2KfZhNit2KfZhNin2KouPGJyIC8+2KrZgtmE2LXYp9iqINi02K/Z
itiv2Kkg2YjYotmE2KfZhSDZgdmKINin2YTYqNi32YY6INmC2K8g2YrYs9io2Kgg2LPYp9mK2KrZ
iNiq2YrZgyDYqtmC2YTYtdin2Kog2YLZiNmK2Kkg2YHZiiDYp9mE2LHYrdmFINij2Ygg2KfZhNmF
2LnYr9ip2Iwg2YXZhdinINmK2KTYr9mKINil2YTZiSDYotmE2KfZhSDYtNiv2YrYr9ipINmB2Yog
2KfZhNio2LfZhi48YnIgLz48YnIgLz7Zhtiy2YrZgSDZhdmB2LHYtzog2LnZhtivINin2LPYqtiu
2K/Yp9mF2Ycg2YTZhNil2KzZh9in2LbYjCDZgtivINmK2KTYr9mKINil2YTZiSDZhtiy2YrZgSDY
rdin2K8uINmB2Yog2KjYudi2INin2YTYrdin2YTYp9iq2Iwg2YLYryDZitiq2LfZhNioINin2YTY
o9mF2LEg2KrYr9iu2YTZi9inINi32KjZitmL2Kcg2KXYsNinINmD2KfZhiDYp9mE2YbYstmK2YEg
2YXZgdix2LfZi9inINij2Ygg2KfYs9iq2YXYsSDZhNmB2KrYsdipINi32YjZitmE2KkuPGJyIC8+
PGJyIC8+2KfZhNil2LPZh9in2YQg2YjYp9mE2LrYq9mK2KfZhjog2YXZhiDYp9mE2KLYq9in2LEg
2KfZhNis2KfZhtio2YrYqSDYp9mE2LTYp9im2LnYqSDZhNmE2K/ZiNin2KEg2KfZhNil2LPZh9in
2YTYjCDYp9mE2LrYq9mK2KfZhtiMINmI2KfZhNmC2YrYoS48YnIgLz48YnIgLz7Yqti02YjZh9in
2Kog2KzZhtmK2YbZitipOiDYpdiw2Kcg2KrZhSDYp9iz2KrYrtiv2KfZhSDYs9in2YrYqtmI2KrZ
itmDINiu2YTYp9mEINmB2KrYsdipINin2YTYrdmF2YQg2YjZg9in2YYg2KfZhNil2KzZh9in2LYg
2LrZitixINmD2KfZhdmE2Iwg2YHYpdmGINmH2YbYp9mDINiu2LfYsdmL2Kcg2YXZhiDYrdiv2YjY
qyDYqti02YjZh9in2Kog2K7ZhNmC2YrYqSDZgdmKINin2YTYrNmG2YrZhi48YnIgLz48YnIgLz7Z
gdi02YQg2KfZhNil2KzZh9in2LY6INmC2K8g2YTYpyDZitmD2YjZhiDYp9mE2K/ZiNin2KEg2YHY
udin2YTZi9inINmB2Yog2KjYudi2INin2YTYrdin2YTYp9iq2Iwg2YXZhdinINmC2K8g2YrYpNiv
2Yog2KXZhNmJINin2YTYrdin2KzYqSDYpdmE2Ykg2KrYr9iu2YQg2KzYsdin2K3Zii48YnIgLz48
YnIgLz7Yp9mE2K3Ys9in2LPZitipOiDYqNi52LYg2KfZhNij2LTYrtin2LUg2YLYryDZitmD2YjZ
htmI2YYg2K3Ys9in2LPZitmGINmE2YXZg9mI2YbYp9iqINin2YTYr9mI2KfYodiMINmF2YXYpyDZ
gtivINmK2KTYr9mKINil2YTZiSDYqtmB2KfYudmE2KfYqiDYqtit2LPYs9mK2KkuPGJyIC8+PGJy
IC8+2YrYrNioINin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjYqtmK2YMg2KrYrdiqINil2LTYsdin
2YEg2LfYqNmK2Kgg2YXYrtiq2LXYjCDYrti12YjYtdmL2Kcg2LnZhtivINin2LPYqtiu2K/Yp9mF
2Ycg2YTZhNil2KzZh9in2LbYjCDZhNi22YXYp9mGINin2YTYs9mE2KfZhdipINmI2KrYrNmG2Kgg
2KfZhNmF2LbYp9i52YHYp9iqLtin2YTYpdis2YfYp9i2INmH2Ygg2KXZhtmH2KfYoSDYp9mE2K3Z
hdmEINmC2KjZhCDYo9mGINmK2KrZhdmD2YYg2KfZhNis2YbZitmGINmF2YYg2KfZhNi52YrYtCDY
rtin2LHYrCDYsdit2YUg2KfZhNij2YUuINmK2YXZg9mGINij2YYg2YrYrdiv2Ksg2KfZhNil2KzZ
h9in2LYg2KjYtNmD2YQg2LfYqNmK2LnZiiAo2YXYpyDZitmP2LnYsdmBINio2KfZhNil2KzZh9in
2LYg2KfZhNiq2YTZgtin2KbZiikg2KPZiCDZitmF2YPZhiDYo9mGINmK2KrZhSDYqNi02YPZhCDZ
hdiq2LnZhdivINmF2YYg2K7ZhNin2YQg2KfZhNil2KzYsdin2KHYp9iqINin2YTYt9io2YrYqSAo
2YXYpyDZitmP2LnYsdmBINio2KfZhNil2KzZh9in2LYg2KfZhNi32KjZiiDYo9mIINin2YTYpdis
2YfYp9i2INin2YTYrNix2KfYrdmKKS48YnIgLz48YnIgLz4xLiDYp9mE2KXYrNmH2KfYtiDYp9mE
2LfYqNmK2LnZijo8YnIgLz7Yp9mE2KXYrNmH2KfYtiDYp9mE2LfYqNmK2LnZiiDZh9mIINmB2YLY
r9in2YYg2KfZhNit2YXZhCDYqtmE2YLYp9im2YrZi9inINiv2YjZhiDYqtiv2K7ZhCDYt9io2YrY
jCDZiNi52KfYr9ip2Ysg2YrYrdiv2Ksg2YHZiiDYp9mE2KvZhNirINin2YTYo9mI2YQg2YXZhiDY
p9mE2K3ZhdmELiDZitit2K/YqyDYqNiz2KjYqCDZhdis2YXZiNi52Kkg2YXYqtmG2YjYudipINmF
2YYg2KfZhNij2LPYqNin2KjYjCDZhdmG2YfYpyDZhdi02KfZg9mEINmB2Yog2KfZhNis2YbZitmG
2Iwg2YXYq9mEINin2YTYudmK2YjYqCDYp9mE2K7ZhNmC2YrYqdiMINij2Ygg2YXYtNin2YPZhCDZ
gdmKINin2YTYo9mFINmF2KvZhCDYtti52YEg2KfZhNix2K3ZhSDYo9mIINmF2LTZg9mE2KfYqiDZ
h9ix2YXZiNmG2YrYqS4g2LnYp9iv2KnZiyDZhdinINmK2YPZiNmGINmH2LDYpyDYp9mE2YbZiNi5
INmF2YYg2KfZhNil2KzZh9in2LYg2LrZitixINmF2KrZiNmC2Lkg2YjYutin2YTYqNmL2Kcg2YXY
pyDZitmD2YjZhiDZhNmHINiq2KPYq9mK2LEg2YbZgdiz2Yog2YPYqNmK2LEg2LnZhNmJINin2YTY
o9mFLjxiciAvPjxiciAvPjIuINin2YTYpdis2YfYp9i2INin2YTYt9io2Yo6PGJyIC8+2YrYqtmF
INin2YTYpdis2YfYp9i2INin2YTYt9io2Yog2LnZhiDYt9ix2YrZgiDYqtmG2KfZiNmEINij2K/Z
iNmK2Kkg2KrYs9io2Kgg2LfYsdivINin2YTYrNmG2YrZhiDZhdmGINin2YTYsdit2YUuINmK2Y/Y
s9iq2K7Yr9mFINmH2LDYpyDYp9mE2YbZiNi5INmF2YYg2KfZhNil2KzZh9in2LYg2LnYp9iv2KnZ
iyDYrtmE2KfZhCDYp9mE2KPYs9in2KjZiti5INin2YTYo9mI2YTZiSDZhdmGINin2YTYrdmF2YQu
INin2YTYo9iv2YjZitipINin2YTYtNin2KbYudipINin2YTZhdiz2KrYrtiv2YXYqSDYqti02YXZ
hCAi2KfZhNmF2YrZgdmK2KjYsdmK2LPYqtmI2YYiINmIItin2YTZhdmK2LLZiNio2LHZiNiz2KrZ
iNmEItiMINit2YrYqyDZiti52YXZhNin2YYg2YXYudmL2Kcg2LnZhNmJINil2YbZh9in2KEg2KfZ
hNit2YXZhCDYudmGINi32LHZitmCINmF2YbYuSDZh9ix2YXZiNmGINin2YTYqNix2YjYrNiz2KrY
sdmI2YYg2KfZhNiw2Yog2YrYrdiq2KfYrNmHINin2YTYrNiz2YUg2YTZhNit2YHYp9i4INi52YTZ
iSDYp9mE2K3ZhdmE2Iwg2YjZhdmGINir2YUg2KrYrdmB2YrYsiDYqtmC2YTYtdin2Kog2KfZhNix
2K3ZhSDZhNi32LHYryDYp9mE2KzZhtmK2YYuPGJyIC8+PGJyIC8+My4g2KfZhNil2KzZh9in2LYg
2KfZhNis2LHYp9it2Yo6PGJyIC8+2YrYqtmFINin2YTYpdis2YfYp9i2INin2YTYrNix2KfYrdmK
INmF2YYg2K7ZhNin2YQg2KXYrNix2KfYodin2Kog2LfYqNmK2Kkg2KrZh9iv2YEg2KXZhNmJINil
2LLYp9mE2Kkg2KfZhNis2YbZitmGINmF2YYg2KfZhNix2K3ZhS4g2KrYtNmF2YQg2YfYsNmHINin
2YTYpdis2LHYp9ih2KfYqjo8YnIgLz48YnIgLz7Yp9mE2LTZgdi3IChTdWN0aW9uIEFzcGlyYXRp
b24pOiDZitiq2YUg2KfYs9iq2K7Yr9in2YUg2KzZh9in2LIg2LTZgdi3INmE2KXYstin2YTYqSDY
p9mE2KzZhtmK2YYg2YXZhiDYp9mE2LHYrdmFLiDZitiq2YUg2YfYsNinINin2YTZhtmI2Lkg2YXZ
hiDYp9mE2KXYrNmH2KfYtiDYudin2K/YqdmLINmB2Yog2KfZhNij2LPYp9io2YrYuSDYp9mE2KPZ
iNmE2Ykg2YXZhiDYp9mE2K3ZhdmELjxiciAvPtin2YTYqtmI2LPZiti5INmI2KfZhNmD2LTYtyAo
RGlsYXRpb24gYW5kIEN1cmV0dGFnZSk6INmK2KrZhSDYqtmI2LPZiti5INi52YbZgiDYp9mE2LHY
rdmFINmI2KfYs9iq2K7Yr9in2YUg2KPYr9in2Kkg2KzYsdin2K3ZitipINmE2KXYstin2YTYqSDY
p9mE2KPZhtiz2KzYqSDZhdmGINin2YTYsdit2YUuINmK2KrZhSDZh9iw2Kcg2KfZhNmG2YjYuSDZ
hdmGINin2YTYpdis2YfYp9i2INmB2Yog2YjZgtiqINmE2KfYrdmCINmF2YYg2KfZhNit2YXZhCDZ
hdmC2KfYsdmG2KnZiyDYqNin2YTYtNmB2LcuPGJyIC8+2KfZhNiq2YjYs9mK2Lkg2YjYp9mE2KXY
rtmE2KfYoSAoRGlsYXRpb24gYW5kIEV2YWN1YXRpb24pOiDZitmP2LPYqtiu2K/ZhSDZh9iw2Kcg
2KfZhNil2KzYsdin2KEg2YHZiiDYp9mE2YXYsdin2K3ZhCDYp9mE2YXYqtij2K7YsdipINmF2YYg
2KfZhNit2YXZhCDZiNmK2KrYt9mE2Kgg2KrZiNiz2LnYqSDYo9mD2KjYsSDZhNi52YbZgiDYp9mE
2LHYrdmFINmE2KXYstin2YTYqSDYp9mE2KzZhtmK2YYg2KjYp9iz2KrYrtiv2KfZhSDYp9mE2KPY
r9mI2KfYqiDYp9mE2KzYsdin2K3ZitipINmI2KfZhNi02YHYty48YnIgLz40LiDYp9mE2KPYs9io
2KfYqCDZiNin2YTYqtio2LnYp9iqOjxiciAvPtij2LPYqNin2Kgg2KfZhNil2KzZh9in2LY6INiq
2KrZhtmI2Lkg2KPYs9io2KfYqCDYp9mE2KXYrNmH2KfYtiDZiNiq2LTZhdmEINin2YTYuNix2YjZ
gSDYp9mE2LXYrdmK2Kkg2YTZhNij2YUgKNmF2KvZhCDYp9ix2KrZgdin2Lkg2LbYuti3INin2YTY
r9mFINij2Ygg2KfZhNiz2YPYsdmKKdiMINin2YTYqti52LHYtiDZhNmE2LnZiNin2YXZhCDYp9mE
2KjZitim2YrYqSDYp9mE2LbYp9ix2KkgKNmF2KvZhCDYp9mE2KXYtNi52KfYudin2Kog2KPZiCDY
p9mE2YXZiNin2K8g2KfZhNmD2YrZhdmK2KfYptmK2Kkp2Iwg2KPZiCDYudiv2YUg2KfZhNmC2K/Y
sdipINi52YTZiSDYp9mE2LnZhtin2YrYqSDYqNin2YTYrNmG2YrZhiDZhNij2LPYqNin2Kgg2KfY
rNiq2YXYp9i52YrYqSDYo9mIINin2YLYqti12KfYr9mK2KkuPGJyIC8+2KfZhNiq2KjYudin2Ko6
INmE2YTYpdis2YfYp9i2INii2KvYp9ixINmG2YHYs9mK2Kkg2YjYrNiz2K/ZitipLiDZhdmGINin
2YTZhtin2K3ZitipINin2YTYrNiz2K/Zitip2Iwg2YLYryDYqtmI2KfYrNmHINin2YTZhdix2KPY
qSDZhdi22KfYudmB2KfYqiDZhdir2YQg2KfZhNmG2LLZitmBINij2Ygg2KfZhNi52K/ZiNmJLiDZ
hdmGINin2YTZhtin2K3ZitipINin2YTZhtmB2LPZitip2Iwg2YLYryDYqti02LnYsSDYp9mE2YXY
sdij2Kkg2KjYp9mE2K3YstmG2Iwg2KfZhNiw2YbYqNiMINij2Ygg2KfZhNin2YPYqtim2KfYqC48
YnIgLz41LiDYp9mE2YLYp9mG2YjZhiDZiNin2YTYo9iu2YTYp9mCOjxiciAvPtin2YTYpdis2YfY
p9i2INmF2YjYttmI2Lkg2K3Ys9in2LMg2YXZhiDYp9mE2YbYp9it2YrYqSDYp9mE2KPYrtmE2KfZ
gtmK2Kkg2YjYp9mE2K/ZitmG2YrYqSDZiNin2YTZgtin2YbZiNmG2YrYqS4g2KrYrtiq2YTZgSDY
p9mE2YLZiNin2YbZitmGINit2YjZhCDYp9mE2LnYp9mE2YUg2YHZitmF2Kcg2YrYqti52YTZgiDY
qNi02LHYudmK2Kkg2KfZhNil2KzZh9in2LYuINmB2Yog2KjYudi2INin2YTYr9mI2YTYjCDZitmP
2LnYqtio2LEg2KfZhNil2KzZh9in2LYg2K3ZgtmL2Kcg2YXZhiDYrdmC2YjZgiDYp9mE2YXYsdij
2Kkg2YjZitiq2YUg2KrZgtiv2YrZhdmHINmD2K7Yr9mF2Kkg2LXYrdmK2KnYjCDYqNmK2YbZhdin
INmB2Yog2K/ZiNmEINij2K7YsdmJINmK2Y/Yudiq2KjYsSDYutmK2LEg2YLYp9mG2YjZhtmKINij
2Ygg2YXZgtmK2K8g2KjYtNiv2KkuPGJyIC8+PGJyIC8+Ni4g2KfZhNmI2YLYp9mK2Kkg2YjYp9mE
2K/YudmFOjxiciAvPtmE2YTZiNmC2KfZitipINmF2YYg2K3Yp9mE2KfYqiDYp9mE2KXYrNmH2KfY
tiDYp9mE2KrZhNmC2KfYptmK2Iwg2YrZj9mG2LXYrSDYqNin2YTZhdiq2KfYqNi52Kkg2KfZhNi3
2KjZitipINin2YTZhdiz2KrZhdix2Kkg2K7ZhNin2YQg2YHYqtix2Kkg2KfZhNit2YXZhCDZiNin
2YTYrdmB2KfYuCDYudmE2Ykg2YbZhdi3INit2YrYp9ipINi12K3Zii4g2YHZiiDYrdin2YTYqSDY
p9mE2KXYrNmH2KfYtiDYp9mE2YXYqti52YXYr9iMINmK2Y/Zhti12K0g2KjYp9mE2K3YtdmI2YQg
2LnZhNmJINiv2LnZhSDZhtmB2LPZiiDZiNin2KzYqtmF2KfYudmKINmE2KrYrtmB2YrZgSDYp9mE
2KrYo9ir2YrYsdin2Kog2KfZhNmG2YHYs9mK2Kkg2KfZhNiz2YTYqNmK2KkuPGJyIC8+DQoNCjxw
PjwvcD4KCi0tIDxiciAvPgpZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFy
ZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICZxdW90O2thc2FuLWRldiZxdW90OyBn
cm91cC48YnIgLz4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9wIHJlY2Vp
dmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byA8YSBocmVmPSJtYWlsdG86a2Fz
YW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20iPmthc2FuLWRldit1bnN1YnNjcmli
ZUBnb29nbGVncm91cHMuY29tPC9hPi48YnIgLz4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gb24g
dGhlIHdlYiB2aXNpdCA8YSBocmVmPSJodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQv
a2FzYW4tZGV2LzI0NTVjM2YwLTM5ZGItNDk5Mi1iYTgzLTg1YjYzM2Q5MmZlYm4lNDBnb29nbGVn
cm91cHMuY29tP3V0bV9tZWRpdW09ZW1haWwmdXRtX3NvdXJjZT1mb290ZXIiPmh0dHBzOi8vZ3Jv
dXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvMjQ1NWMzZjAtMzlkYi00OTkyLWJhODMt
ODViNjMzZDkyZmVibiU0MGdvb2dsZWdyb3Vwcy5jb208L2E+LjxiciAvPgo=
------=_Part_52511_1773327528.1723637865125--

------=_Part_52510_1406280975.1723637865125--
