Return-Path: <kasan-dev+bncBDBLLSVC5ILBBCVO7S2AMGQELUBA7NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 440DF939852
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jul 2024 04:35:56 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-70377dcee38sf5887837a34.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 19:35:56 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721702155; x=1722306955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pj+RF7tQfRWva7CU0JBgX4j96lKw/sc9+7vzcQh8Hcc=;
        b=V4vP4lBdoevUhW+7585/5N6mHzyUY2iqhuK5VG6w2IUWCts9u0vasd6n13dJhbqz1g
         RzHAvLWENfDdLGtMhRyk44uO/PPtoJf2AVreJpLT1laON+dJdeeAublRIXcVd85Q23Vn
         YlOKhCKSQ6ZmBzwTdHE4Ddxmj3Vkdf7TAkWDrhEe8bl71LMRJVqCWpssLqw4ib1E8NMB
         /Gm4fcJVSyzXlJZq5MU8dvzw+jTetQfCEVbgUzVWDc7uVXec9R3f6lP1Hb4azPOHzFSO
         NbyLOHFa28jepO+Awm+AG/6fjacopnmQyEbr3wlhd2Lt+5XMzS6cNMJhQ0t2Xl7x4O3M
         +Vwg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721702155; x=1722306955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pj+RF7tQfRWva7CU0JBgX4j96lKw/sc9+7vzcQh8Hcc=;
        b=jlEwIjJaA4wX+X5wH39Nb9NIMWh2bpDyhsUnDolS07YCQg6sMDFBYWp36aO3yTAjNd
         6nGTm82UFXmrcwrkgbUwgT02N3T+rbiCA96iEjH9hjc4K+yVrJf6PWs97bvUrhzaULTy
         YxYloiZ2INPSQS05B/Bo4ib5jpGKQ6AhYEXnd4em0JE3mwlpvFr75VAQCVP3gLHLeZDC
         fp7AtT4IN4UHN5Jlop6+p42qcpcg9WlCaP0D5vokIIq/rJyPK2qXvRSpD7XOZIkm2hfJ
         Ch3t/A24teZFErnVtqhO8PBK0kxvK2K87lTBRtfFTJVf/nXpgwtBVZ0MrKBR/GE3stVX
         /sNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721702155; x=1722306955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pj+RF7tQfRWva7CU0JBgX4j96lKw/sc9+7vzcQh8Hcc=;
        b=wbAGV3NMySk/ANupdVChXhC/oMiwNMfFjivGgbfbbERmB5SJh18W0ahe51CGJQoOWK
         pGFxjhmY58fzFsBJaUEdSY502Ed1lCNId30rNwFqNOo0tkeHBdBjXkKuGM0vICa7XWCp
         xlUt3nXoB5vsAE6SNSd1ACQX/uFuAJdPKzm0n/FDiKg3FyCUHyTfgInOzYCjt6UcH197
         EPSqd+padEwXFQtsyP1VWicsmwtsoHmP3Gvsi7M5n6NgNtuuNAUR2n9v8R4DGAaXFCtP
         PCcgplc4QJtbJANTquXHqeOiQD3G7evbb9dOdWQnp7owAQerNUvKikuc5ZOqe4wq5sko
         euJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCU4wqlKzQUm5LnncWXM8OuC6nqz4b6FlbtgvPhUF+5CgIDanNY2PzlHsKxjIM13/2UEgPVUBVFYkVO9z5/Vjv5HtMuRwjnCIA==
X-Gm-Message-State: AOJu0Yy5ywkuxnQeYm3iZ2eBJ4nVDLgNeia5+NSu2TzJUqLRtVlWQ359
	RuPPaZphnKE00iFMsLz2viFuZYllUfaOsGvZ6IOCaFHkWQ6P+1EQ
X-Google-Smtp-Source: AGHT+IFSIxSLg1vxY21KuVjBPOfdNNCfx2hlT+EnpvW/cdOkBI7GGXK9q4IWLAWxsDoZt8CUCKScFQ==
X-Received: by 2002:a05:6870:330e:b0:260:ffaf:811a with SMTP id 586e51a60fabf-264690afe68mr1475640fac.8.1721702154721;
        Mon, 22 Jul 2024 19:35:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6c0a:b0:25e:624:afb6 with SMTP id
 586e51a60fabf-260ec4a7817ls5668218fac.1.-pod-prod-09-us; Mon, 22 Jul 2024
 19:35:54 -0700 (PDT)
X-Received: by 2002:a05:6870:10d7:b0:260:e6b5:a203 with SMTP id 586e51a60fabf-261215a22c4mr141927fac.6.1721702153847;
        Mon, 22 Jul 2024 19:35:53 -0700 (PDT)
Date: Mon, 22 Jul 2024 19:35:53 -0700 (PDT)
From: "Lois B.griffin" <bgriffinlois@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <2565c6f0-c7b1-4dcf-98ee-5ed6581bb622n@googlegroups.com>
In-Reply-To: <11b8d32d-7fef-4f23-9e95-9a3cc9a5dbe5n@googlegroups.com>
References: <3b2dd708-e6fa-482b-aadb-434599cfc183n@googlegroups.com>
 <57ea7d36-1be7-4ddc-914e-5568a10c52b7n@googlegroups.com>
 <89591a3c-ec38-4dbb-9def-e0e82758cc55n@googlegroups.com>
 <1ddc75f4-dc1d-468f-828a-aba4dc47b87en@googlegroups.com>
 <aa9c40a8-079d-454c-bcc8-8d0e11b2fbcdn@googlegroups.com>
 <11b8d32d-7fef-4f23-9e95-9a3cc9a5dbe5n@googlegroups.com>
Subject: =?UTF-8?Q?Re:_UAE_-_00971553031846_=D8=AD?=
 =?UTF-8?Q?=D8=A8=D9=88=D8=A8_=D8=AA=D9=86?=
 =?UTF-8?Q?=D8=B2=D9=84_=D8=A7=D9=84=D8=AC=D9=86?=
 =?UTF-8?Q?=D9=8A=D9=86_=D9=85=D9=86_=D8=A7?=
 =?UTF-8?Q?=D9=84=D8=B5=D9=8A=D8=AF=D9=84=D9=8A=D8=A9?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_944852_1952934475.1721702153217"
X-Original-Sender: bgriffinlois@gmail.com
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

------=_Part_944852_1952934475.1721702153217
Content-Type: multipart/alternative; 
	boundary="----=_Part_944853_1290994503.1721702153217"

------=_Part_944853_1290994503.1721702153217
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2LPYp9mK2KrZiNiq2YMg2KfZhNin2LXZhNmKINiv2KjZiiDZiNis2YXZiti5INiv2YjZhCDYp9mE
2K7ZhNmK2KwKPgo+IDAwOTcxNTUzMDMxODQ2Cj4KPiAg2KrZiNin2LXZhCDZhdi52YbYpyDYudio
2LEg2KfZhNmI2KfYqtiz2KfYqCDYo9mIINin2YTYqtmK2YTYrNix2KfZhQoK2K3YqNmI2Kgg2LPY
p9mK2KrZiNiq2YMg2KfZhNin2LXZhNmK2Ycg2YTZhNio2YrYuSDYrdio2YjYqCDYp9iz2YLYp9i3
INin2YTYrNmG2YrZhiDYqNiv2KjZiiDYrdio2YjYqCDYp9mE2K3ZhdmEINmE2YTYqNmK2LkgIyDY
qNmK2LnYnyDYnyAKIyDYtNix2KfYodifINifICMg2K3YqNmI2KjYnyDYnyAjINin2YTYp9is2YfY
p9i22J8gIyDYs9in2YrYqtmI2KrZg9ifICMg2YHZitifINifICMg2K/YqNmK2J8g2J8gIyDYp9mE
2LTYp9ix2YLZh9ifINifICMgCti52KzZhdin2YbYnyDYnyAjINin2YTYudmK2YbYnyDYnyAjINin
2KjZiNi42KjZitifICMg2KfZhNis2YbZitmG2J8gIyDYs9in2YrYqtmI2KrZg9ifINifICMg2YTZ
hNio2YrYudifIEN5dG90ZWMgIyAjIArYp9mE2KfZhdin2LHYp9iqICMg2YHZitifICMg2K/YqNmK
2J8gIyDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmF2YYg2K/Yp9iu2YQgIyDYr9io2YogIyDY
tNin2LHZgtmHICMg2LnYrNmF2KfZhiDZhNmE2LfZhNioIArZhdmGINio2KfZgtmKINin2YTYr9mI
2YQg2YHZiiDYp9mE2K7ZhNmK2Kwg2YrYqtmI2YHYsSDZhNiv2YrZhtinINit2KjZiNioINin2YTY
qNix2YrYt9in2YbZitmHINin2YTYp9i12YTZitipINmF2Lkg2KfZhNi22YXYp9mG2KfYqiAK2YTZ
hNil2KzZh9in2LYg2YTZhNil2YbYqtmH2KfYoSDZhdmGINi42YfZiNixINil2YbYqtix2YbYqtmI
2KrZgyDYp9mE2KfYtdmE2YrYqSAyMDAg2YXZhNmK2LrYsdin2YUg2YXZhiDYtNix2YPYqSDZgdin
2YrYstixIArYp9mE2LnYp9mE2YXZitipINmE2YTYqNmK2Lkg2K3YqNmI2Kgg2KfYrNmH2KfYtiDY
p9mE2K3ZhdmEINiMINin2YTYrdmF2YQg2Iwg2KfZhNit2YXZhCDYjCDYp9mE2K3ZhdmEINiMINin
2YTYrdmF2YQg2Iwg2KfZhNis2YbZitmGINiMIArYp9mE2KXZhdin2LHYp9iqINin2YTYudix2KjZ
itipINin2YTZhdiq2K3Yr9ipINiMINin2YTYpdis2YfYp9i2INiMINin2YTYpdis2YfYp9i2INmB
2Yog2KfZhNin2YXYp9ix2KfYqiDYjCDYp9mE2KXYrNmH2KfYtiBjeXRvdGVjIArYqNmK2Lkg2YXZ
hti5INin2YTYp9is2YfYp9i2INmB2Yog2KfZhNin2YXYp9ix2KfYqiDYp9mE2LnYsdio2YrYqSDY
p9mE2YXYqtit2K/YqQoK2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDZhdi22YXZ
iNmGINin2YTYp9mF2KfYsdin2Kog2KjYo9ir2YXZhtipINmF2LTYrNi52Kkg2YjZhdmG2KfYs9io
2KkKCtit2KjZiNioINin2YTYs9in2YrYqtmI2KrZgyDYp9mE2KfYrNmH2KfYtiDZhNmE2KjZiti5
INmB2Yog2KfZhNin2YXYp9ix2KfYqgoK2KjZiti5INit2KjZiNioINiz2KfZitiq2YjYqtmDINin
2YTYp9i12YTZigoK2LPYp9mK2KrZiNiq2YMg2KfZhNin2LXZhNmKINiv2KjZiiDZiNis2YXZiti5
INiv2YjZhCDYp9mE2K7ZhNmK2KwKCtio2YrYuSDYtNix2KfYoSDYrdio2YjYqCDYp9mE2KfYrNmH
2KfYtiDYs9in2YrYqtmI2KrZgyDigJPYr9io2YogXyDYp9mE2LTYp9ix2YLZhyBf2KfYqNmI2LjY
qNmKCgrZitiq2YjZgdixINmE2K/ZitmG2Kcg2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2KfZhNmF
2YbYstmE2Yog2LPYp9mK2KrZiNiq2YMg2YXZitiy2YjYqNix2YjYs9iq2YjZhAoKQ3l0b3RlYyBt
aXNvcHJvc3RvbCAyMDAgbWcg2KfZhNio2LHZiti32KfZhtmKICgg2KfZhNin2YbYrNmE2YrYstmK
KSDYp9mE2KPYtdmE2Yog2YXZhiDYtNix2YPYqSDZgdin2YrYstixIArYp9mE2KrZiNi12YrZhCDZ
hdiq2YjZgdixINmE2KzZhdmK2Lkg2K/ZiNmEINin2YTYrtmE2YrYrCDYp9mE2LnYsdio2Yog2YjY
r9mI2YQg2KfZhNi52KfZhNmFCgrYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB
2Yog2KfZhNin2YXYp9ix2KfYqiDYs9in2YrYqtmI2KrZgyDYp9mE2KfYtdmE2YoKCtit2KjZiNio
INiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZiiDYp9mE2KfZhdin2LHYp9iqCgrYrdio2YjY
qCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB2Yog2K/YqNmKCgrYrdio2YjYqCDYs9in2YrY
qtmI2KrZgyDZhNmE2KjZiti5INmB2Yog2LnYrNmF2KfZhgoK2K3YqNmI2Kgg2LPYp9mK2KrZiNiq
2YMg2YTZhNio2YrYuSDZgdmKINin2KjZiNi42KjZigoK2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg
2YTZhNio2YrYuSDZgdmKINin2YTYp9mF2KfYsdin2KoKCtit2KjZiNioINiz2KfZitiq2YjYqtmD
INin2YTYp9is2YfYp9i2INmE2YTYqNmK2Lkg2KfZhNin2YXYp9ix2KfYqgoK2K3YqNmI2Kgg2LPY
p9mK2KrZiNiq2YMg2KfZhNin2KzZh9in2LYg2YTZhNio2YrYuSDZgdmKINiv2KjZigoK2K3YqNmI
2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNin2KzZh9in2LYg2YHZiiDYp9mE2LTYp9ix2YLZhwoK2K3Y
qNmI2Kgg2KXYrNmH2KfYtiDYp9mE2K3ZhdmEINiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YXZ
hiDYr9in2K7ZhCDYp9mE2KfZhdin2LHYp9iqINiv2KjZiiDYp9mE2LTYp9ix2YLZhyDYudis2YXY
p9mGCgrYqNmK2Lkg2LTYsdin2KEg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNil2KzZh9in
2LYg2LnYrNmF2KfZhiDYp9mE2LTYp9ix2YLZhwoK2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZ
hNin2KzZh9in2LYg2YXYqtin2K3YqSDYp9mE2KfZhiDZgdmKINiv2KjZigoK2K3YqNmI2Kgg2KXZ
htiy2KfZhCDYp9mE2K3ZhdmEINiz2KfZitiq2YjYqtmDINin2YTYqNix2YrYt9in2YbZitipINin
2YTYo9i12YTZitipINmE2YTYqNmK2LkKCtio2KfZhNin2YXYp9ix2KfYqiDZiNiq2YjYtdmK2YQg
2YXYrNin2YbZiiDYqNmG2YHYsyDZitmI2YUg2KfZhNi32YTYqCDZhNis2YXZiti5INmF2YbYp9i3
2YIg2KfZhNin2YXYp9ix2KfYqgoK2YTYpdmG2LLYp9mEINin2YTYrdmF2YQg2KfZhNmF2YbYstmE
2Yog2KfZhNii2YXZhiDZiNio2K/ZiNmGINii2KvYp9ixINis2KfZhtio2YrYqSAsINit2KjZiNio
INiz2KfZitiq2YjYqtmDINin2YTYo9i12YTZitipINmH2Ygg2KfZhNit2YQgCtin2YTYo9mF2KvZ
hAoK2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDZhNil2KzZh9in2LYg2KfZhNit
2YXZhCDYqNmK2Lkg2LTYsdin2KEg2KfZhNin2YXYp9ix2KfYqiDYr9io2Yog2LnYrNmF2KfZhiDY
p9mE2LTYp9ix2YLZhwoK2LPYp9mK2KrZiNiq2YMg2YTZhNin2KzZh9in2LYgLCDYrdio2YjYqCDY
p9mE2KfYrNmH2KfYtiDYs9in2YrYqtmI2KrZgyAsINit2KjZiNioINiz2KfZitiq2YjYqtmDINiv
2KjZiiAsINit2KjZiNioINil2KzZh9in2LYgLCAK2K3YqNmI2Kgg2KfYrNmH2KfYtgoK2K3YqNmI
2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNi02KfYsdmC2YcgLCDYrdio2YjYqCDYs9in2YrYqtmI2KrZ
gyDYr9io2YogLCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYudis2YXYp9mGICwg2K3YqNmI2Kgg
2LPYp9mK2KrZiNiq2YMgCtin2YTYudmK2YYKCtit2KjZiNioINin2YTYp9is2YfYp9i2INiz2KfZ
itiq2YjYqtmDINin2YTYp9i12YTZitipINmE2YTYqNmK2Lkg2YHZiiDYp9mE2KfZhdin2LHYp9iq
INiv2KjZiiDYudis2YXYp9mGINin2KjZiNi42KjZigoK2YPZitmBINin2K3YtdmEINi52YTZiSDY
rdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2KfYrNmH2KfYtgoK2K3YqNmI2Kgg2LPYp9mK2KrZ
iNiq2YMg2KfZhNin2KzZh9in2LYKCtmD2YrZgSDYo9i52KvYsSDYudmE2Ykg2K3YqNmI2Kgg2LPY
p9mK2KrZiNiq2YMg2YHZiiDYp9mE2KfZhdin2LHYp9iqCgrZg9mK2YEg2KPYudir2LEg2LnZhNmJ
INit2KjZiNioINiz2KfZitiq2YjYqtmDCgoK2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDZhdi2
2YXZiNmGINin2YTYp9mF2KfYsdin2Kog2KjYo9ir2YXZhtipINmF2LTYrNi52Kkg2YjZhdmG2KfY
s9io2KkKCtit2KjZiNioINin2YTYs9in2YrYqtmI2KrZgyDYp9mE2KfYrNmH2KfYtiDZhNmE2KjZ
iti5INmB2Yog2KfZhNin2YXYp9ix2KfYqgoK2KjZiti5INiz2KfZitiq2YjYqtmDINin2YTYp9i1
2YTZigoK2LPYp9mK2KrZiNiq2YMg2KfZhNin2LXZhNmKINiv2KjZigoK2KjZiti5INi02LHYp9ih
INin2YTYp9is2YfYp9i2INiz2KfZitiq2YjYqtmDIOKAk9iv2KjZiiBfINin2YTYtNin2LHZgtmH
CgrZitiq2YjZgdixINmE2K/ZitmG2Kcg2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2LPYp9mK2KrZ
iNiq2YMKCkN5dG90ZWMgbWlzb3Byb3N0b2wgMjAwIG1nINin2YTYqNix2YrYt9in2YbZiiAoINin
2YTYp9mG2KzZhNmK2LLZiikg2KfZhNij2LXZhNmKINmF2YYg2YHYp9mK2LLYsSDYp9mE2KrZiNi1
2YrZhCAK2YXYqtmI2YHYsSDZhNis2YXZiti5INiv2YjZhCDYp9mE2K7ZhNmK2Kwg2KfZhNi52LHY
qNmKINmI2K/ZiNmEINin2YTYudin2YTZhQoK2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio
2YrYuSDZgdmKINin2YTYp9mF2KfYsdin2Kog2LPYp9mK2KrZiNiq2YMg2KfZhNin2LXZhNmKCgrY
s9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB2Yog2KfZhNin2YXYp9ix2KfYqgoK2K3YqNmI2Kgg
2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDZgdmKINiv2KjZigoK2LPYp9mK2KrZiNiq2YMg2YTZ
hNio2YrYuSDZgdmKINi52KzZhdin2YYKCtit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTYqNmK
2Lkg2YHZiiDYp9io2YjYuNio2YoKCtiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZiiDYp9mE
2KfZhdin2LHYp9iqCgrYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2KfYrNmH2KfYtiDZhNmE
2KjZiti5INin2YTYp9mF2KfYsdin2KoKCtiz2KfZitiq2YjYqtmDINin2YTYp9is2YfYp9i2INmE
2YTYqNmK2Lkg2YHZiiDYr9io2YoKCtit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTYp9is2YfY
p9i2INmB2Yog2KfZhNi02KfYsdmC2YcKCtin2YTYrdmF2YQg2LPYp9mK2KrZiNiq2YMg2YTZhNio
2YrYuSDZhdmGINiv2KfYrtmEINin2YTYp9mF2KfYsdin2Kog2K/YqNmKINin2YTYtNin2LHZgtmH
CgrYqNmK2Lkg2LTYsdin2KEg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNil2KzZh9in2LYg
2KfZhNi02KfYsdmC2YcKCtit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTYp9is2YfYp9i2INmF
2KrYp9it2Kkg2KfZhNin2YYg2YHZiiDYr9io2YoKCtil2YbYstin2YQg2KfZhNit2YXZhCDYs9in
2YrYqtmI2KrZgyDYp9mE2KjYsdmK2LfYp9mG2YrYqSDZhNmE2KjZiti5CgrYqNin2YTYp9mF2KfY
sdin2Kog2YjYqtmI2LXZitmEINmF2KzYp9mG2Yog2KjZhtmB2LMg2YrZiNmFINin2YTYt9mE2Kgg
2YTYrNmF2YrYuSDZhdmG2KfYt9mCINin2YTYp9mF2KfYsdin2KoKCtmE2KXZhtiy2KfZhCDYp9mE
2K3ZhdmEINin2YTZhdmG2LLZhNmKINin2YTYotmF2YYg2YjYqNiv2YjZhiDYotir2KfYsSDYrNin
2YbYqNmK2KkgLCDYs9in2YrYqtmI2KrZgyDZh9mIINin2YTYrdmEINin2YTYo9mF2KvZhAoK2K3Y
qNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDZhNil2KzZh9in2LYg2KfZhNit2YXZhCDY
qNmK2Lkg2LTYsdin2KEg2KfZhNin2YXYp9ix2KfYqiDYr9io2Yog2KfZhNi02KfYsdmC2YcKCtiz
2KfZitiq2YjYqtmDINmE2YTYp9is2YfYp9i2ICwg2KfZhNin2KzZh9in2LYg2LPYp9mK2KrZiNiq
2YMgLCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYr9io2YogLCDYrdio2YjYqCDYp9is2YfYp9i2
CgrYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2LTYp9ix2YLZhyAsINiz2KfZitiq2YjYqtmD
INiv2KjZiiAsINit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTYudmK2YYKCtin2YTYp9is2YfY
p9i2INiz2KfZitiq2YjYqtmDINin2YTYp9i12YTZitipINmE2YTYqNmK2Lkg2YHZiiDYp9mE2KfZ
hdin2LHYp9iqINiv2KjZigoK2YPZitmBINij2K3YtdmEINi52YTZiSDYs9in2YrYqtmI2KrZgyDY
p9mE2KfYrNmH2KfYtgoK2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNin2KzZh9in2LYKCtmD
2YrZgSDYo9i52KvYsSDYudmE2Ykg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE2KfZhdin2LHYp9iq
CgotLSAKWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJl
ZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2IiBncm91cC4KVG8gdW5zdWJzY3JpYmUg
ZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9wIHJlY2VpdmluZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBh
biBlbWFpbCB0byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmll
dyB0aGlzIGRpc2N1c3Npb24gb24gdGhlIHdlYiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUu
Y29tL2QvbXNnaWQva2FzYW4tZGV2LzI1NjVjNmYwLWM3YjEtNGRjZi05OGVlLTVlZDY1ODFiYjYy
Mm4lNDBnb29nbGVncm91cHMuY29tLgo=
------=_Part_944853_1290994503.1721702153217
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

2LPYp9mK2KrZiNiq2YMg2KfZhNin2LXZhNmKINiv2KjZiiDZiNis2YXZiti5INiv2YjZhCDYp9mE
2K7ZhNmK2Kw8YnIgLz4mZ3Q7PGJyIC8+Jmd0OyAwMDk3MTU1MzAzMTg0NjxiciAvPiZndDs8YnIg
Lz4mZ3Q7IMKg2KrZiNin2LXZhCDZhdi52YbYpyDYudio2LEg2KfZhNmI2KfYqtiz2KfYqCDYo9mI
INin2YTYqtmK2YTYrNix2KfZhTxiciAvPjxiciAvPtit2KjZiNioINiz2KfZitiq2YjYqtmDINin
2YTYp9i12YTZitmHINmE2YTYqNmK2Lkg2K3YqNmI2Kgg2KfYs9mC2KfYtyDYp9mE2KzZhtmK2YYg
2KjYr9io2Yog2K3YqNmI2Kgg2KfZhNit2YXZhCDZhNmE2KjZiti5ICMg2KjZiti52J8g2J8gIyDY
tNix2KfYodifINifICMg2K3YqNmI2KjYnyDYnyAjINin2YTYp9is2YfYp9i22J8gIyDYs9in2YrY
qtmI2KrZg9ifICMg2YHZitifINifICMg2K/YqNmK2J8g2J8gIyDYp9mE2LTYp9ix2YLZh9ifINif
ICMg2LnYrNmF2KfZhtifINifICMg2KfZhNi52YrZhtifINifICMg2KfYqNmI2LjYqNmK2J8gIyDY
p9mE2KzZhtmK2YbYnyAjINiz2KfZitiq2YjYqtmD2J8g2J8gIyDZhNmE2KjZiti52J8gQ3l0b3Rl
YyAjICMg2KfZhNin2YXYp9ix2KfYqiAjINmB2YrYnyAjINiv2KjZitifICMg2LPYp9mK2KrZiNiq
2YMg2YTZhNio2YrYuSDZhdmGINiv2KfYrtmEICMg2K/YqNmKICMg2LTYp9ix2YLZhyAjINi52KzZ
hdin2YYg2YTZhNi32YTYqCDZhdmGINio2KfZgtmKINin2YTYr9mI2YQg2YHZiiDYp9mE2K7ZhNmK
2Kwg2YrYqtmI2YHYsSDZhNiv2YrZhtinINit2KjZiNioINin2YTYqNix2YrYt9in2YbZitmHINin
2YTYp9i12YTZitipINmF2Lkg2KfZhNi22YXYp9mG2KfYqiDZhNmE2KXYrNmH2KfYtiDZhNmE2KXZ
htiq2YfYp9ihINmF2YYg2LjZh9mI2LEg2KXZhtiq2LHZhtiq2YjYqtmDINin2YTYp9i12YTZitip
IDIwMCDZhdmE2YrYutix2KfZhSDZhdmGINi02LHZg9ipINmB2KfZitiy2LEg2KfZhNi52KfZhNmF
2YrYqSDZhNmE2KjZiti5INit2KjZiNioINin2KzZh9in2LYg2KfZhNit2YXZhCDYjCDYp9mE2K3Z
hdmEINiMINin2YTYrdmF2YQg2Iwg2KfZhNit2YXZhCDYjCDYp9mE2K3ZhdmEINiMINin2YTYrNmG
2YrZhiDYjCDYp9mE2KXZhdin2LHYp9iqINin2YTYudix2KjZitipINin2YTZhdiq2K3Yr9ipINiM
INin2YTYpdis2YfYp9i2INiMINin2YTYpdis2YfYp9i2INmB2Yog2KfZhNin2YXYp9ix2KfYqiDY
jCDYp9mE2KXYrNmH2KfYtiBjeXRvdGVjINio2YrYuSDZhdmG2Lkg2KfZhNin2KzZh9in2LYg2YHZ
iiDYp9mE2KfZhdin2LHYp9iqINin2YTYudix2KjZitipINin2YTZhdiq2K3Yr9ipPGJyIC8+PGJy
IC8+2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrYuSDZhdi22YXZiNmGINin2YTYp9mF
2KfYsdin2Kog2KjYo9ir2YXZhtipINmF2LTYrNi52Kkg2YjZhdmG2KfYs9io2Kk8YnIgLz48YnIg
Lz7Yrdio2YjYqCDYp9mE2LPYp9mK2KrZiNiq2YMg2KfZhNin2KzZh9in2LYg2YTZhNio2YrYuSDZ
gdmKINin2YTYp9mF2KfYsdin2Ko8YnIgLz48YnIgLz7YqNmK2Lkg2K3YqNmI2Kgg2LPYp9mK2KrZ
iNiq2YMg2KfZhNin2LXZhNmKPGJyIC8+PGJyIC8+2LPYp9mK2KrZiNiq2YMg2KfZhNin2LXZhNmK
INiv2KjZiiDZiNis2YXZiti5INiv2YjZhCDYp9mE2K7ZhNmK2Kw8YnIgLz48YnIgLz7YqNmK2Lkg
2LTYsdin2KEg2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2LPYp9mK2KrZiNiq2YMg4oCT2K/YqNmK
IF8g2KfZhNi02KfYsdmC2YcgX9in2KjZiNi42KjZijxiciAvPjxiciAvPtmK2KrZiNmB2LEg2YTY
r9mK2YbYpyDYrdio2YjYqCDYp9mE2KfYrNmH2KfYtiDYp9mE2YXZhtiy2YTZiiDYs9in2YrYqtmI
2KrZgyDZhdmK2LLZiNio2LHZiNiz2KrZiNmEPGJyIC8+PGJyIC8+Q3l0b3RlYyBtaXNvcHJvc3Rv
bCAyMDAgbWcg2KfZhNio2LHZiti32KfZhtmKICgg2KfZhNin2YbYrNmE2YrYstmKKSDYp9mE2KPY
tdmE2Yog2YXZhiDYtNix2YPYqSDZgdin2YrYstixINin2YTYqtmI2LXZitmEINmF2KrZiNmB2LEg
2YTYrNmF2YrYuSDYr9mI2YQg2KfZhNiu2YTZitisINin2YTYudix2KjZiiDZiNiv2YjZhCDYp9mE
2LnYp9mE2YU8YnIgLz48YnIgLz7Yrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB
2Yog2KfZhNin2YXYp9ix2KfYqiDYs9in2YrYqtmI2KrZgyDYp9mE2KfYtdmE2Yo8YnIgLz48YnIg
Lz7Yrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB2Yog2KfZhNin2YXYp9ix2KfY
qjxiciAvPjxiciAvPtit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZiiDYr9io
2Yo8YnIgLz48YnIgLz7Yrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZiti5INmB2Yog2LnY
rNmF2KfZhjxiciAvPjxiciAvPtit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZ
iiDYp9io2YjYuNio2Yo8YnIgLz48YnIgLz7Yrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KjZ
iti5INmB2Yog2KfZhNin2YXYp9ix2KfYqjxiciAvPjxiciAvPtit2KjZiNioINiz2KfZitiq2YjY
qtmDINin2YTYp9is2YfYp9i2INmE2YTYqNmK2Lkg2KfZhNin2YXYp9ix2KfYqjxiciAvPjxiciAv
Ptit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTYp9is2YfYp9i2INmE2YTYqNmK2Lkg2YHZiiDY
r9io2Yo8YnIgLz48YnIgLz7Yrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2KfYrNmH2KfYtiDZ
gdmKINin2YTYtNin2LHZgtmHPGJyIC8+PGJyIC8+2K3YqNmI2Kgg2KXYrNmH2KfYtiDYp9mE2K3Z
hdmEINiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YXZhiDYr9in2K7ZhCDYp9mE2KfZhdin2LHY
p9iqINiv2KjZiiDYp9mE2LTYp9ix2YLZhyDYudis2YXYp9mGPGJyIC8+PGJyIC8+2KjZiti5INi0
2LHYp9ihINit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTYpdis2YfYp9i2INi52KzZhdin2YYg
2KfZhNi02KfYsdmC2Yc8YnIgLz48YnIgLz7Yrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhNmE2KfY
rNmH2KfYtiDZhdiq2KfYrdipINin2YTYp9mGINmB2Yog2K/YqNmKPGJyIC8+PGJyIC8+2K3YqNmI
2Kgg2KXZhtiy2KfZhCDYp9mE2K3ZhdmEINiz2KfZitiq2YjYqtmDINin2YTYqNix2YrYt9in2YbZ
itipINin2YTYo9i12YTZitipINmE2YTYqNmK2Lk8YnIgLz48YnIgLz7YqNin2YTYp9mF2KfYsdin
2Kog2YjYqtmI2LXZitmEINmF2KzYp9mG2Yog2KjZhtmB2LMg2YrZiNmFINin2YTYt9mE2Kgg2YTY
rNmF2YrYuSDZhdmG2KfYt9mCINin2YTYp9mF2KfYsdin2Ko8YnIgLz48YnIgLz7ZhNil2YbYstin
2YQg2KfZhNit2YXZhCDYp9mE2YXZhtiy2YTZiiDYp9mE2KLZhdmGINmI2KjYr9mI2YYg2KLYq9in
2LEg2KzYp9mG2KjZitipICwg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNij2LXZhNmK2Kkg
2YfZiCDYp9mE2K3ZhCDYp9mE2KPZhdir2YQ8YnIgLz48YnIgLz7Yrdio2YjYqCDYs9in2YrYqtmI
2KrZgyDZhNmE2KjZiti5INmE2KXYrNmH2KfYtiDYp9mE2K3ZhdmEINio2YrYuSDYtNix2KfYoSDY
p9mE2KfZhdin2LHYp9iqINiv2KjZiiDYudis2YXYp9mGINin2YTYtNin2LHZgtmHPGJyIC8+PGJy
IC8+2LPYp9mK2KrZiNiq2YMg2YTZhNin2KzZh9in2LYgLCDYrdio2YjYqCDYp9mE2KfYrNmH2KfY
tiDYs9in2YrYqtmI2KrZgyAsINit2KjZiNioINiz2KfZitiq2YjYqtmDINiv2KjZiiAsINit2KjZ
iNioINil2KzZh9in2LYgLCDYrdio2YjYqCDYp9is2YfYp9i2PGJyIC8+PGJyIC8+2K3YqNmI2Kgg
2LPYp9mK2KrZiNiq2YMg2KfZhNi02KfYsdmC2YcgLCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDY
r9io2YogLCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYudis2YXYp9mGICwg2K3YqNmI2Kgg2LPY
p9mK2KrZiNiq2YMg2KfZhNi52YrZhjxiciAvPjxiciAvPtit2KjZiNioINin2YTYp9is2YfYp9i2
INiz2KfZitiq2YjYqtmDINin2YTYp9i12YTZitipINmE2YTYqNmK2Lkg2YHZiiDYp9mE2KfZhdin
2LHYp9iqINiv2KjZiiDYudis2YXYp9mGINin2KjZiNi42KjZijxiciAvPjxiciAvPtmD2YrZgSDY
p9it2LXZhCDYudmE2Ykg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNin2KzZh9in2LY8YnIg
Lz48YnIgLz7Yrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2KfYrNmH2KfYtjxiciAvPjxiciAv
PtmD2YrZgSDYo9i52KvYsSDYudmE2Ykg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YHZiiDYp9mE
2KfZhdin2LHYp9iqPGJyIC8+PGJyIC8+2YPZitmBINij2LnYq9ixINi52YTZiSDYrdio2YjYqCDY
s9in2YrYqtmI2KrZgzxiciAvPjxiciAvPjxiciAvPtiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg
2YXYttmF2YjZhiDYp9mE2KfZhdin2LHYp9iqINio2KPYq9mF2YbYqSDZhdi02KzYudipINmI2YXZ
htin2LPYqNipPGJyIC8+PGJyIC8+2K3YqNmI2Kgg2KfZhNiz2KfZitiq2YjYqtmDINin2YTYp9is
2YfYp9i2INmE2YTYqNmK2Lkg2YHZiiDYp9mE2KfZhdin2LHYp9iqPGJyIC8+PGJyIC8+2KjZiti5
INiz2KfZitiq2YjYqtmDINin2YTYp9i12YTZijxiciAvPjxiciAvPtiz2KfZitiq2YjYqtmDINin
2YTYp9i12YTZiiDYr9io2Yo8YnIgLz48YnIgLz7YqNmK2Lkg2LTYsdin2KEg2KfZhNin2KzZh9in
2LYg2LPYp9mK2KrZiNiq2YMg4oCT2K/YqNmKIF8g2KfZhNi02KfYsdmC2Yc8YnIgLz48YnIgLz7Z
itiq2YjZgdixINmE2K/ZitmG2Kcg2K3YqNmI2Kgg2KfZhNin2KzZh9in2LYg2LPYp9mK2KrZiNiq
2YM8YnIgLz48YnIgLz5DeXRvdGVjIG1pc29wcm9zdG9sIDIwMCBtZyDYp9mE2KjYsdmK2LfYp9mG
2YogKCDYp9mE2KfZhtis2YTZitiy2YopINin2YTYo9i12YTZiiDZhdmGINmB2KfZitiy2LEg2KfZ
hNiq2YjYtdmK2YQg2YXYqtmI2YHYsSDZhNis2YXZiti5INiv2YjZhCDYp9mE2K7ZhNmK2Kwg2KfZ
hNi52LHYqNmKINmI2K/ZiNmEINin2YTYudin2YTZhTxiciAvPjxiciAvPtit2KjZiNioINiz2KfZ
itiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZiiDYp9mE2KfZhdin2LHYp9iqINiz2KfZitiq2YjYqtmD
INin2YTYp9i12YTZijxiciAvPjxiciAvPtiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZiiDY
p9mE2KfZhdin2LHYp9iqPGJyIC8+PGJyIC8+2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio
2YrYuSDZgdmKINiv2KjZijxiciAvPjxiciAvPtiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YHZ
iiDYudis2YXYp9mGPGJyIC8+PGJyIC8+2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2YTZhNio2YrY
uSDZgdmKINin2KjZiNi42KjZijxiciAvPjxiciAvPtiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg
2YHZiiDYp9mE2KfZhdin2LHYp9iqPGJyIC8+PGJyIC8+2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg
2KfZhNin2KzZh9in2LYg2YTZhNio2YrYuSDYp9mE2KfZhdin2LHYp9iqPGJyIC8+PGJyIC8+2LPY
p9mK2KrZiNiq2YMg2KfZhNin2KzZh9in2LYg2YTZhNio2YrYuSDZgdmKINiv2KjZijxiciAvPjxi
ciAvPtit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTYp9is2YfYp9i2INmB2Yog2KfZhNi02KfY
sdmC2Yc8YnIgLz48YnIgLz7Yp9mE2K3ZhdmEINiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YXZ
hiDYr9in2K7ZhCDYp9mE2KfZhdin2LHYp9iqINiv2KjZiiDYp9mE2LTYp9ix2YLZhzxiciAvPjxi
ciAvPtio2YrYuSDYtNix2KfYoSDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2KXYrNmH2KfY
tiDYp9mE2LTYp9ix2YLZhzxiciAvPjxiciAvPtit2KjZiNioINiz2KfZitiq2YjYqtmDINmE2YTY
p9is2YfYp9i2INmF2KrYp9it2Kkg2KfZhNin2YYg2YHZiiDYr9io2Yo8YnIgLz48YnIgLz7YpdmG
2LLYp9mEINin2YTYrdmF2YQg2LPYp9mK2KrZiNiq2YMg2KfZhNio2LHZiti32KfZhtmK2Kkg2YTZ
hNio2YrYuTxiciAvPjxiciAvPtio2KfZhNin2YXYp9ix2KfYqiDZiNiq2YjYtdmK2YQg2YXYrNin
2YbZiiDYqNmG2YHYsyDZitmI2YUg2KfZhNi32YTYqCDZhNis2YXZiti5INmF2YbYp9i32YIg2KfZ
hNin2YXYp9ix2KfYqjxiciAvPjxiciAvPtmE2KXZhtiy2KfZhCDYp9mE2K3ZhdmEINin2YTZhdmG
2LLZhNmKINin2YTYotmF2YYg2YjYqNiv2YjZhiDYotir2KfYsSDYrNin2YbYqNmK2KkgLCDYs9in
2YrYqtmI2KrZgyDZh9mIINin2YTYrdmEINin2YTYo9mF2KvZhDxiciAvPjxiciAvPtit2KjZiNio
INiz2KfZitiq2YjYqtmDINmE2YTYqNmK2Lkg2YTYpdis2YfYp9i2INin2YTYrdmF2YQg2KjZiti5
INi02LHYp9ihINin2YTYp9mF2KfYsdin2Kog2K/YqNmKINin2YTYtNin2LHZgtmHPGJyIC8+PGJy
IC8+2LPYp9mK2KrZiNiq2YMg2YTZhNin2KzZh9in2LYgLCDYp9mE2KfYrNmH2KfYtiDYs9in2YrY
qtmI2KrZgyAsINit2KjZiNioINiz2KfZitiq2YjYqtmDINiv2KjZiiAsINit2KjZiNioINin2KzZ
h9in2LY8YnIgLz48YnIgLz7Yrdio2YjYqCDYs9in2YrYqtmI2KrZgyDYp9mE2LTYp9ix2YLZhyAs
INiz2KfZitiq2YjYqtmDINiv2KjZiiAsINit2KjZiNioINiz2KfZitiq2YjYqtmDINin2YTYudmK
2YY8YnIgLz48YnIgLz7Yp9mE2KfYrNmH2KfYtiDYs9in2YrYqtmI2KrZgyDYp9mE2KfYtdmE2YrY
qSDZhNmE2KjZiti5INmB2Yog2KfZhNin2YXYp9ix2KfYqiDYr9io2Yo8YnIgLz48YnIgLz7Zg9mK
2YEg2KPYrdi12YQg2LnZhNmJINiz2KfZitiq2YjYqtmDINin2YTYp9is2YfYp9i2PGJyIC8+PGJy
IC8+2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNin2KzZh9in2LY8YnIgLz48YnIgLz7Zg9mK
2YEg2KPYudir2LEg2LnZhNmJINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNin2YXYp9ix2KfYqjxi
ciAvPjxiciAvPg0KDQo8cD48L3A+CgotLSA8YnIgLz4KWW91IHJlY2VpdmVkIHRoaXMgbWVzc2Fn
ZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAmcXVvdDtr
YXNhbi1kZXYmcXVvdDsgZ3JvdXAuPGJyIC8+ClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91
cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8gPGEg
aHJlZj0ibWFpbHRvOmthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tIj5rYXNh
bi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhp
cyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgPGEgaHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29v
Z2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi8yNTY1YzZmMC1jN2IxLTRkY2YtOThlZS01ZWQ2NTgx
YmI2MjJuJTQwZ29vZ2xlZ3JvdXBzLmNvbT91dG1fbWVkaXVtPWVtYWlsJnV0bV9zb3VyY2U9Zm9v
dGVyIj5odHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2LzI1NjVjNmYw
LWM3YjEtNGRjZi05OGVlLTVlZDY1ODFiYjYyMm4lNDBnb29nbGVncm91cHMuY29tPC9hPi48YnIg
Lz4K
------=_Part_944853_1290994503.1721702153217--

------=_Part_944852_1952934475.1721702153217--
