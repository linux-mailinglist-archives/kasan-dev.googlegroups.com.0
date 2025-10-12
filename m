Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBPMIVXDQMGQEZARYFXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D4025BCFF89
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Oct 2025 08:01:50 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-58afd11b4d4sf1592051e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Oct 2025 23:01:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760248895; cv=pass;
        d=google.com; s=arc-20240605;
        b=HbbqgwVeQr3nIh9s+wIaf/EjgDt52a+6t0dlqvRVK8bMEViiWbcfSIQNHfQ6un34g1
         i2FHLdjNG9w7+HdpuK/gbfyAOFGjqQPUItdPycPx9m5ALCRccTST1RKPtxMR9MOSI5kt
         dnmaZtEgLHIUOWMkYynA6VEb2z8ypVXnWcsKcucMJ5uPtbV/rYR76LkR69LBTbzS7aIq
         9h725XNBcoMdsgI1OzQXmCQDtW0gPp80WsDBXQmmlPEVl8RbpvGNt717Bmy0GnGD0hqY
         FmA0yTR4vfxpC1KTpmlMPPLhu3TUl+Py4LCr/VxVvXYDzdX7xwRac76sRVVFvC0ASpow
         U8IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=UCR2RtSwP9QLrPz4Fz56d6g22v31aokGVm82fVibg3s=;
        fh=BYVo+sklT6Pw2KSl1t94cx4BzVTdiEZThDhNHdFV7Lk=;
        b=AnQhZjVMSRDeWMHGn8fAWvUt3zmZcUPCe5YJfS9Y8/aQV/+EhcQclEWyY2GUBVfli8
         1hzsQBEIZ+doF3Ekc+GfNxY+l6kTWfP83PpNXxVuKwdya0iEam7fyaXda0wh4PdwBAHz
         squd9crYwQRsU5GtQJ9Bs4WMuH9ZlLWuy1Ha3hl2Qs+EVxdxUT6NghX6bPSKKvnPWdoR
         KJA5bLu+CdaIEvInyw3+wCf+Nf9+UHph/gKaoAQbNVwpwzIUkabUKHaDf6MFIiS5Y/Z9
         X5RvWbV19C8IjRgv6NCQa0SOocWNZEV7ByL6OlmvhPirTWi6QqMWyiDm53IWsn+7Rasq
         +QCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M2Kjv4Jb;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760248895; x=1760853695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UCR2RtSwP9QLrPz4Fz56d6g22v31aokGVm82fVibg3s=;
        b=T/AkbF8Na+PtyAA46iO66GMV2fZPshiGiGhPHsCI7kJuJwWNHTg+JUulLF41uM64uk
         YIgtPPbxak9FIfkTX4dbBgekRx4t1CRDMLYbhGHt0tEri+Z829061TSkJSyb81a4ClSA
         qWyN75npfoq4czW4BTlXtkNWRaR6D9N3Rb+GoT5Q5UoNsnosb38ASuefRUBIgnXyLLqS
         M26Bsc2dkG2zluO3znu478EYnZcwokmoDoelf3j25rN30LZC65kD0htlOtuGPIMfHYUF
         NiGHRK10sRV+Ryyv4j7pU60v9Gi2z7sEG2w+NIS8KZQiQT4S2Hk5b3GV0bbI95Verb87
         GG/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760248895; x=1760853695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=UCR2RtSwP9QLrPz4Fz56d6g22v31aokGVm82fVibg3s=;
        b=fu/fobs50bZcdAzYgkBGdW0zJh1hltv7sVxToEMEyiiQh6DXqfXiNtXfytPnS4CyNW
         f31SwBHEDcyaFsWy6cUqDAab0wmgFmk9oVZaUfNfB4GT/L47LuIqQ3HAXYKy5zsJsnb8
         yEPHa8cUd1IqSI3LVkvpQBGaN6uVilICYosDfNljsQhz+oVsNRyQKfUZ0YgRxIh38YF+
         B6WnoD9GSvuj5+UUjekb6Op8rsDRu6sDUWVDVtBiUvHrFbMTKUqBke6cG4tmCIK+7/q9
         RrYX+P/s2yGgBISx9NqmJ7xq614ObZGZHfYl5W4QJ0h+nA2KIM2qLeekErdApe+N1cHt
         81eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760248895; x=1760853695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UCR2RtSwP9QLrPz4Fz56d6g22v31aokGVm82fVibg3s=;
        b=CPfjJ5djX7w+9MADKKFPs9EqZ6OhwSX9qFDpbv2aghJtiOvJ/F/5lbUq6tnHB16i0n
         o0RfFQh9pDqOuUoz+VBpnB4g8Y9kKnqq5z2lP1Jq1CdQxxsWm4fPSG+tJS79T1U00nmk
         QEUMkdmd5xabGVNvSYqCSnIecorvdBJme+xEXiyfEp5ZlCcUTz8nJmxl1w9RX3MlDs+9
         s5VIqv1YlL3eKg/tXzQKAI/0blF4LkMNmPG0gglM0ai5f1pDE6LIbIGQEoqAk9WiAm+I
         e4JMNVPI75jq5F7ncoAo3BReM3gaLPg1Nd0wwx3Ofen63rWjcV9iu+Te07KylcUOasLo
         i4BQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyvU3tyqlw39TrUYcfrgv8HAyCpy1ZSAIOGnU8q7uQNZmUffiGzTZ0kDSnOrIaX3hhFWRs/A==@lfdr.de
X-Gm-Message-State: AOJu0YxVj8hFEB3n5o/ypaoT6d3uqf6LtL2YvpgsTZGQIhzIBWs59EmL
	RZ7z76ca4DhWD2JLjtY22/+GLHRvfyLkZ8O8QSYAY1ySxu7fQV0s6J/5
X-Google-Smtp-Source: AGHT+IFq6Tt58aK53Y9UXOfnvrpH1AS9ljvRWsQJ2Bwh14AgFDSkS8wJM/M1RtMeDlXGnTvQRvRJJg==
X-Received: by 2002:a05:6512:1295:b0:55f:52a6:d4be with SMTP id 2adb3069b0e04-5906d88b2e5mr5241980e87.14.1760248894564;
        Sat, 11 Oct 2025 23:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4JGn+6eTkUVq/GKmJORr7OxQyPjpVNlHLclfVJ0Z+jAA=="
Received: by 2002:ac2:4c0f:0:b0:587:413a:5b3 with SMTP id 2adb3069b0e04-5907c5073dels844500e87.1.-pod-prod-05-eu;
 Sat, 11 Oct 2025 23:01:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUOSczoMGDHvnLiPluUQCHQB2pSRTCToC+i4HtzK4FFbANVjQS4HDOpnSywrX/aAWT77M7s3espkaE=@googlegroups.com
X-Received: by 2002:a05:6512:3ca8:b0:57d:92ec:67de with SMTP id 2adb3069b0e04-5906daeb7b6mr5021826e87.57.1760248891896;
        Sat, 11 Oct 2025 23:01:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760248891; cv=none;
        d=google.com; s=arc-20240605;
        b=ZxaZf3OweUUZgIGUcd/9v7GeYcr79x04SjuAfW1kxsjm7aAVyl5L1KD7ba+TD2+Fr+
         FSewlE9FcbpoGrTJbHJFyd/SVBJ27aHp+I2Guanny+ZLnugD0K9OFoyO4S1X3SM6L+ah
         LF8l8ekvq/KJvCSXqHjqXZf50cniJC391mAt+j75+WHVCqhlrTVyGUd+JABaVotT5076
         Hv5YyLME9GfkqGQkWYgzspXD0zuo/i4L7pdHnTcStA5tqBHuzXg7dGsPtFZWF79uAK3C
         7lFVQ950q66TgwBMjRfB0Z076TJh5z+cw/tQUiXWonwls3B5H9QKJwPG8G6HPNZ5YW8x
         gVdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=kwhzMbhiwtXeQbJwhdZlocuUFq7HwJpcQea3uq/SsgE=;
        fh=mb7cFvV4SHm+KTG9jLpT/pBNyNtL60picZEqJFtjoyM=;
        b=MGeUFzBpBCX/9TxOzuMTX/lepoDi8Ay/TaNTcwESurb38jest3zpBTQL0wXrfjLYD0
         h985hTscgNkpmTXrZu/Xvdj9//QCXVHixmptX1LnZ+hHO3m9m/Y7c1HGNn24OGH4bSIZ
         01+F9PblTf6a4kaqgSHPXKf3Snw2ItcLv252homkbcKJ0CBjXHikCn3aAH9Ewg6wQeJC
         WDNAFU5V+UKUEWp9anV+IkwPYx3yw968ucTDrYz8+WE3BwXb/n7T315Ycsn+UGpXGSE0
         kZYmG0GkLarBv2Sr4pBW5hZaUDqpuuqmL7fA1XKw0jUE8dC6j4Eu1m0DONj0Yzn3fr2M
         dZdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M2Kjv4Jb;
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-591a1c425f7si14013e87.5.2025.10.11.23.01.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Oct 2025 23:01:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id a640c23a62f3a-b3dbf11fa9eso546901166b.0
        for <kasan-dev@googlegroups.com>; Sat, 11 Oct 2025 23:01:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXMf5H9QpGcyK6Dl+m48ahjcm96Q8JmE3DK5H/c5TfrMXCSGwE2S6DvwttHW9If33DaYR8LlVu1x8s=@googlegroups.com
X-Gm-Gg: ASbGncvTIJAf6UeK18T2iCPnWJsF90w8XFstepffMxunzpY+f9WKBSrMO8/g6Fq2JTw
	BpRE6qh0tzyd6/xF913H+LAhk/uSTCOAHlvT70tjvUP9zFqaps+vk1YxH0O2kWKAMGm8eTZlYQm
	XPGTHvbaibJ315xK3ObrYtNvOd4CHQTc/qx1Ok8CKO+PXeI0/5nHmjo6d8SW/aIXk11xN3kwyZe
	zsOUQW34Q0YKLCwBBrsn2SwbZ28wSLc
X-Received: by 2002:a17:907:7ea8:b0:b4a:f6c3:7608 with SMTP id
 a640c23a62f3a-b50aa792794mr1873178566b.3.1760248890671; Sat, 11 Oct 2025
 23:01:30 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Sun, 12 Oct 2025 08:00:00 +0200
X-Gm-Features: AS18NWC-NvZaM97WpcmIJKJKDbKS8QDd6EnMW_iWUryfV2dydfmumxmt4BRV0oM
Message-ID: <CADj1ZKmK2yWCpBbE+7eRijXnUi7Wd161qvws58i-C39B25AqzA@mail.gmail.com>
Subject: =?UTF-8?B?2KfZhNio2LHZhtin2YXYrCDYp9mE2KrYr9ix2YrYqNmKOiDigJzYrdmI2YPZhdipINin?=
	=?UTF-8?B?2YTYqNmK2KfZhtin2Kog2YjYpdiv2KfYsdipINin2YTYrNmI2K/YqSDYp9mE2LHZgtmF2YrYqeKAnQ==?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000d847500640efe107"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=M2Kjv4Jb;       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::62c
 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--000000000000d847500640efe107
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2KfZhNiz2YTYp9mFINi52YTZitmD2YUg2YjYsdit2YXYqSDYp9mE2YTZhyDZiNio2LHZg9in2KrZ
hw0KDQrYqtmH2K/ZitmD2YUg2KfZhNiv2KfYsSDYp9mE2LnYsdio2YrYqSDZhNmE2KrZhtmF2YrY
qSDYp9mE2KXYr9in2LHZitipINij2LfZitioINiq2K3Zitin2KrZh9inINmI2KPYtdiv2YIg2KrZ
hdmG2YrYp9iq2YfYpyDYqNiv2YjYp9mFDQrYp9mE2KrZiNmB2YrZgi4NCg0K2KrYr9i52YjZg9mF
INmE2YTZhdi02KfYsdmD2Kkg2YHZijoNCirYp9mE2KjYsdmG2KfZhdisINin2YTYqtiv2LHZitio
2Yo6IOKAnNit2YjZg9mF2Kkg2KfZhNio2YrYp9mG2KfYqiDZiNil2K/Yp9ix2Kkg2KfZhNis2YjY
r9ipINin2YTYsdmC2YXZitip4oCdKg0KDQrYqNin2YTZgtin2YfYsdipIOKAkyDYrNmF2YfZiNix
2YrYqSDZhdi12LEg2KfZhNi52LHYqNmK2KkNCg0K2K7ZhNin2YQg2KfZhNmB2KrYsdipINmF2YYg
MTnYp9mE2YogMjMg2KfZg9iq2YjYqNixIDIwMjUg2YUgINmE2YXYr9ipIDUg2KfZitin2YUg2KrY
r9ix2YrYqNmK2KkNCg0K2YXZgtiv2YXYqSA6DQoNCtij2LXYqNit2Kog2KfZhNio2YrYp9mG2KfY
qiDZh9mKINin2YTZhdit2LHZgyDYp9mE2KPYs9in2LPZiiDZhNmG2KzYp9itINin2YTZhdik2LPY
s9in2Kog2YjYp9iz2KrYr9in2YXYqtmH2KcuINmI2YXZhiDZh9mG2Kcg2KjYsdiy2KoNCtij2YfZ
hdmK2Kkg2K3ZiNmD2YXYqSDYp9mE2KjZitin2YbYp9iqINmD2KXYt9in2LEg2LTYp9mF2YQg2YTY
pdiv2KfYsdipINin2YTYqNmK2KfZhtin2Kog2YjYttmF2KfZhiDYrNmI2K/YqtmH2KfYjCDYqNmF
2Kcg2YrYrdmC2YINCtin2YTZg9mB2KfYodipINin2YTYqti02LrZitmE2YrYqdiMINmI2YrYr9i5
2YUg2KfYqtiu2KfYsCDYp9mE2YLYsdin2LEg2KfZhNmF2KjZhtmKINi52YTZiSDZhdi52YTZiNmF
2KfYqiDYr9mC2YrZgtipINmI2YXZiNir2YjZgtipLg0KDQrYqtmH2K/ZgSDZh9iw2Ycg2KfZhNiv
2YjYsdipINil2YTZiSDYqtmF2YPZitmGINin2YTZhdi02KfYsdmD2YrZhiDZhdmGINmB2YfZhSDY
p9mE2KPYs9izINmI2KfZhNmF2YbZh9is2YrYp9iqINin2YTYrdiv2YrYq9ipINmE2K3ZiNmD2YXY
qQ0K2KfZhNio2YrYp9mG2KfYqiDZiNil2K/Yp9ix2Kkg2KfZhNis2YjYr9ipINin2YTYsdmC2YXZ
itip2Iwg2YjYp9mE2KrYudix2YEg2LnZhNmJINij2YHYttmEINin2YTZhdmF2KfYsdiz2KfYqiDY
p9mE2LnYp9mE2YXZitipDQrZiNiq2LfYqNmK2YLZh9inINmB2Yog2KjZitim2KfYqiDYp9mE2LnZ
hdmEINin2YTZhdik2LPYs9mK2KkuDQoNCtin2YTYp9mH2K/Yp9mBIDoNCg0K2KjZhtmH2KfZitip
INin2YTYqNix2YbYp9mF2Kwg2LPZitmD2YjZhiDYp9mE2YXYtNin2LHZg9mI2YYg2YLYp9iv2LHZ
itmGINi52YTZiToNCg0KMS4gICAgICAgINmB2YfZhSDYp9mE2YXZgdin2YfZitmFINin2YTYo9iz
2KfYs9mK2Kkg2YTYrdmI2YPZhdipINin2YTYqNmK2KfZhtin2Kog2YjYpdiv2KfYsdipINin2YTY
rNmI2K/YqSDYp9mE2LHZgtmF2YrYqS4NCg0KMi4gICAgICAgINin2YTYqti52LHZgSDYudmE2Ykg
2KfZhNij2LfYsSDZiNin2YTZhdi52KfZitmK2LEg2KfZhNi52KfZhNmF2YrYqSDZgdmKINmF2KzY
p9mEINit2YjZg9mF2Kkg2KfZhNio2YrYp9mG2KfYqiAo2YXYq9mEIERBTUEsDQpJU08pLg0KDQoz
LiAgICAgICAg2KjZhtin2KEg2LPZitin2LPYp9iqINmI2KXYrNix2KfYodin2Kog2YTYrdmI2YPZ
hdipINin2YTYqNmK2KfZhtin2Kog2K/Yp9iu2YQg2KfZhNmF2KTYs9iz2KkuDQoNCjQuICAgICAg
ICDYqti12YXZitmFINii2YTZitin2Kog2YTZgtmK2KfYsyDZiNiq2K3Ys9mK2YYg2KzZiNiv2Kkg
2KfZhNio2YrYp9mG2KfYqi4NCg0KNS4gICAgICAgINix2KjYtyDYrdmI2YPZhdipINin2YTYqNmK
2KfZhtin2Kog2KjYp9mE2KrYrdmI2YQg2KfZhNix2YLZhdmKINmI2KXYr9in2LHYqSDYp9mE2YXY
rtin2LfYsSDYp9mE2YXYpNiz2LPZitipLg0KDQo2LiAgICAgICAg2KXYudiv2KfYryDYrti32Lcg
2LnZhdmE2YrYqSDZhNiq2LfYqNmK2YIg2KfZhNit2YjZg9mF2Kkg2YjYttmF2KfZhiDYp9iz2KrY
r9in2YXYqSDYp9mE2KzZiNiv2Kkg2KfZhNix2YLZhdmK2KkuDQoNCtin2YTZhdit2KfZiNixIDoN
Cg0KXCAgICDwn5S5INin2YTZitmI2YUg2KfZhNij2YjZhDog2KfZhNij2LPYp9iz2YrYp9iqINmI
2KfZhNil2LfYp9ixINin2YTYudin2YUNCg0KXCAgICDwn5S5INin2YTZitmI2YUg2KfZhNir2KfZ
htmKOiDYp9mE2LPZitin2LPYp9iqINmI2KfZhNij2K/ZiNin2LEg2YjYp9mE2YXYs9ik2YjZhNmK
2KfYqg0KDQpcICAgIPCflLkg2KfZhNmK2YjZhSDYp9mE2KvYp9mE2Ks6INil2K/Yp9ix2Kkg2KzZ
iNiv2Kkg2KfZhNio2YrYp9mG2KfYqg0KDQpcICAgIPCflLkg2KfZhNmK2YjZhSDYp9mE2LHYp9io
2Lk6INin2YTYqtmD2YbZiNmE2YjYrNmK2Kcg2YjYp9mE2KrYrdmI2YQg2KfZhNix2YLZhdmKDQoN
ClwgICAg8J+UuSDYp9mE2YrZiNmFINin2YTYrtin2YXYszog2KfZhNiq2LfYqNmK2YIg2KfZhNi5
2YXZhNmKINmI2K/Ysdin2LPYqSDYrdin2YTYp9iqDQoNCg0KDQrYp9mE2YXYs9iq2YfYr9mB2YjZ
hiA6DQoNCsKoICAgICAg2KfZhNmC2YrYp9iv2KfYqiDYp9mE2KXYr9in2LHZitipINmB2Yog2KfZ
hNmF2KTYs9iz2KfYqiDYp9mE2K3Zg9mI2YXZitipINmI2KfZhNiu2KfYtdipLg0KDQrCqCAgICAg
INmF2K/Ysdin2KEg2KrZgtmG2YrYqSDYp9mE2YXYudmE2YjZhdin2Kog2YjYp9mE2KrYrdmI2YQg
2KfZhNix2YLZhdmKLg0KDQrCqCAgICAgINmF2LPYpNmI2YTZiCDYp9mE2KjZitin2YbYp9iqINmI
2KfZhNmF2K3ZhNmE2YjZhi4NCg0KwqggICAgICDZhdiv2LHYp9ihINin2YTYrNmI2K/YqSDZiNil
2K/Yp9ix2Kkg2KfZhNmF2K7Yp9i32LEuDQoNCsKoICAgICAg2YHYsdmCINin2YTYudmF2YQg2KfZ
hNmF2LnZhtmK2Kkg2KjYp9mE2LDZg9in2KEg2KfZhNin2LXYt9mG2KfYudmKINmI2KfZhNiq2K3Z
hNmK2YTYp9iqINin2YTYttiu2YXYqS4NCg0KwqggICAgICDYp9mE2KPZg9in2K/ZitmF2YrZiNmG
INmI2KfZhNio2KfYrdir2YjZhiDYp9mE2YXZh9iq2YXZiNmGINio2YXYrNin2YQg2KfZhNit2YjZ
g9mF2Kkg2KfZhNix2YLZhdmK2KkNCg0KDQoNCtmK2LPYudiv2YbYpyDYo9mGINmG2KTZg9ivINin
2YbYudmC2KfYryDYp9mE2YjYsdi0INin2YTYqtiv2LHZitio2YrYqSDYp9mE2KrYp9mE2YrYqdiM
ICAgICDZiNiw2YTZgyDZgdmKINin2YTZgdiq2LHYqSDZhdmGIDE5IOKAkw0KMjMg2KPZg9iq2YjY
qNixIDIwMjXYjA0KDQrYqNmF2YLYsSDYp9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG
2YXZitipINin2YTYpdiv2KfYsdmK2Kkg4oCTINin2YTZgtin2YfYsdipICDYqNin2K/YsSDYqNin
2YTYrdis2LINCg0KDQoNCjEuICAgICAgICAgICAgICAgICAgINiv2YjYsdipINmB2Yog2KfZhNmF
2YfYp9ix2KfYqiDYp9mE2KXYr9in2LHZitipINin2YTYo9iz2KfYs9mK2Kkg2YTZhNmF2K/Ysdin
2KEg2KfZhNis2K/Yrw0KDQoyLiAgICAgICAgICAgICAgICAgICDYr9mI2LHYqSDZgdmKINmF2YfY
p9ix2KfYqiDYp9mE2KrYrti32YrYtyDYp9mE2KfYs9iq2LHYp9iq2YrYrNmKDQoNCjMuICAgICAg
ICAgICAgICAgICAgINiv2YjYsdipINij2LPYp9iz2YrYp9iqINil2K/Yp9ix2Kkg2KfZhNiq2LrZ
itmK2LENCg0KNC4gICAgICAgICAgICAgICAgICAg2K/ZiNix2Kkg2KrYrdmE2YrZhCDZiNiq2YLZ
itmK2YUg2KfZhNij2K/Yp9ihINin2YTZhdik2LPYs9mKDQoNCjUuICAgICAgICAgICAgICAgICAg
INiv2YjYsdipINmB2Yog2KfZhNiq2YbYuNmK2YUg2YjYpdiv2KfYsdipINin2YTZiNmC2Kog2KjZ
gdi52KfZhNmK2KkNCg0KNi4gICAgICAgICAgICAgICAgICAg2K/ZiNix2Kkg2YHZiiDYp9mE2YXZ
h9in2LHYp9iqINin2YTYpdiv2KfYsdmK2Kkg2YTZhNmF2YjYuNmB2YrZhiDYp9mE2YXYqNiq2K/Y
ptmK2YYNCg0KNy4gICAgICAgICAgICAgICAgICAg2K/ZiNix2Kkg2K3ZhCDYp9mE2YXYtNmD2YTY
p9iqINmI2KfYqtiu2KfYsCDYp9mE2YLYsdin2LENCg0KOC4gICAgICAgICAgICAgICAgICAg2K/Z
iNix2Kkg2YXZh9in2LHYp9iqINin2YTYqtmI2KfYtdmEINin2YTZgdi52KfZhCDZgdmKINio2YrY
ptipINin2YTYudmF2YQNCg0KOS4gICAgICAgICAgICAgICAgICAg2K/ZiNix2Kkg2KjZhtin2KEg
2YjYpdiv2KfYsdipINmB2LHZgiDYp9mE2LnZhdmEDQoNCjEwLiAgICAgICAgICAgICDYr9mI2LHY
qSDYp9mE2KrYrdmB2YrYsiDZiNio2YbYp9ihINmB2LHZgiDYp9mE2LnZhdmEDQoNCjExLiAgICAg
ICAgICAgICDYr9mI2LHYqSDZgdmKINin2YTZhdmH2KfYsdin2Kog2KfZhNil2K/Yp9ix2YrYqSDY
p9mE2YXYqtmC2K/ZhdipINmE2YTZhdi02LHZgdmK2YYNCg0KMTIuICAgICAgICAgICAgINiv2YjY
sdipINil2K/Yp9ix2Kkg2KfZhNi12LHYp9i5INmI2KfZhNiq2LnYp9mF2YQg2YXYuSDYp9mE2YbY
stin2LnYp9iqDQoNCjEzLiAgICAgICAgICAgICDYr9mI2LHYqSDYp9mE2KrZgdmD2YrYsSDYp9mE
2KfYqNiq2YPYp9ix2Yog2YHZiiDYrdmEINin2YTZhdi02YPZhNin2KoNCg0KMTQuICAgICAgICAg
ICAgINiv2YjYsdipINmB2Yog2YXZh9in2LHYp9iqINin2YTYqtmB2KfZiNi2INmI2KfZhNiq2YjY
p9i12YQg2KfZhNmB2LnYp9mEDQoNCjE1LiAgICAgICAgICAgICDYr9mI2LHYqSDYpdiv2KfYsdip
INin2YTZhdi02KfYsdmK2Lkg2KfZhNi12LrZitix2Kkg2YjYp9mE2YXYqtmI2LPYt9ipDQoNCjE2
LiAgICAgICAgICAgICDYr9mI2LHYqSDYqti32YjZitixINmF2YfYp9ix2KfYqiDYp9mE2YLZitin
2K/YqSDYp9mE2LTYrti12YrYqQ0KDQoxNy4gICAgICAgICAgICAg2K/ZiNix2Kkg2YHZiiDYo9iz
2KfYs9mK2KfYqiDYp9mE2KXYr9in2LHYqSDYp9mE2YXYp9mE2YrYqSDZhNmE2YXYr9ix2KfYoQ0K
DQoxOC4gICAgICAgICAgICAg2K/ZiNix2Kkg2KfZhNmF2YfYp9ix2KfYqiDYp9mE2KXYr9in2LHZ
itipINmE2YXYr9ix2KfYoSDYp9mE2YXZiNin2LHYryDYp9mE2KjYtNix2YrYqQ0KDQoxOS4gICAg
ICAgICAgICAg2K/ZiNix2Kkg2KXYr9in2LHYqSDYp9mE2LnZhdmE2YrYp9iqINmI2KrYrdiz2YrZ
hiDYp9mE2KzZiNiv2KkNCg0KMjAuICAgICAgICAgICAgINiv2YjYsdipINiq2K3ZhNmK2YQg2KfZ
hNio2YrYp9mG2KfYqiDZiNin2LPYqtiu2K/Yp9mF2YfYpyDZgdmKINin2KrYrtin2LAg2KfZhNmC
2LHYp9ix2KfYqg0KDQoyMS4gICAgICAgICAgICAg2K/ZiNix2Kkg2KfZhNiq2K7Yt9mK2Lcg2YjY
pdi52K/Yp9ivINin2YTZhdmK2LLYp9mG2YrYp9iqINmE2YTZhdi02KfYsdmK2LkNCg0KMjIuICAg
ICAgICAgICAgINiv2YjYsdipINmB2Yog2KXYr9in2LHYqSDYp9mE2KPYr9in2KEg2YjYpdi52K/Y
p9ivINin2YTYqtmC2KfYsdmK2LENCg0KMjMuICAgICAgICAgICAgINiv2YjYsdipINin2YTZgtmK
2KfYr9ipINmI2KfZhNiq2KPYq9mK2LEg2YHZiiDZgdix2YIg2KfZhNi52YXZhA0KDQoyNC4gICAg
ICAgICAgICAg2K/ZiNix2Kkg2YHZiiDYpdiv2KfYsdipINin2YTYqti62YrZitixINin2YTYqtmG
2LjZitmF2Yog2KjZgdi52KfZhNmK2KkNCg0KMjUuICAgICAgICAgICAgINiv2YjYsdipINmF2YfY
p9ix2KfYqiDYp9mE2KrZiNis2YrZhyDZiNin2YTYpdix2LTYp9ivINin2YTZhdmH2YbZig0KDQoy
Ni4gICAgICAgICAgICAg2K/ZiNix2Kkg2KfZhNin2LPYqtix2KfYqtmK2KzZitin2Kog2KfZhNmF
2KrZgtiv2YXYqSDZgdmKINil2K/Yp9ix2Kkg2KfZhNmF2LTYp9ix2YrYuQ0KDQoyNy4gICAgICAg
ICAgICAg2K/ZiNix2Kkg2KrYrdmE2YrZhCDYp9mE2KPYrti32KfYsSDZiNil2K/Yp9ix2Kkg2KfZ
hNij2LLZhdin2KoNCg0KMjguICAgICAgICAgICAgINiv2YjYsdipINij2LPYp9iz2YrYp9iqINin
2YTYpdiv2KfYsdipINin2YTYrdiv2YrYq9ipDQoNCjI5LiAgICAgICAgICAgICDYr9mI2LHYqSDZ
gdmKINil2K/Yp9ix2Kkg2YHYsdmCINin2YTYudmF2YQg2LnZhiDYqNmP2LnYrw0KDQozMC4gICAg
ICAgICAgICAg2K/ZiNix2Kkg2KrYrdmE2YrZhCDYs9mI2YIg2KfZhNi52YXZhCDZiNiq2LfZiNmK
2LEg2KfZhNmF2YbYqtis2KfYqg0KDQozMS4gICAgICAgICAgICAg2K/ZiNix2Kkg2YHZiiDYp9mE
2KrZgdin2YjYtiDYp9mE2KrYrNin2LHZiiDZiNin2LPYqtix2KfYqtmK2KzZitin2Kog2KfZhNio
2YrYuQ0KDQozMi4gICAgICAgICAgICAg2K/ZiNix2Kkg2KXYr9in2LHYqSDYp9mE2YXZiNin2LHY
ryDYp9mE2KjYtNix2YrYqSDYp9mE2YXYqtmC2K/ZhdipDQoNCjMzLiAgICAgICAgICAgICDYr9mI
2LHYqSDYp9mE2KrYr9ix2YrYqCDYudmE2Ykg2KfZhNmC2YrYp9iv2Kkg2KfZhNiq2YbZgdmK2LDZ
itipDQoNCjM0LiAgICAgICAgICAgICDYr9mI2LHYqSDZgdmKINil2K/Yp9ix2Kkg2KfZhNiq2YjY
p9iy2YYg2KjZitmGINin2YTYudmF2YQg2YjYp9mE2K3Zitin2Kkg2KfZhNi02K7YtdmK2KkNCg0K
MzUuICAgICAgICAgICAgINiv2YjYsdipINij2LPYp9mE2YrYqCDYp9mE2KrYrdmB2YrYsiDZiNin
2YTYqti32YjZitixINin2YTZhdmH2YbZiiDZhNmE2YXZiNi42YHZitmGDQoNCjM2LiAgICAgICAg
ICAgICDYr9mI2LHYqSDYp9mE2KrYudin2YXZhCDZhdi5INi22LrZiNi3INin2YTYudmF2YQg2KjZ
g9mB2KfYodipDQoNCjM3LiAgICAgICAgICAgICDYr9mI2LHYqSDYp9mE2KrZgdmD2YrYsSDYp9mE
2KXYqNiv2KfYudmKINmB2Yog2KjZitim2Kkg2KfZhNi52YXZhA0KDQozOC4gICAgICAgICAgICAg
2K/ZiNix2Kkg2YHZiiDYpdi52K/Yp9ivINin2YTZgtin2K/YqSDYp9mE2KzYr9ivINmE2YTZhdmG
2LjZhdin2KoNCg0KMzkuICAgICAgICAgICAgINiv2YjYsdipINin2LPYqtix2KfYqtmK2KzZitin
2Kog2KfZhNit2YHYp9i4INi52YTZiSDYp9mE2LnZhdmE2KfYoQ0KDQo0MC4gICAgICAgICAgICAg
2K/ZiNix2Kkg2YHZiiDYqti32YjZitixINin2YTZhdmH2KfYsdin2Kog2KfZhNil2K/Yp9ix2YrY
qSDZgdmKINi12YbYp9i52Kkg2KfZhNiq2YPZhtmI2YTZiNis2YrYpw0KDQo0MS4gICAgICAgICAg
ICAg2K/ZiNix2Kkg2KXYr9in2LHYqSDYp9mE2YXYrtin2LfYsSDYp9mE2YXYp9mE2YrYqSDZhNmE
2YXYpNiz2LPYp9iqDQoNCjQyLiAgICAgICAgICAgICDYr9mI2LHYqSDYp9mE2KrYrti32YrYtyDY
p9mE2KfYs9iq2LHYp9iq2YrYrNmKINmI2KrYrdmE2YrZhCDYp9mE2LPZiNmCDQoNCjQzLiAgICAg
ICAgICAgICDYr9mI2LHYqSDYpdiv2KfYsdipINin2YTYp9is2KrZhdin2LnYp9iqINmI2YHYudin
2YTZitipINin2YTYqtmI2KfYtdmEINin2YTZhdik2LPYs9mKDQoNCjQ0LiAgICAgICAgICAgICDY
r9mI2LHYqSDZgdmKINin2YTYp9iz2KrYsdin2KrZitis2YrYp9iqINin2YTYpdiv2KfYsdmK2Kkg
2YTZhNij2LnZhdin2YQg2KfZhNmG2KfYtNim2KkNCg0KNDUuICAgICAgICAgICAgINiv2YjYsdip
INmF2YfYp9ix2KfYqiDYpdiv2KfYsdipINin2YTYudmE2KfZgtin2Kog2KfZhNi52KfZhdipDQoN
CjQ2LiAgICAgICAgICAgICDYr9mI2LHYqSDYp9mE2YLZitin2K/YqSDYp9mE2KrYrdmB2YrYstmK
2Kkg2YTZgdix2YIg2KfZhNmF2KjZiti52KfYqg0KDQo0Ny4gICAgICAgICAgICAg2K/ZiNix2Kkg
2KPYs9in2LPZitin2Kog2KXYr9in2LHYqSDYp9mE2LnZhdmE2YrYp9iqINmB2Yog2KfZhNmF2KTY
s9iz2KfYqiDYp9mE2K7Yr9mF2YrYqQ0KDQo0OC4gICAgICAgICAgICAg2K/ZiNix2Kkg2KrYt9mI
2YrYsSDYp9mE2YXZh9in2LHYp9iqINin2YTYpdiv2KfYsdmK2Kkg2YTZhdis2KfZhCDYp9mE2LHY
udin2YrYqSDYp9mE2LXYrdmK2KkNCg0KNDkuICAgICAgICAgICAgINiv2YjYsdipINiq2LfZiNmK
2LEg2KfYs9iq2LHYp9iq2YrYrNmK2KfYqiDYp9mE2KrYs9mI2YrZgiDYp9mE2LHZgtmF2YoNCg0K
NTAuICAgICAgICAgICAgINiv2YjYsdipINin2YTYpdiv2KfYsdipINin2YTZgdi52ZHYp9mE2Kkg
2YTZhNmF2LTYp9ix2YrYuSDYp9mE2YPYqNix2YkNCg0K2YTZhNiq2LPYrNmK2YQg2KPZiCDZhNi3
2YTYqCDYp9mE2LnYsdi2INin2YTYqtiv2LHZitio2Yog2KfZhNmD2KfZhdmE2Iwg2YrYsdis2Ykg
2KfZhNiq2YjYp9i12YQg2YXYudmG2Kc6DQoNCtijIC8g2LPYp9ix2Kkg2LnYqNivINin2YTYrNmI
2KfYryDigJPZhdiv2YrYsdin2YTYqtiv2LHZitioDQoNCsKoICAgIFvYsdmC2YUg2KfZhNmH2KfY
qtmBIC8g2YjYp9iq2LMg2KfYqF0gICAgMDAyMDEwNjk5OTQzOTkgLTAwMjAxMDYyOTkyNTEwIC0N
CjAwMjAxMDk2ODQxNjI2DQoNCi0tIApZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2Ug
eW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3Vw
LgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWls
cyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVn
cm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5n
b29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NBRGoxWkttSzJ5V0NwQmJFJTJCN2VSaWpYblVp
N1dkMTYxcXZ3czU4aS1DMzlCMjVBcXpBJTQwbWFpbC5nbWFpbC5jb20uCg==
--000000000000d847500640efe107
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;margin:0in 0in 8pt;line-height:107%;direction:rtl;uni=
code-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;">=
<span lang=3D"AR-SA" style=3D"font-size:16pt;line-height:107%;font-family:&=
quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=B3=D9=
=84=D8=A7=D9=85
=D8=B9=D9=84=D9=8A=D9=83=D9=85 =D9=88=D8=B1=D8=AD=D9=85=D8=A9 =D8=A7=D9=84=
=D9=84=D9=87 =D9=88=D8=A8=D8=B1=D9=83=D8=A7=D8=AA=D9=87</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:16pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=AA=D9=87=D8=AF=D9=8A=D9=83=D9=85
=D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =
=D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D9=8A=D8=A9 =D8=A3=D8=B7=D9=8A=D8=A8 =D8=AA=D8=AD=D9=8A=D8=A7=D8=AA=
=D9=87=D8=A7 =D9=88=D8=A3=D8=B5=D8=AF=D9=82 =D8=AA=D9=85=D9=86=D9=8A=D8=A7=
=D8=AA=D9=87=D8=A7 =D8=A8=D8=AF=D9=88=D8=A7=D9=85 =D8=A7=D9=84=D8=AA=D9=88=
=D9=81=D9=8A=D9=82.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=AA=D8=AF=D8=B9=D9=88=D9=83=D9=85
=D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D8=A9 =D9=81=D9=8A:</span></p>

<h1 align=3D"center" dir=3D"RTL" style=3D"text-align:center;margin:0.25in 0=
in 4pt;line-height:107%;break-after:avoid;direction:rtl;unicode-bidi:embed;=
font-size:20pt;font-family:&quot;Calibri Light&quot;,&quot;sans-serif&quot;=
;color:rgb(46,116,181);font-weight:normal"><b><span lang=3D"AR-SA" style=3D=
"font-family:&quot;Times New Roman&quot;,&quot;serif&quot;;color:windowtext=
">=D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=AA=D8=AF=
=D8=B1=D9=8A=D8=A8=D9=8A: =E2=80=9C=D8=AD=D9=88=D9=83=D9=85=D8=A9
=D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=88=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=
=D9=85=D9=8A=D8=A9=E2=80=9D</span></b></h1>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=A8=D8=A7=D9=84=D9=82=D8=A7=D9=87=D8=
=B1=D8=A9
=E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =D9=85=D8=B5=D8=B1 =D8=
=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=AE=D9=84=D8=A7=D9=84
=D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =D9=85=D9=86 19=D8=A7=D9=84=D9=8A 23 =
=D8=A7=D9=83=D8=AA=D9=88=D8=A8=D8=B1 2025 =D9=85=C2=A0 =D9=84=D9=85=D8=AF=
=D8=A9 5
=D8=A7=D9=8A=D8=A7=D9=85 =D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9</span><=
/p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:20pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D9=85=D9=82=D8=AF=D9=85=D8=A9
:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=A3=D8=B5=D8=A8=D8=AD=D8=AA
=D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=87=D9=8A =D8=A7=D9=84=
=D9=85=D8=AD=D8=B1=D9=83 =D8=A7=D9=84=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A =D9=84=
=D9=86=D8=AC=D8=A7=D8=AD =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =
=D9=88=D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=AA=D9=87=D8=A7. =D9=88=D9=85=
=D9=86 =D9=87=D9=86=D8=A7 =D8=A8=D8=B1=D8=B2=D8=AA =D8=A3=D9=87=D9=85=D9=8A=
=D8=A9 =D8=AD=D9=88=D9=83=D9=85=D8=A9
=D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=83=D8=A5=D8=B7=D8=A7=
=D8=B1 =D8=B4=D8=A7=D9=85=D9=84 =D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=88=D8=B6=D9=85=D8=A7=D9=86 =
=D8=AC=D9=88=D8=AF=D8=AA=D9=87=D8=A7=D8=8C =D8=A8=D9=85=D8=A7 =D9=8A=D8=AD=
=D9=82=D9=82 =D8=A7=D9=84=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D8=A7=D9=84=D8=AA=
=D8=B4=D8=BA=D9=8A=D9=84=D9=8A=D8=A9=D8=8C
=D9=88=D9=8A=D8=AF=D8=B9=D9=85 =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=
=D9=82=D8=B1=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D8=A8=D9=86=D9=8A =D8=B9=D9=84=
=D9=89 =D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D8=AF=D9=82=D9=8A=D9=82=
=D8=A9 =D9=88=D9=85=D9=88=D8=AB=D9=88=D9=82=D8=A9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=AA=D9=87=D8=AF=D9=81
=D9=87=D8=B0=D9=87 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=A5=D9=84=D9=89 =
=D8=AA=D9=85=D9=83=D9=8A=D9=86 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=
=D9=8A=D9=86 =D9=85=D9=86 =D9=81=D9=87=D9=85 =D8=A7=D9=84=D8=A3=D8=B3=D8=B3=
 =D9=88=D8=A7=D9=84=D9=85=D9=86=D9=87=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=
=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9 =D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=
=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA
=D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9=D8=8C =D9=88=D8=A7=D9=84=D8=AA=
=D8=B9=D8=B1=D9=81 =D8=B9=D9=84=D9=89 =D8=A3=D9=81=D8=B6=D9=84 =D8=A7=D9=84=
=D9=85=D9=85=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D8=A7=D9=84=
=D9=85=D9=8A=D8=A9 =D9=88=D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D9=87=D8=A7 =D9=81=
=D9=8A =D8=A8=D9=8A=D8=A6=D8=A7=D8=AA
=D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=
=D8=A9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:20pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=D8=A7=D9=87=D8=AF=D8=A7=D9=
=81
:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=A8=D9=86=D9=87=D8=A7=D9=8A=D8=A9
=D8=A7=D9=84=D8=A8=D8=B1=D9=86=D8=A7=D9=85=D8=AC =D8=B3=D9=8A=D9=83=D9=88=
=D9=86 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=83=D9=88=D9=86 =D9=82=D8=A7=
=D8=AF=D8=B1=D9=8A=D9=86 =D8=B9=D9=84=D9=89:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 41.25pt 0.0001pt 0in;text-align:center;line-height:107%;=
direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;s=
ans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family=
:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">1.<span style=3D"fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-stretch:norma=
l;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;"=
>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;">=D9=81=D9=87=D9=85
=D8=A7=D9=84=D9=85=D9=81=D8=A7=D9=87=D9=8A=D9=85 =D8=A7=D9=84=D8=A3=D8=B3=
=D8=A7=D8=B3=D9=8A=D8=A9 =D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=
=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=
=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 41.25pt 0.0001pt 0in;text-align:center;line-height:107%=
;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;=
sans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-famil=
y:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">2.<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-stretch:norm=
al;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;=
">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;">=D8=A7=D9=84=D8=AA=D8=B9=D8=B1=D9=81
=D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=A3=D8=B7=D8=B1 =D9=88=D8=A7=D9=84=D9=85=
=D8=B9=D8=A7=D9=8A=D9=8A=D8=B1 =D8=A7=D9=84=D8=B9=D8=A7=D9=84=D9=85=D9=8A=
=D8=A9 =D9=81=D9=8A =D9=85=D8=AC=D8=A7=D9=84 =D8=AD=D9=88=D9=83=D9=85=D8=A9=
 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA (=D9=85=D8=AB=D9=84 </spa=
n><span dir=3D"LTR" style=3D"font-size:14pt;line-height:107%;font-family:&q=
uot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">DAMA,
ISO</span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"A=
R-SA" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTit=
le Black&quot;,&quot;sans-serif&quot;"><span dir=3D"RTL"></span><span dir=
=3D"RTL"></span>).</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 41.25pt 0.0001pt 0in;text-align:center;line-height:107%=
;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;=
sans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-famil=
y:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">3.<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-stretch:norm=
al;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;=
">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;">=D8=A8=D9=86=D8=A7=D8=A1
=D8=B3=D9=8A=D8=A7=D8=B3=D8=A7=D8=AA =D9=88=D8=A5=D8=AC=D8=B1=D8=A7=D8=A1=
=D8=A7=D8=AA =D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=A8=D9=8A=
=D8=A7=D9=86=D8=A7=D8=AA =D8=AF=D8=A7=D8=AE=D9=84 =D8=A7=D9=84=D9=85=D8=A4=
=D8=B3=D8=B3=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 41.25pt 0.0001pt 0in;text-align:center;line-height:107%=
;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;=
sans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-famil=
y:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">4.<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-stretch:norm=
al;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;=
">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;">=D8=AA=D8=B5=D9=85=D9=8A=D9=85
=D8=A2=D9=84=D9=8A=D8=A7=D8=AA =D9=84=D9=82=D9=8A=D8=A7=D8=B3 =D9=88=D8=AA=
=D8=AD=D8=B3=D9=8A=D9=86 =D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D8=A8=D9=8A=
=D8=A7=D9=86=D8=A7=D8=AA.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 41.25pt 0.0001pt 0in;text-align:center;line-height:107%=
;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;=
sans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-famil=
y:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">5.<span style=3D"f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-stretch:norm=
al;font-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;=
">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;">=D8=B1=D8=A8=D8=B7
=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=
=D8=AA =D8=A8=D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=
=D9=85=D9=8A =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=
=D8=A7=D8=B7=D8=B1 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A=D8=A9.</span>=
</p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 41.25pt 8pt 0in;text-align:center;line-height:107%;direct=
ion:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-se=
rif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family:&quot=
;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">6.<span style=3D"font-var=
iant-numeric:normal;font-variant-east-asian:normal;font-stretch:normal;font=
-size:7pt;line-height:normal;font-family:&quot;Times New Roman&quot;">=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:14pt;line-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;=
sans-serif&quot;">=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF
=D8=AE=D8=B7=D8=B7 =D8=B9=D9=85=D9=84=D9=8A=D8=A9 =D9=84=D8=AA=D8=B7=D8=A8=
=D9=8A=D9=82 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D9=88=D8=B6=D9=85=
=D8=A7=D9=86 =D8=A7=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9 =D8=A7=D9=84=D8=AC=
=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:20pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=D8=
=B1
:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"text-align:center;margin:0in 0.5in 0.0001pt 0in;line-height:107%;di=
rection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;san=
s-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family:S=
ymbol">\<span style=3D"font-variant-numeric:normal;font-variant-east-asian:=
normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&qu=
ot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RTL=
"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font=
-family:&quot;Segoe UI Emoji&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</sp=
an><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-famil=
y:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">
=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=A3=D9=88=D9=84: =D8=A7=D9=84=
=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=A5=D8=B7=
=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=A7=D9=85</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"text-align:center;margin:0in 0.5in 0.0001pt 0in;line-height:107%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sa=
ns-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family:=
Symbol">\<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&q=
uot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;Segoe UI Emoji&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</s=
pan><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-fami=
ly:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">
=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A: =D8=A7=
=D9=84=D8=B3=D9=8A=D8=A7=D8=B3=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=A3=D8=AF=
=D9=88=D8=A7=D8=B1 =D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=8A=
=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"text-align:center;margin:0in 0.5in 0.0001pt 0in;line-height:107%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sa=
ns-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family:=
Symbol">\<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&q=
uot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;Segoe UI Emoji&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</s=
pan><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-fami=
ly:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">
=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=84=D8=AB: =D8=A5=
=D8=AF=D8=A7=D8=B1=D8=A9 =D8=AC=D9=88=D8=AF=D8=A9 =D8=A7=D9=84=D8=A8=D9=8A=
=D8=A7=D9=86=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"text-align:center;margin:0in 0.5in 0.0001pt 0in;line-height:107%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sa=
ns-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family:=
Symbol">\<span style=3D"font-variant-numeric:normal;font-variant-east-asian=
:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&q=
uot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RT=
L"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;fon=
t-family:&quot;Segoe UI Emoji&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</s=
pan><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-fami=
ly:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">
=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=B1=D8=A7=D8=A8=D8=B9: =D8=A7=
=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=D8=AC=D9=8A=D8=A7 =D9=88=D8=A7=
=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A</span><=
/p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"text-align:center;margin:0in 0.5in 8pt 0in;line-height:107%;directio=
n:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-seri=
f&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family:Symbol"=
>\<span style=3D"font-variant-numeric:normal;font-variant-east-asian:normal=
;font-stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Tim=
es New Roman&quot;">=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RTL"></sp=
an><span lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-famil=
y:&quot;Segoe UI Emoji&quot;,&quot;sans-serif&quot;">=F0=9F=94=B9</span><sp=
an lang=3D"AR-SA" style=3D"font-size:14pt;line-height:107%;font-family:&quo=
t;AlSharkTitle Black&quot;,&quot;sans-serif&quot;">
=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AE=D8=A7=D9=85=D8=B3: =D8=A7=
=D9=84=D8=AA=D8=B7=D8=A8=D9=8A=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A =
=D9=88=D8=AF=D8=B1=D8=A7=D8=B3=D8=A9 =D8=AD=D8=A7=D9=84=D8=A7=D8=AA</span><=
/p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:14pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=C2=A0</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;margin:0in 0in 8pt;line-height:107%;direction:rtl;unicode-bidi:embed;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-S=
A" style=3D"font-size:20pt;line-height:107%;font-family:&quot;AlSharkTitle =
Black&quot;,&quot;sans-serif&quot;">=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D9=87=D8=
=AF=D9=81=D9=88=D9=86
:</span></p>

<p class=3D"gmail-MsoListParagraphCxSpFirst" align=3D"center" dir=3D"RTL" s=
tyle=3D"margin:0in 37.5pt 0.0001pt 0in;text-align:center;line-height:107%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sa=
ns-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family:=
Symbol">=C2=A8<span style=3D"font-variant-numeric:normal;font-variant-east-=
asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-fami=
ly:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></spa=
n><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;lin=
e-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&q=
uot;">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=
=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D8=A7=D8=AA
=D8=A7=D9=84=D8=AD=D9=83=D9=88=D9=85=D9=8A=D8=A9 =D9=88=D8=A7=D9=84=D8=AE=
=D8=A7=D8=B5=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 37.5pt 0.0001pt 0in;text-align:center;line-height:107%;=
direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;s=
ans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family=
:Symbol">=C2=A8<span style=3D"font-variant-numeric:normal;font-variant-east=
-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-fam=
ily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&=
quot;">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=AA=D9=82=D9=86=D9=8A=D8=A9 =D8=A7=
=D9=84=D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D8=AA=
=D8=AD=D9=88=D9=84
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 37.5pt 0.0001pt 0in;text-align:center;line-height:107%;=
direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;s=
ans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family=
:Symbol">=C2=A8<span style=3D"font-variant-numeric:normal;font-variant-east=
-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-fam=
ily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&=
quot;">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=
=D9=86=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=85=D8=AD=D9=84=D9=84=D9=88=D9=86.<=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 37.5pt 0.0001pt 0in;text-align:center;line-height:107%;=
direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;s=
ans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family=
:Symbol">=C2=A8<span style=3D"font-variant-numeric:normal;font-variant-east=
-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-fam=
ily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&=
quot;">=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=D8=A9 =
=D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=
=D8=B1.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 37.5pt 0.0001pt 0in;text-align:center;line-height:107%;=
direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;s=
ans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family=
:Symbol">=C2=A8<span style=3D"font-variant-numeric:normal;font-variant-east=
-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-fam=
ily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&=
quot;">=D9=81=D8=B1=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D9=85=
=D8=B9=D9=86=D9=8A=D8=A9 =D8=A8=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=88=D8=A7=D9=84=
=D8=AA=D8=AD=D9=84=D9=8A=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=B6=D8=AE=D9=85=
=D8=A9.</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 37.5pt 0.0001pt 0in;text-align:center;line-height:107%;=
direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;s=
ans-serif&quot;"><span style=3D"font-size:14pt;line-height:107%;font-family=
:Symbol">=C2=A8<span style=3D"font-variant-numeric:normal;font-variant-east=
-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-fam=
ily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 </span></sp=
an><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-size:14pt;li=
ne-height:107%;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&=
quot;">=D8=A7=D9=84=D8=A3=D9=83=D8=A7=D8=AF=D9=8A=D9=85=D9=8A=D9=88=D9=86 =
=D9=88=D8=A7=D9=84=D8=A8=D8=A7=D8=AD=D8=AB=D9=88=D9=86 =D8=A7=D9=84=D9=85=
=D9=87=D8=AA=D9=85=D9=88=D9=86
=D8=A8=D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =
=D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 9.2pt 0.0001pt 0in;text-align:center;line-height:107%;d=
irection:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sa=
ns-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:5pt;line-height:107=
%;font-family:&quot;Barada Reqa&quot;;color:rgb(192,0,0)">=C2=A0</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 4.2pt 0.0001pt 0in;text-align:center;text-indent:5pt;li=
ne-height:107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16p=
t;line-height:107%;font-family:&quot;Aref Ruqaa&quot;">=D9=8A=D8=B3=D8=B9=
=D8=AF=D9=86=D8=A7 =D8=A3=D9=86
=D9=86=D8=A4=D9=83=D8=AF =D8=A7=D9=86=D8=B9=D9=82=D8=A7=D8=AF =D8=A7=D9=84=
=D9=88=D8=B1=D8=B4 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9 =
=D8=A7=D9=84=D8=AA=D8=A7=D9=84=D9=8A=D8=A9=D8=8C=C2=A0=C2=A0=C2=A0=C2=A0 =
=D9=88=D8=B0=D9=84=D9=83
=D9=81=D9=8A =D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9 =D9=85=D9=86 19 =E2=80=93=
 23 =D8=A3=D9=83=D8=AA=D9=88=D8=A8=D8=B1 2025=D8=8C</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 4.2pt 0.0001pt 0in;text-align:center;text-indent:5pt;li=
ne-height:107%;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:=
Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" style=3D"font-size:16p=
t;line-height:107%;font-family:&quot;Aref Ruqaa&quot;">=D8=A8=D9=85=D9=82=
=D8=B1 =D8=A7=D9=84=D8=AF=D8=A7=D8=B1
=D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=
=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =E2=80=93 =D8=
=A7=D9=84=D9=82=D8=A7=D9=87=D8=B1=D8=A9</span><span lang=3D"AR-EG" style=3D=
"font-size:16pt;line-height:107%;font-family:&quot;Aref Ruqaa&quot;">=C2=A0=
 =D8=A8=D8=A7=D8=AF=D8=B1 =D8=A8=D8=A7=D9=84=D8=AD=D8=AC=D8=B2</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;line-height:107%=
;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;=
sans-serif&quot;"><span dir=3D"LTR" style=3D"font-size:16pt;line-height:107=
%">=C2=A0</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">1.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A9 =
=D9=84=D9=84=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=D8=AC=D8=AF=D8=AF</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">2.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=
=D8=B7 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">3.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =
=D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D9=8A=D8=B1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">4.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D9=88=D8=AA=D9=82=D9=8A=D9=8A=D9=85 =D8=A7=
=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">5.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=D9=85 =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=
=D8=A9 =D8=A7=D9=84=D9=88=D9=82=D8=AA =D8=A8=D9=81=D8=B9=D8=A7=D9=84=D9=8A=
=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">6.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9 =D9=84=D9=84=D9=85=D9=88=D8=B8=D9=81=D9=8A=D9=86 =
=D8=A7=D9=84=D9=85=D8=A8=D8=AA=D8=AF=D8=A6=D9=8A=D9=86</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">7.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D8=AD=D9=84 =D8=A7=D9=84=D9=85=D8=B4=D9=83=D9=84=
=D8=A7=D8=AA
=D9=88=D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">8.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=
=D9=84 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=84 =D9=81=D9=8A =D8=A8=D9=8A=D8=A6=
=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">9.<span style=3D"font-variant-numeric:normal;font-variant-ea=
st-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-f=
amily:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A8=D9=86=D8=A7=D8=A1 =D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D9=81=D8=B1=
=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">10.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=AA=D8=AD=D9=81=D9=8A=D8=B2 =D9=88=D8=A8=D9=86=D8=A7=D8=A1 =
=D9=81=D8=B1=D9=82 =D8=A7=D9=84=D8=B9=D9=85=D9=84</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">11.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=85=D8=A9 =
=D9=84=D9=84=D9=85=D8=B4=D8=B1=D9=81=D9=8A=D9=86</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">12.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B5=D8=B1=D8=A7=D8=B9 =D9=88=
=D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9 =D8=A7=D9=84=D9=86=
=D8=B2=D8=A7=D8=B9=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">13.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=AA=D9=81=D9=83=D9=8A=D8=B1 =D8=A7=D9=84=D8=A7=D8=A8=D8=AA=
=D9=83=D8=A7=D8=B1=D9=8A =D9=81=D9=8A =D8=AD=D9=84 =D8=A7=D9=84=D9=85=D8=B4=
=D9=83=D9=84=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">14.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=81=D8=A7=D9=88=
=D8=B6 =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D8=A7=D9=84=D9=81=
=D8=B9=D8=A7=D9=84</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">15.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=
=D8=B9 =D8=A7=D9=84=D8=B5=D8=BA=D9=8A=D8=B1=D8=A9 =D9=88=D8=A7=D9=84=D9=85=
=D8=AA=D9=88=D8=B3=D8=B7=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">16.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=
=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=B4=D8=AE=D8=B5=D9=8A=
=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">17.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=84=D9=84=D9=85=
=D8=AF=D8=B1=D8=A7=D8=A1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">18.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=
=D8=A7=D8=B1=D9=8A=D8=A9 =D9=84=D9=85=D8=AF=D8=B1=D8=A7=D8=A1 =D8=A7=D9=84=
=D9=85=D9=88=D8=A7=D8=B1=D8=AF =D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">19.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A7=
=D8=AA =D9=88=D8=AA=D8=AD=D8=B3=D9=8A=D9=86 =D8=A7=D9=84=D8=AC=D9=88=D8=AF=
=D8=A9</span><span dir=3D"LTR" style=3D"font-size:16pt;font-family:&quot;Al=
SharkTitle Black&quot;,&quot;sans-serif&quot;"></span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">20.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=
=D8=AA =D9=88=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87=D8=A7 =D9=81=
=D9=8A =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=D8=B1=D8=A7=D8=B1=
=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">21.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D9=88=D8=A5=D8=B9=D8=AF=D8=A7=
=D8=AF =D8=A7=D9=84=D9=85=D9=8A=D8=B2=D8=A7=D9=86=D9=8A=D8=A7=D8=AA =D9=84=
=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">22.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=
=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=A7=D9=84=D8=AA=D9=82=D8=A7=D8=B1=D9=8A=
=D8=B1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">23.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D9=88=D8=A7=D9=84=D8=AA=D8=A3=
=D8=AB=D9=8A=D8=B1 =D9=81=D9=8A =D9=81=D8=B1=D9=82 =D8=A7=D9=84=D8=B9=D9=85=
=D9=84</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">24.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AA=D8=BA=D9=8A=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=AA=D9=86=D8=B8=D9=8A=D9=85=D9=8A =D8=A8=D9=81=D8=B9=D8=A7=
=D9=84=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">25.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=88=D8=AC=D9=8A=
=D9=87 =D9=88=D8=A7=D9=84=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=84=D9=85=
=D9=87=D9=86=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">26.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=
=AA =D8=A7=D9=84=D9=85=D8=AA=D9=82=D8=AF=D9=85=D8=A9 =D9=81=D9=8A =D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9</spa=
n></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">27.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A3=D8=AE=D8=B7=D8=A7=D8=B1 =
=D9=88=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A3=D8=B2=D9=85=D8=A7=
=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">28.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=
=D8=B1=D8=A9 =D8=A7=D9=84=D8=AD=D8=AF=D9=8A=D8=AB=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">29.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D9=81=D8=B1=D9=82 =D8=A7=D9=84=D8=B9=D9=85=
=D9=84 =D8=B9=D9=86 =D8=A8=D9=8F=D8=B9=D8=AF</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">30.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=B3=D9=88=D9=82 =D8=A7=D9=84=D8=B9=D9=85=
=D9=84 =D9=88=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=86=D8=AA=
=D8=AC=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">31.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D8=AA=D9=81=D8=A7=D9=88=D8=B6 =D8=A7=D9=84=D8=AA=D8=AC=D8=A7=
=D8=B1=D9=8A =D9=88=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=
=D8=A7=D8=AA =D8=A7=D9=84=D8=A8=D9=8A=D8=B9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">32.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF =
=D8=A7=D9=84=D8=A8=D8=B4=D8=B1=D9=8A=D8=A9 =D8=A7=D9=84=D9=85=D8=AA=D9=82=
=D8=AF=D9=85=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">33.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=
=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=
=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">34.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B2=D9=86 =
=D8=A8=D9=8A=D9=86 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D9=88=D8=A7=D9=84=D8=AD=
=D9=8A=D8=A7=D8=A9 =D8=A7=D9=84=D8=B4=D8=AE=D8=B5=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">35.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A3=D8=B3=D8=A7=D9=84=D9=8A=D8=A8 =D8=A7=D9=84=D8=AA=D8=AD=D9=81=D9=8A=
=D8=B2 =D9=88=D8=A7=D9=84=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=
=D9=87=D9=86=D9=8A =D9=84=D9=84=D9=85=D9=88=D8=B8=D9=81=D9=8A=D9=86</span><=
/p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">36.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=85=D8=B9 =D8=B6=D8=BA=D9=88=
=D8=B7 =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A8=D9=83=D9=81=D8=A7=D8=A1=D8=A9<=
/span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">37.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=AA=D9=81=D9=83=D9=8A=D8=B1 =D8=A7=D9=84=D8=A5=D8=A8=D8=AF=
=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=A8=D9=8A=D8=A6=D8=A9 =D8=A7=D9=84=D8=B9=
=D9=85=D9=84</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">38.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=A7=D9=84=D9=82=D8=A7=D8=AF=D8=A9 =D8=A7=
=D9=84=D8=AC=D8=AF=D8=AF =D9=84=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=AA</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">39.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=
=D9=84=D8=AD=D9=81=D8=A7=D8=B8 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B9=D9=85=
=D9=84=D8=A7=D8=A1</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">40.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=81=D9=8A =D8=B5=
=D9=86=D8=A7=D8=B9=D8=A9 =D8=A7=D9=84=D8=AA=D9=83=D9=86=D9=88=D9=84=D9=88=
=D8=AC=D9=8A=D8=A7</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">41.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =
=D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=84=D9=84=D9=85=D8=A4=D8=B3=
=D8=B3=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">42.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=
=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A =D9=88=D8=AA=D8=AD=D9=84=D9=8A=D9=84 =
=D8=A7=D9=84=D8=B3=D9=88=D9=82</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">43.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=
=D8=B9=D8=A7=D8=AA =D9=88=D9=81=D8=B9=D8=A7=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=
=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D9=8A</=
span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">44.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D9=81=D9=8A
=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A7=D8=
=AA =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=84=D9=84=D8=A3=D8=
=B9=D9=85=D8=A7=D9=84 =D8=A7=D9=84=D9=86=D8=A7=D8=B4=D8=A6=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">45.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D9=85=D9=87=D8=A7=D8=B1=D8=A7=D8=AA =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D8=B9=D9=84=D8=A7=D9=82=D8=A7=D8=AA =D8=A7=D9=84=D8=B9=D8=A7=D9=85=
=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">46.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D8=AA=D8=AD=D9=81=
=D9=8A=D8=B2=D9=8A=D8=A9 =D9=84=D9=81=D8=B1=D9=82 =D8=A7=D9=84=D9=85=D8=A8=
=D9=8A=D8=B9=D8=A7=D8=AA</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">47.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9 =D8=A3=D8=B3=D8=A7=D8=B3=D9=8A=D8=A7=D8=AA
=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B9=D9=85=D9=84=D9=8A=D8=A7=
=D8=AA =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=A7=
=D9=84=D8=AE=D8=AF=D9=85=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">48.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=87=D8=A7=D8=B1=D8=A7=
=D8=AA =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9 =D9=84=D9=85=D8=AC=
=D8=A7=D9=84 =D8=A7=D9=84=D8=B1=D8=B9=D8=A7=D9=8A=D8=A9 =D8=A7=D9=84=D8=B5=
=D8=AD=D9=8A=D8=A9</span></p>

<p class=3D"gmail-MsoListParagraphCxSpMiddle" align=3D"center" dir=3D"RTL" =
style=3D"margin:0in 32.55pt 0.0001pt 0in;text-align:center;text-indent:0in;=
line-height:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-fam=
ily:Calibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-fami=
ly:Aref_Menna">49.<span style=3D"font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-=
family:&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=
=D8=AC=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D8=B3=D9=88=D9=8A=D9=82 =D8=A7=
=D9=84=D8=B1=D9=82=D9=85=D9=8A</span></p>

<p class=3D"gmail-MsoListParagraphCxSpLast" align=3D"center" dir=3D"RTL" st=
yle=3D"margin:0in 32.55pt 8pt 0in;text-align:center;text-indent:0in;line-he=
ight:normal;direction:rtl;unicode-bidi:embed;font-size:11pt;font-family:Cal=
ibri,&quot;sans-serif&quot;"><span style=3D"font-size:16pt;font-family:Aref=
_Menna">50.<span style=3D"font-variant-numeric:normal;font-variant-east-asi=
an:normal;font-stretch:normal;font-size:7pt;line-height:normal;font-family:=
&quot;Times New Roman&quot;">=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
>=D8=AF=D9=88=D8=B1=D8=A9
=D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D9=91=
=D8=A7=D9=84=D8=A9 =D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9 =D8=A7=
=D9=84=D9=83=D8=A8=D8=B1=D9=89</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&qu=
ot;sans-serif&quot;">=D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84
=D8=A3=D9=88 =D9=84=D8=B7=D9=84=D8=A8 =D8=A7=D9=84=D8=B9=D8=B1=D8=B6 =D8=A7=
=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A =D8=A7=D9=84=D9=83=D8=A7=D9=85=
=D9=84=D8=8C =D9=8A=D8=B1=D8=AC=D9=89 =D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=
=D9=84 =D9=85=D8=B9=D9=86=D8=A7:</span><span dir=3D"LTR" style=3D"font-size=
:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;col=
or:rgb(196,89,17)"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;margin:0in 0in 8pt;direction:rtl;unicode-bidi:embed;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&qu=
ot;sans-serif&quot;;color:rgb(196,89,17)">=D8=A3 / =D8=B3=D8=A7=D8=B1=D8=A9=
 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=88=D8=A7=D8=AF
=E2=80=93=D9=85=D8=AF=D9=8A=D8=B1</span><span lang=3D"AR-EG" style=3D"font-=
size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;=
;color:rgb(196,89,17)">=D8=A7</span><span lang=3D"AR-SA" style=3D"font-size=
:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;;col=
or:rgb(196,89,17)">=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8</span><span lang=3D=
"AR-SA" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,=
&quot;sans-serif&quot;"></span></p>

<p class=3D"gmail-MsoListParagraph" align=3D"center" dir=3D"RTL" style=3D"m=
argin:0in 9.2pt 8pt 0in;text-align:center;line-height:normal;direction:rtl;=
unicode-bidi:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot=
;"><span style=3D"font-size:16pt;font-family:Symbol;color:white">=C2=A8<spa=
n style=3D"font-variant-numeric:normal;font-variant-east-asian:normal;font-=
stretch:normal;font-size:7pt;line-height:normal;font-family:&quot;Times New=
 Roman&quot;">=C2=A0=C2=A0=C2=A0 </span></span><span dir=3D"RTL"></span><sp=
an lang=3D"AR-SA" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Bl=
ack&quot;,&quot;sans-serif&quot;">[=D8=B1=D9=82=D9=85
=D8=A7=D9=84=D9=87=D8=A7=D8=AA=D9=81 / =D9=88=D8=A7=D8=AA=D8=B3 =D8=A7=D8=
=A8]</span><span dir=3D"LTR"></span><span dir=3D"LTR"></span><span dir=3D"L=
TR" style=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quo=
t;sans-serif&quot;"><span dir=3D"LTR"></span><span dir=3D"LTR"></span>=C2=
=A0=C2=A0 </span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span st=
yle=3D"font-size:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans=
-serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>=C2=A0</spa=
n><span lang=3D"AR-SA" style=3D"font-size:14pt;font-family:&quot;Times New =
Roman&quot;,&quot;serif&quot;">00201069994399
-00201062992510 - 00201096841626</span><span lang=3D"AR-SA" style=3D"font-s=
ize:16pt;font-family:&quot;AlSharkTitle Black&quot;,&quot;sans-serif&quot;"=
></span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKmK2yWCpBbE%2B7eRijXnUi7Wd161qvws58i-C39B25AqzA%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CADj1ZKmK2yWCpBbE%2B7eRijXnUi7Wd161qvws58i-C39B25AqzA%40mail=
.gmail.com</a>.<br />

--000000000000d847500640efe107--
