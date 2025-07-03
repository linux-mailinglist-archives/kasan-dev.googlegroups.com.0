Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBRNFTPBQMGQEP37MAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D3572AF80DA
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 20:58:15 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-74b537e8d05sf174043b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 11:58:15 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1751569094; cv=pass;
        d=google.com; s=arc-20240605;
        b=dSoXT/CwVATGnjFex78tHkzt19+/uA+g3OATBMkadZkd0ZFcEtUY86Z20r+CLT5Huh
         ZKn9qq7q5TazyEhpzh/ZASRZUMMwJHfDBshpDZc4Avn3faHLFEY320cpp8B+hxpgY57y
         LFL4iaQfO3viItgN4odP+MWSJ1W/2qhk6j+Pd4lbbDqtqjuxs6HLTe2cVmAxmCi0oRZd
         M6cW8zUQ5MnWPM7joz0fNg05vLnQVI+KN0DFEgUnXrvfeWykaxplCgKE1lKe2X/EA0B5
         2i2pkRJCsB6+NojC4JVf4oscdzIP9uQkliw3Mt+P8ZRLtToizp6DwGBwYylLvJCjnTU0
         uF6g==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:nodisclaimer
         :authentication-results-original:msip_labels:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=hGqFwuPSNyTN7OoZwCajoyfZrdD3cOQ4VUH3PfEErDI=;
        fh=5d6mjrmM0fb92SjM74i7qZ3ElPdHuC915F9ctyhtk7c=;
        b=fLJ+hpGIVFrK43sX5b4HzELyYe46FpqLThedgAISgLvioaOogJ0Q+lqC0n55ZjzsIz
         CYh1l9drKA6zvGFNzVWT5Um6KFQkNIWqjOTcBAw/Z8cbI8DOD6vZRG31gJ7c4QMH5ZRz
         mxihKda1UC4e3TuNRygyeZuo6F0V7t1tHvRNvPSIdQSL6CV0xgS+fDggoBDPfC9D6xWF
         WcjWoaY9JzHYoGfgg1JST0TG4YyJtiT42GtmtTNQ/Ykx1AHvjvQmVAxJ43k0OO5TWK7I
         2d9uWmUOnreNh3PiraLgNzYBqmWie6ZFzapJLjvCTsAd8lWHZ74TmGJw1Nxvcd7Slckw
         xqdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=GFonsAe8;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=GFonsAe8;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c207::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751569094; x=1752173894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:nodisclaimer
         :authentication-results-original:msip_labels:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hGqFwuPSNyTN7OoZwCajoyfZrdD3cOQ4VUH3PfEErDI=;
        b=fzmIRIlJLPNJfVJ1hcIUdQtJ5FrmO8JD9SX1wyZGP9nbq4zShoSWouWzEd+FYWV2iG
         jENDnUMsb48KTDRQr7rTelEqrHh+5a+nZRWHxyiHgwqM7Ns/lHcj6udnaMgaQZ6jFkLf
         FZ/zhKKyAxMKHP+lZgPOukpxSNcrCWpRTF+g0pzdpSLkCTPwgWQpHuuEW6E3Fm95w/PK
         dKWnz9oDg5bJBLxrC4pVOsVP0MKyhi4GbaqaG39wi+iiZcW/mOaoz8kiUbrwUUVEDpH6
         uF+kXkLR/bYlQi/0fiepRAu1yG528bwi+YNuGq8QVU5JhYFdf51lr9o2asoasMGaL5Kj
         im4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751569094; x=1752173894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :nodisclaimer:authentication-results-original:msip_labels
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hGqFwuPSNyTN7OoZwCajoyfZrdD3cOQ4VUH3PfEErDI=;
        b=kV3VBEFFxxFiFgWsB6u6o4g8Shg/YxLncXZjgDruBMsP00O0iR14Ihbo1+I3llcBks
         A4SpzBuGmzGo/W99bqkqtatexUQbUxcBZZD2BtqVwsdjEfEsYi0wysf/15STbDK9s7PH
         b9NL+N0ajonjAk+FTCFD1ILTrhxReFwB0umd/oVZ9kpF+Nb5wQgPlUGHwusAVb6NeP13
         AmYAUhjwzvRexCdVEt/gqUwJ5kKR57qjwrqLRhWZ9Cb6EYHQdZVMvDCkSmoNITTqEUWF
         Iqcsnhoi13ATrhsodoEqeaDmbsYduvDKzz8Gj2aG0JEX6ZH+Ok+HDriHFyM8Dgj0bR3j
         vTUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCV9paNT5fTZs16QwwIVxdwajjTjZhJjp4j4l9VEtOtuSYDK/kJNeK2W6+yR4PWC1guYVAArxQ==@lfdr.de
X-Gm-Message-State: AOJu0YzR0TKVVhKAftDn+IBY/sVddpq6U5JGdcCzc1mrUFGZ4Sw+Hnp1
	A7q34+b4viuvG9MLQIrN61KjC1KaeJ6NuT4rXFFdzrkVHS3pwW1V6ZY1
X-Google-Smtp-Source: AGHT+IFlGrkVXpo+M8W4hBKrOAO5SDNruXXG1uX0mL8BY8tudqk4PQt05SA4RITl1tQYbUNUMvxHWA==
X-Received: by 2002:a05:6a20:3ca1:b0:1f5:8c05:e8f8 with SMTP id adf61e73a8af0-222d7e9bfc7mr11654096637.25.1751569094079;
        Thu, 03 Jul 2025 11:58:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcQ5c02FDgPNhOjaI1FkXFG+4i4G4dKIlxn6p8fePPUlQ==
Received: by 2002:a05:6a00:1912:b0:730:8911:b1e7 with SMTP id
 d2e1a72fcca58-74ce2281906ls162388b3a.2.-pod-prod-02-us; Thu, 03 Jul 2025
 11:58:12 -0700 (PDT)
X-Received: by 2002:a05:6a00:ccd:b0:748:2e7b:3308 with SMTP id d2e1a72fcca58-74b50e8d9famr10420559b3a.6.1751569092540;
        Thu, 03 Jul 2025 11:58:12 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1751569092; cv=pass;
        d=google.com; s=arc-20240605;
        b=kHhpUOZ0/4omRbmbMaGjspwt2tv75CJkM6gcBqOfkg1GYK/WyQ678LOPwhVULRdaGo
         DGiRLbPDygT3nntWLXWbGugRswfUcouAoGMSLY6Jb8R2bilAaRfDTAwPzDCGbakky2Iz
         31mdJx1m4vgqNhMs5U6KibAzVKKFF+nQ8dLeCvqqEQIufks6dprzrMjBJHm4vir1fAe5
         dw/rSRdcEwmdoGuGgp/4qbS0eSykaQt/RXpdc3QIqeCdk3iaLQ7iGhaFsCsWgcOSGluO
         LwvdYDKTV8b2vsG4frjRV1+OmBzYHMZPI9T/1D8bpS0nKr/vCNEUKCYt6M4J/Yfk+SI8
         z7sw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:nodisclaimer
         :authentication-results-original:msip_labels:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=OsIAa0l338poL6k/+8HBucdYxj1GeCJELH5I0CLiRC4=;
        fh=RdHHstoYc0EuNuTrJbaP0C/AVYmYhTagzeTRjQjtDuo=;
        b=LdboMy5q1HIKbvAC814ndanygxYig+sSZ2PR/JDRT5zRgy3phIBagOhaNxUnB6bjLO
         IUy3Myc4nH40IDa2Ws2c/jb79sPOViGGlgm9qKtcb/vbs8bIXqkyz51v2vB77Vl8KDw7
         g3upNj2eMwz8GaJs07AuH0C0q0x9xFeEVFPnB6ugOaUlVN/Gi2GYNJCar5zgrzP0V4gs
         klB6pJQ3aoP5Q+THf5sgtzvpgMEwoRjuERvqF+Urk3sWEdJpvvcdtENW1j5MW2pvFLH6
         kjHZ/xwln6S6qLvo5ATMZ//ue5b4Vf49HNgYdXambtTc67eCxU/KRl7diB2iB92yl53K
         98kA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=GFonsAe8;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=GFonsAe8;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c207::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from MRWPR03CU001.outbound.protection.outlook.com (mail-francesouthazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c207::3])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74ce3f0f0fasi13490b3a.6.2025.07.03.11.58.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Jul 2025 11:58:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c207::3 as permitted sender) client-ip=2a01:111:f403:c207::3;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=hcOZTBIbqLQ+xWgUzWCREJJJ5SFJMQohOuw82Yco51jL2HEs3vJe9YPXDdvV4fdsTqaw2hWGyCncMyW/5kVTo8nm5506N8DSqiRTcMb7w8osmsMBiLttIy9ZShRxv4LrzIu97clCA5Z9jKWbLjoUPYeh8gRqiso27YsHhjrHatru4fmKkVeTofpnOEDKNXMX0uZgAD7eLxj+Z3I5TTLCBsYF2PVIweylkEU35fwMrPLhd23pmrQypR5ZVLBLQF99WpRK7V6HYBNMd3QOAMqyDVkJV794brdiiWa3L1+wRSvWZIr8dAcTYmKzxCYAjXilMHvfWzvvhv57QEPi1R8Bxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OsIAa0l338poL6k/+8HBucdYxj1GeCJELH5I0CLiRC4=;
 b=jHOqRUSho3ySdGOXbSkU1bIDSMyUpx0s70amnxb18Ll0DY4NX6hX5JdujOOcB0a/J+hZXyK5ap7HUCwLwr+6nBZUh792g5RZ8/nRxjqwLWZddcIT6G8+0Qydl9d7BjRBpwMbH0ypuWRyWkJGxah/U9ACN5k8i2asu+GVVOZ3zl/gICXX21IHluC6at8mG9m/b0pognTbrqEO3n6PgT27PTuaVjuw+v2iLWOa9ppKbDtReet0d3hX8HbPr46+kEYnMUSXDECUKPLtaZmeA/u9KndLzikXMBdtvRtyd9MIBEUa+Vr57RaK0lWfZvI3voasFBA8lY/cdLH3sq5Wf462Sw==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=googlegroups.com smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DU7P251CA0014.EURP251.PROD.OUTLOOK.COM (2603:10a6:10:551::17)
 by AS2PR08MB8287.eurprd08.prod.outlook.com (2603:10a6:20b:556::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.20; Thu, 3 Jul
 2025 18:58:04 +0000
Received: from DU2PEPF0001E9C3.eurprd03.prod.outlook.com
 (2603:10a6:10:551:cafe::2d) by DU7P251CA0014.outlook.office365.com
 (2603:10a6:10:551::17) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.21 via Frontend Transport; Thu,
 3 Jul 2025 18:58:04 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DU2PEPF0001E9C3.mail.protection.outlook.com (10.167.8.72) with Microsoft SMTP
 Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.15 via
 Frontend Transport; Thu, 3 Jul 2025 18:58:04 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wllU6duQRH6SE/G7h+nzGoSYN/z8Wd5HafYV2S9g69I4yxw+T+ibyBKfIRKKeD0NL9M59pxO+oUvDyaodr4rrgTflLpK/G33WfHEJy5jY+EgDZG75apRAE3uMy1aW7p19VLJFtRiUh7RcWaYsnnzf3/4SSgokzld3+t0Ur+yJnOTOwNZZb5w8wbfdgxH9JHTn9psleKsNRzuJ8EzLQLxJdhYqq6VaIDgThNIx/OiJ4yHw6Nl3gzw8dRrvcsxrsWaHEqC+YzSryR1xrGhFnZBkFDp2DlgTdG6JWJvOI9q0pQ5q+sNBZU1pQNTnu35WcZI2gz7RDqPB2Tdd6PHpj1ZlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OsIAa0l338poL6k/+8HBucdYxj1GeCJELH5I0CLiRC4=;
 b=v2V0SFnUy2Qqfk2Aw+GYfLSzG3lPggLMDvRT1KOE8/8qek3akwM1tlcbnaY1pqj1J+e1Xn28EAk4Eue4TXo5V0ZwjZ983uzBAf+cTAkO9wybNfhSWanH9LsOrsuRxEs1jjOEOOl0ofi4CzeA0gfKhKsPvgnsVjtl50PadJPEO9eHu3Q2idh7vsFhwkA+0M1ZssUprN3vOs2qw1ohLlCSFHm4RR+oQ7eMmI4qXjyUnP7EIlfrYqWFJa+rUHP1/AMhMgiGgoxwI644+1zO1pdXD/0gZogU4NWd8z8EBd5tv7ZfMsQiiPFTcQvNgiArpJ+eVemLyqXCr/MkhUO1rUk81A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DB4PR08MB8077.eurprd08.prod.outlook.com
 (2603:10a6:10:387::10) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.22; Thu, 3 Jul
 2025 18:57:31 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%5]) with mapi id 15.20.8901.021; Thu, 3 Jul 2025
 18:57:31 +0000
From: Yeo Reum Yun <YeoReum.Yun@arm.com>
To: "glider@google.com" <glider@google.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "dvyukov@google.com" <dvyukov@google.com>, Vincenzo
 Frascino <Vincenzo.Frascino@arm.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>, "bigeasy@linutronix.de" <bigeasy@linutronix.de>,
	"clrkwllms@kernel.org" <clrkwllms@kernel.org>, "rostedt@goodmis.org"
	<rostedt@goodmis.org>, "byungchul@sk.com" <byungchul@sk.com>,
	"max.byungchul.park@gmail.com" <max.byungchul.park@gmail.com>,
	"ysk@kzalloc.com" <ysk@kzalloc.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>
CC: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-rt-devel@lists.linux.dev"
	<linux-rt-devel@lists.linux.dev>
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible
 deadlock
Thread-Topic: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Thread-Index: AQHb7EXBFvAGLGKalEKwGnsRygntW7Qgv8qa
Date: Thu, 3 Jul 2025 18:57:31 +0000
Message-ID: <GV1PR08MB105214A513EE87C80410D28E6FB43A@GV1PR08MB10521.eurprd08.prod.outlook.com>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
In-Reply-To: <20250703181018.580833-1-yeoreum.yun@arm.com>
Accept-Language: en-GB, en-US
Content-Language: en-GB
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
msip_labels: 
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
x-ms-traffictypediagnostic: GV1PR08MB10521:EE_|DB4PR08MB8077:EE_|DU2PEPF0001E9C3:EE_|AS2PR08MB8287:EE_
X-MS-Office365-Filtering-Correlation-Id: 2d5509be-9371-499e-a157-08ddba638a59
x-checkrecipientrouted: true
nodisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|38070700018|921020|7053199007;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?fJcTvBQ3K/rn5fp0o3pU9r9f1RNXsrWTTC9MJey/seUEQcD2cggcSNl/+F0f?=
 =?us-ascii?Q?RrOmcb4SbuG7C/bFVAGlBRm32IyUfWJ2/kMiZFO1MA1CrtdAa1kBiCkuNrTb?=
 =?us-ascii?Q?bDpME8Lz/h+oCXNbmQ/c4Z1t2K7ygJwwaK9qpEIqVEnL8ZOxsS3+Tg3DL2ZX?=
 =?us-ascii?Q?z91JgufIbBlNCkYY/TyzjXWNm9TDZIL8PtluKtM2424D/izqGOYNW9I28sTh?=
 =?us-ascii?Q?xoI9tJOuSfYOBFHAeP9gz7IrGVVH6PUjqeZSWdjvWRj2OfNx0rcbuiJjdsDB?=
 =?us-ascii?Q?uqmikk54eRvPJqVWtEegpwMgoLY93VmLJH4nYpfMISOfxgkE4hZGpfvaDIeA?=
 =?us-ascii?Q?THJX4cCUN3gt/mQY+LNIaK6ZJOpq9ZAqb8BYC59tWYlQ4WM93RaD2hh4d9Te?=
 =?us-ascii?Q?Dg+zRaO5k0ZGxKUO+gjqQm3meZs6dHShktkLjZlfVVSHfLOuH8J9mj9adkol?=
 =?us-ascii?Q?48MUNf9uqkOD3SK7Rros3cx07pSOUlJXlljWJ8jWx5QfdEW8NkLHBRmnqi9f?=
 =?us-ascii?Q?bmnvIy2JveHIkXm2xStlk8yYx3l58LOZo+1TseQt34MJeO/7zOYCBdEFU+vw?=
 =?us-ascii?Q?IuQDuQcEjVrkr06UVYwibpZMPhPef9hmxPoARuPJpBdr1polbi/aEhd1TRGr?=
 =?us-ascii?Q?nWh1WTQuZFp4c5FBLK/s1afsIpYUTLfeMLjV9FzJEHpzRLSwlUjfqYfOJw3F?=
 =?us-ascii?Q?dMomQjImC9O/QL6iSI/wqYVuG3Svl91ptTzJQ1lAQSTOGdLHBs75AGU+aIJ5?=
 =?us-ascii?Q?nBXkAtGyYbYJVRAJQDSWaZGS6xW3ruHhL+SDtvwwykRsHYQYAcZTd7b1SZfk?=
 =?us-ascii?Q?KcWYMJqKdbPUx6oQih2XSuKbOXZ8T93eGT04YzeUTMtPuPiykES0iv/r6xwK?=
 =?us-ascii?Q?MR4NNwNkKUD0Q+Ko+afGp/TD3y7XOvp70DvaBs4+eG/XMn1zywlghfvUdH2Q?=
 =?us-ascii?Q?3P3TW5V6y4wvQhP13B9+3b3hTR88yuFeTVITfuMDc9ScBG8KVSTkqfPFrtLX?=
 =?us-ascii?Q?tPNkxLUcX92l3ZklJQL27kxGulBuUTUk3mTPlDTuONe9Fvg3t0AnGujzC++F?=
 =?us-ascii?Q?m0ggQnaMn4OGiI1IXFMgTWNpAy8RAoWbT+ZNco7NnfUhXl+SmUpxfB6dngAA?=
 =?us-ascii?Q?AFhcKkz25oTnhpOze4qd6On/aNJrhqvoWLsBoPKd2kD79dn+YXrW1m+Ov/0F?=
 =?us-ascii?Q?QrG5cgW6/Ye1N9nT7VHTXgBrHUmzdovRT1r7Uda64DHTvGTKLLw6Rd1aPXJ2?=
 =?us-ascii?Q?ApnRI6lsjnL+01z22iOHTkoAqSPuPeBxo6/6v355/baLwRHtOyI8r42JR+3q?=
 =?us-ascii?Q?jYpxuAxO2tyc52h5d6gq1rpmoSrPsntn9GJvoxQUjxlJcGYg14Qr2QTPs7wZ?=
 =?us-ascii?Q?h2e2rJ6eBLAXZStsZLKDDC8EcRbjeJQmcjyPaBGSvq+xXQOWtramARvHAOSc?=
 =?us-ascii?Q?0Csnl9t3yJ8EQDkKZV7guYkROoB8jmXjqlYYNCoJn7U3E8SJT02hx3MIrXqa?=
 =?us-ascii?Q?qFoWGZQomktX6cS7lyI3CGmA+WUyNXlCNsDk?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(38070700018)(921020)(7053199007);DIR:OUT;SFP:1101;
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB4PR08MB8077
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DU2PEPF0001E9C3.eurprd03.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 58dbe9e4-2cdc-4c9a-047e-08ddba6376f2
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|35042699022|82310400026|7416014|376014|36860700013|14060799003|921020|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Zdzvwj43VAoIASLudSgVTfV40HmQZTYZjRG72p4eKhFI7yuTToKfTE1kJ/qW?=
 =?us-ascii?Q?+41BguOOLbMmVG+eWwvgNi0yvcf8TRaVvLZgYGO/5sSxwezxezw38WbHVVpb?=
 =?us-ascii?Q?imqLz2csr9rLi4+yz2OMnt4tpuJXZ1q6i6+qJRlfSYl/Jnc1MeVjwkXBh5GI?=
 =?us-ascii?Q?tMWMC3pMoURPBGJ0WTZVEMRYCS666Ch2xjzcHN3zRfr5BCcte87LPeMt+ho4?=
 =?us-ascii?Q?iwvTv6FZMxDmoOWZBkVYmJCe374AUdbJlELdyIbs0n5MqlEEiSewFCKhJjcQ?=
 =?us-ascii?Q?mjDiEg0SFGhR/qTafE1XtTpR4NL3V9TFW7ghSfsGi+cf4ryfuMtTKkN+Iqxe?=
 =?us-ascii?Q?O3g034jCST6SshnVDeh2Vjyg/mAHFffzE4F8g8jqn6UHrqxkAyJKZG5EFTWD?=
 =?us-ascii?Q?vCuGZ5bJIFyFX+L7Z+v3TWHVxPOE9/Uk2lUXZgnHe6BcxVRJwDR9qTKMyiAn?=
 =?us-ascii?Q?TcBCaHkFZOXcbjITKnyptIXa5eI+PTSfqoXfX5eEO4r8t35a1thtXcWFS1Ys?=
 =?us-ascii?Q?cMeMT0ExF+DM2Iiq0lplgXqs9dbmej1C8Z2EJkXD7b0d66Dk9l0TP1+DWKpF?=
 =?us-ascii?Q?KZjzZbAtY8AoTDGDjxeqUBodB+4wOvrvkZLuO9Ui0BWgpdsPeS+a2O8KppLX?=
 =?us-ascii?Q?G5eNUEQLNrCOTIzP+8lTp9N2rQQouxxEtLfxiMxxNz8qi7J28dtWwhsHSsws?=
 =?us-ascii?Q?j5dewzhaURg23Z6domxGoo9kc2g+hcoLnBJzMbnNBJkpch9j48qikLHpnZ3b?=
 =?us-ascii?Q?wXh647hFzqrS9NsFujnowyzjBYImdKnnaXf972GptKN3QyXz765hWjehxHsO?=
 =?us-ascii?Q?hYEhsv0W+DUgeJkJmAR4oVStkgfpGgaiD8OC+SWHj+BsTPNgmUk8z4626F8V?=
 =?us-ascii?Q?FpnfnM5BV4dPC/iobjoU/2bYCjpA4JHRpIc2O/7npgYOneUeKkU1Pl6Z8U4K?=
 =?us-ascii?Q?QoXBE7jg8dogC17MTkNu016H1G11EN73T60oQmzunU96H7Z7E71jhaxKzjUR?=
 =?us-ascii?Q?OWb91WWDj51lyyxjJyN24WrSazDXBl1DW7xwT5lkBwrltWHm+aKcjORqcO8y?=
 =?us-ascii?Q?mZoUS4fuAZxj7bPrBzoKUUgv1tZc8lva8yrFOKT7Wz6vhqh4u1Hf1+M7cu/m?=
 =?us-ascii?Q?mcSWg9lRCWwy2k/AiPddETKYaJX3YakovC7RmfcICR/1qcY0fQM0B7uKRr5a?=
 =?us-ascii?Q?Y3toePXrt5RH04j6A6VTTObDF0mYfcnnZQ/aW52DE9Fjz3IwxsOP9viyhNLh?=
 =?us-ascii?Q?AaloP51U/el4k7Bmebh/WVVPvhdwBfMgyDbvXmL2nhLxZaDDTWABW8nwvdYy?=
 =?us-ascii?Q?emycFFKhTpBB1ssmVmAhlj4lfCsrnEnJhTwl5DZjxwfPa1M6/6Vzsri8uiuB?=
 =?us-ascii?Q?1kk8I8eAJeAiS5Ha5kJL4NdH1LU9aExSPwYWgv3TKfHdMqzq1emscQMzJKBI?=
 =?us-ascii?Q?J4g6kvMRD3skniLueOlPxIjqiAtj0tYl0RNtaJn1wOWXNwMVOOncLf2iyrJx?=
 =?us-ascii?Q?q/kSaHGZn1kop+symP5jp1CgjTLSDBc1ktseZUVUc7KMyZqbixrfVTeEjanz?=
 =?us-ascii?Q?aX4hkCHUx7FK/rhgG1s=3D?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(1800799024)(35042699022)(82310400026)(7416014)(376014)(36860700013)(14060799003)(921020)(7053199007);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 03 Jul 2025 18:58:04.1093
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 2d5509be-9371-499e-a157-08ddba638a59
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DU2PEPF0001E9C3.eurprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS2PR08MB8287
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=GFonsAe8;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=GFonsAe8;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c207::3 as permitted sender)
 smtp.mailfrom=YeoReum.Yun@arm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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


+ Andrey Ryabinin

Sorry, I've missed the add Andrey...

--
Sincerely,
Yeoreum Yun

________________________________________
From: Yeoreum Yun <yeoreum.yun@arm.com>
Sent: 03 July 2025 19:10
To: glider@google.com; andreyknvl@gmail.com; dvyukov@google.com; Vincenzo Frascino; akpm@linux-foundation.org; bigeasy@linutronix.de; clrkwllms@kernel.org; rostedt@goodmis.org; byungchul@sk.com; max.byungchul.park@gmail.com; ysk@kzalloc.com
Cc: kasan-dev@googlegroups.com; linux-mm@kvack.org; linux-kernel@vger.kernel.org; linux-rt-devel@lists.linux.dev; Yeo Reum Yun
Subject: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible deadlock

find_vm_area() couldn't be called in atomic_context.
If find_vm_area() is called to reports vm area information,
kasan can trigger deadlock like:

CPU0                                CPU1
vmalloc();
 alloc_vmap_area();
  spin_lock(&vn->busy.lock)
                                    spin_lock_bh(&some_lock);
   <interrupt occurs>
   <in softirq>
   spin_lock(&some_lock);
                                    <access invalid address>
                                    kasan_report();
                                     print_report();
                                      print_address_description();
                                       kasan_find_vm_area();
                                        find_vm_area();
                                         spin_lock(&vn->busy.lock) // deadlock!

To prevent possible deadlock while kasan reports, remove kasan_find_vm_area().

Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
Reported-by: Yunseong Kim <ysk@kzalloc.com>
Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---

Patch History
===============
From v1 to v2:
  - remove kasan_find_vm_area()
  - v1: https://lore.kernel.org/all/20250701203545.216719-1-yeoreum.yun@arm.com/

NOTE
===============
Below report is from Yunseong Kim using DEPT:

===================================================
DEPT: Circular dependency has been detected.
6.15.0-rc6-00043-ga83a69ec7f9f #5 Not tainted
---------------------------------------------------
summary
---------------------------------------------------
*** DEADLOCK ***

context A
   [S] lock(report_lock:0)
   [W] lock(&vn->busy.lock:0)
   [E] unlock(report_lock:0)

context B
   [S] lock(&tb->tb6_lock:0)
   [W] lock(report_lock:0)
   [E] unlock(&tb->tb6_lock:0)

context C
   [S] write_lock(&ndev->lock:0)
   [W] lock(&tb->tb6_lock:0)
   [E] write_unlock(&ndev->lock:0)

context D
   [S] lock(&vn->busy.lock:0)
   [W] write_lock(&ndev->lock:0)
   [E] unlock(&vn->busy.lock:0)

[S]: start of the event context
[W]: the wait blocked
[E]: the event not reachable
---------------------------------------------------
context A's detail
---------------------------------------------------
context A
   [S] lock(report_lock:0)
   [W] lock(&vn->busy.lock:0)
   [E] unlock(report_lock:0)

[S] lock(report_lock:0):
[<ffff800080bd2600>] start_report mm/kasan/report.c:215 [inline]
[<ffff800080bd2600>] kasan_report+0x74/0x1d4 mm/kasan/report.c:623
stacktrace:
      __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
      _raw_spin_lock_irqsave+0x88/0xd8 kernel/locking/spinlock.c:162
      start_report mm/kasan/report.c:215 [inline]
      kasan_report+0x74/0x1d4 mm/kasan/report.c:623
      __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
      fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
      fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
      fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
      fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
      fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
      __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
      fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
      rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
      rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
      addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
      addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176

[W] lock(&vn->busy.lock:0):
[<ffff800080ae57a0>] spin_lock include/linux/spinlock.h:351 [inline]
[<ffff800080ae57a0>] find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
stacktrace:
      spin_lock include/linux/spinlock.h:351 [inline]
      find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
      find_vm_area+0x20/0x68 mm/vmalloc.c:3208
      kasan_find_vm_area mm/kasan/report.c:398 [inline]
      print_address_description mm/kasan/report.c:432 [inline]
      print_report+0x3d8/0x54c mm/kasan/report.c:521
      kasan_report+0xb8/0x1d4 mm/kasan/report.c:634
      __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
      fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
      fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
      fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
      fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
      fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
      __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
      fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
      rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
      rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
      addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
      addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85

[E] unlock(report_lock:0):
(N/A)
---------------------------------------------------
context B's detail
---------------------------------------------------
context B
   [S] lock(&tb->tb6_lock:0)
   [W] lock(report_lock:0)
   [E] unlock(&tb->tb6_lock:0)

[S] lock(&tb->tb6_lock:0):
[<ffff80008a172d10>] spin_lock_bh include/linux/spinlock.h:356 [inline]
[<ffff80008a172d10>] __fib6_clean_all+0xe8/0x2b8 net/ipv6/ip6_fib.c:2267
stacktrace:
      __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
      _raw_spin_lock_bh+0x80/0xd0 kernel/locking/spinlock.c:178
      spin_lock_bh include/linux/spinlock.h:356 [inline]
      __fib6_clean_all+0xe8/0x2b8 net/ipv6/ip6_fib.c:2267
      fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
      rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
      rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
      addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
      addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
      call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
      call_netdevice_notifiers net/core/dev.c:2228 [inline]
      dev_close_many+0x290/0x4b8 net/core/dev.c:1731
      unregister_netdevice_many_notify+0x574/0x1fa0 net/core/dev.c:11940
      unregister_netdevice_many net/core/dev.c:12034 [inline]
      unregister_netdevice_queue+0x2b8/0x390 net/core/dev.c:11877
      unregister_netdevice include/linux/netdevice.h:3374 [inline]
      __tun_detach+0xec4/0x1180 drivers/net/tun.c:620
      tun_detach drivers/net/tun.c:636 [inline]
      tun_chr_close+0xa4/0x248 drivers/net/tun.c:3390
      __fput+0x374/0xa30 fs/file_table.c:465
      ____fput+0x20/0x3c fs/file_table.c:493

[W] lock(report_lock:0):
[<ffff800080bd2600>] start_report mm/kasan/report.c:215 [inline]
[<ffff800080bd2600>] kasan_report+0x74/0x1d4 mm/kasan/report.c:623
stacktrace:
      __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
      _raw_spin_lock_irqsave+0x6c/0xd8 kernel/locking/spinlock.c:162
      start_report mm/kasan/report.c:215 [inline]
      kasan_report+0x74/0x1d4 mm/kasan/report.c:623
      __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
      fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
      fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
      fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
      fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
      fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
      __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
      fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
      rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
      rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
      addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
      addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176

[E] unlock(&tb->tb6_lock:0):
(N/A)
---------------------------------------------------
context C's detail
---------------------------------------------------
context C
   [S] write_lock(&ndev->lock:0)
   [W] lock(&tb->tb6_lock:0)
   [E] write_unlock(&ndev->lock:0)

[S] write_lock(&ndev->lock:0):
[<ffff80008a133bd8>] addrconf_permanent_addr net/ipv6/addrconf.c:3622 [inline]
[<ffff80008a133bd8>] addrconf_notify+0xab4/0x1688 net/ipv6/addrconf.c:3698
stacktrace:
      __raw_write_lock_bh include/linux/rwlock_api_smp.h:202 [inline]
      _raw_write_lock_bh+0x88/0xd4 kernel/locking/spinlock.c:334
      addrconf_permanent_addr net/ipv6/addrconf.c:3622 [inline]
      addrconf_notify+0xab4/0x1688 net/ipv6/addrconf.c:3698
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
      call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
      call_netdevice_notifiers net/core/dev.c:2228 [inline]
      __dev_notify_flags+0x114/0x294 net/core/dev.c:9393
      netif_change_flags+0x108/0x160 net/core/dev.c:9422
      do_setlink.isra.0+0x960/0x3464 net/core/rtnetlink.c:3152
      rtnl_changelink net/core/rtnetlink.c:3769 [inline]
      __rtnl_newlink net/core/rtnetlink.c:3928 [inline]
      rtnl_newlink+0x1080/0x1a1c net/core/rtnetlink.c:4065
      rtnetlink_rcv_msg+0x82c/0xc30 net/core/rtnetlink.c:6955
      netlink_rcv_skb+0x218/0x400 net/netlink/af_netlink.c:2534
      rtnetlink_rcv+0x28/0x38 net/core/rtnetlink.c:6982
      netlink_unicast_kernel net/netlink/af_netlink.c:1313 [inline]
      netlink_unicast+0x50c/0x778 net/netlink/af_netlink.c:1339
      netlink_sendmsg+0x794/0xc28 net/netlink/af_netlink.c:1883
      sock_sendmsg_nosec net/socket.c:712 [inline]
      __sock_sendmsg+0xe0/0x1a0 net/socket.c:727
      __sys_sendto+0x238/0x2fc net/socket.c:2180

[W] lock(&tb->tb6_lock:0):
[<ffff80008a1643fc>] spin_lock_bh include/linux/spinlock.h:356 [inline]
[<ffff80008a1643fc>] __ip6_ins_rt net/ipv6/route.c:1350 [inline]
[<ffff80008a1643fc>] ip6_route_add+0x7c/0x220 net/ipv6/route.c:3900
stacktrace:
      __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
      _raw_spin_lock_bh+0x5c/0xd0 kernel/locking/spinlock.c:178
      spin_lock_bh include/linux/spinlock.h:356 [inline]
      __ip6_ins_rt net/ipv6/route.c:1350 [inline]
      ip6_route_add+0x7c/0x220 net/ipv6/route.c:3900
      addrconf_prefix_route+0x28c/0x494 net/ipv6/addrconf.c:2487
      fixup_permanent_addr net/ipv6/addrconf.c:3602 [inline]
      addrconf_permanent_addr net/ipv6/addrconf.c:3626 [inline]
      addrconf_notify+0xfd0/0x1688 net/ipv6/addrconf.c:3698
      notifier_call_chain+0x94/0x50c kernel/notifier.c:85
      raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
      call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
      call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
      call_netdevice_notifiers net/core/dev.c:2228 [inline]
      __dev_notify_flags+0x114/0x294 net/core/dev.c:9393
      netif_change_flags+0x108/0x160 net/core/dev.c:9422
      do_setlink.isra.0+0x960/0x3464 net/core/rtnetlink.c:3152
      rtnl_changelink net/core/rtnetlink.c:3769 [inline]
      __rtnl_newlink net/core/rtnetlink.c:3928 [inline]
      rtnl_newlink+0x1080/0x1a1c net/core/rtnetlink.c:4065
      rtnetlink_rcv_msg+0x82c/0xc30 net/core/rtnetlink.c:6955
      netlink_rcv_skb+0x218/0x400 net/netlink/af_netlink.c:2534
      rtnetlink_rcv+0x28/0x38 net/core/rtnetlink.c:6982
      netlink_unicast_kernel net/netlink/af_netlink.c:1313 [inline]
      netlink_unicast+0x50c/0x778 net/netlink/af_netlink.c:1339
      netlink_sendmsg+0x794/0xc28 net/netlink/af_netlink.c:1883

[E] write_unlock(&ndev->lock:0):
(N/A)
---------------------------------------------------
context D's detail
---------------------------------------------------
context D
   [S] lock(&vn->busy.lock:0)
   [W] write_lock(&ndev->lock:0)
   [E] unlock(&vn->busy.lock:0)

[S] lock(&vn->busy.lock:0):
[<ffff800080adcf80>] spin_lock include/linux/spinlock.h:351 [inline]
[<ffff800080adcf80>] alloc_vmap_area+0x800/0x26d0 mm/vmalloc.c:2027
stacktrace:
      __raw_spin_lock include/linux/spinlock_api_smp.h:133 [inline]
      _raw_spin_lock+0x78/0xc0 kernel/locking/spinlock.c:154
      spin_lock include/linux/spinlock.h:351 [inline]
      alloc_vmap_area+0x800/0x26d0 mm/vmalloc.c:2027
      __get_vm_area_node+0x1c8/0x360 mm/vmalloc.c:3138
      __vmalloc_node_range_noprof+0x168/0x10d4 mm/vmalloc.c:3805
      __vmalloc_node_noprof+0x130/0x178 mm/vmalloc.c:3908
      vzalloc_noprof+0x3c/0x54 mm/vmalloc.c:3981
      alloc_counters net/ipv6/netfilter/ip6_tables.c:815 [inline]
      copy_entries_to_user net/ipv6/netfilter/ip6_tables.c:837 [inline]
      get_entries net/ipv6/netfilter/ip6_tables.c:1039 [inline]
      do_ip6t_get_ctl+0x520/0xad0 net/ipv6/netfilter/ip6_tables.c:1677
      nf_getsockopt+0x8c/0x10c net/netfilter/nf_sockopt.c:116
      ipv6_getsockopt+0x24c/0x460 net/ipv6/ipv6_sockglue.c:1493
      tcp_getsockopt+0x98/0x120 net/ipv4/tcp.c:4727
      sock_common_getsockopt+0x9c/0xcc net/core/sock.c:3867
      do_sock_getsockopt+0x308/0x57c net/socket.c:2357
      __sys_getsockopt+0xec/0x188 net/socket.c:2386
      __do_sys_getsockopt net/socket.c:2393 [inline]
      __se_sys_getsockopt net/socket.c:2390 [inline]
      __arm64_sys_getsockopt+0xa8/0x110 net/socket.c:2390
      __invoke_syscall arch/arm64/kernel/syscall.c:36 [inline]
      invoke_syscall+0x88/0x2e0 arch/arm64/kernel/syscall.c:50
      el0_svc_common.constprop.0+0xe8/0x2e0 arch/arm64/kernel/syscall.c:139

[W] write_lock(&ndev->lock:0):
[<ffff80008a127f20>] addrconf_rs_timer+0xa0/0x730 net/ipv6/addrconf.c:4025
stacktrace:
      __raw_write_lock include/linux/rwlock_api_smp.h:209 [inline]
      _raw_write_lock+0x5c/0xd0 kernel/locking/spinlock.c:300
      addrconf_rs_timer+0xa0/0x730 net/ipv6/addrconf.c:4025
      call_timer_fn+0x204/0x964 kernel/time/timer.c:1789
      expire_timers kernel/time/timer.c:1840 [inline]
      __run_timers+0x830/0xb00 kernel/time/timer.c:2414
      __run_timer_base kernel/time/timer.c:2426 [inline]
      __run_timer_base kernel/time/timer.c:2418 [inline]
      run_timer_base+0x124/0x198 kernel/time/timer.c:2435
      run_timer_softirq+0x20/0x58 kernel/time/timer.c:2445
      handle_softirqs+0x30c/0xdc0 kernel/softirq.c:579
      __do_softirq+0x14/0x20 kernel/softirq.c:613
      ____do_softirq+0x14/0x20 arch/arm64/kernel/irq.c:81
      call_on_irq_stack+0x24/0x30 arch/arm64/kernel/entry.S:891
      do_softirq_own_stack+0x20/0x40 arch/arm64/kernel/irq.c:86
      invoke_softirq kernel/softirq.c:460 [inline]
      __irq_exit_rcu+0x400/0x560 kernel/softirq.c:680
      irq_exit_rcu+0x14/0x80 kernel/softirq.c:696
      __el1_irq arch/arm64/kernel/entry-common.c:561 [inline]
      el1_interrupt+0x38/0x54 arch/arm64/kernel/entry-common.c:575
      el1h_64_irq_handler+0x18/0x24 arch/arm64/kernel/entry-common.c:580
      el1h_64_irq+0x6c/0x70 arch/arm64/kernel/entry.S:596

[E] unlock(&vn->busy.lock:0):
(N/A)
---------------------------------------------------
information that might be helpful
---------------------------------------------------
CPU: 1 UID: 0 PID: 19536 Comm: syz.4.2592 Not tainted 6.15.0-rc6-00043-ga83a69ec7f9f #5 PREEMPT
Hardware name: QEMU KVM Virtual Machine, BIOS 2025.02-8 05/13/2025
Call trace:
 dump_backtrace arch/arm64/kernel/stacktrace.c:449 [inline] (C)
 show_stack+0x34/0x80 arch/arm64/kernel/stacktrace.c:466 (C)
 __dump_stack lib/dump_stack.c:94 [inline]
 dump_stack_lvl+0x104/0x180 lib/dump_stack.c:120
 dump_stack+0x20/0x2c lib/dump_stack.c:129
 print_circle kernel/dependency/dept.c:928 [inline]
 cb_check_dl kernel/dependency/dept.c:1362 [inline]
 cb_check_dl+0x1080/0x10ec kernel/dependency/dept.c:1356
 bfs+0x4d8/0x630 kernel/dependency/dept.c:980
 check_dl_bfs kernel/dependency/dept.c:1381 [inline]
 add_dep+0x1cc/0x364 kernel/dependency/dept.c:1710
 add_wait kernel/dependency/dept.c:1829 [inline]
 __dept_wait+0x60c/0x16e0 kernel/dependency/dept.c:2585
 dept_wait kernel/dependency/dept.c:2666 [inline]
 dept_wait+0x168/0x1a8 kernel/dependency/dept.c:2640
 __raw_spin_lock include/linux/spinlock_api_smp.h:133 [inline]
 _raw_spin_lock+0x54/0xc0 kernel/locking/spinlock.c:154
 spin_lock include/linux/spinlock.h:351 [inline]
 find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
 find_vm_area+0x20/0x68 mm/vmalloc.c:3208
 kasan_find_vm_area mm/kasan/report.c:398 [inline]
 print_address_description mm/kasan/report.c:432 [inline]
 print_report+0x3d8/0x54c mm/kasan/report.c:521
 kasan_report+0xb8/0x1d4 mm/kasan/report.c:634
 __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
 fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
 fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
 fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
 fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
 fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
 __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
 fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
 rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
 rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
 addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
 addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
 notifier_call_chain+0x94/0x50c kernel/notifier.c:85
 raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
 call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
 call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
 call_netdevice_notifiers net/core/dev.c:2228 [inline]
 dev_close_many+0x290/0x4b8 net/core/dev.c:1731
 unregister_netdevice_many_notify+0x574/0x1fa0 net/core/dev.c:11940
 unregister_netdevice_many net/core/dev.c:12034 [inline]
 unregister_netdevice_queue+0x2b8/0x390 net/core/dev.c:11877
 unregister_netdevice include/linux/netdevice.h:3374 [inline]
 __tun_detach+0xec4/0x1180 drivers/net/tun.c:620
 tun_detach drivers/net/tun.c:636 [inline]
 tun_chr_close+0xa4/0x248 drivers/net/tun.c:3390
 __fput+0x374/0xa30 fs/file_table.c:465
 ____fput+0x20/0x3c fs/file_table.c:493
 task_work_run+0x154/0x278 kernel/task_work.c:227
 exit_task_work include/linux/task_work.h:40 [inline]
 do_exit+0x950/0x23a8 kernel/exit.c:953
 do_group_exit+0xc0/0x248 kernel/exit.c:1103
 get_signal+0x1f98/0x20cc kernel/signal.c:3034
 do_signal+0x200/0x880 arch/arm64/kernel/signal.c:1658
 do_notify_resume+0x1a0/0x26c arch/arm64/kernel/entry-common.c:148
 exit_to_user_mode_prepare arch/arm64/kernel/entry-common.c:169 [inline]
 exit_to_user_mode arch/arm64/kernel/entry-common.c:178 [inline]
 el0_svc+0xf8/0x188 arch/arm64/kernel/entry-common.c:745
 el0t_64_sync_handler+0x10c/0x140 arch/arm64/kernel/entry-common.c:762
 el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:600

---
 mm/kasan/report.c | 45 ++-------------------------------------------
 1 file changed, 2 insertions(+), 43 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8357e1a33699..b0877035491f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -370,36 +370,6 @@ static inline bool init_task_stack_addr(const void *addr)
                        sizeof(init_thread_union.stack));
 }

-/*
- * This function is invoked with report_lock (a raw_spinlock) held. A
- * PREEMPT_RT kernel cannot call find_vm_area() as it will acquire a sleeping
- * rt_spinlock.
- *
- * For !RT kernel, the PROVE_RAW_LOCK_NESTING config option will print a
- * lockdep warning for this raw_spinlock -> spinlock dependency. This config
- * option is enabled by default to ensure better test coverage to expose this
- * kind of RT kernel problem. This lockdep splat, however, can be suppressed
- * by using DEFINE_WAIT_OVERRIDE_MAP() if it serves a useful purpose and the
- * invalid PREEMPT_RT case has been taken care of.
- */
-static inline struct vm_struct *kasan_find_vm_area(void *addr)
-{
-       static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
-       struct vm_struct *va;
-
-       if (IS_ENABLED(CONFIG_PREEMPT_RT))
-               return NULL;
-
-       /*
-        * Suppress lockdep warning and fetch vmalloc area of the
-        * offending address.
-        */
-       lock_map_acquire_try(&vmalloc_map);
-       va = find_vm_area(addr);
-       lock_map_release(&vmalloc_map);
-       return va;
-}
-
 static void print_address_description(void *addr, u8 tag,
                                      struct kasan_report_info *info)
 {
@@ -429,19 +399,8 @@ static void print_address_description(void *addr, u8 tag,
        }

        if (is_vmalloc_addr(addr)) {
-               struct vm_struct *va = kasan_find_vm_area(addr);
-
-               if (va) {
-                       pr_err("The buggy address belongs to the virtual mapping at\n"
-                              " [%px, %px) created by:\n"
-                              " %pS\n",
-                              va->addr, va->addr + va->size, va->caller);
-                       pr_err("\n");
-
-                       page = vmalloc_to_page(addr);
-               } else {
-                       pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
-               }
+               pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
+               page = vmalloc_to_page(addr);
        }

        if (page) {
--
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/GV1PR08MB105214A513EE87C80410D28E6FB43A%40GV1PR08MB10521.eurprd08.prod.outlook.com.
