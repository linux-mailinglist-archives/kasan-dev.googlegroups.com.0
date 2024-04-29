Return-Path: <kasan-dev+bncBD6PZLHGTICRBH5DXWYQMGQEYCRXODQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id C36B28B529E
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 09:52:01 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5dbddee3694sf2675678a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 00:52:01 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714377120; x=1714981920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ijs8+F3FTmXgtuqsHOF7t2mI4VQMeizHwGWdvVoHJ8M=;
        b=dhzoTuozIn8ubc8wv/LoCyuDR/ZUYqUxiMMHX9q1VFdl9F3FzTggEg3RE0D+pti8oY
         0V1Z9BZl7EP8nOkTKM6UlLceuI7lD3NV7DKl7Av0GMu0Q1fFOOGtm0pB30gKAN9XyoPR
         kDFQUcVo6F0aRa3TS0jXdy1mJmtNuAHSSHDC0NBECN0LO4nKr2BUELQ/ywab8p1HcvBs
         fdzXGtcKiE5XcA6P0DTE2JEaFPa4DKRuPPlDnmxQGuYX8PEPNQPOVclIz9dm+BfZ/xw7
         M3zuf2URQJl7Dz2aj5popPKTHVzqIiB3gDK5UPfjE9uczIRIrAxQYNSF9qffDXLIBguX
         Q8Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714377120; x=1714981920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ijs8+F3FTmXgtuqsHOF7t2mI4VQMeizHwGWdvVoHJ8M=;
        b=OjVmF1QFIbtEjOi4hiaEy+rjoE3qsa/81SmPJEo1dChqoaf/rMGruGs5NFbvKyLTf0
         HHSmtwxbL4JidOn3s4+TEK88XdLBaDK8+MTh09l7T5yjHAlLaEjFOHmL4BxepZVMbYYp
         lLehrHkMCRJhIx0Wq9d5/SfVdmz4zadqogmrz18HSslSgAkgDlHnGlox4ioqsfHh2yxo
         nD/tDXyUHRn7TDTX9JY+3QOWM2iodwP/t6emntuVpDgYIge1vWnwUoZJjDqpK9jy15Vu
         QWYuVqZ8Yl+80CeslskNFn6JVMNKU3Z3d7HNhuVfb6nuB7eZsnLyFKiY33UEzm1vRQUn
         xYnw==
X-Forwarded-Encrypted: i=2; AJvYcCX82ERV+8gGKNPQqH9kV9Re8kEkmoeTfiZqT8haNB5pgGn+T7F+1G2eQJNcQlcHOl1GLg/0KFYAUGd5aYmm3ecbJNia64hl7A==
X-Gm-Message-State: AOJu0Yyo68tze+lD0OC9vbPs3dIjg3J2XF0g47fsIkd6cMMJ1rRAqALd
	87FGsMolT3OdSCekeo5a0+nIpkAGVFV/5NfHmw68HoFmXozEMV8o
X-Google-Smtp-Source: AGHT+IHn5m3OAMuC/gzP6C47h0Prxvtq3sXD+pPUWRvhirvPb4itKZeNmVSEVvoumHup5glTe/P4Aw==
X-Received: by 2002:a05:6a00:2d17:b0:6f3:e6ac:5703 with SMTP id fa23-20020a056a002d1700b006f3e6ac5703mr8068674pfb.0.1714377120175;
        Mon, 29 Apr 2024 00:52:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8c16:b0:6f3:f2c5:2ee6 with SMTP id
 d2e1a72fcca58-6f3f2c53766ls591430b3a.2.-pod-prod-00-us; Mon, 29 Apr 2024
 00:51:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUeV4wZ81rVRQ9ZLaRtMfyBHnISxEbx3WIMAibB2WzcAkk+KhkgcPKy0F/k3Wk5r+FIT0aNoFT6O1h7136/MSX013alcKQRTcp8lw==
X-Received: by 2002:aa7:8e88:0:b0:6f3:e6c3:eadf with SMTP id a8-20020aa78e88000000b006f3e6c3eadfmr8356781pfr.15.1714377118835;
        Mon, 29 Apr 2024 00:51:58 -0700 (PDT)
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id p29-20020a056a000a1d00b006ead00499dbsi1764861pfh.1.2024.04.29.00.51.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Apr 2024 00:51:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of boy.wu@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 582a66dc05fd11efb92737409a0e9459-20240429
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.38,REQID:d2a941a2-b5f1-4084-86d5-45d0c0935196,IP:0,U
	RL:25,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:25
X-CID-META: VersionHash:82c5f88,CLOUDID:529178fb-ed05-4274-9204-014369d201e8,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:11|1,File:nil,RT:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES
	:1,SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_ULN
X-UUID: 582a66dc05fd11efb92737409a0e9459-20240429
Received: from mtkmbs09n2.mediatek.inc [(172.21.101.94)] by mailgw01.mediatek.com
	(envelope-from <boy.wu@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 116069807; Mon, 29 Apr 2024 15:51:53 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs11n2.mediatek.inc (172.21.101.187) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Mon, 29 Apr 2024 15:51:52 +0800
Received: from APC01-SG2-obe.outbound.protection.outlook.com (172.21.101.237)
 by mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Mon, 29 Apr 2024 15:51:52 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=JTZJWL0QRxqq7WAJn+fkhLVaW02PKnzzFEkJ2EyHDa0BfI4/uYG/qPsNk4/q65Ffy+zuzi3ABj5X/J9VWV5M6QBjzmfOWRAIe8pCnrAqAEy3XBtif5TNNfOqjlKOSXowfHPNTOt8s1PNCmip8PQ3Gm4vmf78fPC0Qr9WM7ihpfTM0f0ZqNytavnosXhFWU8C7IqN15Nhsqpoo/a9jWKXqNfU7D51F6pybLFSYZrLV2+03bx5Vaghyellru89mD+GjCZrnvIUzIPXSKTkfwleaUSeQ8owRw58RmoAcBK8VHq2ADpBTc3jtJ6SHpK65wHOsEmsVvrTHuuc9PkUipEO0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=f6rzWTyoZHZ9Pjuv/1vDzq5PAfTNbu67H+koR+0DOiQ=;
 b=hJ2502m9h/P2b7oT46MMPddjRBuktaKyeqPFVWjZK4MeAZgoy4jWA7yzaBgeQLTs3/FO8okkj+JGDt66Q6GzEl1PU1DnCgeSikNmSFe6PNdKzjvs2CGes+TVzophKgHQ6gkbAL00ZEs8qWqksUFl7c6MeM/QNiBKGTixFtMkQGOPkV9odjwMrlr2wStlbWLxxZAAdN23ofmI0v4FFnPJqZrEXGamdwrx6fj6AStnQImc5gVx27RW1FJ62+sGODsPwysFoGvgsamsePY/8llox+OluXtD2nI/DhXjzAaSZ1o7VF4XGIn3g1P/qNxwfNLv0oU2gz3/+oLOg+PWTxEeWA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from TYZPR03MB7867.apcprd03.prod.outlook.com (2603:1096:400:465::7)
 by PUZPR03MB7063.apcprd03.prod.outlook.com (2603:1096:301:114::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7544.21; Mon, 29 Apr
 2024 07:51:49 +0000
Received: from TYZPR03MB7867.apcprd03.prod.outlook.com
 ([fe80::45da:cd44:6032:ea9]) by TYZPR03MB7867.apcprd03.prod.outlook.com
 ([fe80::45da:cd44:6032:ea9%5]) with mapi id 15.20.7544.019; Mon, 29 Apr 2024
 07:51:49 +0000
From: =?UTF-8?B?J0JveSBXdSAo5ZCz5YuD6Kq8KScgdmlhIGthc2FuLWRldg==?= <kasan-dev@googlegroups.com>
To: "linux@armlinux.org.uk" <linux@armlinux.org.uk>,
	"linus.walleij@linaro.org" <linus.walleij@linaro.org>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>, "dvyukov@google.com"
	<dvyukov@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, =?utf-8?B?SXZlcmxpbiBXYW5nICjnjovoi7PpnJYp?=
	<Iverlin.Wang@mediatek.com>, "mark.rutland@arm.com" <mark.rutland@arm.com>,
	=?utf-8?B?TGlnaHQgQ2hlbiAo6Zmz5pix5YWJKQ==?= <Light.Chen@mediatek.com>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "glider@google.com"
	<glider@google.com>, "matthias.bgg@gmail.com" <matthias.bgg@gmail.com>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
	"angelogioacchino.delregno@collabora.com"
	<angelogioacchino.delregno@collabora.com>
Subject: Re: [PATCH v2] arm: kasan: clear stale stack poison
Thread-Topic: [PATCH v2] arm: kasan: clear stale stack poison
Thread-Index: AQHaixkSs+zAunuNbEaFD9FHAsfJirFkUwEAgBmMPoCAAR68AA==
Date: Mon, 29 Apr 2024 07:51:49 +0000
Message-ID: <292f9fe4bab26028aa80f63bf160e0f2b874a17c.camel@mediatek.com>
References: <20240410073044.23294-1-boy.wu@mediatek.com>
	 <CACRpkdZ5iK+LnQ0GJjZpxROCDT9GKVbe9m8hDSSh2eMXp3do0Q@mail.gmail.com>
	 <Zi5hDV6e0oMTyFfr@shell.armlinux.org.uk>
In-Reply-To: <Zi5hDV6e0oMTyFfr@shell.armlinux.org.uk>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: TYZPR03MB7867:EE_|PUZPR03MB7063:EE_
x-ms-office365-filtering-correlation-id: 70ecfeb2-60ad-46cf-de6d-08dc682139fd
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230031|376005|7416005|1800799015|366007|38070700009;
x-microsoft-antispam-message-info: =?utf-8?B?STl4SU05Wm1HMGdVbUhFRGN4ZkdaNlBaajU4UnlZNG1YNEFMcVY4WG5iUmhZ?=
 =?utf-8?B?SllRUHkza2tXMi85MENSTDNFM2ZOUnJ2NGRZTG5FdVJURjhOMENtQ1F1ZWty?=
 =?utf-8?B?dU02aTUveXpaWFZ3dFY4QzMxbDNmTFRxR0xIWisrbEVzOEV6SUM0NmJaQ2tY?=
 =?utf-8?B?dVU3Nmhmd29ybERkR2dNeGN3anp5b3BZTkpCZ1Y4MlZaNWF5UW5uSVNNZ0NS?=
 =?utf-8?B?WFhUdC9vV0plZWUxRGNJd2ZRT0JiZ0dYbmpGeUUrbkJjeENTRmtQT1Q0WHZV?=
 =?utf-8?B?cEhjZG5mY1VLS0RQNWhLYTZ2NXNudFhVV1V2WEdOUzYyMkl3THdMeEVkS3NN?=
 =?utf-8?B?aDR2YUVNTGVlV0xBcGZveHJpQis5NlpJNzA3dzFyQWJIZC9lWmxDK1ZhWGUz?=
 =?utf-8?B?Sy9LbXRHMURXTEQrSHNnTjVQZUlpS3puWjJnb2ZNaE8vVWMxU1krQnk2UE9O?=
 =?utf-8?B?ZTEveGlrSUdaZnFuNElyTUExbkRtQzQzNTJ5UDRWdnFtZ1IxSFVYekhpcGpp?=
 =?utf-8?B?OUVlYmI5MFJlaEZjSVBUcXlEZzZITWpjQUVmR3YybS9aQjlnYXNDSGhiVXJx?=
 =?utf-8?B?VjFFRGRUUHNXS0l1cmcvVFpCcGw2bDdYd3h0bzVnNHBRYUJud2dyOGFjNGF1?=
 =?utf-8?B?Zm0wV3d2b0tGNWtZZnFvRzFVWm14RkNsRGhlQVZPV1JHTURkTzJKQkNwSEZM?=
 =?utf-8?B?SmNnOUF6c2VtVFBIc2owb01lb2pTL1dOck9aRGF2dFgxQlRpVjVxVCtSdC9Y?=
 =?utf-8?B?N3owVzlMR2cxUitka1I1UG1GRkZSOGxEd2RGV2VwTXhKeWdyRUJPd3l0QmIz?=
 =?utf-8?B?YlpWZGNzYUJQTGtJT3YyTVN0N0ZZUVlqWFR2NFVOaCtmS1IxaHVZVlJkVjlU?=
 =?utf-8?B?Rlo1eFFmWlJ6RGdPSWtUSTNmZlBXQWNSSDBCYVBCNnp3eEhKdnZpY29iUXRo?=
 =?utf-8?B?Vkp3eWlSSDdpQzdLd0UwNkJmcFROK0c0REpoL25lNG43UGpHSWpBZmZ5dE55?=
 =?utf-8?B?Y29VaW1meXV5d0FJL3gwcFVUV2NPUHhncFYvWG9WSkptM3VQUmNNVjNXRWp4?=
 =?utf-8?B?Q1NOWFR5RkI0UmNGM0MxNVhHR0ZORkNvS3QxaFR3YUIyUkdZejBIK0tEVGEy?=
 =?utf-8?B?eXJZMkc3Rlp1MG1nUXhuRjd4TjBtQUJuZ3Yza3pCb1oyaTRSMUU1ZXdlL0N1?=
 =?utf-8?B?UG8rMnBITW1qNVQrbjlPWXFyd0V1M3NXVGJuVmJwYXBxYy9aNjJyZVI0TXJV?=
 =?utf-8?B?ZUpqVVR1b0ExbS9QNnJqQmRvY3BacDdnR1dEUWx1T1J2OWFVMmtpN0xYbnJs?=
 =?utf-8?B?SlFHbUNEak05MjgyekRtYVVrcUJxWVJOejdBUTBZbmtuQm1PdGVzWGRVeDZH?=
 =?utf-8?B?d1dGWlJoUHdudUJNUHYvT3EyZXhrYWxWYUxTY1BtaXZkK0syNzhtM2M2djRP?=
 =?utf-8?B?bFQ0WERNa0lJUXphSkRnNmZNc2lQVjhnQkxMeUdzOEF0Vk9hMk1LMno2dFRj?=
 =?utf-8?B?L3M4UklKUjFlOVBNN3M4TUhza2lnOHNpMUVvSnhGTWZ6TWdCeTZaTE9DSDVt?=
 =?utf-8?B?Y3ZtckpTWGJzYW5Sam4wTjZ5a3JieGErR1k1VmZ2dEJ2MTcvRXkrV2VxbGlo?=
 =?utf-8?B?VElmZGQwZTUyMnduQXRJdzNtMXQreW5KUjBVK0UxWDVpYURiUVpLQXVEWWlr?=
 =?utf-8?B?ZDFtSjM5NjRsNDFlUWJ4WGNvMU1NVklRdUNKTmg5L0F2bWdyMTgzVWh3PT0=?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:TYZPR03MB7867.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(376005)(7416005)(1800799015)(366007)(38070700009);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?cnBkczh1ME9IcTg4akJUQnM0d1FZZXhJbkgxQ2NHc2pJcVlaaVVGT1hYMXpk?=
 =?utf-8?B?dDlwS1BhaUVHVExCRm9EQWYrSmdaNFlrSzhGdHJnVjZwd2NRc3N0eGErMzJt?=
 =?utf-8?B?bHo0WG51dUxkclQwV2ZCYUJzZ0RsbWZaSjh0Y3lsNm01cXUxbmlPY3FIZFgr?=
 =?utf-8?B?VXJORDJCb3dBemVZRWFuSVZHbVFUUHg1NWtXQS9YWllyQTkyYVU4V3gxTTBZ?=
 =?utf-8?B?K0ZOZVJTZ0FTeE1IWU9rRWI5RVhTSFk3VW5vR2oxcnA3anRsZGZTa0R3M3By?=
 =?utf-8?B?UnRXVElKZzdZY3k3RjJtYURKd09kMENnNndiaFRKQ1Jhc3lCQmFUZ1RMRTJF?=
 =?utf-8?B?Q0hhendlTWdGVFk3dmI2NWMzMFJLRlc0aXlFbUxGWHdzSzU5bTRJeHZvQzdG?=
 =?utf-8?B?c0lVc2NLREEwVWo0cDgxYmh2UFA4QWFCejd4ajJDeTlJUEYvYTF3dkJGemM4?=
 =?utf-8?B?WG1RdzZhYWV3RERwdndDRUc1RHE3NTZrWDRCMG0yckxWZ0xZdFAvdGlIU2FH?=
 =?utf-8?B?MHlTQnEwb1haNGV1THpJZjh1cGZNSkM2cFBWcjB0Nm1yRFJyN1Uwd2hvNVNv?=
 =?utf-8?B?YUxXWnJuTHZ3YnNFcXpHM1lGQ3BwSGlROUtZbnA5cWxZbnR2Q3l6aU1va2Nv?=
 =?utf-8?B?Q2pMOFNEb3U0L2htOEtSbE1YdVgwS2IzaVdPSENXYmJEUjVKUm4zNmdwVjg4?=
 =?utf-8?B?Z2ZBUVViWFhkK3h3bjM1MnNsLzBkNnMvSjZJZ3lmdnhXWVdBSEVKRTBGUTI5?=
 =?utf-8?B?L2d5Ym5lUHRqeVY5Ui9SaUNVMklpNUlpME5NdjBGRmtGSFZyTWRqNkI5U3No?=
 =?utf-8?B?Z2VDMUdPaU9qa3hML3ZlOXEwbGJrSjdSZ1cxVVoxWmhkbjJOVlVWdFNKWk0y?=
 =?utf-8?B?bGhmMWc2Q1dZaUVBSWIvcmxsUmdVUm9QSjZGZGFBTnp3WWZ2UmhsRERoNHdI?=
 =?utf-8?B?YzZsOGt2bmZLNkE0UjBGMXMrYkNJandCVitsVUVJZEp4dHJqMnBmdVFDNzBY?=
 =?utf-8?B?L0dmT2RiVlBrYVJvYXhqYXNNR0NrYmtkSXlTVDZYa1E5MHRQQjQ0dWNySllG?=
 =?utf-8?B?QWp3RWJMS3g5VktqaDNrcWRUd3dHcHNMMks2TWEwa0J4T0swcm9CRlN4Ym1Y?=
 =?utf-8?B?NW9NRVFScHpwS2xvL2JDM0prSHkvMVRnRkc4SjFScitkSitYakZhaHE3Qm5z?=
 =?utf-8?B?UlZiV25hUzB4Q0xuTGFrVHRXTmtnVFZ3UUtjWlR4SkVoSXcwbFdsWlBha1JG?=
 =?utf-8?B?TDcyVlQrT2swQ2cybWVaMXZGQVEwR0FWbFdvYThsRUt1aHArMWNHZmNRUHF5?=
 =?utf-8?B?d3MvYXdZUU5XcU1aL0haR01CbTVCVUdnTm8yTm1hUmRZbmE1WjZSalprU2dw?=
 =?utf-8?B?RlZLOGJUMWJJcE5RWWNEUVNKR2hmejNWUHh1Wi9PbnhSVDJxSTMzR3QzR3dQ?=
 =?utf-8?B?N2pwVTBSSU1Rei9EczNqcWtXVHBXY0IzTTNWeUY2MnZLY09QSkdXZ2NEZE9G?=
 =?utf-8?B?RFRCa01EcFdDc2h1amtFQzFhTXlZVmpwdzlNNXFscVNnUGxoZGpybUR2dnBE?=
 =?utf-8?B?bE9aeDVGUUY4VkwzbjVMTmFZZVViMDR6aDBNWEcrL2dEekRxdG1IMUFia0tu?=
 =?utf-8?B?ZUkvR0I3aDM2bjJlZnQ1NkxSUVdvZkRvVTNnVGpHcTVYQ1lPQk5uVzlrRERs?=
 =?utf-8?B?WUZzSVhsY0hDS0d1NzA0bVhjMTV2WW9xOU9JZmFXMEpFb3lVMEJNZkdlVEdl?=
 =?utf-8?B?b1ZFWVg5Nk5Ua2JOV096bURJME9nL2dLWnJ6cG1DYWR2Zll0aDUxZ0hMVC9R?=
 =?utf-8?B?a3RrV0licC9OdzcwS1l3SmtwQk9sNWFyMm50TjYwZGVIbGhMc2pDSTUzYUtX?=
 =?utf-8?B?bkpSY0ZFNlJ1TGRZSlBzUFFlS3VlTGFJZm81dFlZME9ZV0ZBM2FGSEttTFNk?=
 =?utf-8?B?a1ZPc1lCTmkvM0swS0N6V2VRNTg3ejFrWTk1UmczWUNYSFFZQnhRV05iUFlZ?=
 =?utf-8?B?M3h1TE40VFhyWGEwREFUaEZFU2Z6Rzc5eE5xYzd4NWlPaDhWbjRaVW5HS2Js?=
 =?utf-8?B?YjJWbVp6bFR2SG1Sd3VEKzBjclEyQkw3ZUk0Uk1MYWxuYUdZZWxNUjhEcWlx?=
 =?utf-8?Q?0Vjt6NO7mBkkuqM57/DeH8sxA?=
Content-ID: <A9003FF89DD52F4A93E20DB6338F4B17@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: base64
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: TYZPR03MB7867.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 70ecfeb2-60ad-46cf-de6d-08dc682139fd
X-MS-Exchange-CrossTenant-originalarrivaltime: 29 Apr 2024 07:51:49.5887
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: rleMXmBm3SnVYB+2wYW6iGH8N/N3H6woBTfnCR71U6R288UVTK8J+yc0Ybg9uc88OhKNS+XbvfQSLsoSEHvcug==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PUZPR03MB7063
Content-Type: multipart/alternative;
	boundary="__=_Part_Boundary_001_1731360885.722074763"
X-Original-Sender: boy.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=MCRnUmxJ;       dkim=neutral
 (body hash did not verify) header.i=@mediateko365.onmicrosoft.com
 header.s=selector2-mediateko365-onmicrosoft-com header.b=rwqqeEoO;
       arc=fail (body hash mismatch);       spf=pass (google.com: domain of
 boy.wu@mediatek.com designates 60.244.123.138 as permitted sender)
 smtp.mailfrom=boy.wu@mediatek.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?utf-8?B?Qm95IFd1ICjlkLPli4Poqrwp?= <Boy.Wu@mediatek.com>
Reply-To: =?utf-8?B?Qm95IFd1ICjlkLPli4Poqrwp?= <Boy.Wu@mediatek.com>
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

--__=_Part_Boundary_001_1731360885.722074763
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Sun, 2024-04-28 at 15:45 +0100, Russell King (Oracle) wrote:
>  On Fri, Apr 12, 2024 at 10:37:06AM +0200, Linus Walleij wrote:
> > On Wed, Apr 10, 2024 at 9:31=E2=80=AFAM boy.wu <boy.wu@mediatek.com> wr=
ote:
> >=20
> > > From: Boy Wu <boy.wu@mediatek.com>
> > >
> > > We found below OOB crash:
> >=20
> > Thanks for digging in!
> >=20
> > Pleas put this patch into Russell's patch tracker so he can apply
> it:
> > https://www.armlinux.org.uk/developer/patches/
>=20
> Is this a bug fix? If so, having a Fixes: tag would be nice...
>=20

This is a patch for cpuidle flow when KASAN enable, that is in ARM64
but not in ARM, so add to ARM.

The reference commits did not mention fix any commits.
[1] commit 0d97e6d8024c ("arm64: kasan: clear stale stack poison")
[2] commit d56a9ef84bd0 ("kasan, arm64: unpoison stack only with
CONFIG_KASAN_STACK")

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/292f9fe4bab26028aa80f63bf160e0f2b874a17c.camel%40mediatek.com.

--__=_Part_Boundary_001_1731360885.722074763
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><body><p>
<pre>
On&#32;Sun,&#32;2024-04-28&#32;at&#32;15:45&#32;+0100,&#32;Russell&#32;King=
&#32;(Oracle)&#32;wrote:
&gt;&#32;&#32;On&#32;Fri,&#32;Apr&#32;12,&#32;2024&#32;at&#32;10:37:06AM&#3=
2;+0200,&#32;Linus&#32;Walleij&#32;wrote:
&gt;&#32;&gt;&#32;On&#32;Wed,&#32;Apr&#32;10,&#32;2024&#32;at&#32;9:31&#823=
9;AM&#32;boy.wu&#32;&lt;boy.wu@mediatek.com&gt;&#32;wrote:
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;From:&#32;Boy&#32;Wu&#32;&lt;boy.wu@mediatek.com=
&gt;
&gt;&#32;&gt;&#32;&gt;
&gt;&#32;&gt;&#32;&gt;&#32;We&#32;found&#32;below&#32;OOB&#32;crash:
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;Thanks&#32;for&#32;digging&#32;in!
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;Pleas&#32;put&#32;this&#32;patch&#32;into&#32;Russell&#39=
;s&#32;patch&#32;tracker&#32;so&#32;he&#32;can&#32;apply
&gt;&#32;it:
&gt;&#32;&gt;&#32;https://www.armlinux.org.uk/developer/patches/
&gt;&#32;
&gt;&#32;Is&#32;this&#32;a&#32;bug&#32;fix&#63;&#32;If&#32;so,&#32;having&#=
32;a&#32;Fixes:&#32;tag&#32;would&#32;be&#32;nice...
&gt;&#32;

This&#32;is&#32;a&#32;patch&#32;for&#32;cpuidle&#32;flow&#32;when&#32;KASAN=
&#32;enable,&#32;that&#32;is&#32;in&#32;ARM64
but&#32;not&#32;in&#32;ARM,&#32;so&#32;add&#32;to&#32;ARM.

The&#32;reference&#32;commits&#32;did&#32;not&#32;mention&#32;fix&#32;any&#=
32;commits.
[1]&#32;commit&#32;0d97e6d8024c&#32;(&quot;arm64:&#32;kasan:&#32;clear&#32;=
stale&#32;stack&#32;poison&quot;)
[2]&#32;commit&#32;d56a9ef84bd0&#32;(&quot;kasan,&#32;arm64:&#32;unpoison&#=
32;stack&#32;only&#32;with
CONFIG_KASAN_STACK&quot;)


</pre>
</p></body></html><!--type:text--><!--{--><pre>************* MEDIATEK Confi=
dentiality Notice ********************
The information contained in this e-mail message (including any=20
attachments) may be confidential, proprietary, privileged, or otherwise
exempt from disclosure under applicable laws. It is intended to be=20
conveyed only to the designated recipient(s). Any use, dissemination,=20
distribution, printing, retaining or copying of this e-mail (including its=
=20
attachments) by unintended recipient(s) is strictly prohibited and may=20
be unlawful. If you are not an intended recipient of this e-mail, or believ=
e=20
that you have received this e-mail in error, please notify the sender=20
immediately (by replying to this e-mail), delete any and all copies of=20
this e-mail (including any attachments) from your system, and do not
disclose the content of this e-mail to any other person. Thank you!
</pre><!--}-->

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/292f9fe4bab26028aa80f63bf160e0f2b874a17c.camel%40media=
tek.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/292f9fe4bab26028aa80f63bf160e0f2b874a17c.camel%40mediatek.=
com</a>.<br />

--__=_Part_Boundary_001_1731360885.722074763--

