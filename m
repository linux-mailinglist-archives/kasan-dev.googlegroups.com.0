Return-Path: <kasan-dev+bncBD6PZLHGTICRBEOHV2YAMGQET4L67TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 871B8894B38
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Apr 2024 08:20:03 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-22a0094c322sf4039398fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Apr 2024 23:20:03 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712038802; x=1712643602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M+cs7nqeN04npCombNeSlGzXcS05PHYGadFoclfj86I=;
        b=n29TJ7z2W6UGM+b1v6bSHnrk+5Lv2Z3PLQrqxveyxv7XQmvB2yEC7fl6Wex8LLy15a
         uA2aLlRLF6Xvj9BFsYFF2Z8w9W/n+W6TYLT09TQJmsrWn4Jvn8+P0x+WBbmLGSXmk5Y7
         r0vr8mVyGAzwPF4bDAUPoXTxqizzvYm+315gtpZ/OKJZVU+1cihtW+/zmAPNUQZU6Jml
         DXiNp5v1kvpGG4kBLMMj2TdCtfx06XdtfQlNbKS+n6U5ozVhQhHzavoltkNJr+OQPhtt
         3NIwEokc4lofUiwZV7uDlOEgJQOEUyH+YEY5l20JRnP/Z0y/R4pgasaqnWg5RAu7KtAV
         ktBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712038802; x=1712643602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=M+cs7nqeN04npCombNeSlGzXcS05PHYGadFoclfj86I=;
        b=VG6wJo1XGuR117xscGCJ6hjTxrvQcpU/YHpZAtl32/3GeYbKnCAJ9enSQKVZt9et2x
         luNRIK6gUeO0vY4fcGFUm6HUyJeMaJbkqQkm2IzZglvUFyK1NJMd0XSaGs5Xz00Q9L21
         +WUA5GTGk23W5H+56t7POVoOhESvoHPL8gbqj3zVAmFb6I8cUGB+qNTDD//wDZKd4zW4
         aUdWI1+qa0HvqNEmnFbXLS+AjOiuXOaIomTQjftSvx6+NvxmV27QACoAS3N9i5ca1T1y
         lmAZHUKm0iLoYRktXtdjT5xxqwBhw1p6/TkEzJR4RJ2NK9k1Z5jp9foIi9DyLtadGNxQ
         of6Q==
X-Forwarded-Encrypted: i=2; AJvYcCUgbprX670TAKPLKtO1parm7AVLemew69OvYHRGpl/3YUlXHCUPW9JPccAj86CC2rR4N6U7P/K1Ag1IQ2Y3yOdAgDL5s9zVHw==
X-Gm-Message-State: AOJu0YzpdFxlGHfjFo681oFAJqvzh4e7CTM7wMdBAufqyeDIz50qR6LT
	XWAibgu21YSCEzcPX5feZRq420RtzNXsX6aNTDwMgiVlA0iCE02t
X-Google-Smtp-Source: AGHT+IERYDJlC6yCM8TdeR/tv6YSn2f1+enJTJqYoYAuGtv0/uIzpQreQRQB8eh9RM/VG1nkToF6JQ==
X-Received: by 2002:a05:6870:1607:b0:22a:9ba8:f5de with SMTP id b7-20020a056870160700b0022a9ba8f5demr13401440oae.1.1712038801778;
        Mon, 01 Apr 2024 23:20:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ab8b:b0:22e:4093:c644 with SMTP id
 gs11-20020a056870ab8b00b0022e4093c644ls2213681oab.0.-pod-prod-09-us; Mon, 01
 Apr 2024 23:20:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQ2yKMqGY2dkOnW+SckRWvhMAin6fcdPIsjCRL0zMi3r5Fzw0abYY1SFdZeT7uxjWv4U6Ak0rgNEmeycYrP+d+2Ukn9P2IrvAV5A==
X-Received: by 2002:a05:6870:6587:b0:221:c58f:a8b with SMTP id fp7-20020a056870658700b00221c58f0a8bmr13165840oab.17.1712038800946;
        Mon, 01 Apr 2024 23:20:00 -0700 (PDT)
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id k13-20020a056830168d00b006e67e931ae8si798560otr.2.2024.04.01.23.20.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Apr 2024 23:20:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of boy.wu@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 05692ccaf0b911eeb8927bc1f75efef4-20240402
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.37,REQID:f6f52f98-bc39-49f2-9817-e34b8e4d2ca3,IP:0,U
	RL:25,TC:0,Content:-5,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:20
X-CID-META: VersionHash:6f543d0,CLOUDID:ad11b785-8d4f-477b-89d2-1e3bdbef96d1,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:11|1,File:nil,RT:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES
	:1,SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_ULN
X-UUID: 05692ccaf0b911eeb8927bc1f75efef4-20240402
Received: from mtkmbs13n1.mediatek.inc [(172.21.101.193)] by mailgw01.mediatek.com
	(envelope-from <boy.wu@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 593041149; Tue, 02 Apr 2024 14:19:54 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs11n1.mediatek.inc (172.21.101.185) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Tue, 2 Apr 2024 14:19:53 +0800
Received: from APC01-SG2-obe.outbound.protection.outlook.com (172.21.101.237)
 by mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Tue, 2 Apr 2024 14:19:53 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=H1M1DnopipzgAffSK0mfGHqQGmbu85x9gzRxCtObPT4JFizFW+LlrveRdZcGS5Y5S9w1PC/9qechiEMlBWwSZ939JSrAjHhHS+7+qDHLWY0EGl2drv+f6eZ+12KD1IRfV13LwjQOgWjYFia+xho67Ew0ELAohl9q7Pk2MKinmN4LcnAQpBzoPpyth568lc0OF/AYTdxLuxjxlMviIge5Jf9vvavYmsydrZUZpfI79vDRiofEgZyz3sEB/b9g/OpGwFA5t4WplFYiVs5DFh78o7l2y3npm+nHgxN5CAE0XC6L/xA7S90ujDCgdbfP8/kOR6ieOnUZ8B4vQM9EICdakA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=f2Lh5eRLWX3yb6bWKYqHH1vp77wJljITj+EIHLEAYB8=;
 b=HLMkKNaF08MhBvXTjTK9jlTXt+4XTzgA8tdEnbFxkOzW/7T5L8jgLuBdcpUqe5H4WViW/hY8XN7OYlNlyWjB1x/2LA6j98Ix7sZirSApkJnCFWgJWZg7FFR5RyC8T/Rojv94hmzZs5BvwFJweuc0mYZz22k2TGLOhno9DuQABrZ2r2xMaiYehn8rAY6Uhmjk4eLPWAW5EXfejuBIjtVoGdsQ31O2OMjvVWvyQXAEVVbfgMDxCTutxpen/kJQz0a0Sg7+AVv4F14pxlKI+/BqapHGw02Dc9NQTIhL1x+nynxDkm4Z7h+9tECmwe4EaNTLaZkggHogaB210jDbuVJmwQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from TYZPR03MB7867.apcprd03.prod.outlook.com (2603:1096:400:465::7)
 by SEZPR03MB8418.apcprd03.prod.outlook.com (2603:1096:101:21d::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7409.43; Tue, 2 Apr
 2024 06:19:51 +0000
Received: from TYZPR03MB7867.apcprd03.prod.outlook.com
 ([fe80::45da:cd44:6032:ea9]) by TYZPR03MB7867.apcprd03.prod.outlook.com
 ([fe80::45da:cd44:6032:ea9%5]) with mapi id 15.20.7409.042; Tue, 2 Apr 2024
 06:19:51 +0000
From: =?UTF-8?B?J0JveSBXdSAo5ZCz5YuD6Kq8KScgdmlhIGthc2FuLWRldg==?= <kasan-dev@googlegroups.com>
To: "linux@armlinux.org.uk" <linux@armlinux.org.uk>, "ryabinin.a.a@gmail.com"
	<ryabinin.a.a@gmail.com>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "dvyukov@google.com" <dvyukov@google.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "matthias.bgg@gmail.com"
	<matthias.bgg@gmail.com>, "glider@google.com" <glider@google.com>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
	"angelogioacchino.delregno@collabora.com"
	<angelogioacchino.delregno@collabora.com>
Subject: Re: [PATCH] arm: kasan: clear stale stack poison
Thread-Topic: [PATCH] arm: kasan: clear stale stack poison
Thread-Index: AQHaNH50g4opuV1/1EWa6LrsT9gdhLFOplGAgAKS7oCAA+lIAA==
Date: Tue, 2 Apr 2024 06:19:51 +0000
Message-ID: <1b18064c7ca66b26114610772f17753159351355.camel@mediatek.com>
References: <20231222022741.8223-1-boy.wu@mediatek.com>
	 <6837adc26ed09b9acd6a2239a14014cd3f16c87c.camel@mediatek.com>
	 <Zghbkx67hKErqui2@shell.armlinux.org.uk>
In-Reply-To: <Zghbkx67hKErqui2@shell.armlinux.org.uk>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: TYZPR03MB7867:EE_|SEZPR03MB8418:EE_
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: hmTl+8hCLhD2FKA2uSSjnam2fiOhA4lVr1QEup+z43+MfKsydGp+DsZLVywFfOUX1m3KiQaKwdACvBrv3O2N6/z8aNqP3hJ73zOGj/MvwJRiB2BIgzqSCEtAEWg9lZN74KP7gx7Sun1SnyA5Y43hySNs0gV4FIQWOvZkuzOt3WDrcDNMqFO2o/kN4sV4xIj4LoGA9KqGmicM8U4jEUSoPKhqcTda459XhU58ucP0gBfxvgmb9m/qGXg1CPhotnafotWycv0GtGYxzr5uQGHXxtBRZiSCr7u2hJRqH5DyVxfzTmFJKRvzDO83LuvMdo7mfekkReIfF9oGJiYjYWijZMx9opqSlWyJq9ohJPyH9WAWTUicGwBnnieYjkMcRSWF5EUHBpty/Qr0t2wSdOy1HlSjCvBDhebw8rKxt+zBL8A+2WMZLIG/5sXqiH1SMyGzX0+JWZlX2p7BcnxySN+ESk1hlB0ScO165b8P3JG/0QOO538KUyNxgwQtKkvcCZHvAnhadR0G+ZO58Rgiq6WZUtHLyODZntSyAZbLQwdpxkzQWDrSCq65+Zka+QGrZNsCrH4ZSTufLln6Y2XM0Eoqk6GEc2lGgl6E/2Us2SBwhag=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:TYZPR03MB7867.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(366007)(7416005)(1800799015)(376005);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?MHVMWlI4anJIa3ErS2xvaWhpZmpUZklvTlBweFNKLy8xUWI5TlJGMjVqZkRv?=
 =?utf-8?B?akR4R1NPSENPYStRanlLNnNyVWZuY1VLQi9DMWFCQXZXVFFlaGFpaC95a0g3?=
 =?utf-8?B?L0RuK3pJMlBrbEVycEU5RDRlTFN0alM1WWpwYnRUb2kxdVZSdkYxanZQZFJ3?=
 =?utf-8?B?NysvZkc0YmQzSS9OWWVmYmtBYmRFSjBJM0xLTXpnRWszSGo3ZXViTEtaZUNz?=
 =?utf-8?B?NlUveGNrR1dFR2xaSS9zY3B4dUlDem80Z29TeUxCekkxTnNtMjZ2ZDJpZmtF?=
 =?utf-8?B?ak9uaWl2REsyUWpTU0cyOVVEWTBuclFDeGRReXRZRHl1WkdZYWJFZG9VdWpP?=
 =?utf-8?B?TUVpVUFmc3NYdnNjbVlORWY4M0lNQW50cUFOVjRkSjRmUFF5Z2pGaVhoSEcr?=
 =?utf-8?B?bUYvVndZdVJ3SEh1ajdrVk9BeSttb3AwM0ZXQ3V5MVVlakV0My9DWStBMllJ?=
 =?utf-8?B?VloyYXgwZ2w5eDA1K0ZaOWU0YTJrMGhZd3ViVEJIaENjTGpERUd6NkxldmtJ?=
 =?utf-8?B?dmFCRkZ4ZW5ZSDhIQnhqWXRzVFdQWlF1THJqL2FyNU14UWtROFJzYUdQdmQx?=
 =?utf-8?B?LyswT0NHdlZ4cUFEd1ZBVGRNRm9ZUkQyaG9WU1psZ0Y2WGNWdyt5SytORnJJ?=
 =?utf-8?B?UTEraW4xcEEyOU9hQlF3NnhWTEZqUmt5MWowSG54NkZBQlFyTjhydWVzQ2Q1?=
 =?utf-8?B?MnNWdU8vYVBURjBQNE8xTUdlYUE4d0UwUTZjR1c1UU0wN2dMUjFOTnhERTli?=
 =?utf-8?B?bklia1FWL2tBNEVJOHFlTzJsaENIZEVodnJ3S09LaWdISkxuUGh0VGZCekFW?=
 =?utf-8?B?cHIreTd3NTNNUE9FK0kya090bThOTkZrM0xSekpGekVhdms0WVRJQ0N6V1Nw?=
 =?utf-8?B?VUpuQ2QrNm5OTDZsa1gxckFIWVU1QjRNNmxFODcrQUcyeVQ1dUM4Zlp4U2V4?=
 =?utf-8?B?ODBzRFdwa25BRGhUMFNSb1VkeEp0Wld3L2oyNmh5SzdTcTZTei91ZXFraTFV?=
 =?utf-8?B?QzZTMGY4TzBlN1RFMkdwQ3FxNEtISW5lSG80NlpwNWRlL2pWR3JSOUdQdXJ5?=
 =?utf-8?B?V0tRUjJUOHZCc2VaNjd6VFl6UUdBb3hoNzR4dENVdUYycGVWQWlmVjNxV0xG?=
 =?utf-8?B?TklOaFhSbS9XTGdJSVVKRjlHR0pPemxlaWZua3ZIUTBKRktJeDN3TDZObzRS?=
 =?utf-8?B?TEJOM1l3V3FobzQwQ1NmZEd1K2R5Y1BMakp4T1dzYzZnbkZHMmE4NFRjN3dw?=
 =?utf-8?B?ejFpdHl2VUdRU1hleTlDWTNoOEx2NGhTRHRLZkw0SVVpanlGckR1QkYzdFJj?=
 =?utf-8?B?UXRZRWY0ZDdJb3VuUndtbWhNdDlmL201VCthSjdCVEZSQ1kzS1U4UmNOTlBC?=
 =?utf-8?B?T0k0bmdSc1N1MkhxZWxDL3lhSWYzOTk2Z3pMR3pOTmpTakdHMXl6TkorQlc1?=
 =?utf-8?B?QU5Dc1hkYWFac0xsZ1ZTMjdxdmt0R2wzTWZJdzEzN09tc1FhcnJNeGFhSzVN?=
 =?utf-8?B?bmt4TE1NSE5wVTFGdmhPOGpFRjE5UEZydGs4QzNvUnczYkluelUwRWNZSWlX?=
 =?utf-8?B?ajZsbUVHOTBVVnU1MGI5cEtYOGVwcXd0aTU4aXVHWmtKQkRiT0x5RE5nRXFZ?=
 =?utf-8?B?MldQWWFqY1hzVlpqczRqcWdGVTlLZVQybFRreElDWHJmVkdpVUJsSkF5eDRZ?=
 =?utf-8?B?UWdaU1lCN0dtcnZkOEt0ZkJuMXByYWJwNk5tVlM5N2srYkZUNWJHaTVoZGxE?=
 =?utf-8?B?SS9MZXc1TGk2UWFzaENGRmh1dXhYaWcvY0o2dXhQK0ZKbVkzclZWTDF5N014?=
 =?utf-8?B?Q1NxdnM4cXFERCtXVWszaGlLODB4dCtCNVYwd3NEUm9hOUNhYlNReE0wTUVU?=
 =?utf-8?B?TUNudjBUdGVZVGFLZ0RRalFzNm4vR0JWOG9nVUVVTDNlK3A4SWFyUjBZQ0tj?=
 =?utf-8?B?cUVReXMxTXFZbTA4cXJtSk5rZGJzSEhJWktCMzBuQ2kyQUk1TkpmVWpsSFRT?=
 =?utf-8?B?Q3dBaXhzQmNRNmdrR0EyM3FTcXpJNFZ5M2llT2RZdWNOTVdCYUpxdG5RQ21J?=
 =?utf-8?B?elZTcFBCcDAvRkJsc0pCTFhSM3NmMFp6SlhKQXYvS01vY0grSERFU2ZtOUtE?=
 =?utf-8?Q?d1zLaYQ4HSFuknfD59BbkSzPx?=
Content-ID: <A803291350A36141BE4301FBB87B7EB4@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: base64
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: TYZPR03MB7867.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 03853e36-222c-4b44-bd39-08dc52dce790
X-MS-Exchange-CrossTenant-originalarrivaltime: 02 Apr 2024 06:19:51.0986
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: lNjSacrvt5mzFrIxSoy3yHy7dnC1RxbKDcC+bkf7fsdCwWnyf64qKWmy8ykVoMHyC7odMdAdIpe81q5tLOfwSg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SEZPR03MB8418
Content-Type: multipart/alternative;
	boundary="__=_Part_Boundary_007_1764058620.1192101469"
X-Original-Sender: boy.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="SobqS/CN";       dkim=neutral
 (body hash did not verify) header.i=@mediateko365.onmicrosoft.com
 header.s=selector2-mediateko365-onmicrosoft-com header.b=tKZPuemv;
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

--__=_Part_Boundary_007_1764058620.1192101469
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi Andrey,

Could you please help review this patch?

On Sat, 2024-03-30 at 18:36 +0000, Russell King (Oracle) wrote:
>  On Fri, Mar 29, 2024 at 03:17:39AM +0000, Boy Wu (=E5=90=B3=E5=8B=83=E8=
=AA=BC) wrote:
> > Hi Russell:
> >=20
> > Kingly ping
>=20
> I'm afraid I know nowt about KASAN. It was added to ARM32 by others.
> I've no idea whether this is correct or not. Can we get someone who
> knows KASAN to review this?
>=20
> --=20
> RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
> FTTP is here! 80Mbps down 10Mbps up. Decent connectivity at last!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1b18064c7ca66b26114610772f17753159351355.camel%40mediatek.com.

--__=_Part_Boundary_007_1764058620.1192101469
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><body><p>
<pre>
Hi&#32;Andrey,

Could&#32;you&#32;please&#32;help&#32;review&#32;this&#32;patch&#63;

On&#32;Sat,&#32;2024-03-30&#32;at&#32;18:36&#32;+0000,&#32;Russell&#32;King=
&#32;(Oracle)&#32;wrote:
&gt;&#32;&#32;On&#32;Fri,&#32;Mar&#32;29,&#32;2024&#32;at&#32;03:17:39AM&#3=
2;+0000,&#32;Boy&#32;Wu&#32;(&#21555;&#21187;&#35516;)&#32;wrote:
&gt;&#32;&gt;&#32;Hi&#32;Russell:
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;Kingly&#32;ping
&gt;&#32;
&gt;&#32;I&#39;m&#32;afraid&#32;I&#32;know&#32;nowt&#32;about&#32;KASAN.&#3=
2;It&#32;was&#32;added&#32;to&#32;ARM32&#32;by&#32;others.
&gt;&#32;I&#39;ve&#32;no&#32;idea&#32;whether&#32;this&#32;is&#32;correct&#=
32;or&#32;not.&#32;Can&#32;we&#32;get&#32;someone&#32;who
&gt;&#32;knows&#32;KASAN&#32;to&#32;review&#32;this&#63;
&gt;&#32;
&gt;&#32;--&#32;
&gt;&#32;RMK&#39;s&#32;Patch&#32;system:&#32;https://www.armlinux.org.uk/de=
veloper/patches/
&gt;&#32;FTTP&#32;is&#32;here!&#32;80Mbps&#32;down&#32;10Mbps&#32;up.&#32;D=
ecent&#32;connectivity&#32;at&#32;last!

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
om/d/msgid/kasan-dev/1b18064c7ca66b26114610772f17753159351355.camel%40media=
tek.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/1b18064c7ca66b26114610772f17753159351355.camel%40mediatek.=
com</a>.<br />

--__=_Part_Boundary_007_1764058620.1192101469--

