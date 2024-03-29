Return-Path: <kasan-dev+bncBD6PZLHGTICRBXXFTCYAMGQEIIBBCOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BB4F8911DF
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Mar 2024 04:17:51 +0100 (CET)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-6144de213f3sf45167b3.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 20:17:51 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711682270; x=1712287070; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eqdWX6hRWpbpFyWwjbyzVEKahzxjbJbyEYQhgm6mg98=;
        b=qp8sXHs3BmKgP4r3a7bCwI3mU5tVoTSrPGMptB3r3kCU9rXGqI1g3pkOFaHpti+AsG
         FA1ZHBZULiZEQEndivlcYnJY37AL/Bxz0i0SDj+N2a7ZK8sdBXj657LitqABpHpZrKja
         VtIWGMOWmhbIU5Tvq5KWPKd0xPNwZ/2uQwNIJ7jiBkQ857KtP3syqkgmWsf/yVadS+Z9
         0Gk0Vo0VFNn+jAlQyVBHWAKJ3IUszZ/Is9zZL9dpUeu3aCWYINFPz1KRueY9RlTBMcaG
         Rdn9/2xK5ZE3n2E8OZXc0r8PihT2kIKl8OWEVjpDtGJCexkmzF2ucEt2YH/eKLfJ6Jgh
         w6Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711682270; x=1712287070;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=eqdWX6hRWpbpFyWwjbyzVEKahzxjbJbyEYQhgm6mg98=;
        b=VJ9dLgEEZCfVLYkBt8JZAMPmmIQNCo3EuJcb42CY6o+Yqe+7T/I1uPbN4vCHrRNW+o
         f+0TxYf66qyEVdPIVHbxxiJ9gkTtNirCFOBXHx4oq+tLAWlc8u2Kv/+GpQ+NTM8/6Y9M
         WC98H8CQpAVAg8SX9CKvdUDydMCVbFW8vpg5MqfbTGqjwkjTTm6eDWLu/hsF41B6Aac+
         6YZVjwVR/CbhDqQcVBNl/fq9eMPnRYEEiL5yebjLqpLxY/FIsrfAWBPdqKWXUgnlu6hF
         Q8fcvvWgDMmB8eD3qls6UmcBwaV+fED+JIH5rN7n6zqxpylHjwT5cwSfcTWsJCIA9cMI
         UL6w==
X-Forwarded-Encrypted: i=2; AJvYcCUBTgrAGg0jC8TcJnsfTMafBH4bwCfXENhLRQteum+joGsL0opT1Mds5TzKHmOfcdxhFb6MMbQDsQ3eybNgQbdmyvKB9aZuqA==
X-Gm-Message-State: AOJu0YzNGxcXFUV1n4nulNzqeusUwf9q/HNA4j9VHiGwA75TLKYaNKsb
	K5Ojfv/fIZgA23huiPI6CrbueAN5YFAb4hVuo45vVnqWYei+kp28
X-Google-Smtp-Source: AGHT+IEoUK6PtIeZuYOuPJhdC8oUfsTIDGHQrLaC+Yrkd5cq4WnHY3NEXs7xoP3vYFKEQo+8zrR1JA==
X-Received: by 2002:a25:bc48:0:b0:dcd:b624:3e55 with SMTP id d8-20020a25bc48000000b00dcdb6243e55mr1288613ybk.54.1711682270147;
        Thu, 28 Mar 2024 20:17:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ceca:0:b0:dc7:4417:ec4e with SMTP id x193-20020a25ceca000000b00dc74417ec4els77431ybe.1.-pod-prod-04-us;
 Thu, 28 Mar 2024 20:17:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVswpPnKfUDRgczZxam8QTUv8t5dxTEMIeNYnDoLNgQbOkREMNb5QYVbAuhud8slmm2wCMcntrkZKUUu5RNtlo6fp3Iu2BMsdQtg==
X-Received: by 2002:a0d:da06:0:b0:611:1456:c817 with SMTP id c6-20020a0dda06000000b006111456c817mr1389759ywe.51.1711682269060;
        Thu, 28 Mar 2024 20:17:49 -0700 (PDT)
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id r9-20020a0de809000000b00609fe86a0a6si226995ywe.2.2024.03.28.20.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Mar 2024 20:17:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of boy.wu@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: e82fdfb4ed7a11eeb8927bc1f75efef4-20240329
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.37,REQID:f63838bb-c0d3-438e-a1e0-9f44041e7614,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:6f543d0,CLOUDID:8e017600-c26b-4159-a099-3b9d0558e447,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:0,File:nil,RT:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,
	SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: e82fdfb4ed7a11eeb8927bc1f75efef4-20240329
Received: from mtkmbs14n1.mediatek.inc [(172.21.101.75)] by mailgw01.mediatek.com
	(envelope-from <boy.wu@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1083750164; Fri, 29 Mar 2024 11:17:43 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs11n1.mediatek.inc (172.21.101.185) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Fri, 29 Mar 2024 11:17:41 +0800
Received: from HK2PR02CU002.outbound.protection.outlook.com (172.21.101.237)
 by mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Fri, 29 Mar 2024 11:17:41 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=K+VByv4mImFfuSgKT8nbIBvvyncw5GDyr412VxN7GTc2R0dAFVoVkz/8746ThJS2BZuFtlneox46QjoRYSZyhq5Ix8GLnvUYeRJ1Y9GlKvB0I4P8wfrmXVlq3/nFWtVVSGMhhKiXBvqyHsBFuHuTHJGEWu3Jzd9TfYvBLrtJwBIO59e1RpWUP219/LSwEad690jsfWEMDWDGLZe0JdRblKi56eBV8rqhCnhkcpNlYB3YZL85PjIHbAUtqyBpc95R6AYxv//1TwxUuUJCYr96IHCPFfrXbO5PSoCOur3cluloC5plReeoh59LUvGHV5ueB9B0U+T001uEP8B15py0Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lypGSi0e3ySUr8Lr9xZ5ri1u09+DZiia8qf5pzOFi6o=;
 b=D7lNodrgxCoAJ1v1Rh3Sm6dZdTdyaAwb9ZA+XtnmwSFzcSxbQUCQBo8xbkJJ+tbhbO3IE7ceQSHKsq827S1QY1JLBgfNbtuoUVbMoUI09oWBkK+xzF52zJZmVCpx+J5na+jWuALTwks1fpUMXnorq8edjryBgo01zoVVHHy9NCqLpcgsrC7TAuMF/lnIYK8+7yiBc3XyNRmysjn/abUKAVZjjiytcG8R1bLQy7qUWSsJb+UbYYbXMFnr0WMJRE0M3tBwdFfptqyF3ojIN6entgXCA7XVmQlEUSdVzKu6EPjzx7PNoldIc+REXJ6wbNUrWzs/0WSgphQAlAVTMfN6vQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from TYZPR03MB7867.apcprd03.prod.outlook.com (2603:1096:400:465::7)
 by TYZPR03MB8461.apcprd03.prod.outlook.com (2603:1096:405:72::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7409.33; Fri, 29 Mar
 2024 03:17:40 +0000
Received: from TYZPR03MB7867.apcprd03.prod.outlook.com
 ([fe80::45da:cd44:6032:ea9]) by TYZPR03MB7867.apcprd03.prod.outlook.com
 ([fe80::45da:cd44:6032:ea9%4]) with mapi id 15.20.7409.039; Fri, 29 Mar 2024
 03:17:39 +0000
From: =?UTF-8?B?J0JveSBXdSAo5ZCz5YuD6Kq8KScgdmlhIGthc2FuLWRldg==?= <kasan-dev@googlegroups.com>
To: "linux@armlinux.org.uk" <linux@armlinux.org.uk>, "matthias.bgg@gmail.com"
	<matthias.bgg@gmail.com>
CC: "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "angelogioacchino.delregno@collabora.com"
	<angelogioacchino.delregno@collabora.com>, "linux-mm@kvack.org"
	<linux-mm@kvack.org>
Subject: Re: [PATCH] arm: kasan: clear stale stack poison
Thread-Topic: [PATCH] arm: kasan: clear stale stack poison
Thread-Index: AQHaNH50g4opuV1/1EWa6LrsT9gdhLFOplGA
Date: Fri, 29 Mar 2024 03:17:39 +0000
Message-ID: <6837adc26ed09b9acd6a2239a14014cd3f16c87c.camel@mediatek.com>
References: <20231222022741.8223-1-boy.wu@mediatek.com>
In-Reply-To: <20231222022741.8223-1-boy.wu@mediatek.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: TYZPR03MB7867:EE_|TYZPR03MB8461:EE_
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: Ob6h6Lj5aCU3uPuwBelxkEevXMUff/f/Ab9SL8uYmVqDYs+0XSTPp5xn56UVq6jLxTjnqWK56ZKPXNJHo2s8APJUvU46m1m4UGsTJvyke2pUDi+Ump+/3odcjD5a06CaafE+0indBP5RXZSMXYOiw9P9gNyOFnyjVJ+FvlvjRCwQJfHI3f7Z61/H7cVbmZtrsbopX7/9DivDAqRH9G6/buy8Ke2dA+VGqKk2jTincJ8i3pErORsBJ1uIK43VAjqjgUH1iDiEccqRCm3vgKl4IDTKw8MLeVMpGH2gTs6x1YaTBYQPBKySOYzTxTu5GdtxjIeht2q9i6mlW8C+cyCi/dLZuLcee8XN1CLrWyzw0JE7y9kItEjt0rMovq9+wTZu6sJeTuTge1ApBTS4PD+etRp0xMCOUtD4TTOUY8jbl0JYPjcm+FFrCthMUCh6VnUWnofEy/own92tcYvHy8WkaGm+bfw6CYLq2TT0lkKFGK/LY+HFfgNqJ7e/Vlbxb4LMy7SlsH9R6wiJ1k8JKMmCk7wH4Yphjh0IYLuzOnuLQNPM8oRDOU6yOVOjrbsFDAPWtwVuS2eI85a5S0MWnhbT/qtsxercdmvMyAP00echfcI8JrmdDKQerduuUX5uDtZXZJjwOq8QFvL9CuCMMt+vG1PDQT+RelzH6n7lgmZISDM=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:TYZPR03MB7867.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(1800799015)(376005)(366007);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?MzFuQzduKzM4SXRJd0ZUY1hqMXRmek9zUGZwNGRuV1pzM2FOUk0wdFU1YlJQ?=
 =?utf-8?B?UXVlQ1d2ZlVWNS9TWXQyZHBaSE04QmZCUXE5dC84bDBFZ01sUnNMSDZBYXlY?=
 =?utf-8?B?U2pPWGNOSS8vSWV0eklEczZxbzlDTklQVDJTRm0zWVZwVFNmVldoSkgwOWdk?=
 =?utf-8?B?U1hSeTZMOXdURWhUL3VzTENRMy8xMkt6aHlUYkhocjErYVgvaEdad0xRUE9W?=
 =?utf-8?B?MTVseTJpM3JnZ3dEc2RwMzVFRDVjcUFKNlQwajd4aVVRVDNPYWNFQzZNbGZa?=
 =?utf-8?B?M2ttN2k0TGREbFE3UTJSNnNsdG9YYWxvV0FjRE16YXdFYzRtUTZ4YlJiYU4y?=
 =?utf-8?B?d2ZyOUkxeG8vaW41OEtGMFJtc2JFNUIyUDl5N1F4cVl6Z3V2KzdxbSswMWF0?=
 =?utf-8?B?M0JKMFR6Y3B3UjRmb3pzbDJOajZPeFR3Ym03dCs2MFZSaWZJc1dQVE1GYTEr?=
 =?utf-8?B?ck11T0kwSVhuaklVc21PLzBPYzhSQWk3cXByanUxNURLWWJ3cHNWams1L3BK?=
 =?utf-8?B?ZHdvd21VaXFHY29hRzFFbWVMa2ptYjREUlhmcTNDbFdpaUJhN1JQR0lVK3lv?=
 =?utf-8?B?SXVLeXVQOGlLUEVZOXJQaTNLeVRRTDk1TWlZaEhvVUI0ZXRVTDF6OFVaS1dN?=
 =?utf-8?B?bjVPK3lpaVBjalBwNUx3VFlIbHp1ZlpvVnlkL1FkS0F5TVAvM0dWRlhZcjBI?=
 =?utf-8?B?ZXVIQ1FkT3BETWVnaEhFR3NucDVCaFpMWDlGQkpmc0l2QVBpTld4SVhmaWVI?=
 =?utf-8?B?VyswbXZ3OEFPL3pxL1NFR0NyZDd0dDhmNDcvRnJDS0RGSFdlWEtQU1Z6TkNv?=
 =?utf-8?B?Zys0TkJ6OVcxN1B3RjZSckYySVVRSEdSMkcxMHJ0VXl1MGxWOFF5SHYrQ2FJ?=
 =?utf-8?B?OGkrRjlMZUNqeUNRWXQ3aThjckQ4MGhIeHFZSWVvQ0xLOUZndmwzN0hPOUho?=
 =?utf-8?B?OTVGSUJENUxEM2JVMUY5Q3E5TVFYTUx1aEU1aFZ1RDArV2QwNTVaRXpsV01p?=
 =?utf-8?B?NVNMei9aa0cxWHFCeDVvUVVTNTAwTUhXV29uV1ZqYi9JLzEveCs5WXVISFE4?=
 =?utf-8?B?cExKWDhvOVBTdEU3UVJuVEQ5SzhLV0NkNm0rbE15SDFCcHVWYUs1L1NLOHN6?=
 =?utf-8?B?U05NK0RZMENzWW0zWERPcnI4b0lUMUFELzBNek5JQXpwMHFUZGlCQ3ZhV2xT?=
 =?utf-8?B?QnYvSWRCQ1hBK3c3Wm4rWHI4TFZwcnM3OVVUQlhVMmtaQlJqQk5WQ29wMGJB?=
 =?utf-8?B?WEV5VzdtbndrcXlhdWRKV25hY1lyajNwV2FLbGU2K25aOWo1c053K1FTZTd1?=
 =?utf-8?B?VnNzczBjTmdob01lcmZQY1U3c1ZLczF0UmlUVkl6RVFkdVMwVmZ1Rk1VbXov?=
 =?utf-8?B?UndSZk9YZW1DV3BuaklsVWw5M2F4UVdReDltNGlQeVorZWZxRnVJcjIyRks5?=
 =?utf-8?B?akdId0c2OEd6bWZWM0NtZGNpcVRHKzN4RkZZa200TmVUTG44emNBcUM0clJV?=
 =?utf-8?B?MUV5V3Nsd1NKQWQybXN2YVJSRXNPNFJ3VzV5ZGtNMnZ3ZDVsQUNyVFZ1cTVM?=
 =?utf-8?B?TXlheGZFL1F6c2prMVo4U2tGelJPN1hrZGFRa3p1NEx4dGR5bTRObHNreXVX?=
 =?utf-8?B?ajJBMytrY2tVOGJ5YStPeDFMRkZmYmNMaytVcXNIVFNudlpwQm8xdDExUWN2?=
 =?utf-8?B?YkZkeXJnQW11ZmtQMXBSejdNR25oK01SeW9kdnpFOVU3Mk9aKzQ2Mi9EM0l5?=
 =?utf-8?B?bWhoU1c0S29zZ0c1MVJnVk9zRVpuditLcDltL3RrU09ZcnY1V08rWjJhaEdp?=
 =?utf-8?B?eWIxN1ZPZVMwY1g1VlF1RThJbjRKQkVXUUNSTWMzR2dkc3hXek5sQzVOVG9S?=
 =?utf-8?B?aFp0bEU2QmQxNEJCM1RuM2lwdW5Gem92SW1vUDJZZERwbGt6cytlZTVoZFNs?=
 =?utf-8?B?bE1odDVQeDQya3VOYmlVNjQ2bjdHS2N1eEVKcFQ5eitJdkozOGlKSHVqS0ND?=
 =?utf-8?B?cWdxMVNaUm5RVlA2dHNLNXZLOE1lMnpNdHduZHZlcmlhS0RqTXRuRG1JbEwx?=
 =?utf-8?B?YUJmenlEQ1YrMnZmZUtRUFhWS1JvVGxDNzNTa2FKei9xdTN0aW5ZUW44WWV4?=
 =?utf-8?Q?kTWQIOWEXdZF4pAhxJvDinWtc?=
Content-ID: <95F0D0B74E336944A2C84DE1489B7D74@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: base64
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: TYZPR03MB7867.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 459c8283-a30f-4f89-0cac-08dc4f9eca54
X-MS-Exchange-CrossTenant-originalarrivaltime: 29 Mar 2024 03:17:39.7453
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: +qIpw7L6O6rV5sgqpfemTjFm+Y8WP83xscKIHuxTlwxGhHgZKX/kXEaU0EaA6EQBeJXEteDkC1e8pJ3RoeKxAQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYZPR03MB8461
Content-Type: multipart/alternative;
	boundary="__=_Part_Boundary_002_1354427398.1720080783"
X-Original-Sender: boy.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=LhJeqdiZ;       dkim=neutral
 (body hash did not verify) header.i=@mediateko365.onmicrosoft.com
 header.s=selector2-mediateko365-onmicrosoft-com header.b=g5WHWgTx;
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

--__=_Part_Boundary_002_1354427398.1720080783
Content-Type: text/plain; charset="UTF-8"

Hi Russell:

Kingly ping

Thanks.
Boy.

On Fri, 2023-12-22 at 10:27 +0800, boy.wu wrote:
> From: Boy Wu <boy.wu@mediatek.com>
> 
> We found below OOB crash:
> 
> [   33.452494]
> ==================================================================
> [   33.453513] BUG: KASAN: stack-out-of-bounds in
> refresh_cpu_vm_stats.constprop.0+0xcc/0x2ec
> [   33.454660] Write of size 164 at addr c1d03d30 by task swapper/0/0
> [   33.455515]
> [   33.455767] CPU: 0 PID: 0 Comm: swapper/0 Tainted:
> G           O       6.1.25-mainline #1
> [   33.456880] Hardware name: Generic DT based system
> [   33.457555]  unwind_backtrace from show_stack+0x18/0x1c
> [   33.458326]  show_stack from dump_stack_lvl+0x40/0x4c
> [   33.459072]  dump_stack_lvl from print_report+0x158/0x4a4
> [   33.459863]  print_report from kasan_report+0x9c/0x148
> [   33.460616]  kasan_report from kasan_check_range+0x94/0x1a0
> [   33.461424]  kasan_check_range from memset+0x20/0x3c
> [   33.462157]  memset from
> refresh_cpu_vm_stats.constprop.0+0xcc/0x2ec
> [   33.463064]  refresh_cpu_vm_stats.constprop.0 from
> tick_nohz_idle_stop_tick+0x180/0x53c
> [   33.464181]  tick_nohz_idle_stop_tick from do_idle+0x264/0x354
> [   33.465029]  do_idle from cpu_startup_entry+0x20/0x24
> [   33.465769]  cpu_startup_entry from rest_init+0xf0/0xf4
> [   33.466528]  rest_init from arch_post_acpi_subsys_init+0x0/0x18
> [   33.467397]
> [   33.467644] The buggy address belongs to stack of task swapper/0/0
> [   33.468493]  and is located at offset 112 in frame:
> [   33.469172]  refresh_cpu_vm_stats.constprop.0+0x0/0x2ec
> [   33.469917]
> [   33.470165] This frame has 2 objects:
> [   33.470696]  [32, 76) 'global_zone_diff'
> [   33.470729]  [112, 276) 'global_node_diff'
> [   33.471294]
> [   33.472095] The buggy address belongs to the physical page:
> [   33.472862] page:3cd72da8 refcount:1 mapcount:0 mapping:00000000
> index:0x0 pfn:0x41d03
> [   33.473944] flags: 0x1000(reserved|zone=0)
> [   33.474565] raw: 00001000 ed741470 ed741470 00000000 00000000
> 00000000 ffffffff 00000001
> [   33.475656] raw: 00000000
> [   33.476050] page dumped because: kasan: bad access detected
> [   33.476816]
> [   33.477061] Memory state around the buggy address:
> [   33.477732]  c1d03c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> 00 00
> [   33.478630]  c1d03c80: 00 00 00 00 00 00 00 00 f1 f1 f1 f1 00 00
> 00 00
> [   33.479526] >c1d03d00: 00 04 f2 f2 f2 f2 00 00 00 00 00 00 f1 f1
> f1 f1
> [   33.480415]                                                ^
> [   33.481195]  c1d03d80: 00 00 00 00 00 00 00 00 00 00 04 f3 f3 f3
> f3 f3
> [   33.482088]  c1d03e00: f3 f3 f3 f3 00 00 00 00 00 00 00 00 00 00
> 00 00
> [   33.482978]
> ==================================================================
> 
> We find the root cause of this OOB is that arm does not clear stale
> stack
> poison in the case of cpuidle.
> 
> This patch refer to arch/arm64/kernel/sleep.S to resolve this issue.
> 
> Signed-off-by: Boy Wu <boy.wu@mediatek.com>
> ---
>  arch/arm/kernel/sleep.S | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/arch/arm/kernel/sleep.S b/arch/arm/kernel/sleep.S
> index a86a1d4f3461..93afd1005b43 100644
> --- a/arch/arm/kernel/sleep.S
> +++ b/arch/arm/kernel/sleep.S
> @@ -127,6 +127,10 @@ cpu_resume_after_mmu:
>  	instr_sync
>  #endif
>  	bl	cpu_init		@ restore the und/abt/irq
> banked regs
> +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> +	mov	r0, sp
> +	bl	kasan_unpoison_task_stack_below
> +#endif
>  	mov	r0, #0			@ return zero on success
>  	ldmfd	sp!, {r4 - r11, pc}
>  ENDPROC(cpu_resume_after_mmu)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6837adc26ed09b9acd6a2239a14014cd3f16c87c.camel%40mediatek.com.

--__=_Part_Boundary_002_1354427398.1720080783
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><body><p>
<pre>
Hi&#32;Russell:

Kingly&#32;ping

Thanks.
Boy.

On&#32;Fri,&#32;2023-12-22&#32;at&#32;10:27&#32;+0800,&#32;boy.wu&#32;wrote=
:
&gt;&#32;From:&#32;Boy&#32;Wu&#32;&lt;boy.wu@mediatek.com&gt;
&gt;&#32;
&gt;&#32;We&#32;found&#32;below&#32;OOB&#32;crash:
&gt;&#32;
&gt;&#32;[&#32;&#32;&#32;33.452494]
&gt;&#32;=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
&gt;&#32;[&#32;&#32;&#32;33.453513]&#32;BUG:&#32;KASAN:&#32;stack-out-of-bo=
unds&#32;in
&gt;&#32;refresh_cpu_vm_stats.constprop.0+0xcc/0x2ec
&gt;&#32;[&#32;&#32;&#32;33.454660]&#32;Write&#32;of&#32;size&#32;164&#32;a=
t&#32;addr&#32;c1d03d30&#32;by&#32;task&#32;swapper/0/0
&gt;&#32;[&#32;&#32;&#32;33.455515]
&gt;&#32;[&#32;&#32;&#32;33.455767]&#32;CPU:&#32;0&#32;PID:&#32;0&#32;Comm:=
&#32;swapper/0&#32;Tainted:
&gt;&#32;G&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;O&#32;&#32=
;&#32;&#32;&#32;&#32;&#32;6.1.25-mainline&#32;#1
&gt;&#32;[&#32;&#32;&#32;33.456880]&#32;Hardware&#32;name:&#32;Generic&#32;=
DT&#32;based&#32;system
&gt;&#32;[&#32;&#32;&#32;33.457555]&#32;&#32;unwind_backtrace&#32;from&#32;=
show_stack+0x18/0x1c
&gt;&#32;[&#32;&#32;&#32;33.458326]&#32;&#32;show_stack&#32;from&#32;dump_s=
tack_lvl+0x40/0x4c
&gt;&#32;[&#32;&#32;&#32;33.459072]&#32;&#32;dump_stack_lvl&#32;from&#32;pr=
int_report+0x158/0x4a4
&gt;&#32;[&#32;&#32;&#32;33.459863]&#32;&#32;print_report&#32;from&#32;kasa=
n_report+0x9c/0x148
&gt;&#32;[&#32;&#32;&#32;33.460616]&#32;&#32;kasan_report&#32;from&#32;kasa=
n_check_range+0x94/0x1a0
&gt;&#32;[&#32;&#32;&#32;33.461424]&#32;&#32;kasan_check_range&#32;from&#32=
;memset+0x20/0x3c
&gt;&#32;[&#32;&#32;&#32;33.462157]&#32;&#32;memset&#32;from
&gt;&#32;refresh_cpu_vm_stats.constprop.0+0xcc/0x2ec
&gt;&#32;[&#32;&#32;&#32;33.463064]&#32;&#32;refresh_cpu_vm_stats.constprop=
.0&#32;from
&gt;&#32;tick_nohz_idle_stop_tick+0x180/0x53c
&gt;&#32;[&#32;&#32;&#32;33.464181]&#32;&#32;tick_nohz_idle_stop_tick&#32;f=
rom&#32;do_idle+0x264/0x354
&gt;&#32;[&#32;&#32;&#32;33.465029]&#32;&#32;do_idle&#32;from&#32;cpu_start=
up_entry+0x20/0x24
&gt;&#32;[&#32;&#32;&#32;33.465769]&#32;&#32;cpu_startup_entry&#32;from&#32=
;rest_init+0xf0/0xf4
&gt;&#32;[&#32;&#32;&#32;33.466528]&#32;&#32;rest_init&#32;from&#32;arch_po=
st_acpi_subsys_init+0x0/0x18
&gt;&#32;[&#32;&#32;&#32;33.467397]
&gt;&#32;[&#32;&#32;&#32;33.467644]&#32;The&#32;buggy&#32;address&#32;belon=
gs&#32;to&#32;stack&#32;of&#32;task&#32;swapper/0/0
&gt;&#32;[&#32;&#32;&#32;33.468493]&#32;&#32;and&#32;is&#32;located&#32;at&=
#32;offset&#32;112&#32;in&#32;frame:
&gt;&#32;[&#32;&#32;&#32;33.469172]&#32;&#32;refresh_cpu_vm_stats.constprop=
.0+0x0/0x2ec
&gt;&#32;[&#32;&#32;&#32;33.469917]
&gt;&#32;[&#32;&#32;&#32;33.470165]&#32;This&#32;frame&#32;has&#32;2&#32;ob=
jects:
&gt;&#32;[&#32;&#32;&#32;33.470696]&#32;&#32;[32,&#32;76)&#32;&#39;global_z=
one_diff&#39;
&gt;&#32;[&#32;&#32;&#32;33.470729]&#32;&#32;[112,&#32;276)&#32;&#39;global=
_node_diff&#39;
&gt;&#32;[&#32;&#32;&#32;33.471294]
&gt;&#32;[&#32;&#32;&#32;33.472095]&#32;The&#32;buggy&#32;address&#32;belon=
gs&#32;to&#32;the&#32;physical&#32;page:
&gt;&#32;[&#32;&#32;&#32;33.472862]&#32;page:3cd72da8&#32;refcount:1&#32;ma=
pcount:0&#32;mapping:00000000
&gt;&#32;index:0x0&#32;pfn:0x41d03
&gt;&#32;[&#32;&#32;&#32;33.473944]&#32;flags:&#32;0x1000(reserved|zone=3D0=
)
&gt;&#32;[&#32;&#32;&#32;33.474565]&#32;raw:&#32;00001000&#32;ed741470&#32;=
ed741470&#32;00000000&#32;00000000
&gt;&#32;00000000&#32;ffffffff&#32;00000001
&gt;&#32;[&#32;&#32;&#32;33.475656]&#32;raw:&#32;00000000
&gt;&#32;[&#32;&#32;&#32;33.476050]&#32;page&#32;dumped&#32;because:&#32;ka=
san:&#32;bad&#32;access&#32;detected
&gt;&#32;[&#32;&#32;&#32;33.476816]
&gt;&#32;[&#32;&#32;&#32;33.477061]&#32;Memory&#32;state&#32;around&#32;the=
&#32;buggy&#32;address:
&gt;&#32;[&#32;&#32;&#32;33.477732]&#32;&#32;c1d03c00:&#32;00&#32;00&#32;00=
&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;=
00
&gt;&#32;00&#32;00
&gt;&#32;[&#32;&#32;&#32;33.478630]&#32;&#32;c1d03c80:&#32;00&#32;00&#32;00=
&#32;00&#32;00&#32;00&#32;00&#32;00&#32;f1&#32;f1&#32;f1&#32;f1&#32;00&#32;=
00
&gt;&#32;00&#32;00
&gt;&#32;[&#32;&#32;&#32;33.479526]&#32;&gt;c1d03d00:&#32;00&#32;04&#32;f2&=
#32;f2&#32;f2&#32;f2&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;f1&#32;f=
1
&gt;&#32;f1&#32;f1
&gt;&#32;[&#32;&#32;&#32;33.480415]&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;=
&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;=
&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;=
&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#32;&#94;
&gt;&#32;[&#32;&#32;&#32;33.481195]&#32;&#32;c1d03d80:&#32;00&#32;00&#32;00=
&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;04&#32;f3&#32;f3&#32;=
f3
&gt;&#32;f3&#32;f3
&gt;&#32;[&#32;&#32;&#32;33.482088]&#32;&#32;c1d03e00:&#32;f3&#32;f3&#32;f3=
&#32;f3&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;00&#32;=
00
&gt;&#32;00&#32;00
&gt;&#32;[&#32;&#32;&#32;33.482978]
&gt;&#32;=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
&gt;&#32;
&gt;&#32;We&#32;find&#32;the&#32;root&#32;cause&#32;of&#32;this&#32;OOB&#32=
;is&#32;that&#32;arm&#32;does&#32;not&#32;clear&#32;stale
&gt;&#32;stack
&gt;&#32;poison&#32;in&#32;the&#32;case&#32;of&#32;cpuidle.
&gt;&#32;
&gt;&#32;This&#32;patch&#32;refer&#32;to&#32;arch/arm64/kernel/sleep.S&#32;=
to&#32;resolve&#32;this&#32;issue.
&gt;&#32;
&gt;&#32;Signed-off-by:&#32;Boy&#32;Wu&#32;&lt;boy.wu@mediatek.com&gt;
&gt;&#32;---
&gt;&#32;&#32;arch/arm/kernel/sleep.S&#32;|&#32;4&#32;++++
&gt;&#32;&#32;1&#32;file&#32;changed,&#32;4&#32;insertions(+)
&gt;&#32;
&gt;&#32;diff&#32;--git&#32;a/arch/arm/kernel/sleep.S&#32;b/arch/arm/kernel=
/sleep.S
&gt;&#32;index&#32;a86a1d4f3461..93afd1005b43&#32;100644
&gt;&#32;---&#32;a/arch/arm/kernel/sleep.S
&gt;&#32;+++&#32;b/arch/arm/kernel/sleep.S
&gt;&#32;@@&#32;-127,6&#32;+127,10&#32;@@&#32;cpu_resume_after_mmu:
&gt;&#32;&#32;instr_sync
&gt;&#32;&#32;#endif
&gt;&#32;&#32;blcpu_init@&#32;restore&#32;the&#32;und/abt/irq
&gt;&#32;banked&#32;regs
&gt;&#32;+#if&#32;defined(CONFIG_KASAN)&#32;&amp;&amp;&#32;defined(CONFIG_K=
ASAN_STACK)
&gt;&#32;+movr0,&#32;sp
&gt;&#32;+blkasan_unpoison_task_stack_below
&gt;&#32;+#endif
&gt;&#32;&#32;movr0,&#32;#0@&#32;return&#32;zero&#32;on&#32;success
&gt;&#32;&#32;ldmfdsp!,&#32;{r4&#32;-&#32;r11,&#32;pc}
&gt;&#32;&#32;ENDPROC(cpu_resume_after_mmu)

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
om/d/msgid/kasan-dev/6837adc26ed09b9acd6a2239a14014cd3f16c87c.camel%40media=
tek.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/6837adc26ed09b9acd6a2239a14014cd3f16c87c.camel%40mediatek.=
com</a>.<br />

--__=_Part_Boundary_002_1354427398.1720080783--

