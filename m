Return-Path: <kasan-dev+bncBAABBV5RU2PQMGQE5HCQYWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A5A78693BF8
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 02:56:41 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id x14-20020a9d6d8e000000b0068bd4aa4439sf5806334otp.20
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Feb 2023 17:56:41 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ad6y8UXgWT7WW2txjSLLHT8q0M6I2bt48sux5Hx8i8g=;
        b=THOr2ALOQy92bHl4QB8omnpXvIsS9RT1TteCDNwtBHdq6OFHCSrzgMfFXKvEXsR9NH
         rrlpAOZntzL2GliHnOcxdEP+K35BEP+IaWUcJ5VHyWLrcFtp0xU2Z73WYbqoiQPECJPi
         g5U9OBAIyVndcwIxDwHbGXPBlksrtB9DkIIYUDQiLxEBfmgYiBaO7nXhkguC87te62lw
         kqP4dqhQcgRgH11k/I4hS7jRGnPu5+I+PUhf83jYEUJcaTYeLUBGkPDiNPBa98ptKk41
         RiMAbZVwzjOFvHTTlAkJQMoipr8JlpiDGwXSeHehp2hiDNQtX9+NMaboanVDKKfKJ5Xb
         xndg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ad6y8UXgWT7WW2txjSLLHT8q0M6I2bt48sux5Hx8i8g=;
        b=KXmF+09r8LM2tPSwD0oYj1rFE3N3hWhyb/wOT9JKzP5tAV/Bbe+rMPoEmJ0GPSj2MH
         HMPsHgdE+E3SHy6KlUwGbNZhKm0W+ti/EoSwUI26NwHIb4su5a5hmst7H3RZgrkCf3Xz
         bZ+cffSFDLSPSDzAv9cvk4Dkhk5/OvmqgkxFees4pQIO3jjNqvEPqpuUgGojvXK/6yEY
         fIxpqLyD6cHQwOqilV2iVkkskRq9RzAqA9zosFCtu2/jwZFckpSb7HSAWC3yUZvZNaHD
         wsLfmlqs2W+4JX4IAeZRuwDwMiOSdclQeyoualpBX9qmA8i1CEk8HZYbqTQqN8gBO+SJ
         UQ7A==
X-Gm-Message-State: AO0yUKUQrsvpfynO+ZBut5AMVf5PwrAeeumT5cgyqjOAHgMd1bkHn+Tn
	9j3bJlzn/Gt2PafEaLr3BWo=
X-Google-Smtp-Source: AK7set9rQidKeRzfCUykdqAeA8kjTn4fChRDg7tr6v1WWWmHAizHa9hsx/HT++V0pZs8zVW87BHBnw==
X-Received: by 2002:aca:bb08:0:b0:37b:5331:1b8a with SMTP id l8-20020acabb08000000b0037b53311b8amr2114718oif.180.1676253399924;
        Sun, 12 Feb 2023 17:56:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6c06:0:b0:68d:b7eb:4712 with SMTP id f6-20020a9d6c06000000b0068db7eb4712ls1712530otq.8.-pod-prod-gmail;
 Sun, 12 Feb 2023 17:56:39 -0800 (PST)
X-Received: by 2002:a9d:490a:0:b0:68b:cd66:2c52 with SMTP id e10-20020a9d490a000000b0068bcd662c52mr12790213otf.5.1676253399386;
        Sun, 12 Feb 2023 17:56:39 -0800 (PST)
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id br2-20020a056830390200b00686e40e1e0esi1596031otb.1.2023.02.12.17.56.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 12 Feb 2023 17:56:39 -0800 (PST)
Received-SPF: pass (google.com: domain of qun-wei.lin@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: a2ea2e72ab4111ed945fc101203acc17-20230213
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.19,REQID:afd2b6ab-23ec-4e66-86f6-8192249db12c,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:885ddb2,CLOUDID:2bc30e57-dd49-462e-a4be-2143a3ddc739,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0
X-CID-BVR: 0,NGT
X-UUID: a2ea2e72ab4111ed945fc101203acc17-20230213
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw02.mediatek.com
	(envelope-from <qun-wei.lin@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1269957116; Mon, 13 Feb 2023 09:56:31 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs11n2.mediatek.inc (172.21.101.187) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Mon, 13 Feb 2023 09:56:30 +0800
Received: from APC01-SG2-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n1.mediatek.com (172.21.101.34) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Mon, 13 Feb 2023 09:56:28 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=j8VcP+JfOqOl2tfUqM9Fm0P5ijaLklUKaJUM4nam+pAXCXaM/fGDMegO7cumn8sqpBy1NMbtff5XxmItcedS+EmeL1wqRpA91ZlxTR4jITjqdPeG9NihFpx8g06TETWu9B2IKtkmx4oQArTY0KtVv6/wK96hpCN8q9UPvpaoxbGJ1cMarqwB1z41xwjKfFHYaln9l/epQaK0ov0FpQfOV9AjViOIvhfz2pYP+4LnlgC12NWYScN/+XPIUDx3Fn33DIIH083xSovIq5Vd51mQ1rSQaZMppEMccnSTlc4BNpQ2voJFpxF6unbRJ1MlYdA5FlvYZV6xCw9n/uTfasm0+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ybYP1odfYv3tkg3B7Coq9ooK65A8H6TgFD5wZdr4Spk=;
 b=SN0wSOziLJbIdSvW/T+0TNEE2lJJW4bXioXM9FUoSuElLnBmO+VTdzasDYzj7b1KGQwLjZt3bxAL+hgTvffgNlGEALaBmr+lL+h8dgNRRTqi0nbyTQhpKzmPQZPLnhLVYqWCqUBFthUlB+qVl/iDUbUwNmyxge2cPfe0BXo0E/Q0q7+izKRzZVOQFf14EdX+Cy/RPsRi+09nmuPghmn4yPDfOgGX5pn/o9CVaxqL0sz3iYNdv3XcoTWvK8NY/V+Mg4amPBFsdR1xXeTkSwP7WkfVUgughi0Of9v+u2izGVCxhLwcG42pjU0csP2IENa3TgmIeJ+FRTjP+JYDEdjSLQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PSAPR03MB5542.apcprd03.prod.outlook.com (2603:1096:301:4e::12)
 by TYZPR03MB7101.apcprd03.prod.outlook.com (2603:1096:400:343::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6086.23; Mon, 13 Feb
 2023 01:56:27 +0000
Received: from PSAPR03MB5542.apcprd03.prod.outlook.com
 ([fe80::d95d:2759:fb36:cecb]) by PSAPR03MB5542.apcprd03.prod.outlook.com
 ([fe80::d95d:2759:fb36:cecb%9]) with mapi id 15.20.6086.023; Mon, 13 Feb 2023
 01:56:27 +0000
From: =?UTF-8?B?J1F1bi13ZWkgTGluICjmnpfnvqTltLQpJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: "pcc@google.com" <pcc@google.com>
CC: =?utf-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, =?utf-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
	<chinwen.chang@mediatek.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
	=?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>, "catalin.marinas@arm.com"
	<catalin.marinas@arm.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "vincenzo.frascino@arm.com"
	<vincenzo.frascino@arm.com>, "will@kernel.org" <will@kernel.org>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Thread-Topic: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Thread-Index: AQHYfN3UQ2ZS5zhImUiCo/W/1QNefK68k6aAgAB+/YCAAPZ+gIAA7XQAgAcPvACAAy8rAIAEbYqA
Date: Mon, 13 Feb 2023 01:56:26 +0000
Message-ID: <fca211403447d116be62f494c42e7554f869e389.camel@mediatek.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
	 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
	 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
	 <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
	 <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
	 <a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel@mediatek.com>
	 <Y+Xh6IuBFCYZhQIj@google.com>
In-Reply-To: <Y+Xh6IuBFCYZhQIj@google.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PSAPR03MB5542:EE_|TYZPR03MB7101:EE_
x-ms-office365-filtering-correlation-id: 7eebed16-56ee-450a-e9d7-08db0d65848a
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 2sg1iDBLA29KRukIHNi3mj2TJrQmTUUUMNBv5cQa97ndKCqbcePyLATiLfYy9avkbOQckxb6H7ioopgeOJcprCyx75/iAY5KMTCwgsRASFDVqeDV+pIhdHjcucB+h1sgGjjFLKnm1bl1CbLOJWZAzGESpFWs2O/gjbmSa+yjU4BrCqTVmdnCoHzz45OCDKmtwVKudCplBrZgbLD+FsBXodE9HkmJBtUQWuIxjz/y/66bcE9b4mzJwAycVvpHXAM4+3yQK5E8GkDQlPmh/MoOuqjhFQhJ3cul8/PYK4au9qIrhnw9p6sDxNCRLTRpMNPxiFKMw4m3WONKaPqRtPnv+ywm6wh7GxJH8+YjlTKGGsUz6nhq13Jl3sjp3LmP0x+kjty5tmghgGBrwuoZe4KLGTLdzfFI+ZYhLvUCz9tilZTj389UJTJudEZYzA8eDfRsWlNj4GUi9HdcsRNfvb1cpbsSVcgond/5NxUTOFx8JkabOJQExGTKqQ17Bj/+aeqA/jlGtspZHVv0lFLqi6i8JOFMmr74HOoG6BTTCXjfuZw/vReRuj5xB0Tw4uKEr5mtzdKdD4B25WHZOusW03i7JwGxpTuXshDxXGDpn+vaJKLVUtxPY0lzIsG1GCR3oj4XPsD+2o5wpl5J7/AwNofK4Ymqae1sdWTRPOKR2zf1ZhnCrWSXdlFyk2SQfQPjKQUXXDq3DELDQBHZDbs9Z/xgocv2tcqBjTDHVtKfW7ad2oflAyi93sfGQZ3jgO2tHyLO0qAdeHb53cdsav2NGc1DC5AZoKCDzXRi9yFKIoIP98aYBZ0y8Yr7JTSejTQA4n+3
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PSAPR03MB5542.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230025)(4636009)(346002)(136003)(396003)(376002)(366004)(39850400004)(451199018)(316002)(38070700005)(83380400001)(91956017)(4326008)(66556008)(64756008)(66446008)(76116006)(66476007)(6916009)(66946007)(8676002)(2616005)(6486002)(36756003)(71200400001)(8936002)(85182001)(38100700002)(2906002)(966005)(478600001)(86362001)(122000001)(5660300002)(53546011)(6512007)(54906003)(6506007)(41300700001)(26005)(186003);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?NDZnMEZCZUVnS0hMWW1XTjlmUndHcjgwM21YQ3N5Nm02Y3hiRGhvVld3eWpE?=
 =?utf-8?B?MlhvNVEyTms2bXplNDNQalF5MEF5VDdXd3htSmxVWitCTng5WG5uVEVDS1Rz?=
 =?utf-8?B?QXh5MDhqTFlVV0VKZzV3WXJMaXNhdTZDMHpadTdjM3BVQ091blZuaW5xRUth?=
 =?utf-8?B?ZDVKK0xtdm9rOU1VU1ArVlNYdmlYQWZWdHdDSlNwREh4NDdEMDc3KzdLYWd2?=
 =?utf-8?B?bmFtVFIxM2pJNzUwZ0FXT3NJVE00NzRyYVAxVTRsTE1zRG1heGFDdURrRG5K?=
 =?utf-8?B?bHBYeUlES01XVm9SM1ZJL3gvRHU4Q2JQNTg3Z3RIS09xRnF2c0QvVjdrcFFH?=
 =?utf-8?B?b1dsRThMcHF0WXhiWjZZRFZvZEkrTXI4T284VTlGT1dpTkdISG5QbTVZazhB?=
 =?utf-8?B?dHdBYkhLRk1ndE8zM0xVbXlGM1JJajNveGZSeGJ3NWFaaGgxMUV6OG03SXlI?=
 =?utf-8?B?VG9nMURXcDlOUk9OL3hraUt6b2FQU1dkUm0vMGtVNi9lUTJpSGp4T1dzN3Nt?=
 =?utf-8?B?VlI0NEErOEJUdmlna21wdnpLL3FSejM3d1Vvb2pjQ3lteFBVVHhrRFZsWTBL?=
 =?utf-8?B?aWlWNjJuQUR5T0hsb3prcXpqYTF6R2dsUG9aSEpsYmhMM0RJY1dLVmdDRnU3?=
 =?utf-8?B?cVZxbnNwUVFnaHJIbFBRTmEyeWxkWHlhemFBSXRXOERISjRMd1ZWY0x0SkNR?=
 =?utf-8?B?NElya2ZmVHRWNVVjOTZFdUZJMSsyTTREUER3TU1XdDk1R3l2OFJGeWEyNkZE?=
 =?utf-8?B?OXplaU9EK3FzbmpaL0k2UkNjRzV0YU0zeWd2bjBaRk9OcnlCTmF3SjRrQzNS?=
 =?utf-8?B?akg2MjQ5Ri91VXFKSWF4VW94TytmbUNTaDZ1NjczK1RaUStzaTRVYnNvK0Zq?=
 =?utf-8?B?d0FsbFl3am1kQm1BZFNQVlQ5RkhtK0tKYldWWFVVR1ZCOVFkK1UxdEh5Q2Nq?=
 =?utf-8?B?VnA5L3FwY0R6VFVJUExOVkR0eVdWS2dBYlJEdjgvYnVUaUJlNUs5VS85ajIy?=
 =?utf-8?B?WUM2WUpHL2c0YzQwSmxnYzVwSUN5YXNHaGhwcVk3MndyZ0FKU3dLbFdjSHdN?=
 =?utf-8?B?M1NWM0V4b2s0NG5veVJadXhZTno2VXYwSFNaZmpjYk5uVEY2SmNkcTVDNGNI?=
 =?utf-8?B?SGxDUFZid2JuNnoyWVRHQkk5aVZ0RzFjV1RQWGFDd0toYmpXY2ZhNTR3ZDI3?=
 =?utf-8?B?Z014MERQdjlKbmpOVFJBYUV2UHoyS3crRWNjYmZOZlBtVTNiSFJVNW1PQmJu?=
 =?utf-8?B?K2tITUxFdER5K1FrQ2Z1NXowdmpGTEpRaWpnNXFUY3VROGJWajJZOWltcE1x?=
 =?utf-8?B?STRCQU5VeW5Xb2VsN1lCUU4yM3Z6YXlRVi9DK2ZMalF4WHYzY0FvL3pNc3Z4?=
 =?utf-8?B?em1CZ0kzMzMwZUw0NEM0OHAvWnBnSDJza0Mra0laZ0RHbVcvNXZDT1NHQTJV?=
 =?utf-8?B?QnJPZ0I4eXBQT3lmblVJRDNURWM0R1FuWEJ0cmlvZlp3amoxN3dMUFJDNFVT?=
 =?utf-8?B?YmN3c3l1QSswb2ZVQUpXY2Q1dGZyeDV6c2UvdTZsL2kwVHMzcGVJUTUyc0VG?=
 =?utf-8?B?MjkzaU9LT0kzUjQ3R2NNTGdIWllZZUNZL1FIeUhYVzZscmhwQXd3MWlVUW9M?=
 =?utf-8?B?MG04akxCMllPWUVvbGhvWHpDMWt3V1p1T1BlcUdvNm9RazViY1N2Q1lvOTVI?=
 =?utf-8?B?RjZQYk9sU0htTkErZW1BaE9SMDJPemxqaGV0Q1NMWTExYXo3aFZXM01ScjRN?=
 =?utf-8?B?TXdZNnhwOWtmb3RFOHNjY3N2bDJwUXRLU2gwU0FONGt4b3l3Tmo3aktqNEk3?=
 =?utf-8?B?Qkw0ZlFwRlY0MFRSMW5UcHJVUnpEL2tuWlA2NFJYcE1vVi8wdDkrV09OL2xX?=
 =?utf-8?B?b1lUVHczWS9BblUxWlJkeG9HOVBpOGVROXVVU3drRkc0Y1NXYVYxb1FVa09P?=
 =?utf-8?B?TExaOFVEampBOXRsa0UxckhLa01xVzR6REtkWDEycVRLa2NKV1o5dU9MTG9q?=
 =?utf-8?B?QXpsT29XMG0vZjl2UW5KOWNTVWFCeXIybGxqS2RtcDEyNU9zM0RVYnc5RzNU?=
 =?utf-8?B?dU1ZeEo2dFI4NVM0MDZ2YVBwWlR1SjR6UE5oWGJIMjg3YU9vMGg3V0NQRFRi?=
 =?utf-8?B?V3dhUEdFN3UySlNSdWloQjl1RWFXU3cxRlJlRDl1V3lGa0Iwck12Uk9zQlpU?=
 =?utf-8?B?cEE9PQ==?=
Content-ID: <092F307BEAB81040B8DC43FB96DCE511@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: base64
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PSAPR03MB5542.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7eebed16-56ee-450a-e9d7-08db0d65848a
X-MS-Exchange-CrossTenant-originalarrivaltime: 13 Feb 2023 01:56:26.8986
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: BGbjViMQBb8T1iGs5DBZohs5gBncG/EbGx3deae0u+ePKWe9Gl0aWU7zrPsZIZsMz0fEu8ORbHdsdftkXSwQI6AQqgJk2wCAyyd0jgDi6so=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYZPR03MB7101
Content-Type: multipart/alternative;
	boundary="__=_Part_Boundary_004_1524195472.1592563418"
X-Original-Sender: qun-wei.lin@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=XzQN6htk;       dkim=neutral
 (body hash did not verify) header.i=@mediateko365.onmicrosoft.com
 header.s=selector2-mediateko365-onmicrosoft-com header.b=qRPNecqX;
       arc=fail (body hash mismatch);       spf=pass (google.com: domain of
 qun-wei.lin@mediatek.com designates 210.61.82.184 as permitted sender)
 smtp.mailfrom=qun-wei.lin@mediatek.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
Reply-To: =?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
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

--__=_Part_Boundary_004_1524195472.1592563418
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<pre>
On&#32;Thu,&#32;2023-02-09&#32;at&#32;22:19&#32;-0800,&#32;Peter&#32;Collin=
gbourne&#32;wrote:
&gt;&#32;On&#32;Wed,&#32;Feb&#32;08,&#32;2023&#32;at&#32;05:41:45AM&#32;+00=
00,&#32;Qun-wei&#32;Lin&#32;(&#26519;&#32676;&#23860;)&#32;wrote:
&gt;&#32;&gt;&#32;On&#32;Fri,&#32;2023-02-03&#32;at&#32;18:51&#32;+0100,&#3=
2;Andrey&#32;Konovalov&#32;wrote:
&gt;&#32;&gt;&#32;&gt;&#32;On&#32;Fri,&#32;Feb&#32;3,&#32;2023&#32;at&#32;4=
:41&#32;AM&#32;Kuan-Ying&#32;Lee&#32;(&#26446;&#20896;&#31310;)
&gt;&#32;&gt;&#32;&gt;&#32;&lt;Kuan-Ying.Lee@mediatek.com&gt;&#32;wrote:
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;Hi&#32;Kuan-Ying,
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;There&#32;recently&#32;was&#32=
;a&#32;similar&#32;crash&#32;due&#32;to&#32;incorrectly
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;implemented
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;sampling.
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;Do&#32;you&#32;have&#32;the&#3=
2;following&#32;patch&#32;in&#32;your&#32;tree&#63;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/9f7f5a25f335e6e1484695da9180281a728db7e2__;Kw!!CTRNKA9wMg0ARbw!hUjRlXirPM=
SusdIWe0RIPt0PNqIHYDCJyd7GSd4o-TgLMP0CKRUkjElH-jcvtaz42-sgE2U58964rCCbuNTJE=
5Jx&#36;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;If&#32;not,&#32;please&#32;syn=
c&#32;your&#32;6.1&#32;tree&#32;with&#32;the&#32;Android&#32;common
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;kernel.
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;Hopefully&#32;this&#32;will&#3=
2;fix&#32;the&#32;issue.
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;Thanks!
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;Hi&#32;Andrey,
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;Thanks&#32;for&#32;your&#32;advice.
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;I&#32;saw&#32;this&#32;patch&#32;is&#32=
;to&#32;fix&#32;(&quot;kasan:&#32;allow&#32;sampling&#32;page_alloc
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;allocations&#32;for&#32;HW_TAGS&quot;).
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;But&#32;our&#32;6.1&#32;tree&#32;doesn&=
#39;t&#32;have&#32;following&#32;two&#32;commits&#32;now.
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;(&quot;FROMGIT:&#32;kasan:&#32;allow&#3=
2;sampling&#32;page_alloc&#32;allocations&#32;for
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;HW_TAGS&quot;)
&gt;&#32;&gt;&#32;&gt;&#32;&gt;&#32;(FROMLIST:&#32;kasan:&#32;reset&#32;pag=
e&#32;tags&#32;properly&#32;with&#32;sampling)
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;Hi&#32;Kuan-Ying,
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;Hi&#32;Andrey,
&gt;&#32;&gt;&#32;I&#39;ll&#32;stand&#32;in&#32;for&#32;Kuan-Ying&#32;as&#3=
2;he&#39;s&#32;out&#32;of&#32;office.
&gt;&#32;&gt;&#32;Thanks&#32;for&#32;your&#32;help!
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;Just&#32;to&#32;clarify:&#32;these&#32;two&#32;p=
atches&#32;were&#32;applied&#32;twice:&#32;once&#32;here
&gt;&#32;&gt;&#32;&gt;&#32;on
&gt;&#32;&gt;&#32;&gt;&#32;Jan&#32;13:
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/a2a9e34d164e90fc08d35fd097a164b9101d72ef__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745_3oO-=
3k&#36;
&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/435e2a6a6c8ba8d0eb55f9aaade53e7a3957322b__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745sDEOY=
WY&#36;
&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;Our&#32;codebase&#32;does&#32;not&#32;contain&#32;these&#=
32;two&#32;patches.
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;but&#32;then&#32;reverted&#32;here&#32;on&#32;Ja=
n&#32;20:
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/5503dbe454478fe54b9cac3fc52d4477f52efdc9__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745Bl77d=
FY&#36;
&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/4573a3cf7e18735a477845426238d46d96426bb6__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745K-J8O=
-w&#36;
&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;And&#32;then&#32;once&#32;again&#32;via&#32;the&=
#32;link&#32;I&#32;sent&#32;before&#32;together&#32;with&#32;a
&gt;&#32;&gt;&#32;&gt;&#32;fix&#32;on
&gt;&#32;&gt;&#32;&gt;&#32;Jan&#32;25.
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;It&#32;might&#32;be&#32;that&#32;you&#32;still&#=
32;have&#32;to&#32;former&#32;two&#32;patches&#32;in&#32;your
&gt;&#32;&gt;&#32;&gt;&#32;tree&#32;if
&gt;&#32;&gt;&#32;&gt;&#32;you&#32;synced&#32;it&#32;before&#32;the&#32;rev=
ert.
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;However,&#32;if&#32;this&#32;is&#32;not&#32;the&=
#32;case:
&gt;&#32;&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;Which&#32;6.1&#32;commit&#32;is&#32;your&#32;tre=
e&#32;based&#32;on&#63;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/53b3a7721b7aec74d8fa2ee55c2480044cc7c1b8__;Kw!!CTRNKA9wMg0ARbw!iEzuh9LYXl=
wXkpcWaHjncfr6lNgTky7OEAEzQ7cIFjlTD__7lwXqAhPJwWJXEnD8THUS7jnBK7hjnHw&#36;&=
#160;
&gt;&#32;&gt;&#32;&#32;
&gt;&#32;&gt;&#32;(53b3a77&#32;Merge&#32;6.1.1&#32;into&#32;android14-6.1)&=
#32;is&#32;the&#32;latest&#32;commit&#32;in
&gt;&#32;&gt;&#32;our
&gt;&#32;&gt;&#32;tree.
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;Do&#32;you&#32;have&#32;any&#32;private&#32;MTE-=
related&#32;changes&#32;in&#32;the&#32;kernel&#63;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;No,&#32;all&#32;the&#32;MTE-related&#32;code&#32;is&#32;t=
he&#32;same&#32;as&#32;Android&#32;Common&#32;Kernel.
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;&gt;&#32;Do&#32;you&#32;have&#32;userspace&#32;MTE&#32;en=
abled&#63;
&gt;&#32;&gt;&#32;
&gt;&#32;&gt;&#32;Yes,&#32;we&#32;have&#32;enabled&#32;MTE&#32;for&#32;both=
&#32;EL1&#32;and&#32;EL0.
&gt;&#32;
&gt;&#32;Hi&#32;Qun-wei,
&gt;&#32;
&gt;&#32;Thanks&#32;for&#32;the&#32;information.&#32;We&#32;encountered&#32=
;a&#32;similar&#32;issue&#32;internally
&gt;&#32;with&#32;the&#32;Android&#32;5.15&#32;common&#32;kernel.&#32;We&#3=
2;tracked&#32;it&#32;down&#32;to&#32;an&#32;issue
&gt;&#32;with&#32;page&#32;migration,&#32;where&#32;the&#32;source&#32;page=
&#32;was&#32;a&#32;userspace&#32;page&#32;with
&gt;&#32;MTE&#32;tags,&#32;and&#32;the&#32;target&#32;page&#32;was&#32;allo=
cated&#32;using&#32;KASAN&#32;(i.e.&#32;having
&gt;&#32;a&#32;non-zero&#32;KASAN&#32;tag).&#32;This&#32;caused&#32;tag&#32=
;check&#32;faults&#32;when&#32;the&#32;page&#32;was
&gt;&#32;subsequently&#32;accessed&#32;by&#32;the&#32;kernel&#32;as&#32;a&#=
32;result&#32;of&#32;the&#32;mismatching
&gt;&#32;tags
&gt;&#32;from&#32;userspace.&#32;Given&#32;the&#32;number&#32;of&#32;differ=
ent&#32;ways&#32;that&#32;page
&gt;&#32;migration
&gt;&#32;target&#32;pages&#32;can&#32;be&#32;allocated,&#32;the&#32;simples=
t&#32;fix&#32;that&#32;we&#32;could&#32;think
&gt;&#32;of
&gt;&#32;was&#32;to&#32;synchronize&#32;the&#32;KASAN&#32;tag&#32;in&#32;co=
py_highpage().
&gt;&#32;
&gt;&#32;Can&#32;you&#32;try&#32;the&#32;patch&#32;below&#32;and&#32;let&#3=
2;us&#32;know&#32;whether&#32;it&#32;fixes&#32;the
&gt;&#32;issue&#63;
&gt;&#32;
&gt;&#32;diff&#32;--git&#32;a/arch/arm64/mm/copypage.c&#32;b/arch/arm64/mm/=
copypage.c
&gt;&#32;index&#32;24913271e898c..87ed38e9747bd&#32;100644
&gt;&#32;---&#32;a/arch/arm64/mm/copypage.c
&gt;&#32;+++&#32;b/arch/arm64/mm/copypage.c
&gt;&#32;@@&#32;-23,6&#32;+23,8&#32;@@&#32;void&#32;copy_highpage(struct&#3=
2;page&#32;*to,&#32;struct&#32;page
&gt;&#32;*from)
&gt;&#32;&#32;
&gt;&#32;&#32;if&#32;(system_supports_mte()&#32;&amp;&amp;&#32;test_bit(PG_=
mte_tagged,&#32;&amp;from-
&gt;&#32;&gt;flags))&#32;{
&gt;&#32;&#32;set_bit(PG_mte_tagged,&#32;&amp;to-&gt;flags);
&gt;&#32;+if&#32;(kasan_hw_tags_enabled())
&gt;&#32;+page_kasan_tag_set(to,&#32;page_kasan_tag(from));
&gt;&#32;&#32;mte_copy_page_tags(kto,&#32;kfrom);
&gt;&#32;&#32;}
&gt;&#32;&#32;}
&gt;&#32;

Thank&#32;you&#32;so&#32;much,&#32;this&#32;patch&#32;has&#32;solved&#32;th=
e&#32;problem.

&gt;&#32;Catalin,&#32;please&#32;let&#32;us&#32;know&#32;what&#32;you&#32;t=
hink&#32;of&#32;the&#32;patch&#32;above.&#32;It
&gt;&#32;effectively&#32;partially&#32;undoes&#32;commit&#32;20794545c146&#=
32;(&quot;arm64:&#32;kasan:
&gt;&#32;Revert
&gt;&#32;&quot;arm64:&#32;mte:&#32;reset&#32;the&#32;page&#32;tag&#32;in&#3=
2;page-&gt;flags&quot;&quot;),&#32;but&#32;this&#32;seems
&gt;&#32;okay
&gt;&#32;to&#32;me&#32;because&#32;the&#32;mentioned&#32;race&#32;condition=
&#32;shouldn&#39;t&#32;affect&#32;&quot;new&quot;
&gt;&#32;pages
&gt;&#32;such&#32;as&#32;those&#32;being&#32;used&#32;as&#32;migration&#32;=
targets.&#32;The&#32;smp_wmb()&#32;that&#32;was
&gt;&#32;there&#32;before&#32;doesn&#39;t&#32;seem&#32;necessary&#32;for&#3=
2;the&#32;same&#32;reason.
&gt;&#32;
&gt;&#32;If&#32;the&#32;patch&#32;is&#32;okay,&#32;we&#32;should&#32;apply&=
#32;it&#32;to&#32;the&#32;6.1&#32;stable&#32;kernel.
&gt;&#32;The
&gt;&#32;problem&#32;appears&#32;to&#32;be&#32;&quot;fixed&quot;&#32;in&#32=
;the&#32;mainline&#32;kernel&#32;because&#32;of
&gt;&#32;a&#32;bad&#32;merge&#32;conflict&#32;resolution&#32;on&#32;my&#32;=
part;&#32;when&#32;I&#32;rebased&#32;commit
&gt;&#32;e059853d14ca&#32;(&quot;arm64:&#32;mte:&#32;Fix/clarify&#32;the&#3=
2;PG_mte_tagged&#32;semantics&quot;)
&gt;&#32;past&#32;commit&#32;20794545c146,&#32;it&#32;looks&#32;like&#32;I&=
#32;accidentally&#32;brought&#32;back
&gt;&#32;the
&gt;&#32;page_kasan_tag_reset()&#32;line&#32;removed&#32;in&#32;the&#32;lat=
ter.&#32;But&#32;we&#32;should
&gt;&#32;align
&gt;&#32;the&#32;mainline&#32;kernel&#32;with&#32;whatever&#32;we&#32;decid=
e&#32;to&#32;do&#32;on&#32;6.1.
&gt;&#32;
&gt;&#32;Peter


</pre><!--type:text--><!--{--><pre>************* MEDIATEK Confidentiality N=
otice ********************
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
om/d/msgid/kasan-dev/fca211403447d116be62f494c42e7554f869e389.camel%40media=
tek.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/fca211403447d116be62f494c42e7554f869e389.camel%40mediatek.=
com</a>.<br />

--__=_Part_Boundary_004_1524195472.1592563418
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Thu, 2023-02-09 at 22:19 -0800, Peter Collingbourne wrote:
> On Wed, Feb 08, 2023 at 05:41:45AM +0000, Qun-wei Lin (=E6=9E=97=E7=BE=A4=
=E5=B4=B4) wrote:
> > On Fri, 2023-02-03 at 18:51 +0100, Andrey Konovalov wrote:
> > > On Fri, Feb 3, 2023 at 4:41 AM Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=
=A9=8E)
> > > <Kuan-Ying.Lee@mediatek.com> wrote:
> > > >=20
> > > > > Hi Kuan-Ying,
> > > > >=20
> > > > > There recently was a similar crash due to incorrectly
> > > > > implemented
> > > > > sampling.
> > > > >=20
> > > > > Do you have the following patch in your tree?
> > > > >=20
> > > > >=20
> > > >=20
> > > >=20
> >=20
> >=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/9f7f5a25f335e6e1484695da9180281a728db7e2__;Kw!!CTRNKA9wMg0ARbw!hUjRlXirPM=
SusdIWe0RIPt0PNqIHYDCJyd7GSd4o-TgLMP0CKRUkjElH-jcvtaz42-sgE2U58964rCCbuNTJE=
5Jx$
> > > > >=20
> > > > >=20
> > > > > If not, please sync your 6.1 tree with the Android common
> > > > > kernel.
> > > > > Hopefully this will fix the issue.
> > > > >=20
> > > > > Thanks!
> > > >=20
> > > > Hi Andrey,
> > > >=20
> > > > Thanks for your advice.
> > > >=20
> > > > I saw this patch is to fix ("kasan: allow sampling page_alloc
> > > > allocations for HW_TAGS").
> > > >=20
> > > > But our 6.1 tree doesn't have following two commits now.
> > > > ("FROMGIT: kasan: allow sampling page_alloc allocations for
> > > > HW_TAGS")
> > > > (FROMLIST: kasan: reset page tags properly with sampling)
> > >=20
> > > Hi Kuan-Ying,
> > >=20
> >=20
> > Hi Andrey,
> > I'll stand in for Kuan-Ying as he's out of office.
> > Thanks for your help!
> >=20
> > > Just to clarify: these two patches were applied twice: once here
> > > on
> > > Jan 13:
> > >=20
> > >=20
> >=20
> >=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/a2a9e34d164e90fc08d35fd097a164b9101d72ef__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745_3oO-=
3k$
> > =20
> > > =20
> > >=20
> >=20
> >=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/435e2a6a6c8ba8d0eb55f9aaade53e7a3957322b__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745sDEOY=
WY$
> > =20
> > > =20
> > >=20
> >=20
> > Our codebase does not contain these two patches.
> >=20
> > > but then reverted here on Jan 20:
> > >=20
> > >=20
> >=20
> >=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/5503dbe454478fe54b9cac3fc52d4477f52efdc9__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745Bl77d=
FY$
> > =20
> > > =20
> > >=20
> >=20
> >=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/4573a3cf7e18735a477845426238d46d96426bb6__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmunR=
cQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745K-J8O=
-w$
> > =20
> > > =20
> > >=20
> > > And then once again via the link I sent before together with a
> > > fix on
> > > Jan 25.
> > >=20
> > > It might be that you still have to former two patches in your
> > > tree if
> > > you synced it before the revert.
> > >=20
> > > However, if this is not the case:
> > >=20
> > > Which 6.1 commit is your tree based on?
> >=20
> >=20
> >=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/53b3a7721b7aec74d8fa2ee55c2480044cc7c1b8__;Kw!!CTRNKA9wMg0ARbw!iEzuh9LYXl=
wXkpcWaHjncfr6lNgTky7OEAEzQ7cIFjlTD__7lwXqAhPJwWJXEnD8THUS7jnBK7hjnHw$=C2=
=A0
> > =20
> > (53b3a77 Merge 6.1.1 into android14-6.1) is the latest commit in
> > our
> > tree.
> >=20
> > > Do you have any private MTE-related changes in the kernel?
> >=20
> > No, all the MTE-related code is the same as Android Common Kernel.
> >=20
> > > Do you have userspace MTE enabled?
> >=20
> > Yes, we have enabled MTE for both EL1 and EL0.
>=20
> Hi Qun-wei,
>=20
> Thanks for the information. We encountered a similar issue internally
> with the Android 5.15 common kernel. We tracked it down to an issue
> with page migration, where the source page was a userspace page with
> MTE tags, and the target page was allocated using KASAN (i.e. having
> a non-zero KASAN tag). This caused tag check faults when the page was
> subsequently accessed by the kernel as a result of the mismatching
> tags
> from userspace. Given the number of different ways that page
> migration
> target pages can be allocated, the simplest fix that we could think
> of
> was to synchronize the KASAN tag in copy_highpage().
>=20
> Can you try the patch below and let us know whether it fixes the
> issue?
>=20
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index 24913271e898c..87ed38e9747bd 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -23,6 +23,8 @@ void copy_highpage(struct page *to, struct page
> *from)
> =20
>  	if (system_supports_mte() && test_bit(PG_mte_tagged, &from-
> >flags)) {
>  		set_bit(PG_mte_tagged, &to->flags);
> +		if (kasan_hw_tags_enabled())
> +			page_kasan_tag_set(to, page_kasan_tag(from));
>  		mte_copy_page_tags(kto, kfrom);
>  	}
>  }
>=20

Thank you so much, this patch has solved the problem.

> Catalin, please let us know what you think of the patch above. It
> effectively partially undoes commit 20794545c146 ("arm64: kasan:
> Revert
> "arm64: mte: reset the page tag in page->flags""), but this seems
> okay
> to me because the mentioned race condition shouldn't affect "new"
> pages
> such as those being used as migration targets. The smp_wmb() that was
> there before doesn't seem necessary for the same reason.
>=20
> If the patch is okay, we should apply it to the 6.1 stable kernel.
> The
> problem appears to be "fixed" in the mainline kernel because of
> a bad merge conflict resolution on my part; when I rebased commit
> e059853d14ca ("arm64: mte: Fix/clarify the PG_mte_tagged semantics")
> past commit 20794545c146, it looks like I accidentally brought back
> the
> page_kasan_tag_reset() line removed in the latter. But we should
> align
> the mainline kernel with whatever we decide to do on 6.1.
>=20
> Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fca211403447d116be62f494c42e7554f869e389.camel%40mediatek.com.

--__=_Part_Boundary_004_1524195472.1592563418--

