Return-Path: <kasan-dev+bncBC3JHBGJ7UFBBY6AYW3QMGQEX5WOQ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 48DFC97EB90
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 14:34:46 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6c3554020afsf65992876d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 05:34:46 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727094884; x=1727699684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tUUMPMxw4PkUezC1iBP3eYU8S63154r3md5xMOJIrf0=;
        b=GMfqfrLGVF2fb+EVli8LX46vpTmMc+g/jum/C5mzFEsYpPpbtELhb0XbFxgjZ/Y4B3
         PLpj+n1H4iACr2Iqi9nn6QFIaMTSWamKEj6nNxOTlFkDabx5D9b9LKmacsTX78znjDkf
         sS6hColKObyi9jCAHLwipDYzN59RQdi74ohIaz1Dg+M42IL8or4wC6YtpzQwqykzOngx
         dEOiRvDGbXiy5EpcVsj6ViKVBM3OCLjvDX6u8dUGcFb8pHbWrgnWtSHQ+Sxz2VBfxWUb
         EY27PQFMlHFuxI14X8DCnDm14x/aosv3jPZnFZzI965s7jTHDPcUlp+DgLwEW2W5C/B4
         DksA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727094884; x=1727699684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=tUUMPMxw4PkUezC1iBP3eYU8S63154r3md5xMOJIrf0=;
        b=bYqeWZoaMQxmh9pDiRBJUz+7pQpqqWrJTvSEaHg/o/4ydMjCvini86vySoFRxLAXmJ
         Ix/HGmff3vqur/Uz/gsYESD3LBgBTURgEkD6yKt+ohLQY/8KG9s9bfOPGVd1yqVcJAVj
         b2VuMtUnuLGyQ5PRvqY4kGf+OVZaU5qBQxjsbTazcSIaOOqH0ewQO6AKdOWucuhohtCD
         j/uXeeI6EECpajVhTRvaPj7f4XmejxmZbUyH06d0VfXnGE5/r3BWl6i/kZTPfr5TPPXe
         +qdYeiIiK8+VYPpGpCXkUhBL87etR/nCCXGdvhQjyq1P+qXrCBMXQl6sSf68mn6PbAU9
         dXAQ==
X-Forwarded-Encrypted: i=2; AJvYcCX0VAPy9R7wKlZzw9yLeXXCvyx1QPBu207ujClZr/9GKrGYeHJrrEJXUwT/GLw1ou4xIz6C5A==@lfdr.de
X-Gm-Message-State: AOJu0YwyQJQZn3DbVqOBFJjBxBKOrb6Q67sWyBV4AdUfaEiks9FGsV8L
	doXlYrmCO6fy6+Q/CfeOY8lXXV1jF7KA3lz+mWMyW/y/axcF/1ri
X-Google-Smtp-Source: AGHT+IFQc3bdeWtqSmIxpY35KbZmGyjy3uVZD6omVGdxAw1bTdKJPTeheQKIig53x8Hr4dv/Oip27A==
X-Received: by 2002:a05:6214:4199:b0:6c3:69be:a3e with SMTP id 6a1803df08f44-6c7bc7e844cmr130550206d6.43.1727094883958;
        Mon, 23 Sep 2024 05:34:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5f08:0:b0:6c3:62ce:cbb9 with SMTP id 6a1803df08f44-6c6823b2e4fls16086796d6.0.-pod-prod-01-us;
 Mon, 23 Sep 2024 05:34:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3+z0EEhADKssHW8Fbl8LXcO3n0GDZA06L/H4LbS+8LdkaRI2CARUNtptFlUC2TeI5JXHXRbs45J8=@googlegroups.com
X-Received: by 2002:a05:6102:26c9:b0:49b:cfe3:a303 with SMTP id ada2fe7eead31-49fc7561a5emr9294547137.9.1727094883213;
        Mon, 23 Sep 2024 05:34:43 -0700 (PDT)
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4a0f234ce70si156449137.1.2024.09.23.05.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Sep 2024 05:34:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dengjun.su@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 31503f0479a811efb66947d174671e26-20240923
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.41,REQID:0a3231e0-21db-438c-83d6-d4c7aa7ff530,IP:0,U
	RL:0,TC:-9,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:-9
X-CID-META: VersionHash:6dc6a47,CLOUDID:05811d18-b42d-49a6-94d2-a75fa0df01d2,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:1,Content:0,EDM:-3,IP:nil,URL
	:1,File:nil,RT:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SP
	R:NO,DKR:0,DKP:0,BRR:0,BRE:0,ARC:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_ULS
X-UUID: 31503f0479a811efb66947d174671e26-20240923
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <dengjun.su@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1854287887; Mon, 23 Sep 2024 20:34:36 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 MTKMBS14N1.mediatek.inc (172.21.101.75) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Mon, 23 Sep 2024 20:34:33 +0800
Received: from APC01-TYZ-obe.outbound.protection.outlook.com (172.21.101.237)
 by mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Mon, 23 Sep 2024 20:34:33 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yHMY5Uk0jHgXpgnkxTSoIrN2EN30o/ERVxGzx+1OpgZVkx6N3icPczG/aZlVeiLvnsDqZr1OkK5i4iaKPNIdgoJl3ezeIUTKxzG1TttmSkyVQjYrEakig2n5p5PUDxNi2BmihGKfm4ygwDLGhiKlbiNXXY/m49X+csU7BetEBE0Ik9/lSm6Vv7MYCPkT/O+BpjGNuVD00TtiO7qqdAqrkiQ+u+pRXB0D4auiQHxslp1D1yq96OOYu3rXV1sZT0S51xji8nLN3rXUiZKX96VHN/rxFMGfhIN6nY28ylpzenKoOqJgka9TSzj3IVcoVxxr9fHmcBo03uB6nJZuLDI0Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=GQ5GqusOoeq903teCJPlmuPnxrKdL5N43yPdgPkxlkk=;
 b=L7GUIAW42BDB2zCx5SeA1rurQ0y+nXrEdqdH1r2QAOw0piMtzGP7AgOi4lUxPnGZxCSNnyZsucpyCH8qwf6fmuNJHHqR7cDJG85SDLXL1oYop/yk5gjSO+ljMmrO35odcxsXixEpC6YNcT6nYPc6wzJESmO03VeMnF8/raTL1gmyT0db2OEfJxGNkS9ePq8xuLlWUM4CdsRblcmUVDqmmpEXimceFzox+OSJHf1M318e+R+gKLNqwdMVbC8RtUeRtaxWkEsTL4a7hWQaZ41vpUYPZYsPA6g75erK573Gs+6EymnP/aKdxcD8NQAKVj1+oBlDsCUo7snF8impDHFVOg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from KL1PR03MB7055.apcprd03.prod.outlook.com (2603:1096:820:dd::15)
 by TYSPR03MB8589.apcprd03.prod.outlook.com (2603:1096:405:8a::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7982.25; Mon, 23 Sep
 2024 12:34:30 +0000
Received: from KL1PR03MB7055.apcprd03.prod.outlook.com
 ([fe80::6dbe:fcda:31ae:d583]) by KL1PR03MB7055.apcprd03.prod.outlook.com
 ([fe80::6dbe:fcda:31ae:d583%6]) with mapi id 15.20.7982.022; Mon, 23 Sep 2024
 12:34:30 +0000
From: =?UTF-8?B?J0RlbmdqdW4gU3UgKOiLj+mCk+WGmyknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "vincenzo.frascino@arm.com"
	<vincenzo.frascino@arm.com>, "glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
CC: =?gb2312?B?SGFpcWlhbmcgR29uZyAouai6o8e/KQ==?=
	<Haiqiang.Gong@mediatek.com>, =?gb2312?B?SGVhdmVuIFpoYW5nICjVxcPIKQ==?=
	<Heaven.Zhang@mediatek.com>, =?gb2312?B?TWlrZSBaaGFuZyAo1cXOsM6wKQ==?=
	<Mike.Zhang@mediatek.com>
Subject: [BUG] Kernel panic when using Gerenic KASAN on kernel 6.6.30
Thread-Topic: [BUG] Kernel panic when using Gerenic KASAN on kernel 6.6.30
Thread-Index: AdsNtIHVzlAgtFydTAWnRfy+S9M1xw==
Date: Mon, 23 Sep 2024 12:34:30 +0000
Message-ID: <KL1PR03MB7055D61840DA5252B532D6C3FA6F2@KL1PR03MB7055.apcprd03.prod.outlook.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-dg-ref: PG1ldGE+PGF0IG5tPSJib2R5Lmh0bWwiIHA9ImM6XHVzZXJzXG10azI1MDU5XGFwcGRhdGFccm9hbWluZ1wwOWQ4NDliNi0zMmQzLTRhNDAtODVlZS02Yjg0YmEyOWUzNWJcbXNnc1xtc2ctMmNkM2RmOTQtNzlhOC0xMWVmLWI3NDgtZDhiYmMxZWM2MTIwXGFtZS10ZXN0XDJjZDNkZjk1LTc5YTgtMTFlZi1iNzQ4LWQ4YmJjMWVjNjEyMGJvZHkuaHRtbCIgc3o9IjIxNTM0IiB0PSIxMzM3MTU2ODQ2OTYwMTQ1MzEiIGg9InhQdVZ6SERGOWRyRU9oc09KVWxGUE04aWd0ND0iIGlkPSIiIGJsPSIwIiBibz0iMSIvPjwvbWV0YT4=
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: KL1PR03MB7055:EE_|TYSPR03MB8589:EE_
x-ms-office365-filtering-correlation-id: a9ab9a19-b03d-4cef-1024-08dcdbcc1242
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230040|376014|366016|1800799024|38070700018;
x-microsoft-antispam-message-info: =?gb2312?B?RGg3bG1vemE0MjYwbWwwOWVpS1lBSXFGM1k5OGwyUzZPVDZNYXFlZWgvWkJD?=
 =?gb2312?B?eVdiRU9ML3JodTNVbDJiMWd2b0RXVEtyWlpyMGYvUDZHaHdGRHZuZXlZL0Js?=
 =?gb2312?B?ZlFpUW9qWVh3d2VCbzhHWUw3azl1TmJFeFAvN0hOS25RT0t5TUVHZnpKcDBk?=
 =?gb2312?B?SmlmN284QzNLNjh1bHBZMmtIS2tLMmd3Z0lheERVb0tvZ0ROM25tb25JNlpo?=
 =?gb2312?B?c08vZ3VpNzczVis4elJXRnJpVjV5S1hzVUhXRmdNNXpmekEwcmdxaGVVdysz?=
 =?gb2312?B?OTIzU1FNdkpFK1Z0SjdXWU5oWTh2MDJlYkFlNnRNbGxVNnhsQmNaajhLNjg5?=
 =?gb2312?B?bWdETnJxRS83cmV1a1dESU9paTR4cnRpS0pCaXNuT2NvRGZPQnE4THFmYkha?=
 =?gb2312?B?L3RjWDhvenU5ZW1QRFN4QW0wOFRCdXdFbXNMdEFvVUtVWlpPL0JRUVVHQmhC?=
 =?gb2312?B?Y0xTSTJzNzFtbzRtMkErWExOL1lHU1kwcEt2bllFZ1ZtOTJEeGhnNkptb29r?=
 =?gb2312?B?Y01rdHJpUElUVi9LekRVZnp2VWhkZ1M3eWtrcjJHdGxaYTBGOFJEbWxxVW0w?=
 =?gb2312?B?bFhmZUwzZ0FrdnZiN1ZmV0ZHNys5MU1rdVVhNktRQkxqVDh0bytkcFlDTjAr?=
 =?gb2312?B?SDdkT29qcURBTmhEWFdxWktXbjN1dmRGaWwyd1kwL1hOVnYxaVh2S3J5NzhT?=
 =?gb2312?B?b2VVVkdCazIzT2RnKzhQaTROODdjK0Q0czFvVk02V2o4UXFSWllma0ZWZ2dL?=
 =?gb2312?B?czhMZHYzbllRRkhGVWwrNUR1ejdrZ0dQMXdzZmIrUjUxSW5saDlrVTdYeXRI?=
 =?gb2312?B?QWFDM1NUMytyUXdtaGpCRnUxS2lqc0tpVFhZaU5TT2lkSitTNzJsd1ZlV1BE?=
 =?gb2312?B?ZlU3d2ZKVDUvc2FnOGdwTzF5RDhMeEJVZG42TU1EeVNGYUFkVTVsbC9MY24z?=
 =?gb2312?B?OTFhVDFjVFlTNHJlQWVFZVJUY2ZYQTExbm82YkhxUUlvaTFKSzJWYU1mQ3No?=
 =?gb2312?B?d2I0d29kbDlYT25FZzlGeVgzRnFtblJjZDQxb1FTeWtRM203Kzd6K0dJVldJ?=
 =?gb2312?B?c1Y3Wm0vVGZxRXRSY2RYZERoYUIycnBlU1dMeGQwVi9BU1pOV2t2RzRHSDJm?=
 =?gb2312?B?a1BWbXJRRDNZbWFDUlVDYVI0SmNCcmE4L3FWU1hQVHYxeS9URlV4Qk1ZZUFy?=
 =?gb2312?B?YzdrQ2dIV0lQNmROZWZkYWhybUZuc1N6YXlWOHgvblQvcmFPblNKQ2lKK1Qv?=
 =?gb2312?B?cGw4ZjFsOTlHeHZKRWRSN3hlUXVFRzZpQklFbDdRYUg2aDh4YW5tMG02QkV5?=
 =?gb2312?B?bks4R0dKdUNtaDU0UUlZQStTbTN6bVBQbC9kcHJJekdmR0tlQnpoT2dSdGUv?=
 =?gb2312?B?YzdxVXMwSEVUejIvMzBYM3RjeE54bWtTZ1FRZUVEQzRpdExBTFc1cEhWUmVD?=
 =?gb2312?B?NzdIUXJ5Z1ZtekZNeVlOb0M4THhWYXVXdGI2czlOditnbmF4K21oUUJucEU0?=
 =?gb2312?B?M0F0blFkVWJXZ0U2Vk9sUnFPV2k5MFJEM0FNVjJNWTByMGc0MjI3c2JVUE9M?=
 =?gb2312?B?NVBFVWkrM3RoUVpJNzlKZW56elFMNmQrRU94WmtrcWVjRngzTGNvNWNJZ0Q0?=
 =?gb2312?B?ZGRsT01NbHAzbmc4UnJMVVdQemhmZ1JvdEE4NmI5UWFRaXZlSmJ2YTVNeWh6?=
 =?gb2312?B?ZU9RTUpWZEVJUGJzc0dhYjNuY2VGNXNRMHJocWN4SUtvOGsxYVRtQmZYQlJB?=
 =?gb2312?B?UndmWml3MUxINVM0YXJKcXhuSlRYSXB5cDh1bXBxVGhHRi9RWFN5aHNnRDZa?=
 =?gb2312?Q?jHD2JCpE6teqJVak0mmjcLuESDLA/Y9WyjBRQ=3D?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:zh-cn;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:KL1PR03MB7055.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024)(38070700018);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?gb2312?B?TElrSnJ2Q1pIemQ4WTRkRXRuMzdRVWtkd01tNVQrbVNLVmdCcWZlTERaZU5m?=
 =?gb2312?B?bEV6WDFtQmYzcFRYVGZ6VDN4UG1YZDNvV21WbzZxT0gvMVQ2NWhGcXBPMjdY?=
 =?gb2312?B?d251a09IUzZhTEtiTUlCbXF6dG5TNHNpUWZ5UXNhKy8xdXZEMXRFRnRUTUor?=
 =?gb2312?B?TVRXTVBOVldmeS9xY3piUXVVR01XKzdjM1JIR3JFeGJyUUJqL1BUcjJTakdQ?=
 =?gb2312?B?MmEwZU1hRlF1ME45dDJmd3RUckVlVU5vTkJ6YVJySVlJTVpXMCtHbmQzczIw?=
 =?gb2312?B?WHhBdk1SeHB2STJQcWZVZmNGSTlRbW1uWjh6cXlzQnlnTkJYNE1CT3NUT21Q?=
 =?gb2312?B?OEdIS2ZyNGVQUDNObVExY0syVk9Qd2hTR0VVcHNKejlkRldXUlZYUmVtY3l2?=
 =?gb2312?B?N2RWYkh4bkREeUNlZkxmVHB6ZVBSQkRna1V6YnRERkNPdEtSeHF4Sk5PRkg3?=
 =?gb2312?B?Slp2VDh0d2RxQjFkWjZNQ0pGTWI4SEtrVlJWZjRaM095NFMxTWxFWkFPODcy?=
 =?gb2312?B?d3VISGk4VVpWSy9sVTRrcjVQMXhQZFJkVU0rdzA2ZFNPT1lSNVFoUTJFMHFJ?=
 =?gb2312?B?c2dCVW9ibVBHZ2prVFdVc0FDelZzdHpETHhzVDZGblZRUDNjYlF0R2tRdzN1?=
 =?gb2312?B?ZHNzSmVneEdDQVpZdkV6SzcweWNnUWJ0UHNEZXEzN1BsMUFRa3ZGeXd0RWRa?=
 =?gb2312?B?d3FseFJRWHFtU3NadVdVdUlhUU1WcWpLS1ZlaFU3S0hpREQ0V05rVUljSjNU?=
 =?gb2312?B?U2l3UjVJdTNlbXhVUDh3TWxCS1N5NUpoNTRiYlJnWkhjWmEzZFpzQVlUUmFP?=
 =?gb2312?B?OStCTGk2TUI2QzNkdVVCb2VTSUZRUWlQbEFJT05qeG52Q0F5VmtXQThLcC9L?=
 =?gb2312?B?aTk5V1drRHA1SEIxRkNXWWlsM3dLL0s4RFdkYXFLV2pXS0d2T0F6amE3cVht?=
 =?gb2312?B?Z3pKdGdia21sdVNYcFZSUFNHMDRJc0lOV09RWFZKam9yMUtKUE5KMkoxWjJ1?=
 =?gb2312?B?T2FJTklwMVBOdGo5OGg2WTJQZytadmEwbW5qazdGZkx2dnV3MlRLb1E1bXlF?=
 =?gb2312?B?T3VwSHM3ZEgyZzV0SkVyc2Y5VkNDK0xYR0VDeitIb2tsak1QbTFSb0FWWXc5?=
 =?gb2312?B?cDZYMlJ2NENWbEFhdlIwbytoeUlQbDhQakY0dDFka2JGa0ovVi9XQ3U0ZG5i?=
 =?gb2312?B?VExmOHNDZ0RkZTY1Y2V6UUxZQ1o4WUJNQWxROXFyK0s0SmlBODlTZFhUN2hR?=
 =?gb2312?B?Nkh0MGwweSt6ZmVnalpqdkpWS0dPa21aT3VNRDJoN1ZwL3RpOFRXWTc2eWRT?=
 =?gb2312?B?UFhPVGhkODFkVGVwL2piVlZaNm9SazZtRjBhTWtPUUdFVyt4dWVCWW9pY2hl?=
 =?gb2312?B?MVlQYXV6M1llbXRTYkx3Wkl4NDhrZzZoYmRWbis2STQzbU1KNThxMXpMeDVS?=
 =?gb2312?B?ZXZmOWJSOXBleFVSYTRVL0tHMFExMjNJWGY5NUNJNkV0ZllvNW5VcWxDdkNi?=
 =?gb2312?B?UEdsNVViVU1ZTW13MmptRXBxZTh5MTdtQTVXanVGVkRyU2ZDUEhPOStxMEts?=
 =?gb2312?B?aDA1NE1SVTluNjU0ODJTVGN3WjdaM2dZQ2hJSXE0SG0rTHg5VG5SOFozV3RR?=
 =?gb2312?B?VG9mOS8xMmlUT2Y4VEEvOUQ4ZkU0SUs0LzNTN3RUWE1oWXp2UHRyRGR6RG0w?=
 =?gb2312?B?ckZoUEJ0RldIanBqVmpJMWRvcCsxVFptN3hpVU42OVgwZXRhMi95SVBZZjND?=
 =?gb2312?B?RTZlcndHMHpDbzd0ZkpNMkJNcHJ3c1hMZFEzRWhpMmdJWmVjTXpOUnE5ckY3?=
 =?gb2312?B?WGJ0N2NMeVdIYVNjQjNaa0dOd2FRZTBuSmFZM1ZTZG1VKzMwRUdKN0ZxUDM4?=
 =?gb2312?B?ajZ4MkpDM1VmWG44VG9lNE9rb0NtMm5mZUQ1eHdYK2RqRk1McDVwMWxnN3Zo?=
 =?gb2312?B?QS9QcjFaVmtHNG9uUGtlNXFQMHJQR081Wlp3SFR1REp6L1pLU1ZBdGp5NDJ2?=
 =?gb2312?B?dk1tRnZVd29MYTNWVlNkVlF1MGpJYjROWFFFRlN5YTlFQmY0WnFmUTVmSHFs?=
 =?gb2312?B?NzJ5NU5pRUwyRkFXOEVyeTRESFU2b0FiT2JUYVNJVUUwTHRORHdCOXpLR3dR?=
 =?gb2312?Q?nZ+HOeGj3HUjV9iAEERrTIKcy?=
Content-Type: multipart/alternative;
	boundary="_000_KL1PR03MB7055D61840DA5252B532D6C3FA6F2KL1PR03MB7055apcp_"
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: KL1PR03MB7055.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a9ab9a19-b03d-4cef-1024-08dcdbcc1242
X-MS-Exchange-CrossTenant-originalarrivaltime: 23 Sep 2024 12:34:30.5823
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: Qh3i2rPeB0y/tSydtLoVGDscweZiBqF65tEyjsiAUujUHoNmX0+rasBmggkz4OyhOMIyxGYI7Jesb3R6jxOgqw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYSPR03MB8589
X-TM-AS-Product-Ver: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-AS-Result: No-10--22.734100-8.000000
X-TMASE-MatchedRID: rVdTBz1G77ajFnc4yUrqERlckvO1m+JcLPcgmI1EekuX4KtwQf+wEcEY
	HnJZxFh9HRsVEQ1vjjSjEOMaqr2DSUYFpocK2yt3yDp+jSvEtWtdymZBcuGGRHfc+QilBukYPZW
	zDGibn2egtbgqwar/QqOfwZ5d9btRaxXbwRJk57zN+qWlu2ZxaOj86Ng8AayKJLfQYoCQHFZxqa
	/P3zyVomF48SHEAMdo13EeR+aP9EEvA3Q+mqni9w5KPhGIg0MR0i/hFXziUdMlP1vFxquW9jySB
	MzALmMWdon9m81h+IZSTIrdw+LdCWmDdc8APp60kJi1wdeHFto+WWrj7s+yn2jliw+xvItdaqwI
	oaIdvpHcDXlRMTXBD/n27S56veM7kKjL2IOi2LAI8o+oRtTdk/ioIsi7Sa0gRoS5c9eVHmoyJXW
	I0QewufnI9ojh4UpHyvkBV2KfhrVHW+94FA8JF0K9qlwiTElf6r3HCixfuKcc4ri4RJV/1SWeOH
	ilL0WHP5mpBtPr/e4BZOsOGHKpoR6zMsc8JBv0W3yipes9rvKcd0oWZ9tJgxS11FlOYRoh8zGz6
	5yndkzuDNx+Tk7mC3URwB/xkHoU+ybY5Ha5C8lE8AQC7KOVrpdhffisWXfHKzMXWgba/W+FAf5i
	ylR8Wnb4Bm7FqQnLJ3vJqf6MlejmjGKFz5VaCWY0Io4Kxb86Dea88pmP/P6yy072phvASaPFjJE
	Fr+olkZ3jZ7ODxXyMgVQnEg1UaMC4UUZr4lSFSnQ4MjwaO9dfNjF5BHUO+wK778o2f0cOVmIxZK
	gY9x+h9lmS7WA9Iya/Cbgl+1Jyj71ujwrIxi8=
X-TM-AS-User-Approved-Sender: No
X-TM-AS-User-Blocked-Sender: No
X-TMASE-Result: 10--22.734100-8.000000
X-TMASE-Version: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-SNTS-SMTP: 6464B2734051393B43069F896E768B9521436853D81C33D012308711E35CA9C32000:8
X-Original-Sender: dengjun.su@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=RvgOXiQ9;       dkim=neutral
 (body hash did not verify) header.i=@mediateko365.onmicrosoft.com
 header.s=selector2-mediateko365-onmicrosoft-com header.b=LTGFwTcA;
       arc=fail (body hash mismatch);       spf=pass (google.com: domain of
 dengjun.su@mediatek.com designates 60.244.123.138 as permitted sender)
 smtp.mailfrom=dengjun.su@mediatek.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?gb2312?B?RGVuZ2p1biBTdSAoy9W1y778KQ==?= <Dengjun.Su@mediatek.com>
Reply-To: =?gb2312?B?RGVuZ2p1biBTdSAoy9W1y778KQ==?= <Dengjun.Su@mediatek.com>
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

--_000_KL1PR03MB7055D61840DA5252B532D6C3FA6F2KL1PR03MB7055apcp_
Content-Type: text/plain; charset="UTF-8"

Hi



I encountered a kernel panic after enable Generic KASAN on kernel version 6.6.30. Below are the details of the issue:



**Description:**

After enable CONFIG_KASAN_GENERIC. The system may crash during the bootup phase.



CONFIG_KASAN_SHADOW_OFFSET=0xdfffffc000000000

CONFIG_HAVE_ARCH_KASAN=y

CONFIG_HAVE_ARCH_KASAN_SW_TAGS=y

CONFIG_HAVE_ARCH_KASAN_HW_TAGS=y

CONFIG_HAVE_ARCH_KASAN_VMALLOC=y

CONFIG_CC_HAS_KASAN_GENERIC=y

CONFIG_CC_HAS_KASAN_SW_TAGS=y

CONFIG_KASAN=y

CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX=y

CONFIG_KASAN_GENERIC=y

# CONFIG_KASAN_SW_TAGS is not set

# CONFIG_KASAN_HW_TAGS is not set

# CONFIG_KASAN_OUTLINE is not set

CONFIG_KASAN_INLINE=y

CONFIG_KASAN_STACK=y

CONFIG_KASAN_VMALLOC=y

# CONFIG_KASAN_KUNIT_TEST is not set

# CONFIG_KASAN_MODULE_TEST is not set



**Environment:**

- Kernel version: 6.6.30

- Distribution: Yocto 5.0 64bit/Kernel 6.6.30 64bit ARM64



**Logs:**

```

page:000000009a6f4e33 refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x27db51

flags: 0x2000000000004000(reserved|zone=1)

page_type: 0xffffffff()

raw: 2000000000004000 fffffffe07f6d448 fffffffe07f6d448 0000000000000000

raw: 0000000000000000 0000000000000000 00000000ffffffff 0000000000000000

page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set

Workqueue: events do_free_init

Call trace:

  dump_backtrace+0xf8/0x174

  show_stack+0x18/0x24

  dump_stack_lvl+0x60/0x80

  dump_stack+0x18/0x24

  bad_page+0x188/0x1a8

  free_page_is_bad_rep

  dump_backtrace+0xf8/0x174

  show_stack+0x18/0x24

  dump_stack_lvl+0x60/0x80

  dump_stack+0x18/0x24

  panic+0x21c/0x570

  add_taint+0xc8/0xe0

  bad_page+0xb4/0x1a8

  free_page_is_bad_report+0xf8/0x170

  free_unref_page_prepare+0x524/0x5c8

  free_unref_page+0xcc/0x5ac

  __free_pages+0x11c/0x144

  free_pages+0x28/0x34

  kasan_depopulate_vmalloc_pte+0xb0/0x118

  __apply_to_page_range+0x474/0x598

  module_memfree+0x4c/0x78

```



**Some Experimental Results**

1. After disable KASLR. This problem will not be reproducible.

2. PFN is relatively fixed, and the corresponding PFN is marked as reserve state in kasan_init_shadow() through memblock_reserve().

3. The location where the crash occurs is fixed.



I found that other people had similar problems to mine, but I didn't find any follow-up solutions in the discussion about this part.

https://lore.kernel.org/linux-arm-kernel/20220428161254.GA182@qian/T/



I also found X86_64 will disable KASLR when CONFIG_KASAN is enable.

> /*

>  * Apply no randomization if KASLR was disabled at boot or if KASAN

>  * is enabled. KASAN shadow mappings rely on regions being PGD aligned.

>  */

> static inline bool kaslr_memory_enabled(void) {

>      return kaslr_enabled() && !IS_ENABLED(CONFIG_KASAN); }

Form the discuss with https://lore.kernel.org/lkml/CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDkrV1XxQ8_bw@mail.gmail.com/T/.

There have some problem in memory layout and it should have fixed. But this part of the logic has not changed in the latest kernel version.



Please let me know if you need any additional information or if there are any patches I can test.

Best Regards
Dengjun Su

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/KL1PR03MB7055D61840DA5252B532D6C3FA6F2%40KL1PR03MB7055.apcprd03.prod.outlook.com.

--_000_KL1PR03MB7055D61840DA5252B532D6C3FA6F2KL1PR03MB7055apcp_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html xmlns:v=3D"urn:schemas-microsoft-com:vml" xmlns:o=3D"urn:schemas-micr=
osoft-com:office:office" xmlns:w=3D"urn:schemas-microsoft-com:office:word" =
xmlns:m=3D"http://schemas.microsoft.com/office/2004/12/omml" xmlns=3D"http:=
//www.w3.org/TR/REC-html40">
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dgb2312">
<meta name=3D"Generator" content=3D"Microsoft Word 15 (filtered medium)">
<style><!--
/* Font Definitions */
@font-face
	{font-family:"Cambria Math";
	panose-1:2 4 5 3 5 4 6 3 2 4;}
@font-face
	{font-family:=E7=AD=89=E7=BA=BF;
	panose-1:2 1 6 0 3 1 1 1 1 1;}
@font-face
	{font-family:Calibri;
	panose-1:2 15 5 2 2 2 4 3 2 4;}
@font-face
	{font-family:"\@=E7=AD=89=E7=BA=BF";
	panose-1:2 1 6 0 3 1 1 1 1 1;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
	{margin:0cm;
	text-align:justify;
	text-justify:inter-ideograph;
	font-size:10.5pt;
	font-family:"Calibri",sans-serif;}
a:link, span.MsoHyperlink
	{mso-style-priority:99;
	color:#0563C1;
	text-decoration:underline;}
p.MsoPlainText, li.MsoPlainText, div.MsoPlainText
	{mso-style-priority:99;
	mso-style-link:"=E7=BA=AF=E6=96=87=E6=9C=AC =E5=AD=97=E7=AC=A6";
	margin:0cm;
	font-size:10.5pt;
	font-family:"Calibri",sans-serif;}
span.EmailStyle17
	{mso-style-type:personal-compose;
	font-family:"Calibri",sans-serif;
	color:windowtext;}
span.a
	{mso-style-name:"=E7=BA=AF=E6=96=87=E6=9C=AC =E5=AD=97=E7=AC=A6";
	mso-style-priority:99;
	mso-style-link:=E7=BA=AF=E6=96=87=E6=9C=AC;
	font-family:"Calibri",sans-serif;}
.MsoChpDefault
	{mso-style-type:export-only;
	font-family:"Calibri",sans-serif;
	mso-ligatures:none;}
.MsoPapDefault
	{mso-style-type:export-only;
	text-align:justify;
	text-justify:inter-ideograph;}
/* Page Definitions */
@page WordSection1
	{size:612.0pt 792.0pt;
	margin:72.0pt 90.0pt 72.0pt 90.0pt;}
div.WordSection1
	{page:WordSection1;}
--></style><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext=3D"edit" spidmax=3D"1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext=3D"edit">
<o:idmap v:ext=3D"edit" data=3D"1" />
</o:shapelayout></xml><![endif]-->
</head>
<body lang=3D"ZH-CN" link=3D"#0563C1" vlink=3D"#954F72" style=3D"word-wrap:=
break-word;text-justify-trim:punctuation">
<div class=3D"WordSection1">
<p class=3D"MsoPlainText"><span lang=3D"EN-US">Hi<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">I encountered a kernel panic=
 after enable Generic KASAN on kernel version 6.6.30. Below are the details=
 of the issue:<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">**Description:**<o:p></o:p><=
/span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">After enable CONFIG_KASAN_GE=
NERIC. The system may crash during the bootup phase.<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_KASAN_SHADOW_OFFSET=
=3D0xdfffffc000000000<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_HAVE_ARCH_KASAN=3Dy<o=
:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_HAVE_ARCH_KASAN_SW_TA=
GS=3Dy<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_HAVE_ARCH_KASAN_HW_TA=
GS=3Dy<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_HAVE_ARCH_KASAN_VMALL=
OC=3Dy<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_CC_HAS_KASAN_GENERIC=
=3Dy<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_CC_HAS_KASAN_SW_TAGS=
=3Dy<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_KASAN=3Dy<o:p></o:p><=
/span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_CC_HAS_KASAN_MEMINTRI=
NSIC_PREFIX=3Dy<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_KASAN_GENERIC=3Dy<o:p=
></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"># CONFIG_KASAN_SW_TAGS is no=
t set<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"># CONFIG_KASAN_HW_TAGS is no=
t set<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"># CONFIG_KASAN_OUTLINE is no=
t set<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_KASAN_INLINE=3Dy<o:p>=
</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_KASAN_STACK=3Dy<o:p><=
/o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">CONFIG_KASAN_VMALLOC=3Dy<o:p=
></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"># CONFIG_KASAN_KUNIT_TEST is=
 not set<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"># CONFIG_KASAN_MODULE_TEST i=
s not set<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">**Environment:**<o:p></o:p><=
/span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">- Kernel version: 6.6.30<o:p=
></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">- Distribution: Yocto 5.0 64=
bit/Kernel 6.6.30 64bit ARM64<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">**Logs:**<o:p></o:p></span><=
/p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">```<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">page:000000009a6f4e33 refcou=
nt:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x27db51<o:p></o:p><=
/span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">flags: 0x2000000000004000(re=
served|zone=3D1)<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">page_type: 0xffffffff()<o:p>=
</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">raw: 2000000000004000 ffffff=
fe07f6d448 fffffffe07f6d448 0000000000000000<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">raw: 0000000000000000 000000=
0000000000 00000000ffffffff 0000000000000000<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">page dumped because: PAGE_FL=
AGS_CHECK_AT_FREE flag(s) set<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">Workqueue: events do_free_in=
it<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">Call trace:<o:p></o:p></span=
></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; dump_backtrace+0xf8/0=
x174<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; show_stack+0x18/0x24<=
o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; dump_stack_lvl+0x60/0=
x80<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; dump_stack+0x18/0x24<=
o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; bad_page+0x188/0x1a8<=
o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; free_page_is_bad_rep<=
o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; dump_backtrace+0xf8/0=
x174<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; show_stack+0x18/0x24<=
o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; dump_stack_lvl+0x60/0=
x80<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; dump_stack+0x18/0x24<=
o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; panic+0x21c/0x570<o:p=
></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; add_taint+0xc8/0xe0<o=
:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; bad_page+0xb4/0x1a8<o=
:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; free_page_is_bad_repo=
rt+0xf8/0x170<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; free_unref_page_prepa=
re+0x524/0x5c8<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; free_unref_page+0xcc/=
0x5ac<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; __free_pages+0x11c/0x=
144<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; free_pages+0x28/0x34<=
o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; kasan_depopulate_vmal=
loc_pte+0xb0/0x118<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; __apply_to_page_range=
+0x474/0x598<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&nbsp; module_memfree+0x4c/0=
x78<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">```<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">**Some Experimental Results*=
*<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">1. After disable KASLR. This=
 problem will not be reproducible.<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">2. PFN is relatively fixed, =
and the corresponding PFN is marked as reserve state in kasan_init_shadow()=
 through memblock_reserve().<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">3. The location where the cr=
ash occurs is fixed.<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">I found that other people ha=
d similar problems to mine, but I didn't find any follow-up solutions in th=
e discussion about this part.<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><a href=3D"https://lore.kern=
el.org/linux-arm-kernel/20220428161254.GA182@qian/T/">https://lore.kernel.o=
rg/linux-arm-kernel/20220428161254.GA182@qian/T/</a><o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">I also found X86_64 will dis=
able KASLR when CONFIG_KASAN is enable.<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&gt; /*<o:p></o:p></span></p=
>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&gt;&nbsp; * Apply no random=
ization if KASLR was disabled at boot or if KASAN<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&gt;&nbsp; * is enabled. KAS=
AN shadow mappings rely on regions being PGD aligned.<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&gt;&nbsp; */<o:p></o:p></sp=
an></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&gt; static inline bool kasl=
r_memory_enabled(void) {<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">&gt; &nbsp;&nbsp;&nbsp;&nbsp=
; return kaslr_enabled() &amp;&amp; !IS_ENABLED(CONFIG_KASAN); }<o:p></o:p>=
</span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">Form the discuss with <a hre=
f=3D"https://lore.kernel.org/lkml/CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDk=
rV1XxQ8_bw@mail.gmail.com/T/">
https://lore.kernel.org/lkml/CAPAsAGyG2_sUfb7aPSPuMatMraDbPCFKxhv2kSDkrV1Xx=
Q8_bw@mail.gmail.com/T/</a>.
<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">There have some problem in m=
emory layout and it should have fixed. But this part of the logic has not c=
hanged in the latest kernel version.<o:p></o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoPlainText"><span lang=3D"EN-US">Please let me know if you ne=
ed any additional information or if there are any patches I can test.<o:p><=
/o:p></span></p>
<p class=3D"MsoNormal"><span lang=3D"EN-US"><o:p>&nbsp;</o:p></span></p>
<p class=3D"MsoNormal"><span lang=3D"EN-US">Best Regards<o:p></o:p></span><=
/p>
<p class=3D"MsoNormal"><span lang=3D"EN-US">Dengjun Su<o:p></o:p></span></p=
>
</div>
</body>
</html>
<!--type:text--><!--{--><pre>************* MEDIATEK Confidentiality Notice =
********************
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
om/d/msgid/kasan-dev/KL1PR03MB7055D61840DA5252B532D6C3FA6F2%40KL1PR03MB7055=
.apcprd03.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/KL1PR03MB7055D61840DA5252B532D6C3FA6F2%=
40KL1PR03MB7055.apcprd03.prod.outlook.com</a>.<br />

--_000_KL1PR03MB7055D61840DA5252B532D6C3FA6F2KL1PR03MB7055apcp_--

