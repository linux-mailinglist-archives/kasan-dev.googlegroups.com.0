Return-Path: <kasan-dev+bncBDBLXJ5LQYCBBNNV2WGAMGQELZVIZHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id E6EDB454E0D
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 20:40:39 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id f206-20020a6238d7000000b004a02dd7156bsf2224221pfa.5
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 11:40:39 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=R32sZrBG30PkxCLq0wfQOYMxwjIIu3mtjswd5n2C5x8=;
        b=I2LX8Pnt+XZDIuyeWBwRNksV4udvLReXke2k/Ba4ChzhpdSBpos1mYqCrGBzbf19P5
         1M6BY46qXnBSCO3M9StRV5PuZCMUCajoXVhFZuGYu+uh0/CDqj4ltJkw4dd8NT01MOV+
         sbY1X5iy3wgb0gJdUyIUgcNnngwKfkbR0rAVeTMf/nZkvH4SlLpbkHcJLq5BmAURnwt4
         yH+rKG1AoTyrLmbAbwR95IvDIi4ib0oXTraGFr2ih9140G54Dg10t+6xrZdJo5YlyU6z
         CRxyj7IVoAq4wlq2FF9251dv+cEWk1X4/fwpJ9SMt1fWL5mHOi6YWm5s2Iwz+BRn1Omq
         Lv1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:thread-topic:thread-index
         :date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R32sZrBG30PkxCLq0wfQOYMxwjIIu3mtjswd5n2C5x8=;
        b=YPLw1hPfIhlPpUmC+VDU+aO5J9d9x0/x9b+a9tHZhjjNB/QOlDEZF8weoQtazMgNlm
         pvqMOuEYSt0y1OyuYRX3KWURxh+UyW7gZ9/VD5ENyU3cEkZLO5w9pgcYbYozDRSPH8Qe
         R4shCzwPtnBx49RKhOQVPkdyW9zjbFaIOPw5mlYnAZvrWKgBiIx473LZVA6QtjbYO0hQ
         jOxf9T1U6yf7DM0uEkp0FS66g+T+T9jRL18vePBxf5Mv6kewCI2L2XL2z3BTYJTtB+Vz
         BoC+ecd7RiMtfutmWhF10Vv3aLoCX2UGtDwDct1Oc6s29alcSaOl14O+IiK4Xnf4zZWl
         s+Vg==
X-Gm-Message-State: AOAM531jmVyc+uzc7kCwxBTFo8DMDZU3z8BQm+0BSf4j8SRS/x/4dUqW
	iZMNDMwQmOup7WOK3n+Fecw=
X-Google-Smtp-Source: ABdhPJzX9v0ds3ZAgl7cPe4HFU9CNZvfPmXl8zXNVrq9cFLB2VmIfq8scWKGI3TnBSrYN+c1JnJ4mA==
X-Received: by 2002:a63:9142:: with SMTP id l63mr7092271pge.384.1637178037306;
        Wed, 17 Nov 2021 11:40:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d50e:: with SMTP id b14ls487984plg.7.gmail; Wed, 17
 Nov 2021 11:40:36 -0800 (PST)
X-Received: by 2002:a17:90a:ba13:: with SMTP id s19mr2685233pjr.62.1637178036635;
        Wed, 17 Nov 2021 11:40:36 -0800 (PST)
Received: from mx0a-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id l11si65794pfc.4.2021.11.17.11.40.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Nov 2021 11:40:36 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=0955d447e6=terrelln@fb.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0089730.ppops.net [127.0.0.1])
	by m0089730.ppops.net (8.16.1.2/8.16.1.2) with SMTP id 1AHJdtFC004740;
	Wed, 17 Nov 2021 11:40:06 -0800
Received: from mail.thefacebook.com ([163.114.132.120])
	by m0089730.ppops.net with ESMTP id 3cd1gnk610-8
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Wed, 17 Nov 2021 11:40:06 -0800
Received: from NAM04-MW2-obe.outbound.protection.outlook.com (100.104.98.9) by
 o365-in.thefacebook.com (100.104.94.228) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.14; Wed, 17 Nov 2021 11:39:42 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=ZwAtCzQvlWT1q771Tk8COUSY2XcUVGfgr72yr+Z6xPbFVpb8UJoT3DY7anfi+cTbUN+5TlpziTdzfY280xnk31qbL1peJc0nf53NgyyvaFjaDoLEoeG/GcL46uKMyFfWxSr4hYE4scBmVIjLU2XqCCN1TWyIRRok3iN646GBx2dyOkowjbpKe9M1vgYVo3MHe5tz6FOgJd6wWviWjvRV/vFBKhWutZfdNnFjXcNYz7eAUK0WzNK9m4DN/t5QGGs1O2qH4XzsHmfiOtmBPKgjQyvkyVCe5OMqoCdluEh60eUreQ6x4fZIEotBOILuBiGsnbLeJK8xUsi3HokhOgTGZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=wfjcIKT7XzV6Dvjzx+Gs0kgXvkD5gJKAPj82OBOJV8Q=;
 b=Bw8fZ+Bpauq8ZyldPqlyS7E+87z+S0rcy0O5DwDMfZiRu9RhHlw8GX5qdzcGt1dLJyEgBzF1EYxAZyDEfPzChBcc6QlItjwN6awAdshUEs6mqAxswbcnmKcpMwTQDHe+6qDKh2V4w2LOVE99oSV7Efl4BF6KU0PrHzKqk4TTuSiTcmbEC0Dk5M8MpzJG15UTyiBuYr6QWW5DP6HLMNWbq9mHplp36Yn7eY3s4CMQl0rjnlPO3YpKU9KAx8zAO7sVGqAqioLT04U/3JcPpg4fBNC+iqUyfcNXch6h/ZD2ZiPnDJf/uczI+TJKJoj13KQFyTR1Vytx7oRH9MStS+prIw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=fb.com; dmarc=pass action=none header.from=fb.com; dkim=pass
 header.d=fb.com; arc=none
Received: from BY5PR15MB3667.namprd15.prod.outlook.com (2603:10b6:a03:1f9::18)
 by BYAPR15MB2693.namprd15.prod.outlook.com (2603:10b6:a03:155::30) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4690.27; Wed, 17 Nov
 2021 19:39:41 +0000
Received: from BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4]) by BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4%6]) with mapi id 15.20.4690.027; Wed, 17 Nov 2021
 19:39:40 +0000
From: "'Nick Terrell' via kasan-dev" <kasan-dev@googlegroups.com>
To: Helge Deller <deller@gmx.de>
CC: Randy Dunlap <rdunlap@infradead.org>,
        Geert Uytterhoeven
	<geert@linux-m68k.org>,
        Linux Kernel Mailing List
	<linux-kernel@vger.kernel.org>,
        Rob Clark <robdclark@gmail.com>,
        "James E.J.
 Bottomley" <James.Bottomley@hansenpartnership.com>,
        Anton Altaparmakov
	<anton@tuxera.com>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        "Sergio
 Paracuellos" <sergio.paracuellos@gmail.com>,
        Herbert Xu
	<herbert@gondor.apana.org.au>,
        Joey Gouly <joey.gouly@arm.com>,
        "Stan
 Skowronek" <stan@corellium.com>,
        Hector Martin <marcan@marcan.st>,
        "Andrey
 Ryabinin" <ryabinin.a.a@gmail.com>,
        =?utf-8?B?QW5kcsOpIEFsbWVpZGE=?=
	<andrealmeid@collabora.com>,
        Peter Zijlstra <peterz@infradead.org>,
        Linux ARM
	<linux-arm-kernel@lists.infradead.org>,
        "open list:GPIO SUBSYSTEM"
	<linux-gpio@vger.kernel.org>,
        Parisc List <linux-parisc@vger.kernel.org>,
        linux-arm-msm <linux-arm-msm@vger.kernel.org>,
        DRI Development
	<dri-devel@lists.freedesktop.org>,
        "linux-ntfs-dev@lists.sourceforge.net"
	<linux-ntfs-dev@lists.sourceforge.net>,
        linuxppc-dev
	<linuxppc-dev@lists.ozlabs.org>,
        "open list:BROADCOM NVRAM DRIVER"
	<linux-mips@vger.kernel.org>,
        linux-pci <linux-pci@vger.kernel.org>,
        "Linux
 Crypto Mailing List" <linux-crypto@vger.kernel.org>,
        kasan-dev
	<kasan-dev@googlegroups.com>
Subject: Re: Build regressions/improvements in v5.16-rc1
Thread-Topic: Build regressions/improvements in v5.16-rc1
Thread-Index: AQHX2jynD2CHATmgwEukyh+iAPvEB6wEy7gAgAItboCAAAGdAIAAA9+AgACXqoCAAIrygA==
Date: Wed, 17 Nov 2021 19:39:40 +0000
Message-ID: <62F607C5-0004-473F-9864-4F73E70EA8F1@fb.com>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
 <480CE37B-FE60-44EE-B9D2-59A88FDFE809@fb.com>
 <78b2d093-e06c-ba04-9890-69f948bfb937@infradead.org>
 <B57193D6-1FD4-45D3-8045-8D2DE691E24E@fb.com>
 <525f9914-04bd-2d8a-0bbf-daf2d0d2053d@gmx.de>
In-Reply-To: <525f9914-04bd-2d8a-0bbf-daf2d0d2053d@gmx.de>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 35d7bf98-109c-4288-5a84-08d9aa01ff9f
x-ms-traffictypediagnostic: BYAPR15MB2693:
x-microsoft-antispam-prvs: <BYAPR15MB26939139D96F136F45400D2FAB9A9@BYAPR15MB2693.namprd15.prod.outlook.com>
x-fb-source: Internal
x-ms-oob-tlc-oobclassifiers: OLM:9508;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: TDFFznG/8SflJPzXTOT73Ctuc872viio6hpgNZzAvuDjveYwHkpeMQVQuDqmc4ZARE6+VUCVxPhKlBWc9miVFjANF4rgJvUbeVPW3r2uJnFaH4XaSGnewapXFHQ/KgkaBwR6q3ASJkvRCjjZQ9NxvjC5t7Ql7ovl0+146iXyBf5ENA/GcYHrqvqYrnOB8MnxqfF2Kmnp0ai9ODpm+s1vRzz6ouz9tDESYO+ZjxPQOA4DKonED+MqTcfy7NOmhoCkE0nxRnXaAdzM6M9k7WVTmGemvYterzdHzM0/ThJ0HLRiUYZR8UU/PExovLuLsXuJlUQxEqJcgbzf98ItEYMyoYUTLYigl8q1/JW+xgjO7N7OPlLY7LdtUi8Ogz+Jc80Zkxe0HGWyOHKhtYoi72W0ac3XYYsoHKTeEIIW9ekDzZud63Q0wqzWH5TuxjIAC3pTdJxlM7UmLbKO1Ho5I6cReMq/m3QH7eiyvGwqvDgUSGGmwd2CJFnWTJ9OmxCFFG6EIhSkDtPZR/Uxp9JsMeLSlHS7vj8RuSdX8vEmEDy9zMUI6bfJCk3QT70g1hzGruVVPbsBHFJVFueR7bAqrBwjGzEHTcK81f+K9YW7IEQ75caKt7+xpzTA7Bmngmc7ZWPInX1xJ78iw/h7D3yqKUKzQMIa+0rEbN3dugpwmIaFZZuD2Mgf4wPm9RaiuaPzya3uPsk0ZKSdpAhnY09Ep4DQ+7O7541IbMIyNWtbmQuKVzTlCiDf3ILOW14H4sjMAbh+XJAKnf786E1jy6AcDh+qTrwtN8k0TB2jo0kd9mUS8vSFj0YBbuZzX00V5zsWtsACrTd533OYDRHhGn1hwnA+EQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BY5PR15MB3667.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(8676002)(8936002)(86362001)(4326008)(66556008)(966005)(6512007)(5660300002)(66446008)(91956017)(71200400001)(6506007)(36756003)(53546011)(66946007)(76116006)(83380400001)(66476007)(38070700005)(64756008)(186003)(508600001)(6916009)(2906002)(33656002)(7416002)(316002)(122000001)(6486002)(38100700002)(54906003)(2616005)(45980500001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?bHU5S0VFby9saDltVlhIazFWUVJ1WlR2Tlg0RU5aTldxeXhMVnNqak92K21w?=
 =?utf-8?B?d0U0WWxnQXpOTTJQcXR4Zm5ZQ0VzWnBmR1l3VXVKbUJwUk50U0RWWUhpR3ZH?=
 =?utf-8?B?LzBFbUFQU1kvb3pwNlRLVHFXZ2ovenltVTZmclBUNGwrdlpxS2lzQk5Ma05I?=
 =?utf-8?B?emFHZUIyVXVoUWxLZUYxRk85c0tuK2RhNys2NnhWN2VaOVBlOElGdnF2Nk93?=
 =?utf-8?B?aGdNaUdHbHdBMjM3ZFZRRkVEQTdHTEtEZkJtcGxxMGZIZERwempWaU5vdHY4?=
 =?utf-8?B?RVpRZW9zeXVCTEc5dFBsRUhTS1hJNytzWkl1UXBpZzRsMG5wV3N6Q1g2aWZ6?=
 =?utf-8?B?UHprdUZGbDF4c09wbVJFZEkya3UzenRieHl4VFlmeWErSEx6T1h3VHN1ZUsz?=
 =?utf-8?B?TTlGK3ZNR3RCZzRxbHp0VFZ3Ri81S2RFTVZnRkdESnRxYVV3ck0rempacUZU?=
 =?utf-8?B?dUZxL2hscFRpeEFvV0xqZ0FwUWNJdXhUcUdCdHN5RWFKVFpZQ0FGQ0MzZkFx?=
 =?utf-8?B?NUZ2NU5KMmNOZk1BQXpxd0c0d041WU00aFRDRUI5Si9SbGRNWEtGb2M5Njc3?=
 =?utf-8?B?T25KMXk5NFVXUmhLSXBiR3AyYW4yUUJ6Z0t1Y2hCUW5jNXZGSjg0OHhOOTFp?=
 =?utf-8?B?dFoyeko4QXFmVFM3azhOQzl5UlRiQ2VNVzd3V2FJOXpDMXByeittMFZZa3U3?=
 =?utf-8?B?Z2ViRFMwdHlRczlUTXFjWWtTaUdmVVJMS2NacWkzNUtXZmMrSDJtWmFJYjZt?=
 =?utf-8?B?Tyt4WGpPbnZ5dGJsSXFjNkROdlpMSUdZVTJBdUl4bjduU2JpZGhIV2NmZW1t?=
 =?utf-8?B?VWJPeDRMRnJZdFYveU5nV2JlaG54WUVXUHgzMVA2NzNySXJjV0FyYUNPQ3Bu?=
 =?utf-8?B?ZlFBZVh4eDdlMjlCNUNxR29oRWN6VUxOUDJqMjZPUzZ0NklYcHFGaWNmN1kv?=
 =?utf-8?B?TWdteDgrMzF1dzcrcDdsOFROakZsSGN2RVJQUkluZzJZYW1QMVJqczlWd0k4?=
 =?utf-8?B?dXF6dElQY1B4M0lvd0Joa09jdDJiaXRkTjNMbVZuZTNBMHhkTGtrR3hUanJM?=
 =?utf-8?B?TktWZU9lcVFKQUdWSEtBQjBYUG9OaGFQYjAyaWNIVmFYckFYcGwzVm1pUHB2?=
 =?utf-8?B?UHduUVdoZndjSDlPSHA0SDluYWczNno0eW03K2xzaG1kM29HdXRWL05EcjNE?=
 =?utf-8?B?eTZpN3Z0aHJmZm1QV2xraGQ5S1pzczdSeUFWSEtTeDJJd0FsQzRGVzZKTkJq?=
 =?utf-8?B?QityZ2FnK01iNGRuZHF0bEFvcnlRV3RHOTZvSXpYQVhvazJDVjZZaU00Ty9S?=
 =?utf-8?B?TGxxZkZPMkRlbVpnckdjVzIxTU12RlFEQmhvbHdTVTdHTnBickJycU5VN0Zn?=
 =?utf-8?B?b0NHMi9lRzRHRExKV01rd3BtNEgyRTVVaHZLT1ZMRUZJQ0xnTVRGQUhLTENI?=
 =?utf-8?B?Q3VIdk1PWkE1MlpoSmVmV0tmMjhYcU5VYVZ0SCt3RkZ1QXE4Q2I3dnBSRjFV?=
 =?utf-8?B?Qm1MSFljUkNRMFpBRVk1RHB1aXQrUGQ1VjVMSXdkMlRWNk1laXhxaSt2Sm10?=
 =?utf-8?B?Q1p2NVQwclVURlovdmdBcXh5V1BwWHpMdGFDcGlLVFVyMkdDTVFyWmhuSWdh?=
 =?utf-8?B?WDNpcWVBRzJCVUNGWXZxZUpiTFFyejhidVl3ZnJjTnZVNm5EejBRQnVJOXpz?=
 =?utf-8?B?Q1lLdS92L3BKRzk4OUJnWmRSWEhSRmJwTWdINkVoTkh0ZmI1K1pRcUhSQ0tN?=
 =?utf-8?B?MHJ0UE5mTkFPTTRTbHg2cGVyRldBZHZSZ0VYYWRjWU0rbVdaV0kwWFJTVXlq?=
 =?utf-8?B?RVdvYzJRSVNzeDZtdFJsRjVqdnRyNytOSmVxeGZnejhiTTR0VVEzbmZsNDk2?=
 =?utf-8?B?Y204bHhUVllxWXNlblljMXB6eENIbG5xQ2doQVlEYmlYUFdRdnNvbFlmckFk?=
 =?utf-8?B?YTNiT0h4cGtNNjRPSEZybXpOL21HdUdmOWIxSkpMVWZ1OTRlSlVzWDVId0dt?=
 =?utf-8?B?Z0kreU9yK0hla0NYUHJGYkNpY0xEWXhMTXJSSUlVOXhnelhyVFhaRUtuK0h1?=
 =?utf-8?B?N2ZQVlQ0SkU0S3RmU1dmbWhaYnhsREtxMWdwcGVGR1VvZEdmd1g0L1c5UGh4?=
 =?utf-8?B?d1NJNk1ucXpQVHh6QVVuRDMvUEZFa0VuZ3RPK3JOanFjZ0Urb0F3WlNLUGkr?=
 =?utf-8?B?alE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <A1CCA86516A21F46B2F1B76ECB5AD575@namprd15.prod.outlook.com>
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BY5PR15MB3667.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 35d7bf98-109c-4288-5a84-08d9aa01ff9f
X-MS-Exchange-CrossTenant-originalarrivaltime: 17 Nov 2021 19:39:40.8089
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: QBJWUViTlr7KCgh89OqNGa49/oaxLTMtpHKAtZ7kGdiKn0DggSZ00LJqnL7S39rM
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BYAPR15MB2693
X-OriginatorOrg: fb.com
X-Proofpoint-GUID: tdC2voR1NU9mrsbUqafjSZ1MJEQmCWbY
X-Proofpoint-ORIG-GUID: tdC2voR1NU9mrsbUqafjSZ1MJEQmCWbY
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 2 URL's were un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.790,Hydra:6.0.425,FMLib:17.0.607.475
 definitions=2021-11-17_07,2021-11-17_01,2020-04-07_01
X-Proofpoint-Spam-Details: rule=fb_default_notspam policy=fb_default score=0 clxscore=1015
 impostorscore=0 lowpriorityscore=0 suspectscore=0 adultscore=0 mlxscore=0
 phishscore=0 spamscore=0 mlxlogscore=999 priorityscore=1501 bulkscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2110150000 definitions=main-2111170086
X-FB-Internal: deliver
X-Original-Sender: terrelln@fb.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fb.com header.s=facebook header.b=clDBZ9LK;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of prvs=0955d447e6=terrelln@fb.com
 designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=0955d447e6=terrelln@fb.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=fb.com
X-Original-From: Nick Terrell <terrelln@fb.com>
Reply-To: Nick Terrell <terrelln@fb.com>
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



> On Nov 17, 2021, at 3:22 AM, Helge Deller <deller@gmx.de> wrote:
>=20
> On 11/17/21 03:19, Nick Terrell wrote:
>>=20
>>=20
>>> On Nov 16, 2021, at 6:05 PM, Randy Dunlap <rdunlap@infradead.org> wrote=
:
>>>=20
>>> On 11/16/21 5:59 PM, Nick Terrell wrote:
>>>>> On Nov 15, 2021, at 8:44 AM, Helge Deller <deller@gmx.de> wrote:
>>>>>=20
>>>>> On 11/15/21 17:12, Geert Uytterhoeven wrote:
>>>>>> On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k=
.org> wrote:
>>>>>>> Below is the list of build error/warning regressions/improvements i=
n
>>>>>>> v5.16-rc1[1] compared to v5.15[2].
>>>>>>>=20
>>>>>>> Summarized:
>>>>>>> - build errors: +20/-13
>>>>>>> - build warnings: +3/-28
>>>>>>>=20
>>>>>>> Happy fixing! ;-)
>>>>>>>=20
>>>>>>> Thanks to the linux-next team for providing the build service.
>>>>>>>=20
>>>>>>> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcd=
c43c1aa1ba12bca9d2dd4318c2a0dbf/    (all 90 configs)
>>>>>>> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca97=
2ad531c9b149c0a51ab43a417385813/    (all 90 configs)
>>>>>>>=20
>>>>>>>=20
>>>>>>> *** ERRORS ***
>>>>>>>=20
>>>>>>> 20 error regressions:
>>>>>>> + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected=
 ':' before '__stringify':  =3D> 33:4, 18:4
>>>>>>> + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l=
_yes' defined but not used [-Werror=3Dunused-label]:  =3D> 38:1, 23:1
>>>>>>=20
>>>>>>   due to static_branch_likely() in crypto/api.c
>>>>>>=20
>>>>>> parisc-allmodconfig
>>>>>=20
>>>>> fixed now in the parisc for-next git tree.
>>>>>=20
>>>>>=20
>>>>>>> + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefine=
d [-Werror]:  =3D> 531
>>>>>>> + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the fram=
e size of 3252 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 47:1
>>>>>>> + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the fram=
e size of 3360 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 499:1
>>>>>>> + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the fram=
e size of 5344 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 334:1
>>>>>>> + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the fram=
e size of 5380 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 354:1
>>>>>>> + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size =
of 1824 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 372:1
>>>>>>> + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size =
of 2224 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 204:1
>>>>>>> + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size =
of 3800 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 476:1
>>>>>>=20
>>>>>> parisc-allmodconfig
>>>>>=20
>>>>> parisc needs much bigger frame sizes, so I'm not astonished here.
>>>>> During the v5.15 cycl I increased it to 1536 (from 1280), so I'm simp=
ly tempted to
>>>>> increase it this time to 4096, unless someone has a better idea....
>>>> This patch set should fix the zstd stack size warnings [0]. I=E2=80=99=
ve
>>>> verified the fix using the same tooling: gcc-8-hppa-linux-gnu.
>>>> I=E2=80=99ll send the PR to Linus tomorrow. I=E2=80=99ve been informed=
 that it
>>>> isn't strictly necessary to send the patches to the mailing list
>>>> for bug fixes, but its already done, so I=E2=80=99ll wait and see if t=
here
>>>> is any feedback.
>>>=20
>>> IMO several (or many more) people would disagree with that.
>>>=20
>>> "strictly?"  OK, it's probably possible that almost any patch
>>> could be merged without being on a mailing list, but it's not
>>> desirable (except in the case of "security" patches).
>>=20
>> Good to know! Thanks for the advice, I wasn=E2=80=99t really sure what
>> the best practice is for sending patches to your own tree, as I
>> didn't see anything about it in the maintainer guide.
>=20
> Nick, thanks a lot for your efforts to get the frame size usage down!
>=20
> I've applied your patch series to the parisc for-next tree [1], so that i=
t
> gets some testing in the upstream for-next tree.
> My tests so far are good, although I'm only using gcc-11.
>=20
> If you don't mind, and if it doesn't generate issues for other
> platforms & architectures I could submit them upstream to Linus when
> I send the next pull request.

Sure, I=E2=80=99m fine with that. The only other major goal of this patch s=
eries
is to reduce code size bloat. But, that isn=E2=80=99t blocking development =
of
anyone.

I do have an update to make for patch 1 though, after some comments
from Linus. So I=E2=80=99ll send out a V2 shortly.

Best,
Nick Terrell

> Helge
>=20
> [1] https://git.kernel.org/pub/scm/linux/kernel/git/deller/parisc-linux.g=
it/log/?h=3Dfor-next

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/62F607C5-0004-473F-9864-4F73E70EA8F1%40fb.com.
