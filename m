Return-Path: <kasan-dev+bncBDBLXJ5LQYCBBZF32CGAMGQEEZPHGDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EB4A453B79
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 22:08:53 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id bl6-20020a05620a1a8600b0046803c08cccsf165866qkb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 13:08:53 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ErsnrdlzdQGp41G0Ec+ByKZ30No2loQUp/p653CXKU4=;
        b=MZs94OsD95NCiPh4VHXUq/P9P3eJiACaSMfsk3YORNx62zZ8EB1lxfj89bYr4DxAik
         GgzcJPejnoYhleYJGCWxXZdkV0s1AzGphYcqcm9ge8Zks97V6JR0TTeCCrqr9sWJMcQ0
         wNxE5+Q2bLuJewy0Hlw/Lc0cbsSDt4NlHS/qecPERMkdlJq83ppMZ18MLicM031NTLfz
         IqDbPn5OzAf2dK5G8XZrVa64JelgnIIiimQlyo0mOhGVDiatL2/Jw+JHiByUqfM07xGh
         9PxH72QnAgdrqkw+O1StBpbHwtiznSFX/SpBr/dPj3vl/oquFM9lwmlfQjUwLVMOXDxL
         +uoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:thread-topic:thread-index
         :date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ErsnrdlzdQGp41G0Ec+ByKZ30No2loQUp/p653CXKU4=;
        b=V/329CTVqapo/5ZJM/RifZ3M5fZFMv6h+Nkpq5d/GlrLlA6ShBz8M8omR/JnvuRi46
         +tXOb/wRSQV6S03aUly+aCr2OjxXC1glA5eUqJFI+fAwG4FqYjGo9LCiGs9RAoleucjN
         QTwI/UJly8xL/uxwO8mydGcyUIU7EgWhxaJXODJLFlcuZbJL6iK38MhNL0hFSk9wQmft
         JN0xw7qaFywLasw59134zoGV00MvDq4EYRNKKL9nzgs+7G6RC6hZrYZFLqaDhSdC3FTb
         WrMeR74cN5kOwp9jC3Ec1VEcfsExgz4IMxyOggXywcE9UyBKGbP7JIK7WpNcnRTNi0oA
         rzHQ==
X-Gm-Message-State: AOAM532HIi1bsaYb1UAFu31akwC6AQ8SXNIQ+Psz9DPYEQ45mkvm88Un
	jPAH/IikNLvWuNjRDIxJ15E=
X-Google-Smtp-Source: ABdhPJxOpzCRwzI60pcXjSLmqX5Hs27d6hjZFY1xziBPewjVaoyHFdmaACk0Itsd7iPwKiHNhAs5jg==
X-Received: by 2002:ac8:4a0e:: with SMTP id x14mr11182435qtq.345.1637096932371;
        Tue, 16 Nov 2021 13:08:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5746:: with SMTP id 6ls10451575qtx.9.gmail; Tue, 16 Nov
 2021 13:08:51 -0800 (PST)
X-Received: by 2002:a05:622a:20e:: with SMTP id b14mr10974025qtx.288.1637096931855;
        Tue, 16 Nov 2021 13:08:51 -0800 (PST)
Received: from mx0b-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id u2si990207qkp.6.2021.11.16.13.08.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 13:08:51 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=095491a111=terrelln@fb.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0109331.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 1AGIC2Zk004993;
	Tue, 16 Nov 2021 13:08:37 -0800
Received: from mail.thefacebook.com ([163.114.132.120])
	by mx0a-00082601.pphosted.com with ESMTP id 3cc8t95n0d-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Tue, 16 Nov 2021 13:08:36 -0800
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (100.104.98.9) by
 o365-in.thefacebook.com (100.104.94.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.14; Tue, 16 Nov 2021 13:08:34 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=aCCl9O8kTwCZMiVbg5adqjva9tK9dM5JXu0TvNxCUonTNcxq4dTAW9WQH1F2DeFQ3hAygs4L1CO9h0NlLPvBwsfEhJVUn3CbocfqI0LCMq3P1YWsobZLgdTkak3XJmcyu2zH3qmujaX0bu8im7RF3+fXulyYccjmi0xS3phemayOSfIJPd57pGOaii4JKGI92SquOzMBOJx6Deur/XGmwVO5z39ZUVlMqqv+RDlPEUUia05Uzy2WR2QHjocXxfHWtc9yzNusvj5h6AMgEy7353dBwnP27D5G+dIXj3eZvRmX4uL+a+o+7FnHsnmbFyWxq5QxRJ0eJQvA/n2WrjTySQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ianiptz7NQix3E32MDoN5XkvD0wGbtJiOMocc0f67w8=;
 b=ORnZniSkLuq2BE3039qdMgYj8XOS92Iti4OJw5mnJJ6IndwtxQXynHQr6OmJduKMgFimIQnpdjyhygtRS7oWKtQXERBLjIICftcIPJZlkGKwqE+bJ8Cy+hML1fZFnhpQ4oNsVlxhR7xInCT+KZA4viq/HASYcDlmNUabL9gPAHA7sJqCnwUGeOjrY+BYveINjIoXotg+uoY4e8m/h06sHP/DPsTvmHBb9oLjisGpSbhfBU2ycfaWOgY3/jIRUqi5qRdA1jhub8hzUD526bRIjiVlpMcQkjrxdf7HCdwGCjeJfhvMEw/M3g8jB9G6hpG/ZaxxzPqMfTMoKqxk75tMvg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=fb.com; dmarc=pass action=none header.from=fb.com; dkim=pass
 header.d=fb.com; arc=none
Received: from BY5PR15MB3667.namprd15.prod.outlook.com (2603:10b6:a03:1f9::18)
 by BY3PR15MB4979.namprd15.prod.outlook.com (2603:10b6:a03:3c6::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4669.11; Tue, 16 Nov
 2021 21:08:33 +0000
Received: from BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4]) by BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4%6]) with mapi id 15.20.4690.027; Tue, 16 Nov 2021
 21:08:33 +0000
From: "'Nick Terrell' via kasan-dev" <kasan-dev@googlegroups.com>
To: Helge Deller <deller@gmx.de>
CC: Geert Uytterhoeven <geert@linux-m68k.org>,
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
Thread-Index: AQHX2jynD2CHATmgwEukyh+iAPvEB6wEy7gAgAHcBwA=
Date: Tue, 16 Nov 2021 21:08:33 +0000
Message-ID: <587BB1D2-A46B-4E93-A3EA-91325288CD6A@fb.com>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
In-Reply-To: <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: cd780381-a434-406b-dfc8-08d9a9453f81
x-ms-traffictypediagnostic: BY3PR15MB4979:
x-microsoft-antispam-prvs: <BY3PR15MB4979873CEAD1EC76DB32E1FEAB999@BY3PR15MB4979.namprd15.prod.outlook.com>
x-fb-source: Internal
x-ms-oob-tlc-oobclassifiers: OLM:10000;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: BUZdjGDsXTlfsazQqGuQVn1hXFDAzjeIBgOF0eCXN4A8dD2bhbk7fehaeMDk/SoOo2A7k7pEgQsZ1fXXPAHpExv0HJazZ+eilspaIJ/WKC2jZbS8IfL6CUIiwaDITfaEEGuDikvyF4RrTVAMMtacUO0TSFZXRKWDFEip1UT3nAPmgjAkRQt5i22rlSg247rYDwsLkjRFbGj9GUf5BghOMem+NjpFjr1p5Fv4rLfeahmYM4dzYiH/3ivpRlPpXURVowJHbqJ9WaPZXIKXPFxP55SXPfTYta7GkRgR2fHJOnnc7SXyWSU1c4hkHICqEIxTXox4e8XMSrK7eqRqpzUvcjGU0L/h+EI2y1IeSyN3XL8/7U8BvvPXU4uXLB5crU0Nq4JP30wb41QXWN8tV5X6K7IsPJaxU67UoRn4a4KVEbMfmIsS0NgYekzkYfh8AdWjKBlODDVMNCjrZXbIu6mDbskBIUlUWZlE4J4AHYQIiLY/0eaxELfrGYzL1wa6FxiOM3N49PUZkclSVy5nY2frNOrM2rrghPQuDLU9NTJA5SOv1ki6Yqadk3ncFBRgP7tPfp4i1ljb/mKty7yEl8Cdl+hQlI5P3fkc5wK6j6+2UL1VH8jqkKbDtExH9TMZ1takkxX5WZz5l7AjMM0SXkouZiCzu31IYvX5mr8Y0HZPsvthNWUyLXgWynO5XSZA9REmGC0nNBk+2A757nhJ9cepbfPFMBNj7eU+v/rdw8N1iomuXNaxcfRHShHCNuLjxjqeo404CSCIDe3MnIOxeL/kWiisyNl9aR09YZRmSMa94GdU8HQ+WuYutTvuOb8R3uxpZnr3L7PGrolwzt1dAJ5NWA==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BY5PR15MB3667.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(186003)(36756003)(966005)(6506007)(2906002)(66446008)(33656002)(6512007)(8676002)(53546011)(6916009)(6486002)(86362001)(76116006)(83380400001)(316002)(64756008)(8936002)(71200400001)(54906003)(4326008)(5660300002)(66556008)(508600001)(122000001)(38100700002)(66476007)(66946007)(2616005)(7416002)(91956017)(38070700005)(45980500001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?YytMUHNMeHMwT3pRYWZQNTdzMGNOeGt2ZUkrZWVaU0FBRDJSdjU2MlFVU1lN?=
 =?utf-8?B?QUt4aWlZM0VhclJIa2tuZEN6RXNjQWdiN1FYc3k3ZFVzUTR2NVJxNkhvWFU0?=
 =?utf-8?B?QUl3MjR3THc2QlJ0cWZzbUFocDBmZDROYnhlRTBBZDRUOFZaVFNVMCt2VXdH?=
 =?utf-8?B?S0pMbmw5c2F4ZEFlamJHUU9DZ2c4REF2ejZUWDFHSy9aZ25xa3hnendvaXlL?=
 =?utf-8?B?ei9SSGl1OU5uSTViTi9VcExkWFpDekY0U01XZnRCcFg0KzFUOHNKN2dTMWZE?=
 =?utf-8?B?SkJ2RHJxTWZQczhhQUFVNU9DVFg1M1FrUzdNUGVJcmsrOE5pZ3NRaWRVVm5p?=
 =?utf-8?B?NXF4SUNCMksyT093OUZoc1hZWWRjWTJkQzhNZndIbXg1aUJJN3RtZXRQdlJC?=
 =?utf-8?B?ckNvNlRhc1B5YlordFhLanVvdWZXT1FZYzdlY3FkSUN2REttd2tMUGFSZENI?=
 =?utf-8?B?NGJ4UlkrSC9lNmIzekJleXprOXJDM0kvcEJlZUtHUTF2dzJhQksxVW9EUGNT?=
 =?utf-8?B?OGMybzFsQ0p1eHVyc2lkVDBXRWg4RW52YTY2NDVrcGRENVlpN2hiZHJkd2NX?=
 =?utf-8?B?MTdmUy9DZzV0Sldid0trUG5kOFpHcW1WTmcvODU1NnRFZUVmMHlYNksvRXRk?=
 =?utf-8?B?VWhjcGRvOFgvSjFKZ3NLM20zRGMrTzFSZkhYcXNkdk5nZGlxT0gyV0R0bTZL?=
 =?utf-8?B?dlErUjd5VlJZOEt4NlczZjlaNFhWaUNsSVpLb2twL0RsbjNDMU5uUEsxRVB5?=
 =?utf-8?B?aTRjYnljeGdrNUtMbmM4alN5OHloTlI4ek5ZYS9UanN3MlNyQUtMN090Nm1q?=
 =?utf-8?B?Wld3andpMVZqMGt0UUFHRXl4bUJjaFAwSnIzVXo3UVVwQ09YYUZYbmhNcHE3?=
 =?utf-8?B?b3VGM2hacVFPQ2R1ZC9rTDRPU0V4RFhqMXVKK2J2WXZGdUI3RWhuRHRJY2th?=
 =?utf-8?B?ZnpPeGl6MHNvYkZHMTFLNitXemUrUWhwSkpFWVFNTytHcWkweXJ5WUgvdFpz?=
 =?utf-8?B?VDV5OW5sWG5yWjhOSXhSUDVoSnQvY1pKUGVLY2cxRE4rK210U3BSNytNTVJo?=
 =?utf-8?B?UDdKbmdBd01wWi82SXc1Unc3VGNLczFTZ0w5UzhNcmZnY1h0dFNNM2g3dnov?=
 =?utf-8?B?SjNsajF5ckM3NkMxNjRzdWpqRFVmdVBCNzJQUlAyeVpmajdnNmtuK0hURUJz?=
 =?utf-8?B?QlhSYnpWQTlNWXVRS3I2S2dmYXI3K1d5OUg4K0U4aGhKZmo0UTluMW9Mc09Q?=
 =?utf-8?B?aUpicWN6dnNUTmp4SWh3QzF3ZXlqSVpaK1NYYmZORG8zN1NBdTdTTk45NlJ0?=
 =?utf-8?B?VUo1ZkFTdStJa2pGYWkyMmN6Rmk3VXV4ZERxdmpMZnliaS9QTWY5UCtPYlBx?=
 =?utf-8?B?ZTNmUkZKR2ZkcHgrSU1hYVRHUVpkbis1T1RQSHRyL3NBS0QyS2dSdzNoT2tG?=
 =?utf-8?B?VWk1VWdzQnptbzRUSldxZEF1NUhxL0xaMk5GdXNUZVIwZW43M0xUZWFsTVZU?=
 =?utf-8?B?T3lHdUpzTldHQzFtM2VOSVUwMkJwalZkeklXQkoxcnMxNXNuNTVEWEpVRnlI?=
 =?utf-8?B?Y1BVZ2RlSmRadU1HTHBQbzdvbHpINUhZQ2tFa3BzMWIxYVIrMWF0WCtjY09I?=
 =?utf-8?B?dW1rZVcvVlpTdG9HV3VMSnBxQXI2VExabjlvYzg5RlVlbmxXLzZKWGdGT21t?=
 =?utf-8?B?Tkh6RmRJTU9xTHVVWk55aCt3UHdKNzEwU0Jnalk0SDNwZFlyOWo1MHdOK2hP?=
 =?utf-8?B?c3k1V3BJSGJhZTNoL2hpNC9LVWdDZVdlK0U5RE5FT1VuWHJsYll6VXc1QnVn?=
 =?utf-8?B?RUZWUWttTEdHMHpDVndmVlEzN2ROcXl6YmJWYWdQbGp5UEpjY0hlUjlJd3E1?=
 =?utf-8?B?MlV3UExBbk1UWjdBelBXekRUNjkraEhacEJtdmhZTy93S01rUlA3UXc5TTF4?=
 =?utf-8?B?UHdaWHJQazlDUVRDOHluQlBwYmxSU1BibU1pM2x4aVVIdXRuNnRmNE4xSHpt?=
 =?utf-8?B?TjQwb29aS2ZNUHRkbURqQzh3dW1oblN0dnNLdko3MlRUTlVhZU41K1AzRnRN?=
 =?utf-8?B?dXpaOG1nT0ZUaXFGbHBaUjFYOWhFMzBvREE2OGJMcndmUk5OZ0l2TmxLcE1J?=
 =?utf-8?B?aHBXc25ydEpPM05XR252U3JWbENEenFRcVQ3R3pEVmtBVm8rZlVESmpkMU04?=
 =?utf-8?B?TUE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <5657D1FAB6DC0240997FED2AA1A7DD9E@namprd15.prod.outlook.com>
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BY5PR15MB3667.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: cd780381-a434-406b-dfc8-08d9a9453f81
X-MS-Exchange-CrossTenant-originalarrivaltime: 16 Nov 2021 21:08:33.1170
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 8IpzxyoHM76V7EZ+M0ZBqWXGlF2ZvScXsmLldnuwcRbb6y5mm7g3JIO2I9/tWIn7
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BY3PR15MB4979
X-OriginatorOrg: fb.com
X-Proofpoint-GUID: xy00tocUOXNuXqEyO3e5T0JJeAPL6SNv
X-Proofpoint-ORIG-GUID: xy00tocUOXNuXqEyO3e5T0JJeAPL6SNv
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 2 URL's were un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.790,Hydra:6.0.425,FMLib:17.0.607.475
 definitions=2021-11-16_06,2021-11-16_01,2020-04-07_01
X-Proofpoint-Spam-Details: rule=fb_default_notspam policy=fb_default score=0 lowpriorityscore=0
 malwarescore=0 bulkscore=0 impostorscore=0 mlxscore=0 mlxlogscore=999
 adultscore=0 spamscore=0 priorityscore=1501 suspectscore=0 clxscore=1011
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2110150000 definitions=main-2111160096
X-FB-Internal: deliver
X-Original-Sender: terrelln@fb.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fb.com header.s=facebook header.b=rXmsJvvS;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of prvs=095491a111=terrelln@fb.com
 designates 67.231.153.30 as permitted sender) smtp.mailfrom="prvs=095491a111=terrelln@fb.com";
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



> On Nov 15, 2021, at 8:44 AM, Helge Deller <deller@gmx.de> wrote:
>=20
> On 11/15/21 17:12, Geert Uytterhoeven wrote:
>> On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k.org=
> wrote:
>>> Below is the list of build error/warning regressions/improvements in
>>> v5.16-rc1[1] compared to v5.15[2].
>>>=20
>>> Summarized:
>>>  - build errors: +20/-13
>>>  - build warnings: +3/-28
>>>=20
>>> Happy fixing! ;-)
>>>=20
>>> Thanks to the linux-next team for providing the build service.
>>>=20
>>> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcdc43c=
1aa1ba12bca9d2dd4318c2a0dbf/  (all 90 configs)
>>> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca972ad5=
31c9b149c0a51ab43a417385813/  (all 90 configs)
>>>=20
>>>=20
>>> *** ERRORS ***
>>>=20
>>> 20 error regressions:
>>>  + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected ':=
' before '__stringify':  =3D> 33:4, 18:4
>>>  + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l_ye=
s' defined but not used [-Werror=3Dunused-label]:  =3D> 38:1, 23:1
>>=20
>>    due to static_branch_likely() in crypto/api.c
>>=20
>> parisc-allmodconfig
>=20
> fixed now in the parisc for-next git tree.
>=20
>=20
>>>  + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefined [=
-Werror]:  =3D> 531
>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 3252 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 47:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 3360 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 499:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 5344 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 334:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame s=
ize of 5380 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D=
]:  =3D> 354:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
1824 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 372:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
2224 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 204:1
>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size of =
3800 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D=
> 476:1
>>=20
>> parisc-allmodconfig
>=20
> parisc needs much bigger frame sizes, so I'm not astonished here.
> During the v5.15 cycl I increased it to 1536 (from 1280), so I'm simply t=
empted to
> increase it this time to 4096, unless someone has a better idea....

I am working on a patch set to reduce the frame allocations some, but it do=
esn=E2=80=99t
get every function below 1536 on parisc with UBSAN. But, in addition to par=
isc
needing bigger frame sizes, it seems the gcc-8-hppa-linux-gnu compiler is d=
oing a
horrendously bad job, especially with -fsanitize=3Dshift enabled.

As an example, one of the functions warned ZSTD_fillDoubleHashTable() [0] t=
akes
3252 bytes of stack with -fsanitize=3Dshift enabled (as shown in the first =
warning on line
47 above). It is a trivial function, and there is no reason it should take =
any more than
a few bytes of stack allocation. On x86-64 it takes 48 bytes with -fsanitiz=
e=3Dshift. On
gcc-10-hppa-linux-gnu this function only takes 380 bytes of stack space wit=
h
-fsanitize=3Dshift. So it seems like whatever issue is present in gcc-8 the=
y fixed in gcc-10.

On gcc-10-hppa-linux-gnu, after my patch set, I don=E2=80=99t see any -Wfra=
me-larger-than=3D1536
errors. So, you could either increase it to 4096 bytes, or switch to gcc-10=
 for the parisc
test.

I=E2=80=99ll reply in more detail later today when I put up my patch set to=
 reduce the stack usage.

Best,
Nick Terrell

[0] https://github.com/torvalds/linux/blob/8ab774587903771821b59471cc723bba=
6d893942/lib/zstd/compress/zstd_double_fast.c#L15-L47

>>>  + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2240 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>>  + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2304 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>>  + /kisskb/src/fs/ntfs/aops.c: error: the frame size of 2320 bytes is l=
arger than 2048 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 1311:1
>>=20
>> powerpc-allmodconfig
>>=20
>>>  + /kisskb/src/include/linux/compiler_types.h: error: call to '__compil=
etime_assert_366' declared with attribute error: FIELD_PREP: value too larg=
e for the field:  =3D> 335:38
>>=20
>>    in drivers/pinctrl/pinctrl-apple-gpio.c
>>=20
>> arm64-allmodconfig (gcc8)
>>=20
>>>  + /kisskb/src/include/linux/fortify-string.h: error: call to '__read_o=
verflow' declared with attribute error: detected read beyond size of object=
 (1st parameter):  =3D> 263:25, 277:17
>>=20
>>    in lib/test_kasan.c
>>=20
>> s390-all{mod,yes}config
>> arm64-allmodconfig (gcc11)
>>=20
>>>  + error: modpost: "mips_cm_is64" [drivers/pci/controller/pcie-mt7621.k=
o] undefined!:  =3D> N/A
>>>  + error: modpost: "mips_cm_lock_other" [drivers/pci/controller/pcie-mt=
7621.ko] undefined!:  =3D> N/A
>>>  + error: modpost: "mips_cm_unlock_other" [drivers/pci/controller/pcie-=
mt7621.ko] undefined!:  =3D> N/A
>>>  + error: modpost: "mips_cpc_base" [drivers/pci/controller/pcie-mt7621.=
ko] undefined!:  =3D> N/A
>>>  + error: modpost: "mips_gcr_base" [drivers/pci/controller/pcie-mt7621.=
ko] undefined!:  =3D> N/A
>>=20
>> mips-allmodconfig
>>=20
>>> 3 warning regressions:
>>>  + <stdin>: warning: #warning syscall futex_waitv not implemented [-Wcp=
p]:  =3D> 1559:2
>>=20
>> powerpc, m68k, mips, s390, parisc (and probably more)
>=20
> Will someone update all of them at once?
>=20
>=20
>=20
>=20
> Helge
>=20
>=20
>>>  + arch/m68k/configs/multi_defconfig: warning: symbol value 'm' invalid=
 for MCTP:  =3D> 322
>>>  + arch/m68k/configs/sun3_defconfig: warning: symbol value 'm' invalid =
for MCTP:  =3D> 295
>>=20
>> Yeah, that happens when symbols are changed from tristate to bool...
>> Will be fixed in 5.17-rc1, with the next defconfig refresh.
>>=20
>> Gr{oetje,eeting}s,
>>=20
>>                        Geert
>>=20
>> --
>> Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m=
68k.org
>>=20
>> In personal conversations with technical people, I call myself a hacker.=
 But
>> when I'm talking to journalists I just say "programmer" or something lik=
e that.
>>                                -- Linus Torvalds
>>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/587BB1D2-A46B-4E93-A3EA-91325288CD6A%40fb.com.
