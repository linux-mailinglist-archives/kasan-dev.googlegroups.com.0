Return-Path: <kasan-dev+bncBDBLXJ5LQYCBBS6N2GGAMGQEPDZRAYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 10A1E453E52
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 03:19:56 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id v14-20020a05620a0f0e00b0043355ed67d1sf713636qkl.7
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 18:19:55 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gYQM5TBPcjoGryCPCZQmJP58w4A3EGDabuwsAPluEUE=;
        b=nkzNgDXCk2qJiVwxUZJye9EhmElwQUOmfYA1bSICKK7kYiWwgSToD2jqcB5LSoe4jV
         7pO8AMMPj5xp7ElDy9TsBRsghC7OYXq0XlJik1Mwdk9XkAAX8ubdn773DHIERL9CeAYm
         pHPsgqyhL8Qt6ffeFvq3Bc83K8QmVtc0xPbZTp1t9WSJNoYU0Dq4RwLwMKD74UkvwuX2
         ltXfqHANAUoUBqx55FXDD/2L8YejF67PRgTrFQIv37YOAvEjDwpGHyDD5B68ZztHuSp/
         ahBDayC9LApKkosxJSc7JHTdRkZRrhXDJvFIeKfk7ymhO+cU8k4Ziq0y33C/kRP045cH
         3pSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:thread-topic:thread-index
         :date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gYQM5TBPcjoGryCPCZQmJP58w4A3EGDabuwsAPluEUE=;
        b=UkGG3L8SyI31N6IDbS9+EVKWkWiEnLkj1RamA5FS27LTwRRpjHUhygQIfNZS5YTjH0
         /IsPuVjuzp5QrloF3oNnu7XAzbrW+1ZW0I0It/NyR9+1vVFrydqfKUDAj2yPyRIOcp+P
         1wZIUqmTmgZFSDIRpZkg4lQbVhjgheiqrS1ZwpsBL4+qKLHc/GfaTma+/NQqD25mEWbR
         E/vy/T6NnUsAmtq7CnJ2ERlzk1rhfBqri4573qwTQxq4+2itNeZB6NpS1uiI+NJlKrmL
         cQYQPOAVZ+AfwQkbfKBECoAU79AjFuogjMsVACL2P+E2ArazhTGN9iniJJTCHvaNTArr
         BmfQ==
X-Gm-Message-State: AOAM532+D6GwdPGJV2M1LUpip/T7TB5vVvLyQd/0Tikr8/GFRHHWff6p
	SYtlTJq/KMojzYBlj3iV8Z4=
X-Google-Smtp-Source: ABdhPJwCDvJzHo1FtNe7fhOOskg6SAiNm27FGs/h2wu9/FVlCOU3I/GwsZAR2MWpl4QC9Rml6Dxjjg==
X-Received: by 2002:ac8:7d45:: with SMTP id h5mr12861018qtb.256.1637115595155;
        Tue, 16 Nov 2021 18:19:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:24b:: with SMTP id o11ls10890638qtg.0.gmail; Tue, 16 Nov
 2021 18:19:54 -0800 (PST)
X-Received: by 2002:ac8:59ce:: with SMTP id f14mr12905659qtf.30.1637115594721;
        Tue, 16 Nov 2021 18:19:54 -0800 (PST)
Received: from mx0b-00082601.pphosted.com (mx0b-00082601.pphosted.com. [67.231.153.30])
        by gmr-mx.google.com with ESMTPS id i6si254113qko.3.2021.11.16.18.19.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 18:19:54 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=0955d447e6=terrelln@fb.com designates 67.231.153.30 as permitted sender) client-ip=67.231.153.30;
Received: from pps.filterd (m0109332.ppops.net [127.0.0.1])
	by mx0a-00082601.pphosted.com (8.16.1.2/8.16.1.2) with SMTP id 1AH1pQV2003739;
	Tue, 16 Nov 2021 18:19:39 -0800
Received: from maileast.thefacebook.com ([163.114.130.16])
	by mx0a-00082601.pphosted.com with ESMTP id 3cch9x3fte-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NOT);
	Tue, 16 Nov 2021 18:19:39 -0800
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (100.104.31.183)
 by o365-in.thefacebook.com (100.104.35.175) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.14; Tue, 16 Nov 2021 18:19:38 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Cu0X/VvKNm5J7BnHf6kT4jLNevtHTDd0HI5mPp0EnqtEu8ghTTuZSuEcfOjWJNvJKq+0uiPcSEW8koc4VqAWWzhbg/VgCH3S5QUOk74F54R7F80y9Y/SpH4oxAgQKm7XlBspA2DfNX/LkKDH6JrkqDF5tpyR7aDftz6SfQFVG1Hig9nL4mREDK0xxrAZJlXdrci7Xt/AfHPyd3biSxjvKisQZRFCZUQxekq4jdk32oteZQt9qfw8N/ObRXKul75GBuIUb3wFDi5OZ8qc2sQ95s94g9KdkQZ2MyIEck37AtlADgpQ2fWSxIp1OJVazWyEIMBiixgo1lMdJDA5rb9bYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=f0Za2ACT3ZaRoTY8XTFPQuCzyP9a87pJXo0dcwAl2ak=;
 b=WMLl92vSa0vCC0yB+fwoJzZmsa6dWSbXejlvnUs4OdNK7ne5+sq6lUkP3jkMzCrmnQxVDZEed51ZwqPUh94u52OoPKSP6ubDMwD2jIQVbgKXHQTnynd25+YMLk9rJt8kdPwMNL4WRryKFgoJghPf32XhalqbMgvmYXL/wpI8JOQhUB6ov2PfzRtXWs4MHEEuBzVW5/oQPnNOfglQy3ue3PPbwqrkmbf3cp6OJq9PLfMJiYtIukW+mgdIR2mcmtS9PL+PpNy2dluV0erSOxWPAigxMDexk7WOXRJB0HQp5jZzeMXTcceNX0WBIsIs/ii+VnmVWCAFALLM29vxhCkljw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=fb.com; dmarc=pass action=none header.from=fb.com; dkim=pass
 header.d=fb.com; arc=none
Received: from BY5PR15MB3667.namprd15.prod.outlook.com (2603:10b6:a03:1f9::18)
 by BYAPR15MB2456.namprd15.prod.outlook.com (2603:10b6:a02:82::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4690.26; Wed, 17 Nov
 2021 02:19:32 +0000
Received: from BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4]) by BY5PR15MB3667.namprd15.prod.outlook.com
 ([fe80::8d7d:240:3369:11b4%6]) with mapi id 15.20.4690.027; Wed, 17 Nov 2021
 02:19:32 +0000
From: "'Nick Terrell' via kasan-dev" <kasan-dev@googlegroups.com>
To: Randy Dunlap <rdunlap@infradead.org>
CC: Helge Deller <deller@gmx.de>, Geert Uytterhoeven <geert@linux-m68k.org>,
        Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        Rob Clark
	<robdclark@gmail.com>,
        "James E.J. Bottomley"
	<James.Bottomley@hansenpartnership.com>,
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
Thread-Index: AQHX2jynD2CHATmgwEukyh+iAPvEB6wEy7gAgAItboCAAAGdAIAAA9+A
Date: Wed, 17 Nov 2021 02:19:32 +0000
Message-ID: <B57193D6-1FD4-45D3-8045-8D2DE691E24E@fb.com>
References: <20211115155105.3797527-1-geert@linux-m68k.org>
 <CAMuHMdUCsyUxaEf1Lz7+jMnur4ECwK+JoXQqmOCkRKqXdb1hTQ@mail.gmail.com>
 <fcdead1c-2e26-b8ca-9914-4b3718d8f6d4@gmx.de>
 <480CE37B-FE60-44EE-B9D2-59A88FDFE809@fb.com>
 <78b2d093-e06c-ba04-9890-69f948bfb937@infradead.org>
In-Reply-To: <78b2d093-e06c-ba04-9890-69f948bfb937@infradead.org>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 1a2d3ab0-18e6-487c-08cc-08d9a970b13d
x-ms-traffictypediagnostic: BYAPR15MB2456:
x-microsoft-antispam-prvs: <BYAPR15MB24563099488E2EBD125C88E1AB9A9@BYAPR15MB2456.namprd15.prod.outlook.com>
x-fb-source: Internal
x-ms-oob-tlc-oobclassifiers: OLM:9508;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 8uBXr6FaQzF4nFe/MM+0Tzr+HhKUgN/Le0Crea7p8PZiUtyh2gsvKqVmdGhkCDz8UTh8F59PtQ9eP5oOGy+rd4v/Paxvv4kjNOt0QU41qAxjIAnnzomQUabeCpYg3lCWec8WGOY90clvOSX2AYWjIk0dbE4+mzvwwmvt2Q4p6sHpyIaqgTP1BBT/pX/xwOJjqlrqtDB8XaNL6KStVzeRvh/7NLsiOekDOo8TuRLSBmRH+vZ8n+i9UyKvTraGesjWh+9cmagCWplSzeAFpKItOXE59axgmo7qUmkB9LQ+fxd/2Yv7tMpBrYKfAyag+PuQxxmjJFEGP7H4poKi8z2Izke1wwrqGCAF/l0lXGbYOWScOv3KdX1bQqMooYRquIjU51Pfh32s4RoG4YjTP0w2PFIWURmZqeyRQGoLVAvahPecQrZVW46StZRHOjnsVyxZYD4ynG8A5/xWozn1UMeIFBSxPxg4eqIFF/WUJjQyxx6NjKAIPbgCMl9/zx/nEV9U9LHuyeHMbCK0Y6poQjNxSfJItZ9DdQKNLBt0HdQk0AohRf++7ksjxXi27qISOF+KQllCbgPXy26zdP1RMEWBV7FO0imv1ANPlQtFMBSFZNlnfqgg+q2RiQXwF8leMk1oF5NPc49AAyjGkTJEzQHW3WyTNEEszbbKQ3ZRaTmw3Z0S9plZMYQVmKqm+WXyL0faLr+3F9hlMpO3qmTusorUNxsV8D/hk4smh9yNs8dP9B7gKfm0qpKQMU4z9NDvgXls0O+2AVaTOUP2Q8x2XxPyskKD2KstAVXzP6UkvAuoCcupgAhPCN7pj8fYceErf58InV+JhPkVvIQt73i27tc7+A==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BY5PR15MB3667.namprd15.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(38070700005)(8936002)(6916009)(316002)(91956017)(54906003)(508600001)(8676002)(186003)(7416002)(5660300002)(966005)(2616005)(6506007)(71200400001)(86362001)(53546011)(33656002)(66946007)(66476007)(122000001)(36756003)(64756008)(66556008)(6512007)(76116006)(66446008)(38100700002)(4326008)(6486002)(83380400001)(2906002)(45980500001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?NEk4c1RSRnhPd1NndUZIb3RlOS90RFBjd1RRQ2ZMQ3ZOM0NVbWdSTDRBcVBM?=
 =?utf-8?B?NnJwOS9rOVUvSDM0MWtnV0RQaWcyTG5vQmF3TVJ1S01Gb2ZGaURKRXpqMlJN?=
 =?utf-8?B?bmxKS1RkanZkODF4cDRpZ2lwa0NxQnorc0R6eFkxTzRVQWoxemVzTWVvbUJw?=
 =?utf-8?B?eCtSRjVHQ1lzbG1wMnZncmxWZklzUitWR1NKUVdZdGNCTFpucmdyZXZ3VndN?=
 =?utf-8?B?TFVycHp4SHhHSUtLR2IyVGJhQS9DVWZQM3FPalplT255MnpsYStmTmwxODBN?=
 =?utf-8?B?T2E0SXBRN3ZFSEl5TlR4YlhDWnFLY3JCTmwzVUNiU1ZSYU9xZzVjVEhQTVI2?=
 =?utf-8?B?UnNOT0wvb2FFWENxOXBvczZiKzBtVUE1dWU3VW1OTTBUeXJrNkt3WjNqei9W?=
 =?utf-8?B?alJDTVg4U2padlFSUlA4M1lIdnlDSUZzMlFSZlMzbDhHN1M0KzNHMitHUmpZ?=
 =?utf-8?B?R0JaMUhWTEEzZnhDaG5vVVVMVEtYaW5qQStRYmdWM1ZHY0pQZ0Irc0NlbTRs?=
 =?utf-8?B?UWVYdCtrcUtDVERQUUNZY0pJN09JQUJwNnRuZDF3eFliYURlRk1nZkZadytt?=
 =?utf-8?B?Wk5wZW1DLy92czVZM2REN3NwQjJuelNBREphanpkZW00eDdUbFU0L3ZXV1R5?=
 =?utf-8?B?TG9sUTRqNmN3Y1AvcFVLcDVyekt3dmJmTTFkSnpIeXlndE5MRjdtNmZMdENC?=
 =?utf-8?B?MThBUnA1dTc0TERkMkV3ZUNiQUtWa2VBYzVhR21HNmQvTDlYNU9tZ0g4SUJy?=
 =?utf-8?B?RHU0U1JVSzF1b2ZKWE8vOU03YmZXbmlGN21JWi9vVDJyNHZMVFd2Q2V6U3g3?=
 =?utf-8?B?dGtrT3pFT2htTjZxa0lXUW5GTURRUkhqWmorTjd0alpuRWk2WW9UeGZnOVJ5?=
 =?utf-8?B?dk8vMUhaMFNtamJHS2gyR25xNURscUpmTE1ROUJSaG5BN29kNnVCbk1HL2Zw?=
 =?utf-8?B?REJ0NzRWS0d2UDMySzJnU1J4U0xCWXhjaWR4c3ZweGlZcE5aYXV6UzhxZHFp?=
 =?utf-8?B?S1A5dG9YVytLcEYvSGdkWTRsNit3azlJeWVLSStzdnRKV1M3OExsNEJiZWt1?=
 =?utf-8?B?SFRpcGVmK0Fiek1uS2pGaGNtdjdyZFc4cFA2RHBIbmRtN0ZlUlFOMVM5SU15?=
 =?utf-8?B?WHhJdmdLRjhrdkhWaG9KbDE1SGlsajE5TTZDdkcrWnhSL1JQVVlkcnc1aHl0?=
 =?utf-8?B?eHhPdHJFckJQOGM3WXMybGZUYlR3WDd2RnRuUmx3YmNoOGp0YVRMQmZWSkZS?=
 =?utf-8?B?RzN5K29jNzVlTGUyR0NSbzF6OXZySU1DR0hBNnhsVXh2Q2N5ZDZlZGNBMDJG?=
 =?utf-8?B?cjJvNmxoemFRTFYwWmpIcGFvUWdjc2t1T1R3b1N1dnoxN1Z5SlRvUS9HSjNs?=
 =?utf-8?B?N0xNSkVOQ2dqSi9rdXUxQ0p0RjNheE9QcThWV1I0MGFVMHN1WnJSWEpBUlpv?=
 =?utf-8?B?TnFhMDRwK0lQUlZSZVVKUnZYamltclQ1K2l3Q0hScDBTQTh2SnJjOHFERXc1?=
 =?utf-8?B?QzJ2a3lFUTJjcUdvZERtVlVodEdMVTIrcngxNG5BdFJyOGNBSXdoUncvM1Ex?=
 =?utf-8?B?QzNIS1VFNGNrS1ppWlhDckwydnYzV0Q3eDB5WEdLZFlldndRNm5zbW42Y2VY?=
 =?utf-8?B?c21hTUFLZjJBZG15VUF2c01DYk1LM0lWS0JBZjZVSFRiMnU0V3d6NTczQUxo?=
 =?utf-8?B?RHRjOWwyUm5SRlZ5YmwrL3o4T0ZzdjUzbTB1ckZEK2JOeXlQRTBYYkM0SjB5?=
 =?utf-8?B?ZDhBL1BUODBWZFdNUU5uR2JtRHMyT1FPUDJxSDB6Vzh4aDlOenhaY2taL0xk?=
 =?utf-8?B?ZDhMN1llWFdaT28xZDhnTlBLbmkwZ2ZsQUFINzR6cHp4OFhpb24xbGJxNVgr?=
 =?utf-8?B?c2h4ZjFZdEtjN0pZblRDVHVtNWkyaHJtTUt0ZzNZN25LMzBUQWdzcWdiamxS?=
 =?utf-8?B?WWF6NWsyRnhxWWQwUFFGSGtETHVJSkZWREorVytmdUZWYy81MzVoaHlxeWV1?=
 =?utf-8?B?RjBKUHBIdHkzNWVsanF2QUJLcWk0S0N0SWtTZ1ZvaUpZRTV0RDhUNnZZQVlu?=
 =?utf-8?B?TkU5NDVCV2Q2NWU5T0FUSFJmbFBzblh1ai95OGdSMlE0WWpvcEpHcDQxVnFI?=
 =?utf-8?B?QlAxZEN2a21CQmlYdWxTWkhaWnBRRlR4MGwrbDM0eC9VM3Uva01PY0x2Tmt6?=
 =?utf-8?B?YkE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <2DE18F7773349D4497C4E2636E96C550@namprd15.prod.outlook.com>
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: BY5PR15MB3667.namprd15.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1a2d3ab0-18e6-487c-08cc-08d9a970b13d
X-MS-Exchange-CrossTenant-originalarrivaltime: 17 Nov 2021 02:19:32.2285
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ae927fe-1255-47a7-a2af-5f3a069daaa2
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 9Z4KzT+7g04BlBqEn7A9dAvPkSDqWfCvR7Tc3XOl08TB29zgDxDwcd4ZF13jklqe
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BYAPR15MB2456
X-OriginatorOrg: fb.com
X-Proofpoint-ORIG-GUID: eEaB03tzDHzivai07-_NT1UhvUKsSgdP
X-Proofpoint-GUID: eEaB03tzDHzivai07-_NT1UhvUKsSgdP
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 2 URL's were un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.790,Hydra:6.0.425,FMLib:17.0.607.475
 definitions=2021-11-16_07,2021-11-16_01,2020-04-07_01
X-Proofpoint-Spam-Details: rule=fb_default_notspam policy=fb_default score=0 mlxlogscore=999
 mlxscore=0 bulkscore=0 malwarescore=0 spamscore=0 adultscore=0
 suspectscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 phishscore=0 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2110150000 definitions=main-2111170008
X-FB-Internal: deliver
X-Original-Sender: terrelln@fb.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fb.com header.s=facebook header.b=SlkrnHDL;       arc=fail (body
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



> On Nov 16, 2021, at 6:05 PM, Randy Dunlap <rdunlap@infradead.org> wrote:
>=20
> On 11/16/21 5:59 PM, Nick Terrell wrote:
>>> On Nov 15, 2021, at 8:44 AM, Helge Deller <deller@gmx.de> wrote:
>>>=20
>>> On 11/15/21 17:12, Geert Uytterhoeven wrote:
>>>> On Mon, Nov 15, 2021 at 4:54 PM Geert Uytterhoeven <geert@linux-m68k.o=
rg> wrote:
>>>>> Below is the list of build error/warning regressions/improvements in
>>>>> v5.16-rc1[1] compared to v5.15[2].
>>>>>=20
>>>>> Summarized:
>>>>>  - build errors: +20/-13
>>>>>  - build warnings: +3/-28
>>>>>=20
>>>>> Happy fixing! ;-)
>>>>>=20
>>>>> Thanks to the linux-next team for providing the build service.
>>>>>=20
>>>>> [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/fa55b7dcdc4=
3c1aa1ba12bca9d2dd4318c2a0dbf/   (all 90 configs)
>>>>> [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/8bb7eca972a=
d531c9b149c0a51ab43a417385813/   (all 90 configs)
>>>>>=20
>>>>>=20
>>>>> *** ERRORS ***
>>>>>=20
>>>>> 20 error regressions:
>>>>>  + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: expected =
':' before '__stringify':  =3D> 33:4, 18:4
>>>>>  + /kisskb/src/arch/parisc/include/asm/jump_label.h: error: label 'l_=
yes' defined but not used [-Werror=3Dunused-label]:  =3D> 38:1, 23:1
>>>>=20
>>>>    due to static_branch_likely() in crypto/api.c
>>>>=20
>>>> parisc-allmodconfig
>>>=20
>>> fixed now in the parisc for-next git tree.
>>>=20
>>>=20
>>>>>  + /kisskb/src/drivers/gpu/drm/msm/msm_drv.h: error: "COND" redefined=
 [-Werror]:  =3D> 531
>>>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame=
 size of 3252 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 47:1
>>>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame=
 size of 3360 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 499:1
>>>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame=
 size of 5344 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 334:1
>>>>>  + /kisskb/src/lib/zstd/compress/zstd_double_fast.c: error: the frame=
 size of 5380 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=
=3D]:  =3D> 354:1
>>>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size o=
f 1824 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 372:1
>>>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size o=
f 2224 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 204:1
>>>>>  + /kisskb/src/lib/zstd/compress/zstd_fast.c: error: the frame size o=
f 3800 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =
=3D> 476:1
>>>>=20
>>>> parisc-allmodconfig
>>>=20
>>> parisc needs much bigger frame sizes, so I'm not astonished here.
>>> During the v5.15 cycl I increased it to 1536 (from 1280), so I'm simply=
 tempted to
>>> increase it this time to 4096, unless someone has a better idea....
>> This patch set should fix the zstd stack size warnings [0]. I=E2=80=99ve
>> verified the fix using the same tooling: gcc-8-hppa-linux-gnu.
>> I=E2=80=99ll send the PR to Linus tomorrow. I=E2=80=99ve been informed t=
hat it
>> isn't strictly necessary to send the patches to the mailing list
>> for bug fixes, but its already done, so I=E2=80=99ll wait and see if the=
re
>> is any feedback.
>=20
> IMO several (or many more) people would disagree with that.
>=20
> "strictly?"  OK, it's probably possible that almost any patch
> could be merged without being on a mailing list, but it's not
> desirable (except in the case of "security" patches).

Good to know! Thanks for the advice, I wasn=E2=80=99t really sure what
the best practice is for sending patches to your own tree, as I
didn't see anything about it in the maintainer guide.

Thanks,
Nick Terrell

> --=20
> ~Randy

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/B57193D6-1FD4-45D3-8045-8D2DE691E24E%40fb.com.
