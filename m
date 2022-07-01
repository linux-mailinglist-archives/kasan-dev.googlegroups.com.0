Return-Path: <kasan-dev+bncBDLKPY4HVQKBBXPM7KKQMGQEEO7K2CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 23216562EFB
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 10:54:54 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id z17-20020a05640235d100b0043762b1e1e3sf1332750edc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 01:54:54 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1656665693; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZHWyxvlygVKQSWY65Vfcpy+4tJOCv9fiVrBZ+2iNwROgsPxQTsZCtODKoLafgNWfSy
         pAJzaINf2wcRpofLtDWkrHstIDBcGpFrvxYKtE5f4YcJnChijXupelami+T5sZN9f7vR
         /ogUBS92S0woieXh9+P0mLjkPdQQikknND30lmE16Aq2uvImInYXeTT+KpKYMkZaRS6z
         gy8RQYmzyBnN285Cgy+VjTmiq8xnkAxzWJoLAVKxzYNNIuCz7icjR/pSEXU/AutTGHJj
         +kysTe10s2jdt0KMjiB7CM5sMh2PGQ88ajEMOoBawlOvxz1TB0Cp2mbW4igj9oKHPmhK
         3/1A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=p3jWmAaBUbYwY78XrxVSA4RrjWRdUzixUShMznaKq9M=;
        b=RKY68A2fIejMfKAn4NN3hBhjURG6kEKjv/zkf8ZbauhpWx0+Qhj70NDYBOuUgWFoxe
         nl1CrfT66hMqoZxKRq1wNJIafrHgpNMT3i1sx9HRxwam9RkDJJJfNzAn8znFTCyICmjI
         t14QokPM7+rDaM/QarUEnoNTWWYGTPwQi+V1MHRSZH9vubJMPxIDd5pCvRAx7hKHLf1w
         M1D0lBt1jKwr4DQXGaeHEJTurLl+NqqIu5TpjG1MV5fLHvYjQd/De8UNB/0mMmwqf9c9
         hkrKwZxA3UB464zJrcRVtrAl2IgXTjkhLDBCrAS3+y9Aqp1xhiL21Gd583Dd3N7s6DFV
         66QQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b="h/EIfkOg";
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.75 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:user-agent
         :content-id:content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p3jWmAaBUbYwY78XrxVSA4RrjWRdUzixUShMznaKq9M=;
        b=j6t52rDD73i+xM2gPR7klwa1cNr6iteB+iV7gzVIywFLOkegiQQMa+gyR+iWb44MPM
         nc9jnLjelq5GmHk10N17t+96Gd0F+vo+flm+/se2w8XbxH2D1glCpRXGXuQLoBinVkIn
         xZfCs1pHbJ9ekvHH0p6ZZ07LzR4yr0bUXhQyh0JJZ7K5DetTr3buAVUOI7hLkT05LDYg
         zAkOQ4sK0YS08hBJZZOHHbuXa0Ae+aku9fUZmt7Wucs5JA8quV83cW7rUi7026oPrWJW
         oHHbdoz0MujIqd7iAkHwEAoFOHaUxFGEloQe5e9arKdB/Ns2RfkCszB22wWSk8qRG5x/
         T3Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:user-agent:content-id:content-transfer-encoding
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=p3jWmAaBUbYwY78XrxVSA4RrjWRdUzixUShMznaKq9M=;
        b=cF+zuDzdW6Bp55iHfRVWH98QPJGBhYZ3HnHdqT5gY+P3KT1gl5zxzQX3OAp/2FBBgp
         B6cIgyVJkkbLD0zzjtTGu3U+LnB4oakiRBuBA4M1sf6Fi9KqQBxFPlbJ6uDKknNjp+Dh
         L7si4vf3o8a0AWOYlZJciC0UX10xwvXF9qx5ONmztPIGmFkYDj5L7fOfS6bq6DnOh0F8
         9d83gYRjQNkT+ka4EhrA2m5pyXsoj9lZ4tPIQAfqaxUprcbK5nlRp0tzUqtyp7pAuI63
         DQ1iHCc2fKUMJjze5V+9U+GEa3uOo4ryKGOpaiKBsX0xKu5GUgVim/5VEenDP1O2skJb
         iXBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+ttPyeMrqdZlwyBMq07UvNWaBbPah+UA9JReJa4an6Fecsp+mJ
	xaIM/Ob2tm4vgY4T9At3wcs=
X-Google-Smtp-Source: AGRyM1tipP6+m/6XQM0uAipMc01L9TW9xjsLXxWgmWScUKmAZwMpARAM2Qu3XZMt6IiMFyA3G15JCA==
X-Received: by 2002:a50:fe0c:0:b0:435:510a:9f1f with SMTP id f12-20020a50fe0c000000b00435510a9f1fmr17680592edt.297.1656665693722;
        Fri, 01 Jul 2022 01:54:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6d05:b0:726:a6bb:94ac with SMTP id
 sa5-20020a1709076d0500b00726a6bb94acls2807058ejc.10.gmail; Fri, 01 Jul 2022
 01:54:52 -0700 (PDT)
X-Received: by 2002:a17:906:4f:b0:712:af2:29d9 with SMTP id 15-20020a170906004f00b007120af229d9mr13416451ejg.751.1656665692590;
        Fri, 01 Jul 2022 01:54:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656665692; cv=pass;
        d=google.com; s=arc-20160816;
        b=z2VYIqX6pLFQ0xLjaybZ20xTrsW8JIxg1geP/GHYxvIyhhrxmtc8VC/Bes3R5k+SMj
         vAJmKAyLuaQUTDKLPUoqgHQZLoMFXNh8MsfDodkbxlXmtXWScsnlqObJQ61QNSBbxYeD
         m/Spj8sEGCQCit2HyKCojRF0yfUnsI6A4D2KzORni9hpSPzGHsqiGx3DQe23aI2cNHs6
         Xi8n4Iy13GPua+K5mEacuf/ZtbNGFUOIRGqnSlRQQPapczdmrEiWNv7I+Br0oiVSjzUB
         3M1lGj79b81ZHXy0t3J7j6TLPrWTfSDsCzbHRp2YnkfSxE+IUoFmOx29exZdWXkBpIlV
         SIPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=Ml0AXf9dwT04QcS728BCd8cgvT8g5POAYmzDA6pF/Sc=;
        b=d3OLmxeO3o3a6seIQtCL+xKzw20riOFGq9JE6CUcIn36Xz8EqwVWX/ixUkT0lV/Bf2
         5B7lCbbKJx8Ebj4sl74+Sx11cwlDhBxuzd2+fuH8EgFKjoRyg272d+7aSu3DBHyGoELF
         ajNx+EcN0qODQ9S8S2bllYjRtz3cZtkG44BMUh15W7/uMmGfFrHtaFzZ7TQIOVGdeIex
         AldndG/4lweu9g/FYYh0kBMKlfJ3y6h37qumvw8pRg4UfDQiIUoE0qgcwnzcqm3p8+oI
         OQddGnpEG8Z5gjMikrKZvdwZg0BHmW0VpR/lzJHia3TgJRo8OrSbbLGc6ajfD+RWiHx8
         vJig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b="h/EIfkOg";
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.75 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-eopbgr90075.outbound.protection.outlook.com. [40.107.9.75])
        by gmr-mx.google.com with ESMTPS id jx1-20020a170907760100b0072a6696083bsi194741ejc.2.2022.07.01.01.54.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 01 Jul 2022 01:54:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.75 as permitted sender) client-ip=40.107.9.75;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=m4Zm2Qo4yGyxJ30A7bMq+qBjXfJxft9e0OsSWtRdS6qFCy7vgeUREvP/SEog5DtZTI/fMF8zWqW4kPQUHjVG3aCcxDprvu0T4anRy8fCA8vgJ9sXGLJ3SW/1/8Vgo0JcBPp+lPlzPCAnSKoo/mo6XK2qvCnGNAninnoymVL1GIYNTmSCWWEodlFf41+Nmncqaoldq1xP5xkM25RApqR6fEqfGzAxD59sS2qNVaQnoM677/gjsr5DMRNGu/cxsCj9fnhjzgwT4dPGmXZarbJoip/yai4wryAZ9hKutx1s32KD2BL2nKpc9zYU8cuNFeZZb5C/3PzlJIKOXXcJJ0mJpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Ml0AXf9dwT04QcS728BCd8cgvT8g5POAYmzDA6pF/Sc=;
 b=lATMpzkbUOgHtu6PJ7sRhPXUT8aFCc+0OhCHeqG7Jgmu7bImxWTobku4OH5UztYoGnOCLcpYdaDCunMbuL5Mvw+wIFZqW7UtPgNlAdh8RFZgnFPv5gzfftUmiGqpTOk6FnFWR6av5o3t2WJiAmxnfttVBeMs9EUv8MnGmYd2CeTxy7GoKBXVgy7do7tn8+skL7LdkjW+3XW30WTUluLkw1TzavwrVCgGogNORSWMYdwczkb7OkWhZwVG0qqA1U5NdmJuhTDMV2huf5NmLnu9KKAv8au3aTHVO7Xs44Ma5qW5GjJiO4IAb48Uudh/g+KMxmNeiolIaTfzWz6SoKYdkg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB3905.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:2d::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5395.14; Fri, 1 Jul
 2022 08:54:50 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::e063:6eff:d302:8624]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::e063:6eff:d302:8624%5]) with mapi id 15.20.5395.014; Fri, 1 Jul 2022
 08:54:50 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
CC: Mark Rutland <mark.rutland@arm.com>, "linux-sh@vger.kernel.org"
	<linux-sh@vger.kernel.org>, Alexander Shishkin
	<alexander.shishkin@linux.intel.com>, "x86@kernel.org" <x86@kernel.org>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>, Arnaldo
 Carvalho de Melo <acme@kernel.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-perf-users@vger.kernel.org"
	<linux-perf-users@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Namhyung Kim <namhyung@kernel.org>, Thomas
 Gleixner <tglx@linutronix.de>, Jiri Olsa <jolsa@redhat.com>, Dmitry Vyukov
	<dvyukov@google.com>
Subject: Re: [PATCH v2 08/13] powerpc/hw_breakpoint: Avoid relying on caller
 synchronization
Thread-Topic: [PATCH v2 08/13] powerpc/hw_breakpoint: Avoid relying on caller
 synchronization
Thread-Index: AQHYitZo2ef+XoeA/keVuMHbOZq9GK1pOsOA
Date: Fri, 1 Jul 2022 08:54:50 +0000
Message-ID: <045a825c-cd7d-5878-d655-3d55fffb9ac2@csgroup.eu>
References: <20220628095833.2579903-1-elver@google.com>
 <20220628095833.2579903-9-elver@google.com>
In-Reply-To: <20220628095833.2579903-9-elver@google.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 648cfb63-ec4c-47e0-92aa-08da5b3f5b99
x-ms-traffictypediagnostic: MR1P264MB3905:EE_
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: gtG6f9YjRKBlyaqRfiDtMg/Hu6Rl1aXS/C0v8G2XxTAzjo/8/v+f4gojdgHUKZyQ5dIxztzPb4W6rSexgkcRiGhIV9dcxWsdTRIKNn+jFEwgXD+cjgr9iNhVyJBNnjmEnfdCbCQO+P5sTjew1ZDuHaMTF7Wvz2SY/HDbzfZCRNn4vJ8/heMNTmhRfAdUIUdxtL4QYZwkLO58CqFEPispo884Qs9OESFHRbftU7LTsuGL/DgMdrnh1DMX2AUFJpZRrnvhBryHCIAtn9a84XuGYUuCyURamk3XSjNs7pDCMC25ECpIeNuoKNXjFaxhgGdDDynhaEnPT2shGBw6CzSPIBN6aHZ2trLWUBptbh3tgfpa0Vh2gN0KJ+vMb6RJAnNmqEbe8MoQwrz+r36yrA0Bk7OfT2VTk/c6UjYrcgzXEt7+D5yLHeVK3Q/Wlz5jVLZ4N6wWB6oNuhxG2Xjmf9NlBFeHygbDjWQCDr9+DTcCyib+2j/lvNOGOvWQK64ITD/gQR0NjHn0r82WMxiDzX2fOG6cSGTSzhHudhyi6MWdQSrSRak5Zq9DlyeyISmyLfAjn9/5/hHGhWqjo1skgEDvtDkeEOMbEwz/wmhTXMX+sjDmYWECH+2+ohvc5/AwTY3TLFSJNxzO9Vzq06YHyv+t3YTAE4PJNpo7ntKrJidCPKpQMNUAHxbQKjkkoS1tzzEjnM9Mk5pg/eSQ/LgwWZOskKoZIjj96N/DqS+Uv66KLFYjDMtA0CvIAp+s7LrhGZRIvDhG0TpyLXzilw3V7Z3droRof4skxH8MuxxGud0ROelNO4CvIifqsTpie8UJV771OnVuYaxNIqQHIAAYZIjFWx5s7vwXkRtOP7Ekzb6TqmG2+apojrUSNQEpYj6UJmSSCZAK6Y+ZgJGDCZ7o4yX1c7x2RBVTrmIwJAGnpANCaDE=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230016)(4636009)(39860400002)(376002)(366004)(346002)(396003)(136003)(316002)(71200400001)(38070700005)(54906003)(31696002)(66476007)(122000001)(66946007)(8676002)(66556008)(66446008)(86362001)(64756008)(91956017)(4326008)(6486002)(26005)(76116006)(6512007)(966005)(6506007)(2616005)(44832011)(5660300002)(478600001)(8936002)(41300700001)(2906002)(110136005)(7416002)(66574015)(186003)(38100700002)(83380400001)(31686004)(36756003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?d05zZGpCVHZsekhYUExSaXU3Y2N6akZuc3NYOTlxQmNVWlAva3oxWFZ4YXZy?=
 =?utf-8?B?dW9udGtZY2JCcFh5cmdWd1ZPN2k1enpHOHp2UXlpbjJhQjlsZjBOanY3Mkkv?=
 =?utf-8?B?R3lrNVpxME8yc0xFSXNnVy9kVGlHejNmYVMzbmI0R2JOMXQzYlhPK05VN0ZV?=
 =?utf-8?B?Ui9pbjdXWmpEOWFLWDBPRllNdE5RcDRrS1B5V1l5US8zemNCNyt4UWhzelJs?=
 =?utf-8?B?V1ljdW9DNXpBbzVaQXFvcERKNHhXUXEvS3FqQy8rdUMxY3pEcThsSnlPTFJl?=
 =?utf-8?B?UmFPenhkQm1VVmNQRU1Yc1RUd3F4RWpOTmVXc3BpSnRuQmV5SS9ucm4yZitp?=
 =?utf-8?B?bUtBZXhjamM1VVQzVnhzZE5KSTRnRERrWGljUDR6ZDN3dVliR0ErSDkraG11?=
 =?utf-8?B?WmFZdHZ2Q2JXdnoxbWNBRGZwdUFnWDR2a3dSZWpIREQyQzF4S1FhaS9wTStM?=
 =?utf-8?B?U3BVVGRDbkhJRmFUZVZ5K1Fheks1Y3owT3RhaWFzY2s0di9WMUk3bXZGVk5h?=
 =?utf-8?B?L04valI3N29MQTFRVGpsaWRZdHV2U0tjUm5PZEZScTRCaFpUNkRodWVsaXpT?=
 =?utf-8?B?TUpqcWY5ckJxeGs2U0VlRlJsZTVYQ3hJZ0x0VWcxYWxYVHJ6cGExZ1BHZ3JS?=
 =?utf-8?B?UEJNYlVBZzZ4bWRYWURuNDVvclNTYUNYWU11Mi96YlA1K2p5d2hmNlpzQjFh?=
 =?utf-8?B?UnpBWWFOUVJwMjlSSUYwOS9CZ1BlWUVualo5VmtlMnVPUjF3K3BRNTEwSGNt?=
 =?utf-8?B?TzhvNUdsQnRpOXFHaFdUN054QVdPWVBYTEN0dTkwcjhpMG95YWwyUXlYQTh6?=
 =?utf-8?B?c3p6RU8vWjFob3RNVGdRSzVuSndRdjd4a3Q0dW53MGI5U0NXcXNTM29Nd2hw?=
 =?utf-8?B?U3RubGdKVTluRjZFbDVjRk5JQ0gwaTh6SkFpcCtwcm5INlFDUzFFSDNWVE9J?=
 =?utf-8?B?ekw5bEpTZXJaOUdMTmhQWDkvc29ib1o1VllCUG02Zll1eHNIdk9BdWtFMkRv?=
 =?utf-8?B?aXBqMGxmOEVzSVlrQjN3N0g1NyttZFlyY2ZmWjBlRjh3QUc0L1M2Z1BWL3lD?=
 =?utf-8?B?M3Ira1ZxV0xiS1MweStPeGdFYkRSVnEvZmhEd0JUWHZhWUdaaDR6SWNjcHRJ?=
 =?utf-8?B?VWlQRmRkUzc4YjAvUUc5QTlsNGNtOVUyOXBXdmFOTkY1UWo0cjNtNmZ0czRO?=
 =?utf-8?B?UnRFN0JUM0c3VGE0TEN2Rlk1UWUxUklvWlBXek5ab2IrMC90b01TdlJHTjdl?=
 =?utf-8?B?SkZHVEFVell2NkJKOHo5UGQ5bEVGU2hBZmNCUW03d1M4YktLVDFCa09uaE85?=
 =?utf-8?B?eWh4cWRYd1ZpODJLYWtHYzdPS1JmMy9aajhtS0xvZm4zRUJuenpaOEczRC9k?=
 =?utf-8?B?enVhSXBRZ09QaXdGRHdpYjh5RmxjZkE4em5OeXdFUTMxeGNjQVlnN1BWaXdW?=
 =?utf-8?B?THJnc2lYZjV5RXhFemRJamp2VnNSSndTMnQ4WWZjVVI2MVRzTTBWWVhyUHA0?=
 =?utf-8?B?MnhXZzc2TFB0V2tCelluTmIzVjk5UG9GUlZja3luNGoyNUJkSVVBWkdwKzFZ?=
 =?utf-8?B?UWZWdXJpY3JpTUNoaXdyaG5zSUNJVmRlazZaRDFaUExsL0YyNTF6RzdlYUtP?=
 =?utf-8?B?WjJVMmRLUTcweTZxeW9saVNWbWp4UDZhS3JaMXdYcWRQU1ZWOW9URUtzNVhJ?=
 =?utf-8?B?OExSckJQWE02VlJ2TGhRM2g2dXBSRUk1ZW9CaXZ1UnZUbU44VVdFTFhYNVFF?=
 =?utf-8?B?MWJJSStXdVNoOVRRaVFCUGhwRGtZdVd5QXNQbGhpaEdIM0V6TitxNk8vaXBi?=
 =?utf-8?B?eElnU1M5WGtnRUFQc2J4Nmw0WUZtTUhZdlJEelI3NGFUaHlyVmNsMDZ1VW91?=
 =?utf-8?B?ZE45N09HWTFLcGE5UmQxNTBhdnVITVcvQUd2aEE1MWZvY3FiTjFXYVNGa0sy?=
 =?utf-8?B?dkprS3hJL09BWlZnYVp4VUgwVWZoaFdQZ0dkcHhsUWxaSS80UjkvNkhrVVp0?=
 =?utf-8?B?SDlwVlpaaEtWeGlzcWRFODdSazAxOWFLSm03NVJOZlJueWVjNUtFVXJDeVkr?=
 =?utf-8?B?YitmWS9DOHFXNTVGZzNpSys3bHpYSiszQ2FhS0pxRzV3R1hxMmZSWWRReThP?=
 =?utf-8?B?NjR5d2Z0SkFSUjJUbTdNWUNtVVY3c3l1MXN5WVlRVnhmZVNRSDFXc3QwVklx?=
 =?utf-8?Q?SuWmzjV0QUyBbLIlKcenV00=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <1313F1B72640054D94F22125F9DEAEA1@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 648cfb63-ec4c-47e0-92aa-08da5b3f5b99
X-MS-Exchange-CrossTenant-originalarrivaltime: 01 Jul 2022 08:54:50.3892
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: GIlfDkeBTxSkRly27JzfH1HNmArr35se3ge6DGPa7l5LflqnhAJQUiCJmCVH1I0HZgkHBzWyDHzG4yTrHxX1qdrLtXlwYkP4Db0BdE6DPJo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB3905
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b="h/EIfkOg";       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.9.75 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

Hi Marco,

Le 28/06/2022 =C3=A0 11:58, Marco Elver a =C3=A9crit=C2=A0:
> Internal data structures (cpu_bps, task_bps) of powerpc's hw_breakpoint
> implementation have relied on nr_bp_mutex serializing access to them.
>=20
> Before overhauling synchronization of kernel/events/hw_breakpoint.c,
> introduce 2 spinlocks to synchronize cpu_bps and task_bps respectively,
> thus avoiding reliance on callers synchronizing powerpc's hw_breakpoint.

We have an still opened old issue in our database related to=20
hw_breakpoint, I was wondering if it could have any link with the=20
changes you are doing and whether you could handle it at the same time.

https://github.com/linuxppc/issues/issues/38

Maybe it is completely unrelated, but as your series modifies only=20
powerpc and as the issue says that powerpc is the only one to do that, I=20
thought it might be worth a hand up.

Thanks
Christophe

>=20
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * New patch.
> ---
>   arch/powerpc/kernel/hw_breakpoint.c | 53 ++++++++++++++++++++++-------
>   1 file changed, 40 insertions(+), 13 deletions(-)
>=20
> diff --git a/arch/powerpc/kernel/hw_breakpoint.c b/arch/powerpc/kernel/hw=
_breakpoint.c
> index 2669f80b3a49..8db1a15d7acb 100644
> --- a/arch/powerpc/kernel/hw_breakpoint.c
> +++ b/arch/powerpc/kernel/hw_breakpoint.c
> @@ -15,6 +15,7 @@
>   #include <linux/kernel.h>
>   #include <linux/sched.h>
>   #include <linux/smp.h>
> +#include <linux/spinlock.h>
>   #include <linux/debugfs.h>
>   #include <linux/init.h>
>  =20
> @@ -129,7 +130,14 @@ struct breakpoint {
>   	bool ptrace_bp;
>   };
>  =20
> +/*
> + * While kernel/events/hw_breakpoint.c does its own synchronization, we =
cannot
> + * rely on it safely synchronizing internals here; however, we can rely =
on it
> + * not requesting more breakpoints than available.
> + */
> +static DEFINE_SPINLOCK(cpu_bps_lock);
>   static DEFINE_PER_CPU(struct breakpoint *, cpu_bps[HBP_NUM_MAX]);
> +static DEFINE_SPINLOCK(task_bps_lock);
>   static LIST_HEAD(task_bps);
>  =20
>   static struct breakpoint *alloc_breakpoint(struct perf_event *bp)
> @@ -174,7 +182,9 @@ static int task_bps_add(struct perf_event *bp)
>   	if (IS_ERR(tmp))
>   		return PTR_ERR(tmp);
>  =20
> +	spin_lock(&task_bps_lock);
>   	list_add(&tmp->list, &task_bps);
> +	spin_unlock(&task_bps_lock);
>   	return 0;
>   }
>  =20
> @@ -182,6 +192,7 @@ static void task_bps_remove(struct perf_event *bp)
>   {
>   	struct list_head *pos, *q;
>  =20
> +	spin_lock(&task_bps_lock);
>   	list_for_each_safe(pos, q, &task_bps) {
>   		struct breakpoint *tmp =3D list_entry(pos, struct breakpoint, list);
>  =20
> @@ -191,6 +202,7 @@ static void task_bps_remove(struct perf_event *bp)
>   			break;
>   		}
>   	}
> +	spin_unlock(&task_bps_lock);
>   }
>  =20
>   /*
> @@ -200,12 +212,17 @@ static void task_bps_remove(struct perf_event *bp)
>   static bool all_task_bps_check(struct perf_event *bp)
>   {
>   	struct breakpoint *tmp;
> +	bool ret =3D false;
>  =20
> +	spin_lock(&task_bps_lock);
>   	list_for_each_entry(tmp, &task_bps, list) {
> -		if (!can_co_exist(tmp, bp))
> -			return true;
> +		if (!can_co_exist(tmp, bp)) {
> +			ret =3D true;
> +			break;
> +		}
>   	}
> -	return false;
> +	spin_unlock(&task_bps_lock);
> +	return ret;
>   }
>  =20
>   /*
> @@ -215,13 +232,18 @@ static bool all_task_bps_check(struct perf_event *b=
p)
>   static bool same_task_bps_check(struct perf_event *bp)
>   {
>   	struct breakpoint *tmp;
> +	bool ret =3D false;
>  =20
> +	spin_lock(&task_bps_lock);
>   	list_for_each_entry(tmp, &task_bps, list) {
>   		if (tmp->bp->hw.target =3D=3D bp->hw.target &&
> -		    !can_co_exist(tmp, bp))
> -			return true;
> +		    !can_co_exist(tmp, bp)) {
> +			ret =3D true;
> +			break;
> +		}
>   	}
> -	return false;
> +	spin_unlock(&task_bps_lock);
> +	return ret;
>   }
>  =20
>   static int cpu_bps_add(struct perf_event *bp)
> @@ -234,6 +256,7 @@ static int cpu_bps_add(struct perf_event *bp)
>   	if (IS_ERR(tmp))
>   		return PTR_ERR(tmp);
>  =20
> +	spin_lock(&cpu_bps_lock);
>   	cpu_bp =3D per_cpu_ptr(cpu_bps, bp->cpu);
>   	for (i =3D 0; i < nr_wp_slots(); i++) {
>   		if (!cpu_bp[i]) {
> @@ -241,6 +264,7 @@ static int cpu_bps_add(struct perf_event *bp)
>   			break;
>   		}
>   	}
> +	spin_unlock(&cpu_bps_lock);
>   	return 0;
>   }
>  =20
> @@ -249,6 +273,7 @@ static void cpu_bps_remove(struct perf_event *bp)
>   	struct breakpoint **cpu_bp;
>   	int i =3D 0;
>  =20
> +	spin_lock(&cpu_bps_lock);
>   	cpu_bp =3D per_cpu_ptr(cpu_bps, bp->cpu);
>   	for (i =3D 0; i < nr_wp_slots(); i++) {
>   		if (!cpu_bp[i])
> @@ -260,19 +285,25 @@ static void cpu_bps_remove(struct perf_event *bp)
>   			break;
>   		}
>   	}
> +	spin_unlock(&cpu_bps_lock);
>   }
>  =20
>   static bool cpu_bps_check(int cpu, struct perf_event *bp)
>   {
>   	struct breakpoint **cpu_bp;
> +	bool ret =3D false;
>   	int i;
>  =20
> +	spin_lock(&cpu_bps_lock);
>   	cpu_bp =3D per_cpu_ptr(cpu_bps, cpu);
>   	for (i =3D 0; i < nr_wp_slots(); i++) {
> -		if (cpu_bp[i] && !can_co_exist(cpu_bp[i], bp))
> -			return true;
> +		if (cpu_bp[i] && !can_co_exist(cpu_bp[i], bp)) {
> +			ret =3D true;
> +			break;
> +		}
>   	}
> -	return false;
> +	spin_unlock(&cpu_bps_lock);
> +	return ret;
>   }
>  =20
>   static bool all_cpu_bps_check(struct perf_event *bp)
> @@ -286,10 +317,6 @@ static bool all_cpu_bps_check(struct perf_event *bp)
>   	return false;
>   }
>  =20
> -/*
> - * We don't use any locks to serialize accesses to cpu_bps or task_bps
> - * because are already inside nr_bp_mutex.
> - */
>   int arch_reserve_bp_slot(struct perf_event *bp)
>   {
>   	int ret;

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/045a825c-cd7d-5878-d655-3d55fffb9ac2%40csgroup.eu.
