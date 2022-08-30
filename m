Return-Path: <kasan-dev+bncBDLKPY4HVQKBB4OOXCMAMGQEQKUI4TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 98E3C5A66DD
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 17:06:26 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id k13-20020a2ea28d000000b00261d461fad4sf3219114lja.23
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 08:06:26 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1661871986; cv=pass;
        d=google.com; s=arc-20160816;
        b=nebmy8NuhjEtV8TI7xo6azeGa1Zm53QED+YPBh4gS4Uoe4z4w5WBCC49ruG+nPMUDj
         uKN+6xIYnVStMQr5pOjnfEv8J+JiCPEHnwFvHXByXnnz3HO8MxybasBuVaty0p/dDYfq
         15F66OIv5XEx1CebON36HrhgOTjpXMOBapdcqf/Z5BQF31jsMg/0OFXH40Fpf/691TX/
         dDy3DRtFfyU3Y29MrO01ubLyafJeB8V8P+SYBh8VpTwxwbICZJYnA0VipZSOB0e1iZh1
         aOYCy1iYjVC29IlqYJH7pDjIeg03wJf+uLkGMMEpQEilOhcu/+p6fIpcrvl4IhehiXmM
         T7Vg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=mu6Bov8Y51nYQnJzzYyQE3frOreKNBV1v77/6/Pw9H8=;
        b=DWxhEKkXXcQVAuHnq/Z4fWnMcbdl2l+G56hPXzC+36RmzKU/8L3WB+25Gg7UjHBeRN
         XZenSWiOpV+9UyHM7xLYsWfxjXb+2rCnS8hiHs4rHmnoF4YpFyVKBRV5BQsbXQZxa2Jx
         roeTJ5dx/Ln76elDwzfmjGJWCmmFIdkqFUrr0XRYXCgwtyV9kCI96Orimf7Fjea1VMe9
         rA3ygjD1g0ESuo2F9L1JnjaQm1Y6bxbVL4QWVN2ITWaNe1uh9nrICdBvszziGZu8pUJk
         gvlDJk0HHI446LEqqfbkwSYuuOD0tTO81YB4qdCtMPWrneicF+wAsqiETLyfIu0nHCpk
         v9vg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=Ej+wHolB;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.83 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :from:to:cc;
        bh=mu6Bov8Y51nYQnJzzYyQE3frOreKNBV1v77/6/Pw9H8=;
        b=AtZeN8xnG4X6zarJDdnTJXR8bBMgiUKWfKmO0ylDmEIRQenvOQUVyPl3zdPcKqiZD1
         vcNxNMfFKjdo3hfRX4zmXrurlLwR2VYhcoiCvvcIeF2MBCmU3DvgBxj+KC1ikuR6Vybb
         2Mnrts/TGIocJ1E97tWuIGht14h174axV4GDRv5IC3AVQcJh7XAAq5E/IOfrvvvdCwpn
         1zE2/ROetuhyJhkZnwL2SGH4TZAY48T60x3dwzYBdfqpbZ92nOKlVAaeZGbTzZuszUpk
         T9MkA7s2CsjObuxh+yj66ZB5k4sCxQneJUpd24eCToSLdAk3ngoAa+JPK/0z/tsEtdtQ
         hhdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:sender:from:to
         :cc;
        bh=mu6Bov8Y51nYQnJzzYyQE3frOreKNBV1v77/6/Pw9H8=;
        b=FjDxUrC7cTD15/SOkMjMWn7DClwvy/IYx+ABvWxTFYdleT1TzG4ZSbOhWiTpT0NF4D
         tS8JN8WknGru626RmCVxEh/sV+XrNb3gFDlEyFDYiNda7dMs+Vgx2frYeQokMSZPaAqu
         Tww0a7WFBbCij7fiEZi2zhQ6abBiGgPy7KaH6rCHDgax3uQLFNTvL+QXok3Jz3adVYc9
         HLCRWQ5qF7MLElVFdrHoawp9iNSt0Vg91FtlpOfGcOrRl3fjoKTbXUXtQmshLS4Sizb6
         aDDx7toNH/rGTQHS/OnX0onGQP/h02sWljKPklXhXO9VE4cWN414hLe3NfC1k0aowps4
         1j+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1c2rZ9JMKg3LIZa2QiBuLABoy5EP+yVjHaEvIL9gQR+sxdb+EG
	mSRIRuBAeYA/G3KfpnuMA4E=
X-Google-Smtp-Source: AA6agR7D6as9oc7wnIzgtc1kODHYdizOOVQwrI9NpZuEeyVs/TabMvFG4j65NGgEQySr+VzLKOYGKg==
X-Received: by 2002:a05:6512:68c:b0:492:2f73:6135 with SMTP id t12-20020a056512068c00b004922f736135mr8298248lfe.480.1661871985926;
        Tue, 30 Aug 2022 08:06:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls1281819lfo.1.-pod-prod-gmail;
 Tue, 30 Aug 2022 08:06:24 -0700 (PDT)
X-Received: by 2002:ac2:4bc1:0:b0:48b:2b20:ed24 with SMTP id o1-20020ac24bc1000000b0048b2b20ed24mr7388695lfq.67.1661871983912;
        Tue, 30 Aug 2022 08:06:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661871983; cv=pass;
        d=google.com; s=arc-20160816;
        b=VejlP7KDus1gXhkq8zFtDOrKBfV1Npg8QKs2RBdVKO/JTbNIgIhtDMeJ6eSniLh8VW
         5AxGmETd7ZKRFuKcJOMkmx0sJfsvGp7RFL3aKMLRmlPv4Q2k//jp0A/Oay6R2Eex0b7X
         1lqHXc0FvWfeETuxTXHEA+7kBL+xHLXZMrF74aFErWwf1rXOxXMEixN7q3KqoSzK5+Tw
         Gtf7gCGmMO2sCWiGwQ8xZM/LaS/N6Wi92hoH733cZvteTzNnitlnkAQlU+XXSZl+A+qU
         gpOaWYMrD89ZEy+Jz7IwveNBEEPgCaIV7r9KpjpCOH4S2FrN/K3piDIIWTb+ShZZ7gyX
         FiuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=lG4jdpTkHOvXzIgATS4yYyGV6Sr2KWeCVf2ozBr8EV8=;
        b=Of8ux9kVckw30mJNJDewPbpufQ7ILT6QiZO/EehWXeftY9ICWIlIb3/1zhefqFzeCF
         y0NYxNnPvMxw1Atzp8hCQzQYNVqZ/sHuoCwRkD+5C4mvcwDUrqgsqCcUaCoC39x72lkK
         t8UVzDIO/KM1Fl2Nxl23fEOrBFp4xpFsu1h+Dfz+zNktnTnc5Ls0lpi5PuDvhaCB4GxA
         TjC0pWrSSSkZONCxgdXbUZf2yhBFxcxZEiTNGAcvH6GbJdFAEmedXFJ5M4Od8/LlWgz2
         pkrCXIm/10HCKlxHa2n92idfYjCBDGB0JHM/2Q/KkgavV9QnINM4awm8S4O7k6Nh71So
         G+lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=Ej+wHolB;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.83 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-eopbgr120083.outbound.protection.outlook.com. [40.107.12.83])
        by gmr-mx.google.com with ESMTPS id u9-20020a05651220c900b0048b224551b6si578331lfr.12.2022.08.30.08.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Aug 2022 08:06:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.83 as permitted sender) client-ip=40.107.12.83;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=JgA6TMMexxOzn9VVDSQTyFmvEvxKFDCTBje8Ecq5O+76Ivd3Iqf5txZLrWun1l/apgWs5y729LYn3usYykmyxyBCdR/Opo1gxYZb3ctTP+v0XAt+7WkuUZRIpqHZjOH/zt3tBTMCJWSoRmX6JUvO4pWLVTZaPtJsMuhbe6mFpriMEj0hzxkI51yC/wIFZp2WfH5910Zav7yT641zj4ZMqIp8x2qSJLJ9HJXoJ4kIRdD9O5wk7ZTql/tPmIBaI8ZtXy16JHZ0hLDZU4bNLG+LHBmdEFs4xVG7VmG127lGWBtCN77jPLvprQAQFkrkZNX/S6jOPNEFsbg22mK/WnvVtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lG4jdpTkHOvXzIgATS4yYyGV6Sr2KWeCVf2ozBr8EV8=;
 b=TSqfJRnouGJYYDImfMW/iufTe7cLANzWRFAAmvNN34WKDE2URKNQzjp/gjTodQAFS9621SYtlYK7fVLYw8Yyx+xEaiaY6+hRXXIDSp4/PjskHF5usNZa0eMl9WLd/zNXEf2XmM5CoK5W6TTIovGM7HmreBIiz3J+/GOgziLa0ObQLtI/QriFmrsSwrZF4cHiYlgRIlGC/wAr+zrkrHe8mxE+dbGcAHphFW/qE9StfDhqel/n/M7Vag4BGSeaQkS8zKCx4wr1YWyf9qfzGb2ISBMXfayEyJYJLinGYBapsSDsFB1+B6QgfgBNstPSwlJGX0o+XKN407GZpvx5gkn5pA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR0P264MB2997.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1d4::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5566.15; Tue, 30 Aug
 2022 15:06:21 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::382a:ed3b:83d6:e5d8]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::382a:ed3b:83d6:e5d8%4]) with mapi id 15.20.5566.021; Tue, 30 Aug 2022
 15:06:21 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Alexander Potapenko <glider@google.com>
CC: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
	<ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov
	<andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann
	<arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, Christoph Hellwig
	<hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes
	<rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet
	<edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich
	<iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe
	<axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook
	<keescook@chromium.org>, Marco Elver <elver@google.com>, Mark Rutland
	<mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, "Michael S.
 Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, Peter Zijlstra
	<peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, Steven Rostedt
	<rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik
	<gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and
 put_user()
Thread-Topic: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and
 put_user()
Thread-Index: AQHYuV2zgoiwrRRxuUOabTtvU9EmQ63HkWMA
Date: Tue, 30 Aug 2022 15:06:21 +0000
Message-ID: <51077555-5341-cf53-78bb-842d2e39d1ec@csgroup.eu>
References: <20220826150807.723137-1-glider@google.com>
 <20220826150807.723137-5-glider@google.com>
In-Reply-To: <20220826150807.723137-5-glider@google.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.11.0
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 33168c62-9f3d-4adc-6be3-08da8a99330f
x-ms-traffictypediagnostic: PR0P264MB2997:EE_
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: hoIkqG7rA5cLucG4YnuCHFaKDCGOUXOfVaU0vAL6k7ajyoZ7NW6GvPt72Ss+/mWlFZESAl/KZNFI8Erjojo4uo+HtecgJqfUbGjLkptinGx5t0obDauP7M3WiK9Q7/mb7LjWrHjoF0AGSlpjORn0UdDoQEl4nNq8/qgW9Eopk2Iq7NgpYo6XAELKYeZSJDGqKg569ZPWtHZ/rPkII1IaYFieVyYCMVQheJXlQ6G6cpyutEUefhy7jnOxUIzZGuhuDnmW5VoBC/ObjE2ncFSfROQdrXCMpUTIt5SmK7aa6ZsSPq02mdo4WkcTI3KyOOl29r/Uyd6cKz3GgGNBEl3IJNO0sPHqqKyJ9zn3TLmRKrKrVhKq3shG1jqCNNhinA22NZxluAkn2Ylxzu1IoBAtK86ODzFXYa9DNT+boiYKGwTPQwlRhVGy8dsv1OffCcU3THrIIXVTS7mj5TkK4xI9QepzI94bStPj7hIe/O6sNDU8Z2wHht3GoodfZF9zkXNAMuXz5TMOl7ukIF/KhQdRFhw8/km9lIUNL/RiFESx7dTm3ONB90YO1FYK4hm45/nu+cJJEkYq/VnJ1e9YLkSeJ2hypPfkRTX0WfqSxoGht3gzQzXMWwOJ0E8djmWeUTfhxCSuI08vVeLU6lI4rV6JOndDk8peHITd3cf65JJCkBFmOJiJVNi8MkhHJLWlTw2LpjAk5aysyVXd0/RVZHXdHyubccX6JwkGRf9gTA3Q45U8kNzFQWKq6yRMEpRMPj3mJ4rTnpg2TWxfH8uom1v+h7kRhujZcRTuAagVmcTvQfzzWMk7ol0wVvSNHIqu/dZ95DocOmJO7eP0TyRTMMrxqNECTESRBj+KjDXa3HNP+zM=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230016)(4636009)(346002)(366004)(136003)(396003)(39850400004)(376002)(6916009)(66556008)(83380400001)(36756003)(66946007)(31686004)(66446008)(64756008)(66476007)(66574015)(76116006)(966005)(316002)(478600001)(54906003)(4326008)(8676002)(6486002)(91956017)(2616005)(86362001)(7406005)(7416002)(5660300002)(26005)(41300700001)(2906002)(31696002)(71200400001)(186003)(6506007)(38070700005)(38100700002)(122000001)(8936002)(6512007)(44832011)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?MTVMTjcrL1pta05HL2ZOaTNZRlgySEk5aTByUFhZQXZqcmo1VitJeGxhU0pm?=
 =?utf-8?B?ZllTSEVFVzdOYmVyU01BOEhjbHkxYUVBbEE0RFFtM2pac0RsQ0htdmlJdUl4?=
 =?utf-8?B?b1RKZFVQRms1V2lKcWtrekQwelBHOFVTR2tWd05EWEd6YjcwM05aWC8ybTdu?=
 =?utf-8?B?RUh0ZHIwdFBUeDdUTTJ0aDZCa1RkQTh0VTVNSU9vQndjOFpHcEVlUVV4dzVq?=
 =?utf-8?B?Y2RsdVFtYmlYS1E4U1NGVUhuOUlsZ2huQWtsb0FmUW9WQkF2eENnMUZGaUdL?=
 =?utf-8?B?cHZtZVkrMWlFTmZJb2NwaTZRMFFRQTdNVkovd0FvYWt1d21XaE1QLzRxdStq?=
 =?utf-8?B?NUYyS2ttb1I0dS9JUkVWVnFmbnlNNktLNVpoVE1obGhvbU4xeUowblExT00y?=
 =?utf-8?B?Y25yVEd5ZGRqTlduYjhVbUU2dDdVbU1aZmo3N3F5a3JKWWc4NldweCtSbmxh?=
 =?utf-8?B?UFN6SnY0VlV3SktoVFY0M0RvWndTZ2dFNUxTYk84eGlnZUNkaUJkUmMvUWFR?=
 =?utf-8?B?ckQrcWl6S0JFRTNPcVJFc2JPODd1KzUrZXByc09qYm15Q0lNdFBCNHdCWnpx?=
 =?utf-8?B?UVRBZHU5UENCaGFnVHFsSjJ4ZXIrQk1aYjdBdm1TdEdlUllNYkNCZTk4RFRy?=
 =?utf-8?B?amt1ejJ6eHdMRnd4MnB1WGtRT2FpdERrSFFtVUpsN1YwT29OemkwK0poSFcw?=
 =?utf-8?B?cjA5UXdBRnE1c0dpVVZVV2hJa1BXK1FndVcvcDBLVFFYdVdwY3dEZllxNFZi?=
 =?utf-8?B?NVVRQnlPZzVYbVZmMjYzZFlWaDYvVVpJYWNMS3BVM0dDT2tTWDlOcDRVZFFY?=
 =?utf-8?B?cVp4UEJ6NlVVbExYUmUxRnE4dEEwdThYc2R6bEVyMVJFMCtrTXNXVEMwR2cy?=
 =?utf-8?B?K1NmZTkza0h5a1UxZ3BjOVFKZC93SUVYcnh6QkpqcFU4Tk05am5lWE0vbDc2?=
 =?utf-8?B?WUZxWENHTEV1Q0toVXRZSVV6MlRUU2lhdEQ3b2pZSi9LL2FIblVnQU9WZThL?=
 =?utf-8?B?eWlRaUFuU2lCRkQrR1NCYXZsejI3N3cxdWM0UTR1dVNFUVJhdkpDSmdQK1I5?=
 =?utf-8?B?WENqRGY4aXJqd2QwOHJiWUVoKzU3V1U3cHZLUEUvUVoxejdjQVNlWjZsem54?=
 =?utf-8?B?Yk5IWTQ1RUFtclJQLzhmbitJMENIWDVjaUU3cTh6KzJVeUVUOW00emQ4cnhU?=
 =?utf-8?B?NlFMcEVRTnBuME9zbThoQ0M5QlR2KzZmc0tsZDVVMzNwblRTank2aUJpTHp4?=
 =?utf-8?B?bU9hRUcvdnVtTmd0QUF1YkJaMTV4UFdqSFpiWTA3MlpFMkk4bnlVL2hEekZY?=
 =?utf-8?B?aUpWd3BXWWt0YzVJUm5ydGdPNmpaSFNOUm1YZzd3QVVONzFjck93SnBxSWsr?=
 =?utf-8?B?TzJXRi8xSGFTTzdGM0dHclpwaWlKWGU5V1ZQQWlPZ0ZMekdldm9Da1dHdHND?=
 =?utf-8?B?UTY0V0lRRnEwMldYMkhJeE9xRXZFS3FYV2RKcldmaGt2N0ZFT1NweGREV1hi?=
 =?utf-8?B?cTNQdFN3ZDZHdEJGUy94VTk0T3hOcEhqRlBPbjJZWXpITzdpM1dBRFNPVjhC?=
 =?utf-8?B?bkhGRzcvMTJDYW1nTk0rUmVRcXNmcm5lZDh2QXQvb1pZbEhpS3dZcm4vVjY1?=
 =?utf-8?B?MXBpTXN3b2x0Wkp6bG1GMlZac3R1Q2lBWm5jVVg2Y3Q3VWtTaGRUK2NPd1Rr?=
 =?utf-8?B?aHJWMjlaRjNITVFTbHF6cWN3ZGo0YWE2Sm0rcEk0cjlNcVY3Vzh3U01qeGJ6?=
 =?utf-8?B?WW8zYXZ6NzdBTHRMaU1aNTAyQ0RNYzlRdEc0VEUzdGRENS9XM0NMaGVhTXVB?=
 =?utf-8?B?bmp0UjBVeHVSN3BWKzd2VVVGVnh0eDlIbHdHTUhPTEVsN1BOdElGaXd0Zzgx?=
 =?utf-8?B?Y3JDZVlNQnZGMmtVWXRaeTdZRE4xYi9IeDQ4VEt1NjdSMWl6Wi9JZjNNaXZF?=
 =?utf-8?B?bExXNXkzRWlKTVcrdjJCLzdKVHo1K3ZjZkcvTjk1WG5ZTEl4YmlEYWNaWGdy?=
 =?utf-8?B?aVpUUmthekY5LzRBM2VOVjREUUN5NGtrcHVwZFkyYlNVS1NEK09XNzR1K1dN?=
 =?utf-8?B?M1lYL2RvSU1BNWtyTFdCL0ducWg1VUd5eHlaRnVUMFpFcGtLNGRRMUgrK2pR?=
 =?utf-8?B?NjA2OEVkeHh1MUp0YXhDcHNZdXE4OXRHMU5HYzljM09SK1BiSEZ0eEgwbUVp?=
 =?utf-8?Q?cblbFMup+a0SVhTihtRwcVQ=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <7940925FCCF9C84EA7C7B7718689F727@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 33168c62-9f3d-4adc-6be3-08da8a99330f
X-MS-Exchange-CrossTenant-originalarrivaltime: 30 Aug 2022 15:06:21.7312
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: w/fh1OLU/QWGZDmySwrDxSa293tuJ+Tj3/rit46M1SXWaxeYL/Wwxmdj+BKuY0upUWB1swpgtLPMbv573Bflpg2i9S82/9tNWcAhvRAcddk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR0P264MB2997
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=Ej+wHolB;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.12.83 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 26/08/2022 =C3=A0 17:07, Alexander Potapenko a =C3=A9crit=C2=A0:
> Use hooks from instrumented.h to notify bug detection tools about
> usercopy events in variations of get_user() and put_user().
>=20
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v5:
>   -- handle put_user(), make sure to not evaluate pointer/value twice
>=20
> Link: https://linux-review.googlesource.com/id/Ia9f12bfe5832623250e20f185=
9fdf5cc485a2fce
> ---
>   arch/x86/include/asm/uaccess.h | 22 +++++++++++++++-------
>   1 file changed, 15 insertions(+), 7 deletions(-)
>=20
> diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uacces=
s.h
> index 913e593a3b45f..c1b8982899eca 100644
> --- a/arch/x86/include/asm/uaccess.h
> +++ b/arch/x86/include/asm/uaccess.h
> @@ -5,6 +5,7 @@
>    * User space memory access functions
>    */
>   #include <linux/compiler.h>
> +#include <linux/instrumented.h>
>   #include <linux/kasan-checks.h>
>   #include <linux/string.h>
>   #include <asm/asm.h>
> @@ -103,6 +104,7 @@ extern int __get_user_bad(void);
>   		     : "=3Da" (__ret_gu), "=3Dr" (__val_gu),		\
>   			ASM_CALL_CONSTRAINT				\
>   		     : "0" (ptr), "i" (sizeof(*(ptr))));		\
> +	instrument_get_user(__val_gu);					\

Where is that instrument_get_user() defined ? I can't find it neither in=20
v6.0-rc3 nor in linux-next.

>   	(x) =3D (__force __typeof__(*(ptr))) __val_gu;			\
>   	__builtin_expect(__ret_gu, 0);					\
>   })

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/51077555-5341-cf53-78bb-842d2e39d1ec%40csgroup.eu.
