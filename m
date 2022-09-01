Return-Path: <kasan-dev+bncBCJZ5QGEQAFBBXPAYGMAMGQEIEAV42Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AFB35A9240
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 10:42:06 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id b4-20020a05600c4e0400b003a5a96f1756sf967414wmq.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 01:42:06 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1662021726; cv=pass;
        d=google.com; s=arc-20160816;
        b=MMU7nO+eQHJrOv8BuoMwgrFvCoxk50PdK2SFRcbRq66IfvBmMtLEpglhXxTaruugbU
         pz5312BL0ccCvN2pdnjhKSxDLNZrmPB+SMOj9NLLI/GjEOmVKiftEbJKD2X2mAQ/fYad
         irzZDvb2XXCnP0jmzE5l4wX/WccJVJ+6Dbv7lOkV5PWzUmF9cfeVOPoZSXwalccMP6iu
         0eHWMZRuV45S7DwnM4Ii9Q3PgmdpFpSqCmJgvhjvOLuzIfNpQQCtaarn3IRTVXIQy6N8
         unMa1tap/Vfd7LNut2EcFAaEqlFWcNrsqP1Wt7IjHzk/tOPaU+wI8XMmuTPMIkeNYA6e
         MBUw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:date
         :message-id:sender:dkim-signature;
        bh=fAaZbUMHxMILXn3XziXfPSdWKl5T0EikWVnRhihHkrQ=;
        b=a/IlaS4vwqV4vwrH21+NEkHS6nsVT7OxSH6fy1Ms/sj8FMror9nrXGm2rceXpPh9jp
         My/czVXoBV9grjrRbTS4ad6mhrfnXE2MjfMSwxmwIDHBXm81i/67ineWbq5VplYwJfNz
         ICmtEUxhZZUyo225f6wGG44e24ie9ZCq5lyfn1BGRBO+L/IxoWRFM+xiuA7iZfpYvZ/C
         /66BEjL5+nfxnQAACfA3TAlk9d+diZB7m1u1NwhVam4S9VklsBLlyj23OdPptce6OBH0
         A/gDOmse+n765MjB5ATEKixxOaTpt7cmh2XuzscsyJXEz6gxvKu1Z8C1AbH/qWYU7w7X
         AXmg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b="g/oVnBqL";
       arc=pass (i=1 spf=pass spfdomain=nokia.com dkim=pass dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.8.139 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:sender:from:to
         :cc;
        bh=fAaZbUMHxMILXn3XziXfPSdWKl5T0EikWVnRhihHkrQ=;
        b=oDncjGQLNRND1hCnZefi0zp775KRCBjx32B3oA9qOiiqby9S2lR51j8b1//zwPIu6D
         192/vbzgEz7pYu2UMEgepYvnQYs/GuO3/Fz94CZWjGkh4W3HcKdYSGXE/1SiSl3xTL1L
         pN+FVWk/wr6pJxIMuvD+oZEsrBP6iSWYsERu3eVA+FH7Ts73Qcu5GHy7yTQRa0sNTWU+
         qMk0pX57ZeS+pbKXPveXpeH3HK7wKLIlQaWe4daGmSUllFCjC7S4IoVUIPXfOOFZ8URM
         lmBMEVLHOsre/SsVmoZvYhxmRUF8IqnBvVJNEGcgi0dg+4st3zzdeiI8qOwJe1aIBws0
         pkRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=fAaZbUMHxMILXn3XziXfPSdWKl5T0EikWVnRhihHkrQ=;
        b=XJXhPxn98DHFJ9lthqrDClDfkxDZPGjA/PLo2n0Ib7fCGd1GkBpwiF9MO5MYqE6Wt8
         hTz/SGf2dCy5D0C93tQB656z/dgnB8Ms2xXsNiRs0Ft501C0gIuyOh3zu8h3ztGTYEz4
         CKERbL/UauxP8JF83q9rt5639niyyI1Gfxsi3V/7X13aeKaM/49nFzbrsAD4cKGvafJg
         6yBNCrsbcK4JdQN5X604/qEuq+xD0TTOImoi0znGjUPvGnMVo//frXGKCMmXE/vWY2Gd
         XNy0lulMYoW/G5R2CYA06AjWL3Nw9Clc3ePMwFGm7RHtQukHR67N0vY3VqlXzIc032IF
         wkLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1MU6h4Fx3CWZ6aVIu7qlvVFJCFnTjETQ4WKt/rUvLuG2NLDLck
	k5OGK0LXBjzhxj50egMFfK0=
X-Google-Smtp-Source: AA6agR63vycisdeHiZ/2Scm5S2wxk+cr6Eyo1ibrHDjO/eNeMvv5yiFurpa/pKopR2alb2yGOz3Ocw==
X-Received: by 2002:a05:600c:1c1b:b0:3a5:e6ec:d12f with SMTP id j27-20020a05600c1c1b00b003a5e6ecd12fmr4435550wms.2.1662021725719;
        Thu, 01 Sep 2022 01:42:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5b08:0:b0:225:6559:3374 with SMTP id bx8-20020a5d5b08000000b0022565593374ls1907934wrb.2.-pod-prod-gmail;
 Thu, 01 Sep 2022 01:42:04 -0700 (PDT)
X-Received: by 2002:a05:6000:1861:b0:220:68e0:ac7e with SMTP id d1-20020a056000186100b0022068e0ac7emr14874998wri.376.1662021724854;
        Thu, 01 Sep 2022 01:42:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662021724; cv=pass;
        d=google.com; s=arc-20160816;
        b=VzD27Mnq/VlNq+AbmsUYXSEAaiYTRKYDImEANkHBWo121Anj2jJhKdEqEUPIe2TKDS
         evccDaLn1fydevxajx6rSLdO+xcjgtZh+498KPaRJTg28sXDPNtwFgpsorYUe6iyOJ2F
         QDpUvTbNGdHe0BBdy8B2W5aWM+TKK20XuBR0CObpvvGrrr4muM4AwzykLf5g2lriaEo9
         VRN6j8WBkaMD4/VVFVgegi8/rwouDN1J+mLyTXYtVslxJDg3gfe4FbbE82N9UhhxftuP
         K0Eu96CXHgBQYIiRqLX5MEXA4teP5vM0KOo341FGy8RzqMBMUxATIMvyhUbsTHNjjPGb
         46dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature;
        bh=uhokj4qEhrWR2R5XusB+WLqCDAPCr0rwwaKcebjsgOI=;
        b=AkZyRqaDq8c35zdJwc6R/t+Un72QE3eXePQ2NwVcsmW5eRwYkA3UTS0jdX1LCIQ7Uo
         wCBqmm97DAexOD58wsVsfHL0uIOTbFIj1+McNdEhb588AGeGjtvr0R4MxzEk8EXjbA4Q
         V8QysCo52URTyZLdl3LpitNQ7ygCK6l6Fu08i5feKq6Ecup3wFsRxKaQBg5/eHCWonjq
         qjz6DFXtV0LUjAKHl+zim7eSMwP9zvD+3D93+X0Na7Lflk4rzXB54+L8mRdY0+49RwGB
         IEw1Z+rrXfmCEIJQYBzxxXqhJHvXIZznsw1kqiBXwBNS1ofAN0KMGZ0IzgZbSnQMHgOC
         1V8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b="g/oVnBqL";
       arc=pass (i=1 spf=pass spfdomain=nokia.com dkim=pass dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.8.139 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
Received: from EUR04-VI1-obe.outbound.protection.outlook.com (mail-eopbgr80139.outbound.protection.outlook.com. [40.107.8.139])
        by gmr-mx.google.com with ESMTPS id cc18-20020a5d5c12000000b00226df38c2f0si452802wrb.4.2022.09.01.01.42.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Sep 2022 01:42:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.8.139 as permitted sender) client-ip=40.107.8.139;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=MjoYo/+BWCxBdwgj0gFTiI3nDAMOBX5M0e4SYO+IDGFU7j2b65E5BclHabTVaHL1sRUojAzJgD1YjkuOXZu8LhiiYYKv5BZpmtHOxeFxTJYyw7suCf15MzwSXgN73v7pdT1yZf/SVETDZN0FyHH90XMv6TxjeY2TU4PIFo1F4cFmVVYJe+JOgV54T9GwJ3R/sBdZyCS5Zv0dHh2RGlo/aTVQNusJOy05h5JX3p+Q0Ip84l5Mp/ROqGU5L20MW1epCee0w7NcgwVpJVZEF3mwGi9f34RVs6bzVceehtLgJLM89egQgDWRGbkAcDWJMPhJBvM+HStQCIseBK/T+Z3Zyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=uhokj4qEhrWR2R5XusB+WLqCDAPCr0rwwaKcebjsgOI=;
 b=k4ZvYMGlbHWf4Ta5ZTXsPmGgUVqVw/5hycOrlFznjjZ580HA0gQ4NFBTvnrhjiZq6SUmy8t3TKcphlNkaX8zjVy3O+AwBsSEzjh2TolIKwZQz1HT0zcKBhTrSA4IQGd/o6zcOP2VyVK1uoElcjf2cJKWTcZ9pJikFKWGqkV/AK3MfU9kLZYYo1sKr9VjR5jQUpDiSRFn2FFIGgTxAHX9Jx8dgYVR5KGItFfMgiQiWybusHLJQcfWjYiXXpDVyup1NKMrw+O5T8BBMKfWa2KGdqP2V3ISod+KAuTa/pPHLifDImsrLTFax2yYd8mO9fYRHLG6hqE5YaQYjWziRlj9Lw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nokia.com; dmarc=pass action=none header.from=nokia.com;
 dkim=pass header.d=nokia.com; arc=none
Received: from AS4PR07MB8658.eurprd07.prod.outlook.com (2603:10a6:20b:4cd::12)
 by AM8PR07MB8230.eurprd07.prod.outlook.com (2603:10a6:20b:325::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5588.10; Thu, 1 Sep
 2022 08:42:03 +0000
Received: from AS4PR07MB8658.eurprd07.prod.outlook.com
 ([fe80::b333:1f3b:1b01:50d9]) by AS4PR07MB8658.eurprd07.prod.outlook.com
 ([fe80::b333:1f3b:1b01:50d9%3]) with mapi id 15.20.5612.005; Thu, 1 Sep 2022
 08:42:03 +0000
Message-ID: <ccde957b-20b1-2fd6-5c90-ad9ee4b8924c@nokia.com>
Date: Thu, 1 Sep 2022 10:41:58 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH] ARM: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
Content-Language: en-US
To: Linus Walleij <linus.walleij@linaro.org>
Cc: kasan-dev@googlegroups.com, Lecopzer Chen <lecopzer.chen@mediatek.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Russell King <linux@armlinux.org.uk>, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org
References: <20220827213009.44316-1-alexander.sverdlin@nokia.com>
 <CACRpkdYgZK1oaceme6-EEuV3F=m1L5B3Y8t6z7Yxrx842dgrFw@mail.gmail.com>
From: Alexander Sverdlin <alexander.sverdlin@nokia.com>
In-Reply-To: <CACRpkdYgZK1oaceme6-EEuV3F=m1L5B3Y8t6z7Yxrx842dgrFw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: FR0P281CA0094.DEUP281.PROD.OUTLOOK.COM
 (2603:10a6:d10:a9::14) To AS4PR07MB8658.eurprd07.prod.outlook.com
 (2603:10a6:20b:4cd::12)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: AS4PR07MB8658:EE_|AM8PR07MB8230:EE_
X-MS-Office365-Filtering-Correlation-Id: 0d10f890-ae24-4c8c-9aa5-08da8bf5d7c0
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: rKsssqzQAOqqR2HjGsp0sFVz97vPnrS11HlnjSNIHBoqNFg1s1BZundSrm5p7XYLyI1olvGA9TxKrR/azIwYL+us9jaBsjiKTQQGD/6sQDqstuLvKtl0YyHBEJcMjDl8lqw+0S1QlyyI4Jmh3WS9H+sM4R/ukUcLeMTqcVlrhT94Rs3d+N0U5wzLq+sxBKOFdJPAmx2iHb/hvJfbzgHbr+KU9JL4Y/t3K/mYKh300FQR84Xp9IHw/TyFMP+ODopDldrw01TT+1PKYj3GoDkyLg8tpMhbYlPV8CYcsGyizdBy5evmDMyl8Diz6sa/3D1TSt4I7Ybbql1Mp3aZOxqUsT+VKNH8Nk67F/BG2INyxY3XyhVlkfBjpgtwFzlCaYxnH873TZf3b4P5rrnNoeof+pA/lM49IOu+aFxIY5u6PQFLD0ECGYC+Koi7Tc9+NKfqfH4sTxNQk184t1XQbN3Dah9Q2tM/TNtrpAFZ4gH3+LgYRgvFO9/aYpxCm/FqSVYefO5vJ2sLbFcC0Vpn43cXlE3od390NaThL2b0oFGpOWpQw9imnUb8MG30UQsXYh3VmxwgR0PE96cfwiMl2vmomLrJgtxKfgo5slY4JQGg3uROgXR9Vw90m6kDY8aBt39Cmf9f7zS6WHRUUKjNF6Kk0hZjQrBUnlmbRaI9AXw89frjYBVX3lUGoiDllHkXYiCPUuOM6dn5yWsCwPg0JqFtV20jlgYdF7rqhyFyr84OH41MNyn6ePJs68ksNz6rHNe7U6qUuL/6my7GJ8thD9w2krpBCP1P/Jo7kj9wEBNMjSqXrgKjrTXKGPZr2JFH8xk1imCH3fI61pqYuYU74b6AMw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:AS4PR07MB8658.eurprd07.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(4636009)(136003)(39860400002)(346002)(376002)(366004)(396003)(66946007)(82960400001)(31696002)(66476007)(4326008)(66556008)(6916009)(2906002)(38100700002)(316002)(8676002)(54906003)(7416002)(8936002)(44832011)(6506007)(186003)(478600001)(2616005)(53546011)(5660300002)(86362001)(41300700001)(26005)(6486002)(6666004)(6512007)(31686004)(36756003)(45980500001)(43740500002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Q2ZGUUpKR3BEdzZxZDNUQkk4WjZsZ21QbzlsUDZ6LzU0UnFocDVOdkdFdCtF?=
 =?utf-8?B?dXQ5L00yb0w2RzhuNHhjelA0dkIxWlJQUEMyUTZVMVNJK2hEb1dZZTZGZldQ?=
 =?utf-8?B?VnJtd1JMN1RrYjByeCszaEs5WEYvREFaajhPRS9pZ0RqZ0JJVzR6U2FkOWFL?=
 =?utf-8?B?dlZSalN2MTRjdjgvaFp6UzJvU1h2dVArR0JPUU5LU0hPUUhKQXI2SGpEWmFM?=
 =?utf-8?B?WDh4QkdHaGdvamNTOGx2NFF4M2NVbFhrenFUa05nMXVQNEN0WjhEUlNZZUlt?=
 =?utf-8?B?Zjc3MXVJUFk2RUhXUVBvaGNhN2dEa1pWTThqTE9TeldsRGFndVJzSzVFK0wv?=
 =?utf-8?B?ejJtU0pDQjVlbXZlQU03NklvanJta1hHQXdJOVdaY3IrbkRqeGVnKzQ0VnBs?=
 =?utf-8?B?MkNRalZwREh2K2crZG5QNVhMM1k4eS96eWNaVW9yamZhdFdiZGJNczE2TEh3?=
 =?utf-8?B?K2dKNitSUDI5cm85OTg3djkyY0lRZUtrSHZOd20xZGswUkdsakVnZEpKQlRr?=
 =?utf-8?B?bU9iMWJRcDIwVTYvN3Y2ZmRLM1NXcmpPZHBMaHBnYTM2UUszSE56WWpZOVdt?=
 =?utf-8?B?dGJCRlZiaTkwOFBnWFVhU0phejUrTVRvRUJ2c3hTZ09uV0RsYzNyaU1XSW9W?=
 =?utf-8?B?NkprRHE5NVFvZkdla29SVFJ1SW15WjdySHE0Y09jY2JEMEs4ejRHeFpmbEZ4?=
 =?utf-8?B?b0dCZ1RGOW0wRTRSMUVHSno0KzZCd3JUZjhsRU5tTUxtY0lEbnBTLzJQV2tK?=
 =?utf-8?B?SkdLSGRtcUZmTU5ZMFduYmU1azE1WTE2a0MwdExaQzVPTkxxTU4zYzNGWlk4?=
 =?utf-8?B?WFpWUjdKdlRTSGRLK0RSRjRlN2RRVmpCWk1zV2FPM2pFenkxdXVuQ01vbjZ1?=
 =?utf-8?B?a3ZUK0JySkhKdGhoRHAydXBrZTFzYWZ2dEVKU3V3WFhnOGpZblV4WS9RRzNm?=
 =?utf-8?B?ZENEcWcwTlo3R3hTVTA2NXc3OHFBLzd6YmEwWkx1NVUyTHJIYW9Vb3FBQTlZ?=
 =?utf-8?B?bFg4RU1uSDBvaWNXK2VQbWtJbU1EdzRaR2dVdFZDQUFMQXNENG1lUjBWK2s4?=
 =?utf-8?B?UkRybElhaEF2TW9GbnhkZ3pkNVFFMFp5YXl4V2NEaDViVW1vQi9CZmFPS1Iw?=
 =?utf-8?B?dkVhMS9jc3N6QS9vbGd6UUtIQndEeURKVnJXUUV1eHB1WHVueXVLcWl4S0Fw?=
 =?utf-8?B?UDhTVGtkVURWTDNzNmpMYVlQZlVNL3Q3aHNqdDJYb0p4K0xkUXovYmRxNlAz?=
 =?utf-8?B?Y1VvdjMzWjNCUGhIWEV4YWJIcnd2cm5Jc1FneHFOSWdFMG5TQWlJaU8xNmVM?=
 =?utf-8?B?YnlQK1R1NmlJSFJzSWZjLzQvN0dGWEozdm9FV1RLckd5ZGRVOEJGWVN6aDJ1?=
 =?utf-8?B?QTRuZzJnUzlxNWY0VFBJUllndWFyZ3A3MmtoZDhWSVFPeFFBemxvR1paSFk3?=
 =?utf-8?B?OVFLRGthM0hFVFNEUnFSUkJxc1ExN3hJbEdxSlU3VUdYNjhGVHIzcGI0MTJi?=
 =?utf-8?B?bjdzRW9HT3JPdU52eG5rOE1UNEtXakVsMXBlMVVyYW9TRGI5VzIvdlN0aUFG?=
 =?utf-8?B?WEV3a2Z1NkM5VnViQ2Z6ZmlHcUVkQmFOK2t4bDdjVW9xRGZwOTB3YXlxdU5s?=
 =?utf-8?B?bEFORkk5RmFZWXM1SVgvazd1ci9jQ1JhU1Z4OHpZMzk0UU5URmxIQzcrNnlB?=
 =?utf-8?B?Q2ZGdEVxNzdEbEI2TmRyY2JUS1F5Tzl6eExvRlZBa1NBc1ZERDJ5UTNhZFNz?=
 =?utf-8?B?N1NZOXlVUzVsMW03QzdDNHg4Sm1jd2VnQUIwN0RkckgveC85VHhad3RxUGIr?=
 =?utf-8?B?Zk8yYTB1TGpacjBTNW5FTi9rYTEzbnJtVXY4QnJYZlU5Q0dFMmdzaWYvVFFG?=
 =?utf-8?B?dGxXS1BGYmIxODZTRjdNeWlySk1QUVlvRm4vS2lubDVEZFM4YVZkVVZNdmxJ?=
 =?utf-8?B?dWFKU3liOE9ieC9CUEFsVTFFUUZCMzdIb0c4OWQwN2ROdFZjQzlHbjdMNlFI?=
 =?utf-8?B?RjVVOVl3WE80azBZUjNjOVhMV1RDcWI3aVFEZngzcDV4Y29LK3hjOUtmRnFz?=
 =?utf-8?B?TEErd0tKdVMzUFYzMWVsSGx0bTk2S0U3M1prcW9qV2RTQ1FscGF2RE5pak5S?=
 =?utf-8?B?QVV0N3ZOS3EreG1EWVRZTW1sQ0FHeXhXRlk2SDdoNlkzN0YzV2tjaVZiTTFy?=
 =?utf-8?B?bVE9PQ==?=
X-OriginatorOrg: nokia.com
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM8PR07MB8230
X-Original-Sender: alexander.sverdlin@nokia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com
 header.b="g/oVnBqL";       arc=pass (i=1 spf=pass spfdomain=nokia.com
 dkim=pass dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);       spf=pass
 (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.8.139
 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
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

Hello Linus,

On 31/08/2022 11:30, Linus Walleij wrote:
>> -       create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
>> +       if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) && IS_ENABLED(CONFIG_MODULES))
>> +               create_mapping((void *)MODULES_VADDR, (void *)(MODULES_END));
> So the way I understand it is that modules are first and foremost loaded into
> the area MODULES_VADDR .. MODULES_END, and then after that is out,
> they get loaded into VMALLOC. See arch/arm/kernel/module.c, module_alloc().

yes, but both areas are managed by __vmalloc_node_range().
 
> If you do this, how are the addresses between MODULES_VADDR..MODULES_END
> shadowed when using CONFIG_KASAN_VMALLOC?

That's the thing, __vmalloc_node_range() doesn't differentiate between address
ranges and tries first to recreate [already existing] shadow mapping, and then
vfree() unconditionally frees the mapping and the page.

vmalloc() KASAN handling is generic, module_alloc() implemented via vmalloc()
is however ARM-specific. Even though we could teach vmalloc() about MODULES_VADDR
and MODULES_END (and don't call kasan_ instrumentation on these), but, this is
ARM-specifics that it's used for this range.
 
>> +       create_mapping((void *)PKMAP_BASE, (void *)(PKMAP_BASE + PMD_SIZE));
> (Splitting this in two steps if probably good in any case.)
> 
> Pls keep me on CC for Kasan ARM patches, thanks! (Maybe I should add some
> MAINTAINERS blurb.)

-- 
Best regards,
Alexander Sverdlin.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ccde957b-20b1-2fd6-5c90-ad9ee4b8924c%40nokia.com.
