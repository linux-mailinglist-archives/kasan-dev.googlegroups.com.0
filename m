Return-Path: <kasan-dev+bncBAABBT5J6OVAMGQE7MWYPHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C8D5B7F3312
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 17:03:28 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-58ac3c313casf4456422eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 08:03:28 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700582607; cv=pass;
        d=google.com; s=arc-20160816;
        b=gDy7rk5wQxf5QnYAl7JZxzvSIW6PQaHHFRFk+KGBTPiTkfS2aFI3h4BDxMdzCDW6bC
         r4J5CNskWC+BUt8b8YXBXxYqDd9Lg8OkO4BFHNds1MBjIsUW6g29gAF1+vg8FKNjB3GW
         HXHQFhzGw+hv2EGDeTpRCL0yhK3JecYkR2BWELOnM77sUHcwLGlnZTjmtFGTAEYg5hmC
         7IgtSCTcXKrO/qKNgvOmLM7e/U+uYuK9EyC13+azD9GdvWGT3EMipkAYBb9c/78cj1+H
         1E5kThmBH4Wum3roaUBgAV7JqyFt5IWcdnqJi4PsUmKbhSVX9c+ed8DeKX3w+6cDiY5H
         PAlw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:subject:user-agent:date:message-id:sender
         :dkim-signature;
        bh=6lioChKSGug7nG+/U3Fisqf8GeOvWKPTiux9y394/Zc=;
        fh=EdGaATNRJHWrDjijERWx571Uone+l/MnCESUIgc73pA=;
        b=BoMttTmMVovwS+ul5VTJkbYhLSdJ9syAymxxEOgMaq64eFsse06JdRBb18TAaeEdcx
         5rK0C9JNjJ1RDvtbP5e+Dh69hB3Wtn+kPXRNjgxv6fjvAV9BoA5Yl5I7JGvz1ywKQD4M
         XXEGQTpB/rm2q/gpXz5BYxmPIjrY9qBmOw5d+Z3ObGy/sl/vx2eMf6mXUUW24OmUye37
         E8KK3GND/jckdHjVfA5hO/QBN1DQsVlONRIqc47Yni4K3lH8pZGc2/X0/4zZKSx/w9aD
         jlEGo2oSfCF3hEJNEqTywRBzooMsUpTRuTDyOSdW/2b/24uU/t+vsk1LDI99jrJTtoVY
         HOaA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=EXjrCd7m;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1e::814 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700582607; x=1701187407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :subject:user-agent:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6lioChKSGug7nG+/U3Fisqf8GeOvWKPTiux9y394/Zc=;
        b=qWDI8tjBr4Q6xaXvJcU4H4ADL82JbrI9+9kb6Hw09zzTIB6jLw7NKaDVREq77OLkpY
         7YLF18+3IWIphNa6kctekVdOjC+vsPkIGBXJ143gqyJe05qDO/55eze0a+JwJ1lhpdvL
         qB+Gz692mX/yAqGO/BL+lfb07ykoSgGAKqZgxiD14izIxgL8iiv47ddmvVaj7wcsGNoJ
         0i+dYDoLtQloH4vw89Ns48fv3t5k6BTQCNitNxlhd8Ax5foXIfDLOpLoRgfOftFUS9yA
         eqQulKmx8PvQIfJ4KUPl6FzNmJm2YY17kE8ksIc57oA/daZ1HRaLZScMSz7e/8/0ETr3
         K6NQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700582607; x=1701187407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=6lioChKSGug7nG+/U3Fisqf8GeOvWKPTiux9y394/Zc=;
        b=NRo3bP9L3n6+3WZ6TOdScF2W6+aU/Cp+4mgnAxnzTMDySULH2Retimg4fprUyzFey6
         nB/4M+W/fMZlaSC0OiTNfHu/HZAPkl9oqwijusiSWmHtEBGjlEL79GEuKxpHEnUDkVaM
         WsosSlWuN76BNCOvrfNqi5RACDXRoqgv/RNZOg251sd6ibOuGCE9uMJ08TzUqWHD3UCp
         LXetT2+Y3k95AMKM9Of2b5PpbftNESxWcqqur0AnVgoIuzHH28Pv4rIWvAtj0E9SaYCH
         81ZLUwN12bUTY0qKTvN8OkWJKuxG6TVvBcNjbUyR2PWjYhLipDiDP3DquUTLeSMeJONX
         hkGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy25RghODrJ/Q+CKLRoUablHSzlM+OOdHMYBlhETSXvw2vOUfof
	y3GZlCu5uhpT/M1rq/LIkWA=
X-Google-Smtp-Source: AGHT+IEZkLGRE4NcxHqARNv5aJSVAnXkovo5AtE8I2tAvSDtvvtXwFG2yK/vyDGTFWm9sp2E7VlUVQ==
X-Received: by 2002:a05:6820:161e:b0:571:aceb:26c8 with SMTP id bb30-20020a056820161e00b00571aceb26c8mr11796392oob.3.1700582607177;
        Tue, 21 Nov 2023 08:03:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5808:0:b0:587:ac60:9825 with SMTP id f8-20020a4a5808000000b00587ac609825ls168558oob.1.-pod-prod-04-us;
 Tue, 21 Nov 2023 08:03:26 -0800 (PST)
X-Received: by 2002:a05:6808:1a10:b0:3ae:a6e:6ccc with SMTP id bk16-20020a0568081a1000b003ae0a6e6cccmr14954333oib.49.1700582606602;
        Tue, 21 Nov 2023 08:03:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700582606; cv=pass;
        d=google.com; s=arc-20160816;
        b=DnXh/OXY0HRwYUTi/trf7RtjFuzkIBSVSey4sS6VqO2/sKIvruKIyODYP+1q3R8FEn
         O/xt3YCAt1lYvRVfilQJA3YFR+zfMbof29O4Q6EdOsWy/e6PPQX8yfk0/fahpMkJzf/J
         2HWEQt1LetWTogC57GrjjL7xmTai6D/dwBAhN35QzzG1bZE700vtoWWgSyqgaD5N/OYC
         LbsICfS7OIb7XpJFIyfQdMTtPTG5IzjNKsEwduB7xV1uHcq0gKd66u1cIVSSVGzieJ7o
         mq8nQSCMVYEL8gNZiTL0NaHE5iV+6gbflFWg+cpO1UD+KEw7dDPTQixzG9SgcnN9zapP
         0s4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=O6WGpGlEdzPqyGWO2lpaqt3QCjVzaL1YFFK43zUA8gs=;
        fh=EdGaATNRJHWrDjijERWx571Uone+l/MnCESUIgc73pA=;
        b=gKWAY2OnRLZCzMBr6t7z+0FVcLYZqfbvChCV3dSL3PJhH0XyEPL6g0Ees/9PgqN7hy
         GOshRHR4WmiNN7OUtYYYpbhDHaFbcjULKW8GVt6Br6MKJ6lnN0aomRnsj2rOF/dv1HoG
         llJikTMV1UxgzPK29DKHug4fwzPaPHBobVdhqrxmcn9c9vJPnBzYr9kjRmm4SxFBp2Gp
         lj/XxaxyudJoECOf9GxMGV8W+dissg0XHhYoj9GKlTvIB6trXR8z1MZe2Yf02jRhjErJ
         8IzUww/h5n/OlqCNg7kDuaBSTN+zhUGB77KNo85H7XY+WHYHqkhMYEf7ARgFrBJApxb/
         jjLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=EXjrCd7m;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1e::814 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR01-HE1-obe.outbound.protection.outlook.com (mail-he1eur01olkn0814.outbound.protection.outlook.com. [2a01:111:f400:fe1e::814])
        by gmr-mx.google.com with ESMTPS id gq18-20020a056808399200b003b83399ca7dsi215148oib.2.2023.11.21.08.03.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 08:03:26 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1e::814 as permitted sender) client-ip=2a01:111:f400:fe1e::814;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=m+mbFzoGQZDx1YpMzhe2YrEA9hqSr/Z4gBhTBxgCS7zA8IpoOFpomOqKp2kGOduY7EWkM4rqdJOJ2yT2dvJHTLtkmU9zWJSKgmwOePQD5Y6ngYQ2HwZdEPO0XSnK+ARezugR3qQD92c67D3NqJ7RTUq+OgTfMwZaSoKBhNCskO2tlze5yOPl2+7JJYZaSKRy3S5GJbLXcKHKZ7QrB8ESWUbFgNEhS7KKu1RtakQ19+a5pxH2m+dz/Mra3l030mwQJuxdE83FC8mRYELdtMy4j5ckKMid6tEhwE5DxiOvlvLn2are96kp3XoqDKNq7HlVxDUKBe4XKP0g3FgMpFikoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=O6WGpGlEdzPqyGWO2lpaqt3QCjVzaL1YFFK43zUA8gs=;
 b=RO29KVXxVRyZN5laRaSMMX57oJvTqLMZRzLwpKm4XSj7L0C5NvOYO0GfNeaBEVcMC9rm26wdV5bDWM7wJ48yZKzhb14xRLFF86tVIFMOeogwdoONXKrvdBJJPQlygrpX6n7vCm7yLp0KoH1XnS6lyGiaqwA3EccEOaCav2DtvQqwg7l0Ylj1jwh6AAo+xYaNtjKNPJGUsXuFFKU7OsbkuBEOf55I1ZPRjfmkdrx2qpP/nuJ8GsjNPFK5xV04DPaxeW9U9MkAh1ATO+S+am19UYsvEx8nC7kMyxGaFBlvb0c31XuwaLLXkPmpZGzCN17JOstrhDynEbpre9JwbbGigw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by DU2P193MB2131.EURP193.PROD.OUTLOOK.COM (2603:10a6:10:2fe::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7002.28; Tue, 21 Nov
 2023 16:03:19 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%4]) with mapi id 15.20.7002.028; Tue, 21 Nov 2023
 16:03:18 +0000
Message-ID: <VI1P193MB07520067C14EFDFECCC0B4C399BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Wed, 22 Nov 2023 00:03:17 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: Improve free meta storage in Generic KASAN
To: kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, Dmitry Vyukov
 <dvyukov@google.com>, kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, vincenzo.frascino@arm.com,
 akpm@linux-foundation.org, linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 linux-kernel-mentees@lists.linuxfoundation.org
References: <202311212204.c9c64d29-oliver.sang@intel.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <202311212204.c9c64d29-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TMN: [7A2Ztj1D8k6MrQxgadNKMQen7RkUeMm9]
X-ClientProxiedBy: LO4P123CA0652.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:296::13) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <3386a261-9580-4bd4-930e-1c24aad85800@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|DU2P193MB2131:EE_
X-MS-Office365-Filtering-Correlation-Id: 9778aa12-446d-4cc7-ebd8-08dbeaab6098
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: tucBqHmJdr2H3lThbTgGsUrZXgiIlSb5IbZ0WzqRXkRQaBttqQCSaK3hhTHYVL5KQLDi2GiVuCki33okgb7a9FAf5+M+t7VryYnu74MkU0PxznIucIoOawkMkecAe7VraYxl9mu0pKFqrRYrnX2wc1KWZhE6rIAEYC4MqEJV5VzMu2x7hw4FUFu/OsX1z8hHZtBuGM1WTIp1LO/MWwXlZUuub5E9ZYZ2sV6JKvBdGF8qKjD3B/wNkPtQs07cQJo9/4KXkOvz+Fnc5kQsD/SrIxYngQgsGRzfClUtAL/uvL5SlpzH0ckeLHiBvJkQinyyWF3bzpEcQPXyIEygHSiMwZKxu6WCaKE7TuUcrv9oQwc4f2z9uKn22X7LszSVKghLfRrcdE7cWZcuonUPqRFEVK7vhK52kT7DoPRZJPAHNYM0ToVbBOk5yuaEmJDwaFnEaqM9H0AYMlcSfJMIb6E4sUGchrH7QB3kcGbwycPMZ+ipkOaANxQJimEm3KZMX7aHyoxWQKdMe4wVCzvA6od5fstRkf3pOPYaYvOscZ3MNU9pNajFFLVji18GSlf62gdfcZG3GvfsKUCdqsWKAV6Hjq/tGuF7UF6Q0bDPe1K9kVY6ffRyQEsB9p7hS2QGFa2vBliUbuHsP+Fvv+HAa0SLDw==
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?cVhPckZzdHVjR3B0TXU3SHQ3ekd6R1FkZXJQODNheC9iWmFXTWJGdnJZU2t4?=
 =?utf-8?B?dVJLVW9lQVhDNDV1azZMaHhsQm16QjVOaWNFMWU5SjVHeFJaTHptQmk1dVZZ?=
 =?utf-8?B?Y0R2K1lsMnQwMGFTdVNNSEo3UGNCSUw3dFViL0FScVVCMCtNc2VmNjA2d0RQ?=
 =?utf-8?B?WC91N0UyQllTR0dxRzlqaE1sbWE3b2tmWVNOd0N4RDRwdmJYRy90dlhYazFj?=
 =?utf-8?B?V2kwRnFpUEhNYUVER2J2L0grZEcvRTBudHY4NFRNN0ZyZ3RBT2JJRVZqK1VP?=
 =?utf-8?B?OW5yWUdsRm1SanVPS1UzSXAxYTFMeUIxS2NKM1Qvc0V3ajE0SGNGQkNSaEpO?=
 =?utf-8?B?anQxNCtYM3NSaWYwVzVyb296ZWlDb21jeWNOMXNQVExGcFF1ME1zL0pxQzdh?=
 =?utf-8?B?S0lZa3RtZk0rMGNiZTlxMDdDTUw1d0c3Y3owb3lxbjgvTWp5M2gzN1VDTUg1?=
 =?utf-8?B?dnpjRDdkcXpkcm1UM1d3TkJQUkRsUFV3YXFpbm9GK2dkN2lJbStiOFRGZjd6?=
 =?utf-8?B?V3hkZ2RyVGtSMmRyeVJMZUhNd0Y0Wkdsb2c0ekJRRWlFSm1NbVlrWVk0bVRZ?=
 =?utf-8?B?OGFiS3JwbUErNDJlazVTS1J1TERJR0I0c2dMSU1oamNkZ0NQdTh6dkNOTlFk?=
 =?utf-8?B?N2s4ZmZISTJqcTdjZkY2NHBrekpUWHRFUzFOc2ZPem5QUFJweHF2bDk1Qi9j?=
 =?utf-8?B?T3lTSzF0dFpQL3YvbS9ZK1dRTnRWTXJ6eGpwMzNkT3FCVjVzT1N0NWZPcVBO?=
 =?utf-8?B?anpUWnZSajVQQ2g0YVI1Kyt1TzVkaVhyZkhSK3dvOFcvU2hUUWlhL05rZnhH?=
 =?utf-8?B?bVFacmJwMytIcnFmY09nYTAyZGVKOXVGWWgxNUkrRFRLLzVJTkIwcEMwM0FU?=
 =?utf-8?B?MXpNMjg0Zmx2dlpEVEl0SU0wbUh5M0FqY096S0hKSkFkeTJkeXdQZUxUdE9k?=
 =?utf-8?B?dlJPQzl5T2ZJSkNqc09sV1FJbEpSUk41SXdCUGJESDE5MnQzMEFiM2IrcTN2?=
 =?utf-8?B?MzVPTVlJdmNGZjNDeFpjOVlZTkxTcUcwcis4RkpBWU5iT3lMNGY4M1g5Nkxo?=
 =?utf-8?B?eEhnNExsUW1lVnZGUW40UXZqUXJLWDhFR1g1SXhSZVZvaU5UVDcwOTNPazhq?=
 =?utf-8?B?MjJhRndibDE0eitMS1lpZjFiNHhjZGo1Zlg2b2VYNEs2eERGUE92MlNmaTZX?=
 =?utf-8?B?R202NlJNbG01YkZXRURSbVhKVkRKWmlrWTRQaEFJQVIvem1EUTVDQlNlcFpM?=
 =?utf-8?B?dWZ1NEMwOU1McVVTZGxSZVV4TVFTWU1QQ2RyNUxOUCt3ZjBTRlJrL2xHMk1j?=
 =?utf-8?B?elFnclBQMVp5N2oyTVZPbk9QMkppVVpGNkQzMlpiRktjNkUzdXBxMzczSm4z?=
 =?utf-8?B?VUcwUUJTNld0ZVhqWWZuaUYvQW5mVFNDZnQrRHdRd2dHTjIyeklhSkdEL0Nx?=
 =?utf-8?B?em0zUHpFTmNPdThybGd0cXowelFnSytoeVNack5nbG1hWTRVOFpBOEpEeGdV?=
 =?utf-8?B?WmcyZ05HbnZaQzI2RDdwZ2lCU1NVNkRkZGNjUi9nbzJjS3BGZjVNTGYxL0tz?=
 =?utf-8?B?ZnJISnpYMEczSk9PZTVYUndaKzZTZm9xOVpvZzh1MlZmTTE2OTFjTDFITFRQ?=
 =?utf-8?Q?NzKM3OiGDv8/Oi1Lzpl+WOmEUVFABV4Ri8FDt98Wtsk0=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9778aa12-446d-4cc7-ebd8-08dbeaab6098
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Nov 2023 16:03:18.8823
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU2P193MB2131
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=EXjrCd7m;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe1e::814 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

On 2023/11/21 23:06, kernel test robot wrote:
> 
> 
> Hello,
> 
> kernel test robot noticed "BUG_kmalloc-rnd-#-#(Not_tainted):Object_padding_overwritten" on:
> 
> commit: cb53c2a822df305ec84b291e4c4a348c7d394b89 ("[PATCH] kasan: Improve free meta storage in Generic KASAN")
> url: https://github.com/intel-lab-lkp/linux/commits/Juntong-Deng/kasan-Improve-free-meta-storage-in-Generic-KASAN/20231120-044846
> base: https://git.kernel.org/cgit/linux/kernel/git/akpm/mm.git mm-everything
> patch link: https://lore.kernel.org/all/VI1P193MB0752DE2CCD9046B5FED0AA8E99B5A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM/
> patch subject: [PATCH] kasan: Improve free meta storage in Generic KASAN
> 
> in testcase: boot
> 
> compiler: clang-16
> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> 
> (please refer to attached dmesg/kmsg for entire log/backtrace)
> 
> 
> +-------------------------------------------------------------+------------+------------+
> |                                                             | a350566908 | cb53c2a822 |
> +-------------------------------------------------------------+------------+------------+
> | BUG_kmalloc-rnd-#-#(Not_tainted):Object_padding_overwritten | 0          | 17         |
> | BUG_kmalloc-rnd-#-#(Tainted:G_B):Object_padding_overwritten | 0          | 21         |
> | BUG_kmalloc-#(Tainted:G_B):Object_padding_overwritten       | 0          | 21         |
> | BUG_kmalloc-#(Not_tainted):Object_padding_overwritten       | 0          | 4          |
> +-------------------------------------------------------------+------------+------------+
> 
> 
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202311212204.c9c64d29-oliver.sang@intel.com
> 
> 
> [    1.104299][    T0] ** administrator!                                       **
> [    1.104884][    T0] **                                                      **
> [    1.105469][    T0] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
> [    1.106054][    T0] **********************************************************
> [    1.109891][    T0] =============================================================================
> [    1.110637][    T0] BUG kmalloc-rnd-09-8 (Not tainted): Object padding overwritten
> [    1.111258][    T0] -----------------------------------------------------------------------------
> [    1.111258][    T0]
> [    1.112154][    T0] 0xffff888100078074-0xffff88810007807b @offset=116. First byte 0x0 instead of 0x5a
> [    1.112904][    T0] Slab 0xffffea0004001e00 objects=30 used=1 fp=0xffff888100078090 flags=0x8000000000000800(slab|zone=2)
> [    1.113798][    T0] Object 0xffff888100078008 @offset=8 fp=0xffff888100078090
> [    1.113798][    T0]
> [    1.114555][    T0] Redzone  ffff888100078000: bb bb bb bb bb bb bb bb                          ........
> [    1.115329][    T0] Object   ffff888100078008: 6b 6b 6b 6b 6b 6b 6b a5                          kkkkkkk.
> [    1.116098][    T0] Redzone  ffff888100078010: bb bb bb bb bb bb bb bb                          ........
> [    1.116868][    T0] Padding  ffff888100078074: 00 00 00 00 00 00 00 00 5a 5a 5a 5a 5a 5a 5a 5a  ........ZZZZZZZZ
> [    1.117691][    T0] Padding  ffff888100078084: 5a 5a 5a 5a                                      ZZZZ
> [    1.118432][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 6.7.0-rc1-00145-gcb53c2a822df #1
> [    1.119122][    T0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
> [    1.119953][    T0] Call Trace:
> [    1.120209][    T0]  <TASK>
> [    1.120439][    T0]  dump_stack_lvl+0xa2/0x100
> [    1.120808][    T0]  check_bytes_and_report+0x113/0x160
> [    1.121240][    T0]  check_object+0x1e1/0x380
> [    1.121599][    T0]  alloc_debug_processing+0x10e/0x1f0
> [    1.122027][    T0]  ___slab_alloc+0x81b/0xdd0
> [    1.122392][    T0]  ? init_freelist_randomization+0x11/0x50
> [    1.122854][    T0]  ? cache_random_seq_create+0x49/0x110
> [    1.123308][    T0]  ? cache_random_seq_create+0x49/0x110
> [    1.123751][    T0]  __kmem_cache_alloc_node+0x161/0x1f0
> [    1.124188][    T0]  ? cache_random_seq_create+0x49/0x110
> [    1.124637][    T0]  __kmalloc+0xb5/0x1b0
> [    1.124968][    T0]  cache_random_seq_create+0x49/0x110
> [    1.125395][    T0]  init_cache_random_seq+0x2c/0xc0
> [    1.125809][    T0]  init_freelist_randomization+0x2d/0x50
> [    1.126259][    T0]  kmem_cache_init+0xac/0x120
> [    1.126630][    T0]  mm_core_init+0x2a/0x60
> [    1.126972][    T0]  start_kernel+0x156/0x370
> [    1.127334][    T0]  x86_64_start_reservations+0x20/0x20
> [    1.127770][    T0]  x86_64_start_kernel+0x59/0x60
> [    1.128162][    T0]  secondary_startup_64_no_verify+0x167/0x16b
> [    1.128652][    T0]  </TASK>
> [    1.128887][    T0] Disabling lock debugging due to kernel taint
> [    1.129373][    T0] FIX kmalloc-rnd-09-8: Restoring Object padding 0xffff888100078074-0xffff88810007807b=0x5a
> [    1.130544][    T0] =============================================================================
> [    1.131270][    T0] BUG kmalloc-rnd-09-8 (Tainted: G    B             ): Object padding overwritten
> [    1.132002][    T0] -----------------------------------------------------------------------------
> [    1.132002][    T0]
> [    1.132893][    T0] 0xffff8881000780fc-0xffff888100078103 @offset=252. First byte 0x0 instead of 0x5a
> [    1.133638][    T0] Slab 0xffffea0004001e00 objects=30 used=2 fp=0xffff888100078118 flags=0x8000000000000800(slab|zone=2)
> [    1.134524][    T0] Object 0xffff888100078090 @offset=144 fp=0xffff888100078118
> [    1.134524][    T0]
> [    1.135292][    T0] Redzone  ffff888100078088: bb bb bb bb bb bb bb bb                          ........
> [    1.136060][    T0] Object   ffff888100078090: 6b 6b 6b 6b 6b 6b 6b a5                          kkkkkkk.
> [    1.136827][    T0] Redzone  ffff888100078098: bb bb bb bb bb bb bb bb                          ........
> [    1.137596][    T0] Padding  ffff8881000780fc: 00 00 00 00 00 00 00 00 5a 5a 5a 5a 5a 5a 5a 5a  ........ZZZZZZZZ
> [    1.138418][    T0] Padding  ffff88810007810c: 5a 5a 5a 5a                                      ZZZZ
> [    1.139167][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G    B              6.7.0-rc1-00145-gcb53c2a822df #1
> [    1.139971][    T0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
> [    1.140800][    T0] Call Trace:
> [    1.141054][    T0]  <TASK>
> [    1.141281][    T0]  dump_stack_lvl+0xa2/0x100
> [    1.141643][    T0]  check_bytes_and_report+0x113/0x160
> [    1.142068][    T0]  check_object+0x1e1/0x380
> [    1.142423][    T0]  alloc_debug_processing+0x10e/0x1f0
> [    1.142848][    T0]  ___slab_alloc+0x4fe/0xdd0
> [    1.143214][    T0]  ? cache_random_seq_create+0x49/0x110
> [    1.143654][    T0]  ? cache_random_seq_create+0x49/0x110
> [    1.144092][    T0]  __kmem_cache_alloc_node+0x161/0x1f0
> [    1.144524][    T0]  ? cache_random_seq_create+0x49/0x110
> [    1.144962][    T0]  __kmalloc+0xb5/0x1b0
> [    1.145289][    T0]  cache_random_seq_create+0x49/0x110
> [    1.145713][    T0]  init_cache_random_seq+0x2c/0xc0
> [    1.146115][    T0]  init_freelist_randomization+0x2d/0x50
> [    1.146561][    T0]  kmem_cache_init+0xac/0x120
> [    1.146928][    T0]  mm_core_init+0x2a/0x60
> [    1.147272][    T0]  start_kernel+0x156/0x370
> [    1.147625][    T0]  x86_64_start_reservations+0x20/0x20
> [    1.148057][    T0]  x86_64_start_kernel+0x59/0x60
> [    1.148447][    T0]  secondary_startup_64_no_verify+0x167/0x16b
> [    1.148929][    T0]  </TASK>
> 
> 
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20231121/202311212204.c9c64d29-oliver.sang@intel.com
> 
> 
> 

This bug is caused by the fact that after improving the free meta
storage, kasan_metadata_size() continues to calculate the metadata
size according to the previous storage method.

I will fix this in a separate patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB07520067C14EFDFECCC0B4C399BBA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
