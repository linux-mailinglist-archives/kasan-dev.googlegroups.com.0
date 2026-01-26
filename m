Return-Path: <kasan-dev+bncBC6ZNIURTQNRBBVE37FQMGQELMZ2FZA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uGlrMQjSd2mFlwEAu9opvQ
	(envelope-from <kasan-dev+bncBC6ZNIURTQNRBBVE37FQMGQELMZ2FZA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:43:52 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 517A98D38F
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:43:52 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-790157636e4sf57088077b3.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 12:43:52 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769460231; cv=pass;
        d=google.com; s=arc-20240605;
        b=fm7V72HlF1irxxN57lYg4LB5DF2e24P08MpmGel5JUNh0fImm2T4RSE112Tka8/r3g
         LGLLaWk8A5jSYRfr+WNqnpHkzaqQ1YvqG0n+p63eNqwUoV/8qt9GhIMavsgRScEBoq2X
         lSYXjVj6JU3Pj9E7mU4CfpyVG9wcZXUMZBAVnBTfAZbHmfZ8MjWa8BbZBOYp1BaOmaCJ
         vwxi2BKsPT7PayNINsdtN1eFtZymB8lMPAkk5orLT7+9BXvFJS9E/Fz+N0yDbpoLdFOr
         2QyrJY5uycT83S83SzDPgK7suh46cx2Lq7husFFZMDK6Liyo2iv4syCJM6gzgACudKmY
         kiYA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:dkim-signature;
        bh=3lzRx/nTMbclk32bRyXtYx2dvU7vp4Yi4Ez1Ka9V8vs=;
        fh=aVySCvtGp1KRTB6U/3UYxJyl7QiIPpKzSDWT9bLAFjU=;
        b=P1OZ8N77dYOJAey4Z/9KNBsHWFGv86OHd1VQrHp2ShITagjCYTOIBfDYocUuwpWcfj
         /bLQ5qyWbxmi/5K+uZZeM1WhHwe3rTfkzvdRtv6MwMCeDSFxWR23QO9CS6sAvTRcu2NZ
         7fPEl9cMzc2WsqSA3S8fPGs5BjTmWYVVzCLQafozstPQUlk6XAcZ22sPzsjvEP1fPSl6
         A62aCoWvIFxlIUjfWLiCzsyYuHjH6f3qGNUmB/UuE9w00ps0hOVxuQCsilr49OFho7/z
         pQhTUtk+wjpNrd/3Tn1W030pgcZK6PLFGTTGXDC3eAhTG2HQYtBL/ieruFAwQdRKezrT
         C6Lw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=LgbkJRRy;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c005::5 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769460231; x=1770065031; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3lzRx/nTMbclk32bRyXtYx2dvU7vp4Yi4Ez1Ka9V8vs=;
        b=bioBDEPGAqnIqTQnXnrWp8vDS/aS5nDg0kTkvJRqdQ3cWXJgy9+DPYEbC6jYRCfBJm
         PzOfESkDOmSEGlLjGzGkCdPsS4KFFB0r4keikWgLNU0i0ZMmJX/A8rOzOop1iBRYOoDp
         CU4kmpAYazAfHe/kejjg6sU42O7ZzWOjpkzf0HDlfHZ16/hzlwwmujzXRwD569dY7wOd
         sJKYNdFmSegEpjgTpkSbtV9KbS5TsTqNAIIISnVQY+fGwBmsuDcEWDBrNzbL8JImnyVS
         erc+uWoDeq6+2SeGSLPUkgytaFIVMhxH68Zr2QeB8sZ5UIYGABQTfNADi0ernXjIGgSY
         HVsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769460231; x=1770065031;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=3lzRx/nTMbclk32bRyXtYx2dvU7vp4Yi4Ez1Ka9V8vs=;
        b=mLETjiWXzBHCEhGpzj83ytUVqKiRVcgBBa21c7gren5P4pKQshgIvDKAM6Wt4M/DTU
         9Rcb2vBdKDlQ0GrvXzhILZZ2NsfZo655o0hfqeQzb3ljP9KE433sJ/iJchA5nM0GOFLi
         /ED2lIE7YkdP3iG7JJ2cMR3Z0jrWtHen46NdMXnoYhlFodb/uJFTpPxmU/EvJZDu0iSq
         ZqfKVMo7cywOMT8gXNmWcRpKepzfZTmeaWoYamSh/KBFoqWr1tRfXPpRX8hhWfNXROC4
         GhwmkntpTZ59395/IdI6kRbybgragp4ammmVhai7NeoVjlUU4MfXvmBBJ7rROD8IfV09
         rsXg==
X-Forwarded-Encrypted: i=3; AJvYcCWMlHv2LxwCb7oOnUG57smstxowltGnuPXxk/n3Ct8egiofKhQ1SNigkvbv4qIUj4wVYQW9Dg==@lfdr.de
X-Gm-Message-State: AOJu0YxJN5j+GA64HcQrdv5U/C1tA4dOlRjOcpebJ1KSRdiPHMyeAMlI
	nVd1WDvFchTyiqqbLECpqqxYRYZxaAHtSm+gctH8EzlHqwAhJCcgfn+P
X-Received: by 2002:a05:690c:6083:b0:78f:b820:f2f3 with SMTP id 00721157ae682-7945a86ee11mr95643617b3.12.1769460230893;
        Mon, 26 Jan 2026 12:43:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fppnt30Gl5mnnnTi7Vn4Yo4BD987xFSQjmJrZfpWUM+A=="
Received: by 2002:a05:690e:4c2:b0:647:27b0:1aa5 with SMTP id
 956f58d0204a3-6495164285fls3314526d50.3.-pod-prod-08-us; Mon, 26 Jan 2026
 12:43:49 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXyBGRz+2MYKKpHqrX9kCmGJdveQrdJxiWJaOscKdpoj8ZSvSLpb4EvUEXeLvtRKNR7mPC7+w2rt2M=@googlegroups.com
X-Received: by 2002:a05:690c:c3e5:b0:794:647:6719 with SMTP id 00721157ae682-7945aa091camr79365777b3.50.1769460229324;
        Mon, 26 Jan 2026 12:43:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769460229; cv=pass;
        d=google.com; s=arc-20240605;
        b=AC+d0J0T63yTIQvIjQOeHaYiCWgXWgSjpVs2rD14EXTq3TWG+yROA4ThmIwC6ppBn/
         KE59eg2NJc9kfL8uZeBKKgucT1WGxwa3xGsW/m4VUYA07ie1x4cUNxG7vexQzo29BE0N
         qZknxX7z7rFhxvm089o4mG+qlx6mCk7EaPCnPoorw4jrrZ4gQbusPq+wIIFYca2LtZfX
         fpwlBIG1pfeqOMCEJtZPqTWygm1KLkYr3bL0XXruhosdWBnbNuf2YTN7r+5jKgsoJAYG
         +PnWLO+RhjRBx9whyO0bX+9OgZ5m2pLanWq0HaeeKCqPjLNa8dCtYIlMgSTm8EOC6gps
         MQHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:date
         :message-id:dkim-signature;
        bh=8NiIDGFxtwexQudYoSrpm/+QX0oGpl3fxTiLgEP6IhE=;
        fh=L+B44ZUUmWSmNJ/w1ewG47TteekqbM4kQ2su5Agx4/s=;
        b=az5kbq+8GzqGzjS5aFPPY2HexKVKomjZKoNVOUmfvqUPX/fzrtmPscoIWl0EoMIjFI
         O50OYkrkxemxm23QZ6UkzQMsx/bniDc0zrojsnkcvA6mqulSewKOSjfpOHODGz3aHivH
         BeDyHRnS9stxI7vkEb4wNOo6sTDNst+rRy0EwuGKNmAD7fYYm+Ouy5xTKsUOGOojMFQQ
         i0PftN5NONBM9YsbUNcUAKz3/zoO/cXoYYw9Z1o1qZQmLNTvGV4G7mvshTk10H1GB4fc
         yLUcQsw5gND44t8u6lBiVFO1Etj5TbfCNnCJ0rTjdasvLLHace8Xho5o3u8bWrhDF+2P
         7I3w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=LgbkJRRy;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c005::5 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
Received: from CO1PR03CU002.outbound.protection.outlook.com (mail-westus2azlp170100005.outbound.protection.outlook.com. [2a01:111:f403:c005::5])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-64966092f7dsi265279d50.0.2026.01.26.12.43.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 12:43:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c005::5 as permitted sender) client-ip=2a01:111:f403:c005::5;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ivhHD9hv9V1k7n/+6xgO+RDOH+uNGln4pPIZJnqCbm1KQY8Kb7I1//xB9f56CUZp/zFShpG20cAPAcE/sp9DHac/uHyBuRIxGIBxft9pRffMuC2kNXb3ifqK4iodEMH4TLN7Vk1NrtuubGxCJ1+GAu3l9FepHdBXYVhbvuapRVam7VY8NYhRUEivFRQsXtHeYyTaiQK0KOCObiznhftY0rCjH8IG1WmBv0L2gKj0tTmPNsUxgzSQp4JLLlPQUKBFgKpttHjR+4HHKMuEic492Ay/WhHrqlNoJ0mNUkLSlVjAqgVSw1kns6u++wcZH1ClLxcOGoLlpg9HG8yCA1mcmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8NiIDGFxtwexQudYoSrpm/+QX0oGpl3fxTiLgEP6IhE=;
 b=E6xZSMh9GfSUmZzBfs+OYz/ssE23iuHleGixYrGmJWG13cj5YC5pHnsl0QY9RnSabnIJQOeY4JLxsFgvIg8Rn1+F9VbTH+mrZ/oxfYafQxuTR/PkJ5EgWnHy+4y+fgH2DKd5e4+GaVGZmnggLG4bi41kQeeqmqBq7GO2w9UiXeT/mHSdS354v8RwAXLWiRyfNq3k6oPbZm3UzXMpziO8gKnYueCF79pAxXm/T9pCKVtQMnFOAyX5l3CSKqVh3W4H8OJpO5unAKw8EvxCYMYwyknd6q1Lz3+mCcvUaTy46PEy+oc1KTSIE5AqxJs+5+At+IglFly1cmiYIyYUTSgxKw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=citrix.com; dmarc=pass action=none header.from=citrix.com;
 dkim=pass header.d=citrix.com; arc=none
Received: from CH8PR03MB8275.namprd03.prod.outlook.com (2603:10b6:610:2b9::7)
 by DS0PR03MB8296.namprd03.prod.outlook.com (2603:10b6:8:292::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.10; Mon, 26 Jan
 2026 20:43:47 +0000
Received: from CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37]) by CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37%4]) with mapi id 15.20.9542.015; Mon, 26 Jan 2026
 20:43:47 +0000
Message-ID: <b013cd73-a99f-45bd-959e-8fe2750281e6@citrix.com>
Date: Mon, 26 Jan 2026 20:43:42 +0000
User-Agent: Mozilla Thunderbird
Cc: Andrew Cooper <andrew.cooper3@citrix.com>, Borislav Petkov
 <bp@alien8.de>, Andrew Morton <akpm@linux-foundation.org>,
 Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, X86 ML <x86@kernel.org>,
 "H. Peter Anvin" <hpa@zytor.com>, Jann Horn <jannh@google.com>,
 kasan-dev@googlegroups.com
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
To: Ryusuke Konishi <konishi.ryusuke@gmail.com>
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
 <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126195431.GDaXfGd9cSwoH2O52r@fat_crate.local>
 <6adad05f-bd56-4f32-a2d5-611656863acb@citrix.com>
 <CAKFNMokFvcMdAfsvRy6JVpWGnr6BtqUOwH7nmyS=1K51HD1vYQ@mail.gmail.com>
Content-Language: en-GB
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAKFNMokFvcMdAfsvRy6JVpWGnr6BtqUOwH7nmyS=1K51HD1vYQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: LO4P123CA0365.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18e::10) To CH8PR03MB8275.namprd03.prod.outlook.com
 (2603:10b6:610:2b9::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH8PR03MB8275:EE_|DS0PR03MB8296:EE_
X-MS-Office365-Filtering-Correlation-Id: b9d28a8f-7224-4980-8e2f-08de5d1b9a7a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?SzlPbnV2YkpTcVdpNS96aU1DVTh2ZlhRdlpueE12amRsRG9rTFZmdzVvSWI4?=
 =?utf-8?B?WWhoeVJYL3BwOWFkbWJOMHBPelhTUlJuTHBiZE1BNDNoQXRjaG9FMkFTWkVI?=
 =?utf-8?B?RnRWNTVja0kyUWhJV1dnS3h2K2NrN0V3ZXB1OGhHRktIOENDUzhUVG5ZZ0h2?=
 =?utf-8?B?cWJwV1lxV3NhOHNuUHVqQkdVeXYzQVRVcS9POEJIS2kvL1hPeFlnTmRFNmNk?=
 =?utf-8?B?d29KOUpPenRobENHRERvWVZSd2FuTFdkam1Mak1tbGhNdUFZRkJ3QVNoNFNl?=
 =?utf-8?B?eGlmM2JINzM5MlJOTmZ2N0NlZVNWdXcrbWRJVFlnZWlLUFFkMm01c0pPRWNx?=
 =?utf-8?B?SnNiYW4zVzJpRmtkUXlrVHBSa3h2YW9HSHBoMXhRN0U3MEVrQ0dDczRvQnBV?=
 =?utf-8?B?a1p6Z3RudEllcGY1N2d0UlNVMnNrdEY0VkoxencvKzY2Q0hYRUwwVC9yS3NG?=
 =?utf-8?B?aWV0VDJ5bDVBN3YzYVRDeDlteFVjVnNRb3NqWVdJVWttcWNUZHllVHJPNUwz?=
 =?utf-8?B?Tzg5VVhid3ZpbXZGelVYYjNjOFFEc29LZytwMFZNa29IeVJXN2tVak45bmRy?=
 =?utf-8?B?czFQc1RQRjRDdzR5QjNrUEFFbWVpL2g2cVZTeFJlRmZGZTEvWDdmYUtqRWxx?=
 =?utf-8?B?M0xDak1obnMxOG9GUm9VUWNoeW95OXJZVGxKUmdDUloxaDl1TlZwZzB2bS9B?=
 =?utf-8?B?TDdvSjZQRkJCOXFMNlkvak9zTy9oNm1oZlJMS01Edk9pWXIxYmxzRHJFREM3?=
 =?utf-8?B?Wkh3cmhZbm1FWmZ1TnEzeUpkdDBhVTRTc29KbWRRaDdUNzh1MVZBTHJGaDNL?=
 =?utf-8?B?MjJlSUppb29rYnNjTjJVdXZPemxsNzJ6Q3JGNmdETVpKZmFiWGlYaFBiSnp2?=
 =?utf-8?B?UGl4d3JsZVhuZVEyTUxZcE9GbVo0K2tvTlJGS1BIZnBiOHY1YXNqNzdGNWVi?=
 =?utf-8?B?NUhLbzhXNFZyRkhDM3ZETGI0M1c0RVp5WHNhR24zZm53TzdqWVl1c1JJYlVI?=
 =?utf-8?B?Q0ZYVFNPZisrSUQ0TUw3TDBxZXVwZVg0aXdBM3A0NUdCYUh1cWl3NXgxVWRY?=
 =?utf-8?B?ZStEVWpmMVFsaVlUSUk5Tm4zY2NNaEU3VC82bGt3L0RpUy9ZOGpuMnVLam9Q?=
 =?utf-8?B?MW56Y1VXU2pWM3NiWWJHRU1YbUJoWGFrVENFbEdFYTFHQlZ2L2g1Qm40Zkw5?=
 =?utf-8?B?OUFRcWQvZjRKbE85eCtSVUp2US9aak5CNUFWVUVuTEdIbS9mSGI4R3ZyR1Jk?=
 =?utf-8?B?R3NERnp6djd4d294R0xrWFVOd3JrZDluVmhGalJXMHlFUEFZTzJDNk12VzZp?=
 =?utf-8?B?eW9EaU96cDMxV1FIb2xZZzlpRi9xbzNkZ2ZPZDQwMjU2dEVoc1d1Z00zZ1gw?=
 =?utf-8?B?bkxjeCtXby82cG9Db1VtMW5ZaDBXYnNEdGlicHFqWEVzQzJVTVJYdHRDNGRh?=
 =?utf-8?B?KzVUNy9KVmowZjExMDV1K1FsbFlpNDQxNFh0dng0aDRoSy9kOXg2aEo4K0Ev?=
 =?utf-8?B?RHJGSEg1cGFSUklmajI4U2dzWVBnOHM3N3l6djlIWjg5RURVeTRrd2pzeXor?=
 =?utf-8?B?enVmMmExcUpNY2VQZCtPeGx2Wkh2NmxkVSt4eDYzK0xOdzJLYTd4alVlaHJm?=
 =?utf-8?B?WmZXaUJMbjlzM3BMbE5HNFN1SmJMbGpRbkxKcTNwWFlWLzVYckV1Nkp4dEU0?=
 =?utf-8?B?NENtYlcxSUZPdEI4VmI0ZEJWUEVXYVcvdUZSRVQzREpNSmgrNFNSOVFMdTBF?=
 =?utf-8?B?SlZjcTlpcTZyL3ZTQUFaL0hnTXh5R3BpN09LYnRGNmFjVkpVbDVYaTNVRWcz?=
 =?utf-8?B?WnMvYUdDMmZ3Z3FuaUdaQTRYVkdJb0VQSHRiTlR4Z0Zaa2JjTGNBYzAyVGMr?=
 =?utf-8?B?UitHT1lrZ28vV2NVNFJIbmZzakxlbWRuOEx2b3dheVRkZVJFY3ZNbHJDNzdM?=
 =?utf-8?B?SnVuZDlzQTg5Y09ZSU1DRC9xRnhwYmRMWmdZYUVMSDRlUWlkMjhoaEpEeU9v?=
 =?utf-8?B?SUQ1T1BDZlV4enRSbEdTUGJlc3MyeU9hcjRkRXVzaVBUVmhQZGtqaER0WDdk?=
 =?utf-8?B?T0NHdVhITFlOTFd1UHZzblFrTlJFKzFoWEk3aE1GVHBLaEpvNUxzdU12cFll?=
 =?utf-8?Q?dvXs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH8PR03MB8275.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?UGtjL2gvMkhMVmtNV2E0OVdWMWhtdGpSSmI2Y0xOVHhvUmVjS1NzNks3RExk?=
 =?utf-8?B?cXRQNEl5RklVTFJvdnpCWHVKU2JkM1BPalQ0N0pUTG5OTkxNRGRkVnZUcnFC?=
 =?utf-8?B?ZmpSQmJ5d0pZNis4eXVnclZFNVhxUjM4RkNnKzJSSjBzUDcxcVQxUC8razJC?=
 =?utf-8?B?eVhzN2ZPRU9zNTNuL3pqeFRpZ1habFdlSFNZdEhpOVFRTUxHaHpGM1FiRG54?=
 =?utf-8?B?cFhmbllHdmdxODRKdVExNUxTa1l3ZjNud3ZHWUJBMmJFcS9NUEhveE9DMHZY?=
 =?utf-8?B?WEk3QldSVEpSVFBlVVBEWjB0Tk1qaVc3MU5iMEhXY2M1NlRGcXMvVmRpdGdU?=
 =?utf-8?B?NVJZakVkQW9CQ1c0L05NTkpGb0wxd1Z0Y2NNVGMvWWtPeHpZbkpJMDdZcnlv?=
 =?utf-8?B?enIwVWhDTEhXd1gxWDlrLytiUHVJcUJQWVMzWWIxcGdpUkRqVDVRd1FkUmZa?=
 =?utf-8?B?c01wM2luTDNPY0I4OUZmY3JDN2NnTE9RZzViZ082NkZaUlVsQWlYSjBUajlD?=
 =?utf-8?B?T3NlTWRtUzR6QXkvYTRzZW9YMmFMaUVwaTBRNWl4NHdWM3YrQi9LTVNFM2lQ?=
 =?utf-8?B?dVIvbis5b29INGRweTAxOWZYV1g3dCtpUWxaNUVxaGFGY1M5c00wWUxRemww?=
 =?utf-8?B?aVJJNGFObzJYb2I0Zm9NYldJRlA1K0JKNlZYeXFFWlhDV1ZBS3RGOUdMRUpk?=
 =?utf-8?B?RjEwbTdLdGdNdFd0U2tNUHRGOFF6L1hsRG5tOGVaS2xoalF2dkJvZW4ra2du?=
 =?utf-8?B?ZUdjei92KzFOWmZIU2RWMC9UNTdWS29FcUV4UGdWSUNHeHdVQWIzL21jV1RK?=
 =?utf-8?B?ZktpTFNxclU2Y3lTOGZ2eElFdWZMa1NkcDNiSy9KY3JneStXN1JSVEVZSmlj?=
 =?utf-8?B?OEtBQ3NURVV2M0JLYTR1Z1FUSThzV1FCOTI5cmM5UnhWUmJidDUwWTZnR1ky?=
 =?utf-8?B?am9ab1A3TVo3elIzQ29qcmVSdk0yYlZLd1daQzRnM1Y0NHBTV0VqSC9GQ2Ey?=
 =?utf-8?B?MEhKMFdWamsvdHJsWFJYNUZCaEJaaU94NjlibWJPMWNBLzY2MUdDY2FNbzRC?=
 =?utf-8?B?UWJqMHlnTkFKaWJ5NVNxVmVkK2tNVldPUmQyNXNDZmtUaHBJMzY2dXVPQnpR?=
 =?utf-8?B?UUs3bEEwYzhZNWdZWlc5LzJzZTI5aC9qaXdLZjk4Z3JGeXJzVWI2UWUxNGtO?=
 =?utf-8?B?bDBrblRwakhObHdZVVZwbEFsK1ZzYjM4dFZqMktzV0ZkYW12VThPMVJUZGtQ?=
 =?utf-8?B?cThUYytZd3ZtanN3K1JrZHBObUFIYnFLN2YrSHRjOVh1SWsyVmZQcnM5VnFB?=
 =?utf-8?B?b2pKRWwwdjhpdzQxeVRMeTYvVUlTWDIxUDEvZU5VM0NPM0JaS21RNHd4OFlz?=
 =?utf-8?B?b2FSRndHNXlYcTdzZkdKVG9aTjlndFRYTkFGS2hVeHZ2b0tRNUI1eTNsUU01?=
 =?utf-8?B?M0FOa05KWkRjQjgxV0RHSlBESlhJM3JWNmpkN0Vnb3JKM3Nqd2hZbzE0cU4v?=
 =?utf-8?B?S25tcGdBcld4NU9pQ0xYQ0ZtRENtTFVtVFJLc0krMjF6ejI4a2lJbmovNnNX?=
 =?utf-8?B?a2Y5NGlsaHd0SkFTeGJyVU1Dejd6TnVVM0tGRkFscVRkVmhQblB2U09vazB1?=
 =?utf-8?B?dWpaaFlHaFdRY1pYd2xpaU1QUHphaGtRSGdrMHB3NC9qdWZJVHlheGQ0K3pl?=
 =?utf-8?B?cGd5UzQzSWlmRlV1SG5XbDdQSENMSlJUK3BYMGd3N0d5U0NGV3pTRU5OQmV6?=
 =?utf-8?B?UWEyR2xwNjdOUzVJOW9uYnlzQkpPNDF6MGNVSHdqWDQyWTE1L0Z3N09NYTdx?=
 =?utf-8?B?TzBrNXVFbnNmK3BPUGVLMWpQQ1hqanArWWw0SGJ4ZGdlOTBCNUFtU1ZwdmVp?=
 =?utf-8?B?NWtmNldiT3NwTjZacThGNWt6eUxpTitDaFZmaE9qaTJEWGtFQUJjUE5vaTQr?=
 =?utf-8?B?dnFMcEQvNU9WbmhUZE1TOUJaS0ZldEJ0NURpcGlBZDZxOFZXZ1BzSWY3YW85?=
 =?utf-8?B?cUtqTHNXL3J2dUFxZ2Z4T1dvQ1hiL1hzelVVVjZhSW9VVm5ZL0pMSGx6YjEz?=
 =?utf-8?B?N0JhWmVmVHk1Q1N6WTAyaVFhRm9iVFYyWEtzS3ZwRkk1L3AzK0k3clRnWW05?=
 =?utf-8?B?NVJSdzFjTFZIbWNzOWVnVUJtYUhmVUpBZnFqdW5UWGtQL0J0ZnB3T2Z4WDFl?=
 =?utf-8?B?ejFLZ3Y1dUo3T3FzYjAzVmpISnNUTGJDTFplMTZSUHBaRTdqdGwyb2gxZDJC?=
 =?utf-8?B?Unc0VUVpaWpDdzl2Yi9wYXg4NUNnWGt0djV5TnB5MEs4QkZxVmdtSEkrUUtM?=
 =?utf-8?B?RlJWYXpubmVsVTlFeWZtdHJCK3pNeDJIeU5vUzltVW1pSE1lalF1QT09?=
X-OriginatorOrg: citrix.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b9d28a8f-7224-4980-8e2f-08de5d1b9a7a
X-MS-Exchange-CrossTenant-AuthSource: CH8PR03MB8275.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Jan 2026 20:43:47.0964
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335836de-42ef-43a2-b145-348c2ee9ca5b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 9KntVvmfMLJ4t8lFJEX6gnICv0d7Fxl+c41HjUj44t+M54fRrkTJ1H5O0dsgPFxoxpRECCNLluBR36tx5wKANhhGKn+Qy5qOurFo1n7H1EE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR03MB8296
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=selector1 header.b=LgbkJRRy;       arc=pass
 (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass
 fromdomain=citrix.com);       spf=pass (google.com: domain of
 andrew.cooper@citrix.com designates 2a01:111:f403:c005::5 as permitted
 sender) smtp.mailfrom=andrew.cooper@citrix.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=citrix.com
X-Original-From: Andrew Cooper <andrew.cooper3@citrix.com>
Reply-To: Andrew Cooper <andrew.cooper3@citrix.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.29 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_RHS_MATCH_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC6ZNIURTQNRBBVE37FQMGQELMZ2FZA];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	HAS_REPLYTO(0.00)[andrew.cooper3@citrix.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 517A98D38F
X-Rspamd-Action: no action

On 26/01/2026 8:41 pm, Ryusuke Konishi wrote:
> On Tue, Jan 27, 2026 at 5:22=E2=80=AFAM Andrew Cooper wrote:
>> On 26/01/2026 7:54 pm, Borislav Petkov wrote:
>>> On Tue, Jan 27, 2026 at 04:07:04AM +0900, Ryusuke Konishi wrote:
>>>> Hi All,
>>>>
>>>> I am reporting a boot regression in v6.19-rc7 on an x86_32
>>>> environment. The kernel hangs immediately after "Booting the kernel"
>>>> and does not produce any early console output.
>>>>
>>>> A git bisect identified the following commit as the first bad commit:
>>>> b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
>>> I can confirm the same - my 32-bit laptop experiences the same. The gue=
st
>>> splat looks like this:
>>>
>>> [    0.173437] rcu: srcu_init: Setting srcu_struct sizes based on conte=
ntion.
>>> [    0.175172] ------------[ cut here ]------------
>>> [    0.176066] kernel BUG at arch/x86/mm/physaddr.c:70!
>>> [    0.177037] Oops: invalid opcode: 0000 [#1] SMP
>>> [    0.177914] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.19.0-=
rc7+ #1 PREEMPT(full)
>>> [    0.179509] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), B=
IOS 1.16.3-debian-1.16.3-2 04/01/2014
>>> [    0.181363] EIP: __phys_addr+0x78/0x90
>>> [    0.182089] Code: 89 c8 5b 5d c3 2e 8d 74 26 00 0f 0b 8d b6 00 00 00=
 00 89 45 f8 e8 08 a4 1d 00 84 c0 8b 55 f8 74 b0 0f 0b 8d b4 26 00 00 00 00=
 <0f> 0b 8d b6 00 00 00 00 0f 0b 66 90 8d 74 26 00 2e 8d b4 26 00 00
>>> [    0.185723] EAX: ce383000 EBX: 00031c7c ECX: 31c7c000 EDX: 034ec000
>>> [    0.186972] ESI: c1ed3eec EDI: f21fd101 EBP: c2055f78 ESP: c2055f70
>>> [    0.188182] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 002=
10086
>>> [    0.189503] CR0: 80050033 CR2: ffd98000 CR3: 029cf000 CR4: 00000090
>>> [    0.191045] Call Trace:
>>> [    0.191518]  kfence_init+0x3a/0x94
>>> [    0.192177]  start_kernel+0x4ea/0x62c
>>> [    0.192894]  i386_start_kernel+0x65/0x68
>>> [    0.193653]  startup_32_smp+0x151/0x154
>>> [    0.194397] Modules linked in:
>>> [    0.194987] ---[ end trace 0000000000000000 ]---
>>> [    0.195879] EIP: __phys_addr+0x78/0x90
>>> [    0.196610] Code: 89 c8 5b 5d c3 2e 8d 74 26 00 0f 0b 8d b6 00 00 00=
 00 89 45 f8 e8 08 a4 1d 00 84 c0 8b 55 f8 74 b0 0f 0b 8d b4 26 00 00 00 00=
 <0f> 0b 8d b6 00 00 00 00 0f 0b 66 90 8d 74 26 00 2e 8d b4 26 00 00
>>> [    0.200231] EAX: ce383000 EBX: 00031c7c ECX: 31c7c000 EDX: 034ec000
>>> [    0.201452] ESI: c1ed3eec EDI: f21fd101 EBP: c2055f78 ESP: c2055f70
>>> [    0.202693] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 002=
10086
>>> [    0.204011] CR0: 80050033 CR2: ffd98000 CR3: 029cf000 CR4: 00000090
>>> [    0.205235] Kernel panic - not syncing: Attempted to kill the idle t=
ask!
>>> [    0.206897] ---[ end Kernel panic - not syncing: Attempted to: kill =
the idle task! ]---
>> Ok, we're hitting a BUG, not a TLB flushing problem.  That's:
>>
>> BUG_ON(slow_virt_to_phys((void *)x) !=3D phys_addr);
>>
>> so it's obviously to do with the inverted pte.  pgtable-2level.h has
>>
>> /* No inverted PFNs on 2 level page tables */
>>
>> and that was definitely an oversight on my behalf.  Sorry.
>>
>> Does this help?
>>
>> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence=
.h
>> index acf9ffa1a171..310e0193d731 100644
>> --- a/arch/x86/include/asm/kfence.h
>> +++ b/arch/x86/include/asm/kfence.h
>> @@ -42,7 +42,7 @@ static inline bool kfence_protect_page(unsigned long a=
ddr, bool protect)
>>  {
>>         unsigned int level;
>>         pte_t *pte =3D lookup_address(addr, &level);
>> -       pteval_t val;
>> +       pteval_t val, new;
>>
>>         if (WARN_ON(!pte || level !=3D PG_LEVEL_4K))
>>                 return false;
>> @@ -61,7 +61,8 @@ static inline bool kfence_protect_page(unsigned long a=
ddr, bool protect)
>>          * L1TF-vulnerable PTE (not present, without the high address bi=
ts
>>          * set).
>>          */
>> -       set_pte(pte, __pte(~val));
>> +       new =3D val ^ _PAGE_PRESENT;
>> +       set_pte(pte, __pte(flip_protnone_guard(val, new, PTE_PFN_MASK)))=
;
>>
>>         /*
>>          * If the page was protected (non-present) and we're making it
>>
>>
>>
>> Only compile tested.  flip_protnone_guard() seems the helper which is a
>> nop on 2-level paging.
>>
>> ~Andrew
> Yes, after applying this, it started booting.
> Leaving aside the discussion of the fix, I'll just share the test
> result for now.

Thanks.=C2=A0 I'll put together a proper patch.

~Andrew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
013cd73-a99f-45bd-959e-8fe2750281e6%40citrix.com.
