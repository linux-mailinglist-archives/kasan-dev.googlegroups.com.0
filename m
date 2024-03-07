Return-Path: <kasan-dev+bncBCZLJOMFV4FRBQOBVCXQMGQEOYAVDFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D07B3875813
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 21:17:06 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2218f32ac7esf364486fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 12:17:06 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1709842625; cv=pass;
        d=google.com; s=arc-20160816;
        b=no52Gut7n9KlWtKv269EcKEnSrL2tVXwMvBhpJrmCA5B6YcwOHVlHwViUtlkaDMfFM
         oWQBbbbE9LoEOhYgsCscvzseBQbSsTSE0B8z81fobWoRNUh4fXSNCrrugScEaVCn1zM7
         jjieU3+uuYS4sll7hEOeiznnOPCHjU2QLPk0tAsIEZ8onDtpcPIWsGmVU9gWVPPaKWw4
         bOJQAy0F9ohSsEKg0fwhm8QTGGANH5r14eUmXmFMg/kBU59lIeQHxtBwZJPyicr3dd+Y
         GFJm/db3aEs1ZkzNwAL0qjnQQv1yDv5FHa3kqEtk2RHUtqEHb/cRQAzP10yLFYquoWg+
         3ixg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent:date
         :message-id:dkim-signature;
        bh=rAjihbS1iTCdw4jpi3BJ1uLx2ENyEhq6o52/Jki1J7Y=;
        fh=Em9pjQFuQW+231POFY8KxX12pVTkqVo+8ImDMQeA2KA=;
        b=Yq8pLqJYHi7NNGk3k0ZKCRiIpE5anBu364rbZ/VRTa89Urusf31ck5UdgdzV5MrE3J
         dmIuQ/qm0eNeJPssU+K4bh6yq7hsIpY0rHBSQD25/wD0EhFa3YaNsBdQIbVW189v7pow
         ky218vl/iPwOOOOdVOZG93lSHOUkxQYnlaGEx25pdE5+IE6OFRiAK2ee1bExe16jM3Uh
         eG6fTShVYywwVg/Fxh6nXKMUiPuEvNLxPPpJzb0xYIxyQ+7UfjHdKijwk4tg+KvS0SMi
         VvcU3UeudXWUjU7SziKETTd1L0ckD3N/laaZ0PrE4JWsJqP8pbc+YtBTByDB8FzFE0QP
         DXXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=T7vZfY88;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:200a::601 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709842625; x=1710447425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rAjihbS1iTCdw4jpi3BJ1uLx2ENyEhq6o52/Jki1J7Y=;
        b=wyJr0FgeSXrlxvjzqYOBTGgWKa09Q7CXbagmO/D39NI3FxPeRPLyt3minFJwYFSJ37
         N1QgSOSEX4z9EXSgxcibHzvp+BjaONRG77Ee44O7pIGmvRhhp8e2TP1xBC6f6X2CKTgo
         kJdjgOLWVGV/zCzQuP1Zsqe9PvhPUN3vUZAKt7lWmgg4z5stFixY5Hs8KEPgPTe8spHm
         egtgEB9lqvJkTeifsP8PAe0g+J+om3Ukh7rs4XP87d+2cF3AMqEt0kds/GBmjwT9RAGw
         /x/Eg26UGYXSuCXrs4uJL7vzXo26EcyVIhNraf5SZjLLjFnMw4Q3BPlx33sCPh2qHzvV
         GakQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709842625; x=1710447425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rAjihbS1iTCdw4jpi3BJ1uLx2ENyEhq6o52/Jki1J7Y=;
        b=wQbpn4HSsL4lU7NId1hIJy+fJftEZqHCFvQN99ubXaXgJ6tCcm4aqpv2oQKTzejGBy
         J2EDHkgm9ki7KgsDSCaPDZn7QK5YrvPyb+g2UJ1oR2h5uDnMSlHZq2Pp+FRcugexsOX/
         49+Gy4eZHOoJzg6t3AO2y6zSqBkpGblgAUz5EtiIHYHe8OI/9PE1Sou30nZoDCH2q2im
         yDcxWaDzsvAZrMiLc2s5f8fQooaeUmR7Lk8fKBX/kkWis1I4MqAe6ktvwYqEBYi6dUzA
         C0Jaj9X8KGmtQ3ROW/qHb+QkFVLlXwE93ZhRg5WAlDV+ajhD2VtqfrIT9982px+jJOjp
         m8eg==
X-Forwarded-Encrypted: i=3; AJvYcCU3G+Xqz+l2DlC9B/DDQ/VG0J8ZOqDjLpwSkL/cY00uI+0Go2LivG1ZXfAjTAWbWHaW4NGgbk8gJeeqS9cBld0az9cLdpy/wQ==
X-Gm-Message-State: AOJu0YxNxM/qKvp5645R1Etas63fhaTfzB/I7E/YjopXotm8A5oEycPn
	S9c7QE3+y13y+JssT2sWf0xktfTzRW5nUqatOOlo2EMt32O5hZXP
X-Google-Smtp-Source: AGHT+IFLT/acZviCGF31iO+plAX+3BV4JGjmRvd7Dg6Ey3cTLk9Wj9cggfifVBN5kHjqbCTSTFQYUA==
X-Received: by 2002:a05:6871:25a1:b0:21f:8de6:a6ac with SMTP id yy33-20020a05687125a100b0021f8de6a6acmr825647oab.46.1709842625520;
        Thu, 07 Mar 2024 12:17:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e48d:b0:221:4d34:2b50 with SMTP id
 pz13-20020a056871e48d00b002214d342b50ls1479736oac.0.-pod-prod-09-us; Thu, 07
 Mar 2024 12:17:04 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXIH13+ujQ5mSZ0BXYPaUmmXvE3LRbAdv+d6P7CQqzPBTF5+O+HnpkKvyIDp1DtDHdkD8cF9jWvH3LOeuMLeH8jBViD1ZWjZ87HzQ==
X-Received: by 2002:a05:6808:218f:b0:3c1:c124:6d4d with SMTP id be15-20020a056808218f00b003c1c1246d4dmr10060217oib.56.1709842624459;
        Thu, 07 Mar 2024 12:17:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709842624; cv=pass;
        d=google.com; s=arc-20160816;
        b=rB/1XJUUTnnOj+zj0Q/EjbuJfI1QL4rphPcpQPUVM6LfX/vITGRXAaTzZAQfPUYymK
         QqQNqLO55+W+NxQ1azAbtd+VnaolNv/kNK9uAiOjoOZGVEbRxRfxwAHfrzCIbQxvZNZQ
         dnU4atcy0xxBBVkYhl4mHm+iNwDVfw1wqUwIKtr6D20FpZHkjBuCvrsu71kO+KueNNiW
         00EkRSEYzEHGt6dTncB88nIl2juRkE4UwkEDL2hHZvqXQtjgUKyKguL410Ge3QpTAgc5
         Oc7LGAMYAmfMvHyqHrsqsIL5y4xOzmzDr6GcXF0U6UwQmbet3G+A7M4R+0/1Qg8rHgtw
         8AfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature;
        bh=H7s4XicH8YeybJo/rrKc8QE6AxNj/Mk8kfuPkU5a3d4=;
        fh=Hpr7F3FJIj/DtpvMjh880+hhRe7wnJRwNosW+5Vpvgc=;
        b=jjzT88CTzNzNcSo11bz9DKLWKWaFvqQJPQf7TpmpFOUyqdM6tcx6PTpN26TM4Gc2jV
         ynpP0ztDZJj2p8rTzvW02a0POgVNgB+45q9zInFeG5vLcnOYRIUHBJTWNtM6Hzr3/QII
         Z7/BTapy4Ek1pkXA+TXQVvqcd5RFR4TI7jnKl1jWyQuCqSgAOUpvd56UC6bTdQET+GzA
         a6QUNM+pIlckOM/0WxpaHRfP3NO49c6uBlYLDRwN5M1n1YCS7Ko5EdxxSyA9boU7ymzZ
         tcMabpFy/n02Ex6GsmfLIPsWdPESIIkbdJwTLOs1zJKYvTEVJFeDvcSQ1mszO1bLFKI3
         wWCg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=T7vZfY88;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:200a::601 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (mail-mw2nam12on20601.outbound.protection.outlook.com. [2a01:111:f403:200a::601])
        by gmr-mx.google.com with ESMTPS id dn7-20020a056808618700b003c1ea9f61easi671997oib.3.2024.03.07.12.17.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Mar 2024 12:17:04 -0800 (PST)
Received-SPF: pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:200a::601 as permitted sender) client-ip=2a01:111:f403:200a::601;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=YOlLTBwlMmZM4tvonNrG4XcUDT1W23QwizPhaTv2CY8wo5Oasq9VQEcpl/wt0zHlz7/wPG/+J4fDzs3cd+f7FX0aYlRgVa8iUrSWC3gtm0fU4aaf2Zg/VN5oRJocim9m6sE4U0M5cY4jLzwuyvgr3N1LgWwBxmzOGNVG7W2H2eGqi0GbtKsugx0tV1/qyTy3UjtaI4kRQf1es1yj5Mfo0KI9H6zLve+9zBsoOam3O7qGVTDUpXux8FWUda6kLOIfXxmfGooAFjkshE1G/kawmXia2QTy3KJaLMc1+pHebJZmhqyXYM5qd8xY9yGrFno/J4ghUxnsJHyHJJeaj1aaZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=H7s4XicH8YeybJo/rrKc8QE6AxNj/Mk8kfuPkU5a3d4=;
 b=IKjhN5gFUR0DHlkjrgaH7yQgpWKqR92BeMLVMm0vu4Y9em7uEnDpj3XqIQPX6dQAiiFx5Nre0/oLKZLDksw3uzJ+MB5cHzCr82ZqGY6e4aA0dRJ1zGKsImjwDC9CAquI3qQl3Xm7eDRW0eQ+D3+LayJV8yTW3WooAFrIyO7C3p2+JtXQFdWpOY64E6cVuklc119gIJGew3CnXnNoO6iQzkRKg8fDhkGsv00UVDIHPkdljYyZZuAnPgLf29qW9N1Bt511u0aG8opjDTV/tyB91btIYnR8qVOJTCnwkj9IeY8LeunOZyCJqSLy8F/9aLQAG9eX0XiV7NouS56lAHjuGQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from BY5PR12MB4130.namprd12.prod.outlook.com (2603:10b6:a03:20b::16)
 by CY8PR12MB7609.namprd12.prod.outlook.com (2603:10b6:930:99::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7362.26; Thu, 7 Mar
 2024 20:17:01 +0000
Received: from BY5PR12MB4130.namprd12.prod.outlook.com
 ([fe80::3889:abf7:8a5e:cbbf]) by BY5PR12MB4130.namprd12.prod.outlook.com
 ([fe80::3889:abf7:8a5e:cbbf%5]) with mapi id 15.20.7362.024; Thu, 7 Mar 2024
 20:17:01 +0000
Message-ID: <72bbe76c-fcf9-47c2-b583-63d5ad77b3c3@nvidia.com>
Date: Thu, 7 Mar 2024 12:15:54 -0800
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 37/37] memprofiling: Documentation
Content-Language: en-US
To: Randy Dunlap <rdunlap@infradead.org>,
 Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-38-surenb@google.com>
 <10a95079-86e4-41bf-8e82-e387936c437d@infradead.org>
 <hsyclfp3ketwzkebjjrucpb56gmalixdgl6uld3oym3rvssyar@fmjlbpdkrczv>
 <f12e83ef-5881-4df8-87ae-86f8ca5a6ab4@infradead.org>
From: "'John Hubbard' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <f12e83ef-5881-4df8-87ae-86f8ca5a6ab4@infradead.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-ClientProxiedBy: PH7PR17CA0024.namprd17.prod.outlook.com
 (2603:10b6:510:324::21) To BY5PR12MB4130.namprd12.prod.outlook.com
 (2603:10b6:a03:20b::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BY5PR12MB4130:EE_|CY8PR12MB7609:EE_
X-MS-Office365-Filtering-Correlation-Id: 18c9a58d-89c8-40d6-9452-08dc3ee38c0c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: X2EsV2IAe4FAnTQI+rB7lTLs7uoxGxby4zg3lV+Hh8RFantomVuzBAcyCRhg0rBaWddYxbEk/6WiwAw/V+6Lo7q0zdfSbYHrD5psu4u5J+szSWKwDZI2WwWPtm5FQcb81dEdOxg0XeqMmwDTrrOkg0jvSQfdrPGYnn6qrtWcZ9xv4dTy8X7VDnIKl0QUem4RzhettuoteOaOdtA+LFdCcF9aB3a12BULVDo1Rk7BRK46KDMtPEi2DpGm3RdfNhRZscZlpVqNr7Lh3Q4kqIHwhd3vC25BZ8Pme14RpXgnmF9VpujVjWK8xrZIrRwtwQ3MlUIKgveL6clVe6yNcr9uyByR2Oo1xQeqdpN8ztHaRe8SFg3wlp7es0QjHUKMylZeCjHPvKHWQ4kt51ddT25XIlAIitIxZIAj1PgU2RG3HKsJrbh/GPNu0vwc7r2VLmJaOlgoFHwGfHzzZ15Icija5pnClLOIYzmivK1vRYvhQncU4wfG18zg2jpVtAiUZXMeA6q54OPYDScfv7rSOMe3k7cfB7sbWV+JbxbmFdRNAezm2uXQoGceTVrgIZGslJQChI0krmJgWl3GQ02v3nDO/xaBcHbtljb++ww0UpSfG1qrgMMkwbWEC2xBQlj5TnXiN5fiA27s+atesxmbTFWaagY4PCp5zwx/lNh4qV1F+00=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BY5PR12MB4130.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(376005);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?RVRNRUhqNnlSbjJZUTlHbk9QQmVVNFppazFXemszWURWRVc2RHNHKzJWOFl6?=
 =?utf-8?B?dThTQ1lVUUdReGNyM01tb3JnWGJJNWp3Z3haTklXdmdDV09jaVVjM1VKaU5N?=
 =?utf-8?B?WU8wdzRCUWhWeGxMQ2UwMUdZSkd3MTV1dndNa3NRT0NEWWRla0U0b2I0Qm9w?=
 =?utf-8?B?Rnd2UkxreVBieEpjQ2xmWkpkeGc0T0hPZlZZb3JJU2xVem9LU1J6TVkyYmlj?=
 =?utf-8?B?SzVxQjkxQ3UwYmp1d0hDaVRiQlVDS3I2WFVYeVlMaFE1NkZtdWJVaEhJQUhZ?=
 =?utf-8?B?cHI1VTdGREZWOUFLMU9xZkowdUVIZHNkNDdYcThORlc5LzFjcjBXSURXOG43?=
 =?utf-8?B?ZnJEdzI2QzJLbG4vMHRIN0U5dWx4RlRBbW1YVkV0eFVVQmJONmk4ajFZU3RT?=
 =?utf-8?B?V2graFhEd3l1ODdGTlZPQUFqeSsvWkpCOVdoTzJMOU0wSzhVYXVRYXBuMWIw?=
 =?utf-8?B?cDIya1NDR0JQVWdzTFk4TFo2c3ZEOEJnazMvWmtJZEhPbmpORncwR1NOVU1m?=
 =?utf-8?B?U1FpUDBpVTIwMER5dFZJOGFudkpnNjFBbExMYnlTMzVEejJFZk81KzQzbTZP?=
 =?utf-8?B?U1d6MXNaYVEybFJYOGcwU215S2tMRmZLSEh1L1d2bWtHdmppMVh6RHhJT1hP?=
 =?utf-8?B?eWY1dGlWakQ5Q0xMK1l1Qm5XRGhiY0lnaTh6clp0Qk5vWk5SZlh4MVRwSVdY?=
 =?utf-8?B?d3BMc0lKMFd3Tkc3N2pZK2FjRDcxSTFnLzBacEdRWkRqTlBZZjByVWNjL3V3?=
 =?utf-8?B?b1JaT0wyZ0V6R0xuNE54VGdVcnVsaFpHYzlSTzRZdE4yRVRxbGxuaW9ZNGo2?=
 =?utf-8?B?OUJKbk1HdmNJblo4Q0JlMGNGWFE5VnN5anA1Tm1tWVg3Z2tOOXQ2N0Jrdlhs?=
 =?utf-8?B?Ty85blJiN2FqZWhZS2FqK0VZd3pTMEV2TzdsVzErZ3pUSEk5YzVjdnQzWkFk?=
 =?utf-8?B?eGZrY3NsL0ZQMVZWaGtEcHAxNjNvKy9TTlVRNWtzNi8zMWw1N2o5aTZLOVJK?=
 =?utf-8?B?N0grd29ReDRLbGlZbmwrQmZEYkZ2Tjl3STNwNjNsazJ6Vm1tOTh4MThGUVJE?=
 =?utf-8?B?S3ViQm9OOG1TcnF1dUhiQ0VtTDRiVlMyUFZoNDg4UUhhdFRPUC9sdlIxSUhU?=
 =?utf-8?B?NUJ4MXF5clNBMmxudmxkeldNdUM5NUpVQ2xwcTVnMEpJK1phQS9WUzI3VnFC?=
 =?utf-8?B?ampxRmpkak9tRFZRMWJMcGp0b2pKamw4VFNvMGVHTDVRS29PVm5HOHd1dnFJ?=
 =?utf-8?B?YjYxcGt4bmw3NCswY1Bqd0YvdTludDdka0tVY1VkaVdWMUpWRmRlYk5Ia3NG?=
 =?utf-8?B?dDMxVDFxaEtmUk43ZXg3S0x6QXlodWNhNkdCOUkxeDdNOTBHUVZsRDN1QnZo?=
 =?utf-8?B?RE1BOXlSNG92NjlUUW5waXh5UXdRbzc1c0JzUk5hK1o4alBVL2NGL2pUWnlX?=
 =?utf-8?B?bENSNHNmVldSTGx3NjI5NmJvWDdGUzVZbm5mVFpwRFZ4MEpsS2hhKy9KNTNT?=
 =?utf-8?B?ZkYvVU4reXFIWDgvVnUrdURBRmRhSEl6T09UaTJ5YmV1eDl1dzBIc3ZYMjM4?=
 =?utf-8?B?UXBnVjVZUm9xdmVYREFwRC9OaXdzZktDNmZpdEJzNHJQdFhzY0RDYU5hVU54?=
 =?utf-8?B?aGcrNm1ia3ZvK0xRRTFXTTNIajZXSFN4QTVpZWNZYk1hMlZpNTVNVXRrL3Iv?=
 =?utf-8?B?eVVuUGZCenZaK21VQVV1TnU2LzFsY245VEFwVEllQnZ5ZzVXRTRUV3pCRGhx?=
 =?utf-8?B?R3BhVnBYNUdLS1A4TkhlNklpTmpQVS94TldQZ0crUEpnOC9KTlRueG53ZHp2?=
 =?utf-8?B?Z0E1SjduZ3VqZ0tyTmxKYzAwTjRudmw4VlBzamhhaVYyQlFVUnhJczhENW5T?=
 =?utf-8?B?Q3RIaTBoVXAxNkNoS2FqbHpLblQ3TlBsNmt6VmFoYXNNdm9Fd0NreUoyeE15?=
 =?utf-8?B?YVlCcFcxeHROUUdSL05TSWhmQjhnY1ROeVN0dHZzVytpc3ZRRTNabHJHUFVD?=
 =?utf-8?B?Y0ltem1NVTBFSXRSQVR5UXM5NTlCWlcwdXlDQzQ1US8vR3pieFlIRFAxbVNn?=
 =?utf-8?B?Vk8zaXNsR3p3Y0xKZkpRandOdGVDNzlwRXVTV2MrYTNjbURadzdWRVorSGNQ?=
 =?utf-8?B?QTNNSGcwejI3MlpVaXhLQll4TGZFU0J3NzZTeWN3am04M3YxOVhBdmwweW02?=
 =?utf-8?B?amc9PQ==?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 18c9a58d-89c8-40d6-9452-08dc3ee38c0c
X-MS-Exchange-CrossTenant-AuthSource: BY5PR12MB4130.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Mar 2024 20:17:00.9231
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8aX9+cx62u2VWbPatFvmRIH0FEDGtvJ01V77+fNZobRLlIU/4l9yam0PDiX0zd2ehjS8vamskC4Is9iiR7oNtA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR12MB7609
X-Original-Sender: jhubbard@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=T7vZfY88;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of
 jhubbard@nvidia.com designates 2a01:111:f403:200a::601 as permitted sender)
 smtp.mailfrom=jhubbard@nvidia.com;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=nvidia.com
X-Original-From: John Hubbard <jhubbard@nvidia.com>
Reply-To: John Hubbard <jhubbard@nvidia.com>
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

On 3/7/24 12:03, Randy Dunlap wrote:
> On 3/7/24 10:17, Kent Overstreet wrote:
>> On Wed, Mar 06, 2024 at 07:18:57PM -0800, Randy Dunlap wrote:
...
>>>> +- i.e. iterating over them to print them in debugfs/procfs.
>>>
>>>    i.e., iterating
>>
>> i.e. latin id est, that is: grammatically my version is fine
>>
> 
> Some of my web search hits say that a comma is required after "i.e.".
> At least one of them says that it is optional.
> And one says that it is not required in British English.
> 
> But writing it with "that is":
> 
> 
> hence code tagging) and then finding and operating on them at runtime
> - that is iterating over them to print them in debugfs/procfs.
> 
> is not good IMO. But it's your document.
> 

Technical writing often benefits from a small amount redundancy. Short
sentences and repetition of terms are helpful to most readers. And this
also stays out of the more advanced grammatical constructs, as a side
effect.

So, for example, something *approximately* like this, see what you
think:

Memory allocation profiling is based upon code tagging. Code tagging is
a library for declaring static structs (typically by associating a file
and line number with a descriptive string), and then finding and
operating on those structs at runtime. Memory allocation profiling's
runtime operation is simply: print the structs via debugfs/procfs.




thanks,
-- 
John Hubbard
NVIDIA

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/72bbe76c-fcf9-47c2-b583-63d5ad77b3c3%40nvidia.com.
