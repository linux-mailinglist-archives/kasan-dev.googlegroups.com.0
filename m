Return-Path: <kasan-dev+bncBDZYHIXQT4NBBOM3T3DQMGQE3KH74QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D582BC876E
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:26:03 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-332560b7171sf3066288a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:26:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760005562; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ecjn9lgzSC13lHbKuoPPfBHHM2AS4Pt7pmXlK5eKWTtrNJAW+zjNxuvOOVDZlzTZCa
         3OH2cihehVEd0g5zD4Ti1Gu0iWJDphg9SwgOton6vqFeOWbCRP4GQ+2mCn1+vmRRHS8s
         f0FRgNSC6iXEVsWywkcOWHqpvOzBRESCSGYngqMs18IawYEc2Xe3aaVxzvselzJz+sbC
         gvX8HaSy+IZyuPZ+IeZ6oxWqmOspvlvlCLk1dgv3lh3r/2EtTjiukC0CsjovgkWAeiac
         bvJobImAsTXZ7nvzxdejUmE6HP82iqaYl0ySdvqM9G99UfEBYSHHqW76cN74BxfN+/AE
         P2/Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=O4HKxHA9LwtglqPi3hdY9umbzPoJ778+NXdoSc7zLRI=;
        fh=N54zgVlTZC1viN/wxmPNlZKyJTxfHI/eNRT3NaaG1Tw=;
        b=TLoWMYffjtyOqNMpXEaw7wgg8lsXSsYPg3wk8CLdhBuYrAi/KIOP2ATWZRUgP4EO/Y
         m+G9cyew3ls1hfaVSID+VVT2UTYuzTPyAKjAl9UHLl0/A14NgVXbNuqwcePdipoQklDZ
         55jo4Td8AFyaD7M5l3shJdGcJgAI2Shmuzf24lxm2H6tguz81dcBbP+ybtvM2jlnu5FG
         LsQXYgrlqIqMJbDEMTzpMWXgvw4/MMmSHl3C9uwQ9lnj6vyXKMFvPUqL07f56JFxAuof
         D1Lb4Noj/dQ8/SNHNKDQRAzB0O2x4cvaid82by1zdSHQbgNRwf6dvarSN1I+F+tGsowK
         LiBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=AEkkbBeT;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of balbirs@nvidia.com designates 2a01:111:f403:c10c::1 as permitted sender) smtp.mailfrom=balbirs@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760005561; x=1760610361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=O4HKxHA9LwtglqPi3hdY9umbzPoJ778+NXdoSc7zLRI=;
        b=jL4CsisojcQAt+oZhQC/wo49hZ28/IS0oteHokEpDB4JjCK70VmuxCdYGpj5Camw7S
         A8Us4Zh7aecU9vKAeqNGUP4GarD2oyJ76G8LXpduuM0kT5nDUoNfjLOwpX+cF+7rt4lG
         dJKgfW6lgPSMLouf5xqOjDz0vr/npnlj6kjEFedREcAkmHvGyGMsT808kqLg1KQSQws4
         woUnlMwpQwnHTxcXj3sL9kKmvDM4LFlzNv1BLAJT/DQRLZRB3Btl7XtlfnxFeAdSS+y9
         zVprT3cJGgsJa/k5NQVgolJabQulnGlR6KnQdCl9b59QyXFpFFWi9I4Rp7BoNP70/zlt
         +gcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760005562; x=1760610362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=O4HKxHA9LwtglqPi3hdY9umbzPoJ778+NXdoSc7zLRI=;
        b=CEzOqxAlT83aypFseG/GS145t4qFgnVr6aVywaiGP9GWxJ7HIezyw2FLbJE4t7SxyI
         cFnwNld3Un5NnCY3V9AJmWPwcP/k5cLUcYEB4FRqfH5BuMg6Ptw89vF3EpGeLf64QW6F
         N3hghVLr7tyQ7/QJYZ8E79gZdgCa7OVqLCqKsm8g27fdWl8YngltgfsDi4uGYTVdrzoS
         h4ZOWTu3bvmasy3E7G0H6JMeKJhO4H883KdV6R6STwSGq7upNYaWFEfInJEMGv9jEae7
         lLdpQqFmwCemI49YoncgZWo7Nk704ihcb4fkRdJJ0WiLe180oKFWlUcPXuVy/clG300b
         0YNA==
X-Forwarded-Encrypted: i=3; AJvYcCXQl/awsVd1rsvG1/phxrQWoCAdjYeYQZ0cUP0bFsu0Q/kIku38WPjE2noNVorT59QORttFnw==@lfdr.de
X-Gm-Message-State: AOJu0YzsqEhAnLxYlOj9Dc3RJj3/KAzwFNeCZfDCL+A/a5a4OKkPtSeY
	054BAGqBa8UlOll641nvpF3jnnX0TvVGjxKQg4GrYWwXBiGQdANsi0U3
X-Google-Smtp-Source: AGHT+IFiiXkSMo4I7aNaXYbm0zl7zTqZ7KHAlNuXN8AN8Pe9XYO6rJx2CKBU+XSg6x90j6Xe+RxiOg==
X-Received: by 2002:a17:90b:3908:b0:32e:7ff6:6dbd with SMTP id 98e67ed59e1d1-33b5154dbb0mr9294864a91.0.1760005561615;
        Thu, 09 Oct 2025 03:26:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6mlFnqV3n4p48h44QQ3Qz3r4K+CNbEjLnWQp9qGoam4w=="
Received: by 2002:a17:90b:4a82:b0:338:3b76:8c40 with SMTP id
 98e67ed59e1d1-33b5985a6b0ls578187a91.2.-pod-prod-00-us; Thu, 09 Oct 2025
 03:26:00 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX69rdHFHPLgP9F0ZKiWE4mxaY14If5t8HGqIobDyhyuMC/vG2LL+9HInWMPZKALjMNQiRpOQzlXn4=@googlegroups.com
X-Received: by 2002:a17:90b:2691:b0:330:55de:8c20 with SMTP id 98e67ed59e1d1-339eda4935emr13945018a91.2.1760005560198;
        Thu, 09 Oct 2025 03:26:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760005560; cv=pass;
        d=google.com; s=arc-20240605;
        b=An/NqTFA3yCp8VuSzgtOuk6ObyAjz61JH+5MBPrQnDzdhLZTUeNLoSeVVyBvx/tmi/
         Zj1fmhZYVRYlICb7pJiHeO7OwPlX+Sh8pXhwSQso5XASia4/6hOTgxhyjczgMLin91hj
         d8M5B8QObWnRC3GDGOCaIQCqaLSFVRXVBVD3T8v21KygWn+6EfNuFnRmm0B17T2Ms9Gb
         i9OyRuSYEVJl/G6GvsPfQAGM90f0UQFuHRMKXmyuUIQy3VriqPeYZGWe/uoJdOQ2fkgS
         xbGu3dkrtnUMRpjmB3wkxBQbruORx/f7dmP9eXGEy81S67llOnf7fAYsA1gSaxxuhezH
         L4gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:date
         :message-id:dkim-signature;
        bh=biWLAK0VQUxowCTa/aYyaJoQmxJX91FUNylh8OApvso=;
        fh=a9tDAJI/CRsp0mrhqJymePbeUPsR67CSIJP1fIig1pw=;
        b=BXT6vWThVQClEUWNpYPtWIhCb798U+7XkBzvMWj94XU+L704ObwLEpSvpM6tZEw3I2
         L/Kw8IW+quNss15mabcKNzWwZ7TC+5/yGS1tW6GBf9UzBHTVuyo4UFYK4EcBJAcMGjf4
         3FkG7iSGxE9GJtykLyB9y4KqXPHC6KtAPNfCvXdgt75S5TDJC5Du3bC+DIolTFDCVsfi
         xWz3P2l2dAOJtLKmaAZUV064XH5wSqON03GQuEloc2ylAwr5fMQX10DOzbaFUeFU/HeJ
         CV5dp5On26rtqwhVMaOBYEn97X2MUa0eKl2NkkWW/OvcVJfARaXglY5bHGoGDgDGhy2f
         biXQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=AEkkbBeT;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of balbirs@nvidia.com designates 2a01:111:f403:c10c::1 as permitted sender) smtp.mailfrom=balbirs@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SA9PR02CU001.outbound.protection.outlook.com (mail-southcentralusazlp170130001.outbound.protection.outlook.com. [2a01:111:f403:c10c::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-33b5294842fsi181960a91.1.2025.10.09.03.25.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:26:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of balbirs@nvidia.com designates 2a01:111:f403:c10c::1 as permitted sender) client-ip=2a01:111:f403:c10c::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=LPJawCBvlNpu1oP6SlGKaWPBKvCgBaXt5knCw9W5wgVd4wWV/8/e41tFIaVtoi+DvySnbctSfvpq7CECOAGMhSQXGPyfG0dmZfULenc+8E/EbDX2c/JaEwDcWcCP/XJZ5N+a14wbVJTurk/LGUkmprOT8gMmrpszr1b0ZPZN6sUXDfMDdraTBYS194onXyzh33kANiy+N5W8iPhufLHhMyl2z64WF4KY3UlAO7/qMKO2ELzMOEDjHVLqa/HeHgtpvgDM7dlOEvWlbDSGlkiNkcHIXaSCgCsQP0lX7NnsC/3OPHks/xXQXgsCGJ+YTQaLanVWz/zIseYB+0qm6J7jTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=biWLAK0VQUxowCTa/aYyaJoQmxJX91FUNylh8OApvso=;
 b=tjsBr5Rnu5JUB2YChOCfBtXX1sASbxwpxG4kkVS/3ae+g8Ju5Kn9TG8CzxtNbWIAIFml5MdvccRpjTvwATmwbSlkEaqrtu92jb5mQsvvDu5ezwU8QbBAAzqZMvxmJz34C3Od8JUbZipM9hXblov1PorErrfKBa+xtpzUuA6vT4/XtD8l0xMqkJjQ7RhY/BQtCpgUM9U1R+YORnhMFuojrgNxUTVtqQzBsIW5+9emmTow1BETlURWrQ+fA4TWh0H1eTgs3miNOVB4nHwuxVnLAe+qjqgafrccFVwqktIW1+3qCLkaujFBiU5nDGg/sfs/TwL+Fz3y2zJH7Fk9fULZiQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH8PR12MB7277.namprd12.prod.outlook.com (2603:10b6:510:223::13)
 by PH7PR12MB7455.namprd12.prod.outlook.com (2603:10b6:510:20e::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9203.9; Thu, 9 Oct
 2025 10:25:53 +0000
Received: from PH8PR12MB7277.namprd12.prod.outlook.com
 ([fe80::3a4:70ea:ff05:1251]) by PH8PR12MB7277.namprd12.prod.outlook.com
 ([fe80::3a4:70ea:ff05:1251%7]) with mapi id 15.20.9203.009; Thu, 9 Oct 2025
 10:25:53 +0000
Message-ID: <a04d8499-85ad-40b4-8173-dcc81a5a71bf@nvidia.com>
Date: Thu, 9 Oct 2025 21:25:42 +1100
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 06/35] mm/page_alloc: reject unreasonable
 folio/compound page sizes in alloc_contig_range_noprof()
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-7-david@redhat.com>
 <fa2e262c-d732-48e3-9c59-6ed7c684572c@nvidia.com>
 <5a5013ca-e976-4622-b881-290eb0d78b44@redhat.com>
Content-Language: en-US
From: "'Balbir Singh' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <5a5013ca-e976-4622-b881-290eb0d78b44@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: SJ0PR03CA0191.namprd03.prod.outlook.com
 (2603:10b6:a03:2ef::16) To PH8PR12MB7277.namprd12.prod.outlook.com
 (2603:10b6:510:223::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH8PR12MB7277:EE_|PH7PR12MB7455:EE_
X-MS-Office365-Filtering-Correlation-Id: fc042970-8d41-4fd6-bef1-08de071e3985
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|10070799003|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?ZUpVelpzcVYydjk3V1lyTVk2cGpJZmZuUUFOUnRScHhGUis1L25Ra3pEQVU4?=
 =?utf-8?B?L1BZREhsQ1o3WEc3VXdoRHIrMUdCeitRRmYxeTlONlhyRWFoYUlXQVNxVVE2?=
 =?utf-8?B?b1ZLaW9KR1RmUzA5bW5BOHdvTUt1c3h4a1F1ZUVRa0dUMCtjSjVmZjZsVGR4?=
 =?utf-8?B?WFJkWUZXT29IRUN1U2ZSMHh2VWlVMG9GSlM0MVVtYkZ3bEpER1ZTMm9jeWcw?=
 =?utf-8?B?RGVZakJ4bURmVGVJM05MMjgxT3FlTFlQNEY4SGtnM1F5ZEp0Z2Vjd0VQZi9r?=
 =?utf-8?B?cFlqMWt6bzRuQk5qdHZ2MGlVWkFBQmRVWjRFRUVrZ1d6blgxdlR4cDJhT3d5?=
 =?utf-8?B?Yi9VZVl5T1g2MUpHYm96N2c2M2tyS2djWDFoSENRTUpLZ3J3OE5qcElWQnlp?=
 =?utf-8?B?QjBKWnFwZ3E3bVAxOVM3WEhPVHhMQTNFV050aHdjalJMLzNQQnEvOXJ4c2lD?=
 =?utf-8?B?UlAxQTFaQ3krQTZiN25YS3duN3ZxclVUMjdINnQ3UGVUMzRFb0JHdGp4bjdE?=
 =?utf-8?B?Ym9wakZhQ1FkZlNBRGxhNmcwNHVDZ3Ywbno3bGIyZ3NUT1RBbXgxTmN0QWdj?=
 =?utf-8?B?OXRxMis4TWk4OUhPTHRTQmRld2FMb2FnYlZSN0J6L1Q5eUJ2Wm05RUdZdUhZ?=
 =?utf-8?B?ZXZadVVsdlJZUHVTeVhmNSsvdGY2eVJtbnVtQktsOWIxUHJiU3M2K2tPTXJK?=
 =?utf-8?B?a1YrVVcvS3RHZ21oSmgxYVZoZjBWRC9jY0ZlOXd5bFlyK0x1VVFHcElxejFv?=
 =?utf-8?B?M095d25yeW80R2x6V0JGb3c2WUhaa1JMaS8zbmg4ajM0dGZzdlZ6cDJuSjNJ?=
 =?utf-8?B?NVVoOFpKR0xlSnlaTmFJRURXNHdRdzRLRnduREk0eFVOcjNhaGVCcEQwZ0tp?=
 =?utf-8?B?WDhCaUFpZzlvQ0ZmQ2QyeGFmNm9uT2VhaC92SmJ3OFV6Vi93Mmx0d2FZeDU3?=
 =?utf-8?B?RzBTZHZSdVhtU3BnMHJKV2JpaVRpbGYwbVJ0REg5YVZ0MEg3cG5XVjJkY01h?=
 =?utf-8?B?c3hSMzVvR0Job2xVWlV3SElGVG84QytVUC8vbnF1UTFhVXExRCsrcVpTTTBv?=
 =?utf-8?B?SENKL2d5UnBLc3hjdWpsVjF5V2F0YjI5T2xsdzNIcGcxYlFqK09nN1pjdzhm?=
 =?utf-8?B?U1M2R1N3L3g4ZjRvajlwbXJxYmhKVW5ZRTVtRjRWb0Q1WnVJTmJWWXQvRjdV?=
 =?utf-8?B?TlVnWVRTWGdlTkUwS0F1ejQ5VWl6bkc5b0paREhLR3NFeWxJNTVSak8wSHUr?=
 =?utf-8?B?ZDVoMElwZzlSZmI3K05kNkQ4MFlKc3hxcDlNS0hyUFhCQjlMUzUwd1UrRHRL?=
 =?utf-8?B?NzEzcks2eU9jaFpGVkVTamt0Q1NwYzIrb1I4U1F1UU5HaVM3alNHTGhnaVYw?=
 =?utf-8?B?S0ZsUmpWTW9ZUUtHZVg2THVoTDRzVnQwS0NRSHlPZXBRYW5obmYrLzZPcGNm?=
 =?utf-8?B?MW40QXJLc1B3Z3dDRlN1aHNkZnFKNHg0VU5wYU9FT2xGbk9GSUlXM2RKclYv?=
 =?utf-8?B?MVA3cG03Q2xJeDEyZEtIOEwrYUlqbW5FS2w5ZkRuNkd3Zm9BTjNuWlFzZDVM?=
 =?utf-8?B?RkMyNjdIOGlTMWc5NTl2djNPRlZxY1hDZFJhRXgvV0REdDZITTg0TkE5ZC9D?=
 =?utf-8?B?WWdldmhzRVl1V3hmMVBGTjF4Y2thS2lrTGh6RjA2d29wNklCcUNaNE9lUjFk?=
 =?utf-8?B?R0tzQkR4bitDYUZwQVgzamNQTlVUUlBJYi96N1N0bTZEV2t5VXRRSjR4SHZ2?=
 =?utf-8?B?eTlUNmFyUWt0WnZDZU5kYWVRYlBLb0FTZVNlOEF2WWtNRTdUNWRVZllsbWp2?=
 =?utf-8?B?YUo0SVZuQTRkNWdLZUd4cy9rSHFMYUIwTFBkRGZENTZOdjU4UHl5L0I5N0hM?=
 =?utf-8?B?SWtGaGVLUXlMR0grcmd1a0dYOHZORHM3d3Ivbm4xSGpqM1F5ejE4S2tjSEhZ?=
 =?utf-8?Q?RIki05ZQBRLqC4OWQsYahsTOprT9c9ID?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH8PR12MB7277.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(10070799003)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?dlFSQlFOSzNOSHBwYXBRZm5xNWRYa0M0KzdRR0JoTzRaVXFPR2VFNmNHV2hG?=
 =?utf-8?B?M0t5WW03V1FvVnJKTXVWVDIweWt6cDJ6RmlrdnoxMGVpYjUxRXN4VjQxUU15?=
 =?utf-8?B?cTRFWWp5Ukd0azJmZ0cxTjdlS2JWR1YwVnV3VCtjSU9Qa1dwTEpHSW5EVDE3?=
 =?utf-8?B?Ry9GVUJ5eE5mWXpORnpHSUZLMHBRVmxDNTY4V2xjYjlZaXJqWEtEaDJLVGU3?=
 =?utf-8?B?NFNIbXk1MUh6dThIRkw4WmlXWjJLaVdaWDIxNlhMQ2wzVll0ZFg1VDVVOW5s?=
 =?utf-8?B?ZmNwbXorRzVoUzVZQWVJSWJ1RnpwNHozOXJ5ZDdhMDN2TzFyNjF0WFVrTnl1?=
 =?utf-8?B?N3k0UUdTMzQyT2lpMWJDRjB4S3JmMTVheWtDajA2M0RYeFhIYW5VR240dC9a?=
 =?utf-8?B?UVhjMlc2a2xaUHIvUjQyVGxOS01GaXJHdytlMEVyYkRtWXJCckF4SXlUMSs4?=
 =?utf-8?B?M0hEWStPWnI1Mlc2QmVlTTBhTC95VE4zZk5STE1pTE1aOWlKT1RXM1BvMTdP?=
 =?utf-8?B?RFFMSFlvT0tURmtaYzdEaVBRWmVTK2ZyNS9EU0dzQy9oUHZFVkN4QlIvaDVR?=
 =?utf-8?B?ZndBQm1vMnBjM1BEN0orZXNhcUdEQThxYzRQSTVhTUI2VkJHaCt0L1F2L2ZL?=
 =?utf-8?B?L1NNQVhSTlhRVUVXQTJOZUlrUy9KeEpKRnhIZ29wVzFvM0hXNDFiOW5mcEJ1?=
 =?utf-8?B?N056YWQxQUxHNm41MzIwSERsNjI3NG9OVGdMaWRJcjU1TElHY21acEFPclBB?=
 =?utf-8?B?NklLc2JrVzZVcTVLMWh1WVNxZ2JRMmJ5TXZvZ2h5bHliQ2pvZzR3RFdKRDBu?=
 =?utf-8?B?ZkZCb1N4TGt2MTEyWnBXTDNQaFZZc1VEaHoyb3paTGhQK1FkSHFsQzNHQ0Uz?=
 =?utf-8?B?WmN6eHZuMXdFU2dFeE9laU0zek1oZ0pMU3REaW42WkZJTWpQK1A2cDIvdDk4?=
 =?utf-8?B?T3pnZks4cThmc2pxZUY4UllZK2JBT3h4a1VMT3p5MVVrUGdHOEx3bDhyUnFm?=
 =?utf-8?B?U1pKQVgvUTdwd3d0Rm1LYkJ1RXJCejNOVlVvVmtlUDg2ZTVTU3ZBaVRJaGxh?=
 =?utf-8?B?RmFiU1RIOTVlR2diNi91UUFMUFhYWEJJcytlazdjbkJxRWJyRUVUMGtzUFg2?=
 =?utf-8?B?WG9kMS9aNkJybVRDNGJTUnFCd21TcjBFNXFFaUZHd0Y5cE5GUTNHVGtZbDRh?=
 =?utf-8?B?Z2h3d0dYUWg2MG5aZlBJTWpYSnJ6RGpoNXVjdTJ0NzlBQWRmaERvWVJYN25R?=
 =?utf-8?B?SnRnS0VXRjNkVndpQVFRNFg1YnFpak5aNTVZSHF2bDAwRTdlNWFxd3ZpYTNL?=
 =?utf-8?B?OUpPRVNtS1JyRWorL2RYWTlrYktzMmxlZWtzTTF4WW5TY1BpU3d6U2pvRFpT?=
 =?utf-8?B?bVNVM2lxaDl4U0s0OXlHODVQWS9GdjkrSW1LcW05bDROeHlqOE5tQ3EraERJ?=
 =?utf-8?B?bHp3VkFySnBHTkpYS1dYRHZvWFcxVlRibkZqZHEyMlo3dGNtazJGM2RxTkN6?=
 =?utf-8?B?MFFybFRoV2NjUXlhelRqTUlObGszSjcvT3ordnZrcGVKVmN3RUc3TzgwMjl3?=
 =?utf-8?B?SmR5SlhRU1pPZDJ6QWxaeHhqdm1oL1NEcEc3c2ErS2pjckFKV285bURldERa?=
 =?utf-8?B?aDg3TEltTHlQdFc2MTROVW9DUDN4OXArQUNVNmtveU5hZjlkRkwwQVRmcEgy?=
 =?utf-8?B?cmU0TDhVOWoxRUJqTlBXQ1o5eW5uMVEyaWZUamNOb3hQOGx6K2RwT0xpTlpT?=
 =?utf-8?B?VVBBNjBZN3h6TGtYL25VMXNkK1VnZVVzS2NZU2grZ1A0TytxT3F3MVhaWkpv?=
 =?utf-8?B?eHl0MElDN2UyNnZOaDh5cXUyMUp5eE1TQVN3TGhjOHJJbUpBNk1xWVpselFG?=
 =?utf-8?B?Tkp2cnd5U2dJSEU2ZkpIbzF3Y29pK3RVanRXVUcxRVRDeEI3WlBLb1N5bFpz?=
 =?utf-8?B?ZkRvN1FkYWNtMksvUUlveTRCMXdiRXgyalJRSDZnTmlWSU5JbGhFN1RiRWZx?=
 =?utf-8?B?TC9hRU9XWFVSTnZ5MnJ2YThBRG1EYjlyb0dtYm1EU0twUW5xMTlZODBjWHdk?=
 =?utf-8?B?ZVBQRmh5MVpweE44ZHNMV1dGZ09aa1ZPNHg4SE9iOENIbEYzSHlxd1RXbStm?=
 =?utf-8?B?K1phdm5PS2pQc2w3dFdMT1U1OU1XTlVUcVZHRHBMdzArM1hRS2RVYWhYZXk0?=
 =?utf-8?Q?efW3/6z1peeZJ05KBnsNhLkPgCVix25OmEHkOeTGaYh2?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fc042970-8d41-4fd6-bef1-08de071e3985
X-MS-Exchange-CrossTenant-AuthSource: PH8PR12MB7277.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Oct 2025 10:25:53.1264
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: L959gJC8jrvJvfIb4iQtdd7P0YXxd978MySa+fAzHqrX3t6Dj+mRSWeQoKjvNjEI4YvCngzAp2V3GSUCLThCkQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR12MB7455
X-Original-Sender: balbirs@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=AEkkbBeT;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of
 balbirs@nvidia.com designates 2a01:111:f403:c10c::1 as permitted sender)
 smtp.mailfrom=balbirs@nvidia.com;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=nvidia.com
X-Original-From: Balbir Singh <balbirs@nvidia.com>
Reply-To: Balbir Singh <balbirs@nvidia.com>
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

On 10/9/25 17:12, David Hildenbrand wrote:
> On 09.10.25 06:21, Balbir Singh wrote:
>> On 8/22/25 06:06, David Hildenbrand wrote:
>>> Let's reject them early, which in turn makes folio_alloc_gigantic() rej=
ect
>>> them properly.
>>>
>>> To avoid converting from order to nr_pages, let's just add MAX_FOLIO_OR=
DER
>>> and calculate MAX_FOLIO_NR_PAGES based on that.
>>>
>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>> ---
>>> =C2=A0 include/linux/mm.h | 6 ++++--
>>> =C2=A0 mm/page_alloc.c=C2=A0=C2=A0=C2=A0 | 5 ++++-
>>> =C2=A0 2 files changed, 8 insertions(+), 3 deletions(-)
>>>
>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>>> index 00c8a54127d37..77737cbf2216a 100644
>>> --- a/include/linux/mm.h
>>> +++ b/include/linux/mm.h
>>> @@ -2055,11 +2055,13 @@ static inline long folio_nr_pages(const struct =
folio *folio)
>>> =C2=A0 =C2=A0 /* Only hugetlbfs can allocate folios larger than MAX_ORD=
ER */
>>> =C2=A0 #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>> -#define MAX_FOLIO_NR_PAGES=C2=A0=C2=A0=C2=A0 (1UL << PUD_ORDER)
>>> +#define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PUD_=
ORDER
>>
>> Do we need to check for CONTIG_ALLOC as well with CONFIG_ARCH_HAS_GIGANT=
IC_PAGE?
>>
>=20
> I don't think so, can you elaborate?
>=20

The only way to allocate a gigantic page is to use CMA, IIRC, which is cove=
red by CONTIG_ALLOC

>>> =C2=A0 #else
>>> -#define MAX_FOLIO_NR_PAGES=C2=A0=C2=A0=C2=A0 MAX_ORDER_NR_PAGES
>>> +#define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MAX_=
PAGE_ORDER
>>> =C2=A0 #endif
>>> =C2=A0 +#define MAX_FOLIO_NR_PAGES=C2=A0=C2=A0=C2=A0 (1UL << MAX_FOLIO_=
ORDER)
>>> +
>>> =C2=A0 /*
>>> =C2=A0=C2=A0 * compound_nr() returns the number of pages in this potent=
ially compound
>>> =C2=A0=C2=A0 * page.=C2=A0 compound_nr() can be called on a tail page, =
and is defined to
>>> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
>>> index ca9e6b9633f79..1e6ae4c395b30 100644
>>> --- a/mm/page_alloc.c
>>> +++ b/mm/page_alloc.c
>>> @@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t g=
fp_mask, gfp_t *gfp_cc_mask)
>>> =C2=A0 int alloc_contig_range_noprof(unsigned long start, unsigned long=
 end,
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acr_flags_t alloc_flags, gfp_=
t gfp_mask)
>>> =C2=A0 {
>>> +=C2=A0=C2=A0=C2=A0 const unsigned int order =3D ilog2(end - start);
>>
>> Do we need a VM_WARN_ON(end < start)?
>=20
> I don't think so.
>=20

end - start being < 0, completely breaks ilog2. But we would error out beca=
use ilog2 > MAX_FOLIO_ORDER, so we should fine

>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long outer_start, outer_end;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int ret =3D 0;
>>> =C2=A0 @@ -6850,6 +6851,9 @@ int alloc_contig_range_noprof(unsigned lon=
g start, unsigned long end,
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 PB_ISOLATE_MODE_CMA_ALLOC :
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 PB_ISOLATE_MODE_OTHER;
>>> =C2=A0 +=C2=A0=C2=A0=C2=A0 if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) && =
order > MAX_FOLIO_ORDER))
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> +
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 gfp_mask =3D current_gfp_context(gfp_mas=
k);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (__alloc_contig_verify_gfp_mask(gfp_m=
ask, (gfp_t *)&cc.gfp_mask))
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>> @@ -6947,7 +6951,6 @@ int alloc_contig_range_noprof(unsigned long start=
, unsigned long end,
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 free_contig_range(end, outer_end - end);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } else if (start =3D=3D outer_start && e=
nd =3D=3D outer_end && is_power_of_2(end - start)) {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct page *hea=
d =3D pfn_to_page(start);
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int order =3D ilog2(end - s=
tart);
>>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 check_new=
_pages(head, order);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 prep_new_page(he=
ad, order, gfp_mask, 0);
>>
>> Acked-by: Balbir Singh <balbirs@nvidia.com>
>=20
> Thanks for the review, but note that this is already upstream.
>=20

Sorry, this showed up in my updated mm thread and I ended up reviewing it, =
please ignore if it's upstream

Balbir

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
04d8499-85ad-40b4-8173-dcc81a5a71bf%40nvidia.com.
