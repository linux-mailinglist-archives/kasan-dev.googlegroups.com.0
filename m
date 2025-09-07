Return-Path: <kasan-dev+bncBCZLJOMFV4FRBOFJ6TCQMGQERDTYCOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id E41A8B4791C
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Sep 2025 07:14:35 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-32d4e8fe166sf1454775a91.2
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 22:14:35 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757222074; cv=pass;
        d=google.com; s=arc-20240605;
        b=CePsSjiEgSdZm4/b81n42/0wOxsubLBpWUnx+Hr6Yp/Pomfv1rFFY/gkdfV2uVIxXz
         i7yjwGGNSxIv4WHel7t9mOb8hW26/HLWXqj39os5yoOcMBJ4CH6XCJHEBhBxdOj/zFMx
         zhWj9NTM0yZzLLekqsAY8MjnYAgtj8ckq/zPkAm4ivUpng42T7Cefzl3+pfXa8IxgxR0
         JWHiEJtc3xjrgHbY/hskwC2KzRhprpOgYg52i9vLKJIAVfnYN7IqCPNc3B+mhXXRc4e2
         Ju3KYjCQCJQYFKbUhRM0f9whF2XHn5YKcwpkz4My6uPylE01VzVaw7G5Kgj69ejTDRBw
         xv8w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=pWen+y3bufgvZETJ6/SvGqLqdA0C0ux9MqwxRcFSjoI=;
        fh=vuD84uCLW8TQgymPT4eAYpiKkS89qvxJznxze9wXh98=;
        b=SQjoLM64t31XaPajzDGm42iZZgUawsS7oZEoKpCV6F9YGdxL16u6PBvIpjLjmgbfBv
         sOr/Q9B2lkcOmTFdiRIRE2Z+Pq4Lke24oNpOYsgi5XACE2wt1l/ZtDyVigB0KasdGs0J
         gFHbyeJnu3QtGSOSnbdxpwvQovQFO5mjVcPVNDksRwsAB9Ro2qca0wEqQfaY36Cwl+L9
         ZO5WaaefnzizOBwFrJ8AmGrK6CHVw+zPCqoZh13ZiUWcyqmX6clfIE/mR+tqgodToQT3
         2YM6j2lrtbu0WL6N88M+818l/Fk8Ma3yB+RnJ/z/L36kwveOpkD8v8DGxjPHLmFHvosM
         srPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=GJCW+3DS;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:2415::622 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757222074; x=1757826874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pWen+y3bufgvZETJ6/SvGqLqdA0C0ux9MqwxRcFSjoI=;
        b=IqSGeqIbEzDGs1EOPjHvZCPnDvIvJcuDIaZ8h7uDtuxGks8BMG8Ns5yM7xh7NUZTwV
         Sex0zyJlhVbAqHQXtxz8G+db5T1dJCY8Gn7BoQT4ipl/0xNkdwOtmsKDcGSKu6G1H/QD
         bSV609zaXLvzB3M2qgRGejbHoI8Ss0FwC/GHFlwtLUlvUZ2FLCrExuAe8u/T+yf3QmKb
         CtHim+WGDgwUwywDGFXsTITT5unxQD4M267fiJhjnl8kAfZCFuHlpavWDlIxPQp/gZVC
         YHtviH/EOdGgurhVhEbf2/YB+yjDQQ9AWoicr28vynpzJvtXuJzhsllolNHqjqTuLvfu
         sZ5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757222074; x=1757826874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pWen+y3bufgvZETJ6/SvGqLqdA0C0ux9MqwxRcFSjoI=;
        b=wM9csZiJmH1E+zrro/PioL/1cFytlZlJTd0ToXsyiZgJDAuPwSxTlZT4GCNwSsMv4o
         fxswwDiGpkSOPjTdYjZNSrzfhkpFAdrfZRYGOH+vHj3M/aOLxpHIFyStWR+qBkyIxJ9S
         A0sVU3P+gF/YKwCer3ErzRU/+V0P/ZVUuyB2rPUeETJdu0moNJdGx5HVer9HTUviIWOd
         fUkSjitx09/D709zu0mOKHbBH/SUwjtctGjP28mwf+VcLwGOfiiCQARdP+7ZmfSTRslU
         YtK4jbZsKTGaFFMekR/QzH39yM5DMdWACPCE9pu3LX8wP26P5g3IJxv17ZKUpA72q9D7
         pnYg==
X-Forwarded-Encrypted: i=3; AJvYcCVR2jl+JM6OCJx2hLEx2fJgU32Pp0edvADaF/+IXJLMYdT8zNBjaU3DEC/YbrWUb03Evb4faw==@lfdr.de
X-Gm-Message-State: AOJu0YyEBwePBZ7ZbSCnPbpMJstvK0NQGA8PFk8F7WoFraJoU3F4RTU6
	cAf6aoM77mzXGGdb3KJJkllWMxAd7v1QV71Kz0nxL7WbzBUkjUa3wB1h
X-Google-Smtp-Source: AGHT+IGcMqNlunIWOz6iqimR61fBLXsVF9BmXBBsmm4+AmLO6L/CWaJ/b6ioKhjR7kPse6C5/tRHTQ==
X-Received: by 2002:a17:90b:48cc:b0:32d:439d:2aaa with SMTP id 98e67ed59e1d1-32d43f1b4bcmr6434099a91.15.1757222073979;
        Sat, 06 Sep 2025 22:14:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6psOUW+7RJHS7vqe5vG4cY49+hRhS1h+J2PKdJC5CvnA==
Received: by 2002:a17:90b:2688:b0:32b:bc5c:d64b with SMTP id
 98e67ed59e1d1-32bca93be89ls1588991a91.0.-pod-prod-06-us; Sat, 06 Sep 2025
 22:14:32 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWg8ZVXWncTV/b1WJ/DmJjdgG8klHMMD8mxRzbQX/xXdv7kQITlpDWJJL1ktBIfxHzaxlVbzGK4lOY=@googlegroups.com
X-Received: by 2002:a17:90b:1dcb:b0:32d:3d64:a7d1 with SMTP id 98e67ed59e1d1-32d43f7704dmr4848752a91.22.1757222071727;
        Sat, 06 Sep 2025 22:14:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757222071; cv=pass;
        d=google.com; s=arc-20240605;
        b=Of4wmMTKTBldeEjk0ntL+W2lT2MJQCFpeaYve6p1tduwlC08fkGzdqDZbZZ9LElvm0
         KoZl0axy5St3m96kObX7+XvsiWjOSqsAITR84yjmnWqX6c5X4mxJmkJErIAe5B8BCqbZ
         KS4PfONqrqiHS1Po/9cMJ9AcGWf6DywRgQYp29ynCOKDR1gAlcxUcWGZj41WyrMrxuCY
         cc6tBvciGiLDoz+02DvZbbrVeelkLSYZzH/2pt4atOJcpCOviMr5hspCGuCVO13PEflN
         4bQf+qZ9qtc2bVZJ7is55rzqJJI2g6Wtfji3/yg1AyePjdw7usZYG4/xTyYlMZlw1ULl
         8VUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:date
         :message-id:dkim-signature;
        bh=ZBp52V91Gxr27f7RudT0aNk9Xj8vFIecZ5YmKsPh8yA=;
        fh=qRi/oHUYAXGn2YukaaI8eEYYZ73DH3/0DPEnerz7rls=;
        b=itOIq+TGfTzpTyK9zbRokJPI9c+184x23zpxtLJ2k0SiRSIybiBeRCsw+i38aeDCgE
         8j/bmiphFATBYvmL18FuOyAaC+4enSa858APY7PY78SBLnujkRiCKYIeZjNS1CUp75I/
         RyEE0ovregj66gPyYimsrDcaWwcr3zBrw118Qtl/tezGuW+BANpOzs/MaLtFAZkP1Xt/
         8TJNA6z1OhLQhvCffdbmAcpqf8g300023cCFF/XH0JYugQK3hp6kqNusy9zPtMZLtCpg
         +fEb9Yy5yuXFsvbFJ/f72UQJu/AU5DNe47FN25BPuXhXRo8cQKOvqysuy4+fEEZ6/gvl
         NUmQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=GJCW+3DS;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:2415::622 as permitted sender) smtp.mailfrom=jhubbard@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on20622.outbound.protection.outlook.com. [2a01:111:f403:2415::622])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32b4dd94d0esi559631a91.3.2025.09.06.22.14.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Sep 2025 22:14:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of jhubbard@nvidia.com designates 2a01:111:f403:2415::622 as permitted sender) client-ip=2a01:111:f403:2415::622;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yUBsZoa48ubr5UfQCm1JGG4S8RpaYQuK3qinFtfTVoIyblstuFvs1UtepWrL6qmhVxym1pIpbEsbMAvn8OLpFtnGKLdFRogzsXju1CrLLfxBypz+Hkszu+T6TOwyetB17oSLAcgJzki+fDcVYN+oiTtl/ehsF6gZlXmpmGbHNSDpgD44y8PNgeLafTwUoVPHuULARbhwZIgo3c8tKzUiTcLIbjk9SxJ0Ts4DKpyC1PPtY5Ts15C7DoSWyHHrOZcmwjhmNkBgLbdBHDWKr41d/hH0Iq4wl03K3165j0jxtSFnMsVtfLQLsKI5Op+VEBMmGm8nEPF6cEUtHrz9CFbJvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZBp52V91Gxr27f7RudT0aNk9Xj8vFIecZ5YmKsPh8yA=;
 b=GGSMAlpnRrdP4a44ktU29+KpniQMk+UW6Gda+8KCQog3qwPiGbBpp73s+/BJXgR5l5bJpq0nocNaVsitWzZ27gkvAs7+LxMqwmYUV2xlKVIBVq5LtnfXWkMzSe/DZQIkP8OYzgKltBhzt4+fC0FDtL1N5BxRrHQ6eiPyq6WPHX7Mw70yooOKJZYN8RX93Z/eXOoJCFvUeMmcLM1q/RmGzGzlKZ0t8Hie845b//12OtmTUXi4bBsLE8ZzjltETh8kwzNO/DLMfeCGMi39ZmzVvGlWny5kJms7IhwCe7n+ssvUIfmauKp8Nas/sp0t4pEIwgYbDOC5YTUN1q3j61eICw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from LV2PR12MB5968.namprd12.prod.outlook.com (2603:10b6:408:14f::7)
 by DS5PPFDF2DDE6CD.namprd12.prod.outlook.com (2603:10b6:f:fc00::665) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Sun, 7 Sep
 2025 05:14:26 +0000
Received: from LV2PR12MB5968.namprd12.prod.outlook.com
 ([fe80::e6dd:1206:6677:f9c4]) by LV2PR12MB5968.namprd12.prod.outlook.com
 ([fe80::e6dd:1206:6677:f9c4%6]) with mapi id 15.20.9094.016; Sun, 7 Sep 2025
 05:14:25 +0000
Message-ID: <0a28adde-acaf-4d55-96ba-c32d6113285f@nvidia.com>
Date: Sat, 6 Sep 2025 22:14:19 -0700
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <016307ba-427d-4646-8e4d-1ffefd2c1968@nvidia.com>
 <85e760cf-b994-40db-8d13-221feee55c60@redhat.com>
Content-Language: en-US
From: "'John Hubbard' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <85e760cf-b994-40db-8d13-221feee55c60@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: SJ0PR05CA0048.namprd05.prod.outlook.com
 (2603:10b6:a03:33f::23) To LV2PR12MB5968.namprd12.prod.outlook.com
 (2603:10b6:408:14f::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV2PR12MB5968:EE_|DS5PPFDF2DDE6CD:EE_
X-MS-Office365-Filtering-Correlation-Id: 89b9ab1e-80e3-48bd-897d-08ddedcd6976
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|10070799003|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?N3VhS0huWjQ4a3lsVHYzQ0ZwUFpBUjlPQjE2VXV6aS8zdmFuZzZLajVkaXpz?=
 =?utf-8?B?bEpMMWxBZ1BOWVU3QjZRaVpkNFA2dFdMTXJ0VmJCc0tSYmJTd1ZSQjhWS0NR?=
 =?utf-8?B?L2JCYU5wYXhNU2tweXhzcFUwQlVkSTgwQjRaSCsxUWdwSHpvU1NqYWo3eWlN?=
 =?utf-8?B?YWphSzhUcWxUU1dsY2VtdDdvZmRHRC92Sk1nSmZCeW1tTFQ3YUVia0pxZGtv?=
 =?utf-8?B?aTRMa2hmMEYzVEZTejRBck5nSXdWb2tHbnNaOWkyMDNmV1FTWUNYNVRHMmFw?=
 =?utf-8?B?cUJmdGM5WmJDTk1SWkREeTlUR2E5cFpRTjFDTHdkSFRLZ3FNNFVXQmtyMnZY?=
 =?utf-8?B?MlZCS1JScTJPWWNjaWRnYSt3STA1Nm94bGorSHlkZ05iM1RrQmNVaFRzRjM2?=
 =?utf-8?B?b0s5MnUwV0w4RVArdXVLcmFtUW9JT0VORFpqbEFOYnROZDQ0Uk1idHNnSnZQ?=
 =?utf-8?B?TzdIVHZpRExrMFRjV2Y0YUtKU0NJRnRxR3hhbHIxQ0RmNG1rczd1NWtDWVZs?=
 =?utf-8?B?ZTdJQTZGSmFHczhaWHRCVjVQWjdiVnA3MW9wdXNPQVp6djJVU3lFTTcybFNo?=
 =?utf-8?B?UFNHTkg3Z2RCZEYyTVVFSUVna2thM3Jwd3hZYkFuUm1oZlFtUDRnRTZxVGVq?=
 =?utf-8?B?N1ZDVjk0UE9seTRvTmxDTVYrUFJ0Uy9yV2xROEliWk51eEtDdXU0Z3pYWXJp?=
 =?utf-8?B?anBGUkt5bnRwSFo2a2ljNmVxTEIwKys2T2lQSFhwTkQrdkVvY2hxU0VUWThS?=
 =?utf-8?B?OHgweUV2elJuR2VmYU1kb0VBRHNnYXpyODFueFEzSktNQUNMTnRzTkRKbDdP?=
 =?utf-8?B?RlBvWGVvMm1uV0tlcmc4cTlRMllKTGYvUEpmMmVVTTNnWFJrMjhMSlRtNzBG?=
 =?utf-8?B?ZDArTVhwaHJZdXVoOXhFYXA1QVJRWFRJd1NkTnBmdngrWGxnVWNhUUVSUmov?=
 =?utf-8?B?K1RLQnNvQUM2NzM0WE1ONzNjUzdFeUl2RjB1NmFVRDR6VlJLTHpMdTNlOHNB?=
 =?utf-8?B?SVNXa05oOUw2UDhkWWZmZmpLd215c3lubnphcWUrMHpKSkxSR21MOEJDMllY?=
 =?utf-8?B?aWFVbEd2cnc4WGhkcEdMTnJKaVFBNHl0YVBVV0FxclZEb0JoVjlEV1AxNHFh?=
 =?utf-8?B?Kzh5d1JQcmNoRmlpalRrc2ljTGtKQVc2aUJJdlZML1pGVVVCZTByTGFFWW5N?=
 =?utf-8?B?eTRIOE5Nb2Y3OGFucVZSVGtMaW5xeHdwV0tad1E4cE9GUk12MDJOU0w1U25N?=
 =?utf-8?B?dDgrdzZWbUd4VjFXZTk1OFZMZmxMbi93cXp5c0Z2UHBWOXc3OHpJUEhCOHFQ?=
 =?utf-8?B?MUk5RG5DeWs1MXVLOHE5TTRCMkl3cXFTRHA0WWxxNWhVV0gwa3phRitqTlNC?=
 =?utf-8?B?c2pTdlpFdW9wblI3c3AyYmQrNDFvNWFYT0dzM3YwRnZXUk9SUHFEUTJqM1pp?=
 =?utf-8?B?M1FJRUVVOWpEd1hTOWYwUjAzVjJpcnlNZkhWTnhIdGJ4NzhlTGJIK2NabTgv?=
 =?utf-8?B?OGxGNUQ0cU43UTZuNXErdGVnanJuTEd2M0VFaTlDNzJOZXQwOTVYQ2tkWnlO?=
 =?utf-8?B?K0cyMEFKUGFzL1R2ZXlYLzVRbWpTNUZMeU5qSGVVYXpCOTV5OFcrdlFrL0JT?=
 =?utf-8?B?cEFROEViM1JtN3FySDd4b0xJbXpyemgyN0x6QmkxYWpZUlprU3VMR0oyYlVQ?=
 =?utf-8?B?M1FNY1lpVjhhYmlhVVl3U1JBTUJ4SjFVOUdURFZDVm1RdFB2Q1hMS0lCeEY4?=
 =?utf-8?B?NUtsMjNRa0NQUHJHU1MvMURkK3BEcEEzY0ZUcDBjR1N1Qit6RTJHU1kreEVr?=
 =?utf-8?B?MUxxZW11V1JCSGR2R0w0RTRzNENkeEc5dGtFWDZKanBZaGNGVDBsL0VjdzQy?=
 =?utf-8?B?U0FKMWs2N3lqR2txMkI0Sm5kMEdkeGpSN3U1dDhHZzg4Qnc9PQ==?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV2PR12MB5968.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(10070799003)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Z2FmbGhrTlFWREJvWjdCU1VYNHgya0haRTlqdUtTa0c0Z2VPbG4rS3NOQ3VP?=
 =?utf-8?B?aTc3dURUbGo5WXg3ZXNRWEJQVWdabGRxOWw4R2RUS3UwczltdmtmdnZlUlRz?=
 =?utf-8?B?OVp6R3NaazB0RXVzZUxHTld4Ny9jU3BxMWd2ZVF6YlFhV2lYQnVrK3orK2pZ?=
 =?utf-8?B?aWMvOFN2UG1DTDVZaDFtUVVkQ3pRV08yTVNYRTdkMTIvbTB1OWh0Sm1HMCs3?=
 =?utf-8?B?WUpNTnVkSytmdHZmOVZvR2tVbTNxQjlkb29xZnB1bzhObzliaU84UG92RW9E?=
 =?utf-8?B?M0lzeXUvYnpkelJiQk1zLzhWazN1dThSN0JnRzkyQWZMSVdnMjY3cnViQjhZ?=
 =?utf-8?B?QkhxUVpFZHpGRDRObnkzbTA5QnJlMlhnaXYrSCtWMXBQZ0V2MktGVTJhbTRn?=
 =?utf-8?B?bGJFeU5EUlpPVGwyd3hxc0JSa3ZOUTh3NmxZdkkrOUZRVUR4ck0zVTh4dzlY?=
 =?utf-8?B?YTdUTXBtZHhMdUQxRzJwdDB1YmFiRUQ0YzFCa0JjQ08zU1V4N0tVUGJjTmVo?=
 =?utf-8?B?RE5JTUV5VFlOaVlTMEFzaU03UitTVnprSXZoOWxwU0doN0ZsK0JCRlJMaitY?=
 =?utf-8?B?UmFHeXV0ekg3QVZoNENJaEc2QjQ5WUpaMWp5bTBwMnllTGs1Z20xZ0x3a0Fs?=
 =?utf-8?B?Q2NKblU2NUVEV0lqQjZBUUYzN0w0RE9kUk9ySlM2eDVqTG1ERzlTOWUzMjJj?=
 =?utf-8?B?M0JrZXN1MmxoU1RLNFZMK0pwLzA3NHdCUTNmazZJM01zYTcrNGsrYXNIZWVM?=
 =?utf-8?B?TlBlT245aDZ1VHlVcVlDdUxEMWw2QXRNU1BFVW5UajduclBnenMrNXBRNUMr?=
 =?utf-8?B?NWFyQ3FsVzhuNGNmSnY1Mi9ISndPWjliWW0rS0xJc2V5QzVKSTRvalA2aFUw?=
 =?utf-8?B?SE1KTkVpTEVFQmtKUTg2VmkvbXF2L1NLdFBMRzNDS1I2MDAwKzZuZmtzd1FV?=
 =?utf-8?B?TjhreGszMlJkdFJyK3RRbnpQZ0RxVzEranZVNS9kRmNQUHIzNzBNNWVOUHVi?=
 =?utf-8?B?RGYyVU9qVStQQXUzR0lYaXlKOENCV0RWOFVDT1dOZ01tRGNRdHhVazNKKzdB?=
 =?utf-8?B?Q25OT3FaNThIV3RWVmVDV0paV2FJU01sb3IwTTVrRzZEaWRzY3pBUmJlRit1?=
 =?utf-8?B?MmhJbmp4ajI5OENiYTNra2RlaEZjRmhiRmFPVDZZdGN6YUFyc1N1MDlrVlJ2?=
 =?utf-8?B?TnpqdWJpVWxyRTFXN09MSDMvUUdjZ1lrdGZhN2xEeldEQjRGRjA1RWV4cGdS?=
 =?utf-8?B?eTBMZWRFU3NLMnYrTXdTMGFEbXI2V2M1SU1KZVVIVGF0dFkxV0xMNmdWNWhF?=
 =?utf-8?B?dDBUZ0l1Mm4zU3Y1UWR0dnVsWExuL0Z2bHVEQ21ML09TWlgwQXJRTzhaQTJr?=
 =?utf-8?B?SDVvQ001cFV1NmdNaGF0ZUJneEFlam1zWlAwY0lzTWVjelEzNnFscGhZbGtv?=
 =?utf-8?B?S0crbnF2MDc3U1QxLy9WS1ZvSUdqc0cyK2wyWk9mRnZXWGIxaGE5WWFwbWlZ?=
 =?utf-8?B?UjNMT0hIQTRhUHV3MFNVVFNjSEtmbklKamVzMDZpOVdNRGdnNG8wbVpKakdo?=
 =?utf-8?B?eXpGaDZobXM5NWVTZnY2VUcvN1dJek1YT0w1UFduazVqOUR2RjVHQ3lZOG5E?=
 =?utf-8?B?cHhzSHpmeXBQYmEvTHNEdWlFVjVtdTFoMzZpVVVZaGxQc2oxNUt4bFBIT0do?=
 =?utf-8?B?SEhDMDRJK2NHOUZpaVNqWkxxNFF1WkNRTlZ5amJhcXBIS1BDYzVhcnVVNUI0?=
 =?utf-8?B?Vy9vOWFWWG1HcHNOWEtCRHR5L2JqM2drU2pFSHZmcVJ0Wm53Q1NGdktNMDl1?=
 =?utf-8?B?dU9VUUdMaldtdkQyVTJRLysvR3ZKZHZmem85alRmUGtzSlQxZlFOdkZHVlJy?=
 =?utf-8?B?OHBkYTZ4OWdia2tXTXk5dE5EZkdTQVNrSmc5QXlDNUdDU1BQbmo2c3ZaNEY1?=
 =?utf-8?B?YTBlelUxU0F3Z2h5alpQNUdkM3pwNDFwSHRkV2lUbWIrTUVscVljeUVlbUsy?=
 =?utf-8?B?eWkwdDF1Vk5uUDB6N1pDU2UzSVVoZXUvU2JWRjhTK0NMZFppUzhLbEgrTkUy?=
 =?utf-8?B?NXo3KzBPdkFPNXpTSUZaY0R4Z2hMbkZpaXhpeWxCbzVhWExlZUtxUmM5T0Ri?=
 =?utf-8?B?NmNoNmZJdXZTRU04OGRJWjhMU1FDZTZDUGlhVHRxYm8zZzRVQWtQamFCdm41?=
 =?utf-8?B?a1E9PQ==?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 89b9ab1e-80e3-48bd-897d-08ddedcd6976
X-MS-Exchange-CrossTenant-AuthSource: LV2PR12MB5968.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Sep 2025 05:14:25.2162
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: nMH9E6FIAuGh537ODX0TA1FL8Y+H+9s2oVS0wOHG+o0yolAQXZ6PgvaRmfySFg15SGYvEm2Bjkc1N1v56jE8Fw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS5PPFDF2DDE6CD
X-Original-Sender: jhubbard@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=GJCW+3DS;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of
 jhubbard@nvidia.com designates 2a01:111:f403:2415::622 as permitted sender)
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

On 9/5/25 11:56 PM, David Hildenbrand wrote:
> On 06.09.25 03:05, John Hubbard wrote:
>> On 9/1/25 8:03 AM, David Hildenbrand wrote:
...> Well, there is a lot I dislike about record_subpages() to go back=20
there.
> Starting with "as Willy keeps explaining, the concept of subpages do
> not exist and ending with "why do we fill out the array even on failure".
>=20
> :)

I am also very glad to see the entire concept of subpages disappear.

>>
>> Now it's been returned to it's original, cryptic form.
>>
>=20
> The code in the caller was so uncryptic that both me and Lorenzo missed
> that magical addition. :P
>=20
>> Just my take on it, for whatever that's worth. :)
>=20
> As always, appreciated.
>=20
> I could of course keep the simple loop in some "record_folio_pages"
> function and clean up what I dislike about record_subpages().
>=20
> But I much rather want the call chain to be cleaned up instead, if=20
> possible.
>=20

Right! The primary way that record_subpages() helped was in showing
what was going on: a function call helps a lot to self-document,
sometimes.

>=20
> Roughly, what I am thinking (limiting it to pte+pmd case) about is the=20
> following:

The code below looks much cleaner, that's great!

thanks,
--=20
John Hubbard

>=20
>=20
>  From d6d6d21dbf435d8030782a627175e36e6c7b2dfb Mon Sep 17 00:00:00 2001
> From: David Hildenbrand <david@redhat.com>
> Date: Sat, 6 Sep 2025 08:33:42 +0200
> Subject: [PATCH] tmp
>=20
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  =C2=A0mm/gup.c | 79 ++++++++++++++++++++++++++--------------------------=
----
>  =C2=A01 file changed, 36 insertions(+), 43 deletions(-)
>=20
> diff --git a/mm/gup.c b/mm/gup.c
> index 22420f2069ee1..98907ead749c0 100644
> --- a/mm/gup.c
> +++ b/mm/gup.c
> @@ -2845,12 +2845,11 @@ static void __maybe_unused=20
> gup_fast_undo_dev_pagemap(int *nr, int nr_start,
>  =C2=A0 * also check pmd here to make sure pmd doesn't change (correspond=
s to
>  =C2=A0 * pmdp_collapse_flush() in the THP collapse code path).
>  =C2=A0 */
> -static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr=
,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end, unsigned i=
nt flags, struct page **pages,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int *nr)
> +static unsigned long gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp,=20
> unsigned long addr,
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end, unsigned i=
nt flags, struct page **pages)
>  =C2=A0{
>  =C2=A0=C2=A0=C2=A0=C2=A0 struct dev_pagemap *pgmap =3D NULL;
> -=C2=A0=C2=A0=C2=A0 int ret =3D 0;
> +=C2=A0=C2=A0=C2=A0 unsigned long nr_pages =3D 0;
>  =C2=A0=C2=A0=C2=A0=C2=A0 pte_t *ptep, *ptem;
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0 ptem =3D ptep =3D pte_offset_map(&pmd, addr);
> @@ -2908,24 +2907,20 @@ static int gup_fast_pte_range(pmd_t pmd, pmd_t=20
> *pmdp, unsigned long addr,
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * details.
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (flags & FOLL_PIN) {
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ret =
=3D arch_make_folio_accessible(folio);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (r=
et) {
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (a=
rch_make_folio_accessible(folio)) {
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 gup_put_folio(folio, 1, flags);
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 goto pte_unmap;
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 }
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 folio_set_referenced(fo=
lio);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pages[*nr] =3D page;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (*nr)++;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pages[nr_pages++] =3D page;
>  =C2=A0=C2=A0=C2=A0=C2=A0 } while (ptep++, addr +=3D PAGE_SIZE, addr !=3D=
 end);
>=20
> -=C2=A0=C2=A0=C2=A0 ret =3D 1;
> -
>  =C2=A0pte_unmap:
>  =C2=A0=C2=A0=C2=A0=C2=A0 if (pgmap)
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 put_dev_pagemap(pgmap);
>  =C2=A0=C2=A0=C2=A0=C2=A0 pte_unmap(ptem);
> -=C2=A0=C2=A0=C2=A0 return ret;
> +=C2=A0=C2=A0=C2=A0 return nr_pages;
>  =C2=A0}
>  =C2=A0#else
>=20
> @@ -2938,21 +2933,24 @@ static int gup_fast_pte_range(pmd_t pmd, pmd_t=20
> *pmdp, unsigned long addr,
>  =C2=A0 * get_user_pages_fast_only implementation that can pin pages. Thu=
s=20
> it's still
>  =C2=A0 * useful to have gup_fast_pmd_leaf even if we can't operate on pt=
es.
>  =C2=A0 */
> -static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr=
,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end, unsigned i=
nt flags, struct page **pages,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int *nr)
> +static unsigned long gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp,=20
> unsigned long addr,
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end, unsigned i=
nt flags, struct page **pages)
>  =C2=A0{
>  =C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>  =C2=A0}
>  =C2=A0#endif /* CONFIG_ARCH_HAS_PTE_SPECIAL */
>=20
> -static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr=
,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end, unsigned i=
nt flags, struct page **pages,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int *nr)
> +static unsigned long gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp,=20
> unsigned long addr,
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end, unsigned i=
nt flags, struct page **pages)
>  =C2=A0{
> +=C2=A0=C2=A0=C2=A0 const unsigned long nr_pages =3D (end - addr) >> PAGE=
_SHIFT;
>  =C2=A0=C2=A0=C2=A0=C2=A0 struct page *page;
>  =C2=A0=C2=A0=C2=A0=C2=A0 struct folio *folio;
> -=C2=A0=C2=A0=C2=A0 int refs;
> +=C2=A0=C2=A0=C2=A0 unsigned long i;
> +
> +=C2=A0=C2=A0=C2=A0 /* See gup_fast_pte_range() */
> +=C2=A0=C2=A0=C2=A0 if (pmd_protnone(orig))
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0 if (!pmd_access_permitted(orig, flags & FOLL_WR=
ITE))
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
> @@ -2960,33 +2958,30 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t=20
> *pmdp, unsigned long addr,
>  =C2=A0=C2=A0=C2=A0=C2=A0 if (pmd_special(orig))
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>=20
> -=C2=A0=C2=A0=C2=A0 refs =3D (end - addr) >> PAGE_SHIFT;
>  =C2=A0=C2=A0=C2=A0=C2=A0 page =3D pmd_page(orig) + ((addr & ~PMD_MASK) >=
> PAGE_SHIFT);
>=20
> -=C2=A0=C2=A0=C2=A0 folio =3D try_grab_folio_fast(page, refs, flags);
> +=C2=A0=C2=A0=C2=A0 folio =3D try_grab_folio_fast(page, nr_pages, flags);
>  =C2=A0=C2=A0=C2=A0=C2=A0 if (!folio)
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0 if (unlikely(pmd_val(orig) !=3D pmd_val(*pmdp))=
) {
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 gup_put_folio(folio, refs, fl=
ags);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 gup_put_folio(folio, nr_pages=
, flags);
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>  =C2=A0=C2=A0=C2=A0=C2=A0 }
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0 if (!gup_fast_folio_allowed(folio, flags)) {
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 gup_put_folio(folio, refs, fl=
ags);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 gup_put_folio(folio, nr_pages=
, flags);
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>  =C2=A0=C2=A0=C2=A0=C2=A0 }
>  =C2=A0=C2=A0=C2=A0=C2=A0 if (!pmd_write(orig) && gup_must_unshare(NULL, =
flags, &folio-=20
>  >page)) {
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 gup_put_folio(folio, refs, fl=
ags);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 gup_put_folio(folio, nr_pages=
, flags);
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
>  =C2=A0=C2=A0=C2=A0=C2=A0 }
>=20
> -=C2=A0=C2=A0=C2=A0 pages +=3D *nr;
> -=C2=A0=C2=A0=C2=A0 *nr +=3D refs;
> -=C2=A0=C2=A0=C2=A0 for (; refs; refs--)
> +=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < nr_pages; i++)
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *(pages++) =3D page++;
>  =C2=A0=C2=A0=C2=A0=C2=A0 folio_set_referenced(folio);
> -=C2=A0=C2=A0=C2=A0 return 1;
> +=C2=A0=C2=A0=C2=A0 return nr_pages;
>  =C2=A0}
>=20
>  =C2=A0static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned lon=
g addr,
> @@ -3033,11 +3028,11 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t=20
> *pudp, unsigned long addr,
>  =C2=A0=C2=A0=C2=A0=C2=A0 return 1;
>  =C2=A0}
>=20
> -static int gup_fast_pmd_range(pud_t *pudp, pud_t pud, unsigned long addr=
,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end, unsigned i=
nt flags, struct page **pages,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int *nr)
> +static unsigned long gup_fast_pmd_range(pud_t *pudp, pud_t pud,=20
> unsigned long addr,
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long end, unsigned i=
nt flags, struct page **pages)
>  =C2=A0{
> -=C2=A0=C2=A0=C2=A0 unsigned long next;
> +=C2=A0=C2=A0=C2=A0 unsigned long cur_nr_pages, next;
> +=C2=A0=C2=A0=C2=A0 unsigned long nr_pages =3D 0;
>  =C2=A0=C2=A0=C2=A0=C2=A0 pmd_t *pmdp;
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0 pmdp =3D pmd_offset_lockless(pudp, pud, addr);
> @@ -3046,23 +3041,21 @@ static int gup_fast_pmd_range(pud_t *pudp, pud_t=
=20
> pud, unsigned long addr,
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 next =3D pmd_addr_end(a=
ddr, end);
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!pmd_present(pmd))
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retur=
n 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break=
;
>=20
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (unlikely(pmd_leaf(pmd))) =
{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Se=
e gup_fast_pte_range() */
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (p=
md_protnone(pmd))
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (unlikely(pmd_leaf(pmd)))
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 cur_n=
r_pages =3D gup_fast_pmd_leaf(pmd, pmdp, addr, next,=20
> flags, pages);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 cur_n=
r_pages =3D gup_fast_pte_range(pmd, pmdp, addr, next,=20
> flags, pages);
>=20
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!=
gup_fast_pmd_leaf(pmd, pmdp, addr, next, flags,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 pages, nr))
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 nr_pages +=3D cur_nr_pages;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pages +=3D cur_nr_pages;
>=20
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } else if (!gup_fast_pte_rang=
e(pmd, pmdp, addr, next, flags,
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 pages, nr))
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 retur=
n 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (nr_pages !=3D (next - add=
r) >> PAGE_SIZE)
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 break=
;
>  =C2=A0=C2=A0=C2=A0=C2=A0 } while (pmdp++, addr =3D next, addr !=3D end);
>=20
> -=C2=A0=C2=A0=C2=A0 return 1;
> +=C2=A0=C2=A0=C2=A0 return nr_pages;
>  =C2=A0}
>=20
>  =C2=A0static int gup_fast_pud_range(p4d_t *p4dp, p4d_t p4d, unsigned lon=
g addr,



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
a28adde-acaf-4d55-96ba-c32d6113285f%40nvidia.com.
