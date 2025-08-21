Return-Path: <kasan-dev+bncBDWMT3UBYINRB24GT3CQMGQEV35FG6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 795B0B305CF
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:37:01 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-74381df95a6sf518576a34.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:37:01 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755808620; cv=pass;
        d=google.com; s=arc-20240605;
        b=eG6l2mDtvZka2kNf/9zHAqCyuxErAywkGhEG7bEmyoiHHsUIMgK+2EcbaFVECcJua7
         3Q4DILSVii/OzBvdSIraZMA9qa908hw0WEehzRy58nMIVgnGHMNGTL46kMJ6xEZ/EtOy
         OUq3wkeUN/TyRASldgMq3A5+z+DU1JtMLlwFbGHxHUorqSCSmibADlHf4KW8xt6GDHUV
         oGWD86C4pbToNJKXubBL8yDgE2oCujkwsRKoIpWATJbI45znVDgvbzNV1ybJ1MBTBoAn
         Jqa30LlcUwEesQipNi1NOjf0d8PmHzDXvyKY2R5S5X6QafDXUCI5XqENczxcpuBx5S4A
         yQ4w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=umXwUXK/RQ3oL/ukuP6yIlOP8X8ygxp8DLEC6dT4GFQ=;
        fh=EU2RTePUaMA615yCSFovyKnZWvxJzWmMwmQmapNS20I=;
        b=D69P18MqiUFdyUSZXNPrs2qhV90JRQSPiEStGKlRIrBiW242boGpONBvaUliU2aYNZ
         qFt2p36cxf0XnAMu9C0zfx5HphsCM9h+daIKxf4oMJMUTOz8VjnIf20jCLTECwBbGrY0
         387mq8ysloYSCoE3HQK9nopqLRmFlkXCXXxyAMpPPNbfG/F37bOSKGz1t+2IKAMkIPmB
         GudwpWdn8tqIcn/PnoyLSJdd+8lOdRqxKXKS6E1VMI3NE8nf3F7MQKPL9mS4HWMWUmmJ
         1vac0KTKVTwvAj7AgkULGrk5rl1HW5PI8xX4cgLVtgO7CK8u/TA3BNsRgtq9HW9VJgJl
         QBUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="rcCjS/R+";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2406::613 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755808620; x=1756413420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=umXwUXK/RQ3oL/ukuP6yIlOP8X8ygxp8DLEC6dT4GFQ=;
        b=T6/0CcfwXFzuwzynaeMU/8DI9XnQpn912f774eHPRhhICffx/4wDRXnhX5N0QDvOUI
         4bcfArH30M8NWmIZvs0fVyT3cAE0lre16ECq4s9Ore3xwg5+K5WvvJBjogpOygyvptk5
         uCGGl+QXO4m9Zf6xcjuTCXekgIwBQXc7MhL7Nbr1Xro8pj0HTSdWI138Q73FHfx5GHDb
         YY1dRoEQjVDFAjHt27Doe88pjdeT8/dMBVoJ9zB9GoQaNq6ql5lq6lwFeMGAqF8gm92+
         HTKPSIsFoIJaYmzlMDfcj3/srIeYA8d+8SOp8nlGfvYJ6xQ3pRv4AvWr6fVKU9Ic2ZzH
         dRQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755808620; x=1756413420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=umXwUXK/RQ3oL/ukuP6yIlOP8X8ygxp8DLEC6dT4GFQ=;
        b=uQMN42mMT+LGG/r8JdsdIV0+i/khLaEhK8KaPhUa4QLrk8jHYVRJs+c38Qk6g2TGiV
         B4jSURLnSVqxLvJWTRDBuI+p+Sbw6LYqm8u9kyvWfph4l5t2nzbs5grvOWYZRKy8/j0F
         I6+2KQoROqsa523/1r6E+mDQDLhisnXmSTCrXEmkF/sBAEgxUGCnlEErOljmD4VmBpt8
         68Jd8r+CvzTpv40DyYS+GiJxCUmzItO4IcIQkxfqWRGmUeGUcz0y4Gb7v3xvF3ZgL+rW
         kv94r1afTRcm/EJg1RAR4JJuyG8/sphifLaMgyT02xCn8SykTDGeuGJfOHo2XSRpkHOL
         8fjw==
X-Forwarded-Encrypted: i=3; AJvYcCWVg7dgF7AWgD7PwU9VPA6PCHxR41QTU5qxPQgIBrkiP7l67e9CF1RsgSA98lwcEjMEgjZTWw==@lfdr.de
X-Gm-Message-State: AOJu0YxG6qBdFDii7mM8KKUWj1ZBaJuUWrF32ijqHSNjGSpxLZ0VKrWY
	nb509vP79N+MnzxeO/JfM4kEelmAH0D8YcnNraXXD9U99ZB2k95+hlRC
X-Google-Smtp-Source: AGHT+IEGTgbJzrcxRyUzBIAa8+C0o6zchvP+gMxsNaXoljxHfzYARWPhXChXehg/BPBJf718sqE2Hw==
X-Received: by 2002:a05:6820:1609:b0:61d:a31f:47cb with SMTP id 006d021491bc7-61db9b6cfd6mr291306eaf.3.1755808619838;
        Thu, 21 Aug 2025 13:36:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZew4BV6i3blAwVUQv5D0UKq3I4MnXlnFqDwVV47Ye59Xg==
Received: by 2002:a05:6820:1c90:b0:61b:d6ec:565 with SMTP id
 006d021491bc7-61da8d11e28ls348738eaf.1.-pod-prod-06-us; Thu, 21 Aug 2025
 13:36:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUm6rsBzWh9gNzp74DSo8BBag5mZ/y6MPCUsz8oqhU3w966+Nt8+E3uurtH/5WXYMnW7lh3gHEkPIw=@googlegroups.com
X-Received: by 2002:a05:6808:23d2:b0:40b:2b2e:89c9 with SMTP id 5614622812f47-43785282856mr337454b6e.16.1755808618887;
        Thu, 21 Aug 2025 13:36:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755808618; cv=pass;
        d=google.com; s=arc-20240605;
        b=OrWPToNZ4tueJaAl7bJaRYi8QJ1FjHp67QOYYEtWWXcJSHu9YoxVkL07EU0+hnqNgh
         LbpFddNjDWVkltavFybQn8kMytvvQ/8Xp7b5XtTVdxH9ErZj53g9b4kWM7HVUe7dzEhH
         j4bJ8HwmxtMJM2CJtfFe7VQ3wRwrLPHJfudAzniCtTCPElf/ImFLIRIx/c38Q4yrx4LY
         gkES+EZuqRm+nZ0zFh+GfV07L8D+b6NJbs6fxr4frt3MZPLrDnZ5Nr0edzwp7X6WyOaW
         eG4z9fQi1o2J8BaQusBLYPAnTZ5Fs9I2yEAfq600Rqhi5fJummfOQlk866gArfsdLk9z
         peNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=koxUl9Bhb6pOKk6qTtolc4aNI2RYQiUs0Al/jCKT/zU=;
        fh=mkkYPuurUY7GUu5MdEwXZN672Dpu8wx5Bk7gstqa7/Y=;
        b=J0hFAMUQakBgNlSmKcaSHA7pjsTOxKzgNsDhsPVTj55Ibtoi7zZSMGvxhqTy8xp4Ds
         EMJZvmZW/N5RzTJ2h2DfLpXmHe9EMHrIHa0ved17Bs7hlHtBJaGIo8udNsFDP9LoGEwc
         bAiHMntIhDahdIjpcjL/RHBqRRyq7XhtEyvshUxODRDGHBCjqNSei9kSnlJmt8FaziU4
         3EGUGsAdNuF3zQVQGugu8K8BZPd/4ZHZr0o3xVLfIFmzbx1NAKVTB0xM42IJ2VZeZedi
         BRg11oymXwgRGIsicGmnU8ivleaLd1nbUacSfn9UuTstgwNQNa1Onv2AOim65LNnZR/i
         Yigg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="rcCjS/R+";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2406::613 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM02-SN1-obe.outbound.protection.outlook.com (mail-sn1nam02on20613.outbound.protection.outlook.com. [2a01:111:f403:2406::613])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ed1496d8si26929b6e.2.2025.08.21.13.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:36:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2406::613 as permitted sender) client-ip=2a01:111:f403:2406::613;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BY7LS5y3JQenbmDByqzihvByyrkH1pN9soIW0P9fMXbW8+WpzopxmLSDm26mfFPN9oLmxBqOEFnaNIl+cSgDJv8Chn7ihmyNM9elDFFJTu+8zJ9LY0KbWuVBW/MrUrQtJcd1mwouOLjErg/B9nY61f8s4zLAmm1OG3RUX/8vGfQAOBv+Yw9ERGvXDqPLoM1Sk3IGIn9nXeunHnJywjlgJRh7WyYfeGWfvbGGslVtlxiCVLw34ma1f2fOQy9X+V7R/nkiyGR/L8rltTOKs1fzyJPWP1CFBWjXTtDNe3ICTRIJfUJpQ3zSuvSfSylPYnuwr5O2y8mn/RX4u9gBFsillg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=koxUl9Bhb6pOKk6qTtolc4aNI2RYQiUs0Al/jCKT/zU=;
 b=qI70dwEuPwA0XcKralhUMn9j/7sGA/Wtj5TxNEeIpTBuemix5hp5yFVdULQr30Huzn58n4HXilwaCY/L1H+3nH1VHriNhV8mssgAO/2RNKRTP3BvXLK3o8p0g+BNluIWNSV43R4RmDTrJJXgOBkTwNqRsM0VMzZOEPOI+vV/rFmHHDo8sn/vtwWYcezJ5/Pj9IzdbFq5SiXxexvs1GYmrTKUBD3I2Km5Q4kJ/qglzH+1xAruQbj16eO97BBvEN25bSaIqar9tyIgUFrdA/iPYTMD1TyEBvCKt03ZanadFeWDrXa8heVKDB34alCLTgpTNccsv821ElRuS6pKM8zV5w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DS7PR12MB9473.namprd12.prod.outlook.com (2603:10b6:8:252::5) by
 LV2PR12MB5967.namprd12.prod.outlook.com (2603:10b6:408:170::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.16; Thu, 21 Aug
 2025 20:36:55 +0000
Received: from DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a]) by DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a%6]) with mapi id 15.20.9052.013; Thu, 21 Aug 2025
 20:36:55 +0000
From: "'Zi Yan' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH RFC 11/35] mm: sanity-check maximum folio size in
 folio_set_order()
Date: Thu, 21 Aug 2025 16:36:49 -0400
X-Mailer: MailMate (2.0r6272)
Message-ID: <5566D681-ED92-41A8-AF46-216AC8F62174@nvidia.com>
In-Reply-To: <20250821200701.1329277-12-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-12-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: BN9PR03CA0501.namprd03.prod.outlook.com
 (2603:10b6:408:130::26) To DS7PR12MB9473.namprd12.prod.outlook.com
 (2603:10b6:8:252::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS7PR12MB9473:EE_|LV2PR12MB5967:EE_
X-MS-Office365-Filtering-Correlation-Id: 03b70a1a-d4c1-4d7a-4988-08dde0f277cf
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?oPSl07THh7u3O1EO6lVPOnLiqj1qdmDxNG48EQlXY/Z1DBgjMvRNhbBgVbP+?=
 =?us-ascii?Q?5c8IQn+YeAvMft2RN5YpsUx8tf7odVvPJN4YsNBfkrUtQFeaKBqc4anI4Lft?=
 =?us-ascii?Q?2pgj/DQv9voztvCeamHV0GoZ61QF75TomBVTq8uIpMlq4e0fnAG4Ay7GMBh1?=
 =?us-ascii?Q?pCWRdRTdUvwxF/o5xGQBb13ydF743QdzOa1614X2B+YO3+Z0HqXfkLt7smRQ?=
 =?us-ascii?Q?4SfsJMu3bj/9F3eYDHXtJM6PlXI3E8eYROWE7p9eJdwe6VlSIrOfeJ8I8Q8/?=
 =?us-ascii?Q?Rz/xwL6c7gOIFa+67+vyemz82fJCPQPDnXPMffcFlCsoCh78RAHGAZ7eqsUY?=
 =?us-ascii?Q?U5DueMcDmQY/0WL9EL1VN3VoMtzpIzf5opEIqUAWlRego7b7t59QxZUCbNLB?=
 =?us-ascii?Q?i6xuaTLhjzpSeYqp4zLzndjf5znIIqx8l8HSmWL2wYQCKA0Ax581aGlWkniL?=
 =?us-ascii?Q?rZoCCMLJcd+iNc/OuEpqoZng3XANzftlFqHqKNBSoDwgfkAiNzURHOpp0LAv?=
 =?us-ascii?Q?vDFBXequetCV9I/J9wcP9mSVTKRS5WPFrg/KjKOQsP+wNJZlwJ4lkBVu/Ry9?=
 =?us-ascii?Q?v4VnzKccbctS66ESBJC/2Cyxu2BuWhNhXg8aR8spFpD09PmJ93YbcRMJ7nAP?=
 =?us-ascii?Q?wEEWF99o0SJQ4eVr6eoqT1Vgb3oYiJoFkrf90NaeIpG41NDyY+IJc0u1INe3?=
 =?us-ascii?Q?eNJPHuJxJCkDQeoxEGzxgQoLRq0Yi9wVFV4J0tDBho0O0ghbEV0+/0wFydA3?=
 =?us-ascii?Q?RoXClFOHshIO2weAkXu83wuil3VdSkCQuohwC0fgeA6NM9S/jDqSN5jVZBfB?=
 =?us-ascii?Q?IIB7xtpz0QTCHp7cY+PCom1oxGOIX0ikbtpROouo3eC/lVDrrmAvy/sDbFwk?=
 =?us-ascii?Q?BVOg6L9DTE/l2qX+9qy3PR4608Cp9NeoxlOxXYzC4wd1R2v+4oWPy1XN+8li?=
 =?us-ascii?Q?9jQlN0LlQCYZAXJX2/lbP+V9fQFpOAZ1T73uV4orqvUZJB4nG0/uVfWiJaC3?=
 =?us-ascii?Q?a5EWMnFOh2bKUYS3NHOoodPSJTUs8VDFOihMRMxB3vUO77EuPr+Jd5jXu1m3?=
 =?us-ascii?Q?QPi/qZKvK1EUNjrc3G3ULcYr6/+j0orXdCpAs9xIKwqkRaNdWoMR0mbCbMmE?=
 =?us-ascii?Q?eA/BmX9E1pZeUXaoNyHxs2lzfWkNqG1+Kx7zPxrs9eBfXR5uLR2aL5i/4pWr?=
 =?us-ascii?Q?3ae5JVIJZQtvXFx6iC4i6+ANoAYbp6gu1rlZKug7Wy/HVzNoqSZQoZKzsOZe?=
 =?us-ascii?Q?OuEd27ahWJDBRK9uNsAnnYlij7711+fpEEf4dhP9fzhjrsmT3Me62283SHcO?=
 =?us-ascii?Q?6BIqDqYhGC9bi3DgYmxLLk2l5fnCb8hBUdMbs0ogqaFyOCYrbKn6Z+MZM6Sz?=
 =?us-ascii?Q?6wNqb8DmcE3LSjlPzQ1Q2mB2TaE+9Hy0t6HxFW4pIyT0KkI9aD9MfqWGvGqg?=
 =?us-ascii?Q?kqKS6IGegl0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS7PR12MB9473.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?NCxgrQAmFjVQiLWTEgbWaY1DWfNMsLBr5j4o7FqESo567f8Zsbf6o9O2Jxk/?=
 =?us-ascii?Q?ByZkiveTXAXeSQZglx3TtNeqj9M0134y2uBhq405H0h7FO+B+VtL6xci2Eio?=
 =?us-ascii?Q?TfittsCGQkzFdQj5e6dCcd0tOWGjvpz2ccs41HYAfeXvnFlCfnjGrhpaYeDY?=
 =?us-ascii?Q?2V9xnAM+/TSc4HfNgbeQQTo87KaKBGCUo1d10iVinUnReSxT1iRjp6U/rAY9?=
 =?us-ascii?Q?lwgZSPu6DXNpzvFanA/fAKzt0VjT+9r9PxJMr3hhC2D9gXe3v7qaQFtRMwNm?=
 =?us-ascii?Q?bTyxMuvGH9vxWcEaNSqo+nWDGgLANM39pacn/xTHeQf8RQTIJq0i/xKwKv4b?=
 =?us-ascii?Q?X6E5zUafF3q2r/9SCLgY0pgIwtVMaeBYd3c1wX4kJgXUHr9oYuegtOd3Bcsz?=
 =?us-ascii?Q?7k86wy/Jsh46mBqrUmq0hI1lXzQR8iTyBUTkB93aTsz/TveLLVQtvHS40+ZV?=
 =?us-ascii?Q?+pgXPV5MqpzfQAB+UKWTg4cQGuiIyJ70P3kRQoXTxgqm4emTtWCzcGL/RMjl?=
 =?us-ascii?Q?Qby52xm1T004O7RgxffycpNwHIR+Zu7am1RyOl3Rs4ZcNQW7LJrioi85KPVU?=
 =?us-ascii?Q?V9BDEp574hHu8HvH80fyi1LheAiX2kOWPKzi8LxhjaWuzYWsZ0Zx/ZRLXgqh?=
 =?us-ascii?Q?k8gWefQxOTmuKeH9URI6a22pkabpy2E9iToh0AEXVFi0K7qRMIgbOW/9LESZ?=
 =?us-ascii?Q?dSGLV/CXKjBWvYrDSsh1I97IUvpqi+LsmuuJLjvjOSFx3SOIkcQIj/KCrBaV?=
 =?us-ascii?Q?w8PJsAEYr+A5NYX3+ahuCPLIlKWOLt3vRpgdHqbiMJtty7BG7IPGy+r5i8jj?=
 =?us-ascii?Q?hM2fcLktkFLJycL+FBqgJcWyLEkgPh4zy4/cymAv6FKdFp+GMCIV2DhgpJUR?=
 =?us-ascii?Q?W5PDB3LhDArixTSi62DrDJ6pegFsaDX5UgaF5nWcdUecW3FrnbbggGL8LxjT?=
 =?us-ascii?Q?IoKBdKemFTdoYQZNG9sLHzV67Z/EttdA8gWbOCbedjzfS6aeEGjOLFxt3TdE?=
 =?us-ascii?Q?15aHpR532HIFMTzkWO9mZTMqKeWybAyu/4QD2Dc/yS3wy0DTqe8HVvSwevuA?=
 =?us-ascii?Q?wOArp8D0/x3FOncrLjj2Hm/c9TS5K5IS1S9c5+0ONdpv7v0cjnFwdgFElOkL?=
 =?us-ascii?Q?w5CrIQ1oHYf4/BIavrQ84/rxhpUsdrGW4wHwiw4lapCAS6FafCdRTMaojS7V?=
 =?us-ascii?Q?J3EGXKj5RwGfGCpcHeVrZVT/hVPbPeBZk2DPxjm2gABpKOwzGIT9UqrGKkQN?=
 =?us-ascii?Q?0S5xWs2IPJT7wsM1qgS98Q/PbRix8XxVKziCntzYXlQ/GVJWywgRUopWEnG1?=
 =?us-ascii?Q?tEsGzTPn3BBtKKVYmWGEla1rLgERpkS0gnrcIkp+a8Qzcj7tQA1L1qbEHFOs?=
 =?us-ascii?Q?5Adq83nn4i3xhRoMtRa8h9eQfDOtKYEWgCUy3sVr+iAmqHY1TC+tE/UOrVq0?=
 =?us-ascii?Q?sYvDPO9P40i2BIVEJTfsuhU/VfEqRWvyxQFCFaj77ZqGi8CUZ9msrA+dFj3E?=
 =?us-ascii?Q?wtG6Nrl3LDege89oYWCgeU+cOHtCdkJkKaZgjx3QNTqlG+4UNMHexFMs4F6L?=
 =?us-ascii?Q?ZjP+GY5NuKmstmha0QkelsVjJ3ERyasWtxek21yV?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 03b70a1a-d4c1-4d7a-4988-08dde0f277cf
X-MS-Exchange-CrossTenant-AuthSource: DS7PR12MB9473.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Aug 2025 20:36:55.4394
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 1C2xVTmQxGlMPGE216NMJWrvZ0hUQ0fdjv+vn5C3E0IEGdPCLRnd2ChnSJgmZQ4Y
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV2PR12MB5967
X-Original-Sender: ziy@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="rcCjS/R+";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of ziy@nvidia.com
 designates 2a01:111:f403:2406::613 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Zi Yan <ziy@nvidia.com>
Reply-To: Zi Yan <ziy@nvidia.com>
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

On 21 Aug 2025, at 16:06, David Hildenbrand wrote:

> Let's sanity-check in folio_set_order() whether we would be trying to
> create a folio with an order that would make it exceed MAX_FOLIO_ORDER.
>
> This will enable the check whenever a folio/compound page is initialized
> through prepare_compound_head() / prepare_compound_page().
>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  mm/internal.h | 1 +
>  1 file changed, 1 insertion(+)
>

Reviewed-by: Zi Yan <ziy@nvidia.com>

Best Regards,
Yan, Zi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5566D681-ED92-41A8-AF46-216AC8F62174%40nvidia.com.
