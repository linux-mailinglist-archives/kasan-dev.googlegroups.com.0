Return-Path: <kasan-dev+bncBDWMT3UBYINRBCG3X3CQMGQE7Y7LXHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id C30E9B390D5
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 03:14:49 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70dd6d25947sf12751856d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 18:14:49 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756343688; cv=pass;
        d=google.com; s=arc-20240605;
        b=gr1wV1nxzz5Pt6MQ9diUZmH0EtkqRVQaJzixomA0Ym8C4ij5HSDwB+g6y+DT8cfZjC
         Z1xjX16uWHsDSCy8hcHLR+nHhQ+uGaZSCHn9m5/2zeENxSMhYVxMZ0rikkfytnBHRRIZ
         SCyX0Bd3GJ2vBWuYImN9/7s6cZezn0LzhFQvKID97QpGQcnusYRXf2VSHLv9mQWqVcmL
         BJZeBrtJh/WOD14QNuCxrTPweUXvgC2tvbbe/EMilK8nUFjk24Gq5bIYO0fe2gG8+0s1
         f50Ub9FQha3d91E7lQOj/xsRsO8iKhgm4sWH2bx4cP9BM0PkKZRNkcEH/iVWFTWLKUlE
         e3dw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=pARHU5KsPLXFdKgbXs4v84a/yhg2i/W9RM36NWSxhZI=;
        fh=f3XGEnJlp0tH8QfLavXDmGgUm0E8/qSaOunEg8k4MMM=;
        b=JbSJ5CWRtO10mNYlbgxn5h51hqyfW6Q7P0k2lDdcafr5gP+unQBZSY1su/c6LTuKKt
         VPoi8L50NpJ/TPXkunEGLGINm4a2nrDHBl29PUirv0J3u/gF8ktiCTVpH1oO8dwkR4/0
         KWswH5A2FHhNZi2Aqg6LrxDbey23pl/XS/F0HCReZfN26cbFQqJBTKuNYc0pQ9FG72ve
         rDlNUqdFNQH1CC3hOWGMwTYgxrs0YiWGSluQKQA+OPobVtubHl/BJ8AD4/W8A/YadUtD
         drKtYOdXwtPPZgr7dvfyclxieRVTpDeVvi+W/kGVBx7j9yjjTdN6PmIwlwSYmuCoRDnO
         IwrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=YW3BsJ0P;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2009::61b as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756343688; x=1756948488; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pARHU5KsPLXFdKgbXs4v84a/yhg2i/W9RM36NWSxhZI=;
        b=woEvWJGWoO0NfncADW55gSGEtAHcAMM6S1BCfQCd1qemVLsmqZvzHSfHWpkeyU3kXa
         9EVSqJIzfkQTvm1quMD8Lcug8F0dz7NcDiWVlqcXpbYlX9I4i/XKYLQUFWMhniE7te2C
         YOOrh8+5e05cvz3Dww2G6rIXpUN47DUQx8VWNp3VTjh0w/pi2mGX8IEHLIe7mgyZHmuH
         D0Jyn4zVkNc8xctGN/wsMx8Upmif51sNphJew7J9fS/TKWvjjm8sQ4UDiPVS+0piB5OK
         NnS4tmUm0/VEq4wAQQB01z/oDW2nLGmXPR0F78+RyTWopSsjqZIDp9T02noSSAaHPHMC
         Sd3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756343688; x=1756948488;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pARHU5KsPLXFdKgbXs4v84a/yhg2i/W9RM36NWSxhZI=;
        b=lfcmazQBcRbIIOcGnoOyzHKfuv0acDS+5r+RXRRtSXl6wJR5gtFfpjH4qxz7YbLCCc
         kVGIeLUUbuvIOxmKWG0jGPLb1bo3byTYPDhvQpqRGUshtCdDtfcXjiEgd3H0ArFilr/O
         65RyVT1KrfahADjhdbOuCe5uKM7/h2deQbh9v7pKSrHS+Sfm8xIFnrusfiFX4ZiT/5an
         zCEF8BSx834v/THlSb4p81HQyBVZL3nG5E2KUeGojQJY9j8wCGHAeMy28Gd2qxBdG/nR
         /Umxa4dTSTeJ1AWulR0qgvzLU5eZHem0V2Au/fiuZAd1NsbBh77Q4iM8zMQj67k8xZwp
         1A7A==
X-Forwarded-Encrypted: i=3; AJvYcCUzuPXdlDz7unwH1wk/myGXPeJxCOON89u+L8ToZwyEnD7YwNx5PpbT4/gRzVMr1oyjzODgIg==@lfdr.de
X-Gm-Message-State: AOJu0YzgPj5eEc7LgpsgDKxzG+9D/P0ctuCZzggG4aSJi02be6MvVZp1
	hnQAcD9Dl/qpxIycOFlK9dnn7IpmltuZz70tApS1V9mPpzjiLjfAyDZ9
X-Google-Smtp-Source: AGHT+IHte9F0Mv7Z3j4j4bt+pCyk7cNrfNWXVfu6Geh4cEYF0hkDBzb25V5yYBbPE3zMbKsAFFI+ug==
X-Received: by 2002:a05:6214:252b:b0:70d:b15e:e8e3 with SMTP id 6a1803df08f44-70db15f14b5mr211553086d6.25.1756343688283;
        Wed, 27 Aug 2025 18:14:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZduwna8ra09Ielayrc9qsaltaa4rjX7XzYM5wEUC+qaMg==
Received: by 2002:a05:6214:29e5:b0:70d:9fb7:7561 with SMTP id
 6a1803df08f44-70df0540d16ls3919946d6.2.-pod-prod-05-us; Wed, 27 Aug 2025
 18:14:47 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVmNIwWAFj1Z8NvXxd3d1+ycgI/d4Y4/cdBL+RU8yzxZzI+mA8UKQYAZyVaLM68Nr4BkjV0I4uBYp4=@googlegroups.com
X-Received: by 2002:a05:6214:5e05:b0:70d:dade:c34b with SMTP id 6a1803df08f44-70ddadec893mr69566506d6.33.1756343687515;
        Wed, 27 Aug 2025 18:14:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756343687; cv=pass;
        d=google.com; s=arc-20240605;
        b=i+UODdSwmGVExdAj389/hYQ6yBqFcdvvvU0L4WqmkXQ5M2lGs8Nif5R48nrCTqr1QO
         EnujUBNaz5iegn4HIC21ZB3omhDb6NvoD9604LSLnq/1gxxjcKAvza5I1tSLMz83VqjJ
         ei+H3qqR8IEeFA+4vRquYesKjElzRmTn/F4yHcQYNxDS7VhIfr8ft8IYU3/LcoDq40TC
         9V6WxrdXLUC5d9Pcy9pQXkyQcxMKs8nk6nElSVQEpnHbXFicpAkRIgh+Z7v8pfzqTqky
         uWhNNACxK0uc+5pV/sbQTiIwPfX8YKulEUUDwZaj24gATSVODO6SqBPHgg5qM6XZr211
         rYZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=eOGtdA0Di0Rlnjn+c0u3tTO1GxdwIqcIssxc+f51KF0=;
        fh=mkkYPuurUY7GUu5MdEwXZN672Dpu8wx5Bk7gstqa7/Y=;
        b=U6jO8SDL48l0IN0d61clGnFFBK3LDBwMW02avuXO9GvQYihXD/Ldjm+UiEmllO+q2Q
         onQOP1Rbvl4KZ3jBFtUQKjbKPF3DFosOqN0yHxCbzg8Uwuc6CUY6tJ9HxBFHVKbYU0oB
         KMHTTn4J6dhW8lMtV3AGScFnwSdz4tUv9DtlyLL/wOZfSRZq2mEujL1xJ14ZjbIm6b3E
         lHS0AqB5W7hOtwAJipJvNcVE10KBl8Xj1KfANyTSTu3TMo52sNFpbXqMMZ6jvQ7g/Ghm
         qO9zubVEsBCP8ja3CkwHBIhuuMA/gxv5oeiMhmkTp3w8Ii1O2eUwI3A9T1SJZkqaXzWH
         teEQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=YW3BsJ0P;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2009::61b as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on2061b.outbound.protection.outlook.com. [2a01:111:f403:2009::61b])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70da71eeaa4si6108586d6.4.2025.08.27.18.14.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 18:14:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2009::61b as permitted sender) client-ip=2a01:111:f403:2009::61b;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XQFx4cYMZybm2J2nM8eFTb7B1A2OEKmPLOSvRYX+cK6XqBGn25jpzB+udse2u2HCd551xV+BlxB3OZm/CiSgpTtW0X4dz5i6ZzL1TFGz9cWduwChr0+V97SxhGDSani/cD4BMdnNmmKapW5ng+hqSNgyDXZ2gpMKt3Da7X7noZxJmRDpMk+Yrev+DfTEOoGbEV67iy1eIywIT3sgsQfzVSz3MbzHrYjVaJbIjrtr65IqW3dpmkLArZRbD2TKB6dj/0lxceizjGLmo9q3CHdLNVeiLd8qPtbzwm9ds6m0I3bR8VpmC7+t1MYSxsFYwQedLQrT2Ld+8rdvijmV1rGL0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=eOGtdA0Di0Rlnjn+c0u3tTO1GxdwIqcIssxc+f51KF0=;
 b=DLDCi5N8wmoNX1fB9DXvjJK2Vvp4P1BbU+6c/LQiegFQO6JRz1kzyL6AL+ohdwSOnsd3Dpb2Tk5hUohhP0pBWpxBNSPfmqwMpQkZWhsyKU4jFefO6eTBRiYTaShUwkllch7uJS5ZdpNvHCx8/r1tw/atIQtU+fBGvJUPGOW8nPlOJMc3NjNr6gwiggT47FbOxUXRuvMvrmQmVz9HVGdjPHaNeDV3ToFuryq4gCH3/fg5tFjSQvcq73EsisAbYihD+dryY7MZyOTbC3+yHGJfRTgjuqAcQSLgPFzi9B+KBaT6857sEHvdMC33EyEcizizfy/3l9I8PgHkAVkcLgvhzg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DS7PR12MB9473.namprd12.prod.outlook.com (2603:10b6:8:252::5) by
 BL1PR12MB5755.namprd12.prod.outlook.com (2603:10b6:208:392::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 01:14:44 +0000
Received: from DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a]) by DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a%6]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 01:14:44 +0000
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
Subject: Re: [PATCH v1 15/36] hugetlbfs: remove nth_page() usage within folio
 in adjust_range_hwpoison()
Date: Wed, 27 Aug 2025 21:14:40 -0400
X-Mailer: MailMate (2.0r6272)
Message-ID: <521A948B-6E62-4CF3-947E-17B93F524DA0@nvidia.com>
In-Reply-To: <20250827220141.262669-16-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-16-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: BL1P223CA0040.NAMP223.PROD.OUTLOOK.COM
 (2603:10b6:208:5b6::13) To DS7PR12MB9473.namprd12.prod.outlook.com
 (2603:10b6:8:252::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS7PR12MB9473:EE_|BL1PR12MB5755:EE_
X-MS-Office365-Filtering-Correlation-Id: 13406c34-d33b-4262-f00e-08dde5d0456b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?DQ1btIH1/OU0LfcBm//weklucY7uq/JeyjMqxcSb9EijXvlcjUuqBhorQIYZ?=
 =?us-ascii?Q?wi9/YNjAZxRzJPNApKGUHGCXM/9JSlamXQJO8sotiqYE7qSCGCe3Jz1MomHG?=
 =?us-ascii?Q?sbz9VRlWRUcIEpIkmcDQQgTZq1zLPQNf5fe/sS2JtexkUkL/JAE51IQP+xrH?=
 =?us-ascii?Q?kYiX+hynt4rFmbEFbvlp5PKQYmn22bBwNKfztufgBA5n4kfc3++W5i1KshL/?=
 =?us-ascii?Q?QEJnCmy0NRvPDUG3VX3VH3YmGD6CVwqn1k6IxvDCqWNyAHH4O0Mfb+bG4uWr?=
 =?us-ascii?Q?fp4smFq0mSDBOKkLZ9fcmadnQ/Cv8I+F018ESB1ycQvKxB7Bn+JKHmOsmDK4?=
 =?us-ascii?Q?IuI7KxAftQ610wUj4X47KmhmMYDSqwrjf2QjgFHuR/MrFckKOQaPB48mFfC9?=
 =?us-ascii?Q?5KefS4SiTHn0DazBnCW07EmpV9FwVgqmLR3ozCVpceCwBdQ3ULlutG2xlEjY?=
 =?us-ascii?Q?feoRu9IJrZ4gudvYvcKYvKj/U1f6q4/VTzarWQTnPxPqtvRM4e/2/zoYJpx2?=
 =?us-ascii?Q?P4EowQTkvDe4U36JRYwMfUvzAF1gerB8I/+Xp5F8J7nfzEz2TgvKzzhX3CT+?=
 =?us-ascii?Q?hJmM0qv8lQmL7kPA5WIehwwZtGrxacwmOutUH9W4S/Bi8kyhMIcvE7i1bb95?=
 =?us-ascii?Q?kf8TxAg1kKXuRxNmff7Y9vw1IAj0/C1HOZ7ubdGU0M/4dZwEJ+MuBkHHJdUl?=
 =?us-ascii?Q?/xhqwW3ErzO4SAbJFaX4UmgTTBeY4Mp1tlGPgNRB2gFKf9wC6NsHhO4D0V2d?=
 =?us-ascii?Q?549v7PasxnI7+hcEY0Hzbk81ebN5g1OyVWoEkI3D9L1F2XPd3WMDeZO4cXxk?=
 =?us-ascii?Q?UmGIG2L3qdSxDjZe9z2wAXWVPfGh4BkzA2jh1ME3MPAJ+EN/nZ/17qy7de7o?=
 =?us-ascii?Q?aViWzhZw563mM8MPd+PYOMJ4blBfLdrwsUNj8cvfgQxPySXR9gtSYKRqXMdI?=
 =?us-ascii?Q?C2dLUwF6gQO/Ygm4w8wjKIhYZSQt2k6xfusSAyfsaVGWAWW5MMLnQMSWZsAn?=
 =?us-ascii?Q?hlZzX3bz9aTj0m3rQoQLmvz0VEeeuWJgj/U7AbXFXeQwIplQea50uOO9tfI/?=
 =?us-ascii?Q?fx59KfpniARPlFqB7Hv/47EvTGFHelgE7ggHPtEse41ES2X8AuRCdohShEcY?=
 =?us-ascii?Q?+WbzyfLMhqDAJ3V289W7am9gQ1vnZzExNfpaJNXfrh7DccgprPMCD5JwgyXu?=
 =?us-ascii?Q?bHmVHAqRPZjouFsxJ09T4E8Vf2wU6XGs8vmGHomnOygyCBycgy3x5Noa1b16?=
 =?us-ascii?Q?77essKYfv0+dnBdB19RLhXOPtg1epxRoPdUV41u++LejZb8QTWAfN4pzOgE/?=
 =?us-ascii?Q?hSnErFsVeESuFm6pf1rSdoAlXnMaelnb8NkWWSfokaIpnAd/SenvaR2moysO?=
 =?us-ascii?Q?D5Hk8oZkD2P2HjG58++yfxH431r+gXcMMc3SdIQtQv1bBQGq5w=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS7PR12MB9473.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?FK7IDYCXKu8JNi+OBI2CFu3IzqBv3kCtXf1uoRLlTqr6hQUDMPOzwzshdiVj?=
 =?us-ascii?Q?abJoYmGiIztOdTuV0BiHcOnpSEN9uQmncrmId9zK/3dB8wIAWHEVEq+4kGNV?=
 =?us-ascii?Q?MjRwGA4sS/9JZl6levdUChRbeNTb9+leafcNhT52JlUnhGfAPlOZct9SKcx8?=
 =?us-ascii?Q?2ipAJscc6pggZImgo+ZuAhl2x1K9Sj8XyMyIIHUGdnmW1p2yRdkMCNEHxeOL?=
 =?us-ascii?Q?etELJoR/SbX2UCSu2q/6fF7Q+19EG8gacp5B2qiO+ylbS3BDgYMMWN4IqfXx?=
 =?us-ascii?Q?HnAOXKBVraAC21CREORzTTlwqCAPKvFjYl3ws8q9kcXZ15dhUR3nhz1xrVoK?=
 =?us-ascii?Q?pLVwoauuqo3U2brn1gErB6S0ocRDymZj1o1gq1XpYmWkMTRpp4oNuqOnroZG?=
 =?us-ascii?Q?WXe3ji+Gi1M6YGAKSD07t94/jyyia+o0msMEBUxxlCPTY5p6nlJ7LxUmhBea?=
 =?us-ascii?Q?16CvUTCOfP8vjwJOejO4cPC/i89bCXuLw3iViwh+ryIwELip7tD0vxI/vrGZ?=
 =?us-ascii?Q?/AZTaAEFNrng26VVHvNoJCoorMRFCWuSFVudz9c/Mvekwrjja0fmKIOnzlzk?=
 =?us-ascii?Q?ma/Zkrgx52V/r+z5vtvJDrYWPcj8QdSB1TNjn6KuGcuVMQtE8i6/jOPTFcVm?=
 =?us-ascii?Q?gfUlqNDLAmsH7TlZnfsunEioPrrHR0WQt4ZgeaP+/2iY6ihf6lMAXMm0mELc?=
 =?us-ascii?Q?LCg2S5SdiOkb6DxJ/tdEgE94OaIQ50qFZMAdm7KxFREq/GuTdtKoAsviEw/n?=
 =?us-ascii?Q?S0J4bepq87omKUhD44Jio3P4c7UrZMOAd7lFt9/MZa6AmYO8VMr9M+xoSixK?=
 =?us-ascii?Q?p2JhnQHgPFNWdYvDAOff3ZJeNEQDgBsZvSDyF9y8Jf5KwQTx1v8bZnI8l5Px?=
 =?us-ascii?Q?5IRcCqJKRhAl4iIZ3v2fCmibSyr8QVVK1Qsa1h4Hi3bz9kMbUXL9Dwa1rgbT?=
 =?us-ascii?Q?yH+fQSM9W61yrGfNVSdA+kZBqIDiGnOcByN3wZVoKy4EfKKF1S78CiMegQvb?=
 =?us-ascii?Q?754zXlpR6C0k4F+40gXDkWq5RbfkFgMB96YQnjGREYE5qt46T8eSn6WKvwER?=
 =?us-ascii?Q?D/VU4RIWd+bghsp1XdyhNg+11O9L9Y/h7sf21T1v3hhl1Qnd7hU1Zeiqsv64?=
 =?us-ascii?Q?J3C/G3iGyjxz1oW1GdZpLj+5Pldmog33KnE1fg2d9fOl7b1OgBz88j11f+he?=
 =?us-ascii?Q?3ImiKvfcsHoNdRrz6ah8RENMBf0GioU4DeTgCxbPyOgvpLPtVXPcHppEZkOR?=
 =?us-ascii?Q?CbcTNuyhfaK644HlSxP36ea52+NFvBbnQ1Hr+d6PAaD7a55oze4qTgBNikxY?=
 =?us-ascii?Q?4/WjA6tmAjROPBPnqDYFT4nURLYuHAPAS+NXXQXQwlp+hG6av+f/QPgT57wb?=
 =?us-ascii?Q?CJo152MrYeaAackX6awBw2uXR2d1frds2V3ypnXY2XgDfIVmv2ao/mRKG2+r?=
 =?us-ascii?Q?DNLovNDAJjNmRUVCQoSpW+uQPML+jUTWZKk0Zt0Kmz01BRFjnLp69CLOcKwx?=
 =?us-ascii?Q?Lfs3xuJWP2XmOkEZ1uRX7+M/qBKXTgHOi0HyJbns7cM10P8CqdTyeyEbv92l?=
 =?us-ascii?Q?WNt4PSAl8p3ZaZAJuGc5dRpDaGOIMuaf8ox+qtmV?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 13406c34-d33b-4262-f00e-08dde5d0456b
X-MS-Exchange-CrossTenant-AuthSource: DS7PR12MB9473.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 01:14:43.8835
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: BWNOW8xk+ahrDJdsv+KB0H5muwq4mEATrKm4/WnVLUKR+GfC6TiqXBhYaTVsXER7
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BL1PR12MB5755
X-Original-Sender: ziy@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=YW3BsJ0P;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of ziy@nvidia.com
 designates 2a01:111:f403:2009::61b as permitted sender) smtp.mailfrom=ziy@nvidia.com;
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

On 27 Aug 2025, at 18:01, David Hildenbrand wrote:

> The nth_page() is not really required anymore, so let's remove it.
> While at it, cleanup and simplify the code a bit.
>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  fs/hugetlbfs/inode.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>

LGTM. Reviewed-by: Zi Yan <ziy@nvidia.com>

--
Best Regards,
Yan, Zi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/521A948B-6E62-4CF3-947E-17B93F524DA0%40nvidia.com.
