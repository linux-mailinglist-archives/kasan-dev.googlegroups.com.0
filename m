Return-Path: <kasan-dev+bncBD6LBUWO5UMBBRN4Z7DAMGQEPTIXAMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 14727B99BDA
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:04:24 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-26983c4d708sf64437105ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:04:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758715462; cv=pass;
        d=google.com; s=arc-20240605;
        b=fM95SZiABeNXIemGaUMulWM3AxBEbrmRQRJssGD2fTeNCG8gwU2uMJKNnX2evntpGa
         TH52gHz6dKroX6MDfVo+CMFlkthjWC1FsJeK5i9zjej3SFrcSZfvKdt2UuxRh8JuuWwn
         18l42nzFRn5nVqlowcQOyiyv2EBBN3dMrOc9H3TeJ9Wqb3iHffx5BX8qm6rg491wybSL
         kxGlclyhKz+k6XNxFBPLoJfHayxs5lFqE+AWOT7LZ/HySJLJ++KjGQbrEbrlnXADkjwp
         bYDYNvtSQRhu2YKuDLHlxyMDa8ni5lvizis2xN+JMzogF5NhUoaMw/WJBwvwoDl7MYNt
         b9jw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=8sd0KvlGRZRgdvVqE5Ee6eIs8MTFc1mpP5afIYh47BA=;
        fh=8EzvMFCEMJIx4T0BEWmXp1sQaaZOrmBBhSynxjOUnqw=;
        b=cvNZmrBLHKB4uPhl3pO2MPut7+UB7BFOsNcZqsbpGM8LpMszpqhNVRl5NPyE1KPJs/
         dGJb5+KD3VYS/UzytRPybJKcvNm36jRxTHYGOZNJkuETs0p8AzoXEwwFhcZzhb3Qj41b
         lBFw6YsIiD3QLyBjrgo4z1/deCspQP3zHsahyePKCcGvPfCxLGyoJpR+IrLWdmL1FzE3
         sMl4qweFgXb6Rc9/kSUGAetVBkRJK4nMS5mV+IXycbdV/GNeFsYuCrwSWQXbLlWIiPoz
         K6V73KnveG1AkkQrPGtZ9gocaSKRri3mI7HScLZmOfpg+G7E0WPZWpuYVilLUbeWGaEw
         kJXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=hZfPQbxb;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=jdoZtQ9c;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715462; x=1759320262; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8sd0KvlGRZRgdvVqE5Ee6eIs8MTFc1mpP5afIYh47BA=;
        b=Hk7YmGADgIMa4c6BVEwbzpvUKNL8hXsYWH9PFX/eCYaay2vGPG8EEc09MqPCryhMaV
         EEphjK119MjYSfLFa6Rb8tZ20UQGG1WP0KRGNlB6r1g+Apz88JEWlRuswQ9zbOpNviea
         LvFAVQQNFfLzssIvwYx/DyM18+M2+2fzhdQLApHq+KFM8autb8Zl/xOGQwkWcsUdiybY
         tMk8nmG9v7ybvCoZ2NMFpRoFbK84O58eSxnp5EA5cj3hU9L/+VX2U+PlXH1ffqTaIcsc
         86qeZhCWKmF2bya5DaGhHI653gEacI8InF3RSsKuR2e1mRTVsXm8hfn1+iP/DWM2+Nmi
         dehA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715462; x=1759320262;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8sd0KvlGRZRgdvVqE5Ee6eIs8MTFc1mpP5afIYh47BA=;
        b=icJvFp87hoBym7nt2Y5PeSVpDWIk6yRjcX9smWaMpQCvBgoqOMl/0HwOZu4nj8Ba67
         V+59xaqTa2ySbk2wfdUhOJdOSbbD25x/WO7OYtKKOGjG4oF1SYn4lm58wi4FdP0bGMfS
         klMTiH5+cUS1fkGXCK58abkSrxr+zAZBgGn8W45RE+WZ0A76wWWN39jHeDIruy9rtN1n
         f1TMATDiLMP4zqgkWfxsWTCN9cK5weVMu9z0TRm76iGkQ51ySycWTcHwauEaaIhD7D1O
         qZ1+v1WZhCHGbi2Yx4id2nXKt1BvYNEXd/xoFv+ntUibyxVraMwmt3bkG4S2kRlDiwlH
         /VOA==
X-Forwarded-Encrypted: i=3; AJvYcCXqi2RdUNM4/wvjo3OGqtoZfUQgnjn99jgJ2RFitzbLNo8jdP2tfnGkDudzpS9uBJqmQFd1wQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzp0yOEBX94V+Rl6it8pXyTxHOg8ObGC2w2Dis0o5bL8B9ruR34
	71qa+HvgXCCtxA0gw3kYh1N9px6D9gH/jqp4DcuGNU1OOE0OETa3zM/+
X-Google-Smtp-Source: AGHT+IExidK+o7ZehrRt0yiypmkSWWSQnNeVim5hR2WkvvrGVyYCnaGcCwRG7B67qg/SXeP9YUYsgA==
X-Received: by 2002:a17:902:e88d:b0:269:9adf:839 with SMTP id d9443c01a7336-27cc20ffd3amr75278805ad.19.1758715461973;
        Wed, 24 Sep 2025 05:04:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6LCTSgEvlUoqwIzkpEA5pTowr6VF3eVWRaCyqxrU4XDA==
Received: by 2002:a17:90a:ec86:b0:32d:efd9:d13a with SMTP id
 98e67ed59e1d1-33065233139ls6190964a91.2.-pod-prod-09-us; Wed, 24 Sep 2025
 05:04:20 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWCJL3+nECB08hgiG4nJG/axbTmBEqc0Fz4CoeJUyokUpvkPggGV4GSxB1RXKq0j7nLWqHQnLE7wV0=@googlegroups.com
X-Received: by 2002:a05:6a20:85a9:b0:2d6:9a15:137a with SMTP id adf61e73a8af0-2d69a1514e7mr4519342637.53.1758715460381;
        Wed, 24 Sep 2025 05:04:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715460; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vv/fuaWw9OdnXJNHdYOp3aPe84Y7Ro7q81ZfBfUzYQsxXeBZzJTay5p8SO1BDSwhei
         3WyTXY3t+YmzyCXkq1Dz1f4MJuwx0FSD1yQNlKRfShLoqcHjYPYpSJpEkBrtmYzGxYi1
         /Gk3SR5PjDap3olAn7rBPS45zBrQsqHRc7rjy8paix6/6E5Dh7inYcnMJOIILZzVyA7k
         yNKM3rdiGChaktZuig1gCgFo+uo/FcXH5ExcIWSiewOJMXYgon46wkBNotH/fz2gmwi2
         qr3/xrJYdbv9nq8TZUe9DuKkWdgq9cDQCqPYqOCxrYqSQ8HbHFB5L/ff9Vl8QQEtJ6N4
         XUlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=YDEFgeXJhOei4PwVGE5ptxybwP4fnxGr3Qsh+J+TyCM=;
        fh=lFQY7KeWndSbGlUnMTXXyxMqcgcR/Ax3JR251ljFdS0=;
        b=UBuo5LiFYF71OIgwq76xRaatCrOPnGwOnlYV2weXRcJdtKyVKh7s50VBBcz1n5NRRP
         TzBNuNW9bONm/x/egDDhm0TiHAXiSJsbEIIHnyUuwpWlYsVlfFXV4gmsGISZhUS24F4F
         pmLMoEc3kmAp031F14XK7WTK7Je5v5yEJ8SusrkqdroM9NIE8IspMGQ7UD+UyheoAIuR
         UkBN/Dkokgzyq3liSzebaBA4JWnWg5OJMv1RQBNc+B95KygF0B1w4KUUGwk1DVAu9CCg
         DwylTlKRzvxD8OJ2iyv0RRgnueO4+LU4S/1/CTaTrjF5b6Ldmp3bbLTonoolnvX02mCC
         IOMA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=hZfPQbxb;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=jdoZtQ9c;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b55283f66ebsi563540a12.0.2025.09.24.05.04.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:04:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58O9MrA3032003;
	Wed, 24 Sep 2025 12:04:08 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 499kvtygv0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 24 Sep 2025 12:04:07 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58OC2Cxd026702;
	Wed, 24 Sep 2025 12:04:06 GMT
Received: from cy7pr03cu001.outbound.protection.outlook.com (mail-westcentralusazon11010031.outbound.protection.outlook.com [40.93.198.31])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 499jq9rwdu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 24 Sep 2025 12:04:06 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=QNNDMkH5zJDgnPJvqbetJRSa7Rik89VbN/eg+1f7bjvoh2WH/IpGUERrDuXVZEAFyH9DCljRACXi1/VSOCK0XiODkp9dtENEHGO/AkG5u4T+4/YKTKP25OoA7icfRLq4a7YHH1eNyNW1tsAptimZk7YhSBjqDQ9YVX2Lr6gARB004mxotOmYRMwCkylQgEaralH7Ak8BfyH9EXLrmccBsa974LstfZClVQJlV7gy7cqOZwCyUr0hS01JCB41fyfM43ADrDLSgWZits5vDBDsD/tfliYUDzalnaO7xfI/iPAeO6FT5aNCjyP8k0eN1VhnQM1+C5ZoOn+9+s7SaAlgSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=YDEFgeXJhOei4PwVGE5ptxybwP4fnxGr3Qsh+J+TyCM=;
 b=XpIUNzbWwy4lnUr4pUKY0ddT96sqkKPD5nCiXUV0Ph/v8jcAN0GPGpkF2j7PYL9gcyzBaFQFjCt+nAGTvvQRSpu531BN9a4/O/cE6pu/34HSg+y7uFK63oRgkuPbzT9HUjZvlftlBXzYO91boYOf9PMDHP3H7ZGKdDgYS6kL3lwTVAdX5+yKMTSMB39YQguzNvYTGutdkF93jSZwLjkA8TLVSkVnkbA/HBJBrn5+HUVrYADRP5uHEksOTU94uQ08SbPfNKP6aVLLH9i765SLCA7g6JhRdUqPXQFO62e60f3tWYqggvqeVY1DETFDr8rsPJS2+hEWqIMHsv7v+JhlmQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM6PR10MB4363.namprd10.prod.outlook.com (2603:10b6:5:21e::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Wed, 24 Sep
 2025 12:04:02 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9160.008; Wed, 24 Sep 2025
 12:04:00 +0000
Date: Wed, 24 Sep 2025 14:03:53 +0200
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Sumanth Korikkar <sumanthk@linux.ibm.com>,
        Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
        Guo Ren <guoren@kernel.org>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        "David S . Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Dan Williams <dan.j.williams@intel.com>,
        Vishal Verma <vishal.l.verma@intel.com>,
        Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
        Muchun Song <muchun.song@linux.dev>,
        Oscar Salvador <osalvador@suse.de>,
        David Hildenbrand <david@redhat.com>,
        Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
        Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
        Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
        Reinette Chatre <reinette.chatre@intel.com>,
        Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
        "Liam R . Howlett" <Liam.Howlett@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
        Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
        Hugh Dickins <hughd@google.com>,
        Baolin Wang <baolin.wang@linux.alibaba.com>,
        Uladzislau Rezki <urezki@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
        Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
        linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
        nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
        ntfs3@lists.linux.dev, kexec@lists.infradead.org,
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
        iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>,
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 11/14] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-ID: <ff0ff4ef-bb6f-4a43-a2d8-35ab0f18dd09@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <e5532a0aff1991a1b5435dcb358b7d35abc80f3b.1758135681.git.lorenzo.stoakes@oracle.com>
 <aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
 <20250923141704.90fba5bdf8c790e0496e6ac1@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250923141704.90fba5bdf8c790e0496e6ac1@linux-foundation.org>
X-ClientProxiedBy: GV3PEPF00007A87.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:158:401::614) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM6PR10MB4363:EE_
X-MS-Office365-Filtering-Correlation-Id: 012bfdb0-6dfd-4afc-7d53-08ddfb6272a3
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|366016|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?QszJoOsOc4hDiaMvwPYNMJ1RFEqLl/Mr42eQ9xmER6ijeptE6r3enDuTTcrV?=
 =?us-ascii?Q?NZgLfn5ntxyl1QRnhYGESwManQQL5kLuznwF+Qb2JEt+PcsZttSMAijWX8oU?=
 =?us-ascii?Q?El6yvW38GP/6W9iKlVG2zp4r9RKhqE7ax70TiBRsA5LDvXn2V0hXF0aGs5Bl?=
 =?us-ascii?Q?If6C6eDUr/olhZeKmH5vu/ZTQZMfMLz5j4JwWJE0D2+g27iyOP96E3rdcjjP?=
 =?us-ascii?Q?XM03SCPSGG+7VlAVx/OZFbEmyqmdJtwkSTB0++gNCYLc6xJSCemuRk+9E6oG?=
 =?us-ascii?Q?UgYJ7EIEZnR9AYZaZ8lmpUxZ2Fj9Kfx/+RUfObwJgx2dLGZbDjkPx5LWjeSG?=
 =?us-ascii?Q?GLTLXchw+4lNX545Gc8bKZ6+9CNdNZSyV7fMJAVFuJZ2dh6qIjrA4oTS5xCX?=
 =?us-ascii?Q?V1lcypzy6DYYwhgYd10XP4L36wpGDJusRnaS2DjM2TBoG8XEUZAbp7pgWv8F?=
 =?us-ascii?Q?6Az9r4/G4RlYRJBbyaPoHasy5uP8Z7YKPvb5lNaZIGSLw6pdjBwY9ealLlUE?=
 =?us-ascii?Q?t4211+UJA8OnmQqfBg15sO5dj4qPo81iz4kI/ENBFZbE9uWiJ6dT8ORj3+3N?=
 =?us-ascii?Q?wL3+VDoI0Q7U++BwNpkSeImOtfliSd2Vtyd9H9247pYJ+nSNPD6ilS5Cy910?=
 =?us-ascii?Q?qYr5Pxlorhf3nqlZlk2vWvh6B1z+Jp/EMrIwAB8B8P9LVwgXwbny55zePdQE?=
 =?us-ascii?Q?PxFRXpydCDPlo9M4zxyi/BzFFF+Lq6x9h6DofQXtMhjJnXkP88gzmMSUG5BN?=
 =?us-ascii?Q?UfsDUaNi/nuf9WPsMmqWuGqvf2BNsC/oD52lVltOueWjGV7oGGj4bid9roJN?=
 =?us-ascii?Q?5EpJ+SdnOQux7/1Rw/H8q1eLFfGhwKKzuZKC9jTKbZcoy2s365ZXzp2e3rg8?=
 =?us-ascii?Q?jElI8E7R1oJwqtgAGMKWBfyG4x6lJTxwGIzZVWV2AFnXMHw30lSOZ6iHmsPV?=
 =?us-ascii?Q?lyjtMg6ypgHhmuXfDd0cETo2qKv2R/BtXwv1RY7BN1qjPMBkxm6R3EaJrJsZ?=
 =?us-ascii?Q?iAJbsTUwyq6+JzzO9jaS5fGD/JdLVOWsNraNYUF/GADXNy9Qhfw2jaPt1WZm?=
 =?us-ascii?Q?OaKyjxq0Y01WX5Q4g0NjMP6uNZ+OuEkhwsSqYH81kjFUNa3PL0dI/uQZc6ME?=
 =?us-ascii?Q?Zlhi2iz+MBQI1CAO9MVUfyPiOQlO8kOROHmkCORXI+3SMhnc8AaZbxzPAyH2?=
 =?us-ascii?Q?tCh6UhYUfYlPg4iD9NPtzIqkg8zTnc8nDrAFpoaMd/bp801mxmlbSWYlr0cs?=
 =?us-ascii?Q?f5Bp16NRTAtzMU9yy6QzngTdO6sQBrUQWJuPLS7wzHLyE5sfJj1mK87c0m0a?=
 =?us-ascii?Q?syrgCUP2KoVSpZ36ISeGMGhioBYEh333ijqfwd39HB8HImhV5Da6Ad5PILeT?=
 =?us-ascii?Q?nLf1MF5WvfbD5NT6fYWe4iXdxDdCqDCyaMdX/Rwl7beeGWeceT9rkFxoTeVV?=
 =?us-ascii?Q?GXgwCFZIejk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?UVytuLx85TL/TWFlFrHuy6Ogupl5+amiMmcfAZcJ/g+diJPSV5KqRTluuez1?=
 =?us-ascii?Q?hDUJDoRMXay3WQSeAfXUe09XzU9Eiv+fhmGMQRfAQGC0XWWRtP4xWUnxr1BL?=
 =?us-ascii?Q?VC0Vw/UsXGNBrW6wNw3/GFZBfcuR0O8RGBCr8xM6yUGTJK7VJPISDA4w4iDN?=
 =?us-ascii?Q?bfPNDuSHZT91XqdewBoeMzLQ/lz/4G0zpOMH5gWo1tUO/lOY1ujT2oKCoM7R?=
 =?us-ascii?Q?zFaL0MTdgCE0s8DDsS/50OmrUX5Z2PET559qjljLS9IQojiIxKYiR0gvHTte?=
 =?us-ascii?Q?5rzhHLyjBPnqR8giLOGWK1gIxrTS3OFurvJsNmczy4bYkIng1F7cvcJkCi8+?=
 =?us-ascii?Q?gttwltkkPv7ipox1OHjMpRv7k/hEQehaWUleISW5a8eGU3eVa7Rw+Q8L6mAl?=
 =?us-ascii?Q?J8DEqJM9TWfC6cLPFynWOv7INLfrGuB9SDTn4wzRr7fPw4YB7B9+2Suc22Np?=
 =?us-ascii?Q?kdWV/kz/zeL9hAdKJk6S2stn+eYhqYe12Kf3wx7ojhkeV7PEa8HNEe8C2To5?=
 =?us-ascii?Q?ExCVywaeavBmgRaPMypde5XB3smHh7A1PeT9HfVsiQkT7eU8H5ywtHYUcZHl?=
 =?us-ascii?Q?CKjlme8Ivlu5g4AR7NnegBrBTSeZ2ydzZlclzJiG5aoi6x2gcEzLxXEzI0XF?=
 =?us-ascii?Q?J076YM9yas+7S5NBv2+qu8DvURJKFFxqxVKOA2mgfFyk/7+pbiCacKxsLyy6?=
 =?us-ascii?Q?d0wU3GcvAlqRhPai+mGntlWfNblwurcj1qTvcY2G2ytQ6pCwsZxsoOybduI6?=
 =?us-ascii?Q?r32PLfBMgt0fS3ctgPf+0iWNYTqneHJ/Ev1szRXe1VA0OfQkmibF2sC7hDHg?=
 =?us-ascii?Q?hDc6mGSykiVdzNdUYgu7U/r/Tb5kRDyJ9y51JYEdAzObCp/BL2pYT6h7YChm?=
 =?us-ascii?Q?ElcDFYvMOcKanPOF+S1sP6pU3TV9mr+tXyowBrWBh5kGm4DbsW2WzDPanqP6?=
 =?us-ascii?Q?/WyZMQqJzmX70EBnUvAKFUR4rY3BmDYwQv/hees1Vmp0rrvJBVOtQBVCZEoJ?=
 =?us-ascii?Q?mlPOwFK3dYKKLZzuREnzZMi0pJbHeci7CpZCLLQAcdWBpKPGGKTHscPl7oCj?=
 =?us-ascii?Q?KK0lCGic0uKv1tb2YhRoKDn18o69TYy2qP59pT/lQoztQba/m7zcuk6zH/PI?=
 =?us-ascii?Q?dUwoW0NSDoqaomdDAj8mQ5Cc7WCjRxjPyhPWw3goTF3QWjf7L31My7YTGEaF?=
 =?us-ascii?Q?AWJw0OBi3GWYSwXUfhrwkrzbWTNU6hxoCfcaB4183zS9rDU4ovo1IXWhxnz1?=
 =?us-ascii?Q?0W/FHrawdTko8y3sBVLCY15rI+aPNQx8QtQIbqkJ2OJ4FerHe7qPlLtqmv8j?=
 =?us-ascii?Q?G4xdULmUvJATPq6RgtbdRRVlxQCrd+Wj2kpFSUV5P7nVvW7qPUQ6mJS9akpH?=
 =?us-ascii?Q?ks3zywSLdtWNYSgIUeD1ylXmrRsbHX/bLN9MEgDoRscdLbdkP4AFbPV4NdnG?=
 =?us-ascii?Q?mDgQ9zz1v4OYoMueNtabPreI9KjwvApCTynNv00Bd455hLqYf0hRFsGNsotY?=
 =?us-ascii?Q?H93AL43C6zo0B4KjUklCIapNZJB/E02NKSH9gjn5qDDGmgpVoqFYD45E3pQi?=
 =?us-ascii?Q?eM9x0EMhFb8N74WJhr2at/HVGDLzX6pLIH5c0PZfnwhTcaQj3tNtzyO/uf1e?=
 =?us-ascii?Q?PA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: EKHGuW9m+W7S27tkv4Oi6YMqKnZSFYg/uMKHsv9u1xDPGlaLjG1NhN7+9Qvcfpn/Z/w9BM95lxaGJ8AgQ6q+V4BRcjG60bDYjp01zHjfSupep/1xn85D1V6MX6UXJ+BGntjNITrtiajiuqEG4TXIiJDfRQiqfX59S6E1GhrT3Du1H5WqP01dthKhzmozY5k+QyuxvTLDRhsol59disLtfXmjLBxNq6TXbWR60O7bGCJRjZmDVjUVpuWhxPSsIUIhTDB4hj12pHnCLy/YuMTBV6vdzh/ipqW+xESCDO2W9gk7mvwpk/R8AWNsW3+ibmfY3OqQm60C8sM3nQ8XIQqbDPGkzJqxoDVmOSiRSa3rdzhAhUH8PxfTghkODqCqdrNSVylarLbfXGmbrmUEZpi2V5PMXiQmAukUQbxAjmRc2D+jv9fS8eRhoqZOp+5z3gmHir6JvdPSXb+o+8SSyMGGpvJklseRbSbXCefZB3n4gP6MLISkxdvilAKWtM54RdU3ef/HYieeC7tZWTyeAhGVbRBSQAQlYNT35HmO3kesvfGcO+v/9JTaJvyZcEPrHdLWFO5RO0szs52x8voHOZIcmR7G2pNNp3go14G2eESBQ98=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 012bfdb0-6dfd-4afc-7d53-08ddfb6272a3
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 Sep 2025 12:04:00.7316
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: zjGcbdmX4e74LznTfUWL/+OuzNGapQMGLKATF/YK3FOan35OFf1tDRrpwPlSd7tVUGmhw6kS+E8Y+/jXFQEGQuRvagCSunrR8LA4Q3uG/K8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB4363
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-24_03,2025-09-22_05,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0 suspectscore=0
 phishscore=0 mlxlogscore=999 mlxscore=0 spamscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509240104
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTIwMDAyNSBTYWx0ZWRfXx/Yt+E66U9Ey
 YUppLrJGSmZjk0VS/d0UWTHXkqxOwXJwZVZdvf4dOT0Mc+MIQJFvEFP9F6IQ09GT0hKD7NE1hur
 ku/AFVw9NYQ2m8MFn2WZv4YMQk8FeDMXpv3a1yaRY71sZNz6Y6o8In9cE9wAM6U/jQVALrrmkX0
 /gxbj7NNqkCXN8cKD4DUracqEa5wwAh+/46heIZj47fAIADh+cl62GM7m31AYpVDNgT5xXSlzTg
 +jv3KrxRZ2AWiXCxCYcK5jJNQJ7Olf08BtrOmFo0jMfdTc0FdRZcdNgCqGO2tge1KNU4QiraoV8
 efB2t+mD2hI010fNo7FoqWXzkw8ZIlK15QyCJsP3qXbyzZ6JU8qDZ0F7xcLuPfQSFOY6inDIFt6
 2l+HnUnA
X-Authority-Analysis: v=2.4 cv=UPPdHDfy c=1 sm=1 tr=0 ts=68d3de37 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=VnNF1IyMAAAA:8 a=pa9L9dGALShiNK9x7aUA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: yIW8VasfJ0oYnwQaVnZHEvcEz7_JaR8u
X-Proofpoint-ORIG-GUID: yIW8VasfJ0oYnwQaVnZHEvcEz7_JaR8u
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=hZfPQbxb;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=jdoZtQ9c;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Tue, Sep 23, 2025 at 02:17:04PM -0700, Andrew Morton wrote:
> On Tue, 23 Sep 2025 13:52:09 +0200 Sumanth Korikkar <sumanthk@linux.ibm.com> wrote:
>
> > > --- a/fs/hugetlbfs/inode.c
> > > +++ b/fs/hugetlbfs/inode.c
> > > @@ -96,8 +96,15 @@ static const struct fs_parameter_spec hugetlb_fs_parameters[] = {
> > >  #define PGOFF_LOFFT_MAX \
> > >  	(((1UL << (PAGE_SHIFT + 1)) - 1) <<  (BITS_PER_LONG - (PAGE_SHIFT + 1)))
> > >
> > > -static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
> > > +static int hugetlb_file_mmap_prepare_success(const struct vm_area_struct *vma)
> > >  {
> > > +	/* Unfortunate we have to reassign vma->vm_private_data. */
> > > +	return hugetlb_vma_lock_alloc((struct vm_area_struct *)vma);
> > > +}
> >
> > Hi Lorenzo,
> >
> > The following tests causes the kernel to enter a blocked state,
> > suggesting an issue related to locking order. I was able to reproduce
> > this behavior in certain test runs.
>
> Thanks.  I pulled this series out of mm.git's mm-stable branch, put it
> back into mm-unstable.

I'm at a conference right now and after that I'm on leave for a couple weeks,
returning on first week of 6.18-rc1, so I think best to delay this series for a
cycle so I can properly dig in here and determine best way forward then :)

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ff0ff4ef-bb6f-4a43-a2d8-35ab0f18dd09%40lucifer.local.
