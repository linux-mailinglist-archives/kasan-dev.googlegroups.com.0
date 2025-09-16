Return-Path: <kasan-dev+bncBCN77QHK3UIBBYVJU3DAMGQE2YERMWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DADDB59E28
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 18:48:36 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-32eaa47c7c8sf764642a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 09:48:36 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758041314; cv=pass;
        d=google.com; s=arc-20240605;
        b=M4lkiSbYbVXQapP6AwprEGmXhqKg7M2szG5qa2vjLi7cYUciL0Dvk96CayLfue9cVk
         qo/20Sr59oLHr5AHlK8u6FzsKSI7SMJJSpxJoOMg2HAFLNcAFQxG5E8Eu8buN5J2IfjM
         cILEJAF8wQr8aBt9oqjknXT6EI36ZxkJfzoJo/d7WIvE8YKmdRsRGFfKAQQtgng/0Ytw
         uu0c9ELb3jIatG1x+5uxXJ06cP7u6N0mHYVH3BXKykvURq7ldMwJSuSHRF3KH/WZNDA7
         sQSflH4mLx7qKtxuJ93nGoxUf3V0X/N0tUf4/fKxBu7yJb+TCFg0nQTW274juqjXOj1g
         KDKw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=JDL/ViZBQWDDXQNgUjWKZeu557hstOtzYMno/IaFDSo=;
        fh=HPTXcXb+StpDHH71K2VNqJ4314/MEQshkbTky6b+nFw=;
        b=AuxX//soB2PKePWM0CJmYfrwsY1RpWbT4YcQHJiWO/6EUPBUiSYixvZC+2/6cX9u9a
         U0MHxZ2UQBBN22zk7QXORRuKjle+gZOOC3A6QmYGrw21QrvmDVZaC06ObRdUkMky6ddD
         lYRqPDjk+mdxAOoo8psuCQKZoo/B8SB3VAiKabh2ZGdea/XZOQfQ5fcHv852J9Jnp1bl
         aRE692AEa4Oa85z00p7XrUhJnjHl9wKtPgQ10ypINSgPPy1FrW2YoQ1Un8FSp3aIzUmO
         W7NLeauvCKiqOmGEmbBT8+3Jao25nIUQNgRYCyQ0PjsWVLKk1tdWZNMgzWf5yoY7AI39
         TW2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="KiuzhT/8";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c107::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758041314; x=1758646114; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=JDL/ViZBQWDDXQNgUjWKZeu557hstOtzYMno/IaFDSo=;
        b=QTD3GoGmirTM19E/71cI+XNGl31u6A8eiCykYUM5h9jZFSCMx9bWVNfjPenOOjKDMd
         RFdmMvFLt82tvFnOx5ncQsJrRa+Vt6fA3cnU8DWfFiiljhMFCIZNfOCoGRRpS1Q3lnYj
         YZt76c1DaokmYh4kG0q2BCMp7nQyH030wdMvaJdQZNx08izDMNMUDRiu4+5jCBLugcSQ
         qpdSJpEpeazY1U6A7GpYDjKCAg1yZlMHM7kdEV9rLNtVRvy+uoMFfI4Z8SFdvd44iPwa
         3ZOhKStXZBjF9nKwG0W/kWIRjFpaAefzyH8G185K1Un1opaR2tTx9tvD5e9zKZKIToCL
         4UAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758041314; x=1758646114;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JDL/ViZBQWDDXQNgUjWKZeu557hstOtzYMno/IaFDSo=;
        b=ZspuPuZU2z9lx0+Di6Z/vRUoF3bkILkIts9nY79sSkD/2JRp2VYSBMPIMw29Si2w/8
         XQgs3+P7XxKMmbU7rvIqK+7rEVJWhf+skB3qdzCDAUduPiNScCd9PhN6tmQrEClEuHnu
         euusSDifqbYlFjtx5XAK+JgvHMFWeJyZt0qenKY9dNR1xWT7HjynHyqaNzxXSSAp/sZN
         AtQDXLj7yeOwbUE997BfPmxRA/QnCbNkHPRniA39rqNU3L2BIkHrwKnsBqQAIGmBTXhV
         ywvjciCx2/XRpbYHPW7L1JeTwGbRzWWAEUbhLndhye4/ab8Ik2tMjF2DG06dkMRFfDoZ
         LeiA==
X-Forwarded-Encrypted: i=3; AJvYcCVzhMdtSAfcm0EOUpH4YMka0A4HLBickQUYpjYGjngBMSz63qNUS2AJO6hWJsPX4fokXPHzKQ==@lfdr.de
X-Gm-Message-State: AOJu0YyEpjFX5UqMPScx4esI9uxb+wWpCmmAnqcVVljhrbnyS0oVVvmp
	HzsMEGtjjvR+mw/+XhKmLmE8w4w8d4SU1CRN3s518DT/f2yhe2k03eE4
X-Google-Smtp-Source: AGHT+IHxzkvbNaU2VnTcIXJoSUrSb/Um/TckJgiomiYgHOwPxao9sShHxnmKSXcQt2RFSV0L5PKefQ==
X-Received: by 2002:a17:90b:540c:b0:32e:f1c:e778 with SMTP id 98e67ed59e1d1-32e0f1ce9ddmr15327802a91.3.1758041314492;
        Tue, 16 Sep 2025 09:48:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6xX7uov/JZmB3g/s1vyUIh8XNKRBnqeeVvVxNf703YqA==
Received: by 2002:a17:90b:5745:b0:32d:d5f7:68c5 with SMTP id
 98e67ed59e1d1-32dd5f76aa3ls4850631a91.0.-pod-prod-01-us; Tue, 16 Sep 2025
 09:48:33 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU5ZR5E2L4gTrdH9huZ3u56xdm45NCwsBOSyVlUmaVpj+UqQsxH1NS9N3yF7GugrA2Op6Yz0UVc3nk=@googlegroups.com
X-Received: by 2002:a17:90b:48c2:b0:32e:96b1:fb70 with SMTP id 98e67ed59e1d1-32e96b1ff8amr6802582a91.12.1758041313090;
        Tue, 16 Sep 2025 09:48:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758041313; cv=pass;
        d=google.com; s=arc-20240605;
        b=N8FS9/3mac+qNMKPAmIT12lON1g2lz8ZkRbmbgalwhIWFG3XR4Fnoxnw1Q1WTlH0PM
         RDIdAcFZ5jVS6R3U0PBB/6Zw7WTLLi0LAtNN7mksfMjIcHXpeOCdNTo1k3Ke5epkhiO9
         3879JixlLiOe+DQOaQbf17iBfpHtCOmBXvszz5JYVytUU0kA1/Ap/DX5+1u0i2yw3j/Q
         T6bvsbhbqxkCDM4wetnj2f185xWgM0rgb2R/rGyDhEaRLRCxShfDr5wiiqnJ5EVy3Vok
         PSTWYafRhMC0aRwJfdBli82vhqTyDfB/+9HaODKiY1hzRGv1VB7Bf8GLOlMF7I/g4KlO
         phlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jJOpMhAEQgYILl7N5a8CSSbKFU1PshJgODTRh+eGBmY=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=hGCGZ+/TAtglirwhk8B6uL/bD2Rb9ZWWXb1tfcymrlv5QsQOlQgAPfzg1OXecc8uJ4
         bMqXLF1fLlYeYJ5PwjzsX4xr3asqsOS63K/12uNLJEzgpe+rKFxeRtnr9GeqANKwlRlK
         1EgJvs1XJW3dF1CLkWtuJe1QHNulln9DhV7J2Jtx6m7aILtjBN7qWyuBiWKidF0nnYRj
         wUp7dhEM+Xt4Prx14Q9yz9nZLZaKlZ3zBM2+35jn6GihF99W/cbrrF4yhOmE47XlXmxl
         EWzdRAa7EzGcj8CY7D2jxGWRzUe8S+/Yl67XwYgfcuhOdkIPB07lIjtsUdJ0VD/pDge4
         493w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="KiuzhT/8";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c107::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from PH8PR06CU001.outbound.protection.outlook.com (mail-westus3azlp170120001.outbound.protection.outlook.com. [2a01:111:f403:c107::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32ed257bb9fsi4792a91.0.2025.09.16.09.48.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 09:48:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c107::1 as permitted sender) client-ip=2a01:111:f403:c107::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=qm7srhq9bvmlQEFLB25kzJ3Qy4mRsPJoRZp6pYOX5SWn4VmH4t211rDkJWh359T0qE6sXe9qBN8FCkrcFOfEsnuSITSWfBWatAKgZNJFtPHaYqBRuh9lyfEHxjalJ4zHSyLou2WGjAsN0apd5Y3Kj8jOJ1YaNItkygbVWjsJP89SEPRkL79phyrQOGFsOqIgRCVDI+u4JsdlRQL4RbLjxiloFNmzXQIknbSrm62wUL0H+QLDJPHFL3Gdvf3Bb5QLH2RnK7G+6/IeVDLju2u86y1ketob4sr9xs5JAqSZ+GKkkCPIgo13gXGNmR/1kBs1woeTM28b8Pb5Po5V7244ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=jJOpMhAEQgYILl7N5a8CSSbKFU1PshJgODTRh+eGBmY=;
 b=VqpmXRgC4j8Yb71vO1bc+5LTJ866xYTop3/9y8x8vucH4PpovangczPQNmljrZwg4MRbw9xbYgD6hGiQ+F0yrqCvb0FMn59QcW+kFR06k7zqSTjzZ5paozUhqycx8WcNUXD8qp+coA25rerY1yxapt8k5j4q0DY8ukfyW6pEXOmD4iZRAoy3oV2Im143SxFGHRYdluTBYEIMiwLY17WOB5q1fzPpUh1r+gtmPMZiZ2hMozxuBGzD+7QCFMtHc4ctg/XMa55Y1IyACIBn9kaytcU/z3LIx93sygkmWDmUYZZdCuxSYuYIjcGZ/t9svaoHEZfFIZg/mRCO9fCNc9LJJQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CH3PR12MB8257.namprd12.prod.outlook.com (2603:10b6:610:121::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.18; Tue, 16 Sep
 2025 16:48:30 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 16:48:30 +0000
Date: Tue, 16 Sep 2025 13:48:28 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	"David S . Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
	Arnd Bergmann <arnd@arndb.de>,
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
	Dave Martin <Dave.Martin@arm.com>,
	James Morse <james.morse@arm.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	"Liam R . Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Hugh Dickins <hughd@google.com>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
	sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
	linux-cxl@vger.kernel.org, linux-mm@kvack.org,
	ntfs3@lists.linux.dev, kexec@lists.infradead.org,
	kasan-dev@googlegroups.com, iommu@lists.linux.dev,
	Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v3 05/13] mm/vma: rename __mmap_prepare() function to
 avoid confusion
Message-ID: <20250916164828.GN1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <3063484588ffc8a74cca35e1f0c16f6f3d458259.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3063484588ffc8a74cca35e1f0c16f6f3d458259.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: BN9PR03CA0132.namprd03.prod.outlook.com
 (2603:10b6:408:fe::17) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CH3PR12MB8257:EE_
X-MS-Office365-Filtering-Correlation-Id: d61a45e2-8d55-4647-e77a-08ddf540dd6a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?8RWKJpYSrLCKjmnnPUO7QpEx9qzXPTOStt6AZhaiOW0y5kVo9v7T2kPlBkdv?=
 =?us-ascii?Q?X/6WLa/9S/UAxKMPUDE/axAPVJ5WtY+lkDa4VkK5MioDErbyS+2JXLUAM9Zr?=
 =?us-ascii?Q?gSCUXU6xMVdIcFdi4lHxJDHZL61j1kJ9oL/S+mMw6pz2Afs0I3AcNmdHb8/v?=
 =?us-ascii?Q?e9fJ1QMGRZ8x8viGEvllnomQfXJpduamUcjEptcaTLYxzxfws5f4EVw1KGFP?=
 =?us-ascii?Q?D/Exd0Tqmb/3bR13Vc+sdiaUOTlZ+J4jqSTul58Yr6Oi3UWXCzRNmZIQkFYa?=
 =?us-ascii?Q?NZ59Dd06cZHPk33/ZsZLw5k49qUaSWXAinp8RDKLTR9OGqYNMBLlHhL36Jyv?=
 =?us-ascii?Q?3J9c8Cwy1+7ubjkb2gzPGRc/GnABk0di8z+VogaLvpT/DlaXSE1+6DGA9Rj1?=
 =?us-ascii?Q?AE3LDIEVLGoEiOjO7RxkJipEE6gxhI0p7F8xNEevlp7hV/KDtQ9GFsC1q4Jv?=
 =?us-ascii?Q?bB2ly10MIuycDEzXqi/WbOLZMStH1V8dJcOtI9ANtN7w7M5BKx6rqdGueULT?=
 =?us-ascii?Q?MIdwK/YH/Rc9FtZcI28rmWHqDpnuQrDuR3HdgEI0VhwHGWDQss51K2vGWX30?=
 =?us-ascii?Q?Hbu4Pb/0HVToDj2+4tSkgpefkOxX490k4SR9S0g5f3gggXp07g73kf7ZhdSg?=
 =?us-ascii?Q?rjvOknxSAy7YHyj70Wpf4J8pZRF1dS0reolH9czf0Ra6qI+xhkCzoMZriThW?=
 =?us-ascii?Q?FxXaBul78GXxFgLCtB88AuaJlKYXStXSSAy63deapvyeM2IlFWQqPs1f9X8l?=
 =?us-ascii?Q?jCnDtiJYS6NQFdtPAjbwHnVBSC2M42xQuBPC0D0SXwdPdVt3BadD1vwYX+j5?=
 =?us-ascii?Q?6H1gJtaOuaqCvUGiH2HbDKX5Dh+M1835VZibHhr43oEeqPIAv/ZjvOCHxLin?=
 =?us-ascii?Q?HL6cKXPcrjDPVpQfIOOx95/kDpinl6Y7J1kBzBv61wHUJP+6y6/kTqj5Q2Mt?=
 =?us-ascii?Q?7qn0G8X6xFmIfprO3ocogXIq0+E0WudUm42xGDFi55OoSY2PaBiUlMQB8VSO?=
 =?us-ascii?Q?175Zo1R5XmPUZhxd5sbg3OYUvjbehCOodPDBjmB+ybmSK7Q7/RIUmjFB2M87?=
 =?us-ascii?Q?ct4+w02ne8fy7ZrgtDmBHdjUA+ocF5c0WiajteEMM/tW0wVVgggwD/12QJ34?=
 =?us-ascii?Q?9pjVjxp0z18O+WqlHxiAdPF5EIUGkijn9vOEZXs0QoGJps0eME443WgenxSh?=
 =?us-ascii?Q?6PNiOGw32WUEf25Q+Vx2IimFWg8H9kJE+2WMrlS9E3Hq0Fom3jcC6wW6xbBt?=
 =?us-ascii?Q?+US0ixCIFPP7pOPkMaJ2RZE/kr3f8uzon01m4YVpE9bJs48pR4H39HaDrOJm?=
 =?us-ascii?Q?fJQT8fhnzRRORng3TDJeiOBZeL2f9PzfnaAY4N4UZVk2je73k8bqt6ZtSgoW?=
 =?us-ascii?Q?anxXJGxH2nbb0M9rhW6TA5Zkd9m2RPFf3dT2RiKX4oy/qPxFazbzd5NZyCjB?=
 =?us-ascii?Q?X5lD466DDzg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Qs4mq42U9P5yoyksAXh++z+0qZ1kS/QpnK73bm1/HHbcHS16/cknuK13jix7?=
 =?us-ascii?Q?KKi0Mi3KpYC71BheZZQoOjewlBnousEo/bRNYijdAMqmBJ+0daelj/whUSi3?=
 =?us-ascii?Q?PTHO+tjRbDGjfBq78QyK/qf0QXdA7FLLncG2cIKUZISawyaVuzCvaUlfq+Im?=
 =?us-ascii?Q?elWwtDBTILKnRZ2SxPrGkZ7qoGZxL/Gzm/MFcIP5JExwCL3wzSoo/RX9VCpv?=
 =?us-ascii?Q?m/tbFE2pz6zzmYiwzJ8RzJ/bfgyPomoTcS+qPIl2Ogk6PE8rA4RNuFsp7sD7?=
 =?us-ascii?Q?x4EncUAL0Pqltf19qfw05o39iHlqzrSSzkftrsmOBqqoINNhspVU7rSGVWIs?=
 =?us-ascii?Q?A0y0Qub2n8Q2EeTs6BjKeB9EMjhjea68HMAkrKNL3dy+MNbYsAJSHQ1apoyV?=
 =?us-ascii?Q?BL9XKzjfxKKwmuvu/1KNYRUHLHN3R4hkjOXDgtNeuEK6Zhd3hlUOwLs/AxIh?=
 =?us-ascii?Q?uhB+9JN9xrcJHrAIZ3gduZuT919LuuufImEsDuYZexrTc/eD7c1YRTEGJcq4?=
 =?us-ascii?Q?06EAJmvJUY4Jjw3aPZ1kXhleiEb2Xt9C7NuAPcce01sYOByP31pMDtm6ETMd?=
 =?us-ascii?Q?FVe1XVXqVqTvs0HLvM19G05aHKPRxsoyWjhKQM8ziLE/578yajYJ6csCZIQp?=
 =?us-ascii?Q?bBm4V2pvFXk7JcAnVck4eF+N+O1z8xP4YzLD0KqfkHd3+yWMhLybM9KEJtsY?=
 =?us-ascii?Q?bY0N+/GIs1Qnh0Ta1MAJJ2OSUYiRldhadGPkqyg9Q3LZM6ILwDxzEnF5gHAL?=
 =?us-ascii?Q?svrFizmaGaCmpYyqiJs+EniYcA1t5a+KDLiU6lsLZbFoZHN3gHdco+cqLDi6?=
 =?us-ascii?Q?prpvjrL/B+NlG46lS2zFoZajID+kb1fkqg+B3Reddq+GI1SbOnwjN/wRqSUS?=
 =?us-ascii?Q?vWxq7kbRDAc59UM3gUysrWftnoeTzDDTTl+s8gAdXQAGxhTQOYTewhR3Vjww?=
 =?us-ascii?Q?BIkNC3TYQIFmJr0D01HoMH3PlLTQavRODxkhEZkpnkPWQEEnlxerc8azmVvL?=
 =?us-ascii?Q?9BQS2p+HZMCKj0qsJV3+EQRD4AgqJe2O+H56Zx5rduZc+64wLWD0Htjur9of?=
 =?us-ascii?Q?8rM4RX5U8ZwMEZY6kThMurLzMij7j1aHM36nMPcEz45zyJIQZBe1ObC6QpPf?=
 =?us-ascii?Q?NBheEVjCfZinhxROy70K4Op3uNz1VUJl/riFA8wg0c/a172wtPj61jXXZrSb?=
 =?us-ascii?Q?CtWPPP39ClBQpJuzGs826c97YcAU347tqDKfgoyFH5kLCgbKyFy8zYJ2+6oJ?=
 =?us-ascii?Q?2CDTpWIz0qgl4ZibklE5oW93rL4EodSKmjneYyA+NAfwOwnuaXPvvikdG65E?=
 =?us-ascii?Q?B4lLH1J6V1KCllxGzIox8SulJWc6Q7NAjeE5q7VNeMI2Zgtp4m2I7sch4Pg1?=
 =?us-ascii?Q?O1TGlYzSBezafwIs2eFipoks5aOt6tE9PF7kn/6HG2A9MftdhPa5ksFwj0/v?=
 =?us-ascii?Q?urZqLglyGBvlWi7PC0anMniFzcwvaLbMofJumfW8/AuLP2a3VmweigBM4Uhq?=
 =?us-ascii?Q?+RO8KTj09iCsg1AOrGjR+7pMBgqmaeOSYw/Y5LMYYHfaHGuaNUqyEs35AkgN?=
 =?us-ascii?Q?HZJ7BwxDQYXb81nXp702CanB68Y14EGyOPP+JaCq?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d61a45e2-8d55-4647-e77a-08ddf540dd6a
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 16:48:29.9628
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Nwp4eaw66L824OfadXyw3gBYlcskT/1LXtQo9n4W1IsVfavE77R46nxxn2WN9RTQ
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR12MB8257
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="KiuzhT/8";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c107::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Jason Gunthorpe <jgg@nvidia.com>
Reply-To: Jason Gunthorpe <jgg@nvidia.com>
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

On Tue, Sep 16, 2025 at 03:11:51PM +0100, Lorenzo Stoakes wrote:
> Now we have the f_op->mmap_prepare() hook, having a static function called
> __mmap_prepare() that has nothing to do with it is confusing, so rename
> the function to __mmap_setup().
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>
> ---
>  mm/vma.c | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916164828.GN1086830%40nvidia.com.
