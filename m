Return-Path: <kasan-dev+bncBCN77QHK3UIBBWUTUDDAMGQELYAZ4KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id BF70AB57B62
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 14:43:10 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2621fab9befsf17091695ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 05:43:10 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757940187; cv=pass;
        d=google.com; s=arc-20240605;
        b=h2B7hwbtr4C9FSgD8agKBk+bdKnBohM11rHt1J7g8sMqWe4/LVALWkcO0f1M82KdRl
         Zaw3HOPBNxQFZodjbFUSamrW2cfhKo2xafreO4gsLoNmWf88DkvbG/JntGRlRaKDfIoG
         j9xhsXVtvbbMMgZ7bS3xpnCyM9JZcLRAFxkuT1NhY/ZKyQBABEimEwu5Dw/yXQjOosxr
         +gy8PfDlHkHZO/6GOPiyNQ3T/wM7gsQs1ym16yPqdzCwYjFWf9RJn/nEEOJ/udNBIrj2
         0U5YQdJZXDrfhr0ZwVVFtWhMOXuFPh0MD0dgiacOsDcDYqlgZdtY4pOhzLtVCKNDBMOC
         lS0w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ioq0lnE2YWtWKFu8YnXcx3NPJImOI7YrWXz3ABdB4uk=;
        fh=PSYEn3dJ0ViG/0VaiTLAtkwgcxSdf3QTr6JAAXyBDfE=;
        b=h+iYUpiYZ036fP2qvlMWboNtVP03BiTAPSbXov+lIm3CaoBqLEVXEDHA3+VhLjFFkv
         5KIcK7S7bFGM2JY8MeAMsFXENF7mLJHey4yUIf1zKtpx8vFfsIlBIMTnz0mkGCxReEgo
         FnYufK629pxd1DNb1Iza3VI6YMBIKT718kV4B/28MOYPGRQq0dVqjchTc6/BXsTXwY42
         3oa9GMjx95k3WxWroxm9Rb54SCieCqXkQz9TuUZimaJRoutc1Tspo/Pq4tq1bZLf+GId
         0gR9KxuGZJ612EgU+gAuZrwdzjqMdfkTiCvN86hDEHWQQkdxvQhcnaj8B04qvjUnnTnQ
         JdNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=GfyE2UD1;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c101::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757940187; x=1758544987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ioq0lnE2YWtWKFu8YnXcx3NPJImOI7YrWXz3ABdB4uk=;
        b=Q0lfM3KUp0lFKoWkMcMWTTpUrrYHxDFs2vz93MjFs0iTSUdxiBTLEnSY78gpWcbBEc
         pOQIRkrNRiMuTTkGsIOHEYtHRlj3AaRRTyTdMeLMM7Yfoo58haHCRnDRzd84LCbaLdQU
         izTLR+eIFL10z1LnRBoVH6TBKblknqz4EiY1wi5Id8PPAVUuFWcLwyJu3/FARcu3aqpb
         tSS2Tp3RVxK5bocwaWBw7dsHTC08olFhe/VEwSmUgyB5nDs0j1iV3dLXid8xLKemaDY6
         pZ/sVTV/z4xb9nUbZ1t9c1rMnCfTqV2hMdPWPbD7IHMCuzpzBbp37cfntAsHO9NhSRx6
         DZfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757940187; x=1758544987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ioq0lnE2YWtWKFu8YnXcx3NPJImOI7YrWXz3ABdB4uk=;
        b=EvDQ6SMBHnTrG4RvDKHfVuNx/YCAbbnpek/qpfJpAMc2/8ymxxyKhAFxlVeJuoq7AR
         Y3LqaPUbYulVm+7dcH58fKEdYkw5Kkrqua7PTUWOL9vJpz2nscqIv3YkzT05t4hIqe5Y
         yQionsmZKHjhPxFhNKBtckEHhC4GB11etIrL2Liyfvmg3KGEnLiInWEjrkvbnOdf9qeU
         4gIGqc4MI5im5gW1xDpTsob0Ib9ax30E4f6PAj19yBC74KenJT1DuSS0mHoo8ENFTqi/
         eYRM3dYPwTjEEPdNazg2891WHAUJsvVGWlYTm/88pzdrdPoiBgEaVewWuGJBwX3Mb6MW
         GAVA==
X-Forwarded-Encrypted: i=3; AJvYcCWfNy2rv9ayoYqqkAxVhiTutoIDbWW6vEZUKS9SzJRxvGi+iwL4rtp3JMPLebs9Do0T+wWjKw==@lfdr.de
X-Gm-Message-State: AOJu0YyO7Dbm5YCglSBiLiN1nfys7lvcmW1XWy3jxCHWJB7M1cElKnQ/
	imMroW+bH7xSQ2UpDsIkS1Smz3P8+KTikPevcmtz7DYX230sZ0tFCddB
X-Google-Smtp-Source: AGHT+IE4DnrjqJvORNJLVbtUA4JmCMNDZaZI1NEv8n+RDifybWg8SdsFgkBYZd2cxhbst1l/wNo1fQ==
X-Received: by 2002:a17:903:1b67:b0:24c:a9c6:d193 with SMTP id d9443c01a7336-25d25483a5amr155495345ad.18.1757940187286;
        Mon, 15 Sep 2025 05:43:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4UX7i7zqpZwOLIlWshfPLczNEVRDMYAvzYQbwJItILmQ==
Received: by 2002:a17:90b:5745:b0:32d:d5f7:68c5 with SMTP id
 98e67ed59e1d1-32dd5f76aa3ls3402069a91.0.-pod-prod-01-us; Mon, 15 Sep 2025
 05:43:05 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVD47N0o5PEnjIV/y/EbfSNpWe5lPVtv8VjbPqM/gjS2CfYEjAHwQknvC7BhJyv9yKaf1w2xida+r0=@googlegroups.com
X-Received: by 2002:a17:90a:fc4e:b0:32e:3686:830e with SMTP id 98e67ed59e1d1-32e368684bfmr6007478a91.23.1757940185646;
        Mon, 15 Sep 2025 05:43:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757940185; cv=pass;
        d=google.com; s=arc-20240605;
        b=JW4zc6XYXf6JqmFGBbp2e9RYN8ZetQacV7YmMZnZ7wPZF4T2DA75djVj8k2CKLS4kF
         ZJl69UC0ukbfgEJGpiYW7zYxaHSrDik+kDlEdr3iosZHtNSwPu09Mcfggu0/bTkVtFuj
         5BJQVjAEGxBrppIH1p/Zvr9bVsO/zhtVvTE4Aj2fJgzPntVcWfaLpJMPVmG7Q6VlXOKi
         0/J4XhDrZh/CAOlJjVj5knd+4Jl37aCQ7hBKAclAGUvdBMgk/2d0JnX1JEQi/7/LFQUe
         nlcMlcL3sLJPfJFJqDcCj7jfbf0B+Q32WSUr6eFd2KQNHhH8cYTK3RGaZMxXjUrZ6aAU
         +8MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5ohlcgjMwlPGLbA0CUY5UdnvTO4QqpmsXQ8z+4+DxPI=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=GuXsv0iTDytXgFaLvPslT0fS+FbmMGiyMHeY9PgEyJLZ/+LmmJAVHCB6yueHazFUye
         huPPrr4Wft9G4HzrTyDiI3NSUy5qZDlM+/N1dQkUHzYSaftuMeUad/LzN18wh1V69vkV
         PzVdxXVquslOZQWW6VuAymS/UAVQ2s6HD6+rqnvNpBh4wiTQdr8U5L4IKF3q7G+DcpdG
         PeMbL+g4YV7XZQ/Sba86BGwlhA5lxTzR5/ttAQhRdLVDppuQiI3EgwZiXJfy6yp8Vkfm
         UykdH0f7HYB0JWO2Q6a7gFeEv1vyc2xxcWi/qV5/Y3IlHKs8isbs8UI+bh8s3u6nx9Yh
         5rBw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=GfyE2UD1;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c101::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from BL0PR03CU003.outbound.protection.outlook.com (mail-eastusazlp170120007.outbound.protection.outlook.com. [2a01:111:f403:c101::7])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32e1212322esi93181a91.1.2025.09.15.05.43.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Sep 2025 05:43:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c101::7 as permitted sender) client-ip=2a01:111:f403:c101::7;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=pR7jGD5VQnZyjw5oIRcFhS5gDbhMafpokwhWVfOrNFr/6RkZnXxPVXdevX6JcNXXPiwMeJBlg3TzngI1Ubn9u8iUQ7z9IgxzslxFRq3SX6JGbskR0Wt+X5kax2+Gt46TZCvW3VYB3f1n61PH7kjIk2I49XT0VyRfHDrcq1R248P3zHUxoAoFYHRLrVmUUG/ZSo1A3wj7uKlbAp0ZEBRERw64bY+YO0SKNr5ptpDlKfXGR0n0jWLvM8SbOtQqkUry4bm/upMkSR4s4EX5EEruVs2UT7laz5PujPEvUt72i10HKo6kvH5Z77sG/GFoiqXNKl9/SmCkmDRXZoY9/Nodag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5ohlcgjMwlPGLbA0CUY5UdnvTO4QqpmsXQ8z+4+DxPI=;
 b=Eeqc32uVtYdCGbzaTdrWyUoSwmCDaFsoYMKaTm8a6giV9EOhmI35GVxMl6tXMS35q4X40liQbjYkYhNyUucbAnPuOyN5+09UZYrgmZBgP7gstPkY1CZH+Gyz1x3jJCV4FaC9fUBtlOE5caC7VxoVZM/LojJtYeRxdOc+3N0Dgje3k9DXtPaZM6CTFUY1nH63NFyZ/ap0wyuG3Bc4jJWypJE2wUcVXobH/H3gYYiclu4uUkCdvQ+8ZCgzP1gZSPvS8lKlB6r72yfap/tYxKm3zHg90pCLMIqs6V/oGCVjp80IfyVwnWgWEB4k8xFZ0407cpehC9tUnvqsuXZ3MV6eDw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by SJ0PR12MB6688.namprd12.prod.outlook.com (2603:10b6:a03:47d::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Mon, 15 Sep
 2025 12:43:01 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 12:43:01 +0000
Date: Mon, 15 Sep 2025 09:42:59 -0300
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
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <20250915124259.GF1024672@nvidia.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121112.GC1024672@nvidia.com>
 <77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c@lucifer.local>
X-ClientProxiedBy: YT4PR01CA0402.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:108::14) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|SJ0PR12MB6688:EE_
X-MS-Office365-Filtering-Correlation-Id: 42b53a64-026a-480a-11a4-08ddf45567cc
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?sO+0aRI8RF5E58QKySfGcP9rblmVAJnVToMQWH7P2RgYhbMUamsORmdQNvT2?=
 =?us-ascii?Q?4hVGV6Fe8VMp9+5bry894eXhYKoD1e13Ke4krKmqJu502FkzPzn8nOBFvGtu?=
 =?us-ascii?Q?RNFhml/Dvk8IbNVHIMGTgW5q6n97z1YmrvDw8tyuA3Rjv/PFJb2dit5Qw3/v?=
 =?us-ascii?Q?h+iv2zuRUjfI2HKtXxF2myowN129A5nwzPKvGQMhqI7UH7JNNg9HantiAkgG?=
 =?us-ascii?Q?85cRSeEpLozDBCahfEbOyKCMB4sSS4XNCnxuHr5AIVsr623Fp6J82VBAjAUo?=
 =?us-ascii?Q?CroL2JdK4o2rdiUABeJQFAXPPt/Fjv1KX9sjg9gxUqnlCuh8tcwoTHvKjXkn?=
 =?us-ascii?Q?y8POQl7ggi51dgLCqiuEkIQOMmjlQiPUCsp/iUIIQ6hQXY51f4ZJu+5Lvcpd?=
 =?us-ascii?Q?pjPpLtXV4V0i5BOnNA4lZXUuonJtriokF2IcwY/LNUniQGvAjW6ngqlfac6l?=
 =?us-ascii?Q?Pf4SFqPbClChMDVI6O+ahaflpaO9H1X25hKqseS/bYVfOCKMDb5yb6HYTa3m?=
 =?us-ascii?Q?IisTBnIhzzBBe7a3K+mQ4SDMlK3875gEWBicjOg7rNcbEMGQULyLCmTc3HGf?=
 =?us-ascii?Q?l6zhTU2l0Yr8fG4WEgSDdax5suBtBaAF7ecfXyiakYfT6UKxiWmoybpt+M6j?=
 =?us-ascii?Q?vjoJ5uL4s1DVLbguIjnGmk8v3HQfCnSv6pQ0GelJWJduheLWO04ZC/VVNsaI?=
 =?us-ascii?Q?5jGR8iXHJVJ7i2z17CpvZrOZOTqD65zhwYnVuOf63FuYNaH/XY7BpRgjyA08?=
 =?us-ascii?Q?k84YSL/l8VhBNV7QMHsMkAGsos+sG3JBnzxRRWXzy1ESOgTrMyj1Shqua0uP?=
 =?us-ascii?Q?pP6O8qMr6ndlSQJNw+MuhKI39mJ9hR+wDH/AKQ8L/nzMBpwQRRdBCNZWbzKL?=
 =?us-ascii?Q?T56Q29Ey+jKQQAKlOTd747y118vnv96O36D3wmq+H1/k+B8QfEFShDTN4lj3?=
 =?us-ascii?Q?uj5Dco6nVX3a0EK4rw88BRun/FlAJK1Npg689UQeTLxfXEMa2R1kShoMwX6b?=
 =?us-ascii?Q?Auv78JqnBrCoPPS6VYERG6cL0YJ0EOu8z6QW4ZBLwLjEaMIFmYfav6qUpsVR?=
 =?us-ascii?Q?5c2bSws0vf7PY0BjHzxliGliYDFMe23rjltQnQ3BcLPQ5mxK1JzyYFUTIpiR?=
 =?us-ascii?Q?zNivisaLb2psgQUFLhLANtP7/7tJLF5WOPtiL2/quwrjQwiOYzDLfy8khgMH?=
 =?us-ascii?Q?swSjjmfgXF2OysqdHycMq2veOuxb692FusVbVF/oOZL5JbuWDRLdfnLeTihM?=
 =?us-ascii?Q?6a4S1yQuWc7IzcOiWYbuKSASxEUqMssSP11Y8SKqJkxQQeV7yx1GFDgDqCVW?=
 =?us-ascii?Q?hzAJzFGDsk85yMPxwznxc7PPz2vn66e74hk+2xBYlH6V4maYoZxhCi+LVaIB?=
 =?us-ascii?Q?g+Wu7FmSqq+oooUr4+J1+LNUscnOD9o7NrvCk0O80qa6YBjrSF96kPdNIElr?=
 =?us-ascii?Q?zlw68AQKqR0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?BBAt10kH+tWfob6BKdTgTRP451+49KXe9TmfP/ryYA3h1XJdSeAJ7b5s/2Gr?=
 =?us-ascii?Q?QGxCitj26rNqrLm6MBIFnWwj5/KpCrTRTGunvzJUgnjKenYtnEp0LBzr/Wy4?=
 =?us-ascii?Q?ZxwSaHtGXXYdOE0jxuzprbSMn1VImi1d9rC1dkmx12eDXLhj/kAbxW4LemFb?=
 =?us-ascii?Q?k1uRZ0l8IRPe1Yl4kChd9jrjQZuCPewV2Po2XAv2qmH1j5bPvOheuWJ9h1TF?=
 =?us-ascii?Q?RTRAGuSb7sAMbLR4EJpYXl9qqVOPT/MCcKJhlvSh00+sXYpBIXpeqnxzUMiE?=
 =?us-ascii?Q?cVQxBXTx5xpcd4jofLhTDfzkKG+d1X5xmLQbg57Jmp24AiXBRlnpQ4dZj29R?=
 =?us-ascii?Q?xP6SdBY9N0TCqtRCClAl731hMgKTUDz+M0wEDftfJI03PJFR1bmN0BD2iizf?=
 =?us-ascii?Q?7KLtjRMjYSmOT0NT0BcKyU3km58kvQ6myyPq1j4JyNZrToYpKvltWnrwSCr0?=
 =?us-ascii?Q?F/P4LEUBXY/KF6O4konJQVAxDCFnwvgl0kYjY3901jnb1sRynhAfR8u3kPA7?=
 =?us-ascii?Q?vUEvoR3rGADRix0CJoOqTeMJbMrWBjUJtv+xsz1xmKb/h+ioifDwaUjfhjU7?=
 =?us-ascii?Q?/oq9Q52TS+DNYa/IXqa8F44a9kcPQ2gHbvE8XFxfCpJzVZoiO6NZnb6uO+Lt?=
 =?us-ascii?Q?gxC/sEOVk9lh8WDIpG75kiA1PHn4CIbl6tciBFkY79OMzu5HaW6uL5wh4dzn?=
 =?us-ascii?Q?cY0T8qkSyYXVcR6iMTxIJeWOWIg33TzikEyJJj+DC0+QlbqBB6Lu1oH6o5zQ?=
 =?us-ascii?Q?DiFFBDqjGn38eciMiMVu6mqkSBX4wF4kAWssrQc6oStqfG5FSgLziEgk7ETw?=
 =?us-ascii?Q?eyi16ITzUraQVM8U+wZ9pazofspZjUVrMe6Rb7E2Rs5Jhgy67y0yW2U5wdvw?=
 =?us-ascii?Q?5x8FVKOP+7RBfAVO6xe7CV7zezXrMu1aSghwv+Na7kFJS3/yC9lgMEoQfppv?=
 =?us-ascii?Q?EHi8Ep541WvJ9w5WinP309soLvEW5p0XplG6UeiqJ0XZq9yBJGKNrWEBU8+j?=
 =?us-ascii?Q?xJbAK2g+LCwMSz/q7GG4h8TBaSv8M3M9oLrCHCoxvmyi0dW7djb2TY+QU8cJ?=
 =?us-ascii?Q?skNWlO2/aie1ISx5hiMucb8Ir3Q+qCDBgRB47IRmiY9EM7LjjUojXgP5gz8e?=
 =?us-ascii?Q?gGMGh05d2DzwNMUqE+cGTXI3akqvdn0Z06maSA+iJTDJpy9IRW23bXbp29D/?=
 =?us-ascii?Q?NhXYfKDbnkFap8CnKM7PdDqPVQQ0kqNCCab3lY+neUbfHN57qHoXQiXb1ZO8?=
 =?us-ascii?Q?BOW0OIqFaRK5kCrIQ8BGpY4MIkfJac5T71Wx/PVdCtHn5TDmqUhVPhnRb/1Y?=
 =?us-ascii?Q?SuTXO3dhlEalK2LetiMyLvix9hWBacFvp8Nm8ZF13fD5h/MZ7egAceAzg4ma?=
 =?us-ascii?Q?KSQ4HBblKkEcXla88k3Gwmq/AaQpjITCfIrhfRfmWF81/2TKSZVUPF7A1bSi?=
 =?us-ascii?Q?j2oXpzTdB0/t8a2fQrhMQg6q9EgDTDkr/dFBjGd2uFQ7et7iE4vXr/Cylck4?=
 =?us-ascii?Q?fnR0nrz1r3yy1hIy9qzbqLAqvNwdMMDjdlfalSf9lERNQ/+Lx5djtTiRR8rh?=
 =?us-ascii?Q?HsDybNinu6XY/lSHsGQ=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 42b53a64-026a-480a-11a4-08ddf45567cc
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 12:43:00.9844
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: JS1pkbfkkyjH+vyQuj9eiMlbzo7knWphYkn1+RNTWxsr2kKTKllQ2Qv0GgnxArOq
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR12MB6688
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=GfyE2UD1;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c101::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 15, 2025 at 01:23:30PM +0100, Lorenzo Stoakes wrote:
> On Mon, Sep 15, 2025 at 09:11:12AM -0300, Jason Gunthorpe wrote:
> > On Wed, Sep 10, 2025 at 09:22:03PM +0100, Lorenzo Stoakes wrote:
> > > +static inline void mmap_action_remap(struct mmap_action *action,
> > > +		unsigned long addr, unsigned long pfn, unsigned long size,
> > > +		pgprot_t pgprot)
> > > +{
> > > +	action->type = MMAP_REMAP_PFN;
> > > +
> > > +	action->remap.addr = addr;
> > > +	action->remap.pfn = pfn;
> > > +	action->remap.size = size;
> > > +	action->remap.pgprot = pgprot;
> > > +}
> >
> > These helpers drivers are supposed to call really should have kdocs.
> >
> > Especially since 'addr' is sort of ambigous.
> 
> OK.
> 
> >
> > And I'm wondering why they don't take in the vm_area_desc? Eg shouldn't
> > we be strongly discouraging using anything other than
> > vma->vm_page_prot as the last argument?
> 
> I need to abstract desc from action so custom handlers can perform
> sub-actions. It's unfortunate but there we go.

Why? I don't see this as required

Just mark the functions as manipulating the action using the 'action'
in the fuction name.

> > I'd probably also have a small helper wrapper for the very common case
> > of whole vma:
> >
> > /* Fill the entire VMA with pfns starting at pfn. Caller must have
> >  * already checked desc has an appropriate size */
> > mmap_action_remap_full(struct vm_area_desc *desc, unsigned long pfn)
> 
> See above re: desc vs. action.

Yet, this is the API most places actually want.
 
> It'd be hard to know how to get the context right that'd need to be supplied to
> the callback.
> 
> In kcov's case it'd be kcov->area + an offset.

Just use pgoff
 
> So we'd need an offset parameter, the struct file *, whatever else to be
> passed.

Yes
 
> And then we'll find a driver where that doesn't work and we're screwed.

Bah, you keep saying that but we also may never even find one.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250915124259.GF1024672%40nvidia.com.
