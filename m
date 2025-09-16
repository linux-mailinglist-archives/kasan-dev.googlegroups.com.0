Return-Path: <kasan-dev+bncBCN77QHK3UIBBKFYU3DAMGQE5CAL5AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EAD2B59F19
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 19:19:38 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-78e45d71f05sf4279686d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 10:19:38 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758043177; cv=pass;
        d=google.com; s=arc-20240605;
        b=C7vLYLNQJFKIxx3RsPJo5iHf1MgB/dZy16tgU+tEU3g36Ch5jmVE+L/aawKzhIBmyz
         bwUomzHgMlYa+O59DQOcy3oU1MQT9J2XT62sXh0nqjQ2bDEIQ1mf1iyRlwcw5Hi1WXZg
         uCP/IZs9qslwO4la1dp9evov5WHNyT6s9LrOCJXfFT6mKmirdfp8EF/v+q2kI+GPOewc
         BhVGLJtjMmoKknqg/IcPkLBQB9YMgGtJTqHfN0mfAL3uwM5D4Iea4VUmMyRK1sc+4YV9
         2BQ3iLmqR1B3x4l1eZdbJoD3QQeW26ftn4bA/jNs8Wp8oYOAlEpR1ZFV2uPOXbgdTJoq
         mIBg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=q/7WDFByAj2NFtLinn+/kF2PcmRjs9Y3lIeIqofdCKA=;
        fh=AHO4rIV5I02+3ZJg9tayDXANZh44wDiHnswwexi+WIk=;
        b=H7NVmfbQSEpfRP7dGCwMSHowdtaF9Y8nrDbvdfruevpS5uHbX0X5D2aIvSuSmcdz26
         SBIgEJEnmJT1yWK85GKUWmGaBZusA5x8gO950InuUN4Do00ITbBurmpSB9s8wrsB416J
         tGxNakTddbKEJveylyNBChfMs6T0SFSFOhx63W6ySWxLg1nSrBvaa0BBsQzbxLlFaJQH
         eTE1408k2ZeNggLOx0qqO9tZSa0KhM7ZI96/RzTG7U5le5jU4zdvrjPrd3gjkArZGdbO
         o5ns/3rGPpTUnz+SisoBXncuAQUdUOS74nuXNgbL8rlE793MKRYHgMM6lu14Nu0Xmrpr
         lJfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=cOwLbzLy;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c007::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758043177; x=1758647977; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=q/7WDFByAj2NFtLinn+/kF2PcmRjs9Y3lIeIqofdCKA=;
        b=UkX2lA3LHm7zolGHz3VL+3fkjwAPabZazGZ8lHtOSNWCsT33amkbC4LvB7nZvZVgHf
         V08/3IdOmTzqslxUtp4Kjt7EqYboNE2tcfddsrxTPag/fUnLOw1lMJpYzIW1fQ07TrJ8
         s5d+4b7KS8refZXu77cmyZ+2d2IX3MY9BzHreF719VmuPDZtZTfJCcsc3xo1QzwfS4Tt
         XgWF+0VoUsL3HHeqcmX2iuT08LSvXYzl8ET9CpI+4GMSKgwu9nzQpoJP8CExYoffyKbL
         qDSRv3MaqRq73jkgtU2Ve2O8Um9ow7XXaVYhj/28EEGc7HRSN93Jjsv2VZVzc7i6WuV1
         EDgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758043177; x=1758647977;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q/7WDFByAj2NFtLinn+/kF2PcmRjs9Y3lIeIqofdCKA=;
        b=nwUOQkahATh8UFAp69rEPkMzeGdtHw6FYwxjCMrIA4xpb0Wmr+8L93EMIhazUdoAI3
         t51AMvcUFZZaBs2WnjVFVKG1xwR9oVy6QynHgXkhGVeyNEzXGXP261tV/uC18RW1g382
         Kw0IlDXVrmkdtX5UhZWb3yQ2mvzRp8U0K6k+Ju5j2af+Z+EuA3TkgftGZl6PVv5dAWzp
         2YAgFuRP05e3ZwI3aYwIGIgUkRV94PO9D8l54+TBEvqjDuOz+m9/LGa/Ane2Y969Cnro
         Ps/4LJYHrm3YXv4NxrgUcIXyS00T/hkK+p37pNDVXBQ/I1qnfWrUNwHi4FxklliQ9okT
         xf5Q==
X-Forwarded-Encrypted: i=3; AJvYcCXZ6oz/u6qW7g6iKCQ5i5T/iCENvTzgOgjUzzs80f2BU3V5K+EvvDXyw1v58nThPBBNKffRNQ==@lfdr.de
X-Gm-Message-State: AOJu0YyT7YI6rXOUnNJwIfUtHBUD5DJV3+mcJ75KCyWl0T7kqYO+etrS
	87y1gwznL7jSzGTZfevDI8lpfFt6uTYF/Nu1lfd4FPNVzMzmALWuxGfy
X-Google-Smtp-Source: AGHT+IERl3ELLFr1mo9csCXdFgsS7r1NYBO+GZjQfqXhv/VrXAcDLYbrWrb+7W+9E0isg2DYaHJK/w==
X-Received: by 2002:a05:6214:2aac:b0:736:514b:b90b with SMTP id 6a1803df08f44-767c377255emr222135826d6.45.1758043177174;
        Tue, 16 Sep 2025 10:19:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6xOMSFclETZOIbfOSxk5auQRnzBS8h8yY6iSyFjI+XZQ==
Received: by 2002:a05:6214:5287:b0:70d:b7e6:85e with SMTP id
 6a1803df08f44-762e5bef220ls97784156d6.2.-pod-prod-01-us; Tue, 16 Sep 2025
 10:19:36 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWtXSWAdCwV3QUXEFyZflbhyjx7WB3wbBxhARJGpV7JQnlPKCK6/tZUAVWzqWoPYqgtHqby5LM+NlA=@googlegroups.com
X-Received: by 2002:a05:6122:17a0:b0:544:7f66:fdf9 with SMTP id 71dfb90a1353d-54a16cd7fb0mr6137508e0c.13.1758043176307;
        Tue, 16 Sep 2025 10:19:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758043176; cv=pass;
        d=google.com; s=arc-20240605;
        b=A8Owx0+caSfOfOyxAnRRk9LzoXgXwjqWzOUgzEc3iN2YKS+8x/9Y0PjASvK+BzzwbS
         gekR4wKh4jwBXC4gRZPZI6O1UDSlsi9AxH4/XEB4hd9f7L53ODBIigTP7blF1OP68zkW
         lzhBb8WwkICpblEKet5GxuBxDbTc+TFqH7EPjCUYU7kcZ74l6wCVyainSCpEhtikIBSo
         zkNbgCb8909d+VqS9n6CG218hPSg6AAsMuiy/ZUBQBgg/2L+YXnSrsNgUZsMFpza68rZ
         gKn3SqYNe1ldJoeI34q7CEUo5aU2MsU5LlaFEr6YpPdVY3u3ppU1zbuFDzScOLOTFDSm
         NHAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ItVKPLLwvprRNFT6X7VAsBvihdfCxXFF9VCA4y3l4f0=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=IfAUPcoVzspKStCagMIFrNDIay1qLwjeD0ufRsnDrxVGXZsVgijZ0/LU6/OHwsk5d8
         TV9siabnXW4OjZ9kqee6kvACryrdxjEVKomYGmVJhVX+VmZ1DLyDg/9MRyCxxTPB+3/W
         CKwc0zPJKj/Jn4dCCkXd7vpfsV1hcKpFQ+yuPb1yC8gQIIGj59Lq3PqAaObKoGy3k3KF
         yxwQcrmaaToRhEw+/vNI9auCy85HUcW11yaaoc6a4Bdp4gRd7cCG/5lwzjEF0fgmlesz
         qMeMqu64VJBcdvMRkZqgsIjiZdKzRNlUoOP0ClBIUxh34lCsaXJFExTflUGABmJtvVFA
         rQ+A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=cOwLbzLy;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c007::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from MW6PR02CU001.outbound.protection.outlook.com (mail-westus2azlp170120002.outbound.protection.outlook.com. [2a01:111:f403:c007::2])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54a1716bc45si550899e0c.3.2025.09.16.10.19.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 10:19:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c007::2 as permitted sender) client-ip=2a01:111:f403:c007::2;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=baSuvDaQ2ylCrkHKkizEF6YSOnKO3Pqk8tJzdh02lSy/NQ+wERIy3K7yq4rZepdxkn6GPefbrjr1gXJSZVPxEOb6ppb79G6jnwMANSJ6BEbR320R1T+XPOZaSYB/i/59rSnTTS74WevapLytqDY0l99m0ASADQzsRUeNXIqwTl4KIgDj01sUdEp6E9HfWZbSp/jurSrENOxQDO+pA4O5/+bTV69QGwGtGDMn8HsuDBBVIZodYcegYUgLW6zVgfOgdz91wIeGB5HYtmBOq1C5pMgNzoe0Bi8Z+SJT1VSJvEFadqsqjlXIqNFDbYUEsG2CWibS9J7b69MtwInebu7Yhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ItVKPLLwvprRNFT6X7VAsBvihdfCxXFF9VCA4y3l4f0=;
 b=v2syJOjmtdwzii2SW5wAzlm+1rY7WyiBUiVwx4t/Tfy2P4qFz4p+Gvm5MbK8xWByj4UtZruJwghb902kM8Z0rJCdu+D9vU15eC+3ULfP5GeTZDkWo7mWL2o+Ro8wwHbrbCPgClMuzJRcazicgNkN3af1ebFYlrxKM/gP4tsrqgOLpauDIcp2UESVivsgv/+lnuoe61CIIQ9R/tss6rTO6YhbZ2NlNl1DAbkTK2A53tiC3JI8cudr+7XSCvnGirohdHkjgmsT/KFPIPAVUmh1eMjUdD0cuj6TCqz22hwjFu6l/MiXsgSBVJX5msYxO2edF4DETSEiWfrnFlgiCwjo0A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by MW6PR12MB8900.namprd12.prod.outlook.com (2603:10b6:303:244::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 16 Sep
 2025 17:19:32 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 17:19:32 +0000
Date: Tue, 16 Sep 2025 14:19:30 -0300
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
Subject: Re: [PATCH v3 07/13] mm: introduce io_remap_pfn_range_[prepare,
 complete]()
Message-ID: <20250916171930.GP1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <3d8f72ece78c1b470382b6a1f12eef0eacd4c068.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3d8f72ece78c1b470382b6a1f12eef0eacd4c068.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: SA1P222CA0108.NAMP222.PROD.OUTLOOK.COM
 (2603:10b6:806:3c5::29) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|MW6PR12MB8900:EE_
X-MS-Office365-Filtering-Correlation-Id: 341fc7f3-738b-44df-f13b-08ddf5453383
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Vl4N23yHSqL+EMYITX/5wxgcMBlb101tXwqHSvX1Nrj1+UJ86bWRvRyWZi97?=
 =?us-ascii?Q?4aDaQDAckt0xzvg/pnEA0L4xfyRH9pKyVhAdep6gp9Etjvho+S0uOL/Ueod4?=
 =?us-ascii?Q?l8GCHY8nh/p/odFodZlqU9CvPHfxom4zNbZCdqzXRwzxqvGhsdYiU7td8II7?=
 =?us-ascii?Q?gQJkRywrOuRJzMkyb0Nn6akE+z6Yt9iyIeFUk8rtyL8NXR2mQaEcxBjDZx6p?=
 =?us-ascii?Q?nu0pECMpyFFvp52GRPbs6s71w5TCLtZUV4Pyce67L89kHDU9S+LSICtTijeH?=
 =?us-ascii?Q?n236R3+ZllgrVSg8TH8rSlVY6sLvs5f//OBkFgsRiGFbHYrZp4Fi399movEO?=
 =?us-ascii?Q?Slg4dmL9r6J7ivLBtZE56TAtKgD65wPssa+blGBP0/C7vmeewWhuU88zHx1w?=
 =?us-ascii?Q?rwRBW6yjGV99OOPlkFJJvT9G1mb4B8gL9kodCW8TYybevEAD9T9+qnQZ3MXA?=
 =?us-ascii?Q?2KeA08uimOIknR2Os1tMMr6wUtdtfCAViAou4nTxXMKF9i8HO1aYVb2NagEG?=
 =?us-ascii?Q?qFB4751J+ZsMnITBVGt8/zBa9BU3mjbke3NGaiaJFv05kk+tJN5HRCD9cWuK?=
 =?us-ascii?Q?Bpi9zO9vYmyT/unFemMnk0RZC4/IdGafyfWr354d0qEK7ps147cLF1rrBmSN?=
 =?us-ascii?Q?Lxh+Yv1z9+QKD/KRkGQsQrmbHWclN/SjnSDth9tyfwY0U9ob0ZTwmDZCDFBA?=
 =?us-ascii?Q?EwXp7REhQ2FuEMUiESSXffaYIgRLSOrI8NUS+smvPLajuOxSZX3Eo7RmPI7F?=
 =?us-ascii?Q?gxFOkg7WI/LgdriTHfi3is2ggJvE1kUV1dSF5K/0N5iwEfgCxec5RLy1Q6Xs?=
 =?us-ascii?Q?blPz+y5aLy9VA7VZVL2/vth3f5cA3XI9gdxYPjsRohbK4VHmBvxujN6JmTUD?=
 =?us-ascii?Q?Aq9aWNnJt0M4o+cse7wa+5G2rgt05I2/qUdGhka3IRly7TQGMSHycu7yX7pD?=
 =?us-ascii?Q?l++J6YGzSDCDzbhOJUA4ZrOB3gWbEqi+Hu/s8QFUjdIrg2zyKk2WwT1UPL9m?=
 =?us-ascii?Q?PDiLxtTVncgc6f1iTKvLw8Y9Kjbum+fQ5nV5jdnBt9wjBw+ztcRoJpqULl+A?=
 =?us-ascii?Q?LrDI7yVlMv0UU3b4suMX1NSfn/Aw7RV4rWRqzGW6Qu4Kj3h9vbenqGGAsZsq?=
 =?us-ascii?Q?0QDD/pT3C/kLdRwMy8c1kZ0azCMdYvJ5zNY+vn3ke8m5tYwHMIYaxPficH2f?=
 =?us-ascii?Q?p/E9JtqqjVrAW6gKMaJbOpurvRBKsNpKGrESev/ARBgpkHn8sxjuL5pOaDq8?=
 =?us-ascii?Q?AtWI2BVjgyKbdJyBCZYtC7jB2K0UcGtXx3Ukx0qpTIzJK52CpOI6Aw+QaSS7?=
 =?us-ascii?Q?UsalmDJ58w5f+Gbhn+zfkmXUXtyU0IKxzaEXSsqN5jZ4QbgwxwsWNoJxP8E8?=
 =?us-ascii?Q?8T/tf1iDCyvFLMjxZ3VZuHV1J9zgH9X4fXxPraGNesIi4sjqd+KWsxg9SiUC?=
 =?us-ascii?Q?RNqaEY0eG2M=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?AhwdEjg3CH98NPMwNrq81fS5VJ/FD+TIBa+jyUvBQ/8W5qkcRF0Opo6yy2BR?=
 =?us-ascii?Q?ZB5IIt/4Yd5JrkXHQHnDOV7oAA2VKBoGWC5bVgihffsfh8z2f0ROYF07ivZP?=
 =?us-ascii?Q?3hx2dy3cBDT5Av+sOMvESByR/9/oV7DywGArpes5AMdzy/619g+VWbwTktan?=
 =?us-ascii?Q?aT9DMqwLjlKCXr04SQAqBoBWItfVP7wjrn2fCOIa/XPIUufaz8+QsBE248Jy?=
 =?us-ascii?Q?EVaftuOPijwlnyrq7mVw90wtDmJojgUZwFKzCXEVnG/HkuI0qdb/ak2lEJPF?=
 =?us-ascii?Q?roiIAteoeVmCv9rEQXUNcTX81SrF1lGhgOejDhCom+BhNMANb8FMpTH0ixvB?=
 =?us-ascii?Q?QTcpbAQzKuHel2TCYd7drfhLv3CYaYvx7BHkGeO6qXrfXw2xOddHan1lQ4tB?=
 =?us-ascii?Q?fjQnBtzkIOa3IpSlvDgjn4Utr0hlJMuLmGHJPZv6+dq0qYR7JC4t8VPOxr6T?=
 =?us-ascii?Q?mms9q/k1HKC3m6oRj9cznzrJCJRo+78AZKslDQ4WPAZNXHcOmUWWwAvffarV?=
 =?us-ascii?Q?D0wEVgeKg4CYq/xcuq5lat3lza2xrApCjnD1g3mYeraJ86uQIc16Px8v91rb?=
 =?us-ascii?Q?iPGcvDeycPdvttntwZlyTyW98R3XqteIkBbltnqYSr5iYOT5B6jfqEiXX7sp?=
 =?us-ascii?Q?KAIofZe34u5h3lSpAXqhvoCT2nlQffsv+lwObsfWmxLGW91QZwXfudYmHxXc?=
 =?us-ascii?Q?mUzIeCFbESPH1HmFqN6AXg8HCL6qkTMerzYMVuhZDj58zgx/rcbUDBu18095?=
 =?us-ascii?Q?1O1cErQrnPi9ZtmIOFbefnvuTWPX65wt0HJrzEnOzmC1omSrF5Dh0Q5mlik4?=
 =?us-ascii?Q?fGROhDaqH0VxNl2IV4qPczxcwJzvG+vYlbGDojr5X0ECOGw+HWvhwRlNFp4t?=
 =?us-ascii?Q?5p3ywYkzsN2cbrNSp6cEFvco1xpuUae34qXvSOX5rQQV10RoEZ7NI0M7VXdg?=
 =?us-ascii?Q?CyR71cqiAnjT6eZQ6oW6KewoVJbjvrQNKluIglALj1kl67hIwJHgRXLvBr/Y?=
 =?us-ascii?Q?NRB0GUZsej9HAgoejz9WJ+M3yg0DRRMjduhr4AsMeTUNLDr3wTWzS9ppogl9?=
 =?us-ascii?Q?ieNHrlC+EW9+5wP7Jbu5fJyyNh84qflUltAqsPOv3QxgPrW/lR1pr2rEEXHn?=
 =?us-ascii?Q?Zy2+neRkJsJI8SibWnTenMm5YmNSaoLq7f2uPVSDrgFexE+NTRxc9MP5hghR?=
 =?us-ascii?Q?Rr86kppon3ONCuT+C+Q3G9ekSRToyy7illnDfqrXHyCjgQvwfiD4rOTHfuuF?=
 =?us-ascii?Q?vcC7dkdhPXxfiGvwAuHDNEm/D1Mglg5wHH3qjnm1RzRRaFbwIzsEhCx2ZIkS?=
 =?us-ascii?Q?9d5RoYvbK4ajNSOeovHsyLQDyOf3LP4e2uXBx70Ej+OFHmbkDBiRl3K1+fiC?=
 =?us-ascii?Q?CqJ5G4A/Ni/ynEFwpA0Eh/74B24XN2sjZGfvYiyH50S15n/Qot8jyV+kkthx?=
 =?us-ascii?Q?oKqmJzk7uvzIbI9ZrrrxvbiqZAHosoN1/J2DzrIP7K9O2lULFL3791Q8GuWk?=
 =?us-ascii?Q?+9a/3uBPmjXwSCRevZ9y0tUg6KMQYGsqlAmLuqHYkViSS0d1JPXMdwahe0t7?=
 =?us-ascii?Q?OShIkfoXWMm6LOzV1cLtpbMgi7F8EuFOnKiSYl/l?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 341fc7f3-738b-44df-f13b-08ddf5453383
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 17:19:32.4937
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: EjmQ13RSj0Z960t1+t5GSw7mtIVaFDa31d2y75L2NwWOggCBGnh8VfbpxDh+LgXZ
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW6PR12MB8900
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=cOwLbzLy;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c007::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Sep 16, 2025 at 03:11:53PM +0100, Lorenzo Stoakes wrote:
>  
> -int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
> -		unsigned long pfn, unsigned long size, pgprot_t prot)
> +static unsigned long calc_pfn(unsigned long pfn, unsigned long size)
>  {
>  	phys_addr_t phys_addr = fixup_bigphys_addr(pfn << PAGE_SHIFT, size);
>  
> -	return remap_pfn_range(vma, vaddr, phys_addr >> PAGE_SHIFT, size, prot);
> +	return phys_addr >> PAGE_SHIFT;
> +}

Given you changed all of these to add a calc_pfn why not make that
the arch abstraction?

static unsigned long arch_io_remap_remap_pfn(unsigned long pfn, unsigned long size)
{
..
}
#define arch_io_remap_remap_pfn arch_io_remap_remap_pfn

[..]

#ifndef arch_io_remap_remap_pfn
static inline unsigned long arch_io_remap_remap_pfn(unsigned long pfn, unsigned long size)
{
	return pfn;
}
#endif

static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
	unsigned long size)
{
	return remap_pfn_range_prepare(desc, arch_io_remap_remap_pfn(pfn));
}

etc

Removes alot of the maze here.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916171930.GP1086830%40nvidia.com.
