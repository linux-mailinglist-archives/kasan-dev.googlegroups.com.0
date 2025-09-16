Return-Path: <kasan-dev+bncBCN77QHK3UIBBVNJU3DAMGQE545ZDPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D9A9B59E26
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 18:48:24 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-32dd9854282sf9067974a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 09:48:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758041302; cv=pass;
        d=google.com; s=arc-20240605;
        b=WlNzsm9YmB/mf5XYZ9iVr9glWTYWlCX7r9LaKy5yoxus5XNZ3hLWgUcggFEyw7OdeN
         xElFUPM86P0uzi8eznRy0klTqgiUzCLqhzcn1z9SVDUoF32EB8MevduJQYjZlbnTAUJu
         pfogkXS6CScctRLVkTFTCCxmpVK4xgyIh/skV4M0iquPELlU8aqztsZXZ+8IbUKRrUUt
         dHeF/78dEO6LaMNQccmyZMXWFfdiUqjwItG/P/ktlIyYvONCyb3x0hDY95rxmYfKb3Bh
         73IpI+XlITkY2otaWc2Iy8fN7BOCV45SaHkgXnS19dMwfWRRMW9NQ8bCc38d0/YriVPI
         epPw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=qh4wMAZneQKjPHL0f9MeDl2zxmBga5aag9X7LMr7WF8=;
        fh=RrdkRDo9+OrTMiD/YHPfgtuzxcZN3sg3PCClHUcoq6k=;
        b=L6YpG0GZBWOh1UniHue/DiO1i8/hNa8029nSDENdB7QPwTgKcJOZP4SvIf52csFG44
         T34pCytTtMEIhPJbSO5M7fZiMBFWOXzI6Y+41rn0j6C+bzroZ2bJ/5zDg4nFk1byCKJm
         ZA3K7xaCr/jjDpsZIaapddfTnb8VmKrpv6tWcz8ucnL5fGuYpSrTBP/IBU6G25s+V5FV
         ypc4+nRz2IiIWpZ6UH18o8C3c0Q9QGsSd7xLhaoJXwofzY96mxTqTGykHtHqEEECLSOw
         /DnsCFowOXgR0ehF32n/RwdH7F3iOiXNO78934+K696R5IjHZk1cvXk2QSGwX/f5tuCh
         pTkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=DxrRmol3;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758041302; x=1758646102; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=qh4wMAZneQKjPHL0f9MeDl2zxmBga5aag9X7LMr7WF8=;
        b=pdNd6eNfxCdj/z95w7Tu2JvbMAEouTAqou1yHXlU74kOOEVLMNMrQbA2PcG9PxP3R9
         P7bvbEoVpxdYOLnP7BeOtw2NRdrfXznjcfSW3RtZXHBY8EPoTB8AjP25qC/FjMXX0sKY
         hQxm51gA30PcJ/sGYUkyl3rz3xAZ0Z1foS6efvUrtHv6xpgs1uSM3PiT2lwj0hRbfwjP
         GrD5kPBVup5OZ5R2D4KLaOQUF8nD/7XMKrePO89Ji3dJOZkQOgrwTmdWCe1TG8fyampT
         U0dvtyBuvya2yEnuyhGwf8mLS9oOQSy/Iuw/ygHvnin9j3qhsw7+RrQc/96y+xorns6Z
         wRpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758041302; x=1758646102;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qh4wMAZneQKjPHL0f9MeDl2zxmBga5aag9X7LMr7WF8=;
        b=WBgPLrYT/FgR2q+P9mzama1E8tiJuTNOWQrpl0MZpWjsoBKCfKJ7b+vjVeGpJjZWr1
         jAT1H9otK3NcqaJ5FYiC7ttIGZ8+rTWW4pt3XXEsJ2kUPZm45MWOAgDOX7vFf3+srNsx
         hySEadEfmqP+PQskiwy4SpNAIgl2NXoaMmTHLpJmX1zUtciYkZcwpdcVWPpvAb82Snde
         Nuoz8Kak0SPwU8UPNiU6hUgn3E1Dd93zBGzGVbUc0PtG9N1xGUDB7q/tJN24RJkJO1iv
         8c2W6drsIfnnuR/Y6+tntiaR3o/i1KEynj1wBF+2Lu9U+HsaRTvLdOq8Xzeg8s4OSTwN
         zghw==
X-Forwarded-Encrypted: i=3; AJvYcCU2uyA8OW4lYCGMxEBaZhAXVE5BM/Od5o6SWkwZ2hcyo2UYsjbpIveWmhtpoq08QZWbtxWzxw==@lfdr.de
X-Gm-Message-State: AOJu0YyTBNWSqYhg4Qj8CgXWciuqyVtGgxxApw0poqb2WpqBYqh4NN2e
	BBWkEulYjWddTp1Jej4LzCbm2KLXQB6ejjzvdupgExN2ra9wcia1mEKr
X-Google-Smtp-Source: AGHT+IGHZcd89RF+mZg89l0BqxgswEM6A9sYbFW9MS9gAIqD/9F8pqH2dBM8aPCtUvhw1Liu/twalA==
X-Received: by 2002:a17:90b:57cc:b0:327:7334:403d with SMTP id 98e67ed59e1d1-32de4f7e0d0mr19499253a91.26.1758041302219;
        Tue, 16 Sep 2025 09:48:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4B67pH4pC6hJtLaP/+ec1dRH3mkn+EOESxVcdw0UDqzA==
Received: by 2002:a17:90b:4f:b0:32e:800f:c520 with SMTP id 98e67ed59e1d1-32e800fc8bfls1876858a91.1.-pod-prod-08-us;
 Tue, 16 Sep 2025 09:48:21 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUavwSUW/8cOIykod5jr2FmP9TKO9xv/j1sWDRHN0fhDPOqlmYtXRYyrJATC5wWhHWFWfN6ZDDNeq0=@googlegroups.com
X-Received: by 2002:a17:90b:2cc3:b0:329:e9da:35e9 with SMTP id 98e67ed59e1d1-32de4e5cf50mr17321203a91.2.1758041300878;
        Tue, 16 Sep 2025 09:48:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758041300; cv=pass;
        d=google.com; s=arc-20240605;
        b=Up//KXcHJ2WevX9hVj9cqu0SzHtOsXR6MoqRfPL6qPN35fcboe+bGlfREGHWU+P6ZQ
         D323ievMl237CzjD/AnPKcLJchm8zXUClfhqsf8DUCiJbrkW2LWEpf3oTkyxM9WWkDa9
         KlXMmYUucZ8ewhNdTrK4t6loMBCh51uyyrTk3Yjpo4FkgJ9oHkhrK4q1RBDyh0GwUSKt
         HUpsB6f9w6KrxNeEuogktrZenI+pTHa/Tf112LCG9BqtYvbsOUTH9CWot+Lh3N20Ffx+
         ALvJpRgxK0EPxvYwaQcoUA+oTX0sYF+ys+wiLX4Qhva9059wcHT8GgLhM6RAy4YLRB3N
         /9kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZGxtqEtM6qSmnl6AZaDwla56yx+e5zZr32Ux6EqwK8U=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=V8Yu6dIZk/BQjE9EBRTtFLxKVQHWrld6Lov2vIHdF4Xj91fQ8x5bo426Cp+4sAalxE
         sB49oID/SEroQXNJqgSaLidIMFhE28fNZR5/w0JOUOl+0u0cVgreRE2zEUgROCjOCFbC
         yXeo9XAWRrnanvGPbANo+i1soAnDLuDfyyJ/+LA/Nz8a6lJJzxm9TgyHIpPPhnqvxkNg
         0Rt7VswUA7t5n172zZtcq7b0/QdaNvyZbeSGreSp6pMFk5oreVZj9H7JwoAPPqlvt887
         jHpVlgsJ6LadOnd4P0YZmKls0Vq4ZDW4AAxjObWMZIeQ+Sg05otjlg/E8wuMWSun/zQc
         tMHg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=DxrRmol3;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CH1PR05CU001.outbound.protection.outlook.com (mail-northcentralusazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c105::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32ed26fc0cdsi4854a91.2.2025.09.16.09.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 09:48:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::1 as permitted sender) client-ip=2a01:111:f403:c105::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=T/PJA5THrrIzhyTY4fNrHVPlFK7klVw4Q4Ma18Ceu9Vl/g1wbwzMsq4ed3f4zDfHY3SdjW4WH/NZ5C0vzjUffV2/icc/EvelIrKbWlb8BO9E62Tu6CL6rKY4mZyhmYPEjGqQCDqtFXcJpO7NzpeTwrT8m1Z/5lUFSmEooyLtk90hiLsiuB6qmUwO6a0VN2mr1uQaeeersy6qam4R8TovwSiapF5P7kRMBbYsH5BGwLmPwsVF92/xYyv9Qk2tHigqQwAXOVnZanl3ltZa7LrLcgq96UaXWi5VcEoLUB9ZscLEC+wTBRVohTvh7DlOZn6wr3r+0Jiz/h86X+WY34ioBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZGxtqEtM6qSmnl6AZaDwla56yx+e5zZr32Ux6EqwK8U=;
 b=TgFDyOGXbQ/h+fFaVX6/G0sOqsn3RiZf3DZMTnf/SVb5uGimPK4CsEC5S1jK13ZF0az2o670mv6P/DVW7/GZ0e7xDVLd8CdErH81/1C+3E2ADIsa8RA6kob3TGH7x9iXpnbZXsbt9GNKik+AHouLuw3Vy4xa+SRauUpfR97CgsiZ24uVkMba+mTJrAQbmISMjBVW02e0nmGAd1CauVezEgREn68GN7TnvPUmXtfKB380k02QGQZ+/Ts0RAbFrUZqByk6aMFU7TxCbsEw/8FLACZxBgB0apO7AA8pTeKqBtq+EB2TOax20LnwLdjV+CaCwEjoaB9Vp210Ep0NQxRtoQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by IA1PR12MB6306.namprd12.prod.outlook.com (2603:10b6:208:3e6::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Tue, 16 Sep
 2025 16:48:15 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 16:48:14 +0000
Date: Tue, 16 Sep 2025 13:48:12 -0300
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
Subject: Re: [PATCH v3 04/13] relay: update relay to use mmap_prepare
Message-ID: <20250916164812.GM1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <ae3769daca38035aaa71ab3468f654c2032b9ccb.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ae3769daca38035aaa71ab3468f654c2032b9ccb.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: BLAPR03CA0031.namprd03.prod.outlook.com
 (2603:10b6:208:32d::6) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|IA1PR12MB6306:EE_
X-MS-Office365-Filtering-Correlation-Id: 08ba4db9-17a8-48b8-4955-08ddf540d455
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?y3s1kf7V8heKV17eIqquy1ZN04e/zQTUTMYIRw48ly3jYe8ccTQBEfAMqSc6?=
 =?us-ascii?Q?FudoAUyU0ArFjJi4RX3RhZLzUDObS1Egr87uF5YHivcKWciOUrbX7RS0OjAP?=
 =?us-ascii?Q?FyFCYoE/y9JCAX79jGHpTAH0fRjj7bRBvKEw0tQb3PUam5ftH1f/K/+MpXTB?=
 =?us-ascii?Q?cqqk2nNntPUiGMMdYumSg/Dir899vINi8k5NKOpOIPnHDCQ6v9mFtvBjeFY+?=
 =?us-ascii?Q?3ce7w6c58538DV4hJmTyjOBmCPxP4kqa/sEHcmz2YnPbLL5Vqvun0D2wJ8p1?=
 =?us-ascii?Q?59+Vp2DP+4eHuU5y/XmUKZQ0tQmmDUgRJbyQXEc8BWWGOWS2nvd3qobYYOBy?=
 =?us-ascii?Q?AT9Pc9U/1zTSXA5sxjOY/DIr5Z9hNt3X5yh2nZlH3/Tz6noCk0RWY4JqUesY?=
 =?us-ascii?Q?kJXpqwJ1FmtF/G5+Dbv9dKNH0TdFhPYOkY5L8Pw9m3kwOgyN1FAhwJu6aQ7C?=
 =?us-ascii?Q?DsKgLS5h9mWJCgt/BjmeuzKTV3pQIs/Ipzv7ReysiM14l2IuqaTQAmKkDW+B?=
 =?us-ascii?Q?Pv21CX6Gi1y3LWeGX16a+gQX4agQVILiHMOjTKV1MzNloC5rjxeeOmeZRPHf?=
 =?us-ascii?Q?M8Wx5/722UaQICJQosJCmic529qBAMm21PWKkDpkvAI/sMo/2H+y68TPtpRa?=
 =?us-ascii?Q?OrXVkU27BRNVwqHzCHhT0pSOonwIy9dbZ+N61AfUWF0Y2hJxrMJJ69cUh1WI?=
 =?us-ascii?Q?xB0Ch4QMTWxgiIWfIsKQZAxvClS4C9FbQKdksbnpjKFte+KnUzOQjtA8LTUG?=
 =?us-ascii?Q?oGlWGSU1LVVLI6Bvm/wWUG48Y22se6JZZW9/4uEC49i82ROd8rHNtm2J6Vl4?=
 =?us-ascii?Q?Lm5CzO9W1VpYrRW6EBAfi+GNFSfHyxB0dkWEBrv/bK1rY0/LwiFBK851MdAy?=
 =?us-ascii?Q?5RwufG+gmdR5O8GurYEI0SBZ4SDqTtjsgNKuQmO6qN9QEXQqTyCYN3cQl8hj?=
 =?us-ascii?Q?BWdih9buibfUxryiTlNOu279HVAMa22upVNm57zmDZycQuFyPDRAIPuLHVHt?=
 =?us-ascii?Q?0lfGzwUyRw4CCNKWF4RwWklUnsKykA6y7LryxD8zvbolvAxk18ucq7DfwBoQ?=
 =?us-ascii?Q?IZXnZ+HSCbirIYmxGjXGDLNwEh+/nmo+6HmDPpYQlOe4TxDs2Q3hP22+BfdS?=
 =?us-ascii?Q?z/6MpGok/oivhCZqJP6iBFxdV4PsmeuSxMwYBWY/e52n9nyzGyKRZhlRsm7Q?=
 =?us-ascii?Q?fNhlTWcKy9xgE5oeSHnlVMcMiWdoKU4dg+ILTLNMh8jsH2QmIRX+w/aFSp3u?=
 =?us-ascii?Q?OISp+ZzR63hXQ6e6uFRRPoNM+vNK9AzMW4YRP2Ce0LJMaOjFOzVWBGUgoUDm?=
 =?us-ascii?Q?1dCSA6Zx9/2hCJF74LKLdQ6+fUf3RmzCzt9spHEFXAVfOS9BXV4ZdLe6N6/g?=
 =?us-ascii?Q?P9S9ZwVnFZtZymXpn9j+/aAUk5SsJ7uVhLoWumliY9rMO0zqOgW5m8lgC2s1?=
 =?us-ascii?Q?HrqYn6I92B8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?9Duq5LEZpk/YBdps7+9tqiQbxVyXjQ6DwRwGD7gvOXbqvJf3cAMFfGkuAI6s?=
 =?us-ascii?Q?kgzVQxnppEx3Hxa1KvIhfiocMEroUhxs/AJGLViw5u8BwWlax4eFrOewFUQk?=
 =?us-ascii?Q?/nAC9AHLxIpcMEKt1X/e59t01FR79RPPRCA7MYPiQ339HbOqjKIPeplHXzNA?=
 =?us-ascii?Q?oR4V3e0TsDg7v0VIGIelwuSs4WI47o+Im7uRzmDJe8aND19qrjLm61ZtRK7s?=
 =?us-ascii?Q?kNbnt5kp9eLYf+SNrGVqsRNwqHmjUWklH8yVXKE0ldQnV5hRBERmG82BA1dy?=
 =?us-ascii?Q?0ldP6cIwNzaBnieqIObmKYgcReAwGcf51/cERNotidr/RFunydtNC0mD5hs3?=
 =?us-ascii?Q?wf1cEohL4Yspiwq3rPyhvNpOSGu9NL5Aqlza5D36zhsKab+Mz+jalkz5a4FR?=
 =?us-ascii?Q?b/r3Rr7WtswikEKlxjRGxCbND4mMWXkTdNJyp2Gr7RUO66ZPw51yN+3jCTTw?=
 =?us-ascii?Q?mW2di0SvXhyT0scsQyWk49mUiWgFkcd/Ff7P7eInR7/+SBdn4SwsTzluMjLj?=
 =?us-ascii?Q?lGjho5O0YoS/yh6F7WLqB04hBUWGzJ8DXCOT1ZwCu6MfVi7/RdxTDTCJEHaD?=
 =?us-ascii?Q?eGUy2sfX71VPEg+Y92222XpmQJEisQgbscHYok7xJP1ANtkustVFB33SmtYN?=
 =?us-ascii?Q?tgbCCgu/reyPaKuy9mdEbtmsXdgnaTYgAxe+qahoMh0/jbjpV/coO1jM1+24?=
 =?us-ascii?Q?EDy906JVYxGXaopLndYhov8EalQNnu7IAhPJnaaHLg+vY8/aK3VtkH1yYHwY?=
 =?us-ascii?Q?VzxpmTkuVSmKi4GK120cluvxJxSseQUluAenvL3N4RHH/Q3Kln+1N+dxMBvN?=
 =?us-ascii?Q?78PkTJdZ511jiK5SdG4N8KlPGh2oTffc/W26LGdK23lQQ3eSi7qfDu2DTRzB?=
 =?us-ascii?Q?LdSM0pe9aL7gF4d/hctDsYBYAJ/6uu3BYEzY/jFMxJFCjdCqjOPuOyub0vRs?=
 =?us-ascii?Q?sCCQbt0N0C+4pQfhTQwzelNkHmRSHrl+4HXh9GSWJ5kLADWoBevBAgY3hcNS?=
 =?us-ascii?Q?aRxQj84kDQMHNfyldnCdgATBN6CY23TEiIygJfSbOLOZTbbsoKOGF2GwU5nQ?=
 =?us-ascii?Q?OZ7fqmxzWe4NakSiKARUZvWSxR254gsLVEzwztcb/kqDCK4CPll2U/BprqjK?=
 =?us-ascii?Q?VHjhIFrinWzfer0RbSf/88XrvF+lO6zrg9mjoIjjyzBxpcyKGJeRMNyxfBCB?=
 =?us-ascii?Q?velojaAo/wDZV0VF0l+Ar9Qm/6iylzUKf8jbWBmixT9EBuz2AuCElpQwboph?=
 =?us-ascii?Q?Hq8OGcJwI25y0pm0xNYtAZEtXSV43bZ8y24SqF6au6HkbmKg8zk/7YOSvqaN?=
 =?us-ascii?Q?/HavOgfck4fzQnVD8qrQx2jl6yFaNRmIV4H6kIeH6hfMCX32s7iGjzkQSy82?=
 =?us-ascii?Q?n6bGBt3laRK1Ic1Lz6I+OSsrUTIMqxVR/laJY3F/oqIFuZJafhEvSDwvef9Z?=
 =?us-ascii?Q?O09zMqsyV4BgYfxiX9gcLUee7p/QT50VAPYNeRAdXdEwp0ALpfwMCPDYW98d?=
 =?us-ascii?Q?VJr5ujnd3n7DnDNVPemsryDvKGTs40GynW7lM51DrQBD3LvrJ0iEn9MHlzr3?=
 =?us-ascii?Q?S/spiDlKNfnIu6wrzO3Qzf0c9ufYIVAnMpJnLOOA?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 08ba4db9-17a8-48b8-4955-08ddf540d455
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 16:48:14.7629
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: r4fivfu+frkvHJBnjEA82CgOPlL2cLtcBCqd1SwbVM+wIOZQIM/DQUGJzfKXCHwh
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR12MB6306
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=DxrRmol3;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c105::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Sep 16, 2025 at 03:11:50PM +0100, Lorenzo Stoakes wrote:
> It is relatively trivial to update this code to use the f_op->mmap_prepare
> hook in favour of the deprecated f_op->mmap hook, so do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>
> ---
>  kernel/relay.c | 33 +++++++++++++++++----------------
>  1 file changed, 17 insertions(+), 16 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916164812.GM1086830%40nvidia.com.
