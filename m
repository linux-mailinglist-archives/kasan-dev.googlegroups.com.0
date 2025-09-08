Return-Path: <kasan-dev+bncBCN77QHK3UIBBRVE7PCQMGQE6N5K6BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 736EBB48E43
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 14:55:36 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7e870614b86sf1489649985a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 05:55:36 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757336135; cv=pass;
        d=google.com; s=arc-20240605;
        b=JJDkgGH9DYLmH35D2JLVG7Wl5kkDHS6ImHTqvMofUHmDmClq485OiX5RqskXuL7vsa
         /KJHC3sdl45HOlXK8zUqOCRfD4Kcf2RbyoaK+Zh+FyH4gfBoltmJAy4DFap9053dLL6X
         fcXMN48+N2/r+GybOOcMw8nh7MSvDRDZWPCSfowXpdYgwdIsWdjVxyq7cmulpJObIAA0
         lePpo4K+gyb3kNgKmwSxj/shCoq6gw5hgvvaxIXFmVhD5LzvehPFqUDYwQh5IPJ2vZ5B
         ry7RuSSmgNh+CmyIT+Pp3uM5lS/VHtWjbY0TG7lwncJxC/8wikhpaNOPUtvjGLO/BFgu
         4hFg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=wwxmk+3QqxWl7oxG5ip7e7EKUpeFVIoBf/cDzNo8bU8=;
        fh=DjJVeHmrWqTXM4y66qCYoGPEm7LAwvMUpRpvWNTSgSc=;
        b=EgGnpL8C7SQjHnfLK/xUy5zBqTKZhjJz3m4TPnrc87NvOViyq7zMr9B1ey7chURgcm
         TpSJN1UAGl+GUyItEPN3+kFOokL5dObltq2hWJJpHalFeVtvV/RVv1HYFK3Rthebcg73
         7d0odQbhTl5Ob/TQTwhYm1iN+MWphAoN3Lx4CGv4+ll8WSZbwco0A0TLuQofskmxO/N9
         EvbffOB4vRvlF3o0EUHSTx4z3kTCz/sELGwcUb21+BpFkHwe2JZCUNW23OO+JzKPDKTI
         frtqqlHu+sZk4Ws9BZDRtB4Ipj09nIuqaVNrNl5wktfWkMZtE2ozDmreci5GVPw0vQcS
         SmWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=sttyjNGN;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757336135; x=1757940935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=wwxmk+3QqxWl7oxG5ip7e7EKUpeFVIoBf/cDzNo8bU8=;
        b=TTLa6tto3dvKiOuywYXvLBsaSwsZHBzuA3cr52rOrKB7eGHq8JhVPtMuCJbHcHFZ8G
         B99zoC4g/kVQu6fogFyaGQEXjaPPAA9Fmf3uPsvrp2vr/iMls1f0Bk76c9Hz9HevezL/
         8nUdapWaXfc2F2Xt2C139HNWYZoonUTp7yX49NSdhk/86xJutb+3Fj+I+HFmXgYR4N5j
         775dCj/Hl4IXoLghIqwAKSFBqv+tiJulNiTYMPR86oHPQuYabX8JEZndtP+aYw+bDwvB
         7IbemE8myEQLM9F0dvdoZMo9iTsWrHnlJgg0gjwM9hKs/+Fp8i5w77wUSuctlYc5xabh
         KWXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757336135; x=1757940935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wwxmk+3QqxWl7oxG5ip7e7EKUpeFVIoBf/cDzNo8bU8=;
        b=JS1y84YKRhm7yau+/RR7WUZKNjLLFiaxXkVVPc1gxKI282MumcRXGpoT6tnT14cP4X
         /1aBe/kyYld2FMsbsjOaynG13uN72z163S2HVhTueplW6KzLtLFBWuAJMWdmHYBZIrXC
         +7gE6K8B99PgLa5ePhUJZ9WMuNM/vxYS+rxa5ppRPYdwWSLeY3be8PXZ0uU165EhcRpL
         1eq/Fs6EcpEQfVQaEXWyWBq1ogxdQELF9ZHmM103Dpsu9CR545h1K4+Q58Y2O1h8DlYm
         X8YOfWTS1P6iYBnlE5Mx9QYwurglKz0dq2c5TZc3moYQUqhTV+Y7TYg6VR9mdDucQuYz
         Fjrw==
X-Forwarded-Encrypted: i=3; AJvYcCXXOv9ViTFzOhnVu0oGXs456AQ1yXVUFF8Z9Qdw9sjIpGY22K9mV3lu/R+CrWofDDPwVfOoyA==@lfdr.de
X-Gm-Message-State: AOJu0YyceJ9qqLCq/iJE/YglXztogpLKLAPpEgVf1kGR1H6f/+NHOY7j
	mSLoJVY9VotMv8uJ0SXhjmlmUZjUkrTMG8nzIJ6PzduttWB74JmJ84lz
X-Google-Smtp-Source: AGHT+IETlnULms0UuA9V+dK8u+j5JIjwKYXAdPWeblD8sWflzAXPVoYEDnshgjIsz2/oGzvt4Gqyrw==
X-Received: by 2002:a05:620a:2954:b0:815:6a98:a1ab with SMTP id af79cd13be357-8156a98a43fmr627836185a.70.1757336135061;
        Mon, 08 Sep 2025 05:55:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd5Nq58UGBm3LAltVzvYrfv0LFdqW1mg0VM18UWC9fuLA==
Received: by 2002:a05:622a:1804:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4b5ea98c7ffls54517541cf.2.-pod-prod-04-us; Mon, 08 Sep 2025
 05:55:32 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUIpdi8IWn6DdiSZEUejUa9G56ZkoKAA4r5f4XWnZu7aLuuSPgIGS9jLcmPsKbLOoxeN0mSxR09WC4=@googlegroups.com
X-Received: by 2002:a05:620a:4621:b0:80a:39b9:4855 with SMTP id af79cd13be357-813c406657bmr782860685a.84.1757336132528;
        Mon, 08 Sep 2025 05:55:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757336132; cv=pass;
        d=google.com; s=arc-20240605;
        b=b/4nbzc+mdBuZC73e9xeVJgTZMbVBiABgm/kspF77byz2Yz3lYKmAfQtOgVfiXbm3O
         GOSEjeENv9yzybNozwfRwhKBQAxEzBblQok5F/q7854jGB8ngLzmwetpVvBey3wRf9Bs
         /EaWEjsbye1B6Qo6usNuqmMYmHCzKmGaSeEjntjBPag+favIa5ePTIRZNmx2mIUO+Ygh
         fbSqupOP5DIMYB1MAqApDLXyl19YxQsNX4Ownh7Spko6k2Q2bG0gcJaQte+cnHxxKM/f
         +wUI1XZNoJVSXbe5HVNgSD5NEdntQ9CN63NoN9X0qrpXsQrqd5oVCaaVD2vywW0yJrda
         jabA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SRrPfiibCGwC+zaCjoY5N9gjObQEi6dhTCBpZrINs4A=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=F17jyRgoBCiAbkJZ7Vb9TVluiXdH0+Zi8ikFvkPFfrLkWliKV1IcBBxu9vgXzBNePo
         tZy6Wo/F0UxkNooG8MpfZD7WMpl3yiGy7E9+lMnawNQgXxEO3wBPvnUTI81/dliU/BRN
         fhzIx8KNM2INtllhNKzXhQPCCeFmjRUmZjRp9dIwY/LDtSKGX4IQ4jbsO/jdOlIX46Kj
         vvTg4UqQP4qqAlLMRWQ4Z0yv2qv6NrOihrW8xRYeR9+H2E9eWkhSXveIVbGAMP3HE659
         0OShJE2UYglHdkBUdKO7bxliIu0A+Y0Dttk/eENlR8vLi718Itvb0apJd7ujtxLAFakD
         3sww==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=sttyjNGN;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on20627.outbound.protection.outlook.com. [2a01:111:f403:2415::627])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b5f36f48bcsi168791cf.2.2025.09.08.05.55.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 05:55:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::627 as permitted sender) client-ip=2a01:111:f403:2415::627;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=mQaF8TJ1Q4Emvgr2GrBjBSvbQPLhDZ7OTnTBlHBCx/gFfE2XbxfwBHoeDtY6LKbHLMimyGmikOQTd2HstyUvdiYnuOK+6v1xx2JC8cbhuTFB44MyG5r9gzMiVrX3DSNe8YFtVMykr4EGR8YqkcAQ1p7GdEFXIAgEDLnFd/ZmenDy7fNCsMceHHciwY0XBwmJHBs7JTaGBMfRMO5M/f262/MN4IGqRyjbxFU2Cyfwcu0ns4olbKTBYkoFMtNpzBIJw9HuCE977oFwJj3YHNNAmS9rW60S9Q27qUBSYkpLzhAa0xsnRfr93vVc/uTaQv5BwrEGvXF2IAkXBN6fGN1K1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SRrPfiibCGwC+zaCjoY5N9gjObQEi6dhTCBpZrINs4A=;
 b=TqCagHm19sWiMkS0WD/VPlt1A7ONWi485AzlJ4DuwXLFhQ3YqCxUHnwU8x2Unqd+8pPKymPmRFMnmnpF27CowACKwcTf2OQBnkrOQl5G1HzwzdNCuiSV2Epw62P/rkMJ1SpvWnNcwTCJqj/55vv3apPM0yYL1ZWz+tGj9whXEgBmc24oloxFdI0H0e5mr1wwV9QWn7Tl7QMChCM+oO8caiwdKhBBuL+t6jeFxNPYmGnf538LxsrmL9Atz5ORgnypDZWYoJFqP6aDzJQYqAlqXvqqkARQ0v6nSOiLMKfJWSbUuGjlja6j2TPS7u5Q7mJJXGvw2OF7D9wCcdYVT5+vdQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by DM3PR12MB9436.namprd12.prod.outlook.com (2603:10b6:8:1af::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 12:55:28 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 12:55:28 +0000
Date: Mon, 8 Sep 2025 09:55:26 -0300
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
Subject: Re: [PATCH 06/16] mm: introduce the f_op->mmap_complete, mmap_abort
 hooks
Message-ID: <20250908125526.GY616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT3PR01CA0129.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:83::17) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|DM3PR12MB9436:EE_
X-MS-Office365-Filtering-Correlation-Id: e548f10d-fcaa-4f1f-3736-08ddeed6fc49
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?hOLzpllpfjJV1l75dvoebmxablzhZqGRn02hp8Er9zgVtXKfRDLHj2J5345W?=
 =?us-ascii?Q?78gWzVSOi/uCjeTviNl2jHB++OnlYRXhAOCOBLt95Gv5xXJEo+GWYzpkmXbB?=
 =?us-ascii?Q?BWTW60yJJCrxSOv1IFuMBcKAt/TP+jnP+hFI5pcQInxMhYYGyU2KN0aZHC0+?=
 =?us-ascii?Q?hzO3kMnN2ee49kPX8q4/7UxJMJSou6hisu7UwZekP/LW+TwwQJXCnIYZ0+3x?=
 =?us-ascii?Q?VmgX2HvwEMe+Y3WA0WH6BnwdUP/bWjSYmQzDVBsZ05R1tbXzSxSCUBlbqv9w?=
 =?us-ascii?Q?lxj/tIckeFbx+GZm7onzTt/e9gXpkdUNwdpzEEb+VIt4heM46O4h3zjtG2dC?=
 =?us-ascii?Q?xM1EADd7FTc0PQFf+4YVFYkvpWXx/fOnlAcXVNDzRltJyL2eHio9Hr+ce5lI?=
 =?us-ascii?Q?mtFieFut3fMcMRPAtN765t00cpPPo5VZzMiYNhGbcND1gTVKygcEgus0R6Hw?=
 =?us-ascii?Q?wQjguPGow4ulCHnmM8xKxK+U97cWc0HlzpVBWayhXtoPf08EVQOkiasN4PD+?=
 =?us-ascii?Q?Sm3JvUgGPwZ/GGMYfAdFHwjP02+XFNY0CEvENReVnYRvPClAvo2NAc0KcdpR?=
 =?us-ascii?Q?NEp6jgELeHQdzXGx4IG9vDvbzO6PVdU+QC0EyzIoImwLdjq53u59d3BWpyyq?=
 =?us-ascii?Q?ZJzIAkopxeQzhWrvE5ogYgqPA3TLI+IJ3D5IjKByPTjWAMYRXQsays/pTUfa?=
 =?us-ascii?Q?BnUPRKjVuC33UDGLTBJfhE4vltW06tds7r1DrRcjPtbyStlfCUeOYSxHzGPT?=
 =?us-ascii?Q?VTFI/YKhTwJgEWgkKL3EQmHagke21qNpFK3d86cybJEtp8S6YWHduHTOGguz?=
 =?us-ascii?Q?+UDz5SBqnAY4Sq8XY1Bn7nbBJMmC8BU88ZzkfymmP5lh75OWkDerG0fnxosC?=
 =?us-ascii?Q?Ryq2IHLf4vdOKs6EP+kDHi633+JCo7Uj4QsnTV3KcIdS22vTCT1iY42ql5vx?=
 =?us-ascii?Q?qB9vOhOS6JniEcZTVkLNfNy4kq2cIkx1IO+1kbgxH42/gyN+sDEjev6F6vTR?=
 =?us-ascii?Q?4tS/CLqI772rAIHO61GOrKu4R9t/GHmwu/Rdxtn2TzJb3pK8o5l+O1K/Qkan?=
 =?us-ascii?Q?zimXSYbaR8Q9AORsvkaCDCOWr7syEFCJHUyj2PrCyYh3r0vitqAgg6q2Wuoc?=
 =?us-ascii?Q?B+7NXMLOu1/u2zrDL36DXH3k44vthCEpmWwigNs48+h0kC/dzi65Mf4lTnvc?=
 =?us-ascii?Q?Z1ST7LnmAreJ75qxW9XZBloCcX97po0b8+lX4Aq/d38ml0vYYnohbrpcxfk6?=
 =?us-ascii?Q?bOQt9XNON+AuejEphu4zi9S9TAMqjrG6qK40az0OJclh0TOdfnkEEmr+Oqgu?=
 =?us-ascii?Q?E0G8SrPosfwSCejBRRfmTnnpn5mdPdLzT5+JBerjLC9fofTUTjGnGhXUaWfD?=
 =?us-ascii?Q?7r8mVW4/7qmjf/Rpz+4Ry8SrkJxUcUwHvSv8lw/uNX6sWIZ5Ag=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?oIcDJZNfShniNK/etH2wxFhi//hajGhHFdmCnLtf46OOA9sGmdBa6ghcVL+r?=
 =?us-ascii?Q?tJsF7W0LaEDWk/G96KUaaXh1nRYASHW3KS1ycu/I444a7rmYdAaILZK0aRIW?=
 =?us-ascii?Q?bloidKoYiuWF3x+nLsQGKj+bB9KG262oSIFnC8cIE3P6h2mzYAws1eisy/Rg?=
 =?us-ascii?Q?yebflx546I4o5RFGYPdC60jlH5l3VjnyTSjoJTvuJpJ0mkoSaW8A2lM+vJDM?=
 =?us-ascii?Q?XZOLW2zkX5EH2m5lwoQYAuVjjLy+R90YCt7jEKPGO+/WIeDM6/E5Q6DuSTGp?=
 =?us-ascii?Q?uWUlekAmQ/p7wb41CQD87q6JPiXYM5MsQx7YtBpDsmpbrsLj8BSmRqvS1k8p?=
 =?us-ascii?Q?C8LGW1X4ptEKAVsx7QBVKEozTCFUb8vrEAVHME9nJ9poRhvWEf6v1PjpeHPL?=
 =?us-ascii?Q?tNbZOb370TyMwaxMAFdBen2DhXJVgL1ESIS7fwyTTCwKyeH5Owu5J/g87/gr?=
 =?us-ascii?Q?8DmXhL04uciEofkDaWOVo5MKmxRidSgexagbUJYw1D0CeA1AMY2lVBl6/VwH?=
 =?us-ascii?Q?pV/Wuy1F21xuWysnkCUmqw8S5Z88dEOP2dlaAgGa/6xuf7HAtOGq92rpboU6?=
 =?us-ascii?Q?5hpY+K/ICzuxjNfY1k83a5NODCYa/RMpR8hThZCq/hbVUNYhatN4D0gF7Ch9?=
 =?us-ascii?Q?KPchDhdjVejDLm+JyHKSyM271BGXc2rzJeo85M+XVi6pxOSX8oipqx2b2vVH?=
 =?us-ascii?Q?C1RJS14MPXgQdV2Y/8pa2vvSduj8cK2ral9q7qb2gzb/MUJpOyrN06f2xcem?=
 =?us-ascii?Q?y9FXKGjk5zmsjvnhrUfDwRg6qDl/aOUj7/BeDQ+gLA4dYOVneZr+9hXCYtrP?=
 =?us-ascii?Q?dEJH18C9o/2XRP9eYGEVP8Z8ENp+VJ+QMicnqvlNet8NAoLN2ijluDcOJ1Kx?=
 =?us-ascii?Q?o+WvMYu+vel7+YSIB9ahPJOFkibzzFFwqziLB7kNNMoSN9VWfm6b5v13GYQJ?=
 =?us-ascii?Q?LMFPvguxw0nZdc57UiR4LyHBPvZt0836oyaHB+8qwCDdqqvVGI95HLOEXF8S?=
 =?us-ascii?Q?ccXQkOd9L66atXWy0ao71ynwNeA7vMFwmTmWBOXfRm5mAevAKSaZNjAJfcOR?=
 =?us-ascii?Q?nA3a8uEpRPdoIid3oNXQoFidwuky8uaA8d8K0xEWk8zlfRVkn/6gFCCrIsPX?=
 =?us-ascii?Q?cS7HuUCuC4JMIL2N42DCcvBywJFfe26tUe/TXt+TOB5SdG6tTkiORdoIEsUf?=
 =?us-ascii?Q?GnpHy0g2eScGN2LRgLkvnXUdEMnI/a15/JauikF0o2L0fhxD0sHwgjdURlSh?=
 =?us-ascii?Q?j36DzNyUDA9lM6F4QKuvOnICWpO/iKvojedw0sPRuXz55zE9vJulwXf7OwB+?=
 =?us-ascii?Q?vSNkpvvVEk9t6NDVfywSeVc3N6KL9lCubKIIBHZ9bJQ5Gw4c4JalYyfYaW2Y?=
 =?us-ascii?Q?T/J9gV8VBDTidnU1t7xWplV0zTSXHnND9NY3oqiHtwTEYj/lPBq7YUAX7eLo?=
 =?us-ascii?Q?LagfIR/gi2VRT6iBUhCn9M6hci1o57VZTx5/D6BhamsApghl1Ik/1D5qHHOm?=
 =?us-ascii?Q?0e9Ad9bjpMirYXxO3jUvxq24gAONWEPpp4qAGi2880kHK0OqlHoZ6mbDsDq4?=
 =?us-ascii?Q?c3b4KJPEvHvZB8pvD5c=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e548f10d-fcaa-4f1f-3736-08ddeed6fc49
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 12:55:28.1443
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: R1ezjMFFuTM5OI0AydpXJG/5y8pqqbydzBG9m50QBq7gRMt9aV3i6yuenmm1weHj
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PR12MB9436
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=sttyjNGN;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 12:10:37PM +0100, Lorenzo Stoakes wrote:
> We have introduced the f_op->mmap_prepare hook to allow for setting up a
> VMA far earlier in the process of mapping memory, reducing problematic
> error handling paths, but this does not provide what all
> drivers/filesystems need.
> 
> In order to supply this, and to be able to move forward with removing
> f_op->mmap altogether, introduce f_op->mmap_complete.
> 
> This hook is called once the VMA is fully mapped and everything is done,
> however with the mmap write lock and VMA write locks held.
> 
> The hook is then provided with a fully initialised VMA which it can do what
> it needs with, though the mmap and VMA write locks must remain held
> throughout.
> 
> It is not intended that the VMA be modified at this point, attempts to do
> so will end in tears.

The commit message should call out if this has fixed the race
condition with unmap mapping range and prepopulation in mmap()..

> @@ -793,6 +793,11 @@ struct vm_area_desc {
>  	/* Write-only fields. */
>  	const struct vm_operations_struct *vm_ops;
>  	void *private_data;
> +	/*
> +	 * A user-defined field, value will be passed to mmap_complete,
> +	 * mmap_abort.
> +	 */
> +	void *mmap_context;

Seem strange, private_data and mmap_context? Something actually needs
both?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908125526.GY616306%40nvidia.com.
