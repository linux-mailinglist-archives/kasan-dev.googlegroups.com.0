Return-Path: <kasan-dev+bncBCN77QHK3UIBBPWPU3DAMGQEMXHD2VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 04CB1B5A027
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 20:09:04 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-7721c5d874bsf68430576d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:09:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758046143; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xd0sULb++kWYk6kMLUMRhM/7xhQlkdL5BU38Amtrw3zKgIrMrodnvSBCvqmZWBFXhU
         QIAScaBGUT+S8fCUMxqDJtmD2WumjAHN9SN6EPditUXD7tTV2MrU8BH1jXUUMGj5O4Vm
         4/ww5WhczWzkPMBhFEp2O0kQhWcAMdbAlMIGVtX/h73PCYhCPwI6oDWJIfDk3cR5oJzy
         PRsy9aueOLWK8UZRaWwnmhXmEZUu/kTDMaDTlvZy+44qFn3vM7RhbqKqZOvLUIXBmSxL
         qR4WaKbOVWk4exDtq5gP8FJ2Sw+eZJEuswljWOG4bAIR5torxcnHoQIcHPu6OOAtKLty
         tOBg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=YYtjQy9uJJu8P+A0uaIKZVmdEsI/LSTdfXe9ao3o1zk=;
        fh=DWxvEC0wIm83EWWRlIUhzrF1CR7xukT4avrgE+6Uto4=;
        b=HC/tQJJct/UAnc+QQOoy69orN5oJzxLN5NOSKamT8ttrL6h3pwQVU79fBivWVCvBsB
         Em1mCLh3R9eIHS5gkKwu0aV3OQBPId47wFW7nYrH7Hp+HhfpHNZSSZxxwghrzQrcldSH
         /bueWeW+ndEB/Nf/iA3wwbvXooIgG0dzTxoTAuFhOv1SkeUW38J22AgUXLj3ybBnlLJ0
         U3DEJGusgFI3QI24PcokoQ52as8PJmVEt5mVUIwmb4k/rUw3bmvAU+eB3+CUTLO4ZS7F
         T4zIuWpV2DtVuE2Jj9D2Y0YJBj47fEKJsdXBzFZYOn9PWsKALGwwILnB0cwFAxqZS09e
         9gWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=XcLrphLJ;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c000::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758046143; x=1758650943; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YYtjQy9uJJu8P+A0uaIKZVmdEsI/LSTdfXe9ao3o1zk=;
        b=J7fJvHGhg/qUXRbRY/PLV3JqHHpoB2ckLirclEIUutepa9LjFAV0BJIo5GdFRybcj2
         9gc+wU0vLCivAodAJOIMUto+9rjcJca54k67H9h1fmoL9Q9TTJJgLYQ8rdOPwbt5vqB2
         SgTdkNGsycmIHLeOUsS+SXF4d8kEKTaFgdS1lQa5QhMI1Qh2U/lRsgIK1DWj2y3lcclF
         u6iDLWmzMkuTU1+21MBoLDT78Pty9ypeuRHEPTZuUi7YfI6eXi75EJqvZICSVEt7V1IA
         3aEBa0Ylte9TBO57ejxlH/48w6Lcda/7mRi6wdVXyYdJOlr7Z65LaQE8gyRH87XcfBgh
         lluA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758046143; x=1758650943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YYtjQy9uJJu8P+A0uaIKZVmdEsI/LSTdfXe9ao3o1zk=;
        b=SNXXbMt3pqR1WNW7eppmmXPOt05GOou7cRM2fcUkfqyltjr6ao3ryem7kEwxe8cQDb
         KbdBOirVTTpjUViqCf3p8HldUTve+PbJl5e5PToulALl11mmfUZwtmBjFG9hh0zWGf0B
         JzKgfWUHYYVS+ADxJqzwG63FtsQo5morQZe1yDrgbtGR3gcCXt7J5xbMopuBkr31i8BL
         xGL4Zh4E9mx9WuBmfJbS7REtmB4l4B9TNDRFsZ8Wn1RuEcXMomxtdwf5tORp/V82UEzQ
         2BP5m4kvLmtgPTun3JxhRW7XKF6D12vc5mYXJVdPVRNzdmpYj29jl4d7cpF85LBknEjd
         Nhlg==
X-Forwarded-Encrypted: i=3; AJvYcCWc6r6czz7jwy+JDDd9LQywij2lv6PPz3gdG88B/iX4K6/7GB7lO/G6jOoTdl4zW2XLBDHZZQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz6PXS7KhrHtD31xH4LzQ2AJTDHRDdfBhwTrRscAD+yPx7A95en
	Kak0iZegV5+5fD5VlnuMzTRaUBa4qKYh7LOuf2yBT2XHwRBLEAvsKwsj
X-Google-Smtp-Source: AGHT+IESGCZtZUvwQZeeH9EB9o7do8bFWXYqa4wu+z6GB25q0hySosa7nO8SC7E3vsJWiTo/cg9pkA==
X-Received: by 2002:ad4:5c88:0:b0:78d:8414:e4c2 with SMTP id 6a1803df08f44-78d8414e5f9mr34356086d6.50.1758046142341;
        Tue, 16 Sep 2025 11:09:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7CzPmxjaFADjX2l7JcmwXncorLXAHPBx5XVSjHV8LwgQ==
Received: by 2002:ad4:5c46:0:b0:78e:136c:b6d8 with SMTP id 6a1803df08f44-78e136cbd11ls17838806d6.2.-pod-prod-07-us;
 Tue, 16 Sep 2025 11:09:01 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX1iqTcwu+4FHPItWebb+SSqvLjEydtRf1FBgQT1uIb1yQmXWmz771f1jk5f7vAoWQ97DLAXKFXIas=@googlegroups.com
X-Received: by 2002:a05:6214:500a:b0:720:4a66:d3d4 with SMTP id 6a1803df08f44-767bda414a9mr218225126d6.23.1758046141448;
        Tue, 16 Sep 2025 11:09:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758046141; cv=pass;
        d=google.com; s=arc-20240605;
        b=dxq/upls8O1zqq8hECAWdK5aSJf5Q8UCVPZDgsKcwmASGx+kis95j69/svW5Q+keNM
         kKrh2DCSsSJt0XTAnVZ9hqF2BrGqIWFAMwj8xW3OTC1w1ZbbD0hMWXoOxtNup1jbIdjV
         JBvxjUKcr1soXbM9CWdHSHkVLkjjSB4//bYA3EW54IPuybkMZ9naR7arwpS1I31gaiKy
         BSM9gWjYIMm8ae+WlwYZxdzSlHLP31GnOdEMJUlZoQfxDiiUFce/J/w3Rv00Ee0gtIht
         Woud82SAVvogOux2ZAF8+aObovGUw3iPL9zfQwAZtrPQ2JEfsVVA+MOpwByn9Avehrio
         qobQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eJbs56PiGkpOK5+9sKNM0bbDf5X9UPIzyxQBTUs+5vQ=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=BdOgxoYSWGzd7WmsgZKntDK2suJkRkFGZUJ5yvCIKBa0bvxB8i0Qz0DPnWKN9NxxfN
         G1dWhT1vgtUBZCgWJizL20l9EpaNRBw9l0f30eGwpWYxEdDTdnUWs0eQvCQ5I9WxPkCj
         FdYKOdkcn7xmKCVm4vXO6KlJjcj3pfVLWjxzv5/CQp8MNlJKGmIlynPFDTfTq6VJIAS+
         At0CtpaCsr0aM+P2xSSrxqcuCJqVf9LjJCexZV8O2tcSFJ3/oQED8iUBuT0TfJalNm1N
         Z+uStXIGF5fsM701X9q43eS3fq5Iw2NW6Bv6T55BFe5JmLJ8Ov7dMM51YH0uNCXt/8t0
         EKCw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=XcLrphLJ;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c000::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from BYAPR05CU005.outbound.protection.outlook.com (mail-westusazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c000::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-778019a6eb5si3358296d6.3.2025.09.16.11.09.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 11:09:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c000::1 as permitted sender) client-ip=2a01:111:f403:c000::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=tflhO0OiPrmJ8aMsBbcPA0WTkLVCrmPIzg70jmrggAOc7ixsXN1H79Zby6C6caajXXxydrZUwFsi2G3ZlbYT2/fCcdxuzJlqN/9Ar09pLlGBAWR4xflig4AWlVj9nn8B3c3wakU6M7/IczQB4DQrYxxoMn+DqENUQRix1iAUyMS87zA0LhnZJlXTiBM654Xme5WADjG10jVtDdfecsTdK/lGfc4syQMMz+GNTiLwk3wdOVKDnMQ1BEczAa+0ZGdn3ZWHdC/KudPQXkv/EvpcTgKQO1t5CAH0N7dCz43z0ndxRjLXtYBnluFuY6cASubpXf23GTVVlSyEhYxO+7BXWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=eJbs56PiGkpOK5+9sKNM0bbDf5X9UPIzyxQBTUs+5vQ=;
 b=nemgzA1Il3kTAcy2Vcd7NRN3eUxlzamFAdNOh4MyFQ7IaMNirETb3Bp8CKCDA5ywv2je/7pcmR5caoKDQWpustMnK/9gRKQp/xnZUG0kTnLk7MiqFK/Ab7cMkUTB+hknku0SZL4RrZBVH6AYktqTQ77fHwWcmx2dxNEumd8awlublT8K94xga0BPLZlWaOjr+yqilz7qSGhm6woH0cKtmv3wyOk+BclfNilwvzvfLrxKtHmhRExlhHSEI657goo0o0hpYJljRFjnw+wzGCztQgTTyvief1TeoRbxWiGNc6ztsysDG7MgmY6yBjQrcgZuoCyXW3a3gwoW+ZzdW8ofXQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CY5PR12MB6084.namprd12.prod.outlook.com (2603:10b6:930:28::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Tue, 16 Sep
 2025 18:08:56 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 18:08:56 +0000
Date: Tue, 16 Sep 2025 15:08:54 -0300
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
Subject: Re: [PATCH v3 08/13] mm: add ability to take further action in
 vm_area_desc
Message-ID: <20250916180854.GV1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <9171f81e64fcb94243703aa9a7da822b5f2ff302.1758031792.git.lorenzo.stoakes@oracle.com>
 <20250916172836.GQ1086830@nvidia.com>
 <1d78a0f4-5057-4c68-94d0-6e07cedf3ae7@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1d78a0f4-5057-4c68-94d0-6e07cedf3ae7@lucifer.local>
X-ClientProxiedBy: SA9P223CA0024.NAMP223.PROD.OUTLOOK.COM
 (2603:10b6:806:26::29) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CY5PR12MB6084:EE_
X-MS-Office365-Filtering-Correlation-Id: 9843905b-7372-4f4d-b237-08ddf54c1a6d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?zqe+j0H1PrmLyeCv47EBElzx653DxjCOGJmwCdrFPwi+DieR4O6tT3K+e2yl?=
 =?us-ascii?Q?whIJUVhK8ngLNfnGreVGUj4ZRyve5EIuBQEfMm/FXCNc78NF2HDsY+B8MRGK?=
 =?us-ascii?Q?pU5GzlmvvTFjGZ5A24d/Y8cItddSR/zHjJ20vVCbNzNQHRC9F1kr209KBgw5?=
 =?us-ascii?Q?8V5WlMU7w8cZl3UFpmkWHWh3490Wu3AC1L/ek9rpjgGot7Qox7/qDNLKr+rv?=
 =?us-ascii?Q?hZi6tcfRx77n1QpIM+laOAj0B45gHK5sgbZ232so/AOQZkGy3DYvxuvDoeW7?=
 =?us-ascii?Q?LyM42S3XRKHUIEV4QiVo5hYagbrPoEMbvFfGw2f5r3rx6Kps0K/jCeS2zHkj?=
 =?us-ascii?Q?qy3OA5oI/7PX0fiYoeo5ZA53aL3q6RWUcq8qQ7r/huwXOSaMCrWxUMcj8reV?=
 =?us-ascii?Q?9WFTe7ne0Lb71dKPjYDjoGv7ByOlEeFMGwjLs8eCohXdn9tb3LM/63XjdjY0?=
 =?us-ascii?Q?PEgnk6XYEouMgaC0j8JWJd9dOYf5XRxMBFmcIPw3e3JFGC5dkEIeLa30tH71?=
 =?us-ascii?Q?b9HffoQdA2qucrE/JgFSbw+0hgfx3FG32vaTu8CNMcTxY0HHS4XYMtIwXsg9?=
 =?us-ascii?Q?auYBp1gV53qIQl2lq3VKA3CCRhhfibvKQ8Fp+U5BhvYC7z0birQrFBCRJp4Z?=
 =?us-ascii?Q?AUgYNVnzsGbqStVLtvLcQAyMyFGcVstr1cfk+YqC3U1iXBtis9knEtIijVdt?=
 =?us-ascii?Q?MHsm/vD3MAR8uTQhSLJSMi4uxx2n4Y5GqmCqqA9swl8nAm/qfRbV/KzkzcOM?=
 =?us-ascii?Q?5LT4sjpudWdUMBCaJvIvfvTtZ5VivnpdCQAf1WhVSeGtMnAe1sGSQcMuI6Gr?=
 =?us-ascii?Q?qNVwz7fvNG4gvsYIu13pDU9qoESHyeirP+IiZ0A/qwstv1KaqvUYCnueyhgB?=
 =?us-ascii?Q?rVXoDMoI1fczBLs6OY0LmDBeV0XpG0NPsFr1sHcJ5gPj9mD9T8JRWMoP2c30?=
 =?us-ascii?Q?5qredbfvVNs05QToAaF1t2RzWKdAf+/5beuwG5Q75CpbuWcGY1KkHL0P9sZX?=
 =?us-ascii?Q?OHqEAxaTQWO5xUmNzxQ8KPKw53JhUo7tBtDByXjkx37SzRWbZAzkF3Tspu38?=
 =?us-ascii?Q?fnXVy/G58B1da2xcVVTlRrbHbPh/GJXAYZBsMjEa1Rv07GHHpJ5rs87kVWhm?=
 =?us-ascii?Q?fKO1bQyDnuv1rOnddPdfYzPnUWMFuliclrjd+7GHkYQxNLWdAW+WRZFOZj6J?=
 =?us-ascii?Q?goz/+d934SqE0XgRO0S2pfp/zhTFJGAjacROszevUblf2SQr7LAhbHfBbgw0?=
 =?us-ascii?Q?Xosb6DVh2N0uf02tgJtryQ/75G5hCS9LJeKXcE0zW0ZfwFikw60lb9djXegp?=
 =?us-ascii?Q?LL0xucJj1AgzHThQr72J/+pRO4OIF5SpRDAvGNzLGivYqTk5BcZMz/1hUBlj?=
 =?us-ascii?Q?+WriPK+eisSdaR2yOu3q7rAttEFvHdlSj84oC6UuYYlxcw2Yxi14M6Nqf894?=
 =?us-ascii?Q?pDeM8tONyWs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?XZ0gQ+81uXsTH+88XZfaiYuL20GFILyHIwsfJxNPdVRiF+q21D2kIJbbsbUR?=
 =?us-ascii?Q?PzuYH1xP2EIhYuvpPXHcoWx62OpNKYNpAwjOP9K8Y+/Yd90caD/MSsIXaX6E?=
 =?us-ascii?Q?SuY6F7J+3LTFgOeYwZlhE3TKgul7wj62zJzYDZ1+hvEbyESeH2WjsVLfUdeC?=
 =?us-ascii?Q?Ab28n97axgwA0+KKDT0qCdFypXoq19ZhO6LUFCAjofgE2izjysfkE8LQA/6s?=
 =?us-ascii?Q?4B4wC7eOpt2pyhwyZnbiSrR7tFnJ/UY8v7EK209l5UP1s0Q0eBnHhG3l5gWU?=
 =?us-ascii?Q?/u9bFGiqwgXySN3AoIEOjRehCD7VWWTwC17GI/iRAut5eDfCm58CWplKy5i0?=
 =?us-ascii?Q?xyi90oh6eqsqXZQ6NCG/EDerGL1Fo4W0LywRjUMoFR9OezWdLxnA5Pt9LFxt?=
 =?us-ascii?Q?yK3d1dymFglnZKvtY1xXTBQcmXXM9gwL/GVYQkm8NOs0AVKKGcFLdpEbHqq+?=
 =?us-ascii?Q?BzwBGpI7S/9acS0l7KMZ54SwhWojPA+r7rnP/YqsovPtUfBxsB3jQaTJvzDw?=
 =?us-ascii?Q?zEATzfmgcbhQvGAjAY8wIpSeLfNYFe6Xd8yGLUl7sSkEnFDbD2AZBf/jRGne?=
 =?us-ascii?Q?m0CmZylELKwajIMRw+XJNW9OfhyhlJu+9d2LvHHuHBKoszr8d9dMKjWmn6Gr?=
 =?us-ascii?Q?GoREwWumZVtFcdptpXaj04qWpniqRs1Ux5z7zP6iFfcdbhb3g5L6ODEpkmI+?=
 =?us-ascii?Q?5iJjYzoGIxsY8uEfSb8Glj22XMnOfv2J+dwv6rpwZm8gvMVpLpO/SxD1/TTE?=
 =?us-ascii?Q?jtI5RlzwN+9cDZVNg1bMbhSgt76xfEljCdJKHc8XKvsDo9LZa6m2R1D/ZN6+?=
 =?us-ascii?Q?zn2rLC8RfeQDo5fwydVTTYYe96ka8t53P02XI7J2W0nYOsxxIajnRd8Uky3s?=
 =?us-ascii?Q?BmClM14Dq8IfK+nZiqGykT4/6rYv/2kvhX0q/SDQNAc9ewnWw7tstTnfh+KS?=
 =?us-ascii?Q?vsRhPgDnHLXhYpBhqqOnPVy8pt+cz0lisOAglGCZ414hStOuqa2Pq+Tvia3g?=
 =?us-ascii?Q?paYM6w5FzAGQh6l/Ufw0faZTk7nTHaNcOqIs3KobpNmGlQP0Ej1Bo+tTE+CC?=
 =?us-ascii?Q?/jdjhh92edF5VhOcRsPKf1fYktWhYrwfRfUJSqfhOAln/A613B5hfh/FmUSr?=
 =?us-ascii?Q?XqXNCEAjJWHnFHhysRrr0XZJHnRym+vNpw7g3n9xE6lYStRqSUP+1aLe2i6X?=
 =?us-ascii?Q?VcG791t0EeMN3ZzXJJT2X8Q+bKO5gnwFKPB4bUNRxiCQPjckcts+WKlsebfU?=
 =?us-ascii?Q?yFv3VlHMjkIvF3IrqtQNFkCAg6+6iS1O3yV/sH/r8Te+d88DRL9ZIhV8PZBb?=
 =?us-ascii?Q?YF4lRdJWaaCPeHMWz1V7IaPGh4Ch8KgWr8IRs/Tr6LtQF6Vb3R1rW3B5YADP?=
 =?us-ascii?Q?XXrfcH3LjVUDMnJxGQ9PhlcEp+8M0uHrYQfCkN7y5Nt3StVcE7XeLnqO7aWX?=
 =?us-ascii?Q?yZ2tHJnfU9mO4NXJDNcWmJwli7aZQG1ZAo625boTpcxcae0MshyRsCLgtKix?=
 =?us-ascii?Q?2nw7tMNf2tYEy3KTXiSvqE4nY7uDGZo7YdtlHX+RX8MwGlNE/m6rU+Civ/eP?=
 =?us-ascii?Q?RZkUS6rwPK95wMh9v7GvTR98YpjYY8n2xyb63StH?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9843905b-7372-4f4d-b237-08ddf54c1a6d
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 18:08:56.7902
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: jD+g3iGDATEgOBQQcWfdrD3y7mCza8LbxSbt8VmMnU3JV0SnRV5GemxzZ5370arD
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR12MB6084
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=XcLrphLJ;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c000::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Sep 16, 2025 at 06:57:56PM +0100, Lorenzo Stoakes wrote:
> > > +	/*
> > > +	 * If an error occurs, unmap the VMA altogether and return an error. We
> > > +	 * only clear the newly allocated VMA, since this function is only
> > > +	 * invoked if we do NOT merge, so we only clean up the VMA we created.
> > > +	 */
> > > +	if (err) {
> > > +		const size_t len = vma_pages(vma) << PAGE_SHIFT;
> > > +
> > > +		do_munmap(current->mm, vma->vm_start, len, NULL);
> > > +
> > > +		if (action->error_hook) {
> > > +			/* We may want to filter the error. */
> > > +			err = action->error_hook(err);
> > > +
> > > +			/* The caller should not clear the error. */
> > > +			VM_WARN_ON_ONCE(!err);
> > > +		}
> > > +		return err;
> > > +	}
> > Also seems like this cleanup wants to be in a function that is not
> > protected by #ifdef nommu since the code is identical on both branches.
> 
> Not sure which cleanup you mean, this is new code :)

I mean the code I quoted right abouve that cleans up the VMA on
error.. It is always the same finishing sequence, there is no nommu
dependency in it.

Just put it all in some "finish mmap complete" function and call it in
both mmu and nommu versions.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916180854.GV1086830%40nvidia.com.
