Return-Path: <kasan-dev+bncBCN77QHK3UIBB2GUVTDAMGQEQCN3WFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 64A4DB81FE2
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 23:38:50 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-81678866c0csf60838385a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:38:50 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758145129; cv=pass;
        d=google.com; s=arc-20240605;
        b=KIaT0INGeJVgLmZhkpvU2+Z4MYwHnAtWWcOR6PFomXq7w+j2LUFbFbQjWQMZyYyDA/
         u88GCZ6x/gCbFEjuV1LzcKURdEqtDVOhGmn2wrj1608I2bfYxj+6dLYgTIG4kxh6k6A1
         FgGXmscfHQhhmZG3zG+i/+AeEVOu0KM6kOR7VTCU29mI17Bm2ACM62cSMMnSpjy+FHHR
         VrbYK9gKn0NogmAp4iw77Et3vxQZYeD7da9oDLrbI291ffGwj1MLjqfIBQf4LerUEFzx
         gSsWo/q9P1Sgkssl7Md798YQxmfWKsRlzy2kmsXL/MwqU9Lnsc9LM1Xz7ADSmzNyVPiA
         Rp4A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=MhutwJVxDsIgn2G5TDQRmGWcLtBnRirnFeEDPFJAOUk=;
        fh=EJTVmRTw+DbAxOYUqx+31o6T+rNSvANkEUmi4UzlSW4=;
        b=UdA8+JgeGYjbzs6EdvoJtsLtbndosMQYYkJMSNiP1cVjfAjelOPm/qeEbXQwePJQO2
         UthyD0GvxqOdf5A61C3sQDML+qZGZ5NM8quQKnq/EsFpn7CGtH8UzGnB3uQmUceYxqq6
         jaLItN442jG1DgQyhEAlht6JUvs7N//pmWqNBdsDxPpj9zsIMlYWI4VS2YGFKeNl/8Ol
         5xIKWn4BoVxzJGt8nCx0keUetY3j8/7ok5U4fqbjd/UOWGhf70xlR0OigEQ0RZn298NM
         rWvRfFIjv8Fi+CXdH7XRYDUSZSI+kreYt9Z3q+zWXBytvUdFhQzqeaCWBGw6RCOr1lGQ
         SLbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=DileqXqA;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758145129; x=1758749929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=MhutwJVxDsIgn2G5TDQRmGWcLtBnRirnFeEDPFJAOUk=;
        b=IMd0o2XxAW6DmvueBwc4ua02CbnYmeqMiiPKEAYXuwhHzURGfxYm9nwbzsk6HHDRZ7
         BxaFIAZOavRSIRtqjrndWt9OcZo1lVcHDsCEDAm56KofUudMJHiZW92PxQtbzeGfdPxj
         SWaKWzZv2WSK9WUdPsrtZSLzso0DpBObydnaIviPJdYzRFVkySHibupWjM5+OjaCZnDF
         N8jgPXt9bdHdNg+jAy9kHl14JQmi1A3HJxATAmi8TJY+pB84oRCbNj39x4DOPvTgrtrK
         5pQD79nOK8gFxXLa06KERXCRhtiCG9Eu1RdBoQxllpsjmpUcDVLwSkTFywvoOoUUN7tK
         uNiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758145129; x=1758749929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MhutwJVxDsIgn2G5TDQRmGWcLtBnRirnFeEDPFJAOUk=;
        b=uhDc2zP837Pu6y2Q2lqPCOfp5f17EA+C13EiaNOcG5pHHLbStfQ0niiP4ESkA15lRz
         /A1ukG/7GGaUMqs6wlMUGYMdmnnDHFSjtaDWo6PcsGtlVU0sLhAzQ70jkrnXr1GfnFpv
         HePirpBLmr3EiXVD8YHPLJJ3bO2lzgw5+pZpHIKmhcuJrQ+DG78mPDJr36cQnnIjbbDi
         nLa397IyFuU0NyG7LXRj9CbWjzh4dCqIIzdbi7r8hXK3d4c0XUNnaKKG/jVKzvho0ctx
         pi6FhwU4gIqSpEqpv6evjgBzCbReAfHCCpPX+rQ4ObIWgINLM3JhvmN6LeAWLMm7kZ23
         P26w==
X-Forwarded-Encrypted: i=3; AJvYcCVx4pyQa/h16dYKVCHbB6oFxtvrQYAMT215fgpi5Y34PVHXtJ3ScjE+vdbJNpYtRPEt7EVnCw==@lfdr.de
X-Gm-Message-State: AOJu0Yw2x6Oqy308mqYpyd4/E3ff3vna2TfgTyV/UqI776ke0dPhOMki
	VQ6qiVEV58U3tasqpv6Y3z5Nc9UPvbb58j9Z7miS8dtE6czSaXrdOypu
X-Google-Smtp-Source: AGHT+IHpNSsmQGTKCUKnCpc83jGSHVTzKXnh4TSZRWrdyFtyO5AB+IW07O59GvOkHfrsMYiaQcevYw==
X-Received: by 2002:a05:6214:21ee:b0:70f:ac13:f04d with SMTP id 6a1803df08f44-78eccefdd84mr41029756d6.23.1758145129162;
        Wed, 17 Sep 2025 14:38:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd68E4DxajuFnbZyrw/GRgSIw+t29yYxu7zpfNaHBrLK1A==
Received: by 2002:a05:6214:224e:b0:725:7cef:3097 with SMTP id
 6a1803df08f44-793361c5e27ls2876526d6.0.-pod-prod-03-us; Wed, 17 Sep 2025
 14:38:48 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVVUcy0T+cFbq7u7GYXny84OACSGzBB6sL4B+bIo3OxeRqVpHHW7luKD/OsWeJEu5/V+kUxuo0p14g=@googlegroups.com
X-Received: by 2002:a05:6214:2a4f:b0:726:9bc3:f8b5 with SMTP id 6a1803df08f44-78ece74aa98mr37776836d6.32.1758145128456;
        Wed, 17 Sep 2025 14:38:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758145128; cv=pass;
        d=google.com; s=arc-20240605;
        b=RHtRzZDWwQgW4ZSL+7tc+cqfIjXxaNd4XePVmpc215ejFuGybRqSrOcdt3rZgDmo1G
         n3f7BnaVnne8EBiKwPPPtAuMjc2zsSOcaqXHslrf52gz2pwU+yrL+9Wgz6sDC9okuZiH
         zA/HuUrkNxWDVq/JZESyH2KUkJaslZeHLSHn5OE/Hat9JK9XCbYkgtjRA+PzlOgjb7M2
         itk/0nTKwZbKq/Xhpn0YFTOlGQT4w6xKOZKcF0ugZsz2etESnPvHKz7DsZD3IqYOMWlM
         K2koLG8XQKsVOhtH6tYo0VAqdNCy7VVFC6pjfm6ysax6UC0RiJKVLAzg05oDFL5KT68Y
         M8sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lF5KVuXz/1zcfTw3CpjReV5CJqzjHk74wv6/Oxx0d80=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=Ho8jGBDpBqO6wSc+BRt0lZg5jL+FDWuiz0AIW0WkwlxhiaC4kojmjB8zhKEvuA1WRG
         AzFjzEE+MHQLyh5g99Xycms6uyhH7ELtvIXdmXCZIKAA7/74EWPdSthktboz21+poR9j
         GBa3j6/0lznC12Xd2/yp6akGLHoUdLzk4K2fLsRx36kz6+E/Jed+wxQI5ZhiQO0FgR3Y
         qZUeYrDgZzFgvh7qPGqB1XVLsgZwcLjbIPducfAk2yWMdnKfOBVyedi15FytrqzBFAwF
         Nlo+cSPU5FExw4/B7Xeebpl22o3FUVKVPXp6cDa2I/pp5IvSnjK8AzlxT7JVFsLOEQ6i
         0J6g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=DileqXqA;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SN4PR0501CU005.outbound.protection.outlook.com (mail-southcentralusazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c10d::3])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7934d1c380fsi208906d6.5.2025.09.17.14.38.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 14:38:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) client-ip=2a01:111:f403:c10d::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=DH45ewbwOslUcbwpcV2jFQnR1CdboL0OljoHbprUB/hWAkWoQsmzjAmy7Jcn96J5fdqWxVq07HRPZwLsoYF5a3P9WMbOtjfFISmE39BJBDqtNyMYiGQ+ZGLWXfPHLFc2CPAzP/b8se2x3P0d2/JvhTaD3Z4LAO8Zkr8HNYWB8MrDotRX8gdFs/QtxTJiv5v3u78jqTy5cZklhJ3WTdzUBPHOVUhUxs7Fry8NAascFGrdB/enptgueGuiiCK74ARN7peXPd7MbNr0xcjhZs0YVqTfPhzazj+jo2uTPsJZoGoC6Fv3dVn8CvkuTCtntk+3ngY9ENpDjPSGb9ZQu6qi2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lF5KVuXz/1zcfTw3CpjReV5CJqzjHk74wv6/Oxx0d80=;
 b=F038bzCz+167/rlkjvDzupNY5apfYkE0S3yhqIJbQ5JTIRjCuYKCTAhdDgsOAc/7nxQ7sROxcchNMD0vlXs0g0b9hsiY2G+RbHPOH5sZzdC3UjJF5Zwl7kWEV1lYw1tdXLqLnHVvQfKjWyWwxNT1Z8RqXI4Ffz5hxUJ0uGeUO8+GK7PDTvleE5FTo08hukCI+wpXVGFuMD/LcTznrqPlHYYk2T/a5RLIr0c+jFHQ4/RXDvaP7rN+LsxKhm+J57YCKgy89nSi4wB1KwAR/qCBywgwqycbuKgXIPM5UAJ1khNGrMbTCnVhqaL/QYf8vUGLmuTFSMoWLt0399nfOe66YA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by SA0PR12MB4464.namprd12.prod.outlook.com (2603:10b6:806:9f::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Wed, 17 Sep
 2025 21:38:46 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 21:38:46 +0000
Date: Wed, 17 Sep 2025 18:38:44 -0300
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
Subject: Re: [PATCH v4 12/14] mm: add shmem_zero_setup_desc()
Message-ID: <20250917213844.GI1391379@nvidia.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <fe4367c705612574477374ffac8497add2655e43.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fe4367c705612574477374ffac8497add2655e43.1758135681.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4PR01CA0264.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10f::25) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|SA0PR12MB4464:EE_
X-MS-Office365-Filtering-Correlation-Id: 9352092b-8e69-477e-afa7-08ddf63294bd
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?auzMi/sTWx/0AuN+gPFH01Vdv5ix4f6Z/XsT12pLBHz4vTY4tbdnzKyLrvfq?=
 =?us-ascii?Q?W2gEk8gE9yCPZfKE+X3AqumgfKfNEaRHGz1q5F9G3a1a6VP5V8s5bUR/s9oA?=
 =?us-ascii?Q?HVFHqvD4vTD/qNCEnnkyWtiNZHDqezQbFexp73rGSmmBl9N9rtTwC52mxnnF?=
 =?us-ascii?Q?8tX15skbFLJF14qr3UKtZBIWNeehiALrHFGyLTo5koGeRCauV+dfFiATmDvU?=
 =?us-ascii?Q?lHoxM2rO7A2jPqeBccjhU7iPVOT9UtaBTzVSpRu5QyPRN8Xrf12koFTTdiIF?=
 =?us-ascii?Q?/5H2Ff2uS368817Sac1h4jwTypXVLpjdnYtYcFAOI8rjOJGi9WOPiLUfGbHu?=
 =?us-ascii?Q?e1BydCnW3P4Ci5ZOFM2WMfkqIAzjoGJ+7sku8/3rsHDiXiBsoNyOWUwDHcIe?=
 =?us-ascii?Q?6ax6+C7zaITBgjcpzw3aGLZrD/Gk+Bt5MILqQvpqJZGeI9q+sJyoCU8Km2KR?=
 =?us-ascii?Q?+6qXI28EzF+VDDDgk9lybWG0mtcY7NkBa8s9VhoGHsSyeGzdH2GjnOMIjAJT?=
 =?us-ascii?Q?UKbMR8FbQK7CRQAKuU49zZrXwNMm6wikk3ECRms0fzRQuLevuAl4Sv6+Gva+?=
 =?us-ascii?Q?Agfe1EWB0JRr98bpkRX8SxsMyJbTJ//R1mCK1p7dvdkdsfFaw3B03s6bTmVC?=
 =?us-ascii?Q?6O19yL7SrRYl6hhbdy18MxDCEuJsUDqHdafD6cnbqpLh/hWMmVF4JhqIIBjs?=
 =?us-ascii?Q?sEURcxGoVNUTp5a66o28vK4nnboyaIphUt8DxcFy1+vMiGeOuUjvnbAJGdWr?=
 =?us-ascii?Q?s1iEWIY2rQFlBbq91oFhkZjdtcvwImBzhE/r+i78I88J9eDftZgj+atogNuj?=
 =?us-ascii?Q?1R33Mh7dEUaka9E+xmQ6Aq5KrLVTM+2UrVReDzFx0knK8cHMdDT8hlbM37py?=
 =?us-ascii?Q?r3DA75kO8EuZJG+u+WOs5MKboF9enbH0uJXqa1oYLTPd7SVKhXjEsxM2Wuxr?=
 =?us-ascii?Q?qiR945aopNOGfIkhZZB3sNsAmn3spUaMTTxvm/2QDKozL60+QqSY2WCB7v9O?=
 =?us-ascii?Q?Z18h5Kx3ZNw0yYBVvk58PE6luVngtRSy/VgUjN70xapb9ebIlQm4lfjdtmvI?=
 =?us-ascii?Q?kis5YALr6Af3aBtPtIv4EuToV2051R20u83phOh7BCufCVFUUSQnHbqR/WQo?=
 =?us-ascii?Q?hXzn1OFNL2wpwXgZ5p2WiaHcxKlKnOZuxOqe1A1zQnPFCNCzYVztL9KImSqc?=
 =?us-ascii?Q?kvel0pL85fPBG6WLyOrKnOCfAUkxKrfupTQt1fR3poZerOj0GashElmvFoWi?=
 =?us-ascii?Q?1coY9gQqYHlMJC5UEapSSFGgXY/dB4mTudi6iTISGNTs3wzQWODJHVarqsjQ?=
 =?us-ascii?Q?SfB2gYyEhNlj16IVFWNNdTkjT22jQvzkM4eD/FZBEHDwEKLs0gDyjlUFu6Gh?=
 =?us-ascii?Q?OuhSpZQfsjjABq7VYIabcKCIIhumCMYl37MLUpjWvjrtrXnAT+OkSPjLY6Mj?=
 =?us-ascii?Q?wSOuIA+Du8A=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?3keE6VgY65koBrB/8iiaINZmyzIoNpWMlyUv6b5pStE+fVQuHOYi5R3t/CTj?=
 =?us-ascii?Q?6WVFxspFCT4guWKrlFTOP3o493YzRi5CjbcvZ/di0vnc28X8We3EpwWA23VR?=
 =?us-ascii?Q?jsEG722Yi7Co3YhWuKEptTDilEsn9nH801PdNXZSibHGvMB/eS+pWyAVbYuN?=
 =?us-ascii?Q?bCJ/dHtAUblnqz/fvHvfl8ykBSP7EDTCk+24DBcbeJ+YI34F+X6jGFWRlv13?=
 =?us-ascii?Q?lKJ7Xh6fHPDvDEovee6GDRe4059R7nZgg0gJQMdh9mu3/GkOs8w2F9tkCz4i?=
 =?us-ascii?Q?RpUc9i/YcvsU4J8aLY8gcq2lWeqWdgPaz2KtmmdeY7Y8087wqJiLOXvdwA1Z?=
 =?us-ascii?Q?4VDEkRf82FX+lcXXCyH9Me5LmrGRLJyuFqMZlUeFWj+SJ9hQIiIrn6vQI0Dv?=
 =?us-ascii?Q?qzpOYRaIEC5y9yoZSgPS+lHhrvULyMeWfA/iggoOdc4PrR/nL8yYexojhubE?=
 =?us-ascii?Q?S0q1ujbcLVPqZ6zHOy+9gj/A2JMeGPsmfwzzRiAgu/labI7ZuTNiz77YQKQK?=
 =?us-ascii?Q?2W7TB/JeaWgooNFO4bx/XY2GNjYhfl7pk02uB0jcA98ZNBDmSedop7wb6X5o?=
 =?us-ascii?Q?AjYgTFuNCetlZcVvEJHQGTprPDB7Wb0SAcXwDqzcPDKVaKBHUdMQwj8NHD9n?=
 =?us-ascii?Q?NEtXQfgy/wqrTLGHNHkub2Wa+ipDAEa8rM+PpKXw0HeASgPDuVc94XDuZMtt?=
 =?us-ascii?Q?RHr3KkK0DV6uJykBGr92ckASugFRZNIM8g5Lf0zPAOvjJTHX1Xo8uXiy/7G1?=
 =?us-ascii?Q?BVy4AqTY0u+sDeFlcL3ECGPOb9ckp2jj4o2cS+oeo5Nr4D0zCjOEAnA9EPf5?=
 =?us-ascii?Q?VefqaOmEupFP+Vg5QVk9RR2IAYE1Eka4wGQojAW5KfxwSt7GViNSd5ndKDyU?=
 =?us-ascii?Q?y2/nY1M5GyZDMazbsVfOUTnVC1jZ7oYSey4saV4bUmFPTUOjk8k9bhz8VESY?=
 =?us-ascii?Q?feOKPoIZWhxRtG4JahsOkP5sjpW+RTV3RDUMegJJ9VsLeFv3kt3GrBoX7EBX?=
 =?us-ascii?Q?DbAg1UOi9TYTP8gZ/XdlDJ7mbasMtQgxW0H8O0WVR4C58dKiA40fnUnCNCxS?=
 =?us-ascii?Q?BnyEEKNAtvl52EI+mp5Ip267fA7BaMfIfpV906KZ+0ERGrvnZj4OBdW5PREV?=
 =?us-ascii?Q?1ZsXFw8E9QH+To3BmPaB9xLq/X0lRQI8WUmVUpG0JpZN2syIHi4SKYgyj8sF?=
 =?us-ascii?Q?1NhrdoZcC/6B8Lu2tHP0OGj/SJ5v61xShPsy4ILzz2iJPQ7nT8/YsAHmskcI?=
 =?us-ascii?Q?acm2aazGoxTak9rhGqSThCNg4Ao9Jtz5meAAqvwFxUULjAk6o5+a6gzKv3NS?=
 =?us-ascii?Q?k35IAYcxqTXIwu5F47DGoQwCX2FlJe4qvAyf3+0APmfFMN08tiHpXfjMdTWd?=
 =?us-ascii?Q?P2O7Y+Q7IS83/WBtiIXB1mbUt5XhuFbTYBifOInwCmTiF4DZVCKyUmD06uIj?=
 =?us-ascii?Q?eHUSDwAem2Qf1YndY/sC1cshaaepw4MpSMFdJmoJSm6QZg4RY25705r8C+cE?=
 =?us-ascii?Q?f1EAErUe5zYFU20AKrw1ubd9rLkKmSGb2jnc50hv/9wDQ/vAueQl1paSPBjM?=
 =?us-ascii?Q?OkdYuA3ALe11Gh9vQHI=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9352092b-8e69-477e-afa7-08ddf63294bd
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 21:38:46.2503
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8mfaXxn5rV+kc9WTkq0LNL/qX9Mr87eGpCFc+CFvYjNTfWN8j88+jmeXB6T9l2gp
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA0PR12MB4464
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=DileqXqA;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c10d::3 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Sep 17, 2025 at 08:11:14PM +0100, Lorenzo Stoakes wrote:
> Add the ability to set up a shared anonymous mapping based on a VMA
> descriptor rather than a VMA.
> 
> This is a prerequisite for converting to the char mm driver to use the
> mmap_prepare hook.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>  include/linux/shmem_fs.h |  3 ++-
>  mm/shmem.c               | 41 ++++++++++++++++++++++++++++++++--------
>  2 files changed, 35 insertions(+), 9 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250917213844.GI1391379%40nvidia.com.
