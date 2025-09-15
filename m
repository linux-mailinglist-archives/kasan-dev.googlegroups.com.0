Return-Path: <kasan-dev+bncBCN77QHK3UIBBB4WUDDAMGQEL4TQA5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B85B4B57BC0
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 14:48:09 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-411db730dcasf149272985ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 05:48:09 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757940488; cv=pass;
        d=google.com; s=arc-20240605;
        b=JCqJcRfJA8rhvoM0yhHbtrC4gi5N0Ejml7xOJfVZyXyFLhvG7N1N24RTIPBNAGRMXe
         DhBM1nYgsQPcjJIyyYQ9d4cRdiLKqWwcbAW9Xu1qvQ84lAOaqGCeMIRbek+eEqmCrLPJ
         EJjRU3Jds9ybMVxRg1mdonaeoHLR9X46QqB7yvkXQc0zLxv0p3QT8QCdIPUsIMh2pLGO
         jfHGt7qiaYijHEljXO7vWrQzKrGEq+Ui6/NMyyyZvyp3jnTxucuWeM9wmqBfKrKhqdxs
         UZoBSniCidp+NCFEnhM5LHGl5TYRfVIVScWMDZ1R633xoOsUg46W+//jsaFEQguWRRGC
         bmOw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=uBC0R0X8du4hsH4uFksj1LDvkEfYFDPyJyqxIuF2raE=;
        fh=mJQaeKsQkzrviuRXMIGU+t09htPfcd+KdJfGoR3/anY=;
        b=KWRjIFey0k24hxYEgjkOauxdAi/JZ9a4S3oWfdfomDXmgG1Lx9gv1mvr5Th1HXVaPt
         V17qwkENW2YakY3n75/HBes2h0vH5DG/sQpBC+/VG/oMslh4Lq4N/HODUb+BV1ONUJI1
         8wxM9PqsiOnDQG6LpOESU7RiJRh0JUxbkdvch9otHUJWHx/PNMDw2zE4N1/3nMvo8G2D
         gWzny5wa7xKkpBY1j+9ozKlmvhfTZVh87PQvGQKIaN0XaAoC0jDoqU7072OnuBR+WI7L
         ME9qbbr9l8SHTOyt5ogFDqyrvWu8JFwTJo6z+OphMFyJN8Ze3x0GZYaFitK0ID8hrG+z
         nAJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=F2BY1gAt;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757940488; x=1758545288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=uBC0R0X8du4hsH4uFksj1LDvkEfYFDPyJyqxIuF2raE=;
        b=LVSPj2UhLS9QSWzst9er1g83BZVPG4OzJjSeo40ZIa2TxVpyPafBIBufp7aYfmFoJ1
         ZQqGHFNpWehNTWSVkQenknuYy3FAKZTrI45zrKxAhYEBquUn9xL4l8nxhayix5Z488Lc
         NvGHsJdxLBQmir/kbhb6OdwW/8HV92I7N0m30q3oYXGBt7iXDinUi6U1hQGWGrIhOpIe
         kRY6V5LXQY+wC2LkcQ9Te8Ae338Ba+s0LbRzB7s8ONhK3VuCa5A91+JqYndDKmVfj9aH
         kUdEOJ84b8MMJ8Am1mMHQqHvu3ATL4CRXZU/AmcBDi5zaSXc595YYNjPvtXK5zmfbxxd
         HFGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757940488; x=1758545288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uBC0R0X8du4hsH4uFksj1LDvkEfYFDPyJyqxIuF2raE=;
        b=nSeD97ONbzcIPCt9Xy7rYwYsJ1GjcKnNzwW/0xcxb05fuixf5kSh6zUAOs2FVpg/OG
         kJxoHYyQQtdVgS4V0iCbChIdjOB6Dq0iw8STr24MsTCVrHOj9dsOc6XEwUhRordW6jmt
         xrXVCjTs603RGHFqfUOCxS6msqP0LfjKGBRQImXiaFUCwsi7hiESz3A6L8P5wK1sGNC1
         aPCGfaK3/9ZXWUIgVHnIQt+Jz36kLwn+Uz1hdtFmT/oA7DeM3qYbPWJ5LmS21ub856n1
         /thkB6sSHHXrtnX5cVFc4BSDji0C2tLpvScKfO6GwxvQwbbCDshrOwezGAOHeGgxFihh
         9Pyg==
X-Forwarded-Encrypted: i=3; AJvYcCUO58gNkid4pNUYgjMynKhMpFgLmZ5u1lFuZR8G7Go4lngBerihZMxijuncNdLFRmUmGaUO2Q==@lfdr.de
X-Gm-Message-State: AOJu0YxTqTOQ0R7pbiCSNuwjOfrzPJL1T1SN9/l+xsdh/TCJJRbZLVsI
	SZUK6sENzaf1xsBkoeQ1TSuTEPkf1m9WJpKfoFsD/nC/846XdZJVtZDs
X-Google-Smtp-Source: AGHT+IGoDrtc3PUMszh2I5IFKURs/5BgEP6sFqcPS922FONgxKPQNE7mi/MyVhxmE4XzfZl9H4e2KA==
X-Received: by 2002:a05:6e02:1a07:b0:3f8:b464:6d1c with SMTP id e9e14a558f8ab-4209e8347b8mr159806075ab.14.1757940487840;
        Mon, 15 Sep 2025 05:48:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7MLAs9kzXJtHQuD+v6JPyayVcgCOv53fmrZF7UIMcxPw==
Received: by 2002:a05:6e02:3e8e:b0:424:6b1:5287 with SMTP id
 e9e14a558f8ab-42406b152fdls5749085ab.2.-pod-prod-01-us; Mon, 15 Sep 2025
 05:48:06 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUFv3rJI8VPBKIE8ozTC2P8lA33j1fg7vliN6Ry8U3l1BvXsdxMkBpVXgUixtR+t+8xwidpwkF5+bc=@googlegroups.com
X-Received: by 2002:a05:6e02:148e:b0:41e:799a:81cd with SMTP id e9e14a558f8ab-4209e834237mr148707295ab.12.1757940486788;
        Mon, 15 Sep 2025 05:48:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757940486; cv=pass;
        d=google.com; s=arc-20240605;
        b=ClEsIcSz6y2RPagttEFCI/JjfzNKw7SGMBFNVodFmnzs9LhmuOm6pI9DI9yzNgt2U+
         72wezjgQ8SpW+mykavyFUpGHM6rhqAvs3vWLvJwLtrqjFfPzHC2NUj8qpxbVpl1xfnWu
         J7YTcsbGeaKJQeDcNsriZaoF2oANaa325P1LRUrE7XrxxCDnKl/NhV9xzTPv9Fq/UfAN
         uHmSKtQObpVV9lmR19xMjSr1rl8RJjTPmdJH6UHp9XmnuKree7tirtVW+O1jVI6qXCIN
         yJH75usNGSC6VL1ttoXAW9XZMiqca9AowiXRqkMpiWVWgkMX8+9JMJL9auPm01RWBDop
         hsqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=u8VVEzO9o/35ttMOcQLCNrppJIx203qCXHmmvtiGP+Y=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=fuBQyCAQfoQvcJ79nNstwk0UyzSz2nHpGuvB3q3ic+Pm01AG+xWgBRqhXwmyj/ftjZ
         NA/C/PPC9dMMIMqpVD78DoOj/Oi7qJ8KyCUqb87OLzVUtl3GKZrIKMoquZU2hOFLIAHL
         PqviBpRtecme91G0O3F9nVJq++q3BwEMOiJTvXpT+KSqTVZTwTJ+NW1TAKGqdgWY/UC/
         cSPdC2PfW4UzaScW0Kj5Dxzp9X4XB3cYclvgVusnUd7KAZ+mcidS/5zMOMJlpRa0UP5f
         j0FPzdFZoxnWVRVGp5OQbp5xdAJPxogqQMzeuxSrmSkIk0hluaBvJMc+VFQbQTGornwC
         5pqA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=F2BY1gAt;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SN4PR2101CU001.outbound.protection.outlook.com (mail-southcentralusazlp170120001.outbound.protection.outlook.com. [2a01:111:f403:c10d::1])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-88f2a5e7cc0si40658339f.0.2025.09.15.05.48.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Sep 2025 05:48:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) client-ip=2a01:111:f403:c10d::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=dlSIxsCR+FzVFz02fh/03m2+Bner2nQrcojaHa+yVDJnOjL7Ihh5XN2eEWwooGymo1l9eLZ7pPGiYzrX/8JY/UJoro2Vakjqwo2veKc/5EjUDu8MdXby8cfhq7oRvjhiQ/DCezAbx1ynlRsKzQTkWgPAlnLlazEsjXnA3Ym4gYeyQIOBFEP1PxTyyhqT724vv7VbVbhL0lVbMYM1ebc4zlpEESZEnzIigfM+RG4k6FZ2HFBXnE50+8Q5jQePTWq4ERZ5gJMnpJcEwpYiIO1pwth3+TAO/tfwcDiKST+a8tbUhvEV+6QN7CJzCvIlyfb2JSVZGScW93QQYS5pcfPgmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=u8VVEzO9o/35ttMOcQLCNrppJIx203qCXHmmvtiGP+Y=;
 b=Ddv8Km1pqYUUqB5sr998b6GFEDBoqI8V46DDCl3e7jvpUvpE6cgVaHrp6IQwLfDAR8AbiYgHZz4B2k5R7IspvK8j3EndZmUgePo1IznukCIdx/MTm49m7bxTXrA+y07BH08oQ7x7eLEyEiNW5iFp/2+4KGOOlUF+j++KuF/OMnAhqJCe92jOqZS34S8grURZeTVUvz/CR7lApo8Ym1nzNJv1n5wnfcs6R3aUo5gUyIKAuwHJGFSgymWja6RmzcnAi5dv3JfJaO5NaZwg+5FvsYQ9R+lriz+x4iho4xiuCFU93tHttZZRiQ0q1vKd2PbVkT4whjrb+sSFafsK+YbJzw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by PH0PR12MB8797.namprd12.prod.outlook.com (2603:10b6:510:28d::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 15 Sep
 2025 12:48:03 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 12:48:03 +0000
Date: Mon, 15 Sep 2025 09:48:01 -0300
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
Subject: Re: [PATCH v2 16/16] kcov: update kcov to use mmap_prepare
Message-ID: <20250915124801.GG1024672@nvidia.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121617.GD1024672@nvidia.com>
 <872a06d7-6b74-410c-a0fe-0a64ae1efd9b@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <872a06d7-6b74-410c-a0fe-0a64ae1efd9b@lucifer.local>
X-ClientProxiedBy: YT3PR01CA0129.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:83::17) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|PH0PR12MB8797:EE_
X-MS-Office365-Filtering-Correlation-Id: 47b0046c-5032-4fe6-4a90-08ddf4561c2c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?h69OqifMYJ77UeoUpRuSUzSeSb7tiVa615I6hYAzwR8MdOH6gW0D61yooP48?=
 =?us-ascii?Q?p2a3mL9kQB7BFSEbEsOXkgPhyVIwoDeGL91zQtUSUYQiHGT3PIdSdukpRKeQ?=
 =?us-ascii?Q?6Sa+XOSAUPqMbuXaZ3pJBqlTxw7UJ400o981XTveJtFaJGsXgj9+LNgqcZQW?=
 =?us-ascii?Q?DNbnh/aVpHUXW4jdeR7rVFsIyttbpu2isVo+12Re29YAT5SX6i85D0X8d2RS?=
 =?us-ascii?Q?wMwifiw1KR1PxphYJrjpTV8xe4Dkf6CWW/X4RxJJ0T4JBrou+XbCa/QdhOE1?=
 =?us-ascii?Q?7jwpcMajUbCLrq9c7ptog80tZc1FmUKylCmvj7PM/3qIzyWUL3xkb0GTprAY?=
 =?us-ascii?Q?/sjKCNskD2K4XEjB2ggfp8D1eezZ9fU4c8KZuJbDR9SS9UpBkwPIg0KYgU36?=
 =?us-ascii?Q?Ksu6piLrmaVIQUy35jjt/bmfpeCo41wfWpRndNDIrxe8D6oRgSTT1UramCz3?=
 =?us-ascii?Q?rUwmH75mGac47qc36ywNePNNBWYYntSeVBaFhBho6xh/XOMXhe3AwJ4eLGVY?=
 =?us-ascii?Q?qqqjokf3oR/vkmDkGvimHfVm/yaAScMBTZOU6S+K84a5WXnsOmw4C6AK69IO?=
 =?us-ascii?Q?umnyr1FyfJrqUeVqBZOFNuNq4sSw/u6iD8UzqN+S0yY077xoztTj9L7VNZzN?=
 =?us-ascii?Q?4rWRwK9w6NCOZ1CfpWINuJBFPQX44IsZoCnjaKFp+VUk9bswYyfnMvaMEc0r?=
 =?us-ascii?Q?lszc5vap141CeUOVbQ9d04i5aG5cNSCQ0b8oNzTZLDvahCOkCmfs5ybwF3Mp?=
 =?us-ascii?Q?Jmr15dQTwb9yvTliFhWzOErZntnWZH9BgkfqG3/aBOnsyf6HXvBlhl6BDXe2?=
 =?us-ascii?Q?PD4zfv2T6XnNrZ1lH6RFkMcxOnhnZ8udUCIVcEwobI96BsQkXtUoGnqBGhMv?=
 =?us-ascii?Q?oG2afYTK7ADVFOTSdmFXTqlNR3S4Eh2fRnUBa8c4r9nUm8Jixthxdlooct79?=
 =?us-ascii?Q?CKmo/bI+qmZHwrfUSjNcwrahPW7bEWwcNtUD7A8o64MX9oz9XMvNykMYT59N?=
 =?us-ascii?Q?MBqQg5N4QSCs13wPzMnkbR8GGD4Q7aTr8ySU+I/kdIDGPSY0J9V8s69Gsob4?=
 =?us-ascii?Q?RYw8RuuGXtJwUR1kDo00QXnOWMPfGYkrwwHI57wP1k5tTEVr1rbFCCIxVT0R?=
 =?us-ascii?Q?PXqX6zSk0wu7eS4QH4d7pYuToTnaaAdUGqaz7gWd0vwSMOadmcuMZwKLT5nG?=
 =?us-ascii?Q?egv4D0MCecVXy+7ymclegsHVJwO9GS60eZsGb6gDsF44edGSELzEkU2ryOpT?=
 =?us-ascii?Q?kinGfbNGRWnM16sO3XUwZ2Xj5x2GgUcOjpnvLkUkGzkOToZFfkUh8hcpMr+m?=
 =?us-ascii?Q?eJ7lylSvdm349sFbRKjxlTNEnLJybVac/mUCCKMIkqITj6X89EUt6pNsZzVL?=
 =?us-ascii?Q?aheissS841EFHtMfEDIBApnD5zem6zQo/Uyyubm56XHC5ST3hrDxzRGxjkrD?=
 =?us-ascii?Q?sDBFVrlqHbQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?VRWn03OitKYRA/DwuaRE4Cz5hxYxke5N/q7ey/Z9o3NeiogdaYuIuN3b3w6O?=
 =?us-ascii?Q?vcH7/9gKtxt80vCJOGkoSa5jVEOS8npGNmbSQwAYuG4xcgDiJI/kjTeneB14?=
 =?us-ascii?Q?6PtduwEZ9Qjf1X7Or6XaNpDFULeXuc57I+i/Y4DLN1Eh9XqWoU/oYC6zUW6W?=
 =?us-ascii?Q?6zQSp8rStAtgE6J4r5VAXo+HQUJNMIh4i+W7/c5QMSOCOa1UUGa6M1Ha7w4H?=
 =?us-ascii?Q?nfYvEmBa9nrkUwmycN4NJv2dW7cbpRuWGaJqlYtS6GyZpl1OVfRTD4t/W3Xt?=
 =?us-ascii?Q?bAbuOJovwi5hqRu2b8Blj9IhdV+MuY7xaw/4zO2JQQ+ztKMRxT/OWHNL7D/6?=
 =?us-ascii?Q?++M02t3H0wRIEZTLIBDN1qpulzu71mRouTohx2icrvQ6uNjSzBAj5sZGRRC2?=
 =?us-ascii?Q?/ZrUQGfkWAh80HCOUvU4c27xV9J+Os904X9Yj1gIDOZ26ST3386hOqfLvuJn?=
 =?us-ascii?Q?DhlMDquwC6N95vEtk9Bo9Hd1QmgLn3VqL/R3Ydbn72fUGCaSqNQNNy48eWLQ?=
 =?us-ascii?Q?FJ2/zGsbWNlYDeCv14SazZOQ/tTiPgKpISD0cIa+oUvB6Ra+OJ/MJqDRdUOr?=
 =?us-ascii?Q?URXZwn6RjWnRdGwVYwobyr1RI6rEC+l3rcZsWljG8YEFQW5Yp+7hsNgFCtdD?=
 =?us-ascii?Q?mqlRZTtxPy7dt4HS5YfslZoiEh5rhJMLT7eJZVUDEcSzMbXyElIlGTFp2rCI?=
 =?us-ascii?Q?kLz5sRg05Gat92uRQ48Awq45oR0GTqpohqckpPODcqxSfRrw2ISO13QMJdVs?=
 =?us-ascii?Q?Qxke30Q9p/RCFMpVpaBnx6oecxI8TFbyoCENqlwAG80+uDkBdCnHCZe7UJN/?=
 =?us-ascii?Q?YBODqs8e1Kh6/jQnMZfhrRJm4IjIJjN1jGIDjEYe6EJ1EePWA1AFpD4cBGs8?=
 =?us-ascii?Q?v0J1vFjK2+5cvbbhEkDu1zrUGuqkEIKCw5FHXLCMnRl6gzBLMQsxUupBZQvL?=
 =?us-ascii?Q?EnyeIvO5Fkqkih8kIkAqk6rdhbn+/ONDy+xvIz6kZHkJlDIzNxMJ+sYr5UAs?=
 =?us-ascii?Q?rxcR4KMNO0CCHH/qjXfwFz3jhopelZIM2UI83JZ3N2ISbDddMJuYYpKwoU09?=
 =?us-ascii?Q?W5bmc6JilH2AZGPFNE9GlHGcEGpV/vAE75WE6jyxCOhN7xGeyPxMvHYWNc0l?=
 =?us-ascii?Q?5iwFn+7Vv01wSTcvuSG7x3vz/KFaAzDM2T6mjxfm2FTXUixrYSII/rcIDk46?=
 =?us-ascii?Q?G645bU1aiZzTvkyLTA/kkx0qBxsvn54HHsFzAbTSMjX+gmlrhYejhT7bV0fZ?=
 =?us-ascii?Q?7X53i8vx06iJUfF+DLvswGrND4tvkus/ZFfFckkRZnJy/5fuflApTbC3zZWY?=
 =?us-ascii?Q?6aAtj9rXUUld/CjFcMzGfYEa82cf+elD0/6MLo2/h5VeTEp37jBh6RjBxiBK?=
 =?us-ascii?Q?RqVCQFLLzaacsd3mTrW6ENKOukVGHSHi8P1ykTmgwVggYagRbtC/KjXCchz/?=
 =?us-ascii?Q?K5U612uOW1On5OVXjUoQmcqxrYnENWHRLUiLykJkcMXVzZEmW/F1adD/DPML?=
 =?us-ascii?Q?SqD56ktlJnUaMPm8HNZ9hvaZMYSwwr2Gk8Vki37XiDK6asijXzzyYJO9I2N4?=
 =?us-ascii?Q?gGONw+NzJyG8YnMPhx0=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 47b0046c-5032-4fe6-4a90-08ddf4561c2c
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 12:48:03.5144
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: mzogALwuNUANkerB9kJgREo0bYyzFJppK0PxFsRPgsC3FoO4zqVXsW11aSVktkt0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR12MB8797
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=F2BY1gAt;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 15, 2025 at 01:43:50PM +0100, Lorenzo Stoakes wrote:
> > > +	if (kcov->area == NULL || desc->pgoff != 0 ||
> > > +	    vma_desc_size(desc) != size) {
> >
> > IMHO these range checks should be cleaned up into a helper:
> >
> > /* Returns true if the VMA falls within starting_pgoff to
> >      starting_pgoff + ROUND_DOWN(length_bytes, PAGE_SIZE))
> >    Is careful to avoid any arithmetic overflow.
> >  */
> 
> Right, but I can't refactor every driver I touch, it's not really tractable. I'd
> like to get this change done before I retire :)

I don't think it is a big deal, and these helpers should be part of
the new api. You are reading and touching anyhow.

> > If anything the action should be called mmap_action_vmalloc_user() to
> > match how the memory was allocated instead of open coding something.
> 
> Again we're getting into the same issue - my workload doesn't really permit
> me to refactor every user of .mmap beyond converting sensibly to the new
> scheme.

If you are adding this explicit action concept then it should be a
sane set of actions. Using a mixed map action to insert a vmalloc_user
is not a reasonable thing to do.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250915124801.GG1024672%40nvidia.com.
