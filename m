Return-Path: <kasan-dev+bncBD6LBUWO5UMBBS54Q7DAMGQEL6CZITQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B458B521C3
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:23:41 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-7273bea8979sf142084856d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:23:41 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535820; cv=pass;
        d=google.com; s=arc-20240605;
        b=h68cR+1WP1KTLfiMNewy+kjTCeQsTbzQpgtwKm/J7C0CYY5e/U6A/DZ0d91zcRJjv2
         LjwtSh8Ctp7uBfWTldpj5Zwn0wxQ32+celAjQtuhW3+O82gNHbDvd/RfWxYtlPXBZKVz
         kUuVImEUXKoV8xZwACTERam6x8MlkCYHYLsM2Ft/gBNzxFDs4QNSJZgKdeqYkf2GvAIK
         SPDKAJaWRwzwzYBp6M8MzEP2BUxgFk8TrPTvh6Y+xVBc4xn9vhrWmuMx99/6uMGDqGgj
         BAfPZ+dqGB0BIStXod1v/1tzIhOFS4iAXHM6a3qKKK8UV4ItFXnhNCXXQ3mH2/oVde7i
         WAmQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=O80AC42FaEM6Y9p72Ny3mza+kgVwgLKAIAEsn8loER8=;
        fh=c8QjbFvOxyJ7qqsz/Ke+Y6GADhdL2ilDSjGyj7Kte7I=;
        b=JZdOq1R6K+wC4H5L4QW7YcKeWSYyLQNOs2yhOZ9dOP2yty1HyHh/eRykj4eNc2RK2L
         435OnHqKgson9YtcMfsrKuekjl83xJwC3/rhvUU7sQ0HsxErsTgmhFNDhTr7D+UXtwOm
         Onjd6wxPCRDoM1DDhz6X+uiRgfCAF8hZ5RydGWcheDRri7GUN9RnIZobYnMvo9Zpcl+U
         hQ2YVsJ2gzrnmwdWIKOPq7ZNprqds/Qc7c2KTBCYsWF17ekjRD+7Hlqlj/3rX/knfavc
         VKLXNjsW/AMp7CKmEDu8b3oEcTpuldL2t3MinCnvopSkLFQSQwkb5vTu58PZ9Yk7DwNK
         gDqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=CJTd+DR8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=lWobbSVO;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535820; x=1758140620; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=O80AC42FaEM6Y9p72Ny3mza+kgVwgLKAIAEsn8loER8=;
        b=E5Syu3smtwTxim4JIsvKfel68Xcchy4qqnbcklX+NjNEVC8K3WLTefCBTwV0iYUzYe
         FH800nlIgSoYFyTmQ7mkrLZ278ATt1vxIcE+2DkIBzoCflTpAXbaAXKCjj9QMQLHh+mn
         lhUbM5qpzxnMk8IlVOXXZaPg5EjTLiFNWGa1Zvi8MO1GUHZK/jCZXIkKrLAGhsdNrMkW
         4K5defg0oOhx7xX+uKHzTo0hZWCq76AhHX543oTpraeXAxCCZTUKE57OccQ7o17xhy0Z
         /49ue2TdolMxEUQ9+ULRsFdrLEB2X/Q775tfklUTr6WsVJcX1tsfM8ELOQZSVCCFiuOr
         Jr2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535820; x=1758140620;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O80AC42FaEM6Y9p72Ny3mza+kgVwgLKAIAEsn8loER8=;
        b=pg7vJR0SoPRiHaYvxSHRT9XYkrw4UVYaynAYDba9dYgK/FeIOCtCkT6PN5v+Aa2oEx
         pdeQFsAmhIkQJcCjBglwKuvIQtyqFDRIQnJ9927elBaul2Dw8VQZDJe3296EAPIYK1qN
         fFwemCC8ehG4xyp8ZAqDkOpsgBHdycL09XcZwO48HdNrQT4AN5VXkznhEvyDKUHeC2bn
         3VCzBNsb0HsXJJWWQFNPL3xdb4odi6D3HwP5E6ijmluEOE1Mr52/An/RWOcnjK+JEo8O
         baPwrfXVx27hYaWhEWvS4VYeb9Hiwq41EPK+AWMGZaTt12oAUZ/BpQWU+1VCLDZsAL6M
         ME9g==
X-Forwarded-Encrypted: i=3; AJvYcCWCBYUYfPWaX5Z0FrGTEgeXcL0KmFHM+ZJIFK4t4FMF9OnWJVYEQuMlfBIhobbV48c0y8GBuw==@lfdr.de
X-Gm-Message-State: AOJu0YxvHHwiaHHtHai3Ql21n+iKDUsqjWm2M2kdoOP1DyWMoXfYmWob
	YN0UjG9LEBX6epuGgia0VW4w2cyfyhsqmXgupIctTWLfi9ZG1jtX5vGC
X-Google-Smtp-Source: AGHT+IE5TVYXxBVgaDlBder+GILw8O43GWqH0yma8/U91WzzyAU2Qg56hKNKYGz1IIpyLpHIn5KXDg==
X-Received: by 2002:ad4:5ced:0:b0:726:91d:bdb8 with SMTP id 6a1803df08f44-7393ca9c2bdmr178798106d6.55.1757535819717;
        Wed, 10 Sep 2025 13:23:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7cVnKfWAEt9ql0750hhp7q4a5Cdqxhi4o9zb6+/uKsWw==
Received: by 2002:a05:6214:d85:b0:70d:b7b1:9efb with SMTP id
 6a1803df08f44-762e46c4b9fls1047646d6.1.-pod-prod-07-us; Wed, 10 Sep 2025
 13:23:38 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX37+dpAwYwzmHZPDEP+OYXn0HCQKDcLcMaLyDcngRoP0OSknkwuwWrRaNhshM66xmrTjoHiVenGA4=@googlegroups.com
X-Received: by 2002:a05:6102:4a98:b0:4fd:53e0:b522 with SMTP id ada2fe7eead31-53d21db63c7mr5404879137.19.1757535818209;
        Wed, 10 Sep 2025 13:23:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535818; cv=pass;
        d=google.com; s=arc-20240605;
        b=JzjYH+ksE5BQgAHGS+YjhD6Ae2CiKoSS92c9c83LZ6GWvZ1DA9Qb6c8sqUMkLyblxW
         Ny4DClqQNOxNh89+gMBh4MZP8DGjjFU6WH2D3d/I8GsRZy03jlTu21nfh4WHFH7zkx5D
         7X1Mxnk5wZZtREbmjqqZMK9E1kteiDv1tnBIeO6XKoISrmoPsLA+S8c6iJNSN13q0jBR
         +PIAQTutoPo0C02DSHZ68bDkCygyGK3LDeK3OYWd4QnvJeu6xKOm6Tv+o7zE9cPSvdUg
         GrN2IX7toVQg1HYlAXlJ0z3QoYIqufekruQqlj3ISEQvHfBPXDrDPKTX53P/4wW/KMcE
         v8HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=sNRgN8ww4NFZcyigkZ3PExC6K+MQT1o42BfSvdw6oZw=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=DFZWHdzKjOj8S3L8aPMUWWgjkvuobfPuJTp9bRAr57FQ/CtS+Y9PD/lXZrb4ZH8Gi3
         GAaGYogae98/CFdT3YQOwP50oOfNvfw10iNyoJUz1LkXr3ZQh/sYsHlzneOY+dC/gxun
         KcTq02KuHmudR5ovDQyotkXcGlzSqxKEzQv0oyQsyi71SfRt4kbojX47tQm8bCsVti13
         DFoHTxZ6Hsi9OLtbJVl3YUuNbpPEshvJMGJidIWgitlFTCeQDnoo2OVNPA+HknfyTVnu
         mi1ZLPuqJyr67vPuDyDV62iHVM1G7N81E0h6I6DK+SYjQE44CJECfumOQ0Rd+PhTpuqv
         oyCA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=CJTd+DR8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=lWobbSVO;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-52aef469018si1288442137.1.2025.09.10.13.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:23:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfpW0009838;
	Wed, 10 Sep 2025 20:23:29 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922jgvy4b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:23:29 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AJfi4Q002816;
	Wed, 10 Sep 2025 20:23:28 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010005.outbound.protection.outlook.com [52.101.56.5])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdj1cg6-3
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:23:28 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MQIm3sQKlRKnJoD4vZaIypCT0BX27c4/+yeSmNPp2bMUno8jjWmPC2yQXjVrWnwqABtuCy7gjf+dgra2Iz/SXxp12kj/ist3UAS20EZl5kTvWlLyWZydZi/n7xKQYUFGE6tinMj+4SnYFrO8wc9b/gkudn4baiD34uGuIs1NO0wQwF4ihF7LHNjASSihS4KYcu76VJb2gDWutgQWGjz46kBpydRcfcGXmZ/V9l+oFfx/1YO/MSC/QaBzKoWZlAYWMpmT8ZuirKrzyxitXo9YiB0qz0LCbHPxq/GPA0IZOJvOWYWkdOFAASQd/QjxhwAYPqMvPc8jJh8oBssRtn0rcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=sNRgN8ww4NFZcyigkZ3PExC6K+MQT1o42BfSvdw6oZw=;
 b=zCWpy0X6PhxD7Z6zybt+LBukzHZn/Jrp4O311G6OKxXdfGJc0EWryMKRwmUDI6NhA/hpUiQVvoo1X2IveVS9VrUvyOVJvUX6l+jiUO8zdxtgd/m+5QsKr9jjJjInVQcZ8bpB92vQzBjLqC7dFN7byw0yRDtptAFmvrk78xoS6Mt4+l533HV1IJTtYvnBu7Tlj7Wno2acJHZLr5Y/dtEFnc8M7vnuX7dElh5CnJv9gKYY5UWBmJnkL4QmIgl8Ooh2soyQ71lHTTMndWzi3VnR8tsp29a91IeI6Tte26uSDj2kzuSKTHfZsm+yaTIdFj3vb1dsZP91ke/usVTEUSfOXg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB6278.namprd10.prod.outlook.com (2603:10b6:8:b8::8) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9094.22; Wed, 10 Sep 2025 20:23:03 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:23:02 +0000
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: [PATCH v2 12/16] mm: update resctl to use mmap_prepare
Date: Wed, 10 Sep 2025 21:22:07 +0100
Message-ID: <f0bfba7672f5fb39dffeeed65c64900d65ba0124.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV3PEPF00002BBE.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:144:1:0:6:0:10) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB6278:EE_
X-MS-Office365-Filtering-Correlation-Id: e31eea9a-841a-4011-b571-08ddf0a7d79f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?yFrn9FDcbis2xWAbv9I7nf8a64mV9tbWHZ3qTXeVvunpjDY4ViEw+zscZspe?=
 =?us-ascii?Q?noRfa6o75DWvfpDGbr9IOCP2un7nUfTemtdqHGttRlwa3hnl5NQC+6+rRJwo?=
 =?us-ascii?Q?XsZ2MhEmkzy6zhPfA6jc7Y+8dJ3ocTisvVFxjrow5VX2y3bC+Cu3XL7ODFJM?=
 =?us-ascii?Q?oiD7pe5i2woO7+y/0sLSoO8AiFG0cIWSvD/xg2x6tDRHdGAjE7kpjwt35Kfw?=
 =?us-ascii?Q?DX+wqc3W8kOSaTkvkCmB7Jh5gNS4CnuQlgcddR4u2mEdMNUEDT4d8V+1ex+i?=
 =?us-ascii?Q?arz7jfB5P27Jhb2Cxf+v/ocPv3r/sByY+bGpepQnmsQc9tGyCgA5NlKkRrBr?=
 =?us-ascii?Q?2lAmp/IC+qy/IdFvuk+77vXzRPhpSixckX1d6pu+iW1naRkSqhd5N3yGJSWc?=
 =?us-ascii?Q?Q2Fh8fnJQChK3NwqhFGo2IX1LNLevqP02/pfDZsKZJAswD9tjnNzwvTZu49a?=
 =?us-ascii?Q?Wsb7Ui9lcywys3hJC7yN39xBXwQm+pL4RNF9bB1nU1J9Y/Ps4hGyawaoaubx?=
 =?us-ascii?Q?IdLHxvky4ih4zBuIhkAFSxiVIXcoXRsFlxB8gM/V937Vx56mr8xFbl/SdFTJ?=
 =?us-ascii?Q?Z9XfL6721x0qF6iMbXFGHYe2I13aPQ8/7xEViXHE4ZYYegRZU136KbZLYbaj?=
 =?us-ascii?Q?hIRcTM3SkEGarC6YWexFMuqSv9gQKOuw0L4DOTa607h6/7nxPdoga8F/VggG?=
 =?us-ascii?Q?TJ2eTJ7fBrnrDH4XZclfEwGexHQiAAWrhyQGwb7CR2NmMDJJdCKdosrDGuIg?=
 =?us-ascii?Q?iz9+9U23GorU35hicWaCt1Jcv/aDnzaoTLixNEuHOmzTCN6bZj++qFOxI2u5?=
 =?us-ascii?Q?ntiDz0o3OpJVrAghIRpsgTPSx1BUhCsSKhZCms37tHCJ8ZHM6PhzE8O6cCmh?=
 =?us-ascii?Q?iHVomDNPfOinDfPxHHhQnVFHcAwbur0FdyMpsJ3tta3UDdu2LElTt4qE1VyL?=
 =?us-ascii?Q?VsrFnDvkSKkj6OTYDd2fnnx4OqoKeAEWnZhg7lOna8biKqjTdaA7nERqPefC?=
 =?us-ascii?Q?MygkPQbqDXKdxNT5d4tyEZ3b37WOClsXYN6BbRSc2dYQ7vIlbOWewK8DJFgN?=
 =?us-ascii?Q?2LFxGWw7uxDxzneyGzVrVwIqNlLswsaT2p8AXaGg25OsbwYnQ/3xWbnhkHJf?=
 =?us-ascii?Q?2KfH9nzzCVkN5LaJzPDUGAhiTPLIemPllRJra30wwJZ0GeuFPOXlQTnP9d3k?=
 =?us-ascii?Q?QjmWTd0/xxWyEU0sDeti5vR0w0OO+SUeYtzSDFUI+B+a/Wc0YQaaiCHdvHOg?=
 =?us-ascii?Q?Us0irPbBoG0ydNiNObUSGDDqTKltZYCrye58Ee8uCfmotcejUkuDVC4G2Dj3?=
 =?us-ascii?Q?37P2k5Cs8NmEhJtu87SCus4D+wwFZ+zINFN98vlt2oqAG8GQxF9m71LISQ3q?=
 =?us-ascii?Q?5RSNbqG7mAL14DMcmuMpI2Ym3MzDHZMg71GQ6CHJ/hnjV+aqiW7AzoB61LMO?=
 =?us-ascii?Q?soTJK8q136I=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?DZOss0P9M8Dzyrv8IeMixiNj43SslqXXwZFaqq06QCv5p+x2tP/J9hPDPGb/?=
 =?us-ascii?Q?hPIezvkyOV4ikzjn/d4OUr1qDRIrhundz6MkERjK6Y+0ww8FAUywC4LlB4qO?=
 =?us-ascii?Q?nXDGGNsfRrm5y6to/7ce+J8x3jPmkYsFqnDH6Ew9On8qU2M+HZ4ZHugKbbcz?=
 =?us-ascii?Q?5l69hTnMLYOdVml3s6N5e+cWzjIC7RlpiOJ+WBi+zfdPJBZTTIY4u/Ek0TVt?=
 =?us-ascii?Q?RDnUr9Y0YzziaHYzd+DeItUu2r2PsyoeTvYMyqaxrDx2P0Ye9hjahC4srr1W?=
 =?us-ascii?Q?Xnws+J9EmUnhK9Ikn+nJvsPArEERnKdBJNmJ6LoRtio2XBc44araCINlz7II?=
 =?us-ascii?Q?ybmQBy3Th3tLhnveenITwrHX224MnwYMXKnvTIDYPX5MfXUsPOcVRTGZgH11?=
 =?us-ascii?Q?YCd1Jd+IgOWKtfnEU5o4dzfxWgFknzULL9mPtyYxUWoZ5bUCF1JecrviCf2A?=
 =?us-ascii?Q?TS2kH3zieFiPiAJLRJoBvLmFFh37pfApyzptKQmtGdNrwjudwTyOZXnaZ4pC?=
 =?us-ascii?Q?U1EqCLVPb0Ix+RgXASimtdBmzSY7LzgFauHzDrjYYvJZyeOR37qsn9n3757K?=
 =?us-ascii?Q?2YtDV0eeLHd3UhLp2xDONWExb0HzmSQhfZS8J2PhtjzXnRx+P+BddREWfH7r?=
 =?us-ascii?Q?IDWH2dkaT8CAtvtatBiO/lfKl5pjqsofmVmi9vVw7txjNq6jqDK/oQCexqbL?=
 =?us-ascii?Q?3EeOF6aoEVwR4k0nLxalb5h6kuyMulMcRE5YqV11Zp8XgOqDXkrC7Z7qjpDB?=
 =?us-ascii?Q?8nRLKDH2ehMyKeOZOT6prhKbVvSoIfJ6ALtzMzvC1X7TeLKTP4GGpQVlTBxB?=
 =?us-ascii?Q?qWxEKoZtL1vFeCF1LoLPgxU/Q5X9zkSJboSQf9mDxL9XeA03A7ysozF6leqq?=
 =?us-ascii?Q?vwj500O/SjjhOXnKhuLQ5vjS//W5FdZ+tDuS9/PDhSZz1BQeP7DMvaMFKEHP?=
 =?us-ascii?Q?mUnr89LvuZLiQxrNrmsfzaU4WsZmjQaEiNX8Gs5xjQePMxKnFuun/nZzRHIC?=
 =?us-ascii?Q?2mM/SI0RsrkymJgtx8gSrgA+i9sDdO2kUCdqcKjVW44pRo1V9LXhPy1pCiG3?=
 =?us-ascii?Q?ZA7u4aslzX3O9+VL8mi17DSA2kTb8BV719H71QwWT9gz+Ix1C1chonugbkQX?=
 =?us-ascii?Q?KvEY1hbVVcFTM8cvrBo+XDLJZxY9+HqSY3461IMxH/Ru/gd6q2+DMVFn0c5S?=
 =?us-ascii?Q?86fdNr2t3r5Mi6H54mSOExdU9wkZMbH44h1wHz5xBvh8CusH447EydReN6MV?=
 =?us-ascii?Q?eq3WAb2qha+Mj+g/xsvkILWToa8CqAp3dsF+xeAT8a7qGiuPXT53wI4wWpz/?=
 =?us-ascii?Q?G6OT5+bl7BgkM8PjCzeN949gYvPgMuynZHFbRfVwVMML0jXxbOWRum2lh10k?=
 =?us-ascii?Q?Q+7Qj97DHaUog93Pn0Ar1VwLSt9yJvm+DBc9hb73WgDDdLc5cOPp5nqI3svQ?=
 =?us-ascii?Q?cVssrfFasyVoES+87NrN7ZHxaJDqhiW/12oZCcK+oo5owcCuA+4LsX/2sh/f?=
 =?us-ascii?Q?EYheRIrO1xgN3Mwz0AGGX7aVDBLmh1V6g1T6tibKLl94v2DcLiIjTIaARp2j?=
 =?us-ascii?Q?rnIa3L71gNHM7bcYHlQgvshOHim6iikUduG+ZCLefHTalXkYUGW7EMgMt2E6?=
 =?us-ascii?Q?DA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 7P5hl6twlN3sLSTOu4RshSLZ8X1JE6uySQhkrpcCPOrP72eYjkI1JbC0IZ3D7Oj6kD8LIo3zpKlfxNuDVXOAbCt67NIhnqjMBKXNrttrtGeZzuW0ncm9m4YkGsyHaEdQHD11D1HnnK+BATU8oCqP408q1Awj16IZoSKF9hSZZ/DXxIeYu4roYAJpAVcAaEEvvePzrGtMGIQH73gllkaChb1sdeYVBmsmeel3h1KedUhOQi8dM0vXYpQUbW7rYfQML8O6zJSOJkVJo+cimG8rOTm8AUJUS/vTYhhxX0JQ2NmqdjaGgz5b8avdXu8rKIZaBLtsoeQVeXOKRZ3ypDBj6q8h6ZgV5g7qkJs3sGRHNuruD8eosTHBiu9u1vL4tRmJlxfHC/KVgVpdERV1Gi4yzymbOObhicZnDSIjn6U6N6dLNkKXwUEupxJF7YzRTTKasFNMYUIZJcACUaTqDMdX1JA9TAIPhVEGYHPipklVUdh0xv7UoHsMZTv2JiG3/9HcBdiS381+sYXKp1dhphXWc763znE+wLFh1b4LFGEm3fd23J0IVBioeXnDuVNwoAuwEWk/iBmVXF0PS9GOjsSvYh/W2PuE40Suz1HrJn2VJPU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e31eea9a-841a-4011-b571-08ddf0a7d79f
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:23:02.5243
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: EuuyK4AeRwcTQxpyPNznDt2l9xtD+XWUrp0cgWVwQSFQUqewllcLrTfhPPMAjf64h65NWb105BEVGFs/IzAf+pYIUnMK24mJTx87vMilOYM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6278
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509100190
X-Proofpoint-ORIG-GUID: PAq414IqEPL6UVMNDjq6NFqq6yaEvh7A
X-Authority-Analysis: v=2.4 cv=PLMP+eqC c=1 sm=1 tr=0 ts=68c1de41 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=XorjO2LDAUPeUTK5CBgA:9 cc=ntf
 awl=host:12084
X-Proofpoint-GUID: PAq414IqEPL6UVMNDjq6NFqq6yaEvh7A
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2MiBTYWx0ZWRfX1tdeLsxJ6zHF
 7ologTU2EYdrSgonfje/zRp/ssjsNG0yXyxX8HQ80lTOVNSrPRLbnzUhsaoMLbniO9FN2vwCS29
 R1qhROIg05FfoSYKsZBq3J3MF9N8aMBHEY/GLYomtysbEdv+nOW0Cj1jixWlWfkRQRMwH6HylbT
 mdJvRSOrMLe3vcxz2zSK9ivfWtXLq7//aXrLSi12mVNdMwM4iT/XYT77WhvAoCEyC30WhBkPsac
 fB2a4JOSwAu/lxpcUk2U4EsSYG5XLrVMAbe+etiybtVOhG8mroNBI04ZB0zy615mBXIKbV0o+dA
 Ck7x+use20hThyr24i7hkrlh1pi86coPZRNGeBmPFbt9ulbdAp1jKXELCpWnv4vEFOkBzwR+huM
 SYNepX3UF/9IvwxkN0s47l5kxABEMA==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=CJTd+DR8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=lWobbSVO;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Make use of the ability to specify a remap action within mmap_prepare to
update the resctl pseudo-lock to use mmap_prepare in favour of the
deprecated mmap hook.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 fs/resctrl/pseudo_lock.c | 22 +++++++++++-----------
 1 file changed, 11 insertions(+), 11 deletions(-)

diff --git a/fs/resctrl/pseudo_lock.c b/fs/resctrl/pseudo_lock.c
index 87bbc2605de1..e847df586766 100644
--- a/fs/resctrl/pseudo_lock.c
+++ b/fs/resctrl/pseudo_lock.c
@@ -995,10 +995,11 @@ static const struct vm_operations_struct pseudo_mmap_ops = {
 	.mremap = pseudo_lock_dev_mremap,
 };
 
-static int pseudo_lock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
+static int pseudo_lock_dev_mmap_prepare(struct vm_area_desc *desc)
 {
-	unsigned long vsize = vma->vm_end - vma->vm_start;
-	unsigned long off = vma->vm_pgoff << PAGE_SHIFT;
+	unsigned long off = desc->pgoff << PAGE_SHIFT;
+	unsigned long vsize = vma_desc_size(desc);
+	struct file *filp = desc->file;
 	struct pseudo_lock_region *plr;
 	struct rdtgroup *rdtgrp;
 	unsigned long physical;
@@ -1043,7 +1044,7 @@ static int pseudo_lock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
 	 * Ensure changes are carried directly to the memory being mapped,
 	 * do not allow copy-on-write mapping.
 	 */
-	if (!(vma->vm_flags & VM_SHARED)) {
+	if (!(desc->vm_flags & VM_SHARED)) {
 		mutex_unlock(&rdtgroup_mutex);
 		return -EINVAL;
 	}
@@ -1055,12 +1056,11 @@ static int pseudo_lock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
 
 	memset(plr->kmem + off, 0, vsize);
 
-	if (remap_pfn_range(vma, vma->vm_start, physical + vma->vm_pgoff,
-			    vsize, vma->vm_page_prot)) {
-		mutex_unlock(&rdtgroup_mutex);
-		return -EAGAIN;
-	}
-	vma->vm_ops = &pseudo_mmap_ops;
+	desc->vm_ops = &pseudo_mmap_ops;
+
+	mmap_action_remap(&desc->action, desc->start, physical + desc->pgoff,
+			  vsize, desc->page_prot);
+
 	mutex_unlock(&rdtgroup_mutex);
 	return 0;
 }
@@ -1071,7 +1071,7 @@ static const struct file_operations pseudo_lock_dev_fops = {
 	.write =	NULL,
 	.open =		pseudo_lock_dev_open,
 	.release =	pseudo_lock_dev_release,
-	.mmap =		pseudo_lock_dev_mmap,
+	.mmap_prepare =	pseudo_lock_dev_mmap_prepare,
 };
 
 int rdt_pseudo_lock_init(void)
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f0bfba7672f5fb39dffeeed65c64900d65ba0124.1757534913.git.lorenzo.stoakes%40oracle.com.
