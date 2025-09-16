Return-Path: <kasan-dev+bncBD6LBUWO5UMBBGE6U3DAMGQEK26YMIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id ECF83B59D75
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 18:23:54 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-61e577efd27sf5775169eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 09:23:54 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758039833; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dynfb9tD01dKfXiTLbZeqiAPxLtsaJhGYeI98D2dCv64UUy6XBfom8hyDuc2C5qCaV
         0HkUm+gvpRRRZnPW+5Uc3TiZqNE35wLxO2cOWBP6ImUi4nSmfVBt+Vq4x6rIFs2/LZex
         /FswqZ+UZVR2c1ftBgiJ/LUv4DV/dcm28qvIIong4rLvwMsMU8voyEJqD5AAt8D2QJPH
         x3SApUXlQqDv7De0mOYnNy6BKwIEFCpBSLKnybnnskSd2BowHlKBKEg2AlZnv9wDXvhl
         bmlCc0wJCo4h/K4ziXFKh4q6MnMfxO+Q3cdNHG6Q4Rcc6ptKQ18aWhozJJtzpv7qrtSH
         dIkg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=fiPmn1vfvcB1wQb+BvpEy3WiqeINfhziAd05dSlH81s=;
        fh=SY26rF2Hsv1SUQxWCAGQK7+Qbz2lHxMTEUeYdrrSzJo=;
        b=UKDP9C6I8fz9/SyC1BQVVAUwCF9pkrKTb9pBMvNGf/yd53jvtyIaoAMDT2OnSCaORD
         r8xUQD/uRr3sgDlo6xpYNv7xrw+mIa+7+5MdFtud8wr14SMh/F/PFdcHAQUCPBVnmRuI
         ifz5FgJYu0W6J4JepBRKbr1j/XBmgdNPST0GaRYanbde4Yy3+xybD7wo+JCwhgkHN/ZN
         or+sTQ5dp8cntoXvQUZ2ZkSKVSu9mxcD9qMhej8NTrXkikVtjaQ7Xdzoy7AkLaycrFcx
         R3lcrBXYcP3CegtfaxpE0DTckHjq9d9+6dHoj5ohGxM5l4qbqcDgGIaH05v/BjpE/iUQ
         VoOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=IyUaYU64;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=nQ6+JRsh;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758039833; x=1758644633; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=fiPmn1vfvcB1wQb+BvpEy3WiqeINfhziAd05dSlH81s=;
        b=Ykya42r4sD+PKEEOuWlLfJsTn+RvlJJU1UZ+47YCMrCscHZ7osuQq9l6TArH+1PQV9
         z6Df7NCvJvU1pU1fKyk4XxXZmwFoV5j1MekqXGoviy5wc3P78AMrCjHUTcpCmChPyuBY
         0Fu/o5XUmXmzkokZnDpOkO5aLhBCQOv7PKAT7NQ4+oVPgmEOwmNaPy/fOInJWwsybxwH
         s5ImjfKQtErGelJ90XlphBXOJikbZj1f0+d288UtfVAMCBkkbqZNi063lu2EwYJj1odO
         IF7G81+rz+TMChj3gxGY/J+FFUoMm02aBeSIQCJQiX7rnFIvYp6bMjjBQPdoHJqHdJNS
         3AyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758039833; x=1758644633;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fiPmn1vfvcB1wQb+BvpEy3WiqeINfhziAd05dSlH81s=;
        b=cWqjqBWhdHuocfOtQ3hEV+acB9p1df1vcxAkZELn72uTbeT0JSYTXomOwBDEbkZbhc
         lN+geG/fzaNv92Dzb+DzVe82KrZM/+0crS47rbG+UPBV4h/O0s3cov6x4uCZ3CC3zW2N
         eEXqbMBZEZzS+oFKNtQoZDraQgOSAcEmWl5/sbONKve0vW41v8ie3OyAJPqMJWiljItB
         Uh6BX6sUQbMfXZ1SPCSxLcszih5Hwe1RD9vveH47e9ji3wRPEdgTy0PQomENL+0J7K1G
         PuVlJPPt2EIHlOxhdUaM0OF4QvXnUGkguMtf283br8qMUDwPNwOVoW4S4AJAaeR9OIK4
         5glg==
X-Forwarded-Encrypted: i=3; AJvYcCXGE03QrGqZlxQ3PbnWtHZ+cIFneLoyAFs7E77yBHze1aR6+Ki3mHsNwrRz0Xz86cEgnNp/tA==@lfdr.de
X-Gm-Message-State: AOJu0YzhXIjmEvb68rNFBtm4BycxU4bLP1iiFsUn9bxYBGbPXkyuyHfW
	SIFPbOGQdzbZA0J/C4BRwAvcNVgBJlgy3qjw8gXIUEcdI5R/NZuynvbZ
X-Google-Smtp-Source: AGHT+IGoJWymcJyoCuubKkFDFY9CTJCgNEJ6/ucuFKy5iy7XUdQiT0oin35V69ucyGeL0v4n3FGoYw==
X-Received: by 2002:a05:6820:151a:b0:61f:f932:8d68 with SMTP id 006d021491bc7-621bec78c19mr8555047eaf.1.1758039833139;
        Tue, 16 Sep 2025 09:23:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7XJDPb0FwYCb57Ce/7mY8TWzB3ex+mkxoCeUG1MnMZKQ==
Received: by 2002:a05:6820:1f90:b0:621:a2f1:abe6 with SMTP id
 006d021491bc7-621b45347c9ls1606216eaf.2.-pod-prod-08-us; Tue, 16 Sep 2025
 09:23:52 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUpsaI1HhueoGT92EtvXtR9oe9smJuR6I4vaN2YifotYh6ttW/6KvfOz/WiarqRzvlzzqCcu1JsAnI=@googlegroups.com
X-Received: by 2002:a05:6820:618:b0:621:aadc:8d28 with SMTP id 006d021491bc7-621bed8ff65mr7438071eaf.4.1758039832098;
        Tue, 16 Sep 2025 09:23:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758039832; cv=pass;
        d=google.com; s=arc-20240605;
        b=dNAnN/tP44iFh3UTLz9ObYtIqSPl7FsNC74Z37hr7fyNuabcHyhXMt4uNzINGgS9VV
         nLCRvUWGt3NdJQhy1BK2hV7989jLiFjN7w30Kpb86xlfI+c39t9cYSxnvwZNhRTlRufj
         s8/orBb/luTuQJDMis7Qyp3KC15CiuJRhA9EM4yvcU41QjsRWWhK9NJ3JJdZLD/g4R1d
         +3BcIFFyfi65EDg+RWmmSreVbDh0E5A4mobDcLoaXYgol1Rdiy+35+2Ewt+wKViSUPdf
         /oGdhpezuCJ9P2ZZ4fnNFqbyeCR/7i6S9LzCUmyqEHuklkUVwJ9jnF0TMdGCnGPDJTy+
         0WIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=wjLMUHSs1uKS5u33xOILwewX43qpHNn4XxpppHrHz10=;
        fh=xUviwb3uuLvfmo/fIFWQyuSDmRei/NnmmsQXdNNNLAY=;
        b=LMs034ZtKKBfCOl8mLfx463DuJSiFEsXIBvL3rfpT5Rkn/YgGrN+A17JhSocOQU80L
         T9FvGz80DSY2BS0TDafnpkxk2GNr4xFhf9br3KMVoNADGbHM6C3lYx0gqRSlo5Mzt4W2
         GlWeNi9dhSuyyQ2EHWFui/uaS2vwR0gx45V/YLPYY3jJK9wC0mwSkgY46GItlls7W/Tn
         QiBKErU4fdITYDyfI2j/TaHYbpg06PgThXOjLd2rnjLprX/Fvcto8t34xgrpe8edz22c
         aIi+vwjO3XA+dnl050zD98Bvuvlt/MNZhpTMBxC411UqhdauNiwigf1uO3+VNbqEkWme
         Qsug==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=IyUaYU64;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=nQ6+JRsh;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-621bfb66c02si501954eaf.2.2025.09.16.09.23.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Sep 2025 09:23:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58GGNIDC025423;
	Tue, 16 Sep 2025 16:23:38 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49515v507b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 16:23:38 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58GFS58B001468;
	Tue, 16 Sep 2025 16:23:37 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012034.outbound.protection.outlook.com [52.101.48.34])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2cv4a4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 16:23:37 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=R2FVy4H7NfiWj6j2oDXl9MwhYTRVced9o4eSlVGUJVe9PgfOasECdan48gHVKWi5KVC9D8+kOKNDqIIFUlGs4vboDXRvfQ3QIcqABXwFMXgJ1P5p1tedET5M0gfAg0raa9MrbcQDFgi8Wdxsg+MYbhWOhd8iTxDl0Bv8gKZf4aLnlF0VXvcyAgmfRSEG77lyxF6GqKYud1k/IZ0EyFKvspP4mhc01usUEY3Bohn6Nr+QxCv/goEd1Urt63NoCuH7fwL2KG81BTviCGrU3Iw4w3Mnz80YoHa7KtWaF0FDvCAf4Qxem+16PHyHS0rMtPonhQ/iPltB7dy5cc/f8erejw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=wjLMUHSs1uKS5u33xOILwewX43qpHNn4XxpppHrHz10=;
 b=j36tpfbvQmaJ9oQ8sLW/T5WaRGeX7xZV1syWsC9Ei2jHhp2bq92JMJlMmX0HyyR7iMeNF2XFQpqk+v5ir4WkmHuGLe1HsWjZZyDz9qhictp4KZLyVCz8wS67ZFvnNX9RJRMd6sN7zIk5BI+zFZP/AALhmI0FpBbgDfcHrlwItGWbm7cCV0wU5ceILtnNjusQl8TUdFic9xeDUIuF1qxKHsNUzXQdiR61ifSVbPOihDZJiPOehj8NhJ6GCKmp809QFoVXl5hjHBCBvqBd00C9ohqCPei3O0mCgnNQMlZFQj2Ydx+IQozwGWeIsLmI6EVOdM8iDb5ey2v1lyzls7DOWg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS4PPFBEF84CD53.namprd10.prod.outlook.com (2603:10b6:f:fc00::d46) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.19; Tue, 16 Sep
 2025 16:23:33 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 16:23:33 +0000
Date: Tue, 16 Sep 2025 17:23:31 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
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
        kasan-dev@googlegroups.com, iommu@lists.linux.dev,
        Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
        Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v3 13/13] iommufd: update to use mmap_prepare
Message-ID: <a2674243-86a2-435e-9add-3038c295e0c7@lucifer.local>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <59b8cf515e810e1f0e2a91d51fc3e82b01958644.1758031792.git.lorenzo.stoakes@oracle.com>
 <20250916154048.GG1086830@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916154048.GG1086830@nvidia.com>
X-ClientProxiedBy: LNXP265CA0048.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:5c::36) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS4PPFBEF84CD53:EE_
X-MS-Office365-Filtering-Correlation-Id: 402d915f-e0dd-42dd-b086-08ddf53d612d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?J1QkL5xCQyfrwn7sWLjJuqoFoIuXx5GwanjZW6482mIyIJckPme4Q1+eBVcn?=
 =?us-ascii?Q?IgSLbkh79UeqjZaDCHm6+8qrCGG0bLdbsLRWy9FcQxV9285r4wsTI/Cw8mA9?=
 =?us-ascii?Q?cSSrkx78RIjuekZSv5JGg82SADJwedTRtHaGhX5eAmCXywA9kN9QomR7Q0kv?=
 =?us-ascii?Q?V7EYooQXzuV1Jyi1iYmhEeKdsUXAQ0E5SOGnay1wBJFg/B9JpifodpJ997nr?=
 =?us-ascii?Q?TiZBGFKCO6sj5hQ2QfUZtyqLnoBngtKczzx6sOhKPVG27etixC266mT47TiJ?=
 =?us-ascii?Q?w+1z2jCBsq2p7Q53o5nDWwOvPR6qV82e/SLGbfZaLl1dT57z3+uAkUnOrSXX?=
 =?us-ascii?Q?3G/mNhs/pCtOJ/H8S+tuT1WjanYcAL7iBqrv1UjKIZsoy/gSwz0QQxYM632A?=
 =?us-ascii?Q?/UTkoh5KvAMYc9oubCIsAgrurQKgErgZb+eQoTwxfWDx2mbXcMpddSBKFla/?=
 =?us-ascii?Q?sgSNiukchmJtarRLTufFTzw5TzVsoGMVOb3UcBeIEM1SXtbIULD6ayy8hWJE?=
 =?us-ascii?Q?alRpyVCUaGnW/xbuxRdGn117ga6rFyfAA2DVjhA2tzFloXwjpXl4+Lf5ufzi?=
 =?us-ascii?Q?bcNxpTERONnhqVM28WjGb84QFCK4pn239MtpOzCzgoY6CRsu7Bu79MlvwtmL?=
 =?us-ascii?Q?DL91H1Hp4PWUo/lNNfUxIx9Wl7BOvGRgKqlW1bITIXkCoSMUdCtHoSlpnCsn?=
 =?us-ascii?Q?9keo6hDielOK5uNZARjJEVK4TiYAbGflFiABlwFhXCpaDaIZKpZim8+BVvos?=
 =?us-ascii?Q?Gd4C3GkcBqZeH2wcFVcDbdbmVwdcHZV01vmW/m/mnpaESQZJAtbac5dtedip?=
 =?us-ascii?Q?c4UwNcHFAGD1s3FKnYJ+uvB5zN1c6Lgba83rnC2X73uRRCKiNQqPHm2aL+lQ?=
 =?us-ascii?Q?htIg8OjVTIygsfmKzX46/hEEO758TzVgoN1Y14yqNrAF2GrxjYQLh1qWsucu?=
 =?us-ascii?Q?6R1DNHixb4mGfkQ6SnTy3ZTYCt3CKN1rJJm7uBNMHV0RbwRaSOUr7c9rCQAC?=
 =?us-ascii?Q?lUF0EO8UE2eS5adh8+aSVnpEOMBxPWk9ieUkeQXJUPpE4P7vQSpT82WntvO9?=
 =?us-ascii?Q?Vsrzj7iWmzh3C9Mu7Z+6m+gVZixzdSbcSAMZBYQIdazzcosUhwpW9NSz9YSE?=
 =?us-ascii?Q?V35sn0i4XYGHO0t8IW45NOuPygYnp/40EsGMZ8Z7GRJbCW0TdkjyOl9xf0o5?=
 =?us-ascii?Q?KL1acd5pznkGQI36OQz3ts44lYf6ZQat2TJg8++v3uVOOUpgm1t55iyYXHfd?=
 =?us-ascii?Q?ANnPHh1YHNNGtQ9nyRswWUMaZXyssKp+uh5ZXliMnz7F4kAlLSq7si9hg6SA?=
 =?us-ascii?Q?5y8ikiTGnZJeqVcURnmByFwylRFP7detLQvQpE9tCUuX2P/9HBLfBPjmhTh7?=
 =?us-ascii?Q?uUoo0SuJz6kBBauiRRGNGXibgFjiEFSs9aGmOYeHd4cNU6bsHA=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?6QO/SIwD0Y/QZXTsEOVjKt2DaK/hgjxNKBhT/ly6eu6DS7QZhcwgrCHn0H/z?=
 =?us-ascii?Q?bdgHNMFec8E90lo6RVaXTOeVLBImR5rNFvn0YzESA1RYS9Kq4TmxgEni62Xj?=
 =?us-ascii?Q?JHXXWKXfIZf1mKzJyegW6N1GMbCopV+17uZ8uA9Nfj2U1DCYEwGXzZD7tQeH?=
 =?us-ascii?Q?hHvDmUT3i1SvRMGmk8KKaeKXu+uUo7UT/VjOostMhAN6DTeHsBYyi+3QT3zL?=
 =?us-ascii?Q?rZlmZ+Fwh3jBmEzgomPKZY5sBtOtB3eufMcbJ1igPRpYSmNuT00Nrp6VUwo+?=
 =?us-ascii?Q?W5dr6GFk1UJo6uCU7h05OHZMLNhFNEvhDUIU4Dj/ysxCqSYkEP34JBZdiURD?=
 =?us-ascii?Q?CidoDyBNHeKLJn6ME9iT2drijKDtytZG4qXcK7lDz+0I7vbYOe4Zos1OU+5i?=
 =?us-ascii?Q?LrRLoyrHOgRHOwe+peQxHS1TlJBiUDETQ4TMeMj/23fTu7sNkyOLkJx62QR6?=
 =?us-ascii?Q?pYbBNEg47KhtBuIci/mdUXYCx3f+r9KDMbZlxgF/SklQstKiqBZo2oI39psx?=
 =?us-ascii?Q?vPAHW5NcimU3eGaOTOMyS3EbrtasJAyZPo9sGN5X6xmJa2CIyBqycgEnmy8b?=
 =?us-ascii?Q?sT/em5aOLaTsZTlhckiL0ayTDdozdA6gC/GRXmW2Fv2eYbPuwiKdzujL7DPo?=
 =?us-ascii?Q?Md9U11FiSvf4vuGhcDM5VMQTeoPjV+lwASAiA+UjOIIb02i/tV030tiqnw+t?=
 =?us-ascii?Q?9ujjG5k4hfcZjKQayY+snkmPvGYQb4KElzjEWctrd5NJ+HBgmVRTk+qYwMpf?=
 =?us-ascii?Q?7fNjsyGiKk3qlCoJa6tvPh4GDy4P6VDH/Aw2I8QpGyFxOd50MLFcC3AY1zBo?=
 =?us-ascii?Q?4wb+mb3rljzRHd0TR5JjzCVPEb9M/jdPC7NKXsV96lHtH9ZBrzaz+2Yzw9xv?=
 =?us-ascii?Q?+gR6UNisTAuqfWVCIhcgvSo/BLixYHXD1N4x2i2VYfD7uITjX58bwOF//iwD?=
 =?us-ascii?Q?ekLakguT7+XyMInpKCtLE7ALc1kgQ3JecSKULFtTaNEXX7CfyZTFrKfybic6?=
 =?us-ascii?Q?23mut2X8/aemE2HsuaPcBrjQShQGaWGjFJaZFRtjWMfty62V61+RdB59voDf?=
 =?us-ascii?Q?vv0tCR4qvKnjz03ItaDiLQtncjUAdeNPiPKcjeE2oKne6QCHOahTDrpRmFEx?=
 =?us-ascii?Q?UUNrqefu0wCjiArOxtO9+ZFy3znYrcKp9trsB2OPWyOcb2gLnten8l+abPzv?=
 =?us-ascii?Q?wjJl2hxFwZ0cGQjskOI2fA68KqRbh0BE7/gmQHyuxRtScAcPtb+YCNZ9aIbr?=
 =?us-ascii?Q?4Sz0MejF65siLx5pYvJja27NTPYzD9edJBXkOnzgkA56RVVOZL+CCzEQjb0x?=
 =?us-ascii?Q?dxOgVInBDhXdNWt3dNtoQMQXUtjVCfOYui3R6AR7xF9yfndIrCAJiq8fp4vb?=
 =?us-ascii?Q?kH5lbIKkqYVO0RyAaYRYLtZYcWmAZWJDbEGj33PsNRG1Vf6bYb8RS+3wuXxn?=
 =?us-ascii?Q?sRyJpIGlaEsElVKBKe3P0/nGCqhkFOFIEnosCpruMj8SgAwXye8mDnVi7fkP?=
 =?us-ascii?Q?noVolW5dtH1qszSMCXEBqbcvFvce1K8drUEiNSU2AC+gXdXB5iRsooiJRJ8S?=
 =?us-ascii?Q?HDYlDcfigTDK5OoVyCu+blYcD0WcIJ2RGu2tIVqgwcPP6beRRVgFvXAZyz7P?=
 =?us-ascii?Q?Mw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 9MtJr2bduo7NwHDRJHCa7049pNx63FCcabI3eFqpqqlP5SYuo3V28U1TD9sJfn7cZpr1Qn3j0a4cviqZXd9j9DcPZrOZ1YUNgYRk3G5k48SFqIJZaHARLas1TswVYZJi1xWl8VwYv+n3xOeajaf3+y08TA/seX0iQ/d5kmI0Ql3uanojou3B5DPAo1MOsS2wsZ9vnuOo5w/Ceh49hcJOiu9VIa39saWYGO5W1zEqgZBugAmaeFOSump/TJX+7xmd5KcVQq9ySLUp3LyK4DqOTCziMEyxGE6Vzc7i+zkxvVUM5sYufKWg8Kfvj6bVKuq1u8g5iqvWUKAE+EDNrsd1NpGS61Eoay26wPToh7a2xOekBen3devaeWI02vTV0fwZNFwEdQs1spWOFpR0wlv9bB9fxHUf93eXb3FtUdSx4ALZk0GJeMC5pww/nUPVxT2IE/FbIVtcx3xIrYzCHbfxjUqiCcBUWKOj2NgZf0fZFo47qZYKsd09/muyCZNiIKfMtsrAnCyxYqQcyHArdDTmpJSfpIeVeC+ebhRXtFevIuVpjSvwWftFmrsmqP5IuKTJv4byMvaviGPBXF3VW9yJ1Klgcw039fs4Guv3OqCt/N4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 402d915f-e0dd-42dd-b086-08ddf53d612d
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 16:23:32.9380
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: UgJ73i4YhL2hE6c0IIKvcj0xR6kXYqEooAewvRvUFDbzdbGA/Mi0NV5bUK0frW/RaVM+Zl88PhrZIxXsMhs9k04Jl+6avq0hABbEu2b9ccA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPFBEF84CD53
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-16_02,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0 bulkscore=0
 mlxlogscore=717 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509160152
X-Proofpoint-GUID: nAxw8Ie6f6-Muqj6vdXMSJwB48cmcTId
X-Authority-Analysis: v=2.4 cv=RtzFLDmK c=1 sm=1 tr=0 ts=68c98f0a cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=cO3NwslvaLH2-759FBMA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAzMyBTYWx0ZWRfX8uX6eQkHlfEb
 U61B31eFlOmAx7adC/cEUghr16x633lbUWz3/k0C+oyW0Un5ySQy91N07ZNtWpa5DHQgC2ZTNa5
 IILgIf6XGjN41jReP2G2S1NgCwOwwkFkUbpg7uWnm3p6CCIprccx5WBg1f4A/8BqOFbNNTFNsQw
 iTXE2Nw/yL2lWvREYWwtWW6dU3k/qEQ/gQnMRq+p4+QIAO/E6b7qz8xNLvmWr5wO17QAJr8so0P
 OtBpjput/V6F8KKU4wBxVylmvAS0grRCR5Uj7PoxxQL2huKsL/83ygjiVHrpJh/ukyCUQ+6G6Pa
 6dwyCKpJHAzHUR7VtkPVClHPST+aG3Dh5qJYdJby+bSjd5h90bClKNkP5zZ8ISKiSzgZCFNJrIP
 BBXCe6E1
X-Proofpoint-ORIG-GUID: nAxw8Ie6f6-Muqj6vdXMSJwB48cmcTId
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=IyUaYU64;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=nQ6+JRsh;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
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

Andrew - Jason has sent a conflicting patch against this file so it's not
reasonable to include it in this series any more, please drop it.

Sigh.

Thanks, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a2674243-86a2-435e-9add-3038c295e0c7%40lucifer.local.
