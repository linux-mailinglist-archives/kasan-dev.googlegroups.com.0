Return-Path: <kasan-dev+bncBD6LBUWO5UMBB4ETVLDAMGQENHI5AFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 81E01B7EB13
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:57:59 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b5d58d226csf163865091cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:57:59 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758113878; cv=pass;
        d=google.com; s=arc-20240605;
        b=FXqRlCBNJihnQ51TuN7aHM9x8f34cUfeg6GgohE6IPrl9HS0nzVEq/eLj0WASlHS5O
         whykXPuz2AoqZ7yzvVfq7gL4eFSDK14Om1oVX3L4RiJw1VCX6XN44FZrqYc8xolUPDrH
         zDUqX6Y6biuzRGL83MSYUV75JCgrlFiDu5jPwpIRJRuv7o6OokrIQJJc82DNT8P44b84
         bRTUvDw1Ggwa1QRYOPnr5oUi7x4DHfjOrMHQt4pc8aVD1ht0dmRnBoeM+k0DtoXckqSy
         4XuZeZq3Tv7gqMcagMd1fXAAjH1WBMBwkKyUYuDALcrmLWmKjo1F5HPf9svAxXx65Cb5
         X7zg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=OTDR5B8zFxLJdABn8QYa4cSoBGwZvDVO7jPxBkPGF84=;
        fh=aSKC5eZvsmu4QJNcN+eZO2aPlR91YNHGLhYgEv9spds=;
        b=Ap5jknRuxcEYveUhrC9Y1rMUDs6U7CsVM54TapCHUz4oFcmh0boBzkiGW4yH+rHeiQ
         5tZzO69OQTrbN7TWBNLivBSw+a8Ae2OGEqPuZibFwIST1jHEzdaZG1+W6H06vhrJRC67
         FHAM+u56ESl0ONMlw15YLrQSz/P0rcv9ncHR6w0wshHObCiz8W341is91iNvOszc5dHp
         NVfuB+t0HXFBiNaZu0boxvKs1fxLhATGAXV6eocy4EKdX5hR/rMPooKbRlPexF32NdjL
         xMKwLyxuYorAWrQwQD3PGq5lQ1mOJPAstSXAPUU4WTHxwGOLuArYTQYCKIO3sFg0YoV7
         2J2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zs+xoEvG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=titzfDz4;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758113878; x=1758718678; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OTDR5B8zFxLJdABn8QYa4cSoBGwZvDVO7jPxBkPGF84=;
        b=AnwARuaclQHHe6LAjwXeXHuxPEGbv4uVbW6/+pBBjFnQvtDOPC87n3SzNuOHLJcLwk
         fVRsrA0v58BwzmnLk5nZY/NnxJyYOn5wJvMSKCxIWNLkmtfURnzdRMbUocNyeY1WVRvG
         smchDjGjnyAapYqihTSCt593CXnBmtnkIEj3HVcG7NC3DDPiHjd5AGzq2EH7OOgmJiZ5
         3U5Kko9nKiP7g7rzmcVNTf1gTOrvB5+EKBz+UELKF9ToZ3Tm+J0nwZ9mFYo/amGWDInN
         aYm8e1NKrRc27RvXThhjXVDY3JzVj9NZV7R1gRKu6F4ALQdNXpOIHIxZRYi32OH328YT
         dFAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758113878; x=1758718678;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OTDR5B8zFxLJdABn8QYa4cSoBGwZvDVO7jPxBkPGF84=;
        b=HCQUeBnVLr55AlhMbo8qnHgxPq4qzKTj2heOHv4ffuNRq761bJyNnGAmnwEalScXGt
         2T3ZZFgioByovWkW1zHfZixySfDCJbhHgpQG8yBggxpAyRfsKT3rkJSGwWWVsyA2ToHW
         DUxLezoYdd0xC2hyxmL5Ds+20Oo9/+cqnv/PE9bapjyEsQBNg454NpzbtbW+RfyFqp0C
         j4WwOHmwrhaYsExBu4uKGF+f4g+w7cHn0tkbRJF1QZjLTMfvJeP0YfmioqeMqhnyGO4P
         Yq9mj/uXITjE18t3ukq+Ff6qXqV+PKs11wx7PI78G++H1JpEqumYm50ur0IMRcCu6Ua7
         twZQ==
X-Forwarded-Encrypted: i=3; AJvYcCWBoqd5LlFqyzaGiKgGayYKSf6h/A4BpoklSLQ6eUo/7veC8wGxGlzqR+dAmfDO024jKsuSWQ==@lfdr.de
X-Gm-Message-State: AOJu0YwXFM18O0yOK59At/yAQEh1TAy6HC1ODjGqEB9APTzuThGXMla6
	i2CWc1N5O/mnlKIUXs4L7/PfowhY7UARnsilXksZduLyz41YSl1KrW8T
X-Google-Smtp-Source: AGHT+IG6Ah2i5uDghoM9TO8TNOxYV2qPx4ko4Cb2IudVQzIFbEivnO8qxSO+82bsrnqn5G661RWGEQ==
X-Received: by 2002:a17:90b:4cc7:b0:32e:87fa:d975 with SMTP id 98e67ed59e1d1-32ee3f65fbemr1913866a91.34.1758104049318;
        Wed, 17 Sep 2025 03:14:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6O+583jy40sEZ2/1FWOvTHuhRcyl3SMomO04lXF4KkHw==
Received: by 2002:a17:90b:3849:b0:32d:efd9:d13a with SMTP id
 98e67ed59e1d1-32defd9d2d3ls5656599a91.2.-pod-prod-09-us; Wed, 17 Sep 2025
 03:14:08 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUO2oL0G5FDRWem06gGq9q9sidcqQZKrf6tyhZxjYvlV91Z/0PYEjatNpCCBilDDya3mVWZc0orOTs=@googlegroups.com
X-Received: by 2002:a17:90b:1845:b0:327:9e88:7714 with SMTP id 98e67ed59e1d1-32ee3f6d3f2mr2216248a91.37.1758104048019;
        Wed, 17 Sep 2025 03:14:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758104048; cv=pass;
        d=google.com; s=arc-20240605;
        b=BLs1NrqrNBIXFNkgpN3YspBx5NKiCvSh8S53WDatR5no4rg8ChzbP4/egxMRpJmIOY
         u2zQSsdBOEIqqb84o6fwJawct6i4gQgFMjyNqV7cBZp/976KTLGm4hrGwnCm3h1ddrdC
         +t6U7IewOt0tP2WQBmy80mfXe97zbRnxxJKtUcXUtL0QoE2uMj5qBpYtC+FM+zLAyALJ
         wOvQz1+whteOZbp3jdQ/G7Gd0IxzHLJMdbQGzlYTf/ieoT/qbY4CitGQzHfD23T802MO
         HMB0/ry81nbyXUXzOSM8UREOcOLibAPSDFJnS0bVSwgSw9DaYmc7F2srd9bUZBgpYbF9
         bACg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=WHQl46h+sq5Uj3KXrTLPSluU+FQuQ2sRVSzH8pXTIVs=;
        fh=zqvmkuMfKE8heS3YzAc0cw9c6YJe6eg4akrz2/fmpPg=;
        b=DX4cesVFQpwyDCLgsl0vLgrqvIZBt7Mc1v46VuFzXNTczFy8imnST98t1kIXvKl2SD
         +9OrneUNFB5t5hfI6bPEWu1ENVi/v7XNvOBHNdZZdjNeG/G7AUeq11loI6V9Bay6tIju
         yUODI7hJ8apCdVo5rhXOVK8/W5eCIGRgWcMpqPY72cKr7sYqqbBSLBFc32HuWII2/tML
         05QvmxoFdMReqIVjK0iqE3L1TotJWXC4DwwtV4A4dwdkHfrNQratVloWXntK+ndH4jB3
         woj43yTcHAvH3OchFsDcuBO4pNywkEL4kz8AUWGKAEUBoEbQ9sdbgnNxJ6Mvon4JEi3B
         4O0A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zs+xoEvG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=titzfDz4;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32ebc6d7a98si154219a91.0.2025.09.17.03.14.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 03:14:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58H9tx1C031993;
	Wed, 17 Sep 2025 10:13:51 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx9rwvf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 10:13:51 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58H9TrCN001635;
	Wed, 17 Sep 2025 10:13:50 GMT
Received: from ph7pr06cu001.outbound.protection.outlook.com (mail-westus3azon11010058.outbound.protection.outlook.com [52.101.201.58])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2dt0q7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 10:13:50 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=HzdqQLcXy3VMnGEg8NVvNHdHSv0vdHUDI3843YIRoLKCwWRWzL7i8bFe+1ebpp0i/eTslGpgtKmubcdJY74LHs8NB+L5/4go5F093U3sCvylxHIdap1aHPZRsYQsrOlpknnJRChxUbg8oc5COw08pqEOWcm9FZt7ATQPZ6DAk4FVv8qdWycf9TzWLz+EiklkAcXXfu7z2C0yU+V7r++soK+7v0GcnYNB4+LizU7ev58w+qoU40yJNnH1vfjWtmh4f/lhm8TEt8+peS50gyUHuLCdrezi9YjI59xWYiHVTNYue/j6mfHRxuCmH3+vO6LwcgXrcvAevThUudu8KuECOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=WHQl46h+sq5Uj3KXrTLPSluU+FQuQ2sRVSzH8pXTIVs=;
 b=FCcMz0ihneTwpnmMjdfRXIOtSenFfnFvJ2ecDC/Ug/NsX2DviAskuk+QLEwWWtU7P1yntlcnHRDreR0Lt4v7mwV8FYGYc1iEJ+g4UhD8huS9dLjn5C6jfAn8oKNMn4VTvhiaaLmnBjWiGxX9S4RZ18IH7PIsCQKXqh5TxPzrFoOxX+S9TuO5gijX6hx5nZ78VqzCvcxqEspVVUROTg+d01JV8ELgLho+MBYvEacKUDEuMyGKtXvUlV9gRMKbhl8fyRbksXqly4ICN7isD4XG5bVrCcrQ40Jb9ZtYMD9YUhpe1lxgbh6x565d161g8mdVsxta6BxA3H3dnqkbY86Bmw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by DM4PR10MB7525.namprd10.prod.outlook.com (2603:10b6:8:188::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Wed, 17 Sep
 2025 10:13:47 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 10:13:47 +0000
Date: Wed, 17 Sep 2025 11:13:44 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Jason Gunthorpe <jgg@nvidia.com>, Jonathan Corbet <corbet@lwn.net>,
        Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
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
Message-ID: <44f3cd3e-d0cc-46fb-b9d5-0ddfe678487a@lucifer.local>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <59b8cf515e810e1f0e2a91d51fc3e82b01958644.1758031792.git.lorenzo.stoakes@oracle.com>
 <20250916154048.GG1086830@nvidia.com>
 <a2674243-86a2-435e-9add-3038c295e0c7@lucifer.local>
 <20250916183253.a966ce2ed67493b5bca85c59@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916183253.a966ce2ed67493b5bca85c59@linux-foundation.org>
X-ClientProxiedBy: LO2P265CA0514.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:13b::21) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|DM4PR10MB7525:EE_
X-MS-Office365-Filtering-Correlation-Id: 8a66a104-5562-42d9-6dd0-08ddf5d2e3b7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?gQqTGSk8gMNIiB1hsVxd6NjjSEH2Li1VXVPWyIsU0KHpBgBfHJV0mrKOO+yM?=
 =?us-ascii?Q?U3gq8v56fPwhbeeDoFmpsWfj2QiqUg4tQui4/YkbR/bVv/1V/kx94GHuSmc0?=
 =?us-ascii?Q?a4PLoXjSlTvZRS98zvHHUssqjg+HL6XV4BiLhnrTyJWpPgw825+3hzDwCDHk?=
 =?us-ascii?Q?RIaeggmRybJS5MJ1MLaotfWO9BlKFq2Ewkm/OKv3niWtNzpNwRcZefx0s9Ul?=
 =?us-ascii?Q?wlcyy2CsV7DRMBisPEijO5Nidz/DxR1jVGXS0Gjz9SGqAM8ZZ1U/cdkuAVAC?=
 =?us-ascii?Q?sf4Ry6Ad0CnMSsVMTi5rOfl2PruywSdv51YMr1T+3GVnvTZTMgKmZLpgCd2W?=
 =?us-ascii?Q?ibX7ftH76SXf84/8jV49ZXXeBJCy+8r8zxndYK2PXpzbThwwgLdiZOIjjnoX?=
 =?us-ascii?Q?1zoW0azE7Q1OTucuxa7S+b5qFWsbNgLkqS1k2kKijuL3/d16EpCIbD5b9a4i?=
 =?us-ascii?Q?hbmeSpgfIE15AuqBzzIEf9HWHitO5Us3VxMPU726bewBBiBG4TBLsBCd+uSu?=
 =?us-ascii?Q?xhNmPRMo8x1vPVvpw72pZ5/DgPKp95fYt7/ox9DbITkKfhJ9Uh7Ob3tPj8sV?=
 =?us-ascii?Q?y2kOzEqqaZdm2S657JPFaYapZTAiYvvdOg1nrYLQ3Ti9I/SI+tjk2EwlX2EL?=
 =?us-ascii?Q?ZhPEKPCZW7fy1OcTNTR5LBANMaiYI8XJCYadlM521PYxZsY1UtHwTAScXMw1?=
 =?us-ascii?Q?NIoh/RW8GX7j2Bt2MPBlblHGfjWD4lh681K0Jr1/xdO3sHjc1+URPYRYxYOx?=
 =?us-ascii?Q?72g+I6e/8U40UeF5vGAMxMsVIHarU4hdy49/6zeDoM1ZKBoZ2uLAp+svnzAo?=
 =?us-ascii?Q?u3DaEiXhJuNWzGD8iNQuiokNGaQ2cat3Omc93WfG+DhgATG9JFqg92fdxgur?=
 =?us-ascii?Q?Y34c0T4L9re3uYr4ckovR5Ti1uOCHV11bzXe/dBobo54D5GuWWUWwQk9Dju1?=
 =?us-ascii?Q?rDP4RcBf1ndWcbSRK2dBvjutPprMIECV28p5/u+/g3WkT3SC8aUc52MF+5B/?=
 =?us-ascii?Q?amotvKcwPZt8glRjJvxAgWABZGr6TItTwZ1gDjPKENMNgnaI1txaacakXiKD?=
 =?us-ascii?Q?fVX9n8Wxt8iNueg8zPiv9Myz91yqyfXFGYN89Wv3UQjOiWb2AtPlFV+NLkap?=
 =?us-ascii?Q?j76QuVf4Q1DzRZqMOBiQYx/QhZi4XR/5aHcy0JRcXZ2RKRnpScbdesTkKU10?=
 =?us-ascii?Q?Kt8G/feyUlNN1ObSEclxoCbHqBzRZ7rh1Cn9GB/C7FTiz/oGNUbJJ1GjVLyL?=
 =?us-ascii?Q?7bSmsKdOPXtKDic4b4PoUhOYVA1t8hU4PO/jALsQq4Ivc9jPhBPCDB7P+Fd4?=
 =?us-ascii?Q?EhvtOjuM9nsDETkj3XV5i3xSwkWRIiMxdEzYeIwKKZdQKrjGiSz6eDJnXLO9?=
 =?us-ascii?Q?vokBkKwQqxoYsJf8nVfaC+X0tQ79p3mwCoodG48IPKLtKZqS6Q=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?AMPwGHPUp1wjvrsq1w7trHnkLmNGdP3yLsHziVrv85+FuBIXtfdI4Gej6YIy?=
 =?us-ascii?Q?lggspXcQbrc/d7iEPS63LZ92iUzbTNV2TKPNzyN2pwtFVHcKSqAG0JrXl8XH?=
 =?us-ascii?Q?bGMXSAxOAP7DZBXpxhnT5XeAqnkEAgoXOUjvNDDhit4wUY0/qO2K91jduTrs?=
 =?us-ascii?Q?ayOtkP2JQ7XNt6q4PbXHoJtMrU9mSj+8RenEz/87txQ19ZAGT7+kdugG+PPx?=
 =?us-ascii?Q?izU8NkaT5kXMLSkG9Hu26Mg/8JLdJy4QP522LCUzqMraYJPAmfd9grhbH8BW?=
 =?us-ascii?Q?RyB5gDsfgmxmtr4fbBCTGTytXJb6em5pIohmYGzyCZ2spriRg2qt0Tvs4gua?=
 =?us-ascii?Q?9r6+eoJAYRjv476pPOdq4aiBBmQ7d/XSxGCPk/R68Q6koIe8tDvPsJDqmhdh?=
 =?us-ascii?Q?5YxCRq5At1FUB6GZQcjZdPTWmu1zCHhwiuZzqjtyiUmm+7vdhT1qSxWW4MMm?=
 =?us-ascii?Q?otCtcExtMU4oCDveY9gFiDvu0utFd6IY9jDf+FapVbEKGHaCUWSJCMavSOZV?=
 =?us-ascii?Q?C+r09mgEBuD0EPjstXzatSwhhp/dBBaByvMEzB2ASK+hjgc1kEhNS8uLn6sp?=
 =?us-ascii?Q?EmtaRpRxrTjTy04fIzx3k/3/IkE4nYh17iN5CZA6Fuv9AzbE0E+p/nbyoSKF?=
 =?us-ascii?Q?W25KIQ3D4sCmNhoHJ5c6fPYlhmukbqOcR5mZ5L4SSb1ocmn4u1PuuM4RqfTo?=
 =?us-ascii?Q?JHQmlXgxL0bC18rCPj/lOlqEVUeeLDBiPpp1KLgHqEoJkkr+Mt0GzeIXS+7N?=
 =?us-ascii?Q?oT+uKEvZEsh7vnV0tkB/3azG8y9z75naRX6oztGUplOYyKjmSfvXIsMSbkq3?=
 =?us-ascii?Q?IOhIXAXdORoreEKuTSRnyddRT267JT3MVOYjBeivdZK1bEcuvwRGfkWyPTdK?=
 =?us-ascii?Q?YHfyMrlUOBN6/V5jvy1mbCzJHxVF8aOGUr694HLa53u3lFLQEsOB3iuan8bP?=
 =?us-ascii?Q?jMEE9UuHcBRR91UXwSzKVOfKVxTNgGMHRLv1lmhdEWbITFFziGZ5Wjto8ebc?=
 =?us-ascii?Q?a5Jj5Kw331CfbYuoBo1wBS3gStRysOQ71VxJXYtgrAWMqjfo9aA5uSd8lDx8?=
 =?us-ascii?Q?A6it/x0G570yKwbSV+pKEwxtNSgDYUMw2imzgzknVm5ANocTWj2jK5g9SfQU?=
 =?us-ascii?Q?drK5suOBxt/k/bGU93RRLWZDuTKNfnTj+ShfzRnfg6eD3pfzNYZXk8pjuPBn?=
 =?us-ascii?Q?pciv6Fl8hITLex9ivgicW96xS3Ds9/U4X6ClpInb1LEY47NTQEjuDXR8TTMX?=
 =?us-ascii?Q?fxzeu2UbhMpZ1npbQDrLOYg5v1p10fxVrI4DZ01NyEaySAyoGRvlifC5zO/5?=
 =?us-ascii?Q?B079iDo2V+wgv1SBqEGoOyce+ZNqXbnYiX5BSKwxAdRbaS95wvEoY9BXsCUZ?=
 =?us-ascii?Q?RvTn67O2UoBbLbW+VkScPP7U1GirshkoHLQXbUY28aTpegeI8tN8HolEgyLi?=
 =?us-ascii?Q?o1hL3WjhNUZqKLHFe5KV8Aspa3Ccs9RLQcZrSiTsH3FPXwZ8fFpjHVP92zNP?=
 =?us-ascii?Q?Yn2a6NWFXnpqDvlxYFAquSS2W1BPJABrg4BjfZ8W1JwWZH5kuO/4gbby+ntJ?=
 =?us-ascii?Q?rmTJ9HcuLa5yEhtpLzwVVLuM5I69fE9jc1FZRNF5+FMWNIMhBm/jADJ5KdYK?=
 =?us-ascii?Q?rA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: XLeSukRZCD7D+wwn05jXehb0nU8uQ7ej9h7y2yWx+MWqxEaRcme5YpXzFm2vQms/DYNYrwGUT9Gy9dLn+VGZbt4VK3nQQYdgRv3pO1pMGuAT7szz4p0maJ98B33pldIhvcGhScKKK4kT2ekaBy5QqyZSJHoU34rQUPPhUvw2SXb9Z7M/e6hnSBv3Y+DSm66PZY/uTTy5VoFgECVLrzzcu2avVGdDtcfKyowPdEizWq6MwQQhlHT0bsu6z8UtVdsNN6jdZ0YNDnxXAg0TZRg/IdkJ2jCh9ojggqxvxyzAi3MdLDOMYB0bA5Jf39qrE9tJxZ2NmbAX573JAZsuUhgEJdNKs5Q5xu4xyiVKixosQ4uhSMC97Y7/bovjPBcdpGHZW2saoS0zyVOKFdSdgvj/8S1QSAeUQLHwmCOrJb0TeIFa/xCbbWG+tQHXnYPA2E0ZMQxeOi6Hnn9oxFnqXk2k9RUfCTdDpI1tSUTcABrHPmttM1Wr2ZNglkDu/r76JjXpd1/14oR5kdig8XBaNx/O9xwGWLZ4p+VNA4SlEYLl3JFHWMAEMScdQOYeCrvQKbPyQIQ+8LxElbkGf5VTdnrVgtgY3UapK5V6+s1SXsV2CTQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 8a66a104-5562-42d9-6dd0-08ddf5d2e3b7
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 10:13:46.9577
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: tzsURELcWKaXvIBwtMXXktyJwGvqFUL0ZlyKnvcjYobyJzdvrniyM00CmgJHJSVYFYBP7q6W4u4vwwqNtKUP3oU4tqrr8ELycGWY0NdNgEw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB7525
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0 bulkscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509170099
X-Proofpoint-ORIG-GUID: hSqHHYD39s6lfhe3C-xgdK9xNOEttg2d
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfXwomsjDNFYKyV
 Jjrrjnrv8u2k7dAbXfZPe13HMsDYiyi8in1E1Tl3exifWxY0NIhcmjZYieIArJGJLW9tIj5pV+V
 ZtpnEljb5jaZ3hBdPF/RMO30R0QohHwaisWkSWNRNH5SaCdcnTQsyih+NtiotCNUJlPpXrLJLVF
 /moPnPQysyXkjGe9N4v/vwxEwJSaeRRGn03dCBotJpWOoy4D3xl7VVItvJ4QN112O3tv3lgF7IF
 64x6zqF+hqK6+DwcNezjUpiNklhn0OKKNuysHBprKlKbDtVzQUrl7+HO6zJSQxOE+ySl7ojoaxC
 FsY8f6r7zBDPLsjE+vsV+Ph0ZcjDzvF9i4VXv0Ppkjx4nzsXG1ThPKThG8RGXbFYqJAQVwATE4N
 NC5SUWhg
X-Proofpoint-GUID: hSqHHYD39s6lfhe3C-xgdK9xNOEttg2d
X-Authority-Analysis: v=2.4 cv=C7vpyRP+ c=1 sm=1 tr=0 ts=68ca89df cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=fsd4YKtpGBD9qYw4rf0A:9
 a=CjuIK1q_8ugA:10
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Zs+xoEvG;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=titzfDz4;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Sep 16, 2025 at 06:32:53PM -0700, Andrew Morton wrote:
> On Tue, 16 Sep 2025 17:23:31 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:
>
> > Andrew - Jason has sent a conflicting patch against this file so it's not
> > reasonable to include it in this series any more, please drop it.
>
> No probs.
>
> All added to mm-new, thanks.  emails suppressed due to mercy.

Thanks, should have a new respin based on Jason's feedback today (with copious
tags everywhere other than the bits I need to fixup so we should hopefully have
this finalised very soon).

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/44f3cd3e-d0cc-46fb-b9d5-0ddfe678487a%40lucifer.local.
