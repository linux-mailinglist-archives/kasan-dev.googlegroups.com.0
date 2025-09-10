Return-Path: <kasan-dev+bncBD6LBUWO5UMBBF54Q7DAMGQEWQXG2KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BF7E1B521AC
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:22:49 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-3156b87d6ebsf1568484fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:22:49 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535768; cv=pass;
        d=google.com; s=arc-20240605;
        b=jHPiqsTrMJcia4EbW3TB96Fu4PtVwATKSF6lvbdfz4Xi7oh2+M1gWeFzZrNQUOAjMw
         IpoW6Sh/zRh9VjDgvGnDj7E3fX1+Q/gqNQCOTpvzYDEgK3wmTyFBwN4d0JwBeKZK1RoU
         qTZV/CdTJb6pC9kdj/2fLJ9NDE6SYam33of9IzRPpze0ly71UYxfkQhpi9rNlVlPVn1x
         oyYXx3NOJGQVBpnnJkWwYORNpQ7vu2W2XgmPo0BWRFxVEbHH1Ojuubgbc3m416EJmk2h
         0kX/Ur2qVbJIeTBY+Xx/xqkNeOt8Y5ik2KEY1yUZ50R6Clgu9QYJiBz3NU8RTdzAx8hj
         /UYw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=X1zmbfpSaXs4vFQczmx5gHnqmKraPgwBV04hM8ttuIg=;
        fh=7DlkORDJXHz+x4fiIuFKY+3WU9+F+Emm63v8cqRAjlU=;
        b=XyCr3pDGVnOoD1RG0ENaYslFP/sFMZ8jMLJrk2VZV1fRWd4/Jnwwe1AKFBtjcCmyqu
         UywafgWKAPLfuxabu5uNNyoe92zIxDtJlKotzaKn7MuzmRxycqnvR0RLaHC/c6WoqWzy
         KZkkhSbtPSA+6rwVgaVNyEsinuWUYt3s6NYqdLom10oMzqc/lAzAcOoXmoEsjuagy6SL
         NSVZNDqSMXhYfDu7RFmSx8y8cwiXsXQzc+XRIa4uDol+NClhOs9PiwiM93Z4ac6M2/hy
         4VXRebHCqOlnWlHMcexDvr3CDF9X6lg2mu9hWwrbnDqFgSvPCp/TYdXE326I9/umCnEH
         q7rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=LGv1E2t9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=o545mt3E;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535768; x=1758140568; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=X1zmbfpSaXs4vFQczmx5gHnqmKraPgwBV04hM8ttuIg=;
        b=twrY/sSfJDJ4txG8rlqk/ufL+e3zSvq8/0i78PKOi5UAWy61Ibuzse67HuFG6v49lR
         vsAhXIBUfmBhQVL7o/sHXGWflYHfHIR5bFKfgvA7DoZeeJJTAuXzo8a0uqVfqdUU4b7b
         1nLjNoV1hEWhijLnJZrSxjRM7MqmsxD3IF85Qv3g0udKfllLicY48MKPYFbnG1ZZiM+B
         rCETygDB0wjqSt7xfznBOAfienO11mHC6pwp398U8MUT06cctfzkg37cfTmdWWzHp+ry
         OLrfDbgT9XrhtUeKFFx8nxXlQVbAxtL8DsDfyjfrjxEZEu6L4ntGacZnN4JxHvxwhM+F
         eHjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535768; x=1758140568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X1zmbfpSaXs4vFQczmx5gHnqmKraPgwBV04hM8ttuIg=;
        b=xRFcPJ2EWq9b7NgzBXerZRhl4kNla4tZrKWVmAQYSjGYPx8yCKRbFw3D7MWNu21Z8J
         P5gE4pPsmoi7mZd9XJdjataF2VR73bnZMRuibPFBgaIShDjVSzPKI6LkzhUy8miG24vG
         nqS3ftO0SMB8U2vQJjsudvcfBKsQ3RKUD8ePGEnNvA8smqHWaYdc5vVYUKFl3YNYIxDv
         axTXg/q/tz/haapPaUXi1neA/YV5kKZkrVBJpEGRxBhTAngXT2VEDbP8dFzxe6Ix8SAQ
         6bRoVBAbX601GgpKTIOEOOYMzZX4PLTdPwHnYAUkKeDcln4PQWQi3/xenNueNm/yi0EF
         QILA==
X-Forwarded-Encrypted: i=3; AJvYcCVHwxny1fGHc4P3WXQ/b2ufqQkSpuJfl1CxI+txGPXxwdeNeltnP6j/la8Y63bX8Kqm4rf/RQ==@lfdr.de
X-Gm-Message-State: AOJu0YxgymfOUKpRmYvUVmd8YjczQrWzgAg5+BPA3MyU8AZ0JeG1Sw9t
	yfjc5NGJFKWZ/gUgfeNlSyY6eHq5pxk4AsZL12uYFFsi9QYe5bSRQfBt
X-Google-Smtp-Source: AGHT+IF+qhdWNJU3Ta3u1l5E/KHOCR20A3gyLra9lLks6qk2ztypDqyqst63Yq/sy6W029Bk8arlhQ==
X-Received: by 2002:a05:6870:b01d:b0:32b:d4f0:46fd with SMTP id 586e51a60fabf-32cc5862629mr423058fac.7.1757535767982;
        Wed, 10 Sep 2025 13:22:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7/4g6i5zLJtpOPT7Bo7boQ9J+8OWJEmK850lgyPdACug==
Received: by 2002:a05:6870:2e83:b0:32b:b1dc:4a51 with SMTP id
 586e51a60fabf-32d021d57a1ls6483fac.0.-pod-prod-00-us; Wed, 10 Sep 2025
 13:22:47 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUqCJILC8YfT8BDVXbiZQGz8vcViczKzYEOoh9i8KJDsgx8YtpREtFi9vRZwlp8yIfMnx7mbTGnYdU=@googlegroups.com
X-Received: by 2002:a05:6871:3609:b0:32b:9843:edf8 with SMTP id 586e51a60fabf-32cc5f70cb0mr420750fac.11.1757535766874;
        Wed, 10 Sep 2025 13:22:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535766; cv=pass;
        d=google.com; s=arc-20240605;
        b=UYV+md0hIpQkTrsbpflS9RwQGj8fMsw2JBZC3bSybYTc4MO7k8THlFkKq82bSfQ/WX
         pd3HcPAX3DajOc8ke99nbJApv5szWcT7S4zP9eV79U0uNssd1zaAnEWBvj9HnwquEqWh
         oiqtDrjcq9Ank+dn0djUeb7dS78FHbHGoxxCstvQ9xXnWZIiGTfMY0/kg/I/d9+MwOR8
         Vj2/2wy8LH//5dYHWLDTOtpHHnD6kPWPtaykLlBJl1Q5FEkuaGANxjK6KYP3A68Yawoc
         MjSyzt3nwG0iiR0WAkLRtW/kGbE51JiqggShC+IBSmpGBHNe0x+RXO4s7MdXoGLsBWen
         GqGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=AmUcjNy47CjjgkAwV08cKlUqjlePUW7BN5yFydg4gC4=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=S30Z2YzFD2zAFV2OJxj1oBz0NtKvmEewSUkCWNtjefr7pSqNbQT5y+S1uuIBb6V8KY
         btisjLhaigCM8bOpcmrEr1wQRhdJWRpONcAfK21R7K+TP1derqCqPShsqTm63tLXC+X7
         IFKf6nt/MUtStXI9NEFGialRW07Fle04Q2moN08sk3hORdjxPUEJN/aC4DbjWhSw10a6
         sPxOwSaRn/5Nmv3P0oHNKBtYvDTISfQdY4sEeTcNpRkUtWtupgL/nNx/Cu/XPKJieQKf
         rhbwelb+D57Rku8FX0wiBZDHL5udjBZX1Uk0N9pu24z6ZOE/cRobN0C4VvUacOtsR2uO
         WuoA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=LGv1E2t9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=o545mt3E;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-32ce849c137si11973fac.2.2025.09.10.13.22.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:22:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfiCU009725;
	Wed, 10 Sep 2025 20:22:35 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922shvv1h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:35 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AK3dAp030716;
	Wed, 10 Sep 2025 20:22:34 GMT
Received: from bn8pr05cu002.outbound.protection.outlook.com (mail-eastus2azon11011034.outbound.protection.outlook.com [52.101.57.34])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bdbfhjs-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:34 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BOLownyJS118HOK7Q0fEk7IiEf2EvkkhFR1R8PFRQ311QY2w0ovTZ8b2+UDaSiG/JlGYnkBVONbuz80sJwnhpgQ2cA0WOS0F85Qlt0rkj8hWiX2LiAbaSeWcDo+gcABCPv36hMMHq1sSag+ahHd/whAwfqwCgLaeF/tNaNnrVl2hFtTMFMPOocZdZgu4TUX2m2a3UIU22+8+TB8ZGRPGw179j2h9lu1br2Z9d/hLQsT48/P54vgEG8n1gJkSPRlZokCR2arBalcJZ7PJlZpDv2BWfjpCC0sxx4QoRmBSwf+ndb6bGa88R9Hm68INRhMofGz16AmVIWCj8cLiLIVrcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=AmUcjNy47CjjgkAwV08cKlUqjlePUW7BN5yFydg4gC4=;
 b=UnSKrnrpuCJL7Nz1S/vPYB9dMcAfV12RoIv6Fm8Q3K1go4vcftJMQgsqdzOatJvO6TMHA5PUiFcNt5Nbon6k4/znsUmQgu8fLTZ0sk1Fm1hVJSNgYDvmz7QZlR0wKgJq8gfUddjEe+qcukvnzt+exkwOp4Di1fAJg0Uajui7KWXw2sjtUsfYXryXNH2F3hpE90L9wjh7mlIrRZx95WqO6MLa0u2Aq6miVUgq4WB9wxcNXy9svOJgJ11q2aiNR5NAYQBF24yGr3hVRH0yp5AXE2eiYXeG2yAiMF/pQUSRqemk55LSeqwqeRgiFPjzpxkfj9zzlTfoIOqHmIDVlbeEng==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CO6PR10MB5789.namprd10.prod.outlook.com (2603:10b6:303:140::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Wed, 10 Sep
 2025 20:22:30 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:22:30 +0000
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
Subject: [PATCH v2 01/16] mm/shmem: update shmem to use mmap_prepare
Date: Wed, 10 Sep 2025 21:21:56 +0100
Message-ID: <c328d14480808cb0e136db8090f2a203ade72233.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV2PEPF00004532.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:158:401::35d) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CO6PR10MB5789:EE_
X-MS-Office365-Filtering-Correlation-Id: ccf4f7ad-bebc-4e20-c43e-08ddf0a7c45d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?B11zIKsXFrIYiJr20PeoKdAPn+wWU6k5j0lGpTZCHL3/3dtqff5QjWqr8cqv?=
 =?us-ascii?Q?kQ+A2plbfPMpwIMlkSJSjVgtAwc0r2XV72GsV41FDA3PEXiOvpB+2V0tXIv6?=
 =?us-ascii?Q?Fx09Crlltsz6HwbVvlNcQ2QPN3gcIicPJqfBY5sQccedqUMIe0J6ZPo+Yy7f?=
 =?us-ascii?Q?bnnJhZ1rXuta6cgj6rO0yjvYaoCxXEn18z2lbN9JvMk4KC+MtYLrpzfPGL9P?=
 =?us-ascii?Q?EFz185uDiZHkXE1bczMN+is+zL2mUQOh0dVWFAlKMXQx/2A7hmo9kyZ77dGB?=
 =?us-ascii?Q?7NPGZmpmBi42kJTKv4wWlckXxSXvMgPp8bCZjTcRa3n5ZXp4rk9J0sL/iakE?=
 =?us-ascii?Q?uncXdo8C/KUQinawlNnggQUMexl7hNvegG4UYv0BYZ/1Fiy3j529HZmaoyKL?=
 =?us-ascii?Q?//XvOG0XxHKnIuAnN2XAjUT+6i5kSbFIqUQGilGfwylnf5cZ6NamV4ZoYfUa?=
 =?us-ascii?Q?wlNlQqGZz+6cIXqPrGpb7uG/7igfxm9RO5r1yPXd5ib4la4b1GhD3g4m9O1K?=
 =?us-ascii?Q?H8X9VLKMWZYom6PmQPB64HugoqU1yKV2o3qOblDOoQxhxoHF8GS3vrM219tp?=
 =?us-ascii?Q?eGEVs8CndqqWnjRAfkApXWJl1TmAkBR33cp1WZTgSDsI0ixtDkU4TVd3J/QI?=
 =?us-ascii?Q?tffFqhORylic/9iz2Q3Ju+uT6pefiTePWNwB8ih4zkgGgBohmsYD8kgk3J9Q?=
 =?us-ascii?Q?VYDewrdlxGgqPPRG80Vg4V+e81A7dYfLqZbDrrXXyc/V4Gnot0bT22AfidLO?=
 =?us-ascii?Q?l4qoxqgACVuQvUbWMSDM5r8vrHwuJlGx29Ll/0xTLskLGkoaPhwjVb2rb1k2?=
 =?us-ascii?Q?lUJ+9vSxekSwgCINCX74bq9ruBjof1Ctt7g1UP6JuALx5w3oMJtbJXpc7ZI7?=
 =?us-ascii?Q?Ze+CUfJZfvPZHBJJELdm6pvrWzDx+P+Csec9uqVjBeQWCgP7MsCW3V/RuqmC?=
 =?us-ascii?Q?2zukPnvh5fRpKGGbGSyJXIAN2KblU0hN7R95xofWYew7wN4SZYvTs1aK5D4L?=
 =?us-ascii?Q?RbwUnwNheklE255s0/XRgzDgqziQnxvfIVEg4azrm5E1XFYiMf/UTOV6J1HA?=
 =?us-ascii?Q?xgGMEy9Jp4e3EJdKqgrmoepZu+YOyTVn0ODd/NOLa05NEvCmB9aB6i9/UMLS?=
 =?us-ascii?Q?tjzqsiw8lAaZ1z6+mvtZub1ZFjCSTKnqGZICLKbYcJKVcYCLq+lZnGxuUwMq?=
 =?us-ascii?Q?0xtZYyKZOybHg3k6jKEykiEOq1Dyf00WhFwqKDsZW1Noqh41/nlD85LR79r1?=
 =?us-ascii?Q?U/1eCliWOZjAi4/T9GAzFMTQaTlez8rmyuUpmLMONVFjkBNLxupUOhqfyYJD?=
 =?us-ascii?Q?1bq48M2b6UPmwwXwGVMI5PGgK9fUYlkTSGXSyc7pzA0CdDLItKFpE1fxloJc?=
 =?us-ascii?Q?6u4ZeVOLyySZJWEy+nnp9G9FvYL56ylnw011dO04ZLjSrFU8QuQwlQajSIM+?=
 =?us-ascii?Q?vpTc6kpsNR8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?VsiYuZCMKhXG0nioAlubhjlKmR1Dr8GaZnsOvXWypOzLkyOHS7/PMOQqNHRI?=
 =?us-ascii?Q?KTakZ2iKBcGjEfBIftIUtYnfC6LfUhOKaFeVdaM+2vwL+mP9mZDLpkS9Ggq1?=
 =?us-ascii?Q?jkMdjnzCT8DfnNGhqfAu1MXt3c6H9xSophHPPaALp4Csyv4CgA6rL5tblR9r?=
 =?us-ascii?Q?SB+7UdHUQEv//B6yiPOH8ktapruaJ97uPujmWheAI5Xkwr50jPtuU9EWzJ8w?=
 =?us-ascii?Q?9OIoGxSOOgmcydCr7D1lDc0MnPEt7xQF6pMt/hLtckOUVCFew1kiftSmMPao?=
 =?us-ascii?Q?pi04ST9aI8DIW+fH4dhAk6BCJZMD9511vNyYyaiNTh8xEioEir/4Z6RPLJNs?=
 =?us-ascii?Q?OX5O6jjtdW8d9Vnr3d8DmTkPgTq/l7prqbfd/oWSR+YAjqxnekgYgg4JFcDI?=
 =?us-ascii?Q?so9P3vpBalIv/77/u7PWe/vuV6FBk1TiMtXO+x2vHlO5mDWDtRvWDPngmjG2?=
 =?us-ascii?Q?cV1KpthEjXYlx87eHRzFRCuSP5z0kLHYkCZwog2WShAb+wWlg8DR/4HtoAdu?=
 =?us-ascii?Q?W2HxdgK2o4oQP3uAhfjqiCypQmpkZU0JVYcajmV691oML5zj5+uUEnuWMlC6?=
 =?us-ascii?Q?3o9EVbON5qOzYSq77LnXR+X0J1UWr4R7EXuRcJcBDm8zhtqXxV2pxwh6JSom?=
 =?us-ascii?Q?xH0iGmwtq8QdXoGR5EoAgDqT+GFJNj8nZZc12L/6rie4EopYOAjL2b6tKei4?=
 =?us-ascii?Q?kU0hZA28pTq6YhCiQ2Ps4jAgDuiTQ5M5O75k7sRbPPt5iXf4SaL7UTqq+ZEr?=
 =?us-ascii?Q?U4jojGr2rrQwHCUJACGMVIuTuMz0gef/cLQswoFU5K3ibSJBN/nDNRFT7ZD9?=
 =?us-ascii?Q?wz4ECdYfU8o9Lmv9dv5EiTMUs9IYbFq32OVHTsNANSuCCmahS7K1s8N5oky1?=
 =?us-ascii?Q?fWG5yFewQGhTFxlU/d/qq9n0Xx/Fphx5Kn3YHUF/GxqfbhgCht0fqfPGpk2n?=
 =?us-ascii?Q?fs8xwVZLAtyLjd2qcLLNWPDjrv8OnGG6NpaLbxTE6n20U1JBzYIQsZwzgbhI?=
 =?us-ascii?Q?5nD0MwNNUz9OzLVfNyLD2F3iD7m2peOp3HluNC9wSsXxv5vxCUmpK/eAmdYo?=
 =?us-ascii?Q?Eud115Z1/LXRUm3o0BRK2LOfeaZbFD0BVAFtAqSEnRE8bkSvS4V9DV4yWvyB?=
 =?us-ascii?Q?loCL9YFx3LbgAyHgJcAczPSqCPRFgUxv/xRSjujh9fRPc5GqtlLaBVPbj5yw?=
 =?us-ascii?Q?Pr/v3A25+jVF7ikboZoUW4PXbUXcI1EO2nTB6hmdd3OvGmSZUM7h/vAIVNOf?=
 =?us-ascii?Q?/0KxHkJpg7eTL+9UJLJN7baPwcsyuOWipGb9lIWXc0D76cBKTjQ41PxmXaF8?=
 =?us-ascii?Q?skBALQRZMB++Iy2qutIoUvf8325QKz2DBpbikBFb8H2oj7X0m0qRoQVS7j+9?=
 =?us-ascii?Q?7CVE04/UPtNfzVuu1vW6IVDkfPCHvzP9QI7S7EPgRb6yP8wwAM7q3VGwYE3v?=
 =?us-ascii?Q?IwN0xFWW9LoOqrPfS4ofOFzmUETygaez5wHy7AuzBJFdqGarOje8DPU/PFI+?=
 =?us-ascii?Q?tMvbUHDTv9tfrzsEAMt711OKUVBeal3BdXyNNzbsYtHXuSfxBnUHIHGdyMBa?=
 =?us-ascii?Q?9LDgon2cF5hWRh+XewIJcMqsKs9NmlhwoI04PzAwMeIvCGneefYskyo5cLpZ?=
 =?us-ascii?Q?hA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: djpwhirJCLPyoghPxLEuYTHGmqZdQ3/6QGJzQZnFNDLF8/9/l54VRyYLfVAP5QT/nFHidCV8YHu9LgXNPZpqsc1j8amL2HfBQ+ZMuHVukfR+S5tg5utPAK569WKAwgu/ESoA6+Hwyh5Vn0BS5p2w9no0OEQ3WOveTY012o2FbCP4rrcCHXIof+EdDuqTFaEvov0/sbgWgz+V3BOvMPi884erLLCmLx4+c32igrNqhbnygUipQ0kyNhd2oFLcVv8v8A6Y6XHNz2poyDH3LWwB16EoQwFPluVF06VHOqm6OJRcXotxcMCxSk3vpROMmXjCnnQAqf9RtZQSFrzQJQR+a3m37g9orFs5rnDB5Ds30G18WL+2oAHV5v43EtYqGqUOzwVjyHo/M8sM/VUb+DN9VBXpkfiDmDkWoVHRYY5Sw44e6bhB2Un331k54UfVnkbFD7VFjquVl1OJu6AvhrBjO0Y8Pn/L+kuktOdRKaNKZ6jrwV6NG+ooE4T12jnzMYm25wjj+l2rVaobOdbvVjbRP9rs4sI0nDMJ+zon7lexq5oWswIcLEiSSgkckMd2e1O7Ii+ZYgrUkFl+M6Td14Jbl+W/Hu3Wq4iwvKgWoj8ZOtQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ccf4f7ad-bebc-4e20-c43e-08ddf0a7c45d
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:22:30.1953
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 6Y2NM5r+x2Z7jNgDR8EKm9RUQKSEHtSC4kdQ+eEHkedf3X/82lk3JAswZSN3XunBo39NOY5Igm3lZ8WYnklidhTlqHVigfIRdtOZZKMBm4o=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CO6PR10MB5789
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509100189
X-Authority-Analysis: v=2.4 cv=esTfzppX c=1 sm=1 tr=0 ts=68c1de0b cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=SRrdq9N9AAAA:8 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8
 a=hKknKL_MvJZ0P6Ka4G4A:9
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2NSBTYWx0ZWRfXxt3OuHH2FB8T
 ZPJdgwiA40Gpu0E2RJ+rtQItnq4Lvj5qKzndFvmMZZA+sQedDy52kb07kccc+2iOGN4uE9Tev9T
 2OzOOcX+xfP0ccvprD3270624BIqSMzpzp5Gr9GwLTbxBS0aOyFHQa1azabVIWmPura2bsy8ZlX
 iJed+RUH4HKhXEhzrNka5inpYeYlsqaEgj3AVrTV0GCjeHBeNNu1KAnyXwCE7izMUojj8WAuJhp
 R78Vq3WW8fS2gwYg6EeJBy7fZhjf/S9JCHIqyWnYUFANgX0KNLuP6VstqbZk+QIVzrag6eymGZs
 6xm7NR5YNo1XwACatyMHlELA1U73VXE8/tvbDxYUG+St3OqqNyJAu0kGj+zpTQ8xkCoHC56+800
 bsQp02xu
X-Proofpoint-GUID: _SXzNTioQD4tmu8rWAwd4SW1mnVHkuSk
X-Proofpoint-ORIG-GUID: _SXzNTioQD4tmu8rWAwd4SW1mnVHkuSk
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=LGv1E2t9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=o545mt3E;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

This simply assigns the vm_ops so is easily updated - do so.

Reviewed-by: Baolin Wang <baolin.wang@linux.alibaba.com>
Reviewed-by: David Hildenbrand <david@redhat.com>
Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/shmem.c | 9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

diff --git a/mm/shmem.c b/mm/shmem.c
index 45e7733d6612..990e33c6a776 100644
--- a/mm/shmem.c
+++ b/mm/shmem.c
@@ -2938,16 +2938,17 @@ int shmem_lock(struct file *file, int lock, struct ucounts *ucounts)
 	return retval;
 }
 
-static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
+static int shmem_mmap_prepare(struct vm_area_desc *desc)
 {
+	struct file *file = desc->file;
 	struct inode *inode = file_inode(file);
 
 	file_accessed(file);
 	/* This is anonymous shared memory if it is unlinked at the time of mmap */
 	if (inode->i_nlink)
-		vma->vm_ops = &shmem_vm_ops;
+		desc->vm_ops = &shmem_vm_ops;
 	else
-		vma->vm_ops = &shmem_anon_vm_ops;
+		desc->vm_ops = &shmem_anon_vm_ops;
 	return 0;
 }
 
@@ -5217,7 +5218,7 @@ static const struct address_space_operations shmem_aops = {
 };
 
 static const struct file_operations shmem_file_operations = {
-	.mmap		= shmem_mmap,
+	.mmap_prepare	= shmem_mmap_prepare,
 	.open		= shmem_file_open,
 	.get_unmapped_area = shmem_get_unmapped_area,
 #ifdef CONFIG_TMPFS
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c328d14480808cb0e136db8090f2a203ade72233.1757534913.git.lorenzo.stoakes%40oracle.com.
