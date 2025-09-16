Return-Path: <kasan-dev+bncBD6LBUWO5UMBBCWBU3DAMGQEP5RRTLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id E5F0BB59F79
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 19:38:19 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7725c995dd0sf5301325b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 10:38:19 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758044298; cv=pass;
        d=google.com; s=arc-20240605;
        b=SnZm7O4ZkudLoZcTpVIvtXyxIrje/dRF16hFAxHVCRUvkckhSD6QKP0AjZrGcxegKq
         CFSDNlbTP+ctZNpuiZ2vlaDJ6FfOj1QkYYb1QCXP1x1Yvro9Vy9YP4aPsVG4t0PfCNGW
         yQ91FkA9au9sPiW2iixbRWe8/z3YcQJzpC3XQoZxwP8uIlu93NlAw0lK7+8ZkLtMUZTM
         49seG0gs1eNQDHCzGFaQ+qGZU7DXUb4rcK5gi/5XZb92zIFCOHLRIIF4OJWqOoD124TI
         HFxGvF05eVjPipUpTJgOXYqD4FhDuvPwDwSJmRn3BKHxyUtkX6618abOTultF4NP/uBA
         DnqQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=dxAMvMuyWl11QaXw/QkV4k/RvximuKkOzwBPZGGscgU=;
        fh=rw1c/XBLUNoO/EXbTjo7uXPKhKzm/cTtbqZTVPCkwxk=;
        b=DKBjy0X4S5s+GcWgVCwCFjdL8FJDOJpDeI5hp5jJX6k6InnLE9MPY+dhep17wRqLJ4
         v0vnvGVfeBC0GdBBrqg0BaxVeafrrCJ3mX71VcIQHif7ktch/pMiSqcpyWJPPvg5eaLI
         CaB/1qd1hg5muoJPBACeN3Wc2sfygWCHn3Q4B4AFAzPfRQ7Gp7oMrhg9XgaN2leBVAYI
         uB5HW0YRJrAm31nXjGPnL620gOMy77vLmEBxFQAB8pfno3e3qUjq3vwndCimyNZprkvH
         TeCYaWfMjqSXlcJozNJl1jfwOYtfZngOYaaxrfcJcIJv7iyxuO+uOhzdSKWtpmrIoR0W
         blSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rp3nw1i5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DctidhIK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758044298; x=1758649098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dxAMvMuyWl11QaXw/QkV4k/RvximuKkOzwBPZGGscgU=;
        b=rIu0tFSwc5sH1UvyZrRbGWg2rtA6JmU5aQtHmsO2KI2Fna2BucCip4MTyCbIndmCWt
         dV3+z7p41JcuaTSR9dZFtdl61dMNQqys1j1qX+5QbOPSfJdpwVXZ1DKCwPMBLNGXDawX
         6gzbkcP1egEit56RVaT5crjy9s+35alJtgZlT99om6tzfmuGjV8z7wm10w3E0IM3ooKI
         gZWwmuuSLY3U47wYU0+xhga97XZn4fzS4YfaV5W3VeZ3il1bTqWyK08WvCELAxxYKplv
         E/acz+91yVl28JNYdgRMkuGqzjmqsmidG8iKyAwDBDnLxQB5E4VQ6FV+uN5PhG4mSoD1
         uDCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758044298; x=1758649098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dxAMvMuyWl11QaXw/QkV4k/RvximuKkOzwBPZGGscgU=;
        b=awXtQ4gBPgx6Gm4nbCIbPZfoUiP6xBv2hemiSELFmRDtMHnbL3i17fwEoEAqfLLHIo
         a60ADPi3cw4a9jPYGZVbn2/9iVXnNVZ3KR4tc0LApKJcOctp/z7pLVZfLpjDzu5u0JQ2
         apZcdtm3V7qJTu2//v39k/zYkgZ4yRbsiH/gSQ/zVczk7K+M66YAwrC6qXaVAVGcOo0V
         2FITIfXEj1YhvhEB75Kt5jqDu3oumPRx7NhxH0RE/seWG2TJJik604FXOerngqzcJKZ4
         A1sLx9lEf0Si4oawwLxHff5xq2+ueJUH+uL2YIn1GfAmnLjYJKrm9Fxd4TJZAr4AaOkF
         FU1w==
X-Forwarded-Encrypted: i=3; AJvYcCWOYHSOpE0+1B4v5kUpesZO30dmR24smt15sIei2TuPuInfmrpW/SyjjuukEtZ8K9EGQ02Zcw==@lfdr.de
X-Gm-Message-State: AOJu0YybHbp5zyuecAJsGBLuG1nGfGNUlEnC0QQR/tfoUcJsAPfjZck+
	NCYf8nbRrryLoNyU8HXIM/+xQFH3avnSqs8L9BlmpjNzv1kDurh7ohOk
X-Google-Smtp-Source: AGHT+IF5w/xV7I9J/tYKJ5Q+mWRKZJ/eQgIF46iy/GGOWaZ6v4HSOmVC/7mhjlsnfTWJ3rCcxbt2ew==
X-Received: by 2002:a05:6a20:1a83:b0:262:514f:16d6 with SMTP id adf61e73a8af0-262514f1963mr11519448637.12.1758044298354;
        Tue, 16 Sep 2025 10:38:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4KMDBqAdy472z8YhicAnn0chgljH/xgwk1aK1EtFjLtQ==
Received: by 2002:a05:6a00:e14:b0:772:437d:60ca with SMTP id
 d2e1a72fcca58-77615879eabls6126216b3a.0.-pod-prod-01-us; Tue, 16 Sep 2025
 10:38:15 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUQJ2MmFHdFSlUR6nNviT7X3L7HAgXkpM/eFL+tW9AKcWdsNQ5Z1FhC7fHxoouFjqc7KVYC8DffB20=@googlegroups.com
X-Received: by 2002:a05:6a20:72a2:b0:243:ffe8:9513 with SMTP id adf61e73a8af0-2602cd2745emr24682610637.52.1758044295556;
        Tue, 16 Sep 2025 10:38:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758044295; cv=pass;
        d=google.com; s=arc-20240605;
        b=PdYw5kEM/FNiEnn3g5dESgHe7cwxE/y/xEJMu1/BU9pfd543C7CzwCSq2S016+JH9E
         ghtvG+lBYR2K4Jew4BKknV6Wk0ktlcwkmh63BB/VYbzQSZaoNVIZr+/Sq7KQNmbOtNcZ
         F8l8Pka/JHFn9zbuxjmJ8esnyecuuOb88abpKIeu8Z0nZCORCPqVkKJf4/2zQvFvijs9
         LP9KuCN92Jp5YRYPDO9xkQTgrTO0YKv7sRqIfHlPkKO5v/2ojgfP7e/9kIX8JzobvCZz
         joVUX/BhejAVwBcu5bBU0GXWVtwGSijBiFPH4a9YyyERGTM2VO5LCAamXL+kynA+w4us
         1iFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=uxapfRc7HQovadVMarQt0MupoTPzMNCVucnOfihB7/Y=;
        fh=xUviwb3uuLvfmo/fIFWQyuSDmRei/NnmmsQXdNNNLAY=;
        b=jd3JncgZuZ9+fkgLuOQpBsm8ZyE95OMFevi89Z8M/Z7KeqCxZbCBQYl0qQsWCo5KJF
         ZY13vn0q3VbNi38ZrCelJqnIhmLfpZZWYEiBDPTdaaM4Zdgx0Ibduo/dMI+LGEnQ04Jr
         Qn5ZCL+MQQyRhYNxW2dvLtFD1vD6q0OAIZZX3F1gM/jBJDOJSzAmFG/zE2EArQIF9hIp
         RF55O52TMzKzvysab4ucwaEGG4nyFnDc2yxFYj2JbfWCQ8l8ZUyAl7REPosJaXo0nxqz
         4D9T7ZOuyvWXMdBYMFohzbldE/yrv3l56zkDjar+h3/Ts+EIg5g5B0S2jCMYEWfRI//D
         xCrQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rp3nw1i5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DctidhIK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32ea3bde9e9si88772a91.1.2025.09.16.10.38.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Sep 2025 10:38:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58GGNEdU014342;
	Tue, 16 Sep 2025 17:38:04 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4950nf59ty-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 17:38:04 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58GGkHCx036751;
	Tue, 16 Sep 2025 17:38:03 GMT
Received: from sn4pr2101cu001.outbound.protection.outlook.com (mail-southcentralusazon11012039.outbound.protection.outlook.com [40.93.195.39])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2cqyeu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 17:38:03 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ei+8PCWKqogccjLH/9v/KDI1LALdaQwmlGsTkGaE2earS/foCkCxUrp0dEG/wntRXpsjwo09UB9b7Y3JMhQMOPiztIOIyHYQds+morPxv6WAHV+EJv8F+ubbBhSamrFYXezozNu4W8/iI+HaJwqtF81AuTwkZOp8Yb0cWyBJv0rRy/6rhEW5r62CKZb3JyW1VYHKwc34FCt25SsIFcXBW2NmongpSFM343bAlVKlJERU2r9Se1GGVSHN91CtFllPSzAv7+SD1nNwirBJZGDDiBMfiQavX9WiOblFwb3LiPjmUK33EpqX5Y/dC61nemiO6uL875uRO2TiYudSn7fuyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=uxapfRc7HQovadVMarQt0MupoTPzMNCVucnOfihB7/Y=;
 b=GCuPlE3BgQ3cd3fPdDpVVmJ5N/A5gw2xAeIIHw2AwEPvYyT5P5yPAap4+uvImP1xsziOj0ckFMeF/zcRBePd5pv04j6ylcOV7Y79fSwRfmueSJpsGPIZ1b1FcHGCVgzD+BWXC/hz2RauoGdqsPfJH7Q+kx7dUMzSCBR2STVWqoofolPcn85UIK62fL4YGnmEsD/v+Mp44pnKdva+XjkVn6lo3WaGqoPR0Z+M9oc+1t71oQhq8fh7B6/rVUyqfilwnsCqFfL1mMNpnCj8gPWT1d+UrTuMImpCeKM4lkPGseeHZIRsWDUgpA5TA79PGenSF9XNuV7SpUGBD5l+hYXOOg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CY8PR10MB7377.namprd10.prod.outlook.com (2603:10b6:930:94::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.19; Tue, 16 Sep
 2025 17:37:59 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 17:37:59 +0000
Date: Tue, 16 Sep 2025 18:37:57 +0100
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
Subject: Re: [PATCH v3 06/13] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <19ec3d37-46c4-4921-933d-4d554a351ef2@lucifer.local>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <7c050219963aade148332365f8d2223f267dd89a.1758031792.git.lorenzo.stoakes@oracle.com>
 <20250916170723.GO1086830@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916170723.GO1086830@nvidia.com>
X-ClientProxiedBy: LO6P265CA0020.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2ff::11) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CY8PR10MB7377:EE_
X-MS-Office365-Filtering-Correlation-Id: 64505f58-b98a-4574-9d48-08ddf547c730
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?cYTlBbdDE0xLygR8T38KMp8aIwqEz93e8pQKc1WMNKBG4hOG/p0G+E6hXLdy?=
 =?us-ascii?Q?NTWiXUwA4L3OFj+hKQpiFJMdUTLPXF3ViQl0Eob/aeYPWsoggtstW2SNNr5e?=
 =?us-ascii?Q?/C7AewL1X0/mGVCuhYzBCXJ3ESTu5e/jr68g/5zu87a4DlTJ+jMwhw//uXF8?=
 =?us-ascii?Q?YcjhwZXA6Bg+4z85AG1/mFgyNvuHSgiVvy/6omufGnruDHM+KKc0cT3IoUXt?=
 =?us-ascii?Q?kfBccnaZWPp2nZWD46ykyM+BHnWh1VQ2L1NNW4KuXcrYvjuW9g6UsBlSiccs?=
 =?us-ascii?Q?boKlbDKxAQnOfvq80cv80aTKAtbrHWC8ZsjzSFHz3bQpMf1kaeJMT+OeAmwK?=
 =?us-ascii?Q?p+GBlKTqC0psy8ghZBL9395kPGD89KRUcynnk0e8nkWNH3/loOq+f5z5865L?=
 =?us-ascii?Q?aykp+kxpis1tSKnIJ3G9uL6bqg7029kW8HnNnmXovpa1qW09TSr5YJ3dhUR2?=
 =?us-ascii?Q?D6ldV40rApzTh5DMFsqlPs+ZqgXD7xJl+E269OawUB7x7awnVO280CLqQI+C?=
 =?us-ascii?Q?dDYg3l2HqPCXvJ5YHoO9iyMYQ1fJjBKxCElFVnifxfStjm7gr5GYdiNFak92?=
 =?us-ascii?Q?0mVGWtmSw8EL5+vuigDrb8XpTcHYUYf/HrzliunKT9Zq9H/t2fVlIC9VQj8Z?=
 =?us-ascii?Q?PUJsLcC/hWoVP+YQQz+IgFHST7GvElDkXCQpqaCdfsXEATzPjDBw50WOx9Pi?=
 =?us-ascii?Q?gRZC3TkxfUB89gbg+74P/ctUixbCXjuuABchBojqX0XQuxjo05JgGKOzUxwL?=
 =?us-ascii?Q?TkClffID8rNELx0a5X7L7gpjTrxxt+yk1LDSkhnOixxXp96Tn8j5hjluWw3F?=
 =?us-ascii?Q?LyhCkLMgXNuCtiKQX3cr2MFeTLoD5SYFWE9dipnvSIxV6oVsanCjXzmin05n?=
 =?us-ascii?Q?xduoavOu4220XUwu4nndNQwLTj8DM+9ZMRAPugn4hcw46wi7++eeTd6hYT71?=
 =?us-ascii?Q?MF7WrO7nv1fTjjXVGrO0AS8yCig/bm7At+Mo4XCJdI0FE+ulMneAbTghjcRk?=
 =?us-ascii?Q?DbWc/A8sY4GkUWJpPQ3Mq0TM/y7eCPI236kidn7QGrxLYLP4/yenCPxoo0aF?=
 =?us-ascii?Q?A1imp7jQcQOxbe1H3bp7aE3+yaN1L6RC/ETcdZxV7z2r6pPSm6e/G5gD+Cvk?=
 =?us-ascii?Q?OelOpX9NcAEBb7wBshpcCBQBTP41nE3h8U91nmCp6Un8RucvEuPE/KecE9lF?=
 =?us-ascii?Q?Lxj9llIBqfRIwpIZzXlzS8nEt5tdPFUiV/RKILGrkiH5HpYhQgYhIsUyKwcm?=
 =?us-ascii?Q?U8LyY5hlaZF0MuSh8Fm+oC41yOUU6SsqnB5W3ah9EirwjLJlwMy645vrkf7I?=
 =?us-ascii?Q?OhlKRTy52cvjQm1nQVGSm8SrfqHb+Y/yobyK6BsmpaPDQ8OgUzXKww+9Cj3l?=
 =?us-ascii?Q?xSccyQzfnQ+bfHMey0sAsCEI3KUAX3V1ceWDOPo20HhmNboq/Q=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?fw8Fi2/t9QD57poRstxiDnpnisOEg1id0oQ2rbQ0AEjjQxnYJUkyBXIurohn?=
 =?us-ascii?Q?i7+zywd/3fs6DJPXVY0ZLmaV2c4fhGgUPUq6t3WG4Rgo8r7Gx8Z1hnQElEQH?=
 =?us-ascii?Q?N8MokEFfsggMLQncRPnJEoIRApDLcXZ585z5pHMAeQmlEf2J+Eo8jxMGO18+?=
 =?us-ascii?Q?XomFhAOb5rNDW5sX4VEVZW9LQIZx0nFZbV4cabPeUAgAaLyPeGyE+EixwLhg?=
 =?us-ascii?Q?MBpjghHnfSs7p1Q5btSP2wctBbF0vd1XTDYs952sYBNLpuYM/E0hPtslt4wX?=
 =?us-ascii?Q?5ZUHR4Na3JxQa/i46vqt9dHs986NyCywOgTFCdr28mVQcH17ymKtRvLWYwxQ?=
 =?us-ascii?Q?nMNP7FdfSWB5Oz3LZYruVb6p8QQUEV2TvA3Nzbj8nE33B9VrLmoSutOPM2Pu?=
 =?us-ascii?Q?UCjJBvUqvUcqIYpeieRbSiyjowIC+L2276VJGex3+HjvnGGMuDoe26pO4gRG?=
 =?us-ascii?Q?LsCHUWNgRtTAtAyi6fKySJgsheVmv9Q/2/hZQncz6kbTRFMO/+pceOCAVhQE?=
 =?us-ascii?Q?K16joH9W+VE3Ua2kzozblDYzuHTRwyLE0KwJ9jkcQXivfiy7SPAkSwYCjtSU?=
 =?us-ascii?Q?S5Lqa5i/niDEPZD1ebNWQuqI4Fk9wG/n/DUG5udNPrTM/TqVfCW0SGqrftjp?=
 =?us-ascii?Q?vdjZLwqWyv8fZqQiQPkU8QKvZlA6tsenDY0NDzjSaXVG3MNFbKsu/brkDnpO?=
 =?us-ascii?Q?wNSdGQ6g815QT3t0zW3Ce1tfwJNXAunronmGMoFEQNVwxDpF9KSARE2gLna2?=
 =?us-ascii?Q?oEIdJP8FcE8MaXo5yF/2jnc1WFg5f2e1LjzMwsZHqo2mzkLYCu28bDCQXxyj?=
 =?us-ascii?Q?eC9404kxTgX5VAre/6QZ0fAGrMt+YN4VD3fr7MRGtuTYkghtbuYohn2g42Yc?=
 =?us-ascii?Q?Rrst+BPxRcI6CRcQa82RFOk1AMTYcQSaVWMmMiex4FMSgtb5SL50A9g0Anx0?=
 =?us-ascii?Q?XUtEOsvPwAFVQVoDABV5l1zeM3IPr8MPhjRVX83G69tAVMjRMfcleR93PPPX?=
 =?us-ascii?Q?CUZrYe77NxTVNIga4iEyspjYpJ+uBaUZRyk+UpxPSIOcjDT2ySawcHybpTGy?=
 =?us-ascii?Q?1AfG6xTyhs3RdMRdSo88MnBMu6Mgz8plYKZwZVI+fm4TdCCk3dSteo75AJ8f?=
 =?us-ascii?Q?9h0fcaULahiGBiviE3fFF3b6wu+NpqBgNrIEPnXw8km7AtvhBf+Rwq8petZJ?=
 =?us-ascii?Q?ZtOgXvCeDWoK5v2h/kGAo7jjAZkKipfiRH150Znq8Mi289gCLvOWUzm9bYWW?=
 =?us-ascii?Q?bVRMTdgXnIPFGUWfOW4XdOWH3frMiB1g762CbruoPqopvwX25eSL9yyAiF59?=
 =?us-ascii?Q?vcJjGeV06/Kvv4Cp3IV/KUWQM54hjQ8zI8OgsmY58AFMb3eU5mtNUiIJfFbz?=
 =?us-ascii?Q?fQQ0IEaYI4agMBQ/TjgZq3CMKVH9YA024XgbOGT1rJVqF1WTJfpjUGBQfy4s?=
 =?us-ascii?Q?JweMK5Updmv9orP4uDNU5wl+Y2X2/UXhZudVxoFK7jwsOuNI2DWnHxMb5rux?=
 =?us-ascii?Q?rMBaH6k2EBLHPa28xjZwhQNk+hAK0LosjfOF/w3XdSlkdWPbhnk9T0zokn61?=
 =?us-ascii?Q?W5wcwlcAjBs1gjwhJrRhl3eDsRcKrSshwA3079o8DSc9KhTWdalUVA8sC0Jq?=
 =?us-ascii?Q?SA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Os6hWf9h3734TiK4kaQuQSEbtWms0hkfTU6hcBpth4XCpsxTJ9ws3i7efrZcdCXfUiUS13s4W7U3iwLIymF2TXynLurYecQY36/mV6R9rRHZODy5QFBZvmB650j+I3PZC1/WFMC12D/3OmmQk6dB4YbOllVDtBtTlH1rjhQvOlX85b9nhdp93WOGoO5r2IAhV7CO4FVuBlbS+fE55Afxg9Fg4DDwO0LbU4sWwZISGf9ENRmEVUhRF8QjP6LEkuP9WdgCaxsBP3eFyS4IzGjh7m9i/fRtpAJ8eott+9oWOVrxoVh7UM3Vd+zSEMswD8RbokPO2m1esnTL3gPOeugdGo7QCriDbimigf66CrR+RSNjJZS5t/Is/5hz9bZHZFenshgU4mSko1P5kBi+B6EUNPtD2xGuTdAypPM8O/HWO3stYSJmI2BKIsSKke7F6giVrfIEhf1uMl2nbxdsj8tk1m/2v5Er578P/fynm7UnWyFTKaRqtz10ErstR1fwDyWm4QyKbPhHgy6GyqHd7jhe6wa78faWxjv+3LL6zYjepdhOkHk0GnF0d+sboOXrcxgJQObrvOTHxaQMEiX0palICD8QVkbLASNkzQ6l2+h27n4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 64505f58-b98a-4574-9d48-08ddf547c730
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 17:37:59.0511
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: SKjt8Ea3+9X3Wxse2HJatFY3rgPmvHIU1FAttbmWo27h8+DL35IsDoemvwMm10sq3SGvIU6rQVcFdOyg8V9ye1FoihDRSRI0o7px87cxVeQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB7377
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-16_02,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 spamscore=0
 adultscore=0 suspectscore=0 malwarescore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509160163
X-Authority-Analysis: v=2.4 cv=S7vZwJsP c=1 sm=1 tr=0 ts=68c9a07c b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=Ikd4Dj_1AAAA:8 a=RV78GzlOPR0tUAWTfhgA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12084
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAyOSBTYWx0ZWRfXzsstSIRoWpbK
 WN1s2OCzqh6gA23+diKBjpwh7e4P6VUGh7TUjSKddFO6w5r7S2rjjKl4gdptAbmwjByaIptDnJV
 FE/s1Z1ZVtBThNomgABtku3L2mtILexSCWvLTBObjZGjOl2MubHiftZz/NUVVDhYKpPJb63ASi7
 l8n3acz2V/E7kgyxdZWeQ3lwAxqQji2yQh4+qIR8Wgkq0sKrW4Ehh4fLteEoni+r9yhAiP3C24A
 3C3UhTEYhELTE3eVbtmwcWF6BlirbSToS+h41I36WWKQzYBEIRfQyiO/bQFTR7g77IWqJpflSU5
 mjKUxtpcQjB3EyvXWGVeyiZNO0ECyKO7QvGyjK8KgCfLTsoUs5yyOICNms4Mx2dtyBD0nstvlTO
 PQilGy09PK1xTHRAQM0tD8vlssokyA==
X-Proofpoint-ORIG-GUID: H1b_nVzTbGyMunA6BzqGx0lh-p-J-3hp
X-Proofpoint-GUID: H1b_nVzTbGyMunA6BzqGx0lh-p-J-3hp
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=rp3nw1i5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=DctidhIK;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Sep 16, 2025 at 02:07:23PM -0300, Jason Gunthorpe wrote:
> On Tue, Sep 16, 2025 at 03:11:52PM +0100, Lorenzo Stoakes wrote:
> > We need the ability to split PFN remap between updating the VMA and
> > performing the actual remap, in order to do away with the legacy
> > f_op->mmap hook.
> >
> > To do so, update the PFN remap code to provide shared logic, and also make
> > remap_pfn_range_notrack() static, as its one user, io_mapping_map_user()
> > was removed in commit 9a4f90e24661 ("mm: remove mm/io-mapping.c").
> >
> > Then, introduce remap_pfn_range_prepare(), which accepts VMA descriptor
> > and PFN parameters, and remap_pfn_range_complete() which accepts the same
> > parameters as remap_pfn_rangte().
> >
> > remap_pfn_range_prepare() will set the cow vma->vm_pgoff if necessary, so
> > it must be supplied with a correct PFN to do so.  If the caller must hold
> > locks to be able to do this, those locks should be held across the
> > operation, and mmap_abort() should be provided to revoke the lock should
> > an error arise.
>
> It looks like the patches have changed to remove mmap_abort so this
> paragraph can probably be dropped.

Ugh, thought I'd caught all of these, oops. Will fixup...

>
> >  static int remap_pfn_range_internal(struct vm_area_struct *vma, unsigned long addr,
> > -		unsigned long pfn, unsigned long size, pgprot_t prot)
> > +		unsigned long pfn, unsigned long size, pgprot_t prot, bool set_vma)
> >  {
> >  	pgd_t *pgd;
> >  	unsigned long next;
> > @@ -2912,32 +2931,17 @@ static int remap_pfn_range_internal(struct vm_area_struct *vma, unsigned long ad
> >  	if (WARN_ON_ONCE(!PAGE_ALIGNED(addr)))
> >  		return -EINVAL;
> >
> > -	/*
> > -	 * Physically remapped pages are special. Tell the
> > -	 * rest of the world about it:
> > -	 *   VM_IO tells people not to look at these pages
> > -	 *	(accesses can have side effects).
> > -	 *   VM_PFNMAP tells the core MM that the base pages are just
> > -	 *	raw PFN mappings, and do not have a "struct page" associated
> > -	 *	with them.
> > -	 *   VM_DONTEXPAND
> > -	 *      Disable vma merging and expanding with mremap().
> > -	 *   VM_DONTDUMP
> > -	 *      Omit vma from core dump, even when VM_IO turned off.
> > -	 *
> > -	 * There's a horrible special case to handle copy-on-write
> > -	 * behaviour that some programs depend on. We mark the "original"
> > -	 * un-COW'ed pages by matching them up with "vma->vm_pgoff".
> > -	 * See vm_normal_page() for details.
> > -	 */
> > -	if (is_cow_mapping(vma->vm_flags)) {
> > -		if (addr != vma->vm_start || end != vma->vm_end)
> > -			return -EINVAL;
> > -		vma->vm_pgoff = pfn;
> > +	if (set_vma) {
> > +		err = get_remap_pgoff(vma->vm_flags, addr, end,
> > +				      vma->vm_start, vma->vm_end,
> > +				      pfn, &vma->vm_pgoff);
> > +		if (err)
> > +			return err;
> > +		vm_flags_set(vma, VM_REMAP_FLAGS);
> > +	} else {
> > +		VM_WARN_ON_ONCE((vma->vm_flags & VM_REMAP_FLAGS) != VM_REMAP_FLAGS);
> >  	}
>
> It looks like you can avoid the changes to add set_vma by making
> remap_pfn_range_internal() only do the complete portion and giving
> the legacy calls a helper to do prepare in line:

OK nice, yeah I would always prefer to avoid a boolean parameter if possible.

Will do something similar to below.

>
> int remap_pfn_range_prepare_vma(..)
> {
> 	int err;
>
> 	err = get_remap_pgoff(vma->vm_flags, addr, end,
> 			      vma->vm_start, vma->vm_end,
> 			      pfn, &vma->vm_pgoff);
> 	if (err)
> 		return err;
> 	vm_flags_set(vma, VM_REMAP_FLAGS);
> 	return 0;
> }
>
> int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
> 	    	    unsigned long pfn, unsigned long size, pgprot_t prot)
> {
> 	int err;
>
> 	err = remap_pfn_range_prepare_vma(vma, addr, pfn, size)
> 	if (err)
> 	     return err;
>
> 	if (IS_ENABLED(__HAVE_PFNMAP_TRACKING))
> 		return remap_pfn_range_track(vma, addr, pfn, size, prot);
> 	return remap_pfn_range_notrack(vma, addr, pfn, size, prot);
> }
>
> (fix pgtable_Types.h to #define to 1 so IS_ENABLED works)
>
> But the logic here is all fine
>
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Thanks!

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/19ec3d37-46c4-4921-933d-4d554a351ef2%40lucifer.local.
