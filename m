Return-Path: <kasan-dev+bncBD6LBUWO5UMBB7XT7LCQMGQERU4PWII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C507B48B3B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 13:12:00 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-72108a28f05sf177412376d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 04:12:00 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757329919; cv=pass;
        d=google.com; s=arc-20240605;
        b=fVXYHdmoPRMB/nrqv9H1CL80hQ7UXYB/4cZ8AMQCxypCc7yp7/8wrhNYXzuDZQakeC
         6TO/GndcsxB+hBGloX/0MBBmmMWTKQUqWDEavMMDvoe/z06KTCid+HhosjIv+OGlh6ny
         5MrnEguHbnQqN5Q/1gLmbQeIKeXBjGXOl1HnKsKGVHA8HfEzYF9f67c9PRvR83+VcpUT
         4Hsn9KxAQAQBZJv1417NDL8xf2BeEPmIq7dk0czXmJGQUkzo8BYDsfD1doWMwY33NkAt
         vO+DfsNxNc9rZ1ki1F+JSo7PAPDM774jMXC2ucxsiEPxKW6cNEkpoYs3Ior4oRGDZ6Av
         yTbA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=v33HTAzYT7JiPS3t94ZTEhtlFtp5WaGsnSOvlrDVVPw=;
        fh=Bb9yQ117mpUUG4o/CGV6zHSCogI/omZNR0iHpuAHvHA=;
        b=Lqr7tcnxwbkKXSBNEHawRPKRlbmAgQQbBTkfukb0lHZy0OKVNNYGbwY8kvo8jH2d3i
         mLFmmuaWyEueGZNDTgQSpzTbS/+DwrqTnhXEeDmybdOU6/lkYpQZfXEtepfmg+E1LSB5
         tq+cIdmsORodHk0lCz0Z+3hlL2GgFEbNvtvvUR3qW+tZtMBEzjf4TQsPxDi78ojh5bWs
         SfJlmTikUHATvg8WwHnilcjM0fq7KCvgfkDEQhkcgSY/smnkTTIXuFuBpDVyCkr11TV9
         AkMCa9eFmqMXjNDflReHrjAnTqxkFGJTg2Ckp6/02NXL58a3SYMCWZg38MkuV0fzp+od
         v48g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=o+wigU1s;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=FWihO1Wg;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757329919; x=1757934719; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=v33HTAzYT7JiPS3t94ZTEhtlFtp5WaGsnSOvlrDVVPw=;
        b=TOO/McqAzOpsRaKBTmmcZjNDF7y4ysu+FNfqFbLbG89WYSkqiEBHIX4O25gABBluTx
         omM1Va/rG21L33+GdxZpBTD/1idaEPhv+KI+ZWKONAax04xdr8+oAjTkQil3KhQ9gUXJ
         rUYB1/pNLXzcjBT12GgUydzCe79lI/bH1d8dyJnefVgVwd6qKngi+b9xIakc3l5eM6tc
         CvFCmh53tJiEJ0JqhDKYMD0qsNRDVCCe5mPDBA1IYwsWRsdCj2MyV29+rLtFbPkPPc5S
         3uepjZALqL3FP+tqpqMGOJrxuBsctZQV+Q2ZPwL30v2lv8fIqAlLjh/BzD3wknUcfvbY
         NoNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757329919; x=1757934719;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v33HTAzYT7JiPS3t94ZTEhtlFtp5WaGsnSOvlrDVVPw=;
        b=DhTzS4TSzyiT/XLHw0KNRU3MgXrF7xXNQ0n9iVkKEV353leQ20+dqtckqcZ+m58XaM
         /SZ6QHtVkzd4C7maMmtXzpqWJ5zMGj9Cj5wbMY+svxc4UdG7VtP0XAQMpJ9/Wfmlloyo
         TqjWsTyGb/zKykUU3b/8PGJTyQ9Hov5T36keFn+g8cDqx8jNQsu8f1oBoNC9NLxTrlyy
         Fjko7JyeJhgEtwojfoaemrKErO0JAiwIY5Rx++IJiGm0XvkJMkNTJh17exF8mKWI7Zp2
         JZz/0w16Qn7XiQzg+V588q+mbheekV15Led0eSVOauHgbg8KFXGLG94mgUUyO5VFXaVk
         holA==
X-Forwarded-Encrypted: i=3; AJvYcCX3gcoJKdP4YJpvXV00df3SS5u7oJidB28eNsTCVwztVJ1dCHMe/dj8VqYlJs3wVL5/e7vR5w==@lfdr.de
X-Gm-Message-State: AOJu0YytBrA/Isdhgs54PHa6WijqMNodQjzQEKVw0NFq9SkgsuqFYFH5
	3RgceEcDGryosVxg1i7bnloJ8BCNmQl7oHSW9I4i9zBYCnyDrlmL0MPw
X-Google-Smtp-Source: AGHT+IHP8CHL8+nsNSpxyJTsZwCAlZt8ZbrZQPeXZfmobp2RBQmFfgliN4tcGX2UnNIUkYKvPKiZdw==
X-Received: by 2002:ad4:5e8e:0:b0:70d:bcbe:4e87 with SMTP id 6a1803df08f44-7391f30407fmr88813836d6.8.1757329918990;
        Mon, 08 Sep 2025 04:11:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Se1naav98Oa8K/VetjrW/+F6zvzQjXakZhgtDv6xRMQ==
Received: by 2002:a05:6214:c2f:b0:6fb:4b71:4195 with SMTP id
 6a1803df08f44-72d3eb383bbls44699766d6.2.-pod-prod-06-us; Mon, 08 Sep 2025
 04:11:58 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV6bH9b7BvcWbooMCpYQjUFfht4/+CishjBvx5zpWzIVcWFWPjJzmQrHUsS5zX4BrqaGVbwWwfImB4=@googlegroups.com
X-Received: by 2002:a05:6214:2b09:b0:744:be95:5ba with SMTP id 6a1803df08f44-744be9507afmr46963966d6.6.1757329918063;
        Mon, 08 Sep 2025 04:11:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757329918; cv=pass;
        d=google.com; s=arc-20240605;
        b=buKe1nvJP3Tcc4iBcVT83kZem3c1LmVAg8XXRO3XKKJZDB6zv1U5R9uAdzuID96NIm
         EdES2HGTih63v9Sdak9w9izLzx7kxtlY6H/Y4dulDqAy32XxfrFzic1vojKePicgolSi
         7Kky52hyTyB3TlkzZjnuWXbmWqOhz8KoFXujnyAnctpJqbcRfz/JLh56CfJmM73Zddf7
         iseurC1oaevsbGOOnsZMM3hOtkRoC0F5LO/kIblPanttxyJoZbrJYEftEdRmxWF7G/45
         ci6xeBjKcsTKIVkegGWR5lDrCWZxs3LXgZIwBKVO5W9+vu1gIGpMCa5pi58Nh9XP687K
         yBGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=0FyF7ochlZG4iwLKtmoWolNE4EO847Xqh6CTV1s03MU=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=H54EG0CQJaEM3okxbM11dVzrA5LoMZ9F1JS+YM5rv4ZDtLMSKuE1ozdxNaXsAm/wGy
         ndr5nUWtZN8h4E3LPCDHhN7WGv5FVo7tAAsFf80ySzOzoOflEHKlPdHhs1IWgwW1H7ot
         E8oWZ+VNsQtKcWAi0JFkhWG30mmF6uKYjenhANjwmgUud8FFpuFKEUkvF5IU2+v8Op2B
         Fyu1PhLo80wa3K5ps5v0ZfoKVCYkZYp493FtREw681Kb1OZHI6BYPJl+Xeh6uAqK0b7x
         KkI4M4M8pYkhJ7BvQPLLYxqxutCilzcYSIioAff7uMl+TxQ2aYjp0PMbjn1toM0LrVDX
         M1cg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=o+wigU1s;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=FWihO1Wg;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720b331c56esi5619026d6.7.2025.09.08.04.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 04:11:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588ApExe005225;
	Mon, 8 Sep 2025 11:11:45 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491wqug10a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:44 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588ABIFQ032942;
	Mon, 8 Sep 2025 11:11:44 GMT
Received: from nam04-dm6-obe.outbound.protection.outlook.com (mail-dm6nam04on2074.outbound.protection.outlook.com [40.107.102.74])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd91rc5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=KR5PnD71NbzbIWLIOEz2esRvtUsEBLx2RaG+xqD+dSPYrpbNA4+jR9cDNBcjYuLIsDRtWhSY4tccJ6l0M4WwqKXWkJpFsmKAsvdfebeV/sgs+pwYQlKqsHbeQNEW6Fht7rn+u60eKBl4Ad4L/GOroz39CBY0GK4Hogy8PEXC/SmKsn9XvI0HZZKDv1d3LjncjEKRx7qqeO6uKRgMQ39d/OqbYzIOZ8YppzxIJAkZyeQvQD5f0sJas2RPHffXTKm4i7yG0mvN3Rn4Q3OMIRJAdMT02opNtA8xQ+sFDHkypUzK4CqD6bhkHeg9F4p5EUQhN+AWcY7PVKKbzb75Ooybtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0FyF7ochlZG4iwLKtmoWolNE4EO847Xqh6CTV1s03MU=;
 b=juuWvP9l0JSCYQTKRTl1Ae5CZ8ODuVZM3xp4C3Perhmjf8eZsaYHEZsFVM9ey0BZFWo0heDMBDG4QNn0U/THEDAQqj/u2iixPUqgCKxYs8/G0RF051kj0if5Papp1YNZMBJYOLZBecQPtJ6n8+GjBMfbf1u7lwLv6MvJU7JKFUNxrp24+d0q7aw1bqkSxuDa0h5ub6yBb+fDiXXf/83fpWQwFJWWcS266Jwo7xawpHGHJMhRGaqJJcydFf0fiZqi1W2KgZus1oc6Ycxcr7aq3scnUJ499HeKKGW2VvRzX2s7PmSTFGuNCAAdhBvg5c4yZgHvwZjp+0ZJGbdDLDVXog==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CY8PR10MB6588.namprd10.prod.outlook.com (2603:10b6:930:57::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 11:11:40 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 11:11:40 +0000
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
Subject: [PATCH 10/16] mm/hugetlb: update hugetlbfs to use mmap_prepare, mmap_complete
Date: Mon,  8 Sep 2025 12:10:41 +0100
Message-ID: <346e2d1e768a2e5bf344c772cfbb0cd1d6f2fd15.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV2PEPF0000383E.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:144:1:0:5:0:13) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CY8PR10MB6588:EE_
X-MS-Office365-Filtering-Correlation-Id: 380e77bd-4326-47a2-50a1-08ddeec87c3e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?CUDkJbjFSXXwajluoDLhcytUkvUwjL4RL3EzyRi7Gubk+NheKN5Z1JP1iWl8?=
 =?us-ascii?Q?HxqvoBhHSzeQyuhJD979lYHsAcmHiUcAdCqh3h7gEqBPv+jaYosRFx+OxkfE?=
 =?us-ascii?Q?P/P1K5d2Z+P0HoaSgovN8Y809hDkT/XMCUqPOQ4a5neQ3x9/oNman3m1eCkT?=
 =?us-ascii?Q?kx+WErp1C/PRFPPt17AqUSrGZLywaW3m1PYYfyIoD/5Qk0CSdN47Nzsxw8ho?=
 =?us-ascii?Q?TSqPN/BLHx1VVyed3BEj5AmxZeNqvfW/U9jX708WBay7uxiNP0Zw5hbq89Zr?=
 =?us-ascii?Q?WtSPFg4+WRzKva0056NLxb+DaCcLnLNYw42UIanjpW9uy4U398S8bVA48OdN?=
 =?us-ascii?Q?q9k0sXO7urMK996l3ASuG8STlvPnY8OizgDJLdd8K6PCN0/VaqDqXzVgt2i+?=
 =?us-ascii?Q?Bny5ydavyZVA2k4jmbCkV8cHjbub/Ks0kpICpG4k4N1Dzwu9xFn3pgEZdPuQ?=
 =?us-ascii?Q?xgY+LSbJFL7EW4CuzVrmrUOc/9bgLsHlmqcrNwIKilz++XLt2I9v1VQtwkiN?=
 =?us-ascii?Q?zfowH/EOeXhip88IjilHGjjDVtGBiOH+qTbMVaEYT6DFcA6Er8k4UhcC2qEn?=
 =?us-ascii?Q?IK7CpK4gWjmrUePT2+ZREY+PYvlZCLxk6/Tc2dBpzc/n0AvA0v9PeT/gC2eN?=
 =?us-ascii?Q?/oeS0DUeofpx9GiKL2ZIXatrUHrvPtdtVbj87+9CNIxrEAUQ272rOohm57LF?=
 =?us-ascii?Q?L4euGhxV7V7fQhhrVxl0CCTJkcQ2RRG13UdLO7BWliqklloE6Xo1kekcbNEh?=
 =?us-ascii?Q?Do4ueMgBF/R6w/wVVNp0SO37nEdFgHoc26zYXaxLdpevy/GezJnUr3MJ5vaN?=
 =?us-ascii?Q?PUZ8VVWaRS8wI4EIybuqRjdrP6Z3IO+PzCDsuZrsytFUvP/Pkk7f3V5wIawl?=
 =?us-ascii?Q?poglRFu5INHxB1Vd1Omq3l0rtml3+cLjnr/66X0PZZb4AcoQi6q4mixYtUF9?=
 =?us-ascii?Q?XvdN9iBil/KqwIMN3FuV9LISNTr504CVi3rBFvi8iE9mQhzLJqd2XH1XXb4X?=
 =?us-ascii?Q?uCnup0mrQhw5J6to/33n0FGMAbr/O+wcNSc/uIYcHblqQL2Le5FDRIRjieG7?=
 =?us-ascii?Q?7qbXRcgtUacOJmPsUnk3F5jplZJr9r+6XzPb3QuFV3k43aRHEGLf+E52PzUQ?=
 =?us-ascii?Q?pEcE6iITjHsfvDAwxBBDoMqN/moSjE01ffX3WdYvcyTaPNQdbptndrayK3qO?=
 =?us-ascii?Q?AWqDXzd0Wy/FBzOgUSP3Ud3qR3n1y5CQJdNd4/hlr8kE3VfGbkSI5U16BaQC?=
 =?us-ascii?Q?8tRzPnGximtXW4itbVA+rJto0VWGbEcfEhMpbEpOaAC1AcdaHgU7vPyG5uZn?=
 =?us-ascii?Q?+Ig6/UvGeWe9Rksp0h/jTrnO4IsSZc7ql1gkS3GUXBURnrHDWuC/JndWywS0?=
 =?us-ascii?Q?7Bb9hLFj/xY1Kiu/RBrcMZSv1p+l5F0+XXowh/hrPMQgi5t3A8WdxGwLRYgj?=
 =?us-ascii?Q?iAR3kmTnNIg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?kIn2VnlRTJFXv8olI3wu+VQC3/pw8+yoKT4DRLkSqjiMvn3ldVRl6r0BC9HW?=
 =?us-ascii?Q?/KXbZFzw1eovMtQnaSMDM9JGpgNBG0FCFbfjzSYr8vctSoAvoBVAcvHiFJaK?=
 =?us-ascii?Q?sbZCmKRklnG/oa9hq4YyVyVkkM7n2XmNyQj6uO3elXR/vSGgnsnZXUsFdDhU?=
 =?us-ascii?Q?AAzZN9NVQ7hugsotkTlwsTpMxMd/tKznYoIaMvq0D5HpEd8OC//Hu9LbFBvM?=
 =?us-ascii?Q?9Pwg49YEtiDQ4QIJedGsCPtcbEr/da++1c02nHvYEVbnz35QFrjBvVaaRa7n?=
 =?us-ascii?Q?3ZwVQYyRCOEtYAn4s8o7sN5pKOcrvDYrW0XtIuaQmnSkl+RgyA1v80BCrVVr?=
 =?us-ascii?Q?Y+5vjXaEoD2CAdSiXASXjMrdHd29l+iXjyvLIC1W85Eu9+U0kQPP2+8yS9JU?=
 =?us-ascii?Q?Q3GNQ0i9PGfw6I6bjdCsS4iBdAJpj77P5xeP0OkkqVZqsYf4toDhaVajx5zF?=
 =?us-ascii?Q?byXzFmTKjrK3TAtUsRRmLQuMyxKLv3F51xzLIWt1j9z36T9OlrM8Clq6w1no?=
 =?us-ascii?Q?FmmGlC/we9cwXyHBWoS7sZ3/lcokRvnXUcbCGuz39OHxL22JNgOorWe2pKOU?=
 =?us-ascii?Q?zMxtb4Cvg/w85H94WwJg1IaXEVq50bYETgcM9/Ev37z1vVWBDFLKBL8qoXTJ?=
 =?us-ascii?Q?QDUaiwk/qRisREfAeBCoUU+SO00wLrYdq1sFBCIQLD3vUtl8Fe877Q2ZcwPF?=
 =?us-ascii?Q?S2MQtqpFYLC8+CTPafsMSj12IQQm3ccT71N9W9p0ieVYWsD8nOIYh+I8nz/N?=
 =?us-ascii?Q?X9TcWUFjFBXI0fTNnEQmJlKyYikGOwNXolovRZ/PRgY8UhqTah0uk2hV1zeE?=
 =?us-ascii?Q?0al0TXhQyZAsqu+ES0It8u39AgcjN+PXbvx6u4fA7+LonQmTS23fzzbcjzEU?=
 =?us-ascii?Q?xtAYMJFsPAdrI/0JNrGFlL0Pmga2ZPoP7ni72YRhg7n/53gB3MqcWOUxrERn?=
 =?us-ascii?Q?675KcAF9TfrhQzHmuTheo8ZS1WkUgCCubTE1ynRSTPlmGB9hchezs8JD1wOL?=
 =?us-ascii?Q?JOWh5U+3tOzPPr6i/qkMihSybIpgFKVg5nLsqX3MwgdrR+nneHxvYjzTdobz?=
 =?us-ascii?Q?L/baQ4qqhDgkglc3UUDAV/4X1/aL6qoIG7sJkbDGLyCgi0mG18YLqxvo5O3W?=
 =?us-ascii?Q?v4dxUmzAy6ofPVuO+umGb4t9AqEWmWYLc388asyTzqaIlU7yS8JszZ9Z9Kp7?=
 =?us-ascii?Q?AQm+/m0rYYLpQ0SrRWKPorzJoA/eF+xQnMrLmB81FW9zQrIy+9IY86PDrSSB?=
 =?us-ascii?Q?+D7KVJnmf9DQvakqIMcE3N8oYbL6xBScnJbhrXOnDZ4uaoaGJFyPXdGxMFJS?=
 =?us-ascii?Q?Gmk5rb7wgUlZ9kmPRSmJUCyaQjMfzAasYIGi3/1lolfJSgObqY5ZPmf4RPfo?=
 =?us-ascii?Q?S6vQ9Y5mxmGZ0TKrGFWROrHT/QwpqPfUo86YWkXhLkB5+XoAzQfFXWBFURZn?=
 =?us-ascii?Q?6KmCZlVq8HlJqx5KFaxyawCvsspe91pOPTdS7UWugHRU4UHUkJ/dFElVJ8AI?=
 =?us-ascii?Q?YYNo7imhduXhv5UpykZsmNijlIKjuDrz9q+TfOv4VjDelAKfdsNFmwbxq9hF?=
 =?us-ascii?Q?tk+nzqHGyfR+8oF4J2yvvrDeWrQSSuYbEjiLLX3H/lfMSijyLoqDhu9p9hKx?=
 =?us-ascii?Q?3A=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: d42Qgxc9LsnqVO5LoTvL4taZE/IUPZz+m+bWffF2YxClSv2xfA6EZZnXVYXxANtFUd4rGEoTWhWlGnPXh4ZE9T4QGiXO5SPF4pB5eylkdYXHzuLnpxicjEpSVvVucgb5W4YTETg6X3EmK6IoLG9/rub38/+503D9I8P88bVP2m7OkR5zFDnL44Ql6/3IQq2YMcvO+nItBfu7Mh9RCzaSpHHnQZ7Y/gbmw8YS/5vlJaPlP8WKAgh17rSP5+XjOUUcEuSj25InZ4K7gnU+0gDJeHjkBx/M5WMxmSvs2HAiyfH/gBxj/q1SWdFOFsxoXYiMCNEd2/0igtio4jN3nsZdX9Ma/Qx/Td/A+WT3oCyglkAHpCHzHf935TxTT4bXFJzOanzFnqDvrbmb3yta6BtW7It5MtCevrJakLsG4tKHhv2KHZCS7XGjLIwGdxdtJyLHjfeUVfeneYSm5jw8IR2f8wIg8e3yAdtLw/8nI/gNMCQh99hb4FyKlI+hR/l0aKOd8DTTxbABDM8vrGZeQlO45BB3HrCkYjYuR9FCuUqv5W9Oc1v9Uq4ezdJawfj3Pt9jcYMMHw+k/oNfWBXZRWFOrCcMftHXFfO4EjlG4QH9f84=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 380e77bd-4326-47a2-50a1-08ddeec87c3e
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 11:11:40.3603
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /+kZOaFkcXSLeyjsxPUJ6ejSDWk8Cm73bUpl8fUWfjnMoIuxMRQGgceiw5JeoBVuoQowJn9pvPadVYMgB3XoaR2x8+AucSxiuFf+tFDjfF8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6588
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 phishscore=0
 bulkscore=0 mlxlogscore=999 malwarescore=0 adultscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080113
X-Proofpoint-GUID: 0sByKBS-NHv3PhEfDJVBVhI8VWl_5b4l
X-Authority-Analysis: v=2.4 cv=Tu/mhCXh c=1 sm=1 tr=0 ts=68beb9f1 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=p3grG-4SqU5JK2rJE7oA:9
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDExMCBTYWx0ZWRfX45OhzuneqV6s
 wPg1Yo5C5HU7WyZliA5kfQzwGzwcX2zFLhgRvOrBRPL0LOZ0eut9KRIfD5c9g9nfHlADp/oDZES
 CRbTqjzKqm5XQFM9HiMV7ebzTPy3B2aTcpuKozhRlWPbNN5AYRP6tnHL4dxHzyfrJDIH6PQczGW
 G2nfw2fST6LgrGbfcOFuQKYxvZw4K8tkS2Nd5p+ZS/7M9J0EOiit+z32AwGZc9Of8m7lAhClqq0
 CuKRVz+Wz2RUC+1TRqc8tv1ds6kML3LlOdgvrwaGIa/TbfbYdfZUckoEuMgJ4NnBVhk5S5heqSX
 7/9Y650f7oy1vj2wTQpe2Oa/4lHHIi2Maq9fqhajyz2TdZnEuesm2x1sMjZ0Jm4WqAlX/Az5DOP
 TMros7+T
X-Proofpoint-ORIG-GUID: 0sByKBS-NHv3PhEfDJVBVhI8VWl_5b4l
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=o+wigU1s;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=FWihO1Wg;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

We can now update hugetlb to make sure of the new .mmap_prepare() hook, by
deferring the reservation of pages until the VMA is fully established and
handle this in the f_op->mmap_complete() hook.

We hold the VMA write lock throughout so we can't race with faults. rmap
can discover the VMA, but this should not cause a problem.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 fs/hugetlbfs/inode.c | 86 ++++++++++++++++++++++++--------------------
 1 file changed, 47 insertions(+), 39 deletions(-)

diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
index 3cfdf4091001..46d1ddc654c2 100644
--- a/fs/hugetlbfs/inode.c
+++ b/fs/hugetlbfs/inode.c
@@ -96,39 +96,14 @@ static const struct fs_parameter_spec hugetlb_fs_parameters[] = {
 #define PGOFF_LOFFT_MAX \
 	(((1UL << (PAGE_SHIFT + 1)) - 1) <<  (BITS_PER_LONG - (PAGE_SHIFT + 1)))
 
-static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
+static int hugetlb_file_mmap_complete(struct file *file, struct vm_area_struct *vma,
+				      const void *context)
 {
 	struct inode *inode = file_inode(file);
-	loff_t len, vma_len;
-	int ret;
 	struct hstate *h = hstate_file(file);
-	vm_flags_t vm_flags;
-
-	/*
-	 * vma address alignment (but not the pgoff alignment) has
-	 * already been checked by prepare_hugepage_range.  If you add
-	 * any error returns here, do so after setting VM_HUGETLB, so
-	 * is_vm_hugetlb_page tests below unmap_region go the right
-	 * way when do_mmap unwinds (may be important on powerpc
-	 * and ia64).
-	 */
-	vm_flags_set(vma, VM_HUGETLB | VM_DONTEXPAND);
-	vma->vm_ops = &hugetlb_vm_ops;
-
-	/*
-	 * page based offset in vm_pgoff could be sufficiently large to
-	 * overflow a loff_t when converted to byte offset.  This can
-	 * only happen on architectures where sizeof(loff_t) ==
-	 * sizeof(unsigned long).  So, only check in those instances.
-	 */
-	if (sizeof(unsigned long) == sizeof(loff_t)) {
-		if (vma->vm_pgoff & PGOFF_LOFFT_MAX)
-			return -EINVAL;
-	}
-
-	/* must be huge page aligned */
-	if (vma->vm_pgoff & (~huge_page_mask(h) >> PAGE_SHIFT))
-		return -EINVAL;
+	vm_flags_t vm_flags = vma->vm_flags;
+	loff_t len, vma_len;
+	int ret = 0;
 
 	vma_len = (loff_t)(vma->vm_end - vma->vm_start);
 	len = vma_len + ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
@@ -139,9 +114,6 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
 	inode_lock(inode);
 	file_accessed(file);
 
-	ret = -ENOMEM;
-
-	vm_flags = vma->vm_flags;
 	/*
 	 * for SHM_HUGETLB, the pages are reserved in the shmget() call so skip
 	 * reserving here. Note: only for SHM hugetlbfs file, the inode
@@ -151,20 +123,55 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
 		vm_flags |= VM_NORESERVE;
 
 	if (hugetlb_reserve_pages(inode,
-				vma->vm_pgoff >> huge_page_order(h),
-				len >> huge_page_shift(h), vma,
-				vm_flags) < 0)
+			vma->vm_pgoff >> huge_page_order(h),
+			len >> huge_page_shift(h), vma,
+			vm_flags) < 0) {
+		ret = -ENOMEM;
 		goto out;
+	}
 
-	ret = 0;
 	if (vma->vm_flags & VM_WRITE && inode->i_size < len)
 		i_size_write(inode, len);
+
 out:
 	inode_unlock(inode);
-
 	return ret;
 }
 
+static int hugetlbfs_file_mmap_prepare(struct vm_area_desc *desc)
+{
+	struct file *file = desc->file;
+	struct hstate *h = hstate_file(file);
+
+	/*
+	 * vma address alignment (but not the pgoff alignment) has
+	 * already been checked by prepare_hugepage_range.  If you add
+	 * any error returns here, do so after setting VM_HUGETLB, so
+	 * is_vm_hugetlb_page tests below unmap_region go the right
+	 * way when do_mmap unwinds (may be important on powerpc
+	 * and ia64).
+	 */
+	desc->vm_flags |= VM_HUGETLB | VM_DONTEXPAND;
+	desc->vm_ops = &hugetlb_vm_ops;
+
+	/*
+	 * page based offset in vm_pgoff could be sufficiently large to
+	 * overflow a loff_t when converted to byte offset.  This can
+	 * only happen on architectures where sizeof(loff_t) ==
+	 * sizeof(unsigned long).  So, only check in those instances.
+	 */
+	if (sizeof(unsigned long) == sizeof(loff_t)) {
+		if (desc->pgoff & PGOFF_LOFFT_MAX)
+			return -EINVAL;
+	}
+
+	/* must be huge page aligned */
+	if (desc->pgoff & (~huge_page_mask(h) >> PAGE_SHIFT))
+		return -EINVAL;
+
+	return 0;
+}
+
 /*
  * Called under mmap_write_lock(mm).
  */
@@ -1219,7 +1226,8 @@ static void init_once(void *foo)
 
 static const struct file_operations hugetlbfs_file_operations = {
 	.read_iter		= hugetlbfs_read_iter,
-	.mmap			= hugetlbfs_file_mmap,
+	.mmap_prepare		= hugetlbfs_file_mmap_prepare,
+	.mmap_complete		= hugetlb_file_mmap_complete,
 	.fsync			= noop_fsync,
 	.get_unmapped_area	= hugetlb_get_unmapped_area,
 	.llseek			= default_llseek,
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/346e2d1e768a2e5bf344c772cfbb0cd1d6f2fd15.1757329751.git.lorenzo.stoakes%40oracle.com.
