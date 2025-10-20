Return-Path: <kasan-dev+bncBD6LBUWO5UMBBJOO3DDQMGQESM6PXQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id F2289BF1014
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:22 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-430c8321bc1sf36237825ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:22 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962341; cv=pass;
        d=google.com; s=arc-20240605;
        b=FBMpQ0xFdvUNDW9gWsLg9GkhXv87X9ibP7ToYCkqkBt0lVis5HygN1o+tKg6StVzyw
         efYGudnVy4qWjQV64YKQmWzf3cd09PJ5Ygt2Sp99TkMm7LPvas0bb6Y5eRgm2R/Sb9o7
         /hbaA0+XX+tuBJ7GJnynanzuGGEHK8nflSr7R7o+iwNxtwL9s7qJT5amsDJfLtoHHt0k
         AOSi37Djp8AnaDDrTjWQcfBFySZaR3qa27l/u+8ehZF4W/JlgeaXJC3CIQMAmfoOZ9aV
         aA2wKNNRPyykvO5SK8zqcGCYZebg9XPbnldP8BFp9J5jK61VrkgYOu556+ub8j/wEzPd
         BwiQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+mwyj6LcX4+g3gbFGuBUzQKPLmgtSCykKPmz0/+Jn9I=;
        fh=8mzOmr1KyagiobJ1OwUfI5N7di86xpBvHUg/jvkMKk8=;
        b=L5/x90LXLzm/ibvk2n7Wk4dYt1/vbdf31ZpFODOGwrZH/Ml5S16z5lf53l7rDKGQYX
         ZuzXL2hrA2VTboHZja3ihHRXK9+Gh5T155aDbIEJqvYWbpaK0ADr2shPyUdUkbQ/2DxR
         EoOVAu9UOx86T9dHK8s6BTEdZ0ynKByWLuA6RjI04ubL3M7RJGzB2/TcsoDYoZ13QWCR
         OSwH8nwxpwNcEaJhCj1BFvG60RRtpIQRX45SV7AItAed8jy1IWR08zAiJ08yS1VVeKZA
         8JsbZvuzKTLB5ZlQ/xNZyzxwOZfNM0hj1+Kh7sfy5thdYxWMmSn8q6Fba6Esc/pjOZS5
         6lwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="XedX/zhs";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=doCX3j5f;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962341; x=1761567141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+mwyj6LcX4+g3gbFGuBUzQKPLmgtSCykKPmz0/+Jn9I=;
        b=ck3WojOSbCX6MYEzK1GlCr+NxpdxQrQRWrbEAFxSVfTItfYfQbJ6fMCmaajVN/nhN+
         ddVzADOsM5WL/aS5iMdOFRQoAGSIL2K0ZA9N/+UyRdDJuSd4y8U6h8cm0+1lwhIrxE55
         wRR6ukbJt0pby4ApqDOtEZaUAMxMLWWsC6FQfbDxeZW+XZvJf0O+zyue0PoEtggh0EWi
         HZnPbhVO3wOBV4kPQ4+2ZQ12DcdrRoNSMqirrslrEW9uAHcSu+Ft6iA4MiU7spIK4GFP
         3/p6HATTx2IAOHqKCB3yAS/1bXMjYk4kiOjBe78Jaq+7/E5MfbYa8NMIM+7ztmoXOTyF
         ejrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962341; x=1761567141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+mwyj6LcX4+g3gbFGuBUzQKPLmgtSCykKPmz0/+Jn9I=;
        b=JXFu5Wtds8o066/qUHUmZg9qlGZtu9oQSkBx4He4szIoVomP6X4lV0J6n5RyMjk63Y
         ZpF4yXvkq5N/L35vQqxfbHfgWOZVRHC0JXczt4MZfHLuvtNLi1FBlZl7KpqxPYZeGrko
         mywMcztDapF2ir7zwtR79h3NOmdPrpW6OQwicWqIWu0DwY9XJdUE3XHaWqeNPD6CBtDd
         Ys9+s1MXA2eahlX01su4E0CcF7VUfuMsulBL1dEFTt55lX+sdmHq2tO4ZlMMcK9gEiYS
         wGg0UgRasdv46gQRdTd4hbPCSLQwsw1l6SGvwyL0j6NHYVtvzV6iPe3/j+Sl7lYjlYSb
         LKSA==
X-Forwarded-Encrypted: i=3; AJvYcCXvZtiF1dj4c22noriH89AqCrapX4GkJFUvrRsr7PDcTuXW0ISEgoN74gzzPrhebURH0+ZKlQ==@lfdr.de
X-Gm-Message-State: AOJu0YyUEmDXYL+9hBft5YxmVzjwSFbLKRt720N6s4TpuV9zmWQPfdI3
	4uOt8voaJd756E4NYaI2EKrqXl5dSg7SZ1xhtcgXvHFls8SeqTBVwCso
X-Google-Smtp-Source: AGHT+IEi9ZGy+Kyr+d+hXuA6Op9hi799OyjwNABfbk7pwVK8IEy+WUnWnSsdXjrDWYR06B/slQWkEQ==
X-Received: by 2002:a92:ca4d:0:b0:430:b05a:ecc3 with SMTP id e9e14a558f8ab-430c525f528mr178375225ab.9.1760962341518;
        Mon, 20 Oct 2025 05:12:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6o7DVFWswY8Lezh6Me8BTX3Kju6oXxdFbvBbg72pTxdQ=="
Received: by 2002:a05:6e02:4507:20b0:430:d4ee:ff0 with SMTP id
 e9e14a558f8ab-430d4ee1104ls11957135ab.2.-pod-prod-04-us; Mon, 20 Oct 2025
 05:12:20 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVQf+7L1VPI7uwvMDFN95tlXoi/gTOmTDHWz8lL4RDAyNJubTezjPeFuxDn0HUwn/7oEIcW0Hz85vI=@googlegroups.com
X-Received: by 2002:a05:6e02:190c:b0:430:a550:3003 with SMTP id e9e14a558f8ab-430c526bd5emr206655525ab.14.1760962340467;
        Mon, 20 Oct 2025 05:12:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962340; cv=pass;
        d=google.com; s=arc-20240605;
        b=fj+j8TYRSQ1SG+X5+SiU0JARi11amkKf1MPbMwPJiclsmRL3ZKVimZck6XA/2GCYtc
         oSA/wAkOCF7WbBmVmr63mK5kA0j8cE3fNTHQhiqon3Yd1HsAwtszqia3ncvez3HskzGv
         DJTwBMfnMfzt/k/9nfhlU2+Kx/cKsfzrqpixmMKcaAaOXKsreSZoNC9FytBrRTXYdMyo
         f3nWeZlLmpj5yYABPv3b6T6EqCbYo9DzcLFTXNcocg+36NZf9c4GIzERj1Qj1oEbF/mN
         5CBxCxmSy7CSY/g0egr8KAEjmbaktXHkNNWvTbq8NPuihUBisW35AMNE0s2Ek3naqeLh
         t+HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=Tbd+xrtgAX7jQLjegM/oU5YYW4XrPGgQ+r1/SbDKG8A=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=LBMvYgqL8a7Y5R4fql4a5Alax3fBSpweKDSP1nlYtm01ww9TSEOYOtzgXf7B8HqdHw
         znfRmfhDSruwCGncgzWgIpV/chbokOnFmbj2FW3pkAJa5TPj6UEWpRq8byP+JmkMZvch
         yVOK7RoaFKnHofTL0dtqKSlduwOQ6wpgHe8x48a+6EbkgDSQ2MCHjwMFuw5L624MVag5
         g497E7VXAIL/eBHBAQkwYrAGr9DuvvyBdH2QHOtSo4RuBNMD3UYf0C1siG0YuAnh4/l5
         BOpbYt1nWQueEeBUMc6OmwpQtcDYek2RDurFN3Az2KUWYQNNoq1GXZjcdXX+myOvZoeQ
         1qSw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="XedX/zhs";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=doCX3j5f;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-430d0614ba1si4908395ab.0.2025.10.20.05.12.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:12:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8RmX1005909;
	Mon, 20 Oct 2025 12:12:11 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v2vvt4b9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:11 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59KAgp82009470;
	Mon, 20 Oct 2025 12:12:10 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011044.outbound.protection.outlook.com [40.107.208.44])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bbvbac-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:10 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=KP53Med+yKWpvb1nMtlUOYjM1QHM4Y6vPSUWNLUy6CrdQIBQhQ/JrI/1P3xEVey9RWqvTQ4tbRmmOEWKZpSvXn9m0JMkJEFywGE1c2k9VSvc27xx5w2xb7pHeqf3JYy9JHO/hX5taW1C6AaK1vOO0mfrPkS455+U5Tm4o9+y6L8PZgvAPpSSlICetROavMKnTKES/94uZy/NX02pkpMcFO5t/gh4fNlFX7U6EH1DqpW/SMT4YwK36J/0Crh5k45piPQFnkogNQWrw0nRk723OBkG1xpY7HdDFq6rDfHOLSQxO9BRCLIZPeJE0OCEiDwV1ZE3CalHGAU+ODyne5hM9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Tbd+xrtgAX7jQLjegM/oU5YYW4XrPGgQ+r1/SbDKG8A=;
 b=Yqe4pq4LROPWtVyMha5Cl1gl+45IRqT0OP2Rx7w6LhbERpa2h/tUOh9wWwIgzQs5LkFCriAkaQy5gf+DbNQH1fzsJTwlP6pVSqh7GkHO57VSjPgq/5v5I7jGMAwaZFiOLF55gRZBPQo0pqVnUpBx+a0f4j9TSv3FuV5jPftLPvtRwjqhxMsCZv20NxMBe8itMNYNWyK9H51skgF3lBpBFWvX/4CuJk/finHf3YHiHiP0FCfONH1nSVU5r39Pnw/JDuDFLhBXgZpBnax3gFPb8/HAUT+ilMj8D2d7YaggxnYT1DudrdUR14aVKiZfeiZbL6dXfWMTqphF/Q+KML4dRw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF4A29B3BB2.namprd10.prod.outlook.com (2603:10b6:f:fc00::c25) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.17; Mon, 20 Oct
 2025 12:12:06 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:12:06 +0000
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
        iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>,
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>,
        Sumanth Korikkar <sumanthk@linux.ibm.com>
Subject: [PATCH v5 13/15] mm: add shmem_zero_setup_desc()
Date: Mon, 20 Oct 2025 13:11:30 +0100
Message-ID: <d9181517a7e3d6b014a5697c6990d3722c2c9fcd.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LNXP265CA0051.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:5d::15) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF4A29B3BB2:EE_
X-MS-Office365-Filtering-Correlation-Id: 9cd34d0a-cf5d-4598-d10a-08de0fd1e2cf
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?JIbqlPqYtWBO1XP6ZTGbhGZNrxlK2vCYa2hTjILZ02URZKNs4+U/RW/FWKD7?=
 =?us-ascii?Q?BTRQvXYyqPid069QKNMlyVU2AsDUN9p5zASv4eWd1Fzv6Zpj3BdjTSDwqVRe?=
 =?us-ascii?Q?BJCuXnqDquEf0t9yusJpumKg7LxyWZcXd7YIekX/Auu1KJuVTbc2GzhN74XU?=
 =?us-ascii?Q?VxjpA3hcClG4VtE+Yt6AEgfeDVs8IoTTWp2UXUTCdZUjsu5wYpBMktow8Fwl?=
 =?us-ascii?Q?PbZp1gqNNtkZXLVKcaXWh1rLmVsqKLJtGwWqNKx5IMAUuWNc7kDpsCH17r91?=
 =?us-ascii?Q?lSn1MVrzVJHpHv5NyNnoNxg2NxHEZurAAjCBK5MRobaDn27ZIvxBtaM7RVVi?=
 =?us-ascii?Q?D0Pp0fLR9bkZFLD90CM5GC7iyjp8ax74qBZMeTayMiPfhmj2NJqTA8Yc95Wi?=
 =?us-ascii?Q?1nzD/wAk7Nlv7IKJnG95HrTJEhyNDBGrV3Ago8m2WISbL96NzJMlSWl8xTwH?=
 =?us-ascii?Q?YY07OBObqKpNbG7lREtFp7r0oZS7PBd99wDHjSvw/vWtl1Y53rUpZLqo2eVD?=
 =?us-ascii?Q?5CIKGvtQh0f+AqnIrkLbLUjDWqQCSjKepyRlHqPUT9h3wF+TRfs6ANnGCIbi?=
 =?us-ascii?Q?50YZbi8PFP4XvJRMlwq4gB6t+6LQJzC/ddtl8TTEYqT1A7/YyzRCM9lxuZ00?=
 =?us-ascii?Q?Hu29VeJmqimbLa6iwcEJT4BpodN+GPcQY/eu2aZZBLrrPxzOtves3r3r3+Ii?=
 =?us-ascii?Q?oLlTkz2RV9ubsLNOeIc3cdULmP2CEEKl9g3HLIxcYaU4ojd28Xh/ZaGPRmkZ?=
 =?us-ascii?Q?JlkzX85DyB9jbT9rJkhZhWENQ0zRAfCcyWyxIHgf9Ok08O78sPmYx+EYJTe2?=
 =?us-ascii?Q?lKFTfhENneoKQOlgXxcuNEpW4zWm9d4yvBPsPtJ0s2i2OfzKjnJmX/fI1Tu1?=
 =?us-ascii?Q?2GCVzHy5uHpnMXflmc/QY4YjrKMBDdz0b4RV7naouNd+LA6z6pmI3Ot4Zz3H?=
 =?us-ascii?Q?vpY+xfUmpkq3deEty9syTDLvQQBW6HBD5EwlWbj2Pah3g0nnf/uBlZTozLzP?=
 =?us-ascii?Q?WWubHeM9KNV0AHnMsIA9rzIqYZ/7yLTNpRNdZS3j8XROwxk6ZXVgQ2Hc+6c3?=
 =?us-ascii?Q?te/0jAfLiP0lX0oIai3Qlb5lJZvXvGMNuVutnDdAtNm/lNBVzd1xYME29MwT?=
 =?us-ascii?Q?VMvElyY9CAyWcvjrGeFOBYWxQJO7EnfYJO86nDd9Bxr+RuqoJcn7KbmYrgM1?=
 =?us-ascii?Q?in5uAX9p65/xcO+IoC+d/ZETNA1Yb0w6I1IL1ZESeNgZvxBKgOHNPS0K/Dka?=
 =?us-ascii?Q?Wpb9GkpmLl1/aSL/glMR9lQ3UGKisLlXmeth/GChWjV1AicJvys2+6sJu//X?=
 =?us-ascii?Q?sLut9JEBKN4ny41sgvM8Mk4YCB4b0407kbOPlRv+XRMICdBH9RBq+DkPNlGn?=
 =?us-ascii?Q?qAHmOcp+egeWc9pU+qL8qnb+L0x5LylbZ0T54tc1jjRo5Jmvt04wWI3KP72J?=
 =?us-ascii?Q?qk52URSEJ/JzH7vQutZ5zTOK0EGMVDql?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?WX6wqxSsJH3QqyZGcprKfZkEC8VLAYfujaM5kxKLrGR8WZfHuTJKh4HJ2kKm?=
 =?us-ascii?Q?ODRAX426u1WSWbuqm1XXvGj88OtmRKVrdf4LGjRA4NVay1eeX3j8rZR79Cq2?=
 =?us-ascii?Q?SXO0M1Df+0rZCYTezvQHGza23LnLwPa1IadjGwm2ounBkSqRPwTohudka1vn?=
 =?us-ascii?Q?gWmlFd563Zsiw25BooaapfvTpe/rXW7LME6/bVQCVHoLdOhu3unZXtZHTeti?=
 =?us-ascii?Q?ik76GxqpP/6bBdnDm6dDdmpV5tOGbfgSqBObI8qHrJ5hQxrkFTJW8g3al/wv?=
 =?us-ascii?Q?JJUVg8aBS5Y7ghgXlxQEA4oa9p8pZcuAcsn7xzsGSXu5F2uCIYrjHzAt3+pz?=
 =?us-ascii?Q?ICDgqOiHSYSgFWuWFSpaw/RH7i6PPTMDfnKdrF7x8l32EF9nsyhJxeEiQ+sY?=
 =?us-ascii?Q?whgvbN5DQIDRIbhENq9CNFkrIkd7oEv4VaCsa/HrE22f+ECgcinnowec29yN?=
 =?us-ascii?Q?n4gQ/TAwiJaTrvFCjCdFQGKzoOmhjmoAiuCQiPK/BrnEmAKhEq9KjWYDr3B5?=
 =?us-ascii?Q?NvDZdH9M7rppWUiRpKk8mT/XnCRCEnAihneEDwvvylzn8Q9dpu2K8pfimeDE?=
 =?us-ascii?Q?xQfjfKhVQDkx4Cr8aA1sXph7CkRp2qa2sc4WFLS+idmtl8BGEUErStGeQc1G?=
 =?us-ascii?Q?kV6NRQbJ7K/Dcjg+2Y9woWmd3trn6ZSJD9wufOvNI5vyGRkAoPjMCPP5f0XX?=
 =?us-ascii?Q?PfqDOaXIV49fjIr/ArNuEsBdas20Wu9sZs9UOwmb3aSZGoidpOLFb7tQ81if?=
 =?us-ascii?Q?X44V/asVOMu0snpEuINrIrfqcHwrytnWZtch08TUKvdv0bEAuUGhHNtwlivK?=
 =?us-ascii?Q?tSCYKp87fNIg3K9M/sBU6c5AQf4C0z4595Qq86FaZy6Sb8m06eLQLCiqUIiI?=
 =?us-ascii?Q?LFtTHqceKmU+lJaCAHWrF2dLEuvzjtGHQrr+wIN8xn6hEzbqUwvtFifr54JV?=
 =?us-ascii?Q?cZHQzM8ZldJDwzATm3prHXhi4M6ZyzGv5Mxh90WJXCrDST8N47FBnW5nUYZM?=
 =?us-ascii?Q?DKtsCWqWbk3YuFgPbkGYouhkhwKGKLP8s7o5syGJeOoQ6mbBLAywWt1EuWU/?=
 =?us-ascii?Q?8g5CHt+gVa87qYiSkToDl5njScmY+VZyGI2CkMYDxGuKrwKznp8FouEfFBXw?=
 =?us-ascii?Q?/4ErIo9k3lYacmVTjf+s4+SZv7puLkz2fBKYyZNk3ELaegTIsbzPzm1inJ4H?=
 =?us-ascii?Q?Z8GDMQXfx7Ld7Y10fk//RyVU30S6RTQF6LGCKk+nu0KPl/P0YPz3LWM+K4Ok?=
 =?us-ascii?Q?iYlVd0VriC5//aBrKKpa05H6Gct//rU0hLAMoHM9eo+UyH0YhXKzVVEtG+f0?=
 =?us-ascii?Q?jG53m4gWU+G1JwaSE1TL9FNTeeLgCWIDmo0/Rzo9gkmlcXjerqXdWecHXyHD?=
 =?us-ascii?Q?t9XyMk2MV/pSXk3vbukbCZPJVqgPt3Va9M9+7b+F8ExydccY1gQrts8kZ+92?=
 =?us-ascii?Q?sjztYYNemaKZPTil293yVfsB/l/TFlTuNuO0Fkjvahmeb89YYpXeonErE73G?=
 =?us-ascii?Q?AS3IsS8icHEgMfLmDbxBvTwpvrOiUpGNnUQ8FAILAgmyGmWyJQSRgzeI62Af?=
 =?us-ascii?Q?NxHfSA/YmxIO4ogPfbdOo5GQYF6nIdXHNNB2r2RG8x3ayWGskPfDVoHU/q7f?=
 =?us-ascii?Q?pA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: YMfs0kl0aVNL/SvxyBkCkkvFtQwdwXXBst86UIf++iV2ETRjKTCi++78PXXQ2xssMKJbv2i0g4H78ew/uFoiy2Yc9ZkA5sI4lKqfUxLbtziSawbdzDbJoZnhC884MWTlJZ78FmPNGzjAWT/w+8PVjm3tdH11U7BFxrZbiBcfPysGMi1vcriCD9YYRYyf09Zb05FpIU70l7a4v5uQTmMbGf5Jt3F7Zm18MVAuT2JJ5Zab/wGpc567tYtgr3dV0FBqFLawESwNXPGIaMEwo9YNrAqbZSWYatZYhc4iJRXl566ERxEONPpBVabzwKXvwyXnmFP2Kss9vAPyESJRlFyz2dUfScsJ7b+ss7jg/iEWRKZzzoXuXYCPLAv911sGnhcqDjkLhsyS7svMTn542wceCABTr9KI+TNG4S5iUL4MrvczJADpG1rvaQcoNh4f/5hoo+tXGOYIojy3knCdJfi41V1ksLsijCVN6iKzHM+RExEn9JxKvPrr6xrypFgxm86RswHiwBAjck82GqnMPu235ttHQt9Z01De4X4+v/PIx7/5jiPPKZmVQljorp+4HI8zG9hDgNxLi/AlvbAe/WTgB/CBjdrD3k8PKLq2ooHYWpo=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9cd34d0a-cf5d-4598-d10a-08de0fd1e2cf
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:12:06.5556
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CRFSlqwLgK+odjiFIN8QEHCBBAqdH3cUg0eDE5FLYCbF59dYGa/sFvpFwGx+hWCESLkRvuvthko6+Kg4O3bcSEjSdriNDtD20je1MDx9FcU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF4A29B3BB2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 suspectscore=0
 mlxlogscore=999 bulkscore=0 malwarescore=0 mlxscore=0 adultscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510200099
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMiBTYWx0ZWRfXxPfTwHEYbGIZ
 WrWH0/siAwoCPFJsSPmq1JQRW4gDM75PMdoAvBtBVDnUGSw8ykniXZJWLNx2OSRJKc3IY9ObFKS
 SawT9YvtmJEklAcWNsveQGB+m+REhH03aEOidl0T/0MpggIOCqNcSEyFQIvT8XHLqg9sDfdnYZ8
 LciXUWaSzfWuPecYggprKM0ukxWbk9Bc0VwNUak8/gOWqeZknvASKo91a/rGIoJ1O/iUB/dbFeV
 iewrrg+BvCkfo7Lu/qkmvFGujsMchKC8J5yYghbFxbld9VGVy7XFAg+0V47EI3+uUeCGdmWjFkX
 tQXZQ3Jn9yFtQWBrWHP08GB78tNToHZbv5xlla2wFB1Go5I/rc4kJtorxlC8qYU7GDNON0dQtY+
 9o5WGh3V70wmHZzlxblnSPzDDXq7aLJE5rckB2T6nWsqJdt1Jow=
X-Proofpoint-ORIG-GUID: okvuu7hU-4_ecdGeJh3LvKXmaazEAN__
X-Proofpoint-GUID: okvuu7hU-4_ecdGeJh3LvKXmaazEAN__
X-Authority-Analysis: v=2.4 cv=FuwIPmrq c=1 sm=1 tr=0 ts=68f6271b b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=yPCof4ZbAAAA:8 a=Ikd4Dj_1AAAA:8
 a=McSR8okSZ11kpnvm8pAA:9 cc=ntf awl=host:12092
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="XedX/zhs";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=doCX3j5f;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Add the ability to set up a shared anonymous mapping based on a VMA
descriptor rather than a VMA.

This is a prerequisite for converting to the char mm driver to use the
mmap_prepare hook.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
---
 include/linux/shmem_fs.h |  3 ++-
 mm/shmem.c               | 41 ++++++++++++++++++++++++++++++++--------
 2 files changed, 35 insertions(+), 9 deletions(-)

diff --git a/include/linux/shmem_fs.h b/include/linux/shmem_fs.h
index 0e47465ef0fd..5b368f9549d6 100644
--- a/include/linux/shmem_fs.h
+++ b/include/linux/shmem_fs.h
@@ -94,7 +94,8 @@ extern struct file *shmem_kernel_file_setup(const char *name, loff_t size,
 					    unsigned long flags);
 extern struct file *shmem_file_setup_with_mnt(struct vfsmount *mnt,
 		const char *name, loff_t size, unsigned long flags);
-extern int shmem_zero_setup(struct vm_area_struct *);
+int shmem_zero_setup(struct vm_area_struct *vma);
+int shmem_zero_setup_desc(struct vm_area_desc *desc);
 extern unsigned long shmem_get_unmapped_area(struct file *, unsigned long addr,
 		unsigned long len, unsigned long pgoff, unsigned long flags);
 extern int shmem_lock(struct file *file, int lock, struct ucounts *ucounts);
diff --git a/mm/shmem.c b/mm/shmem.c
index ec03089bd9e6..b50ce7dbc84a 100644
--- a/mm/shmem.c
+++ b/mm/shmem.c
@@ -5877,14 +5877,9 @@ struct file *shmem_file_setup_with_mnt(struct vfsmount *mnt, const char *name,
 }
 EXPORT_SYMBOL_GPL(shmem_file_setup_with_mnt);
 
-/**
- * shmem_zero_setup - setup a shared anonymous mapping
- * @vma: the vma to be mmapped is prepared by do_mmap
- */
-int shmem_zero_setup(struct vm_area_struct *vma)
+static struct file *__shmem_zero_setup(unsigned long start, unsigned long end, vm_flags_t vm_flags)
 {
-	struct file *file;
-	loff_t size = vma->vm_end - vma->vm_start;
+	loff_t size = end - start;
 
 	/*
 	 * Cloning a new file under mmap_lock leads to a lock ordering conflict
@@ -5892,7 +5887,18 @@ int shmem_zero_setup(struct vm_area_struct *vma)
 	 * accessible to the user through its mapping, use S_PRIVATE flag to
 	 * bypass file security, in the same way as shmem_kernel_file_setup().
 	 */
-	file = shmem_kernel_file_setup("dev/zero", size, vma->vm_flags);
+	return shmem_kernel_file_setup("dev/zero", size, vm_flags);
+}
+
+/**
+ * shmem_zero_setup - setup a shared anonymous mapping
+ * @vma: the vma to be mmapped is prepared by do_mmap
+ * Returns: 0 on success, or error
+ */
+int shmem_zero_setup(struct vm_area_struct *vma)
+{
+	struct file *file = __shmem_zero_setup(vma->vm_start, vma->vm_end, vma->vm_flags);
+
 	if (IS_ERR(file))
 		return PTR_ERR(file);
 
@@ -5904,6 +5910,25 @@ int shmem_zero_setup(struct vm_area_struct *vma)
 	return 0;
 }
 
+/**
+ * shmem_zero_setup_desc - same as shmem_zero_setup, but determined by VMA
+ * descriptor for convenience.
+ * @desc: Describes VMA
+ * Returns: 0 on success, or error
+ */
+int shmem_zero_setup_desc(struct vm_area_desc *desc)
+{
+	struct file *file = __shmem_zero_setup(desc->start, desc->end, desc->vm_flags);
+
+	if (IS_ERR(file))
+		return PTR_ERR(file);
+
+	desc->vm_file = file;
+	desc->vm_ops = &shmem_anon_vm_ops;
+
+	return 0;
+}
+
 /**
  * shmem_read_folio_gfp - read into page cache, using specified page allocation flags.
  * @mapping:	the folio's address_space
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d9181517a7e3d6b014a5697c6990d3722c2c9fcd.1760959442.git.lorenzo.stoakes%40oracle.com.
