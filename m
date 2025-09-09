Return-Path: <kasan-dev+bncBD6LBUWO5UMBBOG277CQMGQEID2FY5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id D74B5B4A666
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 11:02:50 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-32da5dbbe9fsf468954a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 02:02:50 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757408569; cv=pass;
        d=google.com; s=arc-20240605;
        b=kod8KrsapHz2mb6NTs2BRJzjBkFv6HbwY0pu1JoSHgro/MyAAZ4NoCxN0m3EfV1+Eg
         1ehwju6YER2eQU3bM6+5ZsyzSJnQdC5Ps68j37JJ2q1tjI991PS5LTNCklVM2DZ5jjRZ
         vC10wdwJQa+31qWiKVB168+R2Slatv2nq+r6KxCRk7ZPQKcNfKsC3ZTnuCtEVeN/bev0
         s6QZcAmYw1NYa7mkJJ3wDzEJCr/w4ff8L0ybq6BmB3JocOYCpHZnzNNcyY23W1H2NRFV
         htBaeowgBJ8QuTpv4eNLapz0ceJEPS+KL4uB8+6HuyK23GJ0Q7xNb8N+QvitVlDmMq0L
         czjg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=z6dVVZWDCmMsf/CwGCGdAZYQ7azSMsDDHnIczGwsgKc=;
        fh=eksT8E8a8zoio4cDSuj+hkelAnR6Uh6axQKCCP+Tecc=;
        b=hlPxFDgOK9R1CBd0D/lNPIXAs9RfmwDo0Av526WjxIvvYLOxj3WKmk31gKl42bWfhl
         4Nkae22Ljjrv9s0BwmmQgKp5GIy80HRh2nRNszRpVetzseD/ZgCOOTBH/bVhU+TGLW+T
         qBdIHidzvcHKCGDDLbPk3Kyn22p+RDA6zQ4L4+JYgEDwF0pOz4DJ1ogbPcwqboHWV4XB
         QJwQ4CiG6/T2z8uwtmyfd0feH+AP4TahDXjXNHw5XIZVh4D5ZYtPWQ9+pPXeO8SpXUtG
         7wNzbGM9pA3kKC3lXvgn5+Bw6b0/N5LeOGjoCxcWDNEGmpbczOQFgBadd7NxdXBcJ7sw
         fWew==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fby3hU9l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=BGG4P5Sn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757408569; x=1758013369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=z6dVVZWDCmMsf/CwGCGdAZYQ7azSMsDDHnIczGwsgKc=;
        b=awxh6guWg9gHtOh3uGN1hdrqlGrKEkbrNiq16hpeE79OSKvcMnM2hkUl38h+wWkvqq
         J2KhDWxyzCjM4qGaPR47vhH2/+KqoTe3pbdpWzPYH9WKrCKlZXbmgWlxfyDfeehNmAxC
         AiAB/M46EUgqVpPmDcO27tQtgnMuvqQ8CVBMGJFWSFp6qT99dEAPuCGXDff867JWIt4y
         DeP/MnoHfoX2I151mPiHB5HfYDy71EoIjBqunh6hk4eLVf6abNoJTeKRerqfFowmRZ4J
         GX1fJdCTrUx3FR6vnidHldukpEli5T/8iDom2NEPabcTYNNFCHWs1ktZj8RwZ/wxxS2B
         921Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757408569; x=1758013369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z6dVVZWDCmMsf/CwGCGdAZYQ7azSMsDDHnIczGwsgKc=;
        b=nIQ4tfXruESt/6QdL1bYkcjPf93g9glnTmgrcrAo5X9S18UEJOzRqRnKQs6E/e3K9Z
         lp42aCUjBuRVq7+Qbm33DoK9tlsq9T7Z8vArnsf4aMAoTH4UhNjdAtT44F5hl+e3XOhz
         +NU5xMw/P3DVpKiwWnSpZ9ZiuL8a33jN3fujbKZGocdiaHTseW9X62MnD5BYBxUkDin/
         JGExea2IobOu6YScjr+EOU1UDuBKyQffs+8YhUGlilZLMzCG9PCqflr6PQVqyhKfSbvK
         cvL3PB+uruPDx5QxLaX5jbATYppAPbp+0UA1bpJRX8PSRhty6L0TyrOqbIQQ9eq/chl1
         qQvA==
X-Forwarded-Encrypted: i=3; AJvYcCUUy07Pv98uM04FYacTtm5D0qNfIzPLtIsdqtVlQFfATKRxG2yPeKDYs+q33WLbmnUjl/VpAg==@lfdr.de
X-Gm-Message-State: AOJu0YxWbfy3Mjq6y+V3e+4d3Mc4cb9cxwCy2sJ3E11NLBtW48XOrqJA
	OzBLgXGn6YVMV3OHo0N3HgAn2vTdBiSONf8hkgeNcfi3vmfRx0ZgfBR/
X-Google-Smtp-Source: AGHT+IGU1tFePBUvXDWpMXilkWO5VnRFYxFeBK8ikI0t8X6v25xPj25h6DnWXHupqErnZMbPMzzA5A==
X-Received: by 2002:a17:90b:2249:b0:32b:7082:c1 with SMTP id 98e67ed59e1d1-32d43f2e3eemr15366965a91.12.1757408568810;
        Tue, 09 Sep 2025 02:02:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7DhxLMuyJgnIs7JdBx+2lyu3hMpFCe5DC+xA2binMAGA==
Received: by 2002:a17:90a:d005:b0:32d:36f0:e621 with SMTP id
 98e67ed59e1d1-32d36f0e630ls3504871a91.0.-pod-prod-05-us; Tue, 09 Sep 2025
 02:02:47 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXGFFkBjnV55MjRv2CXVCcDsjHlskk0oZOSJS0/RYncWe6iJ88JCQP2jU8DUkXr4dRijqKVl7EK0y0=@googlegroups.com
X-Received: by 2002:a17:90b:3d8c:b0:32b:be39:7810 with SMTP id 98e67ed59e1d1-32d43f2f437mr15846750a91.16.1757408567217;
        Tue, 09 Sep 2025 02:02:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757408567; cv=pass;
        d=google.com; s=arc-20240605;
        b=dk3zpGlTGid/dmoN8MhKtO2tnGw8r1qskop6M1+1I89GrOdqe+/tIMpk6y4NmJJZ+a
         NEIXUZvOh6ZztEDjssNpu6JQEs0SvOYcEUG/VSmfIY5//0DYNMDOENOAK3J7AmR7jBXg
         +ZekESdnB1jDd0YOXofRr91HMhItifLDwBTCidMGEF7/p8vnFi72iE5DDSmKb1UntsTO
         kYH4xgmE4z+7qrDEsSjQNUIbjLTixSmnkDBINMYQH+c0LLsrJHAAegVpT1L3VVbN68kR
         emuGN2TzE4PBLH3OZrnUb5HhFXq1v0uL+tdNQhY2usfYUWSOIPJyKH0xQA81/vKmo/Va
         qpAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=VNQsMydS7yWOLelpdGtphwOXejiwVo0zgaYV2Iorq9U=;
        fh=xYe2VetryT9meapuwMBc6HEwOrNuLoYJKA/f0iF2dE0=;
        b=MRx+DJBfdstt07laU7+ooxaFY4h+vXCGOpl8VZMdqEau4bgSb3r9U3rw/OTYrOeqAU
         ZLiCM301+FZnEl2W46k9XtGSkAuYI7RYdBaECac5+Kla6CZ0XFkkZcn8wAreAeu7+AnF
         d0nooPQb2eITUS00laU5TKXRFyPsg6sYC6eMfBQ+RBBu20vPJPH0znGaaET1HstK9n3y
         X6ODWudHKI8NEiML23tjhMi4wqMvZLSM1PdjYBCy8x4osSmkxt7e9DO6y6sEj0XCbICJ
         HhpxUEIGOkfvBSklUolMuemzn96EfnwOM1q3Czj+nZZXpvVUfZUWcYzhkAm/Lwsb6ASi
         dDGA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fby3hU9l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=BGG4P5Sn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4ccfd81d13si1197832a12.2.2025.09.09.02.02.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Sep 2025 02:02:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5897g1Ol009625;
	Tue, 9 Sep 2025 09:02:35 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922jgsdar-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:02:35 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5898u41e026540;
	Tue, 9 Sep 2025 09:02:34 GMT
Received: from nam11-co1-obe.outbound.protection.outlook.com (mail-co1nam11on2089.outbound.protection.outlook.com [40.107.220.89])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bd9bbh1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:02:34 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RouU61+EE3f1Ubf+Fh5KXDWA9RZKX6XqMLaY57ecaHG2kNh+FvUOmJFb+4Y5al+p6JpTPjcWOyuuSb2fuBts2hjDkI8JvgYDSPN9lZ6h7bGqmiWSQWI5Ok5y6psoZcf+HjLUBmQjyRr1oP8GUWFSXJJ/rBQAbKqg6vWa8ypRodYZiHWbmKq3KfPewqRxczrfOE5JUqkzZIgaN6UCe3oCqEMkOp2cHj4kSTXvdIUFXhcAIx3BQna2eMQgO3D/p0EhqNQdzGm//UknSRFvFhzlHMYvAW63z25j3d2CMX9d6Nk4/EKu2hGGrLwyZfj4dnczaMWzkyMRpsCLDeKwjrUMvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=VNQsMydS7yWOLelpdGtphwOXejiwVo0zgaYV2Iorq9U=;
 b=QtT7eARFd519QUvCCuZjs5N0kFdzV7DFE+N2WOFTm69tBTYAl1G8w7EczcU23JlEuCeTNF20v4nT3X9KyYxr6fyERUNu8PJORXXa3/NnB3IA7kfAZ5R/nB/LMPr4ZoGGRYernbshHH0h0AVkWld2VnWtpCQX6yYvhN9wuBSBLCCx+phqJdbAsk7ccTHwslNcL2VxJFUQJMZqeKJZW0HtwkCCSdh8DHlYjaC0WboF60D6jh5S/QyudYJVrkhZbw8/UV8JVqnpwrf7YtvwB5ShTRNiDRhxtce0zt/+SjMlqjnCPxRdukcfwb1EW6oh3xEuLBBvRQDVoCzmZincFRYQ2Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH3PPFD7011BF84.namprd10.prod.outlook.com (2603:10b6:518:1::7c8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 9 Sep
 2025 09:02:30 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Tue, 9 Sep 2025
 09:02:30 +0000
Date: Tue, 9 Sep 2025 10:02:27 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Randy Dunlap <rdunlap@infradead.org>
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: Re: [PATCH 07/16] doc: update porting, vfs documentation for
 mmap_[complete, abort]
Message-ID: <0a19543e-d2bd-40d0-8f0a-42cbabedaa9c@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <1ceb56fec97f891df5070b24344bf2009aca6655.1757329751.git.lorenzo.stoakes@oracle.com>
 <c0d7df5f-ac43-4e15-8400-155bf87d5e77@infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c0d7df5f-ac43-4e15-8400-155bf87d5e77@infradead.org>
X-ClientProxiedBy: AS4P191CA0036.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:20b:657::18) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH3PPFD7011BF84:EE_
X-MS-Office365-Filtering-Correlation-Id: 840287a8-ea2f-4e34-2881-08ddef7f9b28
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?A0Zc9ZhKjmf3bNgIZnfqvb1MyoXGD0Bg3Ou3/j/6vRIsb2Z42qy0nZ2wWgKF?=
 =?us-ascii?Q?IdIbKD3rSWi7sBIzzJDTULGw2TM1190O6ynpgzQiQ3LQCC1JwG73ku4gRMwn?=
 =?us-ascii?Q?lLiVA2jSw1pYHQYGhZeA1GTvz/O9Dmn1OpRah82AySmJ17gBbYQSSg9PgdEX?=
 =?us-ascii?Q?QKE4T8S3iHc9IvONrgY51/+tmKpS3B9Ja9qvLdnZ325PPOfXM1nLuppMRk6Q?=
 =?us-ascii?Q?lMhuqMDL7nqbAZSwQXLVI/908yszVcKKgR4GPCB+v9Y9dowBg5yXsnkOfztl?=
 =?us-ascii?Q?gtCrZOgsVZLoHgicdtNfy7LKIPlkGp1rQl0/GgVgisB9SEDWR0rbgytKQL30?=
 =?us-ascii?Q?Wnc84ymDnsOh8mH144QhQk3AeuyKeBCx3xXZmLviZM3BaBctbtZgVxHX+1H/?=
 =?us-ascii?Q?dUc26N65R1WTWMckHzT42sflpy8jRU51A/HSnDLk9fcWKCJUdyLI/vPaFXMV?=
 =?us-ascii?Q?k1VtVhnS6LmP0IE0nnWf0YJnCepLWYsO4ocltog07XjkNtudMkeOpAxE0T9Q?=
 =?us-ascii?Q?sM5gEcEXk6kNw4AqWQbkXA3zCnZkIM8gTx/3PthnDNNsx8ZJdvwLSAanCKV4?=
 =?us-ascii?Q?d2M/uvrucCSGEveSBRxqDJrOMc9nlMGKIAKItbHKjzE03JyCbR7huXYHu0HE?=
 =?us-ascii?Q?m2x1tG0V+C1D9+KJfszN1fxSy7pnaFbgIB6rScbiIQvhuYX2TDDUH8JLWV9b?=
 =?us-ascii?Q?UsFkPh/VJmWEV8jsqTnREQ03ZJkhMkNjcNyhJzoLdFYyYhcSSPHrnmX14e9f?=
 =?us-ascii?Q?bS9HyHFVV8EZpgkFZbxodA4W8h/aJhTlwc9svALmVbGNYIMH6iAPb5nA5XHc?=
 =?us-ascii?Q?FS/CXd+FqKIHtZVIBRi5bkPRqEYp3LJp7MsHaeaH7jRq/dOoEofvDDjPbiMe?=
 =?us-ascii?Q?a97uU8NAyj9TrixQT/XDkpJj5XplMJgdaGuJpPyet4J93di0YQxojSvhZpzR?=
 =?us-ascii?Q?ar3dkpya1FHA0ql0TnFYWf3dzwUmImd8d9rclH7VRH2WHUFWviB4V5iCvlw0?=
 =?us-ascii?Q?Et5Z+wbOb73YEMUjWsDL5vO3ltlTMNVIoHhBXdsvoMj4ozD+ixzric4UdVrD?=
 =?us-ascii?Q?LsIrHvhdP3Cb+NdbRIzZUlRtu5djuYL01hOGx5X8rdpWzirh0COSrN3wJJDt?=
 =?us-ascii?Q?FwZJ5KU4fGila5L0rFg7T4aeAP7AyBnw073ed+ka3V2PvCQ0bxlE6EXXWMHi?=
 =?us-ascii?Q?w/DpeOsr6xhD0Q76cie/ktGiaUmQ2ymogQRSgHeYZj4iIg5rzSBzBBXsPKio?=
 =?us-ascii?Q?81c3nZqkA6CYgzCcvCZoj+AxkjnNBBVZJnjoTAaCa0b3MCpsFcJMiqcK6M7w?=
 =?us-ascii?Q?aA7J8LbZCNHVWEjrap9nNJVjj31Ikr0/isLfJqQlV32BexatGdNJZnIEwy5+?=
 =?us-ascii?Q?8SL5z846YZlnI9VLsQlqbt7MX0FBPrinRixdaDmh5UgCX0PFWM5VoZplgoTv?=
 =?us-ascii?Q?2QncEd0ADqc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?/vqDD/7sVCKCkPupKB5+SgEHn3lAz1ZWutsIF59Z4QOXcYGLhcnVCnVQ7Vm8?=
 =?us-ascii?Q?0tworREyRd02GgfAxPGMOE/uW4LFi8KTbILO3Seq08VuytaauCFFlnPIQJHZ?=
 =?us-ascii?Q?pimJdXimufB5GET5CXGL9zp2lOtkp9Bq62AiieVgVBaNt62//svohDg50JH2?=
 =?us-ascii?Q?8AnACGEbU0Zz73n2EgFvtPssd+DdPv9Do+tyMJHkmaXyWwMSNAe0zyW8RAl7?=
 =?us-ascii?Q?R73D/4BP2Cp6eKIutgZqsOTyGDuHL2sh/iA0hKdkXxIbHoRGFibDvX5VXZZY?=
 =?us-ascii?Q?fGMVmzz6RGqKODQXzwx78YEsusQ6tXA/cON7xN4cXHkMkMKFZFvuwFhhqscg?=
 =?us-ascii?Q?OsD/58KgknaT3B7WDI3hr1IhLLYdqumcP8YjS08JhGKtkV1PN3IwQmPTEMVj?=
 =?us-ascii?Q?8uIx3QseLVJRXVu73N4hHRXCX78EINq8N39IYiAgWyk19L6Z4sR1a7kPRwE9?=
 =?us-ascii?Q?9X9hawKfy2OxfuglSmhRCHnON3WToJ16DQOxensThyvHvcGMuLUY9x70ckUt?=
 =?us-ascii?Q?19fXK8Qnsn3BQWrvSDLsLDMQG3oj7q5FjYPVv1aKBSnwSN59eTyCQlV9MKDv?=
 =?us-ascii?Q?spS2q53J1RUFSZSu3Ye/lDPr/JAqySxAsA5k5Yu0Qngm0SG4AkV5CloUSRJ2?=
 =?us-ascii?Q?LqCNOPMHZ87lQxFZ7Rpy7fDsqgroNvTW8k2s9KdDcDKMd5gSZdZ0LdJcbrPx?=
 =?us-ascii?Q?PufIBdw2D5yzrnqToiSuv6ba2qEMLWvSvbTNccJ6JmRM7jFVVC0BROsnPb1f?=
 =?us-ascii?Q?RFKKofE2L+LYWXmr9y1e3H+JIWfSAe1g3LfCYt2LtLimeFi7X8AKTxURJDuV?=
 =?us-ascii?Q?cpG3OFhHLgIK9vrwcWG+A4LFwEgszfDuTEpqdqbPSMweDtbLdKAQE68pOMV7?=
 =?us-ascii?Q?SeoRoay517z7kG/HhmqijzBiVa5OrMQQCC4iLVS5ME1vrxjmOeplVC1ub2Hg?=
 =?us-ascii?Q?qSizqMNs9iy6dB3Vl1XM3UozISMEQf86+dWVywuJraFbkKXDTOuyXtPrONVg?=
 =?us-ascii?Q?FIVQAu1peuLgO6Wgaqgj+6jpD2aG574slm3FSnDNfwsP17vhH+u8lTXmYlu9?=
 =?us-ascii?Q?TgZn+NCi4O7iufUS5J72CDvVeygPu5pX5u/RThAlfFoYxlv52wGBlSETI9Dv?=
 =?us-ascii?Q?wkMaVlaPER8q6432nPw4JbRrPfuvMAmzjFQ9rphgKy2O/bGT0Nztb29MtNST?=
 =?us-ascii?Q?OxKuRLQII2PewNeTncegvDjOiPBye5Q4QojAABaY6E++pcopofqGDjuE1UPr?=
 =?us-ascii?Q?SIeVaplNMBPdTlM9cvfcWDixQreowoUCZ8gAdde1fOnkRQqbOmTNCtNZZ1tj?=
 =?us-ascii?Q?Y7doLnBndsOQ8Q/O3Ka4QJNNNUyvYPFpoyUhavThcbKpMXvOu6HBQIfcen1K?=
 =?us-ascii?Q?8brfCn/DcXjPgSAKO5GPksRHCZ0Yk6HCz5Dvy71PoPsQj8f1epAI1NNE8obw?=
 =?us-ascii?Q?EIbSDo/Ay1SNYoHSJiE4h3vZOKuN+NECBSV7d+DpNVEDuriE0Z7sAGhyWlkI?=
 =?us-ascii?Q?Bq89kIWmNZaEVjF2tozxyU6WmB3KlWF3h+Hx+v5gSW3C5BMoz2E0EL80xi9/?=
 =?us-ascii?Q?KTkNVR3LfbDsxa8eOi7fjyDKaYewVkv9rtAdaWJTd/DtaG+6hfAd7U9cD3NI?=
 =?us-ascii?Q?+g=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: HRera3tBPG3djQckdCSg/DiPb7fcpq+lbncWSu2mKXKCkqHlx03AmfivQYWIebLzRv/4k013sY9dQFARc9OfnuTS2L9oKG8FyAPlL/CDlBKaersWl6W87yY/NlrAsPeA4e3ZNYIsQ9u1yUqJQeQ75Dga0DI9WjDZATPnOvCGfnUYMF3idlslCrTuxFcY1f6ZZd6SZHwznaIjcEezkQZNKftkQDctvTDLvhXYe8ZuBKmsO1eSk6LJVhFjW+J9rpK42qVBlsPVHrSAnXDS+tBGtELC+BF/jNDQxU/hrQmqXyzZWU4qSTXko2QnCfmVsw3WX/pkR+PSDuGGntzG4eWaFqgvlA3W6xpsuqweacnW39xV0rl+aoqlEPkBJf/ssFFxjhCULZNq9tf1mo/qPW3jqeqiQN4YPJD08XP2BcB+S15Hew4DKJgVwhGsTE1Wx6KKEbDu+1L7KXfrF341kwsfHqFkHfsN2j5FY5IFk4AiNu+h9Rq4/1WL0GfMN2qCT9GLo2bYV4ZmmX6dBw2wZGM+/UX3YogmxHgJRGnQmUsi2fUmKlT3lHreayi53c9dEcEb4+UXOjFeNBYc97Ty5Ye0ghynPl7TuxgbP57cb0AkDVQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 840287a8-ea2f-4e34-2881-08ddef7f9b28
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Sep 2025 09:02:30.1169
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: O/7M9LKhfoM4+Ihn6I6e2Yv61OWStjKVs2MOgg3heaRVyBJuyhmka6MxnXDIpKFhlRiT5H9oDQ6KbyKIY/1Fb1NgObA2G6j65khaquXPmsA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH3PPFD7011BF84
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_06,2025-09-08_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 suspectscore=0
 mlxscore=0 adultscore=0 bulkscore=0 malwarescore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509090088
X-Proofpoint-ORIG-GUID: 7RqPNJvbkIbL3TpOON1cLpYqfiwzL2xB
X-Authority-Analysis: v=2.4 cv=PLMP+eqC c=1 sm=1 tr=0 ts=68bfed2b b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=ntSo-Hi3etu3jdbqjNQA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13614
X-Proofpoint-GUID: 7RqPNJvbkIbL3TpOON1cLpYqfiwzL2xB
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2MiBTYWx0ZWRfX1WgknYqrL8DJ
 PuUbOP7t75ejQNwHd/jDbvPa/Z2KbLrYEiKLVewUnebmfWUxvGjmyLDmfJ9mBmo912dCrmwizJV
 i57cmsqRZuoAQTtSlkeQ4CyMcvOJIoexU09rpPM3rfVHNCD2l4rn5K8KSXIImuQZCnIW9EfLwVp
 BcCtOR0R2trICU/NEE8H3zfQoG5fXv25h4tLjGcPhMoQGozNUzVadiSmfAV9bq0jDaiiOgmEY2T
 VSAmyO4wFInuX5J8nJccil6csZ87iFGDP6z6+7tG1lnNs6qo7Ep7+E7dYxGFad4yTYZDY+mIhAb
 X7ghACgrvRzWqtPECqtLXqcXwBQzVeMBWy39m1zRQzkAy0LqWXuqJ9ng+6Q1++/kt98C7Kvzr5s
 dc/qhcqx5qEDl1z0oNldfTf4rtP6CA==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=fby3hU9l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=BGG4P5Sn;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 04:17:16PM -0700, Randy Dunlap wrote:
> Hi--
>
> On 9/8/25 4:10 AM, Lorenzo Stoakes wrote:
> > We have introduced the mmap_complete() and mmap_abort() callbacks, which
> > work in conjunction with mmap_prepare(), so describe what they used for.
> >
> > We update both the VFS documentation and the porting guide.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > ---
> >  Documentation/filesystems/porting.rst |  9 +++++++
> >  Documentation/filesystems/vfs.rst     | 35 +++++++++++++++++++++++++++
> >  2 files changed, 44 insertions(+)
> >
>
> > diff --git a/Documentation/filesystems/vfs.rst b/Documentation/filesystems/vfs.rst
> > index 486a91633474..172d36a13e13 100644
> > --- a/Documentation/filesystems/vfs.rst
> > +++ b/Documentation/filesystems/vfs.rst
>
> > @@ -1236,6 +1240,37 @@ otherwise noted.
> >  	file-backed memory mapping, most notably establishing relevant
> >  	private state and VMA callbacks.
> >
> > +``mmap_complete``
> > +	If mmap_prepare is provided, will be invoked after the mapping is fully
>
> s/mmap_prepare/mmap_complete/ ??

Yes indeed sorry! Will fix on respin.

>
> > +	established, with the mmap and VMA write locks held.
> > +
> > +	It is useful for prepopulating VMAs before they may be accessed by
> > +	users.
> > +
> > +	The hook MUST NOT release either the VMA or mmap write locks. This is
>
> You could also do **bold** above:
>
> 	The hook **MUST NOT** release ...
>
>

Ack will do!

> > +	asserted by the mmap logic.
> > +
> > +	If an error is returned by the hook, the VMA is unmapped and the
> > +	mmap() operation fails with that error.
> > +
> > +	It is not valid to specify this hook if mmap_prepare is not also
> > +	specified, doing so will result in an error upon mapping.
>
> --
> ~Randy
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0a19543e-d2bd-40d0-8f0a-42cbabedaa9c%40lucifer.local.
