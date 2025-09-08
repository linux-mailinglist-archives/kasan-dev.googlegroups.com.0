Return-Path: <kasan-dev+bncBD6LBUWO5UMBBOHM7PCQMGQESWBJEPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb140.google.com (mail-yx1-xb140.google.com [IPv6:2607:f8b0:4864:20::b140])
	by mail.lfdr.de (Postfix) with ESMTPS id 872B1B4934F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:28:58 +0200 (CEST)
Received: by mail-yx1-xb140.google.com with SMTP id 956f58d0204a3-60f47bc0cd9sf2493393d50.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:28:58 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757345337; cv=pass;
        d=google.com; s=arc-20240605;
        b=iVnYV3hSPWYqiACgol/2y7TQEC9OLNzvAeSiflXJWVYMY4+rIDZQNa16d2wfHGNTQU
         2HdxK0yVX1BWQHsD3ITi2YoksAJWIqR9/6R8WXGzfguylsWqNGK8+U1uEUxpg+sTK6eV
         r6NKLuv6dIurVjWj96pWCNVOqP5C/ChsGSGqT/c3VAng05Eln55IEE3IGpG+O0Ke6hlM
         vCg98lpxN04YEDkvovnrIorGruFz4ra0xi9LG+HFmCEkBGdJZ8H4QRn28hT3cCkBfylt
         ndoEr0O0FtA5CFoRjVWIHCeH8EjN8Lc/dcxDu/c6TvBrxeTBEWtN2wNUx6ByIVQv6Buq
         SaOw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ZJiDPvZt8974Mua3QkcbYWQSMCl9ncMVqclDg4SCHEY=;
        fh=aLg2WZU2cXY5OajUNKJRKgdU4/39SNO3rdCoFNCkBr4=;
        b=HsNoD7JTOf1F+4E2cBieJ7ogkLv6M9uoxmLH3Dpa0cvkmePYBAlzYwy8EUkgor8+pd
         iIHedPc5fQeTSkvhk/LEczhwFYeQ4CdQkTSOByD4f9pcn1T+vA4OOUZCtkAqHzXJwkZ5
         Kuq+tQo6EAdcWDtdLxd8QzI34Dvf8O4b8OyokZcoilYiWolW3Mvr9rz5BtsdmgeJ8zTq
         uk6bm12HezM6bmD0rQE1gIU//LTBDREDNgfATWQCLJei015Ju7B5uehUCbH7O+yz80jH
         Jzat+XWsZrTVDrMeGvU5o/e8OSc0P8gdZZgPygBzcMlPjfXFKBjR57WvhE89b/xxaR27
         CIXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=dnZhGRjA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=llLYgjNF;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345337; x=1757950137; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZJiDPvZt8974Mua3QkcbYWQSMCl9ncMVqclDg4SCHEY=;
        b=VxdAuQbwt/x7WmN998685jLdEPW3Z8IqXWLqVxuT/Br0oF4oBJtJVxvkyOe5rWVsIL
         QDmx9dAFmaOcQmdjMTMaef1N6r/VQvV975nTW5D88KGtrU2RBZH1yat05x4w+jZNT9Cq
         xZ4bWBF5xlG155sGZ2TsOYCzlB3M++HEKpBaEStpYGWjnvwBIRFp9RODLB7J4Hfka6jy
         Hrw/ExcvC7FcuU9a8/RpAXYLu57AS0GKpPqbB1PeY9X8DFtD60X0agaivmepEKcvdWqy
         DBgwV/AZmw1YZkHCEKaZati8fgEVeBzH8X5hEChQD1+W1WS17GN6Bb+Xg64fEhk92lYP
         Ns5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345337; x=1757950137;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZJiDPvZt8974Mua3QkcbYWQSMCl9ncMVqclDg4SCHEY=;
        b=EAJZw9YA40ik2bkc3WCboiFyIy9nF87h1lBDd8Sek9I9K9Qw6QTwGhX23bWINfyN1d
         kNRpdMq3pKFdef+WWf1FY19Rz0iopjBgUTsLqBe6glFSqNJcFot6kdhbGlZkdYhTQ1xs
         GmGmp3UhFM1ovlK+BDgykQFY3zJD5ZUNx6J6t3rRxWpxENIwGAql2CaTFVKD34LRs1Me
         x6hkS0rAPHtk6bFxHweVzU7GM489vhQuZu29lp8tnjuQ/c2JsyJ4Q8SXSG/+uAZ1WBRU
         TUqwQfCI1xCGKT4k5cGbPky5jpIA4ZaOQbF0Lr7k7HNSNT+KhOqbyvpM5UErGuLRTzwj
         Rr8A==
X-Forwarded-Encrypted: i=3; AJvYcCVtdfEEw8n9ZJmCplh78oQFPjb4OP+pxLcZIRav9iPE+7YF8WtY1tao7ixi9O/TDiiBRmKMPQ==@lfdr.de
X-Gm-Message-State: AOJu0YyDM6edNdFK+88SN6N1N0quhbZx2NRZRuuBSGyD5zoDrVKR8eOr
	GUBXBwutg6E+uBOb8A4Y5umS28QldqWd7grl0OVuioZHbEJFh9E8liFg
X-Google-Smtp-Source: AGHT+IG0ddtG5t+eIJ8bKgd0Ud9W/sGWHYi/LVKzYHuAk1Kw4j0I5E596sWDoCa97+V0bgWdbTZMlQ==
X-Received: by 2002:a05:690e:d4a:b0:5f3:316d:1cf8 with SMTP id 956f58d0204a3-61027e48d0bmr5689418d50.23.1757345336957;
        Mon, 08 Sep 2025 08:28:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4RfL2h/e71GooPN8gDUxQ8sslIvfJ8VcDTxuUa1key2g==
Received: by 2002:a05:690e:4199:b0:604:3ec3:620e with SMTP id
 956f58d0204a3-60c7872829als1449236d50.2.-pod-prod-03-us; Mon, 08 Sep 2025
 08:28:55 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXMXD4lRqVQLsLeYoCGhvOfTZLm3dKGU9ZAnMqCjFPNodAfMBZZoAshhFTLKk1zRvfNHKRRUvSzZbw=@googlegroups.com
X-Received: by 2002:a05:690e:4308:b0:603:512c:c641 with SMTP id 956f58d0204a3-610223a823amr4669017d50.3.1757345335781;
        Mon, 08 Sep 2025 08:28:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345335; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZwbJNRaNEhP/qacW3zdhkBc/S2DOH/6bwUG2qxrQT0hFwrIn57mgSDSq5ORH+X52YW
         rCJ7TBE5mGzadf8B07tGTf4Nqu7TP4cszyZTu6LuX/DVi9AhUMyyTtXE6Z5nMBuUstQA
         eKNaBFKN2srM6/Paaqf/eRhCytEmjzPH6ACfZXMf8EZnjKV3rOXAO4cD+qhAc9qDuAQS
         maYXX5wUKAdPp55Hhvjeijhw29DrHLccfa7cL9GJdKPy+ANAYGhtnmn3oJ2yYD60jswC
         9uE3ELEhcMIiqhjBhi/A6r2TRoXfNaptKsYwSc8MReXdrpBFXNujOBFQmvxOBAcrzIRw
         n7bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=LFrO642zTZ2CU0+cfg5wc9mH/pm/WN2tuE1Hv9pil54=;
        fh=rBgXewyurrOnUosxB6Y1BSdBMLv7NW0sq4bxnqF789M=;
        b=JFQ5q2cHkT6fAiynFqKZJXTfFZCyhYLBcEbYY7qqHXWczpCk002l3wAgFTgNZKlKbV
         b39Mv6wfZctO1aLCyExCdVHufxHu2yluy/UmTOslEzFGilRxDV4/f/8Nh7xOKB2XfawP
         Yks5TS/L4JQGsD2e3u/elKRb0Hs1fNwRL4QmAUHq2F2QfV28SQTgIsdIKV18O6xNgin0
         QXYYSsxGm7asojWpCeo/+xmEXehoFFs+i80OHd0Jd8vewt1mT+dNG1yD7HoQ7ad7lVqC
         qgtQ+hT2oSzLDB5INsaNag/WLQyblRrcDRxXoVWG9uyl1LI2Mc00NJeJKrGl3tw/SEkl
         eIFg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=dnZhGRjA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=llLYgjNF;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-723a85336b5si6502637b3.3.2025.09.08.08.28.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:28:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588E1rJ2017683;
	Mon, 8 Sep 2025 15:28:43 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491yx6ra97-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:28:43 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588EPFal002816;
	Mon, 8 Sep 2025 15:28:42 GMT
Received: from nam10-dm6-obe.outbound.protection.outlook.com (mail-dm6nam10on2076.outbound.protection.outlook.com [40.107.93.76])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdevh3y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:28:41 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=o0mHJoJggnlUwwwFyTzB2InoaYZnZ3VID0w3LxBujojZ4uMPs1ncZFE5i2wG30fQxWxr3j0TWUhX3YHv1X1ZRAaRm0Kd7N4Jamw8QcMknL4Ze5YQkAKVhWUQ++Zmc32sdIwiKMffF791BxyQ8om30yXAvC8UumIW+PiEyopV7cs4mMx+1CePjPdWBI+4vqYDNjoBgsYQR+sQJSie3EJjh1Hepv9rwOwQdE2/JphkShLDtcehhUvV8GrQ1Kwhll6AAXu2740eUCOVu1/WAOHjs5jpT5mkV0SiqMe9s0JRHVrqlXGuNozaYVY8HgfQLnoM6iYuhnwoxUPaHjuAP13uMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=LFrO642zTZ2CU0+cfg5wc9mH/pm/WN2tuE1Hv9pil54=;
 b=ErK0avFiNhbB4tmpaho3TNJ0Vq1qx5biCHizX3N8LtnrbA6l/5vPKDEc5LiWtSqWakACpn1etI2J7m0Bxs57fsIKawaOJPqNvnXW7YfJiD8kYMAikGGxR70PtB9PFbv99Py7jJ+0BbDwUfnuvOtl8On28D48NGTqiC5ZvoIjGh7xJa0LHeySwi+Gz/jY2c8kLF0qjWerDesLaznKv45pUqhFYOaXV8QxEV8XoPyE60s85bvTI9TtIaF9Xac4dTpwLz2KfkYYedaJRYqx4Ol2n3BllTS15o/uS47xyRxi7VCk0DnOKlkZMbyCKXroZ0FSmArHJz3zgT8oTcDDQ23a6w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SN7PR10MB7102.namprd10.prod.outlook.com (2603:10b6:806:348::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 15:28:38 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 15:28:38 +0000
Date: Mon, 8 Sep 2025 16:28:36 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
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
Subject: Re: [PATCH 02/16] device/dax: update devdax to use mmap_prepare
Message-ID: <a97321dd-d8a4-4658-8894-14b854661d34@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <85681b9c085ee723f6ad228543c300b029d49cbc.1757329751.git.lorenzo.stoakes@oracle.com>
 <e9f2a694-29b0-4761-ad7a-88c4b24b90b7@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e9f2a694-29b0-4761-ad7a-88c4b24b90b7@redhat.com>
X-ClientProxiedBy: LO4P123CA0146.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:188::7) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SN7PR10MB7102:EE_
X-MS-Office365-Filtering-Correlation-Id: 53aa73fb-c2fc-4af6-297f-08ddeeec6220
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?YwwCZqMHFmuhBmrmTbmvaINjJcnV0v5YOuD+AzXuMnOcrokJCfonvZ03AIs6?=
 =?us-ascii?Q?fubW3Wt+O3+1QDQpKhvIIuTkgLueUuRoW7YRQjfLnR0U2fcBWoxwM5dfRxKR?=
 =?us-ascii?Q?hVBNNI39sY8aCfzPH0QEnp/eQ/IkYKk11kqfJeHstSWM9n24oboUGTQ8ywC8?=
 =?us-ascii?Q?1A3g0PBvASTrkWCTEQ7ZNBuwPcmDevfyiOcW3HbwqQUAtk6kToUyqlq1LqsX?=
 =?us-ascii?Q?YJoeVKZ4jDsKYC+WSjuFhHRpltwF3rTXTgVusuAyDtWwRwWKLE+v99va8OZq?=
 =?us-ascii?Q?t0VSZ1LH2aT6UPprYk0Ax5P8o0NYdmQkQPBx3y+acpmF6btrBUCOgUJvAZmY?=
 =?us-ascii?Q?EGnvEkGg5v0hn2UpGpqrgPv8sukYjMaxSbFdOIiY2TnkUzX/p9/2i73Xjg+E?=
 =?us-ascii?Q?io4dKlYwXjylRjHLpUKXE9lyJWfW4sjyiTs2K8PM6p0s9+B022qM6w2Vtx9T?=
 =?us-ascii?Q?a1gTXK175cUyb7OPNadVIcr6bVHwBRsCzHbxpYugha07S7Bbb47ZN2saeDrX?=
 =?us-ascii?Q?7xp2F+OI8IiXlyAok31CSyEsqDcqchtpnkOfU1h8IeA8bkW7N7s6Ull+40st?=
 =?us-ascii?Q?OT4PuJpXy9a8w8oTlVZL9M9gavf7fdIBhBqmzHTCQzql0NEFISuFw3PYZ2/u?=
 =?us-ascii?Q?5UJHFCYP2/B+47WE/NT3F+Ajm2agMqK8+HMJ8s4QxJN98EkHju3qBcOId9ir?=
 =?us-ascii?Q?7FcHgxy0/DYUH603Haz2sp8xW096xXZdVE3D8Od4+cFsXtLdxyCWZcR1AzKd?=
 =?us-ascii?Q?0Yknl+IzKmOCHu9cbG0tkZ/rrG8qtHfNPgbmznMg8ZISTS/DACw1Z/Y+LVzL?=
 =?us-ascii?Q?9DpJTpKqg42AQhtJr8xOYMcxZXNbRMyRtTmAyVgq/t0wR+hTLI7keCtPAXAx?=
 =?us-ascii?Q?g3fGXJvKFfAxVMvIV9CBOpjQNw0XjgBzMIe0gwXHeBcXJEAcn1YyTrKx1Vzg?=
 =?us-ascii?Q?lkQSMmHXVJeTdmr8xoXoMMZwmRLtUiH8u94+FTW+PatQZ9eqtDL2NvZfIuTP?=
 =?us-ascii?Q?CDqlSrnh48Hk/E0Q+uKL3GxpBA09W00XwJtvgMlTCna7YpSE/GjAOycUne4I?=
 =?us-ascii?Q?adprRBZGrf+MERrUdbVfCSoPbVKy149yRGmqfX5PQMy+2WMH96wC8lQr2bFf?=
 =?us-ascii?Q?NetLiGVdeDX7U4Wyc9k9I2tymnQyUvVNg3Tm0s+l/pkpYb3XFYLlTWGIFoLP?=
 =?us-ascii?Q?gWml3BGioqdLX6YcKhsUF1wFwLvTiRSno9+6hyDG8fTxEOJ+jK33NMiJSwRc?=
 =?us-ascii?Q?EqPMqUSrg2SxFiPXlVbrQheAmgMHH4I0ZP8yjeK8zzF6xPJ/WjjXJ2NOylIq?=
 =?us-ascii?Q?cKSa82KgTBTlxKpOeeFsZlxQIogqMsHWK4bLHNSzNf5vtXZoI0CAgDADnw2Y?=
 =?us-ascii?Q?BJGmqIkp78Z+2mf5mxm5jwKweCjFiDcT9isiklAME6di56Z07/ZuTGQqPXnd?=
 =?us-ascii?Q?swX4R3W0bZo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?FpodwtG1n7lnSZ9X5YmTEdOAlGcQ1J9OnEBhi2fGy9GGrMwpeoRf8Iaz3K2t?=
 =?us-ascii?Q?rW7TeTwc4L2ACvmMBparuMk95dAMCdfiyOqGOzfhGSlgf9FvKdGIduJ1yPdv?=
 =?us-ascii?Q?Lxe5doJFrB2YF7tANnEAnlenok7jbJEA1l91ottOvqLq3PsHCoe7C/SWS1bR?=
 =?us-ascii?Q?DlZKcJvT2xYo3Srz/Wob1cMq3lMqr6bMbqWNG4oCt5dn9NZgMPxXqqZ2WTeJ?=
 =?us-ascii?Q?TvLtklm80zLlTjgtyxwgUj+Undt5jKtd4Z7HTdHzotKSF8HrN7ptbhCnZL8R?=
 =?us-ascii?Q?TyjWX8IuNn8WecdIp8YrwXmVhUh/qRR76nH2GKYbB0BXtThx8sGB3uOcZks9?=
 =?us-ascii?Q?9+mnkZTwqTUwPYRIwYt7VTXyJlPRNmbM4BN29y/Judax+iU/DLBbhA99CP/h?=
 =?us-ascii?Q?jSfoJ/s58Rj3+AdqZjR7+PXYU3xKLRfkIsT2RVIKAQLhWnf7tSHtIjbcmKM0?=
 =?us-ascii?Q?nmexwuoP6Ad1PWLuHZquE9MDV6lHCL9OOoZizKASf03g0gqOP2zC6XefJeY2?=
 =?us-ascii?Q?Q2nz4UUqNiQnAiCR7sHP4ldP2ZYx2gqGD5m4KMQMI0GeZLizmLPCTwcaqBJd?=
 =?us-ascii?Q?/3IpugBKcH8U/ASMKnsuA7Q5JIjpd2WHglOUPG5JEestU9m5I3daHeD58yOS?=
 =?us-ascii?Q?tN+WzhzKUOXAfbC4/Pg12wy2HjhtyCBrWzbcY+PO/9LjBPU+eC4rtU5bopCm?=
 =?us-ascii?Q?Ip3YA17FVEz1KVQ9T1mH8QVkrAO9H5fVP3qg1RzAoC4qmgM/KtDLVgJ8HNYX?=
 =?us-ascii?Q?oEu7gX4jUYa6aoimu6V6MY5HacpyH+JSlqdepems4dsxs1cy4bRualGjPxvH?=
 =?us-ascii?Q?PihZu+TidS6GsO6/BZUFaCBd9d/N5GcY6uqPnU6i0gQzV/KI/5h+EW1mWzfN?=
 =?us-ascii?Q?mGuAfIAzqvmRg1gQP5tc1GPQ10LAZyoDQX8lO7Ue2uYU8Ww4UADE9+8r8UFQ?=
 =?us-ascii?Q?VFX+SqYywbCpLeIye2ehBxw7P/fxn1Oe9jgnbqkA8mwA4EiNqjap/0Pyd/ur?=
 =?us-ascii?Q?zRdcz8rmEqXpHJhCkPZjzeemJwnUWQHrx/kh673+s7f+K+bXdQQvLUwm3RSu?=
 =?us-ascii?Q?qhOC6UC6Idccn0IBBV3kTaXUDU7WtaRw36CEECT7eWSXADORWWaPTmXR6P2f?=
 =?us-ascii?Q?Nay6o86rCCFblXxJXAg1PJTia0Hyqzhlrk7l/dqB5qZfK3WFJMZOrv+1WOU/?=
 =?us-ascii?Q?SKy6wY7hmC8+J9WnfRu/Q/wxbq+G2aTeRGXG3gNArQbFc5feBDMndOEWNCNj?=
 =?us-ascii?Q?Eo3ObhUNUdsP7ysJDDCOp4leR26au5FOE5DbUxX60nn2BsdseBeNqZOkMcBz?=
 =?us-ascii?Q?aIbf/xrWT9yWYPsGHStIMmbO+MyXV2Fa50BGMPCGXrmDLPEosYUUkW4lF0J4?=
 =?us-ascii?Q?SCFaSw3I7uJf6SvPQRvKlaJnpHnLiXmOf1lW/BNme5czH5tCbW7CCPFtw3dn?=
 =?us-ascii?Q?1XGOkXolIKfEq8WDanw+3Y0WERK3Z9IIh4vP/AtnGwYwL+URcj6EAsfCBisZ?=
 =?us-ascii?Q?TshXIVeWZtVRYecPEmsfkx106eeHfH6C5Lt3jGeVrmf4ZkxDRjtCG069dczq?=
 =?us-ascii?Q?II+BfcQ00wLCnyBH+d9Bx7PXrjUwGC+iqe/JUwFLwdVXEvLdpo2HSEQ/nuxQ?=
 =?us-ascii?Q?3w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: jZ7eWEUjj0xK65zRawJOdi3zMkMhigCsskmj7J09xVKu4G02B0YS/iaaMFFKhbESTsEOSto9csuFoEtltUf0oPrsIKlp7A4xy8Kedntw45e578pijlCYKC9dzkIuCt0s4T7jxZaY+tH8jPuu2F1JaWKrD/pwVYH4HlPyum0Z1bBqmTHtlnOSlWDWoXT/WO6dHqPeIDDQcj41tISZmblKOi/DiRlnegpVH0uNyjkt1Cpr4hjCV1q7mqe2QY8mPu5g0ub8T1eFC2MZMo0edYF2hwuC+z1o6uztA8OYGyytfALmdOYzjaSzOAfbQpALDJUh/8IRkVoIoNkNJ/eGNrvf2DdGftJSl5f8xHoMvfh4XefPi8WhNXRoLBCvCjb8FDAX1Hpp7kuVYZHKuAQrcuyOHblJ48nSD/Eoe7EBF+G3tIRX1oVqOQsBVeh6/ELOIAXG3N8WhVqMqbe6+TZ5zZqQv5FRx/zC+/PtdXdfCzoFVvzNl0+LukXEkcLVK/83IqqNmNWPOCJ0viQeTHEotg4DjdMhe0583getsO4UuNEA5hMcJANxAHDHYoZ98a1omvMecs/g8vJMIIsEItm6e/D6k6mLfQvxV0WFfCnFgI9LjqY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 53aa73fb-c2fc-4af6-297f-08ddeeec6220
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:28:38.3133
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7DVkOfxIxEj6ITZH+VHTQ13nxxpSmW6/6YSkQRJa+sVOUMsuor4fGGXeIO9tpDjsjzKFOL6qyasGPatwks+i+uE++z1XaA03/c9fav6Xy3o=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB7102
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_05,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080153
X-Authority-Analysis: v=2.4 cv=SaP3duRu c=1 sm=1 tr=0 ts=68bef62b b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8
 a=G-FeugwYlrBPhemZp1IA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12069
X-Proofpoint-ORIG-GUID: 6_ko7O_ESaeYpmrmCjM5NuQhxJkXNqDY
X-Proofpoint-GUID: 6_ko7O_ESaeYpmrmCjM5NuQhxJkXNqDY
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDEzMyBTYWx0ZWRfXw8NF1j1uB1FN
 JhFA9QYjTYZ+jy0ypf+mPimVwPtSWKHm45gi3oS1RGzlb+LS4ZMR/f+0PXyT2LXr09rcYUO18N0
 GCFgkTA+AgCDGYCNduOLVOM+I7K+hAk5zs13DPq49FwX9om9DFmSsBnqRucE4G7eb1H8R4m5Mjp
 /A3qHe4V79hlqSgVBkGz+DUDWyvnbfz/wpwzb5v2k++NDOj0jhp4TskhlqU51McMkUQlQBw1vFX
 5zbGLrwtOleMfcDyB/V3ew01ZkanMBRfkz5cWlHvW88lLJ8cHMBvfMI5ZInvlLyxojy+2UUdxVo
 zO5EQCbNVnKm6e12RH/K1xJBE777CvbupSApdpRH/PVtwdyf/RYs1q3liqxPm7SHcnLJPSKFm4F
 zg1NcEMR9gWSy9reHFT6syU35IuTvg==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=dnZhGRjA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=llLYgjNF;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 05:03:54PM +0200, David Hildenbrand wrote:
> On 08.09.25 13:10, Lorenzo Stoakes wrote:
> > The devdax driver does nothing special in its f_op->mmap hook, so
> > straightforwardly update it to use the mmap_prepare hook instead.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > ---
> >   drivers/dax/device.c | 32 +++++++++++++++++++++-----------
> >   1 file changed, 21 insertions(+), 11 deletions(-)
> >
> > diff --git a/drivers/dax/device.c b/drivers/dax/device.c
> > index 2bb40a6060af..c2181439f925 100644
> > --- a/drivers/dax/device.c
> > +++ b/drivers/dax/device.c
> > @@ -13,8 +13,9 @@
> >   #include "dax-private.h"
> >   #include "bus.h"
> > -static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> > -		const char *func)
> > +static int __check_vma(struct dev_dax *dev_dax, vm_flags_t vm_flags,
> > +		       unsigned long start, unsigned long end, struct file *file,
> > +		       const char *func)
>
> In general
>
> Acked-by: David Hildenbrand <david@redhat.com>

Thanks!

>
> The only thing that bugs me is __check_vma() that does not check a vma.

Ah yeah, you're right.

>
> Maybe something along the lines of
>
> "check_vma_properties"

maybe check_vma_desc()?

>
> Not sure.
>
> --
> Cheers
>
> David / dhildenb
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a97321dd-d8a4-4658-8894-14b854661d34%40lucifer.local.
