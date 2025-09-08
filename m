Return-Path: <kasan-dev+bncBD6LBUWO5UMBBFWM7PCQMGQE7Q2OXII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3254EB4911E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 16:20:09 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-72e83eb8cafsf68197126d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 07:20:09 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757341207; cv=pass;
        d=google.com; s=arc-20240605;
        b=DFxIeaE6/C9IGbSRrkVLpVq2Ef0iS5fz0p3nDpgBpGSqbWf2la3MiG6kpBYvlbUITm
         QTbKanGr9eSaWpIxK4cesL7UeDpbmO2PL3NAfgAJrzPn5/FRSPCqH2evXoxusDVoXiZr
         LkqPkZ/nESlJil8mHxyiKWz5AatBPr8f9YQeIJnfHEAcLnRIzdF7YfgHvoieqrHTO/6t
         rwTtlGgoVHyNUS7ESc1aEfCNjEZbZh2YIOFpmRqGF3zjNW++ZVyt2WgKwB50aTe20H0R
         l+Viljjk8kRynF9yiNAXvVGCU6g8eUjQgVoPdITcmMyBUqrwBByVkB5yjrL/9e2avI2H
         h53w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=YUe5fMR9Y2I5KZqbz1gEfHpzhDakkRBnBL+txS8lkwQ=;
        fh=J2Y2Ms2wR2G+H5EZ1hif0sqzVLyfRMNjkDe+fWEv0J0=;
        b=iAwPl+qtGNEEG3PsKPjJq2g4JVdQ0P/e9v95OUF95bg7Ql3l/HO7hdTLZRneKkpeNZ
         gkGuIMQ7fBJGQzUH5hGHvFZibcIYHIgZbv+CgXaOWtPFIHziJjIH/IowR8ubfxNcl1gA
         YuAh/GJiV/ddFEv7qFnBERwzyKlyfSBzZmDtSmFUXkGIZbHm2oxxU5V5kECGcmRFRLC5
         whwDI1ClOSRkVU/1tW6bkXlkHCokybFt+W1n1OA9M7c4xi9rCDa1lN0CSEYQpnOf0oF2
         wD00MY9WhfH/BmnWsk7qjUeYeDEFYs1x3X15SCFcTKA5UiJLaTEabjukc4ojM4tF+1iL
         CBhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qcOrMTHT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=GuchOSAA;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757341207; x=1757946007; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YUe5fMR9Y2I5KZqbz1gEfHpzhDakkRBnBL+txS8lkwQ=;
        b=MTAeFQ8BHBt94dFvduaHNJ87vOo4cTLRlPckG65Spy+xCk+oT4podAmVRsFWurrprk
         T9gNexRWHtLf+rZpmM7JRNkcBnhqeQc6FkjBV3k3tgOcONukTUtPD5WuS/MCQ2+4SDgV
         wG0aoUPif68zBugZrEvTHggislJJiGPekDnCzo9Idh/SIyqZBPxdlCqr/PqMzG5AGh1X
         mvJVCuKCQdp17Ja46VDt6kC/JKOTpHflsk3nH8E8QIB1XIXmOHoCzl0Rb8VHig4QJ/o3
         RmPifWEItiNhP/X7Ds5d8UuIUiv/hkxYQc2C/yqGJx3PXaAM8j6vC3IEhVRdriPaGibo
         2Aew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757341207; x=1757946007;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YUe5fMR9Y2I5KZqbz1gEfHpzhDakkRBnBL+txS8lkwQ=;
        b=wA3YIYIGqvRpEDTFvX7is2ySFI4lJMlSP+g+MEhjriI/ibqVx+8uonG55R3s7zxhus
         vBlWw//jz+XdNZF9o5UecbpMRgBxGY0Jb3IRPlG2EpRwItlmQ913KP+pyY30ccHtnNnW
         2JNH2CJxDQxRLr/ZyGYhD9Fy11zTXzkPkBaLi5P+UiPA3Mii30EW81/i6XMSNL44JJvN
         qivKX5Z4Bqy69RptuOlYsCWEVsjJg5hoEQXXsBFVbGKX4e7GbSW5oMr7htM9Mod90KyO
         gUG2z0qqTLiPCgiozUVWxLNFyjscPBLWY6xQ0pi5P3qwoRc+1NF1mAxoe4HQP+DqCdWY
         jWNQ==
X-Forwarded-Encrypted: i=3; AJvYcCX1WCpeJu4EgmQ0sXHotoURMalPjAux9J54X+Wv0m8hVSn0Veb5GRluNsUmjuNECDcLeiElew==@lfdr.de
X-Gm-Message-State: AOJu0YwrPpo9QP5y1T6FxLhNjMyjAnuTf3rSkm03PBCI+0jPvABrzbdI
	xl4Bx1Cp+rWohg8rGOylg6VunuZdTgGinTvUoBhvecnssI9OSRKObLw8
X-Google-Smtp-Source: AGHT+IFO17Jd2zV3SMQPZaM4RJLAliete/wiYurUPPdpg9If3B/HBQr8eXRo2lvKAP4wUJ/4bFsvZQ==
X-Received: by 2002:a05:6214:2421:b0:722:428a:e3db with SMTP id 6a1803df08f44-739403158acmr84785336d6.49.1757341206761;
        Mon, 08 Sep 2025 07:20:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd59YTSrVPtB3TdfM0cy4qhbkYcgAd326//zev3Ueip7xQ==
Received: by 2002:a05:6214:2582:b0:70d:9340:2d97 with SMTP id
 6a1803df08f44-72d393497bels52980266d6.1.-pod-prod-03-us; Mon, 08 Sep 2025
 07:20:05 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXidN2fuk7LgA5LiyKW/TsJYgF8NNCgjAybX5RISezaV1F2/MdVX2h/aE6NcdEwN8XFGsVd4b2TcMM=@googlegroups.com
X-Received: by 2002:ad4:5945:0:b0:725:f014:6f25 with SMTP id 6a1803df08f44-7393ca9cb08mr76613906d6.33.1757341205389;
        Mon, 08 Sep 2025 07:20:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757341205; cv=pass;
        d=google.com; s=arc-20240605;
        b=lFJwzeg9uptM+Jyoc9CBgZsqhASlLfkiU4zlcUNHbB7y6+Jr7OEjANTkR9EAprUj2O
         v6XA+5rPhp4R/o84oo9coHsutOBWKI5so9ZGBiBDQvdRSIOHjMeHvNIgEsDvO8vnXXuj
         hJBqrwVPL7l0hTrxu3nhdfJvigqbJuRx6QJ35RxJl3UY2XlEsSfo2ntxff52zoz4ou/G
         OUr/vzrQIGn2EnKn1a81R5IlWBuANSSizrxnjxv/1vcLi5uYDjWzFEp+QyalcsFHKtm2
         2qOejFWpXANuzuPFOzMk0wVBOMNJh6dhy2OZr6NUyyrAhiOnMbUCuCoptY8rSa+6gMSj
         8tVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=wfEmfOliu6v9Q2jCKy8mwJIIEZAM5ZL2Lu/9af69v38=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=TYt+byJ5IajCv/HVEm1wpEf/YnWwrrjfTnOGdZOzNIfdKd8Zm+/Mte6KI9+hE0UdbJ
         pebwY1jCZ9XwbqkfQty/xPZ4owuSwaRqp8DO3Wepeb1bvNP67552yfLQtpjNrbovsgIs
         AM2tnEBsJNIxVM/kWlzSQtTV2AdVwOCXlxc9j5gtH1pVmqddowyTP6sl+swxdu+sjAwX
         zFLY9LEiLsVtWhB6PF3GpAULfcm1M1ELxCVEeR161bT7y5KNNfmqDxPmj+gz1yHkjKDn
         UfJ9W3udI9VZzwk2ozf0/PefOsKeLEn5hWPDGDd0+U2IV6aCUS3eHSgVj4hMEqiYXnO3
         GONw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qcOrMTHT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=GuchOSAA;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720b14475e0si6902046d6.3.2025.09.08.07.20.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 07:20:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588E28MY006494;
	Mon, 8 Sep 2025 14:20:04 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491y4br835-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 14:20:03 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588Dx2Ch012871;
	Mon, 8 Sep 2025 14:20:03 GMT
Received: from nam10-mw2-obe.outbound.protection.outlook.com (mail-mw2nam10on2087.outbound.protection.outlook.com [40.107.94.87])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd8g3cw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 14:20:03 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XzWobYM3uVK6zcqe+sNRs8VG4wSdYfnZdt2nKwhavSk1XSBaDQZJ5uok/j3ROGzCtZtYWgk6FRz/lCKeMk0xVNn6el8+LZM9zBrjQ4pf/g+sTeSXZDNYaEK+bi3Dr9KshehW8GPdaDSUwxhS3H7xdX1ykPUTkw0CJwJRPwsQUGvBUw1B3F8wLG9zu5Xt25duDZUA6tJ1kctV6CZ6Il0b3QWQYeY5iYaNSHJ7o5CB6AN/n0D+MrOQrEsc1KHldDE+jYiXVGn38RZpTAgHFgUYP8zn/VGnigAU9MVlz9HNhLijDE6RJDWNxQGbx3flioC4rbZ1Sq2UY8Lg71fiaP5x3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=wfEmfOliu6v9Q2jCKy8mwJIIEZAM5ZL2Lu/9af69v38=;
 b=wFM/y+iKTB56W/6Bcn8GmfPoYEoPxKyzqiL2PHoeg8iciRUO7e8u8KnlTSFk8bk8q8wckZ85R3w2is+NGMcaANyNw3giZw/itS2XyNMFLv6GOmgFut5JHVjS+30cZp3KD2YCCt6WVSUVNE+AMi7cxomnqif+Xc1kaF4Rzo9tnbWRSirrGEetgP1/pYjX5Mwofkw0ScOhQPrnrWCiU+WW7ymJXyAg16YQkZ7w77TgEov9IXxgBkl81NTn04yUqTn2hGQDzTt5eFhzl2hJ9Q1zIswrm+nzRveHPW7VqrFzMDOORk7AFkebqMqQ5olyqy3u+ajLAEpDNuzkvme+VuNo+w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by MW5PR10MB5808.namprd10.prod.outlook.com (2603:10b6:303:19b::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 14:19:54 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 14:19:54 +0000
Date: Mon, 8 Sep 2025 15:19:53 +0100
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
        kasan-dev@googlegroups.com
Subject: Re: [PATCH 10/16] mm/hugetlb: update hugetlbfs to use mmap_prepare,
 mmap_complete
Message-ID: <d9121de1-e929-4450-8e19-f1df8b617978@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <346e2d1e768a2e5bf344c772cfbb0cd1d6f2fd15.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908131121.GA616306@nvidia.com>
 <f81fe6d4-43d2-461d-81b9-032a590f5b22@lucifer.local>
 <20250908135240.GI616306@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250908135240.GI616306@nvidia.com>
X-ClientProxiedBy: LO4P123CA0228.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a6::17) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|MW5PR10MB5808:EE_
X-MS-Office365-Filtering-Correlation-Id: 948f7875-5236-4ad9-227a-08ddeee2c83a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?mS/QWDkmXtclGx5wjq/tq6BJOVrEZG65ceMC11Zto7Z6XvSxNkMgngGUaoer?=
 =?us-ascii?Q?sG/btw8oJLnm9Fuq0dsWJU52whaGbMoZ4C3y2/Dhs0cujAZnxsKiaSNgSEWG?=
 =?us-ascii?Q?7JcbhSCR86BymiUJBx8UYYPTG4rvJk0RXjKLgW/wtAXW8C06HfTJtT0/l+7W?=
 =?us-ascii?Q?TTIMMYedK73vNKsN9k5lOWbM39jDZlpsZ7erbGP6ZYdC+cAVjxk7MdF2KCfg?=
 =?us-ascii?Q?ISWePq48M4MPoZ9vrCOfyO5JeFqoBjAx5/fZukSDB/eKFgO4IdYNjrNVv92y?=
 =?us-ascii?Q?kCK5nllnbi6ZfxLtK0FwkfuIeCJ+NKiJ0+doc6R1h0pdfR/8+isL/2XDufuA?=
 =?us-ascii?Q?CuDk/0e+3gWStBEfMveNQY4I9BmRiq/Dbr1elUrGgHzyqID+94fonZKBz0L2?=
 =?us-ascii?Q?33X/+sWSZH0Do9tCN4JPB+2/4C60hySdA1rf648y5OazCDhf+FLNfzpZJt5C?=
 =?us-ascii?Q?ptSrYDFAzqxQvlWJRTX3XYLcLdF+j+aE94623exaXZDinIwLzt6afh/Q+WAc?=
 =?us-ascii?Q?LN35JfzhsSSoPiXLoQryXITOVVQUEUkLu2FjoYnXgSuLzdLNAKBcsPoNUyYO?=
 =?us-ascii?Q?zqgG+JrosDwOzxQlnzieM+Ji6brJ5ReN6cDf6Kpnmu9B6CfxoGCM8ymD1AT3?=
 =?us-ascii?Q?PDU6sYpwXizZ9Ng5nP3Fj8B6wocaQX3okMpFMY+42vgiiAnoCEuA1UBq85Rm?=
 =?us-ascii?Q?2Y3KbdtK+EKMdEdHJ0Hv5eHQl8BdUDDfeEaxTds5jn+wdjJjis7WARDRZ2C0?=
 =?us-ascii?Q?89kt6T8cJEyaFFWE9gAKjsq1cJQBtU+6GxDsgcCEiER5NnjoF27zlLKLGKnt?=
 =?us-ascii?Q?O4h2g0Vi98fjfAG4f1vST3n9kZYWmvL5MmR5xxTh/jVgP1aXO065MA+VLdzG?=
 =?us-ascii?Q?XwqLH9nS/k3HL1JlPgFlMARaPjwhLvIjOnxUsF10tPDzdZU/sgNzolgo2DC8?=
 =?us-ascii?Q?l3eSbajcM+EViX/HtYIOYMuOn0XOAM6qjR+1EiFAaFOFM88r8deplc5es+hp?=
 =?us-ascii?Q?Izm5EilK1ssch4wxzw1K0J1ZSPPMIAhPKyRbwfEprDpNSIFISNqMEd1c1mr/?=
 =?us-ascii?Q?n+A+isiD9dOiPZW+zrWfbbaSyyKCJXLg6Hgp/qD3aJzO6rZE8ThS+HojjN1m?=
 =?us-ascii?Q?Cj2lSAKf9UCcMaSzz8AMv3p4h70749KSxCV3SFDiMvhKKQZV6lLiGNi9CBkv?=
 =?us-ascii?Q?k86qgVLBxKhAT9s2Lxm5oPHfR1aWLj9aSDhG5HQgXEh9AI+3jptDhf13Fn35?=
 =?us-ascii?Q?nW6gzYhM5HsmPiyv96pJhjZOL8MDavf1DH+jNKxDIQwlXPNo/dWpKEWUkGRl?=
 =?us-ascii?Q?UhVu89IBGYpYpbiRW9MR8LaH+JqkxHlfTr4aq+EWICWWL3DRS8h4B07h0Klz?=
 =?us-ascii?Q?5u9FhZeGmQpnBzdLjh40pz/IL9Fj15wSd8JKUmKUKqjD69raAinS9kz8h083?=
 =?us-ascii?Q?BqNeqVPRhUM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?XQ4LfOpHjLLDdprZ58WwCNfwq69GahNDuS/To72XXqIK2IIq68oNCO3dzINV?=
 =?us-ascii?Q?Tfdbf4hr+8JjJoMzEGgN5sjXfxqSE7UTlbGKAcaoxZxVmi7n3LMvOC5eiR/h?=
 =?us-ascii?Q?2jhoueZ81+wKBFqXSxYfapvDLtrleB0YLpVviQqJQFEQDiirp1+c1JtmQLvJ?=
 =?us-ascii?Q?Kznns+7zEqJxSqJPW6AZAuu4vZfAYcxA+eEnDz5ssEwCQFQB1FLqxysTwiAw?=
 =?us-ascii?Q?QH2XOG9eOqZisru8C1ZCos22UGkKYq7W1hxaXUmvKobJ+EM1y3kVJf2SfmqF?=
 =?us-ascii?Q?Etf1iPWpRG5a8eNvq03dFeBF/LrNk2srNKkla543r7V+2tQkACQZxZ/3CRvN?=
 =?us-ascii?Q?yNy1WoxhMLN88fTxVp5lUB5Ztfs7tkoe3HSDIE0zTEfUgOYGyqww2/qvPkp5?=
 =?us-ascii?Q?o520fckvz7mMMdDWisQGXZe3YXeJCkewckk+lrmxAQEShclDa30obL3BgVTh?=
 =?us-ascii?Q?HW3mBX5uT4pjyoa5cC2z/ytvuwhUkSsa1nSSOXloRAMvu3I6hl5V0mMqAb8I?=
 =?us-ascii?Q?oycmNF7JK6nfCTYoVsEtxOwxqQzfzGF91OOP6bKFsr7Gg2I+rwOxuJAJuHzS?=
 =?us-ascii?Q?aRyHejgTTJXgIZFeDF6uW6JNvnZvN0k37Cf0htAZBGhve0STt+Z/phN0652D?=
 =?us-ascii?Q?b53gjtZZBcWSriJddryKV4L72MYKH5z1GOiV8vmplRO/NSJlBFPCQ4G7Iinu?=
 =?us-ascii?Q?xeeUGN020bG4CzsqKgX1eISlcwfDoeWP24hPMegwwnqELDJhji3rfcZxsl26?=
 =?us-ascii?Q?AlHZWzgcWXvehWFhS0QckgmfVa72GnJmhLt1BbkbIFgCyBVJESEVBtfisF/q?=
 =?us-ascii?Q?RYHP1tEj2ZwCCR1gWVahZodkqA6mMxFLoFB4wfBTZS8giKiU2wPBmULmU5lI?=
 =?us-ascii?Q?YxFcohoVLGS8KjWJyk25UaxNHBeTX5ylEwgP+jWTawBOKtFgZ0yv5SocBShC?=
 =?us-ascii?Q?bXzDcjQ3yUem9BwiiubWQVG0sLpkNIxlsh4ByJfeSXE2XWzIYL8Ywfdggxd4?=
 =?us-ascii?Q?Z7Mz40Aad2aPwO1sSfsehRxzYV8qRI0F7/0cpKQDwAx1+gcz/KQBJOc9s5m9?=
 =?us-ascii?Q?0P73OuhsXXHJHfUJXV+R+9zjxP6fc9vsEvBdlbodZS1auI8SR+udF+qjzsDE?=
 =?us-ascii?Q?1Pb98aUZ4hQb/YkLkesyyLsy/FPzcs3tj9IBaks7EFWgSr5GCLtxkCjGcG7N?=
 =?us-ascii?Q?dnpJus+3PptWLr6T5Vf0YwQ4K2nVltXAADBooFT8sR3Me4/s9vgo1PBQeIhV?=
 =?us-ascii?Q?cdJi119qJxEgd8rLiF+DkA41OJkapFlsbyVBn9XRt24nOlu2voSOY2dr5g2E?=
 =?us-ascii?Q?BwdE2W1qLiX69UoAatplxkYHYCMDOB9CGAarxHkc4pC3uZEiOrCucuqWxI2a?=
 =?us-ascii?Q?20KBCrk6Jw5hzu/2jg1NfsQXEpK6cHxd/tS8f4gc7M8D+zg6CP6ix+Gh0yQY?=
 =?us-ascii?Q?Y1MNjEb+kTmzTfcmDbFIUJzFZ5gw7RunPSs6I3RmEljqjO65+xATrMPGD+mI?=
 =?us-ascii?Q?r2cPLOkcUP0EKsbCwIOqmitRffnPghtMFoSOQHQk1dUYZvHl8ugMkLWyJfpR?=
 =?us-ascii?Q?w/42Xk07oOboJ94nSyiFVGQgLoBARL7jEQtq/XHZxotdxp+Q8TTPqXNdHPUV?=
 =?us-ascii?Q?8A=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: eMLTe/51kh5Yfjnh9AMCF1fBA23noy0TJ/j8tP+VxyeZzzafuO085XyNgzgtsGhu4kE7F3ZBsPzWXCLCoOzgqy0HlW+y6IjKFcCI89z3m8gAHOVXYsMpO4kD6pK9hx5itC5Bbcuhozvtey6cTg4soANaYXNCGsEUqlSL/2Qb5h9zxNKbhKEFPR/Nu3UhW98VTJdpjKjQ9Fql4tQUQkWRSpKOPIil4YNMVx9EcQl2JstZKXopf9XVvhGt3aKMtn7jb0GZw3tGlWYBljRHvnz/YjbUOUxt5Ty0/r85cAooLvbsZFYBZoVbZq08VlrZbadWBL73gdKTsh0KI7Xj2G64QiKlo/OkPiIrCGUk9hPWuncHXvOjd5esn0FhWND23GX4tFDolcF9Glpd786UKw43gqiUZEOhzDzumXd2xcotDUDS3JrEmDQf1GDPTZif6I/qmyK/sfHy+jhyX0OXFPS5qEPs6piQgLoNbcGcC3lou/hIX6xD6+ILyWniOT4ZB1orx24IvdXJJPN8yoQ2AzXvlNXqJlnYBUzhkoVE+TDcUOipSxq5ceaBOc5AyKEY3YoNDxL3+j+0XQcouxgh7MzmzG5/uEx5o9k+gxu+q60FwSE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 948f7875-5236-4ad9-227a-08ddeee2c83a
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 14:19:54.7117
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 58j4osLP29vjJcFP9hBUAoW7YnlY3OtJRHAXxQXNK6+pGKCG9ch548cYbjkqetYu+K3smnCXdBqHQC8iIWCvRP/g+FH7FhRaP+3bZTJ9TW8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW5PR10MB5808
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_05,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 spamscore=0 mlxscore=0
 mlxlogscore=999 adultscore=0 phishscore=0 bulkscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080143
X-Proofpoint-ORIG-GUID: 7jekbWcXCUBsps7DQA5zsa7EHBqxMTWN
X-Authority-Analysis: v=2.4 cv=ILACChvG c=1 sm=1 tr=0 ts=68bee614 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=ROdJHagua6v1V9-Z0y0A:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDEyNCBTYWx0ZWRfX1DY6MoUH6WFu
 vDHKSDDDnDPwwLiYNqGRWZCv1YpSGepVTAl4EttTOgKzqPD1PTG0luP4NFxSMphS+Vxurs/KvKr
 zkKKn9GpRlCIznHyCRD6V8Gq4DB1724lQXu8MCsooubMfUtyM3fZ4LlH6ZuU5OJNLzBBYSt+Dlp
 AJ2isrQ0D72pGsY9c5i0EIpg2Pp7VxFjnCLqMWcuIOKt0ixHXd+4PY6T86ikeshvwQ9pB0725IZ
 Sr54EvbonT+YUTCCAMHP0ilri0ismXNyxG0DTqmNG0ntsnxaEZpW4+/5eJrGKA4G2tbazT5mrSp
 mLzh4veglDuqk07E6Mb1bFCPkShak5redCt5JccLSL9TlWS8edQf9UY/0NpjGdS+0FZZu2lcReL
 0QQFEej0
X-Proofpoint-GUID: 7jekbWcXCUBsps7DQA5zsa7EHBqxMTWN
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=qcOrMTHT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=GuchOSAA;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 10:52:40AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 02:37:44PM +0100, Lorenzo Stoakes wrote:
> > On Mon, Sep 08, 2025 at 10:11:21AM -0300, Jason Gunthorpe wrote:
> > > On Mon, Sep 08, 2025 at 12:10:41PM +0100, Lorenzo Stoakes wrote:
> > > > @@ -151,20 +123,55 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
> > > >  		vm_flags |= VM_NORESERVE;
> > > >
> > > >  	if (hugetlb_reserve_pages(inode,
> > > > -				vma->vm_pgoff >> huge_page_order(h),
> > > > -				len >> huge_page_shift(h), vma,
> > > > -				vm_flags) < 0)
> > > > +			vma->vm_pgoff >> huge_page_order(h),
> > > > +			len >> huge_page_shift(h), vma,
> > > > +			vm_flags) < 0) {
> > >
> > > It was split like this because vma is passed here right?
> > >
> > > But hugetlb_reserve_pages() doesn't do much with the vma:
> > >
> > > 	hugetlb_vma_lock_alloc(vma);
> > > [..]
> > > 	vma->vm_private_data = vma_lock;
> > >
> > > Manipulates the private which should already exist in prepare:
> > >
> > > Check non-share a few times:
> > >
> > > 	if (!vma || vma->vm_flags & VM_MAYSHARE) {
> > > 	if (vma && !(vma->vm_flags & VM_MAYSHARE) && h_cg) {
> > > 	if (!vma || vma->vm_flags & VM_MAYSHARE) {
> > >
> > > And does this resv_map stuff:
> > >
> > > 		set_vma_resv_map(vma, resv_map);
> > > 		set_vma_resv_flags(vma, HPAGE_RESV_OWNER);
> > > [..]
> > > 	set_vma_private_data(vma, (unsigned long)map);
> > >
> > > Which is also just manipulating the private data.
> > >
> > > So it looks to me like it should be refactored so that
> > > hugetlb_reserve_pages() returns the priv pointer to set in the VMA
> > > instead of accepting vma as an argument. Maybe just pass in the desc
> > > instead?
> >
> > Well hugetlb_vma_lock_alloc() does:
> >
> > 	vma_lock->vma = vma;
> >
> > Which we cannot do in prepare.
>
> Okay, just doing that in commit would be appropriate then
>
> > This is checked in hugetlb_dup_vma_private(), and obviously desc is not a stable
> > pointer to be used for comparing anything.
> >
> > I'm also trying to do the minimal changes I can here, I'd rather not majorly
> > refactor things to suit this change if possible.
>
> It doesn't look like a bit refactor, pass vma desc into
> hugetlb_reserve_pages(), lift the vma_lock set out

OK, I'll take a look at refactoring this.

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d9121de1-e929-4450-8e19-f1df8b617978%40lucifer.local.
