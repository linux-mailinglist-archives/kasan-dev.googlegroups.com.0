Return-Path: <kasan-dev+bncBD6LBUWO5UMBBYPO7PCQMGQELHUOM5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CDFCB49386
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:33:56 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-724ee8d2a33sf97209626d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:33:56 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757345635; cv=pass;
        d=google.com; s=arc-20240605;
        b=esL6UNph/uS/VIZrB/yCQQtIjcsk73rrnsYxuw912lObqTFl/hLgmVO03R53mf3FYj
         0NWiJ19QUO8tqSBbnm51bxtVliitM4SQbjSssm++unNeMx3wlY1Fj71bAmwat0quS2oL
         k2I/f5mliBeWkC5/08kjDm5RLpI+sX8/Q9ylO5RT7OBIJvJnAdESIdDIOsq7y6oJAxil
         ZstImRRRMSQnTiGRLF8V5Tqf2RhZSnn/SNbe80XsZAe5L3eEL5+WAMR8kx3wKUUrKGlJ
         GhVQbCxa1Wdl7WQTNa2kZeG6IuIOAiKEuyyOYBfPQHsxgcd1HscalEb1Iw+DQqwmGQRJ
         Y1GA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=71vPAmFp0R28QcubAGKMo4iijXZReuKQD4n1P3AqYro=;
        fh=w0IJIQ/X7f6za3ppen0uRIYhj++vHlCoo3DZo7DVmiU=;
        b=lAOukboTqvNFYnC6YI2eMZvpnRR+ttg4nSwPPVn9yLxin+9/8SR+RQg6mjSrZOMZXI
         mYWF1IAX8HYOOp6FDMtbvfxwMgHjMvL49xVRyebyVOm089BcjcsvVkNOXkg+OgUYbU7B
         bV6v4lGCkEQaU4S+YcdGEYNEIHZK/KMjkp6iqsTvxz40HAaTdypnDi6mtSVSgY1T0d1N
         mmXfLhtmLtIAsFNXSfbIpSs82jSGa8n6li3uiA/bVbD07sNzDF4iHTlSsQnIPF8pOKnj
         uIaHFlllmevgaeutrtPf2uYQK+LRoPfUs8phY1MVPKtlTQAiITtzsFzYIfrdwC894gVw
         a2zg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="NFCpALo/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Xj4gC0oa;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345635; x=1757950435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=71vPAmFp0R28QcubAGKMo4iijXZReuKQD4n1P3AqYro=;
        b=KhaToyUNj8uBJHHeMbweQ7rskfty++HL8EAz8Acn8tYEXBQOl4TpyodFRPsvlUi7ve
         DdbnU+NM9amz37sYgor8Q9PYUHpBy/Ig/eqU25ofbaUQp2Ej4oYVU6ep7JNMldMqEL4y
         /gZ7zh8taHJNC3joVU8H9+8cHA3AM6xsbRgc4Bnx0WGtWJmwbjktlywL0DSzXgCtk6tU
         SGLfQOgIE51ppFqPDfjw83YpXaldGKLh8lciak2qxiwxR48SIcIxgdt4bGqvkU0RoG8r
         jvmtw1x8Kj+BiWWGUgPxkwV00F9y2ANT8xQk1R5lzfr1fcl8v/B3bK9RWcfcbqahcM5T
         2Bzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345635; x=1757950435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=71vPAmFp0R28QcubAGKMo4iijXZReuKQD4n1P3AqYro=;
        b=dDHXnan9KnUpgSrJcm5gmOcE7qqWZoCnJRNHBe0PLmTjFOHbbJphdiGv2BQxSu16u7
         3s59MHvpOD29xfGpMI1mO9Sol2DL4iMga16BRnHQIpzR7GysISxmyGXAYk24hS0oIVLC
         JXk8c55WM20cg1ci5Ow8i4xtRJiNIa5UPZ1sy5l43GOV/OlGdt5Pb+rTWUOWKYE8NMuN
         ScoUI1clrapffJ6ymp7scqxQDmjV8VjmyzOfmpxv/bhTVzd3EvVfFGD2KYTdzgwR0mB1
         IlgdmGJk3tC5qUnoU8GhU/AUOWt4fcXYsvs81aL6fVqR5puCBiP1jkGxWAdnpCMFmj3X
         fGVg==
X-Forwarded-Encrypted: i=3; AJvYcCX3ugb0qZ5FDTzuT2tpBg3dmDWQUm0tu8hCiCyN7ChflEAZESCzcd3TaP014onVjWcVMwnDog==@lfdr.de
X-Gm-Message-State: AOJu0YxG8ZZLVitEBlqfTzvUmD+Hr/e5yPJAHfoVmHIwlTtBrS8L19GI
	PrSPmDjO8qzUKCvikhjUAiV/02iGgrM2QpI0y8K7bQTgKotCRPG09Spj
X-Google-Smtp-Source: AGHT+IGm4gACTI8KX1ngx6AuXj4gBu/e0zVvej0RsErKvBKxfE1Zk0o4rJYu5Q9TU5HB0EJIQBNhGQ==
X-Received: by 2002:a05:6214:5184:b0:70d:b0eb:3ce3 with SMTP id 6a1803df08f44-7393159535fmr87183306d6.21.1757345635164;
        Mon, 08 Sep 2025 08:33:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4agmt5jlOHSkDmpf0EsvtA4FdL2zqLFALvy3oWcP218w==
Received: by 2002:ad4:5942:0:b0:707:4335:5f7 with SMTP id 6a1803df08f44-72d1b4f52adls45006876d6.0.-pod-prod-09-us;
 Mon, 08 Sep 2025 08:33:52 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVxbELCET2Y9QeRhPSs8qh5LaBhlaf6E05FLXGi6BL2oqmCkQVtvsA1nKdy3AHGOdPj2o9+tc+OMgk=@googlegroups.com
X-Received: by 2002:a05:620a:4510:b0:80d:e0d2:6e01 with SMTP id af79cd13be357-813bdf6866emr653599585a.7.1757345632058;
        Mon, 08 Sep 2025 08:33:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345632; cv=pass;
        d=google.com; s=arc-20240605;
        b=fQ2sZoY7/FTP/OxXVz4u/B/hvvYN91d+ehJXDHhoutZ4gqaGSqDOhEJRYJgRxBn0Dc
         UtkBWDEEhyBIb/oOmDjv8T57T7dcndv0AlLgs/8qLgS0nA7YEwVdUQT6+oDCcLQC/VI/
         cY3gpTkYddC1tmHA+mPK+6+gfs2TSQg18CRBRfW/rmDHnZlhPjQCPX1HJMcZsIyJVwCB
         1ryJVI0bRXm+BemRHst5U7enkgTqgNlkZFR5TpaNlGDsfD/i7qJ/BMd6D28vYXHeqBhK
         RYAowXZPf9ljnkWjQ2cn0D1oc4CFkP85b5DhFffGOM4cesvnAtV/pzy6V7xUWZoJzt15
         wnhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=D369ynQR2O4iZgPez3DMZ3cGNHf5wQEjqY+V0iofwzU=;
        fh=2af8N68QYnJpd17/7xhpiRlIgvxld8TIWYgdTT6ZNWU=;
        b=WaVlMFyZxpFcB95iiCvFtj6+p/sLLCA4BzRsmhJYW1fH6WctRlhk+0wHIBP/QBK/XW
         sLcUbOSTCfjNofwFTgeD9eG5NfGUE07zHL3YcnI/MC4T8bQpSMSQh/+5xof3CX/uELVj
         Libcdb4Kl+yxg7y2cF3RAWjVV+I+mYmYSagTRHQegSaawtXnkEDBh9NQG3TbnpNNYimD
         EM+MO1c2Em0dev8f04isRRjVOD2/GA3mK6wuRt92HXeUo5+pPSQJNzp8BB6tzxIBGmA1
         ho41o5AsO+2qZVO7m7K8VwvK4kSVcaChnDcrjRqzWA2O5JujyEeXGe9fg6851txWW5LO
         aBPQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="NFCpALo/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Xj4gC0oa;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aaa832f28si54145385a.6.2025.09.08.08.33.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:33:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588FEcoP022677;
	Mon, 8 Sep 2025 15:33:51 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921m2r1ue-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:33:51 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588FCHo5030655;
	Mon, 8 Sep 2025 15:33:50 GMT
Received: from nam12-dm6-obe.outbound.protection.outlook.com (mail-dm6nam12on2048.outbound.protection.outlook.com [40.107.243.48])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd8bxhd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:33:50 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=i+GcZCKzsGxDmLX7Z1xUG7P5ahr+MfMC/UrTDYZ5z+vN5f97GRUDXlqZBYH667q1SJbaUydyztX/M4N8a08F0wbFBbjaSMoPRU76tC24K+Woo8bZlENOmm2ScHxwsPAufEWY8N882RAKKbWgXqaJbLiiYkkXPeFTH+Zlu/VG5KmQNjTvPymw3K/3I++Eq8lBMym9mzUDI0vvJUD8ove3ouupKGeQObezHEpP3Ce0cmoBQwVSzJsZ/b1wJdNpvJXjsEOKNuL+RHMYXlj7/Wp6xnJMeVnUBcJFFhMXZ8RaAyV1aLLy7jk1rFxT1Wt3v/YEsU7Xj41a3GQ/154ZhgNrKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=D369ynQR2O4iZgPez3DMZ3cGNHf5wQEjqY+V0iofwzU=;
 b=a7uUZS/HW8JdSNk7um5wv9MnpT+x3Uc2OAmL2L7waq0UiH4oWyXGgZaztGT2Xa0xvMOqC3fBpQ032uVojFGqASQrMrcQgQfmKCwfBoMl5zEgbfpb9zFcorFpxGDqsvCYAyUu2BWDnm5aGWJwPPf5IAsYhzrNLaqHx8sbDnvJNipFKI6iVh+VfJ3ju636cwF2fRLOnXUTJPRloPD+QGzyK2VM7REUHxLvUkwEHynP5GMwIL6Ehkc9vDQJpabG5ZuZYDp3n12d1eaXCsWu3y8HyIWa8PKqdo02SAwvvnFIu2STxsQlDyizgIfbGX2vyxZFT2t285Fcy41a+8721d2dWA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF6AE862AC6.namprd10.prod.outlook.com (2603:10b6:f:fc00::c2d) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 15:33:45 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 15:33:45 +0000
Date: Mon, 8 Sep 2025 16:33:43 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
        Andrew Morton <akpm@linux-foundation.org>,
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
        kasan-dev@googlegroups.com
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
Message-ID: <b62e38e7-9f27-4594-943e-987a14dba05e@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
 <20250908151637.GM616306@nvidia.com>
 <8edb13fc-e58d-4480-8c94-c321da0f4d8e@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8edb13fc-e58d-4480-8c94-c321da0f4d8e@redhat.com>
X-ClientProxiedBy: LO4P302CA0029.GBRP302.PROD.OUTLOOK.COM
 (2603:10a6:600:2c1::20) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF6AE862AC6:EE_
X-MS-Office365-Filtering-Correlation-Id: 2f4abb8c-42b7-4014-35e6-08ddeeed1909
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?2tWxLcFTGQpj4G8+FW199SCjW08eJ/yFdDC2ev5MBH5iZO0G45ko8XhZSWrN?=
 =?us-ascii?Q?IFWMf4/Liblt0cRQ3mPJyMOMPd4i5Q7YTytq5CWprBOKQeVAimXwHg7+qIfr?=
 =?us-ascii?Q?9XVktmckgVSD0iaPVZLShUr8S/zb/aID58uQkkRnccM1U35ijycd8ufdeGAL?=
 =?us-ascii?Q?mJA8Y9VbQ9+OQaRcnEaOO5ga0efLH+gp4BV2lYvZ4N+9raRq3zrodQBfBEdj?=
 =?us-ascii?Q?FPvd6ZqiD3xxxdIyaaHRs7EVL7vJKJTx3bA8BmHNJq1JnOKqj0Xx3VxhcGxz?=
 =?us-ascii?Q?kBmpCvj0/u5sAZRYzhcJ/t9n6bqBL7rcmzNqxM8WF98Yw2tJRiYwechF/IiK?=
 =?us-ascii?Q?6oVvjzzCPbYifPjlkI5uDoNRG0wdzqrQ7++ybc0qMe+dGvsUHyN5vQzcVRyP?=
 =?us-ascii?Q?XgJnk4fhNzi7iSr0Mot4/+kUpRuEEYas0e23KbllcuWOw2F0nKvT6uvVgJVX?=
 =?us-ascii?Q?UG5N13atNbkl7rut2jlMjMeg1asWXsHXkDP+35yk3UM0Jn1Hvc1FA7EBzGgb?=
 =?us-ascii?Q?tVa+zWHzH/cKvfeo23nrXHj+M0/wvg2ClY2bbTZ2Kk+xAlAM8ISPYXil0azq?=
 =?us-ascii?Q?Kz+sMovEamgtTB5/q8e3jM4JAGOed/TNTEpQNgDUsVfA8L5iD8JHd72BC9qI?=
 =?us-ascii?Q?R8s2LKkpaUIdfMx/ES+b40TX8yS5jnJMdFBjQr2TUNIAlX/Kbg9zpqkT/OB8?=
 =?us-ascii?Q?79uu2APL00Z25HH8K1d6D9T6jpM5jTp1V9fHaCWKooH1QPEbA6IWrRjKeA3q?=
 =?us-ascii?Q?yS8MOAfshPKLi3UeON2eypWRkIDBHnqiqAQEkA2gAj9av8tu9DRM0zVZczPW?=
 =?us-ascii?Q?skxsw/BVuesfu5jtwMbJMcm9yMAlsBdRPpMB34nP8NYeDr2L1Ga8z0ut8qZ1?=
 =?us-ascii?Q?4BX2cGQveo6xCnzM+QLvpw/LR7MLp32Z0b/gVr6Zj4Aq4jRGzqQZgTehK8XK?=
 =?us-ascii?Q?xp3nwbE4nE18Q6i4TJLLb4JebSCiJcLZ7PU03JItlWfd8+vYKHzUeSXmUcNO?=
 =?us-ascii?Q?S0cIkmpv6qXb6qs5vYSK9J5o1JNgoryS+fhLtlzhWyh994MY9qobSHXXrOZM?=
 =?us-ascii?Q?TJ0H0pMQEul6E3XgP6u3LPuiyxvQEy0+2ujvr6g8dBaF0mQcsVrIvvC0X5mo?=
 =?us-ascii?Q?N1nZegcdnvriPB7Qydd4R+GGw1hxth/8BP/4ahovrOyN8sImgSkek1/beLRT?=
 =?us-ascii?Q?8fSaRMKnnpCHKjSbXQhph8Cv6LwpYSMSl7M8su9E/zahKVXqtK4tfQue1WWN?=
 =?us-ascii?Q?d8IR16Y9d5v1zCIdleIURfZnMzyEktxuU8imTrkZVORuZlfiWpcxR+f3LXRJ?=
 =?us-ascii?Q?teslc82tYFZ7dOf/KFQoxLJKpCwAo48A+pq/hrVP1b1oElGwE1Hr29dYyarz?=
 =?us-ascii?Q?q86a8/2lKz2PIq9lu0rx06qZv7fovLq3HDD2oywiEHc+xSU9wFaaU8MgIMOF?=
 =?us-ascii?Q?83sa+HP+/P4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Pm9FW7QyVuEv5uppkK6z42vh3PJBsQ1L7Jz14wCY2XufmyldaHpQy+ARlBzQ?=
 =?us-ascii?Q?DpIrZU+/bMZe8xgFCHQZNgAcLu+hHwNkO8Slg/KeodoiviFUwPvKggUWCu2g?=
 =?us-ascii?Q?SUvQcItfifn131HuIFu9LSsezK1wEhU70Tp3fiBh60Ocjc6XPbQMo7wW2PE3?=
 =?us-ascii?Q?0uRRGysNSnurH+WMkglG7rFZ0K0ptAdoKC4XBYlsUNS91zgppkfDhTlMUt0T?=
 =?us-ascii?Q?8hdIJhGOCJ57H4hfI/+fgElQ037Q3Zu2d7YHcQTaWQSa/x7Nuz2t6sXQgooq?=
 =?us-ascii?Q?xCJ+ZBb/ygo3hK2aFNP/ALc7TeiqPAhsMKdI2BFyYcS3IcF/cJBGsyS7zgi3?=
 =?us-ascii?Q?RHidI5xhOYfmByQsUP2LcIQy5J97boSmH24BfeiTiMeH7rZAiLq6Gk8cwfl9?=
 =?us-ascii?Q?CjDKlHv3Bg8vT1QYrjTh/EJE5Lad6ZH3UhV93KvYVB2f7ZD/YaHmxy5RiaV2?=
 =?us-ascii?Q?F44N9H7+iMXhVzNckm0Q2SYv1ZDLKAxklVAWIcksEd6yZ0KP4Xm3Jl7RXy2a?=
 =?us-ascii?Q?6l/LN00nn6AO2aM1WiUuvMzrMad5DSUAzo0gT1KmtCEiPnCnNvRzp97SLI37?=
 =?us-ascii?Q?6W/o6NOz8odHS+/tQPKfXIk/6A3niod3mcx/vr3taEP5jnH26llb9nL4uKNM?=
 =?us-ascii?Q?gaGhJnArUDwNBy/DagQvI6xeNuUKZUjrPgp2ceY1VsQev8ynXRvcpq3/tk4S?=
 =?us-ascii?Q?y/+DK6QusiRYvzq/TVxL1Ljz0D8tWDMaSmZYUIGmVPkuaKeoXiCdDU4ljV2b?=
 =?us-ascii?Q?aofrd0Ei1pjbuLs5HVoIwdX3axaJESUG6dSNrSvSfDtCkxr4MA0EispUQlWG?=
 =?us-ascii?Q?uIr5+3cjn/3XCZCyOf3akSOcMWX9JPU3okGfw//nKlf6MMPyIzN50yvc3iW7?=
 =?us-ascii?Q?EmVCrBi5GYUWWmH8SIO9RNSXgz0Vr/djlsusSl6qwbTjR9BcwTyhjgNNVMJy?=
 =?us-ascii?Q?DbR8mUfUrV6B5P4g88XMPJpL4qGcBDJKHZZtJG1RrTKHlwoSK5aTpxQY5Oww?=
 =?us-ascii?Q?Y05eEokE3HNnk7Esk8t/m6Hz6r55flMzMb6UCJhu47RP+JMsmki8wwA/vz/T?=
 =?us-ascii?Q?03CDC32YSJcD3i/oPjcGe870wrGb9zSXX6iigXHRpbGbL0UzAeX9Hapjh8Tc?=
 =?us-ascii?Q?iRwkQe0ibf8fDgS9t5WMK2/6pwQhigkXS5+tPfd94VYCVE3hg/d9uv4zTuhd?=
 =?us-ascii?Q?m8F6JQzbuRxIfabap4WWVkcyTDGVQ/w+T0R6IlqHq7eoj/sy9dscSNHxNvBY?=
 =?us-ascii?Q?6hcoBcnePRgIsBEFPJFtSjd6BxoUMUPEjfZfBMwQwvlzBogL+QJXRXh0qEOm?=
 =?us-ascii?Q?38gLiN6BHM2qIQa+c0OAwhwNlt7Npq4RqPOTwjawL8O5jq9TTeVkYD1xJ+TL?=
 =?us-ascii?Q?wVZnKYcCvPB58V3X1Ylo9Q0mOfIuYUl4d/kqQKc/kcl2m2BYe/eUfXC9TxH0?=
 =?us-ascii?Q?N3agAG6yFzjEh7e+B2S2P0EmjnlU/A9Sfw3uDTqSYYCApheV09GzE2oMK2os?=
 =?us-ascii?Q?lGHRKYnfmp51mM8HPF8xl2I5fbsnCRQ3EFDiTwz/N7LnoaHsidSXiOKKTntC?=
 =?us-ascii?Q?XjA/4S+xTMZmn7TRisWK/ram15WIl2hOWpm0T4e+9xwprCY9F9BqwMseEBJg?=
 =?us-ascii?Q?FA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: K5DJDxnGuhAaTTCnfMdR679RtRjz1m5e1AY2ibU5FXN+dy53St5ksWaOnnXaxg/47YyyAahIGUw9ycLBrd1kPqktSjlPUpZP265dcWpsVP4K0HJf44IxuS8LojZCsWvyuDaFgZF+Wb4fnd8g486wWSuezf7nP4GYr7XxY4k90GAxcHPmQ6YlOUd10N8EiPaNQCeF85lQAoWV5a1fkf3RPaipoD9zRPiWXAoTKO8KDZN22wE5qhG8Q9TIZPZ/neWqzm/mYH0KQAfek5zWolh1UVAmaG+RUhiahyjHuH0yt3GkX1UyT8WFPmRCl010ds7t8YWWLbCxGfliQpqWPfycHurX4T/y4ECEs4xHnLP4fDHLH91Dw+snl/AP5jgOc9WQuEJD6mXE7zf0IF/SSmr/Ge20ouZIl3+qC3Q0znjO90X0ftmuhhEynExPqqPwebS0+8AcOOQdy47Ml6aM8b318p5TkzvaBsnZXbBaB/V1n59ZBvNfggVxoTodGux2gESWlOdx2nijQ1LEjhd0sY2fJqyG72WKBtHwQXW9CYEMrI2Bqk6kbkcYGMbG2UGdZRw/9VxgnPVHLcfDlbQN02hk3amDFRJ++hQCzMollqC+j00=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2f4abb8c-42b7-4014-35e6-08ddeeed1909
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:33:45.1759
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 5LXrsfOK2DsR6TsDan4EvInOaxOlfVWuqDVhJga5rZnbTbpAQI5rmYh78EeAo92xAG2aTA5yvUvWxaunnhHQtSKb5bRxWMQ3B0HoGlMTl0E=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF6AE862AC6
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_05,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=915 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509080154
X-Proofpoint-GUID: Hezx4uRlzFBzcW1HSTr8m6F4CRpY3y0O
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MSBTYWx0ZWRfX9jISmQysT7TV
 QRHTLEyfVYrWYnq7K+qaYFZZeGwrvDKUVrw0ygpBeP/vibEtW47Ytx4znH/DNw3ZaoNJDDFzo+L
 9j/3fDC6mURewhF9/Hviy6DIS8xqzQ0lQd4h70oO8T4jhu85MiZUbZp/9qAWs4zvFt/j37Z8zp9
 zSRcVqzHJHN+Rz0LDvMjr/eMq+m/gEq5/2/XfEgCGZOe16MRlAGeYmAbdMQyBbKQ64X0KF5Md8k
 AmrfWDRoEx7jfpqMWev3kDEJbr3kwQ5YiWIbXJ7vMYW5LSele6acRo3dRD2IyFOn1dPkmQDWB62
 tDW9fZwBuDZgpbq/5iYLxbafPXbcT6CZzvd6y1Lai4Km/fYFqH1mR4Xxp/DJB2pIU8KpbvPmFux
 zEi1zsIF
X-Authority-Analysis: v=2.4 cv=Dp5W+H/+ c=1 sm=1 tr=0 ts=68bef75f cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=CcX3mz_LIa5ZTRlDaXkA:9
 a=NqO74GWdXPXpGKcKHaDJD/ajO6k=:19 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: Hezx4uRlzFBzcW1HSTr8m6F4CRpY3y0O
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="NFCpALo/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Xj4gC0oa;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 05:24:23PM +0200, David Hildenbrand wrote:
> >
> > > I think we need to be cautious of scope here :) I don't want to
> > > accidentally break things this way.
> >
> > IMHO it is worth doing when you get into more driver places it is far
> > more obvious why the VM_SHARED is being checked.
> >
> > > OK I think a sensible way forward - How about I add desc_is_cowable() or
> > > vma_desc_cowable() and only set this if I'm confident it's correct?
> >
> > I'm thinking to call it vma_desc_never_cowable() as that is much much
> > clear what the purpose is.
>
> Secretmem wants no private mappings. So we should check exactly that, not
> whether we might have a cow mapping.

Well then :)

Probably in most cases what Jason is saying is valid for drivers.

So I can add a helper for both.

Maybe vma_desc_is_private() for this one?

>
> --
> Cheers
>
> David / dhildenb
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b62e38e7-9f27-4594-943e-987a14dba05e%40lucifer.local.
