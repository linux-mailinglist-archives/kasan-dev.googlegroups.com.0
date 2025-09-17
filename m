Return-Path: <kasan-dev+bncBD6LBUWO5UMBBAEQVTDAMGQERKOYY6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FEA0B8171E
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:12:02 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-78e50889f83sf2003006d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:12:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136321; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ga6lFpxIm6dDctACkm+z09zd23kfU7+Rh7tmoyzuUD2DVf2o2TDhuazZtnuXiFx0Ny
         5H39dQ7+VZ+g1dvmUK8UZ1TFr2zSkUU6Ja6D0QWh2CORfW7vNQ1n3PFrxY1a8GWO/Au8
         laf23IaSnSNJ1Gl83K5O89qn8MHC9tO5AKHBouy4qhCr9R/szUqpwf8t9qznDgRyoTX1
         b4SL8kmKEdzpP8wt+nGT1sSWGNwEZ4VGrdlVWnjAjAoiXcDIFAk9B3HJDwH2G+BraTYU
         tVtN3P1FGyMz4n0a/8JBY68DrGopmvH30vOwkRbebzgz6/usnMR+AwQHBNRg54g6XAmy
         U28w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3FYsZKbLJh30jTejPhmu1XDh2ATai3GgXpGgocE1Fvk=;
        fh=BEYk+2tf9mp46UA9F578t52GU5vayq59UkaRkPixI30=;
        b=lEulkCgJLrnb2PTqRxcW2mWTszTzjI2adTZbBofO8pg4i+ZKQkxipo42m1AXwTOt25
         WoFa7FOjnckhO4n+eB/CPd79SZhWmN1PaV9ZTlNfPLoWN1EzYbGrhy37YZtcqSTscv+N
         W2673EAjIx6B+zD4kL5HcFgDHzVHI219p69/FiFpQ36ByKttRl/To4dHH/8BGBJ9BwD/
         9rt/SeNs5XIuepXpd9VKNAVLwg/sUw17ngyG/qGeStu7hvAwN4DRiHWZohFZ12s78EYc
         F0n6qFYphIFmb9UYVwxUesrRlyyRqC270MMBVI28AiWEcSUvvzyPWkVJoX2Vu4/ATH9e
         NBeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=PPu1tKSv;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=W5xndNRB;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136321; x=1758741121; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3FYsZKbLJh30jTejPhmu1XDh2ATai3GgXpGgocE1Fvk=;
        b=rH/ncdpbXArnao2g+PDiWFl+9I1lABnn/sPAfKm4EdsyF0ab0fnnrx4ychGcvJjY1e
         9P+6O9HEtQroeKkOhFJkeAa+yrrTYHUXvXZ7yvTOUIT+cY8SZRflFx6evW9WeDlYE75r
         B2YJw2iKVcQp+DVNaVGuhvP3DrG6ShBO1zN6bzIr74r3X4oKz4Bo0mCdRGenPUJpAQPt
         i6f3tZL/yY3mMjvhq7AR3eWk8PRsHjgB37cczdReQSeJfCycP0z5ixamWHagM0WHR8Oq
         GqgvB5gRBYdagtI07yVH/UknNNELxI1zp1AljqZTT7vT3FYBAPlOidVAnsDMi0GZD6R+
         rezQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136321; x=1758741121;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3FYsZKbLJh30jTejPhmu1XDh2ATai3GgXpGgocE1Fvk=;
        b=ac0YDVI3+phbDJl3H6i/HzM5E3AZYYbqNTgW1hOIOoTA5HwUpEbkts8aFZpfalENNP
         32xQnvEmJ/4l7v661eKYThUcdoY1yHmhQH9K7UaLsu8uHJhLMVBrAEYXjV+QQpurtIjW
         E8JgEyYWknBlOlaFs2dRGkhigThK20hkbtOhyoeCe915KCNbhpvFxJLWWcCeCiklTY70
         xriiaE6RDkE7f/Sppw7F2dxC+7m31/WI3lvckqAs2Fb0J64pf63KwjStVb/2ptH4YFLi
         PXNXdgLfLVQGAD87Xy0KC5vEd/n1RvSXIzWyTtueG0CkMr+BZlWPlCXfnGsq3HOKmnCj
         8PVw==
X-Forwarded-Encrypted: i=3; AJvYcCXKVh+0kyiWIJTV1vW+YhTS8Z7+DPXZV0QgSugCg8QEIzx4H4abD6w235Bkhk6Mi4B/YJRY0A==@lfdr.de
X-Gm-Message-State: AOJu0YzKwTye62TER20A/OnB98O6puj7KN0R2hWOkIxkbNgxhCnfsp//
	TAwFXGQk/YufptrI6eAGXhdP9SOcZIPqCrTQiCHt8sjGbIxDgafYGrUl
X-Google-Smtp-Source: AGHT+IGlz1EvydsRc4FQRZ0Fy8k2VBo0qMRQGKHd7zZa0Nm6eXBQRMKP6oPHOTGVU8IQG1tejf+lXA==
X-Received: by 2002:ad4:5dc9:0:b0:786:dc95:7b4a with SMTP id 6a1803df08f44-78eced25f39mr46329926d6.54.1758136321167;
        Wed, 17 Sep 2025 12:12:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd50GWF+dpk1X8jwy+fXCPyhlZh85/CWSlmKLRLOI29F4Q==
Received: by 2002:a05:6214:2b09:b0:72c:74b2:94c9 with SMTP id
 6a1803df08f44-7934a0cf5f4ls1192006d6.2.-pod-prod-04-us; Wed, 17 Sep 2025
 12:12:00 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVGGuWm7cQT/bcLken7pWnoS4v4D6mmYKxhb7/PbXCovMF3HzN4Tb4WKLuzAJUUWt2nwfOlhi84Sno=@googlegroups.com
X-Received: by 2002:a05:6214:d84:b0:721:cbee:3a5e with SMTP id 6a1803df08f44-78ecc43c1c8mr35847506d6.12.1758136320269;
        Wed, 17 Sep 2025 12:12:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136320; cv=pass;
        d=google.com; s=arc-20240605;
        b=cJoTHWWEvLLJIqgnTkyc/9bQ7WvsH6pga1Lb+h2vQjptaxJVN/Y6tqk3W57BKFlavD
         bgoVeqwGNuDwOf2IeFUtYYwNuD5ntfDCCM9YlAXjMkKJt1PeSMu9pivYdPJ/rdZcI/hm
         w8QgI0/vJ51NuEqq49Il1x68R99kcsoB9jiMmfCbjHyezFZ4yGLMTJQcqgr9N8mB9Cqs
         WcNWEb0Fbbt4VW3oN9tKwHMydLjpM640Vpb1v/kKGTwplUKzgCmBYkD6jd4UzACdrcVw
         7+37eXBnus3dGyc/JJLKp2jFbnOzgctH4fy7dBWn7R6p/YVpxIKClozuBQReV5PUFJr8
         lM7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=iKXTZ1pQwSJCVddD59OiaFOmJfQs8O4g6Ma/tUZpxKM=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=KamIl5wsCELCh0NsTcUVoV+lOQrhnLavD4eqkNyjr2U60jwjuZxJZs4CE/Eq3pTIRC
         AcjMv/gk2jqFZyaZxFyLSBNaCwJIQeskpW2LkyjfYPuTtRnrl/mks5bAuiOKwYTlOa7M
         N4l2aTrzs5QYM+9G+LFoL0Q9oUnzhPEPD0Bl0FbdedX2rClAJTZgf7wYDyjOvNVZ6iut
         1zeANQ98r4bf62ISyHA8Ev6aTkJ4KnBf2/Wh7zt6SDDxRbi6L9s2lPumPE/zzbnrXDeU
         X/NneY90v2oBcHR9ePq/M7YN/FeE5eRr8ELGyu4wK5SfuUZbnKFuDkmbXfsSSSsc2K61
         mJuA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=PPu1tKSv;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=W5xndNRB;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7934ffcad87si61726d6.8.2025.09.17.12.12.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:12:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEIUlE010043;
	Wed, 17 Sep 2025 19:11:50 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx6j0qt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:50 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HHEIeh033687;
	Wed, 17 Sep 2025 19:11:48 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012009.outbound.protection.outlook.com [52.101.48.9])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2e5fqw-4
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=zUjNgcCWV/ZPlpBtIWM/K21+bG6qaqN4+Gy5cKAgTQwzY0LKh1uvDXb2NHYdRiNzr67Tujc9LwkVRPhskvtYlMlRICDZn2jaHSuAqf3qoflkjY2GTsbRvm/YfPiGLCbFTSDgnxFTbosG33ul0tkNElU+FgPmVkLe/5pfICYIS/D/39FmWxUYbiui2O73upcvKQmMowpX7x7L+GnBP9ivPbyiTqz/bmpuB4GaMWTOEbqEWv1C+LZLmrT7U7n0lTkd1PaqXTLsD/JWTi/dCDDmd0oGn5uAxfkAN0pl15MPhVTT/+BEnz/9k+6jUNuQSf7Wi8giv/Pb0CHqskhoNyFyxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=iKXTZ1pQwSJCVddD59OiaFOmJfQs8O4g6Ma/tUZpxKM=;
 b=bVdC8+2a96HTo6DE5W81mhZ0p6rjs0jN3DlZyI0UyTw+BLBzepBCVl4+CS3A0X0uoAcvm9qkhC3T8xFJXutlAF8NK9M+q1lk7BYvTQgn6CyYolvj9W3NLqqlj+ALoZLrsQxYoZdHpGv2OCSAhOFTQ0d0x49MBn3m4Vn7iEx4pjnKNCHIkKq1RJ+PSAqNLZHMaw6WCuvlSG/YmycOSqqgOqeLKrSxleK3tPLQ7t1Ly9/tax515dyf5kCjkE5OjY3ZdI/dC3dano1We0R6+4XwCAfJc4Yj3/gUN6IGF8RImiYTyB5zeBe+K2Ssmj3pUPuHezLIeM8iK6aW7gFtGZkGEA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by DM4PR10MB6063.namprd10.prod.outlook.com (2603:10b6:8:b9::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Wed, 17 Sep
 2025 19:11:44 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:44 +0000
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
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: [PATCH v4 12/14] mm: add shmem_zero_setup_desc()
Date: Wed, 17 Sep 2025 20:11:14 +0100
Message-ID: <fe4367c705612574477374ffac8497add2655e43.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P265CA0110.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2c3::14) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|DM4PR10MB6063:EE_
X-MS-Office365-Filtering-Correlation-Id: e3c45309-de5a-4b02-b60f-08ddf61e0a12
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ndcdei4vFxFQNhcHfws6/lzHeOf7+gzPqGGa1eKvWMuGhPPg9I9K7GPXunep?=
 =?us-ascii?Q?rf0v06aNDXfI6FWOh3Ce0r6WUmrkW90361YHCncWDC5xdCVwsQE2okCV30mF?=
 =?us-ascii?Q?RfGB2dxBSuFiG9nYNF3B26WqyDzAjvU17TvB9NAZjwLCGraAL9SE2QiifcVd?=
 =?us-ascii?Q?hJ+XxTHcfeCN47PNLnhrcMbTlhhriIGB00Qj95v7oGXRev00fgO6gJF5dVsa?=
 =?us-ascii?Q?BnRvg7FVNEr/xdhvcPnGuJRU3AvlXDbTwKjpZfAGo0ppK7u5+6P3WmBowmyl?=
 =?us-ascii?Q?l79PK2q6WERGke9WzSPiMK+OY+D8hWCBWwdFPjeG/eOUVBPWXXYpxJTkQvvb?=
 =?us-ascii?Q?scj9wmB5cencutyWiAITleg2+y1ku8DIdDH6cbdwLMZT78LRUTfiYexOTp9H?=
 =?us-ascii?Q?XtYt1GV7OHrOnX7tSuh+A6oEO2FELwJS/7qpekGj+347xhYo5n40AW7Pz/dS?=
 =?us-ascii?Q?hU3wct1r6ti63FHgmg4lshiTqNYLMCXNmvFxFSS7kBBWsZfQNW9Ni8FqCL5p?=
 =?us-ascii?Q?hxiX8ynQGCzLCuXZFmTpo5PDT0C6Z83o374EgZMrcutfTuh05dqoGsQ+KpEO?=
 =?us-ascii?Q?rn5/RiU9c3bHmbwmo75l2DT8iNjKCUARKIWIwChQGCi7H14Z4mZxLniLkZhR?=
 =?us-ascii?Q?rjdjJwMZYh9Le/2+1me1+rXnMqhfqOyJtYNn/BtxM9/Lsn4CsizawXD48gkF?=
 =?us-ascii?Q?YolNe4y4kHyQd5zJKGcpPR/oLFPncQA8Pfnxx/hdIxm05bCV3t/bK6DFqlm5?=
 =?us-ascii?Q?UTmESJ73BeplONk02UeG1TT38HwCcCXWhnAWvJoK9JBi3nqdx94EY3HtvZO/?=
 =?us-ascii?Q?ptcyodRsC6lY/0NineZqbStoHCajBMkaOrLq4UX2Cq8VxKWEWMDacFte72FL?=
 =?us-ascii?Q?vEhGmEPf4PqC1lcpBv/TfSD6+0hpIRJnCPAs8qX7jKGPZogTq26hbZG/jT4t?=
 =?us-ascii?Q?sMsPI5qbUQRrzCo+KrxrFwK56/ufTXQnY/iPP5h5Am2LsxLAAHWor7BJBeNN?=
 =?us-ascii?Q?/02lV8xFgADmb+eZVapN4K3nJdFu5YTB7QOIlgF/IBjOEscFWNx15XIrssvM?=
 =?us-ascii?Q?eyXhBAtexLypm8NrhyDDG+BC485EL2IuUAl0NBd6GLpZ54Zzst91DkdCZhpZ?=
 =?us-ascii?Q?wsWbgY/kk+R4jXsC8CBWAVx12G6MI27nXKxJpx7PaG3r3vZcsHpq4EeJkRjE?=
 =?us-ascii?Q?mpjVlclLs+xXsV54Bsr+OWk0y/oqGqP+X1U30mSP5AvtGGN6OqbsXE8r6g9z?=
 =?us-ascii?Q?L1/PgDY9Kpv1KjpZLcVj1O8LNlxlJUrIjubnESjS1/sGCCPfqDAl+BcfQ5+l?=
 =?us-ascii?Q?L+TFG+KmCLtDS6lwCkrgE3+qIETI+BS098hAALh8JokNZKT1dQ/XIBHZBw4Q?=
 =?us-ascii?Q?BgmF5oL+L6tOMLXKXPWGE+0yTIAHD+uvmxnwbrcG4sil54vpxLrVyAGrS91y?=
 =?us-ascii?Q?6e1xIxuZ2wg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?THINpftBorxqKWQvQXSubOtlmc/T1LKPrpyeenkw2HTChrybz2GaTNwGuuof?=
 =?us-ascii?Q?sdg8eFMNWvGNEt5cIYG5yKIEcAd46VpFFCVlgNXaBbJSpfCLWOI/2uPHGTf7?=
 =?us-ascii?Q?yOXCktU4oYQiI5Ml2Xm/WrDfmtjGH1HZ9P7YqR/T0dPFb6G/xkCL3F7pA0Q8?=
 =?us-ascii?Q?IXLS129K4gfCWAlpSawTUQ05oCvoO4ORVrRaWb5tf+iC+wSq8dFxrHyiBCPe?=
 =?us-ascii?Q?38gaLJq5UJbjlEK5VeMEWBk+ERc2Yl7CH/6HY/LK+eoOe92jDNsC45MsnVdi?=
 =?us-ascii?Q?CHcCaO5wg7A/T0h20nuvpJep7EUdY1YMKd77JsaBBNvSQeVGpl5Du51/ULF5?=
 =?us-ascii?Q?nwS0Jy9HLEMg+UkPNT8EHhwMOmmczwQxbQQMFIGzfTZ5P5li/c8oFgCE4Byf?=
 =?us-ascii?Q?AOy9tttovLlf+ioVzFUIkToPEPcSJxHD7IFuf8GlraS6mSfI0WYisaKgmfaO?=
 =?us-ascii?Q?fCtlvSv6DKyL/8u2ocCd6gvcZEIcChJrpFg42m5BMzvaQiYHlQ72ljwHbxNJ?=
 =?us-ascii?Q?Uzbw4eWvQGXUb449aSXxxDHX52qAdOjIVMRWCXBADqx6IwW6xRI7reHHN43X?=
 =?us-ascii?Q?jcyYjp1dW6OMR80UenL8RAOs/H+Lu8Nil4Et11Pp0v/XGziqCHFLNSMi/v92?=
 =?us-ascii?Q?CXZYyZUu7j64nTRzhf/bBhfdxdoa+Ol5iipW4fcbVoOWQYaJPuYrpWJ5jT0K?=
 =?us-ascii?Q?uAXxBwPaRFvMvIJTa4JTFeW+BD2BYmceFSR8SMFkXI/b62nt67hWmmCUhtSw?=
 =?us-ascii?Q?S7kd30NPPMXQzB3BkznVpGeC+e2C36qwcQL1sr9xEiwnhm+xsdbEk645N9VN?=
 =?us-ascii?Q?H0sotJS9Js2B2SlZz+J5C/BzoJqcBUagE0aLml5D6BkEwDVXYs1Rx1hhNCjY?=
 =?us-ascii?Q?OmuQizB4Kg9husrQuCkvG0G0K4YdX5P0yrDF5P8qmPDfVORJERK+Yv69t0fw?=
 =?us-ascii?Q?FFQcTKv7iCOh3zS0b2nKRzVghH9ClaIpBwXDOB7SbczTnlXRV2PxkypI3Rfz?=
 =?us-ascii?Q?N1uXNMDY6+/oZTr7I9lDJKyp2JhRStsqZIM8I61hQjW8yA/bwYKsiZLe2zIw?=
 =?us-ascii?Q?j6EW8g+Qu0jK3LHcx9QLknfGOTmcWsKHTLIf75ejBuIj1YYGzWYXRWV3i4Bz?=
 =?us-ascii?Q?+uVCcXZj8RzD89ftmUB4hjbxSpvVO3ztHI4GW9O1oNjLfA+hewRIOa9GtoJd?=
 =?us-ascii?Q?GNXLhMye/mum3oPHDdT8SaO8rmzkz+AFmgDqPRGNQ0Sjs1IxwpxmOGko3mp6?=
 =?us-ascii?Q?SE2/s6lsS2TUhLYWRB9KY0tuXf9HahCKw7mAWPpjaQsfunU1818j6HuIvjEe?=
 =?us-ascii?Q?aCZcrIDuKJje1loDAqfEAHaowMT7ok1Z02iu4bzlqYe9HxwydLewt58X8FA/?=
 =?us-ascii?Q?SiEnLwM1fO1Ing71JbCjobL3VPVtvN/dLKJUT3rTgzYMOsQ4H49tOj17gcLa?=
 =?us-ascii?Q?zZVD0Np/X3q8+nTAtprDQuvx5NG5seMj07upTw6EhuiRoB2wJCYKuLylCbxs?=
 =?us-ascii?Q?EYi9j1/ejkkpBTiSi+P8m39WHaITuuaj67NZWkU+vOHigye0+72Jy6duSjI4?=
 =?us-ascii?Q?JW9fyuJkNOpwKYgKXZ7UrdpT3N2VbfSnP3+we2LBwA+6meskHFT4uc9XSlIn?=
 =?us-ascii?Q?2A=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: M4K3uVKJJsSzPacnxfkWC8uY3VoKiVraspOKZ7CKTkUcrwVhIauAHwIgVQCDfi2k0NV2dckhBft9EbuOwgUglC7F98cq4NYqK5s5b95U0K7qeuv3m3rj5S2Gjjpb9tW2UO3AhcI+NK1UVuec2X6yUOHpy/F/cf0HEHaC/mnCQGSAUtqY3Tm9jMwA+kfarnYBRKHtQl6G6zrYuq6eOvs4ACCHWR/lMddqXtDdLS5KDMbFOjKT20UG3DXtwFuj/ktEy86avQT6/U3ovmt8mjkjDPt/gVVR01gUf+YqmDafhUDuw66ZS0bG9gYmDCmTetO6W8u/hw2VAq0OdY9B5FORWgWs2i8/KksIvzCLi1vYcuHmFt707Rb7zRez16+Xy7lPPTuJR+/HzOsw8kVLo6gS1Ux7dIkMLO5QnfAnHfI/WQBrQlEydW0vg7Z5iQeYEe2k9WysRLIfrN/ogVvW2xRFBDU/oqLxTQVoXnYcbJqUrHFbWbOIOrSuejBsgcWkP5lc07yQa3daBMEIfMbt99rr2nhiTd0l/4ERHY9EhEv1dhKqHzcTiAVxHRqi/gFiLp+CA3BXerLl1pmLAaesvn04sMKThAyh6NzAOlpysGieUuY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e3c45309-de5a-4b02-b60f-08ddf61e0a12
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:43.6178
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: wR3DLVlxE4qZvz1hdqt+kdOZUdD/q6Lx7Umt4mG/3yxnJEHvk71fNM4W0BmhPI6erXEQdaM+AdEbgS1iJ8qfNsdO64Z8WSdjVBYkx2X8WO4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6063
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0 adultscore=0
 mlxlogscore=999 spamscore=0 mlxscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509170187
X-Authority-Analysis: v=2.4 cv=TqbmhCXh c=1 sm=1 tr=0 ts=68cb07f6 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=bmQnSVsLClFk2KiDA8kA:9
X-Proofpoint-GUID: yF95KaCGtXKqfOFoCGrdEJNSiC8BH54Z
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX/s2C+nzjXeD+
 zvFuTQ/dnsWJH/+VweaZPGLdKszLFRkNXLQ0X3f7oVnK1VOgeRBFvnLvlo/bfYMfYjTXGjNjxte
 kKpcT6cEVuxNNPSfjptUfLF00Qu+TlQauC9gV9f5ekUmGniZ1p8nMT8qTBYZufCgphFynRsUQnO
 me6/Pfk7d8uTLBDC/o7GbUN7/vno0mpQbl1ss4l/pODW8DU1SeeorNZJ/gFead8128V4VezljLK
 QGFbgVblfzRlaTnNdy/khXb1mkl983p1/Otfblzbw5R2jVfFH2ZEtPJNV9fPjAO+MmxrYlpbCJc
 USKCF9mIDQ1AYV/TIBcL+pXXfeo14yQdgB8FDX1TMcdeznMptg/OyJHXMjUPL9lfuGMIVmv38o/
 9z4P5oX6
X-Proofpoint-ORIG-GUID: yF95KaCGtXKqfOFoCGrdEJNSiC8BH54Z
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=PPu1tKSv;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=W5xndNRB;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
index df02a2e0ebbb..72aa176023de 100644
--- a/mm/shmem.c
+++ b/mm/shmem.c
@@ -5893,14 +5893,9 @@ struct file *shmem_file_setup_with_mnt(struct vfsmount *mnt, const char *name,
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
@@ -5908,7 +5903,18 @@ int shmem_zero_setup(struct vm_area_struct *vma)
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
 
@@ -5920,6 +5926,25 @@ int shmem_zero_setup(struct vm_area_struct *vma)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fe4367c705612574477374ffac8497add2655e43.1758135681.git.lorenzo.stoakes%40oracle.com.
