Return-Path: <kasan-dev+bncBD6LBUWO5UMBBG6O3DDQMGQETQULOAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A9D0BF100D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:13 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-290b13e3ac0sf38714775ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:13 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962331; cv=pass;
        d=google.com; s=arc-20240605;
        b=iOdeV+29wfMS7xsIjFfrWdnAnGWHKViYOitnTRhEzpdWBourGRnbAXjJcWnnZKRbx8
         evGIm1n5Bm37UpCWegOjP2jE8u0BJx91wP16th300SwtDd9+mT7lq5CclfbdGZugx9hP
         hv9yYCNlUeJaAb3ZhvDAe8cjtMWUbw7O8hyBtjjZoJcPiBNDXudYWDztYWFercjJynYO
         vUZt7u/uY85vkMM0N5Sc4NdrUAQOf1hFJniLc63Vy1uVq/GxZ9OonK2zyD71OStDnMZW
         NpwbdrzraxcE86nnZavtfHThWAxCWjALDK1l+gRUvA71541h6cNQ8bcvN81xGiSwqEYA
         8B6A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=XnjxU4gOSrasbifBsDeD8Aukeb+22GAbID5OuOK9OIo=;
        fh=vVWubQTh06s+BlApTtHwu5t4ytgtUNsoUk/9U9Bu6gY=;
        b=DOo244W8Z9s42pwbdT4iKBfYNXU93383ShhmsCmWXfWgVTnd9Z4idzzuzFWi/J7XSS
         7H+L1l/9/S0w1q+7MjwI8r9WuEVAIrR1oycMW1N6JYdGjgIByhAwu2ctCZwa8lJpU4xF
         Xf6L8+snk3RAoHeJEddbIlpL3On2nn8uyW4tKlUM2J/NWbWJrSKMkwOlnPh33oM2Eu3x
         DwpQhYNxSycknpNDDNgUBLP45oo+PiXf2aXxZ+76ydfye4R3EqQ+KCIz5KPVLZF0YfHS
         5uYysYuXaFxy35ZIBTnoD7VrSTCpLCXL+iPDha1A9hiZH44GXd8CsJeOuHowLv3E0fba
         zxqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=D750FPu6;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=u2qFyJu8;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962331; x=1761567131; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XnjxU4gOSrasbifBsDeD8Aukeb+22GAbID5OuOK9OIo=;
        b=U6Jnn0JlouzpYXFcKWrSNP4NFEY0Q4Vg/fJ3CjeS+6KJX2iFqhltrVFtf3UvEGFpEz
         rZTjEpoBGL+v3pTa+8j0sEatG+7BfjqITYa9cHLJ5he5/w0aDe7fg4wuyceMtUikgjUd
         Edi0BWb0WC0jAVe/YVbbWTzfYX/y54NLC5u0dhq68zamT9XpGAPhaI6g0EA/zGper5qv
         NK4UKnLCO5Z0LJ03DIFjwWZkAQvAmI5d2zYXVtXsbEDy6qG28P6nC6NQM5SdeksEGR7J
         DK4IYqSz9Y5U+Rsb/PCp9BEPmop8EKehWkJumwKzW06eBf0qHVHD5fieLQlZxMuEZ+2x
         ZKuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962331; x=1761567131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XnjxU4gOSrasbifBsDeD8Aukeb+22GAbID5OuOK9OIo=;
        b=V6gCCeFLDLi11Uum8JFfOfM6qzqzuC68lFEVtVKmH0v68UBCdaj+JYm0r5/4+7moby
         GQxMyV5bZWMRnmEHoCs+AUSg1yJj3p3l327+8ncrY9IlhAlPK1uWt/62AIqMU+jWk60y
         CYP3nNBVKM1JSSLMHOwai/I+qsntyz5bpYkMbRm5mv7gr0BVAV745vJOywrBpCAwlt07
         o0IycKnXkLQSW6N/GNM8JgGHZiIuEVicEpAXmIzIMZWf2P+Isqkx9hA9kdPD5pf7y4ad
         NmwSfbQCtiyFyeim0I6MFV+7CMdxHAMSWubauPWZ72gGxDKD6yeiEu1NmOOjDbK+Ys6Y
         uxOw==
X-Forwarded-Encrypted: i=3; AJvYcCVfc0DaFkbM+zgMjComDs8UzKCyHMygL4/EI/ntK/iibnFF4jvwTfKXX+lVeKTU2OteqWlREA==@lfdr.de
X-Gm-Message-State: AOJu0YxRF/uia9EVAQ5bkt0JMEW9K1owrykdGJ8at5cKttfSuWpIFL+o
	jMts7L9UA8E5ymrdtgLBAcEtT+smijqogFpCqDl+a1td0d6jocIPYZrh
X-Google-Smtp-Source: AGHT+IGlTeYECuKeS7rA6/G3HkSa4ipVr60snmtZD3xNEtkyunI9MZoNlqQF2Jm7kA1nz5BBmVjJRw==
X-Received: by 2002:a17:903:1a70:b0:268:15f:8358 with SMTP id d9443c01a7336-290cb080e21mr184077065ad.42.1760962331431;
        Mon, 20 Oct 2025 05:12:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd40mt6eBZB6nqq4FavlefPA0yq8qWiMWXE3QAHb7366Ug=="
Received: by 2002:a17:902:ac8f:b0:267:dda2:1db with SMTP id
 d9443c01a7336-290aaa651dels31553385ad.1.-pod-prod-02-us; Mon, 20 Oct 2025
 05:12:10 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCViCBAItmqgh7qGRDWCh6Pe/proADF8+6xLaeEP3NKt4H9GmtzqVT8nBY4lZwIVjJU2en8ahcgNdEo=@googlegroups.com
X-Received: by 2002:a17:902:cf0a:b0:291:2b6f:cf64 with SMTP id d9443c01a7336-2912b6fd015mr140220675ad.55.1760962330186;
        Mon, 20 Oct 2025 05:12:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962330; cv=pass;
        d=google.com; s=arc-20240605;
        b=G/nyufGsJtFWpjGdxm35nt281urAENVdLnl/Y1628JnYF66Bx4tNF0PE3VTCBKap/8
         DJpyfSMLpWKJhvoMLYoidlFvL1o0jTr6S1k/KfgxrK56Nx8rbcSxbSkIswki9D04bUmg
         /Hz5HeSRhecdpEUipFr8dkKhO7g0lVGRk3axsZjSvW0PNtbj/Jdgy//ylLzEAg+MlyjS
         E/vIgIU0CxBXWe1L2wcgp2papfb3LKAxLSiaK4KzwG1IT+F9cpNHPuqHzu3xaxNdi2bH
         z8qWGc1MN2fSOd2SDZeI9Ly7dlOg/zXJwVQJiHQ+31R091oofdq1Clw628SopnPHABWM
         ttWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=k4Z8Gkrp55J6NdvMNggSqA4WJaWtCUu6nX8MlsUMAyM=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=ae0QioRq7SMPx8XvfYRvwdPCvUY1WENv/D0c6M3233ygBw/wceVCKQxCo3tZ7XvlRA
         ypX6uTdqXD8QOubbzzo4DDXRzwenHCx3v3lahov1aE6R4lNHG/sEwsjO+xrhJoIDMe+D
         esxhDbPzcKHKVfy37dki9n79Y+0VwF6GaLaDT2ALeLhyN/LqWJUxpLDP8l3w8BZTWEk3
         qN+51hHqf2pZ7vu1ozMEVLeHZYTkNsQ6ZR/ImPuULvp2XgFxQ+uwO65DvNpbeWYHwc3P
         VLmGY3kmfdGz/jgZOk/PdKetnLAbIKkjqJAMIcEgY5ECSQ6+LVp5Xo5LYgIwMDl4TOAA
         gMdg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=D750FPu6;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=u2qFyJu8;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-292471b1b98si3528065ad.6.2025.10.20.05.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:12:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8RkwF016825;
	Mon, 20 Oct 2025 12:12:00 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v2wat4h8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:00 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59KA9Z9l032462;
	Mon, 20 Oct 2025 12:11:59 GMT
Received: from ph8pr06cu001.outbound.protection.outlook.com (mail-westus3azon11012028.outbound.protection.outlook.com [40.107.209.28])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bbmfad-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:59 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=JMYJxuNangs5gxQBJgzbA2qsvufzYoNLiaDcPQg5zzKXzEaWkv6Rd3gQ1/ckmjITY/PyI5ecZlCqG4jHYfmo0FmAS8CQNYqfjkv3D9b0xvED9cv4dftZPQ+v+ucz7s2ncrJ78ObkREBx7q3+NTU702dBrCnHsLwz4+h4sjvgKe/e1qOAkA5Fdhk5X6n8Bk2r0TaDFcFJa2FPzdltiQTr3bCnI5W2z/RNCOxuOcqRjRBBY+nQZ4nRTKTDI90oNJ+AFa+jT/CFpGyc2+EFBKmYf0bFpRhpJ/tTXe82bXj6gcEhV7iM0tD518At+NpUsMFao9hVERRnR9AX6/KoKYX38g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=k4Z8Gkrp55J6NdvMNggSqA4WJaWtCUu6nX8MlsUMAyM=;
 b=gh1/MHjyc6c8oW6+La4P1DRu1yf4+6BNYfVWMzywBpiRJ35tuaU7yR84frJzUO5Kl8al5aun3iAcSVRF7XLDM2BG/w/Nu1lBMoO1vbEfp4NQDikKIQ26ygAkh32Lvd4ODJNQsmUADkDkLTvbl7RWb+yTEl4KYCDW8m2U4+POFq7KT9FVXk4PrCRlCxpGv/dXewu8lPZCTi78z205ZxbDwR1+1R8q4Ku3WR/KtWrGyDoeW/xmbeANp9y6HekAZTF2OnIGtwCuQrkswftyLuNHybM4AAvYUHJ+TrkLimndFC7hYqJJ2mDnPMVsfO4qqSdocMmSFgZ9dyJhfKN/sLtCzA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF4A29B3BB2.namprd10.prod.outlook.com (2603:10b6:f:fc00::c25) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.17; Mon, 20 Oct
 2025 12:11:56 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:11:56 +0000
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
Subject: [PATCH v5 08/15] mm: abstract io_remap_pfn_range() based on PFN
Date: Mon, 20 Oct 2025 13:11:25 +0100
Message-ID: <d086191bf431b58ce3b231b4f4f555d080f60327.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0680.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:351::9) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF4A29B3BB2:EE_
X-MS-Office365-Filtering-Correlation-Id: c0216fc2-512d-4e96-42c3-08de0fd1dcba
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?qYjdC3K/YXM547PVkem16+JUja01cTMOfxhOVhvteMpDSqVV10lP9+JF2gOo?=
 =?us-ascii?Q?uHNcy2IFI8ox/ZoDh630+/N9Hlco8lNKg5pbEZuwjPaS0qxEMxuymcxEhIwb?=
 =?us-ascii?Q?DCv/z8Lwy7Go+ty467zXZlTojDIq+c8FkUbyzRkFJSBA7DcLgICKCfRxFNCm?=
 =?us-ascii?Q?uaScKTtc08Ip4ZQ36j6GJBF8CRz9BixRVgiOJIA/RAeFWjak9tE7QJdsC7Ol?=
 =?us-ascii?Q?lr6qjmA7SVp9cYkFoBm+XXj5obBdCJgzddKJGAdoyDGaN279T1qqJAjRwEPs?=
 =?us-ascii?Q?n9KQP7VtaNy6HW7F/ykFdxu1+t9az0Inn3Otom+oEMXrTFvSqM4cH4CPVoI+?=
 =?us-ascii?Q?mEgKqlasBimWGnD4wqBV9zKQkUhqk+CEJpM7GCPx7pLsDZnF8VLrzti5o+If?=
 =?us-ascii?Q?2JlYwIYThKz0MAguF/CFHcFEP8xtx1q83hwU8TIzsybk0AsUKv5m0DGIJYcp?=
 =?us-ascii?Q?fSmO/yJO3Tvoy9bQjc/0ds4K7s7wtV50gfDe2a8TGqJam1s15TS5eJi5tOAS?=
 =?us-ascii?Q?K/vU15nVnsWAuRrLL3xDNzbCu5adew1JqEpTSa65ZL74iKVY5VdR5ywS6hkN?=
 =?us-ascii?Q?Kd5myjdaBNuNe9+tNAvmKi4a+6y1dQnal3/XO4zQvKmRXxEcjWpuBkw1B7Iv?=
 =?us-ascii?Q?K2oEkv1YT5+I9RMg5NwvZJa7YJLtmQb81nZdVL5GaJDTlI0j8OUk1wKYhihk?=
 =?us-ascii?Q?9qoSg2fkRCDGFOYuMp/hOrWNNzt0XCYymHCXBbJwsqAuxMG7n1I5SkKaURS+?=
 =?us-ascii?Q?AH0kUkwrDhrrzQTVBNqy6m/C93fLD7liutMQC4+bNk3CkQudfGCnrqI24SGU?=
 =?us-ascii?Q?vGVZ1vc4uELHug0ZzY0SeMF2ez1uBhGUIMFp9mb9DF+Qqsocq+0DfVyJHHfo?=
 =?us-ascii?Q?hvPcLFru0v43p5/hk2ExdWOkqXxfRkcRLRq7AXFgjDjfOrdLQEUxAYceNtYC?=
 =?us-ascii?Q?qgDGvdUsFRmfBWmaW+WPApblog58MkX31cjhF+uO41SSAi+kVrptQDWIBvde?=
 =?us-ascii?Q?VXeSzCpg5Jaw5OC1U6WYzShH4qy4k2XkNBVDxYfCNhViEZrFYe33HMKkTt8t?=
 =?us-ascii?Q?LJwh8RwKvVfUW6Juj9x0Vho9AYyZNRNS5wnOF2UeMeDXGZV80kn1nlBno38P?=
 =?us-ascii?Q?N8A0frrhFzMXNrTOYYEE/h6jKMDCeOrasW0qiM1Fw7eKimCMEzOdAnmT9LCh?=
 =?us-ascii?Q?OOnKcC9sPllyV3ogSR5VSE55zDKEwOmz3C56MpPDVMAd+rnNqMS7i3AlUGlJ?=
 =?us-ascii?Q?4pzpyD6myixc3Qmxf38jO+uDKKGcV1fADDIYg44UIJA5XtNE1sNpt+5i+8U9?=
 =?us-ascii?Q?3R6tPHdR13tJRqDTGlrdv14nkIIWI929zjU9a/0G0oUz3odvQ4SiNYLi68o8?=
 =?us-ascii?Q?Ln1JdY/GUphTahAdCKCBFRZiu+Vo76QQjjzni9iwtRrbW3iT/oeAPmt6gD38?=
 =?us-ascii?Q?jf/XJJV1GqLd56hdBKqZ1JSiVSjLdiOb?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?a+BUSDjKcl5e7VGu47hFLybhjy8Bkb9Jw9a9mfjBYq1FuIqnLzX0Zgd7HszL?=
 =?us-ascii?Q?ImdwzIRaWz2CazVEVBeav67AfowQMMZtOZHpDLVeYaY0SO39l6RnR7rO1VfW?=
 =?us-ascii?Q?JSIt9R8cnOIXxpsTdt2GYx+tdzgAWa6Ne0ijYsKGjqaGi2Pqt1WqM28JgItX?=
 =?us-ascii?Q?x3NRO4m9Y6L/TzLVWYnjC1apf+Gk449uSMgSzrPq4hTWpLZ55qxfgwaF0vbU?=
 =?us-ascii?Q?Zn16gK8+eozc2YXasrPf9Mst5OvnFLQ4yBBUtQYLrVRRiesk41EfDZxaTnn0?=
 =?us-ascii?Q?4tdq475acQ+CYyxqcXI6baOQHKW2tfYZNSvZet09CwwRItcyEIwct/F2qKtX?=
 =?us-ascii?Q?7mu/3EP6GRt8Apc0zauK08okdVQMv4KkxcfR4nWmDk84NVt4XYFyc+HLyrGr?=
 =?us-ascii?Q?/urbJCXZYGD6jNHxKi8dA4wLF6lJp71+ympLAT9OOh1v0nX++/lCSiD8aY/N?=
 =?us-ascii?Q?j/D+/vNlk+lAQZsPg8RXwPOR0v7PXkDdAnqVheGuej0vryNGmQ75D2KvzkwF?=
 =?us-ascii?Q?JVKGDWVdfqUqhbejcW8fJVyp3Y1uFgV/O5EKsgMfpLvMUGMe1ncyU5IpA5xp?=
 =?us-ascii?Q?S61FwF2loQxwfdw+t8mv+CGOoAqcslQnw8nnWJX+LfINyue3NXEfeJ+w6NbC?=
 =?us-ascii?Q?mzODmICc2cFj4izfehtqZycEc6IZUSAVXIE7fIzVc82AmGeny1L7rcY54mQs?=
 =?us-ascii?Q?amznHMuGkl+JEmoqoksAFer1CkukHxPd6M3I/Hbb4RNWQuaMQvNhAN3o2ctH?=
 =?us-ascii?Q?5wbe0ZUxRK/S71ap6tNkI01dATu3awMa9XFKZzR4cB58QDl7pIYQ76blYsmi?=
 =?us-ascii?Q?w3XzbmwnDD9V6hVI6d+RTp13MPYwPNefHnfEb/I7dHQ0qh5J3k0sj5vE5+Jh?=
 =?us-ascii?Q?LhGRNjEH0zO0uDP2u4SaGDYvAl3fWKv5w7UlotWUHjfRU1ztlWn4iayGYXlH?=
 =?us-ascii?Q?/Kze3p7rVQ/SEh69OtYziQZJ25beb8z/BSm1KBcuPUzD3QhuYAFzELXm/8is?=
 =?us-ascii?Q?Ja0pg7kZgESmu0gxpy4pB71OGUMD8aLT5Nae+bOIYgQ2AVEXbttU5H3gaqnP?=
 =?us-ascii?Q?5IiQoFjt5D+cjvbQP0hKIwlGzBthBieSGa+S9CBmRK/ct/UVDsqT314W5FFw?=
 =?us-ascii?Q?pbPoJ7zDlVz7IPThPLiSQLhsYBId2+VrHhB8YRLCCnUR53VDBqztwLrizLcy?=
 =?us-ascii?Q?QSZWD0o+jSW9xYTiJRLzclxkmcW7T1StsulgI61I/TdXqHO5P3KlIw/DYupg?=
 =?us-ascii?Q?JWqsT/etYFRp25w4OzTXsKD41ooqq0+dFXo1Q8rEx3zp16PDyUFE48/Me1wo?=
 =?us-ascii?Q?2cpqfFNNACvCYZplAKhSDyQhiz9iaY2U74trwAAU8Sjc+q0KnjBt+fGKvgW5?=
 =?us-ascii?Q?gBbh7yzPt/uXhgtHpZBHFfVxuvDfE+gBkusCn2+m2mvcep+AW3AkgxWNAhrc?=
 =?us-ascii?Q?/tyfO75EhBRGjP564wPYBOqQAVB7daiKCkN+gXFDkB1op1VD951HmuyEMbXp?=
 =?us-ascii?Q?/tlauNBWN4SaUwb1Rr/RciF0trAbIOPplbOI8ndrSApKISOQ2TduXYFI5/T6?=
 =?us-ascii?Q?HyLp6Fj4wbFDNiGan17aWhcoz3az8OUF+4S3/vMQLc9h2M6JiOk/VrpaEVoh?=
 =?us-ascii?Q?mQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: /hISRaSge5ABGR8ITCIE2GjTThyGirPezfoQLiF4C/tRk7lb/VKP51ifopwFmzYd3+tv6E/Sz3cBQhLK2rbH4RxrzE64WKuE5eBxmXXq6W+nbdY5CT+6UsHhTnMkNcI18SeQlzsn4lBNQDNBxB3VZucoc27aE434FhYo9ePyo8qhRz3Eov4Wg/vdP776lwDWobh6Pzz6CxJggTn/6b8YuBDT1jdTReSsFUqKiKLd8kGWZEnpGDavq4CUuwgvB+od7bxUqIWUoxKF3O0Fv8UihKDEBTPxqN9pMgVH+95dM6hZ1kLSkqLJwWzSxwxlYscDKC2MZvsXVBs3UVkZn3ASWH3UZTQ6N6rBws/q4Bl0U5dnmluHWu1l6LjGvkbp4k3Qtozl6FfrG/IonbCrUQ+E7WnzVTE2tAI12/FW0UyBrtPnOMIAuQpyl3SpK0pwohZYIZHGOJiuQDknzAzh2LQfy1af1JQC3+bOFqk59ZooPeMNuW3Ff54mDCKbg4p0gu9ZJ7o5i0Lx4VgTpvB4n7BDzzNLRs/V+NkR0WqTNAuiZcqsWTsiA/Yi1xry3R40vydWkPu5ysYdRv9xYDEht4W52WAsdukz4NbDwg1VdqhfEZg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c0216fc2-512d-4e96-42c3-08de0fd1dcba
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:11:55.9653
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: KeKOzhNKvCJaCa5zSzVJoJNNwdqErRvL3Zoah+ki6CNxb/2o+va84q1cQar3NceimXqPDznzF4+37VtOS7Lr9v6m6ppimlu9PBw5UDqoFgk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF4A29B3BB2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxlogscore=999
 phishscore=0 bulkscore=0 mlxscore=0 adultscore=0 malwarescore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510200099
X-Proofpoint-ORIG-GUID: iOAve9le2khrsn49eX81vxF8GUj598SM
X-Authority-Analysis: v=2.4 cv=Pf3yRyhd c=1 sm=1 tr=0 ts=68f62710 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=Ikd4Dj_1AAAA:8 a=yPCof4ZbAAAA:8
 a=4Mv9xYtVCqfn6bI3fU8A:9 cc=ntf awl=host:13624
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMiBTYWx0ZWRfX0/mftYM9uc0G
 figy3e5H+ZUHLLd+EquGRyz/a6jlQeq4jaq17CaecErjugaAVtv7oq4BjiK0plEtSPc0lf31ZnV
 4wSsEYKCWUa6ohwYxPe3b5xXh1stWAIuZfF6GvQZeQ63nfH1lhUo/B6oSeb71KQf6OvmQDLrYTB
 UioR0Qt/GhpC9odqGV9sJ8tZ6dlkBkv8wbNAcjIeZPFflkOJ2CbxUp85Al05OGLZDdf+DWIufOh
 Eehbas+gQIAHKcZVRqWyQS6X2rZAP6d/5Px5cAHJyEq3fFxD57ZNA2OebzeuTHbWItHtfv1uJT4
 SpTfAM+VwccUuF9OBEuT48JdlvxgWSJTSc9c2B7VR3T9ALi3O2oIL12BgEBbxWuOwOVwjiRuOpT
 pgZjkVvBm7t6iiLPQyPwQjA03eOHImzH1TdwFa/cEPVZsgoI9ec=
X-Proofpoint-GUID: iOAve9le2khrsn49eX81vxF8GUj598SM
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=D750FPu6;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=u2qFyJu8;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

The only instances in which we customise this function are ones in which we
customise the PFN used.

Instances where architectures were not passing the pgprot value through
pgprot_decrypted() are ones where pgprot_decrypted() was a no-op anyway, so
we can simply always pass pgprot through this function.

Use this fact to simplify the use of io_remap_pfn_range(), by abstracting
the PFN via io_remap_pfn_range_pfn() and using this instead of providing a
general io_remap_pfn_range() function per-architecture.

Suggested-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
---
 arch/csky/include/asm/pgtable.h     |  3 ---
 arch/mips/alchemy/common/setup.c    |  9 +++++----
 arch/mips/include/asm/pgtable.h     |  5 ++---
 arch/sparc/include/asm/pgtable_32.h | 12 ++++--------
 arch/sparc/include/asm/pgtable_64.h | 12 ++++--------
 include/linux/mm.h                  | 19 ++++++++++++++-----
 6 files changed, 29 insertions(+), 31 deletions(-)

diff --git a/arch/csky/include/asm/pgtable.h b/arch/csky/include/asm/pgtable.h
index 5a394be09c35..d606afbabce1 100644
--- a/arch/csky/include/asm/pgtable.h
+++ b/arch/csky/include/asm/pgtable.h
@@ -263,7 +263,4 @@ void update_mmu_cache_range(struct vm_fault *vmf, struct vm_area_struct *vma,
 #define update_mmu_cache(vma, addr, ptep) \
 	update_mmu_cache_range(NULL, vma, addr, ptep, 1)
 
-#define io_remap_pfn_range(vma, vaddr, pfn, size, prot) \
-	remap_pfn_range(vma, vaddr, pfn, size, prot)
-
 #endif /* __ASM_CSKY_PGTABLE_H */
diff --git a/arch/mips/alchemy/common/setup.c b/arch/mips/alchemy/common/setup.c
index a7a6d31a7a41..c35b4f809d51 100644
--- a/arch/mips/alchemy/common/setup.c
+++ b/arch/mips/alchemy/common/setup.c
@@ -94,12 +94,13 @@ phys_addr_t fixup_bigphys_addr(phys_addr_t phys_addr, phys_addr_t size)
 	return phys_addr;
 }
 
-int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
-		unsigned long pfn, unsigned long size, pgprot_t prot)
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
 {
 	phys_addr_t phys_addr = fixup_bigphys_addr(pfn << PAGE_SHIFT, size);
 
-	return remap_pfn_range(vma, vaddr, phys_addr >> PAGE_SHIFT, size, prot);
+	return phys_addr >> PAGE_SHIFT;
 }
-EXPORT_SYMBOL(io_remap_pfn_range);
+EXPORT_SYMBOL(io_remap_pfn_range_pfn);
+
 #endif /* CONFIG_MIPS_FIXUP_BIGPHYS_ADDR */
diff --git a/arch/mips/include/asm/pgtable.h b/arch/mips/include/asm/pgtable.h
index ae73ecf4c41a..9c06a612d33a 100644
--- a/arch/mips/include/asm/pgtable.h
+++ b/arch/mips/include/asm/pgtable.h
@@ -604,9 +604,8 @@ static inline void update_mmu_cache_pmd(struct vm_area_struct *vma,
  */
 #ifdef CONFIG_MIPS_FIXUP_BIGPHYS_ADDR
 phys_addr_t fixup_bigphys_addr(phys_addr_t addr, phys_addr_t size);
-int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
-		unsigned long pfn, unsigned long size, pgprot_t prot);
-#define io_remap_pfn_range io_remap_pfn_range
+unsigned long io_remap_pfn_range_pfn(unsigned long pfn, unsigned long size);
+#define io_remap_pfn_range_pfn io_remap_pfn_range_pfn
 #else
 #define fixup_bigphys_addr(addr, size)	(addr)
 #endif /* CONFIG_MIPS_FIXUP_BIGPHYS_ADDR */
diff --git a/arch/sparc/include/asm/pgtable_32.h b/arch/sparc/include/asm/pgtable_32.h
index f1538a48484a..a9f802d1dd64 100644
--- a/arch/sparc/include/asm/pgtable_32.h
+++ b/arch/sparc/include/asm/pgtable_32.h
@@ -395,12 +395,8 @@ __get_iospace (unsigned long addr)
 #define GET_IOSPACE(pfn)		(pfn >> (BITS_PER_LONG - 4))
 #define GET_PFN(pfn)			(pfn & 0x0fffffffUL)
 
-int remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long,
-		    unsigned long, pgprot_t);
-
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long from, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
 {
 	unsigned long long offset, space, phys_base;
 
@@ -408,9 +404,9 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 	space = GET_IOSPACE(pfn);
 	phys_base = offset | (space << 32ULL);
 
-	return remap_pfn_range(vma, from, phys_base >> PAGE_SHIFT, size, prot);
+	return phys_base >> PAGE_SHIFT;
 }
-#define io_remap_pfn_range io_remap_pfn_range
+#define io_remap_pfn_range_pfn io_remap_pfn_range_pfn
 
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags(__vma, __address, __ptep, __entry, __dirty) \
diff --git a/arch/sparc/include/asm/pgtable_64.h b/arch/sparc/include/asm/pgtable_64.h
index 64b85ff9c766..615f460c50af 100644
--- a/arch/sparc/include/asm/pgtable_64.h
+++ b/arch/sparc/include/asm/pgtable_64.h
@@ -1048,9 +1048,6 @@ int page_in_phys_avail(unsigned long paddr);
 #define GET_IOSPACE(pfn)		(pfn >> (BITS_PER_LONG - 4))
 #define GET_PFN(pfn)			(pfn & 0x0fffffffffffffffUL)
 
-int remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long,
-		    unsigned long, pgprot_t);
-
 void adi_restore_tags(struct mm_struct *mm, struct vm_area_struct *vma,
 		      unsigned long addr, pte_t pte);
 
@@ -1084,9 +1081,8 @@ static inline int arch_unmap_one(struct mm_struct *mm,
 	return 0;
 }
 
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long from, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
 {
 	unsigned long offset = GET_PFN(pfn) << PAGE_SHIFT;
 	int space = GET_IOSPACE(pfn);
@@ -1094,9 +1090,9 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 
 	phys_base = offset | (((unsigned long) space) << 32UL);
 
-	return remap_pfn_range(vma, from, phys_base >> PAGE_SHIFT, size, prot);
+	return phys_base >> PAGE_SHIFT;
 }
-#define io_remap_pfn_range io_remap_pfn_range
+#define io_remap_pfn_range_pfn io_remap_pfn_range_pfn
 
 static inline unsigned long __untagged_addr(unsigned long start)
 {
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 2b08ab2c42b9..89e77899a8ba 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3677,15 +3677,24 @@ static inline vm_fault_t vmf_insert_page(struct vm_area_struct *vma,
 	return VM_FAULT_NOPAGE;
 }
 
-#ifndef io_remap_pfn_range
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long addr, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+#ifndef io_remap_pfn_range_pfn
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
 {
-	return remap_pfn_range(vma, addr, pfn, size, pgprot_decrypted(prot));
+	return pfn;
 }
 #endif
 
+static inline int io_remap_pfn_range(struct vm_area_struct *vma,
+				     unsigned long addr, unsigned long orig_pfn,
+				     unsigned long size, pgprot_t orig_prot)
+{
+	const unsigned long pfn = io_remap_pfn_range_pfn(orig_pfn, size);
+	const pgprot_t prot = pgprot_decrypted(orig_prot);
+
+	return remap_pfn_range(vma, addr, pfn, size, prot);
+}
+
 static inline vm_fault_t vmf_error(int err)
 {
 	if (err == -ENOMEM)
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d086191bf431b58ce3b231b4f4f555d080f60327.1760959442.git.lorenzo.stoakes%40oracle.com.
