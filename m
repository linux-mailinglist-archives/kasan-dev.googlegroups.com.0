Return-Path: <kasan-dev+bncBD6LBUWO5UMBBA7O7PCQMGQEPQRNGWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6167EB4937B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:32:21 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e96dc23e87asf6764403276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:32:21 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757345540; cv=pass;
        d=google.com; s=arc-20240605;
        b=cIO70pwsH2HVh/PA+wy4i5bXBnJ+Paxjq98x55Sif9TkHwycKIGLGElvTLI6bzYVnP
         ieQm251nexBejQuUFQSAvFVp98mn6LBGN8z3WQKT+KPbgCJEWmUWViN2QKf6MbceBaH2
         1w0RHn/8BERSjeC1mx01hkgswAVEMDYeNIS6649Cm9yqgnIFJk+zONdX2KWfEzMyMb4l
         sN2Al3t8mqPvAS0nWZkh3+0EYVEaer4GxUV0YwrHRK+4bFgOM/nvjHkMIHyw8wPSU/Ug
         Jng7VU5xKpSxE7Gfm1pQiW6J9XD58CwFamTXNladagCbfLDxAsZE0nbRoBNJTe3TygNw
         /Uyw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=87OrdhDh7uZcBv7O2MqMy+/0s/DJomlahvETUbkbSvE=;
        fh=4C0Z+Q9tRVrL9lHcyGgwDaa58NoURIhq744pCWaHXrU=;
        b=KILg8WTJvWBBRyCoR5wAK4qbBZtxt8Q27X2NZS4ICxApLc0DfsxCSgUA3INgL12gEg
         aoOnpwZHAcKYiWfZ/Dc5NQdzbuO/Kx7LtZY8wCUoprGVcSGZePN818THQ6/rehlVRYA2
         xVWkDWOmCgiVaDzK2zgqFbMZaNKXAytphRLtp78faXAWjdj+veWLb6ZrNQhrguNSdNrZ
         LrMti1NesoJOawydkrRvlEOMfVPumi3klyMrb45chAh/cqjbjwp/CfHYin2dmWcpuxK5
         7iHUc9I1vkV7t86Yk6QQClEiiWMhWYY0Ir9AB2EzFVnzCle6UBLDJoX0RV1mBRaFIK+a
         W+0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=eIF+FjSE;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=SMMuI6pg;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345540; x=1757950340; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=87OrdhDh7uZcBv7O2MqMy+/0s/DJomlahvETUbkbSvE=;
        b=txFvgzEa5i32yW8+WvMTjcQ2K6Qh4mYepXZ8BS6eow1Ex8+V3/rTR00zPuwce0EBDo
         q6yGUYSi65LGH7HpvL/xC5QKPU0pft8i7K9gq8XkqeW/oVfl5u25PhSMA9TGRdvK8hGF
         eA3uaswCjPPzt0i/sfJk+7ovepsuufdJiYEcTP+e1293EubMTcpZBhtfq0xsQUMXrau1
         oCPGhsP1ajIaUorcQGOv0heM4+HD9qRLTCqKuIvTdDBRytf3rmwZR89J83aM/TXA0mJ6
         i44JLbQJZa3FoyeTYR48UhZpVxagNTdcQp2HYurw1N3m51yUdIQcOFUZd1p3j8YWvTQa
         CsRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345540; x=1757950340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=87OrdhDh7uZcBv7O2MqMy+/0s/DJomlahvETUbkbSvE=;
        b=dC6VUHUoumi4BqCryVMSByvUaEFtAMmdbTDv2VvvbzP9G48eDVK+rl9BrxsKdKJSAS
         ncKAfRH/NjhvRb1aekSGDymyH/ZBIG1VWx9SDtF9zb3Y7XJZlLcruaS+xd/dOdHvSnQe
         UovE3UiO1PB14fgFytp8YdJBhQ7HbBVEDs9NI2iBZ7DqLID+jadb6ADB4a7IkSoYLJFn
         XOw7dTfGN0BDrSH0MCoOOCjHK7SLJRqA68t05iLACAkV0MEth4e13L2afrpTOogg58fJ
         +wJCZJV5iCu2k0P2PCkAax9/ilC1Y0Gh4tixd8joJbFb7+ZBFXa8DfU9AYKJykbYDcvf
         m3/A==
X-Forwarded-Encrypted: i=3; AJvYcCUcUFsOCwM6ZrY4XvRiA/wA9NY/cr6WDiYst+QIdDRLbHpIoHT482bl3vGmQpQVYHxprq1qqA==@lfdr.de
X-Gm-Message-State: AOJu0Ywo597AeIGw7fZMLXSaRyvU+Yfc9brJTF9DL2eutbRYoBBcR+yS
	nbLhBepcqBhSUTyEU1Y4+31BaeGlsg9ylb9CCxH7QAh5OH5efLxdar9u
X-Google-Smtp-Source: AGHT+IHUmOh7b4uEJqx/DDUwyr1OfTwjwjPdQMtFEc9vHRFXElSTuT5Xb0zpF3h0bUnRMvF/3EQVww==
X-Received: by 2002:a05:6902:4889:b0:e9d:68d6:da17 with SMTP id 3f1490d57ef6-e9f67fa41b2mr7571294276.37.1757345540163;
        Mon, 08 Sep 2025 08:32:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4amveJrXnngmr7/a+oQnZPqHQKkpsdvbXNj9AyTz+M2A==
Received: by 2002:a25:4c86:0:b0:e9b:e2fe:3ddc with SMTP id 3f1490d57ef6-e9fcc2bb1cdls1058769276.1.-pod-prod-04-us;
 Mon, 08 Sep 2025 08:32:19 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXh7P1yPIv54kaukUXGzzupOOcEECc0xk5XHTLSxpz8jyKtcFxV/9x/0axt2UJWOyYMuz16MKFGioI=@googlegroups.com
X-Received: by 2002:a05:690c:4984:b0:722:8611:797e with SMTP id 00721157ae682-727f4969bf7mr61757647b3.34.1757345539254;
        Mon, 08 Sep 2025 08:32:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345539; cv=pass;
        d=google.com; s=arc-20240605;
        b=NxfwHsFpQqvU7E3HiZtmSReVNGlIxwI3PqmDEecUQXv/ByZIEwWP5YxMXVFCj6WJr1
         rY1vadGZAPLuvcnK5wPMAxTtBWuFuel8BTDCuQukJRetq8aSycl7P36lozMObjm0zjsT
         sAeoplW9rEVN8KNms1OP0A+ggg1pu5S6oE4ZwNWo6jsqpvSVFuNiZV+1yW6DdAJfsDuj
         vO3DEVjXOUYgH6Nt6ttxogeWxF3RqcBW7n0SjBHpQZExEZ8k9FElLHhElk9X2MwUhBjV
         Rb0UTbgPj3VCVzrYE26v8UBpr8z9fnvJhJUxkt05dxQOXebQz44OYceiFgMeKxaEcQh8
         u/Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=89fg/8C4jtDzJlUkib6aHwbhari1RID5Z0M8iwJx5UQ=;
        fh=rBgXewyurrOnUosxB6Y1BSdBMLv7NW0sq4bxnqF789M=;
        b=RbMuTFez7+06qiwW71c+RdBn4EanPfA7uN4l2JSmgErBftSClEBc4FCtpSOjhlVqjv
         KBzE5jWY5pawkAGtYjME0KsbQfvMMFxS2MJCipccIQCFTAGWNvGqsOghyJ5yX1fW6QhP
         LDb07bMy7F5pg2AWHP8Iguil3+HR4ckJfVvkzpOdjtO+7iEbFRtUH/zPUf+UUV8RPhE+
         ASTffbLh9HZdFBar1qrQd862nJBq9ZCf4CmmqcvBibgmRnX8aSZFuQtWFShW9A4pVg7M
         BjOqshwgztQIpos3pBLIYhZpRKcxQ36bjzLoi2pKCRC7uGq+0518qakTmrfEn4b5NCZW
         DqbQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=eIF+FjSE;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=SMMuI6pg;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-723a85336b5si6505907b3.3.2025.09.08.08.32.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:32:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588FEglH022696;
	Mon, 8 Sep 2025 15:32:10 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921m2r1kn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:32:09 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588FGtEQ013632;
	Mon, 8 Sep 2025 15:32:08 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12on2077.outbound.protection.outlook.com [40.107.244.77])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd8kr1k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:32:08 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=pEI+TZ8wkc3QoftfZlS5osBKhh7W3YjfygU/zBdZif1xLejs7can7luhWFpK8uHa5pqmrtdjXHdJwtS90bOzm9zGXNUNfOXvmNNJtKVsWxIT5a3BAUl5HteTrCcCHeasOjtGbWgqKNjcAeiXPHmO0QxkDxMqcpl0O/B5nyYe1G1FBMZz0pxw0cm6dLCQmT8ksntpceVzoAfIMMs0q6lEQcHkqiotek0Twjfh0tRTzu2DI/tdG49zrx8WQzwAmM+q7dzJAJBtwGm25ONax5zGKdZHvOqlMK/4wzuFCqcT3IOMnqmeA1GWM658W8JQ6yYX9aopZpOzHPOrugWD5maFig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=89fg/8C4jtDzJlUkib6aHwbhari1RID5Z0M8iwJx5UQ=;
 b=Ag+hfBgW08pOvnvaySubbUoZcKcL89E7qqx8MPzHmcsdL5fRB42RbVLlq9sYD1f5x2UKvaMjAAB8qYDK3VqR7UZZrSMhAya2IbXH0VTfG5ytNxNasbBEkisiWA8ZLyIjOvjMRr+sg/t2cwrxHkcAJz6DETENvHS+chn/l7zsVkh40ByRuXY7y4uo2CWHIvGJ0ubqvgJyVmhEq3fDzjUPH/dXhlzUth0TxVcW/15a5gmHLc7eMa10ZCn5NboixZMFaGPbkYqBPPnHdF58nkTbN4lAaY5iwH5ViuX3DNEgzZlZn0twV1/in0740ENuUe5PJLe33kwMhJmmkY7vjTjIeA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS7PR10MB7298.namprd10.prod.outlook.com (2603:10b6:8:ec::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 15:32:00 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 15:32:00 +0000
Date: Mon, 8 Sep 2025 16:31:58 +0100
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
Subject: Re: [PATCH 05/16] mm/vma: rename mmap internal functions to avoid
 confusion
Message-ID: <a8fe7ef8-07e5-45af-b930-ce5deda226d9@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <626763f17440bd69a70391b2676e5719c4c6e35f.1757329751.git.lorenzo.stoakes@oracle.com>
 <07ea2397-bec1-4420-8ee2-b1ca2d7c30e5@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <07ea2397-bec1-4420-8ee2-b1ca2d7c30e5@redhat.com>
X-ClientProxiedBy: LO4P123CA0192.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a4::17) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS7PR10MB7298:EE_
X-MS-Office365-Filtering-Correlation-Id: 79da7d8c-3c0c-4180-0bd6-08ddeeecda3f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|366016|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?TghN1FBFJdwzZ5GY/I/UMl5X7EETE15tgVqCI7AEIdmasBtKllQpPxPCLDWn?=
 =?us-ascii?Q?G748zscC/AyWomJ/TII2zBSN2KuRepIzWOOy78g5SEiCHvHarsYSqSrrEa9J?=
 =?us-ascii?Q?HDjMeZO0bbVGn4QjPvgF/M/K2z0ApOcS/OqayXS1M+LCjRqc5jWle9FWqUWF?=
 =?us-ascii?Q?bNfAtjP0NzwA2D70Wge/4mRn9TrHlRMsMxSPhXqyTtiBJffiQPLs8BQJb5wh?=
 =?us-ascii?Q?C9bXwLTncOND71fAKGA0xIz1+xL4Nag7pJZus7MUHjDNo3VdH66Rqi0lDA6D?=
 =?us-ascii?Q?15SJkj43i8v/q3LJGqo1nScgPENMHYzZF7ctgr5W5ZwqBKcF2K6auwwoiAm8?=
 =?us-ascii?Q?V4LfcvolN6VidS3HXGiuoSfIZT0zZeqH04hPI9UJ1xeUlh/FACBiiC7L1kZ0?=
 =?us-ascii?Q?y/mfeGAnddH49t8tuSLrfRmG3J1q5WAheKFE3WyJMUKVS9LRKodvaxdQpEyv?=
 =?us-ascii?Q?cax5Ydm1mX7sVa8Gbwe4PSAhN6pg79bVX9PcQ1jco96/QjniY1kfnLTVQNK8?=
 =?us-ascii?Q?nDrc/G/Oq9VFEhJBT7x7iiB15o94DKNtO3lx4XZQgh9SHDrrYc7eEb6lCUEb?=
 =?us-ascii?Q?uS9L9UcR/5hvHVB3FSb6wRbJ/DNhAMua09FivrIX1bM6LJdkaDJ31qqmNf/S?=
 =?us-ascii?Q?KaV+bsx4QItS03CjXi3nWDYhtA2mYjo3ki4//Pj/VVjRCYh/4cs8UpuEouR3?=
 =?us-ascii?Q?MJTtQq+nSALS+DhWqfK+iHXHxG27icZ99jvilpfdQPZJLuQoVZS/+7A5ufZ+?=
 =?us-ascii?Q?K6R2mnaX8zLBZlFfeStV+GZApvDKmrX2mpdh4J/70KgtFD9P7HUa+qr3TIuh?=
 =?us-ascii?Q?UVCWLR1dUkYPMYt6KXhNd+C+vSqW3Wg8J1IEe7M+Kz2Wa6uUHUICI0U4/ApR?=
 =?us-ascii?Q?8v5MtRzcq65EUY/pdqFzU0nlb2Z7HxnfNPp/8WS7WbBtcG2TLRTomFtGNB5G?=
 =?us-ascii?Q?j4hr3QFH88lFzjR3EkvL3CUkZx/YPw8eePYFbTefOcMh/TSd78cZBTIK8LI9?=
 =?us-ascii?Q?F4TRt60JwTCgohgPA7LQvvzwoK0dLPngpbCcZ6RoMG1Wc/i7DeG9eP3VMAWy?=
 =?us-ascii?Q?CLKUF8vHzMo3HiYgkDHKWvWRDQoGxCl06UZIKWafCA/niNVlLbjJMpPI51qt?=
 =?us-ascii?Q?25wCwTolOGLLZXROtV0t5VORcZGz4aPtIF0ERoFJLU9V8hjSpy5Uhdxia1l3?=
 =?us-ascii?Q?NNIZq+/We+bdcvOrzm7wJfH8Y6ekiThAvblcDM2PsY8WHajDvi489XoNLgm5?=
 =?us-ascii?Q?bFAn4ALrcm5MKW7wKl6BI9NxYZmAgf5V2WmaPvlIykkVap6ldwtyt0rJN8wO?=
 =?us-ascii?Q?xz7Uc5iM27cPJXAr98PI/nvweaHy2H7UrrW7uXtGVyOlSRPnvJx1LZKjerhZ?=
 =?us-ascii?Q?/Vx0veoz6eVUvJ/IreBv25kN2ntanjtfaUQMXIc84IYcdRt992pD9PyBuPs8?=
 =?us-ascii?Q?vQhlSWwbofc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(366016)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Qh2aG5jgpmOziH7KlyVWvS6HFy+7ktdENZz7gd3z7zJLO/SL+H7JOqXzRZiB?=
 =?us-ascii?Q?Z3/lYwPpgVgAZnN7dTrcY+Ueqi/Gwk5hoN8BrQgkdB8AFDEMm0qQBEYPoYAq?=
 =?us-ascii?Q?2iPTHZkX+sE+xYpv7RoZ08m54JMmiD35bMrXwPXVulZCFSS88ODc7ACV+3gH?=
 =?us-ascii?Q?zwU8RtXiCp4mlul55n33ubIJispl5PwEpDXsPAjB8TX6029xmitCy3C2CqKi?=
 =?us-ascii?Q?f4FVzkc561roJVX9JhdIArDh7X38Vp5AnFmfP8Aglkdo7LZdhgGMNgw6R0+h?=
 =?us-ascii?Q?xeuPEJ9R02Mz9CLBy/HpJAC2/QWXjCQtADiSHMeYf27BW0vWAq99y5MZiH5I?=
 =?us-ascii?Q?pZnP6Zhb1aE/kJAA90G78TEz3YczZaKznpiC0Nv7Gz7wioluB+VS0EVo/hLy?=
 =?us-ascii?Q?m0pMymy4dv/Y0lu8ltsuFQ+fNL0W+rlneZdPzt1vvetVxla2J8K8Utcpmgpi?=
 =?us-ascii?Q?dh/DCFwubjyiLm1pqSQj/OL4x5hQ+bRlLTCasIvOBmYT/+cAC7coWlxVpG5Y?=
 =?us-ascii?Q?T0ZpnXNXYYuJHJ64gvDU0q1C9Toq5SmJg99kByY5sOpRjdI4Rhg2DutKQUtr?=
 =?us-ascii?Q?LKDBV6JiAvRg5h+KLonL8YFgFSfre02s88IamoWyyOJnpXJj7gTnn5i82Zdl?=
 =?us-ascii?Q?HMlKCABZbHfGURduinGqXGsGh8rC/bHXQ3BJ/V5/gHB6ofIn63T0wVhTEx2x?=
 =?us-ascii?Q?g+AEMASW/dyIc3lw9qPF5vYmUGLrtXjQGBHJaex24yhbn6oXSPhVI5ZXfwha?=
 =?us-ascii?Q?SVjRJHauWXV3IYo8tKQRfCOhyCUTY1/9g4pU3uOTDeFA4mJ9Sz0AOJgyOvcb?=
 =?us-ascii?Q?UvE6TvVon1UDKQdxUdaHD6HJRiXaBkoTvDGRdQWQuBhefCxerU8a1EqsK1lq?=
 =?us-ascii?Q?dd0n0jQ+Tlsn3u0S5GH3yJcrgolFabL6HftvjNg962E3W125UTM/xsO1IDna?=
 =?us-ascii?Q?NeZnGh09OJYNlafW8I8Uu8YTrW8fv+BwSqx3i59vNpRavgKSDVMhCCyFBEVv?=
 =?us-ascii?Q?slxiL1+7sZeuUejxEYp6SajkdHQOrRTgDxScqv6CdtQwY6esJnuTHsU0CPQW?=
 =?us-ascii?Q?rmGwCjT8CpmJj7Yi4G7HV/+r/ClQ33/Ru6Vpd7m/u4h/OroOTjUUh9jICt3B?=
 =?us-ascii?Q?ik2uCw23OBI5PhY0SkJpEXEHlZEyXI2NNCHOJGfh1UpS3+cJYCnopgk5m0YI?=
 =?us-ascii?Q?RXUMbIvVi7vIB3YYBAlfOUBHGhGFmC6aPDLvNmYSoWI4jtzcpnWcmdcdLAxz?=
 =?us-ascii?Q?VfFSjarSje1sg3ZMuxB06G+Oe2H2Xxm6zgKtIf5RvxZuSXKdVQg853z7Xx5n?=
 =?us-ascii?Q?IMPRn/tlrBdNgB/IQ92k/Wv+puHeoSMVVRCZkSfaj/DJXmtWpC9EFMaE+fNu?=
 =?us-ascii?Q?KCszxdzTsa6r7PoN2b4DdKwPhlHV4H3i+ek8q2WXG7zLerzLIfXjflWOgRaT?=
 =?us-ascii?Q?c+MZPlkECPNurUrKR5a4SzpNXh1ndBTGmet3YwuwptrnhzhbB8bzA8wkgSEx?=
 =?us-ascii?Q?MiANL+jWKrY81nd7I9m0rPqV4qPoD/P9kYCs7zk6eY6F4Jm+QJOvkcwjGPVv?=
 =?us-ascii?Q?VSk3dwPbBZwuEC6rqH6w5qExyaQKBWZV9EUnaZbZorE9Grm1j43x9kNjqxWN?=
 =?us-ascii?Q?vg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: pg7+v47Xjo2MvHHGMPxg38Ts6+fzxXu6Bq67vCRFYZdUWUpsG0FuZDX1rIrklAnvGmYG9QD3NXfdeMBN0EFyeVX0gTjv5ehE0HCK5cbXzycOyGtBqThOigQhPtwyImgRlemDOY0Ky+a5uw9U7A0ZKSRW922ZZEeU7rPjMWTYmfMl+QvttkTwv9kPNEtLTYFWoTxgPeCpTDPb4xnTDs7cO512dAuP1TZkhxuXH/WMPhHuDX3WZf690wu1SmLHvmUM1AoMn/X4eNKgPpZScstRLZ9cuCjRvngEcYzbWSoONvG2u7imu+WjefzvfUdt9+42kZJWRqziJ7kCuaUjBVkBII7tlvtm6x2on8PmOCi2r4lV68mW+/3qgJbIfIGWOaR0+HBgyncex/cn9t1Zkj/45oX9qHYvpw3uFPhA9icfaP8kaXo5L3+gl6JpjwmVgTRRcDS9x4ZKfHIrWDWc48DXSc5xB5NVYNvWZBEWdpT2zz+/AbTpxgfQhT9UYOzA+Y04J0Kj6y4xmBjJbFSCkeDfAxSx9C4eVBuT02GiweP+tsS7seazHYbN5Qg42NxG9G10Tn657XTQkkBIWVhjjf77DrVTavgBnlZ70wMu7cXtPwc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 79da7d8c-3c0c-4180-0bd6-08ddeeecda3f
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:32:00.4815
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: AscD2aAW8a9cz21BM40V1TePkIUdGskVvfng6CN7C7MxzO4cICSn4gHflqYyZBQqaVT+RKBYgQ972kKSYJ/mFg9k8REg4dg5JDh6ZMoGo4c=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB7298
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_05,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 spamscore=0 mlxscore=0
 mlxlogscore=999 adultscore=0 phishscore=0 bulkscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080153
X-Proofpoint-GUID: O2A5gcURinWGBTqCwWQVTQojFlqjAOh-
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MSBTYWx0ZWRfX82eWPmlq6j5h
 Ta8RqQC7Spw8vbOrtLg3EADzgaFyymyUpwu18MyjtcSPlEzZXCSCJczTAAZZA2N2dqr0eS7yxwX
 p3R5SZ3AxYociZUSqm/7abbYB+g2bnJAAd3dQhjzvJ1cMXDCR2qVWbUxIx8scuKX8Fr+p2GsNUb
 rfrJR2UxDjtUvJYHOa7QIDVHIbGyDldfkhuv0WMwyQVLRUueeWdUVk+TeFpSlWPhAOt4o2XhAAD
 kpV8Zr4W9KML3DOtgLL0gxb8id2r7z3CleB56fU+fTTmXnq6kMShru2IHu0V1Mfo5O3f7fZV0Vc
 69lxNYqjBUpm5U/rK36QV4WIncA7i71vg3FZxewVzMJVFjQvwd9eJtt7EOR51Tyi1Zez1yrR8LZ
 vsYnr2ga
X-Authority-Analysis: v=2.4 cv=Dp5W+H/+ c=1 sm=1 tr=0 ts=68bef6f9 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=s9zNRFAIneAoMknafZYA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: O2A5gcURinWGBTqCwWQVTQojFlqjAOh-
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=eIF+FjSE;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=SMMuI6pg;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 05:19:18PM +0200, David Hildenbrand wrote:
> On 08.09.25 13:10, Lorenzo Stoakes wrote:
> > Now we have the f_op->mmap_prepare() hook, having a static function called
> > __mmap_prepare() that has nothing to do with it is confusing, so rename the
> > function.
> >
> > Additionally rename __mmap_complete() to __mmap_epilogue(), as we intend to
> > provide a f_op->mmap_complete() callback.
>
> Isn't prologue the opposite of epilogue? :)

:) well indeed, the prologue comes _first_ and epilogue comes _last_. So we
rename the bit that comes first

>
> I guess I would just have done a
>
> __mmap_prepare -> __mmap_setup()

Sure will rename to __mmap_setup().

>
> and left the __mmap_complete() as is.

But we are adding a 'mmap_complete' hook :)'

I can think of another sensible name here then if I'm being too abstract here...

__mmap_finish() or something.

>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a8fe7ef8-07e5-45af-b930-ce5deda226d9%40lucifer.local.
