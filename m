Return-Path: <kasan-dev+bncBD6LBUWO5UMBBD7FR7DAMGQEMY734GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 268FFB5490E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:14:42 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-7314497fa2fsf763107b3.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:14:42 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757672081; cv=pass;
        d=google.com; s=arc-20240605;
        b=YD8Xf2lqItF1zyjFK50KQfwmdDFWCHsRcIjyqkK4AZOGyIN6Rk0nTJuXUqTbyOmqBX
         o2DREmgXkiqY8m06/Eu1KiZ67xnM/Es1mhO6Ryz3JhkgrkBwyJWIyS4kspDP51d4JLqP
         tJJb56fha+rHgtIBqJDIYkzRwoBqEw6nDfd6Sm4czoVty+wHDWdfZVyDUeVrUYnuryvU
         3RQ62J/irP4CrFMpptioGu14TjhuAm6ZbqWQYnpsES2GKQ2oo6/2YtcgrYvq9V0yOQ39
         xLsHNyYM9e4RU1x19jQaeq1vXpY8tHSaoM2zGr3ZJIGz9AIG3IpPPBc9J3w+qOnxLGmK
         A8qA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=13bdKgky+TVvf7FMNmEVsda0BRt76zHjSWJUMCjEZBg=;
        fh=RveiFDwvjHmilSdG7zLDQiKCjqBlcc1grrlrFLQTdNA=;
        b=Ft2Rj8BxsgzE1rONsq8vuSemUfTETZCAUyCo9fOP3GlBgdQHsW2y8JMFrM0jRV7lrb
         YW9AKcp82cmr0+lEI+kzyIPdOQ/6M/JrZYVoH/ojWiZSAha8qvJFBu7+nuXwiBDC+ZmV
         8minqFydY8Jp5YoVHsOVAssFQEXXPrMjDPJBgQehy7228x42ttxDd0EV8/qqwqPggJ4J
         Y7H6ymXXhYwMal+cMrN9scqnwTVJ4b2zK30J86IfuwZ4Tm6bV+Fwu88yMyv+OfNetX0D
         mtmqQEMnFJjzEqsz+Yf6D8GQf7Pp2yJ4sOVgswATSvzc2cydMKiANra2IqjcYuWZay6Y
         44bQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=bqpqcsir;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=kLoRIS49;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672081; x=1758276881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=13bdKgky+TVvf7FMNmEVsda0BRt76zHjSWJUMCjEZBg=;
        b=PsV1qDo0RJoWQrEO7NaLuZFgJQ0W6i51ukSghs4KToK13YXIYK3s9hHLoWEdE2rSrx
         nE/rfuQC6zMjuULyGRF2DMBUJ/VD3A6jxQaxeECSv5EzV7mQ3AeBcs9CZbS8XT2Uo4w6
         /mkY1NdqU658/Nff2Nrbt7QPpOPoylDB1IwVio9QVWNBRF8hqCxp0H2vOU63//QBRtJM
         rQgrJAC3fS6VIbW7y23vGE+2oQ7qWAIW9tVQ/OXYxNo4HP8lsies6uSCWiFjFtW0oFJJ
         8y9HHvKC/CHH0CCODRtcCiG4D3VpwtBQUYsTPpNL1r1j4cCxcikLY/knAgY08P39U3g3
         WndQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672081; x=1758276881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=13bdKgky+TVvf7FMNmEVsda0BRt76zHjSWJUMCjEZBg=;
        b=JWnvKaHpAsyeXjf9A635FEN9jn8/RO8TUujQRcl3qZ4rf3yxZPkJ8dafgUCoQr9cPc
         8Rw9rAGHqEQ68QIfpJM8rU1/+NNM+O0l8jbmWJslp89loaUYNLNA/KuJYz7yrv3WjYqp
         uAuXh6hEBXRgp8w3JS4TTKrqU48r/UuDD03ULFAhqoIhsBE8AxHPyBhHv5tKP23tLYmX
         N3A4kFY4oJwOTdRIn9Ucz7zxS136cohsj8mv+51eZXpIeJtYdEMfBw1cNXF0FOeYykwU
         G74nXvpqsjR5vuAxnn/n4IPFE453MK9dLMndiKfjFUx5W2s7vnNEF0NRZUDAM2nMCAvo
         w6+g==
X-Forwarded-Encrypted: i=3; AJvYcCUe9kSH1hpVF6up0k7S6+jX/6QN6wpNKO90uez3tI2kzztpQFJp0CF9mKD2WyRC1Add7uH8vQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw6scqsNhMJ9TYCLD0faUvlsrN1B4eQYHqWHp5RtBmTHhHBm2Oj
	hHOmKNjoTfEW6ZXqkSHnkUQyYynlfvtkdkGkPTC6a+hHdf/CEFCmpXs5
X-Google-Smtp-Source: AGHT+IG80u6B8XV+M7eUwEHAyP22voGuxkYwwVBWIcGKRPPh5FIa4mbmoUXVOVeadnW0hqNFghSYLA==
X-Received: by 2002:a05:6902:4787:b0:e9f:bf6a:3108 with SMTP id 3f1490d57ef6-ea3d9c836d3mr1940173276.45.1757672080250;
        Fri, 12 Sep 2025 03:14:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd45uia/grVekBOOvkz6c+VaDjdYVIc2aCnE9VbnaAphPQ==
Received: by 2002:a25:4ac7:0:b0:ea3:ddb6:513b with SMTP id 3f1490d57ef6-ea3ddb658c5ls258204276.0.-pod-prod-08-us;
 Fri, 12 Sep 2025 03:14:39 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUZu+0+OuaNJ+XXEg+ktOg3z63VivXNt/WAaFNUHPaGOVQag5KTih2tJK5CoL8ghBubmdiOwVcE4Kw=@googlegroups.com
X-Received: by 2002:a05:690c:b86:b0:71f:b944:1013 with SMTP id 00721157ae682-730651d8aaamr19410847b3.46.1757672079055;
        Fri, 12 Sep 2025 03:14:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672079; cv=pass;
        d=google.com; s=arc-20240605;
        b=jR/cuOPogNaMdNXyjAbfaqlvz8v1f6ZIE3AsiHEo4slQ2NMZDgBqbu2FEsP7vnlgmr
         A8+KdAKAWFFhOsykdTY5ylDGktnNLFkobp5a/60TGWxNh1DHFxcWE4/GVw5ZJAZb4xq1
         hQ2rgzM+UEoinVtg34QgkgseVMj47D+peQk8bdSNOaLJ7ILcNs5Z6hI1xA3lF3qaPBFY
         RqedoyHA7tNCDsoxOFaXse7QYBXdNJX4ebvdDExMdAsbjV0kcDkJ6WMwVBZuRyPpAt7r
         jMtuwlAfUuiaLgH6JK3Ia23i7fpel8d7scseyaylNJx66ywDa88QdHp3j7ifdwTFNCPF
         tMWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=zdr1hPU6JA/zhG50uc+HHu8Adr5bmnNS6oki/jy1LgQ=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=DQ8pjNj0ZZ2k4K30o5y7Iq2wtxIYJSqQ+P0q0fzwjDvq0OFrPEptULGYHFt122D6Bn
         D9teWwlo97eTQs/M73wFuJOkX8gE7xOMK/0KvGPcvt90h7/1ZCPJ2LvYDVyuQD+gdGNo
         CoEDWGqd2Opc00AsCwQmMYarkDNrp5momn6842rouUb/zDyq6RFMC6CVJRMGU5bogEo5
         hRAZiGPcGLtn5cOYrykFpxMKbhSnY+dqjWRYr1qvgtJ86re9Wog7oFBPRugU+bMyQ+Mm
         66/T5kLVAxYHE6NDXG3u3oDQOCWjEc+ysKNMRmxoXvA2AqDFR6yORR9mjxzXofFuujvQ
         jPBA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=bqpqcsir;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=kLoRIS49;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-72f785c8398si1518407b3.2.2025.09.12.03.14.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:14:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58C1uY1u023133;
	Fri, 12 Sep 2025 10:14:23 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921pefyg8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:14:23 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58CA50ML025951;
	Fri, 12 Sep 2025 10:14:21 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011033.outbound.protection.outlook.com [52.101.62.33])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bddqg0t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:14:21 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=H6z8mGQFgHLXQytGuzpN49J4jmRC1XZFnEr7obyKzNNFDhW2OTJsX9+FiPZRmfeBXp8lhsXMp7ZtdMo58GyQPVJ7AOyKiwNyL+89rFVBvz7bIOf4wAdCQIdGNeSfKH30CBwGI8zjhkwxeASvKuQsx8Ngrgob75ToPcGiC/wqqEvuGwdBMfSxUmUBG1+YwJKcWLKwkYe8tC0siClIq6FIGTpoqJNU3skgJQWXMt++iPSXjSrbbgwT+EP9cgZb9n5TvoxxbZAPFlmik+U8J0fsxkAHxbm/Uz1IkSE3SZYr43/JYC/99j+KDhlK/OW55qBtfqzw7VLi5w20WOsQ/Q61Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=zdr1hPU6JA/zhG50uc+HHu8Adr5bmnNS6oki/jy1LgQ=;
 b=bMGBSeCpQ/r6tSVaUN7cjW4ri3ak0+y5VpXjA3uQ6BH8ihpLTn2LI3S1ymMBks+h+uDr/uvGVDJ9BqlREHE0SSQGVzY7MgcCYHCDgOa2QfnaAFEL3Rzg500LBdvvRbnqkgelbIo55DbJqUO1zsrxPx9t36syY1p43u61nyso4wsP6oJdzB2NnyrbAo6VWDi86xlZBJif93WfdPC8oCRn2BmQgKGr2HdO91KjdyDS9ZpKpmyMlAJzcjSEAEaICMJmjLXoLihxREjAKmi/mrL/thZhT5EBrCPYR8lYoILrg+XeIdurBReEe5M20xOsfvkdz4NRVmEMSKqvecMVUJhGMA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH0PR10MB4630.namprd10.prod.outlook.com (2603:10b6:510:33::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Fri, 12 Sep
 2025 10:14:18 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Fri, 12 Sep 2025
 10:14:18 +0000
Date: Fri, 12 Sep 2025 11:14:16 +0100
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
Subject: Re: [PATCH v2 15/16] fs/proc: update vmcore to use .proc_mmap_prepare
Message-ID: <26d584a9-86da-4286-b980-d45ecf6321d4@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <163fba3d7ec775ec3eb9a13bd641d3255e8ec96c.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <163fba3d7ec775ec3eb9a13bd641d3255e8ec96c.1757534913.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: LO4P123CA0070.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:153::21) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH0PR10MB4630:EE_
X-MS-Office365-Filtering-Correlation-Id: 993c8130-a3fb-4d68-9be1-08ddf1e5223a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?OHPSzSr/YWz4v8Cuqk2qBw0k9Rg0hM8vnCgwxch4hQex8YgkZ8mvEaJrfBae?=
 =?us-ascii?Q?bgDxcWFIp0wOV3fr8lOwp7CXHF4tZuMGO6Tjob4sutsEQ6fxFLtSYBsFu6Fs?=
 =?us-ascii?Q?ltbTHRkxJ3Xx5e/fvPNOFoK3XOyIWjo8RDZzBjNQlJmYd0YM7AYsZbQYKaTt?=
 =?us-ascii?Q?V3F5KfYkcgbyU20XDSl4NUnAPHXlhZ057jANg84ggbNsrH/kSO6syod1DAvE?=
 =?us-ascii?Q?JCB/VfyVUKXISWxnhbq6O3/3QD1fvFY52cPD4r1sFmAfJqMJBIoJZxuknDtb?=
 =?us-ascii?Q?1D5SNzRZrOGcrLWyZ1xdVLhkA02gxuOIjU0qQ/jzrju45wOHO+y1vReBxGDD?=
 =?us-ascii?Q?fZRkr2U7vmBgkls/Y2T1EOaKJbL2tKyz2j7X6Kd9hMNsrxnlotYJu9CtF670?=
 =?us-ascii?Q?i1PFGU6TPkSSNt4LdpgKCDo45NCeZtvI+i2g7oz3YVFKEPq3tVUBcvnvPS71?=
 =?us-ascii?Q?pgPb6mXLBoTAEeKW4YaJd7gPXxZ8L+2YRvLo0CLMvLD6MwUXPIG1nCkQmHIG?=
 =?us-ascii?Q?9KYzvOKb2b5mvYzPHhtijeadxPV30cEiAJraG96yOgpYviugsaZY1IV0yJDC?=
 =?us-ascii?Q?18LmVPQzB6n95ew8wOFykkxVmQMwwhd0L1foE2cS9lEcCsw0gkbNNSaml0Xq?=
 =?us-ascii?Q?yo//IM0RskXFypBZQHUZT46MEp/r8D6eRIs7BQY/P2VSASaFd6MPmEaLOqSu?=
 =?us-ascii?Q?Po5v5U9pEeeB2ze2RwVhnlNRxH7dn0KjGKjmr/Zv+jz6vVj6229W7P3zOaQ5?=
 =?us-ascii?Q?wnl2Ve4wf87juBK2q5S8PgZeJIDhYfN6GWNXtokfwgnmGJR9I6QP2WJEzXoQ?=
 =?us-ascii?Q?o5t+wG96K9lV1DFacX9T7kjrjwVGQlyc6UVDRAInuJCfx9PXGCz7OPqhZqhd?=
 =?us-ascii?Q?lDTIcweZmHZv+AKcAESLXNju0gf4Xc5LhdjKBn5ASBAGgCskd1MET/6efFIk?=
 =?us-ascii?Q?9I/cuiLDdh6VghBM4Ksc/panEdlCvHmglfFQAVqBLPuL4oPVDS0TuZvYnldP?=
 =?us-ascii?Q?7viEqBTLNDlf7LgdY+NW/+7jrAqoYKzt6sOvTa/A0UgeIwycGmYzwMpsygzW?=
 =?us-ascii?Q?HvQ5bunr9ewQ83CfJ2ftcuzui8OT2KC0WyTLbTPnfC5ekNkudrIRPQXmRO0o?=
 =?us-ascii?Q?FHNvWPY26kvjWn5N5tuwwWS8JFnMtZdubIySyMqA8M5NesUctl/VoHxUgm+J?=
 =?us-ascii?Q?kuwOy5IFNpYuvlwuxD2WT9O9oV2SYulLeBQJeEwJM5CKk58Y3eF5qBcGLEni?=
 =?us-ascii?Q?akuj+HEMQkYiG+PF/CscZ0tyjkXjMf3PRf0MReiFaw84yRsx02QBxs83K78N?=
 =?us-ascii?Q?yNQQn1VXwLFtG3MwDBu7grQ8nZQ+rM3MkvcSFlXnvwX7jbOcxCAhcsrH0geW?=
 =?us-ascii?Q?bzCPpVUJ6MRVxguDCPNTlyWBkE5VgtJa1B27IfrsAnPKgLh7YE0HGD4WJ0+f?=
 =?us-ascii?Q?+sxRVAGOwAI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?pctqzPbGODlOr8TocSUmgA5LvHZVLRPHZ/gQwm9v1FdOItIEPWMLN78789+F?=
 =?us-ascii?Q?ML/yqfLKC5XSmWG2GOFWHXcDAH0hpw4W+RcCA03FZamMZWnOcmVQG7kYjA9D?=
 =?us-ascii?Q?Yl1z8+wqXR2cAwbJsE2/fWNLZ5kBzkVoX5TTFeyqLDShGq4aZ+M1Avsk5MpR?=
 =?us-ascii?Q?3JpXUq73tiLqW3rngdx1d+17X/1STp30zOrItg1m5+ac3OKkqUGxn0C1tMfP?=
 =?us-ascii?Q?TKaBEvk8k/46/FTdmHZnokf8xOHNgHg8JaFM/qaRwJxKgSsrSFC1N69GZyO/?=
 =?us-ascii?Q?k56MGv4V7fW2/ZEVtnH5fksBgwqz0bUTkjRP2TDVshJznAXdTrilGP71wN6g?=
 =?us-ascii?Q?cEs58TzOcV41oG/56E3KG43EvfSDU2gpoTT9bOVgQx0v+ORa8E9B60ezMRVU?=
 =?us-ascii?Q?eKFS3/DWa6drrBE0PPj2Y6uZAAppVqjZR9WWYze72rktq3InGoDsYzko4ycK?=
 =?us-ascii?Q?QgW0b2vVM4Kp7969E6IET15Y0gI9YApT3UZmvKH53m2KaaVp93brnVNQVIw4?=
 =?us-ascii?Q?ck2qZtUoRLYVWv8sHmTHqN5BBolss/bxq+l9v/jpZoDUfOvZgSAGtyYMaCXu?=
 =?us-ascii?Q?m4cjm8qjET6uwRQA1bE1FJ/D57aui+5G7C8fdkPcs3+F06bDNgDBUwdWLcaX?=
 =?us-ascii?Q?3bJ6ZcVs3LS/lLt6ugD3vO3zc2BFjEvyrxYB8zF/YGuIpeJj+v06rtbbNCwc?=
 =?us-ascii?Q?PBO+Su0v9O/JTxzMkjSSFfVKd+8pXbH+b/Ltppl3dKvyZTJZDKwYJEd5ZV23?=
 =?us-ascii?Q?JmQIpGYr560KHKo5UOsdvDoVZObX5xe8IcVaWHTHvPA4OBnMbQ9O8TOeJtuy?=
 =?us-ascii?Q?3/3pASrCBqCRxE8s7vhQk+koX16QCkvxhhGpMO6zzYFCOP2Zjp5ivrvCgkMR?=
 =?us-ascii?Q?CGqdJYsU4cFeWCHQ1w6fBVE0iSWtnIIYwy3eaX8H9E0U73PzCujSuIfT6I/K?=
 =?us-ascii?Q?cW6NJXnJOPFjlnl0n/NmmhevbQHRf9y0kprbmatINiU5Dit5iTag8jnLVZTd?=
 =?us-ascii?Q?5tVk1AMuZkrWSTmA7Qhcb2vk+F2hb+Fkej0EkMrBKcOsEsjTuVcsj5QAV56v?=
 =?us-ascii?Q?opnz2DWJsUnI9QXMvPKATPIxILe5lPCoRfy2w2Inw07rSl+BZKzrxSk+i1GC?=
 =?us-ascii?Q?VsEcJn9PrJ5v57Aru68bmDH9bFmtY67jXpJ6zQuw1PUSdsJOvFGBB+z3oBSo?=
 =?us-ascii?Q?zlLP7FLMjron+ic5VSy6xAzs8E0Q6uXg9hY0mO1hTzmS1QHT+qEX/PGBvbE3?=
 =?us-ascii?Q?MtrOwjlMTxR4CtN3ej4cFgD5La1JkXjcfsIabk69CibMgMpc4TL/7ahOkmAI?=
 =?us-ascii?Q?Zm371z8odxoxRQ5p4FUVsZrfqYGjvmFNil1pCN5K9lN4qPrh72O8BenrkuW8?=
 =?us-ascii?Q?gVK4XKkT1wZQiDDPsCOgeB5a2g+Ia2+3w+x22fAd5/aGNSgnhPfOGiS8lO8f?=
 =?us-ascii?Q?vnWOJkY9TSCERfnpSQZgfQmHyZRPnjJ3Cko5zoy6k0Pybl5UZVUvpIk3FK4Y?=
 =?us-ascii?Q?HC5q35MoHqBsMnxqoVbkE4h69tZXaZIEc5oOhgRloNRBoC3V7DqSQqTqcgnn?=
 =?us-ascii?Q?J8x3gpedmUMvGzb1Bbbgz97gID3KXLOIk+vMlg7yjV/bvhjbWmNPclk76SqT?=
 =?us-ascii?Q?cg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: E2LnCv9XrsHH7leTuGZ68v5Wd9SVw6b9gaS0DtbG8HP0dpKK8qyWx0gRiTFEhvtJ3RA5L2vbkDb52/m6M0QIFb7m3fRsH+ztlTBhl/WyMCvOqwFP5tn3q7PXKVIDUoLLWXEWg1tsUKOlcDCUXYMFhRDHATcbkb+Z7TeMwEyOeS8syrYk2N8NbZpVmizFkGaB/2kfMVuemNH3FmzEFSaXOcphXWzZet8aZs6EmfFs+VDT6eTs8NP7t+8Dct/lyQRDg1soR/GmSJxG5LUE4W65H/sdp0AvrqU3nShA28PIw2gjCzpvXEmVXAIt4nNNaFGYjY0tLdrcsGxUEqXbJi8OoMoL2qKPh8GsXRNtHy+GPjNqqXZt28mDlzqkhI+w1thRXKyLn4lIOKtwYm5QhwJ5SfwxoxAKySXhKmXQEw37G9BRwP9ZdtwKD9Ru9XdGjJo+vjpQAM0+nIdCW901a7zQwIJErYi9NIZFFXu2WGXyfkRN9QfM/N480DekI1Hh1y00bnUjkVale/F+zPueB8lYUsnYN+zi7HlNQOQgU6SVoXXm7pZ9vyb42Nn5aD9TcHll85Bq+FYpPDYlso8g7FefM4dXFcTIgjBI/dFePX7PkxU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 993c8130-a3fb-4d68-9be1-08ddf1e5223a
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Sep 2025 10:14:18.1244
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /N0jZubBhh+zDpboBXIXKqyrwmqN8zcDSOrwhTqXudt8itO/TWsCEjy8JnkLi5nCcF24Blx3U9xYD1nFxsN5MiAHs4cGuqA9zEt+TUmAv2Q=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB4630
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-12_03,2025-09-11_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 suspectscore=0
 mlxscore=0 adultscore=0 bulkscore=0 malwarescore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509120096
X-Proofpoint-GUID: TTO9fSkDZzVHAlryTATiZ0uBolnrm7fq
X-Proofpoint-ORIG-GUID: TTO9fSkDZzVHAlryTATiZ0uBolnrm7fq
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MiBTYWx0ZWRfX5MIg6YepPqx1
 vgokq57DZgdxdO43xoVXbVSXaKEIreFCRdsWNf2KS9+uwJ4PwzOB1zKDQnL9Plcl+02Q1rv4W8L
 Nr7uOzs8GNifVHFQDF8Yqfirmk5WwnrTyVGArszMH7A8eJFfneTb8lIKcQTCK2iYJ93RTQs9oSU
 TKunHwmbz/YzeKm7AGSvfOdwe8LRwgGATJ8P2E1EMMD9VFw+70PQb5vRApy2KIFyY6SKP4//kFD
 lOT4HBk89a/Ar2/8CrYGx7nspZHRthuZOQ+mmGGoVsCwX90Obkm5GBdEaLgzIzpSew7GQjlrH1m
 ltB2GG9iQh1CqQu0I09Ul0a5+lhnr7Kr++PBwWL30/ItlnbbpjzJVMvmY7kUCHXV9FdH460AJdv
 FEQa2VFy+1sRx/nzyEIVwImhbkzbOw==
X-Authority-Analysis: v=2.4 cv=b9Oy4sGx c=1 sm=1 tr=0 ts=68c3f27f b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=c34yhIT1r7kIJM1nUv8A:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13614
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=bqpqcsir;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=kLoRIS49;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Hi Andrew,

Can you apply the below fix-patch to address a trivial variable use warning,
thanks!

Cheers, Lorenzo

----8<----
From b9d0c3b39d97309bf572af443e2190bb20f6b976 Mon Sep 17 00:00:00 2001
From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Date: Fri, 12 Sep 2025 11:12:10 +0100
Subject: [PATCH] vmcore fix

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 fs/proc/vmcore.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/fs/proc/vmcore.c b/fs/proc/vmcore.c
index faf811ed9b15..028c8c904cbb 100644
--- a/fs/proc/vmcore.c
+++ b/fs/proc/vmcore.c
@@ -592,11 +592,10 @@ static int mmap_prepare_action_vmcore(struct vm_area_struct *vma)
 {
 	struct mmap_action action;
 	size_t size = vma->vm_end - vma->vm_start;
-	u64 start, end, len, tsz;
+	u64 start, len, tsz;
 	struct vmcore_range *m;

 	start = (u64)vma->vm_pgoff << PAGE_SHIFT;
-	end = start + size;
 	len = 0;

 	if (start < elfcorebuf_sz) {
--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/26d584a9-86da-4286-b980-d45ecf6321d4%40lucifer.local.
