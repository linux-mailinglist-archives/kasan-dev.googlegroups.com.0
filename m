Return-Path: <kasan-dev+bncBD6LBUWO5UMBBMXVZDDQMGQEAVWWFVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 04E03BE8A2C
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Oct 2025 14:46:45 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-651c9ae5b28sf164751eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Oct 2025 05:46:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760705203; cv=pass;
        d=google.com; s=arc-20240605;
        b=V3+j1vwvuUgeIGApvhMPbgTzLFserXKV8LDCuymrYM2SIIdeTdgN8Yq7PO4QbdoAKP
         yHbVrNlEEMbWhNUP5DXJBqjVGL+cR9WTOxGc0aTlyz5l6bqYVePcc1qnf+M88k0i5Qkq
         is8IL+zFfNDH4BaqPwSZYoEsvtn4fMarmCpDsgP7WXCyIdyapuiab+T+M5ITlNjqkt2k
         MkSsIWuxtkfxGAoHjj/DgfcuwA4WfWw1jon/tD9UNHwNQoKN4M6EWfHTvHL29o9Q2Zl/
         ASgZ4Ovb0w9jKIDs8FSO+nBWq7nzb/+jwFZpf7jzRS1zywCMb9frBmtHLOZKdjfbUcBa
         ghbw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=uxkBpTp5fFd+cM3RdDzrFx5BbqXTODIuqd2eeyp8Law=;
        fh=KlFOKAgIhgf5KfRRv0hr1gOM6sq5l7sXq6nwsyxYh9c=;
        b=DjMkLIjdEAhcrbBmk3BpWqua9qug59D2N2CtgRTzAfizFZ9ySLGxS7ToHqahlthikd
         W9die/Wv+qJNMrCebtig1mVNlA6hImmQIPpVSkAD/KEX3BPPCCYEo04ozBX4WtuXTfsk
         KxJCS69e2x0lNeyEs1AQFs1U9SuHRTUhrIypCurR5D8E8cMO5oRb0SqwZFT2rjQWLE2U
         Ap3/IsG13GZ0/9Hej44gnzj8kDviWSTwJSMdSpMx2vYLIHP+CScDl7ffq9qGEhHWXZXD
         3cvWP9Yx2LJV9ioTzoecuw7SlW9sFDZ0qDTVb+JF1OJIq4DJswgbFh3xUPMEK/eoIr+x
         styA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qw9hJogi;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=xqpcYlCD;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760705203; x=1761310003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=uxkBpTp5fFd+cM3RdDzrFx5BbqXTODIuqd2eeyp8Law=;
        b=gmTXltKsPKSLSuXmehdjOlfyea7rMGGQ2ovlmfSSZ+V0kyktvpix7aC6/g3FU0M9mL
         Nve8CrU2VGSGls8vjdX6PkxnJsvnRGzx7RyiAK1dyuptYG1zT03Trm1luRmy7DRKOQNP
         2jWQxCWmK+X3B8Mpd+64+X3qZ3YQw6/s8vfzjd7zAjnc3SYBz+WxES2e1Mbu0Gvh62o3
         8VcpAOsWJqtSINcWwPavNyJkONcVPpR68oO4irFBjphKj4rWjfeg9dC46ulVCiHCW2ml
         IU8nl6nArG6UuNK3oxCOogeY0DvVdOWOq/HRBQNoMwGBuTla9yHER7tOr0Gu2Nqv+0bH
         SmEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760705203; x=1761310003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uxkBpTp5fFd+cM3RdDzrFx5BbqXTODIuqd2eeyp8Law=;
        b=Znhodm0yqo/pebClAIHDaSnHCymoioXU6OXt1AM+GugUpQXnQQy/hUfRgrsgj0ADiT
         Ow2Q2M0FD4ImeAifXS2YQgXuBUkYTVYL+fJualYv/B0dp6w1vQIMTmCRJY7USI+oA3sr
         jxe+NMtpOK4Y9xxQbka+tKm/SQyqQJPyH3lTdyfc23qOGdhcsPLRNNpfdENCchpNWu7L
         OWKW6EsD0Nt4x8B7HzKPmkZew857d/G4ydD8JrIC4xYV9AnuFHIH82feWAu0zsRRADnP
         EblyCfnVYgUN92BSpb60gx7Pcomyd1lQ9XSmWyWwGWWANXcWdd5K6LU96udWxuwzb1b3
         mkOg==
X-Forwarded-Encrypted: i=3; AJvYcCUH5zEe0mmWratGlf7jMBRxF6dWmE+HX18mxtMMexXq/uzbjvUrLXzyG62A1D/zShcqpAlx3g==@lfdr.de
X-Gm-Message-State: AOJu0YwU6Jern8aGpqQvPAIn+5doP2RW3tEqlsUnGS8QyiMyMvkaCblf
	NDBaYsgfgfkA0ZJbaJA1ob+9vFMB+CYfqIkbBECIPjdP98hbTEoDxUra
X-Google-Smtp-Source: AGHT+IG8Uc6G63xU/sxIl56NE50upkpF2g1rb0sQaTRtfw8JW9yOo4UlQCqAuFjOAFEfzo37TGaB5g==
X-Received: by 2002:a05:6870:7021:b0:36e:74ab:54bc with SMTP id 586e51a60fabf-3c98d0af2f7mr1385583fac.26.1760705203117;
        Fri, 17 Oct 2025 05:46:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4cLmByvXD6YF+sk7AG8oFYRlIJA8/o5TjqwXs5Y530WA=="
Received: by 2002:a05:6870:5a8a:b0:34e:7f9a:dbf4 with SMTP id
 586e51a60fabf-3c9752d6acels396019fac.2.-pod-prod-06-us; Fri, 17 Oct 2025
 05:46:42 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVZeoLXxnE6+MCPCjRwvmLk4UzkorEgZR+8OqnYjU2xoOWD1ei08rCEq93smR8sPb1E15MZRhrXOiM=@googlegroups.com
X-Received: by 2002:a05:6870:71ce:b0:2e8:f5d6:2247 with SMTP id 586e51a60fabf-3c98d0af30cmr1682363fac.32.1760705202029;
        Fri, 17 Oct 2025 05:46:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760705202; cv=pass;
        d=google.com; s=arc-20240605;
        b=WVv/LsvnrPExbEuEdl8+xBgHotA3XW73OCZNb2Qs6eWThlLyfhm+r5G7V1bFYfaNgN
         a15Vh8chRzNojneZO+hLrTjRDWZp1gdCSdL4vH9OGAbXQcZ26c82EPKw3ROwPpRlI0zh
         6MmOv/BTayaqXo3pk4j4WKQDMvZxRAbr4pyoGYad8YUZUV8XG8IHkBXAHZbxKM2WwgHq
         K2LMfvY7Du3cSSoOiR+DOylST+bPoV2ZrOnbE9dA22SSEHdl9etaUZERNhWCn+8lyBN0
         QU5aGiLM9XHQKYI7xbZKvV0tRPiYuJfhiPcfUUWwR/Ajfz8LFug3rmDNZjSXTMHG56bi
         zGgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=oI061dAy8vsrxlC0Z0wPC3REZJnjXCHWEy6h0Lna4zs=;
        fh=8lNOV8uDr2VTmczN2n/RzalrcIupURSrGqhSN3ZqU3E=;
        b=iQvTpPICu9pnaoWXWXmR8+vEInrAbSPug2DrnXMf8CHfARn01bafXmvfxK3HsrViPt
         FXAH1kiReK4q0iDb3RPGRKRilIZh7XKXNcr5ZuQDskIBWa+SqBmHZVnu0it2nlpOxvA0
         9qv8AH0AL9XP6kaYzU0h8oC+h2SUnr9kN8cbQNujMyaoYaVHCmJr33OYuwYUpc4PTa7M
         IpuMAR4nQqap+NxDDwjRGmLPVv4MG9ujB32Dckymn7lE6VzCFMoT8yDqqWHzIkaRyZ09
         UM5Lu2IN4+l247APqK2C6PzNaPmJ24BbMBCSBXzAq1pVigvYJ8j+/DwvocVlKBuz8wBt
         +6iw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qw9hJogi;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=xqpcYlCD;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3c97ad631desi305079fac.4.2025.10.17.05.46.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Oct 2025 05:46:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59HCdZYZ019395;
	Fri, 17 Oct 2025 12:46:28 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49qe59jwaa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 17 Oct 2025 12:46:27 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59HCag8r000649;
	Fri, 17 Oct 2025 12:46:27 GMT
Received: from co1pr03cu002.outbound.protection.outlook.com (mail-westus2azon11010047.outbound.protection.outlook.com [52.101.46.47])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 49qdpd1ftt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 17 Oct 2025 12:46:26 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=o6yHbbY6DLxJVTAmOaPL0lSsud6KNTmo/dqjmGuKwwVHDkFpmzhyCcn5qdbcvY/5mB8SLePCCt3OmGq7bO7z0UsfevnBG17ikhZfZub2wJuV/vivDWzkqEo5af5r4ZRiFNuMoKwv3B6jgxqS+ipZeBHgq5qw7xp2bLAzRMX9MeIcGRlO+1D70mIV+BY0wp/GA9ch0LqAV1let/jhUGXYymWCAqwKge62PUXEtLsODIuCUKMuqfxZNS/4HL41NBZF83rod3GFPgJWFm1N5wTAU4h9edD+5YGhuY/diJGKkfgvnDYBzrH0BJnO3lanVklgF/UeAXtlpwMmfmiS94Fgrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=oI061dAy8vsrxlC0Z0wPC3REZJnjXCHWEy6h0Lna4zs=;
 b=NVnzlgvhrfGnEXlKYsNtLUQE/+YhIUtjEjilzFTH1lW7RWtzIeADq69PzCIqfRVZt8Qlc31DvPe/pEkzLranU9K3kuPuMqzYD4W6KVHZr4KyTJG4HrWJtr4YgCRmQTHWflh5O0pJJCqxLAMci5iMWgnvYjOLqs3TRV94eP8e08GL/0ow14Aqp6JfvwU/GJhc0idE6TrsiA/CQDSnNYUkE2aLQ7sx7n3ReDRdewe2wYVMKH6eVTq/DD2PZ19VfGxDhRInGrm0JNrHEtd9R59WfRcigiLYooQBnznWs4gLYdnCNQE0aW/pshrfzhqEM8ISidjB9LLhfLAioSGS/igorA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CYYPR10MB7627.namprd10.prod.outlook.com (2603:10b6:930:be::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.10; Fri, 17 Oct
 2025 12:46:23 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.011; Fri, 17 Oct 2025
 12:46:23 +0000
Date: Fri, 17 Oct 2025 13:46:20 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sumanth Korikkar <sumanthk@linux.ibm.com>
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
        iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>,
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 11/14] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-ID: <c64e017a-5219-4382-bba9-d24310ad2c21@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <e5532a0aff1991a1b5435dcb358b7d35abc80f3b.1758135681.git.lorenzo.stoakes@oracle.com>
 <aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
 <20250923141704.90fba5bdf8c790e0496e6ac1@linux-foundation.org>
 <aPI2SZ5rFgZVT-I8@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aPI2SZ5rFgZVT-I8@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
X-ClientProxiedBy: LO2P265CA0149.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:9::17) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CYYPR10MB7627:EE_
X-MS-Office365-Filtering-Correlation-Id: 4e644385-67e4-40c3-db52-08de0d7b2dab
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?QPLeEIcJ/w59HVFnCTEmNLMUIwdU5nhIfjMZH7IyCC464BQ2EmzZ8h6HCZwx?=
 =?us-ascii?Q?ZQcPhNWDSvIWr0uuVwnO6YN3XGzmYuAbtSyakg0SfsyMM8erwgTYCqCHUu2g?=
 =?us-ascii?Q?E0wwjZXVRU6KhguU/Bm2hEvYDx7OsLqfOhqeq3igTcG1oLBOVBQY2Shq/1XA?=
 =?us-ascii?Q?6OcZKPWI17ch7uTlRjull11omF/iw3L/dit8gduJY/+fPDIrHWBKhaWJMQSP?=
 =?us-ascii?Q?fS8lUAbf1pM5VtQQf58gZW9DV5YReEGrpy/aH60WlLeTggBCzILJrWeA/k4Y?=
 =?us-ascii?Q?vRh+O7rxb7YMvKa3LfhjdyLFNNfWHHuqXexjDS4lZvRPsPzAiIOebGa5utVz?=
 =?us-ascii?Q?nssfIcpZUbday1FH2MPn22zJk5xDkx7C254i58QP1tzNsAU+c1DNckIiDHBR?=
 =?us-ascii?Q?Mt3oQl6pT1JpSQBZWhcAn1gj4tcFBG7b1ZtFgICII0HMyjDHMUB40YTgI+9Y?=
 =?us-ascii?Q?wczQusQwwUNGg8UdgLy1qAqCCgQVlBQlKmAi/V2VATGgzFSPfeKB5SDg66J7?=
 =?us-ascii?Q?tm/6Yx6MgcMWwqT0gT2Irip05m5rkLX9mkyflGuR7kaT0gbR4rb9lxquGToX?=
 =?us-ascii?Q?GSddsciv2cCf0i9iLfwP2/2wuSwDIV7uXA8+ivK2DLmMIexIkeKh/BiI3bZl?=
 =?us-ascii?Q?UWTvO1GBg8zXR3mUL9OW9/MOIiFX11I72eKqr2Xtk8np8Cl4mGeqV8x/0wpb?=
 =?us-ascii?Q?2UC3+8gvTuXjt1G1Jx6nCptXV4d1BnsWZzEGaYQETRJqfwxJYSy1Ky0M5dbA?=
 =?us-ascii?Q?rExdemD5X39GaNyEoPsga+q8UIZHmDCA+tGdMJEijg/EXQLnLbxjSTHzT4ZJ?=
 =?us-ascii?Q?+svYIh3HJ35mgpTB1yJVI23qEMDy3GxXnuKEWnQuYMofnB9c+q3N9eQFnr/6?=
 =?us-ascii?Q?3le56jFz9vHACRMyOMfRUE7sSt3ede0JxaGDYSqYGCA3YxdouTbYmybVzSGQ?=
 =?us-ascii?Q?aOHaN/LsyJx5BzXu8LVhWxPJMxWEiOP4c8zsvUbCMX0L76neXyy0VWDDWEYN?=
 =?us-ascii?Q?S0IaTZwvREmzfLP1YOMDCvgGlAIV50fM+csbz7uTmpwGGprb8X//2DwQU5Yf?=
 =?us-ascii?Q?kha6rxm6wtjfQpYQhccjT4RDMQhrlyzeGk3M1DoiUe5/DKMLn83Rv+PY2j65?=
 =?us-ascii?Q?2z0Ek62D1/RqOISu+jsofJfzXbnZr01fOhDbjjS6Fp1c27WTTZh9sBhFibf7?=
 =?us-ascii?Q?Sx13g62oEbaa+Xzb2SGxN82SAYhZiJlN26BQa2dpcHxpeIK/dqTSPDDNsYSj?=
 =?us-ascii?Q?1jCWeb91N9N+8d6JD3MB5gaIuNq4LCYw6/XXXpLg0nASqow+unX4hwoZGrn+?=
 =?us-ascii?Q?E7TtSfNJj/hiGpxJlxKEs74MR5slhPy5+UWc2OEuWEBPQ7FTs8GsXGyOgpWd?=
 =?us-ascii?Q?aiGOcdtcbM6bUSFhpS9HPdE7uk6KkPLcFDhUUcRmZObUR7BOiAUzL6WPm9G9?=
 =?us-ascii?Q?YIyWlog8HPnpjn3ZFFp0qKAKzzmTK0VQ?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?H/w3MGCmG8RFh9h2aXw4RCdESHRsDE8VGfOXPQjXlTC12qyM1V/hxm19kzNJ?=
 =?us-ascii?Q?GxMTBeYtKgYLWntC2C217SIhs4gZYXRbyyU3uDt8FxMbXT+vTalloCnEdY3B?=
 =?us-ascii?Q?nQ+sENoUSn/FCHRQWszFO9m8NwUjxiVC+lKo5+Rftw6i1FqMBjsrcAx3eoKe?=
 =?us-ascii?Q?+qJCZISuVbKMsBahtAM+zbPwZOonGAiLgwgDNMiZgHi47FjNm0dC0+MSumEY?=
 =?us-ascii?Q?uPBLyv1tSqEjkpyOVxGhPUVRSsxGLirpOg2bUA9ooGmGyiC8p1D1q0TDadAi?=
 =?us-ascii?Q?fvfBS3yjjVxU2NAV78eye4cMtp/LlLnVnL4x5LzqTytBMwPVLRQuThb5La8S?=
 =?us-ascii?Q?BZzpyL5nCPElpa4FQ0GPblMcFT4zcmeTV1wB/Chxe5T680xbPo2O3cp4GZ6n?=
 =?us-ascii?Q?Mvq3F1yjNNAuz3GuxeYFQPURbEfKCGw6JaCv1H2wRlmSHREPKgtcFQ0apx16?=
 =?us-ascii?Q?5LwVIhcWr8IfPut0ozAQ+VqLVPuCp1ZmvAMTbU4R+kccBuE4wuBqEEDIpAP8?=
 =?us-ascii?Q?U4ADcRbYoDZdWDywSKZ+S6OcfRLPQK4H0OrvrxpfWQXWh0DDb3kIUs05RtgI?=
 =?us-ascii?Q?H+3IIIPqcRnIt2EGNqF0TIlWsfxf0EygecyZuYr8DVZn01b3g28p4Y0K3LAl?=
 =?us-ascii?Q?BROYvFsh4/phke9jv0b5tuwpZFMEFAlGDwD2W5kGGZ8XIQri9s2BG5ysOBO4?=
 =?us-ascii?Q?8TuX/wnonYcBF5cHnuwDJszMF7U00VMjGF9SWL04hWyBTOxNA22PhdqAvTGO?=
 =?us-ascii?Q?bkMlp9s+Hgugs5xYuEHx3gR83K62Y1hPC8g4spGWFSzmNwd2EYQMkcEz8J3e?=
 =?us-ascii?Q?mBs4Z5oIiXJr3jbHCBBPSwpDvta4WGQuS0rn3PVfdQiGePse2pGvdr1jQMoV?=
 =?us-ascii?Q?LPjMe5LmECVJ8YnSiljzVhX4Hk0QaYbznI7iSD7lkT+FpEjM6MJa11MbNBuR?=
 =?us-ascii?Q?VJSYfqT5M3hEae8K8X1loQREmOWrksd9WYdbW1HzMpVGF5leUsKnd0CuS7EM?=
 =?us-ascii?Q?JSwz/PPDGLGxhSjJBexCOsYPx+vF1Z+kGgJ/MowCdPf3ppFPS8PFpvmZjETv?=
 =?us-ascii?Q?4aUqyV+JcMFZn3+zPpnsS1DUriDvazcLPgJBoDEzLYil/hfCdHUbZDP5GCZ7?=
 =?us-ascii?Q?vJHstp8h7iyoE34S5eVJ7hbNM9yXozVM37Gs4Fu8wl5O2X/PpPX6wKfQvIPs?=
 =?us-ascii?Q?IWlOHiLh+V4JRc3SGG+ZZ+EA/61TDIvKi79I3lWGJLJjq8OkEgZeJXqVLD/i?=
 =?us-ascii?Q?K0NA+l7Y8qDNIMFaC6SUy4Bo1kQ3r52fTJ07YjCk6OIjCErBbG7FJWxvcVU/?=
 =?us-ascii?Q?TdCWP5sHm4B5Pm2XALHSB3Yj6nlI3ChiMsgPZn+4lgB+x6G6p7ox7/mwEU2g?=
 =?us-ascii?Q?LsCqpSkS6HR5C0NFxDbiZuLbgTFz8+bOgD8jqUFr6V1c7/OtWm7X7LOLvbZG?=
 =?us-ascii?Q?xeyZ6y7j76d11fuGOnP23pmGKtURg4PmLzGWDiYILZkpLiRhlguq8XbZu5BK?=
 =?us-ascii?Q?Eq6XgSULp5CZd3R6yGG+/Fq5xJtva6VeLI2DawW8KTQWr+dQpn7gI7hqblb+?=
 =?us-ascii?Q?WAXOgRUzRIxyAxycHXX66KNdu3GBZ6zR1JoYGRzJmj0J8zXqRWCnFtQOfJ5r?=
 =?us-ascii?Q?eQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: NCUDsCptfdl6NVzE+XRmAcfVB0TCO0kpXJIYms8adXUf22J0h7WZM4IIQd7nCVa1F70dSW1XQFFS4AAYF54RDH2F3aMWjcjcbahwaWKuOFaVO8N7AOo1W42VJaLM2K91sbRYV3Fl2Dke+PSfHAprFZF6wV98Mzuzz4mfzWBzFEPf5q1elBX9i4rYazjn1LsdPZYYPIdtpaA8/CxEK4qd9tgoNwxROINZji6a6T1obs7ArnN3seeZFVn65KgjLsWr/UGmKhr3M+R0smOhWExz+U24dH+tTsyew5TQ1vV50pCgs6MozIUgk+BcbH2jEACMHOX9ndzsi6ss27MIP44Mgw5LuIAtO1o0WlOo6f515vUCKwai+nz6QDrQT8RsiVmy5ZM1ebqHY3hYrXuTmOKIdP8124X0FpBYoXA8ASV/uoEuLithP7pJw5x8aujv2gOcrRUs7zETEwsOdhqBNvHJmiHUSHjJBwQPjxfYxpp3Gk+MczXRLdHqBCcrnUA/YjIBEr2DYazVyWKousL4/raMwtgmxhibM3sZoZwoprBgx2j/7ZjdfqhYUOktLnSqjqgWkt523qYg5SMtL8feCFCd+qG+y5F4cOZmlJNfc3SPG9M=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 4e644385-67e4-40c3-db52-08de0d7b2dab
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Oct 2025 12:46:23.2333
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: lyLZpbdgkkaBS3MV9WFDbMuMpa0JedZDiK/jFohQfYTWt+VxXKJUsZBh2gIbhpo1iV3p4pNO+fQcbUE206exI9rSpTuPe9vvF3+pqNs1fXo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CYYPR10MB7627
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-17_04,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0 mlxscore=0
 adultscore=0 phishscore=0 bulkscore=0 mlxlogscore=999 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510020000
 definitions=main-2510170094
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDExMDAxMCBTYWx0ZWRfX3CdVs5SExetr
 yYo6EN3KDVrGoeTEdYk5fuIcEIIn0CT6zD1IeIJhsnYZGyqOnxxbkOqcpu40PCqlO2a1oYhrpmp
 x+n53pSct9KOct8ZXC2VMx4n4NZUKpkQdrZSBAcTkXPN7nH9H4lXTt15raRoMUF1eNpCY692sr4
 JMMc34YULLv0Zh1J+HBTbZfh8qB1EbDkN7JtDOObIHRFaS3DuQZKtjRZ/ff0bgaRN4ZbtkzNdfM
 ZTnY3s4sxeeL8UsBO04vvO0aTNFT7qT/51swibZ//2a2O1pAtLzIPeoDWPvoHnKZ5NNav+Sem7s
 YEyc2mfgbHWRTULBj4vAvk21A0iVSAymDW8TQfyFIrKrBZ0fRc940Gw5b1MbCXb3YurPx4vsK13
 9GzrxUE6CRJORmob6d8Kijfw9C+W3A==
X-Authority-Analysis: v=2.4 cv=V7JwEOni c=1 sm=1 tr=0 ts=68f23aa3 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VnNF1IyMAAAA:8 a=eWYn1dIeHkTF74O058IA:9 a=CjuIK1q_8ugA:10
 a=UhEZJTgQB8St2RibIkdl:22 a=Z5ABNNGmrOfJ6cZ5bIyy:22 a=QOGEsqRv6VhmHaoFNykA:22
X-Proofpoint-ORIG-GUID: 0ATmMJrwdHoEuzfB9kMIKut0xlYxjzQs
X-Proofpoint-GUID: 0ATmMJrwdHoEuzfB9kMIKut0xlYxjzQs
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=qw9hJogi;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=xqpcYlCD;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Oct 17, 2025 at 02:27:53PM +0200, Sumanth Korikkar wrote:
> On Tue, Sep 23, 2025 at 02:17:04PM -0700, Andrew Morton wrote:
> > On Tue, 23 Sep 2025 13:52:09 +0200 Sumanth Korikkar <sumanthk@linux.ibm.com> wrote:
> >
> > > > --- a/fs/hugetlbfs/inode.c
> > > > +++ b/fs/hugetlbfs/inode.c
> > > > @@ -96,8 +96,15 @@ static const struct fs_parameter_spec hugetlb_fs_parameters[] = {
> > > >  #define PGOFF_LOFFT_MAX \
> > > >  	(((1UL << (PAGE_SHIFT + 1)) - 1) <<  (BITS_PER_LONG - (PAGE_SHIFT + 1)))
> > > >
> > > > -static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
> > > > +static int hugetlb_file_mmap_prepare_success(const struct vm_area_struct *vma)
> > > >  {
> > > > +	/* Unfortunate we have to reassign vma->vm_private_data. */
> > > > +	return hugetlb_vma_lock_alloc((struct vm_area_struct *)vma);
> > > > +}
> > >
> > > Hi Lorenzo,
> > >
> > > The following tests causes the kernel to enter a blocked state,
> > > suggesting an issue related to locking order. I was able to reproduce
> > > this behavior in certain test runs.
> >
> > Thanks.  I pulled this series out of mm.git's mm-stable branch, put it
> > back into mm-unstable.
>
> Hi all,
>
> The issue is reproducible again in linux-next with the following commit:
> 5fdb155933fa ("mm/hugetlbfs: update hugetlbfs to use mmap_prepare")

Andrew - I see this series in mm-unstable, not sure what it's doing there
as I need to rework this (when I get a chance, back from a 2 week vacation
and this week has been - difficult :)

Can we please drop this until I have a chance to respin?

Thanks, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c64e017a-5219-4382-bba9-d24310ad2c21%40lucifer.local.
