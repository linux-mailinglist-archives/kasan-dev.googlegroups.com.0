Return-Path: <kasan-dev+bncBD6LBUWO5UMBBWHT7LCQMGQEUIIC53A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B369B48B29
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 13:11:23 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-62180f9db58sf2346608eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 04:11:22 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757329881; cv=pass;
        d=google.com; s=arc-20240605;
        b=innmt7oGwpaohaIRe/WmRJoeQZtJjT9UCQbj9dbzYRKBFMmO1uNJtSLmOoo3x+zPTk
         D7mmmEkc7r9HlZzlEI77geuOr2hgiFC6chH4Lyo/ZZsxq+ltopXwC+09bsM6asJuihY9
         n/rvwrO5UDbyxOS3z6f1fYhYQC71mU4hu03kWDUfIy6KxX9AOTeWoJxhgl0mp8zfDFIA
         At5M2X6fBR94VkQio4kmdu3ez02t01cmKZOynh8rwiHWXjFVEIz4ZQtHpGHMhF3BEEjF
         OZ7wTxlI2n4u0pNp5XY9EMmErIZBDdKh4CO13TTKYeHhiNgZMZQK55CNH7Gon5yQuqkw
         t2qg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=tOfWsbPoDZT7p/0hCc33fWFr/d7kgrKxZ6JOiWXO/II=;
        fh=6nKAs5tHMKhXDpCrKbxuzWkDqzYDjfDLsM0vBPecP1U=;
        b=a65YZHb07apxEq1sm4GUGmimEaEKQTwMqiT9j0Lm0TLkTteTdkJPZe8qsC8sz1UyVm
         wY3RKPX0Na/GTcjW57NyYjTZhHlKLTEP7Kg0m0iY9pKmZG6/MOfgLmPOjOgnjdTDie4G
         rhFGMZuZ7fYmPhj8Q+HN3cHbXBU3+digtrGpDFYnlQVXCJJ/g76KSGXCR08NuRpKOfUH
         1tNqtFLeaGXS/J2mhL4k5bisgm3uA1H11uvRbwCb7d+MDjyUF2Swwu2cYCN1ThYUNNY5
         pJeCa+/F458Pere4GzbUmfBJ2ARIyOqvJSHohct7YE0re8iVXuiiv+0GlHprG84PHDYD
         38lA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=pTWjqNgl;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=e1AzVsJt;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757329881; x=1757934681; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tOfWsbPoDZT7p/0hCc33fWFr/d7kgrKxZ6JOiWXO/II=;
        b=LUUhgonIBPmgM7wMSNjxPzHTOK/MHjlqTgb7OHggatELGKOe2A3A9W3VsJpUT1w7+Q
         5i+28J7fvfRczyhFnA2rHmokcNaSoLUA5V+WtDEkMcXQnuTjKAmbRYC5++/UXLn7C/AI
         BP2DVg4prafei8+cg4K7sZYMabqgciwApAGpqtei6gFo+8erUeBpS4V536wR1wS+9MO/
         uhpebc3iPvVfjn/7q3Dnc8CVBWUJUXfBFMcA/EilpTXBvGO3S58M4zlbZ0dZ5uRZQZa+
         gVaGH8ioP5IWBy966ZCOVdsrZtFkTDhjxWoZfVsuBZdcjVaNGakrN00uPLk1ECB1mo/g
         dojQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757329881; x=1757934681;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tOfWsbPoDZT7p/0hCc33fWFr/d7kgrKxZ6JOiWXO/II=;
        b=TvYLXaXvWmklab5MKxILmA+wCK4hHUpawzgNtlUwSLlMjodrNrl38RDDS6rg0++wUY
         fdJqRAmXhMRpuKfBfGNeWgBByZ1g8XE3+pnrGlNfqvgbT0vOr5SGTHhZFyZtVoSzlPun
         7cSDFdquWgEX3TzUEEFhY+y3m95+KqsiBtDgTYY1Ol0jrbz7smVhct5dTNt40nskdCEp
         v57vfjclXs0a4WBrW1o+JeW+CgPnC71SrFFMOAlqdl4gWi45uH9/HLxXdFTxcGj2SJQG
         VXJcPkWBdhljk1eE2fZF/dFxKAFJwdBLLPtEDuKjXt61sqa37DTK+pHfqH76Z/gmDz5U
         iedQ==
X-Forwarded-Encrypted: i=3; AJvYcCUfF7Sr/O+r2jQxsvSgMEau7jDviQcrXQLrtESkgwYI2oVeVViVev2ohFDBMJquDmZxA0SIQQ==@lfdr.de
X-Gm-Message-State: AOJu0YwTgZjMVaZls524Qz3WAXd57zHy9nOqLPupodkf31SzUycAvoG4
	fbSUmfNe4iKzxYlWW7UKuDd+5ttHcemGzdA3mNUYMVX8a/9yo5UVIHte
X-Google-Smtp-Source: AGHT+IFselI58EL/aSB+cRjlL3t2pAQtdB5K0qNxWp4pz41GOG4Hne2ppMVHFbL3fRi0KaH1T56MMQ==
X-Received: by 2002:a05:6870:d610:b0:31d:8c7b:401d with SMTP id 586e51a60fabf-32265240bbemr3416009fac.46.1757329881250;
        Mon, 08 Sep 2025 04:11:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd73b+GJ06NVgo9//v5h5rkNNXAv96L+l0ieV919YJSbVg==
Received: by 2002:a05:6871:181:10b0:31d:642d:3aab with SMTP id
 586e51a60fabf-32126e748f7ls1443292fac.0.-pod-prod-08-us; Mon, 08 Sep 2025
 04:11:19 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVlitz12ZJHBvKrqr+pAsSvPzt3/m8ceqYcdM1nii/ssnQnKfVyjqqu/M5faffzHTAepDMne+v8IC8=@googlegroups.com
X-Received: by 2002:a05:6808:4449:b0:438:257d:6664 with SMTP id 5614622812f47-43b29a4a621mr3549065b6e.20.1757329879557;
        Mon, 08 Sep 2025 04:11:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757329879; cv=pass;
        d=google.com; s=arc-20240605;
        b=EYZFHjpU6BnnyKBZghmKkL5Z7MbDiz9ICa4dDfQjylRjqzTKDG9H4eUbLH0kcN/cka
         19LZlP06YcrqcHbTovBJ9kc879SnTMBgKhrHo70ISIeg3GvUn7hHW9TC+tFqqJbtazA2
         hb9m6s6dOGIZUHfPpHscFu0/T7ha+Zs/Vo+8zxGNY3XsuM2ULRiKy+9Yk8h4bEefo70O
         o1I7qObVJwj0f2JvOSXH8qbs2IgZYMgzWCXgUhGWK6TaI3jnRKRKvSdZ7aHRPus0OrQK
         v7C8MGbY+Anc9calYjcaw+cQlpFcS41QLybAd85NqOe04HT09mKhbaxvzhm1oOm9YJeF
         70gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=nxkWlLtokqabHXHmPgkp4TNnmeCCeD6Mtfl16z2oXcc=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=WtOAz1Cv70v//VXfB/t3atk3y212MiQepkIAdGybT+oDJtg48eiFQQs1Nd3waECVti
         QLtzKTARJHfunnHNUS0Ipj1Q/iPb052cpr6ykoO2wb9XKRhej1x2045I4/gz/oH4cpyf
         7anoZmAnDi6VRI7ljmtJ9FnL/2u0WhNJwdwfZQ13wl8niDmfWaHACt9vB0M6wbjLRBPp
         NpLB+pF+OSb/8JLUy2Dcc5b6wA8ajnGZRIGCd0awRvE6hO28Vx8bkMYSRG89Qb5GtqPr
         5HEHQX1BfSt6WWhzBfiy/i7GN1ofCNQNxKvvLIGJPOslDCaP8sb5t3LrEwP9CTJJIq2O
         mJ5w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=pTWjqNgl;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=e1AzVsJt;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43a81beb9d7si201394b6e.5.2025.09.08.04.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 04:11:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588AnmpV003050;
	Mon, 8 Sep 2025 11:11:05 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491wqug0y7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:05 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5889pgY1033216;
	Mon, 8 Sep 2025 11:11:04 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12on2067.outbound.protection.outlook.com [40.107.244.67])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd91qp6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:04 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=cfgo9grdJ7Fl4noiOGY1Qf2JzdpQtR62DxvMOdHmLJGoRS+KWXmKUx7Vwgozg/WC/D7Qw3mijNCzBOy/15OUrSsrdnWyLVl3Qo3Re4Yb2s0772rSJyWJPE4mR9geigT8PX7zczt029hmkOoOXrbnbGg52x/QamrztZfgnyK53X2xKrHzI8h1g1nZ+HK4kIohu2webg6k37Zxhf4+RY+JtpG3wodejrmS3o1WuHVEEhlry6Hz/Pnekqk9NFMwb0EH0g1LkSxscZJhBiNzPOkBxOKrd0a4PRU5AGmyma04eyimR79CqZNYoQrschRWf11Oy+CZqCHkvZdGwbechy/mgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=nxkWlLtokqabHXHmPgkp4TNnmeCCeD6Mtfl16z2oXcc=;
 b=iPSl/QtqFakGlWViy5y2iKrbmvimr86G51HOL8ow6ZAf7YzlQitGfLU8UsV9ue7nECbWuK1k2QEqomLT3Fn5e9qND0sJPyQ2E++S0J1lM0s62NLjSTQuLivzFKJGVDZxaTWhV7Z9RLN5Yo3fKX9BpN+/eSh+qFWe6Ly2np9rLTflMFMhTrE47BW2BiTls+UE4NubHLVMLTxak8ddYd+rfL2onltcDVahZEEbQIWTpj76zHX9+m7xvUqDCa0HvRTE9fEEsPh4gHTpvmjp9GVhCrmx0j32bV7qxlP9ftrTpDCwl2PlD3VtgS/WaFYiXK1TuXIGez/VKJeF8DmrMDk8Yw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS7PR10MB7155.namprd10.prod.outlook.com (2603:10b6:8:e0::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 11:11:00 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 11:11:00 +0000
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
Subject: [PATCH 01/16] mm/shmem: update shmem to use mmap_prepare
Date: Mon,  8 Sep 2025 12:10:32 +0100
Message-ID: <2f84230f9087db1c62860c1a03a90416b8d7742e.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV3PEPF00002E6C.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:158:401::3a) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS7PR10MB7155:EE_
X-MS-Office365-Filtering-Correlation-Id: ccf6c11b-ef4b-4c70-d1f0-08ddeec86458
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?BR7ynvARSQMr1+FUu3jrob4/k1ne7Q5d1qYvOac3Zy45BbVlmfASMuLMULB6?=
 =?us-ascii?Q?jEPmF01wvkNyKCD2lCF5vGbsPgYfihivi+0+4LAFEQlZFslvpdhf/eAncS6N?=
 =?us-ascii?Q?JS6ydfJgIeulxaQfhaAFk2+miiBkEnY5y4ypGu02r1DBtPk/6+EhxvefhDdd?=
 =?us-ascii?Q?/gvfjkNpy73DQKGQKywtCPO4eqa0/jy1D8sMJE2wyQ0VuqrXo4reoXnejWY4?=
 =?us-ascii?Q?3bzBYf5eohKgLvliPOzeKQga962PQnfwJdf331PknEHyVu/ZL0vaElZ8ZWvJ?=
 =?us-ascii?Q?9NIr1JyBGSswAT8si9T2K13wuUJrWqFs8OeQle6BKnTGtkIM60I3Lus6eIoN?=
 =?us-ascii?Q?GAEcXLw/9Qi38ikImPvJcHowhkkQtaoMmf7SgKo/tq3pEO2MxPM9qoeqpCqh?=
 =?us-ascii?Q?evrw75YWwzQTMOutX/2cfJywvtF4cZ3N1twvMX+P4r/i3/zb4x6b0C/c+ONA?=
 =?us-ascii?Q?drhMGgFHZvJqrQd7J1GuDhhJLJmqqqq21pifDQDkOHmJqdnT5VvTLgRIcmAe?=
 =?us-ascii?Q?LyFWxhlfe38R+BbbepA6KQAE4Qm90Uml8XAy0ItxaT/HYk5+mPRwGIkthqds?=
 =?us-ascii?Q?Si7A9w+YDqyaykPHCVkLE6ZTmk++xnxDRWGJ9uHrnSBzhICLKvXNNPMWruav?=
 =?us-ascii?Q?irA9+4gmD0v9CiUEei231wzjao1xCpU/7o+jnEXIZpVRcEUE56mj+NupFiLv?=
 =?us-ascii?Q?yusI/hk0UTBwYxrJ5YY2lXftjiKKKU968VyNFw8N+r9uXE1yNmtgCAYEBMY3?=
 =?us-ascii?Q?fjUriEa3BwsMVy9tAGpLTX8mp7pQg7QWpTNnmbLUSVOjXz5jW5ki1y4+fklV?=
 =?us-ascii?Q?0rYUdYrtcRNH/RZvm3v1IFsR2E0vDDUrbbJAQJEyO77erpxUjx/Y2Te1Gtpj?=
 =?us-ascii?Q?qiv+t0qQ2a3aUQ5f0Y+X4KYbyb7RSOGK/2IEt23CM9uE+4jCF8VkYOUWFgsB?=
 =?us-ascii?Q?zhvDfkG2EsOZelaWaDNcIMsWtViG0UNf7AKX9DCuHSC3Uv83j8cDG94/E+WA?=
 =?us-ascii?Q?wp16JVjRykP5yJhMnzzC2V3uSd1lSLVboIqjdxXMDggTTZOJyrjPC5G8Vt0H?=
 =?us-ascii?Q?7E/Djan4bX+o8JGsO3kNuJ+RVYga3anj0BV6iZwjaigdw9RVyW94HLca8Mec?=
 =?us-ascii?Q?5hbyqa5YGvb2EztGNhesuH6gOhpnI+vvaWVNSR2nnNeB9hF1SiOISeBlJMnB?=
 =?us-ascii?Q?Qa+8EhCaCAbIVpScgMbH50U3ZTOUBOAWnSuiE/9icZ1ADEJvrJIsvVYRCfFl?=
 =?us-ascii?Q?op4BVXTZpZodiMaucc6PSlXU+BVh+8Xv8+FnikvFoLxOLsKAKxo5IppY14r1?=
 =?us-ascii?Q?aOGtvQoy1skP0iTJY0jtByu5g4W6yw2zdpN5LkoGvtk8tCSFCmoMOkHFEzlZ?=
 =?us-ascii?Q?LVdukttSxRGgkCgxcfpWz7tWand60cx+hcBtxqeF4ASbslCHgcJWMvIxgZiD?=
 =?us-ascii?Q?/SDgJ0ciqWo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Pja1TxKi7l6ZSWS4o7vPyxg5weYKmbz/b8u4IuWoOgBqlKzXB/qhD3tBWT4Y?=
 =?us-ascii?Q?lanQVFQABnTqh4rED3gT6z6xVIvkQjR1JPMmqT/06UllNvXrS458VkCQBwnp?=
 =?us-ascii?Q?Bb5N2TfuRxFi/CFmZbShC/IdHm8lPLSax9BAqJPkTelMcPsVJTefoNeBOaT2?=
 =?us-ascii?Q?5ab3E817FWfwXSxUduJYHIvb2CY0YBZMxAYM2kcHWrIPtq6Q++sK4nPquGNM?=
 =?us-ascii?Q?+2vH3Jm66pEKdRVYtIoVCNVekFD8jBea6Xe3CU1x7ya6rpKpVOzanj3ae0cp?=
 =?us-ascii?Q?iM2RtxSY/T4h+61kAwsXCqP7hz93KVE+wgDVmd3QkxRFtCEnmgrsFXuBquaN?=
 =?us-ascii?Q?ztZ92K9yDGIWBPafEUNizRDLmhaDpvI4EaYCKR4JnSUp6ObQMsCPSSb3OcR9?=
 =?us-ascii?Q?BRoaOUCeyZ/elQUvi5FQIlMTt22AEP5TWUUIJx06KR5QKQ5kqg/J6cB4VuVb?=
 =?us-ascii?Q?bcALeMwKLfekBb+w3fnOyYAB4AA4jwaJkoCpyAZ1EML5Wwk2ZSopUn+QSW7T?=
 =?us-ascii?Q?krwYyaXTwkxbzfC6PxMpo4RbP/NGDLtQKdo9VX8xG3oEv+6whzjWi7+9yK9/?=
 =?us-ascii?Q?kSdWoI8Q50a1nZ+VIlATMaPlWjqLqlHidf7ajeNUu84fUFZ+gymqPjCbZVoR?=
 =?us-ascii?Q?cXAwBATHusgDRWhsjVu+tL2ZESzCcxGuf04rhnmYlH4CeCEvffi24PQNfjxp?=
 =?us-ascii?Q?6JPLTJVRX6wD+6v8aq4cpYjOY4/dK7Mj5VU2kgp0FkKLWL/w1ZViQSmI7O1s?=
 =?us-ascii?Q?tpty5bS1JAZ+qp1Yv6uthCa9b3Xu/KVjTV64mOagTfIoNp52ud+YyovNGNxJ?=
 =?us-ascii?Q?LX+wdlvJsrfPBfx8jImXmSFEN0KALAtvX3bHyTDwdrW1lqU3ZMQKs+8YfPSe?=
 =?us-ascii?Q?jmCbiGCauCcEdFsXrQ5qBJK68VQIujd7YFN0rwO69iq2ArNczwKmJqsonylk?=
 =?us-ascii?Q?UIA3W1/gVWSBxAhx4ZRDFLTbWUCQ8A3yHOj34IOdNvgTM0rzs0lJR96CIj0p?=
 =?us-ascii?Q?IKpBiHOIyovhvl8FJ2uOT8GsKLb9b9EVd1HabkQAenZOYSNr3AvG7mXWB8xO?=
 =?us-ascii?Q?ulnRM+8ibj3GAX6hPa134qHhjvPfHwfnT837czi8f2BsdB5DldLyU+LmWLXq?=
 =?us-ascii?Q?QicgoUNcK+lVGtL1MVODCD/uY5i80oeYm7qJiA6bcBpPpNWrbKE267y3Xmas?=
 =?us-ascii?Q?j/YnPnBJM5HiR1zAxtDXqSrCHDrDjM8BjAlfKzKlCSz+l4Q4+Ve3ShzvPTCU?=
 =?us-ascii?Q?NJ0D3Em5VlRS6XkDJbiYYRbo+EZCnfyvoG0OnztrssoBfkzZHMiJUh/PhXWv?=
 =?us-ascii?Q?AJD4eJF1oeTIzUt1het1zaN8IXj8pvX0+MBMaGonuFnuozFXdnYZWJqM20OA?=
 =?us-ascii?Q?t1Rysf6VTRMKfbMSOoyzkM+XSiakvE9ojV/LvPI/bRBdQqu+Qpwhy23Lh4Qx?=
 =?us-ascii?Q?mwHnJ60YuzUYCCgZgZLFZvp+mHeJdblivWvIzd3jsVLiHvQq78L1iA/pt3Yf?=
 =?us-ascii?Q?pi7WblDNhaFssno1QkM6Wbtp0brapbdZ4JyDjy0U2uBf7hUkLvqOalALQf0N?=
 =?us-ascii?Q?TYVhZx3/v12+1EDGVjItiT2TrvOlAruCaXrvrAVs0cTIxtSFVOpyYKPyBHRs?=
 =?us-ascii?Q?Kw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: THxy0ycnOeEkIJeyRaJNGlYvg6iTHobA6f3is7vtimPZv6yt67XYizRB11Y0NfvFn4aQw7U2YWzKRSiNuUUvSt5w7ot+YjpE0TIPf9oZqtKdjfRDEPQr+F3n6pPs73w3CHPl9RRdpnD1/B6GjMs1mL/yFTB+nfEGlK0KAzE9DS8l4jV8PLncGwHAdd8H7tOutmD0rFiUCuQlLlCPZgqswzFQYY6lMkmUk1+c0v3qtlKuxBBRs38HBT1KN4thfo05dbuNdI+NQzgbSZaodvZkEpdfJ/rBC9ltwoe56YWYK/EoXekwDJVZse1hGtxMsYnhLBzQqOj3qqsvBIV7Ljo7ug4D7CXo62PRMN7H7rnriozWU3MPVpHiFxSm5TY/ScTz6hUfutSLo/2z1VcFzsIQw3MRwYqcYltG4al1oHHPv4fRWIseBWFKS4/WOg6dGdtfIpiFsMPCbnIPtBXPbVSPJPM2JZ8RffkY6qywWyiZSMSyUnNcteibv3mTdXH78eubqsTx75gGbLN2BadCm1SfZidTM4PPXtfkkEcqG0Epd1ZktmiZ+GuasggGzvAwIKDqfeh2IShcL8yjwinNzuBOc/hfnReidcOW/peDyV9qKS0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ccf6c11b-ef4b-4c70-d1f0-08ddeec86458
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 11:11:00.1571
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: F4AfiIVndAhCLSNE8/w2A5pKQ7FbsLnm+aYHKeILUUBLnfy8OBLkjsgVmjA6ihsz2GP7gAMlB11Ph+58xKuqhD7171iq9E66/OSqQuuPjgI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB7155
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 phishscore=0
 bulkscore=0 mlxlogscore=999 malwarescore=0 adultscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080113
X-Proofpoint-GUID: eMaQcRY5YrymYflPJmfuu1hOjJSP-law
X-Authority-Analysis: v=2.4 cv=Tu/mhCXh c=1 sm=1 tr=0 ts=68beb9c9 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=hKknKL_MvJZ0P6Ka4G4A:9
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDExMCBTYWx0ZWRfXxcWBAqawFrf+
 IoNIcEcIcu0gNxFvVGSK5XpxK3s70oeoYSini7hPlswT93wzMKb5SHHHK1wkVhSaiTJ2Mb0I6Bt
 Xsf1tyQkbDyTerflPV6DKx6kdNJqAC0ZbVJ+Z5OtH8l89mWDDsMXOFDru0j+2TX0i3GPh2VPZEw
 Ua4Ou70U9SvgoqBLyNXv8xNBBggaXkk2zzLUod9ZA0ZJCHWByvlMb43HwpolVR7WZ7dl76T16A0
 gNRaPvi7+or5zAI6ED6GAFOiztKbmcdrZpR+PJleqUi8JjYidmxAwokwXrUFx1fvQObhrKn6G4n
 E8TnqD6p8j0noa6xk41S5FKNdIEU+6hw5UKYK/ApqN+S8pTzaHk0hjF60FMncQJHl9zupnVTxt1
 1uB70jas
X-Proofpoint-ORIG-GUID: eMaQcRY5YrymYflPJmfuu1hOjJSP-law
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=pTWjqNgl;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=e1AzVsJt;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

This simply assigns the vm_ops so is easily updated - do so.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/shmem.c | 9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

diff --git a/mm/shmem.c b/mm/shmem.c
index 29e1eb690125..cfc33b99a23a 100644
--- a/mm/shmem.c
+++ b/mm/shmem.c
@@ -2950,16 +2950,17 @@ int shmem_lock(struct file *file, int lock, struct ucounts *ucounts)
 	return retval;
 }
 
-static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
+static int shmem_mmap_prepare(struct vm_area_desc *desc)
 {
+	struct file *file = desc->file;
 	struct inode *inode = file_inode(file);
 
 	file_accessed(file);
 	/* This is anonymous shared memory if it is unlinked at the time of mmap */
 	if (inode->i_nlink)
-		vma->vm_ops = &shmem_vm_ops;
+		desc->vm_ops = &shmem_vm_ops;
 	else
-		vma->vm_ops = &shmem_anon_vm_ops;
+		desc->vm_ops = &shmem_anon_vm_ops;
 	return 0;
 }
 
@@ -5229,7 +5230,7 @@ static const struct address_space_operations shmem_aops = {
 };
 
 static const struct file_operations shmem_file_operations = {
-	.mmap		= shmem_mmap,
+	.mmap_prepare	= shmem_mmap_prepare,
 	.open		= shmem_file_open,
 	.get_unmapped_area = shmem_get_unmapped_area,
 #ifdef CONFIG_TMPFS
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2f84230f9087db1c62860c1a03a90416b8d7742e.1757329751.git.lorenzo.stoakes%40oracle.com.
