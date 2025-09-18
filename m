Return-Path: <kasan-dev+bncBD6LBUWO5UMBB7MZV7DAMGQE3LPPSIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id D1F10B83B4B
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 11:12:32 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-81312a26ea3sf155051385a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 02:12:32 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758186750; cv=pass;
        d=google.com; s=arc-20240605;
        b=BjDF+U3IsCzH0+sWRS54DvBm7pwa8ImMPSxGZ8qu2L76/8U8H1LgNJI/E0aVZv/jDK
         l7AF4kL9UYwnWTdTOraK8qsGuZKn7LAeHFsF7ErCy0tc7jD2vmsAV1Rkouxlsg6+8wZG
         16vcW5lnFo07t55u8DngAEz0Qu50ZuW9qqhJ9I2NkjAnCRm701FwSq3GmYAxtaNUoiES
         0GEDzI7kqXna22VhcjdI+jUs4csRMefQGweEIT1RRJ2UFYSUZurEqJoedU3QjxqFCUsm
         o03ESB9KTKfydcKCQSONSnofiFk4+SHFgEj5vKp7PVxusbqB6NlNM45+/eyfBTZ0nT3/
         5/yA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=I8B7uF/szAF3I3BRBEMqg5LEid9y+WIKLk+glrp72eM=;
        fh=FbNt95GFUzPhWrNNxSJHXbP8aJ6/aIK+34XC1/3kFhY=;
        b=Cus8pzkQcYgcfPgBHQbQtR1s86Unf5ZEzu1Z3fO448RiQcFJP6qs3QaBfFzTc8WYcE
         sHs7MwLJCK1e0fzTgtJp923UnRtV6BTqiooO75K0gjO3xijVtzp7oDmXy8/itsJP5eWG
         uZon6qh59RQkzVOF7Qez1sViy0tmsgXdARBe9V+r5N3OxwMySQclrBFT78EDT1tkOpWx
         xgZmV+rm3lVacLwZSMjvo39+AeK8pswfLzQAinQKMpKHtud95DNUl12PoSec+qaWhc9Q
         TH1bnOg/bIzG79rh3S1wPTWUeVq833guPz5ZqJGNXM0Yb4PGLMdz9GLZRpmqh1tu4bK7
         UQwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=NhJZ56zj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ica6ggx9;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758186750; x=1758791550; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=I8B7uF/szAF3I3BRBEMqg5LEid9y+WIKLk+glrp72eM=;
        b=YPE7tsT5yVIGTm9/X35L+++zkEOUibsgwlHPABIk0ApkDUcfn8nreXsKADUrmj8VaQ
         qiA7EAD3FdSgUudetxyJJYpE7K4RTloQDlvfZsLCvlIJYcL2/Ll+ZK9AG4ANAOMfrPUf
         WcSHiNLzAv+mZeqF4L5oO/ssttwaG3SJWoIeewAwL851llzbDg1BLpcPqufoVvAgrYXs
         F0z7pScKifJzPvHuJOZFOL7AhUG6xFi7+O93OlMKZlITchFggh02MacBT2gOWNoyAYx/
         ++qgeVhDlHFM/wZ2impMabfdje5f7tTuZF5/QW9AFjgrs13QiHQ47f9euDMZ7anJikbq
         QjkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758186750; x=1758791550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I8B7uF/szAF3I3BRBEMqg5LEid9y+WIKLk+glrp72eM=;
        b=gYHiBZFE2KimOhzEpIBGuS8SKQ7NO9TXCymzSQcYvOqdojhVqDrySVqgflLrPyorFc
         HQL00TtZkp/iXdyw4uoGsTybDOsNKyMf3Dfik6lguafTblaRcsCMx07ztVsklbROvXck
         ZxF5nfjZHMN1y0wfzJvdo1EQFYaUUGjxQuprp6rylZz0YW8+JT/a8xNcbSgIlT9LCf9w
         YbI2NPTd3SOBgOiE1prMfNql4dvwmB49ySq6aSi7wpXV50qfw/Y9sRY0VA8frYoODvuY
         FZHRwYLjW307b57iYFAGpO/iacUwgwPR3BNM86UiQuD4gbwN3GYuDEq3G0BRY4SAfKFe
         COVQ==
X-Forwarded-Encrypted: i=3; AJvYcCVy+twfd2qi3QdD6I5VlUtwkUhSyNU+p7K5QZly2rsUGBYOa/xBR3ylUH+LJfQBPrmyuk6kIQ==@lfdr.de
X-Gm-Message-State: AOJu0YwHVfEz/jbnsIvi/z28owcpa+OoSrjGZeQCnvCF0E4Qy7X0t35C
	2gnIHmZqoPiJFzLgBhKhZx7cRcMGi844AI+SVQ24UvBoIw7zfp5eJ8x9
X-Google-Smtp-Source: AGHT+IE5D3gpFlj3L/9Od+uB90wgneU70JO8biQEmgJlnSii7PU8bBM5HyujbraiJ2C/eYoyYmyLmw==
X-Received: by 2002:a05:620a:19a1:b0:829:e6ea:80e2 with SMTP id af79cd13be357-83111e2b9b6mr495751885a.80.1758186750154;
        Thu, 18 Sep 2025 02:12:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5DegAUTYrjT8wjwPq3d/xaRhfos8xDv0h/vdbcQkgTBw==
Received: by 2002:a05:622a:30b:b0:4b5:de61:2c8a with SMTP id
 d75a77b69052e-4be04c3a4c3ls8155001cf.1.-pod-prod-01-us; Thu, 18 Sep 2025
 02:12:29 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWKPIb0WS0ksTvMFoxuSSNgqxqDs3BYz2qk6LgNBhWHdyUIE56t7PlEOgaUdJrDEEpxFH48U7ephOE=@googlegroups.com
X-Received: by 2002:ac8:5cc1:0:b0:4b7:a8a1:3f2b with SMTP id d75a77b69052e-4ba6b9393efmr61999901cf.64.1758186749241;
        Thu, 18 Sep 2025 02:12:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758186749; cv=pass;
        d=google.com; s=arc-20240605;
        b=ereVOdOpuk0oZSoj2aGrywvJWhj820jGd3H8Om2cX0f9+0R6bp7/jNXXqVckXvMu9/
         2qUHBj1IlTiza6XWnGgh0Iv9zfhWU91OpxxcsMRtsGmqyV9E8ybyshMgXYM6ZHODv66A
         XU6A+Xp1RQWuwlm7t8qcYosZHeTcL3N7d4SOPcKMAuyTqMeS5IFZU48WyJEiA3WX8Ymr
         36rnXdzCnRIs4v5HqW2BM8yk+x0rcIBeZmI6UAePwTUcTcqcQgsGQWDgMziE2gq/Rh2f
         12wGlxJejXjUYDVEJlpHsqYAzisqaikXJ9WMAnrt1lCcEAl9XvB9YfvYMetipXG3FNf1
         n2uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=4XV/YSwwCubHadBNTVDiN9OAKiJyfI2V0Xa0jt+E6a8=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=FvWSfpm2gwwC1eD1n781Wuoe2KJ/uRntbyBN3e1hFLp1/AQ6pgAQs2Tg3PJ06Lw+fc
         qqEvd8ZIffnKfdaleERqIvR8yK411yveR7AF3GeGjgBs5USmxTBxc3j4brLqW6+c2z7C
         WOl3YTwq6cZsfgUMYS5a9J4gQ4O3fZAXEupMo7tPnzxwn9B7PwHjj09fHrRtw1KKFc9z
         0RZS98e0bDWLWJRP+LVj4brXmSwf0Mibimmt/RigmSEMBf3v28l385WgmMIoT3d/647E
         PFtZKvRVA7TfoYuTLRcQdBoF7LcMUfnL5iJGGq75n/pEQZJ/+ooOjZ7imV6bl2t53WLn
         LEKg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=NhJZ56zj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ica6ggx9;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-836260cccb2si7934185a.1.2025.09.18.02.12.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Sep 2025 02:12:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58I7ftMI002490;
	Thu, 18 Sep 2025 09:12:17 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx9319s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 09:12:17 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58I7uIMx033667;
	Thu, 18 Sep 2025 09:12:16 GMT
Received: from ch4pr04cu002.outbound.protection.outlook.com (mail-northcentralusazon11013014.outbound.protection.outlook.com [40.107.201.14])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2ets0t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 09:12:16 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RqfWpaEEvhLMQH3x6TMecUtPYmQyBMoMh5JZZWjUvebgcq47YWSfC9tXQ93akfei0Y0/+gTnaExgbKPNR5inhdYlf71+B6wv3lnbfBLf9XHtFfJA3j6CA+QD2HNJLA4Zb/IOj2uaxYB3n0Kw/VZXG0N06H5jbqoF7EEF6wSH3vaHlRNgj8V53W7H+YjxrMR+ax9ILTs0Ude7L4/BLpenQuhOw7DTh3RJqVw7eUsTHNjUEq23BUKfi0utfm1bGcizomYbz0AKYSMdMp6z9fVvx/SzfR+Qyj69esEVZSDBSxX8RQk037fcaO6V+k/+0DYaMgBjSE2qqTB0l5wVb5u5yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=4XV/YSwwCubHadBNTVDiN9OAKiJyfI2V0Xa0jt+E6a8=;
 b=e3UYAmcrxI4EN4Ku2oOg92w3a2f8arlQLEFmHl9wE62B+ofSE8CMZFrIOeVN0Htb2hXdSigOBbZv+Kf7C4n3pY2aFSJHVvCY9wK7Ypcx/jwlEZGv5m3tiONBl0NOFQI+cX/MzeICLwa+CRC46ySOqFoMqS9h2Nd3kQz+VFt1fE5s24RTy7/OgYi/tVnxlUQKOYxkj1UO0iM0GPc0Uh2vgE59MEIgg1dF4daw98zutOfZmOllrWANsF92oXWSUCJqdx05PTQGlY7vdw9/X36jMDooyt3I4w2QpmPeCCw7EatZM+wUNDS6WlszrPw+ZDuvQ+rpB31cdtjvRDe1NwD/6g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB5991.namprd10.prod.outlook.com (2603:10b6:8:b0::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Thu, 18 Sep
 2025 09:12:12 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9137.012; Thu, 18 Sep 2025
 09:12:12 +0000
Date: Thu, 18 Sep 2025 10:12:10 +0100
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
Subject: Re: [PATCH v4 08/14] mm: introduce io_remap_pfn_range_[prepare,
 complete]()
Message-ID: <2cf129c4-627b-4a78-9ec3-cf43c95cf17d@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <cb6c0222fefba19d4dddd2c9a35aa0b6d7ab3a6e.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cb6c0222fefba19d4dddd2c9a35aa0b6d7ab3a6e.1758135681.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: LO2P265CA0098.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:c::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB5991:EE_
X-MS-Office365-Filtering-Correlation-Id: 9dc0521a-b371-4771-5109-08ddf69373e8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?YPMUMS9SJ5G7Pl32cKc247A/E/8qeylpqC6U4AbOiXCOqtolfsHCGtquoqQl?=
 =?us-ascii?Q?SpYTxYCi94H6YmekVFHDurIPSyr9Al2pRKtBRJWgzNhWD5NVDzFxYQ5rP0q0?=
 =?us-ascii?Q?KiRDTXbq0s5rlfgc6PRlwVqAjNPltFwPGMcZUv0ol8U+GJHb7qkX2q+pPbok?=
 =?us-ascii?Q?1Gmok5RrnD8ch2czbuYSYo1BEcH69vXbm2f+4AXFaQgy3dhJZp8P48LvW3c+?=
 =?us-ascii?Q?fIzt4wQ7K95gogATNqdrxX3FJA8YOutfIUzBQIXQsMmioCabp+wyHqdCpF3o?=
 =?us-ascii?Q?IPh5ZeEVfiLtz634bzfwBmCEl1idtKwa+iO2Gbzd2nDvxRGJyhoTvr+6DouA?=
 =?us-ascii?Q?Ddgd4ZuIBX8gbaATMW3uwfLj3ZFWBWHREkdUaNGQ8qXEZ9PUnLK+l4X1QTKk?=
 =?us-ascii?Q?4w4TSsLuHI1wJS1g365rMrRq2uJnRIjfm/psFcQ7S6vo5Z7jzf2ZXFesC5/E?=
 =?us-ascii?Q?UUMHraVwCUX4nLXEFcpQbQWdPM3JTl3gSlAuaY3pQiIAfT2V1iwMc3WFZtAj?=
 =?us-ascii?Q?995TWmc3ORLi/Pr3JKBww0Vj5HZbLjTCgA3xUaEBWy2EDpp44CCYfko7Kbkl?=
 =?us-ascii?Q?VGTgIfg+foH1l4wLfMK5YtYggSfEd8oTCL9QJ+R8xmXFeoyHJtjXKkzJYEzl?=
 =?us-ascii?Q?Ryjo8FlIMGD69TPjhC9PInTVrOVPCXwavLwF7qGzTN5Yp7thkscQc7kItCK9?=
 =?us-ascii?Q?OVp97XLKot+LfloCUSkg3D2y3K+0myOlPOKE6R/fInMaUSh+cDedGboZGijB?=
 =?us-ascii?Q?wCL7tr+zJpGIITa1Hdglgy2R+SaRQAHYNYN+YbyWV3DvdBcnuxNVcF64+zZr?=
 =?us-ascii?Q?+5JV3bF/8jV/+PXKdf31bqegG0Vq7GDNYVzt+tsyS2P3dPUHs+bRBGCsSDv+?=
 =?us-ascii?Q?h+mvb1tqQ38Vcl8oLNUZijtM7eMEfCoiFXaatJUk5+PTACXCqQn8MsjSVX+4?=
 =?us-ascii?Q?G8UgVchJyc7mGD8bCRtT6Dahx0Xn5duUdaIHpOyKQFOqOiZM7ejFj2rfZF8Y?=
 =?us-ascii?Q?KDAvEMnJ/GVzvMATVXugGzYqZSWicv0Q0NSMpX11QLb//HcD3Mp4YYSH0uid?=
 =?us-ascii?Q?F0pO4wJ4nBczxJc+ajNS6kZGvhQA9ReB9KE6qeQBXAT+19WoE7CE4xCE/eci?=
 =?us-ascii?Q?ZU13OG7hLAe8H9DC4kCPnDvtsBgFHwLiW0WDoTx7WtMeyynKJWanm0pF8Q5J?=
 =?us-ascii?Q?OUq351i8opDKSbJIJhGFv4L6/lAQe+jiOaaOeEd9Hy0lsWFSQOXsknXNeIBd?=
 =?us-ascii?Q?1dL9lwTnZqsdOMA9UlZ/floAYe6pwD6QyO6cZAO3OL1vQcJoSUzjM8hfqwIW?=
 =?us-ascii?Q?bywRe4dvmlmt0r/9GkkXOCjpz0womlqsT81na7JxgCCXRRwaR73g4nxrUDBL?=
 =?us-ascii?Q?rW9PGPfTWN6bY+JQvI78KLmAjfpDVJjY69U08AcAFrEILT0WLtmIy+0fqLWR?=
 =?us-ascii?Q?ep8hraEs4vE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?J6z6vH2/B63KCzRf1oXGXILZVJP5WUtyH7dHiPn7/7TdbEikGCzBsdmUmPlN?=
 =?us-ascii?Q?eKJIRQsr/YlgqJ+mdx9tQJf/KR8TDwtw7rqp9y0g1cAKqpj2XSGyKUlR9Dop?=
 =?us-ascii?Q?RT2KtJ31IPE9QG/r9HodgZsESttHZW78pmt5Hfwa7ivawexQioCrYejvnH6A?=
 =?us-ascii?Q?kcxG0pD+AGHiPQCFXStsVYZwoi4j95t92iuMoKVYgEQv+tOVFGu+QRRERHTj?=
 =?us-ascii?Q?RxyRZzkfWngwVL5CSuEfpcJlmeFxy4NkpmxVNOuwggdS28fFs1zuAcWipwv4?=
 =?us-ascii?Q?ihTxatwUCmNj2XH2jNBeFEK80/Rx4oXyg488U89IR2J3HusK+Kw1XxWy0EUe?=
 =?us-ascii?Q?YPABIgti+Ea9ehhvMdxCz0rOxhhxy7eucx0bKUMtWYCcSVIWl/fNEU3r50aC?=
 =?us-ascii?Q?eCTL33NsjMybV45LPari0M8TMlS6aQGlUwsHb16WUgichCCOlVeEWPP+d9NE?=
 =?us-ascii?Q?xQFh7yQzPsxVTU1XNg13Oc1e9QwBzVMsOdQpGS77bHHRze/pqygE4a8NK/cC?=
 =?us-ascii?Q?mLY1ANTY5Sw1r2Hxougs3qK3Z/YNcci7MWddjAO5iGH8BgRW9mA1RWKJ2/RI?=
 =?us-ascii?Q?514RyMmVfjWmBYnB8W0g6ixzsS1XhIL3t+afcZ8GWy9BFsMABNpz0a4ZpR7u?=
 =?us-ascii?Q?lvFzWocQdbfgbaaFnS065qWab6U9hyI5sRqSmVrqBgrsWLIfh2L8sXQ370wU?=
 =?us-ascii?Q?fEbgs2N3Ch/svtSrKDrsNFzmpfk+HkoXKqUkbJnJsthqrCFZAE2FNK3WJJ3h?=
 =?us-ascii?Q?fIPagUDgQ8EpyG5b2AR03ftLwjbWd6V8XMskSHo3vEbC1nuhjg7Z1pCnwZZQ?=
 =?us-ascii?Q?Oc3VYNrgXAY60X/sfBnWSckikZZ7vT0NGkUF5YmEnoSKHYvt23k96fzw0akW?=
 =?us-ascii?Q?Kx+kl9n9YmYZcXZCJK3lhyAcvbErll0/ccmQuV+rmuemkccJXMEzbf7Zpbli?=
 =?us-ascii?Q?KdVWcd2QO1BCVl4/l+Wxw1ViOc5vffNGIknrXBHHXGcY4gQYHJbb3dgcFn/m?=
 =?us-ascii?Q?BrkuHwOib117JCUVIvcaDAee+o8dsHg0UQp9Ilma0P7RoB8ZvoJr3obP84Pz?=
 =?us-ascii?Q?7pspaS7W+c5hgdJGY7ypjiTfFa4A7KZnikEhw05PdHke0schWFqS6lBU90R2?=
 =?us-ascii?Q?khOjxOQk6GIdJNg6MGInj+bJc5w0AdZ7M7OI0A7bNWlpIlPjZpI449P81f8m?=
 =?us-ascii?Q?XpnTUfGLj0yRUka0/xBd9juSTlunImAaZcVGuPzP2HWayNhPplrjgkbaUbqx?=
 =?us-ascii?Q?RCHR1a+DqpNsKRrdj/vc47yzMlBPuw+idfmIBaeIIk5dlRRSAHz/XtQj9Src?=
 =?us-ascii?Q?Y7bsrHntvIXLBW0j9/62mmAq4M6FVLkQjV+UL0lLpC9KaJJffxHv/p3OmWn6?=
 =?us-ascii?Q?PL7NOKIjUybXqurk5iVo20Uvrh9lvp1L9EI9hrp6NcJ2N2Nh5uj1X7tungc4?=
 =?us-ascii?Q?bD4i/q1Rm0K/IYUs34L6/wQ0FbYH91YXPtrW9nWWl+Z7Cz+Byj5NreCio9Pd?=
 =?us-ascii?Q?23Ny6Gif9FlZAGz5zN284EMVxslTjOXWW2AevjYeSqOmQuKrrYNwK2wdStYt?=
 =?us-ascii?Q?PfJrnIxNGk/2JkjnXkZkOeNqGOGbdEYkhDQJSsm+7Vpng7r9MpfA4/KavyXn?=
 =?us-ascii?Q?sw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: CCS1W4tVWAmJqwsocAoUD+fGIc75iw4DqClI981kwcrRKfBBKOKPAxCbDWbT/eey/2xwJQ/x/wHW9/PJWRvfWOMneCtXSA8rbudIKDh39iJYjOswUdeAnhFRHIX+zZVzlCKg7myBKqcYtysZsUqYi8y/Z2uPcY9gJX6vHUHmxs1nNn0f5lnRzdgte3UMmUneqjOGpfi1syk9NM+IKjtX+4LzLRIqzqNb9vaAeYdFkI7Pe8JJ3ffWPCvoZvrriv1kV9yX19FtcjnRjRRk3+NoXCRFYysS755/jE1twXs0LgCKh3PMuQA4AgTyzVPOa59V4jLNae1QwYfAj3tL9T8ueAmwrKbsBXAXiA904UU2mzRhyPPz4VxwXobj98PjsFdYGZp/uvZgsPLpTnOPYqMbi8FE4647vPKh2Wt3JWUNQzkNHd1tsF6SMalB9QYTD+W9yFhUX7vYdhcS9yhyJcbDEnSBkO2y4ZiOdye5WSSgr9mlhgLzxv6RgsbbUbxGcKGyswk1pFjI9bRtEbTB1V1TjugOniwinNp3FFNlzPIjy3NTQ9/KI8aBcFNZiq1/rbiWefIuIfE7EEcBYkfBshERWEhX5WvuwSKiw4HuXjAJgH4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9dc0521a-b371-4771-5109-08ddf69373e8
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Sep 2025 09:12:12.2378
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: afi3v7PupA2QBjTL6eoy+Wzr0/5D2FEXlHbW5U6mPmxMeZY23T84+ewGkO41pU58tXW7PtNGAi/9ljmlZcQQluNRqdg3ZLLK4fG43mPi/fc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB5991
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-18_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0 adultscore=0
 mlxlogscore=999 spamscore=0 mlxscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509180084
X-Proofpoint-ORIG-GUID: pgT7gmKePjCDmEhmjYl2IC7c65Zz9pzK
X-Proofpoint-GUID: pgT7gmKePjCDmEhmjYl2IC7c65Zz9pzK
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfXwLsLGFo7YpyW
 EaJsatwWFgCQvvSttee3vou/Qt0R6PLeE/QgIGeY5C0HLCS45R1LpQ9NeLpEJb24iFeSYNn/VB1
 437wXbVN5ZTfvw+tOiCyDExryR5qyFADV6fkxscmYNwsRvENjVzOpzSuP5rAWV3w7EJRBLgyDdO
 nVaOS+JwDQ/7UwRF/k7iQANDUJYrq+kzHgUOlUI7vH0yIX874yGeEe9p8SJGtYsQ/epJ5yQU/qY
 q1rriUfHwBWpznlOIm6N8FhJRxnLnKf0Pp/2G5JxicGr+ZbR9+poWf0Rq0Dcx4XP/4/zwSw7H1z
 PjUUuSekU0GjKn067P/sdgItQJRdOEVnaTqRfW3Ncu8qwc0IGUESBgUH/9jgqrRGQsgI9shSa3s
 ytGofoab
X-Authority-Analysis: v=2.4 cv=N/QpF39B c=1 sm=1 tr=0 ts=68cbccf1 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=Qzu-K-EdHhc5Hhb8t48A:9
 a=CjuIK1q_8ugA:10
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=NhJZ56zj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ica6ggx9;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Hi Andrew,

Could you also apply the below, so we propagate the fact that we don't need
io_remap_pfn_range_prot()?

Cheers, Lorenzo

----8<----
From cc311eeb5b155601e3223797000f13e07b28bc30 Mon Sep 17 00:00:00 2001
From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Date: Thu, 18 Sep 2025 07:43:21 +0100
Subject: [PATCH] fixup io_remap_pfn_range_[prepare, complete]

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/internal.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/internal.h b/mm/internal.h
index 085e34f84bae..38607b2821d9 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -1670,7 +1670,7 @@ static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
 		pgprot_t orig_prot)
 {
 	const unsigned long pfn = io_remap_pfn_range_pfn(orig_pfn, size);
-	const pgprot_t prot = io_remap_pfn_range_prot(orig_prot);
+	const pgprot_t prot = pgprot_decrypted(orig_prot);

 	return remap_pfn_range_complete(vma, addr, pfn, size, prot);
 }
--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2cf129c4-627b-4a78-9ec3-cf43c95cf17d%40lucifer.local.
