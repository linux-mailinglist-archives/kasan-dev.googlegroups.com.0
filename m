Return-Path: <kasan-dev+bncBD6LBUWO5UMBBBM3V7DAMGQEN6QYDEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id EEF98B83B94
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 11:14:47 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-b522037281bsf537810a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 02:14:47 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758186886; cv=pass;
        d=google.com; s=arc-20240605;
        b=NBa4TbLZ8CmO8gv/HZs8KgkTl9YWPvLtTuDXU4J0eKFoZ6ty0hG/ydcjGp0rKJt6j9
         aYQQnjCydp8nF72csJ4PvAhjDh1FYGSAMRtYVl2y/ivkgK+Y0nuq253FwRbbxI5UQUxB
         F2oA9NtcsPXgK+/NbfifMdvjxtTSN6Q3e47eDKAgwvb2z2Teba7M69nNkjpMzCeavEfM
         JRngL6JgU+PyMbELmPHKvxcH6uMj9shTk6Pu775EmlrBc2fGf8GGU+0hIZab8PMlRndu
         0ERJ/fH4MDC4HmwBYWXMBk4TTCmqp6Emgp2InIXOfSSkpUw6qIHkYpwNSYq8dnGKAvQ4
         sRww==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=HlOE9XOxJ1cHWBh0+27VfAyg+jCW9BAJvNAOO5fd2Cs=;
        fh=ES07eoQV/lzcSYA3+CyvL7F0SO9480gNQoO2g1JLaJI=;
        b=Nu4u6i9HSHW+5cPLoINZyz3qmLSSqduTj0Nr7pWlC+4xtpko82TdRbTkvZrq/Oed8s
         N9n7PCNn4WNj78OPIFzZvvMnVvlUy3Z5nW54x6Tlx2Xaw1XS+WAhfOz6SsETGfmY7Qhs
         2ilmiBWAAOA1s9z+kx55wd7KO9J6NJ4CpI+8vBoaJmTJhy7mE5zqXHOtpDRVSRVQllyD
         hIbgAIrkzuM0Ut69utEqcvRu+/xub094Ky4535Ayhbf2LrB6Rl+41nkIZ12OQz3P6n4B
         WCmkjw4wOk/4UvroamUwveFX3N6tPFQ5gn0cKSsVfdIqh99J5QTLRB0TtMm3yuBSsH3O
         ksSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Y52N4+uY;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TIMLsb6W;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758186886; x=1758791686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HlOE9XOxJ1cHWBh0+27VfAyg+jCW9BAJvNAOO5fd2Cs=;
        b=g99tZ5gWI+BlU/sY4AaKovYketv/yyuXijgiy+q82rsXGTcXOnpLkWC4qM8HWAIA0N
         4Rkk46S9TzeUGsw3zVc0l10ty8TRfw1cb0n+NTL0LJORHX29Dy/XJJVy4Ch5k+6KLGQV
         73ugDu/UAg1AyRbr8FMDO5Uze5NfE+WaL0X9eB6GdyE35DEomwNLnXUnkqMdM8q/RQwB
         u/vlHgtjqGHM9M8R8xegr6eGvW+sb1NbQ4rAznyioLkM9luqd0K/S1AL7rzYPN6hlPoI
         4Ivyx5u8cqGEFx7/BGiWCpCvo55xdHj6TaiOryDZNwYYIx+ui+qzXlUbv/qiLbjiotzP
         Z59A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758186886; x=1758791686;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HlOE9XOxJ1cHWBh0+27VfAyg+jCW9BAJvNAOO5fd2Cs=;
        b=AjFyFBvvkcsqeKa3TjVchz1C1q5obVUMzRYd/tAfqeDmPvAC5zDnKyNYADgwPpBj0C
         kfihykWOdV5HaVWqDEEwsYD3E/y4V128yY/H3itZ8ibaWTosZ4va23U6pILrKALBJlxp
         Gf97AqBo8FiKd8PeRkKWOf0dcBGuiAGgUO3eNDvNsUxsjZVGMn85pS6dHjKZX+55j9/I
         I/c/1AyH16FmaKkOzbY71B4ZjmrRcCaYKMsi0V6hZuOQ0n8h15ciw2fJiBTUUKRcJPae
         9Gifs4TsCMYEVHcM3cPLrwR7/h8s3IAYNp1VIZYMhd4Apz3QrmQM+Ov+zH7Au/4bQIf2
         mQ7w==
X-Forwarded-Encrypted: i=3; AJvYcCVJOE8nfbArOeVr4x1mnDRn7wp1XwUEhW88ff6eZWMqKgxEXypDaFu2iJNojHfIA+3HGQ+N7w==@lfdr.de
X-Gm-Message-State: AOJu0Yx11TdXl7xpg/SaP1O4U72CYSeyOBXbRmdaWuqiUrSHcwFLYk0/
	wzh/dnrjc4sHXpIv0IPj2T5BkUgBbJMGEEm1q657AxpkQNDQeUHulwv8
X-Google-Smtp-Source: AGHT+IGKbTPQEOpxh9JuMM/da/eJBcHQshP0cfq6OQAIBjaDz8JLLk0wMKUpmEMGWYFrfu2TByyRtw==
X-Received: by 2002:a17:902:ef0f:b0:24c:965a:f97e with SMTP id d9443c01a7336-26811ba541dmr76191765ad.2.1758186885995;
        Thu, 18 Sep 2025 02:14:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7HqqrPaM/5iXLl6Chr3nhx+RKxz4vRLWKp7qTRv6qQSg==
Received: by 2002:a17:903:2586:b0:24a:ffe4:1ba6 with SMTP id
 d9443c01a7336-26984028622ls5826995ad.2.-pod-prod-05-us; Thu, 18 Sep 2025
 02:14:44 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWQ28Q65sCOa09qnvgN30lwOpEDbWN4zch8E7Dl32z+uw2cBj061QK8rEjFDSB+RgaATERb0WmEqxQ=@googlegroups.com
X-Received: by 2002:a17:902:e80d:b0:266:9c1a:6def with SMTP id d9443c01a7336-26810e0b1e9mr68346005ad.0.1758186884639;
        Thu, 18 Sep 2025 02:14:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758186884; cv=pass;
        d=google.com; s=arc-20240605;
        b=EsGNimlBw+8No1RN1p8BRwiqTA2UhZbbus1Stav/1n0+YYYmktnG+i7nzYt8pDHNY+
         Ttd2TZDJXO48RNVoJKeuM7Q+a96KWpwc061bkYWGcTrDThk+kGwhf4NHNp3OHkxPj290
         NES+nnvpzXIdBmcBFVH3LoXpGCmhOvju62xtJ0ywP+fYlw6O9R+aVhwYT+oOfecUbrbj
         4yb9AJ6KjYIx6QwDlss9v/C68VBc7jWC1NxgXA9pUIM8L1EHw9y9fgzbiaoLKtFvfWYS
         u6Pptr/9rcIabB/dxasV602GrkilfxQtq+3w2z3RMHmXF7xiTNZfKWbvCyULPI02WB24
         1zzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=1ZWnQKPBXFipVJycdc86MGYCQplUmlHAEcateV9m3K4=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=YuPw9n2GtXMF5eSOx+wRHNzqceq5vrZPPZB3FpeCn/NzewU0V0JXmYfmpDlu5KXMGk
         GI8V17dVJ4s5p6EQ1edX/I0r+GFRHE7i1ntOJUfVs0QMS55/rfMYzV35EESL9sxvMPzL
         TZ/pNHuNQs5N7ImCcJo6MFqhvCBVOr5sJDCfLlO1PO2rcXF/Tf36oqzyZz1ArrP2nSEt
         1hQQWDL2irMmu2vszXXBbbmPMSXb5qCztoRW2eyWeMmc8ZrhbQHDXwPir5YH7caSRnf/
         0M9NUrDjK6lrA4jGm8G4qA0jxHFWynpZM1UiJXwIrHEx2a9ecrw0f573J/8kBnZVPZRm
         S9Ug==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Y52N4+uY;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TIMLsb6W;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2698026ae41si702385ad.6.2025.09.18.02.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Sep 2025 02:14:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58I7gjFP019426;
	Thu, 18 Sep 2025 09:14:31 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx6k2gv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 09:14:30 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58I7Y9K2028755;
	Thu, 18 Sep 2025 09:14:29 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010023.outbound.protection.outlook.com [52.101.56.23])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2euku4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 09:14:29 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=kufxMYRMJmKNvxBF6/gKsBVWCzw7W6vBmb2xrNC3TdJRZKzmwCnVCHXDdVQQSfGB9uCgUA+Y2GUd39z8b6FjQIEMOofRl2XyqgHgja60DvVIPGfrGBshhgHv9O7C9CQIntLO8IUHsooUqUhd7SuHGu3RU/+iYiLOs4syJksedyRI38Tn3VS56Kb4ihGKSewGyVrIzqCRxI7uwlVgON+A1j6uyo5SxPzPxRnBasvTBhxRWTCjpcu9U6U4NU90sR7SBecY7prIZOwYNA7NrF/Z7uz7cSB/e2GLB3B7K6T4IXa3kGorLTxp0Oy7y6RGDVtCWC11Psd9NuXv/go2YIEPUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1ZWnQKPBXFipVJycdc86MGYCQplUmlHAEcateV9m3K4=;
 b=BaBoG3jDSts7LPL/D2lE79cjr3hFfmXqV7kJYmWmCZMVQJCN5hRturlmKWUm4aEXOUndxNZdHrlQX7FCcHXaYGk34udflAYQJOX+EzVVmikvcRh0DgVSRF4g+pwiOmYVzv3up1ZQLEdEQZBYJx4eV83kCJumaumDvkInGnKZA3edHq1NUw5d1oQjmR5wwS8CpnHgt4wKkxubpqyHgDXdWJpwY/ajZSP1G+2bNt5AjEEUaJd1OTD+/pOy7PEXzhXIk9rEi4lvJe4/ErWQnCGPCUOgrw7CCY1hyCnL0lmDdwcR1Ywgm9plQR/j5HZmrKgiUutc1qo0K12F4tVNMoyc1g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB5991.namprd10.prod.outlook.com (2603:10b6:8:b0::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Thu, 18 Sep
 2025 09:14:25 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9137.012; Thu, 18 Sep 2025
 09:14:25 +0000
Date: Thu, 18 Sep 2025 10:14:23 +0100
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
Subject: Re: [PATCH v4 09/14] mm: add ability to take further action in
 vm_area_desc
Message-ID: <20f1c97d-b958-474c-b3a1-8ea9a177e096@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <777c55010d2c94cc90913eb5aaeb703e912f99e0.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <777c55010d2c94cc90913eb5aaeb703e912f99e0.1758135681.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: LO4P123CA0456.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1aa::11) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB5991:EE_
X-MS-Office365-Filtering-Correlation-Id: 7e61236d-661a-4d75-6977-08ddf693c36a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?v2AdNP/olnugc10JNQJ0Cv5Ygb+NrabsIxLX2RWSLH6MH5bE7sRGmH7tfBQ3?=
 =?us-ascii?Q?GXzDvmLZz7VugxevlpeXFVqrNCV6XRtxu8A3a5dVCarEFP8wkBvvfo6z4G2t?=
 =?us-ascii?Q?xnObd/PCdS+llHiHgrb3vXL+2lhimjitWB0yxA42TodoEjbLIW4nFy42XYpP?=
 =?us-ascii?Q?EC9usY4s6YHwpUSqkrnnG9VoODbSxjIvZLsn4v3jA96P9FhkiaJWsgaa5RdS?=
 =?us-ascii?Q?pcLFrJNiFz3Dt+1t4dEKDZ4YlABXKSZzULqvzbuKSGiNI6WEJ1kyv2CLtr1Y?=
 =?us-ascii?Q?bOerX95gKpgSFlL4cXiBjk4DAOIDUe847BirfbO5IkJ48pDMB0/G1fiOG20o?=
 =?us-ascii?Q?9a83I22gvRQ77LjQVqBl8ikVSYEzaSepcmkz0gHeuT/lGXBlT5SjbpheI0rW?=
 =?us-ascii?Q?jBvQjwxfZGLZkkoRbhzp47FslXXxpoBp08P1DX6g0C8czbbUuMDJaAdsP+9C?=
 =?us-ascii?Q?yVFaGAeukMrmruVBjIkxAIg4qwT2lCHBz4lHjj6j1dgqwP9qmLskVuTk3p2b?=
 =?us-ascii?Q?Kz63jcNdcQBuyH1aVrSP25gdw//8Kquyqy9ol+w1Fa5RPPH9DIle9dY5r0k8?=
 =?us-ascii?Q?qxyWY4T2JXVP86niJsl3C9/WUTzpI/arjj+TAeTqN0Abn98knZQqXqFinQfH?=
 =?us-ascii?Q?QCm/w1/iGeJAhc32m0iUO0qgpVRDW3C5qfRYfFwk3ezvk+FD0D8EuHg69jGo?=
 =?us-ascii?Q?SBKa2hWZnJhJHo7nP5pKbVBcoX4QxlmgoDygkEaBMWyqJKsujkLlU1vVQS2b?=
 =?us-ascii?Q?6wZJ0C1EgM/DDA5Yv//XSPa4zF4XRXOKgSQv3CliUGoevFiSN/sZkqgGeu7R?=
 =?us-ascii?Q?HeRUZYLgIZSOKcuJU7XUYhp3xFLyrVVTPUSgiK+E6evee+7lsTNYV5cr5uGT?=
 =?us-ascii?Q?Cwcgitd4kSpqoUV/YhD3dpE/NHAdbFQC11tLQiC4xvHFBzfRRdrb2bwTrOm3?=
 =?us-ascii?Q?V9QwR7O6nhKXqvrkTJg+E0e7368Q0CpZ0uQxUoWkQ8NYjyMzxexZNrIhZlyN?=
 =?us-ascii?Q?t1ZxgZ8IMZnwrwAKAJKUKtnUAND4uIJgmx5GhYZFJbEzABe1uT0xfz6ykt+o?=
 =?us-ascii?Q?iaRPgezlVkAdI2TJjHDTunqM+0NMYE4w2kqYL7b5fGOwArmwd2nU5Nrhn4Wa?=
 =?us-ascii?Q?4kjJzPXTJkCVGB1ifCK62atbApyQijiyvTG9nYVboAwSRBEhmGbo6O7c0JNl?=
 =?us-ascii?Q?wC3YvMSL0aL3KUCNXUKSbdcRZWnblQVP+XEWCkjgiNAv0/zyR7N7PjOqnhm6?=
 =?us-ascii?Q?1Z3BC6Zi3H0KBWKvmFNkzPpAjVqAQkU+Bxvur3WecCEWwKs1sjTvzEAnGKua?=
 =?us-ascii?Q?KvHu4/1UE8jBwJjeS6bQsLSNIoPRiJaMv7Cf9fy0Rv9Xxek9xLfoTrlOITxa?=
 =?us-ascii?Q?SF2CEsI36fbey2UyAfowZY4E/BmkhUOGOoxXQ4p0HDUeHPjDog=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?XgmqFs4iailYvekmQzq65cMjCKFz/qU29Ez9iHty+aRKlI5wSs7oej9jWTnD?=
 =?us-ascii?Q?uzDFmx86O4orU1X8kn0Rct7PfUqkw6HKJ2C/z/9lUrLpAK1yXS89BkQ2gGCd?=
 =?us-ascii?Q?2S2VOhxKJCIsB6Jb8g7CWeIp6aflc2ByUF9X5HOsUxMeQNYl0ng4NEbsRsZP?=
 =?us-ascii?Q?jZ9nAlQ/p+GOSmCBKkB6FEXKftxAsC/EYNzhJ1CZlXymDRlPeDoKxsOCIWzs?=
 =?us-ascii?Q?/YViGcIdhk+Lc2haoxqMqkqUFwPBy+wcJTp6LYxmxP8Qdo3lX2ewT2VVXscp?=
 =?us-ascii?Q?ML3xSoNVJWvTo4A4J5Jmq8OsUN85WjEpcFi9oRKocJgRMeu1THBaEDI7HHW9?=
 =?us-ascii?Q?9NQRPcqwaA7ZxGenZL4sfjT3DXHRNOsOTJeU+mo2CYdFsjbVW+4SAb4YTLbl?=
 =?us-ascii?Q?5LPe7j8uT0OtJYB6iwTjnZTlnsWVLpgYheBT9LOEd5G35iAA7AJiQgA3vHW4?=
 =?us-ascii?Q?pkkhPPNgq6R7c4JLxUUwH9U1eDyLtUIaoml2LhvfGXEsZEvnUe4mPEELMPhP?=
 =?us-ascii?Q?k//nJHD1Ntt6eu+A13/FYNYYJPn/EbkwuKJQ5L2Nq4McgMoJmtJn7Qk2s2Zg?=
 =?us-ascii?Q?rveQf/Iu1ctvI2J9Lj3S+c3VKwaAm8zECHjF13qROPnNzZIjb6LjPbXkNAtx?=
 =?us-ascii?Q?hALkTM0xQjvQ1ASydavuu6Ey0f9rIiL9GWU0HVexEKj9DgaMZvHNHvnKxoDW?=
 =?us-ascii?Q?AyMqDvaWpTqJzy+7uZx9YAu3UFztdQUjJ+ekevK1rj6Mczr+wn6YLRHdNdF4?=
 =?us-ascii?Q?pn1DdmloejVFuQoqxkuvcRDTRf9n+Yuceis2SvSG+XOXgvJq/7omrQ9yrG5A?=
 =?us-ascii?Q?8RgWU3WA0Ic0ox9Q+Ya9dGD2Spj8ftGu6tLO53EBK9a3HtrlYWqYCL50gI1S?=
 =?us-ascii?Q?TqH3+goP36g0iXw9jlGKxp4/+Y3HkKRZCI9JOiOTuTytBF779AB6HUCB++RK?=
 =?us-ascii?Q?DqowB0XtDaEnVgw+zJ/7c21H/QDKoV/244fE9n+vZ6kwSpML/hnF3/efM4ef?=
 =?us-ascii?Q?f5iq5cC7yYOfT+7GA62kT8f+QC2M2LYaWwFu8S/uoei84NGN4T9/d/0RXhFt?=
 =?us-ascii?Q?YnjM+JK1DOPJC8enVQzqUUGEOlLqFmSvtyAvb89LwNRq/udhVtKQq+oRiABn?=
 =?us-ascii?Q?vLey5tZKdEMMnco6d2oiS2nQlCVWKpXJvprfq56DgxbPTK5Faq17ujOHL4TD?=
 =?us-ascii?Q?xb8D69cUObDimGu4iUwV6/pYrjFaIN0BMQY+kvURjuaUxuZtwsj6G+JnmRdX?=
 =?us-ascii?Q?jo82e/GHKRdmBmXha3Fe9/uEsDjVUMkzRf+68Q3eDidqAVM/ejFw4R0kKbSH?=
 =?us-ascii?Q?tM7d/i/XYTMZfGPYvARaIj900UQ0LIOj3xu7wFVei1ionOfg+TWh8qApJ85R?=
 =?us-ascii?Q?b36DiOIW0a8woB+bMaY5MXU2IFhnPjKfPK0zlQ0Q1bWoDC4M3wXTEu6hVhp3?=
 =?us-ascii?Q?3FtrnjWKIw2xtAA1IfrKB7yfzdjGCimdatl8J+8vlwvcjnTb0cgqt/XwkLuf?=
 =?us-ascii?Q?sq7TW0vKNCgXhwGQwLlGUhyMZne/J+xMYmiafnqdJE6qh5/cpKnXuTph1XN/?=
 =?us-ascii?Q?INM+k8D4/bTNpXol0SHRsPVNdG1XHY2I/LWQmigAZuPmzi6Zv2kqdyWNdQla?=
 =?us-ascii?Q?bg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: YWEgk+Xl3TYMx85Sva0GQjUkoPyWQCA1+I/HyXbWEj4znv/ZKRVlw0Ap3g+6Gc+lJ2Z1XKIjEZrKWtGf/h3G4Yjm7IrcPx8x+18xS8t62+G4NNtRMiSZdvyN0mGaH1XrCq4cKXkMAkZh39ySThKkCE+HEpqGQb+Baiz+Pxets5CtTPb28BOAFroQ8BwSebRYARkwXn7OEDXJctbOTmQ2U78AoI7jDbJZ4gdN26wUb72KIsw4uUz1jJARucrZosZFDQrLvVYoKycRfc1ViqPovj5amTrQaaSiDYFyacdcVS6HFQzevIyTkN9vvk5F39mdjUr5xncRbpuLYTwMrZQLW6LwiB1XPWELxEqsVbxgmwvDs72MbydTWNthBi91a/7ZY/KXnwZ0rNzQMICr7x2MyKXTDsTs+IhZnJWQc6xyw+DzihtTw5sITWKDfAgbiua6sKSVmOzsXIbMbGtRy+iis23QSOPsASHGCqXTfLwMs4qOiKIVwK9mW/AT1Or1nVB7ngEJD3PEBHZ3UMNl4vIbgjGCdupsRqx1yb3mAse8LtogeLIu1IBNnnTTQ4gGyoFQNUQKaJCie9Ghj8y3weQ0yPZe4x9S2ld2j5mT2bVX3/s=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7e61236d-661a-4d75-6977-08ddf693c36a
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Sep 2025 09:14:25.6266
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Twf7tp0S2QDNWlaAvzlH2yhH63u6wkCjGYc8QnrChh87qHQR5LzmcAZR52lBLv/kZ61qS6hoxK1BPRlXdcIN/mxYVQ88xsD5p7ShxILXj7w=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB5991
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-18_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 spamscore=0 phishscore=0
 bulkscore=0 mlxscore=0 suspectscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509180084
X-Authority-Analysis: v=2.4 cv=TqbmhCXh c=1 sm=1 tr=0 ts=68cbcd76 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=6GBqCms67bi5QGnjy7EA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: c1VH1OHWlz4HvKONPPdaIt_DmfqJboZ5
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX8p36igjenQnU
 0nDIDwy3IcEG7R0q/8rVlHsf4/QBzw8fBM+ufq+TpQuvO3xo0Cs3Nx5cbqBo+w0jaFLASQ2N5/N
 eez9ZMuCJrbPcp0ps6lh0Y22H6+5/G/Ufj8GZXng/dl7aIVQCg4iXmW9yAkUWtKmgbtJ3xuFK68
 ZppSAlr/xEFE65bu9Yl1py81r52hBfaGVMzVkO1b0bTcWFH1Ih068sWvisOcjFjWWge5ZBNAMkV
 mKhHcyCY8DMO5CL8AiARrp/kqJhLKjgQj1E14qzB6mKY7zYha3NZmF10COuFZW6lTIN5TdOSQk1
 6Fq76N4FraFf1IJb6JBFj7mNE3qtlTeF3LxE72al2HCWc6Xvv39dCSdxVhtToiy///6ZMXmiZEm
 zfL+8jzx
X-Proofpoint-ORIG-GUID: c1VH1OHWlz4HvKONPPdaIt_DmfqJboZ5
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Y52N4+uY;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=TIMLsb6W;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Finally could you apply the below, which has us return an error in case of
somebody implementing a buggy nommu action.

I also include a fix for the VMA unit tests where an enum declare was not
correctly propagated.

Cheers, Lorenzo

----8<----
From 17c8037bc3bfd5cdd52369dc6140d0fbbd03480d Mon Sep 17 00:00:00 2001
From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Date: Thu, 18 Sep 2025 08:08:31 +0100
Subject: [PATCH] fixup: return error on broken path, update vma_internal.h

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/util.c                        | 6 ++++--
 tools/testing/vma/vma_internal.h | 1 +
 2 files changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/util.c b/mm/util.c
index 0c1c68285675..30ed284bb819 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1385,17 +1385,19 @@ EXPORT_SYMBOL(mmap_action_prepare);
 int mmap_action_complete(struct mmap_action *action,
 			struct vm_area_struct *vma)
 {
+	int err = 0;
+
 	switch (action->type) {
 	case MMAP_NOTHING:
 		break;
 	case MMAP_REMAP_PFN:
 	case MMAP_IO_REMAP_PFN:
 		WARN_ON_ONCE(1); /* nommu cannot handle this. */
-
+		err = -EINVAL;
 		break;
 	}

-	return mmap_action_finish(action, vma, /* err = */0);
+	return mmap_action_finish(action, vma, err);
 }
 EXPORT_SYMBOL(mmap_action_complete);
 #endif
diff --git a/tools/testing/vma/vma_internal.h b/tools/testing/vma/vma_internal.h
index 22ed38e8714e..d5028e5e905b 100644
--- a/tools/testing/vma/vma_internal.h
+++ b/tools/testing/vma/vma_internal.h
@@ -279,6 +279,7 @@ struct vm_area_struct;
 enum mmap_action_type {
 	MMAP_NOTHING,		/* Mapping is complete, no further action. */
 	MMAP_REMAP_PFN,		/* Remap PFN range. */
+	MMAP_IO_REMAP_PFN,	/* I/O remap PFN range. */
 };

 /*
--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20f1c97d-b958-474c-b3a1-8ea9a177e096%40lucifer.local.
