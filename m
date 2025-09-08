Return-Path: <kasan-dev+bncBD6LBUWO5UMBBH7M7PCQMGQEL3O5JLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC2FFB49340
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:28:32 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4b5f9673e56sf67393311cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:28:32 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757345311; cv=pass;
        d=google.com; s=arc-20240605;
        b=UvrZ5GwfG/fynFAxtGsxZlNf1zw9ud6ps7yJ/h/V6Re5GeztINbbmhfCtBBJ4L0Qom
         P46V6UaHgopSF3TrMbzh3OCaRL2BtBkbu5Q/r5wXWPbb0vopBMLs8GIidAneaw2Mz73h
         pO7vimqMF4UfcHVOKI3vAcIIWHnmvydhEFu3hMphrm28UnhMmfqps6b3vysmnWU8N7iP
         hRBkb0V2+cCDLdhKTyBmzORzP7oOf+TGhGKKTaDJ5mgzsFeBGKF2JDXRx4J2i5utaTvl
         GFviS2hvY5XNmF9MSV0ysTT+Ta7n29/jLL0dB2Rp8BQuoWkNduVLVHtj2ij2aVOYjwh+
         WeJA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=3sCu0LYofpRyennaqDvfyZ39ahwZdHwzZV2amROnrY0=;
        fh=XbQiCn3OkWEctj8HdXzIp2VkXw+i9vDHcyrm+1QB7r4=;
        b=a6YBStFvuZqDShrGGbRLpriXjHdd5JbePfRaF/JD2aDtfi7xQKWifoqH/cKZ++35k2
         HvEnwBAygd7NaT6WE1DNQxzafo/u7S4/3AHwoOpSZ2Yy6K1tKrPROpUX4ydMywvCVfik
         tFq8YNvk/8fBJogToQvOEufbl49MaiGsuMDzDVqFvNKXz8/jmZXvXjx6ahSkYwfYUtDX
         vlfxZ1gVO7tEGiIwAfMJek6myTXmGGl6UWhuswWyMreGbj4OsDltIPT5Ju+X3T6fJ2iN
         MG6u2OH80lSOf4HmiyBPoVa+WQUif1N7QUwTHN+B/JPKidnCj46tLotOPO9qgJxyZWqc
         YbPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=jZURQn60;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=XuJsxuR4;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345311; x=1757950111; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3sCu0LYofpRyennaqDvfyZ39ahwZdHwzZV2amROnrY0=;
        b=N/E9do8UPbv67aGSYZG/YhbytUV35KigYSFeWHLYOFQsJxGAj9kwxwh/zd1npoXZgR
         UDNslndQHJI+qwHRI9fgEp5kLW5jaOtJ66HAflAJJ3TB6L46TRn5QGejUkTBrOsbwum0
         e0I7gzWtQ+TQaTo1vaP6bM7nya6ai2LXyL33/5ecWYgm8vHtcsfuUNSuR6qqwT9o/R+W
         T5uCuN6ljIy52fF+vZlSLKr2MzY0IheGBTDbiAHX2xIt1gdw6iOki3SMCL70sB5951vt
         NcxBlAMbMusdpHZXNZeLmwp+7cr03vp3O27glNg3Ub14tJqnpijUMqOq95RkYkjzCXrG
         2/BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345311; x=1757950111;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3sCu0LYofpRyennaqDvfyZ39ahwZdHwzZV2amROnrY0=;
        b=noFKg+AbxZ2jL+EPtH6t6ImAidYDmrgAC+XIiTSI5YEwG5LeHCpuHFOt4CRwIH6VwR
         +Chy2UjV7JlLUKDDN1X0ne6JtqPOtCGGLkbf50sv9i5/kaYhj7LeEtjphrxJm9OkheT5
         1yU2Q6BYdQR1dGCQ2wCm3SaIf4XFwKzzJdUucaydG8JDDVghMGDDlxkLbAsSx3ogDNP4
         IDz7NwlCIPWaFm5XWsbMcndhpwErDFrGJZ9XS5YN8xJN2FzguVtRtbwIvYbDgku5Ludy
         GBc3RY20+CjD7zLchR2fho+T6REwtuGP4Q6a90BhivHdJ7iJ6GiQIsL4iJNDvpdnHTEN
         N4oQ==
X-Forwarded-Encrypted: i=3; AJvYcCWEpuhtbdUzdn8aD0zCsqyrQEJj4GQR5HAE5HeSapYY1sf14msbXhT2Ltb0HaZDOcYakTMj6w==@lfdr.de
X-Gm-Message-State: AOJu0YxZQJlf1jm35ytw+uY/4P55ykUGx0+UonYiDn2Xv9+bOqN/8L6P
	d5/XG9mu97cy3V7jzJNFsLvBPd/Z+EtowMYRhHWaGsHzpU6PLZ3kgSSi
X-Google-Smtp-Source: AGHT+IH45qa5oKXHWw+bNndgVO5eySCeNpExaNaV3f/KSXFn0XUIgDNjTFtGTnt2iZbwmjNgUw9FGw==
X-Received: by 2002:ac8:5953:0:b0:4b5:de44:4ec2 with SMTP id d75a77b69052e-4b5f8491d1emr113003521cf.78.1757345311446;
        Mon, 08 Sep 2025 08:28:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcx3VpjR5L77K3NnvIGXKBovJKLSbXcZ6+H861gMiOnWQ==
Received: by 2002:ac8:58d3:0:b0:4b3:aacd:5c80 with SMTP id d75a77b69052e-4b5ea97519els56592271cf.1.-pod-prod-02-us;
 Mon, 08 Sep 2025 08:28:30 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXiMT8ikR2aSF/Rds15Cp3nvuerDzuR3FlDLi6bQrX5q8OTw+WMb0mOn2zfFznvx3x7JVcBgPG6oOU=@googlegroups.com
X-Received: by 2002:a05:622a:289:b0:4b5:e9bb:846e with SMTP id d75a77b69052e-4b5f83a51d3mr102262641cf.21.1757345310401;
        Mon, 08 Sep 2025 08:28:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345310; cv=pass;
        d=google.com; s=arc-20240605;
        b=QtVCjTZ/bfmnRHkUKgRbKy3Ox7mJek4OGV90kKL09AAtWFmk3F4DiOtbEtXGxbMUr1
         G6rUQv8aSqfszoGYI+HozwQXEVAgQhU1LJDiFSDWUZW5jrbmRZAQeOgKt8kC43q0hFbj
         ft20MNyTh0RILnsbfZe4/meSf+3veOEUwLUL8gtHWKe7L2QgJInLAL6mPbz7Oo7s8rZp
         dDRRre7h8+D6/eyxxmcIIEZLhXOoxP5Lf47f79EUiT7m4dVAAx/pK8/h7jvaV1yy+vFn
         EnUlVi2QlS6Y8vpMllytHEuf/SsJ8DHE0kIq3o9/cY6mKQWpLxYvyxyGGl9kr2JpSPLC
         guWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=tk+oOrjt8IXf6Zy4SCOVkDSXg+oacDEAfcKssA+rI90=;
        fh=rBgXewyurrOnUosxB6Y1BSdBMLv7NW0sq4bxnqF789M=;
        b=BY8cLQcv5U0Snzj6LNwyFvbz0W3hwsbkOo005LgxFmk/Pt5+BTcAOGEpFP5Vm84W6M
         Wm5kSR9M70BmhGIXHLLRQub7osZ3iNJmK0PyDPup4yhkrIj55B1CL8DpZBoVoLB0HAt+
         39vaBB+MsEiCbxZXmpH0S/yTivPCq+W6O9Gd7u/5/p9YQMpDHKnWIcYiAgrjdlCxhzvW
         licJn3NDAfYnTQAW5kQN/mhSN8dj0/flwWAXjV8DZax4ev4sT+JRmwZsBr/Ca/8IOC6U
         fVyNLrt8xIImlykL5iANUVJx54eqWnjHabFa8VvNm1nSYIef7fu4BWz34JObj9Mr5qVO
         OvgA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=jZURQn60;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=XuJsxuR4;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b48f506f50si6156001cf.0.2025.09.08.08.28.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:28:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588E27Pl018134;
	Mon, 8 Sep 2025 15:28:16 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491yx6ra7q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:28:16 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588F6VLM038858;
	Mon, 8 Sep 2025 15:28:14 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10on2047.outbound.protection.outlook.com [40.107.92.47])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bd8c6ms-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:28:14 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=uT7C1FAeXCQhLgtoTltQDl9AblOQP3NN7za2xqHZspXOVnkxXHLbQn7Lnf65LTajKtYukfDDsmMcXcjiPu4f38GBwqlQSYgjJp9/DPPBsIg/ghK2Lc9EinWQf/yRndNlUUnCsLCb1N8caFj+GBgPWAPzBJhr9mvDZD7w/KrazC6EX99kjtCIs32bY5whEv7psZeoGOJFsad4KRopVtVxOXQlxlswL6RzCghpoZVXTn78A5SSJr8+b3V5IKC13jZ0a0/f8DIp0aXrKx1Mc6tUV+ohigXA3LWVrU7m71x+59UVDwCWwoBz5yIIxAJFEKL1yaPd0RNXZp1tlbb35dxhwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=tk+oOrjt8IXf6Zy4SCOVkDSXg+oacDEAfcKssA+rI90=;
 b=D6B/LPmrgGWl+5QE+Vp2uNeOlMUAR7FLCVhtGgEq0ODi8ssiSRiPpdKekvufcCK/wBD3B8/aYRuiNdxzAHYdsr3XJenCcDemX8R7z6c5FKYUyReaMGC9q9kiJnpsbB6EmnM1p6oRMG6KmUck7yqYot5RpkCFT15XKX09uXPrF0aW4NNOZ3h7UXP92pp5VsFq9418oBNzfK4jckjtXA2HtIx6MfFiCNQLe3dkvVtKqLgqXPHt4WN22wTzea2DiEuh6ZkLT3tLhmwDm9MTqOj9Cfq1t1BKvwFzW5Q88MMiAOs6egfgC14Y1QkREUotup1tQVyVHMplyuDwSHDIQCwsgg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SN7PR10MB7102.namprd10.prod.outlook.com (2603:10b6:806:348::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 15:28:11 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 15:28:11 +0000
Date: Mon, 8 Sep 2025 16:28:07 +0100
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
Subject: Re: [PATCH 01/16] mm/shmem: update shmem to use mmap_prepare
Message-ID: <171b197f-0f40-4faa-9e40-1b68a79e05c9@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <2f84230f9087db1c62860c1a03a90416b8d7742e.1757329751.git.lorenzo.stoakes@oracle.com>
 <cc59a58c-266c-4424-9df1-d1cec8d740c5@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cc59a58c-266c-4424-9df1-d1cec8d740c5@redhat.com>
X-ClientProxiedBy: LO2P123CA0020.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:a6::32) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SN7PR10MB7102:EE_
X-MS-Office365-Filtering-Correlation-Id: df85cd61-f802-406b-a3ef-08ddeeec51fc
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ZtZ32P3jlsK1Ar/BPGhCzsdMYajauKJU3p19d567nvh2qKqes5kNOSj61n5O?=
 =?us-ascii?Q?q3WGG2g+mvnpr17yBJlV9AKrRgofJqMahSM3ZXWbfSP3HHkCkoxVx5DcWfGo?=
 =?us-ascii?Q?NsGuohn8LV8KtUIkP69w0E3/BFhE2es82LxZj8NT5fbMQdQT92vnvHDhp+pF?=
 =?us-ascii?Q?XV02pY3v2lrttI7W+z0jczpvN1sx6cOvHF+AvU6lLbtIe7Nin2xXFTyjC2JF?=
 =?us-ascii?Q?3zrrzgRzFGvQGSUPteNgdne8onXbx87EU/9Y7q8kgGxTjFaQxNfcmLwjLl7H?=
 =?us-ascii?Q?76pZIEfZEwBWIC7czdILg+rEEQQS6C528SkdlYJhsM5FuTnmw8s1DprohKMI?=
 =?us-ascii?Q?ZoZPLSCbxDsVLlrl3bZy0aZqgqwPJcpcRxoQGnltTU4BUNEC2qnK1cA9RyHw?=
 =?us-ascii?Q?eGaj31mkgHafAVeWDSu3bvl1l1lfq745dr27K+c+7yOma56DhnWc0F5nuiXZ?=
 =?us-ascii?Q?ALhixOyrBzJrVt8nxzGnHywBEYrykE4r6psziItuYOF1NgmxeIZBwc+FSOal?=
 =?us-ascii?Q?gq2FSsC/6VkKOdhXJDWuXUegnZS5+PgqYPBRbjiYB91k+5rT7IH1w7S5TA0B?=
 =?us-ascii?Q?fRRNM6k2fk3JqAcGtuCO0fV5eKIUPfA2fcIqMY6/M1lDcz/LZND7JsLBMe3P?=
 =?us-ascii?Q?6JNZdes5kArC3zPyQe5vwlNz4mC+Z/K1z490rUVRX6FwWXNa2hk4bM5QHkDK?=
 =?us-ascii?Q?6s2RGmPbPrrGjdvftfvuvy5iZcLBJBxZs5XnCxSVaUyfoDc3eVRwaJxP1Mr7?=
 =?us-ascii?Q?jCwf9ULqkcXYmU8kJeLPg6C6UvRQWjk57kd+Fa1JZkl6uV767DjGIARi1BJ4?=
 =?us-ascii?Q?VrZG5+CVbYfLbCMaStOUVDHJrqaOrXRsipBkB5aciklzIthW+c2B6DCSRqUw?=
 =?us-ascii?Q?xF1VErEq3MW86yc0O02ZR5HJI3S/NiDkj3+L/8/ukkk5R+I6cTwoKL+2PeR9?=
 =?us-ascii?Q?rWB4NmwI72iKMD6rTnRQC9KLieJpc0QkUez0GdTh70uaPw7QRCBcDnTSvADM?=
 =?us-ascii?Q?n6FFqAY4BKwSawK5+d+3WPfH5HMwCkHEgNm3Wv/UrzIUAo7UhUNxto/XPJ0Q?=
 =?us-ascii?Q?rCKK2i1xkkMvGdVfxl9oYRK71X/5ejJvzkjgikfmalA0ZoGJ8Y5pTXqhaUFO?=
 =?us-ascii?Q?CcIXQGHazpMZLmAbBbOmuTOMqMAVs63jnD3fGBNfcf8ntGvkQXhOR5OH+59j?=
 =?us-ascii?Q?zzfun2w1Jyeec7jYry9VPIcvQ1gN+fUEbdM0W0uTr/3+FlmUHzvRt77xRgsY?=
 =?us-ascii?Q?TBaJMy8vZJ+IF5HPw7Ii9vOi8A2/5dPz5cr1ECcvetAWsXaLMs3FbR51jiku?=
 =?us-ascii?Q?l2lBxtK4UuvJ5YD1JNaKfNT6F13Ad/OCRtaQTs+y2mBkIn3m9IeFAsWUiF/3?=
 =?us-ascii?Q?qaJEK6aRq2TafaAovyQenW5F7sIhkDC7nshnNXWtmXZmsvsOjX+ktLn5xbL9?=
 =?us-ascii?Q?U/h9Fvqyxls=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?wynVh8sX9cRf0ZyAKQXV6igD6REDe6LjlNbjUvfG88+i3vcDT4M1WBA3n+J6?=
 =?us-ascii?Q?4iB4SqNSiR8Pjil4v/fI1iS9l8ZvtK7hhlFNiz15trjuXdw4hqHMFF9gVlhX?=
 =?us-ascii?Q?dDuHb2+bG9K9HVCp/GPXQG3sUHIPFMBqoGy44HtoErIgQDY7LLbvlJCLdzTB?=
 =?us-ascii?Q?SMUTw8krNDTvgcEiUQsVJ7dYb5uK9DRwbsT65KvFCCYuvRsbg6XgQ7FzO+n8?=
 =?us-ascii?Q?6xolVXv4qnhGqJGB0sOght3miMNZWFb3e/zhLsb+bzllzAATGTKwnsAYlBKU?=
 =?us-ascii?Q?leBQ/NEVyxTTjVOlq1qaWsKi3QeVF4SQ/a2bM8atrzL4ohJNs8bGN8yGbFFz?=
 =?us-ascii?Q?rRt8Vn7U1bwDlM+dYTBGDYIeSgZ9uuiTbQCxtJ9jBIOhY8m5ammi73SLW4/n?=
 =?us-ascii?Q?Jdv109GPbV89UX35oz/s8LokC6sk39ukO4599nW3ffVTXpdVJZMw6d2m93wV?=
 =?us-ascii?Q?whZvFNdISRtJ+kXfaCFTHacjz1Uk94S/FjqWuxKMu81fAAZ+JPtcm3MPkwNI?=
 =?us-ascii?Q?b+TzI4PCdEqa7gMf5lee725mHUSrDYszNMXMsq8AtRKYiMVC/zE2utZkXPU8?=
 =?us-ascii?Q?MMVaUleyImvAhRFG55yVRRMIIeCl3NpffTPZl+41CfTsbLC10colRpVmfi4I?=
 =?us-ascii?Q?KrrQA5h8i9wXcv9diMwJPNVmHYqHeaDaGDvQn/vz8mH3xeHdQtjnt25k5Sq2?=
 =?us-ascii?Q?AHY8ZOPmzTnd5JFw8yTfQaGLL4/wkrkxg+sqbqDE8G1E7AHhD4jluEeJOWRQ?=
 =?us-ascii?Q?KVWNXkXA7yZeobNr7WJfMLrIaHPvIzlB9DhGNT7oSnCgTMs6+rq8rPCWqcN5?=
 =?us-ascii?Q?SEu4OFW8E06fH8VVEz1Y+JmoCbdpDPhchpwcip+tpDmaX5xu+bovFOKUZuWO?=
 =?us-ascii?Q?RvrPlh5MfKSK8iWopnhVJjMXc94vu8EI+T0zcsnmTpJq1IMdZKbFnHeKtvvD?=
 =?us-ascii?Q?VBtqcK+iT61ZiXBz4nbGl+MVCo0H3r28J1T5M7dd6/Elvhudfah36EATPxQd?=
 =?us-ascii?Q?QuqSqhFIBrOP8ieX/nGRnvWGOmjUEeKA+4hc3hZXsdiRd1jgtRprktBAxypg?=
 =?us-ascii?Q?V3DLe1jg5u7xOpawDsx9f7tjMLypc65ILekdyM2IiiWuGj2/pHwsRMrgJRUX?=
 =?us-ascii?Q?jbgnXq+lZc6oSvGML75GdxHIrKQPzXoLuqSWf8eqM2IfGIlKIPobE1M03fHK?=
 =?us-ascii?Q?ZDPYhEunaeBK7zaPiW84gyJBOACG9Gu9lHYjYW0xoqGB6UoYglW0i+l4SR5z?=
 =?us-ascii?Q?7Azyyy9tXzpcXbZ5TGe5i149PPB1enE3oU7wGI3o0eCkwNYJE/eB56pK+G24?=
 =?us-ascii?Q?1yS3wj7NiS7S0CjSzspXoc3Pukv4PqNQBmz7dNCfCFZ99McLdfwarrioxZvK?=
 =?us-ascii?Q?cvHsJH0ED5UCFdDlYgNqAidK1IW2LKpE2GyoUj1aq2mOCIW6WeJWh0npwkwu?=
 =?us-ascii?Q?1FNFe8PHGQN1wcwDHrpol28LGxfXsM/qWJpX93tXLRnCdoNqVKeYVZsgE8B9?=
 =?us-ascii?Q?1OM4q/aSpG0+lulNXGlqrJQQ4kOTDmJiIpRKrSUK5i3QTZ6yhnUdUaDmPMNv?=
 =?us-ascii?Q?Cho2NJiy47jnHbq3z8PYSYTGU0N03RABilJ7383LfhZpIpfLdLvWFwdcRgmD?=
 =?us-ascii?Q?ng=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Kco7Q5SWyHb8THwZcxUXFmw6p3f4VT2PLORsrle5gHizzbj39oNk/3wrm8gLnmiznRptgeYnozRT0yn9zFxW8p5smxEr7qJhMm3RRvoc0QZTH5FUNd/Aojdf6ode3kJAgyYZndUTZQZg2l8uq41oTPNqfy8a577PdM6bswCnNzvJ0PtGnnR5+Z/CYLhf/j6GUQZo1vDPMJeSbaMVz25rD3YIcmKz01F96kD1P/qRSOOgbNAd/Q23kgrm/2u9BG/Mkj6CbSsnNnSzh23Us5uVuBzyy5hm/Cw3Z86KHi3kxIInii7UDhGC3XqHlLgJ8fUceLnMVfdBl7QBd7soj9QgGLHbktCaEb7jx2bNJ/OXwn1QFjDg04k2h8VeFdScbmk9AmwOoxIv5mM0nkjE62cFVS6Waf4YRFlK1/LOMvTNEqB/9AXNCX+GFTPeLYfbUOx5z8g/YYRLDdU1UdqF8nG3rbq6x2lA4gUiAamFWAckQEv4/emZJDcxyNn93WO5t83Xf/hqZyXodLYBEkbgYq86pn0TuyRlKoRAYAGeY0PkOHyuKgFxX965cUMv4CYKUWRADUDJdMugGOdWSwYOgIWCmHE2zfdNQ3akdfwyYlUGuVI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: df85cd61-f802-406b-a3ef-08ddeeec51fc
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:28:11.2588
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: jX4DXe1MUZpcISpm5wITTqBDYyQMMsTzdg3vS3wx/f1CTTS+pLNBE1uY4ksH6PLsuyxFYSNvU+1viERxWn8pC6/TQRfDWvoITGYA2YSr9DU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB7102
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_05,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 suspectscore=0
 mlxlogscore=962 adultscore=0 spamscore=0 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080153
X-Authority-Analysis: v=2.4 cv=SaP3duRu c=1 sm=1 tr=0 ts=68bef610 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8
 a=UQyiNi7Jvx-vLDuNDE4A:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12068
X-Proofpoint-ORIG-GUID: 4v9mq8MoXs05fTzfPDpidNpQBLYVYucL
X-Proofpoint-GUID: 4v9mq8MoXs05fTzfPDpidNpQBLYVYucL
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDEzMyBTYWx0ZWRfX+LH0NQA8zQ9L
 yjp2RPdxzChJmhtebJyTglBeCsqpwDPiaerOuLMD9hal1SQ2Cq7ee7m+Zsqw7ve4UeImD0bpk8D
 H0+zmggvvCT+B/7JVQqbpyag05KVvG18wCYqq11fx1iLloiIpy7u0l2OfBFXjGOF6TrQTmHAJ98
 Y6SsmYuWprUWqr3rMeGQmilRDbPMwOU4q2WRCXDD54rA2BKCNoLlGmhwIaWftpeIvjiOC5n79YD
 /dfzFPsmbtoC1Wr3Blyz/ne8jZ5OO9j33ifWgLTipy1iB+MODxY9ahiB3+GoHJQkqu3p961GpBk
 9amoFQWrP1DWNmmh6vnwz0GZA7KAnQRayxF6/dyX7q+jINYTQwwcmIKNTrCS6i130ZHP3Zmu/il
 Eu4JqrFQA7oWXZZltAX1hs21Sjokmg==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=jZURQn60;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=XuJsxuR4;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 04:59:46PM +0200, David Hildenbrand wrote:
> On 08.09.25 13:10, Lorenzo Stoakes wrote:
> > This simply assigns the vm_ops so is easily updated - do so.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > ---
>
> Reviewed-by: David Hildenbrand <david@redhat.com>

Cheers!


>
> --
> Cheers
>
> David / dhildenb
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/171b197f-0f40-4faa-9e40-1b68a79e05c9%40lucifer.local.
