Return-Path: <kasan-dev+bncBD6LBUWO5UMBB4UPVTDAMGQEEGMLVYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 581B3B816FA
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:11:48 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-32e09eaf85dsf103253a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:11:48 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136306; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cj70negSmkHP76ouLLCbFR56UDlkJjCBzI5VxCKbcbPdZE02k0f8lbpZdURFIMMFyd
         IfDiQ3FvxroJgo7vlxI/5YWz3Kr3noc15+jqGgoTQ0Qc8UCG7N4wolzaTJ2OKKM478VT
         eRM2IMA5gsr242/YVaFPxJKWcN+1QRpBzczgX4NWseHBo2bMn1kW27/eH9cvcYgeTfWE
         sjEzlpQgsgEbi4sZ0a27DJIXr3m6t5d2KwyMml1wK1YONJr+Mbg6ZDGukII6ycf8l5+o
         42NA+yQa+NKlIHDOeQCXNTDbOr9Bszf5ro9y6ItStyXBFO9a7xW28s086hyjQYfO96JC
         YUJA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=SvN1w0nOC+lhBzG1exdyxKxcQ5Evm1FgQ8UIqU0f68c=;
        fh=M6Kq2Smz1OVcGazbBMARgwVpGcBPNlnhA9i357IN5Ns=;
        b=MNXyBb9mCzgMHFEv8mAotViQfzfP776tA3EEGscnjlCTAQ1ndU5/SHuut4aSf843Jr
         ZrByCv4Vdt/brSyCbdBFLGgK0kahneRock0oRqk+jJAzljoLzU88uRo+abwrYioTYXeZ
         lWuSBQT7itt2JC+pDCXQ9shzHT62f1uLSkwSOD1ILO7RT04g0nrvzp3TqDXD9r1dKaPd
         g/WriefAKDY78sM2CMpT9FlQ/S3xtCPmPIjYtxpXbl4d7SQ6yC7mm5FNj0niSw7jtvJM
         m+mJFSzh5oVsyvG+OtuTphx3Y43q/6A2jMjCiaM6bzVu7DGQi/fCdBqc2s8PSrIXWmC9
         dQrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gQGikju5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="B9PI/8Pg";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136306; x=1758741106; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SvN1w0nOC+lhBzG1exdyxKxcQ5Evm1FgQ8UIqU0f68c=;
        b=JquwHtp2FuStfsqEvc5+bhJ84FP8ZGqkls9ljI94Tu33VpH3K5i2ZX8qZVjrWkiuvv
         xZmsfOoPiyC1sxE4opgONk97cj75xZjZ/UB0xLLP+iwlh1JbPzJtPk/z6rK62UYu1hB7
         L6w/UCy+22sxanSHXRnQQAePbhKOWjIEFiPs2z5CwQKWPxxHXmiieCsKUf6G354NLO5G
         +n37yFPFN9LpJVRdw9VufI9koSXNHB/6X65jNH4ccI6b14lE5vSL9qmXvAKkwrc4cLN7
         mYZeD31Hn+UL/4idjNeaIo8JE9IuJRizzkGqof+8tJJqDPJwhyjGuK1uMH+UvuWlXifa
         uNDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136306; x=1758741106;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SvN1w0nOC+lhBzG1exdyxKxcQ5Evm1FgQ8UIqU0f68c=;
        b=UAIeA90UAqQSQNAHlC/nZAXaNyFM3ZQf0ztXNxDyGQMcCXGl6BVcp7YBHY8896XscK
         xj5lEIA61+yQPWbhpSRUmLvmX+6THjBw116WlIHRKbwQR4JI2MtktC509//yKt5NimiQ
         YOYRSNBceYxlI1WX80V0hKK/OWsP8s//kFtNpTBQTMe9ydw+r4dE2F73R5w3+l9hVkmB
         Y8IxciFrUWXfmMY+MeLFmapMz2BQ+ftZxbzKcSI9Liq46bfCfe/O8S/o6TtoIuE9euXq
         Ky+ocs7MvgEKL7U93aIwg06Pz4v0CFlgXIOhz2jtYyPl1iYg1EwN8GVlSS2sd/UzxXx4
         pkvQ==
X-Forwarded-Encrypted: i=3; AJvYcCX4aK8KxmGjlZw1VMWW5IlMyeDZ0l96h7QfbmW5K++wprTUbs2AmjXoFVa4qbfdrEx0wbDrmQ==@lfdr.de
X-Gm-Message-State: AOJu0YyqqTPkiUn5Hs0NzjMfoGTgPZA7rLXgDvgwHoi4ZjqFG3va8gtx
	6pTn/bV+HNB64BWXxqNIOr/fiamBmuJ7PxbbNOzvI7PsVsbxB6UVjLzS
X-Google-Smtp-Source: AGHT+IFy4R0fgLavVuF2KKU/OnQqPJQJkOuSqjFWas/msSIKykUuCBOjBvFe8SQYHZtttjoL8LNVBA==
X-Received: by 2002:a17:90a:d606:b0:32e:528c:60ee with SMTP id 98e67ed59e1d1-32ee3f7570fmr4347847a91.24.1758136306431;
        Wed, 17 Sep 2025 12:11:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5HKdP0AwKaWXHvf4qUJZBV/mi74Kx+KkyjXXf0A0zHdA==
Received: by 2002:a17:90b:354e:b0:32e:23e8:e0cd with SMTP id
 98e67ed59e1d1-3306528fb5els16726a91.1.-pod-prod-05-us; Wed, 17 Sep 2025
 12:11:45 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVLkTsnOKXWP0zUTsEnwchYJoPh4iec9rJyVRh/3BUkxkPBcnBc7j2GNqbGFpQVROS0gx7aQrMOxv8=@googlegroups.com
X-Received: by 2002:a17:90b:2d82:b0:32e:aaac:907 with SMTP id 98e67ed59e1d1-32ee3eee71dmr3500626a91.5.1758136305090;
        Wed, 17 Sep 2025 12:11:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136305; cv=pass;
        d=google.com; s=arc-20240605;
        b=B/xqX3FoMxhGvaJRcjU6gWK0F4fc7XI2leHtR8n4vyaCihGBKX1M7WIwdMtYgreGcd
         g2og/5cUIgCXXkioVN98SbG3sYckHE8OaoGrkFqqFuj/jktMjx6u/5TZtS53mOX6JZxV
         JedwOKQiEArXPHzkJ5bjNBW7vTd5r5ivY6OfprW0U4uXMLwytEj+q1dA2w0EPquXMVGf
         c6AJwG3m8Q8ZRoFW2AJk5zoyKaNwNb0Nytr+pIH6xFNmb0zwtvVDah12mL7EYeMNhI12
         6ZFWqT+xlfM0xcB2j8d8UfQ8Zoovhktjg8L6g1wjlUTts7DXpGkGBu2HpJp1zLjXLIIS
         EZqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=pF2eY4Gltm75j9utnrjI+OtFdlruUnTM+YMpT/p1noA=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=av8QZy3XPgD5wwnDxbWjU2aPL+d4rQ+rszqd+oTaDMaoalBhiyT/LXnt33m6eOYuvA
         geCUXGMaPXpcx2GjkyP0MpqggaNYSp51j1M4ciD7gaa3p+Cy5cxriJkDxBfs3rkqVBsa
         fLtWnkNYP0YV5Linzz+PqgLlNqdW/E0/lnfvfFeDp5TmubH0oem8jRyM4Wx2kMxYqWN4
         9mPwlMuPNqjZMo1/yjf7NmUJw5vrgfOc+7mNnL2Zy25T55TAXnPEvqpd2lR0WlUY6+PK
         sLXobnfQ3ZOuOiWgk1XsIJLhnz11FzuxBSm3mIrP2a2Jj44WMWZYTpyqjjFIDnl+rN6Q
         m4Hw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gQGikju5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="B9PI/8Pg";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3306070f7d4si22404a91.2.2025.09.17.12.11.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:11:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEIWYC014420;
	Wed, 17 Sep 2025 19:11:31 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fxbt1q9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:31 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HIf5xt036751;
	Wed, 17 Sep 2025 19:11:29 GMT
Received: from sn4pr2101cu001.outbound.protection.outlook.com (mail-southcentralusazon11012014.outbound.protection.outlook.com [40.93.195.14])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2e76fp-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:29 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=GDpaXKdZEVS0GaKbF/s5DbX2t/CiC2aIEBqXDJgbKpmQNug7+e+AHHiEEIhCcTKtdJVH8p9Fvgh0W+UcEc+doMByl7xYaNRaF79Y2asAzHxF64IxjXcs3S5eMnupdoreHtyyQP7pbwa/4tIT1ieTRMAV5etQgCTre40TyIoUxPtquh81ku6tKMkSvniaTIRApRPTz958ijfffLS3WnSDjpdjWnfaVZfByA4POvxCVJyzvg88x8ItgUemf3dV7ex9wTPvtYyuT2xTSBdO33+68ZCSszxvGb7NL5HUGP/Nhq+hUZuBiuTu8wV7oP6rPxO+K1zq28RcBCjtt/jO4B5S0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=pF2eY4Gltm75j9utnrjI+OtFdlruUnTM+YMpT/p1noA=;
 b=HMttLy2mrLJcapM2ymjQpHmxC/1xj095s/A6KsnaDdenOAom9t82LO2YSXakpT73EvqeL6lHanNH1uCzqcKR8gyehJPo1hY8KOc+w5fxDMRrRwvLQE17c8aRKKj3CuxRULfPKNI/7mmTYBw33YxaKavO1wfnQbkGp+sPDb14mhoU0nKyq1RdLVU7Yg93CTTMHhGOm8/uNBOkTkUUx7knjy/qgS/ewwGdW3+PiiwMoZK9Gwkj4oYBM1uqBGPllQaqo7x8lve6cSttnv1URo/cbaki1PHItXoFTvdPMwsLKaEUzGr5Wus3LtHo9X8WDe19zsWxlOCf2BkZbsRHBENNlw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by LV8PR10MB7774.namprd10.prod.outlook.com (2603:10b6:408:1e8::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Wed, 17 Sep
 2025 19:11:24 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:24 +0000
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
Subject: [PATCH v4 01/14] mm/shmem: update shmem to use mmap_prepare
Date: Wed, 17 Sep 2025 20:11:03 +0100
Message-ID: <86029a4f59733826c8419e48f6ad4000932a6d08.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0548.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:319::11) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|LV8PR10MB7774:EE_
X-MS-Office365-Filtering-Correlation-Id: 3cbca183-4227-470c-2b8b-08ddf61dfe86
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?52iC5q+vzCPEfxIT12GjpRo2oqRaxiRq4s3nUfPcMViluo5+REfhab/+tJeT?=
 =?us-ascii?Q?fh2r+dQKM1nGm9BdZxDcRaMmntlUHkHqHnRMhU94eEfTptz9ri4i4nkIuLik?=
 =?us-ascii?Q?AoTa76kAXBt+BvnQ3oh2ZipLt2QkklZsHnNE3cSNMETShcyRUDxiq98AWsdn?=
 =?us-ascii?Q?Ig2HBFEXxpy2ZHxbdi1itDCRHqtdruchW9wWCloKPoTHJMIxK/aCsZe3HC33?=
 =?us-ascii?Q?tX53R9QE8uqKU0XIgozC5ZVI5tUsoDmVTwNuWMPpfeTb7AYrM4puol8fUvcE?=
 =?us-ascii?Q?bGdtOKV+lQbErIf3NaD9I61Zh5QQMrHQN5lvvz3p15qN1l9LtFOaOUOTGJ0X?=
 =?us-ascii?Q?OZL+bu/c2w5c1XVCbRJ3EdqAK+Plwoc1w/fd6wPdA8et+yzIa53BWKBEKtk6?=
 =?us-ascii?Q?m5IDW27SFOcTWeZdlPi0oRmY4VFTsnDPG15zWLKSYS+B7sE99IK4U+PVgI+f?=
 =?us-ascii?Q?O6DuTmL9byTut+RwF6gMGhJRN1M9Kgn7SWH0izjKOkY49+/MDJjBPk7Pblfd?=
 =?us-ascii?Q?P3vfws2XvbJyCwYN+xudU4IKN2NF96Xkrk0sSGWNtWIusvUyi5aistf8LB2C?=
 =?us-ascii?Q?zoz4nTwc0a48rsiXq2kv/7vI88V8Ia6JDzU1DfwYXXwi4CjNyMIOmIbaLubL?=
 =?us-ascii?Q?lVT1GED55zKWp0ycEjB4CtMiShQgnbwhGGdaU/xQPSuvU56egrDrSCGVu+tm?=
 =?us-ascii?Q?mS6EZNEGuXzotJkE1Tmgo2uIcKvO68G3An+DxGff7ECestftl4chzsbMYL2U?=
 =?us-ascii?Q?N4Kg+wm4oozY65h0ml1SJYeq/ZV9AKqujLYL3nqvMR/ADGsHLSuoBu4GI1IM?=
 =?us-ascii?Q?GhalAJaXPg8uBXEzlQyAUmI3N+kWZy64vKnmc1TtUoS7HIb5M46cFWqPelMQ?=
 =?us-ascii?Q?iUk8xKj2+zpb6YPyTayZ3WSwJCabFttYYdk4BaYQgpjA/MYHF4QGLE/ovRw6?=
 =?us-ascii?Q?xyCAd77lrby5ZsrzRX4fexXRyBXEd+yBga7Rae3ecPfv1wXoLOhmzTlZsucd?=
 =?us-ascii?Q?SvCpBYmp63eYNUtv5NhYKgSa1Q93I9oksHuqnDoX83pHDXn+9W6XT8mfdkSA?=
 =?us-ascii?Q?Fs0xcSZe+4+lhGjfS4WP66V3rHH12FSjnpGIfbvQCPZ0kE45U5WQnJepoOkE?=
 =?us-ascii?Q?m/hmE2ECzT3uz3R0eaIw/h1Lye+xCOoOL6c9zuSoiRewSE/RX08UClKUWIIr?=
 =?us-ascii?Q?olJc9Sw/663hGvUYfwob9sSa2rFgiRvXVYGRCuiROl37bDqpgROrM2H7r2rt?=
 =?us-ascii?Q?+OGaXFq+kXuJjPac8kXzRenYY69i+6KkLmLjrQdWnDuwzzxr1jHTl3WUlhxW?=
 =?us-ascii?Q?Umez2RPZHPk63WrYs+K1JSdvkXJlkSfARdgAVDnaoDkbbt3zFWLfzJx6PTe/?=
 =?us-ascii?Q?oZYFfQOTARhc5KbiEFjQcnJVscSz1gH659+gBcFlDI0sbB2WGtCLNgxq8kIp?=
 =?us-ascii?Q?hLLARLmc5EQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?DvhsD9l26t6Og2y+ryUflNsgMAol/PBpuRkpGrjyI/ZmNV+Arx8AEMTFyE5U?=
 =?us-ascii?Q?CB9vTAoTTRsOygnhv8LEPweN6BQMGvipxY5eHUsyuxLJCX4fmYnicQkwv51Y?=
 =?us-ascii?Q?E8IOpXzqAIVpNcb0ufF8T8+28Ttf8hkfQI5AIuu4AoAe+JzgLeu2mZGO3ISv?=
 =?us-ascii?Q?vBBjdaCThX+NpMJ1280oJzhmk8nk3UBASH5fmEMlQsaGSEqddybH8d0zmA7H?=
 =?us-ascii?Q?HSjklxpbRGoBoa+cfzWD2ZqFfDE5YrQoCKaQRXJpJgXrrRGI5D8fgdT/38oO?=
 =?us-ascii?Q?2EYdpvkQWowREMy5wuT5FsOOF98hLlnXOyYAwRjm0cuNlQRHdfMIhTe8w9ng?=
 =?us-ascii?Q?WTljD3XACjShoZOK80SuJgTRjAbDh9AjzPXoPwbZZkSPfkj+OaGYNsKGdzE7?=
 =?us-ascii?Q?YarzG5gOxOHkXMlO9fLy+mLP7BBLGR/KZ4gnGmD5Nid6E+XQ/+ZBsRp33HY3?=
 =?us-ascii?Q?bt/fyXHRcik45Qwec7z6Ajeid+Nn8PLcdLHSRFGwrhoMeOrBk+ZG9kB2EVjX?=
 =?us-ascii?Q?PQ4D2Fx+8bF/H/AbG5pRY1a23tUV1Y3dl9w9xWu1t+sc7qjs1min+kHI87+d?=
 =?us-ascii?Q?igezvw3WsWTuMcsfhzNfx+Y6kYWUwy1ji12LuGoteqK/VZeRJBOH/A0d0pn6?=
 =?us-ascii?Q?yVoGTFCEaIxMM/sBnh5Rx/NwMubWv1RlS3iSSojobVIYQ+3ys4HJhOyAFDad?=
 =?us-ascii?Q?s2fu+MRA1TiW+3mSM1299UNG9+29R9xgjwwIvp5IXcnduGuW/ZZnrOgStNaZ?=
 =?us-ascii?Q?W2ptIy4+FFYSGHl8A5kt5ViQ7lW0M++oV0b88AuYjS32MYTbhqlll+7QlLQ5?=
 =?us-ascii?Q?add24DtkQKqhRs4WYglNkUe/UnRMA2sRN6pmNp9sHHDfYLpfBUBJTnLrJLuU?=
 =?us-ascii?Q?PShSJc0EgiHS8664Ge1niOh7gCqUmZl8bZQTGoNZWJXHMsPtDxzGZrareQpb?=
 =?us-ascii?Q?q5gvvdhXTbKtMiFXLlwJGSENwabFuV1WeejlxGetgt0cyRiUjOvstujZJ6x9?=
 =?us-ascii?Q?RQOkbacPxY6fwZOMjF58/jdsYvEtXn2FU+jZtLoSZQBiebgsn9cyy4OVJlKa?=
 =?us-ascii?Q?QJ6Wr2k3PCA0H7tmV8u4RssalfWo3wC3q+CmhU6g9hmhodF61BOPtPYwzXRP?=
 =?us-ascii?Q?f0v1BA+io63aOnIIAbkc9QUVYAtwj3rwKIYthBp04y0N0Mfwv2FhFMrpPiEc?=
 =?us-ascii?Q?ZanOXP9FDdALw31qBNEU2R7z30C/kRNeeHyQvsvq6viBefayF7KgKISWcfH9?=
 =?us-ascii?Q?GwPMKn3j3nlZz07EwiC/DQh9oYT5/gIV/SPBZkB28I5Rh2pV/dDMd18sqKSP?=
 =?us-ascii?Q?WFEXjYR5CSuYDUiVVCbLuCY1eGVuQDbrXCfYULq9N7wXLDk/Id98TEAFxvSi?=
 =?us-ascii?Q?FtR+TavIJHhcW1/VcX5DMaCk7yKfvUnPKQLZ/I6kXpmFsjbTOt3YJ/Sw5zSQ?=
 =?us-ascii?Q?LC2QqtyArJohy+Ape0zS8IWJnVUva+hiGSB6zA7FcSNU9KK8Zn2WaOq0N2Rc?=
 =?us-ascii?Q?GuHjPsLkqCx/Mq00b7vezY+hYcgF0JeTtVA09gRdLupkHDYrEeICDWu97r0p?=
 =?us-ascii?Q?kqdNlcIF2a+M8vSRdmLwwfJPPgI81HvnYiHnOgSLWjbUWhIA2FQw2gq36G0L?=
 =?us-ascii?Q?LQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 9ZoLRbCgba+SxrqaDB6ykuDUpK5K52hyksmettEcNGE0VyfnJmUU8LrfKgQSLlXhaVhOA6Cy7Jxg1ilbN1Zxir+23bCKOTRw1MJsliM4xMxHptNFKZ971xiMU7bbKcM9lFmWFAniagSl6UK5xtZQ7kjF2IVZIiJsfy5BPGB5weYMveEeuZFMetUSbfjaJ4/Obk+bs1xhUtq6LuR/IrNmbLcrVle3TCsxKalRLVuwwtU5UP1VVuk37gU509HJv1iEVJTzdQvUqigsF7FKuENhhf7E+/YHGKrJBLvOrqbyZpdj2p+MlHhhRySVzrYq9JWyHWBY0YQI+hGHKe1NcFgOtel4ha3E+Ka63G6ey+BmkE4mDd2qX292aySAKYi2qbnDsFhT20dtZkZNbs/okxSnPJGl4tgqCvWu8bEELsVQIzCaNq1NNwq3A1IiXTv29MAHPV/XWtDlIBSJnt2nld2tZnxwX3MDmdcPUS0yX+29MICDp7sBvs6x830Z6btZ5yKYUczDz1Q5PcgF4fwP426K8MkJeN42l1tX2XEwguu8e6dZweUi2SysjulakBJM5XQ65yKmfKo4IO2Au8M3vYSC9Mn9HWEcTdCFGHjf7qAWRb0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3cbca183-4227-470c-2b8b-08ddf61dfe86
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:24.1746
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: YCBuJVFn0lRpqNIfvmCN7HfLqJwDQZ7L7XDeu///hQZU+5U39nLwfGT24/GhGHcqfHq5wkhzGHIpmotqd6tDl4w1x5TjOiCSqomlQy/3OLE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV8PR10MB7774
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 spamscore=0
 adultscore=0 suspectscore=0 malwarescore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509170187
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX/H671OResUYu
 bHhHLYKqGTfsXZaiIkQLayVtc6zOSRPvwBRn12AiyzsOppclp5rHeSeU1QR8UOij8m9SkP+MIFO
 IIwKhuhoG4mPjAs90vzsH6R4TcJSo/pagjVOy8qIdqtmgSn0bUMv2J80KKrCCNZ7jxJvsno+BNv
 2lkZGsNYQrsAW0vfmS8EJ6dfsg8cnhrSkSHcW8wbbnyPASqB13fQ7rtxhdPAZkdnVVMLZXyroLk
 UMtiTMPWxaw+UoWlUUhCKF3ZX9WyTfiQe9o3ws0XJ43TOEZy67IlBNtXrcRdrVP6w4hq7g2xFS1
 zBb92s/M7J0Xu9nGKrHV+r1tde+PytmhI20Ik6NZ3ga1rSGT/8NZPH2nO3g2/BFxA537p31SAzZ
 sh58SdFkw7jprABuJBDioqZeamq6cQ==
X-Authority-Analysis: v=2.4 cv=X5RSKHTe c=1 sm=1 tr=0 ts=68cb07e3 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=SRrdq9N9AAAA:8 a=20KFwNOVAAAA:8
 a=Ikd4Dj_1AAAA:8 a=prdUi6YERRC1zlzC8DUA:9 cc=ntf awl=host:12084
X-Proofpoint-GUID: DpfuqrhSl1RETCC_OIcvTeb-ojwLfBNE
X-Proofpoint-ORIG-GUID: DpfuqrhSl1RETCC_OIcvTeb-ojwLfBNE
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=gQGikju5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="B9PI/8Pg";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
Reviewed-by: Baolin Wang <baolin.wang@linux.alibaba.com>
Reviewed-by: David Hildenbrand <david@redhat.com>
Reviewed-by: Jan Kara <jack@suse.cz>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Reviewed-by: Pedro Falcato <pfalcato@suse.de>
---
 mm/shmem.c | 9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

diff --git a/mm/shmem.c b/mm/shmem.c
index 87005c086d5a..df02a2e0ebbb 100644
--- a/mm/shmem.c
+++ b/mm/shmem.c
@@ -2938,16 +2938,17 @@ int shmem_lock(struct file *file, int lock, struct ucounts *ucounts)
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
 
@@ -5217,7 +5218,7 @@ static const struct address_space_operations shmem_aops = {
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/86029a4f59733826c8419e48f6ad4000932a6d08.1758135681.git.lorenzo.stoakes%40oracle.com.
