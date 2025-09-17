Return-Path: <kasan-dev+bncBD6LBUWO5UMBB7UPVTDAMGQEHJRE4EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 10D5EB81717
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:12:01 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-25177b75e38sf1817515ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:12:00 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136319; cv=pass;
        d=google.com; s=arc-20240605;
        b=dgLEl8xXwE9Q/5zIXWGA3dU0TVx6UNftagbNCogEOHB0ER+z5SYQkRGE8w+2xVjopC
         CSStcibygc8zfufgwEwSW1iJALTrF4Hw1JZycEMem/kk0Q9vGgXAdYfm+LX9cqCeD4IL
         JXYPm5ecnYoHqb66fiOU+Q85ytAqVIxJkSFP61C9vHMohb5hw/CpxsGwlBfgp/HMuFnG
         op6GA1dDgfaGQuc77RepLxTqcoqn9bxT0XehkwwcQmOSqHTMZxCsEj+fxKEbDO78q+56
         xW4nlAH19lpN6cSI1kbox9Za9oJWbzaIhSSHpzefYnTDai2MdP3tVkibmpJfcUjC3u0q
         +Z2g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=HQJcMgmJUrEqrR8qdQELyFVC5P+4Wc+Kb/isz/91RYA=;
        fh=6P/NyU4dztijV+90e7mIn09W8MWPYVbJifO5pGhbGLc=;
        b=ibdhRX8nPYZ36S0U4N+EqMMUbSqgOuq6vqZmuT3huIBdRHeb0u2m+5ViX+n1THwAhr
         vWFgQwNiszYim79kaQ8MFkQkR5kY7i++8o0vRTCCP1l2GC6pPIDNUCVKToKnDvzNg7Q5
         alZbTqcbz8yDEmGbXvRyNg6gm1lkQ+jUp/27zQ9N7KV0sA53ysdNkRFf3y198eyhHwTg
         9VPaIphN+bta+e7xIXPcWfBiVHI4PspCHQhslJL3kyDMaRGHFkOMjh1/p1QYPmHz+M/d
         8Xd6T8u/7alWUc1FB9JTAZ31MQlqUTUsVwqqjM0QlBaCVOkmBDxizIBLNSnnqc41k7/Y
         SJwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Emrtb9+y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=qKKNdh+Z;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136319; x=1758741119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HQJcMgmJUrEqrR8qdQELyFVC5P+4Wc+Kb/isz/91RYA=;
        b=kQkls04DEVHflgCIlg9ZU/tv7iI75KRCZ0EZmx9h6PACe3KFNJWzDdhGSvcQKHiPL5
         Vkxvg04QFFc8gZwl3toiEExnkz/O5YKaOD5gq2oIn0qXx0h4TG2CAxGPzaigmOJlEecN
         JnqsdSv6BVBkYcjydrg4oq8qgwPxL0Ctg7SS60AobYb9M14Yfg0CzBNUY7oO990arclg
         FyrzHSP+FLNNn7Wz35eQi/6lo7GF6M0gqKsmBfKzVtV4ZA7Ve6wLSDzuCPFEU+d53f4V
         QU2ePh49b04OS4paOsA3wHNiu1QBAYgFivGTLXk4qRY4/zfNuhn0K/RrzMsRMGrCWMf5
         SSJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136319; x=1758741119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HQJcMgmJUrEqrR8qdQELyFVC5P+4Wc+Kb/isz/91RYA=;
        b=o2TzddfFasvoYAgzAo9Cv51xVeA8185d6Dgmc8WwC5nkm2CO9TYYxV5vMknPTNQHIk
         WOuxc0BxpyDxBQeuCIwrRKUQGfz4UY4Ne2PaVm1EOLGY+No0X3of2vT8ardkhK1VajgH
         u3zGGKZ0tO1QppDRAoEpypdMZapLgwMP+11eCsMWVNFr9gQpkZaOctSC1pL5ypYJLWRy
         3khMmATHZZ5SjVuIRSPOvl5F+0tWB+rzLpHmzzzMFbWiMJpk+xZahfHkAokHcrDJPFGe
         UaRc0y6EXbKPQNYilQ1VoienHnz4+yKRqgSjrBNE5c1vMMT1QTMHW9xQhckor+gjmE1Y
         +RGg==
X-Forwarded-Encrypted: i=3; AJvYcCUNCdd5PflTYw71U0Ss2S/HWsHs1HHXCe2itMqjxMTwGFGJ/sHOZZfiLOOJXr1mn8IvMNfSfg==@lfdr.de
X-Gm-Message-State: AOJu0Yw2U3Z/HqxSSTE0+Gzgr5/oODb/r/ghx8icaJ49/YbsuVz7JjXr
	sncn1CAYKCoewIwChao1t4hsjmnrWxxChgsC7f8pbwjHFx9AtUg9UMMm
X-Google-Smtp-Source: AGHT+IFBad7ohyCGmkgOzYzMK2KE1x+xPVgUqhuGN3nK3tJAy805Bz44z1u9+Yv0EW+CxFXTdlFkIg==
X-Received: by 2002:a17:903:2ece:b0:24e:229e:204e with SMTP id d9443c01a7336-26811d910d8mr36338725ad.16.1758136319111;
        Wed, 17 Sep 2025 12:11:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5OOtgLKQ/kpLyShWQvyRI/Ln/zHvvM2jlO/XHi02rkiQ==
Received: by 2002:a17:902:e48a:b0:267:b739:fb with SMTP id d9443c01a7336-269840617a0ls157625ad.1.-pod-prod-01-us;
 Wed, 17 Sep 2025 12:11:58 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUu1Ewchs7lJl3cqg6ZaFb5CNr2/yVlOgqVi5EuiErfCRXh6+VZ2Zt+OyPsxqVOkPZsFGQhKQlSmOU=@googlegroups.com
X-Received: by 2002:a17:903:3c2f:b0:24c:f589:661 with SMTP id d9443c01a7336-268118b963emr42022555ad.11.1758136317757;
        Wed, 17 Sep 2025 12:11:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136317; cv=pass;
        d=google.com; s=arc-20240605;
        b=WkNXzl/z0wO4siUzr1rwmk/PRb917V+julsHEghABhJlHzyOl/R1RNOQWBDXsJFNtb
         3hH5PeCh85TGmgXQ9QC33cdy6dsZHit4lQnWJVNxx10XfsI/nOZeaug8EYXJFh1FWlsM
         FMdLCa7rZXEaBSumyMog6gOpU+q/Z7HaC7iQbAcPSRutqHjx14IuZgBoiw+BsHjPCOtF
         PV2TvLW7ZGY5DeOU6av4mDDsNIt/EIPymE4QmjNCXw857yr1VLHrkBa9M2FYdqNvZWp0
         hAztcM0uv8fGrJJHMuCdnQeyMluwtTJ70TFyN6Q4/nOgvfxFbwg1XpPE2wiaqteziWOy
         xA8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=mLt6Iw8NNsjDpMDEGiSX6emtwWW6f8/pFdcoNzwwJeE=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=Z8Et0nBMLn5Fh3pZknCMH9korcnh3asEXgqEfj5krGszntB/MGz7gw7+Gxdy79P7y4
         Kq5KZnSWQF4qQBQtLMERtALUvE4CW8Yh6EMu9RoE8QnyFK9BksDq8L8vhBlCxP78m2OZ
         y3rmMwLk28mU5J7rXURijdeHOSMEcaVTBokMb9jYv3Gw/KVvOHoDOMxZrUgqvc/zIcb1
         kuKPfhi83bLhZu3MmgEkZrFFAyjdeo9e+0b7NN2WueKNWP2xpq1viDyHPvSwDSA4M8yy
         tCCwXBbx06R6rXOD4qGIm4HSkLLLBAilNWW/ulXPjN4TwlrJbAav++Ll9BNuABmX8Ett
         uoLw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Emrtb9+y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=qKKNdh+Z;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-26980246d3bsi173365ad.5.2025.09.17.12.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:11:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEIStO001868;
	Wed, 17 Sep 2025 19:11:47 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fxd207n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:46 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HHEIed033687;
	Wed, 17 Sep 2025 19:11:45 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012009.outbound.protection.outlook.com [52.101.48.9])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2e5fqw-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:45 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=nXEVswrWqbd3Qehi5bRZBYtirKKRPvwtbe6UjQO1isDx1wYLgYhu7a1AF+mlZUW76WwZGS5q3QswedW2ctKislZzQewa3ZJjHeoQQMAA/K4+Fr/tzGXf5neRQszc6jKm1h8i6TdFgMxtCy+BGtg6jQWG3Kyu5U3mN6uGOgbAV7tSgSzwXv2eS5lUuf8jpHH+k5xZ6Sdi2TKQQgqaDp2sPqHt/4EJkW6MwW4QusPj0zWuChVIfb9g1v7mZ+DX4iropUiUfapuW0VmXryLONwDL16VqL5ID11QjVbdfbN0p7x7EgOW/xGa2l03msmNogKjh3JymTFOoluXk/8kMD5GaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=mLt6Iw8NNsjDpMDEGiSX6emtwWW6f8/pFdcoNzwwJeE=;
 b=U4f+rj9R/sYJ7mb9OyKlR0ns+Yh1NqX/Ggd+AgTUCKX8zYfQY66WJeX2LjjqG4aMphlLzl0CnCWBUAq8MVoeDI2BhR1pAsT7AQbNJzwOTTiPzQnsPCrYn7JJC/f1hFsI6Vqmex1Vd+ewcVfBBaQv4FujXyK8w0qJMchPn+89HRlWib1wtpPrf46dc/HouNIWYb717D/dI0RUBjQVW2HBL8uQAMxSmGOOGNv6IBYT3SEdHjN7AUrVFgxNgEJt7HqqLUpO3MJnZ65DpzLQdqJiTwbKDM7TFJOr6cGRafh6GsG01pfOxxvZgpeO5zUOkccojEHYDPKXIHh3zt4O4wG/qA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by DM4PR10MB6063.namprd10.prod.outlook.com (2603:10b6:8:b9::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Wed, 17 Sep
 2025 19:11:40 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:40 +0000
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
Subject: [PATCH v4 10/14] doc: update porting, vfs documentation for mmap_prepare actions
Date: Wed, 17 Sep 2025 20:11:12 +0100
Message-ID: <269f7675d0924fff58c427bc8f4e37487e985539.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO2P265CA0453.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:e::33) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|DM4PR10MB6063:EE_
X-MS-Office365-Filtering-Correlation-Id: 961c355e-fd3b-4be3-ad0a-08ddf61e081f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?9I0Mqifa/72QVUok0F3aDTnIo3OIxYxRpvhJQmiXGUdjsrH9Oa9Kgr8q8B8+?=
 =?us-ascii?Q?Bzk7Wm8UsUqEtL/Bb7laSkywuFdnvZ2laf/d85NvAncNvuB+SY5wdrBkzCHE?=
 =?us-ascii?Q?me6o2q0CFitrJHgjBTuv5VI6i8iTCReNMWYksGhTo6s5XOybiR0lv3aqDahM?=
 =?us-ascii?Q?0nojYyeERx5wr8fYdhOusndkzlIrQUVAHsBKmG4RV6KxXLGD0if/9DiTyk6D?=
 =?us-ascii?Q?7YGcz7ZzKwEdUac/KHcusLL7kmVNilFK2o3wJEtmc3T6/3IT0rAaf/Talsm2?=
 =?us-ascii?Q?IeroV1mH4eZHsXup8wE/Vx8GgffLNzF9rKx6l1WywRQhQgZjjQrz9FOTqZt6?=
 =?us-ascii?Q?oMq5QlGYVW8E2YC5DcWsUW24rx9AhnUE2INMfdEFxv9md0B1PzibdDdRPoGT?=
 =?us-ascii?Q?Lc7LZDROOTP6wwUHbO3sXjMFbBuBBarf5Q2vMfjg1/77IKCZwjwrNyeiMmFj?=
 =?us-ascii?Q?7n3yxiYfOtq820Oc2ilB3anBSy1P+VtgOY0jssBUhcvMh2ELMR7+vwksOfQU?=
 =?us-ascii?Q?tLM50sSrmgda7GSIAxyHPZYsuksXhBoRR6JS05fRTRxHY9iFqrFCLkKxe4Fo?=
 =?us-ascii?Q?ZWPNsVGVoRAt8umdbg1o8QQSTZfLbiv29nM5Gml3YnV6k9FNTgV/KrM+GOnG?=
 =?us-ascii?Q?moTnX3yTyZFn/HU67TX4K2ns0j2M8Z127950vnpxXQvlCtPpaHDXPyIvkqPJ?=
 =?us-ascii?Q?ppp/6oGsu3qRqAM7gtx8LdsJuloQiY5PYKvZBH74yxwBvdr27R6je3LtsbNi?=
 =?us-ascii?Q?9kvc5AVSZiqgnUqf9UQqwaJSTocONCh+D8BRh9ncE2q7iE/thCxmfjp+tPRT?=
 =?us-ascii?Q?+s5vXCqVEpcrLp8C8ctyzxiUatUju9joMuOh2EsFerCf7cgLH+osZfZWJfii?=
 =?us-ascii?Q?QF25rIKL4ZhpLEvSYUC1fu6wAvzXEGbV/zxLWcf2CDvuK+8kCfsXJhvGmdVb?=
 =?us-ascii?Q?mDiV4wR8nvxmMpHiBviWnZEjHnq0ZsnnefjaV/efPCPFHUZSTDv9+YMFGjmv?=
 =?us-ascii?Q?+RBqPjIYXosuv6X79O9YLowhWbifZeZccvmbAj9t+qnWj7vJLoEyojfkp33y?=
 =?us-ascii?Q?fcgI3i3GnOvPxe8rldCui7rEa8fAB7+qzyxwgb9ZlxVft7WKl8SKLXMmseEl?=
 =?us-ascii?Q?/qIvAikYhXJ5l5FzoBTlsg3YQhSuLMrlih1IBRjuEET/fi5rw3Qlg519coRh?=
 =?us-ascii?Q?GDErFr4T0AAVnJe36zx0tpU5rLekgxxDV+D6GighM7n4lyae+PeZOo9tgepS?=
 =?us-ascii?Q?Tx91bqabB4pZxB+nU1FoYcHTYNM9WL6OLLZW/Uy9aEEgrYvqwHf8lGnJl0tl?=
 =?us-ascii?Q?BKmOvppzkKi/Z2prv2CS+gbdLWqsMIppQE6Kvv+TP1C1P2njOXiQSn9JcvY+?=
 =?us-ascii?Q?aglG3YVdOli/+etZ2R+u0dAsbfzhEy+HxV9m71GKm/McMGlqCqt6s+J3QGBJ?=
 =?us-ascii?Q?aKMtknRkCMs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?O+2AYuIACUTsPC/uvnULkS5FV1CYCKlRgQUPUH80urylxVECIqPakeedyLFs?=
 =?us-ascii?Q?b/0UGIwNLng7/NcCzWnT/V4szZNxYXoE2wZJXwTbCTmvm0JgFWOmAL43HRE+?=
 =?us-ascii?Q?Br33CnJhyhmY+rUtg3h0MfrQHTocAjbB5s7v8L/j8JQNDVWQSQhUML2y9HWM?=
 =?us-ascii?Q?ypLelpLW6uSQaS52+OWL2KFnr68IlxgvT7gE+aU3ZipM86zuvRsPRAECp8ay?=
 =?us-ascii?Q?fIdJUos/TroTCHI5JlJNdB6rEoEeTkJCTWHe9wEIS34+3zlovvf28k6kmbGJ?=
 =?us-ascii?Q?S4RLIzBMgIMI4+hAb1B33KjXXjbcE51lpwpK+JPSea9Q3y610awtT6siEVrx?=
 =?us-ascii?Q?6AIpNw1AvtyfFIMp+Xlayg0nWdDjJNMd2hz2WCFJNB5i+1fwcY1muGKTEqM5?=
 =?us-ascii?Q?p9YZZJ5ajCLTd81CspWxblLVjpGgteD5OxCa1NSGoilpjeZonCOvxAlngctE?=
 =?us-ascii?Q?eyuEUuJNGRPcYtf7WpJswpTTuzFkInKozZmkQIbzkENoQsKKk+u7jpNxfc+3?=
 =?us-ascii?Q?cSG+jVglqdQLBBcGL1gVL7Nocx16UFhSjhZmb6MyeTrPKxOsWE9n+Vk+kr66?=
 =?us-ascii?Q?uHtVioBafvTMU5Q3jods913+yxuiD67Nyo/i3EzlQwtpq3ZNMDh45dkjQJI1?=
 =?us-ascii?Q?3gs4/t2GcxHgdCBg9RGgTF5GHh0c3mhilm9jdBKDZV4T0LsKDDbZ5/iavZO/?=
 =?us-ascii?Q?DD4W8JzElY8QOcc48qUCN8DYo458MSnN9qi8WNHjJXcJxVPXTLdr5S7VNRcX?=
 =?us-ascii?Q?9y5gjplcOFT6cJg69FSlcUMh56VhtELusLnemfaQkAm6NEe/lkRaOZpQUkoE?=
 =?us-ascii?Q?De94ch2/H5KIHpHhqFckTgAPCYwNnZXtJUV/5SzsN0u2fevEiYdoz3KcZe7J?=
 =?us-ascii?Q?9KKr1RLOhcBxqh/FQCDUEdDYZb5AF7EwtyZva6uQPuv5K+l13U529SIRkYkr?=
 =?us-ascii?Q?Rr9vlUEH6tJ7R6V1qTgRtddmVGF+ww0DGz83ItLwkvbDqLPQG9keUZmiIHFk?=
 =?us-ascii?Q?aGxadEvj1ktHCUyK+Afm3iZz1cEKLd35NsniLCfFLWYjlJGH/4+Fk+rKJHM+?=
 =?us-ascii?Q?bfZiBoIf8OQqD2wBjJLly6URBT5aROGjzSqKFOSiOmWQ6lUSnZgD4boEmoVU?=
 =?us-ascii?Q?+3+wEKwk6b0zl5AIfwrQ/aCoOoXrcDj/mOlbfqXWFFhBFxWU+HqXrcZrhG52?=
 =?us-ascii?Q?UxOz1qe9j5qz2qcV8WOWPzyvH72mYmRpvcpYnR9HmSZKrvm98AjS24Gd17UQ?=
 =?us-ascii?Q?tmdp6u0UiShOKp2b7pezIJ4/yQIUgCJ5ojGem4q2KLg6P7RJ/8D9lGrLRAwk?=
 =?us-ascii?Q?l7r3mVcCRJKdGepPvRlkh+WcbAmwiHmt/5FGqO4pZOdXNw6XLPLnxBeL+HBq?=
 =?us-ascii?Q?7jrNChYg4i8RfTiWwMfCW6R0Oau3xyixVGBVoD7tH+ZgKT1CvJw6BDuYPPKM?=
 =?us-ascii?Q?krxqziBt0jRuHbBh5dZFJ4nC+55ioINsUWsPpU/up7TFQSI/AEnWPgl8eHTK?=
 =?us-ascii?Q?mog/EASnQbm8PpX6w13GlgWrj4CbbUtoHo8ifsUP+XyvzSRXSupaKEKndBPs?=
 =?us-ascii?Q?HJX8sdAAnubbfhfucQaUNz/+oyyt8fVZfwKUViW8DiUohVXxf4WD80mE8MXS?=
 =?us-ascii?Q?Kg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 0ENtYV4CKfeavDGNOSGwmsmaEPhUwdhcuN4aCe13XZkOnAqMRGuq6lUwf5Ibe97h7jjnPGyWAulBkwZwdBZZscNsW0hcCLU3ZVZDr0JLOp2BEv57CsA1zAcJLo6hD2rQCJfIgOISTQYVUGOm9cSf8dTsUZnjpwqcrfsqhHnsCb6Kch3StsF6aTGH+0RwW1+XrQG2wKREDDimGizk5s5KUnBhTttcSqYkYSY/dEhm5ROhSNtaxFRGCVkrc5VpJxzJJqeypTMbE3kZ5X2L9VQCP6RiEv40WbzWrFZyFROisBJGFQAmcsgJfNs0lYZHqAFA0tPrL8oBK0twXLguY7Qrk1V98mW4ENFfVYB017MNNSvl+vXpoKD4DWKggQ5BKCQ4l+bp3skJ2zsqYEAGpzEMOsSKbUT/p5ViiTd6Eh6L4R0UVbgadZ1uRovvgMn8QJ8v2lgSmtN4SzNpf0JUKOdZSHe8BNKIcKaGcrzU2nC3asjiN81ssCceFMv8ATJ/wfZNNxD+Nyv+YTM+eHCt4nRqkddQeAPkCJ4c8LvqSIc3fC7uvJSXv7aGNS1IEm7HIJt3fRj/XORGnMr6FbIp5gw37ldvyegOlT1GMudAbIYVNGo=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 961c355e-fd3b-4be3-ad0a-08ddf61e081f
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:40.2746
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Jj7s+bpP0ciOzealvO1eGfzUPwQqNIUiWZyBBnDuOqyNVHnQvIumRKGEhWN6PsNy1RmhLTOiJwZI2SSLQ2GaN5JmiTdypEaI0yEeQqXjIF4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6063
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0 adultscore=0
 mlxlogscore=999 spamscore=0 mlxscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509170187
X-Proofpoint-GUID: KTTnpgrI421CcI7gatKIDumiEB0nNiyz
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfXzbe1WAuA6RMo
 jTXhzaipWhRQGuFRKVbgwcjCm2/uG4Avlzbf+N3sGtGTNiIumWMcr1v2RUvHQmQ7MceNm8O5dCV
 0bACRw+3jHAFd1lqBxz0hBWIMSiu4kO1w0jX/amuAh3HDZG6/EPJ88PSUNHsQe980sfwvj85epA
 AGi4zDJBfSyPLly9+q/rr7qWACG1Q68v4s0C0BDAR5IKavvb/p7nZvzvGtGF8BACyAb4OVEaISj
 MgItyY+JrgJNTjSlhKE5NO763MjfsoedTd7WeVGw616blERkDmO+w8CbudK09MBWKL3m/EvYy1q
 pDNk+vCN+wYxU091UuNYiIXCVCFSrdNuvvzBlA5XO0V5ezUBqm2wjIHI0wEPEMTtXySDuyg+3NJ
 MlBsu7ci
X-Authority-Analysis: v=2.4 cv=cerSrmDM c=1 sm=1 tr=0 ts=68cb07f3 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=CxsoVSIMbwK9moDqu60A:9
X-Proofpoint-ORIG-GUID: KTTnpgrI421CcI7gatKIDumiEB0nNiyz
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Emrtb9+y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=qKKNdh+Z;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Now we have introduced the ability to specify that actions should be taken
after a VMA is established via the vm_area_desc->action field as specified
in mmap_prepare, update both the VFS documentation and the porting guide
to describe this.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Jan Kara <jack@suse.cz>
---
 Documentation/filesystems/porting.rst | 5 +++++
 Documentation/filesystems/vfs.rst     | 4 ++++
 2 files changed, 9 insertions(+)

diff --git a/Documentation/filesystems/porting.rst b/Documentation/filesystems/porting.rst
index 85f590254f07..6743ed0b9112 100644
--- a/Documentation/filesystems/porting.rst
+++ b/Documentation/filesystems/porting.rst
@@ -1285,3 +1285,8 @@ rather than a VMA, as the VMA at this stage is not yet valid.
 The vm_area_desc provides the minimum required information for a filesystem
 to initialise state upon memory mapping of a file-backed region, and output
 parameters for the file system to set this state.
+
+In nearly all cases, this is all that is required for a filesystem. However, if
+a filesystem needs to perform an operation such a pre-population of page tables,
+then that action can be specified in the vm_area_desc->action field, which can
+be configured using the mmap_action_*() helpers.
diff --git a/Documentation/filesystems/vfs.rst b/Documentation/filesystems/vfs.rst
index 486a91633474..9e96c46ee10e 100644
--- a/Documentation/filesystems/vfs.rst
+++ b/Documentation/filesystems/vfs.rst
@@ -1236,6 +1236,10 @@ otherwise noted.
 	file-backed memory mapping, most notably establishing relevant
 	private state and VMA callbacks.
 
+	If further action such as pre-population of page tables is required,
+	this can be specified by the vm_area_desc->action field and related
+	parameters.
+
 Note that the file operations are implemented by the specific
 filesystem in which the inode resides.  When opening a device node
 (character or block special) most filesystems will call special
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/269f7675d0924fff58c427bc8f4e37487e985539.1758135681.git.lorenzo.stoakes%40oracle.com.
