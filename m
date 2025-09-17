Return-Path: <kasan-dev+bncBD6LBUWO5UMBB6EPVTDAMGQE732PEIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id B1D13B81708
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:11:54 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-424074f3f83sf2823555ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:11:54 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136313; cv=pass;
        d=google.com; s=arc-20240605;
        b=EhI48PkMIpXEx/aV40M8GEjODPwubR9uzSNWh36NLJ06uShBPeMv2CrZpYX8hq9KuA
         1wHzk1rDCWrtej//fzFN1QCNqBmCmgBxfRD2wAmO/GCWgXhH0CpoXhGeHRE8P0piSYN/
         +XWmGl2kS9K095Zr8nKaOKvhPExVbNUxgv6X4p0vDpkUPU6GoaZWmcULZtePhvdKqcSt
         6z/Mi8rDoADSYJrgCpFAvIr8RlAEn4vYwzx/vXy0F/KqxV+9yjRmrjNlGpmRracS7JD6
         ILkOY3pqfdDUHq1irHxRbMylJ248ziImPIjKySdXZTVpVCTVTWWewhktiSM+FprM+STj
         58jg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=400Jr5mmK7vPsUrlInraHNNoUreAUuBh/lsoOuthNWo=;
        fh=F2h5bJcmc4YJ4C8okLrMGDi6ZWSm3BYfXLF2GEl1ptc=;
        b=UOamBPpWiCTzdylnjkV96Z+80jHck/MNVtVQ3/TRnEiZXh0BCfkYUAyz/Q0fIx/xKY
         rRSXdFu4W5hcK3kLquMYA6CKtqrlbmuRrPbDUCFCXMLeE+EYOJyKrEWh+LLO4FFpH5Id
         zu4VkqsMexSJf8dGzVYN+Z3gUWGSbn0cJq5HoFCdKngFdbic6AvWWqPDZZR0oSIwmTmS
         BZJlrXteBBlu6DKBAjNQKCd4ObQXuXBq03OdAtb6fSPPr+v3zV/vlBlNRCljLRDfPDMj
         wTGMHlY8hPazVCGSUkpIpT9GuYqUUdaU/ctpviAar25lmVGbfhGUTgEzSTrHqh/oprac
         NWmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XeftUVu1;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=CrbzVq3k;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136313; x=1758741113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=400Jr5mmK7vPsUrlInraHNNoUreAUuBh/lsoOuthNWo=;
        b=rnE5NpiKXa1FjnQsrrHN/ZvWXE4SDXN8thArKw8vHfVBlPuYAdmQ0nUtsh5G6G0VzS
         djIpecCQ/Psk5mXUJ+g6KYm/kUl7TgXYFMg7dfLgiI5e8zZy7OxMp1bXXhFGnolxvUZo
         DpR4CO+775nXiKOdA6oq1oClHZgia8ruAX4EmuXf+oVDGUngqjvaD8IfSlQ27EENC/FY
         v/Sme+TGaDd2wg5PSwJl3n0uqk7ZLqVHW7fSSyuXvLIwtoUh4NIf33B+uUS19dP5mc2G
         IVyBm2CY0wR81ToepGwLJst8f2HG3NLqzPT6IP7ZMV7pJNT/yg5/Mo2BxhXCcd0j94eq
         hkEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136313; x=1758741113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=400Jr5mmK7vPsUrlInraHNNoUreAUuBh/lsoOuthNWo=;
        b=KXGDqe0ALvxGOxCx/oaIGbLwpuPIWpXzzk3QwvJv3saoSo2NkZFfIzk3ZBZ39oO6/1
         mruK48PQ8po5ufduQXN8HIIOsrClQvcJ8hxHa5EUkE02aHzOBxaJAIdJNDllUTxvmIGC
         fBPxxDBhaaKuLfFpOWNpZ0MA66xEkjtDGQAetKPtxi3z4KjWSdguFIZ7FiEJ1zIGET/y
         s/Xrl1HPEBtSkmIh3rkvZHdC6ooSNnNMEXmkvpBAcByXAdmBHdSpkGQUMOkQaAf6dFUp
         XjcrJCa5Nn3jQyGr2/MPYHNI+JOlfPjdFwBd0/Cg+xe+FNFDV7T/MOFvl3UC9fZhMLz5
         mIsg==
X-Forwarded-Encrypted: i=3; AJvYcCUc0yjvLmbsXd+0kb7iT3u6BB78uZJChqutBVcgrh93QNXFyeymryxN3m0TnQbA2EVjb82dlQ==@lfdr.de
X-Gm-Message-State: AOJu0YwL5FkLV/HLZmUe60cdsYlsy63G9QAU2siXyIOEbfgGAuRXXoht
	ydlYaELN90xwNyzS30b7DPePky+xYl1eH8JNcgwj4+U0ut7s3Z+bctzs
X-Google-Smtp-Source: AGHT+IGemWGhPAYSfSUrHPtgG4/VKgz+pnGW7+iQ1jeej8w1Cl98L+F1bL5v0SBEx85iUfL6223hvw==
X-Received: by 2002:a05:6e02:19ce:b0:421:7d1:7af8 with SMTP id e9e14a558f8ab-4241a5330dcmr39745435ab.26.1758136313146;
        Wed, 17 Sep 2025 12:11:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7Ptzmy6mZWHr4+ouQXohIcC/y4c2P9mkk8pNtpS0hPSA==
Received: by 2002:a05:6e02:d4f:b0:424:2138:a255 with SMTP id
 e9e14a558f8ab-4244c81e11dls731945ab.0.-pod-prod-05-us; Wed, 17 Sep 2025
 12:11:52 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWo0VxoPvbkh7Ht22bThaNmqE9d1034SxGe08loN5qchn0cLIho9SWTP7ZyjFvoPPGXHMlXaqjo0Sg=@googlegroups.com
X-Received: by 2002:a05:6e02:2307:b0:423:feda:f162 with SMTP id e9e14a558f8ab-4241a55da46mr55250465ab.29.1758136312226;
        Wed, 17 Sep 2025 12:11:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136312; cv=pass;
        d=google.com; s=arc-20240605;
        b=F9HCdG5DTcfKuPiqReM5S+aDLNuIubGhDd2zThmiOtfTEfRONMg1/z+5ssAfXSEcKV
         LpDn/1o1yfJm12vZKMRf0HSQ4CF8W1bc1/zDspPagD4EZ4XjWjW+Exk1kkLVDT03T3ka
         k1D081RfRcr/tyVbY/PVMjwbwo9wDdGYS+WItSFulyYOmxKCvO0V9Nn97fLUNC811bGh
         2heNSTfmpyY/8gypeli+iinEUk2h2oKWg0e9JrgOC1ajykkhOyOBRRjEllikp3RUBCoN
         kwINM/ESCE0emS+BFBCDoC7Q0OTBfINSytM6vUNcQe5BsxRiL8zGd4azm80zQGrEb8Dg
         tkZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=esrzli4+YEEqWyBETu3tv+dfK/pvdPpC1zpkqMlWctc=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=DQpz4DhaRyaW031N4kMAX2eZ9p7/8voVdqKZZ2CvlLokYogGjeaa2ZoWpo7hAaN6oD
         tHpFYD8LBl13nCjlWo7Rn1fBLOjNHtg6KFFowoftNkr/8uI5z8OZ6flxYcZ+xRT8oqH9
         Fnr11n+DheWGHOG7pBL7R/lpErEe/eY0iwlZsRAxSIG9ta9BVVYku6rKYGlvIX7Mgw+i
         9b7a6jvsVh53nFZ+CT+xB0AgAmv2Hj8l+4PcFT/ZCEcFthhSj1Qla66tTq77lRRsJdj2
         ZxSW1ninnyIDm/xg+bRw6X382V88XtJEgHEpv/6EVR+4HFZDamREzjDxcm9WEXgeAF43
         N/pA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XeftUVu1;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=CrbzVq3k;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-53d37e63300si8806173.1.2025.09.17.12.11.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:11:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEIUwl008312;
	Wed, 17 Sep 2025 19:11:42 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx8hxne-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:40 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HHmk6c001628;
	Wed, 17 Sep 2025 19:11:39 GMT
Received: from ch4pr04cu002.outbound.protection.outlook.com (mail-northcentralusazon11013068.outbound.protection.outlook.com [40.107.201.68])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2edr1x-5
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:39 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=NEyoX0fy9QnnXPkfu4Ud74XcoKGhoB40k0yiSmHDXOREjugtpMs70X4LZGdWpmDGQCHCiwuN4Z4P/Ke9D7i/jxv22OtzpZ7V5NpD1awGyQcE4bLNlwR+GNM3LE2veLh1TSVF8sIEjelTrEqgtCcULCpaiX9IHC81NuB8mCBdJ+oqHdSyrLVDp2tw50qBjLDAWAohbewmD/kugVtfYTctP4FL1naiAGQk9FwnkhWka/dRjRfDmX+TVM779pk9ZckboDugzGdLdm+7h4zNOokLUMa1qviqMEr8XQ/uWE2rNfmHckjJEE9PMk5a/iBOCTSPPRGCaFVyiXVHAJZD7zJSVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=esrzli4+YEEqWyBETu3tv+dfK/pvdPpC1zpkqMlWctc=;
 b=eCMa7++TiWhPThu2dnIGzlwkPx+6bM3NvDOIFpjWx1NRylS0V6old18JCrDEaCa0xAp9B0E0FFwgr+nlGhSYmAD2ZBddi3NV6Q8gISJlOaKESsaFUtgjFBKSJnAqKbxq3jqJJB7s/ZjVnKvFdkAbwGF1Tfy2uVJPAynA49uAEDDznsC7HothdSANKZM7FSOUJMmPHKXzRHUPvjGGoAFYdt9Ah8ncDFkW8gbLzP3oQ1gXMFB2eeXQx9j2afm+gqh2aTEj2FSIPdrPZB79NBD0CVNXKtA3QjxNvPjkQawMSgfw+d+du/ZIOKCGk/LLuiyMOG9aRisPYuMN9xWMb/1c9A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by CY5PR10MB6189.namprd10.prod.outlook.com (2603:10b6:930:33::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Wed, 17 Sep
 2025 19:11:35 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:35 +0000
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
Subject: [PATCH v4 07/14] mm: abstract io_remap_pfn_range() based on PFN
Date: Wed, 17 Sep 2025 20:11:09 +0100
Message-ID: <4f01f4d82300444dee4af4f8d1333e52db402a45.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0399.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:189::8) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|CY5PR10MB6189:EE_
X-MS-Office365-Filtering-Correlation-Id: e0fc1fa7-14f9-4fa8-9dae-08ddf61e04e5
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?aiHyp+9u8hZ1SP2ijhqjz1uSq7n94b9nwRrh+jDbKzQTiGJTtpPrwPWb29H1?=
 =?us-ascii?Q?laIwNosp4wbJvrsoB8gnfNHihWkXfEIKPi28XVWO4O6CcDRwR2ouq2LC7FLB?=
 =?us-ascii?Q?8tBXNQp1r/Anj8RtowjXmwbPZhsOuNIR6lWgGhUhGGMYm6QSDg9zHvYHdVnP?=
 =?us-ascii?Q?PCSc0ZhvOMDGzcaQSfw7jxcwAUmooDdod618LYCph86zHI/Zm4LkB1Ukomc1?=
 =?us-ascii?Q?0WLVBKwa3CmIAP1KXpbk8t8j3ckW+yDrSURLzix7LGQAGNh0cXb0mY+f8hbI?=
 =?us-ascii?Q?U8UR/gBxaaZYFCPjL6HudWpnXho/ozvyr3/NlI6AEgcnhLb2KMRQKz19M3yy?=
 =?us-ascii?Q?VzhHlQCVIf9WYDvUy+h0TyCkmK1KuPCS+ONj3N3gWSg7Vh92nzUavw3s758Y?=
 =?us-ascii?Q?coZYMVck+PXB/4Mhw4ffYQKtz4BCA+hl8fiYRpmHWxMJVmvRpQLa7w07w+2Y?=
 =?us-ascii?Q?LfoMdmCk4kFsEDWzIpqd30Jd1+3gCXu+662VxuvDPOu/WVtyU5OVQvKKLDIH?=
 =?us-ascii?Q?Zzmw/V+OLbd7mPiD6K82YtXybLvCVgS0d+NUF5FizALqkVaX/PQDQOvDrI9E?=
 =?us-ascii?Q?9IrdFiSlZ5FH0XNxQOJEq4ZblQxY28h5zRWi6E2uPFia+GGA0r21nLegsf6k?=
 =?us-ascii?Q?H87w09cyX7vlo7pvJUv3le8iMC/T977xdcIbtGA2BDlxpr3Cs9tTp5fNZ87q?=
 =?us-ascii?Q?LuwjzgDjayJok0Uiu4CnwKrnR4k+CdK7CPh6TWFB8FHHLRAhZTssNYcGD346?=
 =?us-ascii?Q?4o67xeQhHqCKhlkcpvQwwkI+HULKTmF1juLrVif9qCdPSWVjKQv1poZ9RM1z?=
 =?us-ascii?Q?lq/OT+6dEdIWbAnHdjzf4Z+EKqcabE/dor7hO1mIqL0BxTHbiVhpDtD+WLpn?=
 =?us-ascii?Q?9A6M3sjbkddQxvcCR+SRnHQEdNj+I/0DM41G9ZYcotN+jgM7Z2LEsnkP4LHN?=
 =?us-ascii?Q?nI8/7xHcsp6+1QSf5t6k9Q5gElCNBsaf9tMMLVq2grazHrsv9CzWc35OklHC?=
 =?us-ascii?Q?VG9usS0Vi4bfltrppNVrNAghQLhHuRqdVoAiJfBCrWpqAd7gpSbtuM4bFG3I?=
 =?us-ascii?Q?4sy3FmIDY4AGMf6ILXCcpaLsb1V6pMc0+Nc6pw/pVwJWnFZ2OqGAP1MnxegF?=
 =?us-ascii?Q?dcreBdAHni6H5ek/r3XdindwglLXBjg7VVvYw/dItp0jB9XKUnZEoG6M7jGq?=
 =?us-ascii?Q?pRT3T59kOaWpMNUmXWNthqkxLrJpU0+VA+fDe8ll3nxsC550rRoAKpScKlqg?=
 =?us-ascii?Q?SkNFB8AgK5FYnLL0wjepLvUjZwQERBhioswzWdmNBRaGHpNSz+4odAXLtX0b?=
 =?us-ascii?Q?Rih29spbIxSd9Sp5oR6Xp0oTKCyuvIsfxDjGXBHG/otzwf8/qJNk0s/zi+KN?=
 =?us-ascii?Q?oSNq4Fvqk/RpRNOHOxO5LRw5CMHvCLQf8cOp1INzflx0yealrg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?SZb4W/xdg+rPiyJAtm9QuhwVWjyHx+M5gg6zcVXtTAWNNMPfmhziINMdfweO?=
 =?us-ascii?Q?Eh63MUyG4NhcJmbn3uws/h7uwSo9WqRUsA2x8spPoVCqjtLwRBTVhnsO0GHo?=
 =?us-ascii?Q?jPx/JgQy0hJqMemBLKvlJQc8ijIjbvztNDur6wRBH877P94hSHbogvAldPm2?=
 =?us-ascii?Q?NMjDYc9lEaGBPQfi36baxO+JI7MrJ+GiN2Z0lDgD8s/4ZdnxOnUt1sUBErg+?=
 =?us-ascii?Q?+DIG13BIVC1oEXmpQ1P22mx/P2F6dDUvm1bfcVIV83Ig04E09AJpO+cdIWph?=
 =?us-ascii?Q?nWgpVkNNNQ5yAds57ofgDj9GgQghAW8aHEa3LMBQIS73O6iLiFQiDjTkfTCJ?=
 =?us-ascii?Q?JeofbQq2oc9uMPFpYA2ayBrXQgd/uow7fnVw4m7KBbaimEgr2cnpI3om9lXO?=
 =?us-ascii?Q?2eLiORllv6DfpRE9+WlBscOfavt32Lfqpr/qG8MQYGtJjZj2+x5oq68QU2iz?=
 =?us-ascii?Q?gixrGAcaVYuXk7u0z6l2TlDg2KSaGc33rPva9W1QCPUeVq1Vc5IbfI4fxeFf?=
 =?us-ascii?Q?M4/FwoI+IQH85O6f19/+4R84iq7X8ON1kd/HzGVzcnTU/WZ5zjmenNvTZOT4?=
 =?us-ascii?Q?ic34ZpZGcmLNg5v6MZ3qigbeCaTsZTCn5b4qov5SjjH/5Xh4ALppFf03/dBr?=
 =?us-ascii?Q?2CUZ78jobaZLhtDAMSrd3sg0vHXxUm0399z7E0H5n7Ie8UfMffXc8U9t74+G?=
 =?us-ascii?Q?72gqWxlOidXnAYkWBvPYRVbWCs4JqB75n73JokawY8YOEIusgj/K4nT9gQi/?=
 =?us-ascii?Q?7lcYNuZOVX5z9uQ2zT9WfPlKOY0gmS5EaGtLVlB5C+lCpZ9YfiySZtDlWSx6?=
 =?us-ascii?Q?q9ruQDw++eb7UXxj4mNnp9jY4Uc/j0epjf50zLFzqayvcQyVXDF11u2mM4YA?=
 =?us-ascii?Q?OmdlkHrbN/9o6rVYG7yB2s+oPFE0xXmV7f2+0NeSeVSum4pPrrZCLz2YaOQB?=
 =?us-ascii?Q?v94mi3U0E3184yWmA1i3iabJUJWH9GS6FPROEX+26jIuqMPbbtF8kklhkLES?=
 =?us-ascii?Q?gglMSpVp8+E7W0xPVsUHQWNZTao94Gr8971s8jwsShQ1rZXd/+fRls2u4C4V?=
 =?us-ascii?Q?ZYCeUORhRd+DSYbu7Lni+D7+C5AzQsj/wuhzajhMa/3SPivtbK9IGOhswx4w?=
 =?us-ascii?Q?kNdj2+xybl/ca3JIfP32ETq/CMA+co9tEtM4rnviiYf6XZdNCdElVCWxt9Zf?=
 =?us-ascii?Q?bAXgOLN3dhY2Mpqoqw87Sc7BQ0+cTf/ATA+c42K9HNAMAeiCuHMiD92+jZFq?=
 =?us-ascii?Q?pAGeHlAd9hYVG9F7nMKIIw63/Ayg47AhwbziNNmjet8YIGcHuCQrD7gf5T49?=
 =?us-ascii?Q?0/JtT1eVzHmmfFW+HgWMnE/1dJKR4AP12pSkyBYDvaG34RO23qlmDsQ/orCK?=
 =?us-ascii?Q?DlcYQQUL/BIwH7e9eEHE1F/9V6iJSZetzcjd0iD6s7EVxgY9pXV8kvNPVift?=
 =?us-ascii?Q?qNr1vEheJ82zt5gGo698YDX+ecYF9DuSkk+zpm3QRbqK9tPuwF2ZQTRaeVUv?=
 =?us-ascii?Q?iT2pM017K9kngxANoQ21o8IvPoFJlrK+Zjt1XtwEg6cZytYwtQSqMwev2KCK?=
 =?us-ascii?Q?FkEG3YM9ea38B60mrng5ez/MWSGkANLOUBRjfJ6diX3jQPmDLVi9keReSFZr?=
 =?us-ascii?Q?zQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: iEQUGzvnKnEChsf7kaOF92MapphD864CplOIR/9A/lhoh4BgRqWekimycVwmV0UZOQiuHdPdvvuatWN2wpHWGMhl3Z9yvPx7neP5xRUITYAsm/nI2F4CBx9xKHV2T6WaXeBt+PRnkKBP0sQqEjcJjJBwzf4qThyMrdjmmCMaBHzXUE2smsay1Z4nIDADvE49AgHtZdefGjlE7dpdfGbxF1M9ev9eTECxXCnRAf5q7yhYK3H0h+82a784S5PDY8VfM2+kwLOA+rp58EqaA1Aaplf4XivTIwcEfkikfIoeV0SnbuNoxIsmT4CEAJQP/ojfKHgv1NvFUNWuxa0IGfmmcXW5I2rxC97ZJBpkGZvzXXpx/Bv6UK798LAEquHt/pOc5sKpbFbXASmIN+vMgCjCLYg6JphmKtMs6oyvTrvFrTjD/SScSLXj0mGMuC+ruXLnLhLFKQss1yG5ySe/wXsOZTLQc6Nia7uiun5HOOZHdpqqfB/8B7lgnpXbSQi7Aa+mVWa8+f+gfcfVhCLO9trgj/+U9a/4bpUhdn7XpS8yepJeSsguUvEGj7exRsOg7WGZX0D4RrJ/EYiHTPt9csi+chro3zGujMAn0nnU07Albz4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e0fc1fa7-14f9-4fa8-9dae-08ddf61e04e5
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:34.9356
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: OswbYRYH0ILwXrmqugLV4m9j41+Ae9GOJcim06pD3qQZROh1DOHYY04LT+5j3dZvK6mmRKTcAp+4GN8kgR0bZFPa/vS+LRqVL9PU4S0iQQ4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR10MB6189
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0 bulkscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509170187
X-Authority-Analysis: v=2.4 cv=JNU7s9Kb c=1 sm=1 tr=0 ts=68cb07ed cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=Ikd4Dj_1AAAA:8 a=yPCof4ZbAAAA:8 a=d3CWW7REp53awPo2IZMA:9
X-Proofpoint-ORIG-GUID: uOvvLWiJ7PebyfTpFNbr7vqK1Zs1AHfY
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfXyvDEoqhlSAHZ
 FTzQJHM9SQF2UNF7RoNqzcTh5BYAFLo0t7F46u5uOzngs5JjgWR9manvvX7UTndTkntD8b6KCJl
 2C06EUzkgerHdCdb+6yB/SIAHvtVwazPXe/SpXuIc/DRZxx/166cfwjXqiZ23qEg+ygQmeEcZB3
 vdOexaTuwVwMAI2p9N1z/FZINK80g5GJ30AxU9t/WF1Z2g+G8CNEIA8+vYW1dCr+VcsNhNMDJAb
 GjZAN21O2Vr1j0aRf3Cq6eKvQwb5kzXJv5qMa9yqhahS3h2qd0DuY49aJxTkLvrXg/u6ZLw1GgI
 LE3NFUzPILe9ZDepK150fxT/6Fl9sour9bsjOHNydovlulf18zRZeJor8JzBysJEb0IPerXV5rw
 CJSN8hok
X-Proofpoint-GUID: uOvvLWiJ7PebyfTpFNbr7vqK1Zs1AHfY
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=XeftUVu1;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=CrbzVq3k;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
customise the PFN used, other than the fact that, when a custom
io_remap_pfn_range() function is provided, the prot value passed is not
filtered through pgprot_decrypted().

Use this fact to simplify the use of io_remap_pfn_range(), by abstracting
the PFN function as io_remap_pfn_range_pfn(), and simply have the
convention that, should a custom handler be specified, we do not utilise
pgprot_decrypted().

If we require in future prot customisation, we can make
io_remap_pfn_range_prot() available for override.

Suggested-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 arch/csky/include/asm/pgtable.h     |  3 +--
 arch/mips/alchemy/common/setup.c    |  9 +++++----
 arch/mips/include/asm/pgtable.h     |  5 ++---
 arch/sparc/include/asm/pgtable_32.h | 12 ++++--------
 arch/sparc/include/asm/pgtable_64.h | 12 ++++--------
 include/linux/mm.h                  | 30 ++++++++++++++++++++++++-----
 6 files changed, 41 insertions(+), 30 deletions(-)

diff --git a/arch/csky/include/asm/pgtable.h b/arch/csky/include/asm/pgtable.h
index 5a394be09c35..967c86b38f11 100644
--- a/arch/csky/include/asm/pgtable.h
+++ b/arch/csky/include/asm/pgtable.h
@@ -263,7 +263,6 @@ void update_mmu_cache_range(struct vm_fault *vmf, struct vm_area_struct *vma,
 #define update_mmu_cache(vma, addr, ptep) \
 	update_mmu_cache_range(NULL, vma, addr, ptep, 1)
 
-#define io_remap_pfn_range(vma, vaddr, pfn, size, prot) \
-	remap_pfn_range(vma, vaddr, pfn, size, prot)
+#define io_remap_pfn_range_pfn(pfn, size) (pfn)
 
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
index 7c199c003ffe..fd7be02dd46c 100644
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
index 669cd02469a1..f54f385a92c6 100644
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
index 8e4006eaf4dd..9b65c33bb31a 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3672,15 +3672,35 @@ static inline vm_fault_t vmf_insert_page(struct vm_area_struct *vma,
 	return VM_FAULT_NOPAGE;
 }
 
-#ifndef io_remap_pfn_range
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long addr, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+#ifdef io_remap_pfn_range_pfn
+static inline unsigned long io_remap_pfn_range_prot(pgprot_t prot)
+{
+	/* We do not decrypt if arch customises PFN. */
+	return prot;
+}
+#else
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
+{
+	return pfn;
+}
+
+static inline pgprot_t io_remap_pfn_range_prot(pgprot_t prot)
 {
-	return remap_pfn_range(vma, addr, pfn, size, pgprot_decrypted(prot));
+	return pgprot_decrypted(prot);
 }
 #endif
 
+static inline int io_remap_pfn_range(struct vm_area_struct *vma,
+				     unsigned long addr, unsigned long orig_pfn,
+				     unsigned long size, pgprot_t orig_prot)
+{
+	const unsigned long pfn = io_remap_pfn_range_pfn(orig_pfn, size);
+	const pgprot_t prot = io_remap_pfn_range_prot(orig_prot);
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4f01f4d82300444dee4af4f8d1333e52db402a45.1758135681.git.lorenzo.stoakes%40oracle.com.
