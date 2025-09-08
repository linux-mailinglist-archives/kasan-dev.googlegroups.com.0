Return-Path: <kasan-dev+bncBD6LBUWO5UMBBVXP7PCQMGQER75LVDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13e.google.com (mail-yx1-xb13e.google.com [IPv6:2607:f8b0:4864:20::b13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C47CB493A0
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:35:52 +0200 (CEST)
Received: by mail-yx1-xb13e.google.com with SMTP id 956f58d0204a3-60f47bb49f1sf1912887d50.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:35:52 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757345751; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q8LRMirLNyVhlkE/STukXIcmy3wOVHDdkah+cK83myFdUJfevqZGCwcDOHOl9MpIM+
         oUp3GmKWktWWufMMZsAHK1+P2Hu8EQcvNfkXmVKTM/aW+Nt1EMbqsW/m8n+iJbzbUE59
         29uNA8sR1+UM4a3zrzSHGqXgM5T8v9AlM1m4ZjB4osiu0y0h1GKsGon7+H3BGWwAx3pu
         l8P97wksAmvkGlhsjvjGrcDsvzyEgbnxXfv6gvtBvXFNmxLfRJflwVuaM5d8b9nWdQF8
         jd3ZkYQhF45p0NTGn7tpxMG/M7IPV11LHHCX2KWZz1p8hywfY8sVDFTOxUh6uqQOoNq0
         F6PQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=juOZOASKkceuzpJcLtV+TtRRP2M7puxEbpUpSj//ZuY=;
        fh=mnWi3pDFRcBdFCOA7rqy/knlThRmhs+FaNc7Jskizik=;
        b=YBfaxiaBqurzF7ZNwGKpnYAkrG2pgXXfsMn7UyRNkKjuXw2cpnMXETJQUKj81oGxtK
         AtYs/4SmfZRSuJtjn5wEp32ZFumbs4NoKrWehGXQgU81Yh6ebAqU1VADE+8vw8rz/X5J
         GY3TXHKTfrKws6K7ORgsua+h9KgjEVNxYMqkTyybRb1lfRhpruvQXwXmvF/me0S4tshh
         IIUIZ1wob/luqVU3ozghZweuv7vDeX6l5wtxCq5uTHEz6Phhqn892c8MKYGqtH1KAtK0
         HBO2PKiwtAXOgPirIlZmh7hmNW3A9zW0nJStf4OsDzDTPmoOmzRptMfTldr2FUXJ8qVc
         wF/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XByJjYp3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ULoCx6Rz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345751; x=1757950551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=juOZOASKkceuzpJcLtV+TtRRP2M7puxEbpUpSj//ZuY=;
        b=Z2hOHVjr2RNDdvuLOOIGq5misUvXIf3mHF72O7PXNJShBnG9wtpSdu7FyQ5VOjr+8h
         lyxCmRDNZ3rmGVsVNpJNxOXkY/gCCM+q5SvxdEBLO92tJdBWo1u9O9pDY1RK0IrIGuKt
         tlrjqBUzgZH13ZoFZq/W31uSZSNhp+9Rnzo7RX9idJKSdDVHMHN6+Gn5XG843zKX9WOY
         7orIFan6epgoMAIrbEeaLovJtn+TqSF6QrdYejNxgJVrIESDe4ro8I0z12kZAah4lzZX
         RPy/uCaUb7ch5HtbWHBoQuGvI3cp3q50uCAnoFovKe9O2wJLYZI9pO0PMX+6PfD8CYqK
         3WlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345751; x=1757950551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=juOZOASKkceuzpJcLtV+TtRRP2M7puxEbpUpSj//ZuY=;
        b=LLrpk9npfvMvK4Udk6/h9gT33zqanukHBiCfWF19DuftWUpjVy1unvf6c/h3Ud3E3a
         tZnD9vl44FgxR24gNZOhvDIfZ2G81v7Qo5jVC673GoIfQPGw/n6hNag7G8bBQ2Bq1v/D
         Sl76rz6UR5ocvDDxq3NMSeD0h2qmr/keiolmp+Dm9cDlc4KAdctsfvU4HynKMbWf3HDc
         6+ttOclBsMaBNYMM4bYiMmko8ab871K8mmVqknitWeewuC67R+fVZomAt0Gg5U6YWAbq
         vjdjstn/axyVbUQOT2m7JO1by2zoELNHQ4j2bfDKmCFRX8bKzAhnq7lSLBABDRC9P8ip
         PGnw==
X-Forwarded-Encrypted: i=3; AJvYcCWWP1KIx2Uh1rKCCKs3wyXSoHuwATXCZIt2BQN6MNxSWxRRNcB5QE0hjAxI8SIuwIl1mo6Tuw==@lfdr.de
X-Gm-Message-State: AOJu0YwwGUqixghA7qRgfxw4/JsqAnPK1EJkYShbUliqNGeE+UY3jP74
	KfIRxHuqy8v17DkpUSpJEO55ASo8ct8O1fsNrJQMXB7DXY7YyUEmGI6b
X-Google-Smtp-Source: AGHT+IHAm2LQxc4CwpFFup4Eq2N4hR8fp3Nn+vSQhdfr0c2bD+fVTusZur3CSWVVFfHXrtbUyKvOaA==
X-Received: by 2002:a05:6902:2191:b0:e93:4787:2747 with SMTP id 3f1490d57ef6-e9f67991122mr7076997276.24.1757345751010;
        Mon, 08 Sep 2025 08:35:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd49w5dqZBnKYIaGwZN1mX+qsrwymp1dYusHyAnb6de0dA==
Received: by 2002:a05:6902:2d87:b0:e9d:6e39:6d48 with SMTP id
 3f1490d57ef6-e9e0a850083ls1018295276.2.-pod-prod-09-us; Mon, 08 Sep 2025
 08:35:50 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXeYc8m0DaksmlziZRomdurW7Eqfobm3zK9JEQeq2MbKZ9ceHP/oWPhFKpu1UDdGJ2l75QNXeQqKFg=@googlegroups.com
X-Received: by 2002:a05:690c:30a:b0:71a:34f4:7530 with SMTP id 00721157ae682-727f28e3a55mr60578127b3.8.1757345749867;
        Mon, 08 Sep 2025 08:35:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345749; cv=pass;
        d=google.com; s=arc-20240605;
        b=kE5F3T1TR4IunAUw5gP/79aw/QG4i8pWCju6IfsmER0MX/ggk31yvuwPmbDxo5uRKs
         rpOkl1zlsOojqDNJzOnwdS/kBOyd8TQbCOuGHdirElmNBIB/D0cmbVSrouj0BToPr2xN
         UjBlGSObWhXDWe2VHhNop4R/qBFPYmzxXmuPSescQs/Q10kAvTlp36EkdOnb6yIjU09K
         6UtMgWD53IRn7E9mwn04li0d8W4i0La4HDIbDk3bTZ5PT5aSjCIISEsPr+h32FrX64Uh
         aAa0GLqfFnJy4vDkIazjOWsdFDRaw2TCUBkuRi+YxPAXbLnKTXm0JtGTO4UIt4kM4Yui
         OF5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=ikXNTcHVvEsKk9Nx7itjKZwYDa5C6eOkm48i0GwcJWg=;
        fh=2af8N68QYnJpd17/7xhpiRlIgvxld8TIWYgdTT6ZNWU=;
        b=MgOLOkLFV+peYPkV4sNiTN4fKvEGUJ4vbJaEd7c32De3qrjMGi+B4eCo66k7cpQgIP
         kDkxsT+dxaB0UaRZnLY+35uj9mchPjmRMIcmJLNpa71ww+fDLq81WssXh4kKT/IniFVn
         LfdQmFEpfEG6Gk1MYA+iryhOrZCnYA8e4oNJVHe0MYLeONk8pitwwtLUVcy+FEUvkm18
         zvgWmu6vbZukEzDTsFT06Z+Ky1bstateejYeEbdjRSgWchk/nabNu+3u0TvpyvENXdWf
         1x/9EZTnGou+Tdkg/cerZIc34kJ49LOnxCIBXPF9nyQmJAryncKzwKvBD1zqmnxz4rRH
         J9lw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XByJjYp3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ULoCx6Rz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-723a7eab3c7si6959767b3.0.2025.09.08.08.35.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:35:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588FF65K023717;
	Mon, 8 Sep 2025 15:35:49 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921m2r1y4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:35:49 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588F8k1G031517;
	Mon, 8 Sep 2025 15:35:48 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12on2058.outbound.protection.outlook.com [40.107.237.58])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd9cgy0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 15:35:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SHBbEHWDRXDlIoSqpnteufLSCkwUkAYab6r7Cexxm9kwPw92eE8a7t55dl3gy8gdJtmNbRATTWEwEIm0H4yYOvi+3s2XMRFYX5fjYL+Uyit1R9ah3S09W9U6ymt5ImOacSNSihp/9hvCI50bKkvk5jJyAe0e6nw8bsLHMAHqm1P6zr/74BabVz/gGPnckYE7vrl7u9wmUeHtcCIWM4ggUaz1UDMybKJWEaorI0N5uLT/6/K9M7MefzH14V7xeH82NL9QllPN6CD/IHmT6PpOyLmajcvbdLTBgtsLvZdiOX6nb06LIIvWmcPgk9093RVur7nvnX+0lQiurSaYuQ7B8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ikXNTcHVvEsKk9Nx7itjKZwYDa5C6eOkm48i0GwcJWg=;
 b=dyyCxNwvSXbI1Ibj2BWMHNG30RHcvO4O6qcA6ohw2CZkhreF693Ezp07ou1MYDtmxSs54cOk5vzOeFoxXlWU9mzJrhutdYxwf81VlAwfNqnLtcTzD6H3kEMEVVA+tDKE8F0m2E4dwkroBOMOOoQjsLU6qVDnE7GFS3+v+edHDbCVpwnLgd+ga9o6/Q9qrr43CuM1cuykHp3C7xet8LIaNDxvcOvUzJIV0zf6ZoFEjVCsTakJ3fvhsexQT4jYKTDJG1we8wia1urMejYSOnJqwj6N2oLohea265j5OrSBw56WG2PkOlGzSJ+7L7HhNi1oTCVisFABOiE5zgEBlMCIbg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF6AE862AC6.namprd10.prod.outlook.com (2603:10b6:f:fc00::c2d) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 15:35:43 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 15:35:43 +0000
Date: Mon, 8 Sep 2025 16:35:39 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
        Andrew Morton <akpm@linux-foundation.org>,
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
        kasan-dev@googlegroups.com
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
Message-ID: <d47b68a2-9376-425c-86ce-0a3746819f38@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
 <af3695c3-836a-4418-b18d-96d8ae122f25@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <af3695c3-836a-4418-b18d-96d8ae122f25@redhat.com>
X-ClientProxiedBy: LO0P123CA0013.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:354::6) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF6AE862AC6:EE_
X-MS-Office365-Filtering-Correlation-Id: f7514a03-7358-4c7e-07be-08ddeeed5f84
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?yL1ka4/gQuzP8ybRUKqDqbOj1YEhmZ+TIuMIXYUw8dICxc7MsMcQ+PsTR6m2?=
 =?us-ascii?Q?OFslpoNTc5INwqUSzRWvP87osrbZB6wLK90CUr0XW8d2rRffDJo54q9MhiFu?=
 =?us-ascii?Q?zY7PCp+b6TDdP7O/AbuCJcYC+eP8PhGhkPnPJOBjVFEOXiQRyMq1rH3+ZVpw?=
 =?us-ascii?Q?Z+7/ZqJc+rflTFO3dF08HPJfxROvftwrhpRimanegI8JJxJvxHUqBtj6On4L?=
 =?us-ascii?Q?kBJfeFSn60Ja+ZO+BLhW6Vy8vsRg1GvoL+llKNbu7i9FDlhxx1zXNlv/Fr3p?=
 =?us-ascii?Q?GJGVLVgh+Kf0WUV2/zua8wrEt9T6rTWd5HIYWXbDJdioo6dZUE75QsypKfWv?=
 =?us-ascii?Q?xOaPXU/FPwSRZPXucms2nEX+DYlzNpCDCkJ2mWE5x1HXdxkG0Q95DSJfEmtp?=
 =?us-ascii?Q?2J8EwOfD2QgWHEqA2Jh/Ji03VuKGMP4Y14qSqoKzAiq7Bt25V/6qttYpbyNp?=
 =?us-ascii?Q?d12L7SnGdkSMaY77LZ8F8OIv3MvHgWhN4QHNrU0ToWOZ2B+gSOxHCUNA6MG3?=
 =?us-ascii?Q?5dAObCabs/wOe0CDK6/xxkOKvO2CJ9BI+Fnj6HR6us+aIUi16e1sVqvDr3B+?=
 =?us-ascii?Q?3iW+2IgQKRW60bV52J9ufgKyeFeiiihAZv+pLAmJkCbBSp75dpHVkgDanREc?=
 =?us-ascii?Q?enI6MsvmVmg+jAxZInoqvrsNl19Xd6baUG5VGf6Gn0PvuZMRmiocZnz2Y7jT?=
 =?us-ascii?Q?4CwVp9hFILIkKTdz3RWMFnbAJDo6oPtbs8YuFFHIArUZ3JT8fHoi1u4t88iD?=
 =?us-ascii?Q?Loh3ybJLthFviJwg0ToWHWYCKOt8tDlNguxN+Cgid5g4vFdNQCKHcW0D7ZNe?=
 =?us-ascii?Q?B8YC+6b/EdlVCUWxBidq+3nupD5T8QQUt+g6PdGnlgiNLiDhNtEBkWF/Vtkk?=
 =?us-ascii?Q?7tAfuVuZY3g0HCN29IowVxOT8/aizYi52QMkN4IrXjQW+dR4aWp0DCl90uty?=
 =?us-ascii?Q?2TEd3A9eruR+BdAyt2pP/1BRF3RsnFENB3PD7v1kpDMqQSgQLQ/dp5Vc3t5P?=
 =?us-ascii?Q?yECjpI7tpBMEgtvrpryg9YV8i4jxZ5knSZtSPYq86CDBsav8OtJGR3XL6GBR?=
 =?us-ascii?Q?S5kQ/v5TYP+JK3i6wphfZqXEohDCyVWCZHk+n4+KOU5saMni4XpzaHTGHZAG?=
 =?us-ascii?Q?JYptQCE3LCkKFG1tCh1EkqzTwXZcC8J2vzAdd9T5rFU92mosaTfAwZESptTf?=
 =?us-ascii?Q?J80KKuCY9Re2z98dqeRpwTHe399cr3YiDAPYrtfPOxD+7VM3aqvO+0HRwKgQ?=
 =?us-ascii?Q?ygCxTu2yWzCg1Ibr/s7yCDenM9m3f38kkx6xpY9c9gIBQaGpTeNFq5Rbhvp8?=
 =?us-ascii?Q?n+OH+y50oIfVCFGE7NiPmYZU8MZoLWJhcj+UB4DLZjYesmRJE2FAsSG75K85?=
 =?us-ascii?Q?lzdsEThLUcTLMFjU3/m1HE353fVYGrqsrXTuA+3FBVYzlhtzJA=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?AYSddy6dVi205aRXrTDNF/WhoAmRWti9HwQSrWWiN7PJ1wc2J2WlHQtZ1sfQ?=
 =?us-ascii?Q?mZcn3ovJSjUPT3lQo7DJ300gbt8JhurIyzTqz2TPQ+tNqBmkGA4uws+LrUEq?=
 =?us-ascii?Q?42kwOnWuFR+aiahf30q59JO3E07wd96YYzpl6bc5rzwb3eIeBcFLDmHUTCxC?=
 =?us-ascii?Q?yWV2yPjZBmBWn3qY4KuHZ/68Qy+3U0hyEhDPlHVdbgd0UCao49YEz7aMrcbN?=
 =?us-ascii?Q?p14jPCsOD6hteBTH7aD/7Mt9B0YVoNae60kAt/J+9gFLEBvfajIc0thq4Ogg?=
 =?us-ascii?Q?rdzlta73SLdOCdnboIkgKLmC6Gg7Vq+0z+89uTtTlHsgPVmeVc5s6f5LLgMP?=
 =?us-ascii?Q?u/Bom+QC1eUDFZPmHauKzU6of/+i9cHivTMMsh35B2LLMWbfXMj+TSx93tjJ?=
 =?us-ascii?Q?/pmiY8fbgstK1j6Yq0OrOtQ9PNBLiVcEdc3fdGdLvc+uqjHkOOO4bOWTQ1ji?=
 =?us-ascii?Q?7qY25U0SmYSn8VHiSgBB/lngyk/JlFdzSf9thxPYcrqIa86OeXK9/nd0sE2S?=
 =?us-ascii?Q?Ia3y8n8z9H/swWC0ajGN+oAQMor1JcFlZ6zeQqICOkoFrQAdMUKpiooGP2h2?=
 =?us-ascii?Q?aZx+Vlw/aenf5peaT2x0ozHhI0s8rWMJH/MdynmG6BDRwKbcuGUHvIy/R0ib?=
 =?us-ascii?Q?3T30kWBgzQbdRm6RVAP+BX1ijgIxa+cRq8O6Jnht1npkqdPC/vOYxtesFgLv?=
 =?us-ascii?Q?FNXI5KSVfusDZpyE6bXCVizD9J2xLwaDCjbCL9KrY+dS9PdVTQ7Lv9VuGcdH?=
 =?us-ascii?Q?7YWNyOp/q7a3qTOBLF6bsyt5m22pLFeUVXNFOuiisjKhHa3xgjkuV9sICMiZ?=
 =?us-ascii?Q?1cqDo1nJplJK/Njt/jjO/MsxQFzvr1y0x5Wo+i9k8NDOFmyKIgiNV6uStMTy?=
 =?us-ascii?Q?siykF8ClM4wEwLKyBTF1XK8QO1MxZoBDv+Bb2yJDE31vZF+9h9Dbbfl+EQlf?=
 =?us-ascii?Q?MXZqAFIEw3q7rYmP3rRlPdnVCs7AY4hKKARZkIIiZNd1XmMwcY2ZtyrYny0I?=
 =?us-ascii?Q?d7xvQ37gIKh7ebY6ECOW/UNK65ifpWqv6axwH88qqe68lxUp5rS+QE6YBdqz?=
 =?us-ascii?Q?N30iBc4mG4+6csrqohOevPYwWqwUsv2FqLW4J7ea6rSOqskecjqdeB3lWIy4?=
 =?us-ascii?Q?La/ctO9ofMaRumrgWIY1oH/NxFGEQ8u0nQFGpOz72EM7vC1W99Suhc3onQh6?=
 =?us-ascii?Q?s49EmiqO/yA0dB4XpfMvixogi3ztnLfFoUU6Bwogh+J/ZpwmFeKqTAxOFuAJ?=
 =?us-ascii?Q?QHCexPkESuy7dtn4RpPf354//ZjiaoBbrbV44oXOOfQEgXb6vnTkztIC96o3?=
 =?us-ascii?Q?ZjnmNgO89Mm3PXk6K8CIOEX9cclEcRM/uvpVpwF3TbmfunSSz2aLRwetzbWu?=
 =?us-ascii?Q?hZatW9U285YMAogFeXRSJStIa4V9s/hSw5V6FIO3Y1nW1qgbYikOhrNlWdWP?=
 =?us-ascii?Q?UoMcFNuIy5GC2SXyz+rYGoZ2fubVsSBhnISIq/AlaQWPiG+U3KHKr9DBX0GE?=
 =?us-ascii?Q?MFXtgpwk+Bnmrxe5XpsRmIhkBtDlOpk3oFYSi09l7WK3ivOzhEBgzfhtEfU5?=
 =?us-ascii?Q?qw//3YVA5WhanpE4VisTMwfol1bGtf8VTDiNy2SdQUMyBKUwOJdL2dX948E/?=
 =?us-ascii?Q?BA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: ntzJ8QECYTW8rHec1TGwc15G9JqLJJtxCV9RQEk4S6tRSJPgWepD3zUsYLpIqx/gxjfxGXNKHFcnN0Q+aoRork7KNqq7+I2Oygtsh41PYhsR6WvO1EPAjz9UQUIheqmc0VY7oy9Wp7BSGatspyS5BBwZzeVb8gmOfUQc0+06NrLXzI6IlF+jbjpdiHM4WeC2D08tD54FueQfWUnxDySOjwHqPiQ351+D9nQb++0K06/XFRJzMDT3r4eAO4rK9V3zLXfnLA12z9h588yp1j1TuwBmCHCsD3bM+dLQxr0TBANr82Tf1R5AlTWUFk3NVBGGScgAzjNfbQb2Ynlz7ReCuxC4POD6jIBbAvlJATqAKwdOx5oENXpSSEfhxaWvxdfql0y+Wupe7EnGf7/RskYCpW3qu8jJw84wLpbFdownBSeK3zq0755SEaRlKncAExZ7c5e+1M9iMnaYAWkBEVJWheM8EF94elRQimC26GP7lzbRYDVNWbbnV/hk7v7xYztLf4XQwxHP2RDZEg/mPYS0RSTykY6Wn941WGkBi9zDzXRTeMHWCXe2aUH70cT8wHZ3JYIouPSsUVQgc7Av9Y2cKIqD3ccsg7pbICkuorYq6Ko=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f7514a03-7358-4c7e-07be-08ddeeed5f84
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:35:43.4298
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +RIKeTEWzlWc3qT/K/qRyt3reHwfcc5QmCAfj19dnp0f8PeeTTMPctw9z5dsmuh0BmNWJowVjsFDhnGqZB6onQXeXUdUyxAZummoYmOcQf4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF6AE862AC6
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_05,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 phishscore=0
 bulkscore=0 mlxlogscore=966 malwarescore=0 adultscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080154
X-Proofpoint-GUID: RWRPA0T6Kz7jXjwFm4te_Lqt61jNovJs
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MSBTYWx0ZWRfX4h/kFrjSlUX/
 mua1VBubnSGvIOYzyj+JmAnQyZ+bVGdP3KREK7dgQWgwatIxx4pJwjJ6QH+VrA98t5rufRpePJh
 FXeX19ghVrGyc8qvsAZiZ2lN32oZHlhZ+Z9ZPHo/d1kW5ycSc5dKW+lawxQ85gptsuLOVpWIkvH
 zrM1Z4VtnTKO4Q/wai2qLdyhXGH0HGV0BPbmQgWd7Cvqx9dYOh0QdpY5nyseooEtzQiaHCBo67O
 Fo8eEo39fOs24rIbEZGpNLIAFxyf+DfBjvi23OhEoHn1PTtsKCF3qfDct0SM6G079T8IgdQYlnd
 r4osEm+Qunsup95I+hamvknNUozAY9FUvZSWO//kkRZE3SpZJl5IGj8Lu0Nrj8PidIQOIw57KaA
 1u6LNZwF
X-Authority-Analysis: v=2.4 cv=Dp5W+H/+ c=1 sm=1 tr=0 ts=68bef7d5 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=D6T3AiggkppvC9Cbe2EA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: RWRPA0T6Kz7jXjwFm4te_Lqt61jNovJs
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=XByJjYp3;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ULoCx6Rz;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 05:07:57PM +0200, David Hildenbrand wrote:
> On 08.09.25 16:47, Lorenzo Stoakes wrote:
> > On Mon, Sep 08, 2025 at 11:20:11AM -0300, Jason Gunthorpe wrote:
> > > On Mon, Sep 08, 2025 at 03:09:43PM +0100, Lorenzo Stoakes wrote:
> > > > > Perhaps
> > > > >
> > > > > !vma_desc_cowable()
> > > > >
> > > > > Is what many drivers are really trying to assert.
> > > >
> > > > Well no, because:
> > > >
> > > > static inline bool is_cow_mapping(vm_flags_t flags)
> > > > {
> > > > 	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
> > > > }
> > > >
> > > > Read-only means !CoW.
> > >
> > > What drivers want when they check SHARED is to prevent COW. It is COW
> > > that causes problems for whatever the driver is doing, so calling the
> > > helper cowable and making the test actually right for is a good thing.
> > >
> > > COW of this VMA, and no possibilty to remap/mprotect/fork/etc it into
> > > something that is COW in future.
> >
> > But you can't do that if !VM_MAYWRITE.
> >
> > I mean probably the driver's just wrong and should use is_cow_mapping() tbh.
> >
> > >
> > > Drivers have commonly various things with VM_SHARED to establish !COW,
> > > but if that isn't actually right then lets fix it to be clear and
> > > correct.
> >
> > I think we need to be cautious of scope here :) I don't want to accidentally
> > break things this way.
> >
> > OK I think a sensible way forward - How about I add desc_is_cowable() or
> > vma_desc_cowable() and only set this if I'm confident it's correct?
>
> I'll note that the naming is bad.
>
> Why?
>
> Because the vma_desc is not cowable. The underlying mapping maybe is.

Right, but the vma_desc desribes a VMA being set up.

I mean is_cow_mapping(desc->vm_flags) isn't too egregious anyway, so maybe
just use that for that case?

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d47b68a2-9376-425c-86ce-0a3746819f38%40lucifer.local.
