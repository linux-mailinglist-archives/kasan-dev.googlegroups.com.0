Return-Path: <kasan-dev+bncBD6LBUWO5UMBBEEUUDDAMGQECHXA74I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F95DB57B6B
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 14:44:03 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-244581953b8sf47760935ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 05:44:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757940242; cv=pass;
        d=google.com; s=arc-20240605;
        b=g6N7SbdZ8xMrjs+nte6eEr+QGDEup4PKMCYDOFgJRufgJvlyrChCpTphDfkEmKGyog
         JNu9oQPXhkWlLGNIEkNoFNOkJWIDY+25lDM/0Hj7nsUx5rKZ9+dKXx0WcHCe5l/jEup6
         clS5/7s4xKZULUW7GbPUpNfLVOQoNAvPjqfiaYzozmhnbvpGgEuJVMLiQMrZXK/nEoF/
         3fUms2UPPSwQPhaa8Qji4DEK8Dj6JcoY+/9cJBaNeYjNja6/03zO9dnLMPH9YJVo2lgX
         TW0k/j+aM32BeeFHaYTOps/zkJI4wvVxekWt2eXJQNnBMr8H7cR6g/qN4YH8de+ZDWVQ
         YE4A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Rnh8gZUwHyqEb/zrnuqgC85vvkNxh99eWGRCUq+mxQA=;
        fh=yPiL3LN0aSkD1PzRFQ4yrLZW3eopz355RNmqhDduf8M=;
        b=DGrDRK/H6LOW8fyHO8Iv46FR/jIo/cJvi/6N+CrnjvXbg/RFkxdGs8cNCm0yeJCW25
         yz41aYrmltNur0yZuDa0eJ55fPF0kOC/tEDDvNXtdudhuk/9MzyPK1HLJ59fHaTNqTio
         K95gTVj925E3Yn1B2QZRjPX2jOUJNZelnP41QDbDzjPGTGeRFzthJMg58wKVfHy8pWPe
         TGMy0P1573Qp024wGdSLVEQQcPf2av0Jsj4IzMEJlxCMjFNhXDGyPlHJVy7oWbIsNHW7
         QZnlAA/UWWLs9b8AEcOiKc3aWTb4P1KndlrKm/lOsdqrVmtmbCeETa1X1IWCQGMAd9Z2
         Sv/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=dD4tf7gt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Km+PAh1x;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757940242; x=1758545042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Rnh8gZUwHyqEb/zrnuqgC85vvkNxh99eWGRCUq+mxQA=;
        b=Q6PV9ufQEeX2mdZAdFRItQJqidV1D/66YH1jek3LV+9C+SbSlERwYvEbulSewUxHbr
         V20jF7YyFhsxKEiHqHOFV2MA+MZ5NsWw7weMfeMvRC7YceR4rdm382RnPGkKR/ZDvQNC
         xzzTYqQjYFbCQtZkiRizlqCY/c+GH3xLLR2SChoPXqn4BE1VKubMyDG578vYDEVPKUSJ
         pH6chcTfNgQq6dvJltWgZdpDmlQjdRFg5/AbErwGK52mzHKrETR0KJE2SmYWoMFHcTJH
         vw/URI7Amv4ycawLV504j4MC+Jpa0H5VZt8f1K5NXY/C4gxKHe65TdBwbTRe+fnRtbne
         1HFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757940242; x=1758545042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Rnh8gZUwHyqEb/zrnuqgC85vvkNxh99eWGRCUq+mxQA=;
        b=BIjoYJb2tV3v2wx0zlDNDYoy26p+FBI8CDZo3ojDr0Hfgn9HMmuJBCZLUhq8lfPlhs
         ksGWkyWLbPsDg3yoFB58XpXmOTBxm6setoTPT5YPD9Vdnzjf13otMlvXhN195RT0v+dE
         Lbr9RO6eYZ58rY6PIny6aP7314HHgttMVXLs6MuS/mXJl0FQhixrwlLY5PC1eOm1W+AV
         SfEVWqidTsxmCABdfZT3YnrJnanKLS0zuDXS7wKVANy/NjxPzOgYQFFwad3Z7zUUpUx4
         9/I8gbt07YUnXgZ9VKVVOqDCbivmLfPe6vXwWP6bq2xIpjcUd7TQcopa3sj8jw8IyY4X
         jYhg==
X-Forwarded-Encrypted: i=3; AJvYcCUSmAcl/niLAYBt5LprVDJzCjVFxk+qOmgTgrni+BaCA6xW6T65A+bnPjhy1IVBtMPvDcOMmw==@lfdr.de
X-Gm-Message-State: AOJu0Yw7gGgkKiPq/DwuC6k5VR/8xJYVthE5VHaDiEl+rW1Cw50G1gsY
	2TgKbTpEXcfsRJsnp/+64Kr9oIHEycVr6y35ATxml3Ngk07FbD2Z/8N7
X-Google-Smtp-Source: AGHT+IFzOoJqoKe+SFL1LZRbGju/rC9XrXQV2wIzrL2ZEqgna7mYf83Pd/743c7BS3hvujyDRPnVcA==
X-Received: by 2002:a17:903:2a8e:b0:265:acc3:d2e7 with SMTP id d9443c01a7336-265acc3d517mr50760935ad.16.1757940240717;
        Mon, 15 Sep 2025 05:44:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4+bJ8F2m8M9pZcpK6Ig2iqUfJJvl6cLgBoR/aukBJQbg==
Received: by 2002:a17:902:f542:b0:24a:ffe4:1ba6 with SMTP id
 d9443c01a7336-25ef1a23573ls20647635ad.2.-pod-prod-05-us; Mon, 15 Sep 2025
 05:43:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVluD1HvnNJNrG9GQmvy2nlay8f+J1CPMzK6ybghMc5T7i53/ql4Fcr3kcMUOXMyq1Vc6rHSJBhGMA=@googlegroups.com
X-Received: by 2002:a17:903:41c4:b0:262:f626:d516 with SMTP id d9443c01a7336-262f626d6b0mr91828995ad.20.1757940238866;
        Mon, 15 Sep 2025 05:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757940238; cv=pass;
        d=google.com; s=arc-20240605;
        b=lsN0SqaRdQCLWNNXBl58bEw4RdMEOEvco2fD4Uf+Ff54EtjuJr0ZkYThQmp6CdYp/s
         9SDiqSsogMj2vgfxXok+mDo2q3qlZNixgu1QmwwqWVXRtXeBAujBIdnPZ+fkbPBY1UVW
         7vDX0LKzH3oWqPLI38w0wnmW0xySov81kv0c582DlaVjzgRoiKn3FO5ixlItIfU7noZ/
         BiitAr6u165s2KVj+INd6WcZm4aEK96VZKA5w/YOyUo5z9WQAB/l1gWSjw1I+uTHbslj
         M5oBUeE+9N3Z4Z4zCaULI4Ejwku7ht1qPJ3gvqqvGJEDZgvwlc5dG+7zNzi9u8SOAv7N
         k2cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=cg53KnBMEMN86OdMPXwFzVcrhTkrqe4ZT8XqvpS3s2Q=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=jXfHBU1qnLhgkRy34d8Aep0W3a3bTYl5YJaJdgTaWijDs4TJc94DqY6N7czyrtbsa5
         sCehJI0+/2uXnh27fvHZdOPSgfHztPr251kxg3CwVkWCccqPOT2+sUMgqhpFOm7eqoSK
         EU6nYssFF04u3ybv76UeRM+radeoSnlWSiFIwj6mCS9Jm1LvWY+uvCSFHLM9rq8bm4/q
         /r8PH6UT2fS0lPIxkaJMPBV4i3VDlmO8X0ZEv3UFWI/rMhZMGlhfhHUGGU6B5NdhER3Z
         09IvV0AD1b7VnX+hw7MmOrPoGR3EK7L2Jd8Ak+9UplQDOVFx5QBiSqJ8749QjhHuLwqD
         vD3w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=dD4tf7gt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Km+PAh1x;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32e11f4c004si110141a91.0.2025.09.15.05.43.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Sep 2025 05:43:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58FAtqR2009937;
	Mon, 15 Sep 2025 12:43:57 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 494yd8j9wh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 12:43:57 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58FCaejU015290;
	Mon, 15 Sep 2025 12:43:56 GMT
Received: from sn4pr2101cu001.outbound.protection.outlook.com (mail-southcentralusazon11012066.outbound.protection.outlook.com [40.93.195.66])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2b0ekj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 12:43:56 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yUskIcun2a4nSWtCy0A6MbGJnGwqQDvx509kokTkFv2pN69GI5Nx131O7AxDLMx22+yNXJ1lhbHtREfBYLMzhlYmbQQh33Q1gKWnX+UueGp7e+st5PpI8+FnENtjadAyr8+QK3AB9WBaGnhpdkQzne5PI4vMMVBjR+sDnwQZa+NGGsTSI9WhSPFTF7CM2T9hiC/5j6CC7qmBy/MYOWxTcKg5G4jmRWNhG1OslcvGQyBy3CM4mps7IROAcdd2uQEjg/3tPyu92bKfDFM3I5bBEST2M01WDWaDui9l9MhG4dFBCyp1mHGRMyn3zhZo7/uTLA/iiaoJoqre1LePau2+vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cg53KnBMEMN86OdMPXwFzVcrhTkrqe4ZT8XqvpS3s2Q=;
 b=f5RMo0eliFzCDH6t/NgTRAam9RkSpS9lHiLNDGyIrIF/5DHDciWcA/VsHiKQ4M3vhihKOQEETzNL2zUiDh39h02cj/7JNbl6AehgtQ9QNuo/+hfnIr0DKR5bbF9uEhCw33aSZwZQqilkQ5Evn9Gq4dmujQGTMOguX9yo2WCKe3kW3NTMJ+F9iqWsaTDcJmF9JQaOVDpRyTHB9SRMHnG+sEy8AMMUsaYuP5EMM5uLjWaOBGVkc3yWyfgOoZg9Q2AGGkm+F2GSyFTBfs4iozZil+jR4ai/emrYQArXuM7QPOHAsuar5LJi4lbXq7zT20AeXHb2txR77EmjZszwVbISpA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH3PR10MB7763.namprd10.prod.outlook.com (2603:10b6:610:1bd::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.19; Mon, 15 Sep
 2025 12:43:52 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 12:43:52 +0000
Date: Mon, 15 Sep 2025 13:43:50 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
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
        kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 16/16] kcov: update kcov to use mmap_prepare
Message-ID: <872a06d7-6b74-410c-a0fe-0a64ae1efd9b@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121617.GD1024672@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250915121617.GD1024672@nvidia.com>
X-ClientProxiedBy: LO2P265CA0056.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:60::20) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH3PR10MB7763:EE_
X-MS-Office365-Filtering-Correlation-Id: 3d2ebeee-e59f-492f-9f24-08ddf45586a5
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?e9pNiQ68uH1w8UA0ym309x0wPdyvCEuWVH13ivoxG0qkHPP0xtmhj4/Qa4+8?=
 =?us-ascii?Q?ucR6mCoG5CT2uPHniUU4yqp4PAQ4ZyXbwa1ZQxx4mwgaBH/uvdbvanWlRhkP?=
 =?us-ascii?Q?4naeU21ZDzjimgw4jQ51Pv+VsfL2Ng6uDNyFONlh2xEbbOCjaMJt4HYxHhnq?=
 =?us-ascii?Q?rO2a2uJz7RfWJg+soj+pJtXgxNkzh7j1H7HmQIpVY2URP92nz9sylGug+cO0?=
 =?us-ascii?Q?jdOQRzu/RjOz3L4AWQnIQDMO7LJAXOsP/ZZrE1odXRHNFbkPwDGoiYSk9Lhk?=
 =?us-ascii?Q?KpH+7rttxz01zBk1AinbGMaFkHFDb95jXpuAgyFrAlM4jsYuhPpKA2nD7jwy?=
 =?us-ascii?Q?S1EG4qnyip1saci2kRWi5qsjkIWxM1WvX2feAGuD5AgoJdVoSCIDHwabIXlx?=
 =?us-ascii?Q?EJ7iTn0FDRVs6PqdcyXH6dAkhgsRjHiZyd6r25EzivgW4Yc8Wm7W7nuV0n+Z?=
 =?us-ascii?Q?HQbhFDFC8TLJvaygwInjnB0oZhkWogOXmq57ufF0EZFK/u6UQWWHRGSCot5W?=
 =?us-ascii?Q?oXGBlV1yUOl9CovM6BvcRgIRTOPVWUGTsTkh2U6gyJYWyhDR7D8QtpLb45IN?=
 =?us-ascii?Q?GUV8lti0dZY/5zAmtSzI//Q4UUQxfUQTHXqTyAve4Gi7MBBMnJJ4IgOXNGqa?=
 =?us-ascii?Q?fqmjZgs05+KTxrqhWZWrSYM8jo/A+4/jsiBh+ysBJgwbquSlU3HwLzWD1toT?=
 =?us-ascii?Q?WirkzAOp8dOBLQgkL0ECIfmNMYuomjPd6dZsvFI/iZV2uDMJmQyNPd7UKMUK?=
 =?us-ascii?Q?rTOPDYLtmJ4vZp8LYnfMrU1qGB0pBfPy1/VLAVJAggRQsVxSCluWY1tcRLsr?=
 =?us-ascii?Q?zu/BCuFRja1ruubwXe+YbYuEWwkc2rwMBZKCXSLZhzeT0Gfk4ZQq+l41VtAt?=
 =?us-ascii?Q?ccOoPltGBaUWW9G38gl3+HC6YJ6y48QNRi0/QmcBEiOx2ovCJhz2W8qVFz0q?=
 =?us-ascii?Q?frbvifAuIHdIZ7lHFmF3RcdZpuXoCyJIPWE9x8TZhxc4UBsxddllMRGvN84V?=
 =?us-ascii?Q?NMCwywWBiJtXZfJdwaPH1+azk4iuS4aiK9ycWFy4dAHga4Ofb3Q/NzRlaMPl?=
 =?us-ascii?Q?Ztk1WejYgCsZUFC0CcM/Dj8wc9Q1ODiHNeQlcC4MMRZ4unW7LPjcP1gmbv81?=
 =?us-ascii?Q?5Ji+xdTFwNqDcuz9YFhUvw5sTLneD6vQwTmtXq5qv6jZy+lbTOL2ABa43Ezk?=
 =?us-ascii?Q?A2S1UEw3uaiFCikPt9dzThyE4/wyjVkzUJaTJ8cx/jhwvkZfpCT+YWRlu5uk?=
 =?us-ascii?Q?uZM1aknqvVNNi9ShHJe11iSrI2PF5cm0CDmhtV7t1kgdtKLCT5g1htSkGou7?=
 =?us-ascii?Q?xqLQJCmARZ54R3/G41oVFG4ynZLZQ/IXgyatT9M3DNyxplgvS6eGjgIH6Z8q?=
 =?us-ascii?Q?3t8eoGLMks+3qOl/PzxIzIs09vXxQwJtbjqYvLeum5gIFKNfnO5YCigyIpa9?=
 =?us-ascii?Q?aCMlbQ/3Qro=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?w11LpkFoCaGzaupVvehj/AWMygl7E6NCXcHIueXAPbC0QM2P6kkwLrJWpqa3?=
 =?us-ascii?Q?+1YeDvj+aK09QSx64aEbMdCiy4Vf+tRQhV0ErpLDN4kIspqXkpSFxZmusIAt?=
 =?us-ascii?Q?c70CrCgzoqYzBsXphsyMywJKNyfFuon8i9rshKpSRHR0pRu4d7dck6gfnzUm?=
 =?us-ascii?Q?o3eRY6lLWca1KhqKFU+hdhawPaeRdlJ+f23zbODB3Cb+3zjev+y9EsjpyVu9?=
 =?us-ascii?Q?p5jfx2Kl7zNAfID1t0J8gZai8LQsTJZZjpvEvZYp4KoJ7CgN+UpYzoYkSq3M?=
 =?us-ascii?Q?KX7D96nBBohBHKKzivDKw6hCmz+WEWp4koMtFMrcxgYhWIIOlMFLYyu9tfL3?=
 =?us-ascii?Q?FecwyxBr6igqQ9qLWXbkSqkJwz0Md+jhFEoc/FCKPJVcPMdPkX7k59XFW9kL?=
 =?us-ascii?Q?g05p+47VTj0Qhjv8KhOIUE1i24JgxtIUlTpl0/Rf4uFeyO6YhDurbRCL+6z9?=
 =?us-ascii?Q?fEJunkA30XwBCfpMys5A2yO9RZZAmjxmUJlkSBIxuAEdr5sjVERK5KltLvvy?=
 =?us-ascii?Q?MDqav9PES9z7antTE0iBk81PEW9+Q9hvii2CnyDEHDQ8BhTvIjDTZi+5PStU?=
 =?us-ascii?Q?gX2zW1pBXVquAivzPhYMkWMgYHs+yHuZrsk/nRIR8QGsQKSaJNwHHDSPvu3R?=
 =?us-ascii?Q?6QD04bIUR2zXzgfovQ3oTwXz3N/M8lENtmfgud5bXhK+4oTKP6CR6VZVZF1u?=
 =?us-ascii?Q?hGHCkXZpkQThwnpQE6MvJuXoSgdJwc2Ehc5VhfMPr51ZQ7KzB8H+pYrs1hhI?=
 =?us-ascii?Q?arYGERkEqDDy/68IflDVp157F37OVlfJ4+MvgVzyY/FmKBo9IZQtHwT2S/bJ?=
 =?us-ascii?Q?8T4wckYztK/r0GVLTdAGdZmpgW8Ncz5IwDB7VdHu5uDIzDaLEl/otsjkxY9d?=
 =?us-ascii?Q?m1UGHVTWs7Ng3UMj/v9csyuCloHh5xsc9xeNTBMqbrW6Ka9yTBTq845XvuuO?=
 =?us-ascii?Q?fNB6tNqzT6aMCne5RD7N/yai6W6oyXOQZaIL0Nz/RvGTKXjArWqWvJbS5VIP?=
 =?us-ascii?Q?YaeM3iBVxUEk2OIeT5JVpJXuQXLB5ij+fPYC6u+iloNhfpcII4ppiUbnoR/f?=
 =?us-ascii?Q?orgltS+gsiLDiHAnOEMbbsUwjmmj4tLnQBcAJeyaER/i+dVLaco14qSTfrU+?=
 =?us-ascii?Q?Zm8eBVYrb6ym339LuZjTOqNggEkS4RPCCRIRleG0yYDBlymfO9zILs5sg1GV?=
 =?us-ascii?Q?cXt5D0v7HExhmMfHJplMAh4WMWsDzEYFko1PiUWiC6sPpfeFIdi4ry/2hz6Y?=
 =?us-ascii?Q?eWbxsZpqN0CmflaNEkyIVAw2hI9hUui4bTa3yg4dU0YjnHbEXEBFdRSJmUW+?=
 =?us-ascii?Q?w9BU9vKydEAc89JUbFRuHb6vrlGofPxfbW8cUcj1/GRirK5imwdCWp4T8Be1?=
 =?us-ascii?Q?SJH57ohD57ulKbyXpOTNBF5agV1k5KZiVDkGF+kb5otF6w+HskkN0vbUsnRR?=
 =?us-ascii?Q?17gZrPY5Ix8+isf7CKhHC1gNmkYdKfnWzZNZHJRESSWzn4J2IUwoLATwDuUF?=
 =?us-ascii?Q?eNF4Eb+h/0+lHBZdJMqV0mjxSvkVqZnkH5ZZEaRGG5sGQyx+NFSN/nrjuCQu?=
 =?us-ascii?Q?IwbnRSSfotQZ/HkkpbstJTzR2DzeCXhgwO1va7dy/RDEQMxj/T2QMaJNtP/T?=
 =?us-ascii?Q?5g=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 1QlTbM6eaRW1MPAw5I77VTfYV3YrhTBo1dlJIs9yjaEzECEf423w58j9cFscGT+uJZI8wDzTGghmayo2SQ0KYwuRlNVR2XSm2OZV1ihWYlw9LpRjOexFs3QEyUqyFvTog1mBMOLw9o21IHXUUoyAJ5rKwXETQ8qvy86XbfhSNVOeTYyazdS2XWLtZHnwMx/D1TFZBBj3bla4+LY0ksIFrWQUEEniKoj658mLD5chr09MVyf2nlkJP3t6a7Fr2fPQpgck7ujieV7f7hz/195y8DWx4Z3noFmZP5jsVwTBkcoxi+49SL0zTWCwJhHnabFt5DzAzr1HieJPCFRsG8WiaMZMLIKoXK4pdLKZCPQ8FMdh3E8WBUGcwptQDvENZbBsjpXfDUyOCgmj3i081VJCDpg+shGIRjjudMKyNEaSh6km9KZYR7n46LBQ0LnP7miR/KtBvLXJG988J+w8ozrd2bZSyc0ngDB6Vy5u/nSGUz9LblxaLH+CtRCTx2Tjsvl0KOHSCC605FzpqNpVwD2KXClqVozRTReUKJ61OdEpb8aQRRTfum6WmtfPZgPP3ugKYtkA+9piLRRJsulPQc4ogsQv033PrYb8ynRHeldj32k=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3d2ebeee-e59f-492f-9f24-08ddf45586a5
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 12:43:52.5503
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: XYY5l6c2o02LW1jKmybiI/dcWQbgdN9e1cjXT0ntHatt1iyzWioRVVVd4GOOrMFbkgt5qCja3BD19il9sg2S0dFS4KDlGfoSXlfkg0HdDWE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7763
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-15_05,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 spamscore=0
 adultscore=0 suspectscore=0 malwarescore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509150120
X-Proofpoint-GUID: b3PFSMqr5RH1rtUQlEdFNKfWD53tw-Sj
X-Authority-Analysis: v=2.4 cv=M5RNKzws c=1 sm=1 tr=0 ts=68c80a0d b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=BLP_E2ZtPSKGuAszSdcA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12084
X-Proofpoint-ORIG-GUID: b3PFSMqr5RH1rtUQlEdFNKfWD53tw-Sj
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAxNiBTYWx0ZWRfX0HjFvbFx2Px4
 ivnQ/nYwGRrjUq4YlVhZ7wpHjtVrq7xuuyb8nwMqILU6rtNkoDkh5ZlIt1q8IDOTRt6fszCEE0Z
 FymHMkj3HfOMbdX+KtVxKLGj4oJvLJLNTZ2KSVlgP4IJrl8/6m6nGLVtUUVkJCOKwMqOoD9q6qI
 QgFz5+vFrQ6Iyl3wTdQvMHKcy3vCRLdIt6XYWipQWx0EqLuN1vpeso8xnEMAEzFwXOeDR4Nw9V0
 NpzWxzp/nDPxfoyGO4g31ejCJPpH98Nc/0nIrnpanK3FVuU2UkLLq+4qpV1ukWeG4kOGZXwe2cm
 xURLFLrtCrRtMYYbIBAnROyAcnsIaNiK32wMXZbZ4wIM543oV3XFHZfgEv6r7VFAQeeQx3EK7wD
 FgT7lcS2qAVCd0i/ulEn+1cf8FcD2Q==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=dD4tf7gt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Km+PAh1x;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 15, 2025 at 09:16:17AM -0300, Jason Gunthorpe wrote:
> On Wed, Sep 10, 2025 at 09:22:11PM +0100, Lorenzo Stoakes wrote:
> > +static int kcov_mmap_prepare(struct vm_area_desc *desc)
> >  {
> >  	int res = 0;
> > -	struct kcov *kcov = vma->vm_file->private_data;
> > -	unsigned long size, off;
> > -	struct page *page;
> > +	struct kcov *kcov = desc->file->private_data;
> > +	unsigned long size, nr_pages, i;
> > +	struct page **pages;
> >  	unsigned long flags;
> >
> >  	spin_lock_irqsave(&kcov->lock, flags);
> >  	size = kcov->size * sizeof(unsigned long);
> > -	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
> > -	    vma->vm_end - vma->vm_start != size) {
> > +	if (kcov->area == NULL || desc->pgoff != 0 ||
> > +	    vma_desc_size(desc) != size) {
>
> IMHO these range checks should be cleaned up into a helper:
>
> /* Returns true if the VMA falls within starting_pgoff to
>      starting_pgoff + ROUND_DOWN(length_bytes, PAGE_SIZE))
>    Is careful to avoid any arithmetic overflow.
>  */

Right, but I can't refactor every driver I touch, it's not really tractable. I'd
like to get this change done before I retire :)

> vma_desc_check_range(desc, starting_pgoff=0, length_bytes=size);
>
> > +	desc->vm_flags |= VM_DONTEXPAND;
> > +	nr_pages = size >> PAGE_SHIFT;
> > +
> > +	pages = mmap_action_mixedmap_pages(&desc->action, desc->start,
> > +					   nr_pages);
> > +	if (!pages)
> > +		return -ENOMEM;
> > +
> > +	for (i = 0; i < nr_pages; i++)
> > +		pages[i] = vmalloc_to_page(kcov->area + i * PAGE_SIZE);
>
> This is not a mixed map.
>
> All the memory comes from vmalloc_user() which makes them normal
> struct pages with refcounts.
>
> If anything the action should be called mmap_action_vmalloc_user() to
> match how the memory was allocated instead of open coding something.

Again we're getting into the same issue - my workload doesn't really permit
me to refactor every user of .mmap beyond converting sensibly to the new
scheme.

I think this kind of change is out of scope for the series.

I'd rather make this as apples-to-apples as possible for now so it can be
done vaguely mechanically.

Of course we can follow up with improvements later.

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/872a06d7-6b74-410c-a0fe-0a64ae1efd9b%40lucifer.local.
