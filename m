Return-Path: <kasan-dev+bncBD6LBUWO5UMBB5UYUDDAMGQEACKQG7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 19311B57BEF
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 14:54:16 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-319c4251788sf4884339fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 05:54:16 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757940855; cv=pass;
        d=google.com; s=arc-20240605;
        b=K8AdjL8YfJgBOL3+0t7sfh0E//ZYdNHiKih3l99xQpu3fj7svk++hUwbMTsHrUtW7a
         70rSI8ujD25zMPhYPs+yEnlDsoJNIMW8aXUcZTB6nFMU8jMdSX+ujN5kVDHyRO5/RTIO
         g4sAUbZsf4JrqEPX867wuYcM4N1mRZEn7NYi5wFAB4Unsa+YNrCjgsOGf+k3olRm8TQb
         soUkTkzSSuTcDLk2+yBj0R4vlOWSehQWWE3veLNNHA75bOaxLW3elf/kEab/8NIto0cV
         /VsSAmV275F+eNMMK0XbgAmzvHqlMNtCVp6wq6Srvb7AslkqOAsX0jXQE0KI8pg+Y1QJ
         e0iw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=dntEXbhFQhXr3gGQq2xGgTja9VxB4EGR4MR7MKEJVXU=;
        fh=GDDvoYcoE3ugIvWeKmgvW29j/XdxQNzs8cTYrQIfUy8=;
        b=bgJyqbWLMgdepDDbvkkb0wN+/w/SrIEjJYUGeea86l3SV466Hd29/5zcQ6brjOxGOG
         fVaDIFWT4lo2qs/T/Ueo40wvue5gKZ98O1hU8FzU+/7pZGr2gQEiH1v3+pLEnvl78jEZ
         uH1dZpxNSpS9vZBz2FMUu5ewBESLDnAbc5ZMxK/AKLN2k6Z6ucTXPRxofoefolQs4Dm4
         yEVGR9//T+kqwe8BLuJikRtt3b7Un+IpBWw5HCs7sDRZK9nDbumUqUkG84/pBZEUKuoR
         lBlWfZQ88WRvy0TMglo6hJTebo/GQ9SSEqBJtN2FRIKck5OosOXWftlnpAabbHtY8+fR
         RkFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="UHjTZ/zB";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=lO6Ovs1V;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757940854; x=1758545654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dntEXbhFQhXr3gGQq2xGgTja9VxB4EGR4MR7MKEJVXU=;
        b=wdNsUOyF3Z5N3+ShA87IuOO/qp7JEHY4r49E5cqhZmfXRnEtP7pWythopSFhshGvWx
         NlPSxde3ScLD+2HxD5GRPzNBRu0edwl0nTiJEeTsXQIZmSn454tLLetqpEzsllhqE85o
         9dSjJA2ERXlvsx0bRcEls8j8nR+hX40ekjn4QuGdvOfPBS27VLWrU0e2nGojhqgHTU30
         u4aeuhpV8CzDzFOYzwqIDIuIaELwYPJG+QfTWS9UYFjhq13HtEQXngUQByzTM8f32XSf
         3n9sbeHvD5yt9v3iTZPl4VDO+aoJcmD08v4kcWbEw1LJer9so451rWVeRUFiBc15kE73
         f/nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757940855; x=1758545655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dntEXbhFQhXr3gGQq2xGgTja9VxB4EGR4MR7MKEJVXU=;
        b=IpFWUbDbcrXVsPv/VuT1mAcHL4tg5x32VvZWEzuWem9sMB+T6hMzlJGJX02CUmYkd/
         9MpUB63WaAd9v6llnkRTR+/od/3k1ZHy4GIywO9YzX5jgIMZDwkKbunztN1ouqO/EKdT
         rqgeVB8X4ZzPkgRq10fg69HDzWtAa+U80nPV4v7b5c4dnvtukbmO/T9+kqhjdzAJkjjR
         TVHTs4v0gjLWhd56v0ClmZb5o6F5yZ2pU+CXGVZjaNXPENYZ+FbQLw90dwbvrVcg7zcf
         Z9iI64+MFuCxYgIat2ZI7nAj96w/XykNTVbZiKBzkew209+rlLvdFPF6ngDgZZbBgnQu
         s1pA==
X-Forwarded-Encrypted: i=3; AJvYcCVxy/X59GtWDcVj3d87i6uAj2q6nf7bmIC2i0l8mOxKci/QBCjqmL2bfPuHIPgH17Tyex44cw==@lfdr.de
X-Gm-Message-State: AOJu0Yx62x2/NZtkOZ3EKbyx1gNgKG2awkxzZ90d3BHpQzMa8cPgy2Ot
	cHR6veco0koa44UemvvML9h/DZok8QtlKTJg4cv497LnLxW+vkBd+z3J
X-Google-Smtp-Source: AGHT+IFb760kCmp3bkMq7+ZJGYwEP9yfuzClQzezAmjdke5xCjnmlcjarUxHoTyxIfDAL/FB+oanwQ==
X-Received: by 2002:a05:6870:1697:b0:32a:1155:5c89 with SMTP id 586e51a60fabf-32e578f97dbmr7342610fac.45.1757940854533;
        Mon, 15 Sep 2025 05:54:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdIweq/Ig3gusyFow+0hmrkn822cXsXXvllcYvFivGbow==
Received: by 2002:a05:6871:9c27:b0:30c:c0b:fe9d with SMTP id
 586e51a60fabf-32d02f12b7als2463617fac.0.-pod-prod-03-us; Mon, 15 Sep 2025
 05:54:13 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWogN2b13ZyVVDy+X59StGhqSNOfeOv6JWmLiLpfPINEIAqha5E+Uly/YDbv/PPohdscErGgi2YlyY=@googlegroups.com
X-Received: by 2002:a05:6808:219b:b0:438:219e:1d56 with SMTP id 5614622812f47-43b8d9fb070mr5031104b6e.24.1757940853620;
        Mon, 15 Sep 2025 05:54:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757940853; cv=pass;
        d=google.com; s=arc-20240605;
        b=NCD/LqGbVW8kAzryR1PE0t88+VPbF+rWs7wQCtKHcFFlAvmPhXLtRPufzjwa4sLI9D
         1dhWmyAZqDs/mm1h7uf3dkdKi6hG/sOFTT8qFFvLn0Job/CSL1pmTiRmNR+iRJImmZWx
         unkemMk1eqbbn4SNdY0AWG2I48YE++eS+c1BIC3Si/gxa73u4Tf073PqY+RHlh+HaUPf
         ESvoAp89UYfcX9cUbN4tiRpI8nygAFVb+zjO89YhMDvzfdZ91JfsvQgJFuTJvzXthOqb
         XWYE3PI1PBqvUZ+6d+GgXCKgkiV0XbjeN/dcOyFJlJPvy7dpNN4nkvNiKj+DaQDB4jIc
         aM7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=7zoDu6Wrkf/iopCyjhc2aXPOi914cAMgs9C8XEsAN6g=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=CLvyl4/AkB+9oHxj6nD9k09sbSMWIkTyFphjKK+f2Vd5yRz2PjWDonCI1IyhMmLFlP
         bxZ6543KzHE82NRo6E+CKEiSZi2qW3sVgS5EV6lK7JZ6OnbxmiNKFECCOWrbPFVp9AaO
         AQGX7Ildf7WrR+pUAQcD6PzFeeSob5jUEpSuIJ33LISqbF5wYVGg3tAtQF4Xy8OrBzt0
         kgu6DeFMeR+rgbkQOY6WHuZ7+mVeBAPYrPRd1rKUQDrGCtoX1fapc3uy/uvTrIofZq6k
         Hj8+NCSsxkvyuq4ex/62JXf3+tRKQNqiOyptpAk9IdatF6+iCCz+0sHpD8X7r854mfmd
         YhuQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="UHjTZ/zB";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=lO6Ovs1V;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43b8dbc95besi300358b6e.1.2025.09.15.05.54.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Sep 2025 05:54:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58FAtmK9022582;
	Mon, 15 Sep 2025 12:54:12 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 494yhd2bdu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 12:54:12 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58FCkajv019277;
	Mon, 15 Sep 2025 12:54:11 GMT
Received: from ph8pr06cu001.outbound.protection.outlook.com (mail-westus3azon11012021.outbound.protection.outlook.com [40.107.209.21])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2b8dje-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 12:54:11 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=OHGxak6q8AhrX8fpOG0Z7yxMehqzqyonAKNgavgJNJh+qlZYy1nGS1xWpMJykWthocALOSPYqHvJ57Jyu1c2WnXim7PVIjQWfdLIukgQOOxAGacSwVibQjnEKxBps524X7FzSNS3CZRI5J/VuPAV3SITpCIQ5zANTz7eoudICsySTpAnhJaq6lM4ta+iTR3m29vXGI0L0hC7dm8OIwdLzG8JqN7wAg5VXuPj4wPilCZ3/9E/5sUwPtMX/wrkQGt6vVHGnceKQIkSkrv2qoDRGMHHxrlSMm5+Fw0ad7cWHT3ai6hkeFpaI7HnCtG88dqunWj8VkWif1JDLsoHj6h4mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7zoDu6Wrkf/iopCyjhc2aXPOi914cAMgs9C8XEsAN6g=;
 b=xzrjsD9tDjfmrZhx0BA+CKEXlvAuKQgI61aurpwRTl//uQsGH0kqjXW8m1cBrjYLhHD59Fgb+wEJ6HAYdYOYd8e0bXwGdrM9p68Tj6v3ooexDGEGo59Rfcx9iCA2R9vcgkwPY1BDVUfvT5cLUN2Fc6RToXrr0gDKnlQK7gXcdicRVwFg/sZfm3tUSsPO4MInoDxiPEv33HdhXKcg08Y2fK6ESEU3vgBsBVv1ZacYN3fG8EQzBtaJCqLV/CeldvbDRp1V8NkfAGM8SlAvRfvdxCQBePg1W/t6yPIEZgDunNnpDjkz4Nl733B7j22dj5sBBrX3wiC8MTQ3uaN+OaET/Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH0PR10MB5730.namprd10.prod.outlook.com (2603:10b6:510:148::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Mon, 15 Sep
 2025 12:54:07 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 12:54:07 +0000
Date: Mon, 15 Sep 2025 13:54:05 +0100
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
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <5be340e8-353a-4cde-8770-136a515f326a@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121112.GC1024672@nvidia.com>
 <77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c@lucifer.local>
 <20250915124259.GF1024672@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250915124259.GF1024672@nvidia.com>
X-ClientProxiedBy: LNXP265CA0074.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:76::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH0PR10MB5730:EE_
X-MS-Office365-Filtering-Correlation-Id: 9141ca23-f36e-4667-b8c5-08ddf456f557
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?s79zYsT7Yc2bilLY+9UvxOUdgTArmX+OjQoRNr0UXVX9jtsMiJbLieuc6E0l?=
 =?us-ascii?Q?dkYpvE3mPZpTmu4Llp/KMzy4LL5Cte9+9qmiTNnpuSMUDH/aVFKPqnLFT0hj?=
 =?us-ascii?Q?RYOWC1h+tozaTu0YiUOAJ7/9VxbMfP3iECdI1Si3oMiSlvc2siMDBjGupZu6?=
 =?us-ascii?Q?eTlZw2gEFqMUCtfwuaDCBwt4KT3GlDoojF8/D3zRjz1BvXQJyLgQeV97YlsT?=
 =?us-ascii?Q?MuuB/efqcyznrPo8uRvB+LSgqQ7eorauHhYRl3mevLrKp5YnEgaiMzEanI6R?=
 =?us-ascii?Q?nHHQajFH03bc6KUVWxG7uF9S5s7PVksdGkBlFXRXXVG9F4FpEI/kTXLFTanP?=
 =?us-ascii?Q?uENhc7K/SXCXzi0xFTIOyLwQ6MFU6/QETgfSWe5WVJNjhIjebeuvT+QdGtl3?=
 =?us-ascii?Q?i5sDXcKyvlacFdOkazS4Tmw/wYrBK9XM2anBqa7wq74wGv3B3G5yrgAVOHf2?=
 =?us-ascii?Q?cNAIqMWUpPLdW1ZNmxoYVWuFBGnT4YijO8JPKe2ZfyVqmMUmemHuPhS+E8VJ?=
 =?us-ascii?Q?oe7uvipiCxQBNRZIT3LCktRBaRMDFlffYu2x9OzwlvrG1Y3pfFdxhu6OFWkc?=
 =?us-ascii?Q?OgevKA3/+vxC60V6wCTrjQOval7qW6OQE5RUqtI6K1nH5DAXxntTJDeKOQB+?=
 =?us-ascii?Q?5CIagmq5Pobr3pa/1389lsVMbfP8R9Tj4xhSfN8NbcYZzk58lDpYy+7Suv6x?=
 =?us-ascii?Q?xnAeS7JWukcjiYIQd37BJBU0UaXZfYfJ+hZwftxMgFRfG42Te7n1fM6j40bw?=
 =?us-ascii?Q?AkWNal/LkGZiGq7IB8lL2l51VV9osfXXX7WfYMHmvNyWcgM6Kn7sA05seQqq?=
 =?us-ascii?Q?obxBN0qRHt/W+nVK9ZG/ItXpaDRfrRgVqDkcUPrX2DvLJoh82GdaJrZzdVXP?=
 =?us-ascii?Q?H/baI8aN+3OwGyO8gx2Yt8M6E2DSUUXIDFfFo3RpzPVhjCZQGtPF/TbfVk+w?=
 =?us-ascii?Q?+d6Hl+On3dAz6kYHkz9PZcr9NHwKja+oSFTEYDvZGqm/ajIDWyaQdweITOLT?=
 =?us-ascii?Q?6vTiSEv/aVI5sLRe5nNKfSUL/qBiu+/5RR09oaKP+wBwWPWKRYrIVqrHe1EA?=
 =?us-ascii?Q?i8La5WEmpDgsvgxTP76rnrg5nu18W1UrhI5CR4li3u/pZj9jrQ7JrS7qhUnO?=
 =?us-ascii?Q?1P1zBOAhr/frb0UP0fY/eHmxi3z5al4oP58OfBvnUbGfxm4RQAEuoDFbYKmK?=
 =?us-ascii?Q?fIMCoWIn2DU8qKYZeFXhCU2nadXL6anj0ItI/E1NQwRJPOq+EDU5yzi7Vwcm?=
 =?us-ascii?Q?UkJI5yvF/gghg20X+Z/LInRj/5wuwtzp9wjdj9//ln0Egdko9ENdjTZTXLaf?=
 =?us-ascii?Q?hPeUABrzEroxcZk6nn0GPLrgmIJLcnnjiK6WvtjZ2QAUMson4ZJHHatU45rh?=
 =?us-ascii?Q?9I9vQBk8lC1aXSmMyK84pjp56vDxvUh7jID0KS6t6/5fLId5mXEaAQhjLXtP?=
 =?us-ascii?Q?j3liBEL0GU4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?xHQIhZpjyJhZvd1W3i7pFumVaCk9wgtKQuU4ZjbZnJS3MZ7EPaDib0Rk2Bwi?=
 =?us-ascii?Q?pz1PIGNQks+NKBNUDb+6ESihKjqoNfXXGlzYFl3mCF808Q3v8ev/cm03sGLE?=
 =?us-ascii?Q?uItxzvKcVOiMtUqoUGuirNXpoaVlhB4CDTANOm8ZZPI7UJT1qX1lSynYChkG?=
 =?us-ascii?Q?3m/nDDo1uShZivfdmo7lf+RbZMNXwBY1KI50wgvYoatfGmtDk/mz4WuHh4GX?=
 =?us-ascii?Q?wZBymHYxc1+BO1UI6Dy8e2UVdhp1fCBsVFulo3PIWIJjEJGSfiJ0P6I4ro2X?=
 =?us-ascii?Q?XSYsPnrjXtvXR1+LcYGEuqt6W1mMf9U9e+YaLVBERpyDgtlELHxjaPwNYTVc?=
 =?us-ascii?Q?jQSL93tqX4xrUyGqRbTBqIWXUu3V05cT45x1sS6ct0kPOGpSIe2D2YxSDDFU?=
 =?us-ascii?Q?eWUu29QzLNaJaLLLFUj8ubq2QIRIoSwkOD5TjBnbAiN5CEsuXnqLEvwsQ0Ie?=
 =?us-ascii?Q?ChXei5ebPY8GIi7LbW2O/VXN8wY0YRNAu9fXDIRcmm37kHlc+bz6SRLTGmmc?=
 =?us-ascii?Q?pFjMwnghfjkUGxGkm8GugK0pGVHNHnMBJjY09ydaHN4FsZ4/npRRrUdBmQT6?=
 =?us-ascii?Q?vUPsEi3dqxOqgMmLHTfk88oFjnzQWksDTAPov6ge4zR5Vqsei5AtLiaaNoo9?=
 =?us-ascii?Q?MKKciY+isPMy+OHzR9x3efSPZ65z1igC3iPrabhozDVRudFn6mvu5lfWYVwS?=
 =?us-ascii?Q?alIrPjbtM2qbRedsUInTyngyeHXPZ7I/YgJmInqANUrgZvBo7lCY/fmPDp2x?=
 =?us-ascii?Q?8YqROawBPWYXjFE+pRt1h2eLa+QTRte2HRJm0E7btB9AwLFksTXB8YFQopcO?=
 =?us-ascii?Q?0WXbJvinX94GXjWWSHNZWmCIqpPzkDuV9RUxo5b6qpvgzjmwP68/4rdzVV7N?=
 =?us-ascii?Q?5dE/fzBXQBnmA+L8G1GGMrFO/DSsKWoL33hGo7r9HipSPTreqsHILFcJArE4?=
 =?us-ascii?Q?q51rsVmeywdQylD7/hscWKuRo5SuynYYW/Il4cDAdLTSPH8cIPLcW9lT5gN6?=
 =?us-ascii?Q?SL3TN46RHHJWr2CC0pRlgZ/4XIdDv8iO1qminT55Oese7HCb7xNq4U6Q1K8d?=
 =?us-ascii?Q?7+Nu26badd81WTB/yLHRZpvuNRW5xxnmi4V/yw8zq/KkAxJwo1Ki45lqj4ON?=
 =?us-ascii?Q?zP9dU0Kd1vImtuVY4OOjSo/SMAn7zvSYgjtiYUDjrcEn8yvifS8gTkkWLy0g?=
 =?us-ascii?Q?Qw2oizwDjEF0boWrW30ElM3+1yQhLXXdR0KnM1uS8E9mT20sJ9EVVRkL2jn3?=
 =?us-ascii?Q?rxjXil4+BDvlj4mJp8m7hFJdtIt7KPjLaI4Hh2LEI0RFCaXvSaljTf8B/HBy?=
 =?us-ascii?Q?7+Gy2puO3OW2wB+bKhPLHeRxZsnLnlCCNbeboRdenqGoAxaoG6kC7SoX8fBc?=
 =?us-ascii?Q?ATah7tHTc+ZSDVlVPuxRlD/ZoQsjY5AALvRqj0lzXhSQ01NYFU8St+hB9ukr?=
 =?us-ascii?Q?9wxY0dWNIH5ToGsDQ+SccuqnMiXVAj+WbFZms3rIA26tnnYfPyW3VJPoltWk?=
 =?us-ascii?Q?mY8RQa940xfEywcEj+Fx4CLIgIFQDF6U/TOBHO252jxMMUFMdWGA/3S/SrZi?=
 =?us-ascii?Q?2WS/KpEZ33n8bo2hKK+MHNfuQTHuwBbnKR7aBo5qdb4oKGicAGblFCQezu6u?=
 =?us-ascii?Q?Cw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 7uOX7KCF2mivNApxFeH1MaacyjwtKr683Luzr5Maty+ulVBwgzrxfTJLEBv6Y+F3+B1quV3jg35CXFJOIictJOmIZ01Ypyswmwv82wrI+wtMMo6i/TLOeM/WJ26i1kIcLbopqR5U4ptYblt9w3uIPUUckuMfkDVyQ/WCTe+Zgew3MLK3GG3p6rFuxnrjdonuWrNb4MzyIgYEB39F6AE526i9f37CfrzM73f0L/CNtA4I5R81DVjRpoiRKpAiv8Q5CXW+Y/KGnCS322PdQOZ3pViFK9BRRM/VyxSpsk2ChdHr7XLkTMyURvs/upbDHhvczYNbWEeGthxVs9rQ0SgvcU61atU7hSyTWfj/9jMBEaK3g31HnvY4aa1/P7mzfyz+yWjo46o2Hh2R2yr9+I2AksYJtIIV0m+/EZUT+klSaXZhNhO5TIxzfRX2mNMMA2vTRZVodZ86j4qIZo8Z/xGpL76z1Kz4aZwkXcEQ3qTScHF3cWxBobSsRUE8bd2Zrjsh7ShfA4gs4OM7n0OOti2cRcTDu29qWKkHgnT98cNDe7R0V0stLspRdCTdTRUyevBJJrm+OQ7reYafEojJk6V6qvjXUBKZYwWgq1WMrudfEpY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9141ca23-f36e-4667-b8c5-08ddf456f557
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 12:54:07.7757
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ZNbzcLZDoA8e0aZVT6McvsKrB5wvOMlXATJHrifTmZcVLg1CNnkwHR6s82JOEhMWRS7PtxfKk8o3Qf1VMc2ktQQLqFxol5RlELQzrgQriNg=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB5730
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-15_05,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0 bulkscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509150122
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAxOCBTYWx0ZWRfX3zc+bmGkQMku
 lWFRwyQ1Tc50+muVThG2baX3DQ4uokwwgJFh/bJfrVGIsrogF4lSmMQyj095NGXQ4/MZT+f2fCy
 QTi2/SaD+HqMxhLB09lxEU18qE5jnv/deBs4+QETEgm+zSGmqDa9/BUTDXTHvyb3iu9caHa9sVn
 dfxVPYlg2GF42tfEuSzqHTU33RR10cpG+tYFsZZEn+FpBClK0y7HQCvd+j/e8NTrQWwRudibvk+
 w+vnWj9cl59VPkxk/Qd00RA9QcKH6GM+LGkrqdSH8qFHVUHXJdtx2KgVbt4SsgVeVYub6+bgZ/V
 evXZD7FPDIvWyJGAE85+ypbUQgUfLaiV+vbbJmN9/JZB/Tl74VAtZoC0NUkmL6e2wl6xg9DCqnf
 eXhCl9e+
X-Proofpoint-ORIG-GUID: Ov07CENjU0O3FGej4BB54JelU-3o2iNZ
X-Authority-Analysis: v=2.4 cv=YKafyQGx c=1 sm=1 tr=0 ts=68c80c74 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=1Sb-PNH_FbyoOkfzMvkA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: Ov07CENjU0O3FGej4BB54JelU-3o2iNZ
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="UHjTZ/zB";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=lO6Ovs1V;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 15, 2025 at 09:42:59AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 15, 2025 at 01:23:30PM +0100, Lorenzo Stoakes wrote:
> > On Mon, Sep 15, 2025 at 09:11:12AM -0300, Jason Gunthorpe wrote:
> > > On Wed, Sep 10, 2025 at 09:22:03PM +0100, Lorenzo Stoakes wrote:
> > > > +static inline void mmap_action_remap(struct mmap_action *action,
> > > > +		unsigned long addr, unsigned long pfn, unsigned long size,
> > > > +		pgprot_t pgprot)
> > > > +{
> > > > +	action->type = MMAP_REMAP_PFN;
> > > > +
> > > > +	action->remap.addr = addr;
> > > > +	action->remap.pfn = pfn;
> > > > +	action->remap.size = size;
> > > > +	action->remap.pgprot = pgprot;
> > > > +}
> > >
> > > These helpers drivers are supposed to call really should have kdocs.
> > >
> > > Especially since 'addr' is sort of ambigous.
> >
> > OK.
> >
> > >
> > > And I'm wondering why they don't take in the vm_area_desc? Eg shouldn't
> > > we be strongly discouraging using anything other than
> > > vma->vm_page_prot as the last argument?
> >
> > I need to abstract desc from action so custom handlers can perform
> > sub-actions. It's unfortunate but there we go.
>
> Why? I don't see this as required
>
> Just mark the functions as manipulating the action using the 'action'
> in the fuction name.

Because now sub-callers that partially map using one method and partially map
using another now need to have a desc too that they have to 'just know' which
fields to update or artificially set up.

The vmcore case does something like this.

Instead, we have actions where it's 100% clear what's going to happen.

>
> > > I'd probably also have a small helper wrapper for the very common case
> > > of whole vma:
> > >
> > > /* Fill the entire VMA with pfns starting at pfn. Caller must have
> > >  * already checked desc has an appropriate size */
> > > mmap_action_remap_full(struct vm_area_desc *desc, unsigned long pfn)
> >
> > See above re: desc vs. action.
>
> Yet, this is the API most places actually want.
>
> > It'd be hard to know how to get the context right that'd need to be supplied to
> > the callback.
> >
> > In kcov's case it'd be kcov->area + an offset.
>
> Just use pgoff
>
> > So we'd need an offset parameter, the struct file *, whatever else to be
> > passed.
>
> Yes
>
> > And then we'll find a driver where that doesn't work and we're screwed.
>
> Bah, you keep saying that but we also may never even find one.

OK let me try something like this, then. I guess I can update it later if
we discover such a dirver.

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5be340e8-353a-4cde-8770-136a515f326a%40lucifer.local.
