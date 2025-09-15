Return-Path: <kasan-dev+bncBD6LBUWO5UMBBN44UDDAMGQEKWRJQ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 30926B57C31
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 15:01:46 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-77585c74658sf62374916d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 06:01:46 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757941304; cv=pass;
        d=google.com; s=arc-20240605;
        b=CMWtl5BbVVLurSe6ulQK7T0YQ1wF1Nfr4yx0V2tei70T5Epo393l52WgUekLZo+jrB
         aq5wc10FnDtHWFH8BQdmhm7B5QXa7UCBzST/A7qptjWXfs4aqh9CBdx4Hg5AByycP2AV
         VGNxSfaSujD2CUpxK3Kjjc0sU48AvUU/FbG16Rm7feeUczzheoQsigz2De1zuElLQq57
         dH8jGRaFfH8pqT5OIINTbQlzh9FrApY6Vi+SABhK7i+ecmcw7Juj0lZMpfMLtxYYW4pT
         gJ3vmkG/tbqL5e7VgoAn4UvHDpUDXN03ZM1OqExZu+W9qu2Pc+xP6DqTmd3xnpAP2i6Q
         1HAQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=km3HWF+waks7Fk1yXqXOuWNYACIEixeGFRcrNCn06hA=;
        fh=NBSnXaS9xSbGi98uyjFvYxB1vqIf2h+CJJlAcdKEsJk=;
        b=gM1NNz/yFmz/xii7MFaoWpGIEhLUgDjSvhDPUmy4EF9cPiPig7nNkE8NeAqjj70ubJ
         A+/mbEzfoZSfkwNMdPsspTspfh1SYoZxECiQON+P6MbCI0LXBZw7Nur7083utB4rWIdy
         MH75u9feD5I0NfWlPrIVLwOen/hrBL+/T1HMMD1Aaj2XWI5XLlKzvdJP8ESoNlX4fi56
         GyUbzqWq+LLtYZMaZyedeUO0qFIPJlIWqgJcCjuxiLDcqlXe4Lekbw7dxhMi0+H8yaVY
         aFnXmBapIq1SUfpRx9u+EkTKH1JENi8DjNj6glqMqkC115XpdvbxNQD9GC0id3o6xyou
         iQYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=BEHJXlAr;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=wq9zJxv7;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757941304; x=1758546104; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=km3HWF+waks7Fk1yXqXOuWNYACIEixeGFRcrNCn06hA=;
        b=pZ6HEP0/CgCj7/z0+5KNTV0svvPypQLdKzQqkWY9verseu+bVJ695tuUV6OgL6jahi
         N0DKz+fSbD5dQI8rlgkyuOq1PxZudLBZd8cTmoUsiL+utUhZoEBattTpNcrcVvQeCApI
         CQTYOQpM1ghNrI9+i21TT27UK4sHMFAuT+vknFKzN2QfJPpakG36AhprdI5xJUSnjpcP
         u4RHhwSaRWig29WAu/DMGe1xhUjpHGvKQPd6NZV+KX7/p4J/n07nO/8d/uq9WsvFo7Z6
         STaHk8/aqJze+M0RcO7jyZJEZ1gwGZ20DLPXb3CN3TAciQZc1B3egdrT9gz/nxVuwO4R
         3mwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757941304; x=1758546104;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=km3HWF+waks7Fk1yXqXOuWNYACIEixeGFRcrNCn06hA=;
        b=MMM7bSAkZQmQp+HA5g6AsoMifXxsz7ZnOuHHnxP4/hODnZCjOzBAUb5oDmQO0T3/lc
         /31EoH1bZBOTn3T4xnbpX2rKcVVRu7ouRWV0tgbRGS57oYgMaz8antCueW3NnLoMgfaK
         Oj3rapzrLHBTwuMhYWX9LeBSEzdBtEq3ZBInMtB/LpPw6bTJXVndirkkT2Sutp3oJLRt
         6NIqgLxU6hCuGAivPZ3sppT6twfzZSVnLup8OH2wjbWFH/KyKAxTzUKpapu37WF3rnq1
         mw02oD/brKV4QCBO38T6rv90aOHbB32cbdy8O/q+yG9/dHa0fK7MnnqIa778h5O7qXrh
         m2dw==
X-Forwarded-Encrypted: i=3; AJvYcCU7d8Jab6quYXjbjAkFX1jJ6pX9QCg/5UJ6dqhwEbNzmpe1ZUzPMoA1VVFvpSYfeDKv3x2SPg==@lfdr.de
X-Gm-Message-State: AOJu0YzwTSFSibkFJxrP5G0l+Bqpa6kusuXgTdw02t0wqFqlaTL2P/37
	R15jZBhDsDOlZ+6ADEENQdd5Xno/ShZpThsyVnFDMz4Bcrhv+KS/0BOF
X-Google-Smtp-Source: AGHT+IH6H/pwcn/bRm3pUfH3dQqWjkiUpqBEcRn6ePVnW1nhKna6ubvSzPtngCrAeuDeHvYAtWAa+Q==
X-Received: by 2002:a05:6214:2528:b0:77b:3a8d:7c7e with SMTP id 6a1803df08f44-77b3a8d7d15mr76265416d6.12.1757941304019;
        Mon, 15 Sep 2025 06:01:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6sxgibniIPcGkKLonV5b7dDhGH1rBLpbpV9AMfYziH0A==
Received: by 2002:a05:6214:5287:b0:6fb:4b71:4195 with SMTP id
 6a1803df08f44-762e5beed52ls67913426d6.2.-pod-prod-06-us; Mon, 15 Sep 2025
 06:01:41 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV+3KyTdYlQTLOJBd3GhHbHVTsmRr05xIogr1zuBI0Gvuu4m+ZTzs+DKS+zAOITFtMUdOY2JbUt5vM=@googlegroups.com
X-Received: by 2002:a05:620a:2585:b0:800:c495:48b1 with SMTP id af79cd13be357-8240084efd7mr1320845885a.61.1757941300714;
        Mon, 15 Sep 2025 06:01:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757941300; cv=pass;
        d=google.com; s=arc-20240605;
        b=GvrbM0KNBSnifOHZtlmaA4ueIV04RRXRUOOXDmC4/zEkOm1OjXlNLx4d/Ck2LyBI75
         fp+rulpQDWi1tbmABOQxbQ/WfF7IH3DCdymaBSeonnoXX0gTQNGyYwDSVFRsSPnOJFab
         oDHlU87EG74/0ZAi+VEqeTOC5/Dx/PRGwNBSUW1MLphkYOKcyD68TBEUljApI/VJ6qQH
         tNIhrrLVnkXrOT9KdSgdQJlyW1n7uhbujdFT1Xn6IeDZf6dhbc6bwKvdyuRotZzueMle
         tkT98ouaoS7ObxHhU9AR6/VSgf4NSZz2LmC+56BAe7E/jBgmJHSBTFrR2D2OR22PLkcE
         DWzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=7T3jI5545qmL1/J3D10t9tmGcZ3W3KiAyOuKTOuZC+Q=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=iDeIaxOuJ4csdSyL1+n9WqQV0KX4x+cnFxjPJ62MWlnOwpZb0Vu4o1APRwBmghKmm6
         uKTsiPlV4JUfPsIx0UwqOe82LzZCXN59xWcBz+dvx98tvJMeBxp1svjNsO9hQhSgw167
         dAT8HLsx5qL7m1gJ/facs2Y02YzjWV03KYNToW71Co3npbg3zwvMedB+UFUq7JFmH1PT
         CV1gsqJEKwHLmQN3PGppNwDfOIjzj+DvvGw+FKme/XW82MAuJgKtfTqJL3cZTYr9pUDU
         4242ngQa+SonuW4WdjXLk8d30Q9upZgQsfb6XYhUlITY4xs/FBMyjlTOuAFDGY+1l8JI
         Jfmw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=BEHJXlAr;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=wq9zJxv7;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b639a628e9si3994241cf.0.2025.09.15.06.01.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Sep 2025 06:01:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58FD1FZF019968;
	Mon, 15 Sep 2025 13:01:38 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49515v29r2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 13:01:38 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58FC0Ak8019324;
	Mon, 15 Sep 2025 13:01:36 GMT
Received: from ph7pr06cu001.outbound.protection.outlook.com (mail-westus3azon11010014.outbound.protection.outlook.com [52.101.201.14])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2b8p47-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 13:01:36 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Hzo8MS2WjrOrVOCqdMjsuqm9PpKs9qdB5/4fTY6PpnVjgZ59TuHan2Bk7ezGJBHaWzUtNJC733BSWumbCQtToRkufTiBUGsI8q67SyeRXG2RbZMX94BZ9sU+YWIRgow8jAXZU7qjqFy7qnonUWVpw5gdpi+LrxKGZrBLfY+R0ueS0V9ahdF27z9PWlZSGlLhtCvD/CsBIQzsXQHchLURuL6aouANJCo4ItvHO6zuxoU4yVVYKeLJ6w/wJrTLlCQtUi7STcnDI55mxCc9zfBwy8OoD9G2uEkqVZnFfkAH2HkmlAEPc/TSwGE8XH3qFlWItQeKMieLtwlWg534qPqSmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7T3jI5545qmL1/J3D10t9tmGcZ3W3KiAyOuKTOuZC+Q=;
 b=WTQ9wy8m/NyHiNrf2hbdGRKDtG/PD+F/mgULO/0YThZ/t60Cdo/1v7M5MLb95NPgnj6mCbbSSdlr6vJa1lrcPHTzKzU1JRolc/bog9OyHfleMx2zDT7BjdroqvuQy7IR+2P0NJTAxiw6imNjqk6b1jnQMiDJflFeCCSZ5vD3h/RtRYg4Eg7S7VzYG4U8MKU6mIjhtgeUdW2FRhAE4pG0NEJ1jXmVOjQcOB633nF3fnm8/XVy8LXwqPLtEaVQ6x0MgVeB8Vha+wEE4LekEbSM2+nibMA1wH5RExzhD5ajhU7iIW8xtUKnEl/sLPmT3f783xwaUuFRBGAS/KFcYWdGPw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH3PR10MB7307.namprd10.prod.outlook.com (2603:10b6:610:12f::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.19; Mon, 15 Sep
 2025 13:01:31 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 13:01:31 +0000
Date: Mon, 15 Sep 2025 14:01:29 +0100
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
Message-ID: <ed1c343b-db56-4eae-83e7-ffc12448fe31@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121617.GD1024672@nvidia.com>
 <872a06d7-6b74-410c-a0fe-0a64ae1efd9b@lucifer.local>
 <20250915124801.GG1024672@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250915124801.GG1024672@nvidia.com>
X-ClientProxiedBy: LO2P265CA0253.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:8a::25) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH3PR10MB7307:EE_
X-MS-Office365-Filtering-Correlation-Id: 73b0a799-dbd2-49d4-506c-08ddf457fda7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?dovrZs1epP2/X5oB/tVwwBEwxUPnPmjzSaCCcHPlb/mg7mG0SpDSTP7fNF1h?=
 =?us-ascii?Q?TinO22KYajDrbWIkjXW2VGda4qxarJ9jfgAvrx7i7LXxkiYG5xxIkLm3BeDk?=
 =?us-ascii?Q?T2fHEnd2JaYw8w9z1uuRjlo+tUIhNkP5aMV5qMQMjh1o/1MQeV06QHjNjgRe?=
 =?us-ascii?Q?+IanC//OMqwKmlDyKFYA3MrXAZqZGyZbBSQ96p4a4y3G4+6FTdBocCjcj8ss?=
 =?us-ascii?Q?g6YZhA499R4Nz5ATGiq25jIgbHrBpi3HPOXV8c1dLyqM07TJ7JwioTgRfMtp?=
 =?us-ascii?Q?uPQby8kNZQIO/77IiJy0ZUyPuZyg7couMhHYTVkwjMfgJPEk895zibbfE/sL?=
 =?us-ascii?Q?o6sWau4GqnzR04yzABf0UZZt/eFa+BXqm/v+K876OkJ+n6sQDQfAYUTfPFuu?=
 =?us-ascii?Q?w2ZG0TFFQXW0LxlA01JlTOCu7MPCrZn3SYLo2oUZz7157JsWqlsdOc1mqARA?=
 =?us-ascii?Q?ISBOHR6jr9RtPXRupYF+47suLpDNI2QnhT+Gx0/K8CuOcusa90FX/6c8+BNB?=
 =?us-ascii?Q?TpBDC0KHQEeHba3O/HxgzKuS21ZnwDDcyh6920jjmCKjuuWRTrliMZ6IZpbI?=
 =?us-ascii?Q?rSpS8FlS53ME7qGzv1WBABL9o1UjG51kPUYX6xyNZQk3pc/9NRKI6uHBTGDJ?=
 =?us-ascii?Q?QZSlTPcUNRF/6JRB7x/37HTztDqsQxa5i95UKCOC7kjj9Uv7X4W2tUUFImIk?=
 =?us-ascii?Q?l2T3Joe1zoqgupLJqgCGmk8hzQShGek3YB91paJaO5BVbHY8PBX6lqep2ozM?=
 =?us-ascii?Q?jd08e7fLdjmE5CRDQ7VSa8AkFLJlg02xkXOwIj+LI+ahg5zyw/uH7USLOflu?=
 =?us-ascii?Q?vaygGEHNwznOK+1YYSELPOIik9Eflj8NLyxvZ1Tm00jRdsPQsRGJ4Dgp1TDn?=
 =?us-ascii?Q?/50S4vgdTBQcqqfXJC3zii0GBpZM92NUqwtnrjumQXTnRahJQQj6AflLxCAm?=
 =?us-ascii?Q?wFIGWGhxg3E4YOQyHQFksBIluuXzaj5QBx4XSB9E+lJQKCFz1mZjutsxOUU8?=
 =?us-ascii?Q?t8vWj8juyaaAE/lq5Rcv1QEukw3ftFIQmbnvdDWvhdiX4FsnmhDuryH7x/PA?=
 =?us-ascii?Q?dbOin+o36Lt4tsFSrrqDz8x6eEAtBTC1jc6qVTed95vHYamoziDM53MtnPzZ?=
 =?us-ascii?Q?mw6/CljTNe4G9FHyTzLy7JcWOqi61A3RGxfdV2sdpZlHDV9Ha/4IbufuQi+T?=
 =?us-ascii?Q?7w4Gmr1vZKqkeoy5+T40sdvYVkn7nNhMDRq4ZVdWJk08eEtofco/OabfuSWl?=
 =?us-ascii?Q?Y/bT9SR3yWi1T4M2OXuqYxlYkkT7s2OsSeA99keU9gQrx1CXsOdPOyihWfIU?=
 =?us-ascii?Q?05cJmrw7Z2gmIX7QKWeqJzEDJDlDo0X0Hn01Gk04YA/2MJ18wP7MYESGDgPz?=
 =?us-ascii?Q?SjYvEHgc2POblNRxHyj2Uu5FeWGF7f+D4ISI9k+iVRSkewV4RyrZiuIkDMRt?=
 =?us-ascii?Q?r+3kZjtn3x4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?LM0Q3OY7GpaoN580nhQBBqibTyrZcBtZ92TzFXBjmvUZJP2Qz7gcL4mdAIDi?=
 =?us-ascii?Q?vSQTvczU0GaAStdxSybBpMWoGS58xTqYE6bKfpAN7k/RoxofDRyGAFWm70jM?=
 =?us-ascii?Q?I47jnNwr17Cj+TFYxwZAsYPJaqScuBkCj2fDI9GfW8fLFxFXkWJdWR22JtLr?=
 =?us-ascii?Q?/apZTkSxvDnWUnpRMjJ6O8R/svsvh8Br5oqbPIE9dwnlaVjeNwmBsR2bduRf?=
 =?us-ascii?Q?elsA/oN3mjE86Meq9PTKBhcgHpVppGBM1mCq6azQMDKwEvFLOmBkcx+wAn5b?=
 =?us-ascii?Q?D6+awlX5cT8ojAu/6GwJgzjIa7nYL5J3tboD67i28tAeeMBj2Vo1BpDBq82A?=
 =?us-ascii?Q?X49v7NEj1VlRJcS/x+/ze/TUTbAFrRbM5khInJVBdVFyYyRQ4rfc7jHuR7nK?=
 =?us-ascii?Q?Ne8iz/hrjxsqZvgas8k88kizCTPZASIGjHA5Ss4Qdcegb4Gpt/xKpq1cobzw?=
 =?us-ascii?Q?6fW4xWvGGgWQfdcCPvf0PFpKursMnZRz9TteplZ08CnkyqE/UlyJU9VFc56d?=
 =?us-ascii?Q?ehJfrct1Se5vsYa3iJe8k2ACBdaoA7O/1DpEBjLxcyeL444IQFwJcoJYzEHN?=
 =?us-ascii?Q?GHXij/NLP6PLZvJ1CiGg3bh4PIBKNDYzp6L/y0AbNbP20XSo9wJR0MjlmhxJ?=
 =?us-ascii?Q?VZZ9LnOofel7M0R3wN+yiuuBBHnd9uOUdahTaQcHYi5wqtW28p+QG0BP3V+J?=
 =?us-ascii?Q?soMBV4ig4B/+uPFKUToBOcCCHHncZBHs0le5wpX+iIeNvtI3zd4az4Nh2II4?=
 =?us-ascii?Q?emfftXyvyBgGzBXr45bKnoQWetpdo7Vwr666EVHfHPVs6GWQZdyMaolzvx3i?=
 =?us-ascii?Q?4tt3qN1zyfJ5QmAiiuUVlWnyskb3AR4QR5TFxtPOcogOO0mKumIARNqW1K0Z?=
 =?us-ascii?Q?xIdBz9Tgufcr083qTXaXQxhboc5hG9Ez77PSRiskiQ63UJBx/GLT7yudz1RO?=
 =?us-ascii?Q?2z2M/eYhb6iLqdCiYfM/RRUBfJ0ZmzxH3osmJh7JMEdAJreR20HC0ZaKRuol?=
 =?us-ascii?Q?iC+rJfWZSxL6Xpmsj43ALx4rz7bTSBsfScT3pLIABUhT1N1ZEXOHiqi1vm6J?=
 =?us-ascii?Q?an1MHq8iXo/kQP6yde5ZPCrkcaG1to6ZNpaWFnHb0byEPaqu6/HR3E3ZSfkr?=
 =?us-ascii?Q?ty3PN7gbUUhJe0wjdoiiiNSnSktU3czlYw/myxICupI949Rk5/e3l58hE5sY?=
 =?us-ascii?Q?eRv4vpowVpqpCXUnM84g163CLTzffCxG+UYj9mOba0zAcI8eY19qer7MK02W?=
 =?us-ascii?Q?GecX+3HwLCvXAOuVuOS+IGYtZiWokqkoSySN14XRu2Gus9yU5JdKgiWI3Ugh?=
 =?us-ascii?Q?TWHbvBAnzYn1P0NPr+yz9XikM+hJ5fexzeTS9D93FzTgLjyTf+jgXylfmekk?=
 =?us-ascii?Q?+iYIweewmHqHuWN1KY9fghuKxbfT1AMxqCbDpFIwXs1GDjVC4X8f2DKJfzBF?=
 =?us-ascii?Q?GAizU1YCWUsBwWBVcjKjv/92OLwuWcowST6baVXcr6FHPEONJwcNwWW5fyrJ?=
 =?us-ascii?Q?MKx0CGsrfhbkmqBdVekLRAoEa4RDqISAr1QdVOSpP/XzXo0xc0VEbs0I5mds?=
 =?us-ascii?Q?T/4D9uHFmR8eA7GKjL6e7NCrNo45lJEOy+VwZ6YaXmc8xgSeU/XD4zEJ8vpv?=
 =?us-ascii?Q?rA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: IeopUG4DCCg+izhfGVvEfwusC/t52kJWTNxcT8bVBk6waOdh5OJMkwQP8fj1UcKaDTbQcWrZLYoiPnMdWmXkoHOgmfZ+mz14VF8FLvXPgf3eOmuXdIhAfv4ONkHkTmEE7RRoKlgcFy2DmBZlNK+WSs7Al4O149zU6IN/2gfKTbQeQRMWM4zlkuahCPzqYeYBrj62keLM8cdiEGlffaDrOIyPgTdseghXPBLgByit9WEpo0sRuVvLQ6/K9aiAthwaJYJJe5NOj0vbRq4dfs5t0fQv8gOmYxdcsC6JX/T/rkNwyVyannqn+AAyHxNc/DL6Ei6G07rKo6is6o1qps0GOvfCqOWIE73hOwnV0R14vDxWsFW84zL9KD6bGQ4WgHeKKuqhwpqcmRDPuG1MLuwX+8DlG4OADITTRWmcHYMvCfO2iwxltsDQ34l9YBk4e4hRxhTnL1Y34z+f8SPbrxtoSp8OY2XMLHLPD2H3bQfCcAbfbWD8wQFCjj1+QNSAlTocdhwDS1vL28SsVufevn2WTlW7BMKjW1QEEBTJF/FgnKmhbY6bDmdsXu11fVj7y5ZgmzKCEIVzlG6O9jAVotbRV37lU+8Qa1clTyM7k89qgwk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 73b0a799-dbd2-49d4-506c-08ddf457fda7
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 13:01:31.2073
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ++Y1bMBCZC4b5CvZ3w0Wv4HdPd9aqn2WJGxh7YU6RFG+RLELl44ATbMBEtTme0Y4nVojH2LYCE1eFc4gBouD3g2qZPlKe8Kwuu9V0uWfTDw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7307
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-15_05,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0 bulkscore=0
 mlxlogscore=906 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509150123
X-Proofpoint-GUID: Ql--HIT_8MtxBZnEDec5-lg0FiGlfgfD
X-Authority-Analysis: v=2.4 cv=RtzFLDmK c=1 sm=1 tr=0 ts=68c80e32 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=RGcR6wvab_-L8bjMU00A:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAzMyBTYWx0ZWRfXxRs3l9doFo1B
 /dI6b1sEzl63wRCoxSM8zsnIBk7vam0Kt6BJ+07EIOalxuoizSyqvxeLBWdLBqtQ0Yt9vDZf2O9
 C1NchA4R7VDLqRmWNUP/VTRo4p3qh5nnxpN6tdbhiYQEfNbcR6dtYN43UVtU8sPp4x/h+phHzqv
 pQV7m2J5i1gaB/nIQjyRQs77b7HhlA5Qu9CMayeFfW/LeGHT4NpBauvCpLg9KDSw+enhXB8kqGS
 hxunD8fzGYUz87258wulLKSIo7TVa7yhfKtySdT8Nqh9Gz0ffLQB9NfLbnIqvQCzGe92jhJB3lv
 QuUQMT1tAJZ/4MeuCA8fmKyj49+fDzN2UUaZAnKF0HKaIuT/0GWo48jSCByogq0K9J9GKN0jLP1
 nq0pHSwS
X-Proofpoint-ORIG-GUID: Ql--HIT_8MtxBZnEDec5-lg0FiGlfgfD
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=BEHJXlAr;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=wq9zJxv7;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 15, 2025 at 09:48:01AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 15, 2025 at 01:43:50PM +0100, Lorenzo Stoakes wrote:
> > > > +	if (kcov->area == NULL || desc->pgoff != 0 ||
> > > > +	    vma_desc_size(desc) != size) {
> > >
> > > IMHO these range checks should be cleaned up into a helper:
> > >
> > > /* Returns true if the VMA falls within starting_pgoff to
> > >      starting_pgoff + ROUND_DOWN(length_bytes, PAGE_SIZE))
> > >    Is careful to avoid any arithmetic overflow.
> > >  */
> >
> > Right, but I can't refactor every driver I touch, it's not really tractable. I'd
> > like to get this change done before I retire :)
>
> I don't think it is a big deal, and these helpers should be part of
> the new api. You are reading and touching anyhow.

x ~230 becomes a big deal.

>
> > > If anything the action should be called mmap_action_vmalloc_user() to
> > > match how the memory was allocated instead of open coding something.
> >
> > Again we're getting into the same issue - my workload doesn't really permit
> > me to refactor every user of .mmap beyond converting sensibly to the new
> > scheme.
>
> If you are adding this explicit action concept then it should be a
> sane set of actions. Using a mixed map action to insert a vmalloc_user
> is not a reasonable thing to do.

Right I'm obviously intending there to be a sane interface.

And there are users who use mixed map to insert actual mixed map pages, so
having an interface for _that_ isn't crazy. So it's not like this is
compromising that.

(I mean an aside is we need to clean up a lot there anyway, it's a mess, but
that's out of scope here.)

>
> Jason

Anwyay, for the sake of getting this series in since you seem adament, I'll
go ahead and refactor in this case. But it's really not reasonable to
expect me to do this in each instance.

I will obviously try my best to ensure the API is as good as it can be, and
adapted to what mmap users need. That bit I am trying to get as right as I
can...

But in each individual driver's case, we have to be pragmatic.

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ed1c343b-db56-4eae-83e7-ffc12448fe31%40lucifer.local.
