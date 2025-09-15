Return-Path: <kasan-dev+bncBD6LBUWO5UMBBAFUUDDAMGQEU75DYYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9918EB57DEF
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 15:52:02 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-424090abf73sf8247245ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 06:52:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757944321; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zs51JFXsXrjZEyhnNT0fNzF2PpCph2wT7ns4WQi1mX2Pe6md2DFkyDqyCymK8oHf8s
         ejqOdgeQ+yneBeOCIYVZA2rhes1UthfwtdRLUeis7gqx7NReZTkZZ0qLXwcyRnHrtPP3
         VqZk80gzd+2lzXYLFw9x14MCcIK/ylR8Zg87M7/q0BpaPQpUQkhOcyt0Z5Tne8tI7VoC
         4fXx5Fo+IKlfdXgGSTOT1qcVsB2CaNTkrmPxTV4IvPY6HP/nihLi4SPpQ8y778EJyL6i
         B+taYGX2OdanYHLmqCCLRX2ylZBkVYkM/t0kSDCJDWywHyqotgPVmY5TpdtS8+duyrcw
         yJng==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=1mV9Lq9czgCz6lVMJwkrDkYCQ5qytOgbAxuv+XVzbGE=;
        fh=IKiv8hHd4U0hz37/olmFH+X38ZGBldIFArQmAia5NdY=;
        b=H5ujNXqGqr1yPfq/Lbbvp3KCbW4UgVa64eLvo7uAGYYONWTB8JZH8hScyeV/L6ZJrn
         qZ9cP30h9eUL/30wPGZfIopftPsuwnrRgRABiafcMkmgCotP285cJcKAu812BVJzeNmc
         trcO+Rogd/6F65KkCmYSPsEvjmj8IvavNAc/KYtCvSajWLwR2a7b1JZvLzb8OcCyn1EV
         veiUCdDBlZuargu5LZgtI5cWvISXHvIJ6LVgmI8PbaGhenJEMuwYEQ+KLp83A8DNyD7l
         BA4Fn/3Z8xd7BRW/rFQAth0cqEZGV67WpBrxX1WIERly2/Blty46CzxLeQdzpPbT9Icl
         drGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Je/bfMan";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=eRJbFBJO;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757944321; x=1758549121; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=1mV9Lq9czgCz6lVMJwkrDkYCQ5qytOgbAxuv+XVzbGE=;
        b=octu4KfuXx9pwgR/KffZPqosWKFdSq6AnKYPqs2ilWpccVf7GX7FeRvapRTcJAcBSm
         ZeFkhz9fzt/08q5E+yrUaHQmPhacSaJaq6BzMWBj2huUgimwUtziEazMtbwm/l159n2E
         dmZllLOh5nyt3qEWCKdzNLrEiN9ztFZUtgbv5EV1cRiD3fd9z/EwPbwn3aaQpPBlU7i5
         Cw1xpQQsbKwkGm6UV1NL+siHwbsq7bxBwelYtujSrdhh0Opi8zbGdCdFlZxfLBq1tMFP
         0O3WxlQ/QNc/GCMtv4JVSQc84/kF6K7S9uHLyIpDJwS4cN1TppBbW1dQcyI6aNOn0FWl
         D1hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757944321; x=1758549121;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1mV9Lq9czgCz6lVMJwkrDkYCQ5qytOgbAxuv+XVzbGE=;
        b=p7c4/qdsR0YTLDWft/1MxBc5m5YQk6/e9UeVtUCtF/g20ArRecscR9tpGEdaU44K9P
         gnpQ4jvK/3wAGjmC6T9LOPUJe0ub9cQ9/8sn+BkdF6uXPpsiEx33Hdn0yNSu5dUfWY7v
         gqexBPIuAgeSTY9ZiFGlmKhHFNNXd6UCy7mQD2ZDc3gcIDWIUYVgw+n4gylLdIQ6KcR9
         X+lcfY1K1hSDsCGjTOZWdk3J6cWaXf1EWdj6Ab0HYEDZPmyJFdJfOYZco3xRICZ5/F6/
         pgEb11/2YDjy242Ehu1BmZsQMNEWbROXgv8oX7vSyef/c9heabnGyOlNC1HrspUNqIoD
         VcRw==
X-Forwarded-Encrypted: i=3; AJvYcCVxiO/PsHuSCDGStxLdWqIc+Zp4pRTQOQLc0gejsqhT6llIkP3HJflhn/AYQohSoXfNT9bDcg==@lfdr.de
X-Gm-Message-State: AOJu0YwxyM9cjAp1LO2Z63bFCqgVtgA/l9jQXDJD+sxE6IZ7tHhMpkgw
	hn/rutC/MZk3+afKtoRG5duVreEkX9X56xqJwdDu548mQO4mWhJqcoc/
X-Google-Smtp-Source: AGHT+IHOT1KfoWU2PgMew9+vd6mZi5ur3C0PoQqwJ12gp90/bCvze2/ACRHjOZb16y6nJXfT8mt2ow==
X-Received: by 2002:a05:6e02:1a89:b0:3f1:931f:bc33 with SMTP id e9e14a558f8ab-420a4174333mr121303785ab.24.1757944321008;
        Mon, 15 Sep 2025 06:52:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6yPSOYVbYkFlQI0X6u6Rz7rlpl7FuauaG7z3PHtHHoaQ==
Received: by 2002:a05:6e02:ecc:b0:424:19b:1d0c with SMTP id
 e9e14a558f8ab-424019b1e96ls5829175ab.0.-pod-prod-07-us; Mon, 15 Sep 2025
 06:52:00 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWrci0cwDatktBh5eTLbEzvIOgrdmldIt65dPzAXqpCenjk3WANsBaKgYcGVXE29WFXp/veSyJeCgo=@googlegroups.com
X-Received: by 2002:a05:6e02:11a4:b0:421:1f0f:5ff3 with SMTP id e9e14a558f8ab-4211f0f60admr85416575ab.26.1757944319891;
        Mon, 15 Sep 2025 06:51:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757944319; cv=pass;
        d=google.com; s=arc-20240605;
        b=XoXvlEsLhkBElU1frtEPYNk8m+hw96Dupj/AQ4g89l5nbQq8RzBkC9zDY4YG9SYQjr
         mTdbomMsHjVpeQohqlpH6T+S6F4lmsacWmeksslRtY1P2/sZqrIKljufrVVLX5mIdRJy
         sEpHCRwN4NLDvP5xjuJQmLreLRnbh64GWZandW8cTXDg2vCTNiPo8M1EVx36dGhEgkgT
         utyoJMflPjC0y+SoLp90sAUXSTIPG5eWEJm7ACvThuPOPwb0oj67RLBYGS7I5n7dn87P
         xXepCBKalKrqFpTZzsnxsxTzvDRAHIkuJb4urGI685T9twQbrdou51e/wjjV/o5qDd/c
         VMWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=kqola0MdN7qJFl5/SccvB5ilHkN8lF2Mp/LG0uGP1VM=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=diytm7lu2BDXCqY1Z/OR0wezTO3BWt27UT4lwbuKHBhLzwyogFuAGdVeBiT1jfBV6W
         fzSgvzQY++j+G+FpJWvl8AqoSVXCOkx3EyhZqyPyUba7WOe4VCTQCJOVBhKKECItzNG/
         JG0X+bCNWG8dJowE4bqL0QfJkDfpULRf5WHbjJfu13xeGv8lkYcxxz2m5WXcljEJvW4S
         0I6aWKwZXgEUjNHK5Vb3xE7GjQXmtjKSudvB5NuuB4lfMhXC2IbMrdzxoUiadYjiUrcE
         KnQCFmliN7z4wZ5WikdxUJYU753AxiZBOQoQ3OIVR1HDWz8l6UJMDv1ERA+dtrPKNCsU
         k0hA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Je/bfMan";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=eRJbFBJO;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-424048cbef3si1587595ab.5.2025.09.15.06.51.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Sep 2025 06:51:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58FDBsaA009125;
	Mon, 15 Sep 2025 13:51:59 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4950gbjdt4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 13:51:58 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58FCoHA3010552;
	Mon, 15 Sep 2025 13:51:58 GMT
Received: from sa9pr02cu001.outbound.protection.outlook.com (mail-southcentralusazon11013063.outbound.protection.outlook.com [40.93.196.63])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2b27j4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 13:51:58 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=GgFBdxd+Jv1zpCAMAHA8fHBCt+MRwQN2radDYRhINqqmaSu8vX3NsZ6NdoQagSMGCvk19VE/DUBCYyFQYz8lPLqpr70vnMhaT+X0wAkz3GQ5P6+s4TZ5urJVQSHm3EDpMrCoVS1bODjZuaV6Ro7eBJAgo7zxRwPlKRjqQnia8+5R/XEKDJJrh3OoETuAgn/lPHsoKkqCjb+nxul+D9ov7yWYiKKKSLLx4z2MfHMSVOfRURqwAiD3vGcfRL7CAQYH2w1ujTRwoWIQpFQU2bAKomJ+uwzHuJocKtA21DrZP1PB1wpFgykUuwpHwh05I7UqkuCSqrI8sKWa++46wCxbWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kqola0MdN7qJFl5/SccvB5ilHkN8lF2Mp/LG0uGP1VM=;
 b=C9YLxOLhNr4oxKDBR2wtYGjijsvns9J9OLPczoQ92iMFBK8BkGC8+bm0SCWNOyvix1TAcvXI8AjPefaI1qn8EKXC99fnkWlyPpT0VvpWV7aiUppycqxRAJrq0S86690wMkRZKkovk4mkEe9L1gddmXpMBNjPdBa3BakPY3sR2BpVSy25L440iibSqM1tETnqzko/BQzqCc539iVkrVWeLxGnz6sr0HgsEzwJkExhSN6OtwDggIKouMp/M1LEh5GR/ocZYhV7NYmN6LeLVBFTXu3iIdhWd7a5XMkpof5Fei4NHf/rSmCF5IizaeapGr6mxQuZmfBelsa7NngMVjUcRA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by LV3PR10MB8178.namprd10.prod.outlook.com (2603:10b6:408:28c::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.19; Mon, 15 Sep
 2025 13:51:54 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 13:51:54 +0000
Date: Mon, 15 Sep 2025 14:51:52 +0100
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
Message-ID: <c9c576db-a8d6-4a69-a7f6-2de4ab11390b@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121112.GC1024672@nvidia.com>
 <77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c@lucifer.local>
 <20250915124259.GF1024672@nvidia.com>
 <5be340e8-353a-4cde-8770-136a515f326a@lucifer.local>
 <20250915131142.GI1024672@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250915131142.GI1024672@nvidia.com>
X-ClientProxiedBy: LO2P265CA0376.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:a3::28) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|LV3PR10MB8178:EE_
X-MS-Office365-Filtering-Correlation-Id: 61017c59-a778-4efa-9177-08ddf45f07b3
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?RyTD4n53R7bk2i7QEH16BZGE74ArW3Fte1TI2FFlIEbCn2KofG3dLnA6Bnx8?=
 =?us-ascii?Q?kBsI0ddoitZ6mp4/9ESzU2aKKuPLEv8VVoS7lK35pG0LJv8QdEZaLBD8T9Pu?=
 =?us-ascii?Q?0sLf73XZmvaNb4HXR7WDdM982/v9jXmHPxRxOnTq08lWBiHvkfF0T4J8w3nM?=
 =?us-ascii?Q?NQlTGIhAfFUuIZOLYrfKqKW+NWNX438KGgP73OqQDA4V5kH6DeLXLArkuxQL?=
 =?us-ascii?Q?fpr0P6H4bFO13mMXwXw663ip8UpMbtogyVvkR+iK9qji6ibng3ptDhJVqkWb?=
 =?us-ascii?Q?ofZ334wSUf40ZZ6QBOnQktfLShy6gAHC4lIZ0WlkXUVyxrWthwblmb7Nif85?=
 =?us-ascii?Q?FCXQlQCyLJbuVHbsMwFbAcUlYyjjQ31zr7YWyrRl6lQcXMVJ9ugejBiCgnZw?=
 =?us-ascii?Q?KqRsGRsYvF5FZUnJWydqu8KF4Ux4b/7W8VG3pCpNy3D0ID2DN5JouKEMiR/u?=
 =?us-ascii?Q?qIyQLRIYoObReqnYOq4qyfJVaCojiua9wKWPiVPMx+WEtzGHtztyB9EP/lUz?=
 =?us-ascii?Q?JGIz78jqDvoz6DO0ExN4ZbXQZPFVtP5LzQznHHXUwrS7Rs51Zubo5W/RlOid?=
 =?us-ascii?Q?0Knk7CtKvshPl9rLa6e7/qb1C+OkV4vrS7yh7am+WVLo4RmfHxGiNNtxNXHN?=
 =?us-ascii?Q?q15RAnTC1e7LFYpPOi/Fw0d9zt1f4RT03TuzLNznNyRXnG1O3YgC601M7K0y?=
 =?us-ascii?Q?64pnPgCeZJM8Xb8umDc44U5SDOjsLpDx2SmHV2utqE3NZn8h9aGVl4KyMa0o?=
 =?us-ascii?Q?8wE0ZoxOjSRRZqU3imhTckhsrq4uxvh8dU4fUfaLEnkC4PaipfqQqzNYWRqr?=
 =?us-ascii?Q?3+tAkMi0lmc1yrTMrarfJN4jnN/Jj+i8ZkECy0jG7YqOOuEA1bpvb7cI1osZ?=
 =?us-ascii?Q?hse7xKkJsaSmtFlKO/JdterWeykaHtBC4sMPkU18zFDCrlNOgk3yu6HKE2ZM?=
 =?us-ascii?Q?EbsA2w/5ua74QXi9KiF1tgU3YOzOUnK6fxmUlhISgL196WbeHwdxGhWpP94p?=
 =?us-ascii?Q?zTOxfzu0ZQhWEqfk0abledRxUDt7keEqmpC80t1S0Aq80jnA/gaRSgwVCkXa?=
 =?us-ascii?Q?ujQgPY0MOHT/bBzrtD3kzh1ZmPC7TKfaUiQ1zMro3MCmVexu/BexQIqbTNoJ?=
 =?us-ascii?Q?BEvgKwyEfoztH6GO8WC3chJg+R0sYxK3hcXXFwwwyQEhsgQx0I7syQtrR2tO?=
 =?us-ascii?Q?3hBl0MK37hTz/1EahcHbu+1bZ4tZKxQCmsME0D/NEaWyRwr+uep1TVCiegFn?=
 =?us-ascii?Q?BpLveBo4EnD/wQvviz5ycM7LWkcleVYihcuIbPSuvgGnfRg00G3HIV+kiyKJ?=
 =?us-ascii?Q?wriH35UX4adsx+hy+9NDU4ruvQg+KYcMfYTj7t1Uj4OERM7lGx4Cjhb+88Pn?=
 =?us-ascii?Q?e/Ga8wQHXbHE+qOs6v2VYypgfGO11wuQURSwq/8RpRYq5pdReTivv8tOqmzl?=
 =?us-ascii?Q?aWLrV6AXov0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?1f23maKpzUfQPEb8tUw/BwwCraOzyEKMHo7gMKsW4nYCmAXofpgBjWI6A+e1?=
 =?us-ascii?Q?EWMBgNZgiup3VNntUQreyfeRWnk3hsJKYfKKcwQqWGb7YNZxbTXe7AiNS89S?=
 =?us-ascii?Q?vs2UKd3nGMRkkhDSLedukWqr7Z2jWpnhJMH2sGVQ1ABi/hlW7rnzoGpry35M?=
 =?us-ascii?Q?O7lzR14N4MkKYwwjihiR0kygw/HRAwhpIP6UkbCw8E74mTIYTO5vScKgOIk5?=
 =?us-ascii?Q?6U2mtinWP0t0dc1AQCMVgbK18LB0kuYdunY2MgokIiO7X5U6krGOA596OlFg?=
 =?us-ascii?Q?3XZUWXvWSbDk01/2OmctVTb8TOfg24CEpsGt8b4ECv8a34+7jQHBJl3pO7JF?=
 =?us-ascii?Q?3+rhpm+tLjXO5++8DinxvgyIjhU1CRkOupm1IY6aNp16aweRcWXN8t8ARJx3?=
 =?us-ascii?Q?ce/5z+iQEi7nG5yt/nlGeOfSyuAwwgt5TjK/q5Jz6v2DxRNhuzPo7V/PxRQ3?=
 =?us-ascii?Q?OIJ+j5vHpZrmnXMTTkbyNtIcK3q5eZVU4NE4ZGrhFGhEmJf26zqFyO5i56vD?=
 =?us-ascii?Q?CnjNCKnCs/+ypOgKcEALaovUUiCXeSxVcdGucFTrB5oLWJ4eOWfUzDbhYtoZ?=
 =?us-ascii?Q?AoyDW221f4D5Xn37RM2lQCUKWVuBPh2LvZx1v0aoFpkQ+ZzIDKss+xmdTuQP?=
 =?us-ascii?Q?oJ+c7wzmZ6YnJ0hl0JYcB/uJoGgcwdvgPuj+Dz+P1FmB5L0NfUiQG/SB+Ble?=
 =?us-ascii?Q?FJN2Q83f9N0DZGpD2on2octcZ3Q0e6ebt7UXxhX+ctbN4l6aP3WLmV0QOdff?=
 =?us-ascii?Q?KGVHc0z4h0PzdAH5B0IkDv5cG1VYhi1uFFvRmVNKZvSReYyG1czQR78/5+zU?=
 =?us-ascii?Q?fpmzHwIN35JoDX/vzJJKqIjLNfzmNKp/MwAHkkVwZ2mK3lLVQT6yAjqL/+JM?=
 =?us-ascii?Q?GJWVkVTvwlyToGjuQLzmlDummK3OHMlbRVpnP7XNAlGeRB3OBv4C39lG6JY/?=
 =?us-ascii?Q?mAm6UosALr3P5l6IrsdsZysmD4Wbw3JKeq2Oqnt4FN7mhbQEASMkJ5kHJqk+?=
 =?us-ascii?Q?e2ZSjNEjalr6rQvE7C3le3Mb7pMJsQd51W6VqlKg/MOgAOJlNjy48kGjS1z7?=
 =?us-ascii?Q?8sb9YaDAFTTHQ+Y6HExKQC+SnzDV17HsOeViWJFZS+n1/2qdLM8E5pT87xd0?=
 =?us-ascii?Q?LHMX0pcZm4vYx+BoBTG+4dxYZS2Koo6DXT3CaEDYh155/M8oN+l5/i+5VuD8?=
 =?us-ascii?Q?rmj7inhUg/CpsjEbSMjRUmcBnyEGw1ZQzumDJSqFj7J9hjGOFSEnhpLT/wy0?=
 =?us-ascii?Q?fHIGoi5fEKvbcSdHHk8YEs7QEf5ZI8W6PIa92SAdLJup+EkyXt0BhjygL2sW?=
 =?us-ascii?Q?aXQPfmXM0f/pwPqDZtDR9qKBqx7N8ZTuDR5KIQ5+UxN8MFtyn3OhjH6mQii1?=
 =?us-ascii?Q?A74ctus+dfEMXw16O9NwSv6ILjV7xhlVwuUInBHWsQ+CiaZqnYIC8xOpD/RX?=
 =?us-ascii?Q?5awjKY15xseqWaM12zCl9HL74mSPY12Nc5BYkuBbtY1e8NhUSG+gWTB9MEsA?=
 =?us-ascii?Q?U4gCzb93YSRKI+ZokkLuoNcKqw/8QFDX/5akg1a2iNyCorHTeysPrnjCW4q/?=
 =?us-ascii?Q?tSD1g52vMoIk/GvsztE/cezJaVHjmIQ7VEnVvYJG2/6A6f8iPvgiI5z/eZvM?=
 =?us-ascii?Q?dA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: r2CgnSnv92gAftfG2ElsbuVf7bKxxw2kyFDIsqGzXW6atNOzV2mPEZS9nsVJH7VmlSC6S5XLyLkD3Ti4Q5OrFt6t+QX0kbNrPK6xIFk8iBVkOxq6SO8BmVGKO3jKRsj+s/TEP+dz+O3agmYD8kzTNA9J8cZCb6LpQFZcJjPUWHM7P16GHPlVYEjH/MIMPfpg3+hio5fMCulUVz+UCO96nuAippMoUfNTxf5sys1jY6qtd3D+CDXbYfnxLPcROf0Rx1ifZt6jBTjmgXmp2OuMZft6bMVtl9XnCJIV+O06js2YkvcKJBw7ta0vqcpPi+ObVWmVfw+4Ih04oRTF8MFIIeFg7EBqM6SoNR9i+UkTvOjHR1bWwZ/DXpq7xoh28BMzGFvrEcT8HggQKwe4YtMrDRkqTZzP5ARb33DW79+3bAgVVUTPSyjj8AdUvEYZWf4VLnwb0AXqJjO6BSbN05Ix76aWo/XlykhVxI/KXX3cSluskx2awZkV6LLMZTlghzHYFS3wirybLHnriM6XbV5YnSSXaM3hiUdz/bexB/YVENbLi+cN3WT+5XHFVZpWI/ilbdI+QUhTBQ6ccFs5JYExbGPB1O2uu5vWECuvsjsEhjg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 61017c59-a778-4efa-9177-08ddf45f07b3
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 13:51:54.6639
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: yT+WR51P9CDksfkZ3sF5mySHwBZVaiUnn5UUshuo89gtQUrDxoAJElPzT7h6wYEvmNfJCYyffH896iJyeSgrrdQhte9KoX/i+k36KJuvTw4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV3PR10MB8178
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-15_05,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0 adultscore=0
 mlxlogscore=999 spamscore=0 mlxscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509150131
X-Proofpoint-GUID: Tt78ya3lwAW9H9OpVwGXwb3vZZb5UFKN
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAyNyBTYWx0ZWRfX8GMWsOytK/as
 y8lD++yW8Se8b8ZVOMBbKja/Dg+9OOIt6VFELCHxAAH2CNBpTYCnkEgJDgeTHFC4AdPPRTQjBWu
 4V/mC+ta/k/I32lVtKxVO9yXWJQXhsKiL2yqCNjpP98KOzCQNwIWlMpQ8rz9liBPMdfkx4vTtv5
 /Bbs7Gqok7EslQwKwj9O416g0CUAerrJbcATd0/hBQepqnzRr9FJuhInseo/+LaDCA5u8SllDuy
 TPgHQ0XYrC/2m4fu4/Z/3KcdE5VERVIAlQw3twb4iLdvmv81OOZuZkjobd/slLdGBLX21jEuIPY
 eI2UbwQO7n//uBhopIb0n3wDcK2lAm+9xpqYfuOWfc1/gCIP6/4m8aLrIyi9QPesGlCZVSbemlj
 6RgR4in/
X-Authority-Analysis: v=2.4 cv=QIloRhLL c=1 sm=1 tr=0 ts=68c819fe b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=mw15ZVPzND2R50_b3F4A:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: Tt78ya3lwAW9H9OpVwGXwb3vZZb5UFKN
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="Je/bfMan";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=eRJbFBJO;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 15, 2025 at 10:11:42AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 15, 2025 at 01:54:05PM +0100, Lorenzo Stoakes wrote:
> > > Just mark the functions as manipulating the action using the 'action'
> > > in the fuction name.
> >
> > Because now sub-callers that partially map using one method and partially map
> > using another now need to have a desc too that they have to 'just know' which
> > fields to update or artificially set up.
>
> Huh? There is only on desc->action, how can you have more than one
> action with this scheme?

Because you use a custom hook that can in turn perform actions? As I've
implemented for vmcore?

>
> One action is the right thing anyhow, we can't meaningfully mix
> different action types in the same VMA. That's nonsense.

OK, except that's how 'true' mixed maps work though right? As vmcore is doing?

>
> You may need more flexible ways to get the address lists down the road
> because not every driver will be contiguous, but that should still be
> one action.
>
> > The vmcore case does something like this.
>
> vmcore is a true MIXEDMAP, it isn't doing two actions. These mixedmap
> helpers just aren't good for what mixedmap needs.. Mixed map need a
> list of physical pfns with a bit indicating if they are "special" or
> not. If you do it with a callback or a kmalloc allocation it doesn't
> matter.

Well it's a mix of actions to accomodate PFNs and normal pages as
implemented via a custom hook that can invoke each.

>
> vmcore would then populate that list with its mixture of special and
> non-sepcial memory and do a single mixedmem action.

I'm confused as to why you say a helper would be no good here, then go on
to delineate how a helper could work...

>
> I think this series should drop the mixedmem stuff, it is the most
> complicated action type. A vmalloc_user action is better for kcov.

Fine, I mean if we could find a way to explicitly just give a list of stuff
to map that'd be _great_ vs. having a custom hook.

If we can avoid custom hooks altogether that'd be ideal.

Anyway I'll drop the mixed map stuff, fine.

>
> And maybe that is just a comment overall. This would be nicer if each
> series focused on adding one action with a three-four mmap users
> converted to use it as an example case.

In future series I'll try to group by the action type.

This series is _setting up this to be a possibility at all_.

The idea was that I could put fundamentals in that should cover most cases,
I could then go on to implement them in (relative) peace...

I mean once I drop the mixed map stuff, and refactor to vmalloc_user(),
then we are pretty much doing that, modulo a single vmalloc_user() case.

So maybe I should drop the vmalloc_user() bits too and make this a
remap-only change...

But I don't want to tackle _all_ remap cases here.

I want to add this functionality in and have it ready for next cycle (yeah
not so sure about that now...) so I can then do follow up work.

Am trying to do it before Kernel Recipes which I'll be at and then a (very
very very needed) couple weeks vacaation.

Anyway maybe if I simplify there's still a shot at this landing in time...

>
> Eg there are not that many places calling vmalloc_user(), a single
> series could convert alot of them.
>
> If you did it this way we'd discover that there are already
> helpers for vmalloc_user():
>
> 	return remap_vmalloc_range(vma, mdev_state->memblk, 0);
>
> And kcov looks buggy to not be using it already. The above gets the
> VMA type right and doesn't force mixedmap :)

Right, I mean maybe.

If I can take care of low hanging fruit relatively easily then maybe it'll
be more practical to refactor the 'odd ones out'.

>
> Then the series goals are a bit better we can actually fully convert
> and remove things like remap_vmalloc_range() in single series. That
> looks feasible to me.

Right.

I'd love to drop unused stuff earlier, so _that_ is not an unreasonable
requirement.

>
> Jason

I guess I'll do a respin then as per above.

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c9c576db-a8d6-4a69-a7f6-2de4ab11390b%40lucifer.local.
