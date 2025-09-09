Return-Path: <kasan-dev+bncBD6LBUWO5UMBBZXK77CQMGQELFFPZ3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 64BEEB4A833
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 11:37:44 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-406f47faa7csf28620165ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 02:37:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757410663; cv=pass;
        d=google.com; s=arc-20240605;
        b=TpR697YI88+eko3w/Xj5BEpdTwJrl5b/F7YcpXu+EY0KX5vsNvEl9Ctxe9J3w3aoq6
         gfWOeok/9yoeBx/nNxnN1/zNJoyzWvqKcovxb+RudD22zDq5nD7LU0t1Yhu4y/Zk7arB
         MTpi+QaSUFdrEvD8k3G7hE+XurgoZhVgyZwYTTZZ7gxqVTs0BQcF99wElk5gb4OIlSrs
         JURbxOyRAd01RxJQrN/OtCELRw7Zl50CGLTJEGogz94D0dbTBDNRSUafCzCHsJCQcL7i
         k5WmD5NIvprRRXmDW8gFsQYVPzgbhOxhEKP6UpEhu78hST3PjnSEyvuSobECFaoJTolZ
         YptA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ZEG5OKitUpV0YxyGmDQBHG9HmCWGF6p6XrBz+hjm8Ns=;
        fh=JpRKNrKq9Kwm5y5IYE+XgvH1oGP+/gM5K7xiazHCfjg=;
        b=fiNWKtBtyRfQiv0sGVISkkf52hjLIDnE+owAeZ6pVcU2Lc7m1P7ZxusnUtHZ4lGOMz
         lLkJogkiOzRe7c9DVo52+TBjcUkBBlZkcrOU9pvW9eqZlAEN9KeFyweJt2vy9tz6rYjF
         xoBS1mC/hcK76BbBF6InBAgrFYR59RKdi4sd/oa8WpSdKy78pt3atlXEoh1B7h7sN6Zz
         sbrqJ+j5vK8oefr/GlvaDtCl3utdY0T+mZIBcLJu73Yeo1oCBPPtTIk+fOuQHpPN/LXU
         jI5XrIcYcwMJu5K0MhQB6DrhODyRH0fzNtmWrBqZbMMzhxBTlVmIGiqhSF6WBonkl8l6
         icuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=TSref80P;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=k6PbJETG;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757410663; x=1758015463; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZEG5OKitUpV0YxyGmDQBHG9HmCWGF6p6XrBz+hjm8Ns=;
        b=ji+a0aopVaZ9RxmvWsDREKNmh+8UeCDJmIeNpUWbAoFNdsZihJ/loGJNJ6oqOqpfHh
         p1JadgkMlhNOHv/P+JaixiIzn6lrIr7FuliUmOcTaMACQYkgPanyM2keZSlu8HXim/So
         mfp+8Exk8CMJPbmm92UTVaGa1q+OVxKSDq1byjukz4BDYBe0p/gGKztkJjncYx+DOp3Y
         lNziaoETQFmT61/+u1DEHmSolgZKRR5w3ntqbTCGS669Z2rKhLfqlC7DtfzvZf1f3B/c
         a2DXYoSYyY4wQiwxhQJbpCKYI7swOe+TNFxSXYMtVXP76/+B8DLx6VOqKodt7bwVIQb+
         6pQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757410663; x=1758015463;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZEG5OKitUpV0YxyGmDQBHG9HmCWGF6p6XrBz+hjm8Ns=;
        b=SVUMz4lxm9nLhyPdyLVHcZnpjRGXCGJbyY/EKjO0vHoyFp5cgn8+K9/ih1MUdKhCco
         rV/MpXXWG6KIpr5BQgapJk2kDHDEEtSVz5k2JwySS0hBMhyJwYRRJy8jMhZ53WFwDjsx
         ISagKFSMRZZuE/TP9rte7HpzzFFBhGq+5p7DaBovUuPRAKUGl6V/jCSxXPl3nm7SF2ql
         aWfzv1bi5XOEftKzTpotEBINVPQLQnXStPYV/OgPmYTFHsq0QjQ3UZzy1hc0HKI6E7+y
         QMoLNc7CFBJozctM9t52ndHZK4tg3tMhi8wTZpicD4olhpS0bC4v2XTBtGyRu8e4viwb
         bJQw==
X-Forwarded-Encrypted: i=3; AJvYcCUad5h3i7pxhTVxDEW8qUgyGBmbXCj2aswVUiZ3lFrl0lugosq/m+gEd1Ib/LJJgGmn9AIOtg==@lfdr.de
X-Gm-Message-State: AOJu0YwaXdKx9D33W1sEOpYy5USU1MhhVFL9Gv02F10xG8+sUYr7K+I6
	bMB+InomM6CyaNGH1T+fyAWChFQqTvB+RGZZijPiRaAbXTdsUxK+rrnn
X-Google-Smtp-Source: AGHT+IFzcdjKMKxZ/sA1ZlBNpySu/M+0TLvlS82OeUr2iSJCMwcURYccROB7MTDclsIdcyHd27sojg==
X-Received: by 2002:a05:6e02:440e:20b0:3fe:f1f4:77b1 with SMTP id e9e14a558f8ab-3fef1f47850mr120434585ab.21.1757410663062;
        Tue, 09 Sep 2025 02:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZed8PS1Rw71qKfLLDPr8nSGhsovIkUJnUbQdmtStMDMJw==
Received: by 2002:a05:6e02:3093:b0:3e8:b7de:887b with SMTP id
 e9e14a558f8ab-40e14a7708als8798565ab.0.-pod-prod-04-us; Tue, 09 Sep 2025
 02:37:42 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWViU667yM56cczm6vJ/tePuQau75SF4xNwUFnsxwV0/AdTU9zyxo4izClSHGNNUvWe8MLjzaTVzcw=@googlegroups.com
X-Received: by 2002:a05:6e02:4614:b0:409:4650:2f07 with SMTP id e9e14a558f8ab-40946502fb6mr64137875ab.23.1757410662204;
        Tue, 09 Sep 2025 02:37:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757410662; cv=pass;
        d=google.com; s=arc-20240605;
        b=bcmFnKPq4uzo1DGFLHzy9oMgJFkz9uvJ+kdi+hnVDlz0kNl4Z6b7lU55EvYrE04PkZ
         KPjETyHpPQfCLxaB32Ab8l3uY9pfT6Lf7+1ta5Pqg5T2eab/F5LEBtKoD2pwCdLCTgof
         g1kwGMEFrekSABWaIrO6/6d29i49szB8SP0H/zyURie4v+6ut5InuEKm9vNhXaUJgchA
         qVVPnmuA4rrvBRd949v/8vUIUmvU+PAP+imkBg+sdcdVa1FoA7t8C0fWavtUfEaH/Ct6
         K1+wraCqdAdtMzziYLXX2o+Mf0p7w6O0fJvYEb84d5HUym2iS3mtNS+s0y84mZjAsl+c
         Qp7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=TIzTmZGc0uMPRmE9S6Iy2XV722yxu69GQPrD+2ps1Ss=;
        fh=rBgXewyurrOnUosxB6Y1BSdBMLv7NW0sq4bxnqF789M=;
        b=intvpoJq3/HIOjMdWMXlsdZSEL4K/n61Ed6v9qZzs43JjlIrtR8xVGmt+w4El0dmmd
         xPxPpc73Uxu9aAiFUBXs3xe/7lmBGRuKMkSdTXJkUABDzo+rRDSQYB4oqUnfU5BRQoxz
         v2pYajtRcSemHkP4CpE7OMM9XHmmvU1NOBEoFrcbYgiAKe+fYK+LP+E9TozpDXTiBJH0
         GGae6ZmsIrg3gJLt/gfsXJnDqNLLBdUwsYmwl9yAMlJFov+R/KNLSMj/USDYe4s56dHk
         MGVSltUZOnFL8jw5Lt3h/+W+na5Zt4g1I42HPOi4rgq08gVnyaVZ56iSQ7vLXGk7e5zr
         tJqg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=TSref80P;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=k6PbJETG;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d8f1f1f47si798047173.3.2025.09.09.02.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Sep 2025 02:37:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5897fpTe027366;
	Tue, 9 Sep 2025 09:37:29 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49226ssgkr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:37:29 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5898vCXB002755;
	Tue, 9 Sep 2025 09:37:28 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10on2088.outbound.protection.outlook.com [40.107.92.88])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdfvn8q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:37:28 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=JAlSnKdYTr2R6qghruOZydtCGFB2mWF9Q47Vo/SUTXE1ln/1Kx9X2TMxKOr4WsYR1td1GLOyxWLagDZTUOteXW+U9bKE7iTaBbWQB5LK3cxSSkXAy0nwT3JtzK/RhBHxepuvyhLR4xnpdX5UaWt3FwHmBZS6vkDuoSLxOMRtZFTrupIf/Y796Haz/NfUkxpO1XuP7vtJb2sa5/1QCACWBGnb8S34s4nXR29B4++7NsN9rD0aN277J57PtxaOnPKV6FJrSvwcF3vNPfEJgmvaE6Dar4o4KnZbFSUz30qLY3XCYt/UvYw1QCRw/dM54DUcGl3QT6c7cH0k+ypA1Zz27g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TIzTmZGc0uMPRmE9S6Iy2XV722yxu69GQPrD+2ps1Ss=;
 b=aHdKBkO8yQTKxAIh6xpes/ktRV0mBqMTrprC4jGU700VtF7sbn2yJ4XK5wbCLb85Wb+zPrSq0QPRDnzb8LfHpsNrrTLwxP+Vy6v+31ldJuc+WkjmY/MvEfom3SvSV6LCK9qZtyhotxxGUSbSJzqVOOmKSmy5EJLPBiGcMWterVvUDr2DHuZ0w3qqhUWtveZ3IifSOVnQnjaADQqxxj9HOA+OIdRN1nTcslRlhGyXMd6L8HHm22VGGT1WdOoB35uCilVtPGiBC9mpIBjcvuvMO3pBhGq8zbuQqdRxsVWeeoGgauFKYq4/b0HGDJwq6VYGJ3kVQnGUJqAKXgD/NTV6Qg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS0PR10MB6775.namprd10.prod.outlook.com (2603:10b6:8:13f::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 9 Sep
 2025 09:37:26 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Tue, 9 Sep 2025
 09:37:26 +0000
Date: Tue, 9 Sep 2025 10:37:22 +0100
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
Subject: Re: [PATCH 06/16] mm: introduce the f_op->mmap_complete, mmap_abort
 hooks
Message-ID: <8994a0f1-1217-49e6-a0db-54ddb5ab8830@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
 <ad69e837-b5c7-4e2d-a268-c63c9b4095cf@redhat.com>
 <c04357f9-795e-4a5d-b762-f140e3d413d8@lucifer.local>
 <e882bb41-f112-4ec3-a611-0b7fcf51d105@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e882bb41-f112-4ec3-a611-0b7fcf51d105@redhat.com>
X-ClientProxiedBy: AM0PR04CA0076.eurprd04.prod.outlook.com
 (2603:10a6:208:be::17) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS0PR10MB6775:EE_
X-MS-Office365-Filtering-Correlation-Id: 8f8e8beb-cebb-42b8-b82c-08ddef847c90
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?tLhWhmq1X38UP42muIa/QdKydjyyU81HlLX8GtmyAGFINp6mt/ijHjKAFaAV?=
 =?us-ascii?Q?gFxgzrMfi+2mLTHZviSbwPXAhKD52MSEk+zSu0qNvvmxC7gADOdBaApQPP0V?=
 =?us-ascii?Q?KiKBi97kQldcJryjt4DzM0C7FFEKD+52WjJqy90Fa8aGU2sCgPkG7TSI4A0c?=
 =?us-ascii?Q?e23GF++i4TyaSMX1TffAscBHCRNm697fvY5rokbZ0HE40j63PZBtEU29fyr4?=
 =?us-ascii?Q?RjN4aoELHcqWKoKqJEBTiXF8PzFJQyI5F8R3pHPvGXW85um8XwnLlmADiMJ8?=
 =?us-ascii?Q?UZ/xNlSy2RieoxGB88mpRAepcdKeMAPT8zh15/QChDJVMNgVuLJMO1I9Ulzy?=
 =?us-ascii?Q?og7y1VUZL1B3fvgVhXZgKOZ3igOYX4YMaxglQSmORqAueozjiTJizg9D1k6U?=
 =?us-ascii?Q?hAoyDM1KPyucvcnP4bG8vjQAKcX2vtHocNwMcXFUi747R6tfzuObjyJLFx92?=
 =?us-ascii?Q?WlQg8ywzrJ22r3zWnP0bjMzONlr3PVHpQmbEgAF1RujtkrUNV3D+I4sUKZJ9?=
 =?us-ascii?Q?aMrZkIN/dFYGVAjc/X7Gqzj5r+uSWbTEl7Zg9GAf8uQVvqveyBT9DW7fv22O?=
 =?us-ascii?Q?hcg3ugBA3J3OxaQ3LtkxktHGv9lBI0g5FuubSf+xv/1+fE/Up2wGfkOcccnP?=
 =?us-ascii?Q?CEVXylnay2W0byIqoYRXht76oYvdQSwKiHBAJHP6DnVXNYHPRaivueoOcxsf?=
 =?us-ascii?Q?Lv1W3999eWDmw42JSCuTMVZrKevR6AFEur5vDIE2ULB7CNQtS6fppBmMHoPk?=
 =?us-ascii?Q?naTXaufiMfjfouP5rUzDEJHpE+82cjMvStu6eHjjQgZEGnQsA+7Bqeke75aQ?=
 =?us-ascii?Q?x4BZi1/UAM3+OhkUP1qupOc59UFF9BfHbR6HcF19FFT9WPeKxuOusJ1epcbJ?=
 =?us-ascii?Q?oFXViU7dMg/mdV5tBEtwUGD5IqRXGa+DoLDC4bgFVaXlC/DEEt1B+cpWoN+B?=
 =?us-ascii?Q?pvq0sKlXp33OVGoVNnheBBGoTjl827pM5d1T6RmSB9JO0jAVlc1e//85Jexm?=
 =?us-ascii?Q?F32tx2779QTqqi0MhvEuWVdPwNY27h5Z64+JQdyJOSU3vgK77tLAxAmVGO3Z?=
 =?us-ascii?Q?FJTeLq9gGcDfl9pgFzdmkg5w+KRaLKat8gAON1Pl290/PPkQYZL0TFG1Q75Z?=
 =?us-ascii?Q?V0mUpAHiOJksdvbjVS6DoKVeJtHEavZIKnaKmDmGRWVAP5bSgDALFdUUL4Je?=
 =?us-ascii?Q?d8pa7edVDW2GWOmvEXFxWcE0MEHTiJSSvrrMKqDGBw0zZXas+IAOMe0XQGfu?=
 =?us-ascii?Q?pr5+4327BQJg4r1RJgi9YxCZMRXyGd4BpCvv4wKKR+7MrGmmlaVfquVovQ4f?=
 =?us-ascii?Q?YvM8j0XZCFfix9hdnouSRYpiMK6Ag/s13d6xBQp71oclTRqsoMWsIz42z8+z?=
 =?us-ascii?Q?6UbnAYcU4xiJABqd0n/Hi3L9J9QiN470PidjLyCZ9GAh+QY7wpkyxpyK+CtL?=
 =?us-ascii?Q?AUoJF5xrxPI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?NoAVNoceKTqK9B/1sNef19QSHWhVUGwy52VmyAshl9gsTJROLmxJb8DUxyHZ?=
 =?us-ascii?Q?IBaV/XMZpKv2FcJ4XiD5vjgDtzGsiDolxyjcyyi0DfAC0IPnYbVRACtAoYN1?=
 =?us-ascii?Q?M4F8oDAyDX7de8SEaBxNo9bI2YkAmIxB2dEHqg5WdsWHndyEEcOhIgWymRSI?=
 =?us-ascii?Q?G5ZNDf3tmz0cDoHKCMIZ40u3LKeWXecjqH7gFabzz6GC3Tb7MLWArP7HtNhJ?=
 =?us-ascii?Q?CcTB+rW6xmOVn+kgVHduZKQuyuGLmiJVL1nkgKh1GA/bD/GYuAff8vUGbyOf?=
 =?us-ascii?Q?yOQtb2LyElTxPI/YBwdILB+84vAV2tCWXYjXj8asQP/aWrOSuiJTJ0o0uoDg?=
 =?us-ascii?Q?JF/5rLONA7CexP/cZw1Cv/WDNC2JMixxirQSmLURZCZfVCfjN2GC1m5jqCPD?=
 =?us-ascii?Q?QtCd3nsQNm1slctFo8UBuJGK/v0RCUTm0/CUN2vt9e6Gk7S6CNIiiiXwZQzi?=
 =?us-ascii?Q?cCZFekONX3wbrB4mOsoRGpLhuLNIKZYn/Ughw0Trj+aQL+s/YY19Iw1e0YX+?=
 =?us-ascii?Q?PCKpPEaH9SbrkZwd92gplY0D5ZW4aCSZhRYFRg3d8EQgSlrQqzSvVLLp7n0I?=
 =?us-ascii?Q?RfzsVMOH0Yc3GZ00l4j+Tp9hS0KzHcI7X2LZ/PN6pSy3urSIoMUv9VWRsN/b?=
 =?us-ascii?Q?1J2XoXKQLYpIo7lBcIi6nUXyJxKqY07p7NwyXdI3ifUDjB/q8t0ICbW9XJQg?=
 =?us-ascii?Q?pJhFUn/j4JAC+cQIWERhiDxxhxXo8cy06usgttcIKGmUltyUFRvQLR4YVyQa?=
 =?us-ascii?Q?8yf6dRjTiB+95Q5zogSoOTXW5qIuUxo3vh/2MFm5+mj0gzNc7XxSfMaaL02E?=
 =?us-ascii?Q?1S4M/fKE6ATGynjSBuMJRPVCgZi6T/AEzoh8LqbMYfJ6atVH8aFIA+DqXAB7?=
 =?us-ascii?Q?hMAU1bNrcdII6zZDQhSh2wOkKC+4hUCjgfOk0Id3r5qn79QtYZMNZ0e/0+YW?=
 =?us-ascii?Q?iDo3fizOpw9hRXWFVHzrDtkrWCcHn5aXsIxLCA/Ur+HisQJhYRD8hTG5WcGF?=
 =?us-ascii?Q?DijFVVfioTLpABJxqTLrVk0QLvpVP/GpkAkA+l2E55Nrjbp9V6I0cE7zpZ7Y?=
 =?us-ascii?Q?C1DJbVnxuYu/6FUwx9jnoD0Py//xX9ilqNCazwk9B54ZU1kwl+TQqiFm6Wv7?=
 =?us-ascii?Q?Wmgu+TvkjMCSgEyJbB6h85eUBsPCV4W6GgTH0sflPwDWlXQJWGYRSOxSIppr?=
 =?us-ascii?Q?YvuKslucNCbEFumq+UWpAk9ToTPRQ8JU1A/5AvmCiv3cypJ3Ptg0cDKx8jWL?=
 =?us-ascii?Q?ekC+yILaH/7EhgCF4jU6fftquT2BdNy1oPKeiIJ7wltVf3gSyRrPthY+4gNo?=
 =?us-ascii?Q?PEvINhx1aupxNuUUCBAkQFtJeIf4AuHjy+HTWpXkI1tWvhFgWH+1fHtrdINl?=
 =?us-ascii?Q?Mh7dy6KCPjPg7SIcSD9Q4ORrltgW1PQ3frRWH5Wm3tkbBu925VAV4a8XiSFW?=
 =?us-ascii?Q?wItcBcm1M1QfmHMFvs/LaaawMDkBj5odLWtzEIPPQPVn88N+V6BTdUKSKvss?=
 =?us-ascii?Q?AJIylvo3+8AHLb+8IS/V99UjNXINrP4ELZrLIugWZ3XkkdK2bnZgCofR/oZo?=
 =?us-ascii?Q?KhKDOlJM/4M8EbizqrG79gZIcmqtEGnHuD3ssv5p985CYUxj2UE6Aul3hZuq?=
 =?us-ascii?Q?kQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: /H6redPxiUdjGAuDgvO+w7LRBlicllo0jAZ1QGtuashQzNqooEoKIaPrx+m7g015IMeOKfb8sHDzWeUVmu5ccLXV9foN6t3b2hrzhr0GNmEVD3LpOY+01O/A6nHU9ox0FLxIUtz0D1XfvoWNpIgrem6n392F+NUI2ijzbKHf8UHlYRHr3z4Q+rukuLS5YqXo1w3O94GEQqo80Q0HCx1aByOfvwhz09Yq+LLcaCDFDAAunQDyybZWq6HrLhuqTV5nSl7AFzDGN6oNOeOz8JvM7N0p+uv+FWtfCvi1kxSGhikubSBavwK0s+w0mMS/JeGoIsK1kdomH55ZFUw8qeLNXxkHbbQqDVPx6T5QrSBYB7lZCk4LCOzfpYVyHrVsuTh/csKVBJ8lrz3GnEaX+WZBoM3gJ6HYF11pOu39p9COzzcqZ80uYdMUJSIZaUi+MDc6RUfkeLNOSgXRMCB+Mptfky27o8kVb1nnYB4MgOTKijEGQHxD/dsYpcjHi7y0X/WRL8wlE/cZ0z/QhLQDB+hyNtBGXdKJYOictQezGvvhsvOoLMKdGBSvHavK5OYUrLZin5tbrPZMNP8XiC3H5JEdAn9Jw2ZMhzkPrkakenWI7q8=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 8f8e8beb-cebb-42b8-b82c-08ddef847c90
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Sep 2025 09:37:26.1757
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: eHLIp2gX6nDTGkKojO0vF9ts3RjtUKTL6dAM+FJpypXyXA9xUeToXsgtWc2cTuaXTVGU3Bsw2nZl/Cl12BtvUe9rDv9tYzBfaCGZY4EXKhM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR10MB6775
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_06,2025-09-08_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=903 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509090094
X-Authority-Analysis: v=2.4 cv=QeRmvtbv c=1 sm=1 tr=0 ts=68bff559 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=VadzeYaZer0EV3dStXgA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12084
X-Proofpoint-ORIG-GUID: Z6qQJXlrKKGR_nX47Wc-Jeca5dPnQQSt
X-Proofpoint-GUID: Z6qQJXlrKKGR_nX47Wc-Jeca5dPnQQSt
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1OCBTYWx0ZWRfX46Dr+R+CqQHH
 WLTSlVgHMZxoaUpeES03Uz4qrcQL8AtcUvS4Y2NtF3JsrZqAvPCYjNqG6sEvbNILucAO3FDvGAF
 gKeSddC5m0Aw7fj6dTIRNfIY5OjpVphOypRSHUL1PPXnCiUyOrho0fceF54ktFs8cyQnywqtPXp
 tN9R1Sf5q45Y9VoDlghYblC3EX90lIcTUCYosdTtYY77d8SdrH12owWu0cCkr6puLKHIcEf2L+F
 8ikYPwuTkCSYO15sD9jRx1UXHLFSQYhGOKzGz18m0RcJncaemEZJAZufD4PqneE5B/jqjO8nZ4E
 hMbKaUSliS13xrNIUcJFjjbaV2v8O4C9LHtV3ZYHRfVdgS9BVQfMnjYGbh+xjD2RNd/VyV9r156
 tPtP3E6yLHc4h34dtvZk6y45MvO6Ug==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=TSref80P;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=k6PbJETG;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Sep 09, 2025 at 11:26:21AM +0200, David Hildenbrand wrote:
> > >
> > > In particular, the mmap_complete() looks like another candidate for letting
> > > a driver just go crazy on the vma? :)
> >
> > Well there's only so much we can do. In an ideal world we'd treat VMAs as
> > entirely internal data structures and pass some sort of opaque thing around, but
> > we have to keep things real here :)
>
> Right, we'd pass something around that cannot be easily abused (like
> modifying random vma flags in mmap_complete).
>
> So I was wondering if most operations that driver would perform during the
> mmap_complete() could be be abstracted, and only those then be called with
> whatever opaque thing we return here.

Well there's 2 issues at play:

1. I might end up having to rewrite _large parts_ of kernel functionality all of
   which relies on there being a vma parameter (or might find that to be
   intractable).

2. There's always the 'odd ones out' :) so there'll be some drivers that
   absolutely do need to have access to this.

But as I was writing this I thought of an idea - why don't we have something
opaque like this, perhaps with accessor functions, but then _give the ability to
get the VMA if you REALLY have to_.

That way we can handle both problems without too much trouble.

Also Jason suggested generic functions that can just be assigned to
.mmap_complete for instance, which would obviously eliminate the crazy
factor a lot too.

I'm going to refactor to try to put ONLY prepopulate logic in
.mmap_complete where possible which fits with all of this.

>
> But I have no feeling about what crazy things a driver might do. Just
> calling remap_pfn_range() would be easy, for example, and we could abstract
> that.

Yeah, I've obviously already added some wrappers for these.

BTW I really really hate that STUPID ->vm_pgoff hack, if not for that, life
would be much simpler.

But instead now we need to specify PFN in the damn remap prepare wrapper in
case of CoW. God.

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8994a0f1-1217-49e6-a0db-54ddb5ab8830%40lucifer.local.
