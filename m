Return-Path: <kasan-dev+bncBD6LBUWO5UMBB3HT7LCQMGQEEXMAGAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 96E41B48B2E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 13:11:42 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-77278d3789csf9478771b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 04:11:42 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757329901; cv=pass;
        d=google.com; s=arc-20240605;
        b=lIRcSqimq3l61uGAP6Cm3vVkpQDunAGiEhD7TxXATG2t9ijseqsBen3AFXB/qUKIFG
         ufB4BbuU+D+pfz5bhUIHU8ddy3cSANVE6SM8fKyHFc8oN4bFOwCkdLN500vZjJNRIMam
         n5FBO4fhjCmxhJ8dtWMb47gEeDKbL2Rx49wpUqCALUd9PbzD+EJ/txiihf/92cvH6UXX
         WzbNLWN8LEmYIuzrKyjBHe/bKO6x6Hpoi3/VY7SYQ/eNZ3AT6N9O+jkbRfAmvp+9247b
         8FZibIz9mqfPlve8JLAI1csDR+LxaxQXS4+QQwcHRWyXKxyhmzvU79QJE4/B2G628kRV
         laPQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4N06O668ZocSNZnE6GnQxROcz3ih/BywquFx0gSBEZg=;
        fh=tZWcC1Ryag+6Neo/JvDYe+Fea3BPFc5bsPqX+eK6lE8=;
        b=ZBzqkg+qy8979IikoY0mSz8/N6EPqUX5Ho3UcacbdbFnme1FKlJjGvN1GnH0EUYBL7
         wvm7tlPViQt/IuW0suBKR4eXSbvnaCSs/Hoa3hybrdDK7wis3z/htBRNr+b/CInjaS46
         nzp4rJ8o7gfiUeD7plBnhgjP5u5EfQ1uUQYKc91YNa/s8MHicHtoui3Or184lTA9+vYk
         N6n30JcCrGXWiM/UjCejLk14JKbQpmJhW188o60L3Denhnsjqe6qJe2MAuqbvvLv93A6
         4QT7OgW+fUCKzHEhQUxFbBRze5OQCgNqpZu6sPYq3r+Ak9vvWGU4Z9Jg8imJREq7O/4f
         lJGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=n99bVbKq;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=UNtIpMqH;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757329901; x=1757934701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4N06O668ZocSNZnE6GnQxROcz3ih/BywquFx0gSBEZg=;
        b=GCr58IkhSDj9BpYEF5tLqtzC17Qu5djYfrquhKnULyoNKXwo5FbdD/03fXHyPFWizf
         fzdwyhwNyq3PbR2lwYYY6hpNNyv5R4xy/xXvcCSkbRi17JuMWM9TUqDASMfHEdnHSQuB
         cxMs/OaDOJTgC9V20EqixTqSXznpxdptc8N0RxPr1Dp5mzA0z15AAq4eLd1FaCemAuWK
         MKUGDBCd8VOEZ+0vCTsjVLtafkpezcYuxjj/SeJK+dqoHN+EmHgDBm5rwBdLorqRT9xu
         7qidFUMO7awNm27tZVcNdbogrn6quR+4THiSUX6u1bb01lFvVBsD60/HohZLUtGraX7B
         wzFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757329901; x=1757934701;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4N06O668ZocSNZnE6GnQxROcz3ih/BywquFx0gSBEZg=;
        b=vamHu9YGkvbnNquaiO7c0J1gecquQ4MjPxA/vonxVErZAE4XWSsn60GD7x4IPEHUec
         WUAtaDGOmFgInRmyEh1GOPyOv+it0rOBht+Ob+FVlHnU6dA1LXsM0XMoumQ/gmxmFlip
         y6QBUb3QFLVA7DnR4d7PLAOQVE0qOHtz/NM3De7btOF/7m+VKrOPp5vVi1Nq14TNrTF8
         YhT0CvxY/vaH3df96TL31C1v+wH5M5iKMbnRkFa5saywFL/A+OjhA3rIh9Mnva4YpW9k
         Bwr4lZ7OWdQD8D77LsFVNkpnq2hkGOZ/I3wzJGv2qn+SEQ5qO6QwG58VSRufgfWal0+C
         wZHw==
X-Forwarded-Encrypted: i=3; AJvYcCX0aNGo0Gwz+XjpIHpo9YxCJb27h92h/2d6cmvi8/Jj3/OFAvqlcXVzAf/MAzpJ8MDGaCjnSA==@lfdr.de
X-Gm-Message-State: AOJu0YzIwliOHaftvGwTJj6oMXjBq3J2V/ntD03k9VPZ9/vxc/m8flKi
	zwtNHn8qkvYYspYnAraDGtiMJK0KODF2fkrUZ8Cx6q31CksuDdJhVHJo
X-Google-Smtp-Source: AGHT+IFIoeF5ILWVabKcOlJJq3zN6FBOcHOjxJ8Oyo2oMOGn2puGoVbSkWrTqQx/xA0X84I3/ghu5A==
X-Received: by 2002:a05:6a20:394a:b0:243:aca2:e500 with SMTP id adf61e73a8af0-253444153damr12032652637.29.1757329900945;
        Mon, 08 Sep 2025 04:11:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5DbjDPUDNrvM5Td/ltzE02X/Px5gCne0q5NvIviEJuQw==
Received: by 2002:a17:90b:3c0f:b0:324:e4c7:f1ad with SMTP id
 98e67ed59e1d1-32bca9fd043ls3770755a91.1.-pod-prod-03-us; Mon, 08 Sep 2025
 04:11:39 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXf1os/b/Gxp7wIJlL4e6DI4AMHTloMgStSXcI0H3nxFkLYnPhMCjXzUiexmcKspGZrCiUZ+bKY4Do=@googlegroups.com
X-Received: by 2002:a17:90b:3f8e:b0:32d:41bb:2055 with SMTP id 98e67ed59e1d1-32d43f473admr9398354a91.14.1757329899433;
        Mon, 08 Sep 2025 04:11:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757329899; cv=pass;
        d=google.com; s=arc-20240605;
        b=fRUTpOn3HcCPF5V9TA2Z3zzF54K7dDlJiLfrLtyBvwHd3McKSTSSp2hg6ZbT1KweaF
         59IPZW0q1gqW47IfDESGrBDN7pTh3k9QMb0QREKqDReCClJzxAcSZmNvqMtxG1yQd5iI
         EO1iuRHKPCzjTfB51YL6H6G7HJbFXDxDjxTUdwYHSn30ZKcuXwHU8JRS1eB+nF7ouUCs
         Dbz5yB8+ISmsZERRJOtuyAZSl3O17Y3zZpa8Txq4I+riQkDs/jdlQUPcRWaE/ssKugGt
         6/RXLUBbayVie3JRsCshKg5v2RJDXQ+PHdweV/7+k0jbxUrKT9S7f0DdbjBDDjmHaiab
         vC9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=x2m2zJltpI2d75i0wgHzJI3NxuI4tTUMGch3HIo1zkM=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=Ne/7qTf/j1hD70BjweQKSfIP0c6c0kXQgOI7B4a/A5ArbgMR2pGDbMSB2k4vlhb6Nj
         ABWHVwBE5RVnOjj1zEvvWl9f/0JGb6I1kJmjj6USRmnEuFxQP5ytxwQfXszXpkidAs5W
         UrhAU81qb20kZ96CD0p9FJ9Bppn8twFalZOjTSv/sAv1JiLizknGmCufSIIDBx97UtoW
         a0sfQJ8y8VT6EjYuCWlLPi0pULDIadEVAHxl8VrILJJJJbBO7fuumwr7/tmkBzU1Gjfj
         gCB4fZzq5OnfYtwz5Qn5gYCjkuuq7VaiXtzdNelxV6NI7FuzwGEFfsft187G2t7OL5YO
         zptQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=n99bVbKq;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=UNtIpMqH;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32b94707585si541377a91.1.2025.09.08.04.11.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 04:11:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588AsxUN014185;
	Mon, 8 Sep 2025 11:11:29 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491wt5g0y4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:28 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5889YAKo030737;
	Mon, 8 Sep 2025 11:11:27 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12on2042.outbound.protection.outlook.com [40.107.244.42])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd819u7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:27 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SgMPXspYgBEw77Lj74oiAKOXqle3cpEOEic5BeQGHDhcGSYfV7lSLzDJvUD1rPvlWkNfGKJaylLSR4Jf7pvJS5ERuRfAKRqbVnvmanEQgb0GIrrbukD1cwLlPWphd+GqbeQrsPZn+XWeG2LY1rhsurmXFH5VAyM8Bh7qG6EidLt1AtZUj3R4d9EqcNWv8cBN0KCxHnIjW0ppck55QAIZyJYpS4l3VheGCeKWSGhigYy9yTRfyFmgyGyfCCRxLPe0Sz6pYK7UKkOfPKBtcUs7k7xrujGNmhJaqS8ld5bdeI7ypUmdrIxxdoG2M6OgzJxRlVZ91mheBVxn4Y4EWuXcDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=x2m2zJltpI2d75i0wgHzJI3NxuI4tTUMGch3HIo1zkM=;
 b=Aj/cq0bsC+UtINi+qOtvM6RdYl+A33ZNxXTuBBdCHGP8MzWZ+qpMobotDLu/vbXkN2NGI3mGQyOlf0fDibTrKrFwoKPQ4v2h9HIYJq+VrW3ySwUiaXW/393pKakAyysbyp39+bMH4Mlp+VcM56upIdTfrnTqvIpBcyMKMFGm/YcLhQNgOUmA6oO7dCjRacviUjl8ME5LxlmAh+LvPuYow4iPCJbxqZ6VzFuuQZvyTLXykCRiG9VONFeG5M8gqrox+V1CL4bL25UED++vqPrdeB5abo6YRC91hQjlOdyikdZ2Z47atclObGbFu3nzUgVE1BJvqKNoNqTTFN/gqXa8fw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS7PR10MB7155.namprd10.prod.outlook.com (2603:10b6:8:e0::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 11:11:19 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 11:11:19 +0000
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: [PATCH 05/16] mm/vma: rename mmap internal functions to avoid confusion
Date: Mon,  8 Sep 2025 12:10:36 +0100
Message-ID: <626763f17440bd69a70391b2676e5719c4c6e35f.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GVZP280CA0066.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:270::13) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS7PR10MB7155:EE_
X-MS-Office365-Filtering-Correlation-Id: 0c10ec92-f5c0-4fb2-2e4b-08ddeec86fb7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?fJsAGUh1nw6ES1DR+uvg5v/kp1C9oEl4SvcQN2PZfqXiVeX+BLROh35QqKaj?=
 =?us-ascii?Q?ypKPPdIT89GpCu2+7cI3OysLnFfoy7o2XI51A+059IvlOsj2VXjlDbCKbU93?=
 =?us-ascii?Q?mnbxCKC1Lw/1t2f9gP8NeL6cRZlJfQ686SZ2iZPraqVV/SDhHAy7/LfTLwYj?=
 =?us-ascii?Q?kgMfQgp7TedkIIFV+TDInNWeUPmy/gJXV22ZO47SPhHp94/IYBv9HpiUeusj?=
 =?us-ascii?Q?PEkJUX+Hw3037DJ/l3dwxOnSOMiIg/21aPZj21NWuNPXCaRDQkQ+Vz+n9t7n?=
 =?us-ascii?Q?cWtcen+v93f+/nmGs4f8vXaQSolcDA1QdX8qlERJVZllck2GbvA4HNTqcn/p?=
 =?us-ascii?Q?xglrwpBbifcZ7BDD5E6JU/lXj44FTIIOkzSGz6/zzOloJc13KzWceJAKMy95?=
 =?us-ascii?Q?y082MVl41MJvuZpX4SlGFE3EjsQOQw1WHzmJjcasH2SOBUB4mpkQW3udpnzq?=
 =?us-ascii?Q?M8kEE+dd7d3gGDQaUtDmROVo/bgD2PGvjhOKDzQigwYJtGXkp+TLze0yhDiC?=
 =?us-ascii?Q?lxUYEhoGxW2L65PsJCJoy90FdQgN0rjNCYsWg1KFXgrNT1WGZKqnr8Tkqab0?=
 =?us-ascii?Q?86rB4GI2OGDOHec7w28Jvg/zwYcjVvcnf1jAlN2SWZXcMAomS3+fgZbzkOAJ?=
 =?us-ascii?Q?MpJOJLrlko50AfcSmtbX4gr4u6UMNxyn8VA//bmvr6D7OtgMoqoY0qkO2xxL?=
 =?us-ascii?Q?9nQt0xy9KUL792K0KCLEtMHbyAiGjjPJRKJkm7Pyqr8aezZOCoVvSmolG3ZO?=
 =?us-ascii?Q?Ta5eEgYc7RJpWpVao0PG2+AVe4BqmUae9HkknJCeDcBWD+YRwgr/OBB6Sg84?=
 =?us-ascii?Q?p5NvawyYDliaSPEN5LXbOGTLFypvbA/lCdZPhb489TR/B1XombS6cfUbw4TJ?=
 =?us-ascii?Q?aINqAnGJdcUsqdC1X2//RVe7Htj5eUP1gYJYPgjunLbcfSabK6I80099zOxi?=
 =?us-ascii?Q?TsK3QMNnzdGM78Ma/9SBCxcSn9QyaVzP+Ob/pQuOjbTM1PV2xWsnP7MqRvKm?=
 =?us-ascii?Q?8zXXnwCdEO/JKo//RLo07hYc3VoZKhlLYZcdH9mXWXvD5UDU6CfUiJbO/Fri?=
 =?us-ascii?Q?m500iDuq6RJA8Q1Eq0pJcIkibIIxpAC7C6htgIf3xhQRNCzclb7VnLl+xPiR?=
 =?us-ascii?Q?hGX6LG0s9B22gfGl9/FQdqbAeBpwbzGZBpRQ+M09e9yPjHWh5/kR4lp6M2Jv?=
 =?us-ascii?Q?cgIkjI1rs1huwyLC+TUoml/iF/CE8b2ZXSJNmEVN2+PHqEG2MfHe4D5efvFo?=
 =?us-ascii?Q?S7zd65kWlPAY3Ox1ZuW9nTEi9H5gNSB6G2CbjZzrLaiGAObRZCFO8NFUisiZ?=
 =?us-ascii?Q?Q7ZaRenOi2vjr7648n6sFBE1HdnJhFSXayXRIOh/YuNML4MckNlwEoYsBb5h?=
 =?us-ascii?Q?SEnLi0KGJXw3LmNwzUOM82Eh6KQWHywllcLy2lg1Fn33Uc6dmfoSSuZi/Myi?=
 =?us-ascii?Q?yucabGIYMKU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?rKvOKsWwfnBbzUGAEQsFgQM+oSFe0wOZtRRVLk63mwoWPr04ufCK5LgDCVDA?=
 =?us-ascii?Q?fTLMbe7LCIM36Fy/MI4RqYRyaZbFAirbZUJiy7NaG9+s7f41pnoio5cMh5Ee?=
 =?us-ascii?Q?kHhBBKUvMcCDPhX0n8QS4Uskv3IJvUfVLu4ypYTIw61zL6qk8/wSGvpmuQ8F?=
 =?us-ascii?Q?jh9vyUwv8IFgmazGZUiZN0RRHFT7j++Qz5NhqU05oUSyX2H5fohsrgr3P8fU?=
 =?us-ascii?Q?AXgzEBYzb8QtzyYzPy6+BQBsDQv7DiQXId5lZUhf8myQjQLCuQdhvRC3c+Ak?=
 =?us-ascii?Q?r/VRYjYEatIQNujk3raPBkB1JcVPmmXmEZg2nqfYqcKZDR3xGn5UAjEvqOOX?=
 =?us-ascii?Q?mjOCXlyPdRY/ZQLL4lAu3R70R587sU94kL/eodBaEfBvDMoQY4xN+r2NWLX1?=
 =?us-ascii?Q?Wh6jxcE9S9rQBjak+sL0UdXt0WD/V41T3K5mvLAHdQLAt5yu58P+ywGVI7GE?=
 =?us-ascii?Q?0jt5Oi3NM8WBUHr8pc21OWz4oSacd2xObt2PF+Xcj8R2xm1mr4KyXz+IrHQZ?=
 =?us-ascii?Q?9zN4LxF26/5JNjQr6JkBFoBl/fmvO3tNpXZMsDV3tpPwbyrAU8aoMRzpiME4?=
 =?us-ascii?Q?O5ZI3Naw6agbkk333zXH0Zx1lf9CTx336kmMDw8CdgBVFn0gEvehKi1CR8Oo?=
 =?us-ascii?Q?pmval2sY25ZmhB4BKkGEjUmP9e/CEb1+0JOvE51+havXOWCS7zOgqsKctxbP?=
 =?us-ascii?Q?gRz2uFMWZYvBNS093eTLxMEyGyzYJiGI/VYzPaBzWylxGWvdQHWfARca0WL9?=
 =?us-ascii?Q?NRPy1mdxuoBV134lEgPhvBCGZK1yGOky2bZd0pWKirFHetLgtenNJp4nr0C7?=
 =?us-ascii?Q?TCWVBSCAPfYxHMKVByd5lRIDcW1aNl0Fu/5J9WNXVq5f6Z69axOOyeftqkg+?=
 =?us-ascii?Q?LbwGLGFQNKENzXv2BknNxtz0fJWFqj7BBChJLxTuU5F26eW0z5R9eKEBLcvg?=
 =?us-ascii?Q?pQJr1fIycOYVNtWzRUbDXgmZSHRYQp/9UDVmeodQXlpLTTKYtZD3GlChesRm?=
 =?us-ascii?Q?VSyIgsqAaEZgK0QN39l6xQ7/jkXjPp6e54p02SLJA9NDbRVFx9ris6gfXL6W?=
 =?us-ascii?Q?4vwpJfybyDcSQeRsePlAYFxafo2bo9gpCjzfRjjmMZkTAqILLRkMOo6v0zqu?=
 =?us-ascii?Q?dBsO3scdTb11k/0oFGxbuzR+c80Lm4w7Zbhrc47z27kNzMSB2+13FDFGhSxW?=
 =?us-ascii?Q?8P9FszPr3Mufn9I7GpEJot6kP8vacHzj2xRfKiA1Ps2xEDARJaLdOExSPiL1?=
 =?us-ascii?Q?SdpIsr7KCJreYBJ1mTLq9xkYXXg00zTKFRXe4PdgFAN4TyKULkkDLthJOQFz?=
 =?us-ascii?Q?CpPPAwF0RfxCnOfTDw7P6vCx88m20OMITSHQx7fUmf9nortmqsI1sUqX0ymU?=
 =?us-ascii?Q?TPmJ2mEPVeP9OEtEiBtpMZmKqsq2+PtqmWZ2d5p2rzErnLcTrYFYZbbc+j1Y?=
 =?us-ascii?Q?X9sSZI+ysfd2tHvTla0+4ww2DOwX2LaXGYgcOMZjTfFZwNKQvnjwg4qnNIpg?=
 =?us-ascii?Q?gg/8ytkJla0S59RqrmYWygo7c6jmLwrCekpOu+A1Uz1fz5XF084wLldC/mZn?=
 =?us-ascii?Q?NzXg0WO6C9V0o2QkJ4EmPOtgqgE8bSmlyIqxTo5Id/LQKsCeX4pXJ+7Xxpof?=
 =?us-ascii?Q?YA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: ETNn+vKgGRj90fn3dMMOx9eJA/r8WsgB6S73gV7qGDaKsKL8AiANDihkvqn0vZOkVSM20a6wXUA+aHY0xFjFVIp+ElqLlyKL5mI4gbZ/QmUdhCrxsNeY2yqBhsYnoHQM9iWNe+SVPpa8hi69esRgg5FW2IfXLblkylEuNbKjbpi0xAfxrVeKkpsMI4mpF+acyDHKsZxHThYiCUHt5+HlPr7xxuBl8z4xylKNMKnyEsICzv3+2g8NzHlrrBNrR1DxyAzGRLj3KNWB4PuGLomGMh5c3aSXZhuzmqj+PXCZT4wC3iTFNrNwI7BPvF4ojgZkq4a9CpyyhABjOclnJDETenonTRJQ4mtAgd9BJlCHaC38ceFh6vfZgPzZbbz2PjeVbmqhJzpgCa7vlpKJwEMcoH4kyqph6CbTseXdca7D4c22Zx7a4w3LWlQzRvcW6SYJaARZkCVRDSzoD9xxWqc5peTuQtQm/xVkrpW9vzXHp+nIj8tok8NZJ7cuma/k85neWU3TX8+Yc4ad31FBXilZbFrxL41CcMY/AkG+tzDMymOo6SCPKbR8IOwct5qIppYERoDgcCT+q9CvPQlu8H415iLIcSfIBcoaU1SvvHQsXRw=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0c10ec92-f5c0-4fb2-2e4b-08ddeec86fb7
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 11:11:19.3409
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: U2Vl/xtGhpYFsq1Ij+9X6Y7AYlb7G7KWPeB2udVVZG61jAp2LnTghDVLywtDg8Mc27J+exFjrucAJfTcYwUjHS6/ZVWpc8AhCqGxp8cHRDE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB7155
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509080113
X-Authority-Analysis: v=2.4 cv=ON0n3TaB c=1 sm=1 tr=0 ts=68beb9e0 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=QQqg7_2JtjZtJ-DplxwA:9
X-Proofpoint-ORIG-GUID: L2muTcunIzeSwfBYBqVKynE-73PpkFBr
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDExMSBTYWx0ZWRfX6vRX62kU8AH0
 M+2FTXHRaAwsI3/2A2UG197wggf3oMkgtO3jJJxS+gcqmeDvSq7u+rWBhMgkN9A2T5Or1IVAIdM
 zXusAALak8PFXWFr3kvbriLoT8LnOKFkIBz5i/sDvCHmiiG2B8x3q4knpgPcWt85NsmlzqswhrB
 d3iWVMVD7jFljznS5Tl5O/EI5s1nKiM+UEvTMNUj08ZRZV3fYClO2cwMrVROYNF2gjQ0mv17mya
 Cq6zsmLYgC4HPGmp8dYjaOJy2F1UctejYCIEh7Zk3XpYlR2mPbwrrYo9d0cvdtxZxHYtCL8XqdZ
 9B2t0wGgY2ByVO9oWh6jG77XdQm3eYmgXzc0QCCa3cFzfribPkyJHhvDIO8RKPpIhtfzl02w0Zm
 xm9xMmVp
X-Proofpoint-GUID: L2muTcunIzeSwfBYBqVKynE-73PpkFBr
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=n99bVbKq;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=UNtIpMqH;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Now we have the f_op->mmap_prepare() hook, having a static function called
__mmap_prepare() that has nothing to do with it is confusing, so rename the
function.

Additionally rename __mmap_complete() to __mmap_epilogue(), as we intend to
provide a f_op->mmap_complete() callback.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/vma.c | 14 +++++++-------
 1 file changed, 7 insertions(+), 7 deletions(-)

diff --git a/mm/vma.c b/mm/vma.c
index abe0da33c844..0efa4288570e 100644
--- a/mm/vma.c
+++ b/mm/vma.c
@@ -2329,7 +2329,7 @@ static void update_ksm_flags(struct mmap_state *map)
 }
 
 /*
- * __mmap_prepare() - Prepare to gather any overlapping VMAs that need to be
+ * __mmap_prelude() - Prepare to gather any overlapping VMAs that need to be
  * unmapped once the map operation is completed, check limits, account mapping
  * and clean up any pre-existing VMAs.
  *
@@ -2338,7 +2338,7 @@ static void update_ksm_flags(struct mmap_state *map)
  *
  * Returns: 0 on success, error code otherwise.
  */
-static int __mmap_prepare(struct mmap_state *map, struct list_head *uf)
+static int __mmap_prelude(struct mmap_state *map, struct list_head *uf)
 {
 	int error;
 	struct vma_iterator *vmi = map->vmi;
@@ -2515,13 +2515,13 @@ static int __mmap_new_vma(struct mmap_state *map, struct vm_area_struct **vmap)
 }
 
 /*
- * __mmap_complete() - Unmap any VMAs we overlap, account memory mapping
+ * __mmap_epilogue() - Unmap any VMAs we overlap, account memory mapping
  *                     statistics, handle locking and finalise the VMA.
  *
  * @map: Mapping state.
  * @vma: Merged or newly allocated VMA for the mmap()'d region.
  */
-static void __mmap_complete(struct mmap_state *map, struct vm_area_struct *vma)
+static void __mmap_epilogue(struct mmap_state *map, struct vm_area_struct *vma)
 {
 	struct mm_struct *mm = map->mm;
 	vm_flags_t vm_flags = vma->vm_flags;
@@ -2649,7 +2649,7 @@ static unsigned long __mmap_region(struct file *file, unsigned long addr,
 
 	map.check_ksm_early = can_set_ksm_flags_early(&map);
 
-	error = __mmap_prepare(&map, uf);
+	error = __mmap_prelude(&map, uf);
 	if (!error && have_mmap_prepare)
 		error = call_mmap_prepare(&map);
 	if (error)
@@ -2675,11 +2675,11 @@ static unsigned long __mmap_region(struct file *file, unsigned long addr,
 	if (have_mmap_prepare)
 		set_vma_user_defined_fields(vma, &map);
 
-	__mmap_complete(&map, vma);
+	__mmap_epilogue(&map, vma);
 
 	return addr;
 
-	/* Accounting was done by __mmap_prepare(). */
+	/* Accounting was done by __mmap_prelude(). */
 unacct_error:
 	if (map.charged)
 		vm_unacct_memory(map.charged);
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/626763f17440bd69a70391b2676e5719c4c6e35f.1757329751.git.lorenzo.stoakes%40oracle.com.
