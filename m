Return-Path: <kasan-dev+bncBD6LBUWO5UMBBSV4Q7DAMGQEAEUSYZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3555FB521C1
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:23:40 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b5fbf0388esf592571cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:23:40 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535819; cv=pass;
        d=google.com; s=arc-20240605;
        b=FcPa9M/Y6FJ0944sQsdR0ggEFJn510n0tC+8a2ojqVL99cMGR40qoJzF+ajSU3LPtj
         L94lf+/eRkXsE6OQFyf5fJ7YynhpwRssn3xqgaslhXRRY6t1lx3pDvITUiSyS8fm0UcQ
         vSNdmlbf3UdcOIyQYJsZm+pPznfvIewFbdfeUf7kaqpl164lhcWEcvTGsDpx1V3BSDtr
         7+xGovxTAL/aHRHMmgxZjqCE5PiebzrwGDIg54boM4+8Z90jFJPacH9rNqUiAA5wryCk
         ikLqXvOQQIDFaBYZVAcf6tWIUKF6rARBJGA5GWpf0LKZ5X2FclVzHKRDcQQYSemrkSMl
         HJTA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=WVh0Op4AL7zMxmipilhOJ3pC6Ct6M8sER0jsbaoR1yg=;
        fh=azA/MFvNxDXgBViPAMlmmqeZbNV1CGjlpzZ8x1XrVpY=;
        b=WdrYwhSF5OnSi37nRmUbrOj/5Gv19HZgbK3CtRRq1yR/fZRU3EiLRDcZOWVOHUAgfT
         pjwLwyrwI2N3gZsJMGwQtgaFZhHBpC9Ed73kj9hgO3LNYIirqnCIyQS7dLmb57gboIhP
         XBTcN9+N0QXIAuD0DIGSXkkkMCDRXbZIoyhEzY9yKfxeTO/lQ5joesbxSH+aU2K4LQO/
         163bL/KV3nRRzIKl6u7Oz8kNEs5Oje029ApX4kPbIuSWcrTeRqP5QYgRxmTKT8jH8jD8
         YSpR11tnaz8jcZr8e1sEQ3iEkdJBX2yy1nja1a9Zo95SMFyFCh44LWm9mrRfKZNB+dOl
         5MuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="fECf/Vps";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=JcaYp9vb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535819; x=1758140619; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WVh0Op4AL7zMxmipilhOJ3pC6Ct6M8sER0jsbaoR1yg=;
        b=bYpwCg60yFGYfUAmm4pkdYP6XudqVXt70Ubrjxyg3g4QM/eS/xyJ2OOs9rjXI8MHQQ
         0LvTwk4FdTRjD4tf1FXANZE3T3Y2CKOJOUyyxbsOSfsss5ifxRuUIvMwtWcONrcYcxa/
         7FUMrJkWpc+xcB7ZJL1IxzCNLlzNZFs5zitvcrnKy7WSIH3kU3JgncY/JtNUJTRdKTmQ
         IKaM83l2mid/2fo2tQfUm0eq5bwPzp+bFmS2PfmyHiBhuHf1HI/j+ie+oQY7lVFmwMX2
         LFlX68jPWVuR0L6FXzJxQHyu7lukv/9DR08pdtrBSCCRY+SHfHIAB+REj/MyAEaREa4C
         CyyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535819; x=1758140619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WVh0Op4AL7zMxmipilhOJ3pC6Ct6M8sER0jsbaoR1yg=;
        b=Vq8yH8Pw6h7vTRhpBk0gc2mXqS3/2cPIQUc80JThWrw0Hn+GuakwwxptU6jPIfM77s
         +CqZhC8fhTk8Me99Om+FqrPZ6XhN/7PVORBUNkmQIZk2Jj8TZ1EAieHAlF/h30MwB0zE
         CYM+G3uqGlGmWlmXZIEtplrI4zgOmCuK8NxT8rmKRq813fvpdZBqcDFhEJ7UGUTxNKTJ
         peqRk/34iQIRhZl2xUoqrIl2wtX0G94XSyxXcr3UigPn4uApvTtJkbbPByT8oEpdnOqT
         D8OmkwBgVjbZGZFQdYfKrTAwgNBkt7xJqpVL8mZwDw6L8+4XgYlIDX0pyaosunDAgPgU
         XzdA==
X-Forwarded-Encrypted: i=3; AJvYcCXX7wYDw6dnBIRSUFiCvsUg/HL3XGHUIFU5VlimNcn37GeYtffp0p9t9vbAkXpanB77mPPH8A==@lfdr.de
X-Gm-Message-State: AOJu0YyaaIcoL0BhuYqtSrhCj7qJRQitjBg6ppU+Hb3Q/gJ/UnbtVjMi
	5WpgoiIYy721uayCudZ9eNUWdxJH1udM7SMq6uv6Hn849RBkOL5qXPoB
X-Google-Smtp-Source: AGHT+IElBrQ3T/uQGCKMsop7Qim4rOYbbGF6Nznqk1QXQ2NpkAGM97Apc3pxgcSGwvy+bqV51iaiPA==
X-Received: by 2002:a05:622a:50e:b0:4a7:1401:95a0 with SMTP id d75a77b69052e-4b5f834ab2cmr182594531cf.2.1757535818706;
        Wed, 10 Sep 2025 13:23:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcmhemg5w2HGwHF8jTb7/oGa4YoDFFR3OJAyfJeaOIoYA==
Received: by 2002:a05:622a:20f:b0:4a8:17dc:d1ee with SMTP id
 d75a77b69052e-4b636b8e2dcls916851cf.0.-pod-prod-08-us; Wed, 10 Sep 2025
 13:23:37 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV7T+cZI/FiNsFjuVru+0G/6OtgRyeSLfpzchZn3lLc4HNhFVTC8U8U84PRzuXjGtxR5TUpGnX8upU=@googlegroups.com
X-Received: by 2002:a05:622a:189b:b0:4b4:c44f:1a7b with SMTP id d75a77b69052e-4b5f8454f57mr172909271cf.62.1757535817555;
        Wed, 10 Sep 2025 13:23:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535817; cv=pass;
        d=google.com; s=arc-20240605;
        b=FLLcCEQxnM097UsoPnNGuDNrZj5Gmb6idUmp7QNkBr65RKW3x6ESDTdu4q40Qp8rIa
         dcSprKBbJzeJJgWHjped6gFdFkayYmvHR1vdDieqlxxUgIwR7uNR7EitxlYfgxS71xei
         i+RoQww/TXFnIoW845lvz5g3AqLCNBEYEWkEJQeCXAUPY55vDYPbmyg2hzsN94HV/weh
         SeG0dHyENiWGiTXQBLH+uZlwx3zoQzrR3/7zAqir6O/grkTD1JipLlcHBgEsJn5qXkfs
         OVcnjpCkG6yxjwSUwKzJ7cGIiA1BQC/64eoom80OfOqcEmZYXRBUSplmObcct2rGmaxw
         u98Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=IdO+5riToqMw0UNPLrgmJbck6oD8g2wCEdmFRuXk5ts=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=BPVEucxWtF17KbEcIEcORNaOSyLm2kHROqMUuOkNptIfxNOgK9O04RrKlKJtOBBRsi
         MaGIl7SLSBwjcHkx8d0OwKisADYG6gapxsYu/SD8cQQS2hRNoJn4DQNdNkmB6s/v3gmp
         ezxzxwTd8jrClE10HKjGfngPSM+vcNEHiVMqPeMuUTnpEVSbMehTHVJrRpyL3P5HtZu5
         WOlSYu8BLmtTBKMRMMbmWiEp6mrZTm37DubdFqNqf8f5a9MBoG5WZxfYWbo+72OghaOx
         pvePn05LDXCbVF1std7sjeGR+fzUZo9Ryd4UFx6RVk3K6XkAUEvnOqbfLknur6ZCDors
         818A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="fECf/Vps";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=JcaYp9vb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b61baae916si210631cf.1.2025.09.10.13.23.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:23:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfinx005160;
	Wed, 10 Sep 2025 20:23:28 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49226sw00f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:23:27 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AJfi4O002816;
	Wed, 10 Sep 2025 20:23:27 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010005.outbound.protection.outlook.com [52.101.56.5])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdj1cg6-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:23:26 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=sI/qBe4GXqh2AJHSZizc+B40K6jLseQ8fyoINRlKhI7QqvvqVAdpj+nAY2aab8Pk0f0UEgCDIpJfldaaWjafWq+44+286pi0d51EVz4sS/O35K3hZQmrTAWz79mSUfCuOrY1qhlVZxwwPH/mLhjhvjL5fZAKhpU++i/6LF51wV4XvYdfklITmltiSeinSrZytwK4PowNJRq3he0kys35/pcrT0rtDnuFcqyvDFiqHHNv6bdNI3k5yOl52Db8sIgFvj7Usy+BVV2kJ0VYIFJf0ng0qFl3boTqvxY/0mOr9tTyI8Wq26IzzIHbWZsymW39w82UKh/zHtQYRnGaT5VJkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IdO+5riToqMw0UNPLrgmJbck6oD8g2wCEdmFRuXk5ts=;
 b=h+kC9YUwITWOnGxwEc1f+cbIhGmkUzJvkIZDQEMJYIcQUX5LmqdTPnnAjehz3s5GATSfQc5tWG6xBJqVG+rRjNJ8K1p5YAA/rsYN6AGRBcs9bP31NX3902gAOmMAeEdKv4RK4TwZETnst9t8amlfvrG+6elEwx+59Ud/wi6QMEdxMk8Ge0GWHfdqXf9MrBE1GWiVLEdSwanyB9D9Ok+IvqjvYtavQleqxQiTBnhOaVNvwoNnEBTLaWf2Gl2XVfPkiAkT+AxZLqEzdCtIsACvOs3HGVI8xpQPvsIzOa8/l79OX4yxiqOdfKKz+AxGI4sEU2UPHBvoVBs8+jtAJ2fteg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB6278.namprd10.prod.outlook.com (2603:10b6:8:b8::8) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9094.22; Wed, 10 Sep 2025 20:22:56 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:22:56 +0000
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
Subject: [PATCH v2 10/16] mm/hugetlbfs: update hugetlbfs to use mmap_prepare
Date: Wed, 10 Sep 2025 21:22:05 +0100
Message-ID: <ed2cf936858c0fa14adbbd71e7638be489357df8.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV2PEPF0000756E.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:158:401::3f0) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB6278:EE_
X-MS-Office365-Filtering-Correlation-Id: a2ce813b-16ec-498e-30f3-08ddf0a7d400
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?IOmig95u4+n02wy7liK5g7skucqhUvmnzezd+yOeKPD7zXwk25Jxtwp/SHEj?=
 =?us-ascii?Q?IHTqEJC8ag4dPpdMhojMQcnLmtqMobWj05JJIxck1lLf5qa946U9jTFzhopa?=
 =?us-ascii?Q?bRcQLoOnZXDalQ8jS2OraGXEJJJIlLbR/os/GwiAaLgWbkYjQiOIL+tnTvmO?=
 =?us-ascii?Q?wrqwODv04rlkwnQDemrQUkjtoH9opb6bWbM8JjLcAXkl5RkfICJgqMmSjU7B?=
 =?us-ascii?Q?wKFLEVGzj2Yk7w6SOA+U2EQmnWhHcZ1NZtPtcBxQcDONToT5Exky37Cdn7Jr?=
 =?us-ascii?Q?ZoSYnxOQfrSjzcCGQElATSQnhasaZF5IPuWFOA77bs+TeqbkMrOy1TonMb7x?=
 =?us-ascii?Q?hJr60N2fbmYISj4BtbghfLKmaBfK+CQd5pjJiAEFhgYuoM9UV01AoeN5/E4e?=
 =?us-ascii?Q?YRfFmpgoLQVs2KGOvFJpuBG/5E5ytlnJrN4aeP1PV6cBTU5naxJiXhMBGmdo?=
 =?us-ascii?Q?nyWF1CNR37wrNwU+6lSjKS7Nb5wPuXONs+T527vI7VfZ7ocL3JbJ9gLaK29T?=
 =?us-ascii?Q?t0Cya0IWgwXUbFOpuJuXGSCcAAMZ4oHkC3z571Lwun+Webffl2HzbE5qKAuY?=
 =?us-ascii?Q?jbLa5TL5Yj+wZ2cEsJlC7RzegqhRChn5fKgD0mWvgQCqvYd1V9ScEjqY1CyV?=
 =?us-ascii?Q?cfsV9eTWotCiK0ULgqvoyvtd/YlJC2NA/Un4D/QNiVVA1zR3LTa3bxiLLpiS?=
 =?us-ascii?Q?nolKmDsNNF3rOIR+bHfvxRBx1At8hxD0akFEJyTtR9g01Xp/4CutakUmijEL?=
 =?us-ascii?Q?5wrPxpZopZdHlAP5T8Cwc6ovCl/2yvPzFY5TAaVCLK7ulpkufzMM3sXLmdZx?=
 =?us-ascii?Q?pGW7uVC/wp4n2MK8KWxfxpzB8EFW5OwqizY5nddgCp680/Jdg30XoY023Il7?=
 =?us-ascii?Q?B4n0VubDllBn89SIctnsCFvWrgsDxfZHwi1vLOhJgy4Xx82PhNTswLa7mDrn?=
 =?us-ascii?Q?fcND2Rtz8OiKDBeALCuG+GiienpQKCvB222zTXQvShMxvJBYooE16m/bwSPT?=
 =?us-ascii?Q?J0Rw5tLxqupXkH7d4Chj+JRUP1Gnm0+NIOtTaQNU8hpWFxyaTJDgGAOI58S1?=
 =?us-ascii?Q?eAH3ehlbIBB1YHhCjL1OT/fvHyRABFUpvdnLoHy7WYm01ML6RxPRZZRYDPmv?=
 =?us-ascii?Q?lwr4th7CGxK+r2Y2j5orNOptV03iiJ8n7TW3SF91ftpt4uiS6eczZQHC2yTR?=
 =?us-ascii?Q?LxXh0qnLS9H0djACf9RcT/OtQnzYLnxCquH6nmZPITjIx1tCC75V8ZQILg+c?=
 =?us-ascii?Q?XVagVj4LCgWhJkcoe2fHKL9KjzXETlKGxhIQZe4mcR679eRBXex5UMHOhoOx?=
 =?us-ascii?Q?78qcl7lvdpofaHmvV6zRMRSuAckCv23u1xa9/MzfnhuuDd3EjsG8KBhDb0tX?=
 =?us-ascii?Q?tvqzhLC7SdcNTBFUvUv/fjSX1KKsUlRSYc6QJgdVD3ppiBIhICh6fg06IMS2?=
 =?us-ascii?Q?KWCKm7mj45U=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?xXXrJVxGUANES5RVoKIVKWIKhrto0ZQcafs6lwAC63Ae3W6/xG1SGuYLGg1v?=
 =?us-ascii?Q?Exe4er4B/bl3VBn4VyrIsLtMlZSmiSZ5Pu/O3I4QUtzSm4fIaJugpONsdm+e?=
 =?us-ascii?Q?NjY5wUaQUQ/GF9cDWDB8XRVn8fKHErYQAwRn9A+Oi1ZEkQ7M6GIjvTbyxkrX?=
 =?us-ascii?Q?b4MB4+spO/vv+hmKX4N/KixadhKuBRkW1RTofZ72ftvIqG+toJ3tC6o1WiFG?=
 =?us-ascii?Q?hxASQDARgb8VWZ9cLRbkwUVbe/16wMjJAAhErQOPCm1i3WdXVc5I4TMYT7Vv?=
 =?us-ascii?Q?O1dGD0jutyEtCFVi/qHFTFGbJbSXX5y+5BH5PpBaa0oFvvHzBj4R7dhiqUuI?=
 =?us-ascii?Q?LIA0LYiqxAedRqxwd6k6gbuiMsab0dB04zMNQXKBj4WiKpVSZ/d+doXf5HFd?=
 =?us-ascii?Q?WR1QTZ2w+ZwnQtYgEi6Hj5oh2tb/HgiyY/6rgXbvxb64hE8QOWYjscqIPnNk?=
 =?us-ascii?Q?9Wk9KKLn0lM0zWdZMsQw8jZ73Qwnyxxp0AdeCSVVK5QVC5pwB5xeaX9WB6Wl?=
 =?us-ascii?Q?gAYpxe8rnp/MEyPk6qAc6PwaRHUI9gjjoL35Ebgs/LYQJSMRYHC9nfdjcT4o?=
 =?us-ascii?Q?9NHWk31SlPUPEjq4Qc/lQpho1tjhTv+f7/A/8wsOwdzIU96oOoUqdwHInjiK?=
 =?us-ascii?Q?iLs59Pnv2jJvSzLzwKCyO/hS4bb/XR3d26S2rLU7P3rX1B/l6wuOOHKNQeYz?=
 =?us-ascii?Q?bEm8tjyz21CyItbHK+6dNkvAg1AYKKUEmF68oVxRAccKrYgQOoHisf8sOa/+?=
 =?us-ascii?Q?C0QPavY2xL0HqsFPyteJmkmLbsVXWVSLbglZ1MVE3nta04KKQM24jH9b7Y7i?=
 =?us-ascii?Q?uEqaAd1wAOf3Z0gcEnyaGAYO4cpbWCQtAjB4VGu1sAF4g4z6seop+9Y3/AKs?=
 =?us-ascii?Q?lcArOb4sfwPS/YcELSBAg/tJEOeZGMcg3Fge54f4Rqq/V/6GP48UPYv9/hTh?=
 =?us-ascii?Q?u2Nl8r51VuT8lHD4x3GRQ9x6sEGpQQhi9qKgTa5DvxhKC824YMn61Xku0Jj6?=
 =?us-ascii?Q?K84Hg56G0P1h0Ej3HC2RWzbtK8RoT5RE2I4i6/ktXSoJFbYqBmrWb8i/350n?=
 =?us-ascii?Q?q0GPrgPp+/4vJ4CrK21IiFWj1Yw2Vyfe/Zx2bGHkQdzJSXew5iqgDoQI5+qX?=
 =?us-ascii?Q?ipTFXDZt5VSDJb50xHonlpJjCVBDu5UEgigq+sHm4YYV2rWR6gQeBZh6STe7?=
 =?us-ascii?Q?O/Yi4n9S8W2If1hi2P+bMcUGBDIQj7gXbA94y6uykf5VjmA201ll3oKK3LqX?=
 =?us-ascii?Q?DWxfaOws+TVgK8jyw5+Qv7VgegqnB2sfoBlPJIsT4rWS2UkAD/ea/KtWVVkr?=
 =?us-ascii?Q?vePhDb0AoTJJxdLm0QeqR9GM4+4PzZhUr6bvfBRO0iEhLyheE3i0nCnp4blq?=
 =?us-ascii?Q?KDURNh6K4ivFuzGBYy8vPsHgZ+8gjSG4Wli6k+Qo3vuydNiq72sdTiezcL7R?=
 =?us-ascii?Q?oKl0QH4LrEyQ4DTP4uWtVFk7T667v2as7CxnK7+jr0jsC+VObfyQxZ7+Or5B?=
 =?us-ascii?Q?KaPtFpbhvF5JvtuKfNfqvCdUUhs3cXUv0nsE49IqTmyKV4kj7oIuNxwrErzy?=
 =?us-ascii?Q?X8xf57eCaDQjamXt5gU74z3bvORyYBK56Ypl0AcR1bssCdGd4gvfsagxy6y6?=
 =?us-ascii?Q?bw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: EPdApATLMAxe2Dsvp0o1QKGIZ/na4DHKGGcVw8syG7UR3Jmnz1GTkGHb9iAeAENmlCo0oihDJyJzyaBrEj5ev/Zr35lrmJMOgWWGxao73TfL96tvvkXXmlRx94GloRoZQJ9rqp5sg3VHxsbflawAq33mrAzCxeAgz8l5Bz51fzpi59E6kJl8StLN/YmkBW0WI8fzItkBKtR8A2cbRokXiNVdNQss58jW/abZu3RPb06X/oyOhVa4OXDBi/9ITHlSP5XlAOs8rtpelCTCMZk3r/FaKIPmi67kcsKwZZfCO3cPYs14F0numhIBmPaqcdLpezj1iPKdTgzcy25e0vpgRKJVRX+f1PkXS75BZTmTHeu9zmxOav5iM28oF1/bRNFJ+y+7wJ/RTqM3/PpLqSuY1Nk7C8N2tEOxliCGAfQwIEnM4xucAHSI2KKLMo+Mju6jksPNa+YKDxAlfKGpYS3qnOXR2XOx0GppQhdi7UsFvT9GTpPeVriUCJynVsPmIycVg85kEm6klxwO5U3AXYd/mtJq3NwL+EJn1zPjs8mToFby+Vs+EpsnT0I/yROMPyxzRKpPmhBPRCYL/G/yr0+mcxW7xDhvNCaymQNgQVgtQF0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a2ce813b-16ec-498e-30f3-08ddf0a7d400
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:22:56.4577
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: m4Tq2x6wt8FkM4yekMPT09hwU9aIuPFI7S0oSwdKFrjXZzdZZUx0ppEWvzNPdmAOXepJfOPqmGDVgSTbYdqtbskzy/J2btxbyA3Tbn/vY60=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6278
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509100190
X-Authority-Analysis: v=2.4 cv=QeRmvtbv c=1 sm=1 tr=0 ts=68c1de3f b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=i1sCd5a19pX9XIFVDjUA:9 cc=ntf
 awl=host:12084
X-Proofpoint-ORIG-GUID: xjJQNEBG9pwZzsY30YZBHlpE-mV6C5jX
X-Proofpoint-GUID: xjJQNEBG9pwZzsY30YZBHlpE-mV6C5jX
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1OCBTYWx0ZWRfX8SxfCygmhOQx
 ngpBnDLVwCDOr6OlXZETWD7f9A+CWWCrmYSU2l0BJrO/J7ftSVCatqZ1awr9L5zAitsePM2p+83
 dv5JME/q2n14RGHyu1ZKEwkd9voKpSUC5xiaQOv40tPRxixuTMaek94i2TKLE7NrEoLl54nm7df
 QJaJYqpbFBW//PLk4lpHn3tBhDMwPr2L131xKHbZH59DCmEKwFAJfv4NfWHuDwVQpdd0mA/4koR
 Vxgwj0TvB4Z3asyTrZBItuW7ygLf1bEr7pvJbrE8lR0//YOUFSk4tBG9w2EwKRc7TNVcW7I4hZo
 JIcm0w5SRn2BMr0AvCks6hZJJAt9hA72wgAGFMmcHjjf92ugSljeLi6S9u7sTjlukiwBjbiQEbJ
 Xmiv9zT6M0BUA6pymrz2QOGrOV9z0Q==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="fECf/Vps";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=JcaYp9vb;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Since we can now perform actions after the VMA is established via
mmap_prepare, use desc->action_success_hook to set up the hugetlb lock once
the VMA is setup.

We also make changes throughout hugetlbfs to make this possible.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 fs/hugetlbfs/inode.c           | 30 +++++++------
 include/linux/hugetlb.h        |  9 +++-
 include/linux/hugetlb_inline.h | 15 ++++---
 mm/hugetlb.c                   | 77 ++++++++++++++++++++--------------
 4 files changed, 79 insertions(+), 52 deletions(-)

diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
index 3cfdf4091001..026bcc65bb79 100644
--- a/fs/hugetlbfs/inode.c
+++ b/fs/hugetlbfs/inode.c
@@ -96,8 +96,9 @@ static const struct fs_parameter_spec hugetlb_fs_parameters[] = {
 #define PGOFF_LOFFT_MAX \
 	(((1UL << (PAGE_SHIFT + 1)) - 1) <<  (BITS_PER_LONG - (PAGE_SHIFT + 1)))
 
-static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
+static int hugetlbfs_file_mmap_prepare(struct vm_area_desc *desc)
 {
+	struct file *file = desc->file;
 	struct inode *inode = file_inode(file);
 	loff_t len, vma_len;
 	int ret;
@@ -112,8 +113,8 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
 	 * way when do_mmap unwinds (may be important on powerpc
 	 * and ia64).
 	 */
-	vm_flags_set(vma, VM_HUGETLB | VM_DONTEXPAND);
-	vma->vm_ops = &hugetlb_vm_ops;
+	desc->vm_flags |= VM_HUGETLB | VM_DONTEXPAND;
+	desc->vm_ops = &hugetlb_vm_ops;
 
 	/*
 	 * page based offset in vm_pgoff could be sufficiently large to
@@ -122,16 +123,16 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
 	 * sizeof(unsigned long).  So, only check in those instances.
 	 */
 	if (sizeof(unsigned long) == sizeof(loff_t)) {
-		if (vma->vm_pgoff & PGOFF_LOFFT_MAX)
+		if (desc->pgoff & PGOFF_LOFFT_MAX)
 			return -EINVAL;
 	}
 
 	/* must be huge page aligned */
-	if (vma->vm_pgoff & (~huge_page_mask(h) >> PAGE_SHIFT))
+	if (desc->pgoff & (~huge_page_mask(h) >> PAGE_SHIFT))
 		return -EINVAL;
 
-	vma_len = (loff_t)(vma->vm_end - vma->vm_start);
-	len = vma_len + ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
+	vma_len = (loff_t)vma_desc_size(desc);
+	len = vma_len + ((loff_t)desc->pgoff << PAGE_SHIFT);
 	/* check for overflow */
 	if (len < vma_len)
 		return -EINVAL;
@@ -141,7 +142,7 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
 
 	ret = -ENOMEM;
 
-	vm_flags = vma->vm_flags;
+	vm_flags = desc->vm_flags;
 	/*
 	 * for SHM_HUGETLB, the pages are reserved in the shmget() call so skip
 	 * reserving here. Note: only for SHM hugetlbfs file, the inode
@@ -151,17 +152,20 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
 		vm_flags |= VM_NORESERVE;
 
 	if (hugetlb_reserve_pages(inode,
-				vma->vm_pgoff >> huge_page_order(h),
-				len >> huge_page_shift(h), vma,
-				vm_flags) < 0)
+			desc->pgoff >> huge_page_order(h),
+			len >> huge_page_shift(h), desc,
+			vm_flags) < 0)
 		goto out;
 
 	ret = 0;
-	if (vma->vm_flags & VM_WRITE && inode->i_size < len)
+	if ((desc->vm_flags & VM_WRITE) && inode->i_size < len)
 		i_size_write(inode, len);
 out:
 	inode_unlock(inode);
 
+	/* Allocate the VMA lock after we set it up. */
+	if (!ret)
+		desc->action.success_hook = hugetlb_vma_lock_alloc;
 	return ret;
 }
 
@@ -1219,7 +1223,7 @@ static void init_once(void *foo)
 
 static const struct file_operations hugetlbfs_file_operations = {
 	.read_iter		= hugetlbfs_read_iter,
-	.mmap			= hugetlbfs_file_mmap,
+	.mmap_prepare		= hugetlbfs_file_mmap_prepare,
 	.fsync			= noop_fsync,
 	.get_unmapped_area	= hugetlb_get_unmapped_area,
 	.llseek			= default_llseek,
diff --git a/include/linux/hugetlb.h b/include/linux/hugetlb.h
index 526d27e88b3b..b39f2b70ccab 100644
--- a/include/linux/hugetlb.h
+++ b/include/linux/hugetlb.h
@@ -150,8 +150,7 @@ int hugetlb_mfill_atomic_pte(pte_t *dst_pte,
 			     struct folio **foliop);
 #endif /* CONFIG_USERFAULTFD */
 long hugetlb_reserve_pages(struct inode *inode, long from, long to,
-						struct vm_area_struct *vma,
-						vm_flags_t vm_flags);
+			   struct vm_area_desc *desc, vm_flags_t vm_flags);
 long hugetlb_unreserve_pages(struct inode *inode, long start, long end,
 						long freed);
 bool folio_isolate_hugetlb(struct folio *folio, struct list_head *list);
@@ -280,6 +279,7 @@ bool is_hugetlb_entry_hwpoisoned(pte_t pte);
 void hugetlb_unshare_all_pmds(struct vm_area_struct *vma);
 void fixup_hugetlb_reservations(struct vm_area_struct *vma);
 void hugetlb_split(struct vm_area_struct *vma, unsigned long addr);
+int hugetlb_vma_lock_alloc(struct vm_area_struct *vma);
 
 #else /* !CONFIG_HUGETLB_PAGE */
 
@@ -466,6 +466,11 @@ static inline void fixup_hugetlb_reservations(struct vm_area_struct *vma)
 
 static inline void hugetlb_split(struct vm_area_struct *vma, unsigned long addr) {}
 
+static inline int hugetlb_vma_lock_alloc(struct vm_area_struct *vma)
+{
+	return 0;
+}
+
 #endif /* !CONFIG_HUGETLB_PAGE */
 
 #ifndef pgd_write
diff --git a/include/linux/hugetlb_inline.h b/include/linux/hugetlb_inline.h
index 0660a03d37d9..a27aa0162918 100644
--- a/include/linux/hugetlb_inline.h
+++ b/include/linux/hugetlb_inline.h
@@ -2,22 +2,27 @@
 #ifndef _LINUX_HUGETLB_INLINE_H
 #define _LINUX_HUGETLB_INLINE_H
 
-#ifdef CONFIG_HUGETLB_PAGE
-
 #include <linux/mm.h>
 
-static inline bool is_vm_hugetlb_page(struct vm_area_struct *vma)
+#ifdef CONFIG_HUGETLB_PAGE
+
+static inline bool is_vm_hugetlb_flags(vm_flags_t vm_flags)
 {
-	return !!(vma->vm_flags & VM_HUGETLB);
+	return !!(vm_flags & VM_HUGETLB);
 }
 
 #else
 
-static inline bool is_vm_hugetlb_page(struct vm_area_struct *vma)
+static inline bool is_vm_hugetlb_flags(vm_flags_t vm_flags)
 {
 	return false;
 }
 
 #endif
 
+static inline bool is_vm_hugetlb_page(struct vm_area_struct *vma)
+{
+	return is_vm_hugetlb_flags(vma->vm_flags);
+}
+
 #endif
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index d812ad8f0b9f..cb6eda43cb7f 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -119,7 +119,6 @@ struct mutex *hugetlb_fault_mutex_table __ro_after_init;
 /* Forward declaration */
 static int hugetlb_acct_memory(struct hstate *h, long delta);
 static void hugetlb_vma_lock_free(struct vm_area_struct *vma);
-static void hugetlb_vma_lock_alloc(struct vm_area_struct *vma);
 static void __hugetlb_vma_unlock_write_free(struct vm_area_struct *vma);
 static void hugetlb_unshare_pmds(struct vm_area_struct *vma,
 		unsigned long start, unsigned long end, bool take_locks);
@@ -417,17 +416,21 @@ static void hugetlb_vma_lock_free(struct vm_area_struct *vma)
 	}
 }
 
-static void hugetlb_vma_lock_alloc(struct vm_area_struct *vma)
+/*
+ * vma specific semaphore used for pmd sharing and fault/truncation
+ * synchronization
+ */
+int hugetlb_vma_lock_alloc(struct vm_area_struct *vma)
 {
 	struct hugetlb_vma_lock *vma_lock;
 
 	/* Only establish in (flags) sharable vmas */
 	if (!vma || !(vma->vm_flags & VM_MAYSHARE))
-		return;
+		return 0;
 
 	/* Should never get here with non-NULL vm_private_data */
 	if (vma->vm_private_data)
-		return;
+		return -EINVAL;
 
 	vma_lock = kmalloc(sizeof(*vma_lock), GFP_KERNEL);
 	if (!vma_lock) {
@@ -442,13 +445,15 @@ static void hugetlb_vma_lock_alloc(struct vm_area_struct *vma)
 		 * allocation failure.
 		 */
 		pr_warn_once("HugeTLB: unable to allocate vma specific lock\n");
-		return;
+		return -EINVAL;
 	}
 
 	kref_init(&vma_lock->refs);
 	init_rwsem(&vma_lock->rw_sema);
 	vma_lock->vma = vma;
 	vma->vm_private_data = vma_lock;
+
+	return 0;
 }
 
 /* Helper that removes a struct file_region from the resv_map cache and returns
@@ -1180,20 +1185,28 @@ static struct resv_map *vma_resv_map(struct vm_area_struct *vma)
 	}
 }
 
-static void set_vma_resv_map(struct vm_area_struct *vma, struct resv_map *map)
+static void set_vma_resv_flags(struct vm_area_struct *vma, unsigned long flags)
 {
-	VM_BUG_ON_VMA(!is_vm_hugetlb_page(vma), vma);
-	VM_BUG_ON_VMA(vma->vm_flags & VM_MAYSHARE, vma);
+	VM_WARN_ON_ONCE_VMA(!is_vm_hugetlb_page(vma), vma);
+	VM_WARN_ON_ONCE_VMA(vma->vm_flags & VM_MAYSHARE, vma);
 
-	set_vma_private_data(vma, (unsigned long)map);
+	set_vma_private_data(vma, get_vma_private_data(vma) | flags);
 }
 
-static void set_vma_resv_flags(struct vm_area_struct *vma, unsigned long flags)
+static void set_vma_desc_resv_map(struct vm_area_desc *desc, struct resv_map *map)
 {
-	VM_BUG_ON_VMA(!is_vm_hugetlb_page(vma), vma);
-	VM_BUG_ON_VMA(vma->vm_flags & VM_MAYSHARE, vma);
+	VM_WARN_ON_ONCE(!is_vm_hugetlb_flags(desc->vm_flags));
+	VM_WARN_ON_ONCE(desc->vm_flags & VM_MAYSHARE);
 
-	set_vma_private_data(vma, get_vma_private_data(vma) | flags);
+	desc->private_data = map;
+}
+
+static void set_vma_desc_resv_flags(struct vm_area_desc *desc, unsigned long flags)
+{
+	VM_WARN_ON_ONCE(!is_vm_hugetlb_flags(desc->vm_flags));
+	VM_WARN_ON_ONCE(desc->vm_flags & VM_MAYSHARE);
+
+	desc->private_data = (void *)((unsigned long)desc->private_data | flags);
 }
 
 static int is_vma_resv_set(struct vm_area_struct *vma, unsigned long flag)
@@ -1203,6 +1216,13 @@ static int is_vma_resv_set(struct vm_area_struct *vma, unsigned long flag)
 	return (get_vma_private_data(vma) & flag) != 0;
 }
 
+static bool is_vma_desc_resv_set(struct vm_area_desc *desc, unsigned long flag)
+{
+	VM_WARN_ON_ONCE(!is_vm_hugetlb_flags(desc->vm_flags));
+
+	return ((unsigned long)desc->private_data) & flag;
+}
+
 bool __vma_private_lock(struct vm_area_struct *vma)
 {
 	return !(vma->vm_flags & VM_MAYSHARE) &&
@@ -7225,9 +7245,9 @@ long hugetlb_change_protection(struct vm_area_struct *vma,
  */
 
 long hugetlb_reserve_pages(struct inode *inode,
-					long from, long to,
-					struct vm_area_struct *vma,
-					vm_flags_t vm_flags)
+		long from, long to,
+		struct vm_area_desc *desc,
+		vm_flags_t vm_flags)
 {
 	long chg = -1, add = -1, spool_resv, gbl_resv;
 	struct hstate *h = hstate_inode(inode);
@@ -7242,12 +7262,6 @@ long hugetlb_reserve_pages(struct inode *inode,
 		return -EINVAL;
 	}
 
-	/*
-	 * vma specific semaphore used for pmd sharing and fault/truncation
-	 * synchronization
-	 */
-	hugetlb_vma_lock_alloc(vma);
-
 	/*
 	 * Only apply hugepage reservation if asked. At fault time, an
 	 * attempt will be made for VM_NORESERVE to allocate a page
@@ -7260,9 +7274,9 @@ long hugetlb_reserve_pages(struct inode *inode,
 	 * Shared mappings base their reservation on the number of pages that
 	 * are already allocated on behalf of the file. Private mappings need
 	 * to reserve the full area even if read-only as mprotect() may be
-	 * called to make the mapping read-write. Assume !vma is a shm mapping
+	 * called to make the mapping read-write. Assume !desc is a shm mapping
 	 */
-	if (!vma || vma->vm_flags & VM_MAYSHARE) {
+	if (!desc || desc->vm_flags & VM_MAYSHARE) {
 		/*
 		 * resv_map can not be NULL as hugetlb_reserve_pages is only
 		 * called for inodes for which resv_maps were created (see
@@ -7279,8 +7293,8 @@ long hugetlb_reserve_pages(struct inode *inode,
 
 		chg = to - from;
 
-		set_vma_resv_map(vma, resv_map);
-		set_vma_resv_flags(vma, HPAGE_RESV_OWNER);
+		set_vma_desc_resv_map(desc, resv_map);
+		set_vma_desc_resv_flags(desc, HPAGE_RESV_OWNER);
 	}
 
 	if (chg < 0)
@@ -7290,7 +7304,7 @@ long hugetlb_reserve_pages(struct inode *inode,
 				chg * pages_per_huge_page(h), &h_cg) < 0)
 		goto out_err;
 
-	if (vma && !(vma->vm_flags & VM_MAYSHARE) && h_cg) {
+	if (desc && !(desc->vm_flags & VM_MAYSHARE) && h_cg) {
 		/* For private mappings, the hugetlb_cgroup uncharge info hangs
 		 * of the resv_map.
 		 */
@@ -7324,7 +7338,7 @@ long hugetlb_reserve_pages(struct inode *inode,
 	 * consumed reservations are stored in the map. Hence, nothing
 	 * else has to be done for private mappings here
 	 */
-	if (!vma || vma->vm_flags & VM_MAYSHARE) {
+	if (!desc || desc->vm_flags & VM_MAYSHARE) {
 		add = region_add(resv_map, from, to, regions_needed, h, h_cg);
 
 		if (unlikely(add < 0)) {
@@ -7378,16 +7392,15 @@ long hugetlb_reserve_pages(struct inode *inode,
 	hugetlb_cgroup_uncharge_cgroup_rsvd(hstate_index(h),
 					    chg * pages_per_huge_page(h), h_cg);
 out_err:
-	hugetlb_vma_lock_free(vma);
-	if (!vma || vma->vm_flags & VM_MAYSHARE)
+	if (!desc || desc->vm_flags & VM_MAYSHARE)
 		/* Only call region_abort if the region_chg succeeded but the
 		 * region_add failed or didn't run.
 		 */
 		if (chg >= 0 && add < 0)
 			region_abort(resv_map, from, to, regions_needed);
-	if (vma && is_vma_resv_set(vma, HPAGE_RESV_OWNER)) {
+	if (desc && is_vma_desc_resv_set(desc, HPAGE_RESV_OWNER)) {
 		kref_put(&resv_map->refs, resv_map_release);
-		set_vma_resv_map(vma, NULL);
+		set_vma_desc_resv_map(desc, NULL);
 	}
 	return chg < 0 ? chg : add < 0 ? add : -EINVAL;
 }
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ed2cf936858c0fa14adbbd71e7638be489357df8.1757534913.git.lorenzo.stoakes%40oracle.com.
