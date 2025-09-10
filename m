Return-Path: <kasan-dev+bncBD6LBUWO5UMBBSF4Q7DAMGQELTDYS7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C3EEB521BF
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:23:39 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-772299b3405sf14431147b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:23:39 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535818; cv=pass;
        d=google.com; s=arc-20240605;
        b=GjymqRHisP1fB1A8UMmHQii0biPpgyhnek87Ts8A9DwYb7NObpUUvBbBrppQkU3p/9
         KJap+7MgzSFrsX5um8LUWgrhERrA40gshrHJ+KvQh6lIPyjTMEtfXanpNINZUC/Kp7D1
         zR0BraQjjGarcCsaeD/ZNQALB5hs1O1XdDVbLIA4tSuBCeBtIeNqMF2FJFbDbAbnbciK
         PcKvMxW4P8OAbFG7Awbcu6aaKI8DUhwcyom6msda2dZ878/DujP4N3DZryn9UgttpUHV
         mIjqlI8xaPZqA43lM1LiBnquIcg3/9VrJwh7EO8H4uyU6VQFt+3fSnoKfNoPAKsBXJoI
         VMyw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=TinLMPTvA1r1NemiBFdcBRMS1NlT7+LTRBDZ4zvRXM0=;
        fh=bKJzX4j+2yi0qljo3oQN9luycMT/H4V3FnHrOJlEpCY=;
        b=WDr6KROhvOyr1FuQlxzboFlQvbERsp9XxuuGLeiA6FTmdg7l9sbFMbVd9uE/3TztGV
         xYj5hBA7fy4a07oDIzqObso6P4N5U+uQZ2GDq4uWbyVOqN5Zlq46o7IRk5xzkw0C0sqr
         l3q0DxoGXKFlBD7NfFy88jIVS/MMOcBXsje4b5JpdXI2OSXtFmpXX90umimlkLDwayBf
         O53vye5/JpXWOsPzxbBCdvNcrKn8tm1MqtLtLgChGUL9rBAaW7QFZ21sh6qh9Fq1Zvfy
         N0w29KmHBBCCObWE+rPQ5vVl3Ayid7Ck97gj03+4TqS/N5/NE9wyRsU/aff4mNWOayZp
         7ftw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ObIV4SC4;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=YK1wF6ke;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535818; x=1758140618; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TinLMPTvA1r1NemiBFdcBRMS1NlT7+LTRBDZ4zvRXM0=;
        b=Un+yj8+dGXnIMq5MBWvQpA10fQRh59Z5jmGUxNWXmArgMcxoWdkj90cKUp1yYNQrJK
         aPWvXRrTGStJlEhD9wujQQj/CkdfRzCzhMbsLAi5N6uLsNYathCXVA3l4F3AmX/NLgCT
         62DCQneSwfXv8nNwK1gSvvkIofOwltNhMosj4wcm/MbOZXy4G2G3STQRjlpqemeFMYbD
         /+FysgBjD8FD7oWB5uIrrJaw+aiCQT+kg9lzPgd+awpkgipNqroHtRZv8Xgv/8bASBSG
         3+uATAFoNgeGxro8loodUGe9L7nldFbOqH78QTgnUNjGntZanUFScRDoJf5DId5rjg7J
         hl9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535818; x=1758140618;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TinLMPTvA1r1NemiBFdcBRMS1NlT7+LTRBDZ4zvRXM0=;
        b=JJmGnv8HLCL/AkzhLuF1ZBtObE+V7ROICW0gBy4OGKhDta03xTKumhqGt49pxQzuN2
         D620FU6ckIBL0NWDsIkPsfznYi6G2H+uH+QzMbuDNct5Mn3SFW5NKS7vc6vUT0y0q1Lr
         HJLl5yhe6/VNpwVmtfVM2kSp6YMsW54vNkWSZukwfG6aF+tSHGhF3z7sbRyapgBXaT8j
         oGlBg3RdrL0OeFsNP/iAilgdHeqOO1faFrcaBbWasdo+XZgijq9p+8lMfRhfA4C84iBD
         m+T8HCcMnDMET3Q5eeRtYEMzT48evwMYarlAlLuGwcHv5LHpLGyvMkjkUeCaAaeVZ9+Z
         NZeQ==
X-Forwarded-Encrypted: i=3; AJvYcCURAnC8WrAfb9XRloQebqi528XXWgESmmgfQGooK0B6RKDpFcWY3YUEdg5EBZRJ5Qtu93OxJg==@lfdr.de
X-Gm-Message-State: AOJu0YwXbmuiVITKCsjXVSInI4T7+PfofgKJhNfzdoBxCnRE9JREDiGE
	JH4l7dB4Uzqo+hgjRSYFiwXUK1KdIsZNPVmndMhFVGs60f9ozfxueqlQ
X-Google-Smtp-Source: AGHT+IG6Rm1w736HJ9dmtO4OPm19bob5ePZKPhG/d+8SWGTUxeI/DcIm9spINNHhUsvlyFzYLyivzQ==
X-Received: by 2002:a05:6a00:3d11:b0:772:934:3e75 with SMTP id d2e1a72fcca58-7742dde2ccamr21198174b3a.11.1757535817557;
        Wed, 10 Sep 2025 13:23:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcZqaAHedvJs2CXNw+SV5BiqBm81Uk9InbxkD8fNlQNDQ==
Received: by 2002:a05:6a00:4503:b0:772:51f8:58f4 with SMTP id
 d2e1a72fcca58-7760513cf52ls41644b3a.1.-pod-prod-03-us; Wed, 10 Sep 2025
 13:23:36 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXNRGqVFP4ZRE2sMrN4ctB0adUlFySzi4dLTxNXqjFBSMdRZCJQNjRUR9ykgxQUcMku+iJuv58Rj4Y=@googlegroups.com
X-Received: by 2002:a05:6a20:9186:b0:247:b1d9:77c with SMTP id adf61e73a8af0-2533e5731cfmr24808830637.3.1757535815804;
        Wed, 10 Sep 2025 13:23:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535815; cv=pass;
        d=google.com; s=arc-20240605;
        b=J/7zOFIBYeMn0pvpUjr4NxgDyKGCOTvjs/at7cCbWbw94XmZ3OcCQ7u5Sj/CpWWvbW
         efD5ud6omfDjwMendvgQIbE/sUOLXYsuqfPzdne/MT+prA4pLPQr+xfYDTPZCvtsmbE7
         Mojhd1yXG9HXKjC/qBlTyZsfg6OFswtePeMrWPG8H8q84y0NQ5fzeVBSVBXqBKdm0tcq
         BLQv2cJtBE1FFXPLbL4QcY6ag+EZcREbJjS2vJgKNrKJ7BjkW6r7c4ITfmDV80cn1Tj1
         NCQiXYG4OH/kJvw62WTmxnhSgfRP+v1D2rJ7S3CNCHX6Y3zZylcmXMan5j6/eA+VUy/m
         9Tbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=RSLOn2j28R9kM5FsmlPMWXz46guFdqwiFtj1MWQEEAI=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=Jm4Z41A0F+tYOjDa73jt9joMSf9wQXwCDRPJvod0ea706Dy9r6P24wcUAde5gaqVCZ
         bfXcRyxk08mfe5mCuI3XfUeN/gi2fjgLGmE7Ii1uG+zQSBp77eI91CuGlCy6rroDMqsJ
         S+xl9PAD6mgNraon+f4xH4i6p7ehK9M0mV41HJsOCHkpCbIFuArExOvjVvj59T79z+W7
         sE+5iVUTzzm2ryxoecc8EiHJVtWveIxX1cfzSeSKUVw1c9CiSdhZsGXwnvsNTKl5FetP
         6PMIvuW1zG9vi0SL8eK1IvdyFlyggkOsA10RmSNS/+Y+A5e/KY6DjGxPk6rbxy2DO0NE
         IEqg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ObIV4SC4;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=YK1wF6ke;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4ccfd81d13si1384721a12.2.2025.09.10.13.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:23:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfigc005172;
	Wed, 10 Sep 2025 20:23:26 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49226sw002-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:23:26 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AJfi4L002816;
	Wed, 10 Sep 2025 20:23:25 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010005.outbound.protection.outlook.com [52.101.56.5])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdj1cg6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:23:25 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=lKJ3wjJIVkFVp9hxj4ZimMp0eiXlM+KNAtb7xMQxOMV9uqWgQBWitXMGcEobcPM/x3GE1nyTI5rWHifFNrWrnotU24Zny6qr/x9x1M9WWkbcUUfLHD44uRQP2ptM/sDUu54pZDgVIBoe1rVJ9GAHyINWs5b15gRAsyOktw+E1qpdw5V1tUARDbfzm3mKNR/dUHXYgTXysQzGfj2k3NZNKXvngpvZKw4mpKnYxbdUEzx7pEVNJPomrQ6+BNb2ZUMaAqLlsAmcRyRRZpUUtHpyVFRfT0Wl1fEbKe5SzbRaztTzhEILYKW6odjuK9pn7NxXgQrYnzXcv4BJeyxNGYyP+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=RSLOn2j28R9kM5FsmlPMWXz46guFdqwiFtj1MWQEEAI=;
 b=XWeQOGeIvq2KkZ6rbt7EiDtOamGXyo39ennV95ZS8p7roFByQDXEuW3kxm1l7i0p4sv9fTqEK7KJbJM7cXA97lCAdW5a2w+nPsqrLny7OxXX3nfSMlmbx05XkN3yr71ERjOlnlDaHw/L3IVJIitfZzpB+pH2e1S0DbVt4SRmNMgfN6sVWSjb0NZ6hs3vuS3biOuHcVZrlvPq5gGfXXOs//3jNUl/J+VXZixTyW3BFnXJmzdCbxpDdgfBGQjoluyoyRDgSs+KaWZFG/O26tjIzhsIWqeUZ1eCrHXpZDAqpT0rNf1rJEJBOlXTa+ip4vTyq2axsGr2ro9JdVdT7pcLIw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB6278.namprd10.prod.outlook.com (2603:10b6:8:b8::8) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9094.22; Wed, 10 Sep 2025 20:22:53 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:22:53 +0000
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
Subject: [PATCH v2 09/16] doc: update porting, vfs documentation for mmap_prepare actions
Date: Wed, 10 Sep 2025 21:22:04 +0100
Message-ID: <e50e91a6f6173f81addb838c5049bed2833f7b0d.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GVYP280CA0046.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:f9::16) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB6278:EE_
X-MS-Office365-Filtering-Correlation-Id: 729f4b94-2b2a-4878-72e0-08ddf0a7d24a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?JUrPMECNB6p1lUEk12FxjwDWp/mdx1gtVjU1qKq2AgHKwge/6FkrGxi1ZWoH?=
 =?us-ascii?Q?5y8kzQFp+di3hO6t4hi+1TaD+pGg9T2sr+TEK8CtfE/tq/ipJQU/JkyVppdg?=
 =?us-ascii?Q?U2xnX5IlutTOkJvUoEhy2m1fCMfb36sUKmmgVCn/Mb2exNrV2yRgx1ZiLd4o?=
 =?us-ascii?Q?4kU4KrMPmLj93Xnw+BniHKK8vqAvvsvR1WtCOaq466HaX9/Bo2TtdHJb6IKq?=
 =?us-ascii?Q?WjdH+6fVX+zQTc8TULo2jELyjXPcRCND4RRr7XnAQAph2IRfZKD0Z6j7xsMp?=
 =?us-ascii?Q?b/Syd5i5Z/gXU59YVsI/mKE9Xxx/QKVsozYvYkiOdmOGkZD8icoJXrcDbeUo?=
 =?us-ascii?Q?ZN0uAHpmk4GTjB8vwNTyMZ9ekNtXHbVM55CD72NKZBboMn6Gqxe2PZqGkCtk?=
 =?us-ascii?Q?RTHp6tBGyDqK/RAGptwzm2TPpzoLAjrCht21mMlYjFe66GQ798V5meX5tcV7?=
 =?us-ascii?Q?Y2zWF9RFXnEei76HgGRrUkslnIhlBxzoJW9axCDWn2ufvmCRa0yGPLWbbeZl?=
 =?us-ascii?Q?Cg39CkljUPefb7bPPbkSjOJuAKqdZ94Mn9JSkJY52LkmE0C3z0A6Q2ZEoF0G?=
 =?us-ascii?Q?lV48PiKJO8WDM6UMJ7k7oahIlsKp7quI30oTxxoh4Ie1Qv6h9zyWDPkwvKz6?=
 =?us-ascii?Q?gspBhU4zhFM2OeM6aZN22PHbsTGcNupSyIhaxfNK/feAi3Zc/RCOW8cTontz?=
 =?us-ascii?Q?h3sV7P7UUpNPKVQ3CEPVCmOlj0opClHXQCDM2h0LdEZnL5GUlJgAZbfTB6kv?=
 =?us-ascii?Q?E2pyFO8TVO+DX0fPBhSIUgwnymvJ4bbhAmhUwzM81QL/R55CiMchoJRCnOM2?=
 =?us-ascii?Q?jKk4t2QCUj8YM6xNb4dCHqb9HKQFxskN4GQvZDEnEWBKxyC7A51cLoxVxKNo?=
 =?us-ascii?Q?DwhjZDUr0VvRMdQ1VBzwnesT1tKmd7ZjrGvLlQz2Cg3vvwDflgalnGCjIY7A?=
 =?us-ascii?Q?NGbO0Ex1vHaZ8EB+/NCQ7qGIESOwfdvBfctv4t1oWeNaHCbdO1X8W0GnhepY?=
 =?us-ascii?Q?meq0HxtY8QcgK+bN8CUDL7CDIvvfrQc7gVOZQoGMVtL+G6ReWe3cc7lpk/sT?=
 =?us-ascii?Q?tLmSU8TnKtA3B/2GDqZvK24/MVDKhlRKwgNIpSDv+QnDhms+rvDD0P5CC3SC?=
 =?us-ascii?Q?8LEJsaRnIWKrIz4CNHC29ePUJe4V9Jy9iJdHrrgMHR0f7OcCczm4F744E2yR?=
 =?us-ascii?Q?pitgBgGJl7P2D6fIBUgzkOJqHG8t2JXUcf0s42mi0o5cGHAWUx09rURmdOQ7?=
 =?us-ascii?Q?renEixs09LV4AaovY3Y0sJemQlc8Gw4pTf1dp7eSm2MxGxnV78lOkjuwfNn1?=
 =?us-ascii?Q?JKWLxWThDFMLbOoDdW3xD2N3Oq/V1vhhhWLM+UH1t/HmmMP23N6253Rd5Uj8?=
 =?us-ascii?Q?61IjEZbrHSn+k8mEIrMfcR+53e5X8Ht/4OkRGRK31DbcICTxO/GJM/RFzPqL?=
 =?us-ascii?Q?4BzH1i/sBds=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?euU+P+auMFHXUlcOFmQiansK+q6gF6XpgEpxVlU+NScTJ4niF9ygK11oANTR?=
 =?us-ascii?Q?mAocld++W8Porc22OPvhl0mD8meU2y8QWiNYrTnn4eSx0DTHETDkf1uvMwy9?=
 =?us-ascii?Q?IjY6lnuEns14Oj1IsprEE1fYXTTDasxfWG8/M4mfP8UOSepI+9EkO6lY1j/P?=
 =?us-ascii?Q?goDnnQAcuf6ooAuXE9W1u8R0vbko1Vrugaw2gGZBYDOvHGhpJ5Wke2cGjQwX?=
 =?us-ascii?Q?K2guExt29XCZnJqEE/z5rzsJW0Ap3GISHTUSMA5yZlX3+A5UxZQ2B/pYtHE2?=
 =?us-ascii?Q?R/nOdcbp6C45sybCLGBeeQlx6iguVNvCUoOQOk/HtVu9i6IpE2B1PqeoZ8vA?=
 =?us-ascii?Q?u/Xqf2jffO2ece2dN4Q82IClQ5zSPSfh+LBSEljZarQXk+6buPgrd8DhIiWE?=
 =?us-ascii?Q?loHDA0wLEhaj3JEqZbBjIrprkmC0lwAW8/73S0PekPdVSH05m2BDKfKwefjw?=
 =?us-ascii?Q?P0Sc9gieZ75xr3G9PGsktfzEn6xvlyhuEFueb91RnlQfFhchbCtSS+RFInYY?=
 =?us-ascii?Q?Dt/1/RZQUWFt2/x2sHlxSKoLh6S0hSvLGT31S6B9e1I4dAzjPSEaT4MWmGex?=
 =?us-ascii?Q?MSudFlfHfmmxgZtZ85unhKxJ2L7zW8RYaXsZlAITIVBcd8RkS3rHLhM6usDV?=
 =?us-ascii?Q?kSQHUzNlFKJPjrZ6BTU0HOuMXrse1e95afuPqlFTm0Hhw74T1Xkhl/xhyL9h?=
 =?us-ascii?Q?mE/z+vcbAIJQxzmhKzmiYPg0Bp7pti7vA5VaRPQpB1Hdzt4jHh4vhLSiMeAL?=
 =?us-ascii?Q?ZaMlPj/F18DolaYhLdWOtzLZmVoO80uEXORXOvzzti+OE5UWHMn3U96PPax7?=
 =?us-ascii?Q?BKS9wNtAlDkGMZ8mee+mBqKIO8kM+oB96NchS2PT5iAwbUsK1Ztmhyo4KSs/?=
 =?us-ascii?Q?PFAyklBkcSL4s/Uo0PrdJSnBPrq8voP0MvXmvYwP4HfNY0YyDvZzLJdKuisd?=
 =?us-ascii?Q?RvKdTeSczSL1I4XfuQ0bnvNZLEBuCXXggrDoL6YlINEGoeQXVuBc2VzWMx7D?=
 =?us-ascii?Q?UPUT7dxh98j0+9t4vrYdwsFMwiIAgyhP2X298HGnqG7NqbA6pxeXzZpus7/9?=
 =?us-ascii?Q?U6WLAWMA1cRWUnhEfSrfWUBl17mTtGHjxYXn9dxaZ1OQJg0aH3m7QgECfpIS?=
 =?us-ascii?Q?jFQcOY18yxJRX+eKCZOLD2voaZg8YBZUo6UyyFvEZ3AE1eImNvHZoLOuUbXP?=
 =?us-ascii?Q?SmZ6UEJrhidS7k+V1pfENARDSSw+UVHlXPdst05OfKSk75F+B+Bj33A4IBER?=
 =?us-ascii?Q?7NHyMSiTfNzln4ZCZLAyPDhUbrpM9NzJctFcxNowU9ItaGirnqhNzZUSevm8?=
 =?us-ascii?Q?BaTG/X/85dQThcs5PnH/fBPMLcwlPiiOmzC/QS34WtSKtZY2YwVWVlpdBET1?=
 =?us-ascii?Q?BVfjDo4pE4CZBFo1Pq6olp7+h4eMcVMJ6GiBuNYqFPKjJ1CbpY1I0eKw/3Xl?=
 =?us-ascii?Q?h4pXmXwSPC5qmNhI052fDXlahB2ewMWDlsnl7xxChf3+vGOgYGDs40DxQF2t?=
 =?us-ascii?Q?vYxFsIi9HMiqPiEer8LRFBBjeXN7cmilLH6IvWJoHMR10gYrFX7hiO2okbzo?=
 =?us-ascii?Q?50OccLj6/cur0JYoBXDnixaS0PRey8w2UDx+BSAc/lAvAYymZnY6zo+LL9Ud?=
 =?us-ascii?Q?bw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 2bE5kSjPaD/YhbmEeFdnk8oneH8cm+aOnFfY4BwTamL4PMw5ijVuNe3eMUBCS0UMG0aZvIFzxB7GmMKQP2Zbs9qi7h7QTMwoBNVDtaJcYPJBOEFXkeMdbFWDuWn2cXf13iW4BRk2GbIucwQ+D2HaewY0h6T7UUBKXS2pBVl1/mKhcm+ebuVEp7IuMdHC2InE3OKHYq9IqXeRb/fLeMSvI5cqcHLYqmuae92WzaFC8ucm0AgEFJ3NftJ+mqTCztQQdryuMbNU3x6Ru1cNC/11SxPRpt0IbR0K2y7Hv0lcTeL2q1wz9Jb8E41sM0kz7j6oWhkIo8SOFYAqSbbqmoubroFSI8Ejj2ojDwWTQD02uvFwr4i+q74Il/vBL5XG3A6CPcrgqMkKj05O4pmjjqEpUhoWWtbqyQTmIo86su/tmex+aTh41RKhucb3G+F9bY7LJlKE1npC1SdwRsCuEWiMFmYsZXD171+rkRHvhxahSbXiC8+dqu6lrtxUC8WbqptZloEZVQc91KwkasMaiebk9eEsrfo5xz5NHw3cCmWk8qcO1SfRuKr1hF4LQZ/esbYoL6RaCuh/WyZqpIo9emvINTaYv9YRGbwUWnsJb0KeD/U=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 729f4b94-2b2a-4878-72e0-08ddf0a7d24a
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:22:53.6568
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: O/mOo0Z5HSPrGzRcleQn6gyJHCD6TjKL6YSXfDLwykoYSvdjXcIHZjYPeIVJM2BpQwYIjEZElGup4dZMDIkuZ0DlCqh+tKpnK6faAekCB8U=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6278
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509100190
X-Authority-Analysis: v=2.4 cv=QeRmvtbv c=1 sm=1 tr=0 ts=68c1de3e b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=CxsoVSIMbwK9moDqu60A:9 cc=ntf
 awl=host:12084
X-Proofpoint-ORIG-GUID: 2jZcJypCMw4ZaAzbXOlG6eVmfZv5itma
X-Proofpoint-GUID: 2jZcJypCMw4ZaAzbXOlG6eVmfZv5itma
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1OCBTYWx0ZWRfX7fVhP82iXqPJ
 0IoctgL4CGLy7Izt/b1q925tORBuZe0G4m0JAamtpW8tfDr8vyGej7F/+VgIqZL5Xa1mR9U6mII
 GtTMV8fWmsDWXCBAdf5KKCnRWQcwSPWSALoAcy1w6CxtQczcb68bIzrP5mFOuOoJ6Mc8bzIfdWo
 Y0dQGezOyZ0Vc/82aB7pxaSlPp+wHS5ZQ0cYDxl+mJzYjG2grGhsK0V7IBD+iYt8M0Tk+iUIRtG
 XU+kxBodLWYLFEolplYjUs7DO3sUSAZBXh3Z4ht/KHiY1z0+DbqTV7RpjcfedPHoeFEeQmk09Em
 BlGq4tocJxoq/3Cb/43NyiWy1pdU+LhasC/m/J08Uxglajtd5cCH2/mv3Gz79yUxpHtRZvrD3tX
 RBAkjB2+NLV/0l3W3Pim/wzPDNn72Q==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=ObIV4SC4;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=YK1wF6ke;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
in mmap_prepare, update both the VFS documentation and the porting guide to
describe this.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e50e91a6f6173f81addb838c5049bed2833f7b0d.1757534913.git.lorenzo.stoakes%40oracle.com.
