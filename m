Return-Path: <kasan-dev+bncBD6LBUWO5UMBBWXT7LCQMGQEN5AYHEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 594ADB48B2A
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 13:11:24 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b5f818eea9sf48415501cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 04:11:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757329883; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ejp5RvNpRkyOT/hyR0dn+x65Emw4Ak5BBPnOAqBBieH/mhuFwC0/x5+mOvOzRSyIXo
         vutzvId0QgihYj1Ee8nGC3otm5gmTRBd27dgsWcArA+lLlkTs+wmLgr7dTQPaKMc39UN
         EDkIXQXeZiPUR8fyLfPwk6XmTFExr8OfbPjxKUPvFxrAJsEhZIfMH+v+ZInJISVxRWSK
         pjuc6frXX2jAjYjpi04vOOjuYFJCNYFsytFne80G2/RZO5ZfTdl/L0YspOqlFuCBqFwI
         K7wLZg+BqEkwGXdpjJDeeKTOb+maY/ElumENEDlenOOmXK5Wq6t0en3GAp86WbNXOxse
         cECA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=k7VdV1yTCVGI6T4HwzQJFU+gyky045jvyNlGO24oIMU=;
        fh=11uC8Of+lPugEkM+k8xSUlbm1X5dmlD1efE6LB7vEEo=;
        b=b+pDo/tuRbH225SVLVd0CG3giEOljccIwxgRFTGRoA7HL3PK/6adYeEXwMq/AYAGhl
         itWxnVEDHhtWXL0ExVICy0z/jrrSXIggtcS4035nKf6qi/neI+8wcrmel0ymZH+yGbfc
         /Ehi0waGUnQLnnV99sCYMxFr/UoyhDu411KtmJTI8+TEOcdk4n6j8ko++xjb9+z68ayW
         GP8eEI96skn6EFEVxE4fgzt3SBqnkEF/PQf5MZceRK/52gtbse5J1FpIfLmSa4+SRxgH
         Tc5clM2qPOk56DqDQMufDULXGXwU5Mwl5LjZyDnFqmRKJ8F+8spZwmkywXMVTlqopUl7
         YIPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=kU2yOKOJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AnwfP8MJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757329883; x=1757934683; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=k7VdV1yTCVGI6T4HwzQJFU+gyky045jvyNlGO24oIMU=;
        b=Ju+uJPUUoNxMjvBW9RvTzrl+E69dt16w70AaCT1E7ST6GjEOqpctry5R/RPUVB1Zx0
         nv8FkCiJiJFE5SxbSJVKwzX5vbsQjxKDaLMWCXu+PzOeVlqSMGp0LNWXsq9ADrEvntZe
         Sks/hDSjW52tVw2/74EaJlDeNYG99O9/uVHidPXOhkonQUQi9kXrV0rNJSGm4BAxzUeJ
         5toON4IBF3U6Db/dcDxsUGsnQz+7b+6qGtMzqAcxH68lqOxCGX8drKL/EEGvXboMOEFs
         NN5TAuam84MfBXzWFXTYkYw9QfRNP4h98NhhZUMQnglqOzc3MvgQibQYysFJKNvOMrYa
         VWYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757329883; x=1757934683;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k7VdV1yTCVGI6T4HwzQJFU+gyky045jvyNlGO24oIMU=;
        b=s0QT++rVkuzEyVdbAakpSWtbuPOL78NkqT3BdDraOWdciCUsm518P/qSAZPlmUPljb
         qaTrL5hTYO1ckWbxbdQnNDdJMIAVRAEggwhcKrL4NvkyYTjnnBfB+svfqbc1B6/Ndjj6
         u3S3cxCiMh2eZRFFg3TTZTfMXHjXJW+FdoYRoy3oOJGPGr2/QO3kmvwFf83t8MlO0TOU
         6CpGkm7AnXliZVBJZMiqW1L8U0ztFr7kMphx51dOV2Ze2ysOGov8W+OzrgFi8hpnBIjR
         rve5GtwX2dPAoOx7zhnA16PB/z8k05lgXXi2D/fFQ44WkLmZvG2eQVYAbAvpuedAXgRt
         c5wg==
X-Forwarded-Encrypted: i=3; AJvYcCUrhmPSEEOsrdVFXGNwzy6JIzX7xgQl3yA69EQ6bHbtD4P1ztud3uA5NYzcby0ZQJvXZoxa0g==@lfdr.de
X-Gm-Message-State: AOJu0YwA/8F/eoHge55WbqZwZRpRyfsLv5TVlo4ZXVC2vqdtdQ9JhYWQ
	Cs4MOnJBC81+/0T5jT/e4tMsckM7miaCa+6PJkZBLeuJBkbd7l4E7021
X-Google-Smtp-Source: AGHT+IEJkf+SRIAc8DfQRIAvRQ5Y9JxL43DEVO8zYCqnnTuSySkO6ThdajJef58NuqqR03oXv0jtoA==
X-Received: by 2002:a05:622a:4118:b0:4b3:10f0:15b8 with SMTP id d75a77b69052e-4b5f848a7bfmr98883631cf.77.1757329882948;
        Mon, 08 Sep 2025 04:11:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeIPgjAoXs0Z2elKp1mm3fZsqngxPeTT8u9iZGwPGp8sQ==
Received: by 2002:ac8:5808:0:b0:4b0:774e:d50c with SMTP id d75a77b69052e-4b5eaa1bcecls60810631cf.2.-pod-prod-09-us;
 Mon, 08 Sep 2025 04:11:22 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW3oXA/cSXZEIKu84O8mynPEfjEyQO0EGe1/jG9vazjKGBA/Fwco1JDWTX71Dswakj7qQUaip4mLQ0=@googlegroups.com
X-Received: by 2002:a05:620a:2584:b0:809:3aea:1401 with SMTP id af79cd13be357-813c30f9588mr836111085a.75.1757329881953;
        Mon, 08 Sep 2025 04:11:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757329881; cv=pass;
        d=google.com; s=arc-20240605;
        b=BzT6nEnCHCBV/Gk9L5Vep6o6sRBO8r4vxwgGW2EPCSHAUFtRYzlhfH6E3PVM5b8MpD
         9dSPJLvgYt6ksdEoXYp1rOoE9hK7NZ7Y5Sew5Lu6Au5Mjc4PAznr3wKURyH/kHkYUxYC
         8Kf3KOncdx8MMRwH0qikBiFAxz/jkwBpmy7V7MDenq7I3NXffGq2xkzIlvNKEbz57Fip
         FfdQQ/MEuiulgqb687vhC7FoL5KoU1qmGY63bsp0vgqQ1vdEviC3gwc95GwafRiCrZP7
         KTPbl4n44tIitcOuGm6CJLIaUXEFt9/nqBRhucigXW5M9kRhE5ih+V+BGJEixoN3ov8H
         5qcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=awbeTVBELcexcVcF6uO1PpXHm35opz8jWAHuvNO18vs=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=VGBObh325KvkojZOmkfZpbBPpBuRmtft6YhWkdYRlesoWEQZHdmJhYax3bxbR6HWw8
         50RaglMhAY6QySkUU9D/8+59LwqAn0wDzyPy3JYYG98puyp8ItO2cXOphRCReBB129bO
         ZHL97pI/eTChhJ+4HrDOPnrmWEv1/7BikDGM6br7dhmMNJlJn1GJX3RhTOLabn/B0p3P
         mNDNd4mCxrzMV+/swbK6nqALXGaFOb9zuWAvq+dKkZe6kQ+p0gtWKSGAdwJuJilNxGzJ
         zJBMG99ubyxu5MZ2Krz7CC8NjEIZGhzOERLb64PZsKX3LqRXaCraizP2PV3V2aW8lHbT
         EwAw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=kU2yOKOJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=AnwfP8MJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aa0b14b1csi51081085a.0.2025.09.08.04.11.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 04:11:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588AAtR7006140;
	Mon, 8 Sep 2025 11:11:10 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491w5402we-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:09 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5889wZ07012806;
	Mon, 8 Sep 2025 11:11:08 GMT
Received: from nam10-bn7-obe.outbound.protection.outlook.com (mail-bn7nam10on2066.outbound.protection.outlook.com [40.107.92.66])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bd895ur-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:08 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Z6XVtZ/d7lI+HIyN1gUcj4MLF0wh1jFqQKJJjflIpEHKwSaZlXmiJr5sfdg0mEi3ViEsCvOHXBHHlQV8oefGV7HeHEqNy8Jv8iewSroi/8DmsgcAJHzwBL0hWsvqCpQpH27uw8ZDNMeNJU2T8f8zn6pUR8mVKa+7Fv7zpjLRSuyMThfba+wn1rclo8OdUEeuvN9s/UM/KfzB4zuk/PII4OK1JJxmmwi2JVa9Rmb79TatzbeuVPqpa9r+s84SoA/Np91bRVz9Z20CqSZQEWUT7ozlIDj9KQs6E1yZECfPKoPdujSoTFtkSZz1z5fuBZFswhExCZZ/1nL2Qc69Tkqdng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=awbeTVBELcexcVcF6uO1PpXHm35opz8jWAHuvNO18vs=;
 b=YlPADDnToVWz1N3JYDZT6q0KtLU1FHbkxk7sAGGCPSLdbVAggiE+K+rnRgnVZ923KP0KyP1jlpnxnmUZO8LNJugpm4cXqwGNL5QQpZj3tIzW3nS+hJ3bVsNyUfxrkmlAx1++PRKy7NwTXFnMU+6EOm6gI1J6tJVHjmS4/vzn7+mmvoBKovbyhCf3Ut9jmBcUoFGvd/W8u+nvo3kCgadeeo55TTtAqOTdYaJP9eMQvNUZBcmgCD3JZ9rslBbXxdIgIl8xKS3jfCcmZKr288wG6bLkwTa+ZkApreK17oz//+aS7PXM5YuQ55Vklr5RzN9yLkWAzxQYBaSFgagnR42vmw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS7PR10MB7155.namprd10.prod.outlook.com (2603:10b6:8:e0::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 11:11:05 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 11:11:05 +0000
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
Subject: [PATCH 02/16] device/dax: update devdax to use mmap_prepare
Date: Mon,  8 Sep 2025 12:10:33 +0100
Message-ID: <85681b9c085ee723f6ad228543c300b029d49cbc.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GVZP280CA0009.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:273::7) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS7PR10MB7155:EE_
X-MS-Office365-Filtering-Correlation-Id: afc6a53d-aa10-4426-a225-08ddeec86750
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?VxL0hQqurvRuWcS2twQ7RUQESiR/LviSJ++zc2Fsi0ObiuDI7NvX4lXml+tX?=
 =?us-ascii?Q?pI5YXpd2uSioqJCSgemfMWDnMD0m/e9R8YQxBiJfqrNErRSlWGv7kTpu9n1Q?=
 =?us-ascii?Q?/GlUWPtY85YV0BLwPPYbi4py0z3gAi6vbiQ/JGUsmh9RrzdrebhZnSDlz99N?=
 =?us-ascii?Q?tNLntJ3gTNbwkBCT1xPYLTQETFQ7K6pZtvFYoHE+SEEfeYNxYCVGcQJ2E9bf?=
 =?us-ascii?Q?RIQ5IbgTnTxnwds/ZX+Db2MHQnLC1TVOZHiEv5qWgXufIfPjo4+Bvnkbaj07?=
 =?us-ascii?Q?UtA/9XDIy0JX7mXZ5XxKGcVRUWcQHAq6uTkL4znOxflQMgWobzaD1/x1bgS7?=
 =?us-ascii?Q?ZYgiJ8K9IfGZycJRJ8M67Y9q3Evl3t347TNWu8ANWM7xHdHHedB0+5lJPHee?=
 =?us-ascii?Q?LsX37XNnaYLtLDHpByVfuO+WOe/z8NJhuyHGDw6kuayomlzG/od42Z9j/V7/?=
 =?us-ascii?Q?R6L+hsMaZzYfqg7O2JqeJ0QN9ywOLVOLe2yOBVEB1QRMlv8MlPs5ZFlXSlet?=
 =?us-ascii?Q?boR7xnRWZZpUrLq2Fo32rsm8Bxu608m9xY/c2T5KiYE04gLWOIHfZV8TxdP0?=
 =?us-ascii?Q?e8pwpsj+fx6IWmdFNzhsBlFdzJw5RqXTwQnPM+bt4BQsWi4GkugTYHKt7cHm?=
 =?us-ascii?Q?sI2HZcVrhia934j5jnvZJ3JNAWc7xpf+JPxD9JbKKuZf8cdS0YsZJCT6wH5x?=
 =?us-ascii?Q?6OQUao3G70Ft2wwEZgbnV5XXxLcZ2NKvtrZ5bTMkgUSLbc83Yl5JudaxAMYV?=
 =?us-ascii?Q?UIZHtUOiha06R7qh/ON7iQaFbhfE0bBxpow0yUdW+c9N7oyT5/2F+xJuuCPh?=
 =?us-ascii?Q?+TXilrR+2Y2CshG10tZr+1LHWSm0NIwD0CITonuH+9uZZRtreDulyqoxuoH7?=
 =?us-ascii?Q?26xqq1tdu1E2bxN3lF72x0oq42NZPa3Mlyw1LmFYTblfXC+5os9ycfKVbidB?=
 =?us-ascii?Q?5KLT7cBwzjczrLZFn9ttxMhaoEFGFB3LRcUN0i/gRlmLN0VO9NnpdPJ1YhxJ?=
 =?us-ascii?Q?SRHocoxVVmAC56jO0ZFSFzpL57LGkbJ9c890+RKIs7/RQSh7dC68ql1jWMoH?=
 =?us-ascii?Q?4Yc66uLonW4qNpzfZH0ZwYIMQWRbww0GQWmGN0IfUhOSbmr6i7Uq7DRtofgN?=
 =?us-ascii?Q?9FB0MhLJDoygZ2lqqFBUMHAQc9xWz0UPFkIoTzV844Z7D40cfgJU3BYnmNnm?=
 =?us-ascii?Q?/eD10NOVJ1e7iWVBsMjABADvzwJsemyuB29N4EDSvhKbiUObuHtVr1qP9jlT?=
 =?us-ascii?Q?vtqTkqAoFt3f/m/98b/Biq0jZh3YOAK4ddVSZOR8VeKhAVoEDJ1VnGeU6DBe?=
 =?us-ascii?Q?hL/W9C79SCGhf2Hs/YKluMDwnnwV6Jtz09+koS9DlLagNc3RN9DtEyCIhpF/?=
 =?us-ascii?Q?vQ/23gXOr/Q1XtGWZyg6ysw6N9OWQIsvw8PhPy5qnuzFPdefvssZxGYnjkDc?=
 =?us-ascii?Q?ZWkFdttN9fw=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?DDzW0cYlpXg2M3JVdX5mcaWfqUFqOnUAN/nJNGiOEQp06IfwuiCeXs5v0tbO?=
 =?us-ascii?Q?gpf2f+cliKWd2kNstmMNiQPLvRgO5pxkuQUa22t0yvK43WJyHLOdXJxf80P3?=
 =?us-ascii?Q?oGipZA442teFUnukouuPbdM1pakLnpWQef9v4gqIh3O+yRBhePRlMTzTZ3RH?=
 =?us-ascii?Q?0pZNHW9enBiRHooxbeHiJojGqjf84XfohHjImh/UnoNC14H5G78aoha0VUOM?=
 =?us-ascii?Q?zdJsdGxmiZ2vIxVSh1/zipOceL3sJiwj+gpLKzyG4n1ZnVtfkm762NAThy3d?=
 =?us-ascii?Q?kZzC0FZjfC6T2hKWMhyqvjSfeJaD6pANf42FOguj6NIY99mC4sb8jyExJhYP?=
 =?us-ascii?Q?SuhmOUvHAKA5NNQvSbSO9eQp3Enc2U+Izsw1fzcaOjSGuwyd9zwc132PBFmH?=
 =?us-ascii?Q?kETzMnTbcdUfXQQuGuovjxGJ1wVuDamEjtUeW9HdijyZh+2r2v9L2qIXA4Hw?=
 =?us-ascii?Q?2FgPt0YgnA3zbMbXpkkTv/VCqPDA2sPdDqM2gGFCTx8R7vvZxA3HEgp11xZk?=
 =?us-ascii?Q?fCRrtCaWyq8/AahtRSk7DUNcJcaWH3OCY7ev6TZXH6BwfnBBT8+UZ8ZDrUCq?=
 =?us-ascii?Q?2YzbY+stHPz8J7sfY2gCNCyAqVRQDN53LMUngIli7W7urzkPO3yelzYqEXU0?=
 =?us-ascii?Q?9rPLLyk4y1Pv/2APVhf3dEcQ0s1fMkSQDBrFGe69Th49LDitf7yR6DxR4958?=
 =?us-ascii?Q?6byARW3iwdCwxsp3MHRGDTCCGyTBYII0QXwF5p/DU1tBvsWuaNUq93gmMX9H?=
 =?us-ascii?Q?ilhYxOg6AUZ/clNsxpfjvmf8zoAX9gCKIIfhV6FnHwRvJUvToCN9M6Dv4UnC?=
 =?us-ascii?Q?7LxztoOhmfN7GPU+s8QeJ+OeFfADzNy3er0YU0kra8HyhRQTmmGiCpvIegpi?=
 =?us-ascii?Q?S1F95Vq1voelBytHsOGMRsWawZuFoOLIRrsesHH61mRocx99wppzdI6vvhua?=
 =?us-ascii?Q?WUYSvxqOPAj7kwWbvqdhXZLyguYAXCTu2dwXtKjiw5AQGlvWxnb0NKFaU+EM?=
 =?us-ascii?Q?JFHNsarvmeWPnOjC+LrCsr/IKF4NF/qPvKDiBc2YlmQWLTwjEh5mcUehihX8?=
 =?us-ascii?Q?bdnfA9g/k+uBzjn5fAwYw/yE+dP6Y2TlQNwyrDEclMjqxdQ+mwxUPQ+LFjaG?=
 =?us-ascii?Q?ZHFKAXBRqPHmJXrE+xHD6lI33hb22Nv+gm6RiGOgN6XSmNQoAacGw/l2oxVY?=
 =?us-ascii?Q?OOvhyWH60eRKgOth/XDAEXvWaIs2W8RQH6NX5Fzehc+HMcAV+nrQHBUokEnQ?=
 =?us-ascii?Q?AS8B9wgqLOaWdY/z92EBNUTOfFwI5YYsuD2U0U8doVqveS7PmjyzvKaz38Sb?=
 =?us-ascii?Q?EgajjFJFeAp6pMham7CFohUs+g8vsx8IseZJzpvGV7wUlEqIiqLE6qdohBMZ?=
 =?us-ascii?Q?d6QdXsrcaIZvLVcfdKsWufFyAX7JQjwPzdYrzvzDJdjwrtjZp4WZTjW2H1FE?=
 =?us-ascii?Q?L2AxYixKNDjwt0ZQTtiutVhL0dz4TUI63zKbBeeIO//pSLEpP2f05Cu7ZgrE?=
 =?us-ascii?Q?mbSZ0qpdOHZSvGB7Ofwx9AXNnqWdR4F5+2JY781BXPnDQTT1IweRrNLPtHbh?=
 =?us-ascii?Q?VXJAzd0tmhp/NsCtFfzpnzl46MR1V2SBzp4KhG/cTI17slyYOV82oJMiRx7d?=
 =?us-ascii?Q?hA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: PxBQRqBeEwcNQuSXHVCvkPw00ofA6nq9b7MMN8ldE/Jip6jHZOaeEUA0Azn7uC+7F/tztvPaSUzu7GM8J49rgmP3T7stGyI8AJ4+gu7q6EJeXMbt3/5VyEPQsTkONWoDX13D3UVeYJvQYtSjdmFTCzVpVmpULKBKWNQJTyvPgJlRegqH4dLQCeaVkMfqxNyvJPntgxjilR7plg6PEMJbWWZ2N9hxf58/C8gXJj4WI/YAuBPwfeCrhBFJU/vlBONIVjcgL7qFaHGnQtKiirIgyzWP9r+9B6zT2k+hAn4bcfWrTQA41yVhTRY2IupvvH6QHVL4d8NuRUdomHclD8rMptkAdjHog9I3YhMgp1ODBZ1n/0/1XJRVQPMAn8Cbfg4HHPYqwcdObp4c+t6X3ctKDJQZzO+gIH+qBjJfPTvLOEHqjECc3a/z7cPWhsr2zKzviEatciOWi3MREP/gD3Ugc0cj091gNQ7TyxAWdrs5VIo7Tojl83er5R7OYbawriFqA/wlmVXuHPuSABKqAj9xAz5l4V3S4HkqoVRqvLfECuhRJOpg1Gp1rdNuKkk3G3hnGbK4iXRHRta1RRZh445q0komoA5+HVewdpj3h8qRLf4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: afc6a53d-aa10-4426-a225-08ddeec86750
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 11:11:05.2504
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: wW6wx7x1JBYBYm1WaxcsWr0ODQiHwSWDjgBXRYTdT7NzxwytoisqkhcpZsECD+qHe45UKEX03cyDfcC2PJE2ccA2ioGR84jAV0D6eWV/KY8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB7155
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 spamscore=0 mlxscore=0
 mlxlogscore=999 adultscore=0 phishscore=0 bulkscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080113
X-Authority-Analysis: v=2.4 cv=M5RNKzws c=1 sm=1 tr=0 ts=68beb9cd b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=2q_dOInNKJsfLPmpoRAA:9
X-Proofpoint-GUID: nWMTSo2gYJisiimMjz3mVaXPLgAwpEJi
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDEwMyBTYWx0ZWRfX47RYoZs8SGPC
 tD2gT3HsjJUG3Igiev6xVBz1w27w99r/f2h7ihYDyEs1vLzwc/rjeww7mMHIzclU7qOiV2PNez7
 SQRDe/zhAZLdjq+pn+uVJFLXkCTfbQVUGuRJQb+gTZ87Z4RYnSzdkL2ZegqvLU8FE5z+ghtC1Wy
 czE7zcDzYfqt/eFKot2OLPFHVs+X/+C6e0xY+Py/CqVHRs93nTrcrlmX371uKvAhuerevk2XfKn
 Q+R4una0osXA1cNYUjG+F6NCofFn/8dm2R7beUUXBbFMHLuqSCQtWQchW4uLxOFO/EberVbQi6e
 ouPtN2lUbwxl0Qusp22zry1AyjGFcr4QlXdzOy3AO7GdweBQvEE1K6L9Vj7BV2FlhtSZhWgvnm6
 8Ak2r4hw
X-Proofpoint-ORIG-GUID: nWMTSo2gYJisiimMjz3mVaXPLgAwpEJi
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=kU2yOKOJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=AnwfP8MJ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

The devdax driver does nothing special in its f_op->mmap hook, so
straightforwardly update it to use the mmap_prepare hook instead.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 drivers/dax/device.c | 32 +++++++++++++++++++++-----------
 1 file changed, 21 insertions(+), 11 deletions(-)

diff --git a/drivers/dax/device.c b/drivers/dax/device.c
index 2bb40a6060af..c2181439f925 100644
--- a/drivers/dax/device.c
+++ b/drivers/dax/device.c
@@ -13,8 +13,9 @@
 #include "dax-private.h"
 #include "bus.h"
 
-static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
-		const char *func)
+static int __check_vma(struct dev_dax *dev_dax, vm_flags_t vm_flags,
+		       unsigned long start, unsigned long end, struct file *file,
+		       const char *func)
 {
 	struct device *dev = &dev_dax->dev;
 	unsigned long mask;
@@ -23,7 +24,7 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 		return -ENXIO;
 
 	/* prevent private mappings from being established */
-	if ((vma->vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
+	if ((vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, attempted private mapping\n",
 				current->comm, func);
@@ -31,15 +32,15 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 	}
 
 	mask = dev_dax->align - 1;
-	if (vma->vm_start & mask || vma->vm_end & mask) {
+	if (start & mask || end & mask) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, unaligned vma (%#lx - %#lx, %#lx)\n",
-				current->comm, func, vma->vm_start, vma->vm_end,
+				current->comm, func, start, end,
 				mask);
 		return -EINVAL;
 	}
 
-	if (!vma_is_dax(vma)) {
+	if (!file_is_dax(file)) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, vma is not DAX capable\n",
 				current->comm, func);
@@ -49,6 +50,13 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 	return 0;
 }
 
+static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
+		     const char *func)
+{
+	return __check_vma(dev_dax, vma->vm_flags, vma->vm_start, vma->vm_end,
+			   vma->vm_file, func);
+}
+
 /* see "strong" declaration in tools/testing/nvdimm/dax-dev.c */
 __weak phys_addr_t dax_pgoff_to_phys(struct dev_dax *dev_dax, pgoff_t pgoff,
 		unsigned long size)
@@ -285,8 +293,9 @@ static const struct vm_operations_struct dax_vm_ops = {
 	.pagesize = dev_dax_pagesize,
 };
 
-static int dax_mmap(struct file *filp, struct vm_area_struct *vma)
+static int dax_mmap_prepare(struct vm_area_desc *desc)
 {
+	struct file *filp = desc->file;
 	struct dev_dax *dev_dax = filp->private_data;
 	int rc, id;
 
@@ -297,13 +306,14 @@ static int dax_mmap(struct file *filp, struct vm_area_struct *vma)
 	 * fault time.
 	 */
 	id = dax_read_lock();
-	rc = check_vma(dev_dax, vma, __func__);
+	rc = __check_vma(dev_dax, desc->vm_flags, desc->start, desc->end, filp,
+			 __func__);
 	dax_read_unlock(id);
 	if (rc)
 		return rc;
 
-	vma->vm_ops = &dax_vm_ops;
-	vm_flags_set(vma, VM_HUGEPAGE);
+	desc->vm_ops = &dax_vm_ops;
+	desc->vm_flags |= VM_HUGEPAGE;
 	return 0;
 }
 
@@ -377,7 +387,7 @@ static const struct file_operations dax_fops = {
 	.open = dax_open,
 	.release = dax_release,
 	.get_unmapped_area = dax_get_unmapped_area,
-	.mmap = dax_mmap,
+	.mmap_prepare = dax_mmap_prepare,
 	.fop_flags = FOP_MMAP_SYNC,
 };
 
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/85681b9c085ee723f6ad228543c300b029d49cbc.1757329751.git.lorenzo.stoakes%40oracle.com.
