Return-Path: <kasan-dev+bncBC37BC7E2QERBE7VTXFQMGQET3Z4SKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x1238.google.com (mail-dl1-x1238.google.com [IPv6:2607:f8b0:4864:20::1238])
	by mail.lfdr.de (Postfix) with ESMTPS id DE9E0D1E55B
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 12:14:29 +0100 (CET)
Received: by mail-dl1-x1238.google.com with SMTP id a92af1059eb24-1232dd9a256sf683406c88.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 03:14:29 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768389268; cv=pass;
        d=google.com; s=arc-20240605;
        b=GguMnsOmJWNj9j6KKRrTVpsvLnveQDTC56Tvzym5suVUOxcnCe3VOxQOu3AGH+Mzdp
         lI7nMB5yvOi/xqiUgamk3NxUFsBCOYTKCDFuO/AQaJ6Y6WMCFLtRdHrDCvQO30yWOxVl
         IoblHEnvfHLBpE7F3A8WKTq6CqL8cXdUnF/RSWXrFcHIgRJr6/S1538uozP6bNY2kEJd
         csMow06Zi4vlUYHJsQ5hOcKq+EHZWfbMHEAKHXEzrsRJ9K3lfFV1BRpItJkEyMKMboPK
         kzpptGNOdMj654NRr6fziX/PtRcWDtJV9Enqln+jdDgchF5kxVWCf9BP9iGUCgwfXX+T
         Qmsg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=w1hetCNPLgavidhM7t0nRKI6RgHM9ibPU1l0+9CmbNA=;
        fh=ND17l/zP+FZ/hE9SVYqGC/hztiXdk7HG+Qb7whBMv1I=;
        b=SW/5608By2BPeG2GtUCFsN0gDIOyFaW5LbGHE566GZGE/C48b4Xb+T6PADPKRQJJIv
         uemJObtusK2FrUjt1LtkJodshzrelr6kt4Nk2x5vrsij6owAyWcvs2xa8skRgPaGItw2
         iGlPiHisEK35XWFi2iPZX7eY49z3bU0XEwVZs/jM82Khgz3o/+4V1NEvHRHBrH2rka4h
         9MxeP8Lsq7J1TSP9UpI3k+N7J1MQOouxQOUtO8SKeqEdcwy/NgFsAHpmci0oruZrTS5f
         J32ZSGLehkEh/yE2eZzxHjjY3QY0xMDJFMJ9bwwOEKI6razCH/A2b4Iao6saNY3Rbd/P
         Apgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Y4o1jpK5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=iCbujTWb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768389268; x=1768994068; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=w1hetCNPLgavidhM7t0nRKI6RgHM9ibPU1l0+9CmbNA=;
        b=p8OeBPlXcXYYJmlZkZCy+i+EpSiwPMJ5ac5q908HXt2MWHRpqvI+uetvMfaCIjk3OU
         Q1+HBQYsLLPa9GdOacMM92i0Pe5UC20z/8wyqebcII3RIAHuf0SeFUL6mDQXKs3XUKPb
         ZnFTHSBGKr+e1LDsS7qSB456GgKR2/jQ4ZR8dBkTw7uRquyQ5snANjsQTU8eYd1N1iIZ
         DgF6jRyJPgbqb7mDpyG6KKVqasOMazzRbUDY5blzeOFj1OieGHbnlNEOv3DebC2Ed+GK
         mRbgRRb6JnK4ad4eQGNoytSiTkK2Ro0I3es8pHmIyYkXQwXkRNAKAN059UaHKNP3Dbix
         UafA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768389268; x=1768994068;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w1hetCNPLgavidhM7t0nRKI6RgHM9ibPU1l0+9CmbNA=;
        b=nuMvmbGBU2D0BVVWuJN8ExuyFEjI91bAj0Og73EOtIxVs9mj2lIEuh8akOu1uYOsyC
         dobu/cV8gkhjlRM41NKV9sRvNFKlDOBZNwT1yDr2B8WdDuauD5wl7ZaQTPXffWNPrODU
         xF+dLezHHBvdUABe61Ka3WVy1oOxkJSDqF2E7aLNE5mBHVTTFUWJckG83roNCWiwEUJ9
         WA0p8TjP8+TyNbPG/nlpaHYwpK/b6oziEy+NLTiVNn/0GGpTdsNedBETiCapa4B1vgib
         z4UMmFGGw6vXOgUBfY7Kg7NqQrIEY0WEk7AiLhigimsdgQ5hx6BY1KjFF1dzC6lhMyqo
         ljTg==
X-Forwarded-Encrypted: i=3; AJvYcCWq4V56s3a8L1ez6xFV8+6ow8PJiuVEXTxKIIGwbDB2dHedXr+0O9NT4mZHrS9oe4Uu8wJvzQ==@lfdr.de
X-Gm-Message-State: AOJu0YyrRkgs8sTmpXUe2kO8jEIRPVP7R1NYPUY0wIu9LAmQRFfFAgZh
	4MFkxQwfIhJHqEMGucISFzbXXJSbcaZhK1HghP+FK0VYpa/20370xSpD
X-Received: by 2002:a05:7022:e803:b0:123:3301:a718 with SMTP id a92af1059eb24-12336a0c13cmr2330176c88.1.1768389267916;
        Wed, 14 Jan 2026 03:14:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FzgW3x1/zNa8YXmSNpPsFxIB9pJ4dEmOGq1otiTIGNmQ=="
Received: by 2002:a05:701b:2204:b0:123:2c7f:28de with SMTP id
 a92af1059eb24-123361c37e6ls351722c88.2.-pod-prod-00-us; Wed, 14 Jan 2026
 03:14:26 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUo7dxYEIx2UwDvU6yo8fVTexu1CzY1aCsKYZL5Lo61k/Qx9LAaRNbNQo22YYp53rOhOa8+78NAt1c=@googlegroups.com
X-Received: by 2002:a05:7022:419b:b0:11f:46b4:449f with SMTP id a92af1059eb24-1232b6425f5mr6691063c88.24.1768389265943;
        Wed, 14 Jan 2026 03:14:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768389265; cv=pass;
        d=google.com; s=arc-20240605;
        b=RzvQwPfXiCtMVj6sa2kE5kqJQBpq5zfZ/KIH8+c20pYgSDGhyytvb1JvcijMCdg6pO
         G8JlKat9XmIl9uFuSPe8T+MzJeWqw1JI1JVShRNyOZ4vPYK9314uepYt6T8asrdnrKD/
         3+2+a/iVucBptOs8cKyqgijdz8kDV42Okhy6Lw416Z3x2fJZBmytbnWuW/6LGsFKYf1+
         MeKEnHorUqpb/Px8IGeCe78N4zHrZVjxzp25iJq+aivT8+erXvNDOZLuy8DikAtYenN6
         BK/JbvUwRPtPHV5xNxW22tTV6/R250XmxvBhiSXYvLotww2MkuNwld1uyL2TLw6b//gI
         Sr9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=MSso4XPnVjoi2Pe6F1o5cX+SG3I9VxcV45WgDHSMpMo=;
        fh=kceCFzMIgve5i5+gz0p/EEtyI1JcVUwOSRB4LdjPUvg=;
        b=NjExRhMA1qNFYSs9k8GLkY4HBwR6UtGaHP+UEaiFuZWTOTqWDW31JAZGEhWarsHOmO
         X08W0lUez5m7VIT/uDJUN9CbrvDBBeEjZTY6yM+/A0JN5fT1TWbiWAZvIKqsS21xjdBI
         zqHNlhCF9gBA7Dt8yfsj3TTZHKvNJ6P+5MVEgB+L4URwEOMnmAuSsb9/++1pknNvUb27
         WeWbuekO9OEEp9hJ6oiUe09+KMdwo5zvmnwBotvUVyEdZ381Ie9k2PFcDA2UNydqUYhr
         7VZSbffiKxmErK7xTMPlf1d3qeMvMIM50ycXuLXNbxhRxhNDNe28WBQonFttDdr58tas
         u28A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Y4o1jpK5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=iCbujTWb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-123391bdeeasi34053c88.2.2026.01.14.03.14.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jan 2026 03:14:25 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60E6H6Qq1008313;
	Wed, 14 Jan 2026 11:14:21 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bkqq550wh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 14 Jan 2026 11:14:21 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60EArVMW029408;
	Wed, 14 Jan 2026 11:14:20 GMT
Received: from cy7pr03cu001.outbound.protection.outlook.com (mail-westcentralusazon11010057.outbound.protection.outlook.com [40.93.198.57])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bkd7kpddf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 14 Jan 2026 11:14:20 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=PZHUqhxHsdzUO26nbyyFH3X7jUVXXh7CZxmHu+xRQbPSF9kXbV8TZnmFwTGEO/54aRFEsviaVZ14B2mtNhxw2rE4II1t/spyaWLsvqDEtBx9N36r3YAmRpZGBMm2Ax5w2nSe95gesROfsPyCtAYqsTqOdrHJqj2kqoZhgzH5IyDV4ld06mLXF5kUJEJBnKFSMehCuYIFBotAZRjZB4UR0HEYgLv9xbm+hYs6iWxf1hEegIoX4QrTuHpMgOFMy7LfmsnQJ5r33T8/orJjOPu4cwHurdOJCREa0iRtlI0D7LRjWaJ4TaLlifYbYPQpkwgU1jKRxEmZRGpkXW1xJWKJNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=MSso4XPnVjoi2Pe6F1o5cX+SG3I9VxcV45WgDHSMpMo=;
 b=FcoqOQNIqUzFUimxYVbAvlF7B7ZHHU4M37tlL4IFrQwyZrVEHQeLPYqpF3diFYTDCNy7WlRm8dbREanJuIdV9bOU2FBlEVj1Z0SE6NgLJQ34zsBXj798hBrh3ktotDgkpNvahZjtt5dq9aktkAJXb79A/sMg64ckTrdPWr1kRYDpjavvktPh86odsR6SGc/1ZeJDF5vpoVMiN8ADx2N5IJmTrMUvpkl9eQxuIgmRcC/yDXLZQ+zEFekEBFo/CBnUASTq1UtoqIKMfqvSHao0bNYGqVUtjOAvgcgQtp8WVL6c+CklG0pTbWqhygc/AD3PNHL75+mkpOqCfYlbw/bk2w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DS0PR10MB7341.namprd10.prod.outlook.com (2603:10b6:8:f8::22) by
 IA1PR10MB6784.namprd10.prod.outlook.com (2603:10b6:208:428::7) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9520.6; Wed, 14 Jan 2026 11:14:16 +0000
Received: from DS0PR10MB7341.namprd10.prod.outlook.com
 ([fe80::81bc:4372:aeda:f71d]) by DS0PR10MB7341.namprd10.prod.outlook.com
 ([fe80::81bc:4372:aeda:f71d%5]) with mapi id 15.20.9520.005; Wed, 14 Jan 2026
 11:14:16 +0000
Date: Wed, 14 Jan 2026 20:14:07 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com,
        kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH RFC v2 01/20] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
Message-ID: <aWd6f3jERlrB5yeF@hyeyoo>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-1-98225cfb50cf@suse.cz>
 <aWWpE-7R1eBF458i@hyeyoo>
 <6e1f4acd-23f3-4a92-9212-65e11c9a7d1a@suse.cz>
 <aWY7K0SmNsW1O3mv@hyeyoo>
 <342a2a8f-43ee-4eff-a062-6d325faa8899@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <342a2a8f-43ee-4eff-a062-6d325faa8899@suse.cz>
X-ClientProxiedBy: SL2P216CA0076.KORP216.PROD.OUTLOOK.COM (2603:1096:101:2::9)
 To DS0PR10MB7341.namprd10.prod.outlook.com (2603:10b6:8:f8::22)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS0PR10MB7341:EE_|IA1PR10MB6784:EE_
X-MS-Office365-Filtering-Correlation-Id: 4bf11082-d294-4661-f0f7-08de535e0e50
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?1gTEsKSiPb+BHjlChLi7UVWW2jGkk90rni1gddyeot6BoO/aKqVl6NacgCg/?=
 =?us-ascii?Q?YywQMP7E7/81p9Y3Ml6xGRQ9tMSmNEFgyrlo/fQKehecWSL2rpE+VDJGkxdZ?=
 =?us-ascii?Q?CA8KlXlxJ2AgMj9yWMdNoU/E5D/0wQO9Od4Mn3myULwq3fH0r2lFvDEgoIxN?=
 =?us-ascii?Q?CASw7BKpA3eIae8uSIB9xyQcDNzhl7lnQJWabuNz1417/tUHsO2ejqa9dUoA?=
 =?us-ascii?Q?2L8ezpg8QYOLUFw2nbetISV7cuWQu+OAPaLn8qg2O+zqhyUtA7wQbauIyuMn?=
 =?us-ascii?Q?8+CD/CFZqy7Z65fHSaS/ElT8/1heFmZu0laTcPJpt9QWAeJkjJUq7T78ZrOh?=
 =?us-ascii?Q?JyOdLT89wsvNFra2lYBz9ruquF+47hzin0R1XfY2zzF4lAehcXV6RFFV0vPg?=
 =?us-ascii?Q?SF43slC7WASp57ve34PzW2mtVwucEFarT1G5mSwAXuAOGoJuPzXJfHxFHsV+?=
 =?us-ascii?Q?3EebUahmAiONCPjh7deoY/L11Is0I/mNGxEjyevX/QBrjtOLkleQb/QfvzqP?=
 =?us-ascii?Q?cv9tUh1mVCcfEgF1TSsPlaPPiWziID+fMCn844SamoSZ3kGRxiP7H/NpTVZ5?=
 =?us-ascii?Q?cMJ4vBt+gmBf6im+O8qIdO54iW6nvb/C1RHq81nQoRPfm0xUd6Xoaowo6Tq1?=
 =?us-ascii?Q?l+cjwKAEbgNnKwWajQ6SiAltaJZkMAG/Deu/ZQrlnFt6q+1baLM++ILBqeVw?=
 =?us-ascii?Q?vdxsUZEHfmNfQWt9A9Xj2BJsifJeeq2NVHx+61t6Pp2vGPEXrevaPfiG8pxt?=
 =?us-ascii?Q?rRI4YPJbAs4j3p27p6CJkk/aGB7V9lOKXvakZjU1Ec/51t/IYVT6viv0dTFK?=
 =?us-ascii?Q?s8dKMjWMh2KAW7JjM+wOnJqLsn9da8ze8E2Bn4kZK0LHefvv1sD77xx7Yje+?=
 =?us-ascii?Q?pWnEkhWzeZCeJS+Gypzp2ShK2t/z01TlwIxuBquC0xiCqe1cBAeB6KDKuWJj?=
 =?us-ascii?Q?zWCfcW8n+r2F3TjKBntP9UkH1WO5MH86TuXkefVaaHiW42cAn5sLhot7KIhp?=
 =?us-ascii?Q?ACH0xZK8CZYysiIvHryufqWt9L0gVGk3OXXYmKtvDu5pNAn0CuyiUEsGg/kn?=
 =?us-ascii?Q?/ZIaEWDl/svz27EZ8uVjNt6CfqIlKYp37gbv1ZK699Q/kvqQKXRHbg6Z00T1?=
 =?us-ascii?Q?olfQjwX9JiRsyZl8KZuBJmDjoKaTEx4O6HyZneBQ3cyginEj8l82n+1jYFHG?=
 =?us-ascii?Q?Pl8VhPbySI5+7yfoYvEuUM1gL19u9O3mIclEOKJ7N2M5zFT8/Gj2zoEvtUQa?=
 =?us-ascii?Q?TieTd71g69VYIE0jD175tSlFcr8AaWWaSmMJkXq40iC6QDv0f6G+QWWkAtRm?=
 =?us-ascii?Q?YMYHeM3m9RqgCPs936nygWVsXf2/xq3J2zyrSXYNBdtJKS4NA6uCy0uu8bUv?=
 =?us-ascii?Q?bMyY3iBHtt2UiGtTphxYsgxicBtpS4otncDd4KT7yYp5MYQoP+/rnbLUDNfT?=
 =?us-ascii?Q?xnY61wMybD/IA+7tXaPS53Vwhcd5bSW80h2Eo9VnZhvCRIPeWxVlcQ9ni844?=
 =?us-ascii?Q?uTp7zn+T+8GY2mnNyv85EqQVyh3HMim/Q8fLEIYTEP0qhPmb/f3sgRc9Sm27?=
 =?us-ascii?Q?LqztYRZC2WtpBGmwm7A=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS0PR10MB7341.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?wfuoXaq9WLWkz+1GtAUoTNcXmqtIfsGyhFLTS42wLnCdB/0qaDUe3EZV6dRN?=
 =?us-ascii?Q?Fn23k2UOO8bVl5/gfZg1eaJY93s+7OTPHaZghh637cjBdqugl5aIx0MVkUwu?=
 =?us-ascii?Q?Knevnx1v2f8GQngooLxNlwuBnaDGc5RSFXR/HFqL8jZIg0Pd5jHPOnDYzV7p?=
 =?us-ascii?Q?TQ6o/jSRVTuvZWedr03hIdGqpk64bsMrgyMtp9DPvUjW9NJRp3mU6nPZai1R?=
 =?us-ascii?Q?/PclPmUqpjOXt1FzbcXHpw74KYNsWIYYxoCHL89iN8DewDTO2ESobELEICvK?=
 =?us-ascii?Q?8HIN6EBvXCGR1aIVY7UaUU2FyxEv/iz3JMlbK/oVS5b0NpqU/AdEN9TpNSv1?=
 =?us-ascii?Q?R5bCPBNpWUPu6j7EML6nimEOVL7UGcMtKhF5ZvIysUyz6bsjPxrqmFN4CUrM?=
 =?us-ascii?Q?MWMItpbcKVxo/ZIeBChRMZk0T2iULdB4gAaTyQXIJ0Mxpl2EiP0l6p+1mPeN?=
 =?us-ascii?Q?QLZRQqZaNuOmZHvYAijNqQU59CE383Sa6tZDMn5NzDtsMrDrMr0JVCmQ+uSw?=
 =?us-ascii?Q?wJdl9bZz4TchLcYLi+Fr7KZRPtlfAME/KsOtuSvAFXj9hhXFsbA9gpS6986T?=
 =?us-ascii?Q?MLvCX+q3NaHCKpfo6wSdX1gKpK5kgUZJQCbhZskme/q5l7gDjT2gYuqQO7Hf?=
 =?us-ascii?Q?y7ay1QgnyRjLfqpLNk5u58GWJWYue0jGTIkCDn+jwsip9611wKrcTYF9AD0u?=
 =?us-ascii?Q?/cRgcnrQ0S1/quHL0l42EcjWKj1PHGXa7T8PaqCKOoVEGJm4lsDwxPNMfgJ1?=
 =?us-ascii?Q?CePduFJQvVXmkoefy9bbb/wd/u94VAPAqrCJc7XAa8JdwdZSi4KxKa0KfetB?=
 =?us-ascii?Q?XRumjHw5dpzLud9IxZVROTEszcaV0VXIPTYGuNppHli7StSDwTau53oI80AJ?=
 =?us-ascii?Q?p4f8VCkrUkUFYbKixTTSTQub0mjS4KF0zwZzcu7DR+QD0l1eSIlNYj+gGPHo?=
 =?us-ascii?Q?nNbZKhwsp10EsTofm+PcvpnIaF+qOvfxeN2E6UHdkDnYaFzUilBQFobh/uG2?=
 =?us-ascii?Q?SmBoWuew5OywMbblgwTPMor2U+J9LfYTVX+gleZuiLnJkC78yCPOVi52V5FN?=
 =?us-ascii?Q?/FCx3vGh8cJNtCXAicm2ks7fHl9jK3Hab7AAesZ2yomotCxyTx7ClKHn3IxY?=
 =?us-ascii?Q?bDOWegrLgPRa9NMTz8DD54ju/zpasDY7wHHUh4zwKOhe8Q87gObDNL6VPTqn?=
 =?us-ascii?Q?6Jq5Vm/BQDLYPw0h35WhK9W5CBo+pV++3IoGq1dfoNiUDfQ1VwD7QiAWXS/c?=
 =?us-ascii?Q?PNW7lQTT/UZyPqYU7Dy7QvAWbAfvRoBIS8PBbKQZo6khXy5nErh9aSAJTUao?=
 =?us-ascii?Q?neYY/lc3Til9tBnX/0L2H32jQTY9gDKF/uhTJlLaZ3IppuAyqmlEZvzygvob?=
 =?us-ascii?Q?XoTlmDeNBMs2bApzuRGcN/2MZGfnmGk964oVO6s7VGoCy90+UHqGXq+S29V/?=
 =?us-ascii?Q?O9BFJl02IWZLGdO1njMYKmbfwkPk1W3wrqyAv6lSys/NXJp4jIG9aiNB72l5?=
 =?us-ascii?Q?WMso+ovdUcrCNpqxdq37GpyQBgmwBhi9HtCnXslSBS2fq1p+2sKpwec3mgu5?=
 =?us-ascii?Q?3Y/QXy5CibvYd8LQWeZCxSISsRbq+Xg+z3izmnrcqx7biIHexw+qV1gwJk3d?=
 =?us-ascii?Q?01qSQWr56TCMMT4gxG73CvzM9BKRzWv2vCCSP0A0BtvATQZ6P2fZoh+v0GaT?=
 =?us-ascii?Q?IWKKxxvpqDxmoAHOht1IBZM3pGjSv9Df4ZBR8mQFqtEBDZhBEixmapFZJID0?=
 =?us-ascii?Q?YXfvtlHR/w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 1u/r2c8P+khM74HDLAWbGnyTaWFgF5CKc4ImYiMVMD7arczR32P5yyXlr8kQwDCvx3y55CG+2KYZ+zdFsuzF328vY9o76K4LVdXuQrEFSKMw5edO2kXPquKFqG1lGmSETONYVo5WAwGY0Vv7Hl7vO1Xw9l5uAgIujgET7ihkhEZG1kH81NJF/FkzOlMTiIESh9cKVjf144g8DSxLq9dFKO1+vvlYALewPpg/QkBAQ8y+btm79wBo4XJV14IDrSoSW274dVZvTGWZpr2gdaP1zct1zwGnsbLRyv1Tlu3PaVHsWkfrP99TPF3md5e2OayMKBsO/2yDs9SldPUbP5vlHN3vIvgmT8i3E34MClxbbPZknb2CKSJQXg+jMSOuiyli+tPmb+5GwE3Dzs5K/n33I2jwMaPpIIHTBtsODnSzwagrSpGDbvTui9dfAHHONqyR1xT2XCgTBJ5RzRckYx/3sx/MHEUoLWnQM6A1LHSvcMNiCmsCiD03aTqHDvmDtPwiC6tC+NWKfjKOrro2rCIrXCarULDTiqdbj6ulABPPEye20Q07rd2uF/roYSoRtxHbuEJWTZzahNVhMtUTejJvct45EU/xl7I09eBxQihP24g=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 4bf11082-d294-4661-f0f7-08de535e0e50
X-MS-Exchange-CrossTenant-AuthSource: DS0PR10MB7341.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Jan 2026 11:14:16.7339
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: BuiJOpP2jIAPWYkb7FvFI7JGoT98VPyymkPHacnCMHNUi7Naadry81Y6R1cKJ5EmTeQpaz/jAzfSijzjjlLwdQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR10MB6784
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-14_03,2026-01-09_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0
 mlxlogscore=999 suspectscore=0 mlxscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2512120000 definitions=main-2601140092
X-Proofpoint-ORIG-GUID: KKbjMqC-U7XomRZPtQYS8jzNDOuu25AU
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE0MDA5MiBTYWx0ZWRfX2lZs+xPtR5F2
 Uo53RdcoB63tPZOBK3b6khg1G8Q8hNmJvBXnwGclpoFYzNBgzGpM6t313wMJLiQX+AubdqWbtl0
 aQaEGLEvR4IeDdKXTfw8RhK2H+9UyrJDnCjTYFDyW0WIR7h7I13HzwRrGJGGw52BoVIURxWMrWl
 tBsGddi7CpvIZ0gMA86yHf5Z92iFRgbrMBFgtrImoGX0JgTyNJFyjEiZ7ge+QO5eJfGS9PKugHo
 NUxFEw+IiujNAVYebjYpt7NkGPbeN5RUQMv7h5wR3N3CW9vwcVoVUfsd3Gexm1dQLOx+yG0l2fN
 Sxa9OZrBMljW56uk0ia7dxK/BdxkuHQ/eBshjvAfD9ejmCPyGhrDMqNY8G/KLUz7XmoE5hCoZc+
 HscgikLemHudbbPxK8thT4ZwLWCLvvOWxpRib9ln9sayueUwq9lY06Of9QYj5a5YssVDO0ajsPN
 3LbDkwq8IbaoG0EIm7rEcVAihBbDSx+tQUJz36C0=
X-Authority-Analysis: v=2.4 cv=J9KnLQnS c=1 sm=1 tr=0 ts=69677a8d b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8 a=bcoFj9AnJuNMWZxSLeYA:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:12109
X-Proofpoint-GUID: KKbjMqC-U7XomRZPtQYS8jzNDOuu25AU
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Y4o1jpK5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=iCbujTWb;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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

On Tue, Jan 13, 2026 at 02:09:33PM +0100, Vlastimil Babka wrote:
> On 1/13/26 1:31 PM, Harry Yoo wrote:
> > On Tue, Jan 13, 2026 at 10:32:33AM +0100, Vlastimil Babka wrote:
> >> On 1/13/26 3:08 AM, Harry Yoo wrote:
> >>> On Mon, Jan 12, 2026 at 04:16:55PM +0100, Vlastimil Babka wrote:
> >>>> After we submit the rcu_free sheaves to call_rcu() we need to make sure
> >>>> the rcu callbacks complete. kvfree_rcu_barrier() does that via
> >>>> flush_all_rcu_sheaves() but kvfree_rcu_barrier_on_cache() doesn't. Fix
> >>>> that.
> >>>
> >>> Oops, my bad.
> >>>
> >>>> Reported-by: kernel test robot <oliver.sang@intel.com>
> >>>> Closes: https://lore.kernel.org/oe-lkp/202601121442.c530bed3-lkp@intel.com
> >>>> Fixes: 0f35040de593 ("mm/slab: introduce kvfree_rcu_barrier_on_cache() for cache destruction")
> >>>> Cc: stable@vger.kernel.org
> >>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >>>> ---
> >>>
> >>> The fix looks good to me, but I wonder why
> >>> `if (s->sheaf_capacity) rcu_barrier();` in __kmem_cache_shutdown()
> >>> didn't prevent the bug from happening?
> >>
> >> Hmm good point, didn't notice it's there.
> >>
> >> I think it doesn't help because it happens only after
> >> flush_all_cpus_locked(). And the callback from rcu_free_sheaf_nobarn()
> >> will do sheaf_flush_unused() and end up installing the cpu slab again.
> > 
> > I thought about it a little bit more...
> > 
> > It's not because a cpu slab was installed again (for list_slab_objects()
> > to be called on a slab, it must be on n->partial list), but because
> 
> Hmm that's true.
> 
> > flush_slab() cannot handle concurrent frees to the cpu slab.
> > 
> > CPU X                                CPU Y
> > 
> > - flush_slab() reads
> >   c->freelist
> >                                      rcu_free_sheaf_nobarn()
> > 				     ->sheaf_flush_unused()
> > 				     ->__kmem_cache_free_bulk()
> > 				     ->do_slab_free()
> > 				       -> sees slab == c->slab
> > 				       -> frees to c->freelist
> > - c->slab = NULL,
> >   c->freelist = NULL
> > - call deactivate_slab()
> >   ^ the object freed by sheaf_flush_unused() is leaked,
> >     thus slab->inuse != 0
> 
> But for this to be the same "c" it has to be the same cpu, not different
> X and Y, no?

You're absolutely right! It just slipped my mind.

> And that case is protected I think, the action by X with
> local_lock_irqsave() prevents an irq handler to execute Y.
> Action Y is
> using __update_cpu_freelist_fast to find out it was interrupted by X
> messing with c-> fields.

Right.

Also, the test module is just freeing one object (with slab merging
disabled), so there is no concurrent freeing in the test.

For the record, an accurate analysis of the problem (as discussed
off-list):

It turns out the object freed by sheaf_flush_unused() was in KASAN
percpu quarantine list (confirmed by dumping the list) by the time
__kmem_cache_shutdown() returns an error.

Quarantined objects are supposed to be flushed by kasan_cache_shutdown(),
but things go wrong if the rcu callback (rcu_free_sheaf_nobarn()) is
processed after kasan_cache_shutdown() finishes.

That's why rcu_barrier() in __kmem_cache_shutdown() didn't help,
because it's called after kasan_cache_shutdown().

Calling rcu_barrier() in kvfree_rcu_barrier_on_cache() guarantees
that it'll be added to the quarantine list before kasan_cache_shutdown()
is called. So it's a valid fix!

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWd6f3jERlrB5yeF%40hyeyoo.
