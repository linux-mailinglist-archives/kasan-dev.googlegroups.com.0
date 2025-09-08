Return-Path: <kasan-dev+bncBD6LBUWO5UMBB6XT7LCQMGQEACDYUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 83451B48B35
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 13:11:56 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-30ccec20b9bsf7012412fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 04:11:56 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757329915; cv=pass;
        d=google.com; s=arc-20240605;
        b=b6j7fEbLl90CVxyZea+bZqvXE55Gm/UfW04LuWl0A92D1eFq3dQJiSVs7IWy43oTbJ
         X5gASHTsMtM5wROdb5SyvoT/auc2ZiaNM4ZNa95P2QBXTeqz1OWQP5ERrPd5KYwqGvyU
         07bNhpAPX4tDoBLSuj1us2SRjn2obD64uqurHPTUEf0SqBy7L0ATAlkrUWT5Du7h5aP/
         gzeNsugdTKKQHjNxnqRMCOaaFAVefY3ON/yEkhZL4YtNq8dqn8snuF2jd/ZDMqyzO5ki
         u3SgTtuCyB7ks5hVSAX84/bzpESRH5n3ar7ZLHDVd/SgFm5/uJwoQdqVQBMwlGyWj0AJ
         iH1A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=4tGcCbOeAegngHbkMqcr/VQI9GzCHWxZ1M2F4POIqR8=;
        fh=koajd4fQ0onJFh/523ixm9oOtCqt7fCGISQ9MMx9EtA=;
        b=JtnwEYLOmVXtQCDylEQLqIG4t4hBIAI7eIQFaDxd3PDVmCVEzM4Vo6F9lm1xU9mKhW
         xlcE00ItILlmsKBizVgHW7pBhaqV3Mxen7lV+caT2SOio+Ksnh5z/InwWWZMdiQNLuWU
         saOZu5HoLoY4IWSzOuNfWFnx5KIC6hshbesbt2rNlh1ID4m+/QcC9Tm3P3uW/UBRVZdb
         Rae+daX/kr0SlZmoBC14VuIwkc+uoff5gxOYz3PJm57QFZHE+1ojpOg5HOWp1VqtQT1F
         dI2DJTk5vpUhXlkE94p/9R8yN0he3ahbyM6XrGp43cM+1ZMeYAXGR8KrTJlk4MCUeq08
         bp3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=mljG+8VA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=QlJyRUnY;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757329915; x=1757934715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4tGcCbOeAegngHbkMqcr/VQI9GzCHWxZ1M2F4POIqR8=;
        b=gPRjCpit/4tSIVGXLyFPBovNSsOd/J09GQWhR4zUrMIPftCwn6/sulG/xHFj08mOra
         OYqo/i9qI69ioev8WU8aCPY4aOsqYCTsXUaqzR5aXlClxr24+FWTkat1NYaUu0IiZ+Fi
         s8n4HiST6txLZ2YT2XrbijEVBPB+QtngHK2YJO5M+XBTwxIZuIKO+7dleoyPv7iqeiy0
         U67gKv/DBe9VjU3kQ8XgjOPDlGzgRVmCAvrK4W52bJtx/MPC5lAhQmtZXstmHrsbSAz8
         yAOpnXpDY4YLp3D38r/L2QEitS/yASj/OdckDOTv/VWjOw1mk/nSkwPGguvw+w8mygPQ
         LCZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757329915; x=1757934715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4tGcCbOeAegngHbkMqcr/VQI9GzCHWxZ1M2F4POIqR8=;
        b=iPKvrRH/QfRaL0BmmaSDeJe6HCNZH/weXgnu9YU1g1xyyGtMtcey3YztWpbjWQEPqg
         Pi2Wa47VVJb2c6Bp91dfLdv6J9FDLDt3r7pXSrf9yeJW4LPSHGB66ZOjMqSbABR3Lx0r
         HzPcMgWo1otAkJvbECqb8Io+dzibK9OZefxg9YKHRZFI3ND1gCVLMSIfqUolwTWpQLK/
         2HUOBRRY7bPajrLyAxcsuCU9VCykasfGGVvm0LSchMX+t5d6Lj9kxP463ieHtCmIIZ8b
         VJppaaF0ncBIj1Ah0XeNirgpVGIfABDbKG0I7oZ1EB2/nNkVSHt9m7UmEQO3ewXfiA6L
         MOug==
X-Forwarded-Encrypted: i=3; AJvYcCX/h7G2rigx1zy0UmIWLXphINcNQ9z57yMBzv1ejr7gK3gl03epsPZpSKsqlFSwV90Y/Z0fsw==@lfdr.de
X-Gm-Message-State: AOJu0YyiOUstUFp0pTmA6DcxVzGavEde7Ac3Cwem5R3TnpeXEUsPFCPo
	3ISYvXpK4XX/SriId6ApiV1gbmVEy92ex7pF4KionalgZqs2eYEuh8jO
X-Google-Smtp-Source: AGHT+IGL5u9E2HLTK/X3l0KxOOvcj0W3Nu5rQHdPNMke+nU+e3sNYixeaROzr7uCSrfumdheYoAATg==
X-Received: by 2002:a05:6870:4e8c:b0:31d:63f9:b247 with SMTP id 586e51a60fabf-32264607e14mr4346095fac.25.1757329915151;
        Mon, 08 Sep 2025 04:11:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4vDeDhR25fG6OUbZO3fm/UzsFn/PVdIeoC22PIzjIowA==
Received: by 2002:a05:6871:503:b0:31d:8e96:6f5e with SMTP id
 586e51a60fabf-321272207bals1260720fac.2.-pod-prod-08-us; Mon, 08 Sep 2025
 04:11:54 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWRCdbVUEcwpRVcCXo5fx1bfZBF7xAkZObfFxYldXnRR9WR2pihA4upR2y2fp14611eU1t7PXsndLw=@googlegroups.com
X-Received: by 2002:a05:6870:7023:b0:30b:beb3:5424 with SMTP id 586e51a60fabf-322631a293fmr2657100fac.19.1757329914242;
        Mon, 08 Sep 2025 04:11:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757329914; cv=pass;
        d=google.com; s=arc-20240605;
        b=IAwIGR4ZDXJ5lIvTb1JFucGHSbx0VEOf2bhF4uv63JsWOu66X+yaxi3fFhp7jQn961
         mSLdNJKJj31XGNetvROWcnltrkF1lXuMjZMl1Wg3eRpMksoNqkURLhYBlYvRAs712Fuo
         4c5Bomt39qXVYGzxepb2vs9s8i2urRulzn5xn5iZGI2aVWKkXKDMQvHEC+QJQEX6PAuq
         RSeZF9jjSwGg94TrX+YCdAucSEA02e2KdSNlUx1y1vKsdDLp1401az9zgK5KQ1D8HiDV
         Za25krM+dGpWDEevQ4OGTaGUO9f1Dn9aHme5sFxOpv764H78PI2Be6ciUbvVU8FGxgY5
         jQNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=jFeM+IklPleV0gR6/nJieTKITDf0dbD9LUtd2DY72B4=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=Q88jN49iOANeDZieBy7ZgU91Qi0yc1BBB8k19YAwt9Ou8DxGH2LLimyx25EmifHslC
         /k2GfcppIg7pBnJrRPMa1idTUfMU0nQ181Agt/j08xX1TCtC5xynEqStOMUCfe6I0oWp
         r2k8Qc/RYCVxAzmBzsgir4twvujzSs9Jl493zfqNhGgTc6J+4gHP+uoSiuWlDQ/Sevkd
         n5obgKLMjEbHXsUmnrdeJYxUp78izXfi4U+49y/D2z53++Jt1i1Ws4LWyBJK1E5rqW44
         zUus5MnqAwvLkLKGELgCY3fYXl30nXM4P+fxUlBINeJZSuNkQy8/tfv8sjLcU1+ZXF83
         PULQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=mljG+8VA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=QlJyRUnY;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3223f6d0d07si260577fac.2.2025.09.08.04.11.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 04:11:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588B4tN9011866;
	Mon, 8 Sep 2025 11:11:42 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491wxvg07s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:41 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588B6G9D026049;
	Mon, 8 Sep 2025 11:11:40 GMT
Received: from nam04-dm6-obe.outbound.protection.outlook.com (mail-dm6nam04on2051.outbound.protection.outlook.com [40.107.102.51])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bd81nkj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:40 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RFPNoUAytJA5B0UpPrDVa1wpeWVL506QF8M+iQQQpxLYL/Iiex6NlTFw/cV3Q6EZpMX9TSn4/BteN5raGi+I38FpuG/2YuTwptnMYUW2VQRdqXcBAaV00d5KM4xbhekpcdOzxSHPBs0pCQd/NQpSA3FhsCPH3Z8G8GsXml8ZOdufsP3Le/T8zbdkJWpfjFFRxWymAi/vUtlJSviNjtXpLrMgNkA3h2u5GIVxEsnr8F+PguNveY0pq5lxIcViLU8y5C3FTlFrOdbErO0LZs6bXZ1T7RCJNCppm0QrqyfDahsQBWrhfvDUrFNvw/a9OrEOJwb9ZLPPvoAhqtlEDqiWKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=jFeM+IklPleV0gR6/nJieTKITDf0dbD9LUtd2DY72B4=;
 b=tYksr4y3Oe9byJJyCpOGKBvY7z71zvKxg4AR4a+X8jC2dp3erseEI1qWEQvzr7YWUs1oVCuflJbr35W9/L9fyzeyAnH0Fok4MoigIocGghvfds/zKPRK+2L7bPSkpmxD+jCUdH8W+Z9WFeW8M79QpcYa5+7OkcE26HOqYPcU3Ut5AKwhOdgbBWeBVRiKAGimolbiu7U5yOOKEqvNe+XnJOGRsmHvb314l1SRbup11WBq7taE2MTtm3aemQ1B8xrRogSXe4jMgZCFNGbiBxzk7iNXrfBMY71rSjZmlFs42YYolIJIdy8HeEvUyyja21+zwj5npVrs7imtxcNtZE9lDg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CY8PR10MB6588.namprd10.prod.outlook.com (2603:10b6:930:57::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 11:11:36 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 11:11:36 +0000
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
Subject: [PATCH 09/16] mm: introduce io_remap_pfn_range_prepare, complete
Date: Mon,  8 Sep 2025 12:10:40 +0100
Message-ID: <68b2571de694e883b8ffd6cdc0448849ae67b683.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GVZP280CA0055.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:271::12) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CY8PR10MB6588:EE_
X-MS-Office365-Filtering-Correlation-Id: 097ccb31-adda-4479-90f3-08ddeec87a1b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?URu94y6dwJpUkpHAiK1ZCCnSPW48zOKrETiE+/IP4+p07IgigUmquLdvrXVw?=
 =?us-ascii?Q?u2tV02kA9Iwo/VNMyh095x7eaPb55PsRxQ+hYvnQovIzyE5Q6ZwDoGdNKLpu?=
 =?us-ascii?Q?e4BDey9gQLXdMIH8Q0t4YyHwbV7SuDn/XOk0btJF/DG00Yv1+3+gywYilfbP?=
 =?us-ascii?Q?Bgxqs0mhrQEpD+D8HwVauUBCLGjkbhMWgPHxVDKnCj/m6G4TAzlrMk0lSzuL?=
 =?us-ascii?Q?zuR3vBrS5l5Cv5UMPVTSKDAqfQsYKJ/UH4ARmo09YIbDrLFpWYGkmc5vit9g?=
 =?us-ascii?Q?PSKJWyHrQ5HoMCIgJh0u4cOwBAzRhsBNsQl+iqodtArP/RkjjsZU8QArbdqd?=
 =?us-ascii?Q?msgVJIw8YZSIG4ZvuK/t2iFIK0+B7+rKeJBe/TBw+/RqqLDMkZj6tJ5mbVyQ?=
 =?us-ascii?Q?UYIwJe2KjhcKwpKmHxAw3powkc7JitDMOawY65QoWvYVAjUaM+kUiRykyvS+?=
 =?us-ascii?Q?GNcBCHYDJF7duwHwZH7F3zRDcC4bHi57vyNS9YkyuN8blPu5F0XElBSMFrvL?=
 =?us-ascii?Q?WonDW8VIoUl1hoCIk6DSxtOOHqKybAncGzpGiDFOCJZt5be+QA7zwplg/8GI?=
 =?us-ascii?Q?QAQ191wZz5jit9jaf3O1dpUVFEZ9my7TtLGk0SA7VNsLnjYMshEK0fF6ZMav?=
 =?us-ascii?Q?q86cc1GyJSIaWYR6j5UdxNP2DtPhoWnvY/+ROPld947KV1By2ZOSBxuV8sFS?=
 =?us-ascii?Q?LyMR981vHTci//+2e11rCj7zMEggfUdHhLjs7r1mPc9mgVakXkZHHMJjMAv3?=
 =?us-ascii?Q?ocvRHJAYd9G5p02ct8cjVwnWyXuZw1n6VRj9WC3ZMVsJjMWlI6brSWgSyQoF?=
 =?us-ascii?Q?NZCRKVu2TvW19i3WxhlxRkgiVnwxJj91kcxZH4NEGv2NMBRmZ5s2YaQ2+RP6?=
 =?us-ascii?Q?0v4Y7FjFah635ghRFFdtfIfiTEBpGbCRsl0Oultz1kpoMvc9xKjfmhatEi+h?=
 =?us-ascii?Q?ALala/q58uBcxq5kIBibVhgLGAoUju6m9FDg46Rf4a4+RvbuZb/+Xbhyj078?=
 =?us-ascii?Q?893STAd9EtOLJLGTWjJ17NRz1tcB0KFbscKz7+Fphd8p6jPZ5Y3qU9ritQH1?=
 =?us-ascii?Q?h1tD/khjn+TYM+nv1aHccUWE3e5jipdhvIgbQ6ffHoh2yRHnpQnlOnxlS+H5?=
 =?us-ascii?Q?kaKM0KeeDtx3X3070R18eT746zgSS/Ol6+hV91MvSZBex+wPaOBqNkbWeuGu?=
 =?us-ascii?Q?CFrLHMwxAMUsihFPAWlpPjpAAHHYgFV4AmJP02PW7A/V6OhhlTTC+uRJ+yz/?=
 =?us-ascii?Q?NtwDgLvbdmhPRAYJqugwCtjKfIB+u5GlJXt88D88a1Yv/5CPJ/aWH+/301mN?=
 =?us-ascii?Q?KszYFS+AQPiXlAwzDiEezmk5WherlpqVVD51sX7AGJgubevyuGkuA8/5GMEu?=
 =?us-ascii?Q?H7aaNH+H6rfAk/UAVXaKvvk/xA39l349H/UngVOkZskiRhzzoIIhc0mO6mDz?=
 =?us-ascii?Q?gi3Om8Gu2pU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?SWGRzDC+FFLFwQEpOhMnHeXYj3bRGqvtxAL7zyQxTrC+oYeY1b0ElNWnaroL?=
 =?us-ascii?Q?mBHl4FnJs2bZ0/bkfjf7P06nKq1DuEspRyp09TSVJJ1M5kWOdaGPO9BoP6cE?=
 =?us-ascii?Q?UngC5uD1ueBRzKtNo2ydVliF6cc8Vc2DYsJ/Px86E6xeJE7nCzXG2/z7IYsb?=
 =?us-ascii?Q?tFYnwju+fsr2XgLPBM9LbYnpijY83wWe2XI4sJSTzIvBDQmZo90MOIrfPvMI?=
 =?us-ascii?Q?GPqshr/EISrKJtkLBhtZjTCCFV1tXmBPQAKpoqVdYfi2C92lSJWcZDlNvYgp?=
 =?us-ascii?Q?WsJAVIwlRYb1OOASbLJXJkp18LqNHZZoi9V/eOTDM1an6eS6xcXCl+y99oJ2?=
 =?us-ascii?Q?8vOfUrb89BixgQfx7AkEmKv7VPrEthgF3Ef7dk24Ii3AbhuSzmxq105oqZPD?=
 =?us-ascii?Q?FayISTA8P/QFnPeF5TECOl2jOOX9ms5gXz8cRF+aAD2sCa2NGpum5+mRfW4y?=
 =?us-ascii?Q?tx/hZjD05mUFpcVYVA6tSCoVZ5rKh9rfIqCrSuwR/iQ2yHaDxPvsK2/uOIxL?=
 =?us-ascii?Q?SaxS4bP8sWsqIR0GVf6MMq1++A99ab7dJBSNSl50w5NXseCTRBOFWMg1JqpE?=
 =?us-ascii?Q?e8QCble2YkCcrft2ONNvn92CR/IBa9Akf3y6UTUlepeZvniuxFXTKq3giRiK?=
 =?us-ascii?Q?sMKJHKZcLvJu9alDYSeqfEhsSGr1w2pmPpJubP6qT9O1rMLDL+IiMR8w5YZN?=
 =?us-ascii?Q?kSsdYdveoo1lnkHkSaxtKgykyP+6yzpIT0oRUr/P0k51FS4ujoFTURZad3Pb?=
 =?us-ascii?Q?6Cg9Q0YX9INtaZIZDgeJL9vt+GWAnALecrpouvsmy/cPqGmW6PSfRr83DjTz?=
 =?us-ascii?Q?KrIHIHpuCcDu9WxojmKGFDltS61Xy33RDowkDnp7xq+l/kbzM7wNcHWi/uJI?=
 =?us-ascii?Q?XgyAM70Q4/B/waXoSmyMwZcnqW8StosssunJ2crYzEoBdOazKsBbXr3xwi5n?=
 =?us-ascii?Q?mvJbanJwAAr4oJeoLMO/1s7vXqUUIHPKEH5x0cg94w7unYSaMFOlc6qW2pQW?=
 =?us-ascii?Q?df2JFzi7YDPS0AOc51pk0IuhFbzVKWhOar90bIIDFZrLymt7CJ4Ds7+KMFIo?=
 =?us-ascii?Q?ABRr5tGoGf7f+8nIa+nD/ptmU+4WeoY6i98oeM35Zx9L5mceo4biKWDUW6KW?=
 =?us-ascii?Q?6T9Oo8Pic6aKPBjBa1JXdq9IsUULEZManqWCZjUYMJH04JDbCfkIpb1bzJqJ?=
 =?us-ascii?Q?te22d6vIH3Um27x7PChmxIcDqBogkzU1Ylod2RAV4ST/FV6eVOKenT9ni425?=
 =?us-ascii?Q?VHBGQ1uwwkTZoJnsiAaMF0I9akxCPzxS8CPTGLJ9c4V5TZHzmrcbqpnR0ntp?=
 =?us-ascii?Q?Y5wd2iVWZVqvniTXZZBI/sxUtwUgK26CW2XfNBaabwPCEuAKm/28z+54SnWR?=
 =?us-ascii?Q?7cU1ecojyTtKjPZSs/qWgMU7oq+dBDtKXtxP4MWqTXXfcaJgB6W7y7ZtOyn1?=
 =?us-ascii?Q?rBenrXJZ09H+8StFZS9HpyNn6e788UPcCrZucewKY63NLT7Lb/uj56U4jNKC?=
 =?us-ascii?Q?68q8pvZUmDtjaVi9kbAm6FLTgyIAwGkB+dSSSdcgEraSd1BASEpNVGO2LYf6?=
 =?us-ascii?Q?6FvHtbHPNLJy9RoNiSwxRz0tg0wWd88KsRqkOwHXwB8ayiKRS4s3DTnVapQR?=
 =?us-ascii?Q?Qw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: x9JUtJoUqEDI2FJ/cTKKOiMuU1ChK29OlvIoWihoEnUP8/GyPV1TF0IDdrnHU641L+was9O59FJ2CrSVlo97+RVHP6bQdEfdvsw7g8qqFrdkho+oKjMohBSOiuSuCtgv/A9I797OjJdXd027D6H2cOGkn91zctO4u8OUlitij4kwX2cdNPOEjQk1eCgwUqaO93c8VwckeR3fJvR3GxdHmTzsuQ/+dF+xTpW8pXaSXVja/XjeV4AWOURvG8gR+TI4ybruxFGZODMfF9EaDynzbnobfOXgzu2w48Z+/1EmKteoM0wFW8Sf83jgJH1I/R08TKfdmED3FNE24fqW13oeG82YGMLh3ah5VgUFdQpCewkEUNeYNVuEpxdxvbTdtnn+c70faiQ6RdaEr20JI/ko62/fxOboiaj67r5MWyzlXXENBbMppRhCDIg0NEmbqeWRfZ2S/hmbHIkwOUHhssVFNaMV/4uW6kbev4tpaGv2ITVl62lyZ3Xdu5/3VBskbwfkX/0k+3g3IwI+eU/9gZrL/Zb+XhDkb0ZVya9fZWY4AjuViFdHlVPKHzQMwMZAPOCwHskn1bBPyKD6iCt2YbS9mmdjunAOc+JsfKAUdU2un5U=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 097ccb31-adda-4479-90f3-08ddeec87a1b
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 11:11:36.7753
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: FZvmJ+NDJoteXYzZMfNTZNTQlcYP9tIbldcwnEsjoUlR3DPsT5E/gfBY/1E8E8F4g8W7KWrIui7ZcttEkiOgYc4+fNR0iDluEOvOibEIqqI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6588
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 suspectscore=0
 mlxscore=0 adultscore=0 bulkscore=0 malwarescore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080113
X-Proofpoint-ORIG-GUID: nKFGd1X3n5saloJ_nqdHoji6ovMgfWna
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDExMiBTYWx0ZWRfX4p5uW7hd/ViC
 7n7ZE7j+T5GJCVyUqYzEZ6Ip74jKnEsnGqe3eeFaE2xv2r2M4FBi0QnPgjetAmpJeGC70eJN3pF
 DebpZD5Dhkn1VurkTM7nl/DEYJSz8FoNSS68xSeBVVPYN2IjFGkUr4AWlWAJiUQvPli/eBXfJRx
 UPhcGfugqd2T5ECfl0cikkkAGTDZAwnuqav1m/ENm3/syYtUi7Aax2o9BbAuZHmdUPU1M9tNlli
 Mdj+5X/4OllWX7Tr2iBamOpJBj5GyRzprmhLBdcy4SIGwTZBl8WFhItTwylQWwsZldjydFTrcOu
 UGK5NQRiGQ6HVxiJWE/+QDiVqMrRjzgTYT5yZ0w4h8OvV4apJdvzkz4FT44F5Szeqh3qx9EbuDl
 18L4oS3xaHlCTNhRQIkRqP0SHlbcQw==
X-Authority-Analysis: v=2.4 cv=MIFgmNZl c=1 sm=1 tr=0 ts=68beb9ed b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=8VW42N-dlZBHzYBeMqgA:9 cc=ntf
 awl=host:13602
X-Proofpoint-GUID: nKFGd1X3n5saloJ_nqdHoji6ovMgfWna
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=mljG+8VA;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=QlJyRUnY;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

We introduce the io_remap*() equivalents of remap_pfn_range_prepare() and
remap_pfn_range_complete() to allow for I/O remapping utilising
f_op->mmap_prepare and f_op->mmap_complete hooks.

We have to make some architecture-specific changes for those architectures
which define customised handlers.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 arch/csky/include/asm/pgtable.h     |  5 +++++
 arch/mips/alchemy/common/setup.c    | 28 +++++++++++++++++++++++++---
 arch/mips/include/asm/pgtable.h     | 10 ++++++++++
 arch/sparc/include/asm/pgtable_32.h | 29 +++++++++++++++++++++++++----
 arch/sparc/include/asm/pgtable_64.h | 29 +++++++++++++++++++++++++----
 include/linux/mm.h                  | 18 ++++++++++++++++++
 6 files changed, 108 insertions(+), 11 deletions(-)

diff --git a/arch/csky/include/asm/pgtable.h b/arch/csky/include/asm/pgtable.h
index 5a394be09c35..c83505839a06 100644
--- a/arch/csky/include/asm/pgtable.h
+++ b/arch/csky/include/asm/pgtable.h
@@ -266,4 +266,9 @@ void update_mmu_cache_range(struct vm_fault *vmf, struct vm_area_struct *vma,
 #define io_remap_pfn_range(vma, vaddr, pfn, size, prot) \
 	remap_pfn_range(vma, vaddr, pfn, size, prot)
 
+/* default io_remap_pfn_range_prepare can be used. */
+
+#define io_remap_pfn_range_complete(vma, addr, pfn, size, prot) \
+	remap_pfn_range_complete(vma, addr, pfn, size, prot)
+
 #endif /* __ASM_CSKY_PGTABLE_H */
diff --git a/arch/mips/alchemy/common/setup.c b/arch/mips/alchemy/common/setup.c
index a7a6d31a7a41..a4ab02776994 100644
--- a/arch/mips/alchemy/common/setup.c
+++ b/arch/mips/alchemy/common/setup.c
@@ -94,12 +94,34 @@ phys_addr_t fixup_bigphys_addr(phys_addr_t phys_addr, phys_addr_t size)
 	return phys_addr;
 }
 
-int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
-		unsigned long pfn, unsigned long size, pgprot_t prot)
+static unsigned long calc_pfn(unsigned long pfn, unsigned long size)
 {
 	phys_addr_t phys_addr = fixup_bigphys_addr(pfn << PAGE_SHIFT, size);
 
-	return remap_pfn_range(vma, vaddr, phys_addr >> PAGE_SHIFT, size, prot);
+	return phys_addr >> PAGE_SHIFT;
+}
+
+int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
+		unsigned long pfn, unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range(vma, vaddr, calc_pfn(pfn, size), size, prot);
 }
 EXPORT_SYMBOL(io_remap_pfn_range);
+
+void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+			       unsigned long size)
+{
+	remap_pfn_range_prepare(desc, calc_pfn(pfn, size));
+}
+EXPORT_SYMBOL(io_remap_pfn_range_prepare);
+
+int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot)
+{
+	return remap_pfn_range_complete(vma, addr, calc_pfn(pfn, size),
+			size, prot);
+}
+EXPORT_SYMBOL(io_remap_pfn_range_complete);
+
 #endif /* CONFIG_MIPS_FIXUP_BIGPHYS_ADDR */
diff --git a/arch/mips/include/asm/pgtable.h b/arch/mips/include/asm/pgtable.h
index ae73ecf4c41a..6a8964f55a31 100644
--- a/arch/mips/include/asm/pgtable.h
+++ b/arch/mips/include/asm/pgtable.h
@@ -607,6 +607,16 @@ phys_addr_t fixup_bigphys_addr(phys_addr_t addr, phys_addr_t size);
 int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
 		unsigned long pfn, unsigned long size, pgprot_t prot);
 #define io_remap_pfn_range io_remap_pfn_range
+
+void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+		unsigned long size);
+#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
+
+int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot);
+#define io_remap_pfn_range_complete io_remap_pfn_range_complete
+
 #else
 #define fixup_bigphys_addr(addr, size)	(addr)
 #endif /* CONFIG_MIPS_FIXUP_BIGPHYS_ADDR */
diff --git a/arch/sparc/include/asm/pgtable_32.h b/arch/sparc/include/asm/pgtable_32.h
index 7c199c003ffe..cfd764afc107 100644
--- a/arch/sparc/include/asm/pgtable_32.h
+++ b/arch/sparc/include/asm/pgtable_32.h
@@ -398,9 +398,7 @@ __get_iospace (unsigned long addr)
 int remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long,
 		    unsigned long, pgprot_t);
 
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long from, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+static inline unsigned long calc_io_remap_pfn(unsigned long pfn)
 {
 	unsigned long long offset, space, phys_base;
 
@@ -408,10 +406,33 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 	space = GET_IOSPACE(pfn);
 	phys_base = offset | (space << 32ULL);
 
-	return remap_pfn_range(vma, from, phys_base >> PAGE_SHIFT, size, prot);
+	return phys_base >> PAGE_SHIFT;
+}
+
+static inline int io_remap_pfn_range(struct vm_area_struct *vma,
+				     unsigned long from, unsigned long pfn,
+				     unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range(vma, from, calc_io_remap_pfn(pfn), size, prot);
 }
 #define io_remap_pfn_range io_remap_pfn_range
 
+static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+		unsigned long size)
+{
+	remap_pfn_range_prepare(desc, calc_io_remap_pfn(pfn));
+}
+#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
+
+static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot)
+{
+	return remap_pfn_range_complete(vma, addr, calc_io_remap_pfn(pfn),
+			size, prot);
+}
+#define io_remap_pfn_range_complete io_remap_pfn_range_complete
+
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags(__vma, __address, __ptep, __entry, __dirty) \
 ({									  \
diff --git a/arch/sparc/include/asm/pgtable_64.h b/arch/sparc/include/asm/pgtable_64.h
index 669cd02469a1..b8000ce4b59f 100644
--- a/arch/sparc/include/asm/pgtable_64.h
+++ b/arch/sparc/include/asm/pgtable_64.h
@@ -1084,9 +1084,7 @@ static inline int arch_unmap_one(struct mm_struct *mm,
 	return 0;
 }
 
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long from, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+static inline unsigned long calc_io_remap_pfn(unsigned long pfn)
 {
 	unsigned long offset = GET_PFN(pfn) << PAGE_SHIFT;
 	int space = GET_IOSPACE(pfn);
@@ -1094,10 +1092,33 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 
 	phys_base = offset | (((unsigned long) space) << 32UL);
 
-	return remap_pfn_range(vma, from, phys_base >> PAGE_SHIFT, size, prot);
+	return phys_base >> PAGE_SHIFT;
+}
+
+static inline int io_remap_pfn_range(struct vm_area_struct *vma,
+				     unsigned long from, unsigned long pfn,
+				     unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range(vma, from, calc_io_remap_pfn(pfn), size, prot);
 }
 #define io_remap_pfn_range io_remap_pfn_range
 
+static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+	unsigned long size)
+{
+	return remap_pfn_range_prepare(desc, calc_io_remap_pfn(pfn));
+}
+#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
+
+static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot)
+{
+	return remap_pfn_range_complete(vma, addr, calc_io_remap_pfn(pfn),
+					size, prot);
+}
+#define io_remap_pfn_range_complete io_remap_pfn_range_complete
+
 static inline unsigned long __untagged_addr(unsigned long start)
 {
 	if (adi_capable()) {
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 0f59bf14cac3..d96840262498 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3673,6 +3673,24 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 }
 #endif
 
+#ifndef io_remap_pfn_range_prepare
+static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
+	unsigned long size)
+{
+	return remap_pfn_range_prepare(desc, pfn);
+}
+#endif
+
+#ifndef io_remap_pfn_range_complete
+static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long pfn, unsigned long size,
+		pgprot_t prot)
+{
+	return remap_pfn_range_complete(vma, addr, pfn, size,
+			pgprot_decrypted(prot));
+}
+#endif
+
 static inline vm_fault_t vmf_error(int err)
 {
 	if (err == -ENOMEM)
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/68b2571de694e883b8ffd6cdc0448849ae67b683.1757329751.git.lorenzo.stoakes%40oracle.com.
