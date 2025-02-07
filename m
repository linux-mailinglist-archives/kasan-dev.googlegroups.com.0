Return-Path: <kasan-dev+bncBCMMDDFSWYCBBWXSS26QMGQEJ5OMCIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D07EDA2BC8E
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2025 08:42:21 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6e42d792056sf34822226d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 23:42:21 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738914139; x=1739518939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6XU2VwvwsN4XVm7rnN4zXXpJbnN5bhMdoneq4Ltbfao=;
        b=Ay1bfggDB2bur/RrB84NXkyG9KldJxdko+DBFPhz2u2RJWU6rmV8+H9QcE1NzWLbMa
         SBJDdRB6QNa9zYuYxHoa+sDesH2Gp4etQ6Od0zuajLCdV6gdJdYqfZOzyUOc4SmNBW9r
         MjXBk5B9scymnu3gY6VkB/0yiBhFAvbPSZbagh0TPt39EHPcx5FvxnWJfcZYoHUOlUrC
         oXhCz8kEn4hyQ+pc2gIQH2PKU4efCgFPTpf7zwIUuGp9apgB4BH7BUfJk4m+KPcDjY2R
         YKDvCPf8UQK4Pf73Erni29w2HYivlBEclHM4Jg+/xfJDOhPiW6abv+x42ffk+z1vRwUU
         4n1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738914139; x=1739518939;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6XU2VwvwsN4XVm7rnN4zXXpJbnN5bhMdoneq4Ltbfao=;
        b=JTZkndMUijpZBCC/8y1RU4+yK9eEOt+e6t6bKoskmIfE30v96KxoMwZXx8pVHZbr0X
         qIVmONXDnCLiLUyi765g4iZDlWadDzuRdzwzd5rsdUd85Xll44K5AEEjd5gWzxk682Dk
         wBfIH0eyIGuHQmWIqPOJIJrEp4ijlexrbP3tVApZNvBtDSkaQ4N5WtyzSlF7sLs/jf7o
         3/lnC8pwDXMx9Kcjn/PYxzyXgjcB4ERaQvAt+QV7ng+ry1Z7YdEt0TZtGgY4LPZAn1I8
         Fjry8J0pkO0uPfwYUArFHzB4khm3uw/Hr2c5Or1pBsmM0ZA/qr2Ch/v28Zb5AC+m3p/g
         aiIg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUgsN44azGN16Dxk2MNscnMDCeC731aZgzSyaveqnrT3oQJZW19B23My1CsOx3rMFoL9pATlw==@lfdr.de
X-Gm-Message-State: AOJu0YyDTyFWq8ImCcwN05sBAStUmquzsMSWZD79OczjYB4XTc61/Lt8
	sMykpw7JNzOmTxqdqH784DZOvssSm2kai4JKEEIDZfWVJ9Hi94Up
X-Google-Smtp-Source: AGHT+IGDUm+RkX1H41ZcwVSXR15tI9BqH3r0B4SB/DoQM5aj4LcHMRhtb1C1dL/DyT+BrSRtLC1Zug==
X-Received: by 2002:ad4:5aea:0:b0:6e4:49aa:9721 with SMTP id 6a1803df08f44-6e449aa9c57mr13571946d6.6.1738914139142;
        Thu, 06 Feb 2025 23:42:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2cce:b0:6e4:3edf:605b with SMTP id
 6a1803df08f44-6e43edf617els21219056d6.1.-pod-prod-00-us; Thu, 06 Feb 2025
 23:42:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU2lIwOvconm20FOvmF0euw1XUuR3+jGyJzPAduP0B16AEBsNHBhjdJXOTQvTXqWNrvc2nNEQd36EI=@googlegroups.com
X-Received: by 2002:a05:6122:6d02:b0:517:e7b7:d04b with SMTP id 71dfb90a1353d-51f1c2b9f65mr4012184e0c.5.1738914138213;
        Thu, 06 Feb 2025 23:42:18 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.8])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-51f227429c1si137121e0c.2.2025.02.06.23.42.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 06 Feb 2025 23:42:18 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.8 as permitted sender) client-ip=192.198.163.8;
X-CSE-ConnectionGUID: su8Ga4uCQOa5EiCXxiW9Sg==
X-CSE-MsgGUID: JZyaw5LVR5GoLD7SE9Cncw==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="57084841"
X-IronPort-AV: E=Sophos;i="6.13,266,1732608000"; 
   d="scan'208";a="57084841"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by fmvoesa102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Feb 2025 23:42:17 -0800
X-CSE-ConnectionGUID: X467ugz4QWe+aqoZKKaHpg==
X-CSE-MsgGUID: DufqB3bUS2Kfe7ptw/hq+g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="111892963"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orviesa007.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 06 Feb 2025 23:42:16 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Thu, 6 Feb 2025 23:42:15 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Thu, 6 Feb 2025 23:42:15 -0800
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.175)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Thu, 6 Feb 2025 23:42:15 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BU/M+HWd2DPXu+q17NHf1qe0X1DQVWWvmvw/5ukH68XtjxTBcAmAYRksd1rZ3Q/fy9zaZh4QcdmwLMXQYMpkcPmHcaHxzZwHSHxfK+EsSYyH7R2NL4KK2H/8kQUgJcOq4dukyy/GNw8ZmR7XYFlnj1CKZ3KS65JpLdRKLB/8U5L0OjpcKeYY0wDkJLTsw1NlNi8aeJ5ZPgmrJ0EOKafB9y4PgcSby+BoGF1Ip8y+Gc1O1JzS1PT2f1wMVY4Oj+YGnXLtC7FLWSKA+8SSadTscBY7xnf0cv56LSbniuqUDfM9OYVqQw4mxZViC++z3th8Pvr9OiRG/moBBph0rI1f6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ORYhLmeD8sHQuoVL/ckajNY0fBr/hDb8W/kZemV8M4w=;
 b=KLfr/aKqUQDuymoYlrwyvi6WxF1nX/y0TDSN8OWtFiTi0t+/iVjK5841EsXrrtn4KFq2piDo2kkWIBTUC6GKquOjSLnWhICKTaP3c7zk9Gtssb0RLIYcF2+FWXxfzFii1tWw9sfRM81L/ka/Xe06QLaH/zYUWKf3+1xiQ4/oQubHhB+hFtgviVi9H91qb0i/vxsD5mJ++oqFH8cfGZoiwz/gM9xOrIcD3b270zq1pjqbYbxkFUEJ/zgvBGil7GxsF8EK6pCQK5ArtGORYcbQCjvMmhnzXc6randOdkn4OlGY1WzqYnxsqlNxuDcwq+y93ti03RKn3NaePHmAx7ERhw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by CYXPR11MB8711.namprd11.prod.outlook.com (2603:10b6:930:d7::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8422.11; Fri, 7 Feb
 2025 07:41:46 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8422.012; Fri, 7 Feb 2025
 07:41:46 +0000
Date: Fri, 7 Feb 2025 08:41:35 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Dave Hansen <dave.hansen@intel.com>, "Christoph Lameter (Ampere)"
	<cl@gentwo.org>, <andreyknvl@gmail.com>
CC: Jessica Clarke <jrtc27@jrtc27.com>, <luto@kernel.org>, <xin@zytor.com>,
	<kirill.shutemov@linux.intel.com>, <palmer@dabbelt.com>, <tj@kernel.org>,
	<brgerst@gmail.com>, <ardb@kernel.org>, <dave.hansen@linux.intel.com>,
	<jgross@suse.com>, <will@kernel.org>, <akpm@linux-foundation.org>,
	<arnd@arndb.de>, <corbet@lwn.net>, <dvyukov@google.com>,
	<richard.weiyang@gmail.com>, <ytcoode@gmail.com>, <tglx@linutronix.de>,
	<hpa@zytor.com>, <seanjc@google.com>, <paul.walmsley@sifive.com>,
	<aou@eecs.berkeley.edu>, <justinstitt@google.com>, <jason.andryuk@amd.com>,
	<glider@google.com>, <ubizjak@gmail.com>, <jannh@google.com>,
	<bhe@redhat.com>, <vincenzo.frascino@arm.com>, <rafael.j.wysocki@intel.com>,
	<ndesaulniers@google.com>, <mingo@redhat.com>, <catalin.marinas@arm.com>,
	<junichi.nomura@nec.com>, <nathan@kernel.org>, <ryabinin.a.a@gmail.com>,
	<dennis@kernel.org>, <bp@alien8.de>, <kevinloughlin@google.com>,
	<morbo@google.com>, <dan.j.williams@intel.com>,
	<julian.stecklina@cyberus-technology.de>, <peterz@infradead.org>,
	<kees@kernel.org>, <kasan-dev@googlegroups.com>, <x86@kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-riscv@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>, <llvm@lists.linux.dev>,
	<linux-doc@vger.kernel.org>, "Shutemov, Kirill" <kirill.shutemov@intel.com>
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode
 for x86
Message-ID: <pytojmt43uaunsqexyeo7anmjimzbqzec3nqla3hyzne7ttjvn@lwzrjoq3yx6w>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
 <F974BA79-80D8-4414-9DFD-1EEF9395143C@jrtc27.com>
 <72837fcd-97a8-c213-0098-c8f308c3415d@gentwo.org>
 <29A74A26-E922-4A4F-9B4A-8DB0336B99DF@jrtc27.com>
 <94f81328-a135-b99b-7f73-43fb77bd7292@gentwo.org>
 <239de2b9-0787-4105-a481-418dbd4d861e@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <239de2b9-0787-4105-a481-418dbd4d861e@intel.com>
X-ClientProxiedBy: DUZP191CA0071.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:10:4fa::11) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|CYXPR11MB8711:EE_
X-MS-Office365-Filtering-Correlation-Id: f030df3a-e3f3-4472-d299-08dd474adf6e
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?z4EZDStKg3rhZZPrFQWcH/WXFUdYK//JSCde/PdAChKLrw3flLBrRHmurD?=
 =?iso-8859-1?Q?0ngALskjElVbUrT0YNVabGgZRJ3qfWzs2cWAizpsKKik6rN98fMQh6021c?=
 =?iso-8859-1?Q?A4dODajS7nYhqiPQqFsFUhsHVVw/hlR1Lam8MOuQyal6pCVSWN31tO2Ngz?=
 =?iso-8859-1?Q?qaPxKcwPkpduBNmvOlXEp8VGqSpbp+rR2g5Foyw8a5E7Xnz42p6HW3J33N?=
 =?iso-8859-1?Q?L1L9HZeSaBknY9gwN48lMnDo8OVIfe8QQOwdbLIbQdqM2evNGhim085BJc?=
 =?iso-8859-1?Q?2UVCGO9qO6hicOe6Fksuns6xYl+BVGmzmryqZDu9dDyUP0rl5mRkAEGZZ5?=
 =?iso-8859-1?Q?ZAu2UOvNPGyNfxZSCH+A3q2GlvwEbkxzNP4DAWJFwV+whFU86cVN4Zwexw?=
 =?iso-8859-1?Q?xgStJ8osFgH5FoLlmpFfGFrzi55fo0cjt3/l8I469by8mRvvuF8x70RtRn?=
 =?iso-8859-1?Q?ixFX6ESCwlFcs4xSQnpovFnRbgU408J8wNjYOPNzmIgdH7lF5XrQ4PBOAa?=
 =?iso-8859-1?Q?WlJm5zts8v0rIG5QwlQjh+5VVfd+bAVs2Gl2LqHZ3Ih61OyC1BZIPktdfe?=
 =?iso-8859-1?Q?Wz3iLiTm0drnu2BTlC4HSsSTplkqjZdVlo1b8wEX5idd1lipM0zy7n3Mer?=
 =?iso-8859-1?Q?5fG3XtEbUiNbehPYE+o9W3GopPIYOFNfAm3NKFhRKcw4iaqhXqiZ1xPiXv?=
 =?iso-8859-1?Q?vIS90/u2nUj4QoDEgi9oGrHH890CV+J3mwpMTe8DNrdNQZGvtTJzWPl9b5?=
 =?iso-8859-1?Q?ab5T4soHBNMSCY4t8HpNrqyTExNzMg7CF1PfbkmPjPZd4KLv/hbTofzctf?=
 =?iso-8859-1?Q?CMSTeVp58k+5nwPZF/IG8Rq6GvnrRcrDDRmi2+Pz8Sq5DannGt94ufzfNZ?=
 =?iso-8859-1?Q?c9mKuZZ5OANmiFwtC/20HwgMXE5MlkljWzbpU40S+fPf6UVelJTkqsAMOx?=
 =?iso-8859-1?Q?MmZ2Yu31hjVMcjMFIoB+DmKo6uYCrv63Psrz+qi5LmNUpv+dNbk4HDBXnO?=
 =?iso-8859-1?Q?PWYNfY9xiaZwE5COhHC21GP4lxne7bngY2jbvl950yrEE64Rc8u+zQhYGR?=
 =?iso-8859-1?Q?T7yk8EVUAfoy6sNHeqC5dGY+4q6QKi+v5/DmwlT8ppkPq7LuISGTuPydDb?=
 =?iso-8859-1?Q?ynRA9kYegZF+bUInGbSWAMYiJTpm/tb10FiHjdrymoFCMDavpJQCFFMIo2?=
 =?iso-8859-1?Q?BHrluXueSkjxH0FoI8r9I5xI4N/V9j+tQ9KanFtjR2vn9ggyIy7aE7dwLG?=
 =?iso-8859-1?Q?l+CHh9f+8EdwdjeXaA/YOrVqKeqSDbqCw37DOpkRfB1fq0sAp9d4rLiqvS?=
 =?iso-8859-1?Q?BtxjcXJEbuFiy/nAr6byKXEr09rTD8GBO7kdGhGktlPUHktc4Ty2J0gadt?=
 =?iso-8859-1?Q?qhCUbotUqu7kkaEl/3l+fvVay4oPN8gg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?0i1oZF91tc9niHk4iFJC8swp2LuSnVxOKnk8nPlHCimX4Z4ahDcXh7CmNn?=
 =?iso-8859-1?Q?TLVyhHOkYViKIDERTYCgI0WMqzwFBR2L3Z46i9pzJtfrGo3uOtQrbyW3+h?=
 =?iso-8859-1?Q?7xocn0h+R9gvQnGn1xxx1QJwessSqxZ1O2Okr+5YzZCjgYOtWWrUsaFCie?=
 =?iso-8859-1?Q?zHPTM6w/TE9iZk/XP6vcKLWGuZFLqup+EwRCA+dKdwj+xXjGx9iyjOcSSC?=
 =?iso-8859-1?Q?8GbtZmwor3tkT6krthJT37qohrgqU1gX789FTMsnUdqC6tKS/qGeKAfc9C?=
 =?iso-8859-1?Q?jEpoFt6bNBXQBlTepcGGgNAdrMrxHC44S4etcKPTqCsvQW5yzpPHZdWApX?=
 =?iso-8859-1?Q?VYQmuwZF3HE0wCBHqv5qFLM9rwPTNPm3h/Sd6VeTBvpuq846H0t5D5Ipbd?=
 =?iso-8859-1?Q?7buqAYlWCT8iJwgSdltzfqxzDHxD5VGpV1wMJxRFrDTLWLFy6GsaASEmWH?=
 =?iso-8859-1?Q?reB9uF4N8vSGb3iihtFzEo7Kpz3Pna/qcYe/bs6x5SBgJYP2ZIOBPrcTm4?=
 =?iso-8859-1?Q?H+ME6gJjdnCGFZVEnjsRRFaWNwZL7XBPCx2U2I/7VcnuSFxxtP3YMQ6XSt?=
 =?iso-8859-1?Q?Xs1Oq5xZnlTW6FGUuA2a324DI6KCm2cTgx4x5Q8ichf8GlXJjVbkjETWf4?=
 =?iso-8859-1?Q?2NBMDLxpHysZrSYssXybu09JXMR50nqNARX57WkrsSpPqFUwdOfXnaj4VM?=
 =?iso-8859-1?Q?oFv0FVFKkYP2leiO0qse4mdY1DDXShQPcRLYknmSbyuH+GizmZFA6ha3MB?=
 =?iso-8859-1?Q?peb1LYe+xPi+p28elVk49OfZXArhl1zLMx4qh1E84ft/YvB/AdG8+jwCYi?=
 =?iso-8859-1?Q?wgMeX6cJ0uZHcaNTHU2aPdYd92y+a39KV/bmIaaFal6+Wa2WW/EkJRKV7q?=
 =?iso-8859-1?Q?tBv2T4cDyzZFXtKRjmxHpPj7JEJT0H+Rfs2AL1G8bdK+lmP+9OqGnDKLll?=
 =?iso-8859-1?Q?wjYhkgWmlBIY/CHdbAwGC93kUvHQqyfyal4h+Livr0g0KGDi+rDXWDgmvX?=
 =?iso-8859-1?Q?qDI8uubdiDhNsF+EIyepop9TNKTaG887sK3MnSPw1bvWm0Z3AwR95N6rJR?=
 =?iso-8859-1?Q?DysI/hHUW3CpgIHBLgOPZiK3uGVlX/Wa51AwQxgdNAxRqh8uBBlgV4pCmf?=
 =?iso-8859-1?Q?Vg51k6ea/9fjCRnRf0a/abHl1Ayxg2G/equtca4qax2hlQ4isEvn6kcaZB?=
 =?iso-8859-1?Q?r5jk8+zYVt86/oO6RWAgCfgc6pZmeLnx5gq99RU+is4Q1uXeLgVOcCfMup?=
 =?iso-8859-1?Q?NXj2qEL5+IW80aaH81dSi+fzztpDIsUoUmxt5Am/telWgiUcyPdAmiHQ7Q?=
 =?iso-8859-1?Q?EBs77bM+f4bwXH2CPKtgVwQfFM5ZgbrAM+s42uxNldclLPcOgRWBsduTbZ?=
 =?iso-8859-1?Q?PwsBZg8jFDGzDgcd5C6WyS4HMxdrW2G5popiiPWPovTf4pk6Ma2WAwGrvk?=
 =?iso-8859-1?Q?bRU+p2f+jNSGCnkgHRVG+VOCl6PEZ8wRbi0DevJnW8sfIHsKMyK8NOYWlv?=
 =?iso-8859-1?Q?+DdcYLG+TMmZhggnr8dxmP7hYqiioCxD1PEleJTH2j2WO1WqrOiF4jD5jA?=
 =?iso-8859-1?Q?MTMSi7cBLHYJwHYo1M6+cN34JiDi+Cqtrbi1+NAtkOFiHvvaLWqWMk0WNE?=
 =?iso-8859-1?Q?Cwgf0dgcWG2N+dK07X2XwB9Cc90VgcmmlmTITquPv9o4qE3+F/jD1FCDgK?=
 =?iso-8859-1?Q?gjYCh/eJj57jB6Xx3Aw=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: f030df3a-e3f3-4472-d299-08dd474adf6e
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Feb 2025 07:41:46.0531
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: FBe3sj+FGNemss3i+wDkdtUjL1er0swNtfrLvNpbSmfS8PibDAQWK1hF7nwqLdAUpzwHxE8FHQrRUWUEjQzyL8s754yyE0RTdykg984hNCc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CYXPR11MB8711
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=atbuPZyj;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.8 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 2025-02-06 at 13:41:29 -0800, Dave Hansen wrote:
>On 2/6/25 11:11, Christoph Lameter (Ampere) wrote:
>> I also see that KASAN_HW_TAGS exist but this means that the tags can onl=
y
>> be used with CONFIG_KASAN which is a kernel configuration for debug
>> purposes.
>>=20
>> What we are interested in is a *production* implementation with minimal
>> software overhead that will be the default on ARM64 if the appropriate
>> hardware is detected.=20
>
>Ahh, interesting. I'd assumed that once folks had in-hardware tag checks
>that they'd just turn on CONFIG_KASAN and be happy.  Guess not!
>
>> That in turn will hopefully allow other software instrumentation
>> that is currently used to keep small objects secure and in turn
>> creates overhead.
>OK, so KASAN as-is is too broad. Are you saying that the kernel
>_currently_ have "software instrumentation" like SLAB
>redzoning/poisoning and you'd like to see MTE used to replace those?

I share Andrey's opinion that in hardware KASAN mode (with MTE on arm64) af=
ter
disabling stacktraces (which in my tests in software tag-based mode took up=
 ~90%
of the allocation - small kmalloc() - time) and tweaking the bigger allocat=
ions
there doesn't seem to be anything more left in KASAN that'd be slowing thin=
gs
down.

Obviously this series deals with the tag-based mode which will suffer from =
all
the software instrumentation penalties to performance. So while it's still =
a
debugging feature at least it gains 2x-4x memory savings over the generic m=
ode
already present on x86.

>
>Are you just interested in small objects?  What counts as small?  I
>assume it's anything roughly <PAGE_SIZE.

Would disabling vmalloc instrumentation achieve something like this? That i=
s
tweakable during compilation.

>
>_______________________________________________
>linux-riscv mailing list
>linux-riscv@lists.infradead.org
>http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/p=
ytojmt43uaunsqexyeo7anmjimzbqzec3nqla3hyzne7ttjvn%40lwzrjoq3yx6w.
