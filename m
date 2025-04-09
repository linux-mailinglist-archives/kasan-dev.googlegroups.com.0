Return-Path: <kasan-dev+bncBCMMDDFSWYCBBQ6N3C7QMGQEIZJFRDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 81713A81EA4
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 09:50:29 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3d43d333855sf56603865ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 00:50:29 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744185028; x=1744789828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ax5DWfBnWd6FAJY0K2pwuuGInfL1gPYstpeQP5Xowb4=;
        b=l4LG0EuHKsqYJGv3NPaMNlIIvusG51FjsjeQ84AuskJ2lP5JS40oAnBxYyVzAA6fRg
         1jW7L9r0uDIJVnd3GH36cy78J1zHzOezBr9vqbf1/34smUr2GJyzWeAJl42IiRHXH84F
         5c8y+3rg+FxYzys0+nOsBbcP3pzGJ2afKVqzPgwN6yrxcWOT6qX7Di405oIwSX9hmQkT
         JG1qMUCXxDfA2noYN7FPtlhS9g2x8ZQi2mgNE8zSvBkRgn3uYUmJII/Szl5i7ycafAIb
         YyYaM8vm/OAitcxhectWqxDTDnLgx4+VqIPiLiJq8el+wzbph6xRcTX1w2saOg5b4KAE
         oQnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744185028; x=1744789828;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ax5DWfBnWd6FAJY0K2pwuuGInfL1gPYstpeQP5Xowb4=;
        b=GCBEGiAePw8szma5jmwyMKDkigl5p+fhqUDa3VWIRNEM5AufFjiFufZkPJ+6BUSrkE
         fQc0s9BEB5TS9FmTRQV/efJ1ztUADN9LlR+zAzZZQnPF6pqLnflmWcDpg07QhzjtIBfb
         7DbSFKO+VKasjxWxWhOJRsofpEnUKHTZXV/CdLCPLhYht5HJzH2jMwobfceCnZ5985/Z
         Xkwuc0JDufjMZF5oj/6re1EuFR+aXdLG9tAtF2F+ZwJ1aKXwCkHCJOkCyNKJVIYQ78jk
         spbRX89Suwbwv6RcWtTHUm9yah3JsZprC6JH9zarilwSNAwzknMGjXXW7hh8tk3b1An3
         aNrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiysA2+/0Imza4g0nGAb99wccg1FCkwneG7mWIv2WgZuC+anxoApiyjfz84SFuSbf9aqaHsQ==@lfdr.de
X-Gm-Message-State: AOJu0YxkHz21E7RET8q09TYEEjby0IQb1JS9zYnC/mLV35RhOlfMYX2L
	lhJO/pnyfX9pVCFXp/UmxzI761zJg4XT6McrRQmC11eyDECcYTlt
X-Google-Smtp-Source: AGHT+IEWTmJyv3HdyxnG08Fvo9SNQsIx8CG1MH3DvvNiiEBAEP9em5NutNyShM5b6uUCz13kGraJ1w==
X-Received: by 2002:a05:6e02:17c9:b0:3d1:966c:fc8c with SMTP id e9e14a558f8ab-3d77c2adf4fmr16302245ab.17.1744185027901;
        Wed, 09 Apr 2025 00:50:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIp5ePZx5Yv7hJY6psOoE2QHVJPMI6Of9gJry1I8Dq8ew==
Received: by 2002:a05:6e02:1566:b0:3d4:582a:acdd with SMTP id
 e9e14a558f8ab-3d6dc90487cls425765ab.0.-pod-prod-03-us; Wed, 09 Apr 2025
 00:50:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWB8pcFO1jBbTXvqMr+7v6nYyM4OHjS7f4wwEej4RVH8XC8T7J52y4uJr9PrHB5OlbdJG48hNXlupc=@googlegroups.com
X-Received: by 2002:a92:cd8c:0:b0:3d3:ff5c:287 with SMTP id e9e14a558f8ab-3d77c2ae095mr16032895ab.14.1744185027051;
        Wed, 09 Apr 2025 00:50:27 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.17])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d7dc56f86asi320105ab.3.2025.04.09.00.50.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 09 Apr 2025 00:50:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.17 as permitted sender) client-ip=198.175.65.17;
X-CSE-ConnectionGUID: /PsmmGPSQ0iusE016+70ng==
X-CSE-MsgGUID: /d2QRpD0TXuOy/5XGT6L1w==
X-IronPort-AV: E=McAfee;i="6700,10204,11397"; a="45659712"
X-IronPort-AV: E=Sophos;i="6.15,200,1739865600"; 
   d="scan'208";a="45659712"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by orvoesa109.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 00:50:25 -0700
X-CSE-ConnectionGUID: e5NN2Nq6RFO7+sn5ZdaFYA==
X-CSE-MsgGUID: SHcK+rOnQoO7ARKIKR9wjw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,200,1739865600"; 
   d="scan'208";a="128851267"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by fmviesa008.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 00:50:22 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Wed, 9 Apr 2025 00:50:21 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Wed, 9 Apr 2025 00:50:21 -0700
Received: from NAM04-DM6-obe.outbound.protection.outlook.com (104.47.73.49) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Wed, 9 Apr 2025 00:50:20 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=N1wEldIaY8yWMtEcDGnfk6nPTxOUfV7Z6I+S85yGvjT+NMHLF9DrkF3KfnQJ/I1Qh3pu0cm4U+KCg+p3qO82Ekaf1FsCJv3oYRcu0AmevAGyed9EQfuQZqlJGxwy5aM6orUQxPiiGR1qvsmL+3E2vYGh92U1KLKnD6fzd44I5KT+a7fpDzdU9mar445jI6Ls2MvFSSZw0XFbiPxC/T9UqTXN18ETe8ucGsZg+QIeZgtzx/P7Hy+rWKw/DCtxAm9QWc7+FmiYXcyxh/6b5xTpMFEerJ38kOiEv/VnV3nFWcR5xGP+bzkSkr/AZzJD3j9svcsO/kfYcWrBrSygZvP6gA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=VQcQR+Ry4MldQ0ybRESNJFC+qiaY57zFR93HhekL38Y=;
 b=R+R5VVuF8lL6S4h2QiXpV88ZGpWYUxyOWHw53EmLANxziexfbsQnXUJ2rFpularISbxb5Qmh7q4QusXltGaMx+GpbIPnEsSpLoVwZwSSiH2aAJeVXDSFLiIYm7WKxuTaVZ1BJSypew7hgdF8q9YrObZUUqpvKhWcrdEgoqoO0cO3gljWMBBJ7ilPvkJiIrPgQXrwd2Appx3sHSMARJ7W5S4zoqaaYFh6iEOJXM2J8cdFoDby3LZSZULNHn/6Dir3SJocl6xUp4/y/1nu1Q0HkXit/ainKfdHV5tlPO07+ICC0ksyLmBVso0dCb91tCkhMRtvxgZQsUfAcwwFm48iSw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by DM6PR11MB4626.namprd11.prod.outlook.com (2603:10b6:5:2a9::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8632.22; Wed, 9 Apr
 2025 07:49:51 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8606.029; Wed, 9 Apr 2025
 07:49:51 +0000
Date: Wed, 9 Apr 2025 09:49:39 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Dave Hansen <dave.hansen@intel.com>
CC: <hpa@zytor.com>, <hch@infradead.org>, <nick.desaulniers+lkml@gmail.com>,
	<kuan-ying.lee@canonical.com>, <masahiroy@kernel.org>,
	<samuel.holland@sifive.com>, <mingo@redhat.com>, <corbet@lwn.net>,
	<ryabinin.a.a@gmail.com>, <guoweikang.kernel@gmail.com>,
	<jpoimboe@kernel.org>, <ardb@kernel.org>, <vincenzo.frascino@arm.com>,
	<glider@google.com>, <kirill.shutemov@linux.intel.com>, <apopple@nvidia.com>,
	<samitolvanen@google.com>, <kaleshsingh@google.com>, <jgross@suse.com>,
	<andreyknvl@gmail.com>, <scott@os.amperecomputing.com>,
	<tony.luck@intel.com>, <dvyukov@google.com>, <pasha.tatashin@soleen.com>,
	<ziy@nvidia.com>, <broonie@kernel.org>, <gatlin.newhouse@gmail.com>,
	<jackmanb@google.com>, <wangkefeng.wang@huawei.com>,
	<thiago.bauermann@linaro.org>, <tglx@linutronix.de>, <kees@kernel.org>,
	<akpm@linux-foundation.org>, <jason.andryuk@amd.com>, <snovitoll@gmail.com>,
	<xin@zytor.com>, <jan.kiszka@siemens.com>, <bp@alien8.de>, <rppt@kernel.org>,
	<peterz@infradead.org>, <pankaj.gupta@amd.com>, <thuth@redhat.com>,
	<andriy.shevchenko@linux.intel.com>, <joel.granados@kernel.org>,
	<kbingham@kernel.org>, <nicolas@fjasle.eu>, <mark.rutland@arm.com>,
	<surenb@google.com>, <catalin.marinas@arm.com>, <morbo@google.com>,
	<justinstitt@google.com>, <ubizjak@gmail.com>, <jhubbard@nvidia.com>,
	<urezki@gmail.com>, <dave.hansen@linux.intel.com>, <bhe@redhat.com>,
	<luto@kernel.org>, <baohua@kernel.org>, <nathan@kernel.org>,
	<will@kernel.org>, <brgerst@gmail.com>, <llvm@lists.linux.dev>,
	<linux-mm@kvack.org>, <linux-doc@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kbuild@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<x86@kernel.org>
Subject: Re: [PATCH v3 06/14] x86: Physical address comparisons in
 fill_p*d/pte
Message-ID: <xbzssgempeueehescnj2chlkpgmyvxnysg2cdik7b56i4sri2p@4qfniovr2kdm>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <926742095b7e55099cc48d70848ca3c1eff4b5eb.1743772053.git.maciej.wieczor-retman@intel.com>
 <c4971a5e-1c17-4daf-8af4-804d07902fe4@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <c4971a5e-1c17-4daf-8af4-804d07902fe4@intel.com>
X-ClientProxiedBy: DB8PR09CA0018.eurprd09.prod.outlook.com
 (2603:10a6:10:a0::31) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|DM6PR11MB4626:EE_
X-MS-Office365-Filtering-Correlation-Id: 91f0c156-1df3-4cf4-259d-08dd773b1be6
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?Tu1w78c7OW4RoL3KLTef2GTi4KDq/e0mt9ca4DoqgD4dtDl/XH2hgINXZP?=
 =?iso-8859-1?Q?bqOVsCQm8DYFio+y971hIL6vAWSc+LbLcuctLloHhs5rBvZBjgb/j7kUpp?=
 =?iso-8859-1?Q?HFqu9VQbKm/oS1IupZ10Zqt9SnUrlNv8b4goqK5AwT+1dIR8PElu8lj5uY?=
 =?iso-8859-1?Q?hqVJKONwbyL0W7jeJAcJwz1cZ3DCi3LJn1ccr/bxzWQ7Lxh/eMVtV6+pa/?=
 =?iso-8859-1?Q?JrTk3VsHDQSK1AquuU687oQ83OCNbnefe0u9ndYP9FPeSrmoMuTxSxhfN7?=
 =?iso-8859-1?Q?1GpTLvsuIX9TSGf2NrMUg7Ipy6smXN8RsCnrgbhl8wZr+nMx9SGVCNPn6i?=
 =?iso-8859-1?Q?bfrpkMOaEo746YAWogjLwCh24UgTSqJ2G/SLg8YJ8c8bKY7Vy4VZHmlJSy?=
 =?iso-8859-1?Q?/NbEbcgj71F7X/FgHvG+7JLqpcUCTk0dqwLm5QlfzAog/MI/m1sVV0VSwY?=
 =?iso-8859-1?Q?DUVpI+hS67s2UavxAs+XCraAlsZ4EE2pW6rmEiTmoLmYN75Z8D1Gg2j2J1?=
 =?iso-8859-1?Q?l2u2D6ODOc6CCpGB/eMXzHMFh4hZq1s95MZ1auAV1RE4TlDLJIfCm+EIX7?=
 =?iso-8859-1?Q?xo67bKcOYpTvwBed7EiXTFlKdEZukDJZFKt9YVjnpNLl8ehp8aSHE9wr3I?=
 =?iso-8859-1?Q?2gqfPJqQRhKYv23BIq6rdcFDSGfGZ+X+/ufkNoR0njKjQy9V19u+YBkrL7?=
 =?iso-8859-1?Q?gnGEH+7mjk2w0t71h9yB9ur28y4gAI2KQBSaIVqhU3Q5yQxQZJ7Em4EOJv?=
 =?iso-8859-1?Q?+igx6+brGKEouF/bdLMTa7nK3CtBQVYGJecunSoumoKAN6I0MgdHUbbqoO?=
 =?iso-8859-1?Q?RliacYJOIDbskIWzWjRJwf0fa74y3kb/dWiW7kEv8VS34jqyJnGvWiB1QR?=
 =?iso-8859-1?Q?blqSmbySPfp0u8FAjUf7bbgQQYqNeB7XeVFMean4fNUI3UzBM8tTPyvHJt?=
 =?iso-8859-1?Q?1i9XNH7YHMjjDJx5gXgnfDsX8mnGEYOo4JmRXx4SSF9QTd3ic5/UGDpVsI?=
 =?iso-8859-1?Q?KFho9tfjeQlFQ0rinS2XJKISubMYEMA8NjwGNNGz32yhb/80IIlryuOyHb?=
 =?iso-8859-1?Q?er0MWgs50xaVAM+8srE6R6OFSRZRs4XzwkspwjDEbA69+s/nEvwdGbzRo2?=
 =?iso-8859-1?Q?vzBRXIUAdYesjp7WiZ1lGsccK+lOMsKrZabk18IafhUmQTYx3D8zAZQ8Xe?=
 =?iso-8859-1?Q?0j1Uu8lMs/5UgG7TUQ/yP6AbvoTz0uTr/DwJ+/9B570tfmqL+1QJuKTGn2?=
 =?iso-8859-1?Q?TT9kczpUfBosRYLsEV8iWVVQwWZAk0OHiHRfmQJ+lRIo9lCsKRSOucm2hl?=
 =?iso-8859-1?Q?Ym8+yIWi/wAw3K2byOCJLIbXrNpmUNSsCPT8GR7bmRoSwjlSXppy4vbAPl?=
 =?iso-8859-1?Q?GWzixn5UYasnEWa0Pa/h0vbxXwxRSOAgRqW9UVrYTrZB/VeJmuUIziWi7p?=
 =?iso-8859-1?Q?Cew5j8rVgMMPqhEu?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?zOflJt3s+c9siRWFDzUwyfsYYiOzF2KMMU5pK2SWaxHxS50Rknf8mUFNgm?=
 =?iso-8859-1?Q?eE4BT3xY31qYJKUvmRumu855en0i5aFD0X8RCelfZ5pKKhU4cMbBdMrres?=
 =?iso-8859-1?Q?NchfgjRq2NOKLlUdQdG30/6yFZS2jrlhqitKrNY36KdVgMo8b/VRh7Gp1q?=
 =?iso-8859-1?Q?byOXVc/Fly+4MeKUQEvOw3JQUkyeW7RYOAWcmHz6udlyJq3b6AWfFsq3AD?=
 =?iso-8859-1?Q?6IglO5lqxvxeTbN2aQ7TplcrzomkHoAommyE29kFMnpoKilFNKaynDBQJl?=
 =?iso-8859-1?Q?Q2K/4Wfxqb9c3RBqj91q0D8BJb27Mf7udOpi09CuHH3Ga6+IhnhZ2LNAqs?=
 =?iso-8859-1?Q?rWyM5PsY6EzWDq1Ms4WSdU/AZnvIY1quVUcYp6002MpNapDAsq58hpYKNV?=
 =?iso-8859-1?Q?7FvvHEDj7gXmEZ5/wamKQmdwZKj/yCGrlamH1oxMpHpx+RIi+vyW7ZVF7T?=
 =?iso-8859-1?Q?Gc4k9y4+s/XY4KnZRicltBwGeJHmcaBI5iMTHMFlCwXCVYMSP1toHVaHfr?=
 =?iso-8859-1?Q?u1Awfk7hlW0We0PjbU6c4nX1ZSFy2vpluwXzcQ6NwbI2VWiHrn0cGe8+Xu?=
 =?iso-8859-1?Q?DTnRojGpciwoi7hB8cCGv07vXN0Qn18B1ThuoilOLwiV1+0ayXgPpoaz1K?=
 =?iso-8859-1?Q?uHxLFZ0+4QzMF01F4M2lGRDzSJHyBWCr1daa/TlNyxzNPdc5UNJGcvkJ2O?=
 =?iso-8859-1?Q?aF/nWpCSECsQfT+hj9UOSmFthYCEGPK+uDWfxoNB0htgrky7VIk1kWZ9H2?=
 =?iso-8859-1?Q?1VUd/mP7T0flmdVdZ8ClXbX4ER1r1Gy6GcWWZCpUJbbMmMELgBWYnuDdMK?=
 =?iso-8859-1?Q?4V6XHydx1eRiIjPTf02NqsF+ApCnEg1/Uf73pfY2LjY65ewiylucg1OQSQ?=
 =?iso-8859-1?Q?J2IVulmX7iYdAsQ09NpxYN6WkboP0XuRFWqtq/QpSJE62m0PGtE/FzvlNz?=
 =?iso-8859-1?Q?Dwp1RQznJOivyOxkOJ55Xs2h8hfnGOBXFyNik0DKD9i4qOoyq/bZKGtHoF?=
 =?iso-8859-1?Q?oUwEvQUWmRzJPrGPsRs3/oFQAEOZ3sM8bWpMNBgmofjsZ7x6xzQZftQ/Lf?=
 =?iso-8859-1?Q?3Q+PO/RBRGGgObHz1692dOYMKGWUONxyswnxktRi/sPApkHeYunqw3wslJ?=
 =?iso-8859-1?Q?t9E4ecHtxdy4OXxSrwlYwEbzkyOtGEjOVytMPk3tGaD7H7vKhRbWFC0BMh?=
 =?iso-8859-1?Q?GgkoEZGgkgfpS2U2PnNyZBhQxAptkOJu3kLNFjTYLygyOXmMrGhMuk7W6w?=
 =?iso-8859-1?Q?U+lnvNYWW46tqpU0Ye5NLtQ7E69TdKFJ2AxMtGsw7N/TF1rHeavA/qTKaz?=
 =?iso-8859-1?Q?8hXXfhtEWFsioTSYKP9g4mKz3Wrll5AmvbhUT2ksqq8xCEdqXW0II8ObPX?=
 =?iso-8859-1?Q?FrXwk9Gtz9xNfZnsIwbEy6CY/6VkxOigW5IovfyyApWj5Qe/GWnIZMLpwS?=
 =?iso-8859-1?Q?gnSYxkkqUgYnqUAFmNqqlqX4IbOJfFMdsyHd2omxb9IHBTp/42d+fy30C8?=
 =?iso-8859-1?Q?SUvaNuzNm9SR9/nLu9jnizFKNPaNeV8e4zE3YLAOV+WJYr9BZbEjljkC+8?=
 =?iso-8859-1?Q?zGD46PFd3YyOlTlnnza2SZSx1VocRc1Rklfsq1FkIghN8kgEOSsiUT1fy9?=
 =?iso-8859-1?Q?1OFwyIbCrsBtI7dgoIqFdCNySSZ6pCao/zNQjnIVDUpgxgnYJLAqQ9XgoI?=
 =?iso-8859-1?Q?NTcXjzKfAY0x+aaNapE=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 91f0c156-1df3-4cf4-259d-08dd773b1be6
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Apr 2025 07:49:51.2633
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xiMkJ0Ocfugu+cGXnqa4IO/n50VdAn/aAqCvX4UCwx1f4QXJ3iKZ8oADCS0bzafady5rPatEh3yDkNYetFnGc0bwv/1d/cPKgc6ptUgzYzw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR11MB4626
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=OLacdGoY;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.17 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-04-04 at 09:56:31 -0700, Dave Hansen wrote:
>On 4/4/25 06:14, Maciej Wieczor-Retman wrote:
>> +		if (__pa(p4d) !=3D (pgtable_l5_enabled() ?
>> +				  (unsigned long)pgd_val(*pgd) & PTE_PFN_MASK :
>> +				  __pa(pgd)))
>>  			printk(KERN_ERR "PAGETABLE BUG #00! %p <-> %p\n",
>
>This one is pretty fugly. But I guess it's just one place and it
>probably isn't worth refactoring this and the other helpers just for a
>debug message.

I was trying to think of some prettier way to open code it but this seemed =
like
the simplest one.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/x=
bzssgempeueehescnj2chlkpgmyvxnysg2cdik7b56i4sri2p%404qfniovr2kdm.
