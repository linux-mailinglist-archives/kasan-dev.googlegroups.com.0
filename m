Return-Path: <kasan-dev+bncBCMMDDFSWYCBB74PRPCQMGQETWFMHQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 66215B2999E
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 08:28:18 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-76e2e62284dsf7193701b3a.0
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Aug 2025 23:28:18 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755498496; x=1756103296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E55PQRU3N1aokARQ7yP1ua1vP/tzbetDjbgc3cN014U=;
        b=S3E69zQo6VN7BsGTeRoC+F+H1lPI1jtSSaKPD5PrDa2WDYaOB9Xy1LQntTVpYzWb3I
         5w0JhLl38/9bVQc0VVXUpcZmPxdfLXYjZeWx6ONgzmtIk0zWQ2sf2NKCnYUkaMvibA15
         oiEv8fdsRilnuzcTGaF/7GxlpAPEy+dTGHW95NyrbY9BSduVeaXTD8e4m4KYK+4JHVdQ
         C+RHL0MT5NYJ+HDnk95UxSSXGGU3Uw/skDK/+K0ZYs1IS4wu6/dVp92+h5gacGqRs32I
         ghJEPABnM536rj418B94rYdUnKIKALKLcGz77EWy5f6aNRLi4+54DAS188sl1vyLICDQ
         Axcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755498496; x=1756103296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E55PQRU3N1aokARQ7yP1ua1vP/tzbetDjbgc3cN014U=;
        b=n7r9XjALJGN6Q7SbiPykM3NGqHvRTeOi8BaRss9xb5D4EHMhmM64mnKaH+W9xmMA7d
         ZJn/RHjEEYMDXgReif/aaz8IW1D68mF2pyadkXYYCUo9iBgdPqQkMAU7m1LoN8+gqqWD
         q6CRxrG2FmKvCfK4g/7l0kPrLxMTP40Cw7uXlNYR9HI8mbonQUcl1NmsMRpLdk8pOBNd
         myA08tFMDKCbYVEqSNcTHJMPoMmAoGUzQ0CS4sPzW+PLcoQOwgS/1yO1lckJpUP2+nBx
         EfedXzDa7wnYM05Fqh4MwoeRVZo+HYjobjl+c2W+0iLzz2JQD2GpZZGCnp40IWArfwwX
         PVfA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCW0Q7V+v0QgxoHazlbwxUz9iY9ftyg8diKhRvKtmJhri3pQHC+63ysIz4M2oGdaz63XEweoVw==@lfdr.de
X-Gm-Message-State: AOJu0YzDeSLeGzDlbU30cIcZjxWiZBXsbt289L0YKIdgSxaqAyh5A9Xm
	5J9PuUG1WPtBMV+y9giZH7kb6HVtLvI5Yrhal39vDRjXTRHSb6uhMqSU
X-Google-Smtp-Source: AGHT+IH+J1qLe9weR1ROE8Obkn5wiAcSs2qzEecnCYIm9sulItBXDHe+Fr+p4JU/xOjthi5K0QAmBA==
X-Received: by 2002:a05:6a00:13a7:b0:749:b41:2976 with SMTP id d2e1a72fcca58-76e4469321dmr18137056b3a.3.1755498496234;
        Sun, 17 Aug 2025 23:28:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2Ikh81bEaodjnlVX60TXR+WaPSMnzzytzBo+FvKBdug==
Received: by 2002:a05:6a00:3cc9:b0:730:762a:e8a with SMTP id
 d2e1a72fcca58-76e2ea89f80ls4347544b3a.2.-pod-prod-03-us; Sun, 17 Aug 2025
 23:28:15 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUtEoaXeIaR49m16TwFOyNifhUhGEySUo+o+u8olXmJzgtPqGCacTqUNOZtC7Wp6+wFLfPsUYPiUDM=@googlegroups.com
X-Received: by 2002:a05:6a00:808:b0:76b:f4e5:466a with SMTP id d2e1a72fcca58-76e446c5e38mr16741167b3a.7.1755498494841;
        Sun, 17 Aug 2025 23:28:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755498494; cv=fail;
        d=google.com; s=arc-20240605;
        b=TAPLo8RWZewlUmS7L18yO6wB1uCrQO0rr1OJnKI5Vlxhie2rZlCNnJAiZEPiRLVNV9
         AavJ6ba6LcUKv/cGC06k0JZ98uDE9Q3LV4n2P59uu/dCJjQVFpIvPpcFSuy0RQWHZoS1
         Scr6sykRtlkdE23u9HX/q11fQllZa6ZPPTgKSOwIBR8wFvzdHVvwG9iZAbh8pG1EKF0y
         hAKWW1YFUyPynHJowFTeQgv+I4uaCgEeMnN2rTxDfmbwJNwuvnz8xxn8FkB2HNLNlVPE
         IMg3r09gIFQIMPCBwYZ6SC79sr80yCaS8KG29KxJXEmSw/jq/k3ySjYez4jiWsqwBx5I
         JSWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=n6v5B+FsB/tjLYpFtZ+6qwEmEWrjIwfKfmQ+B84gpSY=;
        fh=QRuZx7gwVOECeM3LJXCW+pFmPo4Kueh796d6/De0IBA=;
        b=S8/E7lYCI3kd9dd+5GPTqndFUhIjFHAIwRGBwPTA/OV3IwLX2yeUL7Kh78EE1lZkQ5
         EHUITfXQmdXuJjWyZgfRi1jijfq9BeV4XvlrnDZKceaulRqvXX7g8qsMKcXrMsXwt6Yb
         un41cGuGA7pSS/9tWaQ8H4lhQ8YC/BaUrxjs3XNG+DccB6uKxyPrp+vhlORiSAJLtNWC
         Vq07y93/1PFwz6kp8lE9SjNBCVSfpFViorutr9sBG+r/WEhBzxCV8ZDlQyoT3oHT46ZN
         AJwdVMhzX4ONpIxMkn87Akb6+lLJfJ8YARxp33VT3/hJlQhCGBILu5ly8TXmo1A/ABv/
         qb5Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=eu3B7zuG;
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e4506715bsi373403b3a.0.2025.08.17.23.28.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 17 Aug 2025 23:28:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: cBztWXQBTXiNSj3J86CT9g==
X-CSE-MsgGUID: NJcFP+3XRyOXvvxIJ2ED9A==
X-IronPort-AV: E=McAfee;i="6800,10657,11524"; a="68316858"
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="68316858"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 23:28:12 -0700
X-CSE-ConnectionGUID: 3Q4u4xy2RtqL1OaNdeqnew==
X-CSE-MsgGUID: vfwWnVdVR5G7mIi2L8Iz9A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="204660537"
Received: from fmsmsx903.amr.corp.intel.com ([10.18.126.92])
  by orviesa001.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 23:28:12 -0700
Received: from FMSMSX901.amr.corp.intel.com (10.18.126.90) by
 fmsmsx903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Sun, 17 Aug 2025 23:28:10 -0700
Received: from fmsedg901.ED.cps.intel.com (10.1.192.143) by
 FMSMSX901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Sun, 17 Aug 2025 23:28:10 -0700
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (40.107.243.56)
 by edgegateway.intel.com (192.55.55.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Sun, 17 Aug 2025 23:28:10 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=h9ShUKN4Q08TpngT2DMh783m2I7svX6JYOn2uFxZN0u7tDrOgwmeY3nxCQMZCisGbbHRg28Wfa3+jlWYP9wGYrpq4oJhepJrqwKW/AIXfw8OgfS04IfesSNiOiaVcGHwDgDvEWUQDbxXfXoc6xOZnJLiZlSiETvTCwxnP6Rs4Z2Q20NksKrFBd47TGp1333RLzoxnrOvwDxgmCjAfXIA+mGqYcFBBzva3zjeL1jdv4LwVmFSIVmee13CGTRqj+nO45RGRqXIXl/rYbeB+gK2zIyG5VZ2HunJIIymeqNRReWf0IQa1G2i54CmtQvgdZoxa18eNc99QkdD8dw67nDwhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aK566XLjUELWgRLzrjgKjESfuqgqk/IJRLRQR3je0TU=;
 b=uQkq8sppQCZ7SJChfdCSyKQJuLGAYwd1P0AhwcCU7Fi8zWuVWrbfjwNhmc3JtTUFLovlc3PUzSxmmvsGclRGjvZOSGadYQTvPI9eYG+hY0CI07ueN97s8PwquFXVJRmgz1eQnogi25irr0dh6jHj33tf8EYpri8qbv7ku9gT+CAafUjQdYT1Pqc7cZxr312jx0nf+N4+B3uXEDiB0rfwlMN4NsjE4HqggxV0gWhyp5Ey+WJUEVxotYtgzXWsgL4wsU650ib4yZVA50Q9NhfXWsL/vwimEPP9FkPfcILmPjKHQAMbOaxVpcFlmyetLKzal14rJ5dE1Wk5fAZzsYQY4w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by PH3PPFE60A892D7.namprd11.prod.outlook.com (2603:10b6:518:1::d59) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.24; Mon, 18 Aug
 2025 06:28:07 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%6]) with mapi id 15.20.9031.023; Mon, 18 Aug 2025
 06:28:07 +0000
Date: Mon, 18 Aug 2025 08:26:11 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Peter Zijlstra <peterz@infradead.org>
CC: <nathan@kernel.org>, <arnd@arndb.de>, <broonie@kernel.org>,
	<Liam.Howlett@oracle.com>, <urezki@gmail.com>, <will@kernel.org>,
	<kaleshsingh@google.com>, <rppt@kernel.org>, <leitao@debian.org>,
	<coxu@redhat.com>, <surenb@google.com>, <akpm@linux-foundation.org>,
	<luto@kernel.org>, <jpoimboe@kernel.org>, <changyuanl@google.com>,
	<hpa@zytor.com>, <dvyukov@google.com>, <kas@kernel.org>, <corbet@lwn.net>,
	<vincenzo.frascino@arm.com>, <smostafa@google.com>,
	<nick.desaulniers+lkml@gmail.com>, <morbo@google.com>,
	<andreyknvl@gmail.com>, <alexander.shishkin@linux.intel.com>,
	<thiago.bauermann@linaro.org>, <catalin.marinas@arm.com>,
	<ryabinin.a.a@gmail.com>, <jan.kiszka@siemens.com>, <jbohac@suse.cz>,
	<dan.j.williams@intel.com>, <joel.granados@kernel.org>, <baohua@kernel.org>,
	<kevin.brodsky@arm.com>, <nicolas.schier@linux.dev>, <pcc@google.com>,
	<andriy.shevchenko@linux.intel.com>, <wei.liu@kernel.org>, <bp@alien8.de>,
	<ada.coupriediaz@arm.com>, <xin@zytor.com>, <pankaj.gupta@amd.com>,
	<vbabka@suse.cz>, <glider@google.com>, <jgross@suse.com>, <kees@kernel.org>,
	<jhubbard@nvidia.com>, <joey.gouly@arm.com>, <ardb@kernel.org>,
	<thuth@redhat.com>, <pasha.tatashin@soleen.com>,
	<kristina.martsenko@arm.com>, <bigeasy@linutronix.de>,
	<lorenzo.stoakes@oracle.com>, <jason.andryuk@amd.com>, <david@redhat.com>,
	<graf@amazon.com>, <wangkefeng.wang@huawei.com>, <ziy@nvidia.com>,
	<mark.rutland@arm.com>, <dave.hansen@linux.intel.com>,
	<samuel.holland@sifive.com>, <kbingham@kernel.org>,
	<trintaeoitogc@gmail.com>, <scott@os.amperecomputing.com>,
	<justinstitt@google.com>, <kuan-ying.lee@canonical.com>, <maz@kernel.org>,
	<tglx@linutronix.de>, <samitolvanen@google.com>, <mhocko@suse.com>,
	<nunodasneves@linux.microsoft.com>, <brgerst@gmail.com>,
	<willy@infradead.org>, <ubizjak@gmail.com>, <mingo@redhat.com>,
	<sohil.mehta@intel.com>, <linux-mm@kvack.org>,
	<linux-kbuild@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<x86@kernel.org>, <llvm@lists.linux.dev>, <kasan-dev@googlegroups.com>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 13/18] kasan: arm64: x86: Handle int3 for inline KASAN
 reports
Message-ID: <nuzda7g3l2e4qeqdh6m4bmhlux6ywnrrh4ktivldljm2od7vou@z4wtuggklxei>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman@intel.com>
 <20250813151702.GO4067720@noisy.programming.kicks-ass.net>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250813151702.GO4067720@noisy.programming.kicks-ass.net>
X-ClientProxiedBy: DU7P191CA0017.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:10:54e::25) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|PH3PPFE60A892D7:EE_
X-MS-Office365-Filtering-Correlation-Id: 9c73904c-51c7-427b-5ba1-08ddde2064f1
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?nEtvl1oXLHgO4pIKxex6v6rURaAdL5OE0Y4/c7XsFvTUWBsYr8XYxKc/Aj?=
 =?iso-8859-1?Q?Lf22gfFwOKOFcRlhfIh7tCMd+fg0sybAs6HaVZba21iM8KostXLlmhn5yV?=
 =?iso-8859-1?Q?XVz+utZPZ+lT70cVALoMYX5sw/Z4+Nw6ljm0WXwI6G/CuF4Gts23ETwlcf?=
 =?iso-8859-1?Q?BWPfTsNqaAG/4Khz3SbDP9dzFZ0QJVxAQUb0cZC8BzzdS0tWHZNzhUA0tf?=
 =?iso-8859-1?Q?8DBXfZo3I4tMxZKlSjriJVT7fjoCJRbduo3n5YnU8c22TtiTb3cUInpe1T?=
 =?iso-8859-1?Q?o1Lt2TFI4uzlgtf5vhL1nK9CaGojgb3RFuiZrC6J0CVWWv1i1GLxQHvn+/?=
 =?iso-8859-1?Q?yz43rV/W/wlHaOwibNveVpSCZXBkrEUsLZg33nhXa1qJcjQc/gV6RFHVPS?=
 =?iso-8859-1?Q?PRkfXIgkh0rzS/5hJWRxSD2Qn+4onJREjvdPosnbC1EGa/n75uX6yjDB7z?=
 =?iso-8859-1?Q?AKbcJsfM1Z4HnSJu89K9wuCQx5dW9Iv6cGd1fPdf/d8R8+CoDl4INTUW1l?=
 =?iso-8859-1?Q?90OJEQocb3ff857EQWrTqzBe4fpxxROmfXJoM1jb5skuUaBcDk+7bgQs9a?=
 =?iso-8859-1?Q?i6Ww4RQSCdA70t2QDfEZGiQ8PpiXmHAOl761/72SS+D+M59mmYC25D3lLt?=
 =?iso-8859-1?Q?/M4yLbhY1qSueK4MsWjYjZA/eA6/xQfuodi9fz7lq/Cuc4lLdT69EtHJXO?=
 =?iso-8859-1?Q?gYUqEm4yZURcj3FK+aU/nnH+8atGikVN5zEacb7Fu6U7JC0KpHBWXer5MJ?=
 =?iso-8859-1?Q?gRi/r0bF5mb32vVscNZynbaPTaFjZJLZYmeQlW3JKDtE1/le2zNBjXhhss?=
 =?iso-8859-1?Q?krzNQyBVdD/dKbqn8ii+wVFQfW7Otj8aF38kCti3Rkpm2jqspbIOBMC50f?=
 =?iso-8859-1?Q?xQxLDetWuGcc+vw+TjDdpFwJI/xE6tBos3kSxEwj6nGJyldPqD9VFR/+O4?=
 =?iso-8859-1?Q?9CLRvRUHMLBA/ETDFRC+sqgqC9zYKQSkCUWU9FjrCuvyLX3spCgUNdYjje?=
 =?iso-8859-1?Q?ahP0uRK28Iv0sOazlog7aVTZOvr0r/OQ700gFCi6Yqp4x1Q2F0Q5QfgaCG?=
 =?iso-8859-1?Q?vePBY8o/H6k3kOr6K/OzcWRBk/ADBQUn6K5BgdG6jhxrs35N0y42nl75wu?=
 =?iso-8859-1?Q?m+jZVyBAAlHhge5ezOuJSDhIOCW5Rmh/A8UEYhYahzTX3SD8y6IO5GzKTr?=
 =?iso-8859-1?Q?XWlcp3I7mtD9YKMCUxFQ99tQIoF5jlMJn8UZkcnS+xCOmQJXyr9F+nulqp?=
 =?iso-8859-1?Q?/tYD5i80GhbBtLPCKkYAd25nxdi6ub02DdxV0VsTSgkyfQdhz9ceOo/6/b?=
 =?iso-8859-1?Q?7TCUGIbuBU5vRBnLAqK9+q4p1VtYYIRVlKfSj+YmjfbzQ2d/UK6ggrKfyT?=
 =?iso-8859-1?Q?qHLs7MEPqMuz3VBYQ7PplOGwzvgcdk9LDKwaAaG9vQyQO61uL9jfVaRJpb?=
 =?iso-8859-1?Q?mXz/5681hm/OLWsPgjYn6Qt06dSIe5OOD6KntTiDVTQGImEgXHJK3Nr22l?=
 =?iso-8859-1?Q?8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?m/kngT3bAUKP6+u4+TUkcDoRK2LUpTM+BanPDh0qdq3IFRfRadKvGJf6f2?=
 =?iso-8859-1?Q?HbDZb2Ha4tGWsZmum8PTXLAEnJq+B6mjJC4vh1ZTILtejR6j3eS87l2CFW?=
 =?iso-8859-1?Q?V+qYi+OuMLa4GgOJu85trRYQnXwd6fiWALOOKzTmoA+8qbVNW1RKE1FKIV?=
 =?iso-8859-1?Q?eWtmtnzXCVyzaY2Ak1JMmuuC+A06xYkZNAMuH51daXLzrygpqV8YYB1HJ3?=
 =?iso-8859-1?Q?MeWNrsk+HC7oV7YZE/7s0fITxy23mab/66h1X9o7Az1V0lHMslRVl+imV5?=
 =?iso-8859-1?Q?ZDgMDSGhWH/EgbHprYEXkMGhBMfxVr8or1vAnq/8BHlXXYK6epYkjnyRIZ?=
 =?iso-8859-1?Q?6TqUgH22QYT4Px7TfpAlL09Uecoz5ljyGMicT0EqK8ijp/M28S2/UzpS02?=
 =?iso-8859-1?Q?jIRXlP9uvi+8rpQB1kbxzxO4yg/5M3tV9thcBaE/t2eR8qkJJh6pF5Epgx?=
 =?iso-8859-1?Q?MiRknC3UTMUMuv1NA28EaVgiYyvwb8irthx+iB0vdhtwyMHIR+8spi6dzY?=
 =?iso-8859-1?Q?37QnRbnkQyjt/B7H9CqMKpZVaifIzAIc0VeVqaBaXbDklfUWh8/KsJgqzO?=
 =?iso-8859-1?Q?iHYgxb8T0J2y/nd7V60oDGMzJvsizsuYmixs5VtnRPbk9Okf8Pv/KNn4o4?=
 =?iso-8859-1?Q?34Pp8gtSAJj6cgbv77tRRKM6essRy80zT6Dpelx4QowW1bDaIDzykL/lpi?=
 =?iso-8859-1?Q?5fLiE0T7ODDCcKcypM9UGX1B/PNfu+IhxJkRvrDu7IT4Q5umOxcztaX1Af?=
 =?iso-8859-1?Q?4jMgouD5dR4GBMUR37/K+WBqMRhSRA945WtpL/cmfj2LP4ONXTe2tmz7FH?=
 =?iso-8859-1?Q?BYLvi9tMbu5miqxSj6l4bT8OlaOSZMVaOC1LHdHj1yZ6ursOR1uVPu2z4n?=
 =?iso-8859-1?Q?JagHs05IczSY6H9fPfltucAXOdt2gNCxZFD0w2iUq6cpL/Ps8KxjKrCHRW?=
 =?iso-8859-1?Q?0dVA+sSEkd9z9M3DyIZWpOblhkhJnjFTOsrnBBwDplGXEcDqs2i5Swf5Ds?=
 =?iso-8859-1?Q?pVHbAN47VNXIbXmiV9G3pNJ84Qnz/5+XmstEZTjsYr0A+jq0QdiWcM57wI?=
 =?iso-8859-1?Q?mEsHztGcZ1G9Nt/1mjYVdxJSPah72wRdbDqwVMBKGmOAO5ttjmzUGlXNHG?=
 =?iso-8859-1?Q?Ml+Bw5KeUgbcuGT2FTtvnw4UvFLu8K5wngAby90obCisSAlaDUKFOBnxYe?=
 =?iso-8859-1?Q?l2igflLXTwjmJSHIIQpUEVreeOnhns/2NH/LM3Qg92Y91olUieEyNLyB9k?=
 =?iso-8859-1?Q?1ONWdbydS+iv9x1Xdm7heh9h8i31Zxa2nd6qDl3ShFUU51LAX7QIJbnXxi?=
 =?iso-8859-1?Q?g/aB+56MNUdozYDq97pSiXAETPOB4YCUAC+tWeAn3eT8VXIPvcp0ZTvDdc?=
 =?iso-8859-1?Q?Q4Av+c/QzxTdbA5qazOzm52a8mIWIX5TdtcDgoh1OESfAV4b2pqHyvAEsK?=
 =?iso-8859-1?Q?H/Vt/DD/JNPo0JOAPy5lzREhXhu1amIDb2g8YUfnwTKM+mwEEtgjOHgbMl?=
 =?iso-8859-1?Q?d+kLxu89N5vFxP6j4w5lNZUxUzt+X7TV5nwCf6Qkog82UOvdp+s+zWjWh7?=
 =?iso-8859-1?Q?1am6sUxmadVRWwpkG6+ZtiTSp4xjiSaN+anb0Vw89tsh0k+KWwoenM37UJ?=
 =?iso-8859-1?Q?JSZDb9Ypw9/NEI6VkqXwcAuy90ubZhbOGMfyQoBxIYlbPis2nJysTvufNB?=
 =?iso-8859-1?Q?SXYLB1ARhJp+xho1gno=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 9c73904c-51c7-427b-5ba1-08ddde2064f1
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Aug 2025 06:28:07.2443
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: NiJcMD/F4WLi0jYdNfgdUg41uOHE5JNWwmscET+JVBdfBlPntkgAtmy1duCKmdugoHD1I6UcivAqc10D0x2zhnDJG5dSpUNkSKJ72tPoHmA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH3PPFE60A892D7
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=eu3B7zuG;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-08-13 at 17:17:02 +0200, Peter Zijlstra wrote:
>On Tue, Aug 12, 2025 at 03:23:49PM +0200, Maciej Wieczor-Retman wrote:
>> Inline KASAN on x86 does tag mismatch reports by passing the faulty
>> address and metadata through the INT3 instruction - scheme that's setup
>> in the LLVM's compiler code (specifically HWAddressSanitizer.cpp).
>>=20
>> Add a kasan hook to the INT3 handling function.
>>=20
>> Disable KASAN in an INT3 core kernel selftest function since it can rais=
e
>> a false tag mismatch report and potentially panic the kernel.
>>=20
>> Make part of that hook - which decides whether to die or recover from a
>> tag mismatch - arch independent to avoid duplicating a long comment on
>> both x86 and arm64 architectures.
>>=20
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
>Can we please split this into an arm64 and x86 patch. Also, why use int3
>here rather than a #UD trap, which we use for all other such cases?

Sure, two patches seem okay. I'll first add all the new functions and modif=
y the
x86 code, then add the arm64 patch which will replace its die() + comment w=
ith
kasan_inline_recover().

About INT3 I'm not sure, it's just how it's written in the LLVM code. I did=
n't
see any justification why it's not #UD. My guess is SMD describes INT3 as a=
n
interrupt for debugger purposes while #UD is described as "for software
testing". So from the documentation point INT3 seems to have a stronger cas=
e.

Does INT3 interfere with something? Or is #UD better just because of
consistency?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/n=
uzda7g3l2e4qeqdh6m4bmhlux6ywnrrh4ktivldljm2od7vou%40z4wtuggklxei.
