Return-Path: <kasan-dev+bncBDN7L7O25EIBBMNN2S3AMGQEBVS7UHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 67669967D6B
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2024 03:36:51 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-714356dfaa4sf3121239b3a.3
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Sep 2024 18:36:51 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725241009; x=1725845809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hrDwKc9njRopSnRd2OQUReVR//N7GYnzeVo6ag+ODGY=;
        b=l6/GEQm34yb1XgP0OD588iWIFZDpQvrb7eD2HRKrmdV4xhhTppRwx630uq6piVfXzm
         V3qPd095BNouo0vlJLnk6TYxuFGQ6/Lo+hCRBysrzCUGSrJ+UzN627vhu52pOnC85Ee7
         ZFWAad/XQM3AU3qpVQt3PVEKrkFT8PF71fAE+7N8DY0ShToS85+k77dvnjeazbLB0GxH
         jaVU3tCx0sKRVfop+9frpRwWshBnE+rwmcbF8T1KUoLr3jCBr+xEddIqOqBSTszL0qL6
         xh8unDTi2ghaZFROPgCWiOmUiKAWo4Hf6L0scGNLgv1+9FCfjVizE4KcmSB5G/yZv8w9
         ErKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725241009; x=1725845809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=hrDwKc9njRopSnRd2OQUReVR//N7GYnzeVo6ag+ODGY=;
        b=a4TiyLOc0/nqEh5T2pXBlD9tcXVhRkPakQTwheiJW2JvIHQYzB5GpRrRTcRS7hqOuU
         Hzv9Oz6emxCPc2w4htOifeIBkys9xmdXoRaLCSCEs1DZAojaijQ9Uz+m92uQ9ob5Qs8d
         ZqEcZkdXJWZtxRZeA8qxgMYSO+kco7/+u9GnUqZy43G+BlYB8Oj3RWZ46+nupKYnJHI4
         X7XxXfPDbZ2lFd+QT7i28yDVyTkSOz6rAR7f0LxXmQKt5/fa1WTnBgxjUIoCpu608k59
         l0q5eaNq32GD03j6qNXfnTWeyPsFMInQBfnhvyl/YQ93mSLJ10QS5Zph+9bgOgJfbcdf
         OHbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWi3nWq2IFPtvNaEvA76zhpTzgcbZSEgCPluAStfwN0pAJEiLY4GAOUR4XY6Lf/dSUr0dGF2g==@lfdr.de
X-Gm-Message-State: AOJu0YzMrrnNqHqR7le7LPlNSYoNlhv8vvWUpMFZZyufLDDswEKAbNkO
	0VQIfAY4V+rc+k/9EEQ/GqjrqND6tPYlJTW9q5W9OCO7l1u9X2s7
X-Google-Smtp-Source: AGHT+IHO+BM0dhGhfnMoU/tEs+vNceB5BfajHZA7oRCZOQ5EvBCiPSw2SbojtWdmVBT9szb/bZk5zQ==
X-Received: by 2002:a05:6a20:ce47:b0:1cc:e02e:f2c2 with SMTP id adf61e73a8af0-1cce0ff2410mr12541245637.11.1725241009274;
        Sun, 01 Sep 2024 18:36:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1806:b0:2c3:dc3:f285 with SMTP id
 98e67ed59e1d1-2d85460f559ls2443790a91.0.-pod-prod-01-us; Sun, 01 Sep 2024
 18:36:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSNKIyxXHLTG7Nh0AxxVCQUDlLP9tis17WFeTi2w8S1J4tPFLpSLDfj+pP1pqj+fZN8oAzloQwBtg=@googlegroups.com
X-Received: by 2002:a05:6a20:afa0:b0:1cc:e24d:32fb with SMTP id adf61e73a8af0-1cce24d33e6mr10254588637.27.1725241007845;
        Sun, 01 Sep 2024 18:36:47 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d8283c2838si1740415a91.0.2024.09.01.18.36.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 01 Sep 2024 18:36:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: x8bmm1kOSLmbf2UyuSNMPQ==
X-CSE-MsgGUID: 5yZL0cj0SAmP4RWb6IHn3w==
X-IronPort-AV: E=McAfee;i="6700,10204,11182"; a="23615981"
X-IronPort-AV: E=Sophos;i="6.10,194,1719903600"; 
   d="scan'208";a="23615981"
Received: from orviesa004.jf.intel.com ([10.64.159.144])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Sep 2024 18:36:45 -0700
X-CSE-ConnectionGUID: EqwIhpLZS+elOPn/8ptQKA==
X-CSE-MsgGUID: 1MwIEqm9SJC1MTPmuzFPQw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,194,1719903600"; 
   d="scan'208";a="69352360"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by orviesa004.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 01 Sep 2024 18:36:45 -0700
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Sun, 1 Sep 2024 18:36:44 -0700
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Sun, 1 Sep 2024 18:36:43 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Sun, 1 Sep 2024 18:36:43 -0700
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.177)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Sun, 1 Sep 2024 18:36:43 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=e2mk5j7VdyrOPyynRAqTrIbsN9c9y1KPqrZ+03mV+Qg60m35leP3EMLlc6mZOMww8qkE6tYnW6Q+NgZ1U9hlvugrWeAF7KzXUCH2u3C/NVrG98BRZ4t+vA5IM0DY5XNareSGFjgU+7EJVnUKs0VdMQSGSsScW/UIkAyjnriiS/mD4nEaY2cFhuvWWE7FcdoIgpTGq5nctlH8dycHTfUV9V22HtjdxMp4fBbHMLqMfnd+oCUs0cFRAKXTvXTf9WcE1IgvP+ilIU90NuCkTUPMoxKng2Tu8s0c8+e5BV2XrFcVHdPAe7ZNS9U4XpmQBWD/MYwG94YNavHrqBSyw9Ku2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8HKXK6DD7NhkVSbVtT80UiZMX5fD7OrbeoN7/hy8HYg=;
 b=mm2R43g3v9mcBTJ5W7KV8X9Bsk27F1TvmcduzMGc/orF28yc8TNcsLomXLT+/jkl9yf5bfN7Sb+n3YHmfOn8OcJv8tJ7PxLkbqURxHLJoLqqIW70+cjndRgUOS8vKlRYBWIngOwwJIAYxkJDiweZYfYGcjWOd70dIq9TfFZiP4+mWdFGiZ2JaXiqNQCytlGd0/woXx39h5nkT8fx2O0Yfl/B+npBw7FBEcGyMQe5HgWW9Zg2c+DUp/hJ6kdPU1+mt6Bk6p4+p/4HAmV+YLH7ZOBiPf/a8AbnTfsvqasd0/qL93aSSUonN2EyJnAH7Z3CHTYnyajLobGYwn9F6NSnhA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from CY5PR11MB6308.namprd11.prod.outlook.com (2603:10b6:930:20::8)
 by PH8PR11MB8037.namprd11.prod.outlook.com (2603:10b6:510:25d::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7918.23; Mon, 2 Sep
 2024 01:36:41 +0000
Received: from CY5PR11MB6308.namprd11.prod.outlook.com
 ([fe80::9ccb:43bb:9d04:14ef]) by CY5PR11MB6308.namprd11.prod.outlook.com
 ([fe80::9ccb:43bb:9d04:14ef%6]) with mapi id 15.20.7918.024; Mon, 2 Sep 2024
 01:36:40 +0000
Date: Mon, 2 Sep 2024 09:36:26 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Danilo Krummrich <dakr@kernel.org>, "cl@linux.com" <cl@linux.com>,
	"penberg@kernel.org" <penberg@kernel.org>, "rientjes@google.com"
	<rientjes@google.com>, "iamjoonsoo.kim@lge.com" <iamjoonsoo.kim@lge.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"roman.gushchin@linux.dev" <roman.gushchin@linux.dev>, "42.hyeyoo@gmail.com"
	<42.hyeyoo@gmail.com>, "urezki@gmail.com" <urezki@gmail.com>,
	"hch@infradead.org" <hch@infradead.org>, "kees@kernel.org" <kees@kernel.org>,
	"ojeda@kernel.org" <ojeda@kernel.org>, "wedsonaf@gmail.com"
	<wedsonaf@gmail.com>, "mhocko@kernel.org" <mhocko@kernel.org>,
	"mpe@ellerman.id.au" <mpe@ellerman.id.au>, "chandan.babu@oracle.com"
	<chandan.babu@oracle.com>, "christian.koenig@amd.com"
	<christian.koenig@amd.com>, "maz@kernel.org" <maz@kernel.org>,
	"oliver.upton@linux.dev" <oliver.upton@linux.dev>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "rust-for-linux@vger.kernel.org"
	<rust-for-linux@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v2 1/2] mm: vmalloc: implement vrealloc()
Message-ID: <ZtUWmmXRo+pDMmDY@feng-clx.sh.intel.com>
References: <20240722163111.4766-1-dakr@kernel.org>
 <20240722163111.4766-2-dakr@kernel.org>
 <07491799-9753-4fc9-b642-6d7d7d9575aa@suse.cz>
 <ZqQBjjtPXeErPsva@cassiopeiae>
 <ZqfomPVr7PadY8Et@cassiopeiae>
 <ZqhDXkFNaN_Cx11e@cassiopeiae>
 <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
X-ClientProxiedBy: SG2PR02CA0039.apcprd02.prod.outlook.com
 (2603:1096:3:18::27) To CY5PR11MB6308.namprd11.prod.outlook.com
 (2603:10b6:930:20::8)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CY5PR11MB6308:EE_|PH8PR11MB8037:EE_
X-MS-Office365-Filtering-Correlation-Id: c3e8636d-b534-422d-fa38-08dccaefb133
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?zOxWJObiCKc/UZpCiclxP5SAwjibJe1ArctvfttaYBDIcQpFJOP+7Rjj+uTT?=
 =?us-ascii?Q?VR2X2h+UKb0SxldfJb0xuveklBn939ekz/BpgP4VCaIBtBaUsDL/pSgd6+FN?=
 =?us-ascii?Q?cuBj1CYLTPLax5r0veqc0KyUQ/02PTrhZmypkpTDRMbc6RSxLWVPovvWaLs/?=
 =?us-ascii?Q?K5CYA+G083eB6nLnWEo7NM00s4ha4ebLBlmvKqJ+KJwz70AlhB2DKNDERMRJ?=
 =?us-ascii?Q?zgzBBQ09HlduwE7ipDMq1OQeYBVEFB9eVIcjvdpoE/R5psjqj0jV2Bh+Fx9r?=
 =?us-ascii?Q?mOWHyBkUBO3EQ2RxkdiSJzVjNpF6wefd1z/u3psr6wcBQhn+/rYxQypc8cir?=
 =?us-ascii?Q?kFhUCd8FrSqseVNxGejjbu6WGUMNK4tvA5HP2lNtPMDUlJQ0QyPsQTCH1KOY?=
 =?us-ascii?Q?Yl52ZbeT/DBsc1GDJny0e1g8uM6YLK11iOJQuJu8uafqTkDGBGOZh/YyfB0S?=
 =?us-ascii?Q?pFzMp9WB05yGLlfNyDzu2/9yrKH1fkRR7DoCFiVYonzrpZ6RWjCEHNIq14C/?=
 =?us-ascii?Q?AYSEmFUOWsFlkN36zEDHbrwvAOyuSAgv6CGLjop5FXLwZq3V/V1e15peL/iG?=
 =?us-ascii?Q?Lbz93N/1QsKgSaMcVihp5e+7P7USyqaDP6jYCA+iwiA+4ZI9zshz8rtnmV3b?=
 =?us-ascii?Q?TWCFKcKmeHj1kDBXcQH2GvWO6VFKieQGVECIRzgRuq7Uz2yCzZmPYxSCrmsC?=
 =?us-ascii?Q?UZwixKg21hY37vkGFmb1U7LEhfho2L+Iqe3gNJFnUzNbco/D3hSXZDqD7Uw9?=
 =?us-ascii?Q?4pFHsMqkT+PlxMIyeSzKMLhbVVsTZag7IlvjglJ8c/C735eg6/l7cD+Zzp50?=
 =?us-ascii?Q?DqeOzjXATId6FlTj5U2viXUzxfx+9dTAv7nORkM1u+KhPzhvtNzgZrbSgf5d?=
 =?us-ascii?Q?rT/FqOh1UdSp2toAnXmzPaQkv7VGsef1Saiv96MXUes2gh+Ul4pbNVwSktHC?=
 =?us-ascii?Q?2Ex3sPF/gzbbCccBZxwUJ34yNYfYq9uA4xjtce7eRuhqUuyOf3LYG1mjGZkd?=
 =?us-ascii?Q?w9lpCLfhHYxrNhNFChWHj+CjGVMpZcmVy3CtGxeSmVO0f6WOQT86cWYnYIWR?=
 =?us-ascii?Q?vHvdyy/iahAUDW4KDbA3XNInDFbj7ga0jw5ewuYWX6++65G0r0orT0sj60Dm?=
 =?us-ascii?Q?PPdQLl0shhU0haVmuXnPSI345KGWTZXOeCmoGyrqo78FhA4APJZM8bNG726h?=
 =?us-ascii?Q?4nOIe6TG+2QYvQDtHwbb0L4NUUvSUFxSzfempHMljDVPMYHryQfH8P2tjmQ/?=
 =?us-ascii?Q?Jt8ogiVzqW2irV2lFTfYFmARkP4X6NwtcpjiY4jjuxnU/gP22dMiI7kNIB9r?=
 =?us-ascii?Q?xh6cyY1ouJNtNcGotdbQASU93fYtsYQRHHGKzzDSyV2ATQ=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CY5PR11MB6308.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?tG5bCCyQn+NtAe5DN/p5QIjGXCy4nPlAs6m5YbMpkUb1jEJEIPu+898voA0J?=
 =?us-ascii?Q?VAyE2LbAYW5tUMpr06RavQNJps6ntFGZvjCmN0EKJ0HUJZvOS8dwffVqL2Uk?=
 =?us-ascii?Q?kwHs7nhMFHH5nvb9J4YdXQU1mg0623y6c4ZitSJH9o22r69BDxJSMgV6aTNf?=
 =?us-ascii?Q?x8wyaUuPBefNOtLY+uD503STfNwry2bXQoSfiG75qPbTB8IfQVBnEApki5Uo?=
 =?us-ascii?Q?uI/+MTd9x4Wp/RqssjZ9cyVHBHHh2OU8hmT6JrTGFBnfBD5hWY9ygcMjDz7j?=
 =?us-ascii?Q?O7HoPMNylLEnoGsx8PKAg55mrDZEvaIxfeR3Ye5HBaqb8om3VekIGP9fTRF2?=
 =?us-ascii?Q?tnZzGJzJ9Jqys5Xo5/vEVR3DgUYmWAILguYYD1DpP3vJSiNTJyUljLWNxg+a?=
 =?us-ascii?Q?ltaOVMOQLurRMdC6jvuU4vKaNnwgiAUIcCb1nTWew5t9oVmH6O2JeD3f1NBA?=
 =?us-ascii?Q?Fb5f6zrTlh5NmZls3nhqGbVeVu1Mk+txgpgpnWuSHp3TqPvnLBFX4lTJ1nGr?=
 =?us-ascii?Q?wcx8TefvlbmxrJ4uDpY+XquH1oz52wIa7LuPc0Cmra7rHcw6glDFAH3MBQdm?=
 =?us-ascii?Q?vtmoV9h+d+GVQPcxGKEBKQljkr9NQFSBC4hlveAsyFiWN9BDQiloxnguTlsq?=
 =?us-ascii?Q?OcAmmROcu4izLjsNnPbn05LvgvjHlA9acl71OY2TKyyDZ3hnYq6n9tMLY63i?=
 =?us-ascii?Q?aSxjYAycigummNxU4HTpCRMyZUlFSo7WgLIMaho5w3/bzpYzYhCetkYSJ/h1?=
 =?us-ascii?Q?SPmlsDvl8wpsIUn7Y93rASf3766wfPTzjxExfmdbrOpXM4dMofD7rahHPVyn?=
 =?us-ascii?Q?IB6tNUnceGKoAIWNe4Va3JNWtbEhCVmsXgETOKU+ORdXwqnay8wTYFCmwa6R?=
 =?us-ascii?Q?4eNhKnilGYDZBSkKT6TxhcImmq2t9EzW6lP/wBiCcLB3hCtC/7U98+EVl6Fl?=
 =?us-ascii?Q?hCJS4r3osyE/H7eJ0g1N2yQPiQN0sbci9LZXlIVQhrBP6g4S+iCnpCRLEAA1?=
 =?us-ascii?Q?AEGc00R6SPaA+gIPiwMPXLLY+R57RPEaMxwQ5OFBikCYzRnhoD4nwFeT/dDV?=
 =?us-ascii?Q?N6Fc57tPkV309iogu2Xu8YSotVu6HfM8qn4v3nSCkeBkEdoEcHK5FlXKngGc?=
 =?us-ascii?Q?6RLvK1hINFNB1XPvuFyxjzKVYsa+wrhNekPh0Jlq80D8bfJLqjJbIUdUDFn/?=
 =?us-ascii?Q?8dmHMOEpNwq1kWHq0fiYKvEpE+xu22MgdS8emkMbWqPg4Sg3V1NR9PBVbodw?=
 =?us-ascii?Q?VGhk2dPTViRUS4hL83iGlQRfUdVNHiZwMalw1tZGciIqNXjcz1/qnNtMVwtS?=
 =?us-ascii?Q?6c+Nw16FjQcb31ZYbT3TGirUuQc8x5p5Sk6wEMbPPsvqPV3xlN9v+eP5PsFL?=
 =?us-ascii?Q?E8BKH5Rm7+weac7vHUxj1zPvsZISuDMVe2BeVPaewu1V67+Ws30e5ylB7rT/?=
 =?us-ascii?Q?tLAG1IJhMZzS+a+ygtRCMFP89gd+58cOjTnyP6ySmMLQdf8I+QvlZ6ER4cRp?=
 =?us-ascii?Q?Uhp5nh6E3TwOeT2zWejmWTYUweH4UeUJfZLdS5dt43lCzVp4RaPQFyoo0aVh?=
 =?us-ascii?Q?rWTLDwvXQGA8ElmGFnzlYEb5CQsrTkqPyAqddhrx?=
X-MS-Exchange-CrossTenant-Network-Message-Id: c3e8636d-b534-422d-fa38-08dccaefb133
X-MS-Exchange-CrossTenant-AuthSource: CY5PR11MB6308.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 02 Sep 2024 01:36:40.6384
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ljD6ttfBSVlOK4LN0JAkTE06q/lN3SPEDmJEo1P8tc9nCsWjUFIo7r4/uGRF921598k2tjW3uQm2yvEUPt2T/g==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH8PR11MB8037
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=KBFKb+xp;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 198.175.65.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Tue, Jul 30, 2024 at 08:15:34PM +0800, Vlastimil Babka wrote:
> On 7/30/24 3:35 AM, Danilo Krummrich wrote:
[...]
> > 
> > Maybe I spoke a bit to soon with this last paragraph. I think continuously
> > gowing something with __GFP_ZERO is a legitimate use case. I just did a quick
> > grep for users of krealloc() with __GFP_ZERO and found 18 matches.
> > 
> > So, I think, at least for now, we should instead document that __GFP_ZERO is
> > only fully honored when the buffer is grown continuously (without intermediate
> > shrinking) and __GFP_ZERO is supplied in every iteration.
> > 
> > In case I miss something here, and not even this case is safe, it looks like
> > we have 18 broken users of krealloc().
> 
> +CC Feng Tang

Sorry for the late reply!

> 
> Let's say we kmalloc(56, __GFP_ZERO), we get an object from kmalloc-64
> cache. Since commit 946fa0dbf2d89 ("mm/slub: extend redzone check to
> extra allocated kmalloc space than requested") and preceding commits, if
> slub_debug is enabled (red zoning or user tracking), only the 56 bytes
> will be zeroed. The rest will be either unknown garbage, or redzone.

Yes.

> 
> Then we might e.g. krealloc(120) and get a kmalloc-128 object and 64
> bytes (result of ksize()) will be copied, including the garbage/redzone.
> I think it's fixable because when we do this in slub_debug, we also
> store the original size in the metadata, so we could read it back and
> adjust how many bytes are copied.

krealloc() --> __do_krealloc() --> ksize()
When ksize() is called, as we don't know what user will do with the
extra space ([57, 64] here), the orig_size check will be unset by
__ksize() calling skip_orig_size_check(). 

And if the newsize is bigger than the old 'ksize', the 'orig_size'
will be correctly set for the newly allocated kmalloc object.

For the 'unstable' branch of -mm tree, which has all latest patches
from Danilo, I run some basic test and it seems to be fine. 

> 
> Then we could guarantee that if __GFP_ZERO is used consistently on
> initial kmalloc() and on krealloc() and the user doesn't corrupt the
> extra space themselves (which is a bug anyway that the redzoning is
> supposed to catch) all will be fine.
> 
> There might be also KASAN side to this, I see poison_kmalloc_redzone()
> is also redzoning the area between requested size and cache's object_size?

AFAIK, KASAN has 3 modes: generic, SW-taged, HW-tagged, while the
latter 2 modes relied on arm64. For 'generic' mode, poison_kmalloc_redzone()
only redzone its own shadow memory, and not the kmalloc object data
space [orig_size + 1, ksize]. For the other 2 modes, I have no hardware
to test, but I guess they are also fine, otherwise there should be
already some bug report :), as normal kmalloc() may call it too. 

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZtUWmmXRo%2BpDMmDY%40feng-clx.sh.intel.com.
