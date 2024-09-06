Return-Path: <kasan-dev+bncBDN7L7O25EIBBV7B5K3AMGQEXQXWNEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 34B2696EC10
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Sep 2024 09:35:53 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e1d1a1e4896sf4300187276.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Sep 2024 00:35:53 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725608152; x=1726212952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0hpptc4USxuxxGEoqYgcuZfzcuWVb76umDZ50Yq0sBk=;
        b=wWotUbJXnCdGsrBRBVI2XbaP35MeLbLNOC02lO9clmyRn8akYqR/bJ9KzwPoJBFPty
         sFsTefxYMp6azNsxPTvLUJC1xZivQJHxbpD4KMfI5x/+e/NZj1u4/LYJiZs3VnGQ8GwE
         eS3VCDzf0n/lUzbdXSnzHPJkj0kTxOUiyLOBEk35HKhix0PkmG46w7DR18zNPaSS730i
         8B+gswNESb0oo05uJgEhoj83pd8vSdbHNr8/x1klRba4LAVEfFItaeOyQfek00hM2lpZ
         sNhBh7ComMXClyBpMaf92En0ORyM2kD9thbqaq9dNnXH+nrMqwmIuz0LbPyNnBdYJQRj
         ur+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725608152; x=1726212952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0hpptc4USxuxxGEoqYgcuZfzcuWVb76umDZ50Yq0sBk=;
        b=ZB53rhCRbrSXbKIxkRaHGS7W/8nO5bddGwqHruiPP+PxDy2SIPVyCqf0eU09YZzU2o
         /cJALc5I9uRijfQ5xQYCptZQVhh+MzzPyBDtXxf6IVN3frWjqVPL41rCQTkBZZi08o55
         DJ929Sn3+gU5OeeJA2SINS9w0sFsRAr9wJqrGQx2XqWqhWC4kM2Ykdi9Z9ISb6p+bzuc
         27i8rLfJupSUDnOqZSmB+SI6mn/pdUnR9eVBS3SlJRjovGPRXXlbj7jFx/tI7y9exoJl
         w7YJqbGh2yI0C1lAc34VyEzCphKSXDQil7juRm3hFVNPrslO8u0mHYzaYXP1uwsjmwBY
         QIgw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDlHeJjvZ+KQkLcG/yFjEMOMQ/vPQeNBfLRVoYTMNrjuUZirz5a3TyfGTYHkEqglK6sKTf1g==@lfdr.de
X-Gm-Message-State: AOJu0Yyc+NgU+nUGP8SJSkIHmUlkDNBu12HILaGgk/JaAUkfEFRcaKwo
	Ruq4lU6mwPw8U0ZrFmwZ55gYIyDHIwv3RhsmVQdlRx98/2j5kXCK
X-Google-Smtp-Source: AGHT+IFusnb/x9iKIk8YuYDAngB1vcfRWIjOg7x3RPU1fK1KqJFUjfnIFxPyI4s99kQ8YFv8QEDW4A==
X-Received: by 2002:a05:6902:2193:b0:e16:6c22:8112 with SMTP id 3f1490d57ef6-e1d34864dfamr1992436276.1.1725608151747;
        Fri, 06 Sep 2024 00:35:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:3cd:b0:44b:e6db:de28 with SMTP id
 d75a77b69052e-4580b7a96b3ls6839131cf.2.-pod-prod-04-us; Fri, 06 Sep 2024
 00:35:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX9GIN0XV6j+XXm9XmOX8h3q0hP5IdoucftckD0kTuvi2nUgAi3PHnNP2ozk/l7R36iRozb/xl6xts=@googlegroups.com
X-Received: by 2002:ac8:5ad3:0:b0:451:d498:dab9 with SMTP id d75a77b69052e-4580c66bf77mr22116211cf.12.1725608151066;
        Fri, 06 Sep 2024 00:35:51 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-45801de2788si1839331cf.5.2024.09.06.00.35.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 06 Sep 2024 00:35:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: Ya8Y8KeCQumGXqIGcX5HZA==
X-CSE-MsgGUID: +Qj3nnemSzagkxxc2ILPSQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11186"; a="23916496"
X-IronPort-AV: E=Sophos;i="6.10,207,1719903600"; 
   d="scan'208";a="23916496"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Sep 2024 00:35:49 -0700
X-CSE-ConnectionGUID: QZN72MlnQ8C4uKqFhUTYWw==
X-CSE-MsgGUID: oQkd+dXQSR2q665PRBP2bQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,207,1719903600"; 
   d="scan'208";a="96659994"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmviesa001.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 06 Sep 2024 00:35:49 -0700
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Fri, 6 Sep 2024 00:35:48 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Fri, 6 Sep 2024 00:35:48 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.44) by
 edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Fri, 6 Sep 2024 00:35:47 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=dkhG7IuM+7bhxOk6OHmAat3ucKmy0U62xsIWFtrwfzNPc0m3nPBAQGcBa2U3gk6UXUJ+m9RAAl29eR2iz0gV/NqpT6bo9//QvXnewE1HXOqrwxp5aiP+IqiZowPDhlf1YH8gDLKf8+95E8wBQkdvWgrmOApLMu9sSvLq9z6DV26i054W6+JBouAGOauKKEQQvdtJOC+Zgdv/E8yacL9Z09YZQKZqgs1fGIyMbNMJwEaNhFsXLtKlVNKDQjeTBBMoTHe2ZZVq/oAgTRMdInNf5cUo75i8MagzCCOVTH4EYTCuFw2UIZ5dF9fobHBIKq8a3k53RAfN4wsHytJw7Aqlkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=99E+IXQ6ZjiFuvb5Xuqsb1Mps1tA2ODRwYss1Nl/9so=;
 b=W/E265YSqHxuquArR2i9ZhjHSdutXRGL04gx/1cdo9kU9V7/JeN2hiQXFEEftMiwBEGtaPdxCdiXqYUKH2rNG9eLP08TCBNlJDsD7zN4PBl7DdFxwHk70RW8em+tTSJWh09irA0SRw0BygX9JUnleWP4u9pX5pkWcDb8E5KhV/qeHl7Ga/u7TJN6KJLCh/DuaTmlzNelsexNb58noiTsmL/QSF/dVO0EfOQoBoUZDIGnuud0cT2kXp7qR7d1DGC5Y6hT94RfQ4pvi3KuS729w/1cXxibWHWwN6LAlbmuN30GlCMT4vsiSi6BxbzHNeY/X8T/gVv6DJmA8RkHUQQyQw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by IA1PR11MB7294.namprd11.prod.outlook.com (2603:10b6:208:429::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7918.25; Fri, 6 Sep
 2024 07:35:46 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508%6]) with mapi id 15.20.7918.024; Fri, 6 Sep 2024
 07:35:46 +0000
Date: Fri, 6 Sep 2024 15:35:31 +0800
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
Message-ID: <Ztqww1HBGpopK5kW@feng-clx.sh.intel.com>
References: <20240722163111.4766-2-dakr@kernel.org>
 <07491799-9753-4fc9-b642-6d7d7d9575aa@suse.cz>
 <ZqQBjjtPXeErPsva@cassiopeiae>
 <ZqfomPVr7PadY8Et@cassiopeiae>
 <ZqhDXkFNaN_Cx11e@cassiopeiae>
 <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
 <ZtUWmmXRo+pDMmDY@feng-clx.sh.intel.com>
 <ZtVjhfITqhKJwqI2@feng-clx.sh.intel.com>
 <ec7bca4c-e77c-4c5b-9f52-33429e13731f@suse.cz>
 <ZtaAGCd/VlUucv6c@feng-clx.sh.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZtaAGCd/VlUucv6c@feng-clx.sh.intel.com>
X-ClientProxiedBy: SI2P153CA0015.APCP153.PROD.OUTLOOK.COM
 (2603:1096:4:140::21) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|IA1PR11MB7294:EE_
X-MS-Office365-Filtering-Correlation-Id: f077595e-006b-4607-b57d-08dcce468536
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?84dDXqUo8oS0Rr6s0SKBWQ61gw/LjKdZLFdrmtpNPj+d1HhplZxN/m+cIxmK?=
 =?us-ascii?Q?MVhr2PvORp7rDHFVR6Nju6C5hWWR/vYE0TmGqA6Sp7Z4urt7V1haJaMQIGaZ?=
 =?us-ascii?Q?V57IIquo1gqYdEpqGTRVIeCVHyWsSx6vZhalCeGiCvSXDTsCv7P6OYbn+StP?=
 =?us-ascii?Q?65kkdcCxrh0jMxOXH6DS//fxrsBkq30/Ei7uSNniYQQ1gCtcDwi3CnSKo78U?=
 =?us-ascii?Q?FI2WHXN/gWluxu8lu7au37MJDpG0Yr+wkJ0vzB4TEQ7+GASkOCFxokQhXuTY?=
 =?us-ascii?Q?h3zk1e+bTWOCJJw8YFiuikVR/1K8aA9QvWzGJYlyYy/WBGLcjoxvissjQ3Sb?=
 =?us-ascii?Q?R1V/uPjghiUspQ1okpflqj9CnEaMo0Q+lC8EEuHAHsbnr4tj4XMbkqoWeaKq?=
 =?us-ascii?Q?e1ak0mOrgMvXZ3K8y/0LBNvx9Olhz5BWq3dRE9h4qrZzWml5qzxn7sZioQpo?=
 =?us-ascii?Q?jDI0RdJ6fpgcsh+fLyvJpOd64uZBLeCIojOJr5vpTPfk0742cMQPAwltSmqy?=
 =?us-ascii?Q?lzKygToHnyqNK02r2DAqfYRaNeR/bI6RzH3s9IKkZaVrPSg6RejRUYeBqZpM?=
 =?us-ascii?Q?W5ZnOGs54ylakecsTEAHCPXwZK33mAn7ojT2l+TWK2x2MUGPImYkZdEmzJKq?=
 =?us-ascii?Q?IH1F+qS6GgFhLOKKvgfRVpHGg33/b1vqrOHkZEaH/e1ctUWrIo00V9UJFip4?=
 =?us-ascii?Q?t3xLi5UC4ENCW6rgEgYegnz06XUwrBW1bOkT1QX9wT7jNo0GJ276UV7pBmbb?=
 =?us-ascii?Q?bzyrh0uxQtB/cAA3V3Sh4/pkwZvdjV98KScIDPBgnxuE9UQdL/VS6pXU3ZSq?=
 =?us-ascii?Q?nGm2L6LKatkobUxQPNlWWCwDHbBHCJ/2H0n6q2YV9kmda9lMhX3RXxwk0vQa?=
 =?us-ascii?Q?6bZhxeblY+RVoB1wpqXygSqohHN2iClR7yZMTVPeeEIFPC1mfb9PceCq8t4P?=
 =?us-ascii?Q?BQKYzzzVBvLzXaOEQCwU1rVpspZzz9tJcVqpCZZvARvHqA+Ro5GDM7D/7AKX?=
 =?us-ascii?Q?yLubUcP0/e9DpGd6LWzA/qQsO22ygMyIHVQ0beoEVnz4bs3DqiLP7/Rey6NW?=
 =?us-ascii?Q?dIXcEZ+61kf51L4bTgPlb4Y/OV5FrqBiFe9hJBaY5V5hqYlbKSOar22PlRPN?=
 =?us-ascii?Q?myZta36ZoZksaMss6TcKmxkCZ58J2G2x+9svgw1Vv+7u9I2KFhmXjury7DQw?=
 =?us-ascii?Q?Z5WC4IgWeayekWLTo5j2zYaiqn0p2dVlnavCfRTb6WF0KuonfjEMbazaDn+y?=
 =?us-ascii?Q?74E1T//iE5STnvQcUAV3mmgnHhbr7zYSjQWmJpGdEDBuccZ6688vUg9Mo48v?=
 =?us-ascii?Q?4F/GAcIJ49DNmelFP81DRaohpf37CHGD0Rlty5MYjKoOvQ=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?C+CFNzlkgSgY3EKIG8xkjzNmHtD9BKD0tlPiYuxmz9cakwSoyWvJBZe3E7Ko?=
 =?us-ascii?Q?n5Tiu11pl+EJcsKSw/MixCJX+70L31Tj46Nql2PL1BQJQPRY2EnwLxEoUCaJ?=
 =?us-ascii?Q?p7einD5AQtUTDpZ0jexASDPGANsIBqHpWAbSyZXqlkCXGb4TCQegeKtkrg3o?=
 =?us-ascii?Q?RyCfbmFW3oM+paJEUCwJGJZP+WG5u+evHScYd6F9EnLYlm7IqhbchLgZKKB7?=
 =?us-ascii?Q?bxAmGe52a84mHalSce0G5ci25A6gVO6TX0nELQ8pit0MJqy1yV6PeFc4ITQg?=
 =?us-ascii?Q?c4/FJi41JwtUT9YnK7ghLOHMuQd3rTqoNsZ4r92TonnsRUTuM6o+YI0hrPtk?=
 =?us-ascii?Q?RXsS3EWZXUE0pJsnNX6E1zYHPXIVeJST074heQYBuNLJKRfoxJPl87EGkAbS?=
 =?us-ascii?Q?N03L02pev9mr3o3sBLmeYMUM0y9r/pC1IZ7Xen30ei4zC4nSzY0nlaCg0UOC?=
 =?us-ascii?Q?xCLX6SXZxF+a1wWBSntWb17qwjwKYoRbJvSVU4kvT8VEXcYcvuInfj88HmKj?=
 =?us-ascii?Q?7i7EvmVFwGRS7i0TEGlkJ/BdZtKbEedLELkA/5atqcaQ4H87EvFtBUyYEEXE?=
 =?us-ascii?Q?xWBfuuVGL2rXIQDwivNTkmlA0qSrzj2/cCjdrUL0z6qMA+1+U4ExdMy9Ssre?=
 =?us-ascii?Q?BgHJCP+t0Y2dM82EIlf8ngNEUP31sJPSaTn2FDdd1v2W7vcs5WlLu0DrfwBD?=
 =?us-ascii?Q?kny2+YcLv+HkhZzoOYiGeke3c5s6Wgqfd1CnwS10DqV6ukwfR9Ol9Ubm23iD?=
 =?us-ascii?Q?Xkz1rzmwqn4o5OQFUmcH6NKGp4ECpZL/Eys/7U+XkPCULV7yotSHM4cOH/4j?=
 =?us-ascii?Q?O/jaeMt5jZ4FMIGOsXuV6B0MIMQ56jV/UDZulyVJdn4/EP85hlCos1WM/aKh?=
 =?us-ascii?Q?ZcR8Zt6zd6hUc2uskTQiSb1JIdJ7V5DXO3BAsZCs4kIHPlgPQ8MPzlYzzIaz?=
 =?us-ascii?Q?EBTSY12GI07u3pisluM5hLgAS8aUTzXooSU1W21FMpmHjJ93yU7xLsNzbLAH?=
 =?us-ascii?Q?XE5bf9qeWakxQiYdm5W1YW3w+V/maStD0xcoWoNt7IGYxtpNz+fzyg1kB6+L?=
 =?us-ascii?Q?j/opT0BFxZwz1lVt5sEjw4Ft3OeebQBq5ho+4VOqLKF1jz1DTbT8oH0KVclV?=
 =?us-ascii?Q?z8gbQ2Qqtghk+TOJ4HM1D9fiP+tZEFr0n1JXJ0f8v3NCB7HTpKn+a8qijmVu?=
 =?us-ascii?Q?zm2voW+astVItxJR8ByyTjSh3ZkPgam16hVHQ4WS95RLRgab8zxRGNGcg+0l?=
 =?us-ascii?Q?ixS4Fl8jdQVPgGz/6/Os2wqrW/fDZ2wlDsTqWR4w0VK7EV6CkipT4/VngOtV?=
 =?us-ascii?Q?A6wqBZ4AuUa+G/GCRqpGOvhhtorWWkU0yameSyR4nR+O/1ivY8pyP+T5bTCK?=
 =?us-ascii?Q?g4lKAFjb5ZicfcNoYU2os5PpSUin+rD/GTOligiAZPha2ss4w8teFXh+XB7m?=
 =?us-ascii?Q?fA7PwPnQq1FyRvC671CAaewMoKyZTgquSsBcW7lpVyfVUO4SRQSYSfV6CgMc?=
 =?us-ascii?Q?dRWdxRjRgyvv/TXxW7Z5b4ckM1qSXy9eK8avJPXCCOepzqIsVk+nk5tMp2Po?=
 =?us-ascii?Q?1MRd8cm6/Zz5ouGyRLbFn8HcmPA6kEmyR2ht681n?=
X-MS-Exchange-CrossTenant-Network-Message-Id: f077595e-006b-4607-b57d-08dcce468536
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Sep 2024 07:35:46.0956
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: t4qqlPp70jLMDt/7NwBashU7IIXbWlSoHtwk+hE5vMWbkqWQQ5bPTl0Tsv33QaHX2qAZ63oY/VcD2oQOTOR0KQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB7294
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lham7DaR;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.198.163.19 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Tue, Sep 03, 2024 at 11:18:48AM +0800, Tang, Feng wrote:
> On Mon, Sep 02, 2024 at 10:56:57AM +0200, Vlastimil Babka wrote:
[...]
> > > If we really want to make [37, 48] to be zeroed too, we can lift the
> > > get_orig_size() from slub.c to slab_common.c and use it as the start
> > > of zeroing in krealloc().
> > 
> > Or maybe just move krealloc() to mm/slub.c so there are no unnecessary calls
> > between the files.
> > 
> > We should also set a new orig_size in cases we are shrinking or enlarging
> > within same object (i.e. 48->40 or 48->64). In case of shrinking, we also
> > might need to redzone the shrinked area (i.e. [40, 48]) or later checks will
> > fail.  But if the current object is from kfence, then probably not do any of
> > this... sigh this gets complicated. And really we need kunit tests for all
> > the scenarios :/
> 
> Good point! will think about and try to implement it to ensure the
> orig_size and kmalloc-redzone check setting is kept. 

I checked this, and as you mentioned, there is some kfence and kasan stuff
which needs to be handled to manage the 'orig_size'. As this work depends
on patches in both -slab tree and -mm tree, will base it againt linux-next
tree and send out the patches for review soon.

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ztqww1HBGpopK5kW%40feng-clx.sh.intel.com.
