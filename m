Return-Path: <kasan-dev+bncBCMMDDFSWYCBB7PEZO7AMGQEISMCRLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id C2D73A5F923
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Mar 2025 15:58:07 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2ff82dd6de0sf1895814a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Mar 2025 07:58:07 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741877886; x=1742482686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4X/ETnrGOgSz5D0A7l6OGPL/rKsdZXBNrKTZLGhZU7w=;
        b=F3cMZ8XZpA9GubLJx/cYRMBWDQLoicjGP3BrgXvja7FeVXWVX7c5lS+DymCY/8kaZh
         Fu52H6rowE/q26hb9bZHAxIwkNRC9lCPcuGhZbJWWDWMPj+tpYlyPkdD4N2xkNHjWnUc
         qnwZLejfJK3iTdqPPwMVLHSNmTu44krddRNLh4odmXHvhnT7Ff2mBcF0LKDW2sMgVkU3
         7uCpSrbPqYURKa6Ztehf2jfnzXUZyf9/alNPJg91NdInIoSOlS/De0zRwIe5+Nv69mer
         k3OgJdqFHzrwXI2rb6EXyydHsAyUTOhSvYnR1fKkWPixqqICRzCCnrDG9gPwJyB9b4/s
         SThA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741877886; x=1742482686;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4X/ETnrGOgSz5D0A7l6OGPL/rKsdZXBNrKTZLGhZU7w=;
        b=nZJf2KQ2Prg8uuVB0r/b873CSyG7/v9HiT6G6vugl06eax2Ze2DU/2MFCMqtVGPwLK
         SwTc5ZJ24TjtxQGHfsWDqt9lG+1FNkOQxWN/d0sbNnIH78yQfcXYMbdSd+U8POOGBN0d
         aR9om5z/2mPJVX3wPJXdyWjZKmdKGqtFXPFMnqolpSE8GNL6QbQE+lcqyz+TwAWXlGWA
         E6OiEEO40VANc9ZVQUym3Q4YqWZzQhD6w3e16ZpIei76MZoiIaDl7H5df3T2OZ8aWzBx
         AgRZ1aNDHhdodo3SidmQx+o/X222yb8FUdMJLTgN3WJdGHtUQLO5ByOERqe33YfTnliH
         lwVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXoGDIUtyuSioMfvnK67pGTrnb5pvKyYH2mMl2SBQnS8Va5OCepFSh1oQq50smwL5sdvu0OiA==@lfdr.de
X-Gm-Message-State: AOJu0YxGGoIabLBRmH51TbF3yW049ckubqlUVtBvVv1VUEkI3AxKfBy5
	YxUCG0lJK3CCLM7RzunljXgTGPJknD7Z0ubLrjJaI5w/rKDw7+gO
X-Google-Smtp-Source: AGHT+IFBIP26vL+ZqxuEGR4pomxR9EOpSWfGBR4zT6+gGerj7w1V5J2TpFwMEkXsNgme2sIBMoCB3g==
X-Received: by 2002:aa7:88cd:0:b0:736:621d:fd32 with SMTP id d2e1a72fcca58-736aaae44efmr33900935b3a.22.1741877885736;
        Thu, 13 Mar 2025 07:58:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFgKQSmebSnqrBj/HUl44PGHhHMV9RppkEYaj4ykytN6A==
Received: by 2002:a05:6a00:6286:b0:730:9340:6635 with SMTP id
 d2e1a72fcca58-7370d963d19ls805785b3a.0.-pod-prod-05-us; Thu, 13 Mar 2025
 07:58:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtDiPx9kB8c9aPZYpLQHut/K0lG0juUh7T0IFRptkxo0O6bNekFPAD6JzaSKl5mPH28kFTmjrr8P0=@googlegroups.com
X-Received: by 2002:a05:6a00:928b:b0:736:5dc6:a14b with SMTP id d2e1a72fcca58-736aaa1ace3mr37176609b3a.13.1741877883640;
        Thu, 13 Mar 2025 07:58:03 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-737116e33b7si83555b3a.6.2025.03.13.07.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 13 Mar 2025 07:58:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: t617JMHqT7S+03Lx+1kLbA==
X-CSE-MsgGUID: MF2rpgH6S8mQKs41xnwQGQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11372"; a="42169078"
X-IronPort-AV: E=Sophos;i="6.14,245,1736841600"; 
   d="scan'208";a="42169078"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Mar 2025 07:56:57 -0700
X-CSE-ConnectionGUID: HK2TIh4dQH6P5wM8oo/SLg==
X-CSE-MsgGUID: E9vKw5DkSIeDS9sEwW2JwA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.14,245,1736841600"; 
   d="scan'208";a="126152959"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by orviesa005.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Mar 2025 07:56:56 -0700
Received: from ORSMSX903.amr.corp.intel.com (10.22.229.25) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Thu, 13 Mar 2025 07:56:56 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Thu, 13 Mar 2025 07:56:56 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.45) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Thu, 13 Mar 2025 07:56:55 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=At/jnnBFuTRl0X0YcTm4/XOaGmzDxqKWirv7BH1GSvx+vpAZeokuetn877FYPBRZvKwm72uEX2oq4XvQPDLC1MKzgYCzy0dklkrTWxKwU2AaJvHORxlDYjlftukWRSbVLlaP0G3M2CyNPxAFXGlYeSE5WiTtTXvH5ZlEqxxOym9fruoVo4s+3stFj4T2elmnsFzkSyOptBcDE4majiqFxaLDwjkiY5ZDkodd4fl9qagbmxG4JspHMprizmPbG05Be5NhUjwmqYKks8nSUVO9bSzbnGwC7gITNdnqwkIs2iteVjpF2Fp/ydwbYbrq8fwkm8fzXGeMYDWwXZW6jN+74A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SllR83UJovzdBijlIETqhAHdZ5gyvP2G3vBnB5dgoV4=;
 b=ansXPUOJ+WhykJAmorN43YFjEe1xO7R8e9ejp31JjwV7RIr7UB9/ngJgA/TNM1rscOb2PAfjV/tySQvoKA0jI8ze4NuBdmOp0kyVS1iE/F5zTj44LzFqEwj5kr0i48YT3oSgN4nUAuW4DMXldV1rr6BhmS21xyCfYeAwOiEO0tADObS4hpj6msz46Rr9fZOa9Ohtj283+VINmTkaG5+tCALgeBgJEKgJWjiMzgOO5uoFhS8iBPu8RIhhsuURYlPFFzrVCfRrbvzhk8hKQ+CojSrDwdpxPBlpVgFaWd3B5WZa5x6YKEMhZELB950ZgHJIvDPOlKhd4IoQwR5s9h7SFQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by IA1PR11MB7889.namprd11.prod.outlook.com (2603:10b6:208:3fe::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8511.27; Thu, 13 Mar
 2025 14:56:39 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8511.026; Thu, 13 Mar 2025
 14:56:39 +0000
Date: Thu, 13 Mar 2025 15:56:00 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Vitaly Buka <vitalybuka@google.com>, <kees@kernel.org>,
	<julian.stecklina@cyberus-technology.de>, <kevinloughlin@google.com>,
	<peterz@infradead.org>, <tglx@linutronix.de>, <justinstitt@google.com>,
	<catalin.marinas@arm.com>, <wangkefeng.wang@huawei.com>, <bhe@redhat.com>,
	<ryabinin.a.a@gmail.com>, <kirill.shutemov@linux.intel.com>,
	<will@kernel.org>, <ardb@kernel.org>, <jason.andryuk@amd.com>,
	<dave.hansen@linux.intel.com>, <pasha.tatashin@soleen.com>,
	<guoweikang.kernel@gmail.com>, <dwmw@amazon.co.uk>, <mark.rutland@arm.com>,
	<broonie@kernel.org>, <apopple@nvidia.com>, <bp@alien8.de>,
	<rppt@kernel.org>, <kaleshsingh@google.com>, <richard.weiyang@gmail.com>,
	<luto@kernel.org>, <glider@google.com>, <pankaj.gupta@amd.com>,
	<pawan.kumar.gupta@linux.intel.com>, <kuan-ying.lee@canonical.com>,
	<tony.luck@intel.com>, <tj@kernel.org>, <jgross@suse.com>,
	<dvyukov@google.com>, <baohua@kernel.org>, <samuel.holland@sifive.com>,
	<dennis@kernel.org>, <akpm@linux-foundation.org>,
	<thomas.weissschuh@linutronix.de>, <surenb@google.com>,
	<kbingham@kernel.org>, <ankita@nvidia.com>, <nathan@kernel.org>,
	<ziy@nvidia.com>, <xin@zytor.com>, <rafael.j.wysocki@intel.com>,
	<andriy.shevchenko@linux.intel.com>, <cl@linux.com>, <jhubbard@nvidia.com>,
	<hpa@zytor.com>, <scott@os.amperecomputing.com>, <david@redhat.com>,
	<jan.kiszka@siemens.com>, <vincenzo.frascino@arm.com>, <corbet@lwn.net>,
	<maz@kernel.org>, <mingo@redhat.com>, <arnd@arndb.de>, <ytcoode@gmail.com>,
	<xur@google.com>, <morbo@google.com>, <thiago.bauermann@linaro.org>,
	<linux-doc@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <llvm@lists.linux.dev>, <linux-mm@kvack.org>,
	<linux-arm-kernel@lists.infradead.org>, <x86@kernel.org>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow
 computation
Message-ID: <qacbgkfbfqylupmoc7umy4n5pdvpdp7hrok7hqefhamhrsnhhm@4e2qucovduw2>
References: <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
 <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
 <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com>
 <qnxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd@czthvwkdvo3v>
 <CA+fCnZdUFO0+G9HHy4oaQfEx8sm3D_ZfxdkH3y2ZojjYqTN74Q@mail.gmail.com>
 <agqtypvkcpju3gdsq7pnpabikm4mnnpy4kp5efqs2pvsz6ubsl@togxtecvtb74>
 <mjyjkyiyhbbxyksiycywgh72laozztzwxxwi3gi252uk4b6f7j@3zwpv7l7aisk>
 <CA+fCnZcDyS8FJwE6x66THExYU_t_n9cTA=9Qy3wL-RSssEb55g@mail.gmail.com>
 <xzxlu4k76wllfreg3oztflyubnmaiktbnvdmszelxxcb4vlhiv@xgo2545uyggy>
 <CA+fCnZdE+rVcoR-sMLdk8e-1Jo_tybOc7PtSp9K6HrP5BEv95g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdE+rVcoR-sMLdk8e-1Jo_tybOc7PtSp9K6HrP5BEv95g@mail.gmail.com>
X-ClientProxiedBy: DU2P250CA0018.EURP250.PROD.OUTLOOK.COM
 (2603:10a6:10:231::23) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|IA1PR11MB7889:EE_
X-MS-Office365-Filtering-Correlation-Id: 091e5ac4-e2db-47d6-97dc-08dd623f4225
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?LzVtR1BjUkV6U3h0RkFNVzlsaVQ1QzFmaFRSK2ZrenJ5T2I2dEYrNkFRcDFE?=
 =?utf-8?B?NFB2VHNQV09CZysyMzNKcFEvK0FYVENPamM5cXpIcXRLbGNnaWh2TjZUL3lH?=
 =?utf-8?B?SU1KQzdoZnpDZndZTlZOUElZY2NiWkM2Q3JlSWQvTHRCa2lOUGJUYjNNWDU4?=
 =?utf-8?B?eFRuZWZHNEVMS2dVK2RjYUdmVS9oUmFra3hKUUNTSmE0bXpvRU9vOTR3MDhj?=
 =?utf-8?B?N0c2WUl6eGh1cURvZUZiWVQ1elVDOVJDSnIrNCthNVIxcnZ3NzZNbVdJUDIy?=
 =?utf-8?B?WmdnLzA3RkYyMFdWSTgzTkg4TjBVL0d0djc1dG93eE9VdHhyNHNTOG15VTVt?=
 =?utf-8?B?Mkx3UlpWSlhtMU5Ld2l0VHkzRlJiWnBobllDTnp0dTFlQVpMekNGWG43MXVz?=
 =?utf-8?B?K3RsZjB5Q3JGK3dWYk94Zld3aG5iN0x2bXZJUlJoVzhpTytSYzY2THF0VXFK?=
 =?utf-8?B?VnJqK2tPQW04RHVSUU50eFJMR2dBKzd4Z09hQzB2V0ZsSk9hczZtb3lBdEpa?=
 =?utf-8?B?Z3ZIQmRWaXhnakJ2TXhYVk45ZUhKeityUHFyNDNTbXR0STQ1c2lzajZxR2xT?=
 =?utf-8?B?TXFqNTlLQlIrS1Q1Z21PK3dxc0piMmdpeFJpcnAvT0dZN2tXd25wbTJBMUlX?=
 =?utf-8?B?Q3JEMStUZk54UThIakRoN05Qd0ZKSFd5eHU2czdZeStLNi9uYVViUm5YcnhI?=
 =?utf-8?B?dEgyaHAwZ2dzN1BxNWR3ZEZYZExQSm1yVVVlU0hNRTNacUIwV25OajFTQ1Vl?=
 =?utf-8?B?azk4Qk9rZElBZ1gxQXRYM2l0U01PTDB6UmtaUkZjQTRVUG5veEhQL2w3Zk43?=
 =?utf-8?B?ME9yWXBGeUhJL0hGNlpNT1hrQWNvSmNLZ25Vb29Wc3VFN0ZCdWN1LzcwWVV0?=
 =?utf-8?B?V0p4dFlLNDcxSWR0Z0kyUTVzNkM2b29icTZPalZWV1pnM2dEN0w4U1FCQzNK?=
 =?utf-8?B?V0hmQU10ZWVwTm5PTXBxQU45WWZnR2VLVGxZcGU2VTd0QnNuWGNLZzYvWm13?=
 =?utf-8?B?LzFXWDlYeTFCUnlNWTBvcHpZcmpaei9mVFRIeFNZWCtrV0VNR0RDdnkvWTJi?=
 =?utf-8?B?SXY5b2h6Zzc5VkxVSVpVNFd0enh0aG5GQ0Y3VEpFYVVialJyVktxTlZLK2dJ?=
 =?utf-8?B?d1hlTG1EdUFMNW91TXo4MzJud1RrU0Ztd2ptZEpVNWQ1YXlSYVhkOW1rQVpz?=
 =?utf-8?B?T0RDLzFWWUpRdUk3YytFd0VIbEg3TVNINHk1Y1JOWVBrcHcvOHhMOFFpOXIy?=
 =?utf-8?B?ZU44SGdwdHd6SVFjK3BKL1dYbkRQei9aVC81VXFtMFVYOWkwcFFYVzNvakRz?=
 =?utf-8?B?eDRXUlNvZGxPSTlJekxXbkRnbE4rZWVSUCt6SFlUOGhkMlNVSnBMK0hldUph?=
 =?utf-8?B?QUNqNS9XUEdDVXJVaEdtdlUzcE5xR1FXcVM5QWl0RVVXYUVYN3kwa2pTdnBR?=
 =?utf-8?B?azNXRG5FdDJOVzJLQVFpK2U5VmFvQlBvU2tIUTZwRkZzV3BsdmhraGR1enVh?=
 =?utf-8?B?U00xK0NiMVg3ZTc3MUlEVzRvSm5NYXhLNXpoYndCMlRLVXZOcTQvWWoyUUJP?=
 =?utf-8?B?SWlyTE5ROEdnNi8wS09HMzVyT1E0NHhIKzk0VlBZcEYzWkIyaWFtMFAxTUFr?=
 =?utf-8?B?akhZSkE0OGdSZWRRY3FBM3pDQVh5SFc2dFdHQnFqdHZYSDZjT3Y3QVFDY3lB?=
 =?utf-8?B?VWl2alRKKzJkL2lMdU1FZG12dnRxV0RHQmcraVc2d1NQZjJYSVpiWW53cWdY?=
 =?utf-8?B?NC9VVVhYY1Y4ZnZYT3BYNS9LZEV1WVBsTG1kakRMTGZPdkx0eHRwMnozeHFT?=
 =?utf-8?B?SmlqeCtzUWtJU2trVzdRNXJHMCt2Y2NZZUg3ZWlkQU1jQnBKSm8wOXdsZWt3?=
 =?utf-8?Q?m45oehChbEcbn?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?cEdHb2E5c0FiYklzRjBaUHNBQURFd2hmRUtWd2xyYXhaT0w0cWFqelJMcGdt?=
 =?utf-8?B?bk9sZk9Qb1JZQTlmcFFxMmdxMDdGZWxHTmZldm5SWWtiM1VEUndNdklzZm90?=
 =?utf-8?B?NVM5Ykd5Um9weGdlc3lsU293RWNOdEl6d2wzQk45UzNXTUhRQlJIVmgzenUw?=
 =?utf-8?B?SURpeWRpdDlsYlM5dFQrWk15a0kxSncxZ1RLOWlPMlNCdjg3eWhRcjJ6QTZE?=
 =?utf-8?B?NFZLM0crcE1BM3FObFR5QXlQOUhrWlpBV2tQNk83NlhYcmhlaDRHTitZUTNw?=
 =?utf-8?B?blVPWDdtZUF3N2VuR1pLWm8yUDl3TGo4MjZDRjBqMDRqVklqU0Q5ODhHaTB0?=
 =?utf-8?B?bzVFeThEaEJhV2dNU0dFRUtTVkliVThaeExOeWlrOW0xbk1XYVhOVXZGdnFO?=
 =?utf-8?B?RXZDUG1UUU1SY2NJVVhnTVJ2R2UwSkVZak9KM3cyL2lBR3kzdXVHNk9ENkUw?=
 =?utf-8?B?MWt1MlN6aVFycHlKQk44b3ozK3BVRjN2aHhYVE1GVCtFejJvRXlEVERvZEk4?=
 =?utf-8?B?SXRHZ3VIMXB1dTcyZjhURHhpWHpxOEdBTDFoMzEvUSt1alA2bjczOTRaYmpS?=
 =?utf-8?B?NVFOZStSRVlNb0dWbXVlUC9mRkVHNmt0cTMyVHQrVjZFWXlaL2czUk1oL2Jv?=
 =?utf-8?B?SGJMbHArTk8zZUhCQVRPVU9qQTI2aWpGaHg5dmlTWW5oR3QvYUo2ZXgrZGJX?=
 =?utf-8?B?bUxodEFUT0QwWGkvNloyZmFFcTV0emhYWnRuQ3BkanBzWXFIYVBUK3BFdkJC?=
 =?utf-8?B?M1FzSDZ4RUhZNzNFU2RDcmtvUDgzYTRaQ2hDbDlDK2ZoZnB1SEIzWjVnOTM5?=
 =?utf-8?B?VjAxcWVkMXhHTTFOU3VmN2RrZXVISTVBTnV5NGRBOEdQc0xyczBycTlWUWoz?=
 =?utf-8?B?clpzK2F6NFRBRUNGRTNmaTdNcjdKVEVqcEZuRjNnZHBVUUgzTmpXVUNmWjEx?=
 =?utf-8?B?eENoN2thN3RlcW5XSDZpTjlkY3VLUjVTQjFuR1dpQ0tNbUE5cHZJSCtpVFV1?=
 =?utf-8?B?R2tWUHhnTUJOUW1sWGwxcEt2UXVFRjNVNnRORVQ0VnlIaU1WbkpXWmtCYWtZ?=
 =?utf-8?B?SFJyQm5aRko5OHNhN3ljdDlUK3E5aHQ5d3VCUkpJcWVuMk9mTks1VFFYNWFp?=
 =?utf-8?B?VXUweWpJYUJLY3ljd1pjQXB0bENGaFBzSXJDK01ET2lUYXhsNFZYcEM1WFIr?=
 =?utf-8?B?ZGF5RGR3Nm05VUZEcW9YZVlXa1JjKzFubWVjeFdCYmVHVHFQZEdzZzhoRmVF?=
 =?utf-8?B?RzROYWcrcHZidVRmMWV4aDlWK3JXVlZ4WkJDK3BxcmlFSEVCQmZsWEZ4eDk4?=
 =?utf-8?B?MUJ3ZWFxc201WkRuY0lrNVJNdU04L0R2UDI1ci96WGJGb081WWlrM2hEYlpv?=
 =?utf-8?B?cTVMTGt2L0tpUlFrRHVGZ1ZKWTU2K1JYU2tjVjQweGpJTHExbmo5ZDFmU09E?=
 =?utf-8?B?bTBqWG1UK3JnMGNiL0Zuc3Jna1lYcXNmeGY4eEVxU1RrblVtMGpBZTRnOHFQ?=
 =?utf-8?B?Z1hOSS9wTGFuQ0dHSThNTWZiUldkaklsRXVoZkpvclozd2R3TG0wZ2JHbmlH?=
 =?utf-8?B?YlVYeHJ2T0ZDc2lTdjhOZmI1LzZxYml5Qk0xYWoyYTBlNVVrRC9QWnBHNzJt?=
 =?utf-8?B?RGdJMGlNNlRKMlRtMU1tR0JFY2ZjbjdlbXhKekFlQVlTbTZ4RFp5cGhKdndr?=
 =?utf-8?B?VE1qZDFLK0M4TGx1QjZYcFdjcnJ1VmJMM0g4OHBzQ2hIWWtISi9jazZONi80?=
 =?utf-8?B?QnF2bis1TjFTNGNjWmxWdldkVFJxMytLOEg0RHFxa3dCUVk0dFFRY2JQTG9Q?=
 =?utf-8?B?L2Rhc2E2YlRNREphQTFZUHlMSUozYldxU3piTEpITkNvUnd1UnRHNUw0ZUgv?=
 =?utf-8?B?RU9iUWZQRHAweTV0NURrdzhTbGJHbkVkR0RzRk1CN21DeDZ4dFl5ZmdkSFlC?=
 =?utf-8?B?YlRnODVFN2RGdUdQUWNzblFidE54eEk3YTNhTmEvMGZWRDVUc0RkL2l0ZjNY?=
 =?utf-8?B?eThWTS8ra2VjVHdSTzA2aHRrWklFdTE4eXFpMEdyOEF4RXNYU05jOS9TMWUw?=
 =?utf-8?B?TlVTdFpua1pSQlJzeWgxVDRySTVUSUoxdjJoRnR2c2J4M2NOSXd1enp3dXlS?=
 =?utf-8?B?Z0tlOTYxTGxsOVloTUdrdS9YU1dpRm1sNkp0dXJOUzNDdzEyaElQN2FEdUtB?=
 =?utf-8?Q?lrNBja8CdMfvJwvS7fJhsNk=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 091e5ac4-e2db-47d6-97dc-08dd623f4225
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Mar 2025 14:56:39.1191
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Ezb2HHR9qIz+yZvbV/wATed0lz3eodz8Blv51kJEMCwMJvFqlKduKWVRTVBwux1MiEQ3A49MeQZLUAO60OkuV3HgHOyADUnJ304ZSyD0yrU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB7889
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ZydzKugJ;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.19 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-03-07 at 02:10:39 +0100, Andrey Konovalov wrote:
>On Tue, Mar 4, 2025 at 3:08=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> But looking at the patch you sent I'm wondering - are we treating the ar=
ithmetic
>> in kasan_mem_to_shadow() as unsigned?
>
>The shift is signed (arithmetic). But for the addition, it doesn't
>matter? Adding an integer to a void* pointer should result in the same
>value, regardless of whether the integer is signed or unsigned.

Yes, you're right, sorry.

>
>> You wrote that all the ranges will
>> overflow but I thought we're interpreting the arithmetic as signed - so =
only
>> positive addresses will overflow and negative addresses (with bit 63 set=
) will
>> only be more negative thus not causing an overflow.
>
>Ah, yes, I see what you mean. From the C point of view, calculating
>the shadow address for a pointer with bit 63 set can be interpreted as
>subtracting from KASAN_SHADOW_OFFSET, and there's no overflow. But on
>the assembly level, the compiler should generate the add instruction,
>and the addition will overflow in both cases.
>
>The important thing is that both possible shadow memory ranges are
>contiguous (either both start and end overflow or none of them).
>
>So this was my brain converting things to assembly. Feel free to
>reword/clarify the comments.

Right, I focused too much on the signed aspect. Treating everything as
overflowing sounds better, more unified.

>
>> That was my assumption when
>> writing the previous checks - we need to check below the overflown range=
, above
>> the negative (not overflown) range, and between the two.
>
>It could be that your checks are equivalent to mine. What I did was to
>check that the address lies outside of both contiguous regions, which
>makes the checks symmetrical and IMO easier to follow.

I drew this out and yeah, it looks like it's the same, just grouping the lo=
gical
expressions differently. What do you think about incorporating something li=
ke
the following into your comment about the x86 part? :

	Given the KASAN_SHADOW_OFFSET equal 0xffeffc0000000000
	the following ranges are valid mem-to-shadow mappings:

	0xFFFFFFFFFFFFFFFF
		INVALID
	0xFFEFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL)
		VALID	- kasan shadow mem
		VALID	- non-canonical kernel virtual address
	0xFFCFFC0000000000 - kasan_mem_to_shadow(0xFEUL << 56)
		INVALID
	0x07EFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL >> 1)
		VALID	- non-canonical user virtual addresses
		VALID	- user addresses
	0x07CFFC0000000000 - kasan_mem_to_shadow(0x7EUL << 56)
		INVALID
	0x0000000000000000

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/q=
acbgkfbfqylupmoc7umy4n5pdvpdp7hrok7hqefhamhrsnhhm%404e2qucovduw2.
