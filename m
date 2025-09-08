Return-Path: <kasan-dev+bncBCMMDDFSWYCBBM6Y7LCQMGQENUQXVEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id ADB8EB489AD
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 12:13:08 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-627eaf68bbfsf1154462a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 03:13:08 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757326388; x=1757931188; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZTE4HaCf6FU0Dx2CdxbmmQHOuMgqxYyphneLVl9N8zY=;
        b=hzlu8NGVM1aW2krBeCwQS9v2rpI9OBH5X1gfMXTIodeLEnpIuZMPMdye9Fm72Ujn/P
         Vv/RJu5xlhpMSuKSvJCbMuNt82JKGiwpV/hW2n6jiRmOUGNCdM950hZI8WzD/X10cP12
         naNpaH4udFWy4l7RgI5//wYWu9Nvpkn7xWp3SWjeETnQO1Lvq70/smCVRBnqPYJ0i2/p
         AjUQ3BWrKWuzhFWRr4ryikAAQ9gBF8MR80NSqszJTkrGHzbqjWO9H2d6zvtsNvkuxkgg
         9eEV4QklGJdKez5QXsMgdIMkc7thVKnhdKfdb1+hj0Wc4MxGrK5ypYJcv8Mrcw8bt7SZ
         tFLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757326388; x=1757931188;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZTE4HaCf6FU0Dx2CdxbmmQHOuMgqxYyphneLVl9N8zY=;
        b=aueXkdMMnwC9goca0ep5q+IRPDHlfZJOaeSuXY+w/yXqypDXM8oC5JHZMX3Xa6GRbA
         Cr0SEYS7V3KXDFIgZAJT9YEmYS/gGn4f9dA9aX6+ANysK42MSMRAfAbsVnOAWWEZLunQ
         UWabEJZp+W0SggIdauT4Eax3Y/sRZ94YUVjOtf+rshJWMerf32irJ4FCRzGeZVi7NLvw
         7QDjR9S/eaM0G+Wcv5qIQVLGZCW2olmGsmNM0eaA2TMpoKqC5zWGQqsB28F/n2cWqUIV
         WySD9B79OnKtC00ELfMZDS2wl6mG7zka7zQiMHjy1t3vcgkEz2mXgFeHY/2mb6KiuFm3
         RFQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWKYfA7wnU82PRVqhyydoPEKAEDTvH1UOI/rhifkSdkI8lPMcVIx6Osugemw7/V4R1hjAq2wQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMQCiSXBEQdd846GFelR2EE3lg4R2qnuSHOvDkt9sanCCr1+1Z
	wjcERgIVvy+cwsF6fBmJYwi3gO7RAC+8sLcNLjZpDj+ZvQcE3QsstVSF
X-Google-Smtp-Source: AGHT+IH9gQ/FkK+I3p9hwOdz8MDJwxYFkfHP5KhvXhf9NMoeP69vHlMyeiOyLg3MUURXXYJU7kYnNw==
X-Received: by 2002:a05:6402:3496:b0:625:fd40:c5ac with SMTP id 4fb4d7f45d1cf-625fd40c6f2mr5716339a12.35.1757326387667;
        Mon, 08 Sep 2025 03:13:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd69gfBFQsCAIvQ5sQ6wATWXum6aIbYTxqxE31qltRKcVQ==
Received: by 2002:a05:6402:46d3:b0:62a:d0c9:c7ce with SMTP id
 4fb4d7f45d1cf-62ad0c9d214ls319030a12.0.-pod-prod-04-eu; Mon, 08 Sep 2025
 03:13:05 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV3pKBVcDsMAAmaK+Z8DlEFBUuV413NYAORhyVWZfnw+aUjnPEvcxP5w/Ln8gar4jIJ4a27Q1HwL0U=@googlegroups.com
X-Received: by 2002:a17:907:61a8:b0:b04:74d1:a548 with SMTP id a640c23a62f3a-b04b13c1729mr518328466b.13.1757326385052;
        Mon, 08 Sep 2025 03:13:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757326385; cv=fail;
        d=google.com; s=arc-20240605;
        b=MXwrtQ0ajBHlP5O8ci9R/afMnInelVnABrXTZ/NaGqRVNhE0TIIn9L+zuV0+S0i8VD
         LHUgk4IR0g0sqg0CyZab/OHQTeCJqwi9ARiRrgOio5Sj656PwwPTiTIM8Z/2Hdxfe44e
         5pct5PA5wNjDrEObAoZQiB+yENj96g8pS0QJ/H66lLYtXshxOve7XnGPFbCrG8cv6I0q
         1r624Be0uGQrB15Vvl/exkivYuBScnlgFVHUht7W2dexUCTMOWgKNyM3wyPVs7yr8uCF
         yqTa4V0fa9JfikibHYMQCH094ZYkNgemLYbm3w8ZUkV+JWjhGlkoBHx03vzMtgtBm3Uw
         NLUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=DvUYqL9o/y8Kfnr8mVVqHhIYQ5BX6R6wR/K6AF/Cbmo=;
        fh=Wufhi7rrwD20YmLOonxnFQWKE9Ef0FLnk1Jd8nrbCPI=;
        b=dI7vdq3ov+uY1BPVPoTx+ZHLW2535BoHee+/3f0cr9xeVsIPo4GDFJfiPF+oIi8fK8
         8KcY4LYNYF8R6X2xA8Hi6XsUr54TNykokNlwbL/CD90Z4dxVyBTFAzFpqA38vHcZy70R
         cooV23nUvpNFtzltcxS5nXvgwkbzTBU0wlPsSDe78Im0JoSY69vppJ1KrXtLa0pjyYAL
         nKaRHl/H7EDK9HB+QM+Jx52sfkHC7e8Fz+nX7LZEHj67SpI2FiA033uVW3v06i93MYsC
         Fg4AZROePu6pSmHFhq7YDq4Ak7B9HnzpzZ/0kAwKKBDmRvrOlE0lDSj01KU2Dg+DGwcN
         5/ng==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fV5Tim1z;
       arc=fail (signature failed);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-aff04cdab8csi51204866b.1.2025.09.08.03.13.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 08 Sep 2025 03:13:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: tATqU/8UTCCk9WEAl02CHw==
X-CSE-MsgGUID: Wy1/lwhCQ/2LSehhsA2z2g==
X-IronPort-AV: E=McAfee;i="6800,10657,11546"; a="58619067"
X-IronPort-AV: E=Sophos;i="6.18,248,1751266800"; 
   d="scan'208";a="58619067"
Received: from fmviesa010.fm.intel.com ([10.60.135.150])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2025 03:13:02 -0700
X-CSE-ConnectionGUID: szq24UfkSaq9ZdIgUrgELw==
X-CSE-MsgGUID: e8yuTRAFQjWqMpM1WR7vag==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,248,1751266800"; 
   d="scan'208";a="173546511"
Received: from fmsmsx903.amr.corp.intel.com ([10.18.126.92])
  by fmviesa010.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2025 03:13:01 -0700
Received: from FMSMSX901.amr.corp.intel.com (10.18.126.90) by
 fmsmsx903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Mon, 8 Sep 2025 03:13:01 -0700
Received: from fmsedg903.ED.cps.intel.com (10.1.192.145) by
 FMSMSX901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Mon, 8 Sep 2025 03:13:01 -0700
Received: from NAM02-SN1-obe.outbound.protection.outlook.com (40.107.96.53) by
 edgegateway.intel.com (192.55.55.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Mon, 8 Sep 2025 03:13:01 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=uQ3NsFdp2q0xRhEzj6opmKO/Bf10fsnSsZzfLiOQ3LE3jsssw0DgibdRF8Ax+XspD4zY9ISTPL2UABjPQbeV8rtulTeuPUTAvCtQJpgGalKm9QXmtA/BXk0O0h4vGyOSxvq0OkXOJNdcsknIPA6cWq1NXaxQKMnkVUXpjuqWzLMD6loT4Dn64YeJGztTOb7a9mo29nJa3rOUQC0lzESWQIWKw/uFMXdd6/xRSOdiA8S3XuF8722SA9aNg0tTZE8lX7H1Mg7Qppxj1p1fMTJVFDL2KWNEl/3H6raUoedq4BhdTOg3refkwoy18o9PfAjXQpq2xgWn1DMMdCq42zQ3uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=DvUYqL9o/y8Kfnr8mVVqHhIYQ5BX6R6wR/K6AF/Cbmo=;
 b=wPYoLdo7lp0AQ7wKbBJp4k+euqeCNucNS4jr38OeKUk4/IqAMvliLFdIlfnlD01S2cr5FTUkl/GtRa5rTYfXppfg/WXFEOLH3shbkLlpxbE7zHXabqHoGFgdNCmCIPIRvE5K03Pl+p7KOfKDCNcCVozgYaFKtqQ84dnbl/mFO3yoA1tPdWSQXW6BV16ko48mDuAJo+HQ4aspXDGwi1h3Z0PFIAlEOwV7ieAyzO4gm0fHN1dYGcF0bxW/Lgf8z8VonF6t0gVnVqm1wQUV3p9IZQUrOp2E70+oE2EZAa68uDJVB3tjbb35T7SYMmjW0Fl3u0d+nTYjfbeE+K6F+uouWg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by PH7PR11MB5795.namprd11.prod.outlook.com (2603:10b6:510:132::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 10:12:52 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%3]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 10:12:52 +0000
Date: Mon, 8 Sep 2025 12:12:35 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <sohil.mehta@intel.com>, <baohua@kernel.org>, <david@redhat.com>,
	<kbingham@kernel.org>, <weixugc@google.com>, <Liam.Howlett@oracle.com>,
	<alexandre.chartre@oracle.com>, <kas@kernel.org>, <mark.rutland@arm.com>,
	<trintaeoitogc@gmail.com>, <axelrasmussen@google.com>, <yuanchu@google.com>,
	<joey.gouly@arm.com>, <samitolvanen@google.com>, <joel.granados@kernel.org>,
	<graf@amazon.com>, <vincenzo.frascino@arm.com>, <kees@kernel.org>,
	<ardb@kernel.org>, <thiago.bauermann@linaro.org>, <glider@google.com>,
	<thuth@redhat.com>, <kuan-ying.lee@canonical.com>,
	<pasha.tatashin@soleen.com>, <nick.desaulniers+lkml@gmail.com>,
	<vbabka@suse.cz>, <kaleshsingh@google.com>, <justinstitt@google.com>,
	<catalin.marinas@arm.com>, <alexander.shishkin@linux.intel.com>,
	<samuel.holland@sifive.com>, <dave.hansen@linux.intel.com>, <corbet@lwn.net>,
	<xin@zytor.com>, <dvyukov@google.com>, <tglx@linutronix.de>,
	<scott@os.amperecomputing.com>, <jason.andryuk@amd.com>, <morbo@google.com>,
	<nathan@kernel.org>, <lorenzo.stoakes@oracle.com>, <mingo@redhat.com>,
	<brgerst@gmail.com>, <kristina.martsenko@arm.com>, <bigeasy@linutronix.de>,
	<luto@kernel.org>, <jgross@suse.com>, <jpoimboe@kernel.org>,
	<urezki@gmail.com>, <mhocko@suse.com>, <ada.coupriediaz@arm.com>,
	<hpa@zytor.com>, <leitao@debian.org>, <peterz@infradead.org>,
	<wangkefeng.wang@huawei.com>, <surenb@google.com>, <ziy@nvidia.com>,
	<smostafa@google.com>, <ryabinin.a.a@gmail.com>, <ubizjak@gmail.com>,
	<jbohac@suse.cz>, <broonie@kernel.org>, <akpm@linux-foundation.org>,
	<guoweikang.kernel@gmail.com>, <rppt@kernel.org>, <pcc@google.com>,
	<jan.kiszka@siemens.com>, <nicolas.schier@linux.dev>, <will@kernel.org>,
	<jhubbard@nvidia.com>, <bp@alien8.de>, <x86@kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-mm@kvack.org>, <llvm@lists.linux.dev>,
	<linux-kbuild@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v5 05/19] kasan: arm64: x86: Make special tags arch
 specific
Message-ID: <mjuxddfbpdvjpjetctqbs5kg4iz4ngsnwl5ovvv63k2gc3f2ir@n67fqqlnyuz6>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <7a85ceb0918c6b204078e6d479b85fef6a6c1768.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZecdx5QsYcwn6ZyNoOkQRqmonUmSmfiihYTF8Ws_0O9KA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZecdx5QsYcwn6ZyNoOkQRqmonUmSmfiihYTF8Ws_0O9KA@mail.gmail.com>
X-ClientProxiedBy: DUZPR01CA0047.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:469::16) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|PH7PR11MB5795:EE_
X-MS-Office365-Filtering-Correlation-Id: af827897-fbcc-4868-1387-08ddeec04569
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?Ty9RNHNzZG95TlNXaGdSUk1rV1dSaXd5bTcwUyt3OTNqQjBKdnpQRStSdkp6?=
 =?utf-8?B?ZzdYK3ZOWmtvNHNGelVqOHRWNkQ1UGRiaXJ3OWduMTN6T0NqSXU3Z3Q1QUYy?=
 =?utf-8?B?b0VxNXorR0NqQWx5eVJ0TGpwd29nTFB0OXZRVDZwV0VNY1lVRGFaajEwZ2ZG?=
 =?utf-8?B?a05TQmRUY3pYdXBHendlZW5oa0NoNHhHOFZQMFZTanJiQlNsUGdkS0xRSzQw?=
 =?utf-8?B?UHZsbTJFbVJaV2dIdzNMaUpxcnVCK0JTSEJCUmloWTRUV0U1cjVaRGp4MHFB?=
 =?utf-8?B?Y21Scmh6VkNyVUpEZk9kWVplWE0rb1BmZUI4Qm56MVZ0MEdDaHdTUjlSZnJP?=
 =?utf-8?B?ZG5CSTBrMWZRZUxuTzhCZG5WQTZoWmk2ajBQekJMRVM4emxRZ0tjemcybXd2?=
 =?utf-8?B?OEIvMXdHeUNWV0w1ZWs0REZKR0EyaCtacmVOWFlSVUJBanVLbzc2aHRDZks1?=
 =?utf-8?B?NzZuTFFQU1A0aUpKdGdFYlhkQTNnVnBqbjhacEJMcmdvR3RjNlYwSVdlUk0z?=
 =?utf-8?B?dkdGd2M1MUJZa3BiMFcyWmF3R1QxRWx2MnVxc1JVbXZRVzRhVTNZVDdXQjdV?=
 =?utf-8?B?czBteTh3VEg3OU1qZmRELytmcC9sYWwxYk9Deko5SmlJV3piL3NKZWdUVmxC?=
 =?utf-8?B?S1c4VGpvNHB2MmFKYUwzM1RBenhSWUwxR0U4aXFOcGliVUpFMlNmUG9JMDNI?=
 =?utf-8?B?d0xqRm80Yk1nOCtsY2FEQzJSYkkzNTNRUGNpQlFrZkdRUGhScDZ0Tm1wdnNa?=
 =?utf-8?B?ZWRXVEZGQmdmYzR6WCs0S2FRY08wVzdrWTJpT1ZhVVJleklhMFlEei9jU2dp?=
 =?utf-8?B?b2hieU9ZOWJxZy9seTR6a2ZkbkNDdU9zdENIaFNUZHQ4OW82eERUNXQvQXds?=
 =?utf-8?B?cmVsU2I2NXc4dExQQlUyamFYd2tGK0tjN0dHdUcyMTR5TXZJbmlZODMyTDBM?=
 =?utf-8?B?cGlKc3FJWGJtQUVoQTJ5eFhjL0RVRTVXWnIvTjUzdWZuR25MN09HRGxmMEw5?=
 =?utf-8?B?b3FzaUZCZklLVUgyNXE1QkZZMisrR3RmRGY4Yk14dEp4RUc0OWhXN1pmMjV4?=
 =?utf-8?B?aStmcDRoRGE3UG4wT1A1NmZwY3N0MzBSY3ZEOWZETEt3VGl5cXFzZGtYeGJh?=
 =?utf-8?B?NTlUL0JqMXNtSm9yL29lSGYwSElNQ0h0bTZXWGVqUlkzZEVQMXZYTnJ3ejFK?=
 =?utf-8?B?ZU9lRmFZeTE5U2hBNTY4RDAvdHpQTlVNSHBkVHpoUlh6RUh2YWVFVGJiUXpS?=
 =?utf-8?B?UGNUeXZ4RTRCdXBTazd2THRKT1BabU8vNGFxUnoxQko5MUg1N1E4UUVaSkZs?=
 =?utf-8?B?eDEwbk9pbjRJTFJmdWl4V1ErOGlLWGpPTVJsMjMzOHlKT21raEg5ajduQmhM?=
 =?utf-8?B?TGp3TlZvclI4VlNMQ3dEcGlJRFA3UkVackhJd05yU0gzcW1rbWg2SEFaSVl6?=
 =?utf-8?B?cjMwTDNVMzhEZ3lYZEpDSkxaaStLMkRRL0lXWVVRVVkwOUdKNkdwTmNMU25T?=
 =?utf-8?B?OWpkZlJ6bW9CeDZFTTFTeWNQWFduWTBOMktkZUd1cUt2dVlOS1ZCV1JOQ1Jm?=
 =?utf-8?B?TFhtWjlDSGo0dFFZa3E4eWNaL0l2Z0MzZ25KMlVwclQ4MC9GeXpXR2xHNWNy?=
 =?utf-8?B?SC96Z1pXYkRvT00rSGVOYTdnTm1pS2xlUHNnak8rdXhyV1BUVWxoYlB2cnVr?=
 =?utf-8?B?TWY3TUJsOThFVWY1YTBNNkxNOWVaSkFScGNGUnA2K2drNGpGbGl5cVZsY3Vo?=
 =?utf-8?B?YjQ2SFVaQmxPSWlSUnBDTksxQzJ1MnFlQUErS00reFNmZ0VaMkEzV2k0V0ZQ?=
 =?utf-8?Q?J/H5ejuP44p8bGtbWC90Qc1F4MkIDb8qwNDnY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?UkZGK1pRSjdEd3llS2J6RENYc0xvOXV4SW95MEJPT1p3eVJMREgzdWtyOXQx?=
 =?utf-8?B?ZzNUK3dlTkdJa2xIRUxScWM2SXpidHczYUhXWDNuNS90cHdVckhDQmxlZ3I4?=
 =?utf-8?B?OVN1QktvQXptdlF1eDlJZjlWTExFdWJ2akJiVmhpREZTbWZzdVdNcllaQ2JV?=
 =?utf-8?B?bUVSS29LdnR1SXo2cjFNVEFsa0tObzFsWHJhQWJjaGJHV0F1SkVQcXFwRSsr?=
 =?utf-8?B?OS9QZ0EvRXBrZk1YeVFWNXh2L1FJcndtUllQTTNwK05jeXlVcUh5ZjY2R0tX?=
 =?utf-8?B?UUVHbXpIc0lJbWRNUkdLajRCUUxqZ2t3a0Z5Mk5LcU9kbmtTdERENUFqNFJW?=
 =?utf-8?B?ckJyRjk1ZzlSbmFYZWh1cmpvbUlOM1B3ZGRIZTlYYTcrMjFPR3YrejdVbERo?=
 =?utf-8?B?SzA3ZFMvY1o1bFdVR2xnQlY4T04yMjVsemFQbW9MaWdydVh1SjVLeFAvNW1p?=
 =?utf-8?B?Y2JRdk1CaGU3RTZIWXpIdG1adnpmSEM3WS9LWWlZaDJUNDVFdEE0UVcvN3NZ?=
 =?utf-8?B?bHFGV2Z4TUFtVG5CeGUzQXh3S1QwNlZmY3QwZ1pIYnJRNVFwekxCRVIwZC9r?=
 =?utf-8?B?d3ZaSEdhMDhqZEQ2RU9FaTdtNWRhYk4wTjdoK1JNYURtclE5VDEyVWp2ZVA1?=
 =?utf-8?B?Y1BwRzdlSWMwSFlNZjUvc2hEKzE2REVsQjFPMi92N2NRU3YzN2tUYW05RnFD?=
 =?utf-8?B?VCs3UmxyOXNRR0kyWjJnZER2S2puQXRabFI0WVl1aGNtclp5SDFQU1dUM1dS?=
 =?utf-8?B?ZCtmQ0hLTVRaZXhmMHRuazk1bWRSVk5mR240TmV5KzdQdlpWdWEycDA2NUNG?=
 =?utf-8?B?eVByVUo1aTdlQ0svd3pJSEVjbVRWZCt2S29lR0ZCeC9OYnluZW9xL1VlZFJE?=
 =?utf-8?B?d0FSRlR4TzBCbUVmNXVYUkdNSDBpcWJoU2xub0JLSXl5TmdUOUVCeTkza1Mv?=
 =?utf-8?B?VmZWOVBCRzJCOHFkNXVJRGlSL3ptbDUwT1Q3eU5FQjJLYk1BOHhPUG5rR1Z5?=
 =?utf-8?B?UkpQQ2E4bnZSNGdQc2xZbGFxODFHa2pzb2EybjZGMmdwbnloTmhEUFlXcXlS?=
 =?utf-8?B?MEQvVUQ3dnJHalJnUlVTVWEzTDFwSE9Ndm9MUzQrYVF2NEJaSUFZSFFlYVo5?=
 =?utf-8?B?M0wzcThPejVpNS9haTB3MFF1V3lhYmhvQVh4Ymt0WFNxN05PZ2VvUCs5eW5B?=
 =?utf-8?B?WHhTNmdiR2wvMkpzdWRKdVE2V1FEbFZtYjN5WmgvdEtKQ2ZNeEZqaDhidFdR?=
 =?utf-8?B?elV5NHJwYWpyajIzbk9jZ1dWTC9kVFVycXErYjBTSk1vWEc1SjM2bW5aUEJ2?=
 =?utf-8?B?YmVLemxTMVRSRWkxWkxkdmRFbThTdG9LOUFlcERjYkFGalVTRTR5dGw5QVFT?=
 =?utf-8?B?NjN4Y3lvbTR4K3lzMTloK1RBeng0eFBkaXg1RG5aRVRra1J1ZVlTTFozT0Ex?=
 =?utf-8?B?SDFqaFI2R24rNW4rRmlhRlh6S2lCN3JtajliTDlzL0pzZHljNHRHZnlNOFV1?=
 =?utf-8?B?VVlMK01yYnhyM2w4Zk53bHUwbW43MHlqdmsrY0lwMVlIYjFLZnJsK1NFaVBi?=
 =?utf-8?B?allUeXg3MUpIRlplM2UyM05zeVNaVThEVzl6Zmp5Q0hCdXdSaExKWHgybHdy?=
 =?utf-8?B?UlBUMzlsM01Ka3Z0NzZIcmxZQlJKM2JHMFhvd2RGTzBUTHQ4VDhac3EvVXRj?=
 =?utf-8?B?TVJkV0ZwRE91T01sbnZBdFNHRURHVStIMUNOZGRGU1BpQ0lOVzhEMWd3Mi9j?=
 =?utf-8?B?bVkxZUdxSDdqUE5la1d3Mmw4aUhIeDhCZklyVU80c3FwWGRvYVR6bGpvQ0Ux?=
 =?utf-8?B?WWZkWHc4Z3M1WXAxUXFFWkhaa2N4eUJ5VFRZNUlJUmRYMG91M0drcUVPWWtT?=
 =?utf-8?B?MlN2dDNzaDBBb1QwSHg4WlR5dFpxcnQ5Uk9XYktRMlIzcnFtMmlnYXpQVEpI?=
 =?utf-8?B?TU05c0l2Z1FiU0k2Y2hJMHNqNTdPNGFpV2ZNNUtDQWNJVFF6dEFVWWttSWk2?=
 =?utf-8?B?Vzl5Z0hGSUs1Q1o1V2U4V2FpOHhtTG5zYkkvb3pRM2FkazZCQ3FIZTVEZEoz?=
 =?utf-8?B?bFd3c2hmdzdwbDZ3TW85ZXFNbWtlSUdrOUVkZlU1VURiUVFKMzNDWG1vaUh5?=
 =?utf-8?B?bnM3NjlxV0NONmRlYUpNTWZXWHo3MmxLL1FzT1NmYllwRkNlVWpKUGJGMXU4?=
 =?utf-8?Q?CrBH4euudSgvoXXjIf1TbI4=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: af827897-fbcc-4868-1387-08ddeec04569
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 10:12:52.4865
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: lbmhOa57ctadh/YENOffhjPokll1wVrJ4vZOoELfIIaJWgDNRXeDwd9sfN0nK1yAo3Tx++gAn8xzr2JfFnkiUNQg2fxNtCEzFL9lXX0+4Bg=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB5795
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=fV5Tim1z;       arc=fail
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

On 2025-09-06 at 19:18:33 +0200, Andrey Konovalov wrote:
>On Mon, Aug 25, 2025 at 10:27=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> KASAN's tag-based mode defines multiple special tag values. They're
>> reserved for:
>> - Native kernel value. On arm64 it's 0xFF and it causes an early return
>>   in the tag checking function.
>> - Invalid value. 0xFE marks an area as freed / unallocated. It's also
>>   the value that is used to initialize regions of shadow memory.
>> - Max value. 0xFD is the highest value that can be randomly generated
>>   for a new tag.
>>
>> Metadata macro is also defined:
>> - Tag width equal to 8.
>>
>> Tag-based mode on x86 is going to use 4 bit wide tags so all the above
>> values need to be changed accordingly.
>>
>> Make native kernel tag arch specific for x86 and arm64.
>>
>> Replace hardcoded kernel tag value and tag width with macros in KASAN's
>> non-arch specific code.
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> Changelog v5:
>> - Move KASAN_TAG_MIN to the arm64 kasan-tags.h for the hardware KASAN
>>   mode case.
>>
>> Changelog v4:
>> - Move KASAN_TAG_MASK to kasan-tags.h.
>>
>> Changelog v2:
>> - Remove risc-v from the patch.
>>
>>  MAINTAINERS                         |  2 +-
>>  arch/arm64/include/asm/kasan-tags.h | 13 +++++++++++++
>>  arch/arm64/include/asm/kasan.h      |  4 ----
>>  arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
>>  include/linux/kasan-tags.h          | 10 +++++++++-
>>  include/linux/kasan.h               |  4 +++-
>>  include/linux/mm.h                  |  6 +++---
>>  include/linux/mmzone.h              |  1 -
>>  include/linux/page-flags-layout.h   |  9 +--------
>>  9 files changed, 39 insertions(+), 19 deletions(-)
>>  create mode 100644 arch/arm64/include/asm/kasan-tags.h
>>  create mode 100644 arch/x86/include/asm/kasan-tags.h
>>
>> diff --git a/MAINTAINERS b/MAINTAINERS
>> index fed6cd812d79..788532771832 100644
>> --- a/MAINTAINERS
>> +++ b/MAINTAINERS
>> @@ -13176,7 +13176,7 @@ L:      kasan-dev@googlegroups.com
>>  S:     Maintained
>>  B:     https://bugzilla.kernel.org/buglist.cgi?component=3DSanitizers&p=
roduct=3DMemory%20Management
>>  F:     Documentation/dev-tools/kasan.rst
>> -F:     arch/*/include/asm/*kasan.h
>> +F:     arch/*/include/asm/*kasan*.h
>>  F:     arch/*/mm/kasan_init*
>>  F:     include/linux/kasan*.h
>>  F:     lib/Kconfig.kasan
>> diff --git a/arch/arm64/include/asm/kasan-tags.h b/arch/arm64/include/as=
m/kasan-tags.h
>> new file mode 100644
>> index 000000000000..152465d03508
>> --- /dev/null
>> +++ b/arch/arm64/include/asm/kasan-tags.h
>> @@ -0,0 +1,13 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +#ifndef __ASM_KASAN_TAGS_H
>> +#define __ASM_KASAN_TAGS_H
>> +
>> +#define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
>> +
>> +#define KASAN_TAG_WIDTH                8
>> +
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +#define KASAN_TAG_MIN                  0xF0 /* minimum value for random=
 tags */
>> +#endif
>> +
>> +#endif /* ASM_KASAN_TAGS_H */
>> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kas=
an.h
>> index 4ab419df8b93..d2841e0fb908 100644
>> --- a/arch/arm64/include/asm/kasan.h
>> +++ b/arch/arm64/include/asm/kasan.h
>> @@ -7,10 +7,6 @@
>>  #include <linux/linkage.h>
>>  #include <asm/memory.h>
>>
>> -#ifdef CONFIG_KASAN_HW_TAGS
>> -#define KASAN_TAG_MIN                  0xF0 /* minimum value for random=
 tags */
>> -#endif
>> -
>>  #define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
>>  #define arch_kasan_reset_tag(addr)     __tag_reset(addr)
>>  #define arch_kasan_get_tag(addr)       __tag_get(addr)
>> diff --git a/arch/x86/include/asm/kasan-tags.h b/arch/x86/include/asm/ka=
san-tags.h
>> new file mode 100644
>> index 000000000000..68ba385bc75c
>> --- /dev/null
>> +++ b/arch/x86/include/asm/kasan-tags.h
>> @@ -0,0 +1,9 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +#ifndef __ASM_KASAN_TAGS_H
>> +#define __ASM_KASAN_TAGS_H
>> +
>> +#define KASAN_TAG_KERNEL       0xF /* native kernel pointers tag */
>> +
>> +#define KASAN_TAG_WIDTH                4
>> +
>> +#endif /* ASM_KASAN_TAGS_H */
>> diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
>> index e07c896f95d3..fe80fa8f3315 100644
>> --- a/include/linux/kasan-tags.h
>> +++ b/include/linux/kasan-tags.h
>> @@ -2,7 +2,15 @@
>>  #ifndef _LINUX_KASAN_TAGS_H
>>  #define _LINUX_KASAN_TAGS_H
>>
>> -#include <asm/kasan.h>
>> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>> +#include <asm/kasan-tags.h>
>> +#endif
>> +
>> +#ifndef KASAN_TAG_WIDTH
>> +#define KASAN_TAG_WIDTH                0
>> +#endif
>> +
>> +#define KASAN_TAG_MASK         ((1UL << KASAN_TAG_WIDTH) - 1)
>>
>>  #ifndef KASAN_TAG_KERNEL
>>  #define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index b396feca714f..54481f8c30c5 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -40,7 +40,9 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
>>
>>  #ifdef CONFIG_KASAN_SW_TAGS
>>  /* This matches KASAN_TAG_INVALID. */
>> -#define KASAN_SHADOW_INIT 0xFE
>> +#ifndef KASAN_SHADOW_INIT
>
>Do we need this ifndef?

I just checked and you're right, it's not needed. I think it might have bee=
n a
leftover of my dense mode code.

>
>> +#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
>> +#endif
>>  #else
>>  #define KASAN_SHADOW_INIT 0
>>  #endif
>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>> index 1ae97a0b8ec7..bb494cb1d5af 100644
>> --- a/include/linux/mm.h
>> +++ b/include/linux/mm.h
>> @@ -1692,7 +1692,7 @@ static inline u8 page_kasan_tag(const struct page =
*page)
>>
>>         if (kasan_enabled()) {
>>                 tag =3D (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_M=
ASK;
>> -               tag ^=3D 0xff;
>> +               tag ^=3D KASAN_TAG_KERNEL;
>>         }
>>
>>         return tag;
>> @@ -1705,7 +1705,7 @@ static inline void page_kasan_tag_set(struct page =
*page, u8 tag)
>>         if (!kasan_enabled())
>>                 return;
>>
>> -       tag ^=3D 0xff;
>> +       tag ^=3D KASAN_TAG_KERNEL;
>>         old_flags =3D READ_ONCE(page->flags);
>>         do {
>>                 flags =3D old_flags;
>> @@ -1724,7 +1724,7 @@ static inline void page_kasan_tag_reset(struct pag=
e *page)
>>
>>  static inline u8 page_kasan_tag(const struct page *page)
>>  {
>> -       return 0xff;
>> +       return KASAN_TAG_KERNEL;
>>  }
>>
>>  static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
>> diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
>> index 0c5da9141983..c139fb3d862d 100644
>> --- a/include/linux/mmzone.h
>> +++ b/include/linux/mmzone.h
>> @@ -1166,7 +1166,6 @@ static inline bool zone_is_empty(struct zone *zone=
)
>>  #define NODES_MASK             ((1UL << NODES_WIDTH) - 1)
>>  #define SECTIONS_MASK          ((1UL << SECTIONS_WIDTH) - 1)
>>  #define LAST_CPUPID_MASK       ((1UL << LAST_CPUPID_SHIFT) - 1)
>> -#define KASAN_TAG_MASK         ((1UL << KASAN_TAG_WIDTH) - 1)
>
>So we cannot define this here because of include dependencies? Having
>this value defined here would look cleaner.
>
>Otherwise, let's add a comment here with a reference to where this
>value is defined.

I'll retest with a couple of configs but I removed this change and everythi=
ng
compile fine. Thanks for noticing that

>
>>  #define ZONEID_MASK            ((1UL << ZONEID_SHIFT) - 1)
>>
>>  static inline enum zone_type page_zonenum(const struct page *page)
>> diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flag=
s-layout.h
>> index 760006b1c480..b2cc4cb870e0 100644
>> --- a/include/linux/page-flags-layout.h
>> +++ b/include/linux/page-flags-layout.h
>> @@ -3,6 +3,7 @@
>>  #define PAGE_FLAGS_LAYOUT_H
>>
>>  #include <linux/numa.h>
>> +#include <linux/kasan-tags.h>
>>  #include <generated/bounds.h>
>>
>>  /*
>> @@ -72,14 +73,6 @@
>>  #define NODE_NOT_IN_PAGE_FLAGS 1
>>  #endif
>>
>> -#if defined(CONFIG_KASAN_SW_TAGS)
>> -#define KASAN_TAG_WIDTH 8
>> -#elif defined(CONFIG_KASAN_HW_TAGS)
>> -#define KASAN_TAG_WIDTH 4
>
>This case is removed here but not added to arch/arm64/include/asm/kasan-ta=
gs.h.

Right, I'll correct that.

>
>
>> -#else
>> -#define KASAN_TAG_WIDTH 0
>> -#endif
>> -
>>  #ifdef CONFIG_NUMA_BALANCING
>>  #define LAST__PID_SHIFT 8
>>  #define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
>> --
>> 2.50.1
>>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/m=
juxddfbpdvjpjetctqbs5kg4iz4ngsnwl5ovvv63k2gc3f2ir%40n67fqqlnyuz6.
