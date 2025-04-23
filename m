Return-Path: <kasan-dev+bncBD2KV7O4UQOBBYFIULAAMGQEVRFZATQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A904A98062
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 09:18:59 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-af8d8e0689esf6382939a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Apr 2025 00:18:59 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745392737; x=1745997537; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZlvzhHq8Z/ljBd/24846B2giZcDYXYM7hyevVvRN5Ew=;
        b=QHrY1kh3Za4C/L0G9AQZYO8Nw4Sj4ehmqg2M1qzINsMzYQp25cq+aA0amIWW3MK7Z1
         s924aKXeD66xRqswps6wLbocWmIHiYTSjnHVPRPMAAqYrcppcoWmV4DX5wnQI+GdT5xC
         xiVe+aTHKEDUhEdWQZJqWMWvWu6ieBZDxcA46ZHZK1SNFKRiomFEqI29aIUrHn/txv15
         MGkxgbd0nYN8pXeoF0wwjyKAwAi3ahjfvhtzzMLpkbeVNDflymwHlqI1nv2vlQs6DP9f
         V4ACFlFTV16E9zM8ocJYbqcknY1CsBx7KmRv5gYA3EyqgPWq77NV+EzlYZ2QVgw7xaxz
         ooFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745392737; x=1745997537;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZlvzhHq8Z/ljBd/24846B2giZcDYXYM7hyevVvRN5Ew=;
        b=F/AuaaE/zE7FekY7+JWCoSR7K/78VfYCg1K0PuWyX+juUsc5IkrnJvKOyYFn+MlK62
         aBLGhFv42f8gBoyxA7k0kaHGJkOMDFYzv0FpesUm1xlQPksE2sl+GHc/wkPN/aAkmO3d
         Tsni/JB2Rcz4KPLqX1ckDAD2yNbWyAEKHZFYF7zkR15N42rHwoXOuDiePQxkcbLZ6Cf4
         QsDL0UHtvarB7yaBkmFiNJ/Nr9kAbN/T4XzkBOQct3LFXbsMNuHXdEcQM+WonPfzEWfC
         H35l2EDdTOyuc0qRmTpdYVJDicb+XWix0mM1dMqFtUDtWGWMbrnZSxiOF9eN7tq1BJ1A
         /Wqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/7Ah+65EEZFm1meAWpeQqFHxCxpXJENrptV3lPr+juMYfkRhvYU0o6dL2DqwVq5KJmPLEsg==@lfdr.de
X-Gm-Message-State: AOJu0YzWlJ6xqxnAbcxOqbFcTPGVSxOqa9HI+1C6d/gT80pwKH4c/gkf
	JYFNmgFjoCyL7EMvB+bxmYpakTQmk/xOa935mVyrUmdo9BxZTSZI
X-Google-Smtp-Source: AGHT+IHo/0HAzQoxWY4Ug2osX43+UtGqgN9HFuIXWl6N5UAQig71CI046mC+X0n3WIE+Xnhi+o7D7Q==
X-Received: by 2002:a17:90b:2d4b:b0:2ee:fa0c:cebc with SMTP id 98e67ed59e1d1-3087bb69ebamr28216348a91.20.1745392737238;
        Wed, 23 Apr 2025 00:18:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAI4IisR4GDR5v+XKe0YXynzo5FPqXrMGLQaJiCjIj3M5A==
Received: by 2002:a17:90b:374a:b0:2ff:4f04:3973 with SMTP id
 98e67ed59e1d1-3086db4d54bls922661a91.2.-pod-prod-08-us; Wed, 23 Apr 2025
 00:18:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZPIVJUP3Zz0l0xHEly05QIFwMFh1S1U0nIRP3GNkdaSqRgqkUyPYRq4Jovn3dusL2yy+6osBxDQg=@googlegroups.com
X-Received: by 2002:a17:90b:2703:b0:2ee:aed6:9ec2 with SMTP id 98e67ed59e1d1-3087bb53257mr30788130a91.14.1745392735590;
        Wed, 23 Apr 2025 00:18:55 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309d62be97dsi97878a91.1.2025.04.23.00.18.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 23 Apr 2025 00:18:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.18 as permitted sender) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: Hp/ePXCPRv22ChXQRq2rBA==
X-CSE-MsgGUID: gnANjRq2TOqyRzGYsrqAMg==
X-IronPort-AV: E=McAfee;i="6700,10204,11411"; a="47100274"
X-IronPort-AV: E=Sophos;i="6.15,233,1739865600"; 
   d="scan'208";a="47100274"
Received: from fmviesa010.fm.intel.com ([10.60.135.150])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Apr 2025 00:18:54 -0700
X-CSE-ConnectionGUID: P/pJraOwRYC/fc47lTgdIw==
X-CSE-MsgGUID: XYAwJmTTRQC/TD1pLkhjWw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,233,1739865600"; 
   d="scan'208";a="132775409"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by fmviesa010.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Apr 2025 00:18:53 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Wed, 23 Apr 2025 00:18:52 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Wed, 23 Apr 2025 00:18:52 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.46) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Wed, 23 Apr 2025 00:18:52 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=KWwvuFbuKY7qEzn1oOr5lcqwovPFYKGAQ5LDzOuShLGJAcDKeR4kOp8tRBYQQ4i+XewOs5YH8bLfJBVCTViuYCE139lsQHbP+PWpHD9IA60JFvplTwTodppHBxTTstQ1yDtT10O/rumGRglx2oxYXS8fRsYLtSxHA0BrAml690n3HkpAZ3jPpxfFcxM/C3kJXwEmAmqxVNZPLe2FIyEMPrz/a2H65y2Acy5Nn03WnyexzjIzTjIeNl4KCIkkhNM5UA1LKnebou7FXfnVCt6d0mKHaNGhmhu5CNeH8TEl26dH9ZHR2Ym6wRNLh3efjlZeFJcFnAoWtrOD79hT7Q4QMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8KIy/eXrQWyplZzP2wBJdY3jQ+AxoigEB6+JLLvI5K0=;
 b=Kypci7BdXKZEbg4zr73gXDCbOlMvbmkUgjJ+h1vpaUez1FHTmS6W72xbzNRrFpoKsiqRyHEjsjWdF2cKThJEhFStRK7DkJV3ia97L1d/d/YRRquIjT0Es60vQ46ILl4xLKmHpTHna/cPtqRucGFXtrkNQKNQKGgWjQCQYt60ZQ4SZPN/pR8cFEKKJ6syKGNwZQULn7eKzjsfdyuKuc8VF7wtv/qCElyYWzvfMMEBpXZ6LtmKCctsfJ7/Th+MJCvdQoIzXD9YerudMkMA4vVNQ7zh2l+yL53vz6RfU4x7WeXqwkAcmUq4vcElgX7eqAY34iXxnPms+BosWH0gt/7TUg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by SJ2PR11MB7598.namprd11.prod.outlook.com (2603:10b6:a03:4c6::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8655.35; Wed, 23 Apr
 2025 07:18:50 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%4]) with mapi id 15.20.8655.033; Wed, 23 Apr 2025
 07:18:50 +0000
Date: Wed, 23 Apr 2025 15:18:40 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Kees Cook <kees@kernel.org>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <linux-kernel@vger.kernel.org>,
	<linux-hardening@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kbuild@vger.kernel.org>, <oliver.sang@intel.com>
Subject: [linus:master] [ubsan/overflow]  ed2b548f10:
 INFO:task_blocked_for_more_than#seconds
Message-ID: <202504231437.d0a0174e-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SI2PR02CA0039.apcprd02.prod.outlook.com
 (2603:1096:4:196::9) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|SJ2PR11MB7598:EE_
X-MS-Office365-Filtering-Correlation-Id: 5c744133-fc53-4138-f54e-08dd82371863
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?rE5ulW/3RUr0WNGoPP1cVtM39cuPIgXLSpHU5haR3fiYLA3CQNS+l5z1BQ+w?=
 =?us-ascii?Q?/FSS7hduhVsAnnBHHT8IfGhkb5EeK5GGPQ+W6G1VVqaztbFDWv9UWwpt6X7S?=
 =?us-ascii?Q?e3SzMPbys/8/KCGpnOM4izISQKrjv3Z8QLy4NlJG4qoNXxzxgPcSYeE1v1rz?=
 =?us-ascii?Q?Z6FLRy8AAXKJ+2WV4UPCwNedjRMjG4N9A6l4XacyR5DOHtqQazKU6j54jpoM?=
 =?us-ascii?Q?D+8z5mSulYbe7gWiPIa26ElF4Db/mtDzrSEvlH8C/appMwPnwHmfak7JfnF7?=
 =?us-ascii?Q?pv8aNfunWEJIjuZxRWBPpt2GEb4sV+7g/PaXtISRBlj/vxftOcvWpmBKtJUy?=
 =?us-ascii?Q?K2Wrpgg2R2xrMPcWm+0DqP47opWmy4NV3qi20MAHElp6gab8pc9/dUY5mABB?=
 =?us-ascii?Q?tTJJOXIxWMkz3fE8JbxaFJNHdP49ZOWih1LaZb1SH3mdsypGi8H9TM/IIj4B?=
 =?us-ascii?Q?LHLo2/FHIkjfF1aLz5C4hxTqAjOrjVzCAwUom5nrcl5NG+eym41B1ef9swcZ?=
 =?us-ascii?Q?kHgruYaRwjkB86quFHLhvXnsz+3pGnMkeNKMIfFhxBv2w0pKg1KzMk/dW8Ex?=
 =?us-ascii?Q?48/j/gySZtFHSielm/q80C7b7rJkvnAoZMiGk77atcKxDGHecwjO9FuPWpop?=
 =?us-ascii?Q?1m+R82AU7JPsD5+3CEsvvBt/mHoOlxrP3tfLq18/RnFUKsmz0fM/tReSqEge?=
 =?us-ascii?Q?SHkzhi3ju8aBHvtgMHwUZ8qaxUd+eGq+1rovPiE/n4+8T9zT6cPrfS2Zzsh0?=
 =?us-ascii?Q?0qE8fzBIwjGo9LCwVGmBZqbmv2Y0KZRxoU+je+pQsy5H8yDQXMcbaVtb8jUA?=
 =?us-ascii?Q?oKNzbT2h8QV7OdLLUrxoDKUmqz4E6lnGqLRdacM8oXYC2fjKA6y6WX0zflnJ?=
 =?us-ascii?Q?+5l7s7ZTY35xgyWb0komcknBvVB1W4Xc5CmnH4HZpgm2pGLA7tDN6yTAUlCJ?=
 =?us-ascii?Q?IrU0RjW/ukba8uSw7Il9C1MrVwQAS9ml8OUkple8opjN3UOoSbZSBCfbsrS/?=
 =?us-ascii?Q?zPORge9jquqrgdM5H7qylD4ewEdQVTXf05i7X93510MEMC4we5kHMK1Iu3um?=
 =?us-ascii?Q?3VTUUEEe5DwoLErzdooCRD5P7pFQoITVS0Lnv5f7VEuhGRbe7rQ4SO12OJUU?=
 =?us-ascii?Q?CqCw4zPT0fl+LT79sOeo7qlP/e+eFR9wQ0YZ1MOTO0Y4cuPTNWl2KEdGYpK4?=
 =?us-ascii?Q?kqHyxK1idAkymB1xUCzc3GLeAjj7wqFkwcx0zIG046SO1r1Qz7e7m58VA3Ih?=
 =?us-ascii?Q?Es0+Uk57zJTwIgOFxYQflDzCGrf+UWfLJBLvvXflI3uq5O1+Jj4VMc2f1eOn?=
 =?us-ascii?Q?UeM13Sqnmy4RdYbBjeytUqCNDF4OjIwkEj1HGGopIvKU91+OCX4dT3lZgx9+?=
 =?us-ascii?Q?t0w9DiYTwQgLr7M7junQhq6wZgcn?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?1WZEH2On+D31rMORkFvsfiy/TYwOP61XisqUZfzbeT3mlapbEsssAjtEn+Tw?=
 =?us-ascii?Q?+q9ZEQaCRu8gJqb5Px7I1kb9RzN3HmInUUz6Zq1IzOb1i0lzOv0QEB9AJbSQ?=
 =?us-ascii?Q?8RfsMBBF2nl/LViUwmRKBCe1ifddRN1wTBLQoebmI8+sTbfpfXvTXv2FZSRV?=
 =?us-ascii?Q?ZimBJ1zqu6xloiMUGj6+lIOQJXd0NxZuBFz5T7hkK25oGVYECs2ZY3biom3j?=
 =?us-ascii?Q?Qok4BI0o8Xp0QLsj+oljDoEvNiFClqBaweypavfykcrzMShGqdDhwAkP8aR0?=
 =?us-ascii?Q?DxdxG/t9uTze1jdzbhXL+zqEBrVKX7lgaQNNu3WBB8p42JNgWtBEe2qBuU7f?=
 =?us-ascii?Q?5W12pi29ETZbPmQWt5WOrUl2pTDkXj7zkusOpN1ChDL7W9wH42nllWK4CW09?=
 =?us-ascii?Q?4tc00sC4yAWdMwQHynZcX+/kb3duHdyFb6FSBaMtcQt3ZvaxHzNXvHIgIAUy?=
 =?us-ascii?Q?N1fvJ3y72iOmGGmcEv848a20g84Gjx0aXC1B31SlPgwHqnqF0c/pKhNy6WVw?=
 =?us-ascii?Q?hYq9by/rg4plJ/sJx8suoMCm0yo19xjRVNGveFvPXT5YEhSewiF+/fdzl7uK?=
 =?us-ascii?Q?THiOnS5GuxEb5TFJ/j63ZFk2tishHHE/+iu4STWXK5VQjTKBTnYx5Hkd9Xh5?=
 =?us-ascii?Q?hzcarI2b9up0EXWgEVIQsxI3LGnP6O5jywxBKVxL9Mo0m603o31Zf4pxCfzS?=
 =?us-ascii?Q?QNAOdjH0HyfCbbvuuVOISWVhvFGMFIwSzQtUsLpu1GjJCbh+ICOkD/opPYMj?=
 =?us-ascii?Q?qLhObvuSQktqaoPXPF+VFH2eoHNzFZphalUz4rkwHVfBEwz6q5CrrsErcbuF?=
 =?us-ascii?Q?R/PwVOVN6d3JIvfR8+NskOCyvEzGSphtfLcL4jpZI6Qu+jeuXzNhUzxQJSs6?=
 =?us-ascii?Q?KvieAYh8zEPBzAFVcSdYHLuMR379wKeOBS/270dCkczTyDQlja7ZR8Bnzxbf?=
 =?us-ascii?Q?QR8Odn8O59ijc/uv+yPWW8Eg+Q3vPwLVN2Jd6sj3xzMnn3oronArpfiolOsp?=
 =?us-ascii?Q?EHKGzul6GU/pLLVasP95nAJwYSbT6hsEfLnu17st7z6iQoaHvMK4RWIgkXl7?=
 =?us-ascii?Q?rPg1Uw/TSHV/DY5Vzj5Lti0p3A17ovC8kX82ky0L0D0S40J0Wo9gBHho+6lH?=
 =?us-ascii?Q?r0OC5PDg+RH5BfUZh7b7N5S6YU7b+lL1GYPlw47YIZbtwHflBm5iiq0d6npF?=
 =?us-ascii?Q?AGTVw+RlWg9+uLx8qWrhSiJDOcf0pya6SiJuc/676AbPLwkBKqeYNdkojivj?=
 =?us-ascii?Q?TWFz/yqdNeZoNOd68+p8zd/PoEDdXXrhpVOmAIczGp+bJhElF+khIZGuM8Eo?=
 =?us-ascii?Q?f7QE6za7hE7xA4S2KhxZj/82C7rWfqw5aPYHkUPlHZqj8ySVoWNVd2HwKtoF?=
 =?us-ascii?Q?d+uI2SQCZ9iaD2FXnfjgdrSfVcp/Tsri/gQhAg5Khbck0tauQ8X8DhbgG0Vx?=
 =?us-ascii?Q?r0J7CpKyfi9xhM5hKrGuKAu518YUbeRlHrkuVJ0tuSKYD7JfRNh0g2fF8GJ4?=
 =?us-ascii?Q?neRRxFvH5cjPPw2iCvc+LrwbD6U4OdQkcpm8glOs6O7fIrFNtNE7ckK5YsKC?=
 =?us-ascii?Q?kVZ0FUGe81pINl2jcZtzaMdYml0htxopMbtFTIewG2IB60hLDyGGwJm4W31m?=
 =?us-ascii?Q?/g=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 5c744133-fc53-4138-f54e-08dd82371863
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Apr 2025 07:18:50.1630
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: rYPOhY7GTlIynbV16ScKNiw/mD9jAvzOUxYrdpauXTF2zcCma6jRoFX++OL8iwSf39bRNdQoDqJ1xu0vUVQ2dA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR11MB7598
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QMMfygn6;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 198.175.65.18 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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



Hello,


we don't have enough knowledge to dig deep the relation between the random
issues and the change. we tried to rebuild kernel. still see the same config
diff:

--- /pkg/linux/i386-randconfig-013-20250413/gcc-12/d2cf8ccf5a1871058a083c00efe37d7eb91bf6bd/.config     2025-04-22 15:01:12.846009313 +0800
+++ /pkg/linux/i386-randconfig-013-20250413/gcc-12/ed2b548f1017586c44f50654ef9febb42d491f31/.config     2025-04-22 15:00:23.620141366 +0800
@@ -5558,7 +5558,6 @@ CONFIG_UBSAN_BOUNDS_STRICT=y
 CONFIG_UBSAN_SHIFT=y
 # CONFIG_UBSAN_DIV_ZERO is not set
 CONFIG_UBSAN_UNREACHABLE=y
-CONFIG_UBSAN_SIGNED_WRAP=y
 # CONFIG_UBSAN_BOOL is not set
 # CONFIG_UBSAN_ENUM is not set
 # CONFIG_UBSAN_ALIGNMENT is not set


we tried run both parent and this commit until almost 1000 times, the parent
still keep clean on running same test, this commit shows various issues

=========================================================================================
tbox_group/testcase/rootfs/kconfig/compiler/runtime/scale_type:
  vm-snb-i386/rcuscale/debian-11.1-i386-20220923.cgz/i386-randconfig-013-20250413/gcc-12/300s/srcu

d2cf8ccf5a187105 ed2b548f1017586c44f50654ef9
---------------- ---------------------------
       fail:runs  %reproduction    fail:runs
           |             |             |
           :999         27%         269:998   last_state.booting
           :999         27%         269:998   last_state.is_incomplete_run
           :999         18%         177:998   dmesg.BUG:kernel_hang_in_boot_stage
           :999          2%          16:998   dmesg.BUG:workqueue_lockup-pool
           :999         18%         176:998   dmesg.INFO:task_blocked_for_more_than#seconds
           :999          8%          76:998   dmesg.IP-Config:Auto-configuration_of_network_failed
           :999         27%         269:998   dmesg.boot_failures


so we still make out this report FYI what we observed in our tests.


kernel test robot noticed "INFO:task_blocked_for_more_than#seconds" on:

commit: ed2b548f1017586c44f50654ef9febb42d491f31 ("ubsan/overflow: Rework integer overflow sanitizer option to turn on everything")
https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master

[test failed on linus/master      c1336865c4c90fcc649df0435a7c86c30030a723]
[test failed on linux-next/master f660850bc246fef15ba78c81f686860324396628]

in testcase: rcuscale
version: 
with following parameters:

	runtime: 300s
	scale_type: srcu



config: i386-randconfig-013-20250413
compiler: gcc-12
test machine: qemu-system-i386 -enable-kvm -cpu SandyBridge -smp 2 -m 4G

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202504231437.d0a0174e-lkp@intel.com


[  985.037272][   T22] INFO: task swapper:1 blocked for more than 491 seconds.
[  985.037272][   T22]       Tainted: G                T  6.14.0-rc2-00021-ged2b548f1017 #1
[  985.114644][   T22] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
[  985.131238][   T22] task:swapper         state:D stack:0     pid:1     tgid:1     ppid:0      task_flags:0x4000040 flags:0x00004000
[  985.184178][   T22] Call Trace:
[ 985.184178][ T22] __schedule (kernel/sched/core.c:5380 kernel/sched/core.c:6764) 
[ 985.239369][ T22] schedule (kernel/sched/core.c:6842 kernel/sched/core.c:6856) 
[ 985.292955][ T22] async_synchronize_cookie_domain (kernel/async.c:317 kernel/async.c:310) 
[ 985.292955][ T22] ? swake_up_all (kernel/sched/wait.c:383) 
[ 985.347537][ T22] wait_for_initramfs (init/initramfs.c:767) 
[ 985.347537][ T22] populate_rootfs (init/initramfs.c:777) 
[ 985.402751][ T22] ? do_copy (init/initramfs.c:771) 
[ 985.402751][ T22] do_one_initcall (init/main.c:1257) 
[ 985.483184][ T22] ? parse_args (kernel/params.c:188) 
[ 985.536816][ T22] do_initcalls (init/main.c:1318 init/main.c:1335) 
[ 985.599031][ T22] kernel_init_freeable (init/main.c:1570) 
[ 985.599031][ T22] ? rest_init (init/main.c:1449) 
[ 985.625998][ T22] kernel_init (init/main.c:1459) 
[ 985.625998][ T22] ret_from_fork (arch/x86/kernel/process.c:154) 
[ 985.680001][ T22] ? rest_init (init/main.c:1449) 
[ 985.680001][ T22] ret_from_fork_asm (arch/x86/entry/entry_32.S:737) 
[ 985.733799][ T22] entry_INT80_32 (arch/x86/entry/entry_32.S:942) 
[  985.842056][   T22]
[  985.842056][   T22] Showing all locks held in the system:
[  985.842056][   T22] 4 locks held by kworker/u4:1/19:
[  985.895824][   T22] 1 lock held by khungtaskd/22:
[ 985.895824][ T22] #0: c88799b0 (rcu_read_lock){....}-{1:3}, at: rcu_lock_acquire (include/linux/rcupdate.h:336) 
[  985.949551][   T22]
[  985.949551][   T22] =============================================
[  985.949551][   T22]
BUG: kernel hang in boot stage



The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20250423/202504231437.d0a0174e-lkp@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504231437.d0a0174e-lkp%40intel.com.
