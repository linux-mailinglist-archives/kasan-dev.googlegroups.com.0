Return-Path: <kasan-dev+bncBCMMDDFSWYCBBRFM7C6QMGQE7W6QTCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 760ABA44B20
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 20:13:10 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4399a5afcb3sf56081675e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 11:13:10 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740510790; x=1741115590; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PNicKCDsR6Rbu0CebP5bfbfJlu62UUkAX/uPQOEJyv4=;
        b=kMCA3WJXBeZCI9edeEYCapRbmJDDKalNilnzxihWGamlEQPBq+hvsZY0UXjttG555N
         i7V1u7f04LHo3R5N4NRSmdFGkU9gxy55w5hdE9lGU7xFWQ7vs1Ku4xJzLVQ5qOBSljtu
         xXp1R3taujtxNj2/O4lH3cK7YF4vJU5o2UL+QwcN5ihoQOTG97wMj/ac4KmyMl5sqdEr
         yi78vDCsOVJTwAd2Y5/IvRCpnD8M/eJT2WzPdKBOmaj+8y1K0nlTgqHGXAPTH+rcKHtv
         cAjBAd1O1qk2bT2K7Focz9Wh1To98jiLmQ8Tscbw6bEZlJCFchKO1JUXbtxPB7ERx2Oa
         r3Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740510790; x=1741115590;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PNicKCDsR6Rbu0CebP5bfbfJlu62UUkAX/uPQOEJyv4=;
        b=gGEpFU7j2BPf2XjrT8fvOJbL4NRWL2GjpQtIhzHKilBdS06JiGWHZL8NJlpHGJ2jG1
         u7vlyFifnCZx/9SLgD+H85jU1AECqJefmyyVj1Lb5Dur33/m4o2ISJ8QdJIhy3Ef8mvq
         YZrgCr3ez+sEpm0cfsMUqdwp39SGwtgC+mKxfocmj8ObrYb7clOFVsPn5pMBHZbghooJ
         mNfZHXIdbNQ3+a32Ytat1wtALMGenNst4nzryRG91hku6N1M4mwOsP2xkCuQyVKVKI0j
         0g+L69rSt2q/GVurWLTms0u8AU9tSWdQuqv3y9NWDfeEKtrkXPvJWHDOe5s3ryJJzOOr
         P4Sg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXEkhoR57chWucSKdTslJxmaTzPhg5x57Igld+FP5zMEoaCqz7dscRLolFC7hlFP9m0Adke6A==@lfdr.de
X-Gm-Message-State: AOJu0YxjbzXGE38qmxITZNv+x41psmk1MA3Zguek8NNoCdKmxQgudAdG
	zMBr3AO4A9fyoCixn5jugPc4kIxT7f51ClUpKn8teRJwwS5OZiLY
X-Google-Smtp-Source: AGHT+IG1MDeFTlEpU2lZCLA2QsBmj5DmSIaNwasB7t20wQIVKzbGDj08dCHwZjFGRX0DwW1TT3aH0g==
X-Received: by 2002:a5d:5f86:0:b0:38d:dbbc:3afd with SMTP id ffacd0b85a97d-390cc5f5877mr5236316f8f.10.1740510788553;
        Tue, 25 Feb 2025 11:13:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEL/RIhv2NHptd5/QJG8Z3eo7rYIb9Sq1pGouBgaGCO+w==
Received: by 2002:a5d:64a9:0:b0:38d:eaeb:19e2 with SMTP id ffacd0b85a97d-390cca9a4f2ls1020516f8f.1.-pod-prod-05-eu;
 Tue, 25 Feb 2025 11:13:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXDuIkdF+A5RGI51QSukUkhfPzhKNbYUiF2XkVTu+1dvoV3jtHPMnyAPD8/nNFW6l+0PmDVHQTXHmg=@googlegroups.com
X-Received: by 2002:a5d:5887:0:b0:38f:2f0e:9813 with SMTP id ffacd0b85a97d-390cc3b0eabmr4835589f8f.0.1740510786398;
        Tue, 25 Feb 2025 11:13:06 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.16])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab2c44017si1027705e9.0.2025.02.25.11.13.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 25 Feb 2025 11:13:06 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.16 as permitted sender) client-ip=198.175.65.16;
X-CSE-ConnectionGUID: 8YF5T2McRjyb+aCafzLXSg==
X-CSE-MsgGUID: CNnHMIB2R2SJ3vB87j2uVw==
X-IronPort-AV: E=McAfee;i="6700,10204,11356"; a="41462630"
X-IronPort-AV: E=Sophos;i="6.13,314,1732608000"; 
   d="scan'208";a="41462630"
Received: from orviesa008.jf.intel.com ([10.64.159.148])
  by orvoesa108.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Feb 2025 11:13:04 -0800
X-CSE-ConnectionGUID: 69ZdoVgYTFyirXmu8OLSng==
X-CSE-MsgGUID: kSlMhdiNTBmgvvmwtWa4gQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="117407065"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by orviesa008.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Feb 2025 11:13:03 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Tue, 25 Feb 2025 11:13:02 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Tue, 25 Feb 2025 11:13:02 -0800
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.169)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Tue, 25 Feb 2025 11:13:00 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=j6vZ+bgvQFUf16iWc+XwSR/AbG5vILf+3TRN8KfSIt8CdyXltXOPc/Gy0zEByG0suvI2kvVPbbnzU1nDJ59bKWcPNbwQwhJvJlHNbXF3O/IO1WTnzE4hAgoFlwPNROZfMVIQ6RpjxJk/jC/jmyUqCdkzboozJ099fKcRGBEur6u1xPnueCNHboQrRZtyrr39H8hSCIGgClIjyNpbyA5iFuWqLBldPswCnTXW1wzR/ZekbaNEdGW7Zgny8u7DsZFUio3ye9r2pNWifeNq3knYmhGWiK4pJNKrqjXs0wxbvMroBSHtLr+iIje1UBwZL5+/1vn4Lk4aILEilfVIloTg/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=BtyYDsWDAPxhsk//OJHdSQJlC3bHQmXLR9yPtJnMP34=;
 b=qRT276tlB1iuKT6VlWIHKlwJ/dc+IATVBcX0Y9U0JVfYKfwjeLjTHbfNmrr4fZwNVudUyP1MfZlqBz3ahUkp2VUYW96UMeIXiUi1Bwld17e1z1KgKintj+HLjKFVjubTws1TmJDShTVZCTySgjs/nfzRRUXEGo9dL9mMPDY0o8HWoe9do/8NotY2QeDDf/W5VD5sDXo+Q9fK1iyK6xuX/P6lXNxbJrXHLpE3vSyAjRAETHR/84iV4UPhcL8sUNfKxeAyTNq94z0xJwSy9zJCtO7tybUR6tgeH8XGbi9vX4BTHihf/Taw1RHQoMSNwa3u70kAyCa9cGKgGp5R/tl7kQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by SN7PR11MB7140.namprd11.prod.outlook.com (2603:10b6:806:2a3::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.17; Tue, 25 Feb
 2025 19:12:53 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8466.016; Tue, 25 Feb 2025
 19:12:53 +0000
Date: Tue, 25 Feb 2025 20:12:40 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <kees@kernel.org>, <julian.stecklina@cyberus-technology.de>,
	<kevinloughlin@google.com>, <peterz@infradead.org>, <tglx@linutronix.de>,
	<justinstitt@google.com>, <catalin.marinas@arm.com>,
	<wangkefeng.wang@huawei.com>, <bhe@redhat.com>, <ryabinin.a.a@gmail.com>,
	<kirill.shutemov@linux.intel.com>, <will@kernel.org>, <ardb@kernel.org>,
	<jason.andryuk@amd.com>, <dave.hansen@linux.intel.com>,
	<pasha.tatashin@soleen.com>, <guoweikang.kernel@gmail.com>,
	<dwmw@amazon.co.uk>, <mark.rutland@arm.com>, <broonie@kernel.org>,
	<apopple@nvidia.com>, <bp@alien8.de>, <rppt@kernel.org>,
	<kaleshsingh@google.com>, <richard.weiyang@gmail.com>, <luto@kernel.org>,
	<glider@google.com>, <pankaj.gupta@amd.com>,
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
Message-ID: <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
X-ClientProxiedBy: DB7PR02CA0025.eurprd02.prod.outlook.com
 (2603:10a6:10:52::38) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|SN7PR11MB7140:EE_
X-MS-Office365-Filtering-Correlation-Id: b59f1399-874f-48a9-fe93-08dd55d066f9
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?aU5kcy9hQmRENHZZaWhGQ09LNUxFdjZYSWszZDV3TzZuSThLK09XVCtiK3Jw?=
 =?utf-8?B?Skwrb1Y0a2M3V3N3VGhwRkxtRW9aUUtUN0Z0MVZNWTJZVmsyYjZOWEJJMlFl?=
 =?utf-8?B?T2lKR2tKUU1MNEJkNk5WYXVhUkF4MWE1aFFKMFhxZjlaS1NWZ0phSnZraWVT?=
 =?utf-8?B?S1BaYlNwZmtod0lSdG0zbkNHdjRCZDhzSVZ3c1JQV2x2NW02TVZTZnVJRzBR?=
 =?utf-8?B?WU41QjB4Z3ZGWHlNRm12NGhDaCt2cmhqNFMwTTFyOWU2bEM1RERzeTMyNTll?=
 =?utf-8?B?bHNSdTdnZ29xb3NVdi81cDg1dlNhWFlpTENUbXZMY1hCTjEvd1pObVMwLzY2?=
 =?utf-8?B?U1hhV1lVOTJxL0UwdlVJUWFCLzlEazVJQzZFYmt4RlZGYTRVWTRsTGVoYml6?=
 =?utf-8?B?YUR2NTlYUG9Od0hZL1FocFAyaVRNVEVXVEVlL3dOUHR4UTdETUlNeGoyT3Jk?=
 =?utf-8?B?dGVlVGhZWHJ2RUJ1czQ3Mk1IdnRBWnJlbUEwL2tGSFZVZHBUOWJTeFdLclMz?=
 =?utf-8?B?QUJtM254RG9uMjRSMmtTR1ZtRWlvRUtWOHN5TWlVZGJKOEp2cmdkYUdiK1lE?=
 =?utf-8?B?MmhROFgwZVliTTlGRlZMcmtxMjJITmZsOUlEVXZTQkR4QS9kYzk4c0RuRllp?=
 =?utf-8?B?cVE0NHMxVVNsZTFraWxTUVJxTlE3RWNZdDd2dHlMZkc3WUVBTVhSOUZNYk9B?=
 =?utf-8?B?Z3BRV2k0ZHloTXdYYzdVQmxrSnBld2dXM2xYc1BqYXFSUWdyU3ZUN1BuZEZO?=
 =?utf-8?B?MWlkSDlUNVIrM3JnVlVFK3RLNDdXd2hrWVltK2xiZCtnZiszRnlkbnV6bnhr?=
 =?utf-8?B?WWZZcVU2NVVvbHJhRGlRS0JJdjBRNGdWMWZqQWJoWnBwVHEzUGxjelh1OXdD?=
 =?utf-8?B?ZkRCTi9rY0ZjdHliQzVrZS85alVmajM2NmtZMGczOGl1WklIZlhuTGRTbmo4?=
 =?utf-8?B?R2hsckJndzZlZ0kzVXovczk4U0JRU0lLbThZT3lkUWRrUmQ2cno3YXBobzFv?=
 =?utf-8?B?bWIzcWhUdU5CbStwWXc1aEg5dVFHOXFVZncrNjY0UHk0bHlHREdpUnR2RHU3?=
 =?utf-8?B?ZWdMOHloalQzOTdTZk5iY3RtNWRpQVBOdWlwQUpwUDFnNklvNUxYSm9vQ0VD?=
 =?utf-8?B?YXRhSlhyY2tIckl0ZEVVTWdZakRjLzhxVHBDeEd3a3ludnRsdEJlU2lUN2JX?=
 =?utf-8?B?NTBiOU1WZTFseGY2R1ZvU2E0dU1MekJJWUw2eC92RTRVMEU4U1dWdkF5ekVQ?=
 =?utf-8?B?NzRMSTRTRnBXRldxQkZNOWNCbXM1UzVieFdCejR5S2xMaEw3L0k4RmdPQVdk?=
 =?utf-8?B?WlZ4anhzb0Q2VTZtOWphSVBFeXdpbnlPVnltQmtyMFgvbStxRlZCc0hXNElp?=
 =?utf-8?B?SFBQNVRZTitXbTNCeSt6UGw5cjN1M2ZpTTQ0WTdWQ29iTjJES21KVlhsVzJY?=
 =?utf-8?B?a1BqSW5lVWNCWUVyYmJrZDZaWk5uaVV1Ry9VKzFmQXdJUHVHQk04R0ZhN1N1?=
 =?utf-8?B?T1FYSnFzdlZxQ2kzOUdpaDJQQWwzM1Q5TzNMSzc2QnJWTlM4a1dtb1E2TERI?=
 =?utf-8?B?VG84QVRNay9CaHJKSVBYNEtiTElpU0h3Y1RZOG1yYnhBTlRiOWd4N3JwZnhY?=
 =?utf-8?B?bDdnRVY3MkxKQndSdHdNNVF4b09LZEVNbXpkU0R1cXI2RHBsM091Nk5XYWt5?=
 =?utf-8?B?WHNVVVU3TC9PeGxvRUZFVmV2TWNqVVRLbWgzaDVpcVFaMXcxZ3NXYmpYQWU1?=
 =?utf-8?B?cFh2cnVCTStVOVBkbUU0Uk9nWERsY205T0JoRmFtMjYyclE1SHZCcUNRYnZ5?=
 =?utf-8?B?WXVHTFlzbjlUYmtHeWJ0QT09?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?bTcybWdBTDQ3cGYyRXFyUWdXMk5nd1lBc09DTGIyeDZPSWtNQTIxbTdCVXdo?=
 =?utf-8?B?dnduaVJFRjYyYWllQzgyeVo0V1FPcFF3WHdyVGFtQ3FnZXV0VFdqQ2VVU2po?=
 =?utf-8?B?Q1lwZGdMLzZqVW4xMlBRcTFFUG1ta05ob0F1clR1bTB1b1ZoVnVpUTcxVUFh?=
 =?utf-8?B?NEs5MDdmT0lsNWhBQ1RpbmNFQm1oa1FOaExSSE0wS3ozcFRMTzBraGZpQ0pw?=
 =?utf-8?B?RjZpc21xV1h0SzZ6bC9CUEl1ckpVSE91OXhHYmRHZk80WWRXYUc2SUVDdnQ1?=
 =?utf-8?B?cEF3cklMMjBwZGRXbTVqcHZFNWNqb3AzSEJKNjJUM3ZZL1NyVys4UjE3dEda?=
 =?utf-8?B?M3B0alNTN3VNMVRnamdFUUJWMXZUWXhRRkgrbFFXOHUrWUtUVUwxVDhBWDNX?=
 =?utf-8?B?UFZpWnN1QlNtNjArL3NhN3pJVlMyeUwvOEgzYU53MDZoSC9IbGNkT1NHMDkv?=
 =?utf-8?B?cVBydklKaCs5MmRNa3FrWURlV1pKZUUrUGRHMXFPeVIxVUFsWVZTWTVMYmt6?=
 =?utf-8?B?OXArSndObTYvVFNycFRxNlpEdm0ybzdBUXlmY0lydHliRlJiby83V3JNN0tL?=
 =?utf-8?B?ZEpWZUZQbU05eG1MeGNDNnZhZVdsNS80c29Ib1RhNEs1dEtMeDBmSmdYU3Jr?=
 =?utf-8?B?RU80czZYQmZSTDJ4K0VxdUZtQkVjcnhLV3Vaai9yNlhxVXYrRFdPZHRJQ1Ax?=
 =?utf-8?B?TmtkWE56OWVka2F4eWZQZ3c1bGpCT08wUXl2NkFOMkFFcDRQRWtuY3puMGV0?=
 =?utf-8?B?OUpwK0lXU3JvM0p1SkVFbWM4Y1VRd3JFUXN4bERER2VPb1lwd3ZPRXd3eW5t?=
 =?utf-8?B?U0hLTmg1ZEZoQXUvdjhMZEw3ckVMZ21RcEo1ait1NWprSEV0K0Z3TXNSMzRu?=
 =?utf-8?B?UGtxMG5oVUNUMTFzc3dSVTBOb04xQ25mRTdxUVRhb0RWa3Z2c0M5dFp6L2hq?=
 =?utf-8?B?V29mNVVGWVUweEJHekN5UndkbXZEMS9TeU9hb0RQQ3ZTOGdaN0VVUEZxcWZu?=
 =?utf-8?B?NzBwZ3ljT1VoSVlKOGlsRkxkTTFvZGVubkRTdXpTTi81NmlnWkRUZ0U0OXJL?=
 =?utf-8?B?NlZUbWJJMk9lamZyNkpIellkcEJmcWxTQ2ZGWGw1bGRlYkp2ZVdhWFBSNEcw?=
 =?utf-8?B?MEVIVytBUGMzb2R2b3dGU1RUTHQ4V0ErRUxVOCtkbitaZzIxMmRDWnhvVVIw?=
 =?utf-8?B?M01EQVRWekxKT1ZCaDhHOU9hNVlkRnU2MTRnVDdhb2srazRwcFFhUUFnbGxH?=
 =?utf-8?B?ZTNQUW1nbWRrcDBQNC9RbkgrNkRqRUM2R0JQK3pWSXR1Y1p6bG5pa1ZVZjFI?=
 =?utf-8?B?TEdwQ0tkMExMTDhpNVlFSFJNbFdYdDNlZktDMXp3cjJaYjBOOHRNejVVSUV6?=
 =?utf-8?B?aC8wNHIvb04vWmp5QXhKOVJNUForakM0UlFjak9CVlNaNU92MWI1Nk96U05i?=
 =?utf-8?B?Q2RhdU82cGJHWXlheGJaRTZVV2hMZzhaSlBhQy9TYnh0d2NpampTQldva091?=
 =?utf-8?B?YVlydkxaWTRUbFB4NmNDaitqRUxRT1ZyaU83aG5Dd3B1NlZpVU1SeFc0ZjdS?=
 =?utf-8?B?dE1paSt0eDczVStOZ3MzbysrUHNxd0tmYVVHckhwWDc4bVpOWlBxVHR3RVhK?=
 =?utf-8?B?OTBBVkZIb2FtRDJpRTdJL25YNmE1MTdVRnpOeEhZV2UwZVpRVmZad3Nsdko2?=
 =?utf-8?B?RXdPQkNSTUlYblZ2SlI2Nk1kTllLWVU5ZjlDWTNrV1dxQS9jUnZDRE82TVMy?=
 =?utf-8?B?aks3NFZCam9sOFphaGJCTHI4VStyRVJIeHRrUFdtdGRTaXh5TkdHNDlhTmF3?=
 =?utf-8?B?YWN1QTFYTEZGaVVtblUxbEhnV1NucW1OQjV2bEhuNWora1ltVytpd2Q4UjYw?=
 =?utf-8?B?SnhjUk45SEFyQXlCREIxU282cENJL1FWaUFvdmhvbG1QVnVCamZ2dGt3ZUpR?=
 =?utf-8?B?VUtQc0dUd2MrTXV3Zmc5UjIva1JjZkZJVXdzeUlhMWpzcStPUm9KV3ppUWtj?=
 =?utf-8?B?bmJ2Z2F6UnlzbDExMFFsZ2lZcjFiajZBNmZXUS9XM0xTUzdSQmNjR0J2SlNs?=
 =?utf-8?B?TDBJQzJnMW4yZXFPWGJJeUFZc1VqRXpsQ3ZDMS94MEtIazd4bWpWVmRyNUZi?=
 =?utf-8?B?cUdhVzQ4bjFGV1BVWGhMbzJ2OWhma3p4WThaTmhaWW1GYUFZRWg3VFpiNmo4?=
 =?utf-8?Q?4UcdFWDzjpK1C7/Bw30dMuo=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: b59f1399-874f-48a9-fe93-08dd55d066f9
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Feb 2025 19:12:53.0361
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Poyfx4e1BL1wDoDAth6RQSnJKNbeJdnVxhhrnJ+vMkCYPJdY4Nh3TNZTxM8KsT8dAse+E4gvhxOG5k0dbwfZKV8BO9j/dBeXAWRbS6VflS8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR11MB7140
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ftvqVgu5;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-25 at 18:20:08 +0100, Maciej Wieczor-Retman wrote:
>On 2025-02-22 at 16:06:02 +0100, Andrey Konovalov wrote:
>>On Fri, Feb 21, 2025 at 2:12=E2=80=AFPM Maciej Wieczor-Retman
>><maciej.wieczor-retman@intel.com> wrote:
>>>
>>> >Is there any reason we need this change for x86 SW_TAGS besides the
>>> >optimization benefits?
>>>
>>> I wanted to have the shadow memory boundries aligned properly, to not w=
aste page
>>> table entries, so the memory map is more straight forward. This patch h=
elps with
>>> that, I don't think it would have worked without it.
>>
>>Ok, I see - let's add this info into the commit message then.
>
>Sure, but if you like the 0xffeffc0000000000 offset I'll just drop this pa=
rt.
>
>>
>>> >However, I just realized that this check is not entirely precise. When
>>> >doing the memory-to-shadow mapping, the memory address always has its
>>> >top byte set to 0xff: both the inlined compiler code and the outline
>>> >KASAN code do this
>>>
>>> Do you mean that non-canonical addresses passed to kasan_mem_to_shadow(=
) will
>>> map to the same space that the canonical version would map to?
>>
>>No, but non-canonical address are never passed to
>>kasan_mem_to_shadow(): KASAN always resets the tag before calling this
>>function.
>>
>>> What does that? Does the compiler do something more than is in
>>> kasan_mem_to_shadow() when instrumenting functions?
>>
>>Same for the compiler, it always untags the pointer first [1].
>>
>>[1] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tr=
ansforms/Instrumentation/HWAddressSanitizer.cpp#L922
>>
>>> >                   Thus, the possible values a shadow address can
>>> >take are the result of the memory-to-shadow mapping applied to
>>> >[0xff00000000000000, 0xffffffffffffffff], not to the whole address
>>> >space. So we can make this check more precise.
>>>
>>> In case my question above didn't lead to this: what happens to the rest=
 of the
>>> values if they get plugged into kasan_mem_to_shadow()?
>>
>>We will get some invalid addresses. But this should never happen in
>>the first place.
>
>Thanks for letting me know about the tag resets, that should make changing=
 the
>check in kasan_non_canonical_hook() easier.

Ah, but the [0xff00000000000000, 0xffffffffffffffff] won't be true for x86
right? Here the tag reset function only resets bits 60:57. So I presume
[0x3e00000000000000, 0xffffffffffffffff] would be the range?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/g=
isttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj%407feqy5fy2kgt.
