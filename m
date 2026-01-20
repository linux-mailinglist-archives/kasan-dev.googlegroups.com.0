Return-Path: <kasan-dev+bncBCMMDDFSWYCBBGVKX7FQMGQEKJ46HEA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MNWKEBzVb2mgMQAAu9opvQ
	(envelope-from <kasan-dev+bncBCMMDDFSWYCBBGVKX7FQMGQEKJ46HEA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 20:18:52 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC94E4A2BF
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 20:18:51 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4802bb29400sf47215135e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 11:18:51 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768936731; x=1769541531; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vOgBVrCOyZH8TDO1B7meNmc32C2Jr6+57L0JJQdx57s=;
        b=mawdbk5VxVIZoH07zGp7ov5bzJsQApvntX4lkUp/7WEtpTJtAP4t2Hz9tKXtWm7ghC
         rmEkSlpagvxx+Rzp9BupuJFOledkAeNY7uKr/l4Jb3SHLri/w1YYSgz+fMx0rJToZP3O
         BOS+DwfbKf9i6A8bF81ooLfSvUwFAkkxx2Dlk9GN0kmG2eQJIZBLgB/fTK4MAvQtG6sc
         sKPf9PsdZqmWy+KllrjoBpOoT3Yb/NxutaK5jkaAeZZF18BEaChr4Z9Ep5IcAPj5oxRW
         o6BipQ2ZCr7rxaO4lhihw3ggfQ8yP3uwm9XV5wK8/m6zpkHFqY9fLiLwpgavqYi5wEh2
         VldA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768936731; x=1769541531;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vOgBVrCOyZH8TDO1B7meNmc32C2Jr6+57L0JJQdx57s=;
        b=wNw60ZMCgToSiIP+pOB8IbJl3rv7GiE0+H5E+NZD2BhxtBWJEVpTGX8vjuhLs4Ao76
         asEMQ6ajFmVr+4Z5JGhKNbdglyYde9MF/chd/l6PKhMqwooix2PZNGWI/v1b4UAb9w0W
         l1PNOft+1TIGJmUvDlK0tHs19OtW+eI6F+E6rjZ5pJa3zXWYMSMVOMWvwAin65mkZmyx
         VFhh1mbG+NjZHiE0rnhdlYYtr3zYHUYnQrCHo/Ao9GF5HKBXCgGJXELsic4iuPrn/PBC
         koyosdeAbBLiMjOOKxHlF0puHwmkg/R79JhPfP4WEXzrv9sVD/Wje1XNVpeQFGv6ASyT
         LSBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCX4NLDrSLADYC8XzdepgzUdk+9mkUE/cNGHH4w0Pua0K98zQGKnUBuQV9rpwHoTUFnQo/MAmQ==@lfdr.de
X-Gm-Message-State: AOJu0YzhzDpLCIiebtDAWgJ5y8JhsS9ZnfBmVeAaDeHoub5r9k638Uil
	E2yCO0gBlOQjk574Fru7EirQw8/bRfkOVNqsy1TRkOqQZkGV28+F6IDE
X-Received: by 2002:a05:600c:620d:b0:477:63b5:7148 with SMTP id 5b1f17b1804b1-480288773f6mr152939285e9.6.1768936730957;
        Tue, 20 Jan 2026 11:18:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ExB4n7ugoO0a9sgHCUarqV3guDE6JPLu6RrtJhVHG3/w=="
Received: by 2002:a05:600c:4ed2:b0:477:a036:8e60 with SMTP id
 5b1f17b1804b1-47f98c52c49ls21776815e9.0.-pod-prod-02-eu; Tue, 20 Jan 2026
 11:18:49 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVQMRy7IcETJvq4d1bCQk87tbcuKrOqnxF8TDDln8pwaxmjEoiLw5o/gN2HiadFwk7nrRpQRa1nf24=@googlegroups.com
X-Received: by 2002:a05:600c:35c6:b0:477:93f7:bbc5 with SMTP id 5b1f17b1804b1-4801e2fdf57mr225616955e9.10.1768936728710;
        Tue, 20 Jan 2026 11:18:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768936728; cv=fail;
        d=google.com; s=arc-20240605;
        b=ai5PQftHfrRLoz/kU2M9gQYFH/F5N1eDs6y93tbhU86aiomHgnlokMCmktZ3U+hGDD
         Vld9BPcpsL2ioNEWUygQK81ABqfpjvz6OhTIuhM3d7FA/L8JIxMh/2RG7/5gMm1VrHl2
         HTbIq0Na6B+zVV9oqLxjT5UXxF1WvhvRvvaHzgBt3yt/0nT3j/+pn7AOWsY3oZXPBZCV
         aWtuAsl3rfJxcd+xr8ydLq3UKYmqYRxvqkMHuIYhVzVvrSx1NMjNcz2nvoPEyQ69rUEx
         e2BIppSMZ4Fr8gJhZjlQM94sqYqWeUhg4taMtxw0JhW7CAQbpcrZ43aGSezyN7zsVwuc
         v32Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ooZwLTGK072AebLwwDIiWKiubOmLgwRPCY0OU37B9Cc=;
        fh=vt8iz+FsrgxeDTsF6VWaqMnvzwX5u2LNRjS/n7L8tDU=;
        b=H4sGk5UTp7uF0EFFQdLog4lNthxFtJ/NyKzWPM4rkYf1ekZMyNei4g4Vz0H70/aWom
         Ebsg/8SmRYjYZopsrcSLuz54UWegKPBGP7yCu/oKQuN4o6Jz0p7W6T+81uAq6o+XEPzv
         NIu2Y44NF7yDOzam3/7+07PHZlIa4TmsoYLoSCL+vQSCBhBzqcAX5OvRjc1cUkUerN5L
         lQo3pJdFTiYI72NZzQvNBvwMQlZvTmjspmtIS111TCrEbNsTSYJTrTtdQkrD0w6YPkdz
         FUgEOBel+QjAIuWD43Q6Z6SyesbfqR4AXtYmtTz3pAUlVpE7TIbhKHCqJhxzvRNIda53
         80uA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=mLBGOl9D;
       arc=fail (signature failed);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.13 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.13])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47f428b1c43si334475e9.1.2026.01.20.11.18.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 20 Jan 2026 11:18:48 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.13 as permitted sender) client-ip=198.175.65.13;
X-CSE-ConnectionGUID: EJLtz9XJQ0SxhH+TLBAONQ==
X-CSE-MsgGUID: mndUE8y3S0OmHDrTTUaw+g==
X-IronPort-AV: E=McAfee;i="6800,10657,11677"; a="81266427"
X-IronPort-AV: E=Sophos;i="6.21,241,1763452800"; 
   d="scan'208";a="81266427"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Jan 2026 11:18:46 -0800
X-CSE-ConnectionGUID: jzlB8dYGRCKgaRYlqzJpMQ==
X-CSE-MsgGUID: OuKWgxHoQeuzj6chWKvCpw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,241,1763452800"; 
   d="scan'208";a="206259396"
Received: from orsmsx902.amr.corp.intel.com ([10.22.229.24])
  by orviesa007.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Jan 2026 11:18:46 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX902.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.35; Tue, 20 Jan 2026 11:18:45 -0800
Received: from ORSEDG902.ED.cps.intel.com (10.7.248.12) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.35 via Frontend Transport; Tue, 20 Jan 2026 11:18:45 -0800
Received: from MW6PR02CU001.outbound.protection.outlook.com (52.101.48.59) by
 edgegateway.intel.com (134.134.137.112) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.35; Tue, 20 Jan 2026 11:18:44 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Wmcl5gBwixEPB3J6M21N24LRv9xJcyLfN5oZJeVFv0G1ISTx9dPa0lCCGxTJLS3D1fiyWB004p/wnH14S8tpftKaTkl1Yr6AKdi3QQRJuNarHuHdy/n2qeHUiXSeh1UdjKOmNkldHuaYGLky4dV/DwM1dLxpfjePChBPttZfKWKDpbOOe4Ynz5g0xclRbCIO6XhbhX/KNBXBDZdGi4ljFPEnNZMBdWhpWrRb0xLtAgHsmZC3opNHnfjB5de7JIy6KccfgMJEpVomxW8yTKgAb5P/NAKlW/80FIGbvxlUUQGY8mXNTSYXgeeoNCtbh77nZLyoEF6BWP9KdAr0YBmSeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ooZwLTGK072AebLwwDIiWKiubOmLgwRPCY0OU37B9Cc=;
 b=Oq2iDOUqHFoFhUjzMSrcmPjn14XU+sq6H715uADyKwEDA2KUZF6WNicBVczbZKhOyilgYrPDoohTLn75zMpBzd3BVhxaB1jFUASNYjaq/iWBCmVA5dR31Rn8r7+C8LXbUQ6IsnJUF5gO8De3VJ0HFiRRyN3y/AX22mYPQLZyJE1xQvX5ZgJXwxUX0mHVNEeDZHShimyF/4VMlzeKIZ6jgT8dmwq3xdWne/3tVyBtlIYrcXU4vot3Ti2s/dQcvWgKDaHRrIQgWkrUKZoDg+7oMA5DFHi/2f9uZ2Zx5BVwCSRdUScQ8HGZwTI2pnrXSxTu02+6eHbIa/hp0UIfgk9zBQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from BYAPR11MB3288.namprd11.prod.outlook.com (2603:10b6:a03:7e::33)
 by PH7PR11MB8456.namprd11.prod.outlook.com (2603:10b6:510:2fe::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.12; Tue, 20 Jan
 2026 19:18:40 +0000
Received: from BYAPR11MB3288.namprd11.prod.outlook.com
 ([fe80::e3e3:c791:111:6904]) by BYAPR11MB3288.namprd11.prod.outlook.com
 ([fe80::e3e3:c791:111:6904%5]) with mapi id 15.20.9520.011; Tue, 20 Jan 2026
 19:18:40 +0000
Date: Tue, 20 Jan 2026 20:18:23 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, <chleroy@kernel.org>,
	<surenb@google.com>, <justinstitt@google.com>, <nsc@kernel.org>,
	<jan.kiszka@siemens.com>, <trintaeoitogc@gmail.com>,
	<dave.hansen@linux.intel.com>, <ryabinin.a.a@gmail.com>, <kees@kernel.org>,
	<urezki@gmail.com>, <will@kernel.org>, <nick.desaulniers+lkml@gmail.com>,
	<brgerst@gmail.com>, <ubizjak@gmail.com>, <rppt@kernel.org>,
	<samitolvanen@google.com>, <thuth@redhat.com>, <mhocko@suse.com>,
	<nathan@kernel.org>, <osandov@fb.com>, <thomas.lendacky@amd.com>,
	<yeoreum.yun@arm.com>, <akpm@linux-foundation.org>,
	<catalin.marinas@arm.com>, <morbo@google.com>, <jackmanb@google.com>,
	<mingo@redhat.com>, <jpoimboe@kernel.org>, <vbabka@suse.cz>,
	<corbet@lwn.net>, <lorenzo.stoakes@oracle.com>, <vincenzo.frascino@arm.com>,
	<luto@kernel.org>, <glider@google.com>, <weixugc@google.com>,
	<axelrasmussen@google.com>, <samuel.holland@sifive.com>,
	<kbingham@kernel.org>, <jeremy.linton@arm.com>, <kas@kernel.org>,
	<tglx@kernel.org>, <ardb@kernel.org>, <peterz@infradead.org>,
	<hpa@zytor.com>, <dvyukov@google.com>, <yuanchu@google.com>,
	<leitao@debian.org>, <david@kernel.org>, <anshuman.khandual@arm.com>,
	<bp@alien8.de>, <Liam.Howlett@oracle.com>, <kasan-dev@googlegroups.com>,
	<linux-kbuild@vger.kernel.org>, <x86@kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
	<llvm@lists.linux.dev>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mm@kvack.org>
Subject: Re: [PATCH v9 00/13] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <aW_TZq0wi5P8jZ5b@wieczorr-mobl1.localdomain>
References: <cover.1768845098.git.m.wieczorretman@pm.me>
 <Ar_xex8hMZGd7xBV9uTSBSm-LJNAF_9xwE6Tk_9N_Z1m_mzd3Rif7vdADh9cmXqByLyLNirX3wtPU-u_70kEHw==@protonmail.internalid>
 <CA+fCnZf+U3RhmMeGxQ-UypJw2yGd8RJ0gFKrCXsC1eQ5YO-eXw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZf+U3RhmMeGxQ-UypJw2yGd8RJ0gFKrCXsC1eQ5YO-eXw@mail.gmail.com>
X-ClientProxiedBy: DUZPR01CA0008.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:3c3::17) To BYAPR11MB3288.namprd11.prod.outlook.com
 (2603:10b6:a03:7e::33)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BYAPR11MB3288:EE_|PH7PR11MB8456:EE_
X-MS-Office365-Filtering-Correlation-Id: 14c3c163-2158-49cf-9b7d-08de5858b833
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?UXJKUWsyQVdacDJiaXNHQUl2NmJKS3E1LzNzclBXLytxWTFlaFlkYmkvRHRO?=
 =?utf-8?B?bjNoYlg0TFZ6TzNOY1ZGZWdhK3JNMGtIVTVRbDU0clEveEFycnFPNXNjLzBF?=
 =?utf-8?B?Tkd5UStFRzJjbmxIOUJQUmR4WHovR28zdk5jL002bkM5ZmltWUJ0aEczaXFv?=
 =?utf-8?B?SGhNZzdqUGIwaDZmQXlHck5jdW1tNGVjcmlRN0xCcWhqeERxMUQ2dWRFTjBo?=
 =?utf-8?B?L0JwZXVieWFsQXZEYjJrbDlaYTRXOWdvR3V6ekFJcHpRUDJKRDlKSzkweU12?=
 =?utf-8?B?OW15b3cvMURTZ3FYekF6QUtDMzRrUTk2L2N6bkNjNGFORGg5VmxrdTFSaG5k?=
 =?utf-8?B?cCt2L1g4SUJrVTEzSXphc2FlZ3RVb2VEV25vaXY3TVdKN1JsTDlwNkg2QUR0?=
 =?utf-8?B?TnhyYVNKMGFiTDA5MFo2ajNaOHA0T0dOQ1VraStlTEVkeFBINWhJci8rZ1NO?=
 =?utf-8?B?bEJXa09YZER0SHVvcEc3d3FlbHVpUlFGZXd4cHprQjZpRjM3dDhZWEtnd1A4?=
 =?utf-8?B?RUYwRGF5RmJBZjhCbUNObW5la2RmdGFXdnpnUElyaFVLbEk1eUh1VlF6NXF2?=
 =?utf-8?B?bmhhSGVkMlpqTWRsK000TXNOd09PV243MWdxaGtuSUtyYmZHZ1c5dm1VbXFE?=
 =?utf-8?B?NWwrbG5aUWZ1Z0lCdEF3T0RnVHF0cFkvdUpaVlJEdDlwRUU2ZUNUdW5EWGpQ?=
 =?utf-8?B?RHd0eWlpdURsVGloT2ZSZmlFeVQrbWxpUU9iUXZyVG5idzFJSFpHV3RMTDl6?=
 =?utf-8?B?ei9Wa0MwcldISmlaWnNZYm1rR3l6OGw4UHMyUEJ5RW5tdDhTM1NJODVicElC?=
 =?utf-8?B?UEcyNWQ5NDh6VGtLRVRpNXkzVGFrdnptcVc3ZlBoVDVUNGNGSURHc094MFFO?=
 =?utf-8?B?WFpoK29KTlVMay9kSzd2TWJFcEdaU3dBdXZGVU55QkpoaUN6dDdQU2ZFMnBj?=
 =?utf-8?B?ejJWRVZnMUptczdVb3dPcTh5ODZXUjFLMEw3aFZFajdqRldDVDJnZFFRZFhG?=
 =?utf-8?B?WnBYYnE3a01rdWFtcVBIZVNPZHJrNlhTWUtKby9EbkRPeFgzZWNqa0ZHZ0wr?=
 =?utf-8?B?STh3cTR0QWtpMzhpc2p5eFp4cndUaTR6a1orNDJNSldwMmRzQjlCRVM5OU83?=
 =?utf-8?B?eWF3MUFOL3RIdGJTdTR6YjhSY2orb3V6N01EZXhJNyszSWpOU0pPYnc1ajM0?=
 =?utf-8?B?NXc3Tm9OeDBzWEpzbk45N2lSSmc5V0w5c3J0TGVMSHF6RG9IeDZ6bnVVcGJC?=
 =?utf-8?B?UmJjMHZydGVMOS9oRk8vR2RIV3pHNGtCOHNJN0lSYkZKeWdESFpxRXNVaDBU?=
 =?utf-8?B?dFU1ZVdEcXRpa1VabFRucElIZTFnRExsODdkU0JsNVBtUjRYa0RNeVJtNzl2?=
 =?utf-8?B?bzBidHdNSGVZL0RYRnpoYnBSdy9kWWxtZHpLNE9vdW1FalBSelVLVTBpK0pG?=
 =?utf-8?B?LzJjdHRSZGY1ZXg5UzM5VUZycmxrVU5HOHB1OE5XcXE2RFoxd0xNbnd4WWdo?=
 =?utf-8?B?ZGV0NTRKRi9PSzQ3WXpQRGszUHJ2NS85OEJKeFhtQmtRZys5YkFRVytvMFh6?=
 =?utf-8?B?cjlaWmk4K2IxblJqTDdHY05oMU5rOWw3bi82MWVzM0psQ045UWgySDg3QnhI?=
 =?utf-8?B?c2RpVHhRRXlkQm02aDl6emVaVGFJVklvVG5jTnNjNnlwR1orNmhiWnp2VWcw?=
 =?utf-8?B?VmJQSHJMeFBETUhkVmlZZVhpa3hkRXFZVm1qVlBjQm9jMnZEVjJYQVcvbHYx?=
 =?utf-8?B?d0pHR0ZkdzV2REhpbXg5WFgxOTNTRG9rMUZlRVhqR0puUU5kRElGVmo4em95?=
 =?utf-8?B?UzFaeS9jbjcyNWRTU3dpajBUNktCa0hoRlBqUmlpeXQ4V2pGcnJzaTFoNm1Y?=
 =?utf-8?B?YW94dmhKYko2aFhmWnVRVFBhUzJQZ1c5OE40KzQ5emNZREhyQ3NPdUtoVkkw?=
 =?utf-8?B?dmE5NmVSZENSZFBSYmxMUVAyUWoxMGpER3N3VjZSa2l1VXhiUUlQckxHNUFQ?=
 =?utf-8?B?ZDUrVXhmQ28vdTY0VTFBWlBPSlNuMjBKdjZGWlFSSStoSWJERkNKQjA0VDZ2?=
 =?utf-8?B?NEFmMFVZck9iUDFyakpyNFM3RTlTTDBPYzVBSWo5RGpoM01wQzhMajQwVXhN?=
 =?utf-8?Q?1Tbs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BYAPR11MB3288.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?NmRGTXhoTlhPaHJ2Z2lTdndiQ2FpTTNIdFc2S0VRcnViaTZVTUlhcW0xSFo5?=
 =?utf-8?B?bXJlRjBLVjNSTHNCTldVcy9LQ2c3c1ZVRUR0TEg5bGx2UDVxeXE3YjFqNUFs?=
 =?utf-8?B?SXhjc2NzU2JlQ3ovUjRZUE5XOVUwcnBRSVZGTVhjbnBOclZMbUNFOGx1aVJL?=
 =?utf-8?B?S2FIV2p3YzZsM3ZjS0tWeEhWUFRTUW11QjYvRnZOTU43YnVWR3o0T2VLd0RD?=
 =?utf-8?B?OHZKTmdwUkJQdkIvSXhBaytydlM1SEgveGxKbHZDTG5FaVE2UnFLZ0ZNL1Az?=
 =?utf-8?B?OXNNVXZ6a1NyaGFCUWRqUE5PVlN2NlFaMXZhTDh5bFFyMXVaVUR6TldQVHhC?=
 =?utf-8?B?TFZZZVNqVnRpd2t6UEVvU0F2Zkd6SkRFMmc5VHFEczhwZXlQVnIzditjQTFL?=
 =?utf-8?B?VHZvVG1obm1PeVo5SnRpeSsxMXhpMDRaWDNkUzZSRGg0TngwYnUrUE5Wemp3?=
 =?utf-8?B?SlU2dUYvZEhkR2kwZmQvNktOT2dEbTBBVGI5aVZZK0g1aDlLN1VxUE1xcW9k?=
 =?utf-8?B?VHdJd0d3a3ZYR1diWXh3cE94MEdVZ29wdXV1SitGNG44OGtBZGxFTC9tSWp4?=
 =?utf-8?B?MFI4RnBQc2NkM0RBbTdRb2V2cVEzZUYrYU1QK0FmQ2N4MmxrNU11aHNoamlp?=
 =?utf-8?B?a2dnS2N5N1J4dE5mMkxmMFFrclNaU1EzU2pmdHV4VnVUcE1QMmUwakc5ZWJm?=
 =?utf-8?B?Tmt1KzFFN1VEaHVWUkxoanpvQ2oxODRzSndPTC9ERU5XRFZWbHI2NHFlbFNm?=
 =?utf-8?B?YjRLTlVRVS9nZG5GcjJ1S05HcTBvaHZDZzFjaXIra084RDFTQ3d2QUNsOWlM?=
 =?utf-8?B?dk5UaDEzd3FybnZYd1hSc3psNHdqMHR3SlhISmV2dDVxWEtQdFJqWTZYNWY2?=
 =?utf-8?B?ZnROK1c1dGh2eEZjUExBKzlBMFM2eTRkT00vS1BPVS9hTkFqR1oweStPZEpT?=
 =?utf-8?B?S2ZRWnIyTXNGZVY4aXlkcDRra3BNWXdCTHhsdEdQeE45SHU2WHorZU1qVzlE?=
 =?utf-8?B?M0x3elZsNjFTcVpjbmJ6cTV5SURiRk83dlJ3Nm5Wc3pnRTRPMkZYTGYwa3RC?=
 =?utf-8?B?NFBWRUJ0MnZJaGJJZzZVUTVoVWFKL3BFMktJV05iV0hwRjl3eHlkelgwZ2J4?=
 =?utf-8?B?bnNBOFFGdlV5UFhpMTBLUVd1UHBvby9MMHFBcXl5L2w5amVEMG5kUTRvb3Zm?=
 =?utf-8?B?WmNxUmdjS21WaUpMUnFOUG5jaUFCaWpjWUpwOXh2aVhBY2s3cWl4anIxRDVR?=
 =?utf-8?B?bzV3WVVOWjRvN1phMmpBR1htNWkxUEZpeTBucUVGWlZCMHdwT2dWOWs3NEw5?=
 =?utf-8?B?SGFxbFhlU1ZTaHF2TkZhSDF4N2dSaHNjU3lUMVdHeGhrZ05oU3ZnaFg2bHhi?=
 =?utf-8?B?a3NRU3g5bmhINkZicnREazgvL3RMam91SWhyMHd5NkU4RzNGeXFMeFdhWGFZ?=
 =?utf-8?B?bE1KZVM4QUh5YVAxTnVOZ1pyOW5yb1ZjMmx3MVZwNGR1YWRyVVlaa0hzUGpO?=
 =?utf-8?B?VG9MSS82ZzYzT1drUFJOUDYzZ2JwdjdhM0xXWGpSZG9hZ3NxRk5EZkxpakxK?=
 =?utf-8?B?bjl3SHU2N0VJZ1JGcDhIOWlyYmJWbU1Sc2lHVnFtR2pBZ2tFa3oyVEhCMWxx?=
 =?utf-8?B?RUxVVE9RZzlpdlozaWw2QjYwVklUYzlFK3hzLzJoaDREaHBXT25YbmVDSG9j?=
 =?utf-8?B?aDBad00zT3hGZ0h4MjBNT0tKWnkwaHNWVU4zcGlKcWFpTVJmNjJOTS9tdkht?=
 =?utf-8?B?S3pSbkRCY3Y4S3l3MUthUlgyNURJVit5OXQ3OUsrSVNyQkZ0alRSdGlJVGFr?=
 =?utf-8?B?NHFidXhiMndxbFhaZ0NpT2pIbHZqVnQvSWRsNjNnVEVCMWhNMW9aeEQ3cENv?=
 =?utf-8?B?YUNrdjNGSkpGS0tGR0d6U2NlV3BJcWdZOW8xU1RSSG1VdXpxVkdDZ0RQUnM2?=
 =?utf-8?B?Z2ZYby8zbDBhRHJzV2xiRjlCdDN5THJsRTZUbE12b2dHZ1hSaVEvRWdSdnEw?=
 =?utf-8?B?aUV6aDMvUVp6UnBQaWN0TWpNRDhtSmFqSDhkK2xoMDk3U1dZeUwzc3RxdWVI?=
 =?utf-8?B?NFV3VDFLOGN4ZmpGOHM1SGdJQmk3Z2drdXp2alFTSmlZRmpjYjh2MXJZR3BM?=
 =?utf-8?B?Rm42aHJWclBCMGZFY2U2YkxqZW1hYlBRQWg1Y0VJTlNqMDN6azgwSU1KQVdh?=
 =?utf-8?B?VmRjL1ZFZGpuQm5wbkV6cG1BdUNXTGNmd1dFNFY2NytObi9naDh6UmJ5Vjk3?=
 =?utf-8?B?UlBPRVhQRU94dlV2RWRJaURpa3ZJYTNhbHMzbjlSc3o3cks2MWZpVGpTQ21n?=
 =?utf-8?B?MCtiYk11U0t2cndxbGNTaE5jUUJKelNQWEhsYXZoRkcySk54L2tqRGdoWFpV?=
 =?utf-8?Q?DmsTWR3DGdr+rlDt+1pCZlaRa+H18+7FVxdC2?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 14c3c163-2158-49cf-9b7d-08de5858b833
X-MS-Exchange-CrossTenant-AuthSource: BYAPR11MB3288.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 19:18:40.5559
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 76HSVs5q4sciVC1l4IR+hPxdEIP3ow5sUodr2p+hREtXwCyuvqLwgWZFrjpetShPXZvMXKmqY/M7GMC3rsnagniwvG9B9EYfcuOI20fM9I8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB8456
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=mLBGOl9D;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.13 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
X-Spamd-Result: default: False [1.89 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_REJECT(1.00)[cv is fail on i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[intel.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCMMDDFSWYCBBGVKX7FQMGQEKJ46HEA];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:email,wieczorr-mobl1.localdomain:mid];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_GT_50(0.00)[61];
	FROM_NEQ_ENVFROM(0.00)[maciej.wieczor-retman@intel.com,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[pm.me,kernel.org,google.com,siemens.com,gmail.com,linux.intel.com,redhat.com,suse.com,fb.com,amd.com,arm.com,linux-foundation.org,suse.cz,lwn.net,oracle.com,sifive.com,infradead.org,zytor.com,debian.org,alien8.de,googlegroups.com,vger.kernel.org,lists.linux.dev,lists.infradead.org,kvack.org];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[10]
X-Rspamd-Queue-Id: CC94E4A2BF
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 2026-01-20 at 18:54:48 +0100, Andrey Konovalov wrote:
>On Tue, Jan 20, 2026 at 3:40=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> Maciej Wieczor-Retman (11):
>>   kasan: Fix inline mode for x86 tag-based mode
>>   x86/kasan: Add arch specific kasan functions
>>   x86/mm: Reset tag for virtual to physical address conversions
>>   mm/execmem: Untag addresses in EXECMEM_ROX related pointer arithmetic
>>   x86/mm: Use physical address comparisons in fill_p*d/pte
>>   x86/kasan: Initialize KASAN raw shadow memory
>>   x86/mm: Reset tags in a canonical address helper call
>>   x86/mm: Initialize LAM_SUP
>>   x86: Increase minimal SLAB alignment for KASAN
>>   x86/kasan: Use a logical bit shift for kasan_mem_to_shadow
>>   x86/kasan: Make software tag-based kasan available
>>
>> Samuel Holland (2):
>>   kasan: sw_tags: Use arithmetic shift for shadow computation
>>   kasan: arm64: x86: Make special tags arch specific
>>
>>  Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
>>  Documentation/arch/x86/x86_64/mm.rst      | 10 ++-
>
>Still missing Documentation/dev-tools/kasan.rst updates. Feel free to
>send as a separate patch to avoid resending the whole series.

Sorry, my bad, of course I'll send it in separately if this iteration gets
merged. Thanks!

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
W_TZq0wi5P8jZ5b%40wieczorr-mobl1.localdomain.
