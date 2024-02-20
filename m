Return-Path: <kasan-dev+bncBD2KV7O4UQOBBLNM2GXAMGQEVSVZ6GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B1EA885B410
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 08:35:10 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-dc6b26783b4sf4131919276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 23:35:10 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708414509; x=1709019309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BfrKLM4MR6uU8+LvJpMKWv9oQNff3S4KfN1DbIartnI=;
        b=gS90+wpWDPRxD9TVKKrbf9dRdlP8kvaW0I+rUoMWv8c+K8xh/OCrTV4cPn01Zm/EbL
         J8jjiLkciNPZQE2RqyDtDkJBhGKRrvBRVXx/bUMGoKAaaJ0WCtlZl2Bxz323lLIgrmYM
         Lo2POU4XsB7JoiMqozJHKm9AIxDR/qXkerSGH3MIO0Nwg1wNznuGFuikEu72sheb4snv
         1CpyowABgoGe3USW5mr+QutvTbNetuwcOOGMnAVc9WMob4xtbR21aGo7gjQ9VWWeQ+qG
         /LdWHc93sLp8T3VA3XFr62CA+WGxQPotKQJN82AppQqWyjJHhT7FIvCmHFCkdoBHYcUw
         Vglw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708414509; x=1709019309;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BfrKLM4MR6uU8+LvJpMKWv9oQNff3S4KfN1DbIartnI=;
        b=hIzD4i7RTHzjsvD3RXi1OPRVBA5rnd6uZhs9SbIQKs0GDhIMacuGEbKuzPDwN5iLBB
         Tnu+x5sknfX1pEJ6eA1lT0ys+y0rssi8cpFNYgAOiB6XS2gh74FP9c86oFetqDMfwQlt
         DIbkiQX4o6USe9iykbEImLZKeVVsbtCTz+EySMnIfIMSi0P8jGHe/efTJ6rmz4L6W8zp
         8YPrIsti/3ykGHJ5rvrhTGAJt+j7Cc8I4Vu7g8mmmxbc1pwWbs7u13s00OwTldZLYHaa
         zKPqPBigcqEJUZee2qgTgphcs2jieHS14CD0OGplOWCCjx3UDyJDJOSGNmmMz4VyL+Uf
         s/Rw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9Z8wyGBCZ7/I5S9rhZZs9JDB8zTVEVUktApK+RHNf8xhyHXRV3bswu5xz5Onm4GZusHRFLGUyfhwvgMD1ZuoK2lyoVf3+bQ==
X-Gm-Message-State: AOJu0YyBoKqxljY9U9Pc4pUY0/eRddmnsLoo3QZrbOhujFSDRlH7W2xV
	WAdkjPJdfZS8Xlua7eEUsS504pY+11VBVAHUcD9yFG1OOAXiRqfs
X-Google-Smtp-Source: AGHT+IFp6qEJWvEVCVDbIiaN5348GUuVlcgmFnz3rEeHNvORkEDNogEUbLJXEJfyPBl0cYolzNYM0A==
X-Received: by 2002:a25:ad4e:0:b0:dcc:f8e5:c8d4 with SMTP id l14-20020a25ad4e000000b00dccf8e5c8d4mr12526222ybe.32.1708414509240;
        Mon, 19 Feb 2024 23:35:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d097:0:b0:dcc:f46b:129d with SMTP id h145-20020a25d097000000b00dccf46b129dls920682ybg.2.-pod-prod-03-us;
 Mon, 19 Feb 2024 23:35:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMwmF4AGgBRSp8YaNmNtQx28YY4MyYcwJPRBLM6GI8EvXyXVri+kGGLA6tsQfq1vCCgxqwPnaxRd1CcO6UwS/NWkr9MsLt7CoGkw==
X-Received: by 2002:a05:6902:2702:b0:dcc:5e60:6fc7 with SMTP id dz2-20020a056902270200b00dcc5e606fc7mr13110193ybb.55.1708414508188;
        Mon, 19 Feb 2024 23:35:08 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.14])
        by gmr-mx.google.com with ESMTPS id o85-20020a254158000000b00dcc3d9efcb7si960335yba.3.2024.02.19.23.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Feb 2024 23:35:07 -0800 (PST)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.14 as permitted sender) client-ip=198.175.65.14;
X-IronPort-AV: E=McAfee;i="6600,9927,10989"; a="6319707"
X-IronPort-AV: E=Sophos;i="6.06,172,1705392000"; 
   d="scan'208";a="6319707"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by orvoesa106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 Feb 2024 23:35:06 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.06,172,1705392000"; 
   d="scan'208";a="4944425"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by fmviesa006.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 19 Feb 2024 23:35:05 -0800
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Mon, 19 Feb 2024 23:35:05 -0800
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35 via Frontend Transport; Mon, 19 Feb 2024 23:35:05 -0800
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (104.47.59.168)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.35; Mon, 19 Feb 2024 23:35:05 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=I1gpcKl3cxsfFK2KCbEnPQHrqIaI7qxI7QfUiUxNMnPrgHfjVmNWK2NW0nvwN+jBzBrZHyTQA88dU58J0PffV2CUI6bzZw1hByZ2EFcdG0A/8VtflnyVDIuV9dAqoA1o/G7Gx39aFv0n4HHkO8jdb4fBfvbEHZETfZwf0q7a0VnbAJxhb0BY9lj4PwqMaIsZDCFw8oa091NUhCF6/5zAzl+MaMw65stO6EsOih+vuiAEYbbI+yMXg4PwRFodYfEGrj8gNH+raPjntrl46DsY+y7ySPgQp4Pdse5rGzz2X721JDL1Bw4qEQ4+3dWmE5ZdB8vTh7gkjRLmJ2ghgUm6GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2V/RwFGMXGDml02CnksDWIwD0Bh6CDszBTXESAwwFjM=;
 b=oaHik8inDgf/GIySpFvwlX5zFRWtuQg/TZ0BSDRlFFIXu83n/w78nvmgq6Omr5rRXXAGctD4NKxz4yhADGliDGzjKrSBmLZOICb3AIBu5EHInViMykB/G11Fp32w7l49RC25aeENCgWMe+XATRwGRkOhJPFJhfNgtPexx9JPoYXBQG1IsKJiWKRfaXxKnlOlY5SaT9TXdzHDzL16Ehf+tObXyKVgu3NJIr50tWZinT9OvZeHo5ay/bRVti7IkJoXfuM4QNMJdsSGYYaGfRftbS4FPUyzEvDcoe/Um25vMHtpcZdPGhVm8EU0R98CMZ2L8drrs7qOrFkpALsklUCpfA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by DS0PR11MB7735.namprd11.prod.outlook.com (2603:10b6:8:dd::6) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.7292.32; Tue, 20 Feb 2024 07:35:03 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::a026:574d:dab0:dc8e]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::a026:574d:dab0:dc8e%3]) with mapi id 15.20.7292.036; Tue, 20 Feb 2024
 07:35:03 +0000
Date: Tue, 20 Feb 2024 15:34:53 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Marco Elver <elver@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, Linux Memory Management List
	<linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Vlastimil Babka
	<vbabka@suse.cz>, <kasan-dev@googlegroups.com>, <oliver.sang@intel.com>
Subject: [linux-next:master] [kasan]  187292be96: WARNING:suspicious_RCU_usage
Message-ID: <202402201506.b7e4b9b6-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SI2PR01CA0051.apcprd01.prod.exchangelabs.com
 (2603:1096:4:193::6) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|DS0PR11MB7735:EE_
X-MS-Office365-Filtering-Correlation-Id: e6ed7b96-5bdf-4a6f-106d-08dc31e673a6
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: PYlpeVm4zG1rHaCivzNIg7pHMmELQqQOMGmG1p47NztYVd7GMypX+4V5Tes7d77wvFBicHPVMSwq7zWC9kwe2xj7EvSs9Ja+9WGzO0IcTlTaBNyLeubprhBUoGk4gg3HYXtxDCpK4KtCekQdv01+kSrOnd6GEJ4kp8kd0XWeFY+uEL9WQV8XLjUuZOJcpk64YDqjc/Y7UmP35iy+Y15WkNh4k2DoX7jywm1pk80Z0l6Fn+NHkDizCKleT+rKsNVD2PG8lrL9JUX4IsK1XpaLX+6Wvw/3H/ENd2MqKrj03PfN+ZG6ivufL64uZJYww2XAnQnA76iNbKQaCSKn/6KI+TfVgYPpGLf6wlGTV3iKfyNTZ5YAT6fLEEcApyfv6TJInG+u9oXSc7LlfotXYSRR/EYKwmhScSpJAogJ5hBO6Svi0JPwfZ64IRrjjy11UFNQLguLhkPt3QIO+d43M5AyQIc9s7OYMvSzCdJOoXIjZ1rAuFR598Re02xtqVJhTdWL6Qn1hIXoce3TtgWPJmNIO6APsfhfgwmU63YNBT44LsJ+aY9p6Xc5nIj1AgWu1p0m
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(230273577357003);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?eRlfO6I9cyX6AEl7a8tCTwcVd4rZyBeG6zbkAVwosdQPZlIuXc9zKh0SrnPA?=
 =?us-ascii?Q?GcTNljD/KCJYIcpkrYQ3L98waswPWDconnc7I1eFKjLYKMAmiCnW/toQtFBz?=
 =?us-ascii?Q?u9QwceLfaU5gfeZB/gL2cG8BiBqkOAJ30oKxftguaSDmV5onS53zeNEn9i5R?=
 =?us-ascii?Q?VoZgO4uwULlQnQ/H3yuzFK9GnvQQ265l6FjEnq/JPk9/fcLTykOM9tG2mCM7?=
 =?us-ascii?Q?BnNi/3uvCxmsV0466jMCsn4AzerCykb3bnPWGSb0bMy9qsk73kvgGv+8Iau0?=
 =?us-ascii?Q?oBPgaYYnYP72ZkcSrEZIEu40LPbWXnCdf6zfZGtwSyxZk0OJGJbp0joNYxYf?=
 =?us-ascii?Q?5a4ZKM5G0DmTW3F8y+XbIKbMZ8ykT3jQLmpTqdUdfXK53AO4ghQLQK8623tC?=
 =?us-ascii?Q?D8ac0ljVFzMzAjIxe7JAxo0OFcPr/nUbEJ6e3WRpQIfGGLbtKVK2sd/pwO+y?=
 =?us-ascii?Q?+62lb/22s8DIDZMBloKxhaQH41AyE99QQPfyTr0D0OXo7i0AbYvhy8zWJz3c?=
 =?us-ascii?Q?N52+Oea6tEYhMrF0ACMfehM5fMjkyNkoBZoUBJRTDcYcwlOG8vLOPcc/z/qi?=
 =?us-ascii?Q?oy3IdIZzb7XY8Q31YXUpallk/f0W0QIG4T0qUxF1JHeCKR8jweTiiLpzEGpQ?=
 =?us-ascii?Q?b/5cxCcfbap5f2sblGJ5B1JweYC6fDGxqXvXcBOzqYw8mFg3kILjSB+omIU5?=
 =?us-ascii?Q?6VFrKEG/u0HPz2OsQ6BUfLsuNf6XXvM1oiwEsc0awm3GhKEOQCOuWb0dUx8z?=
 =?us-ascii?Q?oH1ez0otch0OyJ4YHNorSTqegmG1ra4vX2QUbEs1XaYvEg8g7z/oLvLfPQYZ?=
 =?us-ascii?Q?m4g0nS+1s/KtDciYYEbQ5Ngy5tO59gubfPKNyiNi1A0i9HdzA4RxAu3nWwE6?=
 =?us-ascii?Q?D4ywRd/nSKtomHm8cVb5+JywlMLMj4ID7zrzrBLO4LB4VtREckH3WoUo2d7S?=
 =?us-ascii?Q?rGmkSoYJ0awPM98+fKUkoMfl07B2bgsdk/4l3h6nYBXdKNVoNtvHBKGJoUBR?=
 =?us-ascii?Q?cbwID3fayb+RBjEBakaU/1/A4HrRPGogzU+HTJd0a9pXzk2v0ctaf3SrziGz?=
 =?us-ascii?Q?Wy61uNEmJirUt/zJcliLPsHVWD9A1zqUeP3cjys4EQFSK7uIAB/DRwMk40lc?=
 =?us-ascii?Q?EFcseMcXTXQzXpx7RCQSTi2jCze9aHl/U8Nn6KDcT0MhTuLP+GNFK23fCXSd?=
 =?us-ascii?Q?c5bozMAeH/zxvcKRzK0NIZbk7RatMYdcKI14+jfQ5TC+w9JzaJuaRwHA5MlJ?=
 =?us-ascii?Q?DH9z4ZSAfr2LaRTmOyRnDuN3Q3TqZGSIVVhsx2eRSwqfVcp0NqNjiQOKvZeW?=
 =?us-ascii?Q?rzVv+GvHlM2B5UQ6rfNbHkHoh7hTu33wrFwZUYORoC5OoNk5lXBQAvB7J2OG?=
 =?us-ascii?Q?cAwx+IplHr2MLeIpddU/3B7Ya+AT73UIxzBHZyMSueWZg/Zaq40685CJbz74?=
 =?us-ascii?Q?1mKqQqmpQorddR8y0IpUYf5KEVelLHkCGKGsDH3FjrMQKfvsQcwje0KMl6fA?=
 =?us-ascii?Q?PwOOugYyIgpz++72SYpEdO5FTgYcU5O0FRR0zEm+gVkuRwAXnKLGUbVNOOY+?=
 =?us-ascii?Q?CxviV1Hlk4aXAM3mn4sNHwqg5ydYa1/A8Xm1xKF+Jap83psdokNTYbOkuYR8?=
 =?us-ascii?Q?IQ=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: e6ed7b96-5bdf-4a6f-106d-08dc31e673a6
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Feb 2024 07:35:03.3097
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ugaFBSvR5qPntbHxUay3rfGhzO8akDNwnJbbP0sWrKgVybNUEslKFkz2j5vyRZpgp2EPL8hqCRHqq25fu+RPEQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR11MB7735
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=R4KMVdyU;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 198.175.65.14 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

we noticed this is a revert commit, below report is for an issue we observed
on this commit but not on its parent. just FYI.

113edefd366346b3 187292be96ae2be247807fac1c3
---------------- ---------------------------
       fail:runs  %reproduction    fail:runs
           |             |             |
           :6          100%           6:6     dmesg.WARNING:suspicious_RCU_usage


kernel test robot noticed "WARNING:suspicious_RCU_usage" on:

commit: 187292be96ae2be247807fac1c3a6d89a7cc2a84 ("kasan: revert eviction of stack traces in generic mode")
https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master

in testcase: rcutorture
version: 
with following parameters:

	runtime: 300s
	test: cpuhotplug
	torture_type: busted_srcud



compiler: clang-17
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202402201506.b7e4b9b6-oliver.sang@intel.com


[  292.513535][  T653] WARNING: suspicious RCU usage
[  292.514923][  T653] 6.8.0-rc4-00126-g187292be96ae #1 Not tainted
[  292.516369][  T653] -----------------------------
[  292.517743][  T653] kernel/rcu/rcutorture.c:1983 suspicious rcu_dereference_check() usage!
[  292.519310][  T653]
[  292.519310][  T653] other info that might help us debug this:
[  292.519310][  T653]
[  292.523130][  T653]
[  292.523130][  T653] rcu_scheduler_active = 2, debug_locks = 1
[  292.525644][  T653] no locks held by rcu_torture_rea/653.
[  292.526974][  T653]
[  292.526974][  T653] stack backtrace:
[  292.529271][  T653] CPU: 0 PID: 653 Comm: rcu_torture_rea Not tainted 6.8.0-rc4-00126-g187292be96ae #1
[  292.530780][  T653] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[  292.532329][  T653] Call Trace:
[  292.533524][  T653]  <TASK>
[ 292.534696][ T653] dump_stack_lvl (lib/dump_stack.c:?) 
[ 292.535941][ T653] ? __cfi_dump_stack_lvl (lib/dump_stack.c:98) 
[ 292.537221][ T653] ? lockdep_rcu_suspicious (kernel/locking/lockdep.c:6712) 
[ 292.538523][ T653] rcu_torture_one_read (kernel/rcu/rcutorture.c:?) rcutorture
[ 292.539887][ T653] ? __cfi_lockdep_hardirqs_on_prepare (kernel/locking/lockdep.c:4312) 
[ 292.541226][ T653] ? rcu_torture_timer (kernel/rcu/rcutorture.c:1955) rcutorture
[ 292.542621][ T653] ? __cfi_rcu_torture_timer (kernel/rcu/rcutorture.c:2055) rcutorture
[ 292.544012][ T653] ? init_timer_key (include/linux/lockdep.h:135 include/linux/lockdep.h:142 include/linux/lockdep.h:148 kernel/time/timer.c:847 kernel/time/timer.c:867) 
[ 292.545262][ T653] rcu_torture_reader (kernel/rcu/rcutorture.c:2093) rcutorture
[ 292.546579][ T653] ? __cfi_rcu_torture_reader (kernel/rcu/rcutorture.c:2076) rcutorture
[ 292.547872][ T653] ? __cfi__raw_spin_unlock_irqrestore (kernel/locking/spinlock.c:193) 
[ 292.549108][ T653] ? __cfi_rcu_torture_timer (kernel/rcu/rcutorture.c:2055) rcutorture
[ 292.550341][ T653] ? __kthread_parkme (kernel/kthread.c:?) 
[ 292.551425][ T653] ? __kthread_parkme (include/linux/instrumented.h:? include/asm-generic/bitops/instrumented-non-atomic.h:141 kernel/kthread.c:280) 
[ 292.552489][ T653] kthread (kernel/kthread.c:390) 
[ 292.553504][ T653] ? __cfi_rcu_torture_reader (kernel/rcu/rcutorture.c:2076) rcutorture
[ 292.554689][ T653] ? __cfi_kthread (kernel/kthread.c:341) 
[ 292.555749][ T653] ret_from_fork (arch/x86/kernel/process.c:153) 
[ 292.556792][ T653] ? __cfi_kthread (kernel/kthread.c:341) 
[ 292.557852][ T653] ret_from_fork_asm (arch/x86/entry/entry_64.S:250) 
[  292.558920][  T653]  </TASK>



The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20240220/202402201506.b7e4b9b6-oliver.sang@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402201506.b7e4b9b6-oliver.sang%40intel.com.
