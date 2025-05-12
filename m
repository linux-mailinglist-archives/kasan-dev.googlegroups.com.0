Return-Path: <kasan-dev+bncBD2KV7O4UQOBBK5FQ3AQMGQEPWAOVHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 53696AB2F71
	for <lists+kasan-dev@lfdr.de>; Mon, 12 May 2025 08:18:21 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5fbfdf7d306sf3652404a12.3
        for <lists+kasan-dev@lfdr.de>; Sun, 11 May 2025 23:18:21 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747030701; x=1747635501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+wDCp7gEmoRDI8GSG+Gk9AFkAQvDj8CnYoPmLcKwE7o=;
        b=eRyFV/3r/8EgoExFyi3Am+KNcVBXO/qSfzrRdacKdCPG46lZP61GWwJPKRkfHFXDNO
         ZF+pDVV41kePEhCS/gwx01rEb2ZV7uUUeZhuC2vnWN0CY8ftlopC/QPUp3Vp8d2g2pM2
         hiJv9DcRRBupiJAJld2CrkdZ8XaqTorI+rM9ytCLsXAicL4mbB+u6IV2o84UI4mazRF8
         Tzw+tvHL0jN/i6Qn+XEaw+A33eE76sZEOretHQhvIT35f6Bd9T2//tf/I2H9SHrNG/BS
         jc04l35oJXabmNAtWlQvGZmw6z526TtsacWMhNGv6b1a5pSsKb4s22SZ2ahg8IYacIwg
         ZUiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747030701; x=1747635501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+wDCp7gEmoRDI8GSG+Gk9AFkAQvDj8CnYoPmLcKwE7o=;
        b=orYqThf8J1zdsEaaC2hsnALwsR48gFpXODxOSy4XOSfvrOzaaAReusN7U0AEDH1N5r
         z5b7WoAF7D5vcChkkrrd2XbPNwf1sRbKUn8hITpg4O+PUWNz8ugyJveelEWW/JYnrKFV
         MunhdhP/9Ruwwn0EwglvOc15q6AwEGnNabqnq4WsVVMc232S72+mIqw5NQuWNsbe+tJN
         ktaThgDWgi8rT4aGog/BcvWXJOsXA9Z2S7gzVyzs7fYnObzPD/5TnDIQZiubeRk6izs9
         Tp3i50sxifg58Htrm+m2Wq4GXKtQQrrH+AF7Rount4TJyn7QIMIkawnKzi9QjJwREQdX
         cDDA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWkEUgebk3AaO4C927BRoFVmJ+wXN0CpzM2Kyi5dxyG7JLdXxD6k9uPcrXM09eX9//KDUWg9A==@lfdr.de
X-Gm-Message-State: AOJu0YzEIvkrDZGixXwjRzJE2StCvUg8B6wdxp9C+xKdrndiW1nkQwpb
	OeGN65hI0Sm+DMNPP0/sg6ZPPObKEeKyY8P9cE0TZr6zQ2e5VIdB
X-Google-Smtp-Source: AGHT+IFDy//RDgg0m8NhPJU25X6U8ohDVhZiKgXcINNa2tMaYMd8sUcXDAG5mMBX8FMWufw9qZ9zKQ==
X-Received: by 2002:a05:6402:370f:b0:5fc:994c:b6cd with SMTP id 4fb4d7f45d1cf-5fca075e225mr8134378a12.13.1747030700359;
        Sun, 11 May 2025 23:18:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHNCQfR1wI8Ur4+J7r7EazLadnBj120SzAmUq4lyP9o3g==
Received: by 2002:a05:6402:270c:b0:5fa:a052:b134 with SMTP id
 4fb4d7f45d1cf-5fcc86728d5ls17065a12.0.-pod-prod-03-eu; Sun, 11 May 2025
 23:18:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOOe+iCGR6mA04VIQex/g01UPracwr9+4C6T9ECLTcZJYYxtxT4ooUmx5s61eCA6z9IP3FlSaozYo=@googlegroups.com
X-Received: by 2002:a05:6402:35ca:b0:5f6:c5e3:faab with SMTP id 4fb4d7f45d1cf-5fca0730954mr9912365a12.1.1747030697564;
        Sun, 11 May 2025 23:18:17 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5fced795941si99701a12.2.2025.05.11.23.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 11 May 2025 23:18:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: 8ebhRb3rTb2ZrsM51+6VDw==
X-CSE-MsgGUID: POwA3AjFSciTxjU1Zacq0Q==
X-IronPort-AV: E=McAfee;i="6700,10204,11430"; a="51466287"
X-IronPort-AV: E=Sophos;i="6.15,281,1739865600"; 
   d="scan'208";a="51466287"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 May 2025 23:18:14 -0700
X-CSE-ConnectionGUID: DMYa6HhvR2KWODej1H9UVQ==
X-CSE-MsgGUID: 6FCvzBMCRnSwPdbIlINRgQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,281,1739865600"; 
   d="scan'208";a="136976974"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by orviesa009.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 May 2025 23:18:15 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Sun, 11 May 2025 23:18:13 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Sun, 11 May 2025 23:18:13 -0700
Received: from NAM04-BN8-obe.outbound.protection.outlook.com (104.47.74.42) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Sun, 11 May 2025 23:18:12 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=bwDEO2cAZslxSlfBcphs6RRPPoyzZDGrenzQotya3IUHIlLJhATAQAffzneQgmUoaV/nYUQNfm//REK7oGQpO+FXYHfWT3HdYDV7uVmM/DwahOMd2X9Bec9VpydTRITfAtvjO8DrREHPCNxEPri9xb1DaNBd29p4RX+zrzH+055M/oikI/c4wOYaPodI3fTigbwYYvi7nvWLa3ik5gFFdFNMW2BQr0QqhEKnrKT7SjgBFijhqq471g9ogvugPIUMaJbMqB1HcDXZKd/F1PX2CI9D+UCHWp/7RfYc+9wr9WlAXv0A6xJm/OzSsnlr/7QGd9PLlWwPN11Y722tZ++IKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HNVa56rTxo1qDFvvqFyZq1GwINQXQVcjnjguEH+LEyA=;
 b=uQJ4t6GuU302ZIiZ8YqOLraDLyQyxhGKltGBn5rfGy0GWzmn80wlZSzCTI/EKC5yACa2BSObGKxw+0C9H8XgDjOBMUXa3Rr8eMDsugz6F8sQYUOpPzgO9UFb+BhgAMFNls8Wdk0EzRCJEMmimSN20HgkmqM9iOItBCmNl4tCuo1R+sBRVo3FnfmPtnlZCU47ncX8m1miYPqwIsctJV/VHQhzD55fDinZlVSKe8memMXC3k2reUz/V5vWH45dAk97rPkJFA2L8zMfS0Q7BRn/2+TjHaCVUBKrIkQTqgZIi/TJIAs0XYzvPLSFXRI2Z3BWJsbEQgxgu5rJHakcWGUZvA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by DS0PR11MB7409.namprd11.prod.outlook.com (2603:10b6:8:153::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8722.29; Mon, 12 May
 2025 06:17:56 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.8722.027; Mon, 12 May 2025
 06:17:56 +0000
Date: Mon, 12 May 2025 14:17:47 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, Andrew Morton
	<akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	"Daniel Axtens" <dja@axtens.net>, <kasan-dev@googlegroups.com>,
	<oliver.sang@intel.com>
Subject: [linux-next:master] [kasan]  bb37c7f4fe:
 kernel_BUG_at_arch/x86/kernel/irqinit.c
Message-ID: <202505121313.806a632c-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SGBP274CA0024.SGPP274.PROD.OUTLOOK.COM (2603:1096:4:b0::36)
 To LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|DS0PR11MB7409:EE_
X-MS-Office365-Filtering-Correlation-Id: 6f7fc726-d600-4a9b-c256-08dd911cbcaa
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?kQUesTHmCXA50gHBsOuCXPY68PCAo18/0vjH0gaHwFAdEJTJ0jtNbswFg+Yk?=
 =?us-ascii?Q?P8j2hIGH7nPUrr7xFX/Iyx/nmdDmb6mTxwYIPrQqUYVgtz4brIeQJcPrJh2u?=
 =?us-ascii?Q?4eSfKrdeGR1//YpWdQB+nR1JjVlpFwQnws0Nrd1hnz8QXF7+B0sG6wh8sImE?=
 =?us-ascii?Q?nJxhy7LnDGzDXo6O/OnSVBAnRGz3AyXXjLhCQGxHrrRp5FyzaZG5qHK2VGoI?=
 =?us-ascii?Q?Xkx+oypBs4AGi7Ygf5dVZDjK+iXI1ZA4BnpoeA21GQH0DjLZwvZNvKZ3RK/M?=
 =?us-ascii?Q?dufsu+gHi2dr1SMUfdsggGUbiLBkQa9sJUfzVVOgrfwoP6GcDZNycAyMsWWX?=
 =?us-ascii?Q?94U/Kavbo2TnX7FeBokJbaXuJ0LhrcHZoKNknZBcYk4GLoUKUIaMd7gUwyBL?=
 =?us-ascii?Q?pu2AsnSx7y1jZGsi/Tx2Kja7A3Ere3xEdTGK2ojKbjHQThmITOPV4zFTam/t?=
 =?us-ascii?Q?5tAYJw1GDHyEaE4GfjQvoFusdiVV6ntM72D726RJ10R0MT2QzvK1spf63m9O?=
 =?us-ascii?Q?G4d69ADCsKkQxJvsfJAJu+IG+QmGKSM7pJmM56AMnMhW2k3UvEYR9EVVvv9I?=
 =?us-ascii?Q?cSS7kU5pv+M0cUJVxD0wHFU2yQzfm3WGsGe+bWzZAzEnVBv/ynvO2ZBsFUnw?=
 =?us-ascii?Q?cJ472WP1Txf3LJ9VbVs9X68vaiT5kdAFPh6siIkeYVXWndphYDXN5OziCgdj?=
 =?us-ascii?Q?oJB2atO1JrMx8gqV96iHxfuJYeVsbrj3VYt9Otzo9sBIjlazp+q0vRf/ySEr?=
 =?us-ascii?Q?lQ/uTZF9hObArO84hRRzoIG5oqBAGg+HUa+oL1p7mOu1JHoo/+VL0OV/HUCw?=
 =?us-ascii?Q?Hlw5pAdGg1vTdGo5/ahD7S1XkeJmBliWs/J9cy5GN1zMrFqOmFgvavWuKXXl?=
 =?us-ascii?Q?Zt0sFjdfMrmK5FAdzPr9i8YJ9Vuy24+RjRbz2B0h4Q24kqG8R4x3dEnPVN6Z?=
 =?us-ascii?Q?dcVUVVfkQ6eGLFwRBkCYvhrEMWs9YhQy0mV68NyQ1w+TH0HbnV9R7ZO5UHyq?=
 =?us-ascii?Q?JzvuZWUG+h5hmTdu8X//ZIjR+cJsLFFQmEL0o0TYBHFUK5/QPZIgL4xRIrqH?=
 =?us-ascii?Q?U7V4OS0g1xlz/B2AWP1rjoU5t4EawOL43u3jvzuSWpxvtGSgffKJzjV+Y7ab?=
 =?us-ascii?Q?BXdGNOUCc/ZC0XVavKd2bFZ/7Ez7gh0Sbq0JpXLGIxIgVNRSusxcmPwNb+YK?=
 =?us-ascii?Q?iUVK+MfM4JM5JNvaMZGQ8JiZJVzKMQQgtmjZVhO/Ginmc7HT8eeXWFxwsFoN?=
 =?us-ascii?Q?xJJ7LP8qwPCbQ7htVG6Ru+whgFFCMGhSbTl1sFyS1uHL63siveY8SNKE8tj+?=
 =?us-ascii?Q?Rln8lpB2SY7XRrGiswWQ6VKhfwEngnifAq4oV79dJXnde+Z9lE7zJ+Wyr7p3?=
 =?us-ascii?Q?kOH5EPrLQVQ/hqfe4RTkCw3m9VoV?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?s61YLWJnBtdD89K8rUyrGtxhLPPwo+sHvskLT6pSkg69btoiMBX9sZdBm+1b?=
 =?us-ascii?Q?/Zs/dwfiQy+YdSdaplcDODX5FBaKNE2swBol84vxeSL6aIOaTuU9401WHiCr?=
 =?us-ascii?Q?NTzj91uHVX4FtvrKat4GGmNdhlnaDbeupwlTaoTA3WuipaauimuRpUg2/kR7?=
 =?us-ascii?Q?xtP09QB63uAXQepXfKemi/iLzW0NNtl+NEfJInSd6ez+QLnGMCPAwKyxymSZ?=
 =?us-ascii?Q?iereXVkaNah2uIsvpcBNAVkqeZgw3ilA2G0c7TCawHmMyiFfJKB7Nrvb6Jkq?=
 =?us-ascii?Q?vvxVoLPQdIRUmxGsp9LHPBaFR8r2qYAErLa9DdM9Rs8g0CFGUPnM5sJ3h2XP?=
 =?us-ascii?Q?67Q8JyTYSkcMj4YvzufrJWjTwJwhNdotiwmsIlYICarwEg0iui9bKs1EyAxk?=
 =?us-ascii?Q?eTtK0we3iSdp5PONw9B+2fjUmKDKkeqS37ZqCdke4xeNk0so/tsXK8gxK5hK?=
 =?us-ascii?Q?QTusNzHWNP9/kweX9EpyZ7GQ7CasNw4jK7L2p07pBlXN7n803ChHs/5hkJob?=
 =?us-ascii?Q?R46z3+clYX8gbuMUIFLQKMvtetvVFqQ81P5nZpcqPPjdqa/nHdCKzWoiGSRS?=
 =?us-ascii?Q?pO78t3C4NjbUwy/NF63tI+0GOEav/dw7uGhTt+FPNhvO63rmUaoZPkzkgm6I?=
 =?us-ascii?Q?G3YfdUH3EwGVhVQBMHrD8/yz6lEIJOXte1osn00rN8OsBwixD077n6X0jPfc?=
 =?us-ascii?Q?M6tPaA7M4utCs0YuRgm76lgTYyE7G/Uxrc5W5PSak1+hAB77fOwlVV1A44TO?=
 =?us-ascii?Q?84DsqmB4qw8RSZK4LHQm4z0WUSQw63f2NIXusNslRJ86CHcFcMdz9xW7jyza?=
 =?us-ascii?Q?a5BKeT9SqKMA/D8BMaQK8kIQ27u8oJdyfPdcJjUXy3CYmVrxoXi5wL1UbyYr?=
 =?us-ascii?Q?/tQmP3wtpo0XNP+u/9C8AhPJMrmAZ7YVPLsbnHYDXsFd2VhNiWUmZBwentJB?=
 =?us-ascii?Q?6ledFWA/NW2CyqApE5tM93tYP4gyfSQhsnPMMCFYEK5Cv1F6uvqirXTeXGkW?=
 =?us-ascii?Q?gKdlB2Tg7P9cOiJ1bLAgFwJc7FYRseQTcZCMtuFeVP3P430F2w8KGU+T+diX?=
 =?us-ascii?Q?u7MrSN2G9L9Ce7InXDY/btsPP0Uxnq6L1CwvgD8ozLwR60+D60n/0WEalqjQ?=
 =?us-ascii?Q?lGQTiGdNp3frFof5H3iPwIqjfWHBz99x4HHk3uwK4qoSPBw2Td4i48J1SFsr?=
 =?us-ascii?Q?+/zcIpEEHX99zgHiX6RgR8XXtVTWXmiNXx/Lsv4xr6+1uYQjRwh4h3TNBv32?=
 =?us-ascii?Q?3g3t85+JrV6LKEfiZiG1nhRZURS7op/2Yp/ukO7pZm0pM7pM0NaDZFcNrCZ9?=
 =?us-ascii?Q?1qW4vXfp5xA2x5254JVqwYhnn6EjiWVuB33PlAfT6m4xc3/1YAq0np8F2W7S?=
 =?us-ascii?Q?gy+G9l5aCku1CwyRFjunO/cYPA3X++ivmUvbXVCxyJgqK0B79XqHLLl4Pjnb?=
 =?us-ascii?Q?sDHdmmS5aSJEfG0JleAsFZMS/yUFTSCdpKkhDKrR26FKKGHxKWdmYilr3+xG?=
 =?us-ascii?Q?DP2A4ycQC7fgzu6B/4BMMS7nkzpRgcoYMnhNueaVU1R8EzDXBMQl6WPy+zsD?=
 =?us-ascii?Q?x0Vz11216AtsVbjMBmQFVwbJuqo2t5MEY7eFDJNNXD3btJbKs0l6R1Hl6X6y?=
 =?us-ascii?Q?TQ=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 6f7fc726-d600-4a9b-c256-08dd911cbcaa
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 May 2025 06:17:56.8009
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /I/mkI9NG2i8egSCIHba8LgiBmAxGSDNDLS1VnxXhHpnmVH4IHydGPt3GQKy9oshW32fylvDz2jJSGl9CRsGbQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR11MB7409
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Zc69AJ+g;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 192.198.163.13 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

kernel test robot noticed "kernel_BUG_at_arch/x86/kernel/irqinit.c" on:

commit: bb37c7f4feeb88a194610a849a4e23cbed53bdba ("kasan: avoid sleepable page allocation from atomic context")
https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master

[test failed on linux-next/master ed61cb3d78d585209ec775933078e268544fe9a4]

in testcase: boot

config: x86_64-randconfig-123-20250509
compiler: gcc-12
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)


+------------------------------------------------+------------+------------+
|                                                | 7f87315350 | bb37c7f4fe |
+------------------------------------------------+------------+------------+
| boot_successes                                 | 12         | 0          |
| boot_failures                                  | 0          | 12         |
| kernel_BUG_at_arch/x86/kernel/irqinit.c        | 0          | 12         |
| Oops:invalid_opcode:#[##]KASAN                 | 0          | 12         |
| RIP:init_IRQ                                   | 0          | 12         |
| Kernel_panic-not_syncing:Fatal_exception       | 0          | 12         |
+------------------------------------------------+------------+------------+


If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202505121313.806a632c-lkp@intel.com


[    8.023858][    T0] ------------[ cut here ]------------
[    8.025254][    T0] kernel BUG at arch/x86/kernel/irqinit.c:90!
[    8.026744][    T0] Oops: invalid opcode: 0000 [#1] KASAN
[    8.028093][    T0] CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.15.0-rc5-00037-gbb37c7f4feeb #1 VOLUNTARY
[ 8.030568][ T0] RIP: 0010:init_IRQ (kbuild/obj/consumer/x86_64-randconfig-123-20250509/arch/x86/kernel/irqinit.c:90 (discriminator 1)) 
[ 8.031790][ T0] Code: 1b fd 48 8b 45 c8 4a 89 04 e5 00 4f 4b 83 48 c1 cb 13 41 ff c5 e9 08 ff ff ff 31 ff 48 c1 c3 06 e8 0f 2c c7 fc 85 c0 74 03 90 <0f> 0b 48 b8 4b 83 84 ca a4 57 e9 ec ba ff ff 37 00 48 01 c3 48 c7
All code
========
   0:	1b fd                	sbb    %ebp,%edi
   2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
   6:	4a 89 04 e5 00 4f 4b 	mov    %rax,-0x7cb4b100(,%r12,8)
   d:	83 
   e:	48 c1 cb 13          	ror    $0x13,%rbx
  12:	41 ff c5             	inc    %r13d
  15:	e9 08 ff ff ff       	jmp    0xffffffffffffff22
  1a:	31 ff                	xor    %edi,%edi
  1c:	48 c1 c3 06          	rol    $0x6,%rbx
  20:	e8 0f 2c c7 fc       	call   0xfffffffffcc72c34
  25:	85 c0                	test   %eax,%eax
  27:	74 03                	je     0x2c
  29:	90                   	nop
  2a:*	0f 0b                	ud2		<-- trapping instruction
  2c:	48 b8 4b 83 84 ca a4 	movabs $0xece957a4ca84834b,%rax
  33:	57 e9 ec 
  36:	ba ff ff 37 00       	mov    $0x37ffff,%edx
  3b:	48 01 c3             	add    %rax,%rbx
  3e:	48                   	rex.W
  3f:	c7                   	.byte 0xc7

Code starting with the faulting instruction
===========================================
   0:	0f 0b                	ud2
   2:	48 b8 4b 83 84 ca a4 	movabs $0xece957a4ca84834b,%rax
   9:	57 e9 ec 
   c:	ba ff ff 37 00       	mov    $0x37ffff,%edx
  11:	48 01 c3             	add    %rax,%rbx
  14:	48                   	rex.W
  15:	c7                   	.byte 0xc7
[    8.036561][    T0] RSP: 0000:ffffffff83407ec8 EFLAGS: 00010082
[    8.038069][    T0] RAX: 00000000fffffff4 RBX: 6df7d5fa0f60cd35 RCX: 0000000000000000
[    8.039970][    T0] RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
[    8.041954][    T0] RBP: ffffffff83407f00 R08: 0000000000000000 R09: 0000000000000000
[    8.043898][    T0] R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff834b4240
[    8.045853][    T0] R13: 0000000000000010 R14: dffffc0000000000 R15: aba4cde2058bd46d
[    8.047792][    T0] FS:  0000000000000000(0000) GS:0000000000000000(0000) knlGS:0000000000000000
[    8.049786][    T0] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    8.050884][    T0] CR2: ffff88843ffff000 CR3: 00000000034a4000 CR4: 00000000000000b0
[    8.052215][    T0] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[    8.053574][    T0] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[    8.054911][    T0] Call Trace:
[    8.055458][    T0]  <TASK>
[ 8.055962][ T0] start_kernel (kbuild/obj/consumer/x86_64-randconfig-123-20250509/init/main.c:1003) 
[ 8.056724][ T0] x86_64_start_reservations (kbuild/obj/consumer/x86_64-randconfig-123-20250509/arch/x86/kernel/head64.c:387) 
[ 8.057656][ T0] x86_64_start_kernel (kbuild/obj/consumer/x86_64-randconfig-123-20250509/arch/x86/kernel/ebda.c:57) 
[ 8.058488][ T0] common_startup_64 (kbuild/obj/consumer/x86_64-randconfig-123-20250509/arch/x86/kernel/head_64.S:419) 
[    8.059283][    T0]  </TASK>
[    8.059776][    T0] Modules linked in:
[    8.060422][    T0] ---[ end trace 0000000000000000 ]---
[ 8.061348][ T0] RIP: 0010:init_IRQ (kbuild/obj/consumer/x86_64-randconfig-123-20250509/arch/x86/kernel/irqinit.c:90 (discriminator 1)) 
[ 8.062172][ T0] Code: 1b fd 48 8b 45 c8 4a 89 04 e5 00 4f 4b 83 48 c1 cb 13 41 ff c5 e9 08 ff ff ff 31 ff 48 c1 c3 06 e8 0f 2c c7 fc 85 c0 74 03 90 <0f> 0b 48 b8 4b 83 84 ca a4 57 e9 ec ba ff ff 37 00 48 01 c3 48 c7
All code
========
   0:	1b fd                	sbb    %ebp,%edi
   2:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
   6:	4a 89 04 e5 00 4f 4b 	mov    %rax,-0x7cb4b100(,%r12,8)
   d:	83 
   e:	48 c1 cb 13          	ror    $0x13,%rbx
  12:	41 ff c5             	inc    %r13d
  15:	e9 08 ff ff ff       	jmp    0xffffffffffffff22
  1a:	31 ff                	xor    %edi,%edi
  1c:	48 c1 c3 06          	rol    $0x6,%rbx
  20:	e8 0f 2c c7 fc       	call   0xfffffffffcc72c34
  25:	85 c0                	test   %eax,%eax
  27:	74 03                	je     0x2c
  29:	90                   	nop
  2a:*	0f 0b                	ud2		<-- trapping instruction
  2c:	48 b8 4b 83 84 ca a4 	movabs $0xece957a4ca84834b,%rax
  33:	57 e9 ec 
  36:	ba ff ff 37 00       	mov    $0x37ffff,%edx
  3b:	48 01 c3             	add    %rax,%rbx
  3e:	48                   	rex.W
  3f:	c7                   	.byte 0xc7

Code starting with the faulting instruction
===========================================
   0:	0f 0b                	ud2
   2:	48 b8 4b 83 84 ca a4 	movabs $0xece957a4ca84834b,%rax
   9:	57 e9 ec 
   c:	ba ff ff 37 00       	mov    $0x37ffff,%edx
  11:	48 01 c3             	add    %rax,%rbx
  14:	48                   	rex.W
  15:	c7                   	.byte 0xc7


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20250512/202505121313.806a632c-lkp@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202505121313.806a632c-lkp%40intel.com.
