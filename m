Return-Path: <kasan-dev+bncBD2KV7O4UQOBB4PT3G3AMGQEDFJPAKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D1025969194
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2024 04:52:34 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3df0df238b2sf5294388b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2024 19:52:34 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725331953; x=1725936753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z0vWunu9KL0UdcAw39FcXjr3s4sQ+3fzPassKnA7wBE=;
        b=HvHreqz0R75uHb0RIaQIQBzS3fH1pXftTi68pnCSpenD2bLqqvl8dbhtOozDdWQrls
         +Pbg9Npmys/7vL062h7s/TMSvDVYsiz2R0mSw+zLEpe6/wS+67izWYQliUAHdOlkqYlV
         83276YXOf1YMp4XHAg8nxTV6jBCCCRtkxKiBLgRBHYQ8G7C2RtyI5/bMXwOJs7PBFo2W
         Bbd7GHidARhR3I5o48eHR7XqXcw3hfH8DMVwgQPflTd4BBHw5JN+7rotbfHa8MB/8cZ7
         f4c5jhDqMFkciYYW3VIh5S55MJit6bUMJ0gL0a+Ah+KyHFzB0EzfCWDLki9yR9pjbjG5
         RkRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725331953; x=1725936753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z0vWunu9KL0UdcAw39FcXjr3s4sQ+3fzPassKnA7wBE=;
        b=gLBe7FOqyrmCyBxcULfNNMcJUM/OTyiSI6fAE9nVXdJx6xxUA6pGGmsqDK0UsF3q97
         +fzBxMKy47N5XyYjSdBd5dtNkORZ4DjxTBT/y6XwnlTDeaHd4KGsYVxiJehRRmCoHLNQ
         PjQxZIK2jDi9K0I0aNm+X0BDN6lWAQyMdvG3ey1AUUA4INqj0d8/CQiP+WznSvuzXphw
         JoP0mD6H7ozVQja0Ds7/I5VjGJt+CRSseaa6jEOjEiJ9jA6KNVXG1ad70ZDnhfwZWoRW
         s8lsZNnGKHj3L1qzlW6WCNm5ZKioaymitW44SuMENYWhKRimGdr7ACu1XRO6OQfkDu7S
         fIuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4ycYGmnqBKlBrgHYCUpWz6koitMc3Gn8gWcQC9UPOLB+vicTV6XLxJHyAEfBJGk0rfHxtWA==@lfdr.de
X-Gm-Message-State: AOJu0Yxa9AoZC7zUhWsaJBAtXeMO1DBLDza26UEVzImZY+VqyMlGiIf3
	oXHn+3lHcuT0q2QOYZ5n4UTutQEMCy/sxtawi7YNuNY/9J4ZvYUV
X-Google-Smtp-Source: AGHT+IFY5TFWC8apvgAcfiuWV3AYt62xEw4INb/sY0fB8BCcO/l8GgABuUtg+2FZ5tehnqITqCUGUQ==
X-Received: by 2002:a05:6820:1acd:b0:5df:a346:a1bd with SMTP id 006d021491bc7-5dfacf68f02mr13019219eaf.6.1725331953163;
        Mon, 02 Sep 2024 19:52:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:c802:0:b0:5de:842c:5dd5 with SMTP id 006d021491bc7-5df991e8d4als4707471eaf.1.-pod-prod-05-us;
 Mon, 02 Sep 2024 19:52:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMCf7tfDtRynssHqC4kJuh4wzEDGaH5tfu9TaIltdDlCIFshtyzYtpNrJBkvZGhUjSF7depCPJMUY=@googlegroups.com
X-Received: by 2002:a05:6820:1acd:b0:5df:a346:a1bd with SMTP id 006d021491bc7-5dfacf68f02mr13019203eaf.6.1725331952426;
        Mon, 02 Sep 2024 19:52:32 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.18])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5dfa0537a43si386198eaf.1.2024.09.02.19.52.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 02 Sep 2024 19:52:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.18 as permitted sender) client-ip=192.198.163.18;
X-CSE-ConnectionGUID: Gl6mBYUaSXeHY3WCnB/2TQ==
X-CSE-MsgGUID: 2hosEA/iR7ueTwXlYxFL/w==
X-IronPort-AV: E=McAfee;i="6700,10204,11183"; a="23424623"
X-IronPort-AV: E=Sophos;i="6.10,197,1719903600"; 
   d="scan'208";a="23424623"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa112.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Sep 2024 19:52:29 -0700
X-CSE-ConnectionGUID: xoL3MPNnSS+L9N02m6eD8g==
X-CSE-MsgGUID: YiQrraITSPG30e2PiPiQBg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,197,1719903600"; 
   d="scan'208";a="69557641"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orviesa005.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 02 Sep 2024 19:52:29 -0700
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Mon, 2 Sep 2024 19:52:28 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Mon, 2 Sep 2024 19:52:28 -0700
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (104.47.56.168)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Mon, 2 Sep 2024 19:52:27 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BPKzr7OzmKQp0gItSKxJW6bcuFD0JiSEo6xerBEzgL/Gp4slXtyese041pM95ktzpElOddqVIKmB04KUJIkP2dwieSvC1VdL/W0CVX+1TcIBHciLPpXN+DV8UwGoPfJYpjptqDpVZpbjUXNedfimO+mG1HQB3rAhocv244BC+JGmQkYQDld3TPMnV+3Asj1DKRgOWCFeVar6dAZg+z3cH9BuZXWwxWL5a+AVVW4bCFbQuYiyR8XUF8ShOEMtlfcBg1J4C/W7rOkpi/CK/Q1RZ27MObzyJNX8xgYUnL94W8xrWc455mN+h0Mr8xWV6kNswpwMa8IvWoLJwnwTiTiuWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IldswD+1xaPyF0w8m/nvMdfvW/tPcijOzoC4rD6rQfo=;
 b=m7MWbXPv1wB7QsXsrE1palYMaFBVPtwwCZ+T17ZHAxSW0ohpNhi6UZJIy9HquqUfb6NVvjwJzhwTjlEOz2DAg14lGTVV/aeFKxeU9yevOJTweC1FPikdDyzAtdj045hr6Etx7/M+0mODk3y9wevQ8ni5970O9Om0n0p0QHjfZdwu1RWCi1VWV79K9WentOEK+KHYgz162sXr8ZhKKT0NSiooeWdPLZBjrCbqD+QSx3vi3h8uX64/qrf0AhrFLHFDjCNSSKHZkXohNCCmSokSRAQIVJ/rgsveZ89w3pIbxZiRSv88qJ3lvE6pcjSpY/awhoXPcVxAKUbvVyUJsG+QLg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by SJ2PR11MB8423.namprd11.prod.outlook.com (2603:10b6:a03:53b::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7918.25; Tue, 3 Sep
 2024 02:52:25 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.7918.020; Tue, 3 Sep 2024
 02:52:25 +0000
Date: Tue, 3 Sep 2024 10:52:15 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <linux-kernel@vger.kernel.org>,
	<x86@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, <kasan-dev@googlegroups.com>, <oliver.sang@intel.com>
Subject: [tip:x86/build] [kcov]  6cd0dd934b:
 BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)
Message-ID: <202409031007.2c7c62aa-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SG2PR04CA0200.apcprd04.prod.outlook.com
 (2603:1096:4:187::15) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|SJ2PR11MB8423:EE_
X-MS-Office365-Filtering-Correlation-Id: 39dd1049-62fe-4971-bf5f-08dccbc37113
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?i/U5DsDLQNqok0dhi7+pDcQaMJi4G9DzuXn5QnaG+0Bw6K76roJbSs88YARe?=
 =?us-ascii?Q?/Wm1ZUwIbbcMF3EuyvRjv75UdClxPl7x2nETq4KcoKoAa2iQscN4hInY55aX?=
 =?us-ascii?Q?r+hzU/92u4Fxkydl+WgYFEXNRqFWXAPxnuWx/5RGmC0zJvvLFNd+KeVO0p4f?=
 =?us-ascii?Q?MUBaD8+fsoxOSMGEsn4pxUnMRn61mscISnP+VUDSEEsZdiDDSTSxS1FVs+7M?=
 =?us-ascii?Q?jvaNgVBTfkmCNVHuWyZjsp8NCkF02wBTqAwVOl/DO/ftW4dcPwRNGeRoI9af?=
 =?us-ascii?Q?iIx3dTipGAthcEjjFMY6WkPmnMHt8ma8Q12MBTNsT0DDVOe1pEeDy4o8vseI?=
 =?us-ascii?Q?vp8qZs+bWzzGHJLwBojhACDv7RvUUiLD18arYGeheC4iUrKqOUf42xhPOBJ3?=
 =?us-ascii?Q?66Psceb3akx5pn22CfY0qFyAy0zy4f5FmMCvqumTIFz5ZuO/fNmxYXGjgjZm?=
 =?us-ascii?Q?+wqjwVeEyI6eJDWhLHobP3XiPkQ0oyOi6a2Xa8k7htlLSikSwwtAtmK0d/WU?=
 =?us-ascii?Q?Mu95eeF3/m0p/Uwp5EH1M8WxpAyCQ7hF+8dDHU2PjVv+HLJNYrpCGNj1kNLy?=
 =?us-ascii?Q?aq8TNhtvp4U+GGHbTgxB89C+4latScd+Z1+mm3w1bvaCmvpU1BwkzSjh+Uy8?=
 =?us-ascii?Q?R67i0fWrdZcp5HhXALdxqOBXVdYwrj+OyEmnadtzbBZ3FcoqpNDHQIj3EprU?=
 =?us-ascii?Q?p8K4qOPNU22MpalsYFEbloryYFwWmTDG2AorkBC6pyNGCKD+qNnCrdWdWv0Z?=
 =?us-ascii?Q?0vxcSGnfvIfEfheus+Z2Is4ctxyYekNzRlg8RV6+b5zVUKMLGLiaT0cqt4kR?=
 =?us-ascii?Q?G4Zcb/95isVUXy96gjudpwkdoHrLbGfNGAjG8t03XUxB+Eogy5Iv/78WJZhM?=
 =?us-ascii?Q?UaVqKGobclm+cNAa2A1eG3Rx7ROSYfJZCHwu1SBE7z9k0t/grSPrKcBp6+D8?=
 =?us-ascii?Q?IIb3e596u1j1jn1lxN4soKV3QByqSEbCaNa+e+YeV1m62NzH4SgXc9YSWBqP?=
 =?us-ascii?Q?K7hC5GdF1Y5589CS0S9eCwrZ/dn7zLqGFfY7OwpwPeeACZFLGAnGFryuzkzY?=
 =?us-ascii?Q?TG1Se08NvvzEYLqtSSddHbvN3N+fcwZS0NCvvkGl895/t5BEbUAar3lee54n?=
 =?us-ascii?Q?4ddwK0fDW+d2UeCXDUwyKkxilmiwHK3S07Qx1LHLkZR5gibewMZt7TJSk51V?=
 =?us-ascii?Q?XeyYZiX0c3vQHbR5sV9R5gVaIZ8Li6W6Y4sJqy0y6bIfCcDa+ZnCezWYVM5L?=
 =?us-ascii?Q?il02wKG3Oxi81QkrfnBGdgl98p6oGyoR6joEwofmBiqWcHxDboEKSWWCbb7o?=
 =?us-ascii?Q?QaL88l9/EXEv2Dz9Wah0/fqp?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?NqygdD8Y4IeIqPaNJhgYNaH4k0ON17qOZXwh3IhJP/94887wp2caf3835Dw1?=
 =?us-ascii?Q?CDZfnXprjMhrV69imAJnYcTiw1WKWsttJAaug0u29XrFbXRgJP18AxELZzEr?=
 =?us-ascii?Q?VD28fk2U+77qmAXCrtRkkbv8PcL/rWnLd07AquYiThQ15nX3/nYfRZ6oSHQw?=
 =?us-ascii?Q?Itq4wXq+JJu/Hn+0sYSxVtTYF5sBrJO4S8TPZSAjzqCRpFQe7td1eUNG/6BE?=
 =?us-ascii?Q?VE+Uv1Bx9UNDK5OVxvCz250p9kTdlPJqu9oBprV/BEM6z4n9E2ic5+MG7Imf?=
 =?us-ascii?Q?g8yiPKLeR11Y5LxF16aMSGn0JnTvWXIUt85yACHo9+ptZAESxsCfzH+w/uwi?=
 =?us-ascii?Q?j79GrMoJpmiVIjSqqBcYTHpkLw2C46L9QYSOLJC76RXNofJ10yhlSlmcOHVK?=
 =?us-ascii?Q?ZUbgYSXdop1CK8VU0rPacygfl3YiPu5MaZp7HQq8luqrukatD7bGWsKr7U8I?=
 =?us-ascii?Q?3zye7cMiWUdpJIgNfNNd5C1AitOjb7aaAj6Iaplr4XStpc0ES6mVkKgqUr3m?=
 =?us-ascii?Q?YOC5lkhLndW2wHY7eBKMVyfqxKUHNCjvhH3Mpkj68DrKoSK2wyWSSMHsX+Od?=
 =?us-ascii?Q?6KCwqI+St+m4RDUGGWqb2nAKvBaPsCp9lyAD16mOJyBMD32BEqKFc3ckyhgM?=
 =?us-ascii?Q?nV/zaV+4JrP8wC/ZVi00p1avqiKtheEoW+11aDcA4XNNrfKCboSqG4ojracN?=
 =?us-ascii?Q?TysQN0tSbOU4OuLM+Y2zwfFLa9XraIlytehUmVhgZB/SlqvrZeifI62RN9w3?=
 =?us-ascii?Q?QSmvRU0HBOliMps9aBr2jy/DndEVlfZOMONXbntnxbVY87Pt3/2anZzU6AUO?=
 =?us-ascii?Q?v38Z3FethbdyURL4zi8Sb4zp6YRPnVjbDAh/9w5QMLtUOV2603YcgasRBcbK?=
 =?us-ascii?Q?LjkAhUV5ZGB4HUmX8rnP2I+Ls74XfMEUl6IbD5wAylqOLprPFPFkcRkIBRLO?=
 =?us-ascii?Q?sOIS4R/aZGmGh/Ti7hHxnPH5PbkyR6Is2rnSwGkJO6PCijBl0VhKSNPb8BmO?=
 =?us-ascii?Q?wtCx3E4RK5ut90PYImiGAgbUi4jQoTl6nrjzujZrbLs11wf7AvMaE62ZgeLf?=
 =?us-ascii?Q?8Bf8XnqvRl2pI167ZVpGKKMzVD1B+U/DEHHZitUhngwO4dn1UTjyec6MFbnm?=
 =?us-ascii?Q?Log6QU17lqPJXSdeLp+8hTLpnMNPaFXVGAJdL7l+DgmyWBHggGMMwvy6Pxq6?=
 =?us-ascii?Q?2C6NH4zHi2OHoe4XIfAJfm2AF4r73JWwYgf/t5+1OLNr45iWz7MMuRGpSb0s?=
 =?us-ascii?Q?Js+PYgqojQpiA/sspfV65myPQMFJwwyw+sR33J3TvARF/GK6J/mXE5cNKelA?=
 =?us-ascii?Q?Vfq2c0+LVHuRYPlf9z+KcaTurb9khi05IPEOUbh0maQ44E3DhpbJpJExB7aJ?=
 =?us-ascii?Q?wssl64gqlafLXnXR7gu/k892O2BPj+ZDbViRxWmfIT+JyiOcINpE+mYnBtN+?=
 =?us-ascii?Q?BP46uKU4lNhjhGWWGOjL/H5DKj42/12RobubM5a/BvAaoKvEvuFgp7JUsWek?=
 =?us-ascii?Q?9upmRCm7SBiKdeoUeV5aRCQHRx46yTpH7lEO6gjdDr023MP41WCIdejxdrzj?=
 =?us-ascii?Q?XIPLUaOMuODzHAFI52TQ1lWmISvyQGGowTgdo2WfGeV9rDps7L/0mWR2goiK?=
 =?us-ascii?Q?kw=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 39dd1049-62fe-4971-bf5f-08dccbc37113
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 03 Sep 2024 02:52:25.7392
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: mGCDRFDgp1kWWDiikulqqZ1CMDJcxD34j09bOKndyvlfFs7XgyHk39GDelhoqW8I7LL2UUP4u8LLcmg/ri/Xww==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR11MB8423
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=AlLUVMvo;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 192.198.163.18 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

kernel test robot noticed "BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)" on:

commit: 6cd0dd934b03d4ee4094ac474108723e2f2ed7d6 ("kcov: Add interrupt handling self test")
https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git x86/build

[test failed on linux-next/master 985bf40edf4343dcb04c33f58b40b4a85c1776d4]

in testcase: boot

compiler: gcc-12
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)


+-------------------------------------------------------+------------+------------+
|                                                       | 477d81a1c4 | 6cd0dd934b |
+-------------------------------------------------------+------------+------------+
| boot_successes                                        | 18         | 0          |
| BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)   | 0          | 18         |
| Oops:stack_guard_page:#[##]SMP_KASAN                  | 0          | 18         |
| RIP:error_entry                                       | 0          | 18         |
| Kernel_panic-not_syncing:Fatal_exception_in_interrupt | 0          | 18         |
+-------------------------------------------------------+------------+------------+


If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202409031007.2c7c62aa-oliver.sang@intel.com


[   27.611227][    C1] BUG: TASK stack guard page was hit at ffffc90000017ff8 (stack is ffffc90000018000..ffffc90000020000)
[   27.611227][    C1] Oops: stack guard page: 0000 [#1] SMP KASAN
[   27.611227][    C1] CPU: 1 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.11.0-rc2-00002-g6cd0dd934b03 #1
[ 27.611227][ C1] RIP: 0010:error_entry (arch/x86/entry/entry_64.S:1007) 
[ 27.611227][ C1] Code: 0a f3 48 0f ae db e9 f7 fd ff ff 85 db 0f 85 ef fd ff ff 0f 01 f8 e9 e7 fd ff ff 0f 1f 40 00 56 48 8b 74 24 08 48 89 7c 24 08 <52> 51 50 41 50 41 51 41 52 41 53 53 55 41 54 41 55 41 56 41 57 56
All code
========
   0:	0a f3                	or     %bl,%dh
   2:	48 0f ae             	rex.W (bad) 
   5:	db e9                	fucomi %st(1),%st
   7:	f7 fd                	idiv   %ebp
   9:	ff                   	(bad)  
   a:	ff 85 db 0f 85 ef    	incl   -0x107af025(%rbp)
  10:	fd                   	std    
  11:	ff                   	(bad)  
  12:	ff 0f                	decl   (%rdi)
  14:	01 f8                	add    %edi,%eax
  16:	e9 e7 fd ff ff       	jmpq   0xfffffffffffffe02
  1b:	0f 1f 40 00          	nopl   0x0(%rax)
  1f:	56                   	push   %rsi
  20:	48 8b 74 24 08       	mov    0x8(%rsp),%rsi
  25:	48 89 7c 24 08       	mov    %rdi,0x8(%rsp)
  2a:*	52                   	push   %rdx		<-- trapping instruction
  2b:	51                   	push   %rcx
  2c:	50                   	push   %rax
  2d:	41 50                	push   %r8
  2f:	41 51                	push   %r9
  31:	41 52                	push   %r10
  33:	41 53                	push   %r11
  35:	53                   	push   %rbx
  36:	55                   	push   %rbp
  37:	41 54                	push   %r12
  39:	41 55                	push   %r13
  3b:	41 56                	push   %r14
  3d:	41 57                	push   %r15
  3f:	56                   	push   %rsi

Code starting with the faulting instruction
===========================================
   0:	52                   	push   %rdx
   1:	51                   	push   %rcx
   2:	50                   	push   %rax
   3:	41 50                	push   %r8
   5:	41 51                	push   %r9
   7:	41 52                	push   %r10
   9:	41 53                	push   %r11
   b:	53                   	push   %rbx
   c:	55                   	push   %rbp
   d:	41 54                	push   %r12
   f:	41 55                	push   %r13
  11:	41 56                	push   %r14
  13:	41 57                	push   %r15
  15:	56                   	push   %rsi
[   27.611227][    C1] RSP: 0000:ffffc90000018000 EFLAGS: 00010046
[   27.611227][    C1] RAX: 0000000000000002 RBX: ffffc90000018078 RCX: ffffffffb818de45
[   27.611227][    C1] RDX: 0000000000000000 RSI: ffffffffbaa011ad RDI: 0000000000000000
[   27.611227][    C1] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[   27.611227][    C1] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[   27.611227][    C1] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[   27.611227][    C1] FS:  0000000000000000(0000) GS:ffff8883a8200000(0000) knlGS:0000000000000000
[   27.611227][    C1] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   27.611227][    C1] CR2: ffffc90000017ff8 CR3: 00000003f3ecf000 CR4: 00000000000406f0
[   27.611227][    C1] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[   27.611227][    C1] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[   27.611227][    C1] Call Trace:
[   27.611227][    C1]  <#DF>
[ 27.611227][ C1] ? show_regs (arch/x86/kernel/dumpstack.c:478) 
[ 27.611227][ C1] ? die (arch/x86/kernel/dumpstack.c:421 arch/x86/kernel/dumpstack.c:434 arch/x86/kernel/dumpstack.c:447) 
[ 27.611227][ C1] ? handle_stack_overflow (arch/x86/kernel/traps.c:329) 
[ 27.611227][ C1] ? get_stack_info_noinstr (arch/x86/kernel/dumpstack_64.c:173) 
[ 27.611227][ C1] ? exc_double_fault (arch/x86/kernel/traps.c:380) 
[ 27.611227][ C1] ? asm_exc_double_fault (arch/x86/include/asm/idtentry.h:668) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? error_entry (arch/x86/entry/entry_64.S:1007) 
[   27.611227][    C1]  </#DF>
[   27.611227][    C1]  <TASK>
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:213) 
[ 27.611227][ C1] ? is_kmmio_active (include/linux/mmiotrace.h:41) 
[ 27.611227][ C1] ? exc_page_fault (arch/x86/mm/fault.c:51 arch/x86/mm/fault.c:1474 arch/x86/mm/fault.c:1539) 
[ 27.611227][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:623) 


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20240903/202409031007.2c7c62aa-oliver.sang@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202409031007.2c7c62aa-oliver.sang%40intel.com.
