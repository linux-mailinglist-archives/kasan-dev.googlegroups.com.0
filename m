Return-Path: <kasan-dev+bncBDN7L7O25EIBBD7AUK4QMGQEE65PLRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id EB3279BB342
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 12:29:20 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3a3fa97f09csf42564935ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 03:29:20 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730719759; x=1731324559; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YepxqBYGfppSgOj5mYYiVQMk/C9fscoMjFcvPH3IJPA=;
        b=JKEuIHme+7IoBwFWhVh/MFoLyX+JoQmPNaZA5ZlH7K2aEERyzYc/hsGQmuR+bWKXlk
         l2jVQPL4FwHgTEdtc4uxGuuKyg3y8MsqEi8fTfTkjXtoEVHZc87WjNrycPzfqpo5LQG4
         g5Z0lTf18BJpJSgrTO1nl7XZ5j+XVxPLnJdgM57fBBEoHmwBaGtFzcxj7nvUtRDyiMdq
         +i/Ano5lgu93wf2+QEuAHZFxfqYlEsTKLIBE0XbAS5q/83fYhel5ENeAjJRk9p7/+0Ld
         9oT5iFf6eopXglxTWEWiNPMjguOE2LQ4Ofz5nH43Z0m+Z3CJJIAtea3vK3MT5fBxsDvL
         478A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730719759; x=1731324559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=YepxqBYGfppSgOj5mYYiVQMk/C9fscoMjFcvPH3IJPA=;
        b=UEaSrdsYZlALIHUhQ1zBCYVWHY5fl8VhpdBOUUhGpwetg46QOfcpA+o3add/AqlRz8
         GfFelbWQBbU3/I5ZXRc7mJRit6jGj51n63VlhWQTK4t5M1jLZ9akUBIf83JeMhYKu/Nz
         cFSuRi4LW4BwPoGOyczcrRuQxiG+Tf94FnqIknO4E8dTB4/BpjcKQP1Hi+V+9KrdihQH
         AwDwgysIbC4Ej2i4ADsvg8QanfdMe5PHP2uYySY+ELOvxoGnVnso3gF38s9R1eZGpSM0
         0OJM23LHBLEvii/JenYfBLKQrqOHzIagBy1JVZ5KrrbuYOVcNF9CIQMFcoJcHAtvpl0l
         y/nw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsKEdPT/WOfjNU96S9lbd89Ztewhig90NnrFQF2/NyayEkCydGNWXI4dRnmmLkFnwAYBKi8g==@lfdr.de
X-Gm-Message-State: AOJu0YzvKmwKsVzIS/SzhrdGc9OpxzjkxNk0FLhTWOZKwMTR11xowXuP
	t+I/PMHBMZl/2BsOa56xrqnj79CaMVvXLvvL3UvP6ekKky3OmZIw
X-Google-Smtp-Source: AGHT+IHM1Mevk83XXzcJ67AqDafOZZPvUm+cD7X0hDETaQpxbyDLkyAuhLPfvGkrI5xHnZLy88lllw==
X-Received: by 2002:a05:6e02:20cd:b0:3a0:8c5f:90c0 with SMTP id e9e14a558f8ab-3a6b02cf8edmr121046515ab.10.1730719759484;
        Mon, 04 Nov 2024 03:29:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3b89:b0:3a6:cb15:42b1 with SMTP id
 e9e14a558f8ab-3a6cb154887ls5350965ab.2.-pod-prod-05-us; Mon, 04 Nov 2024
 03:29:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWgIuaBtOHWWXtq5yJmMs8jLgxsnytqITXT+n+/Ss5NTIP2vUtj8W92swBji4FmU6p9jXn3+vPrVuk=@googlegroups.com
X-Received: by 2002:a05:6e02:1d11:b0:3a3:3e17:994e with SMTP id e9e14a558f8ab-3a6b0296d25mr102705615ab.9.1730719758664;
        Mon, 04 Nov 2024 03:29:18 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.19])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4de04b2dbe7si320590173.7.2024.11.04.03.29.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 04 Nov 2024 03:29:18 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.19 as permitted sender) client-ip=198.175.65.19;
X-CSE-ConnectionGUID: 4vqpLbKYRvq4i8j3y017nQ==
X-CSE-MsgGUID: tGxngO7ZTAmh6jBs0iiXmA==
X-IronPort-AV: E=McAfee;i="6700,10204,11222"; a="30265496"
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="30265496"
Received: from fmviesa004.fm.intel.com ([10.60.135.144])
  by orvoesa111.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Nov 2024 03:29:16 -0800
X-CSE-ConnectionGUID: J/mqJphiRcyw9UkKnxxT1w==
X-CSE-MsgGUID: +v1VzFC6S2GsJOdfrOzRDg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,256,1725346800"; 
   d="scan'208";a="88201074"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by fmviesa004.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 04 Nov 2024 03:29:15 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Mon, 4 Nov 2024 03:29:14 -0800
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Mon, 4 Nov 2024 03:29:14 -0800
Received: from NAM04-BN8-obe.outbound.protection.outlook.com (104.47.74.43) by
 edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Mon, 4 Nov 2024 03:29:14 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=g/vdHUZH5obThB208feolQ3ofd2HCN7LSV7ldO0ANi6avNWtkxfSd0C0tjmKdq6JfmnSiyeguETzAtlwPE0sTotIpgrVsIKBRfIwP+h4VTwfxwVVjqCaenHN6AN2f6d5KWp9QNAUiS5S1FOBugQ3P23IFQGODQRuLON83hUR64Adebk9U21JPc7qNxCbBiawDVZDtfIhnI6sAMRptwY+OGmqq5w3pd53/U/pqRG2AdmL3wRkpc6JCc9rspx2PolA9q7ndGoN0TyElxIOwHkTbtFQUE4wBOkXHsx+7Ev8PdvaKfe+MVUN7D89IVV3babXkNyUaNd3mzkeCg09okAxEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6vx5YQEJFfpTNyoZxNOMsEIDNKkGNRGnIZYVkVRRs9U=;
 b=RHEcXkzJCTqIyAHaxGdEoQlK0zLrCahQ8tlToVOxG2Glc1oOTRfvejRXJgqblxr1qv1tY7GyVqNb5AImt89PwrP9U2uPS5iMFqYEC7vKZWQAjRe+8V5MLxCy/xaB+2FoW6llahF0RnxoVFnpwLRM0OFFPRasqBF95obBFZ0+EnVAVx/0u81LEqLaJ+/VY89pU8ZwvbNzDRziD1XGlVtboWRZtWZOZNQ3sI0fdHNl4NHbtO1/xsn5++g8Ypy5s2HsL4GC1REWsg4SfsM0d00k8u4BZbkWRSy6SDXRTJsmLzRbfE0AGKl0tmlwBtrheMH0WCiQ+1KApPUzAwML0K+Zlw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by SA2PR11MB5067.namprd11.prod.outlook.com (2603:10b6:806:111::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8114.30; Mon, 4 Nov
 2024 11:29:12 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508%4]) with mapi id 15.20.8114.028; Mon, 4 Nov 2024
 11:29:12 +0000
Date: Mon, 4 Nov 2024 19:28:35 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>, Kees Cook <keescook@chromium.org>
CC: Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, "Pekka
 Enberg" <penberg@kernel.org>, David Rientjes <rientjes@google.com>, "Joonsoo
 Kim" <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Shuah Khan <skhan@linuxfoundation.org>, David Gow <davidgow@google.com>,
	Danilo Krummrich <dakr@kernel.org>, Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, "linux-mm@kvack.org"
	<linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, Eric Dumazet <edumazet@google.com>
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Message-ID: <Zyiv40cZcaCKlGtM@feng-clx.sh.intel.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
 <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
 <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
 <ZwzNtGALCG9jUNUD@feng-clx.sh.intel.com>
 <a34e6796-e550-465c-92dc-ee659716b918@suse.cz>
 <Zw0UKtx5d2hnHvDV@feng-clx.sh.intel.com>
 <0e8d49d2-e89b-44df-9dff-29e8f24de105@suse.cz>
 <Zw0otGNgqPUeTdWJ@feng-clx.sh.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Zw0otGNgqPUeTdWJ@feng-clx.sh.intel.com>
X-ClientProxiedBy: SG2P153CA0017.APCP153.PROD.OUTLOOK.COM (2603:1096::27) To
 MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|SA2PR11MB5067:EE_
X-MS-Office365-Filtering-Correlation-Id: 684acdce-930b-44d0-5651-08dcfcc3e7eb
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?OE8I9A9jw3gnY+ElxX95ZHfVGtYDunlcowIluOyrIfxe3XAKcWKJgS0acwbm?=
 =?us-ascii?Q?dRtanzzZWiDnJBk8RuLPi4YY1NNP2GPXD6pXcLLT0xyZm08gdQnOAe/CVTvV?=
 =?us-ascii?Q?L5y/M+VdKOrcddYN/0AYktoQm1QjkHKt21QOPDrtuWjNP/p8bgG800SD4Y3G?=
 =?us-ascii?Q?/JfUCGPlH1SJkFOB3yO9qUU530bUJ5nRSaCtDRgmY2iO61fQukmDY4G1mOey?=
 =?us-ascii?Q?ls3MfHmB3KgIMONcXGhGkmoyu9E1K8zuPsadONAiwtVpdRa/FjKeDrCD+cuj?=
 =?us-ascii?Q?7bG2gLkuzAD+RAgmLWo7dGAZtgz5Eb7wrNgNEEKPG0gFKTpsoKqqz6ajdYr1?=
 =?us-ascii?Q?ns0D4eWf34vEFipPe7Hn4rZTEPtcywVow3GOKuYShRYJEIc1aJvpdEUwh/Ok?=
 =?us-ascii?Q?0OoYtN5Z4RmXZzOA9VIS0QRU4G93DundP6Xc4mlxNV2qfXwTCG73KqwKWjCb?=
 =?us-ascii?Q?W01JafonTFpbwmLNvKsb1SU+v9IF2VSNJ93brOidt8vZ5x14iRnNsN9rWpf5?=
 =?us-ascii?Q?Ujo5fMpCfSboSHr7QyJ0jxzVgJKEi/Br4zhDYqux+hJSLk1tfo8AkM6wb77V?=
 =?us-ascii?Q?YeCOQ2/V9LPNu+kUsJuHKYH5Y6or7nzeu8vZw1qJDEYsBibXSUAxgTOsjhaE?=
 =?us-ascii?Q?15QFRW5zDHn3DQIeEOv/EIkBVzncFHfG+jhbQDGxNOBTIMiIlyQJ0lJ4DPEp?=
 =?us-ascii?Q?xz0U9sh0VpCH6PMETCs4keWHpxBs+ZfKitlw1HxQf0/hBQNzK3/ABpxnNEA0?=
 =?us-ascii?Q?gy0o6yc/RYjl6az3WTOz/ENnHzGxewdTqqXK5jO1yV/qm6UpFWztdV42PEH9?=
 =?us-ascii?Q?IOqu+5Hns4K4vkBs4qJww5AhcWXEqlwhJe620+boJMc0GI+bKODZ8EOCxiNJ?=
 =?us-ascii?Q?SabCVtlJuBWkp5TQwFsln1M0q3KrhM1rrXIR40AWE4ee0ExtE6TeQmEaFAZA?=
 =?us-ascii?Q?wcoxw/Gx0VcD1W4TgI4a+yr/6AEkHpUs+y8lBKyzC7nJRvss9nhVS9qvydoq?=
 =?us-ascii?Q?3ua7jlV5m8joCJlr0WPZKkCVaAaKGMb201UtmRKB/laQ3uX6WhE2dOAnTz8g?=
 =?us-ascii?Q?COZFf3eVwkywRcp9nW7/wrzv0uTIUHpTNx7YxiQFaLEYSvrLlquaa8HeOjvn?=
 =?us-ascii?Q?AmCu/l/oUOy34v6bFe4QcwptEpIxjsMHd1QYdND/w2lxFLAANdS3NmFqNOCz?=
 =?us-ascii?Q?X4eMEYWDWoNSAsZmm//yjuJE6ttKk+JepekG9+4aETw/prmcdSd5cL9fp1J4?=
 =?us-ascii?Q?EvwdGZi3f9noL7e+C+SRaKwCgfPXbR3KXDlJAxqmYQXsALFaz4vfBxZ2EN1Y?=
 =?us-ascii?Q?gko=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?mBFyHgmGjDGKa5Li4mnKbNsriK0T8V8rvV7bQiarAqMx0n3Htno4P9jTMkNM?=
 =?us-ascii?Q?7ulUmE2kFW/a9u+PD55Yloq+1eahzWw6b1rlC1Ikp0tyEtAa/kQB2mqdk65l?=
 =?us-ascii?Q?JC93z3IqVgvS8szOee8YceYGQvjv7EAw7DbVBg8zQGR0R5Mku/UCRh3FawVK?=
 =?us-ascii?Q?Bjx9AbJacRLLm82u3phpHqUbMl3zmrdXQKXiqwn3BswOkV2rAIwB/y9msWUE?=
 =?us-ascii?Q?15Czsng56iWY8wxDSArbGEpbh1Ch0aw8O9EH2CM99yNO39pd5tOMvV2NOQmW?=
 =?us-ascii?Q?B3YfMHczkmehwZOqXHfTZRF9A2F4kYKcCAU0Di3F9sa7BABZRqoAcnC1iBhP?=
 =?us-ascii?Q?DH8cdNHoZsM5Rl/IEq4zFrhjEKOUfjZv0YysJkKMFPzt85kU2lXgVeAoYyIJ?=
 =?us-ascii?Q?ZcSppXsZteNyzfsq4B/BpjQJDGRxyr30zYKTdOOnHUgE9WhWvBN6/YlF9YQ6?=
 =?us-ascii?Q?5P9yhxFP5KFOOU2utE0L5G7eLCAOJV3BTlyENWbsXDnp77BIwbBJ5P+BqvN8?=
 =?us-ascii?Q?jr6+m29sIog7Dqm9sYBZ6aCkxZBm/vvGi4rsOMhziebSEYo5ozhOLUzBblW8?=
 =?us-ascii?Q?BtXmKqIaI1k+/HAZgq8xCAF95igqVkaPvKBGeyCQH+NpjT5leJ74Cl1w3w4I?=
 =?us-ascii?Q?k6euFyEuNRUtyiN+MkZghH3F+0xCPN2FraWeyo6F715m/5TGiHtdb7BfpOVF?=
 =?us-ascii?Q?c8lkIuD4GGFAl+u3sJoSQ5SgcJb31Br/NjDT3X24la8UQ81g954dC5Hp+XbO?=
 =?us-ascii?Q?nFsofSWNR2F7ZsOaAS2BlHqaq/Cgsk/7AVWJEBVGuLDxIhtpW6KDcGki943N?=
 =?us-ascii?Q?Lj2iebbAGtyCSWCLsBgMFtk1p/aWpHkjnDplvB1UsXGrC4G3OfhC3QGxxFC2?=
 =?us-ascii?Q?3YCp6Ea1ZeF+Mj1wSGpfMsSJcWYINv64kJk7z8w3GchwCPjSVdJ8mIy18k7H?=
 =?us-ascii?Q?w2WabedEkMGHQ5xjN2mSQgJefCM3E2Lxb5M4UZI3oa2kg0RgaqvV9/5ecBmF?=
 =?us-ascii?Q?Ui2xVyvcmh9s9vjRlQ2r4X2ss84g+f6WdFiBLzf2QpIQGiyP+HOcJmW8zTDu?=
 =?us-ascii?Q?2fDzVZawJwDdDE54K22iNp13rjLqMqaYlj7009cVNSWl6JLxJ4X/WSziXRCE?=
 =?us-ascii?Q?XeJwcSg8oB7i5d/ZYjjKc5trgYBJ9/d5V1y5M/FTQVwlew4fvb95kYh8X6W/?=
 =?us-ascii?Q?vMFFN1Ybj/cbzc42X0DwnNJrLC0dYdib3VV76QmVmiL10TYjz2w1b12dqtOS?=
 =?us-ascii?Q?vfdtwOulEUUNVIMJYikUY21LEHE53lAGRhJW7d7u0TASIusFXHoJf0NGS283?=
 =?us-ascii?Q?+8b3SR0sIW/X5tJBOXwbXUjSnG9/Dxo1jAJ366MeQzYzXuupXTzd6fZpZaqS?=
 =?us-ascii?Q?TY+faRZenF0C6WlH2WTTPxPU2LVozObV9H/7xLUZupnBXVRL/2oOcL0I8zzj?=
 =?us-ascii?Q?7SsfXzrZ+42jy3DdT3I4643No6dLweIQgjh+iEEnPxs/jX6MRGR3GAl1ZAR3?=
 =?us-ascii?Q?tyCMg5HGwz7s27hGE52lkti9VqL67J8Un4UY4H8srY4gPQ8aqHqE9G33ui6L?=
 =?us-ascii?Q?xGFrK6r21gsxQMhDmeDKa8lcMeERxBbC2r6QTbp8?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 684acdce-930b-44d0-5651-08dcfcc3e7eb
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 04 Nov 2024 11:29:12.1002
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: i35MCwkjtzZCW0GGw2lc2N8QrA+2IQ9E2HTNhfgI4k8Wj50GD0MBhtpUyUtY0ekqCAIi6wv1GFKsHPyGke3d3Q==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA2PR11MB5067
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Fv5jCUGk;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 198.175.65.19 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Mon, Oct 14, 2024 at 10:20:36PM +0800, Tang, Feng wrote:
> On Mon, Oct 14, 2024 at 03:12:09PM +0200, Vlastimil Babka wrote:
> > > 
> > >> So I think in __do_krealloc() we should do things manually to determine ks
> > >> and not call ksize(). Just not break any of the cases ksize() handles
> > >> (kfence, large kmalloc).
> > > 
> > > OK, originally I tried not to expose internals of __ksize(). Let me
> > > try this way.
> > 
> > ksize() makes assumptions that a user outside of slab itself is calling it.
> > 
> > But we (well mostly Kees) also introduced kmalloc_size_roundup() to avoid
> > querying ksize() for the purposes of writing beyond the original
> > kmalloc(size) up to the bucket size. So maybe we can also investigate if the
> > skip_orig_size_check() mechanism can be removed now?
> 
> I did a quick grep, and fortunately it seems that the ksize() user are
> much less than before. We used to see some trouble in network code, which
> is now very clean without the need to skip orig_size check. Will check
> other call site later.
 

I did more further check about ksize() usage, and there are still some
places to be handled. The thing stands out is kfree_sensitive(), and
another potential one is sound/soc/codecs/cs-amp-lib-test.c

Some details:

* Thanks to Kees Cook, who has cured many cases of ksize() as below:
  
  drivers/base/devres.c:        total_old_size = ksize(container_of(ptr, struct devres, data));
  drivers/net/ethernet/intel/igb/igb_main.c:        } else if (size > ksize(q_vector)) {   
  net/core/skbuff.c:        *size = ksize(data);
  net/openvswitch/flow_netlink.c:        new_acts_size = max(next_offset + req_size, ksize(*sfa) * 2);
  kernel/bpf/verifier.c:        alloc_bytes = max(ksize(orig), kmalloc_size_roundup(bytes));

* Some callers use ksize() mostly for calculation or sanity check,
  and not for accessing those extra space, which are fine:

  drivers/gpu/drm/drm_managed.c:        WARN_ON(dev + 1 > (struct drm_device *) (container + ksize(container)));
  lib/kunit/string-stream-test.c:        actual_bytes_used = ksize(stream);
  lib/kunit/string-stream-test.c:                actual_bytes_used += ksize(frag_container);
  lib/kunit/string-stream-test.c:                actual_bytes_used += ksize(frag_container->fragment);
  mm/nommu.c:                return ksize(objp);
  mm/util.c:                        memcpy(n, kasan_reset_tag(p), ksize(p));
  security/tomoyo/gc.c:        tomoyo_memory_used[TOMOYO_MEMORY_POLICY] -= ksize(ptr);
  security/tomoyo/memory.c:                const size_t s = ksize(ptr);
  drivers/md/dm-vdo/memory-alloc.c:                        add_kmalloc_block(ksize(p));
  drivers/md/dm-vdo/memory-alloc.c:                add_kmalloc_block(ksize(p));
  drivers/md/dm-vdo/memory-alloc.c:                        remove_kmalloc_block(ksize(ptr));
	
* One usage may need to be handled 
 
  sound/soc/codecs/cs-amp-lib-test.c:        KUNIT_ASSERT_GE_MSG(test, ksize(buf), priv->cal_blob->size, "Buffer to small");

* bigger problem is the kfree_sensitive(), which will use ksize() to
  get the total size and then zero all of them.
  
  One solution for this could be get the kmem_cache first, and
  do the skip_orig_size_check() 

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Zyiv40cZcaCKlGtM%40feng-clx.sh.intel.com.
