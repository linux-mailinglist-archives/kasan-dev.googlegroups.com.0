Return-Path: <kasan-dev+bncBDN7L7O25EIBBTORWS4AMGQEJUX7POI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5227899CCA3
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 16:21:03 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2e2bac0c38asf5428811a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 07:21:03 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728915661; x=1729520461; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VNGaOlS+Y2Z3CxzajdbtN48RiVb5oCBDw7vUw6LGml4=;
        b=qpJRqQ9KlcYHFSxx8hwlfANMVZIIqT6UmBlqiKbY6rx5zUoUOctEr1569kZJXEduu+
         tTcfwD/prJjrvPy11YCFMtCZZZZWOCmng9FJ1XqKCxkTNE5ryFuRyxEwcbUF1ZOAEO6M
         6/P1Q8udgqK/dJh9GBJJ0JJ5+ddg3OnYxBVsJHZOc8jqvTfgYdnErWZJ5A0UpnpG5Qvw
         abu85WIdJooOi4NiVgeeue8IiT1y/AlZ6ARSkaaxAWtv6VxmOuUknVueG/OLn1JPqmLD
         K9+1d3OMk94W0aYvbeY7pjV/07EGliGkYuNjgUU2mh5H0S4/NfahIpDNuR3K1AUMKu7/
         QV0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728915661; x=1729520461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=VNGaOlS+Y2Z3CxzajdbtN48RiVb5oCBDw7vUw6LGml4=;
        b=tqWBbSsELEAOJXV1Ah57OEExCksYytJ4UA/v+hzMDMEaDDKDeJfMVVH1fKnBfRGrHT
         OVqwINOy/9OV8v2JdGpX+3aupTtKBAcZhV9TMlw7T/1dN3NLbTritGy16nWM0vBn65ze
         ARvr+J6koxDTP5VDd/tsnww6EaTFsuvz/BWI+tVvnC7MnG/rLCudghbzUJ4zZdOwbFCf
         Jzc+u7xGke5hoPK4DSCYrvAu2b4BeL3FPkW5xv28y3jJCIW/LqQ/YVu/18Jvqgwh2WlG
         GpVf7WTa/h/Jyt+tVY4H7GXZdZvmNxZYCG540S9qDVce0mNakj/R/HdSRGFyzpZt+ESJ
         K/Rw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkcO6owxGo0BCQYHOcnhnSfBYKyt4QUBMWSGj7gXDdzEUpJriZMjzCaPN6E8WXYGuypDt/2A==@lfdr.de
X-Gm-Message-State: AOJu0YzhSUQq8g0KJDgumv+k8aSQppwHejABbF6CjuHo8eY3uIBiOQrI
	mxrJMJIzVTA1f+L2wsW0BSfcdhbxJ7fnwq4OeYwiIwpPQ9vNF2PA
X-Google-Smtp-Source: AGHT+IFIr32EPIQeG36t0w7qTuyaCYJqNRPz12/fDALm6oewvt3zB7Lyj0GUVb3vVk59NVVSZYaKHA==
X-Received: by 2002:a17:90a:bf09:b0:2e0:d1fa:fdd7 with SMTP id 98e67ed59e1d1-2e2f0d8dd21mr14289303a91.27.1728915661343;
        Mon, 14 Oct 2024 07:21:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f98d:b0:2e0:7e59:ea75 with SMTP id
 98e67ed59e1d1-2e2c835b6fdls2843635a91.2.-pod-prod-03-us; Mon, 14 Oct 2024
 07:21:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXfOrTFx/Onzt5FHZjbPZJ6THB7SVJMpn634Hd/hVxAM274A9VyiM7wuTuMhB/e9Gt0QnVwKfHTKZw=@googlegroups.com
X-Received: by 2002:a17:90a:2dcc:b0:2e2:e597:6cdc with SMTP id 98e67ed59e1d1-2e2f0b01eb9mr12699916a91.22.1728915659954;
        Mon, 14 Oct 2024 07:20:59 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.14])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2d5fc5c2csi319755a91.3.2024.10.14.07.20.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 14 Oct 2024 07:20:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.198.163.14 as permitted sender) client-ip=192.198.163.14;
X-CSE-ConnectionGUID: jUhv+7MTSrqGqgIpyENusw==
X-CSE-MsgGUID: g0p2ufHOR4me5sJt3BESeg==
X-IronPort-AV: E=McAfee;i="6700,10204,11224"; a="28454945"
X-IronPort-AV: E=Sophos;i="6.11,203,1725346800"; 
   d="scan'208";a="28454945"
Received: from fmviesa004.fm.intel.com ([10.60.135.144])
  by fmvoesa108.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Oct 2024 07:20:54 -0700
X-CSE-ConnectionGUID: ZLVNVtuiQJ+ZN5GVDJ1rmA==
X-CSE-MsgGUID: mAxkV5plSc2louqsepSLBA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,203,1725346800"; 
   d="scan'208";a="82208103"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by fmviesa004.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 14 Oct 2024 07:20:54 -0700
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Mon, 14 Oct 2024 07:20:53 -0700
Received: from orsmsx602.amr.corp.intel.com (10.22.229.15) by
 ORSMSX611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Mon, 14 Oct 2024 07:20:52 -0700
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 orsmsx602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Mon, 14 Oct 2024 07:20:52 -0700
Received: from NAM02-BN1-obe.outbound.protection.outlook.com (104.47.51.43) by
 edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Mon, 14 Oct 2024 07:20:52 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=GYbumwTFUpJ1Ha+OADfmoYVY2U8Z0t4NVAE6LQLN9bzcYT/EZTdcMAdC2+AtY2p5hTkkr/KESWBE+sjcF4c2gD3stjBrKnKmzJNZock2ZVZiAKrOr3qt4s5CHW54FtqzOz8+yLBGxJ5L5eu6ScWdJ2ffsIu0V5ler2NtPM00C35li/j1ahNJa4wBFAOKLQ8IwAUC1JO/0xmuMHTP2PF6Ncm6OK3aA95S2fe/XPvr6uSBQXn9ybIrcEJ8bWZm2BeRlxqscPmBOBBNjttWvTX52T2/h+q9eYi4oO6LuwXduV13QoLxV+5NoNfa8sO6bTf/Vfb14dJJmTtdAO1o0/bVkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gPYHEowz5YCMyq42+LrwvqSayyLs12qkZHcOkYib0CU=;
 b=RIAIMSCvJmROsMGDoaoaORw8tQPMiBtR241QwSsLBzzMVfo+JgIf2/mMlwWmvlcn5+XIWplhwHl6j2hp4u++w5yT5QckmcixGVlq//2bw/VKiEYTJVxT9Y8/D4Cp5tnWAfCUQheWjT6iesvb7T7E8WaTEnlt+f1VYjr8BKTtx3fMfvsuyJojwQhmZ2ddSJ36ynzpF2DLZivZFw0JfD76lEnrZPJUAzxn1NsbjQndsRhO4olm5y9a+qG0XKDbw2ZBV626uR1VLKfFF4zlB6TQVRSN/KE1OkhNV++qRWbHJoE3ftveEvVb5iZkL7mEEnN5z4RC+2rvOLsvzUWLRQk9Fg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by PH0PR11MB7541.namprd11.prod.outlook.com (2603:10b6:510:26d::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8048.26; Mon, 14 Oct
 2024 14:20:49 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508%4]) with mapi id 15.20.8048.020; Mon, 14 Oct 2024
 14:20:49 +0000
Date: Mon, 14 Oct 2024 22:20:36 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
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
Message-ID: <Zw0otGNgqPUeTdWJ@feng-clx.sh.intel.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
 <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
 <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
 <ZwzNtGALCG9jUNUD@feng-clx.sh.intel.com>
 <a34e6796-e550-465c-92dc-ee659716b918@suse.cz>
 <Zw0UKtx5d2hnHvDV@feng-clx.sh.intel.com>
 <0e8d49d2-e89b-44df-9dff-29e8f24de105@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0e8d49d2-e89b-44df-9dff-29e8f24de105@suse.cz>
X-ClientProxiedBy: SG2P153CA0047.APCP153.PROD.OUTLOOK.COM (2603:1096:4:c6::16)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|PH0PR11MB7541:EE_
X-MS-Office365-Filtering-Correlation-Id: 8e2dbdf4-5ed9-46af-4ac2-08dcec5b6724
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?vB1iEEvqhQPNW4BgJPPvV6QoBaeheU2qTkZXg19PWAeAE4qjY2al9BgTXwOV?=
 =?us-ascii?Q?yEr3MCeGoXThCA/9xuod7rE/DjbXkY6fO4PQVF77bvXLhse9WC5a2MlLsnCX?=
 =?us-ascii?Q?nYit4aK/fLKI3zj1lEiFg5U/CTJC//w66yTeFeec5ByXqGiBDo7NRGBECR3D?=
 =?us-ascii?Q?HR6fCsYJpdPhNLKVqHmce25iCq7Co5xH4eDQHKJlkMGWqKVFIelTJG9sV/Gy?=
 =?us-ascii?Q?cDCzOb3hdxrr4rlOD8m/8/NEzzghnlT96aAV1HMMKm3KVQYhf0pQ0bgXy5if?=
 =?us-ascii?Q?krGwI/cj/wIV/IXcaEV6wozWzI1y6oLlKuMCwa+vqvuIRbDUg0QIGtt8sf5k?=
 =?us-ascii?Q?6QbwJShpDTCg5mg8pvmc4aAC3WbW+1Gqxjsy9QHpI7k0+41g2asKcFIpl4xm?=
 =?us-ascii?Q?VsTP/1PHtANvQKFR/KvmZQht5VB8Bw08gSfc0r9GhOSCouIHfW7vIue3Zciw?=
 =?us-ascii?Q?zKLLoVOMo/N020SsKKiETkeJhT1IEu4llQj+ky0WMbHODuM849Uf24iuOzAG?=
 =?us-ascii?Q?lu+KZ1a37hgqoyvVXfB9ixvmXvghaPCO1h37pKsuGsd0qltt1PSM2n9jHUxm?=
 =?us-ascii?Q?3mt7o6WxSqWIF5vNlylyi/xi1bcHcJSYmLLZhGJUIRh3/ssbqJZZq0eOnfwB?=
 =?us-ascii?Q?v7j3RPdCqmE4YBFuNaDP9Et2uJhfUJDYESmAKYNlWf3kJ3WxtPWIb9K1q2JA?=
 =?us-ascii?Q?bRpczM1WcpGhM/wF+/XzV6o2DgAFOlXoTI0s7vtuK4ueiUoxRYsiHX5VVuCL?=
 =?us-ascii?Q?tZHUG6HQ9blL+LI6vgF87MPY4qI03FrCHMzrLIh9koENVMDUzePhTJhMm8YN?=
 =?us-ascii?Q?Uv7l8Tg7vwVkt3R+QJJ+DlOsGEFW8txRjg29dqUQTOaotCn+hiKiBNMD392d?=
 =?us-ascii?Q?I38u7J5nOY6iLyLX1tfhBJ1aL4/xLrMgN+uavRjk6PCqEloVp4RGmv6uWO1O?=
 =?us-ascii?Q?c+Yzb0Cd21EVidlolVUQ6D4nTPIEdnntOruvuRrENh5OH03xmJz60v/V5QOQ?=
 =?us-ascii?Q?UcsAutEQEDzpVnrsruGSWfekLeIiIGhhXvXI/dlVje90qKF2FXcnxFBK1HPi?=
 =?us-ascii?Q?akmtGFlSaXpewSu78k8JWigfz5C8zcQjk/e3QA8gtcyeA3Awqn5Y00pebxku?=
 =?us-ascii?Q?sFnXY00i831MauTUF3usEyG1huCjMBdpNLFQ7iSnZF5cDfD5Rjx52Wqyoa+I?=
 =?us-ascii?Q?3/wnD4GSD75GZ67fjqG3Ivtckp6Qm1XdewToY2SK1mGS8PlXIsugf57yGLjg?=
 =?us-ascii?Q?3i2929Eq7BMxw+uS+tK8THQz803foFjUigX0cwmf/w=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?BLFFgh1X+J0xrJcx4HAwlyoZRM4vuCIc5nyeMNaOLwBXirrdO7bjZHaHP7b4?=
 =?us-ascii?Q?jf1yoKcJv0MshPbbyKolpLaCSiF33dlT/IOfzNL6jH4XXgmCma+XhJQw6x2B?=
 =?us-ascii?Q?ByF73Ymt13I+U7CGVLSdWvX0N77VO2ZKkpxaZkINQAYFcnyXsy9B0IvFfiYG?=
 =?us-ascii?Q?s0UHMJupzlbl+aNgApCZ0o77vmblU6h7ty6UTy8Ak4ry60JpXoZdrHjg0FgB?=
 =?us-ascii?Q?37BTzWbzHYEmCFPXkKntwPCyyE7wvcS7p1tl8k1ROcxvdcRrTjwnxHT+IXRY?=
 =?us-ascii?Q?wJM2bOnbxgYMIhoXRxB2oK80ctMAtRAF+l1KBHn0TcipvI1WP+PFvy67gtgW?=
 =?us-ascii?Q?BSEfNL6j4Mcy/73gFJB8HimVnttlyKJTcmWG6xl13X/ja6xKMFvUuu61qBlI?=
 =?us-ascii?Q?8RbH22wfF/IRECcNjtKvgHLHf4qIWqPtldnAqvq+6yc6xlcbkOmB3e4eiHVB?=
 =?us-ascii?Q?4mxlZNHEMxkZKlYbSPJQoi8fGH2/bwt1pEhx+7HS5rwzDQho4pUCrVfH3Py9?=
 =?us-ascii?Q?NJXXMGAWKscPIHlGErhmSmeXxnEYj940SpnegNBnV5T7S63lR3JPRq+JAwqn?=
 =?us-ascii?Q?H1WBmKLWXaiL8qqx9ZVhmT8sWW9pMeYk11C1GY/5/v+kdXyvvJTRUniNtOvk?=
 =?us-ascii?Q?1Mqs1RMOc3I0SmlyDu7xY99ug5iw8QO5maT67YSDE62dA+gxRgFxiRJyY8cx?=
 =?us-ascii?Q?sqvpH6vo1mq4O5gwsvUGPadjbE9FVyPIV1T4sU/3/lIt+fZONglI0QBj+2Cc?=
 =?us-ascii?Q?k57IU1XKKiQEr8tj40iR8/zVi4+7IfQ8C5jdBbrrpDxxy8rzLF4vA5+zpRRb?=
 =?us-ascii?Q?GMg8RbG4blb0UnujLuid11SwPVt00IafBmnpvNHdHUO/c4c7AmpX+0tHovNU?=
 =?us-ascii?Q?793zWDHqOHPG3qwlOLvzNyhaF6CH8GbsZ+/FwBCpXbouX3NfB/hUYey7UNiL?=
 =?us-ascii?Q?y+CxnmQHu5/QckVWi7XXsI6F3pEokWGNBFNvjU6HfJbD8ADQppwTKmhBiF7J?=
 =?us-ascii?Q?jK8Sy5mSf4l6AeyoYSB6nEeWtctxSNz2haoWjF+UdBU3OV8wuvIUzsvNYuun?=
 =?us-ascii?Q?aWpPA/li7gkxGubmZ/jX9Dj9+jVn/kgik+TDmlP1tcSEAwNlr3F1UP1DGZHz?=
 =?us-ascii?Q?aXSKVYodmkyFTQRcTgPcPUJ++m6ap5OmyQtTQTIJplVkSGCrGKfkH4W9/gEw?=
 =?us-ascii?Q?+prEB1pl1AiL2gMbMpsR6qXHB4kgTFr8hRpOHy8hajCWV6dtMmKCg28hN4s7?=
 =?us-ascii?Q?KDjP3IeNKHYgzFasY0/BwPJ1dIMdavml03GQZmTzBfit1YTIlk92KOaLXXgr?=
 =?us-ascii?Q?KU6uNuNgCMiDljSreU6tjKp7ikRUQKOIsqP/wxA2csyIWUK+jG5ke2aKjpWg?=
 =?us-ascii?Q?0zTZ0JslsGbVK+/+nUzQ9n04DpOHLXgxSWeMDoQPYDIep+Gg7fiqLK+1DZwn?=
 =?us-ascii?Q?mW4D0PgwS5NmA/hpcA6rk7uIG6N50ofpMpFpJScrDrNWEcGza4+b4R4xaESZ?=
 =?us-ascii?Q?32danLffNvWJA95B6NUn5DatpGpagtNIi0WANRJQ341JTR1dMbQs4ik10C/X?=
 =?us-ascii?Q?BZ9j1LFCfuIaAkF+KReTN0z/btRGI4r/vfTInbnX?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 8e2dbdf4-5ed9-46af-4ac2-08dcec5b6724
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Oct 2024 14:20:49.7253
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RVO/BpjF099y8/fZwcSX3t4K+RsWrnqeolmYTfzosdVOaDRf4Q05Rr6WOWR847kIA41nq/4coFM9zd1745z/JA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR11MB7541
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=crQNeRkd;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.198.163.14 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Mon, Oct 14, 2024 at 03:12:09PM +0200, Vlastimil Babka wrote:
> On 10/14/24 14:52, Feng Tang wrote:
> > On Mon, Oct 14, 2024 at 10:53:32AM +0200, Vlastimil Babka wrote:
> >> On 10/14/24 09:52, Feng Tang wrote:
> >> > On Fri, Oct 04, 2024 at 05:52:10PM +0800, Vlastimil Babka wrote:
> >> > Thanks for the suggestion!
> >> > 
> >> > As there were error report about the NULL slab for big kmalloc object, how
> >> > about the following code for 
> >> > 
> >> > __do_krealloc(const void *p, size_t new_size, gfp_t flags)
> >> > {
> >> > 	void *ret;
> >> > 	size_t ks = 0;
> >> > 	int orig_size = 0;
> >> > 	struct kmem_cache *s = NULL;
> >> > 
> >> > 	/* Check for double-free. */
> >> > 	if (likely(!ZERO_OR_NULL_PTR(p))) {
> >> > 		if (!kasan_check_byte(p))
> >> > 			return NULL;
> >> > 
> >> > 		ks = ksize(p);
> >> 
> >> I think this will result in __ksize() doing
> >>   skip_orig_size_check(folio_slab(folio)->slab_cache, object);
> >> and we don't want that?
> > 
> > I think that's fine. As later code will re-set the orig_size anyway.
> 
> But you also read it first.
> 
> >> > 		/* Some objects have no orig_size, like big kmalloc case */
> >> > 		if (is_kfence_address(p)) {
> >> > 			orig_size = kfence_ksize(p);
> >> > 		} else if (virt_to_slab(p)) {
> >> > 			s = virt_to_cache(p);
> >> > 			orig_size = get_orig_size(s, (void *)p);
> 
> here.

Aha, you are right!

> 
> >> > 		}
> 
> >> Also the checks below repeat some of the checks of ksize().
> > 
> > Yes, there is some redundancy, mostly the virt_to_slab() 
> > 
> >> So I think in __do_krealloc() we should do things manually to determine ks
> >> and not call ksize(). Just not break any of the cases ksize() handles
> >> (kfence, large kmalloc).
> > 
> > OK, originally I tried not to expose internals of __ksize(). Let me
> > try this way.
> 
> ksize() makes assumptions that a user outside of slab itself is calling it.
> 
> But we (well mostly Kees) also introduced kmalloc_size_roundup() to avoid
> querying ksize() for the purposes of writing beyond the original
> kmalloc(size) up to the bucket size. So maybe we can also investigate if the
> skip_orig_size_check() mechanism can be removed now?

I did a quick grep, and fortunately it seems that the ksize() user are
much less than before. We used to see some trouble in network code, which
is now very clean without the need to skip orig_size check. Will check
other call site later.

> Still I think __do_krealloc() should rather do its own thing and not call
> ksize().

Yes. I made some changes: 

static __always_inline __realloc_size(2) void *
__do_krealloc(const void *p, size_t new_size, gfp_t flags)
{
	void *ret;
	size_t ks = 0;
	int orig_size = 0;
	struct kmem_cache *s = NULL;

	/* Check for double-free. */
	if (unlikely(ZERO_OR_NULL_PTR(p)))
		goto alloc_new;

	if (!kasan_check_byte(p))
		return NULL;

	if (is_kfence_address(p)) {
		ks = orig_size = kfence_ksize(p);
	} else {
		struct folio *folio;

		folio = virt_to_folio(p);
		if (unlikely(!folio_test_slab(folio))) {
			/* Big kmalloc object */
			WARN_ON(folio_size(folio) <= KMALLOC_MAX_CACHE_SIZE);
			WARN_ON(p != folio_address(folio));
			ks = folio_size(folio);
		} else {
			s = folio_slab(folio)->slab_cache;
			orig_size = get_orig_size(s, (void *)p);
			ks = s->object_size;
		}
	}

	/* If the old object doesn't fit, allocate a bigger one */
	if (new_size > ks)
		goto alloc_new;

	/* Zero out spare memory. */
	if (want_init_on_alloc(flags)) {
		kasan_disable_current();
		if (orig_size && orig_size < new_size)
			memset((void *)p + orig_size, 0, new_size - orig_size);
		else
			memset((void *)p + new_size, 0, ks - new_size);
		kasan_enable_current();
	}

	/* Setup kmalloc redzone when needed */
	if (s && slub_debug_orig_size(s)) {
		set_orig_size(s, (void *)p, new_size);
		if (s->flags & SLAB_RED_ZONE && new_size < ks)
			memset_no_sanitize_memory((void *)p + new_size,
						SLUB_RED_ACTIVE, ks - new_size);
	}

	p = kasan_krealloc((void *)p, new_size, flags);
	return (void *)p;

alloc_new:
	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
	if (ret && p) {
		/* Disable KASAN checks as the object's redzone is accessed. */
		kasan_disable_current();
		memcpy(ret, kasan_reset_tag(p), orig_size ?: ks);
		kasan_enable_current();
	}

	return ret;
}

Thanks,
Feng


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zw0otGNgqPUeTdWJ%40feng-clx.sh.intel.com.
