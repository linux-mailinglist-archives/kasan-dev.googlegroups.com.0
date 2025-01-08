Return-Path: <kasan-dev+bncBD2KV7O4UQOBB66G7C5QMGQEJVMBBBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 91909A05423
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2025 08:04:29 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e5382ab0b41sf14521218276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2025 23:04:29 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736319868; x=1736924668; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eQhAvEV+lliWQeLyqN4SvEiE7CM+D3k4wLDdNRaeYWQ=;
        b=ioHALHBYiNGFcl0UZQtedskV2cehgxAMG6f0xGlPzKf3uxV14CGliQmD9EAkR915Nh
         8N3dfwdpE/7L9gD9z0eJSlSD8SyWqVCWgdQJc0yx6Uk9sQNSk8S6nFvE88WRX1OumHvr
         sAZYhoFhfYOeki1gAcnq6v9RqAODgvEIJbBSI5QT/TiteGBEUpoUUFJTI5Fi8nhgDAs+
         tJVf8q9s/3PvwC87wh1WRzKXpz4ZkqLqJdhWUeSec1B6Nezej4bHayso0+NkhADoEhIm
         OxoJshOxnfxUj5MKeHC4OfS+Z2aqU10L0rBRraYjKO3Avo5z78qCoUrAbWSqw9+x00Ex
         SxpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736319868; x=1736924668;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eQhAvEV+lliWQeLyqN4SvEiE7CM+D3k4wLDdNRaeYWQ=;
        b=WxYVmXZPg4mWrzBOZJMZnm0c/M09lFrV/AafZ4g6l3isg26lLzzekQibIkLE08Ri8+
         tCNErciM6r17Lh5a38LRJ0vzDOUiU2xfnzgaoS9t4R1147iltkYl5RnFAUMEUbJMQXh4
         c1RDEO2YmBIo5CcP6O6jbN6YMZ6T6VOW2s1LQHqUwOZS+fO+Sg0CDaF6vtTJpjULZcIh
         Ty8Xr0mj5WJtyZ2bajW2RJIr5LTXnmQ6lxRbJYpgCBSc7iQXagXy4M2S1HhBuvkQvbsY
         iW67QGsHuI56CkAPRognw6wWBhNY38zZXMbmi8E1sUP827ZYbAIO8kNSV4V16lpKgiFZ
         otUw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXwdL6qQ2ZMDBZd2FlWPlou1faAgTkCdDARVBW+qfoSFeQ504tqUPnZ2YY6HuTDNVxII/sug==@lfdr.de
X-Gm-Message-State: AOJu0Yxlcai4wj8ZQUH76+ikBFJeb4RkrLIuSs/9jIjrXv6zLkPizIUx
	kNjDaqWIOD/jk8CJD3lC1hQsWl3uOer1NBRLM6T8pNt+Kve4eBv9
X-Google-Smtp-Source: AGHT+IEaQaUuyVUe/CcKEM0hWbVHYay1cI4dBraR0EGtr+Fggb5UF6nKPfWsW0iEcMbTddmXl+Z4MQ==
X-Received: by 2002:a05:6902:1183:b0:e46:42d4:22c2 with SMTP id 3f1490d57ef6-e54edf4137emr1372702276.7.1736319867801;
        Tue, 07 Jan 2025 23:04:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aa69:0:b0:e48:25c2:a5d7 with SMTP id 3f1490d57ef6-e5411996a9als247000276.0.-pod-prod-06-us;
 Tue, 07 Jan 2025 23:04:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUfnmwu4j3AyMn3dMOmSzGL3ZR/QC6bNeactGCaY2WZKWpA5JagXUSYs8P6q2qSswU0MrgpxJYRuMg=@googlegroups.com
X-Received: by 2002:a05:6902:13ce:b0:e39:8ef6:2231 with SMTP id 3f1490d57ef6-e54ee1636c5mr1596488276.21.1736319866350;
        Tue, 07 Jan 2025 23:04:26 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.17])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e537cefd4e3si1545110276.2.2025.01.07.23.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 07 Jan 2025 23:04:25 -0800 (PST)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.17 as permitted sender) client-ip=198.175.65.17;
X-CSE-ConnectionGUID: cF6JvJ/DSXCbUffkePLecw==
X-CSE-MsgGUID: h43TkGxsS0OK9F0E84XOZw==
X-IronPort-AV: E=McAfee;i="6700,10204,11308"; a="36552906"
X-IronPort-AV: E=Sophos;i="6.12,297,1728975600"; 
   d="scan'208";a="36552906"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by orvoesa109.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Jan 2025 23:04:24 -0800
X-CSE-ConnectionGUID: 3gtnNn+FRlmzjd59wZBvjg==
X-CSE-MsgGUID: mld1vos3STufW8mjKHyUuA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="107628686"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmviesa005.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 07 Jan 2025 23:04:23 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Tue, 7 Jan 2025 23:04:22 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Tue, 7 Jan 2025 23:04:22 -0800
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.173)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Tue, 7 Jan 2025 23:04:21 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=xG8TBovWTx3e8PqtVDI/WBwnNl3E3wKZI27OLNLp8+s2JwoGWQS51LL9SgH2tjzNIRomlWWa8qlHugjoUq3rxKfd4X/t9mjrOnXx2X/H3bQITlGQSRCtZ5Hdznny4O7batOlGwlIH7bhpn4h9cbLEAYOxZh3MAWQyh30DppRuva45mE988PAdz9cX8aRxxSuSvm8sKdeBruKfE9DQzSOFCVZ6rGALggFgTl0hiPg3fl7CXiNde0q3Xyf1asXYUne/qpK071FAV33FDh5TJkFGZF3Nn40LxGYgBCMA+TsLuaS0j+cJ4tFly1ocFe/IaMdFnoYj0nNfCeXbuI8JX+TIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SJvqAE7bHrUE1WRtE3hfmeGNsVNOlr6ScKxBxfO0+a0=;
 b=I+50/jC8La9ovJncZgs5QDsF+JEomT2rkn64hhYpNLUSLYPxSp5yhkWDPQ1Gx+ajx8TN2Gi57sc2P2gF1dePLSGux2reH7gmLuJm8t1kLQeRFABf8cZyQKHON/TEzM7muNtJmYiMQ8Hw0LbCZ00zpRzw9Oj68Il+nNeQXxOPxPuIFWOaLOzbK33Wlkdk//kwkr4+UtAR6LUXdUG/SCl/ozO3O+7uS6yC39gRK75hVOeOINcykMfIhcWHp9diuWMzXmrqTS4NumBU+uYWE+bknZy4vMUpvhz3pZQ7buJZZ+L/kKMUaZ4VVEWyYrtOhxfCnBg0Bd8dkVD2zN56f1D+eQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by PH0PR11MB5879.namprd11.prod.outlook.com (2603:10b6:510:142::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8314.17; Wed, 8 Jan
 2025 07:04:01 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%3]) with mapi id 15.20.8335.010; Wed, 8 Jan 2025
 07:04:01 +0000
Date: Wed, 8 Jan 2025 15:03:52 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Nihar Chaithanya <niharchaithanya@gmail.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <linux-kernel@vger.kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov
	<andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Shuah Khan <skhan@linuxfoundation.org>,
	<kasan-dev@googlegroups.com>, <oliver.sang@intel.com>
Subject: [linus:master] [kasan]  3738290bfc: kunit.kasan.fail
Message-ID: <202501081209.b7d8b735-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SG2PR02CA0129.apcprd02.prod.outlook.com
 (2603:1096:4:188::19) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|PH0PR11MB5879:EE_
X-MS-Office365-Filtering-Correlation-Id: 5346d774-6982-4714-fe67-08dd2fb2a175
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?8U5uvxZuX/ak7uskAquMrg33ObVL1OORL8Ippd+tXUJEBiYf/pqBYEtNFSGL?=
 =?us-ascii?Q?fBkvv17JyP5EG29yKlJ2RUMjlMps17Lu11TlXIv37Aokt+tO1vfEyWG/yp15?=
 =?us-ascii?Q?DrGn0C1d3yfIdKkifGuyChAkcM3Nv5Ukgjee3QvPvuSueGSau2asA/yskB3U?=
 =?us-ascii?Q?ZyoON9ZmYrwl6FZSo/r7GAm7OxI5FIFV9I6xPx65V68x/1mb3JjjqzfpWnS7?=
 =?us-ascii?Q?sUfD37w9wJYjhCco2ovI7UTg3BPYBOqlRk1V1B3GJf5UwQvBFIeMw2PZjhCI?=
 =?us-ascii?Q?Mo6PQj+U9e6W4m5VOgjL5IMs4SqNEXGjOgmlBkH9x57zsLi4x5ubwT5XNGzH?=
 =?us-ascii?Q?WnF7LXevGJT8tD8vuorm6SWnZcp3mB0Aaun/6FhrqTSUxc1tyQv7aL+A1JGa?=
 =?us-ascii?Q?w0fJDL1BhiBcXPUpfRRmHpeYEOXwhcddv9wjkpJ2ldbNLuMMZLeF94pphgqJ?=
 =?us-ascii?Q?u+5ebVWn4eyJxsb2M/di/7vbust3J/fQg2cWzZ9Fst/GH0cRf6/YOX2cF3xe?=
 =?us-ascii?Q?/TiOTsr6c4tX6UrIXgAOzHD3G+zkjZeKjZMVyo6wX/CnKhC85Y9+Sv1z7p9b?=
 =?us-ascii?Q?MvD8kCqHOCkopxsUdqZxugBDoDTqyw0nqzx0+JhKmXhbXvoWkgRGDaR8eEUw?=
 =?us-ascii?Q?Wx0RKkZy3juC+i1mw1RM804kMx9Fz5B6GCJUmo/4DRx1RYUmeYT4e1FiUiZf?=
 =?us-ascii?Q?hsJcXFxiQiI4ErlnNgQ5/23XbA+3S4NVwDQq6ijlsNkRoqOWgma5NmLhbUj+?=
 =?us-ascii?Q?48zbayROIcwDL5lYm5oGy7Wp6A7PfXr5TR2n8d4EW7yJeblThj0oKNFtuHD4?=
 =?us-ascii?Q?hvb6p9wH7WOgsB5Xmaan5wkp+TLapvfzO6SJj3vWDwmLjDHdqe6pCEcnc3kM?=
 =?us-ascii?Q?E/xY6SV9uqFDS5w2Yl2v00E7keMNnAaKYmtNTBhdZZDPib5eCmY4CAn0tpvt?=
 =?us-ascii?Q?EZTHWLohTGbLPFp1Cj0jVperB74SkEJlkJC9CI6EPcZy32w5prQmYZdWeKPE?=
 =?us-ascii?Q?aHVudVzUfrM089hoK7BQ4PMr6uTXWli3M0gYlL/x+fs66TUYMC+CrwfZ4lw1?=
 =?us-ascii?Q?eS/DuoPLXZ7ikLpn7RVeZLaXrLXdsK3bZ13r5M90DEZCFaXC4pp5pB0iRxQP?=
 =?us-ascii?Q?hrkmM1tQinrri43nUcJwF0nvLYR2KjBByu5l2beahSCHoxxu5Zy4958QNt9H?=
 =?us-ascii?Q?DpQwcd6WTbo5C8f95uuEq+MbodEJnOawoIOlNhhDGheGTNAAO/cWTBd8M0fk?=
 =?us-ascii?Q?+ZYQbq+CCeTWoyLlOvGNyPG3Ibfzox2KQWMPGufW+qmrkgSL2SbcmZK5oZDz?=
 =?us-ascii?Q?HDVpUqM+gTiwjUXSeEBvC+IZY01G7zdsao/1nDyYDeyNwA=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?fs8JIT7miI459ZV7JzyJXCXV3LXsZWWckcosexzjXMFPtAgn57vtUpCOfNwQ?=
 =?us-ascii?Q?WSE1RV0LtqDVWmY4aTinhn4QVts7FLchamDqBR6YsNlJ89d5Nq3c2bsJ9Ozj?=
 =?us-ascii?Q?ElmFIqudXtGESzKtg8TA3Ues+GE2id23nmOfVpz/BaqdLwit3NtlhmDQ8bAU?=
 =?us-ascii?Q?DeZCw7i0N8eb1OcZ4VI+hSwJ3BgcP2cXPgS6ZvbeLCpHs6vArrpydsAML33A?=
 =?us-ascii?Q?GqpPcTu32PIeFXK6diFJrDpFxTZmBrO+V6Ad9z0HAuZmrydcrt3C9265ugvi?=
 =?us-ascii?Q?hmHtAya29AgG8f/VyxL+/LnB4TJXkThaD+Au2jqmLKXec5SNh3Bv3q0+7bF9?=
 =?us-ascii?Q?hUemz6RdORsPcK+y3UagywFUTGHOhivVNqdGlfuvEh9/3Tk+CLw3AdcUfq0M?=
 =?us-ascii?Q?3twUTq/6SM2JVolT6rC/reZvC0H8q0U8d1Ix7pgwTTDyTs8p8grGOXA0MZwy?=
 =?us-ascii?Q?PSWH0JFTO/mWSLAUgXrNZXJ2ck35jYvYSEhaGnOqexIwTmFB2vPGLkbbTL3+?=
 =?us-ascii?Q?sAmve1LXSkqfEWBbTP4TcMD04a5xIRL9iTDG5Dd76I0kIhurH/M3aH1quM8D?=
 =?us-ascii?Q?D2B/dTbAmowOJIvueHfyPCx0XhQEw0ZepnEMSWLVM54f33r3YQORkzeDurmQ?=
 =?us-ascii?Q?fnPZHSAqUWgBRTX1tMhq3bT0vPMcDn8SIZ0mCWSkCopdxpZyG+bc/A2JQ5fs?=
 =?us-ascii?Q?YbFQz076n/R3M9X80xZr00GixQiDceRdfoFkN0Mfj96lFZ5b8L1rgXZaPrTW?=
 =?us-ascii?Q?12nbKwWWLdPCstrSo4Je78CQuD3RQpPth9y/mJjeUJqIk1HOES8yAufOAhtH?=
 =?us-ascii?Q?MdAPL7mmFPPM5kdCeONHcIZIMvqYcaSS4pDFX1PAc9wogWEgSh6BzBMINgDX?=
 =?us-ascii?Q?Z+2UKCVLwHaG39eJupfusJvAn4DkL0+I7za3O8xRBcKh4KnSoIIrI9J1+RXS?=
 =?us-ascii?Q?oCqRdVLWJ/xMffyOhbSn2RJEf9NtjHiZBGRQCvAhRipIUeRFn1Pgab3qkCtD?=
 =?us-ascii?Q?fNdcW0jIHU521GleXbOfpiUsc7ozC+Vg6BVNnI9chqYSkrYoryr4cQYKKZbb?=
 =?us-ascii?Q?Nb5Y5MbivhLLEI7srtpk7HuM7VftQsqUkIj5tSlJFbEJm1q6ilXY+J9GyigF?=
 =?us-ascii?Q?6ES0FhMOwI1LPl6ck5cMYRL/4Kfpigve+YJGBRdKNNw/xWs32k1LmTOw/Orx?=
 =?us-ascii?Q?R5IOJZUIChaR8TY26YfD4OAa2N5vRKzR5Ptouyn5XlWSSIlbvkB8tS1/ihz9?=
 =?us-ascii?Q?pcdAjL6paWbJHbD8nJmmpNhjAbNjspeJQs7jF87khB6iN5sKnf/ukQEvtvty?=
 =?us-ascii?Q?4QlgiE7U8sZy05Wt+YGTrbtkPfGrEf6g3z08f9Us2QA3OFJk/oljri+pbaQ8?=
 =?us-ascii?Q?wPjwGEuKnzyGWi0xgndZoRm3bF4mhyR8OrHFC6uxF7+jHoLidXsIQuYfjCrL?=
 =?us-ascii?Q?XNSDuQyKHH/v3eu7Oz61QYxGF+utN0GPPO0qP8RbCuaKpk1XNIPViiJcCknS?=
 =?us-ascii?Q?/ugAtf4GkM2KbHGyLxyevcINETvJhBFJrjhgE/efUrMRxsfTQMPgswyIpR5G?=
 =?us-ascii?Q?5k01DFJoDo903HZinMsl8PM7jG4GWhIhNysYIQYsR2DoXxlJeDEw2x5gI2Ff?=
 =?us-ascii?Q?Ng=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 5346d774-6982-4714-fe67-08dd2fb2a175
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Jan 2025 07:04:01.7744
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: lDiGfYN3vS81hNBPRH1I7D7I2A7QOqB+UQAOGaASUfnlaNLnczTlZ69sURkLxPLnhtgQFarhW6C5LaTQt6FdHg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR11MB5879
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lYIFz7qZ;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 198.175.65.17 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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


we found the new added test kmalloc_track_caller_oob_right randomly failed
(10 out of 30 runs) which seems due to below (1)

1857099c18e16a72 3738290bfc99606787f515a4590
---------------- ---------------------------
       fail:runs  %reproduction    fail:runs
           |             |             |
           :30          33%          10:30    kunit.kasan.fail
           :30          33%          10:30    dmesg.BUG:KFENCE:memory_corruption_in_kmalloc_track_caller_oob_right <-- (1)

below are details.


kernel test robot noticed "kunit.kasan.fail" on:

commit: 3738290bfc99606787f515a4590ad38dc4f79ca4 ("kasan: add kunit tests for kmalloc_track_caller, kmalloc_node_track_caller")
https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master

[test failed on linus/master      0bc21e701a6ffacfdde7f04f87d664d82e8a13bf]
[test failed on linux-next/master 8155b4ef3466f0e289e8fcc9e6e62f3f4dceeac2]

in testcase: kunit
version: 
with following parameters:

	group: group-03



config: x86_64-rhel-9.4-kunit
compiler: gcc-12
test machine: 8 threads 1 sockets Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz (Kaby Lake) with 32G memory

(please refer to attached dmesg/kmsg for entire log/backtrace)




If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202501081209.b7d8b735-lkp@intel.com



[  117.724741]     ok 3 kmalloc_node_oob_right
[  117.724849] ==================================================================
[  117.737591] BUG: KASAN: slab-out-of-bounds in kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
[  117.747467] Write of size 1 at addr ffff888165906078 by task kunit_try_catch/3613

[  117.757782] CPU: 7 UID: 0 PID: 3613 Comm: kunit_try_catch Tainted: G    B   W        N 6.12.0-rc6-00221-g3738290bfc99 #1
[  117.769291] Tainted: [B]=BAD_PAGE, [W]=WARN, [N]=TEST
[  117.775007] Hardware name: Dell Inc. OptiPlex 7050/062KRH, BIOS 1.2.0 12/22/2016
[  117.783056] Call Trace:
[  117.786185]  <TASK>
[  117.788966]  dump_stack_lvl+0x4f/0x70
[  117.793307]  print_address_description.constprop.0+0x2c/0x3a0
[  117.799721]  ? kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
[  117.806918]  print_report+0xb9/0x280
[  117.811183]  ? kasan_addr_to_slab+0x9/0x90
[  117.815961]  ? kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
[  117.823154]  kasan_report+0xcb/0x100
[  117.827408]  ? kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
[  117.834602]  kmalloc_track_caller_oob_right+0x4ca/0x530 [kasan_test]
[  117.841626]  ? __pfx_kmalloc_track_caller_oob_right+0x10/0x10 [kasan_test]
[  117.849166]  ? __schedule+0x716/0x15e0
[  117.853589]  ? ktime_get_ts64+0x7f/0x240
[  117.858186]  kunit_try_run_case+0x173/0x440
[  117.863043]  ? try_to_wake_up+0x913/0x1580
[  117.867813]  ? __pfx_kunit_try_run_case+0x10/0x10
[  117.873187]  ? __pfx__raw_spin_lock_irqsave+0x10/0x10
[  117.878915]  ? set_cpus_allowed_ptr+0x81/0xb0
[  117.883956]  ? __pfx_set_cpus_allowed_ptr+0x10/0x10
[  117.889502]  ? __pfx_kunit_try_run_case+0x10/0x10
[  117.894876]  ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10
[  117.901633]  kunit_generic_run_threadfn_adapter+0x79/0xe0
[  117.907698]  kthread+0x2d4/0x3c0
[  117.911604]  ? __pfx_kthread+0x10/0x10
[  117.916032]  ret_from_fork+0x2d/0x70
[  117.920291]  ? __pfx_kthread+0x10/0x10
[  117.924718]  ret_from_fork_asm+0x1a/0x30
[  117.929324]  </TASK>

[  117.934373] Allocated by task 3613:
[  117.938544]  kasan_save_stack+0x1c/0x40
[  117.943062]  kasan_save_track+0x10/0x30
[  117.947574]  __kasan_kmalloc+0xa6/0xb0
[  117.951998]  __kmalloc_node_track_caller_noprof+0x1bd/0x470
[  117.958239]  kmalloc_track_caller_oob_right+0x8c/0x530 [kasan_test]
[  117.965176]  kunit_try_run_case+0x173/0x440
[  117.970031]  kunit_generic_run_threadfn_adapter+0x79/0xe0
[  117.976097]  kthread+0x2d4/0x3c0
[  117.980000]  ret_from_fork+0x2d/0x70
[  117.984251]  ret_from_fork_asm+0x1a/0x30

[  117.991022] The buggy address belongs to the object at ffff888165906000
                which belongs to the cache kmalloc-128 of size 128
[  118.004873] The buggy address is located 0 bytes to the right of
                allocated 120-byte region [ffff888165906000, ffff888165906078)

[  118.021331] The buggy address belongs to the physical page:
[  118.027566] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x165906
[  118.036221] head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
[  118.044530] ksm flags: 0x17ffffc0000040(head|node=0|zone=2|lastcpupid=0x1fffff)
[  118.052494] page_type: f5(slab)
[  118.056314] raw: 0017ffffc0000040 ffff888100042a00 ffffea00202bd080 0000000000000003
[  118.064708] raw: 0000000000000000 0000000080200020 00000001f5000000 0000000000000000
[  118.073102] head: 0017ffffc0000040 ffff888100042a00 ffffea00202bd080 0000000000000003
[  118.081581] head: 0000000000000000 0000000080200020 00000001f5000000 0000000000000000
[  118.090061] head: 0017ffffc0000001 ffffea0005964181 ffffffffffffffff 0000000000000000
[  118.098541] head: 0000000000000002 0000000000000000 00000000ffffffff 0000000000000000
[  118.107021] page dumped because: kasan: bad access detected

[  118.115431] Memory state around the buggy address:
[  118.120904]  ffff888165905f00: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[  118.128782]  ffff888165905f80: fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc fc
[  118.136658] >ffff888165906000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fc
[  118.144535]                                                                 ^
[  118.152323]  ffff888165906080: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  118.160211]  ffff888165906100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fc fc
[  118.168100] ==================================================================
[  118.176059]     # kmalloc_track_caller_oob_right: EXPECTATION FAILED at mm/kasan/kasan_test_c.c:243
                   KASAN failure expected in "ptr[size] = 'y'", but none occurred
[  118.176103] ==================================================================
[  118.201544] BUG: KFENCE: memory corruption in kmalloc_track_caller_oob_right+0x27b/0x530 [kasan_test]

[  118.213582] Corrupted memory at 0x00000000e59a4b3f [ ! . . . . . . . . . . . . . . . ] (in kfence-#20):
[  118.223645]  kmalloc_track_caller_oob_right+0x27b/0x530 [kasan_test]
[  118.230667]  kunit_try_run_case+0x173/0x440
[  118.235525]  kunit_generic_run_threadfn_adapter+0x79/0xe0
[  118.241590]  kthread+0x2d4/0x3c0
[  118.245497]  ret_from_fork+0x2d/0x70
[  118.249748]  ret_from_fork_asm+0x1a/0x30

[  118.256520] kfence-#20: 0x0000000036299d7e-0x000000000c1813d3, size=120, cache=kmalloc-128

[  118.267597] allocated by task 3613 on cpu 7 at 118.176015s (0.091581s ago):
[  118.275220]  kmalloc_track_caller_oob_right+0x190/0x530 [kasan_test]
[  118.282241]  kunit_try_run_case+0x173/0x440
[  118.287100]  kunit_generic_run_threadfn_adapter+0x79/0xe0
[  118.293166]  kthread+0x2d4/0x3c0
[  118.297071]  ret_from_fork+0x2d/0x70
[  118.301322]  ret_from_fork_asm+0x1a/0x30

[  118.308107] freed by task 3613 on cpu 7 at 118.176094s (0.132012s ago):
[  118.315381]  kmalloc_track_caller_oob_right+0x27b/0x530 [kasan_test]
[  118.322403]  kunit_try_run_case+0x173/0x440
[  118.327260]  kunit_generic_run_threadfn_adapter+0x79/0xe0
[  118.333327]  kthread+0x2d4/0x3c0
[  118.337233]  ret_from_fork+0x2d/0x70
[  118.341482]  ret_from_fork_asm+0x1a/0x30

[  118.348258] CPU: 7 UID: 0 PID: 3613 Comm: kunit_try_catch Tainted: G    B   W        N 6.12.0-rc6-00221-g3738290bfc99 #1
[  118.359770] Tainted: [B]=BAD_PAGE, [W]=WARN, [N]=TEST
[  118.365490] Hardware name: Dell Inc. OptiPlex 7050/062KRH, BIOS 1.2.0 12/22/2016
[  118.373542] ==================================================================
[  118.381677]     not ok 4 kmalloc_track_caller_oob_right
[  118.381777] ==================================================================

...

[  183.260210]     ok 75 copy_user_test_oob
[  183.279934] # kasan: pass:50 fail:1 skip:24 total:75
[  183.284696] # Totals: pass:50 fail:1 skip:24 total:75
[  183.290383] not ok 1 kasan




The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20250108/202501081209.b7d8b735-lkp@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202501081209.b7d8b735-lkp%40intel.com.
