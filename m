Return-Path: <kasan-dev+bncBCP6VKGCU4PBBCUO2LCAMGQEX5JT4YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 296D1B1D633
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 12:59:24 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3e513686df6sf8824105ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 03:59:24 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754564362; x=1755169162; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U20zlkXY0o11e6OHlMM1GqdMdM5A2chgYugWcAuU73s=;
        b=vDSbWM/i9jUd5dV1Q53zwUfwLEE5LIali6imNElpnSD2X1j+GDqiR1TaBLrWnlVuxx
         HGUFmSFxXGjYa6daZERjZyFUYxj7bbNUMWjvB1g+qHLvAv0Q01s5QzlzlwjsO/d+rZvY
         m2y8yk9a+7BUi7SlhiKrIjfaPttPJada/jnTSitSLvmyA5blIYNHnDhdFMrJQHNAV8Js
         /4EIA75ts2JTVK7mz8czVO0iMNyFetEpGJcW9xPoPObV1uUavenFzcEKTNRfvBqzOMFK
         GJ5ZuRqkmpr1lJxoJRhNqijykXw7i+EYW0Vu+TTcElfykQllQ0LRoMxNon2Oy6OLsCRX
         /IJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754564362; x=1755169162;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=U20zlkXY0o11e6OHlMM1GqdMdM5A2chgYugWcAuU73s=;
        b=JcazofqHKd4kRbQr8WndGkLojgPjVJ95N5hzNKzlEo1AVuPmQgCEBuh+yZa3mIaRk5
         TdaYBU7epbVUHiCHRLxJEl8TkSzWD8eBhPn9/d1SHhJGzNyFX9vXxNfKZOSBp5Il8c9h
         oWj2P8CP09s2vO/jQIsItwdsqIvv9IWqOJyptJP7CBaa5Skpyik+ycAi6jqphKWEuK/o
         z1HGEbzg70g3Fj5C+98zeKsTm3+rduq/UcbgpcmiTuaKD+Lwapln7WsdwtgfPGsR84aI
         6pnt5EEEQXICTErzJ3ZmBTSOn8ngA9+5nrZW8ZzBFbh+KoM68Ofcx+qI5WTbnAw0iWVq
         qsOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVJxoP8a+mtvVbt10Lj8QdKE36FTNvuOAx0/tFDiibdt5aN5Rl15P9FHjaozh4XRlXs1W9frg==@lfdr.de
X-Gm-Message-State: AOJu0YwO0SQLqIjQa/pzLxTOKjjBn9BYpyGATGgOXMiAAyie8r7rdenz
	OrvoJ475UzOlG10UiYTcJH8xsyUyyWjsoiy+EiOsTljBOAMEpBmVUAgs
X-Google-Smtp-Source: AGHT+IF21A0TV1mOwCqFkk9Cx9MAF5oXqU1QYf98UpD6ZvVlXQOGOPuB0cZa36+nsW5vzJtfBPlPMw==
X-Received: by 2002:a05:6e02:1486:b0:3e3:fff9:eb1f with SMTP id e9e14a558f8ab-3e52494219fmr50954815ab.2.1754564362517;
        Thu, 07 Aug 2025 03:59:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfaotxdvZZPcQxnOELBfipFERzZSJyi0aHoMhUD1gwEJA==
Received: by 2002:a05:6e02:16cd:b0:3e2:b5c4:3547 with SMTP id
 e9e14a558f8ab-3e519ed7a5fls7395865ab.2.-pod-prod-00-us-canary; Thu, 07 Aug
 2025 03:59:21 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUo3aaFgLvn4LlXLRVYDwulky1WGqRfM9uspYIsNhMFq6DCuqY8bNP9UqDi8P/ko32JFzLLvlqPTrw=@googlegroups.com
X-Received: by 2002:a05:6602:7192:b0:883:ee57:93b7 with SMTP id ca18e2360f4ac-883ee579647mr47392139f.0.1754564361519;
        Thu, 07 Aug 2025 03:59:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754564361; cv=fail;
        d=google.com; s=arc-20240605;
        b=LbbHcjJpug0jOCY+oTKIt0Tyi0W3NINxsaRxzLsWzLDZSixf8PXSKpr60+uE427LXp
         L9vL5jyK5YAkAzEEILndQHd0dAzzJSFWhon/DwOhPR13B53aQ1cmyN0YW4z9PLh8ItD+
         aOSQIUi0yERq0UtUuPXWVcrkLqSgUPj48QzF1kyT85lWTthmqQbfnY0eBxsnoeTRIdPZ
         KVttwzdC1QX/tYQX+j1FJKIl4ReIF7WvYS8Py3I10B3TAYlHGAX1xo/vLzl2k2PmKmyy
         8mvFcFil1IHr2oudL77yQBa6BqIUrirOnh7tVVaq/raYljJz3P2UcaosjqJTpHvUNwhi
         5b1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2cbMFjssxH+imX+ya2QAq+NHPT3Hnq8occ54QjxvUY8=;
        fh=6MjbF69sOZburWtMS2ovpd/IS8Ls5AjNjdseBax6aOg=;
        b=ChOoOtZjQyDORvIL9kRgj2J4g/BWcio4ISBklvotDTfeYziyT/IwuGW+IxoBJfdsir
         +7zvjuKrmmff7FIwFmPUEJmr55iOIqZ5xLfKxCsJs1S2DscJfaNafou386eUwkucg1pY
         hUJ6W8wKIDUHZP+o0a/+pRT1t+APXJdoRI3nluv5jmB3KOHpwAPeSGxTFOs68C+gVnD6
         ujPLqAnQc+esBYAX6VA2meVV4zZT0YI5dxTSJXQ4vqOMutkWVcAfydXStKz21TEZyHHN
         0f85UAGUSDlDRBLKN7Fc0CqGY3Ejl7X/JVisiN1lwSZ8Dp0WGCj6imAeSiKRq/8P4I9D
         FqZg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fsjqsOAu;
       arc=fail (signature failed);
       spf=pass (google.com: domain of lucas.demarchi@intel.com designates 192.198.163.15 as permitted sender) smtp.mailfrom=lucas.demarchi@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.15])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ac064784bsi200308173.0.2025.08.07.03.59.20
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 07 Aug 2025 03:59:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of lucas.demarchi@intel.com designates 192.198.163.15 as permitted sender) client-ip=192.198.163.15;
X-CSE-ConnectionGUID: 5yJquCu7R5iLjOebzi++Tg==
X-CSE-MsgGUID: VREmHU9FRvCFXWK1w2v+FA==
X-IronPort-AV: E=McAfee;i="6800,10657,11514"; a="57028524"
X-IronPort-AV: E=Sophos;i="6.17,271,1747724400"; 
   d="scan'208";a="57028524"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by fmvoesa109.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2025 03:59:20 -0700
X-CSE-ConnectionGUID: Hija4Tn9TveGMThphlcGVA==
X-CSE-MsgGUID: TAASDUKiQfqQUyGODuu2Dw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,271,1747724400"; 
   d="scan'208";a="165040540"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by orviesa007.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2025 03:59:20 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1748.26; Thu, 7 Aug 2025 03:59:19 -0700
Received: from ORSEDG901.ED.cps.intel.com (10.7.248.11) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1748.26 via Frontend Transport; Thu, 7 Aug 2025 03:59:19 -0700
Received: from NAM04-MW2-obe.outbound.protection.outlook.com (40.107.101.89)
 by edgegateway.intel.com (134.134.137.111) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1748.26; Thu, 7 Aug 2025 03:59:19 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=rh5PIMn+FR8uX845jZuWI0FGxebFNiVdXCmZ6htNpJsvJER7bMvTf2fsMIcYdvH48Q18O/D5ShWhX2TmZvdh2irrGPCPgepye0sRe3xt/hZznBV81GAePF7S8NWzwWw2SoIz6/rV4u6wTco/3Y5TMy05LFRFSIwL47vcMLEqWls9XlbXzxhUZWVLb9ghgkTIIAmIYETOV3rK/Pcv/NruA4II7Y/z62G+auSzv6Iv1WtAFCFAr4GMVUZQr0QFdiTq2SZy3jYjWWrItSsUOMv3E+yvBZFJehDAfcPOzjx5B4bRucapIy6wmCTkrUSB8lrm2RXGupgpjy0Phi7jeR0swA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2cbMFjssxH+imX+ya2QAq+NHPT3Hnq8occ54QjxvUY8=;
 b=jDtdo540MdmCZNZf9QlwEj+7ssKC4P1dcGvUSDN4lMq0LquyVaruRSP42zwjUvxA/fl5xBsfV41kSWmBz9gtEnpc2f4RRH5B2x8N3YKpPH2nNNmn31XQfYnHgCx/Qh0JvlvJboAhuokHZBqMu9/RDDxeZM17Vi5hKB5OCeREcCakK5xSjc89e9E1EHjykanzojVswWHpsBj4TEVgkz2yavO9OzEMtDtE+IWJ9afkFet6wpIl/FHhYgTH2IxeZh4d4LTz/8Fr/DrKLwmPYdQbY9twD54P6De7PsWMhN53DuGsoK1lwniiSTqqWt37OaKlcDRpp5Wvr8Q1q2E3jZZPAg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from CY5PR11MB6139.namprd11.prod.outlook.com (2603:10b6:930:29::17)
 by IA1PR11MB7891.namprd11.prod.outlook.com (2603:10b6:208:3fa::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.15; Thu, 7 Aug
 2025 10:59:17 +0000
Received: from CY5PR11MB6139.namprd11.prod.outlook.com
 ([fe80::7141:316f:77a0:9c44]) by CY5PR11MB6139.namprd11.prod.outlook.com
 ([fe80::7141:316f:77a0:9c44%6]) with mapi id 15.20.9009.013; Thu, 7 Aug 2025
 10:59:16 +0000
Date: Thu, 7 Aug 2025 07:59:05 -0300
From: Lucas De Marchi <lucas.demarchi@intel.com>
To: David Gow <davidgow@google.com>
CC: Marie Zhussupova <marievic@google.com>, <rmoar@google.com>,
	<shuah@kernel.org>, <brendan.higgins@linux.dev>, <elver@google.com>,
	<dvyukov@google.com>, <thomas.hellstrom@linux.intel.com>,
	<rodrigo.vivi@intel.com>, <linux-kselftest@vger.kernel.org>,
	<kunit-dev@googlegroups.com>, <kasan-dev@googlegroups.com>,
	<intel-xe@lists.freedesktop.org>, <dri-devel@lists.freedesktop.org>,
	<linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 5/9] drm/xe: Update parameter generator to new signature
Message-ID: <zlgn7ymjtd4avnvccye55wongm5jz6oylzarmwuoqjxy4yeozi@cfly2cafnml2>
References: <20250729193647.3410634-1-marievic@google.com>
 <20250729193647.3410634-6-marievic@google.com>
 <CABVgOSmTNAOoLqLhsZq+RiBU3wj4s79hzV+WFEOS10sahZf6Mg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Disposition: inline
In-Reply-To: <CABVgOSmTNAOoLqLhsZq+RiBU3wj4s79hzV+WFEOS10sahZf6Mg@mail.gmail.com>
X-ClientProxiedBy: SJ0PR03CA0024.namprd03.prod.outlook.com
 (2603:10b6:a03:33a::29) To CY5PR11MB6139.namprd11.prod.outlook.com
 (2603:10b6:930:29::17)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CY5PR11MB6139:EE_|IA1PR11MB7891:EE_
X-MS-Office365-Filtering-Correlation-Id: 48604c28-86a4-477a-1256-08ddd5a173cc
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?PW41XaNyos0MuF/AMO54JKe7CTCCrDsO5VNnbp3FBKWZZ8YGDYtteidnS5Bb?=
 =?us-ascii?Q?G6EL3BYRdsrT/lNWJem5VU2W2Dutw1aFlMue63wefTBzPQysyMwo3s6/6qF4?=
 =?us-ascii?Q?8S+fCtv5K76aHkxaw6oipwidRr3t/Y97tM8DjCgCABOwdNjQ429OBAkXdc+f?=
 =?us-ascii?Q?aCSX52EOsNlzr4VB8fOA0UrKXfo5CRXHUELWfcnnpIwm9Mas/a9Hbf4vU7aF?=
 =?us-ascii?Q?J/lbHmrpPRLi9y5HgJAYviyu47qnmoj1bOex7dg5MEb+6qn1jf1xZlJkfWOm?=
 =?us-ascii?Q?gWQ8Cn3byC0lrqzJlHgUll0E3oi87XwS0JiW/9i+TGPo3gbXSEiPd/dYC5J7?=
 =?us-ascii?Q?+OjRVIwM0Ou8haHHMvvzkzedQPhkq6A9juB50Z7QxFputAq5qnkeJInuejMm?=
 =?us-ascii?Q?KtQA9xZbpceXuGwZyVDdVZw/E0OdC5HWZ4wzoV3CyELj4muVsOKrEIojeVgF?=
 =?us-ascii?Q?qJdfMlugNaYfDgOpHCL0CUZDI8Yj8AfuCjmmXi+g0MfoUnNc+u2q64oHtTzq?=
 =?us-ascii?Q?3tBUDa0V+RKefHkM8NpUK3AbfnaXqQ3LGZk4nZ9NOvrg7G+kftMSsMfQC/yN?=
 =?us-ascii?Q?fV+RZdLLHJX6eIcGusJOvWUNaHtfAM/FeLyOQcvDLq7gvKbY5sNXGv+j0ABd?=
 =?us-ascii?Q?VNbSRoqY7GRTe9N7s00YkPGJUjIDYaQjO4T8hKem9oTq9HUM3w5cENb9Gi1S?=
 =?us-ascii?Q?OfVE3H39YuT9JFP9Qzij1ZYjDT0sInWxBxe8QkvchqRNYndmjuNzqUyFET81?=
 =?us-ascii?Q?eIgF7j8Ani9jko1DCo/WU1m1yIPTgdVxyu5z3ea5asbrcLUsdOHP2bsuyiuV?=
 =?us-ascii?Q?s40ItqeMatRmrQxQoodMHuUP4/NvzS+zuDpOH5fEnQSMARY4O4fXJkF2OYGN?=
 =?us-ascii?Q?tdb0Thj2vEHcvNX8jXk+ZduLRZMBAjZ7Vr8f7pTIcbjwrusd45NneDRNigPp?=
 =?us-ascii?Q?LFqHD+BpzkVlq6InN0qLATrhSjSIv1R/JGmdqmKNw832f3jVsJXvViBt99HJ?=
 =?us-ascii?Q?wRlFa8or2TMfJuwzdGkolT/OlpCADEWX45YHVE32rpzP1P7MHufz8gzEPLNk?=
 =?us-ascii?Q?xyNZ0uFj8SJuCBLFzwtWutPgqVr0ptxSvnZJgeyN1e0kHFMGWCIqAZHuxgjQ?=
 =?us-ascii?Q?0P9G+a0v2YTvWJ1M+GlthoIy0l/DmoKvjw7gfANFj1DZdSxEAIPbx3dFZpdl?=
 =?us-ascii?Q?SKmqcQbJCBmdAB09ZyqdAKE9sEq6XGa9dMh3jDZk9q2RyCW+byNci25WEMo6?=
 =?us-ascii?Q?V0xYUT4pqIfCnBzgCT9ELNwfEoPm2MGUQA6N4DBavqZQdtzv6521gIe1xWch?=
 =?us-ascii?Q?afRMijS4YjIzU7WnQYJtcrywzDW+zaj0EDBsWzmizScVsAdl5P3Ywc5MvO2E?=
 =?us-ascii?Q?pb8ykLpBhQEnvWy5qhgwhCtz7rGMNd8eQrz1ZMiaVww/EIUEQcmiMMlVfI0E?=
 =?us-ascii?Q?dN9TnIKFP2k=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CY5PR11MB6139.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?VqQCfoK/+FKACo0DfZeeV0zgcD2CZMygXtStUoenBGQ8x7aXE2XjWmsH3xy1?=
 =?us-ascii?Q?NGYKHCMrzqkO4ZdGqvcQG5B+nDn6AiAGEQcLdrLkM5e3VloFoZa3m4c8LM1Q?=
 =?us-ascii?Q?XRjDB4Pw10BPiz3GCZ2PqrHPZYAtqwInIdUQd2EWJW+OigALEshfwboeXe4E?=
 =?us-ascii?Q?ZbwFjbLm8MT0pOO9jBT/Is6RBVcXvHdAM1gW1F52HyaI6pUHHv8odTbH36Js?=
 =?us-ascii?Q?JvcTDPqXhV34tMDXtALUEBA0CJgMn04xiuMVCD1/1pU3fUCRSkB3EQoEa7Uk?=
 =?us-ascii?Q?ZxanLude4OhSZqj+syfYCSm54p98pW/lZAixc2jkwIxiWQ0XiiFmZQPvRByQ?=
 =?us-ascii?Q?D6L4U8pbbA0H+iLk8b09AX6mXxQkDddzJVKpZwhvAH+K3jhtgVNHT+zPjgCZ?=
 =?us-ascii?Q?uMmV0o52NIugHrur9GmTh/cdAhGIQxSvmmCYkUrJmbILQrsU17NQrv3Pg70j?=
 =?us-ascii?Q?zuvwQQ1R6eJQ3TL3eK+GXJAGJhyeY4T1B9jrzmcA2fVKZXKTp92/qzyFZRsC?=
 =?us-ascii?Q?BELTUF1E01OU0jX8llbvhGjtBkeDCQxMN9iSYSfuYIo/NxUmOmFAbGlMf8uK?=
 =?us-ascii?Q?Fcu2J/5HiYRnIq4jeDgD7i4B9Lic9S0xW/x+oeV7u7htyIqXGUWA+8cTMhe5?=
 =?us-ascii?Q?ekJelppks/GVNzdj5OfjQ2AXpJoN7/hR5sUIQefzHolHTi3mWmvZRtJkjtFq?=
 =?us-ascii?Q?K8sFqqKuyJ+dcVS2uSvVRNqWkGJrGZzcoQnfFm5WpHqWKYjijyxNs+hJgjYv?=
 =?us-ascii?Q?+KMxIKa6NfLCcA8WO0VzDqwvnu4gMnyldxTTDC0GD2jE/rsFXhvS3t/goHC9?=
 =?us-ascii?Q?7kRzRGd+U45kCraR0VoFYESB2T4iGEfhwScgrVKp8TMttuuFOzDDaqO0bZYJ?=
 =?us-ascii?Q?+0IeR2Dfu/1sMRe9j+vzm8MI6hl70o8V037R4GxKFLtTwxw/nXbQRR0sqMD3?=
 =?us-ascii?Q?5lnsFqjVZQTCOyi7yhYM7alpSzar02qG2v3CFJ0+xHlUGDaG3YO4HQ+Beb7b?=
 =?us-ascii?Q?WnZ9+E8781FESWMZEeZMWNtSBnsYK8gNx6jZHnnDXzP6mCnWQsoPH1sWOyNZ?=
 =?us-ascii?Q?EVSLYp43YRKmrIt/wATg3NPLSDzXC34jciLJZlkLnNMELqlPkOBZN4mt/WYQ?=
 =?us-ascii?Q?jfJt0j9/nuZ1inG93RpE2PcxrQk4IpqL0MWYPPLnjJlLbL4av9xyKStGLP7/?=
 =?us-ascii?Q?uzwHNwkQvTjswA7j5L/xVfeKHlDgzbNiRJcADUuMAk9THgUs4RuaFugEPFml?=
 =?us-ascii?Q?5HGbb9wrLbv6uRCo4hXsBrb58Ix/hosNjjmDYTK+HbB2BpqyY1is9/FJKYku?=
 =?us-ascii?Q?claLhSOISTIDFOvTpHE+eXWi/gKf5uaILtOnD4a9FraiuAyIqUbEQ/39tCJI?=
 =?us-ascii?Q?QZX1j1WqIJqKxdn56lCNF0py+LK9+qQoFk//YB1MFjeAze3jeHtOiay9P1he?=
 =?us-ascii?Q?RiSpG9rCaX3+qF3jMxcIB8wCJ/osvRb/rwINq8kpJMn0wJDEDoRS4FE02IeR?=
 =?us-ascii?Q?GvdbYRlE3Co/1fe356xrmgGfaZAgc42IgE2TGOncu7K3CDhWnYf4vLar0sQm?=
 =?us-ascii?Q?7V7GSGEbDQU8+H8ytB+81wXI8hm6HHJd2E81CEIwUQEoBh9p1pXP0A9p3K5K?=
 =?us-ascii?Q?lg=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 48604c28-86a4-477a-1256-08ddd5a173cc
X-MS-Exchange-CrossTenant-AuthSource: CY5PR11MB6139.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2025 10:59:16.8676
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: TI0dHebFaOxHU611vKq6Nd0ey0Rd53VcsOHYKHcYihUazClTXo0zWtfO9y+AP8qHChNF2LtGvrJCFgMYfLVjErya3yfC+F1zdnAPJfpQVJI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB7891
X-OriginatorOrg: intel.com
X-Original-Sender: lucas.demarchi@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=fsjqsOAu;       arc=fail
 (signature failed);       spf=pass (google.com: domain of lucas.demarchi@intel.com
 designates 192.198.163.15 as permitted sender) smtp.mailfrom=lucas.demarchi@intel.com;
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

On Sat, Aug 02, 2025 at 05:44:48PM +0800, David Gow wrote:
>On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
>>
>> This patch modifies `xe_pci_live_device_gen_param`
>> in xe_pci.c to accept an additional `struct kunit *test`
>> argument.
>>
>> Signed-off-by: Marie Zhussupova <marievic@google.com>
>> ---
>
>
>This is a pretty straightforward fix after patch 3. xe folks, would
>you prefer this kept as a separate patch, or squashed into patch 3
>(which changed the function signature)?

I don't like the breakage. Squashing would be much preferred.

thanks
Lucas De Marchi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/zlgn7ymjtd4avnvccye55wongm5jz6oylzarmwuoqjxy4yeozi%40cfly2cafnml2.
