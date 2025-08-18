Return-Path: <kasan-dev+bncBCMMDDFSWYCBBTMBRPCQMGQEOAWFMZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id AA314B2993B
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 07:57:35 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30ccec4380esf1982466fac.3
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Aug 2025 22:57:35 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755496654; x=1756101454; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M7xJiE3kHNwcykU1uquPV498iBuaiMUumfYM4h+Egbc=;
        b=FmIyYr8cVCDkSHD30SkSEwDCJ6YZ6XRsn7fXizTT/d9dJjE/5wYsn4+IusQMbC/Jgv
         eDcTtcZ0U3KvFLxXQrcPAJz6/tEzRwVLQqQQf9qIOyD9v2hh/elY3zFyCNVC6bEK6806
         oKqvKzyuhL2ah629YGmyAFCQ4eBzwrvodEJauV9j66vizaGAFOCtBjiAg/TJ1hMiX8EX
         R5Gl9ZXrfOrJ8kNJtHfm0Q2SIBdqNJAWgHNODLvA/DQJneEXEG6X+e0y+Nci23uXAv5+
         MQ3AmE797imxGEanBou9c1pK2KUqY3SqnqojK2GUnmmS5F05LY7096yBiLQUB1IDVNef
         e3qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755496654; x=1756101454;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M7xJiE3kHNwcykU1uquPV498iBuaiMUumfYM4h+Egbc=;
        b=e6/2hzg7UZ3c0KM3BhIOogJaG8rLgErJctJeXTV3OxGi27zkq2r5pKAcy/SxmFicns
         JyWnQEsgACLgU3O0WPYQgWEXI2H7EvDdNA8igqtdP5mpwEqkXFIYKRCAPfkU7R4hl+R4
         fCEGmjXxjStf/rx9YmUlsaaRFQVsTLKNQSPuKCma4iykyJf7+sankSP1TolWWq3rHlkQ
         1S9UHNdwKXbDOPyD/Ta2Eu8vOeFt7sJ/bGq0M4ot4u9wIcdLrB5cpRXMm3m57fZ/hucy
         EqJuKjZgmYCMgeBJqmm6HWlxXVo6ggWr33TsFm885A53AUIAfV4hTllXJIjBMgyvUBX6
         70GA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWSGM4s+griCTCu/NkRXtzGTdJKeiOK4HwoqfNNUQ5JwDGZLYuMMFJiAHeQmPm7jWQIRySPXg==@lfdr.de
X-Gm-Message-State: AOJu0YxVNMWC8SAlqmi4TUvjBp68E3KGL9YPw/grYXeym3mhi3f+MVgn
	o+2M8bGpMzPOha4WWoNesJD85Ph8DpQJiMlg0SLyclX5MVjkL8Fj11HJ
X-Google-Smtp-Source: AGHT+IGLJANRZgyrp/s3ZaMMJWYnfo8+/Km8RuhzHuMy6RmhT47+TYtRVBHNux9Lm7FVVgtCXj3bXw==
X-Received: by 2002:a05:6871:d209:b0:2d6:72a4:adfa with SMTP id 586e51a60fabf-310be681684mr4384837fac.30.1755496654135;
        Sun, 17 Aug 2025 22:57:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7vxeuB+V8dxcxfpUKiUTcENvfDuKd0K+yPJXj3nB4ng==
Received: by 2002:a05:6871:4b0e:b0:30b:7ec0:8afb with SMTP id
 586e51a60fabf-30cce448836ls1248710fac.2.-pod-prod-04-us; Sun, 17 Aug 2025
 22:57:33 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXqERjCLluqG1UoQyQRao/43II5LfSgX9/4O5/aPsPIS7Id1hayJZlXeHU8RPmRODCL/PyDUKdVtx0=@googlegroups.com
X-Received: by 2002:a05:6808:2f12:b0:435:f544:a726 with SMTP id 5614622812f47-435f5ec15cfmr4130296b6e.27.1755496653295;
        Sun, 17 Aug 2025 22:57:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755496653; cv=fail;
        d=google.com; s=arc-20240605;
        b=RiQAOVqvd5kXilV5yy9H3rDQkBeJWyfgmedCCGnNm5AsYgBKWuoc4ce9eN61YALG37
         mK5qumLs+cYivX38MDVyjQJjANPEmMb4hn0b4bv6eN+E4PSdVv2DhWltPXoEsYUyfJpp
         gF1xfp3m1mdpiFyMQvxhNX0zMsUElOHBk8jLKxhMyiDkqHZgbzNbfsY55EBrTQRd5zjO
         i6IIylz5LsoLAbzK1GUVpvbI+pJxfX3LhYElGjmJwe4DfFBpml7yGUlrCT1cwGOpsQA/
         mZD0zMQQ5CTf/Rth3PQCY+aKUUEII5pEJcUEH+ugJAPSt0+KqNDV2eANOFodcnhmj/k3
         vp9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Y8C+rAfm7Xa7znY6lyJ86Q8G+lk1DZ/tGnAfaEtMne0=;
        fh=YfqbzSvxCVez2ZmyEqIWPhXY5CaBVAP7tZRZgm6t27s=;
        b=J0pEGT1f2hDntH7B7oXtKvwr+8tnb725VvLK/sRKsA6G1/HBZQc7cQhYCC7RnWqXDe
         opZNvF6DPFLcjoO+TomECsN4TXmcMmTUAn4wUkLEoRlBnCIOB7Rxsi6iUeER59uA7x/N
         T+qjM+BGbfHiQF9R/jprTj7qb511eRPuo0RNZIYN8WqHupKcgoZGh+ZSWzggcmE/fRmQ
         J/XK6zxBbQr0roRfSVQ4FMoGzuCyINVOeUsuLTqyczqipepcriPrn7JEvtCiqcPOWhTZ
         EkvjyY860bI+YbyviQdKvPz9bbI92MHaPoaPBj1W68aj1Hi4yVSIGMphAj7smckUyQcU
         R8sw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=iKQz4QzX;
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.8 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.8])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310abb4abadsi347587fac.4.2025.08.17.22.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 17 Aug 2025 22:57:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.8 as permitted sender) client-ip=192.198.163.8;
X-CSE-ConnectionGUID: msRjF9CZS1qoKtcV/JII/Q==
X-CSE-MsgGUID: 7AHnNvFKTxOT+qHNB3nBbA==
X-IronPort-AV: E=McAfee;i="6800,10657,11524"; a="75282692"
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="75282692"
Received: from orviesa006.jf.intel.com ([10.64.159.146])
  by fmvoesa102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 22:57:30 -0700
X-CSE-ConnectionGUID: /ZSIT7KpQ0W1EXAcknh0kQ==
X-CSE-MsgGUID: heEV1Z6fSs22ztalyybHpw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="166669949"
Received: from fmsmsx901.amr.corp.intel.com ([10.18.126.90])
  by orviesa006.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 22:57:30 -0700
Received: from FMSMSX901.amr.corp.intel.com (10.18.126.90) by
 fmsmsx901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Sun, 17 Aug 2025 22:57:28 -0700
Received: from fmsedg901.ED.cps.intel.com (10.1.192.143) by
 FMSMSX901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Sun, 17 Aug 2025 22:57:28 -0700
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (40.107.237.75)
 by edgegateway.intel.com (192.55.55.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Sun, 17 Aug 2025 22:57:28 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=L/RdhKucLW4EW/6PrtVG0vYugU06jNbgr4KRFWLoB2cZ4opd7cGR9x9Pv47hnXRc6Rp53lix66J4kfJp/AmnQTElrx5Y3hngh3MuN66lNgJJfboSUHGISJ1j+LXfMs1Yk4njNvcqHXM7slhZhrXHDzA+4UIMvYLFjvHDyFi9s7JcKkFJJHibWxmORO1Uv+a0I20skAIEGXV7F/qWW4IHa3Na8nUOOtLjjqyIFRPGGS9PE9BT8vk/QQ9sAV5oyOYanSmvIol6F9y+w7jzOWZn7suCquB0op01DNovld5sVedn6meBuJXMLP6+ph6qGNAjrVlG36rbgJJ6tG6CgrOc1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=REEKnY3wncogAIt7FK6ZHQqMPZbhrNvCqhekY94TJj4=;
 b=bITrOb9DFdo5dmcFgmLielZxqjIy6XGvTvBrb+F3OUQK/U7v9dD0rwIYiTih2tlDURtns3ruxXmwmDNJtmJWTq6YejVpR1pFRo2c8YPKjSlqpa7goScB5+vHWb5RJWfhBHhU+F4GgvkxeI3sygffni0VnF+BiZj0Yjf1df3AgFp3cPDJHxPPVfipKFgBfBS0+ljDEAQSUOtTJnPsGcDkf7HwpV+f3RnPRybfKIoD/37KbHHwEYzSCuaFS99LSfLnqgcBDYgwGWnYCcD4ynaEdveeDTnJ2V/uMOEIjkkB/VIKPxBdutEmW6cOsINpdqbEh5sjMdtwRxxu0M8Wy6kCTQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by CYYPR11MB8407.namprd11.prod.outlook.com (2603:10b6:930:c1::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.24; Mon, 18 Aug
 2025 05:57:25 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%6]) with mapi id 15.20.9031.023; Mon, 18 Aug 2025
 05:57:25 +0000
Date: Mon, 18 Aug 2025 07:57:08 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Ada Couprie Diaz <ada.coupriediaz@arm.com>
CC: <nathan@kernel.org>, <arnd@arndb.de>, <broonie@kernel.org>,
	<Liam.Howlett@oracle.com>, <urezki@gmail.com>, <will@kernel.org>,
	<kaleshsingh@google.com>, <rppt@kernel.org>, <leitao@debian.org>,
	<coxu@redhat.com>, <surenb@google.com>, <akpm@linux-foundation.org>,
	<luto@kernel.org>, <jpoimboe@kernel.org>, <changyuanl@google.com>,
	<hpa@zytor.com>, <dvyukov@google.com>, <kas@kernel.org>, <corbet@lwn.net>,
	<vincenzo.frascino@arm.com>, <smostafa@google.com>,
	<nick.desaulniers+lkml@gmail.com>, <morbo@google.com>,
	<andreyknvl@gmail.com>, <alexander.shishkin@linux.intel.com>,
	<thiago.bauermann@linaro.org>, <catalin.marinas@arm.com>,
	<ryabinin.a.a@gmail.com>, <jan.kiszka@siemens.com>, <jbohac@suse.cz>,
	<dan.j.williams@intel.com>, <joel.granados@kernel.org>, <baohua@kernel.org>,
	<kevin.brodsky@arm.com>, <nicolas.schier@linux.dev>, <pcc@google.com>,
	<andriy.shevchenko@linux.intel.com>, <wei.liu@kernel.org>, <bp@alien8.de>,
	<xin@zytor.com>, <pankaj.gupta@amd.com>, <vbabka@suse.cz>,
	<glider@google.com>, <jgross@suse.com>, <kees@kernel.org>,
	<jhubbard@nvidia.com>, <joey.gouly@arm.com>, <ardb@kernel.org>,
	<thuth@redhat.com>, <pasha.tatashin@soleen.com>,
	<kristina.martsenko@arm.com>, <bigeasy@linutronix.de>,
	<lorenzo.stoakes@oracle.com>, <jason.andryuk@amd.com>, <david@redhat.com>,
	<graf@amazon.com>, <wangkefeng.wang@huawei.com>, <ziy@nvidia.com>,
	<mark.rutland@arm.com>, <dave.hansen@linux.intel.com>,
	<samuel.holland@sifive.com>, <kbingham@kernel.org>,
	<trintaeoitogc@gmail.com>, <scott@os.amperecomputing.com>,
	<justinstitt@google.com>, <kuan-ying.lee@canonical.com>, <maz@kernel.org>,
	<tglx@linutronix.de>, <samitolvanen@google.com>, <mhocko@suse.com>,
	<nunodasneves@linux.microsoft.com>, <brgerst@gmail.com>,
	<willy@infradead.org>, <ubizjak@gmail.com>, <peterz@infradead.org>,
	<mingo@redhat.com>, <sohil.mehta@intel.com>, <linux-mm@kvack.org>,
	<linux-kbuild@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<x86@kernel.org>, <llvm@lists.linux.dev>, <kasan-dev@googlegroups.com>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 13/18] kasan: arm64: x86: Handle int3 for inline KASAN
 reports
Message-ID: <34sbzdtnh74bbkg6yopytxn553efynrjp3nylnx6hg4sgwsder@zff244djrxe2>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman@intel.com>
 <31bac00f-7903-46f7-a5a0-1e8f5fd8b9ab@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <31bac00f-7903-46f7-a5a0-1e8f5fd8b9ab@arm.com>
X-ClientProxiedBy: DB8PR06CA0010.eurprd06.prod.outlook.com
 (2603:10a6:10:100::23) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|CYYPR11MB8407:EE_
X-MS-Office365-Filtering-Correlation-Id: b2f05154-100f-46b6-fa36-08ddde1c1afc
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?Vy/fXl1E+gv+35Gi8jBzq+0ev/tEEHSUbDU7Y7D0SdTKreT/crZhkIDg0o?=
 =?iso-8859-1?Q?KBwwjhRarOho5M5E/Bw14p3vSJwdvOjvKmFCQClUmvmZn6UIrhPKk0Rfvs?=
 =?iso-8859-1?Q?uVLDwUNGMfS0oAw3LvuNANzXajUfmW5HzuSCVe2ZDvpgN2A7JA/H+dS7Kf?=
 =?iso-8859-1?Q?EnEAaXMOu0F6sHSpZPF2ZMVDVBnoF+wSp5JC9Q/n90WVfDazmA7nKgMqph?=
 =?iso-8859-1?Q?X2g0b9XjUOLnTs9NligskIfR6Y5FcLdA/Zj56bFlSWtLDo+67z2gKnc+L3?=
 =?iso-8859-1?Q?eOPB2bn15XUB6MicK6sErFRJZOCCCq/30wL1zZ4Vt3FTje3wyLr8e0WfEo?=
 =?iso-8859-1?Q?21fSJl2IvBd3jYjSNIFoB1ChjcHzAAwz8X3sNuDvn3Cy11Wx5/zE5UPg5Z?=
 =?iso-8859-1?Q?lsikxqJE2e+pzUFTWu+aO9VH7CjWnXYdYVngpmFHkrZbBDqf+Z5JHlRcgD?=
 =?iso-8859-1?Q?hBYz+TxtYR1QybLSB4jyQdNYNN6jWTUXpg9x2KOu3UMCIrcp8O7bKGpgqs?=
 =?iso-8859-1?Q?X2jsNSv5E/Tl9IWbzhLycBz/NUrX10HR3h+03DKVLsL7wlHCavDrmXUSk5?=
 =?iso-8859-1?Q?3tNLlpC13C/y5MfXtOuDCmw9I1cQYIwN2XDdzkfYKuwsBxpchtjfpFgLIW?=
 =?iso-8859-1?Q?hFgC8nutq+JIb8wSaQME8l8+lmbPRW6vDmLSZmkyVBHK93688Eb1cwmCVc?=
 =?iso-8859-1?Q?DxR3qEGOFuXC4cwK+x75Gdt18bpixcIdzcEcWVOUMmMIRN3rA7lFzSTWBX?=
 =?iso-8859-1?Q?VY8gXXvGoiw2Lt2mJeQdwooGTadynLFSVCSCF6FdVfJMZfIfYXCzz462l/?=
 =?iso-8859-1?Q?X2UJk/Hk05O4GQbkcnxSFHzaw+g3Ujbq43KE177kbzSusDtlDm+AkG4U0W?=
 =?iso-8859-1?Q?zdkJywT+WPS9AWCtMDX6BspnDrbYdH+HGHkM2XlV6gyFklcq6M4TnAptJ0?=
 =?iso-8859-1?Q?b3WcjGjip9zRjy4urvLXA7Wx+o9ohlELRUpruFz2Q3Mz9iUFA2Y3300X6L?=
 =?iso-8859-1?Q?Nf0JmTOdNCalDPv3kZMPXNMgPSmUNJfAkpAA9ogdVHh9MosnmtMJw1eVAn?=
 =?iso-8859-1?Q?mjd4eq3pAIQJAvF++6265MxdQJHiBc+5QmWToMd/o+XfPD5ConryxyY7jY?=
 =?iso-8859-1?Q?I+NusqCXc0iqjYr0CZhGUrYMkGeAmraeP+F24sU851smH07N6q+cCLjgCB?=
 =?iso-8859-1?Q?DIwI6jcEtsoxBwo7ElciDZfPOoA4XTflkt17DCNe211/+iMLNGOPjHkr+3?=
 =?iso-8859-1?Q?t+v9381xE5xW63279/B58P/3AQsB/6sYKc2E5+LYCR43su8yWO9Us3RVtv?=
 =?iso-8859-1?Q?/NWk/vavVmm1P8a8cMm0EYK3KEG5d9fDr59VwBC+asXBWmaysbr35DbjVM?=
 =?iso-8859-1?Q?h+lR6k6PbjZbs4mW8Vnye+dAsgumW2c4YX/iX6lLI5dYb9/5WtHM192weA?=
 =?iso-8859-1?Q?mDKEh9rfG3ENmllTpJd88W0ZoJf4FsnWwCFWU+3Pc6ZOX6IHrFcuaTkBpk?=
 =?iso-8859-1?Q?k=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?K/aC4J0lU1qsULrTt/WnycbmoHFa31V0VfYyBSs1clclbc6MNIXWRy0fv6?=
 =?iso-8859-1?Q?W1CXCRJmLSizwCBxzKNaTVtidGBIQMvM5pZQ5HNexEnigR6DZlGjxwOdT6?=
 =?iso-8859-1?Q?gEKzHOWzzt+2nwl9jOYtIfxcGjb7DoB3wX1G4B2ogKmILEOfebjyyQb0ew?=
 =?iso-8859-1?Q?YAd82B341wlBJcsTdbs7r1TvLV3at1p40wyx+WYNFLdAXL+J4lzJy9WHiK?=
 =?iso-8859-1?Q?ZfAsfFFs4ohwn2YDoMOLq5HyZPIZVfcLMt+fN5bmKGNX8pqvfGReJ1SRyj?=
 =?iso-8859-1?Q?yXMcETuGPtdOuuhaNvJocP8IkWcpYfvFVkVTPhsuHzjNEU6HWSmCLCrZ1S?=
 =?iso-8859-1?Q?df5/UxAD1guXjjUzg8f56SV3cjh4tKmPiHWJLRfETic1rDr40IQf37wq1R?=
 =?iso-8859-1?Q?o6/lyL/J1hODSSnSclE6pEwbHvy3JAJuPvZkpA9Yeg0/CQvpZ55rJNCcXd?=
 =?iso-8859-1?Q?7ohrt/LsawpvjmawUmotQ+bOAr/yfsQ5HIckYPq+lbp4cI4mn96j5GWYwo?=
 =?iso-8859-1?Q?jt3xfvMaHTWD+vZ/Of4AVsk8RbffrMgECK3EavGx8dQYTgathpZbfp/U+R?=
 =?iso-8859-1?Q?M50rwyyHkvNP8lB21DJv1FKI73B+W//xosj0bQV1QkWO1JGxSWuJ4rDloD?=
 =?iso-8859-1?Q?cy/eJdWtJVI15wFl8yYFxdm4yUmf7ZNEmbYntXGF7sk6jWLiGnzLd6qpEx?=
 =?iso-8859-1?Q?dxhwDQHobXjsLwizGZitNAS9ZbZFj6uv6tl18BYdXGp5ZE8BCi4aiZAwYz?=
 =?iso-8859-1?Q?eLRopp9DwM7mDocrhi+dWIdQh77F+7HaL8fGcV7f7Dw3aSQk87Qy+k/j/9?=
 =?iso-8859-1?Q?eOYV1d+2FmdMY3cgRxcJOwODVRWER5FTcSWpk5gFtyXY7v02uLH4F8o0G2?=
 =?iso-8859-1?Q?1l7KRYbFTa4Y9+3WIu7fZjwg3TBXAZ2Jw1Tz0vg6uXQKJ9SuqN2f4ukLiw?=
 =?iso-8859-1?Q?zJbnQyrO4T+zftHKv+YopGGrAnyivo/0ExUoRhb9mP/ifMG0q0rLF8ruXq?=
 =?iso-8859-1?Q?iynFTG1aWoPkTmhn5lLTYi2tgBdycUjUYO4LhAm3ie7OE5jp7Tk8EoVGva?=
 =?iso-8859-1?Q?evuFy89R/7bR4xk/GrBpVjmRevxfQJRO90Af9aKWGQdQfxoJoG9v3ZewkH?=
 =?iso-8859-1?Q?W7aHp/evJfWC5sOGzHFpe4Vi18xO2UdI9x3nvCYWUmIhyAK4jBlk9Kt1NK?=
 =?iso-8859-1?Q?FCaWgICxepan2Q1whOn/jK4cOYIrfIcCxr8vINkWWC5xorovHFZoKTmCrQ?=
 =?iso-8859-1?Q?1tWHvhm8JcdDwFSlom6Rffjoif+EjCZvAvMam6zbaQrHC0PsDghqhZyRlQ?=
 =?iso-8859-1?Q?PzOeh3ZLvvGfRgu6bFGzsbP1IWmw5alUoqzKggFmaE7OTUALqd3hTD95MF?=
 =?iso-8859-1?Q?sBTgRgwOFxK153roSHTgNSL/SdEZxRZlrXzuJC0TmEspjNzSHzvTyQHMVK?=
 =?iso-8859-1?Q?P+z/DLSfo1a6NwYbl+WQR4VpIyfsdG4H15onZPHdcHYE5U7wAhb7sJN9dm?=
 =?iso-8859-1?Q?ui2tsG0+Ni6J5UdIUM2l8HMeO+NsrHvTLj+9j+Rs/jh5KUHSJmFV7DYeWD?=
 =?iso-8859-1?Q?XagP1EjSuVnqxKxw+iJ7mdrqI8juQ0Nj0zdjdkdALjZnPSIfxEHnQ4ukDM?=
 =?iso-8859-1?Q?xyRwfYUuHKiZ8Bo99rR17crrXYlXHpzDB0VwYSKZrK1+CKaUALlUJaGMcB?=
 =?iso-8859-1?Q?d8jtSVF/L+MzKf7BbK8=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: b2f05154-100f-46b6-fa36-08ddde1c1afc
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Aug 2025 05:57:25.2364
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +XukfN+azwwDdb80j4Mzek4aVpZYKO4tmy6xsMls4swnjKVPuJ/vozxokAnZIbleeydtcNMnV0Dr5Gc3RlmDg4HytkFfD7KsueKA8z/+47g=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CYYPR11MB8407
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=iKQz4QzX;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.8 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-08-13 at 15:49:15 +0100, Ada Couprie Diaz wrote:
>Hi,
>
>On 12/08/2025 14:23, Maciej Wieczor-Retman wrote:
>> [...]
>>=20
>> Make part of that hook - which decides whether to die or recover from a
>> tag mismatch - arch independent to avoid duplicating a long comment on
>> both x86 and arm64 architectures.
>>=20
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> [...]
>> diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
>> index f528b6041f6a..b9bdabc14ad1 100644
>> --- a/arch/arm64/kernel/traps.c
>> +++ b/arch/arm64/kernel/traps.c
>> @@ -1068,22 +1068,7 @@ int kasan_brk_handler(struct pt_regs *regs, unsig=
ned long esr)
>>   	kasan_report(addr, size, write, pc);
>> -	/*
>> -	 * The instrumentation allows to control whether we can proceed after
>> -	 * a crash was detected. This is done by passing the -recover flag to
>> -	 * the compiler. Disabling recovery allows to generate more compact
>> -	 * code.
>> -	 *
>> -	 * Unfortunately disabling recovery doesn't work for the kernel right
>> -	 * now. KASAN reporting is disabled in some contexts (for example when
>> -	 * the allocator accesses slab object metadata; this is controlled by
>> -	 * current->kasan_depth). All these accesses are detected by the tool,
>> -	 * even though the reports for them are not printed.
>> -	 *
>> -	 * This is something that might be fixed at some point in the future.
>> -	 */
>> -	if (!recover)
>> -		die("Oops - KASAN", regs, esr);
>> +	kasan_inline_recover(recover, "Oops - KASAN", regs, esr);
>It seems that `die` is missing as the last argument, otherwise
>CONFIG_KASAN_SW_TAGS will not build on arm64.
>With the fix, it builds fully without further issues.
>
>Thanks,
>Ada

Oh right, thank you!

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
4sbzdtnh74bbkg6yopytxn553efynrjp3nylnx6hg4sgwsder%40zff244djrxe2.
