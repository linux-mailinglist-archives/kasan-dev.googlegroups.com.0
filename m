Return-Path: <kasan-dev+bncBD2KV7O4UQOBBJVZTS2QMGQET3KCDAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CF1A93EC9F
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 06:38:00 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1fc52d8bf24sf30750365ad.1
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 21:38:00 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722227878; x=1722832678; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7REeqXqHb6zustMKMNnm+nuDrrL63akAjc6o5XH3gys=;
        b=WTC03uJ5nM4Srl7Rt++JTxt+X9dBm4CyYA2xTFoc7POW7K/jQ1sPEc9iUv6bojgxDd
         gg038E0prFSOkRw+cXynxCiUBDMtGDmi9Y18XNKTQMzY1Qt+lfPxpl2ujm12R2Egz6ri
         rVV3oD6FTT9L6hQ+NlU1T/SU8BtdguBTgOkvsmxRGqz3jujy7o42jzfvxqDqtYEPy8WA
         lnp6qnPm3YFL47mPd5nqLLrEZ0+OZmn0cp5rfomCuNh4kFlDboAg5yY5TWYKhiDeAK5/
         MylVf92bmRGKYZgtaNzfe57yHP5YSPFUEDPKw1WMjgjjZCFWFIvJOyr4PqsHQGoQJRhu
         U4fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722227878; x=1722832678;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7REeqXqHb6zustMKMNnm+nuDrrL63akAjc6o5XH3gys=;
        b=m6KPCnB8Uu4HAs54XnYwsgiRHYoEFVvIb/RUutJ/YeeJdu+TKQfUXeYHn6BqzM9oAl
         0ToUvwgSD+ZR1vFLGkx2lUjeqhibT0KU2liEt2vUI8WDUiFJyj+zAxyceDlg3eZjLbof
         pJVTi+WfVdsKJbU1wzUBUBPH0tifjrOaHta+Gnc9KVJf3KVHFgwqpAyG5Uz8oJNgLqSf
         qrS+iowqJKxYNSWdWlvGX3ooW4QdW7UD2Taa2CWLUGBiO3ao5p339o9VdsHZJK7AWBI+
         n5SzmFbhYlfmf+EBJHpjDDnfRGLMABTy7F9febHL4CT7EKGHW1RYpomZ/zmLv12QLLA4
         bc+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXz54O6xwmo2DSf3ggGn1bZ2zVI2Rpis0NW4Z/E/K9D4e7xLwAbP8g9/L3J2xrv4SY9fsj9Ey+0av3EraqLrHK/EPKi0Tk4ug==
X-Gm-Message-State: AOJu0YzMyRNX6wOthKyA7xF6m3lIDXM8LXWk2g4jHV5SWpg/2BI9bsnI
	1tBkBWZnudsf+AcTpx9PsGAj2tH/+CUG9Y3y+aG4aSSMccwgrDmt
X-Google-Smtp-Source: AGHT+IHhohzIgbvTe1mTCy5j4WHEFdHJ/oA2fPBU1K1PN31yc09Fn909/9EQDPP7OKZqwnzXdvsiew==
X-Received: by 2002:a17:902:c40c:b0:1f7:1bf3:db10 with SMTP id d9443c01a7336-1ff04b011b5mr118214735ad.20.1722227878224;
        Sun, 28 Jul 2024 21:37:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2312:b0:1fb:db0:a3ff with SMTP id
 d9443c01a7336-1fed2073867ls29839425ad.2.-pod-prod-00-us; Sun, 28 Jul 2024
 21:37:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVo7cMRtDqalXdVAomQw6PRTcQ3ncu0StNEBykBqhixkXf5zF1blvBR0nRrYtAWEJd/rPm1muPt00mcmGldy4iKTxVen9GsuiD+Ag==
X-Received: by 2002:a17:903:1d0:b0:1fc:41c0:7a82 with SMTP id d9443c01a7336-1ff048dc431mr111077735ad.0.1722227876930;
        Sun, 28 Jul 2024 21:37:56 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fed7cd6c8bsi3882985ad.7.2024.07.28.21.37.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 28 Jul 2024 21:37:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: 5cGjNq/zT16hgMgk7lc24Q==
X-CSE-MsgGUID: /UDr6It5QXKG7iQeyhoNoQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11147"; a="30621750"
X-IronPort-AV: E=Sophos;i="6.09,245,1716274800"; 
   d="scan'208";a="30621750"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 28 Jul 2024 21:37:55 -0700
X-CSE-ConnectionGUID: gKo8Zo5dTYSsYFo4OjfKOg==
X-CSE-MsgGUID: SX0JyswSQvysKn4pfpgIGA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.09,245,1716274800"; 
   d="scan'208";a="58141761"
Received: from fmsmsx603.amr.corp.intel.com ([10.18.126.83])
  by fmviesa005.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 28 Jul 2024 21:37:54 -0700
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Sun, 28 Jul 2024 21:37:54 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Sun, 28 Jul 2024 21:37:53 -0700
Received: from fmsedg602.ED.cps.intel.com (10.1.192.136) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Sun, 28 Jul 2024 21:37:53 -0700
Received: from NAM04-BN8-obe.outbound.protection.outlook.com (104.47.74.44) by
 edgegateway.intel.com (192.55.55.71) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Sun, 28 Jul 2024 21:37:53 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=msXb4uxFyJJKSa/g08r+gpsGS2njRA7iuyfECejDcMIxhTfIEjWpEKN1OVVVAzCHrwN06McQkvIk+RjW6Z62P0SLcRzxVgYSFVU9oJj97xKZTGhfp/ODTBP4wX8h1GxSpu6uin/K6u7yN5IhhzTXD6D65NMGVnPeIP+AnD+8O47YQJXNnjj/WHI6MqJ1jbE7Mu8MLMVRkfTCH4XzwUdBcoEU/FiRAIafomIvzH07zotAcn40ZvMbXmMGoisrDl8eLPxrAP4qjcrFjav5S9RetYOkFAOkXQL7amfrflQqLREmuezrZHZwUzO3jbytFQc41MtwAYxKKwf++kZlSNhKWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9nBwq9uTDRw4UR9fuOzfVnU48fjWa9fcZVWWxcTEST8=;
 b=vNWyoPHmipjwIL18zyai32s5Uel2bi61oBPUp57bFyrwkCtN3asDr6+z52GFZHVqdilwvPtnxBaEQGBk/7XfkGNANHL5DDidRJTHZ4TnR0bv8iZwjpUGpTeLdlv/mxQPzVIynPi4UV0HBSa68XLOs70lyIqdaKyhsfUkq+Et9QEt64k4c1a1G+7ekbJf9FK1LEyHlFzIb/88LIi7K+edfBgShEyGlEf8Mt7KrTWK+s9N3LFuHUjHekTBxIm6fK/TJo395EpiTum2Mgxh4oyfnuDgw3ZqBJeMYcByYS+qkLpcix1Jos4FAuTvzwfRzoxuPN+T3UbIRx8TSVxaMQU03g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from SJ2PR11MB8587.namprd11.prod.outlook.com (2603:10b6:a03:568::21)
 by DM4PR11MB7278.namprd11.prod.outlook.com (2603:10b6:8:10a::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7807.27; Mon, 29 Jul
 2024 04:37:50 +0000
Received: from SJ2PR11MB8587.namprd11.prod.outlook.com
 ([fe80::4050:8bc7:b7c9:c125]) by SJ2PR11MB8587.namprd11.prod.outlook.com
 ([fe80::4050:8bc7:b7c9:c125%6]) with mapi id 15.20.7807.026; Mon, 29 Jul 2024
 04:37:49 +0000
Date: Mon, 29 Jul 2024 12:37:37 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Jann Horn <jannh@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, "Alexander
 Potapenko" <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, "David
 Rientjes" <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Marco Elver <elver@google.com>,
	<linux-kernel@vger.kernel.org>, Jann Horn <jannh@google.com>,
	<oliver.sang@intel.com>
Subject: Re: [PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Message-ID: <202407291014.2ead1e72-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com>
X-ClientProxiedBy: SI2PR02CA0010.apcprd02.prod.outlook.com
 (2603:1096:4:194::15) To SJ2PR11MB8587.namprd11.prod.outlook.com
 (2603:10b6:a03:568::21)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: SJ2PR11MB8587:EE_|DM4PR11MB7278:EE_
X-MS-Office365-Filtering-Correlation-Id: 0dc38930-9f52-420d-eaa9-08dcaf88335e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|1800799024|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?kdQJmAZhiG4XGxcK/MeHuYGD8iJ2Y7iEJbcgwcr6XbLKAeRxvTu36V9XGmoH?=
 =?us-ascii?Q?7IoHfORWeIt86m8PcnkmdOZAgPxjOxOuCUx5PYvQHHjQDIsdS7mUeB10Di+9?=
 =?us-ascii?Q?Gn348taG/3Xp8ugH+yJ9fIzLAa+ZdnlQRnHXAwyiHlUMi07RKfEr2weL+txF?=
 =?us-ascii?Q?tdx2vCFKkaEhnOjzD8ZDjRT4OYhanozy81kLcc5gHZjD3nfwvuxSBr/w89eG?=
 =?us-ascii?Q?TUboGid4LxtGxNkjBWeoUExII4lLzmK6elGmMUodZ2ZYUUavS+pSfAoNRxCf?=
 =?us-ascii?Q?0FPqYwOmXkb8rl1s08DkE6w7Ci9/oyud5IeZd/9uWgh4Al4CauVtVDXegaKu?=
 =?us-ascii?Q?MiQtWLoFdcT2J6Er5ajtY1IHA+CxZ2yLz/sDaqCaO3HdZzxiMPkGeDWfe+ok?=
 =?us-ascii?Q?JB6l8grbgBVauwiGkqj3xbFNVKl29fI+7U1aRTLQVBiNmPRxED+sxe/RRfCF?=
 =?us-ascii?Q?KZ5KguaHjogKTjL6C6aoqR+s5t5GvB3FaeIXWtBlJeXD0k1nT0AX6sU1ZfbN?=
 =?us-ascii?Q?4HWx20aHV++EKHJb3//w9LI3gRYcCgDMlXdW7KpcndO74WiGV0sX6yJqcN/i?=
 =?us-ascii?Q?WD28lHuZACZkHSsumCPxyQe9MlGN0m7Op0BLXzX3I1JP4DSO3XKILvuu+LUE?=
 =?us-ascii?Q?AThCbgLIoqG5zKqVRiEXMhhYs/TKYedQeoWt+T3BRm8PrVM74W+te0VLWOOc?=
 =?us-ascii?Q?SbNRb4Jp/QECXG9uO5oICLCjz9yQK1VLZGYShFAI2UHrkTO1Ki48tHkSmdOn?=
 =?us-ascii?Q?9/fU2KYig7kiJdoYjEwJofpAgVlnovccI2w6XmaSaTynY1LOAqQPN4MO1I35?=
 =?us-ascii?Q?lQQvPBlG20d9CW90PwikrM+FG9wN/0CFNLdvCtH0gXjySZJYJ2JuWNEQs8u7?=
 =?us-ascii?Q?dA8k1c6dRLt/xTDZrdT8V8Evva1ivP64Rbp1Hiz0YOzATCMG5vhB8RIKIUPJ?=
 =?us-ascii?Q?MhuPT40vkQWNgL7OFF1wwBEo3F1Q5Tv4ZbcGHPx2pjR/ujjZ0pic0w2biVzl?=
 =?us-ascii?Q?ydQDUGDaUeoQrbdAonPjQQhwgOh7hbre3/dDId/uCzBasn5a1whbCuzu5d0v?=
 =?us-ascii?Q?szPGKyVrMUXSdp+3yJsERnqLR+V3+didxN9wLc1Nbe1Qxse3aLXBy6rW6xmZ?=
 =?us-ascii?Q?ww/j4S6nCUjh1oEGbR6VYwYTW7XhzPZvP43NnW6gbymQdEiWztDtauSdpPly?=
 =?us-ascii?Q?fxlA2qGgllVi2FxrYqk4rQwQcHXAlcg3f/180wCfQ8dpIaaM4CSd7N/MLjPy?=
 =?us-ascii?Q?UU1hy59NRB/LBJkEdwEnuTJKA5dk6kg11Ne0xdPswh/8/kLqaBj5qTs14GZn?=
 =?us-ascii?Q?vI69sUpY0dhSMYrATIQWrSN8?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SJ2PR11MB8587.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(1800799024)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?v/hGKsIVDZdS/1+AoOmt0dMcU8KNaLfQO8cCSLz7n8n+U09MZ6x17si7uPXV?=
 =?us-ascii?Q?LGM/nONoBqb8iJw2MD9ummWnQLCTojegHC9+KZHEzBGayj4tS/eZvU8vNdEe?=
 =?us-ascii?Q?r7bBrkGXRHF22Gx9Vk5l5QFYyuYyGoBiEjOUW+1Fl06GBZHgSYY07FpZYj/O?=
 =?us-ascii?Q?BHbmZpKByqS4ud/OpaPnG3bHEjrlLgP/XI6HYbiFjMZ8b+7A1Xqc8/E1AwCH?=
 =?us-ascii?Q?4LyT5LYgZIJ6L++IK0GltZJwqoG6CLzgL29HQE9davCdJVF2oIEUZ99vsr+0?=
 =?us-ascii?Q?/bDmMKU1wQ89Fb87FPvuhDzHW57yA+fvS78UTszyM2unme2crzWFAscOsPF2?=
 =?us-ascii?Q?0w6klNWgZZwmwA1wXr2r6szHqorulxDcC7lB9X4J9nv6kRcNdDfvXZ1qtdST?=
 =?us-ascii?Q?lh2Il9Db7QHhczyRkys9Z5EoddQNtQDjlPxCZRS8I/7ojbOeFdyQGIZSggie?=
 =?us-ascii?Q?WyMaekTuCJNTb6O+0XjypUxqkGaKHUsLrHiYudjWsFIj8Uktp3Yt76fHpxM8?=
 =?us-ascii?Q?KLA4fOhMzY3FKywH3ngeaqqXumvwOHxe52MTNcTErW91UHiGGd9xbJaQDx/J?=
 =?us-ascii?Q?seh0YBjo0e+ixkSwu6ussHhnUMBsDm+H2F6RQQnhHfR82X+h6fOnXcKDJpp3?=
 =?us-ascii?Q?DvwPriuUpVatZWZhrW0v/qBwlPE2WT7fIm29iRpXeRcRqFvMeUT2N4EPm+3i?=
 =?us-ascii?Q?gnnfHNS5eFJkPmvHyCZEVmlV0Q8hDG3wphaoJi8YOv88mDL12J0LCFMWqNS5?=
 =?us-ascii?Q?53WXlp/ON/OIk2y8ysOTo6Er46X+KQ1pwStxz2o7syqIljtwQO8xzBUu/Swh?=
 =?us-ascii?Q?AdaM2y9VKYDyDwxOSw6EFUzaGQWDYTO2g5vdhfSaEvtxy8oyb49iXkm9ERDF?=
 =?us-ascii?Q?ZkwNXgVKwiSPvZjmZpGLjco2PerWOQb7pvIzR4RMuOZcsUzRSSDY9KLm8bGm?=
 =?us-ascii?Q?ohrRzmTmO8CPvuz7cGQBaBQRIa8J1kigln9W+NQAxa5CQwcl46XRZqQW/Uv2?=
 =?us-ascii?Q?tzov9VvQ5YdoLYvQ5L4gpm8b87T239EpP1aiCOUPvysIWtT5Fm08cZy7ZoJA?=
 =?us-ascii?Q?aRNaOEqlymcLqQoJajGa1LDLnwUevNlEKGCGMvkyFwyjvQRJLFJ3WTxzQhah?=
 =?us-ascii?Q?dgH8ab9EgejsrJi4MVEA61OsYXYxhyBhsZWMvJqj/Mf9XJbX9j8GK+I3UYLe?=
 =?us-ascii?Q?2DoAsxNkqUj38BdUg58OeV5RT1knRo5jLjZujnYug2aNsQdBPhd3za7ISMjp?=
 =?us-ascii?Q?XUWcykjzV4Wp/K7KQq/X9+hnu8iIy/VwR0TvPOmjqroZgH/IaZGUWf/sMUAk?=
 =?us-ascii?Q?XwFVazZrCHcBpckoH+EmKHahXEkZ8nJDuRh+gC97QDfcRnTnsMBRZI/cHEro?=
 =?us-ascii?Q?9znfjorn3tzQxti/TLWp/7MAPBCpD8Z9qexBB6H6+it6km52/X4RX+TcNmPv?=
 =?us-ascii?Q?X8fINkbQQSPaT2Qr8djJgSb6rHXH5VmP9G3FZNSnFdD1dWLozU5+gjFnVugl?=
 =?us-ascii?Q?KLbxAied0LsgdGbRuDvQ5kVLziPYRWlNLWDLO4XKlqa7E2Png+luCHh0fq0B?=
 =?us-ascii?Q?1pXkoMwnE9emnc51VrvIcT+++NBH+oKLQRrNfIu7?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 0dc38930-9f52-420d-eaa9-08dcaf88335e
X-MS-Exchange-CrossTenant-AuthSource: SJ2PR11MB8587.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Jul 2024 04:37:49.5642
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 9vlzBCSp9/InHluLmPzQ9mDkDnco2Qw479PTLSqyun8/q4sM0gX0Qrc/uIf6PIfhauo27gNFymIHdnB/VtwkHQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR11MB7278
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=OLFMXo9r;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 192.198.163.9 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

kernel test robot noticed "WARNING:possible_circular_locking_dependency_detected" on:

commit: 17049be0e1bcf0aa8809faf84f3ddd8529cd6c4c ("[PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG")
url: https://github.com/intel-lab-lkp/linux/commits/Jann-Horn/kasan-catch-invalid-free-before-SLUB-reinitializes-the-object/20240726-045709
patch link: https://lore.kernel.org/all/20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com/
patch subject: [PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG

in testcase: rcutorture
version: 
with following parameters:

	runtime: 300s
	test: cpuhotplug
	torture_type: tasks-rude



compiler: clang-18
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202407291014.2ead1e72-oliver.sang@intel.com


[  136.014616][    C1] WARNING: possible circular locking dependency detected
[  136.014618][    C1] 6.10.0-00002-g17049be0e1bc #1 Not tainted
[  136.014621][    C1] ------------------------------------------------------
[  136.014622][    C1] swapper/1/0 is trying to acquire lock:
[ 136.014625][ C1] ffffffff868f04a0 (console_owner){-.-.}-{0:0}, at: console_flush_all (include/linux/rcupdate.h:? include/linux/srcu.h:232 kernel/printk/printk.c:286 kernel/printk/printk.c:2971) 
[  136.014668][    C1]
[  136.014668][    C1] but task is already holding lock:
[ 136.014670][ C1] ffff888102658518 (&n->list_lock){-.-.}-{2:2}, at: free_to_partial_list (mm/slub.c:?) 
[  136.014685][    C1]
[  136.014685][    C1] which lock already depends on the new lock.
[  136.014685][    C1]
[  136.014687][    C1]
[  136.014687][    C1] the existing dependency chain (in reverse order) is:
[  136.014688][    C1]
[  136.014688][    C1] -> #4 (&n->list_lock){-.-.}-{2:2}:
[ 136.014694][ C1] _raw_spin_lock_irqsave (include/linux/spinlock_api_smp.h:110 kernel/locking/spinlock.c:162) 
[ 136.014704][ C1] ___slab_alloc (mm/slub.c:2717) 
[ 136.014709][ C1] kmem_cache_alloc_noprof (mm/slub.c:3797 mm/slub.c:3850 mm/slub.c:4030 mm/slub.c:4049) 
[ 136.014712][ C1] debug_objects_fill_pool (lib/debugobjects.c:168) 
[ 136.014717][ C1] debug_object_activate (lib/debugobjects.c:492 lib/debugobjects.c:706) 
[ 136.014721][ C1] enqueue_hrtimer (arch/x86/include/asm/jump_label.h:27 include/linux/jump_label.h:207 include/trace/events/timer.h:222 kernel/time/hrtimer.c:479 kernel/time/hrtimer.c:1085) 
[ 136.014726][ C1] hrtimer_start_range_ns (kernel/time/hrtimer.c:1302) 
[ 136.014730][ C1] __enqueue_rt_entity (kernel/sched/rt.c:122) 
[ 136.014735][ C1] enqueue_task_rt (kernel/sched/rt.c:1453) 
[ 136.014738][ C1] __sched_setscheduler (kernel/sched/core.c:?) 
[ 136.014742][ C1] sched_set_fifo (kernel/sched/core.c:8024) 
[ 136.014745][ C1] drm_vblank_worker_init (drivers/gpu/drm/drm_vblank_work.c:?) 
[ 136.014750][ C1] drm_vblank_init (drivers/gpu/drm/drm_vblank.c:555) 
[ 136.014755][ C1] vkms_init (drivers/gpu/drm/vkms/vkms_drv.c:210) 
[ 136.014759][ C1] do_one_initcall (init/main.c:1267) 
[ 136.014762][ C1] do_initcall_level (init/main.c:1328) 
[ 136.014766][ C1] do_initcalls (init/main.c:1342) 
[ 136.014769][ C1] kernel_init_freeable (init/main.c:1582) 
[ 136.014772][ C1] kernel_init (init/main.c:1469) 
[ 136.014776][ C1] ret_from_fork (arch/x86/kernel/process.c:153) 
[ 136.014783][ C1] ret_from_fork_asm (arch/x86/entry/entry_64.S:257) 
[  136.014786][    C1]
[  136.014786][    C1] -> #3 (hrtimer_bases.lock){-.-.}-{2:2}:
[ 136.014792][ C1] _raw_spin_lock_irqsave (include/linux/spinlock_api_smp.h:110 kernel/locking/spinlock.c:162) 
[ 136.014798][ C1] hrtimer_start_range_ns (kernel/time/hrtimer.c:?) 
[ 136.014801][ C1] rpm_suspend (drivers/base/power/runtime.c:?) 
[ 136.014807][ C1] rpm_resume (drivers/base/power/runtime.c:?) 
[ 136.014810][ C1] pm_runtime_work (drivers/base/power/runtime.c:?) 
[ 136.014814][ C1] process_scheduled_works (kernel/workqueue.c:?) 
[ 136.014818][ C1] worker_thread (include/linux/list.h:373 kernel/workqueue.c:947 kernel/workqueue.c:3410) 
[ 136.014820][ C1] kthread (kernel/kthread.c:391) 
[ 136.014824][ C1] ret_from_fork (arch/x86/kernel/process.c:153) 
[ 136.014826][ C1] ret_from_fork_asm (arch/x86/entry/entry_64.S:257) 
[  136.014832][    C1]
[  136.014832][    C1] -> #2 (&dev->power.lock){-.-.}-{2:2}:
[ 136.014837][ C1] _raw_spin_lock_irqsave (include/linux/spinlock_api_smp.h:110 kernel/locking/spinlock.c:162) 
[ 136.014840][ C1] __pm_runtime_resume (drivers/base/power/runtime.c:1171) 
[ 136.014843][ C1] __uart_start (drivers/tty/serial/serial_core.c:149) 
[ 136.014849][ C1] uart_write (include/linux/spinlock.h:406 include/linux/serial_core.h:669 drivers/tty/serial/serial_core.c:634) 
[ 136.014851][ C1] n_tty_write (drivers/tty/n_tty.c:574 drivers/tty/n_tty.c:2389) 
[ 136.014855][ C1] file_tty_write (drivers/tty/tty_io.c:1021) 
[ 136.014859][ C1] do_iter_readv_writev (fs/read_write.c:742) 
[ 136.014864][ C1] vfs_writev (fs/read_write.c:971) 
[ 136.014867][ C1] do_writev (fs/read_write.c:1018) 
[ 136.014870][ C1] __do_fast_syscall_32 (arch/x86/entry/common.c:?) 
[ 136.014874][ C1] do_fast_syscall_32 (arch/x86/entry/common.c:411) 
[ 136.014877][ C1] entry_SYSENTER_compat_after_hwframe (arch/x86/entry/entry_64_compat.S:127) 
[  136.014883][    C1]
[  136.014883][    C1] -> #1 (&port_lock_key){-.-.}-{2:2}:
[ 136.014888][ C1] _raw_spin_lock_irqsave (include/linux/spinlock_api_smp.h:110 kernel/locking/spinlock.c:162) 
[ 136.014891][ C1] serial8250_console_write (include/linux/serial_core.h:? drivers/tty/serial/8250/8250_port.c:3352) 
[ 136.014894][ C1] console_flush_all (kernel/printk/printk.c:2917) 
[ 136.014897][ C1] console_unlock (kernel/printk/printk.c:3048) 
[ 136.014900][ C1] vprintk_emit (kernel/printk/printk.c:?) 
[ 136.014903][ C1] _printk (kernel/printk/printk.c:2376) 
[ 136.014907][ C1] register_console (kernel/printk/printk.c:3537) 
[ 136.014910][ C1] univ8250_console_init (drivers/tty/serial/8250/8250_core.c:?) 
[ 136.014914][ C1] console_init (arch/x86/include/asm/jump_label.h:27 include/linux/jump_label.h:207 include/trace/events/initcall.h:48 kernel/printk/printk.c:3728) 
[ 136.014919][ C1] start_kernel (init/main.c:1039) 
[ 136.014922][ C1] x86_64_start_reservations (??:?) 
[ 136.014926][ C1] x86_64_start_kernel (??:?) 
[ 136.014931][ C1] common_startup_64 (arch/x86/kernel/head_64.S:421) 
[  136.014935][    C1]
[  136.014935][    C1] -> #0 (console_owner){-.-.}-{0:0}:
[ 136.014940][ C1] __lock_acquire (kernel/locking/lockdep.c:3135) 
[ 136.014947][ C1] lock_acquire (kernel/locking/lockdep.c:5754) 
[ 136.014951][ C1] console_flush_all (kernel/printk/printk.c:1873) 
[ 136.014955][ C1] console_unlock (kernel/printk/printk.c:3048) 
[ 136.014958][ C1] vprintk_emit (kernel/printk/printk.c:?) 
[ 136.014961][ C1] _printk (kernel/printk/printk.c:2376) 
[ 136.014964][ C1] slab_bug (mm/slub.c:1030) 
[ 136.014968][ C1] slab_err (mm/slub.c:967 mm/slub.c:1131) 
[ 136.014970][ C1] free_to_partial_list (mm/slub.c:3337) 
[ 136.014974][ C1] slab_free_after_rcu_debug (mm/slub.c:? mm/slub.c:4528) 
[ 136.014978][ C1] rcu_do_batch (include/linux/rcupdate.h:339 kernel/rcu/tree.c:2537) 
[ 136.014984][ C1] rcu_core (kernel/rcu/tree.c:2811) 
[ 136.014987][ C1] handle_softirqs (arch/x86/include/asm/jump_label.h:27 include/linux/jump_label.h:207 include/trace/events/irq.h:142 kernel/softirq.c:555) 
[ 136.014991][ C1] __irq_exit_rcu (kernel/softirq.c:617 kernel/softirq.c:639) 
[ 136.014994][ C1] irq_exit_rcu (kernel/softirq.c:651) 
[ 136.014996][ C1] sysvec_apic_timer_interrupt (arch/x86/kernel/apic/apic.c:1043) 
[ 136.015000][ C1] asm_sysvec_apic_timer_interrupt (arch/x86/include/asm/idtentry.h:702) 
[ 136.015003][ C1] default_idle (arch/x86/include/asm/irqflags.h:37 arch/x86/include/asm/irqflags.h:72 arch/x86/kernel/process.c:743) 
[ 136.015007][ C1] default_idle_call (include/linux/cpuidle.h:143 kernel/sched/idle.c:118) 
[ 136.015010][ C1] do_idle (kernel/sched/idle.c:? kernel/sched/idle.c:332) 
[ 136.015014][ C1] cpu_startup_entry (kernel/sched/idle.c:429) 
[ 136.015017][ C1] start_secondary (arch/x86/kernel/smpboot.c:313) 
[ 136.015021][ C1] common_startup_64 (arch/x86/kernel/head_64.S:421) 
[  136.015024][    C1]
[  136.015024][    C1] other info that might help us debug this:
[  136.015024][    C1]
[  136.015025][    C1] Chain exists of:
[  136.015025][    C1]   console_owner --> hrtimer_bases.lock --> &n->list_lock
[  136.015025][    C1]
[  136.015031][    C1]  Possible unsafe locking scenario:
[  136.015031][    C1]
[  136.015032][    C1]        CPU0                    CPU1
[  136.015033][    C1]        ----                    ----
[  136.015034][    C1]   lock(&n->list_lock);
[  136.015037][    C1]                                lock(hrtimer_bases.lock);
[  136.015039][    C1]                                lock(&n->list_lock);
[  136.015042][    C1]   lock(console_owner);
[  136.015044][    C1]
[  136.015044][    C1]  *** DEADLOCK ***
[  136.015044][    C1]
[  136.015045][    C1] 4 locks held by swapper/1/0:
[ 136.015048][ C1] #0: ffffffff868fb5a0 (rcu_callback){....}-{0:0}, at: rcu_do_batch (kernel/rcu/tree.c:?) 
[ 136.015057][ C1] #1: ffff888102658518 (&n->list_lock){-.-.}-{2:2}, at: free_to_partial_list (mm/slub.c:?) 
[ 136.015065][ C1] #2: ffffffff864ffd60 (console_lock){+.+.}-{0:0}, at: _printk (kernel/printk/printk.c:2376) 
[ 136.015075][ C1] #3: ffffffff864ff950 (console_srcu){....}-{0:0}, at: console_flush_all (include/linux/rcupdate.h:? include/linux/srcu.h:232 kernel/printk/printk.c:286 kernel/printk/printk.c:2971) 
[  136.015086][    C1]
[  136.015086][    C1] stack backtrace:
[  136.015088][    C1] CPU: 1 PID: 0 Comm: swapper/1 Not tainted 6.10.0-00002-g17049be0e1bc #1
[  136.015093][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[  136.015099][    C1] Call Trace:
[  136.015102][    C1]  <IRQ>
[ 136.015104][ C1] dump_stack_lvl (lib/dump_stack.c:116) 
[ 136.015109][ C1] check_noncircular (kernel/locking/lockdep.c:?) 
[ 136.015115][ C1] __lock_acquire (kernel/locking/lockdep.c:3135) 
[ 136.015126][ C1] lock_acquire (kernel/locking/lockdep.c:5754) 
[ 136.015133][ C1] ? console_flush_all (include/linux/rcupdate.h:? include/linux/srcu.h:232 kernel/printk/printk.c:286 kernel/printk/printk.c:2971) 
[ 136.015138][ C1] ? do_raw_spin_unlock (arch/x86/include/asm/atomic.h:23) 
[ 136.015143][ C1] console_flush_all (kernel/printk/printk.c:1873) 
[ 136.015147][ C1] ? console_flush_all (include/linux/rcupdate.h:? include/linux/srcu.h:232 kernel/printk/printk.c:286 kernel/printk/printk.c:2971) 
[ 136.015152][ C1] ? console_flush_all (include/linux/rcupdate.h:? include/linux/srcu.h:232 kernel/printk/printk.c:286 kernel/printk/printk.c:2971) 
[ 136.015158][ C1] console_unlock (kernel/printk/printk.c:3048) 
[ 136.015163][ C1] vprintk_emit (kernel/printk/printk.c:?) 
[ 136.015168][ C1] _printk (kernel/printk/printk.c:2376) 
[ 136.015173][ C1] ? __asan_memcpy (mm/kasan/shadow.c:105) 
[ 136.015178][ C1] slab_bug (mm/slub.c:1030) 
[ 136.015184][ C1] slab_err (mm/slub.c:967 mm/slub.c:1131) 
[ 136.015192][ C1] free_to_partial_list (mm/slub.c:3337) 
[ 136.015197][ C1] ? slab_free_after_rcu_debug (mm/slub.c:4423 mm/slub.c:4528) 
[ 136.015202][ C1] ? rcu_do_batch (include/linux/rcupdate.h:339 kernel/rcu/tree.c:2537) 
[ 136.015206][ C1] slab_free_after_rcu_debug (mm/slub.c:? mm/slub.c:4528) 
[ 136.015211][ C1] ? rcu_do_batch (kernel/rcu/tree.c:?) 
[ 136.015214][ C1] ? __cfi_slab_free_after_rcu_debug (mm/slub.c:4508) 


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20240729/202407291014.2ead1e72-oliver.sang@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202407291014.2ead1e72-oliver.sang%40intel.com.
