Return-Path: <kasan-dev+bncBD2KV7O4UQOBBAXHZS2QMGQEVHURHAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 727D194A314
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 10:42:44 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-39b331c43desf24231105ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 01:42:44 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723020163; x=1723624963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xSHYaG9nO7E4AFBz4/hjxyRYlA/y6SQ5vKyCNpJFfXU=;
        b=BLZqzC6Zs2C1AHgSBP/1cHt4PxGGpgZkNuAIseUkgsnFre1+QdVy/v2t8j+E4R1mrN
         REDGVzU00oSvZdqJKlMsitww9iH28NShyPa4GfXgPWq/SjSVyzdBmWSNMYMuIHiAcNwy
         GecO2udr5lXn0m87TP7yaZeVpMPgzLpcOsM/EiRIz52BaR3Y8Wss9LK+bv/E6bH6NVMQ
         aMUzk8nLXXCDs6QGx3rBJ6Plim5i8wSRjisZF8caiMHtRwUebRPwDHl6F3Oqgs5RaFiI
         YIS1M6FmRY9XNUJrn40ppMNEEB6KArGKLJR1xUyU8dodOLa4lia9WPV99qQ6RFCW3Lxa
         85aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723020163; x=1723624963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xSHYaG9nO7E4AFBz4/hjxyRYlA/y6SQ5vKyCNpJFfXU=;
        b=Z9BdH+CKdm+mphQBnmtbr6E2TPj+doDgNkI/HWjnjEE8eYIM8VH1izdkeb+g5jWDQY
         rOK7xmxdEFISlpvadweJiOkJWfNF7em/Eaziu0WGWIwW2SX1BCcjryegXboXLq9Qwzrr
         K3NfBVVJPt36C3fBc3ZBldLNp+jOGee//fJr4f5kOb7W0xAdD2FnONmJUYFBNLsUr4EQ
         dfXUGus2GAZ1Sxko+XoNdBjipvHNWEEek0S6NRiZghNyi2W8Su/rDwlRZgyzMW0HiaQq
         7vyrkiZqia7jfOSHtPHvdCe6hIyTN2N4p4hDOpQV1iFvkQwh2gpKIAN5kqDbGcwbUSI9
         5/7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbg1zLwBh9DMcO63j1svfJJjjaJeFrA2u1rqrTxpd6vkkW0xNZDLGs55vQH/zVzc6grN2OFLGFoncUCGjhEuMcx/Os8LRrBg==
X-Gm-Message-State: AOJu0YyUMTZ+Ae/Dbx0U5ZQ3zdvsGjSp/4ypoDj05WQiyHPjaWff2EOo
	qeZYdEt17577d/KrLAVucSOAkZUbEmXVkOQRAmjgmisf5QeecWZs
X-Google-Smtp-Source: AGHT+IHyFP3f8f7EK77/E5XbJsMDi8lsG7iQim0qrHDoOkxHsLI6CebBaDdMtMZyITXUkxSDPcG9cw==
X-Received: by 2002:a92:cd8e:0:b0:39b:3649:1b68 with SMTP id e9e14a558f8ab-39b36491d25mr183336045ab.13.1723020163122;
        Wed, 07 Aug 2024 01:42:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:8ed:b0:39a:f263:546d with SMTP id
 e9e14a558f8ab-39b29ee095els34377275ab.2.-pod-prod-01-us; Wed, 07 Aug 2024
 01:42:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVd1DYpFX/emTgrXDKl0Nal1zyKeQHt0ACoBKRcx2xMf0WCSJt5xVm54B89qlMx+bpHTdZe0wDtotyBQAy/91d9PAyf4zAHZu/Mxw==
X-Received: by 2002:a05:6602:2dcd:b0:81f:d579:335c with SMTP id ca18e2360f4ac-81fd579363fmr1736948739f.17.1723020161668;
        Wed, 07 Aug 2024 01:42:41 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-81fd4d50295si52816739f.2.2024.08.07.01.42.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 07 Aug 2024 01:42:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.9 as permitted sender) client-ip=192.198.163.9;
X-CSE-ConnectionGUID: tVTiXoHgSlO9rcvxAC7lpw==
X-CSE-MsgGUID: k5K5exVCTUe6TD8IO3EEaQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11156"; a="31745645"
X-IronPort-AV: E=Sophos;i="6.09,269,1716274800"; 
   d="scan'208";a="31745645"
Received: from fmviesa007.fm.intel.com ([10.60.135.147])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2024 01:42:39 -0700
X-CSE-ConnectionGUID: noR7e9paRfi69Jt9arVe3Q==
X-CSE-MsgGUID: cgvfK98CQAumvBMRLgwMBg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.09,269,1716274800"; 
   d="scan'208";a="56468537"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by fmviesa007.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 07 Aug 2024 01:42:39 -0700
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Wed, 7 Aug 2024 01:42:38 -0700
Received: from fmsmsx603.amr.corp.intel.com (10.18.126.83) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Wed, 7 Aug 2024 01:42:38 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Wed, 7 Aug 2024 01:42:38 -0700
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (104.47.55.173)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Wed, 7 Aug 2024 01:42:38 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=qpAOvxPEU0jELuqcyFbMx5bG+vkar/uIqz7hjU86UIMR4lEsaGCGhQ7qS+/FheHTFw2+Zn6HF05hJXrdh89MrpiYHbiqLgaWhfrlvql8iHAyoNPh47tJ97IPW8DeKlD0ZiHhoTD5jZJPfS980ct9hsyDRlgp2GNyu6bNDPgm5A+rI4e6ZPd38yhr2g3TtgDybq6Bz7yQP0n+6uuRAFiE51q2vsZqICsl9RrfPxaOPH/ZHs2YsWiv+oE033lMQPMoZ2Sh0z5957Eav2EC6qN5LoYwuX/eliE/HHexDxeE5Qq6QoJtjfA+S7A4skn+57ZlDpuqitQ4sF7dum/iKFstjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TYzb6o/q9VegJCx2lFkICB0oL+6migoEKADX5Qu1eX8=;
 b=iGqhXo12mJVW4pl2CzF8wLPfViTVDlGuHWAtFT2R6hfXZsCJQQ89uKhjen5ykT/fOvX7T2iFnuIFsuBEB1OfsUAqtIk7sNSpoqT66S45EzdF6O0nKoEYTRUKtoBy5kC6iBmHSs7//dc+xQSW1hcByxzBMc4H83fQ1QEHRgiUbBJvIdAePYEod60+1mc3I3BwMu2JsiPsv5nL03pQqIiUbiRnz+v62mzA2gjcHhtt0fbznlJHv3YtESk25yzXXnLWZLYnPKHAN5hSCjUFYkdNsk+Q2dX7xOUQHmPeaYuwxrJUM6mMPxlcHsc2QIXUs8U8Now35dzj4XeXUor6geyuwg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by PH7PR11MB7497.namprd11.prod.outlook.com (2603:10b6:510:270::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7807.32; Wed, 7 Aug
 2024 08:42:33 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.7828.023; Wed, 7 Aug 2024
 08:42:33 +0000
Date: Wed, 7 Aug 2024 16:42:20 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Jann Horn <jannh@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, Linux Memory Management List
	<linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, "Alexander
 Potapenko" <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Marco Elver <elver@google.com>, Pekka Enberg <penberg@kernel.org>, "Roman
 Gushchin" <roman.gushchin@linux.dev>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>,
	<oliver.sang@intel.com>
Subject: [linux-next:master] [slub]  b82c7add4c:
 WARNING:at_mm/slub.c:#slab_free_after_rcu_debug
Message-ID: <202408071606.258f19a0-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SI1PR02CA0042.apcprd02.prod.outlook.com
 (2603:1096:4:1f6::17) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|PH7PR11MB7497:EE_
X-MS-Office365-Filtering-Correlation-Id: 4f661e9e-5dd7-42a3-528f-08dcb6bce175
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Br346evaX86ohdCEtOG5uxg2+V0Vh5TZpLxGHNLwPVGSPND7HDpSHvlHn3LG?=
 =?us-ascii?Q?9pjHcQmayFm5TUpJcgfE3g3QyyEHXlMMYYZ7O9qCM+hra4TDZqC2O5EYh6wl?=
 =?us-ascii?Q?zR0c9HY43VyqE5EhpV/nl6zKm/breD5usY9W03HhfYztFHhm786wUqst+hHm?=
 =?us-ascii?Q?Zq7yF3YcV/tZQpJ6HaowbMivp7vEFfuxEHucdmqD3LHH+iEnCigkFi04VZaZ?=
 =?us-ascii?Q?lqewSTluCHisogPeHHfypIZDp9QLIAswebaiL23YcC/QJUwW6GS3myDiu0ri?=
 =?us-ascii?Q?8vQpTf+UBrWyuIZDlhxZDPm4ryKaj+uqsU1ckxlxFORr5WzTMw7V3oHtbpcD?=
 =?us-ascii?Q?CkWYU4PGYyte3n/KqElTcdxoun9z+WsptN1z2tex48sA42vJhg8guofiV4tF?=
 =?us-ascii?Q?+bnw4vV2nP0Jgcx7fuU7hkK0vfhHp6oc6wTsZ4nzh0umlj5JDOkiD8dyyL73?=
 =?us-ascii?Q?8p5RcGwVMVMDLb9ttBTII9h17ianlAE94LYwBZ5QP1TDNNjaTYhQJXEJrUpn?=
 =?us-ascii?Q?PDu2y993Cj0fFpBTOaQ7QrbAtfMtmUbm2CeeYSoXsThRXzzuElTfn05ygvg0?=
 =?us-ascii?Q?epgiCPJNFyS8PqIDTtvT8YP/HFO//qBi8OVQ866NcJqPH0eeLErX3NTkR5hA?=
 =?us-ascii?Q?3bkqjqNh/7W8JkGcx4TdM2EepZbTn6vfL71KzpfFbV7XA9SKHv7Qu9z3BVq7?=
 =?us-ascii?Q?/M3t6AISwL5CSG+NZBUGJAMMzrx6FiWPy4RN7flN6t76d2UVmAhGzfVA6ohV?=
 =?us-ascii?Q?ASfy4Ei3+EulMoll4FB9p8Hp+KAxcSYH4JmXSQrHSi28jNdETyIR8DAcaLVt?=
 =?us-ascii?Q?qL5wyKroxXVMz4SErYDIqk2qt4KQ5yqdCW+nEcCKlklB9OfWQScOTkmypMtP?=
 =?us-ascii?Q?pKeps+4+3E8qgOyzAeUO6RcV2Ql7E7ZEeN/zFxon1FDxsq5xuXlJaJpoj5Z5?=
 =?us-ascii?Q?hwQThoFz7lkNyB/KweaftwhVt/CGyKmAGspKgjsXpILPEpsIZN2GhfdvzKVv?=
 =?us-ascii?Q?0lvxnp4UZa6ud9KYMP4bOLZrsYRf3ykJEkA8yTWOluEdzAC5ECVQ6+iUw4Q4?=
 =?us-ascii?Q?yUH+Spfm1mVxGeP0rZhSfNIjWdM1E5sXiBYtYQEdtqVTz/t5vsTTSjeeCQ4n?=
 =?us-ascii?Q?UHl72vCQ7mV6rsLcxgVfd0dfF7R1aZKxRlZxqh8dy3JCohDN5vEMjIQJmZ+7?=
 =?us-ascii?Q?bBplcFAUQ33YIfDQJxifiSXwykjPvVUX8ByTHj0D9W6HI3Pi/guxXLjFBpOw?=
 =?us-ascii?Q?lRJtEdbvua/NZyoYa3ZyA8p92fBDQKIJa5fBubj8OPG+KoPKrqzVYvXgHGtg?=
 =?us-ascii?Q?JSwMhRjld7Dn97Rz6oeMBZ+G?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Dv9nw3SBupZ1T0R0KuuaXqsqt7XB0/ZO5b1O2BVece8u5tdn2R9p0ErGvKI2?=
 =?us-ascii?Q?3HJts/OmnHiTkIX/wB5dldmVqsvGs0ZAJWGGc3tcOwIVLPgO3MtW/F/e9bPq?=
 =?us-ascii?Q?ygyU8uhabeog/fhJ5u+rfHOy68Sbm3337wdd3je8InpR1AaD3C8B/K2auXZi?=
 =?us-ascii?Q?anvqSDQ4N51I/iFKg5mdyrSWJumGa9sh/yu9L4DbiiTNsboGN/1hOESxoS6M?=
 =?us-ascii?Q?MQZLU47N7agVMddGFukDIK+WYStpV9DZIdQzjtCSOBsnj0FZ43L7a5fv86eo?=
 =?us-ascii?Q?P62Zy9fJf2rT/7JA1oWL9vr07hk+zbMo1MVuwazUdVzkTQ2bBANMen7KC/1U?=
 =?us-ascii?Q?onWzb3HQrWs6OsyjxWnYUQzy70QlWicf4Qkb2/y+Igqf2QC0u8M67Nc150ih?=
 =?us-ascii?Q?dnRia4by9LwwwkiJqAWzh4JM2m7owNCMH7I85y+yibvi64w7UmaXEQztKoeS?=
 =?us-ascii?Q?sKytdvEXc0tE18ETd920U9Z64Pgx/kfNJw+m5kugYsGkpCXjtuB9yBeZhSNS?=
 =?us-ascii?Q?xS3Fae3XrS8GY84uTKsqHcxgqGOTRRTC6KRIy6eEsOJNLwjw9kVUqK2cOxSo?=
 =?us-ascii?Q?jOwxz8DjErK1ezs6VSrxW2lqyYYXlyMV6SpyeDuk4J3j0TwKw2gS92YyLLQb?=
 =?us-ascii?Q?qpbYEjKjGwYHMA2zafNyTe0MEafdAHCTrIydL8D76RZUNPWRzkpqJRYFOBkN?=
 =?us-ascii?Q?GdXbuAOtQ16aR2xBvJm9syaVeFA0P+GdEODQF4nScTAzQbdc9v/8G4OZSsWk?=
 =?us-ascii?Q?cbjri1SzQNoe2kozbGH3VKVRyIdKuYDwpuSvHYm4V0y+GZYL3FGuCFbwpa8j?=
 =?us-ascii?Q?rgGYdOejRd+pc2WHkgy8AaRevXNw2UuH0K9CS/WkI9tFL19lzidoxok5qOrU?=
 =?us-ascii?Q?sBqg1b0gnIx+XERX1/XvmvoWuzaAqZmecs8bqD8YqW90cT9QIQ2yEwv8DT8K?=
 =?us-ascii?Q?Q0/RrpynaOipfxfJJbRWAoo6Ek0Eanpiw9Z7PxCzgrH1v3lWubJ5Eop4+aTC?=
 =?us-ascii?Q?Yk01TsYaSn1mrIYsc8ozoW+kulJ1rk6PIi5GwXsHeifgKZM6IYaBUhiGofr3?=
 =?us-ascii?Q?I6Z7pZwAI9yqz0hS/yjfO9+3UYu/kS2i8yN0rC8h9QoSqsdVAh8AQ3VbL6cw?=
 =?us-ascii?Q?7vIFszUYA+KK81eS1PBeghQ7uydfzZMUVkEVBZo7rcWzS2LTxyUlSPiS9bKz?=
 =?us-ascii?Q?/49HRotspbqGaETerD3vWMeH0vPPxBcf2NE0T2gMFb5mY8f3XsN+aT1bZDIw?=
 =?us-ascii?Q?4ScACl+n7VVB9DjE3LQOplt5pI0x67avQdHLa32Qao7kvjwKk2RJEiwNnLaX?=
 =?us-ascii?Q?Qp1nkGJ+MIQ3JC0LRlJJLrr+2RQGau1McZDcO5BbturKO4wq2twQscVOASWL?=
 =?us-ascii?Q?H5plxV5CdAFW03XuZfK4WBOGNyB1SgWsRF+u5hwgTjHipZ0fJSWcShDvqFHM?=
 =?us-ascii?Q?ERXftfJdUTj2LU/beDvOFlRekse0QkiIbGW73iAxAFoIewWo2lUr8MVa8GJL?=
 =?us-ascii?Q?3RfiT/fOOaslvqOfzexwpBPtiBN4VDOUyaJqcgXzCeRrJf/rv+CI9t5us6w/?=
 =?us-ascii?Q?08NgErHRSEclO4JLE5NEcNAjwPgLWlDUap80WZjl5+biRQgY3f5l8newo0Cv?=
 =?us-ascii?Q?pQ=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 4f661e9e-5dd7-42a3-528f-08dcb6bce175
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2024 08:42:33.3839
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: LGteDhQygDSpLDP7VsM/rba88yTHRjUqeaegI1hfTr9aLHlKXOQVgBjHojmAPNSNrzLM8hwGWPRGULaVlW2Mhg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB7497
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dr2umA4B;       arc=fail
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


hi, Jann Horn,

as you educated me last time, I know this b82c7add4c is v5:)
the CONFIG_SLUB_RCU_DEBUG is really enabled, and we saw lots of WARNING in dmesg
https://download.01.org/0day-ci/archive/20240807/202408071606.258f19a0-oliver.sang@intel.com/dmesg.xz

not sure if it's expected? below report (parsed one of WARNING) just FYI.


Hello,

kernel test robot noticed "WARNING:at_mm/slub.c:#slab_free_after_rcu_debug" on:

commit: b82c7add4c7fd6beefefbaf67e9a0378ec2e6ee1 ("slub: introduce CONFIG_SLUB_RCU_DEBUG")
https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master

[test failed on linux-next/master 1e391b34f6aa043c7afa40a2103163a0ef06d179]

in testcase: boot

compiler: gcc-12
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202408071606.258f19a0-oliver.sang@intel.com


[    1.253080][    C1] ------------[ cut here ]------------
[ 1.253941][ C1] WARNING: CPU: 1 PID: 0 at mm/slub.c:4550 slab_free_after_rcu_debug (mm/slub.c:4550) 
[    1.254388][    C1] Modules linked in:
[    1.255015][    C1] CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Not tainted 6.11.0-rc1-00103-gb82c7add4c7f #1
[    1.256371][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[ 1.257395][ C1] RIP: 0010:slab_free_after_rcu_debug (mm/slub.c:4550) 
[ 1.258255][ C1] Code: 00 c7 44 24 0c 00 00 00 00 0f 85 11 ff ff ff f7 c2 04 02 00 00 40 0f 94 c7 41 0f 94 c7 40 0f b6 ff 89 7c 24 0c e9 f6 fe ff ff <0f> 0b 48 8d 65 d8 5b 41 5c 41 5d 41 5e 41 5f 5d c3 cc cc cc cc 84
All code
========
   0:	00 c7                	add    %al,%bh
   2:	44 24 0c             	rex.R and $0xc,%al
   5:	00 00                	add    %al,(%rax)
   7:	00 00                	add    %al,(%rax)
   9:	0f 85 11 ff ff ff    	jne    0xffffffffffffff20
   f:	f7 c2 04 02 00 00    	test   $0x204,%edx
  15:	40 0f 94 c7          	sete   %dil
  19:	41 0f 94 c7          	sete   %r15b
  1d:	40 0f b6 ff          	movzbl %dil,%edi
  21:	89 7c 24 0c          	mov    %edi,0xc(%rsp)
  25:	e9 f6 fe ff ff       	jmpq   0xffffffffffffff20
  2a:*	0f 0b                	ud2    		<-- trapping instruction
  2c:	48 8d 65 d8          	lea    -0x28(%rbp),%rsp
  30:	5b                   	pop    %rbx
  31:	41 5c                	pop    %r12
  33:	41 5d                	pop    %r13
  35:	41 5e                	pop    %r14
  37:	41 5f                	pop    %r15
  39:	5d                   	pop    %rbp
  3a:	c3                   	retq   
  3b:	cc                   	int3   
  3c:	cc                   	int3   
  3d:	cc                   	int3   
  3e:	cc                   	int3   
  3f:	84                   	.byte 0x84

Code starting with the faulting instruction
===========================================
   0:	0f 0b                	ud2    
   2:	48 8d 65 d8          	lea    -0x28(%rbp),%rsp
   6:	5b                   	pop    %rbx
   7:	41 5c                	pop    %r12
   9:	41 5d                	pop    %r13
   b:	41 5e                	pop    %r14
   d:	41 5f                	pop    %r15
   f:	5d                   	pop    %rbp
  10:	c3                   	retq   
  11:	cc                   	int3   
  12:	cc                   	int3   
  13:	cc                   	int3   
  14:	cc                   	int3   
  15:	84                   	.byte 0x84
[    1.263025][    C1] RSP: 0000:ffffc900001f8d70 EFLAGS: 00010202
[    1.263973][    C1] RAX: ffff8883ad600000 RBX: ffff888100bbb480 RCX: 0000000000000f01
[    1.264356][    C1] RDX: 0000000080000000 RSI: ffffffff8e009f01 RDI: ffff8883ad604fe0
[    1.265346][    C1] RBP: ffffc900001f8da8 R08: ffffffff92b46324 R09: ffff8883ad206890
[    1.266351][    C1] R10: ffffc900001f89c8 R11: ffffffff92b580f4 R12: ffffea000402ee00
[    1.267008][    C1] R13: ffff8883ad604fe0 R14: 0000000000000002 R15: 0000000000000f01
[    1.267008][    C1] FS:  0000000000000000(0000) GS:ffff8883af100000(0000) knlGS:0000000000000000
[    1.267397][    C1] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    1.268008][    C1] CR2: 0000000000000000 CR3: 00000003a7662000 CR4: 00000000000406f0
[    1.269367][    C1] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[    1.270360][    C1] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[    1.271351][    C1] Call Trace:
[    1.272002][    C1]  <IRQ>
[ 1.272207][ C1] ? __warn (kernel/panic.c:735) 
[ 1.272994][ C1] ? slab_free_after_rcu_debug (mm/slub.c:4550) 
[ 1.274014][ C1] ? report_bug (lib/bug.c:180 lib/bug.c:219) 
[ 1.274891][ C1] ? handle_bug (arch/x86/kernel/traps.c:239) 
[ 1.275231][ C1] ? exc_invalid_op (arch/x86/kernel/traps.c:260 (discriminator 1)) 
[ 1.276013][ C1] ? asm_exc_invalid_op (arch/x86/include/asm/idtentry.h:621) 
[ 1.276976][ C1] ? memcg_alloc_abort_single (mm/slub.c:4524) 
[ 1.278267][ C1] ? slab_free_after_rcu_debug (mm/slub.c:4550) 
[ 1.279254][ C1] rcu_do_batch (arch/x86/include/asm/preempt.h:26 kernel/rcu/tree.c:2576) 
[ 1.280013][ C1] ? kvm_sched_clock_read (arch/x86/kernel/kvmclock.c:91) 
[ 1.280520][ C1] ? sched_clock_cpu (kernel/sched/clock.c:270 kernel/sched/clock.c:405) 
[ 1.281010][ C1] ? __pfx_rcu_do_batch (kernel/rcu/tree.c:2493) 
[ 1.281504][ C1] ? __pfx_sched_clock_cpu (kernel/sched/clock.c:389) 
[ 1.282010][ C1] rcu_core (kernel/rcu/tree.c:2845) 
[ 1.282430][ C1] ? irqtime_account_irq (kernel/sched/cputime.c:64) 
[ 1.282941][ C1] handle_softirqs (arch/x86/include/asm/jump_label.h:27 include/linux/jump_label.h:207 include/trace/events/irq.h:142 kernel/softirq.c:555) 
[ 1.283144][ C1] ? __pfx_handle_softirqs (kernel/softirq.c:512) 
[ 1.283666][ C1] ? irqtime_account_irq (kernel/sched/cputime.c:64) 
[ 1.284147][ C1] __irq_exit_rcu (kernel/softirq.c:589 kernel/softirq.c:428 kernel/softirq.c:637) 
[ 1.284609][ C1] sysvec_apic_timer_interrupt (arch/x86/kernel/apic/apic.c:1043 arch/x86/kernel/apic/apic.c:1043) 
[    1.285176][    C1]  </IRQ>
[    1.285640][    C1]  <TASK>
[ 1.286008][ C1] asm_sysvec_apic_timer_interrupt (arch/x86/include/asm/idtentry.h:702) 
[ 1.286008][ C1] RIP: 0010:default_idle (arch/x86/include/asm/irqflags.h:37 arch/x86/include/asm/irqflags.h:92 arch/x86/kernel/process.c:743) 
[ 1.286008][ C1] Code: 4c 01 c7 4c 29 c2 e9 72 ff ff ff 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa eb 07 0f 00 2d 63 e1 35 00 fb f4 <fa> c3 cc cc cc cc 66 66 2e 0f 1f 84 00 00 00 00 00 90 90 90 90 90
All code
========
   0:	4c 01 c7             	add    %r8,%rdi
   3:	4c 29 c2             	sub    %r8,%rdx
   6:	e9 72 ff ff ff       	jmpq   0xffffffffffffff7d
   b:	90                   	nop
   c:	90                   	nop
   d:	90                   	nop
   e:	90                   	nop
   f:	90                   	nop
  10:	90                   	nop
  11:	90                   	nop
  12:	90                   	nop
  13:	90                   	nop
  14:	90                   	nop
  15:	90                   	nop
  16:	90                   	nop
  17:	90                   	nop
  18:	90                   	nop
  19:	90                   	nop
  1a:	90                   	nop
  1b:	f3 0f 1e fa          	endbr64 
  1f:	eb 07                	jmp    0x28
  21:	0f 00 2d 63 e1 35 00 	verw   0x35e163(%rip)        # 0x35e18b
  28:	fb                   	sti    
  29:	f4                   	hlt    
  2a:*	fa                   	cli    		<-- trapping instruction
  2b:	c3                   	retq   
  2c:	cc                   	int3   
  2d:	cc                   	int3   
  2e:	cc                   	int3   
  2f:	cc                   	int3   
  30:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  37:	00 00 00 00 
  3b:	90                   	nop
  3c:	90                   	nop
  3d:	90                   	nop
  3e:	90                   	nop
  3f:	90                   	nop

Code starting with the faulting instruction
===========================================
   0:	fa                   	cli    
   1:	c3                   	retq   
   2:	cc                   	int3   
   3:	cc                   	int3   
   4:	cc                   	int3   
   5:	cc                   	int3   
   6:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
   d:	00 00 00 00 
  11:	90                   	nop
  12:	90                   	nop
  13:	90                   	nop
  14:	90                   	nop
  15:	90                   	nop


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20240807/202408071606.258f19a0-oliver.sang@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202408071606.258f19a0-oliver.sang%40intel.com.
