Return-Path: <kasan-dev+bncBDN7L7O25EIBBU4G763QMGQEF6T7K3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 61DCE990124
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 12:28:37 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-7e6c40a5795sf1232739a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2024 03:28:37 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728037715; x=1728642515; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AStuh1nRi6UE7jaxcISqScEX7bxIrdOCc2KalGg+gnA=;
        b=FNog5V6Zd09cV/o7gDegs6l7RKPlzAQMS5oqMLzNiq4MZ4FkhJPkzTdytsYr40SViw
         7+I+ZKOBWOOYQ5wJUO/XwMe/HTANO69qlMTAKshntcaV32lH38ZBFnZNTgcGEKkxK6TM
         h/udPEjb5jKI1bU1BXmw8lcTvv4myHyNYQ09xUqxlhE0mNaIBEvgpqM5f4R6zHJViLfN
         YCA8HBS4asUgi4sfuZSmRCt+6dV49QS0uNJ6fb2+oDeW86iCG7h/FbqQ1jUZvq1Y3XuJ
         GQw4F+1aXtXJJ50G0XewMvv2Wa5aXYf0QGPGAZfmRR2o8Teo+UmMBK+5vYsbYO4DgPyo
         N4xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728037715; x=1728642515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=AStuh1nRi6UE7jaxcISqScEX7bxIrdOCc2KalGg+gnA=;
        b=TXJXN/KeDPu7+qfXIa2DgbCsphbkOUs/IbyyoNLkKXhNaziNHbG7F8HhSt/koMWSz7
         JWH9BAvntTS2OxHrXVNbCf75U4kdKbk3YFEmcxeQ4ZUYu3URxHfpipSPJ2C2aT/kr1bF
         aS80QOUa8mQnqrekX16cAVOIvtC/8p0jD2jE0fCMn1R8J9i2opGWgUQD4jCrXaNlqWWe
         w6Z8fmEWHCKwPcVSQzHpbB2YLL9Yt9ea6qjLuXjTw4MO+NEwyBIHqBg+XnSZgP7bjTXt
         7nRf8UkUYY4q4416EXCXNz8P29ZMwO9Ye7SK7SpyuMeCoM4LVL7Q7cy+DA58JZ1/ebCq
         He4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9Ac3/lYgA8TjErRthUb1tG2rtV8HU8Ae/j5A55uTEzsDMf/Zh8EmDeT9bMUZFP5+8Ulp6Pg==@lfdr.de
X-Gm-Message-State: AOJu0YyG66LXRr6zM5JdB0XnJs35XYe06g6YM5G1BH1qauXQcxb8FfSr
	0/FiBwvCAHacfvrP+qDLkk/759YklKFOvEPFEHlQWyNC/o+lLoQv
X-Google-Smtp-Source: AGHT+IEZDuvFA9bmXDbnfs4R2WYutlBAnmDkgE3vPEwJe5kbtiFWvDpPhZayzVELAbNXvl7XnJKpjw==
X-Received: by 2002:a17:902:da86:b0:20b:bac2:88f3 with SMTP id d9443c01a7336-20bff03db85mr27925225ad.53.1728037715245;
        Fri, 04 Oct 2024 03:28:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e549:b0:205:40cd:9c7f with SMTP id
 d9443c01a7336-20be2e42054ls15324975ad.2.-pod-prod-02-us; Fri, 04 Oct 2024
 03:28:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDS5ykvxRSFfphWKbHyAdBjgOLfEbxItz3WvxY+S392LnHBcvK/RMJcCImFF+vSS0sqMXwCQ0FjCs=@googlegroups.com
X-Received: by 2002:a17:903:2301:b0:20b:a739:bd60 with SMTP id d9443c01a7336-20bff03522amr24842655ad.51.1728037714020;
        Fri, 04 Oct 2024 03:28:34 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.14])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20be9790e95si1290245ad.5.2024.10.04.03.28.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Oct 2024 03:28:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.14 as permitted sender) client-ip=198.175.65.14;
X-CSE-ConnectionGUID: o99bTlJ4QSGAEZAKq5zRLw==
X-CSE-MsgGUID: wPBPkQskR/amtx39SajwKw==
X-IronPort-AV: E=McAfee;i="6700,10204,11214"; a="31051905"
X-IronPort-AV: E=Sophos;i="6.11,177,1725346800"; 
   d="scan'208";a="31051905"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by orvoesa106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Oct 2024 03:28:32 -0700
X-CSE-ConnectionGUID: ZNqBzDppTGyo1pG8kr7Bow==
X-CSE-MsgGUID: o/PvG45CTtWbKL1uxdQ4Wg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,177,1725346800"; 
   d="scan'208";a="74493957"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orviesa010.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 04 Oct 2024 03:28:32 -0700
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Fri, 4 Oct 2024 03:28:31 -0700
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 orsmsx611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Fri, 4 Oct 2024 03:28:31 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.41) by
 edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Fri, 4 Oct 2024 03:28:31 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=nMPtj2c7IPPo9ArC45YZuFy4Bm7IXUKPoncSoeK5y+01s1cFjt9FkqHKhhSuP/kq/jXjfvZoLVjBU0F8rJ5x1msMbhF1kxU4tZFryMaSOmjyLXz2kg+LixBILib9/a7TbDfLYmcQRqlt8qo6yNx/52QEvpmfe7J5ExNnzTZ1oz9x483zNgWEr2/kEj2gmYfWi8lAABNcPaVDONLuhfVb4mX7ww0fHNpXbQNMi1+gmZH61DDfYP5neKdtdgskhPFb6MuNwTS6BcSdweJmMiNTd/9BH/Yd8tyDkWCcBTeOJ4X9ZmyDp5kXkvqGi0TrnjBNxpqKnTdseFMTMF+q9972ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=fq0mMuNtSGHuc6SdW1Z6Sm0XdSzuQ88zXNqMvn/nbIs=;
 b=o33uPoHdDBoVfRXHeAOa7Dbw5WnPG/pO6P+kg9vjDG34Lw3ze0euKYa/JiaIBc1XQFGYrFVAknJG4PVsQpZ+VynH2XLG7iXu+lKjF/KQsih28dNTl1YQtd2ME3+uTYyEvPFOcSQFnqx3X+f0znKtAEquBh/fh2Vh7a37dqMTu3YVKYnqo+uIxABFad7wSMxSPs/SO9XrxD6iGPyeIr5ZTyzZq6al+wMS6of0V68vI/NRkxDIUzDaqdLMwg0uinCcgNu9LSJRlXXzqvMhFyyIhRMd8+M37OuotoXLd9pTwe4j7c1wpPf0WX79S0f1NEB+QYDmC/ekzoUNVthmNzzrsg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by PH7PR11MB6007.namprd11.prod.outlook.com (2603:10b6:510:1e2::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8026.19; Fri, 4 Oct
 2024 10:28:27 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508%4]) with mapi id 15.20.8026.016; Fri, 4 Oct 2024
 10:28:27 +0000
Date: Fri, 4 Oct 2024 18:28:13 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, "David
 Rientjes" <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, "Roman
 Gushchin" <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, Shuah Khan
	<skhan@linuxfoundation.org>, David Gow <davidgow@google.com>, "Danilo
 Krummrich" <dakr@kernel.org>, Alexander Potapenko <glider@google.com>,
	"Andrey Ryabinin" <ryabinin.a.a@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, Eric Dumazet <edumazet@google.com>
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Message-ID: <Zv/DPUKwJxMakVJz@feng-clx.sh.intel.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
 <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
 <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
X-ClientProxiedBy: SG2PR04CA0166.apcprd04.prod.outlook.com (2603:1096:4::28)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|PH7PR11MB6007:EE_
X-MS-Office365-Filtering-Correlation-Id: f44d50cb-721e-4955-51ab-08dce45f48e1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ODraKh8AWhNRMIHu9ecSI1ee9tBhUWuWQ83XopE63743Wh89WM+bojUB66Ly?=
 =?us-ascii?Q?nD5Ueig/0hsDHOEpIk2QSEp7LvXn3smBM4Ug7yj01cLb1kkiZlkY/Onvu3is?=
 =?us-ascii?Q?kX786Cx9mmptp/7mIV/oykDyRdwx/mOwFgayPnuJUvJs6wMUE76d6k+GyDKa?=
 =?us-ascii?Q?BONJkRa7nRQpL3yCehIhijlMB1dpJLHm8aMbXNBDA2GFJyZ94E7PWwI85yYA?=
 =?us-ascii?Q?ACONakQap9EHbvy9I3MB9IkK/zwQsnE/sahq/VZXUqfsK5DFIclTx/eXMf5v?=
 =?us-ascii?Q?jKrqtIOvRNkHhivBUMUrIgxtM92oyOz5uh36KalRdjSGT2AXpBSE3865AdKq?=
 =?us-ascii?Q?vx0EAtP1AyDecBdVUKPaIkTMmwyH8oUJ2/oz2UOkd+lErtj8VAjjuY97voq1?=
 =?us-ascii?Q?1LMGeqcGQNjr0SNPL/uPn22dTGnMyzCVAz8M35FaMwZggoS3XkTKmP95jXb8?=
 =?us-ascii?Q?iLlJGZo9l0p+s053O4OAl/Ok8aAnz7W6rs63IKsjsGQPCRfQRWexAH30hdaK?=
 =?us-ascii?Q?XCxCOZT5AV650Zay2+Npw7dS3Xr5xP2ulteWpqbTtASOQ5NAPKTOD7fCL3pw?=
 =?us-ascii?Q?EbIu34Jj12I0DB2Oj8v7eSDa+cG4sURemPl1xejCkxP9tqARcZJPylsZGaWp?=
 =?us-ascii?Q?8kNLLcrPyGnu7GG9oEuzrD5HF85E2GeYiMALoRBlRCG6EmOQA4vtO84iIll5?=
 =?us-ascii?Q?NEefjuiw+rzq88NqdGXpc7d6KMSMRZ1ijMWd+obXEKBi+SKlFs/+WVVJLJks?=
 =?us-ascii?Q?of0fpz4dEMOWrMhf5QzepIorvPkg2/qFgiiGQme5LxKOAdD/DHMKVyB1fXoF?=
 =?us-ascii?Q?aWzmYGHlV70XAtKVBmtLam61LHZpbG1RYuIqWVprTRm/+ZipP56bVszZRjIK?=
 =?us-ascii?Q?l2wTr8JOYwncJE9Lsl/6m1x25v+WTMbotgg3m7nos92QT8Obb3xHQ4jOPLdo?=
 =?us-ascii?Q?/vbuibDIpHw5MKun7yrwzki1Q4ZExRD5dwwP5Z085dqGpVGhm47aPyCD2VKq?=
 =?us-ascii?Q?0H+QtYiYEKRy67sF492UoTP0DnJz7mGOH8EdXov9uBO+zvgv7BR5unhMZ1ta?=
 =?us-ascii?Q?5UYEdJGV9I3aW0vlIOygjZdms5b5JwA57k8bCvIjPfZqarDc85j4Fg8rM0my?=
 =?us-ascii?Q?xPBSlsKrRZUdt5dYDM2qcAUjUKj8QS4bkCez6lSe38ZZNqLC5Yd2l/1rzhj4?=
 =?us-ascii?Q?iqxmR1hL1qZM9B3Dqsk38YHM0YQUfK8LXLlGL30u6RRyp5ZJ4qi5py21aIhj?=
 =?us-ascii?Q?knjAUt8ChSy5X6/WZDIaJRGYMPX6dRJ04kvu98H6hw=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?9ZMUgVru5ajH25SFt8VYeg/M8hOdkNi3PLU/REf/81dCpqcIL3nLPWLlwdag?=
 =?us-ascii?Q?mnkkhvkxEKHfzeX7il6CuJLsGQsxry0YbVTKVMt/M9FgeegGpomUpZEgfNML?=
 =?us-ascii?Q?9aE3l4qicGV0FEXr9z8tbSaGItEq4EO48hNxqUWF/xVdyLAbFQs5Dd7MU3rW?=
 =?us-ascii?Q?AuTae8OV0V9t+RD5y52YM65bksqRxD5mxo/3zhjlK7OGVHoI0gPvi9BetVxC?=
 =?us-ascii?Q?INWMj4sgHl8sAAOn9qu2jWcNf0V4AGxShlDaPwWWUSP13O+tGIgj3qNo2nJG?=
 =?us-ascii?Q?2HENkVIMTt30bpkbS+ZAbPvwjwmImkVEUR5s+4DoQRkX/L2eNj4QJcrg8vD1?=
 =?us-ascii?Q?sKN17xtD+Hyobx2t/8KHPgaLFRM0oYgAPsTCUjhjAiajLimKfdmkzN/rIGuQ?=
 =?us-ascii?Q?Xe0ehxb/mUexXtVWaWXYcQTQ+8sx3dN7GFID+0QXHC7HK2rxODKr1m01Xagr?=
 =?us-ascii?Q?kyPwU2vAHJ5YCV3NKNurNwkizkbtUddITbhJImsNWEcLYaYI8xvutz7wXlcb?=
 =?us-ascii?Q?3+rCuBM0lZL8y5UnvOoe2dVxR5mAfS7rRKsHMGvLyjgEkA8RiOxxvJwk/YlL?=
 =?us-ascii?Q?FTgmemEOMO4/b9jGb41g3+u3tGR5Z6GcXHMiF1axcyngVPXOavSDcEOMMSvC?=
 =?us-ascii?Q?2Vobbn6F68uFWT4a+c7aASHxeZMH39YcrobsJQiIg+lpE5xtChzcG2bmM5av?=
 =?us-ascii?Q?arm90m8K4KPohWYlSBpIxip244sATinK/5rXD8e/kepoE2L0CI836qeo1Dzh?=
 =?us-ascii?Q?S6jiJmKp/CX9Avrc9xMpRIi866NKHqzg52EAJYd+kFdKZxFTG0BSNw61FxLJ?=
 =?us-ascii?Q?uTRvSuOZfFzkuA0gqN80Hoz9Uu82r7wf21EGgSF7x+Zr1IOQJ9wdryH+zhoq?=
 =?us-ascii?Q?qN43dx4oCnbOtUWpE3l5YdHxviR4xLm4YstetBnbFRcKsng7h+o60/X9kIn0?=
 =?us-ascii?Q?m9wo6Lg7u+9kHqeI3k1MiSEo/hIMvdOjIzeoY07Mgi3pGZGtePak2zIjcT+f?=
 =?us-ascii?Q?4i+oRCDha4nK9oTrZVsdg3fpjjqODEuawZq1R12JzN/IGBArPcJhuuu9+FF7?=
 =?us-ascii?Q?UNInQ2u4LQOC4vYmCen6dWwgukpXLKY89oYsUQO/hUlNu4Q+L1PQg/JfJ5o3?=
 =?us-ascii?Q?o4LzOf8Svj6mYYiaS5PF1bu1STG536+zI9ZNj8RUipPSlqAxSS4UlyzZ4b3c?=
 =?us-ascii?Q?D9CyzrDfIzIYwUcRT6rQnbLiBFfQaaH/7QCgb+bzt+zyw8+uaoVTlvpLMil9?=
 =?us-ascii?Q?L44Obkz7ILcX/bdUkD7ALMnb0O0JhqDcuwxlhM3Ettnh42xuAKaLr+HFxZQk?=
 =?us-ascii?Q?VwFb4gS7MaLYdYffWRhXEfQvCYRrOHp9Jbgo2qG8eXvkw+v3WZSlB8vkYQ+j?=
 =?us-ascii?Q?j6QF5T7VhtCiPcE3sLqo8k4kQjzMOtzbV+i7ThieWr2B3uun1nfrf5/jh1VV?=
 =?us-ascii?Q?YczZvQo6dXVXWauAnEkt9T23h89JgeXkq0nN7m7Hh//6kZxoXJEcYXVDULsF?=
 =?us-ascii?Q?vVPl3FJa8CIf4wHnNrtjB5u7A+1lpcApS7X109z6DCagXR4hq1kXVxlXtBUG?=
 =?us-ascii?Q?JxG0aEv8UDZAw4/zwR4DVXtv/RFD37X+ZrFx3x8+?=
X-MS-Exchange-CrossTenant-Network-Message-Id: f44d50cb-721e-4955-51ab-08dce45f48e1
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 04 Oct 2024 10:28:27.6370
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: DKc/0z0u5SWZX6ix2DFJA3JJWcWW2l1ff+iq1paPocZ91PIqJJ8Qj6c4B7AY+qTuHwIcI9oyDb/fbzgXSbSzmA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB6007
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=B13d8CmJ;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 198.175.65.14 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Fri, Oct 04, 2024 at 05:52:10PM +0800, Vlastimil Babka wrote:
> On 10/4/24 11:18, Vlastimil Babka wrote:
> > On 10/4/24 08:44, Marco Elver wrote:
> > 
> > I think it's commit d0a38fad51cc7 doing in __do_krealloc()
> > 
> > -               ks = ksize(p);
> > +
> > +               s = virt_to_cache(p);
> > +               orig_size = get_orig_size(s, (void *)p);
> > +               ks = s->object_size;
> > 
> > so for kfence objects we don't get their actual allocation size but the
> > potentially larger bucket size?
> > 
> > I guess we could do:
> > 
> > ks = kfence_ksize(p) ?: s->object_size;
> > 
> > ?
> 
> Hmm this probably is not the whole story, we also have:
> 
> -               memcpy(ret, kasan_reset_tag(p), ks);
> +               if (orig_size)
> +                       memcpy(ret, kasan_reset_tag(p), orig_size);
> 
> orig_size for kfence will be again s->object_size so the memcpy might be a
> (read) buffer overflow from a kfence allocation.
> 
> I think get_orig_size() should perhaps return kfence_ksize(p) for kfence
> allocations, in addition to the change above.
> 
> Or alternatively we don't change get_orig_size() (in a different commit) at
> all, but __do_krealloc() will have an "if is_kfence_address()" that sets
> both orig_size and ks to kfence_ksize(p) appropriately. That might be easier
> to follow.
> 
> But either way means rewriting 2 commits. I think it's indeed better to drop
> the series now from -next and submit a v3.

Yes, we can revert now. Sorry for the inconvenience.

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zv/DPUKwJxMakVJz%40feng-clx.sh.intel.com.
