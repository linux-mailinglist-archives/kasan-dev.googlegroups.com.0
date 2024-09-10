Return-Path: <kasan-dev+bncBDN7L7O25EIBBM5KQG3QMGQEMZIOZDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id AC34B9739B0
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 16:18:28 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-7a9a653c6cdsf584863185a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 07:18:28 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725977907; x=1726582707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TYkOIkI/n2m8VSpLQ4uK4UMLQN4FNH3R+BBn3Kmh99I=;
        b=U5U/KKScLDBfvr4PnK3mUtu+gtRr9pzZeNTwZ4azCabQureCAItuS6tS2iySgaIqzJ
         BatsXwX85EAGZGEDsDRIZuiwvl9vr9e8xIcInmVPb8tLJgDBDkCxGDOLbpE6e+b14vZ3
         fQi/GZl4Q/77QlQKMoUEbOakh96XJNlP1qsi/xVvRWwN9qUSzU6TdgmjMscCfqpCdOpk
         dAmIrF7feb7Tt8jSNdA1gLsQrhEn62tcxNO6FG9uoUUJ+5pIDHitAXpKVx3d3Shkkm/p
         aQO4PLHKi48vvYe5JV05sZmmJOvCCui+YBR1M+/RP8VUQQ431IJmC9bPfcRuSTfAPttp
         qdEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725977907; x=1726582707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=TYkOIkI/n2m8VSpLQ4uK4UMLQN4FNH3R+BBn3Kmh99I=;
        b=a4cgX8F32zybpjaL/4Fnl1K9Q2KPmsu6P0TBgKnyAGO4jKT3bBvRj06zJ0DD8Kmmcc
         7c5HgP4z9hdnorpVm8avWAcHum1iO6E+KT3z8d595H3B0wEje+c6z7hp7p4lq6n3pdS3
         0OjZvv3k+3xSg7255XeNu908bYlI2GWoSXIwP28AG8qSyIkwVhpM/dmijClrCkyhXPT7
         g0XAHHeIrY1xIab6w7qspmLUC/rUd3KjxotYFOBHG292y/tTNVxSO/r5cIlhDTloPIxS
         rqkcifS/Pcxj+BuRCJucc2g/138LdxvnWkllPmgLyFSioL+89jD7wS+yrRSi9z8nuxS5
         FPFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXy7B/s5+0RziuT6ewUlrCRFQFlzXYNIE/M7VghRgRh6tYywxsc3mdBYTX/q5GLVKsjFlE9kA==@lfdr.de
X-Gm-Message-State: AOJu0YwEBGHE3aix2HQRaXy5BvV5A9y4FDdFSN34yTMXNdseuL5dyIde
	zFGZl42ApC0SttNxvxvnnhbgQe4p1h1AOg7qAUp7PqJpLnu/Db8w
X-Google-Smtp-Source: AGHT+IGGxRJc70j/UQwjQKvtp+Tumi5oMbwTHpNGlktgi27f07lHMlcxMxQfXC3Se0sN0m9hZt5z5Q==
X-Received: by 2002:a05:6214:3b86:b0:6c3:5454:6e1e with SMTP id 6a1803df08f44-6c554d6ffe3mr57461286d6.24.1725977907421;
        Tue, 10 Sep 2024 07:18:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5966:0:b0:6c5:1cfa:1e03 with SMTP id 6a1803df08f44-6c527c31af2ls2883406d6.1.-pod-prod-00-us;
 Tue, 10 Sep 2024 07:18:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSsv+E4qXYD4nBnU1lXnwLzORu6+RMMWGSj2ahdkLb+fML4bDfiJLS3Y5oMLR1EG8/BlqNGtiWbDY=@googlegroups.com
X-Received: by 2002:a05:6102:e0e:b0:49b:c738:4a50 with SMTP id ada2fe7eead31-49c159cf5demr2395803137.2.1725977906679;
        Tue, 10 Sep 2024 07:18:26 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-49c16d6becesi136271137.1.2024.09.10.07.18.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Sep 2024 07:18:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: /y/VmEAORAaxZ3U7YV3Weg==
X-CSE-MsgGUID: vASZNIuTSPijjTZYNnomaA==
X-IronPort-AV: E=McAfee;i="6700,10204,11191"; a="24271244"
X-IronPort-AV: E=Sophos;i="6.10,217,1719903600"; 
   d="scan'208";a="24271244"
Received: from orviesa004.jf.intel.com ([10.64.159.144])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2024 07:18:25 -0700
X-CSE-ConnectionGUID: lgqwb18EQFevkvZAJpFsJA==
X-CSE-MsgGUID: 46rZcYu/TCKNdGwDIqUfmA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,217,1719903600"; 
   d="scan'208";a="72029963"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by orviesa004.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 10 Sep 2024 07:18:25 -0700
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Tue, 10 Sep 2024 07:18:24 -0700
Received: from orsmsx612.amr.corp.intel.com (10.22.229.25) by
 ORSMSX610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Tue, 10 Sep 2024 07:18:24 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx612.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Tue, 10 Sep 2024 07:18:24 -0700
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (104.47.59.173)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Tue, 10 Sep 2024 07:18:24 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ixKimrXXiAndg7vxZ5Z2yV+GdD/X9QG/IsGJKUU+XgDMvXXB3GLYkWg9y1lxK+l1QkBCy07Nm4Pk8ktvYcclY5aAGAWWFyYwVDEUrDWp6TsmJijPvwVGvqXkcIE/8iy4OYDyvfynPTOzDpq44hzHUMT1wEfdZ6acRBnmsYVVUIbjCD6Y9oiizZ9zqCaFsiIvXnxsxoydOqRHAu6+wLSuarX19GuQPW1xAUb4P2rzNuIi9d4RkQhYx/NxpE5LrkIQeq+6HhhPCYE8q7wM2AIhNYLSbetGiYl5uup6HcBwU8+RwFNs36KKJWL2JCbvpscoFv5YrKW9WRnIFh7tSj9PNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=vq+EYJmY9+RqFTJZO/ubOVl6JI6t1pm73ZjZOZOo7NA=;
 b=Bf4T/tvThTiZcdZTHuU27LXi7qGcihXqgQnbsxnToyNCJHPsDpyHr1A19j69bzTXnYFKqbTKxTvYz3ilhBb0mSnrHLZeDXpkbAG0PbU8YAR3grBZ3DEKNpC+GSyFmaIsETO4GT8zlSJeeNTbK9D6eNA9nh4B+6CRRTFUf1APraSxpSaaGOyq0+CpXw/Ui3oQ6CBUS4PzmbMfb711Z83/CZi+BHbaWI85NC3fe0Et0CgmKjuvETRnk1c9AmRjavyHYHMZ7LRAw5YzjQdw8Mculnz3BUxhbjmJQDzdMxQB5BXG+CD02r84VqTIBS9H+yuw1N+UK30PT5f3TEs2El+6ww==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by MN6PR11MB8146.namprd11.prod.outlook.com (2603:10b6:208:470::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7939.24; Tue, 10 Sep
 2024 14:18:22 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::7f88:f3b1:22ec:f508%5]) with mapi id 15.20.7939.017; Tue, 10 Sep 2024
 14:18:22 +0000
Date: Tue, 10 Sep 2024 22:18:11 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter
	<cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, Marco Elver <elver@google.com>, Shuah Khan
	<skhan@linuxfoundation.org>, David Gow <davidgow@google.com>, "Danilo
 Krummrich" <dakr@kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 3/5] mm/slub: Improve redzone check and zeroing for
 krealloc()
Message-ID: <ZuBVI2DXyeZ15lTZ@feng-clx.sh.intel.com>
References: <20240909012958.913438-1-feng.tang@intel.com>
 <20240909012958.913438-4-feng.tang@intel.com>
 <dee10b40-0cf5-4560-b4e7-6b682de3f415@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dee10b40-0cf5-4560-b4e7-6b682de3f415@suse.cz>
X-ClientProxiedBy: TYAPR01CA0021.jpnprd01.prod.outlook.com (2603:1096:404::33)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|MN6PR11MB8146:EE_
X-MS-Office365-Filtering-Correlation-Id: 41a3d09b-6d58-4203-2fd2-08dcd1a36d2d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?zLst8W95XduiIwqmBWf4U2Meh+NGFRTBYDRG2yJhye6DD19XCUkpN4fVT5rT?=
 =?us-ascii?Q?0LoBfD0RfrF8IYb22VL+DwhpgadHvN7AZU0qAvoumT527RGzbEF0BG7GGrZ9?=
 =?us-ascii?Q?4xnudPxLnGgUmPl3Grfbr9Rf2HjT1FTylXTP69jf5LVbKEGdz6W/LAPBNTTP?=
 =?us-ascii?Q?unDQ6tbbwnuLmTluoyojQughuDDJvh+ZF/LMIq+ZKABs0KmUFE01tpF1g5H1?=
 =?us-ascii?Q?rNgpn7TojvhbcKzHMaW2LupzwUu/tmxHn8ncqnB4lBIgfIAG3xawOBKRyU6/?=
 =?us-ascii?Q?kAFNAAe3z++JSF//ZCNAi+4X2wPVfgAtqRvEvhrOB+mEvrR28MW5kjfso8Om?=
 =?us-ascii?Q?HKp7NEcCmuFe/zQ4R1EHaAowOvaQ9YDr9LWvwqqflUZlAj6cYwrranJbHQSW?=
 =?us-ascii?Q?9mUy/FsfkKimrgoFcoWfwTzdix01Z9Jf0qdeWMZ+NnTOluuAZHO0XXVKHzl/?=
 =?us-ascii?Q?MyJmiQ92aMZnnE/lHH2chKqiwjKAurkRvkDB4dqHIqcMgV/c1wiX1Yel3jEU?=
 =?us-ascii?Q?M+mNDA82P7sIKe3vehEW0Z1J8qvozPbk8j9qvYl0vz8xRG3PMyJRuF+bK9LG?=
 =?us-ascii?Q?QjBZqNPZ8tjc8y4Xyy7qRiXwjmqs0jaQbf9jHUKPvSx/btiXCbbp7e6J9/OB?=
 =?us-ascii?Q?E6eafypI32yCqouQSrflA2SjkEzPzk9oRTgCzTkC/xyrv+LYH1W5tHrL9oGj?=
 =?us-ascii?Q?kb6M7tKDRrhWVY0ZQoXvErzzcgAiNQ2s9MbCMpgckfXTiAjbjkNomex43HW1?=
 =?us-ascii?Q?5pVliLCJ2syz9LkF3y1ApmgR2J0P0AMcNUH2pWa00DUVR19Ji6Jbh96voc2k?=
 =?us-ascii?Q?5Z6Ns+xTtSUDtjlSv5fxbvMR5TT2nyXChSnShlT3YSlR1TwoSqKhbzUW5j7N?=
 =?us-ascii?Q?MnJjUTlHXG9Qe6KYyGM67+rgNOHjx9q+5xcX76Hdbsev/eJxsyHoYgI+cnar?=
 =?us-ascii?Q?Y2/OsZvzAsRxrT/zWozi+EQp6lB/zxjQm0xPlZ8esiYNQLiQnUnTd6nZWKN2?=
 =?us-ascii?Q?WqqEQ8rdPp23DUurKv1qLC1drVMlnbR05pt5FQ9W2SC9Q5HaZF47+vpalji4?=
 =?us-ascii?Q?o0hRu8JD67JUH02HcmW2+VYN1CRV1Xwf+8zioBKeSt2z7ZktBBt11L5KMW03?=
 =?us-ascii?Q?THWS1Bhu81uu73WOZcqLYnQEy8I1Qj2v/r0THsaJJ8P6q+eFDHLP25xOwDBb?=
 =?us-ascii?Q?fus+I5+X3NNfzCtB3WaIoSVAZinHtLFa4sEt5b9TNVC0WFch7/hi4uraK98O?=
 =?us-ascii?Q?OOasrbjHUT9XMfnuskJx14D2oxOxUJLiGAyYkFn98qiMmLJ3qYLoKzXQVTsp?=
 =?us-ascii?Q?EW5NL7/VLN06iArVZC3k1/FvSn0ZCMUzDMsrVgdJsNIgfQ=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?5Ruet0koTHsT1tntLbIub9u+QtsFXG25NmO3bIPc4fjJ+29MR/w0+GHNejDe?=
 =?us-ascii?Q?tWHgTnOjEMyndY0ITvx/hM1zf2d6+i9xAma4eDdXxbzVN7zcOkGxrYqVBg6g?=
 =?us-ascii?Q?6QNjn9ph616GAxUfHW+/7KSdbDIjpb6xIF+C28rEHI3zriqZxXX637zds+aT?=
 =?us-ascii?Q?YVHakA+zm+KJS51aqCWl2BTwIwTdGRUrcxKU9Ggq5pDtSbb8WVscHtIjTZ3B?=
 =?us-ascii?Q?WMBpEZFHduwzTCElcTqCwWuC19FVjWpWB0G7onDya0fh80ncM8bmjblGf0jd?=
 =?us-ascii?Q?JvH41v4z6wUBp3U2hsSrkgF0J6rNP9FHwjblwj7tKjGEGeSa72Uz9ezJA+/s?=
 =?us-ascii?Q?wh4ND72v54+bytUYKjez1jjRIqBsCmWAZ3n+WNYUPlIWP7ILuv3nrIDSZulM?=
 =?us-ascii?Q?53K1qMZ7fFL5FVkyMvB/tg/Kzb+UHlMNVDFRf3IrSnoEuadf3ji1PXN/bt7z?=
 =?us-ascii?Q?3GPH9jt3df+zABb4ZME7LU/bfhv4RzUKeb7H3ailWxWyrdtZsmSwYYr+CwX3?=
 =?us-ascii?Q?kg36th8+StykxLqD5T/vEaofY/dlW7v0mZ7O7fv0Y/a5jGz1yU4cljlVPxy+?=
 =?us-ascii?Q?3SynJXofXzk4mJC7MJ0omdwS8W3x/aRjhWoxWNajSv73tBoEN1VzfiQUm+QN?=
 =?us-ascii?Q?dfD6tVjohxFTheXCqIXGnDZm0SGMvyoBofkwOl/dp7Ui4SLVyC+Bl/qBRE2I?=
 =?us-ascii?Q?SU8j4rnRCY/WiBTwa8m5zT8Q65Z5j4dtkyMVpALMnFRlLKq7UG3CXUHKM8Xj?=
 =?us-ascii?Q?s8bpcmeOuINZ2zwZS0MvT5bTtfr2lWiDckOEonoHK9hjRD5Hbvj0g/k8XRvE?=
 =?us-ascii?Q?3uIH6MFKr4HV0KhMFeryzlTy052z4w95aOmGR1fqxj11spbMKDV6w621OdUH?=
 =?us-ascii?Q?fpvYsKD0Q7e6d3LRJ8pxGWDa5wWEE9X0ClNty5p3bT7Jgbe8+ucU+cDZSihQ?=
 =?us-ascii?Q?ujeJX+e73SCj2Rv3ZKPKs0D5eM/kmj4kNcf3ePb/F7S2Dvqo1LXvfxiU7YDd?=
 =?us-ascii?Q?F/ocDdf81qrvApXhVMwP2qWr311m4rGpQvqmKyiry8fOe6CxklI6vuo1TIQ2?=
 =?us-ascii?Q?dA7oKvf9xA/tW/VGMvjDJ1CHuGmySrSDxtgBcp1SkdntcOVXhcQJ9s8cP86c?=
 =?us-ascii?Q?3AhuutDv1pyM9+beTFXdtFKxpXvr+WWCtS5rIUhdOGIsfbs4stpQ8KfDsCSi?=
 =?us-ascii?Q?Tc6J3ay3p7SMD1F0zOHikjmy4NRHIZn8uSRisUP78g5vzq8nXga77pI1H0EJ?=
 =?us-ascii?Q?Jz1zYe3WFUv9dF1yRn5fcmQPoHpVzi4fRjKYpLK4CaEQVkHd1nl8DfkFasoM?=
 =?us-ascii?Q?isu8ZtT3MA7jKFaVu/TIR1ywOssjT/28j9qSK3yXTs5S22KCmC+83fHikktY?=
 =?us-ascii?Q?bgAEJmML9MDPW6sGzQZdrTWn613yFUXngqVx3tpATsHbBAP9AOEYt8olzEDE?=
 =?us-ascii?Q?mQrJ9KqeWKYr0rK8dsWpSB4QyhUNccPMkgxR67xhRv0MFONWUoA4xW6WD/qr?=
 =?us-ascii?Q?QxjPEdqHIyJqyUkukXChqOXLIzjJlSC0O6vepk18slgphTo6pU16kUuaxe17?=
 =?us-ascii?Q?NqQe4fKguxzitK3tHtmLfAv4alv/4pSiXLWcXFNG?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 41a3d09b-6d58-4203-2fd2-08dcd1a36d2d
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2024 14:18:22.2336
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: BSlAzNDaNYcpbdhIGejhcoUbf/1jNA/gbwflRKDF15yEAfhmmNwUhwZlsdnpLwakID5Tc6dP7lYqn11XaHmrZQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN6PR11MB8146
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="csImg/AV";       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.198.163.19 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Tue, Sep 10, 2024 at 03:15:36PM +0200, Vlastimil Babka wrote:
> On 9/9/24 03:29, Feng Tang wrote:
> > For current krealloc(), one problem is its caller doesn't know what's
> > the actual request size, say the object is 64 bytes kmalloc one, but
> 
> It's more accurate to say the caller doesn't pass the old size (it might
> actually know it).

Right!

> 
> > the original caller may only requested 48 bytes. And when krealloc()
> > shrinks or grows in the same object, or allocate a new bigger object,
> > it lacks this 'original size' information to do accurate data preserving
> > or zeroing (when __GFP_ZERO is set).
> 
> Let's describe the problem specifically by adding:
> 
> Thus with slub debug redzone and object tracking enabled, parts of the
> object after krealloc() might contain redzone data instead of zeroes, which
> is violating the __GFP_ZERO guarantees.
 
Will add it. Thanks for the enhancement!

> > And when some slub debug option is enabled, kmalloc caches do have this
> > 'orig_size' feature. So utilize it to do more accurate data handling,
> > as well as enforce the kmalloc-redzone sanity check.
> > 
> > The krealloc() related code is moved from slab_common.c to slub.c for
> > more efficient function calling.
> 
> Agreed with Danilo that having the move as separate preparatory patch would
> make review easier.

Yes and will do.

Thanks,
Feng

> Thanks.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuBVI2DXyeZ15lTZ%40feng-clx.sh.intel.com.
