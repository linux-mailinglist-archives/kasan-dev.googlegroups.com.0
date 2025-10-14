Return-Path: <kasan-dev+bncBD2KV7O4UQOBBAEYXHDQMGQEHCX3BSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id DDAF1BD9943
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Oct 2025 15:11:30 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-28d1747f23bsf97509795ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Oct 2025 06:11:30 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760447489; x=1761052289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=R3eHINdyCczeQJNLMuEPZYZlyEIKBFyTSeU7nqwG8fY=;
        b=hD2ozavfwS/rwBx2tJe+pNcya+mui13FgbqQPEZ4Rq67ZRDdf1r4inBK22xfwq4Awc
         y/SKOQXxizk963ND4RJoY2eqtpIagWUvBOcjNgnBdukWbV2GzSDPfRQ985f5cL/K03Xt
         O1OYxytJ8vKMlo2JZgzmJ2/cQSICi2voc9bT7uOIl7gPT32pRBYqEK/x2MfzMUHtJnhi
         Emmkl733rTlUFH/U0SAKV+w9OKnqtltM+3aEwHzioQybYWjfapWrwlFSvke/2wUAclNd
         e5UYqAAVmITrouIOTGlKxZDZ2UyKkRpR2g0oFyl21NS3Ot3BfqcJo2YVJPPWqHGdfPbW
         Yt/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760447489; x=1761052289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=R3eHINdyCczeQJNLMuEPZYZlyEIKBFyTSeU7nqwG8fY=;
        b=e/QuqQQUxasbJBMSAQEBxUXhydUlgNn1SV1d7Ko5SJWfEOr8gdHRxgPfEEHWyqwW/h
         CHS2gohdiGCg1v1QCtBQGzwhQvtp7qpE4ByJfMIwUIIk3Q0f8GZVq1zQljMuRwRcBxtu
         CkyZxJUPgTyELnKG7RdrMIupXjAhPEJFjoLePzvkSh7eaD6u2rWUSWRatK2yTvJLf3Rw
         3iT5sFtOFywNU0STAXW2YDcUqusyvFFZgFJM0liHYLn8E6xcSDGN4E4dpqJWAc63qim6
         EfO2C/DDJSFIPGNnBu0MtMQAMY1bbtbNJPBhFEYykxqcOdNc9ep8rcI05h0lMNhZFA1G
         PDuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCU8ezA7AnaoR7iDGw6re7mdenKrQMx1bKSYDUUmOocCx9MC+oOfIA9aBzhpYWb4uwNlkOD9eg==@lfdr.de
X-Gm-Message-State: AOJu0YyQ8k/3SwvNdSv2zVZ6iVkgLhRclGNHg1yzVj3PAiVpRnkZ+Lbn
	jAAe+6IdgoDkBrb6x8GguQ2+Hgxl9G7yJHL5MNSjVwWLes8GKr3K4oGU
X-Google-Smtp-Source: AGHT+IEfslVLTTF6QIUW9en3H/80o3PApDfs6g7XoChYwj8zgIid0zQHGMUhgklY3Gf3naFj39xsNg==
X-Received: by 2002:a17:902:d54c:b0:26e:62c9:1cc4 with SMTP id d9443c01a7336-29027356c83mr254057705ad.4.1760447488718;
        Tue, 14 Oct 2025 06:11:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6ZR3J2OuOX6GgXd/BPyXPbCU58cm1W7f0jjPxo5H8yYw=="
Received: by 2002:a17:902:b696:b0:261:d3dd:29d9 with SMTP id
 d9443c01a7336-2903556551dls9394375ad.0.-pod-prod-02-us; Tue, 14 Oct 2025
 06:11:27 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXC5KSSXIcyoQTUEFx6DfGbqJuemi5gm6HbLLmo0/RPJ4QezVK/stMfv0FRo1g+MTen9SGO3gGObg8=@googlegroups.com
X-Received: by 2002:a17:902:e54a:b0:269:8f0c:4d86 with SMTP id d9443c01a7336-2902741e857mr358432555ad.53.1760447487122;
        Tue, 14 Oct 2025 06:11:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760447487; cv=fail;
        d=google.com; s=arc-20240605;
        b=jhIg57jlGzPly4hLt1vrMBFlo53jO/p7jrGu21l3c1Gy74hUx3fUVU8UARVwcCvouT
         vj4myH2S38scFGAmxxRWOhJlG9310/1qbZljZ0greqlYGBIGOsHU7CJbLG5MMX3k6cgN
         ErWh6RVFRHv8CpKof7pK0M9dV4dk5HA21Qqcw7LaKR9I5aPCAe6rW9p3hIhPsV/yJjJn
         YmVEKqeNPgNQ6fqYicyCfdd63lyEE68ZMaGAvTLGpIdkKJPhdb+lVYmK4x+XzPOfGoU6
         TR7BjKIV/eHBCXmSKzQWm2bWlTH0PCZrJir6pOA7vIEQxCWDLTmrhCSZHf4pvuZPyiQA
         zqlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ucIeTqC2MbY5O/6QjTpTpyU532cBqijbFuQ9gevZm9w=;
        fh=k+IlEDAyTa11EjVx0JkN6xtgbrocLuJCsDmyqLjazCw=;
        b=OfVUaYZi/VPafqIbrfwMsy0R8Iy/bnDJKo/XsOfRMHJ+7QZVibvFOr2kt6xfH6yRWi
         gYPMb4Fycfpw9Er0LG3GHDBEfq+jyopaHnTFLDrKyQYkybgtb5rUhEh08eSzouGLEhZ9
         hsK9tttzWc2UskJZVUWKmF4FVgGETXtPxdHiHPSpfRNV2PJvfr7ARv0koFcVn/SOZk/C
         a9dmVvzfdy93Dmxe32sDFuS4EVqPriGYAxToBe1mFyBlWQb473fg6Tu6pKqOtggmxLc/
         YS4A5rES0+NDHqPXsjWo3qG7ViMtZKi6JcoD2/u9IkqpOZrpwa1Gm11uCqwNtr9kvhnZ
         Fw7A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CKqhuPVC;
       arc=fail (signature failed);
       spf=pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29053824e74si7394255ad.4.2025.10.14.06.11.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 14 Oct 2025 06:11:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: IEd9cQwhSqG1c8TS1JKKOw==
X-CSE-MsgGUID: rSEzvv55T7q1Hk14hV3xEQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11582"; a="65228134"
X-IronPort-AV: E=Sophos;i="6.19,228,1754982000"; 
   d="scan'208";a="65228134"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Oct 2025 06:11:25 -0700
X-CSE-ConnectionGUID: zslZxQoxRrWST5Pbbqmq+Q==
X-CSE-MsgGUID: +UXQWOuKT3WxSp5BC6PVBg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.19,228,1754982000"; 
   d="scan'208";a="182341103"
Received: from fmsmsx902.amr.corp.intel.com ([10.18.126.91])
  by fmviesa009.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Oct 2025 06:11:25 -0700
Received: from FMSMSX902.amr.corp.intel.com (10.18.126.91) by
 fmsmsx902.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27; Tue, 14 Oct 2025 06:11:25 -0700
Received: from fmsedg901.ED.cps.intel.com (10.1.192.143) by
 FMSMSX902.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27 via Frontend Transport; Tue, 14 Oct 2025 06:11:25 -0700
Received: from DM1PR04CU001.outbound.protection.outlook.com (52.101.61.9) by
 edgegateway.intel.com (192.55.55.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27; Tue, 14 Oct 2025 06:11:24 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=sDqtpFJ0YScTVL5/AUH0+p6H38raAgTgj2pSS8Ye6YqHxKlzn71dlqhzAvRO46NmaqaxH2AMGuMxkZ8068xaY/6EtfvgQYmIuJkJc2umi8HWiaFZF4A6ZD6buy4MtLGOnnRumoXHp+f4pkAilf8dZZvUDGZ+9CvysOxkvQedl7JVPBmmtInUPieDBPF/VSsLVBoAF+JweC/qMeqmmNEMH90b3ONNk/GntmfHTxeuE4OcQpAzeLGyhCXa/wjgjndFoSDAxQyoqQhPjcTZT9z2gbOmJz2ThuCiA7Lp2zBSFWFgfECy5554cnnKbH6BHhL1/wo3t98RZob58tLumVyA7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ucIeTqC2MbY5O/6QjTpTpyU532cBqijbFuQ9gevZm9w=;
 b=G9ux0APKES9eU+m7KWSc8C3GiSRglqfLpdE45+Q4aC6p3c7oLM4D+AvcJVHz7GTAUclBtCLecyZC2sM7YcwGPL8m8qTGBWFdMgHXx8Vn2oGHqhbCKRbmkKARHHI6Eek9MILoKBre09Z3bkoX82YZHDHI/xz2I/gzJIcTJDbXkJHZQf2I4xWmEdZuvZB4Y/jED1B2PD/4CosFLhjbdhOpNh/rMrCq2ez9ZXzYuOPuLtv6IHvmqghvkgq76oZbw6A/fo8ajeQhcLSuOWsQ3jbDceqaJObY3AOs3EHXYso6XMU2sMqIVuq6/Hva706biT/8yjoAF+3wKfseM1qxQOmJFw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by DS7PR11MB5965.namprd11.prod.outlook.com (2603:10b6:8:70::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9203.12; Tue, 14 Oct
 2025 13:11:22 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.9203.009; Tue, 14 Oct 2025
 13:11:22 +0000
Date: Tue, 14 Oct 2025 21:11:12 +0800
From: Oliver Sang <oliver.sang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Alexei Starovoitov <ast@kernel.org>, <oe-lkp@lists.linux.dev>,
	<lkp@intel.com>, <linux-kernel@vger.kernel.org>, Harry Yoo
	<harry.yoo@oracle.com>, <kasan-dev@googlegroups.com>,
	<cgroups@vger.kernel.org>, <linux-mm@kvack.org>, <oliver.sang@intel.com>
Subject: Re: [linus:master] [slab] af92793e52:
 BUG_kmalloc-#(Not_tainted):Freepointer_corrupt
Message-ID: <aO5L8EG3nkFeBmM7@xsang-OptiPlex-9020>
References: <202510101652.7921fdc6-lkp@intel.com>
 <692b6230-db0c-4369-85f0-539aa1c072bb@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <692b6230-db0c-4369-85f0-539aa1c072bb@suse.cz>
X-ClientProxiedBy: SI2PR02CA0020.apcprd02.prod.outlook.com
 (2603:1096:4:195::7) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|DS7PR11MB5965:EE_
X-MS-Office365-Filtering-Correlation-Id: 0b9ee6f0-a16b-4505-ee3d-08de0b232bd1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?WdqJQepTPCbzGLHyn2KT32h/RK0AFOgptDOZGugIhgP924GXVsamZ9bGrAIM?=
 =?us-ascii?Q?+VVLBf4+VYM5KNw3Gf9LSlXD8N5xO9L65WkvCHOWQnfGFZ4CoTTpAc4uBkNE?=
 =?us-ascii?Q?O4xsz2lSrSjJoaBz702WgyAoDmI8Dx0p7BQSWnRyf55Fr64IklzIVnLx8Pfq?=
 =?us-ascii?Q?SpZWSpFoNhliVO7u/AhBBBxwpguBbATQ5u8o8O/53DH4vTp+3erVpZ1YvXD4?=
 =?us-ascii?Q?2rLWYUG7L6zzCFKyxdW02mzTJmCYfshHpg0wRkrHHyEHO/7pjX1H+E7us+Og?=
 =?us-ascii?Q?cCg5VFPFfGRaJFN7xJwe/Kq0Wyu38SYoZG3Z/0BhmQraXOwKZDQd0Pe6KUiX?=
 =?us-ascii?Q?KO3EmRC9IkKtK1weTozTdJg85+QRUyaHf5Bg1/OfxLW6rshB/wn8K9e6Dp6v?=
 =?us-ascii?Q?z513/acu78Klfytn88rQiMLPoOCknCjnz0k0mtxAOv/b6XXqMGOAbFxfVOHD?=
 =?us-ascii?Q?DAcFS1RDudlAWUYZSnVt9/MqejAR4M35qy6J7fKFXHgnFGulyBDpbjGIwqR2?=
 =?us-ascii?Q?/bh3+6YGko9fGg5tTn+ZXlHF/EKsGl+8bQgW2VmzHs4/W2XrGDXJlmb2NdI4?=
 =?us-ascii?Q?mc7mmmDHNhDOC1YaFMlTyVEsmeQbJCjDwf13XwU+bNRIbBHiQKma2W0b6Wr4?=
 =?us-ascii?Q?9QXwhH54jhQISphUmoKLktCdwoh41qF4ejxGwnNl/qjoLbqyeA+X0jxXqUiv?=
 =?us-ascii?Q?tce2Eb3fWAl1cHCyKR+UZ5COmSNkxf3Ml/pXKEZ/acizl2GFkb3jx/S7/yl1?=
 =?us-ascii?Q?9ei/ELPadHPO+440bvycZ0VuuLfhyU2W5kou1d0JEgHesRvPR/tXWaMDAZ9l?=
 =?us-ascii?Q?sz3x4pd1cUjn+chjBlh4cZ/CcsJnXC/d2NR/2N2DCd1YHNYUZJ54y+/oAeNT?=
 =?us-ascii?Q?zvKXjHG+xaEPfspx7j4ZUp3I11j4lRnYp+O19zki3bgvdYxs2VlHUV/AdI3e?=
 =?us-ascii?Q?ONetN5J/83P2VowVB8nqHk75sLGKP6t5j23hO5h/wTqjQFK9jB+0UTOJhpe8?=
 =?us-ascii?Q?zm1IvqYQ5eslMw7GQV8jGXuaQjxW3EknkFf0wYUY/hJVcE94GrBPyaN66Ydu?=
 =?us-ascii?Q?banAcDT1DqciJ/Etsg42dRsisiR9IOfLYTvcdG2jl33N9cDkP2z3e4rveAyK?=
 =?us-ascii?Q?pxjxtwT/sp8q3kAL+azh4pIaYNJ1R+X5gA/RRwrPILhjg311eAat4fUKefD6?=
 =?us-ascii?Q?xP4QMh2QsVPkiURL21is4QQ2FruU10j7bkASK1CnJITODoZNaiPI+QXPUpe8?=
 =?us-ascii?Q?NC4sPol1eqeBo4ddq2uPTYE0pj4yU49wDm3cFi5Vnd8zpEC1bJ5124xFwg0v?=
 =?us-ascii?Q?g/zPZOiKWO3NDT/hGPdjKBSyLSPu4J1xAKnyz5Uv/eYD590ZoIWv3tKHm5nG?=
 =?us-ascii?Q?JNfY8M2lz1hnuo8s2wvyoOPmTdYw2gExb1Zhg46bNz8YlAwU67NFUXESTTdH?=
 =?us-ascii?Q?LfiVksEdONqspg8tm+RKydYx8n2gORQR4oxBD/7uIzPhhMlitoZKIw=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?WmNAkwDZGpCyfped950N6B/7bFCaWe134A0/rGgDvD/WvssRXjT0G8cPFvYV?=
 =?us-ascii?Q?YvRpFHaoclzPDX/zsVzHFMcdlflUHEK3vqfspaBO+pDr16o2MpbOGxk/55Yv?=
 =?us-ascii?Q?lNGBYZaPZGee4kTsU573Up48USe6JsiXzzqI6TX5dn233HgjTOf4hVA4ZNwA?=
 =?us-ascii?Q?H0Wpw0lajhE/rBdtqOH+S5QIZB3X9yApSeIcCMeaOdNVkgAjQoNEScg64IiM?=
 =?us-ascii?Q?GBvGZCitBfFQeexFzcQnPzZqz5sdNJkBlq1PB9q409ZT3H6W3SvYVI6d05vI?=
 =?us-ascii?Q?TqMUh+wIJdgACoKp68kuhkDGXrhW1PxGauVjaWV/7YvoAbvNgGmf/eEKOVbD?=
 =?us-ascii?Q?i5K1ODvYPfsP126naePh5ZO/TZS9nSyIq2MQabd76x8IrBer8BOj9SYzoFPe?=
 =?us-ascii?Q?xIvdCCRs2zoAhF05dtt+YL3C2YLDGUgDReDmMN1L1LuW0p3qupqYhUDJQItV?=
 =?us-ascii?Q?1v193o8U2Zx/pY9KeKMuXM+t7idcqg/Jqg77Ldu4YU4peqRTpDu4JCTycVym?=
 =?us-ascii?Q?SoMUGm5DlSvlV2ONlMDhqN0pGWQJqyYijD7OC7oQ4SOqyhmvuTjB1JwDcc/5?=
 =?us-ascii?Q?362l19/pEo/S5NaYujvlPashlcPZzC3hAKIn4i6OlBeZ7pqRQN+DWYKYHZ/y?=
 =?us-ascii?Q?d1FNlTTc4KaXYjnxNCsP2Yh4O35TQw+P9bcEr7BtO0LNAf5DvNelGQzvVr5V?=
 =?us-ascii?Q?aNWj0itxk3HYXVr7SsCViC6qHGFxq6UR8A4l5PtYXGOdJIDNenlDoYenOtGP?=
 =?us-ascii?Q?M/yFX+zsN/+qQ75J8nU2iuhOhpr8w1SRR9rh3Qk6FzOQN2ogjX1RXdodEE+Z?=
 =?us-ascii?Q?t9Z8i+0B02x/KEiY5GpSekiu0QrTpge++g8LaNGBmPMNheTiMrPBYlFnDLXB?=
 =?us-ascii?Q?K+a+PKWWGkRd5la1NG0tKsTIaGtMyhwlsp+0SPMBZgxQZ/ONOiCJy6VRkWb6?=
 =?us-ascii?Q?VhYkU2mqm846qM6/WjiBPFgQPD69y+Mr9OjAgRclGQdDzVshW1kv1jsojMkb?=
 =?us-ascii?Q?PLgjLLfKfWX7Wev6+WywWxW/7gcONEpGgQj16L4Ip3nOsjVzX7NiDZM2by1M?=
 =?us-ascii?Q?VE5jG/FwpM8LXkyy6haoE+AeiAAOltFGUCQkOmlNVX0TUS+lt2YIoXk/vPBE?=
 =?us-ascii?Q?h22Tw+N4nIx7sT7bKX+hBF73Nt6v7Fku7uNUXbP9aP/0KSq8eEj2FbA64cLR?=
 =?us-ascii?Q?8TLwGlFCY/eoaiSt+rvzaGtvxdrFN5nFAKaPuQkNg707AFS4teAtE+Lkpi4l?=
 =?us-ascii?Q?to7dzZRXKICTH6i0tZbZSAQGy6WFmpT+5WA1vRxZPZz4JxYeDHO9LdCHbOf+?=
 =?us-ascii?Q?IydNT2ftI7meFGqDUyb2RbnccMXf7MmTCmjh0TXEYhz1ctvzIw8VgwXOt9HS?=
 =?us-ascii?Q?d8ztVX249wvS/WjCvmmvjoQPgEE6z7Gv8nJjn1D8NM6xj6Wl5Sb4m0Qmzj40?=
 =?us-ascii?Q?5RMxc/DjFrEmY33yekbz9zRoDleucR+5dvAYTPvd5CNynU9Bpu/hDetQsepZ?=
 =?us-ascii?Q?bZuKFtxW+BJcAdpUZ5n0/meUvsDsjpp0NdCF2bcH/raiOpYkHBpH7b5i7+LT?=
 =?us-ascii?Q?DeiW8FLlTtFfD6mQ3MFT991GcNWOquAtBF7td2xI?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 0b9ee6f0-a16b-4505-ee3d-08de0b232bd1
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Oct 2025 13:11:22.1872
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: out+vybm50QtTqvRruAE2OuQXtRnUHAwteOx+kJI39HJ+LV3siUWKYIzGozx9nY62P7agmpelVeBPP/QDSp+aA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR11MB5965
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=CKqhuPVC;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 192.198.163.13 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

hi, Vlastimil Babka,

On Mon, Oct 13, 2025 at 04:58:28PM +0200, Vlastimil Babka wrote:
> On 10/10/25 10:39, kernel test robot wrote:
> > 
> > 
> > Hello,
> > 
> > kernel test robot noticed "BUG_kmalloc-#(Not_tainted):Freepointer_corrupt" on:
> > 
> > commit: af92793e52c3a99b828ed4bdd277fd3e11c18d08 ("slab: Introduce kmalloc_nolock() and kfree_nolock().")
> > https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master
> > 
> > [test failed on      linus/master ec714e371f22f716a04e6ecb2a24988c92b26911]
> > [test failed on linux-next/master 0b2f041c47acb45db82b4e847af6e17eb66cd32d]
> > [test failed on        fix commit 83d59d81b20c09c256099d1c15d7da21969581bd]
> > 
> > in testcase: trinity
> > version: trinity-i386-abe9de86-1_20230429
> > with following parameters:
> > 
> > 	runtime: 300s
> > 	group: group-01
> > 	nr_groups: 5
> > 
> > 
> > 
> > config: i386-randconfig-012-20251004
> > compiler: gcc-14
> > test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> > 
> > (please refer to attached dmesg/kmsg for entire log/backtrace)
> > 
> > 
> > 
> > If you fix the issue in a separate patch/commit (i.e. not just a new version of
> > the same patch/commit), kindly add following tags
> > | Reported-by: kernel test robot <oliver.sang@intel.com>
> > | Closes: https://lore.kernel.org/oe-lkp/202510101652.7921fdc6-lkp@intel.com
> 
> Does this fix it?

yes, this fixed the issue we reported. thanks

Tested-by: kernel test robot <oliver.sang@intel.com>

> ----8<----
> From 5f467c4e630a7a8e5ba024d31065413bddf22cec Mon Sep 17 00:00:00 2001
> From: Vlastimil Babka <vbabka@suse.cz>
> Date: Mon, 13 Oct 2025 16:56:28 +0200
> Subject: [PATCH] slab: fix clearing freelist in free_deferred_objects()
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 7 ++++---
>  1 file changed, 4 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index f9f7f3942074..080d27fe253f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -6377,15 +6377,16 @@ static void free_deferred_objects(struct irq_work *work)
>  		slab = virt_to_slab(x);
>  		s = slab->slab_cache;
>  
> +
> +		/* Point 'x' back to the beginning of allocated object */
> +		x -= s->offset;
>  		/*
>  		 * We used freepointer in 'x' to link 'x' into df->objects.
>  		 * Clear it to NULL to avoid false positive detection
>  		 * of "Freepointer corruption".
>  		 */
> -		*(void **)x = NULL;
> +		set_freepointer(s, x, NULL);
>  
> -		/* Point 'x' back to the beginning of allocated object */
> -		x -= s->offset;
>  		__slab_free(s, slab, x, x, 1, _THIS_IP_);
>  	}
>  
> -- 
> 2.51.0
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aO5L8EG3nkFeBmM7%40xsang-OptiPlex-9020.
