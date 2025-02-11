Return-Path: <kasan-dev+bncBCMMDDFSWYCBBXFHVW6QMGQE3T2LI7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 13F17A30D2C
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 14:42:55 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2fa3fd30d61sf7366574a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 05:42:55 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739281372; x=1739886172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4EevHJxJfve9itJcca3v1j7FkHkKYC+W564N+U2k4M0=;
        b=iFBEDFVdvy3SmqwygEPwtVUPpuF04dlBYwuFoUCNO8iw5iEA+SGVuQjwtxmmKfMsEU
         PRnyZ9J5V7ZE1ttr0mH1HiQ5iePDdEjYwhmjm+CdV5UdillW91wBubmsPjKklMqXaiVN
         TI2z5RcyIFE8wh4VrXvdAkk7dyqjWcUuvTwhGZJYIJbPvaJ0yvHwZAzCSLosm/GAqH/o
         MKmXxqbzzGPfbttsLC/qxu25/JajB3NkZ7W3wPWo8Y70f1y+6Xl0ajW0fJpwWWdVBPIe
         tv29gY9QiqHp7kmasiDjz9TiPzzOXCquh2NtHgtSrBDkHlBzZGojlwiDtPyq0DDMVD8F
         P6lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739281372; x=1739886172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4EevHJxJfve9itJcca3v1j7FkHkKYC+W564N+U2k4M0=;
        b=Ijg6Ui8x+CRbVyNrZq2NbBHPNhlrt1NkRFHjx+N8G33NHb8yz8UIAdJbhlUrrn8Z3E
         SU+5D3WAYYWv+c/f+yDWiDRHqx4+LygsubPbhRWtMSi0kEd3p0iPqIMLkZr4Rusja2HV
         0U3l/yFudGrvqZJPkdORbyOj4lY1t1VCk/MRZ4tvcm8fpBv1DOF2WqFBsP0ZJT/SSerF
         O3KVER+MBNd/nSsxTDbcp1qgL2FRFn3+5RrBsBSj2v/dIjsAIe2z1psINQZ4ABy07pnN
         Nm5a8xse/pdwgexTmuDwPbLAF6mJOBnB+udfAbGfHBwxFqzNgPac38Vw4XbKALX2XQy7
         TLRA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZJlS1b1b2OKmgnFTcLqui435NuyV2ZP10PriVhvLbv0NiFIxndQW7FNn46LQ4j6/DVJKujQ==@lfdr.de
X-Gm-Message-State: AOJu0YxO1auQ5h2r9K3I+HU0dW+0Bgu7yR13A105nmBHlX/7yTzt7vMX
	QKUD744VP2jTuZBMwcF3XxjU271pYXvwS+TlnctY95BxnucbiKI2
X-Google-Smtp-Source: AGHT+IGbIBDtqOjdRC8VZ1k6xXcrpbG4dKGey7/M7lJ2039x1nGMfpiox9z0bwgarVZ2WelDm5OHrQ==
X-Received: by 2002:a05:6a21:2d8f:b0:1e3:cf57:5f5f with SMTP id adf61e73a8af0-1ee49f59c59mr7022891637.27.1739281372251;
        Tue, 11 Feb 2025 05:42:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:35c9:b0:725:c8f1:7030 with SMTP id
 d2e1a72fcca58-7304401d681ls5408842b3a.2.-pod-prod-01-us; Tue, 11 Feb 2025
 05:42:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUvh43etYRZc3aV89/bBeDIEpMePZ59GKNfP2ECYLrpH3f09H2F1VZkMUnFXH/zRvXWMkcJSXBfE24=@googlegroups.com
X-Received: by 2002:a17:90b:4a06:b0:2ee:dd79:e046 with SMTP id 98e67ed59e1d1-2fa9ed80556mr4892285a91.13.1739281370969;
        Tue, 11 Feb 2025 05:42:50 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.18])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2faa4aebb95si135370a91.0.2025.02.11.05.42.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 11 Feb 2025 05:42:50 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.18 as permitted sender) client-ip=192.198.163.18;
X-CSE-ConnectionGUID: 3rILWW6cRTGOYvv/Nt+lbw==
X-CSE-MsgGUID: VPTfQrl1RJ2rqETVG2u1xg==
X-IronPort-AV: E=McAfee;i="6700,10204,11341"; a="39135845"
X-IronPort-AV: E=Sophos;i="6.13,277,1732608000"; 
   d="scan'208";a="39135845"
Received: from orviesa006.jf.intel.com ([10.64.159.146])
  by fmvoesa112.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2025 05:42:24 -0800
X-CSE-ConnectionGUID: y1JTG44/RFqyHYKBiFABEQ==
X-CSE-MsgGUID: 7XU8g3hlTH+g/rf4eIn78Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,277,1732608000"; 
   d="scan'208";a="112482693"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orviesa006.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 11 Feb 2025 05:42:23 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Tue, 11 Feb 2025 05:42:23 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Tue, 11 Feb 2025 05:42:23 -0800
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (104.47.55.177)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Tue, 11 Feb 2025 05:42:23 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=gQGjIidsh74HR1VQtQui3TNLWdJJiN8xPn7TBabdRSaMsqWqqwELRYqCj/XZkOcAZ98700ikYh9TSwnURpYhuMc7EHPPgQ/XubV8CFwqx7QzvZ/4whVCFRM7exZbmWS7SNrfUAfwU4+NwJ6ehm+MscFwGnYvy8GKzu+EMeC96W0Cc9qZte/EREqS6mDSCPJlYgkN5LwEwyuElSGGlxS5BJE8m2xPsiIXT3UX30HB42qL2l6Q0j4UFPUrIOe6u2+pVe3DVQUBZ4zmSeEyDDIiakCtmTOIhuZwJH4ZyyDnk1V7ppoumBfxb4I2/1EpGV6QGV3OPQN6KdKOWiNVrN7c1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=906hJVJvloG5PggyPyN+1kX5lKyJvKtsMmkFuhee76s=;
 b=UTUd7FK3sfoIYegMc18Ehayrlam0jUjt7S6hG5xmPe3O10s/YyD9SqMJrEDRaHh4mpQEnLj50pYq/TS7P6pc/B1ElFJpDACkvNsKU1KdUcmw2wi9IY9AD9MzPv+p7Xx3l41HbfLvB1TaIPa3vJhei6izr1N9aOcYTA1D9zPC0AjbAP441s5pZQvEKIp1wj4U28BQYrFkMPZ285F1ezbU3SPEMyCaPOolyRXzjIvGOFzlKLtHolaXqRS63Ab2eci0VyLmzSg+G8f8AXhylvGet0N7Nh67KbNv7doYuQCUEaAbGXCfnsovBwLIL+J/ekRvluPea+GdmT6Po56R6N2Dzg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by PH8PR11MB8014.namprd11.prod.outlook.com (2603:10b6:510:23a::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8422.18; Tue, 11 Feb
 2025 13:42:20 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8422.015; Tue, 11 Feb 2025
 13:42:20 +0000
Date: Tue, 11 Feb 2025 14:42:14 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Samuel Holland <samuel.holland@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, <linux-riscv@lists.infradead.org>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	<kasan-dev@googlegroups.com>, <llvm@lists.linux.dev>, Catalin Marinas
	<catalin.marinas@arm.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon
	<will@kernel.org>, Evgenii Stepanov <eugenis@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v2 1/9] kasan: sw_tags: Use arithmetic shift for shadow
 computation
Message-ID: <4tuj7f3ttmm7xxkom3cm6xjnmd742twbaoieggnzwtmkif7l2l@hgilk7qn5te5>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-2-samuel.holland@sifive.com>
 <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
 <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl>
 <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
 <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com>
 <lrlnvcxofcnsm5rou3iwbawyfwtz6mx4gn6eflpm4srhjj37kb@pwsozjgdyxfu>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <lrlnvcxofcnsm5rou3iwbawyfwtz6mx4gn6eflpm4srhjj37kb@pwsozjgdyxfu>
X-ClientProxiedBy: DB8PR06CA0013.eurprd06.prod.outlook.com
 (2603:10a6:10:100::26) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|PH8PR11MB8014:EE_
X-MS-Office365-Filtering-Correlation-Id: 8e02cf78-028b-4d53-84c0-08dd4aa1e85a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|366016|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?cnprRmgzaGJhK1BJM2RMOXJKb1ZhN3BGWEZEbTlrdmE1R091RzRiMzRwNlRV?=
 =?utf-8?B?YWJ1UjBZbVhxUGhXcFZvYjdGVnlKRnJtcTBuOXFBcnNNYk9JNWFuQ05teUU3?=
 =?utf-8?B?bmJ2RGpJTFZsQjdsOXdRQUc1WlZ2YVZTQ2NPTGVIbFRXUU9rVW1kV3AyMEZR?=
 =?utf-8?B?a3VKZEI2b0plNlQwZllVL1BmTy95TnpxSmd1djcxWEc5TGRhaTNod09ib21L?=
 =?utf-8?B?OHArSkZNRWcyY1UzUmhqTGhnejJ4b2JjRTNMV2QzaUNTYWhPUWx6YVNpN2NK?=
 =?utf-8?B?TDZRY3hqOWZCODZZeEpkOGYxajJxeHYrWmMrT0FxZUJxQTRUSWwwTjFnRVlJ?=
 =?utf-8?B?Wk5vM25vZlFJRjZJVVQ1bjlyREl2aWlGSy93WEZmbDBsMTJUSzBkcHNiYnVq?=
 =?utf-8?B?QWNhdjRSRkNrY0E5cC9WMDl3bzg3NHRMaXVVa1pod2RsMS9GQzV2TGs1T2tl?=
 =?utf-8?B?UDVSN1dBeHNaYzlqN0xKVS92eGhSNytlQUROUFNwMlN6bXZQaFAxdWFqN05o?=
 =?utf-8?B?Vm8wVXBJU0JLQmdBTWh3NDRYR081OFVIdDNoMGZHOHFKcWhmQUZZRDdrWEJF?=
 =?utf-8?B?emRHOEZJMTdjUEhHQ2paWW56WHZpbGVHaVA2UXdNczRJaktxOXRlL3lEeDEv?=
 =?utf-8?B?eGI0cUl3TU42Rjl2UzJIZndHMlZ4bEM2cWY0K3VmZ0txUzdGOWZCTGFTYmRo?=
 =?utf-8?B?NFF5TmxhWlJtV2FqMmJ1YlRLUzZJeHJobHFhM1VsenV1WFdDTFJNZE5yNFhv?=
 =?utf-8?B?dktPdDI2Y1RscTRCTU1KSHB4SnVzVEVyMWRBaFZwN1lIUFBoT0VEUUc3NWJr?=
 =?utf-8?B?Z3ZHODZHOUEzZEpFUlNkMFM5cElsa0RXNTVndDU1dFI2OGJCWC8xQ2h3WTF1?=
 =?utf-8?B?VE0yMXY0ekdyQUhyU2YzaUJEVDFyUjNFdW1MTDhkOEppS2w5SjBEbUlJQmxa?=
 =?utf-8?B?NUhpV00yeUFGQ2hPUVFPOHExU3lEaWZVMlJPVHg2WkxoWForUlhSWHQrZEwr?=
 =?utf-8?B?WWdUNFF6VFhBcmM4b2I3a2taTmJGblRFYlpDTkRYcVZNUkErUkc3MzU4TWlX?=
 =?utf-8?B?SzJkZHhyTm1iWWMyTytWYWtyRnRrQTlTQ3R3U2U1cGxrbnpSRzFrOS9nczhJ?=
 =?utf-8?B?UXBkZy9Zcnc4TzdVaUVBMytCclJiZFZMeDFsemhGT01rWXgwUktqcXMyZ3Uv?=
 =?utf-8?B?R1BENFhKQzREdk9hWmlvcitwVERZdEJ0Z0xVTy9tRHRkV3E2VXN4UmFucERu?=
 =?utf-8?B?bFpPL2Z2QldQYVArclJmVXlmT2NYbGZqYlFKbVpTWnE1T3I4WW5TZWM5R01w?=
 =?utf-8?B?eGVSQm1xa24rQlRuRWhNKzBVUVVXNGpZdVZwaWY1N1FaRVF1S1ZPQVp1cGRU?=
 =?utf-8?B?RDZUc2laUW1mSVgvcS9FNUNTeFZKVEpWQnVJQlhZY0JPdlo4RVVXcEkrSTR5?=
 =?utf-8?B?TDJxNVphN0VyNmtLdzVTMXp2eEhaaW9rVlRhUlRDMVgzdWQ2TnR1VXdMdTRH?=
 =?utf-8?B?di8yd1BtWURQdXpHSWw0M0dheS9NZVFiVEt2UmVIVHZMWktoTFZFYzFwbFc1?=
 =?utf-8?B?aDR1ZFp0VDd1cWgySnd3WGxPZ2JqNEtuN2JYaUwxQk0wcndsRlBXeUNIaUVE?=
 =?utf-8?B?TDZOOXpya2o0MFFGeXVWakZnSXJ3MVcwaUVHRGRHZ210OWxkNXdua2N3SG9I?=
 =?utf-8?B?eW1rbEpIaDhQWTEzczNkWlZ5VjhCVUUvWFJuLzQ5UncySy9TeHBHTVFCem5q?=
 =?utf-8?B?YXlJZVdZTFMzWThvTjA4UUNzWHdzWjlFbm81eGI2ei8zbHVBTTNqTnYxQWh2?=
 =?utf-8?B?d2ZtSnB6U3l4dTArS1E2TGU3cVQ2WVBDcDROWXNtZlB5S1pqRWsrbk5YNzFl?=
 =?utf-8?Q?7zBkrTa5ORO9/?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?OXA2MXNVT0pUSzQwTy85eE4venJzcFpyNG1NYzgzcE91RlBtbzZYUXRnOWwy?=
 =?utf-8?B?QW9XL3N4Q0NZd0lNUml4VlFmYlptMEw3Mm9uR1RZc25ONkxjSG5IbUsvVzQr?=
 =?utf-8?B?QUxaUlVYak5rQzFLc2pHZnByWnhUdk5YNDk3VkhnSTBHT3ZTUndMWXd5aGVR?=
 =?utf-8?B?cnRPeFVaTFhTbjBZRy8yaTF1U3g2QjhqZ1pWbmNCTm5hYVcxdlVvc2NYbmZT?=
 =?utf-8?B?RzNNS284QS9kUzh1WGQ3V2pQbFlOYVQ1dm1uOEVFZXpCMTRia1hKb0t3ZS9r?=
 =?utf-8?B?cDZTS09VTW85ZEx2NkEyWW9JS0EzRFVyNDlSQkhMc0l6TEExTlRuT3pneU80?=
 =?utf-8?B?VENERVJEUVgxWk04MVVKV0RoV210TnFYckRWejdJbXlJeTh2UkZ0YzRyRVBh?=
 =?utf-8?B?SmE5V0lpZVBMUHpFeS9pQk9mWEZ5V2JYUW9IbFRFa2xvZTRmWXJrczJsMmNB?=
 =?utf-8?B?c3cxMi9uRmkyNVo0NFFZSmljUkNJRG1ZNjhUSGp2VkFFZ1dvQno5SVE0RE9X?=
 =?utf-8?B?ajlxMHRJWnRLbUcvT1ErMlEwYU9KbHRsc1ppVXZmV0h1UWNha2pIcHVsbURY?=
 =?utf-8?B?ODJwa0NicEZ3V1lDNmNNbzh6K25SeFlmWE8wSzJqS2pOLzhmSGp6Z0tOL2ow?=
 =?utf-8?B?NmcxT0xGRnZ4N3VvZ3JLMkdpUkFLSTRlR0k3N0NBVWVjNC92RjdRRzNzbnk1?=
 =?utf-8?B?TGNNbmpweHVMKzdFRHhBU2ZaSVR4RzZKSlVaald5TmljdGFyTmtaaTRrNitE?=
 =?utf-8?B?bEpGaWlzU2U0QVF4VnhQZFdkRDFpbnRlN2xlMzNiUHhHY2t5RmdxbmJhbElj?=
 =?utf-8?B?a2Jwb1VhOXkwNmw0dnRvT2tMU3B5OVg1UWUxUnY3U3hmQzB1TldzeVFWN003?=
 =?utf-8?B?d0ltL2R4UjlJUWRWcnVWMW0vU2FBdC9sbTlpcWxnYS9IS3pNellCajR4NmpE?=
 =?utf-8?B?MEVQTU8yZmIwNzBxQTBVcnNnVmJHc2ZEdVpXNnlUTGgySGkrRzQyOTExMWo4?=
 =?utf-8?B?eU56QVIwQmUwdzl2ZGZhVTR1UjNPck5jQWJja0RBaXpIZjkrcTVLY1FTVjZT?=
 =?utf-8?B?elE4YWMrcHdBSm5IUjFGbGhlc3l6WTVLU2hXT3FMVmtJRVQ5NzFBdHZpalhH?=
 =?utf-8?B?bjNuTFFmczJzVW1kY2RHVGFHMWd4aU5VOGdnK0xua2FYTmRsWkdBZTNCbG03?=
 =?utf-8?B?VFV5REFqTDNqakhDamd6WU1UcGpwa2hodWtDeE12QzY3dEN3STJkTExBRnp1?=
 =?utf-8?B?cnBEK1A1eUZJL1ZyU3NvVFVkMkhiYVpWT3hKMnZzVE5OYXpncnE0UFB3d0lk?=
 =?utf-8?B?U2h0aW5QSjBJbjB6em5INzZQUXM0TUZIb0NiMk40OEp3OFpHNTN1ckJXMG5B?=
 =?utf-8?B?WkpHNUFtM2QyUkp2ak1lQ0F0ck1rNVlPYWVsTERVR1hnUmZpaWJKU2tEK0tH?=
 =?utf-8?B?Si94QmVpUWVrZXdTQXlhWkpEaDh6UTNKeXhoaFJyYmtuUWVZQ21pd0NsREFE?=
 =?utf-8?B?YzlSLzRJelpJdkZVQmV0eHV1VFRKQlpFblVDUndsaGp4U056Mm55cHhEeTdt?=
 =?utf-8?B?RDVoaG9PbTFpUlZLZ2RJTTFrRGdGUjEyVzBFQmRJT1FJaVR0VXBGWjZxcXZ0?=
 =?utf-8?B?VTRuUXM3d1dSZlBpL3FsT0NvSTdqUlNkQWdXc0VXbldsN2lCbGRSaURVdUIz?=
 =?utf-8?B?eVMzWWllTUxwWUE2T0o4bk9LR3JEM3lLTnV6UjlNMi9HQWI0M0hCSit0eFMx?=
 =?utf-8?B?cnVVU1BBNFdzUWVWb2IxMTc5bEtGNFFOQjE2bE9OdEM0OG1yTmxpSUhmWDFn?=
 =?utf-8?B?Vm9oNkNHOHVBRGJVV2dZdGp0ZzhURTRKM21mMUw4VkNJVjlwZVBGZmFhUFY5?=
 =?utf-8?B?UEMxNjk0UmlGdWZnQWl4Zks1ZUNNd0QwQlpjTFpZbzF0S3VBUFNyZEJKN1dD?=
 =?utf-8?B?cVB0WUpwYUpvN0hSRFZOUWpYa2FQVEFYR2pCMjY4RjVUNW5SNWJoSXVFRHdx?=
 =?utf-8?B?ekplZkx0VEVheHZVVjJXSlUrUDM3Qko4eWFVejZOekhRWVZvalF0V3phcmov?=
 =?utf-8?B?UTZHVlJRRlN2UVF4ZlVpbG9TL21jaGJnNktSMmN4RzlRemdDTzFVdEtsNzRO?=
 =?utf-8?B?SnJxTU5iQVFod2pKZXV2WWlDVmFGOFNkaHhoN0lGYndiSGZiVGVuT0d0dlN6?=
 =?utf-8?Q?vwvWC22WKFKnOHCspNmlmIQ=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 8e02cf78-028b-4d53-84c0-08dd4aa1e85a
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Feb 2025 13:42:20.6621
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: GFn763YXEb8pEL3FH6EkneP1Jm9jF0JS+XzpigozPaBMPGbtIsKKpaIU5cReun4Rr608HpVQ/ezbN0JezMx11AxKagbfEWHwxmR0ZD0wF0M=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH8PR11MB8014
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BX41YSOu;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.18 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-11 at 09:58:22 +0100, Maciej Wieczor-Retman wrote:
>On 2025-02-10 at 23:57:10 +0100, Andrey Konovalov wrote:
>>On Mon, Feb 10, 2025 at 4:53=E2=80=AFPM Maciej Wieczor-Retman
>><maciej.wieczor-retman@intel.com> wrote:
>>>
>>> On 2025-02-10 at 16:22:41 +0100, Maciej Wieczor-Retman wrote:
>>> >On 2024-10-23 at 20:41:57 +0200, Andrey Konovalov wrote:
>>> >>On Tue, Oct 22, 2024 at 3:59=E2=80=AFAM Samuel Holland
>>> >><samuel.holland@sifive.com> wrote:
>>> >...
>>> >>> +        * Software Tag-Based KASAN, the displacement is signed, so
>>> >>> +        * KASAN_SHADOW_OFFSET is the center of the range.
>>> >>>          */
>>> >>> -       if (addr < KASAN_SHADOW_OFFSET)
>>> >>> -               return;
>>> >>> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>>> >>> +               if (addr < KASAN_SHADOW_OFFSET ||
>>> >>> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size=
)
>>> >>> +                       return;
>>> >>> +       } else {
>>> >>> +               if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / =
2 ||
>>> >>> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size=
 / 2)
>>> >>> +                       return;
>>> >>
>>> >>Hm, I might be wrong, but I think this check does not work.
>>> >>
>>> >>Let's say we have non-canonical address 0x4242424242424242 and number
>>> >>of VA bits is 48.
>>> >>
>>> >>Then:
>>> >>
>>> >>KASAN_SHADOW_OFFSET =3D=3D 0xffff800000000000
>>> >>kasan_mem_to_shadow(0x4242424242424242) =3D=3D 0x0423a42424242424
>>> >>max_shadow_size =3D=3D 0x1000000000000000
>>> >>KASAN_SHADOW_OFFSET - max_shadow_size / 2 =3D=3D 0xf7ff800000000000
>>> >>KASAN_SHADOW_OFFSET + max_shadow_size / 2 =3D=3D 0x07ff800000000000 (=
overflows)
>>> >>
>>> >>0x0423a42424242424 is < than 0xf7ff800000000000, so the function will
>>> >>wrongly return.
>>> >
>>> >As I understand this check aims to figure out if the address landed in=
 shadow
>>> >space and if it didn't we can return.
>>> >
>>> >Can't this above snippet be a simple:
>>> >
>>> >       if (!addr_in_shadow(addr))
>>> >               return;
>>> >
>>> >?
>>>
>>> Sorry, I think this wouldn't work. The tag also needs to be reset. Does=
 this
>>> perhaps work for this problem?
>>>
>>>         if (!addr_in_shadow(kasan_reset_tag((void *)addr)))
>>>                 return;
>>
>>This wouldn't work as well.
>>
>>addr_in_shadow() checks whether an address belongs to the proper
>>shadow memory area. That area is the result of the memory-to-shadow
>>mapping applied to the range of proper kernel addresses.
>>
>>However, what we want to check in this function is whether the given
>>address can be the result of the memory-to-shadow mapping for some
>>memory address, including userspace addresses, non-canonical
>>addresses, etc. So essentially we need to check whether the given
>>address belongs to the area that is the result of the memory-to-shadow
>>mapping applied to the whole address space, not only to proper kernel
>>addresses.k
>
>Ah, okay, I get it. Would the old version
>
>       if (addr < KASAN_SHADOW_OFFSET)
>               return;
>
>work if the *addr* had kasan_reset_tag() around it? That would sort of re-=
unsign
>the address only for the purpose of the if().
>
>Also I was thinking about it because x86 even with address masking enabled=
 keeps
>bit 63 set, so all kernel addresses will be negative in the signed
>kasan_mem_to_shadow(). That's great for simplifying the KASAN_SHADOW_OFFSE=
T but
>it differs from the TBI and risc-v ideas where half of addresses are negat=
ive,
>hald positive. So the temporary re-unsigning could maybe make it simpler f=
or x86
>and avoid adding separate cases or alternative kasan_non_canonical_hook()
>implementation.

Oh, nevermind, I see that this is more complicated than that. Sorry for the
spam, I'll do some better calculations what is mapped where when doing
kasan_mem_to_shadow() and maybe then I'll figure this out.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
tuj7f3ttmm7xxkom3cm6xjnmd742twbaoieggnzwtmkif7l2l%40hgilk7qn5te5.
