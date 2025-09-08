Return-Path: <kasan-dev+bncBCMMDDFSWYCBBQ5Z7LCQMGQE34QM5DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C215B487C9
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 11:07:17 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3d1fe9ecd9dsf3413176f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 02:07:17 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757322437; x=1757927237; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pd1K7fZpQoktAxyNjWJRXbv2mcIb2exvBZMrAE/XQck=;
        b=HzRt9opbTNvJX37AcCr8Y+s499sVH841nhDr24dqzDCNdyrlBAUIz2frWk1iHJS3XO
         1SSd1ssbDPCuSwqVZUIz/UMS0cFmxRL30Wbq9BDNyHYXRyB9b368FZUA2kZhih9SJS2L
         BYyeN4XDoSqbSV84fnKThnEt/fcvDn7AKIjRWkwjPiyNY3Ten+xBtWkBwaq76Z9ffuFw
         T+k4lJz8lOJ3tU6eE1f5BuWdg1ZV8/W9ab0iLzjFjymJ2rluGqXM/aHhHarehM6CEjU5
         bllluaWBxxPjFYEzQ45e9GaYlq8LWkpqcLq7LoxWlQdWyev7TyyqjHy7B4UOd2B4XAvF
         sQFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757322437; x=1757927237;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pd1K7fZpQoktAxyNjWJRXbv2mcIb2exvBZMrAE/XQck=;
        b=ry2BiCSroVq9iyKVqYSzLq0bpmatKHlKdOqtG2mrn/etwu9FDtxxw4n1QIbrngr34T
         Fu6m4+p2CVznGcw/Amt620ttaXfivVQIyX/9D5Us0eR+OOMOhTiDZKwrC9zfl6/+j26o
         +/Q6Kas4dBpNKowKmiW3X+YhrW3WI3FkxnYfsTksPGivtnru+4qlDQJ+gfpqfL77Utjm
         ux6pivbIhTWdmfTZbqBOYmmQtBZZM8HHIyazP/bpEijgmfFABSN1slDPbwjMp1ippOX4
         /8OagmCiDpImpCSpjgXVKyMvNeG2jfeE5la+TURDjptXbjJQIXGnSfJIqRdp/tNanrAM
         YPYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXVW6hNpNDv4hljaqqt6COXL42HtQBk3OB9DWAeLH0Q87feWQvduwI5C/F2KoiWg76vq/GBHw==@lfdr.de
X-Gm-Message-State: AOJu0YzsLlv5DCM1HfCmERR4aYZJ0wC9n0Yv+Q0uIJtJCUZ1nnkVsBc9
	IbaqyAXm1nbxuSxU/KWSOQadpuLCBBnUS2fouGupx5/yYR6tz778mULZ
X-Google-Smtp-Source: AGHT+IGiQPuXHeJNiCB26HPIoJ/K/uDS1PtJrgiWjC9aAa1sAb4JhpTKcPonW5E7EJZOUdrYV2jepQ==
X-Received: by 2002:a05:6000:1445:b0:3cb:46fc:8ea8 with SMTP id ffacd0b85a97d-3e63736a869mr5047955f8f.3.1757322436562;
        Mon, 08 Sep 2025 02:07:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4/F6fWbMuspkk5Tl3emEWM3gpziGfizzUEbIV+9KkePA==
Received: by 2002:a05:6000:4282:b0:3dc:f2f:ee3f with SMTP id
 ffacd0b85a97d-3e3b6091636ls1984275f8f.2.-pod-prod-07-eu; Mon, 08 Sep 2025
 02:07:14 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWHq9tVc5KnvTiN5p6NGWoZMMUpCU2x9Olj4Mr6hvQ9EBnBOcXwqLobz5lx5nYJvjMjLl8uE3D18RI=@googlegroups.com
X-Received: by 2002:a05:6000:2f87:b0:3d4:eac4:9db2 with SMTP id ffacd0b85a97d-3e63736d7c8mr6654050f8f.5.1757322433751;
        Mon, 08 Sep 2025 02:07:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757322433; cv=fail;
        d=google.com; s=arc-20240605;
        b=c4HObcHcLgayMHqxhxaTTLxYrW7CMs14hQfZHqXBiICO4oOpYh5yRa0KfzYrLD2EOf
         M5QcI61U1HzAszQIFRpwLHBwB4uBuzcNPgDoimbLuU19Xvn9cui6pce/MU31NMvB6aMS
         HJ7GQKMiBc3K+sjhp5ygREvCEmygSObPKIZiUA8DUwebE28xg9xbfTRLK1Sb7w2877BT
         pobGLTxp4m7FMtxFelqPtPjv134Y8d+jbeEJ7YWVp2VODPkImCV8fqOGAGqhncxexnkI
         fjE6vMc6b6QruB8ZLtLzW3iT229k7+CMA3Tu2NXtZnby5vQrwbjj8nafSmpdkx8CYg12
         uTeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=aPksAnupSBF3NgzpsbH7EW9yGUATIpZWjv6UCpl5mZc=;
        fh=Wufhi7rrwD20YmLOonxnFQWKE9Ef0FLnk1Jd8nrbCPI=;
        b=LIhE4GCNb09t5HFzBZjRkOG+0AjChCv0q3XFOaY1x5nj5xMijlFwKoAjFUKpJnxvOL
         VMzFNqGLB6qdN335Rq4nu2gtmRrj+ILB/mlp0TvxWQa3N+I278ccP/fU91TWYBSVBNUO
         WYIy4h4oJ8U+EwDN/x2wQlk7k+NwrcJE3ek6rp1AC6GZICePAK7TTCSgQa0/A7JO5kvH
         LrY8jribS5bvzw3GtQxRl1WgxgJKDTfF1dNYeLg2UMrHce0bEYkVv5MlS+TiW3ax7riX
         Yas9x4Bpq5qET9Kt/WoXP3eCxsiMCx2nLZ0ItRZL1pSpwyFtw1ZEOYrqmkmOvQO/tYcg
         j36w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cWZ0WKtP;
       arc=fail (signature failed);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.16])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dcfc48300si2203935e9.0.2025.09.08.02.07.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 08 Sep 2025 02:07:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.16 as permitted sender) client-ip=198.175.65.16;
X-CSE-ConnectionGUID: vX0Ib+emQ8616YWa3tMO1g==
X-CSE-MsgGUID: EeC5pL63S5aCnc3JC4xc1w==
X-IronPort-AV: E=McAfee;i="6800,10657,11546"; a="59720100"
X-IronPort-AV: E=Sophos;i="6.18,248,1751266800"; 
   d="scan'208";a="59720100"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa108.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2025 02:07:10 -0700
X-CSE-ConnectionGUID: 4oN2cMn8TsWOdLK1XeTbAg==
X-CSE-MsgGUID: owyRYs/gTZipmivcWSsL+w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,248,1751266800"; 
   d="scan'208";a="172611664"
Received: from fmsmsx901.amr.corp.intel.com ([10.18.126.90])
  by orviesa007.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2025 02:07:09 -0700
Received: from FMSMSX902.amr.corp.intel.com (10.18.126.91) by
 fmsmsx901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Mon, 8 Sep 2025 02:07:07 -0700
Received: from fmsedg903.ED.cps.intel.com (10.1.192.145) by
 FMSMSX902.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Mon, 8 Sep 2025 02:07:07 -0700
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (40.107.93.78) by
 edgegateway.intel.com (192.55.55.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Mon, 8 Sep 2025 02:07:07 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=uVb2kXiGoNViNZ5updFUkmNPRbvFDnizL++xTY5TeA/EtOzn1IDuKmrEjNPd/YsahTSvOSbs7xJ+MnlCMiYQ2qPXqV3TUccllamRvfjAZWnSULxkIoY3KBNcgKhRFFoHsSA6RqVMdcBMpPhVPvayndDXq3xn6bY3Ea9zy3FKQvo+iTJZ9gkJ0g0wFCYMsbOZ0y3E1nFJn1Zlyd9j7Bel+fKfumncHPQ5hdZiMfMVo8+Tn/oFbeutsOkBZIZIRdxlsltyds2lrmmdTATgEyMakcwssKFzoBFphLQV1nbn8NBcl0hcFeQA8e/7q6qbswRVSRtaTJ0DVgW7lHiC+p1Qag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aPksAnupSBF3NgzpsbH7EW9yGUATIpZWjv6UCpl5mZc=;
 b=Wef+alYWy/uKzID/xoRxGID3AdjqSNa8NtJhc5jEYvTv4FHtWsDtWggetxWOtfo7rd4xvQOiOl6yIBEWfMrz1GH9B1iruTE6xhC2HyBKflBOKI8DjIBosYj/qDW3f8fosQx+EBQ8U6Kc/zVjKxAUyUjEF5CWo1XTLhvHmjm27g7C/4ehhjYWiHNiiMb2vwUxMFZbuYeDD+bXVpXZAgY7nCV9vS2eR/BXJKpDuqLtBrg+WcDNmNoUy/9X+yy2/M96RNnu1iknwPkogI0HGYadcfqMyO5/Hych25wb5PaiOWyO/jIeAQyNPhUzRLfdJKTgyPKsHF36CqM/5pd6xQ0u1A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by DS0PR11MB7902.namprd11.prod.outlook.com (2603:10b6:8:f6::8) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9094.19; Mon, 8 Sep 2025 09:07:05 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%3]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 09:07:04 +0000
Date: Mon, 8 Sep 2025 11:06:47 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <sohil.mehta@intel.com>, <baohua@kernel.org>, <david@redhat.com>,
	<kbingham@kernel.org>, <weixugc@google.com>, <Liam.Howlett@oracle.com>,
	<alexandre.chartre@oracle.com>, <kas@kernel.org>, <mark.rutland@arm.com>,
	<trintaeoitogc@gmail.com>, <axelrasmussen@google.com>, <yuanchu@google.com>,
	<joey.gouly@arm.com>, <samitolvanen@google.com>, <joel.granados@kernel.org>,
	<graf@amazon.com>, <vincenzo.frascino@arm.com>, <kees@kernel.org>,
	<ardb@kernel.org>, <thiago.bauermann@linaro.org>, <glider@google.com>,
	<thuth@redhat.com>, <kuan-ying.lee@canonical.com>,
	<pasha.tatashin@soleen.com>, <nick.desaulniers+lkml@gmail.com>,
	<vbabka@suse.cz>, <kaleshsingh@google.com>, <justinstitt@google.com>,
	<catalin.marinas@arm.com>, <alexander.shishkin@linux.intel.com>,
	<samuel.holland@sifive.com>, <dave.hansen@linux.intel.com>, <corbet@lwn.net>,
	<xin@zytor.com>, <dvyukov@google.com>, <tglx@linutronix.de>,
	<scott@os.amperecomputing.com>, <jason.andryuk@amd.com>, <morbo@google.com>,
	<nathan@kernel.org>, <lorenzo.stoakes@oracle.com>, <mingo@redhat.com>,
	<brgerst@gmail.com>, <kristina.martsenko@arm.com>, <bigeasy@linutronix.de>,
	<luto@kernel.org>, <jgross@suse.com>, <jpoimboe@kernel.org>,
	<urezki@gmail.com>, <mhocko@suse.com>, <ada.coupriediaz@arm.com>,
	<hpa@zytor.com>, <leitao@debian.org>, <peterz@infradead.org>,
	<wangkefeng.wang@huawei.com>, <surenb@google.com>, <ziy@nvidia.com>,
	<smostafa@google.com>, <ryabinin.a.a@gmail.com>, <ubizjak@gmail.com>,
	<jbohac@suse.cz>, <broonie@kernel.org>, <akpm@linux-foundation.org>,
	<guoweikang.kernel@gmail.com>, <rppt@kernel.org>, <pcc@google.com>,
	<jan.kiszka@siemens.com>, <nicolas.schier@linux.dev>, <will@kernel.org>,
	<jhubbard@nvidia.com>, <bp@alien8.de>, <x86@kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-mm@kvack.org>, <llvm@lists.linux.dev>,
	<linux-kbuild@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v5 04/19] x86: Add arch specific kasan functions
Message-ID: <jcdmkdwfh4fmez6i4guyefiqhoz5kz6g6dvhdpiw3nxyeocjmk@juw3nevsqeds>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <7cb9edae06aeaf8c69013a89f1fd13a9e1531d54.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZd7tM5i5jOriaYyR1GgjgREv0PhyxpFuEC5506FkndzAg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZd7tM5i5jOriaYyR1GgjgREv0PhyxpFuEC5506FkndzAg@mail.gmail.com>
X-ClientProxiedBy: DUZPR01CA0231.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:4b4::12) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|DS0PR11MB7902:EE_
X-MS-Office365-Filtering-Correlation-Id: d7735647-8d93-46ec-a9ac-08ddeeb7143c
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?UHQwOUJsWCs5OHZkbzhzaCttTGV3Z0h2bXdGYW9FbUIzYWN5YWsySDJFWW5k?=
 =?utf-8?B?Y0EvMW1jbytjUmU5NjRNdy9ZeExVY1VHSUgrcVFGWEVuR290V0J0Rjc4bWlH?=
 =?utf-8?B?RThVVloya1ZnVmsrdWQ0eHFkQTVMTkhrdERheE9mbndTd25ZU1Jlak42eEhU?=
 =?utf-8?B?L2Z6c0p1K2daeDNES2k1RDJRWnppMml4c2Jyck9RTGdvK29vOHN0Ykl6SDlT?=
 =?utf-8?B?NlJnMEFrV0p4bzE1c1g0eUR0YUYxemsyd04rYVRMdWlFRWljMzFqa2VZM0RK?=
 =?utf-8?B?RjF2eHZYNE1UTzJOaFlkamdrb3ROUzFTOVJ5QWQwaXhvSFFmbG9DcG15WHpp?=
 =?utf-8?B?ZFpObDFjbHpzTGZsUXMvL0s3VFQ5S1JSeFR5ZG53eWI0d3pDV1RHRVBEOURp?=
 =?utf-8?B?RzFyNnpBUW5uMUpXZ1hOSldJWWgydXhMY2lHK3d2R1RYZ0pBSkdQVEJLK28z?=
 =?utf-8?B?eXlyazBqbEgrVXFzS1VRM29qYUhwT3NEL0dNZkNsVmtrWVZBS3QwQi9aYWZO?=
 =?utf-8?B?ZUluclhDUnhRYzQ3VUZibXRzVEJRelUrK1VwTU92U0JWUCt0T0RIUTUxZWF0?=
 =?utf-8?B?R1hpTkV1S1l3dXAxWUxoNWFFaHF3ejBEdkEySEFVUEk2UHM1RjJvR2sxRUlF?=
 =?utf-8?B?T3ltNlJGdlhOeDRUZVVYNFNPcEZ6Mkk1ZjNYaDMvdTc5RGlnSWhRSC9OTXEx?=
 =?utf-8?B?czdrTVp6L1NpWGVUQXA3T2tES24rNng1QkkrSEFGZ25OWklqSElCY29kUnkw?=
 =?utf-8?B?QmE3aVhDK29ickpCb05IWXNXQWZuNzJsS1Fzd0hZQStweTFtd0ZaSGZnaTEx?=
 =?utf-8?B?OFhkQ3Uxalp4TGVmSEJteDdRWkpzK2E0Sjc0YXg2WGJUYkIwT0o5RFRjQXVY?=
 =?utf-8?B?ZTUwK25MS3I0OFZHeXkzUHdUa1cydmlqeVpKaTRMYXAzenIvWFVEQ0lwN0Vq?=
 =?utf-8?B?UnFpUFZ0S0xQazJiQTZJcDRZTGRLbmFFTW5ZMW81dzNpNHRNUUZiUWttY3FU?=
 =?utf-8?B?a0dBOGZNR0FQejgzQXlYWG5zN0wrU0dRd21MV2hra0hKR0NwYzhFT1VYcDZs?=
 =?utf-8?B?R3VWaTl3RDcyQ2Vvd3JCOXhBbS9EWERMZXQwalFBemFSZXExV0dOYzJaTXRV?=
 =?utf-8?B?RTNUc09nRitzYXIxRVNaTmoyUmw3L2k0aitUTnYxS214M1cvR0pjcVU2OEpM?=
 =?utf-8?B?T3E4T2lJOEY5OVJPc0krV1dSTTllbTQyck9ZSFRsc05nZHpJcUZhckl2MTN0?=
 =?utf-8?B?UjFaUzlrNjNjNnZSRmxhbkY0R0VuL0RvR281dS9WNTYyaGJGTk54VHFldUJr?=
 =?utf-8?B?Z1pnbjhqMlFjUWtvNnVNODczVXVnNHoyOXhWdHI5NG52V3pmNXdLenQ3S2da?=
 =?utf-8?B?NWdaWm5JTmpCV1VCMkY0b3dFc040OENwdGpjOW1aV3hReHZOcTlHMC9CS2tH?=
 =?utf-8?B?aTN1QnBsU012ZGc4MllBVUVkSkZsbXphZ1I4N3RpVkxGdk84SmJhdnBYOHor?=
 =?utf-8?B?dXdnVE00U3NnY0xla2tIZ0RMMW9odFU5bUlROWxNdi9DbVM0Q204UjM1Y2Jz?=
 =?utf-8?B?YTBRWU1sNEp1eGRKQ1NwU3ZkcXQ3eEt0UDVucFBJeDhMbWRGamwwQ1NCUGM5?=
 =?utf-8?B?c0NkcjVYOXlPN0o2V1dXdVF4V2lnUWMzR2tWSld2am5tR2NiWHlrYndvZU9y?=
 =?utf-8?B?OUdXTlJTUnp3RW1LR0x4ejY3Q2JRZVEvL1c5SnhUVlJ0U1IzMDhnVC9iYmEz?=
 =?utf-8?B?VjZxMExxaEZrZUVmak5BWkZnK0d3VTFBZ3ozRllWNk5tMmUrRHc1RjhBRFBG?=
 =?utf-8?B?K01nTkYwNy85NzNZSE85MSsyVG1sV3ZzZHlXQi94L1M2R2tuN0RIY3lGeGx6?=
 =?utf-8?B?eG0wRENLUVZwVHRkUmY5SkNSeGN2UHJMVVI4MXh0RHhXMUFxbDcyYlI4dHZn?=
 =?utf-8?Q?mEqHWchj/us=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?dVI5MkViTmQ5cjBGRy9ORm5Mc1hQQ0FNVkJzV1U0c05qbUJrYldwVVVSdFRN?=
 =?utf-8?B?MVcwK2JTM2hRSzhKOGxKVEJVR1R4ajMzNWcyVC8vRXN0N01CN3VJZWVSc0Vi?=
 =?utf-8?B?N0c2QUJYUWxpRk11QlFneW1vUjhEbjZxNlQzU2tLVnovRHpmT3YrUlZBNW5G?=
 =?utf-8?B?SnFrNGRNRHRKcHFjS28wQ281RGJIanRYUDk1UGpHdjVsUFh1ZzBycmFySEpU?=
 =?utf-8?B?N1BSemZxeTFDQU1PRVBDa2gwcXNxNjd5V2lrVUF1RGVYMlhMOUQ2a1h0NVJu?=
 =?utf-8?B?aHpzb0dSdjlpb05TWjVqMmF1QjEvbHRVMlJXeUtvNHVLeExPK0lPVTNyalJu?=
 =?utf-8?B?WVBJbjZSNUY3Q2ZtV3ZQbFRMRmNRNTlGMWZIbStzRnNYTURBaVhkVEpNQ2RY?=
 =?utf-8?B?dFQ0MWFoNTFiR0NjL0c1ZHNtSDVYRm05TEFHeEMzUEtIOFFZSTVvYkJZR3Rs?=
 =?utf-8?B?TnRydi83T2J6cUQybjJ6WXI3c0xFcDBtdmVPUGdhSnU0ak9sSEpQYW1ldG5j?=
 =?utf-8?B?L2hIT0JqYlJ0d2tuSkVIMmFTdm1DenR5OXBFeFVxaHVFRGxzVy9uYTZLNXBN?=
 =?utf-8?B?ckxpUFBIZHd5d2IrK29VZk0vU01vSUxLMElUcHYxTXd0eXpFdGFTNTQrZEdu?=
 =?utf-8?B?ZmJGajRMNFdkUU1UVGRVMm1wMGxTNXVkQVpGaGpPQU5HaG9Xakg1bExKTmpq?=
 =?utf-8?B?bWN3Q0hQTFZHWUtwTlBHUXBDMXlZZjF3bHNubGZVQWFqQVEwTkowaGNadFlO?=
 =?utf-8?B?M3RVYW1IelplTXI4WVJ6TmVqc2J3T1o2bjA1Ry9jTkY3RTFjQU9yUkVHdnFY?=
 =?utf-8?B?aUxsOFBTZWU1RU5sQVF2SlJHQm9jdkJBZzZwY2lNSlZrNFozc3JyWmwwQzJW?=
 =?utf-8?B?SU5ETlhoZXhiYzBQYmpWbEZEWW5XU1g4b1J5WjB3eVRzaWZVeXFoQ1IrMUg3?=
 =?utf-8?B?QkRwOHVnVCtONHQ2VWhZRXJPR084YkJnV1JKMGxHdUE0ZGhid2JpMFZwcUEz?=
 =?utf-8?B?YjNRUzlrUm1oQld5dnVJQmZZRCtQR0h2ekY2TEJWWUFFQXVlTDkxOURDWENK?=
 =?utf-8?B?d1NmL2VNRFFkdm5yMHdwVWtUcnkwQTNLS3dHT1Z6aDRHZlJISmZzNjkwTjNH?=
 =?utf-8?B?TmdTMW93b3lobGdEVzRId1Z4Z0d4SWg5SkpNRzZ2ZUgwWDlKZFB0ZG5LajZx?=
 =?utf-8?B?REZKaVJRdGhlZ2c2bXpGcTF3d29UeklraHd6cDRnYm9qOXBrZDFWYXBMYlJF?=
 =?utf-8?B?eFc2ejBCWnIxTk5GcWx6bDRoU3ZMRXZpYUhSMUVkMzR0Y0dPdEJFYnZtWGF4?=
 =?utf-8?B?TG00elV1QXdFb01ndkdUSzkyVk5WUmhFRUxOTVBvQUdpTUd3S3p1NjJBY28r?=
 =?utf-8?B?VmZwZExrWlo0c2U1aE1lSlhJeGJ5V2t2MXE0OTFzWUJqQXlVZ1AxUS95OStu?=
 =?utf-8?B?SDFyQTJQVzFtUG1EUWtMcTV4VXkvbVBqRWRaQlBDMVgwS2JLbFpIZTlCcXBj?=
 =?utf-8?B?U21aLzk4OFVsbkd2UmdRYm4wTUlrNENvQXJmZlp6ZjJGVFBIQm0xY0xUYnVt?=
 =?utf-8?B?REVYMkhVQnNrM3lXV2ZQMHoyLy8wNFB5MVF6d0pmbG9VUXVxdHRlMkVLU2tt?=
 =?utf-8?B?MHVvbU1zVEgwM09IWXB6WEhzUmpzOS9jZUVKQ0RlUjhrL3NqTXZSd293djUw?=
 =?utf-8?B?dHFVc0NHR25NQ2FNdGdrZ0RzY2NuQTI5OWNISm1Tb213Z09sdUd3bkE1RDcw?=
 =?utf-8?B?eUg5ZTBidUpod1dIbnY0OFVnL3FCVnNRbktrOENlM21qcEpPeVVaUERiWXNI?=
 =?utf-8?B?L2hoc0ttV2krS0M3aEZ0N2JlZ1RsSTJQOXFFUGp5WVEraXF3eEJpVmQyTWJt?=
 =?utf-8?B?MGc5eUk2Ui9pNitvR1RlU24rUE4yMURzTlJxL3oxb3VSNTJlNEYrVkdMR1Zi?=
 =?utf-8?B?OHFkRGViSnErcEk0bkJRQTdKQXpQVWVuZVYrOWRnSkViWnVPUGg1S0hueVBi?=
 =?utf-8?B?K2pudlhpSFJuSGQ1OFJTN201aWc1RkQ2emw3SDkrQkdDQWV5UTNmdERhNEhO?=
 =?utf-8?B?Rlo3bTdLeExaTVJRK3BqKzhJNENUbjVUR2lmWVEwR3NVTzdyQ3BTcTVjdFh4?=
 =?utf-8?B?OEM3NU8veTVqUnJndlhnYWJhZ3p6Q3gzTWtQbTFFcW8rbGs0VE5ZZ1VxcXUx?=
 =?utf-8?Q?WwIlIA1Bn/F8Yqk9g23N7GU=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: d7735647-8d93-46ec-a9ac-08ddeeb7143c
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 09:07:04.4698
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 9FGb11BdX8s78+B375+6OUBoJtpIooqDHB4UINfAK3O+UGfLCZ076VcmsmI43LWk94dJQI4ziNjfERnAJIEqj4oruhBSISwGG9V0TVYEMXc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR11MB7902
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=cWZ0WKtP;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-09-06 at 19:17:43 +0200, Andrey Konovalov wrote:
>On Mon, Aug 25, 2025 at 10:27=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> KASAN's software tag-based mode needs multiple macros/functions to
>> handle tag and pointer interactions - to set, retrieve and reset tags
>> from the top bits of a pointer.
>>
>> Mimic functions currently used by arm64 but change the tag's position to
>> bits [60:57] in the pointer.
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> Changelog v4:
>> - Rewrite __tag_set() without pointless casts and make it more readable.
>>
>> Changelog v3:
>> - Reorder functions so that __tag_*() etc are above the
>>   arch_kasan_*() ones.
>> - Remove CONFIG_KASAN condition from __tag_set()
>>
>>  arch/x86/include/asm/kasan.h | 36 ++++++++++++++++++++++++++++++++++--
>>  1 file changed, 34 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
>> index d7e33c7f096b..1963eb2fcff3 100644
>> --- a/arch/x86/include/asm/kasan.h
>> +++ b/arch/x86/include/asm/kasan.h
>> @@ -3,6 +3,8 @@
>>  #define _ASM_X86_KASAN_H
>>
>>  #include <linux/const.h>
>> +#include <linux/kasan-tags.h>
>> +#include <linux/types.h>
>>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>>  #define KASAN_SHADOW_SCALE_SHIFT 3
>>
>> @@ -24,8 +26,37 @@
>>                                                   KASAN_SHADOW_SCALE_SHI=
FT)))
>>
>>  #ifndef __ASSEMBLER__
>> +#include <linux/bitops.h>
>> +#include <linux/bitfield.h>
>> +#include <linux/bits.h>
>> +
>> +#ifdef CONFIG_KASAN_SW_TAGS
>> +
>
>Nit: can remove this empty line.

Sure, will do, thanks.

>
>> +#define __tag_shifted(tag)             FIELD_PREP(GENMASK_ULL(60, 57), =
tag)
>> +#define __tag_reset(addr)              (sign_extend64((u64)(addr), 56))
>> +#define __tag_get(addr)                        ((u8)FIELD_GET(GENMASK_U=
LL(60, 57), (u64)addr))
>> +#else
>> +#define __tag_shifted(tag)             0UL
>> +#define __tag_reset(addr)              (addr)
>> +#define __tag_get(addr)                        0
>> +#endif /* CONFIG_KASAN_SW_TAGS */
>> +
>> +static inline void *__tag_set(const void *__addr, u8 tag)
>> +{
>> +       u64 addr =3D (u64)__addr;
>> +
>> +       addr &=3D ~__tag_shifted(KASAN_TAG_MASK);
>> +       addr |=3D __tag_shifted(tag);
>> +
>> +       return (void *)addr;
>> +}
>> +
>> +#define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
>> +#define arch_kasan_reset_tag(addr)     __tag_reset(addr)
>> +#define arch_kasan_get_tag(addr)       __tag_get(addr)
>>
>>  #ifdef CONFIG_KASAN
>> +
>>  void __init kasan_early_init(void);
>>  void __init kasan_init(void);
>>  void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int =
nid);
>> @@ -34,8 +65,9 @@ static inline void kasan_early_init(void) { }
>>  static inline void kasan_init(void) { }
>>  static inline void kasan_populate_shadow_for_vaddr(void *va, size_t siz=
e,
>>                                                    int nid) { }
>> -#endif
>>
>> -#endif
>> +#endif /* CONFIG_KASAN */
>> +
>> +#endif /* __ASSEMBLER__ */
>>
>>  #endif
>> --
>> 2.50.1
>>
>
>Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/j=
cdmkdwfh4fmez6i4guyefiqhoz5kz6g6dvhdpiw3nxyeocjmk%40juw3nevsqeds.
