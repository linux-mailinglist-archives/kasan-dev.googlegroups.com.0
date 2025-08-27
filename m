Return-Path: <kasan-dev+bncBCMMDDFSWYCBB3GKXLCQMGQE52W4MAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C310B37A52
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 08:27:58 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-61bd4cf74easf6799230eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 23:27:58 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756276076; x=1756880876; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mpaWHGEYCU0iFDF2DDBzyFHOWME/y7yo4WoNAUp6QMc=;
        b=SrZYhmsj0+0gPOjM8UoPB2zfi7LtJwdSbuEb+XVL3vqHwrafXGrMPnQfmplqb7OHY0
         eDUpiSwM2PO0bNgMQVhuTZIoDo1uvqUtN7WiKGbFOaX4mEWPcnx10trF5zK5OcvGUdwQ
         ZWNsFEy1JSfQ+Ei8MGijH0jp6k16/ms9gxNrVX/Ml9+5Q3oAqPPKR5HDh4E9fGrE330/
         VWMiTj8AdyVucyeJFTLUTFLIUVd8tyGxWFNGJuFSEJ/xLRkhqzZafhD6VnUSWmDK6ns/
         iuu9LqkCJHMBIN7/RSsLxU7LyNWyzXEjQswmbV/TEuqmQXuh6m1s4oebesQXkc/HtVdc
         wufg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756276076; x=1756880876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mpaWHGEYCU0iFDF2DDBzyFHOWME/y7yo4WoNAUp6QMc=;
        b=WCcg51blfnWJO6/ILq3gxtvPcf9jhSTpIgwn5f57VLCmzBWjDU9k3uwQZv7gG8lyXs
         BdwmQF5GTVrpjv6X+r/vOIZWa3eN5m4TYCKZjVx8lPGzdQMaVY3kBIzjw+Gn/dV8BCt0
         eRc/+DJTY3wUwd61KJzeM40nomKjU+No+B7vPP60VfZ4kCs/aInke9eMe/YjbRFXYxDt
         04tKnPRUSetT6jsnUdqp0hVstl7Xz24E/8dMa6zQR9icN7w8zjVnRi48aJIZOaS2ycXs
         nsHnIRz3p0u4Cc/H6/iA4dU4XehbtFYip9xJDgz3Yo8oaU6hzeH6Ui0h9cM1f3VuMc3g
         R9Lw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUA0IyrYUGoH7hu7d/8qtpta5YSIDAmXjEoozC0vB/sQ9kCU2Sw7tsHoLQyaI90kSu0PIVKZg==@lfdr.de
X-Gm-Message-State: AOJu0Yyvd4mj84IA7qm+vm9ECqlunlZivF7vY3Sm7FP5dQGPvrJgNVgv
	witb7GWnv2QcXSsPQ5DQ5GfAVB/IHgxaEK+FCAg6HaoR50rppx3JrKS9
X-Google-Smtp-Source: AGHT+IGA4F+gymJg4S9cDoC4f46ISC+fwyWOoTZEVmTDzrCCphcRMy+fT+CS09INd0e/Q4dWkCBqmw==
X-Received: by 2002:a05:6820:22a7:b0:61d:98a4:e904 with SMTP id 006d021491bc7-61db9b430c7mr9799573eaf.3.1756276076439;
        Tue, 26 Aug 2025 23:27:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcRkUcnw9MoCeRf8RfVnJkXho3m9nTI9uNT80WJbd3lsg==
Received: by 2002:a05:6820:7053:b0:61d:f8d4:b32a with SMTP id
 006d021491bc7-61df8d4bfbfls413149eaf.1.-pod-prod-09-us; Tue, 26 Aug 2025
 23:27:55 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX9jsWaToiG4aG6I3s8A99q0leTzlaUh16TdrphyGOmj0EnkSXcFUADqWhZVS00yX57V8HY/0g0k18=@googlegroups.com
X-Received: by 2002:a05:6830:b86:b0:73b:2617:87f1 with SMTP id 46e09a7af769-74500a85576mr10264512a34.28.1756276075412;
        Tue, 26 Aug 2025 23:27:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756276075; cv=fail;
        d=google.com; s=arc-20240605;
        b=HK9Un6Js9l8D1ZA876P3iCn36NQlGAMdsJ1RrjBXdNX/M+aMSPIKyA1+OfjHiiPNPt
         Jyn/Y5FZ65J6n8yBRNdBsq3PUjp3DqrML9JHaT4ITT+Deg1g2yz1ukilElej0xWMLQh/
         XVsxzvnmOGYP6l6D56fFUWiMC63yjg892EeHto6BKR00m7jMbgbnPDyrI02bSY3A75cA
         LJO7cM+sTTYT9dvAgQMx1SNg/O8Np2b0FVTkAjk5m1J5I/7hBQ8fDRTkmqJaZdDLIn7H
         CyKgCSwF4hLED05wtXyqhI2LKWyEew9vQtYfEGzgIEjMZHIRbaiGh2t6fCgnMRk0g8Az
         NMkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=upLp/c7nvkarhi4wcLqwrYCCMpql68JhA2mtGehnRQ0=;
        fh=RlNA7SCw+K66hfnnKtoFb8LZXL0lbmT0HfQwoST0Khw=;
        b=cUxwgqRACwAfATiTrYv4PPFKg88/sA9u/B8NqnyGVmgeuodPpECwne0/Tc8iW2yBzO
         DJmVZrhWIEMsvjY4GLAsxZFWAgJkPMasx0T2Y5t9bEx5AZn4BZLUxnYmcjyvxSAgHgi7
         40lKyzw9FVI7ygyR5c0xLmnVI+qIkOXpTQBQ8p0vOB/OlS9EO5ZvUWqoEQiPRH5XAwhk
         4tY+ASshTtbyUX18gzTeuJiTmvQlJqMAAYuaENBRwxu/XhssVmfjEcCAQnTWlzw/Mh3E
         qCwdB2y48+vY59998XfSLtBN6iFbnkgsuKpqh4swEL8LISxBjIAs0Cnas8bqspLTXTux
         w1tA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=LFvTBeYS;
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e26e811si551153a34.1.2025.08.26.23.27.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 26 Aug 2025 23:27:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: TK8ePXa+QB+vhGHuAwv2BQ==
X-CSE-MsgGUID: jPGKTRSbSs2tsEUKCc/4ZQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11534"; a="68793028"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68793028"
Received: from fmviesa007.fm.intel.com ([10.60.135.147])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Aug 2025 23:27:53 -0700
X-CSE-ConnectionGUID: lDlwUV6VRQmZfNG/Em730Q==
X-CSE-MsgGUID: xJ4vvhNARniivyoKtrt0yw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169282837"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by fmviesa007.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Aug 2025 23:27:51 -0700
Received: from ORSMSX903.amr.corp.intel.com (10.22.229.25) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Tue, 26 Aug 2025 23:27:50 -0700
Received: from ORSEDG903.ED.cps.intel.com (10.7.248.13) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Tue, 26 Aug 2025 23:27:50 -0700
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (40.107.243.88)
 by edgegateway.intel.com (134.134.137.113) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Tue, 26 Aug 2025 23:27:50 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=vINRHoRpojvcpAkkGb6akgenB3uNiD25VFfNnVrgCloPUdmIT3+5E3FjFZYd8N1xrJAtcab69SN1g7NSv0KjHfInebkOQTa7KnyoVZV11D1wyKcvQ7iyrNBF2/bFg4DrQDXXUdhv+NGhdaRPey82Ehu3daVlAnlWWFDA0oxgMxUAUOlEHyoB9O64Gv/+9wRDCiBeeEawAgUMdUHx8BonRaylWlHNFUCT9UqluW4ZnYccxeWBaU/yJDykw2LwSUZ8PIqee/RmXzKqXZKoa1trL90R2z/oZdQC3iLa5bkKuAc42ImD43cQgK0/ZQuDzsDm+o2kQu5t+UxaPMi4LEYGjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qVpgQuu4a18qaU1w6d1i9ExUt4jSKqQzEQxvdVOOTXo=;
 b=A6nHjYU4Nu+mpWIc8tOPmAwOiBtUC8ZmEHX/XbB5TV5NX3ehQNxjvHaA7OOXmH09vTdhRGd/48eMzzBFs9FYGq0Flk+FT3gV1APpGb3ubhyHrOIM6OsSyhtLcMQgUSPRf8ZD14OHusjCe2R8wCJ/MiuILBtHm8yutqwotbz322cKFM+YdmMdGct6KpZrcNUzJu2TPMdS/aRhtIHfIeQpKVLwUncaz7K5oeri4pmNleP6goYuDcsrhs2T/D/vuiA3TUCABsblwWcuCJn7+WhhWlyujL6DKMxFlKZPUdjCgBJlVWRQIBUD5s56N5wo5h7r1oSQZsT9gdTvJs9f1dw6Lg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by SA0PR11MB4527.namprd11.prod.outlook.com (2603:10b6:806:72::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.20; Wed, 27 Aug
 2025 06:27:42 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%6]) with mapi id 15.20.9052.019; Wed, 27 Aug 2025
 06:27:42 +0000
Date: Wed, 27 Aug 2025 08:26:57 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Catalin Marinas <catalin.marinas@arm.com>
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
	<alexander.shishkin@linux.intel.com>, <samuel.holland@sifive.com>,
	<dave.hansen@linux.intel.com>, <corbet@lwn.net>, <xin@zytor.com>,
	<dvyukov@google.com>, <tglx@linutronix.de>, <scott@os.amperecomputing.com>,
	<jason.andryuk@amd.com>, <morbo@google.com>, <nathan@kernel.org>,
	<lorenzo.stoakes@oracle.com>, <mingo@redhat.com>, <brgerst@gmail.com>,
	<kristina.martsenko@arm.com>, <bigeasy@linutronix.de>, <luto@kernel.org>,
	<jgross@suse.com>, <jpoimboe@kernel.org>, <urezki@gmail.com>,
	<mhocko@suse.com>, <ada.coupriediaz@arm.com>, <hpa@zytor.com>,
	<leitao@debian.org>, <peterz@infradead.org>, <wangkefeng.wang@huawei.com>,
	<surenb@google.com>, <ziy@nvidia.com>, <smostafa@google.com>,
	<ryabinin.a.a@gmail.com>, <ubizjak@gmail.com>, <jbohac@suse.cz>,
	<broonie@kernel.org>, <akpm@linux-foundation.org>,
	<guoweikang.kernel@gmail.com>, <rppt@kernel.org>, <pcc@google.com>,
	<jan.kiszka@siemens.com>, <nicolas.schier@linux.dev>, <will@kernel.org>,
	<andreyknvl@gmail.com>, <jhubbard@nvidia.com>, <bp@alien8.de>,
	<x86@kernel.org>, <linux-doc@vger.kernel.org>, <linux-mm@kvack.org>,
	<llvm@lists.linux.dev>, <linux-kbuild@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v5 01/19] kasan: sw_tags: Use arithmetic shift for shadow
 computation
Message-ID: <cwxjbxch5mu6ji7dhus2kfygys2kky2agu4gqrusnz2autk22t@k2cq7qgqmmvm>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <7e314394fc5643def4cd4c6f34ebe09c85c43852.1756151769.git.maciej.wieczor-retman@intel.com>
 <aK4MlVgsaUv-u7mS@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aK4MlVgsaUv-u7mS@arm.com>
X-ClientProxiedBy: DUZPR01CA0006.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:3c3::13) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|SA0PR11MB4527:EE_
X-MS-Office365-Filtering-Correlation-Id: 15383612-209b-4714-8cfe-08dde532d40c
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?fT5bBLm23rX6Auf5KPDQwPGN+axElsWmRu8oSKqwKCSehhzShBiSiDYyfx?=
 =?iso-8859-1?Q?pT3nIPOMf5vG5c2GGFErRbR5wjb/8lPbggFY4mR/Chw85GDU0hxcSziZGp?=
 =?iso-8859-1?Q?cZrOhn3SUnzwuuO5QOczMKOyrfyQTd9ceLkccHmXqOZ6M20fhw7OMIK4+P?=
 =?iso-8859-1?Q?OyMeQEMkogW2TnqB1ozWZaICilLN0tL0TUV7R1zBURqKhXps67qq75iViW?=
 =?iso-8859-1?Q?06heReNhZt2zNbVJDTzm+vxJTxB7ne/Yhi5gHvgiNmdrX+7YQ6CH4Fk1Z5?=
 =?iso-8859-1?Q?purz9HNcNw5N6Eph/nDDF7VVFOt70Gtz7Dqx0zr2DX5D1/Dqy8NfCSEzPC?=
 =?iso-8859-1?Q?0/jGw1+YWRcmazMpRSDupKU2IFoXgiwyIeeK6aQLCEnlKkmpeWo/SuUXOX?=
 =?iso-8859-1?Q?MQ7Od0j+2zJY3qrlaCobFgpa+1depuRMDy+wiS1Axii9Fyna6DV+Prk6TJ?=
 =?iso-8859-1?Q?MhQUCwFCdgHxuj+Hl11DHUDlbZ3G5P2pli1k73o4iYq5+mMEiOmDvfT7hS?=
 =?iso-8859-1?Q?W1U1ScFd5Cab9u43pfsq8WmRemoovcl7/3tLfTDqUzaPeKqMQNuL2t41mM?=
 =?iso-8859-1?Q?UBeCZ9zBcQ9iA0fZp9gm9F2CARODLUl+KhzlsFM+QsWZCgPb1zT/BPE5kn?=
 =?iso-8859-1?Q?yFfVTlUhhJM7xJ+ilL6jLLqz3Hd69uZH3dQPN6Noj7qoKwfzN+QtzGWaVO?=
 =?iso-8859-1?Q?Z3VpXOM8vBkWbXEaCpK66m7qWNuAvtyoBU0DxdwioAZ6532UoGynix/4sw?=
 =?iso-8859-1?Q?yRCxUj9viREzoijuLmrKrdqR+PLddv77xdsFUXlGsSt94cNhkJiG4MkFwS?=
 =?iso-8859-1?Q?zaLOJc+fXGZfxr/z+A6jjdiCcvlYnZDi63iWy6uSsvfjnSvArlkyURPfdk?=
 =?iso-8859-1?Q?9YUkgwDAObeUQ4YDPBJrwC0MyZxE483kgyRMgXg89cOQk1QKe192lUpyd7?=
 =?iso-8859-1?Q?OCzUsjwjlU+5ku9Yos57SIkgVf/4yKxEzb05tLtcsmDyy5TAWDGNQR/Te2?=
 =?iso-8859-1?Q?fY+BHh9HoQuq2bKn37Xl8wtn1/yETYdrTBnw/SNflf6zYjhfpS1hdQYQtq?=
 =?iso-8859-1?Q?LOMMhJHsJD6h2e4ziAv3sBQkI2/YaINVZKiSg0nXgXaE/sqKU61LA/gtvg?=
 =?iso-8859-1?Q?eJ0plP6dJLSU6LZOxYe5aUIqpSQcytxe3LdFdfsxumh9cYcK5K84TfQbTN?=
 =?iso-8859-1?Q?OR3VDQd1N2yWmYt1YTbe4j/nz+oWWR/iqMVjwsIcBldUpwUjGKuCsc59dh?=
 =?iso-8859-1?Q?2sdZiK0RsNBwe9VIx/dcy4J0wgC1gOufGRE1huSYbzrA9jP8OhjPQoXR0E?=
 =?iso-8859-1?Q?rSkNPLbg4MWRIgFTLHEGX1gzQoulcBMTmXuKmqalWMpGLIV1JCod1jSeid?=
 =?iso-8859-1?Q?7jUi8pq0NsSGnmSBHB2EFWW0MwEymMAEhgEv7ybtyMaKXrgodQyq2lEHSy?=
 =?iso-8859-1?Q?p+7oAMUmKjJR07OyPssf54rxoTj9C4o+f6yYT7TcGUoKUDmP/G8xRxgec1?=
 =?iso-8859-1?Q?g=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?sRJpjmF2TPhOSFBW0EZPcQnkPMTHh6ok7SDGyELJr3xrUeHD3WbTZyTDWt?=
 =?iso-8859-1?Q?w7qe8z+wSYlusmleHbhowdJ3uqElF4qzDvHoE1FpTSxhcSFXwelsKI4alv?=
 =?iso-8859-1?Q?3o+YdaObrdyH+oHTV2NqqFRUeiaScEhqR4ljLoPcQBBjDsAWAnOLfQVT03?=
 =?iso-8859-1?Q?P7YlRYYOZOkfe07GAcMBUNJkDZ8KVlE7ewDaIpao0mWfurVBTuwOIQ5D6+?=
 =?iso-8859-1?Q?HC78YyshcT27QNVERGcUwHK6gRcz6X4eyWiO5OAAm7+8KB42LUDeSrk+o7?=
 =?iso-8859-1?Q?/wbBJOQiAHPrkGhWzCNtKu5EhwbLL2BFyNsgBKijwyrZABapI3yuaxt6Xb?=
 =?iso-8859-1?Q?X45O5fuSx0RQVCJtouNuAcamvzZ+rJp8BDXU+vaS+uwdgxyeCmmy04yYgQ?=
 =?iso-8859-1?Q?rNWKjttO/OREFyOOQSHePpb7HVIXBrQslwLM3gQrZF4GWzn5ppFaUEoPLh?=
 =?iso-8859-1?Q?jAJ3ITvy2H+WMUvY0zDj3fx2KnjMbCD+YKGsymtqcMKGL6gJplhcsFwcI5?=
 =?iso-8859-1?Q?EjZZB8C4uofbQf6fos43o+v/Ke8kf29EgxdessMxi3pOhx5ntk75KZtoLX?=
 =?iso-8859-1?Q?CqCM1vMhbE1kpY4W3+dtEw8RAJNBZFxbLMZm5KerymC4XcuO6O62i2w6Bh?=
 =?iso-8859-1?Q?kYvfIudFseor0XDi2aqRArvdRPsR6s14JY4lHYL5FEnN2Mbf2MeTteH1d8?=
 =?iso-8859-1?Q?bujm/s66kIv9VbUHlUMC1ZoVG0WH9F+9KyGPusGIhGjZW5v8DBY1U4DQMH?=
 =?iso-8859-1?Q?Bzl3nvg+M8OrCCOg6mOEh6Rox9EhHZeNRFro7A+6Z6vkXV3oamB74EZNBx?=
 =?iso-8859-1?Q?TlEpMbKLIh2swzC7aPeQV3lblaXo3E5trRorn1KdEzpV8CDai/Vdj78j1g?=
 =?iso-8859-1?Q?daQPcb/2c+ZlGH6OQlGeflgwhsSBPUL7qPZM4fiygZHeyCURMqNS04CKLT?=
 =?iso-8859-1?Q?E1UhvARP5GS09RvGAbcsSDDtpL1joK8FOcqD8XchPnd56DG62cR8f7Kby9?=
 =?iso-8859-1?Q?jsCyYB6RzLk6qf7C9qe9Wk/v4tjBat3zfeKH9UDf4bMtXRNpkXC2JzQltv?=
 =?iso-8859-1?Q?8eHiSLaOjKYgNtYADODaSa6jIZxbaXesYxt2Dyu25sY8OIr+Jh73iEK6cQ?=
 =?iso-8859-1?Q?C30/NYa6AFACxrG6TFraR27asjbgRXTjBhRAgj0LQUbkYDmvu6nQSftYnP?=
 =?iso-8859-1?Q?rAPOGyutJmZvXUmfjor53YEQHMGRmk46/7Y3tst+6dYeEqcrKmyTiC1t3P?=
 =?iso-8859-1?Q?SYAM8WXrYjaH584LwFu4fdBWKjEiPZvafineY0VGop+Wy2pwDxSjNYWPlL?=
 =?iso-8859-1?Q?u3hHGJz3+P7ztLubSBfjTs6q9bxEbKvhST306rt7PXRSRNFKgVFTJt1YwR?=
 =?iso-8859-1?Q?9J0RCazgNZ0qGf3MkliB/UhfO0ekc3G542ZZ54unIyNpl/Y/kUp84AI8Dv?=
 =?iso-8859-1?Q?ub6mQ0URqUOg3D5bNqugI5nB7ki1wmI/wOEHX8JXGi2PFB1QvbJ8/5I/HA?=
 =?iso-8859-1?Q?Hk7EGmL10F4HRSoOVxRnUkFyplqHlEyBpts+523Kt128xltaQrzNLRPZyV?=
 =?iso-8859-1?Q?XgGAtKuShQKh9iF+dtE4oMR4y8PfZwN182P6xxnlU+agU8jSvi3f1PesWH?=
 =?iso-8859-1?Q?04vL8vn7b20RJbh/P01m2BpUYTeOwg6rhpwdWWPdbDVRgdq1zwS44r1PlQ?=
 =?iso-8859-1?Q?0AQMH44nCCEFeD9cJAA=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 15383612-209b-4714-8cfe-08dde532d40c
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Aug 2025 06:27:42.7355
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8z+9UnGK4WCySK15LQLISgdosoGoW01wH3bshDOyqSxxhx36p//3GPdVPX22t9vb98rxhapvs5bB+AczScPamOhRz5eT06Ssi5XF2u2PnE4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA0PR11MB4527
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=LFvTBeYS;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-08-26 at 20:35:49 +0100, Catalin Marinas wrote:
>On Mon, Aug 25, 2025 at 10:24:26PM +0200, Maciej Wieczor-Retman wrote:
>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>> index e9bbfacc35a6..82cbfc7d1233 100644
>> --- a/arch/arm64/Kconfig
>> +++ b/arch/arm64/Kconfig
>> @@ -431,11 +431,11 @@ config KASAN_SHADOW_OFFSET
>>  	default 0xdffffe0000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
>>  	default 0xdfffffc000000000 if ARM64_VA_BITS_39 && !KASAN_SW_TAGS
>>  	default 0xdffffff800000000 if ARM64_VA_BITS_36 && !KASAN_SW_TAGS
>> -	default 0xefff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS_52 &=
& !ARM64_16K_PAGES)) && KASAN_SW_TAGS
>> -	default 0xefffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_52) &=
& ARM64_16K_PAGES && KASAN_SW_TAGS
>> -	default 0xeffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
>> -	default 0xefffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
>> -	default 0xeffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
>> +	default 0xffff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS_52 &=
& !ARM64_16K_PAGES)) && KASAN_SW_TAGS
>> +	default 0xffffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_52) &=
& ARM64_16K_PAGES && KASAN_SW_TAGS
>> +	default 0xfffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
>> +	default 0xffffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
>> +	default 0xfffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
>>  	default 0xffffffffffffffff
>> =20
>>  config UNWIND_TABLES
>> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/me=
mory.h
>> index 5213248e081b..277d56ceeb01 100644
>> --- a/arch/arm64/include/asm/memory.h
>> +++ b/arch/arm64/include/asm/memory.h
>> @@ -89,7 +89,15 @@
>>   *
>>   * KASAN_SHADOW_END is defined first as the shadow address that corresp=
onds to
>>   * the upper bound of possible virtual kernel memory addresses UL(1) <<=
 64
>> - * according to the mapping formula.
>> + * according to the mapping formula. For Generic KASAN, the address in =
the
>> + * mapping formula is treated as unsigned (part of the compiler's ABI),=
 so the
>> + * end of the shadow memory region is at a large positive offset from
>> + * KASAN_SHADOW_OFFSET. For Software Tag-Based KASAN, the address in th=
e
>> + * formula is treated as signed. Since all kernel addresses are negativ=
e, they
>> + * map to shadow memory below KASAN_SHADOW_OFFSET, making KASAN_SHADOW_=
OFFSET
>> + * itself the end of the shadow memory region. (User pointers are posit=
ive and
>> + * would map to shadow memory above KASAN_SHADOW_OFFSET, but shadow mem=
ory is
>> + * not allocated for them.)
>>   *
>>   * KASAN_SHADOW_START is defined second based on KASAN_SHADOW_END. The =
shadow
>>   * memory start must map to the lowest possible kernel virtual memory a=
ddress
>> @@ -100,7 +108,11 @@
>>   */
>>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>>  #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> +#ifdef CONFIG_KASAN_GENERIC
>>  #define KASAN_SHADOW_END	((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT)) + =
KASAN_SHADOW_OFFSET)
>> +#else
>> +#define KASAN_SHADOW_END	KASAN_SHADOW_OFFSET
>> +#endif
>>  #define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (UL(1) << ((va) - K=
ASAN_SHADOW_SCALE_SHIFT)))
>>  #define KASAN_SHADOW_START	_KASAN_SHADOW_START(vabits_actual)
>>  #define PAGE_END		KASAN_SHADOW_START
>> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
>> index d541ce45daeb..dc2de12c4f26 100644
>> --- a/arch/arm64/mm/kasan_init.c
>> +++ b/arch/arm64/mm/kasan_init.c
>> @@ -198,8 +198,11 @@ static bool __init root_level_aligned(u64 addr)
>>  /* The early shadow maps everything to a single page of zeroes */
>>  asmlinkage void __init kasan_early_init(void)
>>  {
>> -	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D
>> -		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
>> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>> +		BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D
>> +			KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
>> +	else
>> +		BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D KASAN_SHADOW_END);
>>  	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS), SHADOW_ALIGN));
>>  	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS_MIN), SHADOW_ALIG=
N));
>>  	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, SHADOW_ALIGN));
>
>For the arm64 parts:
>
>Acked-by: Catalin Marinas <catalin.marinas@arm.com>

Thanks :)

>
>I wonder whether it's worth keeping the generic KASAN mode for arm64.
>We've had the hardware TBI from the start, so the architecture version
>is not an issue. The compiler support may differ though.
>
>Anyway, that would be more suitable for a separate cleanup patch.
>
>--=20
>Catalin

I want to test it at some point, but I was always under the impression (tha=
t at
least in theory) different modes should be able to catch slightly different
errors. Not a big set but an example being accessing wrong address, but
allocated memory - on Generic it should be okay since shadow memory only sa=
ys if
and how much is allocated. On sw-tags it will fault because randomized tags
would mismatch. Now I can't think of any examples the other way around but =
I
assume there is a few.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
wxjbxch5mu6ji7dhus2kfygys2kky2agu4gqrusnz2autk22t%40k2cq7qgqmmvm.
