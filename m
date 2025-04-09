Return-Path: <kasan-dev+bncBCMMDDFSWYCBBU4L3K7QMGQEFJFE6XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4710AA82809
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 16:36:05 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-73720b253fcsf5399116b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 07:36:05 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744209363; x=1744814163; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wxRY9wnG706Pgo6ZSwOeFTFcBLFUeJBdeorWZm5d/xA=;
        b=qxC9En4xalxjeTvXO6fFA4gOg4Rv1q1qJQtb6mSi8P0Y5s+CQFhGNA0wjdT8LNcKCz
         m8lk8qtOMyRr8b0CHL+Jqw/nn9JJu5900jdL3Nzueo0MX0Q6YIR9DA16rbGQdI7fC7jU
         aFjGBpuT+32ecFZ40WnDoXVxyQbTE6eiUxUuEDm0ohg5ffwiEuZPxiubS+yedsuXZkkW
         PGywPFSj9idQowbOzPaC6Vask7NeS65QNmuus47fMFAEFBRCOl+Yy/dBpAgzR8fbtAxm
         cs1Wwsr4eDAfnJDofR649toEM7KIhRu/ZMc8eG5LJdXYjk7FZW7aTmqBEMZULhuYoNXG
         DIPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744209363; x=1744814163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wxRY9wnG706Pgo6ZSwOeFTFcBLFUeJBdeorWZm5d/xA=;
        b=ZzJWXFNydzkcGsuPKNVfNfHszK6wVoiKbH4qnJEnZpkFXahKm0aIJr3CpOo6exxX//
         C2qICgK1r0D3Zvr7L5QsqJZ2eULj0/iYqm6nOVXlUoKloKoXTk/jli41XWRee/Sg4+hI
         cBvZ0+8dhT3xVEWdz7A8xtZ4ciJwUTeEnG7y+xYMrEo/M++Ig65+1p5789T+x7GnQW9U
         hvxIfzoDJbTrp/iaFaejBSB1QMNkZbYm4gS50T9QDJK09MpSXw5twDFQ/yKROJ5sjZL1
         30i62aDQi7usk5mPRiSmZ1c4oNjlshdnDtyCnJbIW8NU9txnUelBwyEeq/70sxWdtugK
         4PrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXD8jb7T+Ib4UUsQkRY9QJdG9+/fuqJBkx0W26sK6ytg1ki+D0ng+WlUHBjo5L0dr3S4zZPNA==@lfdr.de
X-Gm-Message-State: AOJu0Ywou4OcPAL/19Yq7yP67AEzXOPCxDnpqngvh8WTj/WeBc6G0GTT
	qEW137OEQ0Nak79xBBLlUVgESlG9yawv0v9RGMGbLRCE642VrpXS
X-Google-Smtp-Source: AGHT+IHKTBEXYSmc07Gdc/izkmStv8zcuGRlAf4Cdp288kZGnO9fRfDiRi2trLI/rlLLLBfpkGMewg==
X-Received: by 2002:a05:6a20:c892:b0:1ee:8435:6b69 with SMTP id adf61e73a8af0-201591555e5mr4689221637.1.1744209363318;
        Wed, 09 Apr 2025 07:36:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL8Ll3jlLaY/Aieg/QVMsrqqQRzVDdqbNAFxwzTW2PSWA==
Received: by 2002:a05:6a00:1d9b:b0:736:cdfd:9229 with SMTP id
 d2e1a72fcca58-739d5c8ed1als6379620b3a.1.-pod-prod-09-us; Wed, 09 Apr 2025
 07:35:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVOFQQ1+CEWVcDmcKkTv9TBsOzJzI0itBuNIkHhhImgBxUCGyX7yS8y05aHfC2HjZ9xduGS0SKXfGs=@googlegroups.com
X-Received: by 2002:a05:6a00:3d13:b0:736:4e0a:7e82 with SMTP id d2e1a72fcca58-73bae4b9085mr4029056b3a.10.1744209359611;
        Wed, 09 Apr 2025 07:35:59 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73bb1e51684si62531b3a.4.2025.04.09.07.35.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 09 Apr 2025 07:35:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: j34O59+4QB6zw9EMUAf1gQ==
X-CSE-MsgGUID: V7KNUsORTmKPxPCfzMczIA==
X-IronPort-AV: E=McAfee;i="6700,10204,11397"; a="33294861"
X-IronPort-AV: E=Sophos;i="6.15,200,1739865600"; 
   d="scan'208";a="33294861"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 07:35:57 -0700
X-CSE-ConnectionGUID: 2w+sCjdoRFWUZVEUcD6sQg==
X-CSE-MsgGUID: VkUpKQmsTlS0rBlNtCjY6A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,200,1739865600"; 
   d="scan'208";a="159581295"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by fmviesa001.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 07:35:56 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Wed, 9 Apr 2025 07:35:55 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Wed, 9 Apr 2025 07:35:55 -0700
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.171)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Wed, 9 Apr 2025 07:35:55 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=pmIAO7SQqjZeVUA5ydEIrdZpQOB5jBMAc9nrg/UH5qBhiarKmPTozHJsyqhZM8pnr6Rzk9UP0gBAbmeTIGizSW3P6sBa5spzDg+1c0qjlZkjkXOIvCiO9kW8DxeSjIsmSH4Xewo6U1sIpQelmU1Xs1BuRqTm86xnEkWQ02ApoNkH6QI/CGyBK6+8bdP6yxcZSAjjqW4GnBN3CDpaH3rOhaEqMIt2WcAt7QtBSzySUgZxA+BbQWPfvzOTxm5xLWjpiJEdmXlQQXdI0S73MmtA+wBUZ9VwJEw/i4iw3cHPkPeYjScxNiaOK4qZK1UoabtgP00d3Uuy5YD0nxYfHM61SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=4c+TEdKl3/lDWl5KSRxYNHHBCEGslSt90hkWnMrf8gg=;
 b=NxYzxG5qdCihLsF/sebsz30cKVggEwrBnw9jzIa13y7ClxgyOIgjWotqisY9CN5r1h1Q53xfqoDftmC2lM6QBv/KAnlYYk2E3LLuQPQMR0mrspxsjfbla6iNweGvs3H+Lm4KyE0eKnqPzaqhyAUIu2hZl7e31u5MT563NxihRr1IdwjgKMoKIXSbT7zReyXjLqF2f2v8X574nf68hgQT6mGNFHjibJS5uHsHjaFNQJz2PcGpVh575TGntZMv94kMfg7yZMtcfOxXqlZ3U9eVBo0Wxo4O5gD9hdy4IW6j6KnxOoRwbFze3xLeQrFFjgOzgLGLIXI3dgJfyq6BsUj7dQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by IA3PR11MB9399.namprd11.prod.outlook.com (2603:10b6:208:577::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8632.23; Wed, 9 Apr
 2025 14:35:38 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8606.029; Wed, 9 Apr 2025
 14:35:38 +0000
Date: Wed, 9 Apr 2025 16:34:56 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Dave Hansen <dave.hansen@intel.com>
CC: <hpa@zytor.com>, <hch@infradead.org>, <nick.desaulniers+lkml@gmail.com>,
	<kuan-ying.lee@canonical.com>, <masahiroy@kernel.org>,
	<samuel.holland@sifive.com>, <mingo@redhat.com>, <corbet@lwn.net>,
	<ryabinin.a.a@gmail.com>, <guoweikang.kernel@gmail.com>,
	<jpoimboe@kernel.org>, <ardb@kernel.org>, <vincenzo.frascino@arm.com>,
	<glider@google.com>, <kirill.shutemov@linux.intel.com>, <apopple@nvidia.com>,
	<samitolvanen@google.com>, <kaleshsingh@google.com>, <jgross@suse.com>,
	<andreyknvl@gmail.com>, <scott@os.amperecomputing.com>,
	<tony.luck@intel.com>, <dvyukov@google.com>, <pasha.tatashin@soleen.com>,
	<ziy@nvidia.com>, <broonie@kernel.org>, <gatlin.newhouse@gmail.com>,
	<jackmanb@google.com>, <wangkefeng.wang@huawei.com>,
	<thiago.bauermann@linaro.org>, <tglx@linutronix.de>, <kees@kernel.org>,
	<akpm@linux-foundation.org>, <jason.andryuk@amd.com>, <snovitoll@gmail.com>,
	<xin@zytor.com>, <jan.kiszka@siemens.com>, <bp@alien8.de>, <rppt@kernel.org>,
	<peterz@infradead.org>, <pankaj.gupta@amd.com>, <thuth@redhat.com>,
	<andriy.shevchenko@linux.intel.com>, <joel.granados@kernel.org>,
	<kbingham@kernel.org>, <nicolas@fjasle.eu>, <mark.rutland@arm.com>,
	<surenb@google.com>, <catalin.marinas@arm.com>, <morbo@google.com>,
	<justinstitt@google.com>, <ubizjak@gmail.com>, <jhubbard@nvidia.com>,
	<urezki@gmail.com>, <dave.hansen@linux.intel.com>, <bhe@redhat.com>,
	<luto@kernel.org>, <baohua@kernel.org>, <nathan@kernel.org>,
	<will@kernel.org>, <brgerst@gmail.com>, <llvm@lists.linux.dev>,
	<linux-mm@kvack.org>, <linux-doc@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kbuild@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<x86@kernel.org>
Subject: Re: [PATCH v3 10/14] x86: Update the KASAN non-canonical hook
Message-ID: <ycsp2mypsnnwcvmogvbxgpmw7hia4y5rvywa2xbam7lbuhnbx6@adg6uaasx6ci>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <c37c89e71ed5a8e404b24b31e23457af12f872f2.1743772053.git.maciej.wieczor-retman@intel.com>
 <8416848c-700a-4ff0-8a22-aa62579d60cd@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <8416848c-700a-4ff0-8a22-aa62579d60cd@intel.com>
X-ClientProxiedBy: DU2PR04CA0033.eurprd04.prod.outlook.com
 (2603:10a6:10:234::8) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|IA3PR11MB9399:EE_
X-MS-Office365-Filtering-Correlation-Id: 9a25e937-e27b-41d1-4293-08dd7773cbc1
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?K/UCKYLrqJ2LhN30D06QSh5INtDSx2IhEHRq+Ulgyd3t7m7xvWc64j7KuD?=
 =?iso-8859-1?Q?pqwnhZKQPEFT4xOuRQT+stdCTonwgP1TXTI5PEmMwlj92C5x2LeLhbIYO3?=
 =?iso-8859-1?Q?LQ67PIDr7H45ZTAToYm1JhrITavXehCo+w+C/65sS/eqXZMZkBtnNPK7b3?=
 =?iso-8859-1?Q?aMNjjEPtt9mjY03QGvrm28pwNStj5bRMot9GXXFiQEvM3AKCzpXHXJr/lL?=
 =?iso-8859-1?Q?3kKrbMpOtJv4FFqpIew5iXed3GI74azx0/FijpLnVuaGNOWe9qHl0eOXow?=
 =?iso-8859-1?Q?Zy9hAot4DXiVr7tYemGw92rBq6i+v7yNr1/g9/huHhOVHPgILJuuJofZKr?=
 =?iso-8859-1?Q?jSwJ5En1f//HnMztNCpdZy/3kl124JrQbBFeplGGBc6W8dI7LbMgMfWPuQ?=
 =?iso-8859-1?Q?TV5AcuY81AkGT4GVIOTpnK7iSpnCZ2F09TyidIAPNJPASE07zvFscloRfq?=
 =?iso-8859-1?Q?v4v0I1S3Tl/cRWfXbxxXnXkyaACRba7/iWHtuhdo/5MD9FJqhJmWCuHma0?=
 =?iso-8859-1?Q?SrHGUiJFISHv16lSSCnB2pINllpu8ge3NM11FL43WaQZSl+tnI2QAIcJYs?=
 =?iso-8859-1?Q?Us96ohh2hIvP4TTWnvWsImOw0NIvfiPl5PXSPaaA3VquXvAGmV1585lL3o?=
 =?iso-8859-1?Q?yNiC4dhAEIyQCUjNuIpuCx4oFP4Z7J80aByrw5/e5nsN+Aa1JimZ2aMzQd?=
 =?iso-8859-1?Q?45KilWrjDd0gNoG6zmGlcdSvU2vlawIeYTZloyzucaKVX3CLDN7DDzJcV2?=
 =?iso-8859-1?Q?s8TeN7ZAfzpfc29amX3RckX+1+REv4Tyc6MfDUe0/8desMVeJuzHImfwJJ?=
 =?iso-8859-1?Q?HKV+POilF7TAagnFnSUBMxP4UunW3+G3LAw7WCWskPFdcAA+VX/k2ncWVj?=
 =?iso-8859-1?Q?fh1NVpUWLN54qEOvVM7HkfXTZFfMMJQf8pstxToVUzGIofQ74TfOtzo+jN?=
 =?iso-8859-1?Q?AbCF0AezFWprrrKzPESNEoUd04W099vAHyc260M74MXXBACL0jNzuYaRMj?=
 =?iso-8859-1?Q?YdNge3egchyiIFVQZuldcHBo7yalgUXs2jOicoLkliVoaZv+D3FhGr+RYK?=
 =?iso-8859-1?Q?T0IzW1S2H92GDbFlDf4Seo0t3qm4R7ariQzrKQB2+IB8hNrCF7s7ytVnpz?=
 =?iso-8859-1?Q?9QiqbRgGooLCebDYQvK39klx4uE9ZebuCwqODKCAp3+C2EfRhEPPSvVwHL?=
 =?iso-8859-1?Q?mNVyJIopjF6jspvEGd6YpVJbPIfcFEKXfSrN1ZeUG8LR2O0hkH1EmnXEYK?=
 =?iso-8859-1?Q?EPJO+s54HurE67E0SC6AYLBlKq4Rjzr2Qfcet0tCZaB6aCPft37cIpgzH0?=
 =?iso-8859-1?Q?8RYo0dZz68EjB79hGfVzNzEg/tkrY9CINyvQJjo7ATEokwF94c8pjG2qw+?=
 =?iso-8859-1?Q?gjrJFPtqbRMJehd6BwPV5QfNg3xT08/rUF7AmpmDxTJotb6yB57ufT/0Ek?=
 =?iso-8859-1?Q?72AOVlNOTKdItmmEOAfkxDQxw+ZVz5gLwJugpNCU26d4m0LdTvHRIopH0V?=
 =?iso-8859-1?Q?Q=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?IcNS1BGg0LdMicmwuF9AVYGLIhblnJ0KXNyUNV8e0A54JF1IlTCBwCdA59?=
 =?iso-8859-1?Q?peK17BCyv74cJGCrM/1mYzgp7N/bryniBRXJEl/kAP45Ow90eVsd0bqB7b?=
 =?iso-8859-1?Q?h5+g67TXU57vJpsGlaz3wFIT7ts8wo2cUa67eiQ2Qj1LzJ6R5aelVPFLux?=
 =?iso-8859-1?Q?mGnzpn3s6SH6eV+m+6DYqRfe7IJzAdqU5CJ+kgah/WUhuKoROa5ZPTyEz6?=
 =?iso-8859-1?Q?+RVdvw1PcUod4kDE7Izsyzxa5CWaGGYNhYj8pBPKhylZqVWewO4SCn/CdY?=
 =?iso-8859-1?Q?mBI2c5DpiL2RE1XPRAm7k0QPDEYeC82vbK1iE0gX+V87G85G9yStyaWN+G?=
 =?iso-8859-1?Q?4KaBbKGt2AGoamBG7bSsr8IGAXSNpF9cHNvJFDU5aIm8zWbdX7yN/qczn4?=
 =?iso-8859-1?Q?xY63/hIf8EUmsxIto/wYJiK8ig11bE0DD/os+vS4vFRVpk28sjyRbPSdMs?=
 =?iso-8859-1?Q?4ZEQeZvWiH1Rj7plS8oYPhnT3Z/LBZpDDsiMrjt4xvUnKdjccJcTl/U3f9?=
 =?iso-8859-1?Q?vPhidgnl3OW01TNYD7uT6RnJI5j75hSXaW3pxoPO0+rCQSwl+3JzJg2SLv?=
 =?iso-8859-1?Q?fav1KZcW06kRWJfbLmO9Me7BhCecsm6g25BolbH4AELeE2GDNxQoLbETcU?=
 =?iso-8859-1?Q?HWmQWjaftIY5n0GwYU7om0Oz2NryOBKlKt1U+BXhiSK+lAlKnhmC3yaD4V?=
 =?iso-8859-1?Q?xFhrUuXV5nxzupIFw0IB30fILeF5agbdN+YMkEF0tLJcSr2kluDSu1Kljj?=
 =?iso-8859-1?Q?Z5vsbZBEwLwZcR5mm09aBjbB1kscqNfVkEwB8lhY5Nf54Obj8bJIEvc+tN?=
 =?iso-8859-1?Q?B1811xfwn60LtW+/DlCRP4VwVyxlSfdnDUHS0DlNlaeAz29EMq9na8YnDL?=
 =?iso-8859-1?Q?rCZhsztcbpMQOOfFgTPm8ZGN9UTR3IvLXXPETgTbJHO8VSUgP/ivgtk39x?=
 =?iso-8859-1?Q?eD81tMs4FV/t+WnXRaewvsQbNwXONAVxgsYdEBqO8IMiZrayX3NJ6m6lVD?=
 =?iso-8859-1?Q?X4LT6ngKKbIurE1NrUZcjxPszZAumbtLEw3coknBCm43HOwRAVHPcv9UtP?=
 =?iso-8859-1?Q?KALk+dGRE36c/0wL7DnUrijCWIdWvdZk7goQZegmLNW8JT7tMKGKhj+s+h?=
 =?iso-8859-1?Q?VY80G3oW32NfV2Q3ksnTixqEOE1scLsgIIHXWJnskYj3Vh6zPmuoFycMys?=
 =?iso-8859-1?Q?VyAxasan2NP17DXKOCchKwg5Mwya7guVQZCQL7Eod+DKZEp5ubEyxVoTfb?=
 =?iso-8859-1?Q?4KKF8wV41ByIulXDCceChMQPKE1ujdjbHj5iXqZ4e6gVHQyZ1EY4y0KQ4P?=
 =?iso-8859-1?Q?0urOFPv1o/W71TVYtlmvxNoAt/5pmoy26FTIB5nDE88lDstbE5uyIcw5pc?=
 =?iso-8859-1?Q?tLxQh5tafXolT9Ej6XhBVCCMdRREnh1fa056hWpWJ9pHg0UqcNT5h+t5yP?=
 =?iso-8859-1?Q?7BFLiCbaQSvKpXdwME7014JlB+FO7VU07e0yL7ccsy9cTdE2wLlxVQEVom?=
 =?iso-8859-1?Q?gbTcDia+JqEpNDq4wuCfBoiBWOuWWvvjis4hexaKEp6O0drvSlCz0Y5A48?=
 =?iso-8859-1?Q?9IPuo2tn5+ptypCtALbC76ma+qJJn3/lrfwJmpZzteScW9uoh5lVKVrx28?=
 =?iso-8859-1?Q?brYIiEjjdv2/bIvX4cmiH2DgjIwKIR73ZhfSrTeBoIBnXHg00WdYLW0WK7?=
 =?iso-8859-1?Q?/DJDeRxaD4AT9pLP2WM=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 9a25e937-e27b-41d1-4293-08dd7773cbc1
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Apr 2025 14:35:38.2760
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: th+44N/whc+zmEM2mn8z4SyWDdDWM4zTBbe7WVyd0l9IcN+ywoBFW54YRwMJkqfH7t5rwRE2ciHpp6qKRjsjwEdNFa60iiqV8tU6gEOaI5A=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA3PR11MB9399
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NKPM5wL1;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-04-04 at 10:37:53 -0700, Dave Hansen wrote:
>On 4/4/25 06:14, Maciej Wieczor-Retman wrote:
>> The kasan_non_canonical_hook() is useful in pointing out that an address
>> which caused some kind of error could be the result of
>> kasan_mem_to_shadow() mapping. Currently it's called only in the general
>> protection handler code path but can give helpful information also in
>> page fault oops reports.
>>=20
>> For example consider a page fault for address 0xffdefc0000000000 on a
>> 5-level paging system. It could have been accessed from KASAN's
>> kasan_mem_to_shadow() called on 0xfef0000000000000 address. Without the
>> kasan_non_canonical_hook() in the page fault case it might be hard to
>> figure out why an error occurred.
>>=20
>> Add kasan_non_canonical_hook() to the beginning of show_fault_oops().
>>=20
>> Update kasan_non_canonical_hook() to take into account the possible
>> memory to shadow mappings in the software tag-based mode of x86.
>>=20
>> Patch was tested with positive results by accessing the following
>> addresses, causing #GPs and #PFs.
>>=20
>> Valid mappings (showing kasan_non_canonical_hook() message):
>> 	0xFFFFFFFF8FFFFFFF
>> 	0xFEF0000000000000
>> 	0x7FFFFF4FFFFFFFFF
>> 	0x7EF0000000000000
>> Invalid mappings (not showing kasan_non_canonical_hook() message):
>> 	0xFFFFFFFFF8FFFFFF
>> 	0xFFBFFC0000000000
>> 	0x07EFFC0000000000
>> 	0x000E000000000000
>>=20
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> Changelog v3:
>> - Move the report.c part from first patch in the series to this new
>>   patch to have x86 changes in one place.
>> - Add the call in fault oops.
>> - Extend the comment in report.c with a graphical representation of what
>>   addresses are valid and invalid in memory to shadow mapping.
>>=20
>>  arch/x86/mm/fault.c |  2 ++
>>  mm/kasan/report.c   | 36 +++++++++++++++++++++++++++++++++++-
>>  2 files changed, 37 insertions(+), 1 deletion(-)
>>=20
>> diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
>> index 697432f63c59..16366af60ae5 100644
>> --- a/arch/x86/mm/fault.c
>> +++ b/arch/x86/mm/fault.c
>> @@ -511,6 +511,8 @@ show_fault_oops(struct pt_regs *regs, unsigned long =
error_code, unsigned long ad
>>  	if (!oops_may_print())
>>  		return;
>> =20
>> +	kasan_non_canonical_hook(address);
>> +
>>  	if (error_code & X86_PF_INSTR) {
>>  		unsigned int level;
>>  		bool nx, rw;
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index f24f11cc644a..135307c93c2c 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -700,7 +700,7 @@ void kasan_non_canonical_hook(unsigned long addr)
>>  	 * operation would overflow only for some memory addresses. However, d=
ue
>>  	 * to the chosen KASAN_SHADOW_OFFSET values and the fact the
>>  	 * kasan_mem_to_shadow() only operates on pointers with the tag reset,
>> -	 * the overflow always happens.
>> +	 * the overflow always happens (for both x86 and arm64).
>>  	 *
>>  	 * For arm64, the top byte of the pointer gets reset to 0xFF. Thus, th=
e
>>  	 * possible shadow addresses belong to a region that is the result of
>> @@ -715,6 +715,40 @@ void kasan_non_canonical_hook(unsigned long addr)
>>  			return;
>>  	}
>> =20
>> +	 /*
>> +	  * For x86-64, only the pointer bits [62:57] get reset, and bits #63
>> +	  * and #56 can be 0 or 1. Thus, kasan_mem_to_shadow() can be possibly
>> +	  * applied to two regions of memory:
>> +	  * [0x7E00000000000000, 0x7FFFFFFFFFFFFFFF] and
>> +	  * [0xFE00000000000000, 0xFFFFFFFFFFFFFFFF]. As the overflow happens
>> +	  * for both ends of both memory ranges, both possible shadow regions
>> +	  * are contiguous.
>> +	  *
>> +	  * Given the KASAN_SHADOW_OFFSET equal to 0xffeffc0000000000, the
>> +	  * following ranges are valid mem-to-shadow mappings:
>> +	  *
>> +	  * 0xFFFFFFFFFFFFFFFF
>> +	  *         INVALID
>> +	  * 0xFFEFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL)
>> +	  *         VALID   - kasan shadow mem
>> +	  *         VALID   - non-canonical kernel virtual address
>> +	  * 0xFFCFFC0000000000 - kasan_mem_to_shadow(0xFEUL << 56)
>> +	  *         INVALID
>> +	  * 0x07EFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL >> 1)
>> +	  *         VALID   - non-canonical user virtual addresses
>> +	  *         VALID   - user addresses
>> +	  * 0x07CFFC0000000000 - kasan_mem_to_shadow(0x7EUL << 56)
>> +	  *         INVALID
>> +	  * 0x0000000000000000
>> +	  */
>> +	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_X86_64)) {
>
>One overall comment on this series: there's a lot of unnecessary
>complexity. Case in point:
>
>	config ADDRESS_MASKING
>	        depends on X86_64
>
>and
>
>	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING
>
>and
>
>	config KASAN_SW_TAGS
>        	depends on HAVE_ARCH_KASAN_SW_TAGS ...
>
>
>So you can't have CONFIG_KASAN_SW_TAGS set without CONFIG_X86_64.

This line was there so it only runs on x86 and not on arm64. So yeah, it lo=
oks
redundant but if we remove the first condition we might get some bogus info=
 in
generic mode, and if we remove the second condition people on arm might get=
 some
weird output.

If you still think this needs to get separated somehow then perhaps moving =
all
the CONFIG_KASAN_SW_TAGS code to a separate function might do it? And then =
there
would only be something like if(x86) else if(arm).

>
>> +		if ((addr < (u64)kasan_mem_to_shadow((void *)(0x7E UL << 56)) ||
>> +		     addr > (u64)kasan_mem_to_shadow((void *)(~0UL >> 1))) &&
>> +		    (addr < (u64)kasan_mem_to_shadow((void *)(0xFE UL << 56)) ||
>> +		     addr > (u64)kasan_mem_to_shadow((void *)(~0UL))))
>> +			return;
>> +	}
>This isn't looking great.
>
>I'd much rather have those kasan_mem_to_shadow() arguments be built up
>programmatically.
>
>I'm also not following the description of where these ranges come from:
>
>	[0x7E00000000000000, 0x7FFFFFFFFFFFFFFF]
>	[0xFE00000000000000, 0xFFFFFFFFFFFFFFFF]
>
>I obviously recognize the top kernel and top userspace addresses, but
>there do 0x7E... and 0xFE... come from? Is that because both of them
>only have 56 actual bits of address space?

We want to cover the whole LA mapping to shadow memory. These ranges are du=
e to
the compiler masking out tag bits (in this case the 6 LAM bits). So after
masking out the [57:62] bits, we get these two contiguous ranges. All the o=
ther
addresses are invalid mappings when using kasan_mem_to_shadow().

We had a long exchange with Andrey on how to cover all the edge cases. Perh=
aps
this message summarizes it best [1].

>
>Wouldn't we be better off writing that as, say:
>
>#define HIGHEST_KER_ADDR (void *)0xFFFFFFFFFFFFFFFF
>// ^ we probably have some macro for that already
>#define LOWEST_KERN_ADDR (void *)(HIGHEST_KERNEL_ADDRESS - \
>					(1<<56) + 1)
>// ^ or can this be calculated by tag manipulation?
>
>which yields:
>
>   void *_addr =3D (u64)addr;
>   ...
>
>   in_kern_shadow =3D (_addr >=3D kasan_mem_to_shadow(LOWEST_KERN_ADDR) ||
>		    (_addr <=3D kasan_mem_to_shadow(HIGHEST_KERN_ADDR);
>   in_user_shadow =3D (_addr >=3D kasan_mem_to_shadow(LOWEST_USER_ADDR) ||
>		    (_addr <=3D kasan_mem_to_shadow(HIGHEST_USER_ADDR);
>
>   if (!in_kern_shadow &&
>       !in_user_shadow)
>	return;
>
>I _think_ that's the same logic you have. Isn't it slightly more readable?

Yes, I like it more than just generating the addresses in the parenthesis. =
What
do you think about this naming? KASAN prefix and [k/u]addr since it's not r=
eally
the lowest/highest address in the whole LA, just in this KASAN compiler sch=
eme.
And I changed 1<<56 to 2<<56 so it generates 0xFE00000000000000 instead of
0xFF00000000000000.

	#define KASAN_HIGHEST_KADDR (void *)0xFFFFFFFFFFFFFFFF
	#define KASAN_LOWEST_KADDR (void *)(KASAN_HIGHEST_KADDR - \
						(2<<56) + 1)
	#define KASAN_HIGHEST_UADDR (void *)0x7FFFFFFFFFFFFFFF
	#define KASAN_LOWEST_UADDR (void *)(KASAN_HIGHEST_UADDR - \
						(2<<56) + 1)

[1] https://lore.kernel.org/all/CA+fCnZdUFO0+G9HHy4oaQfEx8sm3D_ZfxdkH3y2Zoj=
jYqTN74Q@mail.gmail.com/

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/y=
csp2mypsnnwcvmogvbxgpmw7hia4y5rvywa2xbam7lbuhnbx6%40adg6uaasx6ci.
