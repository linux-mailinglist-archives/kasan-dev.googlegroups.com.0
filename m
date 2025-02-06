Return-Path: <kasan-dev+bncBCMMDDFSWYCBB5VPSO6QMGQEP3YFQUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 333D4A2ACA8
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 16:40:40 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-38dc56ef418sf164885f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 07:40:40 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738856439; x=1739461239; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Qp+VFXPg+7oQIPsmjDXQVUdD0OYoe1vV8VtK5ccDWn4=;
        b=oaS8g/QaJvLmba3RadTt4FWNn1SB9uC3s9OxRbeH2P4eU9p2MhuZNobk4eGKGgMH8C
         aAZujEVDuITw/ipdGDD2dzQ6pEvaJT5MkJVahloyzOiVGfD1oA1pS8xnp47v1PYn+kE7
         fxhkTBASJOmovprV8q/kmYMKluVEW6Jc+quSUc8BnQoEgHUTALTRmitifzJlKyIkLLME
         qf2Ml9LgUh8Zp2uOUzNun6TuxWYa7NmSn/66cONQh5S7brjv/Hsiq/bmRXsFl5buH3QE
         /Ci7QzrIilmooyPa4RWiSDZkha+c15n0SyybTCL0qPFQsW8cer/CJ2jWE1uVyaeymHsd
         RVgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738856439; x=1739461239;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Qp+VFXPg+7oQIPsmjDXQVUdD0OYoe1vV8VtK5ccDWn4=;
        b=QIi6EBwU6a6GIFzViyHCFwRgzL8PS43BBaCjoa75g4t3d16zyh4mPx/SNliaco6UQb
         5/n/xAi/HnSsWRCzypDH7J8GRVHp0roZspxOjWrLx0eqD+ctzSUjZ+u8BKpUw65Pz33i
         Jb6Sx99ANuzfBEOPpM2Vh6NSadLAEg4ZWgzmZKVNfrWpjWD0k0rU4N32R8fj7C4i8t+l
         Z9Ig9sm+FUd1gnORqsMyC+/r9Qvse4Bz7kOjuiQ8Im88GNLMkbxIXYZFDZ5BpCTaCSHn
         nqioQOXE+oSc9nI9dWgPuUK7KyExCnhwWf10U+pf78Hx/eN2xzuvKrWqu+mWYy7haWrf
         yjRg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAY9D8kkprn9PSZoVgbbl5IO71tj1x64eN2MU4PqYOmvn7cIQRjfbOFqryjmRZDqI+0+HDLA==@lfdr.de
X-Gm-Message-State: AOJu0YzqMKOh4NE9+oFmxB1Qxf1sl2JLNlENb57ipN2EQIeI7jtdEf00
	cDsQ8Sis+B/egeCA4Aqomz2cDGLRwRMcsGoJnmFlIXSas8GAzrsc
X-Google-Smtp-Source: AGHT+IG1o5lFwYOMANFCTwUjj4NCvTX5CcVpDlbC1vNk04XTfhr3YReZaM3imKBIh/XYXYRXuhe7wQ==
X-Received: by 2002:a5d:6d0f:0:b0:38b:ed7b:f78c with SMTP id ffacd0b85a97d-38db48866e3mr5265545f8f.6.1738856438386;
        Thu, 06 Feb 2025 07:40:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c86:b0:434:9332:de65 with SMTP id
 5b1f17b1804b1-43912c2f040ls5934525e9.0.-pod-prod-06-eu; Thu, 06 Feb 2025
 07:40:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWECp5Qh7gmxhS4aUMPqg5zVxjr328cXSU6KXXosYuLGlINWoA1rLj4tF9n2ftfS13mJCx+Kd74n6A=@googlegroups.com
X-Received: by 2002:a05:600c:3150:b0:434:a4fe:cd71 with SMTP id 5b1f17b1804b1-4390d435ed6mr68575045e9.12.1738856436086;
        Thu, 06 Feb 2025 07:40:36 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4391df9261bsi424085e9.2.2025.02.06.07.40.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 06 Feb 2025 07:40:36 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: kTX866pMQcuIkwKqs8d/Vg==
X-CSE-MsgGUID: vbcgdqWbQla56O36oDcJAw==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="27068065"
X-IronPort-AV: E=Sophos;i="6.13,264,1732608000"; 
   d="scan'208";a="27068065"
Received: from fmviesa010.fm.intel.com ([10.60.135.150])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Feb 2025 07:40:33 -0800
X-CSE-ConnectionGUID: ACae1aZrQLeGkz96wlm2gw==
X-CSE-MsgGUID: JrbY9Z7+RSSD9psRSyAs3A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,264,1732608000"; 
   d="scan'208";a="111771443"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmviesa010.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 06 Feb 2025 07:40:32 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Thu, 6 Feb 2025 07:40:30 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Thu, 6 Feb 2025 07:40:30 -0800
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (104.47.66.46) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Thu, 6 Feb 2025 07:40:29 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=HzBTjieDyrgIBQmCD0seEwfCtt4AY4pyNFytrSP01wJ3y6T7U9QYoLRI5MTpWKPwaCbomh/MYAcRDxFLAi5055RhpmnMf9CSPaSqpX0IUtNiaf7/kWgz0CENpJ8xsQZR+mLAGOWzuPGcDU8NKpGoV3tEd8A78DMeadBC5Gv4Dyo74fDJY0++mQG6i3LQrWIGLcHYT+Oqk8QlIe3RpouyXembrEziJNqawZqZiIS3tUurEGslQ+nzd4INXPLdJYUiv7U8AvaQ3LgD8xzzeq2I2VNvFFro2PWvVJ0TlEbDenu04OVCJhZuFq7tZvotJqhT4rpWXlggpBMz/dI8p/rtrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=iKvFsTeewNxNzJvrw2sa3fNT8JGOeNE3CWB1C5VFBvE=;
 b=xQDELHugtb0ycYmkIyPiErAfZD7r9OIa9Y1ot4h3aUpV5wK2wHTl3PgV2ql9QeLUpENq1qepbcw2hKpsifvNaVtNGYa5ff053JMy26ikZ3roVYVXPRlbIgl8xBxHGDl/tEixWcfErhLr3w+vHbcL8kvAzXWLRtIyeJ0y7JHBZ4uXLHs8dz2Ag8mZPIUe3vt/hWn/fkXN/KsCxLpHmKX5tPxWn0G1R/yylvonJPK2MKzUIw0sXc3jt2F+q+f8lXO/bGErRT7XUOx9v8vLfYToTX+XR2YoDMijdCCSwEmT084+9FQQ3v/ejwPBlbC9l+224Uov5HCJGE8Ow19zdvv9dg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from DM4PR11MB6239.namprd11.prod.outlook.com (2603:10b6:8:a7::20) by
 DM4PR11MB7352.namprd11.prod.outlook.com (2603:10b6:8:103::13) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.8422.12; Thu, 6 Feb 2025 15:40:10 +0000
Received: from DM4PR11MB6239.namprd11.prod.outlook.com
 ([fe80::244e:154d:1b0b:5eb5]) by DM4PR11MB6239.namprd11.prod.outlook.com
 ([fe80::244e:154d:1b0b:5eb5%4]) with mapi id 15.20.8398.021; Thu, 6 Feb 2025
 15:40:10 +0000
Date: Thu, 6 Feb 2025 16:39:57 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <luto@kernel.org>, <xin@zytor.com>, <kirill.shutemov@linux.intel.com>,
	<palmer@dabbelt.com>, <tj@kernel.org>, <brgerst@gmail.com>,
	<ardb@kernel.org>, <dave.hansen@linux.intel.com>, <jgross@suse.com>,
	<will@kernel.org>, <akpm@linux-foundation.org>, <arnd@arndb.de>,
	<corbet@lwn.net>, <dvyukov@google.com>, <richard.weiyang@gmail.com>,
	<ytcoode@gmail.com>, <tglx@linutronix.de>, <hpa@zytor.com>,
	<seanjc@google.com>, <paul.walmsley@sifive.com>, <aou@eecs.berkeley.edu>,
	<justinstitt@google.com>, <jason.andryuk@amd.com>, <glider@google.com>,
	<ubizjak@gmail.com>, <jannh@google.com>, <bhe@redhat.com>,
	<vincenzo.frascino@arm.com>, <rafael.j.wysocki@intel.com>,
	<ndesaulniers@google.com>, <mingo@redhat.com>, <catalin.marinas@arm.com>,
	<junichi.nomura@nec.com>, <nathan@kernel.org>, <ryabinin.a.a@gmail.com>,
	<dennis@kernel.org>, <bp@alien8.de>, <kevinloughlin@google.com>,
	<morbo@google.com>, <dan.j.williams@intel.com>,
	<julian.stecklina@cyberus-technology.de>, <peterz@infradead.org>,
	<cl@linux.com>, <kees@kernel.org>, <kasan-dev@googlegroups.com>,
	<x86@kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <llvm@lists.linux.dev>, <linux-doc@vger.kernel.org>
Subject: Re: [PATCH 10/15] x86: KASAN raw shadow memory PTE init
Message-ID: <m5v4zoly67gqwzacoraqm7oyptwstj2ojira4qaz2bir7k6bxr@q5iuqozd6nnz>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <28ddfb1694b19278405b4934f37d398794409749.1738686764.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZfKQwNWbYEhk70ykT1+cnibCBnvZJrhAMvu_b0Y8xZTSg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfKQwNWbYEhk70ykT1+cnibCBnvZJrhAMvu_b0Y8xZTSg@mail.gmail.com>
X-ClientProxiedBy: DB9PR05CA0014.eurprd05.prod.outlook.com
 (2603:10a6:10:1da::19) To DM4PR11MB6239.namprd11.prod.outlook.com
 (2603:10b6:8:a7::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR11MB6239:EE_|DM4PR11MB7352:EE_
X-MS-Office365-Filtering-Correlation-Id: 6692f986-8089-41ec-94a8-08dd46c489d4
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?Nm83MVlXS1BML2pTR0ZiMk9FSEl0dDFXcHJHZjV3QW9ZYlNubThLVkowREpp?=
 =?utf-8?B?WlAyc3V2OXdieWQ0MmRBMy91a0RMV0NWKzZ3d3FwNXE2cElrMWJoaWJOWitK?=
 =?utf-8?B?bEdFWkFhM2lEVHdhTWxOZ3JIM2ZndjRGaEJGcnJISnJxVU9lU1NyNThJQ1FW?=
 =?utf-8?B?MFZVZkozcm90LzFTR3FxczhqN2tIVG5ORkRQQ2xZYTBEYlhJWXhGc01jR2g4?=
 =?utf-8?B?Q3hyZTJBZHFOWTVvR2ZmWU1sanBXOTRJaExRamRrR1h3c1F2R1VHQzZPTEFD?=
 =?utf-8?B?K1BoOHN4RHJOb0tOYThaK2g1VDl6d1V6U21WU3JxdTU4VDJHV041WXlwa3lS?=
 =?utf-8?B?ZW00Uy9RbzNaOWlmeHRYNEx2ejVzaFJzbmtFWUJ1WGxyMDFhUEFUakpWeFFk?=
 =?utf-8?B?QkNzRTJ4bkp2QzMxQm5xMFZ3V25xN3J6T1AyMWhjTjBOZXFEMmhGR2FHZ2c5?=
 =?utf-8?B?ZzgwQkdkcjM1RE1WMTU1MmV3REQvUHBoRnBiR2ZEenUxeXF5WDZxUU4yTmtO?=
 =?utf-8?B?Rzd6UE56dHovU2djSFN6MXZqM0RtMzhCcjZEYm9Ib3piRGltQ29xcmhCT3Y4?=
 =?utf-8?B?MzNGMGNQMjhvNVpXM2xIaHpQREhPdW9Nd1gzWmJ5K0IwRVUxbjJSVjRFalhO?=
 =?utf-8?B?ZTNyV0JtNWQ1TURTNktLbGlCQU9PVzN2eXU4YmNwbEJqZC9zdXBscHg5K092?=
 =?utf-8?B?Zy9ZaFVnWTR2S3pYc3JWOG9BZC8zTmVtazBtQ1JWMHdsc3RXQzZmWUNoelI4?=
 =?utf-8?B?SkFIN0FkL3dJWmxzb3orMm1Qb2lsaVBIQ3ZBSTV3emNlU2ZsTzNHbm1ibFIy?=
 =?utf-8?B?VTAxT2RNL1lJNEpJU0E2eVIyWkQxczVUZHNCaExSYTZPaW96NEU0Sm5RYU5k?=
 =?utf-8?B?T1NOUUhJc0VoUGpxaWFrZEMySVB0SmNESHN5eERyaDIwaWpmc1lmY1RWV3g0?=
 =?utf-8?B?ZGE0N2pHa2p3YWhoRUUrME9OalZqUWhsU0tKUjliTnRNcGl4OWZZc1V2cEhJ?=
 =?utf-8?B?Ym9oY1FwZkZGck9tWjZaYkxCbC9sc2pJWEZEbjlpdzd3bGRMcFVVTHQ2R1Ar?=
 =?utf-8?B?MVU1dnNQV0REb3hVRW4wb0dsMCtaTk1XZUM5dmVLc1BVUjRQU1hmbVFST055?=
 =?utf-8?B?UGhzN3EwZ1JkTDFzREdPVjVBcDNEVngvVGNyMEJDRGRtV1l0a25pcStoV1Ny?=
 =?utf-8?B?aS9CMUlUZWdocnR6Rmw2dXIvNzY2ajdBYmxSUEF3Y09GL3lzRUtyU3dzYitD?=
 =?utf-8?B?YnZhM21Yd0J3c25TWm94REw5QWlqcmZWdVFITU44MDN6VmZCQ0xCYlA4TExa?=
 =?utf-8?B?UXpVc1hMUGRia2hQQUlkcWZPMGY2TGluTGI3ZHk1ZTNNVFc1aW95TWJqWWxo?=
 =?utf-8?B?MUJHQXNWRDFPbXlDRExTN0poQVJnd1k0VHd6N1lGR29CTkZhdlFGeGNZbkUw?=
 =?utf-8?B?eXZRZ1oraUdqQjYxeWE1VGViYk93cGRJS2krQ01RWTJ0aFlMZVpMbC9ZdVV4?=
 =?utf-8?B?Q0RUeHplN013b21JZHdHZCticVJpVkw0d0Z0b3BITmlSOUFIamNicmRTQ3RD?=
 =?utf-8?B?b1dmU2Q4V3ZYdnVmeHowYVg1UldxdEI5WkdiQ1ZzSjVDZXZTYVVXYjVNUGZu?=
 =?utf-8?B?SHVwSmRZNHR3UGZHcEJmVjUxWWRzY2MwTVVjVmtFVmNpZkx0RWMxOE9pbURh?=
 =?utf-8?B?QWdnSGp5dXBlNzZWZWxvb1M1VGxGQ0FpdUlRRjYzMTlpd2x1WGpkSnVjbyts?=
 =?utf-8?B?akRGMWFIWFowMWRPR05Fa2ttWE4xUHkyRnAyQVBLSjh5d1BiK1ZOSzlhcEZI?=
 =?utf-8?B?WCsraTNENkQ1R1hkUndVZz09?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR11MB6239.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?TFE3QitIcWswa0hBbjJkU3gySGxBTWl1NDJtVERHaEwxbXpWb2lXajNXVmJ6?=
 =?utf-8?B?c09nUzRQRDJYUCtZeGRWU3QxOTJ3dWpvakI3d1NmbDVHbk9henlja29VcXJ6?=
 =?utf-8?B?U1FvWWFteUhTUWI1ZjBSS1B0eEUzNlNXWnV2eUJwT3ZQZGF3dFpIRUw0cGxl?=
 =?utf-8?B?ZWZNcXpydXNRbVQvZzErblFZZFRBeloxNVlPcHlhVm1jdXFFUCtYOHh3NUFI?=
 =?utf-8?B?aFZUYnd1cWt0ZHBLZ3lUREllaVd4MTdrSHhjNXFhT013T2ZTTVdiRldpdi9U?=
 =?utf-8?B?TnB4RlY5LzhoM1dDbVdHcXZTWllsQVAyRjVITU1aWGFSUERJS3FibmZ2Y0Vj?=
 =?utf-8?B?TnZpaHNDUHhZdjZuNE9TaHRNTWxGYXh3dnk1Q2xMTEVpVEZGa0lERkk2RHRR?=
 =?utf-8?B?K0xsb3pkRE41VkxsSUhzaVFQa2wvVXhJMldlNW5tUHQwcHlHT1dsZHIwckZo?=
 =?utf-8?B?cWtrN1Z3NHBuRjRQem0rUlE5cWppM1doeWJ2MTU3MEphMVlXZU56RDc5NXVK?=
 =?utf-8?B?T2NOMHlqdCsvblFRMDJvNTUvOW5pUDJVQXZ6YkdQVTh0amlTQlE5RENTaWpl?=
 =?utf-8?B?MXk0Vk9aL1BOQmZYUjFDSkhnelpnbm9qWnp1ZERYR3dlT2ZTbGJFS2F3dGpX?=
 =?utf-8?B?RDYyU2JOdXBrUTJvYndCMjRDK3l3ak9Da3FhUlE5cW9BTmhnTEJlekNseWpz?=
 =?utf-8?B?ZHFjckZmNndtRG5wSzJzelVwS3l2VXVCcXpaeHk2YkR4WkNmT1NtbUVhM1Vq?=
 =?utf-8?B?UXBpWDd2WllKYi9YRGJsRVkyNXJlSVJ4TFAzTUZ0Sm56bTNOUTRNU0pqZXV1?=
 =?utf-8?B?NkpZcjJoazVzZ0Q0WDNqdUdpY2EzVnI5N09PV0ZjbERLL0R4dWI5U0lvamwv?=
 =?utf-8?B?bVplN21iWWVEeWtQS3NPVndkT2dhRG5idFd0NVpVcno0Tm0yQUUvU2tyaHNE?=
 =?utf-8?B?TmtvSlNTcWZyUzhiU0UxV0wvUGRoNi90S3lIN1RRWGRPNXVFZVQ2ZDU1SjZ6?=
 =?utf-8?B?dkV0ejUwZ0M5TUZ0b1dObnlpWGhZVDd4MFhVem0wNjF0QjFlUDJ2VDkyTkF4?=
 =?utf-8?B?UTZJTW1iK0YrR3dYdThQbmhYNThvcDR5S1FBbUNmL1AvM0dZZ0NYRzQ0OElN?=
 =?utf-8?B?YVF0K1lpZVRudzA2b1hRR1NJRmF5cTBZd2FBUWR2YllrL1dPc3Q2REd0NWtF?=
 =?utf-8?B?SkJMc1N5OW1qb0tvWGlwMHY1NXBWaUhjN1FIdktDTHRpZHpZNURYOUV0Nm5v?=
 =?utf-8?B?SjluWFk2MTJvbG1ySlFJMHdjVm9DOWwrZVIyM05ucFRCSC9LMC9mRFc2ekEz?=
 =?utf-8?B?YURHelA5L3hDWmdyTWphVG1ON0RxbmhUTGtHOGh2NUVNUGpDQ3hjTVlKenpw?=
 =?utf-8?B?MmZkS3VpZ0plZ09lUWQzK0k3MG5uN3RwY1FvUXR5SVRPRjJ1N2xINHhWTTVU?=
 =?utf-8?B?ZGtaNHE3dXBLQldmL2ZURkNLdDZhNGFLb0dDSVFTMzcxaEZCa203NnZGbE5T?=
 =?utf-8?B?K25UMUNMWVpYZlBROUlRL2NQbGxjTGw1NDJreE1GVGNFWDF0a1ZCNmp3aDNi?=
 =?utf-8?B?ZUFtUDN2MU1wSTFzMm5LSThvWWswNXhZajRLUC81SndnRERuV2YzcXFmeTI5?=
 =?utf-8?B?aWZUellPNHVpeEJyYVZEU2ZwRElWV2xmWG1rbERyOGJwWEZBUnhDZzJaMk5X?=
 =?utf-8?B?VDBHOUs1bUpZYXp1VEg5bmZob3VXcnFqcFJRcENRR044K1F3V2FvQksxcWE4?=
 =?utf-8?B?bkpXSHVFbGZIV0w4M3kyNW51KzBDd1BDNWRycTR3cGlOMjJNamNhK2tZUnNI?=
 =?utf-8?B?N2ZkMTNHelA3M0s4dlNYQWtORkZKeDRFbTV3eTY2U21zaGtvOWhpd3FBZGs1?=
 =?utf-8?B?TGluRjlQeTdqWlNha2NZakRZSUdBelV4V2l6TlRhS1NXajczcy9XODRtNUhG?=
 =?utf-8?B?SC80VzhXOUlSTXYzUVJtQ00vRHE1SVJFb0gzNFl0ZEV2cWJnOTl0b0Vzc0Fl?=
 =?utf-8?B?UnozYWJnQWUvRExRR2VaZzdBSGkybkpLeWdZUG5pZUJ1dS8ycThWWGQzSzJW?=
 =?utf-8?B?V0w4WjM4eDZvYUs5SnlFTUs1aUJwQ2xwN3RYZXR6Q21jTmV4WW5vZHJyWENM?=
 =?utf-8?B?eXVZdUV1MmtQdXROZUh4eDhTQXZKZTM1Ui96OXBHTWJGVkpVcmhteDNGUDZX?=
 =?utf-8?Q?bIPMvOOYA13hg0M60p8IWmk=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 6692f986-8089-41ec-94a8-08dd46c489d4
X-MS-Exchange-CrossTenant-AuthSource: DM4PR11MB6239.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Feb 2025 15:40:09.8986
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: aXEZsErCCoeRP3nMAmMiM0WRq3vk1drKMueS60Qu1j3sSmWV7Z/CLkMJWdMHUMcZ6mzomMum/bfC/R02JT8CUnFL+D3ycYUaqElZMvaLpNU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR11MB7352
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Hx3GwWz+;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
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

On 2025-02-06 at 00:45:49 +0100, Andrey Konovalov wrote:
>On Tue, Feb 4, 2025 at 6:36=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> In KASAN's generic mode the default value in shadow memory is zero.
>> During initialization of shadow memory pages they are allocated and
>> zeroed.
>>
>> In KASAN's tag-based mode the default tag for the arm64 architecture is
>> 0xFE which corresponds to any memory that should not be accessed. On x86
>> (where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
>> during the initializations all the bytes in shadow memory pages should
>> be filled with 0xE or 0xEE if two tags should be packed in one shadow
>> byte.
>>
>> Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
>> avoid zeroing out the memory so it can be set with the KASAN invalid
>> tag.
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>>  arch/x86/mm/kasan_init_64.c | 19 ++++++++++++++++---
>>  include/linux/kasan.h       | 25 +++++++++++++++++++++++++
>>  mm/kasan/kasan.h            | 19 -------------------
>>  3 files changed, 41 insertions(+), 22 deletions(-)
>>
>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>> index 9dddf19a5571..55d468d83682 100644
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -35,6 +35,18 @@ static __init void *early_alloc(size_t size, int nid,=
 bool should_panic)
>>         return ptr;
>>  }
>>
>> +static __init void *early_raw_alloc(size_t size, int nid, bool should_p=
anic)
>> +{
>> +       void *ptr =3D memblock_alloc_try_nid_raw(size, size,
>> +                       __pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE=
, nid);
>> +
>> +       if (!ptr && should_panic)
>> +               panic("%pS: Failed to allocate page, nid=3D%d from=3D%lx=
\n",
>> +                     (void *)_RET_IP_, nid, __pa(MAX_DMA_ADDRESS));
>> +
>> +       return ptr;
>> +}
>> +
>>  static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
>>                                       unsigned long end, int nid)
>>  {
>> @@ -64,8 +76,9 @@ static void __init kasan_populate_pmd(pmd_t *pmd, unsi=
gned long addr,
>>                 if (!pte_none(*pte))
>>                         continue;
>>
>> -               p =3D early_alloc(PAGE_SIZE, nid, true);
>> -               entry =3D pfn_pte(PFN_DOWN(__pa(p)), PAGE_KERNEL);
>> +               p =3D early_raw_alloc(PAGE_SIZE, nid, true);
>> +               memset(p, PAGE_SIZE, kasan_dense_tag(KASAN_SHADOW_INIT))=
;
>> +               entry =3D pfn_pte(PFN_DOWN(__pa_nodebug(p)), PAGE_KERNEL=
);
>>                 set_pte_at(&init_mm, addr, pte, entry);
>>         } while (pte++, addr +=3D PAGE_SIZE, addr !=3D end);
>>  }
>> @@ -437,7 +450,7 @@ void __init kasan_init(void)
>>          * it may contain some garbage. Now we can clear and write prote=
ct it,
>>          * since after the TLB flush no one should write to it.
>>          */
>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>> +       kasan_poison(kasan_early_shadow_page, PAGE_SIZE, KASAN_SHADOW_IN=
IT, false);
>>         for (i =3D 0; i < PTRS_PER_PTE; i++) {
>>                 pte_t pte;
>>                 pgprot_t prot;
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 83146367170a..af8272c74409 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -151,6 +151,31 @@ static __always_inline void kasan_unpoison_range(co=
nst void *addr, size_t size)
>>                 __kasan_unpoison_range(addr, size);
>>  }
>>
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +
>> +static inline void kasan_poison(const void *addr, size_t size, u8 value=
, bool init)
>> +{
>> +       if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>> +               return;
>> +       if (WARN_ON(size & KASAN_GRANULE_MASK))
>> +               return;
>> +
>> +       hw_set_mem_tag_range(kasan_reset_tag(addr), size, value, init);
>> +}
>> +
>> +#else /* CONFIG_KASAN_HW_TAGS */
>> +
>> +/**
>> + * kasan_poison - mark the memory range as inaccessible
>> + * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
>> + * @size - range size, must be aligned to KASAN_GRANULE_SIZE
>> + * @value - value that's written to metadata for the range
>> + * @init - whether to initialize the memory range (only for hardware ta=
g-based)
>> + */
>> +void kasan_poison(const void *addr, size_t size, u8 value, bool init);
>> +
>> +#endif /* CONFIG_KASAN_HW_TAGS */
>
>Please keep kasan_poison() and kasan_unpoison() in mm/kasan/kasan.h:
>these are intended as internal-only functions (perhaps, we should add
>this into the comment). Instead, add a purpose-specific wrapper
>similar to the ones in include/linux/kasan.h.
>

Okay, got it, I'll pass it through a wrapper.

>
>_______________________________________________
>linux-riscv mailing list
>linux-riscv@lists.infradead.org
>http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/m=
5v4zoly67gqwzacoraqm7oyptwstj2ojira4qaz2bir7k6bxr%40q5iuqozd6nnz.
