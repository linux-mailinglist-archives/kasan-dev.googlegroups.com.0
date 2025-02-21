Return-Path: <kasan-dev+bncBCMMDDFSWYCBBK464K6QMGQEOSIJKDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id DC75EA3F753
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 15:35:24 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4720fdeabddsf58340531cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 06:35:24 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740148523; x=1740753323; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5eUZJbkcuHcC1ZyyMYzi1aVAu+nXWvlRuqEaayXnNXA=;
        b=Ldbq47OXYj7t09DSvR9j0WpzvZFJog9z9EgdH7QeW/CASMBzcpzQD4uP1eWM8oqwfk
         yBZp4JF5nWwu7IoX9PQSGPLtYSU8R8chLZWJvviOZczfj+3fAbu1cwRbbOny+MKBaraE
         cmJihu5/rLyce8Xzow9AR80dg227CxoYK6YAbWkCPwg9c4hVyVvLip0GeWP3jNrcxLnf
         J2g3g41rUMKNBIMGA9hrhGqb5+OqarfdWq7/Zv1JI7mQdVp0Z7DsqrEMkDQpbcaYQ7JC
         m+xMdx/oBwa+CzU3tPqluApiW1tRoctPq1eu6mPHyeTj4PNjbG9ROyPKKyRGcT9uSCMG
         23UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740148523; x=1740753323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5eUZJbkcuHcC1ZyyMYzi1aVAu+nXWvlRuqEaayXnNXA=;
        b=AEkXV4cBorfYIt8q7dSxFEYmfNnMQjwu45Tnw7AC/6x2oljJi359jrOuQjxzg/4xSc
         fCTwx7TtIyUwI5vPlEYdV2DxNgKiF2ElfBMKtN7cWzUgkW5QN0aF8+mVpSbRiqyl97Pa
         SCylbsmDpHCjFqNObaPPkPUnF70VgBx8c7wAIMUdum/5chy+t3dlBbVQ0NdBXE1pN5Fj
         ABjGsOoUKxddq3xiUxroZdVu/qLkiUYODfiIpB4GzIx/iss58SiqqiMDXNk1Qnil5R/W
         MPLoDC4nyHx6n6NtoXDWlSu3csr66okFlnqcMmj355JeYqSNSC1YWEGhxecKs/mZM2IT
         y3lg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOtCggz8mt4CwOLBUb23ERt7ImOeS4g8C4DWsgKZHW9Ywe3r2P699k4nAlqs42AFnDDEIU/A==@lfdr.de
X-Gm-Message-State: AOJu0YwIqEtySJxymECLqz6VBkkZxG3uQgWJiK53SpjDMSWDXnqPMk6n
	yLSM7DXRyK+8HiXK+icxhvnPMm8YgIDyuWq8ntsMkt+WjCvZjKDA
X-Google-Smtp-Source: AGHT+IFM4TvDXlkNNA6zggY7GPbEXQfiMD7Whq4RLC7TXirngFyLcoIF/IIOnmh1NiD3EA7IkHiNMg==
X-Received: by 2002:a05:622a:2d2:b0:472:697:9ab5 with SMTP id d75a77b69052e-472228c8407mr47919651cf.12.1740148523366;
        Fri, 21 Feb 2025 06:35:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH71a7RzTEtnGk/XCWv3n5su7S2OH88BH/lgnRYaAbfFw==
Received: by 2002:a05:622a:103:b0:471:824b:260f with SMTP id
 d75a77b69052e-47214fa9a90ls46108411cf.1.-pod-prod-04-us; Fri, 21 Feb 2025
 06:35:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWN65aeDSODXGcrOW9fKFG43qSqgQGjUflVnHdp7+W+kR8Qy2oARW9sllckqrfetJuI97rUt0Dmn9Y=@googlegroups.com
X-Received: by 2002:a05:620a:29c2:b0:7c0:a64e:8442 with SMTP id af79cd13be357-7c0ceef74c0mr480309485a.16.1740148522384;
        Fri, 21 Feb 2025 06:35:22 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.18])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c0abef9024si35062485a.5.2025.02.21.06.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Feb 2025 06:35:22 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.18 as permitted sender) client-ip=192.198.163.18;
X-CSE-ConnectionGUID: DQzmpJ3cTzGHOSZkaNGxBA==
X-CSE-MsgGUID: CNTb7x6oS6SRrMN1Zzs95A==
X-IronPort-AV: E=McAfee;i="6700,10204,11352"; a="40197797"
X-IronPort-AV: E=Sophos;i="6.13,305,1732608000"; 
   d="scan'208";a="40197797"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa112.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Feb 2025 06:35:19 -0800
X-CSE-ConnectionGUID: 6agdEVkCTtynIgxkAj/FOQ==
X-CSE-MsgGUID: jPe5jo+kRIKFi18EZn0h0Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,305,1732608000"; 
   d="scan'208";a="120313298"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by orviesa003.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Feb 2025 06:35:19 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.1544.14; Fri, 21 Feb 2025 06:35:18 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Fri, 21 Feb 2025 06:35:18 -0800
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (104.47.56.169)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Fri, 21 Feb 2025 06:35:18 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=B9Rbsmu7NWBSC8C4j9Wxrkvj/RibHJfzIv98Ekt2i6khJ9stsYnKvab9oQ51UbtB0pKMXd0Jt9cKhkIH+ZWIRXZbnnimeDnul2Gx6MUIlJvGKU0SKWLnVKXcXaQrtk2aqnoc8yrRwA3Uf7xaEOO0wEde7WZZ8C07Ywuux+hRLmc+t9o/xoTRCylc2rtbBNgAmrBXID0VE6/SolHYFYWM+A6qD+zABmAi4uULuJR498bztSym56tfe2E9P/ilYus9Ei+IJg7EBhdSGX1viCxy7JoJ2YyKWnJVBZ2TF3Y9APUHC147aLZ1uuiPCBkzqSV/BP84UDR7TU9A8KdtsBwOkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=zHLxGxzgT5HB9cIiVYmc0hgwGSAEspN0CpeJt/hRu68=;
 b=gL0yqUl0d3jUeZ4OO6yZ/uzUAa1QPErL36u+LOwtgxhCgSvdJY9XvBk0/XgOXW1fPAc6aWKbeDuCB+3I+wkGe43tfLQDP/+/Vd9r2Q1xxjK5jTZq1BiTUdQ4w2tctqIoePh605w4OruPUQu2AyybddOMLHHiHvylEWc9faFA8ZejkVH3gzH5g7TJIxZtwFt5LNa2p7+LlvAAfLFKq4tj5zB8QdjY6rUsXSm2sKOlNnEeTsjD2rkzF4xlchpJZpjyeZq867k7iIHvOCEbARYvlAMOjYrBs7snA8crJJN5+nRU6ktD2wc74CiEr9QVIgM83kkvZEYZzHyiv/nnUlGpUA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by CY5PR11MB6258.namprd11.prod.outlook.com (2603:10b6:930:25::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.15; Fri, 21 Feb
 2025 14:35:14 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8466.015; Fri, 21 Feb 2025
 14:35:14 +0000
Date: Fri, 21 Feb 2025 15:35:01 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <kees@kernel.org>, <julian.stecklina@cyberus-technology.de>,
	<kevinloughlin@google.com>, <peterz@infradead.org>, <tglx@linutronix.de>,
	<justinstitt@google.com>, <catalin.marinas@arm.com>,
	<wangkefeng.wang@huawei.com>, <bhe@redhat.com>, <ryabinin.a.a@gmail.com>,
	<kirill.shutemov@linux.intel.com>, <will@kernel.org>, <ardb@kernel.org>,
	<jason.andryuk@amd.com>, <dave.hansen@linux.intel.com>,
	<pasha.tatashin@soleen.com>, <ndesaulniers@google.com>,
	<guoweikang.kernel@gmail.com>, <dwmw@amazon.co.uk>, <mark.rutland@arm.com>,
	<broonie@kernel.org>, <apopple@nvidia.com>, <bp@alien8.de>,
	<rppt@kernel.org>, <kaleshsingh@google.com>, <richard.weiyang@gmail.com>,
	<luto@kernel.org>, <glider@google.com>, <pankaj.gupta@amd.com>,
	<pawan.kumar.gupta@linux.intel.com>, <kuan-ying.lee@canonical.com>,
	<tony.luck@intel.com>, <tj@kernel.org>, <jgross@suse.com>,
	<dvyukov@google.com>, <baohua@kernel.org>, <samuel.holland@sifive.com>,
	<dennis@kernel.org>, <akpm@linux-foundation.org>,
	<thomas.weissschuh@linutronix.de>, <surenb@google.com>,
	<kbingham@kernel.org>, <ankita@nvidia.com>, <nathan@kernel.org>,
	<ziy@nvidia.com>, <xin@zytor.com>, <rafael.j.wysocki@intel.com>,
	<andriy.shevchenko@linux.intel.com>, <cl@linux.com>, <jhubbard@nvidia.com>,
	<hpa@zytor.com>, <scott@os.amperecomputing.com>, <david@redhat.com>,
	<jan.kiszka@siemens.com>, <vincenzo.frascino@arm.com>, <corbet@lwn.net>,
	<maz@kernel.org>, <mingo@redhat.com>, <arnd@arndb.de>, <ytcoode@gmail.com>,
	<xur@google.com>, <morbo@google.com>, <thiago.bauermann@linaro.org>,
	<linux-doc@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <llvm@lists.linux.dev>, <linux-mm@kvack.org>,
	<linux-arm-kernel@lists.infradead.org>, <x86@kernel.org>
Subject: Re: [PATCH v2 02/14] kasan: sw_tags: Check kasan_flag_enabled at
 runtime
Message-ID: <4r43exy2amyvqj6pc6gd22ed2zsumofv7u4ghplidybmnlezhx@h5mipkqhdmth>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <b1a6cd99e98bf85adc9bdf063f359c136c1a5e78.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdRHNaxf02DXMm3q+Ecwd4XiaVZ0X9P-sdFfy+9jBMO=w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdRHNaxf02DXMm3q+Ecwd4XiaVZ0X9P-sdFfy+9jBMO=w@mail.gmail.com>
X-ClientProxiedBy: DB8PR03CA0014.eurprd03.prod.outlook.com
 (2603:10a6:10:be::27) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|CY5PR11MB6258:EE_
X-MS-Office365-Filtering-Correlation-Id: 67bed4c1-38bc-4c5f-36ad-08dd5284f440
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?NU5HZ0YycWNkVm5ndmtSYnBGUTdJUHB4ZCsveVN0MEM2b081WU4vcUFHczB4?=
 =?utf-8?B?K2ZPQU0wVnl6b0Y5NFpUOGloVGlJOFlaWGlaMENONzlvZ2ZSdW5KU1Q2SXV3?=
 =?utf-8?B?Wnc5REQ1NVFKOTZwdWtSUG9NcU9DWlhveXZ0SWhmTU9yMCt3RGxBaDBacGR5?=
 =?utf-8?B?M0pocTJXNndaWERwS1kxVU9QcWhKK0tkZXd4QjRxaVBra3RweUdQd2E4cUZT?=
 =?utf-8?B?SVdoMXpwVEMwZFlTU3pQaHdTZWNGdWxwYmNuSGs2eHhvcUpsQm9uV0lpVGdM?=
 =?utf-8?B?ZWdXVk9VVGRVYnJTbEY2cm9aVmszRXhoRDFnMm0wYmxLVlVIQXRxNlU5YVpn?=
 =?utf-8?B?bU1ub3FwcmxtaDVHOWdjNDRRaVZwREthL0dwWnd5a2lXVzdTL25RSVRqN1Rt?=
 =?utf-8?B?eFd0UXZ4K0FlMExlN1BQbGlpMUZKZUNsNkd2MTQ0N0pEZ1FvSmlIWXdVRThJ?=
 =?utf-8?B?L0JSdm44QTlPeXRta01NczNSZURKWDdkcXBwV3pGSGtzTnJIMFJoM3pZZ2dn?=
 =?utf-8?B?bi9HeTdTK25jaG1DckFoRG5VVXpFSitxSndqSjV6cVFKei9HTjJhcmlLWDU5?=
 =?utf-8?B?Ylc2a1dVQkJQNzlGczI4TzBwUlU1eXJuRkFSbUM3S1pGWGNSWVI2cEJoZFdL?=
 =?utf-8?B?dUU5N2pvSzYwSkhqV2xROXg4dlRmK3MrcFZMVnlxeERUL0gvT1dZQWIvZlR5?=
 =?utf-8?B?S1pTWVRvTFZ1TWdkcVE4OUZhUHdHUkZjVEN4VGpERHRSOE9DMW5YTG03aWdQ?=
 =?utf-8?B?RUdDZnhScFhwdU8yMmFkQVVrME96RGs3MnBsRE1Fb0lzdGhDWTYrNDJpSHA1?=
 =?utf-8?B?OU1WVlVSOFJGVURONGNtc0FUaGZsL3YyQmhEOTdiUGVka1djNzFCL2FDOUkz?=
 =?utf-8?B?MXVLY202R2hJcDgrQktpL0JnYmp2bVNIWW5aVTdVMnk1aHVpWE56Vjg1UTFH?=
 =?utf-8?B?Yk5VQUpEd3llY0hCWUduVDZWUWQrc0N6NTVSTkNVcTlXWjNlRUNuUFhENDBq?=
 =?utf-8?B?dU94SUpTaXJ1Q0FDRlhhQ3cvaXZTdktFaUhnZThUekRhb1k5dHlpd0VnVjZt?=
 =?utf-8?B?WU54SGlYVWxSTzRNUjljWXJBaGJhWlorVHNWdnlzWGRHcy9GcXhwdWVNUE9K?=
 =?utf-8?B?Z3F0K3p0SFk4MmlIQlRESkE1aXFRNGE2dk42ZW45ZHRKMnlPSnIxWE93elBN?=
 =?utf-8?B?UzFxSitFY0FvZDRnWHphUTlJRmkrMHBXMEZXOE9kdzJtdzUxblI2SGFqUkox?=
 =?utf-8?B?MnJ5dU1qelZGQS9tZXdLMHNWUFZWSlVhRjVrR3g3L1k5aCt2RlpXb2h6emtP?=
 =?utf-8?B?aXc3cEtCbjZLSW1SWDdJNUpVTW0vNGRad1p4YUhUcGVFNk9kdXhxRGxOeEl6?=
 =?utf-8?B?T2s3KzlCL0REY3hzdWg4Nm4vOVE4R3Y2MUdBQWkvTlRvOU9TQ3ZaWjhhcDdB?=
 =?utf-8?B?WjB1dmdOODN3QVRaRHNkTlVkdVNmMWRCTmJRdnV5cUZUU2FvN1BkMytZd09r?=
 =?utf-8?B?cy91dEpYL0J4VmlQMzlGV3pRUGMvS1MrZUhTVlplaEs1bHBNa1ludUJrZjhJ?=
 =?utf-8?B?cnQ4cmlCTmREdmlqV3A0dTl1ZFJiZS9JVmhVZUY5SFVYMCtVYzBncHVoWnNQ?=
 =?utf-8?B?RVA0Y01ZMm1wdFA2TFBVTWk4L1grZ1E4ZVViNWJzb3hpb1hJQzR1d2l4U2NH?=
 =?utf-8?B?ZDEvNm5QRFhMQ0FLc250WlNKRTdXZm5zZ1Y2ays0cGxvN2U0NVUxVXl2d0xR?=
 =?utf-8?B?bWRtRUN3cmRLazNXRFpEdzBNWGVNRUt2Q0NhdHpEdXRPNE94ZzVLMk5pMVBv?=
 =?utf-8?B?aDdDbFkxcU9HZWRZNGJWN0wwLzhIalJLcWI4WGZibCtJVHY5cVkrYkQrS1V0?=
 =?utf-8?Q?I6vtFkDxYiz3l?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?a0FOVjBScWE3d2Ztb1Ixc0tad2hSYzZrNTNCcEhOa1VYd0VBSm5Hd0Yxamlz?=
 =?utf-8?B?WWw1VnJzLzVQeDd0bFBmMERKbFkyWi9yUVhUd2xIUUc2VzRTTy9VOWJ5RjJW?=
 =?utf-8?B?czA1KzRkcmpYcjdXTnNSR0d5ckZtTkdNeGdTTG1xQ2MzRG1xWnNkOURjWWJM?=
 =?utf-8?B?YVBiQ2p4MGFmQm0ycWZWYkZ6WXJkK0o2dUFYT0N1WUZpM0dYdWM4c0ZHZHRZ?=
 =?utf-8?B?TlB6RkYwVTNuOEVXS3ZPbWsyWWtkWlpuaWN3OHRkQ0tqTm1MZHRPS3pLVENL?=
 =?utf-8?B?K3hCa292TlROMVpCUDRoNmVGT2FORmNwdjVvN1VHM3dWUW9TQXN2N3dzVU9F?=
 =?utf-8?B?Q2p3TmNzZGxLYTR1K3VDYkdBN21rMWdvbEk4WXNoeDdSK21OQ0JibzFlS2pp?=
 =?utf-8?B?aWJRMWdwT0xGRUk0cjh2Rk9wOXNvNDVJUEQyZTFYZDVJb1lSMlYycVE0dVdv?=
 =?utf-8?B?eHBhRzFCSVJOd1NyUDl2YS9Qd2tBeTc5bjdLL0JnRzJyUDZ0VU9OMkJsRVRs?=
 =?utf-8?B?SGhEQ2czQVpId0FTSUdONDNrVDlOZ0Z2c3VWVCtSOTRmUlI0amZHdWp5OElm?=
 =?utf-8?B?VUkyYko3ejRVc096ZGxOdFp4RitDSDVTR0xDejdYYkl1MWJidzRnbDJaV3Rs?=
 =?utf-8?B?bXZHTHkyZ0RKWUxUQmZNa1QveEVTTm1Uck9ldlpWV0M1ZU5pd2lPamlsNHU0?=
 =?utf-8?B?ZzVxb0VnbGNOaHVpWVlsREh2eWZ3VVdCbXJ6S1Y3UTZhbzR6UUwrNUZBZDdx?=
 =?utf-8?B?OURzYVZ3Q05DTVNGTkppbGovYVdwUVdmVFh4aE4xeC9ocjJ6WWYwaFZLcWtj?=
 =?utf-8?B?M0Y1T1ZVYTM5U0ZsV0xBbEt2Y0ZKVFJ1WktHQVJjZ0ExWTgwTFEyRXREdUxo?=
 =?utf-8?B?U29mTlVFeWNmUll3RkYyVmRtYU0xVXpNWWptTW9FMmgyOXJUbnJLMGRidFZH?=
 =?utf-8?B?QUJITTJtazQ1ZUZYa0RIdVZNeWcxNHRsMUJ5VU9oRjVWTnNjNTgxdVA2Qldo?=
 =?utf-8?B?bjMxVUdDUU5EcjVVb3VYckkyWEd5ZWpYVGpxQUhMYitVY0tSbWw3SGlOM3NQ?=
 =?utf-8?B?bVpZSVp1bldodnhwWXFEcUdNeWtNZk9TT1k5NXBPYk4zYVR2T2JiRlM5LzRF?=
 =?utf-8?B?S1plYkFCZ0UzRTM3TU9rUXBWR1cyYWY5K0c1d1pLbW1ha2lTb2NjYUVVVXVk?=
 =?utf-8?B?aTg2dVU5blVoVG1SUjZoZU02MXBOc1JFeFBwcFdIVkdjS3VQOStJVEl2cWR5?=
 =?utf-8?B?Z1JBM0JFZ2NFRGcrTDJGVWVoS3U4d1ZEY2hiTkNaNU1NMEdnUEdMK2ZiS2N6?=
 =?utf-8?B?ZHBNVXpLR3o5bzdEYkR4MHdpTit3T2RqL3hsSGg2UXEyVmloLzRSVGo0RmUz?=
 =?utf-8?B?MVp3cVZBYlRaWUh6RDkvYmp4Qm52OG9YSnBIMmthUHIvSm5hVy9GeXdhYTd4?=
 =?utf-8?B?YlFNY1BGSUhFU3NLL3F3NGNDUmNtZ1p1MjFlcVV6ZFNuYjB3cDBYN2Ivd0FF?=
 =?utf-8?B?SlcweHBNYUpQc25OSDMwcVBGeExXSEJNd0xQRnI1ZGdPdmI0Zk9nZTJWQU1B?=
 =?utf-8?B?Q21ZZTU4RzM4T1l6ZkZyRnA2bmJPY0tmOTVPRW8vZXVHb3hReVVCOTZJKytq?=
 =?utf-8?B?M0NjOFJudXErblZ3bVliMVBDcnozbElFZkVRNXU2RHdGM0gvTEtrYWt2RU5z?=
 =?utf-8?B?RmRXV0o0bDZYc3hNS3ZhUm9HdXdycFlDZHBkNXcvM0wzai9vL28zSjlIUGVW?=
 =?utf-8?B?eWU1TkpaT3FxRlVKNVZWU2hvRE5yYWFXTXpHVzhXWm55WjYraVpDQS9QZmlC?=
 =?utf-8?B?VytnQnA3ZGxyNUdqc0ZwaWZJSklHNm9xNUYxT2dhS0dnS1RscDRCeFBTR3NU?=
 =?utf-8?B?V3FRN3RZMmx2STJHZmdMb0dKc1hiR2J3V3pmVldBbWhPU1d2TElNYlo5N1pk?=
 =?utf-8?B?VEY1aHBjVDBiOTl3UGozZWp0TEQ0ZExlOE91L3pxbTJXZnRGclNpdEhRWEkx?=
 =?utf-8?B?TjgzZDd5VVMwcmJCOTllOXQzajlkSUdkRzErNHJaaFpmai90cjJycjBqK2h0?=
 =?utf-8?B?SU5ZZzNDMDVzVFZxaWhrTFA4VVdreCttWHdvdzRLemJQekVLdjEwWmliSURn?=
 =?utf-8?B?T2JwbklKNDRHbHZmcmVqK3F1aU1XL0dzTVBrRVQwNTBiOTlPd0I5RjBWckUz?=
 =?utf-8?Q?7HOZOIAIAuaGoSAIgRGeiFI=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 67bed4c1-38bc-4c5f-36ad-08dd5284f440
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Feb 2025 14:35:14.5579
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RW1/p9peopElCXwrDehhZ5P1k0WtsHw6hKeDXqaCr43HE3Dl1rKdk9UGBdwT/RKfYgDy9mM+mVgJ9qK/YDG/M/0VC1bpIYl7W+LQT8lEXpU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR11MB6258
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Izzf30Ww;       arc=fail
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

On 2025-02-20 at 00:30:09 +0100, Andrey Konovalov wrote:
>On Tue, Feb 18, 2025 at 9:16=E2=80=AFAM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> From: Samuel Holland <samuel.holland@sifive.com>
>>
>> On RISC-V, the ISA extension required to dereference tagged pointers is
>> optional, and the interface to enable pointer masking requires firmware
>> support. Therefore, we must detect at runtime if sw_tags is usable on a
>> given machine. Reuse the logic from hw_tags to dynamically enable KASAN.
>
>Is this patch required on x86 as well? If so, I think it makes sense
>to point it out here. And do the same in messages for other commits
>that now mention RISC-V.

Not really necessary, I just thought all the general kasan patches from the
risc-v series could be added here at once. But you're right, I'll let Samue=
l
send these two (2nd and 3rd) patches since they relate to risc-v and not x8=
6.

>
>>
>> This commit makes no functional change to the KASAN_HW_TAGS code path.
>>
>> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>>  include/linux/kasan-enabled.h | 15 +++++----------
>>  mm/kasan/hw_tags.c            | 10 ----------
>>  mm/kasan/tags.c               | 10 ++++++++++
>>  3 files changed, 15 insertions(+), 20 deletions(-)
>>
>> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled=
.h
>> index 6f612d69ea0c..648bda9495b7 100644
>> --- a/include/linux/kasan-enabled.h
>> +++ b/include/linux/kasan-enabled.h
>> @@ -4,7 +4,7 @@
>>
>>  #include <linux/static_key.h>
>>
>> -#ifdef CONFIG_KASAN_HW_TAGS
>> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>>
>>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>>
>> @@ -13,23 +13,18 @@ static __always_inline bool kasan_enabled(void)
>>         return static_branch_likely(&kasan_flag_enabled);
>>  }
>>
>> -static inline bool kasan_hw_tags_enabled(void)
>> -{
>> -       return kasan_enabled();
>> -}
>> -
>> -#else /* CONFIG_KASAN_HW_TAGS */
>> +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>>
>>  static inline bool kasan_enabled(void)
>>  {
>>         return IS_ENABLED(CONFIG_KASAN);
>>  }
>>
>> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>> +
>>  static inline bool kasan_hw_tags_enabled(void)
>>  {
>> -       return false;
>> +       return IS_ENABLED(CONFIG_KASAN_HW_TAGS) && kasan_enabled();
>>  }
>>
>> -#endif /* CONFIG_KASAN_HW_TAGS */
>> -
>>  #endif /* LINUX_KASAN_ENABLED_H */
>> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
>> index 9a6927394b54..7f82af13b6a6 100644
>> --- a/mm/kasan/hw_tags.c
>> +++ b/mm/kasan/hw_tags.c
>> @@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
>>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>>  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
>>
>> -/*
>> - * Whether KASAN is enabled at all.
>> - * The value remains false until KASAN is initialized by kasan_init_hw_=
tags().
>> - */
>> -DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
>> -EXPORT_SYMBOL(kasan_flag_enabled);
>> -
>>  /*
>>   * Whether the selected mode is synchronous, asynchronous, or asymmetri=
c.
>>   * Defaults to KASAN_MODE_SYNC.
>> @@ -259,9 +252,6 @@ void __init kasan_init_hw_tags(void)
>>
>>         kasan_init_tags();
>>
>> -       /* KASAN is now initialized, enable it. */
>> -       static_branch_enable(&kasan_flag_enabled);
>> -
>>         pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s,=
 vmalloc=3D%s, stacktrace=3D%s)\n",
>>                 kasan_mode_info(),
>>                 str_on_off(kasan_vmalloc_enabled()),
>> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
>> index d65d48b85f90..c111d98961ed 100644
>> --- a/mm/kasan/tags.c
>> +++ b/mm/kasan/tags.c
>> @@ -32,6 +32,13 @@ enum kasan_arg_stacktrace {
>>
>>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
>>
>> +/*
>> + * Whether KASAN is enabled at all.
>> + * The value remains false until KASAN is initialized by kasan_init_tag=
s().
>> + */
>> +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
>> +EXPORT_SYMBOL(kasan_flag_enabled);
>> +
>>  /* Whether to collect alloc/free stack traces. */
>>  DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
>>
>> @@ -92,6 +99,9 @@ void __init kasan_init_tags(void)
>>                 if (WARN_ON(!stack_ring.entries))
>>                         static_branch_disable(&kasan_flag_stacktrace);
>>         }
>> +
>> +       /* KASAN is now initialized, enable it. */
>> +       static_branch_enable(&kasan_flag_enabled);
>>  }
>>
>>  static void save_stack_info(struct kmem_cache *cache, void *object,
>> --
>> 2.47.1
>>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
r43exy2amyvqj6pc6gd22ed2zsumofv7u4ghplidybmnlezhx%40h5mipkqhdmth.
