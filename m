Return-Path: <kasan-dev+bncBCMMDDFSWYCBBOOW77CQMGQE7J5745Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id EAB79B4A60A
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 10:54:18 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-6215a926e31sf3815152a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 01:54:18 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757408058; x=1758012858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KIsp09eF8sjCUEXmgtQvcAU083IX4qryTluAMKrNqHg=;
        b=MdafiU51VvwbYNqn8SB3LZiMXnRgYCcPNkCD0ReMfTtM0zk2YIyEbAgMjsomkeMt9D
         LC/z0J2zXXamUsI+ye6TwNR8hxtguLo83dlmrMk/IGd7PNwgJuAH0/OZDIUdKtcH9SsH
         XI0DZP47nL4ZAm+NcRtnBrpzjH2XLuIJYh/XwuExJYSvXRR/geCSzYfRxaHWacCOMyi3
         LfQQYFNU41EzLJTzJK6DrJcLeyJ2fPM3UGDpoVf0zlzOK1kuNXJNt9raxcZPeIWpqYSR
         KpAr+jTOSW1v5ZOxXPQLJfvc9wY0R/kJDhJDJVjN6eY29by1Moh3ouj3xfVTD4QHbWrE
         bmmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757408058; x=1758012858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KIsp09eF8sjCUEXmgtQvcAU083IX4qryTluAMKrNqHg=;
        b=BCBuvUrD61cHIiImsCUiOU+5MJvlL+8LzKXRrPRsF4HoVz1Mc36/L5bXzazbo7h2vE
         0J2q4h7mI0xFnZTrmmP6nB2J6uSxOrKYKEQkyIKQGaTYm8Km0uwqS39KrZLUX4M2ISqh
         rQj2+bFtHKfqwXrG6rfA+iAivwg9xikyZMn1hH/0CCLY49K1IO1c/f8FHDcdRzFzTwhi
         d26xZds6htpYuwACq3yDEdnpJIiAS2zpybdZm6IFo/Ob5Cel3aHB6oPhXIWBqneM3yMD
         7NGT+L4tQbB5uicRPslmL/OuAOTJc5UWxsNB/2Fb6Bso5vWyyxJNwM/P/6JwO+ek+ffu
         NaAw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUUrSonwRh4coAfaT3cadlqL3dSwEiFTq5Hon3ZS2tOJ4d+YZjPDL71aCYQRzKKPs/YW7o53Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy8hwDeGZi+dIFeBNsV6jdv60732bvdTTRlMQ9ZkeAX78M/nwCR
	CWwulYCLPtls14bvfHTGVAl8wd9QPfl0gxZx91FLkEIUdnWBeJlmiagw
X-Google-Smtp-Source: AGHT+IEhuG3+JFtWKJH9104b6hYWcZMpTc+dd0XUTlMoYHaUIDcDmQPC0fkKVLhZM4d+YLSBkGQM5A==
X-Received: by 2002:a05:6402:1ec8:b0:625:fc4c:567f with SMTP id 4fb4d7f45d1cf-625fc4c5725mr8335500a12.18.1757408058127;
        Tue, 09 Sep 2025 01:54:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7Tyx6Oe0Ad/A5PHUn1psueEUAeq/KUZEQBVbyf5A8jjQ==
Received: by 2002:a50:9fee:0:b0:615:7125:5fa3 with SMTP id 4fb4d7f45d1cf-62148956631ls3384121a12.1.-pod-prod-02-eu;
 Tue, 09 Sep 2025 01:54:15 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUWn4mC5EX9l36RfyEJUaunrxA3vOAeOKe9AL0l7kVZZCd02xMJTC29ysXByh9VfvUgnEZy86Sbu2o=@googlegroups.com
X-Received: by 2002:a05:6402:5249:b0:628:9fa6:6b22 with SMTP id 4fb4d7f45d1cf-6289fa67387mr5559407a12.8.1757408055413;
        Tue, 09 Sep 2025 01:54:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757408055; cv=fail;
        d=google.com; s=arc-20240605;
        b=KWWNktZC7EMKBfbLVI/80GpzEsW+MS3vBgB5NADW+gpmjWC1tlAFCm0iV1zf+dQf61
         /nBs/HJzsLR91aGNj0OorS+si0b/MFto7BSjMlrGfvexzMl1pe6DX0+EQL+uwJG+gwDO
         8KsUCaLMKneQX4HuHHQuISWXickI/BOXEDMpyXjosvnkBcCgpGUL80xTnDRfgpck7aRs
         G6HdbCss4a7LllV15Ia1IhDp2sf/xdZSh8Bm/JZ62G7CNFz7HeKXL+l7aq9h0c7nmtCN
         yLCJtqhXpDeVvKw0d031SPxC+GFp7w4lZqymz2XXJ86z2heF5YSIQ8ECGZgZvbmG4EkR
         MQNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=aSQGm55NyRV3vwmZjBzOCDU/H5qZ8W8i1JEkgogs6bA=;
        fh=Wufhi7rrwD20YmLOonxnFQWKE9Ef0FLnk1Jd8nrbCPI=;
        b=dAH+BK63KEuVHrteULQmiScszEblFE6SiU4sv+eBE8EGSdCIMUjLthfwn2lRFi5Npr
         FGCx8gg0dPiqit3M/I01YfG0OKDH8nqMVAx/EmWeSbs20b7/jHKyGpBGsFS+n0METyq1
         DNTxVYNfywujX+5gHcSpVThB43Ojb9kzrUSio/ERfR2SLFT17d5jhh29HciaclP+HXqH
         nnViY/6X10YUs/XWIB8SL0UKogahu+gqbple6BqJu1EYbrBlJtSTJrCsG7hoebnP5XJW
         oOUG0xEbXRXxeWQmaM5tzmK5hNHBmcLeogPgT2RsbKyU1paTQZMnIzmjmqhvevaRZ/RV
         JYLw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="ghLg+/aw";
       arc=fail (signature failed);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.16])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-61cfc9d9628si482471a12.5.2025.09.09.01.54.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 09 Sep 2025 01:54:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.16 as permitted sender) client-ip=198.175.65.16;
X-CSE-ConnectionGUID: pyFQ68Z9S4aQGNFa7QYpKQ==
X-CSE-MsgGUID: Bkoy8ZrITtqMs1ucRJXf4w==
X-IronPort-AV: E=McAfee;i="6800,10657,11547"; a="59830993"
X-IronPort-AV: E=Sophos;i="6.18,250,1751266800"; 
   d="scan'208";a="59830993"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa108.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Sep 2025 01:54:12 -0700
X-CSE-ConnectionGUID: xJqo95yjT+Cs6HxHQlcsnA==
X-CSE-MsgGUID: A3Hb8INSQUykvyoQMLvN1A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,250,1751266800"; 
   d="scan'208";a="173493999"
Received: from fmsmsx903.amr.corp.intel.com ([10.18.126.92])
  by fmviesa009.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Sep 2025 01:54:12 -0700
Received: from FMSMSX901.amr.corp.intel.com (10.18.126.90) by
 fmsmsx903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Tue, 9 Sep 2025 01:54:11 -0700
Received: from fmsedg903.ED.cps.intel.com (10.1.192.145) by
 FMSMSX901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Tue, 9 Sep 2025 01:54:11 -0700
Received: from NAM04-DM6-obe.outbound.protection.outlook.com (40.107.102.59)
 by edgegateway.intel.com (192.55.55.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Tue, 9 Sep 2025 01:54:11 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=xjlvYNBQy8h1imCkV0QVlhg+7gbKSKWp4QVmdPN8tJmJt2rD2UgGxbR+XmgYG1C9qm4/lN8qaq0FGG019U2VVeLj/PIUjGuRFcwwgIPNUR83iKQbB+TgSDwRSrYXY7W7kVB8UM93mPVf0nVRxGTXzHWHPtrmpazJqiDzuBuC9XOwFgA1N/XgYX+yt5RUbumld+fOxSJOisHzbE+DW1PjGSiI8Dmpuk5istGGZpmBceXPazquXQ0YvrxbP/7IUh2ebHBqwaE9hK2Kn+cCmEL7VSVhZrP2eRezjxTxMmDavSQOyVx4nDdmAHF0Sl7oO5gHsNkNMWbgYfnuAT6QYi2QDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aSQGm55NyRV3vwmZjBzOCDU/H5qZ8W8i1JEkgogs6bA=;
 b=yxFLP3nJDbMTwZkJPG2UWrVEfpiPE6VTdi9c2ZnLOQ/tYSTITjkxayTtxAjvPOWeL0VUB4FM06ZigoK/JBNfbt/vvx2fqb+fbsC7fEhTKAXA1yfZaIIxpaCaMBHXXWRbz2JAUNCN5MaE8i6838dQywAsDrYgQtUOw/Av3/+kN5pKfNZ+w8JV2a3jVWGH8o4pZDKPHFJgRYpXZ+Q5unDQNsi3i1MKpXOX92MyIOiCcWx7K0UqtIe/SDIQx5uFzIDbJCJjvFS3iSihpboNuRwHyadfHk5v+LHuilAj94V0Si5SwRu09B/0epQhK2fHjvGej560UWPyk+fqsi9HZgYbEw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by MN6PR11MB8104.namprd11.prod.outlook.com (2603:10b6:208:46c::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 9 Sep
 2025 08:54:08 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%3]) with mapi id 15.20.9094.021; Tue, 9 Sep 2025
 08:54:08 +0000
Date: Tue, 9 Sep 2025 10:53:51 +0200
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
Subject: Re: [PATCH v5 13/19] kasan: x86: Handle int3 for inline KASAN reports
Message-ID: <47ip2q7fc3q2igjjjg24bl3gwlpcr5y37pahkqb63ridzj262u@augjvsnpq4kz>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <36c0e5e9d875addc42a73168b8090144c327ec9f.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc=zu+pQSOdVw@mail.gmail.com>
 <couuy2aawztipvnlmaloadkbceewcekur5qbtzktr7ovneduvf@l47rxycy65aa>
 <hw7xa2ooqeyjo5ypc5jluuyjlgyzimxtylj5sh6igyffsxtyaf@qajqp37h6v2n>
 <epbqhjyfdt3daudp2wx54jsw6d7jf6ifbr3yknlfuqptz7b4uq@73n5k6b2jrrl>
 <CA+fCnZdJckDC4AKYxLS1MLBXir4wWqNddrD0o+mY4MXt0CYhcQ@mail.gmail.com>
 <ra5s3u5ha6mveijzwkoe2437ged5k5kacs5nqvkf4o7c2lcfzd@fishogqlatjb>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ra5s3u5ha6mveijzwkoe2437ged5k5kacs5nqvkf4o7c2lcfzd@fishogqlatjb>
X-ClientProxiedBy: DB7PR05CA0009.eurprd05.prod.outlook.com
 (2603:10a6:10:36::22) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|MN6PR11MB8104:EE_
X-MS-Office365-Filtering-Correlation-Id: a7acf006-d1f5-4f70-55d3-08ddef7e700d
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?RUFWS1lVYWJEdXJoaW1GUzFLZllZTWFFbGRrU2lFOUJMbGYyN0xUbFdVbEc4?=
 =?utf-8?B?WXJpRE9sWVFKZmc0MEpoOTE3ZmFqS3FQenMrUjNRZElreVYycWYwd3ZDWHg0?=
 =?utf-8?B?NTRrNjNOYWRTeWtKYVdiUC9VdWppY3laY1pLaWFML0g1WDNwakc0UDNiRFhy?=
 =?utf-8?B?QkJ5OXFvWFZXTHFHV3cyUWZvZ0NUa0RLdXVTZFBnQlNCTktwNUpxZVY1UWxP?=
 =?utf-8?B?Mi9XUnU1eUtiQW1yMzkzQThXb0FhajIySzdDc2tCSjFIdDB4aVRleUZlR3N5?=
 =?utf-8?B?RGtoRjFjOVFDbFlyY3c0MTBFY0lRQmlsNjl2em9xUFFCNXdiVWpueWZjeGZm?=
 =?utf-8?B?S2hKcmluYTE0MkNuUHBjQzF3cDJVejVIRGRpNEFPK0hvSzV2cjdGa05MbFFr?=
 =?utf-8?B?ZkJycHNYb1F3RkZrZy82L0xkSXhaSnRyWFRKMWUwME1GSUVSTVhKZ1hudCtB?=
 =?utf-8?B?MjNMT2twblFmZDRvKy80Q0tjQ3FucjNwTzVCQm4xSUxsNWFRQWo4bnNlaGlw?=
 =?utf-8?B?bjVsZjIyMnNMaFRIZW5rUFRuZE1XZzE2b1lrMGNxMm93dFVtbm1FM3BqeTRH?=
 =?utf-8?B?MmdnWnVrdEdBY05XRkNNOVl2Z3A0dmxQcS84M3cyN0o0ellJUVpPMUV0dkdG?=
 =?utf-8?B?VVpHYWVHdXVWUmcwRmFqdlVINnlVUE10Uy82K1pMV2NFRVhLOTZZNXNVMDJ2?=
 =?utf-8?B?MVdlcWwrckpNR05KdVREODdnQUxta29Ya2VabVV5R1M2RFcwWTB1SjFkUG1v?=
 =?utf-8?B?ZmFHeVpnc2haUEcxYlhvem5zZGhhYXJ6TjlpcU9vSkUvdmtJK2haYzBZL1BC?=
 =?utf-8?B?b0VlcHpOMXJuZ0FLZGNJL3d6MWV0dUlnUjlZaHlPY1NDZWczdmVCZmpUcGhD?=
 =?utf-8?B?WjZ5ZHAvbnpiUk5vd05aczJRMGMxQ0ZXL1NzZG1aRDl0VjZjcGlZNmJSMXdE?=
 =?utf-8?B?N25leENTdW9IMnNMTDdRQ0duVldXKzJ5cXU1aVNzbHlDamIxOGdjS05yTDZa?=
 =?utf-8?B?QUZzc0dZR3lRK3I2NjZwL3JJUktZQWJiaERiS2xPUSswVzd5SlNEQVpNQ0RX?=
 =?utf-8?B?OEZyZCtDOHl1cFIrRll1R2dZWEViTGx2YnZNeVRjU0k0a2Y4T1FqSVdUajFj?=
 =?utf-8?B?Mk5CLy9NVUJ0U2UvWDlRUzhhenFabEJXdlFBMXRuYWh5MHNVaWJjWnIrOWtR?=
 =?utf-8?B?SHc3YlBwU3VLOW1SVjEyblMvaDZsNEJTTThudUNIQ1BwaXdYZUcyMnF4SkVS?=
 =?utf-8?B?MzUwV21WVWg1YnlKVDg5NDN5ay95Q3BCbjNCMDU3U1RURlJKMEVXZ3JXSkV5?=
 =?utf-8?B?QkJiZURXSjRFcXRwNjBCTjZxa0JQenQ5NCt2MkRsMG4yRHdkTGhFR085V0lF?=
 =?utf-8?B?Vlc2aHIwak1aa0grSW9kOFhxTlBFK09UL1dWNUNjY3l6RGM1VWx6dlhidllm?=
 =?utf-8?B?cmZlbk1qVkRhd0MvbytSc1ZkdUFpWmVwOER5bGMrUFhuZ3pjOE1URkdqai9H?=
 =?utf-8?B?Vi9pNlZHREc4aUNFWlRUQ3NhTHNwNGwzano2K1Jlemdqamp4UzhvRTBCaFow?=
 =?utf-8?B?MCtpMWZkVE1BWVhBbmdycUF5cnREQklML3NCTWdRNHRZNkg1Z3E0R25iN1Rq?=
 =?utf-8?B?eW5VYWFqOFFRcmdUbkJENXZhZG5IL1NDSGl4ZU5LdW9MT1lEcTBwU1Zod0FS?=
 =?utf-8?B?NlAxU250Rkt0a0VwSFprdkU3Z3Z6V2s1aU00VHlkSjNwTGUrbW1YdGhGRnVX?=
 =?utf-8?B?OXY5ZXFLR3dLY2tnL1RreTUwSmxCcTF2SGVWOWp0MVBNRmpZSklEUmxqUmpX?=
 =?utf-8?B?LzQ3eGNGRXdyQlNGNXYwckJ6enpjMlJxQUwyU2RUOWF6UGNQQysrb1dsQ0sv?=
 =?utf-8?B?bjh3TUhIZkkyU05kcng0bGRGNnJTeWVRT1RuVTFKUmZhMTdueUVZNk95OUxZ?=
 =?utf-8?Q?xhPRHofcL7k=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?eGM1QVRTV0RPSWd5U2JZWkMzRVg4T1VPZllVdjhPN1NIdjNvT3pWa1BBODEr?=
 =?utf-8?B?Wm4vSUtBa0ZHMTJUd1YzRGd4QnVGSVFBb21yZG5icUtaek1VMFZNdzNHcEp2?=
 =?utf-8?B?MjFtTDdXSklOcmFzUWtvTlhVSU1PMnYwdnJCQ0VWVTFlUmluUWIvTFJhRnZi?=
 =?utf-8?B?TXZxeWRVSmZHSmVyZW1pemhRZWcxaktIVjM4cWR6Rk9YeitwOFIvWGJWQ1NM?=
 =?utf-8?B?ZEROK1lhZjF1M1ZZWVh1NzVtRXI3S1FFcXpDTC9MK1VQSytuaDZwVFY5NlRj?=
 =?utf-8?B?ZlZzdnFWbndPVnVTUHNOUlQzRlBzL1VlY3N1V2xXSmJFR294M1h1SXFWZmlz?=
 =?utf-8?B?b2xqczR6cWE4cC96Y2l4bGxwS2FBVW5tR1VldjJGeFhldktrMUV6ME41Ri9q?=
 =?utf-8?B?b09XKzc2ZkFCZ1hLazB1U1F3SHBGeXp5Z2p5QmhlQ2EyT2twTmpSU21odHln?=
 =?utf-8?B?TUtWYWRIc3BsR3gyb01LemJTUzhaZUE3WjZ2cjF2UzVqODRBcDB0MWcyRGNN?=
 =?utf-8?B?bVpDTjc2dHpqcGRSNzFyOWZxaml5RFlXTUV0eGNBckE3cW9TWlg3NnlSZTZx?=
 =?utf-8?B?bmh5eWcxRUszVnBjbWZXbERqZUl6Qk1pWGtzVFQ5aFhIR3ZtZlQ1T3Q1dHRE?=
 =?utf-8?B?Rm8yWkNDY2ZmWjNlNnBwQ2ZrcnQ1d3FhVlNhQ2RLU0FtYzRXaE4zUzRBL3B2?=
 =?utf-8?B?OG5namRpN09LTVRwMTY2YURCaXZXTUhtcldsM1BrMzhhNUhJeUhPOXFObU14?=
 =?utf-8?B?VWp3TGhySVJJcitlN1lmYzNIeFNhZWcwdkNnVFVPVE1TUjJIR1phZ3MyWG9a?=
 =?utf-8?B?cmE3cG1jTlpRUWJ3cmNEVXhJNmQvVkUxM21aTEl6aktNU3l0M2Y5c3VnMmE2?=
 =?utf-8?B?dGc3ejJ6TXByeU9aK0tMaGRyWkhnNnhJMGc1U2RXajI0Z1Zqc0UzcExCY0pE?=
 =?utf-8?B?cmdaTDdiRzJUZE5RNFVNWW9DYTEzd2x1RFhGSzNmNkdldEVxd0ZvVWRNS0Ny?=
 =?utf-8?B?YklPOTNzdU9kenZjbTVxOEloeHZiRWhKTWdaMUhCdlYraUIzZWsxRjJtY3VY?=
 =?utf-8?B?UzVCSFNiaWlWMU55dFRiWmpScVMrdkhqTk9NcUJ0anBmTzYzSjZwUzlVc21y?=
 =?utf-8?B?L1h0d1FITzBRWlBrWGVQTEx5a013NDMwWlBFeGovWkh4U0xaZWh5QVV3dHYy?=
 =?utf-8?B?ZnFnQ2xIdWFJVzZTZVZJU3gySzNUTkZVZWhBV3VvM25mU0IvdU5aWmF5ZEJL?=
 =?utf-8?B?YkZJZTQwYmN0cWpMZTBZV1pUNUFzNnU1L3F1N0M2djJwRU9Kd3RYSDRLOWdt?=
 =?utf-8?B?dTlVNXR0aU82dXVUc01KaUFMcVZXUzNjRHlhNXdXVjczTktscG1rcWtsTHlz?=
 =?utf-8?B?a1V3ekdFRS9UelM5azNmeFB4R3FwRFlGSmlzbjNEM1ViOHJyemFhY1lCNFVV?=
 =?utf-8?B?OTM0L3lFWkdtbjB0TDdzNXF6Z1dWVGEvQlRZWWtjVUhwTUg3S1JHWVRpUEZD?=
 =?utf-8?B?TDhsSEdoRk1tUEsvNnJmT2hBN1BNaGgvMmtMNWs4czNLUnkzNVpDbkxUZ2V5?=
 =?utf-8?B?dGdzZ3JqZ1lVRUhuc1Z4bE1VSzJFKzF3bHpsWHF0cW5zUlRwL2RvcFVxckxx?=
 =?utf-8?B?SGhJenVxdDZKOXpHaWY5dXlDM2FYalhIb1VCMEk2d1ZYNUFXbFFtWTcvTUF4?=
 =?utf-8?B?UVdsb21sNFNpczJxcTlMUjdIL3gvRUZTSjRsOHJUV05KTXdvaGFVWTQ2SEFW?=
 =?utf-8?B?NjlFallzUU5zbTZtTlpxMHJSK015d2E3bTB3bWhHT3A0SkhJWjB6MnUxMlQv?=
 =?utf-8?B?UHpFV3ZrQTh4Z2hKcWNjaER5S0NaeHI3TUlvK1oyako2RDVieHNjZTJTeW5C?=
 =?utf-8?B?NkpFakZKL2tlMk5jc1VQbEJ1VlUya0RLYm5DMlZpYTFseGMzMWZoa1N4cDNv?=
 =?utf-8?B?MHZQVFltcUlTVlRuQmREdTduMkJhZSs5YldQQnR4UGl5UmQxdlNHcWJ4Yk5W?=
 =?utf-8?B?REQyU3l6M2JQZHcyeFdJWFdDeHhDeVNKM2p4cGt0dkc0SnUrSHF3QU8vdE9U?=
 =?utf-8?B?R01rSmVWWkd2U2pVb0lqUVRKeFJobFFYMVhlaDlISC96NDAxdWdZT2dSeTlp?=
 =?utf-8?B?Y0ZVSjdISXBkeXpUakRkbkY4YnhLZ3pxRWcwaHR0aUdaT0o2OFRlbE9EbFRJ?=
 =?utf-8?Q?RUseUmse+Key+zigZYduZM0=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: a7acf006-d1f5-4f70-55d3-08ddef7e700d
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Sep 2025 08:54:08.3164
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /XlI/GDwuZ8iSUXnHzCiKbvijQAY10UGvFRj+fLo8RLpG9RBweQDFLs6CrjeDCBWyzP3UdbOibv3yWblUj/LkwuPPLe0WLbx5SBjRVa4mLY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN6PR11MB8104
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="ghLg+/aw";       arc=fail
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

On 2025-09-09 at 10:24:22 +0200, Maciej Wieczor-Retman wrote:
>On 2025-09-08 at 22:19:05 +0200, Andrey Konovalov wrote:
>>On Mon, Sep 8, 2025 at 3:09=E2=80=AFPM Maciej Wieczor-Retman
>><maciej.wieczor-retman@intel.com> wrote:
>>>
>>> >>I recall there were some corner cases where this code path got called=
 in outline
>>> >>mode, didn't have a mismatch but still died due to the die() below. B=
ut I'll
>>> >>recheck and either apply what you wrote above or get add a better exp=
lanation
>>> >>to the patch message.
>>> >
>>> >Okay, so the int3_selftest_ip() is causing a problem in outline mode.
>>> >
>>> >I tried disabling kasan with kasan_disable_current() but thinking of i=
t now it
>>> >won't work because int3 handler will still be called and die() will ha=
ppen.
>>>
>>> Sorry, I meant to write that kasan_disable_current() works together wit=
h
>>> if(!kasan_report()). Because without checking kasan_report()' return
>>> value, if kasan is disabled through kasan_disable_current() it will hav=
e no
>>> effect in both inline mode, and if int3 is called in outline mode - the
>>> kasan_inline_handler will lead to die().
>>
>>So do I understand correctly, that we have no way to distinguish
>>whether the int3 was inserted by the KASAN instrumentation or natively
>>called (like in int3_selftest_ip())?
>>
>>If so, I think that we need to fix/change the compiler first so that
>>we can distinguish these cases. And only then introduce
>>kasan_inline_handler(). (Without kasan_inline_handler(), the outline
>>instrumentation would then just work, right?)
>>
>>If we can distinguish them, then we should only call
>>kasan_inline_handler() for the KASAN-inserted int3's. This is what we
>>do on arm64 (via brk and KASAN_BRK_IMM). And then int3_selftest_ip()
>>should not be affected.
>
>Looking at it again I suppose LLVM does pass a number along metadata to th=
e
>int3. I didn't notice because no other function checks anything in the x86=
 int3
>handler, compared to how it's done on arm64 with brk.
>
>So right, thanks, after fixing it up it shouldn't affect the int3_selftest=
_ip().

But as Peter Zijlstra noticed, x86 already uses the #UD instruction similar=
ly to
BRK on arm64. So I think I'll use this one here, and then change INT3 to UD=
 in
the LLVM patch.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
7ip2q7fc3q2igjjjg24bl3gwlpcr5y37pahkqb63ridzj262u%40augjvsnpq4kz.
