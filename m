Return-Path: <kasan-dev+bncBCMMDDFSWYCBBS75RLCQMGQEQWSGKTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id ECA13B2990F
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 07:49:01 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-24458345f5dsf38511665ad.3
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Aug 2025 22:49:01 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755496140; x=1756100940; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pCXg9zIIVdD38vgiWUlDYynioAFD3HlOSamhEWYAb8g=;
        b=BLlLUl40qJxtlaWx0j8AjsAzxG72tnuWBP5f5brE5cjeRXFDDMxD4v9/ewFDX/Mv64
         fUlKG98W7lwVQMeTsB46SJ1VK5HUzRUaT1WXLDCQ7Kefg3tme4Xee74hML57FWTjrHaI
         1e0AbQMaeXV3rWIyJsPI5BK8CJM3J6XP3LagpidElLRC04tMBDw26u9MBj/QmWzATkwg
         RmkRf/q0ojHvfLBDsYXmRrke5J2/YdKQZ6NTAIY7QYE3kvpWqMMZNvpOV45MxIaaS0L8
         G+5ZN1vxzEBKfbnYDnSyQd+SyHZVo6KIq0q+fW4IY9vSWwQecu073L36muT/zx0rEqCr
         nfvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755496140; x=1756100940;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pCXg9zIIVdD38vgiWUlDYynioAFD3HlOSamhEWYAb8g=;
        b=qspBgoIeemgtOyRKrw1OyO2PT4UZHGyQNVrdCTEXgYNJQ17O+vGCXj67+5zvBlGkos
         XXzZSHk1Igag8CwsrSx2ZRFqDs+ZbKir6twDHv33Q9PBNPsY5V5o+PiP1MPczLrpPw6j
         HEq16n9ICjBA9Mn1KbVKC3XWRe4LlFsxhzOCd8vcL+IWYvwsI7ieI7Z5CcYYuKAvrTBb
         H0qDeL9bGlMLhoT0Ji1VhJELZk5M3lUqC/7xBCcjG8eGKnf63RMx0GXZYtgVoYzPh22/
         Gk+wpe0w3/ENFTrWhPA4J/L/PCWIn10DSWDi0oZzTQfWhuKuSPjPC83WLGrJa7K98Lcw
         8wkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXrg9LD+p5Bxsa9oeVKLBm8Bq/7Et1Ivan8XosNGUSDBIiSeGK4wxZWOQzczTzwOusHsOX4dA==@lfdr.de
X-Gm-Message-State: AOJu0YxGfkKOvECJ4rT/B689zeIglCC8iFnRh4rGn0skHYE6mbxFNgLg
	bGStb5Yv92jW4ZM5KCHoyzofnYiEU95R6/gs712xmXwEKB8oYx61wO5P
X-Google-Smtp-Source: AGHT+IFrNSiOAUBuCeaiQWkqsX4x7PwSGQoyNh+LcXmgXUPXCBS9kB9I91H3gcXcslJyfXuL4cwsww==
X-Received: by 2002:a17:903:1a08:b0:242:9bc5:319f with SMTP id d9443c01a7336-24478ff0354mr95568295ad.55.1755496140245;
        Sun, 17 Aug 2025 22:49:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZepva65/2zv7SnvzSOK6ggPTbjvc09E4/R8RD6MZ/d9UA==
Received: by 2002:a17:903:144e:b0:234:cc1a:5845 with SMTP id
 d9443c01a7336-24457414eb5ls33704975ad.0.-pod-prod-04-us; Sun, 17 Aug 2025
 22:48:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU4mDuI/ULk+9B+CrUeJGp06GKXjEN1t2bQK5vmdudzn4YxE4nLtTrkhXOj4VB7pt2QbOYLeyT38wM=@googlegroups.com
X-Received: by 2002:a17:903:1a08:b0:242:9bc5:319f with SMTP id d9443c01a7336-24478ff0354mr95567455ad.55.1755496138897;
        Sun, 17 Aug 2025 22:48:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755496138; cv=fail;
        d=google.com; s=arc-20240605;
        b=ix7Pzgqc5ktKwo8VmMZYmhdB7UUu2/Lyk0/18+8rXiA3Rbxpsu3LfiSDDEY8aRaqs5
         nAoLgSTItFbcMi1YTVpVPXm3jUUY2GBGUxVpJjEWB7BUiWpADuc6/MWKXaRlVN8m8AsF
         Uxz0wb7J6x3TYkaAZ7tLH9R6i5V5LRHvA78wxtYOXK6wbmFBwBxsWuu5ymoVd4powWam
         YPHfVzESRr4rmz+6sg3jCqE77YRTowH4+JdLczeptVG5BgoKXPDxezgAhGucvWyLd0Sj
         Ps6eMsejeTg496XhpAU6cOURXYTCxRZvuLFRBhe6bLNHJafDEbqc6K+Ss+kRsvQsH9+W
         hDyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=YdUmjFmdtMqR+CA7VMMWRCXE8ju5dYfC+FsDVb69klE=;
        fh=UjRGHZyPN0IwEmgzTUA/tyjEykOVjpR2aaeneP4NcAc=;
        b=BvJFOzNBCMDsexiwnkNXRyh/oE9RU0aGz4ABGtHq8NF/kdIatl5/IiURcgq8rrvElI
         0Jlne/KGfnrMWXV9ScYUEoCoDvp+tagb4zIaGd4XsHPyLnHv+VJHtqKuvWmSQusaibgG
         N5K44k8cJIV+jtqq6YwuHbInwFiz2/E0sKJw6cvZ2CTe4OULTMgbiZpRmmsgD2wpyaf3
         gadieqb/oyQ7esQ6aBxy0n6Pn1w+dCPHmM1Y0QqE9IDA5DbniXlFVZ/YZQFc6rOa+yt1
         I1r8cdPrradYSY2T6hJ9on8iM3fvvIUOJOme0JbWyPzwX43bbFilzH8Ln/4M0e36yVDx
         W2Pg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=h84m0fh9;
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2446d52471asi2789285ad.5.2025.08.17.22.48.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 17 Aug 2025 22:48:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: /MxBv9GiT6C4qyTaUKJ+4Q==
X-CSE-MsgGUID: pZHfI0mzTtKPYO18AEaIMA==
X-IronPort-AV: E=McAfee;i="6800,10657,11524"; a="56740615"
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="56740615"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 22:48:56 -0700
X-CSE-ConnectionGUID: 7F1Aqh9URgKZ57e6ZER3EA==
X-CSE-MsgGUID: Lo8bMffcSk+JaDOAKQTJSg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="166718654"
Received: from fmsmsx903.amr.corp.intel.com ([10.18.126.92])
  by orviesa010.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 22:48:55 -0700
Received: from FMSMSX901.amr.corp.intel.com (10.18.126.90) by
 fmsmsx903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Sun, 17 Aug 2025 22:48:54 -0700
Received: from fmsedg902.ED.cps.intel.com (10.1.192.144) by
 FMSMSX901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Sun, 17 Aug 2025 22:48:54 -0700
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (40.107.237.58)
 by edgegateway.intel.com (192.55.55.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Sun, 17 Aug 2025 22:48:54 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MuIFG9EmIFday4lcIL0eGsi+CHfpQEZfUYc+Cor6rhEega/EWrEzN8kzzFcLX8+pKPI2Cnzj2S72p6Bo8pwhQSZgbk225MLYiMmrn62QvAFrsAP8zZM007IkBfIspb/VN+sS1RB6wZ2Vgx0oH0xLr58+Mm7X7nZSmQco8RWLZs8+9GVyU6WMV/8UQzDpKwmh14mt5FeKeq0KVYCNIuufrZt6tlCQS8PWQQy8swliOFmcCa5SjAALrt3ke1t8ll0TcskRNORPYsMlBpWzH0jz5kjKeI/RSCPJThsrbnSWNCnR5EpJEW9priBtuKKGL0VAc879FF6rNFeXdVu/VrsaWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=496JEvK9IiuMJA+AnA57foYZDwfNly1U/h8UhaR1Ox0=;
 b=is/WycuBpkUByW0QOxkqt9rFFsjib7iKHwYtU6smB/Wskb4RoqhNR5jhNoYgNqNKlCesK2k/Crtffkk3xYqNa8w95nPNfIUVg/3n5rPoW+Un3g8SlP0XeIV4vZFhx7GMzCyPshWetqU91sD1fgl9HcImg3tD3uJbFqiGf5DlokX3Tq/WSTojsTOMn5eDZJcYmek0yy7nMtQBnLYjWSAawk9f2xmZcrtrV3XDumhYrpXsDKc8GSOfJ/ugxB3e6rVfMpVjAzV87Rk7d40L1l0s0yhgQNF5KDZ4pW6Zp0uZF/8owKpWWPI/qeADRCNcHUl48bC3Cewn7XYjvkuYnu1adg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by CH0PR11MB8087.namprd11.prod.outlook.com (2603:10b6:610:187::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.24; Mon, 18 Aug
 2025 05:48:51 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%6]) with mapi id 15.20.9031.023; Mon, 18 Aug 2025
 05:48:50 +0000
Date: Mon, 18 Aug 2025 07:47:09 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Mike Rapoport <rppt@kernel.org>
CC: <nathan@kernel.org>, <arnd@arndb.de>, <broonie@kernel.org>,
	<Liam.Howlett@oracle.com>, <urezki@gmail.com>, <will@kernel.org>,
	<kaleshsingh@google.com>, <leitao@debian.org>, <coxu@redhat.com>,
	<surenb@google.com>, <akpm@linux-foundation.org>, <luto@kernel.org>,
	<jpoimboe@kernel.org>, <changyuanl@google.com>, <hpa@zytor.com>,
	<dvyukov@google.com>, <kas@kernel.org>, <corbet@lwn.net>,
	<vincenzo.frascino@arm.com>, <smostafa@google.com>,
	<nick.desaulniers+lkml@gmail.com>, <morbo@google.com>,
	<andreyknvl@gmail.com>, <alexander.shishkin@linux.intel.com>,
	<thiago.bauermann@linaro.org>, <catalin.marinas@arm.com>,
	<ryabinin.a.a@gmail.com>, <jan.kiszka@siemens.com>, <jbohac@suse.cz>,
	<dan.j.williams@intel.com>, <joel.granados@kernel.org>, <baohua@kernel.org>,
	<kevin.brodsky@arm.com>, <nicolas.schier@linux.dev>, <pcc@google.com>,
	<andriy.shevchenko@linux.intel.com>, <wei.liu@kernel.org>, <bp@alien8.de>,
	<ada.coupriediaz@arm.com>, <xin@zytor.com>, <pankaj.gupta@amd.com>,
	<vbabka@suse.cz>, <glider@google.com>, <jgross@suse.com>, <kees@kernel.org>,
	<jhubbard@nvidia.com>, <joey.gouly@arm.com>, <ardb@kernel.org>,
	<thuth@redhat.com>, <pasha.tatashin@soleen.com>,
	<kristina.martsenko@arm.com>, <bigeasy@linutronix.de>,
	<lorenzo.stoakes@oracle.com>, <jason.andryuk@amd.com>, <david@redhat.com>,
	<graf@amazon.com>, <wangkefeng.wang@huawei.com>, <ziy@nvidia.com>,
	<mark.rutland@arm.com>, <dave.hansen@linux.intel.com>,
	<samuel.holland@sifive.com>, <kbingham@kernel.org>,
	<trintaeoitogc@gmail.com>, <scott@os.amperecomputing.com>,
	<justinstitt@google.com>, <kuan-ying.lee@canonical.com>, <maz@kernel.org>,
	<tglx@linutronix.de>, <samitolvanen@google.com>, <mhocko@suse.com>,
	<nunodasneves@linux.microsoft.com>, <brgerst@gmail.com>,
	<willy@infradead.org>, <ubizjak@gmail.com>, <peterz@infradead.org>,
	<mingo@redhat.com>, <sohil.mehta@intel.com>, <linux-mm@kvack.org>,
	<linux-kbuild@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<x86@kernel.org>, <llvm@lists.linux.dev>, <kasan-dev@googlegroups.com>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 07/18] mm: x86: Untag addresses in EXECMEM_ROX related
 pointer arithmetic
Message-ID: <5i5x54pntwjhpmalenhemyra5ybnqrransk5leukpmj3o53e6l@jgjiy4ycduhz>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <aa501a8133ee0f336dc9f905fdc3453d964109ed.1755004923.git.maciej.wieczor-retman@intel.com>
 <aJ2Pm2XzcM3H4aTN@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aJ2Pm2XzcM3H4aTN@kernel.org>
X-ClientProxiedBy: DU7PR01CA0026.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:50e::22) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|CH0PR11MB8087:EE_
X-MS-Office365-Filtering-Correlation-Id: 6eebce60-6654-4aa8-7912-08ddde1ae862
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?0Qc2OeMSq3U1zgCYrlCVtdEhwt9fi7xfR8+JhlvYCbVqDK2xYUmJOknn80?=
 =?iso-8859-1?Q?8hU8vbLLOfsN2gAjwOEBPY06/AlAfeKMsTyaE7/+zrwu7G2Sdp/IQYSyiD?=
 =?iso-8859-1?Q?oD+qH/WgXFZF65qrLquSLnJUEjXHQ08a9jxPbkbTY80aujKVevm5XAJQb4?=
 =?iso-8859-1?Q?dLkzBfWr812yj62c7iR9fNeE/95Ds26WCyFYLmtzUfgSXpHRo9sQQte43s?=
 =?iso-8859-1?Q?A0WLjWtOkFUsCIaiQi33peazR7yj8oX9oS4ufmV3ysyIN8xa6BOdz2Rj8X?=
 =?iso-8859-1?Q?NGYoM+mIwUV7qs51WHbRi1bIS6J3Vo53+UKX/jxWiknbwwrmhGPsUlfKD3?=
 =?iso-8859-1?Q?6M0gEQPEpVYt77wQ7ZawuUFgKz6I4c9ZgdcvA6cWDkVoETEoqdymIK5VRF?=
 =?iso-8859-1?Q?7Fl5B+4TkkdjSjIlg0SND7/Oqa/K3CNzdFUsZhjhuKIwP5dNE7LVy5243f?=
 =?iso-8859-1?Q?qlGTLIG1CAYPKLyCUDuR7E/ptjpV857uttdvCh6kFaKh5oP58XA/aWgxun?=
 =?iso-8859-1?Q?2Zm5EXFeicWTHnQrpSBO8nFnt6sDjrt4qPvYQkxVpq1Qn+mfW2Ic/nlCXJ?=
 =?iso-8859-1?Q?YLETH1sFxPpzSJwdC5BNDti0456dngmZwxZakeH3jpcs4TTIqP9ohdeMwA?=
 =?iso-8859-1?Q?U64WrwbSlFamCst9zPVcy+yvTkM7Ub5qgdGtWDDvlAyiVaOmhOMjN9bECP?=
 =?iso-8859-1?Q?kSmHcJjNl8Y1R6mhGCjGJ7OqiGrmNJhlMFElpAacUNSIdvB7V4U4j1zKFv?=
 =?iso-8859-1?Q?4wPReegCbh6pTYybEiXBGTXYZ+UFxhQ8yUycnywWQSDYnbs33GonPbl9uB?=
 =?iso-8859-1?Q?nr0Qd/p1zJOzPQNoYpmTGvlgqhcvhHbh+4+AWcE9nLgW24eCH4KBSimb0K?=
 =?iso-8859-1?Q?aMaGOGSr+LjL5ybd8/io2geIIi7ZeVIOUpuCb+TAEJopgNPKy6tVqaJ1MM?=
 =?iso-8859-1?Q?Niio/tHwYaeJFHBupaycdDVQvONFyTlUO1Vw3IX43XuQMnHTnPAMiH5Z8j?=
 =?iso-8859-1?Q?OMEeC31W01laDJ3JDWwZ98QvUOWVZLefJTCat0CbtJivxF1LH8jyBmmL3O?=
 =?iso-8859-1?Q?VYnrpghZ9Sxo2/xPwJK9EGsQzX/koMlUMDXkH0ln3+W51Jbbe+z+2zEHvK?=
 =?iso-8859-1?Q?YVApb4ONUadbrXEhTZ1h/qdTk20t57HkBmPncPII1THC4rb6lPdAc3vpYr?=
 =?iso-8859-1?Q?F9/ObjaHnYzyQt34Ks9o8duvKEJeVoPHABvWTRcO3R75VLy4ZhviW/NRLp?=
 =?iso-8859-1?Q?PaebT87S0SAafA8W0sAQ6S4ZLm/OrutJ/zlGWq4S1H1qjsYTkDveP3P3O1?=
 =?iso-8859-1?Q?uk8WcDA9eYlySaPNPkPlSqIkVz/MPGaCLGsY0o1+QYBoeqfW2q4Y3kS3wJ?=
 =?iso-8859-1?Q?AJFJkvADFyWtbfmYfqA5VJac3zkPlcCV9Z/io8oo3AegxbBHNJl9kjD3sX?=
 =?iso-8859-1?Q?INFIdY0FNwuKW7w6lh4Dg1BLeBnyuboXKbFwsct1RJ4fKAkDix1m5HG7xn?=
 =?iso-8859-1?Q?8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?dUPl7vQwKSlHCp4mrNBmviNz3mnEEKXEE4A9VoqcxNj3mytmceznX1G8Kr?=
 =?iso-8859-1?Q?gs1L0lCtO75XLPhE6ubmw09peUaKdqlWKsntLWSZCaerxfvasE94H8+X/v?=
 =?iso-8859-1?Q?2DXBJ24b5k7DDDIihdVrujFW1jSrlJMb0q/bINr4YIca1wQpFlvqdAJZdT?=
 =?iso-8859-1?Q?SryzS9pSAwbZ9IJqFFMJ6S2+thftGGjwJpENnwi6I5NrPPUEpsLHqUc4CV?=
 =?iso-8859-1?Q?WScMG/tC5WZ+5mhqH6oJyQIMQy7h6TZNmFxvPa8H89IXk3nl74SD96mkWX?=
 =?iso-8859-1?Q?X7DDmLv04MtXVPJILDv2noQ1w0edZPr4FDS9LnbLDr6H9W1uZHVyRqFApk?=
 =?iso-8859-1?Q?hy/wrz9yqj4bO9NeeP79PvR79OY6rAyDteXkvgLHpOKGeewDayb1WfrSNg?=
 =?iso-8859-1?Q?Dn1rHjClM5eOICrEq+q9Fp3Xx0lihpdD4xz+Fch9zg2jwG/C3iB6F2gSh4?=
 =?iso-8859-1?Q?IG8BZP+XsxSOVNhahwGaA+bwLL34FInxmqcLCsrRwvk/WmiKuRctGhb1z9?=
 =?iso-8859-1?Q?1btPLY9NvUT52p4wMRhg+MjqSFC1Ag+TtmpIzftslO6liAHQxuyl5XJEyg?=
 =?iso-8859-1?Q?+NXFDHx6OGIww7Pg7PQ6Xbss7zs3BmisVPRj3RGEdTCmxdlojuVP8SYro0?=
 =?iso-8859-1?Q?Vq5l2+Yc5Nj4CfBE8NDrkRvxl4lenZULWGConmiSMsXwQg7NVqEjEBh9qE?=
 =?iso-8859-1?Q?SvgrmQjh7zTed966A6YLVqKwAIoRjmBSWKw+uwAo+wwHOjrb2BXkLsZFLi?=
 =?iso-8859-1?Q?KRuWm/KgNZB/CcKjPLjI6eWN6TzZ8YShVLUA81LeQPovreIVccf4qemJDs?=
 =?iso-8859-1?Q?xWh9QnWerDMMQtDPhkoVb8gLFdbNfQ994Bj1qOfhP56MCZRWS5j+quhm2p?=
 =?iso-8859-1?Q?m4xuZQJN9RQ/gJMxiy3S3K9JZCiK20op61sbtgZlRAWzKdl4cmQWeVqi6k?=
 =?iso-8859-1?Q?jjZiLPiwpiIDd+BzDKnyk2pesE+/c7C9mqq4+n9PFJZWEGuKz8k/XRoavp?=
 =?iso-8859-1?Q?RkodIWdoGcbz+8QtTOMMNlb4kZkoVl6yLGlj/ALfJX/7xL+9l6QLcBuVzR?=
 =?iso-8859-1?Q?rAANRx3pKAOyU/U4m75FfGb3vRii1enDajvvVdtY/aWWZOQNp/mNBlfXdP?=
 =?iso-8859-1?Q?nWf9IhbQ1dPshpga+PGlyuGocCpKvkz8pdVFbYqf7hYiTKTfzWkXEgwv6j?=
 =?iso-8859-1?Q?Kv0MhN+Vyq1wwTS0NxpQPK0GBF9tKHUhUPjz4QyTdjxFRO5U5PZQJrYfnN?=
 =?iso-8859-1?Q?9bBQarPGj0MUkpqseFY7Mzwql4KWZUxthn4ZOsJkh/IwILF0f/fon/0MLa?=
 =?iso-8859-1?Q?y1wr5EA2KeYfClvU4vZcEkN6fjdSwbG+A8gD/8qicl+oyEzaclOj3+j4vB?=
 =?iso-8859-1?Q?H1otSNdbyqmSz6sniFJp9/lfQql4XOR5o+Mp8dWMFDrWtGSjhm7rEQ0zC2?=
 =?iso-8859-1?Q?O3W2EVOrBADgr3ld0eDZG7cjx9U4OGgQRAhO/B/WrFvQmf8gy4tj7sDd7V?=
 =?iso-8859-1?Q?C13smeX2K6zGkc0p1iVmHGbIgDuINv8ze37W0rhK2bVTwQIk6gNu8c9TiZ?=
 =?iso-8859-1?Q?WC3Zc6RarTb4FqFqCBDxOhQRdEcGl9RpCSGIaXbcj8BBpAM1DU0spN4mEr?=
 =?iso-8859-1?Q?bC62QcklCkiF18h+LxnRhx4JSLlmpF925u1tQ28rkKBaWt55MzDNuh76sz?=
 =?iso-8859-1?Q?Ur/8ze8IyZ+t7RhXGCo=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 6eebce60-6654-4aa8-7912-08ddde1ae862
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Aug 2025 05:48:50.7832
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: cJ0LR1H7cizuKmGManYTD4AC8VXFJuPlhALO0+ogJ1gLcE8FQdPjD5DRliyav1B0BZrzBaS1mmFRpkX1NAPfHcIhmhZ5sNVuxMwC8saeU1Y=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR11MB8087
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=h84m0fh9;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.19 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-08-14 at 10:26:19 +0300, Mike Rapoport wrote:
>On Tue, Aug 12, 2025 at 03:23:43PM +0200, Maciej Wieczor-Retman wrote:
>> ARCH_HAS_EXECMEM_ROX was re-enabled in x86 at Linux 6.14 release.
>> Related code has multiple spots where page virtual addresses end up used
>> as arguments in arithmetic operations. Combined with enabled tag-based
>> KASAN it can result in pointers that don't point where they should or
>> logical operations not giving expected results.
>>=20
>> vm_reset_perms() calculates range's start and end addresses using min()
>> and max() functions. To do that it compares pointers but some are not
>> tagged - addr variable is, start and end variables aren't.
>>=20
>> within() and within_range() can receive tagged addresses which get
>> compared to untagged start and end variables.
>>=20
>> Reset tags in addresses used as function arguments in min(), max(),
>> within() and within_range().
>>=20
>> execmem_cache_add() adds tagged pointers to a maple tree structure,
>> which then are incorrectly compared when walking the tree. That results
>> in different pointers being returned later and page permission violation
>> errors panicking the kernel.
>>=20
>> Reset tag of the address range inserted into the maple tree inside
>> execmem_cache_add().
>>=20
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> Changelog v4:
>> - Add patch to the series.
>>=20
>>  arch/x86/mm/pat/set_memory.c | 1 +
>>  mm/execmem.c                 | 4 +++-
>>  mm/vmalloc.c                 | 4 ++--
>>  3 files changed, 6 insertions(+), 3 deletions(-)
>>=20
>> diff --git a/arch/x86/mm/pat/set_memory.c b/arch/x86/mm/pat/set_memory.c
>> index 8834c76f91c9..1f14a1297db0 100644
>> --- a/arch/x86/mm/pat/set_memory.c
>> +++ b/arch/x86/mm/pat/set_memory.c
>> @@ -222,6 +222,7 @@ static inline void cpa_inc_lp_preserved(int level) {=
 }
>>  static inline int
>>  within(unsigned long addr, unsigned long start, unsigned long end)
>>  {
>> +	addr =3D (unsigned long)kasan_reset_tag((void *)addr);
>>  	return addr >=3D start && addr < end;
>>  }
>> =20
>> diff --git a/mm/execmem.c b/mm/execmem.c
>> index 0822305413ec..743fa4a8c069 100644
>> --- a/mm/execmem.c
>> +++ b/mm/execmem.c
>> @@ -191,6 +191,8 @@ static int execmem_cache_add_locked(void *ptr, size_=
t size, gfp_t gfp_mask)
>>  	unsigned long lower, upper;
>>  	void *area =3D NULL;
>> =20
>> +	addr =3D arch_kasan_reset_tag(addr);
>
>Shouldn't this use kasan_reset_tag()?
>And the calls below as well?

Yes, my mistake, the kernel bot pointed that out for me too :b.

>
>Also this can be done when addr is initialized=20

Sure, I'll do that there.

>
>> +
>>  	lower =3D addr;
>>  	upper =3D addr + size - 1;
>> =20
>> @@ -216,7 +218,7 @@ static int execmem_cache_add(void *ptr, size_t size,=
 gfp_t gfp_mask)
>>  static bool within_range(struct execmem_range *range, struct ma_state *=
mas,
>>  			 size_t size)
>>  {
>> -	unsigned long addr =3D mas->index;
>> +	unsigned long addr =3D arch_kasan_reset_tag(mas->index);
>
>AFAIU, we use plain address without the tag as an index in
>execmem_cache_add(), so here mas->index will be a plain address as well

I'll recheck to make sure but I had some unspecific errors such as "page
permission violation". So I thought a page address must be picked incorrect=
ly
somewhere due to tagging. After revising most places where there is pointer
arithmetic / comparisons and printing these addresses I found some were tag=
ged
in within_range().

But I'll recheck if my other changes didn't make this line redundant. I add=
ed
this first which fixed some issues but then I found more which were fixed b=
y
resetting addr in execmem_cache_add_locked().

> =20
>>  	if (addr >=3D range->start && addr + size < range->end)
>>  		return true;
>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>> index 6dbcdceecae1..83d666e4837a 100644
>> --- a/mm/vmalloc.c
>> +++ b/mm/vmalloc.c
>> @@ -3328,8 +3328,8 @@ static void vm_reset_perms(struct vm_struct *area)
>>  			unsigned long page_size;
>> =20
>>  			page_size =3D PAGE_SIZE << page_order;
>> -			start =3D min(addr, start);
>> -			end =3D max(addr + page_size, end);
>> +			start =3D min((unsigned long)arch_kasan_reset_tag(addr), start);
>> +			end =3D max((unsigned long)arch_kasan_reset_tag(addr) + page_size, e=
nd);
>>  			flush_dmap =3D 1;
>>  		}
>>  	}
>> --=20
>> 2.50.1
>>=20
>
>--=20
>Sincerely yours,
>Mike.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
i5x54pntwjhpmalenhemyra5ybnqrransk5leukpmj3o53e6l%40jgjiy4ycduhz.
