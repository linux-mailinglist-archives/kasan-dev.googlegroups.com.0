Return-Path: <kasan-dev+bncBCMMDDFSWYCBBBOCXLCQMGQEU4HI3FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 15E3BB37A28
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 08:09:11 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-886e17c1bb2sf283411239f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 23:09:11 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756274949; x=1756879749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZOZHX282Y/NLPHgrnjlakHtxfKjrTBR3B3VWPOaVdCU=;
        b=QvSr6w4v/for1YgmAkjjUPezZL21seafzKryC90Sdr5pLDGWCiy1jR+aG7hDOxGIc2
         Qk2smemds7/XbXkHZCFYtaqZrqDZUcXzArDmHVBgn7SDyQPgpgo0UhHXwAiAS3TaaofE
         xU9Y2oTJnDXDwPu1vkTq4kZCi6XCQVz0XkcBKqB+jQm5SzMnc92/X33zQFXaAy5asNhp
         MMe3Z0Odr93WbZ3YxMU7s07IJxJa28/v4ojtOoR2ZMHpXMIs35/I/Q9dbm7vzDBU8tyO
         TcsycMCYiH6UR7MA6dXvqpC8NNPIS7zwJ9raoqQGGLKWmlLy50cTbqMqUjptIYKCSVy+
         bbLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756274949; x=1756879749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZOZHX282Y/NLPHgrnjlakHtxfKjrTBR3B3VWPOaVdCU=;
        b=oT7EcO8UUfPId9PqxMPK31cyZMZQWmDWwp28xxT8U957txbXOhKH1H6+Iom+0RQ6Bh
         ldz3B/7iqwQ/ZYcj2L+Invb3BtFbO3ykJF/0ryISOXAnVcrkbiFEfnv0fzBLTL4Schy2
         tn3bVCLJzGQ6CdzY2638e4XCsczEI+s9TJuxJdNtXL25kfhHCXqQq0roD3tAaTPJwVwl
         cwzRlG1xggc8B/Qq+w6rtb4KQxVZCflBwMFBqIMALst/ZDO4kV6hhVL1mlJ0XN0d9V5P
         A2PMqOrwg8gd/i/uVy60F3sN5aQ8eY95R4v53JW5KAL+TAYFr8HdZwvKRE5DqfoONnw2
         PYzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCV/jRlb7HlvtmJhR4upo3LdzIWLTyHh+qDFH/MIncRpvcBkD5UuyiDd9fDb8imY/5m7x9Fvmw==@lfdr.de
X-Gm-Message-State: AOJu0Yx2moYzBfPNj80Az6SJ70Vysk9+TyTqvc+urbcOPq9YFO69pKJU
	ZDDJP4TWB2PVeeRyO3Sp3JJ1/UsMjKPCuGpdGFAAfeldPNYgPUaHeT8M
X-Google-Smtp-Source: AGHT+IEKLCUemtpdVOu5spiwzN0z23NsbC/ALg3hOEeR57ARmfD26SrQMhlkBdSdO3c11NvL3lfIyg==
X-Received: by 2002:a05:6e02:1a02:b0:3eb:5f74:ed9b with SMTP id e9e14a558f8ab-3eb5f74ef09mr160153165ab.2.1756274949230;
        Tue, 26 Aug 2025 23:09:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcx/JFImjAXf/boc4tXtEFz6XNJCBcR7OdMyU0yTVQtDA==
Received: by 2002:a05:6e02:5e88:b0:3e6:6922:1bc1 with SMTP id
 e9e14a558f8ab-3e6836e535bls37317565ab.2.-pod-prod-07-us; Tue, 26 Aug 2025
 23:09:08 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUDKiUtQeeMG7Wr1XmsiNKaPE1uPBJCaLgyTJ6giYML7d8PA7a86rklFTuNbq1zoA70XgsJvFscWdY=@googlegroups.com
X-Received: by 2002:a05:6602:2b88:b0:884:477c:b4ca with SMTP id ca18e2360f4ac-886bd0e36c1mr2483144239f.3.1756274948140;
        Tue, 26 Aug 2025 23:09:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756274948; cv=fail;
        d=google.com; s=arc-20240605;
        b=NeNBHNL5SQJA97tRCQGspAhwtvk1czMCqZcs8TtF8w26CYDNC3A7oLAhPkuRiQxSwB
         ws57F32O3jGza24qCaAFkkE0g7khPU7dYeHATSvadZDUJ9SBHM4c0YPAp9uN11njoWew
         3S2Sa2AVwaa6qJcuorLm4Clp0VWUtfVZIfESW34vglrIr/yzyoxc1nzuA8Zel2sPaUjB
         dHx0/cD4nrk4j9GvSsIrufqoTU3Jsbvy6JQ9piyHqZwBN0BeM6DKPqiZ13RwjnT5c5hr
         8KrbCbH7C1MWlUdVyR5HMdCuy0wd6Qvou2WVbN8/v9cW6ffXANo9stwZk7QQA3OUxHID
         VYdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=eiaP2/jtL+Ftu8pslhiWWY6fJK7DIV/DVBQAJJBuX6k=;
        fh=sF7S6eZX2E2MOaN592eRzeZsLiILaVBndT/7rr+uhts=;
        b=dLe4HLqbUSZrqNYhc5pCH4qLEJcmvgA8Ieslq/flus26WBZzFkVHe0dRBX4JCD4J3I
         5R8Zy6f/Uh/arbm+jiG4KA7ntFuoEjpZrhBNUhz+g6kdUiEHcAYGhLsailGguOMvpo8d
         YBv9USUleXKceLxOxN7+bCbl7aHOttbRn6+YWsYnyqlMDkPnoOHtNdcwulF/aqQhti6m
         TdtjD3/tjnXoNQ2VReP9bbsCEPD3rPYpVUC8uI9eOFWU9kO0YnuX6IDly6gt7qJlq5k0
         G2iq6LFCyYTpISYEn8vcY3ywhMPOOK+EEtWWIXuTlFdMPGx2F1sfIB9mUHZbzzhd7rgk
         wdwA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="cqbY/+oj";
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.18 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.18])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-886c8f6a8c8si45085239f.2.2025.08.26.23.09.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 26 Aug 2025 23:09:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.18 as permitted sender) client-ip=192.198.163.18;
X-CSE-ConnectionGUID: UKDitZZ/SxO2cMXOxM5xfw==
X-CSE-MsgGUID: kgaXaOtXS4uBCwlj8x2L5A==
X-IronPort-AV: E=McAfee;i="6800,10657,11534"; a="57724909"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="57724909"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by fmvoesa112.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Aug 2025 23:09:07 -0700
X-CSE-ConnectionGUID: D3iUhNgzQYSP0N31xmhv5w==
X-CSE-MsgGUID: dE9TQyEdSHSZq59mu2qZog==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169369128"
Received: from fmsmsx903.amr.corp.intel.com ([10.18.126.92])
  by orviesa009.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Aug 2025 23:09:06 -0700
Received: from FMSMSX901.amr.corp.intel.com (10.18.126.90) by
 fmsmsx903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Tue, 26 Aug 2025 23:09:05 -0700
Received: from fmsedg903.ED.cps.intel.com (10.1.192.145) by
 FMSMSX901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Tue, 26 Aug 2025 23:09:05 -0700
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (40.107.237.72)
 by edgegateway.intel.com (192.55.55.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Tue, 26 Aug 2025 23:09:05 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IJm0ohcOG1soB4TLlEn135MGOrEMqJQuzYItr/pkit+LEdiLKvaA2tf0V4gh45p7dlwMmsA8ZT76WLHqHugyms3Oup7HQxio3HU0SmH1VzUs41VHNnbwyRQc0Yd7pxTijfGk9GjMAnSxQFY/XCNyMvpm9PydhDHaX4EeumkJjoB0TeTdJb7jcJb6GCRIQk3quWBBqnUJta/vuaD0Z7XpBTw4ZWrga9zFOXX++q4NXOntUw9wn+PN94TQWxkrbfPPVsT9rXtFHbVPhUJ5z7TT/+9D933CX836uGLNkOeFGffAux9r9P1pN+2j4V2sQxH9a+2wcKycI/4T0coFyCGQCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=DK3HH92O00VpZRiOdtNfl93guRSUK5PuZfDfcXy2YKI=;
 b=NTRhTw/noMzAHptu4zyKpMksFVzGVMIJ02i0/NNoN9NHbYsFFY/cjYsZ2kuH60DmXIbtyzBNrYEbnES4r9wbe+zu8gYaCwfaJ6FhZVCAfOYazdm6ZgniUYs6GseBRVQHdy1zAyJzqIUm8dThXM7WIYQ/e+Rp1n7GwRyAOQqwfirqxgtec5tNV6ZvYFZCNbKiVTBhbqEqJyooGmMsoPxPNWuMUplYxhwtqB/vQgk9g0xQXtQ+Dbr4yNukrLTpGJdsJJ85c79zu4jlMRC7GMIp+aHvmginegdapKPXLvfjxbjW4AKJfROci7BxekjLvit8oa64E8Vy+uYD/ZHix7Olhw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by IA3PR11MB9349.namprd11.prod.outlook.com (2603:10b6:208:571::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.20; Wed, 27 Aug
 2025 06:09:03 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%6]) with mapi id 15.20.9052.019; Wed, 27 Aug 2025
 06:09:03 +0000
Date: Wed, 27 Aug 2025 08:08:30 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Samuel Holland <samuel.holland@sifive.com>
CC: Dave Hansen <dave.hansen@intel.com>, <x86@kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-mm@kvack.org>, <llvm@lists.linux.dev>,
	<linux-kbuild@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v5 10/19] x86: LAM compatible non-canonical definition
Message-ID: <gcpw2nrwltvgatdjcu2at6hpse42iudy5dqx7rv5m427dommwg@akooygrdmfvf>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <c1902b7c161632681dac51bc04ab748853e616d0.1756151769.git.maciej.wieczor-retman@intel.com>
 <c68330de-c076-45be-beac-147286f2b628@intel.com>
 <4rkxgsa5zfrvjqtii7cxocdk6g2qel3hif4hcpeboos2exndoe@hp7bok5o2inx>
 <2e9ee035-9a1d-4a7b-b380-6ea1985eb7be@sifive.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <2e9ee035-9a1d-4a7b-b380-6ea1985eb7be@sifive.com>
X-ClientProxiedBy: DUZPR01CA0103.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:4bb::15) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|IA3PR11MB9349:EE_
X-MS-Office365-Filtering-Correlation-Id: 7f6cc0d5-53d0-4a07-d5f3-08dde53038d9
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|27256017;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?/OIBpjR6XkYn0b1X5wB13Iy9hW2CBOpikVO/Oj898U+a0FzdbTUvHJLUAT?=
 =?iso-8859-1?Q?IX0Tc/mRuYef1mEzfxzFy1L/x8rkXewbJujnYJZgrdKMJ7okK/2yK6xCGD?=
 =?iso-8859-1?Q?msizSfRvKvkyTkJScMX9IygogMbo0S+cu9vObvFg3AA39AjQ9brLXAGWZe?=
 =?iso-8859-1?Q?3ciGXXY735NoTUjTAx4jCff5FKgXVAuXkBUKTLLDdfiVzKksRslc6TueRK?=
 =?iso-8859-1?Q?jR7Bo+pJ+2c0WH9R/mDvZgCIUMWkAv979G7suCGJu5p4J9biWIuKuYnWUf?=
 =?iso-8859-1?Q?ecjGdBiiCrehvXwj3DoLpNkImBTZXUpaZA0EPbXLz9ra5NP2Xl8erPRaQm?=
 =?iso-8859-1?Q?oUNM2nX+iOjuc6nrmLSasMwgbjpnjsXWezlobF/rqhAq3uGl+5i930VrqF?=
 =?iso-8859-1?Q?iqf6u9hstUThSkYGNkFqk6pHj5+vhqDJnDL/O8gTxoC8Uzwfsae4KOgIiU?=
 =?iso-8859-1?Q?Lv+FQvbeMN53PhhkptAXsCD6ARnTDzz6Lrx60Xwx4eOGphff8GlYldJ1VQ?=
 =?iso-8859-1?Q?h9gqhJLbNLSUfYq/cqsyjwheuylpvEJmCfmcyAy3aV3Ds9cbnFaEb4Vm2m?=
 =?iso-8859-1?Q?OpTz9X9As9+/A6qi2hGkD5GJp3qukToM5S6nNZgk5HtQbfF8V85PksUamO?=
 =?iso-8859-1?Q?Il4IuQlEuIob583/PspRQBpF/7C+iVflrISKtjiGE3UtAiZywxQiTOxppd?=
 =?iso-8859-1?Q?IdPrU+IcPFu0dvd1YdU+DM/v+7oF+26WaPi3gXZvejV/tDVZxgo8YSlE5R?=
 =?iso-8859-1?Q?0pS5UyLLIeXtoviWXbK4jVRpwFVxt1b1HiItZcUlrZPSxFhWYx3bImVSa9?=
 =?iso-8859-1?Q?zoHGoza7v99cGqzKRCKkIzGvYID+y5+ELcJMr4rp49s46bLFCiWgF/FZRU?=
 =?iso-8859-1?Q?8THT8kdeQX77c8zQBk8OzQUDvdchloJ/RyoXnCRX2iYKr07MVWZUm4f1Zk?=
 =?iso-8859-1?Q?8rnrHhOKGwkcO11GIWkamhM1+H6a2QQXq/Hbqlr7tN+Sk1Y5oMIrFqXGrC?=
 =?iso-8859-1?Q?zTGTW4hgZRGYRZIktyoTgmJx3lMyBvvbMXulvOxSmB1XdNM+b1AiDaPmpM?=
 =?iso-8859-1?Q?ciJHJn2JMRVNYIuRq4+x3TL7/+jXLx+ouUAu0eK8b+7uPtbRIo9h7CltgA?=
 =?iso-8859-1?Q?+K6L5PkxMoMZ+goOKCNtLA/NyZQRyjhj0kZdqvaMrp8vhjrBwJ5JcJMgNL?=
 =?iso-8859-1?Q?ZuHKUsaq0Ue9LmNvFCGM3V9wTnB1ZCqVDB+fL4vjDikRSE6I2+RiieRiLk?=
 =?iso-8859-1?Q?7aEP8Slft+bRReSHbWQ7wnJZQZ3nTQmwesFskrSFFQ9l/6oE3ZcJ9cRjIs?=
 =?iso-8859-1?Q?hrEgUHbhx/RYEq48z1NMG3OJMY2g2MtbaVJOleD453QfVGNzDO4PDm1Lpa?=
 =?iso-8859-1?Q?uJV+ZKFd0dtjkq4rxx3wBLFhgt8cjnvs1XbSzZb1Ito+DejrttPEh1tCDP?=
 =?iso-8859-1?Q?/CTh2GSgVl7HcM4vO4fFOob/BlJe8qni2XcCxGfK1zrViK0lsZjLxFHfLT?=
 =?iso-8859-1?Q?QgqX4A6qcrSGvAHRdoMUUW6PTMJRYpPrK8aS9ahl0lxg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(27256017);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?EwmElDDC2dNIkiL20YXAKgLRZcGLtBE5gKfara5+e1RzY+MKq1ZJLnx9/g?=
 =?iso-8859-1?Q?jc8EKtY/gB/cCykFfAv/huBlmrKA1XvqNQ9vahK8/v17Ww3BHpXX3prAjE?=
 =?iso-8859-1?Q?j32gN0NCEsHdpJqCvpO9/gql/sVS4wKUjt8KBo6KzqD7sWegN7/syk7Fzl?=
 =?iso-8859-1?Q?/ZkT5D9IbaUBmXUwIBmq5zqCpiMRWdtLYS7ySGaGTPn12VgM9gHwGNmqDg?=
 =?iso-8859-1?Q?rNQSBhJTVp5cKavv2i1Tk0zdK21wOww2nLBKWa2BnexUpr/xr8qrZPn/08?=
 =?iso-8859-1?Q?cMKP8GfVzF3FEU4Lzpt/Y2lwRM6dGNcS5KsDezx6zFpxpAQKihT6JoYUNJ?=
 =?iso-8859-1?Q?1TtNd5KMW6N3jW4YSwSJvIzEedVK2RD35/VRx7wtgSVAdAM/I8oxupfCIO?=
 =?iso-8859-1?Q?co9DDOzeYAmpjzDVHvTIAQAyGhVjcBTG4J6sILxcdxoCqZ8Sjzhv7aniNJ?=
 =?iso-8859-1?Q?nC7zjeKvZZYyiPaLJ6+zxIGD+vAu5hkaifB6Yr9Vpvtom4jP72Ls0Eaczk?=
 =?iso-8859-1?Q?L8jbxE5/av8qRQD9x701rtohCNbxBOcte1aMcF/pTdQ5zpM8a4vVx5Z9Az?=
 =?iso-8859-1?Q?nPPoKIxVRZ+yWsSqhn8OOsPJt77u9QkJ3ljoNQmTRxQ87xHaoUMGxnojCu?=
 =?iso-8859-1?Q?dX9A5V/rN0YDRUA6kU1SliKG7LVZunmEa3mFYWWjM2gyC0WMIDA/jxbuPH?=
 =?iso-8859-1?Q?wLs2xkJ8B+Wvv9P9BowmXOJ9r7f7R4dAoSFoNpbXmDK4EE27OF6Sd7e7vE?=
 =?iso-8859-1?Q?xdL/tfeIRxhAgIJZUEgIPctsOdy2VXQDTgfDwXkpPFgbURIMvrFswkm5DB?=
 =?iso-8859-1?Q?DbXfcipzEVnizRU3CJNE01NfCch/XC8vVjVcZ6pJ54b1+Z4Z6pBpaCdcS7?=
 =?iso-8859-1?Q?3S/Z3bsEx5kOGVJ9SxPv/4LzOd57MqOXLmhPclnLkPwDOWVfZzL0xByr8+?=
 =?iso-8859-1?Q?g8qJhX3KPnEdVMmNfk3eDHqdgVlLkY96W+3xhOk8BTqrkge6FEyvuQ83wA?=
 =?iso-8859-1?Q?XAw0kfJdsjR/iSuRU4jLr/QfLhlyA+py+1u1uP9UIJ/OGmv5ZN2VIlXAUa?=
 =?iso-8859-1?Q?Dq+9uUelsf/TFjwKzUmbTUgzAdXDyfAv+0IjiVaveilO4O72R8Ftvt95O7?=
 =?iso-8859-1?Q?O63YhSUITcRp00GgbvFjN/moJN8ZtuTb4iaadqFiJUIXMd0cX5oRwpieZO?=
 =?iso-8859-1?Q?hfjEsrk+cRC7AElhjs6A9k6PCzF1rXzA3RmCsh2SpKIuZHCFgqEAKI5QzK?=
 =?iso-8859-1?Q?D9TK2Cq7s84r6WbbMFkyRj3bfYagXOoBhZwuJx65r7iXub6qZytGH7xgRG?=
 =?iso-8859-1?Q?jLwXeWRnGXTJXLbU+QfuCCYofhT6KVIk+GYgTt9dMRPewwvAFtli2cU6FJ?=
 =?iso-8859-1?Q?0bjygSRJsrXh/xJK7n9lJC3si6pteF/LbZgq+QSGDFhHPsbTnJJ9vsiISQ?=
 =?iso-8859-1?Q?kiCWUVVIyGe4CMiv2fCEwPajaMHeD5iyE5bIOiBQZVjo862RQ2ubFwvLR6?=
 =?iso-8859-1?Q?a8g1whgF7NQCdS1czxa5RDq7x8XloIrrI2K/MRUkCTu00KTM19bmpNivOK?=
 =?iso-8859-1?Q?uVXooMSUhXXdYDHVneuiwHWqsscrpaiEprwZlEbsg/h+dBwIf6FlA7IavC?=
 =?iso-8859-1?Q?+NPXprx7agmhsSrVS0xYRGAC9t9QEp72lA25ggsyWjMs2ICxBLeIuBgqcE?=
 =?iso-8859-1?Q?JVl9oJJY7QjqmT/ExpA=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 7f6cc0d5-53d0-4a07-d5f3-08dde53038d9
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Aug 2025 06:09:03.3838
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: aplAYVEN7LwEi94pirUyRYIzoEGo2AMl3KuwfxLMlCOG0TtUZkbNH1ySigp7qy6WWfPtfXJcOiS+Xjz+kJJP0DDjpu5IijidDpCrD7GGfqI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA3PR11MB9349
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="cqbY/+oj";       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
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

On 2025-08-26 at 19:46:19 -0500, Samuel Holland wrote:
>Hi Maciej,
>
>On 2025-08-26 3:08 AM, Maciej Wieczor-Retman wrote:
>> On 2025-08-25 at 14:36:35 -0700, Dave Hansen wrote:
>>> On 8/25/25 13:24, Maciej Wieczor-Retman wrote:
>>>> +/*
>>>> + * CONFIG_KASAN_SW_TAGS requires LAM which changes the canonicality c=
hecks.
>>>> + */
>>>> +#ifdef CONFIG_KASAN_SW_TAGS
>>>> +static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bi=
ts)
>>>> +{
>>>> +	return (vaddr | BIT_ULL(63) | BIT_ULL(vaddr_bits - 1));
>>>> +}
>>>> +#else
>>>>  static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bi=
ts)
>>>>  {
>>>>  	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
>>>>  }
>>>> +#endif
>>>
>>> This is the kind of thing that's bound to break. Could we distill it
>>> down to something simpler, perhaps?
>>>
>>> In the end, the canonical enforcement mask is the thing that's changing=
.
>>> So perhaps it should be all common code except for the mask definition:
>>>
>>> #ifdef CONFIG_KASAN_SW_TAGS
>>> #define CANONICAL_MASK(vaddr_bits) (BIT_ULL(63) | BIT_ULL(vaddr_bits-1)=
)
>>> #else
>>> #define CANONICAL_MASK(vaddr_bits) GENMASK_UL(63, vaddr_bits)
>>> #endif
>>>
>>> (modulo off-by-one bugs ;)
>>>
>>> Then the canonical check itself becomes something like:
>>>
>>> 	unsigned long cmask =3D CANONICAL_MASK(vaddr_bits);
>>> 	return (vaddr & mask) =3D=3D mask;
>>>
>>> That, to me, is the most straightforward way to do it.
>>=20
>> Thanks, I'll try something like this. I will also have to investigate wh=
at
>> Samuel brought up that KVM possibly wants to pass user addresses to this
>> function as well.
>>=20
>>>
>>> I don't see it addressed in the cover letter, but what happens when a
>>> CONFIG_KASAN_SW_TAGS=3Dy kernel is booted on non-LAM hardware?
>>=20
>> That's a good point, I need to add it to the cover letter. On non-LAM ha=
rdware
>> the kernel just doesn't boot. Disabling KASAN in runtime on unsupported =
hardware
>> isn't that difficult in outline mode, but I'm not sure it can work in in=
line
>> mode (where checks into shadow memory are just pasted into code by the
>> compiler).
>
>On RISC-V at least, I was able to run inline mode with missing hardware su=
pport.
>The shadow memory is still allocated, so the inline tag checks do not faul=
t. And
>with a patch to make kasan_enabled() return false[1], all pointers remain
>canonical (they match the MatchAllTag), so the inline tag checks all succe=
ed.
>
>[1]:
>https://lore.kernel.org/linux-riscv/20241022015913.3524425-3-samuel.hollan=
d@sifive.com/

Thanks, that should work :)

I'll test it and apply to the series.

>
>Regards,
>Samuel
>
>> Since for now there is no compiler support for the inline mode anyway, I=
'll try to
>> disable KASAN on non-LAM hardware in runtime.
>>=20
>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/g=
cpw2nrwltvgatdjcu2at6hpse42iudy5dqx7rv5m427dommwg%40akooygrdmfvf.
