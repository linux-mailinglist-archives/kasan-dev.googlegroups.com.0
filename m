Return-Path: <kasan-dev+bncBCMMDDFSWYCBBZMTT7FQMGQE7YFM3LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DF88D20573
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 17:52:56 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-81f3fb8c8casf8240914b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 08:52:56 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768409574; x=1769014374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yu3wcYbv9ucDki2WZ+SNEd8iKTN7dzguKxWC8hASzJc=;
        b=ndF9ND5UuiK5SjuMFdOxVzFmOtTF6u/msSSppEX3p4zdv9lcRFZderUM+7l48oo8wB
         dUNbst1LHkXm79bRsK9b0AqqAvDCfAyNpvNlAN0fXl2OBuE8TcskbVV+g3UgbpYwswYQ
         k/Rk63ppHMhxDZ4oUilg4GP83sWpnA+S9vGGolQL0wfN6ytJSsOa9D7/ClnB0ACs+PaS
         j2CHBqWsbbM/OGlfxVB745hQnrTH3tdIOJOecvb6dUE6woYktQq1gvxgcpWJvzb8zPlz
         +41t15PYpgIJ98jlFHoEC5jP3Gu39D+ySB4Yp5nlTBTdP0y+972RfqszOj3RVuJPby7Z
         ntjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768409574; x=1769014374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yu3wcYbv9ucDki2WZ+SNEd8iKTN7dzguKxWC8hASzJc=;
        b=RGxk6DFMA257LH9e6OumcoGC+/O7vJ2FRczlybhORaF7Ggl4ReLWYinIzgmhjpToog
         gyd7Pce1LbWfK7o5ekR43Ot6MZfDQqIQRMdJ6zDBbzmIiEriY4BAqpXlUWl4uzj/RiwE
         DJ5T/wzENv2ftoXQNScxVwE4kgAzWCeA+w62UhyXkzcnWn6W8qilQ06fKGnqLBTz7GQN
         LDdmJ7tqTgCcLZd7yosRfz38VR9nq+Vh6xIVY0K52hs29pIZon+m7xW9XHfT2QDmSTZA
         5V25ISLSGp97dqwjq5s846KpQ6K9lTwlXVWRvCAHvNFQHKczj8NVxMfQBlqq3h0bzHal
         wSmw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCV9Yx5kbRZRA0e5wp7Fco1EUZV3UcAYTLX+r1qatC//4zEpdX7ay+8AJaoAch4Q16v2Nt8hHA==@lfdr.de
X-Gm-Message-State: AOJu0YxQUczBJ0RkCBz49/OtLTtbwYOVKd6PL1Z7gghCJesPQM3lkxtN
	QNAuNZsMWlyqOcGLH23H0sNABqycemTI2e8WegDISFZQ7oBXVkzoQMWN
X-Received: by 2002:a05:6a20:7f98:b0:342:a7cd:9211 with SMTP id adf61e73a8af0-38bed111054mr3309019637.34.1768409574113;
        Wed, 14 Jan 2026 08:52:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Ef2/Wcd95v/1BOKCgU6xakzLUV8nCygAP2WDziHLNNww=="
Received: by 2002:a17:90b:692:b0:34e:b341:899d with SMTP id
 98e67ed59e1d1-34f5e962da0ls9042785a91.0.-pod-prod-06-us; Wed, 14 Jan 2026
 08:52:52 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCX945gJVkYl4++wDNwOEOKp2AIYxWNwLW/cWV0FrhHRqCHRKZiRB7nhJxmLT0YdvifRgG2zpgpWf+8=@googlegroups.com
X-Received: by 2002:a05:6a20:6a10:b0:35d:8881:e6c9 with SMTP id adf61e73a8af0-38bed0d29c4mr3579423637.23.1768409572672;
        Wed, 14 Jan 2026 08:52:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768409572; cv=fail;
        d=google.com; s=arc-20240605;
        b=ZjA+srQRcMR+aDIi2UCa1EGPTrl9iUUI7fzaXs6G0whPk9hcdLiINNIps2O82Jy3Qv
         BdCyUsmEHdk9fv+Z9WgKhPuKF38yH+OcmtlgjLklI3aafzIg58qz1Hzfsuxe/lRIVzdP
         JDwMq2AqhJM694BrzN4aZkxDq1qmjuwApBzNASD/Lbg5UQ0VASMGxHuB7CpR5Us3aHA+
         Xk6t5E3jCgeEEDk2eyRdF07WFRaVGojcvFdfxJ3RljKGyMf0XErP7TnD00IL+A6X6akY
         jrGpiYJywtnwiU9SDrmkICiV9kelatQSdthzA3io4FoLz4lS/GNNwTuckl4MzYLzpqcw
         KvaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=1+jNOizPTpemCUGsr4FWTdYC98LVuNWXNm7QXDxqV9Q=;
        fh=Msc9dwYRLDVOUQNIeU8NXemUFhGFVK4/6BgYO6gGcNs=;
        b=lbKPyUxTHUoa32ktqz4Vp/oOHq93q7IxPkZAd+I2LCoP/PU2clozjU4m53qoi9HdlK
         +cftljkDIqhrgRDHbNJxrU/LkQWx7ZT8w4I0tKFN7p1ZOtNTkI1mgc0b8WFovYbNz9Sf
         lDrIvruKXzurf88fcTP+CqB/C/5mszw6UY6H7C9XoheY+ZNDl+SbQDfxwaZM769p+678
         lL+sj4AvvMzih7fyTRwO3O32QelleaGo/iGPiXBdq/sG7KScYtWcgxHqMwnWRSFyGO6X
         ki6gtThmJK0jTpzdSF6iz+cSb0mWDHfHcRP7senRkxtLhOiw+4ojjYEZktOmnbgvSyIH
         N5fw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HRMlMSKH;
       arc=fail (signature failed);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.8 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.8])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c4d93b595bfsi754179a12.4.2026.01.14.08.52.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 14 Jan 2026 08:52:52 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.8 as permitted sender) client-ip=192.198.163.8;
X-CSE-ConnectionGUID: uQ5QUe6tSj+MA4KZ9Ua1rg==
X-CSE-MsgGUID: Zr7xgjMKR/+N7/AmXTixwA==
X-IronPort-AV: E=McAfee;i="6800,10657,11671"; a="87291888"
X-IronPort-AV: E=Sophos;i="6.21,225,1763452800"; 
   d="scan'208";a="87291888"
Received: from fmviesa002.fm.intel.com ([10.60.135.142])
  by fmvoesa102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Jan 2026 08:52:52 -0800
X-CSE-ConnectionGUID: nVyvET4SRvm/Pet97iVpMw==
X-CSE-MsgGUID: mhs0Q5QzS8u2gYrCsAttnw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,225,1763452800"; 
   d="scan'208";a="227852928"
Received: from fmsmsx903.amr.corp.intel.com ([10.18.126.92])
  by fmviesa002.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Jan 2026 08:52:51 -0800
Received: from FMSMSX903.amr.corp.intel.com (10.18.126.92) by
 fmsmsx903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.29; Wed, 14 Jan 2026 08:52:51 -0800
Received: from fmsedg902.ED.cps.intel.com (10.1.192.144) by
 FMSMSX903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.29 via Frontend Transport; Wed, 14 Jan 2026 08:52:51 -0800
Received: from SN4PR2101CU001.outbound.protection.outlook.com (40.93.195.52)
 by edgegateway.intel.com (192.55.55.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.29; Wed, 14 Jan 2026 08:52:51 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XBwsOCw6p9pcY5+U4PmVTdfqrhpCtFO0ss2xmO240jX/mrtE0qC5RKUH3U31/3V0hJhic97EXMeXynn7PaAdT4hAulmwBFnTvEZ4onsokUpuICI8/NYT5zRSQOP/vLrFlCpWcrkqiYoBD2C5Xzuzd8dBZ023irSKAJg+5352wzm7XXIA9xTTQGpRrga7PGqhky+RzR7/Q1RjZH2QcblP/SCi2Y+n5O3cYQsjN0JjqfCNtufpkDc4FEq8hHvGFpaJbghPcnSBCr16eeEbF2lFJsw5YwNSw3fIgCvlZ0pK/LkyTXpyXlBFv5oDyTXSTBkeESxkNCxV/bTmE3SB5Qrxyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1+jNOizPTpemCUGsr4FWTdYC98LVuNWXNm7QXDxqV9Q=;
 b=pZATMxpCzNn8JRdcu2nUhTnbMIcQeGIFbQ3qp/+sNXJ9wOs7IHzhxNk5Qg04aO0O1kpdc/kcAB+vP9KwZ2HiCKPxg3/t1pkXyxJ+U0ZToeLfFuC8mAJMHIYtW7cfm6VWPx7qttKPU3oSiWLrjqYB4vSdDwOLcg7v5/oHdA5ZS7X18KiXqO1XwLicqbEAkIZKVUGi+bnfhcUvZ3L/2sIprl0cQYsENpShSMZD/ij7ZHivJhsL8T0RlkMJIb9MVY9UW8aA4BJgipcihmMUwuJlG9MATsqi3BiXCjInxsoi6LXYs/4Gi6bBK6NisLwxWibzqW0LwJ5ADiaHlpCsdTIAJA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from BL0PR11MB3282.namprd11.prod.outlook.com (2603:10b6:208:6a::32)
 by DM4PR11MB5263.namprd11.prod.outlook.com (2603:10b6:5:38a::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9499.7; Wed, 14 Jan
 2026 16:52:49 +0000
Received: from BL0PR11MB3282.namprd11.prod.outlook.com
 ([fe80::5050:537c:f8b:6a19]) by BL0PR11MB3282.namprd11.prod.outlook.com
 ([fe80::5050:537c:f8b:6a19%4]) with mapi id 15.20.9520.005; Wed, 14 Jan 2026
 16:52:49 +0000
Date: Wed, 14 Jan 2026 17:52:25 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, "Borislav
 Petkov" <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>
Subject: Re: [PATCH v8 13/14] x86/kasan: Logical bit shift for
 kasan_mem_to_shadow
Message-ID: <aWfDiNl9-9bVrc7U@wieczorr-mobl1.localdomain>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me>
 <CA+fCnZd+ANJ2w4R7ww7GTM=92UGGFKpaL1h56iRMN2Lr14QN5w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZd+ANJ2w4R7ww7GTM=92UGGFKpaL1h56iRMN2Lr14QN5w@mail.gmail.com>
X-ClientProxiedBy: LO2P123CA0004.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:a6::16) To BL0PR11MB3282.namprd11.prod.outlook.com
 (2603:10b6:208:6a::32)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL0PR11MB3282:EE_|DM4PR11MB5263:EE_
X-MS-Office365-Filtering-Correlation-Id: d58722b2-f60f-4817-c2fa-08de538d5974
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?NmNOSWlaSUtmRmtuMm5naWZHY3h4bUZhaUF0cm9OQUR6UHlvSkV6YXNvZ3hR?=
 =?utf-8?B?byttUFFRNHZxK2ZSdnJHNnpOVDg2STArcUNGUWpUUUYxZkx1QkJGdElPcGZa?=
 =?utf-8?B?M3lzRDB6cFlCbWFkeDVBZGc1akxlanVQS0NQSXp1aXBjZjM5aU1wYzRZVlBQ?=
 =?utf-8?B?ZFpWSmpMYjV6WXJjckg5S0l6cDFJK1hwRTJRcTYyUjA1c2tTYlZyOTNmREJ1?=
 =?utf-8?B?RElvZyt1aWxXdG1mU2wwc0RrNlpRUzUrRk9QU1lmak82S0JQMmhGZjduSGJk?=
 =?utf-8?B?N1hwWDNldkFIYnFRSUQxTE5iWXpnYWcwWitLWFRRdTZGdnBoMFU3QzYySTh6?=
 =?utf-8?B?QmJvYnAwRWFpK3lzeE1UcEczZFp4T3kzZUFrUGFqM3J3RGVJbC9ZZU5oUk8r?=
 =?utf-8?B?dG8rckYvSlg2OWNOWCtrcTVpYmt5T3VBckRVWS9LNG82YWRyaW9KUTVEUURq?=
 =?utf-8?B?V2JEMWVQamwxc0JRb0NZMHYwZHhUQXNpOXl1M1VJTURybkFvSjlrWlgxbk5K?=
 =?utf-8?B?cGFOTEtUVjNOdlhhTG5URGJFNjREajF5cFNVU0VwRVJVR2NkMmNQTFY0TTZu?=
 =?utf-8?B?Q1JBOXd1NHBBd3lmZkpUYzU2WkhoelVtWTFtb2pheDRsSjFVckFHWFk4dU84?=
 =?utf-8?B?MmlpVElpZ3pySms3enRwSXBnZ3ZnbFUxa1FlcWwyWE4yNFJxQzlIWGM4Z3RM?=
 =?utf-8?B?L285c2d1SEk1Wnh5Umt2dkl1SzRDanlsZXlMQmRnam9NbmE2eUo1d3Z0a1hV?=
 =?utf-8?B?bXJmaWZOc04zcDA3cEd0bWdLRWhYZDFuS1JXVHpxZVJzNk1UY0NWY3ZVVEZy?=
 =?utf-8?B?ZGM0VFlWZEF1TmtEcEplSitZQmEvb0xZWVZ1M2ozSGFYZmFmUmxHdWREaGhU?=
 =?utf-8?B?bVlIandPZEw1VEc4VUtPWHBrbFpzbkxkc2huUm5xUGZRK054N1JTby8rYytX?=
 =?utf-8?B?cHFGQXRtTTh4WXEvRGFJZXVYbnJLNzRKcFdsYkprTnphK1B4ZGQyOGpkYjJ4?=
 =?utf-8?B?blE5OVpyanR3VEZXUFNXdnBxb0YxRkN0OHRCVjU4aGVueGNVUEpyNTZjczhC?=
 =?utf-8?B?MXpZUTg5dGw0d04rd2FkRjhxQzJuOFo1TW4wQzJpdHp5WXNGVUtxSm90dk1r?=
 =?utf-8?B?NDlPQmZQTEt1cE9DdU42bUVleGowOEI0TUpObkQ2eGorUmRhYXlnMjdJNTlh?=
 =?utf-8?B?MjlkTmNVc08yUWRKcXg5a1FDaXQwRnpldVA3SmVIUU5VQmRnSTU2dVBXbjd1?=
 =?utf-8?B?NVpvUER0ZGZESlR1b0JsYi9qNXV0a0ZFdG53ZmxWdVhhTXM2N3N1bVJwS3RV?=
 =?utf-8?B?U2YwUlNxdm9iekJiRSttdDNWRk9XYVYxN055d2ptcE5KZmErdXRrRXNOcnl5?=
 =?utf-8?B?M3RPbXgwOWRyNWVxT0RWOVBsTTl4emRNQWVOU0ZHS2tLaWcvUlpFUjFKdC92?=
 =?utf-8?B?cDl6N01kMGhCSk5YY0p2ZHp1M2loOFZWVEtVSFZHZk9Qam5TbkNoVmJJQzl4?=
 =?utf-8?B?R2dQUXgycHBzTVdqbXpLZS9BOERYSHFiY3Y5ZlBvL2lTdFhGOUZ3ZWFKYmJW?=
 =?utf-8?B?ckNSQkNMVVJONlREWnlub3VtSklpSDgzaWR4QXcyZXE0dWd5K1FwV0NLOVZI?=
 =?utf-8?B?b29JNVhMd2t1Wm94em5XM1BvMGdVbUdEREJjYnNFTnQwZGpDL2xRdW16WnBI?=
 =?utf-8?B?T1l0eGllcVFZUVV3ajE0MG9GWU1DNTduQVIvRVdDRUhveGE0T3dQWklNSkNV?=
 =?utf-8?B?S1lwZDZUTGhuUTRwT2g3N3RBQlNaS1pkWUtaaElSbXQ0eFRucm5SKzZneTRr?=
 =?utf-8?B?Q29mQ2dzcDRQcWdLZXRGUjMzb3grbkhTN2hXMXN4ZWt6bEszK1ZyN1Z2T2dQ?=
 =?utf-8?B?QVRLQm95MlhyNTJKb1VuRmZSNmQ2SzlrRDE4RDhmUkFveG5JQTZweTh5aVA0?=
 =?utf-8?B?MnZYbGhUellFa1BaREVxUkVaRW5JN05uclZSdEV4OWVtZTdIMkR4bUdFck1R?=
 =?utf-8?B?Qm94VGVIdG9xejI3bVN0TitHVW5RdVR4K3lIWHdpN3czMDIyUUl0akRPQ1Ey?=
 =?utf-8?B?VTFqQ3puYmVZeDYyajlmRkpXMHJLYndHL0Z1M0lKMk5iaVBXRldBSk1NYks2?=
 =?utf-8?Q?gx3w=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL0PR11MB3282.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?c2VDMm5HUVd1RkVLRVFKaUs4ZG5FbVBRK2psSUFaaXJvNVMrSnlkYm92TGh2?=
 =?utf-8?B?N2ZDWDl1Vm9aVml2U3R2d0JCWC9GTXRvcS9HaThIRzV6eVRWVEI0VSs2UUhx?=
 =?utf-8?B?dXJqU3FxN0s0Zm9xRlBGajkzVi9XSkdOdW1pQUZzMEN1a1BDUTcwUUFaTTFp?=
 =?utf-8?B?OElqTWNzUkVoTUxyYnIxcEhrVXNXRXBlYjhGeHp6QThEZFVxbWtQWU9qdjFu?=
 =?utf-8?B?QkVmVFoxTnhGV1AvNERoUHBLQ21EeXFFWkZIQ1JHWmh1bVJoa2wzRmRBdU44?=
 =?utf-8?B?d3lkZWptSWNkV0NSSCt3TWlOaWVuSlVFVjhrdnlUSkRLenovQWY5UHJTc3pw?=
 =?utf-8?B?SkV4ZWNnc09rT1BmUUo0NlpVNGovcGd4TFdMS3J0NDcrSUFGbXFMb0xIUUdF?=
 =?utf-8?B?VktHWnJkNnNuYTRtRXZub2hicE9sWkxyd1ZFSm1ZRE8xVXp5dXhvWVk4US9J?=
 =?utf-8?B?dVRCZXF5aEViZEh5aDMyNzFIWTh1QlFicGxtd1c1RjhVdHBaU21VbHBlYjlV?=
 =?utf-8?B?STdnT2ZBaDFLWDdDT2ZPbUg1b09kN2NXRzdDcjNUVndSK3BHYXpmM3JYWUpM?=
 =?utf-8?B?YjVlaFc3bUVJZlp4NVBQcHE4U3FGU3BuVFgxdnA3TEE3WlJuZjJxL2JOT2Vr?=
 =?utf-8?B?aTRQTnlzdXBMcXo4WTBrYjlGM3o5bUhwY2RWY3d3UEluN0tScm0vbWtIWnpy?=
 =?utf-8?B?bVAvZmYyM2V4dmwzREJxSGRKTFk3bFF4OS9hU1NYd1JPUWU5K3h0YlJqZjQx?=
 =?utf-8?B?R2k1ZUY5TVV6QVRIQ1hnQk5adWRSOVIxV2Nvd0tJNi9qaW1TZEhUVDRrRmFG?=
 =?utf-8?B?TWpTdkl3Z3BnSW5jcDVCdnowM3VkUHlSb3gwbkNJS2hicmlHTEIzSkF4NEQw?=
 =?utf-8?B?ZmJlUi9VaExMYTJzZWVOcVAxbTd4M1g3VHRpS1ZmN2puaGoxanBnL1drRGw5?=
 =?utf-8?B?bkVEYlRkYXhLemYwaEI4SXB2MDZnL1BjaU1mWnRjeTY4UzdOY3BuaVhHYnFO?=
 =?utf-8?B?WHdYRy9Db2ZqaFBuWm84MkUwaDQ5aVczTjZPS29Mb2lKUDlBTzBtSThTUFd2?=
 =?utf-8?B?bDlJMVJHbmpxZlhyaDh1bzMwR0hjbzdCSmtJNmZZRXo5RWtPWHVDQ0RYZElP?=
 =?utf-8?B?RjFIaE82RFZ3WGdyUVpOdWFMUDdINS9neFNzVGFhdzAwdUt4aUc5cXdZZmU2?=
 =?utf-8?B?THhaY3k3NlBMYllkZU53VjlTS0NrN1NxZDduYmR2Y0l2azF3OEZlVzFUV1dY?=
 =?utf-8?B?NWlFK253SFB6YURWMjl6d2ZvSFAveEovYVd6bVZoUEZKNld1TjNoSjVLb2ww?=
 =?utf-8?B?aTltUk53dHlCNCtlV3hmcStRTEJNR2srajRYU21hRHBCeDlERjdXTkh3SjRZ?=
 =?utf-8?B?QmFsaTRrZFdHMkZRb2dmc1JWYTk1S3pIR2JaZ3pTRUo3TGxpT0NmTE1HMFIx?=
 =?utf-8?B?NTdDK214S2J4UTl0UjRkNm1rZENtU291d21BMlZOTWl2VUxFUWI0OHN0Mkpu?=
 =?utf-8?B?eVdzclJ2UXoyOU5jUDhzQWJlbXE0VDdnd3hLbys2dzJIZUYxWjRtSTlCT0l2?=
 =?utf-8?B?NnRWSDlYZGk2TmNVQUk5WWswY0RXZm9MZkI2K0pNanFDbUhjSTdpb0xSL1NP?=
 =?utf-8?B?blVIZEJBeGZ5c25sK0s1dTltSGNjeXJhZ1JTcGVWMVd4VDd6b2YxaTlTZmZn?=
 =?utf-8?B?a1ZJQ1prak4yMHFFMStlb2I5VkhJSVB0a3FMY1pCMk1HaTRVbldMdHF0cGVF?=
 =?utf-8?B?NWFhVlQwWHVZZFV6cm85SE10UU80R1JsRmk3dHNRZFN1dk91T0dyTGwrNTJL?=
 =?utf-8?B?ZytYNVE3dUlrMUYrTWVDZmxRSURPQ3o5MHdZZmwwbEdHYUREaURVRGc2Qkdt?=
 =?utf-8?B?ZzhMNi96ZGNoQ2JzTEFnZFhwdFI2RmRXSjV5REJDZ2xxWlNUVnlFamZQNnla?=
 =?utf-8?B?bnZJMi9TZHZTUzJsUkFGVUx4dE1xN25SZjE2ZTNnREw2aVdtZk0zQTF0ZkE4?=
 =?utf-8?B?cm5OOGVwdG1XV0ZnUld2WEk5cEFWSm1kUXB3eGt1djc0MU4rY0pBbERNYjdK?=
 =?utf-8?B?NmgxYm5TSmhqczhNVUplKzNVUi9Za25kbVBxQjJWUWVuSURQZlVrQjE1eGxr?=
 =?utf-8?B?R2lndFRNWGcwemhsNk9zQm45NDVCSVZKbThVdmVKalJRMCtQVFBCYWxTRWt5?=
 =?utf-8?B?MHM2ZGJoRFdEMnA2SzFZR1owWnppYkV2MXoySU5FTFkrc2xCanR1MXhTL3FY?=
 =?utf-8?B?VmZHT1k2N2xvWmVpY29PRXBLZk1jbTBoQm1yK0trS1VLZUZTSG1zcXVJLzNQ?=
 =?utf-8?B?SytPdkJZVG9jdXpOY1NOZ2t5YlZaTXREdURoS245STk0Y2d3UlgvQjZFNHR0?=
 =?utf-8?Q?6KhmexRlaGbr1ucqB2QJYrUS2skTppb1KLzyT?=
X-MS-Exchange-CrossTenant-Network-Message-Id: d58722b2-f60f-4817-c2fa-08de538d5974
X-MS-Exchange-CrossTenant-AuthSource: BL0PR11MB3282.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Jan 2026 16:52:49.1768
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 9r+5jP7RibuNEyfhLC0dRVFm055de6mHaU9qrhLNuuWTQZheleu+fF22e8a1aiYbbK8b77jCnhZZfYn9XTAWkJ87kGpbgYn9SACL4Sxedso=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR11MB5263
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HRMlMSKH;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.8 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2026-01-13 at 02:21:22 +0100, Andrey Konovalov wrote:
>On Mon, Jan 12, 2026 at 6:28=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
...
>>
>>         /*
>> -        * For Generic KASAN, kasan_mem_to_shadow() uses the logical rig=
ht shift
>> +        * For Generic KASAN and Software Tag-Based mode on the x86
>> +        * architecture, kasan_mem_to_shadow() uses the logical right sh=
ift
>>          * and never overflows with the chosen KASAN_SHADOW_OFFSET value=
s (on
>>          * both x86 and arm64). Thus, the possible shadow addresses (eve=
n for
>>          * bogus pointers) belong to a single contiguous region that is =
the
>>          * result of kasan_mem_to_shadow() applied to the whole address =
space.
>>          */
>> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC) || IS_ENABLED(CONFIG_X86_64=
)) {
>
>Not a functionality but just a code organization related concern:
>
>Here, we embed the CONFIG_X86_64 special case in the core KASAN code,
>but the __kasan_mem_to_shadow definition to use the logical shift
>exists in the x86-64 arch code, and it just copy-pastes one of the
>cases from the core kasan_mem_to_shadow definition.
>
>Should we just move the x86-64 special case to the core KASAN code too
>then? I.e., change the kasan_mem_to_shadow definition in
>include/linux/kasan.h to check for IS_ENABLED(CONFIG_X86_64)).
>
>And we could also add a comment there explaining how using the logical
>shift for SW_TAGS benefits some architectures (just arm64 for now, but
>riscv in the future as well). And put your comment about why it's not
>worth it for x86 there as well.
>
>I don't have a strong preference, just an idea.
>
>Any thoughts?

I'm a fan of trying to keep as much arch code in the arch directories.

How about before putting a call here instead like:

	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
			return;
	}

	arch_kasan_non_canonical_hook()
There would be the generic non-arch part above (and anything shared that mi=
ght
make sense here in the future) and all the arch related code would be hidde=
n in
the per-arch helper.

So then we could move the part below:
	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_ARM64)) {
		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0xFFULL << 56)) ||
		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
			return;
	}
to /arch/arm64.

For x86 we'd need to duplicate the generic part into
arch_kasan_non_canonical_hook() call in /arch/x86. That seems quiet tidy to=
 me,
granted the duplication isn't great but it would keep the non-arch part as
shared as possible. What do you think?

>
>>                 if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0=
ULL)) ||
>>                     addr > (unsigned long)kasan_mem_to_shadow((void *)(~=
0ULL)))
>>                         return;
>
>There's also a comment lower in the function that needs to be updated
>to mention Software Tag-Based mode on arm64 specifically.

Okay, I'll add that in

>
>
>
>
>> --
>> 2.52.0
>>
>>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WfDiNl9-9bVrc7U%40wieczorr-mobl1.localdomain.
