Return-Path: <kasan-dev+bncBCMMDDFSWYCBBHUJ7W6QMGQE72HJCHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 91D3FA466D6
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 17:43:13 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-308fefb2bd0sf97121fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 08:43:13 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740588192; x=1741192992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QBrFlw8KfVDTmmn0jI/yO2rNWUQ+B8gZ6T3tnQhRduc=;
        b=uhTBo6B7N2AhE84d06si5AdkwiKtZQ8HNcnt9b5mu/WMrgFA/OaCEuIIS4Gp9m3YEx
         QVPU6kTRcRyMZHv6BgMnTHoM2N5jCjNKyMZIl71jyQTf4eV2+aF4tO5bQvPYcHQpSzXa
         BzfRBjtcGa2DKtFHzk3PlBjA7Cm/Ze/+hz0ZaBGiOiNSI31jQPIm2MtpWiY2aQXQpKFP
         elqlPYFvLm00nUnvwN4afc13qlszNL3vYdOSZFOoBVR5ejAg9R+ETrQAoL9PYuQ165Jh
         ezAUXE8cabnANh+fyHtxaX7ejgRFYEqgf9OVtG+iWDTud2PbAgFYwPJ+LYN9wQDwtYHZ
         aAtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740588192; x=1741192992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QBrFlw8KfVDTmmn0jI/yO2rNWUQ+B8gZ6T3tnQhRduc=;
        b=kmcoFpbexeadrv5GLSHKJCJyT0LTCogXP2z7RK4KgO4Wvnya6nKjYlIADChts8Qk7F
         cAVtWtbgSXnN2kdres6Jx9Ozfl7zK1QKCEHiIR12AjsBM0MElOM+VeqmlreIprGOR+XC
         yMPi+RmGG4ZYR+QqZ2AwQdjhBVYppk/spZ4tQS/tqH+Kp4xM/pSpYFE/MwPFrHFvWQLN
         YwxgDtzWEzsGV6EiYoCm2M1/ytHn9ifQSYiEpXWF0QAbtS6eZVVfh3RTSFoYPndPiD7H
         tCq/WMf9PCQii7CwSKBCQLUS68LxhcPCuQtq9eLchRB3fSBn8NKRXdpBnWkR2m2skfmd
         bQog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTlGmg7GgHJM/D9DUfjXXt6YzhQmnZN4rZNkV9h5cYN7zUXIjy9PnP94lRYUgp56piwJROyw==@lfdr.de
X-Gm-Message-State: AOJu0YzvJNSwKXzCtpJg5MuFeKWC8u4vMNYqh4kiBxyWKyD5pGOkgY7L
	fHZmg28KKLrJwdtDYASYynTbnsYGBrpo/r5bD13zYxszYzQGnwpI
X-Google-Smtp-Source: AGHT+IGyAXtYbHq8gn0Qm0cHHE5ot6mZPqOo1OdGmv60qtfugvqK5MkklG2P429eiXMAxx6fLXLFmw==
X-Received: by 2002:a2e:9bd2:0:b0:308:f4cc:952e with SMTP id 38308e7fff4ca-30b79163e4dmr29035201fa.11.1740588191047;
        Wed, 26 Feb 2025 08:43:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGLG4B6EJeE3X2YVY28IJoQvdJZ2QljQWNh7e7+oRBKPg==
Received: by 2002:a2e:bc0e:0:b0:30a:37db:444f with SMTP id 38308e7fff4ca-30b79ddcc43ls949171fa.2.-pod-prod-09-eu;
 Wed, 26 Feb 2025 08:43:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU1CiImuRkYesPRcGyvNQrNZHH4pdgfGNPrUWokOuf5s6mMu0SU4FXnwNGpcEXrMpesX5ZGPPydHy4=@googlegroups.com
X-Received: by 2002:a2e:a28f:0:b0:308:eb58:6580 with SMTP id 38308e7fff4ca-30b792e98a1mr27056571fa.33.1740588188517;
        Wed, 26 Feb 2025 08:43:08 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30a81a2dcc9si1264151fa.4.2025.02.26.08.43.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 26 Feb 2025 08:43:08 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.12 as permitted sender) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: 5F5z+xMITx+ugH/oAkS4HQ==
X-CSE-MsgGUID: AXD9b6mMTGCs4/93tyGbCQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11357"; a="45358332"
X-IronPort-AV: E=Sophos;i="6.13,317,1732608000"; 
   d="scan'208";a="45358332"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Feb 2025 08:43:05 -0800
X-CSE-ConnectionGUID: HOP3DFL0TxmdptOvJqrkQw==
X-CSE-MsgGUID: Fj7o3xGtSE2di5qBYjuIzg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147673486"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by fmviesa001.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Feb 2025 08:43:04 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Wed, 26 Feb 2025 08:43:03 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Wed, 26 Feb 2025 08:43:03 -0800
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.40) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Wed, 26 Feb 2025 08:43:02 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=OLVGRdG/sxd7Go8E0dIQVKc4YZjjvaJVFamdlU41gUFv9ssQmFPdP9HgDPF4zIHeoaGjYksSFQ2yRKJQUOdw47/sOwKP15vMbUrhCtkG68FsjExevpQrHxfQal4AAzqb8Uo84/J+PnmpgehFmvU4nOAR3AI1oQ4v6rkdPrVHXhtkBGcC5/7zVBTcs3m5LJAtmXQ/3X79FvpIJQ3fet7OV8LH1RMs9jfWzTqwLTczrwsP5ra/FZtKU+bM+3XAuwZzBCEI6wT+XBZa3FuDV/rmJcIZRgHX22fOxGOGap/LjLIaSJ0XnZPCp3gnUzkw5Sz4WL90TmxvgPiz9nfSTheolQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dLIcEwz1cYEXVv+Z1t+YhrwjlkT01+yxfGT8JGTBVMA=;
 b=AnLUH9bX1EzXSg8QJd6I4HPzCrJLqoJ+svD4mcvlPPMChT88Qr400SdhgcJwbjcc8CnuOLL1CdXj4s/0w0f/G8ElKezm+daE8lL1m1v0cVzDLLbz6Z2Nr4z6nGoRSXzf8kGS0Y89dwdkJs3y391TP5UunDVhyoZReTl+2Fs/38aLfw25HsiNcz4Q3vuaM/IKRJr80M8z0LlEefFSA2uUje5jCJr87w1IVJZNI60JScO0a6d3xr59WzTTeAqVgqNbT3t8uIjE/juSy6q6dSWQ2uRAtznLz1E8qHZoyCAwse6hY9yk2Z6OxrKizjLnhUvKgRVVpQ1cUchfqDivX15+aw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by MW4PR11MB5773.namprd11.prod.outlook.com (2603:10b6:303:180::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.20; Wed, 26 Feb
 2025 16:42:58 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8489.018; Wed, 26 Feb 2025
 16:42:58 +0000
Date: Wed, 26 Feb 2025 17:42:18 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Vitaly Buka <vitalybuka@google.com>, <kees@kernel.org>,
	<julian.stecklina@cyberus-technology.de>, <kevinloughlin@google.com>,
	<peterz@infradead.org>, <tglx@linutronix.de>, <justinstitt@google.com>,
	<catalin.marinas@arm.com>, <wangkefeng.wang@huawei.com>, <bhe@redhat.com>,
	<ryabinin.a.a@gmail.com>, <kirill.shutemov@linux.intel.com>,
	<will@kernel.org>, <ardb@kernel.org>, <jason.andryuk@amd.com>,
	<dave.hansen@linux.intel.com>, <pasha.tatashin@soleen.com>,
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
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow
 computation
Message-ID: <qnxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd@czthvwkdvo3v>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
 <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
 <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com>
X-ClientProxiedBy: DU7P191CA0026.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:10:54e::6) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|MW4PR11MB5773:EE_
X-MS-Office365-Filtering-Correlation-Id: 8528ab9d-ec3f-4fec-b5cb-08dd5684a065
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?TFJOeXZMMjErU2pqNkl3cHVaMjdLeEtqRVZ5czFVeVRBdHA2QWM3dXlVcktQ?=
 =?utf-8?B?Z3hCLzdlMjRySVoxaTh5RmNBVmpRQk5tRENVbEN6NmFiN0xzajlwVVJvUDM3?=
 =?utf-8?B?TEl3VzZHTVJTOExhU0UzYkhTbU9nMGl6L1NDYWRFL3owUFlLYk5rSzMxQ0FV?=
 =?utf-8?B?L3JyeDZtREpLYmdWRS9EZEU3cFhBMW41MjBrbUxIbzVWTlJWbnRpbG5PQm1H?=
 =?utf-8?B?d05UdmZIQlllbTZ6b2dXNGhoMHdkOCtnNmlrWWVoTjhORHNBZzdpdFJYMzR6?=
 =?utf-8?B?UnNQVlo1bTd1eTN1WGVKcXdIREYwMS9RNk5VS3g5RVJYV2FkMUpIWTdSbklw?=
 =?utf-8?B?dHoyL1V4QUYwSDVOcUphNjFUQnVIQ0xSOEYrL1lRcE1BT085TEdjMkZ6c0tt?=
 =?utf-8?B?SkZCZ2s5TjdSQ29YMUtDbHpuRytmdFNVdlNEekNuNEJCd09UaHlRVzBRb0Ru?=
 =?utf-8?B?azQ5WkExVWhyaCtvQ1NySG1aTjc1WENsOGVTTjBSbnBMZXY3S3psUDh3RmNY?=
 =?utf-8?B?dHZlVFRDb1d0dlkza0NORnN5TzlVZlJPUWRIMnp6bmpidTNBS1EyRlZOSklY?=
 =?utf-8?B?UzBSZDFoVEJyNkMxbmQyV3FEQm03OWRmcXJIOXNnZVE3bkRFUFZtc2VMUTkw?=
 =?utf-8?B?WXBoYWd1QzRFalFjZ0ozKzNSNXdvTU5RT3QzdVE5aDhrQlFPelZPVmc0QUdU?=
 =?utf-8?B?SkpCOUVUako3RytVeTg4Y0pkVktoRkF5ekpTd1dudys5ZUh1enJOaTRLUUtl?=
 =?utf-8?B?bk1HRVBlREN3cUlUeVYyREFxUXZxZG5YN05RU3Fsais4N2dudlVHQWY3N3J5?=
 =?utf-8?B?V3NWSnFodExMOFc5QmE5RzhpUlVOa1RGQzAzNWdQRWdjajBsNFRqZ3lLdUpu?=
 =?utf-8?B?OEs2SDRPWmQ1Tm04RDAvbEZaRnNTZFQ1KzFJZS80Y0hMYWcyeFU1MGtrSXor?=
 =?utf-8?B?bnc3anRTd1hTRXNWdzhDUGFRMElZRmlQT0xuRDRodmh6Z09OUmlSV1FRbHdE?=
 =?utf-8?B?bnR2cTFYTCtiUW1QdmxZaFowbWZBTTErUGNFZlFqbDJraGRLcGpUODFyOTRs?=
 =?utf-8?B?VG1pM3l0bFFjV2RoTXpYemxReU5GRmliR3IxbDNyNkVPdzhvM0NQTzZLdmhh?=
 =?utf-8?B?VENGaDNMNENDRGl4VXdaNTFpYmdjZVNhWTRhOUF2NE1EZitxZmJMcTliQ0cx?=
 =?utf-8?B?L0pjMVhYWmkvd0dEdGcyZXdMcWNqS3JBdnZod1JGT3NKc1czeExkcnBEc1FS?=
 =?utf-8?B?RVBid1Rid21QVDRVZHRFRFhKWDdMS0pzbEZKMGl6NklRMGQ5SGpzZTgzOW9Q?=
 =?utf-8?B?WjcwWGI4UkkvYktHbkNaKzlEYjduUHJWMjN1dGtFU01OeUZqRXJMTTZuUHRm?=
 =?utf-8?B?dnl3c3FQTDJsemY4cWRQSGVHZ3lhTVlpUk94eGRFbHRNandYcGZDYitsQk10?=
 =?utf-8?B?clQ2TXdhdy9Pd0xrU3ZiVnVEKzVHT0FpSjQwS2tRY1N4VWYySkR3bHI0Tm0r?=
 =?utf-8?B?ZTlUVEJJS2RTUHdVbTZ0OHpCbWxsbzVhUVdqQkVCWHdWOEhBdzBxTHlYZXdj?=
 =?utf-8?B?Q0JQclFRUjZqYTJ0L3RnN2dDVHFSeVJFbnFDZzkrdFNHRGpFUXBseDVaWWRo?=
 =?utf-8?B?UkJnTXYybk1pU2lNYnN2V0NTVFEvdFBRQW9PRnJpdVc3dGo3ckVYT3M4WWd5?=
 =?utf-8?B?SFh0WUF5M25taC8xemxPNGVSZmFlTDIzd1JkK1o4cUtjREREcU1GN24wVEVi?=
 =?utf-8?B?OWxMUlBwWG9SdU5rUVc3c05SMkpEREdzWlI0aFdCZlNpVHBjaDBUMklIbm5N?=
 =?utf-8?B?cHlpSEJFV0IvSUs3RnZKdz09?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?MTFiOGVaWk9oYjd3QWxYZWVyei9jWEpwdlpSalIxYWFrUmltZ0drY1lPeklj?=
 =?utf-8?B?SHIxcmdjSGl2YXJaTXVxcGlXZHlwWFAzaTNnNXNCdnlrR1ZNcXdxUmxHR2tX?=
 =?utf-8?B?MkVUTXlaalZSb1JySlJTc05YQ2NRTEE5MHJsaGswTS9LWXRjQVRZNTNFK2NW?=
 =?utf-8?B?Y1I1VVh0dkNmRVk2RGlRY2tDOTlKOVdNZFFVSGluUHAxUmtsMGJQV1QrSjFX?=
 =?utf-8?B?MWM1a3MxQjg3dXBRSkdzWG1JZWd5eUl3dVJtUWFyZVlZYU9sK3VkYlcyckg0?=
 =?utf-8?B?dStWelRWcFFCT0UrdStVWEhSNnI1OXFnQUwzYnl3TzRQTXpjRk1jU1hhdjdl?=
 =?utf-8?B?aVd6VzBRM21hdnQ5cmNMWEkxRjVuQUdsdjBXeHpkQmVkd3EvelBCalU3NzdE?=
 =?utf-8?B?K0RqcG4rbU16TzNXdmJYT3pjajlDOWJ3OU5CdmpldHRwYktadjV5NkhMaVhN?=
 =?utf-8?B?L0ttL0ZXd2ZSY2dqalZZaG00WS9CNWtPTFhlZUE5Um1SVWRrVGhoWTZJQ2ND?=
 =?utf-8?B?dmJhV1hBc25HK29OWjY2d1dsSkZudUNEQktFK0hNZkI3VVkvS2lMMWNjblRI?=
 =?utf-8?B?eENrOVBmYTNqd2NFcHNvcllnUXFsd0tPZUVBZEpUQmtzRzREeEZKYzdDWGJK?=
 =?utf-8?B?c2FTdHlMVWNBQm5TalZ1cVVPU1pxbTlwcndaTVgralczWEtLL1lsWFNBc00v?=
 =?utf-8?B?SDB4NVA4SEpWNnRTaXN3ZnlrdkVRRmR6b091RzBRalZZRjJoV2Jrc1hERlYz?=
 =?utf-8?B?aGMzd0pmVzkvZzFSQVZmamRQTHRMN0dGVTdUdFUwaERUOGNMWEhOQ2NoZ3hN?=
 =?utf-8?B?OFl1UmpQY2lrbHBZejZFTlRiY3U3UmVlbmUwSXBkRFB5dUxtaGFrZ21FaDlB?=
 =?utf-8?B?dVBVL3FHT0tleU02akgwZ1ptbWlUMWxXbm91OStRRnhBb1lyTTUwNUxpeGln?=
 =?utf-8?B?cElpNGRyeEdWY0lZdlpDS3JEZVBRYXI5M2VBR3VUYXlWUHVoYTlkWCtjaWhL?=
 =?utf-8?B?Vkh5YmVvcmJwSWxLd09WSjlFcm11QVRpWGhtYjNBSVVjUmdGQ1o4N2JRMncr?=
 =?utf-8?B?RCttOVZMUzJyaEhRbFZoRDNpUlJKeENRQmdlSkVudXVwV09RNmdmTnhFOVEw?=
 =?utf-8?B?YlF1SGZWRFdtb1B3NThlc1RsZlJ4eUg3dTBXb29OeVhzWkdLMjI4a0QxejJP?=
 =?utf-8?B?Nk05TFZyYS9vUGdjMTErYWhwWTVLRzNIUGFuYUxnT0I2dlQyaDJjN1dzczA3?=
 =?utf-8?B?bDVPand5Y1lEWDB1VDFDSUNFZVdIa3gyTEFHdm9RTGp6bitBZmJraGRpNFN1?=
 =?utf-8?B?VFRwTngvNFlkVGlHNkxjU29zSHJ2T2RGNU1QcHhOU0oySkc1elJKRXBRUEl5?=
 =?utf-8?B?bnRxR2oxYUEwaURCREJIRW1MKzR6ZFB2bWtaNkovNDZFNjNXa3NOdG1HZmdI?=
 =?utf-8?B?M3YxdEhxOWhiRTEzU1NYRGVHcG54ZnhGb2ZSdHc5OVoyMkl3ejNOekZsWTVS?=
 =?utf-8?B?a1o0b0VsVWc5aWU4a0wxSGkxeGRjSmZVSEJXWjNXbktEdmpua0U1MlE2a3lK?=
 =?utf-8?B?OUNybGlLQmI2VXQzTlNzUitzeGFEdVk0NW40S0ZTeVBhZWExQWRVWSsxbFRQ?=
 =?utf-8?B?d2xwaWxLaTg5Q0FkOHc0L0Urc2s2bnBheHhyWXNTcVZsM2FWQ01CUmtKbEI3?=
 =?utf-8?B?c1pWRFl2aEJ6bFBhQUorOWNxVW5SUnhYRk12RTF1OWZ6WisxdEFoamhLVTRT?=
 =?utf-8?B?eTZJZTU0MjJqWEtUNzRwdzNEK3Q5UWN2N3BLNFlhcndwakw3aTFBdUY0SnZ5?=
 =?utf-8?B?MjNuQ0ZFY1ZDUHlCNzY5cTc1NnFzcExtUjFrRXZDMGRvbk95S29BV0w5ZEN4?=
 =?utf-8?B?andaaEpibDV2UUxvNUQwdTl4WUhQRExWdFlhdWtUWHJ6OW9WM1ptUE5acWht?=
 =?utf-8?B?VHFLbWh4RUdLM3RodWZBMEFtbklrODVJb0t3ck5XbnhWdlgrR3c2b29lSVZR?=
 =?utf-8?B?cGNBKzlhVnN3NDNxWk9nV2RZRkoyZG5MRXFzbHhKWHUzeFAyZGcybUJqYUhk?=
 =?utf-8?B?MWdSWkh3TWZLbE01QXJRaHFjNU40UkJLWUplaFRUSUlkTzhmSHYrVjZHcjQx?=
 =?utf-8?B?ZExpTWhoWWowR3pCUmpGdlp3VGlKVlVoYnM4WjdyWFk2WFg0TWZ2UHlDd3c4?=
 =?utf-8?Q?7qX0GMQLelO72p48/UC6C6g=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 8528ab9d-ec3f-4fec-b5cb-08dd5684a065
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Feb 2025 16:42:58.5304
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xT5Y0wDm089wxqx6KA7Z/nzo2BD6qS+wWKZT0nRYrW1YZ7hUhoxxEv/QmcujIVsYNzmw4b/8lociRtQvBZQgp3DaXpivgktYnCtdMGyfva0=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR11MB5773
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="Zmc/tFv4";       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.12 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-25 at 22:38:06 +0100, Andrey Konovalov wrote:
>On Tue, Feb 25, 2025 at 9:13=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> >>Thanks for letting me know about the tag resets, that should make chan=
ging the
>> >>check in kasan_non_canonical_hook() easier.
>> >
>> >Ah, but the [0xff00000000000000, 0xffffffffffffffff] won't be true for =
x86
>> >right? Here the tag reset function only resets bits 60:57. So I presume
>> >[0x3e00000000000000, 0xffffffffffffffff] would be the range?
>>
>> Sorry, brain freeze, I meant [0x1e00000000000000, 0xffffffffffffffff]
>
>+Vitaly, who implemented [1]
>
>Ah, so when the compiler calculates the shadow memory address on x86,
>it does | 0x7E (=3D=3D 0x3F << 1) [2] for when CompileKernel =3D=3D true,
>because LAM uses bits [62:57], I see.

Thanks for the links, now I see what you meant.

>
>What value can bit 63 and take for _valid kernel_ pointers (on which
>KASAN is intended to operate)? If it is always 1, we could arguably
>change the compiler to do | 0xFE for CompileKernel. Which would leave
>us with only one region to check: [0xfe00000000000000,
>0xffffffffffffffff]. But I don't know whether changing the compiler
>makes sense: it technically does as instructed by the LAM spec.
>(Vitaly, any thoughts? For context: we are discussing how to check
>whether a pointer can be a result of a memory-to-shadow mapping
>applied to a potentially invalid pointer in kernel HWASAN.)

With LAM, valid pointers need to have bits 63 and 56 equal for 5 level pagi=
ng
and bits 63 and 47 equal for 4 level paging. Both set for kernel addresses =
and
both clear for user addresses.

>With the way the compiler works right now, for the perfectly precise
>check, I think we need to check 2 ranges: [0xfe00000000000000,
>0xffffffffffffffff] for when bit 63 is set (of a potentially-invalid
>pointer to which memory-to-shadow mapping is to be applied) and
>[0x7e00000000000000, 0x7fffffffffffffff] for when bit 63 is reset. Bit
>56 ranges through [0, 1] in both cases.
>
>However, in these patches, you use only bits [60:57]. The compiler is
>not aware of this, so it still sets bits [62:57], and we end up with
>the same two ranges. But in the KASAN code, you only set bits [60:57],
>and thus we can end up with 8 potential ranges (2 possible values for
>each of the top 3 bits), which gets complicated. So checking only one
>range that covers all of them seems to be reasonable for simplicity
>even though not entirely precise. And yes, [0x1e00000000000000,
>0xffffffffffffffff] looks like the what we need.

Aren't the 2 ranges you mentioned in the previous paragraph still valid, no
matter what bits the __tag_set() function uses? I mean bits 62:57 are still
reset by the compiler so bits 62:61 still won't matter. For example address=
es
0x1e00000000000000 and 0x3e00000000000000 will resolve to the same thing af=
ter
the compiler is done with them right?

>
>[1] https://github.com/llvm/llvm-project/commit/cb6099ba43b9262a317083858a=
29fd31af7efa5c
>[2] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tra=
nsforms/Instrumentation/HWAddressSanitizer.cpp#L1259

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/q=
nxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd%40czthvwkdvo3v.
