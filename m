Return-Path: <kasan-dev+bncBCMMDDFSWYCBBYUSU7BAMGQETONCPSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9577FAD5E0A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jun 2025 20:22:28 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3ddf66427f8sf2449745ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jun 2025 11:22:28 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1749666147; x=1750270947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JCv7TbRtV/LvcP2YKiGOgVnumiL0nz4HYv1zgWX9Qm0=;
        b=nGeDr7avyl79ypXBsEV0wue8IqrGfXAiuIBhfo7duNAjnCkT7z9k6uq5NX0Ux+kvjl
         2n4teLGcbCNl1jxh0pLVybrvtBSQx7oO2ZmI6Se4rkN6vuDvLA3OlLGWc7pp+8EgBxps
         5dt+gQM1ygVtue8wVJ9yEaMEfetTmi0w0K/b+EuGphKFGPBhmmwLBfaGMEkRln7wph+s
         9+wJgCcpQSixpA+6Ha/RqAtj9VoOoTcO+7KTDvVW91f8RQOg6+EO+5I4ioSgWKT4wzYL
         neo7RY9nopb1wzsN5vOBH/zXBocehTLo3dGvKlk448g3awoAJkA1pgKteFQXA6FdXbfC
         ZK5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749666147; x=1750270947;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JCv7TbRtV/LvcP2YKiGOgVnumiL0nz4HYv1zgWX9Qm0=;
        b=f10pQojqQFvmGsLcF88wy5Dj7G05Izg64EJ/4lBHOaXHaXYtC0x/BaKJe2u9u7xmW2
         oxKBg9IGadfIZ/c+yp4AY3kB1M32pC1Flu07ODPI9Zo0jI1tdLDCP3XFdrHEFbnqtd3S
         BMYt6ppPUTOZrWDefL9xD4N65f33EOImC16LoG/9tB92dtXN5Nq97AvSBn2DuVZR2L8B
         nntOTaehkV5JUi62YRdTMb8Ro8/OEuw4WRKbryt4lIj3ZvXwSx/RkqMv5zlKFfo2QCxB
         vxXgy04XVWdmw/TW7odemGjIe3e9QiIq/VPgJ7XD0dEwR4YPvcPomdtcR4K12Qo0SvQH
         ORmw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVmPRmP30obvVJnpCcpLd2AlIsEQVWl5OupACihpZmTtWjGOKrK0Spo4c78RkyYpCIEGQTVyg==@lfdr.de
X-Gm-Message-State: AOJu0YyUqj2IdthKrAoIGEaEx4X3/5rwCA9zdqgwExtSNurFU6z7dd7L
	12/2kWgqdZub9Oi76kNtm0D9ypdnH9kIBsvViJ3ycZQZA5lkht6rMb/C
X-Google-Smtp-Source: AGHT+IEnTBsynfdr5z8mrkvDZs6EmFBDhnW1btgaKOIRK/BCllp86hZd7T8uPQIzIFo2H35k8OEq/w==
X-Received: by 2002:a05:6e02:b44:b0:3dc:8bb8:28bf with SMTP id e9e14a558f8ab-3ddf4256fbcmr57307255ab.5.1749666146755;
        Wed, 11 Jun 2025 11:22:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfDx4Q7FimP33+q3E+69i7hrgxNtepeIyfgxPijuLuTWQ==
Received: by 2002:a92:cb0c:0:b0:3dd:be02:1858 with SMTP id e9e14a558f8ab-3ddc65185b0ls40423825ab.2.-pod-prod-08-us;
 Wed, 11 Jun 2025 11:22:25 -0700 (PDT)
X-Received: by 2002:a05:6e02:1549:b0:3dd:b808:be74 with SMTP id e9e14a558f8ab-3ddf42fecd0mr48485715ab.13.1749666145421;
        Wed, 11 Jun 2025 11:22:25 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5012aa77372si100728173.4.2025.06.11.11.22.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Jun 2025 11:22:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: vyUI18p5RLu1taNFLBsL6Q==
X-CSE-MsgGUID: +/wrS9CZQiqPkT7cpWXbBw==
X-IronPort-AV: E=McAfee;i="6800,10657,11461"; a="63230211"
X-IronPort-AV: E=Sophos;i="6.16,228,1744095600"; 
   d="scan'208";a="63230211"
Received: from orviesa002.jf.intel.com ([10.64.159.142])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jun 2025 11:22:24 -0700
X-CSE-ConnectionGUID: PFPa6L8BQ+Wy6Q7VO9jd1w==
X-CSE-MsgGUID: XWyXaZ7jSPyyoY5x1eKX/g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,228,1744095600"; 
   d="scan'208";a="178184005"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by orviesa002.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jun 2025 11:22:25 -0700
Received: from ORSMSX902.amr.corp.intel.com (10.22.229.24) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25; Wed, 11 Jun 2025 11:22:23 -0700
Received: from ORSEDG902.ED.cps.intel.com (10.7.248.12) by
 ORSMSX902.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25 via Frontend Transport; Wed, 11 Jun 2025 11:22:23 -0700
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (40.107.95.66) by
 edgegateway.intel.com (134.134.137.112) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25; Wed, 11 Jun 2025 11:22:23 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=kA6l+qXWx1ooY4W9BJmrbpeplMD8PZuZVHii8owFhK86KLW4MsNze/mAZjOOaNG6Nx/1Q2vu0dcyoNdG9F277IS7fTRW/H9zdCjB0YoRi8Ong8ueGtUnp0JQGGz8PrMO8fo2v/5lJb1V1dopTCWjzuyJajkvbbAfZW/sg0MdBFR/hEDCifI575YzSIF7gQvQjbdywQHDDzqBbfPWsmlaYcfWV7VnqJqkg3WZ3RpkuBr5l9OVJb643CeMGwloSROkSrhnCoH0aZWgsjuvPexZeg5g7DGR4O+FpQCSIbJ+jNwMhBxvrNYDUZEgem80zHOTTRm4YGyNz755HxeSqa8eAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3z9YamaaWwn7qBoML8jb1qQe8J1YMfc8wIFTCkaTlNc=;
 b=m9ex7qMj39uONnm1IdRWy+ih0Me14Z624EBmTYpK15/pQoIRxFHh1hPXbyMjBy2P1HEra/lL/1qcFDnslgGmLvmhbC9oOanMiRvKwSgjrBAkkQvxHMzEY/6/0TbOAZbap5KDVps0u4RKNx/ddZpVNoXYclkckUkI+Q8uJ/zVveSVsOhrWQ38dbVnlTc4mUSheqAMKkKuP1ZkvtKwi6KOnlHmFzbDKwqcgbW4OABK+mtfrzMFgWC3OFfPdrGtPwP5zgci8H0Mmw6XmilD/LG1pP0EeoWXznGk0j+WcUhcTRyjRTGqZpfROtbsvT/+otdCE2h+2gaM9cpZCl63bguZAQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by MW4PR11MB6689.namprd11.prod.outlook.com (2603:10b6:303:1e9::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8835.18; Wed, 11 Jun
 2025 18:22:21 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8835.018; Wed, 11 Jun 2025
 18:22:21 +0000
Date: Wed, 11 Jun 2025 20:22:16 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KASAN stack and inline
Message-ID: <mdzu3yp4jodhorwzz2lxxkg435nuwqmuv6l45hcex7ke6pa3wv@zj5awxiiiack>
References: <cwl647kdiutqnfxx7o2ii3c2ox5pe2pmcnznuc5d4oupyhw5sz@bfmpoc742awm>
 <CA+fCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX+b3L3WmV4tyMg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX+b3L3WmV4tyMg@mail.gmail.com>
X-ClientProxiedBy: DUZPR01CA0236.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:4b5::15) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|MW4PR11MB6689:EE_
X-MS-Office365-Filtering-Correlation-Id: ede904c2-7cdb-42f7-25a2-08dda914e7b8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?Vkh4RWp5K0hSMDV4REtaQnNMUk5wOTFtODgxdVRiZ3JndTdrbDNpcjR1VXNF?=
 =?utf-8?B?ZGVIVEJmWUNJSkF5OGFkSGpseEN1bjNYeTZpQmc3a1Zza00ydWFYbVNxVEVG?=
 =?utf-8?B?NXdaMityZGJwMXRXTGpqaWZ3ZWRVSS9IQ2xXS1NISmt2eG1QMkN3bEZTT3hi?=
 =?utf-8?B?bEluOGxEMjNUUUFtNnNQTDh1aitUWS95UDRPbFlhS1lWZktqem5HVjFrNjc2?=
 =?utf-8?B?ZmlLZktGcmE0QkFMVjRJdkdwY2thN1FDQXo2c3FzZTlFcW9obG9xUFRHbUwv?=
 =?utf-8?B?U3BCWlVWTWUzNnlTdUhuZXlwZk0xY1B2ZVlUNFl0bTBKd2l2UmRySXdHWGtN?=
 =?utf-8?B?ZjNodlVPbE5iYlhqSit6NmhYYW13QXFqcWxRczBRTUUxd2E1enNIWjJpK1VL?=
 =?utf-8?B?MnVtZkZuZWZiT2Q3b3MyYU1yTGc5R0dFcnBydVVaUGo0VkdENGZrMW03MUlO?=
 =?utf-8?B?RFl5RE1YQ2w5TXJXOHpBUXEvanFQUE9iSkFtaEgweTZ5WVZxMDJRLzN2TzJ1?=
 =?utf-8?B?cktzY1UzV0Z4YW9QcTRmd0YzRkQxVDJHc3lsOUJuNFRRc0RyNlVpTzIvMkov?=
 =?utf-8?B?eUZseEh5ZENYUEFOTzgwdi9DbVZramR2UW5WaFIrdUVNbzZ2aTFrWTZzaW9m?=
 =?utf-8?B?Q2IrV3hJbGJqWEo0ZFVTN1ZSdVEvSUw3ZXh2bTROZFFHd1lMeGppYVd1bFZM?=
 =?utf-8?B?d0k2bXg5d1BBeGlRWXNwRnJaMTB0UjdnNGFNU2Z5bDJQUGFuandoNTJIb1F0?=
 =?utf-8?B?c0V1bTA2Y3FpSy9mcTN0aHk2RDlIbmdzY1ZWTHlWWkVJS1YyYzg0T21vYzNu?=
 =?utf-8?B?MmtSbGZ4VHB3dXJzS0creHMvL3FoRHNpTzEzOWNwb3B1Y1Zvc1BBRDUrTzN6?=
 =?utf-8?B?RDE0czBraXVza0VJVm9VaDlFTEk3anl0THg2aXQ2NVlVSk9ELzRZNHM0cFNZ?=
 =?utf-8?B?RzNLWEhpOGFMWWVIQUJONDBGZkFKcjRUVGpqT0dMSnZGWFpkZkZXaFlDc0Vm?=
 =?utf-8?B?S2M4UUsyeHZPZEZjVUpnd1ZQRXBIdmNyZG1TMHc1NnA5WjFiM2dyS2VuZzdm?=
 =?utf-8?B?bzM0SkswQ1pyMHh6UlR5N2tteTdtbjdSSTYrWDhCczdjZWJPSXdlN2lOTzR5?=
 =?utf-8?B?OW13WmkvZnU5eGVOeUNDVWV2SzlyWUJyaTRDWG94VlZiQmJIOXFtK1F4cnVV?=
 =?utf-8?B?MHlZWG5rWHdTRkNScFlodHhlc2tkdGNKOHorWnM2dmpheGlUb2EwbU1qUHp2?=
 =?utf-8?B?bG9zVHQvMjhoWEdGZGhOeFFsQUNMR1FsTm9CUHE0bDZWUlBDUmRERkwySGFL?=
 =?utf-8?B?ZkNQd292OEd3UlYxTEVCWk9TTlg0Q2l6bUdPVitKUGRORktrWitJbzlJNGJR?=
 =?utf-8?B?d3lCUmNRS1dtb3IweGVIaURZd3NGN2JHTWFnRUQ0NjBDeWdReVJJYVlhdDRL?=
 =?utf-8?B?U1k3SlRoeUhEbUVCaEU4ZDZSaFlSQ1pxWEtKaFp6ZFh4azdsM2M1SG9BRXNY?=
 =?utf-8?B?eFJBSWM0ZjJuazdjY1B2d3BBUERDS1Ayenk0UEZNL3N4dEIxazEzdzF1Snl5?=
 =?utf-8?B?a2Q3czRCQ1VLejFmVnZaTHpkclFnV2FWenR2bU5SaUEvejRGWklFMW9UUU8x?=
 =?utf-8?B?a1dDWHUvQ2RFeXFTbDJkM1pBQWluT1gvcGRpSFBGM0p0UWZaNTZEZ2ErODNy?=
 =?utf-8?B?UGkrQnJNak4vOFlnNEhMSVJCdmxNVlpJcURLcktsRTVNZ0h4NHlGcTdRaVRh?=
 =?utf-8?B?dUJFMjMxTVowMm14OUhkZmpoaDEzR1lnSzlhOUdKVXhuanVURS82K0hBaE53?=
 =?utf-8?Q?rpn6W854B1YQT3/wTl4lFLWGbvVL6/OLbo/HM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?OFJJek9wc2FIRk80N2VUeVk0SWdpZUVwZ1VqRUV6dzBGRjFtYmhmM25NYVQw?=
 =?utf-8?B?SGh4a0cwT1ZDdHJIR3g3QllmdVFNUTZNNkg5ajh5TjlHeU5QUlFXQVBIbk54?=
 =?utf-8?B?c3FjS3dlVnlKQ2tmelE1Z1AraGt5OVRKdHpEK1d1WVRyUzh5VC8yT0poeS9Z?=
 =?utf-8?B?TGVMR28xM01lZWVxNElON3doUWNhYkdlZE9saU9xWEU4VUhIMmQ1Z1JJeTlC?=
 =?utf-8?B?RzV2eFZIeE5rblc0QWtQeDR1Y1Q0RGJ0S1BoVjJkWDAvRlRqZCtzVm50cDlp?=
 =?utf-8?B?a0lCa09RbVlYUit4emtOSGhLWkNGaVdaYlB1aEdkK1V5NTd5amxxVTZydFVQ?=
 =?utf-8?B?RDBxM21mRVlnd3ZKd3UxRnhjNkdHMXk0UUNhVDF1UnhBRFM4MHhXQzIzSlBP?=
 =?utf-8?B?NjVIdlpyWlc1VzVPdGZjdzNIRGdINlRILzZEdVRYbVdFYmNsbzFKZmdYeUl5?=
 =?utf-8?B?ZkdEK0p5dkZmZU4wcm1wUzlkZyt5UXlxRUJYWmJVejh4UnhiZEowWG5sTlNN?=
 =?utf-8?B?S2RoaVhhdVVtYnhPL0RTZzhlTG5KcVp6Y3BsdXFkcENIdWZMZHhrWTFXblha?=
 =?utf-8?B?czNXUXZ4Yzh3MnpGU2hrdHBScE01aXhraFZYamxYTHVSM3NFREJINGxaZTRZ?=
 =?utf-8?B?NUM0Qm1VREU5eXN4SlMycHo0MTBvbkdhUDY0MDcvdEd6MFdDK2tIbktKTHBK?=
 =?utf-8?B?WUZabm1WVWR4ZjZ2WmZYZVd1N3pERU5KeWcwWWh2aG9ZRitMbk1DNzhKdlcw?=
 =?utf-8?B?eGRMK2V1REVLMHQ3R2g1ekRsZkt4eFplNjJGaTRzbkJ4WTJ1cUxlRGZXYzBl?=
 =?utf-8?B?UEtwb0pRNjlubno4aHNZNmZvMW1zelRuUVBBTFNxSEszTjB6b1pFbnMraHl5?=
 =?utf-8?B?U0JwN3did0hzVnhiVGpLQ2d0TVVpRVhlMlJoZ0p5RkZUcElJNEF4OWhXSFBo?=
 =?utf-8?B?MTlDaXNFQ1BGQS9tZHllRGs2cnZXT0dWMVE1QlMvejZ2OThvRWJISHJGbGpR?=
 =?utf-8?B?S09Kb3p5NWJPeUtRWFdOV1VVbEhEcmgvQUNWTG9Lcy82TW5uQi9aemQrbllv?=
 =?utf-8?B?ZmkvaXpuSElqZ0ptQUtrYVZucFdnVU9LdkU0N3dhbTQ1b04xa0pmaVEzRC9h?=
 =?utf-8?B?aXo0L0dZbHRwUmdTdFZNZEp4TVBBamhWTkJNWEMySldJQm1qd1p2aHM5bDdi?=
 =?utf-8?B?M2ZreW83ZU1GNTdPQ05XTlNvS3FQTENZa2lPN3VXYWxJYUdTYi9GQlF3MHpu?=
 =?utf-8?B?dzVUWmFROEhmOTMyU2ZIZm1IT2RRU3hEWjNidUUxSitUTFpleXJncmw3di9I?=
 =?utf-8?B?YS9ET2VpdDVjUVV3ekpBUkRiR2w1cTN6cTFqUG1uMEk4Ym5aU3RyL1RuSGoz?=
 =?utf-8?B?NWhHckczcis2VUpGekcwa1Y1OW5BZE5xR3ZJWmUxdHRiSmQyR0tCNVF1MHJ2?=
 =?utf-8?B?SnBaZWF4UjJjMGdWL0VHYnRESzk2MmdIZmVLVFUwdFJ6MTdVS08rRFRkd1BW?=
 =?utf-8?B?VkMvc3BSVlpsVGw2Q05WcVpzYlBFUTFJK1pBTnpOYWFIV1B2dDhzb0Q4Qnlz?=
 =?utf-8?B?N0ZYK2oxWnptbWRWSnpER2VzakxmajRETkpITTNKWTNlb0hOYlQxNjhBY1dT?=
 =?utf-8?B?NnZzaGJZNkF5UTh2SitCSlFCWGR3YU9rNE1leEExc1B3TklNcm1DdEtUb0wz?=
 =?utf-8?B?SThISmh1dmlRNmVLNmRCeWw5Q1Z2R0Uxc1cwUWNQWTUyRHV3djJRUEhpZWxy?=
 =?utf-8?B?ekM5ei9UTTNSd1I5U1JMU1duMHhQbGpMeEFjbzZ0S3ZoSkJ4SzFaV042V3NV?=
 =?utf-8?B?TGFKa0oxcnVsa0ZMRFNpQlJFeldFNTI1TjZUNE9YUm05QW1kRnpENytuMHNo?=
 =?utf-8?B?ditVTDViMTNvL3dkV3MvWW1UU0lITTc5WHdkOW82bWZqVitZcWcyRnlCWWc5?=
 =?utf-8?B?UXZhbU5yckhhVWJZZU9RMW5IZk1zek4vcUdjOUF4UzhCaXh3R1orcGlPYXVZ?=
 =?utf-8?B?d0JOcHZGZHdxKzRNQmt4NUpSYkRiV2lzWjNsZkJaYklnS1RSQ2tyWEtWQlIz?=
 =?utf-8?B?SldGMDZmeEZHVDhxSDQ1a1ByeHhRZVNiL2MwMzgzdHFoZFVxNS95cGxLNW1j?=
 =?utf-8?B?TUl4RnFlSUNBZkRvZDRMVDV1ajFibGh0VkszNCtxWUQwZnl4a1o1RW5mUFlN?=
 =?utf-8?Q?bNs8n5KQ+anMoogzhf2gzMI=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: ede904c2-7cdb-42f7-25a2-08dda914e7b8
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Jun 2025 18:22:21.2630
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: UF4aVvRdUQtDbckQTX3hsmUCBRLVExcolwourM4HhRIQmM/wppJ3NrVWyXOc0QjCHl2XtE0kZ6SEFeog2fHVYh/xsrjFDwGASXOv3djUj30=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR11MB6689
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=K1lXgKNh;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.12 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-06-05 at 20:37:34 +0200, Andrey Konovalov wrote:
>On Tue, Jun 3, 2025 at 10:05=E2=80=AFAM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> Hi,
>> I'm still digging around in the x86 tag-based KASAN series and I'm somew=
hat
>> stuck fighting with llvm and KASAN_STACK / INLINE.
>>
>> Is KASAN_STACK supposed to work with LLVM? Are there any requirements (v=
ersion,
>> other configs) etc?
>>
>> I have odd issues with it, such as load_idt(&idt_descr) (which is just t=
he LIDT
>> instruction) inside idt_setup_early_handler() freezes the kernel. But wh=
en I try
>> to disassemble vmlinux with the llvm objdump there is no difference betw=
een
>> assemblies with enabled/disabled KASAN_STACK.
>>
>> Also is KASAN_INLINE required for KASAN_STACK? I saw some remarks about
>> KASAN_STACK doing inline things but I couldn't find many reading materia=
l on
>> KASAN_STACK on mailing archives or the internet.
>
>+kasan-dev

Hello!

>
>Hi Maciej,
>
>Yes, KASAN + KASAN_STACK should work with Clang/LLVM. At least for
>Generic mode and SW_TAGS mode on arm64.
>
>For example, syzbot enables both options and, AFAICS, uses Clang:
>
>https://syzkaller.appspot.com/text?tag=3DKernelConfig&x=3D73696606574e3967
>
>And I believe KASAN_STACK should work regardless of KASAN_INLINE.
>
>The only Clang-related issue in KASAN that I recall is this:
>
>https://bugzilla.kernel.org/show_bug.cgi?id=3D211139

Thanks, that's good to know :)

>
>You can try disabling the instrumentation of the function that causes
>the issue via the __no_sanitize_address annotation if see if that
>helps, and then debug based on that.

I already tried all the sanitization disabling tricks. In the end it turned=
 out
that a compiler parameter is missing for x86 SW_TAGS. This one to be specif=
ic:

	hwasan-experimental-use-page-aliases=3D$(stack_enable)

Looking at LLVM code it must have disabled only some functionality of the s=
tack
instrumentation and therefore it gave me some odd issues.

Anyway I'll add this parameter to my series since with that it looks like i=
t's
working. I'll also have to recheck every possible inline/outline/stack/no-s=
tack
combination :b

>
>Thanks!

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/m=
dzu3yp4jodhorwzz2lxxkg435nuwqmuv6l45hcex7ke6pa3wv%40zj5awxiiiack.
