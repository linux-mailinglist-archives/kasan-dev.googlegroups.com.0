Return-Path: <kasan-dev+bncBCMMDDFSWYCBBGN4WHBAMGQE23WSTPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 96DEEAD93B3
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Jun 2025 19:21:47 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6faf265c3c5sf34274236d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Jun 2025 10:21:47 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1749835289; x=1750440089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zkxSRzSnTI9d/moqIgMldMi+nbrep/goxJzKKhjp8RY=;
        b=coSMmAYSB8mK+o7dpN8a9W6VNOj5hR3Hp+ePcU2lKT5GUChhd5d0E16cRYgUFdNMWP
         iZH0x7ciG2uQ3kNBxZf5nUQRuIGB6fLx5R+uPgQ7IwdttQfjYMnROkxE8pVhn8qVcKLm
         t+xXP4112HhuHoEsRChprmltqrPon0JbN442FooCaGSufgCpXRPfo/K31vNHoCNicmI/
         EcWXgzaD2jKAkUSGM0ShrHaD0JgAJzUJKmrDLWUTc3Aa/qdHrCAd+0+X0jVcJ3Wy5m4N
         BuKWpUAk2xY0gwAtrAgrpiNJmLFC817CO2bA1kOPRos6Yua3cTij26HBYAKdwErYNGPd
         erkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749835289; x=1750440089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zkxSRzSnTI9d/moqIgMldMi+nbrep/goxJzKKhjp8RY=;
        b=l6HpSahOTQjGe49REwJwgJVFwmaL06LB77wKiTsAgUjAdoy36YiShM6GtbGteEvezw
         xnPH/+tVQpGX7R/NIRFAkBVsHrSXQnp2+H4Rq6wfhLyTLR1g8HZEe8vcQpAyDFryam8E
         7n8DZyQsNX8TDp5ewiu3PONrGbUuKU9VTrFRAtOR8ldiaypfMMeHFsBGiB0ASQk82yYw
         mmHSZB5KH3/WGUgSk/s1A2Gsi20f5gEM3WIKYp48ewcZab/EdmMfTa5dw9b2T3aP21Hr
         Ca+/PTI0IotiJIkY/e7uw9kqlWcMB5uavs/qqPAAr7RDYoXW6LyIcWoKP/pWhR+aEs6R
         FxlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsJ5gIgo+nXzL1okf25HtVhkGFsWepnHVHJnjUFPKivY1NbAn8WSFLpBlJ2Tr+/Ro8RPeS7w==@lfdr.de
X-Gm-Message-State: AOJu0YzJps1zSMacSfMLnkenXDIjuV9Sjg5Z3QOnXUXMNSuBeI7hMnsC
	wn3RjdqOkG0mL7hSX7dBO4KjZgxPGPrTJNnehSKlkI50t6CX43j8q5dI
X-Google-Smtp-Source: AGHT+IFTIVCW00z7dB2S4vLPdknp1YLG/Atv/yMSMeUjV1eDMZL7WUHz4M5YMUrjoPaWY7Vwc4Z4Lw==
X-Received: by 2002:a05:6214:76b:b0:6f5:40a5:e07b with SMTP id 6a1803df08f44-6fb47774638mr3088746d6.26.1749835289419;
        Fri, 13 Jun 2025 10:21:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfdj3HKCWCqk5pTD71JqN9vQsTVFJyAWkDgNdtWYeVcPg==
Received: by 2002:a05:6214:194b:b0:6fa:c4e4:78b3 with SMTP id
 6a1803df08f44-6fb3555eec5ls32704216d6.1.-pod-prod-03-us; Fri, 13 Jun 2025
 10:21:28 -0700 (PDT)
X-Received: by 2002:a05:6102:2d05:b0:4e7:bf04:32da with SMTP id ada2fe7eead31-4e7f62d5226mr605265137.10.1749835288624;
        Fri, 13 Jun 2025 10:21:28 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4e7e666cfcasi83854137.0.2025.06.13.10.21.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 13 Jun 2025 10:21:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: 8UKaIEheT1CdqdfDK6oQLA==
X-CSE-MsgGUID: e26ptMZ8RIu7dItEsq2clA==
X-IronPort-AV: E=McAfee;i="6800,10657,11463"; a="39669129"
X-IronPort-AV: E=Sophos;i="6.16,234,1744095600"; 
   d="scan'208";a="39669129"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Jun 2025 10:21:27 -0700
X-CSE-ConnectionGUID: U39UXHCSSMCm2tDBCLqj0w==
X-CSE-MsgGUID: UUl+bn1lSM2bHrbEAxm18Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,234,1744095600"; 
   d="scan'208";a="151694406"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by fmviesa003.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Jun 2025 10:21:27 -0700
Received: from ORSMSX902.amr.corp.intel.com (10.22.229.24) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25; Fri, 13 Jun 2025 10:21:26 -0700
Received: from ORSEDG901.ED.cps.intel.com (10.7.248.11) by
 ORSMSX902.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25 via Frontend Transport; Fri, 13 Jun 2025 10:21:26 -0700
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (40.107.223.42)
 by edgegateway.intel.com (134.134.137.111) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25; Fri, 13 Jun 2025 10:21:25 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yiG6hcZG+IVZiJcDW6M1PCO0ITOe+YjyoTNYNGRFgoX373iwtN1VU3QCr0hB571xU0pRuXr1R78TUbJr/oJ8tq+b8KivLnFLaYhN2G7VQ5ZzFa6CbtmaKGOpUEcG2z6kuqzaoAnJR65v9Mkb4ZZfS5aqibSnX6RWhcRmBgeh0U23SK5d/oGH5A9HOHLBpzjPuwc1jdZiXBEIC7vkTNUJfiCz7d2VhMQyg/Mkw85WLf72Oct/HPWLyeB5hZ1pQBSF1C6xFGWEH5qFdi20aui+JUoCl9sNNslxY3mZ5YRyAwi3rWhK4MfInIEMWiNxFGF8nJjBrqpu570C/1DXJdNMIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2sKjgoZP5P6Kpo3g8qdkGp70u0kZVZ2T63y9/3aBQa8=;
 b=WyFrpevCFO+8KIPkdtVy94m43hVLh/5awxLhYT5ss1f6Mr2nGEbM+NQMr02KmeflHM9RrVQBZxk6bx+85iPG/Di/OFcA9v1oUJu/UhDUqIGAlFRh1KiRhe6tGChlwv5iG5I6/n3cLmFOCnbIUQa9xKZ1Nii31yncaqTvTlVPHWIifPlNDlK9UzYYmctd2+bSB58XCN0pBNrOZ2SxgrYnpgpsx0wm/hVb0dP6dRlPGmFxbt1JWGx3ErMZMCU1Tf3jBB6iog1dpYkw6kNZ0XlT+pbHbVWOiMz0K4pFGSVSlGp+i4MYFaqM9k5akNQYwaVzIMAiNw7fHZZI56ar6FmIrw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by DS7PR11MB8853.namprd11.prod.outlook.com (2603:10b6:8:255::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8835.18; Fri, 13 Jun
 2025 17:21:09 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8835.018; Fri, 13 Jun 2025
 17:21:09 +0000
Date: Fri, 13 Jun 2025 19:20:23 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KASAN stack and inline
Message-ID: <ik6nus667nhf27quzcsmhwgappwrxwksbmzs7mkv5hqpcgdbh6@qiwsoogdn5pg>
References: <cwl647kdiutqnfxx7o2ii3c2ox5pe2pmcnznuc5d4oupyhw5sz@bfmpoc742awm>
 <CA+fCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX+b3L3WmV4tyMg@mail.gmail.com>
 <mdzu3yp4jodhorwzz2lxxkg435nuwqmuv6l45hcex7ke6pa3wv@zj5awxiiiack>
 <CA+fCnZfSJKS3hr6+FTnHfhH32DYPrcAgfvxDZrzbz900Gm20jA@mail.gmail.com>
 <lhbd3k7gasx64nvkl5a6meia2rulbeeftilhxchctkmajk6qfq@jmiqs7ck6eb6>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <lhbd3k7gasx64nvkl5a6meia2rulbeeftilhxchctkmajk6qfq@jmiqs7ck6eb6>
X-ClientProxiedBy: DU7PR01CA0011.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:50f::14) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|DS7PR11MB8853:EE_
X-MS-Office365-Filtering-Correlation-Id: 65cdb394-1aca-4ee6-b116-08ddaa9eb035
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?NWlJaGxGS3hQNDV1Q1lmV1M2SXhydXBtNi80QkdiTXVQNjVjb2MzTytMSDdy?=
 =?utf-8?B?Szg1cXVWcHEwc0pqM1Zja01XNWNYeXRjd0cvcTF2UUs3UFh5YkhkMkRweUdI?=
 =?utf-8?B?VFJncmx1Vm5KeXUweW4wVE9LSEVaOEM4OHJSNk5qN0V4U09kaDRTcWwwazJX?=
 =?utf-8?B?alcrQTB4MHdhOGEzZ3QvcUhVUFpUQWUxSTR3bnlESW1ld2NTUzZWd3p4aUN0?=
 =?utf-8?B?L0htMk53ZHp6alM0aHZZbVlzWG50WkVPaCtzcFVKNjVlRUg2dkpBeTFCcCsx?=
 =?utf-8?B?ZkFjZTNBMGZWejZMV1F5RGhlWEJpNzYxemdVbTgwRmxVOEk4UHFRclR6Qm9U?=
 =?utf-8?B?bEp4blNscVpMZmVtRGh4S3QzQXJsVmJreWYxa0p0V3p6V2pDN3NRZW5PaXQ5?=
 =?utf-8?B?eTZOc0VvbU1PdUVOTWJrUUR0WHp6Z0FLMGNWTC83OW14ZzNmY1h3OGFiQmR4?=
 =?utf-8?B?RFMvdS9jMW81L2xScWRYZkZTL3hRc3hXSUlXblZxTjZTU2J6RHphRGRvMmRh?=
 =?utf-8?B?N1luaE9BMHRXN1AyUC9rR2szaEMrSk8zYlBuTkgzZU83Q21qUVU3cUZBSU9K?=
 =?utf-8?B?TXFpWVZkYWFScFlnTjliSXp4N2YrNkJKbTlYalRFR3hpaFhkdGNHeFY0NnVJ?=
 =?utf-8?B?QnJnZUY1dlFQZGtMVk5TWEFaZkdNd3piM0ozbFZJSEVMWFdGbWcvSFJaRUhI?=
 =?utf-8?B?bkVGVmZ1R2thSkt0Y0IzQjMxbk9wOVFQMHA0dUV0UWFRSFMwWHR5SVVsUVNO?=
 =?utf-8?B?TzBLbHlUcGFURE1FTEw0ZEgrK0craGlleDY2b1orMVdqZ2FUcExBN0lOV2lD?=
 =?utf-8?B?SjlPNEZQckJvUUxKLzFsMTUzV3czWmVxOGRuTEFTcVNkbE9URlZBa1JPVTJq?=
 =?utf-8?B?LzdCQm1GY1QvWnlkS2ZPWmp5K2lKZ2hvS2s5SmdQWGpWalhiYS96anBsenU4?=
 =?utf-8?B?aFJ1SzYxc1BJb0NXeElQODNDakNJZDZHSDJOZ0U3NUd5YXR0TnZGbGc1emRH?=
 =?utf-8?B?cmt6QU9lWUNzMnVzTExGbWdPcnlEZncrQXd3Y0hvS09IOHc1UHdxVUY4bUpi?=
 =?utf-8?B?N3U1SnFrQlJZd29wOFdUMytaSGNmTHRPRi81OVY3aG5zSU5uYmFCczZPQ1VM?=
 =?utf-8?B?MlU1RldqcXNmVDRXUGJTTVZZSmV5MVZRNWlHSjBzaU1ZRklkVDhadm9lRENv?=
 =?utf-8?B?T2d0OGw2NDE4aVhWYU4yMHVGc3JYMVltb0o1LzVwWHBUSkYxeXdUZHdsM0VQ?=
 =?utf-8?B?NzhPeGRyTEhqazJaVHgxNENZQjlLaXAxeEtBaHhrSVZ6eGpzMG9XQ1BiS3Jn?=
 =?utf-8?B?Ym5HM2JsM2g1MHZCdnFYOEVId3I1RW5MWVZPZW91VUp6ZmJ1UDQzZ3l1YjdP?=
 =?utf-8?B?NktTejB3RHR1WVoraEswbTIxY044VXBERzl1Z1NBeFZSTnVPeHU1Y0ZsQ0dE?=
 =?utf-8?B?K3ByNVFicWFYaFFpUnBBVGcrVnRvelFMcEVOTWtjV1Fyc0szV29hdk5wTmVm?=
 =?utf-8?B?azNVTFdkWHFQcDhlaEJUdjVZOXdQYm5VT0tZNC9FR2gwU3UydlNWWk84blNB?=
 =?utf-8?B?UG5zdi9aV01QellvczF0dHhLZW51WTNrWHpEblRnbHZDUjAvczlBdFdmQVU1?=
 =?utf-8?B?RXBkT25Hbks0VkVBdS9tK1ZJTnFna0xYOGNGeENtZml4K1pyelgzWndjM25B?=
 =?utf-8?B?TzQ5TjFQZ2xIbm1tdHdGTHpMODRkZHl2S0d4Tk4xWUE3STF6L3U2NVIycWJP?=
 =?utf-8?B?ckhYT2lvQkUxbEdtTHJPcEtGSTh1UmgrWmdzU1RGU214NXltTlF6ekxKSDIz?=
 =?utf-8?B?RmQvbjIxcUtENlY5VnF6WnRIVmVPV2U2NW9BQ0I3aHJIQVRnMU5HTkpLWnVN?=
 =?utf-8?B?TVY3aDFFWm1WL0lqbWhKMVNuTzRucjJ3SHRhZXFIQ2w4TTdWdE9Na2JOdUc5?=
 =?utf-8?Q?D4p9cKw0nQw=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?QnpkOXcrNFFLVDRnWjAzSWdWeWtOVitZWXBncTZORFUveDFqSW44KzBOYjNB?=
 =?utf-8?B?TFF3bVhSdVJ4WmtNMWJUSnNpYWF5VGQrc3c1c3hocUhGWDJ3T2ZtN1ZZWnd0?=
 =?utf-8?B?YVNaU21SMWxvbzRWdkYwTStpTmdUaDdKczdaVDR3KzE4Wm1EWDczN2lpKys2?=
 =?utf-8?B?NCszUEM4MjNoUFF2T2ZkdmlyUHhEeFVzY1FmN0hMckRhejhFRzRUMmFOMTZR?=
 =?utf-8?B?ZEpZdXl3SStPZHlGbHlrY1NtcS9kcjZnTHQ0Yk8vREF4bmx0aTBrdGI3cVJ2?=
 =?utf-8?B?bjFNNU4xSGozcFF0Uld6VjlMT1I2Rm95dW5qWE5xQUFjTmVKRTFaMjFmOEJC?=
 =?utf-8?B?UUUvbm1OdXBOZXVEcnBJTG1VQ29tRkJPekRaeFl4UThyT1M3RW1wZmx1ZG9n?=
 =?utf-8?B?MlE5ekVHcU02bTJxRXUxbCszbk1zbmRsOWF2blNzb1Bnd09rdGFuMjhvR3JB?=
 =?utf-8?B?NFNxV2tkZ2NzRHg4Vkcxc1ZoWHBDSUhwK2Q3ZHdaOFZCWGd2MWk3MHZyWENE?=
 =?utf-8?B?Ykx3dVgrcTd1b3hwNmVodU5NV2NqTmlWTmYxUUsrSjZxVTQ4L3JSS3ZUeUZC?=
 =?utf-8?B?ekNKT2dWcVJWa00xNk9uUnBoU1ZqZmFmcm53aU9ZYllDU2xEaTVhMlBQMk9W?=
 =?utf-8?B?VDJHY1JMRHIzcDgvMjR2VWtEVGZQdUdlM1ZGUVZIc1Z2Ty9OVjNSQ0dKZFFB?=
 =?utf-8?B?UXc2K2REc3I2M3R6Q0RtQ1pKdmJLWDd2YlZnY1pEOGg4Nm1tSFRjTFRYWVc1?=
 =?utf-8?B?RlJ1Mis2QXJDb3doSkRQVnFkWDl6NDMvbEQ1MU5MOUJpaUw3aldxajA0WFg1?=
 =?utf-8?B?Wi9samNDM1NKSmpGS3FMQnh3Kzl5Nm4ycFBJcUE0U1poWFdBZE9ydmIyL25a?=
 =?utf-8?B?Y08wUHFKZHd4Nkh3U2FlWjRCWDdLZy85S2tnMDZNZDJGaDg3QUlMRUNXcm9I?=
 =?utf-8?B?bUpEaDd1VTBXWi81TkxndHphM0lsd3FRaVljdDRvcFQyYnVRdnZXSExGUHln?=
 =?utf-8?B?YUdBbUsxZ2c2cmdYWWxHZUFpbkF6Tzc5Wm4yUGRIQmRkSkhTZkFPdGNiVDhH?=
 =?utf-8?B?Zzc3cWpNVk0xVS82M1A5YTB1WjFxR2hXblZjNURSMjZNVzBlaHZJYXZsaHBw?=
 =?utf-8?B?Q09XL0p5aFl0TmVTZjZ1dUF5cXVQSXhwYXdid0RXN09OVFYxSHFNS2lFSi9u?=
 =?utf-8?B?cnVLYklLOGZjY0FJTWhLUTdudVRmT0pwR1JCQ2lRN25DL3RZY05xK2VFckpY?=
 =?utf-8?B?dFBTUkZCbXpISG43WGVVQk15ZmNZTm9rSEltSFlMUCswa2tCVnVwM3dNUFVy?=
 =?utf-8?B?bzM3VEFpbmZlMU5sSU9QZFhSKzRPdWxXOUUyZ3hteE1keDRCeTBuMml3T1dx?=
 =?utf-8?B?UWZISTJDb05iUHllRUg0aUlzZTNkdUtNemZtVmh0Q0lYZmVpbnQ3emJYQVQ4?=
 =?utf-8?B?ZjFDTmxMMVlXbVZVVzNIWko2STNIRDEyblczMHd1QjVSZWxHYW43Y1BuK0xY?=
 =?utf-8?B?TjR0eFkwK3BpV0pIV1lwbEZSakVsMHBaZXhTR0lVNGdTWEN3Y3lUTVMzZXRn?=
 =?utf-8?B?NHM2cUFQK3UzZTg3bEJaMXBBMGUrS1hUaW95STJENlhpS2hpYlJXOUpLY3VB?=
 =?utf-8?B?cmQwWVAyN2IyV0Y2K2ZkVkF4WjRqZUU1Z2t1RUdSQy9DMVh6ZGhnai9xRzVw?=
 =?utf-8?B?cjZrSldUa1llV29zKy9IQmw4V3U1bFM5RGZOUWwrWG4wQTQydTZGKy8yK1VK?=
 =?utf-8?B?ZzV5NXNuK2VIYmhZeTdRTlJURkIvZi96Nm15S2VoSGpoa3FqNFJBd1ZvdmJX?=
 =?utf-8?B?OEJQV2pLOEVJUHl2NXlZSjNtYmx6SnBGNUlZRHg3VjkwTFBpUHp1aGNwbGdI?=
 =?utf-8?B?c3J6QjhrTWtGbFVFNk5vTE1OM3VwTnBPYWRHNldGemtYYytMTWQ2ek4ySGJW?=
 =?utf-8?B?Vi84RUEwRWZMbTh6bnlVbGZLVm1rUzNhV1Z6SFRWY0lnVlNORkVEcDRCS3RI?=
 =?utf-8?B?eS96L1p0MGpFRmNtWXZmSnI0MVNWZXNyUGIrOHhpMVZCSVY0K0FRdzFFZWpE?=
 =?utf-8?B?bFlCWm5ZWkJQS2FKWlRqRy9nbVN6U3Izbm5LWjhsTWpTZWRjbXdiSE81Qlhh?=
 =?utf-8?B?NTlUYzZkQnhpV3h5djZSTCs0bHlibERoTldKMEpONzhST05PMGNpd2hMSFNK?=
 =?utf-8?Q?7SvTQnAI+NB9twZoaN8JHm0=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 65cdb394-1aca-4ee6-b116-08ddaa9eb035
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Jun 2025 17:21:09.6323
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: C48Qn5wA0lEi7hiF+Qx8I10c0zoK680lXZzJhD9oaZ09m/b8poQMK8unAjtU/t3Kxn/QBaowSi/hH/kJ4PyLSdfbYaLYPOQlGbagwuSVWEc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR11MB8853
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=j8pA6qY4;       arc=fail
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

On 2025-06-11 at 21:46:11 +0200, Maciej Wieczor-Retman wrote:
>On 2025-06-11 at 21:28:20 +0200, Andrey Konovalov wrote:
>>On Wed, Jun 11, 2025 at 8:22=E2=80=AFPM Maciej Wieczor-Retman
>><maciej.wieczor-retman@intel.com> wrote:
>>>
>>> >
>>> >You can try disabling the instrumentation of the function that causes
>>> >the issue via the __no_sanitize_address annotation if see if that
>>> >helps, and then debug based on that.
>>>
>>> I already tried all the sanitization disabling tricks. In the end it tu=
rned out
>>> that a compiler parameter is missing for x86 SW_TAGS. This one to be sp=
ecific:
>>>
>>>         hwasan-experimental-use-page-aliases=3D$(stack_enable)
>>
>>Ah, didn't know about this parameter.
>>
>>Looking at the code, I actually don't understand what it supposed to cont=
rol.
>>
>>It seems that if hwasan-experimental-use-page-aliases is enabled, then
>>stack instrumentation just gets disabled? Is this what we want?
>
>Eh, yes, you're right, I missed that it's negated in shouldInstrumentStack=
().
>Then no, we probably don't want to disable stack instrumentation by enabli=
ng
>this.
>
>It's a pity there is no documentation for these options. I'll try some git
>patch archeology, maybe I'll be able to extrapolate some stuff from that.

I tried different versions of LLVM and did some modifications on them. But
couldn't get kasan stack to work yet. __no_sanitize_address doesn't have an=
y
effect anywhere unfortunately.

Then I started investigating with gdb to find out what is actually causing
problems. Got to a #GP somewhere around x86_64_start_reservations() - it's =
hard
to tell where exactly the problem happens since when I debugged by putting
asm("ud2") and watching whether kernel freezes or hits the ud2 I found that=
 it
fails on load_idt() in idt_setup_early_handler(). But looking at the assemb=
ly I
couldn't find any instrumentation that could be causing issues. Then by
debugging with gdb and stepping through the code instruction by instruction=
 it
started crashing around x86_64_start_reservations(). But it just froze on t=
he
early_fixup_exception loop. So finally when I set breakpoints on the early
exception handler I found a #GP happening on 0x1FFFFFF83607E00.

I tried to find out what this address was before it got banged up somewhere=
 and
the only thing I found is that the RSP has a similar value inside
copy_bootdata(). There it's equal to 0xFFFFFFFF83607ED8.

My question is if you have any idea what part of hwasan compiler code relat=
ed to
stack instrumentation could be doing this to a pointer? I looked at
HWAddressSanitizer.cpp for a while now and did some trial and error on thin=
gs
that do bitshifts but I couldn't find anything yet.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/i=
k6nus667nhf27quzcsmhwgappwrxwksbmzs7mkv5hqpcgdbh6%40qiwsoogdn5pg.
