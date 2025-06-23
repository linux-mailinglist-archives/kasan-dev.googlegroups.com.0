Return-Path: <kasan-dev+bncBCMMDDFSWYCBBBNB4TBAMGQEEEYJRWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id E7279AE3862
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 10:29:58 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4a581009dc5sf64114121cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 01:29:58 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750667397; x=1751272197; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F4swe4jPPuYqWX+ryXqT6zsMpK109NtZn6nBuh2Pl/o=;
        b=GxA2hneNIl/cZ5otmdDk/8JAoTjAZfBmb1ImBZsyQWTG7bXSZN8DQBzA1xukNDYJjF
         Y3Iquj5KCmEI4FakMHvkxRZDjOhR5tB1rvGfhYO2VmGi9DDAc6SI2I3iHF2RMoDY/ZVm
         /S8IH8JWBlLG4EgizQzStL01O+nuINQ8KVRRNWURfQtdte/marX2UNnKig3qgTlwP8UE
         zHEV863oJ05t8mYXgkjSQXFideHsxGf4qyzG8bp6NAp0CfB1dW1Z/FDgByIPzZW+u33L
         tCUuFNefB6IPzh+eAlF7V0XQJXbWgnol7alMBjNntxOx3nue4kiZbwHtL6PKk8gZU8Rp
         Mz3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750667397; x=1751272197;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F4swe4jPPuYqWX+ryXqT6zsMpK109NtZn6nBuh2Pl/o=;
        b=M5Sc1g2M4NyDpM0g8JVbDHKZgqNu2WlDekUvtUiCC4P7ukrUBbJ4/rQ+QG3SWJk/RU
         VQD7XvSVzy5DJ01FPha8Y7HmvxIJtE35+RHPdjuLm8TjyW5EcJlWOOTF0GGZp0PWJGhO
         4oyn6Daop43GJBGfNNku7RNldidAxnvTetmVzgUQspSSHsCbd6yv2tm2pRuOQ12njzoe
         S/15jJR4nEPqcIMyafW3JmKr/NbM+sTxtKUcaVjqiNfUaGVmgRPBKpgxjkGFzD4tdfKl
         QnuQ8jYeGfKxsY23WBCqu/3wSXAIkljP/kGx8x0yFjvP/n5cheAPE0ogG62Q0n28mFfK
         jebQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUBqDHln+hsPMNkiE5BrmiIHWFRj2XHq/8oxQPRaHV/vTcUJEG2ccW4BVwCrZTor0E4GRSzg==@lfdr.de
X-Gm-Message-State: AOJu0Yw4foPaPXdN/RXzkV9PFfcmpGOQ9O+Q39/eLe5H+cN1kSlL1ZN/
	k/eJ67I+Cf5bFKQZoZwSTH50EC31EsaSAy4zavdJG9DiNBrSI6CHWkAt
X-Google-Smtp-Source: AGHT+IFA3qnIOo4S9O4TYPp6zNzwvoE0FLZR1YkDGUeD8/E9ummyfkZ90FGSdlb8MggHbT21pcSnxw==
X-Received: by 2002:a05:622a:5c9:b0:4a6:fac6:fa1e with SMTP id d75a77b69052e-4a77c2f12e9mr184729701cf.8.1750667397462;
        Mon, 23 Jun 2025 01:29:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZexr8OVWCMxL9UMbeyTfBdxjD/6u9oP8uejtnzdl0FDgg==
Received: by 2002:a05:622a:2608:b0:4a5:86a3:b2f2 with SMTP id
 d75a77b69052e-4a76f3bfc7dls66749011cf.1.-pod-prod-00-us; Mon, 23 Jun 2025
 01:29:56 -0700 (PDT)
X-Received: by 2002:a05:620a:458d:b0:7cf:5cdb:7b68 with SMTP id af79cd13be357-7d3fbe7689dmr1624519985a.0.1750667396616;
        Mon, 23 Jun 2025 01:29:56 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.17])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7d3ffd2221asi27868285a.7.2025.06.23.01.29.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 23 Jun 2025 01:29:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.17 as permitted sender) client-ip=198.175.65.17;
X-CSE-ConnectionGUID: ClFpuEXGTciY/iNCljb5Dw==
X-CSE-MsgGUID: ixtYS99+QJi1Vg+mqkFUWQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11472"; a="52833558"
X-IronPort-AV: E=Sophos;i="6.16,258,1744095600"; 
   d="scan'208";a="52833558"
Received: from fmviesa002.fm.intel.com ([10.60.135.142])
  by orvoesa109.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Jun 2025 01:29:55 -0700
X-CSE-ConnectionGUID: xskNt9PGTAmHt/3fNzai4Q==
X-CSE-MsgGUID: kRRd18tJRHOUaaxRDhPlLw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,258,1744095600"; 
   d="scan'208";a="175139495"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by fmviesa002.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Jun 2025 01:29:54 -0700
Received: from ORSMSX903.amr.corp.intel.com (10.22.229.25) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25; Mon, 23 Jun 2025 01:29:52 -0700
Received: from ORSEDG901.ED.cps.intel.com (10.7.248.11) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25 via Frontend Transport; Mon, 23 Jun 2025 01:29:52 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (40.107.94.63) by
 edgegateway.intel.com (134.134.137.111) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25; Mon, 23 Jun 2025 01:29:51 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wKO1oaI8QqfBCqrqI6NFV1WTCca+xiD1LXkfqyz15SNM2Q7P9ZrCm8zY9rvxbkgAY44TxUZvrx5+6sgs+JEvkIeGNNabFCQDgwXbz5sG1ivOwly4KrsNpYP3NUbE7uHv2AVJbfeRtpzo7RmgmokxD8UaYY0b8Z9m4Z7VJE6NDlNFcQnVF2J985R7WO4Dxw1klav7PctMz3vgscW5XiPHEl4gsCwXyg+qMF7pt9FWCIGBNpsXgHpTmBF2CyAsmfE1Xzp2533KkXmybdEGHzwhOKbpoJCzV/oVtFZRNRWS9byQDlWQifrPSCtTfYEfy5cei5Us5v/kmMr4jA1Bev239Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=pLivSZ+adESOjFgaffusIDjh/dP2tsre8R0S/sF4Csk=;
 b=JyXdDEusiNzNWORLzK600GMwG26PGkK1HbztxY8qoh0btbQsO4dmaHZE0ERnkBnuerAQCszsQzmlZIqRFbyUH1mIPwO3CFEDKUGaRhfXmdZ8D1GPYYA7hLM++D/2fyYgHCuaGjH6ySeaEmmYzbjj6cFfE3ZANgd+EhAllUDP/2EtzSQY+8VeROFZS1JpuieFfjjzYrDVjXeBVLohLeDvxvPGQjumoc5YeFvo01nELZQ3YFxyoUf1coOmxkLKpWB5lGJhbzQyXsFYLYKVb47D6Ab0o6M2R2u0w25ySRnRXXXi0TSsKN9pCsgXUAekEG3V1cGsCz0RQvhHJgwag753qQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by IA1PR11MB6324.namprd11.prod.outlook.com (2603:10b6:208:388::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8857.26; Mon, 23 Jun
 2025 08:29:50 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8857.026; Mon, 23 Jun 2025
 08:29:50 +0000
Date: Mon, 23 Jun 2025 10:29:45 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KASAN stack and inline
Message-ID: <qifkbyxg57zlyphfam527obiiq6vzcifmf3kqxukjvyabbekgy@o5lufbpp5v2b>
References: <cwl647kdiutqnfxx7o2ii3c2ox5pe2pmcnznuc5d4oupyhw5sz@bfmpoc742awm>
 <CA+fCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX+b3L3WmV4tyMg@mail.gmail.com>
 <mdzu3yp4jodhorwzz2lxxkg435nuwqmuv6l45hcex7ke6pa3wv@zj5awxiiiack>
 <CA+fCnZfSJKS3hr6+FTnHfhH32DYPrcAgfvxDZrzbz900Gm20jA@mail.gmail.com>
 <lhbd3k7gasx64nvkl5a6meia2rulbeeftilhxchctkmajk6qfq@jmiqs7ck6eb6>
 <ik6nus667nhf27quzcsmhwgappwrxwksbmzs7mkv5hqpcgdbh6@qiwsoogdn5pg>
 <CA+fCnZdZwzxYuOGoZf2i52yntugEVhdABuBTX4jvZeXS-tF_Sw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdZwzxYuOGoZf2i52yntugEVhdABuBTX4jvZeXS-tF_Sw@mail.gmail.com>
X-ClientProxiedBy: DU2P250CA0010.EURP250.PROD.OUTLOOK.COM
 (2603:10a6:10:231::15) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|IA1PR11MB6324:EE_
X-MS-Office365-Filtering-Correlation-Id: 2a777620-d47e-422c-fa01-08ddb2301e9c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?bWtGbSt1eUI5WGxERlY5VWU3N2w3bmpKOWJhOFNmZkRVeDlNVC9KV2xlYXlJ?=
 =?utf-8?B?SURxKzV5elNheE84U0dKK3J0VkZKc1JQSjN5SFRsMDZrS1gycXZwV2k3VjhD?=
 =?utf-8?B?K3hsb2R3TTZzRlFQNm82VzErMndmVHNyRkZYRWFTeC9XNjFsdVY5ZUIwRkp1?=
 =?utf-8?B?MW1SenNTZ0UwdXBsMml3V1l3UUVrOG9TRUcxRGVZem80dFFrOU5mcEk2ZWl2?=
 =?utf-8?B?QzcxVjlnZU9UOVpBL2ZGT3FraEZRcGhObUoyNXBDTzBicGY5REx6L3krdkQw?=
 =?utf-8?B?S0NOZGhVOS9VUkIwZkNqY2xKa0drWStXb0VKVjVEaFNFL3AyM3ZKcTJTQ2VE?=
 =?utf-8?B?TklUZzllWDRsem9CbUNrcm80MlVRN1ZDdTg1MTNYZ091MFhQamU2aTJHYjAr?=
 =?utf-8?B?RHZsRDM4alR6cUpCS0lqVVczenc2MDZwcktQNmd4OE53OFVGeXhQdTNQNDlj?=
 =?utf-8?B?cEhNL3pDVjJxQmszN3orR3pET2ViMTdTMzlDV21pNE9DaGRVbnlpZzBreTVu?=
 =?utf-8?B?czBBOFhUY3hPVmR5bGdpMnJjcGQ4YUJKMGg0a09kNTNYMnc1Q0hBdHhjL0xP?=
 =?utf-8?B?QUt1SW5pcHF4WlkwdGRPZDllaXpsS09EY0ROT2pjbTZJOFRxNDd4NGRSdzM5?=
 =?utf-8?B?bytucU15OXpxSXFsRHcxQmcvQzdrTWZQREVuanNVeEJmRkIxMWhndFBwYVVG?=
 =?utf-8?B?NSt5YWpuVmo1V1ozNTdKN1A4KzNWTE1ISnUyVEpOM1d0T2FsSjlXWVNocWFV?=
 =?utf-8?B?YlcvUVN5TkppMjNRWko4SCtHR3crclNNTU41YjROMFh3d2JZVlBvSGFZdUlN?=
 =?utf-8?B?R3ZGTDlpV2V0ZjRyb0JTUmNaRzBOcWo4SFpyMWdLTnV6c3pJaE56dWIvcVBu?=
 =?utf-8?B?S3hvY2NDOFNza2krWUVWcHJiMy9DWkFyL3ExUUUzd0E2QWszQjVuSThaSWY0?=
 =?utf-8?B?NlJDNWNFblRFVWdkNk1rWk9WdjV1ci9ISHlWRDVQV3F4ZmE4TDI3QnBQRklz?=
 =?utf-8?B?ODN3aExhM0FqZzlIQzV3USs1eFZidWxjL2x5VmRhN0FmL1E5VUZnejRlN29t?=
 =?utf-8?B?TllETDg1NTllbzJwZHI0QXRNbHBGMVhucWZoNFpjUEg2ekJMU3V0NGFpWHVG?=
 =?utf-8?B?NlRRK3d0UzV5REtacHZDTlpVK2Q2eGlmMHYwYityU29zNXE2a2FpeVVwbUxz?=
 =?utf-8?B?NnpuWFVPTkswWG9RTkRIOEc0QlNuMjV2VWZDZnhneDhFYTRtaWFyV2UxTXp2?=
 =?utf-8?B?Y2FOVWcvQ3gwWHBVUDBidGNiQlB6d0EyemxxdzAzQnQ3MDNaT1k4SXgxRnJQ?=
 =?utf-8?B?WDNYOFBRZkIwc2J1QnNuUWQwMzRxVTdsbW14dVk4WjBOaGRPVDhRVkwrQlBj?=
 =?utf-8?B?cnNld2JBdG5WZWd4NVJMb3A0VVFQWUVySEg2RHEwM1FqQzhyMW5VQUV3UzNq?=
 =?utf-8?B?QWFWQ2xGZmFIL2p5bXhDUG1uWTlRZHVkVTU4cW1aMUNpZjVydDN6TmhsdjlX?=
 =?utf-8?B?R2ppaVdKMjhiMnI1c1pvaW1PMWFzRGpUb2M5SWk0dXB2cURpRUducXo0QTBJ?=
 =?utf-8?B?OWVjK2orcG10RGtrbUtrK2F5RElYdTRSd0hxOEUzdzhCRVNJMXZHNHZvTGIw?=
 =?utf-8?B?MVQyN1ZwVEpSY3B5NjdudFpwelUwejVOS0tWc1dpUFdNekEvK3JCRnZHcnhi?=
 =?utf-8?B?RXR5MkZZazduVFRDK2VpbmxnN1ArYm50TFpwanVlUSt3Y0l6SlJ1RllJcUU1?=
 =?utf-8?B?ZHhoWDA5NXR5OUN5ZXBKNnZ1R1NGMXJZYjRXbUlrcTk5cTFvM1FNcTNEOWRR?=
 =?utf-8?B?aDMxVE92RnFLdm94ano4OTh1S0dYZnB0b0VVWkd2TXk3OUFKcnZTZXpJVDkr?=
 =?utf-8?B?bzhOcklBb1ZLRGFWMzRVbE1DUHcwdmJyYWY4SEFpazRVUGp0eHlyaERLeEVo?=
 =?utf-8?Q?FFMttJdY0lY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?TU03dHZXc3lLOW50bk52eHA5dmltSGF3OW5TVWhNcjU0RVhZUTQyRTlEMkdv?=
 =?utf-8?B?di9PVk1Wb0lzMDRzNlU1N0MwODB1OUJLZDQ3TjZvbEt2elNMc3BCYjJqMXZn?=
 =?utf-8?B?ZkU5UDQrYlZXZ1RCN2R1YzEyTDdhbVpKd2tycGttY2RZUGJWZm5XNFZFNVc5?=
 =?utf-8?B?Vitpclh4aTNkZEsvdk9MVEtjOFJKTWwzc0ZLbWZRcEJDUEtQbkNmQ0JkQUZZ?=
 =?utf-8?B?V1F1R2JIbkF6ZjVnbko5a3pxNlJRMXR4YzluZjBkTXBxMC8wSDdzaWFUYTg5?=
 =?utf-8?B?cnhNKy9sWWwxTXNRZnFtQnJpY2s4RndyaGl5K0RCaHdVa052cXFTME14QUhh?=
 =?utf-8?B?Y1lEd1ZNSlhLVVRkdGhZekI1S2pwdW4zM3JFbG9LWG45bmhwbDYvZ1J4NDJF?=
 =?utf-8?B?ZnN0R1FUMm8ydzhabDg3RmRhbTd1ZHlkZ1VETzkvYnhmcGtqTkJBaVBTdjMx?=
 =?utf-8?B?R0RuU0hSVGwvT1NmaE51bUt3dnhDNXR3a2oxeXJENXFWaU5jQThicEp6R3Vv?=
 =?utf-8?B?Q1NpT1p6NlN5SFlKZVRwTXpyaWRiVWV0MTU0aytaZVdQZHJLSkplNVJJOGMr?=
 =?utf-8?B?MUNSWktEY3NpelRsZ0xpd0JSMGVoU2Jja2tyQjE0WnlYb3M1bTREUmhBbUlX?=
 =?utf-8?B?Vm1YaytSQmZiRmlMMzBwL3B2OEo5WVVDWktQWEx5NXdkQVg2RjJaTHJrazVt?=
 =?utf-8?B?c1F2M2d3QnlzNDN3Yi9YVnl5YzhnWC9uaGl0akFwZWpLamZLZFE1QkQvdnN5?=
 =?utf-8?B?T1hNQ01ZWEdmOHYwaE5Bd1dISEY4ZHJ3MEtHa0ZXNnczRjdFZTNuNlRkUktq?=
 =?utf-8?B?c2t1T3lNL28xdE9BLzBEWkJQQ21CWVdXY0JuQitkU2l6RDkvUnYvVERZa1VO?=
 =?utf-8?B?Vi8xTmRvdVE3WVArLzJaZHNsRVFaVkpYdzFaUk9WMmxOKzlGVCswMUZrd3Vt?=
 =?utf-8?B?aWNzQnJvcHFkMWZoeGMzS0R3LzBNdEI4SEUyam5tQTR3cVhaNEVlbG5HYVEw?=
 =?utf-8?B?Z2p1Y2dsc2lxaUJIWEViL1pHOG5vU2E1SkVNV1VnQnF3NURlemhJVWJSYnQr?=
 =?utf-8?B?WHN5RHVPdDIyeW95N1hzbDhKZmEzRXkyNWtuZ3BOcGQxNHczREJ2Y3o1aTJa?=
 =?utf-8?B?dG5jaHdhRGUyL3FDWTBPMWVyTEM3M0tpYnhTL0hzMXBGRUZMelE0MktEczVz?=
 =?utf-8?B?WGFtZDhycGlYQUx0cGEwanVFT1hScTJZcXV4M3R4MjdpQnNLQ25BUkRWM0Jh?=
 =?utf-8?B?aEp4RGRoc3B0dkJ5VWh6ZzZPLzNMenVxbWpkWjFBdzF0TU14cjlrd29COXB2?=
 =?utf-8?B?c3REK2ZiOGJaYUpobWZZdlFDWHJCYm43d2tyKzdsVFBxQUEwbXJ3QXRXVENP?=
 =?utf-8?B?QUl0SHBqZTNGWkhkdTA1S1VyU2hNU0pQK2VsYU92a1M3QUptWVlYekJTM1FY?=
 =?utf-8?B?YVdmazFCb3RNOVdVeVd3MEhSZ3k0b1p2aEEyMWVZNXFSZW43ZUxDRjRYOVd3?=
 =?utf-8?B?U1djY09pQTNQN0s1ZTFzbFF0bXUrdlMwWWttS3E0dndoZm5SMGJjZU9IUVlY?=
 =?utf-8?B?T2taYUQxbVZGVnNrdXdqS213V0VzWmVxTTE0eUJZWmRnNERvYmlMVENwanhF?=
 =?utf-8?B?bzgrOGc5WGg2NVNtRFhZOGJpQllHaUVtQnduL0FaODJPbHcyR3kxZGxmK3ow?=
 =?utf-8?B?c1dSNEYzSXdZUEdzd3oxU0ZBSmI1UUFNaHJ6R2QyMGZqWis1SkMvcEtIYnBF?=
 =?utf-8?B?MDJZaGRvWm1ZdExzQzdSWTVid2laWjM5T1R1RkRjc3FXa3hZZy9DZE51SVpD?=
 =?utf-8?B?SmsrSlEyVW5ielQzWnRpejgxVTMrUEljVmF0NTZBYUt5YXE5UkRvekF1ak4r?=
 =?utf-8?B?eGc2aW9SZ3ZqcUNvTEdYdmhkNnZMaCtoUnRWSklxTXBqT1owTnNLcHo0ZVF3?=
 =?utf-8?B?ZkZobXVGbkhITXlsZjRPaVUzdDlGeUtPdUFSYWtaRnpXYm9sbG40UU5YajB0?=
 =?utf-8?B?SGtLazczUCt0dnRSUGw0WXNjaHFJT0dDTE9kWVFKWDltdmhxZzNTK2FYaURD?=
 =?utf-8?B?azdtT2lzVnk4QjlmbDdmMWJFNTgyVEhIZVR6NTFyeXM1b1ltWllMSThSdDZz?=
 =?utf-8?B?V0gxQmdteXVCdUJhYjRVQkZtdWNIRDdGUHdkRGd3ZHkvY2FBYTNPbkxzK1Bs?=
 =?utf-8?Q?FYyeNpj2tP4CYCdZVQvWpuI=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 2a777620-d47e-422c-fa01-08ddb2301e9c
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Jun 2025 08:29:50.0063
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: iMgG83zjFuoCoefNnulqA1ywP3fvvZ0E/FF2LeYRFraR9RVvhEZgBu8erM5dueqhM430Pjx/CIfscYfVReXPlw1YUsHkOchxZclYhCXQ6Rw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB6324
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=eLYmEzZV;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.17 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-06-22 at 14:56:27 +0200, Andrey Konovalov wrote:
>On Fri, Jun 13, 2025 at 7:21=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> On 2025-06-11 at 21:46:11 +0200, Maciej Wieczor-Retman wrote:
>> >On 2025-06-11 at 21:28:20 +0200, Andrey Konovalov wrote:
>> >>On Wed, Jun 11, 2025 at 8:22=E2=80=AFPM Maciej Wieczor-Retman
>> >><maciej.wieczor-retman@intel.com> wrote:
>> >>>
>> >>> >
>> >>> >You can try disabling the instrumentation of the function that caus=
es
>> >>> >the issue via the __no_sanitize_address annotation if see if that
>> >>> >helps, and then debug based on that.
>> >>>
>> >>> I already tried all the sanitization disabling tricks. In the end it=
 turned out
>> >>> that a compiler parameter is missing for x86 SW_TAGS. This one to be=
 specific:
>> >>>
>> >>>         hwasan-experimental-use-page-aliases=3D$(stack_enable)
>> >>
>> >>Ah, didn't know about this parameter.
>> >>
>> >>Looking at the code, I actually don't understand what it supposed to c=
ontrol.
>> >>
>> >>It seems that if hwasan-experimental-use-page-aliases is enabled, then
>> >>stack instrumentation just gets disabled? Is this what we want?
>> >
>> >Eh, yes, you're right, I missed that it's negated in shouldInstrumentSt=
ack().
>> >Then no, we probably don't want to disable stack instrumentation by ena=
bling
>> >this.
>> >
>> >It's a pity there is no documentation for these options. I'll try some =
git
>> >patch archeology, maybe I'll be able to extrapolate some stuff from tha=
t.
>>
>> I tried different versions of LLVM and did some modifications on them. B=
ut
>> couldn't get kasan stack to work yet. __no_sanitize_address doesn't have=
 any
>> effect anywhere unfortunately.
>>
>> Then I started investigating with gdb to find out what is actually causi=
ng
>> problems. Got to a #GP somewhere around x86_64_start_reservations() - it=
's hard
>> to tell where exactly the problem happens since when I debugged by putti=
ng
>> asm("ud2") and watching whether kernel freezes or hits the ud2 I found t=
hat it
>> fails on load_idt() in idt_setup_early_handler(). But looking at the ass=
embly I
>> couldn't find any instrumentation that could be causing issues. Then by
>> debugging with gdb and stepping through the code instruction by instruct=
ion it
>> started crashing around x86_64_start_reservations(). But it just froze o=
n the
>> early_fixup_exception loop. So finally when I set breakpoints on the ear=
ly
>> exception handler I found a #GP happening on 0x1FFFFFF83607E00.
>
>Just to refresh my memory: with LAM, the tag is expected to end up in
>bits [62:57] of the pointer? So we should still have bit 63 set to 1
>in tagged kernel pointers. If so, this address looks weird indeed.
>
>> I tried to find out what this address was before it got banged up somewh=
ere and
>> the only thing I found is that the RSP has a similar value inside
>> copy_bootdata(). There it's equal to 0xFFFFFFFF83607ED8.
>
>Based on this, 0x1FFFFFF83607E00 is likely a mangled stack address.
>
>> My question is if you have any idea what part of hwasan compiler code re=
lated to
>> stack instrumentation could be doing this to a pointer? I looked at
>> HWAddressSanitizer.cpp for a while now and did some trial and error on t=
hings
>> that do bitshifts but I couldn't find anything yet.
>
>The only thing that comes to mind is that, AFAIR, the SW_TAGS
>instrumentation produces some weird effects if the stack allocation is
>tagged (meaning the allocation for the whole stack, which is done via
>vmalloc). And this might explain that weird address. So we might need
>something like [1] for x86.

Thanks! I'll try it out and see if anything changes :)

>
>If that doesn't help, what we could do for now to unblock the patches
>is to declare LAM-based KASAN to depend on !KASAN_STACK. And later
>figure out what's wrong with the stack instrumentation and fix it via
>a separate patch/set.

Cool, I'll do that if the above or anything else I can think of right now
doesn't work.

>
>[1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/com=
mit/?id=3D51fb34de2a4c8fa0f221246313700bfe3b6c586d

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/q=
ifkbyxg57zlyphfam527obiiq6vzcifmf3kqxukjvyabbekgy%40o5lufbpp5v2b.
