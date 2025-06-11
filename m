Return-Path: <kasan-dev+bncBCMMDDFSWYCBBDV4U7BAMGQEBWNF7WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 66014AD5F6C
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jun 2025 21:50:40 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6fb1be925fbsf4384386d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jun 2025 12:50:40 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1749671438; x=1750276238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MRC7f87a0lS2SilaUToKS+wg+D7VUPePa8fKWvFAvC4=;
        b=ACdpsGazhrp8hjVP7AZ39uCoobkuhE8O62xT6FoD1+NJwRWqjukmuybBgue31QStt3
         0Mt1KIhD/6JrIU53Fr053bOWlHoilnqo/QPumvTA/g4691fIm97ge9OdZJEgL7KzuH/5
         K6r/zRAqjifCbhDkPPk50RVraDgWXJldOy1js72QPMWBZrrv2mV6JTcUFA55P+Gmqp4q
         7+heCyf49XS8fTnROZRjn/QkRxl826u7glbU0nMUkc9+gdCCEsxfptlHl6+fTh9IjaWy
         HoS7yJTdbZkDl0Jy8T+anUtwBgh+MQPeUj1qACrZjXbaNnLfTf2yk1r/hgEExSWI94MS
         iaPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749671438; x=1750276238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MRC7f87a0lS2SilaUToKS+wg+D7VUPePa8fKWvFAvC4=;
        b=U2gg1k0bk8wdSzhEBpOBK4H4xB9pPcIJAPkSdPsVEyk4O9BNFPTHrMlttgoj0bUduL
         fglj1FZUeFf1ufdCGOrD6X8H3qsf2i51OruZumUG9NZqbioLjJVdprDOfeAeJdqkzyf3
         K2vG5P0E5Kze6GH3kR+MntUcM8rwai1mbMVt2Ol8p+2dEIcn7yr4jdIthmdMT7t0lLTr
         IBTyWNa9S3mMMGCaoLVyogvW1eCrXU4JZ/1uB5SJzccon5azoFOinZW5KfD9+RnzVb2Z
         LPYdrt883wniIBxkHo+PSEYs0FPh+RvHlxLsi7MD6YszhDNEQ4QQa3ENghpZG1QZ1/IQ
         Vznw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRxJ8ilPxymjzdt/qY91g9UcVT/h2bRBXi86jfNmo48DkGmwSeunC1q7ZL+9ZesBz6rbEcPA==@lfdr.de
X-Gm-Message-State: AOJu0YxZeW9UHOvKkVV3Wlt5Sf2tOG3t6RUFSBFVKPtjUKqGp3miMmvd
	urgndl5vhaLrsLQLllOZO3XD0PBllWYftb/ICsdaakYClfTuXKJZWpxc
X-Google-Smtp-Source: AGHT+IE0K3pINnwlmgyOr63GhwfqmVYQ17TwEot3CkwEb6EP2PQs/wW3sC7kwY71C529DjvlPwBYgg==
X-Received: by 2002:a05:6214:260d:b0:6f9:2c6d:8568 with SMTP id 6a1803df08f44-6fb34eb3fdfmr5335176d6.40.1749671438432;
        Wed, 11 Jun 2025 12:50:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdyiXxJCyxHrbW+CHGwhdYewO34woBBRwL/NhR7zLIKiQ==
Received: by 2002:ad4:5965:0:b0:6fa:c0cb:1359 with SMTP id 6a1803df08f44-6fb35573760ls472916d6.2.-pod-prod-07-us;
 Wed, 11 Jun 2025 12:50:37 -0700 (PDT)
X-Received: by 2002:a05:6122:1350:b0:530:5308:42ec with SMTP id 71dfb90a1353d-5312f99dbe2mr28885e0c.8.1749671437621;
        Wed, 11 Jun 2025 12:50:37 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5312f62e019si3230e0c.3.2025.06.11.12.50.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Jun 2025 12:50:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: o7MHyzXPQ3yFs4Ki8XHWrw==
X-CSE-MsgGUID: 6xQaHBrqS/iZObXXUUuC/Q==
X-IronPort-AV: E=McAfee;i="6800,10657,11461"; a="62107150"
X-IronPort-AV: E=Sophos;i="6.16,228,1744095600"; 
   d="scan'208";a="62107150"
Received: from fmviesa010.fm.intel.com ([10.60.135.150])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jun 2025 12:50:36 -0700
X-CSE-ConnectionGUID: DQxPMKLeRe2RwsUE56ZK0A==
X-CSE-MsgGUID: OKt3fgGqSnymTRxyxSj0DA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.16,228,1744095600"; 
   d="scan'208";a="147777906"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by fmviesa010.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Jun 2025 12:50:35 -0700
Received: from ORSMSX903.amr.corp.intel.com (10.22.229.25) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25; Wed, 11 Jun 2025 12:50:34 -0700
Received: from ORSEDG901.ED.cps.intel.com (10.7.248.11) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25 via Frontend Transport; Wed, 11 Jun 2025 12:50:34 -0700
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (40.107.223.45)
 by edgegateway.intel.com (134.134.137.111) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.25; Wed, 11 Jun 2025 12:50:33 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=E1h9tSSR4NMoNL/NILXjAmVnmnqjj+awhS21IXpaxQ1Xrk+2cQ5QxUPxa2kQgNvkbsqzBOlfmLc6dHpqwmE6VwbOgbsRj2Moq11n115xgNyXqYQD2TmRXhVvanGsJll6NlAkOztA+EJUULGfKy9k+6cg/OvJCehXc3F9MI+oDgKHj3E3WSMdcP+byJJuEyWgQXPAp8seZ00bYAU6PwarM8k8cOG49Qscqu1w9TPEpG1z/SPYnyBECY+P0oB5L8XN7RXVSFbE95izMr6qZPHUNfUStVuUuAezAFS/Bambaq69dn4S1pCig1Fb8fvsH5/GvHVLONYPI3cousoSIxJRcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+zdL0UUZY1OI/ZvuZEnBsAJNt5GpdKYoKpYQ8fjc1xg=;
 b=TJhkkhhHtyUmEeYILBDRa9zveiWDU/1OqWnA4TfXJLxALQUbJTB43ln+47mP3HMT+py2A3QHMv0hFr5FVHItyR+ZkdTZqDFFAbiNln3yukb0BwESUC4ygwoQ1o1BRHeQMAiZ4+5js4NuZGN9Pf+t+H5hGEb3Oe/ESs+Zn8CVacAFhY4SQVjRTKX2DFP2eVVK6GmSMHDSEgbR0Bjs0CCZOBTgnZkEceh8gemQkTAiHNCm/FsgJJoBRBMcWRh/Bbi9GwgYIReQbp0AGBCj078nqKmHjcL2f/E2wVGnPIL5uxVYeEb2kxqWuv5QMnIso4vsfEUo3cII+KCO/Kjizv05lg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by PH7PR11MB7552.namprd11.prod.outlook.com (2603:10b6:510:26a::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8835.18; Wed, 11 Jun
 2025 19:50:17 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8835.018; Wed, 11 Jun 2025
 19:50:16 +0000
Date: Wed, 11 Jun 2025 21:46:11 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KASAN stack and inline
Message-ID: <lhbd3k7gasx64nvkl5a6meia2rulbeeftilhxchctkmajk6qfq@jmiqs7ck6eb6>
References: <cwl647kdiutqnfxx7o2ii3c2ox5pe2pmcnznuc5d4oupyhw5sz@bfmpoc742awm>
 <CA+fCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX+b3L3WmV4tyMg@mail.gmail.com>
 <mdzu3yp4jodhorwzz2lxxkg435nuwqmuv6l45hcex7ke6pa3wv@zj5awxiiiack>
 <CA+fCnZfSJKS3hr6+FTnHfhH32DYPrcAgfvxDZrzbz900Gm20jA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfSJKS3hr6+FTnHfhH32DYPrcAgfvxDZrzbz900Gm20jA@mail.gmail.com>
X-ClientProxiedBy: DB8PR04CA0016.eurprd04.prod.outlook.com
 (2603:10a6:10:110::26) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|PH7PR11MB7552:EE_
X-MS-Office365-Filtering-Correlation-Id: 6597014b-904a-448f-60b6-08dda9213049
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?SkhacnBRNUxMcEhvYzgxcHB0UVVBNjRvN1lKenhRdG5idXQ2NEVoMEx2cUJP?=
 =?utf-8?B?UzlnQUVTUmo2cTZBUWgyWVcwZktTVDdjaWcyL1JrSmpyNWZaVmo4aVpNaWF0?=
 =?utf-8?B?R053LzVwWDYrbUZOR2NFcnZNODRmVmtuNTNvMngyMGZDeFdZUjVUd1NuRTdm?=
 =?utf-8?B?TFp3ekluMEtFN0t6VTFvRzZQOFRwZ0FXZlp0VXpPaG9yVlprRmZoQWc2cG5V?=
 =?utf-8?B?SmhtVXExMEdxWUQ2OTFXY3pyL0lYYnFUNm9KeUJtWUkyK21OTzUreHZTTGhi?=
 =?utf-8?B?OHA1b2Z5Y0ZwQWM0MFliNko2cGFnUXgydzFlS1R4SWhWdlh3MGw2RXgzOGd3?=
 =?utf-8?B?YjFneEl1eUxMdVpaR2czZGZMZnFVSWZlMWloNHRCN0ZBMGU0UFBEL1QwNWww?=
 =?utf-8?B?c3RnalBZdnd6YWhQMGFEQUNydnBFZ3dyT2hHYmUyemc3eG9GaGprKzZjT2Jy?=
 =?utf-8?B?VjRzTVZkQUlWS0xaWjliUy9MQ0laTU1wTmFFajBwckRTZXc3endNZVl6SXpW?=
 =?utf-8?B?Vk52MnNpaWZOL3hsM0F6RWowUFY5dnRQeUtmNkJ5aFg2SUtveXI0MlZTenNh?=
 =?utf-8?B?Sy9nTmpzcCs0UmIyZnBqMjNDdE1XMlZUQ2JRQTMzWVpDS09JR1dmT3cyL29o?=
 =?utf-8?B?TGd0eGgvM05PdGNYMXJaZnZHblF2Y25NWkR1ZWlTVnpPY2Q1SCtGdHBwK21H?=
 =?utf-8?B?N21ONXZsWnBwcXFSQ05vMG9FRHdWSlA0eUlEQ0IxTHM0YnREM2IxNEpXaVJX?=
 =?utf-8?B?Zy9zZndodk9xem5xVUlBNFVDWHJhTnBYaVNDeHUrQUFQbmRlZmtBRG82T3dw?=
 =?utf-8?B?S0xKYVRQVkt3WVlldnhwV1R0emlRa3NFUVdaMjExQ0Q2aXVrK2xFL1VTTnk5?=
 =?utf-8?B?UXNPWmUwbFZvL1FoMXJPQ3EyRWdFZVRrQ3E1RnpGQ1RBSTIwMHVjejJWSGg5?=
 =?utf-8?B?SlRoejV3bFJUWmZ6VTk1Y1ZOMUlUelBETUtUdWZLeko3UkVubFlpUkR6VWM1?=
 =?utf-8?B?SzVuMEJTNXViOUxYQ0dpUlpmcU5ZNFJRTXJqQmpnTUtiSXhRcDRId0c3RFhi?=
 =?utf-8?B?eHMyMGExRHRFYUR3NWxxQVE3L2NoNGhPTU95S0NzL3Yzc0hOYUtLM2dCT1hD?=
 =?utf-8?B?OVpWVm9LRkV2OS82Q0VodmVxVWc1VkFZM2xIZ3JkRjRNdlVzalVYL2JVNlE0?=
 =?utf-8?B?TWQ2NVAxbmRPQ2U3NFZBL2M3cUI2TmRVRUZIZUVFK3d0TmZXWWlMSmdOOUFa?=
 =?utf-8?B?MWRhd0djM3E5Qlh1RldlMUd6cXN2TldoNUFseUowS3JMR1E5bGI1b204RzF6?=
 =?utf-8?B?dUN5ZFVMWHlFcXl2Nkw0d3VtN25xSFBndFp0SEdzQ0FHamw0dmRmZ3VxbWw2?=
 =?utf-8?B?LzlmVzNGNXNrZzhWZzRNWGRLcEpmd3BPWFI0VkZtQXVwLzZHUnFXNzFZdnAz?=
 =?utf-8?B?T2pXYStIbmJveHpHZWFpcVpQci9YVmNpWlJSYW96SG5KVGhwVzdtQ0Q4cFFh?=
 =?utf-8?B?VFZEamREMFpseHlkVWRCMVQ0bmIvQ3hOQjR2M0VIemMvak84QkZnNGxoUmJi?=
 =?utf-8?B?NWpheWpsZDJ4bnc5QnNjd2dEUXc0RHZYZmtIWUltREg1ODJIdTFlY1FFRTc1?=
 =?utf-8?B?OUFDUDhRcUtHVUVmTTlwYkIzanZFdEZtOWdpOWV2OXY1TmxMRXlxQzZHNGZh?=
 =?utf-8?B?N2hKSEhKeDJzUlNUdlRWVlV5b2VOZ0FRV2NDWFRqalRPYzlBY0FnenkxUjMr?=
 =?utf-8?B?RVBaSiszMjFpUDh5aWxHL3R5MFdDUThibjVKQ2NmUkMySmR3eTcwNENac2Ey?=
 =?utf-8?B?aDYrcmpsU0YwcHRuK2xQVGRKYjMybjg3SktPOWxrMGpUUGd4dyt0S3VGQ1hB?=
 =?utf-8?B?RDNkTEUxaUVuMW1KejIybWtMTFFZYmt1b3pSeFFvWkJYbWt1VFI5bXVDWE5F?=
 =?utf-8?Q?SHi03fcp7+4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?cXlpcVR6eVh1TklHdlkvNWhaSjRxakdtNE5iRkQ0V3JrUEVPWVdaSzQ4ODZs?=
 =?utf-8?B?N05RZjAxMVFiUGRpSm45blo2QXBraTd2Q2VtNC9FTGRaRkdXa1JNVERTSkp1?=
 =?utf-8?B?cjJYeW1XMVZVSW1mRmxWUkJIVGxxYmwyb0x0VXFZWjl2SUxpcEZ2TnN1Q3Rh?=
 =?utf-8?B?Z1Q5eGpoMzJrQkk0S2dxWi9JQ2Z5STNDbWlqQU1SVnkxRkg0bi9SdG9Jbkg1?=
 =?utf-8?B?dWh0NFlVV2duaFBuTHNLMjFmSmhZUkU3d2xGbFlPTkI5Qmcwblh3aUVXSkVp?=
 =?utf-8?B?amVMcldqZm1xeWV6VmptZmJvNUV2VW9SYlRjLzBPYzVJUDlKSXJZSmZhMm9O?=
 =?utf-8?B?QmV5dndVaXFheXVmNXpVeUk3NkIvbjZrSmIreEtKZUUyTElMaEtDVXlHTEFw?=
 =?utf-8?B?R3RhcStUdStkTTZyQmIrTEc2enQyRkExVVhMVVNuUWFEUXpwcE90NHZuMHcw?=
 =?utf-8?B?eFptdzlhK3A2dWNCcE5XS0wvclFMU3VzN01wY0hJRDY3dUF6NVRrYUtQKzFq?=
 =?utf-8?B?SitYYUVnUncxalpTMU1SVGxocFZKRTRPOGV0YlE2aUlFbHAzQVllNXBmb0o4?=
 =?utf-8?B?dENXK3pPc0F5MXpNV0VxZkxlYXVwakd5S2NFbHE2OWYwbWhTWmgrVHVKV1lh?=
 =?utf-8?B?OHQzWGJYNXRkTmIrREtrd1g5TjZmMG02dmZiTEQ3di9RbDh2bXpJODZuWVdG?=
 =?utf-8?B?UFczN0piMVRIR1NLeFZCTmVyY1hleitZOXJCbERXN0FVcERLRTlUUHN1Mktr?=
 =?utf-8?B?aXNkQm1ORmpBVnFsem00NmZTYndTK1hvTngyZ0JvbTd3azN6czRMQjJlNXR4?=
 =?utf-8?B?MDBLY1dkZ2xYSWg3Zm50djJrL1JQZTdXS0dad0tpRlFiejliT2VLQ0JoOXAr?=
 =?utf-8?B?R3RNS1NrWktVdmlGdlVVYjRGVVg5T2Y4T0VjWGpaWFJ3U05CUkxvRHBIQXJu?=
 =?utf-8?B?WG5DUzZZRjhOUEM3NWFrbTRIZFl2enJoYWZrTHU2YUxKTWwraCtHZzcvakdy?=
 =?utf-8?B?NjQxaEFvQ0ZMRHJXVVdWZEtxV1UwMnRkNHBIc3hBdHliTXduZk5sYWxnQStO?=
 =?utf-8?B?K1VIeFdNdHlXbE5SekFsbUQxbG5KRzVralF5R3llNVVuTkZrMzM1amU5Q1pF?=
 =?utf-8?B?U0lFREJzWEVxMjVqMmRRTGlQYkhXZlNWdktDYWpMaXo4bXV5a0t0V3M5OHNX?=
 =?utf-8?B?eEtkejV5aUgzWldoVlczU3JwRFZndmt3eWZrMXF2c2pRVVlwcThqdVNoZnU1?=
 =?utf-8?B?cDFsekxtTzVPMEFISDBOZFZRTzlzMHhGYTlqZ3E4Uk45bithL0NheGI3bjd3?=
 =?utf-8?B?RFRydVczSHV5a1FZSnJBb1g2Smx1RFYvNGt3Y0pGWDcwQ0FwL1RuMExFbkVj?=
 =?utf-8?B?dFh0VXk0Yi9xdlFwZ2pZd1I0enlRVGhLWUtwRGlrMXhKU09FcjEwWmloSlFr?=
 =?utf-8?B?a1JrcVNtT3dveHNBblZNVkNHN3hYYUxjaFltVzNNWDFMaEoyTUk5U3k0OHRt?=
 =?utf-8?B?VEl1Q1pSTnc3ZE4rekxPVU84ZVdnay9GYjJNRXdSOVlJWTJOTHBzMWJpdmty?=
 =?utf-8?B?bXk5UDFPQ3V2YVg0ZTlhWUVscHk3eEE3bTJnaTI3Qyswa09kaWpkZHpxKytz?=
 =?utf-8?B?OGNjNkRaOFo5Ui8rWG44azdOWndGa2dYRUMyUXhMeGVzd2lWUEhha3IxbEVu?=
 =?utf-8?B?dHlidXFCbXR0N05oNzJ6Y2w0dGZtQTg5aFRxUWxJQW1VanJTbFN6aTRZRndu?=
 =?utf-8?B?NXNJQ0tXWTF6dENRRm9ZcDViNUtXemNBTXptR1JJQ3VKVk0rZHFqazAycC80?=
 =?utf-8?B?bkZkT0FQSlZqZVdGOGJlNnBKaURBSlAvcUZNbXBNUnAzSTFTUExuSFF4aVVO?=
 =?utf-8?B?VnpMVGZ5eDJUM0FzQjJBNWJMblRjWUxmTDlPdU4vbmRnaFVTSTRrSVU1ajln?=
 =?utf-8?B?TUpjVWM1NnErZkRXcGZXMUhSdTN0eDdpdThaWDBlRzBVZXZYa1lpQ3hEVmVC?=
 =?utf-8?B?ck9hbytGQ3h2Q0V6VS9QajFpZkwyMXV3OVEzOW5SM1dHdEZobGVsR3U1aWtl?=
 =?utf-8?B?RlR1b01DSFNQaTFCa3BFekhSYkFMc0hrQWVkbmEzSHcrcWtxTEZma3ZFL2s2?=
 =?utf-8?B?S0RyRHZSQXBGdno3WXhxT0ZHMEVVWGZqQk5tZHNtcDFUOTNlZ2E5M3V6NWE0?=
 =?utf-8?Q?1xZSEb2aB9gLSkaN/sSkOkk=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 6597014b-904a-448f-60b6-08dda9213049
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Jun 2025 19:50:16.7106
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: zXiKAi0PlI/PD8Z8Wq9mr0rjqOpO/AV/aMmvOPZjIL0gNulAJD8S3pJNPGIITz6dWKwIoAH3VlEAKakfmnjvPQQPdBgmNvicBqY+1dDwhqI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB7552
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jqSAxFQs;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-06-11 at 21:28:20 +0200, Andrey Konovalov wrote:
>On Wed, Jun 11, 2025 at 8:22=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> >
>> >You can try disabling the instrumentation of the function that causes
>> >the issue via the __no_sanitize_address annotation if see if that
>> >helps, and then debug based on that.
>>
>> I already tried all the sanitization disabling tricks. In the end it tur=
ned out
>> that a compiler parameter is missing for x86 SW_TAGS. This one to be spe=
cific:
>>
>>         hwasan-experimental-use-page-aliases=3D$(stack_enable)
>
>Ah, didn't know about this parameter.
>
>Looking at the code, I actually don't understand what it supposed to contr=
ol.
>
>It seems that if hwasan-experimental-use-page-aliases is enabled, then
>stack instrumentation just gets disabled? Is this what we want?

Eh, yes, you're right, I missed that it's negated in shouldInstrumentStack(=
).
Then no, we probably don't want to disable stack instrumentation by enablin=
g
this.

It's a pity there is no documentation for these options. I'll try some git
patch archeology, maybe I'll be able to extrapolate some stuff from that.

>
>>
>> Looking at LLVM code it must have disabled only some functionality of th=
e stack
>> instrumentation and therefore it gave me some odd issues.
>>
>> Anyway I'll add this parameter to my series since with that it looks lik=
e it's
>> working. I'll also have to recheck every possible inline/outline/stack/n=
o-stack
>> combination :b

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/l=
hbd3k7gasx64nvkl5a6meia2rulbeeftilhxchctkmajk6qfq%40jmiqs7ck6eb6.
