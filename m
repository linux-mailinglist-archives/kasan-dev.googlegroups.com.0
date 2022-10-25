Return-Path: <kasan-dev+bncBCHI5IEDQIGRBPPA36NAMGQEQLOFR2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id F08D560CEC4
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 16:18:37 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 3-20020a05600c020300b003c5eefe54adsf2400506wmi.9
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Oct 2022 07:18:37 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0JcpgoyxxB9bMVPuYKvU8OBTKvydYY5oKszR3RNKD5Y=;
        b=sZi8egFeABLmy7oNu35hcDQGBpYzdQyZaXcENysp8SQOeMiaN9w+KC2h2LaeSlcepV
         fJy0+x3s/T8ButZ0V/yElbEq9KU7b/CBKmK19P4YoArH6dt20ggP3m+NKtj9SL0hxkhz
         WJRLs+eLLT19nZXoSsMmuNS3YooO5tgHMqXCoCdAfnZ6QXqnhOa5M/EL+bR24YXINtaS
         7hrLzp0ndW5Y+3N05OXnA7SQUcgZRMQfUqAudxKRZnLxPbEI/ZJA4FMfJO5ZoHqP6wfp
         PTCZPsGEUuf9Qr/LTjpbG7o3+sBeIGcZCcpnyZZ0WvRITmuOjG1uCmfsQelNGLpRv9RX
         4okQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0JcpgoyxxB9bMVPuYKvU8OBTKvydYY5oKszR3RNKD5Y=;
        b=5cyyeZ/XqoZIJt/IDDoDNAxvDJLp1EYm1VILe5Slqx2jtCg1DJhrtqblMqJb2Kpmwo
         9t7bAORPCLDSHUB26xHyr7S60XS1hYLLvSUdat2x8AzrWFE8YYX7MD57Ffu7a0fn8miZ
         WO0nVLbpOLZDtHxlr+k8wXWfXpqy5/wahptTCyoosfD0NYKyhnaTphUtozTXGNlwMvoi
         cDevspkLsSGl7GMy5S12hcNdCV4p9NW2u+Re/2xK63G4okM7+N+5Gfh7lrOa5CHtBoKZ
         k2t4bkls9T9ziTsi/+S0gm6Ki+N8DI9Y5fKeuNgOnVDBKi3mK5mcwJzQkznBvhPZBzab
         OERg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2Za1qKejOROw7IlmR/IANenZX/ur9pE8dqMJ7G/pDyIiIKmq2H
	sZ8TH3+Ui9rHPLfoepFoX/k=
X-Google-Smtp-Source: AMsMyM7/wi/EhJWI2hJjTaQXMHMF+1h2KzZf2KJ2tvsuujCHrceejEfp3acODDW3ZAW5DcSkKjdUnA==
X-Received: by 2002:a5d:6da9:0:b0:22e:53bd:31c1 with SMTP id u9-20020a5d6da9000000b0022e53bd31c1mr27379950wrs.358.1666707517518;
        Tue, 25 Oct 2022 07:18:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7715:0:b0:3cd:d7d0:14b6 with SMTP id t21-20020a1c7715000000b003cdd7d014b6ls3083460wmi.1.-pod-control-gmail;
 Tue, 25 Oct 2022 07:18:36 -0700 (PDT)
X-Received: by 2002:a05:600c:358f:b0:3c6:da94:66f9 with SMTP id p15-20020a05600c358f00b003c6da9466f9mr25553229wmq.142.1666707516448;
        Tue, 25 Oct 2022 07:18:36 -0700 (PDT)
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id e12-20020adfdbcc000000b002366de18767si121975wrj.0.2022.10.25.07.18.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 Oct 2022 07:18:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of fengwei.yin@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10510"; a="371897443"
X-IronPort-AV: E=Sophos;i="5.95,212,1661842800"; 
   d="scan'208";a="371897443"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Oct 2022 07:15:08 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10510"; a="634109684"
X-IronPort-AV: E=Sophos;i="5.95,212,1661842800"; 
   d="scan'208";a="634109684"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by fmsmga007.fm.intel.com with ESMTP; 25 Oct 2022 07:15:06 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Tue, 25 Oct 2022 07:15:05 -0700
Received: from fmsedg602.ED.cps.intel.com (10.1.192.136) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Tue, 25 Oct 2022 07:15:05 -0700
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.173)
 by edgegateway.intel.com (192.55.55.71) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Tue, 25 Oct 2022 07:15:05 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=dQGvyPkNQVRrKwIR9kDRFVLrLgUjA0Y7nejeMSj9qRENJ6s6E7e2ghEOPdiMFroE7Xaxu6VzYkY6v8an2Cm+pBc3IYW0syMorilla0u3f4hk03i7Yk46SmzK5herdYQGM7itwcwxj7aRFdnlQ1zKsWCum7YSgmiPic2rWxNv57UpGE3vF8XH26yETjWI12VVpZb6IeKLuCvcZWJ1r8O8TsHVfjxzycOcSPJcrq0vL1e6IN+jDMuzstvoUW6CcLc8nGRVeHsLqiPPBks2PEcuwy7qdgVeYHm5NJJA6d/njU1u5IMt0dCjrvg6YyOa5rKq5qS+aBrE1gwxeOXj9yTy4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=w54209OiwuNo+yxwtLvu8X1xs4okdf/s+vby3qtv27k=;
 b=cKGs2ZRcIqRyEjyDcunDdXX2p3cEVvg9rftbLkxCPiEQOxC37PatsRjI834lwsMp19qUemmxMShbGhfszEm/tPRj6IKDcdjzhQqnHg4WkMRQpRtdAodxt0XDDnKnBI29DEQW2G+/aqAWqKFqqX5B3H55Ij4rkep5sIKm0cbQ1TaN9p3xtzOMDWRkJSyoHSvww9P7qnDE9MRkuh2LqmRqMHnY34Jlr1cO5ChWXh4pmQWPKhUuSpTI7PpxcXsfXcJI7Qi6v8TjNheYNNRyLgQt421WvWEHDXBtXEWQb2d1kTiW69/g5LviPLtJaN1DJKFhzCuut3agZDbrgrA35SpMBA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from CO1PR11MB4820.namprd11.prod.outlook.com (2603:10b6:303:6f::8)
 by MN2PR11MB4742.namprd11.prod.outlook.com (2603:10b6:208:26b::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5746.23; Tue, 25 Oct
 2022 14:15:01 +0000
Received: from CO1PR11MB4820.namprd11.prod.outlook.com
 ([fe80::982a:b36f:967f:257c]) by CO1PR11MB4820.namprd11.prod.outlook.com
 ([fe80::982a:b36f:967f:257c%9]) with mapi id 15.20.5723.034; Tue, 25 Oct 2022
 14:15:01 +0000
Message-ID: <f8fdb75b-c626-b4cd-cdad-0e2dd23f1d74@intel.com>
Date: Tue, 25 Oct 2022 22:14:49 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Firefox/102.0 Thunderbird/102.4.0
Subject: Re: [tip:x86/mm] [x86/mm] 1248fb6a82:
 Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page
To: Peter Zijlstra <peterz@infradead.org>, kernel test robot
	<yujie.liu@intel.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, Dave Hansen
	<dave.hansen@linux.intel.com>, Seth Jenkins <sethjenkins@google.com>, "Kees
 Cook" <keescook@chromium.org>, <linux-kernel@vger.kernel.org>,
	<x86@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, "Alexander
 Potapenko" <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>
References: <202210241508.2e203c3d-yujie.liu@intel.com>
 <Y1e7kgKweck6S954@hirez.programming.kicks-ass.net>
Content-Language: en-US
From: "Yin, Fengwei" <fengwei.yin@intel.com>
In-Reply-To: <Y1e7kgKweck6S954@hirez.programming.kicks-ass.net>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SG2PR01CA0191.apcprd01.prod.exchangelabs.com
 (2603:1096:4:189::6) To CO1PR11MB4820.namprd11.prod.outlook.com
 (2603:10b6:303:6f::8)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CO1PR11MB4820:EE_|MN2PR11MB4742:EE_
X-MS-Office365-Filtering-Correlation-Id: 3d8251c8-bd9b-4333-37be-08dab6934e33
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 3zqtzGxBOWx4UQb6B8R8C5qtDudQaDryxshT1cje/7F2KXd9I36Df4dSMWttq0jOUyanIDZ/QuAd+Dxn6a1unNOjoUmL2/xR8sH4RV2aawtGJM4Ftw+vcFkFkXrDxdAO5aVFVSuKYAK01RBVu4OcTcBcyhjdHbbBDj7ht7UukFBXj7m1du+OFiqJDUdGgQEuwxkqbCIMskoJYIRBFXa7+1Ytam1q/w1WZV79rSob7hPH/8F1epUjKj4QZafUC6ORKePLzwNm3wupdHUuOlqS47CzfGruU3H1EEzmOJVKqmfk9c8QRIESm4vpjMlZAspaBfhG8U4r2dDQmmKxsLcdcUg3OtOMIPtpBvdToKDnqLJtOEIJRjEoaJprCsbv8azEG2cuRaeuGZgG+T1kOa2Ba5302RqqHNeN94MbGWlllGVUPgpOfrjGyvIXIWyitfniBVNX98JFOA4w5QjSFpIN2p7nYyGcDMmv1csE8PIxtXMCT+xY+u7MeYDNMtDcL7ZxwfqQEddamrIeBYI/uS3aqCpHrUuuXdcyOxQ+J/25aNImggpVl+B7LslUIS+AiESbkvvMQjQ4tU45aVNWvphTq/X3yStOZxwpHIhTzfqIHNdPY2ej+/8nK96Id6K0dVXxbn6ExV0prt9T2E4Yo4IvDibkwryPtueddel2Fsm2cPyIQjIH+wHnvxXkQ4hojFZK+tExFxjqA2m1OHeZBvTQW6ttUR7VE5An7ZB5odkUadgcUAmIiOxLaVeWmaxXwndadpV4bzU9EIGKQpSQIq1Qg2qSD6B4FMX8E2TrNY6WlGR4vulTR46e0TsuyoocZViSMgc50RLrygnHD4BWsQHKGA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CO1PR11MB4820.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(39860400002)(396003)(376002)(366004)(136003)(346002)(451199015)(36756003)(38100700002)(110136005)(54906003)(6636002)(82960400001)(6506007)(26005)(6512007)(83380400001)(41300700001)(86362001)(8936002)(7416002)(53546011)(31696002)(2906002)(6666004)(316002)(5660300002)(66556008)(66476007)(66946007)(4326008)(8676002)(31686004)(966005)(6486002)(478600001)(2616005)(186003)(45980500001)(43740500002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?VlNNeng3WTUreU1xSDFTbFYxbndoY1htNlArQ0hRZm9oaDZrN2NRV0NVY2hR?=
 =?utf-8?B?Y3hNazhmbXpqVHJVUUFxeDlsempqVGpHQW1CMEpHZHc2Vk4wSHcvbGtNNlVk?=
 =?utf-8?B?UkJmUDdVbUNiNXhpS1g3ejVQTm54VGtvcFl3VG1EeUtuMzdYTlVFZjI0L0tM?=
 =?utf-8?B?R0hDY3RNTWszRnFQaHBmYldqU3Q5dHNQeFlQcGU1OTFZRTVZdGZDRHdjMW9D?=
 =?utf-8?B?d0d0L09LaWtUSDJSd004YkptM0VqTXROa3FWcExCWTQ4YXVrb1F1TTRRU0Rv?=
 =?utf-8?B?eTQ1bVkyYXB4bHluemQ2WFlpT0RKNmxtZWwxK1dBV2M2eXF0Mnl4dkRhY25O?=
 =?utf-8?B?bWZxZW9wamtJNnhZU214QTc4ZW5HQ2NSdm5odVhSVzBSSmJoa0tyQzBLaU1j?=
 =?utf-8?B?Y3FEeFBDSFowWDArRkdTY1BzYmIzaVRidXVva0U4aCtleHdDNEJVa0tmSTFI?=
 =?utf-8?B?UjlQQ0VpakVFZ2htRDJuWVJoM28xQlp1YzNDZlEza2lXM0RUd3RqSVVwN0cr?=
 =?utf-8?B?MitFRmRKMEJuV0IrOTQyRFhOdGJUbUdWc0h0SlJYL003NXpEaHhOR3ZZWDFM?=
 =?utf-8?B?am9vMEtLOFErREduSC8rd01rRWNDR0hwcjhhVVhTVFczM2ZSOU1tdFlENmhl?=
 =?utf-8?B?c2NrTEpkUHR4ZnBpYUw2dmxncStCRHpQTStSQUtqbmxBSlBOWUFvVkFyeU1u?=
 =?utf-8?B?YnNQRDhkaUNxSGZQTFNEK1pJZXlYN0V5SEhJY1Z1d3BNNFNYeEN3bWF1Ulht?=
 =?utf-8?B?MTAzamtic25EbnpFSW1nYnNjamRiOG5QLzBLZDI1YjR6Y1NtaDdDNzc0cnhL?=
 =?utf-8?B?Y1REbzZnRVFackhTWG9xZ1ZDUzFHSDN1L2tHT2J6RDZoTnJaM2JyMFRiQ0hq?=
 =?utf-8?B?NjgxY3E4TENVK1hLWjJIcUZ2K3VLajBKVzEvRlorbkVpcTcvVDIwOG5NY1pm?=
 =?utf-8?B?U2VPaVpVNWQ2OVl5UjRpQklsc1Z1OFJzVDEwTlVvZVpEM0N2OG1ZbjBCalpw?=
 =?utf-8?B?WUtFNFFNS3M3dG5UU1FiOTVHMFVtVE9RVjI0VjVacEtxZ1VKd3lkY0xZT052?=
 =?utf-8?B?M2x5Tkw5SHhJenVWVUdkT1phSW5ITUVkMHphaWhFMFczeDB3TzlaWUxLbmVO?=
 =?utf-8?B?S091MmgwZ0I1ZGp2WVJxTlhtQnloclluUkMxcTNaL1AyVzlCaWhyM0hlU3Ez?=
 =?utf-8?B?cDVYV3hWZG4rRXkwTlFBSEYrK3pvaExUQUFaSkQ5V1J6djFnY1c4VGJWVHFq?=
 =?utf-8?B?eTBxdllPck16MUROVWtTNVJoT2JaQnFuVDcrbTRSakxHRWQzUzJHUnhJUHNY?=
 =?utf-8?B?azVjZng4SUFyc2Q0d3ZvQkpKNk5ad2tsRXlFYTdIQVkzYUlYZDkvSXIxMmJK?=
 =?utf-8?B?U0NlS05TMmRGRlVLWG11Ukc5K0t6eTFsUElqNmtUSmo3OXdXTjZZT1IrbGhR?=
 =?utf-8?B?THZXclFIS2xrT0tCV0kza0dZMVNEUjJTVGt6NXVHV1JQSG04MDFVRkt0dzd1?=
 =?utf-8?B?L3l1RUgzN2dqdXQzWDM4SWd6RU95T0llWHRtRzRER0Z3TTR1QkhyUllOMlVv?=
 =?utf-8?B?WW5jV2VQOG1xenVXNTZnNkVIK0dISWx0dE5CbGtveng0c2Vrclo0V2hER1VV?=
 =?utf-8?B?aXYzRkk0Uml2Qm5xWjBQUmV6eEdDSnQrNDFhME5uZnp1S3J2bWtJMWw0cUVL?=
 =?utf-8?B?RVJVdHhpb05KTWtOK1pBcWUySlJuakFON2E4bzRseUhaM1BqQlpaMkUxMFhQ?=
 =?utf-8?B?bGRnczJBdm5PRXM0MktFQWhJRmV4dG5YY0V4cTI3UHc4Z0E0UGU1T01rVkFr?=
 =?utf-8?B?NlRkN3hzVEsralZGMnlLNUszb3FnUERha1RsNzdyUnROdHg5WGpzSWlXVHAr?=
 =?utf-8?B?em9YRnFqWnNaOU1pMzRMZjFoOEQ0WmFmL0xyaDVGa1RjRnE1bWVuQThrTFc2?=
 =?utf-8?B?TmIremtTeEJtUEJzdzIrY1ZZNUF4RXl5NkZqdEpZWGhIb0VBOHNTM3FCNlE4?=
 =?utf-8?B?L1gyZVFFelF3ZGVqdEpnMExqUWhOZTNqc0t4NlRwU2RJNk9DNVVkcDFONFdn?=
 =?utf-8?B?RG03ZEJVYUtoUVMrUEZZYVE3OWZIcGx6dDNkazhFd2lZdjdHSEU0TFExa0Rz?=
 =?utf-8?B?UjRHVTZlSGF0elBiVzhCQ0hiREtDN0JCN3JWT1p0ZE5aV0hOTmRRZ2pERFhy?=
 =?utf-8?B?R1E9PQ==?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 3d8251c8-bd9b-4333-37be-08dab6934e33
X-MS-Exchange-CrossTenant-AuthSource: CO1PR11MB4820.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Oct 2022 14:15:01.7585
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RDZgSULFZ0hVjmdbYTz7kBaxsW6QhC8kHCEPCy5qVq+tezhVxHdRCMeEG7IGYZoiJgDOnEJHMMtJCRrWlwmh+g==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR11MB4742
X-OriginatorOrg: intel.com
X-Original-Sender: fengwei.yin@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UFsAEFrU;       arc=fail
 (signature failed);       spf=pass (google.com: domain of fengwei.yin@intel.com
 designates 134.134.136.100 as permitted sender) smtp.mailfrom=fengwei.yin@intel.com;
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

Hi Peter,

On 10/25/2022 6:33 PM, Peter Zijlstra wrote:
> On Tue, Oct 25, 2022 at 12:54:40PM +0800, kernel test robot wrote:
>> Hi Peter,
>>
>> We noticed that below commit changed the value of
>> CPU_ENTRY_AREA_MAP_SIZE. Seems KASAN uses this value to allocate memory,
>> and failed during initialization after this change, so we send this
>> mail and Cc KASAN folks. Please kindly check below report for more
>> details. Thanks.
>>
>>
>> Greeting,
>>
>> FYI, we noticed Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page due to commit (built with gcc-11):
>>
>> commit: 1248fb6a8201ddac1c86a202f05a0a1765efbfce ("x86/mm: Randomize per-cpu entry area")
>> https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git x86/mm
>>
>> in testcase: boot
>>
>> on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
>>
>> caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
>>
>>
>> [    7.114808][    T0] Kernel panic - not syncing: kasan_populate_pmd+0x142/0x1d2: Failed to allocate page, nid=0 from=1000000
>> [    7.119742][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc1-00001-g1248fb6a8201 #1
>> [    7.122122][    T0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
>> [    7.124976][    T0] Call Trace:
>> [    7.125849][    T0]  <TASK>
>> [    7.126642][    T0]  ? dump_stack_lvl+0x45/0x5d
>> [    7.127908][    T0]  ? panic+0x21e/0x46a
>> [    7.129009][    T0]  ? panic_print_sys_info+0x77/0x77
>> [    7.130618][    T0]  ? memblock_alloc_try_nid_raw+0x106/0x106
>> [    7.132224][    T0]  ? memblock_alloc_try_nid+0xd9/0x118
>> [    7.133717][    T0]  ? memblock_alloc_try_nid_raw+0x106/0x106
>> [    7.135252][    T0]  ? kasan_populate_pmd+0x142/0x1d2
>> [    7.136655][    T0]  ? early_alloc+0x95/0x9d
>> [    7.137738][    T0]  ? kasan_populate_pmd+0x142/0x1d2
>> [    7.138936][    T0]  ? kasan_populate_pud+0x182/0x19f
>> [    7.140335][    T0]  ? kasan_populate_shadow+0x1e0/0x233
>> [    7.141759][    T0]  ? kasan_init+0x3be/0x57f
>> [    7.142942][    T0]  ? setup_arch+0x101d/0x11f0
>> [    7.144229][    T0]  ? start_kernel+0x6f/0x3d0
>> [    7.145449][    T0]  ? secondary_startup_64_no_verify+0xe0/0xeb
>> [    7.147051][    T0]  </TASK>
>> [    7.147868][    T0] ---[ end Kernel panic - not syncing: kasan_populate_pmd+0x142/0x1d2: Failed to allocate page, nid=0 from=1000000 ]---
> 
> Ufff, no idea about what KASAN wants here; Andrey, you have clue?
> 
> Are you trying to allocate backing space for .5T of vspace and failing
> that because the kvm thing doesn't have enough memory?
Here is what I got when I checked whether this report is valid or not:

KASAN create shadow for cpu entry area:
        shadow_cpu_entry_begin = (void *)CPU_ENTRY_AREA_BASE;
        shadow_cpu_entry_begin = kasan_mem_to_shadow(shadow_cpu_entry_begin);
        shadow_cpu_entry_begin = (void *)round_down(
                        (unsigned long)shadow_cpu_entry_begin, PAGE_SIZE);

        shadow_cpu_entry_end = (void *)(CPU_ENTRY_AREA_BASE +
                                        CPU_ENTRY_AREA_MAP_SIZE);
                                        ^^^^^^^^^^^^^^^^^^^^^^^
        shadow_cpu_entry_end = kasan_mem_to_shadow(shadow_cpu_entry_end);
        shadow_cpu_entry_end = (void *)round_up(
                        (unsigned long)shadow_cpu_entry_end, PAGE_SIZE);

        .....
        kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
                              (unsigned long)shadow_cpu_entry_end, 0)

Before the patch, the CPU_ENTRY_AREA_MAP_SIZE is:
  (CPU_ENTRY_AREA_PER_CPU + CPU_ENTRY_AREA_ARRAY_SIZE - CPU_ENTRY_AREA_BASE)

After the patch, it's same for 32bit. But for 64bit, it's: P4D_SIZE.
And trigger kasan_populate_shadow() applied to a very large range.

Hope this info could help somehow. Thanks.

Regards
Yin, Fengwei

> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f8fdb75b-c626-b4cd-cdad-0e2dd23f1d74%40intel.com.
