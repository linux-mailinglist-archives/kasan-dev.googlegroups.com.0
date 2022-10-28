Return-Path: <kasan-dev+bncBCHI5IEDQIGRBOMH5WNAMGQEORRHBDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 082AE61086C
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Oct 2022 04:51:39 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id x20-20020ac25dd4000000b004a2c484368asf1127363lfq.16
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 19:51:39 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5VraeGY2JD+GHzmVSbO4+kLk31xZ9xGvJOXOgL5vT6A=;
        b=glcFEeFnhvMnOQL+a4HKtczBVujjx2rbG0DdcyXu1/dsqLVapJTZox/s5aYpKL3eu+
         NF+NzZIAcYWvlLo04Bcuv5cnh46c3s9YgVF/OYEToiDxeYJtMnf+27pHL1TfqDGIx6Fp
         xpCIb0qty04pU1c40rkPuXKQwdhunlwjq/XuLa5c0f2bqQbUbNT5Qs0VZuKZgRGWLeVO
         7g6nIJVHIEBSeBaLCkKZ+REXr6LUWsK2rLURDX5olWrKsDNygl+TrxFyp6Eh9aUxbygH
         qu5gr90E3t9VfVvwCnqT8gfcI60G0MDGd0GYc/YZt/Zka2ozQunxoyxtwUg/g5TBY7rW
         Ccmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5VraeGY2JD+GHzmVSbO4+kLk31xZ9xGvJOXOgL5vT6A=;
        b=sqU4yVK/b1i7/6+aig90rQGmnQh7jf7vBOC72AOq0SLEH0y4PLPFcdYZjdReBM0brT
         3QvSB42Vn3KXu/XAWppshYp7sX2O/DAsZukL1VOAg559MRmvUPZR56mNaiQRuai+Errh
         GS1ICEDmfyCobV6Awsv4oLE00lMS4+MF584ZYogPBgi0SYIIFbkEW37hcug27DT7K9qj
         XlnzhGyKveVNuOHhe4Mj7xyGLwdb2Wi5vY+D6dl3tAdQq7sbtgGahpNz1LvgdU1X6z6K
         ZZ8KvDjsWIgKRVLykIXUsM/rUHF7KWpXKMrmafhPEA/+ocwgP3AEn8vOKGRevX4A4gOx
         mCHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0Vf+bOn5jcL9JFw2eI2Yn7mlJYpQm1NHbYcrLVajYBq0nZPZ86
	bbhhC+TT7rrtowkBub0WR4U=
X-Google-Smtp-Source: AMsMyM79a6clKf0I1gzfx5UjhP4vr2YiJ9y8/RryeNmpVupal5qhZGxD/+37YECW8nyRhLdA44JMXA==
X-Received: by 2002:a2e:9ac3:0:b0:277:1c8e:684f with SMTP id p3-20020a2e9ac3000000b002771c8e684fmr5723606ljj.260.1666925498203;
        Thu, 27 Oct 2022 19:51:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5d3:b0:4a2:3951:eac8 with SMTP id
 o19-20020a05651205d300b004a23951eac8ls817863lfo.0.-pod-prod-gmail; Thu, 27
 Oct 2022 19:51:36 -0700 (PDT)
X-Received: by 2002:a05:6512:3b95:b0:4a2:7409:b2ac with SMTP id g21-20020a0565123b9500b004a27409b2acmr18189202lfv.448.1666925496742;
        Thu, 27 Oct 2022 19:51:36 -0700 (PDT)
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id k9-20020a2ea269000000b002772ff50da3si82652ljm.7.2022.10.27.19.51.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Oct 2022 19:51:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of fengwei.yin@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10513"; a="310092166"
X-IronPort-AV: E=Sophos;i="5.95,219,1661842800"; 
   d="scan'208";a="310092166"
Received: from orsmga001.jf.intel.com ([10.7.209.18])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Oct 2022 19:51:34 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10513"; a="665916242"
X-IronPort-AV: E=Sophos;i="5.95,219,1661842800"; 
   d="scan'208";a="665916242"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by orsmga001.jf.intel.com with ESMTP; 27 Oct 2022 19:51:33 -0700
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 27 Oct 2022 19:51:33 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 27 Oct 2022 19:51:32 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 27 Oct 2022 19:51:32 -0700
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (104.47.55.172)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 27 Oct 2022 19:51:32 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=JxWQa6VLJ4nvECdywAtSgfcWJ7uNGbz5plMD+BLVz+TBFkHc4ac7NSd1wZ1Bj3My1GwcbnrdyhxJ3Vaf/iN2udlrIQMVoR15YztZZBjT+xemnS9T3NNR+ZwLPCzpRxUVMLoKaoNUk59i23QFNPNHCEWsFdokYWb07aA6qg+0TphqUaigb7gvyL2pH0yLKKxzNsSQDcYZQaSR4oEiAd0rvfrppyAXjlvx9c+7hbu+UavOaZRXCG2n+BhsLZO6b6aS/WUYOOCOhv+X67r9E3B1I62AFF32FgdVPNrKpZ+I6aVaBV+/w2bL83p6fn5++BVc9L6eG1Lp+bNM+hx1o26ZBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=wS6zyrQavFDDw+1sFD7ol+YwxG+OnLx+/Lcbo5BbbTw=;
 b=ATXG0vVDY9sU0+pF2hYQgLQsGuSen8pYR8aKvn8h14dLizavX5ZOgjSvch4uSIW/x5O68dQYf33Ue/sCbynb/jAVvEKxjvol4Rxc3xc9zg9ucykpkecXSQ411wZr5tf2atKTVNQJg1pG+f1EVkhox3cAJcQTWMuV47hemPrJSPhCuAOrzqlFSmhzfpQbYMOz9JUZfgURH7aoBu5lWPESAJf2UuqviOvzWS9Z1Wxo1Qcv246wINfv0s2G8IK6ATIpoJBPi1EVWyhjsWO9Tu1Bmz0AKzg321s+CDU+4B2yUGkVIhBqDGZ5Y9YblHjkh0toc9dW5M/MjyfOJVEp14ZEOw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from CO1PR11MB4820.namprd11.prod.outlook.com (2603:10b6:303:6f::8)
 by CH3PR11MB7251.namprd11.prod.outlook.com (2603:10b6:610:147::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5769.15; Fri, 28 Oct
 2022 02:51:24 +0000
Received: from CO1PR11MB4820.namprd11.prod.outlook.com
 ([fe80::982a:b36f:967f:257c]) by CO1PR11MB4820.namprd11.prod.outlook.com
 ([fe80::982a:b36f:967f:257c%9]) with mapi id 15.20.5723.034; Fri, 28 Oct 2022
 02:51:24 +0000
Message-ID: <3a372c25-7ce1-e931-8d7e-a2e14b82c8f0@intel.com>
Date: Fri, 28 Oct 2022 10:51:12 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Firefox/102.0 Thunderbird/102.4.1
Subject: Re: [PATCH] x86/kasan: map shadow for percpu pages on demand
Content-Language: en-US
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Peter Zijlstra
	<peterz@infradead.org>, Dave Hansen <dave.hansen@linux.intel.com>, "kernel
 test robot" <yujie.liu@intel.com>
CC: Seth Jenkins <sethjenkins@google.com>, Kees Cook <keescook@chromium.org>,
	<linux-kernel@vger.kernel.org>, <x86@kernel.org>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	<kasan-dev@googlegroups.com>, Thomas Gleixner <tglx@linutronix.de>, "Ingo
 Molnar" <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, "H. Peter Anvin"
	<hpa@zytor.com>, Andy Lutomirski <luto@kernel.org>
References: <864b4fbe-4462-9962-7afd-9140d5165cdb@intel.com>
 <20221027213105.4905-1-ryabinin.a.a@gmail.com>
From: "Yin, Fengwei" <fengwei.yin@intel.com>
In-Reply-To: <20221027213105.4905-1-ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SGXP274CA0002.SGPP274.PROD.OUTLOOK.COM (2603:1096:4:b8::14)
 To CO1PR11MB4820.namprd11.prod.outlook.com (2603:10b6:303:6f::8)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CO1PR11MB4820:EE_|CH3PR11MB7251:EE_
X-MS-Office365-Filtering-Correlation-Id: c18a73d3-fe47-4c68-da9f-08dab88f4ca5
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: MZn3oFqEBVt8KiUSvJWxWokR0KwqybUNAeB7yP42QZCIsU746nmh7NaMLr5JMyLN0EkpTxI1OGG66vuXtd6N1EhE0Sid83iC2uGtulGvBbeJIHrDeNqIS333dn4C/MzIgXBtBkJWBnQnTb5tDNMhfSXmuN1Ak3BYFgaopsGOScsFpLroqgxjmmJVWrz6Nu5lgmfxo2EyoftwwAEj50tF74bnfkWsAyIdxskuyMSQN0ScTIguy5kcu6cI4wQ+MSHfNTap8IraxoWjsfZW3tRrKk//+gaVZ3m6GtLXorMABm8yw2iJrQuMvPITqaruudUjr4HBE8YFtprsxJa0MW4KHvqaCRVdp0StLNBdtTSheCbr5uLffV/OuHL1dpL5EbVXHrEO9i0nIFbq50s+uniy4mcdUCbq71+8K14kmcA2eey0Y7y4kDWqGDmmkPR6JUy0wBCN5FOEEBkoxbqRhJbWCxDL9+aR0eLAQveBnO0uuMHREiTaPQ3Eb5sqsvMxe8nLFz1iRB0L+fFHnjxShisp8MLNFSDbVV4xJ2+EPyuqZS0JJzI60Zr/vtMxS+vq3duATbCalKg+YW2Zk5bFUal7SWCgsZNzVctqiRLphjOpOGViik5Jx+Nk/a5nYlYrJTN5OYi0VrtKCi420yAPfIDx2ncfLwxK67LPHJTnVewcrvtCtKS2QJn3/1uz6FH9OiKGKMkx1SJIbbr5YY1ta4DSJ7rOhj1AdlSeBJzHZTytY3I6U6y+8azsz4I96JQ0PKNj93N4/U7vDmy0frsOTcA0M5ZzQ/3z2ZVa8k/PWrp1+WCsaSBNYzQMzC7c/Zq1AnIsWOMcIC8t9OjyOvKjclJ48Q==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CO1PR11MB4820.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(39860400002)(366004)(396003)(346002)(376002)(136003)(451199015)(36756003)(38100700002)(82960400001)(31696002)(86362001)(6636002)(110136005)(54906003)(316002)(478600001)(6486002)(966005)(8936002)(41300700001)(5660300002)(7416002)(66946007)(66476007)(66556008)(4326008)(8676002)(2906002)(83380400001)(26005)(6512007)(6666004)(53546011)(6506007)(186003)(2616005)(31686004)(45980500001)(43740500002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?WVVNSGE3L1ZGcWVlM3VUTnRpTFdKNytpYVdFSnFKZ29ZQjFFOE1GaXVDblZB?=
 =?utf-8?B?R3pPblpMdUcyc2lnTkZNREQ2dGp0Nyt6ZG5Fbm9TWGNBdG9XV0lFU05CMU55?=
 =?utf-8?B?YTJYWEpOM2xRQmN6cFczamdidEdENmY2ZDdkMzFraHE4ZlB0S2E3NDBYaU1y?=
 =?utf-8?B?RTZwOUI2UEJXOVZOajRPR1VNYTZTQkxibytjRlJJL1QzRjdzWTdWRlVVMzNJ?=
 =?utf-8?B?RWgyRFV5VHZvK2JFOU40Y09UWGRBa3hhOG9maUIwR3pZSEFiUFFRL3hLc0dk?=
 =?utf-8?B?WTVJemVYRktPNUhoNkw5MDNDaGgraEVab1I0bUF4YlExcWFQdzlSTFV2RDhJ?=
 =?utf-8?B?UFpQbi94SXlSbWV2ZGNHYi9YYTZ3ckVHUlVaSDFGekN0WFpQODJiTUNtbGd6?=
 =?utf-8?B?elplN3FZekxoSDFsUDZ3c0ZRZW82OXZUa1crL2NpNHdBNHhaZmVFRE11T29C?=
 =?utf-8?B?Y2Y4RkNaSTB2UVBUVXZkcUZGZHJXWVFKdnNJdkJYTkRwYXQ3K0hlQkJURHRX?=
 =?utf-8?B?R2U5MlBoS3daME94bDg1Y2F4MVh6RmkxamdqS2ZFZy9IZ2ovYmVaemUxajYw?=
 =?utf-8?B?ZDBuZkpYWjNZQktmOTdtb1RKUHRnT0ZkSGdBbDYwdEREeHdlYmdNblNIcldz?=
 =?utf-8?B?VUhKcXlIbjhiZ2tPaEt4R1ZJZit6YW1zY0xuc0tZalYvNUJqK0ZHZEFQZDIy?=
 =?utf-8?B?czVmWFhhN1d2eGZSaWRwajlNYmxjUTB5T1hrcmVHZjNkdnRKV0N3N0pnWEtz?=
 =?utf-8?B?ejFvL2RrbU1wRVB0VmFHamdiYlM5bWdaeVRNQmgwZUVlNUJGUFRUS04xcGpQ?=
 =?utf-8?B?UVdaeDFneGYvMFplbEZhNzE0b2tOUnpjNWt6UnBYLzdTajVMMVJQbk9VRS9C?=
 =?utf-8?B?ajV3Ym0rSHdQMTRqNjVPQ0g2VjFiUVNFV2JUUnkwTXd2cW5VQlQxWkZZaS9o?=
 =?utf-8?B?SzA3MjZSdGhqaGN3YU9uRTg2WWFETjRndHpoUkN6ek9oUFdpS0JPbXk4M0E4?=
 =?utf-8?B?MDZ6Z2k4WXFmS0xGSENCYnQ5cFFRS2FvWTVid1B6OTlKR25Kem9lczk1RklK?=
 =?utf-8?B?ZWxjN3JmYU9XaGllaU9lUFFLaExxZmRFdzVoSFQ1Q25iQVBPamF1R2FJcWR2?=
 =?utf-8?B?WkVzaUZrZTVGNDczN2dmdXdvKzd3cFhYN05uQ0xUQ0pTU2lwQ2N2STVoMERX?=
 =?utf-8?B?bHIxNVRLYUNIWUFyL3ZiOHNKVXRzODJRM0VNZExONEQvb2VzdHIyY2V6ZGxu?=
 =?utf-8?B?dWVTd3Y3eUpveDduMG9XVDJNT1I2bUFFbzU2STNHa3RmUWMrUDVJREs5cnpN?=
 =?utf-8?B?NDA3V3VLMXRqdHhzQ2tBTklhMkRCY2ZXN04vOER4dXRpd3BNcEcydEFUT0d2?=
 =?utf-8?B?RE5xeXg4TkpWTGY4QTRVTVVhL290cVZCMzdONDVzMzh1Z3NKZ2tEdnBHZ0x2?=
 =?utf-8?B?Q3U4N1VzYzVJVEttV2gvZkVRVWVFUm5pNDV4eHVYa3lNZWkxTWNkV1ZxSGtl?=
 =?utf-8?B?eEJ4cmJXVXQ3UUhBZlNvNENxSUtyTm1YbWhYcUpLNVJ3aGpHVVlvS1IyeC9V?=
 =?utf-8?B?RHdQcnlZSzUwZGpUZ3F5K3VpVWx6WHNid2o0TnRzMUV4eG1tN1pWZzNGWWVU?=
 =?utf-8?B?cTZneHNtaElPRVY2Uk5DQjBPZ2xDS3V4b3RkSzVGbmRrREx3KzUrdXF6dytH?=
 =?utf-8?B?RWtWcTZmSWx1NzUrTks3OHVmYzdaQ2dHeC9QaG9FZnM3MzBPbDBma2F2MUJ5?=
 =?utf-8?B?MFg0czMyV2tJc0RyZ2xyT09IQktjMndNTHFlZHZMSFcvbDdFcFJ5UjZIemtq?=
 =?utf-8?B?T2kzTmp5SE5nZHpsV1pEdVdzRVFXM0poRjdJbnBIeWw1dHFMbUNRNDFEUFpI?=
 =?utf-8?B?d0dlQVJuWmlWSHR1NkJsNk1idS9qb3lqVHJrREhocTRaKy93MGNwWUFDVXFu?=
 =?utf-8?B?dXJuWFBzOTIxcm5RbHdpWWFTUk9SVldDZk9mc1dTQ09PV2lPWHJwTHQrNjdU?=
 =?utf-8?B?cVQ1SWVCVmp5RFhQaUNVRGhyZ2VDazdtREdJUXlnTlVhQUszdEUxSVBDSVdD?=
 =?utf-8?B?YTc1cXRaL2RCWEJSSzhMNnJmV2EycHQrZlFaTU5oWnBWQ0VCN2MwS3hNVTM2?=
 =?utf-8?Q?mTWT9fDDbGvTPcjdrFD3VkEgN?=
X-MS-Exchange-CrossTenant-Network-Message-Id: c18a73d3-fe47-4c68-da9f-08dab88f4ca5
X-MS-Exchange-CrossTenant-AuthSource: CO1PR11MB4820.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Oct 2022 02:51:23.9460
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: jXBcQBixbWCwdIsEa4lDmhulPKtfXFV1lnmlhePxdCIyoA4baiRJHvt2UelkmM2mWCpX6F2gZA/dnLLj8IksFg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR11MB7251
X-OriginatorOrg: intel.com
X-Original-Sender: fengwei.yin@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=SNO3fNMS;       arc=fail
 (signature failed);       spf=pass (google.com: domain of fengwei.yin@intel.com
 designates 134.134.136.65 as permitted sender) smtp.mailfrom=fengwei.yin@intel.com;
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

Hi Andrey,

On 10/28/2022 5:31 AM, Andrey Ryabinin wrote:
> KASAN maps shadow for the entire CPU-entry-area:
>   [CPU_ENTRY_AREA_BASE, CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE]
> 
> This explodes after commit 1248fb6a8201 ("x86/mm: Randomize per-cpu entry area")
> since it increases CPU_ENTRY_AREA_MAP_SIZE to 512 GB and KASAN fails
> to allocate shadow for such big area.
> 
> Fix this by allocating KASAN shadow only for really used cpu entry area
> addresses mapped by cea_map_percpu_pages()
> 
> Fixes: 1248fb6a8201 ("x86/mm: Randomize per-cpu entry area")
> Reported-by: kernel test robot <yujie.liu@intel.com>
> Link: https://lore.kernel.org/r/202210241508.2e203c3d-yujie.liu@intel.com
> Tested-by: Yujie Liu <yujie.liu@intel.com>
> Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> ---
>  arch/x86/include/asm/kasan.h |  3 +++
>  arch/x86/mm/cpu_entry_area.c |  8 +++++++-
>  arch/x86/mm/kasan_init_64.c  | 15 ++++++++++++---
>  3 files changed, 22 insertions(+), 4 deletions(-)
> 
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index 13e70da38bed..de75306b932e 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -28,9 +28,12 @@
>  #ifdef CONFIG_KASAN
>  void __init kasan_early_init(void);
>  void __init kasan_init(void);
> +void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid);
>  #else
>  static inline void kasan_early_init(void) { }
>  static inline void kasan_init(void) { }
> +static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size,
> +						   int nid) { }
>  #endif
>  
>  #endif
> diff --git a/arch/x86/mm/cpu_entry_area.c b/arch/x86/mm/cpu_entry_area.c
> index ad1f750517a1..ac2e952186c3 100644
> --- a/arch/x86/mm/cpu_entry_area.c
> +++ b/arch/x86/mm/cpu_entry_area.c
> @@ -9,6 +9,7 @@
>  #include <asm/cpu_entry_area.h>
>  #include <asm/fixmap.h>
>  #include <asm/desc.h>
> +#include <asm/kasan.h>
>  
>  static DEFINE_PER_CPU_PAGE_ALIGNED(struct entry_stack_page, entry_stack_storage);
>  
> @@ -91,8 +92,13 @@ void cea_set_pte(void *cea_vaddr, phys_addr_t pa, pgprot_t flags)
>  static void __init
>  cea_map_percpu_pages(void *cea_vaddr, void *ptr, int pages, pgprot_t prot)
>  {
> +	phys_addr_t pa = per_cpu_ptr_to_phys(ptr);
> +
> +	kasan_populate_shadow_for_vaddr(cea_vaddr, pages * PAGE_SIZE,
> +					early_pfn_to_nid(PFN_DOWN(pa)));
> +
>  	for ( ; pages; pages--, cea_vaddr+= PAGE_SIZE, ptr += PAGE_SIZE)
> -		cea_set_pte(cea_vaddr, per_cpu_ptr_to_phys(ptr), prot);
> +		cea_set_pte(cea_vaddr, pa, prot);
>  }
>  
>  static void __init percpu_setup_debug_store(unsigned int cpu)
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index e7b9b464a82f..d1416926ad52 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -316,6 +316,18 @@ void __init kasan_early_init(void)
>  	kasan_map_early_shadow(init_top_pgt);
>  }
>  
> +void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid)
> +{
> +	unsigned long shadow_start, shadow_end;
> +
> +	shadow_start = (unsigned long)kasan_mem_to_shadow(va);
> +	shadow_start = round_down(shadow_start, PAGE_SIZE);
> +	shadow_end = (unsigned long)kasan_mem_to_shadow(va + size);
> +	shadow_end = round_up(shadow_end, PAGE_SIZE);
> +
> +	kasan_populate_shadow(shadow_start, shadow_end, nid);
> +}
> +
>  void __init kasan_init(void)
>  {
>  	int i;
> @@ -393,9 +405,6 @@ void __init kasan_init(void)
>  		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
>  		shadow_cpu_entry_begin);
>  
> -	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
> -			      (unsigned long)shadow_cpu_entry_end, 0);
> -
There will be address in the range (shadow_cpu_entry_begin, shadow_cpu_entry_end)
which has no KASAN shadow mapping populated after the patch. Not sure whether
it could be a problem. Thanks.

Regards
Yin, Fengwei

>  	kasan_populate_early_shadow(shadow_cpu_entry_end,
>  			kasan_mem_to_shadow((void *)__START_KERNEL_map));
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3a372c25-7ce1-e931-8d7e-a2e14b82c8f0%40intel.com.
