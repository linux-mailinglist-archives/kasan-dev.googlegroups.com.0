Return-Path: <kasan-dev+bncBD6YJ5EM2QMRBMVBW2QQMGQE76SYDNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 30CB16D815E
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Apr 2023 17:16:04 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id t17-20020a05651c205100b0029f839410fcsf7922391ljo.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Apr 2023 08:16:04 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680707763;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=djOgPFU038vA2SfZsDJufShLFp+jvgSYswZuiK6/9IM=;
        b=i2A7lI93BdJSqkB153hP4tq2oOBPgjexVRzoZMRHvSJqOY9heGgUVPCNWQn2vZpigb
         N72Xw48aM7oold8FmXcFlA0q/eg8l/CNGxFbVpICRLJlFZrp+WrRY9L6uFzyhYfIIaQM
         puCD5Z0m7V78vP1sMd/+HVCmWbLq+/uCRJ28gMLbx2nv2jycClV/2O/vvrBbpyudPPIV
         +sROceTYbxlAnSCIELcrnnd6vThr9F8f0KcwvCihfksqmrMD5q0y9AHlM56lJE+zuvkV
         vNJ+4AKtpjPG7VFogVdhlOBR+X+T/4OU9OONyRjhMixK3OhjDY/TnWZcd+S3EXvU7k7p
         2Xzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680707763;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=djOgPFU038vA2SfZsDJufShLFp+jvgSYswZuiK6/9IM=;
        b=3FgeOIz8V9cGn8EySuUhAPFuPqmjjTQ6TPKkF1E6YcOcMlO7jL4WJnzVwYBJyxoVY3
         R4kSkcl1+PfjXEUhfOapW314MTkpUOD6TQoxkZLfUicslOm6Mqci42NvLpCmV4dJAli8
         RmXvP0L/mLjeWQKXMT/MVvPgHWtEbY5sITozTl9rVlEuVFostsd7m30RZSaIcz8cHX9y
         sfqO5I+y9e+eJhfSHa5eMx2JFGwyF3PuKvOVIiXEuE0RYB5nljDuIloZgujEeDu3rBXD
         DmFp5W5uCdq8rfFKk8Ods1pn610jvlEyeaEVB3/ndFAn+3fYINx0Ypi0x2slKIp7hGzu
         NDIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dsZxAxPLAUpogfQQKsv/CG9VebCQkQzxjiF/EHgxVdMWPbMFhn
	AIqefOScTu14RUOZ30WTM0w=
X-Google-Smtp-Source: AKy350Y1HPZrJ1fDyGKm+WrK3Iw7Ro77hTUKrOi9S7tz0pStWEvuj2kQXxgMksB19aDtjSmIUQGxOw==
X-Received: by 2002:a2e:7e09:0:b0:295:bb34:9c2 with SMTP id z9-20020a2e7e09000000b00295bb3409c2mr2348519ljc.10.1680707763101;
        Wed, 05 Apr 2023 08:16:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b11:b0:4e8:c8b4:347a with SMTP id
 w17-20020a0565120b1100b004e8c8b4347als3756182lfu.1.-pod-prod-gmail; Wed, 05
 Apr 2023 08:16:01 -0700 (PDT)
X-Received: by 2002:a05:6512:33d6:b0:4eb:4258:bf62 with SMTP id d22-20020a05651233d600b004eb4258bf62mr673953lfg.8.1680707761666;
        Wed, 05 Apr 2023 08:16:01 -0700 (PDT)
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id cf42-20020a056512282a00b004e9d34ac318si737400lfb.5.2023.04.05.08.15.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Apr 2023 08:16:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of aleksander.lobakin@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6600,9927,10671"; a="345061679"
X-IronPort-AV: E=Sophos;i="5.98,321,1673942400"; 
   d="scan'208";a="345061679"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Apr 2023 08:15:56 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10671"; a="756025694"
X-IronPort-AV: E=Sophos;i="5.98,321,1673942400"; 
   d="scan'208";a="756025694"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by fmsmga004.fm.intel.com with ESMTP; 05 Apr 2023 08:15:55 -0700
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.21; Wed, 5 Apr 2023 08:15:54 -0700
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.21; Wed, 5 Apr 2023 08:15:54 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.21 via Frontend Transport; Wed, 5 Apr 2023 08:15:54 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.100)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.21; Wed, 5 Apr 2023 08:15:54 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=VVbxkkfRDbqApkwTqwPOtulR3HouCfoNvNDuke+Ho050xhgQw6HShncok/7/eTxL0DOe2/1EIwJ72hWDc3lzQGMOqns6tKEWH4sorPQ1BFwrA03SmK+M4pagMgSG7uDNqdscA8E3GLFMbILfxqGVY34FYCNndazbzoGnu0Nj/tjqAQgKfThMjPLH4WBsfqTtg80jgk6eGJt5NhkjonL4VJDuopCUN4TIV6m3uWChQkoRlY3R+OI71LdwHTs5Oe37enWYIlb37H6c7DoGeZEvPkU5O0/ONYBz8+NWhIUP1iiJ8E9+INOw9eSNhb4ae1LZ3ZPjedbNJuvG/Xek4tJj5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=pkWOTLyrbe/GJxLCfRJGBgEictpYto+aC+5AzdF72ls=;
 b=Y8/zyu1UEwPjpmBygVa5yvAgtKn8r5tpMcJf5hwdWlalhdhR55s47QDvISnQ+FXulGk20dxVfrg9fqpO+1iY+apfFukyznBuhvxKPbA9K1/ldo0j00fu4xjIb5BxqAEjxxDDipGHJzBL5lmohkTIrtFJ5iOJwIeWpBkqDtJkQ/DLa1yZd6SP3QY9kmj1sDdt35QZuW/I0ETi0XQVVcCga97QEDsv2eomPDEoSb3KYo+aIX0IqHyhk0o9Jtwc2Y/JdjjQ+5ja/MVdSQBoZxP2MdQMehAWP0ycRUs13sr0rjImVEBkD/RQr1JYge07MqpJ9ywz4KlM6KGbl09l0D268Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from DM6PR11MB3625.namprd11.prod.outlook.com (2603:10b6:5:13a::21)
 by MN2PR11MB4534.namprd11.prod.outlook.com (2603:10b6:208:265::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6254.35; Wed, 5 Apr
 2023 15:15:52 +0000
Received: from DM6PR11MB3625.namprd11.prod.outlook.com
 ([fe80::7911:de29:ded:224]) by DM6PR11MB3625.namprd11.prod.outlook.com
 ([fe80::7911:de29:ded:224%5]) with mapi id 15.20.6254.035; Wed, 5 Apr 2023
 15:15:52 +0000
Message-ID: <36019eb3-4b71-26c4-21ad-b0e0eabd0ca5@intel.com>
Date: Wed, 5 Apr 2023 17:15:44 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.9.0
Subject: Re: [PATCH RFC] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
CC: "GONG, Ruiqi" <gongruiqi1@huawei.com>, Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>,
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>, Kees Cook
	<keescook@chromium.org>, <linux-hardening@vger.kernel.org>, Paul Moore
	<paul@paul-moore.com>, <linux-security-module@vger.kernel.org>, James Morris
	<jmorris@namei.org>, Wang Weiyang <wangweiyang2@huawei.com>, Xiu Jianfeng
	<xiujianfeng@huawei.com>
References: <20230315095459.186113-1-gongruiqi1@huawei.com>
 <b7a7c5d7-d3c8-503f-7447-602ec2a18fb0@gmail.com>
From: Alexander Lobakin <aleksander.lobakin@intel.com>
In-Reply-To: <b7a7c5d7-d3c8-503f-7447-602ec2a18fb0@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: FR3P281CA0065.DEUP281.PROD.OUTLOOK.COM
 (2603:10a6:d10:4b::20) To DM6PR11MB3625.namprd11.prod.outlook.com
 (2603:10b6:5:13a::21)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM6PR11MB3625:EE_|MN2PR11MB4534:EE_
X-MS-Office365-Filtering-Correlation-Id: 65c95da6-7e9b-4247-3f82-08db35e8a4c3
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: VocTWIf066vJ6DIEMUFFOfGC9WI4txMiNAVirxuY2DxXCx9EWwWG1ODtRz8z6KjG9lU9vjvv0B00G34MjdVxspNlHSuZ/7AtheoCLF87q/BC6mrpbQg1wAyicGuLefvGFXtqNNFkLemCfXzv/jXq7+oGHpmVh+d15qC8XV8V31yOmNAIYoskfkdQ5oztNc43POVo0YuAW4+eZYxaSXCz28O18MYkUj4k7BxjnUBy2ue6FhFPZAUCxRhM+fo00eywIJSCk0WhxSnAS5B2O6kiW7rX/EqaD8+ERfk4guNdWLpSUSGWx+CEDgb6dTDDiUrAloynZqTCGKn0OZ60sRrPyQpY5z8zV9g71WjCvzdZcsu/K6Us/NRJXlWD6vHJobSB/U/e6DYjY4L++2WNiFaD0VXcLsKm4x2A5TfhglcBVGDSul9nuPiU1oa8HLKSMSsywgDStteEAstbim6fOv7aQGiHeHpWqcBdjBhQ7+EkCvDRraoKHhdKWL6NeKPt/0fx8/3qU1iey/D0EHZR7m9u8NjxsRGZJoaBrhKJRtt+XSTZeSeRP8mqsH/VKVROq3QPuPNE53RbNuqCfJPQqPYu9a2Ta4iz5+MaEsoZbccg7+48HDIj2ebXk3oBsS/RMZTI8OljqqnBEDwPRi8vT20LEw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR11MB3625.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230028)(136003)(396003)(376002)(366004)(39860400002)(346002)(451199021)(53546011)(6506007)(6512007)(86362001)(26005)(186003)(5660300002)(478600001)(54906003)(316002)(8936002)(6486002)(66476007)(36756003)(7416002)(82960400001)(31696002)(6916009)(66946007)(8676002)(38100700002)(2906002)(66556008)(41300700001)(4326008)(6666004)(31686004)(2616005)(45980500001)(43740500002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?ZE9RTi8vUmxpc0tJTWNueVZVWmxaMTUydjc0Z2thS0Q1cm5pYVlCbVVCVy8z?=
 =?utf-8?B?dzJ6MXlBRlFObGw4YmM2L3JCWFV6UXgxV04yNlZ3ZmU1MFpraWI4Yll4TW1Z?=
 =?utf-8?B?dUJJVi9PMmw0UTAxQmEzbzlYVzdoeGFPVS9BdXFIYk53Mm1iMElrUUZPaG1U?=
 =?utf-8?B?V3orL2M4NVQzWlYwWkM0VHNEZHdteDJKNXRZOU9wTnc2MVJmR2RxUGpqaEFl?=
 =?utf-8?B?YzM3M3hUUVRvVVJjaU5GN0RnSXlBb3FkaVB5MnVPZjdtOVhkT0xQbGMzMHQy?=
 =?utf-8?B?WmFqRXhTakJFMFBMOGxrWGJoenZHOGdSVmhlY3pnOVp6TWdjalg5ajVuTWhZ?=
 =?utf-8?B?RnArQnpvUHhuT0VZckx5QXZpcW9ybHVmVTlNM1ExbEVhdWNpWGh0VlNXZmpK?=
 =?utf-8?B?Y1BoZFAvaStUd2MzemRxZFdIMkFFWGFpZDN2WDlKQTVLWWxvOFVuRVcyT3I2?=
 =?utf-8?B?amtxNEhLMGlMZ0xPYmtVN1VjdjR5K2VsQ21nczR0elNnT3ExeTFhK0xtbHly?=
 =?utf-8?B?WHVTamlQNDEvZm5OcUpYT3ZtdWZvaXgxc1JucDE0WUdFMmtNMG5uSmJma1pD?=
 =?utf-8?B?MHlBSDlYRlV4Qm04dUp2WXg4Y1RtQy9XcGIxYlUyVjdFdkRQODVSNEJCSE5p?=
 =?utf-8?B?K0U0bmEvdDVCUmF6NDhsQzA1VUt2enEyMWNwcFdmd3pqSEg3Y3l4TzJSUXYx?=
 =?utf-8?B?WE81WTVZaEhadEZXMEdKZ3ZhZGZFeGxkMXFpSnNsVVNqamJ3R1RBVk5OSTlu?=
 =?utf-8?B?N2dFMndTZ2pDenpFd3Q3aXB2NlMzN3plUURWMTFOMUFYeDZWbVY2eTkvRjg3?=
 =?utf-8?B?YzRRZ0U2MXJzd0RndkJ3VUtmREk0TzB5cjIxNXBWWHpGMVBVWkh0MXlKelln?=
 =?utf-8?B?bTZNc0RvVXdFdWtDejA4eCszT3VGS01NSlptUUxnVk12bm1ZYnFzOXpid3Vy?=
 =?utf-8?B?bHhKb0cycHNwSG00Q1NqbnUxTnRzQ2x6NTR4UEU0eDdqVUNmZW5IZmx0Qk5o?=
 =?utf-8?B?eUNpeXJJRngrbUUvODJQNnd0bVpQWThNeHdsbDMzUmlEbXZPY1lJWU5uQzJo?=
 =?utf-8?B?eTl2VFJvalhFeDFnUWZ5K0R3VklnOUR5YUxFZUlrVXZ5QW0zcVBYcysvWHh0?=
 =?utf-8?B?QW1DNVRxN2liMlM3anlOaVphblFXdi8wWG9pNHRLSUlDZ00ya1ZwdGkvZnlK?=
 =?utf-8?B?ZURRdE91WFBNdHlzLy8vMk1xdytJSzRHenZDQzBadm1LMWtLQzRNdUlER0o4?=
 =?utf-8?B?YlQ2VENDMWZTZndmMElPVnIvR1E2VTFzVXhPZXUrUW9DdG10VUxzdDluallm?=
 =?utf-8?B?cFArblYwSmQ0d1diRkRFR2FhWGxMWERHYnBic3gvTGlJZ1dwenFRa3VnUnY1?=
 =?utf-8?B?RUlvdW9yeHRBb0I0T2lmczBsdTRvN2M4M2c1VytNd2ZZQ2ZxWjRaeFcxUGZp?=
 =?utf-8?B?YkZvQXRzQzUraVA2dllUUXZDVDRDenlqUTJJblNXeXdSQ3VqZWhDSnk3TG16?=
 =?utf-8?B?bzliWDYvTkNmUmRrUTdOZEhubWhSaDY5MlUrTExhWFg5d25nS0srSjI5WjNC?=
 =?utf-8?B?SkJIRXhsNlJ2VzRzdlJPb0FMdVpLZzNFUU5sN25vUXdCUXUvY2NYQmRJVmNW?=
 =?utf-8?B?ZEJtRjBlKzY2d0paeXRpeVN4L1hwNEZlZmhtVkw1NGIydmwyL3VNUVozcGZt?=
 =?utf-8?B?cWo2NXd3bXFXNmRta1RlSE9PeUhrRGhYVmV4WEZKTG1xaXIraFlKY0d5THRH?=
 =?utf-8?B?eVlydzRpSmFObC90WUYya0xmVzA2MmNvR0JBWG04dUR5YlM1RDVWUk9iZGJr?=
 =?utf-8?B?NmxHdkN6THZlV005WGd5ekF1MktWUmxZSUdPNElncDQxbS9hWXh6UkduM091?=
 =?utf-8?B?amVwU1dzaWs5akdmWDJQM0ZDVlBNME9ndm5Jb3ZyeXVUSS9ReHNLWTQ2Uk1I?=
 =?utf-8?B?cTFNTDVRN1QyVjYyYjZ2bzhSK1FUcFFTMXpUQ0FTTmh1TU9TR1RnL1FGL1BE?=
 =?utf-8?B?cGxYWkRMRUNJV2psL0crVXkzSlcyTE5STG85MXlaamZOM3hVL1paaFZuOE43?=
 =?utf-8?B?U1FlaVZSR3p5S1BIbmM1WEU5WEJTWFhzUXJ3THVYSlUzbHFTNUlFVEV2TzFL?=
 =?utf-8?B?cURRSGl0bXorWlU4ZkI1eStLL0sxYXNteTF3TTR3Q1ZYNlNuZCtEeTlMZmtk?=
 =?utf-8?B?ekE9PQ==?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 65c95da6-7e9b-4247-3f82-08db35e8a4c3
X-MS-Exchange-CrossTenant-AuthSource: DM6PR11MB3625.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 05 Apr 2023 15:15:51.9118
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: B3IC8UCDPKjxeE36/sk+aZBmtzIFbuS/nzrFWpBOwSBRCvUZP2bLWWetEegqRFEOBbW9BhswKVnDgCDqpHw/2Sa7A7vsx/HSY+PUJ9q1oBc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR11MB4534
X-OriginatorOrg: intel.com
X-Original-Sender: aleksander.lobakin@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=m4MRUOwG;       arc=fail
 (signature failed);       spf=pass (google.com: domain of aleksander.lobakin@intel.com
 designates 134.134.136.65 as permitted sender) smtp.mailfrom=aleksander.lobakin@intel.com;
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

From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Wed, 5 Apr 2023 21:26:47 +0900

> On 3/15/2023 6:54 PM, GONG, Ruiqi wrote:
>> When exploiting memory vulnerabilities, "heap spraying" is a common
>> technique targeting those related to dynamic memory allocation (i.e. the
>> "heap"), and it plays an important role in a successful exploitation.
>> Basically, it is to overwrite the memory area of vulnerable object by
>> triggering allocation in other subsystems or modules and therefore
>> getting a reference to the targeted memory location. It's usable on
>> various types of vulnerablity including use after free (UAF), heap out-
>> of-bound write and etc.
>>
>> There are (at least) two reasons why the heap can be sprayed: 1) generic
>> slab caches are shared among different subsystems and modules, and
>> 2) dedicated slab caches could be merged with the generic ones.
>> Currently these two factors cannot be prevented at a low cost: the first
>> one is a widely used memory allocation mechanism, and shutting down slab
>> merging completely via `slub_nomerge` would be overkill.
>>
>> To efficiently prevent heap spraying, we propose the following approach:
>> to create multiple copies of generic slab caches that will never be
>> merged, and random one of them will be used at allocation. The random
>> selection is based on the location of code that calls `kmalloc()`, which
>> means it is static at runtime (rather than dynamically determined at
>> each time of allocation, which could be bypassed by repeatedly spraying
>> in brute force). In this way, the vulnerable object and memory allocated
>> in other subsystems and modules will (most probably) be on different
>> slab caches, which prevents the object from being sprayed.
>>
>> Signed-off-by: GONG, Ruiqi <gongruiqi1@huawei.com>
>> ---
>=20
> I'm not yet sure if this feature is appropriate for mainline kernel.
>=20
> I have few questions:
>=20
> 1) What is cost of this configuration, in terms of memory overhead, or
> execution time?
>=20
>=20
> 2) The actual cache depends on caller which is static at build time, not
> runtime.
>=20
> =C2=A0=C2=A0=C2=A0 What about using (caller ^ (some subsystem-wide random=
 sequence)),
>=20
> =C2=A0=C2=A0=C2=A0 which is static at runtime?

Why can't we just do

	random_get_u32_below(CONFIG_RANDOM_KMALLOC_CACHES_NR)

?
It's fast enough according to Jason... `_RET_IP_ % nr` doesn't sound
"secure" to me. It really is a compile-time constant, which can be
calculated (or not?) manually. Even if it wasn't, `% nr` doesn't sound
good, there should be at least hash_32().

Thanks,
Olek

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/36019eb3-4b71-26c4-21ad-b0e0eabd0ca5%40intel.com.
