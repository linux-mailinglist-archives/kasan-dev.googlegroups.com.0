Return-Path: <kasan-dev+bncBD6YJ5EM2QMRBUED6SRAMGQEUU5LU3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id C0DA56FF52F
	for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 16:55:13 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-3f33f8ffa37sf31619535e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 07:55:13 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683816913; x=1686408913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=u0koNBGRtOrP7nfQMBFYcs/YB0ogea8zxqAcTT9CNOg=;
        b=Vujt1B3bxwvSC2VCr9x4GBdKPQ9LiEkkS2U4XJydpOpvWJrxTQw9fotP8XLoLafrJ9
         fbnF4cOtV7oy0ugBJG/c/MxKQ+nSU33clX9mUNZHSUNWsmEPehIh/9wdJTiTgx71kRLl
         jH5iDIlprRXubIfABE5t2j/colx34Y8QczyYHNvtF9x+t+YpC+WCDCJEn7BmVneD42C6
         EFAP+PoVggTdAmyUzi9Yv9RHsftpQ90SaLHpUtd81SAg2wZcpMDyssj2FP4esJZBNIJH
         LXNp/TycXC+r42pfrcbVf+7FmMVx5Ms90DLOMCSoka4+xXXobVtZkW3T/gHWZ2gUkmem
         s/SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683816913; x=1686408913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=u0koNBGRtOrP7nfQMBFYcs/YB0ogea8zxqAcTT9CNOg=;
        b=DSGEwHlKw0DtGiEjPVFn1A9Oo97e/Re8uj8UUw3EstykwJqi36jlpdW+KoTwqWWmVD
         6tYdQcVA3RzlWuUTHZQXueGiFY/Go9sdHpIcRTkDPDpNwa3n6LSchzmvj4evoIXNeLSn
         lBILxraEwgJPLD8SZ3bbo1GvK6YjleO/4UIzemCxccYyxDnkHBdM4VrwiYaYa74Bn1/S
         gca5FIPohWT3u3OmlWkAXYq8UA1kUqWXddDVLM2GoI16oLioc2LSj+tvT6r8sbTbKEfZ
         V293ZMDCembmRj3E4CsGvvBINw8K8P4vt31Jrd5tR/TBrqEExzr8K0a4rPtFbec3V3IY
         /PPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyIOImo4RDOZQVVYiY++JrtzfvXwLBmXZ8Krojp7e0gdQYFc9WW
	bWSvJGIBR4MoIpumkD2yBlY=
X-Google-Smtp-Source: ACHHUZ4URihvUSquJMJ/2tj/r3O2OrNA3GjHLU/F8avvAvL45WDYqyH575npoXJy7OmXJo0yL3N8UA==
X-Received: by 2002:a05:600c:2158:b0:3f4:2148:e8de with SMTP id v24-20020a05600c215800b003f42148e8demr3079753wml.1.1683816912764;
        Thu, 11 May 2023 07:55:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34d2:b0:3f4:267e:9f with SMTP id
 d18-20020a05600c34d200b003f4267e009fls1636901wmq.1.-pod-control-gmail; Thu,
 11 May 2023 07:55:11 -0700 (PDT)
X-Received: by 2002:a1c:720e:0:b0:3f0:7e15:f8fc with SMTP id n14-20020a1c720e000000b003f07e15f8fcmr15651343wmc.14.1683816911527;
        Thu, 11 May 2023 07:55:11 -0700 (PDT)
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id o25-20020a05600c511900b003f4276a712bsi698396wms.1.2023.05.11.07.55.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 May 2023 07:55:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of aleksander.lobakin@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10707"; a="349359717"
X-IronPort-AV: E=Sophos;i="5.99,266,1677571200"; 
   d="scan'208";a="349359717"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 May 2023 07:55:09 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10707"; a="843998589"
X-IronPort-AV: E=Sophos;i="5.99,266,1677571200"; 
   d="scan'208";a="843998589"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmsmga001.fm.intel.com with ESMTP; 11 May 2023 07:55:09 -0700
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.23; Thu, 11 May 2023 07:55:08 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.23 via Frontend Transport; Thu, 11 May 2023 07:55:08 -0700
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.169)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.23; Thu, 11 May 2023 07:55:08 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=oRPuzpHWFq4oP56QBIl9cu5xutw/UHfhzPo32Jy/mBaHO0OY1Tsq2ra9qCWyKFFwfQQrCWsmRlg/h3L44hXjTm20cflaCjreWOGVjL+eaQFKQwgZPLY+ArEreLm0Lo9KuVfnDbyLYS9b4Gxw2RC/znsrs9w41ZZfQmUGZE9dgTmgthR3k1GhIr7WYcicxdnlXScHs+SMyVhTo9OW4rAD+qcRWtdA/KgyyMSdhRVl+g9hxELEp/P3owBEhvkxcMVRchvN9/G0XG0d5YowcgvGZqoeftQFWlmQcBZXiS10KiFsv3JUM8IWL6RcPe7vmoSGWN8lvIeBW6OJzCCMCJ1FHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Bak51/4RAowOJ93drTJqftvUYgcifJc+2PviNDDR8tg=;
 b=TxOMcEMWj9CMIM+ZaSTdXHeDR+cBQo9HR/jt6Joo1NFZyWA/VRDGYJMR2sYMsumAqaazKxy56Eqo1RVB7mFf1UteqSBbezkspzICWzUQ79RhuY6tlS5QggsrpLWEmN70ztGXOBWroN7vlPT43tBfYbuJmYT/LGue3/r+zVPNDn04pEuaQWlC/bnXSXvzhfn/Kg7cbpb/X64iLA2B2Gh0tFoMS3LI1V2yTLEYjVzyjyz1SBapKmBOb1AVpMD3aLDJSuulwrRmbL94kKwRPR+5nVVhqdybGc0s607C/9R4Ks+3q3RsdvnsSA7e85J6NbvUj77ZpcfY5hnhrcpTKRgNKw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from DM6PR11MB3625.namprd11.prod.outlook.com (2603:10b6:5:13a::21)
 by SA0PR11MB4573.namprd11.prod.outlook.com (2603:10b6:806:98::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6387.19; Thu, 11 May
 2023 14:55:06 +0000
Received: from DM6PR11MB3625.namprd11.prod.outlook.com
 ([fe80::64d9:76b5:5b43:1590]) by DM6PR11MB3625.namprd11.prod.outlook.com
 ([fe80::64d9:76b5:5b43:1590%2]) with mapi id 15.20.6387.020; Thu, 11 May 2023
 14:55:06 +0000
Message-ID: <75179e0d-f62c-6d3c-9353-e97dd5c9d9ad@intel.com>
Date: Thu, 11 May 2023 16:54:26 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Content-Language: en-US
To: "GONG, Ruiqi" <gongruiqi1@huawei.com>
CC: <linux-mm@kvack.org>, <linux-hardening@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	<kasan-dev@googlegroups.com>, Wang Weiyang <wangweiyang2@huawei.com>, "Xiu
 Jianfeng" <xiujianfeng@huawei.com>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
From: Alexander Lobakin <aleksander.lobakin@intel.com>
In-Reply-To: <20230508075507.1720950-1-gongruiqi1@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: JNAP275CA0017.ZAFP275.PROD.OUTLOOK.COM (2603:1086:0:4c::22)
 To DM6PR11MB3625.namprd11.prod.outlook.com (2603:10b6:5:13a::21)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM6PR11MB3625:EE_|SA0PR11MB4573:EE_
X-MS-Office365-Filtering-Correlation-Id: d7203700-0068-4f34-f379-08db522fb513
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: E9MXEcacRhxUDBWOCG9F/JQUK6f5Q8THZePQtJ7d3rRuTD1pviqK1zbg3xum3ZmS2fX6GnHRZQhH0RfNZaZ4nto7KkWGEoGFn30l4zMHI3mjA0PT/PWDk4WbRdTclUijER/iR0+1oHCA1Ch+dXHSGYyj/EaML8PqR9x4/Pfn3LR9nqUWxh5OIny63qN1U9jabmPRc1O7CJzewU82T00cj7OkirHKfE3nhTU4E+EMbece9//xmMd29AB5+XisG6ZkPCz71rPGFt5mR0tkKZxZzplcXi0+d3qIFQVYUNdwcWXNOuZsX3jTfVnRyfiIm6nGZWcz3IUQUi3KCn14+MCqv6Qd4MKmcmO2UrobjSIrkazYsRKT8Mj7arQOHg/+Rh8w0BFy6404k45CY1ZdLJlLbV/UNn2QsAkyfuRRpF/yRV5vGRCykThqWFSUMozh5RkR4ECD077cHSBaDi+B3Ha27PMr3r6G9iK0QyN+fq9693zIX4Ja4IqQx+sVFNIuCKhK8mgHLmC9zetzjL0yCVcb1sNygNsJzpHy0MsB6YHWoXqtBLla8agA/0+5ypiBBIfpsjoZC7Ta960QvWWGevP9yyf2Cz2urdmEbA7ETW4b5T71uDnMpCTaqbei09dU8KLf4W/8P69bE3LYlvvQyAdiDw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR11MB3625.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230028)(376002)(39860400002)(396003)(136003)(346002)(366004)(451199021)(41300700001)(2906002)(478600001)(83380400001)(6512007)(6916009)(66556008)(2616005)(6486002)(66476007)(4326008)(6666004)(186003)(66946007)(54906003)(316002)(26005)(5660300002)(6506007)(8676002)(8936002)(38100700002)(31696002)(82960400001)(36756003)(86362001)(31686004)(45980500001)(43740500002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?L1JzUjVOdGs4dHB1UlRJeGRxZW5LSEhXQVBGVDVuQzcxQjltdVpKOGZuMEVy?=
 =?utf-8?B?b0M4c1p1MWFqendnc1lqdmdxdEgrdFB6S1Vta1ZSM0ZWY1VaQnRRSEdNQnlR?=
 =?utf-8?B?SEJsTDNHRzZJcW5PeEF5TWp0bWJURlRPK3R1Yk1nY2Q3NTBxT0xLR1lZdW1r?=
 =?utf-8?B?c01iY003b2VGZlU1b3hNZ1ZaMkI3NWYxbzIzMnZULzlUZGU3ZHRadU51ZXNz?=
 =?utf-8?B?OThCZlArMkR2SWJzY0hTUjBuMG1XUWtCY3ZRc1Vpb1pMTEF1dHk3ZExHeVd4?=
 =?utf-8?B?U2lBT0ZxVUZoZHduK25ETzVBTzNhYWl3T1MvVlRjTS81TUNBQWxwUlllN2hZ?=
 =?utf-8?B?UzRpWEtOclBxVVpmMVlCbDdKaGp1K3dmK0RjWkpOVlhjaDZrd0FhbHJqaHlI?=
 =?utf-8?B?L3VEcVpuS3Y0bXpGZmdRY1RzQno2eDgzWTc2UmR4eTdvNXBpbkZvWXVVR0lr?=
 =?utf-8?B?RVBWVHpleGJkTkkvSU8rZ1R3dEN1aTc2VUk5Y1pGdDYzYmdYOFBmaTlpMjNU?=
 =?utf-8?B?VStseUVLRlRZMTlKYlZ2bDdPSjlnbjlXcmg1b0JoNXhZUkNOMTRmd2ZxUEFH?=
 =?utf-8?B?UFlBSmFSdHc4SEFRRkl1bXBGMXRFK3ZYN202TldDWXFiWk5ZalJEakVEYUhD?=
 =?utf-8?B?b1o5NWxIcE9uNDI5dXBEMlFPNW5MUmIvNGM1dW1VSXFXcXg2eFkwWmN2bmJu?=
 =?utf-8?B?VEFkNi9NcWZPci8rTVE5RVAwZlI0Y2RQNWl6aDBlTmpwa290N1R3QUY2d0F0?=
 =?utf-8?B?R1FiWnErODJGd1ZaVkRaTzZCWUtqSFR5OGk0LzFtdGQ0QlhXc1plM2JuZDkx?=
 =?utf-8?B?bkJNZU56NVQ5ZHB6UnRXU21Qa0lQbE1XQWNBTjhqMUpIb1Y1eThJVjBzQ29P?=
 =?utf-8?B?bHRGQTVNRVorR2dpOWJWR2JxTWZITXZjT3ZIMXBSVEFma1Q0Zm04a3FLQjJR?=
 =?utf-8?B?OXVKdlZodE84SjFQVnUyaERPRk1BWW4xMDZJQjB2Q3ZqaHJUZE1lVm94eU5J?=
 =?utf-8?B?MzNPQk41Z0x4QzF1cWVQZEZySlV5T1BGV0xHeGRxWUJSRmFhQmlPMk9YbEYz?=
 =?utf-8?B?b2ZCT29RbnVncVNhS2xMeHR1cGVFZW16K3l1NHdZMkpDbm9Dd1p1RzM3d3I0?=
 =?utf-8?B?a1FXVzEzOFpmckVZS25JMmVZcDdxRHZvRlpJZi80TWZDUHdITWNyZnNsNWpo?=
 =?utf-8?B?Zi9aQ2xkMzRnWUQ0SVcybUJzSVA4YUpNUFFNSEdOTnJaYjN4UHB3NGhQQk9h?=
 =?utf-8?B?V0Y0cDd1cEgxT2lOcStjTVhTS3p3QUlTSFRQTDBaZm5LZ1RqZU9jSk4wR2My?=
 =?utf-8?B?ZW1lODZjNCs3ZUdWcWJoWUR0VEhzMTBrL2dPUnBMR0xSZ3dIRlVIL1JybFlD?=
 =?utf-8?B?STZKczlNanJzWXQ3bUdXTmVmRFZHZE9yQW1BblN5M3IvQ3dsNzhqamR1Um1j?=
 =?utf-8?B?cTdiamh5d1RoQk9MakdOcWZmSTROMGNoYzhscGFWSEVNamd5WDljVGN3Vno3?=
 =?utf-8?B?c1VyVFBUMDY0ZS9UdjB4SEFPTkxLTjhoRFZmTkpQTXdDelVlMjZsWUdHdjB1?=
 =?utf-8?B?ZWpzV2NzdjdsYjlmVWJ5aU41S1ExOTd1c0tWeFpOTWc1WUo0WklCU1hRaW5r?=
 =?utf-8?B?aklBTG5yL1BDSlJoc2JaRjBydk9SY0JaQXJyRUhXSDByR01mc3dCV1NHNEhP?=
 =?utf-8?B?L01DZ1REdmgyb2VscGFPb1BKWU9zOHNvQ1h5VUlnSkNmRW1IRUErSTV3MklS?=
 =?utf-8?B?VmY4WjZQc1BjM2xBVUJWeUlBVU5lcnBaV0FSZWErcEpUVHJIemxGdDNRcWFs?=
 =?utf-8?B?SGFrcGJXSjlyTldyblNJODh4Z3Z6N3doazAzSk9oOXlrV2hKVmNWNlJoOHVu?=
 =?utf-8?B?UStBZE5uNWFSTjRadW1WaWFMQUFPSTJERHZORkt2MzRsRDFmdnBHNGhSWXJq?=
 =?utf-8?B?Q1FYN2N6cHM0cTN0VHFQNEtUblVhWWo3c0haeCtOZ2ljbjNGeWw1L3lhTjJk?=
 =?utf-8?B?aUNQVGtsRHpBUHpjWEVmaFRqYlJjdEtWRzFLdEdlblBjVWdLeFl2V1d4RXN2?=
 =?utf-8?B?SXB6VnB2Q3pUMEtOeGFPbG13cWw4UFJ2L1R6ai9EL0tEakE3TVY1VlBRdFhM?=
 =?utf-8?B?dmQzbTE0ajI3cEFLT3FkWmhPSU5obHlvR255ZGJxeXc3UlB1MVlHNm0wRXJq?=
 =?utf-8?B?Smc9PQ==?=
X-MS-Exchange-CrossTenant-Network-Message-Id: d7203700-0068-4f34-f379-08db522fb513
X-MS-Exchange-CrossTenant-AuthSource: DM6PR11MB3625.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 May 2023 14:55:06.2269
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7QkvnENllz/Gto05Vqmz5Me6HgNnBJswzckfHFw1LH7ODlEbsJ18KjLmxT00EvS12KYAgKZWPX+0PqvNcylJVvlX+zPa3tEyYUl7hViuDlE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA0PR11MB4573
X-OriginatorOrg: intel.com
X-Original-Sender: aleksander.lobakin@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="TV/+aPqP";       arc=fail
 (signature failed);       spf=pass (google.com: domain of aleksander.lobakin@intel.com
 designates 192.55.52.120 as permitted sender) smtp.mailfrom=aleksander.lobakin@intel.com;
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

From: Gong, Ruiqi <gongruiqi1@huawei.com>
Date: Mon, 8 May 2023 15:55:07 +0800

> When exploiting memory vulnerabilities, "heap spraying" is a common
> technique targeting those related to dynamic memory allocation (i.e. the
> "heap"), and it plays an important role in a successful exploitation.
> Basically, it is to overwrite the memory area of vulnerable object by
> triggering allocation in other subsystems or modules and therefore
> getting a reference to the targeted memory location. It's usable on
> various types of vulnerablity including use after free (UAF), heap out-
> of-bound write and etc.

[...]

> @@ -777,12 +783,44 @@ EXPORT_SYMBOL(kmalloc_size_roundup);
>  #define KMALLOC_RCL_NAME(sz)
>  #endif
>  
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +#define __KMALLOC_RANDOM_CONCAT(a, b, c) a ## b ## c
> +#define KMALLOC_RANDOM_NAME(N, sz) __KMALLOC_RANDOM_CONCAT(KMALLOC_RANDOM_, N, _NAME)(sz)
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 1
> +#define KMALLOC_RANDOM_1_NAME(sz)                             .name[KMALLOC_RANDOM_START +  0] = "kmalloc-random-01-" #sz,
> +#define KMALLOC_RANDOM_2_NAME(sz)  KMALLOC_RANDOM_1_NAME(sz)  .name[KMALLOC_RANDOM_START +  1] = "kmalloc-random-02-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 2
> +#define KMALLOC_RANDOM_3_NAME(sz)  KMALLOC_RANDOM_2_NAME(sz)  .name[KMALLOC_RANDOM_START +  2] = "kmalloc-random-03-" #sz,
> +#define KMALLOC_RANDOM_4_NAME(sz)  KMALLOC_RANDOM_3_NAME(sz)  .name[KMALLOC_RANDOM_START +  3] = "kmalloc-random-04-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 3
> +#define KMALLOC_RANDOM_5_NAME(sz)  KMALLOC_RANDOM_4_NAME(sz)  .name[KMALLOC_RANDOM_START +  4] = "kmalloc-random-05-" #sz,
> +#define KMALLOC_RANDOM_6_NAME(sz)  KMALLOC_RANDOM_5_NAME(sz)  .name[KMALLOC_RANDOM_START +  5] = "kmalloc-random-06-" #sz,
> +#define KMALLOC_RANDOM_7_NAME(sz)  KMALLOC_RANDOM_6_NAME(sz)  .name[KMALLOC_RANDOM_START +  6] = "kmalloc-random-07-" #sz,
> +#define KMALLOC_RANDOM_8_NAME(sz)  KMALLOC_RANDOM_7_NAME(sz)  .name[KMALLOC_RANDOM_START +  7] = "kmalloc-random-08-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 4
> +#define KMALLOC_RANDOM_9_NAME(sz)  KMALLOC_RANDOM_8_NAME(sz)  .name[KMALLOC_RANDOM_START +  8] = "kmalloc-random-09-" #sz,
> +#define KMALLOC_RANDOM_10_NAME(sz) KMALLOC_RANDOM_9_NAME(sz)  .name[KMALLOC_RANDOM_START +  9] = "kmalloc-random-10-" #sz,
> +#define KMALLOC_RANDOM_11_NAME(sz) KMALLOC_RANDOM_10_NAME(sz) .name[KMALLOC_RANDOM_START + 10] = "kmalloc-random-11-" #sz,
> +#define KMALLOC_RANDOM_12_NAME(sz) KMALLOC_RANDOM_11_NAME(sz) .name[KMALLOC_RANDOM_START + 11] = "kmalloc-random-12-" #sz,
> +#define KMALLOC_RANDOM_13_NAME(sz) KMALLOC_RANDOM_12_NAME(sz) .name[KMALLOC_RANDOM_START + 12] = "kmalloc-random-13-" #sz,
> +#define KMALLOC_RANDOM_14_NAME(sz) KMALLOC_RANDOM_13_NAME(sz) .name[KMALLOC_RANDOM_START + 13] = "kmalloc-random-14-" #sz,
> +#define KMALLOC_RANDOM_15_NAME(sz) KMALLOC_RANDOM_14_NAME(sz) .name[KMALLOC_RANDOM_START + 14] = "kmalloc-random-15-" #sz,
> +#define KMALLOC_RANDOM_16_NAME(sz) KMALLOC_RANDOM_15_NAME(sz) .name[KMALLOC_RANDOM_START + 15] = "kmalloc-random-16-" #sz,

This all can be compressed. Only two things are variables here, so

#define KMALLOC_RANDOM_N_NAME(cur, prev, sz)	\
	KMALLOC_RANDOM_##prev##_NAME(sz),	\	
	.name[KMALLOC_RANDOM_START + prev] =	\
		"kmalloc-random-##cur##-" #sz

#define KMALLOC_RANDOM_16_NAME(sz) KMALLOC_RANDOM_N_NAME(16, 15, sz)

Also I'd rather not put commas ',' at the end of each macro, they're
usually put outside where the macro is used.

> +#endif
> +#else // CONFIG_RANDOM_KMALLOC_CACHES
> +#define KMALLOC_RANDOM_NAME(N, sz)
> +#endif
> +
>  #define INIT_KMALLOC_INFO(__size, __short_size)			\
>  {								\
>  	.name[KMALLOC_NORMAL]  = "kmalloc-" #__short_size,	\
>  	KMALLOC_RCL_NAME(__short_size)				\
>  	KMALLOC_CGROUP_NAME(__short_size)			\
>  	KMALLOC_DMA_NAME(__short_size)				\
> +	KMALLOC_RANDOM_NAME(CONFIG_RANDOM_KMALLOC_CACHES_NR, __short_size)	\

Can't those names be __initconst and here you'd just do one loop from 1
to KMALLOC_CACHES_NR, which would assign names? I'm not sure compilers
will expand that one to a compile-time constant and assigning 69
different string pointers per one kmalloc size is a bit of a waste to me.

>  	.size = __size,						\
>  }
>  
> @@ -878,6 +916,11 @@ new_kmalloc_cache(int idx, enum kmalloc_cache_type type, slab_flags_t flags)
>  		flags |= SLAB_CACHE_DMA;
>  	}
>  
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +	if (type >= KMALLOC_RANDOM_START && type <= KMALLOC_RANDOM_END)
> +		flags |= SLAB_RANDOMSLAB;
> +#endif
> +
>  	kmalloc_caches[type][idx] = create_kmalloc_cache(
>  					kmalloc_info[idx].name[type],
>  					kmalloc_info[idx].size, flags, 0,
> @@ -904,7 +947,7 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>  	/*
>  	 * Including KMALLOC_CGROUP if CONFIG_MEMCG_KMEM defined
>  	 */
> -	for (type = KMALLOC_NORMAL; type < NR_KMALLOC_TYPES; type++) {
> +	for (type = KMALLOC_RANDOM_START; type < NR_KMALLOC_TYPES; type++) {

Can't we just define something like __KMALLOC_TYPE_START at the
beginning of the enum to not search for all such places each time
something new is added?

>  		for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
>  			if (!kmalloc_caches[type][i])
>  				new_kmalloc_cache(i, type, flags);
> @@ -922,6 +965,9 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>  				new_kmalloc_cache(2, type, flags);
>  		}
>  	}
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +	random_kmalloc_seed = get_random_u64();
> +#endif
>  
>  	/* Kmalloc array is now usable */
>  	slab_state = UP;
> @@ -957,7 +1003,7 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller
>  		return ret;
>  	}
>  
> -	s = kmalloc_slab(size, flags);
> +	s = kmalloc_slab(size, flags, caller);
>  
>  	if (unlikely(ZERO_OR_NULL_PTR(s)))
>  		return s;

Thanks,
Olek

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/75179e0d-f62c-6d3c-9353-e97dd5c9d9ad%40intel.com.
