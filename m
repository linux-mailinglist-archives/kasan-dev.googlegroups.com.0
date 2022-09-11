Return-Path: <kasan-dev+bncBDN7L7O25EIBBRN76WMAMGQE6Y67HSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EC5C5B4B8C
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 06:10:46 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id a5-20020a05651c210500b0026bfaff5357sf356280ljq.9
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 21:10:46 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=qcrvGPddgtcsNqmLOQRNmDDCzZqoGqyycTluOX8ZxAM=;
        b=g/Z3Yddq7iZIPH70+DXMw+IdjA+QmZdJ01EmCzy4LyVbkVHfjFh3KwSoa0tapEPAuX
         W9re6O+wvnqTLA4bUjk4m8ozyM7mwFtf7w1RgyvUI070uecHv3CnPWHMgyX0R0uxOaxb
         haD3XmB10TmAPuwcOKg4eAaFtUqVVhDBWYxY1EDrxf1XXMPkoGxx+WfjQRp4URQj9dA3
         qcK29O/aKFPkTmeDzRwjdufbVRX/y1M/Uh/RAARjJ6iHkrYf7E30YW/HI9Xy/s9Qbkyg
         pu1eaARabVNZy+p0rmVbkpHyNuIp5FOq/GBIc+gwtu0rmROhUP2tQALAuPImPq6Nq80r
         h8/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=qcrvGPddgtcsNqmLOQRNmDDCzZqoGqyycTluOX8ZxAM=;
        b=byLOxlSqhWZCikUGnnXmPv/EXiFMc7xg4SmOL3a8UicDjvxbDVhDiAgNRpI92wwB7s
         vuJyIc7n++ULYV3o9ZV7PDOX0Uob/GOxGOYU1zwd4jMYL2Pwm0LrR+1ybkkqSH2Od2T4
         89qEzsRT94Dvesm2lSvE2Y8/NIbOckEsWOxB5l+jqkCjSbX/riqVkFyoSKWUqUgzZgQn
         JX1lAKkVHgvG6MY1NNmN4Im+jUZ/bu4vD6myWC7l2uS0Cw7sC+R/SyaVnVDfHB4HAl0n
         EUqydzYn9zyhA3HacwGL0u9k/lJw097PUSTCg7wxREEABXF9nAGZfZqQJC3GbXgui0ui
         OQYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2+c4b7iIpdWptedS7/QQiiTYuVggmKdscyhaVkTEGaB4mvuoZq
	uI13Cp2/gKoeB7Th3eBGJbs=
X-Google-Smtp-Source: AA6agR62t3RYAZnaeHSFPsLCPLMv9uZu29qd4qitMrWPhy0aKN0Wi1vHTAVDq2r09rw6WJUzH06v9Q==
X-Received: by 2002:a2e:aa1b:0:b0:26b:3f50:1792 with SMTP id bf27-20020a2eaa1b000000b0026b3f501792mr4551194ljb.184.1662869445730;
        Sat, 10 Sep 2022 21:10:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls275468lfo.1.-pod-prod-gmail;
 Sat, 10 Sep 2022 21:10:44 -0700 (PDT)
X-Received: by 2002:a05:6512:1112:b0:499:df7f:5830 with SMTP id l18-20020a056512111200b00499df7f5830mr1160847lfg.24.1662869444556;
        Sat, 10 Sep 2022 21:10:44 -0700 (PDT)
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id k13-20020a2ea26d000000b00263ee782b8fsi119435ljm.1.2022.09.10.21.10.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 10 Sep 2022 21:10:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6500,9779,10466"; a="277426123"
X-IronPort-AV: E=Sophos;i="5.93,307,1654585200"; 
   d="scan'208";a="277426123"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2022 21:10:41 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,307,1654585200"; 
   d="scan'208";a="593082742"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orsmga006.jf.intel.com with ESMTP; 10 Sep 2022 21:10:41 -0700
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Sat, 10 Sep 2022 21:10:41 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Sat, 10 Sep 2022 21:10:41 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.101)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Sat, 10 Sep 2022 21:10:40 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Gkcs39o8h6OcUSZ5vdMxhDbZ6q+eOk+unZya0nB9y16scyD4matYI1Y9Pt/7gcFKcjvtU2sMfIcbtn5MUU/zLKFqx/6xa6dgLS3b9lI7u9QQt8xD2rQY4v3mRL1IL834hAB18c4DloHs7ctzgarh0f9xYgVlAH/iA90PXuiaNwLSd7ULWqlOptyXhUyvFzO2gnMc7DUD+PCAKNDOuDlMLAWAsp1b3+zudLTdrph8HKDamOguipNCJtJT5tE5minsbFaK+YMiIY9zHqaj5VqfSjB98ftDER4R7BxW0fOrE+5RPadXw1SjowoaNmSB6Nzb04ZUQdjad9itBwlN4/xaWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1wm+3AixhnI4O6cJ+vka+Ch5GXjbw/RBYC0FX3OYkS0=;
 b=O2LYUyABFDrU6cO4kDTe+62H9clzs/q/ZUo5fQbsMSWzgUqdA4sBOUsiwQ/zOkVYaqDP90zjMgNrGB2udvxBOrPWmp7uybZYVV8qggoXN7xkOE+vnrnXK3uCHwxFxnVCwWRawLfr3P3ZxBY9ONpA88WVsDajW46gKmX3ViO7buKou3bAPSKOGJY45Lp8n+12fRNb6DWxrL6lLrapr/NEmEAO4qn0CXkwJyDcL2iIuG9kH8egR0OzoJqZ131E4zYqPEfwTokQFPgJCyrGPgrG5CilrhsCbDbVLJhaWg4bF4vYvJCk0DWDjqdt0jkBXDpE0iiDDAIl799P7gCxZgcfCA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by IA1PR11MB6220.namprd11.prod.outlook.com (2603:10b6:208:3e8::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5588.18; Sun, 11 Sep
 2022 04:10:37 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e%7]) with mapi id 15.20.5588.015; Sun, 11 Sep 2022
 04:10:37 +0000
Date: Sun, 11 Sep 2022 12:10:01 +0800
From: Feng Tang <feng.tang@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>, "Hansen, Dave" <dave.hansen@intel.com>,
	Linux Memory Management List <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v5 4/4] mm/slub: extend redzone check to extra allocated
 kmalloc space than requested
Message-ID: <Yx1fmSyCNDwDgfqk@feng-clx>
References: <20220907071023.3838692-1-feng.tang@intel.com>
 <20220907071023.3838692-5-feng.tang@intel.com>
 <CA+fCnZfLCe8fhQ5UAyF1LwZuMCfbsoEXDmX3deaW6i_E5UE60g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfLCe8fhQ5UAyF1LwZuMCfbsoEXDmX3deaW6i_E5UE60g@mail.gmail.com>
X-ClientProxiedBy: SG2PR02CA0124.apcprd02.prod.outlook.com
 (2603:1096:4:188::9) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 3be1509c-44d6-40d7-55e0-08da93ab9496
X-MS-TrafficTypeDiagnostic: IA1PR11MB6220:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: fUunN1c2AGrZU6sFtsvxAisdri3eBsE4FMg2lG+8aRvNVSXYTdyUh2gJXrYcFqrhzS+KYBQctMxrwpDXN4c7pejzg2vTtQsTLvZ9eZfxByr3zHKzxHaFv98YTTH7iNYbRCnGZjz2TBX2/ycfzlOqm8Def+ptjoRHDegrdWVtesgHCRQzfe37UEgmKE1toaSjDyRk+7AUv6glcG34SJoqXAVWRWsUQ6L5i24aRJtbrz2s1W+k6EIkpgNAHTgdCMb0DaUuLLCB/shBDe3n3oi8Ok6v5qPcQMUBjA8MHChlRkEQngamdrSYlt7PmWBF3vpl9sBA3YGBMRQDdXlb70puIc6snx/EaoJ65SGa+ASYZZr66F+sEqjjItrgFObACXz0FD492Z11KqjqKuN3dHiMM46oLIMsesj/o2UJvxnUAJy3T8Jvnii0udGrFjEsNroNdvICLAakybnr+Ji4OOp8UFH7RhuPt7opUf1SNO1gciyMIpo7MSiQlWgosW84tGQfJ1tGcIie8i5IEpI4EMeaFYmsvL76HbtAPBNFacHefPurzJwjJ9ZLOJg+R7bGWhLW+CPIObLZ+WvriIaZnQ9s4uJb2q+GE71VNIlEVmODhYihZP2cOmR7o9A12EH2K8GRppSzjeKXgI7UrM9oO+4H9h9DBQri86hyUKvrSXjEM3wCb4KJMgUKeT7cP3tzTaAx78/ZEhmC7+tZAxDNcWxb+A==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(346002)(39860400002)(396003)(376002)(366004)(136003)(38100700002)(4326008)(82960400001)(83380400001)(8676002)(66476007)(5660300002)(66556008)(316002)(66946007)(33716001)(478600001)(26005)(6512007)(6506007)(41300700001)(53546011)(6666004)(6486002)(186003)(9686003)(54906003)(6916009)(2906002)(7416002)(86362001)(44832011)(8936002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?8thG6obMgTzlScHkGQqDZGGDVZvr/rYVtGFNaBiWDPTnpTM9anDD0BeIGIBE?=
 =?us-ascii?Q?NmJ7RmEpqw/S2bw6d03gGONpDxPncL4tyD2+q27+LoMHcXdUcHFfVFCJg/qp?=
 =?us-ascii?Q?2ocf5ssi8t+bYCX+U7EbG26bNL/atKaRZSvef7sIwrSCnjIuPhIDCaDvjGji?=
 =?us-ascii?Q?g5QCK0wXZVI2nPmwLshvSm4n6sqWRKZ+iMgQBbWnJWzmOpR5Yr1ioTzdCgey?=
 =?us-ascii?Q?2J7DEtMQRiwEIE4aIi1L7og42i2snnDW6LZEv12v4guGEFXv4p6OACUsx1ZR?=
 =?us-ascii?Q?C4wAGxlGCDL6x87auH2AEVQTaMI+RmDHslPLboKiTWu9d1OoABizrlFVma/U?=
 =?us-ascii?Q?rywVtT+s8eI5dk6tCdZODcCnU0exjplND2M7hv477yYPPHDIMab6hszdk0oz?=
 =?us-ascii?Q?bNExBmh6pTOCUMkIMXl55L7NjDnqzgmPBPFfha3NaQaaxLswmjgovmLvfUkG?=
 =?us-ascii?Q?b8rE2yDKoHrtbSB1H45ui4ty/VO6/mM7SyI8LfqJiGaMvx5GD8vUxhlgJDIc?=
 =?us-ascii?Q?hWvK7o3eJqClX+n/LamYy+p58jNWeC7qoU6Ov6/nA+DEq+wPFwJ9ZixYCd4p?=
 =?us-ascii?Q?GPbV8+DdAyE7vgBwpYkRqFUA4QehLH3N/we4EML24c+uQVp5mgCBkIixHlhe?=
 =?us-ascii?Q?sPDZ3GwBfWvNQeXE6vhp+vSpP6gtm2hJQtPTIFZ104SjIf1BISocAGj1R0bz?=
 =?us-ascii?Q?mC2ihtgVTfOH7OBDF+pz+QSdSYPAlhFxdpfbO6yI/m/UnCuK7fWVuAyI1TAj?=
 =?us-ascii?Q?LIAROjUYnzKojEdLUI+iteUuTuuEeY4mJtHkQlOyDdfJAFHBpn2+0Mme8CqO?=
 =?us-ascii?Q?i6/ltxXiqdSqO13nVK9WtvbAt87QYSyLS+ggiZCbpl2lcnFahK6CtOO+ppVk?=
 =?us-ascii?Q?LN2KiCJnWn+jj0IcIk7ERWmgp5uR2IX0IQDnjbX4Iao+wDkfX5Fs9Cb1ETa0?=
 =?us-ascii?Q?RVkk/bxufTJ5e3Z62Kimm8kP5+Ka0laXqClEeO9+okjr/wm0jToK0AOfXWRT?=
 =?us-ascii?Q?7vJYe3xhjZzNXO+cUfjNjHyeDQwKuo5am9nzy2HaYkpvmdIePXO0AQG994Gx?=
 =?us-ascii?Q?csPe0QolO+eqEHA1msKuotTCvXkkDxLfTfjVBV2Uxxh4Zn1qXjX56bVg4t49?=
 =?us-ascii?Q?CwgiK9VOTdYpntuGWdTLrvABn+Y/EZfePFmAPi/4OilzO0dvXpHEyvuS0NGC?=
 =?us-ascii?Q?cMBiXuOZ+je7sfDZZyECfRQN1fTnyKnLdVUkAg37WAQGX1ijsGj8RxPQKYB4?=
 =?us-ascii?Q?vCDr07k5TopRqGA/sx0/p9/9qQYwatDAvC+oD+y2nddyA4eQgM9yJ4HA93kc?=
 =?us-ascii?Q?2X3U55wczL8aVhGT3vM8RhHf56Ntm+WmJWHOyemHEgICS/EF23ysJuhIZ5bz?=
 =?us-ascii?Q?k/qgzgkds+zBbVGjLw+j9a4bKADVgMVrNtadwM1IfVq6L9RzYyIwjwakCbRZ?=
 =?us-ascii?Q?3eSKdpKGSgRsCEWJQYlrTNkDNob6MJlJpg9QLInqAgPJ/wAgCmZiSz3L4r+u?=
 =?us-ascii?Q?S1yYB/N/BXrO0jvbyrFr6koHdTwr+EUdmx22qyetTF5qmjSQV4UmlsdL3bMd?=
 =?us-ascii?Q?NK4qJsr7a3cff1C4QHzJNXSsM37GLuXr4I49PlWL?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 3be1509c-44d6-40d7-55e0-08da93ab9496
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Sep 2022 04:10:36.9323
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: DCBjFAnFLbSLhg2S/WG2nbHKyY+0LP+7A/+M/pnrBYdpEvOoklX52hW3TjO2yrxU8LanZ2N4G0G2hcDgeEGHxw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB6220
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=a1akDjOa;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.136 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Sun, Sep 11, 2022 at 07:12:05AM +0800, Andrey Konovalov wrote:
> On Wed, Sep 7, 2022 at 9:11 AM Feng Tang <feng.tang@intel.com> wrote:
> >
> > kmalloc will round up the request size to a fixed size (mostly power
> > of 2), so there could be a extra space than what is requested, whose
> > size is the actual buffer size minus original request size.
> >
> > To better detect out of bound access or abuse of this space, add
> > redzone sanity check for it.
> >
> > And in current kernel, some kmalloc user already knows the existence
> > of the space and utilizes it after calling 'ksize()' to know the real
> > size of the allocated buffer. So we skip the sanity check for objects
> > which have been called with ksize(), as treating them as legitimate
> > users.
> >
> > Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > ---
> >  mm/slab.h        |  4 ++++
> >  mm/slab_common.c |  4 ++++
> >  mm/slub.c        | 57 +++++++++++++++++++++++++++++++++++++++++++++---
> >  3 files changed, 62 insertions(+), 3 deletions(-)
> >
> > diff --git a/mm/slab.h b/mm/slab.h
> > index 20f9e2a9814f..0bc91b30b031 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -885,4 +885,8 @@ void __check_heap_object(const void *ptr, unsigned long n,
> >  }
> >  #endif
> >
> > +#ifdef CONFIG_SLUB_DEBUG
> > +void skip_orig_size_check(struct kmem_cache *s, const void *object);
> > +#endif
> > +
> >  #endif /* MM_SLAB_H */
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 8e13e3aac53f..5106667d6adb 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -1001,6 +1001,10 @@ size_t __ksize(const void *object)
> >                 return folio_size(folio);
> >         }
> >
> > +#ifdef CONFIG_SLUB_DEBUG
> > +       skip_orig_size_check(folio_slab(folio)->slab_cache, object);
> > +#endif
> > +
> >         return slab_ksize(folio_slab(folio)->slab_cache);
> >  }
> >
> > diff --git a/mm/slub.c b/mm/slub.c
> > index f523601d3fcf..2f0302136604 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -812,12 +812,27 @@ static inline void set_orig_size(struct kmem_cache *s,
> >         if (!slub_debug_orig_size(s))
> >                 return;
> >
> > +#ifdef CONFIG_KASAN_GENERIC
> > +       /*
> > +        * KASAN could save its free meta data in the start part of object
> > +        * area, so skip the redzone check if kasan's meta data size is
> > +        * bigger enough to possibly overlap with kmalloc redzone
> > +        */
> > +       if (s->kasan_info.free_meta_size_in_object * 2 >= s->object_size)
> 
> Why is free_meta_size_in_object multiplied by 2? Looks cryptic,
> probably needs a comment.
 
OK, will change, I didn't make it clear. 

The basic idea is kasan's free-meta could be saved in object's data
area at offset 0, and it could overlap the kmalloc's in-object
redzone, which can only be in the second half part of the data
area. And as long as kasan's free meta sits in the first half,
then it's fine.

Maybe I can change the check to

  if (s->kasan_info.free_meta_size_in_object > orig_size)
	...

Thanks,
Feng

> Thanks!
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yx1fmSyCNDwDgfqk%40feng-clx.
