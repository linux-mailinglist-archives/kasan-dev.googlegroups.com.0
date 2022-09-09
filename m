Return-Path: <kasan-dev+bncBDN7L7O25EIBBVWY5OMAMGQEVC3V26A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 803485B2FD9
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 09:33:43 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id z6-20020a05640240c600b0043e1d52fd98sf635249edb.22
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 00:33:43 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=i9/9Ze4FmfcwUmA1T0JzcOJ+5R3Ukyfw/UnKFpVOliI=;
        b=sD2de7teHwyNPGK/efu+aNeyKOtdRKgjlZoyF0DIEbL29A+5odLntLdwpbYPHS4GmT
         fGR4TiuaTqs3Sy9hDtPIRaPF+st5IRbLA/imqKH96O0rsYwSFl5nKCGp/6tpIyOnPzxT
         hhUu1heGbRoyRFzY1OwktL4X6IcB5/9hHK81gG1XkZk2axda6m+WyZDuVvTcsGXAwQpN
         SgUuBLsiZO6jGiwupbxtoB5ps61I3vAnrk+PETg+fdkZVuO9WfO1m3MfRUC3oyxE4F4X
         YcKCDABJuFQhDfWdopSU09/hLDBinPhtaMr+Bsi1s6OSomKiNjZGIBFp0CJeWLEXfYkH
         kRCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=i9/9Ze4FmfcwUmA1T0JzcOJ+5R3Ukyfw/UnKFpVOliI=;
        b=Z3C+aI1yFx72GtQDJVbDcyj4o/0hdMF/YBQX8KXHoF8x44Rwr3eNV/9PMfZudINNRv
         pW9Wt80w6r1/XPfSAA+n6m+GVBs+rUd9QOi4WWGRdLaQtLMYDeWMV//T4r2xHaOJH3DN
         YEdNXsaLe2DDGF07S+BnVt4rqXi4FJ9KBagK7Y0N0j3O7ROqvV1isK7wkYMGVOs2+4o9
         hPy/gzRGPda/91tVXkHr/6PzRexSpp7Tg42pC5HPJe6EsgrbCXHbZ8+Ap6TcQgV1B9qH
         REnjVOXKKojAE7wfaitGms6LqhBt3XRdMnIjQIkHDhN0QYsSW/HFiqZH5c+KaGinD7Ia
         9Jdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2rjMiy3Odsz7aMeVojoRQfc4P74LDh7q7OPziKHW9OlVhMjQ4J
	LNZtOyX32+s40vjXjPWYeU0=
X-Google-Smtp-Source: AA6agR5NAxMGs8WJJ5jG30WW49Yevhh/9Wk/zNsw6jvoIxM4RmZuU7Gu8Z/I9aEQvz87jbu9ykOCtw==
X-Received: by 2002:a05:6402:f92:b0:44e:84e0:1d2a with SMTP id eh18-20020a0564020f9200b0044e84e01d2amr10196935edb.395.1662708823030;
        Fri, 09 Sep 2022 00:33:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:268c:b0:448:77f2:6859 with SMTP id
 w12-20020a056402268c00b0044877f26859ls803848edd.3.-pod-prod-gmail; Fri, 09
 Sep 2022 00:33:42 -0700 (PDT)
X-Received: by 2002:aa7:c78e:0:b0:441:c311:9dcd with SMTP id n14-20020aa7c78e000000b00441c3119dcdmr10058676eds.155.1662708822012;
        Fri, 09 Sep 2022 00:33:42 -0700 (PDT)
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id og48-20020a1709071df000b007796ac0b2e2si68167ejc.2.2022.09.09.00.33.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Sep 2022 00:33:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6500,9779,10464"; a="296155116"
X-IronPort-AV: E=Sophos;i="5.93,302,1654585200"; 
   d="scan'208";a="296155116"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Sep 2022 00:33:40 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,302,1654585200"; 
   d="scan'208";a="566275191"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by orsmga003.jf.intel.com with ESMTP; 09 Sep 2022 00:33:39 -0700
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Fri, 9 Sep 2022 00:33:39 -0700
Received: from orsmsx607.amr.corp.intel.com (10.22.229.20) by
 ORSMSX611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Fri, 9 Sep 2022 00:33:38 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx607.amr.corp.intel.com (10.22.229.20) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Fri, 9 Sep 2022 00:33:38 -0700
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.102)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Fri, 9 Sep 2022 00:33:35 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=TtAbZqlwdz9ATnj+9Mvcba9SgVzSM2VlaEXftZ4XlJ+XNhWAGsm+O//DHeQ1bjAp9fI1ujbvQtFUnfj7tPfdLo9lbd3aI+K9vCVDcdWn65VVbublSHvmCNENAI6Cf81PVssNh2Hyz+R+c6V7/bSovjb2koQwoeaenva6W/GfF8PE90K4b9xRIhKEiPuns15s1c9sEPH7IRqdl1E4L0WvrusXQUWaX0Ek7RHetbEmsNd/+gT6Zli26AMQZs3gKel6n+2M0j5FsrO9PRY03s25B9NSqRljN3L7BXS8G23foLkTeYEYyWS28KQzIVp9QVhW0ytdNmfAriGkHtIXuM+uNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OwKIZBs1W49RVra2C/QKEJgJ7jgsCByNlwqxheEIcbo=;
 b=eg03JDR/Yq/+F3lK0eTWPpQNnvpbCxTt2nUoY08Eol/0/UlOEL0pptAsgcK+aFb0M98/1BOhWtHCGV+2Wj0ChKS7L1XVtfLwiuD0d/hOySDLQwFFNW8/sDd4UWNR7rMnqdcN9cKO8PAA+UiZHwPL7PjKihTFnSt8Kiwt4N17+iR01yK8UGgAC1mXGKWWTfXpTHQSdnp+zeOOFyBeX0UKuPod0DapSltR2yVY6WK83pR0gofNWJoa/xQOs+S64swV7f+ZMsVlEj6pu5sPRq7Zp01ixhZStGxX0amYcl6zNii4yh0yL2SIm8WlLiRh1mFUz22LlD+qIcmSYzTQHoXtqQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5588.17; Fri, 9 Sep
 2022 07:33:33 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e%7]) with mapi id 15.20.5588.015; Fri, 9 Sep 2022
 07:33:33 +0000
Date: Fri, 9 Sep 2022 15:33:01 +0800
From: Feng Tang <feng.tang@intel.com>
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, "Dmitry
 Vyukov" <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, "Hansen,
 Dave" <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v5 4/4] mm/slub: extend redzone check to extra allocated
 kmalloc space than requested
Message-ID: <YxrsLc23lWFZ5H4X@feng-clx>
References: <20220907071023.3838692-1-feng.tang@intel.com>
 <20220907071023.3838692-5-feng.tang@intel.com>
 <Yxrcmk6hSvHBCGNo@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yxrcmk6hSvHBCGNo@hyeyoo>
X-ClientProxiedBy: SG2PR04CA0159.apcprd04.prod.outlook.com (2603:1096:4::21)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: f142a764-bcc6-4615-3905-08da92359986
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: ReUTwQgrDQQ+UO1ESoTiSk/zh01w3K6kGw07PdOMVLlac10JNK+spQPiiz8fQsgyQlRrUNQG+BMieEZZ7i/UP1ESnXs4SYyM3cbkjUZmkkSzHHJE9wDlnEPLbmW50ger/W2Oq64I+IhjfvM2CPLe1ITWSnSamtHycefS1rlldYzmMIOl7reAIqTphTU/Yk6KeQHbpbjiX0iywINGD6zBwWcMsYueScUjuGMq+uzELEgyhaToMPHPctgukd8hCaetNy7h3rw7ZSCPqQSr4EbkVd7DJo+sQXg4Nx9YecC92FgQ+F4bWed0bwRchKwh3CEVQ6v+hv40NfrCwA+tOC4yH3pm6weW6rgJetxdvzeJe3IAPiEEND5aBFBbSGR3qZMJrZ9IxejLse+h3LlNb23LnuPi+3iPNLXWEWOiqPVT/9y2RPagf90jD1hD25rVQU3wzw7OnnHkSZIfeyJMR5raAzze53TlyCvhFDYdxrrMSZW7T4lub/apgVzqEz3ZbNOjKndePfPfEGJaL1m21xOf71gyl6tHCJI8fKjPMhH4VFeptXzDXvdYd/EDMIfyuqjfERfOJMsJg198RS2G75PrdigqXZktS5GaX+ygFV3nWjo4oVjKGJospqiEATpIGC89dPa78GHepntlsNiOb11cjE2BQif3tLd925EAXKOsz14nqVke9Wgz5VzWG7wpwnpkhvNfrxwfdMe+DYhMSTvdXw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(136003)(346002)(39860400002)(376002)(396003)(366004)(7416002)(82960400001)(44832011)(2906002)(5660300002)(6486002)(478600001)(8936002)(41300700001)(38100700002)(6506007)(186003)(54906003)(6666004)(316002)(6916009)(66946007)(66556008)(4326008)(83380400001)(26005)(8676002)(9686003)(66476007)(33716001)(6512007)(86362001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?HRcJmdsSypecUjZ7vTfZVoBxJx6CfFvOXhEA09dw2d2Sa+R8J3eEAIxybxjH?=
 =?us-ascii?Q?wofEiD9Tczeqj7gVpdsiS1Ro3mtzSzpJWe2IEnJdzqUeEqajVaJxe0EqezLd?=
 =?us-ascii?Q?Naw0Wo/lsNq5rNB+qtiAjpid2JIE4E3MTe181YpqyWpoNt6D8+p4pM/er/Wo?=
 =?us-ascii?Q?nJSW0YY4eKpp6Qab/+Q8rH+sIFVI9F/n2C3RJQHz7TW735lgPsLEgNEiDmw7?=
 =?us-ascii?Q?P9qb9YAKCvtYOgt/G/1pLhJfHUWEZObm+183jhuCTYdqzw1MTc8lOoiWhhZB?=
 =?us-ascii?Q?kRY6/pkBETaoUH8CL3Sf8K7RvmtslWMCUbHQEyxAi7ASaxdiUXz7ZJIJV0qI?=
 =?us-ascii?Q?fdihBQKYK5pl0U5t+4bgQzWPsvOE0WD1mNAE+XeEKE+djWJUTbYQkUcDNshz?=
 =?us-ascii?Q?ccFpXsM0yjIfpKkj9lyI9eW3HQTZAKkyskDhsyqBTy6WaNz1K7felScF7MJb?=
 =?us-ascii?Q?re3TGb3pFzLv6HvOAtlQ1K7h/zXkjYBLH6ozVGxQcFUHW1O5lHbYxcj9ETT/?=
 =?us-ascii?Q?0P32Gh8nEaGZqS4ekurzYXa/N/dp5On3TZYWEvrF0CYkYdChO2fgUdkyQ/PU?=
 =?us-ascii?Q?u6HwUv3dBbAucRqoG8OCDteJDIRfept8plTFOPb+z+nQKVcI3pE5/eyk8RS4?=
 =?us-ascii?Q?BxVcpO6gSl+/juLe18beNcTaI+U+tTTqlLsaq7HD+d7HPWGx70C2TCnIhK71?=
 =?us-ascii?Q?VjvryoEaq3e3lD6XE8QKwIetLK85SPCWUTJKvXaFS/IzESB6uJIWwjje1ihi?=
 =?us-ascii?Q?WXg+BduwiBa6KUVIwdO61UBLNgiIEn7Nip4AD1ioz1vnWDdplS05w5FAsqVp?=
 =?us-ascii?Q?pWO3f4KmOTTwM9663ZJiuAVqMMKsBCxgdv988VivHBTqZq6O8fnFaDFOrfuH?=
 =?us-ascii?Q?hlC+Xh8UTe9sT5pZvcItrLQ60OeZyKLwcoX91lskU2jgAeYS0EHE3BMTaYS/?=
 =?us-ascii?Q?PAvPkZa5t5emrUnSZwhN3FH5fbSb7oN4G4CvjrYNN3JJS6oFqn+TdkxPSVN+?=
 =?us-ascii?Q?dFtwV070Jg+JbeHNLzN8rWlBdfo8gglYseY/hanmTR3GydHdXFPJ8btuw/dh?=
 =?us-ascii?Q?WfGs1fvkrMrBu7tWgAgNEUWm/8fYH5egLuhxg+UhA5dBsglnRRM++VH5xbVl?=
 =?us-ascii?Q?sl3tjF/7umrSxChxWO2qgZTyCovUdDd3WnrxdEcz8tDp+Nh33eqt+lMbiCIr?=
 =?us-ascii?Q?I/GOAduOYIEhP7nsAHhDob0EebSjfzIaXMC8PAQ03qIhSWKWaFVVDiytK752?=
 =?us-ascii?Q?8u9Of8F5xjJZ/vk5buZEjyuyjnkteOQ5jf705jazHOsvJbfAz75Avclu0lUo?=
 =?us-ascii?Q?sc+9Aryw9tC7pWJ2ozD1xmJXjz+iXIhn1aqoSMablymMJddnN+r37iSc57Mt?=
 =?us-ascii?Q?uksqog1Px9wzaCtm4DdsqhKO///+XZP3fzUdnrLKh3Bk6faiD+9m0Y21qidZ?=
 =?us-ascii?Q?mShByn5XV6tPU4wMWsMdV632ZFCVxroTDm6X5nHeMprFEuZpxjPQhkGYlwf+?=
 =?us-ascii?Q?OD6GjPTLDKQdpl9snsCI4G0rwZZ6SVqtoUYTf27v7D14jNMmwQfKK4WGUfGE?=
 =?us-ascii?Q?HR+r4B6DfYc6PBkTDCaMskKUzpCxWf+lVjKt/TfG?=
X-MS-Exchange-CrossTenant-Network-Message-Id: f142a764-bcc6-4615-3905-08da92359986
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Sep 2022 07:33:33.6585
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: YZvo9RNimjVnDUv7qJMgnZcYce7rDLM6jcMjPLJXqHWOkWcgU4xwQRpOH26oQ3BbYzZRXf8LnqUGJi4Fhx+Eaw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN0PR11MB6231
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lDkWcKSq;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.120 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Fri, Sep 09, 2022 at 02:26:34PM +0800, Hyeonggon Yoo wrote:
> On Wed, Sep 07, 2022 at 03:10:23PM +0800, Feng Tang wrote:
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
[...]

> > -	if (s->flags & SLAB_RED_ZONE)
> > +	if (s->flags & SLAB_RED_ZONE) {
> >  		memset(p - s->red_left_pad, val, s->red_left_pad);
> >  
> > +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> > +			unsigned int zone_start;
> > +
> > +			orig_size = get_orig_size(s, object);
> > +			zone_start = orig_size;
> > +
> > +			if (!freeptr_outside_object(s))
> > +				zone_start = max_t(unsigned int, orig_size,
> > +						s->offset + sizeof(void *));
> > +
> > +			/*
> > +			 * Redzone the extra allocated space by kmalloc
> > +			 * than requested.
> > +			 */
> > +			if (zone_start < s->object_size)
> > +				memset(p + zone_start, val,
> > +					s->object_size - zone_start);
> > +		}
> > +	}
> > +
> >  	if (s->flags & __OBJECT_POISON) {
> > -		memset(p, POISON_FREE, s->object_size - 1);
> > -		p[s->object_size - 1] = POISON_END;
> > +		memset(p, POISON_FREE, orig_size - 1);
> > +		p[orig_size - 1] = POISON_END;
> >  	}
> >  
> >  	if (s->flags & SLAB_RED_ZONE)
> > @@ -1103,6 +1139,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
> >  {
> >  	u8 *p = object;
> >  	u8 *endobject = object + s->object_size;
> > +	unsigned int orig_size;
> >  
> >  	if (s->flags & SLAB_RED_ZONE) {
> >  		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
> > @@ -1112,6 +1149,20 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
> >  		if (!check_bytes_and_report(s, slab, object, "Right Redzone",
> >  			endobject, val, s->inuse - s->object_size))
> >  			return 0;
> > +
> > +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> > +			orig_size = get_orig_size(s, object);
> > +
> > +			if (!freeptr_outside_object(s))
> > +				orig_size = max_t(unsigned int, orig_size,
> > +						s->offset + sizeof(void *));
> > +			if (s->object_size > orig_size  &&
> > +				!check_bytes_and_report(s, slab, object,
> > +					"kmalloc Redzone", p + orig_size,
> > +					val, s->object_size - orig_size)) {
> > +				return 0;
> > +			}
> > +		}
> >  	} else {
> >  		if ((s->flags & SLAB_POISON) && s->object_size < s->inuse) {
> >  			check_bytes_and_report(s, slab, p, "Alignment padding",
> > -- 
> > 2.34.1
> > 
> 
> Looks good, but what about putting
> free pointer outside object when slub_debug_orig_size(s)?
 
Sounds good to me. This makes all kmalloc slabs covered by redzone
check. I just gave the code a shot and it just works with my test
case! Thanks!

- Feng


> diff --git a/mm/slub.c b/mm/slub.c
> index 9d1a985c9ede..7e57d9f718d1 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -970,22 +970,15 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
>  		memset(p - s->red_left_pad, val, s->red_left_pad);
>  
>  		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> -			unsigned int zone_start;
> -
>  			orig_size = get_orig_size(s, object);
> -			zone_start = orig_size;
> -
> -			if (!freeptr_outside_object(s))
> -				zone_start = max_t(unsigned int, orig_size,
> -						s->offset + sizeof(void *));
>  
>  			/*
>  			 * Redzone the extra allocated space by kmalloc
>  			 * than requested.
>  			 */
> -			if (zone_start < s->object_size)
> -				memset(p + zone_start, val,
> -					s->object_size - zone_start);
> +			if (orig_size < s->object_size)
> +				memset(p + orig_size, val,
> +				       s->object_size - orig_size);
>  		}
>  	}
>  
> @@ -1153,9 +1146,6 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
>  			orig_size = get_orig_size(s, object);
>  
> -			if (!freeptr_outside_object(s))
> -				orig_size = max_t(unsigned int, orig_size,
> -						s->offset + sizeof(void *));
>  			if (s->object_size > orig_size  &&
>  				!check_bytes_and_report(s, slab, object,
>  					"kmalloc Redzone", p + orig_size,
> @@ -4234,7 +4224,8 @@ static int calculate_sizes(struct kmem_cache *s)
>  	 */
>  	s->inuse = size;
>  
> -	if ((flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
> +	if (slub_debug_orig_size(s) ||
> +	    (flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
>  	    ((flags & SLAB_RED_ZONE) && s->object_size < sizeof(void *)) ||
>  	    s->ctor) {
>  		/*
> 
> -- 
> Thanks,
> Hyeonggon
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxrsLc23lWFZ5H4X%40feng-clx.
