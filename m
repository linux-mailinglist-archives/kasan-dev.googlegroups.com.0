Return-Path: <kasan-dev+bncBDN7L7O25EIBBLUU7WVAMGQE6WMWMSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A7547F5F59
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 13:48:47 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-421aca7f03esf8665481cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 04:48:47 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700743726; x=1701348526; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9E00CQn3GiFC5NvlSrm150rx9tn40Bm4tAJbbTrmt1M=;
        b=lOa4u/i8G8LrXSqNK2oOvAGoHes61y6vmN/PUtWA+tiA7e3IzzpXXroxX7ITFNgKE2
         2FVI43mozpMBbATovOA+k7HzWv4IYZuAHrQvylu8eJYZ3UTMeAQtHSBZBdg9W0CaRvek
         8pawQQ8rGlnt9NqLV7LqEDw0evLYqP+U7XDRNp7Nfto6BaQg4REMp6EGSNRXDX0aORbF
         3NaKc77m5FFnQe101hjWy6UBbPT6LmQmZEMz9pI3mOw82dACHEgA1e9AKA/8S1CrDtUm
         ABhGvm7TGE33Hr2gOxDJ+bk36srR9HuDK8WSmfUViLxUYhktoSdcoxmLF+StZNjV+L7d
         Wvbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700743726; x=1701348526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=9E00CQn3GiFC5NvlSrm150rx9tn40Bm4tAJbbTrmt1M=;
        b=ApDEPgZ18lr+NdWXxLNQOGNDyzD2/sFf4v8dkLRrQLgAheKUfb0Ag77jmbzOO6yAbp
         0BvdjcbWHMQn4KfOxYeJmnF0fOiCLhH3+OkBrd+LWIdPxheadcYvCeCd3CqqR+4Eaz3X
         piMH4W6PoJZJgxTa5pVmgVr56AgKVTJwywmWyjzNzwQcKOqyjhj8ENrU+D1pzWWaA0lE
         WJoOt3rRfMGULs7qWSxU0RXdOmRiLf0yPv4KqronrPGhG1UjMd2NxBmhGjTRJNlXlfwA
         ETgZdDMyvHpi11gkRTxhe8+srGjtSIU8NRVbcs0ea09uZxCW6UdTjPaeoY6UC2gY1/Vl
         F1+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzBRUnTfuQuyfFJ9m6xOq4oP/yCBCCCLQyYlDFmnpBO8UvcvZpN
	ze0MsPPEsIoIYgmsdzefvMU=
X-Google-Smtp-Source: AGHT+IFufNjaOhzUfLLoGD2fTrSk/+Cp18/EoN6tx/OOKQ342P/7x8AEtXv+G3OFwSZn3RjVeoz+qw==
X-Received: by 2002:ac8:5f8b:0:b0:418:1565:ed50 with SMTP id j11-20020ac85f8b000000b004181565ed50mr6721790qta.66.1700743726333;
        Thu, 23 Nov 2023 04:48:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:387:b0:423:74ca:2527 with SMTP id
 j7-20020a05622a038700b0042374ca2527ls852719qtx.1.-pod-prod-09-us; Thu, 23 Nov
 2023 04:48:45 -0800 (PST)
X-Received: by 2002:ac8:5d56:0:b0:423:6e27:adfa with SMTP id g22-20020ac85d56000000b004236e27adfamr5875878qtx.42.1700743725490;
        Thu, 23 Nov 2023 04:48:45 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id ck12-20020a05622a230c00b00421e709bf9bsi107584qtb.5.2023.11.23.04.48.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Nov 2023 04:48:45 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6600,9927,10902"; a="377285362"
X-IronPort-AV: E=Sophos;i="6.04,221,1695711600"; 
   d="scan'208";a="377285362"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Nov 2023 04:48:44 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10902"; a="743596437"
X-IronPort-AV: E=Sophos;i="6.04,221,1695711600"; 
   d="scan'208";a="743596437"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by orsmga006.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 23 Nov 2023 04:48:44 -0800
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.34; Thu, 23 Nov 2023 04:48:43 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.34 via Frontend Transport; Thu, 23 Nov 2023 04:48:43 -0800
Received: from NAM04-BN8-obe.outbound.protection.outlook.com (104.47.74.41) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.34; Thu, 23 Nov 2023 04:48:37 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=QGDt2jfRBenCQXJAf1XFcDxaGA8tcZ73hE2cDkdkY/OgltXc7eE3RpCXYsIZD8j0jiV5039kQQIH2LrbPOj1Xpo89eOH5dvEFBVUskYd2CzSR903J5I9aJlia0DWrar298zXesVHHra4O0rYMTpjP29sWOFuZbkaKNQCxXWE561t2uxntoKtq18wgUWb+jWg/YiVPybwFcCTtD+IQrHr1/hTKvcm8ONv5sthIzCYGtNhPDlRt+I/zJSo319j1tWdLPemdwlRhlWGv1eLFYL6yJqBQKNjiPwp94fv54ioqkmMuGeQxOtgUpE7Trg4rEmRtYXn8cOjA2XLta0Qiq1JAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=DC35uQvQ8yxMj8kwSpVVj8U3bP+IaiusM48vApdMvfo=;
 b=oPNc2TBDPk8+bkWB8MmmupE/6tlQyv91lgfxAwtL9aU44OMKaYpgsOfrvmHwod1IjzBUT+VSEr0yXBnePH2IXZhuX248shkpcWJW0xqZ+GosjtdiA14mGSQV+WBS1JiSqZv60PBu2hYTW2ljSUySUmIdkxPS98OVzCoy4OvQkqb8/40jHqSnAKu7df6AO9NKI6e/0MfMTcNj9buiJzfSzKCvy8FUCdjQr8zmHiS+ArUtXZAf8bOzPCT/Kn9hDQs7h+4UX9THVDkbz7lz/qeIQwF7xI0GR7ADyGvtynVUbHh0E6plLpZcknP6u4HuqnkUa/7Vk/enNxT9aaeZgNXWrg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by PH7PR11MB6882.namprd11.prod.outlook.com (2603:10b6:510:201::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.20; Thu, 23 Nov
 2023 12:48:35 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::24ce:9f48:bce:5ade]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::24ce:9f48:bce:5ade%7]) with mapi id 15.20.7025.020; Thu, 23 Nov 2023
 12:48:34 +0000
Date: Thu, 23 Nov 2023 20:39:30 +0800
From: Feng Tang <feng.tang@intel.com>
To: "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>
CC: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov
	<andreyknvl@gmail.com>, Marco Elver <elver@google.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka
	<vbabka@suse.cz>, "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, "linux-mm@kvack.org"
	<linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm] slub, kasan: improve interaction of KASAN and
 slub_debug poisoning
Message-ID: <ZV9IAnfUHq2lcCe0@feng-clx>
References: <20231122231202.121277-1-andrey.konovalov@linux.dev>
 <ZV7whSufeIqslzzN@feng-clx>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZV7whSufeIqslzzN@feng-clx>
X-ClientProxiedBy: SGXP274CA0003.SGPP274.PROD.OUTLOOK.COM (2603:1096:4:b8::15)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|PH7PR11MB6882:EE_
X-MS-Office365-Filtering-Correlation-Id: 790529ed-0d5e-4f9d-3edc-08dbec2280ed
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: te11htPwkZAmvd7ljnmFhJR0ogPkl7Xqpbc7cvC6A4zc9UPEiyn/jbYeeR0l+Ocd3pUydQQ6/gSV2YS4mfAkVpgj0fkTmu/D4ktKGzTOm+ZXVDzERQqmh1yOCKxul0VlnX/SUr9LIIfofmYMYTy6LvaLOpifMYlbDwYrcHyfi5PMtf3/mZt/n7p1HjdcEIgQf6ZmP7wbgjEy/i354v6mgs1j/cGKAXDOxqlEwai1YF0WvmFWC/yfzWZk1iTGhSmeRIFzqYZ3gBdDJ+q4eL3JtGFL0jKp7jS3knIBCtbrCXQEYCae9CmDNFFPWO23rvow+IZf9jds2KUCEojzvqSCBNK1Yu6A2Ev7jxBVw9809PPt+MUbvj3H2mcoVDIpefH407953RLbs/zm14BCiuTB3FLXUqxCOtJBxHSIEa6EodmubIbYlbpfCAtkkmfGFNSkG5rEzgM8e4Xkb9eANAVfj5OPPTM1nQCtxiMjg6hRfqS6LeaXYGrKniDxMQON5RBqmxk6ICcZSLTCVVwZ74OeWpzUkU+S0g9Dbr7C+GX2Y+8=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(7916004)(346002)(366004)(376002)(136003)(39860400002)(396003)(230922051799003)(1800799012)(186009)(451199024)(64100799003)(86362001)(83380400001)(38100700002)(82960400001)(316002)(54906003)(66946007)(6916009)(66476007)(66556008)(4326008)(8676002)(8936002)(6486002)(33716001)(2906002)(41300700001)(7416002)(44832011)(5660300002)(9686003)(6512007)(26005)(6666004)(478600001)(966005)(6506007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?p0/3s+uEmCwMptg4Y3FmCs4UF4jdFibYOxcpV2RGFttG6EoRPIuJHqM0/xLW?=
 =?us-ascii?Q?AkxwWPcxY7czfoSAUsSVu4D+ad0uSc1Bx/KnQKk+KF6l+bWyP44a5ZcFOgLF?=
 =?us-ascii?Q?mQ0JM8U7gUP5qI8jrhSyd0L7Vsy7uPk3Gz1zKENABo8Ztiae9phXr/U3tgI6?=
 =?us-ascii?Q?i7SGQB2IApLlsuVnwvk+yhP21FBBsutPIFAKIHHB8dOXQpjezHRTCLJw6T62?=
 =?us-ascii?Q?M9DaBqrnO5DNFSGkPMZw+6A13QJinaX3BulvDIJnbtlXlLVdpcdPOx6l0YSs?=
 =?us-ascii?Q?TKcE7Y/XYjdsyINhoTQ+HLzOuV2CNyie3jkSAs7X1e7Uw2XaaANMFHb8ttMw?=
 =?us-ascii?Q?/hhk6XaSA0CAy/1rfS2+adcv60qmuh9j3o8vigWYj2RR9vA9vpXTHD3gg49X?=
 =?us-ascii?Q?ylnMG1eq9O1k1hyrkC8Dq0CRMBj5Nzq4+B/ZojdnGWhAzEli4fdjSQvSBzJn?=
 =?us-ascii?Q?uy0q/dXaQ6XIy7NO73h1AWuOEFCBzFdfW6OC47yvUiLoEy9VooajoCFU679W?=
 =?us-ascii?Q?yHTukVRuRFRPql7I2k8sFdLBOR5snQGul+09FUPrtGaN6QPOVEUnRa0VFgXp?=
 =?us-ascii?Q?t6xo+g51H9E5uuQqbrOS9deJx6f/IIAgnscAuOg1++WoBWEF3UpxaS4tXmNj?=
 =?us-ascii?Q?YA/FRTzD25p2cVARLem+4jcOKykl7PpOpFcJ8a5+Y/HuVjk0V/kFQcpYynGm?=
 =?us-ascii?Q?ktFOC4BNQkdW+lFkBEfPNxm11awuNiH+Hk0ofGP/df+Xp4ZtvlPDnRVQF7m5?=
 =?us-ascii?Q?0EX4yLmD98vKiHzjviDIZ+X2IcbaXUQXIOyytXJBZi5nDv41HfL31HUccUnI?=
 =?us-ascii?Q?te8/mmEh4b2cYfKPcF/UNE94X3Z8G6k3pzZZzsuGbnUKiTeM0zCe/hUHWlbi?=
 =?us-ascii?Q?dahEMNJcYQ5y7baPFHgP7EArUb3XRcm9n57XvGIQbbE7BLz4CrWE1o+ZIZCG?=
 =?us-ascii?Q?AM7uM3pnvjlqi79Oy8mch8lVtdKnHtWvU/iuBr48RgN2z4thsr5jO9qY57eq?=
 =?us-ascii?Q?ZOdkQecDnHdhCY4obXcTyo7X4WtuiyCiYMMm2f7gg3vK2FXfuCeIJvAdf6q+?=
 =?us-ascii?Q?KxRwEncJOyf37awS1GrJmzGWiQrut8UF7/GqixxKisDNEXnCD72RRTqnvdJv?=
 =?us-ascii?Q?IZnLFCa+iXDtt+WnfONkyA/tqFYY//qWVp9VUZzAUQanPAqtn4ibrVvEu1yN?=
 =?us-ascii?Q?59TLWmn0ARwf8jTpPgm4/v+For9rChDxrbIRnxPzSINdf1cpf8g6tcrhKMs7?=
 =?us-ascii?Q?KMHmHkveqIfZcc2o/xnY52l5Am5Fobd8m3P2bLAKSfjPW0lONJsrU1lnqXj2?=
 =?us-ascii?Q?FYC1edK1s5NNPgHNC9VnyeiBZWFNn7QlUYnXIaE0PtmZ1OjcyzOqNwxd1uU4?=
 =?us-ascii?Q?gojNP5rcucqJ3DESpwUp4r5Ic1BgFI9lg4Ya1BPRsgRjJT2UZQacOV01yVQO?=
 =?us-ascii?Q?15DyR8LDQ1+6CLDZg2co3ck/Y70Oz8PdFmP8+iOJ0/WYZApQnLjgmHXk+XJH?=
 =?us-ascii?Q?HqLi1nzjZjx/IHjF4ONy7duDFU9AIBJ+rsnBcdncZeanvJCs4AIzDmEX38S+?=
 =?us-ascii?Q?KIYU10lZPTV6sE8TECutYDIyea5L7FI6zTLAHi0P?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 790529ed-0d5e-4f9d-3edc-08dbec2280ed
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Nov 2023 12:48:34.0126
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Ic6gl0OU6Nh8yTS2RY3TukxRJJ4WWx1ql6w03oV4L1g7ikitQdPHpNNxlL0TZvOQchC3nhsg0057yLf0qZf3DA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB6882
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="Pl5/WQd0";       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 134.134.136.126 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Thu, Nov 23, 2023 at 02:26:13PM +0800, Tang, Feng wrote:
[...]
> > -#ifdef CONFIG_KASAN_GENERIC
> >  	/*
> > -	 * KASAN could save its free meta data in object's data area at
> > -	 * offset 0, if the size is larger than 'orig_size', it will
> > -	 * overlap the data redzone in [orig_size+1, object_size], and
> > -	 * the check should be skipped.
> > +	 * KASAN can save its free meta data inside of the object at offset 0.
> > +	 * If this meta data size is larger than 'orig_size', it will overlap
> > +	 * the data redzone in [orig_size+1, object_size]. Thus, we adjust
> > +	 * 'orig_size' to be as at least as big as KASAN's meta data.
> >  	 */
> > -	if (kasan_metadata_size(s, true) > orig_size)
> > -		orig_size = s->object_size;
> > -#endif
> > +	kasan_meta_size = kasan_metadata_size(s, true);
> > +	if (kasan_meta_size > orig_size)
> > +		orig_size = kasan_meta_size;
> 
> 'orig_size' is to save the orignal request size for kmalloc object,
> and its main purpose is to detect the memory wastage of kmalloc
> objects, see commit 6edf2576a6cc "mm/slub: enable debugging memory
> wasting of kmalloc"
> 
> Setting "orig_size = s->object_size" was to skip the wastage check
> and the redzone sanity check for this 'wasted space'.
> 
> So it's better not to set 'kasan_meta_size' to orig_size.
> 
> And from the below code, IIUC, the orig_size is not used in fixing
> the boot problem found by Hyeonggon?

I just tried Hyeonggon's reproducing method [1], and confirmed the
below change of check_object() itself can fix the problem.

[1]. https://lore.kernel.org/lkml/CAB=+i9RnOz0jDockOfw3oNageCUF5gmF+nzOzPpoTxtr7eqn7g@mail.gmail.com/

Thanks,
Feng

> 
> Thanks,
> Feng
> 
> >  
> >  	p += get_info_end(s);
> >  	p += sizeof(struct track) * 2;
> > @@ -1192,7 +1192,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
> >  {
> >  	u8 *p = object;
> >  	u8 *endobject = object + s->object_size;
> > -	unsigned int orig_size;
> > +	unsigned int orig_size, kasan_meta_size;
> >  
> >  	if (s->flags & SLAB_RED_ZONE) {
> >  		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
> > @@ -1222,12 +1222,23 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
> >  	}
> >  
> >  	if (s->flags & SLAB_POISON) {
> > -		if (val != SLUB_RED_ACTIVE && (s->flags & __OBJECT_POISON) &&
> > -			(!check_bytes_and_report(s, slab, p, "Poison", p,
> > -					POISON_FREE, s->object_size - 1) ||
> > -			 !check_bytes_and_report(s, slab, p, "End Poison",
> > -				p + s->object_size - 1, POISON_END, 1)))
> > -			return 0;
> > +		if (val != SLUB_RED_ACTIVE && (s->flags & __OBJECT_POISON)) {
> > +			/*
> > +			 * KASAN can save its free meta data inside of the
> > +			 * object at offset 0. Thus, skip checking the part of
> > +			 * the redzone that overlaps with the meta data.
> > +			 */
> > +			kasan_meta_size = kasan_metadata_size(s, true);
> > +			if (kasan_meta_size < s->object_size - 1 &&
> > +			    !check_bytes_and_report(s, slab, p, "Poison",
> > +					p + kasan_meta_size, POISON_FREE,
> > +					s->object_size - kasan_meta_size - 1))
> > +				return 0;
> > +			if (kasan_meta_size < s->object_size &&
> > +			    !check_bytes_and_report(s, slab, p, "End Poison",
> > +					p + s->object_size - 1, POISON_END, 1))
> > +				return 0;
> > +		}
> >  		/*
> >  		 * check_pad_bytes cleans up on its own.
> >  		 */
> > -- 
> > 2.25.1
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZV9IAnfUHq2lcCe0%40feng-clx.
