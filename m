Return-Path: <kasan-dev+bncBDR6TU6L2YORBRM7TOJAMGQEVYJX57Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id DAD394EEB07
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 12:11:18 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id g20-20020a056512119400b0044ada577e3dsf747090lfr.1
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 03:11:18 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1648807878; cv=pass;
        d=google.com; s=arc-20160816;
        b=nT28hWsFmOJY1BXRY4gw6kg2360v6tyIPB1uXqmLrznR8OvFQoed7j9oCOYNzMz5TS
         keyfUTwfyjfdd3CjQB4JecwRTiJWdIwhewRxjeMWjBtDb6bIb6l1junGI8D0MqCrPHb4
         YAo3uW+g3IH9hCkfoYgVUCk+vwLa2HUAAwwnBn2NgMV1SSyZ3MFtcfSvkIbCUZbRkaXE
         KOQntczvdE1fPsyxyB7dD7WP9l1BvqU0B1+rTOR3WyTO0zEFCNkwPpuyiNOshb1ux0xE
         fqxN7TacSEdyv8mXhyWZWhXsz99FsZvPls+SGyDErSIklqDCXygwsl7gcj4nCwCqhCMU
         O+qQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:dlp-reaction
         :dlp-version:dlp-product:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=kBnp4A/2WaFRFj5hETX4kVp2FluFM+5d6//zy5PaSQY=;
        b=aMnTyUUQgJQ99la9JlBCqMfiA++wmKmOMaTpq0zeZMDA1WmHYdC05CvUHhf9JNjBc6
         iFM+MDWP0tM219dIssgAJVdAQOr3kN3Ny+U/tyiJlP/eOyJGjkM77M8CpUIsJXxEaztn
         uOoF/NAxZjL+SeuBcVobagO6i2AIr4oGtdtC7/1kQcHd3KxKTeV7x3fAue0wTv6/OFZn
         JR0pWyNTK+t3SmOi7jFlSz/2WRvET+dOBhbV6RUtBXySYWCHD9P9ZP/Ttki4I05+XCYW
         4jGxxPWzsaPwk5gYbsBxonO6wn2f/7NY+55q239H5NMGtS6yv9A1ahxcOEIq2xo5xh4C
         kI3A==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Xd7ZCFbB;
       arc=pass (i=1 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass fromdomain=intel.com);
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:dlp-product
         :dlp-version:dlp-reaction:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kBnp4A/2WaFRFj5hETX4kVp2FluFM+5d6//zy5PaSQY=;
        b=JfHleR8bSkMUtu0iROLt/pgXpdZcbSjXBz6VgLhKsF9ycmE/Qg6YVehrUttdYgrQMY
         mI3JqfkzkuzzL208gOckHzJTRbB4y9lSRzeq+Tf+HNB3PlMCjHgXwFWYjWlLOcvr2c2d
         5HQfUqlK2FfxjViHj2kav4KUslIZwJOdO7Oqi64I33P6/VTk09JNv3JxbtqsDZtC0pfN
         wPMnoAvNEDBKxilXDjXQVdp+KcBPXxPqjGB1gWgsZHTW/o7mnxZBMlF5iJsq9JaUgbCu
         VlwoDZec6g8kSzp6OzNytd888OuPKvs9LV/BjE4j8BviGDbFYlzGU5dl+zMU618+WPiB
         Ks7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:dlp-product:dlp-version:dlp-reaction:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kBnp4A/2WaFRFj5hETX4kVp2FluFM+5d6//zy5PaSQY=;
        b=H0fadk3hWCw99TW/UOe/4tedpIRsrNSegNhLFt5M6jLEL1a/w/Gwmu/eO3hzO/8QON
         2kE+579ln0fKLodqOP9Li/MPuwrssqyw8+RhJWIvVbuIWg3AKo30uEMoSp3z5kVau84z
         ARs1uufYQu8RgjyTIC5bOejVDkBiipIaic/od6kaSy/QEzAvtx94kCvrGdYveLMgebsA
         WRw0yYuAxYyBSaJnq4LoK+6KtsFg5DGxLvdOEviJ2oUUlccVqlG0gPbfcfvYM3tcFq4O
         cIWnVTtUuWk7uF2mvHHxaYT4lzlt+NzEHDGon+HC4xWi1GMF/rJeXXQdT0nSHHsXJOlI
         wg1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JqA4sT5TTtgycNdGtAlqcWTNjB1Ye4VFvoUZl/s+pikI2fS5+
	jCaub/7CEO0dA90YnFgWsEA=
X-Google-Smtp-Source: ABdhPJwpfPr/9BAoH0lV4ErL7l24Ch11PhiqIi0XU39a6LoAu88gOfvJ71xqC2HkqOureB9q2b0hjA==
X-Received: by 2002:a05:6512:1107:b0:44a:62dc:dd0f with SMTP id l7-20020a056512110700b0044a62dcdd0fmr13792938lfg.479.1648807878134;
        Fri, 01 Apr 2022 03:11:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9983:0:b0:249:7c7a:28d8 with SMTP id w3-20020a2e9983000000b002497c7a28d8ls214724lji.3.gmail;
 Fri, 01 Apr 2022 03:11:17 -0700 (PDT)
X-Received: by 2002:a2e:850f:0:b0:249:7cec:813a with SMTP id j15-20020a2e850f000000b002497cec813amr13129073lji.75.1648807877065;
        Fri, 01 Apr 2022 03:11:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648807877; cv=pass;
        d=google.com; s=arc-20160816;
        b=aXXAO2vsdaSQ7FNaH8on4g2JClpJBhW97uplu22Hj0WrqzrZTx37bydL0cRbRe+KYy
         wHTRGU5k7f/v1uknWxb+nSovpXLeYaYQYMGk/Bmb/jVC8QtSbCcu4uQuzm+G9IiIWdTu
         usMr5o5X4Y0BWS94XFm0OnCTzDMKk51ftCx+bmXOOJlRARR1UgSbvDQlfxPi5BixZpn7
         MGUJQ+1lE6igiwsaJrZDx9zFB5xKrG2GclpwgjRt3SCQmGPPChTTpMlHvXBTBQEDsT0s
         /0q+1h2hbJQDc/91NQ8hy7HO2KSI/8/aiz4jDX8wUKa7kp7pIu/OkW/obcYBdxHV0BWo
         hirw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:dlp-reaction:dlp-version
         :dlp-product:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :dkim-signature;
        bh=3jrUqHzpUZ6P6RDmRVFOzQHdXQmwz8aUSRdfTS+i0xw=;
        b=DLljYgca1h19tY+5m9c86R/z44lTKa68Yh8jpd18n7DRotG8mXhScM4p5dDlJtNBlg
         lybHS/sXvrE+c5wPdBU9E3ObrDz19sDgxaikaZtonVlx3nWBHgBleFMktc1dGB8H52dw
         RPgtVRUuQgRR/xUaXBeycL4ZSklZHY43lwyM5zfie5NKtBJzJ+9g3F5kSxwV0Vx6IVfq
         h+YBsyrUZCqLNUYNXVn6XqmduyqRYwOYckoac76zInsCl5DEj0DVCkaB6xWd4vE21qOB
         7HJLzlvKluq3bk3t/z124CD0kig9qzfXGdQT/174coleHiChN+uvaH7pSTs06qzeSA5Q
         salw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Xd7ZCFbB;
       arc=pass (i=1 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass fromdomain=intel.com);
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id b11-20020a2e894b000000b0024af7c96040si130808ljk.5.2022.04.01.03.11.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 01 Apr 2022 03:11:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6200,9189,10303"; a="258927458"
X-IronPort-AV: E=Sophos;i="5.90,227,1643702400"; 
   d="scan'208";a="258927458"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Apr 2022 03:10:48 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,227,1643702400"; 
   d="scan'208";a="567359956"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by orsmga008.jf.intel.com with ESMTP; 01 Apr 2022 03:10:46 -0700
Received: from fmsmsx609.amr.corp.intel.com (10.18.126.89) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27; Fri, 1 Apr 2022 03:10:45 -0700
Received: from fmsmsx609.amr.corp.intel.com (10.18.126.89) by
 fmsmsx609.amr.corp.intel.com (10.18.126.89) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27; Fri, 1 Apr 2022 03:10:45 -0700
Received: from fmsedg602.ED.cps.intel.com (10.1.192.136) by
 fmsmsx609.amr.corp.intel.com (10.18.126.89) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27 via Frontend Transport; Fri, 1 Apr 2022 03:10:45 -0700
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (104.47.59.171)
 by edgegateway.intel.com (192.55.55.71) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2308.27; Fri, 1 Apr 2022 03:10:44 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=ZhclSsMO1tfxvuAeJPchnMQ+wDy1qAdf7vycd2zfML98nm4ExGTcjubXOu7PWgO7td6E+sLcPT5iFOPd5FF0KxIpQW7M3pJD7OLzI4LIVB0NC6pnEeDVgkd36tf0YzAcYSS6YqjZh7NB+4WpDvW5572bDW9ia+SVLzAjBdmLiB9WftfomchZyLNN6PwazWx+u/+iND72W1mVitNqjnc/eIqO2DTYO9qDTXjRdS4UIkD6DrOe5MlxH9L+zZvdmSWBaSpFzcgjDlF3gtsctNZAE1daUOuiU3XLSz+WbNfBQw6HwAI7CsLHXrSs+Ea2AFHplBXb+efnIBmr+4YHcVVAgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3jrUqHzpUZ6P6RDmRVFOzQHdXQmwz8aUSRdfTS+i0xw=;
 b=im+ViYDxKhM5mcm+NEkbIPLzYAZibzlsuB8hvBHkiK1UzF+++EExryssq4VKFjC4w4eSBkAhX971Ncup6NZD5DOAbAS58psyFYrP463VPrtAJRHZwX5KxAXJgTMxDodfby+4GNHc0fkLC3EZIzddEUAYR293xay5fi0NpBsdT+HHM7TggMMFjfrZAY9uxndGbC1KPI6uyznlSyJZRgdtW5uZ3oNFCQlifDvz636bbD34HKpGiDEPs01RO9+WT0tf5Ko4sIRP3B8/qyZQXzJeEGFrc1Ut9nrkL8OupKUJpF4kGmxsN9SE+YsWw2avMfgkCgI74xmOFs4xSHEwUEzURw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from PH0PR11MB5880.namprd11.prod.outlook.com (2603:10b6:510:143::14)
 by BYAPR11MB3047.namprd11.prod.outlook.com (2603:10b6:a03:8b::32) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5102.17; Fri, 1 Apr
 2022 10:10:38 +0000
Received: from PH0PR11MB5880.namprd11.prod.outlook.com
 ([fe80::6439:b0f1:f43f:54d3]) by PH0PR11MB5880.namprd11.prod.outlook.com
 ([fe80::6439:b0f1:f43f:54d3%7]) with mapi id 15.20.5123.021; Fri, 1 Apr 2022
 10:10:38 +0000
From: "Zhang, Qiang1" <qiang1.zhang@intel.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
CC: "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, "glider@google.com"
	<glider@google.com>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"dvyukov@google.com" <dvyukov@google.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-rt-users@vger.kernel.org"
	<linux-rt-users@vger.kernel.org>
Subject: RE: [PATCH] kasan: Fix sleeping function called from invalid context
 in PREEMPT_RT
Thread-Topic: [PATCH] kasan: Fix sleeping function called from invalid context
 in PREEMPT_RT
Thread-Index: AQHYRahAPBhx8+IVqEWk1xTI1Gzupqzayh8AgAAKNUA=
Date: Fri, 1 Apr 2022 10:10:38 +0000
Message-ID: <PH0PR11MB58800917A1BF8D1A76BEF84EDAE09@PH0PR11MB5880.namprd11.prod.outlook.com>
References: <20220401091006.2100058-1-qiang1.zhang@intel.com>
 <YkbFhgN1jZPTMfnS@linutronix.de>
In-Reply-To: <YkbFhgN1jZPTMfnS@linutronix.de>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
dlp-product: dlpe-windows
dlp-version: 11.6.401.20
dlp-reaction: no-action
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 32646faa-937f-43f3-0e61-08da13c7dee2
x-ms-traffictypediagnostic: BYAPR11MB3047:EE_
x-microsoft-antispam-prvs: <BYAPR11MB30473BAA821113939619CEF9DAE09@BYAPR11MB3047.namprd11.prod.outlook.com>
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: bEnti1Xivxyhh5bUJYsXpmoh5NJ8FbsbCKD/b2lJpyyeVE6i4d4IodzP9BvWrUt0ebOb8puv+vLQdX4TgiUL2vcSMQ0SJdeAurMt9fEGK/5JP9iTU/HGhFp4s1Xjdy20gu+dD4+GZBTxGTVzQf3fPcF3IvAGoXImsDDn6KMlGE7JMZnatc7lbwpqDHBdYZghhUdoYvSTOFnpzFYTWq5+md51U90ovrYBKLpnVOmR3+HMmsq+hE6Ccwn2aGKOteyUiFFQQUKnknTvPh62AzjUuGx8GOn2wUmGTi9KWU/5zU005LXFXJKlChOPauDKCX9Lb7A0co/Q0LZn6bvr567wAxbojg0cYf5NV2b+Kp72h2oPQV/z/W7qdb/EG/phcBnRGaWUc6ERxwZiADTNeSvAef9ohGE2TKV5AWR5r/xGmfqIyuZ5UcQ6bCvWNRzr5rfqaDtl8qv9h1HObdkZsjOjLNvf4shMuinnkAz1x3XvE8zfF3grgTqSODVfbcfyvLC04w4ozo9Z6GezCvn18Xa09R1jqDDJDhdM2FZ003tpyb6PacmDKOqAFDqQV6SkIUO6lU4rXROk+sXFZlsM4vr6jG+1jbux6H9NW0vZWa65XT5JDPDQH0ZVOg3HI/xOdkDMZkEq5E/Kk8nf6C4L/bIF/opGMJnfiHb6VmYxjLMdF+16r0NiFMSGoVMg6sE/AtVFp/MN4xa6ZPrinAUS6K1RMQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR11MB5880.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230001)(366004)(6506007)(55016003)(7696005)(54906003)(53546011)(52536014)(6916009)(9686003)(2906002)(8936002)(38100700002)(122000001)(82960400001)(5660300002)(38070700005)(8676002)(86362001)(66946007)(33656002)(66476007)(71200400001)(64756008)(66446008)(76116006)(4326008)(66556008)(508600001)(26005)(186003)(83380400001)(316002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?bk53SWp1RTdMcWxHdjZ4SThYeWw4WDVEY2d6bHRPZjduNlJhcVpGVFM5SW9L?=
 =?utf-8?B?dkNnc00vSUM3RTdKYTlkRFZtTjBDNk5DWExUUWhwVnE4RXQ2MlZFVWwxclVK?=
 =?utf-8?B?Q2FBSHNZYVE3RjR3ZkdJd1IzV3JHSWZLSVh0Y2VCcXFWQlhaMGczSVhsMnB4?=
 =?utf-8?B?TStPbEhpdXlDTE5MdmxrdjduS2plNEhSWElKLytUVUtBZitHQWVSeTFGd1NB?=
 =?utf-8?B?ZktRY1p2bWVxSElKRHhKUjVLbjBHKy8zY1A4Z0lqYWFxYytsdWVWMkVhRFhs?=
 =?utf-8?B?UDJ1ait1MlpsUmN1TGh5cWZNbXQyVjNzNzc1MTlBSFFzRWNoaGRjQTJxZzF3?=
 =?utf-8?B?NVg1ZGkwRDBPd1FHNENmdjlhVjFURkRnNDd3eW0wKzJFajJzTnhIVWptU2gy?=
 =?utf-8?B?WUw4Rk5TOFd4MHpSdlVjSzdFVmFZd0c4STZ1UGYwcGRiQWJkN3dhRDRjWm9t?=
 =?utf-8?B?YllCTzZBM0ZXWVM3NWhlTG94RmNpdUZ0Y051aldWa25oYXFCTnQ4VlUrbHJC?=
 =?utf-8?B?ODdOM2EyNlFUTFJRL0NnaGxFazUxWHF1OFIxY2FzdXMrZlZNU20xMlJrRTNY?=
 =?utf-8?B?ZTNUZndwN3dSUytYbzYrK1RDcTFjcmRLK08rdnN2dUtpUHRPZUtOMkFhMzhz?=
 =?utf-8?B?R09TWldBekpMNXJmenpvZklRYmJlUDZKY0xYRFpXMXdTVEdmdWZENitGMEpn?=
 =?utf-8?B?NGJiUUJqdE56RUZwTDJ4QXB3U0F5ekVDV3YxYTdzUXU3RytJcndXbDYwTStz?=
 =?utf-8?B?U1ZQYUZqQXZMSUR4MGhPYXlLQk5Pbk5CV0tJdStxem5aWk5jVkxKZm16MjBC?=
 =?utf-8?B?MDcyZ2NEYXZCckU5alMwVSswTTVwVXptMDZ2MkROaGdYQUdFa2dRd0UyYlcr?=
 =?utf-8?B?aUJTVDVlRXQ4SmpnV0VPaVo2MHJ3QzNtNG5VandUelBlMnh2Sit5T1JIQmZr?=
 =?utf-8?B?dWorcE5GRFdXYVdkTkZmcTAxNG44UHRhU0hyOCtuTWRWdWowR3FuTS9DQ2hK?=
 =?utf-8?B?MnlmcFRnbEo2WldmZ3lsR3kwMitZSnFGTVFpOE5KL1NDZ2dNRzVEZkxsK3hm?=
 =?utf-8?B?QVdFRGJJV00wamROd2pYREQzQXJoTGJlNStCOVFSQmpDb0lrWmVTK3hReGVO?=
 =?utf-8?B?eDQvcFNjcXV4UEpOQTUzMURKKzBMUmk1THhZRWZYOS9NeDVLNW9qUW9nWndM?=
 =?utf-8?B?VDdIMUlvV1JYaUtyUUhyV1BQRHlQaFMyWFZRTDI5VVhwOTlsbEhvVVRQRGlS?=
 =?utf-8?B?L2pUcjdWOTVCS1QxeDZ6RjdkNzYrVjgyakZmU1Z6Z09DZkVZWDQxN0F1YVVi?=
 =?utf-8?B?NEE5U3NBRnh0Q1pqRFpJV1pyck1iWHA4Y2VjeFM4alFWdmxySUhPZGFEWG1V?=
 =?utf-8?B?SUlYL2ZSaStmd3JCTU56WXVpN2pPS0Jwdmd3REEwcFBXbmVSaGpTRU5YZEpO?=
 =?utf-8?B?MVFWWWdrdGNLalVaRjllUkdYaHJKMXhsK2dlZE4zUEtocWlyK054UVpOYVk4?=
 =?utf-8?B?R3pWRHNIdkpWbjF5MmV0SDhMMVZDQytnTlhILzJtM3pQNFFCckNna3o4b2VP?=
 =?utf-8?B?dlRJaTFzSEdZVFRLS1NzaW4zTTlUS0c1QldNS3BadG9WM2lya2JTTGNUMEpT?=
 =?utf-8?B?NVExaUdCTXJuRks3cldBdlJpQy9QZytqYTdkTTRvd2F6Z2hsdGRoWkhuTTAw?=
 =?utf-8?B?N2xtOXlDeDJjTUtQS2owdWxTODNZS1FRMlFZcUJ5bnkyRXN2QkpteWJMeXpo?=
 =?utf-8?B?WngydXo3enJtYkdMTWIvVjlPMnZ6Y1drSWlVRmNWaExWK3lOeFIrRHpUc0xP?=
 =?utf-8?B?enpJNUg5SDlNL3RKRlk1NEI5aVpDSnoyUnFkNURaek00U284VDhnSG5LOGo2?=
 =?utf-8?B?Zmc1SzMyeHRQOXp2eGRDcmc1WHpka3BmMkRoK0hIdEFxT2dIeUtPYjJzNXV6?=
 =?utf-8?B?SE9VZTRpMUJIdmJZSW9FUlYremg2djFrMGlTclpnWStEL0VaajdTTjRRZDdI?=
 =?utf-8?B?VWtheFNYeHhySEtGTEJlWHB5ekdxOFdtMUR3ZFdQU3prT05GMzliT2JMR2R4?=
 =?utf-8?B?QU5EeXU4SEN1dTRGdUMraHh3NS9yeG05a3BkdTBmbDZSa2ozalZnb05nWit3?=
 =?utf-8?B?aTZuZ3hMYkxHcVBydU1KTEJHQlRDcFRKZyt6NGg0eFVzM0VuMVNwbmpqY1d4?=
 =?utf-8?B?aUtEamlUcUZpZlNvbmUrVG1wWVVielFxbENkYVNtUVU5ZnBrU0dERHV4dktY?=
 =?utf-8?B?N2NsR3VYWWpsZm5yOFV4ejVWVnVvMzlGS0l5d1hyLzJDWFNJOFN2bU9MaTlq?=
 =?utf-8?B?SUFla3R1Sk1BL0NYWWlJUWtTWjdmRUYyNzRjVTFtU2NCOEJoMEEzZz09?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PH0PR11MB5880.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 32646faa-937f-43f3-0e61-08da13c7dee2
X-MS-Exchange-CrossTenant-originalarrivaltime: 01 Apr 2022 10:10:38.4185
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: S24SZGqBVXZzYPLz9xuvCsAC9AjVeFsfZ4TlgjBA1rNaI/PfohG8DVxwMZTsB0GH5i1+3dYr53P8od2Mr+/R4w==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BYAPR11MB3047
X-OriginatorOrg: intel.com
X-Original-Sender: qiang1.zhang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Xd7ZCFbB;       arc=pass (i=1
 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass
 fromdomain=intel.com);       spf=pass (google.com: domain of
 qiang1.zhang@intel.com designates 192.55.52.120 as permitted sender)
 smtp.mailfrom=qiang1.zhang@intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

On 2022-04-01 17:10:06 [+0800], Zqiang wrote:
> BUG: sleeping function called from invalid context at 
> kernel/locking/spinlock_rt.c:46
> in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, name: 
> swapper/0
> preempt_count: 1, expected: 0
> ...........
> CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.17.1-rt16-yocto-preempt-rt 
> #22 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 
> rel-1.15.0-0-g2dd4b9b3f840-prebuilt.qemu.org 04/01/2014 Call Trace:
> <TASK>
> dump_stack_lvl+0x60/0x8c
> dump_stack+0x10/0x12
>  __might_resched.cold+0x13b/0x173
> rt_spin_lock+0x5b/0xf0
>  ___cache_free+0xa5/0x180
> qlist_free_all+0x7a/0x160
> per_cpu_remove_cache+0x5f/0x70
> smp_call_function_many_cond+0x4c4/0x4f0
> on_each_cpu_cond_mask+0x49/0xc0
> kasan_quarantine_remove_cache+0x54/0xf0
> kasan_cache_shrink+0x9/0x10
> kmem_cache_shrink+0x13/0x20
> acpi_os_purge_cache+0xe/0x20
> acpi_purge_cached_objects+0x21/0x6d
> acpi_initialize_objects+0x15/0x3b
> acpi_init+0x130/0x5ba
> do_one_initcall+0xe5/0x5b0
> kernel_init_freeable+0x34f/0x3ad
> kernel_init+0x1e/0x140
> ret_from_fork+0x22/0x30
> 
> When the kmem_cache_shrink() be called, the IPI was triggered, the
> ___cache_free() is called in IPI interrupt context, the local lock or 
> spin lock will be acquired. on PREEMPT_RT kernel, these lock is 
> replaced with sleepbale rt spin lock, so the above problem is triggered.
> fix it by migrating the release action from the IPI interrupt context 
> to the task context on RT kernel.

>I haven't seen that while playing with kasan. Is this new?
>Could we fix in a way that we don't involve freeing memory from in-IRQ?
>This could trigger a lockdep splat if the local-lock in SLUB is acquired from in-IRQ context on !PREEMPT_RT.

Hi, I  will move qlist_free_all() from IPI context to task context,
This operation and the next release  members
in the quarantine pool operate similarly

I don't know the phenomenon you described. Can you explain it in detail?

Thanks
Zqiang


> Signed-off-by: Zqiang <qiang1.zhang@intel.com>

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/PH0PR11MB58800917A1BF8D1A76BEF84EDAE09%40PH0PR11MB5880.namprd11.prod.outlook.com.
