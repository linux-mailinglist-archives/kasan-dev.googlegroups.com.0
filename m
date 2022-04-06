Return-Path: <kasan-dev+bncBDR6TU6L2YORB65SWSJAMGQEMO5AA3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id ED02A4F53D2
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Apr 2022 06:39:24 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id o2-20020a056e02114200b002ca3429fc20sf1022633ill.11
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Apr 2022 21:39:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1649219963; cv=pass;
        d=google.com; s=arc-20160816;
        b=0djBxgsojf4TaQrtfvdNdsfJbvdupUKjPdirPh8IZxf1Qvz5moq/EAhJsKUUrdaEV7
         V0QAGlY1cyfI4U8UvmlU4ISIq2DDbSvmTIU5oj7T1GrnYsCvCRRN2zt7Pwp89oYA6kFZ
         qg7EgVBJIcIAxjHIbVIS1eLeIUk1eeA9xasEC1+GObiPsZXTCbnEVjX4UPqRa9vXhsbd
         5DuMVPZ/whRhjm6lUmrs0zI3Fsp8W4XurczURGVWZlBphJH1/hzddteK9DCBi1/jea5j
         fEjfm0pK/Q6Z4dyBd3S1qjNfS88jsqVRr9nOA+YYeeyWjNF7cSwFMTNrTq0mEBhVTNc7
         F3nw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:dlp-reaction
         :dlp-version:dlp-product:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=ORkJXBbRlGlT0DQLOPyPDK0TnR0fmgDrRAuyIJTSaeg=;
        b=I+tBpUwmKSZBgd5s2lMyB7+OjkfHJGVYupeTvNk0rDbsKB3UhJKqAj2ERvfVapzJDO
         OG2Re1lD6BuRcLIbAShY+Ku+q51L5uufE2Q4CMvjnFKhUveyFqsyuJv0n3DhkP7bRrFD
         wJsTJBSMhKhZ2/1FZBN5yHC86sV9UPy41e1oRS9phby7Ub4IbplkAUBa24KvaUxYOoVK
         +7cZnJpR3gHtmos3RK3IT+k9kL8TdXaiunQacSeU6R2C/QA+0tJ+EiWkAsJO2XMGNy/4
         XBtzrzFISveWI3hfhBQrQyGeCzJc9XQld6DZGbheNpNoBdXBqh5UkR9nPlBGrSoRdn7b
         WbXQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=IKCAMr2G;
       arc=pass (i=1 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass fromdomain=intel.com);
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:dlp-product
         :dlp-version:dlp-reaction:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ORkJXBbRlGlT0DQLOPyPDK0TnR0fmgDrRAuyIJTSaeg=;
        b=iIPM2MaPNj7Jmft8gw2dTpQsbCIE9AKPlRcPN2sU5CAVJuiKPFvwjGvaF3D2/4HP/m
         dKXKUF1PICQG7NnemeZw0rEmzHgshiVMKLzxNhdzyn0P4wjo+3IcdT7ORBGedHZ5V3cy
         WMDXtcQRcTHWXsFjnBxoDeuvOhC7sh9mIUg20qEs8a+5V4h4DXLlUPSfDpLeDiDZDxtQ
         5TRWG3iVASYvR11sgTcLnKOVW5Ljn2yGzmXMzowx8s1Q2oUm3Sp6PYyRzi1Q965vg7Wz
         VZsBeYeDbBRy/2gRrE82mIUewb6i3EmjVqlXwTRgk4hJ9qxSIZMpuWvAA0NR0AFXayut
         DbmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:dlp-product:dlp-version:dlp-reaction:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ORkJXBbRlGlT0DQLOPyPDK0TnR0fmgDrRAuyIJTSaeg=;
        b=miC1XKEDwts166eRWEiT3R5NtJ4iVsx6Qtxc0Fqu6JO7c0eDNJF9Gmq9juzrJplnty
         QojJ0h5byr4MbcOFCJazvBaIGA6+U8VqX+tIe2mSn9CqUfRLHui9ltc4oGLzGkBx1Z+d
         UzYPsY5DtYD+uaKJwPj7iY0CdH6p+cE0QsUP2zbtEe12cno8M36mA/BQlGdX3TzSEjbd
         P2E+xYhdx0Zm7kL/e0P1QRLFQnklG8+0p6iU9XXpDuB+6UNDIUsEy0UsiFFsu5Olh9WE
         WLRRkD+w78sDXJku0zEdAoBtHuP+wFhMHPkxpKxNazEegD96NZdEuf+AtG8W6H4d2ZoJ
         prHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CPfBmZlJF4Bdw7xyijk5dTElu9daSNckoN5g1ATuUoRKEqR27
	wdvjqhLhGMt8A27NqGAZXDQ=
X-Google-Smtp-Source: ABdhPJzZKbUbCL9Nq1LLWLNQEH447S40Y7y09GBcfyX2VIEeXIYln24J3zmyyIf9MIpiyG+XRS7eog==
X-Received: by 2002:a05:6638:1302:b0:321:41a3:afda with SMTP id r2-20020a056638130200b0032141a3afdamr3643391jad.254.1649219963607;
        Tue, 05 Apr 2022 21:39:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:aa81:0:b0:323:a215:cdc0 with SMTP id u1-20020a02aa81000000b00323a215cdc0ls4053439jai.5.gmail;
 Tue, 05 Apr 2022 21:39:23 -0700 (PDT)
X-Received: by 2002:a05:6638:491a:b0:323:7657:a235 with SMTP id cx26-20020a056638491a00b003237657a235mr3800642jab.225.1649219963009;
        Tue, 05 Apr 2022 21:39:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649219963; cv=pass;
        d=google.com; s=arc-20160816;
        b=XRlLVDvLAjwF7H56g5dO/CLNMWZjkt+TJ6IgWvHThjT0XsIKlqKYA4O2yy9NQfi6B9
         uSsTYwDFlAgD5spUVRAYq2w3z0SkPP7k3UgphhM818BW36QpJHKg68aBr6mmj3Je3MJc
         mzfud/xmdsLiaDMLaPLxGW2uq89yvHUJ4xIDBytBa+wCZdbcXE4ZkhJMMIvj4tpT1LtB
         tWuNq0BoHOKaIym8BPCT7UpPN4JJ3oUnYo3JKgVMCBX5XdJd8kRtPPQfnRc917Dts2QJ
         XFdoSpcM6PdaCvcTmiaNsUyCXhdguGAAvaHA2/lrg3iMiZE3zy+NcjTlOMTQVAtxvcEP
         x4VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:dlp-reaction:dlp-version
         :dlp-product:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :dkim-signature;
        bh=9qKera1kS3FNY0GCPrF5iXn8OLczEVOQ6vK5obEfMi8=;
        b=lWi2K7t2Ush5QXz0KzrtkYIX37luDQUJ7F82tyUzCN0zQv6vev2K45LfBC0IyWGVNY
         O1JNrU1PLho17cVR5UvasQg0nyQjBswGnjBO8Zqd2PtWsvqqGzlzBGCLrSlKnBR0U084
         lVP92vnV9GwjfUMezUhVLm2zsYhOM9F76kZpY6010knsZ848X9GsOnHJLE9/DWlnWU08
         Luvbe3SVerM2AO1RtKVLieNTRSQQT4z5jWfO22bgJzJr7R+GwBYbJGexV9rNn9zuhY8E
         3CMYuJqaZVErP9C2YOApWEP9rnavL7a2yd2wjnr3lBLaCa1DBusIA2DWlHFRjpqavPw0
         O+mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=IKCAMr2G;
       arc=pass (i=1 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass fromdomain=intel.com);
       spf=pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=qiang1.zhang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id p7-20020a5d9c87000000b006495f98f57asi944112iop.1.2022.04.05.21.39.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 Apr 2022 21:39:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang1.zhang@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6200,9189,10308"; a="347391728"
X-IronPort-AV: E=Sophos;i="5.90,239,1643702400"; 
   d="scan'208";a="347391728"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Apr 2022 21:39:21 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.90,239,1643702400"; 
   d="scan'208";a="790205264"
Received: from orsmsx605.amr.corp.intel.com ([10.22.229.18])
  by fmsmga006.fm.intel.com with ESMTP; 05 Apr 2022 21:39:21 -0700
Received: from orsmsx612.amr.corp.intel.com (10.22.229.25) by
 ORSMSX605.amr.corp.intel.com (10.22.229.18) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27; Tue, 5 Apr 2022 21:39:20 -0700
Received: from orsmsx605.amr.corp.intel.com (10.22.229.18) by
 ORSMSX612.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27; Tue, 5 Apr 2022 21:39:20 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx605.amr.corp.intel.com (10.22.229.18) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.27 via Frontend Transport; Tue, 5 Apr 2022 21:39:20 -0700
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (104.47.56.173)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2308.27; Tue, 5 Apr 2022 21:39:20 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=HEpY8vI7TSb1PixfiVqQVfFIg5TAGS0sHR0THcNoH0eq80wDWDmI7PA04D+UkIhR8Uf/0WqQQvtus66D8sE0jrzWOtjFEscjM1sbUK41aWa8CP8wSVSbGsGPcYqfmT+/xUIbepWgMcdTEB/WnPtJAc9rsnAGiVecLWHHSnazdn1+dn43QJEmz36386bvSHUBR7SBCUa0bYmnvcfgnNK6Ac5u29XOoVvpu+rRQdWQsrjEbPGwbSW0tYy4pUuZXtcBzhWyPtBeFq0e+Azb9PleJOfVK8qAP6xMu+89IUDWzfx3oqm4QBUtPT0EJ7JnxFSoJ2ss2w5dinFkbYFrKy4Qug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9qKera1kS3FNY0GCPrF5iXn8OLczEVOQ6vK5obEfMi8=;
 b=DSVyLjv80l2+N6IQj5YWbB6oUh38kFgNE/ixXxzTpbBx1ARqhnI7zOhuSVezSUWLvHcvGh1/wM5vQAiNU3eVfrvvEF23jcPOfNODEu7looV4+OwjwpJU5a/OHpxDMeg6KPSp4BQynBfMrsJRC6wO1zsxEyrvA2btWgheMZyffSJdYqDVXQZTpM0dhIP0e8mKCKyE2gKilGixPxvtov25UNMc4pLpa/swo5OWvU/moSjAPfe+/XiUFLOTYJ/mbhlheIi1xWC32dHYx0bn16wfjScVuN3l3+Lr66plP/yqPdlSL5XgwQlPXBskpP4IJ/nXjDiXT9sb1eWd5KUztdj9rw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from PH0PR11MB5880.namprd11.prod.outlook.com (2603:10b6:510:143::14)
 by DM5PR11MB1657.namprd11.prod.outlook.com (2603:10b6:4:c::16) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5123.31; Wed, 6 Apr 2022 04:39:18 +0000
Received: from PH0PR11MB5880.namprd11.prod.outlook.com
 ([fe80::6439:b0f1:f43f:54d3]) by PH0PR11MB5880.namprd11.prod.outlook.com
 ([fe80::6439:b0f1:f43f:54d3%7]) with mapi id 15.20.5123.031; Wed, 6 Apr 2022
 04:39:18 +0000
From: "Zhang, Qiang1" <qiang1.zhang@intel.com>
To: Dmitry Vyukov <dvyukov@google.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>
CC: "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, "glider@google.com"
	<glider@google.com>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"bigeasy@linutronix.de" <bigeasy@linutronix.de>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: RE: [PATCH v2] kasan: Fix sleeping function called from invalid
 context on RT kernel
Thread-Topic: [PATCH v2] kasan: Fix sleeping function called from invalid
 context on RT kernel
Thread-Index: AQHYRc7zp74DBEdkEUK28aFOHFLlt6zbOVYAgAB1GPCAAIWQAIAGIHZg
Date: Wed, 6 Apr 2022 04:39:18 +0000
Message-ID: <PH0PR11MB5880AF5035443BA97E69B95EDAE79@PH0PR11MB5880.namprd11.prod.outlook.com>
References: <20220401134649.2222485-1-qiang1.zhang@intel.com>
 <CACT4Y+YrKd=+uJT9UN8QvctPUGKnOgcReYfX41vNuVC0ecWXcg@mail.gmail.com>
 <PH0PR11MB588000A40081EC48536CA7A3DAE09@PH0PR11MB5880.namprd11.prod.outlook.com>
 <CACT4Y+YdRTu=5JhGcbzSra5mTJA4n6mimPSSwXtS=GswRa8CAA@mail.gmail.com>
In-Reply-To: <CACT4Y+YdRTu=5JhGcbzSra5mTJA4n6mimPSSwXtS=GswRa8CAA@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
dlp-product: dlpe-windows
dlp-version: 11.6.401.20
dlp-reaction: no-action
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 6cf0ac02-9d2a-4855-2ee1-08da178769bc
x-ms-traffictypediagnostic: DM5PR11MB1657:EE_
x-microsoft-antispam-prvs: <DM5PR11MB16577C712EA1691B4BD2EB53DAE79@DM5PR11MB1657.namprd11.prod.outlook.com>
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: uJUt57+aU73GMLTlVA4D9KKGGbGez3S7oaOiptWrUU+l6LURSus1NSFjDDzqcehaT+2KwUXwzvJ+Incy8ix9nrGnuncJWaUr4Q7JIXQx4V1oGHSk0uE0mfuVn96dse5NAUnQcLO3muKSNdAAaj8NYX98wbUPnp8gph8Ud/ArvxHsooAP9ahNnKIRY6HflalHardTJVEMWBEQPyK/iVShrV8k0L8oXTRHySWC8J3zhMD1x7LAupSE25ZbOpQguH6acSpSb1NYQv4+fO9aSBZvy7g5Ag2wBaQqh8cEPK1V1JdcHbiudNqKzZf+Y9uZDP+DweW4ByPyvqW995uR9CFEX9SpjXmXllBfnMr5yKiKHC0Dp1AWPmRku3ntTFFP2eANEa+SNICQxgTZ7dPiZ/01k6h5661xl7vMayqOCstBUzSbHQOfqdQNCto951XWOH8LA01ZeVvuFp7yF+ur/1fQwp1+iOv7n3HbBeJIzZKE5wE8X8r2gM+jJ3R4bEs12SpCp7TQh5fef6UrtlFmRzVE1MPxbVZGTqNMqoWX0OZJssBocO+W2lSKbcr1iYkqJlO7deyE5OH6YZkrWrZ2hHvK8NzF21qZE3b5vpTF6UeCMSEObjz9sB7tRH26Oa7c0laPIhBqRWyZNqhyknOmcEdKTe3wjSUuSk8jKy1dPecjMcwwQcFq9OqWG52sSnxKl+c4QrZfTkWnuDPX925XqmfopA==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR11MB5880.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230001)(366004)(6506007)(52536014)(26005)(186003)(508600001)(33656002)(86362001)(2906002)(7696005)(66946007)(5660300002)(4326008)(66556008)(66446008)(66476007)(83380400001)(64756008)(76116006)(316002)(122000001)(82960400001)(38100700002)(71200400001)(9686003)(55016003)(54906003)(110136005)(8936002)(38070700005)(8676002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?R0YvSjR0N0RSUlpHb1ViWlk5Nk8zU2ZBS2ZTeXV1WWgvTE13ZWpqUGFFRFhQ?=
 =?utf-8?B?ZWdLSUx0YWZaWERJaVVhcFRleHZoUTJRc2U3cDk3Qm5YYmRYR2JEbXJRbDA2?=
 =?utf-8?B?M3hHL04yUlUxSHh4QWszSVhGOGlYdGx0MTFSQjh0WWVEMFNiaW1KUkRLdTdk?=
 =?utf-8?B?dXcvZWc4dExLVFlvTStpcTVNY2EwcUdUaFJ4dEs1L2NxWVlsRGhCY0lMRFFl?=
 =?utf-8?B?dmdaVVNHOVFKRC91M1lBV3I4SFUrQWhMS0FDV3g4dlc0SGhFRWQ1NjNLK25L?=
 =?utf-8?B?dGNOVnYwem5yL1o5VVVBMmNPZWxVbGFZV2drV0RKK0RjNjFVNTc1cHcvdXN3?=
 =?utf-8?B?WFNKOGlvcTdaSjJqYUV4OFEyeUYyc2t5MUpQMktlQVBUM3A2SExtdzhOR1lk?=
 =?utf-8?B?WlVjQm9kZkxNSEhRdTBoMVNVMUhwaUk3VkxWRHNsSWg0WXVGUURGNUVUY3pK?=
 =?utf-8?B?bzBES2tSUldJbnlZRysvNXZsSXhhVnNXYnV2YURSVG1pUHY5eWtIMUxWZktn?=
 =?utf-8?B?SlFvTXpTalZiZ3JuRUFsZ2FMWmpXQThlaktzRWU4WGVIaHRCZk83ZkM3SXVs?=
 =?utf-8?B?ZENFSEJaRDlxQ0lheEcvSEJMdUlwL2c1SjA5SHBJNzdDaTNhQnRMUFZVdFZ0?=
 =?utf-8?B?Nmcyc2JmOFpJdGYwWXppRWliUmRpN0ZoTFU1NGJRdDNYc0tGNWhTcVJ4OWdz?=
 =?utf-8?B?Tk1ocEtaeXNDbmlqODEwRUZ6c2tWVy80UFQ5ZGZxWXY0N012dy9JNENTdWtJ?=
 =?utf-8?B?UEVURTlsSmZxWlIrNnB5SWZ1TjR5RnB2ZWgxVE10a3FEK1hRbmhKSDFPUmVD?=
 =?utf-8?B?ZXg1cDU2K3JhMXBkZFloc2ZBbG44ZjlIYysycTFKV3pXdm1oaXJpY0t2eGZR?=
 =?utf-8?B?dG5nSzFpRzRwT1ZCY3ZZdGxYQVFqdmFhMTJhMzB4Zk5pZVh5Tm9UUXVsM09m?=
 =?utf-8?B?RWxrcUlKbkdhbmdEMHZJN0ppZVJxcENwM0V3Sm5RSnRKa2YyaFYyZ1VxSk9j?=
 =?utf-8?B?V3h3SkhtUHVnaDdFUjQ4cUtCcVRBZlZYcTQ5eEhoSzlqTW5xYTdBUmxyWm1U?=
 =?utf-8?B?NXhJODdxYzZOSmI2QmN1UXZpSVNYNzJpZE1naEN1MCtXekVYdWJybzJKTU85?=
 =?utf-8?B?SzkzR2cvK05kNDVHNnZXTXlhcnRSREVDaEJIbjRiTFRteXExSGxXL3BaQ1hO?=
 =?utf-8?B?OXVsdTRoOXVqMFZPaXVGZkhrUWlCNUJZVUxUWDQzbHVicTNQNWtuVGRTSGZ6?=
 =?utf-8?B?QXFPTkdtQUZQalZzNHZoTG5IZUg4VmVyQ290a1A4VjJWLytJNEdZTXBQdkdp?=
 =?utf-8?B?NStsdmlUMVVodVBuT2dxeHRtS05kQjF0enIveU5xQmhpMWUrWkNvTW5TcjMw?=
 =?utf-8?B?N3FrVEo1d1d1bEpGZG1qOWlOTEJ5a0Z3OEYxU2tFaG10S2s5dE5BSSs3Mzd5?=
 =?utf-8?B?ZFlDQ0YyVEJWZmlrcjAwdUNRREo0Y253VnloVktuNStnU0VSY01oM1RiYXQ3?=
 =?utf-8?B?ZlI4bXF4cForNG90K2dHVi85aStDRUU3WXFacU82VDZ5WW1iWTBuZ2RTWWNk?=
 =?utf-8?B?UlhxSTRlamVpTVp1YncrNWZFVEwvUlUzZXNhaG4wV01SWFF1Ukp0Y09ZUVJL?=
 =?utf-8?B?bWVtdUlEd2pZanpKeVZ3NkxlallYTEdFM2s4YWlscDhEQmhSSnQveHd0WGlM?=
 =?utf-8?B?bWpuRDhVdk9wZkRSTzFQSytaeWZoVm9oYUtIeEt2TDdZSStOTkRRRktnSlBJ?=
 =?utf-8?B?ekt0NWtjd0NpSGZha21KVXZneU5hMFhReGxaZmZ2LzNldDFGWjRmc1ZlS1Bh?=
 =?utf-8?B?aTBIbXlmamgxMHpjR0dSNklZS2pyMkdpS2tTWHpEc0FNaUtmaTc1ZXlqZWl5?=
 =?utf-8?B?WFhveVhlSGhpakxma0JwOEVwR084YXVMNGtVVnlESmpuWlcrUlZzOEFIRGt4?=
 =?utf-8?B?dHlNZTZ0TEZYVkxoeW1HUzFNd1B2N2Njb2NEdkFveVhEWWt5aStMMUlBbEpD?=
 =?utf-8?B?YnNFdWJzUS9aWlVCWEtRVk5WK2NBZTFYaDVjT1VpT3Y1NS85MjdDSE9sa0cv?=
 =?utf-8?B?L2llNHM3UXRMZFliVEVNc1gvNEwzVDQ1L094N1pqSGJWNDhoN3BxM2FMTUNP?=
 =?utf-8?B?bEhGOUpWd0VFdU5kODdCdVRhOWNrT3A3a2Vuby9WS1hnRjFSbXFHUXhqYlZK?=
 =?utf-8?B?ekliWFpIUmYrSllnWWt2MDZ2TzdWZEovU1JSaytYNHdwSnFndzNlTy9YM1lx?=
 =?utf-8?B?bTRDKzc1ZzJuZ0JnUE5RUUdreWtEQUV6NlNQeUNiRE94bFl2Q3BjUXJiRXNv?=
 =?utf-8?B?bVpJdW5QYnpsRXV6VnVpOUZCNTI5anR2YmZkZGF4ZzhOenRoUklTUT09?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PH0PR11MB5880.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6cf0ac02-9d2a-4855-2ee1-08da178769bc
X-MS-Exchange-CrossTenant-originalarrivaltime: 06 Apr 2022 04:39:18.7685
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: yztZKfia1PPIX1r1nRcDySpMomUUpHmxqL6nH+7jDWNh/kAmVyQMYREsu8xy8McNIjfkqJtTLtsWHH7ZQO+19Q==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM5PR11MB1657
X-OriginatorOrg: intel.com
X-Original-Sender: qiang1.zhang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=IKCAMr2G;       arc=pass (i=1
 spf=pass spfdomain=intel.com dkim=pass dkdomain=intel.com dmarc=pass
 fromdomain=intel.com);       spf=pass (google.com: domain of
 qiang1.zhang@intel.com designates 192.55.52.43 as permitted sender)
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


On Sat, 2 Apr 2022 at 01:15, Zhang, Qiang1 <qiang1.zhang@intel.com> wrote:
>
>
>  On Fri, 1 Apr 2022 at 15:46, Zqiang <qiang1.zhang@intel.com> wrote:
> >
> > BUG: sleeping function called from invalid context at
> > kernel/locking/spinlock_rt.c:46
> > in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, name:
> > swapper/0
> > preempt_count: 1, expected: 0
> > ...........
> > CPU: 0 PID: 1 Comm: swapper/0 Not tainted 
> > 5.17.1-rt16-yocto-preempt-rt
> > #22 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 
> > rel-1.15.0-0-g2dd4b9b3f840-prebuilt.qemu.org 04/01/2014 Call Trace:
> > <TASK>
> > dump_stack_lvl+0x60/0x8c
> > dump_stack+0x10/0x12
> >  __might_resched.cold+0x13b/0x173
> > rt_spin_lock+0x5b/0xf0
> >  ___cache_free+0xa5/0x180
> > qlist_free_all+0x7a/0x160
> > per_cpu_remove_cache+0x5f/0x70
> > smp_call_function_many_cond+0x4c4/0x4f0
> > on_each_cpu_cond_mask+0x49/0xc0
> > kasan_quarantine_remove_cache+0x54/0xf0
> > kasan_cache_shrink+0x9/0x10
> > kmem_cache_shrink+0x13/0x20
> > acpi_os_purge_cache+0xe/0x20
> > acpi_purge_cached_objects+0x21/0x6d
> > acpi_initialize_objects+0x15/0x3b
> > acpi_init+0x130/0x5ba
> > do_one_initcall+0xe5/0x5b0
> > kernel_init_freeable+0x34f/0x3ad
> > kernel_init+0x1e/0x140
> > ret_from_fork+0x22/0x30
> >
> > When the kmem_cache_shrink() be called, the IPI was triggered, the
> > ___cache_free() is called in IPI interrupt context, the local-lock 
> > or spin-lock will be acquired. on PREEMPT_RT kernel, these lock is 
> > replaced with sleepbale rt-spinlock, so the above problem is triggered.
> > fix it by move the qlist_free_allfrom() the IPI interrupt context to 
> > the task context when PREEMPT_RT is enabled.
> >
> > Signed-off-by: Zqiang <qiang1.zhang@intel.com>
> > ---
> >  v1->v2:
> >  Add raw_spinlock protect per-cpu shrink qlist.
> >
> >  mm/kasan/quarantine.c | 40 ++++++++++++++++++++++++++++++++++++++--
> >  1 file changed, 38 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c index 
> > 08291ed33e93..0e33d30abb8d 100644
> > --- a/mm/kasan/quarantine.c
> > +++ b/mm/kasan/quarantine.c
> > @@ -99,6 +99,17 @@ static unsigned long quarantine_size;  static 
> > DEFINE_RAW_SPINLOCK(quarantine_lock);
> >  DEFINE_STATIC_SRCU(remove_cache_srcu);
> >
> > +#ifdef CONFIG_PREEMPT_RT
> > +struct cpu_shrink_qlist {
> > +       raw_spinlock_t lock;
> > +       struct qlist_head qlist;
> > +};
> > +
> > +static DEFINE_PER_CPU(struct cpu_shrink_qlist, shrink_qlist) = {
> > +       .lock = __RAW_SPIN_LOCK_UNLOCKED(shrink_qlist.lock),
> > +};
> > +#endif
> > +
> >  /* Maximum size of the global queue. */  static unsigned long 
> > quarantine_max_size;
> >
> > @@ -311,12 +322,23 @@ static void qlist_move_cache(struct qlist_head 
> > *from,  static void per_cpu_remove_cache(void *arg)  {
> >         struct kmem_cache *cache = arg;
> > -       struct qlist_head to_free = QLIST_INIT;
> >         struct qlist_head *q;
> > -
> > +#ifndef CONFIG_PREEMPT_RT
> > +       struct qlist_head to_free = QLIST_INIT; #else
> > +       unsigned long flags;
> > +       struct cpu_shrink_qlist *sq; #endif
> >         q = this_cpu_ptr(&cpu_quarantine);
> > +#ifndef CONFIG_PREEMPT_RT
> >         qlist_move_cache(q, &to_free, cache);
> >         qlist_free_all(&to_free, cache);
> > +#else
> > +       sq = this_cpu_ptr(&shrink_qlist);
> > +       raw_spin_lock_irqsave(&sq->lock, flags);
> > +       qlist_move_cache(q, &sq->qlist, cache);
> > +       raw_spin_unlock_irqrestore(&sq->lock, flags); #endif
> >  }
> >
> >  /* Free all quarantined objects belonging to cache. */ @@ -324,6
> > +346,10 @@ void kasan_quarantine_remove_cache(struct kmem_cache
> > *cache)  {
> >         unsigned long flags, i;
> >         struct qlist_head to_free = QLIST_INIT;
> > +#ifdef CONFIG_PREEMPT_RT
> > +       int cpu;
> > +       struct cpu_shrink_qlist *sq; #endif
> >
> >         /*
> >          * Must be careful to not miss any objects that are being 
> > moved from @@ -334,6 +360,16 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
> >          */
> >         on_each_cpu(per_cpu_remove_cache, cache, 1);
> >
> > +#ifdef CONFIG_PREEMPT_RT
> > +       for_each_online_cpu(cpu) {
> > +               sq = per_cpu_ptr(&shrink_qlist, cpu);
> > +               raw_spin_lock_irqsave(&sq->lock, flags);
> > +               qlist_move_cache(&sq->qlist, &to_free, cache);
> > +               raw_spin_unlock_irqrestore(&sq->lock, flags);
> > +       }
> > +       qlist_free_all(&to_free, cache);
>
> >
> >I think now there is another subtle bug.
> >I assume that by the time kasan_quarantine_remove_cache(cache) returns all objects belonging to the cache must be freed. I think there are scenarios where it's not the case.
> >Consider there is thread 1 that calls kasan_quarantine_remove_cache(A) and thread 2 that calls kasan_quarantine_remove_cache(B).
> >Consider that kasan_quarantine_remove_cache callbacks for both A and B has finished and shrink_qlist contains all objects that belong to caches A and B.
> >Now thread 1 executes for_each_online_cpu part and collects all objects into the local to_free list.
>
> According to my understanding
> Thread 1 only collects objects which belong to caches A , because the 
> qlist_move_cache(&sq->qlist, &to_free, cache) Will filtered again,  or did I miss something?

>You are right. I missed that kasan_quarantine_remove_cache also filters based on cache.
>
>Acked-by: Dmitry Vyukov <dvyukov@google.com>

Cc: Andrew Morton

> >Now thread 2 executes the for_each_online_cpu, calls qlist_free_all (on an empty list) and returns from kasan_quarantine_remove_cache.
> >Then cache B is completely destroyed and freed.
> >Now thread 1 resumes and calls qlist_free_all for objects from cache B.
> >Bang!
>
>
>
>
> > +#endif
> > +
> >         raw_spin_lock_irqsave(&quarantine_lock, flags);
> >         for (i = 0; i < QUARANTINE_BATCHES; i++) {
> >                 if (qlist_empty(&global_quarantine[i]))
> > --
> > 2.25.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/PH0PR11MB5880AF5035443BA97E69B95EDAE79%40PH0PR11MB5880.namprd11.prod.outlook.com.
