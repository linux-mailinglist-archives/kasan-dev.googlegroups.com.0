Return-Path: <kasan-dev+bncBDNPZZF76IOBBKMJSONAMGQECKYQKNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 373825FA9E0
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 03:19:39 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-355ae0f4d3dsf119152647b3.14
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 18:19:39 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665451178; cv=pass;
        d=google.com; s=arc-20160816;
        b=rCz9zU2OaQl7nqTMv/giVBpsuKv25MaikMigdRbmbPz93UD5oxw7GfYSMaWkrQ2aVD
         VCaw/iPTpLMVNtZwkGpsSnJjJ2FvG4GnfcyGgzhBXyqXtuO8kR9yy08kXwZCes8duNoe
         gwXlcJOm0e9amfUHdGEDSP8Ad9+EzzkqgInB8GePKNUf1EQ/c+eknzZ8edBl3b/pmRdD
         vWfxQ+lYB/TfMp4FvECmqSEgP1HygQySgwUjq9kqW35eT9Pv0tqGgpp9Y6sXwMU9iclz
         a0GlPKwMQpyoSs5/0buya09KPdNt4+jgUUSmaiBzR02dlqNPnXWmfQPMKx2lG8UeSpyt
         4Leg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=AmF1zHmbRwzsiKDX4WPfFeTWzE8XvvlStNjqPKKf+7k=;
        b=Mj+xa4OGYut5Dv/+9/fhHqP0REVltoxSrQtLpbXN2OhOMhsPBUPaPIZJkaw5jt6hmA
         bp9ymnFDtz26p26xUQhTDEkcNLaHOkLpoqDL3b42x+fTSGxRXfIjGddygAB1iExlUUAN
         Mr3KufCMl5vBmMD2MVYEtgFos55IPU84TH5CMK4kdLFgQtE/HWK21clWV4S7aC0RRk6C
         48VRT5gGCwy5hRTLQA4BZbT+SBR7KwyzFP2PAwgZMlEpr+BUxHCV9D+arqR9GYtBrzH/
         gurS4mm5dTSIKjoeNicrHYisl+6MeCfnlR0qKCLIhY6G5u+4x2a3pjtRAkAgbdrSh650
         Zs1g==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@hpe.com header.s=pps0720 header.b=X+Ikk5Yu;
       arc=pass (i=1 spf=pass spfdomain=hpe.com dkim=pass dkdomain=hpe.com dmarc=pass fromdomain=hpe.com);
       spf=pass (google.com: domain of prvs=0283e28102=elliott@hpe.com designates 148.163.143.35 as permitted sender) smtp.mailfrom="prvs=0283e28102=elliott@hpe.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hpe.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AmF1zHmbRwzsiKDX4WPfFeTWzE8XvvlStNjqPKKf+7k=;
        b=Rr29ev0mpq8lFIqqJWEa9q9VIvll/jdZmuA3tPD6zH/1uXYjr9wOBiYRpwRARnpob3
         GlvEM7kGf7J+mdkKehVhS0jkkHlkxSMo9d4sCmYXt5fedFVIZEM29b5svcb4DTZL8qLg
         3hTI8sIp3fwJeNlZ+rxzyhsz/htzh4DS68O3KFuKg4rEIny9VxkanEHfQxXxFnK2hefL
         d2xVkljeZQXbKy4l+5g+bzQv3bXxrZh9/4qp+SXaz2crCYEQ8NNZZ1Is3SvSRs/43AQf
         cUp+Jr7tUcZwtDBWTGOExCfAQYLWmXT17ZBjGQX5M5XlH65A0+DWICE0pXd1hd7d9Ckv
         K/VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AmF1zHmbRwzsiKDX4WPfFeTWzE8XvvlStNjqPKKf+7k=;
        b=ST4rf73qSB1+3++qOpBAysjeNYeWc8MJv4gHV0tx9gYGkCfRY8I1kAxFa4yb9hs9Ku
         qNSTP7VhdaGpztBgjefKaE52Q0jms2Gv8nv4Lok8DReL0P8h75SOnVJSKUZGdP3Ah2ch
         bp4rsCpxGtJxHSmNXN5PPGfAWUSee3nllePTPaq9wdtwukSNfJYPK5OU/fes3Qzuf1QA
         oJRzmiRhjmrc5Tff0znrHlnVAkoZnvVZO/R5v34/AUBzzhkkwLVMwYALVXucmZrA2hEd
         iwCOQgOni3EteuQK15SxxxsI0JKotOFOtA6YLF1p1TTZinCbVqTL1LgueZBw9WLpluX4
         aHbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2+sbmwJUuQE3an/6HVWyKvmjZry8F5sOno5FmVJ5oelNYTNtM4
	oGRzzSvx3LDegjh2jM94Cas=
X-Google-Smtp-Source: AMsMyM473vQ+QquOsNVfzZJOM6SKahGkD9Py5L8MJotIUxkaSm6wd4hxCr+w6LoNWAHCEiTk6dzGYg==
X-Received: by 2002:a81:5b57:0:b0:345:4681:c1b8 with SMTP id p84-20020a815b57000000b003454681c1b8mr19878424ywb.103.1665451177914;
        Mon, 10 Oct 2022 18:19:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:db95:0:b0:35d:623b:ef3b with SMTP id d143-20020a0ddb95000000b0035d623bef3bls4984109ywe.0.-pod-prod-gmail;
 Mon, 10 Oct 2022 18:19:37 -0700 (PDT)
X-Received: by 2002:a81:8606:0:b0:349:17ad:6998 with SMTP id w6-20020a818606000000b0034917ad6998mr19530021ywf.409.1665451177351;
        Mon, 10 Oct 2022 18:19:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665451177; cv=pass;
        d=google.com; s=arc-20160816;
        b=fAPontr5ke1KQYsagG1liyN7T8Ww0yAHjPOAK4+/wbVjqcf1UimKkETgTY5uN3z5Tw
         E5y6ocTShPqN+/mn6E5vgMmWNn9kVjgi/QUC6q1Ip0kF8lGGRRWe+6F0/8usibPNz3Mp
         7yyTDBeNPeZrt9cOAbIKAVpHYxUCtJRvYYkdTMYMgO+mIjzBoZOUculS5lG6W+ZwnfR3
         aRKwCWpSmNxN2Hp/ZhBhzsi9vkpWgTK2NZg5PuwcG+9G2vUCn6DokMkPaMrEVdRYTgzZ
         11sa9odiaiYqsRmA1vcXBbxmtBQJ7+d2RWum0hszzIGLVaprT1KoBYPSNES7Bn5NIwNH
         D6tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=rNZ80xLHv3c97fUATiizr4WJ1qnu5Xm13xUgF7u8mqU=;
        b=qz9qhJwLi1dFqHrCpOxyE15kZ5J0TRno3zldj9rk2f86vl+5o4XZZ88rCkmG46Iu0I
         U85mvdJFg8yQnV4u/3jGH5cUVXtXUHhNEkg0mGdFyHR9KEKlSUmHQS5raRiEf5fvDgl2
         6hcSXeYqjTpurBmzBSlZscGA7XbOiqP4D2wCBVvrDUkywQpGSbTwywUI82RaPpT7KcY5
         TqSEvLIat95K4CKUf1Z4/26fkJk8qSgUGLpJsBugdw2I+bOfJpCuf+Nirl7VM5vq1EJe
         6Z8yyBzqU2lipIfowJnTDD6X+P+JmPB4AQwWAl9eZ/ryzb6HpDPJCSZJknOmifOiL0Ij
         5o4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hpe.com header.s=pps0720 header.b=X+Ikk5Yu;
       arc=pass (i=1 spf=pass spfdomain=hpe.com dkim=pass dkdomain=hpe.com dmarc=pass fromdomain=hpe.com);
       spf=pass (google.com: domain of prvs=0283e28102=elliott@hpe.com designates 148.163.143.35 as permitted sender) smtp.mailfrom="prvs=0283e28102=elliott@hpe.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hpe.com
Received: from mx0b-002e3701.pphosted.com (mx0b-002e3701.pphosted.com. [148.163.143.35])
        by gmr-mx.google.com with ESMTPS id y62-20020a254b41000000b006be3d17ff2asi725369yba.1.2022.10.10.18.19.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 18:19:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=0283e28102=elliott@hpe.com designates 148.163.143.35 as permitted sender) client-ip=148.163.143.35;
Received: from pps.filterd (m0134425.ppops.net [127.0.0.1])
	by mx0b-002e3701.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 29AJwrwj014334;
	Tue, 11 Oct 2022 01:18:51 GMT
Received: from p1lg14880.it.hpe.com (p1lg14880.it.hpe.com [16.230.97.201])
	by mx0b-002e3701.pphosted.com (PPS) with ESMTPS id 3k4sdxa4k4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 11 Oct 2022 01:18:51 +0000
Received: from p1wg14924.americas.hpqcorp.net (unknown [10.119.18.113])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by p1lg14880.it.hpe.com (Postfix) with ESMTPS id 1E68D806B5A;
	Tue, 11 Oct 2022 01:18:42 +0000 (UTC)
Received: from p1wg14927.americas.hpqcorp.net (10.119.18.117) by
 p1wg14924.americas.hpqcorp.net (10.119.18.113) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.15; Mon, 10 Oct 2022 13:18:42 -1200
Received: from p1wg14925.americas.hpqcorp.net (10.119.18.114) by
 p1wg14927.americas.hpqcorp.net (10.119.18.117) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.15; Mon, 10 Oct 2022 13:18:42 -1200
Received: from P1WG14918.americas.hpqcorp.net (16.230.19.121) by
 p1wg14925.americas.hpqcorp.net (10.119.18.114) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.15
 via Frontend Transport; Mon, 10 Oct 2022 13:18:42 -1200
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (192.58.206.38)
 by edge.it.hpe.com (16.230.19.121) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.986.15; Tue, 11 Oct 2022 01:18:41 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=jqAbY6o50Xx8PB9ek6em3oTT4fMjLL49YBcQvmZh6mWlZRDdjtp0RIAVsv1s4to9Fu0I3/d6GqCCTRDO3x5FFtTKHrWEW53lfXz1GfmWHBSQEQth+tUbR/hm6bLOhvsg3k6bNpqP4gcgTmM1ftl5LYhTlLRdnHv2ix/47A/ZIZlg+VGQ10ehSvL8fxYW5n6uaSH4/tqXlqLDB/LMgSaObWJZFM1l6vxzjWB1SCgWqV8L8FOIhtrE+5ZvCC6ToQwd14L3KIhgOqAhIGNO9aCRXrdnnO56PKxQuPjfFTHnGcE9i3XOC2lLfJlOGW+2nbNCkXBXL5T24XMbEzuVknR6eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=rNZ80xLHv3c97fUATiizr4WJ1qnu5Xm13xUgF7u8mqU=;
 b=YAEbMiR0Wj85en4naS7r/WzeuXQ2a+V7KU5V/eFkaj73fqiINtKSFpQKAw8CYdHlMncYvrKF0bdE/wC74PaNlZXW7ovbvZlGGgce4+zvWb1jftM9+z/4d1ax/4l5UQYUTbHWNCTl9WWn08MeQWmHivU7lOwb+MTAFPTBONQPWjz4eXXdqbXlwUUFcKh+i0cCHp87UTZlGp0QkUZASLtxNCs0tTD3l2vl5jr4uUK/kO94qncAB3rcdRZYUv5gpc8cNvYN+5EFNGBOyavUyJk456W7Syw08poH2eKsC1u94N25G/J48Idk4i4D4vhEt9qRgcQiAJ99BgPCUrEFi14QbQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=hpe.com; dmarc=pass action=none header.from=hpe.com; dkim=pass
 header.d=hpe.com; arc=none
Received: from MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM (2603:10b6:303:1c4::18)
 by PH7PR84MB1366.NAMPRD84.PROD.OUTLOOK.COM (2603:10b6:510:15f::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5676.34; Tue, 11 Oct
 2022 01:18:40 +0000
Received: from MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM
 ([fe80::c023:cb9a:111f:a1b2]) by MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM
 ([fe80::c023:cb9a:111f:a1b2%5]) with mapi id 15.20.5676.032; Tue, 11 Oct 2022
 01:18:40 +0000
From: "Elliott, Robert (Servers)" <elliott@hpe.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "patches@lists.linux.dev"
	<patches@lists.linux.dev>
CC: Andreas Noever <andreas.noever@gmail.com>,
        Andrew Morton
	<akpm@linux-foundation.org>,
        Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>,
        Borislav Petkov <bp@alien8.de>,
        "Catalin
 Marinas" <catalin.marinas@arm.com>,
        =?utf-8?B?Q2hyaXN0b3BoIELDtmhtd2FsZGVy?=
	<christoph.boehmwalder@linbit.com>,
        Christoph Hellwig <hch@lst.de>,
        Christophe Leroy <christophe.leroy@csgroup.eu>,
        Daniel Borkmann
	<daniel@iogearbox.net>,
        Dave Airlie <airlied@redhat.com>,
        Dave Hansen
	<dave.hansen@linux.intel.com>,
        "David S . Miller" <davem@davemloft.net>,
        "Eric Dumazet" <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
        "Greg
 Kroah-Hartman" <gregkh@linuxfoundation.org>,
        "H . Peter Anvin"
	<hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>,
        Helge Deller
	<deller@gmx.de>,
        Herbert Xu <herbert@gondor.apana.org.au>,
        Huacai Chen
	<chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>,
        Jakub Kicinski
	<kuba@kernel.org>,
        "James E . J . Bottomley" <jejb@linux.ibm.com>,
        Jan Kara
	<jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>,
        Jens Axboe
	<axboe@kernel.dk>,
        Johannes Berg <johannes@sipsolutions.net>,
        Jonathan Corbet
	<corbet@lwn.net>,
        Jozsef Kadlecsik <kadlec@netfilter.org>,
        KP Singh
	<kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>,
        Marco Elver
	<elver@google.com>,
        Mauro Carvalho Chehab <mchehab@kernel.org>,
        "Michael
 Ellerman" <mpe@ellerman.id.au>,
        Pablo Neira Ayuso <pablo@netfilter.org>,
        Paolo Abeni <pabeni@redhat.com>, Peter Zijlstra <peterz@infradead.org>,
        Richard Weinberger <richard@nod.at>,
        Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>,
        Thomas Bogendoerfer
	<tsbogend@alpha.franken.de>,
        Thomas Gleixner <tglx@linutronix.de>, "Thomas
 Graf" <tgraf@suug.ch>,
        Ulf Hansson <ulf.hansson@linaro.org>,
        "Vignesh
 Raghavendra" <vigneshr@ti.com>,
        WANG Xuerui <kernel@xen0n.name>, Will Deacon
	<will@kernel.org>,
        Yury Norov <yury.norov@gmail.com>,
        "dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>,
        "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
        "kernel-janitors@vger.kernel.org" <kernel-janitors@vger.kernel.org>,
        "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>,
        "linux-block@vger.kernel.org"
	<linux-block@vger.kernel.org>,
        "linux-crypto@vger.kernel.org"
	<linux-crypto@vger.kernel.org>,
        "linux-doc@vger.kernel.org"
	<linux-doc@vger.kernel.org>,
        "linux-fsdevel@vger.kernel.org"
	<linux-fsdevel@vger.kernel.org>,
        "linux-media@vger.kernel.org"
	<linux-media@vger.kernel.org>,
        "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "linux-mmc@vger.kernel.org" <linux-mmc@vger.kernel.org>,
        "linux-mtd@lists.infradead.org" <linux-mtd@lists.infradead.org>,
        "linux-nvme@lists.infradead.org" <linux-nvme@lists.infradead.org>,
        "linux-parisc@vger.kernel.org" <linux-parisc@vger.kernel.org>,
        "linux-rdma@vger.kernel.org" <linux-rdma@vger.kernel.org>,
        "linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
        "linux-um@lists.infradead.org" <linux-um@lists.infradead.org>,
        "linux-usb@vger.kernel.org" <linux-usb@vger.kernel.org>,
        "linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
        "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
        "loongarch@lists.linux.dev" <loongarch@lists.linux.dev>,
        "netdev@vger.kernel.org" <netdev@vger.kernel.org>,
        "sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>,
        "x86@kernel.org"
	<x86@kernel.org>,
        =?utf-8?B?VG9rZSBIw7hpbGFuZC1Kw7hyZ2Vuc2Vu?= <toke@toke.dk>
Subject: RE: [PATCH v6 3/7] treewide: use get_random_{u8,u16}() when possible,
 part 1
Thread-Topic: [PATCH v6 3/7] treewide: use get_random_{u8,u16}() when
 possible, part 1
Thread-Index: AQHY3P1NjcMGwqqSWkuLJPkN/lqIja4IYEag
Date: Tue, 11 Oct 2022 01:18:40 +0000
Message-ID: <MW5PR84MB18421AC962BE140DDEB58A8BAB239@MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
 <20221010230613.1076905-4-Jason@zx2c4.com>
In-Reply-To: <20221010230613.1076905-4-Jason@zx2c4.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MW5PR84MB1842:EE_|PH7PR84MB1366:EE_
x-ms-office365-filtering-correlation-id: bfaa07c7-2468-4b6d-c263-08daab2687f7
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: M2O6foSQYmsgZteg3U0Bwbzc5ibiulIs7xr1UE+mluU+s+7GvTuJE1Vssm9fNAnEtXQVM0pGUEGupSSSGsELjw9jqrfIj3904SK+cwZpWfVLqeN+mPMaoyohhS4ZNsX3/iBXNFHNmk9HyQ++DAxa8PxEQyDikN/+eM6HXNOIPOc0z0hXgudSe5akaPXlKYdLOC0EbQvHYYuThLY/JueS/9SJkbqvN0wgQKatR8oXodovMOiKsucGk18mNpdKF1NP2jEiflLVUI4jkfYR4OQgU1MfqGgaNbRcBdjiXyL9IoQ5I5tqgMu8ey3b0kIz1HnCNyyYHotGgg7Du47dM441ay+M8oB7OQwKYdEibO/mOop6swOVNE9YuDql5VVuH/d6ZQQgupQFM53JY8dQYPEEeg9q0h9QY3K+ukBDEthFLf2im5hpIojF8/JW1qG0Q9sHqTwpdsYjxbJ8woE5cUE355eLKXxbk6HapuUktPOLKlHmAiI1WWUlb/6wxrRxyOqHGMF81ZwMJ0QxRct1WHmVnQuq40iOA9KcLzdIoUlVvXHiulU4m5KSVw9tZTH3R0DewOU4FS7ZkKIQv+91aT3cjMxLIVivVV6qMxruS4sJ2WhUKeziP250G0m0iFTwAnIASaKOXkTLIdr428ooPRjJdZeZtp9PypV5F7d0em48Z52zg5s0gJ/s5GYej9uLBk1RG91fxm5IQmxPk///KAPd4/pdKTPD7mVti84ggOELBSBNMNX3PPO85MJ/M+y2xuG8t7YmeJQQKKtEz5alzg8EHg==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230022)(136003)(346002)(39860400002)(396003)(376002)(366004)(451199015)(26005)(316002)(38100700002)(33656002)(122000001)(66476007)(4744005)(64756008)(7696005)(76116006)(66446008)(66556008)(66946007)(38070700005)(8676002)(4326008)(86362001)(6506007)(186003)(71200400001)(9686003)(54906003)(110136005)(82960400001)(478600001)(8936002)(52536014)(7416002)(7406005)(7336002)(7366002)(41300700001)(55016003)(2906002)(5660300002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?MlpvdzRSeVZMVFg5K0dKNVlrcWFNY3BCdktrZFM2QVExUlkvdERnQmNidGhh?=
 =?utf-8?B?c2tYRUJrRE9zT3hrZkRKQXNRMmdtbC9DNWRBajhVeTNRbHVCbFdxYmoveEdY?=
 =?utf-8?B?OExmVTlWR3RUclRWNmlVVTJSdmUwbTc5T21VUlNtTjhlY2ozU1EwbkpudW5T?=
 =?utf-8?B?aVRtSWJ2cHA1cC9GZld0S09GY3AvMXFEem1sRXJtVWd1M1dseE1Qa0l2dENZ?=
 =?utf-8?B?R1B0aVptRHRweklHUk52cW03MXQxYTBpK2VxbWh2b1BPbm5RY1BueVZRNjg2?=
 =?utf-8?B?YTlyUU5VWURucWZNVWdoNXFlQ0VrT3psMXJVN0Rra3BNa0hpME9oN1dZN3c1?=
 =?utf-8?B?Z05zY3BmT0dYNTMydXkzTENmMGlxWmNHbHJqbStsRldVSHVvbUU5OFBZejM5?=
 =?utf-8?B?VG12UTA3VEY0WHprR1V5ZEsxTVlmTXE5bHNuUElwcVlCVlM1cFRhV011b2Za?=
 =?utf-8?B?WFlYOXVocTZKSVRTVWZtM3o2aHdzWUt1YUJ6V1pVdEdCWFAxMHR5QkZZOHlI?=
 =?utf-8?B?N0plaFB1R000SEg1Y282bUVXSElhNmpVcmFTdFJpNjdscGwraVd1cmFiSWZT?=
 =?utf-8?B?clhFM3ZqWXhRS2lMaGc0ak5Vem5uQVRDb1Y3b3U2NkIyYnFwUmkveGZJbHV6?=
 =?utf-8?B?bEZURDJ0eXJ5NExuSWpvaTVyMG5tWjUwS0lTSWJIeDdyelJQR3ZYb21JSjVl?=
 =?utf-8?B?L1FaMHZsTUt4RFdENDhpSCtNZk1aekl5TG5QZ1o2Z28vYmlBdjFlRFpZb2VL?=
 =?utf-8?B?cThPZzI1NlhlS0Q3SysvT204TFFraERjekNnemhHbFBRd1FkTWFyZ3UyNVRM?=
 =?utf-8?B?dCtCVWN5REl6ZENWNkQyWHc2RzFQN2orY0xBRzBWWm1TUzJJdGFCZW44NHZF?=
 =?utf-8?B?ekV0aUZGT0p2SE9tTXdPWGFhOEV3SUpWVEg0WWxpMXMydHh6UDdQc0t6LzQy?=
 =?utf-8?B?aXZQdUt0NDMrbGpHZGQwdWxHTmpOQllYM25nK2gzdXMxRm9IQ1BpaHhJanZE?=
 =?utf-8?B?QUcyRm9uOFhmYitaSFdRMGJLcTAzU1pPOHhYWER5YzNCczBKdUdrTGFLK0c3?=
 =?utf-8?B?QmVVQVBhRlhxWnFUSW5uZE5yV045Y2hzbis0TERuV1ZCWFZZYmM3RUxldjU2?=
 =?utf-8?B?Q25CWjVaY01OOTlHVTF0cERiSzVIM1hGam8xVVRyZnk4d1FGcDVlbUJLSDJa?=
 =?utf-8?B?cDdRbC9waUtBRGdETTlSWUdBMXVvZ3pUaStuYnhwTUtsNzFYR2dlWE04MktP?=
 =?utf-8?B?ek0ycmROQ1BzQTc4SnBtVU5uZm1MZG5NMDVuV2s5akdhTkxOa0U5aHVJaWdL?=
 =?utf-8?B?RGlDcnFBSHdNd1VnOWduLyt0N09USEo2SlU4VHd6QUdoMkNtcy9tbXJtcEhY?=
 =?utf-8?B?ZUpscUFhalYwd3hZMGZaZldBVEJpcTN1dHRiS2NvdmZNOHBtZno1bUNqd2xT?=
 =?utf-8?B?YkJURHZ3UFZGMzgwMll6YXVCUHArdUY0T2V2cTZlcnE5eXIrMGF3M1hBS1Zs?=
 =?utf-8?B?Y1RlVFZWd1d1RGZMMk9zYUJuK3IrMnRVZWdtZXYrQ1BHTGxaSCsxbmNNYktV?=
 =?utf-8?B?Yit1OUJCdmtRUVk4dFpuQTNBUHlvZmRKRHFnR3hwSnpxYU40cnM2SFJITGk3?=
 =?utf-8?B?aUR6bXJtUkM5cE5SMnZBdUVmU0Rwb2tEN1R4OVB1RTk3Mkd3bURjTmY3RVU3?=
 =?utf-8?B?WDVwWG5kQVFGQ0RscTkra0ZCeWRBVCtrSGNqcVdkZFRmcFVXRzZveFkvT3pm?=
 =?utf-8?B?VDdhNXpVV3U0Zi9YVHpkVHFFd3RoVE5Tb1JOOTMvSlJMeWhGeWJwTGp1SHB0?=
 =?utf-8?B?QUxFQlNrak9OQ1hZQ3RhK2VaQWpJVHhtR3FnNEtDRTBWWGxlSkg4QlVSK3Rt?=
 =?utf-8?B?enFYWm9QSlErQ1p0a3lEV0FRVVQ5alZJZGdxc2hvalVpUWhaVzRkQmVyeXNt?=
 =?utf-8?B?Nkw3enlJVlJRRzJqRWluRnI5NTkvc3k0SVlwbndQMjA1bzdiY3NTZXhmZm83?=
 =?utf-8?B?NTJwM0dTWVRRRFVabUFoZlNWUkZRNEdGd1BFanFNT1hub005eXhnNjZ3UFY3?=
 =?utf-8?B?eGtxR2tFcDNJODY5MkFHT1pyOVh3RnRReE95dFhuelpkYXlNcno4NEtTbjh2?=
 =?utf-8?Q?S0YA=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: bfaa07c7-2468-4b6d-c263-08daab2687f7
X-MS-Exchange-CrossTenant-originalarrivaltime: 11 Oct 2022 01:18:40.4146
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 105b2061-b669-4b31-92ac-24d304d195dc
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: rJQbQ+h6dy7pzIAU/OPSuJHnLBtLQ/K7M4B/vP3aJNQZx5GDEfgMbuPot67UDylo
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR84MB1366
X-OriginatorOrg: hpe.com
X-Proofpoint-ORIG-GUID: qwxpC5pkiQSSTL8jNKSi61y1st3Y1_r0
X-Proofpoint-GUID: qwxpC5pkiQSSTL8jNKSi61y1st3Y1_r0
X-HPE-SCL: -1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.895,Hydra:6.0.528,FMLib:17.11.122.1
 definitions=2022-10-11_01,2022-10-10_02,2022-06-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 mlxscore=0
 priorityscore=1501 lowpriorityscore=0 clxscore=1011 mlxlogscore=839
 phishscore=0 adultscore=0 impostorscore=0 spamscore=0 bulkscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2209130000 definitions=main-2210110005
X-Original-Sender: elliott@hpe.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hpe.com header.s=pps0720 header.b=X+Ikk5Yu;       arc=pass (i=1
 spf=pass spfdomain=hpe.com dkim=pass dkdomain=hpe.com dmarc=pass
 fromdomain=hpe.com);       spf=pass (google.com: domain of
 prvs=0283e28102=elliott@hpe.com designates 148.163.143.35 as permitted
 sender) smtp.mailfrom="prvs=0283e28102=elliott@hpe.com";       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=hpe.com
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


> diff --git a/crypto/testmgr.c b/crypto/testmgr.c
...
> @@ -944,7 +944,7 @@ static void generate_random_bytes(u8 *buf, size_t count)
>  	default:
>  		/* Fully random bytes */
>  		for (i = 0; i < count; i++)
> -			buf[i] = (u8)prandom_u32();
> +			buf[i] = get_random_u8();

Should that whole for loop be replaced with this?
    get_random_bytes(buf, count);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/MW5PR84MB18421AC962BE140DDEB58A8BAB239%40MW5PR84MB1842.NAMPRD84.PROD.OUTLOOK.COM.
