Return-Path: <kasan-dev+bncBDLKPY4HVQKBBGM57SMQMGQEGKQDQNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 741135F6CA5
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 19:21:30 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id q10-20020adfaa4a000000b0022cd70377e4sf741679wrd.19
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 10:21:30 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665076890; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vt4RC+F5q8N7auFIF7zndpXKvFGcZFE3obyXJoqEkxkROUeJQ5oxYe7jdvwlwvOypd
         sTEjiYqsBF0xHDjKZWLYD6+BDfv4xwZQYAYEg0pd4upIEIgq1YF1LRBYBJ7A9a77PPAc
         yKuKvQiKNJ3eo7kt8wWfMeb3fbTXlgixWvepST7rFW8Znd3ZZwlk7XPYFWwd7x6e1z5P
         NupyktGeSXsynD8PGBLnVqMl0DINKBYyylb0XJEjwjHE0hSk5eYWGsguhIA3fjmv8RNH
         afKpG9YxLDpK+0Vz5wh790g0l8aHILfTSediEHF/UhJGGp7AsZStjgxIGmhYTAFPOPN7
         Wtcg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=Mp7U1WE1yFJ3VdqO7rz5+KKRSYjqu+6hi6JBXU8CQ5U=;
        b=sg3UNiNLKQhhHmGWKblZBqAJDox5Z53QnwvgEoVnyPXYJHj77Eq57GhYqy1uNJnEpZ
         I2Jfgwac47qKGFnfV2lauNBpwJGi7rbFRH9hEmSMI/ujtVR4n3NtApqw1rXecsUw2u6M
         ReHY+llVk0wcx3lq44KC+DUWWHnbEJZTAwl37w5IjwFI+/9pC+DEiiqwNPU8TVhrQOK0
         WQl4o+Ku+NP+4AzLR30kkGPQM77O6OJX3nTa+3t+95Frlx4IuihUmTME4kd3yu83QHLa
         aGStGyMl+NoUdeS+0dcXQc+URyKChV0dC11cACt0O5sbBpLuWWybx7VCRd90awdrClCU
         SoPA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=znWL7iOz;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.52 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Mp7U1WE1yFJ3VdqO7rz5+KKRSYjqu+6hi6JBXU8CQ5U=;
        b=doC7RqG/3TNY8X1o6laqk1kIb4GayUG5/diazkoNGal44VqILMUgyA3JQd9sYT7pGP
         a/eWskZkcKoCrYosLrdl8DfpQNUcLEyNwchvDzoTY69siLfOI7MydNPYudvhJLmytO7I
         pFjWuyKiuOyH6hefgPl+hXUNrB3YcEQiM3DXxOlGWac8BePVoMNeGvnIWKN9lyzIyygp
         Q2Uh/j5k8FeppoNHvrX/nmhk6Dg1Nwmxl2mw5TDJ+aR6gv4vrkaDwU3jrbtYQIU46NXT
         458WBUOyCTrJZQoKVO0amh/c7hY9abUv88hPprG1TbxSO84n6GnACCKHZvW1g7F5uYBY
         E91g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Mp7U1WE1yFJ3VdqO7rz5+KKRSYjqu+6hi6JBXU8CQ5U=;
        b=SAq9pvrcHeznnxYvDRDtoUND3fqP4uV5eZEb8lPIKhGd2cSoJX5ooN+0ex7cFgUXUz
         1j97hv3QrhLoJ8hU87Fc/ZA5tCJ0da3ZyNKDE0Ajexd+fn8GgyglxeE1ELLmuQzYTpVb
         9mPn2XmS3vHJsM4/znSJ9cih0Dg7jjGFx5e83VwtG+P0gkeJL4M2BwIk5YkonlT7ZGHk
         N8A1ftK08qnn+/U+MNAuAv+KoZSEoTaCpnEmiMFwS0rk16S07qebxTxYT0dLROfmauOk
         0jAoM09i6B7q9PnnRhTXMBMSHiJj4L5xvXPlFIw3UsDFK8Ft/dYK8uAswqp0nCeZOlAH
         O8Jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3WXviK1OOamrz92ECnHhiinxCHYegyAkSXDjj6RwbRTCHUaQNO
	F/vaUYIBkBAdbasVvEcQoso=
X-Google-Smtp-Source: AMsMyM5T406Jh3/1MhduA0EWTvga/hwYscsISRcqykyM+q7cGWj7XyW6sQdmv+eutKfO6T12xZWCVQ==
X-Received: by 2002:adf:ee84:0:b0:22c:d1fd:71d4 with SMTP id b4-20020adfee84000000b0022cd1fd71d4mr703610wro.350.1665076889991;
        Thu, 06 Oct 2022 10:21:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6011:b0:3a8:3c9f:7e90 with SMTP id
 az17-20020a05600c601100b003a83c9f7e90ls2813685wmb.1.-pod-canary-gmail; Thu,
 06 Oct 2022 10:21:29 -0700 (PDT)
X-Received: by 2002:a05:600c:1990:b0:3b4:c326:d099 with SMTP id t16-20020a05600c199000b003b4c326d099mr602168wmq.19.1665076888949;
        Thu, 06 Oct 2022 10:21:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665076888; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yf5/xiftPCDhkEopo1XtNtsM4Bw4XMLDVrhVO0farmhS0JKLxbdu7fu0Y+kse/95i4
         yij0rEYq6mV0q5N/77vLLHENMTFTxVp0HlFjT7BHdcOEhoaT+jp3arSbxqhsSJdtrOq9
         bBQVv5eMfpvV0sN5DaU0ggou6tFhw3joEjhjuekfcyEoO4+RjILwuZjnmDvoO+JsByqJ
         m22rjIiAf/+LR4SQf2+v3E9VBxEKcU4pLcGUpQWOBwqwPZI0xhROVRZPfRzWKgQUsKjZ
         0fxkEXVJc7hV55bgJ0UWxhe1Jio+ADbqXGVKsv2u4td+s3nmmz+68GuT7vuEA0IQl2Z9
         BLtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=hjkjH08M4BavjCLQpBhfFzbbLl1J2iit9rB7l3k/q9Y=;
        b=UhafgHH35g3UbcVjYSQyU0pXCFhUavXNkq6jegvGdoS9bGCifT7T4FsVCzcAXuxvuP
         u0Jyl1dhLINoO8mnPDyVSh+hKw5Z7SPHEk+Hnb5qxjjUckjPuM3QDiaG53uZ38/OMyIV
         ViuWvUsQy1y3mzH32ljRTAxnUug7jtl0vtwK2pbJ5/iK6nO4xVTEN/7BdrPRvt74KOx9
         TEk70EnqceH6D+KLZ4We5nJolnCJB7xdpmTuyxf2yyqtW3t9hoYMAvBwVqeLhObZMmnE
         3ozwcQU4csOOglhkPjRC2FDN0R3zoa7PMfYcku8UhHxpXuluJhht9tFXv2P/ilgGFzFQ
         yifQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=znWL7iOz;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.52 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-eopbgr90052.outbound.protection.outlook.com. [40.107.9.52])
        by gmr-mx.google.com with ESMTPS id 125-20020a1c1983000000b003a66dd18895si394968wmz.4.2022.10.06.10.21.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 10:21:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.52 as permitted sender) client-ip=40.107.9.52;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=aRoWTW7pFSXDoezeLFWI45o7NPUHlsDL5IAF/y6dQy84WqOvRojWubvIbwFcVn/tLGicLc8o8Vnhk/D2tugHTFG8WumBGMzvjdjzH7wBY8jYzdr6AdoJ7Tyzhs/+e0WA9d3Bhz8E0dXGSAWJhManGyy8D3kWrnoR5iKAK3eDZSaztzFqBMCDlLnIpdQ37QIcCN+10Lc8WTuYEQPwML/W7YaDG7yplpFtxzfY2jhnsdOAZ0K/D/0T3KLg4g0EV17qYRWA6LvNX7QhNTtHo+UAS7XlbckwbOKrzuiMhcEYU6AbvX+Ob8a5lTCsIfmblb6c4BSAMoRODvO0uWjj/+uPhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hjkjH08M4BavjCLQpBhfFzbbLl1J2iit9rB7l3k/q9Y=;
 b=cXWq0Q7CNJsEuF9NJ93OLaBaz+AhyZnYIF+5wc95uRH2IjSx75ULFSmCBXXgRw/sPDz/PxOwGSF9UDIMcC4ZSLpCOAZwHs+K5i4ULVI/jbm6eXIlhOl+PLQ28f9tHMf1Tsf8qtUkszokwkiyGT+4DEdbwkE/LJ7xPKkhpt78w+7VOq+8PFo71YuqbX93owo3pI8dkLOtxdaGDMXcLfI4XxF/MmJ5rom5lgw6YLe9OWca9zo07022iLhtQYwdW3PI00C+argrXR91v78AsJtmvnd4TnbSjtalFVYmj9wQexDaEalqjKKEeS3/jRDZj9Zdo8mq1nqQMuG8zGbB5E6Lxg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR0P264MB3324.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:144::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5676.28; Thu, 6 Oct
 2022 17:21:27 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af%5]) with mapi id 15.20.5676.036; Thu, 6 Oct 2022
 17:21:27 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "patches@lists.linux.dev"
	<patches@lists.linux.dev>
CC: Andreas Noever <andreas.noever@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, Catalin
 Marinas <catalin.marinas@arm.com>, =?utf-8?B?Q2hyaXN0b3BoIELDtmhtd2FsZGVy?=
	<christoph.boehmwalder@linbit.com>, Christoph Hellwig <hch@lst.de>, Daniel
 Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, Dave
 Hansen <dave.hansen@linux.intel.com>, "David S . Miller"
	<davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, Florian Westphal
	<fw@strlen.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "H . Peter
 Anvin" <hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>, Helge Deller
	<deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen
	<chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>, Jakub Kicinski
	<kuba@kernel.org>, "James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara
	<jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>, Jens Axboe
	<axboe@kernel.dk>, Johannes Berg <johannes@sipsolutions.net>, Jonathan Corbet
	<corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh
	<kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>, Marco Elver
	<elver@google.com>, Mauro Carvalho Chehab <mchehab@kernel.org>, Michael
 Ellerman <mpe@ellerman.id.au>, Pablo Neira Ayuso <pablo@netfilter.org>, Paolo
 Abeni <pabeni@redhat.com>, Peter Zijlstra <peterz@infradead.org>, Richard
 Weinberger <richard@nod.at>, Russell King <linux@armlinux.org.uk>, Theodore
 Ts'o <tytso@mit.edu>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Thomas
 Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>, Ulf Hansson
	<ulf.hansson@linaro.org>, Vignesh Raghavendra <vigneshr@ti.com>, WANG Xuerui
	<kernel@xen0n.name>, Will Deacon <will@kernel.org>, Yury Norov
	<yury.norov@gmail.com>, "dri-devel@lists.freedesktop.org"
	<dri-devel@lists.freedesktop.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "kernel-janitors@vger.kernel.org"
	<kernel-janitors@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-block@vger.kernel.org"
	<linux-block@vger.kernel.org>, "linux-crypto@vger.kernel.org"
	<linux-crypto@vger.kernel.org>, "linux-doc@vger.kernel.org"
	<linux-doc@vger.kernel.org>, "linux-fsdevel@vger.kernel.org"
	<linux-fsdevel@vger.kernel.org>, "linux-media@vger.kernel.org"
	<linux-media@vger.kernel.org>, "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
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
	"sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>, "x86@kernel.org"
	<x86@kernel.org>, =?utf-8?B?VG9rZSBIw7hpbGFuZC1Kw7hyZ2Vuc2Vu?=
	<toke@toke.dk>, Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Thread-Topic: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Thread-Index: AQHY2aRLUOmMOiRiqUe6k1BKDHReSa4BnNgA
Date: Thu, 6 Oct 2022 17:21:27 +0000
Message-ID: <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
In-Reply-To: <20221006165346.73159-4-Jason@zx2c4.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR0P264MB3324:EE_
x-ms-office365-filtering-correlation-id: b435e492-bfe5-4766-80db-08daa7bf33c7
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: aFKb6j0sF9l/sHpq/IwjAhRbihgR9YM2vTrg9tD8u8O4xs83zA/tlTOlJSQtPnbuBBRuJZ8JpW2RC9YvuOEz6I4z9oR+GKHvPeMMxfcF1I6STjqVgOUxncHVEE6hmVv2OqPVzT8CKvB69n/wDHyXxw1bRB6Eux0E6Id0f8C9BEiyEKy9X6QvkJd1Si0f/bBX6jdbKwiqpupDmd+WFvD/+rWWiMsLgTJwWPH2wGTGwIdCEIdXtJ+PER/OhM7G1QyjkNruT58PBvKsosv0t53rX0QlYlEU9B7LSo+5E1WXZEsjUA/DprtrvD5J8VtazIOkS7mFE+RcQnsbzy+YB17rtmUyLpMP+mp0pYqf6nPhJ/faZMNTA1xZjG9eMb9zFjw5s2m4XeAcOWRMtlIqkLwTdqr88htplPlSqzFtPiy/tjDhE4orewHtSoQP7uBDWSzgHLbZj2PWfv3j7xCMgBsIkeihdW1zUC8OuKY8nELfsKO2dyx5kwMEFh+TJJPhs3HWfLejkS2ZGdliwrCquflClZLwGTZv45DolPMRIlPj4a+XiP60aqwGf6otpH2nNpm3HZI/3ZWDhfuN8+qiEK/sA53iVUkyZVbLBMnGCQ/TSwKUmw2xQOmfyS8Tv1dCTEW3AzyzKoU81pnAIWRxWu+zcRrJTK9VkcsG/SkVfvxeKIFaxCZYk6GJ1TCpBgeG3gX3hgbCpPwToJk6H6xvNTp7P0GbeBAPBTrOeeX+gfRLRTHUYhBoiR/BjQKcgNWkhZ42rdiHMPQMJsXmMvfdvsE8huQB+kVHXnZKE4ZBAZSiAVOwFh3s5UBUomlYBzeGfq0VC5P2MalnhZfAanyxB2Kplw==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230022)(4636009)(346002)(366004)(39860400002)(376002)(136003)(396003)(451199015)(316002)(2906002)(122000001)(2616005)(76116006)(7366002)(8936002)(44832011)(38070700005)(7416002)(7336002)(186003)(41300700001)(66446008)(7406005)(5660300002)(26005)(6506007)(38100700002)(66556008)(478600001)(66476007)(6512007)(71200400001)(6486002)(66946007)(8676002)(4326008)(64756008)(31686004)(36756003)(91956017)(86362001)(54906003)(110136005)(31696002)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?elpRVEpISzd2QnVpRkVsU1ZtK1Z0YXFYRnIvRVpMa0QvLy9HcWdUZ3dxUXB5?=
 =?utf-8?B?S2ZETlpJM2lJZTJ4M0pOVjNzODQ5d2hQNlhYMEFjYVBscDFXY2FCVGsxRXRG?=
 =?utf-8?B?YWNPNTM0bTZkc1pjOHcvN3duTjRMQm92eHIzaVZxRkdwSS9vU0Y0Tmg2UlB4?=
 =?utf-8?B?L3l4SG1Pdk1SaEtjTmx1bWxCdjNycW0ya3phM1kvNkFhV0lrdmQ1NktlRXF2?=
 =?utf-8?B?aGNCZ29TN3NJd1pDWjJDamVZTThUSFRMV0JrUi9TalFvNWdhL25RQVlZSkNB?=
 =?utf-8?B?ZUhHOFFjTmRDVW5qZmhMOWUzV2lqSTIxNUZRZFFIYU91eDRDdll5RTBZTmIv?=
 =?utf-8?B?b0F0S2Uxcy9sN1NLT25zS3A4N1BqbXhtb082RFN2NFFpbE1tQ3hvdmI4bTM3?=
 =?utf-8?B?VE9UVTJkSmxhTTJQaU4wV1FtYmlzNHY0NFUrV1p4YVdraCt5SkFoeHBpTkZr?=
 =?utf-8?B?L0hpdHI5ZmpjTkhqbHF2TFlsQ1NjbEgrTzZ1NjJ5OFVxd2FjZ3ZnM2YyY0dO?=
 =?utf-8?B?dlptZnJLd1d3MmNOOTJKQWFwOC9BRmpmSmlYTVJCOWJVNzdXMnBVMlg4R3N3?=
 =?utf-8?B?dlFOUkV4RWRlVThZeFVqUTE0c3RVWFg2TEpuY0kzZzV2STJVdFA1SnE2LzlM?=
 =?utf-8?B?dlp5bGZCOGRuVVdkak1RelNMTVFNYUY1anRCZUFZS09YTUxkYS9Na2I4OWlE?=
 =?utf-8?B?cy8wYmNUMDFiODFxcktKbEhvenNrbWRqVThSQ2UzdVdRUE55ek9zaENVVlRm?=
 =?utf-8?B?c1ltQ05sU01PTnRuWDRTZ3ptTnhPWmNCWDJ6L3k1NElFV05iM1kydk92MEZS?=
 =?utf-8?B?Y2lBK0J0d1RSc2hFcFl3QkxpU3lmZUYwQ2kyYjBSZUZVZHQzZGYyQXRaUEMw?=
 =?utf-8?B?MGJMTitsZVBiMlFQTjV2d3N5Zzc4Rzd4MXlybC9ZclJpaUg4djlXcmtjM3gr?=
 =?utf-8?B?ZnJlWlg0aHVIc2RlVU1DQUJmaVZELzdLZk50Q0NlNlRzc2FtTHJ4NlppdDln?=
 =?utf-8?B?Y1NXL1hKVHRmVjNuYmF1OU8yWHhVYnFsSkVIZnhyMXMxWGpwR09tOEtoTEIy?=
 =?utf-8?B?SnFsUTZueUlFN2RwaHNmZmc5STN3VTdpb3VhNHYvaklyVzZONjJhT0JDWGtJ?=
 =?utf-8?B?a1h3UG9DYjlCZ0VSSTJ4SndFUFdLU2NjMkwweUdVa1IrZzc4bXc2QTlBU0JJ?=
 =?utf-8?B?SWROSEZVcDdDY2lZMVpTTTMxSlpLRDJPYm9Vcjk5OWdOYUNmMjJTc0x2YW5y?=
 =?utf-8?B?NGJzdlEyZm5rWW1VRnhJWE1LMDllbDVPRVA4dTJwWFZvMEFLcGxwWU9zV0hn?=
 =?utf-8?B?VHczbVBXNkhVVHRMZUwrR001ajRZMCtwN0EyN2ZHbTVUUHJKcERFWVoxVzdM?=
 =?utf-8?B?bGpHbmFKZlJ0YjVTU3lMWTJxZ1JvUkxaZkRMc2gxeFU5SEREbEI5M0lCUlVW?=
 =?utf-8?B?M3A4VzdWUGZvZ214cWxkSnBrNUlxbTFHZmkzQmxYczYvTTI0QlMwVnlGWW1z?=
 =?utf-8?B?aG82MllKaHhFcU1mYmIwb3hDL3crc1NoVXdUWHM2YjNxUFdiS3BiVnk1Nk5t?=
 =?utf-8?B?MUNMc0g5bFZvZDV5NmdldjAxaHpDQk5wQVNFWmtyM2Q4cVpybzRndE1HZE95?=
 =?utf-8?B?eHVCZk93OTFRd0QyUi9VUVZHV0g5NEZ5dVBVUE85UDlCMzI2S2J2Ryt5cnhD?=
 =?utf-8?B?RVFCK0tPY1I3blhBQ3duaENNM251bDl3NUZCajQwc09KSytWTTNPOUJKSGor?=
 =?utf-8?B?UEpjamo1cGRxZkpBdXFxemkvSXErOVhSQ2FraThiTCthTHRNWXVmMkN0dUpi?=
 =?utf-8?B?QTFGSEV2T2FoMmNPbGM0WC9YbExISklleTU1ZDMzNUN5MGd0MVJDT05kUS9a?=
 =?utf-8?B?NkVBbzd1SXFBVzFYZ2QxYll0L001YS9sbWdMaFRFVmt6NUxmQzRiUkZMalZs?=
 =?utf-8?B?NzZsUjlpWE5hSURxTEJvK1FwcW1sZXRlVis5WmJsQnJpZUgvVzIwanlRaEE5?=
 =?utf-8?B?QytxY0F3dzRGMGEydUt6Z1l6UVpNUE5LS1FQQUNmNThOekxKa3BwY3RzOHNW?=
 =?utf-8?B?N1A4b0lRQ0tqU1RhUlBlSDVNeWpFYnVWOHgzUkNoQ054LzEwSFpiK1JMcjBN?=
 =?utf-8?B?ZXBHcEVMSGVMNnkybFozY1BtRHRGbGZ5VVhtSHBhaE1ja0RXaGZKVzZKUUVL?=
 =?utf-8?Q?bVGw61IQfN57I5nqkFsm1+g=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <B07B745AE1A6904EBF61E3986BE3C1D1@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: b435e492-bfe5-4766-80db-08daa7bf33c7
X-MS-Exchange-CrossTenant-originalarrivaltime: 06 Oct 2022 17:21:27.5495
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: LyUr5KK+XMmusbQ6YhVGYUYpg2PKOd6bQCvUFRBHYW1Zq91JkHALJ9q3O1VfoqyQV/qNEBNf2qgeOfKWWYBk8HXZNXcwdIKJ3Zm4KWakpb4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR0P264MB3324
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=znWL7iOz;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.9.52 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit=C2=A0:
> The prandom_u32() function has been a deprecated inline wrapper around
> get_random_u32() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function. The same also applies to get_random_int(), which is
> just a wrapper around get_random_u32().
>=20
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_cake
> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---

> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.=
c
> index 0fbda89cd1bb..9c4c15afbbe8 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
>   unsigned long arch_align_stack(unsigned long sp)
>   {
>   	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
> -		sp -=3D get_random_int() & ~PAGE_MASK;
> +		sp -=3D get_random_u32() & ~PAGE_MASK;
>   	return sp & ~0xf;

Isn't that a candidate for prandom_u32_max() ?

Note that sp is deemed to be 16 bytes aligned at all time.


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/848ed24c-13ef-6c38-fd13-639b33809194%40csgroup.eu.
