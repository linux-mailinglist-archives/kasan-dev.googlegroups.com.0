Return-Path: <kasan-dev+bncBDLKPY4HVQKBBOHD72MQMGQEW6ZMGOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EBBD5F73B3
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 06:57:29 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id b34-20020a2ebc22000000b0026c273ba56dsf1464332ljf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 21:57:29 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665118648; cv=pass;
        d=google.com; s=arc-20160816;
        b=zpaW/RdWbx0B65M6i6FYuGBxK/BzSkFQywOLc7lbRIlGu48RAGUORF8oaoWTwLueVw
         DgAa5an59re3SE+7I09b247t5GY80cK00+JxWhct5+TIvljfevvCN+cjuz9WkGad48pR
         nh0+7F6oChftJNnOc71PVfkLHpISte1lg0FhOufVFDeEH15B9gCrXpin1ABGvbn4qpdR
         pNVhm7djLj2pnbJ2ElA6wZncjkF7zG7MN8+UFw6qqs/3SYeUKeZRPp6wixj3wI2SLyTH
         0L7iJ4JHocGtPuCwQ5GHTyec3bqrvU79fIsIZeKbjgG5gXUtcecvhE4gRd698iWhNQYR
         CddA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=+LY0l6DQCNjK3Jk67+LHKz4nM7HHqg/Uuqpbj8HIR5w=;
        b=pg/fgmaNB4jAqs1pqH/FwzgxtGoncU6t0aUK/M/NmcLou17T7p4O3wkBv5MD1a+Zu+
         9qJF0v1wLPGznS8jcQgl6o0sTQBop4s0mskpzQPnBm4uOVVZFpkQMtxgg1KozhFgfq7B
         BjdeR+dYtHwMSJ3mC2HKRvrIg1/+DusKiA9Bqm/3McVAe4CYNPQilEycuo1Ir5EvOjrI
         Lbde20jQy3VcgT02F5YSWxDlrsBHwRO5F/SaJ0ezKScOHd4zRJo6cDKaCi5aUOwv1qHD
         sJwDyRP+J+dFoz5G38DdvY7H9TIqdEn/RB+XXI4Fuppc1AeHmn4d1vkuV7WStS5RA+Yf
         Zqew==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=vvUxAKw3;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.88 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+LY0l6DQCNjK3Jk67+LHKz4nM7HHqg/Uuqpbj8HIR5w=;
        b=Y4I7Tp/9EKH0K9+SnavH5Y70n0SSLGKDLxCH/VQPP2qT0I/Wc+caaUVStah65BW3Qk
         cfxZoJ4tF0PTkMA5GMS41GEqYG+nmWfghHoUoBNEYbe8fSGKHS4A6G39zGM384XKZOvb
         pzrkyjxdd8nc8IAijC+Pjr4jU69h6+Q57ibiuSq+J/4XqyaloNHT0CTwfcJQaTrP7+mQ
         t9yRo+NUCHkarJxBDnLN49JmYBxb+FHxpEM5zSO3OuaDlDnzHa3pGBqux/mX0YCPncsx
         im0otfNLmA8qADdkIpiqWHZBAuFDP+D9/aYkKB3gVW97Stn3zsXoSqs1k7tusumPhRgd
         0ZcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+LY0l6DQCNjK3Jk67+LHKz4nM7HHqg/Uuqpbj8HIR5w=;
        b=Ee86LTHJlVUbN83WwQAYUW/aLRVGtLftGAnZHPWJuqD/ZnZCdJ/xpPmnG1a6jpDQ/V
         w0LwgWbLOHrOqtgIQNgBi/rrao05H8cOPU2uBYPkCAQ0ZvioECH4TO5cPPqHfoxfskW3
         /MMFIznKFtdpE8OxxiPPlu3IzYCKfzK2g+rayy5FGlr8tQhFMfKec5vBzJHWgJF/oX17
         2kdvWgWSjumDkg2jlyptcJrZYNPgAxRC/HEpI3bfg/KS+gofRyYMnR7DIRpL6b2/uiEH
         +LQ6Ghvfq0SkLlahjnH2aah0YeobcmAZQChUWvMcIhwjWwpCpwSfBR9BgUWZehXr0xLB
         idgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3wozmNSZMSeFKGQZURY8bWSRTE8/z6ueOByTcV19ZCddAHdihV
	74dAEZOgihBa5768rwbZ+0w=
X-Google-Smtp-Source: AMsMyM6/YtJlsHQadNWCLIsnfM+uHdLVldnWTU3wa8+LnixOeJV8JQ6U2bWC17q7OQ4LatjD/vmSLQ==
X-Received: by 2002:a05:6512:6c2:b0:4a2:e7c:6164 with SMTP id u2-20020a05651206c200b004a20e7c6164mr1219090lff.329.1665118648503;
        Thu, 06 Oct 2022 21:57:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a5:b0:49a:b814:856d with SMTP id
 v5-20020a05651203a500b0049ab814856dls290087lfp.1.-pod-prod-gmail; Thu, 06 Oct
 2022 21:57:27 -0700 (PDT)
X-Received: by 2002:a05:6512:2618:b0:4a2:1d98:f41a with SMTP id bt24-20020a056512261800b004a21d98f41amr1298951lfb.78.1665118647167;
        Thu, 06 Oct 2022 21:57:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665118647; cv=pass;
        d=google.com; s=arc-20160816;
        b=YNL21Kwu7MsHv6mODlnKc5Smq76youKrKcGdaV4/Li8Kx1ouDd1mcZTssFataC1pOr
         m9ppbAghdFIKGKztX5R0t8R4fi59x3IOCvlJxLwHoL2ci+AfG3lWJCL0AtyiGYtXp9g+
         OQJKel8X3SLDau4yuFT1yZrnmOd48FaDi5T3oBX0ZCK4bMplLZKGhc6byQbhrpeffNr7
         8GiSl2xuHlnJjuA952hPMz724bNACDZIeeqilJTK5J3I8NVXbxKb9K7z6fHpTYb6aKFN
         LvqTBPDWC4XWE3Rf0brQoH0NEiuyezvgfN0aIUpOeMXVsooLHYmLYbFkSMqeth55YoWB
         00cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=oq4wMAaFj/7s0RVxjSrvoiqUcvKjXrV8XQwCN+AY2rs=;
        b=cA5HzbeSvYHusv6zYYBQbW/6mQ//wgsnJ635DGXLKH7dw+Lk0lme7BCzT8AUDarmOn
         EEcp6CBjNCg7XZBk0q0Q769wIbx7xw74dRPSF7gFCfZPVcsrAdVGHxf+pMuFuiWf1qvb
         eOa0efJ+nm+VvhhWHZFetvE6lMMoUD6BaGgfFwiVoRlhMFksn++lwbHVU0H9i8rVQiif
         VZ1YpPRmtYRjPFCRHeRAVVMTNGJdb0+iCkKSokm/yMZGvSiyeXLgVumDkxICq3BGgw0G
         n1aAgK44F3q5qvz2cNpqI1rRHTbVYRPRonI4zxAwKN86CqZ3etTWAahveZSjQi4lFkRW
         y6hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=vvUxAKw3;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.88 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-eopbgr90088.outbound.protection.outlook.com. [40.107.9.88])
        by gmr-mx.google.com with ESMTPS id v25-20020ac258f9000000b0048b12871da5si47942lfo.4.2022.10.06.21.57.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 21:57:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.88 as permitted sender) client-ip=40.107.9.88;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=lh5j08N6jCfV2VeKBdJrJ+Z020WJWMrbJZs4LukNRoH37XN2UjgZvzVABR2xTnGkKxJykn+bpREHo5xxerR2b9PBDeexPhBQYVob6M1g6487HUkYCOtFsU6YfyGkKFDw76LYasEzSAaDYanvWNBu2wapvePeBBCZsHrELDpUxq8IRHpXnFkxrU7xb6D35AYZ8u+gLvEBWsasiqL3Ai4uyz8CLx7faJm1phibeFRS+sDu8yq8IS5TVFuiTqHWnUbfwefYcQvAqCdY4xwKsj6QrA80ViB2P1uvvMJmGfQK94DRadlvSpAGQ7L+UvTrhQRaBAo6SSOdNUVW5zwfa3W3vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=oq4wMAaFj/7s0RVxjSrvoiqUcvKjXrV8XQwCN+AY2rs=;
 b=bSmA4b4wS+tsty+JFUvaxIvsY7bRnbSeCNiwybhPrLKeaoPTUbb0zCykaJcIMYIC8du+J6gWfrb+7U+ih9X5q/X7TeWQM7TeufbJL9r5Mae7pak4Dpihw7V6RGR/JdastkIG58KQwgWZ4nJOs8GZ+4fOEXyCN2C9NZtBT2WIbebwWV+2m/dvtnSM0MhQvKtjGe+AdY+cIp09jiL1cP1pfAc9pF1ROHgnafoovtccJYMibpSSQsbLA/wXsR8v2ri2GlFGIldDsa50lFkH/k5UEtzqL2S58LhY4CL8GX1XCFQCqebfhqWYrTy+cKHAD+2b8rL5w7HL8fK1GKUB7qL4nQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MRZP264MB2086.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:f::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5709.15; Fri, 7 Oct
 2022 04:57:24 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af%5]) with mapi id 15.20.5676.036; Fri, 7 Oct 2022
 04:57:24 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"patches@lists.linux.dev" <patches@lists.linux.dev>, Andreas Noever
	<andreas.noever@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Andy
 Shevchenko <andriy.shevchenko@linux.intel.com>, Borislav Petkov
	<bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>,
	=?utf-8?B?Q2hyaXN0b3BoIELDtmhtd2FsZGVy?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>, Daniel Borkmann <daniel@iogearbox.net>, Dave
 Airlie <airlied@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>, Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>, "H . Peter Anvin" <hpa@zytor.com>, Heiko
 Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>, Herbert Xu
	<herbert@gondor.apana.org.au>, Huacai Chen <chenhuacai@kernel.org>, Hugh
 Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>, "James E . J .
 Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, Jason Gunthorpe
	<jgg@ziepe.ca>, Jens Axboe <axboe@kernel.dk>, Johannes Berg
	<johannes@sipsolutions.net>, Jonathan Corbet <corbet@lwn.net>, Jozsef
 Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, Kees Cook
	<keescook@chromium.org>, Marco Elver <elver@google.com>, Mauro Carvalho
 Chehab <mchehab@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, Pablo
 Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, Peter
 Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>, Russell
 King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>, Thomas
 Bogendoerfer <tsbogend@alpha.franken.de>, Thomas Gleixner
	<tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>, Ulf Hansson
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
Thread-Index: AQHY2aRLUOmMOiRiqUe6k1BKDHReSa4BnNgAgAAAygCAAAHkAIAAA1KAgABi4ACAAFmSgA==
Date: Fri, 7 Oct 2022 04:57:24 +0000
Message-ID: <501b0fc3-6c67-657f-781e-25ee0283bc2e@csgroup.eu>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
 <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
 <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
In-Reply-To: <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MRZP264MB2086:EE_
x-ms-office365-filtering-correlation-id: ae4cff8a-e95b-42f1-753c-08daa8206d11
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: ecYqdAkTmlRgnXmSnSqeTxHPrAmSWJdW2+ksYp/5CrlRUQSxGFELyDBnybCuCYO1HwmDqvagL4rCW/0eDX5lQxqdy9HPHHmqeQbB9VZNl1UV75r+sKm9PeEJ3/r0DW1agvZ6Rzdo0EmiF/z/ITM413QGiv9axIa+OznyfrjcSE4KhzzG68IvCYL8+ZlR33Dl6gW49Cnb8rJXvMjHDC8gwhZt6kcR28RTz7Q9O7wOGJL8U6drBpQhyFNsGeuq6Q/i+rR5dBMUx0Gc2mV3q/R3eGcVtij16JM7vgb1BlUYkejiszP3qyIqbVwMMpsVtksy1Gueic07MuZ/5Q8fXtyfavoHI5sDeFMSYr5HL8LrByALufIkd/GDXOr0UdJ2ArDeRWxZYIRvEGRHSrA75MciLIb+T0wGJTRm3otNH8DIwqCAS3zVBYICOITwedeehgRTLBrg5PVvkCZxip6ub1EW3F/zORDtVfvRHeWu3Bine1Xl6WnqYKqmQT3A6Bv7f1/J/2vGxamgAdEcAiQlIqlAi/NWuwo2zxULgu5lEz4dg8CIR6QZeacjjCgGHgL4sXpaPeFpo4R9/AKwyGp/30g9TgUh2iTwqdvqlcEv+NfGz8802SeG/NfGMJqwnhqRrMmsK/Te6aRg5Kh6NpMTPlB071ZRA9NmJacr8gGeGHS2BW/b9yLueEuNdcIcn7Pi4ZKc1Jxdctk/dzQGezS01UwQ2k6fN8e0ymuGVsvrx0VgmHDRZSLc7XcxboZfCTuQPJuTN70Txavto2+dzwH8n3PXMCZPDttLrBmBPOvty7xYYZ4HBYYbxuNpMRqKDELJYXfc0FftYEbKxk9H5ehAHpDOhQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230022)(4636009)(39860400002)(396003)(376002)(136003)(346002)(366004)(451199015)(31686004)(8936002)(8676002)(5660300002)(7336002)(2906002)(36756003)(7366002)(7416002)(41300700001)(4326008)(7406005)(91956017)(31696002)(66446008)(54906003)(64756008)(66556008)(66476007)(76116006)(86362001)(316002)(66946007)(44832011)(6916009)(71200400001)(6486002)(478600001)(38070700005)(6506007)(26005)(53546011)(6512007)(66574015)(122000001)(2616005)(186003)(38100700002)(83380400001)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?SjBiVnFrN3lGWlM0NXVKdGhSTDd4MVBDT2NmcUdkVy91MWFkNUpKdzZXWDJC?=
 =?utf-8?B?K3R6dFh5Q3lsbnRPS2JEL0lpM1o3M3ZzbzJGNkJraVZOeDVIVzRML3E0R0tW?=
 =?utf-8?B?bmN1dXE2eGpSRFJYRVVURUJHTEU0U21MT3MvL0VKdTdMT1cwenlRazFmK2hs?=
 =?utf-8?B?UDBuaEdES0hCRUw2akZzQm9hUUZPeUNES3hzbVg5SDhsVXJ1a0VnR3NKR3dp?=
 =?utf-8?B?MFZ5S29WMEF3OWVVR2JINzB0OW9VOHJ0aG5DZXJNQkgzTmU2c1NkZjI2WDBy?=
 =?utf-8?B?TDZrQldhL0YvVkcvTlF6c0NScVQyNlZHREdoS0ZMcnB4Yjk3cS96K05QN2xF?=
 =?utf-8?B?NDJHMnU0cG1JQlUvUjFiWFBKc1Zld1JpREpHaG0vaStpRm5WUG1uT1JpSXdr?=
 =?utf-8?B?SUttQUtqb2NJRzdjOWNWNVBqeWZPTGNlRlFlNXgyYy9aNTBWbitOZkJodTRB?=
 =?utf-8?B?dEYwYjFJODR1WlRlRE02d2dPUlJUNXRHZGJXMWtSRlRQaEFtKys4YWdLZGhw?=
 =?utf-8?B?TklpZWpoMjlwRFd4QnlYMjM2Q09SQ2lJWHVncXZKdERRNTkwc1pqYUczeC91?=
 =?utf-8?B?THIrVnppb2tIOGtKT2llUFJ3NHRTci9EOU5iVU1Sa2doQ0t6MzQyN0xRZW1j?=
 =?utf-8?B?VkU4Q08wVHdWUVI2Z2FlSW9nUVdPWUNXSEtIMTF4dEVkekVHY0ZuT1ErZWJ3?=
 =?utf-8?B?YVBMWkQ1ZEdJWEJlaFNKNU1KOGhRODAwU2I5UGYxVTV3T1NOTktrdVJ1MkZ2?=
 =?utf-8?B?TFF5dFlpL2s2TlFGdkR2QUFjYStKMS9oRjZmSVJ5OEZPd1Y3TGk1QWo2K2Rx?=
 =?utf-8?B?WkxZby9TMXBnUlNrdDM0TXVIMFF2aW9kRnFWRHRVa3F3dUl6WE81T2JJSThx?=
 =?utf-8?B?OFdUUkZoUGtZZHRYWi9KNjh5MXYrQ1RFQ1hydUZHNXAwSTRDZ0pUMmVsQWpt?=
 =?utf-8?B?amhveVFtalJlUnpLRXB5Nkd4R09sZUx5K3R6WUtHS21uamhOT3Q4OVFTcFY3?=
 =?utf-8?B?cW9qeEdVS2tJZ2JhNTNxNDk5ckhjVUduTVhOS0N1L1M4Tk9hWmJRZHEvdFlQ?=
 =?utf-8?B?SER3THhoZlJVeVg1T0s2TklZUWdodVZaWUpQMURJd1lTYTBJbXgyMkxlRGZl?=
 =?utf-8?B?YXNzZk92dTVqOEtJT21RYTFKUHNZSHEwQkJsc0cwekNlbm44RkpTb1hnZkox?=
 =?utf-8?B?c0lQOHVoTUY5TFlsNUxrU2tXa1hrNmU3OGlPVk1NeDI2YlpnNEExZVBqVTJG?=
 =?utf-8?B?L0Y2VEU4ekVocDJtOWMxTXF1QWZ5L3JDRGVRakllVnl3cS9hU1praEpWcVBN?=
 =?utf-8?B?MFhFb1d6NzhES3VFTWhkU001VW03NkI2K2JCeXkvK1plMFBqZzdSRFhQY2lC?=
 =?utf-8?B?ZSt6TVk0WWdzcmJDVlE2Vlg4MWp1Tld2b0M1dmR5N2h0RFZIVjBHaDQxdG01?=
 =?utf-8?B?UTRnc2cwb2pQQjhVK0ZpanJGVytiVHZwMkxvWGpHY0tlQTFvZDc2MW9ObFdW?=
 =?utf-8?B?RlNmZHV4TEpqQTZVZmRubE9pT3hqbHVDWkZ1Q2dLb05xUHRZVnF0Q2Q2bjNn?=
 =?utf-8?B?dllwZTRFNytEQm1uYnF3WDUzUHJOeUtDbXF3eklha1VxQm5yd3ZZNGU2eE55?=
 =?utf-8?B?MktpSlovRjdHbXlHdEtSTjJ6eFFwdkg2a1VrVm1ONm1UdCtIVkFNUE9VMkdt?=
 =?utf-8?B?Qm9oVzAvd1NWdkxPc29DTituOWdPQXVaSm0yaDdZL3pjQ043dThtYlhvNVAv?=
 =?utf-8?B?ejhwdkExOXBtMnJSdTVIbEc4dHRHUHJFTktTbGxyMmlOeE9id212Z2U3ajF5?=
 =?utf-8?B?MXJJUEZZank3cWphMmN3ZGFyZms2Z0xWU1R0NGZQVnBTRlZGM3pwRmhZWUFo?=
 =?utf-8?B?TlY1RFk4YkFzdllNSmRFOFdHb3lvYkNIODErWXpZZEo1WE54a2Vad0k1WVRM?=
 =?utf-8?B?bVd5aW5iMUhXUHhhUFFhWFp4clVoTDViYkxncjRLRmdMUm9tRFQ1Z2xiNGpZ?=
 =?utf-8?B?QTVoTjhxNk0vdDJjTU9EbVV5ZkVlaVN3ZVN6RUlhbUVwbFVrbHdiOW5scjNG?=
 =?utf-8?B?akE1MVVLZDlWeExuSk12MDJaOTRHM0hiRXk5dHVtNmE5ckVOWjNKNGs4WmIr?=
 =?utf-8?B?YS9GMER1ZlZPN0JUMWJObUVoSHlKMzVYWkFsV1FBaTdZNldyaW9hVk15VnBa?=
 =?utf-8?Q?AoqtEj+pAO/r5/nujYdg9vY=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <8277F4805BBBC64490B411D5CECB85D7@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: ae4cff8a-e95b-42f1-753c-08daa8206d11
X-MS-Exchange-CrossTenant-originalarrivaltime: 07 Oct 2022 04:57:24.8002
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: cq1ecfOnhv4ymIgLNsdDILWsoBKaeYECzn9QuW4ShXFVtYbHn9+XhLVJ1f9K7Q6r2K8dxDM0MNT/5Y7NJ8vkQB91TU68Hdx5urMk3Ygdur8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MRZP264MB2086
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=vvUxAKw3;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.9.88 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 07/10/2022 =C3=A0 01:36, Jason A. Donenfeld a =C3=A9crit=C2=A0:
> On 10/6/22, Christophe Leroy <christophe.leroy@csgroup.eu> wrote:
>>
>>
>> Le 06/10/2022 =C3=A0 19:31, Christophe Leroy a =C3=A9crit :
>>>
>>>
>>> Le 06/10/2022 =C3=A0 19:24, Jason A. Donenfeld a =C3=A9crit :
>>>> Hi Christophe,
>>>>
>>>> On Thu, Oct 6, 2022 at 11:21 AM Christophe Leroy
>>>> <christophe.leroy@csgroup.eu> wrote:
>>>>> Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit :
>>>>>> The prandom_u32() function has been a deprecated inline wrapper arou=
nd
>>>>>> get_random_u32() for several releases now, and compiles down to the
>>>>>> exact same code. Replace the deprecated wrapper with a direct call t=
o
>>>>>> the real function. The same also applies to get_random_int(), which =
is
>>>>>> just a wrapper around get_random_u32().
>>>>>>
>>>>>> Reviewed-by: Kees Cook <keescook@chromium.org>
>>>>>> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_=
cake
>>>>>> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
>>>>>> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
>>>>>> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
>>>>>> ---
>>>>>
>>>>>> diff --git a/arch/powerpc/kernel/process.c
>>>>>> b/arch/powerpc/kernel/process.c
>>>>>> index 0fbda89cd1bb..9c4c15afbbe8 100644
>>>>>> --- a/arch/powerpc/kernel/process.c
>>>>>> +++ b/arch/powerpc/kernel/process.c
>>>>>> @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
>>>>>>     unsigned long arch_align_stack(unsigned long sp)
>>>>>>     {
>>>>>>         if (!(current->personality & ADDR_NO_RANDOMIZE) &&
>>>>>> randomize_va_space)
>>>>>> -             sp -=3D get_random_int() & ~PAGE_MASK;
>>>>>> +             sp -=3D get_random_u32() & ~PAGE_MASK;
>>>>>>         return sp & ~0xf;
>>>>>
>>>>> Isn't that a candidate for prandom_u32_max() ?
>>>>>
>>>>> Note that sp is deemed to be 16 bytes aligned at all time.
>>>>
>>>> Yes, probably. It seemed non-trivial to think about, so I didn't. But
>>>> let's see here... maybe it's not too bad:
>>>>
>>>> If PAGE_MASK is always ~(PAGE_SIZE-1), then ~PAGE_MASK is
>>>> (PAGE_SIZE-1), so prandom_u32_max(PAGE_SIZE) should yield the same
>>>> thing? Is that accurate? And holds across platforms (this comes up a
>>>> few places)? If so, I'll do that for a v4.
>>>>
>>>
>>> On powerpc it is always (from arch/powerpc/include/asm/page.h) :
>>>
>>> /*
>>>    * Subtle: (1 << PAGE_SHIFT) is an int, not an unsigned long. So if w=
e
>>>    * assign PAGE_MASK to a larger type it gets extended the way we want
>>>    * (i.e. with 1s in the high bits)
>>>    */
>>> #define PAGE_MASK      (~((1 << PAGE_SHIFT) - 1))
>>>
>>> #define PAGE_SIZE        (1UL << PAGE_SHIFT)
>>>
>>>
>>> So it would work I guess.
>>
>> But taking into account that sp must remain 16 bytes aligned, would it
>> be better to do something like ?
>>
>> 	sp -=3D prandom_u32_max(PAGE_SIZE >> 4) << 4;
>>
>> 	return sp;
>=20
> Does this assume that sp is already aligned at the beginning of the
> function? I'd assume from the function's name that this isn't the
> case?

Ah you are right, I overlooked it.

Looking in more details, I see that all architectures that implement it=20
implement it almost the same way.

By the way, the comment in arch/um/kernel/process.c is overdated.

Most architectures AND the random value with ~PAGE_MASK, x86 and um use=20
%8192. Seems like at the time 2.6.12 was introduced into git, only i386=20
x86_64 and um had that function.

Maybe it is time for a cleanup and a refactoring ? Architectures would=20
just have to provide STACK_ALIGN just like loongarch does today, and we=20
could get a generic arch_align_stack() ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/501b0fc3-6c67-657f-781e-25ee0283bc2e%40csgroup.eu.
