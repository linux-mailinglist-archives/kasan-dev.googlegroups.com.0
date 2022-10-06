Return-Path: <kasan-dev+bncBDLKPY4HVQKBBWVB7SMQMGQE4O7NWHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D79F85F6CF0
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 19:31:07 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id t10-20020a2e8e6a000000b0026ac7d6cdacsf978701ljk.10
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 10:31:07 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665077467; cv=pass;
        d=google.com; s=arc-20160816;
        b=jnFZ1M1nDWonMQcx+Iz7d6nUF0jq96vFjg+UiA8wL6zDYMjlYb+PtsbFZrrX5R2qxf
         PSEGmpdJq7AoL+/KjO91Pcg+jMX4l0EFN/7S79pbMeq9pH2mGLgds/ZFRKnidFrdDeUr
         GF+R/9QVsokVPm/aB1wbwBcMkYEGo8O4HUhFSKjpdRZlaZwXDpeY9MIoVhqRUoSNg6J4
         TkOYkY7vQjq3aZKeW7srBbmzxGajz8GYHDbvov2YLibMchO9hmyfZiGRuZDZdanhy2xc
         e7C++ZMBohWh4LNyk6PhiqWaX5XKvIzQrjTRpC/MOLfqi0EteY3hV3iZbFDvkfqzQ82+
         aLoA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=bLDfqK+viMhOrHLCzdF/d1/T0MfG/+QM76Me5km+cFk=;
        b=vwbZPu/Uo690L/fNxxTNpbGByAn/pf6WIUjH/q2YCZcSi8JMcGwsDoye95YiendsnZ
         uV6ukzptnyuLSej3L+aEX+4VRluiN2ScAsh1XljwT5ugY4WShobWlSMVQUdHeDQRw4PO
         NJiJcKGkY0wnfbqgtedE+T4K82TLnEUK5Mp/Tatjb6U064vYW16z0axJTEpQ5VN66FAo
         1ExQ23QSsVbgFBAoUyzZm7FwTBp6HE+NX/Jhu0KGkCsfjQ86QRGYlR/FrlnYWVgXB0ix
         cxIcjKoYTn/EsIXh6kr7WUmAWJzDm1CcxCUa4DliTgA4qEZtiLZcOhJ+zXHgZ/7whC39
         CkLw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=Nj1E7tRv;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.59 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bLDfqK+viMhOrHLCzdF/d1/T0MfG/+QM76Me5km+cFk=;
        b=RcmEpRcM22EcUO4q0fKEPmJaStL5g0wg4VpDdzsSyvVTipbcpRuDHmdymUrFUjn6fx
         g+Ly7Kb4PkXwI8PBaj8TbVzBGxkEkmMKKKVj57QuWho6ILUuF9x+2thULoyjLUGZbj1g
         3GFPEA0N6nTGjoWT4WIGDbnBzukxX4OpFkl8nDKF8fm6Dk3k7wTT3J6o4jndcXrmzQTG
         HSwo/OkmlNFULO0YaDLSopI24F0iy0pHbvevOtUEYTKT2rWx0PvrXmjYTLCR3lre4yAw
         WIUIs1X0mXj8nPi7zbCh1ckBmctSx/FmHvzetyICJcvtb6OxvMU7YXpJE24/WQM0FYDa
         h6Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bLDfqK+viMhOrHLCzdF/d1/T0MfG/+QM76Me5km+cFk=;
        b=ghYM0lWCNz/LRqJOQrA58Rc8PSr1/S6CoiJO43Kno4o7Uqw7WXJKR9tdrk0dEFmhSv
         M4ujoeuHp7L9n6dqJCfmjHnSJDeI3S7dlkjToe/tN5Mhp/BJ+yYbQdDJATTpY5xuI0CH
         n1Ongxc34PPThgtOa6weViBt48ZKQYBYTyJBvSBEd5CBqs1gPooyxNpLHFwoPrcj2oSz
         z+71n0Ez6QiMJ6xCOoEGXkWlfqZoEkaMOLIWMesnFt6oOhSRPBQqIf0Hn1UALClAGrMA
         EwzDlsJot6Tqu2qEQp1bQA/+zyhhSx3AOWr2TvD35B0yq2HtfANpT6xDY2iC9X3Lv3Pg
         ctGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2OCJXp8B56AAxVZM3ghY1cR4lAcMYyIVdKVNXIIu9wLOm/tUvB
	HrsDxGFkT1E5ZPvLwdUBtMQ=
X-Google-Smtp-Source: AMsMyM6WB1+Ob6meqePuOSmIzs/ov5xVv+8JWJIkFQ3yPU2BhES3yQgZM11S4kRP4OIxRLb18gAyPw==
X-Received: by 2002:a05:6512:3b12:b0:4a2:6e46:159d with SMTP id f18-20020a0565123b1200b004a26e46159dmr424669lfv.72.1665077467161;
        Thu, 06 Oct 2022 10:31:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9444:0:b0:26b:ff81:b7cb with SMTP id o4-20020a2e9444000000b0026bff81b7cbls535956ljh.6.-pod-prod-gmail;
 Thu, 06 Oct 2022 10:31:06 -0700 (PDT)
X-Received: by 2002:a05:651c:1542:b0:26d:bf29:8cd5 with SMTP id y2-20020a05651c154200b0026dbf298cd5mr263950ljp.304.1665077465980;
        Thu, 06 Oct 2022 10:31:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665077465; cv=pass;
        d=google.com; s=arc-20160816;
        b=JeehwqIPho2sah2hCP7rF6cCr20Kuw9WAFcCdOBXZzO+WvlPNogbpHnUUb5udtwNN5
         dLmrHbwUhqRTB3/c9Vew6V+NJsdNYLN2diH5pvQdhl15UMhAds5m4UURNUtHdKuRDXun
         /XezA861xCeUsXVMZ5W2iVaUcnITAWOJIaRjnZVZsJt499yxO2y4dZwqKQTc+VjVJI8M
         7GFdJcA6wmfFeAHPiJYk+oJe87cLTCJpYoMROIpnTfyYU/i1bcIal/CIh0drT14UfL1q
         7H4UkO53JtebM6MbH97He2KAFDPf8XnYz4LSOfWtGamijP0LAvvEEttWyxOvEQCTcqcC
         8pKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=kBHgSn82zhLNDnFsZGAKTpJQpnlYJOysvEC5qhsu2go=;
        b=rarxVQn7TjS9uLlEqJ4tjDJY24/N6XC0UJdhd3EBfrcUfFMjSVGPoewkwqiLUg1sMg
         LA6YmUSkbTusMx+ZDxShqFc16KH/tnLWJ2EIVZBHqf2jJ0yakcCd2B+cLHB208E5oXph
         tyJPymAtzWJJ5LtH7DDm0gf01JEFUSvibz9TczmFsMiX8JyMQn2YDjloNYrJxrEu4U38
         ezYBN5dCqiu10YP2o3UrS7TuucN+4OnzLidBepBNV7MbJY/vpJeiQONHCdDWMaRGTL2f
         MLS8n61YutD8KZhp9NWtnTXQyC7cqb8ovLohp+oip90AI0bXrgZ3LCs7NGxmS1wRsECx
         79rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=Nj1E7tRv;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.59 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-eopbgr120059.outbound.protection.outlook.com. [40.107.12.59])
        by gmr-mx.google.com with ESMTPS id b20-20020a2eb914000000b0026dee3f71aesi397825ljb.5.2022.10.06.10.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 10:31:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.59 as permitted sender) client-ip=40.107.12.59;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=HfW8MtdiA2DmeGqBAF5zdAwT18ZMAjGIZ5u/br5Zk82+x8qgRFNjBYdqUoVm8BOO0k1hoaMYXXIwRu5xfb1K7tttqxLJcveCd+efePOGlE9Fwx47Mg/OcLtA9rIM75qbummrLwkGLyzP0dVnaXJWtmbZavWc/00UmslDsBj/jQ8LkHsvI+V4n4mc0rFK695VKljsFFrkZg5oa/7msx530Q2Qr6EsZNf72el3kKIHnZYISBVuFL78+MrroZMJ7nhXzYUG5jQvimWz/ekaO4UzDH4PEN8P2QUXrv1ATVSLK3g1IRKuV+d9UH8eLWfK40TwgrtP4gzPJ/vHcbkWKKWarw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kBHgSn82zhLNDnFsZGAKTpJQpnlYJOysvEC5qhsu2go=;
 b=aZy9qBL4N4cHnYB0Sum5nsaUjmOrLHfVP8kq9o5wVd4pjnfYQVTkz48sPdq0EjDA8MGD4Bjj7YXXoCcWybK+lVhYVXic0xzAxrz2N7NQOsZyn1TFqVhJrdStJ42mzbQ3YQpJbUzRPBUeAs7Y9lbQ97Yv4TzjwEtDhsaxrjy04TZAnp2ZUsaNEkiqYCTvYLOs383Pj02qf4Hh9RlpP8syKPqsc2tuqPsk8gVz1f5m6jZYx77RGXLdDp8qZmgtpxKNJ/awBKiuZMQN8BQ6B1cZC3Kt9mYWxJwy8FnDvlaeaVn4TT9cxWDBhPPw6bW7aGmb/f/xoegdyWyUQmkCbvPbOg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB1921.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:5::7) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5676.34; Thu, 6 Oct 2022 17:31:03 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af%5]) with mapi id 15.20.5676.036; Thu, 6 Oct 2022
 17:31:03 +0000
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
Thread-Index: AQHY2aRLUOmMOiRiqUe6k1BKDHReSa4BnNgAgAAAygCAAAHkAA==
Date: Thu, 6 Oct 2022 17:31:03 +0000
Message-ID: <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
In-Reply-To: <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB1921:EE_
x-ms-office365-filtering-correlation-id: fde2a9ab-0ffb-48ec-6c82-08daa7c08b1c
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: UsDRemlJL2LCwhr0DPfizsHS0RDWofpRVxb2/DxfeFldzJBJszaIIRCLJEEhhqdPMP5cAggvOG8Ifrj0MvMWsP5I/puOI5rgdLf7sjZVyqKsjTjFlt8MTdmzWJtIiz4r3OouMkC+yL9KGxjeEs3lAUQqJhnhLFwa/ybQprjdyUnR1dB9L1B4PEBVUpygDNaN6Cd/sgaRCCzCUmrJV0rl23q6m2w1JAXM+Qse2+zm26qWkVwc7XdurkhJabcum9cpSTMwN+JiwXwT+inQrjtgOWvR0v9lBeBznTau8e9zSJHp4fvXO8ZYI0DLdvRpOsiVO90qAhi0lsd4Ec/Tc58tjEQ7vXtyt7oPQyP5RHcWkx56mqxKp4a/7eX9h8gVDdjrC73xo+HpPSX8iNsEWlAo6J9egg8+F5NeTpE/Cx+aNYPKlFxhij6fMLrKcpWGCuuKNWGdHJPuRQcssi18S33ULeTmNlw/RkF7byvBNeUdhkoYBqPhReSF5CjcBy9X8LZICccr9seqg9db841IyNhBuOEgibABV4yWmlrOhI8zhKnn06QBvnd5IhugrqoU1jttXpNInRt85nTdsAJAZKATJtdr9vchvlD4zGsGQapCVIHy1gUCd9iJgnfQev7O9B/hOiKLPYfOWPZnwLh3FHxcWluw4SEffaQfjGjoCkzAwn0tgFyhfh6cWQtbftwCUfHt1aW0w42Tcd518X+jsVyycgpdDzZXkb2uT9+Hl6zZMPbxmYFuiLBsq7P7/tyyElwXKu8Wt87MKfb22r8BVJtopiwhQw9qYPf/SDHCtKsUjQ/IkV6EFgFVz71BAvtIgTI+l+RbZIsfmFRHTTzfJDx5yQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230022)(4636009)(346002)(376002)(366004)(136003)(39860400002)(396003)(451199015)(6506007)(31686004)(6512007)(53546011)(6486002)(2906002)(76116006)(478600001)(26005)(91956017)(4326008)(8676002)(6916009)(71200400001)(54906003)(316002)(7366002)(66446008)(66556008)(7336002)(7406005)(8936002)(41300700001)(64756008)(44832011)(7416002)(66476007)(66946007)(5660300002)(36756003)(38100700002)(122000001)(31696002)(86362001)(38070700005)(2616005)(186003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?OXRyeGxoZ3RXd1lTSDlKcUlJd1ROTnNTbUYwQWp0OUxPTzE4ZXJUaEw5eVBq?=
 =?utf-8?B?ZVYwUVRkMVFJSWNERU5mQS9yWjdlbU9HcnZMN2FjSlZwQ2srL1pqS3k1UE5F?=
 =?utf-8?B?U2EyQ0IvRzBDbktOSmtwOEwvZ3crZGl2NW1nY2YzWnppTjF1d0dZa1BHcjhW?=
 =?utf-8?B?ajlYV3JLdGJINlRWeCthZjUxSlZhcUNYLzVQK1YvWjVubXc2aktZOFVxWHJu?=
 =?utf-8?B?T21GcjBMVTVGcGpGejFEMXdKU0tXWHZ6b1JoblNsYVVmaGFoQVJZWnl0ckU1?=
 =?utf-8?B?a3dTcnVYeXdJcUpQOWlpNC9kNUU3dVlDUWdnMDZ4eWIyc0x1ZlBjWTBqU0po?=
 =?utf-8?B?ZUdQQnNTRnJPeXRnNkFqWWxsUnZJcHZDa3JPWDZ4Mm5yNEdaVUlCZGc1WnFl?=
 =?utf-8?B?QTVRSGMyMkI5eEhuSFNQc1J0bFJheTRTd0pFVFU0L0ZPcEhTMlhSeG12Q1hJ?=
 =?utf-8?B?a2M5UStQdFZkcVVacU0ySWxHdG1TREtvU3RwNWt1Z2pSaEVDOG5HZXRtT3R2?=
 =?utf-8?B?NElOU2oxK1V1cGZkMjlkTmxFTUk0eGVJdFdNbXJKbGtPWGIrajNzN1kwMUFR?=
 =?utf-8?B?dGV2KzFpNkNKbUtrWXJIK0x5Wllla0FkUE1oRDZ6NVFqKzZ1QjBGcnBhcVpl?=
 =?utf-8?B?cUt4VUllUHQ5ZkRXa0RSek1yVlg3MG1CTS96MDk5RXN6QUVIaVFUeVdwWXV1?=
 =?utf-8?B?dldDYzdwSzNSei9VekIwK0pxVE1yRjNLV2NQSEhSY1FzcXFFc3lSUUpCL3Vr?=
 =?utf-8?B?eFBCUVpidTdmUjRRL1g5MGRMTWowTWsyZko3aGxTSG5JSE1BUTdxQVdJc0ts?=
 =?utf-8?B?RzhMNTYyM2pGL21oeVQzbkxOcHNWeXA0SDg2NkxJelQzbkF1c0NkcEU4dDVm?=
 =?utf-8?B?VWs0bFNWeUNvUGRCV2JQdHRPQTcwY2ZpMXR4ZTFTVjZtZmczOFM0d2VGaHdK?=
 =?utf-8?B?cnJiN3RqYTRIeU10Zm50b25UZHlPclA0UzFRcy92eXBZdGZQdGRxWU9GRkRJ?=
 =?utf-8?B?RDNVaURsdTc2bEk4NnBwTFk3aDZBdEdHMW5PdU0vMDJaRW1DQU5sd1V1VXZC?=
 =?utf-8?B?ajlndkVGamQyUk81cHo0T05zT2t2TmljT3gxM0tFekMrNGFBYWErVExla2po?=
 =?utf-8?B?SG1DMTJCbmk2VW5OUUdXY2JtQVBTTWNjLzJSRXo2NGl6ZzkySDEwL1VZOGpZ?=
 =?utf-8?B?V0RyVCs0WGJ4RThGN0NIVlBwSU1PTnIvQm5Qd0lZSGhwbExEK3QrU0tnOVdF?=
 =?utf-8?B?UTNHNEpwb0lwcnk0L1gwZzZONlo3UTNXd2g5Z28xWWxqaUpCRVBaVmhrWEJ5?=
 =?utf-8?B?bHFLMVpqaUtGdklGdkFwOXRBd0d0SUlyazRsenlmZUJHc0ZHN2x0MysvbGlO?=
 =?utf-8?B?Rk5VNTN3RmVQaWRZWlEzb0IzcitXRUlBbjRnSXk4VzZkZTdodnhEVzBnSDRR?=
 =?utf-8?B?WVNkdHN3OHhTbUxjSlZhY2NhcXhSeUJ1ZHp4RXJHTTNDVlBhdVo1SHJDbkND?=
 =?utf-8?B?TERQWXIwNXo2a0w0K3hwa0k2NTFMdHBDcGFkYmw5ajVnVnlQRkhIeUdPK2xh?=
 =?utf-8?B?dm5tWEtWcU5RdUxKcEVEZi9GdHNtVU9mUWlYY0NjREhXa1RJT3dvWGpVNFY1?=
 =?utf-8?B?Z2k2bkVKbEtlZ0dkQWdlVFFSSHg5VGowZ1hpc1Q3YS9ublZtdGhCK2dhWng4?=
 =?utf-8?B?cUNLT2t2TUNjMWl0amNlNFpPYmJYdmZRZmQ4a2w1UXYzZlZTN3JRd1lueHRH?=
 =?utf-8?B?R00vOW1PdVdjQ3JQMC9SdDZwVEpOYkdxK2QzNXdPTTl4dnFVUkZpemR5WnBB?=
 =?utf-8?B?cmtsNmZ3RUVhWTRwdldIdGFjTmtKVks2R2t2M1RtWHpqaGJxTkh2bTV3azFk?=
 =?utf-8?B?REVDTllReVpRNE4xd29UeDlJaGxtM21YcElaQ1ZGY1RTVTg0Y0ZCWUdMdWgy?=
 =?utf-8?B?bGFiOXpIVm1ZKzBxREpzSENHNTBRdmE4c2dNN0JIaFZBaEN6ZlkybEdKaWRy?=
 =?utf-8?B?S3paUEtvMkZwM25tNFlGZzhWZE43ZURMREc4QzFFQXhibnB5enFnenk1aVkr?=
 =?utf-8?B?aytLUndlRGlkaWpiSnlGbjdmRGpITFJocU4rYUltMnRrOGpiVWMwTXloVUll?=
 =?utf-8?B?NHovTU8rS0kxYlc0SmJtSCs0UlRrQ3NZeHBTdXdscGd6ZElpaFVvMmpxT2Qy?=
 =?utf-8?Q?6H2vxALwWdClO2lEkzBkhMs=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <3A4B84F46BBE6042B54970B24A722C5C@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: fde2a9ab-0ffb-48ec-6c82-08daa7c08b1c
X-MS-Exchange-CrossTenant-originalarrivaltime: 06 Oct 2022 17:31:03.5645
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: neRWjdjuRnBwVq1QMlO4rqYLbb8Jwd1wlMJVaRE1QRTu08F0tgVgoIK9mVx3edwxYRe1nOYw4YSn/6bU7I4jKW1Tz5OEBLxxLLtrGQCLlR4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB1921
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=Nj1E7tRv;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.12.59 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 06/10/2022 =C3=A0 19:24, Jason A. Donenfeld a =C3=A9crit=C2=A0:
> Hi Christophe,
>=20
> On Thu, Oct 6, 2022 at 11:21 AM Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>> Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit :
>>> The prandom_u32() function has been a deprecated inline wrapper around
>>> get_random_u32() for several releases now, and compiles down to the
>>> exact same code. Replace the deprecated wrapper with a direct call to
>>> the real function. The same also applies to get_random_int(), which is
>>> just a wrapper around get_random_u32().
>>>
>>> Reviewed-by: Kees Cook <keescook@chromium.org>
>>> Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_cak=
e
>>> Acked-by: Chuck Lever <chuck.lever@oracle.com> # for nfsd
>>> Reviewed-by: Jan Kara <jack@suse.cz> # for ext4
>>> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
>>> ---
>>
>>> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/proces=
s.c
>>> index 0fbda89cd1bb..9c4c15afbbe8 100644
>>> --- a/arch/powerpc/kernel/process.c
>>> +++ b/arch/powerpc/kernel/process.c
>>> @@ -2308,6 +2308,6 @@ void notrace __ppc64_runlatch_off(void)
>>>    unsigned long arch_align_stack(unsigned long sp)
>>>    {
>>>        if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_=
space)
>>> -             sp -=3D get_random_int() & ~PAGE_MASK;
>>> +             sp -=3D get_random_u32() & ~PAGE_MASK;
>>>        return sp & ~0xf;
>>
>> Isn't that a candidate for prandom_u32_max() ?
>>
>> Note that sp is deemed to be 16 bytes aligned at all time.
>=20
> Yes, probably. It seemed non-trivial to think about, so I didn't. But
> let's see here... maybe it's not too bad:
>=20
> If PAGE_MASK is always ~(PAGE_SIZE-1), then ~PAGE_MASK is
> (PAGE_SIZE-1), so prandom_u32_max(PAGE_SIZE) should yield the same
> thing? Is that accurate? And holds across platforms (this comes up a
> few places)? If so, I'll do that for a v4.
>=20

On powerpc it is always (from arch/powerpc/include/asm/page.h) :

/*
  * Subtle: (1 << PAGE_SHIFT) is an int, not an unsigned long. So if we
  * assign PAGE_MASK to a larger type it gets extended the way we want
  * (i.e. with 1s in the high bits)
  */
#define PAGE_MASK      (~((1 << PAGE_SHIFT) - 1))

#define PAGE_SIZE		(1UL << PAGE_SHIFT)


So it would work I guess.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f10fcfbf-2da6-cf2d-6027-fbf8b52803e9%40csgroup.eu.
