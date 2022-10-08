Return-Path: <kasan-dev+bncBC27HSOJ44LBB67CQ6NAMGQED56O6TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C55F65F8796
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 23:54:03 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id f18-20020a056402355200b0045115517911sf6263043edd.14
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 14:54:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665266043; cv=pass;
        d=google.com; s=arc-20160816;
        b=DInIX+P/h11WmJuE0UvbjUjovfHFLmEh+zZvo80coobrKJ02q006TpnA27x5ZRafV9
         BB1WxeK7hNihOIS2uVRVysWtvMaIA5d2KBZPhIAIFzZ8iRhV5oE/I5nWtRUPtxl583E2
         fH54RMrIByf2hhOpUrwe6617tCThpIOIxnqzb0mI88ilNXM1e3K3AFXb7GEzAiRLYB6l
         xPwioo7WE2DLET2dWOrUq8kMOeW7Q73JKyXzCVsFb5T9W//6GfiS3mT09JO0HQomYGPR
         XN5yTng8QzfvTlu1ql1vTvxudpe/+AGjuMt9u2YNBhWQmZJ1+tWzbvSCFJ+nC09zgVVV
         OkIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=GG90FLk9nwRaE39xPrKPECL1RrpLtXeOrrmrpNEKcC4=;
        b=bPJwS34alRm/QLvL8YOeXbUkQjBwsnQDQXO0hjjquFhagW/bnoSpD0vofQ0CRzuA/4
         ut8u+hcyaqBlSSVu1RQuDVTaivjFcA/gvC8buB1hh8VBh2et4fTT3uz1yBtapkWf0vSP
         qul0M7FLT2pGvYYQF2aefpRjz0oEvuN64l6fzxJihMQCUvLLB9Qlu/ZKLgsK/pVJuinx
         Ks8B+UHXtOpW9psE8MODt/VQttPdB0J3BiD/XJIcw0+4f3mJYw3n2c//sgE0J/ERa12+
         hBrtQvBAAY309dCfTElcF8YnlCmF9wrawXBlc8VSUx1T2tTZxkp8mBOTMQTMz6Im9xdL
         ApKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GG90FLk9nwRaE39xPrKPECL1RrpLtXeOrrmrpNEKcC4=;
        b=JmVtpqCf26/qlRrcGkchiY41UosGq3tpPz5hcFEFOEgh5C3OlXjmvc9WSClW902tv6
         43Dxwa3YPC1ErUUVpOd2cIZD7mcM8L4cmt4lXLKOCBqxdfq9BmvcMsCkR0JYKERK0Mw1
         xoSD7ab6Wveb/XwfmynRmsoq9TJ83njYMNITT/UvGnkZVqsKwMynLvF8s1vnKXWGJZRh
         xmreK+3zeLP3613fDuueC2qs1gbEvWsvOXoDbpWRj7NxRTlBhI7Si+dNBNe9Z5VIIbE2
         whPguvCqYG1s/AEg/5H2s1K9A0DKkOS/YaC4mHc2sReqjg3KP0KZivrk8I8IkJ9D53MG
         D3/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GG90FLk9nwRaE39xPrKPECL1RrpLtXeOrrmrpNEKcC4=;
        b=g/lnYHGGyo3iPuzUYRlG6PuyK+Zt7Z1nAGfXusZRBSCcyV8pIPLMMDMcgpDB3w9nH+
         +KNICNnwdhuJmQtNtWdPGhYmbrJWqd9Y6sua9hGnYMM4yL0BQceytxElDsYnlLznKA8i
         GSS4qeq61KatSc/3LPTqOHKkkdmsyaAKXbl6s2x4F4ZrHarDiob3KUuhKGIW5R1G8Zvc
         bBY+McjsUTs11czb6nTSdcTTterrf/bLi9ERBLQqs5GJN//NRGLM6kV1KgjQxMtYgppo
         ZuI5OHA5IUPOF9/uRCRS+0axk6sWhxiKkRKxqfqQdtNQ9g93ACCHwqP84glTNTO+OJ3v
         350w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1mErlj5y0xprRH3XYwu5fji2HVceQrzw+jAS0c3GfcEikjltY4
	hcTXDGSz8fbHIjUTN7r9W1Q=
X-Google-Smtp-Source: AMsMyM758DyLCzOWAhaAgll6Kszevwmn78dQ97uVlpI8RP+Th8YUSZUaSMAc0C0V7d6QH/VFKjVulw==
X-Received: by 2002:a05:6402:909:b0:435:a8b:5232 with SMTP id g9-20020a056402090900b004350a8b5232mr10589925edz.240.1665266043337;
        Sat, 08 Oct 2022 14:54:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:430c:b0:43d:b3c4:cd21 with SMTP id
 m12-20020a056402430c00b0043db3c4cd21ls4910832edc.2.-pod-prod-gmail; Sat, 08
 Oct 2022 14:54:02 -0700 (PDT)
X-Received: by 2002:a05:6402:1a4d:b0:459:319f:ff80 with SMTP id bf13-20020a0564021a4d00b00459319fff80mr10940711edb.144.1665266042201;
        Sat, 08 Oct 2022 14:54:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665266042; cv=none;
        d=google.com; s=arc-20160816;
        b=sovP8JpEbGTP82UojpPXgMm2KbE+YGBwaiaX7E4F0ShCJaTWeuUJVvfXIgU08FOgin
         xDlDeiB8wX3XtNC2EHa8ukQm8piAy+t5Xr4yaKnc9D5bs7WbIaHfQf3T0Uy/l+U0DOTQ
         mbXjdDe3n1zBQ0oXFC3mHOy/g5tbFrx28lsw9WROI+DmW5x57PiN59v0yKdaZGFb4Zhz
         wTgn4AEGhN+fNg1TVLbgqwkNdBmb+Ue750q2FMZs0DlwOsA/DPFPkudrOIROcAIr6aKo
         tRePw3wajLp1E+NYurWDYUT7bJ3QHChVzWnsf9+qJ+aVReqh5fcDcG/RTAfFGUSagBSs
         8Haw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=hb0VXCKLruF+ZNpCZzbOy07uBh6U/F7RD9v4TsKga4I=;
        b=WwtZhyu/dlnzahnV40kzwBg4//lFrkLsuD+GEJv2CihG6Z3owTD/lq7X5JgxJhS2oX
         tBZGG8TuOSBcDc0OzIRhRhJ0L80nssOs1NX3uU73DC4nr/B77cn43+pA1LrvAud/ZCcv
         f0c76XM/b6fl7NV+AFqW6h9c8si9f/5vF+u22AzZ+GOipKpBL58Q0EO0Pz5Rl2qkjqbs
         QQ6LDxbhkrugAsnVF8jU3uEb8UqsJ3NX6N2XNH8W69ZQLu+lv2lLvzJLswAYxZAhOaJL
         +1RJeukOOyjQQqVbnllAYVSoUE4tKr3KKLyd8/IE5Yn505hzsETaNrBHZF1YsO334B6m
         8rWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id og26-20020a1709071dda00b0078d3ac8bbedsi268129ejc.0.2022.10.08.14.54.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 08 Oct 2022 14:54:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-322-B0KkuonxN4-iDxIJpOcDbw-1; Sat, 08 Oct 2022 22:53:36 +0100
X-MC-Unique: B0KkuonxN4-iDxIJpOcDbw-1
Received: from AcuMS.Aculab.com (10.202.163.6) by AcuMS.aculab.com
 (10.202.163.6) with Microsoft SMTP Server (TLS) id 15.0.1497.38; Sat, 8 Oct
 2022 22:53:33 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.040; Sat, 8 Oct 2022 22:53:33 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: "'Jason A. Donenfeld'" <Jason@zx2c4.com>, Kees Cook
	<keescook@chromium.org>
CC: Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"patches@lists.linux.dev" <patches@lists.linux.dev>, Andreas Noever
	<andreas.noever@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Andy
 Shevchenko" <andriy.shevchenko@linux.intel.com>, Borislav Petkov
	<bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>,
	=?utf-8?B?Q2hyaXN0b3BoIELDtmhtd2FsZGVy?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>, Daniel Borkmann <daniel@iogearbox.net>, "Dave
 Airlie" <airlied@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>, Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>, "H . Peter Anvin" <hpa@zytor.com>, "Heiko
 Carstens" <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>, Herbert Xu
	<herbert@gondor.apana.org.au>, Huacai Chen <chenhuacai@kernel.org>, "Hugh
 Dickins" <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>, "James E . J .
 Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, Jason Gunthorpe
	<jgg@ziepe.ca>, Jens Axboe <axboe@kernel.dk>, Johannes Berg
	<johannes@sipsolutions.net>, Jonathan Corbet <corbet@lwn.net>, "Jozsef
 Kadlecsik" <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, Marco Elver
	<elver@google.com>, Mauro Carvalho Chehab <mchehab@kernel.org>, "Michael
 Ellerman" <mpe@ellerman.id.au>, Pablo Neira Ayuso <pablo@netfilter.org>,
	"Paolo Abeni" <pabeni@redhat.com>, Peter Zijlstra <peterz@infradead.org>,
	"Richard Weinberger" <richard@nod.at>, Russell King <linux@armlinux.org.uk>,
	"Theodore Ts'o" <tytso@mit.edu>, Thomas Bogendoerfer
	<tsbogend@alpha.franken.de>, "Thomas Gleixner" <tglx@linutronix.de>, Thomas
 Graf <tgraf@suug.ch>, Ulf Hansson <ulf.hansson@linaro.org>, Vignesh
 Raghavendra <vigneshr@ti.com>, WANG Xuerui <kernel@xen0n.name>, Will Deacon
	<will@kernel.org>, Yury Norov <yury.norov@gmail.com>,
	"dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"kernel-janitors@vger.kernel.org" <kernel-janitors@vger.kernel.org>,
	"linux-arm-kernel@lists.infradead.org"
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
Subject: RE: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Thread-Topic: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Thread-Index: AQHY2nYZ0LDp17FxT0u8eu+L+6kCF64FCBzw
Date: Sat, 8 Oct 2022 21:53:33 +0000
Message-ID: <69080fb8cace486db4e28e2e90f1d550@AcuMS.aculab.com>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
 <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
 <CAHmME9pE4saqnwxhsAwt-xegYGjsavPOGnHCbZhUXD7kaJ+GAA@mail.gmail.com>
 <501b0fc3-6c67-657f-781e-25ee0283bc2e@csgroup.eu>
 <Y0Ayvov/KQmrIwTS@zx2c4.com> <202210071010.52C672FA9@keescook>
 <Y0BoQmVauPLC2uW5@zx2c4.com>
In-Reply-To: <Y0BoQmVauPLC2uW5@zx2c4.com>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Jason A. Donenfeld
> Sent: 07 October 2022 18:56
...
> > Given these kinds of less mechanical changes, it may make sense to split
> > these from the "trivial" conversions in a treewide patch. The chance of
> > needing a revert from the simple 1:1 conversions is much lower than the
> > need to revert by-hand changes.
> >
> > The Cocci script I suggested in my v1 review gets 80% of the first
> > patch, for example.
> 
> I'll split things up into a mechanical step and a non-mechanical step.
> Good idea.

I'd also do something about the 'get_random_int() & 3' cases.
(ie remainder by 2^n-1)
These can be converted to 'get_random_u8() & 3' (etc).
So they only need one random byte (not 4) and no multiply.

Possibly something based on (the quickly typed, and not C):
#define get_random_below(val) [
	if (builtin_constant(val))
		BUILD_BUG_ON(!val || val > 0x100000000ull)
		if (!(val & (val - 1)) {
			if (val <= 0x100)
				return get_random_u8() & (val - 1);
			if (val <= 0x10000)
				return get_random_u16() & (val - 1);
			return get_random_u32() & (val - 1);
		}
	}
	BUILD_BUG_ON(sizeof (val) > 4);
	return ((u64)get_random_u32() * val) >> 32;
}

get_random_below() is a much better name than prandom_u32_max().

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/69080fb8cace486db4e28e2e90f1d550%40AcuMS.aculab.com.
