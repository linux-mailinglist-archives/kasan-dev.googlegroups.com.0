Return-Path: <kasan-dev+bncBC27HSOJ44LBBWHOQ6NAMGQE6JJPFUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D89B5F881D
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Oct 2022 00:19:05 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id oz32-20020a1709077da000b0078dabbe9760sf3422ejc.12
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 15:19:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665267544; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tpe3JfPcDItxi/Q7l3jTenBDZGBGkOJ9NjQ19UEQDaoz3lJ1YYy7ITU5wxJXVZ8x/k
         VroFZM2r3tMMZ78vZzosHo8O2hX+M7LD0JUcTYXV6TlUj07UxZNyi9k33Y2kSN4Tgqsz
         aCfnPnxa/ag9E97tKSp5Apn9GDVTYwfj4kT9CDwOXHSL8xuEpxU6VeW/pWgAwA+cm3HH
         +UDpem1virnPJ8Rm52SEmnouX6IKDchTIevJ1APw9LMGNkuYWy1NxSS7gccs76RwqWcw
         G+jToOz2+9TCAjy2PVB4yYK9lmEF8ddxFfFAQDFKVL2UQcESs567ocN7XihBtsjW7hXt
         NFXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=Hzws+YrrqNCQEQtm3EMb0fef1uRwZJBRgEaH3PIRX4E=;
        b=ro78SmeGeBln6c/KaDFfv1T49McQo7pOuLj218mh4hw8YFmnzCpgOq1Pcy6f2/hfpf
         RAks+wq6h1MzgU98LEdV72ntKzHO5kIoM0NYZLfWm1xoSTi1swgDIOB3+bgFtcp5MkGM
         KIW3tvHqjyI+vhT5l7fnowd1nEz23VAdgioAxxCCfUemF6YOAR005/99PQXRXC4EUN0Y
         X+1DqbB5uKAnGm/oILW12wJI892pEziZ+Wg9ibKu87dqUP3UDd8gujsifPTkVbHdb74x
         j/PWmPLmJy0OunfoYx4jka4MA65ClHsXpdR2LsLbbdxLPUBmP0o2ObrH4f+xM4uIBNau
         I+YQ==
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
        bh=Hzws+YrrqNCQEQtm3EMb0fef1uRwZJBRgEaH3PIRX4E=;
        b=OecAR/fb03NE7RKetLoP4qI7rbHlmnPX4a0HIA+NMz8lRcqgqrd4HJb6L2/GFG1gYF
         HHBKkUC/flJXpLUqlW0XPnfmqjUevGNydqoXJsTgTXjVpptbjdl/ijj2ttmU5CvQg7vZ
         t2OUYa7D11U/xaOP8bCsrXckaHHjsdBj3ChhiDN/LxwDLCW7BOlGV9rL4AWTguh9nmFP
         5eC9SZ4rnZ3leVQP1FRjO8Wttpayq99vRNTVb0Xd27eCtVt+s3CbOLtNfm+jtDRV2di2
         EoP9aXKszN9IEcVya845kerEvewqqyXYzm3Ervwx7ME1aQivDeYvt8WACPyB8R70LBzK
         Uy7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hzws+YrrqNCQEQtm3EMb0fef1uRwZJBRgEaH3PIRX4E=;
        b=5OhSjq+68DiWHJL13G9HFpom+RJpr6+yv4dLiNyAooW+8Mq01LPOf7tM1RDypzliah
         MF2uO/vd0vDR6U8PgbhkkAJR6+5Q2tZyDf/YrPNdYiqLmugYbbWlAiT/uLy7Kymti3Xd
         /93VpxgKyPQN4jzB8iN/NpQHjugM9aR+yBEyYKZjthvi2+YcsNGOqtCN/CxNxcWutgVg
         bax5J8Yt2XNNKOAMxX71xxCNzdqu9/XVL04o8oAmr+2Zn7lDRdxzFwZ4VbUu8ZM2pmGL
         PJc86Nq3E1VCVHPRbJRc43DNoc6uNsFVqjy+5fEZt5lnJW5rdigjtf71jkPWGIqfHDFv
         JZKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2cA+vYBACYXbGa+2sbihytcHcmjcRW5vwyLSm9jm8COgdmEZk7
	XbaTn29GmIikLT+mvU/9/pY=
X-Google-Smtp-Source: AMsMyM64hInzm3NtnCnbn7/LqdR3xf5uIpz4lDmc4ICUGR2v3p+Npi0e4xJt23UkCgI8IizHPq3PaQ==
X-Received: by 2002:a17:907:7e90:b0:78d:50f7:8abd with SMTP id qb16-20020a1709077e9000b0078d50f78abdmr8142341ejc.523.1665267544377;
        Sat, 08 Oct 2022 15:19:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:78e:b0:776:305f:399f with SMTP id
 l14-20020a170906078e00b00776305f399fls2514034ejc.1.-pod-prod-gmail; Sat, 08
 Oct 2022 15:19:03 -0700 (PDT)
X-Received: by 2002:a17:907:75ef:b0:78d:98a2:8380 with SMTP id jz15-20020a17090775ef00b0078d98a28380mr3306761ejc.752.1665267543273;
        Sat, 08 Oct 2022 15:19:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665267543; cv=none;
        d=google.com; s=arc-20160816;
        b=vKTCEyzGnNsEIUTqr0DPjEo7x958AvpYdAeqlmDFE0Tn0X9W2rz8a4HSJUTrmZD/m2
         5+uw3xqdC0XoZTFYkTEujlXtVWk/iSaChNbJR/PZ1N3dbxaCet39d7n4+ORJSUGv9fS0
         Kuo0EzcxdmmiC+6CYKQPeqspubpJZP/LFqyT8AS0weNjOqP397M7oF/aUve9pVTEVuWW
         YxfR+B0UEXs2A/sg6h3uhLCPcCLQdFUWxGRrOVftMa5avNN7wougcHLajWsM78CGjbS0
         fe4Z5ecPdqL6VOmoZeRIijuqnPZK9vMxkXCT5bbM3ngFryxgLfRp7KRTDLj4DXONoIS6
         WuZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=QPE6Z2C7bDKI1w/an0gLLTE3rvrHgBAFGfBjPI2dPr0=;
        b=vXDOMPFIFc2ckkqCbQpyVfIpg+f1YBd5Vl68WVX3tbYn6n+v5Zv2HuRtaG/VXLE/Jt
         EbZlzwdBDu50ugmjsu1HnNdC6r7GaaVYgJi+hS9LqqNmlmuAMeKBRLS/4s+ZwRYQXfFu
         0UCmd2Yi4pZXZ1r9GktUzvcKb/oe1tK5I3Q8cFZncfKhgrqh/jy6qnSr3zhoE9/3h4F1
         1CJ4CxBK+UAHBbDyxIL8d8tiFDrAMkmdu8JkraP9x2OXMOPfNtAMOleAnxpEhb3ImUQo
         rLYBv8PaLc2I+qknOL4rRNaoCiCz4aAHKdTAsSSNcn+gKTQ63qD3PRVIGiO3o54s2jMS
         rkoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id jx7-20020a170907760700b0078bec38b1e9si1707ejc.1.2022.10.08.15.19.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 08 Oct 2022 15:19:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-78-vsudmffZOXKo2YB6dC4dtQ-1; Sat, 08 Oct 2022 23:18:48 +0100
X-MC-Unique: vsudmffZOXKo2YB6dC4dtQ-1
Received: from AcuMS.Aculab.com (10.202.163.4) by AcuMS.aculab.com
 (10.202.163.4) with Microsoft SMTP Server (TLS) id 15.0.1497.38; Sat, 8 Oct
 2022 23:18:45 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.040; Sat, 8 Oct 2022 23:18:45 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: "'Jason A. Donenfeld'" <Jason@zx2c4.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "patches@lists.linux.dev"
	<patches@lists.linux.dev>
CC: Andreas Noever <andreas.noever@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, "Catalin
 Marinas" <catalin.marinas@arm.com>, =?utf-8?B?Q2hyaXN0b3BoIELDtmhtd2FsZGVy?=
	<christoph.boehmwalder@linbit.com>, Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>, Daniel Borkmann
	<daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, Dave Hansen
	<dave.hansen@linux.intel.com>, "David S . Miller" <davem@davemloft.net>,
	"Eric Dumazet" <edumazet@google.com>, Florian Westphal <fw@strlen.de>, "Greg
 Kroah-Hartman" <gregkh@linuxfoundation.org>, "H . Peter Anvin"
	<hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>, Helge Deller
	<deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen
	<chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>, Jakub Kicinski
	<kuba@kernel.org>, "James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara
	<jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>, Jens Axboe
	<axboe@kernel.dk>, Johannes Berg <johannes@sipsolutions.net>, Jonathan Corbet
	<corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh
	<kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>, Marco Elver
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
	<toke@toke.dk>, Chuck Lever <chuck.lever@oracle.com>, Jan Kara
	<jack@suse.cz>, Mika Westerberg <mika.westerberg@linux.intel.com>
Subject: RE: [PATCH v4 4/6] treewide: use get_random_u32() when possible
Thread-Topic: [PATCH v4 4/6] treewide: use get_random_u32() when possible
Thread-Index: AQHY2ncqUPYFdmCx0kGKfFsfF+6dcq4FEdQw
Date: Sat, 8 Oct 2022 22:18:45 +0000
Message-ID: <f1ca1b53bc104065a83da60161a4c7b6@AcuMS.aculab.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-5-Jason@zx2c4.com>
In-Reply-To: <20221007180107.216067-5-Jason@zx2c4.com>
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
> Sent: 07 October 2022 19:01
> 
> The prandom_u32() function has been a deprecated inline wrapper around
> get_random_u32() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function. The same also applies to get_random_int(), which is
> just a wrapper around get_random_u32().
> 
...
> diff --git a/net/802/garp.c b/net/802/garp.c
> index f6012f8e59f0..c1bb67e25430 100644
> --- a/net/802/garp.c
> +++ b/net/802/garp.c
> @@ -407,7 +407,7 @@ static void garp_join_timer_arm(struct garp_applicant *app)
>  {
>  	unsigned long delay;
> 
> -	delay = (u64)msecs_to_jiffies(garp_join_time) * prandom_u32() >> 32;
> +	delay = (u64)msecs_to_jiffies(garp_join_time) * get_random_u32() >> 32;
>  	mod_timer(&app->join_timer, jiffies + delay);
>  }
> 
> diff --git a/net/802/mrp.c b/net/802/mrp.c
> index 35e04cc5390c..3e9fe9f5d9bf 100644
> --- a/net/802/mrp.c
> +++ b/net/802/mrp.c
> @@ -592,7 +592,7 @@ static void mrp_join_timer_arm(struct mrp_applicant *app)
>  {
>  	unsigned long delay;
> 
> -	delay = (u64)msecs_to_jiffies(mrp_join_time) * prandom_u32() >> 32;
> +	delay = (u64)msecs_to_jiffies(mrp_join_time) * get_random_u32() >> 32;
>  	mod_timer(&app->join_timer, jiffies + delay);
>  }
> 

Aren't those:
	delay = prandom_u32_max(msecs_to_jiffies(xxx_join_time));

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f1ca1b53bc104065a83da60161a4c7b6%40AcuMS.aculab.com.
