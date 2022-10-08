Return-Path: <kasan-dev+bncBC27HSOJ44LBB77JQ6NAMGQERLFX46A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 064425F8807
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Oct 2022 00:09:04 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id n19-20020a7bcbd3000000b003c4a72334e7sf458272wmi.8
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 15:09:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665266943; cv=pass;
        d=google.com; s=arc-20160816;
        b=T2nFxdvMt40DOKuyJdXWiCzfri/Y0kUpYpYrtw20vWj3kapfiOs2iTHZEDB3yZejLZ
         wEYRFXth51uhsyBdC6fhpQnaMNdrszWgV/yFb0gHPariwrlP6RKmtY4QGEihpbQxjGfM
         jNh9Xhwy83IUS6wAGUP5F9qlkubidKRvOD219un0kgkPLwGA4wTIPncwFfVfnQ8d/sbb
         ULCeuSWmmga7k0hkyaYdwYlJDVdhm5qUKY+ycz9cyks0r6itLO1O5XZhi0mNUUqvGNYd
         C1L9kpvudjqISFPb4YTg67CykxiSvSVyDMhovQXK925oIUXaf2G4eOSl/NUYn2ErhRJS
         V2Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=FPzUYb4G65WKJWxxP/ul01mcVjJjrIZ9rgZzxJ4gd9o=;
        b=u71FHCEFj+FztT0OMc5ksMG46exUCI7jLvQnIgMeWiQGjPo6NJeecFDvYMMSodiuse
         0R44Pz+gW1gpQa39ONfFI0J7U9vYlZsI03GJFSfT7m/+AiHmoSgveTSEwS6zJS/2dvcY
         F+AywY2RZmPfO2VMS6sGSxXc83QpNEJqmQqwbExz94grmXTKxwP+ucRkN1KNu+O5JKwa
         VS2WTco6UoGD4cKQ9Kqt7f9hesirGbiNq9OJJueWmNd9hbfvPElOPgK7DT21rcWHbjZ2
         7n/11XJIIDt2vpRTohOS5EDPh8/o+NLLE+z1nsRUCKnzWeV439R2trDxJeuzAJeAYF4U
         e9JA==
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
        bh=FPzUYb4G65WKJWxxP/ul01mcVjJjrIZ9rgZzxJ4gd9o=;
        b=EHaq+VBjA4gRR1oGgNKeP6FBpZzHkjdb7znkGH2TPs22a4C1T1iq/31U0AnSlyxEe7
         yczgWwDT4avXQszgIW40Q/mXTKBaREC0eeHifHfTxB35WF6hEM17Dj2QafH/v45w27S2
         qgr3+aRcb9lCywxXFDnNi+hpuNzFNjx0stgensSs1tlVrv9m47l+Y426RK0vtTCeG1y1
         nRfhwPx7CqDyQfrxa3291OCtPpx3shy0Da6Xc1lTKHacsdU+4Nw0bG4TNEghDuRB3b1n
         OJaqJnRBc2b4SW7L0AJief/88k4U/nfTeE8PKAsZybIDwfuq1aqaNGgGxcBxv28uY468
         2oMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FPzUYb4G65WKJWxxP/ul01mcVjJjrIZ9rgZzxJ4gd9o=;
        b=1rXb95p6IDI1KYKp9fzkOKzKOZuKcCIxK8sLZJwvR4Kk0Y9jttr6NCQYI8PVANNiT2
         gJeRgn+vh8Ft0/FSJ60/4xDTQwgOPTBWjnOrzZZJxz83i8408w8OkNTxcbFqmEf676aQ
         ttKdtMzxair/bR0TjVBI2elZPvVWCNDqDtypJc4AqqbaUIOlbmRs9LyUbr+mUA8F/KIc
         UVqaahMigEIp7ap23Sa00+TGntKhSF6tgDgs3PwM7LaHzc0J2h8WhgT/soB3jCS/icL6
         XTBBK+4t4WpJ2+A0RhSA9rt6sp8A51HKFz6pj4Iu5f/LWx3uVCGruEPJk2EoqI85Sa2A
         5nVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1KzxaMRm0MWVn0CiZxBr1rGtniwkgI9WwObxW6PrnzSCVG5gnN
	JVZZ8azvnjsg7NzfAHWxL5k=
X-Google-Smtp-Source: AMsMyM40JxsCRYMV/zh2aFMOeR9UEpWpnWam1bw6adne1utNt4ouRFmZTbuw9cTXBEcV8TFs8QImGg==
X-Received: by 2002:a5d:6e8e:0:b0:220:5fa1:d508 with SMTP id k14-20020a5d6e8e000000b002205fa1d508mr7535488wrz.337.1665266943466;
        Sat, 08 Oct 2022 15:09:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:b4b:b0:3c5:8bf6:a4bd with SMTP id
 k11-20020a05600c0b4b00b003c58bf6a4bdls238332wmr.1.-pod-control-gmail; Sat, 08
 Oct 2022 15:09:02 -0700 (PDT)
X-Received: by 2002:a05:600c:1ca8:b0:3b4:a5d1:2033 with SMTP id k40-20020a05600c1ca800b003b4a5d12033mr14338756wms.23.1665266942372;
        Sat, 08 Oct 2022 15:09:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665266942; cv=none;
        d=google.com; s=arc-20160816;
        b=sdIY95o/NH6+lT9gUuVDNMFHjI59pg0F6U5gdkrU3XGJSOiYeEZMviVNefbXqeE3aI
         LNkcjFTnWczzvioZQiTYzSn/5TVz+VEPgNk97cHUFiuB2Qr33WCWiGsMPWQru+bghtR/
         T5qQJqwBsXbLw9gCgNU3uFwYeuWtgkcLgbnpR4ElMWmCIsxt0+ufXOzZzBwoLCZLqykb
         5DmTlEAtvh3lAK4q4bYuqpj2gdw0jtHhd5dxe4wl+H5Sv+/7H596WxTi3SA6sJ+pG6i2
         FCQrSyIX3ySCHwAknJe1jVvlVE6/6O2ZDpM+K5WzJFj13zabi0HwjByGw59H8MkT3X87
         qVAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=aU7nS9jrGJvRhaHpSenOURqags1qPX5KpilsUHhXdBg=;
        b=Yuycl07oyC9er76TF4feUfj87NxVs2fbe5tTDGcZoGwU/f8+OphOJhiXjqExvokgOL
         gIfSwCmiAbV72jMPZwazm1GNowvgCYHR7nu8jVTex/TIYxNJpZgrxA2pcOWdqUbEo5Np
         kw2N5x09MO2NhN6w4ZdKLHD4C5UiuZK/7iAIh51U42+J7vokj26uili64AQzl6TYHS2R
         NIg5dv+heJYBfETQbqcjZhNBhvYHHutz5RprtxUb8kTCnVIqLDRy14935cpfhTINezeS
         jZf/7+2ovA7B5r/mZMJKVuTx8ZPtQkCimgS++1vhOwljuYCJtMiCWg6wdstZn2IuJ+J9
         Hv1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id bj8-20020a0560001e0800b0022e04ae3a44si224709wrb.6.2022.10.08.15.09.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 08 Oct 2022 15:09:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-98-KtAFQuLTPeKLVd871cru4Q-1; Sat, 08 Oct 2022 23:08:05 +0100
X-MC-Unique: KtAFQuLTPeKLVd871cru4Q-1
Received: from AcuMS.Aculab.com (10.202.163.4) by AcuMS.aculab.com
 (10.202.163.4) with Microsoft SMTP Server (TLS) id 15.0.1497.38; Sat, 8 Oct
 2022 23:08:03 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.040; Sat, 8 Oct 2022 23:08:03 +0100
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
	<x86@kernel.org>, Jan Kara <jack@suse.cz>
Subject: RE: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
Thread-Topic: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
Thread-Index: AQHY2ncm2NigVNsUqkWyNH5TWnqFQK4FDn2g
Date: Sat, 8 Oct 2022 22:08:03 +0000
Message-ID: <01fafe0e56554b1c9c934c458b93473a@AcuMS.aculab.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-3-Jason@zx2c4.com>
In-Reply-To: <20221007180107.216067-3-Jason@zx2c4.com>
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
> Rather than incurring a division or requesting too many random bytes for
> the given range, use the prandom_u32_max() function, which only takes
> the minimum required bytes from the RNG and avoids divisions.
> 
...
> --- a/lib/cmdline_kunit.c
> +++ b/lib/cmdline_kunit.c
> @@ -76,7 +76,7 @@ static void cmdline_test_lead_int(struct kunit *test)
>  		int rc = cmdline_test_values[i];
>  		int offset;
> 
> -		sprintf(in, "%u%s", prandom_u32_max(256), str);
> +		sprintf(in, "%u%s", get_random_int() % 256, str);
>  		/* Only first '-' after the number will advance the pointer */
>  		offset = strlen(in) - strlen(str) + !!(rc == 2);
>  		cmdline_do_one_test(test, in, rc, offset);
> @@ -94,7 +94,7 @@ static void cmdline_test_tail_int(struct kunit *test)
>  		int rc = strcmp(str, "") ? (strcmp(str, "-") ? 0 : 1) : 1;
>  		int offset;
> 
> -		sprintf(in, "%s%u", str, prandom_u32_max(256));
> +		sprintf(in, "%s%u", str, get_random_int() % 256);
>  		/*
>  		 * Only first and leading '-' not followed by integer
>  		 * will advance the pointer.

Something has gone backwards here....
And get_random_u8() looks a better fit.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01fafe0e56554b1c9c934c458b93473a%40AcuMS.aculab.com.
