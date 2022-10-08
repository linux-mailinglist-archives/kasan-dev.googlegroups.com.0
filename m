Return-Path: <kasan-dev+bncBCLI747UVAFRBOV5QONAMGQEX3OELEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A86A15F8256
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 04:21:47 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id a10-20020a5b0aca000000b006b05bfb6ab0sf6102994ybr.9
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 19:21:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665195706; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cp/njUyMToZ9tMRqBsnEzRP5SAs8X4eIYyTIqV6g015OOz9yJgGbNoYIjCodssiO+D
         7g/I8L7UBbUCsSYhnLN7Gs4ixqUZ8ojc+iWjOiCp6xnpdzsEYOvDqWwL9hSmNugvzfov
         lLUwzZHgbv1qh1bdaXvQGb7Ni673hAqLxk3j+tMnXGy2b9VDlPXTjvi370dI8Q7CK5Mu
         l0o59Oyig1C7KPTNhTES3dguhUllS2uCMK2nYFh+OT7+Aw5NRMafbJ5HgAOYrDcm6kF9
         vG0fcZ8ivRUcba3OgQIrmuAACMvbO+QKJ3bhwSHgyliLtq+h4UvPXmXT7UVWA3if40G8
         Cfcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ea4zh/yYyUrQTmImIDD2yGYv3C/8csBcEGkGdNStRhE=;
        b=u41LESSVtYVAnh/qqxftqzoFa2m/nEnpM1wqvYIf6YIX6hfwQPeWh75fTTHWFv0yLt
         7TukMhnjF5pWkUToTGDN9245fiMwPRGrsVs2XWRI7oyxqFQpMpCDLuWupvmib055F88V
         DFtG04H78vGi3EgZBaG15oZfBFBoLopgu8+cWkADUxG8mbnUfAaLU2Dr8MTxRGDlonDm
         fY3beWxc1ki/vWMETe0fa66cPDo5iZfypv50tYtyvQUG+DcXjAHS/yzggJDqwAf2Q2jH
         O8QDKV9w/dGKvUWUoZ+byE9XpFle4WuCQ6Ka6daADvZuARJpuDdNDTvzkdCXrEfnB6Vy
         qgWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=LYfvW0ZZ;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ea4zh/yYyUrQTmImIDD2yGYv3C/8csBcEGkGdNStRhE=;
        b=hRVoM+rzOgsZXuigfku1vZ12NY3TGwwGQDqcscV9MrO+i1Ydn/HRwjBzrsMRF6dTpp
         5e+tqhK//g6Ce5+/UEByYsJfWpu/fk6Lwdhm/r7GMtITnlZsGGIcvdYZesKQaiVjBlYn
         hPbscIYVYaIMdPBZ01F2YS57UUjy0JjLNEpVZqhniVQWMGjc1AztsFyacCu1I31SeVYa
         vf9mG7LDKba4kqDMJiPZ4MPLVSA4GXOt4LdDvUvxs5nbPiOEa3bThQQ7h+0IQG3zTZF8
         WTW9Qd3ju1d9sprt4Xojt+eCfjURbm2sWJOQDyhuEr6TLkdp4MVQ7NF4XJA665nArxRT
         4Lvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ea4zh/yYyUrQTmImIDD2yGYv3C/8csBcEGkGdNStRhE=;
        b=DpFMdQL1v+sL0YRNMs/7IR1oEAtD3d2yJjW9qyJnuyVeVtXGc+WLaT2s1gVkFLt90+
         Y750zdWgUokTRYRgDFMkP62603TGpo6umt7HpUHNi/3mFJP6ltFcbd32KOgsli0+5KO2
         bHGptzhswhePgrGsXMw69UhKODILMorZYUMxGaMdm9t+AF5G5Os+Zeyfw8xZHriBkC8/
         56DdBzf648CkedG3y+0iK4U/XvkgPRBsd6GZgh2vNXao9vophqhmiCZk71wuS9IvuYYq
         0WXSzTSJKy6OFJ7urh1p7vBDbeeX99NTJUB7QB+EnMtw1Evg0lwV9c74hmgeo5bULcAd
         i+nA==
X-Gm-Message-State: ACrzQf0iuwrB+fWfuOs8H2ddT1FBidpZPTqAR3XvCBcqh+xH/PoyC3aF
	F0+BAfQ3IOjBIZZib6Tsm8E=
X-Google-Smtp-Source: AMsMyM6guImbOJczMc5w5zcW3bqUn1Xv6bjLeyvIHdnGz9zdBlbAoMiMr36YmPzTYb86ZEa1cDoyxQ==
X-Received: by 2002:a25:1082:0:b0:6bc:9f59:b567 with SMTP id 124-20020a251082000000b006bc9f59b567mr7303049ybq.107.1665195706307;
        Fri, 07 Oct 2022 19:21:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b227:0:b0:6be:8daa:181d with SMTP id i39-20020a25b227000000b006be8daa181dls3638319ybj.11.-pod-prod-gmail;
 Fri, 07 Oct 2022 19:21:45 -0700 (PDT)
X-Received: by 2002:a5b:389:0:b0:6bb:bf9a:e647 with SMTP id k9-20020a5b0389000000b006bbbf9ae647mr7736462ybp.114.1665195705690;
        Fri, 07 Oct 2022 19:21:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665195705; cv=none;
        d=google.com; s=arc-20160816;
        b=hw1dR/++7ICpdyv4DaCMIU9wVHu9+QfQGri3hjwwU1sZA5UKQSd62aNZNFcbphsL5T
         B5nx5yTpplqN0SSv9j675bhwDZlV8PL5ED6cDh6yjy1dkX42q6ePSk11RIhm64xruZMk
         BMqxEZFnIDQwt+WVdskw/3dBmxw9tcnBh9Xzee/rmCSbX9FSq9CN2wgUoDhaYZx92OzA
         HXU2nyMq5U0gbbyizccNn0R6AZXPaDyXdt87vTM1xGxzz5OWHOKXaQgSvJ9dbesSIo6f
         1P7C3oBNdi9pgc8OIAlvT7cG2GEK8vcbQETG/XANQ/rPI4o9wtCd5Ww6zccncfMPFf5z
         wRVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nQirwEB0hjkXJ9U2/sbrNj05mdvuwOBFqUHuwVO4sG4=;
        b=Kx7eqezPk3nkLZEW/s92bq/m3bjvcx1iIy7dMV5pjNSrOkF43kcZZVNfWlsP+oPRvz
         cXlrzJ7W+eheq+DiszBum/YoUb3qwCPXP+C1zd0hdHEq6NUY2QkN2htJlLoaKSfp4xht
         ZocRIl4wdzNW6i5ed2I0JJnIsuHYEBqZxoZjjokp7fnfhVv5vAZAJf2UzcM92L8lbHU6
         4jOiFS9xJqzbvbDjTYkphf0fEvPiGDc/baFdKUYydV34AW1GQDpYDqFt3YynZADAdLo9
         L0fpRX1j6jJUWKVvx2eNfd2+JWsa2oV4SEyq4Of7tYjUMDdZSSFal/bDTp+6kjuFlhUh
         k2Sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=LYfvW0ZZ;
       spf=pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u186-20020a8184c3000000b0035c156f657esi232188ywf.3.2022.10.07.19.21.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 19:21:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2D46561DC9;
	Sat,  8 Oct 2022 02:21:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 81D33C433D6;
	Sat,  8 Oct 2022 02:21:37 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 897978b7 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Sat, 8 Oct 2022 02:21:35 +0000 (UTC)
Date: Fri, 7 Oct 2022 20:21:28 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>, Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>,
	Yury Norov <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev, netdev@vger.kernel.org,
	sparclinux@vger.kernel.org, x86@kernel.org, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v4 2/6] treewide: use prandom_u32_max() when possible
Message-ID: <Y0DeqDC3EnA4b6ZB@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-3-Jason@zx2c4.com>
 <202210071241.445289C5@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202210071241.445289C5@keescook>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=LYfvW0ZZ;       spf=pass
 (google.com: domain of srs0=1ou5=2j=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=1Ou5=2J=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Fri, Oct 07, 2022 at 03:47:44PM -0700, Kees Cook wrote:
> On Fri, Oct 07, 2022 at 12:01:03PM -0600, Jason A. Donenfeld wrote:
> > Rather than incurring a division or requesting too many random bytes for
> > the given range, use the prandom_u32_max() function, which only takes
> > the minimum required bytes from the RNG and avoids divisions.
> 
> I actually meant splitting the by-hand stuff by subsystem, but nearly
> all of these can be done mechanically too, so it shouldn't be bad. Notes
> below...

Oh, cool, more coccinelle. You're basically giving me a class on these
recipes. Much appreciated.

> > [...]
> > diff --git a/arch/arm64/kernel/process.c b/arch/arm64/kernel/process.c
> > index 92bcc1768f0b..87203429f802 100644
> > --- a/arch/arm64/kernel/process.c
> > +++ b/arch/arm64/kernel/process.c
> > @@ -595,7 +595,7 @@ unsigned long __get_wchan(struct task_struct *p)
> >  unsigned long arch_align_stack(unsigned long sp)
> >  {
> >  	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
> > -		sp -= get_random_int() & ~PAGE_MASK;
> > +		sp -= prandom_u32_max(PAGE_SIZE);
> >  	return sp & ~0xf;
> >  }
> >  
> 
> @mask@
> expression MASK;
> @@
> 
> - (get_random_int() & ~(MASK))
> + prandom_u32_max(MASK)

Not quite! PAGE_MASK != PAGE_SIZE. In this case, things get a litttttle
more complicated where you can do:

get_random_int() & MASK == prandom_u32_max(MASK + 1)
*only if all the top bits of MASK are set* That is, if MASK one less
than a power of two. Or if MASK & (MASK + 1) == 0.

(If those top bits aren't set, you can technically do
prandom_u32_max(MASK >> n + 1) << n. That'd be a nice thing to work out.
But yeesh, maybe a bit much for the time being and probably a bit beyond
coccinelle.)

This case here, though, is a bit more special, where we can just rely on
an obvious given kernel identity. Namely, PAGE_MASK == ~(PAGE_SIZE - 1).
So ~PAGE_MASK == PAGE_SIZE - 1.
So get_random_int() & ~PAGE_MASK == prandom_u32_max(PAGE_SIZE - 1 + 1).
So get_random_int() & ~PAGE_MASK == prandom_u32_max(PAGE_SIZE).

And most importantly, this makes the code more readable, since everybody
knows what bounding by PAGE_SIZE means, where as what on earth is
happening with the &~PAGE_MASK thing. So it's a good change. I'll try to
teach coccinelle about that special case.



> > diff --git a/arch/loongarch/kernel/vdso.c b/arch/loongarch/kernel/vdso.c
> > index f32c38abd791..8c9826062652 100644
> > --- a/arch/loongarch/kernel/vdso.c
> > +++ b/arch/loongarch/kernel/vdso.c
> > @@ -78,7 +78,7 @@ static unsigned long vdso_base(void)
> >  	unsigned long base = STACK_TOP;
> >  
> >  	if (current->flags & PF_RANDOMIZE) {
> > -		base += get_random_int() & (VDSO_RANDOMIZE_SIZE - 1);
> > +		base += prandom_u32_max(VDSO_RANDOMIZE_SIZE);
> >  		base = PAGE_ALIGN(base);
> >  	}
> >  
> 
> @minus_one@
> expression FULL;
> @@
> 
> - (get_random_int() & ((FULL) - 1)
> + prandom_u32_max(FULL)

Ahh, well, okay, this is the example I mentioned above. Only works if
FULL is saturated. Any clever way to get coccinelle to prove that? Can
it look at the value of constants?

> 
> > diff --git a/arch/parisc/kernel/vdso.c b/arch/parisc/kernel/vdso.c
> > index 63dc44c4c246..47e5960a2f96 100644
> > --- a/arch/parisc/kernel/vdso.c
> > +++ b/arch/parisc/kernel/vdso.c
> > @@ -75,7 +75,7 @@ int arch_setup_additional_pages(struct linux_binprm *bprm,
> >  
> >  	map_base = mm->mmap_base;
> >  	if (current->flags & PF_RANDOMIZE)
> > -		map_base -= (get_random_int() & 0x1f) * PAGE_SIZE;
> > +		map_base -= prandom_u32_max(0x20) * PAGE_SIZE;
> >  
> >  	vdso_text_start = get_unmapped_area(NULL, map_base, vdso_text_len, 0, 0);
> >  
> 
> These are more fun, but Coccinelle can still do them with a little
> Pythonic help:
> 
> // Find a potential literal
> @literal_mask@
> expression LITERAL;
> identifier randfunc =~ "get_random_int|prandom_u32|get_random_u32";
> position p;
> @@
> 
>         (randfunc()@p & (LITERAL))
> 
> // Add one to the literal.
> @script:python add_one@
> literal << literal_mask.LITERAL;
> RESULT;
> @@
> 
> if literal.startswith('0x'):
>         value = int(literal, 16) + 1
>         coccinelle.RESULT = cocci.make_expr("0x%x" % (value))
> elif literal[0] in '123456789':
>         value = int(literal, 10) + 1
>         coccinelle.RESULT = cocci.make_expr("%d" % (value))
> else:
>         print("I don't know how to handle: %s" % (literal))
> 
> // Replace the literal mask with the calculated result.
> @plus_one@
> expression literal_mask.LITERAL;
> position literal_mask.p;
> expression add_one.RESULT;
> identifier FUNC;
> @@
> 
> -       (FUNC()@p & (LITERAL))
> +       prandom_u32_max(RESULT)

Oh that's pretty cool. I can do the saturation check in python, since
`value` holds the parsed result. Neat.

> > diff --git a/fs/ext2/ialloc.c b/fs/ext2/ialloc.c
> > index 998dd2ac8008..f4944c4dee60 100644
> > --- a/fs/ext2/ialloc.c
> > +++ b/fs/ext2/ialloc.c
> > @@ -277,8 +277,7 @@ static int find_group_orlov(struct super_block *sb, struct inode *parent)
> >  		int best_ndir = inodes_per_group;
> >  		int best_group = -1;
> >  
> > -		group = prandom_u32();
> > -		parent_group = (unsigned)group % ngroups;
> > +		parent_group = prandom_u32_max(ngroups);
> >  		for (i = 0; i < ngroups; i++) {
> >  			group = (parent_group + i) % ngroups;
> >  			desc = ext2_get_group_desc (sb, group, NULL);
> 
> Okay, that one is too much for me -- checking that group is never used
> after the assignment removal is likely possible, but beyond my cocci
> know-how. :)

Yea this is a tricky one, which I initially didn't do by hand, but Jan
seemed fine with it, and it's clear if you look at it. Trixy cocci
indeed.

> > diff --git a/lib/test_hexdump.c b/lib/test_hexdump.c
> > index 0927f44cd478..41a0321f641a 100644
> > --- a/lib/test_hexdump.c
> > +++ b/lib/test_hexdump.c
> > @@ -208,7 +208,7 @@ static void __init test_hexdump_overflow(size_t buflen, size_t len,
> >  static void __init test_hexdump_overflow_set(size_t buflen, bool ascii)
> >  {
> >  	unsigned int i = 0;
> > -	int rs = (prandom_u32_max(2) + 1) * 16;
> > +	int rs = prandom_u32_max(2) + 1 * 16;
> >  
> >  	do {
> >  		int gs = 1 << i;
> 
> This looks wrong. Cocci says:
> 
> -       int rs = (get_random_int() % 2 + 1) * 16;
> +       int rs = (prandom_u32_max(2) + 1) * 16;

!! Nice catch.

Alright, I'll give this a try with more cocci. The big difficulty at the
moment is the power of 2 constant checking thing. If you have any
pointers on that, would be nice.

Thanks a bunch for the guidance.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0DeqDC3EnA4b6ZB%40zx2c4.com.
