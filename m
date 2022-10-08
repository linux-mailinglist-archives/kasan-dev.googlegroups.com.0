Return-Path: <kasan-dev+bncBCF5XGNWYQBRBFXHQONAMGQEKIVUYCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D8FBC5F82D5
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 05:50:47 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id d6-20020a056e02214600b002fa23a188ebsf5132973ilv.6
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 20:50:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665201046; cv=pass;
        d=google.com; s=arc-20160816;
        b=oYhMu4vu5Ih6+VpAEHRnA1C4Ew1b6+TkAugQ6OnbDsRWW4jWAkeXKTrm7UMS0DGfev
         ToQrqf0yEG+xDHEJZ3JvW4VMYJlSoMSQyWEwnzQWFI+r/BGqW2lFzyPdngQgdYLyQ3qn
         8vcvGCXDDnkj/tkh3X543lPKDn+8Tf6hDn0rOAwTa3uj7ZEqGNiNxiBlD4IjgEgGL0Uu
         dPHaDmc4bIJd0FzKEitcm0SKE+Ua0IfEnxPOJQ7kLYIXBIPAOxRl6LfVHyQMz5zg6UJd
         u9Oa9L1csQWBJmTq07zn+1DwS0/N6LlskPkAsmJAwki11rikyAysdBAXe9IZQcacZd80
         fK/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DacP6szeUWAPxQOOY0/S9syJnAuM4Z+okbwjSB/JfWA=;
        b=TLpxkz8sqjyRC/2ATaQm8k+Iit48SOfYgKRZjNue8Rxmk+RRwnPCy3niI4+Y4+3N+M
         IG11OOyQZAnKEFHzUTkLQILQD2BahnRjnLRqcy9tQoGgJC5iC9Pzftu+aU6G90U/QDcz
         A7xSEdd3FCcU9MnfuJlFh5Amg3nNDF+JqmmHjHDFQ1FM3NT89/1T9pfcHdIqM4OPxoPl
         fhSBWrKi6TsjLnHZuG3RRGzFFmAp4rTWSK1f6o867Q7C5LNMrYf2uOouH0R5DUHsE7F5
         lpjWWZPaAtKaxgnKZjGLXilwR1d13OMSQjYcKZcbdM4zEMKfw0cUp/m6oLvG3DvcbCnu
         PDmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FTiUCKip;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DacP6szeUWAPxQOOY0/S9syJnAuM4Z+okbwjSB/JfWA=;
        b=dI8EWrUzNjRID+mnghsh2z5gbM+tcA+AXlPJVly53xnSFPWDGOVHFBxoey9M7Gdntv
         gD59FafTlOv6/iZdbzgAXocRieNyJ0ja0CuFPvYjvKWp5QztaAlvgyzm9LVf8p7wjDtY
         5FLiF7x7GywZ70wpunZYRFSLuOycV7LZyWI8FPlQcbggLAkipawXyD/cbUGJ8m+vIZtT
         +1ry3n2fPDELB0UJq5pGDZyEzIL1I4wJYdV18M9BNugXAoY4NIIFpkZTDB+1JaH8rcNt
         umcroBipHL+cuF1pyfl73YDtsW6cMN+DrQ1+trcnsf39+EfMRuKXK38eNKmgaPV2zP1u
         FP9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DacP6szeUWAPxQOOY0/S9syJnAuM4Z+okbwjSB/JfWA=;
        b=dWDiFJGFKSM6SQKxiylLMGPnWaUzGVupoVuyqaiJadELIBu00NNkmAWneiA37tb4sR
         CYrWFsZ8fnaFQnRQ/cjamnXIh4gFqlFPadwIkISqaHItxqA9l+FHGBoHjza/i7NRRSp5
         XBJ6rVt+38bU1mPuEAssNWUrvdflKAOx4HCf1Gja1108x3EqX8R1+euydTYllf3LzCoe
         Arn2aGjDGMuKCAdc50wa6nESxTCPYalUndh+ep29qkybZnRZ8PiLTtZFGYTAkRIV2FmD
         6hMXiRFxqXQCC2i1IXasYCzrFxSzoISbO2tz3GLzBUPtys/wFmEBPRNmMDDh919CsqBA
         uOWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2ZrTCzbllGV/d2eBtab+Y8fUatFzg0c+qc/FYFITSLOLyxZ1gr
	s96c4vSH1ZO3+fzjD/fAz88=
X-Google-Smtp-Source: AMsMyM4i6HGv/EUBkN/mco4q9now9czuxU3kcUryG6LWweI7vPNP1WJEaGbF08yj1VHbmn0Cgpv0nA==
X-Received: by 2002:a92:cd03:0:b0:2f9:463e:279d with SMTP id z3-20020a92cd03000000b002f9463e279dmr3875308iln.223.1665201046797;
        Fri, 07 Oct 2022 20:50:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:94a4:0:b0:363:a0db:5dfc with SMTP id x33-20020a0294a4000000b00363a0db5dfcls321563jah.10.-pod-prod-gmail;
 Fri, 07 Oct 2022 20:50:46 -0700 (PDT)
X-Received: by 2002:a02:1d47:0:b0:363:373b:58ca with SMTP id 68-20020a021d47000000b00363373b58camr4241226jaj.155.1665201046345;
        Fri, 07 Oct 2022 20:50:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665201046; cv=none;
        d=google.com; s=arc-20160816;
        b=RuqnzDRrfIgghrNgzzccpWmjLZqYU108YEcI4mgpwiShQOzMZaeHLzAPim3+5RxUSi
         k/0Zia7RsKH+UR2Hy26mlCU/VFnVXStBqk387cAeH5gbHzcLvAThKWHb1fylvnUPy5nA
         dC1mRIx/4WJUpOQZKSiu42DAM2nnZAyFP5AckTOc0ebBYnXmKlEygLpc6JVC9JFslpU2
         tnNpONbOWjTa5rPSasDe0dbXdZlG3sPTPQvOalWsStxEH6rrtW+qk4UyoDaBbbJ8WYP/
         zmOcx1D5YS3PJN8Y93RmPOPRvPQS9qpn6uHNGv+crrO0Occy4z+bXir9NiT+TrVxagxd
         pINw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=/+M2MWnKezzvwUdnzvMnzBe5u7rJCxF/Jt+qZLDkYO0=;
        b=zT26vWafAFjachsYQMVNgSY8Oin81aiFqWopfQz5CxKswV0IAFcYn4bLXe70ADBfyx
         jzSjQp+/ZaH668xuPygpvMDIfbSkbZSRNjItJDakpd2aVOSwDY41sKpAe0i4s16HjmTX
         /OKtowC9zuBVcJf9AhRcAl5+pFcZtB4UhwWkoljwtR2jkjwctY7IlhX5S548F1Vlf6Dt
         80nxw7bmOYhxjozSw17q8Ky/W7/mLbgJRwc1KcW1mvrrBqCD2ihKTrSfoKGIyZz4vlc6
         +eM6L99UwyCweVWWcFvILpROc45wYL3a+3jfSkLC0ue0YZD2ny7kfs1UFvgSEGKaBOdZ
         swaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FTiUCKip;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id m10-20020a92870a000000b002f93f7596c4si124870ild.4.2022.10.07.20.50.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Oct 2022 20:50:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id c7so6169281pgt.11
        for <kasan-dev@googlegroups.com>; Fri, 07 Oct 2022 20:50:46 -0700 (PDT)
X-Received: by 2002:a63:f806:0:b0:439:d86e:1f6e with SMTP id n6-20020a63f806000000b00439d86e1f6emr7461413pgh.46.1665201045645;
        Fri, 07 Oct 2022 20:50:45 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id w2-20020a1709026f0200b0017f5ba1fffasm2217544plk.297.2022.10.07.20.50.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 20:50:44 -0700 (PDT)
Date: Fri, 7 Oct 2022 20:50:43 -0700
From: Kees Cook <keescook@chromium.org>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph =?iso-8859-1?Q?B=F6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>,
	"James E. J. Bottomley" <jejb@linux.ibm.com>,
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
Message-ID: <53DD0148-ED15-4294-8496-9E4B4C7AD061@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=FTiUCKip;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::530
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

[resending because I failed to CC]

On October 7, 2022 7:21:28 PM PDT, "Jason A. Donenfeld" <Jason@zx2c4.com> wrote:
>On Fri, Oct 07, 2022 at 03:47:44PM -0700, Kees Cook wrote:
>> On Fri, Oct 07, 2022 at 12:01:03PM -0600, Jason A. Donenfeld wrote:
>> > Rather than incurring a division or requesting too many random bytes for
>> > the given range, use the prandom_u32_max() function, which only takes
>> > the minimum required bytes from the RNG and avoids divisions.
>> 
>> I actually meant splitting the by-hand stuff by subsystem, but nearly
>> all of these can be done mechanically too, so it shouldn't be bad. Notes
>> below...
>
>Oh, cool, more coccinelle. You're basically giving me a class on these
>recipes. Much appreciated.

You're welcome! This was a fun exercise. :)

>
>> > [...]
>> > diff --git a/arch/arm64/kernel/process.c b/arch/arm64/kernel/process.c
>> > index 92bcc1768f0b..87203429f802 100644
>> > --- a/arch/arm64/kernel/process.c
>> > +++ b/arch/arm64/kernel/process.c
>> > @@ -595,7 +595,7 @@ unsigned long __get_wchan(struct task_struct *p)
>> >  unsigned long arch_align_stack(unsigned long sp)
>> >  {
>> >  	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
>> > -		sp -= get_random_int() & ~PAGE_MASK;
>> > +		sp -= prandom_u32_max(PAGE_SIZE);
>> >  	return sp & ~0xf;
>> >  }
>> >  
>> 
>> @mask@
>> expression MASK;
>> @@
>> 
>> - (get_random_int() & ~(MASK))
>> + prandom_u32_max(MASK)
>
>Not quite! PAGE_MASK != PAGE_SIZE. In this case, things get a litttttle
>more complicated where you can do:
>
>get_random_int() & MASK == prandom_u32_max(MASK + 1)
>*only if all the top bits of MASK are set* That is, if MASK one less

Oh whoops! Yes, right, I totally misread SIZE as MASK.

>than a power of two. Or if MASK & (MASK + 1) == 0.
>
>(If those top bits aren't set, you can technically do
>prandom_u32_max(MASK >> n + 1) << n. That'd be a nice thing to work out.
>But yeesh, maybe a bit much for the time being and probably a bit beyond
>coccinelle.)
>
>This case here, though, is a bit more special, where we can just rely on
>an obvious given kernel identity. Namely, PAGE_MASK == ~(PAGE_SIZE - 1).
>So ~PAGE_MASK == PAGE_SIZE - 1.
>So get_random_int() & ~PAGE_MASK == prandom_u32_max(PAGE_SIZE - 1 + 1).
>So get_random_int() & ~PAGE_MASK == prandom_u32_max(PAGE_SIZE).
>
>And most importantly, this makes the code more readable, since everybody
>knows what bounding by PAGE_SIZE means, where as what on earth is
>happening with the &~PAGE_MASK thing. So it's a good change. I'll try to
>teach coccinelle about that special case.

Yeah, it should be possible to just check for the literal.

>
>
>
>> > diff --git a/arch/loongarch/kernel/vdso.c b/arch/loongarch/kernel/vdso.c
>> > index f32c38abd791..8c9826062652 100644
>> > --- a/arch/loongarch/kernel/vdso.c
>> > +++ b/arch/loongarch/kernel/vdso.c
>> > @@ -78,7 +78,7 @@ static unsigned long vdso_base(void)
>> >  	unsigned long base = STACK_TOP;
>> >  
>> >  	if (current->flags & PF_RANDOMIZE) {
>> > -		base += get_random_int() & (VDSO_RANDOMIZE_SIZE - 1);
>> > +		base += prandom_u32_max(VDSO_RANDOMIZE_SIZE);
>> >  		base = PAGE_ALIGN(base);
>> >  	}
>> >  
>> 
>> @minus_one@
>> expression FULL;
>> @@
>> 
>> - (get_random_int() & ((FULL) - 1)
>> + prandom_u32_max(FULL)
>
>Ahh, well, okay, this is the example I mentioned above. Only works if
>FULL is saturated. Any clever way to get coccinelle to prove that? Can
>it look at the value of constants?

I'm not sure if Cocci will do that without a lot of work. The literals trick I used below would need a lot of fanciness. :)

>
>> 
>> > diff --git a/arch/parisc/kernel/vdso.c b/arch/parisc/kernel/vdso.c
>> > index 63dc44c4c246..47e5960a2f96 100644
>> > --- a/arch/parisc/kernel/vdso.c
>> > +++ b/arch/parisc/kernel/vdso.c
>> > @@ -75,7 +75,7 @@ int arch_setup_additional_pages(struct linux_binprm *bprm,
>> >  
>> >  	map_base = mm->mmap_base;
>> >  	if (current->flags & PF_RANDOMIZE)
>> > -		map_base -= (get_random_int() & 0x1f) * PAGE_SIZE;
>> > +		map_base -= prandom_u32_max(0x20) * PAGE_SIZE;
>> >  
>> >  	vdso_text_start = get_unmapped_area(NULL, map_base, vdso_text_len, 0, 0);
>> >  
>> 
>> These are more fun, but Coccinelle can still do them with a little
>> Pythonic help:
>> 
>> // Find a potential literal
>> @literal_mask@
>> expression LITERAL;
>> identifier randfunc =~ "get_random_int|prandom_u32|get_random_u32";
>> position p;
>> @@
>> 
>>         (randfunc()@p & (LITERAL))
>> 
>> // Add one to the literal.
>> @script:python add_one@
>> literal << literal_mask.LITERAL;
>> RESULT;
>> @@
>> 
>> if literal.startswith('0x'):
>>         value = int(literal, 16) + 1
>>         coccinelle.RESULT = cocci.make_expr("0x%x" % (value))
>> elif literal[0] in '123456789':
>>         value = int(literal, 10) + 1
>>         coccinelle.RESULT = cocci.make_expr("%d" % (value))
>> else:
>>         print("I don't know how to handle: %s" % (literal))
>> 
>> // Replace the literal mask with the calculated result.
>> @plus_one@
>> expression literal_mask.LITERAL;
>> position literal_mask.p;
>> expression add_one.RESULT;
>> identifier FUNC;
>> @@
>> 
>> -       (FUNC()@p & (LITERAL))
>> +       prandom_u32_max(RESULT)
>
>Oh that's pretty cool. I can do the saturation check in python, since
>`value` holds the parsed result. Neat.

It is (at least how I have it here) just the string, so YMMV.

>
>> > diff --git a/fs/ext2/ialloc.c b/fs/ext2/ialloc.c
>> > index 998dd2ac8008..f4944c4dee60 100644
>> > --- a/fs/ext2/ialloc.c
>> > +++ b/fs/ext2/ialloc.c
>> > @@ -277,8 +277,7 @@ static int find_group_orlov(struct super_block *sb, struct inode *parent)
>> >  		int best_ndir = inodes_per_group;
>> >  		int best_group = -1;
>> >  
>> > -		group = prandom_u32();
>> > -		parent_group = (unsigned)group % ngroups;
>> > +		parent_group = prandom_u32_max(ngroups);
>> >  		for (i = 0; i < ngroups; i++) {
>> >  			group = (parent_group + i) % ngroups;
>> >  			desc = ext2_get_group_desc (sb, group, NULL);
>> 
>> Okay, that one is too much for me -- checking that group is never used
>> after the assignment removal is likely possible, but beyond my cocci
>> know-how. :)
>
>Yea this is a tricky one, which I initially didn't do by hand, but Jan
>seemed fine with it, and it's clear if you look at it. Trixy cocci
>indeed.

I asked on the Cocci list[1], since by the time I got to the end of your "by hand" patch I *really* wanted to have it work. I was so close!


>
>> > diff --git a/lib/test_hexdump.c b/lib/test_hexdump.c
>> > index 0927f44cd478..41a0321f641a 100644
>> > --- a/lib/test_hexdump.c
>> > +++ b/lib/test_hexdump.c
>> > @@ -208,7 +208,7 @@ static void __init test_hexdump_overflow(size_t buflen, size_t len,
>> >  static void __init test_hexdump_overflow_set(size_t buflen, bool ascii)
>> >  {
>> >  	unsigned int i = 0;
>> > -	int rs = (prandom_u32_max(2) + 1) * 16;
>> > +	int rs = prandom_u32_max(2) + 1 * 16;
>> >  
>> >  	do {
>> >  		int gs = 1 << i;
>> 
>> This looks wrong. Cocci says:
>> 
>> -       int rs = (get_random_int() % 2 + 1) * 16;
>> +       int rs = (prandom_u32_max(2) + 1) * 16;
>
>!! Nice catch.
>
>Alright, I'll give this a try with more cocci. The big difficulty at the
>moment is the power of 2 constant checking thing. If you have any
>pointers on that, would be nice.
>
>Thanks a bunch for the guidance.

Sure thing! I was pleased to figure out how to do the python bit.

-Kees

[1] actually, I don't see it on lore... I will resend it

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/53DD0148-ED15-4294-8496-9E4B4C7AD061%40chromium.org.
