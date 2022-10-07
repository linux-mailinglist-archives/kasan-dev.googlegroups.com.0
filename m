Return-Path: <kasan-dev+bncBCF5XGNWYQBRBE6ZQKNAMGQEZKRSP4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id CA2435F80E8
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 00:47:48 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-3562f0fb5a7sf57542707b3.1
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 15:47:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665182867; cv=pass;
        d=google.com; s=arc-20160816;
        b=rF/tZlDuiVLaSKpATojezvVqypM6vwbM8Z48PtMIbuHxgx2hex/BD0GmF8UubgA9OF
         zGPgdroFVqxpwBEr6XlwpSWgXPM3XvHTprq5vWNF8ERSWhHvLyaKsPdlzLaBqZI8cuJd
         1q380WOYqwNw3aVofcxaRTrgs1szHDZ+xmJ/eM3h8hoWWg/PkFbODHjRDteJUooJtggK
         yatbnkGW/Gh+1zmNkbPZ5J8iMJByZ/8G3DuBxIFb0lWmUMHTIppjbfkRVi9M9kgrYi/B
         Usa23F6I/R/XlDA4x/SYTw6LnA4DeqHcAmkUL7XWBVGDUTf1Nq/qAPyIEkvSz5O6dz0w
         Do3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/T7ubdGiagNttr1ECkAzohveZ6JrjuB89s7LOjc9UKc=;
        b=mq35+3VV9tSLYXaoNmVLmBcIQYOXA9vUreM05f83Hz5NdG+5VIUb89NZFbrghXbN+g
         Jl1JX+W68oFsBy4T0qj9RXZswkRgQgcWqXczxpYi8kynISTEG0DtyswYCjtTaAC7G4uO
         5hoSoF2ypIabTms3z/PVro5y/a6GS5Wi2C2n2UdOp76KZ2kGbZ0oE5Hpy5UKPHh7u/5Y
         jFUnr3NokiN3jW0mnvxKOjhIlW2KxDmyVliLohrN9QmXAf4QR+2KvFGKKbYvCUFXzWhq
         YKWaes465nkVYmNVDwVD5gQqb3J6IDeIG6TFCrfRMAJq5hvbVXeuZIJYmEwtcaBSWg3t
         y2lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iXQ9Uvdz;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/T7ubdGiagNttr1ECkAzohveZ6JrjuB89s7LOjc9UKc=;
        b=exc0lz5pgyt0iOdOXuj3A8cTx0T636awk30IkuM0H4QOvykQnE0YeJdDUZ8GT0gXwZ
         1wzZyES26cIbPSPfrEKWrIYNAYRXOL+wozXpQ/Mg9k/RjrDfR6JYF44QuTq0b/a+TcDi
         kAPaq4N+cK4GltQgQncLRSo/mNCjB5YP/7pOfX4xUA/mwVaM8sTwXTkrTtNkyggJyzJF
         56MzhKmyERUp30fvb8ySdr+NNVK9FoyzQlTgvVqN1FBtJQ1gNSYKxWpfJUnUkqh8dm5F
         q4UMihmGDni2Ddnbqwcvarq4vD8pCZ9oJHZKxGZd9Dh16kmSs1gPmxeRC/JVrqZ0N3Kf
         E93Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/T7ubdGiagNttr1ECkAzohveZ6JrjuB89s7LOjc9UKc=;
        b=HDwhSY15H0gHak9qemlK7DpTYJs7vwaWqrMvHGEj2U4y5dHOYLc78AAfmXmmEbZjqg
         bECL7P1YkOAb/h4Z+zUmCyqAvauEl5FsGzWlvjphvM/n/BaJ3xKu5RFaM8ubPP2GY43z
         I0CNYMw3Gd+/1Vid2g4PMmYLABfz2w6t8eAHBz1vT/+YZzCIitJMgNXZVcNicdHcvbpm
         FpxIu28/pOIaMlF7NMOBtA0xt7+WnTE/v8gLe/nEDgG5lnV+NpLgT+osC7KBQ/lLKtyU
         n4EbWKS9cEkSUMG8MAgPZ1NV0AZtu83sadYMhx7RBre/Kagh0o8WHHnKTycdgNpoaXrq
         yZuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3LzkrIKg5+NRuHLBHAB/NearbTpswl+5ICfqp7r2RBSXnxh0s0
	MZnT2PxNMLtaKK7xgfULLFA=
X-Google-Smtp-Source: AMsMyM5MJ+ax3eorSUkSD+5rds3XfMHkhkDGq6wmibX1kmup+deFPB73iH5SVcsOJpqHnmDC99ltzw==
X-Received: by 2002:a25:6f83:0:b0:6be:37fe:4d91 with SMTP id k125-20020a256f83000000b006be37fe4d91mr6470694ybc.562.1665182867599;
        Fri, 07 Oct 2022 15:47:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:690:b0:348:81c3:82e0 with SMTP id
 bp16-20020a05690c069000b0034881c382e0ls2612774ywb.7.-pod-prod-gmail; Fri, 07
 Oct 2022 15:47:47 -0700 (PDT)
X-Received: by 2002:a81:a0cf:0:b0:356:644a:15a5 with SMTP id x198-20020a81a0cf000000b00356644a15a5mr6768839ywg.500.1665182866907;
        Fri, 07 Oct 2022 15:47:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665182866; cv=none;
        d=google.com; s=arc-20160816;
        b=QTxSMq2wkH3Wfvi4KFfBVmjgIvcqAC3i9hiXSQs3fja18OAIrW+xwxfRKtLNThMvXY
         dQPBtILGDnesh9esMJGM82bsjD30bKeYCPpUj2hYxGttKuLKcN8a5XP2uZFjzIKgafnx
         AaLXZnBYoOxx6lEVQ3UeUUH64RvNLibVJxT97YEHM+RbNtNIlw5rZIcYsrzQScVwTx7c
         qjUGDsbzrp+lj5yJXSzXQcjxDoj65g3Xv+Mx3qLjFLwWE+CgfDry70xMgFB2dOy51oqr
         x6TIH8xC1wy2OVm0lnHw2muRDOjuHX1rIYMv8F6ZN53/QB2YuuJahj78vI62P93iEr+v
         bqXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yZqaicka3IU4vV1MYdOWb5w3mOcfwDVNwAUulPcr27Y=;
        b=FxgcvxD6cXOhfE+vUCpDb+jNVH9oII5X3ovmxYumemBsjdllyChxHBrnAJNLlS3rMP
         jUWd7d/5Yz1ThdCU5rC9yuy6fR6Uh2cXakEVRk+N97OK2yUilXxyuRCPTTaK8dCFU+kS
         ykbc+kutfZuP5VPc5TXYWxvpT7eTnaF52HUK7dxrE4O0/xXgHxV/dsI95ZCsumKO/1p3
         DipRfEc2YhMQ0PZsJgMEQH0LDjNRqqgCM41sMMpVJP9eETOM9OY+/xfSBtVgjeyMKrUz
         4cAW3+uXEiL/OqE7tzHOQ9/GMDeivisbGhT3wiZ8kCntvypVHCHU7ZOcV4hxJjH091Pd
         7pcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iXQ9Uvdz;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id t10-20020a81b50a000000b0035786664d22si230535ywh.1.2022.10.07.15.47.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Oct 2022 15:47:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id b5so5822207pgb.6
        for <kasan-dev@googlegroups.com>; Fri, 07 Oct 2022 15:47:46 -0700 (PDT)
X-Received: by 2002:a63:5a61:0:b0:41b:b021:f916 with SMTP id k33-20020a635a61000000b0041bb021f916mr6209429pgm.387.1665182866043;
        Fri, 07 Oct 2022 15:47:46 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id z12-20020a1709027e8c00b0016dbaf3ff2esm2038893pla.22.2022.10.07.15.47.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 15:47:45 -0700 (PDT)
Date: Fri, 7 Oct 2022 15:47:44 -0700
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
Message-ID: <202210071241.445289C5@keescook>
References: <20221007180107.216067-1-Jason@zx2c4.com>
 <20221007180107.216067-3-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221007180107.216067-3-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=iXQ9Uvdz;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e
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

On Fri, Oct 07, 2022 at 12:01:03PM -0600, Jason A. Donenfeld wrote:
> Rather than incurring a division or requesting too many random bytes for
> the given range, use the prandom_u32_max() function, which only takes
> the minimum required bytes from the RNG and avoids divisions.

I actually meant splitting the by-hand stuff by subsystem, but nearly
all of these can be done mechanically too, so it shouldn't be bad. Notes
below...

> 
> [...]
> diff --git a/arch/arm64/kernel/process.c b/arch/arm64/kernel/process.c
> index 92bcc1768f0b..87203429f802 100644
> --- a/arch/arm64/kernel/process.c
> +++ b/arch/arm64/kernel/process.c
> @@ -595,7 +595,7 @@ unsigned long __get_wchan(struct task_struct *p)
>  unsigned long arch_align_stack(unsigned long sp)
>  {
>  	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
> -		sp -= get_random_int() & ~PAGE_MASK;
> +		sp -= prandom_u32_max(PAGE_SIZE);
>  	return sp & ~0xf;
>  }
>  

@mask@
expression MASK;
@@

- (get_random_int() & ~(MASK))
+ prandom_u32_max(MASK)

> diff --git a/arch/loongarch/kernel/vdso.c b/arch/loongarch/kernel/vdso.c
> index f32c38abd791..8c9826062652 100644
> --- a/arch/loongarch/kernel/vdso.c
> +++ b/arch/loongarch/kernel/vdso.c
> @@ -78,7 +78,7 @@ static unsigned long vdso_base(void)
>  	unsigned long base = STACK_TOP;
>  
>  	if (current->flags & PF_RANDOMIZE) {
> -		base += get_random_int() & (VDSO_RANDOMIZE_SIZE - 1);
> +		base += prandom_u32_max(VDSO_RANDOMIZE_SIZE);
>  		base = PAGE_ALIGN(base);
>  	}
>  

@minus_one@
expression FULL;
@@

- (get_random_int() & ((FULL) - 1)
+ prandom_u32_max(FULL)

> diff --git a/arch/parisc/kernel/vdso.c b/arch/parisc/kernel/vdso.c
> index 63dc44c4c246..47e5960a2f96 100644
> --- a/arch/parisc/kernel/vdso.c
> +++ b/arch/parisc/kernel/vdso.c
> @@ -75,7 +75,7 @@ int arch_setup_additional_pages(struct linux_binprm *bprm,
>  
>  	map_base = mm->mmap_base;
>  	if (current->flags & PF_RANDOMIZE)
> -		map_base -= (get_random_int() & 0x1f) * PAGE_SIZE;
> +		map_base -= prandom_u32_max(0x20) * PAGE_SIZE;
>  
>  	vdso_text_start = get_unmapped_area(NULL, map_base, vdso_text_len, 0, 0);
>  

These are more fun, but Coccinelle can still do them with a little
Pythonic help:

// Find a potential literal
@literal_mask@
expression LITERAL;
identifier randfunc =~ "get_random_int|prandom_u32|get_random_u32";
position p;
@@

        (randfunc()@p & (LITERAL))

// Add one to the literal.
@script:python add_one@
literal << literal_mask.LITERAL;
RESULT;
@@

if literal.startswith('0x'):
        value = int(literal, 16) + 1
        coccinelle.RESULT = cocci.make_expr("0x%x" % (value))
elif literal[0] in '123456789':
        value = int(literal, 10) + 1
        coccinelle.RESULT = cocci.make_expr("%d" % (value))
else:
        print("I don't know how to handle: %s" % (literal))

// Replace the literal mask with the calculated result.
@plus_one@
expression literal_mask.LITERAL;
position literal_mask.p;
expression add_one.RESULT;
identifier FUNC;
@@

-       (FUNC()@p & (LITERAL))
+       prandom_u32_max(RESULT)

> diff --git a/drivers/mtd/tests/stresstest.c b/drivers/mtd/tests/stresstest.c
> index cb29c8c1b370..d2faaca7f19d 100644
> --- a/drivers/mtd/tests/stresstest.c
> +++ b/drivers/mtd/tests/stresstest.c
> @@ -45,9 +45,8 @@ static int rand_eb(void)
>  	unsigned int eb;
>  
>  again:
> -	eb = prandom_u32();
>  	/* Read or write up 2 eraseblocks at a time - hence 'ebcnt - 1' */
> -	eb %= (ebcnt - 1);
> +	eb = prandom_u32_max(ebcnt - 1);
>  	if (bbt[eb])
>  		goto again;
>  	return eb;

This can also be done mechanically:

@multi_line@
identifier randfunc =~ "get_random_int|prandom_u32|get_random_u32";
identifier RAND;
expression E;
@@

-       RAND = randfunc();
        ... when != RAND
-       RAND %= (E);
+       RAND = prandom_u32_max(E);

@collapse_ret@
type TYPE;
identifier VAR;
expression E;
@@

 {
-       TYPE VAR;
-       VAR = (E);
-       return VAR;
+       return E;
 }

@drop_var@
type TYPE;
identifier VAR;
@@

 {
-       TYPE VAR;
        ... when != VAR
 }

> diff --git a/fs/ext2/ialloc.c b/fs/ext2/ialloc.c
> index 998dd2ac8008..f4944c4dee60 100644
> --- a/fs/ext2/ialloc.c
> +++ b/fs/ext2/ialloc.c
> @@ -277,8 +277,7 @@ static int find_group_orlov(struct super_block *sb, struct inode *parent)
>  		int best_ndir = inodes_per_group;
>  		int best_group = -1;
>  
> -		group = prandom_u32();
> -		parent_group = (unsigned)group % ngroups;
> +		parent_group = prandom_u32_max(ngroups);
>  		for (i = 0; i < ngroups; i++) {
>  			group = (parent_group + i) % ngroups;
>  			desc = ext2_get_group_desc (sb, group, NULL);

Okay, that one is too much for me -- checking that group is never used
after the assignment removal is likely possible, but beyond my cocci
know-how. :)

> diff --git a/fs/ext4/ialloc.c b/fs/ext4/ialloc.c
> index f73e5eb43eae..36d5bc595cc2 100644
> --- a/fs/ext4/ialloc.c
> +++ b/fs/ext4/ialloc.c
> @@ -463,10 +463,9 @@ static int find_group_orlov(struct super_block *sb, struct inode *parent,
>  			hinfo.hash_version = DX_HASH_HALF_MD4;
>  			hinfo.seed = sbi->s_hash_seed;
>  			ext4fs_dirhash(parent, qstr->name, qstr->len, &hinfo);
> -			grp = hinfo.hash;
> +			parent_group = hinfo.hash % ngroups;
>  		} else
> -			grp = prandom_u32();
> -		parent_group = (unsigned)grp % ngroups;
> +			parent_group = prandom_u32_max(ngroups);
>  		for (i = 0; i < ngroups; i++) {
>  			g = (parent_group + i) % ngroups;
>  			get_orlov_stats(sb, g, flex_size, &stats);

Much less easy mechanically. :)

> diff --git a/lib/test_hexdump.c b/lib/test_hexdump.c
> index 0927f44cd478..41a0321f641a 100644
> --- a/lib/test_hexdump.c
> +++ b/lib/test_hexdump.c
> @@ -208,7 +208,7 @@ static void __init test_hexdump_overflow(size_t buflen, size_t len,
>  static void __init test_hexdump_overflow_set(size_t buflen, bool ascii)
>  {
>  	unsigned int i = 0;
> -	int rs = (prandom_u32_max(2) + 1) * 16;
> +	int rs = prandom_u32_max(2) + 1 * 16;
>  
>  	do {
>  		int gs = 1 << i;

This looks wrong. Cocci says:

-       int rs = (get_random_int() % 2 + 1) * 16;
+       int rs = (prandom_u32_max(2) + 1) * 16;

> diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
> index 4f2f2d1bac56..56ffaa8dd3f6 100644
> --- a/lib/test_vmalloc.c
> +++ b/lib/test_vmalloc.c
> @@ -151,9 +151,7 @@ static int random_size_alloc_test(void)
>  	int i;
>  
>  	for (i = 0; i < test_loop_count; i++) {
> -		n = prandom_u32();
> -		n = (n % 100) + 1;
> -
> +		n = prandom_u32_max(n % 100) + 1;
>  		p = vmalloc(n * PAGE_SIZE);
>  
>  		if (!p)

This looks wrong. Cocci says:

-               n = prandom_u32();
-               n = (n % 100) + 1;
+               n = prandom_u32_max(100) + 1;

> @@ -293,16 +291,12 @@ pcpu_alloc_test(void)
>  		return -1;
>  
>  	for (i = 0; i < 35000; i++) {
> -		unsigned int r;
> -
> -		r = prandom_u32();
> -		size = (r % (PAGE_SIZE / 4)) + 1;
> +		size = prandom_u32_max(PAGE_SIZE / 4) + 1;
>  
>  		/*
>  		 * Maximum PAGE_SIZE
>  		 */
> -		r = prandom_u32();
> -		align = 1 << ((r % 11) + 1);
> +		align = 1 << (prandom_u32_max(11) + 1);
>  
>  		pcpu[i] = __alloc_percpu(size, align);
>  		if (!pcpu[i])
> @@ -393,14 +387,11 @@ static struct test_driver {
>  
>  static void shuffle_array(int *arr, int n)
>  {
> -	unsigned int rnd;
>  	int i, j;
>  
>  	for (i = n - 1; i > 0; i--)  {
> -		rnd = prandom_u32();
> -
>  		/* Cut the range. */
> -		j = rnd % i;
> +		j = prandom_u32_max(i);
>  
>  		/* Swap indexes. */
>  		swap(arr[i], arr[j]);

Yup, agrees with Cocci on these.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210071241.445289C5%40keescook.
