Return-Path: <kasan-dev+bncBAABBB65SSKAMGQEYNFJ5LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C38D52C0FE
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:36:09 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id o8-20020acad708000000b00322487ea641sf1296342oig.7
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:36:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652895368; cv=pass;
        d=google.com; s=arc-20160816;
        b=NhrZVUmu63m8XbjM/Jgrduc4K4tFiliX1892nGOSFJLXzzbLIN0g6NbbVhcy1lJWiR
         AbVC1+r9pzx7XMD3xFQzWlMiZbrBU7bBlsYTrjWZmLyT5ps6kyIoCBFYw8kOOmtUfxy4
         D7LNaf39Ka9Q06MQAnTtKYmmaQAtaUQPUV3sK4Ly+8BuTcPv3Vm49WN1Ah1rdmAHvKHT
         UpOOM/ya6BneoeN3xSlEwzQMXX0kdnrZkn0efZeQfl64e+f7763Pg3jsnG2rTMTwPeKA
         x5SF1qfb0kuEIHmB+lwD3I+umr9i/ULj6VPckrTcX7hgkaXgYIslR3qR4sYo75D0UrEH
         1llw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BYSawePUPsm2cyp/UqmcDJwhrj1UYquKX/xET9AQFiI=;
        b=fpVyHFpgscJes5xfowa0dekp2AutOwIUoq6p5dI8Gmr0jeguq9UGZQQmh0lsAI/Reo
         LLyA5CHOvHXh+VYtoDX4YCODho2rlIOqior4EByWkBS6mPMHsZXzjsZlSkNlPHxAjkPj
         Tj6wyvjRGK6PDPZwPs82G5C5fhn5xnwxkmlLvE8LB9wQufzyEHdR0eP8r6OD0/WDNJrs
         WPnTgxhq9nKzJ6VSlQEyAWTXrEKHtTfS1+azTX27q9CVbf5bgBmziPK75PlHvNmET0o9
         CabxVVfUJUTvjGA4+ChDZI22gTwR0/v2i8MOpYitPsjPAR1Vc4NduVVypDd0fnLTe3I0
         a2mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gcq+AsyW;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BYSawePUPsm2cyp/UqmcDJwhrj1UYquKX/xET9AQFiI=;
        b=E1KzLxuZyIBWtSvZeSfkBsXqOE2BrOd+SunOHGYJHBXpzovzDYn5KyAzecEzOXBN/L
         EhLl2Z4+IeaBcnZuBYs69SNTTI7BSDypT7GxBA0i+3K4Y27obzPyB4oKGM7ru61GNLeW
         GQQAKSkiznOivLUZTN3IAWvyEbpG82e3NDcmyb00YkMBjPWFCZtzx3Gx0lFrAKs3Pob4
         GPzXoer/T5cYsKLPC6oUF1ATyJ264WoknPObwaRW1JilU5QBz1zO6MY3ScyZ5HziPEbk
         g5G/ymFg1+/24TK7G4DsXwNQgvv+m0/ctoTSS1kaYsKxdjxwIO3D+Sfo+lI3rcccZKQg
         eoqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BYSawePUPsm2cyp/UqmcDJwhrj1UYquKX/xET9AQFiI=;
        b=We+nx0lwR6JejUMXHu92VJHSTDh0BkGIzQ2y7Lwn0ove0aaKwsMZ/HpSRHB7GjaW83
         +0akUnioxRhz2kAEVMOjpBfWQgcnR9sXV7tb4YhVUGR5gLbqA6GlpuaHgnbvweUx/7+R
         laaBQME0sQRgqR7lwT26O/3ENfL1QlEae+x5JkqUq7YQRPBMJ15AP38hcVwK2n5n54tH
         TjCocW5uIKMyDmsznhEeEW7U76LX3QRs9fROrnpc3pYkfdSJ26LDXIrPLb1NDkoYwE4j
         ksYFXEMP7p1zPbu97PFGiiXbfhOjV7Kr9ETOZB4dOS8Wi4S04sCtjuzZhgVR9pFMsbvM
         487w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531tV3MFVeh45OWb3tditncuXU7BR4p2yFc0zo8HFPxtVb3LlSiA
	5pJeMjNPIFWP2cdzdF3GgkI=
X-Google-Smtp-Source: ABdhPJwlVgGbiNJhOlVVB+q6U8BAQUE/NjQTCDLgrnN4mFS47tLkHyZII8bRSdeyf41umdAKP+dp2g==
X-Received: by 2002:a05:6808:210a:b0:326:77be:466f with SMTP id r10-20020a056808210a00b0032677be466fmr451115oiw.184.1652895367961;
        Wed, 18 May 2022 10:36:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1807:b0:328:f127:fbaf with SMTP id
 bh7-20020a056808180700b00328f127fbafls118159oib.4.gmail; Wed, 18 May 2022
 10:36:07 -0700 (PDT)
X-Received: by 2002:a05:6808:1a20:b0:326:9023:f7b1 with SMTP id bk32-20020a0568081a2000b003269023f7b1mr399979oib.171.1652895367605;
        Wed, 18 May 2022 10:36:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652895367; cv=none;
        d=google.com; s=arc-20160816;
        b=HljBB/K6HQdvDH9XTOe8y3kU0vguxBUMoNZhaU5qUU1MgXGIgFNnQLgbcvq+QcCvwa
         RLhg3mSe6GYX4JQnTOVYqY+qKVAT+JwNoetIZckRgTOoemV3IFsFkYE66S9YrVvyXFhy
         V0cy5SrpgBSeC4EpF5IT0TfI19fa2k0O9N/bkWiloBpUoe9GojKUaafXJxXJvJSjHLJ9
         mB60BhiJ8Q+19HOihjKeR/ewu3lsbRzSg9ZFTgLPFZ+TLnPQoovbh6INqOlrMQZHPTII
         uV9z/VMblFc6ks2A+9D7l1evljFAw27i1lgBzxwxC7LuHICyYYaj4M/mLv75aVheseSl
         YXBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gPoro/Lzx0t0O03C6+f+LNbsi9Gj9UgbL0r5VXsgoZQ=;
        b=wr1vJ9TjVK3UCrsmEhw0m+Tn9ioqFloCjlQ4RXsSaz0NclocJiAXjQpGJhhRWjoA23
         eZts+jVjL1c5uIE2SnnwP2YIez8guTijLZie2/fonT7l9clLjm7Y/vJuwBCG/1iVagZC
         ehRWGQVfWJhr8J8mrzEkiQMdm92JKW2qRuWwz0J8/ffIYL5bkpc+sqHDkTbhW5gCONJv
         DTcWcBHSbn66nC73Ib4eVXJGxYhvp+Tz+NFGahr0Vqhi84Fn5NhdpddHArrhrV2FJ45i
         JzodJC45OH9Vz2aEpN9aZ2mLNusnPvEVF/7Z4zYJ3v67nKMvOHV4J1Y2P2vUV4j3zLZn
         SwcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gcq+AsyW;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id fo13-20020a0568709a0d00b000ddbc266799si342396oab.2.2022.05.18.10.36.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 May 2022 10:36:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5D05F60C81;
	Wed, 18 May 2022 17:36:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 82D27C385A9;
	Wed, 18 May 2022 17:36:06 +0000 (UTC)
Date: Wed, 18 May 2022 10:36:04 -0700
From: Josh Poimboeuf <jpoimboe@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH] objtool: Fix symbol creation
Message-ID: <20220518173604.7gcrjjum6fo2m2ub@treble>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
 <20220518074152.GB10117@worktop.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518074152.GB10117@worktop.programming.kicks-ass.net>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gcq+AsyW;       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 18, 2022 at 09:41:52AM +0200, Peter Zijlstra wrote:
> +static int elf_update_symbol(struct elf *elf, struct section *symtab,
> +			     struct section *symtab_shndx, struct symbol *sym)
>  {
> -	Elf_Data *data, *shndx_data = NULL;
> -	Elf32_Word first_non_local;
> -	struct symbol *sym;
> -	Elf_Scn *s;
> -
> -	first_non_local = symtab->sh.sh_info;
> -
> -	sym = find_symbol_by_index(elf, first_non_local);
> -	if (!sym) {
> -		WARN("no non-local symbols !?");
> -		return first_non_local;
> -	}
> +	Elf_Data *symtab_data = NULL, *shndx_data = NULL;
> +	Elf64_Xword entsize = symtab->sh.sh_entsize;
> +	Elf32_Word shndx = sym->sec->idx;

So if it's a global UNDEF symbol then I think 'sym->sec' can be NULL and
this blows up?

> +	for (;;) {
> +		/* get next data descriptor for the relevant sections */
> +		symtab_data = elf_getdata(s, symtab_data);
> +		if (t)
> +			shndx_data = elf_getdata(t, shndx_data);
> +
> +		/* end-of-list */
> +		if (!symtab_data) {
> +			/* if @idx == 0, it's the next contiguous entry, create it */
> +			if (!idx) {
> +				void *buf;

Could just do the "index out of range warning" here to reduce the
indentation level.

> +	/* setup extended section index magic and write the symbol */
> +	if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {

> +		sym->sym.st_shndx = shndx;
> +		if (!shndx_data)
> +			shndx = 0;

I think this '0' is SHN_UNDEF?

Also shouldn't 'sym->sym.st_shndx' get the same value?

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518173604.7gcrjjum6fo2m2ub%40treble.
