Return-Path: <kasan-dev+bncBDBK55H2UQKRBSW5SWKAMGQEYP3JOIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id ECE5252C600
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 00:10:19 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id c15-20020a056512238f00b00473a118e7a7sf1647465lfv.18
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 15:10:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652911819; cv=pass;
        d=google.com; s=arc-20160816;
        b=WBbiqr3QQNF9MZeGeg8jrbxgc4saTAOugsYCwR26NrCduudqx0v4oMQJxZz1AS79zJ
         +RKprHL82BqdjK894eBY3nJN4dqxCWNqzankHbXAIRSPg1XoiSQ7zQOzDMQKUlaagicq
         y+EqSMqxMM2aDUu1dFF4zwT0ydwz/TtxZIpUmjsCEK5tvBtHwPvx/CGwIMwcdB4vvpoc
         xvqEcnMO2DbnJ18Uxtnfs9DfG3qKxZ2pYGC4NyNXflANE/UfG8+A1Z5RpbCdgXT1SQ4f
         UCV875S39sRpvxLnDfwjWhbViNaUAkQhhSCcRFXbaC8Vl4EIv/sr3z65ZvGU4XgSoOsA
         +v8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GvhcbttcyP4lx240/j/JcNh5RQUsNn5yOGElZtQiQVQ=;
        b=ECaK+u54R7ruqzUvl15vLNdl0sbpwZS7eypzsQIMk/VbZpHuW60ZpziumN5+C3nMhZ
         0twXx3XRIUREqdZkh5NLTF6XQuU5uVjhJgvZXNY+ho4N+JShbjIhGTXIGqtYppNegA6f
         eSSgq4g6dXYac0vjkeviKXl4JmWiwJcz4u5+VIsVc8IogXPtd6yO+MJtWE11tuES+s+v
         FSaiNOFyFCuDpvQ0/I/sNg/beFtMSFTQs+6iZs5IAjLLa0zskOToX31OmpceNOPpPpx3
         nXzxbn2UVOo6s9nrihWbYOwjFM7+7ey9C/COxRdkOtwavq9JeH66+V34oZRXTzDRidYm
         xtNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=j2e34UkP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GvhcbttcyP4lx240/j/JcNh5RQUsNn5yOGElZtQiQVQ=;
        b=pqVuoDZX7w8Fhgk0y9g9fYlfiaZ27OWIIM5ZZBR9d/KOLkQRW/fp1tU5eDbu7uvgmB
         KMtrhoTeH0IcuIOiZtgGpShl00iqjDP1IDIt6WtJD7A/EtwAHxHxzDnhiuThP3M2rJPb
         nIdYoWMJZL0X0TgK9CjI3a3Ng9jZjsa1pdA0g+bj1MJ2UbHRDVgSvKrfhs+0lfU6oiiB
         gyOLHJJfOj0tYPld00J1qfvfknU2wVJoxoW034KgnLX3bXHKvztGZ5viOtZSenAIOJtq
         9jm5iX1sdjqVRLugvefZlwbX5QIlya4NHgGatgE2zAl7rVxtKebOC0GEL9Yn0iK/DMfd
         lCYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GvhcbttcyP4lx240/j/JcNh5RQUsNn5yOGElZtQiQVQ=;
        b=hCjoZwyUYsWRn9Rd9GhAvP92KVfTpuRlZZ9vkUBlbZbNTbqFvtaw9ginAFdbJnd1ke
         38mNPIKnPn2s02mzWvPoI89epg2UyV498sSIRHCsXDTdrNpPVp8H86gwXQpHvFrgD/UB
         cZBvEGF50fEgfj++kpU2T0m0BbGUREl/Ndvai/FjlVizmE0Cq9Tb2hLVUzwh8AgMbZgU
         GCXrK06sJHEMbeKdBs9RSpHrIOa2vHUoCVuOby9MRHE5u8xxBLr6AWkEOohEfG2nEgXs
         /0eSMiDDHuYmJGyUK7vWh65sf8lCgqyDOuqbakjQ+U1MVXWhdHbjLX5z4wXoGDzl32c4
         o6sA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532H7KTPsPMJzxpI1vl9iOzlKP331uFWlfSFjOHCxKQdOXY+b5jh
	WGi/we0srh2llvPQzMmpX8w=
X-Google-Smtp-Source: ABdhPJy93CoEROEBENNH/y8974yE2Wctgs1zXwKXXoPwfTfY98Tt3b7QSfssgWvHfpGOknNTs9Z44Q==
X-Received: by 2002:a05:6512:39d3:b0:477:c7de:b88f with SMTP id k19-20020a05651239d300b00477c7deb88fmr76957lfu.33.1652911819213;
        Wed, 18 May 2022 15:10:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls803743lfu.0.gmail; Wed, 18 May 2022
 15:10:17 -0700 (PDT)
X-Received: by 2002:a05:6512:1107:b0:473:e6de:2f47 with SMTP id l7-20020a056512110700b00473e6de2f47mr1044430lfg.107.1652911817695;
        Wed, 18 May 2022 15:10:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652911817; cv=none;
        d=google.com; s=arc-20160816;
        b=qs606Y022vUGjG8kAbOL8SLt68zxCDJ+VCAXJ7daSvc9sEV2NYFh+pPYIp4TaG5pe9
         ibQ3XKuVwqoI2SYCizqtFNXbNho2I+G0AasRhldrPzG0XW7lrjH/t3qq05V5omdtxGL4
         4ynzVHZD24RQEGk7CDKWUGu8MZEtTUTNlZMnP3m0oV8hQEumg2cTE6do8aIRxpms3nPT
         Z6v1uxfItiRUDuVjVYQyn8YFsOOTr7O9Tp2Gn14nhQapOk8m30SFe1HueWtdTY4B+p3b
         sneHKk7JlfuX0RcJW465NxIRRjramNSG0buThmjrrSPTI3NRdXEiiuOkwDFq5zzNL5MM
         bYjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mAr+xOmPUpatPCsQEvvtVuA3lNcGb0ypfwN80fV79Fs=;
        b=uq32ZYWq0jtI29S78Ez25cwj4E5Mii9YjNN+ETJ/PchT1WJakXFdJ9PVjwfEwfdkcJ
         ZFCROA55LFajea95P8wkX3ZVpj5isbPXHezZt7e6EYsxEbHfJhK/50pDWyGlIX8WpWdI
         RvK9AB5fN5ml+VNYHPgFfUFD012mVK9VlZAFPyAJKjGVQETHbxV3zgJpH685gmG8QgHn
         cMjYPi7lgfG6ulDyuQEoX9uXsrEyHVXWjKjmMYRhuNtjJleBnbLCNCgO+BweWOWXhRWg
         hFU8OTl3CkZ5XGHkB2t6wh5Fb0AJu9uc0AGZguv8KNlFCIE/39eRdoR02R6T8Aa++YIP
         Grug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=j2e34UkP;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id u11-20020ac258cb000000b004723ec9fc4asi41915lfo.0.2022.05.18.15.10.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 May 2022 15:10:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nrRry-001fUb-Uz; Wed, 18 May 2022 22:10:15 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9020D3002BF;
	Thu, 19 May 2022 00:10:12 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7837D20757B47; Thu, 19 May 2022 00:10:12 +0200 (CEST)
Date: Thu, 19 May 2022 00:10:12 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH] objtool: Fix symbol creation
Message-ID: <YoVuxKGkt0IQ0yjb@hirez.programming.kicks-ass.net>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
 <20220518074152.GB10117@worktop.programming.kicks-ass.net>
 <20220518173604.7gcrjjum6fo2m2ub@treble>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518173604.7gcrjjum6fo2m2ub@treble>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=j2e34UkP;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, May 18, 2022 at 10:36:04AM -0700, Josh Poimboeuf wrote:
> On Wed, May 18, 2022 at 09:41:52AM +0200, Peter Zijlstra wrote:
> > +static int elf_update_symbol(struct elf *elf, struct section *symtab,
> > +			     struct section *symtab_shndx, struct symbol *sym)
> >  {
> > -	Elf_Data *data, *shndx_data = NULL;
> > -	Elf32_Word first_non_local;
> > -	struct symbol *sym;
> > -	Elf_Scn *s;
> > -
> > -	first_non_local = symtab->sh.sh_info;
> > -
> > -	sym = find_symbol_by_index(elf, first_non_local);
> > -	if (!sym) {
> > -		WARN("no non-local symbols !?");
> > -		return first_non_local;
> > -	}
> > +	Elf_Data *symtab_data = NULL, *shndx_data = NULL;
> > +	Elf64_Xword entsize = symtab->sh.sh_entsize;
> > +	Elf32_Word shndx = sym->sec->idx;
> 
> So if it's a global UNDEF symbol then I think 'sym->sec' can be NULL and
> this blows up?

Oh indeed, sym->sec ? sym->sec->idx : SHN_UNDEF it is.

> > +	for (;;) {
> > +		/* get next data descriptor for the relevant sections */
> > +		symtab_data = elf_getdata(s, symtab_data);
> > +		if (t)
> > +			shndx_data = elf_getdata(t, shndx_data);
> > +
> > +		/* end-of-list */
> > +		if (!symtab_data) {
> > +			/* if @idx == 0, it's the next contiguous entry, create it */
> > +			if (!idx) {
> > +				void *buf;
> 
> Could just do the "index out of range warning" here to reduce the
> indentation level.

Sure.

> > +	/* setup extended section index magic and write the symbol */
> > +	if (shndx >= SHN_UNDEF && shndx < SHN_LORESERVE) {
> 
> > +		sym->sym.st_shndx = shndx;
> > +		if (!shndx_data)
> > +			shndx = 0;
> 
> I think this '0' is SHN_UNDEF?
> 
> Also shouldn't 'sym->sym.st_shndx' get the same value?

This is when there isn't an extended section index. Specifically
gelf_update_symshndx() requires that when @shndx_data == NULL, @shndx
must be 0 too.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoVuxKGkt0IQ0yjb%40hirez.programming.kicks-ass.net.
