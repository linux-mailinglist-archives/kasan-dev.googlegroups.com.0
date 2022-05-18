Return-Path: <kasan-dev+bncBDBK55H2UQKRBY4ISKKAMGQE6WSG5KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0966752B1D7
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 07:30:12 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id t9-20020a5d5349000000b0020d02cd51fbsf181219wrv.13
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 22:30:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652851811; cv=pass;
        d=google.com; s=arc-20160816;
        b=LvchyBJqEPtRXZp04SB2qXkC1HR83GbzdOa5Gp7O9QannA0/U/HWvwphEeVuJEolrg
         /CJDmhS/SZLU1e/4P7Ug2QaoWStRxdPlok42Xplp2HRMymiQvTxLT0XBb0bTD2JI5FNL
         /j15xuNEDQOlPEXOXKZVZbZmLN2UXdrX3K6Y/J/W+bYE0E+A8lpyF+YFvbTXhRyJQYip
         aOoZh1N8N5n4lJIX5qPoFtoTkHx1/F4DyghzQSK2bw3jJM2lkpvsTrdos1AHl4E/BLnP
         ZvxhhANrmeiRcJZ6FrzrCV5vjB0fYlz6x/c/PXVFHCHDzfGXgvwrHs1L56b0K/HgIzN+
         BsrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C+NQ54Oh5zEntrpPxTCAn0URY4aS9Y1nzIljm945PfU=;
        b=rjWKs6cgzW/RfZV3p7RYAHPTwrk2dQlGzPAy6+BLSbBoEVZxMruwGmDozQiSWXGbZG
         YjTnOCmyo27iOtY2XL90M32qE1ZoFwYPNNRd6/bk++RgzZ1VSdgxZOe4gRnCzwL2Ovdl
         sErMEvOXtDNNmvdscR7DZKZNGBuyzU8BDORAqhKlaoEuxpwZeesMOFRcsEXYr0uWC3RJ
         GSrTdfUJcztgoVAS3n83RSqFxi9GRm1iehwC0StiVMr2xmFRIHR6dUJWj8LiTJy6iAqd
         C/P4j0uHKUS3GP1n8lS40gNXcaXiK7+3tByXY8Iig/WE3Z6XYRcKHVN0k3XGwkKtNBGa
         NXuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=FiX5lak8;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C+NQ54Oh5zEntrpPxTCAn0URY4aS9Y1nzIljm945PfU=;
        b=Eg8g7YdxXjIrHqzgAI8no9maQq4XwLoP//sp2CYgVN616734U3rLtAX6CdCKte8joq
         1PImYHVog5UP+/H4gQL9CQ03upoah8x2e7FgfLtA9ksk6nsrtvt4Klh+0gUOmUlM5T5u
         BN4Eed8J8JL015fGGpAWqTI54DU2k6xOGhQwFnpH2H61XHHFyF6GCek2ln9hTlklpH/k
         a8Ea4Uc+wSRWpqwyKUYHVF4VwQvNlyudAklggCRnEABxrWLwzGIGhqucpQW7YzdfQzY1
         Uh2Q1ZZO1F7qvR+gzHANvevSHsIR9+64f/eDWl4KaPurSXdTC2uWK+txeKwUc8oRGvVF
         vjQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C+NQ54Oh5zEntrpPxTCAn0URY4aS9Y1nzIljm945PfU=;
        b=us55Ts+0CGqMs/65AakYhbskhIwKUOHYQ7BNt4frFMy9h6UW8fgfC6EHTUz+4YC8yU
         M7fopquA8reAIHAt785dqcnFYESQ3juZ8hTnwyjQh/4rweRIqq/rJoSGr8ysWB2+9hEt
         KkqmGZG5qbqfREKo/qTCPWbcBTpf0PGc2z5LALy6t3vmJsf3aDCaccyI54hX3hp9R0cv
         qmvOlkOt9ozJmNj/uS5fyPrhjEYqCTJDaREfEaurnIBrAnB06/U9F6JYBitoMuXQ06xZ
         BTokSHDlIW5STGYZEp+NLo3nf8oD38v+OAqhJGD+fiNRgXa4d5xgDq9mzYgtsbs5hSYb
         IkDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53307NMkOPQoW1aOInhjxttE7NnGpTbA/fBJFWlr3wsupkj3z4pn
	mnNw2qxcinzWAF9tTZvfbNM=
X-Google-Smtp-Source: ABdhPJwGpJwOq8RXy9It34eKwrZ2RoNMJBsCbjoaCTzKhl/L7Dc0YG4PBWkno9iXIvdaBiwhI0aqeg==
X-Received: by 2002:a05:6000:136d:b0:20d:381:cab0 with SMTP id q13-20020a056000136d00b0020d0381cab0mr14562005wrz.339.1652851811670;
        Tue, 17 May 2022 22:30:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d84:0:b0:20c:7b09:42a4 with SMTP id l4-20020a5d6d84000000b0020c7b0942a4ls5765585wrs.2.gmail;
 Tue, 17 May 2022 22:30:10 -0700 (PDT)
X-Received: by 2002:a5d:6481:0:b0:20c:6b71:211f with SMTP id o1-20020a5d6481000000b0020c6b71211fmr20555457wri.666.1652851810406;
        Tue, 17 May 2022 22:30:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652851810; cv=none;
        d=google.com; s=arc-20160816;
        b=tm/fnKnlhgY7hBCr1/6aY6wGTIkkHpD+wMJ6peMBBQ3ShVJu6NV1L1G1GuebPewp2f
         B6FcdfhNOB1AICsifEi4tSHOrOfBTcY0n7synBviv5mKB9xlv0x+c9Wa1K1MJXc+0b62
         F/0SAkhAr/17t2mvkgeE4ioIhxEge5OpdYwVC2mfLhR7Af1CSk9mfvA71bRAC7ho4GbA
         5Hety/A1FTykNkFgtBmeqCscJOQl58izhN+zgTpIlN4Fsm/lX9ceh/ic7VjKR3Litv89
         dnQuuLrE5E8K/IpHX67mZrN4qTHXSDos4SuycmYCRLA31KeeMGb3nw/EqGxmjYrxq2vH
         bdHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ISxEuC4Kiq3vjUGUEirY3WiUkmrk0AhD6N2mrq7YQrw=;
        b=GrOQmX5E6z1LzqaudG/PulesKC33L4JDBlSr6ZMDaAzWFTZ9CDZ+LdySVYPQCfIVEH
         ixsTGGi6GO4yojQhrY9oABqla0f9mcsBKc1PVUUhIXYbk3oeXE0R08ONLKtxyHaL0zjA
         lCdfL+ibU3IxWxuwIHna+UMHQ3yPn5PD+yAPurPNzMo0B3vZvOp1pWkv8n6kPrnpUcHe
         g8hhfAJkoPoA3ZDJ3pScpsq9V+PCwVokptrHJa12B5RMfjRma9kUMoH5pn7ayM2CLHzi
         Qb8PFZarTPRIIGWGGnYXAdbBqzfIJ29a2lSGFaDjWGFhCqoo5FpG2TRA9CKbHhuKgu0o
         mzlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=FiX5lak8;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id p6-20020a05600c358600b00393e80e70c9si284668wmq.1.2022.05.17.22.30.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 May 2022 22:30:10 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nrCG9-001RwI-1K; Wed, 18 May 2022 05:30:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BDF1C30018E;
	Wed, 18 May 2022 07:30:06 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A068A206F245B; Wed, 18 May 2022 07:30:06 +0200 (CEST)
Date: Wed, 18 May 2022 07:30:06 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <YoSEXii2v0ob/8db@hirez.programming.kicks-ass.net>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518012429.4zqzarvwsraxivux@treble>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=FiX5lak8;
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

On Tue, May 17, 2022 at 06:24:29PM -0700, Josh Poimboeuf wrote:
> On Tue, May 17, 2022 at 05:42:04PM +0200, Peter Zijlstra wrote:
> > +	for (;;) {
> > +		symtab_data = elf_getdata(s, symtab_data);
> > +		if (t)
> > +			shndx_data = elf_getdata(t, shndx_data);
> >  
> > +		if (!symtab_data) {
> > +			if (!idx) {
> > +				void *buf;
> 
> I'm confused by whatever this is doing, how is !symtab_data possible,
> i.e. why would symtab not have data?

Elf_Data *elf_getdata(Elf_Scn *scn, Elf_Data *data);

is an iterator, if @data is null it will return the first element, which
you then feed into @data the next time to get the next element, once it
returns NULL, you've found the end.

In our specific case, we iterate the data sections, if idx fits inside
the current section, we good, otherwise we lower idx by however many did
fit and try the next.

> >  elf_create_section_symbol(struct elf *elf, struct section *sec)
> >  {
> >  	struct section *symtab, *symtab_shndx;
> > -	Elf_Data *shndx_data = NULL;
> > -	struct symbol *sym;
> > -	Elf32_Word shndx;
> > +	Elf32_Word first_non_local, new;
> > +	struct symbol *sym, *old;
> > +	int size;
> > +
> > +	if (elf->ehdr.e_ident[EI_CLASS] == ELFCLASS32)
> > +		size = sizeof(Elf32_Sym);
> > +	else
> > +		size = sizeof(Elf64_Sym);
> 
> This should probably be called 'entsize' and I think you can just get it
> from symtab->sh.sh_entsize.

Ok, that would be easier, I'll check.

> > +	/*
> > +	 * Either way, we added a LOCAL symbol.
> > +	 */
> > +	symtab->sh.sh_info += 1;
> > +
> >  	elf_add_symbol(elf, sym);
> 
> Not sure if it matters here, but elf_add_symbol() doesn't set sym->alias
> and sym->pv_target, and both of those are unconditionally initialized in
> read_symbols().  Should elf_add_symbol() be changed to initialize them?

I'll go have a look, breakfast first though! :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoSEXii2v0ob/8db%40hirez.programming.kicks-ass.net.
