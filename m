Return-Path: <kasan-dev+bncBDBK55H2UQKRB7WXSSKAMGQE24FEHRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B1D6552C0F7
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:25:19 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id n3-20020ac242c3000000b00473d8af3a0csf1338701lfl.21
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:25:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652894719; cv=pass;
        d=google.com; s=arc-20160816;
        b=FyST+Y/Nzih9rlYh4pCU73FQ1g67vgfSBf5Q1vcg9SWRo6ZAaY4aDW6QkuOZ4KOH+H
         Ffikor6586TcxgmU89XxShv7abgzRsQCHzC7sj8dbwd6g8EN8zx/xFOuC5/PXbqAdIoB
         HovMa9IkYEJraGdG/33aiW8Oaqr8J4h9OILV6AdHjQxju8VQvC5obvgGBqe04tX8IaSa
         ta9/tW45IxvIx4AqcqrnWBB3q06dlebIQxRaP8ZYVMKz0ext2XoC8CsjOxZM9QYKo7rF
         ZAgDYBmllI5Fdj2QBGUnHeExWJkbeK5WSydRZki0tu89MCflyEnJxpF8jBAgiopd8YzL
         XF8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uh4AHv/OmDCvaeZdmKllbs8hY2V1Qzbkf4N1sJ9JTkk=;
        b=grXqOj0Ope7SXTCQ0xVFCvUW8H0PIEAoy06o6YO7A9jYbRFowt1sl9OIrTmuL93doY
         jO5NumLp+ShFe8EXnTJwTyIjoHuBj8/XWywwy0ZMnxV7OG+Hf0aNIe5tyDj3NuHiHny+
         JMDDeSD1CXOOrvElEVLwOf4wBCbGONuXBJy8j6oZNSWCM1jYDy0m+En9wSuOl+2VRYBX
         qyWMCbXXDgHUe8pM7Lw2EMEGHLKi3YYmDiEW/9VhLoHFY+c+g+LfPp2eb57CZRajrW49
         lb15NQ8fe6Pzlrv2mk3YXVvBAVghsYEbKy0UhC0L/ym1miLuQDWEXLevFCEr+KugN5JW
         +C6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=vLWKCExD;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uh4AHv/OmDCvaeZdmKllbs8hY2V1Qzbkf4N1sJ9JTkk=;
        b=YQ2wbiA6f5nbfErOCzInU0KMMdDbnkRNPes5pAT68AhOFen8cZe7ip0AbvqIvgcblf
         Jkwdy8wOISvfBTi7JvH5aZ+1DLXbs+2UryDQfoFeyZuk6SEvmDtl9712qqQeVe22MDNZ
         iazVrFj4U/9pfWERu7hqneeeibgB/fzRQ7YHvK/6TRYqR9Bx7UurUB/3RwC7n4oshvOd
         AWqQAWs0SjLtYsG1oACh4iqalMqkiFVEpbciulKdS5OJGlYuPvW2qOX8kNmwyUuG7oGe
         YcomsrPxsXz3UT/hWiATpClVU7kJnPWx5QF0JcThl/u4IP9Y9kbfsKB3HiOFHpLVp3HX
         QWgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uh4AHv/OmDCvaeZdmKllbs8hY2V1Qzbkf4N1sJ9JTkk=;
        b=Do1XuvGTTSZUpeva67jlLJqZHp3qm/G3mJcjHr8jFJ3jVSUm/wblbS5AqMK6HksEjk
         ipWiTdCIUr2VVMjk702O1cZV4+5LdTDmYPhvvAH+mDxkaCe8ZiEjRpcufEpHaXi/zJWL
         sQFsuHpeBeosGndzkoy8u0N+kTeiZwiar5OPJMkkaUEa2v1fcD0tX5WN+cbIrL+dda5X
         tf0GLlhFq0EwBKXVThH460mydZ+DQLRXi1XE0hvg61p7IFtii5Q/wKqlBaVUspwtRNQI
         Omlj1l5G8ui+INfyNlCrWsEtkG60h6md7/9FHTEihPkR+usyfFWJ37GhLpNPVRtiEkD8
         f2dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fQ1zCbLANoy2KdDlTvWmD2oJ9UCXYV8aCcm3EjKT/zFa3r6/z
	NCy8mROBH5buNF28IBtJ+OM=
X-Google-Smtp-Source: ABdhPJyehQWhrEjs6EvyG0cV/w3fke76+bQRdMJD/LWmC/HQuY7yH2GlPMuU0hx0aArKLpAHWJf6/Q==
X-Received: by 2002:a19:e30c:0:b0:477:b21c:db34 with SMTP id a12-20020a19e30c000000b00477b21cdb34mr392359lfh.270.1652894719117;
        Wed, 18 May 2022 10:25:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:b0:477:a45c:ee09 with SMTP id
 f14-20020a0565123b0e00b00477a45cee09ls341782lfv.3.gmail; Wed, 18 May 2022
 10:25:17 -0700 (PDT)
X-Received: by 2002:ac2:57c7:0:b0:472:208d:926f with SMTP id k7-20020ac257c7000000b00472208d926fmr377473lfo.224.1652894717710;
        Wed, 18 May 2022 10:25:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652894717; cv=none;
        d=google.com; s=arc-20160816;
        b=h9Of3SzMS7GFSqq2N4+Fgk2XVKDttZf6F3Cpdxt+FWJWhh6jB6skbdicMP9QaN753f
         nNk0hxwcPRnjI8LcAZtwnqLc1m+ZFr3FVENo+JBEItIODsl+yf9O6+S1xYRV0PbTuCW3
         OjJ7HAEpRPMchOhSCDG4vkbXz54T7kV3Uvfe2OZfpgLeTm6iYgOd936+KntDA4hGDny6
         8hQx+h9On5uxwE8AVTaKnNyZq5kXWu9b48aeB57PDVFRkO/BExc6uwiu3XbqHgYnCnpQ
         3pArLwDqZTmm4kjeLuRrNHh99UA9/1qsUobCajGbQ8DPquop9YPrRDR36uTFlE2zqs/C
         JDxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=65REOusaJPaPEBjW9i2M1+OoIBEIzBECH8es2CherDs=;
        b=DozBf+qA9IL4BNza3aTz1RhviiacwPs183W1NC6toS4soXdseZoBOWZw4hjmdOiiin
         FIJfvlQ9oTXs4CWHsGwsbKZlStR2HDJD1V8nr8ALn49BwSqSpd8fvUJ9w2zX5CzVKalS
         z0joMZivV/DJbCmNfkXqgG9N+RBVXKQKrbsae7fXui+Sewdw2SVeww55AzpGXHRh1sT6
         kCo7iYwQR6ZwvIV0rixt3ccNRZVq+fxjtdCgmpVYXWwhgNa1lT9pabQYLKVvgNDFu/B5
         q97jb4sPOKLuZlqr0qOPbcdCEWfczg+eo3L0ICRhnRGfU6U6sA5ho2c136wI/sAafa6S
         WDww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=vLWKCExD;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bn38-20020a05651c17a600b0024e33a076e7si134029ljb.2.2022.05.18.10.25.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 May 2022 10:25:16 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nrNQ9-00Bz5J-Us; Wed, 18 May 2022 17:25:14 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 88732980E1C; Wed, 18 May 2022 19:25:13 +0200 (CEST)
Date: Wed, 18 May 2022 19:25:13 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <20220518172513.GH10117@worktop.programming.kicks-ass.net>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
 <YoSEXii2v0ob/8db@hirez.programming.kicks-ass.net>
 <20220518161725.2bkzavre2bg4xu72@treble>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518161725.2bkzavre2bg4xu72@treble>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=vLWKCExD;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, May 18, 2022 at 09:17:25AM -0700, Josh Poimboeuf wrote:
> On Wed, May 18, 2022 at 07:30:06AM +0200, Peter Zijlstra wrote:
> > On Tue, May 17, 2022 at 06:24:29PM -0700, Josh Poimboeuf wrote:
> > > On Tue, May 17, 2022 at 05:42:04PM +0200, Peter Zijlstra wrote:
> > > > +	for (;;) {
> > > > +		symtab_data = elf_getdata(s, symtab_data);
> > > > +		if (t)
> > > > +			shndx_data = elf_getdata(t, shndx_data);
> > > >  
> > > > +		if (!symtab_data) {
> > > > +			if (!idx) {
> > > > +				void *buf;
> > > 
> > > I'm confused by whatever this is doing, how is !symtab_data possible,
> > > i.e. why would symtab not have data?
> > 
> > Elf_Data *elf_getdata(Elf_Scn *scn, Elf_Data *data);
> > 
> > is an iterator, if @data is null it will return the first element, which
> > you then feed into @data the next time to get the next element, once it
> > returns NULL, you've found the end.
> > 
> > In our specific case, we iterate the data sections, if idx fits inside
> > the current section, we good, otherwise we lower idx by however many did
> > fit and try the next.
> 
> Ok, I think I see.  But why are there multiple data blocks to begin
> with?  It's because of a previous call to elf_newdata() right?

Correct.

> If so then I don't see how it would "fit" in an existing data block,
> since each block should already be full.  Or... is the hole the one you
> just made, by moving the old symbol out?

Yeah, the hole can be in an arbitrary data block, also the case of not
having any global symbols, but see below...

> If so, the function seems weirdly generalized for the two distinct cases
> and the loop seems unnecessary.  When adding a symbol at the end, just
> use elf_newdata().  When adding a symbol in the middle, the hole should
> be in the first data block.

I tried that, but there's a number of weird cases that made a right mess
of that.

Consider for instance the case where there is 1 global symbol and we
need to add 2 local symbols. We start with a single data block:

 -  L	s1
 |  L	s2
 -  G	g1

So then we add one, say s3:

 -  L	s1
 |  L	s2
 -  L	s3
 -  G	g1

and we see we got a new data-block for g1, but then we add another local
symbol, s4, we move our g1 to a new data block but then find that our
hole is not in the original data block:

 -  L	s1
 |  L	s2
 -  L	s3
 -  <hole>
 -  G   g1

So while writing the global symbol can always use the new data section,
writing the new symbol can need arbitrary iteration of the data blocks.

Something somewhat similar is when there's no global symbols, then the
new symbol needs to go in the new data block instead of the old.

So it all became a tangled mess and I ended up with the one generic
function that could do it all (which is both simpler and less code than
trying to deal with all the weird cases).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518172513.GH10117%40worktop.programming.kicks-ass.net.
