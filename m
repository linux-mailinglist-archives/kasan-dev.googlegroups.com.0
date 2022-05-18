Return-Path: <kasan-dev+bncBAABBGFYSSKAMGQEZCXALWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 11DE952BFB9
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 18:17:30 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id n5-20020a056602340500b0065a9f426e7asf559494ioz.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 09:17:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652890649; cv=pass;
        d=google.com; s=arc-20160816;
        b=OP8gv1yjhPaiYXUL6VMu+mO/c8ow/wAsvHWQ3PR3Ei+VId7t/MCBwwv4wymHu6hpzW
         wsvkmaFUvpEyLbJ66+tceicv9LdjuHcQFmfAnME1Nhg9Qe12mAHDYn5xuiB4ieX3EFAv
         nMq571Lcu3+aTbdNFVYb7uuKajRgrqFI1lO8TUJ6qsrdDOpbbZPk4AHHhXmb0l0NHFGT
         huzavcEc4OsUrzEy+BBDIsnIj07BzKXPKczOc12MSFnD6DVLKyn2RSoIf4cmKs1JMMIL
         u9OFqud6jYfkSY4ADyO0qlVbCv8uwv1t7ElPcaD+ftx+LZlNB6JGcNNaW36guAB5oRNg
         If6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5HlNmz5D3cwJycTDiLaGkKVFEtXr5VtzBKnQ5BGoo8k=;
        b=ZJy3cpIIL3MKD1q3iMSv27utid/EUAO9RYV0fjOqy4kFcU50MwKSXmnGdWKSK1X5+A
         oHuMsypQObK0om/OptI5Jfh2g3qngXHSUI2ataFjfXk5TeyAopKCsx8OrXte1qR/Kuj7
         STjk3HOP/iVCDo2jcRcds1YDM8d+2dk6/JdxSqjI2HjMAIUQGyPh94nHX7p3rfBtrijJ
         0h+8Z1ml5eXJZYbOocSGE/nOCCbNM0O2s6rLtuG00A/A/Kp/LDMAn3On5Pd2PFVSAfh6
         oUGmzgBdYA6jdEQDjhv/rd73SIx+jHlVHcMMC+lzvHkigwUqr2fM1T7UYTX1p5o8QoVC
         OZcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jCo8ns3R;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5HlNmz5D3cwJycTDiLaGkKVFEtXr5VtzBKnQ5BGoo8k=;
        b=h6VNpZr9sDDBXutpGXNEtdqzLEfg+GIAWUE4q5OHEgBrvQAu1LNy8wMPWhn5MeNCop
         Vv/ImhzYrCcY9KEQ67vpsSkYpMUtHLoGzRGMb/4cgOZXrC07SAJOTtoajOgA8ebVLvOI
         bi1mxiK8lH6GXainqjkP1+TsbLvKSPOUQHTLHNfV5+m7XzHRwS4eg2w0aTdfaN6w8H/P
         HJqlD8YnTPP9pZdPksHnJEwiLVulJJHPcXgegfGx6wg5RGepQqLs9zMIWdGmSCLL0znK
         fPlHrKs9tj7uU4azcFjwvm5qSzkc5gu9BLssMvwBrZFjGPgJr9P74lMSNrwf6C8EwuUD
         ILYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5HlNmz5D3cwJycTDiLaGkKVFEtXr5VtzBKnQ5BGoo8k=;
        b=Ag/lAum422gjLQcGiPJfxFnOlb0o9k/5xVTWg56UuUwTfBIUjeLrURUXgn/eQRMbrr
         xrEDJY/Wp4ZCURyGCWGR9GfwniiPYcRrwjy4UvkF59atKVMJ1oPdvmhrt5dmDgioDq2Q
         j9v+56Kx9qnUbv/AYMHiCqedoCs3yfIY+L0fv4LJerk0zu7KToXSJXlSPr3af+0VL3N9
         RJxOC2Wc2h2QOcuTLaNZkyHVqGR17OmW6ad+YmS3Ksbnt1d0OuiOVOFTphdQ+edv8V+c
         UaFcVZzJxFD0pBlZi6rMLatJHUtLvhDf9jZKzCtE297Sfay0tKlgXbJUhgcPzZdt38bb
         MxzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uPZCKUTzvETdGWEM1f7fu99m5sZp2mhEqcnd6Y2Yfpmkjj4OX
	cWpuhp/6Kug151lNiFNDagk=
X-Google-Smtp-Source: ABdhPJx7CuEDVE99RebQRYeRlYNBXGNKNEoNAKxLf3nqbms9O3zvtHx4b6tu5We4loUCTXHsARmijA==
X-Received: by 2002:a05:6602:2dc4:b0:648:adac:bae8 with SMTP id l4-20020a0566022dc400b00648adacbae8mr195252iow.9.1652890648890;
        Wed, 18 May 2022 09:17:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:71b:b0:65a:ae49:c8f9 with SMTP id
 f27-20020a056602071b00b0065aae49c8f9ls22107iox.11.gmail; Wed, 18 May 2022
 09:17:28 -0700 (PDT)
X-Received: by 2002:a5e:c24c:0:b0:657:a86a:d1b0 with SMTP id w12-20020a5ec24c000000b00657a86ad1b0mr192912iop.43.1652890648514;
        Wed, 18 May 2022 09:17:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652890648; cv=none;
        d=google.com; s=arc-20160816;
        b=kaf4DaYkQfIIOFNMOaCXu+b2JZc+PC2TNo0wMx32rhgaeQvk5w8RVIqyPXc+KVnBP0
         dwL6rsdtbNq5vAaw+qE3AU+fv7N3Kcz7moyYlq8bRs2HVEJWSp6DLAo/y9d46mJosNj/
         RYNIPsnIkSqC/uAxWrukC1Am5n6zyCdT8EgJsHGoKi+t9UuT+oAuR/+DUQE7qYfMtcsi
         yQzye5dI7/810ccugUYr6XqfbxkhwSBGlZ+PybbTQl+XY71w9LpRdcgt1KYlytrt504j
         h9bY7PT+x8gUSTWvTbybVyQ/FDqnFnORTVY+fh8Da9IymaBrOS1eYfjXitKVMZj9srfe
         BVPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f1Xfp4scL9RWN6fPO4jPmNqLQDAQGVrdSgoYlcBdULA=;
        b=p8JKTrqMOvjtB97iK1leSZqnC7iqaY/u03HALDCUMnRdjVPvbvS3QA7guu0Fm22b6n
         vzJEdXz9X0n2rVvAHvwNwpP5MkVDIOF9cOlG0FskH3XFXYriv042ujAvx+mNwUGbELMK
         Yo8Odb18uoN+xkBOde7cmqW4HwXN+SLunQEJ6U+JjSalvvvgYTtt8p3GlcHOVnYZ8qxu
         sfeNYAblj//MO5KLcBJAn1BA7rt69+y1/sKHCthh+Gp+v2M5x8i64nTH0R+VHOeu7oRT
         WJp2ITcY5y0ZMtL2VlEDYIDHVZRK5fD1A/cW42zqxhUXHFsvSBs4jJWOLKnf8wo4XNCI
         HxAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jCo8ns3R;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id i9-20020a056e021b0900b002cddc007296si124295ilv.5.2022.05.18.09.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 May 2022 09:17:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1087261526;
	Wed, 18 May 2022 16:17:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3F140C385A5;
	Wed, 18 May 2022 16:17:27 +0000 (UTC)
Date: Wed, 18 May 2022 09:17:25 -0700
From: Josh Poimboeuf <jpoimboe@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <20220518161725.2bkzavre2bg4xu72@treble>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
 <YoSEXii2v0ob/8db@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YoSEXii2v0ob/8db@hirez.programming.kicks-ass.net>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jCo8ns3R;       spf=pass
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

On Wed, May 18, 2022 at 07:30:06AM +0200, Peter Zijlstra wrote:
> On Tue, May 17, 2022 at 06:24:29PM -0700, Josh Poimboeuf wrote:
> > On Tue, May 17, 2022 at 05:42:04PM +0200, Peter Zijlstra wrote:
> > > +	for (;;) {
> > > +		symtab_data = elf_getdata(s, symtab_data);
> > > +		if (t)
> > > +			shndx_data = elf_getdata(t, shndx_data);
> > >  
> > > +		if (!symtab_data) {
> > > +			if (!idx) {
> > > +				void *buf;
> > 
> > I'm confused by whatever this is doing, how is !symtab_data possible,
> > i.e. why would symtab not have data?
> 
> Elf_Data *elf_getdata(Elf_Scn *scn, Elf_Data *data);
> 
> is an iterator, if @data is null it will return the first element, which
> you then feed into @data the next time to get the next element, once it
> returns NULL, you've found the end.
> 
> In our specific case, we iterate the data sections, if idx fits inside
> the current section, we good, otherwise we lower idx by however many did
> fit and try the next.

Ok, I think I see.  But why are there multiple data blocks to begin
with?  It's because of a previous call to elf_newdata() right?

If so then I don't see how it would "fit" in an existing data block,
since each block should already be full.  Or... is the hole the one you
just made, by moving the old symbol out?

If so, the function seems weirdly generalized for the two distinct cases
and the loop seems unnecessary.  When adding a symbol at the end, just
use elf_newdata().  When adding a symbol in the middle, the hole should
be in the first data block.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518161725.2bkzavre2bg4xu72%40treble.
