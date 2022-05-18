Return-Path: <kasan-dev+bncBAABBFGTSSKAMGQEU2N2H2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C34FF52C0E5
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:15:01 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id l13-20020a2e868d000000b0024f078d7ea0sf652713lji.4
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:15:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652894101; cv=pass;
        d=google.com; s=arc-20160816;
        b=gq6k/w9v6WDs32QulOfivhBq17w9tTJJlTIiuYa5vzMQ9qlygSyvYZ3LuhXMw7esFY
         FIkPXQK3vFkpn4k/rdw/d+na+JhpdKab5XAQT6h0PgI1isRj9hCy43t4NRCi67FrsoTy
         JEH826HYE5CaYkHBWgVrHMQvNuVl7lID6cncYiE3ZIbiqvNq0jBmQwUXVRdqJftn7ryo
         wnleep6hWHLZYFv7nNQ3EsD/r+mz2Qe98Py0ky3FXZ1l/veOBgVg4UlGgjKimsUabII3
         mlpJUa2o+8unSnTrCrxnOJcb46ZMWxWsMMRDCB6G2sJqRsr/wlJ5O7CI1m+x05P/U6AC
         lBYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wWOEQ9DXlTPtUkFYtFjlHV0zDz4fOuzSGAo8Ze7cMwo=;
        b=fQY33ISpfsE2KBP4ydC/JqyrzZgXdP3Rv4k1pF1Xk1tkJTaRb+y95eCih+hUsmPzt9
         D8v5kIJKq5FmwQN2TCveiWJYjIlGl3D9KWCN3TgR3ePsFS54Tcg9nATNvHOaHPemOzkF
         KyCDXAdgSOCYje5NhL2yjpAXJxLp7ufZH5/fZxo5Df/Jk1PR5TqOTTU2ZTKPIm+2/XCk
         OpZqzeK8NZkXkAcPHiNt48DIS6Uz6W/mVEOqZqiurJnaYGB6ecKoBTBUPNKyXT+ZnM4q
         TNOXGxmEZcOSORrMQv2uURT3fY0ZoWTRTC54h7PZFgDkAWGmgCrrE1Og+oDhHKcXSawL
         6QTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="S/QHbpzT";
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wWOEQ9DXlTPtUkFYtFjlHV0zDz4fOuzSGAo8Ze7cMwo=;
        b=jttnTa2PmuCPGESNoBNm+KrD/TJCkGZFZ8xIoBpxmytplzt2zQBEiazUcnSJXi9Ldb
         1nDCADcVmBIStGXSKvFlQxnw8gH2JDPOb520CUAxM0x/Ney9292Ko478cJopRIoVWwh5
         +uAeapP/30ZJZJGV/wtUij2eFivEq+TB1keNhj0SLAOJyVNFyZIktCkZr4hVo+MPBLgz
         ZHBmezVFiVEVFeToiJk18odQ7BGr8tlxqingwWVAkAoGQwqnkeLKldgK8gkjsx6upu9S
         f80HjNgowzU2/7lmPNFx3lU0hCAaBvHdpEn1z7xfaVWo2fBJph2x7NCW0lRL+IL9trra
         g9uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wWOEQ9DXlTPtUkFYtFjlHV0zDz4fOuzSGAo8Ze7cMwo=;
        b=KxwFWEMFaqZPzOE6OWPkdn50aOYWDMQIyNX5Huy81+0WNtWwKfSLn/rPSVJM7ryrTb
         FmliTaaJXruLAPcAmxOxrwUCN18UkbtFigSmhWB9yeAEV7CcElyB2WhoWypMDP21u2mO
         cKChK995l+g70LSQ5l4BekJwQD5AkKrQYRemww0uAwpH5jbDSdP4HPlKWKLusadKDkBi
         znjksWYGnuF3qSwr7S8U8GoBVJ1Nbi3HORscjZIJMYyuUA8ShlpeadiqzZOcIstVVklY
         kvytbDcvtInGa75Di/xthWcVEDdIMgnWccORGFqXNbvU93qik/7yH6KvAHu6UGvJzNIe
         ykSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wt6XGVAmAF0gWwypKad9Aao4ZvQRPNEqEsK64xBvlN85UZO4Z
	44zIJ/z71R7xo+eEQW7atxM=
X-Google-Smtp-Source: ABdhPJy6hAlb5WsFghuqC5Xkg/fNw7lKW5wMN7LP3S20BfJh/K6+ra0WrXbBsSpNi0vxnm43vYYN1Q==
X-Received: by 2002:a2e:a37c:0:b0:24f:1141:84f8 with SMTP id i28-20020a2ea37c000000b0024f114184f8mr218048ljn.255.1652894101229;
        Wed, 18 May 2022 10:15:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls327983lfu.0.gmail; Wed, 18 May 2022
 10:15:00 -0700 (PDT)
X-Received: by 2002:a05:6512:b08:b0:46b:a876:3009 with SMTP id w8-20020a0565120b0800b0046ba8763009mr354679lfu.378.1652894100536;
        Wed, 18 May 2022 10:15:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652894100; cv=none;
        d=google.com; s=arc-20160816;
        b=jCNqk93jO06VLxogsorXHvCKKncL85stKzaimAJUDHwHKW9AnSBPY/d4/liXJ7RU9L
         rB7Pal3GA0XMe618cEJfIez5O4M+LySRpneftbGCNx+/PkbEb4scfPbO/POS17Og0Pa/
         o4iZwM3lD1Ppbhel1LFLz85UUpqj29Lu7/zMbKinb9zAsWtQSFHVWptjCc/sK4cnRezr
         mOGSDVIltrq3rc8SDW9spuJaz4TP/SVlWtavmWKXnO7I9XXsLY3o+bn10MqO3aI6ET33
         FeEXTQ/970cSArWe1ww6lDj7QcQKuiAX2Sue484RRDxrj/DK39cFOSO0pZuUW6KoiHZA
         l9GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=x3Yu2Yfw0npu/c4m8Sy6+SrTpuSt8SigyBVYXq4HYd0=;
        b=guPGrfcqjJni7nCDTdVqrfFNhUrKeVEXBnOyMZc/DxeB2EpPDMwtSyAY+uBX/ZZTrT
         rPtCqq1iEs63epycL+jMtTVNNXMIlHUk7RGiChzf2PFYOw+/BXptP+nCtdAtHgkTmV6N
         wlvzm0OTpDk3ZShgP/huSQP0KXFkhnXUjy0FPqK7nNjrc3jkyNdJPRpmsHjx8pmoy3Ks
         XfIdhQJjvxZl4UuA5hZOUkKOEokS4/N+jv10xSOis5p4/Whcvn0CuhFKUD4S18xIQTel
         wOD2RiVVAz6AHG26nKYgsLIfIvYLwL8IVZW6r5Fv9TJ+AWrDrUIvQKuWoe2Q0AhlUHgZ
         Outw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="S/QHbpzT";
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id i14-20020a0565123e0e00b00473a659879csi906lfv.13.2022.05.18.10.15.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 May 2022 10:15:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 1E586B82197;
	Wed, 18 May 2022 17:15:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9F1A0C385A5;
	Wed, 18 May 2022 17:14:58 +0000 (UTC)
Date: Wed, 18 May 2022 10:14:56 -0700
From: Josh Poimboeuf <jpoimboe@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <20220518171456.tao6lmum4a2cpvs5@treble>
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
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="S/QHbpzT";       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 18, 2022 at 09:17:27AM -0700, Josh Poimboeuf wrote:
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
> 
> If so then I don't see how it would "fit" in an existing data block,
> since each block should already be full.  Or... is the hole the one you
> just made, by moving the old symbol out?
> 
> If so, the function seems weirdly generalized for the two distinct cases
> and the loop seems unnecessary.  When adding a symbol at the end, just
> use elf_newdata().  When adding a symbol in the middle, the hole should
> be in the first data block.

Then I went for a bike ride and realized that if adding enough section
symbols to a file which didn't have very many non-locals, the hole might
occur in a later data block.

So yeah, this looks fine :-)

Another idea I had was to forego elf_newdata() entirely in favor of just
rewriting the original data block every time.  But this is also fine.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518171456.tao6lmum4a2cpvs5%40treble.
