Return-Path: <kasan-dev+bncBCJZRXGY5YJBBDMT2SCQMGQECIMMEHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id D0AAC3964B2
	for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 18:06:38 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 28-20020a63135c0000b029021b78388f01sf7380973pgt.23
        for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 09:06:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622477197; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vkst1ZAzOxIaNOTmAU+aLtuij/hY128h65TfNRAWGl48yRFgqmSK5VhhYpCZmBB95q
         UFOOdvpdIe8VvytjGBnoWCWoHVEeZqH1GWTxV0TNEgt6toYFi3gTOki0MFn1g7Npq4DF
         KC5bbd2tm9u/HVO25EvZntsRLSJKaEb+wB1i+d4joxxm9p23xj6+NjvHMp2LiMTD3SU+
         wfxazNOfeaMLGfzjzhnnUiE0xrPI+b3XaqhpIGLk32NZidVkE37wvUB2s7m0436dpDgY
         ShpzYoqoynHnl9MmYPqkeAC+zLjteXlG1Ux88Alyvsp5jC8OjvbJBWo3r95xLjONa2f8
         7cMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=bFqJGclYDrQrrNjO68KNVlUMmhyPnq1BibgFDtkjR78=;
        b=XIeWhB8BiFa7f2X+k0KMVHaLQc2s42PAJL/KZld0tzyj/0wK7Ad2SFr54gTsGNHyQ3
         5jDjQWp93GxDauM+FSRMMdf4r2h3aG3LWnuhK478thWfNFpDFxUL7dj6OATFawDypxOK
         9Xu17ETyVZto6MHzxsP49BPZiF6y0glUaJwxx9/Jx4DQNITRhE/PWlJyrZlaelYZ/Knd
         D0OUon9izY+FPH+ObR8xK84SEl10IOlbSOgy72c5ngtsVpSu1muaQLdlBDs/uGxncGbg
         NDLOa/w6+GNPop/Ns5rStOoLX9ZIxLZ+dNVyLxSGGJCA3zgFTJdj0fCGPCtvEiDfNJLK
         lPQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H36mQQ45;
       spf=pass (google.com: domain of srs0=moq8=k2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=moq8=K2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bFqJGclYDrQrrNjO68KNVlUMmhyPnq1BibgFDtkjR78=;
        b=b+aPZ4eduU8FOxdlTxF2z+KtDLzuky4LiPiA1dPnxqAbZuZmFNJk3taHOQwkHIFI9H
         ga3CsVvAgvbfNSSUC2zw2fzouyiK6EkwkOzNTjEk6xi7inJz2/iM1rKjH0jVZP4ZJpLQ
         q2UaPrUkf9cMKosScmPlK3GwSqktqHMMFCiqSWieU7HUffvIOIWHHqNakTCL0hlQkovL
         LeDV8EzqGjLZi5wprbJ7ZWNQJpf2QzsBvLJNihC8cRAvTwQcABHjnr6xSRDVGV0iL+kI
         mvDrw/+8aaz02iLMaMIXW3ozxHJsn8+5icc/EDMXMR1FleWWaNmgkNi5Brh/i+Sjy8Gv
         Xblg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bFqJGclYDrQrrNjO68KNVlUMmhyPnq1BibgFDtkjR78=;
        b=BldU8wfzS4N7ZbFQ7v/bE3gAyVQbr1O/3CY5E0Dlxsj6hqNhkaaTGOHoxMf9EZdDrZ
         POdbBCFO7t6+cI6wrouzx7Z1tcEobNxVY5D5PbD+wuIOv9Y0QD6bKfwVHDkWInNkSy3e
         Wb/CGyPssUfyDx4mqmcp+jy/6iShjQCeUyD7dAiZh1GQwW4Xipp9+bNJmmn6+gwzeGU6
         w6BcwS9akxUZ5Ivx+RUzbEcoMPQn0YAYXJ5biXyx96N8H95eF7N/DsnpnMzqylZ0/YaI
         ToZNa3NHK9ReijoH3epNFVQByfPUwd54P6c2WYKZHDtvHbWnDThkL1gYHjT3In94ObNg
         cJyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gtlUfRgjObH37w9w899rcfbSTP8mtcP0SXl+jsIj+ExNfTNXJ
	7Y9ENJwUHLkiwB0TT8XCRNQ=
X-Google-Smtp-Source: ABdhPJxIM/+H5nm1gC8beaCbFHNRfK8WyVx5Z85XSdofy6mfCnhCed6rVjip/IGiWkYZWHw5JRu2Jg==
X-Received: by 2002:a17:90a:2c04:: with SMTP id m4mr20410465pjd.15.1622477197523;
        Mon, 31 May 2021 09:06:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5013:: with SMTP id e19ls7374379pgb.2.gmail; Mon, 31 May
 2021 09:06:37 -0700 (PDT)
X-Received: by 2002:a65:41c8:: with SMTP id b8mr23172318pgq.196.1622477196987;
        Mon, 31 May 2021 09:06:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622477196; cv=none;
        d=google.com; s=arc-20160816;
        b=UJB+n7v8eg04KHAwvn+9IlilGd0spTjz3TBS4Xme5iloHk1CHoSwYA4LpvsP0js/NP
         3xgcx/Lt/pgCre9xMqnNzSyC6hJmIn94PtSVBGyuEZsKOLbMPBBaUWc1EfncZ/9vljNG
         CCC4+Io6JEsNWYHe0DMvBJM2/zo1HYOtCXXGJi6u4aMrH1TH0QZndMW2kR4xPUAUQRx1
         uaMemh28ppfg4eGTdXcDfGFHuObdpi/c3R7IWQWbjO27g4e5yeD2FWhePUe/3NEUQGle
         Psx9uv1LnSuDfdf2n4yE8VuF5nwGB6bLHwi5rgpG3iFFKbCiXCUlL9uKlsX1bUTSq0fb
         Xc6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ViCYgT58RpdbAlvjGU0GTLnQ17a5QxA9LkGMI0KTcYw=;
        b=mIOC4HNNm4yg9JjLGHCImOSHV7IBgvMLRfc+uyWOmqgx7TjX1aJDutBW9703HsaggI
         HlKlI1Tah9Jj7D+BzTGtihrydAw0zEJlUhJJ5VjhLm4Wv7DcMUzLWB3rrEcXjWHtcM7c
         faADURZT/tRpbRBepIhwEsMSYgKpkUuUjJxJw4e1CC7sVPZyri88smn98l3V3D3U5tLx
         MoPV2TsDe7ogyWhHe9kEVRAXkcWVWFFxhNr70Nzx48457B+Yi4RDMhUEagzpGdIGqfbE
         dibuSZRR2XglvDnt2yMkCG8ID4ixj6+0Tcf/U7Nol6LX3C2yRhsL5boKiT9YPbIgU9zP
         3xdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H36mQQ45;
       spf=pass (google.com: domain of srs0=moq8=k2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=moq8=K2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id jf17si1335436pjb.3.2021.05.31.09.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 May 2021 09:06:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=moq8=k2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id AC04D60C3F;
	Mon, 31 May 2021 16:06:36 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 753025C0360; Mon, 31 May 2021 09:06:36 -0700 (PDT)
Date: Mon, 31 May 2021 09:06:36 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Plain bitop data races
Message-ID: <20210531160636.GL4397@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <YLSuP236Hg6tniOq@elver.google.com>
 <CACT4Y+byVeY1qF3ba3vNrETiMk9x7ue6ezvYiP8hy2wWtk0L1g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+byVeY1qF3ba3vNrETiMk9x7ue6ezvYiP8hy2wWtk0L1g@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H36mQQ45;       spf=pass
 (google.com: domain of srs0=moq8=k2=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=moq8=K2=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, May 31, 2021 at 12:25:33PM +0200, Dmitry Vyukov wrote:
> On Mon, May 31, 2021 at 11:37 AM Marco Elver <elver@google.com> wrote:
> >
> > Hello,
> >
> > In the context of LKMM discussions, did plain bitop data races ever come
> > up?
> >
> > For example things like:
> >
> >                  CPU0                                   CPU1
> >         if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;
> >
> >         // Where the reader only reads 1 bit, and/or writer only writes 1 bit.
> >
> > This kind of idiom is all over the kernel.
> >
> > The first and primary question I have:
> >
> >         1. Is it realistic to see all such accesses be marked?
> >
> > Per LKMM and current KCSAN rules, yes they should of course be marked.
> > The second question would be:
> >
> >         2. What type of marking is appropriate?
> >
> > For many of them, it appears one can use data_race() since they're
> > intentionally data-racy. Once memory ordering requirements are involved, it's
> > no longer that simple of course.
> >
> > For example see all uses of current->flags, or also mm/sl[au]b.c (which
> > currently disables KCSAN for that reason).
> >
> > The 3rd and final question for now would be:
> >
> >         3. If the majority of such accesses receive a data_race() marking, would
> >            it be reasonable to teach KCSAN to not report 1-bit value
> >            change data races? This is under the assumption that we can't
> >            come up with ways the compiler can miscompile (including
> >            tearing) the accesses that will not result in the desired
> >            result.
> >
> > This would of course only kick in in KCSAN's "relaxed" (the default)
> > mode, similar to what is done for "assume writes atomic" or "only report
> > value changes".
> >
> > The reason I'm asking is that while investigating data races, these days
> > I immediately skip and ignore a report as "not interesting" if it
> > involves 1-bit value changes (usually from plain bit ops). The recent
> > changes to KCSAN showing the values changed in reports (thanks Mark!)
> > made this clear to me.
> >
> > Such a rule might miss genuine bugs, but I think we've already signed up
> > for that when we introduced the "assume plain writes atomic" rule, which
> > arguably misses far more interesting bugs. To see all data races, KCSAN
> > will always have a "strict" mode.
> >
> > Thoughts?
> 
> FWIW a C compiler is at least allowed to mis-compile it. On the store
> side a compiler is allowed to temporarily store random values into
> flags, on the reading side it's allowed to store the same value back
> into flags (thus overwriting any concurrent updates). I can imagine
> these code transformations can happen with profile-guided
> optimizations (e.g. when profile says a concrete value is likely to be
> stored, so compiler can speculatively store it and then rollback)
> and/or when there is more code working with flags around after
> inlining. At least it's very hard for me to be sure a compiler will
> never do these transformations under any circumstances...
> 
> But having said that, making KCSAN ignore these patterns for now may
> still be a reasonable next step.

Given the "strict" mode mentioned above, I don't have objections to
this sort of weakening.  I take it that if multiple bits have changed,
KCSAN still complains?

Should KCSAN print out its mode on the console, perhaps including some
wording to indicate that future compilers might miscompile?  Or perhaps
print a string the first time KCSAN encounters a situation that could
theoretically be miscompiled, but which no know compilers miscompile yet?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210531160636.GL4397%40paulmck-ThinkPad-P17-Gen-1.
