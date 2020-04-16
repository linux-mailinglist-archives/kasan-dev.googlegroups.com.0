Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF6K4D2AKGQE2Q2RXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C9B501ABCC0
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Apr 2020 11:27:52 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id x16sf2676869pgi.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Apr 2020 02:27:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587029271; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q9W6CToIvIRqBosLx1qdDA0zSD6U057Y00iuYxMbAfQDNGMtVS/5h6mLnzne8hd/SU
         jtH5hD2xXcUIYhl4cV3II78JvLWBD+ub6EM4ynjRSuLkRo5eJ6IX61jeMKYNgzcL9zA+
         l4Cbr0LwW4ddiq1o2UVsm3l9sGgbdpvpG39Xt/llmi7ops5q5Jl5LMnDW/FExVtx87wj
         PNHFe6rvov77l5FxqWp6GIalb3JM0T8uhZYJ3iab3EHkseVyGAWTzlSxkXyRnGxhaVrB
         cQ9hmLtGsf9JMgh1gtBpmj1UzD3QfAiAtrIdXiup5pUmlLMgb1Isa9e4VZHy6BUVadeo
         pl3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g9Iua8gmC1TMZYafDsv0mKFF07TXyEJTfb+d2hd3Xlw=;
        b=qgh8klNowRnxju0s0gXtKIHAbG/MDE6QgzXZbkhQ0VGsGThT2W6EIKhKKeoJNaXpeF
         KDh6/7F+QQI8SxWE/pYL9GR/HKgShVGb/TnimwKw4tvwDkL7QrSPPCTQhmoerrdGF+3q
         zCwN73eUD3482hGbILjE3neAXPi3k8kocegcI0U6i3stWqOMY1eoqGtMU4wm3sS8jDtK
         2EHmYw3B3Ug30ocAsyJl13rBQzIMragtdOWV76gUVyCMsM5fPHOJOMNSRDa7ekepb5Uy
         uHVcLdQiEsmx+uvg6UFRF2XZXOFL8NhbVutkZPJ+Tt8OyPVUkfnB2Cbn3mAOAXn0h/QT
         XspA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ug54GZiq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g9Iua8gmC1TMZYafDsv0mKFF07TXyEJTfb+d2hd3Xlw=;
        b=Z/zc7hdTWxQRHedVQVKuFYtaATVa+/gJeWXyEM5RCXA9cn0lpPg16NKxPAwfthiW7r
         nit5gZ5TEzuUb3WYLA/a4/NgF8waPyHVW53I8wgsdyoJdvLLrR2yVErPdiCd52E7bxPc
         AwKLVOwgBrSMWPSBA3vp7cTA2+VjHgvo4I+D5b922rWsVXqncByYWW5Jt1CndiBFdJJt
         E2m8QZ8NYG61FuCLtBCzB2EG1qlW9FaTOeL2YKQuK/FSpt5QUMk601E2vwWdFQ6VGiNu
         4Cj7awythCsjoobe+PigdP/iQR+x5xlUSyLvykksZsUTM/C3pRGYqWMblxpXDYiNZda5
         xq6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g9Iua8gmC1TMZYafDsv0mKFF07TXyEJTfb+d2hd3Xlw=;
        b=KtdJPja6IDzeE5dJwFfVfFUdhe97ENXs6cuBMoYyWP9qgvQEiQet/l2PdaCeIcfZPe
         UnQngIH2L7hpyvwAaOoStG1hVzkMt70f+aSzyHAQwQSKzOBgTwrxdyNc4ggb9VA/IFxd
         nzJsPuMirhfWBXeMRkExExXfBGAhdq+8Ia9bvJgjJsRQRfMtjeQeMaEERZmyWfwY99tk
         3a8pBmkRL7qUBAqjinVn6ExNM984vbwG2r+cigFTwmNA4LJf929JZ3GP5aoqRFf7yUCL
         v7pSSWQoyMDznZXC4ug8jXNQ9uOkEQMmNL6jWhuxtBqPWVH30R3JQKs9CC8wIE9eGC0q
         bwYw==
X-Gm-Message-State: AGi0PuaMDhQi3tfI11IueXxJhUvXNw2XVbZg4iaq8gZmiZniK7kr9EGM
	7PnhhxAWzoxVsYNq+f8/adI=
X-Google-Smtp-Source: APiQypKCz87o+VW1IlfXdf+wok/BUu2KZbcz6kPYpwGZNRX4KdCqgW8bLGt6F4tRn3Xi6J3qRZfIWQ==
X-Received: by 2002:a17:902:561:: with SMTP id 88mr9341299plf.78.1587029271471;
        Thu, 16 Apr 2020 02:27:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fb01:: with SMTP id o1ls7467460pgh.3.gmail; Thu, 16 Apr
 2020 02:27:51 -0700 (PDT)
X-Received: by 2002:a63:dd0c:: with SMTP id t12mr29423261pgg.429.1587029270980;
        Thu, 16 Apr 2020 02:27:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587029270; cv=none;
        d=google.com; s=arc-20160816;
        b=mQLwQz7D9dlBj+ANgU5GQFg+9dbsZtxLJLA9nRdPJIfDb93cek7MbGu/UgiMp3rg1B
         zgRp6YhA8jlWAJDxVnWFK3H4VjKx0mLHNbopYA6DdKaPMthRd48aD/o2uLv9NhFTRPgU
         LMZIdxJ8ZZdYNvwOpYBijYgxUoPt4+cbgMMPg8PtLXSrf3CRf8HHm+Box8+2A7uUF5ZI
         UlG9z8LyCNl8CUAdB5+rt5iQ+b3Kz9KR0E8GGpe4I+IitSpymtp0pxKJi/y35/fB8nlP
         F0RfpHUr3WCoE+rwxhefp/0iODHElcRwYLQFQn2fFoUeopp/2zb7mqflaJDp3MSq+kGg
         bNWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cZyNZ/PomFpedyOsDDa7ffLGcZMQ7O0BTntcLMz/kdI=;
        b=yjNNft+ajwQV1UG+R6T0hKwSaEelHGCfJFsQ7hy4HCGaQDNDZGF/ZUJV/tls2uUAlH
         u30v0Bklh4/k70/QUvyfsfXEzXB5kt2L2yw/cylFtq+1sDdw4Tip9u5ShfYFjNRTwFK/
         vcQQc1dRGjbn2o6H1CDzAqbqc7q9wFlYvFO151+Ghng7ZbPTSL8hSmT9aPmJ27cLDkBD
         wkoR9G0XFquvog1ChG47iBCQUDtvr5aoAf5AgBZ4VbAoP85Mn8+ysqCo+etqq5vo8WoB
         JmSAEy+/OrY5ba13jQ+NP2BjGxNOYRq75fg61c9YWFI9RhLZP3q0MyeuzUOhL0M04cF3
         2W2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ug54GZiq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id j132si638408pgc.2.2020.04.16.02.27.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Apr 2020 02:27:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id i22so2474423otp.12
        for <kasan-dev@googlegroups.com>; Thu, 16 Apr 2020 02:27:50 -0700 (PDT)
X-Received: by 2002:a9d:509:: with SMTP id 9mr14157880otw.17.1587029270015;
 Thu, 16 Apr 2020 02:27:50 -0700 (PDT)
MIME-Version: 1.0
References: <20200401101714.44781-1-elver@google.com> <9de4fb8fa1223fc61d6d8d8c41066eea3963c12e.camel@perches.com>
In-Reply-To: <9de4fb8fa1223fc61d6d8d8c41066eea3963c12e.camel@perches.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Apr 2020 11:27:38 +0200
Message-ID: <CANpmjNOSo2WqquKJwePdsA1VXS2V94DQZ=RVY9bULbVwGPx1RA@mail.gmail.com>
Subject: Re: [PATCH] checkpatch: Warn about data_race() without comment
To: Joe Perches <joe@perches.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, apw@canonical.com, 
	Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ug54GZiq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 1 Apr 2020 at 17:19, Joe Perches <joe@perches.com> wrote:
>
> On Wed, 2020-04-01 at 12:17 +0200, Marco Elver wrote:
> > Warn about applications of data_race() without a comment, to encourage
> > documenting the reasoning behind why it was deemed safe.
> []
> > diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
> []
> > @@ -5833,6 +5833,14 @@ sub process {
> >                       }
> >               }
> >
> > +# check for data_race without a comment.
> > +             if ($line =~ /\bdata_race\s*\(/) {
> > +                     if (!ctx_has_comment($first_line, $linenr)) {
> > +                             WARN("DATA_RACE",
> > +                                  "data_race without comment\n" . $herecurr);
> > +                     }
> > +             }
> > +
> >  # check for smp_read_barrier_depends and read_barrier_depends
> >               if (!$file && $line =~ /\b(smp_|)read_barrier_depends\s*\(/) {
> >                       WARN("READ_BARRIER_DEPENDS",

Do we still want to do this? Which tree can pick this up? Or was there
anything left that we missed?

> Sensible enough but it looks like ctx_has_comment should
> be updated to allow c99 comments too, but that should be
> a separate change from this patch.

AFAIK the C99 comment patch is in -mm now.

> Otherwise, this style emits a message:
>
> WARNING: data_race without comment
> #135: FILE: kernel/rcu/tasks.h:135:
> +       int i = data_race(rtp->gp_state); // Let KCSAN detect update races
>

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOSo2WqquKJwePdsA1VXS2V94DQZ%3DRVY9bULbVwGPx1RA%40mail.gmail.com.
