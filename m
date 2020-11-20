Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZVO4D6QKGQE646NBJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D9162BB51F
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 20:22:15 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id t14sf8432859ilg.9
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 11:22:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605900134; cv=pass;
        d=google.com; s=arc-20160816;
        b=EDBhqAR7i+ekWfwCWbkrUgLshvcE1nXPOuZKdQfpMfvu4d8dZwvk0oJ7K4ENcgcB7u
         kLgBZvSJpTFHSZjQjg8tTKur7QtsGOUCAlhvN2KyMOnyH2JtvCXI13AemV78G3wr8p15
         YyWCHDVGdvv8urINyD237tEGYH6UxPYVgMJhRs3mKlLkEsApFPNMpevYUXt4CvXGb4nN
         fPAzKJP/JzRiykEXXhiubxL553NveztdqkYApKCkoWDsRFEd/PqCrmf4vikUS41ZXuJ7
         dJmFBHiSf+wr3SVK5+zYD0KHMPpo66eIawMJ/C7Mm62Y7wNAZ1yr5UEd4Uec/g97oH9/
         okaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=crc8bsYas3ZzElOLq8xRnYWDA7yGit8Qb9IyOeZ/0n4=;
        b=fa6Br++oXz2eU0cP1wphwHUmY4R2IM64mBBykQPecCXkddxpXgbow472KRNkj+03Q2
         pIld2BbzQk2igYdIlXEk54357x74hjrYvTKGyuYfcMCsOsanKqmKI3LzkPeRp8z7ywnH
         6f3JCdAL8PLAZQuoD9HXX4b34/6S4yY6pcmzHz11KyU1gtXiqfM/8DVsEyVRTihXmOgK
         SZQptbBcrhXPenlP6QwXNrI+isHE69gYaf7lEodqIVqKTRT+huACnnyN5D3GOCs1ySDK
         vAFZXyouTw9a/eexX3jceXYdgkaOvaULPCba5Sm39loNau+I+0c2VJwtaMnlkQKds5RG
         1PUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UoSVrsHF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=crc8bsYas3ZzElOLq8xRnYWDA7yGit8Qb9IyOeZ/0n4=;
        b=IDwi8zV7NjIeqMASdV6O5c7Dp9c+ssSKMmPQrMtTtdWifeHOmY4tyM8RTlyCr7a+sD
         DYRLy9ixqBJiQhRmyV0y7JuSWx/7REwKctzcgACL4fJaqvvzeGP363Zprn/uOtrhSEkT
         siMWDcp9JnQCjSdBQ3rGJpHz9qdEMCNco5WdscZeadItssB60DhDdBSuYwZP4fu/vnXa
         xgM7YPMd5jlO/82JsPu+01ObYtzLq6cOjKNUa6Qg6JElmNgXcK/QC302q9YLs0uZRc2r
         HNaIZiVfp0ZHWs4rFzRxAOnN//EM3nij+gdpAT/tKDRGogb2a8s/SJJqiH1RL8RTXIhB
         wB6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=crc8bsYas3ZzElOLq8xRnYWDA7yGit8Qb9IyOeZ/0n4=;
        b=pEy9G+AySgmZF7OnZ6SnDwhdBe9rrFmukm/+2I33AEeAnqHyhg538VPylJVZsTe/IN
         Jp9fu6xJ/VlApuK5/9P6xQmuRa538i6vkAAM4eKmngMAtdzOG6kcUIWqL7129BMpNsW7
         2WqARJX16QzZuzqhnDJi4jvBZudMw992A8ufqE2v2/nyWMO3tIGDvpzG1JLwZupMLYpK
         Ddtg1OmKHYx0RVpa/bt+3+xp7Iti9CeToFbhcaEIrhn96RBYxe3U7d3vWfFcpxqllrh6
         kwJ36pwE6GWHSqg73HbCNiSRcqODv0bZv+IuGa+z6Ei4NB7wuf8b05d2ONjYAGv7saUG
         VEQw==
X-Gm-Message-State: AOAM533Cw8nZAsIjcGobII8OJwBIxFRj+2gxQdi3VRfqm05MZU8Hu4nB
	3rDX5XHWxN39u4C/ByjZXFo=
X-Google-Smtp-Source: ABdhPJyDxZQoNJ9fesZwHLSL9o7qKNVi7LYh2lW9IXRZBq86jxyiZjIGGPgG59AEj9/YhQcJJIZ+nw==
X-Received: by 2002:a02:b68e:: with SMTP id i14mr19746025jam.36.1605900134512;
        Fri, 20 Nov 2020 11:22:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2616:: with SMTP id m22ls1078678jat.4.gmail; Fri,
 20 Nov 2020 11:22:14 -0800 (PST)
X-Received: by 2002:a05:6638:1a2:: with SMTP id b2mr20350990jaq.118.1605900134108;
        Fri, 20 Nov 2020 11:22:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605900134; cv=none;
        d=google.com; s=arc-20160816;
        b=H2ySnsQJolfM/8dsKMJLJ41UlAHuZvozIwTzStzm9bzDKTeusffIt2eWHLljvQ1ZT0
         aYdeoZzT8eq6q63Y42oMBFVReZCRmGPAks/yQSNTMCOgyJ/a4euesMsZXZuFdnE+ox92
         FvKwKuwszsyfjK8EWMjBIrFvGfSZifHAbjbwi5cDdL37X7su1uOUG4gkrb0kqGZRUwm7
         Fr1UN0trrBmKdnpMs4bKnIYnyIjkD3HCHZv3jX0IZKa4cp9TW85rao+H78szjTUVN+NV
         sIEqQ6Ouin07pQ/lgT4fh0DOmb82C38DuvTgRWfU3BjOFEAOVYAnnyMP6aeHmaM57WsV
         ZOdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x3bHHSoIiWnpt6sSCrh+oplbMynkFaA5raUA9UFenU8=;
        b=e1Nrn43v0DvUm2XODSSfdM+851e+cfqjdqcSkxRMWDM9tUopQxLmni7iIV9Jpx7/VV
         0GK4GlLBdJzelIPl2+Mf1+oJEVcz2J6QRQiU5BTVujVSeePMfw1sggZLAQyjN625bC8R
         TdIDtwus4zdNf4pPsZ7+gNkktXLXE5FAlPYWqYVsWg3vOllptj1xzaXTytdwILwS364G
         91Xuc1NhL/W6y6krA4Dq2C0nfBvbq5FPMNp+WuV8moqIZdJ+97ogWqdixzUoXioljDPX
         AvWjdlfaWw0GY2s5LiaM8Hh0Be3QRl4mWc66LFxJ6Dz939sjLM5uNakJINFJl3jbAvKP
         LUwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UoSVrsHF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id n9si263203iom.3.2020.11.20.11.22.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 11:22:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id q206so11601869oif.13
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 11:22:14 -0800 (PST)
X-Received: by 2002:a54:4681:: with SMTP id k1mr7597024oic.121.1605900133550;
 Fri, 20 Nov 2020 11:22:13 -0800 (PST)
MIME-Version: 1.0
References: <20201118225621.GA1770130@elver.google.com> <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com> <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com> <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com> <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201120141928.GB3120165@elver.google.com> <20201120102613.3d18b90e@gandalf.local.home>
 <20201120181737.GA3301774@elver.google.com> <20201120141639.3896a3c8@gandalf.local.home>
In-Reply-To: <20201120141639.3896a3c8@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Nov 2020 20:22:01 +0100
Message-ID: <CANpmjNN+smYsdcJDDHNCT9aD_WULV3q6UmVRAutKPjzGVi_yfQ@mail.gmail.com>
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
To: Steven Rostedt <rostedt@goodmis.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Anders Roxell <anders.roxell@linaro.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, 
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UoSVrsHF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Fri, 20 Nov 2020 at 20:16, Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Fri, 20 Nov 2020 19:17:37 +0100
> Marco Elver <elver@google.com> wrote:
>
> > > > +++ b/kernel/rcu/Makefile
> > > > @@ -3,6 +3,13 @@
> > > >  # and is generally not a function of system call inputs.
> > > >  KCOV_INSTRUMENT := n
> > > >
> > > > +ifdef CONFIG_FUNCTION_TRACER
> > > > +CFLAGS_REMOVE_update.o = $(CC_FLAGS_FTRACE)
> > > > +CFLAGS_REMOVE_sync.o = $(CC_FLAGS_FTRACE)
> > > > +CFLAGS_REMOVE_srcutree.o = $(CC_FLAGS_FTRACE)
> > > > +CFLAGS_REMOVE_tree.o = $(CC_FLAGS_FTRACE)
> > > > +endif
> > > > +
> > >
> > > Can you narrow it down further? That is, do you really need all of the
> > > above to stop the stalls?
> >
> > I tried to reduce it to 1 or combinations of 2 files only, but that
> > didn't work.
>
> I'm curious if this would help at all?
>
>
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index 2a52f42f64b6..d020ecefd151 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -1094,7 +1094,7 @@ static void rcu_disable_urgency_upon_qs(struct rcu_data *rdp)
>   * if the current CPU is not in its idle loop or is in an interrupt or
>   * NMI handler, return true.
>   */
> -bool rcu_is_watching(void)
> +notrace bool rcu_is_watching(void)
>  {
>         bool ret;
>
> Although I don't see it in the recursion list.

It seems a patch to that effect is already in -next ("rcu,ftrace: Fix
ftrace recursion"), and my experiments so far have all been with it.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN%2BsmYsdcJDDHNCT9aD_WULV3q6UmVRAutKPjzGVi_yfQ%40mail.gmail.com.
