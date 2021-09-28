Return-Path: <kasan-dev+bncBCMIZB7QWENRBFOXZOFAMGQE5U2DP4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id B056641ACBE
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 12:16:54 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id z7-20020a63c047000000b0026b13e40309sf15541494pgi.19
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Sep 2021 03:16:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632824213; cv=pass;
        d=google.com; s=arc-20160816;
        b=eRDkimP3WcX48xjcPQMnSNi88ywI7+/UzwHFTwOfeLqqJKjvD4t64V2F/U12gB5NM1
         GY33UJjLYvh5Z0dw3km3i/Jnp3CGFV9xRUMYEFzJG793RY1WOhniLjgCIV5oKZGxkqIh
         W61BZXbHtUgeOzxjQxPd78DLLSyNH6qpM0KCTv40JzMpHO1zOo1dl7n1TjiC3yiPLnw5
         s7F7s7dlwf/CVC9gq71ZZYLHRpRVfJJ+3K7ikJFzKiXVlxlKfXAFYEHa/dBI/yO3zINt
         897zCvwiTym38cxskjDx9MAe0X4wBJS2Gb/sj4F2iPM9e15MXPJ0PghD3fs/JGwLMGlF
         +8xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=09LVSDo74clccAqUZgZWwyRQAr+5PyhyJkGlR8965IM=;
        b=fK4qvWE45VJu9/x1JjQD3oJCO34jqxwHRYQJO1KgpJy5xtGl1S8q6n2/QRIX/f6LdV
         MM60ubU+Wz8rgvXR5qWtQsrsZJDYYoYgiDqSVkL1/JjyF77IU6QZhOdGOQKlWo0GStj2
         uz2y3yuPS1e0CvXaf4F0OLbR1gaKtw97WwDwrNuKEVGM8ZXA5csD8AqCN8QILleCSOE8
         BGIhGd/5EusE8IZnojQhj05ymGK/rw6k71hnsWfqdkU366Rk2G2q/H+Z+eMGChi8Z4ZW
         1gQ3SjRpTwFb5lc70BzemTmQ+Xie8TT/l7rVgBbId+OGTgg/+dDHe4+WG1GBCzocUdv+
         2BNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=h8iVziDK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=09LVSDo74clccAqUZgZWwyRQAr+5PyhyJkGlR8965IM=;
        b=OUvmcY1e8C6kN7L4MxfGU8ZAcxo+nidc3kIvY2ITI52MlORnnIWE0CNKxW+nd4zPUO
         wV/djyt3ovSsZgovYM9RQlap3Lr/KG7kCYjeMe8/bt96L3sCTDKOpDXoCPQ2LCYOMVCJ
         9TaBwDoW5DcB/TFAldV4LKnrHKJgpd6cNuQaCpdwttmRkDxcHq1M0dffbrC62qR/NWnW
         vQ3Vj/SkhZkIARRZ2VyOmuRxFLzKiCJivJ2YFUT5Oj6Q9i6q4IAj+bMescwTOsPO+dxb
         j4JZVlBVn7n+xbe95C+i835YGA5dPoXU0NSaMoTr4y/mzXPtOP/aCawUSmadU9MN2zm6
         it4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=09LVSDo74clccAqUZgZWwyRQAr+5PyhyJkGlR8965IM=;
        b=LcYTphyQPNQIWWD1HYZ1u+Fk+CzRLFAMKsiK4KwCKTQOUx2+KhEqLOa5ELorerdWBS
         oc/aU4SQ/hN/LkP5F6ilijdMVmtZZNdsJGepLqsMKR+Ep2SLuF+ois6GjRNQ05NK4IVB
         LOuSnkiM2soUdO1pbvRNvJcTdsD+OyOpwzgxp26VK+3TW1oGaZbBqFwBJjH6pYN5P6ga
         2dh/z7SG+/s9vdeeMBKwecwI4qf3zL43mEGm2t0AqhvkkVqhjXV1NYmS4oYvfmcEpTz+
         QOcYTkYRgE1INRwh6CgOQ1RhepJLeq1xKWfjmo9mINV+Llm0UQgGTkl+X4CK+IWm6li6
         jsEA==
X-Gm-Message-State: AOAM532ZDicro51FztRB5BM0TvMe4/h5tXpMf1RHjG4nj/LDCojV5Pen
	95QBtYU+dhBvGCFjYdCFeow=
X-Google-Smtp-Source: ABdhPJyn8sFZr8+rhfYDvzGZiyIiw4331sePKyrMPyR2JTrjMqBb1WoPaJ/oSneug2Km6/HEtA57qA==
X-Received: by 2002:a17:90a:d01:: with SMTP id t1mr4529660pja.122.1632824213435;
        Tue, 28 Sep 2021 03:16:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ba97:: with SMTP id k23ls11513327pls.10.gmail; Tue,
 28 Sep 2021 03:16:53 -0700 (PDT)
X-Received: by 2002:a17:90a:df93:: with SMTP id p19mr4674081pjv.52.1632824212920;
        Tue, 28 Sep 2021 03:16:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632824212; cv=none;
        d=google.com; s=arc-20160816;
        b=ldlgzSAxytvECTKmkri8JuvPjcSmdvNqVy7MVc6rGmGAzh9KWhBPrCMgbqadXvyb43
         xoG8QJP/tPwAhgkFzxsq9CgFbrhTKza5kWc9tI/brHeTBahdE/sdjizRT5Wdtkqm8Pdf
         h1nlKjCpsgvSLakVjucRxVBDZhesX74pRnf2qw6xe1OeWYOIRc2v8mlGtYLO2xxh+9xq
         S2vzsoPWZhNv5mV3zOygQD97EgH32pUl1wPBVRtnGyPKcMp4xlAtxWYM4rqyD225+1ld
         uFWt2A9UDne9QHU4BUOgcVwUEscbWaHDT5mll1R1VcP5ICL+rNLecBcc1GKi9+WMqNCV
         /xLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O+Hd389s4zwlrEfU0RxVwCS/ivAyltT+4eJme/lzcYg=;
        b=rngHXgnn1nKWoxgC/3oKljNAgobLVdqHsf5jdKcR3xb1P1s3Lmu2Az5DMJi/mtPDor
         aj3ljMUky9uhGWFP6PfPf+9Sx+Q3VHwuxiZN9KMSqiysSOuc/znoP7N6XShjdkSNicOE
         vSdtVT9K5xvIftMy0pRrgs5pN7272UTd/cHzWLvVHiT/3vg6vPind8mgHKfUw+TnT9oo
         +P02BE7elqgAxxcwpd+CoF48Riin5xlmIwa5gPAxVBuKkMhwuT1FL6eeplYRTNaC0cTv
         nTVUOdnDDdq54UzzFuAizEtAZ9jmM5KAxMFdvPkD7q2Tgig7SwMmPfUUs+OLFqiLn1qG
         Y+oA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=h8iVziDK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id m1si442931pjv.1.2021.09.28.03.16.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Sep 2021 03:16:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id t189so29370242oie.7
        for <kasan-dev@googlegroups.com>; Tue, 28 Sep 2021 03:16:52 -0700 (PDT)
X-Received: by 2002:aca:f189:: with SMTP id p131mr3052297oih.128.1632824212352;
 Tue, 28 Sep 2021 03:16:52 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000d6b66705cb2fffd4@google.com> <CACT4Y+ZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw@mail.gmail.com>
 <CANpmjNMq=2zjDYJgGvHcsjnPNOpR=nj-gQ43hk2mJga0ES+wzQ@mail.gmail.com>
 <CACT4Y+Y1c-kRk83M-qiFY40its+bP3=oOJwsbSrip5AB4vBnYA@mail.gmail.com>
 <YUpr8Vu8xqCDwkE8@google.com> <CACT4Y+YuX3sVQ5eHYzDJOtenHhYQqRsQZWJ9nR0sgq3s64R=DA@mail.gmail.com>
 <YVHsV+o7Ez/+arUp@google.com> <20210927234543.6waods7rraxseind@treble>
In-Reply-To: <20210927234543.6waods7rraxseind@treble>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Sep 2021 12:16:41 +0200
Message-ID: <CACT4Y+aqBKqJFa-6TuXWHSh0DEYYM9kbyZZohO3Gi_EujafmVA@mail.gmail.com>
Subject: Re: [syzbot] upstream test error: KFENCE: use-after-free in kvm_fastop_exception
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Sean Christopherson <seanjc@google.com>, Marco Elver <elver@google.com>, 
	syzbot <syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com>, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk, 
	"the arch/x86 maintainers" <x86@kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=h8iVziDK;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::235
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 28 Sept 2021 at 01:45, Josh Poimboeuf <jpoimboe@redhat.com> wrote:
>
> On Mon, Sep 27, 2021 at 04:07:51PM +0000, Sean Christopherson wrote:
> > I was asking about the exact location to confirm that the explosion is indeed
> > from exception fixup, which is the "unwinder scenario get confused" I was thinking
> > of.  Based on the disassembly from syzbot, that does indeed appear to be the case
> > here, i.e. this
> >
> >   2a:   4c 8b 21                mov    (%rcx),%r12
> >
> > is from exception fixup from somewhere in __d_lookup (can't tell exactly what
> > it's from, maybe KASAN?).
> >
> > > Is there more info on this "the unwinder gets confused"? Bug filed
> > > somewhere or an email thread? Is it on anybody's radar?
> >
> > I don't know if there's a bug report or if this is on anyone's radar.  The issue
> > I've encountered in the past, and what I'm pretty sure is being hit here, is that
> > the ORC unwinder doesn't play nice with out-of-line fixup code, presumably because
> > there are no tables for the fixup.  I believe kvm_fastop_exception() gets blamed
> > because it's the first label that's found when searching back through the tables.
>
> The ORC unwinder actually knows about .fixup, and unwinding through the
> .fixup code worked here, as evidenced by the entire stacktrace getting
> printed.  Otherwise there would have been a bunch of question marks in
> the stack trace.
>
> The problem reported here -- falsely printing kvm_fastop_exception -- is
> actually in the arch-independent printing of symbol names, done by
> __sprint_symbol().  Most .fixup code fragments are anonymous, in the
> sense that they don't have symbols associated with them.  For x86, here
> are the only defined symbols in .fixup:
>
>   ffffffff81e02408 T kvm_fastop_exception
>   ffffffff81e02728 t .E_read_words
>   ffffffff81e0272b t .E_leading_bytes
>   ffffffff81e0272d t .E_trailing_bytes
>   ffffffff81e02734 t .E_write_words
>   ffffffff81e02740 t .E_copy
>
> There's a lot of anonymous .fixup code which happens to be placed in the
> gap between "kvm_fastop_exception" and ".E_read_words".  The kernel
> symbol printing code will go backwards from the given address and will
> print the first symbol it finds.  So any anonymous code in that gap will
> falsely be reported as kvm_fastop_exception().
>
> I'm thinking the ideal way to fix this would be getting rid of the
> .fixup section altogether, and instead place a function's corresponding
> fixup code in a cold part of the original function, with the help of
> asm_goto and cold label attributes.
>
> That way, the original faulting function would be printed instead of an
> obscure reference to an anonymous .fixup code fragment.  It would have
> other benefits as well.  For example, not breaking livepatch...
>
> I'll try to play around with it.

Thanks for debugging this, Josh.
I think your solution can also help arm64 as it has the same issue.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaqBKqJFa-6TuXWHSh0DEYYM9kbyZZohO3Gi_EujafmVA%40mail.gmail.com.
