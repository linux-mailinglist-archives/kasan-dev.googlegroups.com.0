Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ4E6GFAMGQEBHEWTMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 14466422627
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 14:17:09 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id z2-20020a254c02000000b005b68ef4fe24sf27944791yba.11
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 05:17:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633436228; cv=pass;
        d=google.com; s=arc-20160816;
        b=IVPqUOgaJBq4v5hmYsRY9MnXgtQhAjF9yom2Vene6MRy+z3+J7gFzpLdWf9ghkAv5z
         gs6UTiQTybVtCtGj7QLXWlGPqlzQP3MqyDSx51R7swqkOr12hHHuYKD6lF9iPkXoKu/E
         05IHv89RKQ5oKIei8O7E3AEHtzf9kTVp5clb7EnJN14F2SSvv6SFc/F+s7n/fIS4W/pr
         CW3DdeQ46Bdd58lXnxS5VOmwBPf/xHdT8oSjkZ+bH3HHyd1RgFXBWh87Vuhi2628B+k+
         Fo0bNboWglVExCsUVuEbeeRaF8OP+wgXao7nI/iqO/f2ZrhvsSvkSrVr71VRSXxHQrSO
         VWoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DwS/+hK12guveBlDc0k/tfmSaMKjXmOKMIE7+SMTOhU=;
        b=kdetUmp+2VpSmagUN8paMOkLa6SJaGPcePRfFvvRsxLtrkUG9nzHWD9b/3LURolaDU
         uvKq+ePs+lk0HY8yGJdVga9qz+7uYu/+jeixzc2FC2ancwLQUI1C1yg4/k8GA0z9cYWp
         kjAlDDrhEa/9s+GNT7xMtYk9vhOisMTzbA9+3DN/z4UAfaR7pgFSPDbuUP7l/twXQVSH
         WZtcM+1AguzTNvDpwR0w9LDqLwAue7h4UlsDvmw0Tu2nKxqo03y42u+2BuRAVQEP/9Rm
         xh3B29pWN15Gxa1NzFVJZ/ivkqDCcIrdQOVDvCfqsuRl07X6B53BZTAcqvQN3K4LgwOr
         5R6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="KTwb/ogr";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DwS/+hK12guveBlDc0k/tfmSaMKjXmOKMIE7+SMTOhU=;
        b=a+FsANktUYiG2uV1ulfGbbF02SGyjkNehqizx/5PrgQJfA27Qgg5BjNQTdAqimItGc
         DQygJ9+r54osviTCJYo16QAFHddWFN8sjUnd6gAPCh6/9Nebf+JIilJlCzIuqrhIRnQ/
         GhrofUFZ+1EucM0HpQn5pgcO/vrmLHgWX4Q+X8o4lsU4B6bPGYOaKsx2nC7eQgpThDRQ
         PfFuN9/zPf+V3/1L5G5jN2ZaC7lcjxokmqgj+eHqa4OVoMVr95dg5UkGG2RHGfWjS8D4
         V9TUU0VwI5n5Ogs6Nc6Oi2jAUflfXipKjthVxVBmb7U6UaQen7FP55wsDuRobJcrU5P8
         1LBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DwS/+hK12guveBlDc0k/tfmSaMKjXmOKMIE7+SMTOhU=;
        b=o3e4nvHr/ZMnccerhgLT/SfU9epHsh2j5FdvI8jeU5fSg7d1K79ZZh38UFreJA2vm1
         gC/KXXuhn2STSmtkDPOv8FDX443ENKfGh80hJfdKD/3HaXyXP3/+AMto1wcjUVoxsu6y
         YrLYjYwLCkJ6KvYpxHFG0PmNEZEV1rFq1Z1kODqqnl+nz/C2I1R8JNAh9vBXGITzyYk3
         8nee0Eo3av/aBb5A64w+ptz7qRzdo8JNu82Wxq9/TOFTzEwTW7EdfQXRQC1lGaxKEb9W
         meFakFZmctYH9RhxUsa3gN944hahlL8eRnuv2CanJ/IjtBmoOVa6KdmjZpURvykc44Ok
         0bXg==
X-Gm-Message-State: AOAM533SitTMfsmfWyL+iky1ws87x7zHlGWcx2cdcUvIhH6kz3DTIGGj
	i7qieS7F7xGLcmYlgkD2cnI=
X-Google-Smtp-Source: ABdhPJx2McXEE6pLxvGbYLPar4LYqjLshnub4yyQZpxWexa8KrbEZFNpg7hXDn9/MvlgtYvj7zDFYw==
X-Received: by 2002:a25:ea54:: with SMTP id o20mr22046220ybe.209.1633436227892;
        Tue, 05 Oct 2021 05:17:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9788:: with SMTP id i8ls8465538ybo.4.gmail; Tue, 05 Oct
 2021 05:17:07 -0700 (PDT)
X-Received: by 2002:a25:da82:: with SMTP id n124mr21160838ybf.310.1633436227380;
        Tue, 05 Oct 2021 05:17:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633436227; cv=none;
        d=google.com; s=arc-20160816;
        b=YJNmlDTb2cfDb+Roqy/O1AgouZdlv43qeKM8cXT1wa/u6ckGCSMbUYtqLQB+Q+NdM1
         86Ic5g2yjuC++0H7D3vY/3/7sYFWxyA50GaulwMhqbAB3KePSW/CEPAxZLCUTBeDy3ag
         pR3QKHTkp+iuaLntfH6fAJskSI5QG26Cs5s4ftIZi+sJsEOa6/+XTUthygNU+1mHMJ6V
         CX/rjlllQYlGiA5fQGo7+5kJKSKgOzAZ3bZ18ocboBJMZETMGHd/YOk24STRsZs7OLjM
         unriuGTZQKY6iOnJOt4Ejum2daA+O9Lvp8oILJWPwk2gIPWr6lt00kRFxpYWkUH2O1zM
         3XeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qtirudvd3CXF1rYRgKYcpMfzejgCL2epG1sP1VQEe9s=;
        b=wWInE9ntnr4ft5CbrsrVZDIhdptKWTxND2/Su/h4+56P7bFitp+lhoKsVlPFTZ2ZDk
         CfmX4qXmQBTvYAQ4uYN4KnbHilhaGOgbukGb6jTZHC3Ztg/yHMfbETShrNnpYMKZb4DH
         2j3cbXew6wPNGdtYTvv1tW04yhL13JGg1H3Nmkg5xZcEzvjyovKVxVwZM3FL4dTfQUEY
         5+qC4C3/kcx2+0FJmdOuSETBVjpepAYE/JiC9FXQPkYBmaO3ilknCgLhr3pAtAL37uO8
         hHiH/NIlnZTkFurZjcxt5Gb6j/SmAIbHxwKMb+fXQJ+BvOgfl0mPkkh4m3/FUI7gV0QG
         ZDvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="KTwb/ogr";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id s2si1309484ybk.0.2021.10.05.05.17.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 05:17:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id 5-20020a9d0685000000b0054706d7b8e5so25598598otx.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 05:17:07 -0700 (PDT)
X-Received: by 2002:a9d:3e04:: with SMTP id a4mr14216116otd.329.1633436226924;
 Tue, 05 Oct 2021 05:17:06 -0700 (PDT)
MIME-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com> <20211005105905.1994700-17-elver@google.com>
 <YVw+4McyFdvU7ZED@hirez.programming.kicks-ass.net>
In-Reply-To: <YVw+4McyFdvU7ZED@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Oct 2021 14:16:55 +0200
Message-ID: <CANpmjNO6H2imqsGaLYqimm0POvqA65Pd3OYji-QzONMn=Ht6Og@mail.gmail.com>
Subject: Re: [PATCH -rcu/kcsan 16/23] locking/atomics, kcsan: Add
 instrumentation for barriers
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E . McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@kernel.org>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="KTwb/ogr";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Tue, 5 Oct 2021 at 14:03, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Oct 05, 2021 at 12:58:58PM +0200, Marco Elver wrote:
> > @@ -59,6 +60,7 @@ atomic_add(int i, atomic_t *v)
> >  static __always_inline int
> >  atomic_add_return(int i, atomic_t *v)
> >  {
> > +     kcsan_mb();
> >       instrument_atomic_read_write(v, sizeof(*v));
> >       return arch_atomic_add_return(i, v);
> >  }
>
> This and others,.. is this actually correct? Should that not be
> something like:
>
>         kscan_mb();
>         instrument_atomic_read_write(...);
>         ret = arch_atomic_add_return(i, v);
>         kcsan_mb();
>         return ret;
>
> ?

In theory, yes, but right now it's redundant.

Because right now KCSAN only models "buffering", and no "prefetching".
So there's no way that a later instruction would be reordered before
this point. And atomic accesses are never considered for reordering,
so it's also impossible that it would  be reordered later.

Each kcsan_mb() is a call, so right now it makes sense to just have 1
call to be a bit more efficient.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO6H2imqsGaLYqimm0POvqA65Pd3OYji-QzONMn%3DHt6Og%40mail.gmail.com.
