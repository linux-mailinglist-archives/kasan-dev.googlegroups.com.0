Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIMIRT5QKGQEQ7C4E2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD20E26D3C0
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 08:37:22 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id l29sf807205qve.18
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 23:37:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600324641; cv=pass;
        d=google.com; s=arc-20160816;
        b=uK0PnaDfh6fvA2xkUWq0XkAzZKsq3SjMY6DRWc7zOedWRoKv/khMWvaGh219bKySjS
         OW2iRnIJmYYwIYL0glKm1TO5wSV0NdiMep7wRqyK6Rd4Vng5EeE6Amp3B9i7TCiafie8
         atTEBgt9ComRUAJeR5xvPciuG1FAwPMChmwqkmmUY28ICjaPYtfu4Tbqj93HlXRfCuiv
         TQGcMAsaQMAltMMkcWUFN+/S0qFCrQ13TTImriP/y9RJmftd4k8pzq8Ca5kRV/d0Gbav
         wchmlXhvzjNS+e5bmkXjFxG6p3JCQavStg2YrzSHN74SDLc28LkGlRnVFhlN1uS/wfeG
         qHyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bn2gG4w0gOK5D4OJTPAL7L5XlpcZiFvDlvCwSXNEnWM=;
        b=qynGKMZ/vuEtuJqukOgxTTGFObvKAENOTOWdUpwXNDbOqScoLSyCQKkdLnpGb76i7r
         wuNmpsNvaxGCB1uajAMDpVRTRlqisv9QpBx0PhlF6y+P/Lpz62NCymaVxJegims7y1uY
         l+RsaaGX+QeV7cyn4xXm5+hFPAMJe4dScMw98yxHPE7FlXtRLq2qFF8gDG6jp0Sxxnbz
         6g3cmj4zOtlRjSd9YLPQG8mTz86zMGVLpb/gUysPVmBq5Gx0ZCOjIdEcJvjz94+/xRsw
         XWnIER+PJaKBPgciX/lAHDsoA49JOs4/1d7w1fPff8t3k1cNkvVHb0YIXRnaN8XKpBj/
         M1Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dyKzxUO8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bn2gG4w0gOK5D4OJTPAL7L5XlpcZiFvDlvCwSXNEnWM=;
        b=MKNNiTr5Q+mmDbUCwNRn+koN2FtXlA7frun3S6pacYiFLmzsbX9zQz9eol4G9DSxJY
         EwTM87Tg143kybRhu4sEy+gigF1YXx81Rec96ZPkFJHvutmbVCXSl4j241olqCjSebFV
         sYRSxYaDz3lpm0WxG/l+Rue49830znwW7d206Z+8aGwbn8XyfBcbKEl47mO/Hb0OWIkF
         B1KHkOiLJjg9VjDAR2sJIPGtmuf+DWRz191ajxgzNOgs27ruRHgjOc4Jaro0POnv3W97
         njKs8UZkCvgh4jvoDZHqPYuWXanPjHayVxNsEeIX534Y+u5sEoN4YDd3NwOw4sg011Rd
         XwxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bn2gG4w0gOK5D4OJTPAL7L5XlpcZiFvDlvCwSXNEnWM=;
        b=p42VQXLgpI8mFk6jj/wSEdw3qkJTS0kcdgTACsu7OJQFI/5tiIPXCrbZ0uW61/x6cj
         fdvy5Z2TrHWIafQcw6Y/dxV9QUt2v8CfTbxUSTdK+BO0kdphxVVhz0lavqy3IhG5pUot
         /BB7UDiZE9hgYli/eok6CuuWfIuqKtP9sGM3fqLZaBtia2655+SHJYEmmXpSN5MhyVP/
         3+NsIVUW/8SufuAAjWZRM2/y8CgbKySeQifq86AJCHF+7TqlbvjQJ3jVXBMnaB5xms1M
         DCSqDHAn2ZzA4u1Zgl1u0UwiRq4H83iFn4V/jl6A+JKUfLRIdAguKtEt8SH1qG4scb9J
         weEA==
X-Gm-Message-State: AOAM5322fTzKuJPnpsH1xNG+CGLmeuw4ZuKP4/y5DfkXxQBozQcCpf6Q
	hckhjQ5M3RZh2ubrAtl43a8=
X-Google-Smtp-Source: ABdhPJyhD71xOEuoGATpp+10f0GdZB0uixGHeyF9DZENjeqNfrPzUUbRryMQcXifrHk9aQeoYXofOQ==
X-Received: by 2002:a05:620a:2055:: with SMTP id d21mr27979963qka.202.1600324641251;
        Wed, 16 Sep 2020 23:37:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4c91:: with SMTP id bs17ls301300qvb.3.gmail; Wed, 16 Sep
 2020 23:37:20 -0700 (PDT)
X-Received: by 2002:a0c:d443:: with SMTP id r3mr27308426qvh.20.1600324640334;
        Wed, 16 Sep 2020 23:37:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600324640; cv=none;
        d=google.com; s=arc-20160816;
        b=LPLTqQjqFa5EVrs8PHYJm9SAgQZOR6F82y19reXNvbzXuKGrfGh/8e/KLps2uP5L6d
         KPGohV9qHnTaSjlJqmfUJ12/GLHmVhxL3KTt7No/coza4TO7ftANS5c1MAUu3E7eat/H
         Z5ShBlPvlHWu6eGmqEC12NeMT98a1Z+oq534gln+SEHLKIC0vJbzX7Ywpi+rq2RlNY7m
         C1DinbVDbRLEkYbzHp+h1US/ozR+ecXeGA8D6A9b1aJ1xtzdlfLcZlhz6xjhpXwz6j2m
         a3ehNfMX2nk0ebWNkORaTJ/Z++CZjzLhgSvOOE4rJwoXQr6HOwxGbMNzN1ie1C1n2Urw
         Jy1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DmH7lVb417eXI2VeqeItQgKBp0xKHSxQ9iYZKyDox1E=;
        b=t502QaihhqsLMma0uPVKIxMnnSxD9xmVesdGPWLOL3a0ztQuxkRmTaFO4R2NN2oY+8
         YoCb65J49oXyThzMc3T1wPzX4T1S4BZB0bu9z8T41s1mROf6MSenK9ztF4JH9+TOO0PU
         lOpfM/CFRPTkeJtcY9pKASLtUoxHpvmBIHR1spyBTVExnyGLZvyZb2uVqHnlsaW8FZqT
         B4FdFAaMFBszEMVJtD9RWkp0iMlIdnNXgHgF/WjCceYMG6GJgl5KoJuMUxnxknPPdrcx
         cX77J5NlDi7jGMYUTVD0AX/IKcybV1YnSLTNsijfDv8ZfmuZN2ctF0C/L2xe9HaSXO5B
         HMpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dyKzxUO8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id k6si1229323qkg.1.2020.09.16.23.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Sep 2020 23:37:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id v20so1274102oiv.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Sep 2020 23:37:20 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr5592894oib.121.1600324639579;
 Wed, 16 Sep 2020 23:37:19 -0700 (PDT)
MIME-Version: 1.0
References: <20200914172750.852684-1-georgepope@google.com>
 <20200914172750.852684-7-georgepope@google.com> <202009141509.CDDC8C8@keescook>
 <20200915102458.GA1650630@google.com> <CANpmjNOTcS_vvZ1swh1iHYaRbTvGKnPAe4Q2DpR1MGhk_oZDeA@mail.gmail.com>
 <20200915120105.GA2294884@google.com> <CANpmjNPpq7LfTHYesz2wTVw6Pqv0FQ2gc-vmSB6Mdov+XWPZiw@mail.gmail.com>
 <20200916074027.GA2946587@google.com> <CANpmjNMT9-a8qKZSvGWBPAb9x9y1DkrZMSvHGq++_TcEv=7AuA@mail.gmail.com>
 <20200916121401.GA3362356@google.com> <20200916134029.GA1146904@elver.google.com>
In-Reply-To: <20200916134029.GA1146904@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Sep 2020 08:37:07 +0200
Message-ID: <CANpmjNOfgeR0zpL-4AtOt0FL56BFZ_sud-mR3CrYB7OCMg0PaA@mail.gmail.com>
Subject: Re: [PATCH 06/14] Fix CFLAGS for UBSAN_BOUNDS on Clang
To: George Popescu <georgepope@google.com>
Cc: Kees Cook <keescook@chromium.org>, maz@kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, kvmarm@lists.cs.columbia.edu, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, james.morse@arm.com, 
	julien.thierry.kdev@gmail.com, suzuki.poulose@arm.com, 
	Nathan Chancellor <natechancellor@gmail.com>, Nick Desaulniers <ndesaulniers@google.com>, 
	David Brazdil <dbrazdil@google.com>, broonie@kernel.org, Fangrui Song <maskray@google.com>, 
	Andrew Scull <ascull@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, Arnd Bergmann <arnd@arndb.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dyKzxUO8;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Wed, 16 Sep 2020 at 15:40, Marco Elver <elver@google.com> wrote:
> On Wed, Sep 16, 2020 at 12:14PM +0000, George Popescu wrote:
> > On Wed, Sep 16, 2020 at 10:32:40AM +0200, Marco Elver wrote:
> > > On Wed, 16 Sep 2020 at 09:40, George Popescu <georgepope@google.com> wrote:
> > > > On Tue, Sep 15, 2020 at 07:32:28PM +0200, Marco Elver wrote:
> > > > > On Tue, 15 Sep 2020 at 14:01, George Popescu <georgepope@google.com> wrote:
> > > > > > On Tue, Sep 15, 2020 at 01:18:11PM +0200, Marco Elver wrote:
> > > > > > > On Tue, 15 Sep 2020 at 12:25, George Popescu <georgepope@google.com> wrote:
> > > > > > > > On Mon, Sep 14, 2020 at 03:13:14PM -0700, Kees Cook wrote:
> > > > > > > > > On Mon, Sep 14, 2020 at 05:27:42PM +0000, George-Aurelian Popescu wrote:
> > > > > > > > > > From: George Popescu <georgepope@google.com>
> > > > > > > > > >
> > > > > > > > > > When the kernel is compiled with Clang, UBSAN_BOUNDS inserts a brk after
> > > > > > > > > > the handler call, preventing it from printing any information processed
> > > > > > > > > > inside the buffer.
> > > > > > > > > > For Clang -fsanitize=bounds expands to -fsanitize=array-bounds and
> > > > > > > > > > -fsanitize=local-bounds, and the latter adds a brk after the handler
> > > > > > > > > > call
> > > > > > > > >
> > > > > > > > This would mean losing the local-bounds coverage. I tried to  test it without
> > > > > > > > local-bounds and with a locally defined array on the stack and it works fine
> > > > > > > > (the handler is called and the error reported). For me it feels like
> > > > > > > > --array-bounds and --local-bounds are triggered for the same type of
> > > > > > > > undefined_behaviours but they are handling them different.
> > > > > > >
> > > > > > > Does -fno-sanitize-trap=bounds help?
> [...]
> > > Your full config would be good, because it includes compiler version etc.
> > My full config is:
>
> Thanks. Yes, I can reproduce, and the longer I keep digging I start
> wondering why we have local-bounds at all.
>
> It appears that local-bounds finds a tiny subset of the issues that
> KASAN finds:
>
>         http://lists.llvm.org/pipermail/cfe-commits/Week-of-Mon-20131021/091536.html
>         http://llvm.org/viewvc/llvm-project?view=revision&revision=193205
>
> fsanitize=undefined also does not include local-bounds:
>
>         https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html#available-checks
>
> And the reason is that we do want to enable KASAN and UBSAN together;
> but local-bounds is useless overhead if we already have KASAN.
>
> I'm inclined to say that what you propose is reasonable (but the commit
> message needs to be more detailed explaining the relationship with
> KASAN) -- but I have no idea if this is going to break somebody's
> usecase (e.g. find some OOB bugs, but without KASAN -- but then why not
> use KASAN?!)

So, it seems that local-bounds can still catch some rare OOB accesses,
where KASAN fails to catch it because the access might skip over the
redzone.

The other more interesting bit of history is that
-fsanitize=local-bounds used to be -fbounds-checking, and meant for
production use as a hardening feature:
http://lists.llvm.org/pipermail/llvm-dev/2012-May/049972.html

And local-bounds just does not behave like any other sanitizer as a
result, it just traps. The fact that it's enabled via
-fsanitize=local-bounds (or just bounds) but hasn't much changed in
behaviour is a little unfortunate.

I suppose there are 3 options:

1. George implements trap handling somehow. Is this feasible? If not,
why not? Maybe that should also have been explained in the commit
message.

2. Only enable -fsanitize=local-bounds if UBSAN_TRAP was selected, at
least for as long as Clang traps for local-bounds. I think this makes
sense either way, because if we do not expect UBSAN to trap, it really
should not trap!

3. Change the compiler. As always, this will take a while to implement
and then to reach whoever should have that updated compiler.

Preferences?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOfgeR0zpL-4AtOt0FL56BFZ_sud-mR3CrYB7OCMg0PaA%40mail.gmail.com.
