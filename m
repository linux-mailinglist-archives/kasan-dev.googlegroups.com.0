Return-Path: <kasan-dev+bncBCMIZB7QWENRBLGDYL7AKGQE5U5MNNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 658B22D3F81
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 11:06:37 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id t8sf773805pfl.17
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 02:06:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607508396; cv=pass;
        d=google.com; s=arc-20160816;
        b=f1SkTxGVQdejiddAfEVwdq8t/FuuDmGHIj4YKONs+RS2msnlzqGVb7pKIi7pdo9e5/
         ZPFk2iLvgeIslQX7OWfaCOIMgi91mMjZyxP8gH8wOiC3jQhK/Pez3baKTGOT9p7hpeMZ
         JwHGy2AturRWM8NtvgC5z5BfNDvnpAiJmsqTwp4/mllNTU+ZFLu7GJj9M+3rB/dfErRD
         zYxXT34IzTybmpjVJZsJlRQlee8eeMUiNQYDkeNblNCt7yR+vBfVDzElV7IorY3kqzuC
         jJyeTwebq1xXFjC2nc59JyW+rwlKouE46n17Eos3IuQGO+dMhIQLOvxrdC0+TxqSCRRV
         +eyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GVDohUIv1lfjjx7Qh6IEDt46J7ajzA9UMx+xyzHkF0M=;
        b=U4cT1Dw8R+wlVTx+svx25yfLJSl1S1ICL2vAkf51wc1+cuoNqq7y/lke+bfX0jVZPu
         F3FNhcJT3rZjsG8com6mJNqBL7XI93tEDL66V22oUPLm4IFH87JJkhZe8/hIcAxE1cn6
         fyiGbnRHhaofLLyam3i3SDf/BvMYwtqvONwX6h1T/Ch6fTgqmfubxfcpBiegcIBjSyMY
         ewQ6z/NBSGa/8mhgBP6NEmygRckR1vTNA6ntI+Od++PzR0mJ02V+msq8sTqtmkAcsyZd
         bX14PF5QVJpghKLuYVaPCgxaoi6cawejlF7ZHNh1vQzxhcVSFm2gQo4GAQmcp/3wX++d
         d3Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MjKkDaOW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GVDohUIv1lfjjx7Qh6IEDt46J7ajzA9UMx+xyzHkF0M=;
        b=geo1Ylsfkwxemx5xmbqAyAYvJNBQZUaIiBObm+/13sbLVTfGw3iYlWzHJbU6swexJN
         B4bvjHwKFYXKOo9zVYhfioVNxX38Os5au06Um6KrLR64exCs1Qklh8ty0hILL5jNDgWP
         FPCGFRjShoQzSHnMqDvQk2oyH0Cyiji7gfL4q1qaY89Av8KB2749eg+rbYGXGEUv7pSc
         DMX77qF4CmL/KLviWE+7l0phCfV17v4TaQ9Vvd5O7z40yNgV+hB3GXr4rnjPm5iGNjM9
         Zi5MGmNXx6B9Xf5g0RCF50I0t1P6vwTEmEySgLuKEBN7y1QXvQvseCkosJYYMhnaN3eP
         H2EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GVDohUIv1lfjjx7Qh6IEDt46J7ajzA9UMx+xyzHkF0M=;
        b=EtCxhapeBLHVyeFjxdSNEwEYqeVLZKL0D/dia4y58DUIWN0UvYlHJi1hEq56ywbfUd
         atq5L9HMvfr/bzfZUzHzir9q+qoaI7dlmOc5MUGJbVyvdyAPN4FawmRK8Qf0bVWg9G2O
         QqJKG4RJNVFUi4dAz4xvaBQt5lnMHuqL7/bp5uInLRs36oa0R+i0Eorw6hx+ISw5LYSM
         lPNZxIdWgWoGBzaxA0B/IBhV8tkKWdTSgfTwB3PWjV9VL2HIPldVqYdRNnT4WIub9XU9
         c1BqcpwiBnoLUmuP5gnFiyPwivEvqZgTGe3Nh3iP9/uir343h2na0V1rDPvCsmT685e8
         iinA==
X-Gm-Message-State: AOAM533bi782jpaNyjHx+GjiZn0iTb6I10NpiJmAAWGG6ARHb3ZuZfsH
	ZuVOw7NDDs7AQUSwhw/JW0U=
X-Google-Smtp-Source: ABdhPJyMlIhoUECXDZrzCH79zRnQBA5h/t7cTaEzuXsH4s2m8BH2kMS8EeO3nSJlPoVWsFIdr3NlGA==
X-Received: by 2002:a63:540d:: with SMTP id i13mr1315679pgb.37.1607508396177;
        Wed, 09 Dec 2020 02:06:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls643804pld.8.gmail; Wed, 09
 Dec 2020 02:06:35 -0800 (PST)
X-Received: by 2002:a17:90b:34f:: with SMTP id fh15mr1550841pjb.56.1607508395669;
        Wed, 09 Dec 2020 02:06:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607508395; cv=none;
        d=google.com; s=arc-20160816;
        b=TMErQpiKIeeMecIe4aKujmZZIlDy2R5aBzKTpn6FvJn3mfQTRIkxFkjcQa3/egDlJx
         GTX09Pl3Yc1t+y8ni/20aH2vbYtSFlEnAu9xvQBA05yLkd/skTNHL0eP7mGTfWAX2r/X
         FjWpRnUowc2/4sDXt333vJgrvOZyJDOHh1JTPhHuKwtm8Jy5yWJtaT9drBLEaBLY2h6E
         TTBAG94zVcW6E7CoGmErzNwHH0IPrANw9tLNNRYT3TdyUnsTeswQy9msfPrIDLkOr21k
         2K1Rgs01zhj5CCIzTq88AKI0WfC6op+8BnwPOD15DoB4VRdXBqKGvJjbigdx5XgsQdS3
         7pPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+5z+13xz88XeLJl7OiuxcCFkjcYyny+A4YZW2csEjQM=;
        b=TAu15j1LXW0gKU01Rvxo2bZjMJLuaMQojmKfAUaXNyNpkTv/hu0taC3yeDUgasIlNa
         9JtucDZwpUSPV7Fe8sQ2MRL8t4FbydNZt5pvi9f+RcaRYAfb4SjEVx68fNXBQO2pHTAr
         KBrDojY+f2fdBbD+kDTlZncbz8yqlu3QJy8ji4uoN41H7PZMHXhgpzUfjG9vI9tRn/1r
         +HSnhnDCF3qYSoHtaG+LZnkm4c02258+Fj8F7mwX6dp1aGkbVe2Tx888TynbzhqJmf/p
         1PDPYaZgOrO65g5yV8sGzhQ93p+f4keA8k9WLxDBcRcIwuh9SN/Dp6Ap/HQ6x8yqrbVu
         Rl8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MjKkDaOW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id y68si81857pfy.0.2020.12.09.02.06.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 02:06:35 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id q22so681516qkq.6
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 02:06:35 -0800 (PST)
X-Received: by 2002:a37:56c6:: with SMTP id k189mr1948333qkb.501.1607508394588;
 Wed, 09 Dec 2020 02:06:34 -0800 (PST)
MIME-Version: 1.0
References: <20201204210000.660293c6@canb.auug.org.au> <20201204211923.a88aa12dc06b61780282dd1b@linux-foundation.org>
 <CACT4Y+bYVC=r+bPF7MziOZpJCYqrUj7CFt47Z5PSWjohZLYm+w@mail.gmail.com>
 <CACT4Y+bPPSQ1OgZ1NmUckOO2=07RE3C=deW6BpF0cOR9wnJsoA@mail.gmail.com> <CANpmjNObNia7mFFJDz6ofG06QOTzad=iU=b_C=E97nV2hB-hng@mail.gmail.com>
In-Reply-To: <CANpmjNObNia7mFFJDz6ofG06QOTzad=iU=b_C=E97nV2hB-hng@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Dec 2020 11:06:22 +0100
Message-ID: <CACT4Y+atOaQS==gJ0fDZhuh7A1d=wyd5eQ4on+hBbG5HtSQK4A@mail.gmail.com>
Subject: Re: linux-next: build warning after merge of the akpm tree
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MjKkDaOW;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Mon, Dec 7, 2020 at 1:52 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 7 Dec 2020 at 13:38, 'Dmitry Vyukov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > On Mon, Dec 7, 2020 at 1:08 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > > Hi all,
> > > > >
> > > > > After merging the akpm tree, today's linux-next build (powerpc
> > > > > allyesconfig) produced warnings like this:
> > > > >
> > > > > kernel/kcov.c:296:14: warning: conflicting types for built-in function '__sanitizer_cov_trace_switch'; expected 'void(long unsigned int,  void *)' [-Wbuiltin-declaration-mismatch]
> > > > >   296 | void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
> > > > >       |              ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > >
> > > > Odd.  clang wants that signature, according to
> > > > https://clang.llvm.org/docs/SanitizerCoverage.html.  But gcc seems to
> > > > want a different signature.  Beats me - best I can do is to cc various
> > > > likely culprits ;)
> > > >
> > > > Which gcc version?  Did you recently update gcc?
> > > >
> > > > > ld: warning: orphan section `.data..Lubsan_data177' from `arch/powerpc/oprofile/op_model_pa6t.o' being placed in section `.data..Lubsan_data177'
> > > > >
> > > > > (lots of these latter ones)
> > > > >
> > > > > I don't know what produced these, but it is in the akpm-current or
> > > > > akpm trees.
> > >
> > > I can reproduce this in x86_64 build as well but only if I enable
> > > UBSAN as well. There were some recent UBSAN changes by Kees, so maybe
> > > that's what affected the warning.
> > > Though, the warning itself looks legit and unrelated to UBSAN. In
> > > fact, if the compiler expects long and we accept u64, it may be broken
> > > on 32-bit arches...
> >
> > No, I think it works, the argument should be uint64.
> >
> > I think both gcc and clang signatures are correct and both want
> > uint64_t. The question is just how uint64_t is defined :) The old
> > printf joke that one can't write portable format specifier for
> > uint64_t.
> >
> > What I know so far:
> > clang 11 does not produce this warning even with obviously wrong
> > signatures (e.g. short).
> > I wasn't able to trigger it with gcc on 32-bits at all. KCOV is not
> > supported on i386 and on arm I got no warnings even with obviously
> > wrong signatures (e.g. short).
> > Using "(unsigned long val, void *cases)" fixes the warning on x86_64.
> >
> > I am still puzzled why gcc considers this as a builtin because we
> > don't enable -fsanitizer-coverage on this file. I am also puzzled how
> > UBSAN affects things.
>
> It might be some check-for-builtins check gone wrong if it enables any
> one of the sanitizers. That would be confirmed if it works with
>
> UBSAN_SANITIZE_kcov.o := n

Yes, it "fixes" the warning.
Initially I thought it's not a good solution because we want to detect
UBSAN bugs in KCOV. But on second thought, if UBSAN detects a bug in
KCOV, it may lead to infinite recursion. We already disable all other
sanitizers on KCOV for this reason, so it's reasonable to disable
UBSAN as well. And as a side effect it "resolves" the warning as well.
I mailed:
https://lore.kernel.org/lkml/20201209100152.2492072-1-dvyukov@google.com/T/#u

Thanks

> > We could change the signature to long, but it feels wrong/dangerous
> > because the variable should really be 64-bits (long is broken on
> > 32-bits).
> > Or we could introduce a typedef that is long on 64-bits and 'long
> > long' on 32-bits.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BatOaQS%3D%3DgJ0fDZhuh7A1d%3Dwyd5eQ4on%2BhBbG5HtSQK4A%40mail.gmail.com.
