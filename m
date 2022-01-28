Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJEF2GHQMGQEIQRPQWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B20E4A00CD
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 20:23:17 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id s5-20020a635245000000b0034ea48b7094sf3859354pgl.12
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 11:23:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643397796; cv=pass;
        d=google.com; s=arc-20160816;
        b=WBqTRepayRLVT91Yaz5Zxai4ErW37lQ+C+4jGoEPsuXfzFBIZbIXAxcCr2PF85w59m
         Hx8sqngi1HLrvUE99OXS9WBWNKSfcDH1Kazt295Ub0a775vlwyAC7gB3yWv+3yzPBHqH
         cxS8ENhZLems5AwjYfQGTapnouqh72UN7+rR/0ZTSa9HYpsQ/eCe2Rj2ote+vLz6NQeU
         A0uMZ8L5GoejoBXzYunFskDw7xBpClEbXwBl0RJdiSVzFJqUqr9LIe2KNMeaJJtN8Y4H
         7EcOruxImoOw9onXQ51NCKgFGomXijP383bNHm2+gNdtbV1GqKe5s+itCSmUo8V9TXhz
         c9Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tsJiqccHNHktbL63/5Syf+EwVInIcKp5BgZJC9zDhpU=;
        b=EuXZTsxanyAHTo2li7lrygk8qOStcbOy9oY2t/ZvoSz42Mzs7fGiAK0LJL2bvg/GhA
         8oVi31KvFPUWiat2kGvO3xVOW9lV2mdE3ZMuOdP626G7+oqeSvaM/kk1LO9qWLmGd/VC
         Ezufy/zFlDkcRhSCLjRgvrR8I6n3HrdgQadEvZabzZ9mknqwIdoM7Yf8H3OzJFJSaHyH
         R2ZvM8fJvJImIH22qsrf7NhPOVC5vfBvjb71rhGnZSbLsvOWGmdzlzG3ENbMDntQ+txK
         z43zpgLT3NuKKbaM66wgmn77L/NFcwzqL9tjL+oUlj9xLVU/Z0frcyFIVUwHJ6UG8DsD
         sSjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iUhb6agj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tsJiqccHNHktbL63/5Syf+EwVInIcKp5BgZJC9zDhpU=;
        b=MRjlIR2oZK/4p+5OZ72JprITrzrsJbGRlK+CP4zr8jr/X+R2tkefq9UsLQAi15gaqg
         RX/Qmtdl7cMWWGi1UgiHqCRS7s9ysOjZ4vt+rz/Zuzaksm1PX3wqINi/jalXinmdp0Zp
         ekmq7WMNy0p92HYdofiEWlGhlCYn62cBggErMM8xB+d2gJmSmRL3OOGIckZnHxhCHRE/
         BZyGDQQL4U2cr7f2w7QmMyX0mcK+Vc8/v1Jqy9VSR0m2y/PO7uswULmsUEIkp2h2qjn9
         1uzKWFiqFHs3ZaSxSbUTeU0F22gjdvy02W8aOEBSo9DTTV/YEy14iosdCqSGGz1S4Cqt
         O54Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tsJiqccHNHktbL63/5Syf+EwVInIcKp5BgZJC9zDhpU=;
        b=Eoxwck/sCKLI7vBUlb9mbhr61fnJcYc5yELfJ2nDzhWgPj/WYUxezNx35SErM0IlEy
         AKY1711uTuz7hODLcQVjxy7bGaiTTuXgztS54ipaZ7+0fc/ARczf/Wu3tWDDLDkhp/NB
         yq+IPZafw8rE7AKldH6z2+CgphvJA5mVLB8MjXbli7OtDmQGb+G4aPRd0dch9srge6Wq
         xxf+hSaAEle9DyKDfyJPhRT5w8FAZ25qs9WPYsbtDQsSIHUMZi+bY2wkUlnDBXAjBLLe
         wTUC6mEBxQKaTLh8Zwge7qmKFZKqjWt/W5+rx9/9bqJ0X3EuXyLIFmON+Ky8wmc9d7uG
         3E3A==
X-Gm-Message-State: AOAM532q0eUisO967z2T2cEWHKV2JK3CH2eD2FVMblK+ZCjQQ8+R3XN4
	MDfqbsZB6H5Dl8Uk7HUYIy0=
X-Google-Smtp-Source: ABdhPJwrxCJ2h0wqsUUIf+4v/6tVG6MWqykOrs0K26M2egI6CISBse2bun77hn4yX091E8ZFY9+N8Q==
X-Received: by 2002:a17:90b:3e82:: with SMTP id rj2mr21254694pjb.206.1643397796237;
        Fri, 28 Jan 2022 11:23:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:cecb:: with SMTP id d11ls6659993plg.7.gmail; Fri, 28
 Jan 2022 11:23:15 -0800 (PST)
X-Received: by 2002:a17:903:28c:: with SMTP id j12mr9661100plr.10.1643397795541;
        Fri, 28 Jan 2022 11:23:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643397795; cv=none;
        d=google.com; s=arc-20160816;
        b=dow6rsT3gdR6qxLJ0bBXOIKG1CZ5McWtm5Sp6XQK7QcLQPEBqY/D7hCaDy/VFdWrfw
         ThUGNzzKqf4/iypEZN8z7YWpU6Exh+EIoGkmb8gWcFV6Eu7hAjGnyf08zguNvzG+vNhH
         f+1zRo+ZSXfIA84+/IAA5g5IS1YWMpt+0ctvFOJjiGyNuCZjYPdAgpC/R7ZNiO6hlRcM
         0hLGL01JMNW8vhDmbjFIqmE+snETHddfReL2Lo7inIf/euGZJHmHl5zylQVpBezV5WgD
         wJpQEt1wL2Ioz6qFk848YTa4W5cc/QnXIZ6rNubCNH86tYlS5t1MyXwGFHfeP3z2zEh+
         WdDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FV7ijIEFX2KU+OD0295yjVLA5VTPNJCCnKWoIm2Gjp4=;
        b=VHc4jbIVdQx08G8WPMpoOiwPnRQNcYDEB4OW+0cwtVpwreha719pqTyGZbxB7dEa/i
         6O2BGrgbq2bqygO985IqxIr/4/CgR6q8ck3qSO1bcHbqmkvQXkXEpRrhpN0CuAmP2SHJ
         hOJDIiegbEZ37OX6N/+LIKE0F+QaK02YmQmjkW36iJjyurkiNje3II8PKvftVRvjCmlP
         h98IVz4Q62/YTK0e+hm1afrQ0CVsCwJ1QTAjZPJS1shx39zgE9zVXO5SYRjxAOO9GxVQ
         CD9uFDiF6e2s9yWr0GphtZMFvelhYXJ8IYImL4lO4LCiDuL5I9K2Tv2DcxjiecxUVvQ9
         GfyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iUhb6agj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id i22si2128pju.1.2022.01.28.11.23.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 11:23:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id e81so14193791oia.6
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 11:23:15 -0800 (PST)
X-Received: by 2002:aca:2b16:: with SMTP id i22mr9759910oik.128.1643397794720;
 Fri, 28 Jan 2022 11:23:14 -0800 (PST)
MIME-Version: 1.0
References: <20220128114446.740575-1-elver@google.com> <20220128114446.740575-2-elver@google.com>
 <202201281058.83EC9565@keescook>
In-Reply-To: <202201281058.83EC9565@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jan 2022 20:23:02 +0100
Message-ID: <CANpmjNNaQ=06PfmPudBsLG7r9RsFXYo-NQR4CSM=iO11LFSHKw@mail.gmail.com>
Subject: Re: [PATCH 2/2] stack: Constrain stack offset randomization with
 Clang builds
To: Kees Cook <keescook@chromium.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Elena Reshetova <elena.reshetova@intel.com>, 
	Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iUhb6agj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as
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

On Fri, 28 Jan 2022 at 20:10, Kees Cook <keescook@chromium.org> wrote:
[...]
> >       2. Architectures adding add_random_kstack_offset() to syscall
> >          entry implemented in C require them to be 'noinstr' (e.g. see
> >          x86 and s390). The potential problem here is that a call to
> >          memset may occur, which is not noinstr.
[...]
> > --- a/arch/Kconfig
> > +++ b/arch/Kconfig
> > @@ -1163,6 +1163,7 @@ config RANDOMIZE_KSTACK_OFFSET
> >       bool "Support for randomizing kernel stack offset on syscall entry" if EXPERT
> >       default y
> >       depends on HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
> > +     depends on INIT_STACK_NONE || !CC_IS_CLANG || CLANG_VERSION >= 140000
>
> This makes it _unavailable_ for folks with Clang < 14, which seems
> too strong, especially since it's run-time off by default. I'd prefer
> dropping this hunk and adding some language to the _DEFAULT help noting
> the specific performance impact on Clang < 14.

You're right, if it was only about performance. But there's the
correctness issue with ARCH_WANTS_NOINSTR architectures, where we
really shouldn't emit a call. In those cases, even if compiled in,
enabling the feature may cause trouble.

That's how this got on my radar in the first place (the objtool warnings).

So my proposal is to add another "|| !ARCH_WANTS_NO_INSTR", and add
the performance note to the help text for the !ARCH_WANTS_NO_INSTR
case if Clang < 14.

Is that reasonable?

Sadly both arm64 and x86 are ARCH_WANTS_NO_INSTR. :-/

> >       help
> >         The kernel stack offset can be randomized (after pt_regs) by
> >         roughly 5 bits of entropy, frustrating memory corruption
> > diff --git a/include/linux/randomize_kstack.h b/include/linux/randomize_kstack.h
> > index 91f1b990a3c3..5c711d73ed10 100644
> > --- a/include/linux/randomize_kstack.h
> > +++ b/include/linux/randomize_kstack.h
> > @@ -17,8 +17,18 @@ DECLARE_PER_CPU(u32, kstack_offset);
> >   * alignment. Also, since this use is being explicitly masked to a max of
> >   * 10 bits, stack-clash style attacks are unlikely. For more details see
> >   * "VLAs" in Documentation/process/deprecated.rst
> > + *
> > + * The normal alloca() can be initialized with INIT_STACK_ALL. Initializing the
> > + * unused area on each syscall entry is expensive, and generating an implicit
> > + * call to memset() may also be problematic (such as in noinstr functions).
> > + * Therefore, if the compiler provides it, use the "uninitialized" variant.
>
> Can you include the note that GCC doesn't initialize its alloca()?

I'm guessing this won't change any time soon, so probably adding it in
the code comment is ok.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNaQ%3D06PfmPudBsLG7r9RsFXYo-NQR4CSM%3DiO11LFSHKw%40mail.gmail.com.
