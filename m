Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIUB5D3QKGQEOBSKETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5807520CF46
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 16:54:27 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 73sf2310358oti.21
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jun 2020 07:54:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593442466; cv=pass;
        d=google.com; s=arc-20160816;
        b=FnrB5Bw5BOLASvs+phUKzQJXV8/UXvC7Pcv4eSELf+NwwoqvOqWTHzlzU/k2P5nwnF
         pET3j8QROIgc33IMlD9tolzwJhCCU7VeLwZAMPtzOjaBHIndGB04hFlQeImW8lBIBnvw
         N2s+2b9q73dOKwhZiGiQp7p57ux1W038zzbFSIXwM0SpZXorXwfzZ23mHHUDdInN4zqe
         xA/MbF9Mpp4ixn4nR+zMSqG2JL38Lh+3nnmBs74Pq/IkRVShCTEduKSG1ExuD7MgkLCr
         E35IDsoYqnHg2+leEyy8/Bp7QKviHepOUt15Mjx75JniJYZoc5CJW9icySdZK8cM5ss/
         tV4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wZIXNyM+S/Xb9V7UwrJQ5KoFIXSLKYvNEArfg9MLWSg=;
        b=TMae/geqY9Yw0oI08ZKJa6zEATSsJ0dz8RB1xrnxmSsbsAjnuPWCJOHf04OLLwRzjp
         L26TutjlQmXitjG6tutZgn6xdnHyL01IuWqNcQVshp0gyVsZh5BPPTcuv1uP99rQrzpO
         upp2X+vu8WRUvxueiMGkCJ3p3Co04GI/75bFjGcPvjTKK2QPQyC07oJJMsAUZsliK0Z3
         lfBiPiq8a/+etFpETL9F9x1BktSTb1l0J8iJJnoaCz4UFay+csYVdLQ/JRTc7p0mYr3H
         taHNkOSjF7wPRIesZ1grWU1Q9I5e+J2L0WbJegXD/OQ6RLGCc2ju8CFDR5h3o2i3M0qJ
         APOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LEw0pNBj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wZIXNyM+S/Xb9V7UwrJQ5KoFIXSLKYvNEArfg9MLWSg=;
        b=RlRJZVCDLzQhNp3LrxdnhSFPBIQWAOfTt6qx/8c92ntwGMFtz44XIo60w3xi6e/1l0
         9yyXXTYt4lOB+7p5Em41falzzMW4d8a8mrZURcL0ATIKpBSAKykX/vz+/2g39pIC7W4y
         /chmMlXORt/d6DiwzI+onRpV+RiH94hLyIPW/d43ZWq13ktUTcfHwfZzn+LMQzfTlJc+
         VISgYhKcsMJH0JLsDMIBz/R+xdDRJw6z3pKFE10aOSY46t++YIPTVgrg3JupGBfTEQY6
         jg6x1M0QaTzS8/QNOtOYzQLU/OhgsDSqkjnObIKY5OQSH+JDogG+IjpPootnwb7HDaRH
         h3xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wZIXNyM+S/Xb9V7UwrJQ5KoFIXSLKYvNEArfg9MLWSg=;
        b=VBHSja7k1FTAhsGWTYPlop40nCmMmG557tWHl9f6CWEuPzPYqV6Cf44hovFL0nkME0
         7SYu1fXtPjM2xt8Se6EwLCVut/g9d/BeXvhMjf88vL+mA5nRs23qpotiBUwYOr4qSPA7
         pelqTrr2qFZVZG4B72Grxv+/LveNdm8d6w9sFESHoqsqnG7tWuvzY3st6TTGqEqcQ7gf
         S7jOIK7y1qFhJPadW85D9srFdB8n2AXgH2iVmYr2SN6Y1LmnDiuMla3AoDG58NpjdFR4
         tqXUzah5TMJj6Y/Gmx5kcecgdFv3jsAfygcBzFTakE8N84oOiV0icRQn8bjyldrDImSN
         GbLA==
X-Gm-Message-State: AOAM532P0FzOL2fxB/+NT14F8KF7aQFA1tYg57uJqAiZbB73wyM7eJh5
	b/+Y67hgyEP005eEfvg8nt0=
X-Google-Smtp-Source: ABdhPJz3hfHz8YekwbqOS0MqyS2Q1TDM8AaSFUBHX8KRJadtdIMi+CjPe/NV9lyqrPbAMfMm/mZNNQ==
X-Received: by 2002:a05:6830:1093:: with SMTP id y19mr14168884oto.204.1593442466250;
        Mon, 29 Jun 2020 07:54:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:dbd7:: with SMTP id s206ls3335672oig.6.gmail; Mon, 29
 Jun 2020 07:54:25 -0700 (PDT)
X-Received: by 2002:aca:6004:: with SMTP id u4mr12833074oib.106.1593442465816;
        Mon, 29 Jun 2020 07:54:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593442465; cv=none;
        d=google.com; s=arc-20160816;
        b=vtzRouqN4PvDQLbGFZ2M+AfM3GKGTSOT4EiVBukqF5WCpLC+QMfBSZSIqULivx5HWq
         lIEhczqx83VveqtNKZ0Kqo4wy4iLwXMnD1opUwgbmCeJXQpTWve9W119tGA890mz7s+U
         Kh4a2qEynwqp5hnw+palXhVDSSMgMyeptd2WWutoWzJGK08E4ZsCQgJ4FOLSEDJdw61u
         9hvlMCqWSiIu2JC2c6LxGdPSmP2WsPpPO1wsr2XLj4Ex8i96PiSXk/7YGawL6n+P9e6H
         7xtZmIOYVUlgamxqLCNiBLxofKAqIBQ2bBCP3NnaFft2adqpN81Z5+jXCVNok2DDKija
         ZS1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VYgNM/DVHPEkntLU/yBA/5PMKk3x04iIvLdywNiIUKs=;
        b=IFvzK43/sc9RsaMeJwDDkWHzh2PdJLeKScqYI3ofPPuYJCyyBQcc2vScZlPTFUojL7
         Sq7isD0awo4haMF5dzq+pHEDn9JPtJ6IgTyV0TWdllhQJA9W3hKYGOsghz/sfyt/02fL
         1+N1kqtd7cPuGcXpRBURDpApjb0NqdIhMIconp3UqJLjJVTe5BQLHbCEme6//Lhm7e6Q
         BdNrBj4hFJPfNfiY6kkG4lIL6vFpoe+jlz74WHiQURYonVxIHicc/HE/vv/1VhP7vF6y
         2fP+Pf2/npPzl4KkCtX5GKxjVm0KpcU+D1jaOP5QoduwlwWKMbPUAHwasoAFuI4/kYiW
         Bktg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LEw0pNBj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id l14si2140otn.5.2020.06.29.07.54.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jun 2020 07:54:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id 76so1335418otu.9
        for <kasan-dev@googlegroups.com>; Mon, 29 Jun 2020 07:54:25 -0700 (PDT)
X-Received: by 2002:a9d:638c:: with SMTP id w12mr12713578otk.251.1593442465246;
 Mon, 29 Jun 2020 07:54:25 -0700 (PDT)
MIME-Version: 1.0
References: <20200624014940.1204448-5-keescook@chromium.org>
 <202006250240.J1VuMKoC%lkp@intel.com> <202006270840.E0BC752A72@keescook>
In-Reply-To: <202006270840.E0BC752A72@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jun 2020 16:54:13 +0200
Message-ID: <CANpmjNMtFbc_jQU6iNfNx-4wwQF4DY3uaOB1dCPZ3dMqXx6smg@mail.gmail.com>
Subject: Re: [PATCH v3 4/9] x86/build: Warn on orphan section placement
To: Kees Cook <keescook@chromium.org>
Cc: kernel test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	clang-built-linux <clang-built-linux@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LEw0pNBj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Sat, 27 Jun 2020 at 17:44, Kees Cook <keescook@chromium.org> wrote:
>
> On Thu, Jun 25, 2020 at 02:36:27AM +0800, kernel test robot wrote:
> > I love your patch! Perhaps something to improve:
> > [...]
> > config: x86_64-randconfig-a012-20200624 (attached as .config)
>
> CONFIG_KCSAN=y
>
> > compiler: clang version 11.0.0 (https://github.com/llvm/llvm-project 1d4c87335d5236ea1f35937e1014980ba961ae34)
> > [...]
> > All warnings (new ones prefixed by >>):
> >
> >    ld.lld: warning: drivers/built-in.a(mfd/mt6397-irq.o):(.init_array.0) is being placed in '.init_array.0'
>
> As far as I can tell, this is a Clang bug. But I don't know the
> internals here, so I've opened:
> https://bugs.llvm.org/show_bug.cgi?id=46478
>
> and created a work-around patch for the kernel:

Thanks, minor comments below.

With KCSAN this is:

Tested-by: Marco Elver <elver@google.com>


> commit 915f2c343e59a14f00c68f4d7afcfdc621de0674
> Author: Kees Cook <keescook@chromium.org>
> Date:   Sat Jun 27 08:07:54 2020 -0700
>
>     vmlinux.lds.h: Avoid KCSAN's unwanted sections

Since you found that it's also KASAN, this probably wants updating.

>     KCSAN (-fsanitize=thread) produces unwanted[1] .eh_frame and .init_array.*
>     sections. Add them to DISCARDS, except with CONFIG_CONSTRUCTORS, which
>     wants to keep .init_array.* sections.
>
>     [1] https://bugs.llvm.org/show_bug.cgi?id=46478
>
>     Signed-off-by: Kees Cook <keescook@chromium.org>
>
> diff --git a/arch/x86/Makefile b/arch/x86/Makefile
> index f8a5b2333729..41c8c73de6c4 100644
> --- a/arch/x86/Makefile
> +++ b/arch/x86/Makefile
> @@ -195,7 +195,9 @@ endif
>  # Workaround for a gcc prelease that unfortunately was shipped in a suse release
>  KBUILD_CFLAGS += -Wno-sign-compare
>  #
> -KBUILD_CFLAGS += -fno-asynchronous-unwind-tables
> +KBUILD_AFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
> +KBUILD_CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
> +KBUILD_LDFLAGS += $(call ld-option,--no-ld-generated-unwind-info)

Why are they needed? They are not mentioned in the commit message.

>  # Avoid indirect branches in kernel to deal with Spectre
>  ifdef CONFIG_RETPOLINE
> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> index b1dca0762fc5..a44ee16abc78 100644
> --- a/include/asm-generic/vmlinux.lds.h
> +++ b/include/asm-generic/vmlinux.lds.h
> @@ -934,10 +934,28 @@
>         EXIT_DATA
>  #endif
>
> +/*
> + * Clang's -fsanitize=thread produces unwanted sections (.eh_frame
> + * and .init_array.*), but CONFIG_CONSTRUCTORS wants to keep any
> + * .init_array.* sections.
> + * https://bugs.llvm.org/show_bug.cgi?id=46478
> + */
> +#if defined(CONFIG_KCSAN) && !defined(CONFIG_CONSTRUCTORS)

CONFIG_KASAN as well?

> +#define KCSAN_DISCARDS                                                 \
> +       *(.init_array) *(.init_array.*)                                 \
> +       *(.eh_frame)
> +#elif defined(CONFIG_KCSAN) && defined(CONFIG_CONSTRUCTORS)
> +#define KCSAN_DISCARDS                                                 \
> +       *(.eh_frame)
> +#else
> +#define KCSAN_DISCARDS
> +#endif
> +
>  #define DISCARDS                                                       \
>         /DISCARD/ : {                                                   \
>         EXIT_DISCARDS                                                   \
>         EXIT_CALL                                                       \
> +       KCSAN_DISCARDS                                                  \

Maybe just 'SANITIZER_DISCARDS'?

>         *(.discard)                                                     \
>         *(.discard.*)                                                   \
>         *(.modinfo)                                                     \
>
> --
> Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMtFbc_jQU6iNfNx-4wwQF4DY3uaOB1dCPZ3dMqXx6smg%40mail.gmail.com.
