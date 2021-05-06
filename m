Return-Path: <kasan-dev+bncBCQJP74GSUDRBOFIZ2CAMGQEG5BTYUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id EEF7F374FB2
	for <lists+kasan-dev@lfdr.de>; Thu,  6 May 2021 09:01:13 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id u13-20020a17090a3fcdb0290155c6507e67sf2459474pjm.6
        for <lists+kasan-dev@lfdr.de>; Thu, 06 May 2021 00:01:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620284472; cv=pass;
        d=google.com; s=arc-20160816;
        b=alsuBansmlRGPm6bBlbHS/3dIh8aUArvTI8DEyVRRT+74hBZHxb7kTedvA7266MSJ7
         KgpB44PnviKkgg4aC+O4e5ZZ+gYvVB4VJobW51syTK8T0hVWeMeHfw3FtQSGPB+OtLgL
         JXx9aHBVTXhSJIPcXaHUVIY5x/auxyycWbx0ShgsMSWl6zVufUAl0cb381Z5C/4iBYt2
         k+gCi6+GaXcqtTafeJo/qd3xYF244WWcdtBaWBYuJGHcVbvnm2YaVtfxlVrzRyD+Rox9
         oDHCg+FMLOCfZHJaS0HW83Ux6xv5pjBbhipfduIJFMtkmlI3ljT0YYSon2czdPC85peZ
         l1Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=tI8A32ez8Maiuyo3R7s+0wqmpNsApT3pibifQ+r5i4E=;
        b=FG9Z4/FHxtvMK99VEQgdj2P4sAD6o1J7LeDUnowLVUJ8KIrTx9h4RxzCh1F+uXTRy+
         2NJKjMSidTAKFy5md2vBxTljW5IwPc+9LmzcnwiMjSb9qCpb4CnafYjvFDZlooeRFsiR
         nxk3OPR0zBhLUpKiImtTNOInwatvfai72x9UB0rJKTlSeoF1eaqE9ioLw22gr1S270sq
         RKGuAAwQk4ayzlzjqvwquD6AO/cOceMGvQtxA8u5ckhW4GnNCZqIDaP1DRo8Ikt6/gUj
         8ea5IuxG/jneHQ/Cu5zhJDHM9OwtUkrQ/ikPpLOQXRYTh9ISudsf9rcO3/DXCyInYo8y
         cScw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.217.54 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tI8A32ez8Maiuyo3R7s+0wqmpNsApT3pibifQ+r5i4E=;
        b=sp6qZu32YF9s8tzd+lt/5zuj3ZqsDjk4kiEDWJfBgOQ8QvHufcdcubSOzx2BaO58Ln
         hMie6fQkGYvSSBVtKgEKlqAspmt2A5VI12gV0XAoXJbl1GomnyUVqODFY9d4YUll4Oc1
         ouSgqooBk5fYzJM7/rqzgpmCyhxs5XRoerViHaJCUSqgqAtQQY2RFY4tnOHBngHrq+nP
         w7Y/WUiy6mWmsiWg78xWa1Zz6UxrR8NX1ZIkxyNvBxU2Qfn/KRuQtjPu6BRlmTMyhwWI
         PzzS1hiRgUcB2m6PMiSdQrpjl2E5kf3YHTJsuiW4cvxHkX+Oohaa4QIyoG62VtRhtwET
         bEtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tI8A32ez8Maiuyo3R7s+0wqmpNsApT3pibifQ+r5i4E=;
        b=T2WqdsP/v+XaiUlrHj+kfErtfOJU3t+qgBQa3BCPYekuIHaWpkJVMtFRXsrwe5+iMT
         FNyJB7TSbHjO4wsqDPFCYlhJOhmsld54zGAURUPMphX9BgAx9/z62N3Ptp0ofMSEl/83
         ruRZ/Ah3rbZTlpXW8rtT+iEeMa0A77dFXMHBLI+2c3MqG/P4WBTjIsnCd8fOOyBmJF3T
         H49LSR8EDbQ0tB44U5cGMquhWkKt+LNdOoXyCR+RPRfb/+lJbBo4L9oRO9NEXpzukZlk
         jZFPuNTVb+07sCKMiOQVoTfINomukxvht2WyHgjPJp/SDWNSdjPDUq2/aOukBO0fAqkv
         i5kA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304H5Eh9pbUCbDYygwOvAVJKZWrqF4h6dUVIfqG8sqm8cXMYpEs
	8GEskNHVAzL3gOQiRNCPubw=
X-Google-Smtp-Source: ABdhPJz6Htrj6lnq+Nt61+D4uM/NyHyAKSSJ7fmaF64AgahwRvdzNKo4/ujyv7/svpNlFitoWCrbqQ==
X-Received: by 2002:a62:18d7:0:b029:28c:fdfa:f95b with SMTP id 206-20020a6218d70000b029028cfdfaf95bmr3045008pfy.57.1620284472338;
        Thu, 06 May 2021 00:01:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a4a:: with SMTP id x10ls1029422plv.6.gmail; Thu, 06
 May 2021 00:01:11 -0700 (PDT)
X-Received: by 2002:a17:902:c106:b029:ee:9d6f:8861 with SMTP id 6-20020a170902c106b02900ee9d6f8861mr2799227pli.85.1620284471694;
        Thu, 06 May 2021 00:01:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620284471; cv=none;
        d=google.com; s=arc-20160816;
        b=Ihv3jFQ+tqMgFfkZCEk3Lw2xlmuThJ7bhOwsb8ekAB8Yb52pSvIwQ4wlnMEc7UkizE
         n3vC1Etz+e1TZPeKnUDCZ2e45N7elzcoksStAYbc0i7mnZw9BQTqr62t/+v1ncPddiJ+
         QUtuDntwvVlTG5Fbrp32BKL/TvD6XwgM0n2u+ZFB8ABmrwQ+n/FAWa/D41TkdwwlPA01
         0+1g6/2GwmSNSA5067hfpr12M2BHhO1tBSsrr+fM/rIkvTEVS+yM4+WTfPiEkbMDCrYC
         H0PVOu/SeAoFwyi+aKbH7Tn7gdFGd7n2yLIqU+MSgeT4oFvbQ7WVWbQIu2VAb8hGPirc
         MA/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=NoT+A0718WNsTbHBS5BGp5G+tj2RfytrZk7R7tgIl08=;
        b=EVh74B8M1mwiTU1r9kPNBd6yHgkMxyDLGB9mfQtrUADQobNLr5nPY8aWXblUvc7UDm
         2OZapgSzwREVjQGQHCI92jbuluHuK17Ryo2M2rYgd4njI498E6bpe5gASdbaZN+0fRbY
         OLbHeAzpfduQZwUo8hsEyFzLSe66WIOI8wUjG8ZlNzK7OuLFm5ym2r66F3ytcisex10p
         HSgXKG5Ko81WvYFSsoxYg6YCQnMAhJAHylPMsPASBh0MbkfAhXfn3k8+4AJE2fv7NNmw
         3d6vVEnf3mbD05c6rtTrzIQx0q6vOTuYN75mqQUpbd4O7dJYhgkzqN0qUJaDCjnhgH9x
         YuwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.217.54 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-vs1-f54.google.com (mail-vs1-f54.google.com. [209.85.217.54])
        by gmr-mx.google.com with ESMTPS id x1si110675plm.3.2021.05.06.00.01.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 May 2021 00:01:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.217.54 as permitted sender) client-ip=209.85.217.54;
Received: by mail-vs1-f54.google.com with SMTP id c21so2403551vso.11
        for <kasan-dev@googlegroups.com>; Thu, 06 May 2021 00:01:11 -0700 (PDT)
X-Received: by 2002:a67:f503:: with SMTP id u3mr1764571vsn.3.1620284470626;
 Thu, 06 May 2021 00:01:10 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
 <m1czuapjpx.fsf@fess.ebiederm.org> <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
 <m14kfjh8et.fsf_-_@fess.ebiederm.org> <m1tuni8ano.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Thu, 6 May 2021 09:00:59 +0200
Message-ID: <CAMuHMdUXh45iNmzrqqQc1kwD_OELHpujpst1BTMXDYTe7vKSCg@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] signal: sort out si_trapno and si_perf
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Marco Elver <elver@google.com>, Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.217.54
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Eric,

On Tue, May 4, 2021 at 11:14 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
> This set of changes sorts out the ABI issues with SIGTRAP TRAP_PERF, and
> hopefully will can get merged before any userspace code starts using the
> new ABI.
>
> The big ideas are:
> - Placing the asserts first to prevent unexpected ABI changes
> - si_trapno becomming ordinary fault subfield.
> - struct signalfd_siginfo is almost full
>
> This set of changes starts out with Marco's static_assert changes and
> additional one of my own that enforces the fact that the alignment of
> siginfo_t is also part of the ABI.  Together these build time
> checks verify there are no unexpected ABI changes in the changes
> that follow.
>
> The field si_trapno is changed to become an ordinary extension of the
> _sigfault member of siginfo.
>
> The code is refactored a bit and then si_perf_type is added along side
> si_perf_data in the _perf subfield of _sigfault of siginfo_t.
>
> Finally the signalfd_siginfo fields are removed as they appear to be
> filling up the structure without userspace actually being able to use
> them.

Thanks for your series, which is now in next-20210506.

>  arch/alpha/include/uapi/asm/siginfo.h              |   2 -
>  arch/alpha/kernel/osf_sys.c                        |   2 +-
>  arch/alpha/kernel/signal.c                         |   4 +-
>  arch/alpha/kernel/traps.c                          |  24 ++---
>  arch/alpha/mm/fault.c                              |   4 +-
>  arch/arm/kernel/signal.c                           |  39 +++++++
>  arch/arm64/kernel/signal.c                         |  39 +++++++
>  arch/arm64/kernel/signal32.c                       |  39 +++++++
>  arch/mips/include/uapi/asm/siginfo.h               |   2 -
>  arch/sparc/include/uapi/asm/siginfo.h              |   3 -
>  arch/sparc/kernel/process_64.c                     |   2 +-
>  arch/sparc/kernel/signal32.c                       |  37 +++++++
>  arch/sparc/kernel/signal_64.c                      |  36 +++++++
>  arch/sparc/kernel/sys_sparc_32.c                   |   2 +-
>  arch/sparc/kernel/sys_sparc_64.c                   |   2 +-
>  arch/sparc/kernel/traps_32.c                       |  22 ++--
>  arch/sparc/kernel/traps_64.c                       |  44 ++++----
>  arch/sparc/kernel/unaligned_32.c                   |   2 +-
>  arch/sparc/mm/fault_32.c                           |   2 +-
>  arch/sparc/mm/fault_64.c                           |   2 +-
>  arch/x86/kernel/signal_compat.c                    |  15 ++-

No changes needed for other architectures?
All m68k configs are broken with

arch/m68k/kernel/signal.c:626:35: error: 'siginfo_t' {aka 'struct
siginfo'} has no member named 'si_perf'; did you mean 'si_errno'?

See e.g. http://kisskb.ellerman.id.au/kisskb/buildresult/14537820/

There are still a few more references left to si_perf:

$ git grep -n -w si_perf
Next/merge.log:2902:Merging userns/for-next (4cf4e48fff05 signal: sort
out si_trapno and si_perf)
arch/m68k/kernel/signal.c:626:  BUILD_BUG_ON(offsetof(siginfo_t,
si_perf) != 0x10);
include/uapi/linux/perf_event.h:467:     * siginfo_t::si_perf, e.g. to
permit user to identify the event.
tools/testing/selftests/perf_events/sigtrap_threads.c:46:/* Unique
value to check si_perf is correctly set from
perf_event_attr::sig_data. */

Thanks!

Gr{oetje,eeting}s,

                        Geert


--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdUXh45iNmzrqqQc1kwD_OELHpujpst1BTMXDYTe7vKSCg%40mail.gmail.com.
