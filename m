Return-Path: <kasan-dev+bncBC7OBJGL2MHBB663WSCAMGQERYVVO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id A375C3706D5
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 12:31:24 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id l10-20020a056830054ab0290241bf5f8c25sf783395otb.11
        for <lists+kasan-dev@lfdr.de>; Sat, 01 May 2021 03:31:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619865083; cv=pass;
        d=google.com; s=arc-20160816;
        b=rbE8UjpTvFVWcdAAQYKkGuXQ7SFqlHPQ+4B1Zb5KxRzDpu4BnD7G2szBXPf36p4u0O
         NnOgYtXK7g3NazmnkSRxn1+NvphKj9tPIk+FZ7gQjswgM/+ZZ6rCi5KNq1ldHwF8bgAH
         7OLaZ1R7W1zNv9kQUG4mLglS0Fj7pIQAA467HHU4NTwCpkKbE9JisFEFBJHakESWw+rm
         2o/3rmkxfFziZ1XU5YrsGftpnEJikNxO/d8Ggq/vIUJjmMxv4vK/Ox7yu+LI9uxh7CNJ
         BL57iWajAqqfzUN+IV7/728clcaYAgA6kPJZBoEcd+KyHkQh7E2nd8lHduN0ev0JDP5Q
         tROw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1uBH1IbY1+8Wx0ZqLHzmh/8b9X1sSQsFpbNv6aDdsIs=;
        b=JiXfouV7VND4TPgU8QFkPMr0jz4Sceii/FQTLiXciqUFbYxI8w0APF82bAzY//6j7Q
         xhNnuYVq5ZPrBG1EWIZpISQlhyYn1B5O2G9FE01L+xkqxmSvbE1a8JsUlCGUdYcOi3wI
         LjyVRmd9LV5zGBM4nGO4VUuF2UqbqfyVAk+T3Wy0MM7pbAWWfUqyGG5Ovb0+ZteTeKLU
         X8rrXlyjr1eiV8z4FNQM9AKlvv9/Ywcf5GvWUZWZA8rOES6ZQ3RRmMOcBM8LuTYEsUBr
         bTSLOx0mzcvwXsiXqgINmV+owJe4JgbxaExVL4MlbTXtTCpf7TFnBhqqkN+gVjXLMzVI
         szjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hy8ij/KJ";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1uBH1IbY1+8Wx0ZqLHzmh/8b9X1sSQsFpbNv6aDdsIs=;
        b=NfhKfSDb4CStZGB6+Q1IgOds43H0wuvIM7Kcer7dZzrsX0OqEXJbopPmNqW2RN8fIN
         YlEuPAUtMqBMAIGZQjR35HmvtyohBCV5pS3OMOEfGl8hHW1CO+l0V0X8ASqKjq3UxpM/
         SEnD2fy3quP9B1GPJEYWSpbf/2BhAFK53UHYKTA0voZDy7PWocnhL8QPjXkUOyXggmhj
         T0dBl6zL75bgL78XGfmObHUIj5oQmJIKj6FhOHhAaMY52IV+47AVJyErrq1b9QyrHpZo
         2Kq+JzMwqsATkxik/YuPhO1z80NTun2LLc7IlmlRVwyws8xK+ynNFTCTv/tD81IWR4zK
         7fww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1uBH1IbY1+8Wx0ZqLHzmh/8b9X1sSQsFpbNv6aDdsIs=;
        b=HR2fh1GWq0jPSREnCLh2n3gyTbKXjvp7kFvXxwnX7b0dFkWQry4962H5UNYNLWyMyi
         JwncGEDdG7GktXLNrnABwhILrfvzYD+9wks50+ctU/bxF2UWG7CegV4LyLtZgF2QmGUn
         AIHhgjYkwrC+ckYsyXsoiWl7IHInKXqp2m/Fe4VIDU6PykONnY0hv2BSVe599qPN5z22
         VE8wUvoerCmT2qOWePx1Bttvtdkrb7kVQ1DE6naJQKsCHclugDtK5pdH/qm+saBdI2Vv
         buKhLaw5HjcuypcRxdqWKi9flad0QBN/rSRLF5OOBbnQD2Q35zZOMUDZ2Pd6l+gM6RJu
         dBIA==
X-Gm-Message-State: AOAM532iJFMEJTb/vpW0hi1tM6CMEl37jOhnL/pQbnDKK7osomHMfteC
	+bI5iUJjEe+4qEnriDipRd0=
X-Google-Smtp-Source: ABdhPJww1+WqUpR1u4laPiPWKTpHd8ljUOjkyqTBKCxFEz+Z2R+LOFg5SL6POpM5zokVpQbaqnEDkg==
X-Received: by 2002:aca:ad87:: with SMTP id w129mr7217357oie.35.1619865083434;
        Sat, 01 May 2021 03:31:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c5:: with SMTP id 188ls2544466oif.6.gmail; Sat, 01 May
 2021 03:31:23 -0700 (PDT)
X-Received: by 2002:aca:f30b:: with SMTP id r11mr14694429oih.133.1619865083075;
        Sat, 01 May 2021 03:31:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619865083; cv=none;
        d=google.com; s=arc-20160816;
        b=rEKp5U46gfQGyT85tfNcFratmfLWJVtffrKj3AkP2kiluF+GiFeZcFwpche+eCtbeo
         cEoIOtrxuZF6c1UTlAxhQD/uqZXk87qpY0W/pys6KnlLS4pxWssPECcSx7MlPSSe3Q5J
         aAx/49ltrzf1NXggk3C5h9dixisB0FC2kibaOb0CoFMxP6hxC6vlrxkmrXyQw9ioDSYa
         BYSaZy6AIGeF20rwQC/3e5/c3PKzRYDraxZbP8Xw/BBEKR8uBaim76bCDOa3+ac4he9Z
         828k9AKtHkAn6oVBKxNFJtd4D9m5klrtF152EHJLUp65DtMG2zABtzxRSIjqiHOAUUli
         m13g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hTLAv7JY7b65PTCIkNiaGknpqfuRJEA8yhpseb1KzSE=;
        b=i6DGZRnEI0fFk7Did9t7XrtlVYBsqKcH0mt19lbkawdLkCK9r1/3wnGSEvHqHVt5xf
         59wEN0uLZ9n7wN2p/lYR2IsP/4R7EM061e6XAoc0yoDpFQWybiYAehxRVT6MFWWBtIGI
         7K2T8jPiwj+kcl9/YHtluJq++D/UwWeMf/R/+3obobNXrAp/mXu0iO6UteDGYHd84ghz
         VzbARbdSP1kqF6Yvk53GQDZDKldHYjRuoq5VqPi4fFTszS5kW7d9BzRXAocsCM8iPr8Q
         WEU1JsNwAo4JUYJW88aGNyNTDN/56bMpvt5Fe23S9q/llxzm2ghjRi6CvGZUE+tYR1NK
         r/3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hy8ij/KJ";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id f4si974884otc.2.2021.05.01.03.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 May 2021 03:31:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id q7-20020a9d57870000b02902a5c2bd8c17so145279oth.5
        for <kasan-dev@googlegroups.com>; Sat, 01 May 2021 03:31:23 -0700 (PDT)
X-Received: by 2002:a9d:1ea9:: with SMTP id n38mr7332566otn.233.1619865082626;
 Sat, 01 May 2021 03:31:22 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1tunns7yf.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1tunns7yf.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 May 2021 12:31:10 +0200
Message-ID: <CANpmjNOZj-jRfFH365znJGqDAwdXL4Z2QBuHOtdvN_uNJ8WBSA@mail.gmail.com>
Subject: Re: [PATCH 1/3] siginfo: Move si_trapno inside the union inside _si_fault
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="hy8ij/KJ";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Sat, 1 May 2021 at 00:50, Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> It turns out that linux uses si_trapno very sparingly, and as such it
> can be considered extra information for a very narrow selection of
> signals, rather than information that is present with every fault
> reported in siginfo.
>
> As such move si_trapno inside the union inside of _si_fault.  This
> results in no change in placement, and makes it eaiser to extend
> _si_fault in the future as this reduces the number of special cases.
> In particular with si_trapno included in the union it is no longer a
> concern that the union must be pointer alligned on most architectures
> because the union followes immediately after si_addr which is a
> pointer.
>

Maybe add "Link:
https://lkml.kernel.org/r/CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com"

> Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>

Acked-by: Marco Elver <elver@google.com>

By no longer guarding it with __ARCH_SI_TRAPNO we run the risk that it
will be used by something else at some point. Is that intentional?

Thanks,
-- Marco

> ---
>  include/linux/compat.h             | 4 +---
>  include/uapi/asm-generic/siginfo.h | 6 +-----
>  2 files changed, 2 insertions(+), 8 deletions(-)
>
> diff --git a/include/linux/compat.h b/include/linux/compat.h
> index f0d2dd35d408..24462ed63af4 100644
> --- a/include/linux/compat.h
> +++ b/include/linux/compat.h
> @@ -214,12 +214,10 @@ typedef struct compat_siginfo {
>                 /* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
>                 struct {
>                         compat_uptr_t _addr;    /* faulting insn/memory ref. */
> -#ifdef __ARCH_SI_TRAPNO
> -                       int _trapno;    /* TRAP # which caused the signal */
> -#endif
>  #define __COMPAT_ADDR_BND_PKEY_PAD  (__alignof__(compat_uptr_t) < sizeof(short) ? \
>                                      sizeof(short) : __alignof__(compat_uptr_t))
>                         union {
> +                               int _trapno;    /* TRAP # which caused the signal */
>                                 /*
>                                  * used when si_code=BUS_MCEERR_AR or
>                                  * used when si_code=BUS_MCEERR_AO
> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> index 03d6f6d2c1fe..2abdf1d19aad 100644
> --- a/include/uapi/asm-generic/siginfo.h
> +++ b/include/uapi/asm-generic/siginfo.h
> @@ -63,9 +63,6 @@ union __sifields {
>         /* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
>         struct {
>                 void __user *_addr; /* faulting insn/memory ref. */
> -#ifdef __ARCH_SI_TRAPNO
> -               int _trapno;    /* TRAP # which caused the signal */
> -#endif
>  #ifdef __ia64__
>                 int _imm;               /* immediate value for "break" */
>                 unsigned int _flags;    /* see ia64 si_flags */
> @@ -75,6 +72,7 @@ union __sifields {
>  #define __ADDR_BND_PKEY_PAD  (__alignof__(void *) < sizeof(short) ? \
>                               sizeof(short) : __alignof__(void *))
>                 union {
> +                       int _trapno;    /* TRAP # which caused the signal */
>                         /*
>                          * used when si_code=BUS_MCEERR_AR or
>                          * used when si_code=BUS_MCEERR_AO
> @@ -150,9 +148,7 @@ typedef struct siginfo {
>  #define si_int         _sifields._rt._sigval.sival_int
>  #define si_ptr         _sifields._rt._sigval.sival_ptr
>  #define si_addr                _sifields._sigfault._addr
> -#ifdef __ARCH_SI_TRAPNO
>  #define si_trapno      _sifields._sigfault._trapno
> -#endif
>  #define si_addr_lsb    _sifields._sigfault._addr_lsb
>  #define si_lower       _sifields._sigfault._addr_bnd._lower
>  #define si_upper       _sifields._sigfault._addr_bnd._upper
> --
> 2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOZj-jRfFH365znJGqDAwdXL4Z2QBuHOtdvN_uNJ8WBSA%40mail.gmail.com.
