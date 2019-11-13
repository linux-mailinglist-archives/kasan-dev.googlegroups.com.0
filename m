Return-Path: <kasan-dev+bncBCMIZB7QWENRBYVNV7XAKGQEO3HQXLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A80A9FAE2A
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2019 11:11:47 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id s8sf1455326yba.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2019 02:11:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573639906; cv=pass;
        d=google.com; s=arc-20160816;
        b=apxkHJdwAJYLfNDqrosijIrt/GXLPn56k63GimXSgrIYzRXKdEcMluB/jhko6Vz9dK
         EZYgNm01sBOsm7xKH/3mT5SSzyboaUqSuS37BB62m23G6tJnKZrkjl/ft1DJhR3RaXv5
         /00dV682yB6uO01MPM97DujmejxW/6CkAv9ibOvticXUdxOPJciXmFLuOL1Ja6cdd9Lo
         6iaHT/hDtw558hg5u8ei8wepILj9IpBb8NP6yfLrbWpENxIeh0WGFA8CEYW5KBimZKKH
         n/CEPzfpQrEyQ57/GHeXQR+RwivQ/p5uW+NssrXVQxCXflZNPCgzLCfZl5YHJ3E0Rk9W
         GEqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=v1zrwgzU29E1cVa39CQ13HiT5hnWHZWakzL4vQO3o90=;
        b=Arycb2y65m5vdbcFmzwvyHSjW+KLwCO9q7jHYdsoG3mHoSB/+C0rIhs1CK5D+290gs
         rHfQHh/Ghf8ic0meMbzY5Kc1f+KQsjfCC7RdWhYleTAJ13uCYYu02Yl6dYeCwAgJWaV7
         A3eFeYL4UXTO74jMKmsPDfUmUXsJTFdAU69/Ke4T5CfDCi6rgxpCJf4RrTT9yIISutYR
         Wx+YiHmYR/FFb53Fj1nbDQCVrxPwqgIMOfTSijgWaMk3IJQ0YiG2m4HAWBpJdcAfkZsx
         vc9vnB0CVk4wWA5Qv+9hEg5zT1VoiMK1Q7t+/3waxVPKC9uMSu7tfsLaTVZ+yB14QBlq
         fPYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A2JtYD8G;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1zrwgzU29E1cVa39CQ13HiT5hnWHZWakzL4vQO3o90=;
        b=qq8Qd55m0dl88+Mv9qTcl5DAkOX/fHeci/pB8lcs5gweVN1xFGnkiYQozCmXmuJcls
         WK5RcAocyJvy96tjdTzKVkd4pb5nAzS0re7l7or67476K/U2DDQ9RQFG3FJC6ROIiYkY
         tIycxMSQh4PNCMeWnG+mLu0C6S26+KZaOcbCoKvKtYMlju4A766Mh2p8eoDPCVfdXwVE
         kWg4uN+TiGEwGd1WWwZ4DufkZI6U3BZsR6OxGIxjqmdYsbrWk3RB3CHBzFd4YrW5+v1A
         gvyVh+RyW53FXksj91MNMBNqbVRMlcUucq7bc+ufUmJStDjdiO2ZQi7QDrviJZI6S+M+
         h3ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1zrwgzU29E1cVa39CQ13HiT5hnWHZWakzL4vQO3o90=;
        b=T4FFBbkLB+HnpubNy5DMCPtRP4jeUjV/leyKT5wNR8JGqlyiLkNnGKeOdMF/t1Qetf
         NXkdKLNw3Dx8LsrS5bqs00LWmCQbuHtqbaI3lnvEpQU47I9pdD4wAQSCZnBN/PSNGKgp
         e0YX5ASVxtOUJrL2uTa+/wJqwMzU69Nf8b+HYvPx2t+JPlJUmTcy4pLCDya93fFZk45M
         hCY89MxYt5BqurvIM6Rx8zLERKqSvxHKKFl+p9vCjzBiASnbh5RwkuyhtidKbJg1VVGT
         nwONdJIoJuoGZv2ZfquScT7GSURUFEBd8moLbAMT7pIuahtJ7z5TCdQHlarZZdbWJGnk
         /ksA==
X-Gm-Message-State: APjAAAWr3mYF6SweEs2ilyQpdDelNEc/0dVvhJTkYzizU9CNkxxJevhd
	SXYRjXHUq9bC791hO41kql8=
X-Google-Smtp-Source: APXvYqyI/VhUwzZMLyx98sEVVxXELW/A6uVboiyZ/IwHtrPFzTRnNPpGahgMEgIl3rE0kql1XdzPbQ==
X-Received: by 2002:a25:cc84:: with SMTP id l126mr1722864ybf.249.1573639906616;
        Wed, 13 Nov 2019 02:11:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6e54:: with SMTP id j81ls363853ybc.11.gmail; Wed, 13 Nov
 2019 02:11:46 -0800 (PST)
X-Received: by 2002:a25:6789:: with SMTP id b131mr1938187ybc.429.1573639906228;
        Wed, 13 Nov 2019 02:11:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573639906; cv=none;
        d=google.com; s=arc-20160816;
        b=TAr8MkwnGuhMgOnw10n3NLTXjn5KuAyqPOagsRQEObGL1ZK5NeiDtU38edmYEaytAH
         ppll5szMWcIBaNazkEvjjcLbCJpX3JBM9yY5XBVVYP/9flXMNGI+kTZguWYjh9YOnMGD
         VJoDbfRrj7DapDBe0p+J6/P/3Cb6EMk2Vbg1Q0JfOwi13PKDREhYJ3ayc8kh5WzotIXC
         gt6V6QYV26csM0WBBJOWaD06ZJYRJXXywMsh3p+ZneA+WKzY+ejlyBem5QMinjZXWhim
         dKlUNs9/oZe82oyml1vsrT28Hbs7mZLtYkRLKxdw84wVnqFIeAeXgeSclGx1tr3cq7SR
         0Bkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aRCEH7uGRv9k5bHRL7hYJEWrGzCPbbtWyq1WoRT6sfg=;
        b=BPP14G6liivpaPBd2MQlzSDSn1arExbct4Jb1fE/+WozejaPO+/S66PQDfc74CtYZ5
         FPcMTf+BC/VZpUsdbVe9vw9ykBIM/NJxFEmuMo4YomNSkdM+rJRotVogzemMIbAGhoe1
         YC2+dPmTH5Knn36dVZlwKvhfYnZ91qWyIdxIMn5gG+yCfCNvWPhaBQw9gEyOLH5DKvib
         pYOdfxsNOyS2SAwwkMfjFubZpE3xBNV4IewktB9VaVIAcDygsNDa2CsCivSy2MLwNIMd
         THPWt2PEubedVaGxuZdBWNT24MA0PvgaOYME3nOO1p87QZBiL1rt9246Hh4reomS5p2f
         Ngfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A2JtYD8G;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id u3si123528ywf.4.2019.11.13.02.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Nov 2019 02:11:46 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id g12so550313qvy.12
        for <kasan-dev@googlegroups.com>; Wed, 13 Nov 2019 02:11:46 -0800 (PST)
X-Received: by 2002:a05:6214:8ee:: with SMTP id dr14mr2106594qvb.122.1573639905171;
 Wed, 13 Nov 2019 02:11:45 -0800 (PST)
MIME-Version: 1.0
References: <20191112211002.128278-1-jannh@google.com> <20191112211002.128278-3-jannh@google.com>
In-Reply-To: <20191112211002.128278-3-jannh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Nov 2019 11:11:33 +0100
Message-ID: <CACT4Y+aojSsss3+Y2FB9Rw=OPxXgsFrGF0YiAJ9eo2wJM0ruWg@mail.gmail.com>
Subject: Re: [PATCH 3/3] x86/kasan: Print original address on #GP
To: Jann Horn <jannh@google.com>, Andrey Konovalov <andreyknvl@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A2JtYD8G;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41
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

On Tue, Nov 12, 2019 at 10:10 PM 'Jann Horn' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Make #GP exceptions caused by out-of-bounds KASAN shadow accesses easier
> to understand by computing the address of the original access and
> printing that. More details are in the comments in the patch.
>
> This turns an error like this:
>
>     kasan: CONFIG_KASAN_INLINE enabled
>     kasan: GPF could be caused by NULL-ptr deref or user memory access
>     traps: dereferencing non-canonical address 0xe017577ddf75b7dd
>     general protection fault: 0000 [#1] PREEMPT SMP KASAN PTI
>
> into this:
>
>     traps: dereferencing non-canonical address 0xe017577ddf75b7dd
>     kasan: maybe dereferencing invalid pointer in range
>             [0x00badbeefbadbee8-0x00badbeefbadbeef]
>     general protection fault: 0000 [#3] PREEMPT SMP KASAN PTI
>     [...]

Nice!

+Andrey, do you see any issues for TAGS mode? Or, Jann, did you test
it by any chance?


> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>  arch/x86/include/asm/kasan.h |  6 +++++
>  arch/x86/kernel/traps.c      |  2 ++
>  arch/x86/mm/kasan_init_64.c  | 52 +++++++++++++++++++++++++-----------
>  3 files changed, 44 insertions(+), 16 deletions(-)
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index 13e70da38bed..eaf624a758ed 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -25,6 +25,12 @@
>
>  #ifndef __ASSEMBLY__
>
> +#ifdef CONFIG_KASAN_INLINE
> +void kasan_general_protection_hook(unsigned long addr);
> +#else
> +static inline void kasan_general_protection_hook(unsigned long addr) { }
> +#endif
> +
>  #ifdef CONFIG_KASAN
>  void __init kasan_early_init(void);
>  void __init kasan_init(void);
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index 479cfc6e9507..e271a5a1ddd4 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -58,6 +58,7 @@
>  #include <asm/umip.h>
>  #include <asm/insn.h>
>  #include <asm/insn-eval.h>
> +#include <asm/kasan.h>
>
>  #ifdef CONFIG_X86_64
>  #include <asm/x86_init.h>
> @@ -544,6 +545,7 @@ static void print_kernel_gp_address(struct pt_regs *regs)
>                 return;
>
>         pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> +       kasan_general_protection_hook(addr_ref);
>  #endif
>  }
>
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 296da58f3013..9ef099309489 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -246,20 +246,44 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
>  }
>
>  #ifdef CONFIG_KASAN_INLINE
> -static int kasan_die_handler(struct notifier_block *self,
> -                            unsigned long val,
> -                            void *data)
> +/*
> + * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
> + * canonical half of the address space) cause out-of-bounds shadow memory reads
> + * before the actual access. For addresses in the low canonical half of the
> + * address space, as well as most non-canonical addresses, that out-of-bounds
> + * shadow memory access lands in the non-canonical part of the address space,
> + * causing #GP to be thrown.
> + * Help the user figure out what the original bogus pointer was.
> + */
> +void kasan_general_protection_hook(unsigned long addr)
>  {
> -       if (val == DIE_GPF) {
> -               pr_emerg("CONFIG_KASAN_INLINE enabled\n");
> -               pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
> -       }
> -       return NOTIFY_OK;
> -}
> +       unsigned long orig_addr;
> +       const char *addr_type;
> +
> +       if (addr < KASAN_SHADOW_OFFSET)
> +               return;

Thinking how much sense it makes to compare addr with KASAN_SHADOW_END...
If the addr is > KASAN_SHADOW_END, we know it's not a KASAN access,
but do we ever get GP on canonical addresses?

>
> -static struct notifier_block kasan_die_notifier = {
> -       .notifier_call = kasan_die_handler,
> -};
> +       orig_addr = (addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
> +       /*
> +        * For faults near the shadow address for NULL, we can be fairly certain
> +        * that this is a KASAN shadow memory access.
> +        * For faults that correspond to shadow for low canonical addresses, we
> +        * can still be pretty sure - that shadow region is a fairly narrow
> +        * chunk of the non-canonical address space.
> +        * But faults that look like shadow for non-canonical addresses are a
> +        * really large chunk of the address space. In that case, we still
> +        * print the decoded address, but make it clear that this is not
> +        * necessarily what's actually going on.
> +        */
> +       if (orig_addr < PAGE_SIZE)
> +               addr_type = "dereferencing kernel NULL pointer";
> +       else if (orig_addr < TASK_SIZE_MAX)
> +               addr_type = "probably dereferencing invalid pointer";

This is access to user memory, right? In outline mode we call it
"user-memory-access". We could say about "user" part here as well.

> +       else
> +               addr_type = "maybe dereferencing invalid pointer";
> +       pr_alert("%s in range [0x%016lx-0x%016lx]\n", addr_type,
> +                orig_addr, orig_addr + (1 << KASAN_SHADOW_SCALE_SHIFT) - 1);

"(1 << KASAN_SHADOW_SCALE_SHIFT) - 1)" part may be replaced with
KASAN_SHADOW_MASK.
Overall it can make sense to move this mm/kasan/report.c b/c we are
open-coding a number of things here (e.g. reverse address mapping). If
another arch will do the same, it will need all of this code too (?).

But in general I think it's a very good usability improvement for KASAN.

> +}
>  #endif
>
>  void __init kasan_early_init(void)
> @@ -298,10 +322,6 @@ void __init kasan_init(void)
>         int i;
>         void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
>
> -#ifdef CONFIG_KASAN_INLINE
> -       register_die_notifier(&kasan_die_notifier);
> -#endif
> -
>         memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
>
>         /*
> --
> 2.24.0.432.g9d3f5f5b63-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112211002.128278-3-jannh%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaojSsss3%2BY2FB9Rw%3DOPxXgsFrGF0YiAJ9eo2wJM0ruWg%40mail.gmail.com.
