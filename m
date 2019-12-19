Return-Path: <kasan-dev+bncBCMIZB7QWENRBS465XXQKGQEVOG3J7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id AF26F125EC2
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 11:22:05 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id t3sf2793002plz.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 02:22:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576750924; cv=pass;
        d=google.com; s=arc-20160816;
        b=xpcdNHi9GM7ra3BSYAz5UqC3YDeo/1pS5SwPMIIwhmKkoyl/XZ//OfZvbdBie+6SIZ
         QmMN7p+9bv2tlOj1IH8X7ZGJM0RwvF5FtuOM/KjhQTvFp3lTd+08hhMaA3vzpG+S3lO/
         932YWiwpVV4YYtUhyQxf/0vI7QV3WGaYpGPC5mBLw7R7qsAzB5xQaaT+ODY12G+Ar6l5
         sbdN84cIO83/mekhhCyorIBdUaPAw5oTaGBifhn71v9tTSfajIYVf/rlJtwGQBOALsvZ
         wqMjgT9FAmIPMOvEK6GE+POks1s2WhL/pvxMLrm5EWAjdKlWDBWaWyFmAJQWy81i5sHS
         3NGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FafL9E23T6bpfRwlLFC9cyPbDC3NYLQtTf+VfA0OYFs=;
        b=RxSjxLX9gmRsy6oqm6gp13kzYkXDuVhHt2gbv0M7BtOaiL3gSUPCDQ8SHeCpIXzhxv
         oHwjaqObVwpQZfwdEWPKIGO5qaI0OAYzG6xQFG2Ny1TtOEN8qX4PvDFD+Q/DFpxERKxu
         Y2QnX3IPBQ0PXoud1c5d6TGFbHIv3OLsQ89AfbvyegpgMfvf9H0ocTjSzL5TRkXf25UR
         FxNfzykLE66CsImhr7sbGlOHFXmRXmZMWEYjeDmfce5v+wALnKP7kZkRFuGTphz8K4CE
         Kl8tw/VIzZufvbG4j7WDdJ7gGxR4iUoOABaEi6+pABif/uAwQMClalDisKu5XBaXveCi
         cuWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mnU7Uy9c;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FafL9E23T6bpfRwlLFC9cyPbDC3NYLQtTf+VfA0OYFs=;
        b=i4qS1BHRiVIVFL2WDyhQi1r82DnWwv9ZhR/PA8SXUpO+VNbEqyMV+uTVuVskpQay7c
         Q+n/HA7vIFKXcUAQsx7DSGJudSiai7UNk73heCYIXGdkfIQTxO5tTu3Nbu+WDpJkUBrI
         fZoLh5UM0Ifi9/JCDoGcxzZRMSMosrFn+NSAG6LkAw81aYgwnW6OKnURZ60hSFIxnQNX
         xQrlq+x5+6HzBkNBlcB+y4NMwsRKq2T2zcsB5EOnmcUs2G0+dvd2+53acQw/gJnqjpqJ
         sC+7Z/sE+GJZGVw+DV6RyI6E+YJhQdalMU6TE26r0SkQwhEbQ6P9u6ahZMyTwaEtKtPw
         q7mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FafL9E23T6bpfRwlLFC9cyPbDC3NYLQtTf+VfA0OYFs=;
        b=BYvnsSdfiIq3YN3tb8942JxWaYVG2frEP5G3G9Xw3UNNY3gCKcbE+5f+W/741gkuiu
         8r8f9AbkWv0MUV0ndNycjWCN4K4yUxQm79JIUa1OwlD9I3OmcngKg6YKXjWPaXSr/gl/
         ZnRBWatCwzw9XFpMxvc9W+FG743VU37TvmscwF8RqSpKEP1jzqnKdVREQKlRhTioUjlo
         llTd5wrVnXnfGDUKaNqFQTFjDmuqdE6oKNfpWcbDZL8samoRayRl2kBPBptentfvx5Q+
         YxdwdF3ss2i06d3oA3R2VGj9vz8skXdnQ03NveoU6QeFia5tjlHgTD6w5Suz71NHa3/6
         VmCg==
X-Gm-Message-State: APjAAAVDS/eoa2so+BaeV4AMnL7zANIrVxBpbsZWWm25xyqQ68ItlE7l
	GMdkoIP0cUy0pNs4mQWgcbg=
X-Google-Smtp-Source: APXvYqzoHPxyY78APjeGrvHLkt60j+IMHqVypBGmE6QgN1WzDJjKFfByJGJFKx4QTaWW4kQIPWXZoQ==
X-Received: by 2002:aa7:820d:: with SMTP id k13mr9115859pfi.10.1576750923986;
        Thu, 19 Dec 2019 02:22:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8048:: with SMTP id y8ls1401832pfm.10.gmail; Thu, 19 Dec
 2019 02:22:03 -0800 (PST)
X-Received: by 2002:a63:2949:: with SMTP id p70mr8352537pgp.191.1576750923532;
        Thu, 19 Dec 2019 02:22:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576750923; cv=none;
        d=google.com; s=arc-20160816;
        b=gAtRM/zrd83lO70aDiHo5F0qaJp2dWKX8SZS0TvmEHZPGLvijZUNYByGwf5DbCL6/W
         aC04B0xxy+IUSu5AYyy/tSD3FkhloJwH8YTuGf0Mb/KC3ooZIxzFQo+0Ck0m/K40UBwK
         GFwTNOLZ6qbo2w56VspsfO+/S8ltRFP5/7aHqlkbz1Tala9WdVKu9UEnVBVtm6Adr2v1
         QH8pyvneaaq9OerpjNp3Vr4jGKGyR4DfqweIATp3SUX7BsY+ubJYMFDmV0yTV3N+602C
         CBLmdYKFNN5w2y3R0h72eUQWHXcxRamsoKoPhcdQnf+cjiZkpcQZtqSaBJtfqoHPl8aY
         LpHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RxF/3xVlUS8ynULbPMYetj7WI4OWmavmAlIDGJ3QWsE=;
        b=zRvU8vQNECf6E87vOl6HbgiViab7KxK044ZcJNgKTByjONAJwzUG2z/ZjJgfxEQo8J
         nAuoNJhtRWG0qxxZJbYE3uIBl0rwHRWd21N4xGOiCvZDf/FfaJiBhcLUsSkRciDDhmza
         HWcZjmDjheEOt6OU82R1CtAcZPdkfrFmb6HvDCSa4V1vCbVXgAzT1rNATFokJVgeQ/r3
         /DjZgQmajZJHBfZaDHjQ7vz/uzWdZQ/WKn9SfH9KOICgsWhf9f1XW5c+LgnJF8pgBTO/
         6fISYfXhr19ymQA6z79d4MXHKsTIB2IbrhqoZFsJ76UEYWdDEMqfg1zWcYQwKHkS05V9
         OJNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mnU7Uy9c;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id j2si252800pfi.1.2019.12.19.02.22.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Dec 2019 02:22:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id dp13so2009984qvb.7
        for <kasan-dev@googlegroups.com>; Thu, 19 Dec 2019 02:22:03 -0800 (PST)
X-Received: by 2002:a05:6214:1103:: with SMTP id e3mr6769571qvs.159.1576750922197;
 Thu, 19 Dec 2019 02:22:02 -0800 (PST)
MIME-Version: 1.0
References: <20191218231150.12139-1-jannh@google.com> <20191218231150.12139-4-jannh@google.com>
In-Reply-To: <20191218231150.12139-4-jannh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 Dec 2019 11:21:51 +0100
Message-ID: <CACT4Y+bKioQorPESS0B83s4TkU0ZSo7M2JpNxJD06W=OihrK9A@mail.gmail.com>
Subject: Re: [PATCH v7 4/4] x86/kasan: Print original address on #GP
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mnU7Uy9c;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Thu, Dec 19, 2019 at 12:12 AM Jann Horn <jannh@google.com> wrote:
>
> Make #GP exceptions caused by out-of-bounds KASAN shadow accesses easier
> to understand by computing the address of the original access and
> printing that. More details are in the comments in the patch.
>
> This turns an error like this:
>
>     kasan: CONFIG_KASAN_INLINE enabled
>     kasan: GPF could be caused by NULL-ptr deref or user memory access
>     general protection fault, probably for non-canonical address
>         0xe017577ddf75b7dd: 0000 [#1] PREEMPT SMP KASAN PTI
>
> into this:
>
>     general protection fault, probably for non-canonical address
>         0xe017577ddf75b7dd: 0000 [#1] PREEMPT SMP KASAN PTI
>     KASAN: maybe wild-memory-access in range
>         [0x00badbeefbadbee8-0x00badbeefbadbeef]
>
> The hook is placed in architecture-independent code, but is currently
> only wired up to the X86 exception handler because I'm not sufficiently
> familiar with the address space layout and exception handling mechanisms
> on other architectures.
>
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>
> Notes:
>     v2:
>      - move to mm/kasan/report.c (Dmitry)
>      - change hook name to be more generic
>      - use TASK_SIZE instead of TASK_SIZE_MAX for compiling on non-x86
>      - don't open-code KASAN_SHADOW_MASK (Dmitry)
>      - add "KASAN: " prefix, but not "BUG: " (Andrey, Dmitry)
>      - use same naming scheme as get_wild_bug_type (Andrey)
>      - this version was "Reviewed-by: Dmitry Vyukov <dvyukov@google.com>"
>     v3:
>      - adjusted example output in commit message based on
>        changes in preceding patch
>      - ensure that KASAN output happens after bust_spinlocks(1)
>      - moved hook in arch/x86/kernel/traps.c such that output
>        appears after the first line of KASAN-independent error report
>     v4:
>      - adjust patch to changes in x86/traps patch
>     v5:
>      - adjust patch to changes in x86/traps patch
>      - fix bug introduced in v3: remove die() call after oops_end()
>     v6:
>      - adjust sample output in commit message
>     v7:
>      - instead of open-coding __die_header()+__die_body() in traps.c,
>        insert a hook call into die_body(), introduced in patch 3/4
>        (Borislav)
>
>  arch/x86/kernel/dumpstack.c |  2 ++
>  arch/x86/mm/kasan_init_64.c | 21 -------------------
>  include/linux/kasan.h       |  6 ++++++
>  mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
>  4 files changed, 48 insertions(+), 21 deletions(-)
>
> diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
> index 8995bf10c97c..ae64ec7f752f 100644
> --- a/arch/x86/kernel/dumpstack.c
> +++ b/arch/x86/kernel/dumpstack.c
> @@ -427,6 +427,8 @@ void die_addr(const char *str, struct pt_regs *regs, long err, long gp_addr)
>         int sig = SIGSEGV;
>
>         __die_header(str, regs, err);
> +       if (gp_addr)
> +               kasan_non_canonical_hook(gp_addr);
>         if (__die_body(str, regs, err))
>                 sig = 0;
>         oops_end(flags, regs, sig);
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index cf5bc37c90ac..763e71abc0fe 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -288,23 +288,6 @@ static void __init kasan_shallow_populate_pgds(void *start, void *end)
>         } while (pgd++, addr = next, addr != (unsigned long)end);
>  }
>
> -#ifdef CONFIG_KASAN_INLINE
> -static int kasan_die_handler(struct notifier_block *self,
> -                            unsigned long val,
> -                            void *data)
> -{
> -       if (val == DIE_GPF) {
> -               pr_emerg("CONFIG_KASAN_INLINE enabled\n");
> -               pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
> -       }
> -       return NOTIFY_OK;
> -}
> -
> -static struct notifier_block kasan_die_notifier = {
> -       .notifier_call = kasan_die_handler,
> -};
> -#endif
> -
>  void __init kasan_early_init(void)
>  {
>         int i;
> @@ -341,10 +324,6 @@ void __init kasan_init(void)
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
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 4f404c565db1..e0238af0388f 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -225,4 +225,10 @@ static inline void kasan_release_vmalloc(unsigned long start,
>                                          unsigned long free_region_end) {}
>  #endif
>
> +#ifdef CONFIG_KASAN_INLINE
> +void kasan_non_canonical_hook(unsigned long addr);
> +#else /* CONFIG_KASAN_INLINE */
> +static inline void kasan_non_canonical_hook(unsigned long addr) { }
> +#endif /* CONFIG_KASAN_INLINE */
> +
>  #endif /* LINUX_KASAN_H */
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 621782100eaa..5ef9f24f566b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -512,3 +512,43 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
>
>         end_report(&flags);
>  }
> +
> +#ifdef CONFIG_KASAN_INLINE
> +/*
> + * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
> + * canonical half of the address space) cause out-of-bounds shadow memory reads
> + * before the actual access. For addresses in the low canonical half of the
> + * address space, as well as most non-canonical addresses, that out-of-bounds
> + * shadow memory access lands in the non-canonical part of the address space.
> + * Help the user figure out what the original bogus pointer was.
> + */
> +void kasan_non_canonical_hook(unsigned long addr)
> +{
> +       unsigned long orig_addr;
> +       const char *bug_type;
> +
> +       if (addr < KASAN_SHADOW_OFFSET)
> +               return;
> +
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
> +               bug_type = "null-ptr-deref";
> +       else if (orig_addr < TASK_SIZE)
> +               bug_type = "probably user-memory-access";
> +       else
> +               bug_type = "maybe wild-memory-access";
> +       pr_alert("KASAN: %s in range [0x%016lx-0x%016lx]\n", bug_type,
> +                orig_addr, orig_addr + KASAN_SHADOW_MASK);
> +}
> +#endif

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbKioQorPESS0B83s4TkU0ZSo7M2JpNxJD06W%3DOihrK9A%40mail.gmail.com.
