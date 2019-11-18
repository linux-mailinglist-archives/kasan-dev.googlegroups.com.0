Return-Path: <kasan-dev+bncBCMIZB7QWENRBAFQZHXAKGQEXE5VSPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 26961100067
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 09:36:18 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id w9sf12774772pgl.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 00:36:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574066176; cv=pass;
        d=google.com; s=arc-20160816;
        b=W2/tcUWa6ZpZ/yeKmA5fbQCFn5B1g4X0PC1Hb7yq0P4IeF/pVieuhQ+azxNvxJG/ic
         xHSPVaFtU93Zzw3joVSR6MCFHgXM6S7LCabtOnJfrgZZzjRkBLho211Yq8vJy9GUTqXJ
         ruxQXsbqU3kGuvUVhAgYDAUGMPCRxEfswioNW7vT4SfXZquQGGoh2JNx90m9keA4yE2+
         XL9azW9frc+24Qx3fpldG2yHcgH7loWB+7lqhDwL83Vjf0taO4JKVk+230FDkI6LghfO
         tfuU8xSBgiFBbOZ83ZeUx7Le/5eiP6dWo87HIK80QOnIkiLlCVMi9+gd56D4U1qnvMua
         tmjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=P+TiENQD97ePH8TryLa1WZs+h5pYnw9K3/2D8PqsxBU=;
        b=ULYQjjETdqf8hSCVYzuoWBC9kXJrtVZGd6jalsFJ+oBqkZ8kr20Z4cV0W2Z0tX0JL0
         xhmep3y9DpBjBiETR26Flgt2ap9ojUgh8W8e411c3VpRC0Nw3FtRL5bhPG203rIQPAZo
         9bAOAZ2G8wRlWTOcjGJbiTPH9vJQj+HZOYGtRi4Gl/YZ7VOt+9tIyNL0B5fOfBhT0LV0
         5PQcX1f2yj903BKU2sbsuboa1IJLlY44fsbEdZLc37GxXed43VCFIraZH7slSWwvGl/F
         qUkQbdV3oBsnTUkkWkg2xQEx6g2GjJr0W4FWc75MX/qmh21qdLpaxQtvKyAZ249b3cR3
         hG4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YgFrNR38;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P+TiENQD97ePH8TryLa1WZs+h5pYnw9K3/2D8PqsxBU=;
        b=YZ0j0767l/yVtr4UG4Yto9jPgvOexud5O+1KT0UJWXgoT3IagQEhVwUkTPTwSQE6aH
         nVQ2LiKO7c60VNHM279uHWabGIVsAqOzTc3zcxYYI1tCnLttNs8IWfisoYb89F2HkRQf
         lxunIC+/FeNdkBwIgCJxJtJvCf6Nr/WzGG7q2f16ilW4wb78Tgw6FclcjyUELVrkizUB
         s6cvaG3uwQC+iEy2qz4jaewLCaARdGfhYttQXlKCSNY3c2alw2qZzBvmSAQ4qeJFuhgG
         lGeBrHyIv8LWJVXEF5AJkGDOEaH9uEmgehCPsqDImPT40ED7edI19i40uKLsegxjVgfI
         SUhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P+TiENQD97ePH8TryLa1WZs+h5pYnw9K3/2D8PqsxBU=;
        b=MZIAMpGU48KZ8ybdXV6cG5Tk5d3Gv+PWdS9IToSbs7H9wEvNNUga4g/QpWdUPI224C
         cijO6H49CZc777/FFQRc8Hp0WOWagfywxExfD9/b7zeVpvTuRdATcVph15jHU1+G04Sf
         eGbXxL1rgp+JwpaNjv7ICAoJquhpCEfd5T+R8Oz6lmlJG5WXmzOWVtDukSDSXDQGq/4x
         zMb2XcdCJQkutQYQHC52YhBV87PhSZNB2sEcKEeQx5NoayqPZYf43ks98L5LvjolmzyR
         XYVGMLMK5Rhpyl/+xlStHi2b4wpWqcbTVZATTtGRSse27rUztSlPIjYnMuFXpnGL1se5
         B9Ag==
X-Gm-Message-State: APjAAAUGtbEqhOYuIe6IwhNqC/O8RbbmwIQYA0i9lPZSmOj8sMK6SOCM
	BTw9ElW4QoNKvX7PQ8bH9FI=
X-Google-Smtp-Source: APXvYqzlC2RkZgM+e8eIBF1eLd+gceSpSKpouh3adXjG0VuUjxb5i/tR4NhffUBR+qy80v68Zw7V2g==
X-Received: by 2002:a63:1526:: with SMTP id v38mr1430594pgl.16.1574066176290;
        Mon, 18 Nov 2019 00:36:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3d86:: with SMTP id k128ls429859pga.11.gmail; Mon, 18
 Nov 2019 00:36:15 -0800 (PST)
X-Received: by 2002:aa7:8006:: with SMTP id j6mr4864918pfi.182.1574066175845;
        Mon, 18 Nov 2019 00:36:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574066175; cv=none;
        d=google.com; s=arc-20160816;
        b=D77ebxrCauK478ZonVWUbvnfPXGfpwuThxDypZtd3TmxIWyALisQe75Z7fGBe0l3nt
         zqT3/C1yv8OsSG01nDbeRIvzxY11NXIK3RuaPJqO8gatKY78nVIwEhmRT15vxzPvXCsW
         cleHhHeksttE+7k0SvU4h49kssLZF1zbYZW7lQ9zsshN5TmsXJl3skURVkDZEoa2XyX2
         NdcA2O5XoAD4YUKT34oRW++b/lmSEUAa7+QAADdU51DQ32ghpvPYxqMOaxuAMH7uRmk+
         +ocSSS8jKQ2s3Acr/h2lWvnlQ7eZ9RhNcS/5Rq4kiyqaLFSpXkq59rZDGC+UiSPRDJlm
         3YOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JqpfOa+eDbyWdbseRYm3zOhbqqwwfORj1AqplMRUi+w=;
        b=kYCv1cXIO00S4/wDxkGpjt83mcquElXCCaOkIlpMRILYeQ0+AwhXdQf02Jc10ob4QN
         s1hWpPupE9AwLSgDnXXXX+lUXMhBnxVf0gO13PtdNNKJahKTz3u0V2I/zloXfgIGsX1W
         OmrTH3pUasVUCBXOur6ca9BVNe42OW4Wis+t/XPlKr6UGGGGiRXY4QEuaU/Eot0g1Pyg
         bFtRXb19Y9PcCjYHINFaKug9/n/Yekg7lLVnVinzXmW1LmY7w7WSpb5Ujs5ZFdgYFyi0
         9QuhI5IcbOp2sWvqq6yzA5uSPbzdW5QstM/mdY8gtvPhAvArMgOH20lhPsC0AoKF2YAw
         Xv/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YgFrNR38;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id v18si711564pjn.1.2019.11.18.00.36.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Nov 2019 00:36:15 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id t8so19334157qtc.6
        for <kasan-dev@googlegroups.com>; Mon, 18 Nov 2019 00:36:15 -0800 (PST)
X-Received: by 2002:aed:24af:: with SMTP id t44mr25440361qtc.57.1574066174427;
 Mon, 18 Nov 2019 00:36:14 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-3-jannh@google.com>
In-Reply-To: <20191115191728.87338-3-jannh@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Nov 2019 09:36:03 +0100
Message-ID: <CACT4Y+ZmAupVG204VuL_73a8FdbM1NHwgV9oC4mK09ELnYujbA@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] x86/kasan: Print original address on #GP
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
 header.i=@google.com header.s=20161025 header.b=YgFrNR38;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Fri, Nov 15, 2019 at 8:17 PM Jann Horn <jannh@google.com> wrote:
>
> Make #GP exceptions caused by out-of-bounds KASAN shadow accesses easier
> to understand by computing the address of the original access and
> printing that. More details are in the comments in the patch.
>
> This turns an error like this:
>
>     kasan: CONFIG_KASAN_INLINE enabled
>     kasan: GPF could be caused by NULL-ptr deref or user memory access
>     traps: probably dereferencing non-canonical address 0xe017577ddf75b7dd
>     general protection fault: 0000 [#1] PREEMPT SMP KASAN PTI
>
> into this:
>
>     traps: dereferencing non-canonical address 0xe017577ddf75b7dd
>     traps: probably dereferencing non-canonical address 0xe017577ddf75b7dd
>     KASAN: maybe wild-memory-access in range
>             [0x00badbeefbadbee8-0x00badbeefbadbeef]
>     general protection fault: 0000 [#1] PREEMPT SMP KASAN PTI
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
>
>  arch/x86/kernel/traps.c     |  2 ++
>  arch/x86/mm/kasan_init_64.c | 21 -------------------
>  include/linux/kasan.h       |  6 ++++++
>  mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
>  4 files changed, 48 insertions(+), 21 deletions(-)
>
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index 12d42697a18e..87b52682a37a 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -37,6 +37,7 @@
>  #include <linux/mm.h>
>  #include <linux/smp.h>
>  #include <linux/io.h>
> +#include <linux/kasan.h>
>  #include <asm/stacktrace.h>
>  #include <asm/processor.h>
>  #include <asm/debugreg.h>
> @@ -540,6 +541,7 @@ static void print_kernel_gp_address(struct pt_regs *regs)
>
>         pr_alert("probably dereferencing non-canonical address 0x%016lx\n",
>                  addr_ref);
> +       kasan_non_canonical_hook(addr_ref);
>  #endif
>  }
>
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 296da58f3013..69c437fb21cc 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -245,23 +245,6 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
>         } while (pgd++, addr = next, addr != end);
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
> @@ -298,10 +281,6 @@ void __init kasan_init(void)
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
> index cc8a03cc9674..7305024b44e3 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -194,4 +194,10 @@ static inline void *kasan_reset_tag(const void *addr)
>
>  #endif /* CONFIG_KASAN_SW_TAGS */
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
> --
> 2.24.0.432.g9d3f5f5b63-goog


Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZmAupVG204VuL_73a8FdbM1NHwgV9oC4mK09ELnYujbA%40mail.gmail.com.
