Return-Path: <kasan-dev+bncBCMIZB7QWENRBGGK5D3AKGQEDKTZYKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 775611EF5EA
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 12:57:30 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id x8sf1088079pll.19
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 03:57:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591354648; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uy9hzvXBORHJ5djBl1xUuV5VvNdMKzLgAGazcxxwNlSeZUNnwjaIgweju6pTLy2b/g
         sFXn5VLTRYlkcXNF0LiKjGs1IBUC5Nqo/rX+oYYmqQctaUDWDmvj10yW9YNAmzNCW003
         qimJcoTmiBYIunwUm8wsVMtuWAhymBN/FP4fovXlC0U1VwV8mOQl+iIQgJjHTAna1yoW
         aBlFEHbu0Q2hMtbii/CsqVruZbgkqlRxE4ui1Est8gqiLoeMuwOXyZA7G7wyn6W/gXjA
         bgQ2TNKM94MnjmrjM+wmOOAYDltX8QfZswvimL2QMFORy1Rl3+a4BBvbo3D/6gVzRMA4
         WZ1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jZci16vti8LwdbUS0lXCLvXnkvSc5RRcT3d1nwER7rE=;
        b=x8udBDY5v5PeAFoGoqrPqbuPpBLxpn1ONxR8QFUVqMLO0CeBNm8Ubq1/L1yxT/F6Ff
         iUHaVmeVCTBXTiFUeBOa9tfj9lmgdKU2I27YdAQcBdFZvzXEqa07JB4gNW3iGbh1Pgkl
         foGRsFPCrwTaHI8EVRgniCSMKL2sLej+p7S9aTjvBZX+nA150/n5LcTz6NLtRJBMItSq
         X2o4qixt066NgjtpbdvUnEyYv0RxlJFw9A7ygQO/tTRuOZ/3RiiseSoPZte8FKxeUD+t
         HPVuNwUcg+lwAFDnVDLCQpk05A5B6YtlUq8TLx1tmaIe2jAOIe5p9TCSYmTKw30RjLRS
         phuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G4xOIGIT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jZci16vti8LwdbUS0lXCLvXnkvSc5RRcT3d1nwER7rE=;
        b=W9/bGBZlh5EAX7W8/NWzZPU39GOb+X5sxpRLmJmWlwSNzXsYWynJZQ5/hWdgtY9nUx
         inGkt5iaChuLWQC/Z15lrRV9xv/WtIa4dnreWTJuFh0wZVt2Iv1IiZljd6VYXYyFIdfQ
         ZcZEpZLVboEISJuw8LLzWtKpWgArJ9+dkSQyz5Hhag+IKNZ5nGYi7/gc18xzmbjpeWHm
         AthOTDYsPWrc33Uk+dGkTzwGgy/rqJmiY4FAPd6v2sMYOmWMD1iq9fJ8J+Z23CIXS/c4
         KcvUHauPQO9Non9HgPN+GXDgEJp3mJZhZVHs/Kovk9Q6pN9IqY+iEVtRexF3xXyR3G9U
         Dmyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jZci16vti8LwdbUS0lXCLvXnkvSc5RRcT3d1nwER7rE=;
        b=U4Zg8NClIpgBA9PTe58sgIJ3DkcinvujGfynNYGcBVA+6Y7uaO8YNnrrJqjCL3Vwsj
         WRbOcykXqlIwBEtmCnUBwhqDwh9+SZ9ld2orwt7a2uPwyo4lNGKwmPiR0/CAinMXP3Jk
         3HFUgv8glxBzfh3c7lv6saQBCvi8Wk8frV19FGTEGYg8TnnUciL8tyGvEM50qRzyLB0L
         3IXsKoRxNxBhoOtn3kSDs3ZKhMivzzUYi90cqXoecqWxjM/Njlwa61qUcYo2cNlzuR0Y
         fNRrEPv+9Vt53vLzq1+F7WObcuE+OQCu7BBztbMJ3KBH2OX3frtesDgxusimUbpA1BLX
         Hx9Q==
X-Gm-Message-State: AOAM530oL2mGdGrOFm/uDGYSbKOjm9qgM8R48LNQT+R2NC8QSOX1Gw12
	nIMH9F0ybVtaEYS9GINTF/g=
X-Google-Smtp-Source: ABdhPJzfob0djpTpPjjQoaYJ7JDemsGVj+ysJhUQgXq/F1ZsWWxHZu8z/zvGkXOAJJTX24pDzOe9lA==
X-Received: by 2002:a05:6a00:2ae:: with SMTP id q14mr3578601pfs.255.1591354648712;
        Fri, 05 Jun 2020 03:57:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab89:: with SMTP id f9ls3405007plr.3.gmail; Fri, 05
 Jun 2020 03:57:28 -0700 (PDT)
X-Received: by 2002:a17:90b:e05:: with SMTP id ge5mr2376034pjb.49.1591354648295;
        Fri, 05 Jun 2020 03:57:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591354648; cv=none;
        d=google.com; s=arc-20160816;
        b=GyV+kSuKhPHNHkdD0LrqJR7/zW77CWRdhrr1rruFrFJFqWFoDnFV4nLOCdPjvX0YSC
         nf+EFuQZBk+YJn2BCRnnv63bgn5yU/XX1aJTcbQVLWFvlk19d6yExVGl1WIf2Md+oegy
         zaMacJpKMfLnHxCEioznY7ClaXviFBDgL31HTp/5PVeKJXN+6E8x6zvjk3bwfm1K+z8b
         h6eso2KX1aKK4vdL95Vh/lW8aVDMeCXZXsLXJdenP5BUPzL34WY/o0vsART+Eyvty28o
         PGtTbjqvu3lFrrHsfbD2vN728/8KonqirV8t+x5HM1CGXoujptEHczQ7hYSLmEyDgAPh
         AvsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l+FRzkDxx24cf0JvfqgWOwJXwQpB0rcy5gXQ1S61x5s=;
        b=EAXHjrt2fyEiKko+9hx2m7mrwFZCYEi8dKd3TlsjhOvNprcvlFmx4m62zlgm8wa639
         V2FH6BewxIICzxfhTsK0SZY1EqMxDQ/VaxyevJqKkVWo5QIqCF2mQJ4/uy+77+UshSBZ
         cuh7oTbba5i6n3GDszTsBhM5ylE+LGENYi7HjAf32QiWKaSDGydeFFIzeFtsQsEinqxU
         UWznZaBBDRtXBxFDCShgu/NMZJisVGE81Py+HUiVydnDy3dAykErpiiQfEvTCVVzSzJP
         bMHdaqo9VJ2FIc6Xci23oFvvyVxndAVEUOZlw+dotMmeGtjbp1u/X0SwRypfh0qKlavn
         3AUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=G4xOIGIT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id t72si569766pfc.5.2020.06.05.03.57.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 03:57:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id y1so8016541qtv.12
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 03:57:28 -0700 (PDT)
X-Received: by 2002:ac8:260b:: with SMTP id u11mr9415205qtu.380.1591354647018;
 Fri, 05 Jun 2020 03:57:27 -0700 (PDT)
MIME-Version: 1.0
References: <20200605082839.226418-1-elver@google.com>
In-Reply-To: <20200605082839.226418-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Jun 2020 12:57:15 +0200
Message-ID: <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions noinstr-compatible
To: Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=G4xOIGIT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Fri, Jun 5, 2020 at 10:28 AM Marco Elver <elver@google.com> wrote:
>
> While we lack a compiler attribute to add to noinstr that would disable
> KCOV, make the KCOV runtime functions return if the caller is in a
> noinstr section, and mark them noinstr.
>
> Declare write_comp_data() as __always_inline to ensure it is inlined,
> which also reduces stack usage and removes one extra call from the
> fast-path.
>
> In future, our compilers may provide an attribute to implement
> __no_sanitize_coverage, which can then be added to noinstr, and the
> checks added in this patch can be guarded by an #ifdef checking if the
> compiler has such an attribute or not.

Adding noinstr attribute to instrumentation callbacks looks fine to me.

But I don't understand the within_noinstr_section part.
As the cover letter mentions, kcov callbacks don't do much and we
already have it inserted and called. What is the benefit of bailing
out a bit earlier rather than letting it run to completion?
Is the only reason for potential faults on access to the vmalloc-ed
region? If so, I think the right approach is to eliminate the faults
(if it's possible). We don't want faults for other reasons: they
caused recursion on ARM and these callbacks are inserted into lots of
sensitive code, so I am not sure checking only noinstr will resolve
all potential issues. E.g. we may get a deadlock if we fault from a
code that holds some lock, or we still can get that recursion on ARM (
I don't think all of page fault handling code is noinstr).
The fact that we started getting faults again (did we?) looks like a
regression related to remote KCOV.
Andrey, Mark, do you know if it's possible to pre-fault these areas?
The difference is that they run in a context of kernel threads. Maybe
we could do kcov_fault_in_area when we activate and remove KCOV on an
area? This way we get all faults in a very well-defined place (which
is not noinstr and holds known locks).



> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Applies to -tip only currently, because of the use of instrumentation.h
> markers.
>
> v3:
> * Remove objtool hack, and instead properly mark __sanitizer_cov
>   functions as noinstr.
> * Add comment about .entry.text.
>
> v2: https://lkml.kernel.org/r/20200604145635.21565-1-elver@google.com
> * Rewrite based on Peter's and Andrey's feedback -- v1 worked because we
>   got lucky. Let's not rely on luck, as it will be difficult to ensure the
>   same conditions remain true in future.
>
> v1: https://lkml.kernel.org/r/20200604095057.259452-1-elver@google.com
>
> Note: There are a set of KCOV patches from Andrey in -next:
> https://lkml.kernel.org/r/cover.1585233617.git.andreyknvl@google.com --
> Git cleanly merges this patch with those patches, and no merge conflict
> is expected.
> ---
>  kernel/kcov.c | 59 +++++++++++++++++++++++++++++++++++++++------------
>  1 file changed, 45 insertions(+), 14 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 8accc9722a81..84cdc30d478e 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -6,6 +6,7 @@
>  #include <linux/compiler.h>
>  #include <linux/errno.h>
>  #include <linux/export.h>
> +#include <linux/instrumentation.h>
>  #include <linux/types.h>
>  #include <linux/file.h>
>  #include <linux/fs.h>
> @@ -24,6 +25,7 @@
>  #include <linux/refcount.h>
>  #include <linux/log2.h>
>  #include <asm/setup.h>
> +#include <asm/sections.h>
>
>  #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
>
> @@ -172,20 +174,38 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
>         return ip;
>  }
>
> +/* Return true if @ip is within a noinstr section. */
> +static __always_inline bool within_noinstr_section(unsigned long ip)
> +{
> +       /*
> +        * Note: .entry.text is also considered noinstr, but for now, since all
> +        * .entry.text code lives in .S files, these are never instrumented.
> +        */
> +       return (unsigned long)__noinstr_text_start <= ip &&
> +              ip < (unsigned long)__noinstr_text_end;
> +}
> +
>  /*
>   * Entry point from instrumented code.
>   * This is called once per basic-block/edge.
>   */
> -void notrace __sanitizer_cov_trace_pc(void)
> +void noinstr __sanitizer_cov_trace_pc(void)
>  {
>         struct task_struct *t;
>         unsigned long *area;
> -       unsigned long ip = canonicalize_ip(_RET_IP_);
> +       unsigned long ip;
>         unsigned long pos;
>
> +       if (unlikely(within_noinstr_section(_RET_IP_)))
> +               return;
> +
> +       instrumentation_begin();
> +
>         t = current;
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> -               return;
> +               goto out;
> +
> +       ip = canonicalize_ip(_RET_IP_);
>
>         area = t->kcov_area;
>         /* The first 64-bit word is the number of subsequent PCs. */
> @@ -194,19 +214,27 @@ void notrace __sanitizer_cov_trace_pc(void)
>                 area[pos] = ip;
>                 WRITE_ONCE(area[0], pos);
>         }
> +
> +out:
> +       instrumentation_end();
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
>
>  #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
> -static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> +static __always_inline void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>  {
>         struct task_struct *t;
>         u64 *area;
>         u64 count, start_index, end_pos, max_pos;
>
> +       if (unlikely(within_noinstr_section(ip)))
> +               return;
> +
> +       instrumentation_begin();
> +
>         t = current;
>         if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
> -               return;
> +               goto out;
>
>         ip = canonicalize_ip(ip);
>
> @@ -229,61 +257,64 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>                 area[start_index + 3] = ip;
>                 WRITE_ONCE(area[0], count + 1);
>         }
> +
> +out:
> +       instrumentation_end();
>  }
>
> -void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
> +void noinstr __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
>  {
>         write_comp_data(KCOV_CMP_SIZE(0), arg1, arg2, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_cmp1);
>
> -void notrace __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2)
> +void noinstr __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2)
>  {
>         write_comp_data(KCOV_CMP_SIZE(1), arg1, arg2, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_cmp2);
>
> -void notrace __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2)
> +void noinstr __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2)
>  {
>         write_comp_data(KCOV_CMP_SIZE(2), arg1, arg2, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_cmp4);
>
> -void notrace __sanitizer_cov_trace_cmp8(u64 arg1, u64 arg2)
> +void noinstr __sanitizer_cov_trace_cmp8(u64 arg1, u64 arg2)
>  {
>         write_comp_data(KCOV_CMP_SIZE(3), arg1, arg2, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_cmp8);
>
> -void notrace __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2)
> +void noinstr __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2)
>  {
>         write_comp_data(KCOV_CMP_SIZE(0) | KCOV_CMP_CONST, arg1, arg2,
>                         _RET_IP_);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp1);
>
> -void notrace __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2)
> +void noinstr __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2)
>  {
>         write_comp_data(KCOV_CMP_SIZE(1) | KCOV_CMP_CONST, arg1, arg2,
>                         _RET_IP_);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp2);
>
> -void notrace __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2)
> +void noinstr __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2)
>  {
>         write_comp_data(KCOV_CMP_SIZE(2) | KCOV_CMP_CONST, arg1, arg2,
>                         _RET_IP_);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp4);
>
> -void notrace __sanitizer_cov_trace_const_cmp8(u64 arg1, u64 arg2)
> +void noinstr __sanitizer_cov_trace_const_cmp8(u64 arg1, u64 arg2)
>  {
>         write_comp_data(KCOV_CMP_SIZE(3) | KCOV_CMP_CONST, arg1, arg2,
>                         _RET_IP_);
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp8);
>
> -void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
> +void noinstr __sanitizer_cov_trace_switch(u64 val, u64 *cases)
>  {
>         u64 i;
>         u64 count = cases[0];
> --
> 2.27.0.278.ge193c7cf3a9-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0%2BpjgYDsx%2BA%40mail.gmail.com.
