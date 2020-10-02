Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBDH53L5QKGQEBGJCM5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DEA7280D21
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 07:45:49 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id j7sf127845wro.14
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 22:45:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601617548; cv=pass;
        d=google.com; s=arc-20160816;
        b=s9Z2ZRNJ2sm4DW1c5HO/OfJubvNaakNDBnFhbJtGTdProdVM3pDgTKHLs1tvyc2p9c
         xX2sAxRVt5GBWnV8UUetc2/t0umhyvD6P02AFKp195T3liYy0YuxLAU5hxd2OtwvLfWB
         spBBkQX1tQHRI1MhC5TvbFT9T/u1kz/3A7odTLBikMEQMKOZMH3SrDBUMLhbv4QGG9il
         Povr3StTPnIlCB1xksnwqRzPFWLYSDeBIXj8JJKt0UcCqfcE0J9vOmJGVcjJ897YceXe
         JUAOnnCTYm9DNzr0Go5JFd55mu0ZTW35dQZlI0mLMNFWulVjeUOaKW1GPNiXGVDpD6Xz
         WDwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AOouDD0TdBIJeJOBnn6sUiHk5tO5Fdetn4ZUEE31G/4=;
        b=QTB8Ddyv+F5tPiioeUSY6jWMVziCIJFz3hVpHoANIdeozZnGEIWncUGOHt8YUVvUJn
         wkPscE8kEZgmti9Pd1jPv0enqgPqqxAFEiYKP46PJDgvoaSp1WThciSsXA7oZsnnjdRZ
         viNf+h54uqYhYSneObq47pxnlVKtJnSv5mz7Dha22ZhGBhbkAjAqZXY75Rkx7Xzalv2N
         rABjl6bqckFJSJ6BYOZEiw7CiHRltMCrYGcJNUNklKlK+deayDK7toe2XrzcehA7A96E
         +kT0ynhauwqRBNIA/URu8vRrowQBgW9bdZ6crsDJ3gAvZX8kWRy7d9M2jdRaGmdUpT+v
         8PQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nEcpsbTx;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AOouDD0TdBIJeJOBnn6sUiHk5tO5Fdetn4ZUEE31G/4=;
        b=shWmRgC+Y6d0mWrTa91CznDZ1HMAK01/Hbu6qJoLh+XaivtCuDWzApokcWtEpsFh1I
         H0KyKOI/OMlnN/YsrmSbeU924h7c1FDD0ImJz+B7n2ggVZUOEz9TU8iGz1bldGdvVdBW
         CIZSxnrgUUAKI/JyODdC5ayl6SGWUf8Zl2QbVceyaMA+pmy8VhIRpxO7llx1w12xoh6E
         iY41FwM7rAqRnWD5xiAIh5lxXKyqgFb4VSrR42BjoeVqQTmIEdkP+zMI/ARvGYe9PGfw
         u3RocPmcB2oMC9Hu6bbIuLF0mg+dMd+g3H2pt1PTiTCFX6N/dj7g4BoGy7+WqdMEXGiu
         aaWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AOouDD0TdBIJeJOBnn6sUiHk5tO5Fdetn4ZUEE31G/4=;
        b=fB071snCJHGCU8K3wtShk3dJjYvRnzYP2aaNqZ9JGoy+QzuBgZIaR3v3pjIUiLqWQA
         r/2A/KQL3x5Einujp8mAlvzSYES4UYio33bLxNjl57ifWfUk36YLSOZyg4m+ec+ZgIcv
         TJP84OFLlx6HZZh+oRJJyzbLF/AHSYoGr01DRS0BxTIBwaV6p7GRlNi25JVu96VqhZen
         zUGtw3bTSf2jt661LfvDMLPI2rH+pY9oUHjgmRnAI9CdvNSLQRO+iTevv7ww7QYH77sQ
         CegtXxndUaTG0doldeXSXp2WubJO9EhEpxF/dbxyYRhkV102w9rvrtdU9w0fnpxSq+5v
         cPGA==
X-Gm-Message-State: AOAM533CJ1w36lPwVTW7LleUsR0yjHfga0mOi2lh76/ndAvyryEZxX4L
	qXsV8yRzvsT3+HgFeJuOiPw=
X-Google-Smtp-Source: ABdhPJyw9l5DemB2CyhXuzXshbze3XVZzb95nwzMZJh81nHEdl8z+Kx73yUJKtv8xsA0QM3ATYZB4g==
X-Received: by 2002:a7b:c847:: with SMTP id c7mr794892wml.149.1601617548758;
        Thu, 01 Oct 2020 22:45:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls474189wrq.0.gmail; Thu, 01 Oct
 2020 22:45:47 -0700 (PDT)
X-Received: by 2002:a5d:43cb:: with SMTP id v11mr961522wrr.188.1601617547827;
        Thu, 01 Oct 2020 22:45:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601617547; cv=none;
        d=google.com; s=arc-20160816;
        b=guooHsFtYCubKuRBM75XgxJqZOrlAdO2lLtGZyUmR5k3VRdzqLjTOhu9VUNrEEKlpj
         o+y6GLFMJXEfUGPRoprb9h7YuDr5K/S01XeO4oEa5xt6ReUJNFX3+swELgAf0xq4qS6v
         miIFwfSPT7mG5IIAtbh49kFer93djoA4SRVx4EM9iTJ4gRL4atiO+taQ7cbGC6H9oIrY
         n3XdUkwlw0EWlOjMRkMmQLQnGzxWIDNoXxhtL8/CEQm5kd8ooYz+ZD0FdNGJpzze1eG+
         YOgINAmXQPKJJSCRXLqij18WP3LC6RZIsLxOGjbZQSKKHXpbhhmOX5HW5L8GGKcTdph3
         zdgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X/Mw4dhIBbKvuicToqPryCf8ZS6JkibVyJYbIfuE7Gs=;
        b=C3vms0F1kbvjt16xtwgKb4uz44JZ+U/NnWdDwB+BEiluDE0D+Hw7YMHY5riNZGiwUo
         ND/7sAbmtwggHMwSJjamvl1rxZqrIS/0Hb5APsnl7Jb6izeq67DIcFBSpsYXyF9/XQh9
         S+pEVwFjZ5KFDWlwZ8goOXiUHkP9TziXeOFccHRz9zSXk3cHaSjft21iA+i1IZ9gqes2
         Vo2tHKE3hHSeE520AKvd8W8FkPgWAzN5tyEuDlbfmgHlohrLaT0vl4t84BojgSRXxtfi
         oS1K8Kuh36ASfTJq0Yrr557GlEsG3cd9dxuerAxcGpM/HHCQjNVpJKNC71vlZDVmBrcD
         OsjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nEcpsbTx;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x641.google.com (mail-ej1-x641.google.com. [2a00:1450:4864:20::641])
        by gmr-mx.google.com with ESMTPS id y84si15790wmc.0.2020.10.01.22.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 22:45:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) client-ip=2a00:1450:4864:20::641;
Received: by mail-ej1-x641.google.com with SMTP id md26so244656ejb.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 22:45:47 -0700 (PDT)
X-Received: by 2002:a17:906:9156:: with SMTP id y22mr174829ejw.184.1601617547226;
 Thu, 01 Oct 2020 22:45:47 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-3-elver@google.com>
In-Reply-To: <20200929133814.2834621-3-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 07:45:20 +0200
Message-ID: <CAG48ez3OKj5Y8BURmqU9BAYWFJH8E8B5Dj9c0=UHutqf7r3hhg@mail.gmail.com>
Subject: Re: [PATCH v4 02/11] x86, kfence: enable KFENCE for x86
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, linux-doc@vger.kernel.org, 
	kernel list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nEcpsbTx;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the x86 architecture. In particular, this implements the
> required interface in <asm/kfence.h> for setting up the pool and
> providing helper functions for protecting and unprotecting pages.
>
> For x86, we need to ensure that the pool uses 4K pages, which is done
> using the set_memory_4k() helper function.
[...]
> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
[...]
> +/* Protect the given page and flush TLBs. */
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
> +       unsigned int level;
> +       pte_t *pte = lookup_address(addr, &level);
> +
> +       if (!pte || level != PG_LEVEL_4K)

Do we actually expect this to happen, or is this just a "robustness"
check? If we don't expect this to happen, there should be a WARN_ON()
around the condition.

> +               return false;
> +
> +       if (protect)
> +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> +       else
> +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));

Hmm... do we have this helper (instead of using the existing helpers
for modifying memory permissions) to work around the allocation out of
the data section?

> +       flush_tlb_one_kernel(addr);
> +       return true;
> +}
> +
> +#endif /* _ASM_X86_KFENCE_H */
> diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
[...]
> @@ -701,6 +702,9 @@ no_context(struct pt_regs *regs, unsigned long error_code,
>         }
>  #endif
>
> +       if (kfence_handle_page_fault(address))
> +               return;
> +
>         /*
>          * 32-bit:
>          *

The standard 5 lines of diff context don't really make it obvious
what's going on here. Here's a diff with more context:


        /*
         * Stack overflow?  During boot, we can fault near the initial
         * stack in the direct map, but that's not an overflow -- check
         * that we're in vmalloc space to avoid this.
         */
        if (is_vmalloc_addr((void *)address) &&
            (((unsigned long)tsk->stack - 1 - address < PAGE_SIZE) ||
             address - ((unsigned long)tsk->stack + THREAD_SIZE) < PAGE_SIZE)) {
                unsigned long stack = __this_cpu_ist_top_va(DF) -
sizeof(void *);
                /*
                 * We're likely to be running with very little stack space
                 * left.  It's plausible that we'd hit this condition but
                 * double-fault even before we get this far, in which case
                 * we're fine: the double-fault handler will deal with it.
                 *
                 * We don't want to make it all the way into the oops code
                 * and then double-fault, though, because we're likely to
                 * break the console driver and lose most of the stack dump.
                 */
                asm volatile ("movq %[stack], %%rsp\n\t"
                              "call handle_stack_overflow\n\t"
                              "1: jmp 1b"
                              : ASM_CALL_CONSTRAINT
                              : "D" ("kernel stack overflow (page fault)"),
                                "S" (regs), "d" (address),
                                [stack] "rm" (stack));
                unreachable();
        }
 #endif

+       if (kfence_handle_page_fault(address))
+               return;
+
        /*
         * 32-bit:
         *
         *   Valid to do another page fault here, because if this fault
         *   had been triggered by is_prefetch fixup_exception would have
         *   handled it.
         *
         * 64-bit:
         *
         *   Hall of shame of CPU/BIOS bugs.
         */
        if (is_prefetch(regs, error_code, address))
                return;

        if (is_errata93(regs, address))
                return;

        /*
         * Buggy firmware could access regions which might page fault, try to
         * recover from such faults.
         */
        if (IS_ENABLED(CONFIG_EFI))
                efi_recover_from_page_fault(address);

 oops:
        /*
         * Oops. The kernel tried to access some bad page. We'll have to
         * terminate things with extreme prejudice:
         */
        flags = oops_begin();



Shouldn't kfence_handle_page_fault() happen after prefetch handling,
at least? Maybe directly above the "oops" label?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3OKj5Y8BURmqU9BAYWFJH8E8B5Dj9c0%3DUHutqf7r3hhg%40mail.gmail.com.
