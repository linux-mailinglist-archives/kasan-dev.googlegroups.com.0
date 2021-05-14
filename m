Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN5K7KCAMGQEKRCEXMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CB19380CC0
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 17:20:25 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id m68-20020a6326470000b029020f37ad2901sf19339723pgm.7
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 08:20:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621005624; cv=pass;
        d=google.com; s=arc-20160816;
        b=w9kkONoX4EuFqGvtxL04XU6NZzHOta98B3Dh4IAi2bZU+cc/xfFJPV9yZmfUbnH1T6
         COW7O5Ss8cvlze+BozkUEHF4EI4ROgW6IeZerCHvJl8aOAvZdmRl7EDI3FIQuBE5FAdQ
         YfJTZMnhUoXYZQUooIgFeGEf3Ys3RGFkjlPwIxjgXg4j7qd9ulC2CkfXntJVG1QuJ3Vb
         4KywERtHmgCaIr29cFchr5MN+TcbEJf07NKhAlY8OvdppO8+jSqTm4qTOMlrxjOZdNZe
         OGm7yec4ZK9ZAB6UbC/7/QfP1/l2rAVBtmbPEPcmuxcE7zT1PK5wZICHeDFuSbtCg4LL
         cRWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Q4w6SIFhAs5mK2EBMFEfJb2klRMiIASQXiTdimJgSVU=;
        b=uSEvhZ5qEclC3MFHbIv5SRtRAiwlVDdCpuPEq/cMt+nPv/4JtAgbNnTO2EL1xDQW7b
         QzZU5wgOv4EmmHLBdMv/qx1ot1KztszPUVhQbPvRsE5XRIx2pIx1NNky058CkOUQqjeJ
         XcEVS5/7jt8OHVAwsD1xQfZ6VrNV1Y1vCZMgg1ypUNr9aO4+9UsZYcSkTBvma1PohTu5
         +bLMd9Exf/LJcoho0btkQ51+ptxnYqXz7PP3DFB4paM+PH9Wlw5WfHjDm9CpgXcE/+dJ
         TmDSjAgGxnZY9PO52wgw+18UiZe4RbuJIZ0c6WX/0MVZU4dRQ6liJ/MCkw62fLuDQKTh
         xjgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ExnpX06y;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q4w6SIFhAs5mK2EBMFEfJb2klRMiIASQXiTdimJgSVU=;
        b=lFCJc5JqIUcy0aeq5w4hrxD+zRRZGlYVRGQ8cIvb4Qo/iR6FpJR1d9Bn7sd1MOK/3B
         KY+1kvomYG3WkGdVZW+ER6caxdLvDPtrEEoErAGjHU9d2RhfYtGP//5yc21FBnMLBTsF
         aeB8FGPPJJkXobCC3oZLyKq+7CCmfMCym7xA/HwJkPv9YlOHtVkvnguZHkMyZ2oXAeMX
         3GIMxuNqytUExujSnxfQjDi0vY4fxxV22IYSaZs5s8i3pIFiWkUsC8uZwTDrGMv3nMMf
         6NC+opGOaoh6rW+rBAe6ryT3etnjngTCVrXPYu9gvapf9rOFmV9L337bDYZfHnXQf8x1
         RXxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q4w6SIFhAs5mK2EBMFEfJb2klRMiIASQXiTdimJgSVU=;
        b=PV0eAV1XsGV2Y2tTZxwQzhtbdKJ9561u9Ve5uHaLPyzE+aUV1qyYU0r6SbdVSX1T36
         7yxl4nVBWK84DkbofrOJBkNHCS02f+zLWjFldK0N4MoIv1E7gJTL7mS3EzmIBZdllo3z
         iBm0T/01lgRHgDxqKe8aeRdyVBZNTuuE3FxQQ/gh15tN5RoFr/mAavBrCwvS9LqZ3Nq2
         Ka8D2cPD8NNcmN/ltGJYReNgVEQvt76aypt02D1qoOFZNP4sQAuNe7LucgJugBd+GNIJ
         Htcte0bMDBkRt6pLuTcowGNRONnqgyynkoXOixYH6n/f/VP0h+OpgWxRytakjnaKY9xR
         ewvQ==
X-Gm-Message-State: AOAM530XyBuxkRL+w9tgRd25pvAttb5LtZqwTnWW+q5pdaRVmyykEqWz
	FGQSQf8ceGOtNs2TUBFrh0w=
X-Google-Smtp-Source: ABdhPJzG0nR0qSnsCBaYvatQQa5UNcsc0OhwcMRBlH5Yt/eUqFCFPc+yiDjD0E0l1nItWfJSx6a9tQ==
X-Received: by 2002:a17:902:d902:b029:ef:abdc:f16c with SMTP id c2-20020a170902d902b02900efabdcf16cmr6055030plz.64.1621005624037;
        Fri, 14 May 2021 08:20:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c145:: with SMTP id p5ls4259015pgi.7.gmail; Fri, 14 May
 2021 08:20:23 -0700 (PDT)
X-Received: by 2002:aa7:955b:0:b029:28e:a874:d0c2 with SMTP id w27-20020aa7955b0000b029028ea874d0c2mr45666833pfq.66.1621005623398;
        Fri, 14 May 2021 08:20:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621005623; cv=none;
        d=google.com; s=arc-20160816;
        b=B4y+e/AfSxf7cq1wabsQfctsqL1gy5tyykTKPQvJ5MUsPGi+hCs5x2TKzarCTZD3PC
         TnemboaZl6ONx7do5AzKPq8ekD1ClLbiFkusHmcQqwLer2DKuQwDliteXyUuNOTdTr2g
         Ykhwx1utoqGkB2YMKbMP79hFazOhw7HaRFb6ww78RaTnnldXUNoDDcH23wrD2NO6TJKU
         0dug5pX+bf5G6HsEdffabGPWTFKzP18S4lTxSwA2iApHZ0JuIIAVU+VOO+1YpJKFqDDZ
         XHKudDlayfQs9c+Ytm6ZqmEWCFqdDZ/dw20JvWbiM+C1tcasL2Q1Z5FITb26beEeMM6q
         +dtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OUtJdEoTp2E5reOLxrwFg0FEHgUh9mJq9am3px70vxo=;
        b=p2XotoRG8sOWr9bDugE+WVdF+uh6NX/kY9kIjxQbe/HQJYrpXJY4z1h7RzP0NUd1hO
         NQf1vZz1ynefLqykLtxUW6OyugFURc9cyWUEQdiR+LSYPm01paX9Q/tTAkGvQX6Etvje
         EtYJ5WkG4fmPfF9zhG432V+eUlVos8GFiSg+B1THITNhoS057itR9bAjtbyJ31K04R5s
         +qL5yaV4MiM7ThikQ1lOjblNAtlprIqMMgr2GQxiRzVUbDJVgSSyNKCEmccil1UnRjFH
         eH7gPWXT6O4GvBiktB+W00I5hTtaP4gXR29G2AsIszqGfUSbzXYMQtQZNKP3LGUSPLWt
         yjug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ExnpX06y;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id n21si678894pjq.1.2021.05.14.08.20.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 08:20:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id n32-20020a9d1ea30000b02902a53d6ad4bdso26737227otn.3
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 08:20:23 -0700 (PDT)
X-Received: by 2002:a9d:7a54:: with SMTP id z20mr25363513otm.17.1621005622590;
 Fri, 14 May 2021 08:20:22 -0700 (PDT)
MIME-Version: 1.0
References: <20210514034432.2004082-1-liushixin2@huawei.com>
In-Reply-To: <20210514034432.2004082-1-liushixin2@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 May 2021 17:20:10 +0200
Message-ID: <CANpmjNMN2xQ28nsqUzE+XJ_muHUT+EGdCTCDhvLH2hMMxuTidQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2] riscv: Enable KFENCE for riscv64
To: Liu Shixin <liushixin2@huawei.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ExnpX06y;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Fri, 14 May 2021 at 05:11, Liu Shixin <liushixin2@huawei.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the riscv64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
>
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the kfence pool to be mapped at
> page granularity.
>
> I tested this patch using the testcases in kfence_test.c and all passed.
>
> Signed-off-by: Liu Shixin <liushixin2@huawei.com>

Acked-by: Marco Elver <elver@google.com>


> ---
> v1->v2: Change kmalloc() to pte_alloc_one_kernel() for allocating pte.
>
>  arch/riscv/Kconfig              |  1 +
>  arch/riscv/include/asm/kfence.h | 51 +++++++++++++++++++++++++++++++++
>  arch/riscv/mm/fault.c           | 11 ++++++-
>  3 files changed, 62 insertions(+), 1 deletion(-)
>  create mode 100644 arch/riscv/include/asm/kfence.h
>
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index c426e7d20907..000d8aba1030 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -64,6 +64,7 @@ config RISCV
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN if MMU && 64BIT
>         select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
> +       select HAVE_ARCH_KFENCE if MMU && 64BIT
>         select HAVE_ARCH_KGDB
>         select HAVE_ARCH_KGDB_QXFER_PKT
>         select HAVE_ARCH_MMAP_RND_BITS if MMU
> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
> new file mode 100644
> index 000000000000..c25d67e0b8ba
> --- /dev/null
> +++ b/arch/riscv/include/asm/kfence.h
> @@ -0,0 +1,51 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef _ASM_RISCV_KFENCE_H
> +#define _ASM_RISCV_KFENCE_H
> +
> +#include <linux/kfence.h>
> +#include <linux/pfn.h>
> +#include <asm-generic/pgalloc.h>
> +#include <asm/pgtable.h>
> +
> +static inline bool arch_kfence_init_pool(void)
> +{
> +       int i;
> +       unsigned long addr;
> +       pte_t *pte;
> +       pmd_t *pmd;
> +
> +       for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
> +            addr += PAGE_SIZE) {
> +               pte = virt_to_kpte(addr);
> +               pmd = pmd_off_k(addr);
> +
> +               if (!pmd_leaf(*pmd) && pte_present(*pte))
> +                       continue;
> +
> +               pte = pte_alloc_one_kernel(&init_mm);
> +               for (i = 0; i < PTRS_PER_PTE; i++)
> +                       set_pte(pte + i, pfn_pte(PFN_DOWN(__pa((addr & PMD_MASK) + i * PAGE_SIZE)), PAGE_KERNEL));
> +
> +               set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
> +               flush_tlb_kernel_range(addr, addr + PMD_SIZE);
> +       }
> +
> +       return true;
> +}
> +
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
> +       pte_t *pte = virt_to_kpte(addr);
> +
> +       if (protect)
> +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> +       else
> +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> +
> +       flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
> +
> +       return true;
> +}
> +
> +#endif /* _ASM_RISCV_KFENCE_H */
> diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
> index 096463cc6fff..aa08dd2f8fae 100644
> --- a/arch/riscv/mm/fault.c
> +++ b/arch/riscv/mm/fault.c
> @@ -14,6 +14,7 @@
>  #include <linux/signal.h>
>  #include <linux/uaccess.h>
>  #include <linux/kprobes.h>
> +#include <linux/kfence.h>
>
>  #include <asm/ptrace.h>
>  #include <asm/tlbflush.h>
> @@ -45,7 +46,15 @@ static inline void no_context(struct pt_regs *regs, unsigned long addr)
>          * Oops. The kernel tried to access some bad page. We'll have to
>          * terminate things with extreme prejudice.
>          */
> -       msg = (addr < PAGE_SIZE) ? "NULL pointer dereference" : "paging request";
> +       if (addr < PAGE_SIZE)
> +               msg = "NULL pointer dereference";
> +       else {
> +               if (kfence_handle_page_fault(addr, regs->cause == EXC_STORE_PAGE_FAULT, regs))
> +                       return;
> +
> +               msg = "paging request";
> +       }
> +
>         die_kernel_fault(msg, addr, regs);
>  }
>
> --
> 2.18.0.huawei.25
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMN2xQ28nsqUzE%2BXJ_muHUT%2BEGdCTCDhvLH2hMMxuTidQ%40mail.gmail.com.
