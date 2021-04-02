Return-Path: <kasan-dev+bncBDFJHU6GRMBBBCNSTKBQMGQEGIHGIQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 293A73525F5
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 06:09:46 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id v16sf2948139lfg.10
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Apr 2021 21:09:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617336585; cv=pass;
        d=google.com; s=arc-20160816;
        b=a7N7/IePkWSCeuJGn0DGBeWh8Rf8c2cteHfZJzioeMnZR5xf/T/RlRDl8aiI83v1XK
         zFVUj6LlImq+ZNA1m6a0AuJJciWJebsxd3gTQpiCA2/8r4aDf9xeYy6ZoTuOL5JOpyIW
         4JbH+yk1lqlSHY+3E87UlGzmzSOf7N7GCjK5NnySNyMhgSX8CjHySNEHqgGZ+DNijVw3
         qrNFtYAZxcXd5EUT+5VN8F0KLuuTALwCE7rR7XYffCf3KT5Y/VKDxwkfK+xpGOrBZsLP
         9KCMtcMhm8uQMx6ztG8BUuu75qDPd96tI3VAS3RQF9Z3JP5CeGYe4RVEBMVIJh7Bi7Tz
         THkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=liMLg1AoVjxFTgXX1YkadK18WL6rtZMitvAhKB/E0iM=;
        b=Zhg8KnfWK9MSaN8y0TvZUC7+nD/pJJOHklqUN4mZ32wHEsT7vGBwP4YxqDebGcaNUR
         6aRPfZBG8+giNOM0yJpWGEd/a95lnMbK+3dE0sAfEdh8gYArg5eN375vArQg+iVhqGEB
         2vy4aGeZy5ccyoxSf7+8QWrCpgI7lbaP5h6uKv7umVWPkVRGkelLm9/Qfuhzvhv7mDUs
         sFg4zawJdWWcXG1mdALPafsFrTF2ktPO3DLMKilCMNfsnH+BzTZz7hbpJE02RfDlOpOW
         WbsuowTSB+FrP+EaBuuCG6PV/sXUTd8httHzcg1+m1A4kcrgimtdm3+nnWzITOM9v621
         y24w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=JbBObYJH;
       spf=neutral (google.com: 2a00:1450:4864:20::42c is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=liMLg1AoVjxFTgXX1YkadK18WL6rtZMitvAhKB/E0iM=;
        b=bQFSsQhXt+FGl023Da+WzXUqtrU1KUprC0/VOiv2TYp2/sp8DuEEaQIEK0zkArv5iv
         f8X5t0WTrOdS/5IPOWw7NQbYc6raSrql8L8KuZ7UxRes4rjomU7CKn8Sze9e5kf+7saQ
         /Ap7QZBoqirhtEqx5WLKo5Jd6abZYYGX1W3HL1Q96mwX0r+3jYVzKHyWTB/CMMmVGJbL
         puzRbm5K7CS2GnJa8JQy/OJYI8ar8J9/6QEbaciMD0Qrqx8Tze0DKSmC0dWafGmFYiQZ
         0k7+UkXdvBO1wRl+778/xTnTOdkCPCq/GyAkFW48gAX+5c81ww6muULJXpDdHy++pjig
         ff+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=liMLg1AoVjxFTgXX1YkadK18WL6rtZMitvAhKB/E0iM=;
        b=tUAQIPZRIymCqLkUQXlaCTHZ1qb27a/xhxbUHOAZ2JzbSo39kYOOl4zYHTc+sI9wA7
         Z20d36a/4s89HnfN860vRThO4l/uCIquSdHnR0Yw58EsYuI9ICzeecmQllo74TX7AGgH
         VTTcrblUBXk+j1RO4HcWZWYg9/Pw6OX123xcgq0/fZYjcHv5a05t+L+6xr88zxQ/2GSh
         buYSaNNdimHx6qKhRziCEosXlalVNV6/Ot+T7iEvcMikbW27R/4xHXRJMMB41LEuIA0p
         KMswQzdCe41+IqOACEJHUsDCOai+OSdJDegbDCqU0RLndezH4EJivdY017Int0+eNGYB
         7JDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OIxUv7QTiT5ONp5MONklKsgGXbM/VGrIcgehWEWNzvisvbVGa
	SRqmSN5jkf5D+g4k4ELigTQ=
X-Google-Smtp-Source: ABdhPJyfDrhhABwk0Qlec+1bv6hneW04SkTJg+sWp0tK74jc006lldZybgBE4cCoALOhSRVCxgv4/w==
X-Received: by 2002:a2e:8087:: with SMTP id i7mr7456920ljg.178.1617336585631;
        Thu, 01 Apr 2021 21:09:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls90373lff.3.gmail; Thu, 01
 Apr 2021 21:09:44 -0700 (PDT)
X-Received: by 2002:ac2:5932:: with SMTP id v18mr7696106lfi.659.1617336584419;
        Thu, 01 Apr 2021 21:09:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617336584; cv=none;
        d=google.com; s=arc-20160816;
        b=O5idtumi36qxIUCEksnSDlBZQIhIHgCEN7UvslHY8ljWfBZ1YLHyBxVf9J2i/hXAxi
         u6pP0ALCtQ6dP9fsFmS42gH+M9qXnFKSJXoMrNNcbY/f9HlQaQypOznDzQmqSXnAP4cn
         ICV/S24rl1LpkjZIYKGqnR6/g3dF5uq3PRIFnGmFR5HFTDPCPjQoNp/8ArrIM+s7Qp+8
         y/sALKeEquBSwG4HTPs+35GbYlz3z7Z+NtvlADZo6l/Evkgo+2d+Y1yv7KV7mWCx3HLL
         BvfqxeldCTqz8MS8rr05vo4aQD5F9DVjRqIuVWUuPAqksHh0tMGjHHmWmRyPdNl1QE8p
         UMcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=meCY3g4ZddcaVFsiixJeKxINO9meMOC/HmZiu7pSnis=;
        b=eRaV7gM7woWuzzdqGXMFNhgI8IZszNu2wQd63UsdPQLSM/YG06czCzg2hfeRneTLYU
         /FAlPRwdGUhauePjG7/YjISDWDHkoF0DcPRHs0RZdnq0w73pPwdTA7x+rIG/J5QBOaV5
         SPd4MVwezXc/6ORqRkkAsL7jgtV66l/3L6RFFga4zEyRS3Mc/iZyjgKg4xdsftujOJFT
         p+m9KKzMur8rKSvU07AQ3sgr5etOKSt7Nl91NGgc5JMBP53Ey2b+xH0Ea+/x/ufU4eB9
         JBBJPZTrrMTbsBi5nWpabmoWqig92EbXtRDDxbh9gjf3EreF3UtqwML8iXKhoxOBcYoQ
         G5RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=JbBObYJH;
       spf=neutral (google.com: 2a00:1450:4864:20::42c is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id n13si596855lfi.5.2021.04.01.21.09.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Apr 2021 21:09:44 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::42c is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id j9so3650587wrx.12
        for <kasan-dev@googlegroups.com>; Thu, 01 Apr 2021 21:09:44 -0700 (PDT)
X-Received: by 2002:adf:9544:: with SMTP id 62mr12946985wrs.128.1617336583795;
 Thu, 01 Apr 2021 21:09:43 -0700 (PDT)
MIME-Version: 1.0
References: <20210401002442.2fe56b88@xhacker> <20210401002551.0ddbacf9@xhacker>
In-Reply-To: <20210401002551.0ddbacf9@xhacker>
From: Anup Patel <anup@brainfault.org>
Date: Fri, 2 Apr 2021 09:39:32 +0530
Message-ID: <CAAhSdy0N427hw6sK5NEbrs_bb2N9y6aDOrCLO+mcpysLvaaoPQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/9] riscv: Mark some global variables __ro_after_init
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, 
	Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	Andrii Nakryiko <andrii@kernel.org>, Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, 
	John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, 
	Luke Nelson <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	netdev@vger.kernel.org, bpf@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623
 header.b=JbBObYJH;       spf=neutral (google.com: 2a00:1450:4864:20::42c is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Wed, Mar 31, 2021 at 10:01 PM Jisheng Zhang
<jszhang3@mail.ustc.edu.cn> wrote:
>
> From: Jisheng Zhang <jszhang@kernel.org>
>
> All of these are never modified after init, so they can be
> __ro_after_init.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/kernel/sbi.c  | 8 ++++----
>  arch/riscv/kernel/smp.c  | 4 ++--
>  arch/riscv/kernel/time.c | 2 +-
>  arch/riscv/kernel/vdso.c | 4 ++--
>  arch/riscv/mm/init.c     | 6 +++---
>  5 files changed, 12 insertions(+), 12 deletions(-)
>
> diff --git a/arch/riscv/kernel/sbi.c b/arch/riscv/kernel/sbi.c
> index d3bf756321a5..cbd94a72eaa7 100644
> --- a/arch/riscv/kernel/sbi.c
> +++ b/arch/riscv/kernel/sbi.c
> @@ -11,14 +11,14 @@
>  #include <asm/smp.h>
>
>  /* default SBI version is 0.1 */
> -unsigned long sbi_spec_version = SBI_SPEC_VERSION_DEFAULT;
> +unsigned long sbi_spec_version __ro_after_init = SBI_SPEC_VERSION_DEFAULT;
>  EXPORT_SYMBOL(sbi_spec_version);
>
> -static void (*__sbi_set_timer)(uint64_t stime);
> -static int (*__sbi_send_ipi)(const unsigned long *hart_mask);
> +static void (*__sbi_set_timer)(uint64_t stime) __ro_after_init;
> +static int (*__sbi_send_ipi)(const unsigned long *hart_mask) __ro_after_init;
>  static int (*__sbi_rfence)(int fid, const unsigned long *hart_mask,
>                            unsigned long start, unsigned long size,
> -                          unsigned long arg4, unsigned long arg5);
> +                          unsigned long arg4, unsigned long arg5) __ro_after_init;
>
>  struct sbiret sbi_ecall(int ext, int fid, unsigned long arg0,
>                         unsigned long arg1, unsigned long arg2,
> diff --git a/arch/riscv/kernel/smp.c b/arch/riscv/kernel/smp.c
> index ea028d9e0d24..504284d49135 100644
> --- a/arch/riscv/kernel/smp.c
> +++ b/arch/riscv/kernel/smp.c
> @@ -30,7 +30,7 @@ enum ipi_message_type {
>         IPI_MAX
>  };
>
> -unsigned long __cpuid_to_hartid_map[NR_CPUS] = {
> +unsigned long __cpuid_to_hartid_map[NR_CPUS] __ro_after_init = {
>         [0 ... NR_CPUS-1] = INVALID_HARTID
>  };
>
> @@ -85,7 +85,7 @@ static void ipi_stop(void)
>                 wait_for_interrupt();
>  }
>
> -static struct riscv_ipi_ops *ipi_ops;
> +static struct riscv_ipi_ops *ipi_ops __ro_after_init;
>
>  void riscv_set_ipi_ops(struct riscv_ipi_ops *ops)
>  {
> diff --git a/arch/riscv/kernel/time.c b/arch/riscv/kernel/time.c
> index 1b432264f7ef..8217b0f67c6c 100644
> --- a/arch/riscv/kernel/time.c
> +++ b/arch/riscv/kernel/time.c
> @@ -11,7 +11,7 @@
>  #include <asm/processor.h>
>  #include <asm/timex.h>
>
> -unsigned long riscv_timebase;
> +unsigned long riscv_timebase __ro_after_init;
>  EXPORT_SYMBOL_GPL(riscv_timebase);
>
>  void __init time_init(void)
> diff --git a/arch/riscv/kernel/vdso.c b/arch/riscv/kernel/vdso.c
> index 3f1d35e7c98a..25a3b8849599 100644
> --- a/arch/riscv/kernel/vdso.c
> +++ b/arch/riscv/kernel/vdso.c
> @@ -20,8 +20,8 @@
>
>  extern char vdso_start[], vdso_end[];
>
> -static unsigned int vdso_pages;
> -static struct page **vdso_pagelist;
> +static unsigned int vdso_pages __ro_after_init;
> +static struct page **vdso_pagelist __ro_after_init;
>
>  /*
>   * The vDSO data page.
> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index 76bf2de8aa59..719ec72ef069 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -149,11 +149,11 @@ void __init setup_bootmem(void)
>  }
>
>  #ifdef CONFIG_MMU
> -static struct pt_alloc_ops pt_ops;
> +static struct pt_alloc_ops pt_ops __ro_after_init;
>
> -unsigned long va_pa_offset;
> +unsigned long va_pa_offset __ro_after_init;
>  EXPORT_SYMBOL(va_pa_offset);
> -unsigned long pfn_base;
> +unsigned long pfn_base __ro_after_init;
>  EXPORT_SYMBOL(pfn_base);
>
>  pgd_t swapper_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
> --
> 2.31.0
>
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy0N427hw6sK5NEbrs_bb2N9y6aDOrCLO%2BmcpysLvaaoPQ%40mail.gmail.com.
