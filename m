Return-Path: <kasan-dev+bncBD5L3BOATYFRBU5E7W2QMGQEEPPJGII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BEE6954AEA
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2024 15:21:25 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2ef23969070sf20172561fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2024 06:21:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723814484; cv=pass;
        d=google.com; s=arc-20160816;
        b=BjOaThdNsawIV1Yq3rjKbmsoS2OXCg1UH8Pd2sY+ek+TjnM/Wr6e9xwuZl3HtPiY3C
         AloKvFFTg1Xz3OWj8rUJ9lbbTeJ/MmUPhaDRMaPUweUhUinPxXKm4VGV6uoLjb5b2CUV
         PsTTTljHe9PB1vvggWLcxPzzbLs+bBzqNDpw39rdoiWUPWl22wuwtVNnoUtbaGEzrgl9
         h+ZAGIqD1jiCMrcDhtdgtZsuFooemg0VuDsFoJ8RCOoq+yw9+NUYAaZxIsLDqR7qAPqR
         XSA7zT12gvCpApx8JjBeuW9MP+e+Ki6YsyGtJyuaXChIgbY55B2f2njfwhUobWs+D2qK
         D42A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=nibK3DIxzpwwtKDVe7Dlx3OrEFOq36tSL5F4Xgf5dLo=;
        fh=lfSuKNBEAZi1H2Xr0nNuGVt5/4Vfg8Tryct79Os5gVw=;
        b=ljxHToIplVw/hlXYvvg3rCIQ+PWQoJZD7hEwTDEh09Oa7KSJaQnu6sU+pHVKhDHmxv
         ct0W7r9hfbtDO31DUNx3wi1/hAIKNO00If5s4y/uN12pRo6Px7pkzhUAmBRoQKbbOIsR
         b4WUy4K7UROJOP24Z3q8zSWxO3q3X/7jov7txqEAbdWozcIAibmYd6uh89wi5s7qfHV2
         K+B6+4WmMpa1G8RE/fJLW4FngAjNJH2nFIsOSYqzgFbZbpmLaQjAGpCW4gTFrD8vDvw6
         Y4yn8AHnNJJ/nZFNnr1p3icBOnmTlZRtH1Is5YW36wMYYsa8xjx6C/PxXTT8kpkNgAlH
         sI5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=GHdhyi35;
       spf=pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=apatel@ventanamicro.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723814484; x=1724419284; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nibK3DIxzpwwtKDVe7Dlx3OrEFOq36tSL5F4Xgf5dLo=;
        b=X4HF0VxVfqjc6LaVA1NK+/23hhCyVJ4rtLV23DhgtXHI4L2TtbC1fCfLo0YLnp0AXu
         7xCIpcfAadk93GKnftufVP2OcVR/hZI8MyNquJODDSTNM2LmfjZL5C4OT0NqaSyjZ5iQ
         QXlYfpLFfJTy1j/PqXyKZW3YKI5Q8yAp6B0T7+StHC6eKh7mtu8r98jxRosfBDH9g3vP
         LS5rI5QTvBQtCg5qJEQCENXLYbCIXoSRT+OmGVlT6v/jORngqTJP+d5p45q9yTaZYWMo
         Ta63a34rJTtvFjXA0HoQYyYQ1d9ZkSiqigcWQlkDmhjo8gF/rNzwSiDSzkMXAGDZvMz0
         D7EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723814484; x=1724419284;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nibK3DIxzpwwtKDVe7Dlx3OrEFOq36tSL5F4Xgf5dLo=;
        b=FLr6h8a2miOE/39/kN6uWMUPYdqw4yl+3n51LzxYmEXmhe3Hw1HWS1i/gvQuiCA5LU
         lyf7y0n3Ajvv6slHrT03c2J0W6K/2zpw+XRNuE7HlZoRnOXm2OhYQ5luWAIDY9fLkOc3
         MbCPlkKinq+poKpwSrMUtSyv4w77bPfQAoQ4FL+31uKZ0EVuUCOVQDVY62qdAaD62XzT
         ucQ8iiVOieGsksNsMbD9ml216BvX/5NgIa2NLrARFL69UnmHAY38LKnccuMYf67ya0d5
         Q63bMl6JdHYesgxWACjAX6gN8zLz+JwCDNB/XdR69uCg87t5zr4fUWRw6/kNW+vMFrP2
         cCpw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnrn5/bcgXPR5pUnQIdkwB3vHHILWqjBejdi6WImM5ZHGqEapyHHZ3bTxTJXB0Mw88/iMsMq6hoygBtmlUFQGu0tMl0rAGmQ==
X-Gm-Message-State: AOJu0YyalDKVQW67sbSSUExiYDdI6Z6J3uyPcnKk9rls251SByERWjYJ
	ljnxKnPLJsDRpH8aP7D5ZUEQwJ0bQHESKIq7/raErzqdEu2okDQJ
X-Google-Smtp-Source: AGHT+IG9+YNPfYqXpHIVkmcnR5llgP8haQloevHaeNMCMrdhXm1S4n1u/ebuvM7Vm2kItdmItwhwgw==
X-Received: by 2002:a05:651c:2229:b0:2ef:2ba5:d214 with SMTP id 38308e7fff4ca-2f3be572df4mr34906531fa.4.1723814483748;
        Fri, 16 Aug 2024 06:21:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:22c2:0:b0:2f1:5dd9:1b09 with SMTP id 38308e7fff4ca-2f3b3798f5els1179111fa.1.-pod-prod-05-eu;
 Fri, 16 Aug 2024 06:21:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7oJmVSd2JTGHr3u4P+++OgJxO/grVcdJmBGV1q5K8rVXUhdHOdDW83L3ox0XemUo3dnNajKTuqLw4piLpmmhrHbxOenNNKDGzlw==
X-Received: by 2002:a2e:b8c3:0:b0:2f3:a896:1869 with SMTP id 38308e7fff4ca-2f3be5da127mr28141481fa.34.1723814481565;
        Fri, 16 Aug 2024 06:21:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723814481; cv=none;
        d=google.com; s=arc-20160816;
        b=LwhTTdtfLmy1wuJb+eQ6LoKXEok3VYzcslwqcfl7s/f9ZD6lV4+b2qwPLkkWHlX5SX
         6/CAwwa8n5Ox+hbhlRmQ2ClXCwJUNqNB4IZRzWu+kPCTpnVt5QF2pebcZSN/fM6LBSIb
         3pBH9kPgsuBZgcxkfno4XMRtTHiBQM3gFG+THRGyLNqou3Jn7wxVtAjgo/5rKD4wf325
         qlm1RiBGOIs3GZlhCh1qyEZEZL40uFDVuP6H7Z9b6KE7QGDg5+/B5RJLdPY8M2/Sli5p
         rnLrZkpxE3niHzhJx7Uqs/3J8DSwJDBMXJNurPpqu5Qn9Kzf07Lk6lIZPQE5tmE4YiYF
         TI7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9tzbkpHa0cq4jRrURvNzDIHWfx9oBrvzJsu/1tWEVT4=;
        fh=9go9fKVqTmatqjn0rPfjgA+xmk6joN6zcnGyx1j551w=;
        b=YtTqYS/m8rGMo5R6YfTKy4+jzHoD5G2iQ/+3zVmPB+ZxrB0qoejpQx2nxIfBbl0QTE
         39VdV6KjQZXE+aNpzEZxbtIaJWp5PxaUE3BJxB1ksCD6EOaH8ccKKy/tnKvx6AEM5iQ0
         DYJeHUvEuVN7+KSeivn3UPNdUazvu2wxEjsoB5EwANiGnaDSsNCEudH0ZRxe8Md+bXEL
         yuUwLwR5NO/uZJqqJI09nujOrh+qN7OUyAnElmSh71Hvlw/OsOEAxSUMBQSJJVa9X398
         roAclizR/F8Tr8aZYhaYBJ9K3GfrhSp/+F/ELolIv6kfb3I3lBOp8ZlQ86/yhXXuwopC
         XeQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=GHdhyi35;
       spf=pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=apatel@ventanamicro.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f3b7749808si801901fa.5.2024.08.16.06.21.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Aug 2024 06:21:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id 2adb3069b0e04-52efdf02d13so3181521e87.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2024 06:21:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZRhhDhiV7j1RrAJPzaNxXs/qyRjK65egVWaqf7GCsdsKxz0pl9jaYM0KB3/JMJ9hS1NZZmBZO33ubxJPwpZuV2R3emSNFuzFvwA==
X-Received: by 2002:a05:6512:2346:b0:530:ad8d:dcdb with SMTP id
 2adb3069b0e04-5331c6a1931mr2612100e87.19.1723814480446; Fri, 16 Aug 2024
 06:21:20 -0700 (PDT)
MIME-Version: 1.0
References: <20240814081437.956855-1-samuel.holland@sifive.com> <20240814081437.956855-5-samuel.holland@sifive.com>
In-Reply-To: <20240814081437.956855-5-samuel.holland@sifive.com>
From: Anup Patel <apatel@ventanamicro.com>
Date: Fri, 16 Aug 2024 18:51:08 +0530
Message-ID: <CAK9=C2XOktu5kPXEWKMY4Wsf0D9kwh3rZNXricWqLQaiaqWnnQ@mail.gmail.com>
Subject: Re: [PATCH v3 04/10] riscv: Add support for userspace pointer masking
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>, 
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: apatel@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b=GHdhyi35;       spf=pass
 (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::12c
 as permitted sender) smtp.mailfrom=apatel@ventanamicro.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 14, 2024 at 1:45=E2=80=AFPM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> RISC-V supports pointer masking with a variable number of tag bits
> (which is called "PMLEN" in the specification) and which is configured
> at the next higher privilege level.
>
> Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
> so userspace can request a lower bound on the number of tag bits and
> determine the actual number of tag bits. As with arm64's
> PR_TAGGED_ADDR_ENABLE, the pointer masking configuration is
> thread-scoped, inherited on clone() and fork() and cleared on execve().
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> Changes in v3:
>  - Rename CONFIG_RISCV_ISA_POINTER_MASKING to CONFIG_RISCV_ISA_SUPM,
>    since it only controls the userspace part of pointer masking
>  - Use IS_ENABLED instead of #ifdef when possible
>  - Use an enum for the supported PMLEN values
>  - Simplify the logic in set_tagged_addr_ctrl()
>
> Changes in v2:
>  - Rebase on riscv/linux.git for-next
>  - Add and use the envcfg_update_bits() helper function
>  - Inline flush_tagged_addr_state()
>
>  arch/riscv/Kconfig                 | 11 ++++
>  arch/riscv/include/asm/processor.h |  8 +++
>  arch/riscv/include/asm/switch_to.h | 11 ++++
>  arch/riscv/kernel/process.c        | 90 ++++++++++++++++++++++++++++++
>  include/uapi/linux/prctl.h         |  3 +
>  5 files changed, 123 insertions(+)
>
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 0f3cd7c3a436..817437157138 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -512,6 +512,17 @@ config RISCV_ISA_C
>
>           If you don't know what to do here, say Y.
>
> +config RISCV_ISA_SUPM
> +       bool "Supm extension for userspace pointer masking"
> +       depends on 64BIT
> +       default y
> +       help
> +         Add support for pointer masking in userspace (Supm) when the
> +         underlying hardware extension (Smnpm or Ssnpm) is detected at b=
oot.
> +
> +         If this option is disabled, userspace will be unable to use
> +         the prctl(PR_{SET,GET}_TAGGED_ADDR_CTRL) API.
> +
>  config RISCV_ISA_SVNAPOT
>         bool "Svnapot extension support for supervisor mode NAPOT pages"
>         depends on 64BIT && MMU
> diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/=
processor.h
> index 586e4ab701c4..5c4d4fb97314 100644
> --- a/arch/riscv/include/asm/processor.h
> +++ b/arch/riscv/include/asm/processor.h
> @@ -200,6 +200,14 @@ extern int set_unalign_ctl(struct task_struct *tsk, =
unsigned int val);
>  #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2) riscv_set_icache_flush_ct=
x(arg1, arg2)
>  extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsigned long p=
er_thread);
>
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +/* PR_{SET,GET}_TAGGED_ADDR_CTRL prctl */
> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg);
> +long get_tagged_addr_ctrl(struct task_struct *task);
> +#define SET_TAGGED_ADDR_CTRL(arg)      set_tagged_addr_ctrl(current, arg=
)
> +#define GET_TAGGED_ADDR_CTRL()         get_tagged_addr_ctrl(current)
> +#endif
> +
>  #endif /* __ASSEMBLY__ */
>
>  #endif /* _ASM_RISCV_PROCESSOR_H */
> diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm/=
switch_to.h
> index 9685cd85e57c..94e33216b2d9 100644
> --- a/arch/riscv/include/asm/switch_to.h
> +++ b/arch/riscv/include/asm/switch_to.h
> @@ -70,6 +70,17 @@ static __always_inline bool has_fpu(void) { return fal=
se; }
>  #define __switch_to_fpu(__prev, __next) do { } while (0)
>  #endif
>
> +static inline void envcfg_update_bits(struct task_struct *task,
> +                                     unsigned long mask, unsigned long v=
al)
> +{
> +       unsigned long envcfg;
> +
> +       envcfg =3D (task->thread.envcfg & ~mask) | val;
> +       task->thread.envcfg =3D envcfg;
> +       if (task =3D=3D current)
> +               csr_write(CSR_ENVCFG, envcfg);
> +}
> +
>  static inline void __switch_to_envcfg(struct task_struct *next)
>  {
>         asm volatile (ALTERNATIVE("nop", "csrw " __stringify(CSR_ENVCFG) =
", %0",
> diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
> index e4bc61c4e58a..1280a7c4a412 100644
> --- a/arch/riscv/kernel/process.c
> +++ b/arch/riscv/kernel/process.c
> @@ -7,6 +7,7 @@
>   * Copyright (C) 2017 SiFive
>   */
>
> +#include <linux/bitfield.h>
>  #include <linux/cpu.h>
>  #include <linux/kernel.h>
>  #include <linux/sched.h>
> @@ -171,6 +172,9 @@ void flush_thread(void)
>         memset(&current->thread.vstate, 0, sizeof(struct __riscv_v_ext_st=
ate));
>         clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
>  #endif
> +       if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) &&
> +           riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> +               envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_=
0);

Seeing a compile warning with this patch on RV32.

linux/arch/riscv/kernel/process.c: In function 'flush_thread':
linux/arch/riscv/include/asm/csr.h:202:41: warning: conversion from
'long long unsigned int' to 'long unsigned int' changes value from
'12884901888' to '0' [-Woverflow]
  202 | #define ENVCFG_PMM                      (_AC(0x3, ULL) << 32)
      |                                         ^~~~~~~~~~~~~~~~~~~~~
linux/arch/riscv/kernel/process.c:179:45: note: in expansion of macro
'ENVCFG_PMM'
  179 |                 envcfg_update_bits(current, ENVCFG_PMM,
ENVCFG_PMM_PMLEN_0);
      |                                             ^~~~~~~~~~

Regards,
Anup

>  }
>
>  void arch_release_task_struct(struct task_struct *tsk)
> @@ -233,3 +237,89 @@ void __init arch_task_cache_init(void)
>  {
>         riscv_v_setup_ctx_cache();
>  }
> +
> +#ifdef CONFIG_RISCV_ISA_SUPM
> +enum {
> +       PMLEN_0 =3D 0,
> +       PMLEN_7 =3D 7,
> +       PMLEN_16 =3D 16,
> +};
> +
> +static bool have_user_pmlen_7;
> +static bool have_user_pmlen_16;
> +
> +long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
> +{
> +       unsigned long valid_mask =3D PR_PMLEN_MASK;
> +       struct thread_info *ti =3D task_thread_info(task);
> +       unsigned long pmm;
> +       u8 pmlen;
> +
> +       if (is_compat_thread(ti))
> +               return -EINVAL;
> +
> +       if (arg & ~valid_mask)
> +               return -EINVAL;
> +
> +       /*
> +        * Prefer the smallest PMLEN that satisfies the user's request,
> +        * in case choosing a larger PMLEN has a performance impact.
> +        */
> +       pmlen =3D FIELD_GET(PR_PMLEN_MASK, arg);
> +       if (pmlen =3D=3D PMLEN_0)
> +               pmm =3D ENVCFG_PMM_PMLEN_0;
> +       else if (pmlen <=3D PMLEN_7 && have_user_pmlen_7)
> +               pmm =3D ENVCFG_PMM_PMLEN_7;
> +       else if (pmlen <=3D PMLEN_16 && have_user_pmlen_16)
> +               pmm =3D ENVCFG_PMM_PMLEN_16;
> +       else
> +               return -EINVAL;
> +
> +       envcfg_update_bits(task, ENVCFG_PMM, pmm);
> +
> +       return 0;
> +}
> +
> +long get_tagged_addr_ctrl(struct task_struct *task)
> +{
> +       struct thread_info *ti =3D task_thread_info(task);
> +       long ret =3D 0;
> +
> +       if (is_compat_thread(ti))
> +               return -EINVAL;
> +
> +       switch (task->thread.envcfg & ENVCFG_PMM) {
> +       case ENVCFG_PMM_PMLEN_7:
> +               ret =3D FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
> +               break;
> +       case ENVCFG_PMM_PMLEN_16:
> +               ret =3D FIELD_PREP(PR_PMLEN_MASK, PMLEN_16);
> +               break;
> +       }
> +
> +       return ret;
> +}
> +
> +static bool try_to_set_pmm(unsigned long value)
> +{
> +       csr_set(CSR_ENVCFG, value);
> +       return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENVCFG_PMM) =3D=
=3D value;
> +}
> +
> +static int __init tagged_addr_init(void)
> +{
> +       if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
> +               return 0;
> +
> +       /*
> +        * envcfg.PMM is a WARL field. Detect which values are supported.
> +        * Assume the supported PMLEN values are the same on all harts.
> +        */
> +       csr_clear(CSR_ENVCFG, ENVCFG_PMM);
> +       have_user_pmlen_7 =3D try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
> +       have_user_pmlen_16 =3D try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
> +
> +       return 0;
> +}
> +core_initcall(tagged_addr_init);
> +#endif /* CONFIG_RISCV_ISA_SUPM */
> diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
> index 35791791a879..6e84c827869b 100644
> --- a/include/uapi/linux/prctl.h
> +++ b/include/uapi/linux/prctl.h
> @@ -244,6 +244,9 @@ struct prctl_mm_map {
>  # define PR_MTE_TAG_MASK               (0xffffUL << PR_MTE_TAG_SHIFT)
>  /* Unused; kept only for source compatibility */
>  # define PR_MTE_TCF_SHIFT              1
> +/* RISC-V pointer masking tag length */
> +# define PR_PMLEN_SHIFT                        24
> +# define PR_PMLEN_MASK                 (0x7fUL << PR_PMLEN_SHIFT)
>
>  /* Control reclaim behavior when allocating memory */
>  #define PR_SET_IO_FLUSHER              57
> --
> 2.45.1
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAK9%3DC2XOktu5kPXEWKMY4Wsf0D9kwh3rZNXricWqLQaiaqWnnQ%40mail.gmai=
l.com.
