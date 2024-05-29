Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCNR3OZAMGQEN526K5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 61AF78D2E12
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 09:26:03 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5b51482fc04sf1877968eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 00:26:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716967562; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ftv4VZDovq4j54lZJPcjYr6yXko/dEfYnr0W5JS/HyWDs8HzBxK8SrXAP+0zm7znkY
         Ipj3dgNN74h4swAmZVcVAwEZsJvghNS1H7Epwf7G9vykCnBeaOHQ95CCvLhTdCEvzw0K
         rM+PrNtt/leGPxqpsLDk1va4JAu90EI3ooUwLb6mIjx3W/O0uwypbtRjpLmTuYfkn1TU
         PJgh+K2jhglmeuqHiq4zYf41SOaQpgKA3MhyTXxJe3+oWj6iJiWmjw7AfCu4U+JUiQZk
         cgiX0UXXGRdX0ao7qaSuvNas9Qd5zl3knpPWQzTfgm2EjaKmm/vIckvW0AdQj4itsd5W
         Fnsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KxIV1y318kY3Lk1ZcNvPEc864VGAtAEzijd4dsjo9iQ=;
        fh=iYjUQ68zv/MJ7ZQ1hDvO1ILlgIKNdzaqxbucpWVxjH8=;
        b=wZJBT5UnFkD/Ia07qpBXhdplf1xTwHe8ZJd1ZernsFs28e8iQGlWFb6yrJfziKvGH+
         EidEe67gOtUZ1Cno6YeedED49lXytG1OITqmdKEqt5P0eZOiz0swqoaPK2vZSxaR3ZsV
         08ARu2Qki7Ps7KHAsjA/710FEdQUwIQQNQ5LvT9wisGft7IQly/AR2DmSxFz3E5VQA5W
         G2QclGdDbggjofqmWUKLCW5G30LGneguVSMQ8laZUgj4Kq6aRqLFnMnOUikqTi2h4yJ+
         7Hic00j1RadUBhDyGN3FdiIqZuZIhhlk5EHrcP0G7CNraeWEDU0enuymyVgdWw9RA1Ih
         KUgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eelpq84I;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716967562; x=1717572362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KxIV1y318kY3Lk1ZcNvPEc864VGAtAEzijd4dsjo9iQ=;
        b=xZ+W31xm+l7uryvBZ+Tl/8IFPLsoT6Fkz2B5+3txMFWr572oLrjQEt1HvykNK18bUJ
         vfSKxvg4/nDV2icof70XtnpQ1frMhOavPT0He9tsHOpVILNgicEPn16U38qWzo1ibCbQ
         L+mhTVnzldOMAnn75Q6LAczE4EAHgreQ/PUTVtyPTYqylbHg7wEXrMpRNOpxPSh7Xjku
         uNwU9TMnfJMAg4T17HArLf1atNK5DVWYlbm83P0Rp9ISkcyIsKGWvr0hQO5Iv0Sk2anJ
         i1Yfpjf5LF2UUe6axOcL0uxSWg8DKE4zMUvMCaQxUCu5h/GUVYggZ3MBL5sXdAN2GBSe
         GAAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716967562; x=1717572362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KxIV1y318kY3Lk1ZcNvPEc864VGAtAEzijd4dsjo9iQ=;
        b=tDvHKWufO5RnQkBV87qTnAu3wPPc1GXaGH3X7jqV6Bgm54EW8pqrJAp/TriAP4uBO3
         DwYWGJNk2GD7NkT/+EkHnuctP/K4GMxqOHGEaWoKz82dOEtUhtyb8CWGUKSM1vSWou/S
         a7O0Yeh/vazCfHdWbk2egSMQZHS3s5ofW4pKaclZjM4Bd7ABgpVVH5z3RrZCSRHpxrDB
         9a5iyTwhj+MLE2ERJrCGbf66l8zbsV3dfFsHUFPSycWAb+qE9HyuvOjnw/5d9H02LXI+
         4XQwcjThSIaahn+EDDlHR4oJxKlasvjwSj6C9vzwsRLejT3VKEE1dtMtGNaJ9r+PuAWB
         NlMA==
X-Forwarded-Encrypted: i=2; AJvYcCU/pY03gDjbaFc3hqT7BT3Lrnm7jgDptEJFgk3ybGWxicf/BnN8jmLGbbYOVLRrTMNR9auZqbFQGjBijqB8qvhSqR0Q1pJIOQ==
X-Gm-Message-State: AOJu0YyuPK/YyN83gE6N9Cm1yDi9dZ5/COl9AJwaN7jl/s5LetweQtCI
	iS7cxXDAWO6UhatRc/Ep4im/4Ge98bWq1XAogI4wvirTMe3tzzjc
X-Google-Smtp-Source: AGHT+IG1cJJaWC7jqDUII77iOwNv9rPk4Yekr6TT0LcNCRlvXvYRQ3qrHkVnD4rOt8KYmHfAyRYkcQ==
X-Received: by 2002:a05:6870:15d1:b0:233:5b4d:ff90 with SMTP id 586e51a60fabf-24ca13f66ccmr19467403fac.50.1716967561711;
        Wed, 29 May 2024 00:26:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3311:b0:24f:fada:1780 with SMTP id
 586e51a60fabf-2503ef6b35els484100fac.1.-pod-prod-08-us; Wed, 29 May 2024
 00:26:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWI+ba8tEQpCtJE2XrqkH0GBhlTv2HTCLXeLDUm3aAALlL6u+fe8XrqHl4IKpyRw0X/CmO/QYuxyRknCN2WQx9oNBxkU2jh2CZ3w==
X-Received: by 2002:a05:6870:d6a2:b0:24f:e000:a6f8 with SMTP id 586e51a60fabf-24fe000ac34mr12860548fac.41.1716967560806;
        Wed, 29 May 2024 00:26:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716967560; cv=none;
        d=google.com; s=arc-20160816;
        b=ZgbsbmVK7r43qnens2iXqp2uBReXusLLtS9PaH+7qs/THXAuEPNpg4NXwjosOMZ63i
         mKGzV02D4xXWjQLIpFUJ6IuTb50TjZH8Ckx87OU78zJpiJL+qsOqNBJKNH6H/xP2mYOy
         dfw5BjD2cleLXwJYTNmZ1nEilnA1B4pKd6yFMxl4ZlIcuQ2SxrjOrnaAe6O0KPSa5Rd8
         n1xkfEo75A6Wco1tVBPeNyPBAJW0rbWc2Tvjbzn0Oez/5Vef1PhY8OEE2BgX1+zgGj7V
         k8z1GI5ur3qVK8kJvOqcyYHAghfKpliROEM70vzCDnHKabwJidsZb5bw1ZnIxTeKd7U/
         ckHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nWzvmzN7ijIbCBaVTu7XEGtPfeKO3l3ACHDt/WVaHXI=;
        fh=SZL84bEcMGDkM7dom+fSmeaRANRuqNVap0a3RlCy6ps=;
        b=ne78TFH3IUK0z8G7oqKfuofV6p/v7y53EutHs0tczMRS/BuQSAk56IXMqf7A3YnMFB
         Hgsg6mxCkjH1HVCQflLTpyN1StQaQKL9NnSnba4tpqCIfg3oPzYV/LuQ2qnJo1cS6KDg
         zSaPVuaNl17AhmxUukJFBLx0Ao1Wv94v3y41sUS44B2+tdkd+MsMfZTZw75K4qrjE8xx
         c1sIMr2jHbjEnCrt+FEksjZTI8Z9H7CSnpqJD0uRd4Rl8GvhW3bbykYnKfKd3lBJ4NfA
         MVCaX3QIxNMyNC243L2f40Jafm3UJVBFlXrWzrQEftRo0VcEviUxYdWV0exKaGznVmk3
         d38w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eelpq84I;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe31.google.com (mail-vs1-xe31.google.com. [2607:f8b0:4864:20::e31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-24ca20669f0si528025fac.1.2024.05.29.00.26.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 May 2024 00:26:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) client-ip=2607:f8b0:4864:20::e31;
Received: by mail-vs1-xe31.google.com with SMTP id ada2fe7eead31-48a4e48ec5aso540724137.2
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 00:26:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVgJGHFDsWSyZTrLTEkGn/WUSLIlQ+L1QMPPfdDchZ5dDw9iPwvbTOez2D5ZlW/d2aPyOfuPnVzHbfw/gLu/8opZg/umA6cz9kR6Q==
X-Received: by 2002:a67:f4c7:0:b0:47c:2c84:4321 with SMTP id
 ada2fe7eead31-48a38575d3cmr13715697137.16.1716967560033; Wed, 29 May 2024
 00:26:00 -0700 (PDT)
MIME-Version: 1.0
References: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
In-Reply-To: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2024 09:25:21 +0200
Message-ID: <CANpmjNM2S2whk31nfNGSBO5MFPPUHX7FPuHBJn1nN9zdP63xTw@mail.gmail.com>
Subject: Re: [PATCH] x86/traps: Enable UBSAN traps on x86
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Kees Cook <keescook@chromium.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Baoquan He <bhe@redhat.com>, 
	Rick Edgecombe <rick.p.edgecombe@intel.com>, Changbin Du <changbin.du@huawei.com>, 
	Pengfei Xu <pengfei.xu@intel.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eelpq84I;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as
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

On Wed, 29 May 2024 at 04:20, Gatlin Newhouse <gatlin.newhouse@gmail.com> wrote:
[...]
>         if (regs->flags & X86_EFLAGS_IF)
>                 raw_local_irq_enable();
> -       if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> -           handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> -               regs->ip += LEN_UD2;
> -               handled = true;
> +
> +       if (insn == INSN_UD2) {
> +               if (report_bug(regs->ip, regs) == BUG_TRAP_TYPE_WARN ||
> +               handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN) {
> +                       regs->ip += LEN_UD2;
> +                       handled = true;
> +               }
> +       } else {
> +               if (handle_ubsan_failure(regs, insn) == BUG_TRAP_TYPE_WARN) {

handle_ubsan_failure currently only returns BUG_TRAP_TYPE_NONE?

> +                       if (insn == INSN_REX)
> +                               regs->ip += LEN_REX;
> +                       regs->ip += LEN_UD1;
> +                       handled = true;
> +               }
>         }
>         if (regs->flags & X86_EFLAGS_IF)
>                 raw_local_irq_disable();
> diff --git a/arch/x86/kernel/ubsan.c b/arch/x86/kernel/ubsan.c
> new file mode 100644
> index 000000000000..6cae11f4fe23
> --- /dev/null
> +++ b/arch/x86/kernel/ubsan.c
> @@ -0,0 +1,32 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * Clang Undefined Behavior Sanitizer trap mode support.
> + */
> +#include <linux/bug.h>
> +#include <linux/string.h>
> +#include <linux/printk.h>
> +#include <linux/ubsan.h>
> +#include <asm/ptrace.h>
> +#include <asm/ubsan.h>
> +
> +/*
> + * Checks for the information embedded in the UD1 trap instruction
> + * for the UB Sanitizer in order to pass along debugging output.
> + */
> +enum bug_trap_type handle_ubsan_failure(struct pt_regs *regs, int insn)
> +{
> +       u32 type = 0;
> +
> +       if (insn == INSN_REX) {
> +               type = (*(u16 *)(regs->ip + LEN_REX + LEN_UD1));
> +               if ((type & 0xFF) == 0x40)
> +                       type = (type >> 8) & 0xFF;
> +       } else {
> +               type = (*(u16 *)(regs->ip + LEN_UD1));
> +               if ((type & 0xFF) == 0x40)
> +                       type = (type >> 8) & 0xFF;
> +       }
> +       pr_crit("%s at %pS\n", report_ubsan_failure(regs, type), (void *)regs->ip);
> +
> +       return BUG_TRAP_TYPE_NONE;
> +}

Shouldn't this return BUG_TRAP_TYPE_WARN?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM2S2whk31nfNGSBO5MFPPUHX7FPuHBJn1nN9zdP63xTw%40mail.gmail.com.
