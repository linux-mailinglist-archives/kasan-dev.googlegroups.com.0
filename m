Return-Path: <kasan-dev+bncBDW2JDUY5AORBUUE36GQMGQEUCPNDFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3764E473723
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:59:48 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id z8-20020a6553c8000000b00324e0d208d3sf9667496pgr.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:59:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432787; cv=pass;
        d=google.com; s=arc-20160816;
        b=ifJqp2DcDEnogQTPycw2EvqWihKzxzcKLpLMBnQLS4dfVXOEn8P69bDJ4ncNL8esTI
         hB9gXLNwri9n7ViqiWoQwAIK2C2NvlYXnV5QZ8lwu5cS/rZjN3RvVcX4ywq5pOuDZw58
         3g2w9lPiMzTfaUld9WU2qFcSz4iPdVdZFJdWAzGzmhu2VYQu4wvITco6eB0geAQ/p2ZZ
         xIKV0tk7sGLr79I/EEdeREm4gR56LiVLZdSTCfclctwJrzo4sOnvCOvp/Xj4Rj4dQwpF
         V1B8uz2RdJED5j/gY+ta66fD9tvPrSDrcVZTXEdCEWIvEd40KaQ4ILSxgYNTa3xUQl3S
         EC0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=txlA/y/2zUKa6jFgjK3D5HUNQVH3O51/pxtOZ/RfuiQ=;
        b=uCJ/j3BZYxqIZSYy7NJ4IqEJXJ5IN0wUs9yRz8XFXOyfAQYpyOFB5dK3dePkvSsaDZ
         Sthrgg6Pr39F1qh3rnc1zbQmGArQR5klAPV6qqfhbjPPRWO9BFd3srAPSG5bUMmmXrn0
         jQOG1QsDr1jvRkg+9NhMVVwdVtyDahyY6eGa++Tds70+YmSvYHBwO3X7bxpChqpfAmBK
         kKGr3WaiTSiFNw/WbCnnEdoyNlsgs9y6qOOLuXvqHNbcSPFaYl1oimYySETqpyCvVI08
         wAlZ7I4pDDyqAX9mtHZLNTsATUO3aScuhjTUzJmWxiwhfD/+QREyOZklWINSlXLNEuFm
         Iu8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AFw0EAZV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=txlA/y/2zUKa6jFgjK3D5HUNQVH3O51/pxtOZ/RfuiQ=;
        b=m/KWU1R3gvbnCJYAPdMXwypNiv2cRaaNALv1fgomhCMT+NGF9dkn0TYx3hlbBAfLcV
         xYhAEbfdm9ssR0JnNdwTl7UB55pM4vSGGXpWClQce4Z3Ot5OA1VGV/6D7tJBKcmikTUm
         lYizfrHisIKUdqGWhWcW1UfZyQyQSYn6Zo5kCCJczwgCNYH2ssWfC88POD9rVXnRB1qM
         4GHGiStN2ZIFAS+3eXdmK4zFS2Qg2tYZftZ+lOpBqOLRmS7MacZ5Lxmw/ANyESoWX3dS
         K+6MixGYb3CxygLAzo/dopyBy8L+LIJ5TpP81TsamsNaQej2ZM5GVioXSkGHP8CZAlvB
         0LOg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=txlA/y/2zUKa6jFgjK3D5HUNQVH3O51/pxtOZ/RfuiQ=;
        b=imZN2VohPU9DbgUehceSqbQvmhBSBAjXI8gxzf104pUuX8rwrjmZD30qaPC4Rzq8Qg
         vKmy3eTqSimYyyilAyCqpRhOrgycud3uPP94fsTqYpZk12dP28bek9YevDzdRCNODUUM
         iw3XTwqFm/sLVufc/5+aQVY+0TLOyl8+GQjtjXvwOO76Jw03t6Rm1N6pRKhv1ug3TQ7r
         VZPw5PZDVMz/lh2xPMFyyYzA8a1qtagaBmdoC55br8NJdfDO2V1k1N/x8Olvwb6Vw/9C
         YYv1I7AAcE1oplNJDK0AmdkNiYTTkg6vZo+0VjzjRyhqSobqzvmMhm63vvkJLk805Kk+
         Or9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=txlA/y/2zUKa6jFgjK3D5HUNQVH3O51/pxtOZ/RfuiQ=;
        b=VF9Gor1lLzcGWofHqELeqvqMScm8ByD0l7TkF7dw8bj4UiuazouUbGlaW6U0GG9u2C
         W6asmXi+mbUdMtPtJUd/e8fW2sGIV3QxYeTI8mu43Tv3VLgnptgCer3QQa4Gv+MoA1nb
         /re+FND5waNji88lLlO3i6+9VHPsrjQwhwZHudM+1mCZYoDRFUimMiTRiq/+A/UkFbVn
         ybKuYjXcDprAUrsWn7xPWrd/QkfMxZ8FSkC3wqAPsLdo0vlyTQBUh4gJCTjYrdkqwW/V
         2J7YF+KDUW8latSBuBaH9gf0q+7Io8o0mP/an2z/kDo5fu+wPPSK30KArbd+R2+UNGt/
         JYJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334cULPeQc19yxEYG45dg/kIQR3vJvxpWAXy5NSBUk69Uj5MqiI
	etv9CLT3fhSnAS2+N4Mspr4=
X-Google-Smtp-Source: ABdhPJwUsFR+wIA9FufeJll/VPsfO0kD+N8lIIIGDZ33PnDFJrDNqjG6JMm/SLqB9YZMsUpsBuwx5g==
X-Received: by 2002:a63:e06:: with SMTP id d6mr932269pgl.449.1639432786954;
        Mon, 13 Dec 2021 13:59:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6002:: with SMTP id y2ls71564pji.1.gmail; Mon, 13
 Dec 2021 13:59:46 -0800 (PST)
X-Received: by 2002:a17:902:7890:b0:143:c4f7:59e6 with SMTP id q16-20020a170902789000b00143c4f759e6mr1218761pll.87.1639432786445;
        Mon, 13 Dec 2021 13:59:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432786; cv=none;
        d=google.com; s=arc-20160816;
        b=F7eqsWLYu0NE8iGZaYLw+qAb+tZwO2E5piQ9XxJJnJpHahAeAnWKUyWTTpbhlP0jHP
         vAPI2w89Qmd8L5Nq1mGtaaNLpOCF4dVvzhe6+kKCKku40BGOA6btzLB3wLWPh0LIAXKV
         Q5lmML6XCt298ZNa1nlkzRXj99YBa2YnEalVlKRdEX9gxZMY8zsgJmoXTsHL6A1J3IUa
         fLLyow7KMXPuu525/VoIjOBMT7OFrqyJOlTW5esi8XtDS87uSSuOS1g5AzPk/7Mw1IFv
         MDTvYi8VzhuSBOewg6kHidgPzyJAH00ELzEx8AXzFkhf7ICFl9ctu0v/EvrtDptwOPzY
         HZ2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BNW1RvPQZwm1C5HKSe2mnjCE7ya9sQIsxIsz8L3X9Xo=;
        b=AUwTxZkMlZDAd1Apm57Cr35a6ppt6i5GVA5m87QED1I0F+kUZQ6NxSJ1LzZGcOpuFw
         0JoyTyM19b+kp/Ubirf+CHUTpalMpNXdPH8G6qNdgTqHmBVy9NFzJenIrJWOz6Oawy3b
         3p/KwuKYmAkOrHgazr9S6DRMJCB6YkpNK5ge0S13Z0keEh0TRRBL/rp2dwpew21Q0a/a
         T4zAjqGb97eFx0PzkyNfVhLwE+kTWfxCRhfgl+RW2IF5SXfe0SXBDbFnbCJ/1Kb5gKhC
         MdppytJ/n7wW06rH7bJH7XfLLwqzOjF6znPPRhuUhy5JDhf8Tqze0w8qNn8M50jinnYh
         jWfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AFw0EAZV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id g12si1666840pjp.0.2021.12.13.13.59.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Dec 2021 13:59:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id r2so16224759ilb.10
        for <kasan-dev@googlegroups.com>; Mon, 13 Dec 2021 13:59:46 -0800 (PST)
X-Received: by 2002:a05:6e02:f07:: with SMTP id x7mr921673ilj.28.1639432785937;
 Mon, 13 Dec 2021 13:59:45 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <4a5ec956a2666c1f967c9789534a8ac4d4fe26f9.1639432170.git.andreyknvl@google.com>
In-Reply-To: <4a5ec956a2666c1f967c9789534a8ac4d4fe26f9.1639432170.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 13 Dec 2021 22:59:35 +0100
Message-ID: <CA+fCnZd9n1S59mJewsTnN+u-Ng0prrjYhOw4KJWzVKBLf5FtQA@mail.gmail.com>
Subject: Re: [PATCH mm v3 31/38] kasan, arm64: don't tag executable vmalloc allocations
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=AFw0EAZV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Dec 13, 2021 at 10:55 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Besides asking vmalloc memory to be executable via the prot argument
> of __vmalloc_node_range() (see the previous patch), the kernel can skip
> that bit and instead mark memory as executable via set_memory_x().
>
> Once tag-based KASAN modes start tagging vmalloc allocations, executing
> code from such allocations will lead to the PC register getting a tag,
> which is not tolerated by the kernel.
>
> Generic kernel code typically allocates memory via module_alloc() if
> it intends to mark memory as executable. (On arm64 module_alloc()
> uses __vmalloc_node_range() without setting the executable bit).
>
> Thus, reset pointer tags of pointers returned from module_alloc().
>
> However, on arm64 there's an exception: the eBPF subsystem. Instead of
> using module_alloc(), it uses vmalloc() (via bpf_jit_alloc_exec())
> to allocate its JIT region.
>
> Thus, reset pointer tags of pointers returned from bpf_jit_alloc_exec().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v2->v3:
> - Add this patch.
> ---
>  arch/arm64/kernel/module.c    | 3 ++-
>  arch/arm64/net/bpf_jit_comp.c | 3 ++-
>  2 files changed, 4 insertions(+), 2 deletions(-)
>
> diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
> index d3a1fa818348..f2d4bb14bfab 100644
> --- a/arch/arm64/kernel/module.c
> +++ b/arch/arm64/kernel/module.c
> @@ -63,7 +63,8 @@ void *module_alloc(unsigned long size)
>                 return NULL;
>         }
>
> -       return p;
> +       /* Memory is intended to be executable, reset the pointer tag. */
> +       return kasan_reset_tag(p);
>  }
>
>  enum aarch64_reloc_op {
> diff --git a/arch/arm64/net/bpf_jit_comp.c b/arch/arm64/net/bpf_jit_comp.c
> index 07aad85848fa..381a67922c2d 100644
> --- a/arch/arm64/net/bpf_jit_comp.c
> +++ b/arch/arm64/net/bpf_jit_comp.c
> @@ -1147,7 +1147,8 @@ u64 bpf_jit_alloc_exec_limit(void)
>
>  void *bpf_jit_alloc_exec(unsigned long size)
>  {
> -       return vmalloc(size);
> +       /* Memory is intended to be executable, reset the pointer tag. */
> +       return kasan_reset_tag(vmalloc(size));
>  }
>
>  void bpf_jit_free_exec(void *addr)
> --
> 2.25.1
>

Catalin, Vincenzo,

This is a new patch added in v3. Could you PTAL? Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd9n1S59mJewsTnN%2Bu-Ng0prrjYhOw4KJWzVKBLf5FtQA%40mail.gmail.com.
