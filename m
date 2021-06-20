Return-Path: <kasan-dev+bncBDW2JDUY5AORBJOUXSDAMGQEPKDHFTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E17193ADE2C
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:44:37 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id bn8-20020a05651c1788b02901274fe2c687sf7830491ljb.1
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:44:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624189477; cv=pass;
        d=google.com; s=arc-20160816;
        b=TOOVl5hJxIJP1B6BV9qRuT+ZjkWjrbl5u7RLHHcAKbOi0qqus31UnOzP1jJjuE6TkI
         sFKtUCqG/Qz+LnHSdtyRhbf4PLZPVb5Ie6+gSN3qvCf3xu4M1Gr5J8wAIDQDF9E0Ka+l
         Ef1As1crpxxNvL8sWjCvU2hyCwDZlIeqcjsJrrqyVAMYUGbM8Tj6YULrJm+BFir/FVk6
         6oR/OYFnU3/LTWB5PevGsLr1Q+XJfS6Q3ZWL0+f3lbra6s4+vF7RwDGS9/FTof3eDMRh
         Ae05cll6WwZe8TI5MBS2PjwNOZ4RrRC+K/7CbY2K1e2KK2CHH0++Ehm3JngHY5zvUp8a
         UwyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=TJBnwHvIyY65FkFLkU9lG5g2d3S7AnvQXfbc/TElRKc=;
        b=TQuEyrHQ5hCDKeSRmJZru6x0rW3AUCbBBPcbNBNqjNGtPQzu0hnJzAHnqOHeOCCSmN
         ujgfGFBpoQ10clFIGrerddI2pSEGUlXl0wgU3cbxlDJvoFpSYRqyXFezECWOTozgA+nw
         WgkxjbwU3X2TMxgzxqeuBVlJnZPL+yWvZLRpwVKaAtQe42Pp8rPoUW8ZGzCMgtULe0JN
         TLFNE6LeMdN660gfW0WMbYGz2sECsbiqwyXg6ZbwR/vSXOn/hMs2NmCmtGw1NwlJebNG
         L+snEvXPmcGIaYcYfbRTLet2Lqr05hLCaiRelUFfEXVjYFKlIg/j1FFwnrR19suU1Rwk
         Adeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=V8xhXvAD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TJBnwHvIyY65FkFLkU9lG5g2d3S7AnvQXfbc/TElRKc=;
        b=fLhEsEXjpywFImHOZqfiGax4hvdEouq0deSXNIPfzqYDE7Y0UDmGSS+WvHS8Mcc3y6
         40XmYuT1k5pP9WUo0vJV5JKac9+taC2elKP1H/BjpguMli+zwHdIqPFhLNOsoTDzThRt
         LyVT9lUi9/BM4eZ5nCsyervqt2GAdhsAWKMrqV97WdwsxH8GpmrQzJ5dq2URqbFKqISt
         7gwmpT8k9h8QmNDb3extI61NHtCltnCS4pCC/Gbg26NSKsBj5/abqgivtPGG3Iqty9sN
         4qulnqStP02XPe7FFk4a4+u67IKd1D7Tu6POMq6UAm2Uv8DMd4XY/NCt9miA0RfIyPxQ
         /FNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TJBnwHvIyY65FkFLkU9lG5g2d3S7AnvQXfbc/TElRKc=;
        b=dESu+L/L90Ptzx/EpfLLPDVTP7x2Z+80PdR1T1DDKwk4QV00abpRHeLhYwoOn8ndx5
         jh1xOFHw1oyX4OGZWEk2GSmuV16J6YlAHGPKQx3FbRcWiv8VLgGM2RbWuKpsfhM3B47D
         u9CtAKmsHcsamPdNZ5c2dRTjNyw3SVGJnYjUhFfAIuvpKLcCrgMHcdcBBjoqNd3RjWyI
         cdHNS7tc3y62Ok3WRBxfII/S9k4gF9Xwo2n1kgR72pYkYQCNGbOOywcWN2uesiH/thCG
         XS7q06kEU1MY+vR4UvXcf88N8aDBgHf1VGwwcj0y91z3+cCUDlp6eQMbh9eapG+UCY5M
         +S2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TJBnwHvIyY65FkFLkU9lG5g2d3S7AnvQXfbc/TElRKc=;
        b=ZlMFFosXo8zU/6ixtV3psFD+2iaLCAQtrNh05F5s4EiP/fxGLw5z5rKP7oV4OnZ2p/
         fqKOWcWWgYTKYwPBGo6PMY5SYwYRMy17P9LJ6ye5nidWwssBOoTl9VpFEhGRGAmqmy+g
         uNOPxXgsWjH5RMGXc58B8SfGB87TqebEpeqsVfEUtwFveTKgRRo7WsmFfN5F7/Ms4GeX
         2wkXnICtLDlR21kXu9hp0FT1AL7210bg81zuxeqvdG+QaXz4esE1g9+PwBtiiCQekTwl
         WUhcbBQhqO/DcEle/FLevcXZlSUvYV6i2NMAz6ArtZneR2bwawSBj2e12zKO3sYHFHnV
         BHAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/8s5LKtTJlD4b+atBVQhz+YIndsDJZBKUa5SJ5+xhZBUb339f
	QsetzOgCPa6F8GPBZRThAGo=
X-Google-Smtp-Source: ABdhPJzewvU6KK1nEazLULyJtR9z3R/C0L9CLkS9/f8UZYEY0PoUHLBqWJPN6wqln98zdKyrFWrRfg==
X-Received: by 2002:a05:6512:118c:: with SMTP id g12mr1675817lfr.577.1624189477476;
        Sun, 20 Jun 2021 04:44:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e50:: with SMTP id g16ls4548633ljk.6.gmail; Sun, 20 Jun
 2021 04:44:36 -0700 (PDT)
X-Received: by 2002:a2e:9b9a:: with SMTP id z26mr17305374lji.384.1624189476457;
        Sun, 20 Jun 2021 04:44:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624189476; cv=none;
        d=google.com; s=arc-20160816;
        b=tK2G2bjWVuS5cDBHBc1oPsQezxOHSeHE+5wi0c/kIBUvcMdtOvKnGeUu+Br0WXbReG
         g0vB9aDANByjBGiikVBzs60uu/0bWoEm95NDWyaLxVLFpBgm8F7R2PGAmCQ60MHBs+eE
         Gf4uOZRPZAgZncYbX3JWYB/b/dn5dmVcSaHLj7rX2GHf/E5WSINC1pr/gXmIsGKX2ufx
         Ye2mXzre2VoXZGstw2NOjwHCC6BhLOhpbT/VEreVeXREVA3WdbSQ3lpS6QrU2n+ON+dV
         abOWkETVwTFRQuVnUlC0k4h07wAdqajArcnTLFXHdidwB7NjdBz2ul/TGNMFQGPhEWDK
         yUtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mNS466MM1+gmAZ7m5R3iU35irMmXL7Fyl0Gd5MfDyU0=;
        b=KgMfvVS6gwGEOyWgEsy1o7zlVcdMA0wyoSHr+2F1uMwFTxT31RUWwWMiXdPSejHbbg
         U1ixPwwYFGZjfzuE71dL318eublfsHcARNH8uUEEMcumwcJLXuel3+QgkIIRC8VzhBef
         8SQBzp6mlmXMscVMlE2dVcudOXB1KTN38a1W0gi877WddB2LCbx2QsJRVVTLHUhlAwZ3
         48V3AdwpFyEKXKBobY40WPlk+ebaq59zrLjSAC24Z7Dk8Kgl3Y+jUUYqrBtjKnsUfH0o
         kj7jJRpWayjxPw2BeWHdlZva3gumoB5q207TzyFZLc0v3nNzfmkgVEFXf5/PbOGmhoDB
         WHHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=V8xhXvAD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id d7si600781lfn.7.2021.06.20.04.44.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:44:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id r7so14941233edv.12
        for <kasan-dev@googlegroups.com>; Sun, 20 Jun 2021 04:44:36 -0700 (PDT)
X-Received: by 2002:a05:6402:1d11:: with SMTP id dg17mr2680200edb.30.1624189476065;
 Sun, 20 Jun 2021 04:44:36 -0700 (PDT)
MIME-Version: 1.0
References: <20210617081330.98629-1-dja@axtens.net>
In-Reply-To: <20210617081330.98629-1-dja@axtens.net>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 20 Jun 2021 14:44:17 +0300
Message-ID: <CA+fCnZcV3F5xMtvu6n=w9PKRfuJf5v80M8kenkmMv4gb5+btnQ@mail.gmail.com>
Subject: Re: [PATCH] mm/vmalloc: unbreak kasan vmalloc support
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nicholas Piggin <npiggin@gmail.com>, 
	David Gow <davidgow@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Uladzislau Rezki <urezki@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=V8xhXvAD;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::530
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

On Thu, Jun 17, 2021 at 11:13 AM Daniel Axtens <dja@axtens.net> wrote:
>
> In commit 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings"),
> __vmalloc_node_range was changed such that __get_vm_area_node was no
> longer called with the requested/real size of the vmalloc allocation, but
> rather with a rounded-up size.
>
> This means that __get_vm_area_node called kasan_unpoision_vmalloc() with
> a rounded up size rather than the real size. This led to it allowing
> access to too much memory and so missing vmalloc OOBs and failing the
> kasan kunit tests.
>
> Pass the real size and the desired shift into __get_vm_area_node. This
> allows it to round up the size for the underlying allocators while
> still unpoisioning the correct quantity of shadow memory.
>
> Adjust the other call-sites to pass in PAGE_SHIFT for the shift value.
>
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: David Gow <davidgow@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Uladzislau Rezki (Sony) <urezki@gmail.com>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=213335
> Fixes: 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings")
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  mm/vmalloc.c | 24 ++++++++++++++----------
>  1 file changed, 14 insertions(+), 10 deletions(-)
>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index aaad569e8963..3471cbeb083c 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2362,15 +2362,16 @@ static void clear_vm_uninitialized_flag(struct vm_struct *vm)
>  }
>
>  static struct vm_struct *__get_vm_area_node(unsigned long size,
> -               unsigned long align, unsigned long flags, unsigned long start,
> -               unsigned long end, int node, gfp_t gfp_mask, const void *caller)
> +               unsigned long align, unsigned long shift, unsigned long flags,
> +               unsigned long start, unsigned long end, int node,
> +               gfp_t gfp_mask, const void *caller)
>  {
>         struct vmap_area *va;
>         struct vm_struct *area;
>         unsigned long requested_size = size;
>
>         BUG_ON(in_interrupt());
> -       size = PAGE_ALIGN(size);
> +       size = ALIGN(size, 1ul << shift);
>         if (unlikely(!size))
>                 return NULL;
>
> @@ -2402,8 +2403,8 @@ struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
>                                        unsigned long start, unsigned long end,
>                                        const void *caller)
>  {
> -       return __get_vm_area_node(size, 1, flags, start, end, NUMA_NO_NODE,
> -                                 GFP_KERNEL, caller);
> +       return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, start, end,
> +                                 NUMA_NO_NODE, GFP_KERNEL, caller);
>  }
>
>  /**
> @@ -2419,7 +2420,8 @@ struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
>   */
>  struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
>  {
> -       return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
> +       return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
> +                                 VMALLOC_START, VMALLOC_END,
>                                   NUMA_NO_NODE, GFP_KERNEL,
>                                   __builtin_return_address(0));
>  }
> @@ -2427,7 +2429,8 @@ struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
>  struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
>                                 const void *caller)
>  {
> -       return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
> +       return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
> +                                 VMALLOC_START, VMALLOC_END,
>                                   NUMA_NO_NODE, GFP_KERNEL, caller);
>  }
>
> @@ -2949,9 +2952,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>         }
>
>  again:
> -       size = PAGE_ALIGN(size);
> -       area = __get_vm_area_node(size, align, VM_ALLOC | VM_UNINITIALIZED |
> -                               vm_flags, start, end, node, gfp_mask, caller);
> +       area = __get_vm_area_node(real_size, align, shift, VM_ALLOC |
> +                                 VM_UNINITIALIZED | vm_flags, start, end, node,
> +                                 gfp_mask, caller);
>         if (!area) {
>                 warn_alloc(gfp_mask, NULL,
>                         "vmalloc error: size %lu, vm_struct allocation failed",
> @@ -2970,6 +2973,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>          */
>         clear_vm_uninitialized_flag(area);
>
> +       size = PAGE_ALIGN(size);
>         kmemleak_vmalloc(area, size, gfp_mask);
>
>         return addr;
> --
> 2.30.2
>

This fixes the vmalloc_oob test for me. Thank you, Daniel!

Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcV3F5xMtvu6n%3Dw9PKRfuJf5v80M8kenkmMv4gb5%2BbtnQ%40mail.gmail.com.
