Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNGNZT5QKGQEJEV4MTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 29D5E27CA81
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 14:21:10 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id q12sf3153148pjg.9
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 05:21:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601382069; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xgp4tCHVUO03RYgUcnrKa9mG/Mdx17pMmwYGEaZm50TW7Gw5Rb8Zm0tObgjvu88Bv2
         onh8OuvnE9eSmxmUSccK/8381tTnt3oyG4D2LPeBBMSmdgoaGGD0pdbJ0urWyx9gREcC
         +OvfPnP1XnvDtv5MJ5DELGxBI/e2sZQW9nY2g/GG2a3BdV0ZNzeW740m3VTMrjYvEUmw
         /Yr5pQ5Mq6tBlENvqbOnn0DLPuBgd0BcciRBPWNo/DHixYP+Qw+s08QwZ/bt4HpCaUVY
         cDlfhhewmOC/RGIPT5c/Pv9+v8436OSP8H54/1uSxE3zXcnfcdveIgltWfjyFqV6vycx
         MmvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vHEanSCyHKwkQ+/xzvt+IDIHiytFYzC6Gu/TxFqhAXo=;
        b=n349FVfvhFSLDfGwZz13ttjlqNKelgZVgC8887WxHFnb7bL2pXDu6bx7/YB9bimyid
         1IR4RvxmI/4wR+fWN6k83DJE7t1aMgc0DxGnXAcmOnUYWOuVdtqkdgEk6009UY0OBouD
         Wx+3dajVaQTW5dCRcYRTmJ3HhO/P1tufM+PxpMSfVdjbFnQCq2u1V2bLaXJS1NJwbVQF
         t22ffyrlAj/+HXSHsQUfv1UnQHnLRx3yBLxtHYeM+J2b5x+OdLePViZ568ImZZ2NpcCt
         NN+y0s4FOv2DpgbRcbD2fP6vxcWvJUVG5Tv9/uI5gjOp3bYOcXpyanx1QSEMqBVcN4LK
         Y1lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SX2sc9ks;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vHEanSCyHKwkQ+/xzvt+IDIHiytFYzC6Gu/TxFqhAXo=;
        b=CiGFmzPFQ/cUtUZ7yfZAnAWAjNaEb2iN6NAoZY58/t6ZYUdxH8y+skMSw3j/fpynGX
         8LcWW8fDZK42nzLgz+zRvCdItPepX3wmdS6UDOD6JwExYZBDB7lxFgH4rBdC+P3IGT2/
         7W/LT4yd3V7CEpaT3Lwma/rnBUDvYfdsCEvuQcu/revoTJGpRpDZF/RKQP4LXS1JnRaX
         VQfWENNKghbjdFsKzW7VR2knWDqmQcvi55iU1LgqfSyMYPuCb/Dl4jTeumDsZY4qTFNt
         r/Nn8Q6Ko55e0fYscs0I+jPmQZt0PIy5mmfptB8K1itBh8w9wcBXhIVIoIg3ymPAztQh
         YG3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vHEanSCyHKwkQ+/xzvt+IDIHiytFYzC6Gu/TxFqhAXo=;
        b=N0zIF6vF9fG8DD212/oIBEC3PBXTabPH8VLxec1rXKtrlGEJ8qU1/XZJ+35nn2PhzE
         GgNvLn0vfAC2mva9WuD9UqaJzPfjZXEfEitAp96eHOoOs1MUEIP47v9ow6pz/vlpn1oR
         Iaz90Jf9zMc6EVOEiSIP5Ikdtes8GNAr6qkEeiDNoENkey60QmubXa3TFHOKwMU08AT8
         ZlmSV42c21L7LAvfUnA50mYfC67I20l84YLZ3QFeC6226slhF6AjiwzHWUO5tSKd8nBZ
         /Sr5NpVBCWr0PtmVL+RsAAa+Nd+B48IkL6ZlPXDeEHNmgBsSb+HjEPZVutfSenJE7jrE
         Feqg==
X-Gm-Message-State: AOAM531H3UqgW5R0EpYg9aUOxHWa1g0rPWq4a8n2/eoMNGe6tMOLjkvi
	QDYgHmt8ts+iCknD9HSZL7s=
X-Google-Smtp-Source: ABdhPJxj+WLoRam0vUUdxHlzRia6ua8sWVCEXXWHIGCXGeFCsg54gy6IMQSFJN4XMm5D95HXwttq5w==
X-Received: by 2002:a62:1a95:0:b029:151:d47e:119b with SMTP id a143-20020a621a950000b0290151d47e119bmr1997396pfa.46.1601382068745;
        Tue, 29 Sep 2020 05:21:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:441d:: with SMTP id r29ls3120550pga.4.gmail; Tue, 29 Sep
 2020 05:21:08 -0700 (PDT)
X-Received: by 2002:a63:511d:: with SMTP id f29mr3102295pgb.11.1601382068124;
        Tue, 29 Sep 2020 05:21:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601382068; cv=none;
        d=google.com; s=arc-20160816;
        b=DaReGL0TuwjKjXk5s/tIBtU4vU7pLxYd6ivY1MIgu2xrJHweg+gl7Vye64MsfX+G14
         +ZWBBsPtBZ/P/7jR5WLGNOMwpGiFMLZOFK0NwOOdooBl+5B3mwQYkW43LZQc8Cfo3z25
         ls4eTncVi0EVMVJY48n4JqJvod9Qw1U8UMGCOpfotz3IhfSZpcny8U1wHKjN7GU3iFyJ
         pXfojAt7A3bbZVOWQfY23Y/2j9pmQGwTlNq/dlooEZkNWKK0/BDdcrr1HrOFHNBS+eUV
         AzGc8zlvlRIG63U6hNcJdHleHFrDRyM6The7tT2AnYvWHorf+YyoPzQFgxpDpeprbday
         gyWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k5kKBQ+Qqkla12YVhGRy7ZogNeaVCuiLnDorQW/L8Lg=;
        b=RFK5DgA9//dmGeOJrFMcop1n/qvS4JZD2y9ScyoLoB8pl/di+BDCDIUMEuuoSaMxNe
         sARHOxIE+zZAGnGp0ljWorMFke1UqLaV8rgMeXBibC8m2nvQl7QhbK4mEyo2eix6J47Y
         ewPZxk+RkEmiWnMP3TcEDWA3fhoWy1x2m3vmUqs1eus+78hjqnXlYGrtylXuzte0ymxE
         SnlRhyAdFHttBIJiWsprpZl90hi1BpRUkAWbH10zOw3oYQFKijRx2zZFwDH1vT+EzGGd
         H5d7VWr9hhU1lZcbeyScJDYXjzvy15BLSHNMkccEyy5HHv5OectBqL24cZgzwN4S7i5s
         yYYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SX2sc9ks;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id h1si1999pfh.5.2020.09.29.05.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 05:21:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id t14so3719697pgl.10
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 05:21:08 -0700 (PDT)
X-Received: by 2002:a62:ee10:0:b029:142:2501:3972 with SMTP id
 e16-20020a62ee100000b029014225013972mr3782717pfi.55.1601382067482; Tue, 29
 Sep 2020 05:21:07 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-7-elver@google.com>
In-Reply-To: <20200921132611.1700350-7-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 14:20:53 +0200
Message-ID: <CAAeHK+yMmGSTpwC1zPxaoBmXsfmmhuLJ3b2N3qUXUjO5U0tM3Q@mail.gmail.com>
Subject: Re: [PATCH v3 06/10] kfence, kasan: make KFENCE compatible with KASAN
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SX2sc9ks;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Sep 21, 2020 at 3:26 PM Marco Elver <elver@google.com> wrote:
>
> From: Alexander Potapenko <glider@google.com>
>
> We make KFENCE compatible with KASAN for testing KFENCE itself. In
> particular, KASAN helps to catch any potential corruptions to KFENCE
> state, or other corruptions that may be a result of freepointer
> corruptions in the main allocators.
>
> To indicate that the combination of the two is generally discouraged,
> CONFIG_EXPERT=y should be set. It also gives us the nice property that
> KFENCE will be build-tested by allyesconfig builds.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  lib/Kconfig.kfence | 2 +-
>  mm/kasan/common.c  | 7 +++++++
>  2 files changed, 8 insertions(+), 1 deletion(-)
>
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 4c2ea1c722de..6825c1c07a10 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -10,7 +10,7 @@ config HAVE_ARCH_KFENCE_STATIC_POOL
>
>  menuconfig KFENCE
>         bool "KFENCE: low-overhead sampling-based memory safety error detector"
> -       depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
> +       depends on HAVE_ARCH_KFENCE && (!KASAN || EXPERT) && (SLAB || SLUB)
>         depends on JUMP_LABEL # To ensure performance, require jump labels
>         select STACKTRACE
>         help
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 950fd372a07e..f5c49f0fdeff 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -18,6 +18,7 @@
>  #include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> +#include <linux/kfence.h>
>  #include <linux/kmemleak.h>
>  #include <linux/linkage.h>
>  #include <linux/memblock.h>
> @@ -396,6 +397,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>         tagged_object = object;
>         object = reset_tag(object);
>
> +       if (is_kfence_address(object))
> +               return false;
> +
>         if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
>             object)) {
>                 kasan_report_invalid_free(tagged_object, ip);
> @@ -444,6 +448,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         if (unlikely(object == NULL))
>                 return NULL;
>
> +       if (is_kfence_address(object))
> +               return (void *)object;
> +
>         redzone_start = round_up((unsigned long)(object + size),
>                                 KASAN_SHADOW_SCALE_SIZE);
>         redzone_end = round_up((unsigned long)object + cache->object_size,
> --
> 2.28.0.681.g6f77f65b4e-goog
>

With KFENCE + KASAN both enabled we need to bail out in all KASAN
hooks that get called from the allocator, right? Do I understand
correctly that these two are the only ones that are called for
KFENCE-allocated objects due to the way KFENCE is integrated into the
allocator?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByMmGSTpwC1zPxaoBmXsfmmhuLJ3b2N3qUXUjO5U0tM3Q%40mail.gmail.com.
