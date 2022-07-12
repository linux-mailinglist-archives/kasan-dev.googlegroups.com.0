Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAMFW2LAMGQEXXGGW4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id DAF5F571C1E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 16:17:38 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id r6-20020a5b06c6000000b006693f6a6d67sf6131594ybq.7
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 07:17:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657635457; cv=pass;
        d=google.com; s=arc-20160816;
        b=nu9AHdboGwtyHSI1rYhDLfbr8vzsNCeo0EsO7VBksoC3GnNG5qbC/UfI9bj+N0zmn8
         Xdl/klwTOt8cgJcOkY2kuMejFdxAmQneZI6uekm5i+jy7qq6a7NiRMo1G4ugFHxV2nV3
         YZ0ts8Do75nvk47qMC3jDYWIB+mevoxXcW3SFqfBiFFPg3d48rraM3sQwlfVfjRdGPAV
         b29CwXheJx1m7lPCl7hIjci0DVl2F25of/mmU5CbVyNk6nfGRY+78rolr3JNkuFrcUVe
         +scyD0o7xGFhgy1ESCuvAhjth28+rznKINQXIMBTgewENTJn3brK94SYTMC6Xg6dGR+o
         Q8jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5IeAW69CiIK72iyryYjcB6AvW9/JQMi+cyrHwaoJ+0E=;
        b=qTbu596Bpyk/1VaTwyzPEXfN9PanbkUUnyvalCsD92jhIPQWk1j7FIF7JRcUxvzmuN
         U/aJbVpH7bo7b3ECXIeonT4oimMxnpIEEdhqBexA0zSoUtEiCoRVo5M1aLfOHymWib9L
         wj8aBES82fBFwfBJBmbKSrkRyUP+vn3HMheVZnVOPGkU+Mb5ccKp91xVcXpq3zlx4AWS
         OQ1+1fo5Lis03eqqeskFM7WHjv14oycnUWaiMG6JHACOD8oa7QLwT8V3lPHNKIw3eXuf
         VBiWlDfIQpzg8EpJiBT2nvyke6Ta0tBGecJ8IeRbFSIBOuXujdBaN+wH1aPn/BA8ohiu
         MG3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=A0yawrSy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5IeAW69CiIK72iyryYjcB6AvW9/JQMi+cyrHwaoJ+0E=;
        b=dMXeAc0k6eN7OdF6QIugmkwCTYdiFJKTOMxV0whgrrpaeihOBVkZoov9GXr4/ODAcx
         iuH/Fmb3PrOkjxVCHBAANqSeLCgXc1krwPxJkMyFqggQIkwF9+cd6v2BKyT0gs7dJ5z/
         L5LOc9nUzkiXOnljgUa9D8DeTT+sJNdAZM4vmvGF/XIjD7WNswjgwKT0dhwfgIwWFux4
         Aajo6WkcSsmY9S/A898c9QzQdKsNHcmbaErvz+RJg+kMZJLU8a9BTwhRNvZDDZsK8YXE
         VQl9ppLZhFUG7dYc7q/+y2dmzA2xWH01iLaD1zjcyZ6Hfm29htRYDjj8QV0Fa2bsSJUu
         aoLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5IeAW69CiIK72iyryYjcB6AvW9/JQMi+cyrHwaoJ+0E=;
        b=30KgUEkJ5eqs7p17/5RMYCbn0VuXepJ3/5m/5lY0a2G7yhj47n3nzndICtS0lqfISh
         i3yRggHh4aRCRiW+3z3eeOLD5X8qxGM5a8sU+i5WTexqqqqzyrlg6oJb71bCjlYGATgc
         +mqCy5aHRH+g045LtFdn6Ce9rdYjyMd/9Uj3yMyyYJRKwArfyV2hJgrVKLRj13hkz8oR
         AMOGBKTXJhu+1DDi3vHB1bL+UuKX+eBG+VH2vWaskK8aF6a7vtGQZnVvo3dX4X1KMK82
         siCCh2Z3XpJBXaNrLgaNENlkk43V8JlM3+wDnzgaqJJLfBYG+PwKfqEybSve26cxBXmK
         o1iA==
X-Gm-Message-State: AJIora86e7Dc1Zhy2fkzsJl30kuXHAJq//vULJZH+64xUP4/jtFo2OGd
	0Ale+reJ4wU1RWPSIlGGATE=
X-Google-Smtp-Source: AGRyM1vPpoPjr1N2yzklTjX7iI8ArhSQ2tAiPOAbsG7K3C9Lh9rLE6pU42P5E8bkh+/rPMHxJTWTfA==
X-Received: by 2002:a0d:e243:0:b0:31c:9d96:8b1b with SMTP id l64-20020a0de243000000b0031c9d968b1bmr25991129ywe.222.1657635457546;
        Tue, 12 Jul 2022 07:17:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8702:0:b0:31d:5116:6baf with SMTP id x2-20020a818702000000b0031d51166bafls1477625ywf.4.gmail;
 Tue, 12 Jul 2022 07:17:36 -0700 (PDT)
X-Received: by 2002:a81:4f0c:0:b0:31d:85f8:5b7c with SMTP id d12-20020a814f0c000000b0031d85f85b7cmr8379950ywb.350.1657635456798;
        Tue, 12 Jul 2022 07:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657635456; cv=none;
        d=google.com; s=arc-20160816;
        b=msdvvKlvtoh0O3xaJ5J4/DQ6opxUo9u7VQt2exVuzfENHaTO6vVX11929HjqIDw2IJ
         NYw3r7xXZ2MFe/K+LpaBOiAGRhmXRs6WRt/oZ2qiW1fJXogzSOENjTLyV2CpNckGppB2
         cTVlt6Z4SqCyRQ6CD1LKhBH6qHkmRqcA1ArFO3fNlH9QhkwVA8C7V7BdBje8tVwtnhJA
         H+iseNFw/jIS04vfz8CNb5RmFcWbAlGh7bUIHO/vtrqWcMA6yC4JbO8hNvxRBU7RQBiq
         obKOHDbn4VFqn3qcHvmvWq9Bx7wEeiQ5mbt8IlKVnmFXw+Efmy+3ZwDzqY5G2ubWH7dd
         wuHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fEuio4lP8DLja3+6yBSWoacIG45qoddRrq8lnL8+qJY=;
        b=gKYCmgBln6btudy/J6SrpQzTncbUKskcGMnjToGYH49+LvIWMMAn45+zoVuMlkiOvE
         3PwcqYcbtuvcxKP0FA2HkG6IrjFIDgrMzJmevmd/mvgb1P7tcoVpXmNa0x70pgIZuOYz
         aVC5TRwLDInfcGMHE+cDvs6AFasW0kIZkrhFPkHymeOMf2Vw8by75LswO3ZuOp0Ikjkh
         9xcXkc+o2aXfUNj0uo0S7XywbIY6OHAAkus8j4COBwSBMJ/WpUAocgkGvFc7JMnVglO9
         vwv0EvQ5yVcIEl4yof+cI4KtCYVED1/9oX7TDIPLhNfJnsibj/90ELIZb4tI/QCpG7Zj
         zYfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=A0yawrSy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id be5-20020a05690c008500b0031c93664a8esi265374ywb.3.2022.07.12.07.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 07:17:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-31cf1adbf92so82515047b3.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 07:17:36 -0700 (PDT)
X-Received: by 2002:a0d:cf07:0:b0:31d:17cb:ec11 with SMTP id
 r7-20020a0dcf07000000b0031d17cbec11mr26264367ywd.264.1657635456390; Tue, 12
 Jul 2022 07:17:36 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-3-glider@google.com>
In-Reply-To: <20220701142310.2188015-3-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 16:17:00 +0200
Message-ID: <CANpmjNNuys+-OZj5f_5qc9dH3=+gYADJT4uxzsAPQjhPd-QCSQ@mail.gmail.com>
Subject: Re: [PATCH v4 02/45] stackdepot: reserve 5 extra bits in depot_stack_handle_t
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=A0yawrSy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112b as
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

On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
>
> Some users (currently only KMSAN) may want to use spare bits in
> depot_stack_handle_t. Let them do so by adding @extra_bits to
> __stack_depot_save() to store arbitrary flags, and providing
> stack_depot_get_extra_bits() to retrieve those flags.
>
> Also adapt KASAN to the new prototype by passing extra_bits=0, as KASAN
> does not intend to store additional information in the stack handle.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
> v4:
>  -- per Marco Elver's request, fold "kasan: common: adapt to the new
>     prototype of __stack_depot_save()" into this patch to prevent
>     bisection breakages.
>
> Link: https://linux-review.googlesource.com/id/I0587f6c777667864768daf07821d594bce6d8ff9
> ---
>  include/linux/stackdepot.h |  8 ++++++++
>  lib/stackdepot.c           | 29 ++++++++++++++++++++++++-----
>  mm/kasan/common.c          |  2 +-
>  3 files changed, 33 insertions(+), 6 deletions(-)
>
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index bc2797955de90..9ca7798d7a318 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -14,9 +14,15 @@
>  #include <linux/gfp.h>
>
>  typedef u32 depot_stack_handle_t;
> +/*
> + * Number of bits in the handle that stack depot doesn't use. Users may store
> + * information in them.
> + */
> +#define STACK_DEPOT_EXTRA_BITS 5
>
>  depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>                                         unsigned int nr_entries,
> +                                       unsigned int extra_bits,
>                                         gfp_t gfp_flags, bool can_alloc);
>
>  /*
> @@ -59,6 +65,8 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>  unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>                                unsigned long **entries);
>
> +unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
> +
>  int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
>                        int spaces);
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 5ca0d086ef4a3..3d1dbdd5a87f6 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -42,7 +42,8 @@
>  #define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
>                                         STACK_ALLOC_ALIGN)
>  #define STACK_ALLOC_INDEX_BITS (DEPOT_STACK_BITS - \
> -               STACK_ALLOC_NULL_PROTECTION_BITS - STACK_ALLOC_OFFSET_BITS)
> +               STACK_ALLOC_NULL_PROTECTION_BITS - \
> +               STACK_ALLOC_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
>  #define STACK_ALLOC_SLABS_CAP 8192
>  #define STACK_ALLOC_MAX_SLABS \
>         (((1LL << (STACK_ALLOC_INDEX_BITS)) < STACK_ALLOC_SLABS_CAP) ? \
> @@ -55,6 +56,7 @@ union handle_parts {
>                 u32 slabindex : STACK_ALLOC_INDEX_BITS;
>                 u32 offset : STACK_ALLOC_OFFSET_BITS;
>                 u32 valid : STACK_ALLOC_NULL_PROTECTION_BITS;
> +               u32 extra : STACK_DEPOT_EXTRA_BITS;
>         };
>  };
>
> @@ -76,6 +78,14 @@ static int next_slab_inited;
>  static size_t depot_offset;
>  static DEFINE_RAW_SPINLOCK(depot_lock);
>
> +unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
> +{
> +       union handle_parts parts = { .handle = handle };
> +
> +       return parts.extra;
> +}
> +EXPORT_SYMBOL(stack_depot_get_extra_bits);
> +
>  static bool init_stack_slab(void **prealloc)
>  {
>         if (!*prealloc)
> @@ -139,6 +149,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>         stack->handle.slabindex = depot_index;
>         stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
>         stack->handle.valid = 1;
> +       stack->handle.extra = 0;
>         memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
>         depot_offset += required_size;
>
> @@ -343,6 +354,7 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
>   *
>   * @entries:           Pointer to storage array
>   * @nr_entries:                Size of the storage array
> + * @extra_bits:                Flags to store in unused bits of depot_stack_handle_t
>   * @alloc_flags:       Allocation gfp flags
>   * @can_alloc:         Allocate stack slabs (increased chance of failure if false)
>   *
> @@ -354,6 +366,10 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
>   * If the stack trace in @entries is from an interrupt, only the portion up to
>   * interrupt entry is saved.
>   *
> + * Additional opaque flags can be passed in @extra_bits, stored in the unused
> + * bits of the stack handle, and retrieved using stack_depot_get_extra_bits()
> + * without calling stack_depot_fetch().
> + *
>   * Context: Any context, but setting @can_alloc to %false is required if
>   *          alloc_pages() cannot be used from the current context. Currently
>   *          this is the case from contexts where neither %GFP_ATOMIC nor
> @@ -363,10 +379,11 @@ EXPORT_SYMBOL_GPL(stack_depot_fetch);
>   */
>  depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>                                         unsigned int nr_entries,
> +                                       unsigned int extra_bits,
>                                         gfp_t alloc_flags, bool can_alloc)
>  {
>         struct stack_record *found = NULL, **bucket;
> -       depot_stack_handle_t retval = 0;
> +       union handle_parts retval = { .handle = 0 };
>         struct page *page = NULL;
>         void *prealloc = NULL;
>         unsigned long flags;
> @@ -450,9 +467,11 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>                 free_pages((unsigned long)prealloc, STACK_ALLOC_ORDER);
>         }
>         if (found)
> -               retval = found->handle.handle;
> +               retval.handle = found->handle.handle;
>  fast_exit:
> -       return retval;
> +       retval.extra = extra_bits;
> +
> +       return retval.handle;
>  }
>  EXPORT_SYMBOL_GPL(__stack_depot_save);
>
> @@ -472,6 +491,6 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>                                       unsigned int nr_entries,
>                                       gfp_t alloc_flags)
>  {
> -       return __stack_depot_save(entries, nr_entries, alloc_flags, true);
> +       return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_save);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f1..ba4fceeec173c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -36,7 +36,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>         unsigned int nr_entries;
>
>         nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -       return __stack_depot_save(entries, nr_entries, flags, can_alloc);
> +       return __stack_depot_save(entries, nr_entries, 0, flags, can_alloc);
>  }
>
>  void kasan_set_track(struct kasan_track *track, gfp_t flags)
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNuys%2B-OZj5f_5qc9dH3%3D%2BgYADJT4uxzsAPQjhPd-QCSQ%40mail.gmail.com.
