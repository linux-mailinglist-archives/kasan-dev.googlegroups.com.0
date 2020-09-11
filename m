Return-Path: <kasan-dev+bncBCMIZB7QWENRBB6J5T5AKGQEA5HJK6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 53251265A45
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 09:17:28 +0200 (CEST)
Received: by mail-vs1-xe37.google.com with SMTP id z25sf2579382vsi.21
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 00:17:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599808647; cv=pass;
        d=google.com; s=arc-20160816;
        b=SW1sa8IWGleDvvCC6I2uju3bEyhXGn1NgkGOUdC54zleKkXGU68c/qBsA0GtKOmaDz
         G+hcHEwL6lt0GdlManlWUQvLkBwkUxNkq7sf6cwrhmMIm1p0sRWlj2ssxq6aHycrEfS6
         yvF0k0Gd00xoEwzr5+cKBtFWldDH0YoueFoN0DKmmIgG7GpJ8Q8eDfa3jMjfhJZ5AmiC
         5pv16hvd/rjNFc44tEJf7/92sqMKm+QTGBdHDImJWPcQeSJYq2LZR1UfrbLVhRHmvU5h
         6r9OSLNcGEXhzvX3ySCL1s/kKLfdEWcc3tahynYSmjO9T4yYStu5Wzn5IUA4Y36O8vvU
         wIKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gocQFlX8MwBJfapWSPa5FkQ0HjXbDZRw0aoR6u8H+g4=;
        b=A9ywiqCeV1bvacduEN3itcb89AyWjpxYHRRm7i8Z7EbNzh8I0MJqURPR7AuXDxRiKv
         nEvAkVTpQr2yuCFATflYhXaWJ4OMlmfotgpPEHWaFd+zso0CDB7EcNAevvuR6JV8/kFA
         bxiPOw3X0Zgz94YlpjD7Fr8opxRkVIc/ujVB/S69FQ5YY3SiNs2TSyuFXpYpn3RDiiB4
         mMTLMvoslgXi2co35X6q8ShN7SGZGAD0Z/CqlGL5RKIxnqAjsIUmTIKCsJFhej36oWqJ
         gI/7294WheMHeON377AaPqsvDmRUQoczVm8+OgglLV0n84p0alU85uRkakGpoqftHxTo
         LIkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CM1Z1fWR;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gocQFlX8MwBJfapWSPa5FkQ0HjXbDZRw0aoR6u8H+g4=;
        b=OvgoFW+PJtiQaHNY4EC6a6RhYn65kP+rRR+c0780ruZ4d0gKsbkbhh8wpiq0DThWnX
         2mUaGOkMTYnYUeiqDdA6VgffVlAKjEHq52MSR6ulLrIM3VGU81377U5f1tg3O7cruv94
         0R9vALgo0pUTuVOUxncLRYjbFiKQxgGJ1fX83hlwzgU1zjPV46Uxlb4Lv3bX9CPTRDkr
         e6r0FlZwdvSs1sjbcKJ/JcrA2xN+srjfmZ04d6wAIjPTgEXlbVjVs+0r3X2bZuc96C/L
         PMwEB6xiE+R3EFa6PQUcK/e6qsX5eLfPSaDSpCWN/E2jtOEwJbd0fy/xfwbcfrFJp0PN
         4cxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gocQFlX8MwBJfapWSPa5FkQ0HjXbDZRw0aoR6u8H+g4=;
        b=LMNWI6P750Sm1wtLM6e/feTCayw48fegl3cIpnii85VoTCGv7oc2weX2H4eJOVAtVB
         oLuux2S/2z6SSX7Up+LjauE2XNAC0wFgMLrDwSJEw/4PtPVKBNR1CRqQC3/kPSS2fOQZ
         6ymwv1+4Qk1dJbCp1gkzsRD4pQ+RGrvzX8rrjLkFXQ6qJJs7PzBUfYcGGyT+9eN7rLkV
         7OFdmhnOcxGxOfCCtDSoE/rFxnqmxtIauv1PWHWHzMUhQJnDhroe7/7S6VfYX6rIZqaz
         h/A5bAB2DeeeY2kK9cK1cklhBCBnwGZDbFrwG+77t2FelI0ujN3taptx6uBCC+3OHuBo
         d8TQ==
X-Gm-Message-State: AOAM530k8Mx306Pmfof9EVIS5s6rBVMZ9CIjBoKJAaSG5sl32IBlt59+
	tia0rY81kZNTHnfQH/W72u0=
X-Google-Smtp-Source: ABdhPJxqeY11WRjKyXFK0aCcp7gKvS1wDZN4f2pLhAgC6t8h1vd7T/dbRzq8KvTuKo+XRHuRbuQvOg==
X-Received: by 2002:a05:6102:204b:: with SMTP id q11mr319306vsr.40.1599808647106;
        Fri, 11 Sep 2020 00:17:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2517:: with SMTP id j23ls88384uan.10.gmail; Fri, 11 Sep
 2020 00:17:26 -0700 (PDT)
X-Received: by 2002:ab0:2452:: with SMTP id g18mr283172uan.13.1599808646675;
        Fri, 11 Sep 2020 00:17:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599808646; cv=none;
        d=google.com; s=arc-20160816;
        b=YCB/LBKYmaSksEyyo9URWEufW2bukO2+KugneHHrV78EwTGwgM+P8EP3w30zwYQ9ii
         ffXTHyW/g6WqbIg9KfyULeTdSl9EkLm0Zi2n6ROgmBujhAssO0voKvE+XqcH7K5oyVkq
         5kMEZl6iFEhyhxdAZeWc1Tk1WWKFnIxHcj901squi73sYP6Qd1i/XbZPR2mOq1uwwvi/
         6F7slQu9j8eNJn0cWqNDYkXnF77fpdwVQTa5LuwqTuH9scETAyo9oOsWkigOGmKlv10z
         eRZwgqlsepptWYEN2p11U6gyBsYUErGpDGutbLdqtXvIV/YywK6KkMYxFOb7ceWVKOIe
         b5MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gVSrJh8rChLGd4eP0NihtPJ1y8qJuAg60MCfyTLhE9Y=;
        b=PFfUa23t4iA8RV/VIpWT+s0MB1PGCkszkVaWIzmK5attvMVf/Ku9rAkM95EMXyk7Q5
         crRzLBwTyDDyJKTD5b3wnup0N2/pD4uwDvgYcxIljodNUISWx8nLmoQUMz63cFbEMp7s
         XyqlY2oKWZZ/9/9rMzsVpZ1+l3FW3YNSbkuqbS2PZNeLnyAZLkpJKlxJaEvCL5B0wScA
         Pm8o0I5NSWIlwDocBcQrWU6HOawk/7Vbo2ppq7DBAKjtO7Xijxn8OoXOjS7gv+YOQatQ
         HULuwGvCN8pCbPspKLDdF4JsFKNhb9t4RTohXiy0Sxi+BTuwsdnGVOZWclYbSi8ClMHA
         dHDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CM1Z1fWR;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id t1si110472vsk.2.2020.09.11.00.17.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 00:17:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id c18so7111649qtw.5
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 00:17:26 -0700 (PDT)
X-Received: by 2002:aed:26a7:: with SMTP id q36mr642989qtd.57.1599808645941;
 Fri, 11 Sep 2020 00:17:25 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-5-elver@google.com>
In-Reply-To: <20200907134055.2878499-5-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 09:17:14 +0200
Message-ID: <CACT4Y+aXNmQzp6J+mP+ELj8kUHmRPkibc1--KtV9a3ud_X8miw@mail.gmail.com>
Subject: Re: [PATCH RFC 04/10] mm, kfence: insert KFENCE hooks for SLAB
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CM1Z1fWR;       spf=pass
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

On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
>
> From: Alexander Potapenko <glider@google.com>
>
> Inserts KFENCE hooks into the SLAB allocator.
>
> We note the addition of the 'orig_size' argument to slab_alloc*()
> functions, to be able to pass the originally requested size to KFENCE.
> When KFENCE is disabled, there is no additional overhead, since these
> functions are __always_inline.
>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/slab.c        | 46 ++++++++++++++++++++++++++++++++++------------
>  mm/slab_common.c |  6 +++++-
>  2 files changed, 39 insertions(+), 13 deletions(-)
>
> diff --git a/mm/slab.c b/mm/slab.c
> index 3160dff6fd76..30aba06ae02b 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -100,6 +100,7 @@
>  #include       <linux/seq_file.h>
>  #include       <linux/notifier.h>
>  #include       <linux/kallsyms.h>
> +#include       <linux/kfence.h>
>  #include       <linux/cpu.h>
>  #include       <linux/sysctl.h>
>  #include       <linux/module.h>
> @@ -3206,7 +3207,7 @@ static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
>  }
>
>  static __always_inline void *
> -slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
> +slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_size,
>                    unsigned long caller)
>  {
>         unsigned long save_flags;
> @@ -3219,6 +3220,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
>         if (unlikely(!cachep))
>                 return NULL;
>
> +       ptr = kfence_alloc(cachep, orig_size, flags);
> +       if (unlikely(ptr))
> +               goto out_hooks;
> +
>         cache_alloc_debugcheck_before(cachep, flags);
>         local_irq_save(save_flags);
>
> @@ -3251,6 +3256,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
>         if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
>                 memset(ptr, 0, cachep->object_size);
>
> +out_hooks:
>         slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
>         return ptr;
>  }
> @@ -3288,7 +3294,7 @@ __do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
>  #endif /* CONFIG_NUMA */
>
>  static __always_inline void *
> -slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
> +slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned long caller)
>  {
>         unsigned long save_flags;
>         void *objp;
> @@ -3299,6 +3305,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
>         if (unlikely(!cachep))
>                 return NULL;
>
> +       objp = kfence_alloc(cachep, orig_size, flags);
> +       if (unlikely(objp))
> +               goto leave;
> +
>         cache_alloc_debugcheck_before(cachep, flags);
>         local_irq_save(save_flags);
>         objp = __do_cache_alloc(cachep, flags);
> @@ -3309,6 +3319,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
>         if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
>                 memset(objp, 0, cachep->object_size);
>
> +leave:
>         slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
>         return objp;
>  }
> @@ -3414,6 +3425,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
>  static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
>                                          unsigned long caller)
>  {
> +       if (kfence_free(objp)) {
> +               kmemleak_free_recursive(objp, cachep->flags);
> +               return;
> +       }
> +
>         /* Put the object into the quarantine, don't touch it for now. */
>         if (kasan_slab_free(cachep, objp, _RET_IP_))
>                 return;
> @@ -3479,7 +3495,7 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
>   */
>  void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
>  {
> -       void *ret = slab_alloc(cachep, flags, _RET_IP_);
> +       void *ret = slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);


It's kinda minor, but since we are talking about malloc fast path:
will passing 0 instead of cachep->object_size (here and everywhere
else) and then using cachep->object_size on the slow path if 0 is
passed as size improve codegen?


>         trace_kmem_cache_alloc(_RET_IP_, ret,
>                                cachep->object_size, cachep->size, flags);
> @@ -3512,7 +3528,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>
>         local_irq_disable();
>         for (i = 0; i < size; i++) {
> -               void *objp = __do_cache_alloc(s, flags);
> +               void *objp = kfence_alloc(s, s->object_size, flags) ?: __do_cache_alloc(s, flags);
>
>                 if (unlikely(!objp))
>                         goto error;
> @@ -3545,7 +3561,7 @@ kmem_cache_alloc_trace(struct kmem_cache *cachep, gfp_t flags, size_t size)
>  {
>         void *ret;
>
> -       ret = slab_alloc(cachep, flags, _RET_IP_);
> +       ret = slab_alloc(cachep, flags, size, _RET_IP_);
>
>         ret = kasan_kmalloc(cachep, ret, size, flags);
>         trace_kmalloc(_RET_IP_, ret,
> @@ -3571,7 +3587,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
>   */
>  void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
>  {
> -       void *ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
> +       void *ret = slab_alloc_node(cachep, flags, nodeid, cachep->object_size, _RET_IP_);
>
>         trace_kmem_cache_alloc_node(_RET_IP_, ret,
>                                     cachep->object_size, cachep->size,
> @@ -3589,7 +3605,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *cachep,
>  {
>         void *ret;
>
> -       ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
> +       ret = slab_alloc_node(cachep, flags, nodeid, size, _RET_IP_);
>
>         ret = kasan_kmalloc(cachep, ret, size, flags);
>         trace_kmalloc_node(_RET_IP_, ret,
> @@ -3650,7 +3666,7 @@ static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
>         cachep = kmalloc_slab(size, flags);
>         if (unlikely(ZERO_OR_NULL_PTR(cachep)))
>                 return cachep;
> -       ret = slab_alloc(cachep, flags, caller);
> +       ret = slab_alloc(cachep, flags, size, caller);
>
>         ret = kasan_kmalloc(cachep, ret, size, flags);
>         trace_kmalloc(caller, ret,
> @@ -4138,18 +4154,24 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
>                          bool to_user)
>  {
>         struct kmem_cache *cachep;
> -       unsigned int objnr;
> +       unsigned int objnr = 0;
>         unsigned long offset;
> +       bool is_kfence = is_kfence_address(ptr);
>
>         ptr = kasan_reset_tag(ptr);
>
>         /* Find and validate object. */
>         cachep = page->slab_cache;
> -       objnr = obj_to_index(cachep, page, (void *)ptr);
> -       BUG_ON(objnr >= cachep->num);
> +       if (!is_kfence) {
> +               objnr = obj_to_index(cachep, page, (void *)ptr);
> +               BUG_ON(objnr >= cachep->num);
> +       }
>
>         /* Find offset within object. */
> -       offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
> +       if (is_kfence_address(ptr))
> +               offset = ptr - kfence_object_start(ptr);
> +       else
> +               offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
>
>         /* Allow address range falling entirely within usercopy region. */
>         if (offset >= cachep->useroffset &&
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index f9ccd5dc13f3..6e35e273681a 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -12,6 +12,7 @@
>  #include <linux/memory.h>
>  #include <linux/cache.h>
>  #include <linux/compiler.h>
> +#include <linux/kfence.h>
>  #include <linux/module.h>
>  #include <linux/cpu.h>
>  #include <linux/uaccess.h>
> @@ -448,6 +449,9 @@ static int shutdown_cache(struct kmem_cache *s)
>         /* free asan quarantined objects */
>         kasan_cache_shutdown(s);
>
> +       if (!kfence_shutdown_cache(s))
> +               return -EBUSY;
> +
>         if (__kmem_cache_shutdown(s) != 0)
>                 return -EBUSY;
>
> @@ -1171,7 +1175,7 @@ size_t ksize(const void *objp)
>         if (unlikely(ZERO_OR_NULL_PTR(objp)) || !__kasan_check_read(objp, 1))
>                 return 0;
>
> -       size = __ksize(objp);
> +       size = kfence_ksize(objp) ?: __ksize(objp);
>         /*
>          * We assume that ksize callers could use whole allocated area,
>          * so we need to unpoison this area.
> --
> 2.28.0.526.ge36021eeef-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaXNmQzp6J%2BmP%2BELj8kUHmRPkibc1--KtV9a3ud_X8miw%40mail.gmail.com.
