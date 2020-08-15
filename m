Return-Path: <kasan-dev+bncBCF5XGNWYQBRBUFF4D4QKGQEVAVXM4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E4B3C245182
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 18:52:33 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id t9sf5095668otk.22
        for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 09:52:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597510352; cv=pass;
        d=google.com; s=arc-20160816;
        b=l8KAz7cJg/h3X71yGMp6zOJaMgxOt4SpKU6u8Nit5TLyj4NaEspqZLBEtBkUwMu6eN
         SNYeQW8rv2xTv7ndJin+7FRTI/qgzeZwgyWYea2hA/sXUGV+JMIzDcm+v46Crl0o4+VE
         5AsEiZD8hYrQzL2dFFYy3PieJPrPVdlFLuFJ305foHeFtkqGyxP+vEVDorl2FmcIyXpy
         XdlpsVuSnEsV3RBHo/WQLtjZ4IgVI34N/N+HD6/VoaQKK/1p5e5jxgXIfe37wiK0NfST
         RvJTjhwBR9d+xeCjyxLDAXGQPqTJGYBc38kH6a1exNuoBSJym/K6mN7Y4A+U9bLG9zl1
         WKdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SFeotdUxJo4tBwtXms0uZxdo55ElSrh6b7Y/wg3aHic=;
        b=N5q1LSb9oz5C7D8259BIO7XZCAMt1baKRYzqbSZxmzuCj1QrvGMpGTWcju1P7DG7ND
         ZTPn6aiOnsPoH/uYaq44njENvf/iUHxJXFqFK+44+3ZDf0/l9Zgvj5AC0hLpaPy+ERuj
         YenhsPGoWrCOEFkkYj+PXPRTQ10BDpK8k7qZYSWVhggKGF5DKltM+GnRR4VOuFulNuIA
         cHNFzt52ek/AWT1Nkt5lghkO552s5C/yuzX1w1X3jI4gUoWN6pQln0Pk5fVG7GUyAdS4
         bQp0im1RR11qGE1DDNbMMSTBXVRolSPAYsUkUL+ZrZk9Y3qL1QqkQ6I+0joAHdbBlXFw
         hTuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=hujs8iqh;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SFeotdUxJo4tBwtXms0uZxdo55ElSrh6b7Y/wg3aHic=;
        b=Fjdqt2iu055X4CT86P/1yB1YCV5R+T5jizIULWuD4kbeWAl/efpGrVaF9klcWscgzX
         9SduftP96Y+LxuIOJMDKErqwbGGJtJJMOD0RqtR4lPiZKLsT7S0wCkTrf2HgIDqt2zXy
         TfcW004mv7jebT+66EXe1V8vZoxVrVcKBhuuY68z7wJR2skCBTHKtZTdZ6zmNVtTZfTh
         tnrhn/7kquCy39xA0/4bKojQVBlESpbva8IjMUqcmBPatDQb08aIi3w23atJWQuXA7tV
         dBkpcqir/Zhozb2e14ceCGcqVwGYgYc7LLdXi6l/2Sw2lLsTz0PkS46hAQkxenk0a9m7
         hgNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SFeotdUxJo4tBwtXms0uZxdo55ElSrh6b7Y/wg3aHic=;
        b=SsXTC16FopWxh3H3/+Qjfla6OlF/XI1WQ0fxcnMaWsr/IAN9yCxZFetoq0Ui+D6tzA
         mvOzjwj7Td6m7U+lntQk19mSbFJEcCo2/zZpa0Xd4iYj3eKVEOXyQrW+JQsI9GJloUx0
         DITzvZ097MhwuY5qEzxinUOw5vUg/1i8+1fp0tTrpIYPOg1I3MEwlMoaJtV/0mHMKK2x
         dnLaNhWEB5xz+KO/IbpqNh0M8j/+SGcPOPbgAlFBUKGgv/4LNK2bQmeMxIANfUS5CPO3
         Q3f5IFflPzsQiBBhfMQbkDOm26BoxTku0Tl7MD8afbdl6rPKnVSLrDrSbY0rxN8BivqY
         nDDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KICHAIsHSRb7YvJvhYVigTjTfQB7H7jb7qADUFWDybXrfE3wQ
	jIVgs0U0SEHO2ZBFV2Ie6KA=
X-Google-Smtp-Source: ABdhPJzEUfR+XIo0qZmk2qV+sQ7y/YRghjRqJXx2DcK/e7JsxlpqQsXv4Nj8QOVdd3PPifbwewzXbQ==
X-Received: by 2002:a05:6830:1305:: with SMTP id p5mr5953598otq.135.1597510352618;
        Sat, 15 Aug 2020 09:52:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:66d7:: with SMTP id t23ls2674946otm.1.gmail; Sat, 15 Aug
 2020 09:52:32 -0700 (PDT)
X-Received: by 2002:a05:6830:60f:: with SMTP id w15mr5762899oti.85.1597510352264;
        Sat, 15 Aug 2020 09:52:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597510352; cv=none;
        d=google.com; s=arc-20160816;
        b=IjiBo42nKsqC00RmnL1FiepQKx/dZHQcSOpCGjrOdo3bzYi/cPb2GFEgnGY8vjApnA
         0NlWqV8lHDp/99rsuQW3jX/gWRXIeiYj1ElCiKLJRR8apGuQAELNPudnAMXWzY4oGkO/
         pP+gZy4USpBBWpC4v9qcZCXLLr605IjFSUzyvnYo7CHrJ4Hn0BJxbfENLeIRZ9Gfn/JX
         k13BjNskggJ8ot8ACRXFixLpj60guCbmynHWIgtt/PpreKCwKONvyyCPZWSbgob/Ze99
         mVwjzUdlX4wT5wws+A0HhRA1DYNEcuICxfdCGXxf24g8ZXflv9z0f572/0hihBQUxRzM
         57sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DkuPBAVHx3cth8w3eFKEZSaG/hl3FQz11+r5yt96mWw=;
        b=o4YdV7GaW/nxgIL/Y45AmMv9WnyygR/6xspUtJphBV1zzLJr3IQInPsM/4QpM5g6rz
         U2OPkH2HYm1HV++w3826kyU5REJyiVB9UiB97/FmPUpQvRXKpyV2zLMY+nHHD1RMWhiR
         ri+CXIykM0MIK+s+Zd1GsTE0Nz6ToFP8qQ+c2BLJIv4Tty4+LSnlDgzvbZbqBXTgNmHd
         wm76+9DO8Va0uFc+3QcRxK/h0nPY1CVRE9LufC9Cgv5wtpMAFlU6F/tnTECeJk3bFElq
         diG0UOfQkted0/YBMnAGM+4eNdMGUAAvMVFVIIEwpcpARn8qA4E3b+dgndEam8DKXKjS
         ezRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=hujs8iqh;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id t21si323910oif.4.2020.08.15.09.52.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 15 Aug 2020 09:52:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id g15so1605713plj.6
        for <kasan-dev@googlegroups.com>; Sat, 15 Aug 2020 09:52:32 -0700 (PDT)
X-Received: by 2002:a17:90a:1749:: with SMTP id 9mr6560678pjm.127.1597510351412;
        Sat, 15 Aug 2020 09:52:31 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id n1sm12732251pfu.2.2020.08.15.09.52.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 15 Aug 2020 09:52:30 -0700 (PDT)
Date: Sat, 15 Aug 2020 09:52:29 -0700
From: Kees Cook <keescook@chromium.org>
To: Alexander Popov <alex.popov@linux.com>
Cc: Jann Horn <jannh@google.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com, linux-kernel@vger.kernel.org,
	notify@kernel.org
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
Message-ID: <202008150939.A994680@keescook>
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200813151922.1093791-2-alex.popov@linux.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=hujs8iqh;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
> Heap spraying is an exploitation technique that aims to put controlled
> bytes at a predetermined memory location on the heap. Heap spraying for
> exploiting use-after-free in the Linux kernel relies on the fact that on
> kmalloc(), the slab allocator returns the address of the memory that was
> recently freed. Allocating a kernel object with the same size and
> controlled contents allows overwriting the vulnerable freed object.
> 
> Let's extract slab freelist quarantine from KASAN functionality and
> call it CONFIG_SLAB_QUARANTINE. This feature breaks widespread heap
> spraying technique used for exploiting use-after-free vulnerabilities
> in the kernel code.
> 
> If this feature is enabled, freed allocations are stored in the quarantine
> and can't be instantly reallocated and overwritten by the exploit
> performing heap spraying.

It may be worth clarifying that this is specifically only direct UAF and
doesn't help with spray-and-overflow-into-a-neighboring-object attacks
(i.e. both tend to use sprays, but the former doesn't depend on a write
overflow).

> Signed-off-by: Alexander Popov <alex.popov@linux.com>
> ---
>  include/linux/kasan.h      | 107 ++++++++++++++++++++-----------------
>  include/linux/slab_def.h   |   2 +-
>  include/linux/slub_def.h   |   2 +-
>  init/Kconfig               |  11 ++++
>  mm/Makefile                |   3 +-
>  mm/kasan/Makefile          |   2 +
>  mm/kasan/kasan.h           |  75 +++++++++++++-------------
>  mm/kasan/quarantine.c      |   2 +
>  mm/kasan/slab_quarantine.c |  99 ++++++++++++++++++++++++++++++++++
>  mm/slub.c                  |   2 +-
>  10 files changed, 216 insertions(+), 89 deletions(-)
>  create mode 100644 mm/kasan/slab_quarantine.c
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 087fba34b209..b837216f760c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -42,32 +42,14 @@ void kasan_unpoison_task_stack(struct task_struct *task);
>  void kasan_alloc_pages(struct page *page, unsigned int order);
>  void kasan_free_pages(struct page *page, unsigned int order);
>  
> -void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> -			slab_flags_t *flags);
> -
>  void kasan_poison_slab(struct page *page);
>  void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
>  void kasan_poison_object_data(struct kmem_cache *cache, void *object);
>  void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>  					const void *object);
>  
> -void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> -						gfp_t flags);
>  void kasan_kfree_large(void *ptr, unsigned long ip);
>  void kasan_poison_kfree(void *ptr, unsigned long ip);
> -void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
> -					size_t size, gfp_t flags);
> -void * __must_check kasan_krealloc(const void *object, size_t new_size,
> -					gfp_t flags);
> -
> -void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
> -					gfp_t flags);
> -bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> -
> -struct kasan_cache {
> -	int alloc_meta_offset;
> -	int free_meta_offset;
> -};
>  
>  /*
>   * These functions provide a special case to support backing module
> @@ -107,10 +89,6 @@ static inline void kasan_disable_current(void) {}
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>  
> -static inline void kasan_cache_create(struct kmem_cache *cache,
> -				      unsigned int *size,
> -				      slab_flags_t *flags) {}
> -
>  static inline void kasan_poison_slab(struct page *page) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
>  					void *object) {}
> @@ -122,17 +100,65 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
>  	return (void *)object;
>  }
>  
> +static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> +static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> +static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> +static inline void kasan_remove_zero_shadow(void *start, unsigned long size) {}
> +static inline void kasan_unpoison_slab(const void *ptr) {}
> +
> +static inline int kasan_module_alloc(void *addr, size_t size)
> +{
> +	return 0;
> +}
> +
> +static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> +{
> +	return 0;
> +}
> +
> +static inline size_t kasan_metadata_size(struct kmem_cache *cache)
> +{
> +	return 0;
> +}
> +
> +#endif /* CONFIG_KASAN */
> +
> +struct kasan_cache {
> +	int alloc_meta_offset;
> +	int free_meta_offset;
> +};
> +
> +#if defined(CONFIG_KASAN) || defined(CONFIG_SLAB_QUARANTINE)
> +
> +void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> +			slab_flags_t *flags);
> +void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
> +						gfp_t flags);
> +void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
> +					size_t size, gfp_t flags);
> +void * __must_check kasan_krealloc(const void *object, size_t new_size,
> +					gfp_t flags);
> +void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
> +					gfp_t flags);
> +bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
> +
> +#else /* CONFIG_KASAN || CONFIG_SLAB_QUARANTINE */
> +
> +static inline void kasan_cache_create(struct kmem_cache *cache,
> +				      unsigned int *size,
> +				      slab_flags_t *flags) {}
> +
>  static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
>  {
>  	return ptr;
>  }
> -static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
> +
>  static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
>  				size_t size, gfp_t flags)
>  {
>  	return (void *)object;
>  }
> +
>  static inline void *kasan_krealloc(const void *object, size_t new_size,
>  				 gfp_t flags)
>  {
> @@ -144,43 +170,28 @@ static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>  {
>  	return object;
>  }
> +
>  static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  				   unsigned long ip)
>  {
>  	return false;
>  }
> -
> -static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
> -static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> -
> -static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> -{
> -	return 0;
> -}
> -static inline void kasan_remove_zero_shadow(void *start,
> -					unsigned long size)
> -{}
> -
> -static inline void kasan_unpoison_slab(const void *ptr) { }
> -static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> -
> -#endif /* CONFIG_KASAN */
> +#endif /* CONFIG_KASAN || CONFIG_SLAB_QUARANTINE */
>  
>  #ifdef CONFIG_KASAN_GENERIC
> -
>  #define KASAN_SHADOW_INIT 0
> -
> -void kasan_cache_shrink(struct kmem_cache *cache);
> -void kasan_cache_shutdown(struct kmem_cache *cache);
>  void kasan_record_aux_stack(void *ptr);
> -
>  #else /* CONFIG_KASAN_GENERIC */
> +static inline void kasan_record_aux_stack(void *ptr) {}
> +#endif /* CONFIG_KASAN_GENERIC */
>  
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_SLAB_QUARANTINE)
> +void kasan_cache_shrink(struct kmem_cache *cache);
> +void kasan_cache_shutdown(struct kmem_cache *cache);
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_SLAB_QUARANTINE */
>  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> -static inline void kasan_record_aux_stack(void *ptr) {}
> -
> -#endif /* CONFIG_KASAN_GENERIC */
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_SLAB_QUARANTINE */

In doing this extraction, I wonder if function naming should be changed?
If it's going to live a new life outside of KASAN proper, maybe call
these functions quarantine_cache_*()? But perhaps that's too much
churn...

>  #ifdef CONFIG_KASAN_SW_TAGS
>  
> diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
> index 9eb430c163c2..fc7548f27512 100644
> --- a/include/linux/slab_def.h
> +++ b/include/linux/slab_def.h
> @@ -72,7 +72,7 @@ struct kmem_cache {
>  	int obj_offset;
>  #endif /* CONFIG_DEBUG_SLAB */
>  
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN) || defined(CONFIG_SLAB_QUARANTINE)
>  	struct kasan_cache kasan_info;
>  #endif
>  
> diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
> index 1be0ed5befa1..71020cee9fd2 100644
> --- a/include/linux/slub_def.h
> +++ b/include/linux/slub_def.h
> @@ -124,7 +124,7 @@ struct kmem_cache {
>  	unsigned int *random_seq;
>  #endif
>  
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN) || defined(CONFIG_SLAB_QUARANTINE)
>  	struct kasan_cache kasan_info;
>  #endif
>  
> diff --git a/init/Kconfig b/init/Kconfig
> index d6a0b31b13dc..de5aa061762f 100644
> --- a/init/Kconfig
> +++ b/init/Kconfig
> @@ -1931,6 +1931,17 @@ config SLAB_FREELIST_HARDENED
>  	  sanity-checking than others. This option is most effective with
>  	  CONFIG_SLUB.
>  
> +config SLAB_QUARANTINE
> +	bool "Enable slab freelist quarantine"
> +	depends on !KASAN && (SLAB || SLUB)
> +	help
> +	  Enable slab freelist quarantine to break heap spraying technique
> +	  used for exploiting use-after-free vulnerabilities in the kernel
> +	  code. If this feature is enabled, freed allocations are stored
> +	  in the quarantine and can't be instantly reallocated and
> +	  overwritten by the exploit performing heap spraying.
> +	  This feature is a part of KASAN functionality.
> +

To make this available to distros, I think this needs to be more than
just a CONFIG. I'd love to see this CONFIG control the availability, but
have a boot param control a ro-after-init static branch for these
functions (like is done for init_on_alloc, hardened usercopy, etc). Then
the branch can be off by default for regular distro users, and more
cautious folks could enable it with a boot param without having to roll
their own kernels.

> [...]
> +struct kasan_track {
> +	u32 pid;

pid_t?

> +	depot_stack_handle_t stack;
> +};
> [...]
> +#if defined(CONFIG_KASAN_GENERIC) && \
> +	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB)) || \
> +	defined(CONFIG_SLAB_QUARANTINE)

This seems a bit messy. Perhaps an invisible CONFIG to do this logic and
then the files can test for that? CONFIG_USE_SLAB_QUARANTINE or
something?

> [...]
> + * Heap spraying is an exploitation technique that aims to put controlled
> + * bytes at a predetermined memory location on the heap. Heap spraying for
> + * exploiting use-after-free in the Linux kernel relies on the fact that on
> + * kmalloc(), the slab allocator returns the address of the memory that was
> + * recently freed. Allocating a kernel object with the same size and
> + * controlled contents allows overwriting the vulnerable freed object.
> + *
> + * If freed allocations are stored in the quarantine, they can't be
> + * instantly reallocated and overwritten by the exploit performing
> + * heap spraying.

I would clarify this with the details of what is actually happening: the
allocation isn't _moved_ to a quarantine, yes? It's only marked as not
available for allocation?

> + */
> +
> +#include <linux/kasan.h>
> +#include <linux/bug.h>
> +#include <linux/slab.h>
> +#include <linux/mm.h>
> +#include "../slab.h"
> +#include "kasan.h"
> +
> +void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> +			slab_flags_t *flags)
> +{
> +	cache->kasan_info.alloc_meta_offset = 0;
> +
> +	if (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> +	     cache->object_size < sizeof(struct kasan_free_meta)) {
> +		cache->kasan_info.free_meta_offset = *size;
> +		*size += sizeof(struct kasan_free_meta);
> +		BUG_ON(*size > KMALLOC_MAX_SIZE);

Please don't use BUG_ON()[1].

Interesting!

-Kees

[1] https://www.kernel.org/doc/html/latest/process/deprecated.html#bug-and-bug-on

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202008150939.A994680%40keescook.
