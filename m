Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ5H7OFAMGQEJTQPRYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id D34EE42519E
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 13:01:59 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id s18-20020adfbc12000000b00160b2d4d5ebsf4403338wrg.7
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 04:01:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633604519; cv=pass;
        d=google.com; s=arc-20160816;
        b=Byzt7aFiZRe/0BPoieKt0PtKMQXdugYDY0BQ0BzdHicNXMB9dImxhWURKpzRL0ukpG
         yZk7SY/wNlD4nMGjr0O519GzXXJnfdydJjb5f9Wxzjx+GtlHJyQd7bwd88Dg5RS71PbE
         dW0irpwlJGyDKWWEHg9eSGVQH0+fKl3mKy6s0jBGUwrM3oOmeHoXfa8Ej3HgcwrGGYTe
         fGe8OSwTn9OAAF1pXB1omDLkbHqVqeGtR/40AGmEVnpEtx6EVUzQSDW3QnkA/UbE0g0N
         a2N01sVGvXW2WJ8sgu841poL6BH2yzN1Ni7Gsrbfp727uAsRyUo92eHXQh9vaUqGBEdy
         zeRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=soveyNa1wFSuJfHohnVrEeQAUBqcR2sMuq5q8seBwZA=;
        b=JZyFKVnoLwU4iEHZWTFc0RJmydQm2ElN1yh+DVkvZkRt3gg0IyE8Welc/aQgdclvGB
         yRlm2GzAxR8+dcGpA3JANgddC6TJ/r+lHfN8SAh8iT6VHnHkDOpflNAPxmM6Ic4MZIye
         5Qdl8lz1oyo/DlwK0RFZGD3DqAG9iMa1gsn0oy8nb030BeOhUDBmOPYDTAakasvlpab1
         t4SZr6Jbu5dhmi/52I13USOkdnEaz37tn7J//zja7eLe6PCqbd4PCBS7Bvy2E2IkBB8B
         J+c0T3FVSLhP35OFHvL3liczLth2pUEZSee4owSC99XOP+Hk/nvmKmrO5woEpf8OHzVI
         qOlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M7iUMKBa;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=soveyNa1wFSuJfHohnVrEeQAUBqcR2sMuq5q8seBwZA=;
        b=ecUz/aqJKHnyULlNmCilMPPRSlScav/xv5JQeZERdeBykNsYk0Njai61uguiiw8Gb2
         wPCI7RWzecjhxgH79z4Vg3QJ5w7pRZ/ZRoQhiOqYdTmtfuFvVWseSXEDjSMsCE8zNOHv
         7NMgOcM73lG+wM1RerKA8nUN1Ru2Cdc5u2cWbbE9lF8ACZn2NpdQxlzLLBNEUBzfvOiq
         oi7//IEtv3c9G+Dvk5ViN1ZkogJzJq69Lx9cC10SrE0CjcdgXXgFDrR/wTPBRq2LHbwd
         0HcGhSw6PB8v4QfwADR480OTZ5sJf2GoCVsgEp3XcZdRxfqzpCAw5Ve5C3hFGina5u+y
         zTSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=soveyNa1wFSuJfHohnVrEeQAUBqcR2sMuq5q8seBwZA=;
        b=Dos12vvrxqBRTHKUgNoeMweGToHK0Poia6O5WGVePQhtzYi9lqMygfOSuT52fg2Jze
         FqmKkmG/3c2QAZz2x1as3zFBIpRVozb48GfLvhtJS//RY6slVnZ8Wet373reFjQT+Xxh
         HSY79WUnQYHW50Y8TnCYbY8Km6x1lTCDvVX3oE0KtZZ70hs3XfFuj7cYa7TgibwC4PRn
         d/sLbjowqfCe8yw1+1iQIUU+e2mR0Fw6DrUhFynacyI4kM35m3AofIT6QXH6yy6nqn56
         WVMWr1kqQXQyspa4y9we8kkPqzjLOcymkgviNM02si1t+1+kFRVHgk30VnNjgZawpA06
         SIAQ==
X-Gm-Message-State: AOAM530gqdTfpPEGEef+F6FAjmAjZmf/1TkTynLv9iCRDwKX3dz1WOEZ
	fFTvvlzbuGBFaOAiD23iOqI=
X-Google-Smtp-Source: ABdhPJyQ0PFqiJSyLW0FM/Lh7C1UM5rT3xupc92fo3Im3mLZwHX0MNQIg/enY7jxtrdK89A2eh7n/A==
X-Received: by 2002:a7b:c001:: with SMTP id c1mr3841377wmb.182.1633604519521;
        Thu, 07 Oct 2021 04:01:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:364f:: with SMTP id y15ls1551287wmq.3.gmail; Thu,
 07 Oct 2021 04:01:58 -0700 (PDT)
X-Received: by 2002:a7b:ca58:: with SMTP id m24mr15922224wml.0.1633604518514;
        Thu, 07 Oct 2021 04:01:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633604518; cv=none;
        d=google.com; s=arc-20160816;
        b=J9acgqkrW1+b1EXx76tBpRr5n1j+RI9aBlygxXVawkMvSkEODvzO57TXVuBDDpY/i3
         r3JTuJzdQRTLU0bQh+ngHdxHEQwGUKdsOnX8PUDjdw0K0v1mb6n+HHK1WR+bo/+ktTVa
         k86bxjKyJ9Jf/bISJ9ouxyk6NblSPjmAYjksMU98JPNKFSfiJS9q6/aAPGPuiL/7ulCh
         3UXk+uuNh9ILC0DZTc+xtH8O6MkvUrudDn7+ALGhUZVe80QVkc3b4tAv7Rf+WMSJphSz
         S/K+9BFJEVJNGIkIqYEHrw6AdGxlWkfK4i1sXumGGZOjYyddy/KidZfwZapNO0toYEoW
         8u6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NJgOSqoCCgXqOknLz7AdQYpr89OwA0jzXUySVyR80Xs=;
        b=jAbN53F3qpFCYHnLTWdpd1OUAOeMXyDRNmGDxkSuEVKzaUFvYItyQNM4ADjnrLGT6M
         hkTK4u8BJq+Edi92GZaUpZZIa5Tcoy84BHSFzyos63qJW4X5poW7JZu76EuUFEp8utLZ
         CoUav2YcXuJTem7mWq3/cm/carezoau0zJn/+iwaGGZMF/wFaUFupXGm3OATeNP8586t
         HsNfg+4P4F4pGqzjhb+vKA6Orfws4TNO4/1/b9wh8YR9aXx+jtQw/DMWenS04BcWM4qz
         RPg8xUIAyBNpRSANoXBsb4mWX+FMLLVmW5xS3pxH5XjRGs43xVjkw+tLlIlYDJBehGIV
         Hibw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M7iUMKBa;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id b72si209478wmd.1.2021.10.07.04.01.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 04:01:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id e12so17817829wra.4
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 04:01:58 -0700 (PDT)
X-Received: by 2002:a7b:c5d8:: with SMTP id n24mr3990455wmk.51.1633604517859;
        Thu, 07 Oct 2021 04:01:57 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:aedf:c006:6996:1a79])
        by smtp.gmail.com with ESMTPSA id c185sm8441412wma.8.2021.10.07.04.01.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Oct 2021 04:01:56 -0700 (PDT)
Date: Thu, 7 Oct 2021 13:01:51 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Oliver Glitta <glittao@gmail.com>,
	Imran Khan <imran.f.khan@oracle.com>
Subject: Re: [PATCH] lib/stackdepot: allow optional init and stack_table
 allocation by kvmalloc()
Message-ID: <YV7TnygBLdHJjmRW@elver.google.com>
References: <20211007095815.3563-1-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211007095815.3563-1-vbabka@suse.cz>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=M7iUMKBa;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
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

On Thu, Oct 07, 2021 at 11:58AM +0200, Vlastimil Babka wrote:
[...] 
> - Add a CONFIG_STACKDEPOT_ALWAYS_INIT flag to keep using the current
>   well-defined point of allocation as part of mem_init(). Make CONFIG_KASAN
>   select this flag.
> - Other users have to call stack_depot_init() as part of their own init when
>   it's determined that stack depot will actually be used. This may depend on
>   both config and runtime conditions. Convert current users which are
>   page_owner and several in the DRM subsystem. Same will be done for SLUB
>   later.
> - Because the init might now be called after the boot-time memblock allocation
>   has given all memory to the buddy allocator, change stack_depot_init() to
>   allocate stack_table with kvmalloc() when memblock is no longer available.
>   Also handle allocation failure by disabling stackdepot (could have
>   theoretically happened even with memblock allocation previously), and don't
>   unnecessarily align the memblock allocation to its own size anymore.
...
> Hi, I'd appreciate review of the DRM parts - namely that I've got correctly
> that stack_depot_init() is called from the proper init functions and iff
> stack_depot_save() is going to be used later. Thanks!

For ease of review between stackdepot and DRM changes, I thought it'd be
nice to split into 2 patches, but not sure it'll work, because you're
changing the semantics of the normal STACKDEPOT.

One option would be to flip it around, and instead have
STACKDEPOT_LAZY_INIT, but that seems counter-intuitive if the majority
of STACKDEPOT users are LAZY_INIT users.

On the other hand, the lazy initialization mode you're introducing
requires an explicit stack_depot_init() call somewhere and isn't as
straightforward as before.

Not sure what is best. My intuition tells me STACKDEPOT_LAZY_INIT would
be safer as it's a deliberate opt-in to the lazy initialization
behaviour.

Preferences?

[...]
> --- a/drivers/gpu/drm/drm_mm.c
> +++ b/drivers/gpu/drm/drm_mm.c
> @@ -980,6 +980,10 @@ void drm_mm_init(struct drm_mm *mm, u64 start, u64 size)
>  	add_hole(&mm->head_node);
>  
>  	mm->scan_active = 0;
> +
> +#ifdef CONFIG_DRM_DEBUG_MM
> +	stack_depot_init();
> +#endif

DRM_DEBUG_MM implies STACKDEPOT. Not sure what is more readable to drm
maintainers, but perhaps it'd be nicer to avoid the #ifdef here, and
instead just keep the no-op version of stack_depot_init() in
<linux/stackdepot.h>. I don't have a strong preference.

>  }
>  EXPORT_SYMBOL(drm_mm_init);
>  
> diff --git a/drivers/gpu/drm/i915/intel_runtime_pm.c b/drivers/gpu/drm/i915/intel_runtime_pm.c
> index 0d85f3c5c526..806c32ab410b 100644
> --- a/drivers/gpu/drm/i915/intel_runtime_pm.c
> +++ b/drivers/gpu/drm/i915/intel_runtime_pm.c
> @@ -68,6 +68,9 @@ static noinline depot_stack_handle_t __save_depot_stack(void)
>  static void init_intel_runtime_pm_wakeref(struct intel_runtime_pm *rpm)
>  {
>  	spin_lock_init(&rpm->debug.lock);
> +
> +	if (rpm->available)
> +		stack_depot_init();
>  }
>  
>  static noinline depot_stack_handle_t
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index c34b55a6e554..60ba99a43745 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -15,6 +15,16 @@
>  
>  typedef u32 depot_stack_handle_t;
>  
> +/*
> + * Every user of stack depot has to call this during its own init when it's
> + * decided that it will be calling stack_depot_save() later.
> + *
> + * The alternative is to select STACKDEPOT_ALWAYS_INIT to have stack depot
> + * enabled as part of mm_init(), for subsystems where it's known at compile time
> + * that stack depot will be used.
> + */
> +int stack_depot_init(void);
> +
>  depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  					unsigned int nr_entries,
>  					gfp_t gfp_flags, bool can_alloc);
> @@ -30,13 +40,4 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
>  
>  void stack_depot_print(depot_stack_handle_t stack);
>  
> -#ifdef CONFIG_STACKDEPOT
> -int stack_depot_init(void);
> -#else
> -static inline int stack_depot_init(void)
> -{
> -	return 0;
> -}
> -#endif	/* CONFIG_STACKDEPOT */
> -

Could we avoid the IS_ENABLED() in init/main.c by adding a wrapper here:

+#ifdef CONFIG_STACKDEPOT_ALWAYS_INIT
+static inline int stack_depot_early_init(void)	{ return stack_depot_init(); }
+#else
+static inline int stack_depot_early_init(void)	{ return 0; }
+#endif	/* CONFIG_STACKDEPOT_ALWAYS_INIT */

>  #endif
> diff --git a/init/main.c b/init/main.c
> index ee4d3e1b3eb9..b6a5833d98f5 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -844,7 +844,8 @@ static void __init mm_init(void)
>  	init_mem_debugging_and_hardening();
>  	kfence_alloc_pool();
>  	report_meminit();
> -	stack_depot_init();
> +	if (IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT))
> +		stack_depot_init();

I'd push the decision of when to call this into <linux/stackdepot.h> via
wrapper stack_depot_early_init().

>  	mem_init();
>  	mem_init_print_info();
>  	/* page_owner must be initialized after buddy is ready */
> diff --git a/lib/Kconfig b/lib/Kconfig
> index 5e7165e6a346..df6bcf0a4cc3 100644
> --- a/lib/Kconfig
> +++ b/lib/Kconfig
> @@ -671,6 +671,9 @@ config STACKDEPOT
>  	bool
>  	select STACKTRACE
>  
> +config STACKDEPOT_ALWAYS_INIT
> +	bool

It looks like every users of STACKDEPOT_ALWAYS_INIT will also select
STACKDEPOT, so we could just make this:

+config STACKDEPOT_ALWAYS_INIT
+	bool
+	select STACKDEPOT

And remove the redundant 'select STACKDEPOT' in Kconfig.kasan.

>  config STACK_HASH_ORDER
>  	int "stack depot hash size (12 => 4KB, 20 => 1024KB)"
>  	range 12 20
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cdc842d090db..695deb603c66 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -39,6 +39,7 @@ menuconfig KASAN
>  		   HAVE_ARCH_KASAN_HW_TAGS
>  	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
>  	select STACKDEPOT
> +	select STACKDEPOT_ALWAYS_INIT

[...]
>  
> -int __init stack_depot_init(void)
> +/*
> + * __ref because of memblock_alloc(), which will not be actually called after
> + * the __init code is gone

The reason is that after __init code is gone, slab_is_available() will
be true (might be worth adding to the comment).

> + */
> +__ref int stack_depot_init(void)
>  {
> -	if (!stack_depot_disable) {
> +	mutex_lock(&stack_depot_init_mutex);
> +	if (!stack_depot_disable && stack_table == NULL) {
>  		size_t size = (STACK_HASH_SIZE * sizeof(struct stack_record *));

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YV7TnygBLdHJjmRW%40elver.google.com.
