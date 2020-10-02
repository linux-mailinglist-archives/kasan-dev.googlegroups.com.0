Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBWMT3P5QKGQEK6RTSOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0992E280D81
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 08:34:02 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 63sf222767edy.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 23:34:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601620441; cv=pass;
        d=google.com; s=arc-20160816;
        b=W11EL1MEHQVxNOV0/RcxVYyDnReWffnNyQpSIHGv/FpaHIj7Fo6E4Ism83IKhlD9aI
         2EeX+kOJKdJk1JhNFklB+1B7/BB6Y51PyWTCLVioiQVkN2aSqIbaCgU1kJSDTDwmDybv
         n+itsTDtDgNEqBjS6JtelGzV8SvU5vIlQ0uP97SrL3D5mNBzKkRfYNRLVM9Db1tg1zl7
         dliQJukdRFy/vPHBFEjbj0JfscO9u01Mtzua6P5Jk/wg2Z4GzJIggiDYOjIWuttX6SXV
         ljgBw57A0Ru5+xGqlwZlnVHskJ5TnEc/euKgYSrHTalOyqOzvamPDn6iWYQn0+BLQ85Y
         2ZXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pqrnytTXes4RSDFiEhHsdx7Gqxfx6c92NeAgwDa90c8=;
        b=Uhq9L+2hMvSSZFNYBGI4Ku05+KedeVCWKbqBeA7Fcdle2Bsqg4Dg3NDACn6/O5xhfw
         +MNQmv4OTDr4M+uRCSss4Qct+iojb5SCovDtc5Neb7hmWbFwpYmHqjM8IjaSSeBujUYN
         9wtfPtfb7Gd3GFQj7v7MraEHssgDEw2ESasYjzQl7B04400zHTR9MI8AqWh0zkFOvsxq
         wH9hfFnOZQE5CSjt95IhWk6VQAaM8F/k7eibt39XOSWQj7tnCpyY2kkImWhVQgGf2AG5
         1J+qFIJVGlZKh/fYFEOdy5km2213kXRVXqh4Y3Bjy6IQfnvQ6X09q0dHjMHDTq4PO/zR
         F+Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W4cmDp1w;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pqrnytTXes4RSDFiEhHsdx7Gqxfx6c92NeAgwDa90c8=;
        b=oQUl4IhSVYA0hD2O6g9YoV8MJfgf1hD9249aFalZnRCfKD8wgZtKQ1rTpMSxJKSRyj
         ZSYjyRbiOHsl8egWiGFElNSabpGeC/fCbJxv4DWG6Te7STYq5U3fDU3IK+tfPK/6rUNf
         ejwLrXMFGltho6PCs5wwOA8R6n2bqM7RTi/GxUp+7aYQRrYn3trlYnmzBeJ0mHYcUPgf
         9AMzdVCS4S69PnO/NE433CmtDUXylfJYyD1NvEvPp/YL77+8ygfBOKLOmVd7fUZm9CIq
         tzRNmDOeFNHlwG9d9Q7KDVI5H+c634szQqk04B3hm/nnvZjTFQB1PZ61pJSkp8k7YWTB
         i11A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pqrnytTXes4RSDFiEhHsdx7Gqxfx6c92NeAgwDa90c8=;
        b=gaXNmFcYB9RVz0tpt9A3kuwRN3JRP5jkG53Ixka8x8tNBb72dADaVNlX8/23oCb+5L
         F7noEyekmzQ4/odOv8KFne3kqsNkfyMlSIFxIhy3HawP6/cfrVxRIOF2/nCuQC7S3poY
         PgFj/WQFCq+XXMC08jfFxwLyqru3R2irGlEp94p3Tiifhohci/3ibdgoYIwBUIO6395U
         tqhpoafEpnzYwn6YspfxNLfRDrh+UWdGj8UCpQP/QvU1gbkCcEld2a7+8msTv7FpBoAO
         DHOj3+eBmBeBs4+BeWmFeBYhnvH9EwBRLFEkdOzn6qoDqkFCVzvMMv/KD1YWoOURgrfx
         dmiw==
X-Gm-Message-State: AOAM531qFbDttwesq6Qaste/OiAT1Omd/wltRMugoAPgPiAzHGKrFTjU
	2PoMTpgE8xhBqsZmrPJihKs=
X-Google-Smtp-Source: ABdhPJwzrzLziAvzOEGMmd3RB+hobijY5eyiXuCo2Jv8umIClFbv+f1SYqCFkBrLHoaYXQ2R6YqMvg==
X-Received: by 2002:a17:907:72c2:: with SMTP id du2mr756582ejc.512.1601620441639;
        Thu, 01 Oct 2020 23:34:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c545:: with SMTP id s5ls699747edr.3.gmail; Thu, 01 Oct
 2020 23:34:00 -0700 (PDT)
X-Received: by 2002:aa7:d6ce:: with SMTP id x14mr742151edr.359.1601620440660;
        Thu, 01 Oct 2020 23:34:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601620440; cv=none;
        d=google.com; s=arc-20160816;
        b=kdMJEjWxfVZFD9ry8BptWXnoFiTVTXQKqMXA+4LJHCmNDDBBGQQMpvNmKAYgvW18qa
         8/eAQ+D9dbR46ax0T1+XOWfdMbGiZiHJmjK/6NUwSNG3zmGwi6KLgQGq+eTdCEIP4FOw
         cQtYQIJFraWX73iLlV7OzI7lmWdNoXPJdYRJcGunEmYzgmuVg6Mz4/wTYloky++w4yno
         C9/Oui9rQnrn8A7LMMp97/Jw4y74MuAwe6wqsQ9CJ6aKLKmYNKGAif3JkP5LkweMu0CX
         ioMRfQAcsm4IssRSeJy4FPpHpvPe4ynR6Tl1qAw9jnBQFYkLCboIYm2gNZ+yMgfFXBzE
         8C2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7BDuU6sXeGKigaXtfOae0G/hnHiDrPaHNVHyy0KSsRs=;
        b=bySf87iQjGIoTSz15YkjG9S6aW0QZPYgDGgX8JvEnqGu99hyMhrMhLbDyEAqFw+g9i
         wW9I9rjhQXYrSOZ6/ojmiha5Yk3Zy2cN0R3JrqPOxAuFEMIAjikSrmK9u/oKVNOKKlcY
         uPrk2c1VLaclBfxKZBKiZtDCxhZQq6mwCTpuGD7gWkggacDcxzqgojapYZ7RhJKMJN0s
         zCZt4cZJu+SvbUhYYyAjljU7Kk1SQeIeweYdO+FkVzIOudHBULLL2XtEDlt9r8TAXX5L
         DkhVs2SIrYUKEPBOcs59avUstIsr73NthaqpDaoyzxUl7qjyzt/as3x1GzxxURW09HRZ
         r5Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W4cmDp1w;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x543.google.com (mail-ed1-x543.google.com. [2a00:1450:4864:20::543])
        by gmr-mx.google.com with ESMTPS id r17si14378edc.4.2020.10.01.23.34.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 23:34:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) client-ip=2a00:1450:4864:20::543;
Received: by mail-ed1-x543.google.com with SMTP id l17so503611edq.12
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 23:34:00 -0700 (PDT)
X-Received: by 2002:a05:6402:cba:: with SMTP id cn26mr758061edb.230.1601620439936;
 Thu, 01 Oct 2020 23:33:59 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
In-Reply-To: <20200929133814.2834621-2-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 08:33:33 +0200
Message-ID: <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, linux-doc@vger.kernel.org, 
	kernel list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W4cmDp1w;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.
>
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. The main motivation behind KFENCE's design, is that with
> enough total uptime KFENCE will detect bugs in code paths not typically
> exercised by non-production test workloads. One way to quickly achieve a
> large enough total uptime is when the tool is deployed across a large
> fleet of machines.
>
> KFENCE objects each reside on a dedicated page, at either the left or
> right page boundaries.

(modulo slab alignment)

> The pages to the left and right of the object
> page are "guard pages", whose attributes are changed to a protected
> state, and cause page faults on any attempted access to them. Such page
> faults are then intercepted by KFENCE, which handles the fault
> gracefully by reporting a memory access error. To detect out-of-bounds
> writes to memory within the object's page itself, KFENCE also uses
> pattern-based redzones. The following figure illustrates the page
> layout:
[...]
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
[...]
> +/**
> + * is_kfence_address() - check if an address belongs to KFENCE pool
> + * @addr: address to check
> + *
> + * Return: true or false depending on whether the address is within the KFENCE
> + * object range.
> + *
> + * KFENCE objects live in a separate page range and are not to be intermixed
> + * with regular heap objects (e.g. KFENCE objects must never be added to the
> + * allocator freelists). Failing to do so may and will result in heap
> + * corruptions, therefore is_kfence_address() must be used to check whether
> + * an object requires specific handling.
> + */
> +static __always_inline bool is_kfence_address(const void *addr)
> +{
> +       return unlikely((char *)addr >= __kfence_pool &&
> +                       (char *)addr < __kfence_pool + KFENCE_POOL_SIZE);
> +}

If !CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL, this should probably always
return false if __kfence_pool is NULL, right?

[...]
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
[...]
> +menuconfig KFENCE
> +       bool "KFENCE: low-overhead sampling-based memory safety error detector"
> +       depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
> +       depends on JUMP_LABEL # To ensure performance, require jump labels
> +       select STACKTRACE
> +       help
> +         KFENCE is low-overhead sampling-based detector for heap out-of-bounds

nit: "is a"

> +         access, use-after-free, and invalid-free errors. KFENCE is designed
> +         to have negligible cost to permit enabling it in production
> +         environments.
[...]
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
[...]
> +module_param_named(sample_interval, kfence_sample_interval, ulong, 0600);

This is a writable module parameter, but if the sample interval was 0
or a very large value, changing this value at runtime won't actually
change the effective interval because the work item will never get
kicked off again, right?

Should this maybe use module_param_cb() instead, with a "set" callback
that not only changes the value, but also schedules the work item?

[...]
> +/*
> + * The pool of pages used for guard pages and objects. If supported, allocated
> + * statically, so that is_kfence_address() avoids a pointer load, and simply
> + * compares against a constant address. Assume that if KFENCE is compiled into
> + * the kernel, it is usually enabled, and the space is to be allocated one way
> + * or another.
> + */

If this actually brings a performance win, the proper way to do this
would probably be to implement this as generic kernel infrastructure
that makes the compiler emit large-offset relocations (either through
compiler support or using inline asm statements that move an immediate
into a register output and register the location in a special section,
kinda like how e.g. static keys work) and patches them at boot time,
or something like that - there are other places in the kernel where
very hot code uses global pointers that are only ever written once
during boot, e.g. the dentry cache of the VFS and the futex hash
table. Those are probably far hotter than the kfence code.

While I understand that that goes beyond the scope of this project, it
might be something to work on going forward - this kind of
special-case logic that turns the kernel data section into heap memory
would not be needed if we had that kind of infrastructure.

> +#ifdef CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL
> +char __kfence_pool[KFENCE_POOL_SIZE] __kfence_pool_attrs;
> +#else
> +char *__kfence_pool __read_mostly;

not __ro_after_init ?

> +#endif
[...]
> +/* Freelist with available objects. */
> +static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
> +static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
[...]
> +/* Gates the allocation, ensuring only one succeeds in a given period. */
> +static atomic_t allocation_gate = ATOMIC_INIT(1);

I don't think you need to initialize this to anything?
toggle_allocation_gate() will set it to zero before enabling the
static key, so I don't think anyone will ever see this value.

[...]
> +/* Check canary byte at @addr. */
> +static inline bool check_canary_byte(u8 *addr)
> +{
> +       if (*addr == KFENCE_CANARY_PATTERN(addr))

You could maybe add a likely() hint here if you want.

> +               return true;
> +
> +       atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
> +       kfence_report_error((unsigned long)addr, addr_to_metadata((unsigned long)addr),
> +                           KFENCE_ERROR_CORRUPTION);
> +       return false;
> +}
> +
> +static inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))

Given how horrendously slow this would be if the compiler decided to
disregard the "inline" hint and did an indirect call for every byte,
you may want to use __always_inline here.

> +{
> +       unsigned long addr;
> +
> +       lockdep_assert_held(&meta->lock);
> +
> +       for (addr = ALIGN_DOWN(meta->addr, PAGE_SIZE); addr < meta->addr; addr++) {
> +               if (!fn((u8 *)addr))
> +                       break;
> +       }
> +
> +       for (addr = meta->addr + meta->size; addr < PAGE_ALIGN(meta->addr); addr++) {

Hmm... if the object is on the left side (meaning meta->addr is
page-aligned) and the padding is on the right side, won't
PAGE_ALIGN(meta->addr)==meta->addr , and therefore none of the padding
will be checked?

> +               if (!fn((u8 *)addr))
> +                       break;
> +       }
> +}
> +
> +static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> +{
> +       struct kfence_metadata *meta = NULL;
> +       unsigned long flags;
> +       void *addr;
> +
> +       /* Try to obtain a free object. */
> +       raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> +       if (!list_empty(&kfence_freelist)) {
> +               meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
> +               list_del_init(&meta->list);
> +       }
> +       raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> +       if (!meta)
> +               return NULL;

Should this use pr_warn_once(), or something like that, to inform the
user that kfence might be stuck with all allocations used by
long-living objects and therefore no longer doing anything?

[...]
> +}
[...]
> +/* === Allocation Gate Timer ================================================ */
> +
> +/*
> + * Set up delayed work, which will enable and disable the static key. We need to
> + * use a work queue (rather than a simple timer), since enabling and disabling a
> + * static key cannot be done from an interrupt.
> + */
> +static struct delayed_work kfence_timer;
> +static void toggle_allocation_gate(struct work_struct *work)
> +{
> +       if (!READ_ONCE(kfence_enabled))
> +               return;
> +
> +       /* Enable static key, and await allocation to happen. */
> +       atomic_set(&allocation_gate, 0);
> +       static_branch_enable(&kfence_allocation_key);
> +       wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);
> +
> +       /* Disable static key and reset timer. */
> +       static_branch_disable(&kfence_allocation_key);
> +       schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_interval));

We end up doing two IPIs to all CPU cores for each kfence allocation
because of those static branch calls, right? Might be worth adding a
comment to point that out, or something like that. (And if it ends up
being a problem in the future, we could probably get away with using
some variant that avoids the IPI, but flushes the instruction pipeline
if we observe the allocation_gate being nonzero, or something like
that. At the cost of not immediately capturing new allocations if the
relevant instructions are cached. But the current version is
definitely fine for an initial implementation, and for now, you should
probably *not* implement what I just described.)

> +}
> +static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
> +
> +/* === Public interface ===================================================== */
> +
> +void __init kfence_init(void)
> +{
> +       /* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
> +       if (!kfence_sample_interval)
> +               return;
> +
> +       if (!kfence_initialize_pool()) {
> +               pr_err("%s failed\n", __func__);
> +               return;
> +       }
> +
> +       WRITE_ONCE(kfence_enabled, true);
> +       schedule_delayed_work(&kfence_timer, 0);

This is schedule_work(&kfence_timer).

[...]
> +}
[...]
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
[...]
> +/* KFENCE metadata per guarded allocation. */
> +struct kfence_metadata {
[...]
> +       /*
> +        * In case of an invalid access, the page that was unprotected; we
> +        * optimistically only store address.

Is this supposed to say something like "only store one address"?

> +        */
> +       unsigned long unprotected_page;
> +};
[...]
> +#endif /* MM_KFENCE_KFENCE_H */
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
[...]
> +void kfence_report_error(unsigned long address, const struct kfence_metadata *meta,
> +                        enum kfence_error_type type)
> +{
[...]
> +       pr_err("==================================================================\n");
> +       /* Print report header. */
> +       switch (type) {
[...]
> +       case KFENCE_ERROR_INVALID_FREE:
> +               pr_err("BUG: KFENCE: invalid free in %pS\n\n", (void *)stack_entries[skipnr]);
> +               pr_err("Invalid free of 0x" PTR_FMT " (in kfence-#%zd):\n", (void *)address,
> +                      object_index);
> +               break;
> +       }
> +
> +       /* Print stack trace and object info. */
> +       stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);
> +
> +       if (meta) {
> +               pr_err("\n");
> +               kfence_print_object(NULL, meta);
> +       }
> +
> +       /* Print report footer. */
> +       pr_err("\n");
> +       dump_stack_print_info(KERN_DEFAULT);

Shouldn't this be KERN_ERR, to keep the loglevel consistent with the
previous messages?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3%2B_K6YXoXgKBkB8AMeSQj%2B%2BMxi5u2OT--B%2BmJgE7Cyfg%40mail.gmail.com.
