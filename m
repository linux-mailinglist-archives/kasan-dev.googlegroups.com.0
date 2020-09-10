Return-Path: <kasan-dev+bncBCCMH5WKTMGRBC5E5H5AKGQES5MWD3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 8415F264989
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 18:19:24 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id j4sf2447997ljo.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 09:19:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599754764; cv=pass;
        d=google.com; s=arc-20160816;
        b=yq4e4UEHMlD7Ubzw7GlZ8nHaZHJs1PJNyjjN3S7k7a4sl7y+eUMA/qm6KeEq8szLh3
         3Rw2XanXzGOkpxOHybYlkpM30fBMV7IMCK0EBm0Zgyc/RqHChB5pJ6978sjV6Qt/q3mR
         fmXHPTj0Gm1Oc/1QMd31ioxzZKU+8mlZTeRsjcBTT8PLZ4GhfcMQ7YEobZwIxDTrdMH3
         urwrSZdr9IPUr4W6DPK0u3yjpzqaPO78Q3fY4bjzciabvTqRo06TAJIjAIh9CC7MZz57
         gcJBrAPS5uaKwLl5w1I5f4b41r7yPAU50tAQO1BrMT43IgbA6pPxzYvJytIJsGuNTPe+
         3tsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tbIw+QkXLDJvZj1tMGrr8aol81wruJu/VjLLlAxf41U=;
        b=r+qrnbkyXSfWtkUL+GymkAYehJaBaCZfvzrl4gvNht7600cQncY0stizwbdtQYNinG
         x1HtxNtgs/qnvCQp8RJ9q3z6U3sYgwmLjzMqZMmRdmKHDCzjf5gqQP/J1wP6zGbtD3Ua
         Ae2xSKSX45SgmyxMu63TeRiE8HbYkDrwqxIhxybrJP/5t7squN/VOFjQnqlJThAGcROZ
         t6/LMXddCnyxSnER/5dBtv76BpBmMqbWQ4s0xQeJ0N4aAaxuVmLFX6wjI1qDWqEaaQAX
         Ynyoy2Y/q8NdgPqnkJTNHa7hBcj4N9NaJO7H+aB3MEWpgNj6c0/6nAEnVknSRCB0qvjs
         Pxbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qio5Y/ng";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tbIw+QkXLDJvZj1tMGrr8aol81wruJu/VjLLlAxf41U=;
        b=bsyHwTnRc1ajl8WijXdrWMCf62eM40ik0gtJVOYtkYeBpT+lQAWsNde3b0j6X/cnt+
         9pxI5qJCRb4j5ri7X5ldwdIkZZOo5hGplGonRY7sfYjgvTvoVLA19m97CtOn1ZciBL/v
         MPAfVxhFltbHPfaNzFUIN18YmMSxraC5nefmI2e7Q8fqWAUz/nMQHcSFRmSbzvEpUgrL
         dQ1u6tZRI3EocHkYae5ZXG683PrjNYKp/Gpimpvxkx3kPg33R7hL78J5JknKCvxL3vpZ
         /qnMGCmu7T4R5O7nPpDRDYllzAaNWqa4UmAwoZUJ+c3l8UaYZCf7j7gVYkZGus3zlr/F
         4YnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tbIw+QkXLDJvZj1tMGrr8aol81wruJu/VjLLlAxf41U=;
        b=OQIrsnGvmaFDhQqe/V2pmqpmFTkQqJe/YC6Wa0KhiD8anJpFSl///EPHE59UrnVak6
         u6kmmWNtdlfePNEhY73ULNHdnhec+G+RgThH2avn4sK8O9Og9cUZ+SML4gES7RRrp9wL
         JM61MRX9ap99eEw+R47RcwKypDuT/sAUaLOhu2pNu5w6a9FniP6iDP6fcp+VXIqJbhsG
         X+C9L0nNkhTyqg0jIIPyAnb1+PPE+M4lV0dsE+ndVrmWNnhTJc462429mIZjVdejNqT8
         Mm4m6TkkUpK5+ruuJMoHdvYRM9VUEGTHz8M9229fMZ1RL16KMywWAZdSvxCcvn3/fC9E
         hVPA==
X-Gm-Message-State: AOAM533tWmRDirg39exjjmlnJGy3EzX7hkV95QLy9nzwTVuhqBhi41Zv
	s/Drz4N8A+Ao/id6YYUS4go=
X-Google-Smtp-Source: ABdhPJwhvM0QbvK/U6qH3mCu14jI21PInjwjBaCcqWAOLpC7h0skPLzOub6IxlhELfxJgBzKhLqVfw==
X-Received: by 2002:a05:651c:c5:: with SMTP id 5mr5058623ljr.211.1599754764031;
        Thu, 10 Sep 2020 09:19:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls1256336lfn.2.gmail; Thu, 10 Sep
 2020 09:19:23 -0700 (PDT)
X-Received: by 2002:a19:8789:: with SMTP id j131mr4737730lfd.90.1599754762876;
        Thu, 10 Sep 2020 09:19:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599754762; cv=none;
        d=google.com; s=arc-20160816;
        b=q8PJNfeeFZ6g4U1EtgNNyjCw+mHSd1k1e1Vv3Mmoi4POFOfL+qY4WuaiLiI7AhyBY0
         rpDvHGoFud7wduBmxOLj7lUFrOX5scOrajIIIKYJo1nkvSeQqqtWSKLX+MgGCnzUZ01r
         MfW4+kntdgI8Widd+jEhq8qXszDBRq87HveeXhnhO5UK8buFwX1HrgXTy3HuBsUx/X1i
         nM0owTlE4kHjIsllylCeTqnmXP921UPYjsjesOfzErcBkQbb5TuQhHN1IAUJwA1PjgJF
         1vVkw833Ur5bmwRODOeQwQSYB82PJoscGZa3bl4ajCXL1SC+ssNjz4por+LguknYlYak
         MEdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FMPZ+VzJ+cGDOwRKaJNQBA78kSsKgAl4Rh0tiwYlTzE=;
        b=FjvOvEIFaXHhODXqQuvsAatRlitEgYYqbxETrfqhoFe0u4mK9xNwM0pnTETqkmUxMo
         xjK63XcOY0fJYoMb69M+nU3H02pS+8e+4kI5iugDHOMH7vEa+2PrhqMGyCmZ5/ry5VHJ
         VHplBeu2VVsCjItVMEqP56CrmYJ0gratjXOb1i4iBT9PgE8l9irkM0WVGRF0qwPOQZ5A
         0Go8osAkWHhKAwGqkbDVtWEjozDXJ/VSQ0AA5qfJTnzeveCa1ovheO31CVRzoGoV3NAy
         PMQqEc/cRyIcywW/tAGhqhIZVEDHyoiZCeUocsIJOa44X5AIsnI8K1u2v1jGyf+VmP2l
         mL7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qio5Y/ng";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id q20si211963lji.2.2020.09.10.09.19.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 09:19:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id z9so669829wmk.1
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 09:19:22 -0700 (PDT)
X-Received: by 2002:a7b:cd93:: with SMTP id y19mr760920wmj.112.1599754762218;
 Thu, 10 Sep 2020 09:19:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-2-elver@google.com>
 <CACT4Y+bfp2ch2KbSMkUd3142aA4p2CiMOmdXrr0-muu6bQ5xXg@mail.gmail.com>
In-Reply-To: <CACT4Y+bfp2ch2KbSMkUd3142aA4p2CiMOmdXrr0-muu6bQ5xXg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 18:19:10 +0200
Message-ID: <CAG_fn=W4es7jaTotDORt2SwspE4A804mdwAY1j4gcaSEKtRjiw@mail.gmail.com>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
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
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="qio5Y/ng";       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Sep 10, 2020 at 5:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:


> > +       /* Calculate address for this allocation. */
> > +       if (right)
> > +               meta->addr += PAGE_SIZE - size;
> > +       meta->addr = ALIGN_DOWN(meta->addr, cache->align);
>
> I would move this ALIGN_DOWN under the (right) if.
> Do I understand it correctly that it will work, but we expect it to do
> nothing for !right? If cache align is >PAGE_SIZE, nothing good will
> happen anyway, right?
> The previous 2 lines look like part of the same calculation -- "figure
> out the addr for the right case".

Yes, makes sense.

> > +
> > +       schedule_delayed_work(&kfence_timer, 0);
> > +       WRITE_ONCE(kfence_enabled, true);
>
> Can toggle_allocation_gate run before we set kfence_enabled? If yes,
> it can break. If not, it's still somewhat confusing.

Correct, it should go after we enable KFENCE. We'll fix that in v2.

> > +void __kfence_free(void *addr)
> > +{
> > +       struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> > +
> > +       if (unlikely(meta->cache->flags & SLAB_TYPESAFE_BY_RCU))
>
> This may deserve a comment as to why we apply rcu on object level
> whereas SLAB_TYPESAFE_BY_RCU means slab level only.

Sorry, what do you mean by "slab level"?
SLAB_TYPESAFE_BY_RCU means we have to wait for possible RCU accesses
in flight before freeing objects from that slab - that's basically
what we are doing here below:

> > +               call_rcu(&meta->rcu_head, rcu_guarded_free);
> > +       else
> > +               kfence_guarded_free(addr, meta);
> > +}


> > +void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *meta)
> > +{
> > +       const int size = abs(meta->size);
>
> This negative encoding is somewhat confusing. We do lots of abs, but
> do we even look at the sign anywhere? I can't find any use that is not
> abs.

I think initially there was a reason for this, but now we don't seem
to use it anywhere. Nice catch!

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW4es7jaTotDORt2SwspE4A804mdwAY1j4gcaSEKtRjiw%40mail.gmail.com.
