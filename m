Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBOFD3P5QKGQE6XWEQLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1260C280DE0
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 09:07:37 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id y9sf206382lfe.17
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 00:07:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601622456; cv=pass;
        d=google.com; s=arc-20160816;
        b=bpe9Qd0q+9p6NTbObAdVARI7J1lcehXrp39K+GNhUEL6s+OQsM1nbmysNoDlbTlEXQ
         cIdTC5k2lCRh5FUrDSoGfDsbZCBCEZEIs9oCow9Q7KLszxCwt9Olw2qDcWPBPsz4xaq9
         aPITBMpmtYa8IEBg1N+RfVr02JfxmmCFqckG8nmvwY2dfRCF+3BNDvFnurn8ZB23SnAk
         tCL4uqkKw2HDO44/VdUNv3sn9pmVwDVPY+SK710pRVOAu3Fx8/tvlZb4UVW2ZYa3moK1
         ljCdWY2IL7wLTnKb1Y6GCdXJiOjm9/HMqg++36poFj1EYIVcsmk28C/gLMhTvIM2oXq0
         UxYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TMGNn7wGtcO++eOi/PTKKXfwiu+RO4V6bdguogd6lvE=;
        b=uboy9ziSkhpR6nGHT3gbUbjt1da0GH++x9MpaFxnHtxHRyOZogEDk4s1wBFgKZECeo
         FdEW2/PdXQIQRX3DtXJ0x5wAqRYJnd8g4nCoTpJVpIN0Vaj8/K68fGgJ5OHnYullrC7O
         byR+w8wbeLeXYGi9v8oWas8oJjkuge3i7WKh0H5h2/zizmi1HwCRyhUVc7L0RM0SI3cY
         Qou93iT/k4u2bKAOCrGjKCPdyK1qZA29/wWsC6UIDYK89X5wsYsIEE+SCH1lyPJz/JoB
         ZTd7SWmQhqgFI56jYTJ1F1HgGziLxWfDg3sJvoTA7+gYzxagu1u55lbACf+jUDErCcX4
         EO+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lGd6dHat;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TMGNn7wGtcO++eOi/PTKKXfwiu+RO4V6bdguogd6lvE=;
        b=pYP2W84CbPcqYe6POB4nKAFDaE52NFBdsz/VjaWCJUY0Mfu/vDE3bcQpM/6zcGpzli
         wt6jADyY+ojKP5fe1DqMN8psa6759SrR51PYfsghvk/oE6ItWVSIKkILMQD+ilNarbwD
         ZKh7FiXOyI/0XiSihEf3yhpkCQmg4Zxs6Se2I9Gj8Cs3RHtypkmNzXBzntf6r8VqhtwX
         OSpqlL/xVds4Fd8R8KSGvO43iSHQ86w7Cdb37qmjsj9FXcMCkdVKiz34Y9sC9M3XNOue
         5XeZVDaTxB94Cu7lWPHFD7AdwhOn4Dinbctg3a07stBmEUNT/cw4YEQvql7ydOQglx+B
         S1tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TMGNn7wGtcO++eOi/PTKKXfwiu+RO4V6bdguogd6lvE=;
        b=lc81P3fRpLsLspS2Bh6flwMt6VTchgPKKvn6uCFEaK4joG78FrKE12BX7Gg2MHdoVG
         xDz7zTjiSijwx6Nu4qONA4qGvQnksV8hwpJOGKNQBX93jgNbsv8rDz7tMR7zdm5X1nKW
         imxYeKU4EAFwPBy+TTXcJJHm7xJ7oVdMBqqUkI0FJ6B7d6LY15OeoDQ1mfAinyz4psMv
         devWpFYuJwoI7K6Otx+SGiRdY/xVhQ5RUheSsYwgsTbPtZuEhkQrnwzs9iC0wxmVGtfF
         GO+pjBG4AmIQ2VivjnmcYkqAfxZ+nWm3I+Dt/4z5NGye5yZ+yveI9iwPXZOySaVV/co9
         h2eQ==
X-Gm-Message-State: AOAM530x3LUmhZ7o0rBHAt0b6TnYlbUpW5b4YdfUVBghFaJrMhbURRSy
	LFbGsaSFcls6on4LzMdJv98=
X-Google-Smtp-Source: ABdhPJxi7GVsnBpB4scH3ufzF62qrPJBzTWe8dlsjf54O1e7go9itUo8MhTTWDsacNQ8EMd/TwmvKw==
X-Received: by 2002:a2e:141c:: with SMTP id u28mr318703ljd.72.1601622456450;
        Fri, 02 Oct 2020 00:07:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bc6:: with SMTP id w6ls64692ljj.0.gmail; Fri, 02 Oct
 2020 00:07:35 -0700 (PDT)
X-Received: by 2002:a2e:9cc3:: with SMTP id g3mr294786ljj.146.1601622455498;
        Fri, 02 Oct 2020 00:07:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601622455; cv=none;
        d=google.com; s=arc-20160816;
        b=SKsNaUNLrO+Vrq/DcncRF0yvd+09DKO4JBO53xKc+LI0WWFq0ora++00t2wABI/Nyw
         n96pcUqngbVqBBgkHZ1Rfr0lBveVomDleSe8TrUFn5Ugx7TuN7/OFzSjLgiBNE+uhACz
         wg8xe4dXh/cg07C5dN1IzPzLb+ZJF6fdcyEITweqlMaBFt74hKH+cvOBJfT46C0Dqi08
         IW+1H5sDYt//D16M0it+V7SNQP8WFHQfcqlh78loH/rxugfB0dlAQ0YB6tI42+uTWuXZ
         HhJb3IvD1tIb3pzN1oSj+VO85+hoba9sEcEZHQvs1c66ySOKqLXcz4ah4HwRa55OzzOh
         ToUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ye/s+D4VgMKbfo7kHtFUxt4Yo6siN0GRSwJxDl1BL+I=;
        b=a/QvX4swhlwL+iN0NQhWDyWCmFlN/mUiNu/v6KzXJTotkipuwx4bxDcTRvHGcZO4T3
         i6E+eoDX3GOjUlH0r8kt2NhxegFWB+3KPyiXyMHjTXVTJcDenFWrMic1UMKE11Uw9/Bc
         HcbhAPTn6gDjod9jKppv3jeYmYFA6FitNjPUh52xAc5lFUut6+uGzN3AqYEfU9jLyK/Y
         zXcnx9kM35s/3ygiyC9Z17s5ClBRk1Jc2DN5O1fjAHehdOsYm+sSUkz6E2wb8WCu1C2l
         8nJFb6w9lIFtkDdNjrsHk7AAJApH6KB3qMC7wF1Ud/++9mqSpc/++SX64Xet10CPUUr6
         AUzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lGd6dHat;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id h22si8262ljh.7.2020.10.02.00.07.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 00:07:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::544 as permitted sender) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id b12so583198edz.11
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 00:07:35 -0700 (PDT)
X-Received: by 2002:a05:6402:b0e:: with SMTP id bm14mr892264edb.259.1601622454831;
 Fri, 02 Oct 2020 00:07:34 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-6-elver@google.com>
In-Reply-To: <20200929133814.2834621-6-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 09:07:08 +0200
Message-ID: <CAG48ez3X4dqXAEa7NFf6Vm3kq6Rk+z0scWqK6TV6jTo5+Pu+aA@mail.gmail.com>
Subject: Re: [PATCH v4 05/11] mm, kfence: insert KFENCE hooks for SLUB
To: Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, linux-doc@vger.kernel.org, 
	kernel list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lGd6dHat;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::544 as
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
> Inserts KFENCE hooks into the SLUB allocator.
[...]
> diff --git a/mm/slub.c b/mm/slub.c
[...]
> @@ -3290,8 +3314,14 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>         c = this_cpu_ptr(s->cpu_slab);
>
>         for (i = 0; i < size; i++) {
> -               void *object = c->freelist;
> +               void *object = kfence_alloc(s, s->object_size, flags);

kfence_alloc() will invoke ->ctor() callbacks if the current slab has
them. Is it fine to invoke such callbacks from here, where we're in
the middle of a section that disables interrupts to protect against
concurrent freelist changes? If someone decides to be extra smart and
uses a kmem_cache with a ->ctor that can allocate memory from the same
kmem_cache, or something along those lines, this could lead to
corruption of the SLUB freelist. But I'm not sure whether that can
happen in practice.

Still, it might be nicer if you could code this to behave like a
fastpath miss: Update c->tid, turn interrupts back on (___slab_alloc()
will also do that if it has to call into the page allocator), then let
kfence do the actual allocation in a more normal context, then turn
interrupts back off and go on. If that's not too complicated?

Maybe Christoph Lameter has opinions on whether this is necessary...
it admittedly is fairly theoretical.

> +               if (unlikely(object)) {
> +                       p[i] = object;
> +                       continue;
> +               }
> +
> +               object = c->freelist;
>                 if (unlikely(!object)) {
>                         /*
>                          * We may have removed an object from c->freelist using

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3X4dqXAEa7NFf6Vm3kq6Rk%2Bz0scWqK6TV6jTo5%2BPu%2BaA%40mail.gmail.com.
