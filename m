Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7MTZX5QKGQEKJUF5KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id EAA0627D1D2
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 16:51:42 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id h134sf1716737oib.10
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 07:51:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601391101; cv=pass;
        d=google.com; s=arc-20160816;
        b=agWyq756DPPYeGFOf1LR/s35rchjJUvgNxIS0Fj3R11wywrzDgRYV9JH6PxM+kCbw3
         4emCRKPNES7+GHmJw9Hqqn+ZRnFKHIgwdL9/I0/3ydVaQ/80IHiUTb22Fxn0uHLPkDtE
         fGdWkXp5ROlMO3FU2xE35rxVEnYw2p/FHoAnjkPCv3QbLXyRyebcdohpgRJBjTL8BkAU
         vFlFLYRK7JxpiC3Ry7TbX5HlM7FRKC6ys4AByNHhsWWwKnbjR5EL9XUSe2vOb48No6VH
         pNZ7Qqt5xITWKF23zSoW6S0Iuzqs4JLjPXa/8QTZNtia9yrRKVhbRfPhectgMjkaCvD4
         AV/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bmSLCp8uFrqSHvwazUeznGDrWee0ad65sKl0JkSCcr8=;
        b=MGE/5Fxi8w6qIcd4KzIu+X1NJHjde1+PXSAWSp696MokMgnlgdS8S5yTpkZKTHSZIs
         cHCR7vP2/+gDxiuEiPkbk6i4lJQ6J5dPAxL08dmrrQMLFydVPYsgktcjCyeDm0zF9lHB
         A0SmAuJSR5QPCI4jCEuSBOL62xVSEFFoWmrdCRaxxJfoIpg215GLG1Q08rUnWykVHCfz
         r3z7oSge9FN82y9xwfnSUBOlFmHkT8JKY2PkZf8Z/t7CI+rOsqaAEMlSuLJFfJW18erk
         jGl4KQxty0AHXeSWmt90+k8fXrBkxFNMHwJImLApf1b46YHpVlMdCPdk8wjlRBQFwDK0
         JF4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wMGD4Vgc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bmSLCp8uFrqSHvwazUeznGDrWee0ad65sKl0JkSCcr8=;
        b=QGrnQ/dS84l2F/Ob6t5kt/kwQgokALx5a4L2SvycbLiDZ2dJg2f5MOzcJHEz8smqhn
         ATZqFoHKNl6ZE+8isgQu75owNhDH1qMXfL4nlOsR1vq2SsEX+3ew9euH5sx6tqF4HPax
         2fEjiu5MMk945EjZRzLwiSxmOEQFFdm1ElLflMNcFlHyHzPCurEWPLLHeosD0w/lZ2NP
         uVWvlVn2jt/8Mw9xV4gGUgYWmh8D6BpdQz08qUuhSO1rsydbb91Lp4snClJ5bLT//e8Z
         ZdVogK5s9Y1EZ94qlyriEQjnTL37ukLaLOuJxXz9BZfknzQYo5a45IPukj/8d/vF8jnQ
         i9pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bmSLCp8uFrqSHvwazUeznGDrWee0ad65sKl0JkSCcr8=;
        b=AeT99s6PGXbfU4UVeTlE5lc/TnB2rsvbVKfr9s+9TPphWBpxCGHuw4fN2cVjymrZ1y
         pb2lyBwENmB6Uw0dOQLspCTDWgm2nI8mz9vYoiW0hvIr7tAeuzoz/Pzq8xeik+AQjkQs
         6oDMMHF2YPTNH3qPVM4iwKttzNYyX+OpEBlnZswlIy4DQaR/erC7Qp5DBcMz35arA75I
         zhNpbKUEWeh5/Tomsp7A7RUQfHwdUAZPkw9DiDPeJ5MYil+nW2yQqJYGHBUv+TCPW5RL
         6Gw70PqNOdj4nv38HEUerZaY04f/LHxpnjvLrn/9m86J2A8qmgUTqw3C+cAIUTo9yv+q
         FmVA==
X-Gm-Message-State: AOAM531L5ifTCwumlZapCOo70oSS4d3L6LZ1rGwUKQ6FHp2SdEeGKw0D
	kBjF7NQjW9eTBdemfQYWLvw=
X-Google-Smtp-Source: ABdhPJyI/fxEfWgpVWWpP+0APlpUNlk+88+oaQu2J5GODT8SXWCwJZgV3dd/fzRKF42cvIuMHuMLvQ==
X-Received: by 2002:a4a:978a:: with SMTP id w10mr4923596ooi.69.1601391101621;
        Tue, 29 Sep 2020 07:51:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:119a:: with SMTP id u26ls1164270otq.6.gmail; Tue,
 29 Sep 2020 07:51:41 -0700 (PDT)
X-Received: by 2002:a9d:65ce:: with SMTP id z14mr3286613oth.280.1601391101265;
        Tue, 29 Sep 2020 07:51:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601391101; cv=none;
        d=google.com; s=arc-20160816;
        b=Xewc2Amp+d1LbFz3BA83R/dFk+3xnGNwqpO4HvpsEk8meVHC04xKQCqtTz9a9QC0O4
         1SpReGV9VxXEN65ZBGNF6roMBnEfaSqA3qSPR/CJsNKbVmS437/3NHn7v+AdvVGRrOR2
         7vzs0YTLuNIYLI9GAkYneQKYm0CfMLpElM/9WCFY6XFI7wcu0emH73mkDi6mRrUB237X
         vNZZbRqpaXwEVCj3SZUa9y//MxsJs/ngA0wH1E7JTDca9kbZUtZ920s/bK+w6hJYn3uk
         qEER446JupAvEdJ34nH83sjSUO/4u64ysiqijFCC5IRRgx+UFG1gI/Y1J6HywtYdO4h+
         /1Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wW+VJQgARCCUxTSXrTTMpTSAvZIEsqsjgDYoqUGhARg=;
        b=cgM5qqpYQcwwSQ9xnzVlEQwY2qWLB/pUM6GMkHL3czGUV5EwvWDr9ix2kcPiNaMLdp
         LRIYz3W72HlN8zyx+nTI/C4QNtiB9fWv+Vv2+4TTjlKW8nz2ZAt63wzKmCl7wwVZMLC2
         8rT0b48JV5H6RaXrHqC0sp0I1SdOM7ngjyuCgh0jzvqhN2uhv3Ne75Nm1FXF6mgY7H/h
         Sc8Yhkd0ukppglbPNUr5DhOIPPDkXY8vSZByF4BKpczd0Akhs7/wd+1DHFuQmQEC3zQp
         bDHh86CFZjtWhQyxlUdXsgFkz21G0Alja6rzo1AYN0/j/eBwpjaZ4b8WW1D+Aot2S5o7
         93vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wMGD4Vgc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id l18si285573otj.1.2020.09.29.07.51.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 07:51:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id s66so4712305otb.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 07:51:41 -0700 (PDT)
X-Received: by 2002:a9d:758b:: with SMTP id s11mr2840881otk.251.1601391100711;
 Tue, 29 Sep 2020 07:51:40 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-2-elver@google.com>
 <20200929142411.GC53442@C02TD0UTHF1T.local>
In-Reply-To: <20200929142411.GC53442@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 16:51:29 +0200
Message-ID: <CANpmjNNQGrpq+fBh4OypP9aK+-548vbCbKYiWQnSHESM0SLVzw@mail.gmail.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wMGD4Vgc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Tue, 29 Sep 2020 at 16:24, Mark Rutland <mark.rutland@arm.com> wrote:
[...]
>
> From other sub-threads it sounds like these addresses are not part of
> the linear/direct map. Having kmalloc return addresses outside of the
> linear map is going to break anything that relies on virt<->phys
> conversions, and is liable to make DMA corrupt memory. There were
> problems of that sort with VMAP_STACK, and this is why kvmalloc() is
> separate from kmalloc().
>
> Have you tested with CONFIG_DEBUG_VIRTUAL? I'd expect that to scream.
>
> I strongly suspect this isn't going to be safe unless you always use an
> in-place carevout from the linear map (which could be the linear alias
> of a static carevout).

That's an excellent point, thank you! Indeed, on arm64, a version with
naive static-pool screams with CONFIG_DEBUG_VIRTUAL.

We'll try to put together an arm64 version using a carveout as you suggest.

> [...]
>
> > +static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
> > +{
> > +     return static_branch_unlikely(&kfence_allocation_key) ? __kfence_alloc(s, size, flags) :
> > +                                                                   NULL;
> > +}
>
> Minor (unrelated) nit, but this would be easier to read as:
>
> static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
> {
>         if (static_branch_unlikely(&kfence_allocation_key))
>                 return __kfence_alloc(s, size, flags);
>         return NULL;
> }

Will fix for v5.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNQGrpq%2BfBh4OypP9aK%2B-548vbCbKYiWQnSHESM0SLVzw%40mail.gmail.com.
