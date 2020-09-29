Return-Path: <kasan-dev+bncBCCMH5WKTMGRBK5QZX5QKGQEBFK7AXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 75B1B27D325
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 17:52:11 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id a10sf1903833wrw.22
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 08:52:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601394731; cv=pass;
        d=google.com; s=arc-20160816;
        b=z7p1tvCGKVnnzujdAsxeONso9m9o8KgbHECCYtPVa0UxZ9F45DIRhPe7Ep00tpPo/9
         v1KHtZwzRtYP58hO915jPpo5ef1ut8tB6P07kg7zmL0vE4hkeN+JR6LFrPcGfOe/i8Z6
         /9b383SnCmUJ8Wz4txeDbVXFzjV35WcbU+alUTp2GqqPUdJTTgeDewPGkf6WjBC0wA/d
         oULzrkBBSZfPbYFHAT53pbvJaoNPNzd/ryNM521oQmRuNtRWhByXHZ3dtijjjMICryQU
         qfE6f19xsjFtPdiZ3KAkDSwvg+LiHr0qQygwGkbk+dAMC8uUZ16ZMuMEns9YdumHN65C
         CtQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=guGY0Ua/7Y8q7ipzwbJ3+aDmFlccslb8mIsUO387vAQ=;
        b=fn5G+1eOIKhHlpq3E9y8uTS/yHXvGhn/dahwkIaLLq0Fa+ZIE/bXlTDfUQcVfPi2lr
         ft2zitGIS61ilYUvz9G/HB4qYdpsNj9B2VmpFjIvEqhYPG2jEk7Or4DxQo+jJXA1B2wG
         JtY9u8zQ7cjNWgpbYiSntpfNr+73KzgE2ZFgn29OnHUPj74d/LfDJJK5Q9i9evSitCWC
         NEdlglTZDd6s33aitYKbz+AEYpy0BzAjHfqL1I3Cjii3fEE2MTiihlM7vBbzBBV0v16s
         vG8DgkEkMs4cFtfONWZG+TKu5uDv91hfgKiAjLJ6GDGofoAMYiRJZJFkrnKe1riE+nlM
         yO9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C1AnuCCs;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=guGY0Ua/7Y8q7ipzwbJ3+aDmFlccslb8mIsUO387vAQ=;
        b=cwj1qsetJiJfc+Ve+oy9JNMtdC+QliEVJEOoqJWLxAACOr0mRK6La6jGdSmePP+4EI
         8QNWOYN82ozkAgVVzDqhXV248ff6zD+p/C1qPWPZIcnjpjvxAtrqcK8No9Zbqr7ytgae
         KrO/b2n2ip25zsnAGgfsPwdpubcHa/uyfaJqA9vkshO9Cv0qUqms6pL+69VI1Y9Kvntc
         H09uJo3o1llN/gDnWOXI5d9fSG21SXKxpoKky/Xi6azjzOl4lI1XC5+FrDYlpRoBIm9s
         88Gz5TdppdTxnmpl5ZoNHvum/kbfjyRbhehTGrijB3Dgb8lpFco2ogNboJwtP0Cd+ogE
         HjwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=guGY0Ua/7Y8q7ipzwbJ3+aDmFlccslb8mIsUO387vAQ=;
        b=p+dbxQTdWKUpmteO+pzRcWZ8NGOb94zHSPEsT9YrqMV/tpHZpgivtJkeAnHzg4RiM1
         cl3/hjCClKULCRv8OkYdY2q6D8j8ENE2x34uqWh9vOSDvXXQSNrou4gtK+9BBGTolep3
         ORCLpm2Rxoy9TSfwStSJLc+BT4nP+tmoPmK0A67xTYqLc6cA8aNNLy/1qsKi7ib2TLre
         cG8zTwAVgGRP8XEeAFYa7WTqVDom3xSmN7VKpnrJb6r+KWP3R4jZxL875ftpJLwQS5Kt
         wM7z0/p3WeB0k4/8bmmEalx8c85NcuGW0WnsELRkBxG7698ch61chJD0fpXl7WVboPc2
         3AHQ==
X-Gm-Message-State: AOAM533qHfeWQy9en19sKnqIkUuLjPcQSo0TUemeMZsqqHoNG0AOLfI6
	nQbkbDHycrCb+zK4qk9Y6jI=
X-Google-Smtp-Source: ABdhPJyYxF76w0pBV5wU0TKG5jGSdEnUHo93sT0cI3E6CkGJn8+1blVkwL88Eigsq7t51AydC5oc4A==
X-Received: by 2002:a7b:c24b:: with SMTP id b11mr5566277wmj.134.1601394731233;
        Tue, 29 Sep 2020 08:52:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls2151168wrx.3.gmail; Tue, 29
 Sep 2020 08:52:10 -0700 (PDT)
X-Received: by 2002:adf:91c2:: with SMTP id 60mr5492250wri.292.1601394730367;
        Tue, 29 Sep 2020 08:52:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601394730; cv=none;
        d=google.com; s=arc-20160816;
        b=xzKDeIp8l/m8FR3Et9vEJZzCG6gtfdTZCDC+xGpe2CMZQTY0CyQrKoxN6Ijzm+cQSG
         eKQk5DJmPKloLVqWDJBE1KgQYhAcBrYsB1WL4thmRVF4/KUd2pq21womahAQFzf5dmK0
         FkNh3YHqFGU1J5amLok40RupkbEhVJ+ht1UVNclZbclf8Rv2EOMS8ce6E3Kqh0IEcKqg
         ATU8rrMZLCV8f9NdRx2c0sz+EBNJPdd4DOh1zCrN4EA+bttfEhADcBqGCXtqGzqcLRcS
         o8G83qOs3foH1JTWTCHvlZr6nQ1FZxHgywne/meqPF2g0SwJ6OHXzWrApFMlTE1NHGoP
         QAxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=waqIMiy+b2Y1XhEMp7lwlO73kRIAH1OEaVKybD+u/ZQ=;
        b=GV8FwwTXVnUcAE75b/r8SlQndjfaMDaBlwj3lOVR3HzI0xM6Th04PsDupGX0JhDVWf
         W+r/oxN+KuoaqNUp4qiXmfdcUtgoAEl261+kYgdIJua0uJ/6BxkQ2Phi2+NaJsRKaHiS
         OhsRYT5iyTR+lJYVZy8KF5Z0m9oAUvkP3h+7lQRWENaidCuiNYGFhrEyo+/brsVxrAw8
         nKqB7RyuAi9UBFQxbxYpHFyqD+Otz8INwFL3x+OctoUEJPxamg42kzZ+j3zaaYRwRfjA
         isxQH4pA48sZcxBJSXJp5re48UdEZXyDHN547K7ZhfN5RoOg/59dN89q792Ui/yJwM1A
         mwRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C1AnuCCs;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id 24si25536wmg.1.2020.09.29.08.52.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 08:52:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id z4so6005659wrr.4
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 08:52:10 -0700 (PDT)
X-Received: by 2002:adf:e312:: with SMTP id b18mr5418270wrj.372.1601394729790;
 Tue, 29 Sep 2020 08:52:09 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-2-elver@google.com>
 <20200929142411.GC53442@C02TD0UTHF1T.local>
In-Reply-To: <20200929142411.GC53442@C02TD0UTHF1T.local>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 17:51:58 +0200
Message-ID: <CAG_fn=UOJARteeqT_+1ORPEP9SB5HR3B3W8830rA9kjZLoN+Ww@mail.gmail.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C1AnuCCs;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as
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

On Tue, Sep 29, 2020 at 4:24 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Mon, Sep 21, 2020 at 03:26:02PM +0200, Marco Elver wrote:
> > From: Alexander Potapenko <glider@google.com>
> >
> > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is =
a
> > low-overhead sampling-based memory safety error detector of heap
> > use-after-free, invalid-free, and out-of-bounds access errors.
> >
> > KFENCE is designed to be enabled in production kernels, and has near
> > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > for precision. The main motivation behind KFENCE's design, is that with
> > enough total uptime KFENCE will detect bugs in code paths not typically
> > exercised by non-production test workloads. One way to quickly achieve =
a
> > large enough total uptime is when the tool is deployed across a large
> > fleet of machines.
> >
> > KFENCE objects each reside on a dedicated page, at either the left or
> > right page boundaries. The pages to the left and right of the object
> > page are "guard pages", whose attributes are changed to a protected
> > state, and cause page faults on any attempted access to them. Such page
> > faults are then intercepted by KFENCE, which handles the fault
> > gracefully by reporting a memory access error. To detect out-of-bounds
> > writes to memory within the object's page itself, KFENCE also uses
> > pattern-based redzones. The following figure illustrates the page
> > layout:
> >
> >   ---+-----------+-----------+-----------+-----------+-----------+---
> >      | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
> >      | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
> >      | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
> >      | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
> >      | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
> >      | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
> >   ---+-----------+-----------+-----------+-----------+-----------+---
> >
> > Guarded allocations are set up based on a sample interval (can be set
> > via kfence.sample_interval). After expiration of the sample interval, a
> > guarded allocation from the KFENCE object pool is returned to the main
> > allocator (SLAB or SLUB). At this point, the timer is reset, and the
> > next allocation is set up after the expiration of the interval.
>
> From other sub-threads it sounds like these addresses are not part of
> the linear/direct map.
For x86 these addresses belong to .bss, i.e. "kernel text mapping"
section, isn't that the linear map?
I also don't see lm_alias being used much outside arm64 code.

> Having kmalloc return addresses outside of the
> linear map is going to break anything that relies on virt<->phys
> conversions, and is liable to make DMA corrupt memory. There were
> problems of that sort with VMAP_STACK, and this is why kvmalloc() is
> separate from kmalloc().
>
> Have you tested with CONFIG_DEBUG_VIRTUAL? I'd expect that to scream.

Just checked - it doesn't scream on x86.

> I strongly suspect this isn't going to be safe unless you always use an
> in-place carevout from the linear map (which could be the linear alias
> of a static carevout).
>
> [...]
>
> > +static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t=
 size, gfp_t flags)
> > +{
> > +     return static_branch_unlikely(&kfence_allocation_key) ? __kfence_=
alloc(s, size, flags) :
> > +                                                                   NUL=
L;
> > +}
>
> Minor (unrelated) nit, but this would be easier to read as:
>
> static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t si=
ze, gfp_t flags)
> {
>         if (static_branch_unlikely(&kfence_allocation_key))
>                 return __kfence_alloc(s, size, flags);
>         return NULL;
> }
>
> Thanks,
> Mark.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUOJARteeqT_%2B1ORPEP9SB5HR3B3W8830rA9kjZLoN%2BWw%40mail.=
gmail.com.
