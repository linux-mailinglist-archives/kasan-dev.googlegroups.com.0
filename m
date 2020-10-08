Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMN57P5QKGQECMGAZ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E2C32871BB
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Oct 2020 11:41:07 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id bd7sf3177116plb.10
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 02:41:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602150065; cv=pass;
        d=google.com; s=arc-20160816;
        b=kid1upwZx7uQrDwYKaAVITpP7hCunz5oHh/XWxsvZolnGc/UWzbuwLac/JJ+Z0Srla
         qMzOCDg5FMHxlHfOoB4rtQtMtZjtu2tdZ6EaahCKM4y2LTigshs9zP7t7mibjGg2Typy
         ONHXBYEAOJwwSB/j/gLLEY5BHYqmuwyLuB73e49b/kOauC3LW4DsVopo86TAb8xPqFOF
         K/jnhw4cplYaC5d7InCJB2zSmSCC4igQqbKpqsdDSCA1EKyWSiiK6j760ZVZUcWS6TbT
         1/PDuDCZctfqF0702Go1F1XyPQbJU35I/LXrBlBFc+hLSy1Uj5/K+JNL300eQwJXbDfq
         PZsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cyUwwGMgw6UvbT1sX796h2PElBFz8Kzr4ka0q244SD8=;
        b=FKREo97tlrxzHrDavCBdJpm3a/vE3DzkxrRscB3rpqawL6MPRht4GYoMgJtJyLPPdP
         Tl0oWt3cELOV28j7efKoaDNTpQOdJR7LFCtQ72kE8C/QuHvagjerzgRn4shgsTYfIICO
         5mR73Oz3DoWkfInmjefWaBPtIGn2wF9ONZ+w+VzNXM4NpprNc38DDfxgfmu6yJn+MxCm
         spQPQD5kn5Jn4TuVLfZhE/LrJjq3A9k7A2ofJQ1kcBsjyyB6mhSC3nKADGGhRKWIYs++
         FtOKq+xvK5HQcHt1cMnP9ymGe+mbiUdQmB+Ee8Inh1xWUtq2FamJgGNzb7V+XxUK0+ut
         GqZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XhgNGt7s;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cyUwwGMgw6UvbT1sX796h2PElBFz8Kzr4ka0q244SD8=;
        b=H+6LU5Zl/kpTmPElAM5spOlbWV2NwzL8HWN2UbE0qFKDf4OPz51ds6V3mECvx9YNx5
         HiPpg9z9I6jSN/TymCaEYe8gpZ5IoNxk4o9sr77eJKmBt/vIeoyPV0l3eeZWT6hJIdEv
         AyvhEBHg5B12KSbTbBGFYbj/4Ly3/m0aTf2O76d2ZCVAsSt/bi+fvu8CV/9zxk/60eGr
         RSu8SkkrPxf+OOHDXHp8APCw5jxr25RT3G/pCLKfDQIA3LMPckVl4et70U3JvCJPX6Gz
         81lp62mYmJQHI2fD3lDtcS0BPq1Il175tQ67EkGUfPLwnIQr3p+tsFtUU4/gzU+nc6Qp
         91zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cyUwwGMgw6UvbT1sX796h2PElBFz8Kzr4ka0q244SD8=;
        b=C+1juBdDFoa/oj0uNq/FMk3GhTtrMUpZgnJoJhMDpMz1kp7ELkRvIvNUPdmSbEHcle
         BhxGpDQYZYK8qbmOPjnhJkGinKn3EPKhY6ARF4aZ/HBatmWFwQC3vbY4piwQG6f0PSou
         VKTi1AjztzIpQJa64di8eJ5BAvGKXPP7wWX2iymdy4Bxjc6pG43M7lEHPlDq2LBEzQYP
         iKkCOUxycUnPEJDfkIu5X5UO2vK/BuVrReOi5NW3TEDgvKRRT2DPOh7mgwE5XTWptf5F
         TsmOQ73t1ZsUwmAmdW5NBI+YKbOIfCg/C1zHh48j5z+N/tItUXKZDzip8FicCoBdNW6k
         WedA==
X-Gm-Message-State: AOAM533wgasrmbTMDHQ70n5Na8bNjT06rwqRGt8cOErTaS7TgGjtHAKg
	5743VtNHSRZR5Udc+mccaFA=
X-Google-Smtp-Source: ABdhPJy7DQT+yTm9mwXhu9BS8MqaDkNVv1X6BMNdJr94tE2yFDOEHIAgza6pZi1jWSWPnv/3x+O8Pg==
X-Received: by 2002:aa7:93b6:0:b029:155:3b0b:d47a with SMTP id x22-20020aa793b60000b02901553b0bd47amr3285410pff.47.1602150065401;
        Thu, 08 Oct 2020 02:41:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d4f:: with SMTP id 15ls2037740pgn.3.gmail; Thu, 08 Oct
 2020 02:41:04 -0700 (PDT)
X-Received: by 2002:a62:3706:0:b029:142:2501:39e5 with SMTP id e6-20020a6237060000b0290142250139e5mr7066138pfa.52.1602150064436;
        Thu, 08 Oct 2020 02:41:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602150064; cv=none;
        d=google.com; s=arc-20160816;
        b=t172FdAlc5cvangS2kvpCiIQ8ed6Tz1b6PRNQjcjjR7MaLd/5nihuNL2VpjxOmF43L
         CqkgXRQhogYq2rVsklUtZRTCyvOHQpoIdcaKvXQU6ol8gZJ4J2ZwD611WZXBWewEJU9P
         UVgxEe6G7zQSvnM3DJkJM3/nNhIq5YSQk1oNlam1NwPzjAvbsYilljhQFglpyLVogzWN
         zoqh8/bjjbt3LkaiIgPcjnPBK9iWcNBsGUOIHSTyIPwDnatvGRPGJhscEts3PnuvZsca
         aAn1bESTVzUUEbl9ES7E0U4CQZZruA9abyEq5wrntx8crQpCpLdFdnvvl+Xwjp2wjb6g
         OWBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qfMhghjBP9os9D7z08t6DZuXpLEhZ0q00x6tVMxnguE=;
        b=joTP2xJBB9WW3rT/rFdSHwkoinzlNsNpEPx06jOGDRnsOLBeQiasZMO0PwTNYRuLh8
         hxmHDmxcdisccjweCN/KJWjmev4cMEWFfgFg2sj+VwR33hVRitqDflre8TlPFMYNjxYw
         EGPq0KioaXZc74raYxh8jmkxUmdQzF2qbHQKJVbzycxVuSkKL3aY7osxeqsmgZx5v/rB
         DneYOA33H5bdIdG6Tgcm5O+6eNXLi7RBUbQwceW+ONWW/kEUb0AGbfHK6MjtXzgBEnMX
         TR+IHCJUP5tDESfilPRmCrlHeTVMbrcU3AE5hn7tb9CUHFH+AN+uPzPyb9rGt2rCNalI
         40XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XhgNGt7s;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc43.google.com (mail-oo1-xc43.google.com. [2607:f8b0:4864:20::c43])
        by gmr-mx.google.com with ESMTPS id t15si257435pjq.1.2020.10.08.02.41.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Oct 2020 02:41:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as permitted sender) client-ip=2607:f8b0:4864:20::c43;
Received: by mail-oo1-xc43.google.com with SMTP id f2so602783ooj.2
        for <kasan-dev@googlegroups.com>; Thu, 08 Oct 2020 02:41:04 -0700 (PDT)
X-Received: by 2002:a4a:751a:: with SMTP id j26mr4844047ooc.14.1602150063537;
 Thu, 08 Oct 2020 02:41:03 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck> <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
 <20200929140226.GB53442@C02TD0UTHF1T.local> <CAG_fn=VOR-3LgmLY-T2Fy6K_VYFgCHK0Hv+Y-atrvrVZ4mQE=Q@mail.gmail.com>
 <20201001175716.GA89689@C02TD0UTHF1T.local>
In-Reply-To: <20201001175716.GA89689@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 Oct 2020 11:40:52 +0200
Message-ID: <CANpmjNMFrMZybOebFwJ1GRXpt8v39AN016UDgPZzE8J3zKh9RA@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Mark Rutland <mark.rutland@arm.com>
Cc: Alexander Potapenko <glider@google.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, "H. Peter Anvin" <hpa@zytor.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XhgNGt7s;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c43 as
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

On Thu, 1 Oct 2020 at 19:58, Mark Rutland <mark.rutland@arm.com> wrote:
[...]
> > > If you need virt_to_page() to work, the address has to be part of the
> > > linear/direct map.
[...]
>
> What's the underlying requirement here? Is this a performance concern,
> codegen/codesize, or something else?

It used to be performance, since is_kfence_address() is used in the
fast path. However, with some further tweaks we just did to
is_kfence_address(), our benchmarks show a pointer load can be
tolerated.

> > (3) For addresses belonging to that pool virt_addr_valid() is true
> > (SLAB/SLUB rely on that)
>
> As I hinted at before, there's a reasonable amount of code which relies
> on being able to round-trip convert (va->{pa,page}->va) allocations from
> SLUB, e.g. phys = virt_to_page(addr); ... ; phys = page_to_virt(phys).
> Usually this is because the phys addr is stored in some HW register, or
> in-memory structure shared with HW.
>
> I'm fairly certain KFENCE will need to support this in order to be
> deployable in production, and arm64 is the canary in the coalmine.
>
> I added tests for this back when tag-based KASAN broke this property.
> See commit:
>
>   b92a953cb7f727c4 ("lib/test_kasan.c: add roundtrip tests")
>
> ... for which IIUC the kfree_via_phys() test would be broken by KFENCE,
> even on x86:

Yeah, we're fixing that by also making x86 use a dynamically allocated
pool now. The benefits we got from the static pool no longer apply, so
the whole dance to make the static pool work right is no longer worth
it.

> | static noinline void __init kfree_via_phys(void)
> | {
> |        char *ptr;
> |        size_t size = 8;
> |        phys_addr_t phys;
> |
> |        pr_info("invalid-free false positive (via phys)\n");
> |        ptr = kmalloc(size, GFP_KERNEL);
> |        if (!ptr) {
> |                pr_err("Allocation failed\n");
> |                return;
> |        }
> |
> |        phys = virt_to_phys(ptr);
> |        kfree(phys_to_virt(phys));
> | }
>
> ... since the code will pass the linear map alias of the KFENCE VA into
> kfree().
>
> To avoid random breakage we either need to:
>
> * Have KFENCE retain this property (which effectively requires
>   allocation VAs to fall within the linear/direct map)

^^ Yes, this is the only realistic option.

> * Decide that round-trips are forbidden, and go modify that code
>   somehow, which was deemed to be impractical in the past
>
> ... and I would strongly prefer the former as it's less liable to break any
> existing code.
>
> > On x86 we achieve (2) by making our pool a .bss array, so that its
> > address is known statically. Aligning that array on 4K and calling
> > set_memory_4k() ensures that (1) is also fulfilled. (3) seems to just
> > happen automagically without any address translations.
> >
> > Now, what we are seeing on arm64 is different.
> > My understanding (please correct me if I'm wrong) is that on arm64
> > only the memory range at 0xffff000000000000 has valid struct pages,
> > and the size of that range depends on the amount of memory on the
> > system.
>
> The way virt_to_page() works is based on there being a constant (at
> runtime) offset between a linear map address and the corresponding
> physical page. That makes it easy to get the PA with a subtraction, then
> the PFN with a shift, then to index the vmemmap array with that to get
> the page. The x86 version of virt_to_page() automatically fixes up an
> image address to its linear map alias internally.
>
> > This probably means we cannot just pick a fixed address for our pool
> > in that range, unless it is very close to 0xffff000000000000.
>
> It would have to be part of the linear map, or we'd have to apply the
> same fixup as x86 does. But as above, I'm reluctant to do that as it
> only encourages writing fragile code. The only sensible way to detect
> that is to disallow virt_to_*() on image addresses, since that's the
> only time we can distinguish the source.
>
> > If we allocate the pool statically in the way x86 does (assuming we
> > somehow resolve (1)), we can apply lm_alias() to addresses returned by
> > the KFENCE allocator, making kmalloc() always return addresses from
> > the linear map and satisfying (3).
> > But in that case is_kfence_address() will also need to be updated to
> > compare the addresses to lm_alias(__kfence_pool), and this becomes
> > more heavyweight than just reading the address from memory.
>
> We can calculate the lm_alias(__kfence_pool) at boot time, so it's only
> a read from memory in the fast-path.
>
> > So looks like it's still more preferable to allocate the pool
> > dynamically on ARM64, unless there's a clever trick to allocate a
> > fixed address in the linear map (DTS maybe?)
>
> I'm not too worried about allocating this dynamically, but:
>
> * The arch code needs to set up the translation tables for this, as we
>   cannot safely change the mapping granularity live.
>
> * As above I'm fairly certain x86 needs to use a carevout from the
>   linear map to function correctly anyhow, so we should follow the same
>   approach for both arm64 and x86. That might be a static carevout that
>   we figure out the aliasing for, or something entirely dynamic.

We're going with dynamically allocating the pool (for both x86 and
arm64), since any benefits we used to measure from the static pool are
no longer measurable (after removing a branch from
is_kfence_address()). It should hopefully simplify a lot of things,
given all the caveats that you pointed out.

For arm64, the only thing left then is to fix up the case if the
linear map is not forced to page granularity.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMFrMZybOebFwJ1GRXpt8v39AN016UDgPZzE8J3zKh9RA%40mail.gmail.com.
