Return-Path: <kasan-dev+bncBDV37XP3XYDRBKVR3D5QKGQEZ7NINBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C3F2128060D
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:58:03 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id r10sf5175804ilq.6
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:58:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601575082; cv=pass;
        d=google.com; s=arc-20160816;
        b=1GYwAIF41wF94b3PB21PEJUCYNNa8eAMfvOEo45W52VQ64OGfgVx8tSTTmCMTG/zZF
         Q7Ek679HxYgRJkjtDBXEhVAf7VjZ1x1H96EnxsvBI8KtwezLlhuZUT7k9OXdoJDtJwVm
         bMFAjmJrxtZsnMLGKB3rwssr5XonKA8lJx7g7qVF2BNZKSBRVJANm2Yep6yquuQGPd7M
         7F/XbOHfRY6tPHHtOD18MGLoWKPJDuZWSZ5B3VIz8myJXgwXJT0pKkQKgVtkSs47rnjv
         VI6YFH3b4tu4DG3gVOq7DCXqQXJVg/TFa7n/r1n8wf+4sBUpyPwhb3EuOwWuk78zPmeD
         Dq8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Kz3uM6O+1ybKifyVDpTZ4HmGh/oKAiSnbK77UOMmsJ4=;
        b=Q30Qs7B2G77qOsBblOl1vNO1TC9pbHiG5Zl3+D5g7E91gAnA4UtO8gMRFFr+C+QEwF
         kbjaqAcRyBjqDxX5S0zmDCsS/YoKSLSDLiKXopIIbAkzoc1b0khfnJhRozMDdYPzVTqy
         lAfJF7akyWXcRRIBMfAcbLEINNxIs1r5m22V5Fyiisi1snjfAE7gJmUMYsQU2U1hkzPQ
         zOZs0UQHVtcyMdR9o3uAUPvtycqijd5aaXeFXtDecdMuUgzFSotJCQXBa2c2YVpzc61j
         J3vaUjHxRbOkCQGa3TkmfCin16Fluby4drlyRDIbBS+QnTY0qmfz24DI8EG7HWQhw+Pr
         adtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kz3uM6O+1ybKifyVDpTZ4HmGh/oKAiSnbK77UOMmsJ4=;
        b=pj4vWhIfTdbuFCHHH/uA79XcaS+Q3hEIbZNSjat++Lgo9zYXa96wFAEZab03NT2sV9
         7os/zluntKjjS7wyBPvv10r/eAoIeNM9QjvWaEgLrHz5oIamMmzMK5J1GPR2z2pV7yiY
         lEyyHVVv5Ehp93g2OsF/X5N2LN/bs51SYCp+djT37I7IFEUohHuMRDYNsIL+LbplKqBO
         zCvR2rK7Pz9GNv3TOrdOIMc4uvvkrdczcr5ubI2EGBaEdasRJjjkCIrmvMXTYKz6Jxn+
         bv55XcGoFBEfRFgMVyGvo0PvXWoj7Tbs4NPl/T0eNR3Vc1TznZkRGE3lQ/hmi09j4EFN
         nAhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Kz3uM6O+1ybKifyVDpTZ4HmGh/oKAiSnbK77UOMmsJ4=;
        b=oWNwyyWQK8gmoB5/MVg2dyWX7E06wylWwtJl8uwJZpr9mv9o8uHx5xfbu+FdN1adJK
         /aKV8YY9g6DPJC5v7l3tFiColXaFZLWeepCoUFCOtqbSxV0gy5U22jah0+iurVM8g/ad
         gBAeG1UgM+RawXsxCVXu3/EiFW0kmc+fVGXkRYU8h39Uhi9hPo0slWzBQVFqYwoBMEbY
         BAAicGevpEpc4x6LSWqIFrh9QXzggK5yeZDju0JQ5mXsRBx8pur6pJ4ivKut3wvk3kTW
         hnMT54/EqrL1SfJAtmCMidCutqWHTVC1eKemomwqRoyA/9x3NrBoWLcoU91MEqBEOacb
         TfSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LVwC+FyLfgVvMg9vdoy4W0+bToWgklAe1MEm90QRJ54VonVS7
	2bPgqQio0tMUzryFnflMjRI=
X-Google-Smtp-Source: ABdhPJy/F0sAd2UYic0UwrxPZqpa0vrTp7LihSlSCv5s48J63COLWqSs1PXnbLK5ohrlQjL9uANMYQ==
X-Received: by 2002:a05:6638:13c4:: with SMTP id i4mr7469417jaj.85.1601575082652;
        Thu, 01 Oct 2020 10:58:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:cc3c:: with SMTP id o28ls676679jap.6.gmail; Thu, 01 Oct
 2020 10:58:02 -0700 (PDT)
X-Received: by 2002:a05:6638:148c:: with SMTP id j12mr7298030jak.70.1601575082191;
        Thu, 01 Oct 2020 10:58:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601575082; cv=none;
        d=google.com; s=arc-20160816;
        b=On2Sbfj3E+YwKZ79jNyb9EMa93zuRmKNKhl08Bhx8oE/c6oQ6rrgmmrkVLsv6B74e8
         lZcEfLemzwP5v+lW/Ee/BC0Vh9FFu6SSj9t6vKObIIL8jlZE4q8DGk3wvNGSoxH88Ut9
         3SiuK4f6qcChMPGtuKQK/LD6b9eHATKIE4Qfaa4D4GJWwi62YVMWZgQZ5eWM/rch5rHq
         PSbZM3jiYekOQQX0rzr7CsaFxQt62TaBmzGvby37EZj0W4tp77jK5vmOSUAjsTpu4VGH
         cmY8bN+XGEty2f0+0sAzlVPZcGZTQcBOH448qXdXhJRWTtAyA+yEyMfmU2Bu1EbvUMZJ
         gSOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=71qUS5kX2D2lCHGsFC7u85xK49FW5Gbr9/6JRrWrHdQ=;
        b=CxGwiXHzN1mJP8rALw1NMptW2wB0H+1ni9QbIsrAFcpBASZr4IZisD+GtI9zSS9hrN
         HS0hI4YcogyyqraDO25vD8GiG1anEd1AxUSCImYjjRcpfbe4x9p0z4SouIt1raXMdadw
         fZO701DOiG9DAiM1oKv0d8w6b6seXzJDBrEBoRZnx0gWORi0tP96b+4roEJV00Q6XWjE
         SFWN/TgCVzPjNhndcuI62RSyTujaQ2E1Ry1kBWX0zPuiiAPm2yesZYVzxcCAbiEUmy7z
         Rb2L6yLubtT9M+6Ri6iuO9ZZSGe/0ZXgD0Iei2/rx0XwnMfq+AwMVUmLg+WgYWgLdsOe
         VzZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m2si374766ill.5.2020.10.01.10.58.02
        for <kasan-dev@googlegroups.com>;
        Thu, 01 Oct 2020 10:58:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 78BE31042;
	Thu,  1 Oct 2020 10:58:01 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.119])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 604693F6CF;
	Thu,  1 Oct 2020 10:57:54 -0700 (PDT)
Date: Thu, 1 Oct 2020 18:57:45 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Will Deacon <will@kernel.org>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"H. Peter Anvin" <hpa@zytor.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitriy Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jann Horn <jannh@google.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	SeongJae Park <sjpark@amazon.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20201001175716.GA89689@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
 <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
 <20200929140226.GB53442@C02TD0UTHF1T.local>
 <CAG_fn=VOR-3LgmLY-T2Fy6K_VYFgCHK0Hv+Y-atrvrVZ4mQE=Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=VOR-3LgmLY-T2Fy6K_VYFgCHK0Hv+Y-atrvrVZ4mQE=Q@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Oct 01, 2020 at 01:24:49PM +0200, Alexander Potapenko wrote:
> Mark,
> 
> > If you need virt_to_page() to work, the address has to be part of the
> > linear/direct map.
> >
> > If you need to find the struct page for something that's part of the
> > kernel image you can use virt_to_page(lm_alias(x)).
> >
> > > Looks like filling page table entries (similarly to what's being done
> > > in arch/arm64/mm/kasan_init.c) is not enough.
> > > I thought maybe vmemmap_populate() would do the job, but it didn't
> > > (virt_to_pfn() still returns invalid PFNs).
> >
> > As above, I think lm_alias() will solve the problem here. Please see
> > that and CONFIG_DEBUG_VIRTUAL.
> 
> The approach you suggest works to some extent, but there are some caveats.
> 
> To reiterate, we are trying to allocate the pool (2Mb by default, but
> users may want a bigger one, up to, say, 64 Mb) in a way that:
> (1) The underlying page tables support 4K granularity.
> (2) is_kfence_address() (checks that __kfence_pool <= addr <=
> __kfence_pool + KFENCE_POOL_SIZE) does not reference memory

What's the underlying requirement here? Is this a performance concern,
codegen/codesize, or something else?

> (3) For addresses belonging to that pool virt_addr_valid() is true
> (SLAB/SLUB rely on that)

As I hinted at before, there's a reasonable amount of code which relies
on being able to round-trip convert (va->{pa,page}->va) allocations from
SLUB, e.g. phys = virt_to_page(addr); ... ; phys = page_to_virt(phys).
Usually this is because the phys addr is stored in some HW register, or
in-memory structure shared with HW.

I'm fairly certain KFENCE will need to support this in order to be
deployable in production, and arm64 is the canary in the coalmine.

I added tests for this back when tag-based KASAN broke this property.
See commit:

  b92a953cb7f727c4 ("lib/test_kasan.c: add roundtrip tests")

... for which IIUC the kfree_via_phys() test would be broken by KFENCE,
even on x86:

| static noinline void __init kfree_via_phys(void)
| {
|        char *ptr;
|        size_t size = 8;
|        phys_addr_t phys;
| 
|        pr_info("invalid-free false positive (via phys)\n");
|        ptr = kmalloc(size, GFP_KERNEL);
|        if (!ptr) {
|                pr_err("Allocation failed\n");
|                return;
|        }
| 
|        phys = virt_to_phys(ptr);
|        kfree(phys_to_virt(phys));
| }

... since the code will pass the linear map alias of the KFENCE VA into
kfree().

To avoid random breakage we either need to:

* Have KFENCE retain this property (which effectively requires
  allocation VAs to fall within the linear/direct map)

* Decide that round-trips are forbidden, and go modify that code
  somehow, which was deemed to be impractical in the past

... and I would strongly prefer the former as it's less liable to break any
existing code.

> On x86 we achieve (2) by making our pool a .bss array, so that its
> address is known statically. Aligning that array on 4K and calling
> set_memory_4k() ensures that (1) is also fulfilled. (3) seems to just
> happen automagically without any address translations.
> 
> Now, what we are seeing on arm64 is different.
> My understanding (please correct me if I'm wrong) is that on arm64
> only the memory range at 0xffff000000000000 has valid struct pages,
> and the size of that range depends on the amount of memory on the
> system.

The way virt_to_page() works is based on there being a constant (at
runtime) offset between a linear map address and the corresponding
physical page. That makes it easy to get the PA with a subtraction, then
the PFN with a shift, then to index the vmemmap array with that to get
the page. The x86 version of virt_to_page() automatically fixes up an
image address to its linear map alias internally.

> This probably means we cannot just pick a fixed address for our pool
> in that range, unless it is very close to 0xffff000000000000.

It would have to be part of the linear map, or we'd have to apply the
same fixup as x86 does. But as above, I'm reluctant to do that as it
only encourages writing fragile code. The only sensible way to detect
that is to disallow virt_to_*() on image addresses, since that's the
only time we can distinguish the source.

> If we allocate the pool statically in the way x86 does (assuming we
> somehow resolve (1)), we can apply lm_alias() to addresses returned by
> the KFENCE allocator, making kmalloc() always return addresses from
> the linear map and satisfying (3).
> But in that case is_kfence_address() will also need to be updated to
> compare the addresses to lm_alias(__kfence_pool), and this becomes
> more heavyweight than just reading the address from memory.

We can calculate the lm_alias(__kfence_pool) at boot time, so it's only
a read from memory in the fast-path.

> So looks like it's still more preferable to allocate the pool
> dynamically on ARM64, unless there's a clever trick to allocate a
> fixed address in the linear map (DTS maybe?)

I'm not too worried about allocating this dynamically, but:

* The arch code needs to set up the translation tables for this, as we
  cannot safely change the mapping granularity live.

* As above I'm fairly certain x86 needs to use a carevout from the
  linear map to function correctly anyhow, so we should follow the same
  approach for both arm64 and x86. That might be a static carevout that
  we figure out the aliasing for, or something entirely dynamic.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001175716.GA89689%40C02TD0UTHF1T.local.
