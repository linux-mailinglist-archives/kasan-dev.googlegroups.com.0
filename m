Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDPZ235QKGQEQFYMAIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BE1D27FE4A
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 13:25:02 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id i10sf1918772wrq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 04:25:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601551502; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zcf8ke/HdY4SV/CoKQo4CooKlXIOk+k4ux4BuS2kIA8/8rYhcKxIRB4xC6soMX9abN
         1WILagWMG+aMZVeoYlOXXah0+pLOPl/b5PgLW4qdJ5Y2c2hvFTNQfYnxkAG/xkypJOKY
         z51LesW7R46W9ubSvcSnarqaKN0DrJHwHmtfkQkKfyJpsr5y0GRmPBLv3UE3GsCcrv4H
         h1WodxYw92BOtA9qunTyyGd3obHmAe8CnbQn2VdZBbiRKjJG75tShA1IioxOiqCnJUpD
         XWG+DA9gFjDLOjxhgzxaNLJbqu29zjTtoEZ6p1f8jh61z6SPPXuStgDMIKUkvlCZ3xqH
         xeQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ISriHUlmf+PSIzYgxtZ9/1TZojcTeyTbe1yxU4xNYLc=;
        b=gT6S2QSNHuoHvbNTYSpXyz2XUCOnsG7bA/xP5K4PX3FtU+p1sXDzu/53hTL9HU75TY
         u/Hgzsff5OaKAC0rpPQGEZVs9r13+5X8/2QQ3k6xO1riq0S4OIZVHoeZ6iY90nmysZi3
         bSaw395Rp/pZds0XCG7GUGYmyt/Cs9ujod5P8jFJuOklCvuc3OV9o0z4NRThrLCpSkrq
         qejQJi0MGP7XfjDWywMdjcETG83+nVdTrpaN+kE3sIJjy1/0F1HrYjoRY+cN0fyZvztk
         fq5cxt9dDbwHvKyDDY5RJCnFjbl9mdWOO8RQNjrhbthiCvJ1+SN2u4OwWoR+uYOTTrF5
         70uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QCZTFGmp;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ISriHUlmf+PSIzYgxtZ9/1TZojcTeyTbe1yxU4xNYLc=;
        b=n1y3QozAGQlyN29Qty3tI58GfKpvJmVrVlaUYI7Uh/8qhpOuZvl6Tc/XKxU37CY9Sd
         tQhjcvJGvMT3SuOUXqRfDkhvRwE4DKFt5H8WF5Qt3VRfOub8jSrgydbrleYPAHCr8Es0
         njcHu2g52K4KEdkGPuvw9qAlZUAtN8PjK1A1uwij2yVWWUIkBw7Oks5rHTnU1QTjCqcV
         WaUVjZS09z0vHqsb3rOFaCEL4GBBn7AIUbYl5EOBOlpNC10xngHTLrLpLXU48JIlfa3M
         lVRJkQamgHlP55nuJ2YVXCw+CVLyv/xcN/3V6rSCaLPshy3wrVuGsj0/QBhBDHd9upQD
         1fpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ISriHUlmf+PSIzYgxtZ9/1TZojcTeyTbe1yxU4xNYLc=;
        b=UpkK7ikA/0AB2jyXAo8V0OPuUgC25EgdaxmImeawLdOBdfELOuBYcDV23trADNFEQ6
         Y2/wwtPvzskx0ty7U0c1PJE99uRkfDAgZAl9x8lslXtOwIWZJVDt1Tu5UR5Gxbm5Bs5S
         g4CSe+d8Aq2TzCDNB3d/xE7PuRWbX1IdelcauclsKYW/b3h5nOmBOXqG/RkthVO3Zmu6
         inES+rc5dtDB8pcN77WsewtOXIqnoPB8/vW4zLsiR7QWr1aW9vrwEEPWfYYoP6K0ZkK7
         9UMHM0KIvT9MfKJgnRzy6ZEsa6xkimCZqdGFHyHwUWb/4KvcUaZ9Ubf6A37WfW1RWVI9
         pILQ==
X-Gm-Message-State: AOAM533auVos+ZfEK4kR8XZASsn4FqeeVSCckfO0wIIHFY6mt1+uGD5k
	bi1G2opXqeaMgQn3vzj7CUQ=
X-Google-Smtp-Source: ABdhPJxtxRcX5vjY3idGY6xczF3Z0tjOTHU8pZtd1zfiK4CSeAgr1YN01W3GgBbGK37iIjSPcXW3VQ==
X-Received: by 2002:adf:9e41:: with SMTP id v1mr9142773wre.60.1601551502046;
        Thu, 01 Oct 2020 04:25:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls481987wrq.0.gmail; Thu, 01 Oct
 2020 04:25:01 -0700 (PDT)
X-Received: by 2002:adf:a3db:: with SMTP id m27mr8906149wrb.277.1601551501191;
        Thu, 01 Oct 2020 04:25:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601551501; cv=none;
        d=google.com; s=arc-20160816;
        b=DyBUHOH/zxKSOKLnppU7DlhQuCaE3KSuocF568M5vmOiikrGNbpQ/2FTHXkgctQeMY
         7JMwB6K9h5JwWK7C4oOS3bHrB9zm5tCr3e6DxBlnnRgLbdQG9L7v15C0tQqN2HBnXn4U
         dfSGjUuiEo8kUy00CR3IKLLMCu27jZMoAgSKrrcrfuzrtOSCZmxQsVtDSERNWK3aJ4YM
         uPufMJaIvdkDX9Q61xi610Ol26N6BHRCanNIWhgqrYGzxMRuzBBySUV2VrzWG1BaZcSw
         +tuOvc62FH9ce3deG1LB+6hi8TFgzBEpuKexxPZDoRvoD+gHAHe1yzJYcBO0mnBR9e9W
         JCTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rIrqsNB2CCkv+5Up492E6RUjeUyfI0426YjKqnUmMhw=;
        b=YbrLodxV/hihe4TKZTmhRZtk54cIBpUfQvKl82u+r/uEbtLvlLd6u7F5SFHrTUQog7
         8a+1nRE8AyI3kbwawMHscHVC+wWv+ym9SE98GTE1c5bAmI3oMAawMWGlfezztXcQBHN/
         yXOIbnpynqAFwmUYn79b0GJKG23c24/F9u1usbKfhJoUulf0oKY3EYPt8Kvlc3YjU/HW
         tRMUVEC1Ml263L8NxNxX/jd7Q1dtkF5iW6gPynK4AqiK2GvBqaODHOUfe7jtLfFnN1d6
         Ag1H7o6wk4QCfN/R99UDQBCosLYmHYtWimDPXJy6floS2H3yVFN6LJwIrYK53Opj69+u
         BoRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QCZTFGmp;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id f3si75488wme.3.2020.10.01.04.25.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 04:25:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id k15so5230292wrn.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 04:25:01 -0700 (PDT)
X-Received: by 2002:adf:f101:: with SMTP id r1mr8370892wro.314.1601551500540;
 Thu, 01 Oct 2020 04:25:00 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck> <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
 <20200929140226.GB53442@C02TD0UTHF1T.local>
In-Reply-To: <20200929140226.GB53442@C02TD0UTHF1T.local>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Oct 2020 13:24:49 +0200
Message-ID: <CAG_fn=VOR-3LgmLY-T2Fy6K_VYFgCHK0Hv+Y-atrvrVZ4mQE=Q@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>, Marco Elver <elver@google.com>, 
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
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QCZTFGmp;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::441 as
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

Mark,

> If you need virt_to_page() to work, the address has to be part of the
> linear/direct map.
>
> If you need to find the struct page for something that's part of the
> kernel image you can use virt_to_page(lm_alias(x)).
>
> > Looks like filling page table entries (similarly to what's being done
> > in arch/arm64/mm/kasan_init.c) is not enough.
> > I thought maybe vmemmap_populate() would do the job, but it didn't
> > (virt_to_pfn() still returns invalid PFNs).
>
> As above, I think lm_alias() will solve the problem here. Please see
> that and CONFIG_DEBUG_VIRTUAL.

The approach you suggest works to some extent, but there are some caveats.

To reiterate, we are trying to allocate the pool (2Mb by default, but
users may want a bigger one, up to, say, 64 Mb) in a way that:
(1) The underlying page tables support 4K granularity.
(2) is_kfence_address() (checks that __kfence_pool <= addr <=
__kfence_pool + KFENCE_POOL_SIZE) does not reference memory
(3) For addresses belonging to that pool virt_addr_valid() is true
(SLAB/SLUB rely on that)

On x86 we achieve (2) by making our pool a .bss array, so that its
address is known statically. Aligning that array on 4K and calling
set_memory_4k() ensures that (1) is also fulfilled. (3) seems to just
happen automagically without any address translations.

Now, what we are seeing on arm64 is different.
My understanding (please correct me if I'm wrong) is that on arm64
only the memory range at 0xffff000000000000 has valid struct pages,
and the size of that range depends on the amount of memory on the
system.
This probably means we cannot just pick a fixed address for our pool
in that range, unless it is very close to 0xffff000000000000.

If we allocate the pool statically in the way x86 does (assuming we
somehow resolve (1)), we can apply lm_alias() to addresses returned by
the KFENCE allocator, making kmalloc() always return addresses from
the linear map and satisfying (3).
But in that case is_kfence_address() will also need to be updated to
compare the addresses to lm_alias(__kfence_pool), and this becomes
more heavyweight than just reading the address from memory.

So looks like it's still more preferable to allocate the pool
dynamically on ARM64, unless there's a clever trick to allocate a
fixed address in the linear map (DTS maybe?)

Thanks,
Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVOR-3LgmLY-T2Fy6K_VYFgCHK0Hv%2BY-atrvrVZ4mQE%3DQ%40mail.gmail.com.
