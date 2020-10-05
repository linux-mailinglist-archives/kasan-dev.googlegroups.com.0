Return-Path: <kasan-dev+bncBCCMH5WKTMGRBR4G5X5QKGQEEQC5BLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D6EF283BDB
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Oct 2020 18:01:12 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id r6sf3143341lfn.12
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 09:01:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601913671; cv=pass;
        d=google.com; s=arc-20160816;
        b=YpJSu6JZ4l6xgcVSAT2C6M5mSNyTRWAy4Frb2qzmj/kpi/YQP0Fmby3feCU/vxj2d1
         Mf3trG2JIrIBg1QHKDHfB4N5bAGxNd0vcXe8lmmY0Mk34l2P606G5WlY7J1+9sZ2e4lQ
         ln9evaVALWHDcp5VNupEiw+bJq4+AchhXrHYj7MjvFsmI0R3stEIZEHQhkRDlkAUseTT
         BYxJji08ntsh9xz3MkzWtLp7Lhg4E/UfM4XYz6vtkTr6igx5ARDcC+ITd4nb6v8m+rCP
         rk6LRpKn11TJNzKxiLB8yhTY+pYwXNtOn7cinUko2n/WXybBuTR2QVGCgTI8JzByZURu
         d5qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0mrx2kZtQUBNplWFxHD0Dkw/JmEu8XgHetznCNlXKY4=;
        b=Ix/NJkN2GtayYYfwzo+eISyYFvApBo4FSlkyO1G025xtE8mOJYYWOzl2Uu0ajjx3At
         TSawVrm3Frgh2dIC5G+rVIDbkZ9KH2hi9bh3vC839bDxmQsHxfk+YHsbslHMuO0YvlhQ
         VG29T4HalANHOZ5+nMgGejDlueDMWh8buMbne0a826S5cBSjWpJXfLQOy0g973tb6R4m
         RkJl842M8mLS0SzjA8lK6PxjBHBtoWhrRtJ1SeYmWkyyt5GZicNOoawOt3vSMQw+rw6U
         lmvzd3+tJkkrLcGf5MJLj6atJ4lZkZIeXb6XHZg81V3blq8VYbomHT3B3iKQ74uR5qa1
         uUlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GK57Nxy/";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0mrx2kZtQUBNplWFxHD0Dkw/JmEu8XgHetznCNlXKY4=;
        b=gW507szcWLa/Uc8QbikoXFqZ9+fe2oJKrG7JlMpxHNtN/4+TyJdUojAolGvCk90nzg
         /9SiIYeYxlYis1idB1jDjPzYFCV/KjBzXkBT8N03suZm52TSkVL4roadMoh48WXVL1Zs
         5wn3p4l4B/fzq18SIRTvH0C2L8GVN3g32nYGumOH0SEydMAOnbhG/z19EWrAwflQSVxM
         G3yVo0QV2eokp4OjDZ7OYm3/j8P5UYbR2zHv1s/+OM7VUaBzYKrhgBYONDDSwLygDqBZ
         NGXeHFNga0xUTjsgaub7mY7DI/ONn5o/696gIns551zHS+e6W2R4znK3iVjPoGDJ9Heq
         4hiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0mrx2kZtQUBNplWFxHD0Dkw/JmEu8XgHetznCNlXKY4=;
        b=gedZC8DjCQOusmR6ROPKzxrKD4GdNmRg4NlIeCCh/fTZJ4ELCLyESmPVk6RxcOU84A
         eApdifJDhXWqCGR+fQmMQvW4GKnesO09eU+Ee9eZ5lI3W934kpyIQ82Hb/Ov6eprLtL4
         eod2FH8kuLsyLuJgoOoTJIYu8+63ziWHDFS8DB4qZ2FB9X4dvOrYgs2quzDI0CfGIA0n
         yPnQsnn3qIognDLLqh7GhIhwl5XiwnJheuo9nhgnNxYd/VP7iaV7zBdsxAHLqEGElhzC
         55EEzYA/Wbkvjx2Hhdm9KyqK0av6KiBWTDxSMg+RA5yWsqCdkVSvo6GyWhN8l6fqs+2p
         slcg==
X-Gm-Message-State: AOAM532f0DjvDX2LMgXRe0aG1CxC+94MFdurCz7EbUec41STO/ssCLRj
	ojjh9fIz2acznbRNQB3SoFc=
X-Google-Smtp-Source: ABdhPJzmwVRq0k8U+gdt9GdVoMY+jj1b8xR3qtIuwo+f8nc0g3CT0MKwGp4+AacZ6/0kI1Uqoz7tPw==
X-Received: by 2002:a2e:b557:: with SMTP id a23mr147666ljn.5.1601913671516;
        Mon, 05 Oct 2020 09:01:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls416939lfd.3.gmail; Mon, 05 Oct
 2020 09:01:09 -0700 (PDT)
X-Received: by 2002:ac2:4a6d:: with SMTP id q13mr55321lfp.486.1601913669831;
        Mon, 05 Oct 2020 09:01:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601913669; cv=none;
        d=google.com; s=arc-20160816;
        b=U0lnlJ+rPCuVpPdNI8CjL9tnjGfaztUKuKhvNWvDYj2NZQce46IxphUEjhqH9tRwDA
         j3QFKRMoj3joADGSTsRkaM4m4L35IfaoG8LDnOXVOJgCczK+P1oz39t6AWGMWH3tZbQP
         F4D34TiJVKtYylRoAARO7YU9JQXKOdjdqOmtEiRAieCt0o2NYo9wjZVFEh0oWgx0bT4K
         hkgIXIxBzEluDugvCgPvc1xjpWAWOZs57o8BACqfL2xkyEYoiC+KDv3b3w3zEcIQ1il7
         SD9PZjT6JYzddeCyvzyavB12Hx8/z8wN7pMi6kM53BA7zup1zoHggSQ/zl+/oHR6DVI3
         wN7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F38mYIS/X8WyXHWOLkz8wuYqStbWhqnLSCK7WusSBkg=;
        b=Aq5lR0OBc/zEAX1GB+m5f0rF0kHNoAxcfEHcRKDTZwd6CNvMaWiqbZSDHZTqfeNHze
         5rz1bsSwH8AZgm/wCZbC6l8KMOfhrEgG4PKOCb5Nn9QkeQ6wD/GBaZBK0eid2/KYO2og
         7sbliQ7p3FvmHo4a0jcAnVqVYdyI8Aao3AY+IGg3+LcyxUD075eu1iUg7B8xfeo9QCji
         yC1suuo7Ir94fxpUQCAZmO1GSHrJmEA8GNw2Ey/PFhoHyqvL/4myOk6D7cwP+zmBp9t5
         Q7DxYRaYWTkoTJnNUUDQ2AcRUZh2z895j0z4Jg5jSYAjf69m015whYWJflq4D4bQ3zfG
         +0ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GK57Nxy/";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id o142si8778lff.6.2020.10.05.09.01.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 09:01:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id e17so1496510wru.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 09:01:09 -0700 (PDT)
X-Received: by 2002:adf:f101:: with SMTP id r1mr66271wro.314.1601913669054;
 Mon, 05 Oct 2020 09:01:09 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-2-elver@google.com>
 <20200929142411.GC53442@C02TD0UTHF1T.local> <CANpmjNNQGrpq+fBh4OypP9aK+-548vbCbKYiWQnSHESM0SLVzw@mail.gmail.com>
 <20200929150549.GE53442@C02TD0UTHF1T.local>
In-Reply-To: <20200929150549.GE53442@C02TD0UTHF1T.local>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Oct 2020 18:00:57 +0200
Message-ID: <CAG_fn=WKEtVSRLASSZV1A9dnPGoaZM_DgJeH5Q1WcLcFBqH00g@mail.gmail.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
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
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="GK57Nxy/";       spf=pass
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

On Tue, Sep 29, 2020 at 5:06 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Tue, Sep 29, 2020 at 04:51:29PM +0200, Marco Elver wrote:
> > On Tue, 29 Sep 2020 at 16:24, Mark Rutland <mark.rutland@arm.com> wrote:
> > [...]
> > >
> > > From other sub-threads it sounds like these addresses are not part of
> > > the linear/direct map. Having kmalloc return addresses outside of the
> > > linear map is going to break anything that relies on virt<->phys
> > > conversions, and is liable to make DMA corrupt memory. There were
> > > problems of that sort with VMAP_STACK, and this is why kvmalloc() is
> > > separate from kmalloc().
> > >
> > > Have you tested with CONFIG_DEBUG_VIRTUAL? I'd expect that to scream.
> > >
> > > I strongly suspect this isn't going to be safe unless you always use an
> > > in-place carevout from the linear map (which could be the linear alias
> > > of a static carevout).
> >
> > That's an excellent point, thank you! Indeed, on arm64, a version with
> > naive static-pool screams with CONFIG_DEBUG_VIRTUAL.
> >
> > We'll try to put together an arm64 version using a carveout as you suggest.
>
> Great, thanks!
>
> Just to be clear, the concerns for DMA and virt<->phys conversions also
> apply to x86 (the x86 virt<->phys conversion behaviour is more forgiving
> in the common case, but still has cases that can go wrong).

To clarify, shouldn't kmalloc/kmem_cache allocations used with DMA be
allocated with explicit GFP_DMA?
If so, how practical would it be to just skip such allocations in
KFENCE allocator?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWKEtVSRLASSZV1A9dnPGoaZM_DgJeH5Q1WcLcFBqH00g%40mail.gmail.com.
