Return-Path: <kasan-dev+bncBDV37XP3XYDRB7P4ZT5QKGQEJEMJJNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 45BDE27D067
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 16:02:39 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id g1sf3550377iln.15
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 07:02:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601388158; cv=pass;
        d=google.com; s=arc-20160816;
        b=K7PeFdzEMyP/8mPiRtUm+WVrHbv2V29dqUpu03HacJCKu4zirxdKALBgB90CEV6Ka7
         Lgzuu2WSobJGimI0wBZymd4L63NKFKFQEboScxxC/shSTFNVnYmxAnzfqMmRriKORzez
         Uk1Wfm+0/Rdan0eRHgdIIc50P5WUVF/gMHbuKUr9MWU1SszYz/Ia6omJzZ5v5i8lQgpP
         OUHiKYu0Ef5K01wWYmlXEilAkg3jX08buLkskeDchtMIc9fioO88w4qMtxxMgjpsTNRq
         wUbAAO5PeSzi674jYyyTvPxL4CVq29u4tefdG93Ao4RFTJAUy9nd8Y7kmw0y8TPwseZk
         m7bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MS6cdGX6IfHWOVSJp/O3XTL+7mJ9j8uW+WtpP3NEWjM=;
        b=QxHNYSW2NF5s+yYfFDqnykzQVA66eRfl+vra28Jgp9vmAeIQNHTSA8cFz2V8DVYVSn
         cY4k57RtuYoHarsTIYtfYHpSCQUgt4aCgNRUdZ4AYJ0kVNJnlhLnPtgQsDAa3k6wWr5F
         BN5HmgDhGNq353cPAXKl5ztPwsplOcuKFcglcHvW5cNR4/IGXHHuee+CdDNMUyoItxwt
         xGsFJB+5QG1jxG/mqnpnFMqR3qXmjfFGAFQ6NN3aSz0Lj5NxN/I82KuTybYQevwemOzX
         3Ya4VU9HTsw0qWnTFmqLhPQPBZ+vF+yhAhMEzpTnuCFBrg8q4aEMwqXH/ktdUdBxm3q0
         8XOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MS6cdGX6IfHWOVSJp/O3XTL+7mJ9j8uW+WtpP3NEWjM=;
        b=hHbEbjSEVRTcDeq/E+rjN4tI5pNqXS9bLt4t+SDbLDI688xHfIfIH4DxsBSiLN014P
         woiWI35czrf3UXhkUO8EhvH3B/nD3LZtYK9YR6YiUcrvXSge2amBRkHAlpXKGgkx3Ewf
         79O1KnmV914CmAvzt44X8q+39i1xWirQo2LqDVVfff3Tu8cDrjzZ6hiSineuh+iUXpCO
         DWlM7XTZkA3mdUUMKB8NKmScGrAP10nzFlYF4B3VtigMqBr7WVSBFemAu5w9AnCOx6uw
         WHaAe15Z7d6UAlNQkPefXm9jl/vBaU05joGP4kUgeS4uKlkJrW7EIkM/3DvUMljXsN2y
         hi+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MS6cdGX6IfHWOVSJp/O3XTL+7mJ9j8uW+WtpP3NEWjM=;
        b=p3vOVABM1sZ54VwL760xHeqEG8GQZl2JjdtwZ4uieE6JXXNinn/onI3AU08ImTDAkX
         djJSV7PBQ7pDnCsqwicYYNaQynUJdMgBvIR/kj0r9kywK0BsNKeH9b1g1s7rrWV5xq8B
         3Ut6P9p68XmCEkwuq27vjPxGVkVvvrz8V1ApWDqJiyD276grAJHzMIBueauHorFLCTmf
         a0dViCIPcCisPzCn7TTf3vFc9SifcuSGB6dHoVVBUUkrifGsUButslMC/Jbx5yY7yokz
         /GqQ19Ajb8F2iXhYPvNbYlHqh16M1eiEKjVvIWWkUIjYCrsXbGe5f2g1tNPFzHFpxxM9
         ynMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533M+VdJPubgbIwyhRz8oUDp4M50RyElWBa3g+qJE0P05n2gVTZL
	l/+cN9Bvw6UeM9BVSW5KxLU=
X-Google-Smtp-Source: ABdhPJz5YuI0kZRfzF+ruQMlyqiMhzQFyXGXRECAN2XSO1ukLXjXXIEehG5/1GWHomDoK4F8okQH0Q==
X-Received: by 2002:a6b:3bd8:: with SMTP id i207mr2577620ioa.150.1601388157888;
        Tue, 29 Sep 2020 07:02:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:14d2:: with SMTP id o18ls1311938ilk.6.gmail; Tue,
 29 Sep 2020 07:02:37 -0700 (PDT)
X-Received: by 2002:a92:8742:: with SMTP id d2mr3118703ilm.153.1601388157251;
        Tue, 29 Sep 2020 07:02:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601388157; cv=none;
        d=google.com; s=arc-20160816;
        b=F8XVBRbM1D5oJT4dS7ER3vKP8mTfHOiKOFE20CtxUQVk6Vc0HPa4b7i42Itt6Apftp
         7wUtUPgBbE77MUufAL0GkTp/sXCn9+Fd8hPKVQZAqmG9mAU27BGC2ZRp1wBl3JtB+gSX
         3dc/BTNRbbR2QZJxcM3pGiDCUhB70s/IW6PWpdmbrJx49etNbzVtReTOGwLYV44JzaoT
         NquHZxYnoLY3Bp+64KmdNpTZDmi2uTCdLZFYvBKqVlKK83jkYQFkk3+kNYeDqCS0S75Y
         jMjr6+IJ+AA88KPnZm0qTiDJCxIDPaSUebpNkNax/Ch1p6YmTEUvZ7wmxhbtjOWFtPrp
         83nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=DWZoY0cfNfLiRVkVMiwHWltX/QEEJoUPsFYcZfXaYck=;
        b=pm1+cYxm4LFr4Dh3HnIWU5Qvh/BPUco8xzcxu+1+mlJkFIQ2Rg2L6XizYF6BFxs6uJ
         i8ezCW4/knR0NrDMGo5PvFvgM5IOgChUAFUo/AFzER7w6ixWDfPKsmIHMsoWY2V0QD1b
         FBnKBoL2uRnv7w0m2zUG1daOxPUInYzGQhAe/AJhNi6jx7jkl55t5tFIiHemKA58X4Fj
         MSSgjAaSedTTh4qJWeciB3ZukIJS27Dk2BhasbS3nF/jfXX9FS9TsOhrRcsO6K6w/Q8x
         ms3IK2gUtJDBtDAwBRt0xkxhml6yvZPu8x1uUWGz0q5iHB6MloaZPVEahNRsd+27Q66D
         EIgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z85si411410ilk.1.2020.09.29.07.02.37
        for <kasan-dev@googlegroups.com>;
        Tue, 29 Sep 2020 07:02:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9C5AA31B;
	Tue, 29 Sep 2020 07:02:36 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.69])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 921A33F6CF;
	Tue, 29 Sep 2020 07:02:29 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:02:26 +0100
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
	Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
Message-ID: <20200929140226.GB53442@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
 <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=WXknUnNmyniy_UE7daivSNmy0Da2KzNmX4wcmXC2Z_Mg@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Sep 25, 2020 at 05:25:11PM +0200, Alexander Potapenko wrote:
> Will,
> 
> > Given that the pool is relatively small (i.e. when compared with our virtual
> > address space), dedicating an area of virtual space sounds like it makes
> > the most sense here. How early do you need it to be available?
> 
> How do we assign struct pages to a fixed virtual space area (I'm
> currently experimenting with 0xffff7f0000000000-0xffff7f0000200000)?

You don't.

There should be a struct page for each of the /physical/ pages, and
these can be found:

* via the physical address, using phyts_to_page() or pfn_to_page()
* via the linear/direct map, using virt_to_page()
* via the vmalloc page tables using vmalloc_to_page()

If you need virt_to_page() to work, the address has to be part of the
linear/direct map.

If you need to find the struct page for something that's part of the
kernel image you can use virt_to_page(lm_alias(x)).

> Looks like filling page table entries (similarly to what's being done
> in arch/arm64/mm/kasan_init.c) is not enough.
> I thought maybe vmemmap_populate() would do the job, but it didn't
> (virt_to_pfn() still returns invalid PFNs).

As above, I think lm_alias() will solve the problem here. Please see
that and CONFIG_DEBUG_VIRTUAL.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929140226.GB53442%40C02TD0UTHF1T.local.
