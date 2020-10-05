Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBLU55X5QKGQEKNVX3AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 731CD283CC8
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Oct 2020 18:49:51 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id o6sf4238215wrp.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 09:49:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601916591; cv=pass;
        d=google.com; s=arc-20160816;
        b=fCeZoZpcnmSArriMpKHI0s5j07I8c8TPT4S3PT0ssCUaYJEV9vyeX/i7WCpF9Z9zMS
         1wtPPliAOZ4Grao4+B1Wa/qsHsg39pdXzz4YZ3lyIhed7rOuP9BdLMZzwqUfmUO4ufP8
         ffH92c0a6qmRROSnChbHfXpcFo9lzXWrhZkdQMsVGCRMvO4e/1EG/bWQFqbZItoU8zjy
         nD5xKMnSbpHanHU5I3l6zhD0yC9YRMtVhnGP9DX90JCC+Uo3S6iQgctJX+O/wvdER2sH
         EyZXhdPTAk1CXWl+BqZ4QIdVuK+AENK8HKR20PTXPvD3FVcvL3jN5J+KSI9ZvYO5CPIw
         vmqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5gdPHQ0xooeH1aXcIiCQXNMPTiAKNXfUoJji1wZinrs=;
        b=N0o6+0RR/40kfeQpaUKAAhwhj84WRIQvjA06bl6XU4GU+LEHpBbsmtWR53hGsTxmGj
         UQocFtm2N0VMaSOG1fmmigTbDurVI7B+JGVHMc35FeLApD20mk3melqv+jqUGmrcl9S7
         hd3IN2qyq4Q2H8EIJNu3F9HXsmRGHnQgWnTRsSgNA7i1tX3UAJ+/K6rnn/pLm3G4479j
         LRDTglaCyoo/cLKn7pJgWfrrGJmJ4GPYGo57pIDAuVaAiPxBU6zGynIXBAqRJFm47Dsj
         YVtgZKnL+vWjvxBP/9pgveMX1g8MMHLxn+x16ppAtddGjnWZNthWAnrfEByq+KNatMnx
         g2Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YVj4GC3J;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::541 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5gdPHQ0xooeH1aXcIiCQXNMPTiAKNXfUoJji1wZinrs=;
        b=Halwf2r0LX8d+AyOn7eGS8xi9cQKPKLNqnIcT8ahRHJF02oodkQD1fyx1P7OwMb2wJ
         5+2VyRURFFT5Ljd0SxmpBQzh82RdIqY2u2XbLWPFqQMLd/2/CDxgs2vcRI4DS+CP/kvP
         S2sM8EYjJfoBd5bI28PT1bH1t74nIrxikr+L/YdNBpD8jsrupwYp98jhMtxoH032Dr09
         K/j7lRMmwPc9/rn16KGgNENzf918n2RPA/20vZrKMReoL5gkuvW27ASoZ/5fPRvstTBT
         3HiT+uslG2kvfi2gwvPqi+mLK9RucDenmm9TYtgTLEmseWk8mzaa+3lNWnjKkgA/j3oH
         awCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5gdPHQ0xooeH1aXcIiCQXNMPTiAKNXfUoJji1wZinrs=;
        b=iEJXVCk+b3EHTyMe9VZ2uwpD1BWcoLci+Bdhr0EUMlp1LnwCIe4Utb/6G0/jicTnxJ
         +mykDUnnM2wIvQephjQVL7MYoQCW+Kf+fRLa58HsYknlTqvPCyuKGsJ4Tj3hkUpxsD+d
         X0zAJJ44WWqLAPed/0Ju2JTTj695PhH8n8COh1EpXWxRTGohTw030OXkI1DuflM78ZHf
         RrvAA6bj7M5X86Wi7Daf++BM+2ZCmL7rSSFQsm7BsVSJWB6DgeBeKkTS48JrHk+YdXF9
         ULSbSi39lXZ7m6uFdbv1jXI5S9e2t34BhrDsz+XGPJWzxhj8s1sUfQ9nnLZfrJuRLPAx
         VkKw==
X-Gm-Message-State: AOAM531zlqij/IreCDDBSHqO9haA4s4zZYLZ7M3LcZIq6eI25evj6ZVW
	93tygKA62cAynMXJpTpzxr4=
X-Google-Smtp-Source: ABdhPJzV+gewK6uqdma/1asxOxgqeeEimywSeWwy+cOGMaoWctPiVC+2zwzvX5VxvNV+XLEOX7mmJA==
X-Received: by 2002:adf:8405:: with SMTP id 5mr292012wrf.143.1601916591196;
        Mon, 05 Oct 2020 09:49:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c958:: with SMTP id i24ls19453wml.0.experimental-gmail;
 Mon, 05 Oct 2020 09:49:50 -0700 (PDT)
X-Received: by 2002:a1c:7c09:: with SMTP id x9mr248420wmc.181.1601916590127;
        Mon, 05 Oct 2020 09:49:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601916590; cv=none;
        d=google.com; s=arc-20160816;
        b=jUcZIPXnF+9+P/cn6WjUhcbPgQgEK3Y12dYgiMFpimR68I0dPBUu29mTenH5VyYaGI
         L8ismzz3Xs0cKJvB8A7ow7ESS7qiLyExRLBsXeoev3w9TCcgnoSOwf6EvTF6vp/+tKXV
         BpZ+hF3Bx9gqzxUsgI4Hb6T8zqoAubq+BEcnJqECD8Y39lLS965RodJUlrlsDAr1rnYQ
         Ln6KOuaKZxYjpcn3AHAcJ5xMtOQeuTvup1e8riAR7U2nGQDJlqSF/fi8GgVK0AhxECGc
         GFtIP+AyqqcPl3MTyAlGneXORG/5BXfHSPh/2dRF/Wa8N3MqV8whl3cwv39aHzdYO9Tb
         Xgng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e75sgfE0gBHuZ+sQh5xSznZKqRTfepXZ5BM13ORNfbc=;
        b=UbfzwHi405J0v2ifX8FY2bthWIthuie5PwQc2RtL302dN/wCctiH6CdCVOsegrzb6r
         /2iKCTBHfOcHUYUlxAOveRfCTrPR3ouG8h7VhCTHX+CHEw3syaN0FRyqaigAnoL/bNtF
         au5huSFUkvqXeoIP11Nj1aeqQHMTmw7LE1N6T8Bi5ZnAQ0gDzDs/OVhsvMYhvQWT+o27
         JwwoLzBUxM/sM2xlBhqfjUknaSCt1usx5g+rbzqNo7RGsYqAG/wlaYfFrvML74KShehW
         s8+wtbjQOvPVD9tD8FSI4sNYK3qjH9WveI+Tlle6j5e3VTG0rbaHomMQVc/uBQcnq5LB
         KVuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YVj4GC3J;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::541 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x541.google.com (mail-ed1-x541.google.com. [2a00:1450:4864:20::541])
        by gmr-mx.google.com with ESMTPS id z62si4169wmb.0.2020.10.05.09.49.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 09:49:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::541 as permitted sender) client-ip=2a00:1450:4864:20::541;
Received: by mail-ed1-x541.google.com with SMTP id t21so7387456eds.6
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 09:49:50 -0700 (PDT)
X-Received: by 2002:a50:ccd2:: with SMTP id b18mr555817edj.51.1601916589473;
 Mon, 05 Oct 2020 09:49:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-2-elver@google.com>
 <20200929142411.GC53442@C02TD0UTHF1T.local> <CANpmjNNQGrpq+fBh4OypP9aK+-548vbCbKYiWQnSHESM0SLVzw@mail.gmail.com>
 <20200929150549.GE53442@C02TD0UTHF1T.local> <CAG_fn=WKEtVSRLASSZV1A9dnPGoaZM_DgJeH5Q1WcLcFBqH00g@mail.gmail.com>
In-Reply-To: <CAG_fn=WKEtVSRLASSZV1A9dnPGoaZM_DgJeH5Q1WcLcFBqH00g@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Oct 2020 18:49:23 +0200
Message-ID: <CAG48ez3kmvvymiCemX_U1=CoRrn2Ayx1fbwAzPQ2jNE-qfj4MA@mail.gmail.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
To: Alexander Potapenko <glider@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, "H. Peter Anvin" <hpa@zytor.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YVj4GC3J;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::541 as
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

On Mon, Oct 5, 2020 at 6:01 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Sep 29, 2020 at 5:06 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Tue, Sep 29, 2020 at 04:51:29PM +0200, Marco Elver wrote:
> > > On Tue, 29 Sep 2020 at 16:24, Mark Rutland <mark.rutland@arm.com> wrote:
> > > [...]
> > > >
> > > > From other sub-threads it sounds like these addresses are not part of
> > > > the linear/direct map. Having kmalloc return addresses outside of the
> > > > linear map is going to break anything that relies on virt<->phys
> > > > conversions, and is liable to make DMA corrupt memory. There were
> > > > problems of that sort with VMAP_STACK, and this is why kvmalloc() is
> > > > separate from kmalloc().
> > > >
> > > > Have you tested with CONFIG_DEBUG_VIRTUAL? I'd expect that to scream.
> > > >
> > > > I strongly suspect this isn't going to be safe unless you always use an
> > > > in-place carevout from the linear map (which could be the linear alias
> > > > of a static carevout).
> > >
> > > That's an excellent point, thank you! Indeed, on arm64, a version with
> > > naive static-pool screams with CONFIG_DEBUG_VIRTUAL.
> > >
> > > We'll try to put together an arm64 version using a carveout as you suggest.
> >
> > Great, thanks!
> >
> > Just to be clear, the concerns for DMA and virt<->phys conversions also
> > apply to x86 (the x86 virt<->phys conversion behaviour is more forgiving
> > in the common case, but still has cases that can go wrong).
>
> To clarify, shouldn't kmalloc/kmem_cache allocations used with DMA be
> allocated with explicit GFP_DMA?
> If so, how practical would it be to just skip such allocations in
> KFENCE allocator?

AFAIK GFP_DMA doesn't really mean "I will use this allocation for
DMA"; it means "I will use this allocation for DMA using some ancient
hardware (e.g. stuff on the ISA bus?) that only supports 16-bit
physical addresses (or maybe different limits on other
architectures)".
There's also GFP_DMA32, which means the same thing, except with 32-bit
physical addresses.

You can see in e.g. __dma_direct_alloc_pages() that the GFP_DMA32 and
GFP_DMA flags are only used if the hardware can't address the full
physical address space supported by the CPU.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3kmvvymiCemX_U1%3DCoRrn2Ayx1fbwAzPQ2jNE-qfj4MA%40mail.gmail.com.
