Return-Path: <kasan-dev+bncBDV37XP3XYDRBV42ZX5QKGQETKKDTUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 89D6327D219
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 17:06:00 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id r10sf3730486ilq.6
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 08:06:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601391959; cv=pass;
        d=google.com; s=arc-20160816;
        b=GtP2XPrN762+zYIFS2ULCxprGbbh1Rzmk/DYYC2bAkiSSyPxcUzRUx67ow6BzKAqEu
         0JWmHyHjyAelGjfbOYhjT3j3zAqbi3I3su6J8donRhdxgtkTZnq2qgqMEZe7TUcvlql1
         9rNJbsfsG9RQk57GJ8dt20mIi4khP7HCM0vQG9i0m9GrNTRYufxGpDVHY6MZHeE9Zldp
         adt8thJmK9Ys4zm97hQh0HnajdbkTDkG3VjzAqD1L9SLRZiUPOunh9ZBbF0KV3XDBqzS
         GL8k9f9Scf4CXMB3GkgwxJS+wYxV+ki6eZhZk4bsQPjqJRLywFCNnbE01ijMN/9jophk
         OkWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BPlPWxKocYQJVBO2G16d+AS5Hk5Zj0e4fU9Duis9rhw=;
        b=jw5os4l17+hadUci0zIcmaqIZlENWENMvgIM9VJ0pl7PzOmozaKEyp1NJ67ZtUCTZE
         8aDNzT2xDM9Wj4enRcQCXnQbATYZ4VHx0nEDB8My50RAIdHscjoxZjO4nkm5TViWzihY
         PO7rgkh9Z3nz4a/LtXALXyFUnwHMdVj7IHsfYeOzE0dcKWjPmKfPtvUeSfCNxjN9nO4I
         4E0wcRAPZZiCdndop4JNBrg2XBN6oftm47R0oYmF9zsQDsMfS4zjnTcNVG4dz6X1GvrU
         TkZnheatcefWOnSWLEmTVnoX9jyXqv1RCPakVnYLovG9eeIdAcQvmuhj1FAL6qIlDklq
         O5TQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BPlPWxKocYQJVBO2G16d+AS5Hk5Zj0e4fU9Duis9rhw=;
        b=Lw8QQZZuOz99oQPh1rELH4lRytLnvViQsvrZY7qvEFT2ouvb8G5YoqioussNtOtuL3
         k9BcbV7XBO0ceeqLieZVmPqeB4vwSwWP0stiBSA1FwbpkT5cbDEtczPH2lu2xFzhat8v
         jFA19Uxiep5Gc+ciL2Bx9YtdmMTrj2mShnZJ7kr7D0IsvQV0HHj6wwxrm40hLscAis02
         erleeOVzz4dN5+hpu9ph9/gzK/QUUWimw6rfYwe9gw1j//uxQfg3aaRkIzYkqgvBHNf4
         2YZcYIVLiR83UjAugx3XAuWGLsSy3BsM1M/uHTIwrJBDJy5M1mgnwnar+sNh9xWjLds5
         28/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BPlPWxKocYQJVBO2G16d+AS5Hk5Zj0e4fU9Duis9rhw=;
        b=D50RhtLr2+gkjr4EBzNJDBe7MWhaX8HjBwWwdyOUE7+ahGY7BKKcKfZe+j67e+oQs8
         fx4bqD+gghT38npbG9V/sHVUwhrNDzjYStQAb/B1e2vdFIl+2fqKwp2hNAr8zZGJDrab
         4xCEOYkoJWF0fHZDxPUUooUnLzXUMVE+z28hSKV4gsEFEaXwUut2sLlgHHJFy6vnRwKv
         +1FP3hCyyOWvlRws4GWAWysrYKKMNGizbAa9o+7iT2w49o26w948G4fJGUK96148AtK1
         +dtt7PtaUY1ODUQ+GDLP0xQa+3DxF2ai2lAoijdsjdyNjKabhwBiwF+dvgWjVWmS9nOt
         efhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OW+SgxSHoMG449/q+3FYpaLFrrnEVCgVdVMxP4bb1StiQww3C
	LpNVioGv0ObXr4bfG45IfCw=
X-Google-Smtp-Source: ABdhPJxyaKzDhzK05gR0hGWJjLMMYXsDIPmGeqdAKTOXqBbn4bDBVoXZ0v6r3JU8eMnIN7IWVtUmYg==
X-Received: by 2002:a92:1f44:: with SMTP id i65mr3345022ile.280.1601391959460;
        Tue, 29 Sep 2020 08:05:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f910:: with SMTP id j16ls766611iog.6.gmail; Tue, 29 Sep
 2020 08:05:59 -0700 (PDT)
X-Received: by 2002:a5e:9613:: with SMTP id a19mr2771414ioq.116.1601391959014;
        Tue, 29 Sep 2020 08:05:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601391959; cv=none;
        d=google.com; s=arc-20160816;
        b=Xrb9ZcdddttmQM4bWHV1vTwI6hr0KvZs0OuxL3ioT+WxQrI8kEjXyiT6GcSzcA9Hwk
         iXy/oQlmaVptZY7ybcd4rGo2GPtzWPxfo03nibSmW7AafFI/zM+ychWiXo9nQgjesy8W
         KQcm2QBcHdOoFbiup7jti6I1bcGmJeLzojm0J94U534EXijxW95t+YQtFWm5DJsBiENE
         3Uo48AYw4WqUticgvg5MDbeT+QVbRbGEm6aIpzLLr6sua1fCs7RkLeZp0804aQcTgtuy
         827kN62D5ZvWeGb/H0jyN/VsBlUtM6O5CUCGOPsQrvAYQ2IwXn7FgoEk8AlcU1bR4VXF
         Fg7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=YAFIEDr/+k4sqb8bmdJs989UlhRYHSX6fWQAMiQai0o=;
        b=Rtlk9cQefuW9YCa+3D4mfxOJjZyKd9kGSr8C6iBKBOTReEVJQmt+k0BDKksdK3U5Qe
         H4+Z1pPdgGyk/ih/G8iJrSLafVLfYNitdQHYJ82gp7QDSc8OMth5JX7R8o3jJPRiptWv
         Rfn4mohQvbc3mjM0Z1fRc8fxoM179L08FGY1uKsDtCW0Fl/B77wHYkac2Jp+jbabR83B
         NBfZ2l65UY+Nnbn9qFPUPbIT7i82F6N6PrzOTEtRojKoWssXZLnvTiNm+n/rnlXjWx2g
         G9ELny7RJeorZydJD7jXsruebp1Psu908hjFyTropnRTNKOPLxFurw5SrPbFaaoVJK+3
         F1yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a13si643849ios.2.2020.09.29.08.05.58
        for <kasan-dev@googlegroups.com>;
        Tue, 29 Sep 2020 08:05:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 566D91063;
	Tue, 29 Sep 2020 08:05:58 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.69])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BE43B3F6CF;
	Tue, 29 Sep 2020 08:05:51 -0700 (PDT)
Date: Tue, 29 Sep 2020 16:05:49 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
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
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20200929150549.GE53442@C02TD0UTHF1T.local>
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-2-elver@google.com>
 <20200929142411.GC53442@C02TD0UTHF1T.local>
 <CANpmjNNQGrpq+fBh4OypP9aK+-548vbCbKYiWQnSHESM0SLVzw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNQGrpq+fBh4OypP9aK+-548vbCbKYiWQnSHESM0SLVzw@mail.gmail.com>
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

On Tue, Sep 29, 2020 at 04:51:29PM +0200, Marco Elver wrote:
> On Tue, 29 Sep 2020 at 16:24, Mark Rutland <mark.rutland@arm.com> wrote:
> [...]
> >
> > From other sub-threads it sounds like these addresses are not part of
> > the linear/direct map. Having kmalloc return addresses outside of the
> > linear map is going to break anything that relies on virt<->phys
> > conversions, and is liable to make DMA corrupt memory. There were
> > problems of that sort with VMAP_STACK, and this is why kvmalloc() is
> > separate from kmalloc().
> >
> > Have you tested with CONFIG_DEBUG_VIRTUAL? I'd expect that to scream.
> >
> > I strongly suspect this isn't going to be safe unless you always use an
> > in-place carevout from the linear map (which could be the linear alias
> > of a static carevout).
> 
> That's an excellent point, thank you! Indeed, on arm64, a version with
> naive static-pool screams with CONFIG_DEBUG_VIRTUAL.
> 
> We'll try to put together an arm64 version using a carveout as you suggest.

Great, thanks!

Just to be clear, the concerns for DMA and virt<->phys conversions also
apply to x86 (the x86 virt<->phys conversion behaviour is more forgiving
in the common case, but still has cases that can go wrong).

Other than the code to initialize the page tables for the careveout, I
think the carevout code can be geenric.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929150549.GE53442%40C02TD0UTHF1T.local.
