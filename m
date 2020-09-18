Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7O6SL5QKGQEQWTUZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E7EBD26FDB4
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 15:00:45 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id s13sf2030548ljc.20
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 06:00:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600434045; cv=pass;
        d=google.com; s=arc-20160816;
        b=SM3yPSCDD45aUgedozBqpaE1Hu0Vjh0GDODpcNe1XsVuY84L2Mppy3yntBpGR1TUqX
         ScyxCs/b0l9stfm2kfS07x5D1J13QB3grgfBQt+hkbJNorpPBe1MKMzj9le9stSB4gK0
         qbgh/a2obh3M92pRXdxptNMZLpKB9lQxFRSXuc2Ukg/QlMGf1dF6tefZ1x5ggIKCX2rB
         21zWeufkh5O0Metrbck+oCWMO35u/1haqYSb/4SNB0Kc80vbRUyTWLK6V1t1egP3xCH6
         r3Rfk7mc4GG5s8d1dAzCQ09mI86R9cMLZ4qbOkUwEaQMd/XosVciUofeEu6QR0nui1Pq
         4RXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=dnw/yGMn78lXGKtdkdeIIt3JeQ3bEjJiidxVis46HgI=;
        b=D08DL7xQuvBx77GMJOeTo3Vq/Ys+QXBytTTV99P1vpOz4xuwe0Aa7anx+bz63/CM3h
         8uv13NAIippr6VrMDcy2UlQMtbzW7I5GM+bm7hW2ZWB2I6B+DnNhfMh3n+efYHrWKbIf
         82wqrTE2iLffkUU6pupcaGqCZO7ud8PkaegN6hzuxrE/ZiUGUem+VJIEEojF5RRdUJ3Y
         DlnBh/jaL1l44Jn2K8tZIeL+nWcPUrtZIunoxyePlL5+fOJwZIWJ+QlUvldlTvBWUPR+
         RXyA0BtkHnlJaSUxBUjGdhQ16ZYXAMxgAne/knkDfw7GVusUIAbdEiGe4GXM4LvLIShp
         3Exw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L7TWsV+U;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=dnw/yGMn78lXGKtdkdeIIt3JeQ3bEjJiidxVis46HgI=;
        b=sfB9arUYB2VS8vhwjQMPpeitGgmfDyNgIrxb1BEgyxJZeKs/T1s8Vr9rGWZ5yFZKWy
         mkW9Io4JyusmK16GytnGq+Q+xc6GTKLNrxXNvlsMHMtYaLS+VWWQtdK6Ybw0uJr3Wrl0
         NaAUFrP3kKBbbvAAxw0f+/rIh7WndsFK7Bd1HPScbQKN+132eLOtnJvHcU5kHd3TXVZ9
         4C+mpG38HLLC3KTgFwxrLbOoL3XGCQAgsEH5B8nPVTMuSexIFsV9GSuB0+4oADFgnioi
         XNey6vXFpftr7TdHC3zWWb/vQUBfwE7GB6xInN4LeszHVvBHJhtrEUeMto8MfwAJJasR
         N8aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dnw/yGMn78lXGKtdkdeIIt3JeQ3bEjJiidxVis46HgI=;
        b=eeBXI0S9luTNOkVxiY0P5bxIDvDtZKzu6VJh4BxU5tjzhRcvGId1w1QAeugDpDDfy+
         ec3NxDjQXliW+5mQ8jbX9D24JCYgCRF3RLYDTqvMQb8P85zJ/PdWKb19uau1xdNHS6GA
         ukWLi2jdLsTQq8D9JrtAJ2xd3+JxTpRS/kL3N0IR687o+rTm6DsGeLGfw7ANy3F9nGSC
         lDOEXtwclmObWAkTISG4fTWr/Wd6WvvsO7d8fSPZV4o0L2yZcLJHWiIqWIA9EQxfFLHq
         smMwHuYAHsXBBFohL/vM1MVhb2qoinolF/K4XrOs3e8vX8YAk9gtarC3h9YXi4HpVBtZ
         5DJQ==
X-Gm-Message-State: AOAM530Pu/NAFD4VsSDppshlu0z3mrzUhEBt6vTYwDqkIURI9na1vhS5
	U60dBLVgZQOEdjPETD8d67k=
X-Google-Smtp-Source: ABdhPJwVt3odiL1ytjMueXR/IEWUwK4Gyi9oloXPkGbeGwn9NUIPdaMSs8nFUeHep3AmM4swSIm9qg==
X-Received: by 2002:ac2:529c:: with SMTP id q28mr9460126lfm.104.1600434045476;
        Fri, 18 Sep 2020 06:00:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c44:: with SMTP id s4ls390148lfp.3.gmail; Fri, 18 Sep
 2020 06:00:44 -0700 (PDT)
X-Received: by 2002:a19:c20b:: with SMTP id l11mr12157663lfc.438.1600434044269;
        Fri, 18 Sep 2020 06:00:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600434044; cv=none;
        d=google.com; s=arc-20160816;
        b=b7aXuZ7a1B49253FI1S9izopHUR28Zlc7xZn9KDoR/2upcuoASCgFfYvIARHrqfbNc
         Dc308XZn2udWnw7dBegTF75tOnCWC6WufuSPcETV6BPFJXpkdlEanwoHfSqX96f1M9AD
         gQ6gAl/LIyWkC3BGRscGFnTfHRth+6qNXNk3JmPhFXdwHFfQjQ+WbgRiEwzjhhLqEi8J
         8gVdTRcSCYeVO7xlrBu6DKyvtzKqza8ZyOTBZCKum8eIaLIRHh8x238bGeQhTd/EzgCQ
         yN+jXpwLxwgg+VZX5Z0bRfLdg0XRj4DMS/4ks63XPOHrjYvqLnZnwfn0zWZB62oVO7/J
         Ah3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=j891grQjxK5nZuL7fttiNE/WOp/HbOWsFeG5TcMiTo4=;
        b=E0jmF1nhZBxZgV8ruej0WcO26lfBSSV8LzgrgpGuUW4EXJuMcYCn1WFwdfl1+UGR2U
         u4A8Ivp2TrhLjpoO+mxeGmdyJnt2T/4vnWR1wI67D4OuVJY2mZtUtd+GFZelcPwpCO1I
         x/aU2eFlikmklz9QhNIxOHE2Xvci3yoFFWxnWEZ82JVMYffsJ9nqjSjyYTBVGeg/ATRQ
         eYW6ryUoFCdrfAbnMP4bOl9dRGNl36Hag/a+efN1p5JLpvferakgle8JPYzSYPSd3XiA
         y0hOV2Bo5YZrs/+/g9Euwe8he7rKA1qSG/vBWq7USEAwyX3gHyX6cDvXPV9FNEjFhXFo
         s7Tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L7TWsV+U;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id j75si88465lfj.5.2020.09.18.06.00.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 06:00:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id s13so5238681wmh.4
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 06:00:44 -0700 (PDT)
X-Received: by 2002:a1c:e90b:: with SMTP id q11mr15357828wmc.39.1600434043544;
        Fri, 18 Sep 2020 06:00:43 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id z14sm5226677wrs.76.2020.09.18.06.00.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 06:00:42 -0700 (PDT)
Date: Fri, 18 Sep 2020 15:00:37 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 23/37] arm64: kasan: Add arch layer for memory tagging
 helpers
Message-ID: <20200918130037.GE2384246@elver.google.com>
References: <cover.1600204505.git.andreyknvl@google.com>
 <b52bdc9fc7fd11bf3e0003c96855bb4c191cc4fa.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b52bdc9fc7fd11bf3e0003c96855bb4c191cc4fa.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=L7TWsV+U;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Tue, Sep 15, 2020 at 11:16PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> This patch add a set of arch_*() memory tagging helpers currently only
> defined for arm64 when hardware tag-based KASAN is enabled. These helpers
> will be used by KASAN runtime to implement the hardware tag-based mode.
> 
> The arch-level indirection level is introduced to simplify adding hardware
> tag-based KASAN support for other architectures in the future by defining
> the appropriate arch_*() macros.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
> Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
> ---
>  arch/arm64/include/asm/memory.h |  8 ++++++++
>  mm/kasan/kasan.h                | 19 +++++++++++++++++++
>  2 files changed, 27 insertions(+)
> 
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index e424fc3a68cb..268a3b6cebd2 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -231,6 +231,14 @@ static inline const void *__tag_set(const void *addr, u8 tag)
>  	return (const void *)(__addr | __tag_shifted(tag));
>  }
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define arch_init_tags(max_tag)			mte_init_tags(max_tag)
> +#define arch_get_random_tag()			mte_get_random_tag()
> +#define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
> +#define arch_set_mem_tag_range(addr, size, tag)	\
> +			mte_set_mem_tag_range((addr), (size), (tag))

Suggested edit below, assuming you're fine with checkpatch.pl's new
100col limit:

-#define set_mem_tag_range(addr, size, tag)	\
-				arch_set_mem_tag_range((addr), (size), (tag))
+#define set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918130037.GE2384246%40elver.google.com.
