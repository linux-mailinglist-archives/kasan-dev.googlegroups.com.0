Return-Path: <kasan-dev+bncBDX4HWEMTEBRBL6TSWAQMGQET2FL4FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C5AC31910C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 18:30:24 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id c19sf3938033lji.11
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 09:30:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613064624; cv=pass;
        d=google.com; s=arc-20160816;
        b=I2OCJL16Jxx7rPZCPqT3ErQs3FveoQkkDXYYyk5GszLgriww46ORqnmWaqT1LFlEQW
         R7qz7ASRdPvW2KaTRQF/JZdujBZzGv2lNHJ8/0yz0JiTDKiZbTnxWjF4mlAnUY6dS+sp
         gGWbhB0SqqwxsozxtmfFsiw2PSqE1cC3TKbUvw0PqHYMlqPw9KdfAJyF9sD5+p+jDOrH
         He+ZleXxnlbUQlpdBzAEyMRJ6H/QXuQCyhX5oLAxXe68BJlJpzq+lJ5BfMHyAKkMW8N5
         /jBSdMG/GPEO/R2mAI5vDEMwzBwNq+VuKFscP4iiyGT2D7f8RZVehgRCgy7A1VFaJosG
         mFNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EmXFydagaDKQSuofEaeKKMcSQWYaXz8ZkpXGgZgPy+0=;
        b=AlGgqLhx1EKw6aRSIgQ+vuDuJN7o8bWzbEThIC/Y67opCBt/APy0yoyxEYSXDzoMRd
         nBbvdVM5ETgW8zEc80QMPR7C8nzOiGcPNVd9xm9I2wHjkDSKpgFws1bNDbaCDKlXvY5P
         giwdVRZ66s0U8husYm/bKv8WzqG+UsD/yQrpXll8sufXG30qTQxf8OVSRpEtj20sO8Wt
         4cXZaU8TOjA+lU1U9iurs7z9tPK0ME1AUosbSvCgui+46KepGP98rJlfL0+PhsdoBnSq
         haxLA52kJeggJY4g0Mr+ueQlyhmq8hyErRWWkm7oLia24C5x9U6cneiWz6GSZvib2SVU
         Yx+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dAcQsC5H;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EmXFydagaDKQSuofEaeKKMcSQWYaXz8ZkpXGgZgPy+0=;
        b=aVWO7M1LFHGFxDIOlx7JAws3WqLY/J65/rW7t58rMgo7sSEhZl4cSn7zLIEK38eT8W
         ClxfBeY0R4fhS2jVAeau7K2WOfccDrYxKfm8yv6sn8s//vOhLZhq+cSKzCyfIZNAUtqU
         4UlGPZMAQCeQsZeE1HI59sIC1a+2ScrAjx5+1EWqRN59n/B2Hi4tcF1W5fNW/JIoPlLX
         8UcT5kQ91nfReBm1by4GgbnGOzot0wUe3tdpv7ulLcoB9S3n+VJoOvZSD3ifOvR7vPwK
         pSyzKz+ZK7nRti/skmfjXnYSPZMv1Ph57PGFhq1GOT/gPz1A8GjROMQPUic8XHMHDL/e
         EWmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EmXFydagaDKQSuofEaeKKMcSQWYaXz8ZkpXGgZgPy+0=;
        b=mkw0fyEYEFjlmmdYkrwHXNE+TfT43cc5kqvogcRl49KhBDPRGrzaX1EmSntcUVqtZr
         d/oGCFZXTqXW2zGTaGgllRC0d2t+thdgp5v+NP2QS8b2v7h+lI6HX0fmQKR0n06gGvuB
         5kwbVi+7K27fEOy61rb8l7QL93YfMXFqWkQDCfwOkwksv1QZohGiF5XQfCcduTwaTRPi
         s7pe8ThdpMlRdwHQA6MWztMGZ/k7W2rXm2jbgbDjT/recBbmPe7LCHNTwmZjhpUZ8a9l
         dUs/aPTb10Jp+plaBZJ3wRl34hf1Gnwo1DgR6PV6tJAMroNzTvDDaRBDmfqbvn9rsQpQ
         Rs9Q==
X-Gm-Message-State: AOAM532xw2nfzpmjXTeiNlRURpQZR8ii7X4JHBEdXydjJE3rQTDGlRfk
	rMIoLfB+egPmvCZa72i72n0=
X-Google-Smtp-Source: ABdhPJz3tvlUl8R6kBkJvp00sYaHBJLs6+30wQ+HRai83HgCaNXX1+8lRSlK6XW2vqFFgEs/jPYpNw==
X-Received: by 2002:a2e:9898:: with SMTP id b24mr5712034ljj.344.1613064624025;
        Thu, 11 Feb 2021 09:30:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls1093308lfu.3.gmail; Thu,
 11 Feb 2021 09:30:23 -0800 (PST)
X-Received: by 2002:a19:4cc2:: with SMTP id z185mr4636171lfa.83.1613064623000;
        Thu, 11 Feb 2021 09:30:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613064622; cv=none;
        d=google.com; s=arc-20160816;
        b=MTawvuFXFcSJ9JAIDWnWTu8JuXBeKEZkv20bIz5VMg9G7BA9UxH7LYxfp+VsFEtzr5
         uCEd/xwPg0nR17wXw6LEOMcDXVFcA/NZIHcvuuHeBDpUOOQ3uj7qGrdAUDQFEKZEHOY6
         /84Kbyo5+3tVrj9hpzSVS9ft53LimX4ahwkPB/yVT3qobmiYfIJNlzM8ri30/oFtjWF4
         RMoOy6HLU2b9cxNXdYO3+VkMwR2CtXddy/+IgjQo4rNh9MN22BCvc8rtqrCtRJGrppsO
         l8GtDOctpGtmstCQFzjViir1S4M3Z4Ely/NkavnlGVaLesohtnKLb83ECHjOelICg72/
         jH1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a0sLUNT5ihF6g2jXFc7aCUKZ679+kNYXd0ZfZV5p2dc=;
        b=MlfWGUWJE59vUhOszXu0Rs8VxSeVZaR6bpV6N04oSxTeHEkalN2QZBYsfAuc2tJHWj
         5VcMc2qVa3zMlBBe15FmsZ3nXMpPJhh5xvNTMz2J+HIYIU1WkL3q6UkDPxOimf5h02Ex
         nZmsChwdsRjGopzbR2H6zJbrjDoPUE4WFgCcTnj64wj/xM7WkHwAqOzsL/hdLLGgSsQd
         tTPgMKo9eOjyTBSADUBVrLqJdVTfzOB/njvjQ9qULwHA+Gg0g6xR4UZxRcEVAmWrf8Oj
         Cf2RoqShFiPbHOzWckZNEA9i2dJHItRC6aNA16QyaYI0CmvKiKClhydfDZCFp6xineIC
         om6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dAcQsC5H;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 28si271039lft.12.2021.02.11.09.30.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Feb 2021 09:30:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id a25so8362511ljn.0
        for <kasan-dev@googlegroups.com>; Thu, 11 Feb 2021 09:30:22 -0800 (PST)
X-Received: by 2002:a05:651c:233:: with SMTP id z19mr5391008ljn.486.1613064622185;
 Thu, 11 Feb 2021 09:30:22 -0800 (PST)
MIME-Version: 1.0
References: <dd36936c3d99582a623c8f01345f618ed4c036dd.1612884525.git.andreyknvl@google.com>
 <20210209170255.GG1435@arm.com> <20210209104515.75eaa00dea03175e49e70d6c@linux-foundation.org>
In-Reply-To: <20210209104515.75eaa00dea03175e49e70d6c@linux-foundation.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Feb 2021 18:30:10 +0100
Message-ID: <CAAeHK+wuvYDhswWp3VZ+C8uDUVjsZgssWQYnP7CzuoUDgr6=bg@mail.gmail.com>
Subject: Re: [PATCH mm] arm64: kasan: fix MTE symbols exports
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dAcQsC5H;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::231
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Feb 9, 2021 at 7:45 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Tue, 9 Feb 2021 17:02:56 +0000 Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> > On Tue, Feb 09, 2021 at 04:32:30PM +0100, Andrey Konovalov wrote:
> > > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > > index a66c2806fc4d..788ef0c3a25e 100644
> > > --- a/arch/arm64/kernel/mte.c
> > > +++ b/arch/arm64/kernel/mte.c
> > > @@ -113,13 +113,17 @@ void mte_enable_kernel(void)
> > >     sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> > >     isb();
> > >  }
> > > +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> > >  EXPORT_SYMBOL_GPL(mte_enable_kernel);
> > > +#endif
> > >
> > >  void mte_set_report_once(bool state)
> > >  {
> > >     WRITE_ONCE(report_fault_once, state);
> > >  }
> > > +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> > >  EXPORT_SYMBOL_GPL(mte_set_report_once);
> > > +#endif
> >
> > Do we actually care about exporting them when KASAN_KUNIT_TEST=n? It
> > looks weird to have these #ifdefs in the arch code. Either the
> > arch-kasan API requires these symbols to be exported to modules or not.
> > I'm not keen on such kasan internals trickling down into the arch code.

Understood.

> > If you don't want to export them in the KASAN_KUNIT_TEST=n case, add a
> > wrapper in the kasan built-in code (e.g. kasan_test_enable_tagging,
> > kasan_test_set_report_once) and conditionally compile them based on
> > KASAN_KUNIT_TEST.

This might be a better approach indeed.

> In other words, the patch's changelog was poor!  It told us what the
> patch does (which is often obvious from the code) but it failed to
> explain why the patch does what it does.
>
> The same goes for code comments, folks - please explain "why it does
> this" rather than "what it does".

I'm sorry, Andrew.

Could you please drop the "arm64: kasan: export MTE symbols for KASAN
tests" patch from the mm tree (but keep the rest of that series)?

I'll post a separate patch with a fix.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwuvYDhswWp3VZ%2BC8uDUVjsZgssWQYnP7CzuoUDgr6%3Dbg%40mail.gmail.com.
