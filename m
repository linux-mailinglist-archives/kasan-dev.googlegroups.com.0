Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQMKTL3AKGQERNJDBMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CAEC1DCE55
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:42:27 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id q4sf5256895pls.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:42:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590068545; cv=pass;
        d=google.com; s=arc-20160816;
        b=KJMW/3WydcQa3Br8Tz2pBFX5h49QeYw17U3GjUAmACM9+lTBwmX8XRR7CQIpMvPfvi
         1eeBYArP9f4VEupcDi3pF2jAUqhIz9MeE1OQVNPB0kBqI/TzoPzqvfJS0eEU/Tlgrc1D
         aOoZAJEaTfpQSfhxgMaJQDP936yQJ/OQQGV7cK0aJs/+3JxrCV2hT8+CH0I5KSCuzQt1
         NrMneHjsz7FVMrG4P4CL1QNGGO+NCEHG0i+yCrY67DgrcpNP3lkq5Yp25e18XXttF0i1
         JhgXSxCd44PQ7UTVc9tUTSLZDxh6mS9L3BUkmw67ijAyST6xb1hd5iPWg1z5Kh0WQjwN
         SfIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HfJWWvuX2uwiCcRJSY6P2ISDshcgXCa5j++rYZ2lEDI=;
        b=YH5uvmpMhbftLcoBh6JPuOgisQEF2l7GBwWR+OOlKZeF2Snh8q0FVvAsHxtcNgfY+m
         uoiBArWHo0UP+aKKf/7u8xIHrq/NOILq50/JeOzLDN6TL5rd1vXA00O+RNmozaJF/Zku
         upoRgE96XWwbg5Ubm8ju4IL57bQ39Xo4NL6hOiiGb3uDpDiPy+7lA+jZ4ioodp+A2nSL
         ba5ZQHzDqOJ4/NV8Msl3ia2SSUP35Q57f+OQWcEMykoyQ19yLOQayu6TEiHD/7zR1rJw
         A97cnuK44ZZQipSThRK/UU24+0jBt3t0jcEUn1GOPSB4B3DGEhqybcmTmwwWz9kSE1nI
         HaUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RmJEJ+YJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HfJWWvuX2uwiCcRJSY6P2ISDshcgXCa5j++rYZ2lEDI=;
        b=ZreJsR0RtiqZbbC+LeQHbaFLM7j0Xq7sTFKZWH9kdECKCjBkKuuPThIUBZuzXpKnfZ
         sxukHfzbeiaGwvZnDnBwamDt1eeIS3ZpsJy+Q+oYxvDqXGPbnlDa6Vs/v49xBb546SWH
         BDLMV6xSx0tl6mZYDqk2Gov7MQngUIQKInk3gVr1G2w4dJ5BkzvGtHXWLuWMppLCUG/Z
         YwCtKWdepYvrtZBrXydSRjE7TQWD1vL4b2IqRUpr3G+BzQPNf20i5+kAZZ8LIcLjgD+M
         JGnLtJw6TL9SEHIhRz1E5n1I8WP4RWC7ceZex1qx6DngFqFgJeQRctMtf/KV7F0czrZB
         y+kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HfJWWvuX2uwiCcRJSY6P2ISDshcgXCa5j++rYZ2lEDI=;
        b=EiBlPqmebIP8PhsuDlQdeqtEGvIjJCb3PaukyO8gPGbah2V0+3AfVhV3wqBU5CTKkE
         ZeSMnVr2cKbeYnIoMiyymNSJFXnZ7Rs5jW2H0nRlhlKETzmHH010hJYOdudBfK4WRvYd
         iMBueYWVcKjLVv4CXKi0fAo2RDpPiiSKgYHKLaowYxexIlVUXIU5mQbcNWmCR8eF/6hf
         tfmlddFSMfLVmIsIPVmKspQp0fgZm+1yVQhbXsOJeOdhF85MWSN2kMWBG5JfpYtgywSX
         X4yJozOKDKEnxNlctCzCsxwVk2878/wdScV1CdfYYyIQmETDBKXZ8p38gGfiG+6HKQLi
         e1zw==
X-Gm-Message-State: AOAM531XzD+vkizR5UPFaXKrLGYWwc5pMeimv/bLJsWethr2Wb0wRue+
	MxJcCFXRFffwmT/f9knZkMU=
X-Google-Smtp-Source: ABdhPJyC7sIqeWP7bV5TjzNz9Ikoo1oc+ymNxI1jmPbws1gqfiNBrZjG5QCIyj326PbU5wEO9l2h2w==
X-Received: by 2002:a17:90a:384b:: with SMTP id l11mr11592054pjf.89.1590068545712;
        Thu, 21 May 2020 06:42:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d049:: with SMTP id s9ls719722pgi.5.gmail; Thu, 21 May
 2020 06:42:25 -0700 (PDT)
X-Received: by 2002:a62:1c93:: with SMTP id c141mr9690665pfc.289.1590068545274;
        Thu, 21 May 2020 06:42:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590068545; cv=none;
        d=google.com; s=arc-20160816;
        b=gph8W41OqpUXjxfcZAjZ+xycJQhhDkiZxD5gm/QlDze0JQmDHS1tCulXl+/BlgwYQf
         Fp02l0jmx5X7MJaYDtkEvmfMKLuElfueedQqVuYsQ5NJ7jLrPHf7n3JhpOeymmzrYK0o
         CypBjFwSLyV1nAarhVA77NB8odL40q98PCGgbsOe7wckpJEwxlzjiQ6xwOUJxh/0nJRj
         IzUTHploJyhFpZR81VYGIFiVkbuvLcjPn7J4I32D06b5P/yBLCNsF8LGqwWIVwGpKfjT
         DNWZu+5ipgF6I7tkHgzv2tpBGxboOP/x8zXuT2MTPzj+iCD4n/AHgunG3wgl4cIHjyce
         +hRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YoQqHLS3kIB+JIi63PFAQDhXvHkeSj8OSM1KtqfRClU=;
        b=s2Kkk+nwiQxgmdNq2mARmMBK1l/TX6EAQY5UiOuS4P5EsvqYDRRd7tOwIHqiVww8Bk
         PI4fctO3LwuaR2Uc0oYb7f/xndUqv6Ir4hpLhTKi4QjN705/bN9sa/kC1zAPqIxDCqE4
         4YLKjsG2i/5oau7yNugS5ZvbzRGOl6iLeki/QCX4TF0h+z1bq7upFt4wJOqX+uBDkfdA
         z3hfq6LH49Rp6VwTTgXTrI0xuS4gkohGn95ARXQkYWlsGShs+kgxQbhYdEbl6VqXy+ss
         dgGTTwmY03XPZ3Sf2g1lwix167rw0tfR2ba6enPczhDiFNw27XOJrQxV8cjVJUxtgJXt
         ARTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RmJEJ+YJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id lt18si489273pjb.0.2020.05.21.06.42.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 06:42:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id x22so5525838otq.4
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 06:42:25 -0700 (PDT)
X-Received: by 2002:a9d:27a3:: with SMTP id c32mr7617241otb.233.1590068544404;
 Thu, 21 May 2020 06:42:24 -0700 (PDT)
MIME-Version: 1.0
References: <20200521110854.114437-1-elver@google.com> <20200521133626.GD6608@willie-the-truck>
In-Reply-To: <20200521133626.GD6608@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 May 2020 15:42:12 +0200
Message-ID: <CANpmjNMf7JRG4P1Ab2qsCy4Yw6vw2WC7yCgqUSBBOsBQdc_5bQ@mail.gmail.com>
Subject: Re: [PATCH -tip v2 00/11] Fix KCSAN for new ONCE (require Clang 11)
To: Will Deacon <will@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RmJEJ+YJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Thu, 21 May 2020 at 15:36, Will Deacon <will@kernel.org> wrote:
>
> On Thu, May 21, 2020 at 01:08:43PM +0200, Marco Elver wrote:
> > This patch series is the conclusion to [1], where we determined that due
> > to various interactions with no_sanitize attributes and the new
> > {READ,WRITE}_ONCE(), KCSAN will require Clang 11 or later. Other
> > sanitizers are largely untouched, and only KCSAN now has a hard
> > dependency on Clang 11. To test, a recent Clang development version will
> > suffice [2]. While a little inconvenient for now, it is hoped that in
> > future we may be able to fix GCC and re-enable GCC support.
> >
> > The patch "kcsan: Restrict supported compilers" contains a detailed list
> > of requirements that led to this decision.
> >
> > Most of the patches are related to KCSAN, however, the first patch also
> > includes an UBSAN related fix and is a dependency for the remaining
> > ones. The last 2 patches clean up the attributes by moving them to the
> > right place, and fix KASAN's way of defining __no_kasan_or_inline,
> > making it consistent with KCSAN.
> >
> > The series has been tested by running kcsan-test several times and
> > completed successfully.
>
> I've left a few minor comments, but the only one that probably needs a bit
> of thought is using data_race() with const non-scalar expressions, since I
> think that's now prohibited by these changes. We don't have too many
> data_race() users yet, so probably not a big deal, but worth bearing in
> mind.

If you don't mind, I'll do a v3 with that fixed.

> Other than that,
>
> Acked-by: Will Deacon <will@kernel.org>

Thank you!

-- Marco

> Thanks!
>
> Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMf7JRG4P1Ab2qsCy4Yw6vw2WC7yCgqUSBBOsBQdc_5bQ%40mail.gmail.com.
