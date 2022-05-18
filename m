Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBXNCSSKAMGQENMVG5OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C2A652BEC0
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 17:31:42 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id e22-20020a2e9e16000000b00253cd8911easf356000ljk.13
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 08:31:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652887901; cv=pass;
        d=google.com; s=arc-20160816;
        b=KMrNWYq+CddJmOCugo530drM+vJnykVkAUO7WBe02/sl7Hj5/9+FeKnWTExQbo+YzS
         TG19EY7HXhB1lsCSQI74QUXz1/R5XIXNsmfCkWVD87FkUQvo9SG94OVfS6h3QqT0x0VX
         YGT74I5gPvnGpncsfwdq7qNb3gpsg55SUnv8iZgzghvlffa1a5VUy5leV7wnf/6wRpbp
         q5O+vIwbpy/q4q6XfAZqrphguok+OlaDGV2XRWeiGeuX+iWim7khyF/SFDpWiN44EpM2
         w8TWl88PgbnFNHg9wTQ2LXokI/rXb54OXBU7LCtgfBei214wXkjHuNBUSb4imK1Pk5Da
         n8eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=h4GT1FGE7/ZsBSi2Hnsw6EvEM66U5op8ijWEd7uWgts=;
        b=x9NEcovm/q6OP1vOB0lgJZIzfobsr/Tt++qwlPoX3+uQgtg3ScFBRCuEM7lfRW35+P
         4+efGnc/dlzJ/FGQLeIpYyEL4iRaqZT91o3PPN4EIDH9T17q1oRx+tARf/AqevF5h+91
         DMKvxbFDrdozPYku8gOfKCvhtd8QV+gTrzVQCf6RV2/fMV4yq4HLkSXXdoDvKzf2lXzl
         JqRO0RcgfA6ZgSlTuLzNmFnMmeIEU1zsO3mXZxYaI0xJpHIzaKB+8sJGoP+0+sIX4oSt
         L8I421LwZalGvWm3z3iDpdpzZsZU9lmclnzWP9pF4Ewfrq1qMmAFPnFxx7Na8xyNCBPP
         XKVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QbX9x8QY;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h4GT1FGE7/ZsBSi2Hnsw6EvEM66U5op8ijWEd7uWgts=;
        b=Bzmgof3te0BKU4k+BdfIcet4+KOGwUrfdjutUFjkL5j8sopYO4/xoWGEz7DaudaWUp
         VB9uV27lXazLwH1Qft7UZqG1K580gyzN9whMMuSst4nNRXHsrNkSmvpPDa5DpFifxPGP
         WXy0B2bHTaCUjVmeGxL49IKlQ2CKLeELZj+ycffi5zJ6juAg/P41HjFowcA83wlW2u9o
         iI9EQIvTzd/Ir/+5WLVlXD+Fd6CTpPCN/25KQ1SeM8NxSe5ePh/Zf9/0C+xLxAxjuglO
         bQNT76VYCQkNqyD7GZao55S6LLXMgGF/rkLyctHMdBplswBFmxK7fFV5WSbS3dC5SXCh
         nxyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h4GT1FGE7/ZsBSi2Hnsw6EvEM66U5op8ijWEd7uWgts=;
        b=7Ys/L9zVPwh4B3595J+KPvVLJdBnk5sEG5qRmayWDQaYBSe2B6C5T18Orh87C6fbQk
         RHrJk6PbIgQxQSMTo+8tOkKt4w3AhyEYTzGxiphLQ6ihYVxAaaaZNg/ackkdMrUyEsMA
         KzarT/cqWaYJJBWSlYdevmWORF749t/OhFzoUV7lswxD2dHAwHGNVawaXxPYs07kwRXM
         6jLNjAJCffpowSZnKQq+oOX1cS4M5DhvQ+QkkIBM3TCBcSSE7ffsAAgkhsLC+59zLA9r
         e5Fuz7JxyeSVbx6/b24I5cj8Kl6cKjJ1sw3kxRPzd+GnrLQ89sqvjZliWSQNN9hG16lW
         R2cw==
X-Gm-Message-State: AOAM5313RjnBV4wppjFzw92C2sj6HqBNyMuzsRE/AZkbHQes5XxM+YFr
	bBcj39vyFmnX/7R9MM9DO3o=
X-Google-Smtp-Source: ABdhPJypSuzrMdR5K++U/wyl4rZ/XgeGHtbKGwyyRWP7CS3PnFr4MYKUlzODK6wuLxiJanCXtxv3nA==
X-Received: by 2002:a05:6512:22c1:b0:46b:a2b7:2edd with SMTP id g1-20020a05651222c100b0046ba2b72eddmr42479lfu.133.1652887901597;
        Wed, 18 May 2022 08:31:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:b0:477:a45c:ee09 with SMTP id
 f14-20020a0565123b0e00b00477a45cee09ls95400lfv.3.gmail; Wed, 18 May 2022
 08:31:40 -0700 (PDT)
X-Received: by 2002:a05:6512:3d1a:b0:477:ae14:9778 with SMTP id d26-20020a0565123d1a00b00477ae149778mr73532lfv.72.1652887900429;
        Wed, 18 May 2022 08:31:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652887900; cv=none;
        d=google.com; s=arc-20160816;
        b=q6OUTN6TyUJ/izKl4KcqpPT+vB89a6A0d2ieN6JYVM36psCXS5iUZS8EsSGjGRPiOc
         Hioone6F3H4Cs6BHlLtk+krpoa42fpSUb7w3nCkbl2A2t5QIl4xv2kyy4sckSBwMBHr2
         OxrdWS2AJSMoVwbJw9ugPJGJXt2eOi0PuvsJGZt7/TljTuzImoVhb7314ELIgWOZMonI
         UwZ9RNDjd4XyZbpFaVddpKj6QNI0nmy6EQo8m1zIgB+3Lmp3B3BCh0gTQnnzFmIYzO9n
         jjn6dcBftQrsB3Q/ivDoY9ILlw9RNlzI7/csyEjoX7zR3RDqU6ZanjH/6BdWNqvotyW0
         8dRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BsKITgJe0n74ro4jmQWlnQSOXtIrCCeeoRj5fvJvlc0=;
        b=DNGNUJB1+bRItPx+LD1F8iwqzj5sfJgmYRakza/Eiw9gwxkxWroh2ZZh0uVBe1HX8F
         bA08ijlSGHN3EvnycH9Fe26eINpsiqULQTflarGb/2qH5ZT5TiRW2icJooVsClxWXdWi
         NemO533uVRsmeCsTciP9IVD3YygqBZAyf1rnhCom7oOjkes6nXnnleCWjTy2+mj0jLTn
         vMO5gZgYaK73lkXNTYfw9Ew6ceuicnTfbHTyu2T55yWQINinTb1oOZ5aEsNlXL74xv1e
         hbsobb5IMKbdDuj4jPQZnSYbYrSQIpywOTmkQuHU53mujCbfMuS7yWxDd8tKuCdrJ3yI
         wMQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QbX9x8QY;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id o7-20020a05651205c700b00473b906027fsi131355lfo.4.2022.05.18.08.31.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 08:31:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id z2so4564209ejj.3
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 08:31:40 -0700 (PDT)
X-Received: by 2002:a17:907:2cc7:b0:6fa:7356:f411 with SMTP id
 hg7-20020a1709072cc700b006fa7356f411mr118908ejc.369.1652887898099; Wed, 18
 May 2022 08:31:38 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com>
In-Reply-To: <20220518073232.526443-1-davidgow@google.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 May 2022 08:31:27 -0700
Message-ID: <CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Marco Elver <elver@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QbX9x8QY;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::634
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Wed, May 18, 2022 at 12:32 AM 'David Gow' via KUnit Development
<kunit-dev@googlegroups.com> wrote:
>
> Add a new QEMU config for kunit_tool, x86_64-smp, which provides an
> 8-cpu SMP setup. No other kunit_tool configurations provide an SMP
> setup, so this is the best bet for testing things like KCSAN, which
> require a multicore/multi-cpu system.
>
> The choice of 8 CPUs is pretty arbitrary: it's enough to get tests like
> KCSAN to run with a nontrivial number of worker threads, while still
> working relatively quickly on older machines.
>

Since it's arbitrary, I somewhat prefer the idea of leaving up
entirely to the caller
i.e.
$ kunit.py run --kconfig_add=CONFIG_SMP=y --qemu_args '-smp 8'

We could add CONFIG_SMP=y to the default qemu_configs/*.py and do
$ kunit.py run --qemu_args '-smp 8'
but I'd prefer the first, even if it is more verbose.

Marco, does this seem reasonable from your perspective?

I think that a new --qemu_args would be generically useful for adhoc
use and light enough that people won't need to add qemu_configs much.
E.g. I can see people wanting multiple NUMA nodes, a specific -cpu, and so on.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA%40mail.gmail.com.
