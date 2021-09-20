Return-Path: <kasan-dev+bncBD52JJ7JXILRBVX2UOFAMGQECLD7PCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id EC942412806
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 23:29:59 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id o2-20020a1f2802000000b0028db8be8efcsf5340612vko.5
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 14:29:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632173399; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nl7sx/Qz4gczgTkwEIJNuh30N060re22aydLdFD/OysDRb+bpR2o4Z2Na+Q2J5/aop
         R3+lids7pZsjuJOH9qNRLHQGzi/amWZreD1gcKLS5d+sOyIxxzq+zTieVpQsByoDodSN
         pA1GEuxPaj8ysdljKZE6xrkKjOeh9FB+fMD1izGTooyaSSNeXgRFG1TG2GmtbFlMCL0j
         bPGiY0Hw9VpnLcfSxw0TUKVi4TauZ8ghvkROIQk76Oh4KWL1Cjpyf3GuR2F21ACy+NAi
         maDbao4mmO7zSzG3EfK9aROaru9ugBIi5OH4TrLAddw8WASMwt9AFr/mvuYPV6Skev+R
         GYSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CLtE+ZXFyEcXYjYTo5O70UyeqpojAgP7p1y6FBNjdu8=;
        b=MSBGmEIwNZ9tt7eVfiB+JQwHXbhOGjpXqcKXM/Z0KCH3FsuWHUddkSz9eB9dIoeUry
         a1HBbqSgqm8tIyV6jGNJbKGe5akbNPI9Qq3G8ceqaeAMANJF3IHIzzx+gW5AXcj/vWdj
         0EyW53nF/UVl1RprgEEzu2sZgrqZR0jG7fNMm2axBY19uPmdDwzO8v3CNLutgBJNHcLM
         piAd+pwDgdyW5WElWySA+3rtOiuMt91E6w1I6aw3lHTHytG9Wj/b0JlYndMCrydw9+Ut
         GsuGDfEZWBcB6WBva8liN9ITGnJWmkjZww56mBxGLhgvhgtPhSGzO9np1eGXD1YMIGrX
         GObw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AlZLXTBj;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CLtE+ZXFyEcXYjYTo5O70UyeqpojAgP7p1y6FBNjdu8=;
        b=GW6Shhe5g3hyQRUNlWeuCJme8dHz0ABhPpTJlmNfro0GlKrNoP0SK5b/1AdR91+1AD
         EOf+mqiglYmHEwSluTITJ5sb2MqveJfTQc/M2DvNuaEqfkWwk5IBDsNL5PUjMoRaii+N
         7XSRumSlu8FJea5oTCrXD4DZ7PF2fTSEm6ZI7DiCl/RzfWNHhrvkVQ41bHLbsFW5w+uC
         DkP/TDQvmMZZlwUFInMnbdLycV7oZFb5YJyDLfGrkxFIqFc3pdbS6vPFJWh6bLhwNdus
         lpS7G2dORfo0lKKHRZtH8kZvclcQoG9wK33Wy/5VxCsbaHGQehgUm0Nfhsb8Pwvp8Kge
         p0gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CLtE+ZXFyEcXYjYTo5O70UyeqpojAgP7p1y6FBNjdu8=;
        b=G2ERI7eXBpOE9DedkUZUU2VMJBWzq68KJGoyWiyeda5x9/KPVeQQ7pU7YixFstT0+L
         wxCg6+xbKNaRL6Qbl3yxo4yUkib6lZfs1xC/u1kiW9btHzhF1x9GQnH3iWViRx4ztWBR
         petkM5gBoL9SjaR8p6SNKIdvrrTXYHURTIt3oAW0G9xKaTZe+5/Ts1xE5SQFNjgMbZJD
         x7k7jSc1wcKLO7bnUMJWt5QkpJepMCp/casusZ60TdTqDDfSAM8kySXw1toz0BHQo032
         s+cIG56sa/rO3TWj/iai92WMsWQ6t5byMP8VW0rCF2uibdehL73tUDkNgxJP8F0xqH46
         O/Tg==
X-Gm-Message-State: AOAM530a0aB3AADopp8U3dTk3KAf7mieiVs8ErhgU92KZL7/39RiwSmN
	GR/WbVGTpAipLL6jRItDNbY=
X-Google-Smtp-Source: ABdhPJz4+TepXadBXawOStAZ7S3cwJiZB6U2ENdF1xGUjt+7rPPEzhxcga1j+/dHGAQF/50y3KfwMA==
X-Received: by 2002:a05:6102:222f:: with SMTP id d15mr17768854vsb.16.1632173398814;
        Mon, 20 Sep 2021 14:29:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4d6e:: with SMTP id k46ls2061558uag.6.gmail; Mon, 20 Sep
 2021 14:29:58 -0700 (PDT)
X-Received: by 2002:ab0:3303:: with SMTP id r3mr14295111uao.17.1632173398285;
        Mon, 20 Sep 2021 14:29:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632173398; cv=none;
        d=google.com; s=arc-20160816;
        b=MPO9US/G6ikBwPuOLDTW5Hyz1gpXhfUlG+FfMVytSiO/v/rI6OsmxHMGhADgnk2PeK
         +d7pqHPbsm1svws7RvBfpdiHBXCThkithrZ91X+uiZqHE3B3JSMyzhkmQDm7Cj50orb6
         FgiQ+dk8+DKz66k4dobFsgMRg0WLG7f431vcxP/vhWAx3jk/EZl3fQMyDEOFC1WYGIJO
         Fv4eyPZGmGKXB8K7H4fCxV3VrQXO1ZAqM21IrXsPe6l7Yyz5Q2kw2LamyTteRhoqMIVS
         m8v8fKoEvejs9C00FKbQjUJM4QuMcJgjhNF1AhFYLnPyqhcylN77C2jmy3/ilBqdnjFh
         brjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Vs5Sa4Qkum2hykw4ZyahHqvL6vQpnvGsWXcltm8dEl8=;
        b=Ek7o42aQ/2PJxdtB0aMHFJll5JAq4tC9ogQq6IdAOMSveC44I+sd7NnrXNgO3jB2t+
         FAcueQsxLGp/okfa+l+Fja8yRbTfbkjNKRFp/0QTx3avh6z1WjUHrc8/G/ZxKeNG2jej
         n1TgLKe4uzqnrwQjr9q+Nkx67Hyd6FNwg0n0sGmfd2WE1hv2XSyrzAPAnwTFolYACl0C
         7qvalzwHNigys78XCIkw3aahTEne8MkRimAnTRdpmFaypGNhOBFdwLEtCcj4scZD6JEf
         VbVbOqupRFmBrIciOIGLqeaAjF6/2uCzst6BYvjzUDinKRzQ4349RXQ5DYLFWK9el2CF
         3A8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AlZLXTBj;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id t131si460050vkd.5.2021.09.20.14.29.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Sep 2021 14:29:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id 134so549802iou.12
        for <kasan-dev@googlegroups.com>; Mon, 20 Sep 2021 14:29:58 -0700 (PDT)
X-Received: by 2002:a6b:6918:: with SMTP id e24mr20177518ioc.71.1632173397612;
 Mon, 20 Sep 2021 14:29:57 -0700 (PDT)
MIME-Version: 1.0
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210913081424.48613-1-vincenzo.frascino@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Sep 2021 14:29:46 -0700
Message-ID: <CAMn1gO5sUhDkx4w-Kk8hw0xLbXmr129xeJa6YhxOeJ-v83hp6w@mail.gmail.com>
Subject: Re: [PATCH 0/5] arm64: ARMv8.7-A: MTE: Add asymm mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AlZLXTBj;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d30 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Mon, Sep 13, 2021 at 1:21 AM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> This series implements the asymmetric mode support for ARMv8.7-A Memory
> Tagging Extension (MTE), which is a debugging feature that allows to
> detect with the help of the architecture the C and C++ programmatic
> memory errors like buffer overflow, use-after-free, use-after-return, etc.

Unless I'm missing something, it looks like this only includes KASAN
support and not userspace support. Is userspace support coming in a
separate patch?

The fact that this only includes KASAN support should probably be in
the commit messages as well.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO5sUhDkx4w-Kk8hw0xLbXmr129xeJa6YhxOeJ-v83hp6w%40mail.gmail.com.
