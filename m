Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY7UWSTAMGQEZXN3G5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 50F5F77074D
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 19:50:29 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4fe21fda5e3sf2366202e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 10:50:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691171428; cv=pass;
        d=google.com; s=arc-20160816;
        b=TX1ufgJ9yysfunQgHwn+JrLuJztuOM5XsNdUvgXZ5kpm8y3lusKsrr2YImtykXhGxl
         NQ455EEKiyxQVpn2s/2LhqzEUQ9cVOKkupNpz9BGTcZm33I7ef+VWCDbM9P9D3V9TYNM
         vuqLrMCyF7H4U/1vvvok7ZT9mB6R2ks/TLpiieZgkUzohmMtGWKm2rFzDDSXEiZjt40q
         FB3PYkhbdYFjXv/7ztB8UWMJVRVL0mJomGJ+fAT99UK3GE1PEucHE6C3umLRAmNm/QBe
         0Mj9nQ8OXp3aUn72d2/OW3Rh2PalsM/sWsQKotpPLE7ehdpQ/lfYeSf64uuACXrz6rm2
         yyQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e6HdKg6u7I+iX/JCbDP2u5xNWcobkyIC1BA4V+QndYw=;
        fh=3t+9JX4h1FMuCtHxMGExtCnzfKANoxWceyd8tNamNYs=;
        b=QeH2hMCnDSQdMwiKU7I6Apupodrydv2RjjQxQrnDW45d37lZExIsqqE/qVxdyhQrxy
         Fo8NzWU23Js1xHzVlXg+V7gUDV5XG1vla8w20zwJ3mtPMsaHsiVVhysupSl9EUo7Oqw2
         /CcApJJE0NdIcsDXKp2MD8Pr3hABslKDCY0Oy8QSkoqDiOziAltYS3N9KsDjaTyp4llV
         FX2TkxiaRh9RRjCAj6Eom33aUsCgcR+iEvuxJGpaw9nhAEaDvaZ4UUa3Rxh2Otdcz6GP
         HBZTB77J3v1ApL7vFB9QuVa7+lpwhINcOS9CTsbUdN4894dX2DoMnEUgINKdg5ApD+yc
         xhxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UphmCrMd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691171428; x=1691776228;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e6HdKg6u7I+iX/JCbDP2u5xNWcobkyIC1BA4V+QndYw=;
        b=qa0goIBGUyW4Ng+VauyJrnL+Xbr6DXxArJGaB5qH5Y486/hN7IwloGGHhhWtfMFk9B
         9joo5tEbBRBW0WYtbVYP/J2axjqwJL1N58Vw8swrwadQk6cwAs/sGB9rYfuQVui6Ixti
         ymLJb76XPTO0vCBdgtXJGEWVCl3IP4I9JCUIZ+TDUC+txo/586wehETj72BYnyFbnMRF
         xbcZyRzBw+fCr3HaVgapAQ9czGPwdv3b8iGkw6O9myZsSO7sfXWUZiD9zUPW4R+xydl+
         1RQpzK72xnyx7HdboEad8xX/elGdDCr5Q/wGi5HqfRAAQ1GArFq5kWriKC0InSz27Foz
         dOTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691171428; x=1691776228;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e6HdKg6u7I+iX/JCbDP2u5xNWcobkyIC1BA4V+QndYw=;
        b=bRadsC2k5XgmNSDu4lPipQ8Uc2dQyk/rO0/tZd5Do3se0P1VFvf3cfqHWu1m+bkcP7
         Hdxl6g5R5DJKBc1pSKeAaUR+zQRuJ0ux7hrh2UHKlxfMOyp1raEakf6T8+k4Ysh5cXyH
         gAUtQT0jVbBqxPGL69gomENkNOppwtyEK3CYLH7zX/9WiuA1sFZE5hDAGfiO9M8IrhY5
         FK9r4EFEVYyNxLuGKkbpfpctuiRd4JLG/xEkEcfp77tLGcxfhChIwstM/i+FEZWkoqOf
         lWTehFuXMmWcbkXFrxOkQqmDSssVpc0hs0DNS9wjOVbgYXSR9ytczJGfn+7A3nMfcVD/
         XAyw==
X-Gm-Message-State: AOJu0YzObAa+JO7rVJeTkmFVDaSlW5a51/FjvIG263nmZxuA9GapgmbZ
	hFKGF81YvTGPEHm7m4onHl4=
X-Google-Smtp-Source: AGHT+IFMZP2whcX1U+EJCyI4CGNAATGHMLitaQKb2bxgicI0oH+eR4LK2xu8VfPc3PblHhY9T1I+8Q==
X-Received: by 2002:ac2:57cd:0:b0:4f8:554f:36aa with SMTP id k13-20020ac257cd000000b004f8554f36aamr1592467lfo.29.1691171428201;
        Fri, 04 Aug 2023 10:50:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:896:b0:522:29b2:e051 with SMTP id
 e22-20020a056402089600b0052229b2e051ls156175edy.0.-pod-prod-05-eu; Fri, 04
 Aug 2023 10:50:26 -0700 (PDT)
X-Received: by 2002:aa7:dc0a:0:b0:522:79e8:e51b with SMTP id b10-20020aa7dc0a000000b0052279e8e51bmr2142980edu.32.1691171426266;
        Fri, 04 Aug 2023 10:50:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691171426; cv=none;
        d=google.com; s=arc-20160816;
        b=xvagEoa3zVvvLkYzZiMiNtC6LS3zSUhsQrtHT/JBmyiAKFOUnPw2e0c04JLGOAolYK
         fFAIqQQCUWq9zhmzYOD2JbT0RbZKQrSYQ2h9Qzu0AwAHfEzwK83nV1JEeZfg6s4gWCQs
         tgKvAapaHWA4cM12mEsKGoY1Ayv4s6JRZtaklhrKMvgI2JsMZmP+WFX0l0Y62IGzdv52
         MMV20qU3LsKBXjLMtAQFFpuS0Ky54djdrkoVk712XsGKvagylVLMXdAaOxp1aqGEQeMt
         CXi8hyIdrvVytmEUq36ZuBzDCG2AyFyXcJ4azNtd7Z4BA/4+RKcvpS+J2nmz+KeMOj0E
         ykaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Im4dcEZwNsAe1Y2oMqCTaJQsYwxClHXtIW7/6pymoyo=;
        fh=DLrPBd7o2oKP6cyzmVjIsB/4ChRHo+XNiPNmjSWnA/g=;
        b=VFTGjV8+vM/GKYiJriXT4F97ODx/a4hO68U86s/dIZ71PsUI36bynnReGSyinmK4ty
         oBNn3cTNQHACN7W9AF+kobHaqJYckmFrM6KCLSKJrK5G1gaxXjVBI4T+xe7yiRegMh6W
         IQEi6+EUkTCnMj027FRkqUTS4rRUUw8/OC12vUwpE6EI25gEKhyeV5RqGNkUwhVx923O
         nnTGWl/7iCn5acjOl7qv9vxQvByfOYCZHpRmuqpHrVq9RiKzMfxows6utXECOGRAudmr
         E6HryrMyX4+vdr2RaxnczWKJEakkVh2lXEsWW5Z1urQVj6UcphQve0SRsUfMLyMIcvKw
         MBzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UphmCrMd;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id ds9-20020a0564021cc900b0051fe05f750asi218347edb.2.2023.08.04.10.50.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 10:50:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-3fe4ad22e36so6383775e9.2
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 10:50:26 -0700 (PDT)
X-Received: by 2002:a1c:cc08:0:b0:3fe:485f:ed13 with SMTP id
 h8-20020a1ccc08000000b003fe485fed13mr2162276wmb.29.1691171425779; Fri, 04 Aug
 2023 10:50:25 -0700 (PDT)
MIME-Version: 1.0
References: <20230804090621.400-1-elver@google.com> <20230804090621.400-2-elver@google.com>
 <20230804120308.253c5521@gandalf.local.home>
In-Reply-To: <20230804120308.253c5521@gandalf.local.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Aug 2023 19:49:48 +0200
Message-ID: <CANpmjNNN6b9L72DoLzu5usGGjLw5Li8rnfu0VuaCsL-p2iKTgg@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] list_debug: Introduce inline wrappers for debug checks
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=UphmCrMd;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Fri, 4 Aug 2023 at 18:03, Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Fri,  4 Aug 2023 11:02:57 +0200
> Marco Elver <elver@google.com> wrote:
>
> > Turn the list debug checking functions __list_*_valid() into inline
> > functions that wrap the out-of-line functions. Care is taken to ensure
> > the inline wrappers are always inlined, so that additional compiler
> > instrumentation (such as sanitizers) does not result in redundant
> > outlining.
> >
> > This change is preparation for performing checks in the inline wrappers.
> >
> > No functional change intended.
>
> I think the entire underscoring functions calling more underscoring
> functions in the kernel is an abomination. Yes, there's lots of precedence
> to this craziness, but let's not extend it.
>
> Can we give actual real names to why the function is "special" besides that
> it now has another underscore added to it?
>
> I've been guilty of this madness myself, but I have learned the errors of
> my ways, and have been avoiding doing so in any new code I write.

That's fair. We can call them __list_*_valid() (inline), and
__list_*_valid_or_report() ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNN6b9L72DoLzu5usGGjLw5Li8rnfu0VuaCsL-p2iKTgg%40mail.gmail.com.
