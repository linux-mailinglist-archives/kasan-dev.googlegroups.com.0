Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBUTVKTAMGQEDXZQL7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 54D7876D438
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Aug 2023 18:51:20 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-3fe182913c5sf521675e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Aug 2023 09:51:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690995080; cv=pass;
        d=google.com; s=arc-20160816;
        b=PawXPDtmZ1uG9UIBwZ/b5PLDxuQD/xRgOZc8FwtZCXfJPIka4lLvxZ7o72pLq4TvR0
         kJZV723YRd3hQo5yiVASQ2P+ZSinNl4WO9B3wLyINEmhHem3vWIIeMIvBS9pmNhNvfUD
         WtJz8p91or64NUqa0wt0zxpq8J1Q++Eg9av9PuYWpyfIs64Jlr5H+DzhLD6eLDxEOMeL
         VUgDtleSenXTJi3PwdG7fUMvJXzWuBBH/wRkRPbkM2onnjx4X5exRdQ6YgEyvrr+pCM8
         /KZZOphK3lTVHS4+Oet4/CNeAKeF3yYkCYuxz0w43Rl0Ww/vvhfzyBgTzBCuQLxZ6ZxS
         9i7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d6pgfgbWugnBobmRSjsC+hvrvOkEHMwFEe+BYM8rAk4=;
        fh=npTDZCMzSL7q0QPAR2sE4VgQYFKX+PB16hECAC3Z4yY=;
        b=MJ1d7UZiGUJcstsOHgUJr95dGZmthFRbNtIhsvtNYx+lYN1tX5ge/+8IXB1pEPa5Ha
         eiSGQhLI1TU2Kw0OD56y7SehhLy0nh7eGxBYd3v8A5DithLjWfUcZj/Jq0WK9K24LXOt
         m+8sq+3JVO5lAcl0PYnaIEd/Eo0ckAr+imrmR0JTn2CPJqG/6HLsZa6EFVyVIkaHon+L
         sFiHvDhjXOHETllAx2m88BwJCLtWDSe8SLvVg1vjCWmgxjMVLDOi+f1yvAWk+GvtAMnx
         QXNlrd6DEms32r9d1eqhh4slSSz5kMtZJHgzYpC1Jywi3+FQ6tRiYw7of2cmgfx8vNUy
         2glw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Yr2vtAOi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690995080; x=1691599880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d6pgfgbWugnBobmRSjsC+hvrvOkEHMwFEe+BYM8rAk4=;
        b=QznK18qh00C/2JQCtXcgLnOsBmVJJmaoUKu9sr0gTIaNaXstWSS4WGOeQzCaSU4rlF
         OVSoDVP8eDJOiB2tWpoxwom+sQNO/5GcRlqWbm9wf68NPLrXL/9JTyfJriPnoFt/107H
         W8rl24ccJbhUNDpb1UZOi8QfKPqYifILptnuHwYe8KlG5nyOebcMlY820uN+0sJcwxjo
         hWDx2ipO3bkpkcaZhSPLji++qw2Myt70Z4izpP0emqoek0+BjygquWn6PtWamz5z/UTs
         23AUkADGTLJNHyxDLXsKddvaMR0jfQdPFa/FvhqQhURibURC5GV8VsTaPfBYKkAKsHJ7
         6iWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690995080; x=1691599880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d6pgfgbWugnBobmRSjsC+hvrvOkEHMwFEe+BYM8rAk4=;
        b=i8oPNhCxc0EgI6hdEealA1lCEv9k5fRocUaH681jodRWkMWYqmC4rZ1jCXzDMaFfv9
         Yp8ltycz7HVCqujcT6Wgfx6zIW09gcbY8IGDzwWknNmzYEDEV9iKd2RbAKMoWQuNs7/n
         1BqB/BTdFXt34N5/Ubs2JjS0eFU2Y6Unc3T/ocdZ/xmz/xByP0RhPht1BL+uEwqa8pWx
         BTixosF66yszMLBfio7ca8MOUoaJYVhFzq6ejH11ccQoNiGuo1eLM9oAyS5PDTIDuOtY
         wCzTnwRtx7Y1HnS4mcypRDAP96/dk/os/NWEIvVh0K+lRbei4eYLQxlmiC9pH0bdBoWy
         Bd5A==
X-Gm-Message-State: ABy/qLYx5ijz1McacAWdgiI/kSXFd4iMB1E6AOHZkkPbK90/OcrivdRS
	OXIdFF1mPDosZk6uCuZm24k=
X-Google-Smtp-Source: APBJJlH7Vczb/36BoxOBLmNrcbIKQWJpRDeWmmqFi2EACCg9nbQFG89Pt68uYS4LZ8u8jcEUVkucqg==
X-Received: by 2002:a05:600c:2194:b0:3fb:b6f3:e528 with SMTP id e20-20020a05600c219400b003fbb6f3e528mr5471929wme.25.1690995079108;
        Wed, 02 Aug 2023 09:51:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f182:0:b0:313:f4ee:a4cc with SMTP id h2-20020adff182000000b00313f4eea4ccls1780737wro.1.-pod-prod-01-eu;
 Wed, 02 Aug 2023 09:51:17 -0700 (PDT)
X-Received: by 2002:a5d:44c5:0:b0:317:5d3d:d387 with SMTP id z5-20020a5d44c5000000b003175d3dd387mr5123625wrr.25.1690995077254;
        Wed, 02 Aug 2023 09:51:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690995077; cv=none;
        d=google.com; s=arc-20160816;
        b=aeNtbWqq3EM8vFm9Ris305xUAMkSPg4pexnZf2Ej3Yb/c067WURvpnLvL7jbtSuGww
         TQgKI0899PESG+P/RvYSU/n9enphfqvoQKvdftSqc7FkKa8hTVJpx4rs8qwhmLF3Kxs9
         C2a+5hk5LdbdYVuZUw83HFNWpNCyHRhv4T4TD5GrBkH+//i/L9RvRYu95mhhsDCg56Hr
         RtI+Av5juLGhelDzapiAIADBWdoDKRPduELPEam04GDY61J37f8q4gKThcxd0bkP9H34
         dq4zh8pRfUOdtsk7QvEpL2U9OgiB05wFLWkglXXzogWeCBa/Vleza/ch7gcCO2JzJBin
         xvEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LrJLBG38n+Wiyfmv9S4MGg4xgt3i7BNwPWJDTs2HMj8=;
        fh=LclYWhdTYCCnc+/U+KSui7VEiIFUuheOLAb4/BmiW44=;
        b=xHIc/uGAWWoS/NbfnrULBqzZ4Sgs3KNiM1XxiAxuTNMVGT+79oPLWoJb07tmiVsmxt
         2GW28tl0aOJd4HaD5Riq86kU5E/sujFHkZv7R6g5kJJC6PzQTP1ItxtjVchWd3JTqehu
         6awtMTp3z65xJJF7BR+1MtsPWguY87l8rcb4mSP9uM8sEBZQTPA+e+nb1UjbYBZ6ifmC
         7IRzRbMW9PgtMUs16AXoqVX8uP/FmWPN1Ike9rs+vqLtXBGXjw+U5M2TwOWw3c+CGEia
         u2gOF9wM8NwGECYjpNMCRrYvAOGmqZEsgFX2nXQuS6uIhy7rq3RZxGChy62V9ihusUnd
         xYNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Yr2vtAOi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id co20-20020a0560000a1400b00317b109557asi306064wrb.3.2023.08.02.09.51.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Aug 2023 09:51:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-31751d7d96eso21959f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Aug 2023 09:51:17 -0700 (PDT)
X-Received: by 2002:adf:facc:0:b0:317:49a2:1f89 with SMTP id
 a12-20020adffacc000000b0031749a21f89mr5196369wrs.1.1690995076610; Wed, 02 Aug
 2023 09:51:16 -0700 (PDT)
MIME-Version: 1.0
References: <20230802150712.3583252-1-elver@google.com>
In-Reply-To: <20230802150712.3583252-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Aug 2023 18:50:39 +0200
Message-ID: <CANpmjNPVO_t058c6Wcwr9TBwxeoH7Ba0ECsf6Wapn60br8EtkQ@mail.gmail.com>
Subject: Re: [PATCH 1/3] Compiler attributes: Introduce the __preserve_most
 function attribute
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Yr2vtAOi;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
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

On Wed, 2 Aug 2023 at 17:07, Marco Elver <elver@google.com> wrote:
>
> [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> convention of a function. The preserve_most calling convention attempts
> to make the code in the caller as unintrusive as possible. This
> convention behaves identically to the C calling convention on how
> arguments and return values are passed, but it uses a different set of
> caller/callee-saved registers. This alleviates the burden of saving and
> recovering a large register set before and after the call in the
> caller."
>
> [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most
>
> Use of this attribute results in better code generation for calls to
> very rarely called functions, such as error-reporting functions, or
> rarely executed slow paths.
>
> Introduce the attribute to compiler_attributes.h.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/compiler_attributes.h | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/include/linux/compiler_attributes.h b/include/linux/compiler_attributes.h
> index 00efa35c350f..615a63ecfcf6 100644
> --- a/include/linux/compiler_attributes.h
> +++ b/include/linux/compiler_attributes.h
> @@ -321,6 +321,17 @@
>  # define __pass_object_size(type)
>  #endif
>
> +/*
> + * Optional: not supported by gcc.
> + *
> + * clang: https://clang.llvm.org/docs/AttributeReference.html#preserve-most
> + */
> +#if __has_attribute(__preserve_most__)
> +# define __preserve_most __attribute__((__preserve_most__))
> +#else
> +# define __preserve_most
> +#endif

Mark says that there may be an issue with using this in combination
with ftrace because arm64 tracing relies on AAPCS. Probably not just
arm64, but also other architectures (x86?).

To make this safe, I'm going to move __preserve_most to
compiler_types.h and always pair it with notrace and some comments in
v2.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPVO_t058c6Wcwr9TBwxeoH7Ba0ECsf6Wapn60br8EtkQ%40mail.gmail.com.
