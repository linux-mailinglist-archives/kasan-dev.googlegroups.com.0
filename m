Return-Path: <kasan-dev+bncBCF5XGNWYQBRBCPO5KTAMGQEHUJBPSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EB0177C3E6
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 01:21:47 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-41043815a38sf20045191cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 16:21:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692055306; cv=pass;
        d=google.com; s=arc-20160816;
        b=blN3YbFQK4Z7cXnfbUgkhBf8OfsW6c8m72a9mqbKQVcoa2ptD4l9kF1tEdmTwnhhbR
         0DHz5x2xN5mY/G2zpZgPepVsp+zidqEteyexLm0RW2zyUeN5k72foaywngTBtosoklf1
         gUwARUj6OazK2v05CGUwWD/2otND7BT2mnllPEr+D7/Enfce3kFJT6yv0q9f9xEZX7Ts
         04C3bCytc59wPxvf6A3PLkb6sGcZ8KWUIWbnXpTPDG0y6q4Nqn9AzEtXyFAYlu6hSA03
         VgfoMosHnRCwC8hda3vkBxz9uHxyX3J7tlS8kXfFknWvxKxjjPBu1b4Pk0mpPt1BG8Ma
         gVsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MSPzICbiHzM+B6hON3RmU/Rlapn78T6nhuSQGpbnD0o=;
        fh=nGLCeEfsBe9nDa8GHWlTkRf1XXmhaPyBRtQflBA+RHI=;
        b=QVkEg/fTAmBsr8C756iy7o6TQjcHJSqoE0OEiplgmbhkXjS48FBle7mNjrby7UWyaY
         JsQ99Q+MDJM9Cz+jQwtRr5uRseCIX1tYEEGCSzqu/hXxIzc6vfVUXQPsTV3MnnHjyU7U
         SKF8vwcILFAUKG3Gw2HAZXDNTIwcmz2HoBrkOYOrBMblmfq05DMm8cRUpjDAUQU42fZG
         pkg2u6M1wRKrt91lWxNwGyRJBDB38cpYwkG3lJ8Ccbh0dATcvAbod81EmeGrvQo5aIcf
         eO9VtPHbPDyB+tAnfjDd/3ZU8DeZTHF49PJne1ypNt29JVbN3rbKODMFtuUODmdmMdUc
         XiwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=f0Ak5Icl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692055306; x=1692660106;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MSPzICbiHzM+B6hON3RmU/Rlapn78T6nhuSQGpbnD0o=;
        b=p4PkSSx5asga9z8RMzRrLx7lgWnM9bAptNUXoemaT6HqvflWYYRkeO3MXIE/EkuFn3
         /cPW5EK+xJ7egzdk8OK+QWAw4Jb+DOUg9aIyr7toKb2mcNaQ4SbUv9BK7VoDUGBlO+SN
         PMa9Ud8BAA3KqtWv9eLx5Oe38egfJ9mwMPm58KIUZc/4BryLO8YPWYM21Vu2aTqK5FGI
         FBZjOyikTJvhgDOol9V4bTFnxnyU0ysC/IiLKu7/o9p/HZVEdRyj39SDcjoqiz86ISzh
         kg0p5BmtmhDoBoXnyqK2+ozS8GsdgREu2VS7kzfig17ylljwBYeqbM6L5K8yhtkn3Yyq
         RcmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692055306; x=1692660106;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MSPzICbiHzM+B6hON3RmU/Rlapn78T6nhuSQGpbnD0o=;
        b=lwDQcVPYqvf4hbjPlSIvgFz0KCRfi84OpuW9Wbz6eM7xF9+7A2hhKEpB+fTC/rgjk7
         M9irtUgw+mUwOC4ToSpuA673yxk/k6SpEh62B1vW2cBhVE7fdXXNFzOdlxGpa7msPIci
         N++lgngGXJ2kWmSd0m5RocUPL8hp9J+Y+aNxRhzuHmy+Gss3EUajhnFto72hbrPFLba6
         PEVaqKr1rjFG+mp7Mqqm+pd6F3fFh6cJewNZ2pTIzx3mPi/kvQ0Z0hFSOeCkYzY9MTw0
         w9Xsy9DRVzmoW2Hx9QozX0v4vd8JlvbcNAAi+wDmCiR59xDECpmwKPZHBhcHS6UcI1th
         AvUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxbJWXaqsB31HpzJx15LTP+8zNP4HMb8nSpMf/jqCAF7RgsFRgW
	MOGTusfWJ8gMuq0IYAbXq0o=
X-Google-Smtp-Source: AGHT+IGmD0PFN0/EwEBsZK53K8MA2tGaLwfAhVSo0nR8E6THr5Lp34qeNJj8FQMMIfQfbO/VJ2TZeA==
X-Received: by 2002:a05:622a:608:b0:400:938b:eb0e with SMTP id z8-20020a05622a060800b00400938beb0emr15639577qta.43.1692055305729;
        Mon, 14 Aug 2023 16:21:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7642:0:b0:40f:e8cc:ced0 with SMTP id i2-20020ac87642000000b0040fe8ccced0ls5356301qtr.1.-pod-prod-08-us;
 Mon, 14 Aug 2023 16:21:45 -0700 (PDT)
X-Received: by 2002:ac8:5850:0:b0:40e:f3da:507f with SMTP id h16-20020ac85850000000b0040ef3da507fmr16348861qth.11.1692055305109;
        Mon, 14 Aug 2023 16:21:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692055305; cv=none;
        d=google.com; s=arc-20160816;
        b=zWRjpxVRs9du6XP1Q7hq4EcPUQxfJaD3Ar2TTsax6XyxPxe0h+O8kneAPHBkAEYVII
         Tb/mTArqxHXwSV3vNsI83R0Ct9Nyn8AFi+HuRyasyU3xQize/RXSuXzYkKr6B0z8WArn
         PzNPtJcpdadekjqvX3pDMur8Ccbv8s8ULhSlkfuLO/hZ0ZaBesNPv1mOSYDNmcQx8rdG
         MdQosWQViFR+Seyx7v+JCuFmDPnJYTB4AnCzkfElkYOIV3+obSOsoDlJouzx4JbLzoko
         o2Rz7gIR5XNACkdWzwqHqmGJgSB44gGriFTw0fTTEf5jfDLyCpV8w7OhUOy8V0JLXdMF
         VcvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zDgteNssk7bldWg1S9G58zrFCCsMMUu+wXIpurB+HOk=;
        fh=nGLCeEfsBe9nDa8GHWlTkRf1XXmhaPyBRtQflBA+RHI=;
        b=XjCiweFmq3HZZtw7CA8V+dwKNJSEm18zRLqokft7f0ItpEadvL6lMJ0FkyzD0iZEQe
         G/0HqYJw55kq++NkCCzEXB25U2VQCVm7BNPJ69MH2v0POUygD29AwwA5Hny+FqmmsfJm
         x5v6zqwUg4vxrDwiDQE1WAIzBIT+0uqlyegg+HscB8VvsjVmZDuIowTVZ9ar5QCSM3or
         agusn+WFAyNIUloftjO/31TNwGWQCexR3qrU+kEgVutazDr7sF5xbjbf5LjhQlSW3/XS
         ON2dEGF1gk2QnUzKZ5BJ+GhfGuJCRPojDZ2c89UYBkCsKFEaJ5e2AeZRT9+fdV70+C1Q
         2yGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=f0Ak5Icl;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id cg15-20020a05622a408f00b00403ea989befsi329474qtb.1.2023.08.14.16.21.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Aug 2023 16:21:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1bdb801c667so29152255ad.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Aug 2023 16:21:45 -0700 (PDT)
X-Received: by 2002:a17:902:e802:b0:1bc:422a:b9fd with SMTP id u2-20020a170902e80200b001bc422ab9fdmr13245083plg.13.1692055304507;
        Mon, 14 Aug 2023 16:21:44 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id c13-20020a170902d48d00b001bdcd4b1616sm5310621plg.260.2023.08.14.16.21.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Aug 2023 16:21:43 -0700 (PDT)
Date: Mon, 14 Aug 2023 16:21:43 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Paul Moore <paul@paul-moore.com>, James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org, linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v4 1/4] compiler_types: Introduce the Clang
 __preserve_most function attribute
Message-ID: <202308141620.E16B93279@keescook>
References: <20230811151847.1594958-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230811151847.1594958-1-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=f0Ak5Icl;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Aug 11, 2023 at 05:18:38PM +0200, Marco Elver wrote:
> [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> convention of a function. The preserve_most calling convention attempts
> to make the code in the caller as unintrusive as possible. This
> convention behaves identically to the C calling convention on how
> arguments and return values are passed, but it uses a different set of
> caller/callee-saved registers. This alleviates the burden of saving and
> recovering a large register set before and after the call in the caller.
> If the arguments are passed in callee-saved registers, then they will be
> preserved by the callee across the call. This doesn't apply for values
> returned in callee-saved registers.
> 
>  * On X86-64 the callee preserves all general purpose registers, except
>    for R11. R11 can be used as a scratch register. Floating-point
>    registers (XMMs/YMMs) are not preserved and need to be saved by the
>    caller.
> 
>  * On AArch64 the callee preserve all general purpose registers, except
>    x0-X8 and X16-X18."
> 
> [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most
> 
> Introduce the attribute to compiler_types.h as __preserve_most.
> 
> Use of this attribute results in better code generation for calls to
> very rarely called functions, such as error-reporting functions, or
> rarely executed slow paths.
> 
> Beware that the attribute conflicts with instrumentation calls inserted
> on function entry which do not use __preserve_most themselves. Notably,
> function tracing which assumes the normal C calling convention for the
> given architecture.  Where the attribute is supported, __preserve_most
> will imply notrace. It is recommended to restrict use of the attribute
> to functions that should or already disable tracing.
> 
> Note: The additional preprocessor check against architecture should not
> be necessary if __has_attribute() only returns true where supported;
> also see https://github.com/ClangBuiltLinux/linux/issues/1908. But until
> __has_attribute() does the right thing, we also guard by known-supported
> architectures to avoid build warnings on other architectures.
> 
> The attribute may be supported by a future GCC version (see
> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110899).
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Miguel Ojeda <ojeda@kernel.org>
> Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
> Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
> Acked-by: Mark Rutland <mark.rutland@arm.com>

Should this go via -mm, the hardening tree, or something else? I'm happy
to carry it if no one else wants it?

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202308141620.E16B93279%40keescook.
