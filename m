Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG4I56TAMGQEKHFZV6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B78477D1DB
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 20:29:49 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4ff8ade6454sf498e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 11:29:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692124188; cv=pass;
        d=google.com; s=arc-20160816;
        b=omiq2ok0NqzCtDT/5GD3a8lwba3JDM6XMC46SXO3FoQTU241qGVE+rge2fu03FhrHI
         cgGEFmBjyPfar2Pu/6l1lpuX4p+g5vzO/ZdqOMF4nv7iQe/jlTQl8/L3frYceVuXAjqE
         5l5D/TpnX76Sak2XcFoyctwy6sAgrkjFGY7YxQ7/+fVcg0pgVLVXtb8Mz6tuVEwUa19g
         LMO0OiYWoACV7jYCj9qiIjAWH2w4h8F1VGLGaoAY5Sz4UEXXYB4KB9BA0Ns604Apx18B
         Z+Burmgmxa9ZqXLkb4HAVg+KAzrxS+pMp6O6lLbWk9ykgyNaz+s2jpk4J9/woExEfJYE
         YGfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zwqG9v9kVWzL81aNAQbH9/oshBRzuQaTIkgHPlpuwZw=;
        fh=rz9oytbgfnJAfKg+IfpYKN4YyiAGoyN0/vbYM8bc++0=;
        b=QickjgLHAzUZThOcNI9LyV+E32r+MOiTGjlvlldhNqboXhpaIFHhbw4Dm1kIkwx1LE
         4DsorrjMP2HfXEXs4uWyLzLxRw4XyEYYFLMLag0X9g4CqG2o+XR8Td9+A+LmroEvw+iL
         p6frrhva5IGsUV7Sm02I82LwplPg9MrobIYab2A4It0gxnk0uOatH7Nw5c5s4Ru23NK9
         uWyQBKMuTLM9s8rLCzx+Izq8WT03ru+Ixtos/SblsQcy51zGih4b6wXbxdHt1REoZJ5y
         ei5V1YD3aVdVli/orsQl7RDxVnXNNblumCA5n0RKGlwGY7hiwBvGKsw/dD27Nor2BhMM
         fepA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=FWCQauOk;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692124188; x=1692728988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zwqG9v9kVWzL81aNAQbH9/oshBRzuQaTIkgHPlpuwZw=;
        b=AeEMvqiefi1cHYtvf/nwveyprh/mh3ldpac6mfaFooQACWt5ydMWDlBRdE1N/cqp/4
         dgfaFTp1OBBrYHFzML8NArS8CdVOI9ZqjzBnghPFwEfFRvcjZNClvXUeZfcGmHQkgKGb
         htHVMBRKcaVW5YI7buyblSzuaM+Fua3KXxl9en55f9dT18wSNGW+EyZ3QWYpD6y4PjxL
         TPZVLs13+qv84MgmjNZLh7P41eTRUvIyTGsteHgARCQmsvhFkPdl/NY6B+cUpRkTPxpT
         ePPrcZQZzWQnx3ID/FUN3308H7r/x9wnzPBZ5LUrvItTg1bIuhwbP+T+POSJj0Mlg5AS
         JxRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692124188; x=1692728988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zwqG9v9kVWzL81aNAQbH9/oshBRzuQaTIkgHPlpuwZw=;
        b=Xu90+6pYzmFdpd/QNrgBGaBYhVinjooTiOOuCDrrg8b1HoUK+vJuVF/X0fJWz8Dr+W
         i3qYa3eV0Ol0aAbGSrL3CbDYEwuV30lp4S4i1b2UZ0+/VUyWtebYM99F6hvxxitC7gyy
         KVzdVjDrr/C7Fc6OG23bHWzko7neqh2ZwlFZjr4CoBCp7MOs10SZyNzxgD198NmsZaKB
         CGYd/0buhHBnU1aRkLwgfmgAOYFU64NJYQwk+yv+ElzOMIXwRgxRnMibBABpO8McQZZ5
         h96JAh34463bSLr5PPCWfSsxHH+8TstBhlIxJnrz2Aly3oRbLMNNN86pR3+CGyjm8jn6
         S2Lg==
X-Gm-Message-State: AOJu0YwHsST6XjwL4dNa/wlHlPnDTrMPONkiIuGjSTT4FDTO26qHYiIO
	NoomDszdiqOHOO2e29NC5Lk=
X-Google-Smtp-Source: AGHT+IF/ih/tacOgv003Z4rDyv1pvfafNUcT3lE2kByD1jjzucDecrqbYK/54nehDNrVZ7BxqSt80A==
X-Received: by 2002:ac2:59c2:0:b0:4fe:84cd:685 with SMTP id x2-20020ac259c2000000b004fe84cd0685mr13081lfn.0.1692124187590;
        Tue, 15 Aug 2023 11:29:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e00c:0:b0:4f7:68dc:ff5d with SMTP id x12-20020a19e00c000000b004f768dcff5dls308823lfg.1.-pod-prod-08-eu;
 Tue, 15 Aug 2023 11:29:45 -0700 (PDT)
X-Received: by 2002:a19:5f59:0:b0:4fb:9050:1d92 with SMTP id a25-20020a195f59000000b004fb90501d92mr8421507lfj.51.1692124185273;
        Tue, 15 Aug 2023 11:29:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692124185; cv=none;
        d=google.com; s=arc-20160816;
        b=n8ARV59+mxXjIebsvgaUUGc5Vdy6CEosR7tsh76GrWdAe5/VDkZkgXhBBvXL2zpuLk
         PSjjyE0tcGJ8tfM0mqD+FDhU+/4R0jFOFsaldh0EA/XZMZy1ixQRyRNZwXX/fzuLqO+1
         riNVqulPthRBV8zSA0t1CjRnim2nd2136ulxUbueotrYcd12siy9epRK+22q4WI8xN1E
         Y3y+WwHCPi1OGmhf3LYxbWup9jpR2hmrXLNqmbnu8F386IZPd7grUCRV3SlH3zkehBy3
         665Msqh8SxrE+JrVXw2YPGURRvOvSSeeXaAqlnUPhayAPNa+iDafD3ANU5M7PbR/dvQk
         7SVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rRFUf4dNqMSfHq2+lBU85kOOjIYPLnDmd2dSara3YQ0=;
        fh=7QQfPndWvT5OjxOhSbb6JukUnlSum4UIkCn+LGJ7EI0=;
        b=v8Qaiv1Zi7FvOSUG+tBmIBMmhGXdnxB//LnwDUMVn42+/zDJJXx2F5y3HlDiPxZJC5
         MLvhtdrNOunFOhb5RBD7A2rb3FCLr+Ll9J2pKWEP/P4sSAQ5yqKZxMVX+B46bFJ3T7/l
         csw2IS+kDtsWto+FXLQtLQrRycVWa5U7Cshaczh74cyHnZsg5IMU3hi9X7MzLufP+rO+
         iz+fa0MWq+jrp9EC3OmYxSCe0EwdD9wuCO3kZE5i4FjWlvVkTFZn0GOSbfSqkxNuKaUV
         k4Rfvbg9ATTatGsTpTLSQDVAVohAKO2DTgqEfo97AuTV+41GVXmIpM5uSo3T0qZk4ALe
         09IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=FWCQauOk;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id w5-20020a05651234c500b004fe2ec4b003si942281lfr.11.2023.08.15.11.29.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Aug 2023 11:29:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-2ba0f27a4c2so86354701fa.2
        for <kasan-dev@googlegroups.com>; Tue, 15 Aug 2023 11:29:45 -0700 (PDT)
X-Received: by 2002:a7b:cd99:0:b0:3fe:14af:ea21 with SMTP id
 y25-20020a7bcd99000000b003fe14afea21mr10108651wmj.21.1692123756120; Tue, 15
 Aug 2023 11:22:36 -0700 (PDT)
MIME-Version: 1.0
References: <20230811151847.1594958-1-elver@google.com> <202308141620.E16B93279@keescook>
In-Reply-To: <202308141620.E16B93279@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Aug 2023 20:21:59 +0200
Message-ID: <CANpmjNNDcVK9gmnBfxbthD3KEzsdc=PJb97AXcPEaweLNM5mPw@mail.gmail.com>
Subject: Re: [PATCH v4 1/4] compiler_types: Introduce the Clang
 __preserve_most function attribute
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Guenter Roeck <linux@roeck-us.net>, 
	Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Paul Moore <paul@paul-moore.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-security-module@vger.kernel.org, 
	llvm@lists.linux.dev, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=FWCQauOk;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::236 as
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

On Tue, 15 Aug 2023 at 01:21, Kees Cook <keescook@chromium.org> wrote:
>
> On Fri, Aug 11, 2023 at 05:18:38PM +0200, Marco Elver wrote:
> > [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> > convention of a function. The preserve_most calling convention attempts
> > to make the code in the caller as unintrusive as possible. This
> > convention behaves identically to the C calling convention on how
> > arguments and return values are passed, but it uses a different set of
> > caller/callee-saved registers. This alleviates the burden of saving and
> > recovering a large register set before and after the call in the caller.
> > If the arguments are passed in callee-saved registers, then they will be
> > preserved by the callee across the call. This doesn't apply for values
> > returned in callee-saved registers.
> >
> >  * On X86-64 the callee preserves all general purpose registers, except
> >    for R11. R11 can be used as a scratch register. Floating-point
> >    registers (XMMs/YMMs) are not preserved and need to be saved by the
> >    caller.
> >
> >  * On AArch64 the callee preserve all general purpose registers, except
> >    x0-X8 and X16-X18."
> >
> > [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most
> >
> > Introduce the attribute to compiler_types.h as __preserve_most.
> >
> > Use of this attribute results in better code generation for calls to
> > very rarely called functions, such as error-reporting functions, or
> > rarely executed slow paths.
> >
> > Beware that the attribute conflicts with instrumentation calls inserted
> > on function entry which do not use __preserve_most themselves. Notably,
> > function tracing which assumes the normal C calling convention for the
> > given architecture.  Where the attribute is supported, __preserve_most
> > will imply notrace. It is recommended to restrict use of the attribute
> > to functions that should or already disable tracing.
> >
> > Note: The additional preprocessor check against architecture should not
> > be necessary if __has_attribute() only returns true where supported;
> > also see https://github.com/ClangBuiltLinux/linux/issues/1908. But until
> > __has_attribute() does the right thing, we also guard by known-supported
> > architectures to avoid build warnings on other architectures.
> >
> > The attribute may be supported by a future GCC version (see
> > https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110899).
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Reviewed-by: Miguel Ojeda <ojeda@kernel.org>
> > Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
> > Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
> > Acked-by: Mark Rutland <mark.rutland@arm.com>
>
> Should this go via -mm, the hardening tree, or something else? I'm happy
> to carry it if no one else wants it?

v3 of this series is already in mm-unstable, and has had some -next
exposure (which was helpful in uncovering some additional issues).
Therefore, I think it's appropriate that it continues in mm and Andrew
picks up the latest v4 here.

Your official Ack would nevertheless be much appreciated!

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNDcVK9gmnBfxbthD3KEzsdc%3DPJb97AXcPEaweLNM5mPw%40mail.gmail.com.
