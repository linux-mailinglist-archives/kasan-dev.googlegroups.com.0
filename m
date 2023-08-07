Return-Path: <kasan-dev+bncBDYJPJO25UGBB3E2YSTAMGQEJDX3YXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C185772927
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 17:27:42 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1bb691357d8sf7033320fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 08:27:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691422061; cv=pass;
        d=google.com; s=arc-20160816;
        b=CP8k30CkzRfcC+8Dg5zBl1lVCTir1ReZbBTBq9MMA+HhCFOsX1dCQyNLvCdknOJWCe
         Y/kLYqHH92soWZAn21mvGvcUOrl8d6vIakQdN39FCaAd4K9AeuEO8FlbWaTw2FENVoCS
         I4EMf4BP3mvy3sY9+uKIyFsIwcol9+LpEHQ666ailz/8lv6TlSvh0F/g258b3kJ+PlVh
         z83ZIeUoK0VDWkBqyMQ6AzVzvUH016M/cbe4nPHH6PE9X3nYrlzD8EIc+rVFYoGgPrRG
         Os1uQf6AJ4MsEcivXDavPoqINENlLGCWLP1BCZOJuoO3ergGZnoiWWPntWSOT+18g3lC
         oF1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VgBVZEAVbu5EhNOPW7SBXlUVZ6B0xPH6G5mmd5XI+DY=;
        fh=7I9w4K3D03l7AtqfDnWSh0ugHQJMdQqvtNK0uXbXN6I=;
        b=N23TsF/jnyzDCK2GQOk8uqncUSsxJwRxFqwiQpZrMDnFIcBAa7kmMtOo6B2yWjoIyr
         5FbDFQcLIUM3/ddsc89MdXobe4XOpN+hO14fOmVse93BXyp1/R5RJbjsWZGUbKZur8k+
         GUvdtepSH+Evp4227WBkKCSSHXuE2gnpySOz6a19i6DYPPj6B6sGbUts+Jr8UhPivxch
         wmNc/H7bCUsqx9RhMX25fsZTCBBHd5L+TTDthzZHX0Kp5kT4kxWFFC60glzWXK5D3XYL
         +wQsvMyPIvEOYTAmHJBgsgI9OoBJq3dOsYxnPt9A2axxUhCw+nYP0Fk+9etOLJd2r747
         S6hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ZWONZDbN;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691422061; x=1692026861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VgBVZEAVbu5EhNOPW7SBXlUVZ6B0xPH6G5mmd5XI+DY=;
        b=Uau3qX3Iypok1RxljH0uxs7GefzY6Gzpu8Czwzr4bozoiM4AfzUn6e2hZb2RVJmW9E
         sdwYJiQkKEO0JL/zFBYyj9hESC5rqDP+zD5m9ciTEi+hgJutjKNuosGstpWAjIWt8W/Y
         XI2RUXGkNTCja8XlbQ0LYaqiacHxFalRJ8/wG+tK2AZf+0rnghd3qOP+Gx2bfxPmvAun
         tMdAqH1QReDBhYoO/svt5Fd8vBiI8nbddJ4PteoiSVAjzPJE3oPeBQYzfcqY0MnXvPIB
         6S0ZwM/aJtSqIWiKqxn01WQ4zswztPk5mfxh2pv4ZQA6+vX+BnTKcPCo+cMv2TMQZ6/h
         +TkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691422061; x=1692026861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VgBVZEAVbu5EhNOPW7SBXlUVZ6B0xPH6G5mmd5XI+DY=;
        b=YxUF8u82O3SuofSkOSEAKO19OnX1H53xwuj1izpiCwKXmCl/PntX5L5ITXo/GdEghn
         pZl/Mq5mmOQ7u5DvwpL4f3l3RQCxPlqaGMLZlAxF3nwSJgpdMtd57xHhWWD33qFpAAW/
         rr2ps+uBRFQqmP0geGcdmGNLPspRnjx9he3hhz5BacpdeDjMzssgj23emkEF44/NtFqC
         YNQq7gB0smerr7lY2ypS+U8P5NLkbM49K4Amx3Q2J9YJgc8EK8iVG0eB8Qi4na0zoBRx
         yyls9jET5iQ0EMGFK1e3ZxKR1cQxgIXSAMn4yH+el1nHmauya4qDvLLDNhAUOoaEocY5
         /9SA==
X-Gm-Message-State: AOJu0YzL0S0Yo8bsWsbUN6eSAGbY/NJpE1iAKZpRBcPMjLhm77iDj/W0
	juXexyygOFbZt1vgTBLKBEo=
X-Google-Smtp-Source: AGHT+IHGS1AuAe/YPdzIcdKyHSHCnSRkQpLuTY31Bqq/tNRGDbDpOJvMoBMuLxURJbbxy9qeyhs58A==
X-Received: by 2002:a05:6870:170e:b0:1bb:9907:451e with SMTP id h14-20020a056870170e00b001bb9907451emr11124273oae.52.1691422060967;
        Mon, 07 Aug 2023 08:27:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3308:0:b0:56c:6ba0:66ba with SMTP id q8-20020a4a3308000000b0056c6ba066bals2315317ooq.2.-pod-prod-02-us;
 Mon, 07 Aug 2023 08:27:40 -0700 (PDT)
X-Received: by 2002:aca:2103:0:b0:3a7:44a1:512c with SMTP id 3-20020aca2103000000b003a744a1512cmr9423457oiz.5.1691422060168;
        Mon, 07 Aug 2023 08:27:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691422060; cv=none;
        d=google.com; s=arc-20160816;
        b=sz7MGF4X3NzREkHtCKrIlcq5tDWVDjVWZtUX9YyvjomnNFqVtjx7DI9kVguMxOCL+K
         qUUTye2oruYvwcZdYZQa6wb/miM+NSGVTj/yGcANdzkMHKiKZ2ab5iwH1fZ1cIipOQG7
         iUmR4PKrqzi1nPgvb2cDKtsIutihr/zhvmQZhChkXTFcsZJTCYUug7aH9W5u0uqNHqR1
         BlpNNqCRyMARdxj1WJiDAIDtl0tX7Pgtoc0PTEu0R70rHNZN35MnfxuMdr3auYdvaMb9
         vuL0S9p4JCYp+jsEBdyCAuwrhlWw2XJo6bqheiGETiO8/7jfbvU0qysyibqIQNtc0WV/
         GmFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dUwZAwY3w/DCovXOhpFaYpG5BJu/scVYyvQE2nkhLjk=;
        fh=g7yfDPnDDYjP0vmEInSqdUVyLPpgtthrG2gHyGKgBKs=;
        b=v4PZcHRALJEYclkjFz39kA6ZSUn6LiWZoOialoZEGkzHqDpAZTfMlAO5AOVmXbcTIU
         3zv/3NlHBBtRv+/y7mGMV3nPQMIoy2t1ZFhM5pQNeOF3wbLVf2/xzWYaNzsXFUqhZt3R
         WKIlsX+Cewo0nIUUvno3gQrHWMefnnl63BS9j4XNSIzjj9jksNiL04oQGXKd7lh+cgWg
         LHA8RrRpnKU77Dl/ONQltXiuryc4oqflF0KezE0eNQKQ5Mx866VB0D+vw4qGY87mb6nY
         vFHIFCjDZ0O/Vlcl3QKAp+54nlsL+ilj4XPbTjEEFjBRQmVWtU3vhoe/uugrTNnm0sCi
         qkng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ZWONZDbN;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id p15-20020a634f4f000000b00542924cbf7esi425751pgl.5.2023.08.07.08.27.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Aug 2023 08:27:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-63cf28db24cso28308456d6.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Aug 2023 08:27:40 -0700 (PDT)
X-Received: by 2002:a05:6214:580b:b0:63d:36ab:93e6 with SMTP id
 mk11-20020a056214580b00b0063d36ab93e6mr9060294qvb.65.1691422059150; Mon, 07
 Aug 2023 08:27:39 -0700 (PDT)
MIME-Version: 1.0
References: <20230804090621.400-1-elver@google.com> <87il9rgjvw.fsf@oldenburg.str.redhat.com>
In-Reply-To: <87il9rgjvw.fsf@oldenburg.str.redhat.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Aug 2023 08:27:27 -0700
Message-ID: <CAKwvOdm7cTWmp-wAgePBQpa19=PLaYWh6WxJbNUcasSn87ecnw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
To: Florian Weimer <fweimer@redhat.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>, Guenter Roeck <linux@roeck-us.net>, 
	Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org, Jakub Jelinek <jakub@redhat.com>, 
	Greg KH <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ZWONZDbN;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::f35
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Mon, Aug 7, 2023 at 4:41=E2=80=AFAM Florian Weimer <fweimer@redhat.com> =
wrote:
>
> * Marco Elver:
>
> > [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> > convention of a function. The preserve_most calling convention attempts
> > to make the code in the caller as unintrusive as possible. This
> > convention behaves identically to the C calling convention on how
> > arguments and return values are passed, but it uses a different set of
> > caller/callee-saved registers. This alleviates the burden of saving and
> > recovering a large register set before and after the call in the
> > caller."
> >
> > [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most
>
> You dropped the interesting part:
>
> | If the arguments are passed in callee-saved registers, then they will
> | be preserved by the callee across the call. This doesn=E2=80=99t apply =
for
> | values returned in callee-saved registers.
> |
> |  =C2=B7  On X86-64 the callee preserves all general purpose registers, =
except
> |     for R11. R11 can be used as a scratch register. Floating-point
> |     registers (XMMs/YMMs) are not preserved and need to be saved by the
> |     caller.
> |
> |  =C2=B7  On AArch64 the callee preserve all general purpose registers, =
except
> |     X0-X8 and X16-X18.
>
> Ideally, this would be documented in the respective psABI supplement.
> I filled in some gaps and filed:
>
>   Document the ABI for __preserve_most__ function calls
>   <https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/45>
>
> Doesn't this change impact the kernel module ABI?
>
> I would really expect a check here
>
> > +#if __has_attribute(__preserve_most__)
> > +# define __preserve_most notrace __attribute__((__preserve_most__))
> > +#else
> > +# define __preserve_most
> > +#endif
>
> that this is not a compilation for a module.  Otherwise modules built
> with a compiler with __preserve_most__ attribute support are
> incompatible with kernels built with a compiler without that attribute.

Surely the Linux kernel has a stable ABI for modules right? Nah.
https://www.kernel.org/doc/Documentation/process/stable-api-nonsense.rst

>
> Thanks,
> Florian
>


--=20
Thanks,
~Nick Desaulniers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKwvOdm7cTWmp-wAgePBQpa19%3DPLaYWh6WxJbNUcasSn87ecnw%40mail.gmai=
l.com.
