Return-Path: <kasan-dev+bncBDBK55H2UQKRBOOIYOTAMGQEGVZBJFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 10EC5772413
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 14:31:55 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3fe3feb7e2fsf7767435e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 05:31:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691411514; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kz6ROYv/w4nM1Al8i75PDFznqIXIpnLGZziZqjipxTq0Atl2wuXMt4ehm8BrHPXeEh
         Nmh7paS8b/NtM06NzAw6zUmOc9BapHST8ari+B/A4xhB/bkqhC1REEm8sruZ9LLVfbHu
         4f9KP+Dv6qX+Gdyz/qP182W0LN80xunrhjv8OIm7z9icMOY1k68rpPHnUcui8euqxvZT
         LVA4aljugbleAvymnnU31BgqojDb1+6SxEgx4WvzGVc8+Fn81ayRkCzXcBlOrweFbyLA
         WUUMfOgpxPlaazH8MypdNBps3OpSoR0zh5HyUGKDAbNGCrVmvU5TE/mJCa3mr4fF6nwO
         oLWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ExQJnwxgvGFKCtCUs8fudx98OaFADArzVwgSktQWbXY=;
        fh=3T48dBajmuzuZqkU7TBWQfXJzDUTzUOImv3KVSY0ZcY=;
        b=CI/CaNmXvT/bEvDu3xuuf4oTN2Yn3jEvj58OGXkyrMMafrmhIe5wNeToRkZ/0BPdu4
         ukSeN+0/+cs5w0mvfNa7c7aTyW++Yobqs65dBRElXP+xiQHJ1biml5oN77/BKVlmUWVN
         uFYt41OgZC0nHg+SW2lblcbTs39W+xzdcZz4YQPaNBegggftnfBfZHurjXB4hRsf5tsJ
         TpFXIhCiPwVRC5aWKBrb8YvthL0CcH0eCG5ccHHqU585TIkw/92G3EFgf3Ti5SReFfbJ
         ulO4/857gqXDEmxJz6EhUVziQjUA/S4zhRQXOsbegFHdGoeOvHi9F7akf+ySa0gEQX06
         LOSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jnIrvved;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691411514; x=1692016314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ExQJnwxgvGFKCtCUs8fudx98OaFADArzVwgSktQWbXY=;
        b=tS46fYLnDIcaPeEaFS7KW+9cWQuuPNbIaHIM9sMpM6ENXG4ygc5HQKY8+Xaf9jPL4f
         Wm/cJW7IONROO/Zl7VWVsDN6regFAB7fndMQKF2V/lPns2Kc/9mrDLmpNTet5+NomGcU
         rF4/K+PpN1ig2XrrZwy43KebXuCRb2EmPRz95gUQnUVHmgiOppl3OOd1KgegoD9cjgH7
         FPiZ0uSuqqyT22HVsULmVAT0H0+jjd0yd5XK/WwPe1KaQdeUSBTcVoRQoRaUCf8jxEje
         nRg2q8Tq9RIln73zMmJzenebK4nuISaQ7DmxyEnlpzWoDk9XSWhkE6sVKcz926ezNhSy
         mfuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691411514; x=1692016314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ExQJnwxgvGFKCtCUs8fudx98OaFADArzVwgSktQWbXY=;
        b=jO8ZLQCNcw8mah3ISPayi0jU7YcVzULR19drIGVs6ARQkuOniYhIk4GdkAjK0yDERq
         BRMiquLIX9YcintnT/An5yBiKEU6Q5SoE2urc2/BlwmKWyZeRjXM5HZPBNj5cYSQ2FR9
         DE9VSx16u9Aocgf8k/lM39HiMG+uxvlWZvVYaa7C+aekGKlx7giXa/vfjngK+EmnXl/H
         AfX5+Diwsmi0dtSZZ3B+RVwq/SgGMwT+cdboNgX5EZk60vQotiohhOXurEYlusER5CY1
         ZXgCc0UfoXeRtJFSysevmUANe5KDgu0b9IiitYjZSVW2ozOL6KArhtKJc9s/5pYfTGGQ
         os8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLamC4b3HH23zcm863ellDWmmBysq72KUAB+wMNXF+WEMMTbxI5r
	KDEc9F9FEIWiluwB1iB74Es=
X-Google-Smtp-Source: APBJJlE94p51QGVg1pOcXaAbsjhha1xB6233WHuV5eEjni5IhfU3jluEni//0bz+4Sc11z7Uw5Wj2w==
X-Received: by 2002:a05:600c:1d14:b0:3fb:3dd9:89c with SMTP id l20-20020a05600c1d1400b003fb3dd9089cmr23001029wms.0.1691411513739;
        Mon, 07 Aug 2023 05:31:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d8a:b0:3fe:2103:c3fa with SMTP id
 p10-20020a05600c1d8a00b003fe2103c3fals951789wms.0.-pod-prod-01-eu; Mon, 07
 Aug 2023 05:31:52 -0700 (PDT)
X-Received: by 2002:a7b:c5d2:0:b0:3fe:26bf:6601 with SMTP id n18-20020a7bc5d2000000b003fe26bf6601mr5690378wmk.11.1691411511985;
        Mon, 07 Aug 2023 05:31:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691411511; cv=none;
        d=google.com; s=arc-20160816;
        b=TiwxFoPNDulFShW4lPI/DzVLVw86sai8/aBT1dzQFIQ9FurWk1MckQYuq+I6AlELXF
         2ePT+hu4Ev5xJyI6S9CxT+KQqfAxKYBJp2b6wNQWHjYDq1h6X81XGEe8vdkpR5CnPsum
         xG/PiwSd3zS8i84GCLzRhLbSW0HCnzMba25lihRLMowsRtX98gO5hV7XJ7z1UnN8ePAi
         /dpu/bvZv90yQ/drz8Q4Z9+46FkBW7nDULbVrS/vlsvNb5sKYL/b5JplSafkW8f3SNWd
         HMmyh56CbQnXkBWP6ZVMHhKRBfQ8WGKVk05z7PuURpoIT8R2dgbX8ReONWFhetAsm4ys
         dV1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=MKVDKc7Pqd1qB2ritThbJyFE9EXb4dytHxurnka2dE0=;
        fh=3T48dBajmuzuZqkU7TBWQfXJzDUTzUOImv3KVSY0ZcY=;
        b=sqANk6PplsX9jDnYdG5FHC9vmhb3dXKdk7Jejj5IatAL6DuKLZn98UUNsO3qI6UCtl
         tZGtdOkdTMf+426JYKgbPj8bUXYFwonIMXxgK1KvKtGux4HmCpTI5lBrdZuC+vk7mmhz
         sqrFWeo276shB05vR4fMEseLfUj0vmCoF8RdM71AU3Sbt2QO5hOkfxjyffjjmWAOVZ24
         GfwV02b7UjhrS79dK/EkLgaEiy/xat7ZF7S0BRHnnTvo/Qy8nfcvFYutIiTN94a3EPaC
         4tMLZ1IYUy1re4D+RBIPTfVqyZgfbqXZp7QBCygZzexFZWAwL90LJk6xCA5UCv6tx3Cm
         K0NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jnIrvved;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id n16-20020a05600c501000b003fe16346f74si636737wmr.0.2023.08.07.05.31.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 05:31:51 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1qSzOd-003oMs-0g;
	Mon, 07 Aug 2023 12:31:39 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7727E30014A;
	Mon,  7 Aug 2023 14:31:37 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 299ED203B463D; Mon,  7 Aug 2023 14:31:37 +0200 (CEST)
Date: Mon, 7 Aug 2023 14:31:37 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Florian Weimer <fweimer@redhat.com>
Cc: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Mark Rutland <mark.rutland@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
Message-ID: <20230807123137.GA564305@hirez.programming.kicks-ass.net>
References: <20230804090621.400-1-elver@google.com>
 <87il9rgjvw.fsf@oldenburg.str.redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <87il9rgjvw.fsf@oldenburg.str.redhat.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=jnIrvved;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Aug 07, 2023 at 01:41:07PM +0200, Florian Weimer wrote:
> * Marco Elver:
>=20
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
>=20
> You dropped the interesting part:
>=20
> | If the arguments are passed in callee-saved registers, then they will
> | be preserved by the callee across the call. This doesn=E2=80=99t apply =
for
> | values returned in callee-saved registers.
> |=20
> |  =C2=B7  On X86-64 the callee preserves all general purpose registers, =
except
> |     for R11. R11 can be used as a scratch register. Floating-point
> |     registers (XMMs/YMMs) are not preserved and need to be saved by the
> |     caller.
> |    =20
> |  =C2=B7  On AArch64 the callee preserve all general purpose registers, =
except
> |     X0-X8 and X16-X18.
>=20
> Ideally, this would be documented in the respective psABI supplement.
> I filled in some gaps and filed:
>=20
>   Document the ABI for __preserve_most__ function calls
>   <https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/45>
>=20
> Doesn't this change impact the kernel module ABI?
>=20
> I would really expect a check here
>=20
> > +#if __has_attribute(__preserve_most__)
> > +# define __preserve_most notrace __attribute__((__preserve_most__))
> > +#else
> > +# define __preserve_most
> > +#endif
>=20
> that this is not a compilation for a module.  Otherwise modules built
> with a compiler with __preserve_most__ attribute support are
> incompatible with kernels built with a compiler without that attribute.

We have a metric ton of options that can break module ABI. If you're
daft enough to not build with the exact same compiler and .config you
get to keep the pieces.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230807123137.GA564305%40hirez.programming.kicks-ass.net.
