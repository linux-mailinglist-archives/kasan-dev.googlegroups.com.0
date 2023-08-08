Return-Path: <kasan-dev+bncBDBK55H2UQKRBDV7ZCTAMGQEJGBSAQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id F2C7A7739CF
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 12:57:19 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2b9ba3d6191sf53077571fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 03:57:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691492239; cv=pass;
        d=google.com; s=arc-20160816;
        b=SVfm2cuYrz87hkYSACWtjhs2zM6KY4OGgW8iQjZn+nkRlych/guXZ2iVU0krMKCqii
         8ofrbIoRzLhlHERG1igpSrD6oxUQSkwojCZAs2fZq/DdB4KBuTwvisjTgDm9UOWVVPId
         oh5yAtXIaAqmMY1LTwj36lfC/Iomrs0l38L2drkhcJcdtci+v1UtvwGX410l/5wEJqD3
         75hJYsXnNBSybGCXlCjrZHwk5VuCZBX8QYx/FPEpGi+303iFzP+27Hzff63cF9PZepkF
         xqXoNTXl0UFOQRstVUQ3AD4lVlxS5xNg1M7xN/0qmXjxnp4f3PvJbGN6JdVU2/EujPhj
         KNiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=hkNWkDZuxzsTf7RHLaXx/A/u978Iw7Iyivg/bwOsemo=;
        fh=DEWFp4x4IeOm/1V75SpqdaoeA8UnM5fcjxSOKm7M9KI=;
        b=ATEBozqi8TVYYRklIuKtxWCnGKmPtwRiTOWA12QF2vbNUO4rKfCiFk6tI2WU1hcZsf
         hwZv6gEcw8MYibpasTyQF6x+Hb+8I7vX6YXFD2ZL86xB7WOfyZN6mcul1r6tw2rupN/Y
         HK6y0qgQvbx67QZmyvyoTuQ+9S9Irans5Egfv61ZF/D8Nh8iL1DVolcrgpAITt29/YDj
         kp27vHDhrAwkmloRb09jjR2sp1zs6PsUleL+uItx7Ue9iPILi9La+aKUXpgTF8xYdHMr
         Zly3rVZD6WtJ/tqPT/BEt19aYa3TpXmT/j35CQc/Db+HKIuzYVzuF+Ichjo7Afykeuld
         Q1LA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=s+uSHykr;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691492239; x=1692097039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hkNWkDZuxzsTf7RHLaXx/A/u978Iw7Iyivg/bwOsemo=;
        b=CTmKGUZxt2yk80k2JYlUkqahtK/A3a9i9aJLBgi29B8OcRQFfhkalIax0bjXRU9qHC
         l7RFkEYctHXHWUksKX1TA+aaMLb0O5DhN/eBNMoCx5j5niQLP1+5ZO7LHr1umTXBokQU
         gprpYDGZNv8rv9/sZ5UgZJYYqzFBd8Z/5kP1jkD4f+Hkg/gAiFo1RHxGEbCvsFih4hHN
         ef2xWIvkuRA8Gx/w8R4xhcltOKuvNy92pzYNXk1y348ihKCiALOSVROW1kY8NpLamfqX
         0oDoqjQRs4tFlQwQ81MgU4/nQo1nsnfN13+OHGKCnOoIYtw9KSKLeBzXFt3U/KBiKczd
         +w9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691492239; x=1692097039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hkNWkDZuxzsTf7RHLaXx/A/u978Iw7Iyivg/bwOsemo=;
        b=QRKjVwnsQ10RHMNAaYtuOekEePV1+qKrhS1TDc+JeyCOLNqEwmNpVK/b+Ne1gcwucy
         g3bWx7DNKrGxh5XlOCx6O3EIh7I/oszpxVJUn7fh59CXsqiEVxCZ5+C9gyBlDXIsaSsF
         hAa4/YMCf38f2L9iu7FHttIIDk0JdlgRdLplMpKYl+k5Ikpt3anZk8qEarEJM7AFdpaq
         ngPi76HRFC51QY89BSPBFjP3AiuGN6PaEhStU4gkdkekzXJrkHukWc6OUG+JbIY+Vurc
         1t60ES7ijfXzfwpt89UKOmVZEZbo2I/IVdrawSXkoRVQgXkuQpzOSHXo1gcitK1v/Lwh
         qCyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzsuzbWYSHsPeEgqqZMc4QX2ZSesx7oB1dqBTB28fHRAeZ1OZcX
	gQKYjziWFZRRTUCMRToU0Io=
X-Google-Smtp-Source: AGHT+IFFXsE+GdsBJfiFKzPRi4hy36d+JE9/CHQfg00R2SW9+sewF80CU4LZNuMMNddPA23RLud96Q==
X-Received: by 2002:a2e:2e19:0:b0:2b9:e53f:e1fd with SMTP id u25-20020a2e2e19000000b002b9e53fe1fdmr8159266lju.34.1691492238369;
        Tue, 08 Aug 2023 03:57:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c87:b0:2b9:6157:a29a with SMTP id
 bz7-20020a05651c0c8700b002b96157a29als15213ljb.1.-pod-prod-02-eu; Tue, 08 Aug
 2023 03:57:16 -0700 (PDT)
X-Received: by 2002:ac2:5e90:0:b0:4fb:c657:3376 with SMTP id b16-20020ac25e90000000b004fbc6573376mr7104174lfq.29.1691492236204;
        Tue, 08 Aug 2023 03:57:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691492236; cv=none;
        d=google.com; s=arc-20160816;
        b=J3p9z98/girZEQdQkSrg9HjGItAR8s/Zj4JtvuGRWsujiQ7/KVeyT+atmzDQp4BoB2
         35VLpf7PIZ2SqSNQje9GOKChnouEHu/uZPnmrlU4YFMDuhrcpMPxrqgzl9MarGIBcrEs
         xEA8KTAb9vTcIee81SgquUlq4ESzwTSyr0b6Ma6gC3p1LyFaTPS7YislhbjGSNZ0fHum
         0LOBnH/fFL+My7H5NhbxAiemJ9tlCtcok2CRI2YIA7V6B4esa9fsmdLQbD1Qh26TEwyz
         MHWPJXlJi9xXIKlKxtTgwvLwCDO5nzkysA36prS8xKMGUe/+n0pB92RgUXs02fl+vO6B
         JKFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=jW2Ev2fEU+tZ64hL5Q4L57WV2mLp60uuQxKGj9Nz61U=;
        fh=DEWFp4x4IeOm/1V75SpqdaoeA8UnM5fcjxSOKm7M9KI=;
        b=dtYY1TFtlkpvV6ggWPVjQBQJjMTaqGYMMUb/pLOIr6wboXO/dAR5Bl2F1BggK93KkV
         9gZaqKn+ky5I0Jc2cltfgFErTnS62nGgjQv4/h0kfmCI/XKizvlvKrlntMqVhpUFB7/P
         5KcJL5zwI0vTN0okRc5W3YyOpM4vJYzwzeR/F2qwnm8meQvFqyTzfRWYzt0OGX4sBXka
         drrbFSP2x40sopbfmenHom914zuf6ZZBZqVEg//6KHD9IOoxfwKt0vKW2OwQV74xDeeo
         tCZ45pTGQEKhrBk3r5DRruYrxDvFRbOEkbcsPs3dT/CgAhutLr+uIb09NkulgrNp1BLp
         noxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=s+uSHykr;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id d37-20020a056402402500b0051e6316130dsi781938eda.5.2023.08.08.03.57.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Aug 2023 03:57:16 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qTKOh-00H2dm-Bd; Tue, 08 Aug 2023 10:57:07 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C876430010B;
	Tue,  8 Aug 2023 12:57:05 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8B9BE2038C087; Tue,  8 Aug 2023 12:57:05 +0200 (CEST)
Date: Tue, 8 Aug 2023 12:57:05 +0200
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
	linux-toolchains@vger.kernel.org,
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
Message-ID: <20230808105705.GB212435@hirez.programming.kicks-ass.net>
References: <20230804090621.400-1-elver@google.com>
 <87il9rgjvw.fsf@oldenburg.str.redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <87il9rgjvw.fsf@oldenburg.str.redhat.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=s+uSHykr;
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

So in the GCC bugzilla you raise the point of unwinding.

So in arch/x86 we've beeing doing what this attribute proposes (except
without that weird r11 exception) for a long while.

We simply do: asm("call foo_thunk"); instead of a C call, and then
have the 'thunk' thing PUSH/POP all the registers around a regular C
function.

Paravirt does quite a lot of that as well.

In a very few cases we implement a function specifically to avoid all
the PUSH/POP nonsense because it's so small the stack overhead kills it.

For unwinding this means that the 'thunk' becomes invisible when IP is
not inside it. But since the thunk is purely 'uninteresting' PUSH/POP
around a real C call, this is not an issue.

[[ tail calls leaving their sibling invisible is a far more annoying
   issue ]]

If the function is one of those special things, then it will be a leaf
function and we get to see it throught he IP.


Now, the problem with __preserve_most is that it makes it really easy to
deviate from this pattern, you can trivially write a function that is
not a trivial wrapper and then does not show up on unwind. This might
indeed be a problem.

Ofc. the kernel doesn't longjmp much, and we also don't throw many
exxceptions, but the live-patch people might care (although ORC unwinder
should be able to deal with all this perfectly fine).

In userspace, would not .eh_frame still be able to unwind this?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230808105705.GB212435%40hirez.programming.kicks-ass.net.
