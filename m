Return-Path: <kasan-dev+bncBDUL3A5FYIHBB4GKYOTAMGQEOEDD3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4565A772428
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 14:37:06 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-d4db57d2982sf1933724276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 05:37:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691411825; cv=pass;
        d=google.com; s=arc-20160816;
        b=qWwTlr45f2nnxHCuQVdHBGpcK4u2FnyAZ2MfN1gqKsrkRZDLaWFGlYJJvbSplq7wrU
         FnsEgNx1NpPKyzadCKP/umAZ/JPNHXkjf4sVEAMBaq9GTmkDNd31BhzbrCNqCedPzoBr
         Fkci5pY6c9bxO/6V2aFVJd27ocVnHbGlFkGUWcAkwsFcuxPjdesKpmBf0uII11On54vg
         t0Nyp00/vReqxrYbBu86hTHm/T4bfWsOA7Zg+fuYKhp5FUr7ynF9AKa63u/hxX26o6es
         ONsp9dluoMqgWw1ThTwY+AXfHwWlQbZQLdJO78Jsk1LLItLTAVs5G0pyDa5EIriYDWNa
         0z9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=cnjMrdVQxHpOiWhIsqh+pjJA5jpneq+oXDag8lg/3dk=;
        fh=DNJA6HcCJhJZCmWWxaPFAvM+QLbC/Wv2H42SXIZ53pc=;
        b=J4jPjezoZB8K7vUcfYOeEJRGch7layzcm85N4wyae270yUjUkrl3E9/GEbmrnMmkFQ
         m+Zl+tG7GP7sPjwCOgy9vSur6oFCPNkey1YUUncjelMr8uDb36gP2nFhowCthrrsbB3s
         3rrirIKZE8kHtECbE+ChnOJ4F4dq0R0oP4RnkU3KYEsKFsqWMJMQqMTQs4n9c/D3N8jz
         VdKnkXYvuzzXxtYJx2YRwjaMxcUvL42YdORv0FdaZO6Z++OwyE4teQr/980ko2KcUbBT
         sizC/N3KMxxqNJmwHFCJu4tdot/h9JPJaQwxOqtV46cvaxubnndDSLUnc2jHWWocYx29
         CMuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YDc7Gq44;
       spf=pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691411825; x=1692016625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cnjMrdVQxHpOiWhIsqh+pjJA5jpneq+oXDag8lg/3dk=;
        b=rineuv4DQiEPEoYKvOc+ci2hvFnR8KsGP5nLHjf7VH4rk1th7hCWivbY93KVzeR8YE
         dlMCXNSfTjvjr7p20gXlYB77L6M8UsLmcJE7uvpXnZPBtQKXSxzXa9S4u18YWvsIxklD
         bK61n+HXIMGot/IYkAZ/hCQa67Ut8SLStoY8bNyVgXh6Cm+PviRNYqnEpLmPTt17Pmnd
         tKj+tm+b1QqDhHtfzDY/uhbt1BYev1N9rgpU0DgXro3HQRiaVh5dgTxdjUInipiQtejX
         pBhKj/x6tItWUoRbOIs5WTHoV06k3sKQIwl5T93K4ojsbXRLIe4oaNzxPCtCQTvSaxzB
         ssyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691411825; x=1692016625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cnjMrdVQxHpOiWhIsqh+pjJA5jpneq+oXDag8lg/3dk=;
        b=bcuWxmMWs7nm2VqA+9MSRCja0BZfM0e30Umd87y6ppPXoPlvBe0t4Y1ZoxHKou/rWM
         0G2mmynIItTIwkHPpICXhORWXTBu8vntUIFeMsdmaqfbzWNjpgiDx7kWYhAC4KttEkbG
         jhKPclIXmcc5fIsBN9lmcvF1CwFqh7vzpr27DX2yAAsA1c187FuFMxWvo1ohx3oxXAr1
         LsMC88tl0vQG0kFBIN1LuagaZVnoJHOvvuVWNP1uQeXholDrdHpJBZyJoDXy8r/F1bXr
         6A+7bX/TgIQmPprQxWN0cXMkEv+Ojb4HL5Hc3xaD/X/zLN2dLAAHPG7jZnJjWrawyEBH
         Q0dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz1azWeYWF0g13fFEIJR9+jK2eXSxg5BEJM53C1EXKuv8Zg44aK
	60UFLK4mogz65BavVqMeQLA=
X-Google-Smtp-Source: AGHT+IEYskyXZjEUoy/A355Z+kmCncTxsqrXxS3uxI+xSXou/UuCUv9SgrwLKHYnR0A23aBwUNKYgQ==
X-Received: by 2002:a25:e706:0:b0:d11:5574:cff5 with SMTP id e6-20020a25e706000000b00d115574cff5mr8661338ybh.32.1691411824805;
        Mon, 07 Aug 2023 05:37:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1241:b0:bff:8b56:c947 with SMTP id
 t1-20020a056902124100b00bff8b56c947ls203303ybu.1.-pod-prod-04-us; Mon, 07 Aug
 2023 05:37:04 -0700 (PDT)
X-Received: by 2002:a81:4e88:0:b0:57a:250:27ec with SMTP id c130-20020a814e88000000b0057a025027ecmr9686801ywb.32.1691411823898;
        Mon, 07 Aug 2023 05:37:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691411823; cv=none;
        d=google.com; s=arc-20160816;
        b=l12xCcUfEHYzE53mCthfRtltTwBM5jYdgBsKA0TLPvvYcdH3H1UfI+l9jt8gVKS9ok
         0bkZJvztk4ZuLdt9Zv7Bt+tIJScJBZq9QXbDbXNWsQLf+riElIh3K2Y7ISiqE+YWCrgU
         w5+zbQZZ5geRY1QFRy0aBQmzxPrARAAVKf9boWjWFxBTSdUnO3W3NSpOsaWddrHBapto
         p4oNWbAUTLyybaBgKeOwOZAekmEFREtmkWZpDQGLGdJrbBG/DO0nWAmF+PvD3DIXdSDM
         LfTT/xYFAA1DXaxwPYq0FBbzKP8vFum8+6jutiYGwlTmkTZH/xDuwR+haHchEllJqOyZ
         D0aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=5CuphCgJIGsELzZCHyihudC7C9xErjXAeUjA0Czr5WA=;
        fh=DNJA6HcCJhJZCmWWxaPFAvM+QLbC/Wv2H42SXIZ53pc=;
        b=vCMvtEvSDrfwejISQBvhQa2vOCTK7xptSsqDz+fwd/fAjOfF3VBwnuIEgO3tkeRlA6
         Louq0Wc1OGYNp90oXcSh3HI/4zOc94c/n8XqPJJd1EO4WT2VAV1899k6uFHVYAbtIlvc
         dR0dZO0Unwy72d5Ugu7Kkm+0kC9u/TUI/XD6vKfztzTcrXqFndBwW9gF78ukq5XXj2kH
         VUcHi1g2ywFT/FrYEHJtvOrVPbCezpOkEC1/psuCLsUrSIHBFWpCTOKb8DvAmC85bTX6
         xe6F9u03rpn1UNQZ/fdse8svxsLqN8i1A1WcFsSohg2dQbQCSjEBgzbrG5YZh0AmTQbT
         BxEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YDc7Gq44;
       spf=pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id fl16-20020a05690c339000b00586a5c739fesi1034767ywb.4.2023.08.07.05.37.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 05:37:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of fweimer@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-642-tFAqekpKOEu5hfmv8bj1iQ-1; Mon, 07 Aug 2023 08:37:00 -0400
X-MC-Unique: tFAqekpKOEu5hfmv8bj1iQ-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.rdu2.redhat.com [10.11.54.3])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 327BD801CF3;
	Mon,  7 Aug 2023 12:36:58 +0000 (UTC)
Received: from oldenburg.str.redhat.com (unknown [10.2.16.12])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 033731121314;
	Mon,  7 Aug 2023 12:36:54 +0000 (UTC)
From: Florian Weimer <fweimer@redhat.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,  Kees Cook
 <keescook@chromium.org>,  Guenter Roeck <linux@roeck-us.net>,  Peter
 Zijlstra <peterz@infradead.org>,  Mark Rutland <mark.rutland@arm.com>,
  Steven Rostedt <rostedt@goodmis.org>,  Marc Zyngier <maz@kernel.org>,
  Oliver Upton <oliver.upton@linux.dev>,  James Morse
 <james.morse@arm.com>,  Suzuki K Poulose <suzuki.poulose@arm.com>,
  Zenghui Yu <yuzenghui@huawei.com>,  Catalin Marinas
 <catalin.marinas@arm.com>,  Will Deacon <will@kernel.org>,  Nathan
 Chancellor <nathan@kernel.org>,  Nick Desaulniers
 <ndesaulniers@google.com>,  Tom Rix <trix@redhat.com>,  Miguel Ojeda
 <ojeda@kernel.org>,  linux-arm-kernel@lists.infradead.org,
  kvmarm@lists.linux.dev,  linux-kernel@vger.kernel.org,
  llvm@lists.linux.dev,  Dmitry Vyukov <dvyukov@google.com>,  Alexander
 Potapenko <glider@google.com>,  kasan-dev@googlegroups.com,
  linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
References: <20230804090621.400-1-elver@google.com>
	<87il9rgjvw.fsf@oldenburg.str.redhat.com>
	<CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com>
Date: Mon, 07 Aug 2023 14:36:53 +0200
In-Reply-To: <CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com>
	(Marco Elver's message of "Mon, 7 Aug 2023 14:24:26 +0200")
Message-ID: <87pm3zf2qi.fsf@oldenburg.str.redhat.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/28.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.3
X-Original-Sender: fweimer@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=YDc7Gq44;
       spf=pass (google.com: domain of fweimer@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=fweimer@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

* Marco Elver:

> Good idea. I had already created
> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110899, and we need
> better spec to proceed for GCC anyway.

Thanks for the reference.

>> Doesn't this change impact the kernel module ABI?
>>
>> I would really expect a check here
>>
>> > +#if __has_attribute(__preserve_most__)
>> > +# define __preserve_most notrace __attribute__((__preserve_most__))
>> > +#else
>> > +# define __preserve_most
>> > +#endif
>>
>> that this is not a compilation for a module.  Otherwise modules built
>> with a compiler with __preserve_most__ attribute support are
>> incompatible with kernels built with a compiler without that attribute.
>
> That's true, but is it a real problem? Isn't it known that trying to
> make kernel modules built for a kernel with a different config (incl.
> compiler) is not guaranteed to work? See IBT, CFI schemes, kernel
> sanitizers, etc?
>
> If we were to start trying to introduce some kind of minimal kernel to
> module ABI so that modules and kernels built with different toolchains
> keep working together, we'd need a mechanism to guarantee this minimal
> ABI or prohibit incompatible modules and kernels somehow. Is there a
> precedence for this somewhere?

I think the GCC vs Clang thing is expected to work today, isn't it?
Using the Clang-based BPF tools with a GCC-compiled kernel requires a
matching ABI.

The other things you listed result in fairly obvious breakage, sometimes
even module loading failures.  Unconditional crashes are possible as
well.  With __preserve_most__, the issues are much more subtle and may
only appear for some kernel/module compielr combinations and
optimization settings.  The impact of incorrectly clobbered registers
tends to be like that.

Thanks,
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87pm3zf2qi.fsf%40oldenburg.str.redhat.com.
