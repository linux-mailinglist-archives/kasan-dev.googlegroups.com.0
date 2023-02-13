Return-Path: <kasan-dev+bncBCVJB37EUYFBBO5RVCPQMGQETBSSE3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1760E6943B5
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 12:02:20 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id i7-20020a17090685c700b008ab19875638sf7329031ejy.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 03:02:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676286139; cv=pass;
        d=google.com; s=arc-20160816;
        b=nN5K9z7ZzOyvcHWUixjvIG9UrQsM60B6lFKSe/E8vd6lJ8wrbKtSjTqSkwMoJwBe41
         Bm4VxBci+/q6g34ImxbQVqNPoHxdFO8emRC1oMhPKrqq1aqw5T+1pL0chsbCc1iuYhue
         Jjk1W7GjUDcHkCwWcWSRewrDPIq6sj8zPdmBhSbqyzp25+KFHCTHFICyCP4gotr0YfRg
         v7sEmdR7xxq4c3MWrR3lC7T2h25cZA7tPqUa+S9XbOV30+MG22QFcZ7boKiQoTU7XLfx
         stBP2XIbdYGy2ah3IeruyQgNiCR2HKKBYAs6tIo8mDeSI3HKuX/5FkXbxHX8KlAY84y8
         ky2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=4PF0IFCTaXTB4CaZFtOh0Vk5UkEKxhjHWXXTUkOcd9I=;
        b=VjBChMEIfBb8YxYBbAKrFmUgaM0wUx79IBvHmx6DCctqQLbWR0iDtxE6a5yjZ3nj6a
         X1tb7xMZ6In/X7UBNCtc8E4vE+4bDCagJAgPcPx6OfF0GhsEG+sEkewQZQVpU03YVlkI
         QAYO3oQ5Ynu+aBZ6SuDeXlRLM+QANKzLX+9x6NtX6mZ2+3FzBjxP20ffXpZ2CnbbvA6n
         MDBQAKxDN8Xis6hlE2liDwU8UQAQ520OFWpIzVVEqT29xss2G7MRIKeq8FhzA/ntGA6p
         MxXjX68ZOQ81/Y5bfBoJyj8CnSqaQp/C0kPl0g2DsJtvAMnBygS/Km/yBBbvKATfnYNp
         bVlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Gy7F5PqP;
       spf=pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4PF0IFCTaXTB4CaZFtOh0Vk5UkEKxhjHWXXTUkOcd9I=;
        b=GVWGxplwRYbEbBOkqYev10pwz5bp8xBePQyY+iD2WfiIvvstlmUiRjv28p5M471Rk8
         DgtVoWYzvK5Hm/XSal2ZKCOOPquNwyCGjJZ0CIrJri+wkuZMKbiVFOJnegXJDHuWGVq4
         QDhX0P4ehLJ5qMZuIaCgj53B0wjyQzKddKFSoXR+o0Esp3llRtK7PfuGiWN78hFnNST2
         nHJ8YjhsHQHb3peYdm8uJRhqN2ge7qZmElpTrWdUQy/9OOFYwCs0S4rxRx0fu8LKrh4N
         EJ6qOngkrdtz4KIuLZdZtDxY94wZ3VU8NBOL/tXFedcgg+OC/3MlBU9QgcTXhDUT7gbZ
         IZ/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4PF0IFCTaXTB4CaZFtOh0Vk5UkEKxhjHWXXTUkOcd9I=;
        b=pqNyyB8dTt4xPd40RxkyhlXL1M93Y1hq57YNDsJCud+57rU526kgnrfDCCEblTynlZ
         sjRRyUwvzijmwUCaL6NunO2JV6MoFpCIx2bg08xj0iT0WngeXq4xcfTK0pEtre2Rur6E
         neq+4Pi6SzvfivnyTzUajfHyQwDhl3VbjzJgEWM8ezunKJp8sog1rJQr1AC/R7g+L+3g
         jl3aCWpuUnz1aNcxJDGv31Xo/cMqOmsP7COYECdXJWcHDNN/FA0rBXJ4qdDzinvdZ9O+
         2cbpbHHeZ8t6WfwAyAU8yvOFLCY5jbZac5Z9dMyfH6hC9iYH7cPLJmP7GOdr6m5sW99L
         FEUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXBVFOK+BPUaKXMuKKoCV8a1x4DbfGoxOkFAG8wyhUagAMUoono
	/C9QdpnimvP5wqU0Es6aRHE=
X-Google-Smtp-Source: AK7set///rZfZZJ0iPWbrNLJgFDmG7fpCShgJ96gmEVa9WMieCGKM9/edhCti/F3/+8aK7J08xuVGw==
X-Received: by 2002:a05:6402:51cb:b0:4aa:c33c:1f56 with SMTP id r11-20020a05640251cb00b004aac33c1f56mr7287474edd.4.1676286139443;
        Mon, 13 Feb 2023 03:02:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:52d9:b0:869:2189:ba11 with SMTP id
 w25-20020a17090652d900b008692189ba11ls7581482ejn.9.-pod-prod-gmail; Mon, 13
 Feb 2023 03:02:18 -0800 (PST)
X-Received: by 2002:a17:906:3686:b0:8a4:e0a2:e774 with SMTP id a6-20020a170906368600b008a4e0a2e774mr20915597ejc.29.1676286138128;
        Mon, 13 Feb 2023 03:02:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676286138; cv=none;
        d=google.com; s=arc-20160816;
        b=Z026XD4ul9XR0nH+xHlcsCr1McZI0KwHoqLvZkuMS0S2hJ2Ojk2LYMObXbF9iKBM0/
         pMdxxbpIa8J49l+oulcSaIK783XgBKCPGs5XkxpGPZCnO6RIcFZyglIj0jTce5Poi0af
         66jaNKVTVohWcQ9z67uxpBqC8+oCLWq1gYq9SGWDNf+SwyqvOCPvNwl5teD4TVrNCpdL
         gj0gIdGd04I5ywh12fgc645qaLVGz9PRiGN+Y9x4/IiS85bm9ntmZq5IsVwA15LOeV7x
         KAzRKRrQ6I7P0dC/0ec1uFNChu+TbYzAuQm3HOD9JoRR1UclaDvFVk9eK6WivJC7UXP0
         I0bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DPipqMIHUCjrlTLT8I3BRMh5RmQq64goImG0GQ1TK6U=;
        b=NJPvF37G+r86G+46PMNBCm4sgdzQZkVInF4EeqXFJ2Cl+exPtEywEZFYc+9Uw7gGYY
         98pF5K8uWScLgtPooJLPW8GYUf+5TTZ7IzKjI9N9R0TSxG0166U+AuYqN7efJ8MVW0MJ
         ShyTMJBcuVVRcr1huy9CAxzbj8s50Tf0Y6El5Avn6BUowREtze5HVTM+uVfnoIxcWQQT
         WD0UFMUG+PfugbFz1Sc5gmz0qn5lvc1dVASmlRWttN+mYwNLaqh5QP42ksUMPmNClxqi
         cqY2R00hI/lmoggxFDyxg1ToP3aSXhtYDWA/TvgXc45vGeL3sJwVdT+fAI1x8R3MTKyq
         v8ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Gy7F5PqP;
       spf=pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id i19-20020a170906251300b0087873f29192si590374ejb.2.2023.02.13.03.02.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 03:02:18 -0800 (PST)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-468-Iv_R5x0yN7SFfD4IufwsUQ-1; Mon, 13 Feb 2023 06:02:14 -0500
X-MC-Unique: Iv_R5x0yN7SFfD4IufwsUQ-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.rdu2.redhat.com [10.11.54.3])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 167C1811E9C;
	Mon, 13 Feb 2023 11:02:13 +0000 (UTC)
Received: from tucnak.zalov.cz (unknown [10.39.192.24])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 2AE071121318;
	Mon, 13 Feb 2023 11:02:03 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.17.1/8.17.1) with ESMTPS id 31DB1nJ33945034
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Mon, 13 Feb 2023 12:01:49 +0100
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.17.1/8.17.1/Submit) id 31DB1ee53945033;
	Mon, 13 Feb 2023 12:01:40 +0100
Date: Mon, 13 Feb 2023 12:01:40 +0100
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
        Masahiro Yamada <masahiroy@kernel.org>,
        Nathan Chancellor <nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>,
        Nicolas Schier <nicolas@fjasle.eu>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, Ingo Molnar <mingo@kernel.org>,
        Tony Lindgren <tony@atomide.com>, Ulf Hansson <ulf.hansson@linaro.org>,
        linux-toolchains@vger.kernel.org
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable
 memintrinsics
Message-ID: <Y+oYlD0IH8zwEgqp@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20230208184203.2260394-1-elver@google.com>
 <Y+aaDP32wrsd8GZq@tucnak>
 <CANpmjNO3w9h=QLQ9NRf0QZoR86S7aqJrnAEQ3i2L0L3axALzmw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO3w9h=QLQ9NRf0QZoR86S7aqJrnAEQ3i2L0L3axALzmw@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.3
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Gy7F5PqP;
       spf=pass (google.com: domain of jakub@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
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

On Fri, Feb 10, 2023 at 09:07:14PM +0100, Marco Elver wrote:
> On Fri, 10 Feb 2023 at 20:25, Jakub Jelinek <jakub@redhat.com> wrote:
> >
> > On Wed, Feb 08, 2023 at 07:42:03PM +0100, Marco Elver wrote:
> > > Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
> > > with __asan_ in instrumented functions: https://reviews.llvm.org/D122724
> > >
> > > GCC does not yet have similar support.
> >
> > GCC has support to rename memcpy/memset etc. for years, say on
> > following compiled with
> > -fsanitize=kernel-address -O2 -mstringop-strategy=libcall
> > (the last option just to make sure the compiler doesn't prefer to emit
> > rep mov*/stos* or loop or something similar, of course kernel can keep
> > whatever it uses) you'll get just __asan_memcpy/__asan_memset calls,
> > no memcpy/memset, while without -fsanitize=kernel-address you get
> > normally memcpy/memset.
> 
> > Or do you need the __asan_* functions only in asan instrumented functions
> > and normal ones in non-instrumented functions in the same TU?
> 
> Yes, exactly that: __asan_ in instrumented, and normal ones in
> no_sanitize functions; they can be mixed in the same TU. We can't
> rename normal mem*() functions everywhere. In no_sanitize functions
> (in particular noinstr), normal mem*() should be used. But in
> instrumented code, it should be __asan_mem*(). Another longer
> explanation I also just replied here:
> https://lore.kernel.org/all/CANpmjNNH-O+38U6zRWJUCU-eJTfMhUosy==GWEOn1vcu=J2dcw@mail.gmail.com/
> 
> At least clang has had this behaviour for user space ASan forever:
> https://godbolt.org/z/h5sWExzef - so it was easy to just add the flag
> to make it behave like in user space for mem*() in the kernel. It
> might also be worthwhile for GCC to emit __asan_ for user space, given
> that the runtimes are shared and the user space runtime definitely has
> __asan_. The kernel needs the param (asan-kernel-mem-intrinsic-prefix)
> though, to not break older kernels.

So, what exactly you want for gcc to do with
--param asan-kernel-mem-intrinsic-prefix=1 (note, in GCC case it can't be
without the =1 at the end)?

The current gcc behavior is that operations like aggregate copies, or
clearing which might or might not need memcpy/memset/memmove under the hood
later are asan instrumented before the operation (in order not to limit the
choices on how it will be expanded), uses of builtins (__builtin_ prefixed
or not) are also instrumented before the calls unless they are one of the
calls that is recognized as always instrumented.  None for hwasan,
for asan:
index, memchr, memcmp, memcpy, memmove, memset, strcasecmp, strcat, strchr,
strcmp, strcpy, strdup, strlen, strncasecmp, strncat, strncmp, strcspn,
strpbrk, strspn, strstr, strncpy
and for those builtins gcc disables inline expansion and enforces a library
call (but until the expansion they are treated in optimizations like normal
builtins and so could be say DCEd, or their aliasing behavior is considered
etc.).  kasan behaves the same I think.

Now, I think libasan only has __asan_ prefixed
__asan_memmove, __asan_memset and __asan_memcpy, nothing else, so most of
the calls from the above list even can't be prefixed.

So, do you want for --param asan-kernel-mem-intrinsic-prefix=1 to __asan_
prefix just memcpy/memmove/memset and nothing else?  Is it ok to emit
memcpy/memset/memmove from aggregate operations which are instrumented
already at the caller (and similarly is it ok to handle those operations
inline)?

	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2BoYlD0IH8zwEgqp%40tucnak.
