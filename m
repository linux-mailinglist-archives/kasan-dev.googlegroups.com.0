Return-Path: <kasan-dev+bncBDBK55H2UQKRBHEDRHBQMGQEKPCOCKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id E09F7AED61E
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 09:49:52 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-32cf580cacdsf2767641fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 00:49:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751269790; cv=pass;
        d=google.com; s=arc-20240605;
        b=OaKBEGdMPdfmCZq4jo/C6NQfjXPqU0GlJIQz2/QLrx78533enU5wQWYBiRYI8zQ3ig
         8rQXSIWfmKp2JtYqaAF4zpD0yHYHPJvaRQuTIKNEPGhRbvrlGGxGNyHfl5bz1eCJdJcV
         2frru2JjK+mVbdYNwqIWbgVPFw80aJpznFFk8zaQnmgCAS+S5yJPYT7sZ9PQbrj9Yw9G
         Rb04Y4CIYWXkLlJSQxRT8wWrYvOPxgAh42W/3aUx938dLH4fC0Hwg3jlKyEjbUFa78Ku
         EUNCu7HF9DvrArAWjyKOFr/kS1Jr+7UW34L2N630IVD1qOZB4aQl8CgRZmJwq6255gfF
         dRKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kJ4ra8xZ2FQk8ZMOn3AXBHfNTXyssrjvbWu/HnLYyF0=;
        fh=FAmjDZPoIxv4ajGVi4VpqUeGtficeGZXpHtdLEysICY=;
        b=aONIw6hPiGlyW1nVpsUfOPW16Wzuye4YIJGH6Wj9tN2nKou8Tw8cFj6G3+8lljhz16
         IrDZVPk+o9xMFdIbw8Kvwka+Ivpjxur/FVH1mG744CieRTdGsxdHpg3xBtvGEutMWl8y
         CF/8mkRtrhUqnTEcHJs94IkNJHz7E+X4ZwPSK3ZQWmuLaXoymhAy3dJDdR/2w1XyQKxq
         3TfZyTWcXZeUQMZbu6XDE4lkFmT6yvoaZlho13mCBhEX1cvBkyCCGcr6jNVX7zFN/cRN
         nEEpve8QnqiviaRNkRinbvhu44+KpL8eKlzU2IjivqueqESxCmgmRNdNCwExJgAUE31Y
         vFbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="i/3qzLN5";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751269790; x=1751874590; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kJ4ra8xZ2FQk8ZMOn3AXBHfNTXyssrjvbWu/HnLYyF0=;
        b=v4XWwpAvBV0t48vt7yAb4TN0Z57qrKUUHW+qzpW5tXSn+mCCgzhk8Zhi2CgSX43MRs
         cuynhB1AB8s1bjmArOoaMqMg0fEUeW2RAlK7QWHQAmNegfRI5ZizHxIbJELn//zx69gH
         CaRz2jXdFavy/b0VnPBeDDuh4yoRHmuS0uj1hRK7M2IyACICwm6L4uHGxgVGRr4zUWT4
         UbaQ31tcKhUF5ARTdBrj6i6eBOXqOuw8X2OIoGK3ymNwOXPPQDil3hr22wmFxqEHgQ1A
         3sxX7IMIT4+Hi90XP/8qnk4rqMJTwZth/VjIhP7hoTmpfV9Orml/82zWnJFCR1bCb+gg
         jJuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751269790; x=1751874590;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kJ4ra8xZ2FQk8ZMOn3AXBHfNTXyssrjvbWu/HnLYyF0=;
        b=AbWxqKdoaXFJO099LhyPdCRqXrn9eF1CAJs7fflAk638Avs0+Fgvi8iJbNyc6zXAUj
         EIrlTkqBAySMIx0KXtbu4Nj75LrcN92nZhVakTagbvnyGDyx/tjftX1S0FCTSXAgYG6o
         Magj1JtH5p1CLmxDla1EwazI+FObFZACqpREMUg4qa7rtdgEFogPl8FL6RG0Ww3m6Ya7
         tGsvWa56NJQ7PfKpKrEpojFUmXUTJsmZpo+r16T5tZ+bpcoKAfuDcCTWcBXxKoeRb9U7
         NKGxEPsJVa4OFWMBtWqmPF0ZvNwHvDOcYzc2LpE0DezOA0GTKAJMRjELOg2C7TdhnRTp
         qRpg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqYR5fh/S87yKHw73MerDRM0EpJBWh9fipO0WvBss+5vXibXdEztHTTTepINrwOG/BIPg7rw==@lfdr.de
X-Gm-Message-State: AOJu0YzR40SH+ZWHaBraRsRiIMjwFHpPoZkXyk96HRSdnAxRXkTgSiMg
	2I+wgYNRHq9Zx3iTj4iEdw4bKqDSx5yYYreKctPA+vcV11EzH/BfocEh
X-Google-Smtp-Source: AGHT+IGK9vDgGnna9pFMkzlTwKe0IwkPNCmB4J93dnaNq86r2MFcMKpeHiDKgbikAj0mdTjNVuxccQ==
X-Received: by 2002:a2e:8a82:0:b0:32b:387b:de4a with SMTP id 38308e7fff4ca-32cdc50f1f6mr19534191fa.39.1751269789619;
        Mon, 30 Jun 2025 00:49:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfudHMTzexF1Nl1oPMw5/xCl79ahyg8gLIuqcPUXdKFhA==
Received: by 2002:a05:651c:31d0:b0:32b:8061:6a8 with SMTP id
 38308e7fff4ca-32cd0215c08ls9230181fa.0.-pod-prod-07-eu; Mon, 30 Jun 2025
 00:49:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU14GkOxbXmuROQQbf4VdZclu0sdbP46Dllh8NvMRZyM6Ob3f4QLGst8uIVCZMoXmDKRG18mGcdQQ0=@googlegroups.com
X-Received: by 2002:a05:651c:481:b0:32b:488a:f519 with SMTP id 38308e7fff4ca-32cdc42d1c1mr26252611fa.6.1751269785829;
        Mon, 30 Jun 2025 00:49:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751269785; cv=none;
        d=google.com; s=arc-20240605;
        b=bEgVdspRLYX9WyND4f23K1lRnhYhJnCEBZ/8KQPbjN5rwh5gyQzu9ztFmfdPo1cJ2q
         02GEDx45XK6faJoZV/TU59+u19yIRI0eEt5kNRVOQgswHFtvShT1A1fms9b8wZ34FLM2
         dRUPJKuCqyBrQG56GDfnbG5YHFL7bKkvUvHXIIH9G6/Nce92qjoNcBlxHA05vu9FeuW7
         LbVitj76OrxwD2n91BTKmn4qwBvmbGYTFu+ul4ULlT7G9wouWH4cVVlzVhTC4x8i8xij
         5QMmnOpXGvpohC5zAAPA6D+rHEE3YKjVrKqmTQlrVE/vBsz6uOcFZAJiLrVjSCCsIMcU
         1iZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=l3fYRR450ammdDlTOiwajM+tXSXrmrYjTa8TBG4lRN0=;
        fh=6TKN9zgLvb/CKgMZeaoGfcJ+4WSlcvu0IVYYdqB+xXE=;
        b=h0YuRJ9AsarlW++7b/9qVrib7xw/fh7ndvO3dDqvoODlq+hZqtX47oHEi+KLFEZMRK
         WI02JjReB9QEm7yIQ+RaVOsEDJkhhN+P4bKlDd6vO+h3NyK4VlU2skKl/mygMu0CQ7ql
         FbAMElIiARg/rhNLsmeFDoQWbQKwLSkTRlgHSegC3c6jHqkDpaB4jF9N22kp0Q4yxVL6
         yiHwlGRT+CFxjcRY+QKGB2UOd9wEu+FRM1p0HVCGf1RvkBBdMeR+ppG6Nfd+CZDLz7rF
         M21vGGKoQ3yddRGcXTiHGLN7cPexfWbSMHviFUOeKPCzxcdxImOvx4RW1sH5giqNiRtF
         ZyiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="i/3qzLN5";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32cd2db0b4asi4324491fa.2.2025.06.30.00.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jun 2025 00:49:45 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uW9Gp-00000006k7R-0910;
	Mon, 30 Jun 2025 07:49:43 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 96703300125; Mon, 30 Jun 2025 09:49:42 +0200 (CEST)
Date: Mon, 30 Jun 2025 09:49:42 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, x86@kernel.org,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 06/11] kcov: x86: introduce CONFIG_KCOV_UNIQUE
Message-ID: <20250630074942.GH1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-7-glider@google.com>
 <20250627081146.GR1613200@noisy.programming.kicks-ass.net>
 <CAG_fn=UrOBF=hQ5y6VN9VuA67GeVOyaaWtrnaSLz4TnC7u1fiw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=UrOBF=hQ5y6VN9VuA67GeVOyaaWtrnaSLz4TnC7u1fiw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="i/3qzLN5";
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Fri, Jun 27, 2025 at 04:24:36PM +0200, Alexander Potapenko wrote:
> On Fri, Jun 27, 2025 at 10:11=E2=80=AFAM Peter Zijlstra <peterz@infradead=
.org> wrote:
> >
> > On Thu, Jun 26, 2025 at 03:41:53PM +0200, Alexander Potapenko wrote:
> > > The new config switches coverage instrumentation to using
> > >   __sanitizer_cov_trace_pc_guard(u32 *guard)
> > > instead of
> > >   __sanitizer_cov_trace_pc(void)
> > >
> > > This relies on Clang's -fsanitize-coverage=3Dtrace-pc-guard flag [1].
> > >
> > > Each callback receives a unique 32-bit guard variable residing in the
> > > __sancov_guards section. Those guards can be used by kcov to deduplic=
ate
> > > the coverage on the fly.
> >
> > This sounds like a *LOT* of data; how big is this for a typical kernel
> > build?
>=20
> I have a 1.6Gb sized vmlinux, which has a .text section of 176Mb.
> There are 1809419 calls to __sanitizer_cov_trace_pc_guard, and the
> __sancov_guards section has a size of 6Mb, which are only allocated at
> runtime.

OK, that's less than I feared. That's ~3.5% of .text, and should be
quite manageable.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250630074942.GH1613200%40noisy.programming.kicks-ass.net.
