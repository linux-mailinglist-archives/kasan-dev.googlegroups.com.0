Return-Path: <kasan-dev+bncBDPPFIEASMFBBMHDWDDAMGQEBIAULOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id DC4AAB85F66
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 18:22:09 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-74a30209044sf1238337a34.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 09:22:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758212528; cv=pass;
        d=google.com; s=arc-20240605;
        b=XuloyZhd3zTG/LGkWw5vdnwogCWoNHieyB/nIqvPqvndRelTOQmzWIJ6I1Zzhq2H2j
         Eniyyg2S7SNC6t9PZ2UyvMUh/C+UW2LqYeNhuB9iAQMT+sajHNGi20g/hoDd47G+IeWn
         bTiKXBz2NWc5Y1vkL38aKfFKt9JNM4Bt6yYTQ/+CVJ/LYY92yVloUKgyASMxq841sF3I
         VO2alg85ogvq3LWdDvfPTejYxrwm4shcnxJ8dyhQ3Qvtwl6wrdwpBHQYxb2QAd3AsLuF
         Nn2EVypRW6bDgus8iniS5+ogFn0mFWGyl3X0UEYsQgSrYv60VupKXKZugU4WD8jxjdgY
         Z4KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bcHcx03LByNimKQhaWVasAigw9suSvtrNoNZV45JpU0=;
        fh=/5luD3FKMPhwlmjtFPfCrIz7I+gwYW/qvsIpoGB2ngU=;
        b=BfDi/98L/OFw2gUI4gUPOB4YcFoRWBQc+kAFiwgLdqtlR1EehrzDx5a0il+kdPiEEp
         gAWPXb8eSVyLn+Q/PLxy3e+AR5+8fd3cfRb59SokoFkZwJGmN5Q1AFdSeo7+/7KbTzuq
         fZ0QtWOJwmvDQyx0RTRWlvnHfOw6n+ZXzD5y+0h1EcXhvGI6M59AmNUZU8GQzgjLdO6Q
         OhGa+6/7xJSQFwSHrS449uMoW+hJauMHPWokypXzufWrxsQGWvPy/kg8QWFTHkeZ75Rn
         0iuxh0QVEGWhksddXYQTSZK8KoxEb6I5/Z8sMoTfb2gVfnTh/dpksmNGmxuPoYAilKZ0
         D6Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RXMylrf8;
       spf=pass (google.com: domain of irogers@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758212528; x=1758817328; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bcHcx03LByNimKQhaWVasAigw9suSvtrNoNZV45JpU0=;
        b=OGHLvEKSkWXYWK1hl51OnXYfv8wxFDHfFLQe9K/e2bsh6gmPuH4eypXnasp4VLiP+m
         d2dHqsKrLMaFmkK62W24N3Obzv8Ld0Rl3pLO7+UIkCscfmT+yMmKS2xJr0Ybod7KLUuM
         iemNMmdoLX0xMLkbJoKSZERUOOEVEYjyddRShJpMin7228Oreu+55mC1W+YNBYA8mHqu
         WdIoHSjD1XpAp1CJ8VuvU188ibVn7r3c4/eplnG6p1etk6sJE8VJE8hbDvMlRmwq054u
         E8FYbLKBFVQTR2ex9SZyQnKMlfGbN4qybVa/tHXPGNjcgm5zqntsJQGRB7rs3LqtS+3i
         qOog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758212528; x=1758817328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bcHcx03LByNimKQhaWVasAigw9suSvtrNoNZV45JpU0=;
        b=k6uONPHM+juRozVukVb04yLKBJClcdEKU9VieeFvbNR+lJqe/kTu7385udNnvJPFDe
         9ZWzDB3UFOk2nosTryGtT+BBuPwi8N/mjGf2IfmiuUcMQX36RhpwehUWCa/QFLfXHO46
         pTTHzXu2XVVKPOXLsJ87tRenOCMjqnKqOcLBPBI/Ct+wh85lvfHeHDLP4bGtsi8I1cOW
         E4XMz16dZXz2/qVDq7widD1Ui9bOfhcgHmG/sLRzd8J40QfU81yLfeqkKLemsnHmHKVR
         /iwBuxOe+yTTeNw/QD2bZIPPybYB4P1wMdl9F15gWouTgNqGkt+JYVxe8r9P5a1L/sdy
         YFDQ==
X-Forwarded-Encrypted: i=2; AJvYcCVBODyaYLW6l23bAg3x9zPfa8uufcSa1oayHL6uX+1D4Oz9/a/PvokTN3dQE8afNMQ+UEV5wQ==@lfdr.de
X-Gm-Message-State: AOJu0YwRBXIf59y1eUjOGczQ8JhAAvobWJGqiLVDdu9fdk9Xcm2eeC/5
	wqSDb3XuSIG8mwQKtrxty9GRiFHa5zNR4E+6TYjOXsrOt9ZHSdSJBOF9
X-Google-Smtp-Source: AGHT+IGuO1nwvEK6lS5IpV93sTierYvYZUcOt1kjo/f+XqOaUxnXHpd05tLZ4OZ3/TPelQ1HMBGVWw==
X-Received: by 2002:a05:6830:6681:b0:749:d4b8:c0f0 with SMTP id 46e09a7af769-76f82287127mr130566a34.32.1758212528469;
        Thu, 18 Sep 2025 09:22:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6QliCqoDh87UJeo0F32BhwxbdMGyTruhn6x6mEW3Km1A==
Received: by 2002:a05:6820:2adc:b0:621:a2f1:abe6 with SMTP id
 006d021491bc7-625df6d3a26ls233315eaf.2.-pod-prod-08-us; Thu, 18 Sep 2025
 09:22:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFHMnHOW4+o6SWbhoPbSOtCYk1OGGA1Lj3bX0SBf18xqSJNYRBp4KLIimrSmYKrXcGUxnV0/rgmbQ=@googlegroups.com
X-Received: by 2002:a05:6808:4fd0:b0:437:d45b:4e49 with SMTP id 5614622812f47-43d50e2220emr3182886b6e.50.1758212526557;
        Thu, 18 Sep 2025 09:22:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758212526; cv=none;
        d=google.com; s=arc-20240605;
        b=RZhu3MtewzDGci3J0fJMaAdIJfuFKR/cAchUzKPtUV7MJ/zj87kwm4xdf6tMtH47Kf
         6oc2TbZNwNgYtpnNerAYBvEDJZEmiIY93awNEpm3Ns7pt1EznF2egNZ72VLvsyd3zf7Z
         gzm45qVUXMfVtV94hmpQMwfvu42ZyfenCfhM3dkaFmnj3dgRsfK+ScPanh1GJdSEFFDc
         Ij67b64ShFhxvHMQ5VDDyqZO/sKWMLxcjt//ZVD09Kz/4p7GvPj/Uq3AXUBdLDUzgSZI
         A7jiuuinXP8vd2XPuR/768oRitdV9zybOTpPeITFLvDAws+FBajgpuzcJcnFpN+gR8EJ
         XBpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5MVxy+isNSGzxZ1RNWDgxpSBJ+uufmPyWYytHyGJgFE=;
        fh=2xePsRi30+IT0hwNb2EzirXqAp/zLlOxy0wQQaGgY4k=;
        b=Wt6UPYBUfSnHXtFYqUD+JLonndA1B+bCXIvO0/AHdWoeyWlhQVr/JBsUqIL5o29ZI3
         x805sU7o6Q7pXk28/5JU6fE5yBUt384QrTKbgWgz+4DGVKlEDaQnGtKcGcpdiaaxOboy
         McGsTEsSjowCz2ull/KElVYS3Osjuw/8pQAci1wugcgyU2MA87vF8dQzPrCN8MTtM5jN
         L7szpE2VuY4U1i6S5ITwKsy6mTX2c1/ajZKut+N+DbmUhmLnWobdCdoBtSM472wyKIx4
         xP8fpoodt6db8WwRPG2KzZog9j8GIHXME0nhZuXC+WVeKGdVQhkGt8kQ7zJOgx0EjAqM
         8EPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RXMylrf8;
       spf=pass (google.com: domain of irogers@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43d5c90ae59si100403b6e.5.2025.09.18.09.22.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 09:22:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-267c90c426dso256125ad.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 09:22:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcCqfQX7jS7GfHdwPkwSC1v6iRs6fEQ/CVfL633mFesjYUghbWb3lzE12AUNWUs6081sgZ23YnaEc=@googlegroups.com
X-Gm-Gg: ASbGncuUfM4JMnc3VrxnIrgaAH38OklIT4Az+LVFxNAJZ0AD+3vONEsxCMUMjgrPoD9
	K/JmwfzMNmNpGjwVkUy8ABhK0XegbnehGxwicjO4fU2OjAmh0d3HyQiBw/WB5DPHOrPD0AKarOd
	KYJlLOmSF5v3ZE8W19Fy6/2LB+ycFDk3c13h3wcEdrpAeFOE0kPaMcWrppwvHIGo9M+q4IpcTK8
	O7xRRdibNU4LZXosWKFXehztLA/v7TwdAauEN7bnQ1wu89kxxfYE0SuPxHmF/E=
X-Received: by 2002:a17:902:d2d1:b0:265:e66:6c10 with SMTP id
 d9443c01a7336-26800eb14c1mr10816965ad.4.1758212525092; Thu, 18 Sep 2025
 09:22:05 -0700 (PDT)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Sep 2025 09:21:53 -0700
X-Gm-Features: AS18NWCdr0R3pX49u8RURP-UvB2JdrfJJnKQCP7CUfy991L56-Il3vjCOTsSBN4
Message-ID: <CAP-5=fXBe0_aAep4PPwvfyHPJevMeLffHwA80jec2WVb2ugeYg@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Jann Horn <jannh@google.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RXMylrf8;       spf=pass
 (google.com: domain of irogers@google.com designates 2607:f8b0:4864:20::62e
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Thu, Sep 18, 2025 at 7:05=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> Capability analysis is a C language extension, which enables statically
> checking that user-definable "capabilities" are acquired and released whe=
re
> required. An obvious application is lock-safety checking for the kernel's
> various synchronization primitives (each of which represents a "capabilit=
y"),
> and checking that locking rules are not violated.
>
> Clang originally called the feature "Thread Safety Analysis" [1], with
> some terminology still using the thread-safety-analysis-only names. This
> was later changed and the feature became more flexible, gaining the
> ability to define custom "capabilities". Its foundations can be found in
> "capability systems" [2], used to specify the permissibility of
> operations to depend on some capability being held (or not held).
>
> Because the feature is not just able to express capabilities related to
> synchronization primitives, the naming chosen for the kernel departs
> from Clang's initial "Thread Safety" nomenclature and refers to the
> feature as "Capability Analysis" to avoid confusion. The implementation
> still makes references to the older terminology in some places, such as
> `-Wthread-safety` being the warning enabled option that also still
> appears in diagnostic messages.
>
> Enabling capability analysis can be seen as enabling a dialect of Linux
> C with a Capability System.
>
> Additional details can be found in the added kernel-doc documentation.
> An LWN article covered v2 of the series: https://lwn.net/Articles/1012990=
/
>
>  [1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html
>  [2] https://www.cs.cornell.edu/talc/papers/capabilities.pdf
>
> =3D=3D=3D Development Approach =3D=3D=3D
>
> Prior art exists in the form of Sparse's context tracking. Locking
> annotations on functions exist, so the concept of analyzing locking rules
> is not foreign to the kernel's codebase.
>
> However, Clang's analysis is more complete vs. Sparse's, with the
> typical trade-offs in static analysis: improved completeness is
> sacrificed for more possible false positives or additional annotations
> required by the programmer. Numerous options exist to disable or opt out
> certain code from analysis.
>
> This series initially aimed to retain compatibility with Sparse, which
> can provide tree-wide analysis of a subset of the capability analysis
> introduced, but it was later decided to drop Sparse compatibility. For
> the most part, the new (and old) keywords used for annotations remain
> the same, and many of the pre-existing annotations remain valid.
>
> One big question is how to enable this feature, given we end up with a
> new dialect of C -- 2 approaches have been considered:
>
>   A. Tree-wide all-or-nothing approach. This approach requires tree-wide
>      changes, adding annotations or selective opt-outs. Making additional
>      primitives capability-enabled increases churn, esp. where maintainer=
s
>      are unaware of the feature's existence and how to use it.
>
> Because we can't change the programming language (even if from one C
> dialect to another) of the kernel overnight, a different approach might
> cause less friction.
>
>   B. A selective, incremental, and much less intrusive approach.
>      Maintainers of subsystems opt in their modules or directories into
>      "capability analysis" (via Makefile):
>
>        CAPABILITY_ANALYSIS_foo.o :=3D y   # foo.o only
>        CAPABILITY_ANALYSIS :=3D y         # all TUs
>
>      Most (eventually all) synchronization primitives and more
>      capabilities (including ones that could track "irq disabled",
>      "preemption" disabled, etc.) could be supported.
>
> The approach taken by this series is B. This ensures that only
> subsystems where maintainers are willing to deal with any warnings are
> opted-in. Introducing the feature can be done incrementally, without
> large tree-wide changes and adding numerous opt-outs and annotations to
> the majority of code.
>
>   Note: Bart Van Assche concurrently worked on enabling -Wthread-safety:
>   https://lore.kernel.org/all/20250206175114.1974171-1-bvanassche@acm.org=
/
>   Bart's work has shown what it might take to go with approach A
>   (tree-wide, restricted to 'mutex' usage). This has shown that the
>   analysis finds real issues when applied to enough subsystems!  We hope
>   this serves as motivation to eventually enable the analysis in as many
>   subsystems as possible, particularly subsystems that are not as easily
>   tested by CI systems and test robots.
>
> =3D=3D=3D Initial Uses =3D=3D=3D
>
> With this initial series, the following synchronization primitives are
> supported: `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`,
> `seqlock_t`, `bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`,
> `local_lock_t`, `ww_mutex`.
>
> To demonstrate use of the feature on real kernel code, the series also
> enables capability analysis for the following subsystems:
>
>         * kernel/kcov
>         * kernel/kcsan
>         * kernel/sched/
>         * lib/rhashtable
>         * lib/stackdepot
>         * mm/kfence
>         * security/tomoyo
>         * crypto/
>
> The initial benefits are static detection of violations of locking
> rules. As more capabilities are added, we would see more static checking
> beyond what regular C can provide, all while remaining easy (read quick)
> to use via the Clang compiler.
>
>   Note: The kernel already provides dynamic analysis tools Lockdep and
>   KCSAN for lock-safety checking and data-race detection respectively.
>   Unlike those, Clang's capability analysis is a compile-time static
>   analysis with no runtime impact. The static analysis complements
>   existing dynamic analysis tools, as it may catch some issues before
>   even getting into a running kernel, but is *not* a replacement for
>   whole-kernel testing with the dynamic analysis tools enabled!
>
> =3D=3D=3D Appendix =3D=3D=3D
>
> A Clang version that supports `-Wthread-safety-pointer` and the new
> alias-analysis of capability pointers is required (from this version
> onwards):
>
>         https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e6=
10c351a3227f36c92a4 [3]
>
> This series is also available at this Git tree:
>
>         https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/=
log/?h=3Dcap-analysis/dev
>
> =3D=3D=3D Changelog =3D=3D=3D
>
> v3:
>
>   - Bump min. Clang version to 22+ (unreleased), which now supports:
>
>         * re-entrancy via __attribute__((reentrant_capability));
>         * basic form of capability alias analysis [3] - which is the
>           biggest improvement since v2.
>
>     This was the result of conclusions from this discussion:
>     https://lore.kernel.org/all/CANpmjNPquO=3DW1JAh1FNQb8pMQjgeZAKCPQUAd7=
qUg=3D5pjJ6x=3DQ@mail.gmail.com/
>
>   - Rename __asserts_cap/__assert_cap to __assumes_cap/__assume_cap.
>
>   - Switch to DECLARE_LOCK_GUARD_1_ATTRS().
>
>   - Add __acquire_ret and __acquire_shared_ret helper macros - can be
>     used to define function-like macros that return objects which
>     contains a held capabilities. Works now because of capability alias
>     analysis.
>
>   - Add capability_unsafe_alias() helper, where the analysis rightfully
>     points out we're doing strange things with aliases but we don't
>     care.
>
>   - Support multi-argument attributes.
>
>   - Enable for kernel/sched/{core,fair}.c, kernel/kcsan.
>   - Drop drivers/tty changes (revisit later).
>
> v2: https://lore.kernel.org/all/20250304092417.2873893-1-elver@google.com=
/
>
>   - Remove Sparse context tracking support - after the introduction of
>     Clang support, so that backports can skip removal of Sparse support.
>
>   - Remove __cond_lock() function-like helper.
>
>   - ww_mutex support.
>
>   - -Wthread-safety-addressof was reworked and committed in upstream
>     Clang as -Wthread-safety-pointer.
>
>   - Make __cond_acquires() and __cond_acquires_shared() take abstract
>     value, since compiler only cares about zero and non-zero.
>
>   - Rename __var_guarded_by to simply __guarded_by. Initially the idea
>     was to be explicit about if the variable itself or the pointed-to
>     data is guarded, but in the long-term, making this shorter might be
>     better.
>
>   - Likewise rename __ref_guarded_by to __pt_guarded_by.
>
>   - Introduce common header warning suppressions - this is a better
>     solution than guarding header inclusions with disable_ +
>     enable_capability_analysis(). Header suppressions are disabled when
>     selecting CONFIG_WARN_CAPABILITY_ANALYSIS_ALL=3Dy. This bumps the
>     minimum Clang version required to 20+.
>
>   - Make the data_race() macro imply disabled capability analysis.
>     Writing capability_unsafe(data_race(..)) is unnecessarily verbose
>     and data_race() on its own already indicates something subtly unsafe
>     is happening.  This change was made after analysis of a finding in
>     security/tomoyo.
>
>   - Enable analysis in the following subsystems as additional examples
>     of larger subsystem. Where it was obvious, the __guarded_by
>     attribute was added to lock-guarded variables to improve coverage.
>
>         * drivers/tty
>         * security/tomoyo
>         * crypto/
>
> RFC v1: https://lore.kernel.org/lkml/20250206181711.1902989-1-elver@googl=
e.com

Thanks for this and lgtm. Fwiw, there is already thread safety
analysis in tools/perf:
https://git.kernel.org/pub/scm/linux/kernel/git/perf/perf-tools-next.git/tr=
ee/tools/perf/util/mutex.h?h=3Dperf-tools-next#n43
and we should migrate that code to use this code.

Something that I've wondered about capabilities is to use them for
detecting missing reference count "puts", which feel similar to missed
unlocks. In my experience the sanitizers are weak in this area as in
C++ you can trivially use RAII, however, frustratingly clang's
capability analysis is disabled in C++'s constructors and destructors
(not an issue here :-) and based on my rusty memory). To solve this
for perf (and fix many many bugs) we did a form of runtime RAII:
https://perfwiki.github.io/main/reference-count-checking/
There is likely something better than can be done with the nearly RAII
that is/are cleanups. Trying to make that sane for a data-structure
like an rbtree is hard and maybe rust is just the only solution there.
Anyway, it is great to see thread safety analysis pushed forward.

Thanks,
Ian

> Marco Elver (35):
>   compiler_types: Move lock checking attributes to
>     compiler-capability-analysis.h
>   compiler-capability-analysis: Add infrastructure for Clang's
>     capability analysis
>   compiler-capability-analysis: Add test stub
>   Documentation: Add documentation for Compiler-Based Capability
>     Analysis
>   checkpatch: Warn about capability_unsafe() without comment
>   cleanup: Basic compatibility with capability analysis
>   lockdep: Annotate lockdep assertions for capability analysis
>   locking/rwlock, spinlock: Support Clang's capability analysis
>   compiler-capability-analysis: Change __cond_acquires to take return
>     value
>   locking/mutex: Support Clang's capability analysis
>   locking/seqlock: Support Clang's capability analysis
>   bit_spinlock: Include missing <asm/processor.h>
>   bit_spinlock: Support Clang's capability analysis
>   rcu: Support Clang's capability analysis
>   srcu: Support Clang's capability analysis
>   kref: Add capability-analysis annotations
>   locking/rwsem: Support Clang's capability analysis
>   locking/local_lock: Include missing headers
>   locking/local_lock: Support Clang's capability analysis
>   locking/ww_mutex: Support Clang's capability analysis
>   debugfs: Make debugfs_cancellation a capability struct
>   compiler-capability-analysis: Remove Sparse support
>   compiler-capability-analysis: Remove __cond_lock() function-like
>     helper
>   compiler-capability-analysis: Introduce header suppressions
>   compiler: Let data_race() imply disabled capability analysis
>   MAINTAINERS: Add entry for Capability Analysis
>   kfence: Enable capability analysis
>   kcov: Enable capability analysis
>   kcsan: Enable capability analysis
>   stackdepot: Enable capability analysis
>   rhashtable: Enable capability analysis
>   printk: Move locking annotation to printk.c
>   security/tomoyo: Enable capability analysis
>   crypto: Enable capability analysis
>   sched: Enable capability analysis for core.c and fair.c
>
>  .../dev-tools/capability-analysis.rst         | 148 +++++
>  Documentation/dev-tools/index.rst             |   1 +
>  Documentation/dev-tools/sparse.rst            |  19 -
>  Documentation/mm/process_addrs.rst            |   6 +-
>  MAINTAINERS                                   |  11 +
>  Makefile                                      |   1 +
>  crypto/Makefile                               |   2 +
>  crypto/acompress.c                            |   6 +-
>  crypto/algapi.c                               |   2 +
>  crypto/api.c                                  |   1 +
>  crypto/crypto_engine.c                        |   2 +-
>  crypto/drbg.c                                 |   5 +
>  crypto/internal.h                             |   2 +-
>  crypto/proc.c                                 |   3 +
>  crypto/scompress.c                            |  24 +-
>  .../net/wireless/intel/iwlwifi/iwl-trans.c    |   4 +-
>  .../net/wireless/intel/iwlwifi/iwl-trans.h    |   6 +-
>  .../intel/iwlwifi/pcie/gen1_2/internal.h      |   5 +-
>  .../intel/iwlwifi/pcie/gen1_2/trans.c         |   4 +-
>  fs/dlm/lock.c                                 |   2 +-
>  include/crypto/internal/acompress.h           |   7 +-
>  include/crypto/internal/engine.h              |   2 +-
>  include/linux/bit_spinlock.h                  |  24 +-
>  include/linux/cleanup.h                       |  17 +
>  include/linux/compiler-capability-analysis.h  | 423 +++++++++++++
>  include/linux/compiler.h                      |   2 +
>  include/linux/compiler_types.h                |  18 +-
>  include/linux/console.h                       |   4 +-
>  include/linux/debugfs.h                       |  12 +-
>  include/linux/kref.h                          |   2 +
>  include/linux/list_bl.h                       |   2 +
>  include/linux/local_lock.h                    |  45 +-
>  include/linux/local_lock_internal.h           |  73 ++-
>  include/linux/lockdep.h                       |  12 +-
>  include/linux/mm.h                            |  33 +-
>  include/linux/mutex.h                         |  35 +-
>  include/linux/mutex_types.h                   |   4 +-
>  include/linux/rcupdate.h                      |  86 +--
>  include/linux/refcount.h                      |   6 +-
>  include/linux/rhashtable.h                    |  14 +-
>  include/linux/rwlock.h                        |  22 +-
>  include/linux/rwlock_api_smp.h                |  43 +-
>  include/linux/rwlock_rt.h                     |  44 +-
>  include/linux/rwlock_types.h                  |  10 +-
>  include/linux/rwsem.h                         |  66 +-
>  include/linux/sched.h                         |   6 +-
>  include/linux/sched/signal.h                  |  16 +-
>  include/linux/sched/task.h                    |   5 +-
>  include/linux/sched/wake_q.h                  |   3 +
>  include/linux/seqlock.h                       |  24 +
>  include/linux/seqlock_types.h                 |   5 +-
>  include/linux/spinlock.h                      |  89 ++-
>  include/linux/spinlock_api_smp.h              |  34 +-
>  include/linux/spinlock_api_up.h               | 112 +++-
>  include/linux/spinlock_rt.h                   |  37 +-
>  include/linux/spinlock_types.h                |  10 +-
>  include/linux/spinlock_types_raw.h            |   5 +-
>  include/linux/srcu.h                          |  60 +-
>  include/linux/srcutiny.h                      |   4 +
>  include/linux/srcutree.h                      |   6 +-
>  include/linux/ww_mutex.h                      |  22 +-
>  kernel/Makefile                               |   2 +
>  kernel/kcov.c                                 |  36 +-
>  kernel/kcsan/Makefile                         |   2 +
>  kernel/kcsan/report.c                         |  11 +-
>  kernel/printk/printk.c                        |   2 +
>  kernel/sched/Makefile                         |   3 +
>  kernel/sched/core.c                           |  89 ++-
>  kernel/sched/fair.c                           |   9 +-
>  kernel/sched/sched.h                          | 110 +++-
>  kernel/signal.c                               |   4 +-
>  kernel/time/posix-timers.c                    |  13 +-
>  lib/Kconfig.debug                             |  45 ++
>  lib/Makefile                                  |   6 +
>  lib/dec_and_lock.c                            |   8 +-
>  lib/rhashtable.c                              |   5 +-
>  lib/stackdepot.c                              |  20 +-
>  lib/test_capability-analysis.c                | 596 ++++++++++++++++++
>  mm/kfence/Makefile                            |   2 +
>  mm/kfence/core.c                              |  20 +-
>  mm/kfence/kfence.h                            |  14 +-
>  mm/kfence/report.c                            |   4 +-
>  mm/memory.c                                   |   4 +-
>  mm/pgtable-generic.c                          |  19 +-
>  net/ipv4/tcp_sigpool.c                        |   2 +-
>  scripts/Makefile.capability-analysis          |  11 +
>  scripts/Makefile.lib                          |  10 +
>  scripts/capability-analysis-suppression.txt   |  33 +
>  scripts/checkpatch.pl                         |   8 +
>  security/tomoyo/Makefile                      |   2 +
>  security/tomoyo/common.c                      |  52 +-
>  security/tomoyo/common.h                      |  77 +--
>  security/tomoyo/domain.c                      |   1 +
>  security/tomoyo/environ.c                     |   1 +
>  security/tomoyo/file.c                        |   5 +
>  security/tomoyo/gc.c                          |  28 +-
>  security/tomoyo/mount.c                       |   2 +
>  security/tomoyo/network.c                     |   3 +
>  tools/include/linux/compiler_types.h          |   2 -
>  99 files changed, 2370 insertions(+), 589 deletions(-)
>  create mode 100644 Documentation/dev-tools/capability-analysis.rst
>  create mode 100644 include/linux/compiler-capability-analysis.h
>  create mode 100644 lib/test_capability-analysis.c
>  create mode 100644 scripts/Makefile.capability-analysis
>  create mode 100644 scripts/capability-analysis-suppression.txt
>
> --
> 2.51.0.384.g4c02a37b29-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AP-5%3DfXBe0_aAep4PPwvfyHPJevMeLffHwA80jec2WVb2ugeYg%40mail.gmail.com.
