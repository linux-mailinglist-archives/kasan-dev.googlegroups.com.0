Return-Path: <kasan-dev+bncBDPPFIEASMFBBLWYWDDAMGQEG66MCHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 02A34B85D38
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 17:58:41 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-b521995d498sf870099a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 08:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758211119; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pe0tFPExRBef40Pkz5iRF2KLhl+jo1M/fOWYnaNWAopfTxidfgqNIeL3XpdUmHBOT8
         aTtZROyoNWFmLvX8ziYpFTIrOTLqYyG50k3VDBe+DxoMelWKDozwuPYu+TrOxd155Mbw
         uwvjPoRR+EXBoRARCaTmWlCdpV0GO5N8Yb8EL7fYxK0HYwl884e9s3sVCdx3lplVlqci
         AkpUkZZ7PxHXJQZykGyC/q++yRn+WZsSZ9i1X7w6I8ckWHnvpS1yGmqGURQuH8QMaxSS
         6pF7uf2NXPMK03tPqgf8+Jb3tUo4SApBfcnZ4GQ28ikeriCXVH5PNUlYLnOIrWJXhx4/
         vMBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IUPnqdNrFsG1oO1hxBcCCZuRhYJCnMQELnnwUfRNCuw=;
        fh=jUdOq7lqiDwTGBld/5sAGJ92PzxPzT/xMes+9P8Y97M=;
        b=D8P/GIz8efPZN2zYLrJn09GE0c1sKxCyJXvEvfWN+lqJDgcx+K5RK/jsOKzif0KwiY
         lxbpa7cTt6VP7cYB1eSLsWrHcZcj3aALd4YVonLYxZjJUmj3cXOTXCpdRq5jD8w+CZbH
         90YEbs5AVI+KlnPOQg/we5JcNGhUfEGuFXNJ5jztR2iAWZIRHbumou5DkuX0gdGXi3Uq
         S+F3O+VlmNbsO1P0fRwmD5wNW0l2B45uf9NBubmdwm96fKRYJhTG1I8uTpqpJCiCnCRQ
         TtJ4daT3kCK1hrlj/rbKzWjLUdXRH8wm+9tMn0BeHUv2eK50k9HjerHY0CtqGcWRZ4kB
         FWDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FlRLBdiw;
       spf=pass (google.com: domain of irogers@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758211119; x=1758815919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IUPnqdNrFsG1oO1hxBcCCZuRhYJCnMQELnnwUfRNCuw=;
        b=dxGVIBUHHroAA0Cj//hKn6spO8/dwrfKjGkEb08JMNt++hEw5QfsnCw/DVZw6ZJIx9
         Gx6yzKe52yXMy6D0kBJYE0lRmcd+8jVoy7v4YZPJm1d4gPuAz+/VbM+misTBwrsDGpNR
         BNAEdCIh3KbV4Xx1qIPo1x3nmWXyiye6FJQeOYS8BPBcdcDmyOAUKFhiqBbs5of4xCPr
         U5zR8OudKhRrDXI1YVSVQY9KFUDgZN29uDzYiYEhtfstszaZU17XwFXRulhgxEx/hpOA
         7X5d/g9o6V0/bnDXZOTXA8UBH7ApSFKR9dQB8As45aqrjWeEu9YVeod4Ge2p3ZPXZFsr
         N4aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758211119; x=1758815919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IUPnqdNrFsG1oO1hxBcCCZuRhYJCnMQELnnwUfRNCuw=;
        b=SyIIPRBkMRzkFPJeK7gWAairT7sVTtU2LizXWjFvlyZmhBA4nf7TP0NnInNySbZBQ8
         aza+i4jqaqEjVhze9L5G5Z3pNjGq6fANuG0YE2dBtXg8+iVWYD4e31123KCTkpfjRKXf
         th0g542OnwIiqSHrJlYpDO8+mPV+huVRH+nIfcg63x9N03pRuBIE1VAltVIFXnnKY5Xk
         qdXBSxI8rZD4t2tMLjshWuxh0Qsv99uZWn0vfLIOCQ2sKZrV0uw7em6AY3y+6xL38Bei
         kC+tglas2R4gkj0357hcj8VAYWhprpCntIxPZH3pQMdsE0y3ihx8q4B2cEvqpw5zPnq3
         zPyA==
X-Forwarded-Encrypted: i=2; AJvYcCVGMb1NUwcBRr+0A5cSAj/rrfpT8K7vFkINo1otrT1stkbY4sYI6hIUxE7DMcLf6hhKvs3IYQ==@lfdr.de
X-Gm-Message-State: AOJu0YxR4fgxFePWV24bJiJHsWEoSNT2WtNt3jXQxppoAAXDaAxCzPps
	/V2mBZUH9sYgGTkUGy9JNnh9Y3pAGVTHzRr7IbucNX/US0dEbczQumg8
X-Google-Smtp-Source: AGHT+IHPGhSKJthR/OVh2IpE84exjbKGpgPZBKBScTapXOVPD+B5w5Zh4hC8wCbdPOfhbsl0of7voA==
X-Received: by 2002:a17:903:2284:b0:269:9adf:839 with SMTP id d9443c01a7336-269ba427cb8mr1117575ad.19.1758211118558;
        Thu, 18 Sep 2025 08:58:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7EiyaUzf4in4SKy3hwwVgFbsBh0fS3pJSvjY836RXWNQ==
Received: by 2002:a17:902:f641:b0:267:ec6d:9ab1 with SMTP id
 d9443c01a7336-2698401caefls9802065ad.2.-pod-prod-09-us; Thu, 18 Sep 2025
 08:58:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVR23cg7yECN1EyUqxmq72uuoUfxRTPHQU2pGKWeJWWZGA1fw7lEbLcmnSB34QgC+tPpa2uPE7S0So=@googlegroups.com
X-Received: by 2002:a17:902:ecce:b0:25c:46cd:1dc1 with SMTP id d9443c01a7336-269ba4f01d5mr609725ad.33.1758211116563;
        Thu, 18 Sep 2025 08:58:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758211116; cv=none;
        d=google.com; s=arc-20240605;
        b=iTl2BnQZDSeHzK+kmV9LjfpioGrNk23IYdUdqNhDRayrcrrCt5AtocMeAwg3jxBUZU
         OzdIzw52T82KNGjlyNs3S12a2vbVXC0oLzeW24CU5FGajugG+Ip/zrYXhFCbpX8TXLJk
         sBILU/YO9ily358pzwbBP1YafHDA9jZw89ujt0RuBjcFqncushumcmLHYjufYpnfXBki
         u4SZEUeJTWSpVLaMT8LySK95JKiWZkLNweHinipbh+L1ACb3eUuYQBj0SX2/G5aEdoNI
         XGH0zHkjrBjcoBz+sFo7Q7lxzplproOCul0c2gi7/6XP/H5eiTcWKGDrcDMiPyP2Jvdm
         druQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=895yZWLFbl1D+NZ1+1PqGczhz6l6vISR4vdW5wFU+tM=;
        fh=ExOxpMwHLUPGY+66cE/Wcifej15yRAV/F7d7boel5wQ=;
        b=LnGz/cpnK9Xf0tMG1Q9dr+JtoKBeXGv+417eBx7BfRq/1eqZc8GfNNu94sz7p3m1QO
         6jr9DY5sm8wsqLpOY0EYUQvi/TZHebp/6p/W9awRCff3gYQLfpqZmiy7cntPyDGd5Iwv
         yIpM56AKx+5PfBCJZjtAAOpcNWEbcRzAjJR08XbviWNw3EMOmIMHlnM/0Xf911DWbBJW
         wLwun+QU4tsed/gy1RlAK1OyynS8H+N/+DVJZBr6gXPNnsHUqqbaCAjiErHQYbb5oLY5
         3hYd31kbmZg8o0JIrPbka3CQsSjAgCxPVZOsIcW0wpcUYyQKeWnz4ZFD4+gX4vSWkA4Y
         6uKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FlRLBdiw;
       spf=pass (google.com: domain of irogers@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-26980246d3bsi953615ad.5.2025.09.18.08.58.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 08:58:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-2681645b7b6so194095ad.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 08:58:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUpbaZnRgsJ5U1s27g/wX6xOsFiqGCzI4Vmsw7PUTwOCzkc4xaic32ZY164eDaFbuHLF15v9A2u3AU=@googlegroups.com
X-Gm-Gg: ASbGncsE2zL0rUoA4giwPFRW11FySfzqxL56EcWh70JLiZ9RNAq2b+FympzotyAK9Hz
	992nFCRLFnXhKdKCnlAvEQV+Uk+kJtjWbx/6v0kjaW/i5Xz4xr2D4zE9Wf+3o+tBuaFBTAWyPLb
	EiQDOptAWhjJNHXV1i5WiCHTFTElOgrRnnSIhqFgmgR1qAWH3S7O48dEMxtVzk02a3dyJhPm8ei
	DrDYmw6SLCO/SwvktFCbErcejMPHyRV4QWXCtAGslSWEuQhNtj950xZnlmlIBICEZpm4+ec8A==
X-Received: by 2002:a17:902:e5cb:b0:24b:1741:1a4c with SMTP id
 d9443c01a7336-26800b2b62cmr10535325ad.0.1758211115340; Thu, 18 Sep 2025
 08:58:35 -0700 (PDT)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com> <20250918140451.1289454-3-elver@google.com>
In-Reply-To: <20250918140451.1289454-3-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Sep 2025 08:58:24 -0700
X-Gm-Features: AS18NWCmIr3tBq_ItIgZLmVErJr2S-etkG0Czo79LasUH7zn78brxTQjhP3i8s4
Message-ID: <CAP-5=fUfbMAKrLC_z04o9r0kGZ02tpHfv8cOecQAQaYPx44awA@mail.gmail.com>
Subject: Re: [PATCH v3 02/35] compiler-capability-analysis: Add infrastructure
 for Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=FlRLBdiw;       spf=pass
 (google.com: domain of irogers@google.com designates 2607:f8b0:4864:20::629
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
> "capability systems", used to specify the permissibility of operations
> to depend on some capability being held (or not held).
>
> [1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html
> [2] https://www.cs.cornell.edu/talc/papers/capabilities.pdf
>
> Because the feature is not just able to express capabilities related to
> synchronization primitives, the naming chosen for the kernel departs
> from Clang's initial "Thread Safety" nomenclature and refers to the
> feature as "Capability Analysis" to avoid confusion. The implementation
> still makes references to the older terminology in some places, such as
> `-Wthread-safety` being the warning enabled option that also still
> appears in diagnostic messages.
>
> See more details in the kernel-doc documentation added in this and the
> subsequent changes.
>
> Clang version 22+ is required.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v3:
> * Require Clang 22 or later (reentrant capabilities, basic alias analysis=
).
> * Rename __assert_cap/__asserts_cap -> __assume_cap/__assumes_cap (sugges=
ted by Peter).
> * Add __acquire_ret and __acquire_shared_ret helper macros - can be used
>   to define function-like macros that return objects which contains a
>   held capabilities. Works now because of capability alias analysis.
> * Add capability_unsafe_alias() helper, where the analysis rightfully
>   points out we're doing strange things with aliases but we don't care.
> * Support multi-argument attributes.
>
> v2:
> * New -Wthread-safety feature rename to -Wthread-safety-pointer (was
>   -Wthread-safety-addressof).
> * Introduce __capability_unsafe() function attribute.
> * Rename __var_guarded_by to simply __guarded_by. The initial idea was
>   to be explicit if the variable or pointed-to data is guarded by, but
>   having a shorter attribute name is likely better long-term.
> * Rename __ref_guarded_by to __pt_guarded_by (pointed-to guarded by).
> ---
>  Makefile                                     |   1 +
>  include/linux/compiler-capability-analysis.h | 449 ++++++++++++++++++-
>  lib/Kconfig.debug                            |  31 ++
>  scripts/Makefile.capability-analysis         |   7 +
>  scripts/Makefile.lib                         |  10 +
>  5 files changed, 491 insertions(+), 7 deletions(-)
>  create mode 100644 scripts/Makefile.capability-analysis
>
> diff --git a/Makefile b/Makefile
> index cf37b9407821..2c91730e513b 100644
> --- a/Makefile
> +++ b/Makefile
> @@ -1096,6 +1096,7 @@ include-$(CONFIG_RANDSTRUCT)      +=3D scripts/Make=
file.randstruct
>  include-$(CONFIG_KSTACK_ERASE) +=3D scripts/Makefile.kstack_erase
>  include-$(CONFIG_AUTOFDO_CLANG)        +=3D scripts/Makefile.autofdo
>  include-$(CONFIG_PROPELLER_CLANG)      +=3D scripts/Makefile.propeller
> +include-$(CONFIG_WARN_CAPABILITY_ANALYSIS) +=3D scripts/Makefile.capabil=
ity-analysis
>  include-$(CONFIG_GCC_PLUGINS)  +=3D scripts/Makefile.gcc-plugins
>
>  include $(addprefix $(srctree)/, $(include-y))
> diff --git a/include/linux/compiler-capability-analysis.h b/include/linux=
/compiler-capability-analysis.h
> index 7546ddb83f86..6f3f185478bc 100644
> --- a/include/linux/compiler-capability-analysis.h
> +++ b/include/linux/compiler-capability-analysis.h
> @@ -6,27 +6,462 @@
>  #ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
>  #define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
>
> +#if defined(WARN_CAPABILITY_ANALYSIS)
> +
> +/*
> + * The below attributes are used to define new capability types. Interna=
l only.
> + */
> +# define __cap_type(name)                      __attribute__((capability=
(#name)))
> +# define __reentrant_cap                       __attribute__((reentrant_=
capability))
> +# define __acquires_cap(...)                   __attribute__((acquire_ca=
pability(__VA_ARGS__)))
> +# define __acquires_shared_cap(...)            __attribute__((acquire_sh=
ared_capability(__VA_ARGS__)))
> +# define __try_acquires_cap(ret, var)          __attribute__((try_acquir=
e_capability(ret, var)))
> +# define __try_acquires_shared_cap(ret, var)   __attribute__((try_acquir=
e_shared_capability(ret, var)))
> +# define __releases_cap(...)                   __attribute__((release_ca=
pability(__VA_ARGS__)))
> +# define __releases_shared_cap(...)            __attribute__((release_sh=
ared_capability(__VA_ARGS__)))
> +# define __assumes_cap(...)                    __attribute__((assert_cap=
ability(__VA_ARGS__)))
> +# define __assumes_shared_cap(...)             __attribute__((assert_sha=
red_capability(__VA_ARGS__)))
> +# define __returns_cap(var)                    __attribute__((lock_retur=
ned(var)))
> +
> +/*
> + * The below are used to annotate code being checked. Internal only.
> + */
> +# define __excludes_cap(...)           __attribute__((locks_excluded(__V=
A_ARGS__)))
> +# define __requires_cap(...)           __attribute__((requires_capabilit=
y(__VA_ARGS__)))
> +# define __requires_shared_cap(...)    __attribute__((requires_shared_ca=
pability(__VA_ARGS__)))
> +
> +/**
> + * __guarded_by - struct member and globals attribute, declares variable
> + *                protected by capability
> + *
> + * Declares that the struct member or global variable must be guarded by=
 the
> + * given capabilities. Read operations on the data require shared access=
,
> + * while write operations require exclusive access.
> + *
> + * .. code-block:: c
> + *
> + *     struct some_state {
> + *             spinlock_t lock;
> + *             long counter __guarded_by(&lock);
> + *     };
> + */
> +# define __guarded_by(...)             __attribute__((guarded_by(__VA_AR=
GS__)))
> +
> +/**
> + * __pt_guarded_by - struct member and globals attribute, declares point=
ed-to
> + *                   data is protected by capability
> + *
> + * Declares that the data pointed to by the struct member pointer or glo=
bal
> + * pointer must be guarded by the given capabilities. Read operations on=
 the
> + * data require shared access, while write operations require exclusive =
access.
> + *
> + * .. code-block:: c
> + *
> + *     struct some_state {
> + *             spinlock_t lock;
> + *             long *counter __pt_guarded_by(&lock);
> + *     };
> + */
> +# define __pt_guarded_by(...)          __attribute__((pt_guarded_by(__VA=
_ARGS__)))
> +
> +/**
> + * struct_with_capability() - declare or define a capability struct
> + * @name: struct name
> + *
> + * Helper to declare or define a struct type with capability of the same=
 name.
> + *
> + * .. code-block:: c
> + *
> + *     struct_with_capability(my_handle) {
> + *             int foo;
> + *             long bar;
> + *     };
> + *
> + *     struct some_state {
> + *             ...
> + *     };
> + *     // ... declared elsewhere ...
> + *     struct_with_capability(some_state);
> + *
> + * Note: The implementation defines several helper functions that can ac=
quire,
> + * release, and assert the capability.
> + */
> +# define struct_with_capability(name, ...)                              =
                               \
> +       struct __cap_type(name) __VA_ARGS__ name;                        =
                               \
> +       static __always_inline void __acquire_cap(const struct name *var)=
                               \
> +               __attribute__((overloadable)) __no_capability_analysis __=
acquires_cap(var) { }          \
> +       static __always_inline void __acquire_shared_cap(const struct nam=
e *var)                        \
> +               __attribute__((overloadable)) __no_capability_analysis __=
acquires_shared_cap(var) { }   \
> +       static __always_inline bool __try_acquire_cap(const struct name *=
var, bool ret)                 \
> +               __attribute__((overloadable)) __no_capability_analysis __=
try_acquires_cap(1, var)       \
> +       { return ret; }                                                  =
                               \
> +       static __always_inline bool __try_acquire_shared_cap(const struct=
 name *var, bool ret)          \
> +               __attribute__((overloadable)) __no_capability_analysis __=
try_acquires_shared_cap(1, var) \
> +       { return ret; }                                                  =
                               \
> +       static __always_inline void __release_cap(const struct name *var)=
                               \
> +               __attribute__((overloadable)) __no_capability_analysis __=
releases_cap(var) { }          \
> +       static __always_inline void __release_shared_cap(const struct nam=
e *var)                        \
> +               __attribute__((overloadable)) __no_capability_analysis __=
releases_shared_cap(var) { }   \
> +       static __always_inline void __assume_cap(const struct name *var) =
                               \
> +               __attribute__((overloadable)) __assumes_cap(var) { }     =
                               \
> +       static __always_inline void __assume_shared_cap(const struct name=
 *var)                         \
> +               __attribute__((overloadable)) __assumes_shared_cap(var) {=
 }                             \
> +       struct name
> +
> +/**
> + * disable_capability_analysis() - disables capability analysis
> + *
> + * Disables capability analysis. Must be paired with a later
> + * enable_capability_analysis().
> + */
> +# define disable_capability_analysis()                         \
> +       __diag_push();                                          \
> +       __diag_ignore_all("-Wunknown-warning-option", "")       \
> +       __diag_ignore_all("-Wthread-safety", "")                \
> +       __diag_ignore_all("-Wthread-safety-pointer", "")
> +
> +/**
> + * enable_capability_analysis() - re-enables capability analysis
> + *
> + * Re-enables capability analysis. Must be paired with a prior
> + * disable_capability_analysis().
> + */
> +# define enable_capability_analysis() __diag_pop()
> +
> +/**
> + * __no_capability_analysis - function attribute, disables capability an=
alysis
> + *
> + * Function attribute denoting that capability analysis is disabled for =
the
> + * whole function. Prefer use of `capability_unsafe()` where possible.
> + */
> +# define __no_capability_analysis      __attribute__((no_thread_safety_a=
nalysis))
> +
> +#else /* !WARN_CAPABILITY_ANALYSIS */
> +
> +# define __cap_type(name)
> +# define __reentrant_cap
> +# define __acquires_cap(...)
> +# define __acquires_shared_cap(...)
> +# define __try_acquires_cap(ret, var)
> +# define __try_acquires_shared_cap(ret, var)
> +# define __releases_cap(...)
> +# define __releases_shared_cap(...)
> +# define __assumes_cap(...)
> +# define __assumes_shared_cap(...)
> +# define __returns_cap(var)
> +# define __guarded_by(...)
> +# define __pt_guarded_by(...)
> +# define __excludes_cap(...)
> +# define __requires_cap(...)
> +# define __requires_shared_cap(...)
> +# define __acquire_cap(var)                    do { } while (0)
> +# define __acquire_shared_cap(var)             do { } while (0)
> +# define __try_acquire_cap(var, ret)           (ret)
> +# define __try_acquire_shared_cap(var, ret)    (ret)
> +# define __release_cap(var)                    do { } while (0)
> +# define __release_shared_cap(var)             do { } while (0)
> +# define __assume_cap(var)                     do { (void)(var); } while=
 (0)
> +# define __assume_shared_cap(var)              do { (void)(var); } while=
 (0)
> +# define struct_with_capability(name, ...)     struct __VA_ARGS__ name
> +# define disable_capability_analysis()
> +# define enable_capability_analysis()
> +# define __no_capability_analysis
> +
> +#endif /* WARN_CAPABILITY_ANALYSIS */
> +
> +/**
> + * capability_unsafe() - disable capability checking for contained code
> + *
> + * Disables capability checking for contained statements or expression.
> + *
> + * .. code-block:: c
> + *
> + *     struct some_data {
> + *             spinlock_t lock;
> + *             int counter __guarded_by(&lock);
> + *     };
> + *
> + *     int foo(struct some_data *d)
> + *     {
> + *             // ...
> + *             // other code that is still checked ...
> + *             // ...
> + *             return capability_unsafe(d->counter);
> + *     }
> + */
> +#define capability_unsafe(...)         \
> +({                                     \
> +       disable_capability_analysis();  \
> +       __VA_ARGS__;                    \
> +       enable_capability_analysis()    \
> +})
> +
> +/**
> + * __capability_unsafe() - function attribute, disable capability checki=
ng
> + * @comment: comment explaining why opt-out is safe
> + *
> + * Function attribute denoting that capability analysis is disabled for =
the
> + * whole function. Forces adding an inline comment as argument.
> + */
> +#define __capability_unsafe(comment) __no_capability_analysis
> +
> +/**
> + * capability_unsafe_alias() - helper to insert a capability "alias barr=
ier"
> + * @p: pointer aliasing a capability or object containing capabilities
> + *
> + * No-op function that acts as a "capability alias barrier", where the a=
nalysis
> + * rightfully detects that we're switching aliases, but the switch is co=
nsidered
> + * safe but beyond the analysis reasoning abilities.
> + *
> + * This should be inserted before the first use of such an alias.
> + *
> + * Implementation Note: The compiler ignores aliases that may be reassig=
ned but
> + * their value cannot be determined (e.g. when passing a non-const point=
er to an
> + * alias as a function argument).
> + */
> +#define capability_unsafe_alias(p) _capability_unsafe_alias((void **)&(p=
))
> +static inline void _capability_unsafe_alias(void **p) { }
> +
> +/**
> + * token_capability() - declare an abstract global capability instance
> + * @name: token capability name
> + *
> + * Helper that declares an abstract global capability instance @name tha=
t can be
> + * used as a token capability, but not backed by a real data structure (=
linker
> + * error if accidentally referenced). The type name is `__capability_@na=
me`.
> + */
> +#define token_capability(name, ...)                                    \
> +       struct_with_capability(__capability_##name, ##__VA_ARGS__) {};  \
> +       extern const struct __capability_##name *name
> +
> +/**
> + * token_capability_instance() - declare another instance of a global ca=
pability
> + * @cap: token capability previously declared with token_capability()
> + * @name: name of additional global capability instance
> + *
> + * Helper that declares an additional instance @name of the same token
> + * capability class @name. This is helpful where multiple related token
> + * capabilities are declared, as it also allows using the same underlyin=
g type
> + * (`__capability_@cap`) as function arguments.
> + */
> +#define token_capability_instance(cap, name)           \
> +       extern const struct __capability_##cap *name
> +
> +/*
> + * Common keywords for static capability analysis. Both Clang's capabili=
ty
> + * analysis and Sparse's context tracking are currently supported.
> + */
>  #ifdef __CHECKER__
>
>  /* Sparse context/lock checking support. */
>  # define __must_hold(x)                __attribute__((context(x,1,1)))
> +# define __must_not_hold(x)
>  # define __acquires(x)         __attribute__((context(x,0,1)))
>  # define __cond_acquires(x)    __attribute__((context(x,0,-1)))
>  # define __releases(x)         __attribute__((context(x,1,0)))
>  # define __acquire(x)          __context__(x,1)
>  # define __release(x)          __context__(x,-1)
>  # define __cond_lock(x, c)     ((c) ? ({ __acquire(x); 1; }) : 0)
> +/* For Sparse, there's no distinction between exclusive and shared locks=
. */
> +# define __must_hold_shared    __must_hold
> +# define __acquires_shared     __acquires
> +# define __cond_acquires_shared __cond_acquires
> +# define __releases_shared     __releases
> +# define __acquire_shared      __acquire
> +# define __release_shared      __release
> +# define __cond_lock_shared    __cond_acquire
>
>  #else /* !__CHECKER__ */
>
> -# define __must_hold(x)
> -# define __acquires(x)
> -# define __cond_acquires(x)
> -# define __releases(x)
> -# define __acquire(x)          (void)0
> -# define __release(x)          (void)0
> -# define __cond_lock(x, c)     (c)
> +/**
> + * __must_hold() - function attribute, caller must hold exclusive capabi=
lity
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the caller must hold the given capa=
bility
> + * instance @x exclusively.
> + */
> +# define __must_hold(x)                __requires_cap(x)
> +
> +/**
> + * __must_not_hold() - function attribute, caller must not hold capabili=
ty
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the caller must not hold the given
> + * capability instance @x.
> + */
> +# define __must_not_hold(x)    __excludes_cap(x)
> +
> +/**
> + * __acquires() - function attribute, function acquires capability exclu=
sively
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the function acquires the given
> + * capability instance @x exclusively, but does not release it.
> + */
> +# define __acquires(x)         __acquires_cap(x)
> +
> +/**
> + * __cond_acquires() - function attribute, function conditionally
> + *                     acquires a capability exclusively
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the function conditionally acquires=
 the
> + * given capability instance @x exclusively, but does not release it.
> + */
> +# define __cond_acquires(x)    __try_acquires_cap(1, x)
> +
> +/**
> + * __releases() - function attribute, function releases a capability exc=
lusively
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the function releases the given cap=
ability
> + * instance @x exclusively. The capability must be held on entry.
> + */
> +# define __releases(x)         __releases_cap(x)
> +
> +/**
> + * __acquire() - function to acquire capability exclusively
> + * @x: capability instance pointer
> + *
> + * No-op function that acquires the given capability instance @x exclusi=
vely.
> + */
> +# define __acquire(x)          __acquire_cap(x)
> +
> +/**
> + * __release() - function to release capability exclusively
> + * @x: capability instance pointer
> + *
> + * No-op function that releases the given capability instance @x.
> + */
> +# define __release(x)          __release_cap(x)
> +
> +/**
> + * __cond_lock() - function that conditionally acquires a capability
> + *                 exclusively
> + * @x: capability instance pinter
> + * @c: boolean expression
> + *
> + * Return: result of @c
> + *
> + * No-op function that conditionally acquires capability instance @x
> + * exclusively, if the boolean expression @c is true. The result of @c i=
s the
> + * return value, to be able to create a capability-enabled interface; fo=
r
> + * example:
> + *
> + * .. code-block:: c
> + *
> + *     #define spin_trylock(l) __cond_lock(&lock, _spin_trylock(&lock))
> + */
> +# define __cond_lock(x, c)     __try_acquire_cap(x, c)
> +
> +/**
> + * __must_hold_shared() - function attribute, caller must hold shared ca=
pability
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the caller must hold the given capa=
bility
> + * instance @x with shared access.
> + */
> +# define __must_hold_shared(x) __requires_shared_cap(x)
> +
> +/**
> + * __acquires_shared() - function attribute, function acquires capabilit=
y shared
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the function acquires the given
> + * capability instance @x with shared access, but does not release it.
> + */
> +# define __acquires_shared(x)  __acquires_shared_cap(x)
> +
> +/**
> + * __cond_acquires_shared() - function attribute, function conditionally
> + *                            acquires a capability shared
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the function conditionally acquires=
 the
> + * given capability instance @x with shared access, but does not release=
 it.
> + */
> +# define __cond_acquires_shared(x) __try_acquires_shared_cap(1, x)
> +
> +/**
> + * __releases_shared() - function attribute, function releases a
> + *                       capability shared
> + * @x: capability instance pointer
> + *
> + * Function attribute declaring that the function releases the given cap=
ability
> + * instance @x with shared access. The capability must be held on entry.
> + */
> +# define __releases_shared(x)  __releases_shared_cap(x)
> +
> +/**
> + * __acquire_shared() - function to acquire capability shared
> + * @x: capability instance pointer
> + *
> + * No-op function that acquires the given capability instance @x with sh=
ared
> + * access.
> + */
> +# define __acquire_shared(x)   __acquire_shared_cap(x)
> +
> +/**
> + * __release_shared() - function to release capability shared
> + * @x: capability instance pointer
> + *
> + * No-op function that releases the given capability instance @x with sh=
ared
> + * access.
> + */
> +# define __release_shared(x)   __release_shared_cap(x)
> +
> +/**
> + * __cond_lock_shared() - function that conditionally acquires a capabil=
ity
> + *                        shared
> + * @x: capability instance pinter
> + * @c: boolean expression
> + *
> + * Return: result of @c
> + *
> + * No-op function that conditionally acquires capability instance @x wit=
h shared
> + * access, if the boolean expression @c is true. The result of @c is the=
 return
> + * value, to be able to create a capability-enabled interface.
> + */
> +# define __cond_lock_shared(x, c) __try_acquire_shared_cap(x, c)
>
>  #endif /* __CHECKER__ */
>
> +/**
> + * __acquire_ret() - helper to acquire capability of return value
> + * @call: call expression
> + * @ret_expr: acquire expression that uses __ret
> + */
> +#define __acquire_ret(call, ret_expr)          \
> +       ({                                      \
> +               __auto_type __ret =3D call;       \
> +               __acquire(ret_expr);            \
> +               __ret;                          \
> +       })
> +
> +/**
> + * __acquire_shared_ret() - helper to acquire capability shared of retur=
n value
> + * @call: call expression
> + * @ret_expr: acquire shared expression that uses __ret
> + */
> +#define __acquire_shared_ret(call, ret_expr)   \
> +       ({                                      \
> +               __auto_type __ret =3D call;       \
> +               __acquire_shared(ret_expr);     \
> +               __ret;                          \
> +       })
> +
> +/*
> + * Attributes to mark functions returning acquired capabilities. This is=
 purely
> + * cosmetic to help readability, and should be used with the above macro=
s as
> + * follows:
> + *
> + *   struct foo { spinlock_t lock; ... };
> + *   ...
> + *   #define myfunc(...) __acquire_ret(_myfunc(__VA_ARGS__), &__ret->loc=
k)
> + *   struct foo *_myfunc(int bar) __acquires_ret;
> + *   ...
> + */
> +#define __acquires_ret         __no_capability_analysis
> +#define __acquires_shared_ret  __no_capability_analysis
> +
>  #endif /* _LINUX_COMPILER_CAPABILITY_ANALYSIS_H */
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index dc0e0c6ed075..57e09615f88d 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -613,6 +613,37 @@ config DEBUG_FORCE_WEAK_PER_CPU
>           To ensure that generic code follows the above rules, this
>           option forces all percpu variables to be defined as weak.
>
> +config WARN_CAPABILITY_ANALYSIS
> +       bool "Compiler capability-analysis warnings"
> +       depends on CC_IS_CLANG && CLANG_VERSION >=3D 220000
> +       # Branch profiling re-defines "if", which messes with the compile=
r's
> +       # ability to analyze __cond_acquires(..), resulting in false posi=
tives.
> +       depends on !TRACE_BRANCH_PROFILING

Err, wow! What and huh, and why? Crikes. I'm amazed you found such an
option exists. I must be very naive to have never heard of it and now
I wonder if it is needed and load bearing?

Ian


> +       default y
> +       help
> +         Capability analysis is a C language extension, which enables
> +         statically checking that user-definable "capabilities" are acqu=
ired
> +         and released where required.
> +
> +         Clang's name of the feature ("Thread Safety Analysis") refers t=
o
> +         the original name of the feature; it was later expanded to be a
> +         generic "Capability Analysis" framework.
> +
> +         Requires Clang 22 or later.
> +
> +         Produces warnings by default. Select CONFIG_WERROR if you wish =
to
> +         turn these warnings into errors.
> +
> +config WARN_CAPABILITY_ANALYSIS_ALL
> +       bool "Enable capability analysis for all source files"
> +       depends on WARN_CAPABILITY_ANALYSIS
> +       depends on EXPERT && !COMPILE_TEST
> +       help
> +         Enable tree-wide capability analysis. This is likely to produce=
 a
> +         large number of false positives - enable at your own risk.
> +
> +         If unsure, say N.
> +
>  endmenu # "Compiler options"
>
>  menu "Generic Kernel Debugging Instruments"
> diff --git a/scripts/Makefile.capability-analysis b/scripts/Makefile.capa=
bility-analysis
> new file mode 100644
> index 000000000000..e137751a4c9a
> --- /dev/null
> +++ b/scripts/Makefile.capability-analysis
> @@ -0,0 +1,7 @@
> +# SPDX-License-Identifier: GPL-2.0
> +
> +capability-analysis-cflags :=3D -DWARN_CAPABILITY_ANALYSIS       \
> +       -fexperimental-late-parse-attributes -Wthread-safety    \
> +       -Wthread-safety-pointer -Wthread-safety-beta
> +
> +export CFLAGS_CAPABILITY_ANALYSIS :=3D $(capability-analysis-cflags)
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 1d581ba5df66..e0ac273bf9eb 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -105,6 +105,16 @@ _c_flags +=3D $(if $(patsubst n%,, \
>         -D__KCSAN_INSTRUMENT_BARRIERS__)
>  endif
>
> +#
> +# Enable capability analysis flags only where explicitly opted in.
> +# (depends on variables CAPABILITY_ANALYSIS_obj.o, CAPABILITY_ANALYSIS)
> +#
> +ifeq ($(CONFIG_WARN_CAPABILITY_ANALYSIS),y)
> +_c_flags +=3D $(if $(patsubst n%,, \
> +               $(CAPABILITY_ANALYSIS_$(target-stem).o)$(CAPABILITY_ANALY=
SIS)$(if $(is-kernel-object),$(CONFIG_WARN_CAPABILITY_ANALYSIS_ALL))), \
> +               $(CFLAGS_CAPABILITY_ANALYSIS))
> +endif
> +
>  #
>  # Enable AutoFDO build flags except some files or directories we don't w=
ant to
>  # enable (depends on variables AUTOFDO_PROFILE_obj.o and AUTOFDO_PROFILE=
).
> --
> 2.51.0.384.g4c02a37b29-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AP-5%3DfUfbMAKrLC_z04o9r0kGZ02tpHfv8cOecQAQaYPx44awA%40mail.gmail.com.
