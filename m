Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7PCSS6QMGQEULHUPVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id A8F42A2B49B
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 23:02:39 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2fa05b7f858sf2318494a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 14:02:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738879358; cv=pass;
        d=google.com; s=arc-20240605;
        b=DmwxHCFE2Il6zvTxDboBCdiqG6Eych1Bh+r9UfdlSLnvIPYaDA6x2DrFR6ESwi8fmt
         9csFQWF9/dOptK2a6tSbivJpnVL/yvPq4vi3P4Qi3bx/ZN+6Zp6PzBB4xT7TjyvoRjKv
         YwVGGvX/C3BqF6d85E8kEsnOWFez7e/6BUMsQHUgxAEFG8djVCQgRZ/11GKtUZ/0WAIy
         5CCNHJNneeH/hIHS0rC1gYR9QYivu+TIfK632s2pyFhCEh9xk1NefasP0iXwiJ0bnJAu
         iJQW96LHYsrRPdEI0MOPnosA/HcjqGzFmHylAmTxdIbFdhIqRpMAsbQg2itTgMjp+K3d
         3LWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=i+lEr8Zs05q0ugyRe1GFwuXtbJJGjV1Lzu8+A5wRBwA=;
        fh=ePwoEgtszACF+euUnhV73jSHcyETSiZ7Z07UpW1oJpM=;
        b=Iyj6QymZMjJ1uy2H40hRITCIXojgcpxm/tsRFn1A39UTevxoABjc5dIaQAAbldC6RV
         KBY34FZHt3mI1lgJC7o9qK7Mpy1sOIfKRDJIUTtiRFzJA7KwKqKOu5BWIysQwe6ADMo8
         yVY47zr+0cPAyab8KfierwsimWvVvJGF6yJx/uFnQCwY7OmVGWA47aGIBMOm24k2YvL+
         k6ZjTyDJ+cvHnBnzflcsiBCWaEGS8+HK4cBV+whq6HN+6jtYawPVPbgCPQzBDtLZuvXI
         lg9btgrcUJJwopuSLvvEG9HsgGD0wGpn5GY9RJ6cV/6VYpSpkUUWNy1uCnf3zgsNKx/j
         QFHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eGNtR8nj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738879358; x=1739484158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i+lEr8Zs05q0ugyRe1GFwuXtbJJGjV1Lzu8+A5wRBwA=;
        b=iQMQqEVitLwPNYgFrhgkGfi4vlD3MVG5ZPR/DtpFQyj28se9fyLH7sARSsYdTdyv2c
         Ux8DgyH1+WI/EN/boS/9CsYoDE13czLr9381OpRony2zoAzM1SBhkeKfZwb1jS/v/KHV
         CkDTSo43xPbm7/FQ3gKiolG06okiSR1vjLr9xeErkByIhi+Qd+MtiBFReolxAyby26Tx
         EBZOIaj4TAf1dzo8e6i3P7DXikyoYRDzpqMZZNv/PrFVIKqwrzXsXfPJi7D7p6kid7xJ
         a9VU5s0s3LP4ybehbjsBH3MwwOZEfQxfj7BfN3hBcYrDFiTeCHhoBVUMg1aevXRnixGW
         CFjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738879358; x=1739484158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i+lEr8Zs05q0ugyRe1GFwuXtbJJGjV1Lzu8+A5wRBwA=;
        b=WamCiIgRWaPdBIEKMyi7JWRMWXNydlf2vmZVOAjcdFB/KqumYq2NuiWteCB6VlpvWb
         p5lKyDdYgRf9QfocMl+RfO4T/vZb7wiUYBC4ruONNgwpLvV4/VQwSyAVGc413iwkQIjz
         5cW2DVUuwpaDjK/ER/Odv78FaPakPBo3LM8ogYSO6uqwFCe9SlnbbbwwSvxkigmVfrCl
         C5vQqKvRJKsWjFpBUgUqzo+khHM2QyFeMnwvzii8eeiyGTlw61KE6KkiyxXWGgvk6xus
         c81AAc7BBlkCHH9TG6PLma5xsLyC9mc68xg+ZE0g2sQHirvLthDOdGmTAia/Ri9aZOYC
         z9rw==
X-Forwarded-Encrypted: i=2; AJvYcCUNg9kuwZyusGtRXE82JaoNxKLaBsDFu/fQChExdbKdyOUMuveX9Y3SliwqcQu/+ONbup/cyw==@lfdr.de
X-Gm-Message-State: AOJu0YxL282N7FGQQQYbQCV6zTR4tUHIjKFsevUDyD0s6KgX8+ZnAukm
	9o99ndN+7zhV4QTprO723rL7WkhMykxGOda+UpFU/SrsTpWv4sVU
X-Google-Smtp-Source: AGHT+IFhbtJoYanxRE5Zb49WT8RIXxd0EXiWvjE0LQ4NB5m/IX1NES5yUbUTndyRVWL5fHKmOZEbNQ==
X-Received: by 2002:a17:90b:4cd1:b0:2ee:5c9b:35c0 with SMTP id 98e67ed59e1d1-2fa24833ab1mr901533a91.9.1738879357917;
        Thu, 06 Feb 2025 14:02:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1201:b0:2ee:85e3:3bfd with SMTP id
 98e67ed59e1d1-2f9fdaaddf6ls1021146a91.2.-pod-prod-00-us-canary; Thu, 06 Feb
 2025 14:02:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUQPTWIW8wa7xrnrGo1ufPNc+V08X2ilTlVwuyP9ECw1vz1dgrbfo0h914w+sTbrIzYPA70OHfFJ0w=@googlegroups.com
X-Received: by 2002:a05:6a21:8dc9:b0:1e1:9e9f:ae4 with SMTP id adf61e73a8af0-1ee0539cdbamr1039767637.13.1738879356350;
        Thu, 06 Feb 2025 14:02:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738879356; cv=none;
        d=google.com; s=arc-20240605;
        b=TaehofCwtqvUCowo5/F/eSD6xSt5zxLL+PfcmpNMGkkiJPJtKT7ybsgUWMGVi65eXq
         sJvL/P11n5rMlzttubNQs/xbW4n0GE8psOTEnEzOOPxecg//7KqcRSxCbEYHVeNbj3Nh
         bRo4n2Fg5BBOW3DszFK40bdby1ab8WKgq38YPb9sNwpprEk0Gd++LqHuSTNuUyby6ok1
         wcPj4HYGFC6QrBIMqokQF5nJSDZj2bvu+V8gkJrCGuPCutY+GyQxJsyCT8xfoeFjhACY
         XwwdYMbFVcvVKozHi+5LdE1DlNagbKpo4MbtgDPRS8BBJkOxNH+CWJIMXhz0m9/ZwAts
         m1JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+VZ6pc7yhUf3GbCnbHnQECLXNAA4wAPKI9VijFmeNYk=;
        fh=yD2m29NAEVj1nBJbU1+yytpwwsoJv15biZRj+4eOlRo=;
        b=kMC9bRxs5hwxXOH0YtQSiwqzGLJo764Nx9lrYrIfDqzkFZBisTNhJysbGwjWcQBPVM
         4B6afwRZJpOg5V6/Tqwc3Xcg9ytyCDMbocKb0/3Mz6/AhN5X4gK8Hco4vh5YoENeT3Uh
         y6VyENJtGLj9M+/mvfDNFKt5SVWxSFSLiz3GmTXNtqgTF2pL1KRouK+CSN4NVvaNlf4R
         J8+F+C6B61I8H8rXKBVsUpvrYWdC0cIK9b1bLOIbCbCNqpwsbJZfaTs9un0Uak7uc6Gx
         pNrAcm9rAfIGAnxKR8VVl2fojjfRMZkgvNFW/iokzlWL0VAiirHyanOm/NTrL9j33q2p
         DgDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eGNtR8nj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-ad51aeb8f09si99575a12.1.2025.02.06.14.02.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 14:02:36 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-2f9b9c0088fso2315530a91.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 14:02:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWmQwWRM1oFALeFTswCET6XtbX6eleW5/VVKZn0rnM3aUaHuq+z1+cu1L4fBvmV3riw9ArCEdYK3Us=@googlegroups.com
X-Gm-Gg: ASbGnctegoSRly23e38YQT3/OaAZdQ4Zim9m8H1YrksZuHxEUkMUIA4S9aA+GxuulQ5
	0voxRvcRZnZ/4JO+umPRxEh607QwI63HjD7O3kf/17SzTevJ3HdNs4DizyfAMvK6TEu5mWHieDe
	34+1Dao0xQMkaOnxfdgRZVyxLOb7Fe
X-Received: by 2002:a17:90b:1a91:b0:2ef:949c:6f6b with SMTP id
 98e67ed59e1d1-2f9ffb38596mr8748127a91.13.1738879355643; Thu, 06 Feb 2025
 14:02:35 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com> <20250206181711.1902989-8-elver@google.com>
 <4ce8f5f2-4196-43e7-88a2-0b5fa2af37fb@acm.org>
In-Reply-To: <4ce8f5f2-4196-43e7-88a2-0b5fa2af37fb@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Feb 2025 23:01:59 +0100
X-Gm-Features: AWEUYZnffMY9S6S6so6pFI6Su5ySq6ByivopC2ArucfUZC95P3tyJXAV2JoDeGo
Message-ID: <CANpmjNMGH36vs8K9Z8tnJc=4xSeeQjeZGyhZj5KSUwh0kQ06MQ@mail.gmail.com>
Subject: Re: [PATCH RFC 07/24] cleanup: Basic compatibility with capability analysis
To: Bart Van Assche <bvanassche@acm.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eGNtR8nj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 6 Feb 2025 at 22:29, Bart Van Assche <bvanassche@acm.org> wrote:
>
> On 2/6/25 10:10 AM, Marco Elver wrote:
> > @@ -243,15 +243,18 @@ const volatile void * __must_check_fn(const volatile void *val)
> >   #define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)             \
> >   typedef _type class_##_name##_t;                                    \
> >   static inline void class_##_name##_destructor(_type *p)                     \
> > +     __no_capability_analysis                                        \
> >   { _type _T = *p; _exit; }                                           \
> >   static inline _type class_##_name##_constructor(_init_args)         \
> > +     __no_capability_analysis                                        \
> >   { _type t = _init; return t; }
>
> guard() uses the constructor and destructor functions defined by
> DEFINE_GUARD(). The DEFINE_GUARD() implementation uses DEFINE_CLASS().
> Here is an example that I found in <linux/mutex.h>:
>
> DEFINE_GUARD(mutex, struct mutex *, mutex_lock(_T), mutex_unlock(_T))
>
> For this example, how is the compiler told that mutex _T is held around
> the code protected by guard()?

DEFINE_GUARD is the generic variant usable for more than just locking
primitives. DEFINE_LOCK_GUARD_X is a specialization of DEFINE_GUARD
intended for locking primitives, all of which should be
capability-enabled.

So I added automatic support for DEFINE_LOCK_GUARD_1 (keeping in mind
the limitations as described in the commit message). All later patches
that introduce support for a locking primitive that had been using
DEFINE_GUARD are switched over to DEFINE_LOCK_GUARD. There's no
additional runtime cost (_T is just a struct containing _T->lock). For
example, the change for mutex [1] switches it to use
DEFINE_LOCK_GUARD_1.

[1] https://lore.kernel.org/all/20250206181711.1902989-12-elver@google.com/

(For every primitive added I have added tests in
test_capability-analysis.c, including testing that the scoped guard()
helpers work and do not produce false positives.)

The RCU patch [15/24] also makes it work for LOCK_GUARD_0, by simply
adding an optional helper macro to declare the attributes for lock and
unlock. There's no need for additional variants of
DEFINE_LOCK_GUARD_X.

Should the need arise to add add annotations for DEFINE_GUARD, we can
introduce DECLARE_GUARD_ATTRS(), similar to
DECLARE_LOCK_GUARD_0_ATTRS() introduced in [15/24]. But it's omitted
because DEFINE_GUARD() can be replaced by DEFINE_LOCK_GUARD for
locking primitives.

In general I wanted to keep the current interface for defining guards
untouched, and keeping it simpler.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMGH36vs8K9Z8tnJc%3D4xSeeQjeZGyhZj5KSUwh0kQ06MQ%40mail.gmail.com.
