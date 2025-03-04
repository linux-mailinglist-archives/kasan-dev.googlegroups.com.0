Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5GJTS7AMGQEWGFCUXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 23D0BA4E4E8
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 17:06:14 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2c151f7fa61sf7829694fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 08:06:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741104373; cv=pass;
        d=google.com; s=arc-20240605;
        b=kcey/0n68bTvSQ6cYeq39n8ZYTP8CNiinFFfRKVo+r9lGSEewOlV1T42Uw8XXgdrYD
         G1k/locGU8bzH/TQrYqYVEygeQcOX9H0tf2PVTBW4CoA9ovhG16Zu0Xdb/nvvQfBfU3G
         HKEfBGkft4yjdeaVvxXGjmQoja2Kq9tlFwxLkQlYpwUIV+STBm7XOCsqltfBH8bMAwqU
         uv1ocmhYrSh70Q11Df9NUE9o0vcL1tiwT9mR0PPEOJjGmo+Km/gf7cpqYtOkOFFfGBwT
         K+h18pLhKO3/FX8sOdwGR7HhZtzLebO7yD8Yvdw8mNQxoSVEPGxWOmPs6gWwE81YY9IR
         cnzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cuLdpDkWZlqL/goNIjs1NBVccPAK0qvlEOORwf1oHk4=;
        fh=jjfDDsl3/m2RCqaj57OoO18TKe1FD3jpKgW7CGS48bA=;
        b=ZJN6Tay+lciQHFmnUO5G8i+JVPK450Z/WjVcpnG4xjo8l4LX1i23VAthBDl8FdwPqf
         zUAnyp9lafgzzee3s7EWx6e0ziqBn6eF/mRnTBRtezO2COf8fO/cPzH84e6beRtlxhHq
         1UAu4BDguJ94TtRM3l6DK+dcR3blows+Pa2OketDNzdX7rG+zBCAtisWlq3Yp2VoJbWl
         YbM+JGMMH5B7u23+mtYmMA7M7hoHzYnkH9/pYHHGY7NZY5/ewoZYRh1iwsr9r2ltVEhZ
         9DknpVbUKABvyNe9xYh+5rBVunWjhJJnoa+vnrqXZZ+cJ2TH2uoU+dSVCkmakIfSiKXo
         OpkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fBYILs6q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741104373; x=1741709173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cuLdpDkWZlqL/goNIjs1NBVccPAK0qvlEOORwf1oHk4=;
        b=KvdeVqtjNK0I8rcWON+bQ9hVwtQcoXp9KbGXXVtnu0qLKQW9nfL002SjLSTmxtrHYD
         zXekcUOZMXv7MbQO2hzVEj3DdAfq/vJiw3MOLAPowUaccljn7J91hbEAJnn4d/vnzNOI
         bWy4nglx9eYjLoc+81FtszbR9CkEMLk1pcJkJZ2B6cEuJsympZRz4y7bRa4hisnwSZRM
         6f0hbXTG40xLSZlUgEQhOp2iAIXElUbIkYNcO5XieCsvAaDUBPFpN6V8dnRcc61SVf70
         isOFlgud9C1PFjJLMYdlLg9xBkGfEdng+nVFR/XV9HqVyoJi04uAzsdbIaWKKVP+kv29
         qAmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741104373; x=1741709173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cuLdpDkWZlqL/goNIjs1NBVccPAK0qvlEOORwf1oHk4=;
        b=PHHr28aKobYIj4/H/iSS5XhBbFe6/Ogsse/z4wS0h4lKOu8H2lXZg5wyMgDG40VhDD
         cXsgNi5XN8JQRqgXQGxX2ZWzR0/lRKv2tuw70rird/aLibUR7VP32HC37cTPGg24IryB
         7QRmLUqZ6tV2ZatNHJjOqfYMlxN4rVkxTM7GqdZlPdLryrCfrkb/pccHuad57KSdY14q
         zdbKvmZHchPWXg64h4/M9TmQBn5d1RHf/SIJQ7j7v9Ao9LGkQXobCVpEzv3vlVi+Ofez
         UFVwD+FKvfOFjNjxrOsTzfyOFiyLVgv3g4QJOUtG4z81/K1KbtceGbbDws3nqV6sw8ZF
         4Nog==
X-Forwarded-Encrypted: i=2; AJvYcCX0bXBE/jiJHiRA9GrLtEH/sxAFqvubvT3kfcaOmhWZSH5TaYcQseF+xGkc4xWVTiDCK9UI8g==@lfdr.de
X-Gm-Message-State: AOJu0Yyzf3wM5gpMrhXd5cI41VtVzxHwACzcbbCOu7F6X2U34UCD3zec
	f5UhozhPeKdLyislLvYv4jHGidL9EWI/LlmiO6iU0D57ArxwM8tj
X-Google-Smtp-Source: AGHT+IGKrSreSBjUSat56D9imD892XuCtlrmwMgTm+TbDF6TxYB+NlBRRfrq+2NtVkBkXfsodSw4MA==
X-Received: by 2002:a05:6870:b48b:b0:296:a67c:d239 with SMTP id 586e51a60fabf-2c17843f79bmr9319405fac.12.1741104372784;
        Tue, 04 Mar 2025 08:06:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVECgxslWZ8p3iadDES4ykLOj3w6/qyTd2MRIDr2KocXfA==
Received: by 2002:a05:6871:538e:b0:2ab:4267:cb7c with SMTP id
 586e51a60fabf-2c15465adf9ls2799425fac.1.-pod-prod-07-us; Tue, 04 Mar 2025
 08:06:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXaSm5VDmlnqQW5lIJXqG7Cqdoh3KrlbS7qERsMGj8hlARQSehMJ8GLgPlzxiFUncb4E5Od8qYaOeg=@googlegroups.com
X-Received: by 2002:a05:6830:438c:b0:72a:100e:8e00 with SMTP id 46e09a7af769-72a100e8f5dmr3339534a34.22.1741104371732;
        Tue, 04 Mar 2025 08:06:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741104371; cv=none;
        d=google.com; s=arc-20240605;
        b=CSUbqj/aKGMrHK+GjTTBGWsfVTSkG8SN56lLV7blBeP8RaSrOK9WynLiSDW0hYYzxm
         0W482RqTHBqi6vb5Qi6ruNgoFdbY3aiWCcZ/m15nshIAY1shyiFLlBLmx2J3/H00qxVJ
         r2ckXTiSyn7Sn6Bi8SzOMLlfALB1RxXhZZZAdvyVhGm/KC4MiOH706EWrg/QXP+uCNq9
         z/lbvyyYxo2bqCLRLxvsxJrd+AfhM8iwBkF/HIXnQ1tzDt3k9xmSegE2rYcd8drihgdS
         7lYCCALiEC1ofyo4XlUrKYcOp7Dt+1eLULyzy3J68GFR88S4qKNiCgVamMbdZ9JseVa4
         PTZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1t6ivLIoIuftK2f6E0pPM+6bkcWx6f6OEyc75s3kSwQ=;
        fh=nxV02riRC9yvp7eXfZR5LCxc7ZCHZXXmVGLsBLwesMY=;
        b=O4ewIpZEi8xa0qXSgIEz6EJgoP5NnYLQXDsYug0bXizEUHJ9EuvX211rTqsTHynSWm
         i3WJEwhaR7ltHVYpMmrhyaV0x99CW4AGBK87iKuRCqCdG/1hIEnzlFjY/cVMd/L9vDky
         RBr6D5TRUvISBPJCvgZLG5osiRgQ40EVHx3euboOLDp6B/Yf95WSNl/ddqEIVD9V8TLD
         F2ofalXU67zbVsAyJWtQM3GoXdxyp3dAZql739VUCE8yaWFtK+XRSslxfB5EtuNGbBpV
         We+vfK7QFzuCib45BQBBeKwmHcP0eEDDbz1e7ufapvQQ/j2nHK2wBbN7GEEGNbJQmkxx
         KMfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fBYILs6q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-728afcffbb3si578105a34.2.2025.03.04.08.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 08:06:11 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-2f9d3d0f55dso9420625a91.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 08:06:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWtdp2i+ObAkdlk4w8bki4NJIjj81WGd9Yvqr+uCqbz8sVJtHBqZKCjQNrh2WE2D7vzBxjXv1fUFPw=@googlegroups.com
X-Gm-Gg: ASbGncvtPVn+yl72OX7upIUysaY8EqFFuPSazdZxmGm8KSCDZeZuOiVDSRu8jeHWc26
	mphHX+PIu9F7neH8uKyevP2DlbuKE1Um4aevSqRNvqoWFHA1EoISwXiB97R+4/bWcSNeEntV9f0
	s6mPwy0FhVltt114k0N2jqnDIsqTKUbYdZ8qN+8I/eLSHYxNY9A1cdSmfs
X-Received: by 2002:a17:90b:1ccd:b0:2ee:c918:cd60 with SMTP id
 98e67ed59e1d1-2febab78da2mr27444913a91.20.1741104371050; Tue, 04 Mar 2025
 08:06:11 -0800 (PST)
MIME-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com> <20250304092417.2873893-3-elver@google.com>
 <20250304152909.GH11590@noisy.programming.kicks-ass.net>
In-Reply-To: <20250304152909.GH11590@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Mar 2025 17:05:34 +0100
X-Gm-Features: AQ5f1JrbHN1FRthi_aRGgJ-kY7WYoWmU4g-pqTmD_Y1oCMFum9IakZQE8Yg9HXM
Message-ID: <CANpmjNOR=EaPPhnkj+WwV8mDYNuM7fY2r_xdjORv2MGGxxH_0g@mail.gmail.com>
Subject: Re: [PATCH v2 02/34] compiler-capability-analysis: Add infrastructure
 for Clang's capability analysis
To: Peter Zijlstra <peterz@infradead.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fBYILs6q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as
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

On Tue, 4 Mar 2025 at 16:29, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Mar 04, 2025 at 10:21:01AM +0100, Marco Elver wrote:
>
> > +# define __asserts_cap(var)                  __attribute__((assert_capability(var)))
> > +# define __asserts_shared_cap(var)           __attribute__((assert_shared_capability(var)))
>
> > +     static __always_inline void __assert_cap(const struct name *var)                                \
> > +             __attribute__((overloadable)) __asserts_cap(var) { }                                    \
> > +     static __always_inline void __assert_shared_cap(const struct name *var)                         \
> > +             __attribute__((overloadable)) __asserts_shared_cap(var) { }                             \
>
> Since this does not in fact check -- that's __must_hold(), I would
> suggest renaming these like s/assert/assume/.

Yeah, that's better.

FTR - the "asserts_capability" attribute was originally meant to be
used on runtime functions that check that a lock is held at runtime;
what Clang does underneath is simply adding the given capability/lock
to the held lockset, so no real checking is enforced. In this series
it's used for a lot more than just our lockdep_assert*() helpers, so
the "assert" naming is indeed confusing.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOR%3DEaPPhnkj%2BWwV8mDYNuM7fY2r_xdjORv2MGGxxH_0g%40mail.gmail.com.
