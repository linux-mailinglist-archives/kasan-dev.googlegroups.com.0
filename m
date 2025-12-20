Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI5YTLFAMGQEIKHMXCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CEFC6CD2F04
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 13:53:06 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-7c765a491bdsf2457756a34.2
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 04:53:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766235172; cv=pass;
        d=google.com; s=arc-20240605;
        b=jD0U5AKXvgDNG2JHN0o+JIW89u07RgbsqCQOeRe/xcSY5W4SPR3CF848wT8r4/uAYQ
         rMYmm0EJ1lVl2dcZIz9qXw/HkDVz0qxqjG4ydAfn5DKac+q/+acgnHXm1xLwxQTugVBV
         +wrNC1eABJwQxgvrBVBRGCcr5IXIs3FrCkbDgdAingwT+dYw+zQEOu3N8kPa8Cy4o0WI
         457nuRCzcv77KnCQkpYvWInbN9DjyF6DGASPGvOSRT32wL6ryJeJa6Pu1ZEZl2IyaXgG
         julSSPiQqQYt2DZ59K8iHg3Czq454uING+lo7I6exEObLNg/Ge5a+iTbRSkp3iuDjbFj
         w/BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bR5RmTjmpKScbNsbLwflco/uo/+jngOxmZFge25h1ak=;
        fh=TQljUSJhwYcMGtMaY91+REnMAtF0vKnNfs3+zktwD5E=;
        b=PIvW6jxV8EbnNPFpAW8J0FbRQQQBM+j2SocA+7vRte50UX4pwBrrCoap3Pr6jwY7pc
         O0VxQGag26cCjbPng/BVCggMJEzwUPaPC/jh61+p5VzS4NJNc832Z8ydskB9ePVCpIfz
         lpVy/tFnWSj8eNre19udvsUXmaFnhFkaEBlb6Pl+eNe+0SwGk4RGJCCU6ly2GV2qP7QK
         bLeQB6juFswXNHTe5uI9EaTYODeO23sR0AODDY7TmsHM4KdmgpphFQ/N2WsN1cBHuiJf
         T4Nox0THoj1MK+tiLL22XnsBT2c+5yqOef9Q6ItyZ+nf12MoEBv9TS82SAu3YNoXht3+
         40eA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cZpT+bKd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766235172; x=1766839972; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bR5RmTjmpKScbNsbLwflco/uo/+jngOxmZFge25h1ak=;
        b=msRqs3Ynh9mY9JzF9EVNZL8Uif18iQLE4zOyayVz39bCPeVfEULAtHM7jVsqBz+/Gh
         NSyLLQ8HV4LxcxojvMDnrn8KJ+GNcXQOgctPabliHpxJF/UWKrrfmOk3WTuv2ckFk7/E
         7cktgNmVUB9Nr1dIsJ45bZTYzFk3OAYF8KuDDaA+aGITOBR+iOeeAsmrs8pIbRV5Qo7a
         qWjOc4To8Zr9VgaiJthAi/rr3EWdF7fdPUTZT6CpqYEfHx8eCTPJGmimNw9kUaUJt1Gp
         McgIL6mAEpgRJoHunUmAeA5fOOKvfDvDgn30SaHISwA1iZw2+DQSP4qCulD6yYyuHgY9
         9/5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766235172; x=1766839972;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bR5RmTjmpKScbNsbLwflco/uo/+jngOxmZFge25h1ak=;
        b=JKuJiYY+XuIYRGzA/Y9MHK+sNuru4rKuHPtJE9Ila9U6ONhWRJy6yoIIaw2vtGdthf
         ZpKNXylLknbuF8oKmVbgPxl07kUftskFT2ipeoe54R7zZak2LGZacBcS0Yk8vnMt0B9f
         mpG+BsRxtO91tUVNvQ9QN6YOVEieBrBy57sJa8PUvnyamj1p4i2/B4MtSDDaj+6zNfio
         JpKUU3uifSOY60khvVYHZqX9/Iv7775JnELGWLk4GG6VGlcUu0ij1A69msPlRLRBYpjL
         xCUGeA3/hh27v/JVA1SX17CvqEh0WWMErbf/hWZNhjvs/7tKy9xLR6myUmc3KfPdi8qJ
         /v9Q==
X-Forwarded-Encrypted: i=2; AJvYcCV3EhVLQD8CZD2zqbVufujbb+5DzbfVI+0biBRjQgua1dw0rwIz+3ZTulJBI56KHNdsYgYftQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz54m1AUCVv/EnafMEsi3nJO3/Ek7w+iiu6K6JWI8epRQt0bu57
	oGDrz+TzI9DRCdcdivZ9ypL2oGriwWbEcq4FoET7E9fA6n4VT4LnMceS
X-Google-Smtp-Source: AGHT+IGrMGD5RjfkT+ZVr7WJeNMuHxMJLN17p2ct4RDNbZmRdGL7gNDNAeNX2oBXbzJyy62tVo9S/w==
X-Received: by 2002:a05:6830:4125:b0:7ca:e8bf:8c4b with SMTP id 46e09a7af769-7cc668af33bmr3400228a34.9.1766235172174;
        Sat, 20 Dec 2025 04:52:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYXsbJsIm/DK66cKMd0oVbiG3aKpbzAeTHepHgq2anQ1w=="
Received: by 2002:a05:6871:6804:b0:3ec:53ac:b3af with SMTP id
 586e51a60fabf-3f5f8781969ls3742535fac.1.-pod-prod-06-us; Sat, 20 Dec 2025
 04:52:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUig1i0wKu3uyGIJX5WKQSOi6hGs/OZ0denANIQ/Q3KZoNyQCpyXS95Fz5o8kp57PcOIRNWnV2fUgQ=@googlegroups.com
X-Received: by 2002:a05:6808:c288:b0:450:b781:3731 with SMTP id 5614622812f47-457b20c1fc6mr3501252b6e.26.1766235171015;
        Sat, 20 Dec 2025 04:52:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766235171; cv=none;
        d=google.com; s=arc-20240605;
        b=glB8LqxJbpd9N5rwoxlzzUwFWSuKr3NBnm9+D27ay9TPaYd1eDtmZflf56I7bnWqMx
         ibeyrWvO7KGz1UpprKTit2tM+yVZM1XE4hJYNuwCQ5qBsM0onEtnaD2oTERrdcuG51i4
         lvMsIDnZQQRNAu2QluK3OfaRgvMxNts0Qv/+ioBNe9e8slXKToSq4g5FWWnuvt9bghet
         bRNHnadT+31jl7We7nb+rYJ5NzXOnEXQlffnIrfR4jI/t+ayunqDSsKx07GOdShTzLtF
         SmkMgym4GBkZHcwChejqSNZJ7AkXBwPkxOHT5p6TJhUDTbX4OWVvntb0CtT6pD/4LnXw
         SXjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mbJUZ0xTndCf3VdowDat4Wdfn4Fu9I8D0dKSNYqhcFE=;
        fh=cZyimzKobiMbkHjh4DP8kaTVJxIQVOxo5ticlx0wCAo=;
        b=LGj4FUWWjDuupddA0jD2ZoNL1N4UX6Zrqu1oTYJ3dRk+Cdh3h52O7iT1ETZVPbwYc1
         moCFOs1UE08L442kjzmWSxsnoCTFS5qSmfWcP1O5bHt5nfk8pacqpV8UxtzNCsilwJvx
         wfKgClqbGY08kg2y4jiXZHuNe5cg4dBu8NitO4hQ+DTXuNIRJ1FdZNZ6PfH8wzv/lcUG
         UgUVgBMyvBNUqbehL+ALAosOYauPuQgIeul5xiRDnJbckUO9Yw5h0F4HYbEW6DXMOHjW
         QPhCzd6NcoYfCNF90cQ1BfsjF84pZ5iEe8psVx0TOlO645GGUFO6p3tSkDBsiCFxAiI1
         jT4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cZpT+bKd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-457b3c6f22dsi212061b6e.3.2025.12.20.04.52.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 20 Dec 2025 04:52:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-29f2676bb21so33212445ad.0
        for <kasan-dev@googlegroups.com>; Sat, 20 Dec 2025 04:52:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV2I4UJsFVx0b8OfnqZZAzzTgMyQOUD1jPzOUfnKMTq0Pg4+0XD4R5/tFgGqdysar0HsigEmZ+gYgk=@googlegroups.com
X-Gm-Gg: AY/fxX40DvAZoLaV54PY/SJbaBqKtc+eJNvGBwWn1C01hCmDo84UaKFs49+NYosMeAa
	wu9kvx9FSCuw6ao1pT/8CiYbyauhNgwbkrzIWCOm3ACv72A42gtH+B9NgSjmeAcuV3wVqn/7XTV
	he1M3O16306V7XdJHC8tiL2xlutL/FXvv81eYQmDJynF++29ovc7bJKSpYnRd0lQh1kejpBsX6J
	in/OqNSamfISUsE5ZEgdx0I5AHeAKg3Mr7a6qFj+UySrvgwFdlAQzHsH30Bj+4DesFeOAYDvbf1
	chqqmLqglnR6iuZQQggBzoJDK3M=
X-Received: by 2002:a05:7022:6722:b0:119:e569:f626 with SMTP id
 a92af1059eb24-121722e0444mr6670285c88.31.1766235169708; Sat, 20 Dec 2025
 04:52:49 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-18-elver@google.com>
 <81d2defc-8980-4022-a464-3d285aff199c@acm.org>
In-Reply-To: <81d2defc-8980-4022-a464-3d285aff199c@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 20 Dec 2025 13:52:13 +0100
X-Gm-Features: AQt7F2oG2tk1HNWJ4txFgkKVTgQOAoxLExF81nhreitjIuVCBm-zQmVADhDjpfw
Message-ID: <CANpmjNMAGYeFK-jYafSihmA+T7wi3zC8Sb4fJ+ZjzDK5jGuMvQ@mail.gmail.com>
Subject: Re: [PATCH v5 17/36] locking/rwsem: Support Clang's context analysis
To: Bart Van Assche <bvanassche@acm.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
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
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cZpT+bKd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as
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

On Fri, 19 Dec 2025 at 21:55, 'Bart Van Assche' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On 12/19/25 7:40 AM, Marco Elver wrote:
> >   static inline void rwsem_assert_held_nolockdep(const struct rw_semaphore *sem)
> > +     __assumes_ctx_lock(sem)
> >   {
> >       WARN_ON(atomic_long_read(&sem->count) == RWSEM_UNLOCKED_VALUE);
> >   }
> >
> >   static inline void rwsem_assert_held_write_nolockdep(const struct rw_semaphore *sem)
> > +     __assumes_ctx_lock(sem)
> >   {
> >       WARN_ON(!(atomic_long_read(&sem->count) & RWSEM_WRITER_LOCKED));
> >   }
> > @@ -119,6 +121,7 @@ do {                                                              \
> >       static struct lock_class_key __key;                     \
> >                                                               \
> >       __init_rwsem((sem), #sem, &__key);                      \
> > +     __assume_ctx_lock(sem);                                 \
> >   } while (0)
>
> Just like as for lockdep.h, I think that the above annotations should be
> changed into __must_hold().

My point is the same: we use it to delegate to dynamic analysis where
we reach the limits of static analysis, to avoid false positives [1].
Code should apply __must_hold() or __guarded_by() to called or
protected variables respectively, which is both cleaner and the
idiomatic way to use all this.

[1] https://lore.kernel.org/all/CANpmjNPp6Gkz3rdaD0V7EkPrm60sA5tPpw+m8Xg3u8MTXuc2mg@mail.gmail.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMAGYeFK-jYafSihmA%2BT7wi3zC8Sb4fJ%2BZjzDK5jGuMvQ%40mail.gmail.com.
