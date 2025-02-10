Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNMIVG6QMGQENMD7XCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 57FB6A2F6DE
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 19:23:52 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-21f6cb3097bsf65476795ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 10:23:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739211830; cv=pass;
        d=google.com; s=arc-20240605;
        b=MKU1FPG8QZ6Mf2MhwKn1ctQL1t3tnkKUq4R1SEQyC4qWA6WGrqrWyzcinS8bh7Ch0T
         2y0bD1rMMIm/E+UEESPd5f0lPJpOcR4KdVy5lBRq7LolOsVOXCF6qUoPQO9n+t2+3FEt
         TlFVNgtPBZN2nbttXmG7KKKfOeH5iF+6HLWpqlNrfn5nen6gfL7qvAIig3Mg9Iq/Qxcj
         +AL+6fb02giFDsAEZM9R05RXPVDHU9jT2QTPUO09E3qcCAdneeBtE3Fu5nYlBMh3ul9C
         EZ7tB/8t4BEWUxs6MUObbqP5ovpdVsAiab8MUYq2zJhGC4WXelnSVyYUMfRLohVENpCG
         g1fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4JItTLB4NHaucZLR5H+hJplUvWUwEiemNK8Xc0laXRY=;
        fh=SUk9rS9IA49KbUFcyhI1Ocy/vqpMfpegcCGDZ06sfks=;
        b=Nbs6wl7hpXWb7gG///pTNEr8pKULmkMTHfiIp0nnmOPtJo2tlKFKiYVPjnV2imdDJ0
         ECI46GmK0ltVsxlAk2M/OauuMvCFxlDVU8qtIxYhERwFUU4NgrKRVeJhimiOs5ioSJB2
         9jmS5zNj3EyaRAYVIqHFayt0uwuGAlBbPIXWB4YRLlfx7LCCB+yVNXgHX57St6xKEo3N
         ghIp/WIIkimRy3qLADSKncwDaff9IW1Ux+owm7s8+kXxo4bxntTZDECxg3IV3UZpmhv8
         vqhRlt5Hm8x3RbL4nN9srel9C3LweIotYEZVcE9Jsd5esm/9OrvmKShArW3GbckYuW0F
         +AYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=n612z4tY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739211830; x=1739816630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4JItTLB4NHaucZLR5H+hJplUvWUwEiemNK8Xc0laXRY=;
        b=SZyDxu7MZAaM28CzwFcmSstiQzbIszZmti5noSJpkd/7QDlR6//qvXFQPPN1G4ir7c
         ciMNs5aAsR/4tm7cAp553j4PtDL69j30EE0EjcbUABzG3YFsvV+0XqidgqZXbgBX8Jdx
         Vg0hgMt/CdgFCTyUY8rqjkSUyBBedCDDu4W3ZhjpbS1hibxD3WOeNLJ0w/Qeb6Qw6MlH
         k/k9RJ+zEdS19iwpKWfMpcEsdtyQm5lrmsEhvU+4XlTG7Ek0j2njIys9vD08tDGt0UHj
         eS4FZa0K839m82kkJXn5MRw/bkFY/t/6uAeJmSHfyqNdcI63D5y21dlpU0L7PWK2ucVL
         zuBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739211830; x=1739816630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4JItTLB4NHaucZLR5H+hJplUvWUwEiemNK8Xc0laXRY=;
        b=QmppxGCN9dShwN0BvBZ8ki1giorDsxIh3WjqICVOa2tCD9Fi/mZsVM7qpWiLAKFjKH
         YWqRGR3LxF82W+rUAeVnJZGFgfREJQ5ekReovjmp14qtYYfbIHqNo9bdiQMHsQyCWR3m
         EJhNiprPZM4VSCu00MNY7jIl484nKNj8wpwYwObh7+p0fo4uNuCiZorkO6sn7pariweD
         aKxiMokwwNyElFq359MIgWCsroJDdgglfO4nK+rknIcgVWTWDeVtTp+GY6q3qIAbtYdT
         kuILwspauC5A5mupNGrvDWDmucUeZIWMNJKDGg9D3W9Yi55rwY5G57V9g7sad8DApUZC
         SZZA==
X-Forwarded-Encrypted: i=2; AJvYcCXSzoxwZcqW/H/AK4bo4+oyenANWKIVasdrRBq+t5mNeoTA/ce/VuRNCNP8JHPe5M0nUat18g==@lfdr.de
X-Gm-Message-State: AOJu0YxoSCm2dIT3ma7upvKNl222oh6FdRRqMZ+kQwMUZR/1ysn0cxSH
	k+ZdvPYyqii13bOOME1VkVknBYHCmkLN7T7psLEdX8Cx42zPjL3I
X-Google-Smtp-Source: AGHT+IHX7Hu02BWLnrzuRaT8oA8NX39i6w7jlKmfOp4tIMo4bx90v5hZL7Us5Of0CWXS4ROUSMoZJw==
X-Received: by 2002:a17:902:f547:b0:21f:542e:dcf2 with SMTP id d9443c01a7336-21f542edef0mr211953265ad.44.1739211830236;
        Mon, 10 Feb 2025 10:23:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee11:b0:216:1913:1c59 with SMTP id
 d9443c01a7336-21f4e76b2f1ls6958495ad.1.-pod-prod-03-us; Mon, 10 Feb 2025
 10:23:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUizdCNDvDfvknT7xvIWC0JGAWSVs6uv4p+C7PuGnAx1+4EXEzgCH95dUSAbsYRnbK7BHlSH7gElrU=@googlegroups.com
X-Received: by 2002:a17:902:f787:b0:216:644f:bc0e with SMTP id d9443c01a7336-21f4e6c899dmr279925945ad.24.1739211828767;
        Mon, 10 Feb 2025 10:23:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739211828; cv=none;
        d=google.com; s=arc-20240605;
        b=eUBDhvjyd1UMQsTxUKWPcW9/LbCMKIW+UCOaASOPpFNd3IN0KxIe+grDmJmKGeoPQv
         8M7RZW+LM3ApNr5uTzQZPLbI6Z+AJw0zpzCSZsQtGgfaTLQcTbXHKRC0GvJpmJkxpPNk
         ulV9UorysgKhQLvc3DJMgEPCcK9emdRN+Wzk8K4M6VaaH7r7n27Facs1TWUhW7rH63+4
         1b9Nos0kldRgyWXC81619VFin8Il/Ij0d63znsKC3rEWQRzsppXGu7y87PIHnnowAAI5
         85O2BAlGIVpKDtRq8rPJ9G2+703Oya/LoUsZ0ZGNIw5ObFTclgQ1QrReJFldWSqwR70l
         C1GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GHmPYfF8/lSNO+AXa3rKVXqC3Xbb512b0LOODXOyyrk=;
        fh=CQCKiA3zP4IyE9TpoLRmAgInSEembCzKg1Df7sbbAMs=;
        b=A5qi8KHbYYvop4JVTo786f8Ri4N07vW6ux9HFD+ugghLXVghS3WN3ixdy3KZ3QqiQw
         UeNUbb+c/HL2F6wbmt+25DM8yIR1ypZMqi3wZDhvbhK3o11vWuVLgOjT/JzbPriIRrx3
         a0gXCyVPAcEL1/wbM5cOcm3PegcjtU+sz3SYu562otCopK6wuPkRm1kmKTdXHxgiPF8E
         LRDCDa2syfTMHJv69aBxbZ4JLC/U3F0vsxCW9DtC4rwG8QMgLQ0+jRC2k6DpbmYh7uvB
         sRSzzOkDQUgQ2PYkGS0VzZsmGOmBj2svGs11IFinIeYVRhQixM2H07BGKso+yPZA/E7F
         vyIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=n612z4tY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-21f3654a4dfsi4438685ad.4.2025.02.10.10.23.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2025 10:23:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-2fa1d9fb990so7258063a91.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2025 10:23:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX5/94IENPrIPpdVCu9RhsTGeFdbsCnG6rELdmsLwCF01qZy3MrlOKCaR+CNt4qfgOfWXRnHnONWaA=@googlegroups.com
X-Gm-Gg: ASbGncuasijNe9oaqsLZczBrO+fv4bextI1JvVvUnFiWyoh9xvCwM9bFNiIlBv4Uxll
	xR7Tkki3lagGpChP2NRYLfKMYj1zUqo3OlC5+tdGVZM9f9X7coK6GNa69CkqbmiNibSWs6juekw
	R0XV7hOh2YGgzQJgECITKG3xyMJN0=
X-Received: by 2002:a17:90b:2ec5:b0:2fa:2252:f438 with SMTP id
 98e67ed59e1d1-2fa2450cf33mr21544870a91.30.1739211828003; Mon, 10 Feb 2025
 10:23:48 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com> <20250206181711.1902989-9-elver@google.com>
 <e276263f-2bc5-450e-9a35-e805ad8f277b@acm.org>
In-Reply-To: <e276263f-2bc5-450e-9a35-e805ad8f277b@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2025 19:23:11 +0100
X-Gm-Features: AWEUYZmxMGiGlzeQT0LaguR-GUnXW8sHLZhY4gy5ushUKI7JT1xIrRKge8P_UM4
Message-ID: <CANpmjNMfxcpyAY=jCKSBj-Hud-Z6OhdssAXWcPaqDNyjXy0rPQ@mail.gmail.com>
Subject: Re: [PATCH RFC 08/24] lockdep: Annotate lockdep assertions for
 capability analysis
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
 header.i=@google.com header.s=20230601 header.b=n612z4tY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as
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

On Mon, 10 Feb 2025 at 19:10, Bart Van Assche <bvanassche@acm.org> wrote:
>
> On 2/6/25 10:10 AM, Marco Elver wrote:
> > diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
> > index 67964dc4db95..5cea929b2219 100644
> > --- a/include/linux/lockdep.h
> > +++ b/include/linux/lockdep.h
> > @@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
> >       do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
> >
> >   #define lockdep_assert_held(l)              \
> > -     lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
> > +     do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assert_cap(l); } while (0)
> >
> >   #define lockdep_assert_not_held(l)  \
> >       lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
> >
> >   #define lockdep_assert_held_write(l)        \
> > -     lockdep_assert(lockdep_is_held_type(l, 0))
> > +     do { lockdep_assert(lockdep_is_held_type(l, 0)); __assert_cap(l); } while (0)
> >
> >   #define lockdep_assert_held_read(l) \
> > -     lockdep_assert(lockdep_is_held_type(l, 1))
> > +     do { lockdep_assert(lockdep_is_held_type(l, 1)); __assert_shared_cap(l); } while (0)
>
> These changes look wrong to me. The current behavior of
> lockdep_assert_held(lock) is that it issues a kernel warning at
> runtime if `lock` is not held when a lockdep_assert_held()
> statement is executed. __assert_cap(lock) tells the compiler to
> *ignore* the absence of __must_hold(lock). I think this is wrong.
> The compiler should complain if a __must_hold(lock) annotation is
> missing. While sparse does not support interprocedural analysis for
> lock contexts, the Clang thread-safety checker supports this. If
> function declarations are annotated with __must_hold(lock), Clang will
> complain if the caller does not hold `lock`.
>
> In other words, the above changes disable a useful compile-time check.
> I think that useful compile-time checks should not be disabled.

The assert_capability attribute was designed precisely for assertions
that check at runtime that the lock is held, and delegate to runtime
verification where the static analysis is just not powerful enough. In
the commit description:

Presence of these annotations causes the analysis to assume the
capability is held after calls to the annotated function, and avoid
false positives with complex control-flow; for example, where not all
control-flow paths in a function require a held lock, and therefore
marking the function with __must_hold(..) is inappropriate.

If you try to write code where you access a guarded_by variable, but
the lock is held not in all paths we can write it like this:

struct bar {
  spinlock_t lock;
  bool a; // true if lock held
  int counter __var_guarded_by(&lock);
};
void foo(struct bar *d)
{
   ...
   if (d->a) {
     lockdep_assert_held(&d->lock);
     d->counter++;
   } else {
     // lock not held!
   }
  ...
}

Without lockdep_assert_held() you get false positives, and there's no
other good way to express this if you do not want to always call foo()
with the lock held.

It essentially forces addition of lockdep checks where the static
analysis can't quite prove what you've done is right. This is
desirable over adding no-analysis attributes and not checking anything
at all.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMfxcpyAY%3DjCKSBj-Hud-Z6OhdssAXWcPaqDNyjXy0rPQ%40mail.gmail.com.
