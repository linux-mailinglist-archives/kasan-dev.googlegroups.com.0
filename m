Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4NWK6QMGQEGTTF4OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id E26A9A324F8
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 12:31:20 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6e48a052ad6sf11102996d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 03:31:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739359880; cv=pass;
        d=google.com; s=arc-20240605;
        b=juRA/vvWJx/YRTiqDZjfKnosUEbr2HAMGIjYHH+UaZupQLHQ3cR1DZXOCatPms3LRI
         0dJ1ftYsF9QEXEIEcAT+UDABKl9N2rlHw5AB96Kg25Ihg2zOVjbQ1AvxRNF9UbBKsQqD
         K6EhDTVM33hb3Rh7/Fi+pG67qYCZlAawMe2SPSYs2Nu3MXB18gk7QkdeYN9SuTHpM0vX
         I0K/BV7OJbCVPBwPHP4iPxYFMJW8z8KIm8rf8RSfnlxP/Jzfus70HA76qd8KGLOYVw3S
         8A5JDYaornplITSEeu5dsDUsEFXLc0ERhkER/ds8mwH1RXqh2mFaxPoCGFghXhqBVguG
         PnIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vnDFAFhgc0HQI/TTJ6NamJZpveuEHSmyT1WR74jFEYE=;
        fh=lge9z+/fr3Rvcjtm0y83ov+gaLEtn/2l5XOBAKjM508=;
        b=fB/fQx+Qm9AvN6zf2DnNgjICfuBW75ZMHajcSJLI+RVCH0kbYoHNjflICH+7Qol//P
         VKEKMKSqGtSOrr2PhpmSONrKpD4kDzT6UXGE+8C6REPvTPeJC5lMrESafuM9uT4LsE63
         Z/tpWyiMu5SuxzkCqBqMowM05bqzT1Zud4hTy6QHPCoNqo5GRCdeL0PcOAIqqtnIInIo
         fEwZVtEjiTM2CWU2vFgDF7sajyVbp4HGKEsX0kKby5bE838GTxeFhy5kW3IbdE+HMQf/
         5YeoQ9xEeIj+1zErcqLhIe5+MfTx/akM64+vF/e7ypWdNgi37C7+CHyoqNTjutYpu3ZM
         gMqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AxAH5LMm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739359880; x=1739964680; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vnDFAFhgc0HQI/TTJ6NamJZpveuEHSmyT1WR74jFEYE=;
        b=E4jmhZm0Bswt58V2lqTR1sIklNB7I5ItjZMtFeB1i/X9zZkRXmpEHtO4WwfQsJd86X
         QG8DmZCh6sfzaUYH/ehNfSgrPeBhpOH12kvPAsfF2wXMQWNoxonZrlhYJhQu0aSAt01R
         N0m2+3f9ikuHTsHWZfwALu2oGzyr2CcrbKu78u8OiRAEzRudUE2cENvGQ5gXxQMOoDqB
         E8ewK3ZEptALm5NX1YJZgN/Np8d55aczgHx2kJSN4w3tikx7NU4j/INujff4yOTzRqA4
         kaSo32NZUoggfVQFsZTeuTpoWiFp89+CcJezUNrRttMeG2LHLyAl4w9eXIiofVOVAqwG
         fLug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739359880; x=1739964680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vnDFAFhgc0HQI/TTJ6NamJZpveuEHSmyT1WR74jFEYE=;
        b=UPYk8w0TqzHsvh32TAg54XAV1TALFtUlVczCkIAx6Z4W3odrKoxqyONkPLLLNfoSYR
         ORkQA8pvmm5bvzD6y7Sknu39rHmPKl6QVssj2wn5jFLmIUYbQ7JRKiCN4c2cuc7lrwrz
         /waW4dQm2YSaKFy3Ia1ikS1ZeS9nFkDuLY2zvY2ca6dg9U1MDVOBbPQxH6tr77JqLm6u
         CPH4SJp+CSQPpXR2klofsGF1nQvPguDJSuo0jAKRZKI/0jo5lTx8HLUY5SzQvXDwg69F
         O2E48FZYjWHZQ56n85sIKdZoqPGf843szIxUjdahJ4xLtGIMibgOOvG5nDchtqYjk8aH
         sFcw==
X-Forwarded-Encrypted: i=2; AJvYcCUGW3LKJXxnHe+v1vBIIhsPRxfAQgwJrf1Da6VRqjeXQqaCZhwodUm9HukBU1YrawcvWzD95g==@lfdr.de
X-Gm-Message-State: AOJu0YwgchxIkocB1mjfSBs6vaIg9vx9kk9AkP4xoB+/7QsTIhdJwa3P
	GDVy98OAdpTJwsWPAGSSJMy37Ebji9uqW5UbpgmpoLmJNS6HmPtt
X-Google-Smtp-Source: AGHT+IHgyCIPYDft9nf5xIws7MUnSRBmzGRQjD8o3NlZMQwkC4s8304kL16vl/py/6goSLhnpHYAQg==
X-Received: by 2002:ad4:5d66:0:b0:6d4:215d:91b9 with SMTP id 6a1803df08f44-6e46ed7e57fmr40512476d6.11.1739359879528;
        Wed, 12 Feb 2025 03:31:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFsZj60hc7L91+LaBB8rlsC7uJ3LL56dQQg5ULQ+IKspw==
Received: by 2002:a05:6214:5b10:b0:6d8:b1cf:a07d with SMTP id
 6a1803df08f44-6e44530352els3316796d6.2.-pod-prod-02-us; Wed, 12 Feb 2025
 03:31:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWFwM/RWo4rRguaLa1u3lnZwYgbdiSmypF32L6Ff3qWz57WbQvfzsBZjMnIdDqq2zda516nsO6HXb0=@googlegroups.com
X-Received: by 2002:a05:6122:4899:b0:520:62ce:98ed with SMTP id 71dfb90a1353d-52067c75094mr2277449e0c.6.1739359878547;
        Wed, 12 Feb 2025 03:31:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739359878; cv=none;
        d=google.com; s=arc-20240605;
        b=cdrNUuTfceoyOPMAb3PB56FizrYraQBhAeb1K/LqaP+6CFQWJWSZ021Olf2QJ5mK7q
         g4h39aMn7MNr+f19H5gwOPtKCrOc/oObTWCdJWl+rwQOZ7ftxXLpHTaPYqnnEsb6bFYj
         3rnzOWYnpvC8bz6KSIsLhm0w7fZ1PH/v462M2U1WgKbOcYVgfbC+dJIrBnhvS/2YyakQ
         3NFdoPIIirpX8uWTpKXIb+1lkK4QKmUfjkAK0IaZ0CIvRJCCDyRrpx7tlfUODVsY1JHB
         IkBc9v/pe4LojDMzrug0TL/nbsrcRnpKxuQ0BKuQI5ijS/upIc33kjeebCOocGtaSKG1
         NbnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7rEBrHtcjfEoUuHQWiZbj092Ws2ECaqqUNMQHsEcu0U=;
        fh=+hSohL+3c6NcL6cxubjViRKvcYbRhZzfK63gMcYgKDw=;
        b=Uf+ucUjyF7YhfkrXt5bMTuxDJK0jmJBc5yDnzDwTQGS8wp/rN6xGsaEp0xzDX4cnUn
         N8ZHCBaK+VfARkr314+/vWk6PNmHiSHTPnzrOz0p3ABiiyz+0WKGL49YE/gDZ9kD/AWP
         dxaqGn5BJltXA9yNvDs3sG485ifSFR163L0CppX1HaxsigaLmzMwIy/eBdWsetm4gnSI
         NIA5eAlBt0k2S/6TdLWD51CfMZiLitlhi3wknkuydZzuNvzP3RiDlaYYpVJxC8j5+DYU
         7B8msP9X/3ZD2OL5swgeE2qpfu0F9zwShE80F+2qAds6KHbsfOSxf0pPkk3eWtHCEAMO
         6x7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AxAH5LMm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5204dc463b1si250041e0c.0.2025.02.12.03.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 03:31:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-2f833af7a09so9158024a91.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 03:31:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVtARV8QaoQYq6Y72I3gafZUB7kP8F4nYZYemPe9Bgc56wDq74ikHBynyY2DWxSSpo5tSOt4w6/tc4=@googlegroups.com
X-Gm-Gg: ASbGncsvGdB+xz8Pf2GyI4BPkgKN+nq3Yj0obCgg/MBN6iF6Xo+bg5dyoztiqXY9dOZ
	AlrztkBdIcQIwwseGvniXQdKWywoThy8VHDfwwvKPYG3AgYYZBpYoJSCdljOBmNZdBgpgS6Vysb
	FmVXthRTij7Ke5EguX9IEbxUwCR7Ce
X-Received: by 2002:a17:90a:c88e:b0:2fa:20f4:d277 with SMTP id
 98e67ed59e1d1-2fbf5c59edamr4556439a91.24.1739359877300; Wed, 12 Feb 2025
 03:31:17 -0800 (PST)
MIME-Version: 1.0
References: <20250210042612.978247-1-longman@redhat.com> <20250210042612.978247-4-longman@redhat.com>
 <Z6w4UlCQa_g1OHlN@Mac.home>
In-Reply-To: <Z6w4UlCQa_g1OHlN@Mac.home>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Feb 2025 12:30:41 +0100
X-Gm-Features: AWEUYZlid8tnSI_M5CNmo_NAFEKRRgGapbh7_REdPcYQ5nNgIjsLxmmVx436lXA
Message-ID: <CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] locking/lockdep: Disable KASAN instrumentation of lockdep.c
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Waiman Long <longman@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will.deacon@arm.com>, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AxAH5LMm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1032 as
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

On Wed, 12 Feb 2025 at 06:57, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> [Cc KASAN]
>
> A Reviewed-by or Acked-by from KASAN would be nice, thanks!
>
> Regards,
> Boqun
>
> On Sun, Feb 09, 2025 at 11:26:12PM -0500, Waiman Long wrote:
> > Both KASAN and LOCKDEP are commonly enabled in building a debug kernel.
> > Each of them can significantly slow down the speed of a debug kernel.
> > Enabling KASAN instrumentation of the LOCKDEP code will further slow
> > thing down.
> >
> > Since LOCKDEP is a high overhead debugging tool, it will never get
> > enabled in a production kernel. The LOCKDEP code is also pretty mature
> > and is unlikely to get major changes. There is also a possibility of
> > recursion similar to KCSAN.
> >
> > To evaluate the performance impact of disabling KASAN instrumentation
> > of lockdep.c, the time to do a parallel build of the Linux defconfig
> > kernel was used as the benchmark. Two x86-64 systems (Skylake & Zen 2)
> > and an arm64 system were used as test beds. Two sets of non-RT and RT
> > kernels with similar configurations except mainly CONFIG_PREEMPT_RT
> > were used for evaulation.
> >
> > For the Skylake system:
> >
> >   Kernel                      Run time            Sys time
> >   ------                      --------            --------
> >   Non-debug kernel (baseline) 0m47.642s             4m19.811s
> >   Debug kernel                        2m11.108s (x2.8)     38m20.467s (x8.9)
> >   Debug kernel (patched)      1m49.602s (x2.3)     31m28.501s (x7.3)
> >   Debug kernel
> >   (patched + mitigations=off)         1m30.988s (x1.9)     26m41.993s (x6.2)
> >
> >   RT kernel (baseline)                0m54.871s             7m15.340s
> >   RT debug kernel             6m07.151s (x6.7)    135m47.428s (x18.7)
> >   RT debug kernel (patched)   3m42.434s (x4.1)     74m51.636s (x10.3)
> >   RT debug kernel
> >   (patched + mitigations=off)         2m40.383s (x2.9)     57m54.369s (x8.0)
> >
> > For the Zen 2 system:
> >
> >   Kernel                      Run time            Sys time
> >   ------                      --------            --------
> >   Non-debug kernel (baseline) 1m42.806s            39m48.714s
> >   Debug kernel                        4m04.524s (x2.4)    125m35.904s (x3.2)
> >   Debug kernel (patched)      3m56.241s (x2.3)    127m22.378s (x3.2)
> >   Debug kernel
> >   (patched + mitigations=off)         2m38.157s (x1.5)     92m35.680s (x2.3)
> >
> >   RT kernel (baseline)                 1m51.500s           14m56.322s
> >   RT debug kernel             16m04.962s (x8.7)   244m36.463s (x16.4)
> >   RT debug kernel (patched)    9m09.073s (x4.9)   129m28.439s (x8.7)
> >   RT debug kernel
> >   (patched + mitigations=off)          3m31.662s (x1.9)    51m01.391s (x3.4)
> >
> > For the arm64 system:
> >
> >   Kernel                      Run time            Sys time
> >   ------                      --------            --------
> >   Non-debug kernel (baseline) 1m56.844s             8m47.150s
> >   Debug kernel                        3m54.774s (x2.0)     92m30.098s (x10.5)
> >   Debug kernel (patched)      3m32.429s (x1.8)     77m40.779s (x8.8)
> >
> >   RT kernel (baseline)                 4m01.641s           18m16.777s
> >   RT debug kernel             19m32.977s (x4.9)   304m23.965s (x16.7)
> >   RT debug kernel (patched)   16m28.354s (x4.1)   234m18.149s (x12.8)
> >
> > Turning the mitigations off doesn't seems to have any noticeable impact
> > on the performance of the arm64 system. So the mitigation=off entries
> > aren't included.
> >
> > For the x86 CPUs, cpu mitigations has a much bigger impact on
> > performance, especially the RT debug kernel. The SRSO mitigation in
> > Zen 2 has an especially big impact on the debug kernel. It is also the
> > majority of the slowdown with mitigations on. It is because the patched
> > ret instruction slows down function returns. A lot of helper functions
> > that are normally compiled out or inlined may become real function
> > calls in the debug kernel. The KASAN instrumentation inserts a lot
> > of __asan_loadX*() and __kasan_check_read() function calls to memory
> > access portion of the code. The lockdep's __lock_acquire() function,
> > for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
> > added with KASAN instrumentation. Of course, the actual numbers may vary
> > depending on the compiler used and the exact version of the lockdep code.

For completeness-sake, we'd also have to compare with
CONFIG_KASAN_INLINE=y, which gets rid of the __asan_ calls (not the
explicit __kasan_ checks). But I leave it up to you - I'm aware it
results in slow-downs, too. ;-)

> > With the newly added rtmutex and lockdep lock events, the relevant
> > event counts for the test runs with the Skylake system were:
> >
> >   Event type          Debug kernel    RT debug kernel
> >   ----------          ------------    ---------------
> >   lockdep_acquire     1,968,663,277   5,425,313,953
> >   rtlock_slowlock          -            401,701,156
> >   rtmutex_slowlock         -                139,672
> >
> > The __lock_acquire() calls in the RT debug kernel are x2.8 times of the
> > non-RT debug kernel with the same workload. Since the __lock_acquire()
> > function is a big hitter in term of performance slowdown, this makes
> > the RT debug kernel much slower than the non-RT one. The average lock
> > nesting depth is likely to be higher in the RT debug kernel too leading
> > to longer execution time in the __lock_acquire() function.
> >
> > As the small advantage of enabling KASAN instrumentation to catch
> > potential memory access error in the lockdep debugging tool is probably
> > not worth the drawback of further slowing down a debug kernel, disable
> > KASAN instrumentation in the lockdep code to allow the debug kernels
> > to regain some performance back, especially for the RT debug kernels.

It's not about catching a bug in the lockdep code, but rather guard
against bugs in code that allocated the storage for some
synchronization object. Since lockdep state is embedded in each
synchronization object, lockdep checking code may be passed a
reference to garbage data, e.g. on use-after-free (or even
out-of-bounds if there's an array of sync objects). In that case, all
bets are off and lockdep may produce random false reports. Sure the
system is already in a bad state at that point, but it's going to make
debugging much harder.

Our approach has always been to ensure that as soon as there's an
error state detected it's reported as soon as we can, before it
results in random failure as execution continues (e.g. bad lock
reports).

To guard against that, I would propose adding carefully placed
kasan_check_byte() in lockdep code.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNDArwBVcxAAAytw-KjJ0NazCPAUM0qBzjsu4bR6Kv1QA%40mail.gmail.com.
