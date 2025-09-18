Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBMOUWDDAMGQEUL26UVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A2016B85C3C
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 17:50:10 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3ccd58af2bbsf889209f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 08:50:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758210610; cv=pass;
        d=google.com; s=arc-20240605;
        b=XOQ5cUaqNdvcF+XJy61v/MA+kZpwr8vkt3YjskngH1j4hNXbxm0MaCGZjSymx0NGV9
         OWica0AHyHV+BZ2Zu6n9L3cuFcZi6IOtyncpVWXnldeWWR11RnmT3Hdu/63sr4O91xzu
         5ur8470L/o2it4AszCYY1ZAhWQ3YQt9nwNxyKOkRvo4EH8Qg5bJYizGEdor+50aZaHYf
         BJP2uxyD6lL97jQ6tpOW4Y/+DJFxAbEWLT7IveImz7AmNPAo5HV+opnQmw7nMRxzJu7P
         DpU0SpHWiYevkdqNmLYdnRj1QO8nvBwHzVDFsdUKX9OGlrGXZIC9wnkR7ycutEYD9DI8
         nxXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Ow9AiD1rbKReUMFu9GF3OR9YmCftPcYcHu92BZjqnRw=;
        fh=iQpBOXDSLxnA4sa96WxBiQy19/0UO2UulTy8MT5J+XE=;
        b=WUxMI52teVtGz5AJixlgXknqcOHB9VALCNz3X85f2Dt1tPU2orijkOiaTIF99Rb/Cd
         YRZKVYE2a4aQYXGAYZq+NGUPUdO+pTsvqxZAmPm4m/fqF6r1M6KEVUcA6T7zMrIJ+2Ny
         vHmo4Pe7naLQYDb5OQxJL3FoLfNCAa6OeMlxniM86s/CXUxrpByve/zFEx2ZXdYGvAME
         xXr5N28E3uJtUhfcM2FW6q/9r2a6pDMmFuHi1F2wEZdZ97exkVqnBszeLKQb+oQ0bev3
         NekNzUAR7Z9WhX5eNHfRnqiR0QraJVGXbH/vW2VlSG0PwalVaWr0M9biwbW7BCN/rxsz
         QDxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Vebp1m8J;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758210610; x=1758815410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ow9AiD1rbKReUMFu9GF3OR9YmCftPcYcHu92BZjqnRw=;
        b=UYB46j4CoxUuaJKepFMMZG0Zo/M+e4CqPhHGBeOe/2B9pAJw57XeRQQ1mmarNq5T54
         wSE6KLUYp1bxNSOu5WMbLZd/cmyvv+xbfpfDaBpIXNa5Cmj0k8KcQ8dJdWo6ePRZ+ObZ
         njOVSiVq1ELCpY8DnhZCXNbgPFEQruF/rTsNWNV/+c0Ut9ZkojKbH6+jq6KZiIBvwB/F
         8Evvvv20XIsCsIoH139iV5/YxLSVeJ/NCZet3D6Wc1/nHzpNKxZN4baIoatVz2suDHf3
         yjXgeLiDWJ7Y+D3o1zG8s/sQewo7ulI/8cxklvBSb+HIQ4UAwvwN3iZzidMuVUJWajJW
         o6wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758210610; x=1758815410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ow9AiD1rbKReUMFu9GF3OR9YmCftPcYcHu92BZjqnRw=;
        b=V00P4SUaoBaZnf0H1RWaNWwR0CudpWtxaHcyfx/oUIpK6/kpiaFpYjPvltnsVUe4ZP
         AAclo8t9Mk+yegTRo9vuWg/TLf+IUYenVbSpTa0F3dvy7ewmTSuXSUIa6rc9K0HS2z/8
         YM5nyBx/UpcLnOCk+d91N0IuJUknatSNdALKds1b8WQxdQqGc9kqgPFHJ+68zTR/txRJ
         mWKnsryqkApCr/LY25bB7xSHJCQQ/SoZD+Zzr6tMmpzTmYeqtFAf22E7ZJ0ojEm6yUwz
         GBlSGTMjG30qRamiiwDpVTEKF88ZLSwsnpSpGrg8Ut3o7m7+6NxFibFBTFspDvEyIIrj
         9F/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcxVGTISTnSY1AajFcULfq+0AWaofssEmHAgofQvI1uZagAiW+0sPcr/penxc72adlY2yX+g==@lfdr.de
X-Gm-Message-State: AOJu0YzcWbRCyk7b8hjEmNoG6mUa52e/fCaM8iLXLC5OwKwu2LMS67Hh
	mx9IJPg1QzuTOqCsgWRpmGpSLkKWUYSW7ZYob6hBg+mdYINiQOGIyi7E
X-Google-Smtp-Source: AGHT+IHkYKeyeChEe2wB5nRAvSRWXHfcNzzplhIx7fOvIevnkc3cmDDOUFzFb2eSnl/B9JqbBsMjfQ==
X-Received: by 2002:a05:6000:4024:b0:3bd:13d6:6c21 with SMTP id ffacd0b85a97d-3edc9e2ba59mr3964351f8f.0.1758210609902;
        Thu, 18 Sep 2025 08:50:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4p7eOv3cu0aaS3tazpepxNgm6slHYtpSSve3hV7S++og==
Received: by 2002:a05:6000:420e:b0:3db:a907:f17b with SMTP id
 ffacd0b85a97d-3ee1058778fls410311f8f.1.-pod-prod-00-eu; Thu, 18 Sep 2025
 08:50:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV10d7RankCaVG2kl8sNMiYkceRiuTgMgHnCYgI49PFzdm3reBEzjZOvzcjYJFkNdSgiMLOR74R280=@googlegroups.com
X-Received: by 2002:a05:6000:2c0b:b0:3dc:1a9c:2e7f with SMTP id ffacd0b85a97d-3ee16026538mr136467f8f.8.1758210606606;
        Thu, 18 Sep 2025 08:50:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758210606; cv=none;
        d=google.com; s=arc-20240605;
        b=dwSNsAqAEELa4TzL87y0bTJrJveLjsV1yV1pl7iP6DB5QAEv7IAInxALJqpX0g/8+m
         lL555b39NSQK4YBXaTe9OsLLwoKLWxcDQwtTp6oRJxEXy74eriOSwH0DJxzRaatRZ1k3
         fkA7G2AMy4WQo6hSxpJ6CNOXd7LpVf9RKKP63bRfR9qOpV/4ei1fVAPj7Ay5BTQtYuI1
         L4L/KcRMLJNDtxFF+u1qYSz+pnYLSFM2qs4X+NYy7XsmUsILqoDiVmG7NMsEc5ZJ8Mfu
         6fo/EN8Stoe6IGNJfB2F+nV6S36ioPc2jfJPlCsfgu2h726IOq9EqO+R+JnEdPwPVIf6
         hd/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hpKO6CsQCuex3g+QZ22KGPC+ZgcKRmVKS1THDCqCkXc=;
        fh=T+rbCMBi3WxwHgk4i9u7OuSTXjQVaM8kci+o8WkMCVA=;
        b=Iu6t3sgLrSy2I1qkTvDB0jtNHPE3SQP+FJj5fQNii8PxIT/FNRYYI44fWAQFU/AtjG
         kw3nBNKqDL8fVtt64bBSiHOTyNKxcO1T/BfAFZfkxuZlQ+fzMxhmJkUp72txqnb4ywhi
         IIB4e6H6/s8RtN8G7ZfelHbxZALxK61oW6m8dwnEG+H6pINEhw9UpxuRZvLUOlqNn1Dp
         AfH9gQbRVF4d7UnLFlogPWAJuDQowh7EDdZPw4lHY48981kseohk5C0eUhTLu+yBU7bn
         Ws9aipt4fJETtOShKTWf7pBle4SQYfXHlSi3dv/WLYcm2quvwwtpFAD/nsPKwMytUvVo
         Qphw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Vebp1m8J;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee0fbcabecsi47283f8f.8.2025.09.18.08.50.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 08:50:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id a640c23a62f3a-b07dac96d1eso334397366b.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 08:50:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW9a33/DcMfMiKENljvIWn1Mx/iegERnVMiogSIELtPt4uKxvQYFUQrhE4ojpN99khwQs+TxiNVdws=@googlegroups.com
X-Gm-Gg: ASbGncvuXoM1WiVtbQzfiGBItVI/Kg1zWBct1e/A9Sp/uwWNTKMIsGAo+t3GotCwNa6
	jqQcxfxoV1zWDCd4VvSbjhjZ9Pto8LOshZAM/BOjIYpuv7Wz6fUj3sXgk4ty9xgaLP6RY+U84vv
	0HeQgCYwM60k0buDDWDupZ0jhidRRRe3OTpNk5yvC5qo5K0yWrwDkqnNA7L87Jk9tFsCPBIruxw
	QfHBx3yTie+en/FysahL7M2e4PLYCIRJZukKh4ZblfNAkAEbP95eU3tGE9PjYE635GeOGfLLyeN
	VMt4WdTK1W8qCnWzlIqC35OLUkgIWeRJOHZEjDXkxjvbKMWvZsCb4CAw6eHUcpma33obB4K8UmO
	RMsd1A6fzsQ4i9Dau4lTgPUpTAFdRzAAgFXUQWx6fmacLQDbhLXbKE55jG+IYwFeUyomKyc4RpU
	ZOrafLnWcTz9rW7Lw=
X-Received: by 2002:a17:907:7b9c:b0:b07:dd5e:16be with SMTP id a640c23a62f3a-b1fa844e2f5mr390570166b.4.1758210605709;
        Thu, 18 Sep 2025 08:50:05 -0700 (PDT)
Received: from mail-ej1-f41.google.com (mail-ej1-f41.google.com. [209.85.218.41])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-b1fc890cb0esm216830866b.46.2025.09.18.08.50.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 08:50:03 -0700 (PDT)
Received: by mail-ej1-f41.google.com with SMTP id a640c23a62f3a-b046f6fb230so232597466b.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 08:50:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUaLhndHPrMLs9D6SXnLPIgM6eme/R/cLfjMSpCDfRirMPNb/DwF3qj6EgpKZ/sp3IfQ1lkRt0ykI4=@googlegroups.com
X-Received: by 2002:a17:907:9612:b0:b10:ecc6:5d8d with SMTP id
 a640c23a62f3a-b1fac9c9b84mr417765966b.26.1758210601571; Thu, 18 Sep 2025
 08:50:01 -0700 (PDT)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 18 Sep 2025 08:49:44 -0700
X-Gmail-Original-Message-ID: <CAHk-=wgd-Wcp0GpYaQnU7S9ci+FvFmaNw1gm75mzf0ZWdNLxvw@mail.gmail.com>
X-Gm-Features: AS18NWBk4u9ObN57KesSGhJyt-aPlWZgKdxYhvzpAyoaxlNUF53WHe4dSKjzUBg
Message-ID: <CAHk-=wgd-Wcp0GpYaQnU7S9ci+FvFmaNw1gm75mzf0ZWdNLxvw@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=Vebp1m8J;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

On Thu, 18 Sept 2025 at 07:05, Marco Elver <elver@google.com> wrote:
>
> Capability analysis is a C language extension, which enables statically
> checking that user-definable "capabilities" are acquired and released where
> required. An obvious application is lock-safety checking for the kernel's
> various synchronization primitives (each of which represents a "capability"),
> and checking that locking rules are not violated.
>
> Clang originally called the feature "Thread Safety Analysis" [1],

So this looks really interesting, but I absolutely *hate* the new
"capability" name.

We have existing and traditional - and very very different - meaning
of "capabilities" in the kernel, and having this thing called
"capability" is just wrong. Particularly as it then talks about
"acquiring capabilities" - which is *EXACTLY* what our lon-existing
capabilities are all about, but are something entirely and totally
different.

So please - call it something else. Even if clang then calls it
'capability analysis", within the context of a kernel, please ignore
that, and call it something that makes more sense (I don't think
"capabilities" make sense even in the context of clang, but hey,
that's _their_ choice - but we should not then take that bad choice
and run with it).

Sparse called it "context analysis", and while the "analysis" part is
debatable - sparse never did much anything clever enough to merit
calling it analysis - at least the "context" part of the name is I
think somewhat sane.

Because it's about making decisions based on the context the code runs in.

But I'm certainly not married to the "context" name either. I'd still
claim it makes more sense than "capability", but the real problem with
"capability" isn't that it doesn't make sense, it's that we already
*HAVE* that as a concept, and old and traditional use is important.

But we do use the word "context" in this context quite widely even
outside of the sparse usage, ie that's what we say when we talk about
things like locking and RCU (ie we talk about running in "process
context", or about "interrupt context" etc). That's obviously where
the sparse naming comes from - it's not like sparse made that up.

So I'm really happy to see compilers start exposing these kinds of
interfaces, and the patches look sane apart from the absolutely
horrible and unacceptable name. Really - there is no way in hell we
can call this "capability" in a kernel context.

I'd suggest just doing a search-and-replace of 's/capability/context/'
and it would already make things a ton better. But maybe there are
better names for this still?

I mean, even apart from the fact that we have an existing meaning for
"capability", just look at the documentation patch, and read the first
sentence:

  Capability analysis is a C language extension, which enables statically
  checking that user-definable "capabilities" are acquired and released where
  required.

and just from a plain English language standpoint, the word
"capability" makes zero sense. I think you even realized that, in that
you put that word in quotes, because it's _so_ nonsensical.

And if not "context", maybe some other word? But really, absolutely
*not* "capability". Because that's just crazy talk.

Please? Because other than this naming issue, I think this really is a
good idea.

           Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwgd-Wcp0GpYaQnU7S9ci%2BFvFmaNw1gm75mzf0ZWdNLxvw%40mail.gmail.com.
