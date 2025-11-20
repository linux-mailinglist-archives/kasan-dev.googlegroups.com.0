Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBJ5Y7XEAMGQEZLSUZ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 67E1CC75E76
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 19:21:29 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4775e00b16fsf8610635e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 10:21:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763662889; cv=pass;
        d=google.com; s=arc-20240605;
        b=DHaTBoz++Sg6wVu+j+8oEWzfcDI0bqdcSC79V7Ye+KGaHXjzJ9hc4xFPsSW2UcvM+h
         +1VyKMacDtsjKA7K1rzPlztVa5v4DLepkcnn3Z1Pr1ZABziuu+DL42rQ8TB4X5hCmhJf
         2I3L+sMXohhT7ErhvoqEi47/LDV1i04z93of44rJ3L8ztAlfjPVOH2+mkDxWn9Ap9/bx
         Ntxs0ZmFQUiUF2sJ/jyuClvhKjg71enG/6zNJHhce85PGMQofFgQp0fgh02bJkmJE3xt
         qt0HrMIvQfPik0VMSWETn3hJkwpIXUDAHguUDC368vhtAQrdSKEN7QBVF6ThBLHTXT4E
         My/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=3FoaQ0OqsA+vCTGEnzswC8P6yM8NlfDB6wRrk9lcbKw=;
        fh=0OxBWDYe9yx7zeJpa5i8ePA/gyHKY+kvrBexZNhvCAs=;
        b=IQPOxmYR+0GO7awsx8UWze5Tse1VhppyNxUAw0et/b5lqb/ByyK8L7fd7Cl0LkxwA8
         cf+ic9+vloJGV9A9QPdAGzBPPDOaIp7WtZJSfCQMgWJM/wTxKaXM4dyeKHhdX3dQez2J
         Sz7iWOLhIYjFxK25U/8jsFuNlIqLbcf6/0Tox2TECan8tRWyuH13oJ+nMfWkaYA1Wivy
         lcGfagQyB465y8c6vIvNhfXfYiXLI2Kstoo2AUa9rzRIpLlAFEdp9rIT6VUATcVGY4B9
         suHtgViOkdsrXXvJKRx2MgZqPdFslPheSpwZFYdZPejlqkDhgbos6nOVWESbMC7l7/2a
         hsyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="gcWj/4qT";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763662889; x=1764267689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3FoaQ0OqsA+vCTGEnzswC8P6yM8NlfDB6wRrk9lcbKw=;
        b=fGvZYQAbjk483Ttz7Mpn9ZYgz31DsF7CS7CfN/mVkbwtWLz4laVwW4UUwXnSe/G4fa
         auvB3wh7QSp0sqFgo9BEaILlUSR4AxASWXbeABoWniEpbS9pEbe4ryVpwsh/RnXmopBP
         2XIQGoixBSkoobhPwFWYZaRLkMSwHiyIVMaLti7cxNNCWGRjhoLXAFdDYM7Jw1Tu1Tkm
         hPyYn+S61xYjMwrZXj+H6EJcb5zqlnqmcUjhGUCttL9mPI7AAQO95X6eIy8HzV5nW9S+
         d3sV1b/XzfoF3J0JCsxqhPTGFsY8R6FDX6SCTJECVKjE2MMuJVDKrGt3tVM46vSGFsM1
         Dvrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763662889; x=1764267689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3FoaQ0OqsA+vCTGEnzswC8P6yM8NlfDB6wRrk9lcbKw=;
        b=RqjpTYLM2gcXRuDInKvvRGZGoJMFUpp3XQb6EsUcT2Um4CxVO6j/qmIkzjGwf2kLUd
         tcKgYdcFHEG/UoI2Dd8Z9+eI3oA+L2WBJMqEe7YHAhNoG64kVQyPHAq9T8jRkcHKrGRT
         xj0YMP/V9U9VgiYTk2m9b9LPliV6csrxY2vGgh4S+XuHWv+pjtqhBQQOwfPKnPab4Rn2
         I8RJj8Yfaf/vpvzzM+bz7XM8MqUpECqBJtf2Tr54y6u4kLcN37V4KiSMrOtjp+PIHPT8
         CiLx3A1NXmixphqvtlvqoaHwxEiHEiK6uZYqrCdqqUSTXapB+X6o9rR4PWqksWTowAEr
         d6cg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4HxDmebgH96fLWLruXJaKx1FwbXYYQQfbHqjOrKHejkZytZs3otwxvvBf1B2lofrgLbLpLw==@lfdr.de
X-Gm-Message-State: AOJu0YyRF8+uxMLiwK3WWrDyax4xCAKhCrniNn2Nnpgl0FeQGRxVCbJD
	UXKdb+nvAfK0Z8E1x5IW2EsF1EjkcqTK2OsyhhDxW2PR6hUhnG7I8Yxt
X-Google-Smtp-Source: AGHT+IHF88pSbnsscjlD9cWAuNlspy5hXF7fMjPmOKxjm7tTVP4tjSHO1mtkKKRwB/kJtFa8+rk4CQ==
X-Received: by 2002:a05:600c:1f86:b0:477:73e9:dc17 with SMTP id 5b1f17b1804b1-477b8c935d2mr48011255e9.35.1763662888471;
        Thu, 20 Nov 2025 10:21:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+blKI6fVI3rfdeWAVuvo+hXtciAul93++3WDuQnzzMPNw=="
Received: by 2002:a5d:5f93:0:b0:3e7:5e78:598 with SMTP id ffacd0b85a97d-42cb8239d1bls827241f8f.2.-pod-prod-08-eu;
 Thu, 20 Nov 2025 10:21:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUpuWwJQJDzBjr3hkBeuXqOjH2tfqLK8TJB5Wx+MHNghfRjhUATyfFx5532wN7iTOKfi7u7i94R5GQ=@googlegroups.com
X-Received: by 2002:a05:600c:4e8e:b0:477:7ab8:aba with SMTP id 5b1f17b1804b1-477b8579d24mr36842135e9.1.1763662885390;
        Thu, 20 Nov 2025 10:21:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763662885; cv=none;
        d=google.com; s=arc-20240605;
        b=XGKR1B+oO0af2JiOaREwzbV6QBFIsSi1NvUEC5JyT7Zni3dKGIL+TemSmnNKPk5ubG
         4Wy9YVJgcdyy90jZzDgAXs+/JW0XXyRV+u7B9Vk6gENnNgo/bEPyTzix5sI20u3+6vSV
         dyjbJjDypKWkC1avtpdWqvELcAIU6566oPrVDP5KuWfMOx/Ul2a/1YXgWlqDf25eVeYf
         015Ok/osy+e0D4rmjrPE7bHvpPhkRQzLsO1MGj4vtgCDXuIV9twA/lAR5ygD/7cMowd9
         F1fJ7aSMe0niQjPRJU9z+42pJ69QTLN0x4Yz6+QFkiabKaGVsN5SOoDwCgMMVFLfvyCy
         FxFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+BPfdnrOHpw/8tC+sL0oorkp9gKYtrunKdRWYzTn+GA=;
        fh=ZE70MaobYAxvNg475xoj2aDJramfo1Kf/UGaUhrZuD4=;
        b=Pl9ikEo/zZ5rcHpu4XXFgtAvYVLkvUvECMLYMn/Bn5z7AhKFrL60PkAB/8oM0GL62z
         8zkab3nXo+3PdU4PUEzfhxuzZqxv6h18aax9/aiV7AZ6toLpe0Ev+4H3dClxojsk51jG
         PErY0XXy18U0oeVg4GDvJ3IZFP5DCYvHGPv8+Xh2W7cIgGBRy0ittJeOvQmn5cJK3yHr
         9fI29ESmDhaZt7y4IlHfSoaqm0cmVGToF8NQDyqssFAB+3o8ZGKTDiXxqxULS7L5hs9L
         6/Lm6cF+bbbYevUuRpCXCf4SmPwYe7uf8aKR11Yq8ysRW4lYxW8addpKH3qzjEW1EiIG
         JeuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="gcWj/4qT";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-477bf19b404si14985e9.0.2025.11.20.10.21.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 10:21:25 -0800 (PST)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-5958931c9c7so1336133e87.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 10:21:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWULDlQ/09jYNMoje9UmT2KX8DK7sU8jByDTxSd91By24Tsx5Qy38G1G/EUAqmwOH8sG8G1Fr8qch0=@googlegroups.com
X-Gm-Gg: ASbGncsmo9WfHoUDJEUQkQKP8wosST2y45lZhO0I+FQgP1K2HsyvSxCs79pTx8zFN3q
	9FZtke0tNtpKav7H1xi+StkL3BWapU9ifuaJdC7bHCWx7VakP2ZmhcGybDBOq30BYpN4papctoM
	eTsRJDuHSYwzxLvJoBcHRRjba4xe+nXrAJVuT/bbp4RIQtOMvvtNht7v+I7eaR3wR7q6yN+kQ4i
	S6CJw/IgFjL81E703F1Nkk4EKDBjQQIKNfYz/Y6qlQhVynVB5j4HVd48Btjre2vgwGpaw95WAkl
	FdzRYK70xsFDfRlMQw9CIxbvRO9WmLSMT1GeISvtYwx9DB/hg1IidyB7PyvIuFpuYlqeDafchv+
	kWRrh6YhAzYBx9BG4B3MacEt5yN3P+Uhl7ElbgF3rp4Jw347N0VIyWZFPPd84GieyzikfBhDS4+
	QjtpcAx5Gl6PguN95wP47H9BdUtbxGA+/aUYmOJgMgQNtSVq7rTBN19qXwsyOfMraeqZn5dM8=
X-Received: by 2002:a05:6512:3c86:b0:594:5620:c5ff with SMTP id 2adb3069b0e04-5969e2ae9bemr1488173e87.2.1763662884302;
        Thu, 20 Nov 2025 10:21:24 -0800 (PST)
Received: from mail-lf1-f52.google.com (mail-lf1-f52.google.com. [209.85.167.52])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5969db89319sm893181e87.36.2025.11.20.10.21.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 10:21:23 -0800 (PST)
Received: by mail-lf1-f52.google.com with SMTP id 2adb3069b0e04-59428d2d975so1363828e87.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 10:21:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVS0RwOY1+0MUbBkUJqZC+oQMYcqtN5iOUI+sXrQ456GxANnUYXiiJqWofw4bKhe/FYVhhaxzvCb7U=@googlegroups.com
X-Received: by 2002:a17:907:7f0a:b0:b70:b71a:a5ae with SMTP id
 a640c23a62f3a-b7654fe9b97mr482177966b.44.1763662490181; Thu, 20 Nov 2025
 10:14:50 -0800 (PST)
MIME-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120145835.3833031-4-elver@google.com>
In-Reply-To: <20251120145835.3833031-4-elver@google.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 20 Nov 2025 10:14:34 -0800
X-Gmail-Original-Message-ID: <CAHk-=whyKteNtcLON-gScv6tu8ssvKWdNw-k371ufDrjOv374g@mail.gmail.com>
X-Gm-Features: AWmQ_bk-my8wSL6P8yRhTUREdDraem8VrQQmjD7uS2S9oN6T2mRX46ftlS1ytQU
Message-ID: <CAHk-=whyKteNtcLON-gScv6tu8ssvKWdNw-k371ufDrjOv374g@mail.gmail.com>
Subject: Re: [PATCH v4 02/35] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
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
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b="gcWj/4qT";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
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

On Thu, 20 Nov 2025 at 07:13, Marco Elver <elver@google.com> wrote:
>
> --- a/include/linux/compiler-context-analysis.h
> +++ b/include/linux/compiler-context-analysis.h
> @@ -6,27 +6,465 @@
>  #ifndef _LINUX_COMPILER_CONTEXT_ANALYSIS_H
>  #define _LINUX_COMPILER_CONTEXT_ANALYSIS_H
>
> +#if defined(WARN_CONTEXT_ANALYSIS)

Note the 400+ added lines to this header...

And then note how the header gets used:

> +++ b/scripts/Makefile.context-analysis
> @@ -0,0 +1,7 @@
> +# SPDX-License-Identifier: GPL-2.0
> +
> +context-analysis-cflags := -DWARN_CONTEXT_ANALYSIS             \
> +       -fexperimental-late-parse-attributes -Wthread-safety    \
> +       -Wthread-safety-pointer -Wthread-safety-beta
> +
> +export CFLAGS_CONTEXT_ANALYSIS := $(context-analysis-cflags)

Please let's *not* do it this way, where the header contents basically
get enabled or not based on a compiler flag, but then everybody
includes this 400+ line file whether they need it or not.

Can we please just make the header file *itself* not have any
conditionals, and what happens is that the header file is included (or
not) using a pattern something like

   -include $(srctree)/include/linux/$(context-analysis-header)

instead.

IOW, we'd have three different header files entirely: the "no context
analysis", the "sparse" and the "clang context analysis" header, and
instead of having a "-DWARN_CONTEXT_ANALYSIS" define, we'd just
include the appropriate header automatically.

We already use that "-include" pattern for <linux/kconfig.h> and
<linux/compiler-version.h>. It's probably what we should have done for
<linux/compiler.h> and friends too.

The reason I react to things like this is that I've actually seen just
the parsing of header files being a surprisingly big cost in build
times. People think that optimizations are expensive, and yes, some of
them really are, but when a lot of the code we parse is never actually
*used*, but just hangs out in header files that gets included by
everybody, the parsing overhead tends to be noticeable. There's a
reason why most C compilers end up integrating the C pre-processor: it
avoids parsing and tokenizing things multiple times.

The other reason is that I often use "git grep" for looking up
definitions of things, and when there are multiple definitions of the
same thing, I actually find it much more informative when they are in
two different files than when I see two different definitions (or
declarations) in the same file and then I have to go look at what the
#ifdef condition is. In contrast, when it's something where there are
per-architecture definitions, you *see* that, because the grep results
come from different header files.

I dunno. This is not a huge deal, but I do think that it would seem to
be much simpler and more straightforward to treat this as a kind of "N
different baseline header files" than as "include this one header file
in everything, and then we'll have #ifdef's for the configuration".

Particularly when that config is not even a global config, but a per-file one.

Hmm? Maybe there's some reason why this suggestion is very
inconvenient, but please at least consider it.

              Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhyKteNtcLON-gScv6tu8ssvKWdNw-k371ufDrjOv374g%40mail.gmail.com.
