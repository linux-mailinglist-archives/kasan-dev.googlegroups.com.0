Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVN243EQMGQEPBO25TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D4B12CB371F
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 17:18:30 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-5943ca95853sf3730551e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 08:18:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765383510; cv=pass;
        d=google.com; s=arc-20240605;
        b=RTFevTv9zz6i3I8EkWazwbQ40ra4T14hh8zeJVR5FFW2HUQqxDAHdJUiMk2Cs7AS3J
         2qpy/NjIHFThhGKMAkPGdacKz+cQor4QAISGPZIfcZykaneaPbylIqooAWhszx/qaesm
         m5oV1o6Tn1VTW4dqlRtZKa4wVal+D/uXGOzTnKwvBhIrWfD5TMD2BQGbqE5+9s+iT6sC
         O/2AxZmpv27CE50i01QGHbcPTsK0WxXOIw9zLmKeNb2oiZxTb+76WP3ZczcDJt0R013C
         ITSfPoI9ep725N5SZn+rj3uvhvMVoUmtXaQz7BqtHaxoB5DF61HCdksxGYGA2A8Ha8OF
         A4Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=V0a3eLnnXwCtBXeMOf0kTWcTAwqY2U7r7XvJTl281P0=;
        fh=rZufN1+65uRXaFq66Mw8PS9imijQCsmkN6GzfKKJ1zQ=;
        b=Ud3Ll9zEhQHPc8eA2XzMoQuYvuQ+fazw6Hw61OYEhk4Fri03siDo7RdOd3tqkEXbkn
         YlXjiaSKBKyB+NisrgYUv624MbvboZvLJgkzxcbr4Ucii6l3FPb1nYQFmi1500vRkWGu
         +06thEGnPco+duzyikETiwUPpn9h7KdyX3aYm2pOoaJRkoc+eL+A1J6ZNCSRbedXBxyL
         iCedmYD8YPHGSM3Wkw14ULRxoZ2sSK3zLaq3MeBy1eSlOzSpY2OGXeBcffpV98zX3fty
         BUn+sv5MtdGRahV/QbHLHt7cFNKa3uFm1Q/m7LjtEgOnb7yOsstqP7nqc5qrxt9/BjGD
         Gm3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IjH6jY27;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765383510; x=1765988310; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=V0a3eLnnXwCtBXeMOf0kTWcTAwqY2U7r7XvJTl281P0=;
        b=d3vYb4ohN5Qgh6+wVZwjT6Hndbq59UpA5kVFk7po0rJAS3qQEZGNV2/3QY7HWu7LKl
         CmcQaZua0VtIdNaGG8mTlnV+jGNObDScupx4IyM47ceVIuNDNcAaQg6toTO2n5YQgnGU
         nkOMxlBMm7MciqtIxFMNYXw30hHMQWUMlnDGaZcycrkiRszcBXe7CC4bQ480ZgJF6yID
         3XDq9BomvEr1C0AHuFZwXKHFvUGT9HDLrT3fntWQCrazsD2FlX55oaHu+A+kvrF3rtvd
         gsmSVY2GY8LF38sqc6Tj7A3CtzSLNc/elSXgR82eEj4hnhGm5RKXARSDZRq6t1GtaKTp
         DXVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765383510; x=1765988310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=V0a3eLnnXwCtBXeMOf0kTWcTAwqY2U7r7XvJTl281P0=;
        b=Ba+YFoBYWu5g0K7XZ3TZJDWoUYaTllLSoe2Z+BkUp2ls67c5hJwh6Sd/YeyR6q3k4H
         /3YhOrtR+6UaWl9kl79rx9vm4sp4qCbU7eoWXnximFzXJMiEXVA+gIwTPb3fK7DSK6uQ
         3IN/QW2319HfE7PuiFcqJH9UFNDTr1MVOpiYvuwx4gBF58jCvsw5qjpMTys+xISzrKSn
         nQwIyzu1eEZEnjGhjU6Ju0xFvqTwPb4n2rkRTEBIIsHc+jNqGDBtWCMH65QCni+JAXwV
         0d7VuZIAS7PYL5E+anOQwV0Jd2M0prySpyY+aO/X6eCTrFZWMvz5X5oGNBmBBDRBBzoC
         gyww==
X-Forwarded-Encrypted: i=2; AJvYcCUw9QiUEEDWkzjKAyIgDvNJqFg81PBIMbKG67Af2PvfJYgXPDnYnXsl6/Tfcnk4OgT1xWZ83Q==@lfdr.de
X-Gm-Message-State: AOJu0Yxwv2sFldXzGhUJOsdbnFcmvNG70YITizdNzIfXBH9N/0CoeZPs
	j6NWXiMch7wGJqtd/Vt0w7SbPJL7DpJwTM1p/Lw1qLJkD0VRl33ukbME
X-Google-Smtp-Source: AGHT+IFcJozOYpbNESRJUfgWwpZtScLHKKVcENw1fdgwdeyNfm3BvsIOgaaFUN66jsnzHQiG/dq8LA==
X-Received: by 2002:a05:6512:154a:b0:598:ee5e:d8bf with SMTP id 2adb3069b0e04-598ee5eda11mr953354e87.15.1765383509678;
        Wed, 10 Dec 2025 08:18:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYgnDABcNbOX4RoyM8jI/yXdaxRuEtjn5v+8Cdgq33Jow=="
Received: by 2002:ac2:51cd:0:b0:598:f0c2:671b with SMTP id 2adb3069b0e04-598f0c26769ls173113e87.2.-pod-prod-05-eu;
 Wed, 10 Dec 2025 08:18:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV33kAUwWMRfM/XOEyiQLKRP08pafpDiO/d4KdZEhu/0fsS+KLTBH9fngQLuWxQ9ibWPGgsloshFDY=@googlegroups.com
X-Received: by 2002:a05:6512:3b06:b0:598:e94c:1a83 with SMTP id 2adb3069b0e04-598ee4b905dmr1191787e87.24.1765383506533;
        Wed, 10 Dec 2025 08:18:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765383506; cv=none;
        d=google.com; s=arc-20240605;
        b=e5zVt7UYG5dwQuQJ0ia13julPAoSWgAx93zAyBHlkmLUb+8fFJmZvI4KnbiD/Wuzv2
         aQRZ577KDQ6kqi92+412+OefWzoyqwcm6izPaUk82FUT00KEN1k8W4Q6wJwB8o8nyvxm
         Ubl3lCqH96i8ci4I8WWopzatmpo1YiaK45qa8MNmxSqdj9/SXFY7jElhGlBPR87odE6S
         6Q+HwBA3mfjUBRTP2YsF2DuU3aBYwukAfjwU1CuP9Ow5godWJgTrcvCRw5IhbvxkxVpc
         hqkbdEwGTnBhiOaBih6T/0fWhM3t9S3fhQzTk02gqM86AwGeoeVprCaZlZZBP8hHsL4q
         /XGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5R7EEgKhSIj0MssK61oG5hvlzLQojw/c9iQ7wtMJnfU=;
        fh=FzeUQxW9gSPiJ7+t4w05jqJmqfhh7iTo2Uf/fTwpZww=;
        b=fdVDbvWdcCETaVKQzOE4uN0yuY+suKcLzn3/L3YP8MAxZmP0nch/+YqrfxxV3vUw8G
         g1i5HgdZNZwXeOQidBKn+5qDYrw51bdEx2/RAFfUBfVs0NzXB9pBq79PAmHQFxWT9BfO
         cjMMkxgpVP3TdafRhtYWpAuyJVl+AlgtzNMgbjMJQ/5w18Wo54rFHg3d0/V69WE306p0
         3O0OMG1KMhewSO+KRg3hGKJajP6IYDFhgf6YK0P0+ZNYKEl1DiZt7XIpzpAhzVyNgPtz
         zOJ2vYwD3jkIoW8Pers5ey+//HLPbwFj/31eHCXc/ekhWgPNIhDKojfciqAje1MUzhps
         HXKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IjH6jY27;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-597d7bf8fe1si382573e87.7.2025.12.10.08.18.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Dec 2025 08:18:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4775ae77516so85508205e9.1
        for <kasan-dev@googlegroups.com>; Wed, 10 Dec 2025 08:18:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUul8/srYHIRhadtDSpv5hnfYHtjpkx+CrATzULhG8wowQWZBoP58ykl4Rc08YbbsziuYNFry/67Pw=@googlegroups.com
X-Gm-Gg: ASbGncv33hIMXc9fWbb5mstSHnGjUAd8gcTHBLS397aBhL4MJ7bRPb+Qo3PtH4CoxMN
	l57OS95kvSPk2h5RqKrhhqr9AjHExmJAZjrCQLHgbMgjSVogfekxUmNrhcfwYfZePtDxni1a/+L
	C4kGgV3Y2n91pQvF3wjR49HdNevVmM4WUpIa+hrefiH6V0XsvERCGj9WU+rMXEOVqEuQCI1GO6X
	IaP4svnjnxPv1MsOBfrwXi1iegTQ/9SgczDNultEQZkh/2E2ZbeuZ//HM6S53cC8cqiPe44V19m
	Qn1nNK7kY/qhLJYmNwFjRjc7vXYu8GOWhONg0KKuuM2sAYlWm0xjoi86kwNRkmMy+VXYiwWLiHC
	EBfmP03dFLjAVCyq5DeZYps97qYFlCLJyftrlzRmdQyoWd5rHI/mVescgu8DuGrwSntX84lpxq+
	3Hk6OUzJQ8fZxx8s1M9vIVk4ThkcaOVTO1grmF4IAvej8qqiE=
X-Received: by 2002:a05:600c:687:b0:46e:59bd:f7d3 with SMTP id 5b1f17b1804b1-47a83cc5528mr15763325e9.20.1765383505415;
        Wed, 10 Dec 2025 08:18:25 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:edfc:ec3:194e:c3b3])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-47a7d3a75a3sm45109085e9.6.2025.12.10.08.18.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 08:18:24 -0800 (PST)
Date: Wed, 10 Dec 2025 17:18:16 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	Linus Torvalds <torvalds@linux-foundation.org>
Cc: "David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v4 00/35] Compiler-Based Context- and Locking-Analysis
Message-ID: <aTmdSMuP0LUAdfO_@elver.google.com>
References: <20251120145835.3833031-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120145835.3833031-2-elver@google.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IjH6jY27;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

All,

On Thu, Nov 20, 2025 at 03:49PM +0100, Marco Elver wrote:
> Context Analysis is a language extension, which enables statically
> checking that required contexts are active (or inactive) by acquiring
> and releasing user-definable "context guards". An obvious application is
> lock-safety checking for the kernel's various synchronization primitives
> (each of which represents a "context guard"), and checking that locking
> rules are not violated.
[...] 
> A Clang version that supports `-Wthread-safety-pointer` and the new
> alias-analysis of context-guard pointers is required (from this version
> onwards):
> 
> 	https://github.com/llvm/llvm-project/commit/7ccb5c08f0685d4787f12c3224a72f0650c5865e
> 
> The minimum required release version will be Clang 22.
> 
> This series is also available at this Git tree:
> 
> 	https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=ctx-analysis/dev
[...] 

I realize that I sent this series at the end of the last release cycle,
and now we're in the merge window, along with LPC going on -- so it
wasn't the best timing (however, it might be something to discuss at
LPC, too :-) .. I'm attending virtually, however :-/).

How to proceed?

I'll be preparing a rebased and retested version of all this when
v6.19-rc1 is out. One outstanding recommendation from Linus was to
investigate compile-times, but as-is, it's unclear there's any notable
overhead per brief investigation: https://lore.kernel.org/all/aR-plHrWDMqRRlcI@elver.google.com/

From what I can tell most of this has to go through the locking tree,
given the potential for conflict there. However, it is possible to split
this up as follows:

Batch 1:

>   compiler_types: Move lock checking attributes to
>     compiler-context-analysis.h
>   compiler-context-analysis: Add infrastructure for Context Analysis
>     with Clang
>   compiler-context-analysis: Add test stub
>   Documentation: Add documentation for Compiler-Based Context Analysis
>   checkpatch: Warn about context_unsafe() without comment
>   cleanup: Basic compatibility with context analysis
>   lockdep: Annotate lockdep assertions for context analysis
>   locking/rwlock, spinlock: Support Clang's context analysis
>   compiler-context-analysis: Change __cond_acquires to take return value
>   locking/mutex: Support Clang's context analysis
>   locking/seqlock: Support Clang's context analysis
>   bit_spinlock: Include missing <asm/processor.h>
>   bit_spinlock: Support Clang's context analysis
>   rcu: Support Clang's context analysis
>   srcu: Support Clang's context analysis
>   kref: Add context-analysis annotations
>   locking/rwsem: Support Clang's context analysis
>   locking/local_lock: Include missing headers
>   locking/local_lock: Support Clang's context analysis
>   locking/ww_mutex: Support Clang's context analysis
>   debugfs: Make debugfs_cancellation a context guard struct
>   compiler-context-analysis: Remove Sparse support
>   compiler-context-analysis: Remove __cond_lock() function-like helper
>   compiler-context-analysis: Introduce header suppressions
>   compiler: Let data_race() imply disabled context analysis
>   MAINTAINERS: Add entry for Context Analysis

Batch 2: Everything below this can wait for the initial support in
mainline, at which point subsystem maintainers can pick them up if
deemed appropriate.

>   kfence: Enable context analysis
>   kcov: Enable context analysis
>   kcsan: Enable context analysis
>   stackdepot: Enable context analysis
>   rhashtable: Enable context analysis
>   printk: Move locking annotation to printk.c
>   security/tomoyo: Enable context analysis
>   crypto: Enable context analysis
>   sched: Enable context analysis for core.c and fair.c

Thanks,
	-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aTmdSMuP0LUAdfO_%40elver.google.com.
