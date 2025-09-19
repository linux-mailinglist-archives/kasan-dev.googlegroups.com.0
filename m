Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD54WTDAMGQE3R2FZCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 5812BB88848
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 11:10:41 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-62d9be22f6bsf3168541a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 02:10:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758273041; cv=pass;
        d=google.com; s=arc-20240605;
        b=ReWwj72iI+AdpxCVw93BxkK8L8jeRH7L4lZXrXy1F7C+Wrfnsf1DV+DaDTuidAqyTC
         SfHQ/B6/w4+NHrudl7lR6yb8P6d3f+xqpXuVFboTzUXWdZj9aLDx1PYVnBQ9fozd/z0a
         ITiuV/+L3MSjKwQXY34i5CANa4k2o1ciIQcr3lhHsgFhRWjpSuqeAOC4j3C7g8u9fFoe
         zofCfwSlOggD3/ws0X0z5X3sQ0o0kvez8LcQuAmf4UJsPZZdLY8s2GZtbSQ2qwpVDH94
         RtfEmq3xzEicpVwXuxBaO+fy3S6MuDvwLY10NwpMs+1eqYvv5a9yDq/cXcDEc7SXNvte
         ic3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=mNt0ecUHoerOX6s31XhlgownBzxHIOpA5lJ+JOvZB1Q=;
        fh=BAMUqiestlaMfkMwahmNj8X5PFIb6L2lPS03JRg3U5g=;
        b=XIgWu/PDc58D40puVBi1h3BqPfEqp5+OK/FFY1ZPGynnQiq34yNUrkpm7F5EPXpd95
         yxLyFuRQenioL8ogeV/dvLVjHNd8IvL47GQwmCJzEjJ7dWVnhTCJ8TKe0DWENQYEB8n4
         FWYfMZCCT/JbyrPtBr++Da8w5mV1os6+8vX2QZjpFHE4mLNhTcdNuxzxP/mTxC4Dawf7
         fSp5uROk9bShWyfWN1s7IZsw4WB7KgDCWipfPuPk+eQTVTrwkwImOunsqs1qRwGK4crK
         mZLuPDYotd42LUl8d2T72UcKtvugRlaiYmAjTSchzi8zvwgm9c9rgzP3ilSIZUVjwT0i
         QiFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B3tsJ+uU;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758273041; x=1758877841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=mNt0ecUHoerOX6s31XhlgownBzxHIOpA5lJ+JOvZB1Q=;
        b=DMQ9uKfFOgKG3prJ5CfnxYlFphiQvAEzrLyqDHVNyBVfi+9Qz7hxCCzgLZyqgfR5Kj
         4TH6AFpMaC9+kws0R2zDRXK5FLOCshdVq5+KjyHhbSSPp6etV27zdA9YcfC5CDncZCGN
         5eHqDauzPkga9qK0SvDPZ1pvpAqtV5ijJszrjwjM5Lufh/3iHKi+VBbkuZQ2QU4wa9bm
         pO28PSBVYrIuxkvrH/WNxESbSvIZHPPlLSrTDNi2rJpd7q18LiCWTqYjhLDyP4ORByQN
         WfIGIk+B/GOOMCFAI/ytS/Hsl+EaD+dARo5MO8oIaxHZIxHe7Sa4hJanFZoU6L60LGm9
         /Ahw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758273041; x=1758877841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mNt0ecUHoerOX6s31XhlgownBzxHIOpA5lJ+JOvZB1Q=;
        b=G9hCAYvc1MGPs/mgFCRZFdsSvreMqUEE2kcqmlXXkEb2RwHvSz7J2cbfEx7U5DY9UT
         0G7QrhXR/KbR88teWBSo2gbtFSgDIBcCpm3cy+yuRXA327x7zhLps18GnSH2/ASocMHH
         SpmnZW1o5PaLY8I8zoU6YirTT5VebTgdJ7iIjAVH//NsHt3m+t8gNd/ciif+A5G+BBaP
         hA9094FM9RXz8oK7yRTfQBDE9rsUylmQNnG+geMJmS+FI2fXJ1CFqHo03ryIthaa2PXA
         eDurgvvWMK/jel7M2WQZ1y1ju0uRuckj3ibB7H6J6jwlrHNXjtrQaKgENMO9SHkVcw2I
         LgPA==
X-Forwarded-Encrypted: i=2; AJvYcCUrHo7x0ntZgBueHk5yGzddh2z1tewtHGmzDZSktdM2oK6UVEXDnvTsYojEiXjTJc1jJq+OnA==@lfdr.de
X-Gm-Message-State: AOJu0YzK+rC+eH5BN6CtOA24xVmICT1ipAbiYjxF2ktFR0DhB8LIoB1Z
	GBb1c12NhPQWTfnXnue0VZEheA5wogoSy2+t6oLmi+Ef5sOt7GSTv9oJ
X-Google-Smtp-Source: AGHT+IGkV+nK3aq8Xbh1OP5Va/lwI9IjiVS85ZgahtUAFemHnDTiqz75vWVutJUn8drEnWzpUeiRiw==
X-Received: by 2002:a05:6402:5345:10b0:62e:ebb4:e6e0 with SMTP id 4fb4d7f45d1cf-62fbe3af572mr2485126a12.1.1758273040453;
        Fri, 19 Sep 2025 02:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4OGbIeF9jtczidk3cugpICu7RjIu/VY3T2qgRc6whs0w==
Received: by 2002:a05:6402:52d0:b0:62a:bd63:ca1c with SMTP id
 4fb4d7f45d1cf-62f7c2bf9fels2122175a12.0.-pod-prod-00-eu-canary; Fri, 19 Sep
 2025 02:10:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlXrI01RaD83OUGGeDtU3pWxXn5JPy/M4OUaUYFM/mC2sMSeZbY75r7FKLMYywypfejkoUv3U7YXM=@googlegroups.com
X-Received: by 2002:a17:907:7282:b0:b04:5bb5:2745 with SMTP id a640c23a62f3a-b248e106186mr306239766b.21.1758273037169;
        Fri, 19 Sep 2025 02:10:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758273037; cv=none;
        d=google.com; s=arc-20240605;
        b=NGKvKWlZ4GTlh/ZrmpZKMqV2ox7icRjRhNpliqi7ijXiJ5ooEpNPo/S9TSzqTTbP4F
         j1ETfnI8GntxcbWXB0WV9jCmmU6BwoyNOw7cstHB9Yp0Krkc06zk7Zt/+1U5P9TxcKI1
         ZTl082BwQMndpdWhxPj0E0vgs8w/c0VcMhVJItK4Q45PDsB/0r6Cm5IcuoR0rMKRMScL
         QDLQU2vYq1+kO23GkvM+0zyjjZj1Tu5QbdmoMMhBnVN93peFXSk5XomxjmbSoddAYxmo
         PezwTi2MZQ5Bfa6X8AazRFF36zSRHF67zfVCHbLG/4i48CgYv+bjNYonkuJqP7yDvbot
         vHEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=MJe0rinuelKehm5wGFfSGZORMGN5FYJoAjzxuVuk9B0=;
        fh=qcAcLekTXoLqZ5nQRqzMJ/vmP+io/fyxXNOPztbS+io=;
        b=aqEJ0bJLP4tuMQNAGRCcud/rVoMFKj5pxCDlfHNxRuimlxD5NRcgpggJVZ0fN4vPlZ
         kAtdWhmjLWiSLaV69CkEURlyjygs3XHB5NyO4D+yLO2RddNFk/yIJKUzwLuGbdmvFfxw
         ksS0iliKJQsHgGg6wonWLSEQRqvdL8+KBSgEfedBzFf2J+EEXu43zt6Mx93KJvrvqN+q
         f3rDyvmybE0B7x6B7RxUB7U3FvaeU/lT3jD2XbDpdrmn0i1ukgzT9RzDvIP0291KsJND
         HOA8ph0c6LgJ15cv45GY3MwOsf/PfvAJ610QLVpQlBLeiIbZCGPAbVNrCz7ddi3YkTxD
         AtPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=B3tsJ+uU;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b1fbae9a29asi8206266b.0.2025.09.19.02.10.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 02:10:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-3d118d8fa91so746373f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 02:10:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV1j9oY5NVEc46k5BiiOpXL0F4eWeGcy1rrade765nSTzhhKloC7KL0/YafkiaRRP+JSfgd6Q5ti+4=@googlegroups.com
X-Gm-Gg: ASbGncuXnPTqSsJyTo5Ata/oo+pZi56UwZsbh2sP48NeVdJmkWURO+UvP6JU50qUFif
	ULTT8E7XZU5nkNSrAatW2LAEIUq7MgoQG45br1Gug6bftMpFqB+cnK72NG6XHxVxRuZPp7jCmI+
	TTCidMeT27NmehND2CXKAlO8cvf2iTjMKqxYp1h0OYzbLSXy2AYw5ehZ+kLkKkrYsU9N2d+OjJk
	avVeBqMO42WVcIj8aDWyBQp0AB/ho2yGvaBDhtGqLvhxWtaKdIbnuQ6eKPWVh3Xoh2SCNOy6m3U
	fVG+UsB2CEMlcEX7UXUiIYppmj4RBavQNwgsuXoHhyuSOVC5vmCNoU5sVoiw2dQ6eF6966XymFJ
	JugPxEytZioVJPQnGizW7ux1rhYuQnk+JO4GkcCdiWMwPnv5vqR4VL82DPB0=
X-Received: by 2002:adf:a3cd:0:b0:3ee:11d1:2a1e with SMTP id ffacd0b85a97d-3ee11d13550mr3322664f8f.10.1758273035792;
        Fri, 19 Sep 2025 02:10:35 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:2834:9:e4bd:a156:d1f2:9919])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee074106f4sm6935798f8f.25.2025.09.19.02.10.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 02:10:34 -0700 (PDT)
Date: Fri, 19 Sep 2025 11:10:26 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
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
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
Message-ID: <aM0eAk12fWsr9ZnV@elver.google.com>
References: <20250918140451.1289454-1-elver@google.com>
 <CAHk-=wgd-Wcp0GpYaQnU7S9ci+FvFmaNw1gm75mzf0ZWdNLxvw@mail.gmail.com>
 <aMx4-B_WAtX2aiKx@elver.google.com>
 <CAHk-=wgQO7c0zc8_VwaVSzG3fEVFFcjWzVBKM4jYjv8UiD2dkg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wgQO7c0zc8_VwaVSzG3fEVFFcjWzVBKM4jYjv8UiD2dkg@mail.gmail.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=B3tsJ+uU;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::432 as
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

On Thu, Sep 18, 2025 at 02:47PM -0700, Linus Torvalds wrote:
[...] 
> But I don't mind your "Context guard" notion either. I'm not loving
> it, but it's not offensive to me either.
> 
> Then the language would be feel fairly straightforward,
> 
> Eg:
> 
> > +Context analysis is a way to specify permissibility of operations to depend on
> > +contexts being held (or not held).
> 
> That "contexts being held" sounds odd, but talking about "context
> markers", or "context tokens" would seem natural.
> 
> An alternative would be to not talk about markers / tokens / guards at
> all, but simply about a context being *active*.

That works for high-level descriptions, but we need something for the
API, too, which specifically operates and refers to the objects which
are acquired/released to enter/exit a context.

> IOW, instead of wording it like this:
> 
> > +The set of contexts that are actually held by a given thread at a given point
> > +in program execution is a run-time concept.
> 
> that talks about "being held", you could just state it in the sense of
> the "set of contexts being active", and that immediately reads fairly
> naturally, doesn't it?
> 
> Because a context is a *state* you are in, it's not something you hold on to.
> 
> The tokens - or whatever - would be only some internal implementation
> detail of how the compiler keeps track of which state is active, not
> the conceptual idea itself.
> 
> So you name states, and you have functions to mark those context
> states as being entered or exited, but you don't really even have to
> talk about "holding" anything.

It's a tough one -- because fundamentally we operate on objects, which
when acquired/released we enter/exit some context. I tried to balance
not venturing off too far from common terminology, while keeping it
general enough to allow eventual uses for "IRQ enable/disable", "preempt
enable/disable", or anything else where we might need to enter/exit some
context to access a resource (incl. perhaps Ian's suggestion of figuring
out if we can design a refcount_t API that uses context tracking).

I went with "context guard" to refer to the objects themselves, as that
doesn't look too odd. It does match the concept of "guard" in
<linux/cleanup.h>.

See second attempt below.

Preferences?

Thanks,
-- Marco

------ >8 ------

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 3456132261c6..87125ec2db11 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -1,81 +1,80 @@
 .. SPDX-License-Identifier: GPL-2.0
 .. Copyright (C) 2025, Google LLC.
 
-.. _capability-analysis:
+.. _context-analysis:
 
-Compiler-Based Capability Analysis
-==================================
+Compiler-Based Context Analysis
+===============================
 
-Capability analysis is a C language extension, which enables statically
-checking that user-definable "capabilities" are acquired and released where
-required. An obvious application is lock-safety checking for the kernel's
-various synchronization primitives (each of which represents a "capability"),
-and checking that locking rules are not violated.
+Context analysis is a C language extension, which enables statically checking
+that user-definable context guards are acquired and released where required. An
+obvious application is lock-safety checking for the kernel's various
+synchronization primitives (each of which represents a context guard), and
+checking that locking rules are not violated.
 
-The Clang compiler currently supports the full set of capability analysis
+The Clang compiler currently supports the full set of context analysis
 features. To enable for Clang, configure the kernel with::
 
-    CONFIG_WARN_CAPABILITY_ANALYSIS=y
+    CONFIG_WARN_CONTEXT_ANALYSIS=y
 
 The feature requires Clang 22 or later.
 
 The analysis is *opt-in by default*, and requires declaring which modules and
 subsystems should be analyzed in the respective `Makefile`::
 
-    CAPABILITY_ANALYSIS_mymodule.o := y
+    CONTEXT_ANALYSIS_mymodule.o := y
 
 Or for all translation units in the directory::
 
-    CAPABILITY_ANALYSIS := y
+    CONTEXT_ANALYSIS := y
 
 It is possible to enable the analysis tree-wide, however, which will result in
 numerous false positive warnings currently and is *not* generally recommended::
 
-    CONFIG_WARN_CAPABILITY_ANALYSIS_ALL=y
+    CONFIG_WARN_CONTEXT_ANALYSIS_ALL=y
 
 Programming Model
 -----------------
 
-The below describes the programming model around using capability-enabled
-types.
+The below describes the programming model around using context guard types.
 
 .. note::
-   Enabling capability analysis can be seen as enabling a dialect of Linux C with
-   a Capability System. Some valid patterns involving complex control-flow are
+   Enabling context analysis can be seen as enabling a dialect of Linux C with
+   a Context System. Some valid patterns involving complex control-flow are
    constrained (such as conditional acquisition and later conditional release
-   in the same function, or returning pointers to capabilities from functions.
+   in the same function).
 
-Capability analysis is a way to specify permissibility of operations to depend
-on capabilities being held (or not held). Typically we are interested in
-protecting data and code by requiring some capability to be held, for example a
-specific lock. The analysis ensures that the caller cannot perform the
-operation without holding the appropriate capability.
+Context analysis is a way to specify permissibility of operations to depend on
+context guards being held (or not held). Typically we are interested in
+protecting data and code in a critical section by requiring a specific context
+to be active, for example by holding a specific lock. The analysis ensures that
+callers cannot perform an operation without the required context being active.
 
-Capabilities are associated with named structs, along with functions that
-operate on capability-enabled struct instances to acquire and release the
-associated capability.
+Context guards are associated with named structs, along with functions that
+operate on struct instances to acquire and release the associated context
+guard.
 
-Capabilities can be held either exclusively or shared. This mechanism allows
-assign more precise privileges when holding a capability, typically to
+Context guards can be held either exclusively or shared. This mechanism allows
+assigning more precise privileges when a context is active, typically to
 distinguish where a thread may only read (shared) or also write (exclusive) to
-guarded data.
+data guarded within a context.
 
-The set of capabilities that are actually held by a given thread at a given
-point in program execution is a run-time concept. The static analysis works by
-calculating an approximation of that set, called the capability environment.
-The capability environment is calculated for every program point, and describes
-the set of capabilities that are statically known to be held, or not held, at
-that particular point. This environment is a conservative approximation of the
-full set of capabilities that will actually held by a thread at run-time.
+The set of contexts that are actually active in a given thread at a given point
+in program execution is a run-time concept. The static analysis works by
+calculating an approximation of that set, called the context environment. The
+context environment is calculated for every program point, and describes the
+set of contexts that are statically known to be active, or inactive, at that
+particular point. This environment is a conservative approximation of the full
+set of contexts that will actually be active in a thread at run-time.
 
 More details are also documented `here
 <https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_.
 
 .. note::
-   Clang's analysis explicitly does not infer capabilities acquired or released
-   by inline functions. It requires explicit annotations to (a) assert that
-   it's not a bug if a capability is released or acquired, and (b) to retain
-   consistency between inline and non-inline function declarations.
+   Clang's analysis explicitly does not infer context guards acquired or
+   released by inline functions. It requires explicit annotations to (a) assert
+   that it's not a bug if a context guard is released or acquired, and (b) to
+   retain consistency between inline and non-inline function declarations.
 
 Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
@@ -85,13 +84,12 @@ Currently the following synchronization primitives are supported:
 `bit_spinlock`, RCU, SRCU (`srcu_struct`), `rw_semaphore`, `local_lock_t`,
 `ww_mutex`.
 
-For capabilities with an initialization function (e.g., `spin_lock_init()`),
-calling this function on the capability instance before initializing any
-guarded members or globals prevents the compiler from issuing warnings about
-unguarded initialization.
+For context guards with an initialization function (e.g., `spin_lock_init()`),
+calling this function before initializing any guarded members or globals
+prevents the compiler from issuing warnings about unguarded initialization.
 
 Lockdep assertions, such as `lockdep_assert_held()`, inform the compiler's
-capability analysis that the associated synchronization primitive is held after
+context analysis that the associated synchronization primitive is held after
 the assertion. This avoids false positives in complex control-flow scenarios
 and encourages the use of Lockdep where static analysis is limited. For
 example, this is useful when a function doesn't *always* require a lock, making
@@ -100,9 +98,9 @@ example, this is useful when a function doesn't *always* require a lock, making
 Keywords
 ~~~~~~~~
 
-.. kernel-doc:: include/linux/compiler-capability-analysis.h
-   :identifiers: struct_with_capability
-                 token_capability token_capability_instance
+.. kernel-doc:: include/linux/compiler-context-analysis.h
+   :identifiers: context_guard_struct
+                 token_context_guard token_context_guard_instance
                  __guarded_by __pt_guarded_by
                  __must_hold
                  __must_not_hold
@@ -117,32 +115,32 @@ Keywords
                  __release
                  __acquire_shared
                  __release_shared
-                 capability_unsafe
-                 __capability_unsafe
-                 disable_capability_analysis enable_capability_analysis
+                 __acquire_ret
+                 __acquire_shared_ret
+                 context_unsafe
+                 __context_unsafe
+                 disable_context_analysis enable_context_analysis
 
 .. note::
-   The function attribute `__no_capability_analysis` is reserved for internal
-   implementation of capability-enabled primitives, and should be avoided in
-   normal code.
+   The function attribute `__no_context_analysis` is reserved for internal
+   implementation of context guard types, and should be avoided in normal code.
 
 Background
 ----------
 
 Clang originally called the feature `Thread Safety Analysis
-<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_, with some
-terminology still using the thread-safety-analysis-only names. This was later
-changed and the feature became more flexible, gaining the ability to define
-custom "capabilities".
-
-Indeed, its foundations can be found in `capability systems
-<https://www.cs.cornell.edu/talc/papers/capabilities.pdf>`_, used to specify
-the permissibility of operations to depend on some capability being held (or
-not held).
+<https://clang.llvm.org/docs/ThreadSafetyAnalysis.html>`_, with some keywords
+and documentation still using the thread-safety-analysis-only terminology. This
+was later changed and the feature became more flexible, gaining the ability to
+define custom "capabilities". Its foundations can be found in `Capability
+Systems <https://www.cs.cornell.edu/talc/papers/capabilities.pdf>`_, used to
+specify the permissibility of operations to depend on some "capability" being
+held (or not held).
 
 Because the feature is not just able to express capabilities related to
-synchronization primitives, the naming chosen for the kernel departs from
-Clang's initial "Thread Safety" nomenclature and refers to the feature as
-"Capability Analysis" to avoid confusion. The implementation still makes
-references to the older terminology in some places, such as `-Wthread-safety`
+synchronization primitives, and "capability" is already overloaded in the
+kernel, the naming chosen for the kernel departs from Clang's initial "Thread
+Safety" and "capability" nomenclature; we refer to the feature as "Context
+Analysis" to avoid confusion. The internal implementation still makes
+references to Clang's terminology in a few places, such as `-Wthread-safety`
 being the warning option that also still appears in diagnostic messages.
diff --git a/include/linux/compiler-capability-analysis.h b/include/linux/compiler-capability-analysis.h
index f8a1da67589c..b3804c5ac40d 100644
--- a/include/linux/compiler-capability-analysis.h
+++ b/include/linux/compiler-capability-analysis.h
@@ -1,42 +1,43 @@
 /* SPDX-License-Identifier: GPL-2.0 */
 /*
- * Macros and attributes for compiler-based static capability analysis.
+ * Macros and attributes for compiler-based static context analysis.
  */
 
-#ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
-#define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
+#ifndef _LINUX_COMPILER_CONTEXT_ANALYSIS_H
+#define _LINUX_COMPILER_CONTEXT_ANALYSIS_H
 
-#if defined(WARN_CAPABILITY_ANALYSIS)
+#if defined(WARN_CONTEXT_ANALYSIS)
 
 /*
- * The below attributes are used to define new capability types. Internal only.
- */
-# define __cap_type(name)			__attribute__((capability(#name)))
-# define __reentrant_cap			__attribute__((reentrant_capability))
-# define __acquires_cap(...)			__attribute__((acquire_capability(__VA_ARGS__)))
-# define __acquires_shared_cap(...)		__attribute__((acquire_shared_capability(__VA_ARGS__)))
-# define __try_acquires_cap(ret, var)		__attribute__((try_acquire_capability(ret, var)))
-# define __try_acquires_shared_cap(ret, var)	__attribute__((try_acquire_shared_capability(ret, var)))
-# define __releases_cap(...)			__attribute__((release_capability(__VA_ARGS__)))
-# define __releases_shared_cap(...)		__attribute__((release_shared_capability(__VA_ARGS__)))
-# define __assumes_cap(...)			__attribute__((assert_capability(__VA_ARGS__)))
-# define __assumes_shared_cap(...)		__attribute__((assert_shared_capability(__VA_ARGS__)))
-# define __returns_cap(var)			__attribute__((lock_returned(var)))
+ * These attributes define new context guard (Clang: capability) types.
+ * Internal only.
+ */
+# define __ctx_guard_type(name)			__attribute__((capability(#name)))
+# define __reentrant_ctx_guard			__attribute__((reentrant_capability))
+# define __acquires_ctx_guard(...)		__attribute__((acquire_capability(__VA_ARGS__)))
+# define __acquires_shared_ctx_guard(...)	__attribute__((acquire_shared_capability(__VA_ARGS__)))
+# define __try_acquires_ctx_guard(ret, var)	__attribute__((try_acquire_capability(ret, var)))
+# define __try_acquires_shared_ctx_guard(ret, var) __attribute__((try_acquire_shared_capability(ret, var)))
+# define __releases_ctx_guard(...)		__attribute__((release_capability(__VA_ARGS__)))
+# define __releases_shared_ctx_guard(...)	__attribute__((release_shared_capability(__VA_ARGS__)))
+# define __assumes_ctx_guard(...)		__attribute__((assert_capability(__VA_ARGS__)))
+# define __assumes_shared_ctx_guard(...)	__attribute__((assert_shared_capability(__VA_ARGS__)))
+# define __returns_ctx_guard(var)		__attribute__((lock_returned(var)))
 
 /*
  * The below are used to annotate code being checked. Internal only.
  */
-# define __excludes_cap(...)		__attribute__((locks_excluded(__VA_ARGS__)))
-# define __requires_cap(...)		__attribute__((requires_capability(__VA_ARGS__)))
-# define __requires_shared_cap(...)	__attribute__((requires_shared_capability(__VA_ARGS__)))
+# define __excludes_ctx_guard(...)		__attribute__((locks_excluded(__VA_ARGS__)))
+# define __requires_ctx_guard(...)		__attribute__((requires_capability(__VA_ARGS__)))
+# define __requires_shared_ctx_guard(...)	__attribute__((requires_shared_capability(__VA_ARGS__)))
 
 /**
  * __guarded_by - struct member and globals attribute, declares variable
- *                protected by capability
+ *                only accessible within active context
  *
- * Declares that the struct member or global variable must be guarded by the
- * given capabilities. Read operations on the data require shared access,
- * while write operations require exclusive access.
+ * Declares that the struct member or global variable is only accessible within
+ * the context entered by the given context guard. Read operations on the data
+ * require shared access, while write operations require exclusive access.
  *
  * .. code-block:: c
  *
@@ -49,11 +50,12 @@
 
 /**
  * __pt_guarded_by - struct member and globals attribute, declares pointed-to
- *                   data is protected by capability
+ *                   data only accessible within active context
  *
  * Declares that the data pointed to by the struct member pointer or global
- * pointer must be guarded by the given capabilities. Read operations on the
- * data require shared access, while write operations require exclusive access.
+ * pointer is only accessible within the context entered by the given context
+ * guard. Read operations on the data require shared access, while write
+ * operations require exclusive access.
  *
  * .. code-block:: c
  *
@@ -65,14 +67,14 @@
 # define __pt_guarded_by(...)		__attribute__((pt_guarded_by(__VA_ARGS__)))
 
 /**
- * struct_with_capability() - declare or define a capability struct
+ * context_guard_struct() - declare or define a context guard struct
  * @name: struct name
  *
- * Helper to declare or define a struct type with capability of the same name.
+ * Helper to declare or define a struct type that is also a context guard.
  *
  * .. code-block:: c
  *
- *	struct_with_capability(my_handle) {
+ *	context_guard_struct(my_handle) {
  *		int foo;
  *		long bar;
  *	};
@@ -81,98 +83,98 @@
  *		...
  *	};
  *	// ... declared elsewhere ...
- *	struct_with_capability(some_state);
- *
- * Note: The implementation defines several helper functions that can acquire,
- * release, and assert the capability.
- */
-# define struct_with_capability(name, ...)								\
-	struct __cap_type(name) __VA_ARGS__ name;							\
-	static __always_inline void __acquire_cap(const struct name *var)				\
-		__attribute__((overloadable)) __no_capability_analysis __acquires_cap(var) { }		\
-	static __always_inline void __acquire_shared_cap(const struct name *var)			\
-		__attribute__((overloadable)) __no_capability_analysis __acquires_shared_cap(var) { }	\
-	static __always_inline bool __try_acquire_cap(const struct name *var, bool ret)			\
-		__attribute__((overloadable)) __no_capability_analysis __try_acquires_cap(1, var)	\
+ *	context_guard_struct(some_state);
+ *
+ * Note: The implementation defines several helper functions that can acquire
+ * and release the context guard.
+ */
+# define context_guard_struct(name, ...)								\
+	struct __ctx_guard_type(name) __VA_ARGS__ name;							\
+	static __always_inline void __acquire_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __no_context_analysis __acquires_ctx_guard(var) { }	\
+	static __always_inline void __acquire_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __no_context_analysis __acquires_shared_ctx_guard(var) { } \
+	static __always_inline bool __try_acquire_ctx_guard(const struct name *var, bool ret)		\
+		__attribute__((overloadable)) __no_context_analysis __try_acquires_ctx_guard(1, var)	\
 	{ return ret; }											\
-	static __always_inline bool __try_acquire_shared_cap(const struct name *var, bool ret)		\
-		__attribute__((overloadable)) __no_capability_analysis __try_acquires_shared_cap(1, var) \
+	static __always_inline bool __try_acquire_shared_ctx_guard(const struct name *var, bool ret)	\
+		__attribute__((overloadable)) __no_context_analysis __try_acquires_shared_ctx_guard(1, var) \
 	{ return ret; }											\
-	static __always_inline void __release_cap(const struct name *var)				\
-		__attribute__((overloadable)) __no_capability_analysis __releases_cap(var) { }		\
-	static __always_inline void __release_shared_cap(const struct name *var)			\
-		__attribute__((overloadable)) __no_capability_analysis __releases_shared_cap(var) { }	\
-	static __always_inline void __assume_cap(const struct name *var)				\
-		__attribute__((overloadable)) __assumes_cap(var) { }					\
-	static __always_inline void __assume_shared_cap(const struct name *var)				\
-		__attribute__((overloadable)) __assumes_shared_cap(var) { }				\
+	static __always_inline void __release_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __no_context_analysis __releases_ctx_guard(var) { }	\
+	static __always_inline void __release_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __no_context_analysis __releases_shared_ctx_guard(var) { } \
+	static __always_inline void __assume_ctx_guard(const struct name *var)				\
+		__attribute__((overloadable)) __assumes_ctx_guard(var) { }				\
+	static __always_inline void __assume_shared_ctx_guard(const struct name *var)			\
+		__attribute__((overloadable)) __assumes_shared_ctx_guard(var) { }			\
 	struct name
 
 /**
- * disable_capability_analysis() - disables capability analysis
+ * disable_context_analysis() - disables context analysis
  *
- * Disables capability analysis. Must be paired with a later
- * enable_capability_analysis().
+ * Disables context analysis. Must be paired with a later
+ * enable_context_analysis().
  */
-# define disable_capability_analysis()				\
+# define disable_context_analysis()				\
 	__diag_push();						\
 	__diag_ignore_all("-Wunknown-warning-option", "")	\
 	__diag_ignore_all("-Wthread-safety", "")		\
 	__diag_ignore_all("-Wthread-safety-pointer", "")
 
 /**
- * enable_capability_analysis() - re-enables capability analysis
+ * enable_context_analysis() - re-enables context analysis
  *
- * Re-enables capability analysis. Must be paired with a prior
- * disable_capability_analysis().
+ * Re-enables context analysis. Must be paired with a prior
+ * disable_context_analysis().
  */
-# define enable_capability_analysis() __diag_pop()
+# define enable_context_analysis() __diag_pop()
 
 /**
- * __no_capability_analysis - function attribute, disables capability analysis
- *
- * Function attribute denoting that capability analysis is disabled for the
- * whole function. Prefer use of `capability_unsafe()` where possible.
- */
-# define __no_capability_analysis	__attribute__((no_thread_safety_analysis))
-
-#else /* !WARN_CAPABILITY_ANALYSIS */
-
-# define __cap_type(name)
-# define __reentrant_cap
-# define __acquires_cap(...)
-# define __acquires_shared_cap(...)
-# define __try_acquires_cap(ret, var)
-# define __try_acquires_shared_cap(ret, var)
-# define __releases_cap(...)
-# define __releases_shared_cap(...)
-# define __assumes_cap(...)
-# define __assumes_shared_cap(...)
-# define __returns_cap(var)
+ * __no_context_analysis - function attribute, disables context analysis
+ *
+ * Function attribute denoting that context analysis is disabled for the
+ * whole function. Prefer use of `context_unsafe()` where possible.
+ */
+# define __no_context_analysis	__attribute__((no_thread_safety_analysis))
+
+#else /* !WARN_CONTEXT_ANALYSIS */
+
+# define __ctx_guard_type(name)
+# define __reentrant_ctx_guard
+# define __acquires_ctx_guard(...)
+# define __acquires_shared_ctx_guard(...)
+# define __try_acquires_ctx_guard(ret, var)
+# define __try_acquires_shared_ctx_guard(ret, var)
+# define __releases_ctx_guard(...)
+# define __releases_shared_ctx_guard(...)
+# define __assumes_ctx_guard(...)
+# define __assumes_shared_ctx_guard(...)
+# define __returns_ctx_guard(var)
 # define __guarded_by(...)
 # define __pt_guarded_by(...)
-# define __excludes_cap(...)
-# define __requires_cap(...)
-# define __requires_shared_cap(...)
-# define __acquire_cap(var)			do { } while (0)
-# define __acquire_shared_cap(var)		do { } while (0)
-# define __try_acquire_cap(var, ret)		(ret)
-# define __try_acquire_shared_cap(var, ret)	(ret)
-# define __release_cap(var)			do { } while (0)
-# define __release_shared_cap(var)		do { } while (0)
-# define __assume_cap(var)			do { (void)(var); } while (0)
-# define __assume_shared_cap(var)		do { (void)(var); } while (0)
-# define struct_with_capability(name, ...)	struct __VA_ARGS__ name
-# define disable_capability_analysis()
-# define enable_capability_analysis()
-# define __no_capability_analysis
-
-#endif /* WARN_CAPABILITY_ANALYSIS */
+# define __excludes_ctx_guard(...)
+# define __requires_ctx_guard(...)
+# define __requires_shared_ctx_guard(...)
+# define __acquire_ctx_guard(var)			do { } while (0)
+# define __acquire_shared_ctx_guard(var)		do { } while (0)
+# define __try_acquire_ctx_guard(var, ret)		(ret)
+# define __try_acquire_shared_ctx_guard(var, ret)	(ret)
+# define __release_ctx_guard(var)			do { } while (0)
+# define __release_shared_ctx_guard(var)		do { } while (0)
+# define __assume_ctx_guard(var)			do { (void)(var); } while (0)
+# define __assume_shared_ctx_guard(var)			do { (void)(var); } while (0)
+# define context_guard_struct(name, ...)		struct __VA_ARGS__ name
+# define disable_context_analysis()
+# define enable_context_analysis()
+# define __no_context_analysis
+
+#endif /* WARN_CONTEXT_ANALYSIS */
 
 /**
- * capability_unsafe() - disable capability checking for contained code
+ * context_unsafe() - disable context checking for contained code
  *
- * Disables capability checking for contained statements or expression.
+ * Disables context checking for contained statements or expression.
  *
  * .. code-block:: c
  *
@@ -186,32 +188,32 @@
  *		// ...
  *		// other code that is still checked ...
  *		// ...
- *		return capability_unsafe(d->counter);
+ *		return context_unsafe(d->counter);
  *	}
  */
-#define capability_unsafe(...)		\
+#define context_unsafe(...)		\
 ({					\
-	disable_capability_analysis();	\
+	disable_context_analysis();	\
 	__VA_ARGS__;			\
-	enable_capability_analysis()	\
+	enable_context_analysis()	\
 })
 
 /**
- * __capability_unsafe() - function attribute, disable capability checking
+ * __context_unsafe() - function attribute, disable context checking
  * @comment: comment explaining why opt-out is safe
  *
- * Function attribute denoting that capability analysis is disabled for the
+ * Function attribute denoting that context analysis is disabled for the
  * whole function. Forces adding an inline comment as argument.
  */
-#define __capability_unsafe(comment) __no_capability_analysis
+#define __context_unsafe(comment) __no_context_analysis
 
 /**
- * capability_unsafe_alias() - helper to insert a capability "alias barrier"
- * @p: pointer aliasing a capability or object containing capabilities
+ * context_unsafe_alias() - helper to insert a context guard "alias barrier"
+ * @p: pointer aliasing a context guard or object containing context guards
  *
- * No-op function that acts as a "capability alias barrier", where the analysis
- * rightfully detects that we're switching aliases, but the switch is considered
- * safe but beyond the analysis reasoning abilities.
+ * No-op function that acts as a "context guard alias barrier", where the
+ * analysis rightfully detects that we're switching aliases, but the switch is
+ * considered safe but beyond the analysis reasoning abilities.
  *
  * This should be inserted before the first use of such an alias.
  *
@@ -219,61 +221,61 @@
  * their value cannot be determined (e.g. when passing a non-const pointer to an
  * alias as a function argument).
  */
-#define capability_unsafe_alias(p) _capability_unsafe_alias((void **)&(p))
-static inline void _capability_unsafe_alias(void **p) { }
+#define context_unsafe_alias(p) _context_unsafe_alias((void **)&(p))
+static inline void _context_unsafe_alias(void **p) { }
 
 /**
- * token_capability() - declare an abstract global capability instance
- * @name: token capability name
+ * token_context_guard() - declare an abstract global context guard instance
+ * @name: token context guard name
  *
- * Helper that declares an abstract global capability instance @name that can be
- * used as a token capability, but not backed by a real data structure (linker
- * error if accidentally referenced). The type name is `__capability_@name`.
+ * Helper that declares an abstract global context guard instance @name, but not
+ * backed by a real data structure (linker error if accidentally referenced).
+ * The type name is `__context_@name`.
  */
-#define token_capability(name, ...)					\
-	struct_with_capability(__capability_##name, ##__VA_ARGS__) {};	\
-	extern const struct __capability_##name *name
+#define token_context_guard(name, ...)					\
+	context_guard_struct(__context_##name, ##__VA_ARGS__) {};	\
+	extern const struct __context_##name *name
 
 /**
- * token_capability_instance() - declare another instance of a global capability
- * @cap: token capability previously declared with token_capability()
- * @name: name of additional global capability instance
+ * token_context_guard_instance() - declare another instance of a global context guard
+ * @ctx: token context guard previously declared with token_context_guard()
+ * @name: name of additional global context guard instance
  *
- * Helper that declares an additional instance @name of the same token
- * capability class @name. This is helpful where multiple related token
- * capabilities are declared, as it also allows using the same underlying type
- * (`__capability_@cap`) as function arguments.
+ * Helper that declares an additional instance @name of the same token context
+ * guard class @ctx. This is helpful where multiple related token contexts are
+ * declared, as it also allows using the same underlying type (`__context_@ctx`)
+ * as function arguments.
  */
-#define token_capability_instance(cap, name)		\
-	extern const struct __capability_##cap *name
+#define token_context_guard_instance(ctx, name)		\
+	extern const struct __context_##ctx *name
 
 /*
- * Common keywords for static capability analysis.
+ * Common keywords for static context analysis.
  */
 
 /**
- * __must_hold() - function attribute, caller must hold exclusive capability
+ * __must_hold() - function attribute, caller must hold exclusive context guard
  *
- * Function attribute declaring that the caller must hold the given capability
- * instance(s) exclusively.
+ * Function attribute declaring that the caller must hold the given context
+ * guard instance(s) exclusively.
  */
-#define __must_hold(...)	__requires_cap(__VA_ARGS__)
+#define __must_hold(...)	__requires_ctx_guard(__VA_ARGS__)
 
 /**
- * __must_not_hold() - function attribute, caller must not hold capability
+ * __must_not_hold() - function attribute, caller must not hold context guard
  *
  * Function attribute declaring that the caller must not hold the given
- * capability instance(s).
+ * context guard instance(s).
  */
-#define __must_not_hold(...)	__excludes_cap(__VA_ARGS__)
+#define __must_not_hold(...)	__excludes_ctx_guard(__VA_ARGS__)
 
 /**
- * __acquires() - function attribute, function acquires capability exclusively
+ * __acquires() - function attribute, function acquires context guard exclusively
  *
  * Function attribute declaring that the function acquires the given
- * capability instance(s) exclusively, but does not release them.
+ * context guard instance(s) exclusively, but does not release them.
  */
-#define __acquires(...)		__acquires_cap(__VA_ARGS__)
+#define __acquires(...)		__acquires_ctx_guard(__VA_ARGS__)
 
 /*
  * Clang's analysis does not care precisely about the value, only that it is
@@ -281,75 +283,76 @@ static inline void _capability_unsafe_alias(void **p) { }
  * misleading if we say that @ret is the value returned if acquired. Instead,
  * provide symbolic variants which we translate.
  */
-#define __cond_acquires_impl_true(x, ...)     __try_acquires##__VA_ARGS__##_cap(1, x)
-#define __cond_acquires_impl_false(x, ...)    __try_acquires##__VA_ARGS__##_cap(0, x)
-#define __cond_acquires_impl_nonzero(x, ...)  __try_acquires##__VA_ARGS__##_cap(1, x)
-#define __cond_acquires_impl_0(x, ...)        __try_acquires##__VA_ARGS__##_cap(0, x)
-#define __cond_acquires_impl_nonnull(x, ...)  __try_acquires##__VA_ARGS__##_cap(1, x)
-#define __cond_acquires_impl_NULL(x, ...)     __try_acquires##__VA_ARGS__##_cap(0, x)
+#define __cond_acquires_impl_true(x, ...)     __try_acquires##__VA_ARGS__##_ctx_guard(1, x)
+#define __cond_acquires_impl_false(x, ...)    __try_acquires##__VA_ARGS__##_ctx_guard(0, x)
+#define __cond_acquires_impl_nonzero(x, ...)  __try_acquires##__VA_ARGS__##_ctx_guard(1, x)
+#define __cond_acquires_impl_0(x, ...)        __try_acquires##__VA_ARGS__##_ctx_guard(0, x)
+#define __cond_acquires_impl_nonnull(x, ...)  __try_acquires##__VA_ARGS__##_ctx_guard(1, x)
+#define __cond_acquires_impl_NULL(x, ...)     __try_acquires##__VA_ARGS__##_ctx_guard(0, x)
 
 /**
  * __cond_acquires() - function attribute, function conditionally
- *                     acquires a capability exclusively
- * @ret: abstract value returned by function if capability acquired
- * @x: capability instance pointer
+ *                     acquires a context guard exclusively
+ * @ret: abstract value returned by function if context guard acquired
+ * @x: context guard instance pointer
  *
  * Function attribute declaring that the function conditionally acquires the
- * given capability instance @x exclusively, but does not release it. The
- * function return value @ret denotes when the capability is acquired.
+ * given context guard instance @x exclusively, but does not release it. The
+ * function return value @ret denotes when the context guard is acquired.
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
 #define __cond_acquires(ret, x) __cond_acquires_impl_##ret(x)
 
 /**
- * __releases() - function attribute, function releases a capability exclusively
+ * __releases() - function attribute, function releases a context guard exclusively
  *
- * Function attribute declaring that the function releases the given capability
- * instance(s) exclusively. The capability must be held on entry.
+ * Function attribute declaring that the function releases the given context
+ * guard instance(s) exclusively. The associated context must be active on
+ * entry.
  */
-#define __releases(...)		__releases_cap(__VA_ARGS__)
+#define __releases(...)		__releases_ctx_guard(__VA_ARGS__)
 
 /**
- * __acquire() - function to acquire capability exclusively
- * @x: capability instance pointer
+ * __acquire() - function to acquire context guard exclusively
+ * @x: context guard instance pointer
  *
- * No-op function that acquires the given capability instance @x exclusively.
+ * No-op function that acquires the given context guard instance @x exclusively.
  */
-#define __acquire(x)		__acquire_cap(x)
+#define __acquire(x)		__acquire_ctx_guard(x)
 
 /**
- * __release() - function to release capability exclusively
- * @x: capability instance pointer
+ * __release() - function to release context guard exclusively
+ * @x: context guard instance pointer
  *
- * No-op function that releases the given capability instance @x.
+ * No-op function that releases the given context guard instance @x.
  */
-#define __release(x)		__release_cap(x)
+#define __release(x)		__release_ctx_guard(x)
 
 /**
- * __must_hold_shared() - function attribute, caller must hold shared capability
+ * __must_hold_shared() - function attribute, caller must hold shared context guard
  *
- * Function attribute declaring that the caller must hold the given capability
- * instance(s) with shared access.
+ * Function attribute declaring that the caller must hold the given context
+ * guard instance(s) with shared access.
  */
-#define __must_hold_shared(...)	__requires_shared_cap(__VA_ARGS__)
+#define __must_hold_shared(...)	__requires_shared_ctx_guard(__VA_ARGS__)
 
 /**
- * __acquires_shared() - function attribute, function acquires capability shared
+ * __acquires_shared() - function attribute, function acquires context guard shared
  *
  * Function attribute declaring that the function acquires the given
- * capability instance(s) with shared access, but does not release them.
+ * context guard instance(s) with shared access, but does not release them.
  */
-#define __acquires_shared(...)	__acquires_shared_cap(__VA_ARGS__)
+#define __acquires_shared(...)	__acquires_shared_ctx_guard(__VA_ARGS__)
 
 /**
  * __cond_acquires_shared() - function attribute, function conditionally
- *                            acquires a capability shared
- * @ret: abstract value returned by function if capability acquired
+ *                            acquires a context guard shared
+ * @ret: abstract value returned by function if context guard acquired
  *
  * Function attribute declaring that the function conditionally acquires the
- * given capability instance @x with shared access, but does not release it. The
- * function return value @ret denotes when the capability is acquired.
+ * given context guard instance @x with shared access, but does not release it.
+ * The function return value @ret denotes when the context guard is acquired.
  *
  * @ret may be one of: true, false, nonzero, 0, nonnull, NULL.
  */
@@ -357,33 +360,34 @@ static inline void _capability_unsafe_alias(void **p) { }
 
 /**
  * __releases_shared() - function attribute, function releases a
- *                       capability shared
+ *                       context guard shared
  *
- * Function attribute declaring that the function releases the given capability
- * instance(s) with shared access. The capability must be held on entry.
+ * Function attribute declaring that the function releases the given context
+ * guard instance(s) with shared access. The associated context must be active
+ * on entry.
  */
-#define __releases_shared(...)	__releases_shared_cap(__VA_ARGS__)
+#define __releases_shared(...)	__releases_shared_ctx_guard(__VA_ARGS__)
 
 /**
- * __acquire_shared() - function to acquire capability shared
- * @x: capability instance pointer
+ * __acquire_shared() - function to acquire context guard shared
+ * @x: context guard instance pointer
  *
- * No-op function that acquires the given capability instance @x with shared
+ * No-op function that acquires the given context guard instance @x with shared
  * access.
  */
-#define __acquire_shared(x)	__acquire_shared_cap(x)
+#define __acquire_shared(x)	__acquire_shared_ctx_guard(x)
 
 /**
- * __release_shared() - function to release capability shared
- * @x: capability instance pointer
+ * __release_shared() - function to release context guard shared
+ * @x: context guard instance pointer
  *
- * No-op function that releases the given capability instance @x with shared
+ * No-op function that releases the given context guard instance @x with shared
  * access.
  */
-#define __release_shared(x)	__release_shared_cap(x)
+#define __release_shared(x)	__release_shared_ctx_guard(x)
 
 /**
- * __acquire_ret() - helper to acquire capability of return value
+ * __acquire_ret() - helper to acquire context guard of return value
  * @call: call expression
  * @ret_expr: acquire expression that uses __ret
  */
@@ -395,7 +399,7 @@ static inline void _capability_unsafe_alias(void **p) { }
 	})
 
 /**
- * __acquire_shared_ret() - helper to acquire capability shared of return value
+ * __acquire_shared_ret() - helper to acquire context guard shared of return value
  * @call: call expression
  * @ret_expr: acquire shared expression that uses __ret
  */
@@ -407,9 +411,9 @@ static inline void _capability_unsafe_alias(void **p) { }
 	})
 
 /*
- * Attributes to mark functions returning acquired capabilities. This is purely
- * cosmetic to help readability, and should be used with the above macros as
- * follows:
+ * Attributes to mark functions returning acquired context guards. This is
+ * purely cosmetic to help readability, and should be used with the above macros
+ * as follows:
  *
  *   struct foo { spinlock_t lock; ... };
  *   ...
@@ -417,7 +421,7 @@ static inline void _capability_unsafe_alias(void **p) { }
  *   struct foo *_myfunc(int bar) __acquires_ret;
  *   ...
  */
-#define __acquires_ret		__no_capability_analysis
-#define __acquires_shared_ret	__no_capability_analysis
+#define __acquires_ret		__no_context_analysis
+#define __acquires_shared_ret	__no_context_analysis
 
-#endif /* _LINUX_COMPILER_CAPABILITY_ANALYSIS_H */
+#endif /* _LINUX_COMPILER_CONTEXT_ANALYSIS_H */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aM0eAk12fWsr9ZnV%40elver.google.com.
