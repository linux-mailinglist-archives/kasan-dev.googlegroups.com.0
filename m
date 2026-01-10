Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMEMQ7FQMGQE6WZJEMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id CDDDDD0CDC9
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Jan 2026 04:23:39 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-64ba73e83c9sf8088719a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 19:23:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768015409; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lp0dZC4cb+a9OmZnpNV0NmBZrPuo34yPZiLU1nRt0kwY1TdtgCB6/EPrtYormKSff8
         nzxeFWWNj06RWDut41zt4Smv3iCwlvAH6yCEH408yAnHVb1fGKiAU/bon+YAXOBZzKD+
         jXwtHkVnSIGz//YLEyiPNQTEu4u3vG36rz3wGa5D5sWmVK7fmfzLx9ZGw1HPLbzwASAm
         lPVn9BglMMsdUYoXHs4o/6TIUlyMQphe9mkA+nXoHSyMQdFf5yGia8yRPv30vfD9OfpK
         C2Ujua1ASnewQisYID6geJLwsh5SEx2RTo+kLPtisvdS6uJy2BO6luwCUnMPR8iXZLat
         AfOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=U2jkdHRJyWuGRpW1lPvwGB2Wb+1wcI80/8lGT6LH0jU=;
        fh=VSVxcGNWeOsrheEzcuF3zi2JmjrR1e/BCINnV4RAFBw=;
        b=KB1u/f8haas6Vtjd4/HFfOZaiW+OcseI+9HaxWtSmT5B3LfsOmDL6ycq0CDlD/91JW
         938Pxh0O42yC5Y/pyjCA2RKW08QmvuGlonEmtk6Njsz9OlSbnE7nVSA9JGXQAvZ11FBv
         oPy0WVo62qbtVG4mTL4BDgk0uq3xHte7EJyLI0aX3vXLxHS1J90Z53hMhO5MAdeOBZXr
         zcOfAi5ax0wr4GuLZPP/vIsiXWG3642rC0fKuXFLu8WuoxwY8QvhFRLN8GiELEllGcZx
         HtQKGdmU+jaHUUEcH8py9MEC8wavmcri5DCd19WPBvutEwOTpuyMhH7Y2arOO+tLNwFA
         zEhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qZ1WtY90;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768015409; x=1768620209; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=U2jkdHRJyWuGRpW1lPvwGB2Wb+1wcI80/8lGT6LH0jU=;
        b=m4YRq+uQN9Ow9wzmD+J+VJ1X/LVCodoNG+Dqp10YXvWPZ7tTsIv9ir/TmaUgDNTA9O
         6Kozf5YaiatetMC8kmUmoc+iiiSJ4nXlN5j07Ki4YDszxgqXoWwF64DEtSaPPPXNF55l
         IdykJxqt8WFDeSRBuV7lOC5St81PhZZwTcqxDqoU//7RwEwkhVMwYSOLTILn/6mGseDb
         Gid5Z+QaMT36ppC18ulAcsK6JAYnKt9IByn5zYA6R+36xsKI/oveNoASCZ4IgiRas9Zh
         PTvplz1kU/yhxsOu2CkO5q8rb2Sx24d9bxdpqNuzl6nMan4h9hl1h/rK3b/jDoUaGoZS
         /4UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768015409; x=1768620209;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=U2jkdHRJyWuGRpW1lPvwGB2Wb+1wcI80/8lGT6LH0jU=;
        b=a5s/rB/uLh5NgD+vn7gU+9evej8Rn9eQhz69E4op6IxZPqHahXtvCJEeB2LTUtAeF5
         O9rQpHY4PDHx0JYZL9KnXqLbgBPckoixXx7RILg9jfHb58fL+wv/c0cn/AgQcRG8epH2
         WbN2yRPz784mJeadLsgMTMWVOBBFcVBWg6oIn5hwtfPXLfa5r//FrQTZqhYwUVsuTaA+
         Uw8H++J8UXyR6QDZ9GrjLEdfbhQqp2AjKmeoDgN7jL8IA1ods9a/iBfa4tsmQHnq7J6O
         3EjA/1eK1NkUoiwGidF1xw7uMwNBJjnD5NNb/0XiYwFCx/P2KPhrcwcjPfkIjSZesir4
         rpjQ==
X-Forwarded-Encrypted: i=2; AJvYcCX7VurhkwoQvK17F/KMfunAlrAVJq8mnaNWG/7TmfftOlozfcWRmwcuOlHbDsH6ojMsqnGn7w==@lfdr.de
X-Gm-Message-State: AOJu0YxQ+uj5GV23N+lCLWZsYaqbuzWz40K/OwdJDkMZb9MLWeFZkhH9
	bUvWeS1tUnnYyaeeUpEwqKSAtCrmU5Gu4oF5f5lJ5ywrEePcezC3fPMP
X-Google-Smtp-Source: AGHT+IHGdvmBPELK5vbbPd/e147MqUY/WUXtRqh4IdybKhwBnvNzoFd2kHzw7P30GHghrP5p8v9wfw==
X-Received: by 2002:a05:6402:50cc:b0:649:cb54:b7a9 with SMTP id 4fb4d7f45d1cf-65097e47186mr9586726a12.21.1768015408990;
        Fri, 09 Jan 2026 19:23:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FbqKfegqkgU/763UfWlNUU8zTyu1EtPdnmD8iiW4vu9Q=="
Received: by 2002:a05:6402:5154:b0:641:6610:6028 with SMTP id
 4fb4d7f45d1cf-650748e50e8ls4819800a12.2.-pod-prod-03-eu; Fri, 09 Jan 2026
 19:23:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXMOPFoq2waOI7Y0keOj+cGMen6pVKV1vPJwDcsSqdP2f/Nz4uOmxR0toqXK8Axkn0BEeLoKivq0YI=@googlegroups.com
X-Received: by 2002:a05:6402:1e94:b0:640:cdad:d2c0 with SMTP id 4fb4d7f45d1cf-65097e576b7mr10547195a12.25.1768015406420;
        Fri, 09 Jan 2026 19:23:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768015406; cv=none;
        d=google.com; s=arc-20240605;
        b=KiTvhNBHFSrHZy4RD73NOsEu/fQpP99qLmLIi63t9wtQQynHmzdcEkdqMDPggpEexW
         QedyT5XMo3S4wBfzw+7CMxEOctyWVSi2CLpD96E8RPcfEoq7E7N9gSspGkmd7KmNJZY8
         yie9Q1m9HQGhoUxtxsn3u970+d5CeL4rQZoa/RgYedmPu8bL4ty4h2vQ5XLSnf77LqlV
         5iA5pA3G+FsqOojlDoqhGk4siAQ04wx4gwah47b5HCaidU4Rlv7xCNmIMJibTaxR7z/J
         RiXZYq4xNfdA2tUg6m+boQGopRq7E2s78Q9+/2wicFumMD1JU2Bvsd2lkbzHwoFdisb4
         mk4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8mq1TLJDe/+4ZL2ybMlQeyJEwr2YWMjzl9f+SS6lqEM=;
        fh=Vdu7BPiXHluluzSR9Nuy3vl4op6Q8mDos4UfPebblqk=;
        b=EJ5ZOQLJykCXr7p6IuyXvz6jj7mQhqCm5lOV+B7kJI0812N+lo3BFzIS3LJnA9IYbt
         0cEqjMY+Ro1qM4SIxvzUBjRtcDAKLHPr4NWcYq2WjG15VU714aQMuEjN+7k0KtoLM1xh
         KqUxA2ouZou6Y2zLQyGdkTYR5IpZMJir9q2G0EIDR1XEb4jh0CMFlOJjySs+5Rw1KHgl
         ad1tRCpEN5YaO3JUxHz8huDtVrX8kQ1DUpOvZ3y44SCGYdgDo3GklkDL/Z2/nHI7qoIR
         lK5lVxkh2s8o5ljhRQvZRfRMkMlfpfJ6RNQWfdOL0XlKRA2KffkbmuwP+ImMmB0zL8Zh
         APBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qZ1WtY90;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d71679csi231357a12.6.2026.01.09.19.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Jan 2026 19:23:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id ffacd0b85a97d-42fbc305882so2554629f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 09 Jan 2026 19:23:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWB05eiftd1EzDgwXwd9b/kl94Geg74ucs6PbAn0NGbd2OLyyx7TyZRpVOW1g/sXWl0rQrICaOrDNg=@googlegroups.com
X-Gm-Gg: AY/fxX7uuJyH/0hidDukrx7G+1znRU8n5sTs3g6aZ+Zh0vnIxq8WkvxzPm7D1+RXIpE
	Mv62fySIl24i5WPzUR5UywYb80kdN/NOkQy/Qwqlxv/d+BRI0Fu9UsVq9jheTzsAcmQey9r/rPg
	X2YZLRYS5zfa/RE/KL589NQjCEC8yPnECuwcGH4CvCL447EWsJxFf2mQVBTRrDJdPSuCJp4NPHK
	73yESIpiRYD19wsC5gxg4FX6kD/joBs/Brh0rGS5RH+owNf1/mlBXkt7ac8PhJMa1IfAa1e20CE
	nZLsG6iS9gX9nCvf39fr5IYg0gKUiDpK+gMLS+L6EoZWLW95Ix3uHMNAyMZVP8YYnmgDOrScUMA
	HNBJbDW2rkBpVLi09CF9iFwi5CijW+bLeZKFTpGi0awHrXwD/7Sa2W9tmtTFya/GM7g4jmeAwqM
	AgWJcoFucRQeLsrNNqWdzB7hCdGmdF1zQQmVP6VwQhjLL52MR0
X-Received: by 2002:a05:6000:2909:b0:42f:bad9:20c9 with SMTP id ffacd0b85a97d-432c36329f9mr14528086f8f.19.1768015405505;
        Fri, 09 Jan 2026 19:23:25 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:2965:801e:e18a:cba1])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-432bd5ee24esm25605099f8f.33.2026.01.09.19.23.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 19:23:24 -0800 (PST)
Date: Sat, 10 Jan 2026 04:23:16 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>
Cc: Bart Van Assche <bvanassche@acm.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
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
Subject: Re: [PATCH v5 10/36] locking/mutex: Support Clang's context analysis
Message-ID: <aWHGJA8imMgELQrA@elver.google.com>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-11-elver@google.com>
 <57062131-e79e-42c2-aa0b-8f931cb8cac2@acm.org>
 <aWA9P3_oI7JFTdkC@elver.google.com>
 <20260109060249.GA5259@lst.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260109060249.GA5259@lst.de>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=qZ1WtY90;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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

On Fri, Jan 09, 2026 at 07:02AM +0100, Christoph Hellwig wrote:
> On Fri, Jan 09, 2026 at 12:26:55AM +0100, Marco Elver wrote:
> > Probably the most idiomatic option is to just factor out construction.
> > Clearly separating complex object construction from use also helps
> > readability regardless, esp. where concurrency is involved. We could
> > document such advice somewhere.
> 
> Initializing and locking a mutex (or spinlock, or other primitive) is a
> not too unusual pattern, often used when inserting an object into a
> hash table or other lookup data structure.  So supporting it without
> creating pointless wrapper functions would be really useful.  One thing
> that would be nice to have and probably help here is to have lock
> initializers that create the lock in a held state.

Fair point. Without new APIs, we can fix it with the below patch;
essentially "promoting" the context lock to "reentrant" during
initialization scope. It's not exactly well documented on the Clang
side, but is a side-effect of how reentrancy works in the analysis:
https://github.com/llvm/llvm-project/pull/175267

------ >8 ------

From 9c9b521b286f241f849dcc4f9efbd9582dabd3cc Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Sat, 10 Jan 2026 00:47:35 +0100
Subject: [PATCH] compiler-context-analysis: Support immediate acquisition
 after initialization

When a lock is initialized (e.g. mutex_init()), we assume/assert that
the context lock is held to allow initialization of guarded members
within the same scope.

However, this previously prevented actually acquiring the lock within
that same scope, as the analyzer would report a double-lock warning:

  mutex_init(&mtx);
  ...
  mutex_lock(&mtx); // acquiring mutex 'mtx' that is already held

To fix (without new init+lock APIs), we can tell the analysis to treat
the "held" context lock resulting from initialization as reentrant,
allowing subsequent acquisitions to succeed.

To do so *only* within the initialization scope, we can cast the lock
pointer to any reentrant type for the init assume/assert. Introduce a
generic reentrant context lock type `struct __ctx_lock_init` and add
`__inits_ctx_lock()` that casts the lock pointer to this type before
assuming/asserting it.

This ensures that the initial "held" state is reentrant, allowing
patterns like:

  mutex_init(&lock);
  ...
  mutex_lock(&lock);

to compile without false positives, and avoids having to make all
context lock types reentrant outside an initialization scope.

The caveat here is missing real double-lock bugs right after init scope.
However, this is a classic trade-off of avoiding false positives against
(unlikely) false negatives.

Link: https://lore.kernel.org/all/57062131-e79e-42c2-aa0b-8f931cb8cac2@acm.org/
Reported-by: Bart Van Assche <bvanassche@acm.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler-context-analysis.h | 12 ++++++++++++
 include/linux/local_lock_internal.h       |  6 +++---
 include/linux/mutex.h                     |  2 +-
 include/linux/rwlock.h                    |  4 ++--
 include/linux/rwlock_rt.h                 |  2 +-
 include/linux/rwsem.h                     |  4 ++--
 include/linux/seqlock.h                   |  2 +-
 include/linux/spinlock.h                  |  8 ++++----
 include/linux/spinlock_rt.h               |  2 +-
 include/linux/ww_mutex.h                  |  2 +-
 lib/test_context-analysis.c               |  3 +++
 11 files changed, 31 insertions(+), 16 deletions(-)

diff --git a/include/linux/compiler-context-analysis.h b/include/linux/compiler-context-analysis.h
index db7e0d48d8f2..e056cd6e8aaa 100644
--- a/include/linux/compiler-context-analysis.h
+++ b/include/linux/compiler-context-analysis.h
@@ -43,6 +43,14 @@
 # define __assumes_ctx_lock(...)		__attribute__((assert_capability(__VA_ARGS__)))
 # define __assumes_shared_ctx_lock(...)	__attribute__((assert_shared_capability(__VA_ARGS__)))
 
+/*
+ * Generic reentrant context lock type that we cast to when initializing context
+ * locks with __assumes_ctx_lock(), so that we can support guarded member
+ * initialization, but also immediate use after initialization.
+ */
+struct __ctx_lock_type(init_generic) __reentrant_ctx_lock __ctx_lock_init;
+# define __inits_ctx_lock(var) __assumes_ctx_lock((const struct __ctx_lock_init *)(var))
+
 /**
  * __guarded_by - struct member and globals attribute, declares variable
  *                only accessible within active context
@@ -120,6 +128,8 @@
 		__attribute__((overloadable)) __assumes_ctx_lock(var) { }				\
 	static __always_inline void __assume_shared_ctx_lock(const struct name *var)			\
 		__attribute__((overloadable)) __assumes_shared_ctx_lock(var) { }			\
+	static __always_inline void __init_ctx_lock(const struct name *var)				\
+		__attribute__((overloadable)) __inits_ctx_lock(var) { }					\
 	struct name
 
 /**
@@ -162,6 +172,7 @@
 # define __releases_shared_ctx_lock(...)
 # define __assumes_ctx_lock(...)
 # define __assumes_shared_ctx_lock(...)
+# define __inits_ctx_lock(var)
 # define __returns_ctx_lock(var)
 # define __guarded_by(...)
 # define __pt_guarded_by(...)
@@ -176,6 +187,7 @@
 # define __release_shared_ctx_lock(var)		do { } while (0)
 # define __assume_ctx_lock(var)			do { (void)(var); } while (0)
 # define __assume_shared_ctx_lock(var)			do { (void)(var); } while (0)
+# define __init_ctx_lock(var)			do { (void)(var); } while (0)
 # define context_lock_struct(name, ...)		struct __VA_ARGS__ name
 # define disable_context_analysis()
 # define enable_context_analysis()
diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock_internal.h
index e8c4803d8db4..36b8628d09fd 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -86,13 +86,13 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_PERCPU);			\
 	local_lock_debug_init(lock);				\
-	__assume_ctx_lock(lock);				\
+	__init_ctx_lock(lock);					\
 } while (0)
 
 #define __local_trylock_init(lock)				\
 do {								\
 	__local_lock_init((local_lock_t *)lock);		\
-	__assume_ctx_lock(lock);				\
+	__init_ctx_lock(lock);					\
 } while (0)
 
 #define __spinlock_nested_bh_init(lock)				\
@@ -104,7 +104,7 @@ do {								\
 			      0, LD_WAIT_CONFIG, LD_WAIT_INV,	\
 			      LD_LOCK_NORMAL);			\
 	local_lock_debug_init(lock);				\
-	__assume_ctx_lock(lock);				\
+	__init_ctx_lock(lock);					\
 } while (0)
 
 #define __local_lock_acquire(lock)					\
diff --git a/include/linux/mutex.h b/include/linux/mutex.h
index 89977c215cbd..5d2ef75c4fdb 100644
--- a/include/linux/mutex.h
+++ b/include/linux/mutex.h
@@ -62,7 +62,7 @@ do {									\
 	static struct lock_class_key __key;				\
 									\
 	__mutex_init((mutex), #mutex, &__key);				\
-	__assume_ctx_lock(mutex);					\
+	__init_ctx_lock(mutex);						\
 } while (0)
 
 /**
diff --git a/include/linux/rwlock.h b/include/linux/rwlock.h
index 65a5b55e1bcd..7e171634d2c4 100644
--- a/include/linux/rwlock.h
+++ b/include/linux/rwlock.h
@@ -22,11 +22,11 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__rwlock_init((lock), #lock, &__key);			\
-	__assume_ctx_lock(lock);				\
+	__init_ctx_lock(lock);					\
 } while (0)
 #else
 # define rwlock_init(lock)					\
-	do { *(lock) = __RW_LOCK_UNLOCKED(lock); __assume_ctx_lock(lock); } while (0)
+	do { *(lock) = __RW_LOCK_UNLOCKED(lock); __init_ctx_lock(lock); } while (0)
 #endif
 
 #ifdef CONFIG_DEBUG_SPINLOCK
diff --git a/include/linux/rwlock_rt.h b/include/linux/rwlock_rt.h
index 37b387dcab21..1e087a6ce2cf 100644
--- a/include/linux/rwlock_rt.h
+++ b/include/linux/rwlock_rt.h
@@ -22,7 +22,7 @@ do {							\
 							\
 	init_rwbase_rt(&(rwl)->rwbase);			\
 	__rt_rwlock_init(rwl, #rwl, &__key);		\
-	__assume_ctx_lock(rwl);				\
+	__init_ctx_lock(rwl);				\
 } while (0)
 
 extern void rt_read_lock(rwlock_t *rwlock)	__acquires_shared(rwlock);
diff --git a/include/linux/rwsem.h b/include/linux/rwsem.h
index 8da14a08a4e1..6ea7d2a23580 100644
--- a/include/linux/rwsem.h
+++ b/include/linux/rwsem.h
@@ -121,7 +121,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
-	__assume_ctx_lock(sem);					\
+	__init_ctx_lock(sem);					\
 } while (0)
 
 /*
@@ -175,7 +175,7 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_rwsem((sem), #sem, &__key);			\
-	__assume_ctx_lock(sem);					\
+	__init_ctx_lock(sem);					\
 } while (0)
 
 static __always_inline int rwsem_is_locked(const struct rw_semaphore *sem)
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 113320911a09..a0670adb4b6e 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -816,7 +816,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
 	do {								\
 		spin_lock_init(&(sl)->lock);				\
 		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
-		__assume_ctx_lock(sl);					\
+		__init_ctx_lock(sl);					\
 	} while (0)
 
 /**
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index 396b8c5d6c1b..e50372a5f7d1 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -106,12 +106,12 @@ do {									\
 	static struct lock_class_key __key;				\
 									\
 	__raw_spin_lock_init((lock), #lock, &__key, LD_WAIT_SPIN);	\
-	__assume_ctx_lock(lock);					\
+	__init_ctx_lock(lock);						\
 } while (0)
 
 #else
 # define raw_spin_lock_init(lock)				\
-	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); __assume_ctx_lock(lock); } while (0)
+	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); __init_ctx_lock(lock); } while (0)
 #endif
 
 #define raw_spin_is_locked(lock)	arch_spin_is_locked(&(lock)->raw_lock)
@@ -324,7 +324,7 @@ do {								\
 								\
 	__raw_spin_lock_init(spinlock_check(lock),		\
 			     #lock, &__key, LD_WAIT_CONFIG);	\
-	__assume_ctx_lock(lock);				\
+	__init_ctx_lock(lock);					\
 } while (0)
 
 #else
@@ -333,7 +333,7 @@ do {								\
 do {						\
 	spinlock_check(_lock);			\
 	*(_lock) = __SPIN_LOCK_UNLOCKED(_lock);	\
-	__assume_ctx_lock(_lock);		\
+	__init_ctx_lock(_lock);			\
 } while (0)
 
 #endif
diff --git a/include/linux/spinlock_rt.h b/include/linux/spinlock_rt.h
index 0a585768358f..154d7290bd99 100644
--- a/include/linux/spinlock_rt.h
+++ b/include/linux/spinlock_rt.h
@@ -20,7 +20,7 @@ static inline void __rt_spin_lock_init(spinlock_t *lock, const char *name,
 do {								\
 	rt_mutex_base_init(&(slock)->lock);			\
 	__rt_spin_lock_init(slock, name, key, percpu);		\
-	__assume_ctx_lock(slock);				\
+	__init_ctx_lock(slock);					\
 } while (0)
 
 #define _spin_lock_init(slock, percpu)				\
diff --git a/include/linux/ww_mutex.h b/include/linux/ww_mutex.h
index 58e959ee10e9..ecb5564ee70d 100644
--- a/include/linux/ww_mutex.h
+++ b/include/linux/ww_mutex.h
@@ -107,7 +107,7 @@ context_lock_struct(ww_acquire_ctx) {
  */
 static inline void ww_mutex_init(struct ww_mutex *lock,
 				 struct ww_class *ww_class)
-	__assumes_ctx_lock(lock)
+	__inits_ctx_lock(lock)
 {
 	ww_mutex_base_init(&lock->base, ww_class->mutex_name, &ww_class->mutex_key);
 	lock->ctx = NULL;
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 1c5a381461fc..2f733b5cc650 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -165,6 +165,9 @@ static void __used test_mutex_init(struct test_mutex_data *d)
 {
 	mutex_init(&d->mtx);
 	d->counter = 0;
+
+	mutex_lock(&d->mtx);
+	mutex_unlock(&d->mtx);
 }
 
 static void __used test_mutex_lock(struct test_mutex_data *d)
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWHGJA8imMgELQrA%40elver.google.com.
