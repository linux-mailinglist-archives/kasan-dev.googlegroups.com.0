Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRHGSXFAMGQE3XGBDKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C26CCD0956
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:13 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id a640c23a62f3a-b801784f406sf201217466b.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159173; cv=pass;
        d=google.com; s=arc-20240605;
        b=b5j62C0y/OKwJTJYJWU/jNy7qPwp1r+zBL5KJ+J4rofLnpvilV73vDlZeuMCGmeB+J
         u0H/WO6n0M3LLa0PShXjU08m/DGTZPobNkRkMmvHYS7/Tib56QCmTTZg4vqepxikt4Qq
         A3OKa+Duy1VaQPKjJZfH6yjoEJdDx4xwV/B6REYYGhV/1lh9MsV0rg3XisyosA4bvxQ4
         xVo3rux2stmEBfnbVrpWIkYAGcU18HC+McTYar/QsDLH/ySQ5OCjEoQBsNREKKKxSEAX
         2gwMHU5uq/TUggoNz7qWvfIxUuNeqR3eU7ioHCPvZNle8cL5Hukm/XpNFJ6RQAnMhUz3
         Uorw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZLIQQBuVbU4EdB7EVEiK+NJYjg6PD8M40lpTZEAAtMs=;
        fh=LpNhtpX9UAixAyHJ57NOw5SkK/1u1khGrbrfER4SCz4=;
        b=EABHXsVBgWlIF7dNVCmlyiPUXojNhiY9RI3NedOuR6du8hc0mZmmVyd0w+t7P/9TjL
         Bv5hEATOlU9PD3ADA3Z38VyTvZttqdFGcI9U2EN3q4nLF2tVk7zL3GnaIF41+O41rOlf
         Nhy78dmdYlftSYf4wVexhfItTJqyVhfF3JlTJRWGQ8SoYEBPz+rKU9m64nKB9JoUO9/m
         7J9Ovdo8o97Ygjpef1rNsUiQOW2ATAB5q1ASQ9k1Y6ATp2Gi08YxdRm7w8Irnv7kxPRD
         YH87apRVJWpZxMgNBZB+yGOOmRAwrdwjuaIJ2t5ObuxA2d9xlY54sj7Q5pkW+wscUSy3
         +Pvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ruDjQs1l;
       spf=pass (google.com: domain of 3qxnfaqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QXNFaQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159173; x=1766763973; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZLIQQBuVbU4EdB7EVEiK+NJYjg6PD8M40lpTZEAAtMs=;
        b=FFww2P0THYrd+vOJwdGr1Hx2TY3g/3U2t9igumkZvPEkaStazCLdizFkBrN9Kg1FT5
         O2gYje8r7kTsEI3GsDAZVztW+Ckuw8x45NDEs1JDMaQpnmW5mVM+ZFpXrCLKesTurrQr
         XyZH4u8koq5c2x1tlM5MGVFjr9swKeKcmOl8DVCNBOfIgvVUTifutsL2TJOLgVzKigGr
         WkZRS9UM0f1AreBWnoF/sOs3iwOxCjqE/VzmoPvvsi6qB+e4JqHrqmbAcGmkuH2zYQHQ
         Dd1GLu6/8tV7ymzbsdqpBr/MMNZcio27lzEsaUnHPPMIpZJj1dMbQBqRHIsFBeqaOBgO
         ytiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159173; x=1766763973;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZLIQQBuVbU4EdB7EVEiK+NJYjg6PD8M40lpTZEAAtMs=;
        b=TdRApiONpnCb9kjQONeZ5xTAk+mtLasaaOkit+H+oc2DPhwxNe//fTaTAVxe9Q8Up6
         9dc3LMHMnoH6hL8v/Pjuxb9kkgwAkpQ5iQR4Sb1QsaQf/CCHl8XG00+LZjmsK7G21Nn1
         in6tSAwZKjZMh2+ufoMKdzfn5wBna28sUYsIFJj/3qi3Bbm4SV5l1Iuagh3nxEdqj6Ab
         /SxAz9lk3g4KutatRx7r/1ptWx5wxd6DCI6Qnt5kw5hvTLmOmSK6GK2pqDDRIZWPpzus
         WUT85tzaCzG3IQsAseyjLje/x8SrD/qzgpM3JRoNi8OFWDTuBUymfZWlqdTtzKKSv08I
         TAig==
X-Forwarded-Encrypted: i=2; AJvYcCUZbqNhbLaElwyHnmAHmDoWg+CeA/FafUBDsh37bA2Pz+mjYmIiJIM7uNbdaxEqYcX12xqh6Q==@lfdr.de
X-Gm-Message-State: AOJu0YxrePWzi/L2FRchHwokSW+oHz98x00W7HfRBpz8AILB+v7uYyeA
	mK39r4dUB0qKgp7xxUk+O9nSVj0iv2r7RxBh+AZn42WHugVoE6krQl2h
X-Google-Smtp-Source: AGHT+IE2yne3E47qzFJGFDmorsZ5rV4pmRfgFwWVfBPFr8m9up9kmoRifLXoRwQMC9iBloZPn5zpIA==
X-Received: by 2002:a17:907:9691:b0:b80:2315:b4ca with SMTP id a640c23a62f3a-b80371f956fmr357716666b.46.1766159172590;
        Fri, 19 Dec 2025 07:46:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZIurf07JUYxXXEZ9lvGQ1Z+TmOolUamcGfEAxzjcxvsw=="
Received: by 2002:a05:6402:1850:b0:64b:aa13:8b3e with SMTP id
 4fb4d7f45d1cf-64baa138bb1ls639308a12.1.-pod-prod-02-eu; Fri, 19 Dec 2025
 07:46:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWERdYC8gMx4BZqmvgo9XuKc/Ebyyyb+bsLrw+21fuQ7EHo/Y3YrlnB9pAV9G9CUIk3fdHlQar2sqU=@googlegroups.com
X-Received: by 2002:a17:907:72c1:b0:b73:7158:d9cd with SMTP id a640c23a62f3a-b80372300cdmr298871566b.52.1766159170058;
        Fri, 19 Dec 2025 07:46:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159170; cv=none;
        d=google.com; s=arc-20240605;
        b=QTY8roVRAVCjodpNbG5YSEx4sbEGJGFNR9eA3pQDwr+xaVIqKi0LMAxDhNEiPI8z2n
         ATHKWP9sStmyNXD0r26+w5yMWiPsZDHsx0rTnaivB5Ihfn8utYErCY+XDkaReUEcN8e+
         lfBgwB6JcpD25jzK7hGsFkOsID+4Wfkzp3Z15y9ss5jQmTkEs2k89ih7uMc0WywZfLe3
         AWUGDKhpQx+Q6IObU84yw6S/rTbKRDJjEj55dUzMHmhMLeqr3bD1HWOkVO+9qk9fk6r7
         CILci8aF+3xxObJ+XZ7wA3PTca6n4jRD/UvkxH/2AxXDqM0t/BOiSoJnp6jmosrtcbE5
         3ybA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=amWxerODEEoCfIoX62derQiE7p5loIvVLHROm1A4vmY=;
        fh=Qvi8Q4xySBVsYof5Ti8pmj1TNuawxQ+4uGcwM6554+o=;
        b=f8g68F5OUDCHMXUzb1Q6LqxrbuR/ULsgBl+/uZr9W81NvJ+q9oSCiatPdMifVsiBRd
         duyG+e4Jckj38qpKhZFpCW+MaT+7+gPwyPug87tQG1mZj93Stva1YTpSJ1TWAJCs2oNS
         7CMqqlrlTCdstTtM4s66wnf5m4KQKfjt2b9UIDKmJLdEthh39vGzFpl7d/OHgqJyumrw
         D3OxL0tSEhEIZlLidyQjMj6sY3JbaXPPQofU0+hYLoUotqSnFKaTZLk4uL8h7WaJFmaI
         YiUzNSjM1ZNB4Ymi0qkaqcUDBeznC+GWJQvfxqH/Uw9b5q1WxmcHeitxLp9mIzjK9uYd
         wecg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ruDjQs1l;
       spf=pass (google.com: domain of 3qxnfaqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QXNFaQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b915992d5si41365a12.8.2025.12.19.07.46.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qxnfaqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4788112ec09so18333625e9.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUSk5qFI47neZopFWkydyX9UBfSQgFDgyDCqaTE/sYt1augGnPR3/A3aG4rzYQqM1NxMw3MTK4ogGM=@googlegroups.com
X-Received: from wmot12.prod.google.com ([2002:a05:600c:450c:b0:46f:b153:bfb7])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3b2a:b0:477:7ab8:aba
 with SMTP id 5b1f17b1804b1-47d1953bd8bmr31823715e9.1.1766159169275; Fri, 19
 Dec 2025 07:46:09 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:00 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-12-elver@google.com>
Subject: [PATCH v5 11/36] locking/seqlock: Support Clang's context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
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
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ruDjQs1l;       spf=pass
 (google.com: domain of 3qxnfaqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QXNFaQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Add support for Clang's context analysis for seqlock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Support scoped_seqlock_read().
* Rename "context guard" -> "context lock".

v3:
* __assert -> __assume rename
---
 Documentation/dev-tools/context-analysis.rst |  2 +-
 include/linux/seqlock.h                      | 38 ++++++++++++++-
 include/linux/seqlock_types.h                |  5 +-
 lib/test_context-analysis.c                  | 50 ++++++++++++++++++++
 4 files changed, 91 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
index 1864b6cba4d1..690565910084 100644
--- a/Documentation/dev-tools/context-analysis.rst
+++ b/Documentation/dev-tools/context-analysis.rst
@@ -79,7 +79,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
 
 For context locks with an initialization function (e.g., `spin_lock_init()`),
 calling this function before initializing any guarded members or globals
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 221123660e71..113320911a09 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -816,6 +816,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
 	do {								\
 		spin_lock_init(&(sl)->lock);				\
 		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
+		__assume_ctx_lock(sl);					\
 	} while (0)
 
 /**
@@ -832,6 +833,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
  * Return: count, to be passed to read_seqretry()
  */
 static inline unsigned read_seqbegin(const seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	return read_seqcount_begin(&sl->seqcount);
 }
@@ -848,6 +850,7 @@ static inline unsigned read_seqbegin(const seqlock_t *sl)
  * Return: true if a read section retry is required, else false
  */
 static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
+	__releases_shared(sl) __no_context_analysis
 {
 	return read_seqcount_retry(&sl->seqcount, start);
 }
@@ -872,6 +875,7 @@ static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
  * _irqsave or _bh variants of this function instead.
  */
 static inline void write_seqlock(seqlock_t *sl)
+	__acquires(sl) __no_context_analysis
 {
 	spin_lock(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -885,6 +889,7 @@ static inline void write_seqlock(seqlock_t *sl)
  * critical section of given seqlock_t.
  */
 static inline void write_sequnlock(seqlock_t *sl)
+	__releases(sl) __no_context_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock(&sl->lock);
@@ -898,6 +903,7 @@ static inline void write_sequnlock(seqlock_t *sl)
  * other write side sections, can be invoked from softirq contexts.
  */
 static inline void write_seqlock_bh(seqlock_t *sl)
+	__acquires(sl) __no_context_analysis
 {
 	spin_lock_bh(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -912,6 +918,7 @@ static inline void write_seqlock_bh(seqlock_t *sl)
  * write_seqlock_bh().
  */
 static inline void write_sequnlock_bh(seqlock_t *sl)
+	__releases(sl) __no_context_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_bh(&sl->lock);
@@ -925,6 +932,7 @@ static inline void write_sequnlock_bh(seqlock_t *sl)
  * other write sections, can be invoked from hardirq contexts.
  */
 static inline void write_seqlock_irq(seqlock_t *sl)
+	__acquires(sl) __no_context_analysis
 {
 	spin_lock_irq(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -938,12 +946,14 @@ static inline void write_seqlock_irq(seqlock_t *sl)
  * seqlock_t write side section opened with write_seqlock_irq().
  */
 static inline void write_sequnlock_irq(seqlock_t *sl)
+	__releases(sl) __no_context_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_irq(&sl->lock);
 }
 
 static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
+	__acquires(sl) __no_context_analysis
 {
 	unsigned long flags;
 
@@ -976,6 +986,7 @@ static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
  */
 static inline void
 write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
+	__releases(sl) __no_context_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_irqrestore(&sl->lock, flags);
@@ -998,6 +1009,7 @@ write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
  * The opened read section must be closed with read_sequnlock_excl().
  */
 static inline void read_seqlock_excl(seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	spin_lock(&sl->lock);
 }
@@ -1007,6 +1019,7 @@ static inline void read_seqlock_excl(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl(seqlock_t *sl)
+	__releases_shared(sl) __no_context_analysis
 {
 	spin_unlock(&sl->lock);
 }
@@ -1021,6 +1034,7 @@ static inline void read_sequnlock_excl(seqlock_t *sl)
  * from softirq contexts.
  */
 static inline void read_seqlock_excl_bh(seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	spin_lock_bh(&sl->lock);
 }
@@ -1031,6 +1045,7 @@ static inline void read_seqlock_excl_bh(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl_bh(seqlock_t *sl)
+	__releases_shared(sl) __no_context_analysis
 {
 	spin_unlock_bh(&sl->lock);
 }
@@ -1045,6 +1060,7 @@ static inline void read_sequnlock_excl_bh(seqlock_t *sl)
  * hardirq context.
  */
 static inline void read_seqlock_excl_irq(seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	spin_lock_irq(&sl->lock);
 }
@@ -1055,11 +1071,13 @@ static inline void read_seqlock_excl_irq(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl_irq(seqlock_t *sl)
+	__releases_shared(sl) __no_context_analysis
 {
 	spin_unlock_irq(&sl->lock);
 }
 
 static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
+	__acquires_shared(sl) __no_context_analysis
 {
 	unsigned long flags;
 
@@ -1089,6 +1107,7 @@ static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
  */
 static inline void
 read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
+	__releases_shared(sl) __no_context_analysis
 {
 	spin_unlock_irqrestore(&sl->lock, flags);
 }
@@ -1125,6 +1144,7 @@ read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
  * parameter of the next read_seqbegin_or_lock() iteration.
  */
 static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
+	__acquires_shared(lock) __no_context_analysis
 {
 	if (!(*seq & 1))	/* Even */
 		*seq = read_seqbegin(lock);
@@ -1140,6 +1160,7 @@ static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
  * Return: true if a read section retry is required, false otherwise
  */
 static inline int need_seqretry(seqlock_t *lock, int seq)
+	__releases_shared(lock) __no_context_analysis
 {
 	return !(seq & 1) && read_seqretry(lock, seq);
 }
@@ -1153,6 +1174,7 @@ static inline int need_seqretry(seqlock_t *lock, int seq)
  * with read_seqbegin_or_lock() and validated by need_seqretry().
  */
 static inline void done_seqretry(seqlock_t *lock, int seq)
+	__no_context_analysis
 {
 	if (seq & 1)
 		read_sequnlock_excl(lock);
@@ -1180,6 +1202,7 @@ static inline void done_seqretry(seqlock_t *lock, int seq)
  */
 static inline unsigned long
 read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
+	__acquires_shared(lock) __no_context_analysis
 {
 	unsigned long flags = 0;
 
@@ -1205,6 +1228,7 @@ read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
  */
 static inline void
 done_seqretry_irqrestore(seqlock_t *lock, int seq, unsigned long flags)
+	__no_context_analysis
 {
 	if (seq & 1)
 		read_sequnlock_excl_irqrestore(lock, flags);
@@ -1225,6 +1249,7 @@ struct ss_tmp {
 };
 
 static __always_inline void __scoped_seqlock_cleanup(struct ss_tmp *sst)
+	__no_context_analysis
 {
 	if (sst->lock)
 		spin_unlock(sst->lock);
@@ -1254,6 +1279,7 @@ extern void __scoped_seqlock_bug(void);
 
 static __always_inline void
 __scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
+	__no_context_analysis
 {
 	switch (sst->state) {
 	case ss_done:
@@ -1296,9 +1322,19 @@ __scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
 	}
 }
 
+/*
+ * Context analysis no-op helper to release seqlock at the end of the for-scope;
+ * the alias analysis of the compiler will recognize that the pointer @s is an
+ * alias to @_seqlock passed to read_seqbegin(_seqlock) below.
+ */
+static __always_inline void __scoped_seqlock_cleanup_ctx(struct ss_tmp **s)
+	__releases_shared(*((seqlock_t **)s)) __no_context_analysis {}
+
 #define __scoped_seqlock_read(_seqlock, _target, _s)			\
 	for (struct ss_tmp _s __cleanup(__scoped_seqlock_cleanup) =	\
-	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) };	\
+	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) }, \
+	     *__UNIQUE_ID(ctx) __cleanup(__scoped_seqlock_cleanup_ctx) =\
+		(struct ss_tmp *)_seqlock;				\
 	     _s.state != ss_done;					\
 	     __scoped_seqlock_next(&_s, _seqlock, _target))
 
diff --git a/include/linux/seqlock_types.h b/include/linux/seqlock_types.h
index dfdf43e3fa3d..2d5d793ef660 100644
--- a/include/linux/seqlock_types.h
+++ b/include/linux/seqlock_types.h
@@ -81,13 +81,14 @@ SEQCOUNT_LOCKNAME(mutex,        struct mutex,    true,     mutex)
  *    - Comments on top of seqcount_t
  *    - Documentation/locking/seqlock.rst
  */
-typedef struct {
+context_lock_struct(seqlock) {
 	/*
 	 * Make sure that readers don't starve writers on PREEMPT_RT: use
 	 * seqcount_spinlock_t instead of seqcount_t. Check __SEQ_LOCK().
 	 */
 	seqcount_spinlock_t seqcount;
 	spinlock_t lock;
-} seqlock_t;
+};
+typedef struct seqlock seqlock_t;
 
 #endif /* __LINUX_SEQLOCK_TYPES_H */
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 2b28d20c5f51..53abea0008f2 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -6,6 +6,7 @@
 
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
+#include <linux/seqlock.h>
 #include <linux/spinlock.h>
 
 /*
@@ -208,3 +209,52 @@ static void __used test_mutex_cond_guard(struct test_mutex_data *d)
 		d->counter++;
 	}
 }
+
+struct test_seqlock_data {
+	seqlock_t sl;
+	int counter __guarded_by(&sl);
+};
+
+static void __used test_seqlock_init(struct test_seqlock_data *d)
+{
+	seqlock_init(&d->sl);
+	d->counter = 0;
+}
+
+static void __used test_seqlock_reader(struct test_seqlock_data *d)
+{
+	unsigned int seq;
+
+	do {
+		seq = read_seqbegin(&d->sl);
+		(void)d->counter;
+	} while (read_seqretry(&d->sl, seq));
+}
+
+static void __used test_seqlock_writer(struct test_seqlock_data *d)
+{
+	unsigned long flags;
+
+	write_seqlock(&d->sl);
+	d->counter++;
+	write_sequnlock(&d->sl);
+
+	write_seqlock_irq(&d->sl);
+	d->counter++;
+	write_sequnlock_irq(&d->sl);
+
+	write_seqlock_bh(&d->sl);
+	d->counter++;
+	write_sequnlock_bh(&d->sl);
+
+	write_seqlock_irqsave(&d->sl, flags);
+	d->counter++;
+	write_sequnlock_irqrestore(&d->sl, flags);
+}
+
+static void __used test_seqlock_scoped(struct test_seqlock_data *d)
+{
+	scoped_seqlock_read (&d->sl, ss_lockless) {
+		(void)d->counter;
+	}
+}
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-12-elver%40google.com.
