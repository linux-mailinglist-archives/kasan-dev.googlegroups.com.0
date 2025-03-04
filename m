Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUEOTO7AMGQEAM7IZHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id DF748A4D82B
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:41 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4399c32efb4sf27505905e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080401; cv=pass;
        d=google.com; s=arc-20240605;
        b=lzBFnRAvgHqTB5vfawkT9yc0dURgJzgzggiLFdDXn+dmEH6fzxRNfBT43JLIgjrYlM
         hXIqyKnjbAM0xpVrscWrK6rEyKnhST6F2rNWtSy0k4FktXnFxv+V51rI58bJaTE5lWp7
         jX70/Cjgi1xA69iHQ2nI/mnbubuMLvskt/zpfrRMDFSNnqZH49HFdZZDp1bkMkgUiEZn
         vwGaOpoIGaVrF5D91PCn6agKcaUtj8Nh9zFgzOlJ8VUIjOO7QYNVuWE/t911Bv/Lo7VU
         or7g5kVzEjd0mY+EW+bg4gKmRChcCjCvYHIVjYxDPeJsMUwB4dXI4uGHGI5aBZdzUE9P
         LjxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=K1TElLareohEdcJJZZF+QEuVpIUAuOI95+GupjCZPmY=;
        fh=oClUwHzZkKHO53f6b5VeMmxJI7hTRbCwyPZhIKBTdZ8=;
        b=ahWMzzi9rjInXgSMMcO8SjNWpeHvUsChcP7Pi6iOVYVA6tT/20IWuyiC0fYma3yBVl
         NhjodpiUk5hTUrAiUmbTuXBthLFCtj5cOKAbVeAf+nTfHeQaQ6ZKHPJARUb1kaZezDPL
         iLzeQwqArvNCkVqxEX7NhtCAxBZumHZ355VByjx5PA0TxbFmbIn2X/P+upZgWIRX/x+x
         ax53yNno9qRFrjfo85e3nTWONUqEp5ijphRbFzVeBbpFsAvTTkYPiGDf5Sc1KAHzjM6S
         G3A3Apfv/GaUmcQ5gE6prF8f667FYjWhc0kOxnB2tawCsRs3EAQ6hah10cUlZwRY8ryI
         xaPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NY53dv3h;
       spf=pass (google.com: domain of 3tsfgzwukct0dkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3TsfGZwUKCT0dkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080401; x=1741685201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=K1TElLareohEdcJJZZF+QEuVpIUAuOI95+GupjCZPmY=;
        b=Rpn8k2CzOMV9vuDMXTIgFPJf0IyFD48GvkglNr8ibGTklolORMll/hCOUoS1hCCEO0
         5g/z6KA+B2M66wUzECHDTZmruvIgiRLxQYd8+cXyKW2gRlfHZLgmfWq0nO8XpQBd1UpU
         enWABHRYvpaov9yldE6UZRdcCI3pAbBZyuoxrmb5i2DvBZUP0u3SSmhihQIOUHv6VyEQ
         A2ikkggpE/FznEk1a9VECeq2hPAxTwJON6X+1enjK/QOjoNhydkfS6QbycvuYgUjOOlp
         iWtfskryMr56nBesI0ubCR1NA0gfF3we3dh06n68EvZ86dHwJBqDBJETWYCzh72jA6t/
         0Zmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080401; x=1741685201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K1TElLareohEdcJJZZF+QEuVpIUAuOI95+GupjCZPmY=;
        b=Lm4mItebHF/25/HFD+9nPPsCZvBZFAD4BhAiRbHNJ4tpznuCxJxyxPqyITyLGuwDeu
         H/E5MRIP0DjLdfxz59R/qtu8C8Z9kjJJsayAVmAgg32Mom4Z0NpTGn3JA6RGnFsYdAav
         cpmpxZqaYRAxwwYgRD9PmnfVE0aphk/Yn39WqHtqdqnyleH2S6PIjKWdgWeE1E907rRf
         w58yaUDjYz0VVi9Rq5WEC3TID/A+8yqU8BPPNBfkZ9oy/MLE4mF1/qPunr/VycDbte1V
         vHRzYoEf9RnrzHUrQci/cjc8HZnOm7WZQXDPIA7IsGEgmsYc1LzfRn3jgn31dBfJX9gh
         uiCQ==
X-Forwarded-Encrypted: i=2; AJvYcCUOkdxM49kdStKJcA39NhEbY6g4LwGRz8C1P5OLH+JUbzcmHkpTuJqkeDYA2kHjaDeMR3FUNg==@lfdr.de
X-Gm-Message-State: AOJu0YxFd55fJeF77gW7zL4iTAZucQwoJ/CgXkUESr8h25bzfNbgGsMr
	4A7IoiqPno+EQC72JMUoL2YM931Q5zrTt4h+66+TWJ1DXeuiMElZ
X-Google-Smtp-Source: AGHT+IEFq4vtLCVkjLAP40u49CaZJaKWZiaKw0dHq2HHD2/neR+Zi7MzOKrhZr8hdoSOLPjAIYdwSg==
X-Received: by 2002:a05:600c:358b:b0:43b:c6a7:ac60 with SMTP id 5b1f17b1804b1-43bcb032125mr18458605e9.10.1741080401118;
        Tue, 04 Mar 2025 01:26:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEzv9OTuzE8ZQup1qrtwmjbgVlkJaKvW2UfeIYS0guqcw==
Received: by 2002:a05:600c:354d:b0:439:806f:c2dc with SMTP id
 5b1f17b1804b1-43ab97d4b3bls20058635e9.1.-pod-prod-00-eu-canary; Tue, 04 Mar
 2025 01:26:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWtOZ9V5g6X+8rCJ5wIQsXE3ZEBAQgOF1FRPxSRiHfUuQ4eRieFNxaajdxNjk5BRqHCEM5Q2D0ciNk=@googlegroups.com
X-Received: by 2002:a05:6000:186b:b0:390:f5c8:1079 with SMTP id ffacd0b85a97d-39115627ea8mr1905112f8f.24.1741080398654;
        Tue, 04 Mar 2025 01:26:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080398; cv=none;
        d=google.com; s=arc-20240605;
        b=kHZDMgfoKSXXJ6LJTqG2cSfScra64/BVGHI1b3pRryq/HI3pZuvTUyRRJodkXeV94x
         IUo/E1nuFNhwr/Dzt3PvsR+0CRi2LMuuM5Y9lFX5MzBdVTGdP/Emk6iZP1fKIHTLA2Gt
         15E2pCyBlYZd820+rqd7PANjqw86E3WI/jZonfHXYjoH6psm8FjDCtdNxo+3iuA6KFZG
         LdW1q8KnW2JVFmup/aPetoJRnXndgfWA514XmLb3utLRkDKoTTtON10cgrQ/9fwo5CTK
         l1elgM3GHH6P+VMRMB2urmbcuaIMp5eI3ya0n8skKoT77bWxEt69Scls/+y/oyuaIyQ6
         TUYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=N6cosU/aHEF331Tgbf58Vi03lqVulZKFB2l/GT8tm7Y=;
        fh=8LP999ijagPDXfcgAhpMsgD1+hngeGaHlBqK+qUkhiE=;
        b=axfJXJ9hBCeelIq8ZAogpX5V7GOP7HHHQvGv93Zxq+BHQs9423ZS4VMNZvnl6kYrGG
         SHbMojKTLa9+++ylX9MRa+dd2dKr/oOlXYbSR1ErFs71uThhToldCzWRPnXBB4ObeYUy
         6wYdL69eSOlCulDg0pFtYEfjeRou0H8NQ0cyFIjkZCQXlubi1yfu+r2Ug+07h+VXBbO2
         03vJNTsEeLUsZwkNcIB+XT0lWvTtYgK3Ne1c9MlyL0hIagPP5akUnIQIU9RzTx0iW9/a
         QM95wQcAmym3/keJQWtP4PTJ61LveCnxDMGfwFRVHNR47ZUeFc0yVtGIZUvkwN8Gj+xx
         uWWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NY53dv3h;
       spf=pass (google.com: domain of 3tsfgzwukct0dkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3TsfGZwUKCT0dkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e47ff679si387058f8f.5.2025.03.04.01.26.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tsfgzwukct0dkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ab397fff5a3so699458566b.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWpH5MixfzuHkgeM0ujPzJviXwJUaxiNjCmBAm02H/di1lbwvl7L6C25OXWsjMqRfcaDw96ByVVO44=@googlegroups.com
X-Received: from ejcvx9.prod.google.com ([2002:a17:907:a789:b0:ac1:fb2a:4a70])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:3da3:b0:ac1:edc5:d73b
 with SMTP id a640c23a62f3a-ac1f0edc8c7mr225816966b.8.1741080398288; Tue, 04
 Mar 2025 01:26:38 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:32 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-34-elver@google.com>
Subject: [PATCH v2 33/34] crypto: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
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
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NY53dv3h;       spf=pass
 (google.com: domain of 3tsfgzwukct0dkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3TsfGZwUKCT0dkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

Enable capability analysis for crypto subsystem.

This demonstrates a larger conversion to use Clang's capability
analysis. The benefit is additional static checking of locking rules,
along with better documentation.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Herbert Xu <herbert@gondor.apana.org.au>
Cc: "David S. Miller" <davem@davemloft.net>
Cc: linux-crypto@vger.kernel.org
---
v2:
* New patch.
---
 crypto/Makefile                  | 2 ++
 crypto/algapi.c                  | 2 ++
 crypto/api.c                     | 1 +
 crypto/crypto_engine.c           | 2 +-
 crypto/drbg.c                    | 5 +++++
 crypto/internal.h                | 2 +-
 crypto/proc.c                    | 3 +++
 crypto/scompress.c               | 8 +++++---
 include/crypto/internal/engine.h | 2 +-
 9 files changed, 21 insertions(+), 6 deletions(-)

diff --git a/crypto/Makefile b/crypto/Makefile
index f67e853c4690..b7fa58ab8783 100644
--- a/crypto/Makefile
+++ b/crypto/Makefile
@@ -3,6 +3,8 @@
 # Cryptographic API
 #
 
+CAPABILITY_ANALYSIS := y
+
 obj-$(CONFIG_CRYPTO) += crypto.o
 crypto-y := api.o cipher.o compress.o
 
diff --git a/crypto/algapi.c b/crypto/algapi.c
index 5318c214debb..c2bafcde6f64 100644
--- a/crypto/algapi.c
+++ b/crypto/algapi.c
@@ -230,6 +230,7 @@ EXPORT_SYMBOL_GPL(crypto_remove_spawns);
 
 static void crypto_alg_finish_registration(struct crypto_alg *alg,
 					   struct list_head *algs_to_put)
+	__must_hold(&crypto_alg_sem)
 {
 	struct crypto_alg *q;
 
@@ -286,6 +287,7 @@ static struct crypto_larval *crypto_alloc_test_larval(struct crypto_alg *alg)
 
 static struct crypto_larval *
 __crypto_register_alg(struct crypto_alg *alg, struct list_head *algs_to_put)
+	__must_hold(&crypto_alg_sem)
 {
 	struct crypto_alg *q;
 	struct crypto_larval *larval;
diff --git a/crypto/api.c b/crypto/api.c
index bfd177a4313a..def3430ab332 100644
--- a/crypto/api.c
+++ b/crypto/api.c
@@ -57,6 +57,7 @@ EXPORT_SYMBOL_GPL(crypto_mod_put);
 
 static struct crypto_alg *__crypto_alg_lookup(const char *name, u32 type,
 					      u32 mask)
+	__must_hold_shared(&crypto_alg_sem)
 {
 	struct crypto_alg *q, *alg = NULL;
 	int best = -2;
diff --git a/crypto/crypto_engine.c b/crypto/crypto_engine.c
index c7c16da5e649..4ab0bbc4c7ce 100644
--- a/crypto/crypto_engine.c
+++ b/crypto/crypto_engine.c
@@ -514,8 +514,8 @@ struct crypto_engine *crypto_engine_alloc_init_and_set(struct device *dev,
 	snprintf(engine->name, sizeof(engine->name),
 		 "%s-engine", dev_name(dev));
 
-	crypto_init_queue(&engine->queue, qlen);
 	spin_lock_init(&engine->queue_lock);
+	crypto_init_queue(&engine->queue, qlen);
 
 	engine->kworker = kthread_run_worker(0, "%s", engine->name);
 	if (IS_ERR(engine->kworker)) {
diff --git a/crypto/drbg.c b/crypto/drbg.c
index f28dfc2511a2..881579afa160 100644
--- a/crypto/drbg.c
+++ b/crypto/drbg.c
@@ -231,6 +231,7 @@ static inline unsigned short drbg_sec_strength(drbg_flag_t flags)
  */
 static int drbg_fips_continuous_test(struct drbg_state *drbg,
 				     const unsigned char *entropy)
+	__must_hold(&drbg->drbg_mutex)
 {
 	unsigned short entropylen = drbg_sec_strength(drbg->core->flags);
 	int ret = 0;
@@ -1061,6 +1062,7 @@ static inline int __drbg_seed(struct drbg_state *drbg, struct list_head *seed,
 static inline int drbg_get_random_bytes(struct drbg_state *drbg,
 					unsigned char *entropy,
 					unsigned int entropylen)
+	__must_hold(&drbg->drbg_mutex)
 {
 	int ret;
 
@@ -1075,6 +1077,7 @@ static inline int drbg_get_random_bytes(struct drbg_state *drbg,
 }
 
 static int drbg_seed_from_random(struct drbg_state *drbg)
+	__must_hold(&drbg->drbg_mutex)
 {
 	struct drbg_string data;
 	LIST_HEAD(seedlist);
@@ -1132,6 +1135,7 @@ static bool drbg_nopr_reseed_interval_elapsed(struct drbg_state *drbg)
  */
 static int drbg_seed(struct drbg_state *drbg, struct drbg_string *pers,
 		     bool reseed)
+	__must_hold(&drbg->drbg_mutex)
 {
 	int ret;
 	unsigned char entropy[((32 + 16) * 2)];
@@ -1368,6 +1372,7 @@ static inline int drbg_alloc_state(struct drbg_state *drbg)
 static int drbg_generate(struct drbg_state *drbg,
 			 unsigned char *buf, unsigned int buflen,
 			 struct drbg_string *addtl)
+	__must_hold(&drbg->drbg_mutex)
 {
 	int len = 0;
 	LIST_HEAD(addtllist);
diff --git a/crypto/internal.h b/crypto/internal.h
index 46b661be0f90..3ac76faf228b 100644
--- a/crypto/internal.h
+++ b/crypto/internal.h
@@ -45,8 +45,8 @@ enum {
 /* Maximum number of (rtattr) parameters for each template. */
 #define CRYPTO_MAX_ATTRS 32
 
-extern struct list_head crypto_alg_list;
 extern struct rw_semaphore crypto_alg_sem;
+extern struct list_head crypto_alg_list __guarded_by(&crypto_alg_sem);
 extern struct blocking_notifier_head crypto_chain;
 
 int alg_test(const char *driver, const char *alg, u32 type, u32 mask);
diff --git a/crypto/proc.c b/crypto/proc.c
index 522b27d90d29..4679eb6b81c9 100644
--- a/crypto/proc.c
+++ b/crypto/proc.c
@@ -19,17 +19,20 @@
 #include "internal.h"
 
 static void *c_start(struct seq_file *m, loff_t *pos)
+	__acquires_shared(&crypto_alg_sem)
 {
 	down_read(&crypto_alg_sem);
 	return seq_list_start(&crypto_alg_list, *pos);
 }
 
 static void *c_next(struct seq_file *m, void *p, loff_t *pos)
+	__must_hold_shared(&crypto_alg_sem)
 {
 	return seq_list_next(p, &crypto_alg_list, pos);
 }
 
 static void c_stop(struct seq_file *m, void *p)
+	__releases_shared(&crypto_alg_sem)
 {
 	up_read(&crypto_alg_sem);
 }
diff --git a/crypto/scompress.c b/crypto/scompress.c
index 1cef6bb06a81..0f24c84cc550 100644
--- a/crypto/scompress.c
+++ b/crypto/scompress.c
@@ -25,8 +25,8 @@
 
 struct scomp_scratch {
 	spinlock_t	lock;
-	void		*src;
-	void		*dst;
+	void		*src __guarded_by(&lock);
+	void		*dst __guarded_by(&lock);
 };
 
 static DEFINE_PER_CPU(struct scomp_scratch, scomp_scratch) = {
@@ -34,8 +34,8 @@ static DEFINE_PER_CPU(struct scomp_scratch, scomp_scratch) = {
 };
 
 static const struct crypto_type crypto_scomp_type;
-static int scomp_scratch_users;
 static DEFINE_MUTEX(scomp_lock);
+static int scomp_scratch_users __guarded_by(&scomp_lock);
 
 static int __maybe_unused crypto_scomp_report(
 	struct sk_buff *skb, struct crypto_alg *alg)
@@ -59,6 +59,7 @@ static void crypto_scomp_show(struct seq_file *m, struct crypto_alg *alg)
 }
 
 static void crypto_scomp_free_scratches(void)
+	__capability_unsafe(/* frees @scratch */)
 {
 	struct scomp_scratch *scratch;
 	int i;
@@ -74,6 +75,7 @@ static void crypto_scomp_free_scratches(void)
 }
 
 static int crypto_scomp_alloc_scratches(void)
+	__capability_unsafe(/* allocates @scratch */)
 {
 	struct scomp_scratch *scratch;
 	int i;
diff --git a/include/crypto/internal/engine.h b/include/crypto/internal/engine.h
index fbf4be56cf12..10edbb451f1c 100644
--- a/include/crypto/internal/engine.h
+++ b/include/crypto/internal/engine.h
@@ -54,7 +54,7 @@ struct crypto_engine {
 
 	struct list_head	list;
 	spinlock_t		queue_lock;
-	struct crypto_queue	queue;
+	struct crypto_queue	queue __guarded_by(&queue_lock);
 	struct device		*dev;
 
 	bool			rt;
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-34-elver%40google.com.
