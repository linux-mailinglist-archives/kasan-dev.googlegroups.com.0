Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJHHSXFAMGQE6TL663A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B7A34CD09DA
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:49 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5944d65a8f5sf1282890e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159269; cv=pass;
        d=google.com; s=arc-20240605;
        b=LeS/qhPV2TZmitVuBqx11+Jpq1qbmeVK4/b54xoHUb3uyi55f4ygCccptozdM+SF08
         gNIVZMtqHDuubSHd3kSMdo9gyEUHhBvS1m6yQMfdmJ5z2GZFUbqF+xdqzMk+WQHE8RyN
         dKYs1QoLDMY1h4MFr8Tm2RK1Cu5LGbfRg5k90+PgmgqLkoWmWK4YjFK3uhlHs+DBFHXd
         i9kLMjPht4rPTZmq8ch2YVWMMJMmmh3kUKmQ1cB3dv3whW1ZBQprFvQrAkawn/jsI/JB
         GwojkYPCCQeHQ0CvGZuOdlKCshpbBW4Y4ymkvdsdmuZDcV7zL4nHehv65vy1AEeRokCc
         b4KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=kMK5uS9jOIsR3FjV4EhIkEIhQWMlMhBvekw069XvViw=;
        fh=KXNvlvaBq4tXKjBBiIv049DEhO6x3rGMjTdF1tgWpjo=;
        b=GnQlnc8CJLBnW0ElK8QR1+FoMk6/VxXx6eskPxFTQ7Ffu5R9mKLDXek7N2+LRyLjCi
         cXZ0KfPeCBqqTNmWc5BgkaHHSc8ZtAISyD7SY1p8S2IWsUFppd/efJkf3ZLeKP86D0YQ
         h90jQVKgdaRH5mk7yx6dJJ0CVA9C3muAOLshyGf/gCcXXV1l0P6wpK8w7KvdNI//eZRT
         T88Ko1qcQjMYC/a15+OBkXOocPPNZwOG7aq7IBhZYcNNifaMVjFZ5X5O4F+gLsYNQlt5
         6hNKvdumydqHQ76EP2jZ7nxqL5MEtoXtuNR2aFN5dQaRHXVt8pJrCwLg37FK6wi/lqaW
         4YEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ONyb3VRf;
       spf=pass (google.com: domain of 3oxnfaqukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oXNFaQUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159269; x=1766764069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kMK5uS9jOIsR3FjV4EhIkEIhQWMlMhBvekw069XvViw=;
        b=TIFSnwt/D4/sXTWTuPdeNjZV7zihpNtOCh80zFvDUkYVhlNz/otUQF90Xw5rV4NukZ
         RMXd82JzxXn7cU6JoYaW2rSRSgyZSYwD79nlfw7UDzi1dFoVJupl1ezuf9FmQZzA9cCV
         CgjEbKFgZLBk8fmKkPQ7yHQ/Xf/LmGT3m22exq4lVEoS7az4w2kIiSBhMU9tZWEm26Ji
         HYP8IUNpziXMyonPxQM00BimInB2LEt/9s5HIE3sSlHWVGGwf4jTAdHgZzewyqeK7lb4
         +ZwtJDBuNTxrfyRmXiPSnLt5ftdL949r3Kqh0V2Mm6izs9NKIgBe6dkcmdZJFbtPKBKf
         WArw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159269; x=1766764069;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kMK5uS9jOIsR3FjV4EhIkEIhQWMlMhBvekw069XvViw=;
        b=GTR6Da6cnybvaIp0TCDwvE3x8QKkzVggpppyJuIuY92IIn7RhF7y3ETCuTET17JiRP
         wYM5om6C4rOsIq2shVhFksZHkuj0In98CAXZESigHr1rgkgbQb9hSPfV1gpt/kIfClB2
         4RgPgfXpMPCEsAfEFaXLHOQ4Fd7YZrmmtMC/mqlB7WuMH2ZmYWdbDeRIBs499QRqZaNC
         Aj+YzU0xemLxYfHHfM/AZTS5rd9ID+GXRjRQLP0atuScVx5yTSb9p1z7+qUlyPjh9q9w
         YA8FERCO2W5QhNVvLJAA1/G5NUFqSX2nQ3XmwY50Otz+c7w82MK619VU+FY34HJ2CAY1
         BeFQ==
X-Forwarded-Encrypted: i=2; AJvYcCUdiZCPrAZ3Veur+OhOAAY7HRBJi10g2pkJC7EOOHJqy/oxQJFEpGPHMi66/7DtIlWVxPPlgA==@lfdr.de
X-Gm-Message-State: AOJu0YwhWnhInM7SHi7f92Im+E/t9yzzUvcfEefQSihP78AWaJavhiAA
	z01JB9XblO5bIMKak+Dmtcpt4pZ3bMdN77WzSzbod+IURjgkrEAuhjL9
X-Google-Smtp-Source: AGHT+IEvYib0bgQvfB5H6rTrkLqAcYT1sHnZ7cTW3rKR7o5x6INmUo3rpbpDmR3tlIheF76BtieN1g==
X-Received: by 2002:a05:6512:2388:b0:598:e9f9:bdd with SMTP id 2adb3069b0e04-59a17d57763mr1365243e87.27.1766159268918;
        Fri, 19 Dec 2025 07:47:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb/VWYcUQOUNwdWg5sC1gfRxHKI3EMIuk2/tFpfr1Llbg=="
Received: by 2002:a05:6512:b12:b0:598:f8cf:633a with SMTP id
 2adb3069b0e04-598fa413205ls2667625e87.2.-pod-prod-09-eu; Fri, 19 Dec 2025
 07:47:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVUy572+rezWOinRTUKDPZ676BgEuaNUb2F/TwR3BJhED6UnGS5wjtCDgISnEQ6rJFc+iA3/Ud8Ccs=@googlegroups.com
X-Received: by 2002:a05:6512:4887:b0:59a:10c1:8f25 with SMTP id 2adb3069b0e04-59a17d5dac9mr868256e87.41.1766159265966;
        Fri, 19 Dec 2025 07:47:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159265; cv=none;
        d=google.com; s=arc-20240605;
        b=QtnT7thREb2XA1vZuWaJpk/oUQycxN41HswrUK6pA5M9qEHLPnxHYu9lIBiUQ7SXUe
         CQ+G0TM1yRc7W5cjOcr+S3q6OtVc9CMTTa+3rxjoiR3xTRWWkLcVu4AGuTDhG+59uLRa
         nV6izWsx/GUXsSvVNAZH4kLZewY+sWt3prDhyEP/mks2rV7zfkrb3mkQmTk4ySq3BuVe
         SJ3igT7uRlMWRugDdhAkSVgXXZztTWSY/Tt+0WZkcVjlJXaPI/SF64XgCdQh5cK8M7X/
         GZOlLY9efLtZ8i9DaeTasXPZQ01mPyIDUk80cC4B1bjepYRL2XNZUhUT98w3XG9JocvS
         9yRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ZHn8aDcdtAKeJcCs/59KrgcXnzNTM7tjpMFEs44zRkY=;
        fh=ozFm8wx5fErmWGN8160vLINpKmmjKrC+tjNS/zb9dqk=;
        b=VZvMwY/JvYRNWiUFO5c3OrT/ALcsj0lw/B0QGRQ1UiweOwb7oxDb7A4xAnxdVylB9V
         qtX5O7FfN/5JW3NvzpXDwRzYkMRDmt39CWPRd/8+8STJjTHiYQnkL8aGrZ1TDUTeHCOX
         sRYbAdZBTdHx3E1yhfErr+iNyJqcgtxnMIEZqMvGjkobGxCHTNlzMfANeY+kDlcA2YZx
         XMgpfh/tZcfulVNKLrHufJTZ1C6DOASC0Ef9dToQE/SRpwi+t0mz7BBhayH1HaXaXYkk
         ZKxF91aX9kOkVi8zK40tP2UqNU/P83cvo3c1P36YyYZkCIVFrfHM5BaIb91qlvkz/ML1
         0TWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ONyb3VRf;
       spf=pass (google.com: domain of 3oxnfaqukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oXNFaQUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1861bd48si62209e87.8.2025.12.19.07.47.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oxnfaqukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477771366cbso12259175e9.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXGzpRrExZ975U/QaUuFFsGZdqUE1msqVduf8rmeYA5fahWrELtTDzE2ejJ7Ec/KcFuXxCFbasRwNI=@googlegroups.com
X-Received: from wmgp3.prod.google.com ([2002:a05:600c:2043:b0:477:98de:d8aa])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3b8d:b0:477:7725:c16a
 with SMTP id 5b1f17b1804b1-47d1953da58mr36604365e9.10.1766159265020; Fri, 19
 Dec 2025 07:47:45 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:24 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-36-elver@google.com>
Subject: [PATCH v5 35/36] crypto: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b=ONyb3VRf;       spf=pass
 (google.com: domain of 3oxnfaqukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3oXNFaQUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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

Enable context analysis for crypto subsystem.

This demonstrates a larger conversion to use Clang's context
analysis. The benefit is additional static checking of locking rules,
along with better documentation.

Note the use of the __acquire_ret macro how to define an API where a
function returns a pointer to an object (struct scomp_scratch) with a
lock held. Additionally, the analysis only resolves aliases where the
analysis unambiguously sees that a variable was not reassigned after
initialization, requiring minor code changes.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Herbert Xu <herbert@gondor.apana.org.au>
Cc: "David S. Miller" <davem@davemloft.net>
Cc: linux-crypto@vger.kernel.org
---
v4:
* Rename capability -> context analysis.

v3:
* Rebase - make use of __acquire_ret macro for new functions.
* Initialize variables once where we want the analysis to recognize aliases.

v2:
* New patch.
---
 crypto/Makefile                     |  2 ++
 crypto/acompress.c                  |  6 +++---
 crypto/algapi.c                     |  2 ++
 crypto/api.c                        |  1 +
 crypto/crypto_engine.c              |  2 +-
 crypto/drbg.c                       |  5 +++++
 crypto/internal.h                   |  2 +-
 crypto/proc.c                       |  3 +++
 crypto/scompress.c                  | 24 ++++++++++++------------
 include/crypto/internal/acompress.h |  7 ++++---
 include/crypto/internal/engine.h    |  2 +-
 11 files changed, 35 insertions(+), 21 deletions(-)

diff --git a/crypto/Makefile b/crypto/Makefile
index 16a35649dd91..db264feab7e7 100644
--- a/crypto/Makefile
+++ b/crypto/Makefile
@@ -3,6 +3,8 @@
 # Cryptographic API
 #
 
+CONTEXT_ANALYSIS := y
+
 obj-$(CONFIG_CRYPTO) += crypto.o
 crypto-y := api.o cipher.o
 
diff --git a/crypto/acompress.c b/crypto/acompress.c
index be28cbfd22e3..25df368df098 100644
--- a/crypto/acompress.c
+++ b/crypto/acompress.c
@@ -449,8 +449,8 @@ int crypto_acomp_alloc_streams(struct crypto_acomp_streams *s)
 }
 EXPORT_SYMBOL_GPL(crypto_acomp_alloc_streams);
 
-struct crypto_acomp_stream *crypto_acomp_lock_stream_bh(
-	struct crypto_acomp_streams *s) __acquires(stream)
+struct crypto_acomp_stream *_crypto_acomp_lock_stream_bh(
+	struct crypto_acomp_streams *s)
 {
 	struct crypto_acomp_stream __percpu *streams = s->streams;
 	int cpu = raw_smp_processor_id();
@@ -469,7 +469,7 @@ struct crypto_acomp_stream *crypto_acomp_lock_stream_bh(
 	spin_lock(&ps->lock);
 	return ps;
 }
-EXPORT_SYMBOL_GPL(crypto_acomp_lock_stream_bh);
+EXPORT_SYMBOL_GPL(_crypto_acomp_lock_stream_bh);
 
 void acomp_walk_done_src(struct acomp_walk *walk, int used)
 {
diff --git a/crypto/algapi.c b/crypto/algapi.c
index e604d0d8b7b4..abc9333327d4 100644
--- a/crypto/algapi.c
+++ b/crypto/algapi.c
@@ -244,6 +244,7 @@ EXPORT_SYMBOL_GPL(crypto_remove_spawns);
 
 static void crypto_alg_finish_registration(struct crypto_alg *alg,
 					   struct list_head *algs_to_put)
+	__must_hold(&crypto_alg_sem)
 {
 	struct crypto_alg *q;
 
@@ -299,6 +300,7 @@ static struct crypto_larval *crypto_alloc_test_larval(struct crypto_alg *alg)
 
 static struct crypto_larval *
 __crypto_register_alg(struct crypto_alg *alg, struct list_head *algs_to_put)
+	__must_hold(&crypto_alg_sem)
 {
 	struct crypto_alg *q;
 	struct crypto_larval *larval;
diff --git a/crypto/api.c b/crypto/api.c
index 5724d62e9d07..05629644a688 100644
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
index 18e1689efe12..1653a4bf5b31 100644
--- a/crypto/crypto_engine.c
+++ b/crypto/crypto_engine.c
@@ -453,8 +453,8 @@ struct crypto_engine *crypto_engine_alloc_init_and_set(struct device *dev,
 	snprintf(engine->name, sizeof(engine->name),
 		 "%s-engine", dev_name(dev));
 
-	crypto_init_queue(&engine->queue, qlen);
 	spin_lock_init(&engine->queue_lock);
+	crypto_init_queue(&engine->queue, qlen);
 
 	engine->kworker = kthread_run_worker(0, "%s", engine->name);
 	if (IS_ERR(engine->kworker)) {
diff --git a/crypto/drbg.c b/crypto/drbg.c
index 1d433dae9955..0a6f6c05a78f 100644
--- a/crypto/drbg.c
+++ b/crypto/drbg.c
@@ -232,6 +232,7 @@ static inline unsigned short drbg_sec_strength(drbg_flag_t flags)
  */
 static int drbg_fips_continuous_test(struct drbg_state *drbg,
 				     const unsigned char *entropy)
+	__must_hold(&drbg->drbg_mutex)
 {
 	unsigned short entropylen = drbg_sec_strength(drbg->core->flags);
 	int ret = 0;
@@ -848,6 +849,7 @@ static inline int __drbg_seed(struct drbg_state *drbg, struct list_head *seed,
 static inline int drbg_get_random_bytes(struct drbg_state *drbg,
 					unsigned char *entropy,
 					unsigned int entropylen)
+	__must_hold(&drbg->drbg_mutex)
 {
 	int ret;
 
@@ -862,6 +864,7 @@ static inline int drbg_get_random_bytes(struct drbg_state *drbg,
 }
 
 static int drbg_seed_from_random(struct drbg_state *drbg)
+	__must_hold(&drbg->drbg_mutex)
 {
 	struct drbg_string data;
 	LIST_HEAD(seedlist);
@@ -919,6 +922,7 @@ static bool drbg_nopr_reseed_interval_elapsed(struct drbg_state *drbg)
  */
 static int drbg_seed(struct drbg_state *drbg, struct drbg_string *pers,
 		     bool reseed)
+	__must_hold(&drbg->drbg_mutex)
 {
 	int ret;
 	unsigned char entropy[((32 + 16) * 2)];
@@ -1153,6 +1157,7 @@ static inline int drbg_alloc_state(struct drbg_state *drbg)
 static int drbg_generate(struct drbg_state *drbg,
 			 unsigned char *buf, unsigned int buflen,
 			 struct drbg_string *addtl)
+	__must_hold(&drbg->drbg_mutex)
 {
 	int len = 0;
 	LIST_HEAD(addtllist);
diff --git a/crypto/internal.h b/crypto/internal.h
index b9afd68767c1..8fbe0226d48e 100644
--- a/crypto/internal.h
+++ b/crypto/internal.h
@@ -61,8 +61,8 @@ enum {
 /* Maximum number of (rtattr) parameters for each template. */
 #define CRYPTO_MAX_ATTRS 32
 
-extern struct list_head crypto_alg_list;
 extern struct rw_semaphore crypto_alg_sem;
+extern struct list_head crypto_alg_list __guarded_by(&crypto_alg_sem);
 extern struct blocking_notifier_head crypto_chain;
 
 int alg_test(const char *driver, const char *alg, u32 type, u32 mask);
diff --git a/crypto/proc.c b/crypto/proc.c
index 82f15b967e85..5fb9fe86d023 100644
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
index 1a7ed8ae65b0..7aee1d50e148 100644
--- a/crypto/scompress.c
+++ b/crypto/scompress.c
@@ -28,8 +28,8 @@
 struct scomp_scratch {
 	spinlock_t	lock;
 	union {
-		void	*src;
-		unsigned long saddr;
+		void	*src __guarded_by(&lock);
+		unsigned long saddr __guarded_by(&lock);
 	};
 };
 
@@ -38,8 +38,8 @@ static DEFINE_PER_CPU(struct scomp_scratch, scomp_scratch) = {
 };
 
 static const struct crypto_type crypto_scomp_type;
-static int scomp_scratch_users;
 static DEFINE_MUTEX(scomp_lock);
+static int scomp_scratch_users __guarded_by(&scomp_lock);
 
 static cpumask_t scomp_scratch_want;
 static void scomp_scratch_workfn(struct work_struct *work);
@@ -67,6 +67,7 @@ static void crypto_scomp_show(struct seq_file *m, struct crypto_alg *alg)
 }
 
 static void crypto_scomp_free_scratches(void)
+	__context_unsafe(/* frees @scratch */)
 {
 	struct scomp_scratch *scratch;
 	int i;
@@ -101,7 +102,7 @@ static void scomp_scratch_workfn(struct work_struct *work)
 		struct scomp_scratch *scratch;
 
 		scratch = per_cpu_ptr(&scomp_scratch, cpu);
-		if (scratch->src)
+		if (context_unsafe(scratch->src))
 			continue;
 		if (scomp_alloc_scratch(scratch, cpu))
 			break;
@@ -111,6 +112,7 @@ static void scomp_scratch_workfn(struct work_struct *work)
 }
 
 static int crypto_scomp_alloc_scratches(void)
+	__context_unsafe(/* allocates @scratch */)
 {
 	unsigned int i = cpumask_first(cpu_possible_mask);
 	struct scomp_scratch *scratch;
@@ -139,7 +141,8 @@ static int crypto_scomp_init_tfm(struct crypto_tfm *tfm)
 	return ret;
 }
 
-static struct scomp_scratch *scomp_lock_scratch(void) __acquires(scratch)
+#define scomp_lock_scratch(...) __acquire_ret(_scomp_lock_scratch(__VA_ARGS__), &__ret->lock)
+static struct scomp_scratch *_scomp_lock_scratch(void) __acquires_ret
 {
 	int cpu = raw_smp_processor_id();
 	struct scomp_scratch *scratch;
@@ -159,7 +162,7 @@ static struct scomp_scratch *scomp_lock_scratch(void) __acquires(scratch)
 }
 
 static inline void scomp_unlock_scratch(struct scomp_scratch *scratch)
-	__releases(scratch)
+	__releases(&scratch->lock)
 {
 	spin_unlock(&scratch->lock);
 }
@@ -171,8 +174,6 @@ static int scomp_acomp_comp_decomp(struct acomp_req *req, int dir)
 	bool src_isvirt = acomp_request_src_isvirt(req);
 	bool dst_isvirt = acomp_request_dst_isvirt(req);
 	struct crypto_scomp *scomp = *tfm_ctx;
-	struct crypto_acomp_stream *stream;
-	struct scomp_scratch *scratch;
 	unsigned int slen = req->slen;
 	unsigned int dlen = req->dlen;
 	struct page *spage, *dpage;
@@ -232,13 +233,12 @@ static int scomp_acomp_comp_decomp(struct acomp_req *req, int dir)
 		} while (0);
 	}
 
-	stream = crypto_acomp_lock_stream_bh(&crypto_scomp_alg(scomp)->streams);
+	struct crypto_acomp_stream *stream = crypto_acomp_lock_stream_bh(&crypto_scomp_alg(scomp)->streams);
 
 	if (!src_isvirt && !src) {
-		const u8 *src;
+		struct scomp_scratch *scratch = scomp_lock_scratch();
+		const u8 *src = scratch->src;
 
-		scratch = scomp_lock_scratch();
-		src = scratch->src;
 		memcpy_from_sglist(scratch->src, req->src, 0, slen);
 
 		if (dir)
diff --git a/include/crypto/internal/acompress.h b/include/crypto/internal/acompress.h
index 2d97440028ff..9a3f28baa804 100644
--- a/include/crypto/internal/acompress.h
+++ b/include/crypto/internal/acompress.h
@@ -191,11 +191,12 @@ static inline bool crypto_acomp_req_virt(struct crypto_acomp *tfm)
 void crypto_acomp_free_streams(struct crypto_acomp_streams *s);
 int crypto_acomp_alloc_streams(struct crypto_acomp_streams *s);
 
-struct crypto_acomp_stream *crypto_acomp_lock_stream_bh(
-	struct crypto_acomp_streams *s) __acquires(stream);
+#define crypto_acomp_lock_stream_bh(...) __acquire_ret(_crypto_acomp_lock_stream_bh(__VA_ARGS__), &__ret->lock);
+struct crypto_acomp_stream *_crypto_acomp_lock_stream_bh(
+		struct crypto_acomp_streams *s) __acquires_ret;
 
 static inline void crypto_acomp_unlock_stream_bh(
-	struct crypto_acomp_stream *stream) __releases(stream)
+	struct crypto_acomp_stream *stream) __releases(&stream->lock)
 {
 	spin_unlock_bh(&stream->lock);
 }
diff --git a/include/crypto/internal/engine.h b/include/crypto/internal/engine.h
index f19ef376833f..6a1d27880615 100644
--- a/include/crypto/internal/engine.h
+++ b/include/crypto/internal/engine.h
@@ -45,7 +45,7 @@ struct crypto_engine {
 
 	struct list_head	list;
 	spinlock_t		queue_lock;
-	struct crypto_queue	queue;
+	struct crypto_queue	queue __guarded_by(&queue_lock);
 	struct device		*dev;
 
 	struct kthread_worker           *kworker;
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-36-elver%40google.com.
