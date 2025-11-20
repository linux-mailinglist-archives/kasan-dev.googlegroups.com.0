Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSPA7TEAMGQEVV4UCSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 42158C74CBD
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:14:19 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-6411c626af4sf1097800a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:14:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651658; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fq0QAQORuKwhIPzT9T4OSzNLNPsevHyycnm+vtdQ7ZE2Fmfvd+wpGeHN5qJGc5PyNT
         StR9aOpsSPdEBWoh/Wvxiq8B1ezgPO+EXJtcKRdKLLzuKkKH7b/Yybs6WFG+OHjLTdeQ
         b/DBqP9wk4UxKY8QcqUOGyjeBvhGoKv9v6sWH1BuSre+YysRx3e3HC57HiFUtkeEhPnA
         76Kr5x7vgnhwlNEOsFS4pZqLDv9dozO0LBNmPwRAlUuqvqvj32/GT3581k2/NFIR0nY1
         9dNwWS5nuIr1WNXMpDZkkuJMTVmhp44Bh8om/ybtsbodyzcV4vYa9VIro0ZGXVRjzQuR
         joIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=xBMhcST/Cas6AfOkT6bTiS/W01jorQWCuf8z55DDI+Q=;
        fh=rHpJrnSGs31BWzTbUupbh6blDy3rTAYCtnBBunq8/pw=;
        b=CNKnfhnEjTAgiE4L7seuiMKgfF9Etwz5JuxOwnx9/gfFlA1NPeh/a2i/rMvFQOl9kl
         Kh983vHe13NMTazxTs8y+GxlJ3F81j25AgPSHW8E6bvYvZEoTHKEd7FTYm/q+f265JzX
         nBqJMn1iJX7o7TgcmmIZe6+e7ZqHb/cmIf2U2DHJX++vkz3ZQSshUIRVXpFEP/rhnVL2
         X1BtN7/axA0e2zevan7cDhpXzzAEOU1lJSuOzRIuJBjGHqqIp/+rwckrXZiKNv+CjBev
         NaYz0eAC0GiZZF7FEgIJrr6ZCyM3ZV2POoTKZ4432Z0o2aznDUPHBzssl6XbC2jiM3pD
         hBnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JfQDmspg;
       spf=pass (google.com: domain of 3rzafaqukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RzAfaQUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651658; x=1764256458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xBMhcST/Cas6AfOkT6bTiS/W01jorQWCuf8z55DDI+Q=;
        b=KyZldTouIFkhjIEpCujh/0MQ9N9deFjbHZEmelHj68HB30EhKl9bFp+c5HNrv4MxaZ
         P0Dpyp8J/yXPKqsmygIbTouKDnJvQ5qR4TECdRFSuja3rNUuJWC8VKn5zVJWCzaZgYtw
         corGBFVWITSQpldCqRWRERjSzkHe41/jR67DvKqjdwRhdwQuigjQIX+A2JP5AZROfX1O
         619nTIiPK24Wlr2OryY0Fedd0nRc0CL4AtelphFMwCW121wPjRIdpHBgU7ztxdI+GJvI
         HbHCiYlXo5Do5jCXY+HIwBFP1G37MrBACXzEtLRqYQJt6mIyMIdEhcM1TuiGwmrvsFhL
         GfjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651658; x=1764256458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xBMhcST/Cas6AfOkT6bTiS/W01jorQWCuf8z55DDI+Q=;
        b=p+2LceIS4QMHS0GsvozCfuaTGEH62X16/toJ3OBtISrV5dhytao+u5Lk/mJ2msDoSO
         lZWRbe4MUuBaz57D5ahJjwaqwwSivAGuIqQu0GhMFyOTDMuv2a0ilQs87AkiKbuPgOj3
         V6Iz9PPq4sS79W7Q/AxwnPo6eXdRDelBQCroWEyDTsonTUdc/YZr3wUCvMfDPZkplz+Q
         2FRpUW2iF44B7eU02++n67OYhFxw2bEVNeE5+n5Xh2LhLhvwBcYIztZoSZy3oRBEMNDB
         UOTQaFeNh4uPyK6Raoist/dYtMPcdcpEnUe321Hqe8KhMYrw69i39L6YguXggA7GbvHh
         t86A==
X-Forwarded-Encrypted: i=2; AJvYcCXH5gBo2lfbZJYGhtKLoLtTH22nm+a2ckLrWwqB2YyT7H9z3HSr8X44BdxwnVl9F1c05EfhiA==@lfdr.de
X-Gm-Message-State: AOJu0YwYgwnUpiAeuGU5MOOyA/tOdXVNc92UuY3bPdbCZbRmN6T8v+KY
	hOTrwjCiyuwyNblCrlHHzIfflM0oyD9X+kRsUysaADR0QkMfBIS48XWq
X-Google-Smtp-Source: AGHT+IGkpeeQ4CVMoQ+KULtRDMJXdjz2o9pnaY/Wp6VwLXQU8LKgLeMbCO20U8GixvACVcekc3Bjqg==
X-Received: by 2002:a05:6402:27cc:b0:643:8301:d107 with SMTP id 4fb4d7f45d1cf-645364828ddmr3172459a12.30.1763651658399;
        Thu, 20 Nov 2025 07:14:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YlJ6wKqE/9yAiQwTVRj5dx9ab5Wj5qp4R2DM08p6UkWQ=="
Received: by 2002:a05:6402:3048:20b0:644:f98a:dce0 with SMTP id
 4fb4d7f45d1cf-6453640f8bfls969029a12.2.-pod-prod-07-eu; Thu, 20 Nov 2025
 07:14:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzyX0TL01Wqt0tGiR7C6WdGmKQ4/dn1X64Z7dJQprM6yyvsCg4HqlRjCNuGyyZSpmLEuu/vYR332s=@googlegroups.com
X-Received: by 2002:a05:6402:2348:b0:640:ebe3:dd55 with SMTP id 4fb4d7f45d1cf-645363e9be5mr3139703a12.6.1763651655728;
        Thu, 20 Nov 2025 07:14:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651655; cv=none;
        d=google.com; s=arc-20240605;
        b=dDzfHLwRvcepuhHMopRbStyWBL7qDSs9xB0CFomfiNoNMhlU9z2LsjoeUJ4kIb+d3L
         8cwgC8MLb+d5Atl94t4SADUeIM7GLCRTf8rIxEQpF00jLkb2CuwKvI8uV1b2eQzPhhK7
         FOV8086LELhM772lFFDRKlrzntvS8qEtI2S2vNWMVdeppdz+JUKEhypeMCTeqthKAUqq
         KB3H9ot5sXHMk3TFD2i32T7zA8Pe/7EB8HVgTlgYCSoNf8PN5jjEbolOzRCceRrZ8fIn
         whs+IhtGIkXtIsr+VkdcLAz2E/rOcpaBt/PsNvae3cZux7xexWId5m91eNjSctKfPOb1
         XKiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=j4pKPAxAMb/xt3eYfYDMHUG0PZ5TfjoAzjHvbIiVoEA=;
        fh=5HjHO2GDds+BhnBHJ6N1lKv4z/kUNy4MUoLIs1iWtkQ=;
        b=K7k/4XFFvI4fg7UzYYAZQ4ExzWDgciyId1k5VajI+fCLybFuP32GLHf1pBpRy3Kuj1
         3arz74Bph6aa/xFJK5HKYb1uGlk5TOj9YrlaRcbUgBwmMTK1/CEwFXg5bP4hT0GqTiBy
         0pIoXjbLKJGIlj+gnUmAP8rGD5VSB+4gqFeobdyftPI28qUHuP++rL+1m3KoiDHXlmzL
         ptRGWvmJqBNgM0yzTTYZvxT0rmwDBaEczIHy8W0TI2Cfhnu9A61jTQV95vdMQoEBakwc
         gNDZd6+vC3Wq0Nb3NmPdvJqV3bx8o6YMY3G92HUFRQHg//aro5vjj991Ap6aD9Ct3hd9
         1gnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JfQDmspg;
       spf=pass (google.com: domain of 3rzafaqukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RzAfaQUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6453648a420si24161a12.8.2025.11.20.07.14.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:14:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rzafaqukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-429c5da68e5so544297f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:14:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUB8GS/rJsk0f9FlevUrVV9AcOwf8KBcun+jiVNidV0Py/6UtvdvrDPwWH2cH4D02gMEKt5Kc15/U8=@googlegroups.com
X-Received: from wrdk8.prod.google.com ([2002:adf:b348:0:b0:42b:30da:e035])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:adf:e987:0:b0:429:58f:26f
 with SMTP id ffacd0b85a97d-42cba7696b1mr2716676f8f.24.1763651655219; Thu, 20
 Nov 2025 07:14:15 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:59 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-35-elver@google.com>
Subject: [PATCH v4 34/35] crypto: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b=JfQDmspg;       spf=pass
 (google.com: domain of 3rzafaqukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RzAfaQUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
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
index e430e6e99b6a..2e2560310e5a 100644
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
index dbe4c8bb5ceb..9684d952fdfd 100644
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-35-elver%40google.com.
