Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBNEWDDAMGQEYIM5H6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C0C57B85011
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:07:02 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-45f28bcd160sf1522245e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:07:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204422; cv=pass;
        d=google.com; s=arc-20240605;
        b=OSvfeRc+V2o8QMek3oVKxFasH2UxjUV26AAik1wX+uBhAioQu9Ik7WKyNB+S/6x+TV
         0ru2uHUIv6/KtDiB6GlMnFiKYelFk+mULw7+rFWJSjCnW8oDxn1uh3ZgMmgNWBGOJw/7
         sQceeisuSjRasvOnRGjZTBmE6ELlKo8ULRubzhXIGMbpm/MYz4kkuQcNqa63OEdMjQqp
         YCFTUilgJc3OGPe4UVhG65KlCsw1mri00TjY3pPUAQrs94xyPAki9rz+SyMNt8Lv5koF
         Sbvav/O40FHhdNap19Y6A7d7TtVYkFzigejvOlaIEL9kJuWEj0jdlqkOOYuKiHfewXAL
         EArA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=wsaAJ29MKVXlZs8CzRlPZWzWhKOuPkLOpCkp4/UjREs=;
        fh=19lJAvILJTU0JThQyEB+KxmQBZFq6QVOYvWIQoApC50=;
        b=Sd8DrEqle+gt+JmjQoq1s3LufGFimGG6QsOyNmCfaCOznENJ/5qYH+a649jdxDXzo6
         VQcMMYYH26tFeoH6bmXWxSky77JfNE2qm/bSkCGg+sMyyk5F3i1XoZ965El0OaepJJb/
         r8u/huj4WXEL2SZvLOS6DBv0TKJbekv+ojSDdZ4YetM+2N7z/fQzZU7ycaUjWDRakKkA
         YPYAW2HyqPheGypxhNrh5WUmfsPbiRdWmFSjj2JdCYUTAQAoUpPqcTNn6QVYafG17i9t
         rC7s+v1zxtO3E4wbAw7F6u70oUkr/IlpuuDTu0bYKAOxKxRmK9QAzegqmClc3k98lsT+
         inaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p0y39jNG;
       spf=pass (google.com: domain of 3ahlmaaukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AhLMaAUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204422; x=1758809222; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wsaAJ29MKVXlZs8CzRlPZWzWhKOuPkLOpCkp4/UjREs=;
        b=mllsQHqMuNdX3jem7vMiLWykreNAA1CGVjX61i/tJw3INAa0Lm2P5HQ9S+9j57x5od
         EVImHLKLZXu1bVyhJumL1CJUjhvSPMWPExhwphqGl+/yfBczVm4L/1uKmNxELtXH+uE9
         PZJgqWPq1m0TA8kyU2A+V2bcl6bW/v+D5NjGihSLKDiSVQM9D19fL+TfWPyUUOtT1Wjq
         Todf1HzEGdXNzUWcETNSiEPfTFUTMdNa6APjKfWMbNOTM6DMblRufJTyFR+RXyloMWO/
         NKnVXYa5ibXqRyvrcZ2k2Pjw4lV/pWy4nADXdPFsws8/0rY3tnP//o1gvLYywfeMJkG1
         +log==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204422; x=1758809222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wsaAJ29MKVXlZs8CzRlPZWzWhKOuPkLOpCkp4/UjREs=;
        b=ihLrczH1RHgnaQusVj/nHL/AembKrMia7J2mUNYsPDrnY6+Qnt5QzBtu/uzLpsqUY7
         e/wgQA6waxDiB9h+mC02D0qoHqYUg17+bhHvMRYdH8akCRzfYH+g7SvM7LA/jhl1jJHs
         YgViBM4+hPnrsFM+34vTA/P4g8lUMm/roS6MB3JQdJ6vElAM59PNKar/GKIAPsZ+6zhg
         3wqmmKVX1F8TIRpM6ALmIWHCcz9pbklsrLeljn546Kt49paYm2BXi0o595fdPYmLD3y8
         DCijyNCpwques78MAtuEYj7ZAeJHxDCSsZI2dH2qJnIniz2wv4xNyNqHVoUAzbnOukji
         nLLQ==
X-Forwarded-Encrypted: i=2; AJvYcCX1CRHOgYXsj8w7QFv4NeeqRSQ+j13BoS2dm3yLUIwm24VXGelr/GEWZRAg1w7y5DTuirKeDw==@lfdr.de
X-Gm-Message-State: AOJu0YwEEl+ZoYrJ+jcrMMrh6H5fI5fHEL1FU02Vcfy/wrV2x6nbRukU
	quRHK29nEp6sDsM96fhdkY+UZeWvqofFZYhgSuNR95eekP7Yz7DZcpPv
X-Google-Smtp-Source: AGHT+IEFMRNB3kIDMt5mlvvI7DKaOpeclgBIjEAuYSFLg3QC0hXIGLF7coHHyyjESTBf/Dz7zAM9Gw==
X-Received: by 2002:a05:600c:6815:b0:45d:d0af:e22a with SMTP id 5b1f17b1804b1-462072d776fmr33366225e9.7.1758204422117;
        Thu, 18 Sep 2025 07:07:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4YAfFozLf2+A8fg8jrKpNxRU/KhgQY1drtV0TW4s2jlA==
Received: by 2002:a05:600c:a46:b0:45b:6a62:c847 with SMTP id
 5b1f17b1804b1-4653f351759ls5351405e9.0.-pod-prod-08-eu; Thu, 18 Sep 2025
 07:06:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUY64nrSoa3VndG7mGpvFTJLGtud/r//sj7lvD+oydy5cec0UKoSvuTIsuYp2y0QJXG3kg7Pu8ElmQ=@googlegroups.com
X-Received: by 2002:a05:600c:450c:b0:45d:f7f9:9822 with SMTP id 5b1f17b1804b1-46202a0ed47mr60093605e9.12.1758204419525;
        Thu, 18 Sep 2025 07:06:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204419; cv=none;
        d=google.com; s=arc-20240605;
        b=d5eJxCigw7lFkNVjPr7800AaYgiGIA+apwWsA3lWydu7vKN1w1noW3YYwDYPUZ+vP+
         oo4HIz5Yg5+dTOCd+Q2QrGPo7dgp02yUuc1a6vWyc60voZ9rt0ibBYLqX7SwBIGGDOV1
         YEVTB9b1rSq3Yo99vB9lwOaNg8ClGDrRRuFL4YuzysKyqF0RrJEnXwZ/cQE9MhlSywXH
         p8737Fxzady7modKTJCMPQEZBDaSVoV6msSAz2OKuFgjmU9Ohr3da3pSzWafIEjkash6
         eQySOPlony+smpYi0sRWehLAqdJfDIDc4do8xzCAHXESR3lttaD5NUhXtke9MYj2n1HR
         NtyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Z5tu8oxzXQKTnOUiHAzfcXoFAwF2lpCAIFKrvKZ236c=;
        fh=OQhv9uCJnmRYTdDtXkFrrYW6RTfXnR9TcluAc0TT4Wo=;
        b=MMgFyyHoexycTsX2Om4TWL5+oO38Kx4XIa+BpnwSxmK9SWI+VoXe5WqsMpHwDPiny6
         m8ZwvDzGTamYNC5n3Mk6iSEKbUMBPt9co3ghtV7WFyoGa8TIAyyuTTXx1N+nSQcA+Nto
         rL/c7AZfsxD06+iWC9PquQQfeZ4l03i8+KiZSo9liXyMbUa65pBFkv7ufvHUlLrkEZLQ
         8nc0zCb2Co/uXSGOn59fZGqpK/L8cpeQVe2/1vbvI7Aji/eS7GV9kH0aKWEXOMoW3Q+z
         CPgHmLubTzI0L3ZjZTjy0R8+hSQKMYJU3MwWdapPlqIIl2YtwXSMTChGl8bgsy/Rmknn
         oP9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p0y39jNG;
       spf=pass (google.com: domain of 3ahlmaaukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AhLMaAUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee0fba8f88si28489f8f.3.2025.09.18.07.06.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ahlmaaukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45b920a0c89so4648295e9.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVGFvXLiISXuzxG/AS9Lu1tUQ9sjB4Z0CKF0EZSPUBhzjcoZVuzdXvU7QeSAPx3bnSpiVl5d0rs0GI=@googlegroups.com
X-Received: from wmby18.prod.google.com ([2002:a05:600c:c052:b0:45b:883d:4704])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:c4b8:b0:45b:8477:de1a
 with SMTP id 5b1f17b1804b1-46201f8a98fmr48626095e9.7.1758204418672; Thu, 18
 Sep 2025 07:06:58 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:45 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-35-elver@google.com>
Subject: [PATCH v3 34/35] crypto: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
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
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p0y39jNG;       spf=pass
 (google.com: domain of 3ahlmaaukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AhLMaAUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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
index 6c5d59369dac..e73c50a54119 100644
--- a/crypto/Makefile
+++ b/crypto/Makefile
@@ -3,6 +3,8 @@
 # Cryptographic API
 #
 
+CAPABILITY_ANALYSIS := y
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
index c651e7f2197a..fb87f3716426 100644
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
+	__capability_unsafe(/* frees @scratch */)
 {
 	struct scomp_scratch *scratch;
 	int i;
@@ -101,7 +102,7 @@ static void scomp_scratch_workfn(struct work_struct *work)
 		struct scomp_scratch *scratch;
 
 		scratch = per_cpu_ptr(&scomp_scratch, cpu);
-		if (scratch->src)
+		if (capability_unsafe(scratch->src))
 			continue;
 		if (scomp_alloc_scratch(scratch, cpu))
 			break;
@@ -111,6 +112,7 @@ static void scomp_scratch_workfn(struct work_struct *work)
 }
 
 static int crypto_scomp_alloc_scratches(void)
+	__capability_unsafe(/* allocates @scratch */)
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-35-elver%40google.com.
