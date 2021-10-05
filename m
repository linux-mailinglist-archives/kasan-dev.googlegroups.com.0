Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRXA6CFAMGQEAL5MUNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id D1B20422431
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:22 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id x33-20020a0565123fa100b003fcfd99073dsf16646794lfa.6
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431622; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kpm5XbBJhi3RKAkpF0ZRMdUEybfqg7FOrKnAkvxMK4nfk8kJRBxBXMRnWG+EeY3HUV
         jJHM80RehEI3HVdBjB0Q9jC2p/TUYuhCO4asnTaO+quWdWpd9vB6YgZxrlFkfFL2VcGA
         1ihH4uWO4DgmfP5REitCWR4t3naQQPm0th6kRekvqpp4cQvu1ZnuN2RoYsvwbUuIa5lI
         5ZInlqedzac+M9FsFoKe1RQLxOL0+LKDMY3IQAnha2sY55Nen72HIYAwA6Vq0saigoUT
         v+/udL7+v3Oe1MOvpPKU6H1wuWnPeTNH/rc23p+XCM9TLWe1mwSlw+l1xdgHzSU2biBD
         kaBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=YZdRmBdtGG18hoaeuEox32Zu6mqxUTkAr5hf3OywGvQ=;
        b=sRz7Qg94QJB6zZxGrZhg2d/A/CHT3Okj7fPPu9rIucz8zEIthf4l8y4b7jR39tIG+S
         khkjMTRQSNOhZfkBv4MO1u68RC6ESggKvgbRC95xRMGaE2PXvGf0fTYM1ljjDYiRfLQw
         fLbFkfuU3FHBuO5tn72hROKP5VOH1fOvZ6dTE4SyNYLSFOFH3MQD9lGeBdW3o30siZFn
         nQwKazVBy2qFvFg9+R6l+mVuRdEEvgkIKJsB/CHHPKjV+Ba1wePoVrTztUP+ZB3yX+9J
         XYrObjphUwqqnjShKpdPPRl7VceHZ9iWKcWtwkrZD1E/5zl8dVTKJRYwUnxIp5tRZtED
         Fv7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FEybRNu8;
       spf=pass (google.com: domain of 3rdbcyqukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RDBcYQUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YZdRmBdtGG18hoaeuEox32Zu6mqxUTkAr5hf3OywGvQ=;
        b=UccyVs/t4TXMO7hx5+7jsMZUVXk1RwnhsR1laTF1V0g683fduSzPaJ6Hbxsd+h5Jb5
         fLkB8yPIM4++i+8Zn58Pn5EYO+q/w2ggobsuxVe7meZXpc1GK1gjUGY4+zHwgbeeDLE9
         Z1mb9ylDl722L0rXs2e7vLAOU1HUXzI8oixC6ELbuhHO3ApDJh9g2mJDVb54JhAD3WS6
         FAdHLD8oRkcG1xW1afXlRHV4iKe1ahBWK5VIWhUbUTau81k5Y9t51IrEr2zbC3H4cXzJ
         NHGOt7EG6nErDlavK/kLON2rgd9Ztf95SQwJLFpQezZbSeuPkFCTMqQn5ECzUJFBfHUp
         EibQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YZdRmBdtGG18hoaeuEox32Zu6mqxUTkAr5hf3OywGvQ=;
        b=Vd2/LeKu7xCOatwG6+wVLeQFkyr5eBz7+F+40V01xbo6IK/9SJAD3DrgpDZv1mQwjQ
         z3M4vFbUDOt5QRE6usn79yoVFAacS3sYsnES66W7uJjs9ESpPKiSuIyEBXjM38AbKCn6
         +W2zte5IFqfG0vXcoQMoAN2pSWZ/UNAvnxIDPuZUKI8g1CHeXnB75SDQRGupP9OIQ5TF
         Zus9+2evwYYW4U8GMsV2pevShpHwvihJUqMr+9WhVVBM2U+9TTgDEq+Anzg1GR5kye7y
         7cEME7WEdpDK1onzHy/MyZ9XEtx6v8T9G+KF/tq5vuMgdC+dp/JvVnCeyY4YZuVcsHQP
         a/JA==
X-Gm-Message-State: AOAM5316+mTgrXjv2Yb9m/MA8cIJZy6Mo5ARAVSZNt7G8qalAwA9TUuh
	jUQ6EzPvHXhtHEXgCitIJYM=
X-Google-Smtp-Source: ABdhPJz/SPAsutFasOrhctLh8s5XWP5JscsAScqZBB9+aDND3v+susXUIG0rjXe2SIYQaUgzWqOrKg==
X-Received: by 2002:ac2:51cb:: with SMTP id u11mr2755061lfm.139.1633431622426;
        Tue, 05 Oct 2021 04:00:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3994:: with SMTP id j20ls28881lfu.3.gmail; Tue, 05
 Oct 2021 04:00:21 -0700 (PDT)
X-Received: by 2002:a05:6512:114e:: with SMTP id m14mr2738428lfg.322.1633431621276;
        Tue, 05 Oct 2021 04:00:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431621; cv=none;
        d=google.com; s=arc-20160816;
        b=bbI5IWj3ZSOqx6d6uKmH4QZUNscXcU4DpNL1LfBtm4rvy28AFU4Uf0NJk3YOQGwuF8
         CGDzSs0kJhPhONQKiZfgKDziANnvljFvhqJu3tyLz407lJMokZi8U2j8NFOv786vqSlG
         ZFJ2f1bXtAz0mZyNu80rNZbuZaYq1xfGweVHn+byv00Jm6EtAoUVkBaG54+gr9Um3jPn
         Ye/tk943B8AjBX+ZEwjmAQKrsB7YeMVUmhRMH25LQFQszEpEJD1U3rVC2gp64vs3FS/s
         SvqDfyLp7TWBPAviZIrCxCfqbqL4JrFzKXd+atxOmFvhPnDSWbFPkX0XZHvdOSvua/bN
         6JNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rIwmDVerwfzKdUsq5VTaUgCNEFe/HMrrASoB/MaRzu4=;
        b=irh6hUi8ZmrI9C3wFOrpoc/5qxn52HKmmM6AwkmOKhy4XZhLooYZxyIjxZBHMdxy6Y
         YVUN9RiAa6Crjg83DU7fViR2vf3IR3yBKwNjHgdb1n90Z53hbWptijD/q4FN9D0UT7yf
         x9rwTWQwhYxsM3G42cXeThnGjgsfne9sSNAFXNhxhdRYWmxT3mOpkwsaN5FhaIlldzrD
         GDDj9LSb2lTI/uY+biUpFJOrZRPqtAs1+Ss4oikRw5V8v5sun3dH58JStgw/zLSrVl5k
         H5smTFkRIVFjVwqvU97I1bMp+naYXjPKuwU4Q53cv2oUHy/IMd4rMp3YZ8rT35FcOzoS
         euHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FEybRNu8;
       spf=pass (google.com: domain of 3rdbcyqukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RDBcYQUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a3si1125097lji.6.2021.10.05.04.00.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rdbcyqukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id e12-20020a056000178c00b001606927de88so5571912wrg.10
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:21 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a1c:7e53:: with SMTP id z80mr2649588wmc.152.1633431620500;
 Tue, 05 Oct 2021 04:00:20 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:58 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-17-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 16/23] locking/atomics, kcsan: Add instrumentation
 for barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FEybRNu8;       spf=pass
 (google.com: domain of 3rdbcyqukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3RDBcYQUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Adds the required KCSAN instrumentation for barriers of atomics.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/atomic/atomic-instrumented.h | 135 ++++++++++++++++++++-
 scripts/atomic/gen-atomic-instrumented.sh  |  41 +++++--
 2 files changed, 166 insertions(+), 10 deletions(-)

diff --git a/include/linux/atomic/atomic-instrumented.h b/include/linux/atomic/atomic-instrumented.h
index a0f654370da3..5d69b143c28e 100644
--- a/include/linux/atomic/atomic-instrumented.h
+++ b/include/linux/atomic/atomic-instrumented.h
@@ -45,6 +45,7 @@ atomic_set(atomic_t *v, int i)
 static __always_inline void
 atomic_set_release(atomic_t *v, int i)
 {
+	kcsan_release();
 	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_set_release(v, i);
 }
@@ -59,6 +60,7 @@ atomic_add(int i, atomic_t *v)
 static __always_inline int
 atomic_add_return(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_add_return(i, v);
 }
@@ -73,6 +75,7 @@ atomic_add_return_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_add_return_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_add_return_release(i, v);
 }
@@ -87,6 +90,7 @@ atomic_add_return_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_add(i, v);
 }
@@ -101,6 +105,7 @@ atomic_fetch_add_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_add_release(i, v);
 }
@@ -122,6 +127,7 @@ atomic_sub(int i, atomic_t *v)
 static __always_inline int
 atomic_sub_return(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_sub_return(i, v);
 }
@@ -136,6 +142,7 @@ atomic_sub_return_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_sub_return_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_sub_return_release(i, v);
 }
@@ -150,6 +157,7 @@ atomic_sub_return_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_sub(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_sub(i, v);
 }
@@ -164,6 +172,7 @@ atomic_fetch_sub_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_sub_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_sub_release(i, v);
 }
@@ -185,6 +194,7 @@ atomic_inc(atomic_t *v)
 static __always_inline int
 atomic_inc_return(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_return(v);
 }
@@ -199,6 +209,7 @@ atomic_inc_return_acquire(atomic_t *v)
 static __always_inline int
 atomic_inc_return_release(atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_return_release(v);
 }
@@ -213,6 +224,7 @@ atomic_inc_return_relaxed(atomic_t *v)
 static __always_inline int
 atomic_fetch_inc(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_inc(v);
 }
@@ -227,6 +239,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
 static __always_inline int
 atomic_fetch_inc_release(atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_inc_release(v);
 }
@@ -248,6 +261,7 @@ atomic_dec(atomic_t *v)
 static __always_inline int
 atomic_dec_return(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_return(v);
 }
@@ -262,6 +276,7 @@ atomic_dec_return_acquire(atomic_t *v)
 static __always_inline int
 atomic_dec_return_release(atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_return_release(v);
 }
@@ -276,6 +291,7 @@ atomic_dec_return_relaxed(atomic_t *v)
 static __always_inline int
 atomic_fetch_dec(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_dec(v);
 }
@@ -290,6 +306,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
 static __always_inline int
 atomic_fetch_dec_release(atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_dec_release(v);
 }
@@ -311,6 +328,7 @@ atomic_and(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_and(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_and(i, v);
 }
@@ -325,6 +343,7 @@ atomic_fetch_and_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_and_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_and_release(i, v);
 }
@@ -346,6 +365,7 @@ atomic_andnot(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_andnot(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_andnot(i, v);
 }
@@ -360,6 +380,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_andnot_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_andnot_release(i, v);
 }
@@ -381,6 +402,7 @@ atomic_or(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_or(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_or(i, v);
 }
@@ -395,6 +417,7 @@ atomic_fetch_or_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_or_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_or_release(i, v);
 }
@@ -416,6 +439,7 @@ atomic_xor(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_xor(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_xor(i, v);
 }
@@ -430,6 +454,7 @@ atomic_fetch_xor_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_xor_release(int i, atomic_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_xor_release(i, v);
 }
@@ -444,6 +469,7 @@ atomic_fetch_xor_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_xchg(atomic_t *v, int i)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_xchg(v, i);
 }
@@ -458,6 +484,7 @@ atomic_xchg_acquire(atomic_t *v, int i)
 static __always_inline int
 atomic_xchg_release(atomic_t *v, int i)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_xchg_release(v, i);
 }
@@ -472,6 +499,7 @@ atomic_xchg_relaxed(atomic_t *v, int i)
 static __always_inline int
 atomic_cmpxchg(atomic_t *v, int old, int new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_cmpxchg(v, old, new);
 }
@@ -486,6 +514,7 @@ atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 static __always_inline int
 atomic_cmpxchg_release(atomic_t *v, int old, int new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_cmpxchg_release(v, old, new);
 }
@@ -500,6 +529,7 @@ atomic_cmpxchg_relaxed(atomic_t *v, int old, int new)
 static __always_inline bool
 atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic_try_cmpxchg(v, old, new);
@@ -516,6 +546,7 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 static __always_inline bool
 atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic_try_cmpxchg_release(v, old, new);
@@ -532,6 +563,7 @@ atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 static __always_inline bool
 atomic_sub_and_test(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_sub_and_test(i, v);
 }
@@ -539,6 +571,7 @@ atomic_sub_and_test(int i, atomic_t *v)
 static __always_inline bool
 atomic_dec_and_test(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_and_test(v);
 }
@@ -546,6 +579,7 @@ atomic_dec_and_test(atomic_t *v)
 static __always_inline bool
 atomic_inc_and_test(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_and_test(v);
 }
@@ -553,6 +587,7 @@ atomic_inc_and_test(atomic_t *v)
 static __always_inline bool
 atomic_add_negative(int i, atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_add_negative(i, v);
 }
@@ -560,6 +595,7 @@ atomic_add_negative(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add_unless(atomic_t *v, int a, int u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_fetch_add_unless(v, a, u);
 }
@@ -567,6 +603,7 @@ atomic_fetch_add_unless(atomic_t *v, int a, int u)
 static __always_inline bool
 atomic_add_unless(atomic_t *v, int a, int u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_add_unless(v, a, u);
 }
@@ -574,6 +611,7 @@ atomic_add_unless(atomic_t *v, int a, int u)
 static __always_inline bool
 atomic_inc_not_zero(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_not_zero(v);
 }
@@ -581,6 +619,7 @@ atomic_inc_not_zero(atomic_t *v)
 static __always_inline bool
 atomic_inc_unless_negative(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_inc_unless_negative(v);
 }
@@ -588,6 +627,7 @@ atomic_inc_unless_negative(atomic_t *v)
 static __always_inline bool
 atomic_dec_unless_positive(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_unless_positive(v);
 }
@@ -595,6 +635,7 @@ atomic_dec_unless_positive(atomic_t *v)
 static __always_inline int
 atomic_dec_if_positive(atomic_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_dec_if_positive(v);
 }
@@ -623,6 +664,7 @@ atomic64_set(atomic64_t *v, s64 i)
 static __always_inline void
 atomic64_set_release(atomic64_t *v, s64 i)
 {
+	kcsan_release();
 	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_set_release(v, i);
 }
@@ -637,6 +679,7 @@ atomic64_add(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_add_return(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_add_return(i, v);
 }
@@ -651,6 +694,7 @@ atomic64_add_return_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_add_return_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_add_return_release(i, v);
 }
@@ -665,6 +709,7 @@ atomic64_add_return_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add(i, v);
 }
@@ -679,6 +724,7 @@ atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add_release(i, v);
 }
@@ -700,6 +746,7 @@ atomic64_sub(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_sub_return(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_sub_return(i, v);
 }
@@ -714,6 +761,7 @@ atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_sub_return_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_sub_return_release(i, v);
 }
@@ -728,6 +776,7 @@ atomic64_sub_return_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_sub(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_sub(i, v);
 }
@@ -742,6 +791,7 @@ atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_sub_release(i, v);
 }
@@ -763,6 +813,7 @@ atomic64_inc(atomic64_t *v)
 static __always_inline s64
 atomic64_inc_return(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_return(v);
 }
@@ -777,6 +828,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_inc_return_release(atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_return_release(v);
 }
@@ -791,6 +843,7 @@ atomic64_inc_return_relaxed(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_inc(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_inc(v);
 }
@@ -805,6 +858,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_inc_release(atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_inc_release(v);
 }
@@ -826,6 +880,7 @@ atomic64_dec(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_return(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_return(v);
 }
@@ -840,6 +895,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_return_release(atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_return_release(v);
 }
@@ -854,6 +910,7 @@ atomic64_dec_return_relaxed(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_dec(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_dec(v);
 }
@@ -868,6 +925,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_dec_release(atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_dec_release(v);
 }
@@ -889,6 +947,7 @@ atomic64_and(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_and(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_and(i, v);
 }
@@ -903,6 +962,7 @@ atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_and_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_and_release(i, v);
 }
@@ -924,6 +984,7 @@ atomic64_andnot(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_andnot(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_andnot(i, v);
 }
@@ -938,6 +999,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_andnot_release(i, v);
 }
@@ -959,6 +1021,7 @@ atomic64_or(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_or(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_or(i, v);
 }
@@ -973,6 +1036,7 @@ atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_or_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_or_release(i, v);
 }
@@ -994,6 +1058,7 @@ atomic64_xor(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_xor(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_xor(i, v);
 }
@@ -1008,6 +1073,7 @@ atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_xor_release(i, v);
 }
@@ -1022,6 +1088,7 @@ atomic64_fetch_xor_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_xchg(atomic64_t *v, s64 i)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_xchg(v, i);
 }
@@ -1036,6 +1103,7 @@ atomic64_xchg_acquire(atomic64_t *v, s64 i)
 static __always_inline s64
 atomic64_xchg_release(atomic64_t *v, s64 i)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_xchg_release(v, i);
 }
@@ -1050,6 +1118,7 @@ atomic64_xchg_relaxed(atomic64_t *v, s64 i)
 static __always_inline s64
 atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_cmpxchg(v, old, new);
 }
@@ -1064,6 +1133,7 @@ atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 static __always_inline s64
 atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_cmpxchg_release(v, old, new);
 }
@@ -1078,6 +1148,7 @@ atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new)
 static __always_inline bool
 atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic64_try_cmpxchg(v, old, new);
@@ -1094,6 +1165,7 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 static __always_inline bool
 atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic64_try_cmpxchg_release(v, old, new);
@@ -1110,6 +1182,7 @@ atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 static __always_inline bool
 atomic64_sub_and_test(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_sub_and_test(i, v);
 }
@@ -1117,6 +1190,7 @@ atomic64_sub_and_test(s64 i, atomic64_t *v)
 static __always_inline bool
 atomic64_dec_and_test(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_and_test(v);
 }
@@ -1124,6 +1198,7 @@ atomic64_dec_and_test(atomic64_t *v)
 static __always_inline bool
 atomic64_inc_and_test(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_and_test(v);
 }
@@ -1131,6 +1206,7 @@ atomic64_inc_and_test(atomic64_t *v)
 static __always_inline bool
 atomic64_add_negative(s64 i, atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_add_negative(i, v);
 }
@@ -1138,6 +1214,7 @@ atomic64_add_negative(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add_unless(v, a, u);
 }
@@ -1145,6 +1222,7 @@ atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 static __always_inline bool
 atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_add_unless(v, a, u);
 }
@@ -1152,6 +1230,7 @@ atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 static __always_inline bool
 atomic64_inc_not_zero(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_not_zero(v);
 }
@@ -1159,6 +1238,7 @@ atomic64_inc_not_zero(atomic64_t *v)
 static __always_inline bool
 atomic64_inc_unless_negative(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_inc_unless_negative(v);
 }
@@ -1166,6 +1246,7 @@ atomic64_inc_unless_negative(atomic64_t *v)
 static __always_inline bool
 atomic64_dec_unless_positive(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_unless_positive(v);
 }
@@ -1173,6 +1254,7 @@ atomic64_dec_unless_positive(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_if_positive(atomic64_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic64_dec_if_positive(v);
 }
@@ -1201,6 +1283,7 @@ atomic_long_set(atomic_long_t *v, long i)
 static __always_inline void
 atomic_long_set_release(atomic_long_t *v, long i)
 {
+	kcsan_release();
 	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_long_set_release(v, i);
 }
@@ -1215,6 +1298,7 @@ atomic_long_add(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_add_return(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_add_return(i, v);
 }
@@ -1229,6 +1313,7 @@ atomic_long_add_return_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_add_return_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_add_return_release(i, v);
 }
@@ -1243,6 +1328,7 @@ atomic_long_add_return_relaxed(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_add(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_add(i, v);
 }
@@ -1257,6 +1343,7 @@ atomic_long_fetch_add_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_add_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_add_release(i, v);
 }
@@ -1278,6 +1365,7 @@ atomic_long_sub(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_sub_return(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_sub_return(i, v);
 }
@@ -1292,6 +1380,7 @@ atomic_long_sub_return_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_sub_return_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_sub_return_release(i, v);
 }
@@ -1306,6 +1395,7 @@ atomic_long_sub_return_relaxed(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_sub(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_sub(i, v);
 }
@@ -1320,6 +1410,7 @@ atomic_long_fetch_sub_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_sub_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_sub_release(i, v);
 }
@@ -1341,6 +1432,7 @@ atomic_long_inc(atomic_long_t *v)
 static __always_inline long
 atomic_long_inc_return(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_return(v);
 }
@@ -1355,6 +1447,7 @@ atomic_long_inc_return_acquire(atomic_long_t *v)
 static __always_inline long
 atomic_long_inc_return_release(atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_return_release(v);
 }
@@ -1369,6 +1462,7 @@ atomic_long_inc_return_relaxed(atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_inc(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_inc(v);
 }
@@ -1383,6 +1477,7 @@ atomic_long_fetch_inc_acquire(atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_inc_release(atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_inc_release(v);
 }
@@ -1404,6 +1499,7 @@ atomic_long_dec(atomic_long_t *v)
 static __always_inline long
 atomic_long_dec_return(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_return(v);
 }
@@ -1418,6 +1514,7 @@ atomic_long_dec_return_acquire(atomic_long_t *v)
 static __always_inline long
 atomic_long_dec_return_release(atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_return_release(v);
 }
@@ -1432,6 +1529,7 @@ atomic_long_dec_return_relaxed(atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_dec(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_dec(v);
 }
@@ -1446,6 +1544,7 @@ atomic_long_fetch_dec_acquire(atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_dec_release(atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_dec_release(v);
 }
@@ -1467,6 +1566,7 @@ atomic_long_and(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_and(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_and(i, v);
 }
@@ -1481,6 +1581,7 @@ atomic_long_fetch_and_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_and_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_and_release(i, v);
 }
@@ -1502,6 +1603,7 @@ atomic_long_andnot(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_andnot(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_andnot(i, v);
 }
@@ -1516,6 +1618,7 @@ atomic_long_fetch_andnot_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_andnot_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_andnot_release(i, v);
 }
@@ -1537,6 +1640,7 @@ atomic_long_or(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_or(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_or(i, v);
 }
@@ -1551,6 +1655,7 @@ atomic_long_fetch_or_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_or_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_or_release(i, v);
 }
@@ -1572,6 +1677,7 @@ atomic_long_xor(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_xor(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_xor(i, v);
 }
@@ -1586,6 +1692,7 @@ atomic_long_fetch_xor_acquire(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_xor_release(long i, atomic_long_t *v)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_xor_release(i, v);
 }
@@ -1600,6 +1707,7 @@ atomic_long_fetch_xor_relaxed(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_xchg(atomic_long_t *v, long i)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_xchg(v, i);
 }
@@ -1614,6 +1722,7 @@ atomic_long_xchg_acquire(atomic_long_t *v, long i)
 static __always_inline long
 atomic_long_xchg_release(atomic_long_t *v, long i)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_xchg_release(v, i);
 }
@@ -1628,6 +1737,7 @@ atomic_long_xchg_relaxed(atomic_long_t *v, long i)
 static __always_inline long
 atomic_long_cmpxchg(atomic_long_t *v, long old, long new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_cmpxchg(v, old, new);
 }
@@ -1642,6 +1752,7 @@ atomic_long_cmpxchg_acquire(atomic_long_t *v, long old, long new)
 static __always_inline long
 atomic_long_cmpxchg_release(atomic_long_t *v, long old, long new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_cmpxchg_release(v, old, new);
 }
@@ -1656,6 +1767,7 @@ atomic_long_cmpxchg_relaxed(atomic_long_t *v, long old, long new)
 static __always_inline bool
 atomic_long_try_cmpxchg(atomic_long_t *v, long *old, long new)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic_long_try_cmpxchg(v, old, new);
@@ -1672,6 +1784,7 @@ atomic_long_try_cmpxchg_acquire(atomic_long_t *v, long *old, long new)
 static __always_inline bool
 atomic_long_try_cmpxchg_release(atomic_long_t *v, long *old, long new)
 {
+	kcsan_release();
 	instrument_atomic_read_write(v, sizeof(*v));
 	instrument_atomic_read_write(old, sizeof(*old));
 	return arch_atomic_long_try_cmpxchg_release(v, old, new);
@@ -1688,6 +1801,7 @@ atomic_long_try_cmpxchg_relaxed(atomic_long_t *v, long *old, long new)
 static __always_inline bool
 atomic_long_sub_and_test(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_sub_and_test(i, v);
 }
@@ -1695,6 +1809,7 @@ atomic_long_sub_and_test(long i, atomic_long_t *v)
 static __always_inline bool
 atomic_long_dec_and_test(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_and_test(v);
 }
@@ -1702,6 +1817,7 @@ atomic_long_dec_and_test(atomic_long_t *v)
 static __always_inline bool
 atomic_long_inc_and_test(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_and_test(v);
 }
@@ -1709,6 +1825,7 @@ atomic_long_inc_and_test(atomic_long_t *v)
 static __always_inline bool
 atomic_long_add_negative(long i, atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_add_negative(i, v);
 }
@@ -1716,6 +1833,7 @@ atomic_long_add_negative(long i, atomic_long_t *v)
 static __always_inline long
 atomic_long_fetch_add_unless(atomic_long_t *v, long a, long u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_fetch_add_unless(v, a, u);
 }
@@ -1723,6 +1841,7 @@ atomic_long_fetch_add_unless(atomic_long_t *v, long a, long u)
 static __always_inline bool
 atomic_long_add_unless(atomic_long_t *v, long a, long u)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_add_unless(v, a, u);
 }
@@ -1730,6 +1849,7 @@ atomic_long_add_unless(atomic_long_t *v, long a, long u)
 static __always_inline bool
 atomic_long_inc_not_zero(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_not_zero(v);
 }
@@ -1737,6 +1857,7 @@ atomic_long_inc_not_zero(atomic_long_t *v)
 static __always_inline bool
 atomic_long_inc_unless_negative(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_inc_unless_negative(v);
 }
@@ -1744,6 +1865,7 @@ atomic_long_inc_unless_negative(atomic_long_t *v)
 static __always_inline bool
 atomic_long_dec_unless_positive(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_unless_positive(v);
 }
@@ -1751,6 +1873,7 @@ atomic_long_dec_unless_positive(atomic_long_t *v)
 static __always_inline long
 atomic_long_dec_if_positive(atomic_long_t *v)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(v, sizeof(*v));
 	return arch_atomic_long_dec_if_positive(v);
 }
@@ -1758,6 +1881,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define xchg(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_xchg(__ai_ptr, __VA_ARGS__); \
 })
@@ -1772,6 +1896,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define xchg_release(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_release(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_xchg_release(__ai_ptr, __VA_ARGS__); \
 })
@@ -1786,6 +1911,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_cmpxchg(__ai_ptr, __VA_ARGS__); \
 })
@@ -1800,6 +1926,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg_release(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_release(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_cmpxchg_release(__ai_ptr, __VA_ARGS__); \
 })
@@ -1814,6 +1941,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg64(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_cmpxchg64(__ai_ptr, __VA_ARGS__); \
 })
@@ -1828,6 +1956,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg64_release(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_release(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_cmpxchg64_release(__ai_ptr, __VA_ARGS__); \
 })
@@ -1843,6 +1972,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
 	typeof(oldp) __ai_oldp = (oldp); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
 	arch_try_cmpxchg(__ai_ptr, __ai_oldp, __VA_ARGS__); \
@@ -1861,6 +1991,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
 	typeof(oldp) __ai_oldp = (oldp); \
+	kcsan_release(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
 	arch_try_cmpxchg_release(__ai_ptr, __ai_oldp, __VA_ARGS__); \
@@ -1892,6 +2023,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define sync_cmpxchg(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
 	arch_sync_cmpxchg(__ai_ptr, __VA_ARGS__); \
 })
@@ -1899,6 +2031,7 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 #define cmpxchg_double(ptr, ...) \
 ({ \
 	typeof(ptr) __ai_ptr = (ptr); \
+	kcsan_mb(); \
 	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr)); \
 	arch_cmpxchg_double(__ai_ptr, __VA_ARGS__); \
 })
@@ -1912,4 +2045,4 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 })
 
 #endif /* _LINUX_ATOMIC_INSTRUMENTED_H */
-// 2a9553f0a9d5619f19151092df5cabbbf16ce835
+// 87c974b93032afd42143613434d1a7788fa598f9
diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
index 035ceb4ee85c..68f902731d01 100755
--- a/scripts/atomic/gen-atomic-instrumented.sh
+++ b/scripts/atomic/gen-atomic-instrumented.sh
@@ -34,6 +34,14 @@ gen_param_check()
 gen_params_checks()
 {
 	local meta="$1"; shift
+	local order="$1"; shift
+
+	if [ "${order}" = "_release" ]; then
+		printf "\tkcsan_release();\n"
+	elif [ -z "${order}" ] && ! meta_in "$meta" "slv"; then
+		# RMW with return value is fully ordered
+		printf "\tkcsan_mb();\n"
+	fi
 
 	while [ "$#" -gt 0 ]; do
 		gen_param_check "$meta" "$1"
@@ -56,7 +64,7 @@ gen_proto_order_variant()
 
 	local ret="$(gen_ret_type "${meta}" "${int}")"
 	local params="$(gen_params "${int}" "${atomic}" "$@")"
-	local checks="$(gen_params_checks "${meta}" "$@")"
+	local checks="$(gen_params_checks "${meta}" "${order}" "$@")"
 	local args="$(gen_args "$@")"
 	local retstmt="$(gen_ret_stmt "${meta}")"
 
@@ -75,29 +83,44 @@ EOF
 gen_xchg()
 {
 	local xchg="$1"; shift
+	local order="$1"; shift
 	local mult="$1"; shift
 
+	kcsan_barrier=""
+	if [ "${xchg%_local}" = "${xchg}" ]; then
+		case "$order" in
+		_release)	kcsan_barrier="kcsan_release()" ;;
+		"")			kcsan_barrier="kcsan_mb()" ;;
+		esac
+	fi
+
 	if [ "${xchg%${xchg#try_cmpxchg}}" = "try_cmpxchg" ] ; then
 
 cat <<EOF
-#define ${xchg}(ptr, oldp, ...) \\
+#define ${xchg}${order}(ptr, oldp, ...) \\
 ({ \\
 	typeof(ptr) __ai_ptr = (ptr); \\
 	typeof(oldp) __ai_oldp = (oldp); \\
+EOF
+[ -n "$kcsan_barrier" ] && printf "\t${kcsan_barrier}; \\\\\n"
+cat <<EOF
 	instrument_atomic_write(__ai_ptr, ${mult}sizeof(*__ai_ptr)); \\
 	instrument_atomic_write(__ai_oldp, ${mult}sizeof(*__ai_oldp)); \\
-	arch_${xchg}(__ai_ptr, __ai_oldp, __VA_ARGS__); \\
+	arch_${xchg}${order}(__ai_ptr, __ai_oldp, __VA_ARGS__); \\
 })
 EOF
 
 	else
 
 cat <<EOF
-#define ${xchg}(ptr, ...) \\
+#define ${xchg}${order}(ptr, ...) \\
 ({ \\
 	typeof(ptr) __ai_ptr = (ptr); \\
+EOF
+[ -n "$kcsan_barrier" ] && printf "\t${kcsan_barrier}; \\\\\n"
+cat <<EOF
 	instrument_atomic_write(__ai_ptr, ${mult}sizeof(*__ai_ptr)); \\
-	arch_${xchg}(__ai_ptr, __VA_ARGS__); \\
+	arch_${xchg}${order}(__ai_ptr, __VA_ARGS__); \\
 })
 EOF
 
@@ -145,21 +168,21 @@ done
 
 for xchg in "xchg" "cmpxchg" "cmpxchg64" "try_cmpxchg"; do
 	for order in "" "_acquire" "_release" "_relaxed"; do
-		gen_xchg "${xchg}${order}" ""
+		gen_xchg "${xchg}" "${order}" ""
 		printf "\n"
 	done
 done
 
 for xchg in "cmpxchg_local" "cmpxchg64_local" "sync_cmpxchg"; do
-	gen_xchg "${xchg}" ""
+	gen_xchg "${xchg}" "" ""
 	printf "\n"
 done
 
-gen_xchg "cmpxchg_double" "2 * "
+gen_xchg "cmpxchg_double" "" "2 * "
 
 printf "\n\n"
 
-gen_xchg "cmpxchg_double_local" "2 * "
+gen_xchg "cmpxchg_double_local" "" "2 * "
 
 cat <<EOF
 
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-17-elver%40google.com.
