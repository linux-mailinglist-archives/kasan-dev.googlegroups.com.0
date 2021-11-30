Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2M5TCGQMGQE3QMNOVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05EE64632F1
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:46 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dsf10297118wmc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272745; cv=pass;
        d=google.com; s=arc-20160816;
        b=zsUizgqGi/w6DZJs273MmRfX79gMkBDK2H02gQ2ck5TpUU2eZ0Z1ua3h7JJnIgJ8AE
         f+7dqDrOxFpaXeyFUmkmBq6Uk2eazv+GA77LI2uieFRbxSe0HeSKcjbL6Xi2ADJqrPqh
         vg/VpTpN8BO5nluR++Sftk1kz7tSHIBzk+6jJnG5U4QwGxu74Xxvchx1SCmcySm0UgV+
         BBqDga+kc014WUC9hq2qOXtZwsi/IkOIZcRzGlymTkYswfLeXAdc/jzByn7DSQM4lRly
         iqXu/zvsJA9/joX4ksVZmr4jk+EyNWf4CdZijsvehxqNP55UNZ44ZqBwvSFbrbSlk4hj
         ngCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=RYUMtpRxf3YksHMbCbCo7cVZpYjySI55bud0O80mJ6Q=;
        b=zVSBzFo0NKT1Cvtv2pI7BkBk6z3HqtxppHKHAryAG4qgrcMj8iMA7SNmXZLnHOdCeH
         27jMSBbIjAo8dJrJkxnb7aesbyKPKJheb/xIm7iFym9zh8ouV5jrRQZmJhr09FfVOICt
         gK4CY59t4igYF/jH1/lK+Lf8Yl6ds2aCQONGCO2yRFrmQZqdjJ5JYRxQuao7BhqsEl/y
         ETV5/zT1cSuZwzAt1Gd7h3hS674in4IaDVhs8LcPOoPL2w9eeiF1WPZ1W8d54HzUTsR1
         cpAKSVRX/bb8EQc84j8fzFgXoytM4zxVcEZFjTH9NqwV71Uv81NJgDhRbOKs4pWY9xQi
         CcVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HGTmGOZb;
       spf=pass (google.com: domain of 36a6myqukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=36A6mYQUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RYUMtpRxf3YksHMbCbCo7cVZpYjySI55bud0O80mJ6Q=;
        b=buXHo1WmcYrs8ZrHONa/po9IcG/0Xdy03eaWVfoK0DtiQDwa6J7/1Webs1wjWW+GQv
         amOO7z+H/xdJPl3UjNiVZr14f+pxOIeMmzoqYQF/C1GMVMSyJjQpmN1RZs3acDKTlEMs
         hLoSl5ltEnm2BDqC7VKt/Ewfoh2bVz339cG9gkJb/zlj42NKi04AOeB1ei4J3Riv4PAJ
         kIz9nltSEC95YpUJLQLh/aD3Pq/2r7xH5XnN8Fs2OdwSS/U3Kf4ZqA/umJ94N94Vu9wf
         jC0GqTWejlE24LRQfmgHKfaDXu44WyuasaNKj8934c+b3kmfUAfXMDNeR5pLXxBYTd6l
         vf7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RYUMtpRxf3YksHMbCbCo7cVZpYjySI55bud0O80mJ6Q=;
        b=Qsv/tX/gl7/7zEnMlKtftOOKAUgCedgo3DS06d1guWZokav475e+FgA0lzOKlGv1xe
         GuIqH8gDxPWNwMM3QcAZnbZ37oD9xa5yis4k8rN17RDZc1yGDyJy3MrL9fzCHRGS1FAq
         Gy4y5/YAl+VdbT29vhtOw2g6tb5Y9I+Sonux5qFQpLSXRd6hJe6XHd8FuLoX03rglU2b
         /z9uostsOCUQfiahWfaCjdd9DyPR2lRxLCxWrtx8y0UiOrtj98j+O6Jp2Nzn2uANkvI3
         YXjiXv3/segkmb70RMNNOnG2/p7QEEMiu0Ig2j+WAaQ3mCz/OkokgG1dGE9P6yf1LJIr
         NNUQ==
X-Gm-Message-State: AOAM533Igaxwg9xRG69XFDcS2PisuAh+0bH4sYUxivI4sE5KZueFBzDJ
	vfD67/Z9RE3AGqbPSAC9uqY=
X-Google-Smtp-Source: ABdhPJyeuyrnDeIPHRQe8nm32EAwFUOykYYMptt7/C6iF9i10+FWqh4xYq0l+nwmgs+Di4V/xg+pXA==
X-Received: by 2002:adf:d22a:: with SMTP id k10mr41107105wrh.80.1638272745829;
        Tue, 30 Nov 2021 03:45:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls13084030wrr.0.gmail; Tue, 30
 Nov 2021 03:45:45 -0800 (PST)
X-Received: by 2002:adf:dc52:: with SMTP id m18mr41723016wrj.216.1638272744946;
        Tue, 30 Nov 2021 03:45:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272744; cv=none;
        d=google.com; s=arc-20160816;
        b=NAeGAsPbD8wKG6LpPDwuve/WNxyA1Us2QK6H3xqCwkIoLu3ck4xjofq1HYCpj7KvQy
         hUAn8mK4pdqYpgxG1HMhvtlACGO+IyI29AsBmCEPgDpBzJdiED8MoU3WLr2bjOYqAsoc
         SwIbUx87EcCujZsfnWakJ75Dt4HCDWxfTNkZbL80bXPc9EjVegeWoLM17jJRn4iyehkN
         xay1Hfa3FA0yk3oiJdkdDhv0KcaGws+G/Ouk8RLs6TVQRPdrAXnzj6zLdtXaR0Wv4IRs
         jqTJeGTr/oqH92R5X/BNXmP5wDK2tMs+AuCN7/zeaQODSvfNwbyKMGvkQaZ1N2uWjkXj
         kYcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=JvNCvfwB/M304r5/BDcWOzh3dLnMrHum3apHlfxEx/4=;
        b=MCMocoflOO4pq+7PHYDZyF1uLoYDRu9Y9cQU23qHroELrKFqSi6rxAGpMBdYV0jqXp
         /qd086E8ITEOWxX7zyaqqF3uKxaUldtANxojQTAMBKVkutdCS6Dt2iAjhV1Wnfl7sYl3
         8pO4cMLw7df33InEmVfeaaKjrjO1MiJSHHOM/dyvwmBY1Ukfm3VamdSckxPqOoRjIJH1
         3cFRDXJeZaMh0jSb9of7NTQ1Tn9fJIGLCQ/tNfwxhy1Xx3amLX9s/8AAqy5hZegzTKt0
         LO8OA0KFrzBs419y/BQI5rgktl47Q7IJBV/8aI7GngqguHioq2PztxVel9+Py9T6Wkc0
         w1bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HGTmGOZb;
       spf=pass (google.com: domain of 36a6myqukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=36A6mYQUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o29si395542wms.1.2021.11.30.03.45.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 36a6myqukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id n41-20020a05600c502900b003335ab97f41so12709996wmr.3
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:44 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:2e46:: with SMTP id
 q6mr4344091wmf.6.1638272744574; Tue, 30 Nov 2021 03:45:44 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:25 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-18-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 17/25] asm-generic/bitops, kcsan: Add instrumentation for barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HGTmGOZb;       spf=pass
 (google.com: domain of 36a6myqukcbevcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=36A6mYQUKCbEVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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

Adds the required KCSAN instrumentation for barriers of atomic bitops.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/bitops/instrumented-atomic.h | 3 +++
 include/asm-generic/bitops/instrumented-lock.h   | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index 81915dcd4b4e..c90192b1c755 100644
--- a/include/asm-generic/bitops/instrumented-atomic.h
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -67,6 +67,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
@@ -80,6 +81,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
@@ -93,6 +95,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
index 75ef606f7145..eb64bd4f11f3 100644
--- a/include/asm-generic/bitops/instrumented-lock.h
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -22,6 +22,7 @@
  */
 static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit_unlock(nr, addr);
 }
@@ -37,6 +38,7 @@ static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
  */
 static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit_unlock(nr, addr);
 }
@@ -71,6 +73,7 @@ static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 static inline bool
 clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
 }
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-18-elver%40google.com.
