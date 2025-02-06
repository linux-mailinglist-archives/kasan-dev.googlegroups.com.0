Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYHZSO6QMGQE6KBQIEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id CD419A2B053
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:10 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-436379713basf6491055e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865890; cv=pass;
        d=google.com; s=arc-20240605;
        b=WAN8HssqtqqLX9tAvPI+ou9aBsC4KUmKNqRe1nzc+PkcwNDVNDT4ZZx7ru3dKyzS3V
         6KfNg1hUNIq4K+mpLWq5kDtr1AwvCWF3sCWCauLjwQC80PwoUruN4HzdZ3ZbaCe7fZnp
         tUVf82D7iPdVTdKaYO4TPxg34Hh4KCr+SwUko5PtVCSChSan1dEjgB3QK17iNj8Yy3sl
         6KzgxNL+57Rhilbtdn981pPTGiIfnc7CYgl30yka4PXfLjkCNopcRo/c1vnGXm/VOUjK
         AxAXbh3P73Y7CMAnVApqumPKHWsle4Y6vceFBWiVQNvk3hgCJ7+3bmxL+rNkh8zaPj5O
         OUrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=RYrZyuJ9TmlzjoFE6/G61ZIN1AXd09OYVaj58qBq1GE=;
        fh=xGmWqbudgwxxb/RiISqZZPwiT9TZEBF0Y7WukontoIg=;
        b=Yvz9dM/s5zsKUGPZ2onKjfKfxPgvHu9oFTiUH95ChxKWDAnK3dOqXKDwBlWEpO6E7C
         xE5qRJr73eL2n1LyXkwDER9v1rFw9AS312Nme9wnJtG/pm6uIJZHJx3qBfdS5uo0nsZu
         +qMdRGtIfriqfmRbTFeUJK9wa7vzSpgnnjOkuzXVI28rjRNBQLfT3+SB2JBXz1p9aCfx
         0fTDsCWSbN5jx425rMMJaVv4UdVmNLYI9KZZKQP+F6AOhXhBrDoRq1fVaATdfozSoTvj
         HSSpKG0ObOznLyZzKYMLog0hZDPrWsxZS2UYIKVgKHRvpUPGyKA2g/MMwXfBoe8TNVEB
         CIMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PLMwUlPs;
       spf=pass (google.com: domain of 33vykzwukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=33vykZwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865890; x=1739470690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RYrZyuJ9TmlzjoFE6/G61ZIN1AXd09OYVaj58qBq1GE=;
        b=L1g59IRCHUvqmTH1c9bMFQVEmnKZZqIoupDYUBGuQrNvSHSErFYe8CgOgrMkB31VFG
         yiIg2z3P07YDYT/NDsZFs7WIQ4IVwYO0EYXipL2kUpgaUovhJf/6TLpMWndrFHgh1uoF
         x1f1UTSBhKfM5ElXtpPELxIEECnWRJtMojxT0SytRG7zvcK5l/wF9CCX0P2kCq6WP8sn
         ri8y52h4qKpMj3HoOrORN06W9yw1jRjGAqA57f8K55/uetHSTBxe5jidM/X6MLcKf+1a
         /CCJTErL67UVhnbEcGr26ZOQR1vMT/LQRixlrn1R+jlPWad+9+RwmZ9Vt88luGKknWwm
         puxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865890; x=1739470690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RYrZyuJ9TmlzjoFE6/G61ZIN1AXd09OYVaj58qBq1GE=;
        b=UOKB9cbsBHl3vURP+4sQX+v7IM5X0truKFeTAr73pIclb6uWaWaQyzwoX7IVAOqROv
         kn9AfROl4eL1VxfMD6oGSPDexhqOU5mgsclJHI9IxMJrMbyoNEP1xLfOqusXg1wHg4Mv
         5V/UYyUL+VD+3f81lT98TI/iuyKsKctvCsNpF1pgDm88j65FNYVsTL0Mply0HQ7i+JjY
         kS5iu2+ZEfScsrZM+V3P0rA5LEJL/JGlB6XSsSMmVb5gaXjekHGE2xXclAWwX+zP/9jT
         kTvn/ghgtVTU9jazTSumYbkeFuyqX24rb5/2eQckPixblvt6NcPOyPE7OPn8j5HpHWwG
         yWsw==
X-Forwarded-Encrypted: i=2; AJvYcCUwOeLe0jQNFqR24AcmyVoxPwMoqjCSrgx/e14GIxkHtyj3sxOOShjN73tHgZsY24l7sd4lsg==@lfdr.de
X-Gm-Message-State: AOJu0YxeW8gTynfRaoNysoSktcc1y8/pEyWWrME79Kv5ta4c6Dh5W5ZC
	cumoWjAgTin7bnzwkm6QRcmbdKcVNKU/cjWn6hSrKp+bLjKORi/K
X-Google-Smtp-Source: AGHT+IFdEvrC6U8oi6ww32pSCUD4P16CW+37pyFR2fuSsaryQPsLC5Cu6JRQE+THuiUHjO+pyXrYwQ==
X-Received: by 2002:a05:600c:4f90:b0:434:fd01:2e5f with SMTP id 5b1f17b1804b1-439249b2a77mr3730895e9.29.1738865889229;
        Thu, 06 Feb 2025 10:18:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4d6:0:b0:434:f37c:2a56 with SMTP id 5b1f17b1804b1-43924cdc3bdls210585e9.1.-pod-prod-03-eu;
 Thu, 06 Feb 2025 10:18:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhi8JSAG8T25dpYfUXsBpnCQg0cES6MTi1qjnY68bF9IiiuvY8Oe5953hirQg3d7XUHQ1JpjzVsTg=@googlegroups.com
X-Received: by 2002:a05:600c:1e11:b0:436:5fc9:309d with SMTP id 5b1f17b1804b1-439249b2bafmr4275305e9.30.1738865886670;
        Thu, 06 Feb 2025 10:18:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865886; cv=none;
        d=google.com; s=arc-20240605;
        b=J+wgh67Y239DyxhUZuhKKItd7MHrZADDOSVV+GEHvAiXKA7zYx8yzDIiH40qJr68XY
         dBJp4UJdvHwPa97aAGwOSO9MMRiInpX2KMmlLt2F5N/eK9wmqqLVMLigv+nw20Jy6Gh0
         +wWSQz9ZQD+7KoBiE4Ffnhpx6aMJBVosZE0XBcCLVYNA+lFnIkLD0gth2X8ZYIl1yaOH
         oKePtQElGracBB/BrNetYUW8Px6zWl9oCiABk7/1bLRI2Y69meP+J2bNz3uxXPfKcT5C
         tj9oiMeXjykFzsQm4fDK1HMT/sCrXHAMPN9V0NaM6Loe5XBXbBgl3adtcJDLbKQ6nIT5
         W2cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=B9zo14rswWWzdXk+7RXhASP4eQAv2ef2DvmlHG5M+4Q=;
        fh=8YriumTx/6Ww4y2g4xIVBA954kVrJSQNBJb8zx7yiW0=;
        b=GdT9hqtBhD1LVnwn/m3ktt0Z4BkDrrlUWWw6SCD+iVc4oYO2fsTIl41kGQWjOXFO8q
         3JPDIxGL8sobUZX0zKtxZCq2j8FWWxjIeeiqKiaXCrkf5VhDgs0BV/40uXtD9F98fEjI
         mOFApyM2V5Ez1hshQVmE7f5QeVkBpr0l0HGdqU4OCx7L6qWyk3dm4mCrXJbEY8uPCTIL
         jtNd9f0K1PJge5NNtv0Uou4rE+QEO2+75eusqgt34tPHKIFG2qCB52e0yAF/q6DQmtvs
         r9eDST1ECgw//8x2YM/8HCxGhuSrcTqNfMK3wZ6zvBEUksG0xWO8E0ao26uFKllZOR0l
         lwMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PLMwUlPs;
       spf=pass (google.com: domain of 33vykzwukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=33vykZwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43907f18ffcsi2804355e9.1.2025.02.06.10.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 33vykzwukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-aa67f18cb95so136412866b.1
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX6T6f4eqt6EttSPNq9QrN7Ua5DHJ3QRR/IyBS8COciRyN2NCseJ/NBzq9QUdJIhiXIruhaqEb9w+c=@googlegroups.com
X-Received: from ejcvi3.prod.google.com ([2002:a17:907:d403:b0:aa6:90a8:f5f8])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:7216:b0:ab7:647:d52d
 with SMTP id a640c23a62f3a-ab75e322c0dmr999272366b.51.1738865886143; Thu, 06
 Feb 2025 10:18:06 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:02 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-9-elver@google.com>
Subject: [PATCH RFC 08/24] lockdep: Annotate lockdep assertions for capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PLMwUlPs;       spf=pass
 (google.com: domain of 33vykzwukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=33vykZwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
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

Clang's capability analysis can be made aware of functions that assert
that capabilities/locks are held.

Presence of these annotations causes the analysis to assume the
capability is held after calls to the annotated function, and avoid
false positives with complex control-flow; for example, where not all
control-flow paths in a function require a held lock, and therefore
marking the function with __must_hold(..) is inappropriate.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/lockdep.h | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
index 67964dc4db95..5cea929b2219 100644
--- a/include/linux/lockdep.h
+++ b/include/linux/lockdep.h
@@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
 	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
 
 #define lockdep_assert_held(l)		\
-	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
+	do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assert_cap(l); } while (0)
 
 #define lockdep_assert_not_held(l)	\
 	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
 
 #define lockdep_assert_held_write(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 0))
+	do { lockdep_assert(lockdep_is_held_type(l, 0)); __assert_cap(l); } while (0)
 
 #define lockdep_assert_held_read(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 1))
+	do { lockdep_assert(lockdep_is_held_type(l, 1)); __assert_shared_cap(l); } while (0)
 
 #define lockdep_assert_held_once(l)		\
 	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
@@ -389,10 +389,10 @@ extern int lockdep_is_held(const void *);
 #define lockdep_assert(c)			do { } while (0)
 #define lockdep_assert_once(c)			do { } while (0)
 
-#define lockdep_assert_held(l)			do { (void)(l); } while (0)
+#define lockdep_assert_held(l)			__assert_cap(l)
 #define lockdep_assert_not_held(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_write(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_read(l)		do { (void)(l); } while (0)
+#define lockdep_assert_held_write(l)		__assert_cap(l)
+#define lockdep_assert_held_read(l)		__assert_shared_cap(l)
 #define lockdep_assert_held_once(l)		do { (void)(l); } while (0)
 #define lockdep_assert_none_held_once()	do { } while (0)
 
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-9-elver%40google.com.
