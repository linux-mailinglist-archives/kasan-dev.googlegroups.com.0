Return-Path: <kasan-dev+bncBAABBPFGTLZQKGQE6HA3DYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AF0D17E7DA
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:30 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id m19sf5621101oie.16
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780669; cv=pass;
        d=google.com; s=arc-20160816;
        b=jdosgH+QatLTlZeD2RWL/61Frg0CV5E0nRoNAxYzG3Xzn14OOwr4OEGUCpilfg5Cb/
         eQVbJ+/qeqs93/5YG2Sm9/p0H7/IYqO3+IK256VdDAO1yN2OA272EyW9Q+dRlTvr+UC6
         0OfCw7DMgbkZ/LDyYcKgBzSGncZhYc7hcqNDEItPK04jz4sqH7rGjvfMmGfa8WM+qm/0
         C5+Kyz5TEr4U+1K07wkUzGQ/MNIYZvq1Yg3tv0RLLkjv6Skd7ECWJwlbbypurWml68Cq
         ZQCTJ2BERHZ9uOoDMaFhCp2FOqRxpn0mUEiC1mjT79lY4By3oQVIKV0+KF8r/jTRecQf
         xVkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=JLr0ZgelBYxshGOi9pfxGyAHKvgVXxgG276YQeudptg=;
        b=RrS7HLAk9fxuollqRDoqMogPZkPGg8GXR6eLRzhN86Yuo0Xw3/Pm5yjJl65KmCpjSi
         ug8ns62JCHw9KETvFcsm+PgMXK/hIQ6iSIhHoyFQGI73cDOMiVAAlDSmEljWE+crYqud
         BUAGTWM1wnCwH5sn4lQqBbKFfCrzYtBlKa+JnuGi/DWQ8lmkUrpIm2YvvqqvgUdZxqr9
         DH/T3t0NrTefJ74oz4e3YXX7FmJmaXtHXh5I6gPpzP0k8zLuZ0v8LdR9fhZZNCFz0UNb
         hgIr3Xb9mHD9ly/3jA0+inEeKeNrvCQ7WIEXV3hygNFdGG9iCAsqQ011tEU476wnEOdF
         DsBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=eoU+iiQc;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JLr0ZgelBYxshGOi9pfxGyAHKvgVXxgG276YQeudptg=;
        b=ZJRrLPDVmh84TFE3DU86fE1HBf8wtKeDa9KpwHt73XjfAh4LtsdS6L876rCDTgttix
         g8glSKtoTsConSvm7PM2h4/uRsDkWalfhk33VGLHLzWWQO/e2oVmEotW028/sszVicpR
         zhV0EPAqCP4P4iv0MNpmtmZd0+C0O+o4O2QXnUjdvRiemqKvhuXN8iep2W0i6kbzFDKr
         HbP33ILcp+CFjd0g0ewDMKQKPGHMM6tPNTLXpB6mZe+/RfDplSmfo23aV6vAHYNontt9
         0LBTX42jBD3V0+8WQhsQ0n9s0E2mdVLgMXqocLUsdsbdo2yuQVfPQeDd8iVtGVEaXdOc
         cpSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JLr0ZgelBYxshGOi9pfxGyAHKvgVXxgG276YQeudptg=;
        b=Kj2W7gtmrVC4ulu52VDXFAFbW1DVylmJ2xWVPgxC7Ta7LejGp6bbIoCk+abkgHQSZ1
         /jNkRoTtl6G42PUi/dJPpkdM58qFEJwp80RgRUR63oO5LByCb0OrQ8MAEhD1UaYU0ysf
         /0Qm4FyIcIjHzZ4A2TfIfj6Q31bN8ssyNQq+BnQtLlNT2wv5fovMuKKCrbwR8LFdurda
         vyTQKDClpZtr0hjyNppPtPGmCn2JR7VFXH87guMajGKpDxKdW2UfPrgqYtdILpbjv64D
         pPsEwVTrBCZ+S/MtmBMOHXA3m7MqLVpQiAaOoJOh+0ZemJCr+Okty/fDVOQfXUYkIWzV
         1Pbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ03CDmwN+6CVdaoeMtxHLLXRnrNnnPtWpAvyvOvrv+lRjxNxqjO
	V1C7tXhMPZ9/DNX+pVOjhNc=
X-Google-Smtp-Source: ADFU+vuoQ8CYRM35vQhAODMrwllB1xH6wunuAvWHKJSm0bL8bAeUDLcTD4KTeC0ueoCx8uQD1F+tqg==
X-Received: by 2002:a05:6830:1503:: with SMTP id k3mr14585356otp.28.1583780668886;
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a5a:: with SMTP id h26ls1801447otn.1.gmail; Mon, 09 Mar
 2020 12:04:28 -0700 (PDT)
X-Received: by 2002:a05:6830:1bc3:: with SMTP id v3mr14771706ota.310.1583780668225;
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780668; cv=none;
        d=google.com; s=arc-20160816;
        b=m/ol5+/dEzj8J1odplqnR7AvG+U0b/X85zhVDwn7hiT8r2bfgwYZTDFyl9iN8H9WOc
         c6Znckyk0Ups1uLm3K966UUO2A33ESIWdxazyr6KvHW70RkHyVSkU70T1Zu7DCeoPHfS
         vdGzrxKJwQGZ+4Gd1PQqvhTnT6RsdWKCYeTnIvMzpHPHiu4sY41Ika3EFZiG2RSPd1yh
         3qxAEDkVHij/2zT2GVyu/Nh+hnM0mbH0nQgpNL1NT/ED86uJC/i+sQLSjCbyO8BRK0Yl
         81GJgGRrTDtSo9ozRFvUiJnj8vm5QHrpO04euHEMdwm7ulpt7NHqyKSuBBAvPBxo8kHQ
         XzPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=JsHFLf04ezH/jMt2MB+GNUH9i+ZE5EJhksP/hz5dFpA=;
        b=ciszU6Svbqh2VLypfbc1UaDaUEdoCemiNY3KT32LGvVUGxPxB8NzgCyVnrHlBGgfsR
         DpRrrDIf+Fbv3pdA9G12mXb00aaXj8OCHY3o3qc+A9YdoXKrilOFFW/5AXukOqZKL0zS
         25auZLIkYBkYGkETY0dB4HYrpr5ZhkJKjt2WEgGuFzLe4Po7m1kFmBzi3x4kQp7Pmcp9
         1iwS9NY9jlvKvaUWZZtLgnTTUi+byWTDKPqQTVcL9LG2OHvxEJkhglMwFeXTojmaAQbg
         vvY/MpXE5/0yqujoooVPJFaWsSpj51u9/FBHBYWAolhBsw8anqbiVAOg5rf1wxsi32hH
         kO3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=eoU+iiQc;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d11si235195otk.5.2020.03.09.12.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 56F73222C3;
	Mon,  9 Mar 2020 19:04:27 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 21/32] kcsan: Move interfaces that affects checks to kcsan-checks.h
Date: Mon,  9 Mar 2020 12:04:09 -0700
Message-Id: <20200309190420.6100-21-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=eoU+iiQc;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

This moves functions that affect state changing the behaviour of
kcsan_check_access() to kcsan-checks.h. Since these are likely used with
kcsan_check_access() it makes more sense to have them in kcsan-checks.h,
to avoid including all of 'include/linux/kcsan.h'.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: John Hubbard <jhubbard@nvidia.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 48 ++++++++++++++++++++++++++++++++++++++++++--
 include/linux/kcsan.h        | 41 -------------------------------------
 2 files changed, 46 insertions(+), 43 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index cf69617..8675411 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -32,10 +32,54 @@
  */
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type);
 
-#else
+/**
+ * kcsan_nestable_atomic_begin - begin nestable atomic region
+ *
+ * Accesses within the atomic region may appear to race with other accesses but
+ * should be considered atomic.
+ */
+void kcsan_nestable_atomic_begin(void);
+
+/**
+ * kcsan_nestable_atomic_end - end nestable atomic region
+ */
+void kcsan_nestable_atomic_end(void);
+
+/**
+ * kcsan_flat_atomic_begin - begin flat atomic region
+ *
+ * Accesses within the atomic region may appear to race with other accesses but
+ * should be considered atomic.
+ */
+void kcsan_flat_atomic_begin(void);
+
+/**
+ * kcsan_flat_atomic_end - end flat atomic region
+ */
+void kcsan_flat_atomic_end(void);
+
+/**
+ * kcsan_atomic_next - consider following accesses as atomic
+ *
+ * Force treating the next n memory accesses for the current context as atomic
+ * operations.
+ *
+ * @n number of following memory accesses to treat as atomic.
+ */
+void kcsan_atomic_next(int n);
+
+#else /* CONFIG_KCSAN */
+
 static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
 					int type) { }
-#endif
+
+static inline void kcsan_nestable_atomic_begin(void)	{ }
+static inline void kcsan_nestable_atomic_end(void)	{ }
+static inline void kcsan_flat_atomic_begin(void)	{ }
+static inline void kcsan_flat_atomic_end(void)		{ }
+static inline void kcsan_atomic_next(int n)		{ }
+
+#endif /* CONFIG_KCSAN */
 
 /*
  * kcsan_*: Only calls into the runtime when the particular compilation unit has
diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index 1019e3a..7a614ca 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -56,52 +56,11 @@ void kcsan_disable_current(void);
  */
 void kcsan_enable_current(void);
 
-/**
- * kcsan_nestable_atomic_begin - begin nestable atomic region
- *
- * Accesses within the atomic region may appear to race with other accesses but
- * should be considered atomic.
- */
-void kcsan_nestable_atomic_begin(void);
-
-/**
- * kcsan_nestable_atomic_end - end nestable atomic region
- */
-void kcsan_nestable_atomic_end(void);
-
-/**
- * kcsan_flat_atomic_begin - begin flat atomic region
- *
- * Accesses within the atomic region may appear to race with other accesses but
- * should be considered atomic.
- */
-void kcsan_flat_atomic_begin(void);
-
-/**
- * kcsan_flat_atomic_end - end flat atomic region
- */
-void kcsan_flat_atomic_end(void);
-
-/**
- * kcsan_atomic_next - consider following accesses as atomic
- *
- * Force treating the next n memory accesses for the current context as atomic
- * operations.
- *
- * @n number of following memory accesses to treat as atomic.
- */
-void kcsan_atomic_next(int n);
-
 #else /* CONFIG_KCSAN */
 
 static inline void kcsan_init(void)			{ }
 static inline void kcsan_disable_current(void)		{ }
 static inline void kcsan_enable_current(void)		{ }
-static inline void kcsan_nestable_atomic_begin(void)	{ }
-static inline void kcsan_nestable_atomic_end(void)	{ }
-static inline void kcsan_flat_atomic_begin(void)	{ }
-static inline void kcsan_flat_atomic_end(void)		{ }
-static inline void kcsan_atomic_next(int n)		{ }
 
 #endif /* CONFIG_KCSAN */
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-21-paulmck%40kernel.org.
