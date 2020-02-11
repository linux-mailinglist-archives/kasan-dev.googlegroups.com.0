Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXVBRPZAKGQEOTULVOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4746A15944D
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 17:05:51 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id p8sf7135314wrw.5
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 08:05:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581437151; cv=pass;
        d=google.com; s=arc-20160816;
        b=m+tlHIixXJCSE8nvfQcyX0uUidKBQUMTDFjF1fW0jmOl2sRtpzGlkAr/8oz20zIca6
         /d/ZLSDO7b1A74vQbUdBMVyudHK71gF3Ft6jcB3GoYyAt476qr1v8zgWI4UD+ME5GlaS
         uAWjZIdHqlqNog86NVLbcY7OJzpvmDedJPFU6ti/n9EprmKghvtaDoslkyqgi7cJRs68
         QWCrGJAh1YmjMQDqf1aaHDCZ8tg9FdmROYwOS//PPx1vPVpAhTVHjW6+g1WQ2CgQRAja
         lwcpuzc364HMY7pz4oojmF3Ow/SvQ40N+9doM7CNLOW71bGPq5c89aFf8W3GmPB66zsy
         u42g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ULllRDE+BG9kTY83ej7ljgVqCs6w6/ZT1xqDn3qjvS8=;
        b=gxgM6rnms5fFnRdKg21QE9SukqY6cHl7r7V1WsXcl9Ly6m9TJD0zKb4e5wBKYKwCfJ
         VuwZOaT6/BiXZJdwlhpQgmiIej55L0eM4TlgnVB71kI5793NKR3vraBDwk0eY5ukVdPi
         SSdXZk26lkk/2AxuruqaBOmOs8xYHQOjVqxF3741DAKNCxWe13loqa50X+gdBpF1qNAo
         FVEIHAYeNtAFj+HE2Jt5fFTyHO+/9s4nRVbqnkLyOVNViB5AfWDsLVzyqLhbb0vv6FFD
         9RhShqltAdUF8opPWkkfoMFnrUzBauvYI/Se3cH8JtVap2kkQVQQ5xfihdVklIyBbY+Z
         8Xzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wi8bgarS;
       spf=pass (google.com: domain of 33dbcxgukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33dBCXgUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ULllRDE+BG9kTY83ej7ljgVqCs6w6/ZT1xqDn3qjvS8=;
        b=tMPx0LQIYIpVyScPc9wZ6+/kqUunPGTCujOM4AQLM5qMxv+1gIg0wqbDW2Gs5xfsiS
         REJXPXPMMnUB5cBjfrt8vQIhLrbShuJ5w9YcMPD6hwkpP+Vrzb9vCta2YodDMrPEhIfE
         9qTfBXugJHbU9/NTLz1LYpKKqjfDsjHwOp/jz9nDelpVynLvTG6GCJMhnDDHMIubl22v
         uT/4SLVM7cb6sefq9azvcZfqjg+GSJY615QmQICopRGr6csf0lu8jFfNXV9xiaKj8MAG
         eKz7cIeNxlAI+DiGb7XScO5w2+ySSc4g1EvlYqOF6CQJvfEWuz8+S+xcg2lvtWOIgLgR
         3Jbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ULllRDE+BG9kTY83ej7ljgVqCs6w6/ZT1xqDn3qjvS8=;
        b=ieuLo7sKTohM3Sc5pLiS+1XKtTf1/upKipwLGjmu+gE9YoQuXKAID42ukIYhTXW6VG
         g8Y6KRS/zkKbsr4U+6JAHjvUv93cH8LcWgGPFpX83PbgOSNes38D90ZBV40nBrCJiqj4
         P21iJ9CWxbnB69rEBOXIY8hAkBN69wB8YTyghX9yKdf8DgOJa356mgfE6u0W6ceBhHFf
         LHCXaUkQRjODVUyD2AJTc/mmCShY5dsO5yvpYHb12ZS31rJcQf++cgfLR15KKwiUAMEZ
         IMUPNlC5nmXsIGQkyEsKqyibol/jL9nMgu2o1tukOl9FiEua9A/z79ThrPEiMDYxPiF9
         c+MA==
X-Gm-Message-State: APjAAAWU+kn2E170LFCzv2w6NgHvra4bb7pD/6D2HfGQPHlCLVcHz8ax
	fWHuaq+3ONS3ok4HuPRXCoE=
X-Google-Smtp-Source: APXvYqxmVvkAL+2VHGtCKUBoI8wTdE/zOkw3nVv/cWLGhtAjKL8+9hhhDHsB6XtLDotmmTMwvk8upA==
X-Received: by 2002:a5d:5148:: with SMTP id u8mr9680176wrt.132.1581437150920;
        Tue, 11 Feb 2020 08:05:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:82aa:: with SMTP id 39ls8548493wrc.3.gmail; Tue, 11 Feb
 2020 08:05:50 -0800 (PST)
X-Received: by 2002:a5d:4584:: with SMTP id p4mr9784183wrq.25.1581437150298;
        Tue, 11 Feb 2020 08:05:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581437150; cv=none;
        d=google.com; s=arc-20160816;
        b=uUHB88vDFBIa/2PeAnWElAOzpcCgFMIMI7pLxOP0/i2aX/iAedcjj0SUk2mBW10Xx/
         ZDXmoxFI4p6Sz7Qk645l9rhJIUkN7tqnd8R4Oxw2L5w+hqTgnjzJOFh+fXp12dBzqqP1
         0ZaWgPyFEmpivjS0fAgk4z5Tie6Lmup2iuUy8cZgYYJ7J89ew4htdfZQSqz0zgRkrG8I
         yH/U9+R3sqwebPNHRNvt7P4HLivHg/Z6kgPDpjStxZ8CsA1310jRtPKegmcifRYEp4xQ
         B2xtp5eEqF38XSZLrPvZ/mJ2llnEr9W3gZnW3qcH/qTwE6BThi5Sy51DNR4Cw+j+Nxjw
         78Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=fPyPj6YXKlNnOn1twoWGjqPJDWM/gm79Q9ZakEnsr3Y=;
        b=fCPNmqmekb3VPn/xb5t1jQitrY2EEdn+ScvJRYXLRrVXZTF9+jxUH8WlqsB4qpfeSm
         pxEiKk1DuVTtXF6UqcQecepyhnY7yePly5rz2jQgua2R3ux0ISd98PaYGyTIRaPDm4FL
         qqfdJNG/0fBCIUytjPKVJIVr9ENBF6I6yYc5lj8DqJj23j5z6dOUAW1bLnwsR+UGPKWN
         4j8W9AfxKkyogUCDclIANJBsFIC8xM6b+8CiS3ykyWiPqMdb6PjoC9Xt1H/ULJzj0xro
         nWuwM3OOowTZuog+TUhp30yGXQwD3adscUhNfgRS/azJc15l7ZxWRB62UGyAGTTqJx4d
         h4aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wi8bgarS;
       spf=pass (google.com: domain of 33dbcxgukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33dBCXgUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id i18si203808wrn.0.2020.02.11.08.05.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 08:05:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 33dbcxgukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id o24so1641461wmh.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 08:05:50 -0800 (PST)
X-Received: by 2002:a5d:474d:: with SMTP id o13mr8979251wrs.309.1581437149565;
 Tue, 11 Feb 2020 08:05:49 -0800 (PST)
Date: Tue, 11 Feb 2020 17:04:19 +0100
Message-Id: <20200211160423.138870-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.225.g125e21ebc7-goog
Subject: [PATCH v2 1/5] kcsan: Move interfaces that affects checks to kcsan-checks.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wi8bgarS;       spf=pass
 (google.com: domain of 33dbcxgukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=33dBCXgUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

This moves functions that affect state changing the behaviour of
kcsan_check_access() to kcsan-checks.h. Since these are likely used with
kcsan_check_access() it makes more sense to have them in kcsan-checks.h,
to avoid including all of 'include/linux/kcsan.h'.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h | 48 ++++++++++++++++++++++++++++++++++--
 include/linux/kcsan.h        | 41 ------------------------------
 2 files changed, 46 insertions(+), 43 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index cf6961794e9a1..8675411c8dbcd 100644
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
index 1019e3a2c6897..7a614ca558f65 100644
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
2.25.0.225.g125e21ebc7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200211160423.138870-1-elver%40google.com.
