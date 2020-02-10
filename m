Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVGIQ3ZAKGQEILWTKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 56ED81582DD
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 19:43:32 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id t3sf5426231wrm.23
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 10:43:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581360212; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZICdTX1mAntF9ZDlfVWdypCBtt/D7QgaUsy3HWIcB9mPB/srPnxNIwoZu4siGBBit5
         SvY+bWVAzVcj/UNr/nkE4nZm8gfBNG5pPwB97oGNUUrGjl7cS+5JeHQ/kr7HPpzh+lOg
         FjWMAIn2Wnte7ouyzY1VYl2iNDT8TX3fRpTJuZK2EfEwhVJ15Bf1p9zIvnW6GtcHRUGx
         3BC3BZpZJIlcckfYWr7BGCpdNecQEdLLRYfMxJYIJLMFIzFgYdaWdLLvLcMuOUddWWEh
         xGldgG3moGOZMNdDrBQ9EQG2OjLGXoDG+tMcWU+c+KClpkm4fvVuP0My8T4MV1v87+Ne
         OVgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=dd9gkb7hbfOnfJRO8kDxOgY/AKrEuoKWkbtEBhuFEj0=;
        b=vkYm0Z7fLcd0YEBrEIuH/ds58iXEcsFmr9bdq/30hfXyU6PeelKg3IHqKBjtXVBJ7l
         G7rDgPoRXmFpBfvOj+j+87+xf5tABZuFm0/UdbAB4ScFffzhSsALAGTtYQRZ/66gOgwY
         wXoUUf2nxWsHfZVE0i1hB4oLIivaFyY2qtRWM6Gj4PDivaKBdTPafzt7OOP5DKD2awk6
         mlOuPQ27YUe5Y8zya86iSdlbCTl3bLX09f8A+MnkNtMHE0/YO9Y7vGtrEQlS5WPaRb/1
         7vFkNxlEDH5aquNKcICKv4a0Fg7HuGKBJBZVMRqUlIAkn++kRyEtBdQuICnGhWf6Hqxo
         hFkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H5bI+iOB;
       spf=pass (google.com: domain of 3uarbxgukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3UaRBXgUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=dd9gkb7hbfOnfJRO8kDxOgY/AKrEuoKWkbtEBhuFEj0=;
        b=afDsLoosrLRPXwd3n2tmBQ8OesrD8VwEXCc5YWqVhrYBQl9ZXlzLGw7pXhwNwimVo1
         PfqA01lTatRGNCbiuz333JQTvAHyL7xz48JKtEtKio1P2hkT2E7HTz+owmmhj+X9pz9/
         4ERmOCrj7nvprUTwBH2w6cvwQK6VM+/jJOL2uM2hEgvqCcwkASerfvYPdWNNyplD5PbC
         tydLG7sfF2qR74FgU/Ctnq/lIL0M9xsTppZFYoXWItwr8lOw92/MSDg4bLZG7tBsoUgV
         mRnXjq3phlUtMqef65QIkiavFlTSxoDfJusNSvIOcIlTL8SDaPZb7FBiHPbqCLVT3ROd
         RvAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dd9gkb7hbfOnfJRO8kDxOgY/AKrEuoKWkbtEBhuFEj0=;
        b=fm00791KUmQ6RU6DKGRrKtbVlMcSDGEMIDRaN7/6910uv7nBA48UQ6JKRYIExCGFRG
         v1NEdbZtyvZ1gcdRJwpt/cYYjoefcfMhMDe8RyBPhWdDHaWRYUtcT4LRjtr9QSAkAsiv
         UAfJh/cEL41Xsa/Rc6jwbWwQTsOOmZ3yaMsDsYq+x9j6YUr5KJjoxHguGAC4HsbUMM5C
         0GeBW4xnPv4PrDWg45DCa87fwVVfwQiUSz/OF2YMEyFA2FyeplCANvEnT8VeVRyFWOjQ
         go44dqghGkjO2jajX6JyVLGWK8CLkuoS+rTzLfnvQ6U+wjetTcT6W5H2+4WqzU3SwJNo
         /IYQ==
X-Gm-Message-State: APjAAAVV9NLDpu6k1kseXDrrAghmVghWcvoTc9O06T6W9UF5pyrPbMEt
	O9oQsoYtvdyk+uxRvyF4zU4=
X-Google-Smtp-Source: APXvYqxKeodgj7aDNfOK84/aQFubfGqhVyBozgCqcR1Ik4kKM5aJ3MhsWenQ9CzD7w0j3NEF9Le/sQ==
X-Received: by 2002:a05:6000:1183:: with SMTP id g3mr3419287wrx.374.1581360212092;
        Mon, 10 Feb 2020 10:43:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6385:: with SMTP id x127ls374919wmb.2.gmail; Mon, 10 Feb
 2020 10:43:30 -0800 (PST)
X-Received: by 2002:a1c:b7c4:: with SMTP id h187mr336849wmf.105.1581360210561;
        Mon, 10 Feb 2020 10:43:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581360210; cv=none;
        d=google.com; s=arc-20160816;
        b=syK7yNxb90iRld+pSxhz2aFKPMVG5brI3k7XwLhk6Qn0xAalRwjRqF7bEFNXmwQMs7
         1jVgLSS1nN4CY9l/dS+tMlsK0A0bgM2a2QwVeofa8VD4CKQ56Hc/75FLusKJ8Yr8IU6J
         UHD+ljNHnPfhXi/e54e/Km1Q6tZ9IvNk5fcc7Ti10iT14wL8ll5ef6PSDcwkN8Hq3Orp
         JcVrcVsmG/mir13xspfyRFGYd8PsKkIJeWsRfw6Fweb9Lu3lvKm4iHSpGNQp3iSyXy2e
         +Fo/x7qAQS73x29Z25w7Ab6mo6eUjjcwltqVhss1cpG+us/mbUP/PLKKNHkMTSdKW+oT
         c0fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=QdVP7VsBJw+IixbDmWdM2Gp9NWKsZNR2FStw5cLegFk=;
        b=U9wX1GwXFt0yGwFMCbqB/XIOuXOAMaDX+y1uiAcpQ/Zu0VcaZRCYNaswOA75HEukYm
         eB48OT8MMtVAf0C3WpPk/yrhfzgo35qnJnzkmLDvcQ7rWxw4cpOp8r/WdEdceCRsVyJ8
         n7fkuxqqCucZQKKPMcMAUNKjiO9bAINhZb0BQaxAweUs2D+9g2Fth1owjcEQH/J3Z1Qs
         pMk0z92aS9cW6OKjpwHYtssj66XcgxwO3SIokGXfM0TpVn8d08hp2pjSZoaevMzxJEGM
         ORcUY6Wv9Z//5yaqvI8PGGFb/W4WBHaCpiWHrzlcty+oZZxvGqkwZ9vQjeHr9mpiVCzs
         c/RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H5bI+iOB;
       spf=pass (google.com: domain of 3uarbxgukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3UaRBXgUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d14si52468wru.1.2020.02.10.10.43.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 10:43:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uarbxgukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id n23so5464690wra.20
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 10:43:30 -0800 (PST)
X-Received: by 2002:adf:e38f:: with SMTP id e15mr3520748wrm.271.1581360209995;
 Mon, 10 Feb 2020 10:43:29 -0800 (PST)
Date: Mon, 10 Feb 2020 19:43:13 +0100
Message-Id: <20200210184317.233039-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 1/5] kcsan: Move interfaces that affects checks to kcsan-checks.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H5bI+iOB;       spf=pass
 (google.com: domain of 3uarbxgukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3UaRBXgUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210184317.233039-1-elver%40google.com.
