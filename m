Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHEURT2QKGQEA7TYHJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 588371B7A70
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 17:47:41 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id l14sf7355540ooq.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:47:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587743260; cv=pass;
        d=google.com; s=arc-20160816;
        b=nAm6OjYKrtvQ5jgeQn2mrrowUO9pNtVhbwsIZ93Df3K9+qDzCxQ4EhH1MZUJ4p67R6
         gKHrXYVvIZwzPGLFEmAMNggJRQ5JmuYt/mIPKT8VvOG8DzAHhHCQm13A3qkXO7YPoj38
         XuqeEpTFS13KsPyZFUbuDbHmjMrC82hGJP0DuVLKLiiUTnR5G4ytKeRpPUkVY16y7rIf
         ggQRnQSOKDDoF2m21tdGKOym09VI8LzZkC0neET2A8EPvSLGvBtyax4RJ3Lc2pE3yGIO
         WzqfBtZyatmTTKD23My5SrON4mzQQMA94tI+rFYkozhFDAj5Lfh/3vhmTAyHyxl5nN9z
         XhTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=9Xe6ljMUfhL9DdX0dyRz5de76atuT6lsa+HxmdUKlxA=;
        b=ATt+uStu/wvZh6sqO1sTvghF08mSZHAOjeE0gD65/LiYfd1L3GurpTB8PE+aPpBO2R
         c5ydljxbCQ1i9mHXSJy/4qK/vRErUCK1qFVULbV24+UqSmxn6MjNWe8M76Ass4az2Gwh
         bCOYJfMqCZBa/B/+6wO8Hwiqynx0lFsaX0+MaXtoWqgEdfeOzE5uRlHiIs4Sr5f2PX3W
         hkLiqRAlkzx0godF+5lPNOsZcr0NxjFx7OiFnD5ah+1PYPDII1ejFETGbuRDzb66YlxR
         M3tDw2IEDXe+tkD0LQWRqXU0GQx4VMMw84RFGkiwWho3DqJh4uD6CcSo3QpQJboRAivU
         2/Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WGqU76OY;
       spf=pass (google.com: domain of 3gwqjxgukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GwqjXgUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9Xe6ljMUfhL9DdX0dyRz5de76atuT6lsa+HxmdUKlxA=;
        b=B2POG1fm4e0ke6Q1/XC0RKwHx7753nyz0oPKeh9afE1ELi6y6W+X+9tqC/JYQA6S2+
         ROePu9xGZI7M8pmbXD5Ima2+GlnB9TzS3ZHYUwOzvdmA5QPTB2x1Hay900/qGKCsr7Y4
         t5hPqCERib5bwTLJZ891fBPan4TY3BPY6htOvNRIrzUaGK8+lW+zIpMeTGSwx6eyIwLD
         fRBdCCOO3c5mxQQT8Wf+ysnkvI34Jarn+gki5HiDSXPymqDgSmnFJYOtRCR2y83r4+KG
         EawNqoDuL1yyVkI0zkZ7V9pju6uC+OfLKbGvX4PfFns+J5JoAK06bi+xwhJ4KBiAsypu
         8ocw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9Xe6ljMUfhL9DdX0dyRz5de76atuT6lsa+HxmdUKlxA=;
        b=nAwWya5h5OIk279kuL7ZktNPW5EakQU8giVsQlzP3lC6qFex24C2zWXSrrQ+Z15W6+
         7Xxkut6h8MOpNSu8A/WBvofMMUqW/QhY3xMsUVbQn9Z5PWCRM9LgHu1XmJbgQvLU0+4G
         mL4OWtXzCy7wKjMoo/tHPBmKtDrjT/Bt0xw04TAziJ9ab04xJFtsbkMvmSpGxBs30JQK
         +pNSRL2Sb8ZE7hOwkQ8RUYn9TPHj04qnBdPs11ziBQtbW0gsLMiFhXXeSMOoUkk5nu6h
         XGzVoOP6uut6hhpX8UzPF3boDQeOWWYuUf+MNR0c+yfeY2oQ425ureRl969i0Ias3Okj
         th2Q==
X-Gm-Message-State: AGi0PubJX9Pxf5YNiKMRRgJCoA6C9TOwU84xApoWeJbkOzdDtMlJhOB0
	Mg2VNvrM+huaYyXeU4Jsw+Y=
X-Google-Smtp-Source: APiQypL5gE/R9A+JhB3L25cbWUhxVPx3JWvLEzb+mlbVjQzfP0u1lWPTvS8X6VsH2Km1hlf5aS83yA==
X-Received: by 2002:aca:6143:: with SMTP id v64mr7464980oib.36.1587743260351;
        Fri, 24 Apr 2020 08:47:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:108e:: with SMTP id y14ls974458oto.9.gmail; Fri, 24
 Apr 2020 08:47:40 -0700 (PDT)
X-Received: by 2002:a9d:7990:: with SMTP id h16mr2622567otm.145.1587743259952;
        Fri, 24 Apr 2020 08:47:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587743259; cv=none;
        d=google.com; s=arc-20160816;
        b=iqijdghlQMh1/FYW2UvmgzdafvPqNdQNf4P5k5MRwuPJOZ3JEvn5PikyQNelJp4vlR
         oM4qRaOc5fDNBcqFgEIGZfH9zaw6x0MRK12utTFfNXeTedxxeKMNPRWX0Kvphzn8DXkh
         Zit/GziTchuJD8gsIixRgsj1vodrqr/M+/f9oLCYiER0vqlEWpTPk97Q1AnOxL/Ri/0g
         2x+llIToPOUYPnyUIHsam6BSNnQUCrNJSCwm+wwn5408GU8BqRNYxPsxeaWfKjtrV90k
         XApRUc3Orf4idAvUJ/PhxKN7z/V38/nW4VuPgRdLaxmqIp84c2u3jaB2wyzo7WRUKnXA
         ImeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=grccW3g/q/18tgku44K89kuFTrJMvGmwGZNHR1ZbIyw=;
        b=gFLTsYet2L9wYHVK0c3cyUQq+EHmE2BysFh9ptDOiqtsi9wJw0L/VlUI6LPDn9I5My
         P8uq/9LoVf2ZbngQAYL6eoFXNGfubMKjwBfM5V4/c85rm0u5gFRdMZouTGG7VQ/VAG6Y
         qDOL/R/4QnAVk+Ix6iJ2eY9UsdAWokiFSC+OjlXi5rFOaXABwiC9mEfOeIQ3N5b7wKOQ
         JhmWHDDQbN83IJQ0Wuphcsu2l7GWvEBM6MR4gs/qekntLP/9cbBgVLtqoR+dJQJ8D5Uy
         6fd+NbYTKZZSmlsPgcmuLtbbie/Qw0PVB0O30/PIJakk8DeelDCgXW00H0oNF9TOuOKN
         YeFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WGqU76OY;
       spf=pass (google.com: domain of 3gwqjxgukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GwqjXgUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id o6si768616otk.5.2020.04.24.08.47.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Apr 2020 08:47:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gwqjxgukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id u13so11456405qtk.5
        for <kasan-dev@googlegroups.com>; Fri, 24 Apr 2020 08:47:39 -0700 (PDT)
X-Received: by 2002:a37:aa8e:: with SMTP id t136mr9294100qke.175.1587743259356;
 Fri, 24 Apr 2020 08:47:39 -0700 (PDT)
Date: Fri, 24 Apr 2020 17:47:29 +0200
Message-Id: <20200424154730.190041-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.303.gf8c07b1a785-goog
Subject: [PATCH 1/2] kcsan: Add __kcsan_{enable,disable}_current() variants
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, jpoimboe@redhat.com, peterz@infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WGqU76OY;       spf=pass
 (google.com: domain of 3gwqjxgukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GwqjXgUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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

The __kcsan_{enable,disable}_current() variants only call into KCSAN if
KCSAN is enabled for the current compilation unit. Note: This is
typically not what we want, as we usually want to ensure that even calls
into other functions still have KCSAN disabled.

These variants may safely be used in header files that are shared
between regular kernel code and code that does not link the KCSAN
runtime.

Signed-off-by: Marco Elver <elver@google.com>
---
This is to help with the new READ_ONCE()/WRITE_ONCE():
https://lkml.kernel.org/r/20200424134238.GE21141@willie-the-truck

These should be using __kcsan_disable_current() and
__kcsan_enable_current(), instead of the non-'__' variants.
---
 include/linux/kcsan-checks.h | 17 ++++++++++++++---
 kernel/kcsan/core.c          |  7 +++++++
 2 files changed, 21 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index ef95ddc49182..7b0b9c44f5f3 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -49,6 +49,7 @@ void kcsan_disable_current(void);
  * Supports nesting.
  */
 void kcsan_enable_current(void);
+void kcsan_enable_current_nowarn(void); /* Safe in uaccess regions. */
 
 /**
  * kcsan_nestable_atomic_begin - begin nestable atomic region
@@ -149,6 +150,7 @@ static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
 
 static inline void kcsan_disable_current(void)		{ }
 static inline void kcsan_enable_current(void)		{ }
+static inline void kcsan_enable_current_nowarn(void)	{ }
 static inline void kcsan_nestable_atomic_begin(void)	{ }
 static inline void kcsan_nestable_atomic_end(void)	{ }
 static inline void kcsan_flat_atomic_begin(void)	{ }
@@ -165,15 +167,24 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
 
 #endif /* CONFIG_KCSAN */
 
+#ifdef __SANITIZE_THREAD__
 /*
- * kcsan_*: Only calls into the runtime when the particular compilation unit has
- * KCSAN instrumentation enabled. May be used in header files.
+ * Only calls into the runtime when the particular compilation unit has KCSAN
+ * instrumentation enabled. May be used in header files.
  */
-#ifdef __SANITIZE_THREAD__
 #define kcsan_check_access __kcsan_check_access
+
+/*
+ * Only use these to disable KCSAN for accesses in the current compilation unit;
+ * calls into libraries may still perform KCSAN checks.
+ */
+#define __kcsan_disable_current kcsan_disable_current
+#define __kcsan_enable_current kcsan_enable_current_nowarn
 #else
 static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 				      int type) { }
+static inline void __kcsan_enable_current(void)  { }
+static inline void __kcsan_disable_current(void) { }
 #endif
 
 /**
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 40919943617b..0a0f018cb154 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -625,6 +625,13 @@ void kcsan_enable_current(void)
 }
 EXPORT_SYMBOL(kcsan_enable_current);
 
+void kcsan_enable_current_nowarn(void)
+{
+	if (get_ctx()->disable_count-- == 0)
+		kcsan_disable_current();
+}
+EXPORT_SYMBOL(kcsan_enable_current_nowarn);
+
 void kcsan_nestable_atomic_begin(void)
 {
 	/*
-- 
2.26.2.303.gf8c07b1a785-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424154730.190041-1-elver%40google.com.
