Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIVD3GTAMGQEU33RWXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E07747792D4
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 17:20:03 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-1befca4fdfasf2504352fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 08:20:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691767202; cv=pass;
        d=google.com; s=arc-20160816;
        b=FsvvcmSEXYy9hjJau2/is51t9mg+o3Xh4tPy67seGbL9ZaslAd49CpekSJKb7CPJ3S
         ljFfruIu1O/EFiJNQcHWD7hrGHD8R2RoWBo2cXj4QP8zjOp6DxGgudD0/XzaT/amw3Dp
         XzCdCSEcLVqovVmm0jfcvXz++ARlZ9bXSdtJntkF/+U0tdJPje6hv5czcNUMtVWyJbn9
         liJIRgsqgkIh2ANIw8v/REUqINndh4Tus4fK7p/77QHvVRExR/C9l2HLi84KUhgZRo1t
         f/fSVCX/WlH7XcscjGFjF1WlMjz+I1Z6NbdvGxwI2GX8xqn1y8MEVOAZJm44AyrjuScx
         AM+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3++ICTvGVJpHjezq6pCEAge25nn/n/CIBANeQbC4doY=;
        fh=qzUwxS9h9GHZXLKRdSveNA0UW/h6SdpMH03X1Oyv03c=;
        b=ioWcDJ8iP8EUdm6PrP2I8Ej5amWygYsc+WUbHBEGIAebh7FWKyXX83L9gfDCbim/RQ
         EtxwjUcBVqNwsLxP6XxpAYlazmEXfP6PmePfrKoiEYjjy7ALAhweagwZYLNosCh0WSyV
         /Xtmi0OlbhVkYoLTYHQ6AOsHy00dDowm6/VcJiRx4AOBjsYEUEza+77VmwHKc+87Rh+d
         Vttny4Q68u8/o7lM5rGFym5AO6dzBCF/flyyRL1/d5SnUeXaXLnW9zgxhJezCxiOWZqW
         G0TwlrAD07ZS0bOU/ujPhNBxPEeUPq5iwVfKHg1P06qWdV6WIx4KRprAvQg6hgyKdHBl
         rBCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="m1/D3Wz2";
       spf=pass (google.com: domain of 3ofhwzaukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oFHWZAUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691767202; x=1692372002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3++ICTvGVJpHjezq6pCEAge25nn/n/CIBANeQbC4doY=;
        b=l6j3O71ZBrFiHZhWRAp1LZbEABwta5ZrRp/vnG82KYeVyqvawiSWRFe9nOK/PZgWDn
         i4UMhie/sRX4gjOJ9vDGFB8nRueLB3OBllSQ0vJ3EHeDwKhcUVV/YGe155obHuvgiwY/
         zlItD1lukYAaKnypWg7whwkuCyuQ67+TsLP05Ga+4s2pPxWYizdw9o6FyrQIb/BUyxUl
         rlG6VSFonwSHGUAffWPWd0cLwUOHISehgOz8gRYDwk9mvnrSrc3qVMPtmr1jGxImVMX6
         VW+Lv5nKaj0w56NJzO1afLzBcAY/bZ+sgbY1hElihMF251yP696Ki0mpuF/H6qcG9XPh
         iE5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691767202; x=1692372002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3++ICTvGVJpHjezq6pCEAge25nn/n/CIBANeQbC4doY=;
        b=dN15GzpkVID/Umym+9x7e93HBLRB+dd90SchYFkdENRyxXYtA8DLBJ7Pk0gcY4hePa
         xTh8evLq0I9KUGhnGOlni9vSA0bt6XP2rezOJKIB+jzBDWmOu2xsdhxJlF8ep1IkXFX0
         mVp5VZ50aGnqZ8Dy0Fs73QRNliTx+QPOPlZw0jvcqMELy8O6uCsx5J/qxWDaaioyKr4p
         SOPffNluh1dDJLf9cWp+EZ8t+CCsSk/CPlSwnkqpa/e/ypytf+toUsu8dTijcBwecCAV
         I7asNeBBRlXfm1zZO7SvH/A81ot7Fyt3fz2IeEJRlPOzb7T7xe5b5XJlIK9Tv04T5vzD
         EYDQ==
X-Gm-Message-State: AOJu0Yzu3MHN0pDwQggUGdqZ1f38hG1+R47yxqBcCUVVwdACrkTJ359E
	9Z49XPqFatEocOn84LL2obxWUQ==
X-Google-Smtp-Source: AGHT+IH24G/ifdVSoPf5jTmPqf+z9ySFwrSRJz0tvVQIfep8dSU2X9Au6qmB4HAIcANOlVS/oG3rKw==
X-Received: by 2002:a05:6870:93c8:b0:1bf:50e0:95d9 with SMTP id c8-20020a05687093c800b001bf50e095d9mr2168373oal.26.1691767202513;
        Fri, 11 Aug 2023 08:20:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2415:b0:19f:9f28:a580 with SMTP id
 n21-20020a056870241500b0019f9f28a580ls2225176oap.1.-pod-prod-05-us; Fri, 11
 Aug 2023 08:20:01 -0700 (PDT)
X-Received: by 2002:a05:6870:a185:b0:1b0:18e8:9536 with SMTP id a5-20020a056870a18500b001b018e89536mr2262758oaf.52.1691767201676;
        Fri, 11 Aug 2023 08:20:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691767201; cv=none;
        d=google.com; s=arc-20160816;
        b=w+vPxTZwq4oWBs8+VuWwM29s8wXNrQZziVx56hSUHllFQ4mVe2K/vJqtDAFAk5hczj
         SRbXbOLPMKNuMSCXRdpj5VxB6nCT4lR4pYY3cB7mnArsoHBBCU40OTcnsC12WQxXgWD0
         DDoI6K0aMIic7qgxc7F+Uo72a1/7obrheS5YUBW6UyNLRQ1U/Tb5Z3kbo6NG4VGXUTXu
         uicu0IT2OYr/KsMcp5vbd0rmgIhGJL4H63PuCx8gRj0nF6/p9po+HJPJCxPuZxZhGRHA
         fy/eXdNw9RzgaMog/lfjUyMcgG87x0FAiNRDNikHlW4g9pR5MCicEUpOYyia2M4hBDv5
         IymA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=vr1U486Irq718Y5Vjn28mDb0feV+v+GYGzM/Kj2uczY=;
        fh=xh/g7dNJbwYr9WVB3rCguj1R0VLL65UcAaOvl7LeWOQ=;
        b=Zz3+LKYK3FAHNiXr2t1qexvR6JJMCG0iH8cVRZ43Z39BHIpIBFVFDMfAeR19hYtT5y
         w0L8dswSL1AJRVNWXz8am8bHit9lU/rTWOd9IpoU5s7Z2OOYeu0WFEGHvAkAGDqdOc8w
         UFHd9YQVjXS9RwpTyv/zkUNiMzecl+RYFQnxcM888dy5MiIh0p10KyKk7vyo7qUcMrYd
         3B/zZ2chMBwAoEFeUWs2LE6jvoVr6mWUeMjnZFnyG6aSzAMt+uZ+fieIGEnu+5EJMyZU
         DBKCviYiR1SYLuOd2YUiQYSP25Zu8NdkkdLf/UdDeQ5p2ydOqGmTSMqIn6az46Xc6nN2
         XCKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="m1/D3Wz2";
       spf=pass (google.com: domain of 3ofhwzaukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oFHWZAUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id oe18-20020a17090b395200b0026812c2835dsi142501pjb.2.2023.08.11.08.20.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Aug 2023 08:20:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ofhwzaukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-cf4cb742715so2030360276.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Aug 2023 08:20:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:8dc0:5176:6fda:46a0])
 (user=elver job=sendgmr) by 2002:a25:b190:0:b0:d06:cbd:1f3e with SMTP id
 h16-20020a25b190000000b00d060cbd1f3emr33009ybj.3.1691767200863; Fri, 11 Aug
 2023 08:20:00 -0700 (PDT)
Date: Fri, 11 Aug 2023 17:18:39 +0200
In-Reply-To: <20230811151847.1594958-1-elver@google.com>
Mime-Version: 1.0
References: <20230811151847.1594958-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.694.ge786442a9b-goog
Message-ID: <20230811151847.1594958-2-elver@google.com>
Subject: [PATCH v4 2/4] list_debug: Introduce inline wrappers for debug checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Paul Moore <paul@paul-moore.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-security-module@vger.kernel.org, 
	llvm@lists.linux.dev, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="m1/D3Wz2";       spf=pass
 (google.com: domain of 3ofhwzaukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oFHWZAUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Turn the list debug checking functions __list_*_valid() into inline
functions that wrap the out-of-line functions. Care is taken to ensure
the inline wrappers are always inlined, so that additional compiler
instrumentation (such as sanitizers) does not result in redundant
outlining.

This change is preparation for performing checks in the inline wrappers.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Rename ___list_*_valid() to __list_*_valid_or_report().
* Some documentation.
---
 arch/arm64/kvm/hyp/nvhe/list_debug.c |  6 ++---
 include/linux/list.h                 | 37 +++++++++++++++++++++++++---
 lib/list_debug.c                     | 11 ++++-----
 3 files changed, 41 insertions(+), 13 deletions(-)

diff --git a/arch/arm64/kvm/hyp/nvhe/list_debug.c b/arch/arm64/kvm/hyp/nvhe/list_debug.c
index d68abd7ea124..16266a939a4c 100644
--- a/arch/arm64/kvm/hyp/nvhe/list_debug.c
+++ b/arch/arm64/kvm/hyp/nvhe/list_debug.c
@@ -26,8 +26,8 @@ static inline __must_check bool nvhe_check_data_corruption(bool v)
 
 /* The predicates checked here are taken from lib/list_debug.c. */
 
-bool __list_add_valid(struct list_head *new, struct list_head *prev,
-		      struct list_head *next)
+bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
+				struct list_head *next)
 {
 	if (NVHE_CHECK_DATA_CORRUPTION(next->prev != prev) ||
 	    NVHE_CHECK_DATA_CORRUPTION(prev->next != next) ||
@@ -37,7 +37,7 @@ bool __list_add_valid(struct list_head *new, struct list_head *prev,
 	return true;
 }
 
-bool __list_del_entry_valid(struct list_head *entry)
+bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
 
diff --git a/include/linux/list.h b/include/linux/list.h
index f10344dbad4d..130c6a1bb45c 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -39,10 +39,39 @@ static inline void INIT_LIST_HEAD(struct list_head *list)
 }
 
 #ifdef CONFIG_DEBUG_LIST
-extern bool __list_add_valid(struct list_head *new,
-			      struct list_head *prev,
-			      struct list_head *next);
-extern bool __list_del_entry_valid(struct list_head *entry);
+/*
+ * Performs the full set of list corruption checks before __list_add().
+ * On list corruption reports a warning, and returns false.
+ */
+extern bool __list_add_valid_or_report(struct list_head *new,
+				       struct list_head *prev,
+				       struct list_head *next);
+
+/*
+ * Performs list corruption checks before __list_add(). Returns false if a
+ * corruption is detected, true otherwise.
+ */
+static __always_inline bool __list_add_valid(struct list_head *new,
+					     struct list_head *prev,
+					     struct list_head *next)
+{
+	return __list_add_valid_or_report(new, prev, next);
+}
+
+/*
+ * Performs the full set of list corruption checks before __list_del_entry().
+ * On list corruption reports a warning, and returns false.
+ */
+extern bool __list_del_entry_valid_or_report(struct list_head *entry);
+
+/*
+ * Performs list corruption checks before __list_del_entry(). Returns false if a
+ * corruption is detected, true otherwise.
+ */
+static __always_inline bool __list_del_entry_valid(struct list_head *entry)
+{
+	return __list_del_entry_valid_or_report(entry);
+}
 #else
 static inline bool __list_add_valid(struct list_head *new,
 				struct list_head *prev,
diff --git a/lib/list_debug.c b/lib/list_debug.c
index d98d43f80958..2def33b1491f 100644
--- a/lib/list_debug.c
+++ b/lib/list_debug.c
@@ -17,8 +17,8 @@
  * attempt).
  */
 
-bool __list_add_valid(struct list_head *new, struct list_head *prev,
-		      struct list_head *next)
+bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
+				struct list_head *next)
 {
 	if (CHECK_DATA_CORRUPTION(prev == NULL,
 			"list_add corruption. prev is NULL.\n") ||
@@ -37,9 +37,9 @@ bool __list_add_valid(struct list_head *new, struct list_head *prev,
 
 	return true;
 }
-EXPORT_SYMBOL(__list_add_valid);
+EXPORT_SYMBOL(__list_add_valid_or_report);
 
-bool __list_del_entry_valid(struct list_head *entry)
+bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
 
@@ -65,6 +65,5 @@ bool __list_del_entry_valid(struct list_head *entry)
 		return false;
 
 	return true;
-
 }
-EXPORT_SYMBOL(__list_del_entry_valid);
+EXPORT_SYMBOL(__list_del_entry_valid_or_report);
-- 
2.41.0.694.ge786442a9b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230811151847.1594958-2-elver%40google.com.
