Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL77WKTAMGQEE6PXXIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7702176FCDD
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 11:06:56 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-3fd2dec82a6sf11785425e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 02:06:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691140016; cv=pass;
        d=google.com; s=arc-20160816;
        b=RIVVeMqJoQi6pahk3m9IM6KcHHzINVPVC1C6yoEBaulCbUjHqnhRbh7/XT5IBxh/gJ
         P0/SyVXrscMnHB9JiVjvLkQNjS4uWskdwlhaH68StDbM5drMHqO3ZBkncHikoBldJWUz
         VHHw6JVvz9MyhwHTgi93RK/FWZ46pY2Wkghp2OekMYLs52y8bzMQguGEDhXsYMfRja6+
         B0dN12vwgNTA9x75NlFo36Rn4Z39Y7ks/C3eItm1b7RSunihS9V1/89gc3zqHhHPtI2N
         9z6wyUDD3wy6QGTKZTkA8kL395mQTPoFVg5avCGMmyVMrogcryA3IQh9FMnlLdJY1JIW
         Hhqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=RbNFtOT4YLO//YgJGqrHX8+wAvywgSRq+fZ3Ga6kVoE=;
        fh=3EsCV1kjHdS/GYEZbaUoPw6fO/lAfz1JWLpP8sfLAPw=;
        b=LEnWQ8hTvhCLIyZy9cXW4kAmnA9x25c3UU6S3JTmSD7sDk53OlxmVSB02o9Y9MhbsS
         z7mbHIh97j8w1qv9Cnu09rAOm+C5Xtc6rG7BopWUaEMf+SOkLnpcjdmrwYZlCsnxiyBL
         MmfNg3jXtJWvsBl9EgLttjV+Gv2Z7tjx+P6aV3ZsQLpPR5KUSAVopbbBHJfCaYeVFW2M
         4p3KvQ5BozGkWpUIflGEj6TIrVLvXqlOxwgCmaAq5SmdDfoKnpRRPh47bi+ZB93XK2h5
         bApk2XRf19wZVDoHcFx35QlSIicO0X1rkHBM8tRBxEXQQDPokgO1JnGnrPHxsjrpgy3w
         OzvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=2ZPhM3ag;
       spf=pass (google.com: domain of 3rl_mzaukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rL_MZAUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691140016; x=1691744816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RbNFtOT4YLO//YgJGqrHX8+wAvywgSRq+fZ3Ga6kVoE=;
        b=IdJZUzNR7Fr4czxfVtj2HPP0lfFoEUOvNF81mJ2WsyYVEVkTKcjROBK8T2H+amYl6w
         3VMquW7cjr4RGuGiR6hrW0Bxmjyxvx8gRUX3AqfI5zI833HEeDK9sI8f6YzLXZSthL61
         of/lrucqq/GqFEaBFEsLJ9NuzH/KpfHXLph+5Mmd4c/L0NPtzPP+cCGWQJwJ86TjCZNe
         Bs+yHSxFE+3W610aJZ51IltDhQec+wIZqjstB60A0k4ZMlhkssOfU80gC0K/hOumVPNa
         iH/vf1sSL8ewZhvZuGUswS1gZaGc9vGRWY6WolxnW7tMXO1ZhGZElmpgK/jQdRXPzuvR
         mGZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691140016; x=1691744816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RbNFtOT4YLO//YgJGqrHX8+wAvywgSRq+fZ3Ga6kVoE=;
        b=ZKA4dLAWbt2yXOWbFSda7wVGJZ8sPxaZgqGTCHzwD4s8rvTYbydOszh1RGFtkIBJp/
         4/p77eVd69op2v3JhSZwYx+sFq4z+xVgT9oIhoAbj3kXRtP1h70C+F4XfCTEH0B8Dg5f
         9/tQ09nLTkGrRgb8UiNlPbaIR3W2n6XriJ0Us+DLgPsOHQqJ0fWX2kuJ/aUhQL742T9k
         4OYerhJD/SIN/DGrqmKAtSVyrpUU/Itj4CbLtE+YD/T19Gc+8nV9/45Gb5TSXnp7bRIp
         0/FqPS0hwmYJQdOnkQ4uKDbrQ/6HPfqBqISfZixr8r6DdIEWqAHdD2Oku0CRwvfZPcIH
         ihDQ==
X-Gm-Message-State: AOJu0YxSsVFUZGiL8LFRTYqpWGz/bQq5sE/Y0UWwvUXMf4r7UN3Wdd1Q
	RJ8ow6+zg2RH/fzFST4751Y=
X-Google-Smtp-Source: AGHT+IF18RiNOqzkclydmLbCaUGPuYLRsbfzXg/HoC6Ovu4/2e7cGU+UxJI0n7yqZ/+MYv+M/Q5Mbw==
X-Received: by 2002:a7b:c348:0:b0:3fe:4900:dba0 with SMTP id l8-20020a7bc348000000b003fe4900dba0mr1012728wmj.16.1691140015254;
        Fri, 04 Aug 2023 02:06:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:601a:b0:3fe:2021:25e1 with SMTP id
 az26-20020a05600c601a00b003fe202125e1ls2903048wmb.2.-pod-prod-05-eu; Fri, 04
 Aug 2023 02:06:53 -0700 (PDT)
X-Received: by 2002:a05:600c:2259:b0:3fd:2e89:31bd with SMTP id a25-20020a05600c225900b003fd2e8931bdmr1038020wmm.14.1691140013399;
        Fri, 04 Aug 2023 02:06:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691140013; cv=none;
        d=google.com; s=arc-20160816;
        b=QlpYIpQW45LkHzpv5EVyYM1RmHg7TFpoYK3/oNPIHTs+Z/T6ag3kIN1isVNGCUARYL
         n5SVt0NqaKCHTvW8dakj34YY/rseC63KypHr5OCwKKgbWTCqY/asfGkByWLaBQvgCN6P
         RrldAoOo1q0huI6+oS3JCcwjzqSuN2dV7miodmFdfB3hzfcjSqy1/7c+gMTcQL4WmXTS
         nPQIXJ/kIlZh0XvHC+T5lS/LkpU8jpU5O8oKBUBOiww9Tb8RaunUI73EIkQ9FhyOPWtU
         V5+VHVAd9Gw52LTTcvtSx2qHBiUTR/S7WVkpf86LzoMZtutKRb1USOQLopz8K02YNaYJ
         iF5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=GKmfKWa1C9dNl3H8pIKLebOm0SSKHLFe115my+PvGn0=;
        fh=J68g6MH/W7wOt124Z8Lp4h64rxBVPLWDnNTMQSSfdjs=;
        b=ILjPTT9P2uQfLmFRhToWDKDpuMRmUFum5vFlnmWmNxginakZJVnvJWtU54jszTb/TR
         1LmK8SD7b1VR9lOlR2rCGsWMkw32mHI/6xYPPAtI0heIydam/ZpjEwoC/JvotX5yeg7G
         vUkr79eZurJx+pNc0DSN1Wy/Ku0Q/+kFcj5vnbLn/0uvdmiWJABSn98UU3GDaazv9v6z
         ZXbFuEKidbYjWVPkwqeEwUxZzzpxBKp7/jHbayeQk15qfZSQYij3KnEI5w57Y6Dk+pmH
         0Rg/GbhJEa2rXs9hldkd2DTYKDN78iCT3JO0B9M6emFbETKSPBgo3b/mnIKfMoF2+bVF
         c/NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=2ZPhM3ag;
       spf=pass (google.com: domain of 3rl_mzaukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rL_MZAUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ba18-20020a0560001c1200b00317b109557asi165751wrb.3.2023.08.04.02.06.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 02:06:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rl_mzaukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3175efd89e4so1218687f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 02:06:53 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:2ebf:f3ea:4841:53b6])
 (user=elver job=sendgmr) by 2002:a5d:457c:0:b0:317:4ce5:c4b4 with SMTP id
 a28-20020a5d457c000000b003174ce5c4b4mr6475wrc.13.1691140012752; Fri, 04 Aug
 2023 02:06:52 -0700 (PDT)
Date: Fri,  4 Aug 2023 11:02:57 +0200
In-Reply-To: <20230804090621.400-1-elver@google.com>
Mime-Version: 1.0
References: <20230804090621.400-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.640.ga95def55d0-goog
Message-ID: <20230804090621.400-2-elver@google.com>
Subject: [PATCH v2 2/3] list_debug: Introduce inline wrappers for debug checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=2ZPhM3ag;       spf=pass
 (google.com: domain of 3rl_mzaukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3rL_MZAUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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
 arch/arm64/kvm/hyp/nvhe/list_debug.c |  6 +++---
 include/linux/list.h                 | 15 +++++++++++++--
 lib/list_debug.c                     | 11 +++++------
 3 files changed, 21 insertions(+), 11 deletions(-)

diff --git a/arch/arm64/kvm/hyp/nvhe/list_debug.c b/arch/arm64/kvm/hyp/nvhe/list_debug.c
index d68abd7ea124..589284496ac5 100644
--- a/arch/arm64/kvm/hyp/nvhe/list_debug.c
+++ b/arch/arm64/kvm/hyp/nvhe/list_debug.c
@@ -26,8 +26,8 @@ static inline __must_check bool nvhe_check_data_corruption(bool v)
 
 /* The predicates checked here are taken from lib/list_debug.c. */
 
-bool __list_add_valid(struct list_head *new, struct list_head *prev,
-		      struct list_head *next)
+bool ___list_add_valid(struct list_head *new, struct list_head *prev,
+		       struct list_head *next)
 {
 	if (NVHE_CHECK_DATA_CORRUPTION(next->prev != prev) ||
 	    NVHE_CHECK_DATA_CORRUPTION(prev->next != next) ||
@@ -37,7 +37,7 @@ bool __list_add_valid(struct list_head *new, struct list_head *prev,
 	return true;
 }
 
-bool __list_del_entry_valid(struct list_head *entry)
+bool ___list_del_entry_valid(struct list_head *entry)
 {
 	struct list_head *prev, *next;
 
diff --git a/include/linux/list.h b/include/linux/list.h
index f10344dbad4d..e0b2cf904409 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -39,10 +39,21 @@ static inline void INIT_LIST_HEAD(struct list_head *list)
 }
 
 #ifdef CONFIG_DEBUG_LIST
-extern bool __list_add_valid(struct list_head *new,
+extern bool ___list_add_valid(struct list_head *new,
 			      struct list_head *prev,
 			      struct list_head *next);
-extern bool __list_del_entry_valid(struct list_head *entry);
+static __always_inline bool __list_add_valid(struct list_head *new,
+					     struct list_head *prev,
+					     struct list_head *next)
+{
+	return ___list_add_valid(new, prev, next);
+}
+
+extern bool ___list_del_entry_valid(struct list_head *entry);
+static __always_inline bool __list_del_entry_valid(struct list_head *entry)
+{
+	return ___list_del_entry_valid(entry);
+}
 #else
 static inline bool __list_add_valid(struct list_head *new,
 				struct list_head *prev,
diff --git a/lib/list_debug.c b/lib/list_debug.c
index d98d43f80958..fd69009cc696 100644
--- a/lib/list_debug.c
+++ b/lib/list_debug.c
@@ -17,8 +17,8 @@
  * attempt).
  */
 
-bool __list_add_valid(struct list_head *new, struct list_head *prev,
-		      struct list_head *next)
+bool ___list_add_valid(struct list_head *new, struct list_head *prev,
+		       struct list_head *next)
 {
 	if (CHECK_DATA_CORRUPTION(prev == NULL,
 			"list_add corruption. prev is NULL.\n") ||
@@ -37,9 +37,9 @@ bool __list_add_valid(struct list_head *new, struct list_head *prev,
 
 	return true;
 }
-EXPORT_SYMBOL(__list_add_valid);
+EXPORT_SYMBOL(___list_add_valid);
 
-bool __list_del_entry_valid(struct list_head *entry)
+bool ___list_del_entry_valid(struct list_head *entry)
 {
 	struct list_head *prev, *next;
 
@@ -65,6 +65,5 @@ bool __list_del_entry_valid(struct list_head *entry)
 		return false;
 
 	return true;
-
 }
-EXPORT_SYMBOL(__list_del_entry_valid);
+EXPORT_SYMBOL(___list_del_entry_valid);
-- 
2.41.0.640.ga95def55d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804090621.400-2-elver%40google.com.
