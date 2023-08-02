Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNPCVGTAMGQE54N573A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id CDA8F76D109
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Aug 2023 17:07:35 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1bc0972b0fesf562895ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Aug 2023 08:07:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690988854; cv=pass;
        d=google.com; s=arc-20160816;
        b=pVy9vkeKboEccLGQgOOB8Gc7lA5SUfWP14MQ1UKXDzYGGoYuHS+d7rG4AXnXo4Kynt
         AKS9b4FrSRavm3wzIiookrIV9oscWdzK1ntHdOWRZ6wyqve3H5FxPZ7AyJ6ojkZm7s/o
         earPZnAfZhHQuTZBVoA6iaxpyMkaWqT2mTz+ytv2zvrghBlc36VSriQHiIbN/c7dBu8V
         jqYP/WiulMHfssu1ZdEtec4zvXjrHaKI/Mzuiju8xEAzlkCTOY1E/vjZgjV692IqlHd2
         q5GifkaqZgyYYuJlr6xJ2UE0ibbJ0nUiNyc2iOWG84wQFHbElrJCne9Fh3NgYJLDBpGk
         KMRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gKDZbeDMUrG/GLo27eq92oEMzsOK24QCxTn0bsR4z68=;
        fh=uAQSQbJ2uPOh1U3Yr1sxvPhVEW4wvg6y/uAlAwy6j5c=;
        b=kFA3R0j//JveLHIktephizdxKMQnlB3uc0KSDFimOTSs9Dxt8wA7+1UimqoVUlEY8A
         UriiJwE7AR+aTpv5mDFjSS1x0V7sp9tEmFqgBESVEj/6X9GbrtaNLEjLxA1mhBbtMddx
         wt2KoirmVlb0ny1z2wKtbMLR4RZvpbQTQI3Hblz9h3Kal64MSpce4JNbIEvf8zh4RArh
         gvDMt9ZW0OfGiznB2Wdnd3tP2klE8Av7vIUBmWaoyP4LgmBIcJ4l582lddpcWsO7rYiD
         urWP2fm1fsiEELKpUGoZmK7isvRL705N4k4UF3QFnO5wDjr7/8zLZPDfgn8ix1zkX/it
         thQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=GYpXHhyb;
       spf=pass (google.com: domain of 3m3hkzaukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3M3HKZAUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690988854; x=1691593654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gKDZbeDMUrG/GLo27eq92oEMzsOK24QCxTn0bsR4z68=;
        b=MjPD0XSsu0v8nI6NnAt2/QVyds/WPI14//fnoHn2z+rQV7dZwropC9k3eVjZuH52r6
         IVVe79MyxFbdvnZ5bSFl+cdj18E+H9KlqGAIswc3rh5vawD12XVL6jrve8VJQAPYYXwz
         47WGRRNNv24g1upSF99VkUXdmNot+d6dxFlOL7Cs/nCVO+chk0VbxDi5aN7Bb59Sms4M
         6L0X3l7SMOKlzS2VfmyXmX851nUhiwUW4BOvIDrKMsnUVDpBS2PSxd1/a1gbDuSyxn20
         AOmp/jGq6hVqqSHllCf5+rz+Q5sLJWZlAfZPEAN7PozS6wOvbhfwLWZOb5e6wjDhz7UM
         BLHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690988854; x=1691593654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gKDZbeDMUrG/GLo27eq92oEMzsOK24QCxTn0bsR4z68=;
        b=a2TFvGDryTXfAVlT9id5EWoXjUzOjOTxkUmRmxivdUZAIZkIs0BUF5jlxhdExdzSGA
         s2ZKflrNvqP4TN/bL2QsgjLDji7SfgVCLUL25KQUH8RKrbQTCFFwOSS8kUPdoC9kLNu/
         IfDCEBSAzDxqk3AcPDbuKAXHttEwDxogbzZOmhzZMCRknhqgBdneLzGQafY2WLINOprc
         RpEnBxXClr/jdoRS+ry8Eb1bRC//7W/EgpD66kR6XkxAaqICKLRDpmAs9rLmD2MEDcCU
         3fBDo3E6dwrwAbvCBo2nOXJ3nugTg4lHi7hERZLTtEp4v4W8GMtqrQGZWSbqLU+LGirM
         9/aA==
X-Gm-Message-State: ABy/qLYySRn2PYg4Pw0Kl0vDwEBMbPG2gbt7q8ZQxbKWs1DzV1rnfYVx
	WpkeEMEVBtPXWerhDWSiWJE=
X-Google-Smtp-Source: APBJJlFIvF4vtzVS8B+oLmTxNmsh1XXwQH18P3vsleIOuZQPJ24YsrfEXC1Kcm+KPvZkrtJmKRWxJA==
X-Received: by 2002:a17:902:650d:b0:1b9:e245:cd69 with SMTP id b13-20020a170902650d00b001b9e245cd69mr811820plk.24.1690988854017;
        Wed, 02 Aug 2023 08:07:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6548:b0:1b8:c50d:56e4 with SMTP id
 d8-20020a170902654800b001b8c50d56e4ls3051219pln.1.-pod-prod-07-us; Wed, 02
 Aug 2023 08:07:32 -0700 (PDT)
X-Received: by 2002:a17:902:9309:b0:1b9:ebf4:5d2 with SMTP id bc9-20020a170902930900b001b9ebf405d2mr13141531plb.33.1690988852782;
        Wed, 02 Aug 2023 08:07:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690988852; cv=none;
        d=google.com; s=arc-20160816;
        b=Cs/ABrthqYC6safzgHgv7BkcpodoaOb/ydN7hZw9DjWOGHzZqjtPAz86AGhvkYeAN7
         t8ga8hP7Ai94zXgEktsP1kG1NzuvcaAzTDwPIulhVuiuFdSIVlgq18S8yWNTluXlHk5T
         1FELt1TN24yN8TZguWOM9K7Y17n29AhkGldk/GDIOIoW1ToloNxuXV1f3/+75ZT02i/L
         rqhEqeyQEaepchK2jKrmdmsEN0wlQxtH32746a0HNWcClnMSsnW020kzCnoyuUmxJe4j
         xBs5RZhuLqJbkB7D8cqf2u9glLOa0KHeXcULOJzyMBc8WNZSWOSbF2PwR99L25AxGsft
         2OgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bvGboV0t8alUYsd0cddb1UrgSKN8k9GsOS0292grtRY=;
        fh=lNGG3jUJkf8aHp9vpCSrpIUZatSpkge/xU1iDADXpuE=;
        b=fTm/dXom7HQNmpVR5DDt6+aFQto/Dt85bxOwwobRv6hogw8m/PIA9Cg4d+vRsTmQAv
         idUeYNgjd2yRIr5knovdhbvXHmqtS+rG0WBjgRVGyZuF+jA46bd7tf2ZYzOgo/xTia09
         vPsSZheA5vpKlC1bDI1gz7puwegm6N8zzzQOkb9qwjBQEcw0auD5O2kE5YyFzuE1uFy0
         iG1T3TlddntafwTwfdulIDSLhFx/UX3u6uJ2x7c4rR+Q4b67fbfH8jAmBXjwsyd03+W9
         55miZTEVlbnVOWF1oFl798YkGeBu7G+bhJF6lCLb+c5NljIKNyX1ZXLDnK3583IaCyKv
         Qr/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=GYpXHhyb;
       spf=pass (google.com: domain of 3m3hkzaukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3M3HKZAUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id kf4-20020a17090305c400b001bbcd26568asi833347plb.12.2023.08.02.08.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Aug 2023 08:07:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m3hkzaukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-d061f324d64so7122723276.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Aug 2023 08:07:32 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:5f73:1fc0:c9fd:f203])
 (user=elver job=sendgmr) by 2002:a25:ab86:0:b0:d0d:a7bc:4040 with SMTP id
 v6-20020a25ab86000000b00d0da7bc4040mr122142ybi.0.1690988851982; Wed, 02 Aug
 2023 08:07:31 -0700 (PDT)
Date: Wed,  2 Aug 2023 17:06:38 +0200
In-Reply-To: <20230802150712.3583252-1-elver@google.com>
Mime-Version: 1.0
References: <20230802150712.3583252-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.585.gd2178a4bd4-goog
Message-ID: <20230802150712.3583252-2-elver@google.com>
Subject: [PATCH 2/3] list_debug: Introduce inline wrappers for debug checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=GYpXHhyb;       spf=pass
 (google.com: domain of 3m3hkzaukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3M3HKZAUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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
2.41.0.585.gd2178a4bd4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230802150712.3583252-2-elver%40google.com.
