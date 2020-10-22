Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5MNY36AKGQEZJXGT7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 56430295FB3
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:50 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id v145sf747932oie.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372789; cv=pass;
        d=google.com; s=arc-20160816;
        b=WLQIChwtOI3QVQPt3UkGO09Ec2KpR24r/z84gh8xjN/oH8xlYAVW1ZUt4N69hAjwzu
         LetkCelULGdrtjXTSy9ZG5RpEgsC0efUvGbMEzziRjNU7cUE+y7fbiintsfbSbBbUxyT
         OAjOA3NlfdPb06WpbrOMnGm1E/iqs31MQMxdtdg32l1qXoUnm4blzsSDku8C5q4ynTFc
         eN9xbq82PlCBCH69CW9k2HkgEFu9tF4Y7/crlFQ6ftfRaN5TuaYhD9A/cvr0uipln3fn
         7GXhaoraI54L5M94rMUJa+2uNTuelQt1VDeCAINyoWzetJCCk8W1FFbFzeOOJs/uh2g3
         52VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=r8HGi8B7gEXxgfAWoYPO4GPqpTSqXQFxncL3m2q6pb0=;
        b=gxw63Y+bCc2JNwicvWOL0czot7Wi7aA2TflLWY661QijUJudUtMG84Cog/ukhvvzo5
         bEVWy69kG8vEO+eeIyb3cjuTb/RT8YY4NPcGSMofq9qQ5CEJKiBcjpYqgsX/mGLTMUnU
         jm6/zSyRH8hw6rsFpBMdcLbiI3/HChSBPt8aPSLaJkyelEggvwsbm8fHks89b1TPLzD/
         zeWlE1CA1CaicHYoQOVompO3rhC7aQdpeRo687zA0cDJagUKoaswKsqbSDhcH/Grve4P
         a/rfRvjKX988ZFj1UZceNedNgJ2NEzVzxwCKBpjBCUL7P2t6oAQ90c9G4VxvZYbGsdj2
         mT9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DNq7BoOI;
       spf=pass (google.com: domain of 39iarxwokcusn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=39IaRXwoKCUsn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=r8HGi8B7gEXxgfAWoYPO4GPqpTSqXQFxncL3m2q6pb0=;
        b=VEetI5Zks9elZ2MC/QNQCg42TKrQrSi9sbmNL94+2kNQzVulpnGOD7eeqcyoXhmPn7
         6YV8Jfg6CLwqVfO7AQNXzRPCYy4ONjnD3k3BhuvlmY0tB0mQZ3j/trDwDCwsn0BCR9dr
         /ySa74p7I3S0iE05/lsGPFF1fMYmfKJ3yz1bHlr6MFbAOwmsX9eBjX1i8/M0/jdmFz6k
         qKlUAFWIjzpNEJyKa+vG+N17GRckRO3obqpLe0YxwN9PzezMI3KTBElzuerr3pLUkC0V
         3SqBOf4Fe/BK74T6Y5+He0WlrQzS5F3AK2ijbzG7DphLcffcKtIhIDOHO2wiEbqkHZo2
         wLWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r8HGi8B7gEXxgfAWoYPO4GPqpTSqXQFxncL3m2q6pb0=;
        b=rfDz9MECIA58fFyCDtglJh80f7pggD9wuEkZ6RmsqfEq0HZDPz3710s2OAhXUvROvy
         k998DmVkbbeCL7Yr3lhq72+b2PucF81ck2HgoY36fYZAxXmn/9Ek+ot2WW9GOsUvvz7y
         MUQ1PIG98yA13H6IBenjcND6gqje9u+sPsq/liRoImoFt0pHGewCjbae20c1TGCRF8TA
         89JpnxPNjlDK63CyQg/4+5ajLkm2/Xh/uYWTrmcExfzwmccbfGyfRKVHBW04yWBswruN
         A10pi/9svctVgU29/+MZp5SP5N+tetU7pWL4GnIfKXTZNrIZGluLb46igG9sVkNAkZ8F
         xisg==
X-Gm-Message-State: AOAM531CnGNvj48m9xy8NulzOqh754xlxAPZ1dVy/HXwqu+VBprMpo8o
	GxgGpaFUMWAVU8VghwOaLXI=
X-Google-Smtp-Source: ABdhPJyxI3cPucO0WTqtsR85r7kDxX5H4neVeCNwvPaIichfrUBzh2xjR1WRT/YGQFgCIsRym1GKJQ==
X-Received: by 2002:a9d:6e17:: with SMTP id e23mr1707376otr.354.1603372789312;
        Thu, 22 Oct 2020 06:19:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:310b:: with SMTP id b11ls440904ots.10.gmail; Thu,
 22 Oct 2020 06:19:49 -0700 (PDT)
X-Received: by 2002:a9d:4047:: with SMTP id o7mr1988771oti.49.1603372788945;
        Thu, 22 Oct 2020 06:19:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372788; cv=none;
        d=google.com; s=arc-20160816;
        b=R7VTJ2E/iNQ/D1iBeCGZk2KF8r8VpMEb7YLDAvhcuhzQx2VGN8hKzb7GjMDZH/TZDy
         kcuaqYyAvB8HPISK5kinqiY3bPsBr6YwrvEQVPDHmY18wz34aXmcFuZlxH1a90Nz3/fj
         f54X7r7A1RYZIfxbHCbu3ChfmXBxsRFcyjxoIC6XODD2NZiHAza8qPCgQe702XGUdTQx
         onuGxfDA92X6AFS3BC/upktlRaOnsm29rOcsEnBH0XqdV8jrIP1UNyNVnvaVoI5IIdaG
         ma+l6fII7KH47LYzDss150I/CntoPQvRzQfY3sCyfgJFeH8Ia88nT/qUoLmlg8M0eGXo
         TlgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ttDbGg8ckV2PZque6BU+M0wdmEgRXMhDQET60HhqsRw=;
        b=N6uIvce9gqU4Q8c7tZ5O0D0mLWD5AzHah9U0YPpsPkJ54QAaHP5zHKiKpplGcnJK37
         B2qMvl8aVR7FS7xcTUTYc5I+miQLoSaEtaG4FNUzhGwUYHzOzpdCvxAi3QJ3ft9+Wd+5
         HU7lVL7egc9b63Pch6GKC9kgiSs3Ac9f1EUOsd/xEENeEhPGghzXepmkYexvABdaSwpQ
         hLG4ujrZhxZcV+8HG2Uc65HDkYTosVym9fTRZAM0fwrjRniI/b/nTVYWl99LIqj38G+F
         RtPCGzTvvZYamlHqoWCScU0zIMj+RMvpGI7kzQp1F2rVHGILuAkYPB0D8MjWKXWBmxH6
         HV5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DNq7BoOI;
       spf=pass (google.com: domain of 39iarxwokcusn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=39IaRXwoKCUsn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id b15si108061otj.3.2020.10.22.06.19.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39iarxwokcusn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id t13so1000918qvm.14
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:48 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4d46:: with SMTP id
 m6mr2314403qvm.60.1603372788362; Thu, 22 Oct 2020 06:19:48 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:02 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <56b19be34ee958103481bdfc501978556a168b42.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 10/21] kasan: inline random_tag for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DNq7BoOI;       spf=pass
 (google.com: domain of 39iarxwokcusn0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=39IaRXwoKCUsn0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Using random_tag() currently results in a function call. Move its
definition to mm/kasan/kasan.h and turn it into a static inline function
for hardware tag-based mode to avoid uneeded function call.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
---
 mm/kasan/hw_tags.c |  5 -----
 mm/kasan/kasan.h   | 37 ++++++++++++++++++++-----------------
 2 files changed, 20 insertions(+), 22 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index c3a0e83b5e7a..4c24bfcfeff9 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -36,11 +36,6 @@ void kasan_unpoison_memory(const void *address, size_t size)
 			  round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
-u8 random_tag(void)
-{
-	return get_random_tag();
-}
-
 bool check_invalid_free(void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 0ccbb3c4c519..94ba15c2f860 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -188,6 +188,12 @@ static inline bool addr_has_metadata(const void *addr)
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+void print_tags(u8 addr_tag, const void *addr);
+#else
+static inline void print_tags(u8 addr_tag, const void *addr) { }
+#endif
+
 bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
@@ -223,23 +229,6 @@ static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
 
-#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
-
-void print_tags(u8 addr_tag, const void *addr);
-
-u8 random_tag(void);
-
-#else
-
-static inline void print_tags(u8 addr_tag, const void *addr) { }
-
-static inline u8 random_tag(void)
-{
-	return 0;
-}
-
-#endif
-
 #ifndef arch_kasan_set_tag
 static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 {
@@ -273,6 +262,20 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define get_mem_tag(addr)			arch_get_mem_tag(addr)
 #define set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
 
+#ifdef CONFIG_KASAN_SW_TAGS
+u8 random_tag(void);
+#elif defined(CONFIG_KASAN_HW_TAGS)
+static inline u8 random_tag(void)
+{
+	return get_random_tag();
+}
+#else
+static inline u8 random_tag(void)
+{
+	return 0;
+}
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56b19be34ee958103481bdfc501978556a168b42.1603372719.git.andreyknvl%40google.com.
