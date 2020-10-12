Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZEASP6AKGQE2LCNGDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A0B228C2F7
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:26 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id w78sf12762026pfc.15
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535525; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jt5JgwOKY307NzvU+OgD0fJQPSErEi/TfUzniaehV8Q8XTVKk9waa6y7fD18PaI3bl
         QbOoyUb+pvkzgKIUg6RRaMoLManDsqvIoz0fuF/0Nyrz6cIwD9AUwVDaml8lL8QrY12Z
         kijfyA/ifzABob86jbRNIEIjKYxBtpH8pTlHWpKyfsG7FeUN5y0djWpcpspiYVcfZPw+
         AjJlNmKTlokkls0+ZMY7OOkyN2OWSKAFGPXO89NSIU/Vg00wQMn0BxurWpq+bBjG24ik
         g5WcvMYbyw7xA4hAG4+74E8T/IH7p+H8f6/hlY+do4rNDmaFuO4PK1O6j9Fgme4rGUp6
         XDGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=CWLi7dJnjmmXYotLb3NX7/ZniCDiJuJ2BfGK/vx3ykE=;
        b=d6haxUQ0hk1UHlF2EXNl+m6s/n/FHZx6xWsF3IQE8L67ef8RknL6FJUwxUSu3OrFdl
         FU3XOJVgRrJVrp6VPPJRmO6LjjeJSfELdJav2PdqSQK50AJCZfYj2y+KjkzTKzFKxoqb
         sE73S8oEW7Jvb/OLrCshmzjvbvr9mFyBeZjmGPVeFj3B/cmLSKnO4icIdgJYbcfcM2CY
         bnT4V03J6b1ChVWJghPiUOkJGCruLpwfmRi0geZFCwZQbjjxIhCwtBiPaaY5ZryAXU9p
         zJgKyLkfCDfmEGdxuRlK7EyxetAZHJuEtg6xQO2ZOv3hv/DRwdrPO4Q2rhw0far92LP2
         bwJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qERCmJ8f;
       spf=pass (google.com: domain of 3zmcexwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ZMCEXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CWLi7dJnjmmXYotLb3NX7/ZniCDiJuJ2BfGK/vx3ykE=;
        b=YT3/ODWbggoAhQzgglRGtaCLAnV0A3aWHZ29zlpytn4oBlZbbhrt9sL2NhozCJ9RTv
         KHkUNGOHct89EwvjTCPlMhGpVdY701+UMESmgqLFdfiqYqkSH/bNmHw2MB3N4S5bCEod
         AvkIO+j6nY8CfQmCY4HD8M3TFMtLvb56n/O4u1dIoj0lWmqJ3GTnzybIiJU8thjsRGHs
         fzfvDnw/5jJA8upXnIpN7sWCqWwN2botxvGMlRaItAX/QRJ86TwAte81c7Od0F2BL+o9
         hyOd25/7A2SKGv6eiN8pPpWXFt9xRZ+rC7AJI46zVYSXzWCJHu7FEH7eSRFvgTonwMRa
         eHfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CWLi7dJnjmmXYotLb3NX7/ZniCDiJuJ2BfGK/vx3ykE=;
        b=YiMm7Qv+FxMFFwOkpmhZaM1eaYTikh4FE0RzUyyHJE2A7qz0HNCmdvSVh/6lqtGGo8
         hID1iIqPWw0/gG9om8X1CVQ5bMb4Ln4AnTeyP6YeDyqbJ5Tk5NwD7/sKhBf84z7qMzfp
         9egZPN4ZswLePs9g8Du9a9jDl5yyWLGMrDSu80SB4enBhyuf+0PwiC31oifsjq59+8jP
         eVD1ZScxpX2ETlRZYlRCFol2b9pcaDx6PLkJiwd9T+fYb5EAioPg1DVfNgTuF9XiSWPU
         Fr1Dz9GDJStRVWosIVkVU+MU5aLgKuYUQMN5PoFlfblIiG1MEiH5AMvJQnQBNxE//ZBS
         h5Ng==
X-Gm-Message-State: AOAM532g/KGMkb9Lne1wGfc/OzGxbVx+y2Dv/ISpQE6YBwjVNySkXvNj
	QEOGMFsOc8iLSGT0iVMKStI=
X-Google-Smtp-Source: ABdhPJxJwja2ykMjEhYydUyVZDrB6G5X55OYhxE+SmGTrf7HO1CJz+wWylpB/mTlRaU/KWXJnF6K3g==
X-Received: by 2002:a17:90b:1644:: with SMTP id il4mr21235580pjb.151.1602535525049;
        Mon, 12 Oct 2020 13:45:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e416:: with SMTP id r22ls6025319pfh.4.gmail; Mon, 12 Oct
 2020 13:45:24 -0700 (PDT)
X-Received: by 2002:a62:2a94:0:b029:155:3225:6fd0 with SMTP id q142-20020a622a940000b029015532256fd0mr22954564pfq.64.1602535524516;
        Mon, 12 Oct 2020 13:45:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535524; cv=none;
        d=google.com; s=arc-20160816;
        b=lwizUz3FYzkxrGDUQRg4ONGYYDHtJ/Qb13gPxORef8lnPFptts3+XxphEZjuTDjyb8
         +tcOoKdHClCiEIsmqp6W0LoXfuO2oDKa1CFFsXqJa3e5ij2EMlac99Ql4iLRQvGhkmBu
         r6qfNEV/k47vMfYGfEJ8N31XvDIX+QDtFGxQ7QK/BdQQBaBWvs9feHX0PL/EZMjw5qXR
         0hauajhmuU4C1ApOkOSLfqIutVp/ntLXFkRoG8u/EIrA2etvcoiopja5kLGB8q7Q+PIJ
         mcYxO04Fqtxxxp6V47AmPASLxBf2rIdiEQc2sxR5paj+LiDiuBWp2nhODCF8HI7wTjic
         Rkyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Dg3fFyToLX3tIMZJi0YCB3YwOPKd2+CK9QdyHU5e4JA=;
        b=UrVEWAIsUB2lGVN02MiuLWs8oMWRbRayWWvCY5UZQ9TsTwwOksBPMJsVxTuzPv1ZAx
         EEqRIjjkJ0e8AGGJo1Mi1zB1CQwDn/u7GfDupR7cLfzMmqEctdJv7na/K9D6pUMO8hRd
         sLgTgCgn4D9CBbkyN+WtosZCE5+aZxY7swd1akBG7Sl6jL9b3slQorLHfhJy9ZzJLCJo
         sjsjJvssizOTL9FcNSTrCGpflpRk3dGkEL9JjXyrllpyBSlWd25hOEai3Yy5EbYtJA3Y
         ZHsJx390rULY+fi1xOmzOxvbslU8VpuEFAcXZpWnsenwtYm+IYTUA5uA21U7NXzy9Wsi
         JpjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qERCmJ8f;
       spf=pass (google.com: domain of 3zmcexwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ZMCEXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id t15si1427891pjq.1.2020.10.12.13.45.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zmcexwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id d124so8404218qke.4
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:24 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:48c6:: with SMTP id
 v6mr3522338qvx.11.1602535524090; Mon, 12 Oct 2020 13:45:24 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:19 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <9732d5bcae79d9ea644faea900d96d1e5a58bb5d.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 13/40] kasan: shadow declarations only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qERCmJ8f;       spf=pass
 (google.com: domain of 3zmcexwokcfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3ZMCEXwoKCfkboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Group shadow-related KASAN function declarations and only define them
for the two existing software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
---
 include/linux/kasan.h | 45 ++++++++++++++++++++++++++++---------------
 1 file changed, 29 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bd5b4965a269..1ff2717a8547 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -10,9 +10,20 @@ struct vm_struct;
 struct task_struct;
 
 #ifdef CONFIG_KASAN
+#include <asm/kasan.h>
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 #include <linux/pgtable.h>
-#include <asm/kasan.h>
+
+/* Software KASAN implementations use shadow memory. */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_INIT 0xFF
+#else
+#define KASAN_SHADOW_INIT 0
+#endif
 
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
@@ -29,6 +40,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 		+ KASAN_SHADOW_OFFSET;
 }
 
+int kasan_add_zero_shadow(void *start, unsigned long size);
+void kasan_remove_zero_shadow(void *start, unsigned long size);
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline int kasan_add_zero_shadow(void *start, unsigned long size)
+{
+	return 0;
+}
+static inline void kasan_remove_zero_shadow(void *start,
+					unsigned long size)
+{}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_KASAN
+
 /* Enable reporting bugs after kasan_disable_current() */
 extern void kasan_enable_current(void);
 
@@ -69,9 +97,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -137,14 +162,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline int kasan_add_zero_shadow(void *start, unsigned long size)
-{
-	return 0;
-}
-static inline void kasan_remove_zero_shadow(void *start,
-					unsigned long size)
-{}
-
 static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
@@ -152,8 +169,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -168,8 +183,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9732d5bcae79d9ea644faea900d96d1e5a58bb5d.1602535397.git.andreyknvl%40google.com.
