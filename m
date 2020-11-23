Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCVO6D6QKGQEDVN3TJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B8E32C155B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:47 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id 4sf4577477pla.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162186; cv=pass;
        d=google.com; s=arc-20160816;
        b=oslPUByrA9Tp7XuG8bZPQnFgc4hcxvXwK1MhaUKeVXQs19jPicmO+ZcWCYsrVdXrMp
         45A2PVmfHZZoz0PxefyEqJpNR32hiNRpUwq38lg2D40A8zCD2BYXNmwsz47hAdMOsCoV
         aaG0WIvf6ny4RWy7mfvVo6OGvTeJOcAhZlHuOAsSEzfprhX5mXkCalZfY4kxSg7oiNXr
         DBmAhxNwF6NsBTQZoApU9ctnbE9nHQK646bVuW+VEUnJkT3unOHZUic+kxii5mkC1+D8
         WMxATtS73zsh9luqMHlR4apeBTdWJKZzQ/89xCupVqbxfXcDL8O5AfrZgRG/MA9NSMS8
         0bVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=SAUupYq0sKOB/e2JIPJqsB22D9pyQ8UALPz6dR/w3Tc=;
        b=zolCuEytJQlzdO9jRp5DEkPx5aARL1N2KzYAoGlXfOo6ezRkJsDZM/ELEQHatk8gR5
         meRsgrTrAo6Jrann1jv+UQXJdr1TlAaGyONnxN3xvkSKKoWNjePEjgk4rS4HGGbX181N
         RatzhO+b76C4SmSNqm6UXCMgUTn+hRKUjwtoBpWNP/T43Sa5dptEm1M+q9rMNdjaR1J9
         97TuuNUtRcUrZZ8AR5dRw2s9POnZeIxkixzSgvJC3slOt72SXf3xY6uWejnuKTgS6jAu
         5+BxjO4QA/uc1ergdGm+OdADR5W1CPRSWtQ+vmE3avFWrwRWZDa7Jeef168wHojzarxS
         yuyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uWayMXuK;
       spf=pass (google.com: domain of 3cre8xwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3CRe8XwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SAUupYq0sKOB/e2JIPJqsB22D9pyQ8UALPz6dR/w3Tc=;
        b=a1+AHuOcMkzNTQDdiN3TavMwrddQVTqh3aNfR8iV92cUJR7M7NcTO77+YS82u4SxKl
         /adkVwgjH9qceSsB432IfvHajstt2yCflekz3zPE7S4UkvvaboJdQOvf/6x1LEzaVraV
         1HwrLOMsUds4cd8VkOmCdahpTFfqFcBu+UAbu5lfLrxy9pOhYEVPZ6Szkvr68GE21UNn
         oexTRyND2uipah7kBeXvmGgMcWIgwpaIWOb1v/8fAp7FNEofgga25PcahoY4bATVyiQt
         5JnoYjxvt6+73TcPqxUDuMnYT5jk5QVmcscsKbDxMx3mkOBF0w0i1E1rJZ1RonLM4jo4
         93vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SAUupYq0sKOB/e2JIPJqsB22D9pyQ8UALPz6dR/w3Tc=;
        b=rU2qznIrBlBr0wN3c9boc0OG5+nTcVonjuP7MYsCruKsnrsr3BlNB0+xKndO8cDIqD
         uQYUchVq4AXJMZtvMmkgAK8epYR0rUDK1cw8g3iYct8/o+AV5zW/AvbZd8p9YKDuhHRD
         kRS+3PmX51xCfR6Z5ycmjZHUMNrdv31ZNMZH2JEVleDfIYAAhnbGoeGItHqASWkHryDn
         77XUTlzsxTqIHiOsBCLtZZSQsihq2rezHBaD8CjhO1beuymook+pPtlZeLdItJnsv+5y
         8x3jO7j+N310yoyHGuzQs8Lg+bIPE2z8i/MnQr+3/YQxcYiGTnJkcu07UL+g7b0WFkt0
         vwWw==
X-Gm-Message-State: AOAM533V6UF15DMwbaUzEpOFer8sdD/LuxxFDEXgX+82se42LyMkKHCF
	danF792Wa6zNS4a8LZfi1Pw=
X-Google-Smtp-Source: ABdhPJzEarbJLdwLUNvKkeJlabZgxTHnHitHjtdxNq4x7+r9DJSupa5k69cMyZCw5JrjB0ob8rpyWg==
X-Received: by 2002:a63:504f:: with SMTP id q15mr952716pgl.119.1606162186416;
        Mon, 23 Nov 2020 12:09:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:989e:: with SMTP id r30ls5444532pfl.2.gmail; Mon, 23 Nov
 2020 12:09:46 -0800 (PST)
X-Received: by 2002:a63:4d07:: with SMTP id a7mr979542pgb.274.1606162185894;
        Mon, 23 Nov 2020 12:09:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162185; cv=none;
        d=google.com; s=arc-20160816;
        b=0m/HQvLHnnHi3jC4ne1LqRo8epziFus6gPKBSFcG9vOXm5FgYCzH7J+vh4VGYdq2sD
         xZK1Sby/yd8h+wRrGGhOcvWmnSmGIcUJ69kDYErkRIsflZ1oG43nmsNJdAnF1y8xYdHK
         0vkvpEfSZYUwaJKDz6b6csLJY0Bd+d91f9Zq0C4f8h3Ro1MS9SY7kfoy1/Rkr92HB+NC
         U8R1GuVca0alsPGjkQQlKdjFsFMed63PjxMxNiuv1dRqJO4qUeVJ+W2/tBfEdRP0zJeL
         yyjl8cavxKAd2TPd1T8MylZ2ymUoE00Fcv0MskNxZCNL6WQA0I+pw4ByC5A20kjmOvwS
         kmNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=xwstu1pRxVcUMTNe9jDo3bBYpkf7yAJWDfxoqoLQsg4=;
        b=i05/GZfw+KN8sRbxm8L201qXpe/I3xMSOUioKmBOgmAdXT/e9R5glhpYa03XAcN07+
         pwHBo4jaTTqGxGlccl7b8qiHLeMhvhzzlZF7KITLYtecUm30CSGcX39XpiijArqsgqGH
         mPNYBIylDc/DinqLdGitlDnVsukfVDV6RPX4th+wU90Z9LL05+fdnVwpOMCmJx2/H30r
         r6pg/4PnnpenoED0XbK4rklXfZQqzTSN4Um6Ff2NsVpicF+G2FRA+TgA/zS92StDhn9L
         kNtS1fZXewxQ9d+KZJIcf2kZ/tLFbyCdH+o2BfQ5R6psfzmJ7GMT/0/RTlaPpTz3Av7E
         RaMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uWayMXuK;
       spf=pass (google.com: domain of 3cre8xwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3CRe8XwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id d12si691049pll.0.2020.11.23.12.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cre8xwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id p129so122143qkc.20
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5621:: with SMTP id
 cb1mr1321441qvb.12.1606162185203; Mon, 23 Nov 2020 12:09:45 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:57 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <fc9e5bb71201c03131a2fc00a74125723568dda9.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 33/42] arm64: kasan: Add arch layer for memory tagging helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uWayMXuK;       spf=pass
 (google.com: domain of 3cre8xwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3CRe8XwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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

This patch add a set of arch_*() memory tagging helpers currently only
defined for arm64 when hardware tag-based KASAN is enabled. These helpers
will be used by KASAN runtime to implement the hardware tag-based mode.

The arch-level indirection level is introduced to simplify adding hardware
tag-based KASAN support for other architectures in the future by defining
the appropriate arch_*() macros.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
---
 arch/arm64/include/asm/memory.h |  9 +++++++++
 mm/kasan/kasan.h                | 26 ++++++++++++++++++++++++++
 2 files changed, 35 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 556cb2d62b5b..3bc08e6cf82e 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -230,6 +230,15 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 	return (const void *)(__addr | __tag_shifted(tag));
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_init_tags(max_tag)			mte_init_tags(max_tag)
+#define arch_get_random_tag()			mte_get_random_tag()
+#define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
+#define arch_set_mem_tag_range(addr, size, tag)	\
+			mte_set_mem_tag_range((addr), (size), (tag))
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Physical vs virtual RAM address space conversion.  These are
  * private definitions which should NOT be used outside memory.h
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3b349a6e799d..bc4f28156157 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -243,6 +243,32 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+#ifndef arch_enable_tagging
+#define arch_enable_tagging()
+#endif
+#ifndef arch_init_tags
+#define arch_init_tags(max_tag)
+#endif
+#ifndef arch_get_random_tag
+#define arch_get_random_tag()	(0xFF)
+#endif
+#ifndef arch_get_mem_tag
+#define arch_get_mem_tag(addr)	(0xFF)
+#endif
+#ifndef arch_set_mem_tag_range
+#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
+#endif
+
+#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_init_tags(max_tag)			arch_init_tags(max_tag)
+#define hw_get_random_tag()			arch_get_random_tag()
+#define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
+#define hw_set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fc9e5bb71201c03131a2fc00a74125723568dda9.1606161801.git.andreyknvl%40google.com.
