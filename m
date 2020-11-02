Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFO4QD6QKGQEQJ4SSWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AF252A2EF7
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:38 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id r12sf10681904iln.3
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333077; cv=pass;
        d=google.com; s=arc-20160816;
        b=wMBAJD04ea6KBqaa7w31d5kOK7leYNWJDLWqZ1Hhrz6o+jLLZAvzr0e/qDGKBZWzHV
         h89VZAVNpS+w+LR48lKskB5NT0igsjkcy6ozqzU+MaZlsvEE2WCpXJ7NEGJf27mLFtbF
         STu4pB7+1zwMNUlLwD5SblUbZkM9GvZw1/2hRRLfnaXN/Vlp7ofQCa/VGRGBAjdxYZwk
         Et2ap784y9DNvtfR0UvH2awpaJQVAni08bHdGsJlydd9IVwnUlQThq1kPxcaBLznsIn/
         bVA92x/NPapSmk/Y5fHx05tYBsFvyxUp8PvkGPtWKQz50or6Vv84CECzFmPhmkQZAgfM
         Xqjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1D6UOQ2+yyNrNDRSV/2glCVHsEIWIZoYYbNIG2aQivY=;
        b=NvuKpOh2aicTm2BXALQlyNdZ8wocjqV6BFP2A4N+sXah2f6PC5gyFEvtdWXUmeH/2P
         C6F1bfW3UFPPabAsm8CCyUKknrwy7wC4aWiZKvKTUlIDAGYb8xCxfpl/pCMSP/+pO2VZ
         OmbEiunMLFktcNiOhTI0oIOeWhyXpQChvKVAOReNiJYvs2t9avH9WTI9uWuSLuNam6mg
         UfBOQ5Lu15nuYV5579Xkue41b8RJTf7/5bZD/E+b5m15dNOnr2tevWBvbCodUZpkZzPC
         dfi3E+XJaKcJE6q+viuwT1UENTduIZwvrUM+QSM8JSlsuc3/Gbkx4T6dnewERgj/lPUj
         XENQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eTcXtcdf;
       spf=pass (google.com: domain of 3fc6gxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3FC6gXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1D6UOQ2+yyNrNDRSV/2glCVHsEIWIZoYYbNIG2aQivY=;
        b=Pk9CQi0vHxSTrsshmYywqC07Aalm4JzNFZB+2avsIND3vTHZSwIZG0S55hLsNRAb4R
         dU3jv3L9/lVl1TMV1zUJY9HAlQoiQ1TB3B00eSJFzSBm66PkA9TlqhIUaDkLptEDDe8d
         OHEIo7kEVywaC6ewbFQAtGnFA1rO6GYVIRI4ZMFOYIXIC1VDqnwAf46dS4LkcXNkR/A0
         weyOW/u5gXXrXG9Z+xU1339kR9be8gM+sOWgGBUy5T3tZSXGYW3lGv03xjcSTX1JKFCF
         vrQmx1mRsN9mlo3SAxZM7tsIkYMFOAHsTTRg4ldSmKJF6OaKncJzRryU94XQ8RAOqJSu
         Lrmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1D6UOQ2+yyNrNDRSV/2glCVHsEIWIZoYYbNIG2aQivY=;
        b=Lzh80ekAUgFW/QU2p5qQmvqO4o7dS7hUsG+ks/BzQTZg0gh8KzFG1WrxqdmFZsH+RN
         fzgBnF/nIOpO4HYNkMhyhEhHfgYb/OgQL2M67ihQJEhQLMj+M7gKKVxDfsY3aXmw/C4F
         0PXhvjk86FyBwPk6q7CfLL0JDYF7Cs6O3kDjuz231aXTpsDMgoMwQrbWjl6zzDOB/Y1j
         afIBMMbhl5CIT6rGcd70Q/9xX2JwYH6gYQWUnDxuZf7sUyQ/B4zCp/E5QyfKZ5VmJprv
         2m8bSK4arrsmCZlRigw2Vbz6L/E7fZTv6zCzjdmT322LfNyzaIlZ34aKz3xzym2YNmFA
         KGaQ==
X-Gm-Message-State: AOAM533FTYTvITK2LNWP7hbqWmTb0ggqOwYXLJiW69Gw9FEGlhoou8Yu
	VY8lZTO3N2WqLNo3w/pRx/k=
X-Google-Smtp-Source: ABdhPJz+JxIZln+EEHBnClx+CQSqlt6Vv4cDtgT9nqX/ePtY/CE6zy4SskLLe1JueL2NWBAi3q4dsA==
X-Received: by 2002:a92:9641:: with SMTP id g62mr12018726ilh.166.1604333077487;
        Mon, 02 Nov 2020 08:04:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8154:: with SMTP id f20ls2002296ioo.11.gmail; Mon, 02
 Nov 2020 08:04:37 -0800 (PST)
X-Received: by 2002:a05:6602:2d49:: with SMTP id d9mr950828iow.39.1604333077115;
        Mon, 02 Nov 2020 08:04:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333077; cv=none;
        d=google.com; s=arc-20160816;
        b=qpV3eFwFf00/GaL1hqKV2jcDk1CVdWCVEU/r2IDaPtcHSsvLjGBKculNEnsWcIJ6+5
         6pZJ9v7zreFpRjrIoGUtTwWu0Afc1V/qPcQ/LL42tk/YLyu6xnYbKW2vj1vUrZdnP7eX
         /7YcHOTsiZZliVd23v4/dW3E+338do6cnhp+7UqQlerZG4CAuxEoWIpVgxLW2fMiesXh
         UpiUKa+RrLm5y3WmjfZNUQE43Cad210rE+pnKRtEJENIcH+w9ZP12RSFcbSJOj67iS2j
         Ns4ZMSq2b1GmcJyWiC9xU/aA3cBJc0Ki+yYlwpJuFVP1X5EvJ+1iH4MA4DcXMNVJERRm
         BOJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1lgjgRBViJ2FbMeVeB4B/ij4auA2e+RgHcIDFXlMEDw=;
        b=aQ9VhTf8L5WykRT/+wo5h9AhrGlF6v+h9TouE3qvgUJPN1Z5H+HnkAA1Fe01jAXtIG
         FjC5VRjo9DiYVHu5+pDxljv2QRvjvh7U2+aMfVjr8xkigFBI4b4Zp7GLfvaDgrulgmq4
         LBqGhwP+EXMqh919NBreC4jxNy1crksx17y9kMG/B7DNldHhxlQGX/XXc8LSb5mx31ze
         Pb5buM3Q95KTLj0uUXbHpnFrUERTTRQXv+OG+Gg7P2Vo/qm6g3V6+iP71cmJkaks82ht
         Qs+X8Vz6l7FLe/YJSqPJVg1MpB1+grAYc8FqOfWWFRQYbagkjywMn/1uu7fvSSG2AdbD
         Z+Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eTcXtcdf;
       spf=pass (google.com: domain of 3fc6gxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3FC6gXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id f6si49244iob.0.2020.11.02.08.04.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fc6gxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id a1so8501761qvj.3
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:37 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:162f:: with SMTP id
 e15mr23073972qvw.32.1604333076511; Mon, 02 Nov 2020 08:04:36 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:44 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <0fa21264ea32a5820bc6ba2ea2049ccd513cd016.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 04/41] arm64: kasan: Add arch layer for memory tagging helpers
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
 header.i=@google.com header.s=20161025 header.b=eTcXtcdf;       spf=pass
 (google.com: domain of 3fc6gxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3FC6gXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/include/asm/memory.h |  8 ++++++++
 mm/kasan/kasan.h                | 22 ++++++++++++++++++++++
 2 files changed, 30 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index cd61239bae8c..580d6ef17079 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -230,6 +230,14 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 	return (const void *)(__addr | __tag_shifted(tag));
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
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
index ac499456740f..a4db457a9023 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -224,6 +224,28 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0fa21264ea32a5820bc6ba2ea2049ccd513cd016.1604333009.git.andreyknvl%40google.com.
