Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVFN6D6QKGQEGLIIITQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 90AB22C1546
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:53 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id l8sf14989042ilf.10
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162132; cv=pass;
        d=google.com; s=arc-20160816;
        b=dv8sRsnZn7Hil8uu5A2FgoV82QrDdWVMNpHN99oJqsqffJQlKEro9qLTXc7OQO/VQS
         NVtWDxCZM33PMuDJEhYA8PnDmjNnH0Mq9dEl5JMOXu67dolLBeo4of+R92aZWl1wVx6y
         nxv6NqPvpB36TRntyC+0f+OtGaO9o3Tq8p+P2q75J7Qsa0d06+qnbbxaU+1AP9UhTR9b
         uJuydQRb/KYotDLS2A2utKQS11aIujfK5zS7tqR+K2W+XSDJlot0+XCyc9svdup0em1h
         cNdYFqDYs+1ouyiQFrwwBiUZ54Pms4oSPchtlJlmck8z4lXtx4p5yhO7PNLS4Bd5IaHY
         R2xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=GE/zIz06cvM2kiz6sd86StFon/apeXmb+CC3aak4c4o=;
        b=a0Ryq6xZJd/I88zORS05UOWZOnyAF6WnXDT2gv6hChNNRvfEpzGeDuONBtdg8Bw8bX
         H8gDoYfNPCPgby9+Q0OOjj34hSfbDr3nn0jNyyScyQ/jXXHLMtU+uxo2DsPh0wlhvTdP
         HPEqbaZ3YM4Qm41B9qjfUOh9mKt1aKd1rpLQqwPuHUqEXXoqoA/ktrmMEq0Jqub75n+0
         vZ0Vw3kGgQq0ATGEG8R5diRI0GtI7rnGen1Zt6DOoRWbxON0BAsdHvb5wt4A6lIi+QD7
         rqmtro8tDmO1sBRFfDLSl5QEx05Y34VIdORyTyXtJbTwUReMoPt98TiULGbwVzM71xj1
         +sfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=slyXwv8q;
       spf=pass (google.com: domain of 30xa8xwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=30xa8XwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GE/zIz06cvM2kiz6sd86StFon/apeXmb+CC3aak4c4o=;
        b=Q8vZKTpdqkCM2gCIBiOAK3nFbsH+pLsBg5+Cz/fdbAZPK0MG39L5tRgez3ssjPNcug
         T7M26eIYHcXp7Vn2UGcQ5kPLEf/xZ9Z4i90K9SFE3r7n95rsc0dxRF5VyhZUbNZknyQV
         wcVjoaUAGMEYPVhcXaeghmTqzpICha1SJKYTfv10iT1kO7piZWMdTuuHPAqFDSYvbbE+
         DdgYRg93FGDsDEzIbS441nUVHioIVa8TTus55Pq6cy+HzXDfE5cP7MXj0aK2joHBDKVq
         uwPlltMQgfvYs5OVmuzmAg+pIVpZMTAItAYsRBoVLZrxlZl43+z5gIgnZD2nm7uugJMN
         mjWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GE/zIz06cvM2kiz6sd86StFon/apeXmb+CC3aak4c4o=;
        b=mLBWSf6yOCr3vMz2aJY6Wz/XzzgRpvJSVFFIEcbhSiVnO5JadBwME5OvknYSrfnN9b
         7Ku3MOBiIz+FrmL46DLy7miFykhaH0CBHobXpKj3vsLYLGzORSrJTuByxR5JJDeYaiQG
         YvkuS7wXMuJF/YElxXGdekKShBw+Fs7ugpgrng4Vw6ewFRPLl7IbjjaEWq/aL/H5NWSB
         hCoBkxYfvqNnBA5xpZqRfIY0dq4nbH7aErCEmEi81t8Ef+31nBaUWJVut/SMfdIW4ARp
         i/VM0wJvGeI10StodeCt6J6Bdpy3nsSVXORXlXmsbKxau52UEuy2ask2xH5EEm5wFVcP
         xivw==
X-Gm-Message-State: AOAM533cKKclRZbSy2UEM9iPmqrufOH7ST8MiDzrQy7apAb2PEeRYaj1
	M7ANVK3K0Zq7dbZeLQqkBxQ=
X-Google-Smtp-Source: ABdhPJxrz1e60kzK/LOhJyrusInDu/BTHTaWPyQnJCYUXDgnRHp3T7CkYtrM18XZbfga2lB5lxFTBg==
X-Received: by 2002:a05:6602:5cd:: with SMTP id w13mr1176841iox.147.1606162132635;
        Mon, 23 Nov 2020 12:08:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:140f:: with SMTP id n15ls3853883ilo.4.gmail; Mon,
 23 Nov 2020 12:08:52 -0800 (PST)
X-Received: by 2002:a92:850f:: with SMTP id f15mr1403482ilh.286.1606162132268;
        Mon, 23 Nov 2020 12:08:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162132; cv=none;
        d=google.com; s=arc-20160816;
        b=eCybZF0eb/mBh7ATjZ6mQdojlGZKr67xnHuLdEHz1S5IB72hdEtTIjzzUpr7X9YvR4
         Wxd3Sz/zRk+3Azood/DeAUcEBCzBNvx0v8OI/hoKiUHSv78deK3ewFKBjYRtk5ASy9pC
         hLbd+qmR0CgrvyRQF+OlCUZpIrPwHoNH7I6H1BeiOi2PUalcYUeF7DOfAIpJr483763y
         QCOljlc9a1c4uuiv9rMZEF5moljJDCUrXKaBjPEe90l4HLVoSofobSnpPekJAKMK1Z5J
         Seg2VeLa19ERGF8WRJ5BDDdBKRdb81tiu/GWEVofEOF6d9fQQUwVxu5zPt9Llg88hGvq
         frfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=cvraDLvCJyIxw98+lt/3PDpM3Nirwfhsw5x/8diNIQE=;
        b=F1Tkpq2uWZzQR0qXXyNj3AkmsvJqupbRTeoyU8iRvgqMLSxAA7MOujbaS7sOIy9/bz
         DQX0GilXbMdITrQJQ7966sXXsOESDrIB7hbJXzpgDb8dgqHF65GfnJytCo9Mlq4wNq48
         XzUYnDF2Ih1uDf/hynJsTWOdO3sxfrICvVMbR0r61/+uKP3dUdksNITRkFWsDB1+p+dY
         l63lYMExwul7/P68/pITea2Mb4Yrv5BFSXRq0BXK4i3/t5w4pJ/eHWfmWH6/kvyXImlE
         B+j1ZxLp3sNWs7P8MwIy6321Lb0VUX0S0TFaobv62NhQ8AXqxZLQgEjR3XgaSr024FiK
         GpRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=slyXwv8q;
       spf=pass (google.com: domain of 30xa8xwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=30xa8XwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id a2si498452ild.4.2020.11.23.12.08.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 30xa8xwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id q25so15475472qkm.17
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:52 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:363:: with SMTP id
 t3mr1130705qvu.9.1606162131658; Mon, 23 Nov 2020 12:08:51 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:38 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <d1742eea2cd728d150d49b144e49b6433405c7ba.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 14/42] kasan, arm64: only init shadow for software modes
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
 header.i=@google.com header.s=20161025 header.b=slyXwv8q;       spf=pass
 (google.com: domain of 30xa8xwokcfqwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=30xa8XwoKCfQWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN won't be using shadow memory. Only initialize
it when one of the software KASAN modes are enabled.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I055e0651369b14d3e54cdaa8c48e6329b2e8952d
---
 arch/arm64/include/asm/kasan.h |  8 ++++++--
 arch/arm64/mm/kasan_init.c     | 15 ++++++++++++++-
 2 files changed, 20 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index b0dc4abc3589..f7ea70d02cab 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -13,6 +13,12 @@
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
 
 #ifdef CONFIG_KASAN
+void kasan_init(void);
+#else
+static inline void kasan_init(void) { }
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 /*
  * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
@@ -33,12 +39,10 @@
 #define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (1UL << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
 #define KASAN_SHADOW_START      _KASAN_SHADOW_START(vabits_actual)
 
-void kasan_init(void);
 void kasan_copy_shadow(pgd_t *pgdir);
 asmlinkage void kasan_early_init(void);
 
 #else
-static inline void kasan_init(void) { }
 static inline void kasan_copy_shadow(pgd_t *pgdir) { }
 #endif
 
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b24e43d20667..ffeb80d5aa8d 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -21,6 +21,8 @@
 #include <asm/sections.h>
 #include <asm/tlbflush.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
 static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
 
 /*
@@ -208,7 +210,7 @@ static void __init clear_pgds(unsigned long start,
 		set_pgd(pgd_offset_k(start), __pgd(0));
 }
 
-void __init kasan_init(void)
+static void __init kasan_init_shadow(void)
 {
 	u64 kimg_shadow_start, kimg_shadow_end;
 	u64 mod_shadow_start, mod_shadow_end;
@@ -269,6 +271,17 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+}
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
+
+static inline void __init kasan_init_shadow(void) { }
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+void __init kasan_init(void)
+{
+	kasan_init_shadow();
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d1742eea2cd728d150d49b144e49b6433405c7ba.1606161801.git.andreyknvl%40google.com.
