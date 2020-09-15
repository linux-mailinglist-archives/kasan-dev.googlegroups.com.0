Return-Path: <kasan-dev+bncBDX4HWEMTEBRB266QT5QKGQEITWTU6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D91626AF67
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:32 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id a81sf724658lfd.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204652; cv=pass;
        d=google.com; s=arc-20160816;
        b=CDQChv+hp0FA/9KBKr2FN2iEktDYlYkTSZOX27AWpGppcnc2NE6AE6OMd0dSS4XXIW
         OJ0PqbD8A3kyZaMaCECaFwL+4a6EgXemaiR0VW3tvRueEcgDzGKHfMp7bnzRI6DYWCLG
         cixUx/7WEdIyZyJUx4ExLmjxI62ow5pS3j0zIk4iL4V0bASFpN68ZSMEmg8RglwI5Ak+
         teQWCX5d1dVcjHDXCvPNCPvlmJxqySURKOPrymVr/cHCnR8tdZaygKJZ33VP6jaLNTKd
         w6ZzqF6YVKD3d3WTCsnphJiANhiCAjiCRwvakq/G6pefkW1cM1K2WkbpBTnYgFaf6/HS
         0sMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=/JlZlE2v/3HlP55g0a886KElKTohuXtWCqiAP0q9CJc=;
        b=aJXExfmCv3GrFAKvGqYQjpqANgndL87zGvQwgawDM185sAYz3MGjQIuUY+x35Ka/t/
         ZWZg29BG0IvYpnhKj3P54J4ksaAIDyRUF1nPeKpgGHHsQQaAQwQIiaeKjtorU0hnK8A2
         6Qt7dNKXzbOpqDbwe7JS83UkGu1uotf9AOoj18I5k1spPlYE27hLTbDmcgH/LwXuE57t
         3sWQMhinPIWD3a66EUKCe2qxE96VD2uTV8vHdQA7/nwvOTv0XTlkemWUoy2BYoIJpcMI
         JAOYlyXkNDPXVFLlBOQcGhWjnycHti4deYBo1fWp62mI0QKGtARnAR4q4sljoV37mJJM
         X8Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Yy3NAxKG;
       spf=pass (google.com: domain of 3ai9hxwokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ai9hXwoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/JlZlE2v/3HlP55g0a886KElKTohuXtWCqiAP0q9CJc=;
        b=Rn1b+SN/3OUvaDpLAbNCEBPa4KuUzaTuOqXxffTIDEe9F+On6pTSSPOH7a/OTghxcC
         KZRr6VppKS3lHMcBAj6N+uumw2drvbCNRs+VWzL8FlPT5JT/8LCRrMP+ZhSHMPKe7IoU
         KVX0upVYZb5mZhW3lxB4ExcXwZBB88krmRQpjB+rElJt4fQwBRI+13bf2uDhIINkvP2X
         DTVyn2SSoZxwdXQ1gLUs/YtUBaeCvRTlxUJziqoLFOez2PFLC+Yd/Dk7pd3O9RurkN/S
         h5/wG/9Cp/64yTc9BIbdXgj1BVuAYNMr7/N52nlG3rHHlZ0RDGCbdwqD7w6BP4uRR+dM
         F+Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/JlZlE2v/3HlP55g0a886KElKTohuXtWCqiAP0q9CJc=;
        b=A86981Iys7Ka2WnWlQXdeNtDwEppfkbq6FP2IuQIY3NvOrV+U2wk3rnDaSiChYBm0H
         w+f5s0zYGxM+gNFlFKr7B8GD9i+SG3ckdLuH6geX7UJ3+s5tKxWStZcXNkKce1nyv3d6
         Me/WGSsfw+WHsoJ4IsYgKVscUk0iIZYiwozGJR0KZGG3sqOdUNO2TlssCE9kYPytMjZX
         WkYeJCZ6eyVbYDWUekUXf/uq7WaRrlslCavySaLVf263LLF384eyJFuJ3VRVNBJTCvtj
         Rl+/y2YnzzHD/T12dVqZybMd0yGomAbkAzuvfADvnRktR8Yhk7rUysNua2Vxkdmj8BrB
         MPpw==
X-Gm-Message-State: AOAM532GtHRLUJn3/YcXnVzce6VuUNUKLu75EgNTyomcT6KKSMcbiMv3
	EQAmYM2Oh+iqJ87MvpOBVIE=
X-Google-Smtp-Source: ABdhPJxjA5vkkSZ66V2VwAenCPNBSrbTZ68FkNYIx7hHwKtYsu8ptvVFdGI4ZL7fuXtix8bZhjgZ9Q==
X-Received: by 2002:a05:6512:214c:: with SMTP id s12mr6933275lfr.578.1600204652188;
        Tue, 15 Sep 2020 14:17:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls17268lff.0.gmail; Tue, 15 Sep
 2020 14:17:31 -0700 (PDT)
X-Received: by 2002:ac2:43ce:: with SMTP id u14mr6301101lfl.508.1600204651338;
        Tue, 15 Sep 2020 14:17:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204651; cv=none;
        d=google.com; s=arc-20160816;
        b=i1ZrfuMhdl4EPyCp+QKiZchcrFfwgW0FTnIfHR/6hDr7+/oBWLYv478qmU+ecbJZ9f
         nwnH6IZ7BVv45WXVZFdf0jcR50Q+4ZyAYyVEzNRQmY+WjeUm8FZefL26FOrexgjYoeQL
         Vh9WV2QcgFvd4X2xcoYojqClHiFw2yP8Qeo5QaBwtGCEMuxixPynAEIHtIWiBumeG0f5
         ehT7J40GiRZdl70aD4Ebh2gR8WR3wKA5i2N0jcrd21Ysc1g5V/icB8eb1pBRrfazRi/B
         /qsHqZFr/XlzYXT/NXTd0wFU6z3uQ7cnO2XH+/TVZIqiuq6FcsaqGzLteGIGV1ZHekik
         DoZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gQNZi1xbbNqueATb+Ofst812z+wTX6Uhy5JHBLW29HQ=;
        b=d+MAtTmxj9kHD5mKjluFRdbMpXZxIyC3/NqGLCQErwcOndVsofTagfqP/92OGxbme1
         xZDboQWHjlsG+1SQHbDDGhFGaILwgS3gDecjcUZNEkhkbPg/ITPTSS542ZRes/oR+ZjG
         8gFYwDbLmf8fTE8dwVD8RxY/CWS4xflT+n+5JivBulZYxlsebmUhcsZ+Pm9wQ0I9oEzI
         63eC/gLVJosq1T1c9J61YXLFLu5JxWcp4Sk4lpRMqOznIDg1hKLgxfBiuViCqP7lNXox
         75jKl0iutDXGhevVS3lixCySx1VgjDDNbiXLQxoBwTMQGYXnL05shaKVw4Y6XW0yaThY
         SM6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Yy3NAxKG;
       spf=pass (google.com: domain of 3ai9hxwokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ai9hXwoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d1si296106lfa.11.2020.09.15.14.17.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ai9hxwokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l15so1704876wro.10
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:31 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:dd44:: with SMTP id
 u4mr22386734wrm.22.1600204650809; Tue, 15 Sep 2020 14:17:30 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:10 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <9ecc27d43a01ca32bcacf44b393a9a100e0dfdb2.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 28/37] arm64: kasan: Enable TBI EL1
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Yy3NAxKG;       spf=pass
 (google.com: domain of 3ai9hxwokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ai9hXwoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) that is
built on top of the Top Byte Ignore (TBI) feature.

Enable in-kernel TBI when CONFIG_KASAN_HW_TAGS is turned on by enabling
the TCR_TBI1 bit in proc.S.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I91944903bc9c9c9044f0d50e74bcd6b9971d21ff
---
 arch/arm64/mm/proc.S | 13 ++++++++++---
 1 file changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 5ba7ac5e9c77..1687447dee7a 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -40,9 +40,13 @@
 #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
 
 #ifdef CONFIG_KASAN_SW_TAGS
-#define TCR_KASAN_FLAGS TCR_TBI1
+#define TCR_KASAN_SW_FLAGS TCR_TBI1
 #else
-#define TCR_KASAN_FLAGS 0
+#define TCR_KASAN_SW_FLAGS 0
+#endif
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define TCR_KASAN_HW_FLAGS TCR_TBI1
 #endif
 
 /*
@@ -462,7 +466,7 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
 			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
-			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
+			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
 	tcr_clear_errata_bits x10, x9, x5
 
 #ifdef CONFIG_ARM64_VA_BITS_52
@@ -495,6 +499,9 @@ SYM_FUNC_START(__cpu_setup)
 	/* Update TCR_EL1 if MTE is supported (ID_AA64PFR1_EL1[11:8] > 1) */
 	cbz	mte_present, 1f
 	orr	x10, x10, #SYS_TCR_EL1_TCMA1
+#ifdef CONFIG_KASAN_HW_TAGS
+	orr	x10, x10, #TCR_KASAN_HW_FLAGS
+#endif
 1:
 	.unreq	mte_present
 #endif
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9ecc27d43a01ca32bcacf44b393a9a100e0dfdb2.1600204505.git.andreyknvl%40google.com.
