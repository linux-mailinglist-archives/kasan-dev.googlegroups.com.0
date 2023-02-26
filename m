Return-Path: <kasan-dev+bncBC5JXFXXVEGRBM5K5OPQMGQEKUTLYRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id A1C126A2D67
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Feb 2023 04:42:45 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id ip3-20020a17090b314300b00237c16adf30sf1612838pjb.5
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Feb 2023 19:42:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677382964; cv=pass;
        d=google.com; s=arc-20160816;
        b=XDxrJg2mMhPIDxgUeqGImxhUz96x/Y+KZhZg7fbIKNdhtvKDWSfQDrx9nA3h+AHso3
         4G0kT+oBWiTyQL909bmyMqfJiEWZr1qsvy0Zj27iK1+a+NOz9YoNYDTqSPr8B/+6OmH9
         gbcBQXhsndB/WT6f+z4hsYLOSxM45z76AsIAS/3RxgILbMMQmb/TKTvV8xOrkPsHdRdg
         n52N0iftuD/LCr1RMvB13gjLhIIT17mO1mPtlSN03xO8tz+Iriu9kNnOrMVduANoNurD
         BrS/db+UmWo4z6Zkr/eXjZ80m1net2VozhVLcj9e/1DIXHRFeXx9AaJmVM7i0bZSF9XZ
         QjgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0+WiSEOzm8ecFeBb+6Rf4b/3grvJE9Iwqi3ayXmOZ9E=;
        b=Fa0shNye8yrntNZPC0LcdIlS20KjPlRXq2zbEVHBVy8asXUrzuXedAkVzRw5QIuI3+
         h/9811RdDramNU30Ck2Pw+R8i1pXWr7ci+rT8CcCiXi+Mm6MDYpHb6eUpho2FeQ+Tssy
         6zoVtsS9CclzhQFa7nWt5gIdK1AWa2wsQi9xnKiDLlNINWLmuIZymPgc2sL5S7zZKPfM
         81aijN1lQmWDCIsu9mqLQybONqU1ROPR0xOI271yFOoto6ONHkNHvsdahlpQJY8PsV72
         eIpmv148lJ1FfH5VfvHCpFzrcnBKW4AravjAqVd0Aq2af5M6H42VkZMDYm+e2UNZya7U
         ynQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=I3xlytzg;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0+WiSEOzm8ecFeBb+6Rf4b/3grvJE9Iwqi3ayXmOZ9E=;
        b=SS6njg3+vrMciezn7KjoS7My4ZL/TZ828P5D0//msH5jbnQPv1GV4k6AKqs88sYTjF
         ahKrOV9BK8no5/H+j6BlcEOrwBBxRRFooG5FZM+qROYi9mfRo92SaDxJ2jHgAChtRpzt
         B42LIve+InU35rGSLHVM3Ov+N2ZgyZB+5rVMWNNHzSBaePjqFj0mxmlmJf09D6IE4RPP
         hR/sIy/1xxu7uyrX6nAoXc/CCScbdKoP6IfTn1OIXAgKE/QrIeEgEe8crWwIB2SneCmA
         6qW/FbSyjGBlUsPITVv5NIVBTNcquWxpHH2/qlUr76TUkdr7+y9grSSNW/ym1uIbjU7y
         EHFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0+WiSEOzm8ecFeBb+6Rf4b/3grvJE9Iwqi3ayXmOZ9E=;
        b=7ClKRTEyypqaDuQb8pAHBkUNDaUMxzu6Pci7FkUIc2bKjWdjRcuDIWqZgvNzhVDFTN
         6DZqbR1NilYOEDYHaCHe/ZsGrgl+a/ctcPnTZnmCRXim9cj6MnEWxvXfRe8++lx7TdZS
         hktlmayXPgTO+6EnU1CzdAfOFFGSSgPXvdpQY0Mw8F/v20MFk/TDg8paSlxiZL8pzbxu
         NxXLGTk+nwor1mG0zqVd1/TDpGdoo8oj/WcZVd2xTV4S7UqbBtfz8ctOPC7g6knjz09g
         7oSOI0iEKR5tWqUjPVishORGjH/Wb/8Nx3QbcD8Ce3uNsvy9wpI4VW0gM3s88GBWINns
         tzpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWSd7DoDZcuKBDxV7888Iu1etce1oy0Ce42Mahn22z2FPqk3RbK
	ODJWlH0Wr1cuzdcEHtf7V74=
X-Google-Smtp-Source: AK7set+f1EtzNDz7xe5VuhG/k+YCgEdIbRcHhWBqP9lGUg4329qSjKrkmSGTSBi9Wbe3suyKiYIR4w==
X-Received: by 2002:a63:7902:0:b0:502:fd12:83ce with SMTP id u2-20020a637902000000b00502fd1283cemr3115554pgc.5.1677382963730;
        Sat, 25 Feb 2023 19:42:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ead4:b0:237:18be:2595 with SMTP id
 ev20-20020a17090aead400b0023718be2595ls5883907pjb.3.-pod-control-gmail; Sat,
 25 Feb 2023 19:42:42 -0800 (PST)
X-Received: by 2002:a05:6a20:160e:b0:c7:6f26:ca2 with SMTP id l14-20020a056a20160e00b000c76f260ca2mr18842202pzj.58.1677382962833;
        Sat, 25 Feb 2023 19:42:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677382962; cv=none;
        d=google.com; s=arc-20160816;
        b=KdSyeFG4fS5XH52vwPxaL1IYG2iYWo5zvEJy1pyejNJELBBz176Aq6go+bnYyMRIVD
         e/G1nU5qevMMGGlNw2Ot/OlY6qbfFJJIhH5JfaE1wYd6pRyz5GprFotwxORceLJXkBpv
         b4+Gp/WN9h/6uAJtuqcfhgoyh0kAvsSgJDAVEQyPmOh4JdTBjbEaCy7UbHCzAzxwGZLb
         jGs0fYD5+lEUvzuWJC0kGlReIC97kN+b7u7ZkG/FalTjm4m5dTF1cDfe1kkPQBWBPkUC
         4xfyEEGssvhKZP3PiEqPURWVi1EZ4/JrcJrmbZAiSa79f+dTqL2YGjnM0mog5sZ1aVi5
         kxqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7SJgyX1ePUIR2q613R2uB5TGXsIuLBL3qdotgdIwVsI=;
        b=IeC3niG07m5mTs9KcFu7KHiy5xNCwPDb+lSHsM+yiHgrL8rTJNe49i8DBLqhnrNnFD
         QVDrfwR1GUfmOEcYqEsG/jhe9coYDGn5zRdlTUVkFZgQVi1aR1x8omQf9lxXXUeUMob/
         bJty8sAz2FmuGcga45HPrCbcL+JSnrLpGq5yX+vsjCO6hkxcc3bnkbQAkofOYWPRF+/V
         I4rQNqXjFY+cILX3i4yWPhkfkAzE08W4xVRC5GYf16Q/XTj5/P5iO7KW7Tx8dfpXtxMb
         GoO7UJ6ls8ePjg505sPLT5eIv6zZEnkYKkJAySAXHpAc3R+6ni8srP+bE+om0EdE7NOF
         M6Pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=I3xlytzg;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 65-20020a630544000000b00502ff5fbceasi146200pgf.3.2023.02.25.19.42.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 25 Feb 2023 19:42:42 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3918B60BE9;
	Sun, 26 Feb 2023 03:42:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6EB44C433EF;
	Sun, 26 Feb 2023 03:42:38 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Tony Lindgren <tony@atomide.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	"Rafael J . Wysocki" <rafael.j.wysocki@intel.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	dave.hansen@linux.intel.com,
	x86@kernel.org,
	ryabinin.a.a@gmail.com,
	jpoimboe@kernel.org,
	keescook@chromium.org,
	samitolvanen@google.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH AUTOSEL 6.2 17/21] entry, kasan, x86: Disallow overriding mem*() functions
Date: Sat, 25 Feb 2023 22:41:46 -0500
Message-Id: <20230226034150.771411-17-sashal@kernel.org>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230226034150.771411-1-sashal@kernel.org>
References: <20230226034150.771411-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=I3xlytzg;       spf=pass
 (google.com: domain of sashal@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Peter Zijlstra <peterz@infradead.org>

[ Upstream commit 69d4c0d3218692ffa56b0e1b9c76c50c699d7044 ]

KASAN cannot just hijack the mem*() functions, it needs to emit
__asan_mem*() variants if it wants instrumentation (other sanitizers
already do this).

  vmlinux.o: warning: objtool: sync_regs+0x24: call to memcpy() leaves .noinstr.text section
  vmlinux.o: warning: objtool: vc_switch_off_ist+0xbe: call to memcpy() leaves .noinstr.text section
  vmlinux.o: warning: objtool: fixup_bad_iret+0x36: call to memset() leaves .noinstr.text section
  vmlinux.o: warning: objtool: __sev_get_ghcb+0xa0: call to memcpy() leaves .noinstr.text section
  vmlinux.o: warning: objtool: __sev_put_ghcb+0x35: call to memcpy() leaves .noinstr.text section

Remove the weak aliases to ensure nobody hijacks these functions and
add them to the noinstr section.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Ingo Molnar <mingo@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Link: https://lore.kernel.org/r/20230112195542.028523143@infradead.org
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 arch/x86/lib/memcpy_64.S  |  5 ++---
 arch/x86/lib/memmove_64.S |  4 +++-
 arch/x86/lib/memset_64.S  |  4 +++-
 mm/kasan/kasan.h          |  4 ++++
 mm/kasan/shadow.c         | 38 ++++++++++++++++++++++++++++++++++++++
 tools/objtool/check.c     |  3 +++
 6 files changed, 53 insertions(+), 5 deletions(-)

diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
index dd8cd8831251f..a64017602010e 100644
--- a/arch/x86/lib/memcpy_64.S
+++ b/arch/x86/lib/memcpy_64.S
@@ -8,7 +8,7 @@
 #include <asm/alternative.h>
 #include <asm/export.h>
 
-.pushsection .noinstr.text, "ax"
+.section .noinstr.text, "ax"
 
 /*
  * We build a jump to memcpy_orig by default which gets NOPped out on
@@ -43,7 +43,7 @@ SYM_TYPED_FUNC_START(__memcpy)
 SYM_FUNC_END(__memcpy)
 EXPORT_SYMBOL(__memcpy)
 
-SYM_FUNC_ALIAS_WEAK(memcpy, __memcpy)
+SYM_FUNC_ALIAS(memcpy, __memcpy)
 EXPORT_SYMBOL(memcpy)
 
 /*
@@ -184,4 +184,3 @@ SYM_FUNC_START_LOCAL(memcpy_orig)
 	RET
 SYM_FUNC_END(memcpy_orig)
 
-.popsection
diff --git a/arch/x86/lib/memmove_64.S b/arch/x86/lib/memmove_64.S
index 724bbf83eb5b0..02661861e5dd9 100644
--- a/arch/x86/lib/memmove_64.S
+++ b/arch/x86/lib/memmove_64.S
@@ -13,6 +13,8 @@
 
 #undef memmove
 
+.section .noinstr.text, "ax"
+
 /*
  * Implement memmove(). This can handle overlap between src and dst.
  *
@@ -213,5 +215,5 @@ SYM_FUNC_START(__memmove)
 SYM_FUNC_END(__memmove)
 EXPORT_SYMBOL(__memmove)
 
-SYM_FUNC_ALIAS_WEAK(memmove, __memmove)
+SYM_FUNC_ALIAS(memmove, __memmove)
 EXPORT_SYMBOL(memmove)
diff --git a/arch/x86/lib/memset_64.S b/arch/x86/lib/memset_64.S
index fc9ffd3ff3b21..6143b1a6fa2ca 100644
--- a/arch/x86/lib/memset_64.S
+++ b/arch/x86/lib/memset_64.S
@@ -6,6 +6,8 @@
 #include <asm/alternative.h>
 #include <asm/export.h>
 
+.section .noinstr.text, "ax"
+
 /*
  * ISO C memset - set a memory block to a byte value. This function uses fast
  * string to get better performance than the original function. The code is
@@ -43,7 +45,7 @@ SYM_FUNC_START(__memset)
 SYM_FUNC_END(__memset)
 EXPORT_SYMBOL(__memset)
 
-SYM_FUNC_ALIAS_WEAK(memset, __memset)
+SYM_FUNC_ALIAS(memset, __memset)
 EXPORT_SYMBOL(memset)
 
 /*
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ea8cf1310b1e8..71c15438afcfc 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -618,6 +618,10 @@ void __asan_set_shadow_f3(const void *addr, size_t size);
 void __asan_set_shadow_f5(const void *addr, size_t size);
 void __asan_set_shadow_f8(const void *addr, size_t size);
 
+void *__asan_memset(void *addr, int c, size_t len);
+void *__asan_memmove(void *dest, const void *src, size_t len);
+void *__asan_memcpy(void *dest, const void *src, size_t len);
+
 void __hwasan_load1_noabort(unsigned long addr);
 void __hwasan_store1_noabort(unsigned long addr);
 void __hwasan_load2_noabort(unsigned long addr);
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 15cfb34d16a13..3703983a8e556 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -38,6 +38,12 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
 }
 EXPORT_SYMBOL(__kasan_check_write);
 
+#ifndef CONFIG_GENERIC_ENTRY
+/*
+ * CONFIG_GENERIC_ENTRY relies on compiler emitted mem*() calls to not be
+ * instrumented. KASAN enabled toolchains should emit __asan_mem*() functions
+ * for the sites they want to instrument.
+ */
 #undef memset
 void *memset(void *addr, int c, size_t len)
 {
@@ -68,6 +74,38 @@ void *memcpy(void *dest, const void *src, size_t len)
 
 	return __memcpy(dest, src, len);
 }
+#endif
+
+void *__asan_memset(void *addr, int c, size_t len)
+{
+	if (!kasan_check_range((unsigned long)addr, len, true, _RET_IP_))
+		return NULL;
+
+	return __memset(addr, c, len);
+}
+EXPORT_SYMBOL(__asan_memset);
+
+#ifdef __HAVE_ARCH_MEMMOVE
+void *__asan_memmove(void *dest, const void *src, size_t len)
+{
+	if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
+	    !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
+
+	return __memmove(dest, src, len);
+}
+EXPORT_SYMBOL(__asan_memmove);
+#endif
+
+void *__asan_memcpy(void *dest, const void *src, size_t len)
+{
+	if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
+	    !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
+
+	return __memcpy(dest, src, len);
+}
+EXPORT_SYMBOL(__asan_memcpy);
 
 void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 4b7c8b33069e5..3bd5bbfb4dee0 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1082,6 +1082,9 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_store16_noabort",
 	"__kasan_check_read",
 	"__kasan_check_write",
+	"__asan_memset",
+	"__asan_memmove",
+	"__asan_memcpy",
 	/* KASAN in-line */
 	"__asan_report_load_n_noabort",
 	"__asan_report_load1_noabort",
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230226034150.771411-17-sashal%40kernel.org.
