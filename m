Return-Path: <kasan-dev+bncBC5JXFXXVEGRB3NK5OPQMGQE2LEQA2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 572A96A2D83
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Feb 2023 04:43:43 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id cf37-20020a056512282500b004cfd8133992sf845381lfb.11
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Feb 2023 19:43:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677383022; cv=pass;
        d=google.com; s=arc-20160816;
        b=1B7LtuWOM942qAyEqnviwq/Vi39p7iwmW3it60JsgHL7XtC0InYOWC2IS2sHud4cGe
         nk7+VPg0ChsPJHtCFWhY8CLFyS6XSZi+QXPUdS55MPq3K6w6Oasiteb67Ca2/dH7wrWj
         9ZsewAECnp4WMZ0Ak1qKdsYrvTzai99yzf9GTFlsg13qsyevUXzG1WSZ+rFl8dcsoKno
         8y5aV27DJWLuiUnKiJnkWHtSVUXMnnR35xwH5qrre2FbxaCn+8tdG00k9m6M0vmZFQc7
         MgjDhSQL8BiHVNoQdkg3wpOr7t8VS096hcClZc/O3OKE5Vq059KUjPOPGAUSaj2GcenS
         V71w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q/V8vnNJfW5GRHFyyQCeTecjPuU82VW41ioNpZ4XQBQ=;
        b=uzmR/8R/pYC7kz0KOtKu/IrynSRJdawJmgr6xZCc6kdGokiOMkOKeDgup471buuqgk
         MqUapiZ4PK3ehFFaWX9KExonEsw/LjCOTVNigBYXIpap+Fiu0RvgnylRDnDrOBrYHjUD
         tq5FpFUYUgTTCUptUiflNhkkp2CKE1QBqjYgwZ4LPzCMZUmJj4EOHLETUHXPR1M1g7N9
         5lZPGz70EjpqSA601XQl6b2pWP5DD/Jzwbob6C0GSPecO27hAq83rlAltergiBYuU9S6
         N2l9syhf04NeogY7C3pXvj8dW6ff8fveZCm+gLO5BIP0KIXXCqUmjn97MoUBwCgJZlSa
         MdqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YbZYVwCO;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q/V8vnNJfW5GRHFyyQCeTecjPuU82VW41ioNpZ4XQBQ=;
        b=Vxer1eXQSoVBnW8QZYz3097rUK8wQaojpSilrVmq3X7+uVhg5hFm0U5fr1OfXrsvCC
         DHXj5VdzXwuGOOy0t5+ZcWq0i2TLMSMqjeaM60uxNpThV8WhqtTbCQbs9UOcgwKIMzyN
         BWfM+I4a1hDX17GWcS0mfKql3swx6rOZqyyPiMFnT+dSq+UH60wqayIBlZ8eqLzgPiuS
         NC6SkbEjjW4ti+M7T4fykZnb7qSOQ3PJ5AHcdBNBPSiU76SVqMbgfcvQZummOqG5hJie
         nyC8YnP0xqHLs2lCyYrHJ2x0Ox5x3o4VNYN+CMvd/CFyB0xzJAjqWxY9yTu0birLgwIk
         GcKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q/V8vnNJfW5GRHFyyQCeTecjPuU82VW41ioNpZ4XQBQ=;
        b=NwN0HnfJT9SpYIXioYs1GedivH1MD/k4QcttBthD0HvmtqV1Xtz8zufcDSu7bfeMua
         GGUQbvVBPvHYF+ncIp33dNbqpB3BQgtlPGyGJSENSRKHi6XkeJJpmAxa4puMf50pJ/0E
         JahJdgXAyNNILy4l+1EWtH8IaXVj3CRoDGrF2ik6FigW8nRenv9AYdxaEOnKgL5C46Ta
         7kJTaNuOOF+OpG2J3kAg09I6KJLzHZbruV8dlXdmqOEMN7/N7PJLS88zu77xs8vMfeSR
         HbvEpffr64QmcGmPDsm1/At3jPmIEhQNJ0vRtVQ8+OVfdJoj8a910v9wLkiI8MeIM+P5
         x2dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU+CfD3Z2/xmJFYagZGbPj8tDeMjV+XxIJskBbc5JxWkg1BO4Gs
	n3LQl+qdFVPQ20dQMf2N2fQ=
X-Google-Smtp-Source: AK7set9HYJxWM0c/qTJbDVz3i6Enc+AzwUefReOTrRebjXtLcp9BSkhXubCTlsDc24g359h0neZU7Q==
X-Received: by 2002:a05:651c:487:b0:293:5fb9:3c10 with SMTP id s7-20020a05651c048700b002935fb93c10mr6132703ljc.10.1677383022117;
        Sat, 25 Feb 2023 19:43:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e26:b0:4db:3331:2b29 with SMTP id
 i38-20020a0565123e2600b004db33312b29ls2717433lfv.0.-pod-prod-gmail; Sat, 25
 Feb 2023 19:43:40 -0800 (PST)
X-Received: by 2002:a19:520f:0:b0:4df:b123:9a7 with SMTP id m15-20020a19520f000000b004dfb12309a7mr138638lfb.46.1677383020399;
        Sat, 25 Feb 2023 19:43:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677383020; cv=none;
        d=google.com; s=arc-20160816;
        b=JyNSpqnCz2vyJhab6FfxCsBNmByF+JeUP5cWKtagvAzC14DOr0SZd995jR131ODHP2
         dHKPxHLXc8AygxYPjJM88ddbIQt2vurtRBIj8yekLRzRdRRRswHZRuKxt3a1cPvoIosh
         9O+caKQYQTM2DYwFVHK1y5pUByuOe13eVtofNCZjZ8Uf+viEBA9WVRr9KupXpjFd/GVQ
         jspVeq15cZNSdjjZVBiwKknwT0OsaCnkIQHfRR3G7VVp+V7004uM12VcZNxxtYhsBBWd
         +MCmulKoIlPVGTcocSEozdWYlcaqbcMqZbqYtokgeB0MgzbZ/su/9hW9BShnM3wZumgE
         selg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=D/PB6NXKxNdjpynPwo10jn/IZfYn8AcmHC0WUbviE1w=;
        b=zFSVw7CUui4120ku/onlIc68DkZSeh90B/WIqkKlrFctRYNHS9fsiQptuV8RHWKSFs
         z5NeVRBA3DigBuJ07OF1Z9pHYjiSu3bWtSCnqEC5ylhaQbZydzIZ3r+SCqZPgbYpvQmm
         w+9yK4UTls0wg1ucFtjB0drIQ2UIVWU+H/EX4Xna3AYD8hdFBAONU1UJDXjB0ASdj44w
         y3nCHPYls7MKQ/uxHruFSgBzzQ2F5tahR43kg1tPksxw3S5iFFMNFhiPPUTpOCxfs+23
         STJxlSVFZBZyN6MxsnaQLisGeu+q2IUvKU8kzIBp2lMYTEjuhFesaenAimVljxTJqpyT
         yCPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YbZYVwCO;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id s1-20020a056512214100b004dc4feeb7c2si139321lfr.5.2023.02.25.19.43.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 25 Feb 2023 19:43:40 -0800 (PST)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C03BEB80159;
	Sun, 26 Feb 2023 03:43:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 882B2C4339C;
	Sun, 26 Feb 2023 03:43:37 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 6.1 17/21] entry, kasan, x86: Disallow overriding mem*() functions
Date: Sat, 25 Feb 2023 22:42:52 -0500
Message-Id: <20230226034256.771769-17-sashal@kernel.org>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230226034256.771769-1-sashal@kernel.org>
References: <20230226034256.771769-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YbZYVwCO;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as
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
index abbcc1b0eec50..a2a367d2ac809 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -614,6 +614,10 @@ void __asan_set_shadow_f3(const void *addr, size_t size);
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
index 0e3648b603a6f..48c405886f958 100644
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
index 51494c3002d91..1252c06f42b3b 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -955,6 +955,9 @@ static const char *uaccess_safe_builtin[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230226034256.771769-17-sashal%40kernel.org.
