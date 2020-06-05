Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPEE5D3AKGQEJGJWGPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id EF5D61EF310
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 10:28:45 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id i7sf4293188pfk.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 01:28:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591345724; cv=pass;
        d=google.com; s=arc-20160816;
        b=WBb+aC+4BNieQYNs5jkRqBSBtIE4YusqTyBChybH+tuowTA0XI1VZnTJZb3lmCuzvA
         RdrXpt+BfeklRyMTYQgU2k5oi7rJBqzhVH2hi2tdiXzf1HKkhrNykdlM5Q3yYmIlviHG
         zKieVElTcm7bdHph8m/H3PRlYmqyNiEZqqCzsPvV93GtalroRDAS9rtmLjIEUPqUJ61P
         6XwoaCyJMz4mYr8LOkXsNQJqaTovtVfDjg0EosfOccTHtG60E/bD7cvMdq7YWU9Qqmzd
         /IBFqMQDSxtZLN+F35YtqPSkOZxGYjXPQbqZaSmIH5CT+v5SZObWXfiZZSHc6DZ23yJa
         o2sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=7RU0X21CczLnvTbt6YTcf7pTBNYTmCRE2ab/Aatz2x0=;
        b=NGrRhFcz8ZXfczFCtB91W+7pOJvWctErLrSUVthA3qH+wmGmNKmPPnvklIdkKHXhEg
         x5VdjeVPtqLUc1ckFvvGdLqOGhD3Wl57ufyFfMKx6ZjWjkTP/ktPYDI2XuCkRhs7COYS
         5D/gpPMkSDnS5H/gcbibA/xzlsl5PwjxqWuJrNZRlgPydHOXhELpMA46BZAirDBptLB+
         non9EcunUU1mPAdbj0GD0CRDt+FZjKN0P/1VeShqi6pUOMk6NFHDo4EG8X1M/YPas78x
         z6SIN3N5vf5SuXOPmc12kCo+54RQXyG0w6dT7VtQWpZzbjoV/zZiiWWwPD/Ee6aZIvhE
         w8gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NRNhyOkZ;
       spf=pass (google.com: domain of 3oglaxgukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3OgLaXgUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=7RU0X21CczLnvTbt6YTcf7pTBNYTmCRE2ab/Aatz2x0=;
        b=bY9EgElKemZZ3VMQ3vMBzNXfL/i+SiWRXNXyiBYRMBStziJRsl6pKpYvJFb0zJ+m3p
         ncn2OCTfF+p+DqMDgdQfqn4WgOJ4omjCSSbThzcXafIK+PkcWDRhAot8uLfP2tlWb+QS
         tYH3VBtVBLyk48cuE/8Ak+KmLG8HTEjV0i9sjrQTKUEpMFC8QXTCQ6gdT/9ygVk1Mz7C
         T9IqXwaO05kLA/C04140SpdHI9C27yi84qin8PtsQgLqMCjoJW33GbZmwKAZC6ATatFz
         Kp0NJWekenfutjzJiRr743mKQhxoXLjmcVD7biq/NPo4ew8+1MlXoYERBPzw7sW5TbN6
         6yYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7RU0X21CczLnvTbt6YTcf7pTBNYTmCRE2ab/Aatz2x0=;
        b=FLQO8uP3MKm4Clb8Efb8Aad30KJcvTgLk5KOCprQGeuK6VVsnjwJ5AL+0bIx2w23Lu
         8Rka6DfXaZ1jOuzg2IhNoskuMX/EaB6aHdvPIxvD5Q+mvxFmrRRth/C3CZuLZhhzvEgu
         eroOnqGzSl44/XFhgIu4tVvQ5JaQWcRXblT6U81UaYk1sfT26J9BN1OUDK/21FI7jtta
         9Z42qsMR8U9hjesSMdFzQifgYwjVBQroO0IMj3QR3QVLmdVtqz5Dg1b5Qp4H486pOQhj
         HRWLytg2pwWRP+73ySTooOINpJezi5EkQghIfiILUNcu84YxMyhpJg3wG41A+DNHdcGJ
         4k/A==
X-Gm-Message-State: AOAM530vLPXyBhNBxiZy2pFtOZsalp+5qn3hyYaLZqLCmL3K0m0TazIN
	i/chPgupT00sCZ9O/Livops=
X-Google-Smtp-Source: ABdhPJx3u8pT2vE39+/ox4NYWjCR0jiSBrgfVoZegAsIGTeTcIqXcKiJXUTC1gGc5NLdTqkedv2fTg==
X-Received: by 2002:aa7:9839:: with SMTP id q25mr8490109pfl.291.1591345724363;
        Fri, 05 Jun 2020 01:28:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8f3a:: with SMTP id y26ls2778827pfr.3.gmail; Fri, 05 Jun
 2020 01:28:43 -0700 (PDT)
X-Received: by 2002:aa7:9ac5:: with SMTP id x5mr8524164pfp.234.1591345723823;
        Fri, 05 Jun 2020 01:28:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591345723; cv=none;
        d=google.com; s=arc-20160816;
        b=L7jz08BtStKlWRmtryYM5vuXQGugCFtzswhQ924up3Wkz4No/oxsJmtpwpu44HIDab
         SS4wPRernOPowhp/pOmSuwv9TWn3hpj17W/Z6zScKFLUCgH0+60C0N/YybJO9Xc8kwaN
         aRoNdwsvJs6iX9qR3e2LihsxcHSYn1z/HkXxsy+bfaaIvXdtwysytAPd+eg3ykt+4kVg
         SUCZGH+MSZ4xcCbuP7nNRRfgqz7qBgMrmFG/hSt5YwETH/ARIa/SgnO8J/me5NqCIqC1
         o/B/BEJpE3h/zZHfW84+dY+lN3Kvl3WuPFeqbwBN6cJAk9BpfMib6En0l01Kr39CYz77
         kQig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=q4xtHULh8K3VSLAHr6h+7DTr9q0n8BVN7sADFLbNyog=;
        b=Yczdc3U45HyGFftodMfpICYd/zCvTi6v5zO9wQEB9uc4CFGk2eKZSFbO4KpvkARo7f
         QjlHyIA5I4XaEeHwQGYTzI0fhDXK4LYO5TyQl5+4NwP3PQUyKmQ6x1lVhgYrios2Kzre
         N3RmMSmM6mSJRik4Oyq/31XpbyGo3GuST81Cwz2xGJLUHGcQicGHoXqymPxJR1jCZfdm
         Ba2KDgPU46cTtlfB0/Yz0I7ILt998nmey0VxW8ZBzDLslDbH66GYBRuMp02qMLjmr8Ot
         HboHR8MkplkJdUr9b0uWf3iHYmxX+da8GMUNDPcvdT/Wpe34UTmVG/AAFUw5mK/lTp4/
         HC2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NRNhyOkZ;
       spf=pass (google.com: domain of 3oglaxgukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3OgLaXgUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id r17si502132pgu.4.2020.06.05.01.28.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 01:28:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oglaxgukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id k186so10897416ybc.19
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 01:28:43 -0700 (PDT)
X-Received: by 2002:a25:b882:: with SMTP id w2mr14553588ybj.160.1591345722977;
 Fri, 05 Jun 2020 01:28:42 -0700 (PDT)
Date: Fri,  5 Jun 2020 10:28:38 +0200
Message-Id: <20200605082839.226418-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH -tip v3 1/2] kcov: Make runtime functions noinstr-compatible
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, mingo@kernel.org, 
	clang-built-linux@googlegroups.com, paulmck@kernel.org, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, x86@kernel.org, akpm@linux-foundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NRNhyOkZ;       spf=pass
 (google.com: domain of 3oglaxgukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3OgLaXgUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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

While we lack a compiler attribute to add to noinstr that would disable
KCOV, make the KCOV runtime functions return if the caller is in a
noinstr section, and mark them noinstr.

Declare write_comp_data() as __always_inline to ensure it is inlined,
which also reduces stack usage and removes one extra call from the
fast-path.

In future, our compilers may provide an attribute to implement
__no_sanitize_coverage, which can then be added to noinstr, and the
checks added in this patch can be guarded by an #ifdef checking if the
compiler has such an attribute or not.

Signed-off-by: Marco Elver <elver@google.com>
---
Applies to -tip only currently, because of the use of instrumentation.h
markers.

v3:
* Remove objtool hack, and instead properly mark __sanitizer_cov
  functions as noinstr.
* Add comment about .entry.text.

v2: https://lkml.kernel.org/r/20200604145635.21565-1-elver@google.com
* Rewrite based on Peter's and Andrey's feedback -- v1 worked because we
  got lucky. Let's not rely on luck, as it will be difficult to ensure the
  same conditions remain true in future.

v1: https://lkml.kernel.org/r/20200604095057.259452-1-elver@google.com

Note: There are a set of KCOV patches from Andrey in -next:
https://lkml.kernel.org/r/cover.1585233617.git.andreyknvl@google.com --
Git cleanly merges this patch with those patches, and no merge conflict
is expected.
---
 kernel/kcov.c | 59 +++++++++++++++++++++++++++++++++++++++------------
 1 file changed, 45 insertions(+), 14 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 8accc9722a81..84cdc30d478e 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -6,6 +6,7 @@
 #include <linux/compiler.h>
 #include <linux/errno.h>
 #include <linux/export.h>
+#include <linux/instrumentation.h>
 #include <linux/types.h>
 #include <linux/file.h>
 #include <linux/fs.h>
@@ -24,6 +25,7 @@
 #include <linux/refcount.h>
 #include <linux/log2.h>
 #include <asm/setup.h>
+#include <asm/sections.h>
 
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
 
@@ -172,20 +174,38 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
 	return ip;
 }
 
+/* Return true if @ip is within a noinstr section. */
+static __always_inline bool within_noinstr_section(unsigned long ip)
+{
+	/*
+	 * Note: .entry.text is also considered noinstr, but for now, since all
+	 * .entry.text code lives in .S files, these are never instrumented.
+	 */
+	return (unsigned long)__noinstr_text_start <= ip &&
+	       ip < (unsigned long)__noinstr_text_end;
+}
+
 /*
  * Entry point from instrumented code.
  * This is called once per basic-block/edge.
  */
-void notrace __sanitizer_cov_trace_pc(void)
+void noinstr __sanitizer_cov_trace_pc(void)
 {
 	struct task_struct *t;
 	unsigned long *area;
-	unsigned long ip = canonicalize_ip(_RET_IP_);
+	unsigned long ip;
 	unsigned long pos;
 
+	if (unlikely(within_noinstr_section(_RET_IP_)))
+		return;
+
+	instrumentation_begin();
+
 	t = current;
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
-		return;
+		goto out;
+
+	ip = canonicalize_ip(_RET_IP_);
 
 	area = t->kcov_area;
 	/* The first 64-bit word is the number of subsequent PCs. */
@@ -194,19 +214,27 @@ void notrace __sanitizer_cov_trace_pc(void)
 		area[pos] = ip;
 		WRITE_ONCE(area[0], pos);
 	}
+
+out:
+	instrumentation_end();
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
 
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
-static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
+static __always_inline void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 {
 	struct task_struct *t;
 	u64 *area;
 	u64 count, start_index, end_pos, max_pos;
 
+	if (unlikely(within_noinstr_section(ip)))
+		return;
+
+	instrumentation_begin();
+
 	t = current;
 	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
-		return;
+		goto out;
 
 	ip = canonicalize_ip(ip);
 
@@ -229,61 +257,64 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 		area[start_index + 3] = ip;
 		WRITE_ONCE(area[0], count + 1);
 	}
+
+out:
+	instrumentation_end();
 }
 
-void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
+void noinstr __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(0), arg1, arg2, _RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp1);
 
-void notrace __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2)
+void noinstr __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(1), arg1, arg2, _RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp2);
 
-void notrace __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2)
+void noinstr __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(2), arg1, arg2, _RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp4);
 
-void notrace __sanitizer_cov_trace_cmp8(u64 arg1, u64 arg2)
+void noinstr __sanitizer_cov_trace_cmp8(u64 arg1, u64 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(3), arg1, arg2, _RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp8);
 
-void notrace __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2)
+void noinstr __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(0) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp1);
 
-void notrace __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2)
+void noinstr __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(1) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp2);
 
-void notrace __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2)
+void noinstr __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(2) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp4);
 
-void notrace __sanitizer_cov_trace_const_cmp8(u64 arg1, u64 arg2)
+void noinstr __sanitizer_cov_trace_const_cmp8(u64 arg1, u64 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(3) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp8);
 
-void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
+void noinstr __sanitizer_cov_trace_switch(u64 val, u64 *cases)
 {
 	u64 i;
 	u64 count = cases[0];
-- 
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200605082839.226418-1-elver%40google.com.
