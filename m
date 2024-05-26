Return-Path: <kasan-dev+bncBC5JXFXXVEGRB6MHZSZAMGQEPXZI2HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id DB32C8CF334
	for <lists+kasan-dev@lfdr.de>; Sun, 26 May 2024 11:42:19 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5b953e5f449sf2678034eaf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 26 May 2024 02:42:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716716538; cv=pass;
        d=google.com; s=arc-20160816;
        b=cLtrDkrf0gyCrofIOQ6KPYtPIDs7uvigHqc9pA825byGhbnTNWf6efkvBd9ZU7/pXn
         hrtIt4c8piL0qDtfkjIeA2UToYYjoxYbSRI1o/aUVriB1Ino1joFpgOIkrqnWLAtD4yG
         kotrCdXekZ826jNl5so+SbIy6VJtdeX7auT0fZ8Zg20OeEZcHkBuLzRYAXqGWqB2IcHC
         JDYu8jXbXJCu9+fljFJdLkBSVPQHMv4OPJT1vXQU1e88fAJ2/mvuCH0hE1L/kR6vHPQJ
         eHLHX5LXQjdz7VlrI30NaOt7XzvNBgHAd7KNPtr5JSanB0FQgBTbAOfiNMobSKibzWO0
         SFgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+YlDdA9XoHOhGrPOZRVnMsM6rnh3F/WI9xZWkfB5Oko=;
        fh=d4Ji8GhDoNA3HQFx34Sfxz0uz8l4MvGeYAnNVtUvnGY=;
        b=zdIL1/kkI3UgWwlko53xHRnTVWcRficWp/92DzFE6a/oolgTq5ZRZGnjTNPr3AHC0S
         T/a4X2SNYRAvu3rDZ4pN6xiSevQcB9yk1m3pr/Bdx0p54qi1E4zaECLfc0q8ZJvMDj62
         eZBBufMIx1K+1aSC4pIAXpimLAL50Px9GnZrOH4fCFvwHJ9VI24YyjPQqZBORQtKPoY/
         U41pBRgESUhzrRVrBHoXGk/mSeRgufF940GfSHDsSLTKIKJegu0b8e1lxUehlTXVJ90g
         WQSJl1uzg/x8XNSTPaAfFQVFQO5sLjpLKnjt+3uj8WYH1B+yV0I2gg6QsqQvCB7xZKw8
         2Rkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FMMzgPDG;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716716538; x=1717321338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+YlDdA9XoHOhGrPOZRVnMsM6rnh3F/WI9xZWkfB5Oko=;
        b=M698M4tIhXHq8ekLrEYToH26KPpCrbdIDO1c4hs5mGtKw7FxEdhs1WiF8ZVEPXuxbZ
         hvayyLh7/unmvxV8o9DM7d5yxQI4mui00+HjzqaCub+3+2EBu1QuFgPw05lzdjjZnvZ0
         sV3M+bw04yjln0bPMzYS442shCo2mDeSldrItD6AG4QLUFxLIJ7FAlcT/eIE5pTTmbIG
         hz4ybgwrhT9un5rFBQI5j0eufJkiFy5n8X71RB3aPN/DlP0arPk6aX0AxKiesuXqRZoC
         ONxiAW5zLnFt2OiaGxqh1T37PNC/STANLJvAMxbZVdRfkC5KsjJ0hciG5mSu7JzjTVix
         DJQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716716538; x=1717321338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+YlDdA9XoHOhGrPOZRVnMsM6rnh3F/WI9xZWkfB5Oko=;
        b=GwdI7Ws+0h+zDFgcvtq0spT0YGlmM+DKZdPU8KlhnqODtDltQUe+JZYqyQBVxjGpAd
         WI/Lp0YwHF4Q/PlDR5mJpJzTMwIOZS0v+CJOespNr8IxyWd6Mjj6GC3fmkbK3aX/xU0y
         yKJXiJ74yrzXwQyNnKWfV7lfmtmkNlg9KS1jJ6Vr+iXJ3yqbAT8Dkl6d9ufLwIgxx5Sh
         B8smY60WUML3XD+7tuVPozHr9c1uWErDHTQ5iUBHK4kP4kc2r1P09sJu+wZD1KT2X6BT
         ZtT5Y0Y2LzyH7qZ9rlChFxSq/IHVPI59GndAkYb8Y57JoCb7SwTN1Hd91N5eOS0pflE2
         EthQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsx8c27z0HMltUxoD1g1pFPfIUYUEoahjXO5Y4b30h4heOElEKSOIdK7ZpmvDy4dX2XDeHH02yel2KzY1Or4UjXgAAlaCsFw==
X-Gm-Message-State: AOJu0YwPmwi+Un64xLz6n9gHoOrflXmFVwRlPHHavHlZea5s+3kr9xgM
	PPfR3+qAeElCPPLWyzB5DToUGZtLH1bF0q3HSwpok8KL7yD8dJZv
X-Google-Smtp-Source: AGHT+IGrFu9ZLAgPlKPeX106v4xZZ5NvMgfjZEZHVgEZNLB6KSRMr5jlKT9/iXo83dpMtXYYGV7n2Q==
X-Received: by 2002:a05:6870:8a0a:b0:23c:5f20:8393 with SMTP id 586e51a60fabf-24ca1472b59mr6479639fac.50.1716716538002;
        Sun, 26 May 2024 02:42:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1711:b0:24f:dd11:447f with SMTP id
 586e51a60fabf-24fdd11e9dbls456608fac.1.-pod-prod-06-us; Sun, 26 May 2024
 02:42:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvlI5ecz5asBp7S9nKwZRiB1XADrEMf0BYCwEBWurYhTy6v2EAMGzegWJcRQkDtYnaDrnT8Lll5U4e/Rzgd5TodM1F2wQJp2y7Tw==
X-Received: by 2002:aca:1801:0:b0:3c9:67a5:3aef with SMTP id 5614622812f47-3d1a9099e2dmr5983011b6e.49.1716716536856;
        Sun, 26 May 2024 02:42:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716716536; cv=none;
        d=google.com; s=arc-20160816;
        b=RHX7o+uebEt3fguhYSbXWcTu4ASG3nvEGU9I7EliUxc5WDUUTXfDpbso+3QB2mdlII
         64+aDAsQd4ZUviAU1eY2NSjKolGqGYRy2SXWGsyRTq0iMDZyYmRaLOpV9w+/4wmwjfSY
         vl8zmbduUkOXY4il3jInZlnxNYjWnZc3INmj2sQgaRPObJR3tzuSdZ2O2dUmxAtRy5qn
         jvN7P9X6RDyJMfYdUIka1c6HniQ9TTVIMN6QBolJIY/Qf7JIUPalQ4nCv36gVkjXM6dG
         ZCULmYbrxDKm0FJSEOqPcmm0XYnItkDWOf0fhd/J149w/SA+PB36lCcSSs8PK8x3uGa9
         I4KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UwX/8qUlFb3km3W4WeeBJ++XO3510ePxSCR57FtaRqA=;
        fh=OU1KUoTrn77amHFGlKoo97hx/ecw7gFpSGpGlv4wqcs=;
        b=VvIDSTzH1iJa4nmHVqESOldcs/CeHcqrmyhgT2kjUI4SKUBOa4yK21ZjGDH15+Hb3P
         TJsUsYezXLwu8yQo+kP4hle9wF/jJiLcOJ25uasbVYGqx11BMkHnB+T0UK4Fx+Ar6zS6
         SGfCE9NMDW5VulC/j0SlRLfqv4Jc4TumaaCwXutTUWQsHt0u6/xaK13b66+vcI49i8Ce
         lin7DwzEmlzOd+mRmHJwhHDSXNMj6C9LTv5qPEJDERe0yhNnaYvAoq2/blugszz7qjsD
         6v38OAbpZ07+zNgJhdJIIn4KI3lW8RFeHevJCpZ+VGZWQ60TVDGsMkAKDYGAILCsCCMi
         5JQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FMMzgPDG;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d1b379619esi261919b6e.5.2024.05.26.02.42.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 26 May 2024 02:42:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 14A7DCE094B;
	Sun, 26 May 2024 09:42:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 22C7CC4AF08;
	Sun, 26 May 2024 09:42:12 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Erhard Furtner <erhard_f@mailbox.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Justin Stitt <justinstitt@google.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH AUTOSEL 6.9 13/15] ubsan: Avoid i386 UBSAN handler crashes with Clang
Date: Sun, 26 May 2024 05:41:45 -0400
Message-ID: <20240526094152.3412316-13-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20240526094152.3412316-1-sashal@kernel.org>
References: <20240526094152.3412316-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.9.1
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FMMzgPDG;       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Kees Cook <keescook@chromium.org>

[ Upstream commit 2e431b23a13ce4459cf484c8f0b3218c7048b515 ]

When generating Runtime Calls, Clang doesn't respect the -mregparm=3
option used on i386. Hopefully this will be fixed correctly in Clang 19:
https://github.com/llvm/llvm-project/pull/89707
but we need to fix this for earlier Clang versions today. Force the
calling convention to use non-register arguments.

Reported-by: Erhard Furtner <erhard_f@mailbox.org>
Closes: https://github.com/KSPP/linux/issues/350
Link: https://lore.kernel.org/r/20240424224026.it.216-kees@kernel.org
Acked-by: Nathan Chancellor <nathan@kernel.org>
Acked-by: Justin Stitt <justinstitt@google.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/ubsan.h | 41 +++++++++++++++++++++++++++--------------
 1 file changed, 27 insertions(+), 14 deletions(-)

diff --git a/lib/ubsan.h b/lib/ubsan.h
index 0abbbac8700d1..0982578fbd98f 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -124,19 +124,32 @@ typedef s64 s_max;
 typedef u64 u_max;
 #endif
 
-void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
-void __ubsan_handle_negate_overflow(void *_data, void *old_val);
-void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
-void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
-void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
-void __ubsan_handle_out_of_bounds(void *_data, void *index);
-void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
-void __ubsan_handle_builtin_unreachable(void *_data);
-void __ubsan_handle_load_invalid_value(void *_data, void *val);
-void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
-					 unsigned long align,
-					 unsigned long offset);
+/*
+ * When generating Runtime Calls, Clang doesn't respect the -mregparm=3
+ * option used on i386: https://github.com/llvm/llvm-project/issues/89670
+ * Fix this for earlier Clang versions by forcing the calling convention
+ * to use non-register arguments.
+ */
+#if defined(CONFIG_X86_32) && \
+    defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION < 190000
+# define ubsan_linkage asmlinkage
+#else
+# define ubsan_linkage
+#endif
+
+void ubsan_linkage __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_negate_overflow(void *_data, void *old_val);
+void ubsan_linkage __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
+void ubsan_linkage __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
+void ubsan_linkage __ubsan_handle_out_of_bounds(void *_data, void *index);
+void ubsan_linkage __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
+void ubsan_linkage __ubsan_handle_builtin_unreachable(void *_data);
+void ubsan_linkage __ubsan_handle_load_invalid_value(void *_data, void *val);
+void ubsan_linkage __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
+						       unsigned long align,
+						       unsigned long offset);
 
 #endif
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240526094152.3412316-13-sashal%40kernel.org.
