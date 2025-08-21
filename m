Return-Path: <kasan-dev+bncBD4NDKWHQYDRBLUZT3CQMGQELBWX7HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D4C8B30821
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 23:16:32 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-76e7ef21d52sf2917477b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 14:16:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755810991; cv=pass;
        d=google.com; s=arc-20240605;
        b=kkNvm+AME09HiXe0jDtkYkq36Ju+8P6+B4/ju0mm8I3gBpziIGELoeaccOtjEm6lis
         q8Q8Y/Q9Eu+Zh4Fh3JyHFHrUc+Ezq4LGWjJnBK2JzSvS7H4HMF8RUTZUi6ucWpcYRWUf
         c875FkkUvPJsqlw5BRpnaCXx8zJtyRON0gAxojQc3P5mYH3YJnqOLBCYHluSUNPt+rPZ
         jRDUTH8o1EbbnB4QAoa9TW9q3Xqzul1Qv1AvVdO/rTMu3u+Fv4X9jQUZzQAP/APhJMX3
         rP+QGZvCRityd6kJlB+m4Gdfe5UjVEE6HMuIPfg4ur1JpAMqLXM4WKp6cwhk6CtUIIdt
         mAyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=eXzWlmA6LYQSqE/Xxud2i7/cj4s64lCL3ys0/Mi+9Q0=;
        fh=Pqqd1z/cjdJM1SmSiMXEXWPSkw78/lXEphfDIC/mS/A=;
        b=X5BRo84io+D7cy99Np+x7aeNkXAg6n13lYcCNDRFt6hJzPKRSaEyBCq2qhkyfXkuTd
         cypg6w4IKVzkREEXWJ31UZisurhM5auP0bW4DN2BiSoqyHHFVpUu22TAMwAVrEieXr//
         xywEtVZV8MQyrNT8WkbCM2W+8Oqomcl2ynw4DpgdjUptyGXJDerjLwJghLdXENmUEhRZ
         AN9CHWbOw0QdDhMCiMJ0aluzu7KqTqlon9+1FWYwggqo4RWRqNcJAUYtGCbHZVT6xahD
         AwxnXmj2opxTQ4K5xnIduj25nMR/wGoGbDoc9Ffx5alSZ9aYRB1RTtwINho2E3RpphbT
         L9Qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gDZDpVuf;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755810991; x=1756415791; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eXzWlmA6LYQSqE/Xxud2i7/cj4s64lCL3ys0/Mi+9Q0=;
        b=noYQ3blYzTUPwrOXVVKwl+zW93JRET4/0UxU9HdC22tM/XHx3Km8Utu14utRzaV89R
         Bq47grLC0eIXshuJCJqx35MAPXg+oeCjVv5bNrXkMBGk8KmqCs2O6MVnSRkigxQyenpN
         j1tNYbfTpdd6Ti9RhpcV++qnIWnWjHe8fh4dXfbUupTKs/Wgesw2jgxMn5fZm0zY6DBH
         TS63g8q/p0e0PbpTQaQSgbpn1wiCk8/jXrJmpAPgFhxqo76UzisDKSJvAHcwF94NoyB/
         TOaY54vssJ8yWt2KyXLxVTYCXrcVedSJJgt5Ul68VWCA15B7J+WDxfWJ4XfM6pLl2IJj
         RvHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755810991; x=1756415791;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eXzWlmA6LYQSqE/Xxud2i7/cj4s64lCL3ys0/Mi+9Q0=;
        b=ii/wGb1WK4Gq9DefoB6Ld7kvEn3jTMhJRdRMkTu3+f1Tg6deBmkHosUbXD3fmDGPmA
         016SP0xyHBXLaRNoZWdh7liL786Ki40bfSqj5/4tNle4w5LqahQ3T3O3TtNNWAKWmkgS
         UWUFBXldcG6/Yg6sCrXDFTrxMhmGB/XlAq7Hj/+foeMdFtOIlO+VDs8FNVFpq7xAfWCA
         XsucwCRbFJogZUw5eEEgZ/RsP/Ws6eh7VbL78++N3dKiyiQr7D4d5rqxk3UmZhZ8s4Bf
         6rk9hGk1V7fPmodh97PQlzeJK5EK1K7PVDjq+stwhc9BdkYdrRbMCivLqjlyM8m6dkzM
         LENQ==
X-Forwarded-Encrypted: i=2; AJvYcCUv3WfW+sxhXFpT0m+Q3UhAgTIkOu4hBlaXAI2lDpwLJ6fez9Mlik/K9KwWNCuT+rOe4X02eg==@lfdr.de
X-Gm-Message-State: AOJu0YyDZLO4jwBMwZ1uR5f/8PMQ03E7iiAqq3r1huo+cfCQB4Qr7d92
	05Vsbr8GcQkSL4s0RtSbfpdCDmZb5dNbLMGhIO7Q2PpN/lE4x1W4JYt5
X-Google-Smtp-Source: AGHT+IFCsDYp53xBhJ78IqdeZgzWhMFFJKH+wndwZRn8lgvc/dkvml914ypX01399qEndHBG4jaT3w==
X-Received: by 2002:a05:6a00:3c93:b0:73f:f816:dd78 with SMTP id d2e1a72fcca58-7702faac256mr975907b3a.15.1755810990968;
        Thu, 21 Aug 2025 14:16:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeCGkoqGRYDnNuC3wdgGRVo4H6BkNMS/BmyZlTJA3AkFA==
Received: by 2002:aa7:88d1:0:b0:742:8b2f:6e98 with SMTP id d2e1a72fcca58-76ea0146c78ls1478900b3a.0.-pod-prod-08-us;
 Thu, 21 Aug 2025 14:16:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2xEhc/6JWFtpldKyXx8kZuVfNxbDFys984Vh0tWpHYIlmmst7aKpGgXzA766jBQUMweNeQfHdc3o=@googlegroups.com
X-Received: by 2002:a05:6a00:22d0:b0:76e:885a:c3e7 with SMTP id d2e1a72fcca58-7702fad503emr916601b3a.27.1755810989674;
        Thu, 21 Aug 2025 14:16:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755810989; cv=none;
        d=google.com; s=arc-20240605;
        b=DXE0XPjLkjE8cI7HbTZEqI2UD2uUIckHxn70HtMOcwTGlwHJev08Cz6yyIrZllGCcZ
         QGPNDw3NCaoVUb00rM3IMCFsx8txwiWdTYyyZKM8dyif6pS9/bDygd2gvhOVMkBeVdhX
         CwnNSC8jcRAbJYSwWLWr5yOTVAJhinOnyuQIuZryUT/tPabx7mdGTFUHO+fFzZ97xqLx
         E3yP9wwCNR/tE+JCjvGqNF0pB646Fx6P5Zmmq9tLs2H3iGtD+SqVjC/LQ2G7dfMfYn1/
         AG0Wz5sEBNRlPuv3QfzCkmARQWbnOFLe8cvihLVBoeJq25UVMQPfxBS8xOBdcIAqs/NQ
         OlGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=DD8AyvJImHHPwC116vdWYY4WW98XKAOpYlu9DIKuPeY=;
        fh=C0KO1u3Mw1xn5utCA5wELzFydrHJYA2tAFnVGemEfBI=;
        b=PeE7/Cgd/R8JFCEuLZ15PZkCPJe2x85jNDAzLWNtT2XEsObTeb1/ASn5tNlp1h4nT6
         77t8M9Wb+tATAQKHIFQpABTPmSpjIrc3LToL5B9YxDB0gF03zf86EZxlEJEEZmMcjvCU
         v3Vv1a24Q3NqHGswqpwYd+I8wwqU66juJeEkFssIxj6MV/CgUF+mXvFGcbPaHm6wU47d
         peWsPKOPZrxZCn0vUsD73gqHCNAS5ejdlfqCc6Ekqmvpzm6TNtVzo+Q6OBmwbx8t87Ev
         Hy/N1/32zp8vgUutYzgwzx3YjngB1YLvUjgcqf1AQdvI+3FqhMMmTFK3jCJ3+COJ3u36
         VS4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gDZDpVuf;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e7d1dcf8bsi446602b3a.3.2025.08.21.14.16.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 14:16:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id B8EF96023D;
	Thu, 21 Aug 2025 21:16:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2A358C4CEEB;
	Thu, 21 Aug 2025 21:16:25 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Aug 2025 14:15:49 -0700
Subject: [PATCH v2 12/12] KMSAN: Remove tautological checks
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250821-bump-min-llvm-ver-15-v2-12-635f3294e5f0@kernel.org>
References: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
In-Reply-To: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 llvm@lists.linux.dev, patches@lists.linux.dev, 
 Marco Elver <elver@google.com>, Nathan Chancellor <nathan@kernel.org>, 
 kasan-dev@googlegroups.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=1830; i=nathan@kernel.org;
 h=from:subject:message-id; bh=/FaxCgWn3QZynXYwl6BT/KtUuhJScaSVbC/LfUVi4W0=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBnLe1pcPUNm9W6MDuLs/myrJcfNFJTLWv9E/6ZRWI+r5
 4pje5w7SlkYxLgYZMUUWaofqx43NJxzlvHGqUkwc1iZQIYwcHEKwER0OBj+157XEo/zEZQ9YZU8
 z15PkJ858EdhvfS/qz6rSs+b7NykzfDfXe6x0fb3Xy5P/1MXV231eo2pntlbyVJlX8s71sbm1gb
 sAA==
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gDZDpVuf;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

Now that the minimum supported version of LLVM for building the kernel
has been bumped to 15.0.0, two KMSAN checks can be cleaned up.

CONFIG_HAVE_KMSAN_COMPILER will always be true when using clang so
remove the cc-option test and use a simple check for CONFIG_CC_IS_CLANG.

CONFIG_HAVE_KMSAN_PARAM_RETVAL will always be true so it can be removed
outright.

Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Kees Cook <kees@kernel.org>
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
Cc: kasan-dev@googlegroups.com
---
 lib/Kconfig.kmsan | 11 +----------
 1 file changed, 1 insertion(+), 10 deletions(-)

diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
index 0541d7b079cc..7251b6b59e69 100644
--- a/lib/Kconfig.kmsan
+++ b/lib/Kconfig.kmsan
@@ -3,10 +3,7 @@ config HAVE_ARCH_KMSAN
 	bool
 
 config HAVE_KMSAN_COMPILER
-	# Clang versions <14.0.0 also support -fsanitize=kernel-memory, but not
-	# all the features necessary to build the kernel with KMSAN.
-	depends on CC_IS_CLANG && CLANG_VERSION >= 140000
-	def_bool $(cc-option,-fsanitize=kernel-memory -mllvm -msan-disable-checks=1)
+	def_bool CC_IS_CLANG
 
 config KMSAN
 	bool "KMSAN: detector of uninitialized values use"
@@ -28,15 +25,9 @@ config KMSAN
 
 if KMSAN
 
-config HAVE_KMSAN_PARAM_RETVAL
-	# -fsanitize-memory-param-retval is supported only by Clang >= 14.
-	depends on HAVE_KMSAN_COMPILER
-	def_bool $(cc-option,-fsanitize=kernel-memory -fsanitize-memory-param-retval)
-
 config KMSAN_CHECK_PARAM_RETVAL
 	bool "Check for uninitialized values passed to and returned from functions"
 	default y
-	depends on HAVE_KMSAN_PARAM_RETVAL
 	help
 	  If the compiler supports -fsanitize-memory-param-retval, KMSAN will
 	  eagerly check every function parameter passed by value and every

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821-bump-min-llvm-ver-15-v2-12-635f3294e5f0%40kernel.org.
