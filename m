Return-Path: <kasan-dev+bncBCVLV266TMPBB4U6ZHAAMGQEFURT6SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ED5DAA51A0
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 18:27:32 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-43e9a3d2977sf54829855e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 09:27:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746030452; cv=pass;
        d=google.com; s=arc-20240605;
        b=L0H2LLsHOkePbWImxvmQgQQCPy1i0eOMakR3FGFG09tka6lhkY98/sXD3ZlSCG72DK
         L059hUJqu7qE7w0tNzj0i+zSf+9utwB0R57cYVQH++ZSKJjpi8XNuT0cd6KntCwmraam
         BK/JhyN2joZYx/pJ9FBT8VbP+QtLaD/BsUNfaDunFRmjPo9ZrMUohqDR5NTk5iQyR3jE
         /zkqPBKfsx9ecqWgRIpHUAgQW0zAbAwmsEvB1hFHA1X3k81H8XEfuMyuWI5YuD955NCw
         H1xNdkopnBZbJHcx3+ckKTme6swAF/K124dvU3qBxGKt5iMA4uYJY+sPC7zwjzLU9g2T
         V3rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=WL1JjUV/TWuoVk8mbal4Sz7ugpdIWzGHfBchlmV0y78=;
        fh=NVKuTLMZ68aPScfo0CyC9HjHLv69uEsXrgVhnxdkEro=;
        b=g4/6FinpLoyIShkdsO51mEBxXGrWMPNmDEmkxPpr1JIEapY2/6/YAhTQ9ZaYjJSvep
         gLt0XxJN98Uc0QinuOn+49H9EfNBmy2d9LyKdha896LO6IQ0B71fRPD9pBnoJpO8fTt1
         WntpW/8QpQeWnHOhV7Uwx7bIjvrHzcXfo4DN2gzGnz5L1YocbzXBHwv9yUGnezZJnL9Y
         Z5dY3TNWg1Zaasf7akH+xjCLJWFRyUIbOYG8kKvH8emEVFW+EUDDuAXeRT6Vnq1Se9DK
         r+VoQH5r6S1U0uWS2/B7S5ERRctnnf0wyK5E7UiEyCvcU9OgO8khrE5p+oUjBuVB4xP8
         dj2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Z/v64tCk";
       spf=pass (google.com: domain of 3ce8saagkcz8rlnrs9e9fnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3cE8SaAgKCZ8RLNRS9E9FNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746030452; x=1746635252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WL1JjUV/TWuoVk8mbal4Sz7ugpdIWzGHfBchlmV0y78=;
        b=hvi6nbbXGbT7/EnkVTfb9lHbpq4zFPwRrnfW+ZpDcTcBweIbF9JnlLzDFHUA4OtJ5x
         BYrP1AtNcx5rG5lnEAlxj46qaQMeCLZlP/AzLWct5ccGy8kAUyN/oj5pEs1BmQbHUTUI
         /ghihTBx0o5z/Z+klAWEO2uqruwrQQacNz9zhw/eiWjRwTrA6itsZJpvzS+Xv5Hy91HH
         U5rgah33oiTIP3UDzuSFtH7iQWV6xiUq7xfe9HHZlOOEWH+9RF1Tphy/1oj+ipKl44up
         ppkRZLWfVD5vYgbZ4MRt7+wdAjPSdbRvoqtoHB7dXaGnh/HToCrfSyFi1uRAJDLr6Flv
         TpMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746030452; x=1746635252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WL1JjUV/TWuoVk8mbal4Sz7ugpdIWzGHfBchlmV0y78=;
        b=mzvu4GFa8pj/YbBfww7HgU0zbeCLWY1yIjONtH7v0vVuP6LgSODpIpcmR6AOU6y5p5
         nawikvYlfj5j5RPONbbnNOLHp1QjhsJqrM2MhtxdyIgbNBtTO/+TsN/WI4bHvweGHPiB
         mVsGY/FdlS7MHEWQPTf9TwOzxOxv89ujxiRy5COlb2vFGy8X82m+hZKTolOzNSmKkbBr
         jNOAU65cVV4DM+byP4mzyBD/6NNqq9+/mUaReMKWzqkASn4I2ytGLUhZ4Q3dRVd8XouL
         aOv2pFsWf/1IuRA5TCOus/It4kCvJMqbs6Z9Frd398lsUFOxd/I3jgEZIB6veuEAtFLZ
         ydiA==
X-Forwarded-Encrypted: i=2; AJvYcCV+3Eqw56VWBs5fXmwqpK6g9Uj29j+YfZWLOuwUdmVJ7x8w18qL+42i0NX1HHtGxPeD9iIb5g==@lfdr.de
X-Gm-Message-State: AOJu0Yx0C1Nam/cxCUQKhrGhJZBuojFO1Zqw+piXHc0GdmQL7QsRSUIo
	ASY4dYAxVTgIYw7yEYaG6i2Bq4eJLQw/AMG5/3OkchBzPos9f3XT
X-Google-Smtp-Source: AGHT+IHFOH/rlgxuMOg2N7rouskWZugVA99hfoX+T1f8/WIQXBQmQPEJOHSSYT6aTBWbLipL1tDyUQ==
X-Received: by 2002:a05:600c:1c82:b0:43d:83a:417d with SMTP id 5b1f17b1804b1-441b1f35e1fmr33822185e9.12.1746030451222;
        Wed, 30 Apr 2025 09:27:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGdlgYwsz/kzIYSSeWYnk6cEeDyTAyQxKyRUV9LlINSxg==
Received: by 2002:a05:600c:1ca3:b0:43d:1776:2ec2 with SMTP id
 5b1f17b1804b1-441b5c97071ls146485e9.2.-pod-prod-09-eu; Wed, 30 Apr 2025
 09:27:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/nmfY0DnG6fZnSA+nbKfqE8+Ztubq06PF0OojgP7WDhaBRBLJXekqa/5FKJXyRgON44gvVXX7a2w=@googlegroups.com
X-Received: by 2002:a05:6000:381:b0:38f:2ddd:a1bb with SMTP id ffacd0b85a97d-3a08f75260cmr3619693f8f.8.1746030448585;
        Wed, 30 Apr 2025 09:27:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746030448; cv=none;
        d=google.com; s=arc-20240605;
        b=GALukx1sDuDSDNaVagrYkvwxwePfpXQCOUxtbI01ta44HhIbdQnBiD6HgqAyl4cTvc
         GLjnrwmb18O/qOWn9LnuodZI1+vKPLhyKiQyvzYcZLCdNXFJpwBKQeyG1THVNj3BwRy1
         G2TVzhVBx9NbAVKZI48agrU3QroCr/IQeK7m7sGEddJ1rXsLa0Oor0PzKXP0ejgPmZo4
         n1TfkdfweLO4R9ZLjTFEHn0iuKvrrYkLzrM60av58QstU22AHeAfR9wiP3uLlAcmnICF
         IggF6dWrd0Oz/rcpUw1moltLp3D3Xhw1biCuI93cJxXE3U3uCQtQy0P0CHZv8huSJrEb
         Rqhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=003i/GX+SMhbEk8JM6zOLdGB+5OhPHak3AuWaDpYHh0=;
        fh=A4qdL7HB6Q6QaoZTcc7oE4V3cwGVNBU/3OmvqA9wblY=;
        b=Rr+Y0Kyw1u6VydzHgjuwJLw7lI5XVAH8/5tAaDR8qnqkf4e0Ieh8uJC+GZmnuW27n3
         INmQu1nv+sdNO37W/H6yJfo3HQVKjRiqW0pchCVYdKrNEeabNObtJLPvy8Qxd2V2XeK/
         Q5s0jgkC8QEqhZC6wzwDR9+5leqtquZ+Fl4HrKtegnalSq+MBpbsywig/+yh/lK6FSdW
         CbuFZf/me/bZhnrvuQKWLeJ1pEnkhn9jY30KS9q1z1PeQUTYnKmtwPRANLe02+4/85uN
         57UfcpvzLDEOa4p50973amX1tpTtY3PRVvvETyuJWSNcMgSGH8LYHkGCe0ji7KArDZy/
         BKLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Z/v64tCk";
       spf=pass (google.com: domain of 3ce8saagkcz8rlnrs9e9fnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3cE8SaAgKCZ8RLNRS9E9FNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a073dea5bfsi416604f8f.3.2025.04.30.09.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 09:27:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ce8saagkcz8rlnrs9e9fnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-39979ad285bso3479338f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 09:27:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFVG5bgUAB2fGz5zpr1XGDXa2bpL+ELwC+j3x2UGt3SZZ+G+swJYMtTErFzayyW5h2EydLLXjgWOM=@googlegroups.com
X-Received: from wryv6.prod.google.com ([2002:a5d:59c6:0:b0:391:4999:778e])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6000:3107:b0:3a0:7af3:843f with SMTP id ffacd0b85a97d-3a08f761185mr3815578f8f.19.1746030448153;
 Wed, 30 Apr 2025 09:27:28 -0700 (PDT)
Date: Wed, 30 Apr 2025 16:27:09 +0000
In-Reply-To: <20250430162713.1997569-1-smostafa@google.com>
Mime-Version: 1.0
References: <20250430162713.1997569-1-smostafa@google.com>
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250430162713.1997569-3-smostafa@google.com>
Subject: [PATCH v2 2/4] ubsan: Remove regs from report_ubsan_failure()
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Cc: will@kernel.org, maz@kernel.org, oliver.upton@linux.dev, 
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, 
	hpa@zytor.com, kees@kernel.org, elver@google.com, andreyknvl@gmail.com, 
	ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, 
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, 
	nathan@kernel.org, nicolas.schier@linux.dev, 
	Mostafa Saleh <smostafa@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Z/v64tCk";       spf=pass
 (google.com: domain of 3ce8saagkcz8rlnrs9e9fnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3cE8SaAgKCZ8RLNRS9E9FNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

report_ubsan_failure() doesn't use argument regs, and soon it will
be called from the hypervisor context were regs are not available.
So, remove the unused argument.

Signed-off-by: Mostafa Saleh <smostafa@google.com>
Acked-by: Kees Cook <kees@kernel.org>
---
 arch/arm64/kernel/traps.c | 2 +-
 arch/x86/kernel/traps.c   | 2 +-
 include/linux/ubsan.h     | 4 ++--
 lib/ubsan.c               | 2 +-
 4 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
index 224f927ac8af..9bfa5c944379 100644
--- a/arch/arm64/kernel/traps.c
+++ b/arch/arm64/kernel/traps.c
@@ -1118,7 +1118,7 @@ static struct break_hook kasan_break_hook = {
 #ifdef CONFIG_UBSAN_TRAP
 static int ubsan_handler(struct pt_regs *regs, unsigned long esr)
 {
-	die(report_ubsan_failure(regs, esr & UBSAN_BRK_MASK), regs, esr);
+	die(report_ubsan_failure(esr & UBSAN_BRK_MASK), regs, esr);
 	return DBG_HOOK_HANDLED;
 }
 
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 9f88b8a78e50..4b5a7a1a8dde 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -351,7 +351,7 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	case BUG_UD1_UBSAN:
 		if (IS_ENABLED(CONFIG_UBSAN_TRAP)) {
 			pr_crit("%s at %pS\n",
-				report_ubsan_failure(regs, ud_imm),
+				report_ubsan_failure(ud_imm),
 				(void *)regs->ip);
 		}
 		break;
diff --git a/include/linux/ubsan.h b/include/linux/ubsan.h
index d8219cbe09ff..c843816f5f68 100644
--- a/include/linux/ubsan.h
+++ b/include/linux/ubsan.h
@@ -3,9 +3,9 @@
 #define _LINUX_UBSAN_H
 
 #ifdef CONFIG_UBSAN_TRAP
-const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type);
+const char *report_ubsan_failure(u32 check_type);
 #else
-static inline const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type)
+static inline const char *report_ubsan_failure(u32 check_type)
 {
 	return NULL;
 }
diff --git a/lib/ubsan.c b/lib/ubsan.c
index cdc1d31c3821..17993727fc96 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -25,7 +25,7 @@
  * The mappings of struct SanitizerKind (the -fsanitize=xxx args) to
  * enum SanitizerHandler (the traps) in Clang is in clang/lib/CodeGen/.
  */
-const char *report_ubsan_failure(struct pt_regs *regs, u32 check_type)
+const char *report_ubsan_failure(u32 check_type)
 {
 	switch (check_type) {
 #ifdef CONFIG_UBSAN_BOUNDS
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250430162713.1997569-3-smostafa%40google.com.
