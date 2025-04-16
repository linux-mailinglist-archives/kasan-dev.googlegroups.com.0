Return-Path: <kasan-dev+bncBCVLV266TMPBBZXC767QMGQEEKARCMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id D0B97A90ACD
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 20:05:27 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-39c184b20a2sf3434621f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 11:05:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744826727; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ex5kAOom4w8Bjd7EV7J4V3Km8xBxMfmpKe+QbHIpZUmcWJLgmT2JP0JnRHFnypnf7x
         zRrgd4bJEf7Z6b4D3wS3ec7IlkTMqEWOeQYP4PALR2uhvoBN9bPw7L+RpWZLBWEvHBD7
         KLFC7ogFdoCBgDWXcfwRbBAavEYUNkKICD6WsyD3jwh3iu81aDCD0o+d4PhlUXd8Eob/
         4d3GWHrgNvpo7D2Y+ipgt5eI4LAWWOWLhcAGrgea971fKHTAql0pyJMsrcLOTGW47GAU
         ENmmKF67USxxtZz7EG3C05Z0efszTM+ej3Vk2j7hiuw85dSbWbxNHeibU1oh0h6zB9+4
         zq5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=oTBrovDW1KfZnNppa8U2waTzSAQmNuKyaAZRMIKsw1g=;
        fh=DhdKXA5cOXiHqfuZqog7tj2AVNPiCKzPULnhxM24WHM=;
        b=IitPE2qHQk1gcZNwvZTE6oPnHptMpWXNpzLjO3HCznLDPVR9YGcCZwDCKiG+FVQ+Q3
         80fYXsVaykEHXRADkKWIeaATqIgqghevJMOJSVtHuTmLrU1SxLIfAdGgcJ0X2rYgF21F
         KR7Vp1O3iBEPSGt01Lj7iDi9HRun+LJPG0cAXhquROL7+H3p+oAi1fmW8PfP7QYzD55C
         ZSqMPBlru9n0Dj1B96ajdmiEXVEKe/zZgkMYlSBIR3vcTLzSDkzHWY0iK78ecww+e4cD
         jGm23QfmLxJNuurHjmAdwFQZM/g/vYvp0iXPBicrW9U8DOiQoqCJhRkHFqhTra9LiLqX
         /DZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KPWfLwCF;
       spf=pass (google.com: domain of 3yfh_zwgkcyo60267otou22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3YfH_ZwgKCYo60267otou22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744826727; x=1745431527; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oTBrovDW1KfZnNppa8U2waTzSAQmNuKyaAZRMIKsw1g=;
        b=Z6xegWSn+/J0Jg3Bbm14Y2lEAljUFp+BUcjv7KNtJEtst+Vmj8AaO4F3jut3IXesz9
         Fo82AK7iUfsE5n7KN6I2NjGoDJSwHmH9/3Fhk4/75PwZB/ipoKFjLl35QMpXGtWDEGOT
         dTkPDE5+cicvc6OhJgUYA3qRqRjl3fgpQg2G9pweDBxTxwCFy6or7inIw6ifj2Upaj1b
         k2Pu/CwmfXNk6apwYwtCvwUSFwOg7XEWkEltT0dCToLpQOCN/hf4tFGJpdlLyxDl2vG2
         vaHDSQ+3r0vBHs0pQuNMUrocracJKSgo3TF27xAtL2p3FcknpqzrcHj23ZCL2ejvvS5J
         Wt0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744826727; x=1745431527;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oTBrovDW1KfZnNppa8U2waTzSAQmNuKyaAZRMIKsw1g=;
        b=YaAYYRGVZi/u6WLOZB/mD8y2sEXegImx5472jbwU+ntAhmFJgZy4z+uA+PPlGuNReI
         OkVDPuQy7k9HPn4Re02Zow84SrplI+0cSOmqUocwczNyoGQaXXfJ2W+HW1erkcaUm008
         5CbEWnYYCxfSoBmGKYDKnI3Yqy8vBJy/fCoo9zH2PfyrGT6OqoxxTsvR96LQfBNP/HFy
         Q/JThxV8+TCCSamzTH5+qOSlhht+Ugpv6dV+rPlIiHoHIuoUDTUA4B4dJxLnGG9F0cv8
         xlvSDpQhd5Z1E89sHzwKFXFbUxNQ60p7StztXwq9ow1tSxUS33T5Hi0dQlTUKutzpPl1
         caYQ==
X-Forwarded-Encrypted: i=2; AJvYcCVDheUWu7eCCWA4Fg8+E0FlBiuOJ1QL7h2l0CDCVQMhNRaA9Iw+8PLu83a1Uk2Ehb+upg75nQ==@lfdr.de
X-Gm-Message-State: AOJu0YwI6xLflP3RrlcnustFa4wS2AHhyU9fRcTxi+DtYznTJ1Xfn9YP
	dYAxB98YjMKOEMjCxtpwOOoSQ6hVJs8TothETPl2VeE7D+hKJp2b
X-Google-Smtp-Source: AGHT+IG1bsQjiK+NlMb+BDaKHOz5zxlglxFEZZ296wKZclDMuIk2F33WZCd+VXohqUXo7p/FRDT3jQ==
X-Received: by 2002:a5d:6e52:0:b0:39a:c9d9:877b with SMTP id ffacd0b85a97d-39ee5b323bbmr2366978f8f.27.1744826726836;
        Wed, 16 Apr 2025 11:05:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALqRFYhpqQzD24fSGhxr1s5el7lH1o44fjivjfCmXsPHg==
Received: by 2002:a05:600c:3593:b0:43c:ed54:13bf with SMTP id
 5b1f17b1804b1-440623ebfb7ls648555e9.2.-pod-prod-06-eu; Wed, 16 Apr 2025
 11:05:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzYYN6WReYbYkpsj2TXRLxUzgzplwM5VrVAC2jVD2f1xn3tGSA4c0B0RI9+izyFpyHIIiazo9neOQ=@googlegroups.com
X-Received: by 2002:a05:600d:1:b0:43b:d0fe:b8ac with SMTP id 5b1f17b1804b1-4405fbffccbmr21467115e9.30.1744826722066;
        Wed, 16 Apr 2025 11:05:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744826722; cv=none;
        d=google.com; s=arc-20240605;
        b=daez0PAsuJas+q6u5LNznOSI83HKfGMeCFiMWRmDmlbeagTB2DZ01xY+SvmbIF6mXV
         t+U8CybudpCwPSNZnYW2IoYZInC0brDW9tGbu+QZQou7JNvEx0WYqfl00IZE/p5pGglT
         Q2SbZfyw1rXMn5PrMK8M7qaXxtTFOll+QihhiWHrqN29WQ1ri/MWxuC1DSPDA3II4+2a
         +G9fqabI6cJROLncLKCgVXHQWo+eFcTEeFGfdznD3bEps45denXJHz2red9VDxkwxhKu
         K52SV95cxkwmSKDUTEK00kEEjDwn4Jw+w08iK/DluoBZUSpw0ry4NO6MfNpFtz4A0zPH
         RmvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=EWRjEDjHgnGUTAO1fUxX0nlQ73sblTBfWxiyoAckCmI=;
        fh=gdqIUlkx81XOpESbFW6kc5eMlYtdwJNlQVAZSRkZCIY=;
        b=CZVJ4AyaLTpoiWTXkZQc1fQs3/pkP0BC+wWEAVM0BvBGz9mTEZD0tPb5UNcImyCGwu
         +ddSosNFbC5++3LNdLz0HP/bZBqfluGonDiVTNns0h4uyJoLk4R227Arm9k0HMq1KlLk
         jPz6rE52WEXQscpA5Jqv8Z1ubJB4/9N345mFa5TxyljI7zPEf1ScLDnY2djehYI5DXVT
         7NvLP6rRDJo8ETd8TYd4yk3hME6wf+7H6hdyXjWVfDHmKU0OIRr7KGzfsXuCaj561ClI
         gr0FHE9HP5d/nXvTp9cY72Z6/6qNWoWkANE1HhKm/nJ3sqTO8dlmigczcq7Is89xUAej
         DCcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KPWfLwCF;
       spf=pass (google.com: domain of 3yfh_zwgkcyo60267otou22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3YfH_ZwgKCYo60267otou22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4405b4c13f3si446015e9.1.2025.04.16.11.05.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 11:05:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yfh_zwgkcyo60267otou22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43ce8f82e66so43872375e9.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 11:05:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVLBhdeUTh6ENDYEwOqNg4Hlge1LkJMPvcUNhbquAfcE4Zw052igfphAJ77TGoFEg6QuqgBFlImyHk=@googlegroups.com
X-Received: from wmbev17.prod.google.com ([2002:a05:600c:8011:b0:43d:4055:98e3])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:3487:b0:43c:f70a:2af0 with SMTP id 5b1f17b1804b1-4405d62a49cmr36178345e9.16.1744826721678;
 Wed, 16 Apr 2025 11:05:21 -0700 (PDT)
Date: Wed, 16 Apr 2025 18:04:32 +0000
In-Reply-To: <20250416180440.231949-1-smostafa@google.com>
Mime-Version: 1.0
References: <20250416180440.231949-1-smostafa@google.com>
X-Mailer: git-send-email 2.49.0.777.g153de2bbd5-goog
Message-ID: <20250416180440.231949-3-smostafa@google.com>
Subject: [PATCH 2/4] ubsan: Remove regs from report_ubsan_failure()
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
 header.i=@google.com header.s=20230601 header.b=KPWfLwCF;       spf=pass
 (google.com: domain of 3yfh_zwgkcyo60267otou22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3YfH_ZwgKCYo60267otou22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--smostafa.bounces.google.com;
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
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416180440.231949-3-smostafa%40google.com.
