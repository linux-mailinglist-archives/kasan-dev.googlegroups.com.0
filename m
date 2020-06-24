Return-Path: <kasan-dev+bncBAABB36GZ33QKGQEZM4WH5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 236A7207BEF
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 21:03:12 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id q134sf719968vke.9
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 12:03:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593025391; cv=pass;
        d=google.com; s=arc-20160816;
        b=hghehJoQsS1FizUJNhbuWA2wRTE+zhjyn0/fd5iAMxFAvhMA6dQs8xx63OWZd3fPtP
         WSyHiJTlf/t1uk1BUnMwFyvwLbHZTxfjfI+ea1G7If70u0XB+BmAzA2+fJUj53qMxwC6
         ufhan0DfSsA8qMboEqWsyqMI0l0oCt/73VkE/tH0UueoXnYkqX81ll/RNn+8h+CZP7sn
         2FAEaK3Z6of8j6QkDNHVbmU22jIcmNlQMLaNuD9agL1mMr6e7Xl0c49bXU534LTsqQoI
         /5sxPWGk8NPX6EwM3FX5YK9CkvM7ICm7CXNXpG+alW3nFFbgNJ9vK2XQY/DdsdrtazdM
         zfdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=UhcqJpIkSnAzUgjyKrRFEx8Ow5W+gxd6xfiKx/FGUQw=;
        b=VBnhrMBNgkAuu30X/v3Omm6KtK6JStxZX5qvLyTs7n563R1zc0bEqBlHKRCZwGVZBI
         cf501J7f5ndfWk4/NoPOVqOYTrL2jMHX9oxWBMWA5ja4noyH9eT688J0makfIMXyaHZw
         vAz2eSyZczaMdEb7jXzXMf2DHHK8J4L9oiSeZN46LGpUYDz5MTa7ftQUTe1kOlWYOst4
         gsvzRMuBNfTS/9+7iSlw1KQmDUZ54q5vcc76OxQ9q9UzelG9ZzeepVf8T4R7hXGhybEZ
         YMgQ/wE3smKrJvhEoWi13ijPDiN0qsvrhjhHNXtPNAixSzGM75L90ZLU22iwV1rH64SN
         yzfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Cy5H4ScO;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UhcqJpIkSnAzUgjyKrRFEx8Ow5W+gxd6xfiKx/FGUQw=;
        b=IjqxUElmuUyKHeF8B5zxwIItDj8kmRkMiSy7BP2jNWCUzH5r4ooj0My2PLrHWwKFU8
         KiALOf3ltv9KxoSQ+fXP+iANqOrsbH9/6SkJJfKkP3aLZZEOeOw6LejzqRFKk4MlMdAE
         27skpN94fJePNs70RmS+HtIdTF7y1NDTU37HsRTcViELiYKTqka6+bRuGnDUERWRFVWQ
         nVwK5cbWLWbHB/191EmyvCoXrxL8G/5A9U//MNr8A6z/ob5DV7Gf71T8bhxR7mG3JNch
         Lmsp2gT6vaxnQJl/IqO/4WQfytICtwZr0EdE9z7UPDtNtOPMf4H46RTJ9/zWT9BqYFur
         pkyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UhcqJpIkSnAzUgjyKrRFEx8Ow5W+gxd6xfiKx/FGUQw=;
        b=kNx8F7cSOPWXm0LRGo+8NchWVzVIDOx9UAW2uP9KAdNkwhl1v1uHcaO4EIvwBgNT7D
         g/Hg4U+jlyp2DNfa+6TmeZhPCF3v97foccMMF7AxhG0McRWpwerNTxg8puMxkfqbTDGl
         TJPeCHO+EQbHSc5ZlFOKty0myBZt+NeBL56VprS7Ba/Q0G8Y0URigsV/ntBP+1bZsyfw
         dq5l9HyaXQtsnuVJXY7FYxPbpfXORY0Mz6AOBO6nXyu2qWa+YROo3JuS/dqTyOEjHnPi
         ybF0fyZOXVnTQF8jonaIAdOW/JiN7NweYpEhvv+vAjXMqwPt+kDTiCBgbGW6ogwg5zoN
         lB/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cZDd6EVl9LFDseyQAh/EHyVc8s5rjTegTec4TI3ONW/MqhKNv
	9Q5qqO4SJmTHVJ2IyMM6Rmg=
X-Google-Smtp-Source: ABdhPJx8ZD3+1t/5UsSchwnpqxBaUtzPycGqRyDR6VjPkSPbCzDVEmiTt7WqYcSoNbsY9MemMi9tqw==
X-Received: by 2002:a05:6102:1263:: with SMTP id q3mr9759444vsg.156.1593025391220;
        Wed, 24 Jun 2020 12:03:11 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:b6cf:: with SMTP id g198ls158953vkf.5.gmail; Wed, 24 Jun
 2020 12:03:10 -0700 (PDT)
X-Received: by 2002:a1f:2302:: with SMTP id j2mr25082082vkj.64.1593025390767;
        Wed, 24 Jun 2020 12:03:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593025390; cv=none;
        d=google.com; s=arc-20160816;
        b=MLgVIPtwMZuxRi3El5J7POHmVsqfeVOpYrY2quAC1u33yk1xKZzxt54t4Ho9ADp1nf
         FFV0pgc0M3rZa+4GxcwKZm0EHUHm4WqW6V00Om3dMxJx9vWpq8dVik73AXPIJUqQyzLU
         tOK12RCAuo29Xn1OubuTk/NPb0bxKQWvEOtkTsWJeXZP2xX1CdxipIbmOoRgCe5bjx1G
         IFwIt+mSw87Mw1xy3uKFRh8DcUuUsaiBNd2iGjEls41rAIt6U9Nk4i5Kh5Oc/X0lU4oI
         T1PXdE9vp67+PQG6zQZkrlYnpdEe4aOghYvcJQr1848yrxU/OfhjRITfZjdoxqmXlO4h
         Q+2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=hFNrBRvKDlDUQ1+WIffPoMxbZK0XMKvmDDxPMtZURq4=;
        b=eW6FO+08IiQ4FHVWzwxjF5QfaRsl1eu9kd1omSrszbZAe/EAmUCtnu0eMDVC+3dugU
         dl/WlI5tpCFysEQehmhsHKhhsioC73UkmKSfbAXHTVTqJiPNRZbWNOopZBpA7JlVsrwE
         wkxKVD5kF1hbeHuN1ef5K5YPN4iwGSVCzO7wYcu2sLM8e2B9OdaxCS3AKZXCuXZTXSAZ
         vK9BukNgOJoVvP8fGnfQ9VZ1Krk6QJZJNnBsG/RJoR07uDV5gKxDwMPdBGDDE1WCNEXG
         azEDKfyeIdFsqGQCfiuYZv3t7rC4uEQ4h1SyKx7/OlL/8O4OKtY8FIP/XNlaqQ6DZed1
         dy5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Cy5H4ScO;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y7si38291vko.5.2020.06.24.12.03.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 12:03:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A26FD2082F;
	Wed, 24 Jun 2020 19:03:09 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Martin Liska <mliska@suse.cz>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 1/3] kcsan: Re-add GCC as a supported compiler
Date: Wed, 24 Jun 2020 12:03:05 -0700
Message-Id: <20200624190307.15191-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200624190236.GA6603@paulmck-ThinkPad-P72>
References: <20200624190236.GA6603@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Cy5H4ScO;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
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

From: Marco Elver <elver@google.com>

GCC version 11 recently implemented all requirements to correctly
support KCSAN:

1. Correct no_sanitize-attribute inlining behaviour:
   https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=4089df8ef4a63126b0774c39b6638845244c20d2

2. --param=tsan-distinguish-volatile
   https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=ab2789ec507a94f1a75a6534bca51c7b39037ce0

3. --param=tsan-instrument-func-entry-exit
   https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=06712fc68dc9843d9af7c7ac10047f49d305ad76

Therefore, we can re-enable GCC for KCSAN, and document the new compiler
requirements.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Martin Liska <mliska@suse.cz>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 Documentation/dev-tools/kcsan.rst | 3 ++-
 lib/Kconfig.kcsan                 | 3 ++-
 scripts/Makefile.kcsan            | 2 +-
 3 files changed, 5 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index ce4bbd9..8fa0dd6 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -8,7 +8,8 @@ approach to detect races. KCSAN's primary purpose is to detect `data races`_.
 Usage
 -----
 
-KCSAN requires Clang version 11 or later.
+KCSAN is supported by both GCC and Clang. With GCC we require version 11 or
+later, and with Clang also require version 11 or later.
 
 To enable KCSAN configure the kernel with::
 
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 3f3b5bc..3d282d5 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -4,7 +4,8 @@ config HAVE_ARCH_KCSAN
 	bool
 
 config HAVE_KCSAN_COMPILER
-	def_bool CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)
+	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)) || \
+		 (CC_IS_GCC && $(cc-option,-fsanitize=thread --param tsan-distinguish-volatile=1))
 	help
 	  For the list of compilers that support KCSAN, please see
 	  <file:Documentation/dev-tools/kcsan.rst>.
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index bd4da1a..dd66206 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -6,7 +6,7 @@ ifdef CONFIG_KCSAN
 ifdef CONFIG_CC_IS_CLANG
 cc-param = -mllvm -$(1)
 else
-cc-param = --param -$(1)
+cc-param = --param $(1)
 endif
 
 # Keep most options here optional, to allow enabling more compilers if absence
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200624190307.15191-1-paulmck%40kernel.org.
