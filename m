Return-Path: <kasan-dev+bncBDAOJ6534YNBBF6BSS4QMGQEZ36C67I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 087E29B97C9
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Nov 2024 19:40:25 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4315eaa3189sf18082025e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 11:40:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730486424; cv=pass;
        d=google.com; s=arc-20240605;
        b=cCNMCchfdMneUrKh/1jnpQZMgoIt9HOpoikoCcjI/BykJ6My6zGjCg3Ylc6Vf2gKki
         uKiVnbGMBwFH14U9wvG+bOB0edX98e+Yb2xhQuRrlV/6/cxlPbCP2YsXKrSjaTN4DdOx
         eJqsi1YVDYgxwgsGgXBTKqRRRz3eBOHzCdgt3IMSt2Jmq7XlBtAlGm1jChLGvA/H1JFV
         NzplN7BkSZzmL1NketmiHjE+4+9aSxlpk/5IkdJxOim4yavLNcwMR1vNmVn7Tos/4siO
         fclv44LPslWe01C1ri86rbufXPCzjmrm59/9RUu3oM72/ceF2aSftdBPn32zV4sl6+/h
         MZ8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=tkU9xJyPMprP+iHK1Y1MjZkKxSa9NmehzR5xdPzqeBg=;
        fh=ETofHAt1c82Tm/bQTC0Jjxwa9OlgNhizZbZ7hf1Sk0U=;
        b=PORk3VASHVQSiZnGZ0lY7shjHKb6TGFwPPDoQTtCIgumAaJwCQx5LEgTDLsleNPF2r
         QR2xDMcBjic11oOqjCQV1GJwxBg1enfi5Nyjt5dMNHrIjv2BOmCGPiV0voMd34CmBfGJ
         J0/ZFiC9suZ2bIgliCCZVWWp+QZELEn7OzSTukCaz0MqtGZQWBBUgOKP5a1Ap2mzGKVD
         UcoYSM5tvo6DqYocU3ci2XTvsZn8BqwOdEf5DqBvu7Ook9hkMDXWryCUEAl2RR2nOBj6
         mQno1NTGe852BuA+5fPRPG+yuq7jmL/k2T1eb0Rs2dozPffHRxdsCr9jZHgh7dCytD1Y
         RiKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=corkC5Az;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730486424; x=1731091224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tkU9xJyPMprP+iHK1Y1MjZkKxSa9NmehzR5xdPzqeBg=;
        b=XL4HXtHw660zS2M7SghRPA9xlV1i5U8PAlkkHSiDbQ31G7hq8LM8h+Yy8KVfFxouNe
         tiTYu7x9JWFhzPJ6ekGIm36uc63UdUPa3UlFncUmV1RhtcSRR9RfIzN1p9zubEzC3bLd
         ULBkA2ake7TIrYa3VhXq+4bPWV4D6D8v5jE2fj+enlMlxw+t/LStWRRMJnWgXURvhGtP
         5cEbhVlfcDDd0ATm/PCb6QWECb1Baj+UJf7YRi8JxhFT4S3G/gl0DZONg0JKaa4547Fj
         Ad3Fb2oX3unc/B9kSSpiPO2MEMbEL09EQSOE9CpQiPxSKzDt7OMQA/TWkheu5+1XmZj1
         s+Yw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730486424; x=1731091224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=tkU9xJyPMprP+iHK1Y1MjZkKxSa9NmehzR5xdPzqeBg=;
        b=QdZYzgchp78AqT6iRXX+wTbYVbgFJ72GcYcAxFp7I3hJBl22r20RRTtC2vnpPEsdce
         MkrlzYedH+5MHs6pgG1MNtVz1a7EG18ixftPjOjHe26al48TNSp4PPqEVmtASBWW/GJ/
         8/8BHXwrXfcQkAUDIXZUB18mvh2eq+fVJOICk8KAYzTtrOtcD+fkt17g5MQEK4Z3qGDJ
         Eps0dbKiV83NRODIXkDzc7ESxyQLZ+YEc/sGc4Sgar5FKqrSInL/DGGSOw0BgkXIj49o
         UF6gIkhtmGW5XIZeW3BmJHl/pELUYIh6uYlQ5YqcGLzg8hNkX+B/Tj/j/ejc87vUgKPx
         GoHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730486424; x=1731091224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tkU9xJyPMprP+iHK1Y1MjZkKxSa9NmehzR5xdPzqeBg=;
        b=nnybBuzdwddQx6yyTFumnkmFpdMtc0m8Cf1lx3JOzGeZFgH+XGW1wq4Giufx3w8UdJ
         sej64dp+vtGAPC+VQjRAK4uiLPHi06kEQGMLAVYaopHvmALt3RjniGBKwzYBQBVCdAUt
         QNEEQ9tQtobtt+BFoP7fDC1qoW9GFETrOYsoqu9g2Trq2RD77GONc+5KYmLlTrgmao84
         qZLIkWt+9Tt+mXFPnklmOVFN9akBca6IobbCyKaYnT8ptBFM4RllPVuxCj2BRYihfLrk
         jg/oSHZLkEAtVkCIL4ZPEXxV7mMKHXVJPcT+G/SVhFUvX7QXgfWeG9OMx6JlBfzS/D1k
         7Row==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVBRJ5qGuiB173+9A8QJ8phxOXG8d7cG4zMyKZ2SkvgFTRXuZsdrYKSZy1qDUhcaSW8UMHTzA==@lfdr.de
X-Gm-Message-State: AOJu0YztknOHnq/DVV8lYW1WNJ0e5eZ7KHd7eEwPJRDtXuYmyvksh9aA
	Lb2bVd+kfLtWqIzvfARmcRBB1BB9rMi/9QmN4WnIjG93cF+Io4NI
X-Google-Smtp-Source: AGHT+IHzvzYhUj1Iwg/qCsy6G+iIH8OiCfwIjz2rlvnZbBaco7iuSF5+p7oauwLoU2ok2LW6iiAAlQ==
X-Received: by 2002:a5d:5888:0:b0:37d:49be:9581 with SMTP id ffacd0b85a97d-381c7ac42eamr4793130f8f.37.1730486423826;
        Fri, 01 Nov 2024 11:40:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:facf:0:b0:368:31b2:9e96 with SMTP id ffacd0b85a97d-381bea1b2dals616379f8f.1.-pod-prod-05-eu;
 Fri, 01 Nov 2024 11:40:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMDBdEkBLZRQkVeYDmaA+iQXN+0anXneA4nAvwcstGYfetVdh7aaUwz8AgUkvaa6Dj39W1oWVpS+g=@googlegroups.com
X-Received: by 2002:a05:600c:444d:b0:42f:75e0:780e with SMTP id 5b1f17b1804b1-4328324ad00mr41282355e9.10.1730486421647;
        Fri, 01 Nov 2024 11:40:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730486421; cv=none;
        d=google.com; s=arc-20240605;
        b=cuGEnbA8pPFz7YNF2ZtVatwfI0GskdazpuWkDSoKYyHYNlrxYk6NW/iKUCDwVGj2ZH
         XyMRpE4/UFxFaW0v4pQrM1c/S0HeRvhM44aIrOQ8jDpNLMa0fnBJBgKIFNcqppE/GItA
         Xuajz79XTYom/d2CjIsdCMAujiUrIyFoWpIUHWdR+KRce0DwqYT4ce0TYxF+7U0fpciF
         DfM5FARgSIiVsZnqe8KeOYXWv+PFDQjfnGG59FFHR437pkUGZ1Q4fe3/wkq89KmhSsk9
         sneP1pVJaWhNBlCQs7FNNRlErFqlYDRJyxCurrmgfb7dWtO0uEvY526VLTbRN3TpIf6e
         aklA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=325HZLula7jSoNoGXlC+vhYpf/xwBEOPgui+U1ZAOR4=;
        fh=qNfxXF+tRx+1lHeLGIFdvS8z+2ivBg5XieCobTzd5mU=;
        b=PZ0oo2zHVPT2H9gtaRQPNmRx9q6WiLpqot0UefeUR1qvf5DIMwE0usYJ4PAeEWBAeP
         obCPivmuqiAIa2K9LnjI4HzMKs6M4lM3jSVGL9dPGEtOlbJdWIXHD0JlvCdr6ekQHKGP
         xxFHZZMnTDw/UBri3IdyD6Jx94hDw2P98Y8nw8Fzy+YGVSjZZE8SqRsQC8zhHryFdhGc
         d8WPb8EW2EyLZ30rc7rZ+OeAt4er7I5uCsbdDLbgfaHN7AJPKw16htXxFfRn9VQftEQv
         L8v/0JlCw2DEAG3vrdPJp+ExDWf6bEDH0RmmrW+E2TN2iNQTcnFAZMAqNA0qzL0MvNvv
         8hUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=corkC5Az;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431bb793c58si5923175e9.1.2024.11.01.11.40.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Nov 2024 11:40:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-539fb49c64aso3332014e87.0
        for <kasan-dev@googlegroups.com>; Fri, 01 Nov 2024 11:40:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUm98sYrrXMC05FZol3VlWgL2IIkYQW7lsFfvdmgfbFeofXIhAcJTMr1vyZPT1LUs2UoKwObKoMelE=@googlegroups.com
X-Received: by 2002:a05:6512:3a8b:b0:539:89a8:600f with SMTP id 2adb3069b0e04-53d65de5298mr4080862e87.23.1730486420555;
        Fri, 01 Nov 2024 11:40:20 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-53c7bc957cbsm646821e87.60.2024.11.01.11.40.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 11:40:19 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	elver@google.com
Cc: arnd@kernel.org,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	snovitoll@gmail.com
Subject: [PATCH 1/2] kasan: use EXPORT_SYMBOL_IF_KUNIT to export symbols
Date: Fri,  1 Nov 2024 23:40:10 +0500
Message-Id: <20241101184011.3369247-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241101184011.3369247-1-snovitoll@gmail.com>
References: <20241101184011.3369247-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=corkC5Az;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Replace EXPORT_SYMBOL_GPL with EXPORT_SYMBOL_IF_KUNIT to mark the
symbols as visible only if CONFIG_KUNIT is enabled.

KASAN Kunit test should import the namespace EXPORTED_FOR_KUNIT_TESTING
to use these marked symbols.

Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 mm/kasan/hw_tags.c      |  7 ++++---
 mm/kasan/kasan_test_c.c |  2 ++
 mm/kasan/report.c       | 17 +++++++++--------
 3 files changed, 15 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 9958ebc15d38..ccd66c7a4081 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -8,6 +8,7 @@
 
 #define pr_fmt(fmt) "kasan: " fmt
 
+#include <kunit/visibility.h>
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
@@ -394,12 +395,12 @@ void kasan_enable_hw_tags(void)
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
-EXPORT_SYMBOL_GPL(kasan_enable_hw_tags);
+EXPORT_SYMBOL_IF_KUNIT(kasan_enable_hw_tags);
 
-void kasan_force_async_fault(void)
+VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
 {
 	hw_force_async_tag_fault();
 }
-EXPORT_SYMBOL_GPL(kasan_force_async_fault);
+EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
 
 #endif
diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..3e495c09342e 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -33,6 +33,8 @@
 
 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
 
+MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
+
 static bool multishot;
 
 /* Fields set based on lines observed in the console. */
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b48c768acc84..e5bc4e3ee198 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -10,6 +10,7 @@
  */
 
 #include <kunit/test.h>
+#include <kunit/visibility.h>
 #include <linux/bitops.h>
 #include <linux/ftrace.h>
 #include <linux/init.h>
@@ -134,18 +135,18 @@ static bool report_enabled(void)
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST) || IS_ENABLED(CONFIG_KASAN_MODULE_TEST)
 
-bool kasan_save_enable_multi_shot(void)
+VISIBLE_IF_KUNIT bool kasan_save_enable_multi_shot(void)
 {
 	return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
 }
-EXPORT_SYMBOL_GPL(kasan_save_enable_multi_shot);
+EXPORT_SYMBOL_IF_KUNIT(kasan_save_enable_multi_shot);
 
-void kasan_restore_multi_shot(bool enabled)
+VISIBLE_IF_KUNIT void kasan_restore_multi_shot(bool enabled)
 {
 	if (!enabled)
 		clear_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
 }
-EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
+EXPORT_SYMBOL_IF_KUNIT(kasan_restore_multi_shot);
 
 #endif
 
@@ -157,17 +158,17 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
  */
 static bool kasan_kunit_executing;
 
-void kasan_kunit_test_suite_start(void)
+VISIBLE_IF_KUNIT void kasan_kunit_test_suite_start(void)
 {
 	WRITE_ONCE(kasan_kunit_executing, true);
 }
-EXPORT_SYMBOL_GPL(kasan_kunit_test_suite_start);
+EXPORT_SYMBOL_IF_KUNIT(kasan_kunit_test_suite_start);
 
-void kasan_kunit_test_suite_end(void)
+VISIBLE_IF_KUNIT void kasan_kunit_test_suite_end(void)
 {
 	WRITE_ONCE(kasan_kunit_executing, false);
 }
-EXPORT_SYMBOL_GPL(kasan_kunit_test_suite_end);
+EXPORT_SYMBOL_IF_KUNIT(kasan_kunit_test_suite_end);
 
 static bool kasan_kunit_test_suite_executing(void)
 {
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241101184011.3369247-2-snovitoll%40gmail.com.
