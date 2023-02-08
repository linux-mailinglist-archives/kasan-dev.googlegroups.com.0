Return-Path: <kasan-dev+bncBCXO5E6EQQFBB6VAR6PQMGQE6DG2Q4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 81E6C68F36A
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 17:40:27 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-16a255a89cbsf6236908fac.16
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 08:40:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675874426; cv=pass;
        d=google.com; s=arc-20160816;
        b=iz/FENyV+SGWhmRiD1awlZdNAYblm+/JxBgvG4Pprlx73635HIrHTwUyQYLRTrbQTQ
         fY1ssnCI75+zqCAIcU5PArgw8Oxj37TL/bvs/p/bLpSy9CdCxWVFyKwJrlEeHMqv9krV
         bGeUbmq1sUESTimRIpX/565ROClpBJwVIWNtXd44AFqjV3xkbSKSeayeBnimGLDFMjZI
         3LgJixP6OsEWGak5a4CWdZBOBZALbm6ZhP8KOg7bkcaNtFnZWTNopCvn+OO7R7NZ2sAL
         fJyicRr8bdeEFyJ3tKsWPnaCybdmTpD9Wp4P9vlBr3ZRsBQheMRLQCskLuDqUnp4PeWw
         UW6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SdwSy9yc8BbaBHT3ca88ydbhJQH67mAn7fWfV1VXZog=;
        b=Ie5Kz7FciegTJt0j2jBOlWLjaZf+f0KJQQgiud5/6+QYg/HkfOc+LwjX0FNJMYicIJ
         MtM3t6X4lu+azqFJvSklJtyd1LLfKOpV6ipXO1qxxC16gQqMT9E60pA395Y5ZL5v1TDe
         zfOtI5qzVk2sIWh9qB9IOunpHwDxDSKU7DiXFeDIWyZdSgKuAGwoBnHMdMcYq1z1V1iz
         58zFt49gj7gPuYz0QKwZh1Ohpzbt9SUkF5lJ1oXWcL7aLkYvXD6X1aP9Dq7gxWB6Rp3P
         vaf1s52cA3FgufEOk6jQEoOyBQ6sP/IECvT5YwxID4xWZNf2T463lzP0DmMF6SQUaapz
         JVMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q1mVQCj5;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SdwSy9yc8BbaBHT3ca88ydbhJQH67mAn7fWfV1VXZog=;
        b=f/DH3hc078nIiBp2+ylX0tVbrGHoEpihvUJDd+0FnlDfkmS+Xh8FJa4RHhnGfV7ST9
         hnLSTGEaai4OD/vQNsm1BcoNMl5fEhnhux+fNeitX/Y0HPk2smfwoUL7ThWqiivxg4hZ
         5WFJOhavGxvM+jerCgJC3vmsPXvt9KDatmnJS4cV8UDxIFEMOYYPkherQeRrSK0MU8Kv
         unFLibvDm6Suf9punG68rHPILwl4k2/QbNLs3sS3upgWAaYaW3SCQ1MurhFflqbR3zVD
         jY1Cnj9yhDN8oKtTzumurb26+aeE9uE3mQtApm7OoAScLYI/QwygsqsO8YLNLgy62rvX
         vDaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SdwSy9yc8BbaBHT3ca88ydbhJQH67mAn7fWfV1VXZog=;
        b=5gl2N9sDp4DPR2LVswY13D6MpfxRI+wO3i9qP6X9tTJ7mK4Cm++DI1IU2/RIJht4kA
         /x2mDt7ptUZrO/YV5Znh+wXFa3ZsFwSEndwbn80deEMvQuY8RQdhaRYjqp0qk3vv7O7c
         NAEPAP/RflyN5n8lpUlVy8eUjH/W2mHUyBT43eX5YYnxTira7fpH1hI6u2UpTUWQZraf
         00i6qEFbdDJrwZ48zAIa9f5euw31/gMqDyvmR6PJjv2l2a0MMQcOi35muG2haI2qrEE3
         ufBi1xatW2TgY3DaRclFWWnFdHKRTCWpuSw5M3pykuNLEkQ/+lVj3AXrMW9DHMtVHk4a
         rE/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVZXANDTNdR9iTYxOK9/PMaUlwBY5uiCPpBavWVmwvhH0DCKWbM
	HNjFfvSQLyvLqzNTPUzJk48=
X-Google-Smtp-Source: AK7set8j8fCJxqP+CEBNBWm+/nuULLlbgZDebOjvBQHxRUc3SGQXt6lD2uTMCRzYUHDgIOMu592S6Q==
X-Received: by 2002:a05:6870:3118:b0:163:c6d0:295d with SMTP id v24-20020a056870311800b00163c6d0295dmr352789oaa.135.1675874426406;
        Wed, 08 Feb 2023 08:40:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:b11:b0:152:e7d4:7359 with SMTP id
 fq17-20020a0568710b1100b00152e7d47359ls9014102oab.2.-pod-prod-gmail; Wed, 08
 Feb 2023 08:40:26 -0800 (PST)
X-Received: by 2002:a05:6870:330c:b0:16a:92b:4ee with SMTP id x12-20020a056870330c00b0016a092b04eemr3949658oae.56.1675874426031;
        Wed, 08 Feb 2023 08:40:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675874426; cv=none;
        d=google.com; s=arc-20160816;
        b=hfg5ddm0MePJKkCVWmthKlbmjglTxxOue/KFG3EEp9UUx2J+kp0J3EKu6Hhdev9Vkn
         elbIEnL+MCs0/+M0N803x0I1TY9tA1GT0Hunsf60BSyTuO7XWQM2YKnjHatFptDDATg9
         juncEgONzLLu0LyJf5OMMlO4aM00G9QBLXshnywpWaSLVcpx7ZvZ9iiS8s0gjsnDntyJ
         dmfuMsDTEH22BzTraQeF8BueIB4Ze5g7O53psxMA2TvZxKLmqzbFAO/HKTnn3rIa0Eps
         cmfRvnhE3OTJCAFHgmEwilJSFFzDvYl74nw+XqLTkuzHRnrwZ6HYmVkveEg4BeOwOeG/
         a8yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xvTbmEyJDH308Mr1kfAgZiukxgBd5MJ/ejaniJVGR/0=;
        b=p0IrXlfjLrR4o5a05OQsM9L6T7v3NpFJ8yesZskTiGYhp704w06K/Cx3BDCBwO12T5
         K1kkIfvufU1VVhNUyHCOoY9ED8eAl8xs0sbG4GGmWmi2JBgHH5d2d4UKye9PLA52XrCh
         7oUZ9n/oh/ysc8WMnwToLybZtp0B9VBoaxp2n64fQCX/Y+Lgpy3NaLpQlPDj7RNZ/0we
         LKQjrkru2axa4JyXjj2V6S3Ed8/M3PUtPKRPXYej5AVBJuVd9MRKptzNo7yiKuSqhjK1
         pY+632SYgnwvS7ooxRGzmzvaMiUW69dShS48pDubeLpYKmRGP5RyqnKqdlr9tuVX4x2k
         oa/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q1mVQCj5;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id s199-20020acaa9d0000000b0037803603d36si1371683oie.0.2023.02.08.08.40.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Feb 2023 08:40:26 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CBDE461718;
	Wed,  8 Feb 2023 16:40:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 70A29C433D2;
	Wed,  8 Feb 2023 16:40:22 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 2/4] kmsan: disable ftrace in kmsan core code
Date: Wed,  8 Feb 2023 17:39:56 +0100
Message-Id: <20230208164011.2287122-2-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230208164011.2287122-1-arnd@kernel.org>
References: <20230208164011.2287122-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=q1mVQCj5;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

From: Arnd Bergmann <arnd@arndb.de>

objtool warns about some suspicous code inside of kmsan:

vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_n+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_n+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_1+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_1+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_2+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_2+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_4+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_4+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_load_8+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_metadata_ptr_for_store_8+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_instrument_asm_store+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_chain_origin+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_poison_alloca+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_warning+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: __msan_get_context_state+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: kmsan_copy_to_user+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: kmsan_unpoison_memory+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: kmsan_unpoison_entry_regs+0x4: call to __fentry__() with UACCESS enabled
vmlinux.o: warning: objtool: kmsan_report+0x4: call to __fentry__() with UACCESS enabled

Similar code already exists in kasan, which avoids this by skipping
ftrace annotations, so do the same thing here.

Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kmsan/Makefile | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/mm/kmsan/Makefile b/mm/kmsan/Makefile
index 98eab2856626..389fd767a11f 100644
--- a/mm/kmsan/Makefile
+++ b/mm/kmsan/Makefile
@@ -16,6 +16,14 @@ CC_FLAGS_KMSAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
 
 CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)
 
+# Disable ftrace to avoid recursion.
+CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_hooks.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_instrumentation.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
+
 CFLAGS_core.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_hooks.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_init.o := $(CC_FLAGS_KMSAN_RUNTIME)
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230208164011.2287122-2-arnd%40kernel.org.
