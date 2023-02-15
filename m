Return-Path: <kasan-dev+bncBCXO5E6EQQFBBIVPWOPQMGQE4YBQSBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D8206697C93
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 14:01:23 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id b24-20020a0565120b9800b004d593e1d644sf7955278lfv.8
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 05:01:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676466083; cv=pass;
        d=google.com; s=arc-20160816;
        b=i+XSYSjTjJcnXVIxFTQKb1X9/f09E+5R0MAIsnmXG7qzb8iniiziacJRGCWO7nQNei
         lIp4b23zXUrcDTWCMLcLD9DG0LPS9sj8j+9rWqGtDTpR+Ya+CXL2eC7SA0Ih1KcYDVC1
         kB+lr/QEdjkjGD7uL2200RhA829fL8E/lMoHFegHjYOeesh4W4Mk1ret/x0r4IDsT4iw
         nYGn4sintGDKZgJPEU+xZbdB1ut2nj17C/tbrSLTeng+gEmzjzKwUBdp9tUQkXqOdNOq
         kuRBwhua21M9jrFiDXXWLzoSm7YWG4RPn6t2x537RzCx0xOebZB9tdihqeIyY4WUnIp8
         CXJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fLldC7O+xWXvvEmHcwsWTdxLUxG3Mh+7vT4iBvXdix8=;
        b=RTy/gtCiHPA9BaGMoI6q7gL5EjxDkp6NWD+YKnbDSYwcbsvQO9NBU+gOBX0/NZJSxd
         CfqxBF424te5s0vGOGTASeKM7ORMwG5kzLAC2SrAAXIZa5KaJ7Rqwjh3dhAOYPK9MskY
         dYrF9Vsb/I4lNu2gaP+ghf7KG4l51T64X52bNteGLD3RGU4trts696AKTSIYMwAJ8aZF
         sSf6gIjxWTc67LiyKmQoObUJAt3RpxjAhSsIR2l3I633ZiAtKjCxKtw7ennZ1OeJa/Ia
         6GUzxvzEcS3JijgwijHZ56LuKmnZqwhYw616XBvCcjdekZuNF5N0DxUvMekAXev+f49y
         DiNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Lu0J/SbI";
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fLldC7O+xWXvvEmHcwsWTdxLUxG3Mh+7vT4iBvXdix8=;
        b=UlLM2cy23f6MSLsqCNtylp/uo90zWZxxp1sPIl64HNuYTcEDHwCqRTeAbNtn6NmgTw
         XkiaJ8Jyn4r9+/E0zj8OUr45AeP+fnZWZNM9jCSooV72CZBKDHPjWuVfwrsNFJ53H4WS
         R39FHdjldKsTuOeFHfp9xj9C5mfmQoZ8whvr13wXRyW6KOr59v2IDyBLerwyOjmqhADN
         hSewMXa9Q0WzGL2aYSKbd5rBaXmTjNAVJgMpOSwI/HW4u9xNl6iNi5d3Hn4C/BHPWzuF
         ZK+vXPXFpT0N3YradBv0x7+tNhk/01KkuqWT28e2zPDHd4wKpuXDKeQBjlGjvYc4tqdb
         lAKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fLldC7O+xWXvvEmHcwsWTdxLUxG3Mh+7vT4iBvXdix8=;
        b=JyHlTd+LpQfg9TBl9wksva9KzQT9w92ocp3P8diY23N/b1+V9UoUcK7SBQXsA99g3Z
         BMPc/X7QSZJoVA9C/8kc0sUm89cYBsN4BZ2Iiymlai7y4LMPXfwF1wgGdYWqcMUVQOjw
         jI2y0vWwnmkZIMmll7dx+SZYtMPWJlq7goPryu3HnMa4AzOmwvbiuErxjBTgXKlNOSd2
         h2RIHBMurFMJ61GqvTVFTHtDflzD+uPe5bEoObMVziPqZNxcshO85L8G2PCZmzfZ+tqX
         W+wtumLbchJ+4iPs3PXQo2iqCTQcc6PbSV2euGxEq6WDXiBFAweM6UqEjZoqg6eVu3TH
         GwPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVTjI5yFHVw/4Y8EwN82XER0mMcBpn8VIllHUlfckxINIk4JNQB
	i75WyGeSGZVXDr3rYQQvtk0=
X-Google-Smtp-Source: AK7set9i7jdSD29HchTVSwMeXwhqLQFdBWc0SIflBFYzc+Uhmy1RFNlslCVjrMfD0qa9U29wkkf+xQ==
X-Received: by 2002:a2e:b90f:0:b0:293:1696:a048 with SMTP id b15-20020a2eb90f000000b002931696a048mr534699ljb.10.1676466082967;
        Wed, 15 Feb 2023 05:01:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b12:b0:293:5fbb:35c3 with SMTP id
 b18-20020a05651c0b1200b002935fbb35c3ls621820ljr.5.-pod-prod-gmail; Wed, 15
 Feb 2023 05:01:21 -0800 (PST)
X-Received: by 2002:a2e:9d14:0:b0:293:4b5e:6eed with SMTP id t20-20020a2e9d14000000b002934b5e6eedmr543786lji.6.1676466081624;
        Wed, 15 Feb 2023 05:01:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676466081; cv=none;
        d=google.com; s=arc-20160816;
        b=URelhI6rWkQbmNVYYao41u2twKYPUbKUDdR3V4rI0GnESU8Ltdt0TbtR9FLQ4ILqGd
         z4ssrRT7TAu5/grgAyZSQ81HNgY0i0CMOddnbA/6x4QiQNjfUwGvVSAGv9g7fbZIbmXk
         EZfZc3p+VWg2sLB/Td6ErhBVWSVnHiUV7vAwe/PLYUqF1YPSrPUJuACW5aZjhv0o2Knp
         VOEvLP7/wqaVn/eFrCLo8txLGGKe40V/KC+gi9L5qy3V++EyM4EfimYchyvgLz+1Jf2n
         /BAxG7Rki3VQtkOl+tCkUASSWwI4oEiIqvBIAoKkuwONdrN3LBwW3gDiDMzEVvblHhL1
         43nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BcBkGQIO+rb2iXcsy77cxTrQw5FMHDgpD40SU+OF/kE=;
        b=jnAoILN62AiF/B7reYUlQBoUuU7JgTAE5aVLC9Q5Y/40++7N5QqO0946VmygiQVW2q
         nfWciUprHEKpBY8/dvUrIUt3pNGwe6OeEALVNpv5xnOr/49s2DyyoOHjYncKZnwOQAmH
         wOnglb7zEBsooqpJ+1/X152MuM0QIaj9xTWFg9YlQunjX5dm50m19NHwsy/jrtBq5HfO
         b/Lg9BZozmDHB3OQjiHbM7dzFCOs1HvVKxPmn35qMmETX5hRwU9dp0Rw4xWyoXvEG25Y
         KqwUqhT3KaAJpK1HAD20JG8Os2eoprnDVB2aQp0haTb9h5ZcqhM4CbaszsTFTU4WyOQ5
         ICww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Lu0J/SbI";
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id l6-20020a2ea806000000b0028ffa3d673asi833052ljq.3.2023.02.15.05.01.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 05:01:21 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 11E49B820DA;
	Wed, 15 Feb 2023 13:01:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D33BFC4339C;
	Wed, 15 Feb 2023 13:01:16 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	Marco Elver <elver@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 2/3] [v2] kmsan: disable ftrace in kmsan core code
Date: Wed, 15 Feb 2023 14:00:57 +0100
Message-Id: <20230215130058.3836177-3-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230215130058.3836177-1-arnd@kernel.org>
References: <20230215130058.3836177-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Lu0J/SbI";       spf=pass
 (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted
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

The Makefile contained a line to turn off ftrace for the entire directory,
but this does not work. Replace it with individual lines, matching the
approach in kasan.

Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Acked-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
v2: remove the old "CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)" line
---
 mm/kmsan/Makefile | 8 +++++++-
 1 file changed, 7 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/Makefile b/mm/kmsan/Makefile
index 98eab2856626..91cfdde642d1 100644
--- a/mm/kmsan/Makefile
+++ b/mm/kmsan/Makefile
@@ -14,7 +14,13 @@ CC_FLAGS_KMSAN_RUNTIME := -fno-stack-protector
 CC_FLAGS_KMSAN_RUNTIME += $(call cc-option,-fno-conserve-stack)
 CC_FLAGS_KMSAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
 
-CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)
+# Disable ftrace to avoid recursion.
+CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_hooks.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_instrumentation.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
 
 CFLAGS_core.o := $(CC_FLAGS_KMSAN_RUNTIME)
 CFLAGS_hooks.o := $(CC_FLAGS_KMSAN_RUNTIME)
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230215130058.3836177-3-arnd%40kernel.org.
