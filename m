Return-Path: <kasan-dev+bncBAABBZWB562QMGQEAEHUFTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A2B67950FD2
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 00:40:39 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4281b7196bbsf45869535e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 15:40:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723588839; cv=pass;
        d=google.com; s=arc-20160816;
        b=TVwSzTuFbBcCw/s/y6d4rqPZCj3MFrkhvtk+lZtmk8ME94drrdcQCV6DzzwkOu0adn
         gtrlErqoalqbUTaJrInUl4fcSua2uBxF+DATZrHoT9rx2CHFIovANhCOf0zJf8rq2Ge8
         wAoxKrW9gM4YY0cqBJXyphyTXM7COsK50CrBxibuiwuX0t8gXNaPeHy/Z8ejNLnzDYSn
         wS5Fg+83CyVKaitPb7me2e4ekBmEWyJQ0HX/ndqp1lDaG5Hnb++6Xrrcnmmy6dD+uL9K
         An9OaASdl3p01lTd6MduZicihlKfuRrCCmu6fOW/cemb9cuXVkNbjEzjzMFDpWdGcDZL
         Jm4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1GrhXKaZmPRS6d4c5zf1sYe8JWkf0+AsSBL9Wt80Ayo=;
        fh=7vr3zE9izBLi+b2svrAiQrdtb5pcRnaqLjuaXE9jPso=;
        b=xVuaZAvCTwrfy82/UNzam+h07p5Yc7HZuDxuPA4a56qh+7uSUIFsGLCgPEpN8Itu1Z
         qm9AHSJuadhtabsizHJr3D7M3weL/HWIoAPaFh0U5vbSGQqk907Y+tWtVnvbMJDE8Ejk
         nj+Y9fTGKFzeH0cXzTHeUNMJQ0eqvm8S2etOOxZwD6ym5Tu01/tOjIGMdRhuTjWSwFGO
         G3JgihdXdR4Edi6N/sGyHDAT4a63ff2deaodlrQBKKmgnXc78oatxK/UR7aQz6gSGYG8
         f+pUl8n0hw2UDrZjYRiqy5eV3TR2MS6GOM8cgqfEyeiIkznhFKvb3FhCMHu86uEYiDik
         c6mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZG6A2Cxz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723588839; x=1724193639; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1GrhXKaZmPRS6d4c5zf1sYe8JWkf0+AsSBL9Wt80Ayo=;
        b=Uu2KBkcq+sg+7SI0oniiOut3DqbU/9qL3YMb42Yw0zqpfBu8NB28VuDjOlOFmwNzja
         kMTw9vPVuXAY2Y/KsF7qK+23SRmG0gBxCPZAePNKSe0WHlwT39izy+6IfAKYTk9q6DfV
         J8FTVNZMlSnW16ykb4YMJiJ/IJdXLgNCTsVXB+hcpUBV7Np+GMDFch5GQDOc5lO8BdBQ
         pqp1sBdc33U9j9Z1HAiNCbTW5IlLj15KBry8xHKOVc7B7s9luoPehHVO7pdXovUMjcY0
         AN89sYH/V+WG3eXoNDbtiGB6BewvTtFYu3eiJscWGtc32gG4uNirBCAtdwbCsB/Qamx4
         htyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723588839; x=1724193639;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1GrhXKaZmPRS6d4c5zf1sYe8JWkf0+AsSBL9Wt80Ayo=;
        b=csViDql+8qApRSruqFuPempsR5Zpw/UpcSOGi3ioLSRV/QLTmqyGkPswfSpLeoBUSl
         rxXnjawW6NdbkRU8MQD7UXgGfJHrFnX97jRF+54SaeOzKLP9PLVuexuFEe/aoF4NTxcP
         VPPj2iP8Kb1tA2JB8htu+fGDZMVX+SyUAslv5wW2uQ/UQHGwV0Yv7Pk2DqSVzHbMaS8p
         jBCYUD3KqYxPnFrA1nINDV0pN24j2wbbxVfabTETTJnIr3evR6qNQcU3Nwm/CW4g6Lsl
         kPKCfkfSfpolhdB20r9MuChSgmVmACO4UQu6lk8L0ZSIKDtJETq84FV2MRZx+SadygDy
         1rDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLVhdiN6E+8aD9BR+Puubcw12xBuf6ONkBYD3/NUVOrizn3LlEQgZmI9NmlhlBzrFo5myVNF4eWO4NvAvzUfT8h/c1duwv4A==
X-Gm-Message-State: AOJu0YziRBNwr6GBLiIdZEmIbj1fyiCidhkMgB9R2KFPc4XWhWzKwrOp
	r7GRQPOKBHTRyDqJt2TANdx84aSbDs/+u4bIJphvhi+jwJqkr6d7
X-Google-Smtp-Source: AGHT+IFwAe6GerQVeeOTtvKnYp4lKrMqTIfS0ZDgsV62H94FooTs2R80M/2Fqrsxz++lhzhDSKtLwA==
X-Received: by 2002:a05:600c:35c2:b0:426:60e4:c691 with SMTP id 5b1f17b1804b1-429dd23647dmr5745585e9.11.1723588838720;
        Tue, 13 Aug 2024 15:40:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4754:b0:426:6f58:8e6d with SMTP id
 5b1f17b1804b1-429091939d2ls29753755e9.2.-pod-prod-03-eu; Tue, 13 Aug 2024
 15:40:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKU7O0B/FSmT2tjtFR/Mz7k4NFpVposcub0E9vDjRFCHpIu2R9qa9hu0LfqpPE7lrQnKOAz2xaJ6+IWwhsg6dAwaH5h1q/WOIvwg==
X-Received: by 2002:a05:600c:198e:b0:426:6f5f:9da6 with SMTP id 5b1f17b1804b1-429dd25fb22mr6387715e9.27.1723588837088;
        Tue, 13 Aug 2024 15:40:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723588837; cv=none;
        d=google.com; s=arc-20240605;
        b=bZBVdPud173qkeEMAL5lnUXi3vIrexYelIGM4x/vzPnU21ndbw1NyRTzlWgffeAC2G
         srPnKmwKbsOPM4k8dXll6EpJSGIplEWW9ksGjTZ3/GuLlmnh0IbzgPPcnBX3iBdvJIL0
         OWHbRsKrqWhHG5TyFGf/5oZaVSj0RLcwLkXvIbhqDGrcrvoh6uflxNoipWzc1yq7zK5x
         +Jw8dBURaWFWzR7oDrMAavSbLdKqmH7wX+f0Zuu1GS0qAPLvgQEQlerzqsPQoWdLzK0j
         DI3tm4XAaAYg8B6vVUci3oJfr3vunYLguZz5v9m+EBbAlDPgy6U1zVCmT2+3+Si7EmmN
         9GLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ROfZ7+FlItYIEY2a1H0ZOdv21L9gnBvePHx9MzL+ryA=;
        fh=n4K6hLS3ZnXyWj5COIZoemGfxd00diw9UHDEy8D2wG0=;
        b=do2oW+ChFssz1+bVtOxFlIGA5yni5+7/tc0tkzu2QMeo8ukIB9qZH5n7W3a7cRhPWh
         dAP+pvqvC7CCV5VdHBSMpteFptQGoLgs1qT/DhDOuFiinsTuwLty2Cg4FrxNmOGoeWBs
         7aAvVd+0Wt74X5BJlwzKj/LHzuoAsv1eb3tROPOb11xRFEprf5N/yC4dpuJgj4IsVlhx
         qFfKwI/bvIJan+HjrwLSWbQ3giMzFPdMFbgSt3gmj8/jG8LomlKIHL3pmDRfJrKirlzh
         aevRU8M50vLnQmFLPSv0vUNlpvrWy+Eswy7fc+wqpm5ZD6IbPoLT29Lhed7R6OEj6Wj3
         RoTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZG6A2Cxz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.173 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta0.migadu.com (out-173.mta0.migadu.com. [91.218.175.173])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429d877b698si1199735e9.1.2024.08.13.15.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Aug 2024 15:40:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.173 as permitted sender) client-ip=91.218.175.173;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Matthew Maurer <mmaurer@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Miguel Ojeda <ojeda@kernel.org>,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: simplify and clarify Makefile
Date: Wed, 14 Aug 2024 00:40:27 +0200
Message-Id: <20240813224027.84503-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZG6A2Cxz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.173
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

When KASAN support was being added to the Linux kernel, GCC did not yet
support all of the KASAN-related compiler options. Thus, the KASAN
Makefile had to probe the compiler for supported options.

Nowadays, the Linux kernel GCC version requirement is 5.1+, and thus we
don't need the probing of the -fasan-shadow-offset parameter: it exists in
all 5.1+ GCCs.

Simplify the KASAN Makefile to drop CFLAGS_KASAN_MINIMAL.

Also add a few more comments and unify the indentation.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 scripts/Makefile.kasan | 43 +++++++++++++++++++++---------------------
 1 file changed, 21 insertions(+), 22 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 390658a2d5b74..04b108f311d24 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -22,30 +22,29 @@ endif
 ifdef CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_INLINE
+	# When the number of memory accesses in a function is less than this
+	# call threshold number, the compiler will use inline instrumentation.
+	# 10000 is chosen offhand as a sufficiently large number to make all
+	# kernel functions to be instrumented inline.
 	call_threshold := 10000
 else
 	call_threshold := 0
 endif
 
-CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
-
-# -fasan-shadow-offset fails without -fsanitize
-CFLAGS_KASAN_SHADOW := $(call cc-option, -fsanitize=kernel-address \
-			-fasan-shadow-offset=$(KASAN_SHADOW_OFFSET), \
-			$(call cc-option, -fsanitize=kernel-address \
-			-mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
-
-ifeq ($(strip $(CFLAGS_KASAN_SHADOW)),)
-	CFLAGS_KASAN := $(CFLAGS_KASAN_MINIMAL)
-else
-	# Now add all the compiler specific options that are valid standalone
-	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
-	 $(call cc-param,asan-globals=1) \
-	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-	 $(call cc-param,asan-instrument-allocas=1)
-endif
-
-CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
+# First, enable -fsanitize=kernel-address together with providing the shadow
+# mapping offset, as for GCC, -fasan-shadow-offset fails without -fsanitize
+# (GCC accepts the shadow mapping offset via -fasan-shadow-offset instead of
+# a normal --param). Instead of ifdef-checking the compiler, rely on cc-option.
+CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
+		-fasan-shadow-offset=$(KASAN_SHADOW_OFFSET), \
+		$(call cc-option, -fsanitize=kernel-address \
+		-mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
+
+# Now, add other parameters enabled in a similar way with GCC and Clang.
+CFLAGS_KASAN += $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
+		$(call cc-param,asan-stack=$(stack_enable)) \
+		$(call cc-param,asan-instrument-allocas=1) \
+		$(call cc-param,asan-globals=1)
 
 # Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
 # instead. With compilers that don't support this option, compiler-inserted
@@ -57,9 +56,9 @@ endif # CONFIG_KASAN_GENERIC
 ifdef CONFIG_KASAN_SW_TAGS
 
 ifdef CONFIG_KASAN_INLINE
-    instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
+	instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
 else
-    instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
+	instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
 endif
 
 CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
@@ -70,7 +69,7 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
 
 # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
 ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
-CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+	CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
 endif
 
 endif # CONFIG_KASAN_SW_TAGS
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240813224027.84503-1-andrey.konovalov%40linux.dev.
