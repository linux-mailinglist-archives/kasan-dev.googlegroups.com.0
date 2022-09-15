Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKH6RSMQMGQEABFAKXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 80A7A5B9E09
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:13 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id o25-20020a05600c339900b003b2973dab88sf9726905wmp.6
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254313; cv=pass;
        d=google.com; s=arc-20160816;
        b=mZA6SYWmIprSMEfLFSpD9cevt49QUZSJykSCtk6Iuu+pj8pfgIxfWE9C/F+OLrgz3i
         G51KV3Y1RG+ni7GsaBxfhLJAwWf3FG7DmUTMgyEnhc+4K8x/j8yo2z+KiR/D0g7hK2fO
         1Xc2ShGUIHUcyhiOWGq4BKzb8pMXUeN/m7Ty1H53Vq9LYtrMi1ly16Fowxu/i/tYppJ6
         afMECGbJjM9EcQ2LzbRlWpR2HlFSjyvzxdeQeZAqTaDi15Nw1dJ233jN7CyYvQHk6kzo
         sqx1UDHVfUJBW+hSaM40y9VH18u1l+pisUjwpGbu4MVh8vC+b7ZPWNtDpQPaHA2NikFd
         ZlEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=M1Rn9lFhbbW5umiy8d+QgMjmSr4SRhboSPVdoo81sdA=;
        b=drXFccw9SqjjE0H0WXa/Cgf1uhSlrkEXM1aKSlZc7tQLwWpeMtFGaiSNatZ7GIbYxV
         5oeHUb88EHp4tr+Kf6FwyIk2M7JHmCLqnUamM7mylMqpHOLty1wJdE5oXt2Jt04bAUW9
         Ako5/DZYfWLOEgaS7imJ2wm9Q6UckVffQ3eN50mRcX8g4p0NhREyoe9rapyowE46vcy2
         PnmK1mC/+3NowLTdRmvYbyyNRNdr5OoXHgEfqb8hRHlVb0/Ot/BIpZOcLZvvB1q3zU30
         DEoSwUFNuYZGzggnpoyu34WSO4gbdkqAXHHbyZVrrR6eA5QZBhmPsFEAZgOyhAIV2o3s
         IhcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ei0ZOo1t;
       spf=pass (google.com: domain of 3jz8jywykcvi052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Jz8jYwYKCVI052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=M1Rn9lFhbbW5umiy8d+QgMjmSr4SRhboSPVdoo81sdA=;
        b=CBGKryW27np3hKZyBQEo+L+DY9CkQvR8O4Zvyg2b0BeuwohGGPw3uifMnKKokVrq2w
         wXNsh/RWThTHNxRiS/2l/+AOT+Gs7A5eqrc7YJ1db0kErqyI59TnvxITY8A9eX1aKrlM
         pnn3VT6Jg6XxMUd4/v7T2bpW5nmFtC+hF5wPQTXcdjjmcJs01Qb53sgc/6PUQh+4qUC8
         ft1SdM8T080tEqocMzWsVll04eGSRE+g/2yFMOStSAMV2HS+5Tlk4iHZGVOJte/O7TQ/
         9mXOm3ugS2efvFXJnFFEIw/5t33jaEKGe7KRWpncu9qe+XawOrNrmm0aRPruL5vWISow
         TLHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=M1Rn9lFhbbW5umiy8d+QgMjmSr4SRhboSPVdoo81sdA=;
        b=oBfTvt+8hLx8wwe8pVAzNUVTeCDWGWCCGXZx562fSbSYQ5tDik6tUp2Ct0onv9vcmu
         TfW567SgoHLaxsA1DHuP8bDvjPPaKNCXovjE5tWI73YfF4w9T5/DjmfcgymHjD+Cs9jY
         aiFS8pJfI56C54bD0BeFde2Eqbozz4soWQw7EnHJO0mXuQYJ+nlOXee2CrHyo33UgKj5
         LdmkmbdDujLFaDg+z8wfGV2HzfqPBdsgw4+smbHu0P1ANwzqF2rgCTHb9P2asZ/144nz
         3sE1WHJOpPWjv3rnwAyxnlIUQzLaGWJojHm0XQeTD/TrJdColMx6Icm9MAMpx8i9IfFN
         NlSg==
X-Gm-Message-State: ACgBeo3bbk0ziXi1ulNsIhrC7AvW2dqC6ZbayRwi5PDs6AkLhEmtj19N
	swwvl6Savq1mx9oZzMQYoc0=
X-Google-Smtp-Source: AA6agR7ozYs7eUaaQ8oLpphhKh1DGVk7LEn8tIDS8Yte8S4LytodPPEweRmyey1qGbiCNQt+utfnBA==
X-Received: by 2002:a7b:c8d6:0:b0:3b4:868b:afc3 with SMTP id f22-20020a7bc8d6000000b003b4868bafc3mr6886453wml.66.1663254312922;
        Thu, 15 Sep 2022 08:05:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d210:0:b0:228:ddd7:f40e with SMTP id j16-20020adfd210000000b00228ddd7f40els3198340wrh.3.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:11 -0700 (PDT)
X-Received: by 2002:a05:6000:1ace:b0:22a:c9a6:e203 with SMTP id i14-20020a0560001ace00b0022ac9a6e203mr64388wry.694.1663254311759;
        Thu, 15 Sep 2022 08:05:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254311; cv=none;
        d=google.com; s=arc-20160816;
        b=GW8XAPJzYwYNPSJRUB5kCEoxBp2T/8p4ciRwYdSVl2xr9dlzCLUTM+cGOelVu9SYFo
         ZWMdtYVPxIfidwSbkSZv7PwAhBy9gW8bFiQNW/Ukl2/ONXBwYlJdXcq50/alVhlpNn3A
         dtwPpqd9VVqLN3hYXUYzv9WpN8X8d47ujkwG31ouTJ1Uu8HMcdmWWsm8xoiViAdS9wBD
         TyLjcwFzReonraguRLc832LUEzm0Ho3qGFnzx38pjopkIBkFKGYbGvuzZDiDApR8xGct
         2jyKasGBtNL7zFHw38xv/IQqjzi2d7iIR8GE26KJy6aa1RweUVmisxmcrHM8IUMYOeLx
         oiCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=7DSx6RI0rEPDhrbVIpPikNsWTzcR9RC7kojIoDN82TE=;
        b=M8mUtdxPJ/2maCKALqYBl8kHUUPPMkYFXw4jjHZDGBl5iDkfB+iw1JLJzONrJIfU1m
         z9Kso28W5q5FwUoUsAd4v5HDoq+lah9LKcL4SRZZMSNy7nA24t2tLxP0APob7MQo9wWR
         2dOsSgD8QurPP00WQn8OkjurwgLDfa8LRMjVju14KO1QMFEhbOXkx8vPCJVdbMOKpsc9
         KTAuxocHLbJ9jQCzya2jYfKvaMKxRgqPN8lZ5VHPqZLLk2Tec74AckCocdj+YyngoBid
         9W6LHL4zBmjuwfyHVnou9tPwXdPjdjm0Z282UMLh4ImMiP62HUldQivrsUSlwM901E1u
         9cHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ei0ZOo1t;
       spf=pass (google.com: domain of 3jz8jywykcvi052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Jz8jYwYKCVI052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bp13-20020a5d5a8d000000b0022a48262c0bsi62914wrb.2.2022.09.15.08.05.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jz8jywykcvi052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id qw34-20020a1709066a2200b0077e0e8a55b4so5582509ejc.21
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:11 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:aa7:c74c:0:b0:44e:a7b9:d5c9 with SMTP id
 c12-20020aa7c74c000000b0044ea7b9d5c9mr264063eds.19.1663254311281; Thu, 15 Sep
 2022 08:05:11 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:46 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-13-glider@google.com>
Subject: [PATCH v7 12/43] kmsan: disable instrumentation of unsupported common
 kernel code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ei0ZOo1t;       spf=pass
 (google.com: domain of 3jz8jywykcvi052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Jz8jYwYKCVI052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

EFI stub cannot be linked with KMSAN runtime, so we disable
instrumentation for it.

Instrumenting kcov, stackdepot or lockdep leads to infinite recursion
caused by instrumentation hooks calling instrumented code again.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>
---
v4:
 -- This patch was previously part of "kmsan: disable KMSAN
    instrumentation for certain kernel parts", but was split away per
    Mark Rutland's request.

v5:
 -- remove unnecessary comment belonging to another patch

Link: https://linux-review.googlesource.com/id/I41ae706bd3474f074f6a870bfc3f0f90e9c720f7
---
 drivers/firmware/efi/libstub/Makefile | 1 +
 kernel/Makefile                       | 1 +
 kernel/locking/Makefile               | 3 ++-
 lib/Makefile                          | 3 +++
 4 files changed, 7 insertions(+), 1 deletion(-)

diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index 2c67f71f23753..2c1eb1fb0f226 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -53,6 +53,7 @@ GCOV_PROFILE			:= n
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
diff --git a/kernel/Makefile b/kernel/Makefile
index 318789c728d32..d754e0be1176d 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -38,6 +38,7 @@ KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
 UBSAN_SANITIZE_kcov.o := n
+KMSAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 # Don't instrument error handlers
diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index d51cabf28f382..ea925731fa40f 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -5,8 +5,9 @@ KCOV_INSTRUMENT		:= n
 
 obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
-# Avoid recursion lockdep -> KCSAN -> ... -> lockdep.
+# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
 KCSAN_SANITIZE_lockdep.o := n
+KMSAN_SANITIZE_lockdep.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
diff --git a/lib/Makefile b/lib/Makefile
index ffabc30a27d4e..fcebece0f5b6f 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -275,6 +275,9 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 CFLAGS_stackdepot.o += -fno-builtin
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
+# In particular, instrumenting stackdepot.c with KMSAN will result in infinite
+# recursion.
+KMSAN_SANITIZE_stackdepot.o := n
 KCOV_INSTRUMENT_stackdepot.o := n
 
 obj-$(CONFIG_REF_TRACKER) += ref_tracker.o
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-13-glider%40google.com.
