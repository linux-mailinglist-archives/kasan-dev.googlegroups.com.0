Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGOD76OQMGQEPPR2F3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7339C666FB3
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:31:55 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id bu42-20020a05651216aa00b004cb3df9b246sf6818671lfb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 02:31:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673519514; cv=pass;
        d=google.com; s=arc-20160816;
        b=kfTz4abxyjsD2/shPObBgyAXO4/8aqWB6nfBt22zz9uXdhD1CRFr8UekzIpEGCw1p/
         jOTLdfgxiZoWKgMwUi3wuk8QeeR2vGZqItNAxw84Ni+QJrVg6GWp00G9uxeKIWIKeNJT
         rCJk1QnBBioI3X9liCI9uKEXWc1vnsHCabK0Jya4ja1F7KUgLD7jVFRnJAdcUJ2mYxML
         M+PYjsX1SSqR/FBNasiOF26r7diKiLUcTIVnD2HWCMFgGsiVrDhKQFvtH6SyaCPynFwe
         WXH54FLJ9VV3h21Vwtswk9T/nDa+NF1tzX/4ztCqD2dnWoL8e2kypXoA6rOI8kJvw2Qx
         Q5zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=OEr4fO0aj3gkbZfkc/KzhDHOf8NL8kMCdzfOFxezSLM=;
        b=KfYA5sKQT7ETBwDBWp9oscXZFetXHT+Y9kV94IKV/cMegCwmgaOG9xsYhNvJonyFup
         s90hc/N/Yf0+kF3ST2KxAL1JPsVQpP5dL1tk/wMWE2r/mIr1oz0oS/JL4dEVxXpaiOY4
         0DABb3o1iM0nbkq5HJnnypxw71B/HVQ2Pil5Kl4uTM665RSVTeXH19hfBIo+DtgKq6t/
         w9PGTS3sd1nnm0Ww9N246za37X4CXYa1kq8fxd42YtJXsJCjfInfMyuqeU57k8D2+l/7
         NbO941UwxJA+PPulRFUnIannS1VHLf3OfLXXXpTbQ1rS2Xba3I/VsvhRBCd6gmUIhEBz
         UbAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=osDqB7oB;
       spf=pass (google.com: domain of 3l-g_ywykcx4inkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3l-G_YwYKCX4inkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OEr4fO0aj3gkbZfkc/KzhDHOf8NL8kMCdzfOFxezSLM=;
        b=YqctjIWnM+E/ugtLqcQZaqVJvwnJ3tEwefYQ8PHNujuY4rTXMqkN202e12FcL86KIL
         hZxB41/XDgQYYl7oW98NnJs7j1uK0WHbS7lMvaxzXUAKm+9/AiNwm6qNeAMIj7uBO2qU
         dMkS7rWBADbZ9smwjWTflau6vhCeEY3Tyz4c25FGuToHhqVVB/HeX0wtSjI/bhUY+QpS
         fl9zu8NKV2sJMlUifW3mp5iRiVuss3n/f/RzuUUjA0OBcj2ehjFWlToBHRgPp32+d2DZ
         wxKfBcwD+i1+yPxSf/iWdvzqtHezrboNcvPXuLL0IXMjk0PMMVXTfARUEwoYdNezBSKQ
         XTug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OEr4fO0aj3gkbZfkc/KzhDHOf8NL8kMCdzfOFxezSLM=;
        b=yKbJK2+5w+4SkB+KYNswyhZOHtmFBmReKNJEc33OgVSFdfavtnmZiIRbUmJJxdGOl/
         VKhefGowcIOi/f3sXeBI9ET0lg7vAAffRgn0+hh0qrfFCSNdi/wEO0g5/MhmL59o0cvP
         +tk+zeQ7Bugmj3P0JzTXeuHXdx7wmG1Be6e74I7Kk2VOrLgIcKsSUGnzG4ZSqOFdMnZH
         9yrRKnNbX7bCMwhC1G87DoyHObb65A8WGYZ4f9ZJQmzBzNLO0wtrox4SgTRBzjH5+k2e
         DmppwPgTd6S++Y7zgR3F4xp+chSa2eKHwYv7DGOa2vhiijAChtPHJMXObkdQ/0BnTTPK
         oRFA==
X-Gm-Message-State: AFqh2krMD9u7H+VpF8qjxBbXww/7ifr+M0H6xy6Zx2JsZ3YaitmDCmJm
	VRuNMybC7FQTw6c+wT188w4=
X-Google-Smtp-Source: AMrXdXvWImUwZCEP0/yabohXo/u0ScioZTkHOF7m2n5XrqPI4EJVi2YbIuAMywZdI0ogMk5dLMmd8Q==
X-Received: by 2002:a05:6512:388e:b0:4ca:f6a4:455a with SMTP id n14-20020a056512388e00b004caf6a4455amr6619386lft.321.1673519513548;
        Thu, 12 Jan 2023 02:31:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:98c4:0:b0:27f:e5b1:aff6 with SMTP id s4-20020a2e98c4000000b0027fe5b1aff6ls277726ljj.6.-pod-prod-gmail;
 Thu, 12 Jan 2023 02:31:52 -0800 (PST)
X-Received: by 2002:a05:651c:1786:b0:27f:c7b2:d9d4 with SMTP id bn6-20020a05651c178600b0027fc7b2d9d4mr19492581ljb.4.1673519512341;
        Thu, 12 Jan 2023 02:31:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673519512; cv=none;
        d=google.com; s=arc-20160816;
        b=q4JxY/jZ5f8OEubSj7ww0IBGjlhNHfhDcSFS1QOKWgCU5IAg6GBgnrpi3nxTMCP6bj
         C+mFOoXFuBVDDnuD9SFZ09EZLPON4u7ytX636bhvyQfX4nLZT7+jTlxkJQ/vuxMC93QX
         uOVrJoe/E0ihMZfntBAMHEDSOTcxssnGpsCV49ecM1ycY9hXv8rg7zrOGChqDvGY4e83
         UrmtaCQ7/J/aASMAJobLivLpS4b9d7/q/UcwkDAt1YJLaxxbvTVq+D1U5dwi2wu1zvsK
         vYOzTfK8Ob4pENp0AxYxEae6i21/NgdlShjQOJgArPchJuv4EjdQklPtfLM4Zx3XypyS
         pQxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=LSkZFm2zhcJ11sH6VV/UUBhi7d17SDGndMSvaJIxOZI=;
        b=CTGSHUkaL3xkZhc8uqy3SkaNkOy3oATQXcVnnrN/eTR6WgjTtPmn/kg/CgavDFW4o4
         aFyfkOUeroRRxp+nV8jmN4IQFGBnpLqSRDV/Wm/41YCuwGmsLoFGy1nHlAO/L4CSFZED
         QFxla1fRv/vWi4IdCZc4gN4Dpg5yjcUlDFVkbE8v6JD32RxloklalajMl/Xsob0AHWvE
         KG6/OZIpNlBgGD2l2ndNMZHu5WaG5qtQ/1qdLppK9u7ovfJMCmM6PjdMUfG0O4xvrrMM
         4rK0Ah2Aq7KvZOBpL11kxHlJyyAr3yJDi6pxzqhcjntxP3acsCexFeCSXRz+DpEla2PF
         DTdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=osDqB7oB;
       spf=pass (google.com: domain of 3l-g_ywykcx4inkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3l-G_YwYKCX4inkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id g28-20020a2eb5dc000000b0027a2a767052si756117ljn.3.2023.01.12.02.31.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Jan 2023 02:31:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3l-g_ywykcx4inkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id l17-20020a056402255100b00472d2ff0e59so11937586edb.19
        for <kasan-dev@googlegroups.com>; Thu, 12 Jan 2023 02:31:52 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:c17f:273f:c35:6186])
 (user=glider job=sendgmr) by 2002:a17:906:b88d:b0:7c0:911e:199a with SMTP id
 hb13-20020a170906b88d00b007c0911e199amr5393223ejb.689.1673519511607; Thu, 12
 Jan 2023 02:31:51 -0800 (PST)
Date: Thu, 12 Jan 2023 11:31:47 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.0.314.g84b9a713c41-goog
Message-ID: <20230112103147.382416-1-glider@google.com>
Subject: [PATCH] kmsan: silence -Wmissing-prototypes warnings
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, akpm@linux-foundation.org, 
	peterz@infradead.org, mingo@redhat.com, elver@google.com, dvyukov@google.com, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	kernel test robot <lkp@intel.com>, Vlastimil Babka <vbabka@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=osDqB7oB;       spf=pass
 (google.com: domain of 3l-g_ywykcx4inkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3l-G_YwYKCX4inkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
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

When building the kernel with W=1, the compiler reports numerous
warnings about the missing prototypes for KMSAN instrumentation hooks.

Because these functions are not supposed to be called explicitly by the
kernel code (calls to them are emitted by the compiler), they do not
have to be declared in the headers. Instead, we add forward declarations
right before the definitions to silence the warnings produced by
-Wmissing-prototypes.

Reported-by: kernel test robot <lkp@intel.com>
Link: https://lore.kernel.org/lkml/202301020356.dFruA4I5-lkp@intel.com/T/
Reported-by: Vlastimil Babka <vbabka@suse.cz>
Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/instrumentation.c | 23 +++++++++++++++++++++++
 1 file changed, 23 insertions(+)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 770fe02904f36..cf12e9616b243 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -38,7 +38,15 @@ get_shadow_origin_ptr(void *addr, u64 size, bool store)
 	return ret;
 }
 
+/*
+ * KMSAN instrumentation functions follow. They are not declared elsewhere in
+ * the kernel code, so they are preceded by prototypes, to silence
+ * -Wmissing-prototypes warnings.
+ */
+
 /* Get shadow and origin pointers for a memory load with non-standard size. */
+struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr,
+							uintptr_t size);
 struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr,
 							uintptr_t size)
 {
@@ -47,6 +55,8 @@ struct shadow_origin_ptr __msan_metadata_ptr_for_load_n(void *addr,
 EXPORT_SYMBOL(__msan_metadata_ptr_for_load_n);
 
 /* Get shadow and origin pointers for a memory store with non-standard size. */
+struct shadow_origin_ptr __msan_metadata_ptr_for_store_n(void *addr,
+							 uintptr_t size);
 struct shadow_origin_ptr __msan_metadata_ptr_for_store_n(void *addr,
 							 uintptr_t size)
 {
@@ -59,12 +69,16 @@ EXPORT_SYMBOL(__msan_metadata_ptr_for_store_n);
  * with fixed size.
  */
 #define DECLARE_METADATA_PTR_GETTER(size)                                  \
+	struct shadow_origin_ptr __msan_metadata_ptr_for_load_##size(      \
+		void *addr);                                               \
 	struct shadow_origin_ptr __msan_metadata_ptr_for_load_##size(      \
 		void *addr)                                                \
 	{                                                                  \
 		return get_shadow_origin_ptr(addr, size, /*store*/ false); \
 	}                                                                  \
 	EXPORT_SYMBOL(__msan_metadata_ptr_for_load_##size);                \
+	struct shadow_origin_ptr __msan_metadata_ptr_for_store_##size(     \
+		void *addr);                                               \
 	struct shadow_origin_ptr __msan_metadata_ptr_for_store_##size(     \
 		void *addr)                                                \
 	{                                                                  \
@@ -86,6 +100,7 @@ DECLARE_METADATA_PTR_GETTER(8);
  * entering or leaving IRQ. We omit the check for kmsan_in_runtime() to ensure
  * the memory written to in these cases is also marked as initialized.
  */
+void __msan_instrument_asm_store(void *addr, uintptr_t size);
 void __msan_instrument_asm_store(void *addr, uintptr_t size)
 {
 	unsigned long ua_flags;
@@ -138,6 +153,7 @@ static inline void set_retval_metadata(u64 shadow, depot_stack_handle_t origin)
 }
 
 /* Handle llvm.memmove intrinsic. */
+void *__msan_memmove(void *dst, const void *src, uintptr_t n);
 void *__msan_memmove(void *dst, const void *src, uintptr_t n)
 {
 	depot_stack_handle_t origin;
@@ -162,6 +178,7 @@ void *__msan_memmove(void *dst, const void *src, uintptr_t n)
 EXPORT_SYMBOL(__msan_memmove);
 
 /* Handle llvm.memcpy intrinsic. */
+void *__msan_memcpy(void *dst, const void *src, uintptr_t n);
 void *__msan_memcpy(void *dst, const void *src, uintptr_t n)
 {
 	depot_stack_handle_t origin;
@@ -188,6 +205,7 @@ void *__msan_memcpy(void *dst, const void *src, uintptr_t n)
 EXPORT_SYMBOL(__msan_memcpy);
 
 /* Handle llvm.memset intrinsic. */
+void *__msan_memset(void *dst, int c, uintptr_t n);
 void *__msan_memset(void *dst, int c, uintptr_t n)
 {
 	depot_stack_handle_t origin;
@@ -217,6 +235,7 @@ EXPORT_SYMBOL(__msan_memset);
  * uninitialized value to memory. When reporting an error, KMSAN unrolls and
  * prints the whole chain of stores that preceded the use of this value.
  */
+depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin);
 depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin)
 {
 	depot_stack_handle_t ret = 0;
@@ -237,6 +256,7 @@ depot_stack_handle_t __msan_chain_origin(depot_stack_handle_t origin)
 EXPORT_SYMBOL(__msan_chain_origin);
 
 /* Poison a local variable when entering a function. */
+void __msan_poison_alloca(void *address, uintptr_t size, char *descr);
 void __msan_poison_alloca(void *address, uintptr_t size, char *descr)
 {
 	depot_stack_handle_t handle;
@@ -272,6 +292,7 @@ void __msan_poison_alloca(void *address, uintptr_t size, char *descr)
 EXPORT_SYMBOL(__msan_poison_alloca);
 
 /* Unpoison a local variable. */
+void __msan_unpoison_alloca(void *address, uintptr_t size);
 void __msan_unpoison_alloca(void *address, uintptr_t size)
 {
 	if (!kmsan_enabled || kmsan_in_runtime())
@@ -287,6 +308,7 @@ EXPORT_SYMBOL(__msan_unpoison_alloca);
  * Report that an uninitialized value with the given origin was used in a way
  * that constituted undefined behavior.
  */
+void __msan_warning(u32 origin);
 void __msan_warning(u32 origin)
 {
 	if (!kmsan_enabled || kmsan_in_runtime())
@@ -303,6 +325,7 @@ EXPORT_SYMBOL(__msan_warning);
  * At the beginning of an instrumented function, obtain the pointer to
  * `struct kmsan_context_state` holding the metadata for function parameters.
  */
+struct kmsan_context_state *__msan_get_context_state(void);
 struct kmsan_context_state *__msan_get_context_state(void)
 {
 	return &kmsan_get_context()->cstate;
-- 
2.39.0.314.g84b9a713c41-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112103147.382416-1-glider%40google.com.
