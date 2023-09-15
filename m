Return-Path: <kasan-dev+bncBD653A6W2MGBB54PSCUAMGQENLO22JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2907B7A1772
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 09:30:01 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-30e4943ca7fsf1247316f8f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 00:30:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694763000; cv=pass;
        d=google.com; s=arc-20160816;
        b=u+UR+YCshU/cLAhJiyRfaKrSdt64ph2KwBlDA4v3+VJe/uaOhnYnIOMvVlWtimiUOe
         UTglMota150n48Vv/hLPPwUF+5dkP/YN5nbnNHd6fbB5B84IkuC3KRr6AbHTMjs2/z3R
         oZ9NPeQQOgLpkLofDH/5KW0Gw7N9euSi/inOQiM5sC5uXYUEorCs+3N02KtA6WEl3Q2u
         Vag/MStmFs5rCCucq+x9UVCELuGsRcYOeWGrGLbAEvbhrDg0ZkyzIgw7NBlQGze/ZubZ
         MSkTi+by136uhQqVSj9V7wfmtOKXAiSEKbWLaewMOKwArrnB/AW+E0Ijb4Vb3jUNj+SU
         afSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:message-id:mime-version
         :subject:date:from:sender:dkim-signature;
        bh=txQ+I65mQ61beCKqzI8ci2ISyhvy8+q3Hx/6d0UygN8=;
        fh=/BsWuqvqe3eo0r5JRt58YrKg2sVLpkLk+6gUJtF4R30=;
        b=Ua5XLZoZdcVU7CHefD46DzijB5YymWBsD5d6u/t08bOfArmUlI6jnKr7BURR4QpifG
         SgxufmZPsU9FqDhYT2Ao4PKvuvIYs77WyIRvPcgdVN19U26r9xTw8wHr2SWWxCi7zaOG
         l/KT2GEyIejng+piczpeNwLvdDT5PquNTFbHTPsNWOJkKeA1y5H7yABjhZUcyVHY9jWt
         cfgS+nXeXEzzzLpbHo1ekkUumoHqX2LQoNPpq9Fsa8kyBRzoj6HgeAGXsXnq7ZTATHVh
         GsNmoNePXqCgsRYC0jxGLFf99fwb4VyIwToGV9okI3mb8Rb65aalXcVbCrWpTkE0gZCQ
         IwZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=mNAug2cJ;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694763000; x=1695367800; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:message-id:mime-version:subject:date:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=txQ+I65mQ61beCKqzI8ci2ISyhvy8+q3Hx/6d0UygN8=;
        b=OgBTT2sP7O/jsinZlqX8qdIIdv0owDm0M0CIropM1ExDZWJc8/QzmTeoXs6m94QglD
         iy0lC2PfGAd8KoJe503K1Pdof0dRHOzeMou5jWTfg1zk5wo4FnWpehyoYJ2AjlJuwtpI
         1yGDE2y0j38gwiTDaAcVO30f9fSEDPBeOy24mm4/1RvPy+ZTCjB80jYAUXG7B4LyCkqX
         A96MrCbPMaiEqnh8nLMirW6ZLNOYJ7FfaS1dLLmEXTT4KHbRnXzBqFwoFAHPlPhjIFK5
         UVgiMW66OFsn1W1v0ab0fLGfeRSs0yrgpqOLtCyRdwcrNouosmJ71F8TkllACRQfEAaT
         3JNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694763000; x=1695367800;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=txQ+I65mQ61beCKqzI8ci2ISyhvy8+q3Hx/6d0UygN8=;
        b=Zkxyx0rXJ81Y9HbzbrhQUv3+CSvAsfrwuQBKU80aWe06tIF4PQarKOGgtsSnZ9M5hh
         lvWQtdQqIL3PtU0u9jmgtqxqaaR81yn123+y5p+5qyHi0vzOIPPPC/jRctNPWi5ocdbv
         w2X+24ZeD6v52X16Yeji0K07d3+ouyPpq98J2nu6Xzydfj2ts6lQ4NVaKhlmku/hQs1e
         y3KPBy8ZiqQgAYfn7v3L6qvBOCwtX78/9yp4Gcx6QDsQiuqM2OZGVGnGFbW5/mv+Alvb
         /jkXM8a8CMtw/kObZyRkc6Tzzxea9HKQVL/KNpSoSOp/CiNqAXALcVVGLzmswjRUr90W
         JeTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwIULnwZ8ck0C8heLG1RKyLrgT7c3rgGsXSXPK9dH6NP5LiwIy6
	opXwif11yatT86ShYpnVHyU=
X-Google-Smtp-Source: AGHT+IGrTVt6f5KgqhCEMTOqbI/dYQe1akCURBAnHhlevG8v1xDnGAv5ygRdGHO4LieebnwmUmwjMQ==
X-Received: by 2002:a5d:4d4b:0:b0:31f:d5db:a13 with SMTP id a11-20020a5d4d4b000000b0031fd5db0a13mr568527wru.61.1694762999857;
        Fri, 15 Sep 2023 00:29:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:484a:0:b0:31f:f2ce:9acf with SMTP id n10-20020a5d484a000000b0031ff2ce9acfls120516wrs.0.-pod-prod-06-eu;
 Fri, 15 Sep 2023 00:29:58 -0700 (PDT)
X-Received: by 2002:adf:e24d:0:b0:31f:a682:d27f with SMTP id bl13-20020adfe24d000000b0031fa682d27fmr610862wrb.67.1694762998271;
        Fri, 15 Sep 2023 00:29:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694762998; cv=none;
        d=google.com; s=arc-20160816;
        b=PWh7UqUDDTYZ8bcOjVEkbv++uiRf1Ohr0g0ndoM1q0xLlF3ZBFdkJLotyXD1YVrx8i
         tSm0Xwcx0GXIQdGlI6GTi/myZPI4Yqs5M1W4wtRxi3YxD36yHCV3iG4B7sQTxu/cwmKY
         Z5nvXV+zGxOhFf9kIo0yaliXCFoXMFzPSLrVGQ3oO8/cbFiyU0sGGT6gwZ/Y1qLHBcm0
         VzpzNSZyB5hjs37Iu5NCq1Q1tNGjRpJx7kOMiHZAhBiuAt4NxCCqkcdyrlF4x3lbFyIm
         vqaMANIJ3fzr+HUQYCGfyEorNunvT3wr4I/+WCyuBwXUZC13iBPmsXvYMyR4zeKX9RZg
         QfWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=ZtQJD7Nx7MRDe9gv5VcJ0bJ+FN+0txe0L0UuBp9Hx9U=;
        fh=/BsWuqvqe3eo0r5JRt58YrKg2sVLpkLk+6gUJtF4R30=;
        b=tpX5HooMMZEIhEDnitosAKtoqoX90rDpQYOcIzzVPev6egWkoL+mYcPpaaeEF2pF7k
         T0xzseImj5se3rCeQND1/ncvCKAv4hx87YiYyfBMnFifCquSefk5ejnwcO5GTf9jWyfo
         TfC8jF9tNHkCj3f1GsMPS5RXHnyxI7DImQgWbEAuSHjQ8fYiodP9W+5F2Z4rnDQ5yMPi
         NRZieTdHCgvvpSDvw8gEUmt3m7wbsLZ/QFZZKUb5GWM2md8pRxojIbMUawFS0WG1EOKk
         nIHdkuKkUbRwnvsVI82CMdZdh4rG/AighPc8aL0tDoVmMmyEo+XMutJ8JMhpLFkEL0AL
         SyEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=mNAug2cJ;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp1.axis.com (smtp1.axis.com. [195.60.68.17])
        by gmr-mx.google.com with ESMTPS id bk24-20020a0560001d9800b0031aef8a5defsi221516wrb.1.2023.09.15.00.29.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Sep 2023 00:29:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) client-ip=195.60.68.17;
From: Vincent Whitchurch <vincent.whitchurch@axis.com>
Date: Fri, 15 Sep 2023 09:29:52 +0200
Subject: [PATCH v2] x86: Fix build of UML with KASAN
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-ID: <20230915-uml-kasan-v2-1-ef3f3ff4f144@axis.com>
X-B4-Tracking: v=1; b=H4sIAO8HBGUC/22Nyw6CMBBFf4XM2jGlgAFX/odhMfQhE7U1HSUYw
 r9bWLs8J/exgLjETuBcLJDcxMIxZNCHAsxI4eaQbWbQSlfqpDr8PB94J6GAuuq0tbWp2qaFnB9
 IHA6Jghm3ho9Rb/qVnOd5v7j2mUeWd0zf/XEqN/tvfCqxxMaTaW2tOlv7C80sRxOf0K/r+gOhX
 iW1uAAAAA==
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Frederic Weisbecker
	<frederic@kernel.org>, "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
	Peter Zijlstra <peterz@infradead.org>
CC: Richard Weinberger <richard@nod.at>, Anton Ivanov
	<anton.ivanov@cambridgegreys.com>, Johannes Berg <johannes@sipsolutions.net>,
	<linux-um@lists.infradead.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kernel@axis.com>, Vincent Whitchurch
	<vincent.whitchurch@axis.com>
X-Mailer: b4 0.12.3
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b=mNAug2cJ;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates
 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
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

Building UML with KASAN fails since commit 69d4c0d32186 ("entry, kasan,
x86: Disallow overriding mem*() functions") with the following errors:

 $ tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=y
 ...
 ld: mm/kasan/shadow.o: in function `memset':
 shadow.c:(.text+0x40): multiple definition of `memset';
 arch/x86/lib/memset_64.o:(.noinstr.text+0x0): first defined here
 ld: mm/kasan/shadow.o: in function `memmove':
 shadow.c:(.text+0x90): multiple definition of `memmove';
 arch/x86/lib/memmove_64.o:(.noinstr.text+0x0): first defined here
 ld: mm/kasan/shadow.o: in function `memcpy':
 shadow.c:(.text+0x110): multiple definition of `memcpy';
 arch/x86/lib/memcpy_64.o:(.noinstr.text+0x0): first defined here

UML does not use GENERIC_ENTRY and is still supposed to be allowed to
override the mem*() functions, so use weak aliases in that case.

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
---
Changes in v2:
- Use CONFIG_UML instead of CONFIG_GENERIC_ENTRY.
- Link to v1: https://lore.kernel.org/r/20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com
---
 arch/x86/lib/memcpy_64.S  | 4 ++++
 arch/x86/lib/memmove_64.S | 4 ++++
 arch/x86/lib/memset_64.S  | 4 ++++
 3 files changed, 12 insertions(+)

diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
index 8f95fb267caa..47b004851cf3 100644
--- a/arch/x86/lib/memcpy_64.S
+++ b/arch/x86/lib/memcpy_64.S
@@ -40,7 +40,11 @@ SYM_TYPED_FUNC_START(__memcpy)
 SYM_FUNC_END(__memcpy)
 EXPORT_SYMBOL(__memcpy)
 
+#ifdef CONFIG_UML
+SYM_FUNC_ALIAS_WEAK(memcpy, __memcpy)
+#else
 SYM_FUNC_ALIAS(memcpy, __memcpy)
+#endif
 EXPORT_SYMBOL(memcpy)
 
 SYM_FUNC_START_LOCAL(memcpy_orig)
diff --git a/arch/x86/lib/memmove_64.S b/arch/x86/lib/memmove_64.S
index 0559b206fb11..e3a76d38c278 100644
--- a/arch/x86/lib/memmove_64.S
+++ b/arch/x86/lib/memmove_64.S
@@ -212,5 +212,9 @@ SYM_FUNC_START(__memmove)
 SYM_FUNC_END(__memmove)
 EXPORT_SYMBOL(__memmove)
 
+#ifdef CONFIG_UML
+SYM_FUNC_ALIAS_WEAK(memmove, __memmove)
+#else
 SYM_FUNC_ALIAS(memmove, __memmove)
+#endif
 EXPORT_SYMBOL(memmove)
diff --git a/arch/x86/lib/memset_64.S b/arch/x86/lib/memset_64.S
index 7c59a704c458..6d1c247c821c 100644
--- a/arch/x86/lib/memset_64.S
+++ b/arch/x86/lib/memset_64.S
@@ -40,7 +40,11 @@ SYM_FUNC_START(__memset)
 SYM_FUNC_END(__memset)
 EXPORT_SYMBOL(__memset)
 
+#ifdef CONFIG_UML
+SYM_FUNC_ALIAS_WEAK(memset, __memset)
+#else
 SYM_FUNC_ALIAS(memset, __memset)
+#endif
 EXPORT_SYMBOL(memset)
 
 SYM_FUNC_START_LOCAL(memset_orig)

---
base-commit: 0bb80ecc33a8fb5a682236443c1e740d5c917d1d
change-id: 20230609-uml-kasan-2392dd4c3858

Best regards,
-- 
Vincent Whitchurch <vincent.whitchurch@axis.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230915-uml-kasan-v2-1-ef3f3ff4f144%40axis.com.
