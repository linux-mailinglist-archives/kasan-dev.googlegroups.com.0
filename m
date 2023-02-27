Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMH26GPQMGQEHG3IIBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EB346A3E99
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 10:51:45 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id z6-20020a05600c220600b003e222c9c5f4sf2191007wml.4
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 01:51:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677491504; cv=pass;
        d=google.com; s=arc-20160816;
        b=rD2pEuegx6zn7SmbQFLsT1VMrhTAKB8S9SI88+dNlo+0ZxPQsuZaC4WqDIKu+IGDhg
         ZQdiCTO0WyW2Ug7OLPT9KJAU6T+Rjf1ScQorcuORjX1wXgcah0WAPL/LcS5FBdBqAQt6
         VAQmJjqO4T3BaAF2xOYGEG7g0FpPXiamurkPt6so9ZCNLKir5nP5lkGuX9sU+Wvba6ve
         OS9lo2pxW7Gf0SxlB629VPcvSJdgyTEEMR6z1YF23cniCK7DyoLZg4WjeqkCp7F4MhjD
         HVPQyy/+Y0WgkfwsepdnoeVcYsiTsV6oTY5+MP+Ym4ZuSAvPobHd0d0Vti5ggBqLrhlR
         /PRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=po0p5ohk1msq7wKQeRIM65cDGPmbReW1gkkuywj8DJA=;
        b=AJpIAI3THosUeA8vPsjksEEvjeL8a8uJztG1lgOB6ltvPFk46/uxoGWerIE/+r8wcR
         aiqLIzu11APh3ZPcCvXpEP8xvH6sg6dmrW+1CsQLBxBvfzTGAswXe6y4ejYE+kxQsq/6
         VI2jfkCqfUP9q6FrJXbPJOvfxVFL0OlMaN/eSMa7bGWNBZ7BlBcuGlROM1SkOnkL24Vo
         vSVN/Rry2WreqhDvxvpMDLmv0t+aU4XKQKkIUzIxP7BQbf0nNLPpCVOOrOUnfUkn6ExP
         niZbWojjMsBDVDgLqU0x1+k/6ckTMAoSNRD4LamDFJ5C7afITAie3L7PIts4NiyQ3FMK
         E9QA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kMaj71Vf;
       spf=pass (google.com: domain of 3ln38ywukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Ln38YwUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=po0p5ohk1msq7wKQeRIM65cDGPmbReW1gkkuywj8DJA=;
        b=PsLxkc+TpFpXHgaK/PwtiUUd7iL5d+Miq4tu+mOmaoEdlSOLlrGOxOtmYMM+wUX4O8
         za5qbGEDfaAyb3MHdRGNAbcN/QoeeZdygrLvha3T4w/pLvAn8trGFvpuuiFsVCErHPvd
         lBMXyJzZAIPmbFHNgJ1DHogiyvPuhcmmb5iGscVrv1o7SFRbLwTFXv4fUH/9/a1S4CZd
         BpSkaJvujMgu+CIym1pUZPAu0f4guX2UYadnDy/hhnDu9F4hJkIXqHUx+cnn2AF3sNGr
         j5rHO6CrdBO62v6NFeVqfUctLcKLHTJqLE+Q8+9gCAGDL3zepTaQZkLSE2vLmQm2o3fu
         ztWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=po0p5ohk1msq7wKQeRIM65cDGPmbReW1gkkuywj8DJA=;
        b=1uzWgId/KKpY6IB+Kz3TSw6SyZ/RSPxIxB7n8IZIHPfil1FqEI2BGiwjLAez4Wl8eT
         zDLa2vp4DSk9xRkZsHGBclP3oQWj5tZpHbuJEPxk2VtvQKD1c8ihOIzE7G7WS2YAvgLO
         DekHqSMf5mzFNCuTMIADhLgaBSe69L40hlq3beDvh31RaAlb6TjTCpFifxiPSOzfb7W+
         qXpn6V+0n6uPNKiD3lQBFe2zsR1s6YDgmM+p9Chf9X3tNxkO18Kku5t90BqCPQgHjyk4
         pjm4ImxFUroksxqX0c3umvsuK+kNDdg5MgoUQ9XcxcKRTOJ2THt+p/S8q1TnXhwmGyr6
         nSPg==
X-Gm-Message-State: AO0yUKVwtYFuIF/mXAm0f5vfCuy1yUa57VRDQkNrbcw9Jn8cuGc/WVwu
	WJ4qPgKpXVugXgQr0Dd7nng=
X-Google-Smtp-Source: AK7set8wqZNh2zQrOwe/vIP0MNlO9Mzcy/KPhtokAoq5xzOBTf3wfmRaKi2kwqy7JPIL077KIR0wfg==
X-Received: by 2002:a05:6000:1088:b0:2c7:3d2:fa20 with SMTP id y8-20020a056000108800b002c703d2fa20mr2096094wrw.13.1677491504382;
        Mon, 27 Feb 2023 01:51:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d21:b0:3e2:1bb8:4520 with SMTP id
 l33-20020a05600c1d2100b003e21bb84520ls1290585wms.1.-pod-preprod-gmail; Mon,
 27 Feb 2023 01:51:42 -0800 (PST)
X-Received: by 2002:a05:600c:1c16:b0:3e1:374:8b66 with SMTP id j22-20020a05600c1c1600b003e103748b66mr13254278wms.40.1677491502811;
        Mon, 27 Feb 2023 01:51:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677491502; cv=none;
        d=google.com; s=arc-20160816;
        b=j89Pr1ejYDxSX4Ri5SwQHw68sgSqrMtnW14+8yKSCxsfgNsFWwEZiDo+dbCpwzn6bU
         6YuFJyue78nmsXebTcrR5X88Mz86ley4MabGQ240NQ3MW+6gwvRT13BDYhiSyxXIEuz1
         RVINjqD/JChX+ott78p/d7niB+8gC9tvdBSVrNIntsbDy2Hb3Jmhq3TQQ6LG/ZWOTLVp
         3+4yMzKOjLwpSTViNr2Cpv72pdOE8PdkGDk/YTnPKO8O4EjJjfELTQDdbXOVK9ErIeoO
         +/vdVUE0HIWOJMlVUQrMNkY6etkXLvXIzfoH2JQ0RGdJglpwq0MUcbW05caoH9PZ+8/d
         0A/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=vLAZSY9lX30lbRvxmgqsLOf9PyjLVjvwhzsapOvRcDY=;
        b=yGrr9bP3kGgOfDuLGIil7VCn89YsmQnHLCVSc7vyDcN4Dj4ASXFtTxlGlmkj9W1Uie
         OpHplmHQ+oewJPx8M5j3i8vlHswQRTNv8KIZbmJ/ld+G2JeX6I9xRYw5mDH4Nkfmn+eB
         /OAvoG1sbnDYrABBzeMrfCzYL5wtggvnNxLBp8mCXmysKqeWnIef6xSc22zliZwBxzyT
         CcBD95tWgv4gDfQ9QuQzdb2g99wYiLEv9jNwROAXua/k8halNpdQwTiHTrloiwXKCm23
         J/JeYviK6s1U6QBguHTB0xWSQZHdo6Z0JXgFLhE8BCSfbYaHV4Vd74fqLNLZNuqmyUWf
         SYnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kMaj71Vf;
       spf=pass (google.com: domain of 3ln38ywukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Ln38YwUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id l2-20020a05600c4f0200b003e21b96f27asi349741wmq.2.2023.02.27.01.51.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Feb 2023 01:51:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ln38ywukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id dm14-20020a05640222ce00b0046790cd9082so7781086edb.21
        for <kasan-dev@googlegroups.com>; Mon, 27 Feb 2023 01:51:42 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:1a89:611d:c416:e1ee])
 (user=elver job=sendgmr) by 2002:a17:907:60cd:b0:8b1:3540:7632 with SMTP id
 hv13-20020a17090760cd00b008b135407632mr5583442ejc.2.1677491502399; Mon, 27
 Feb 2023 01:51:42 -0800 (PST)
Date: Mon, 27 Feb 2023 10:47:27 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Message-ID: <20230227094726.3833247-1-elver@google.com>
Subject: [PATCH mm] kasan, powerpc: Don't rename memintrinsics if compiler
 adds prefixes
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Michael Ellerman <mpe@ellerman.id.au>, 
	Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Liam Howlett <liam.howlett@oracle.com>, kasan-dev@googlegroups.com, 
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, Daniel Axtens <dja@axtens.net>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kMaj71Vf;       spf=pass
 (google.com: domain of 3ln38ywukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Ln38YwUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

With appropriate compiler support [1], KASAN builds use __asan prefixed
meminstrinsics, and KASAN no longer overrides memcpy/memset/memmove.

If compiler support is detected (CC_HAS_KASAN_MEMINTRINSIC_PREFIX),
define memintrinsics normally (do not prefix '__').

On powerpc, KASAN is the only user of __mem functions, which are used to
define instrumented memintrinsics. Alias the normal versions for KASAN
to use in its implementation.

Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.com/ [1]
Link: https://lore.kernel.org/oe-kbuild-all/202302271348.U5lvmo0S-lkp@intel.com/
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 arch/powerpc/include/asm/kasan.h       |  2 +-
 arch/powerpc/include/asm/string.h      | 15 +++++++++++----
 arch/powerpc/kernel/prom_init_check.sh |  9 +++++++--
 3 files changed, 19 insertions(+), 7 deletions(-)

diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index 92a968202ba7..365d2720097c 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -2,7 +2,7 @@
 #ifndef __ASM_KASAN_H
 #define __ASM_KASAN_H
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) && !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX)
 #define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
 #define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
 #define EXPORT_SYMBOL_KASAN(fn)	EXPORT_SYMBOL(__##fn)
diff --git a/arch/powerpc/include/asm/string.h b/arch/powerpc/include/asm/string.h
index 2aa0e31e6884..60ba22770f51 100644
--- a/arch/powerpc/include/asm/string.h
+++ b/arch/powerpc/include/asm/string.h
@@ -30,11 +30,17 @@ extern int memcmp(const void *,const void *,__kernel_size_t);
 extern void * memchr(const void *,int,__kernel_size_t);
 void memcpy_flushcache(void *dest, const void *src, size_t size);
 
+#ifdef CONFIG_KASAN
+/* __mem variants are used by KASAN to implement instrumented meminstrinsics. */
+#ifdef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
+#define __memset memset
+#define __memcpy memcpy
+#define __memmove memmove
+#else /* CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX */
 void *__memset(void *s, int c, __kernel_size_t count);
 void *__memcpy(void *to, const void *from, __kernel_size_t n);
 void *__memmove(void *to, const void *from, __kernel_size_t n);
-
-#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
+#ifndef __SANITIZE_ADDRESS__
 /*
  * For files that are not instrumented (e.g. mm/slub.c) we
  * should use not instrumented version of mem* functions.
@@ -46,8 +52,9 @@ void *__memmove(void *to, const void *from, __kernel_size_t n);
 #ifndef __NO_FORTIFY
 #define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
 #endif
-
-#endif
+#endif /* !__SANITIZE_ADDRESS__ */
+#endif /* CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX */
+#endif /* CONFIG_KASAN */
 
 #ifdef CONFIG_PPC64
 #ifndef CONFIG_KASAN
diff --git a/arch/powerpc/kernel/prom_init_check.sh b/arch/powerpc/kernel/prom_init_check.sh
index 311890d71c4c..f3f43a8f48cf 100644
--- a/arch/powerpc/kernel/prom_init_check.sh
+++ b/arch/powerpc/kernel/prom_init_check.sh
@@ -13,8 +13,13 @@
 # If you really need to reference something from prom_init.o add
 # it to the list below:
 
-grep "^CONFIG_KASAN=y$" ${KCONFIG_CONFIG} >/dev/null
-if [ $? -eq 0 ]
+has_renamed_memintrinsics()
+{
+	grep -q "^CONFIG_KASAN=y$" ${KCONFIG_CONFIG} && \
+		! grep -q "^CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX=y" ${KCONFIG_CONFIG}
+}
+
+if has_renamed_memintrinsics
 then
 	MEM_FUNCS="__memcpy __memset"
 else
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230227094726.3833247-1-elver%40google.com.
