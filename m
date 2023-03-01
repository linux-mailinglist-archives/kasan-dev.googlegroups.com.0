Return-Path: <kasan-dev+bncBCCMH5WKTMGRBK6H7WPQMGQEZHYN3HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 930CA6A6E92
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 15:39:40 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id f8-20020a056512360800b004b8825890a1sf3814554lfs.1
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Mar 2023 06:39:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677681580; cv=pass;
        d=google.com; s=arc-20160816;
        b=oFW74OdiImq5BheeYMNwG/Na3cmDfG9VifgGG9pKjZ+Txec0kBvz4yMwt4zwmBa0FB
         QT97nIOo0vcD7Arug6L8Nx7QnBZDPSOPzrCWDE9LsQRx+XHOTTr3xJT102MczBgCi1t1
         U4eCNUBcHDg2zjj9r62smgJnEXdrYHyxFWKAHKhmv9ElbBpt8eaQ2o+dseu2071yd+e0
         kT+tMQYvdr5At65ZT2oa4pzKCyRjfT3UMnrmAYANHM+jX11i2bs/DNlP4Tyrt6PQtE31
         JJf66IywhUW5F2XIbAwj0HGLhswwQ5TujJERs10LzfveP52FQiQROhb7q05z8aDgXXbA
         BiNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=ejPShTtC6gq33xRmlJv6dEDFDk4IuQwA5u+DP3THyfY=;
        b=rS49Lql9z6JaOCCWxjupToSxAQr65eApiA7X7qLNs2SfYn3qhn0uLbgc5znSyT8DPV
         605p4JoLVt9j80rWyPDD3UAgJPNShwOB5Sgq9uQ4ZCHN65qh7DPriX3+trcIsURfGbIT
         ybvWVt6T+X/T3DREWHkXblQEDdv7YZda+xPQCITfLEjml+P/XMY8EdRt2+LVMrjHYfkX
         jqfm7Dp59EiwVfC0bqvj9sd17reMBbxfLhDmu2D69wn39ALgGr4gZcmw140baE93cqt6
         kruCDfvYqJdC9YJtjlmuy175BaeM2yi9XMpptmP55cTdQcxasbnuwSrwbw9s4pLrnzWw
         Iscg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hwwsMSyO;
       spf=pass (google.com: domain of 3qwp_ywykczq49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3qWP_YwYKCZQ49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ejPShTtC6gq33xRmlJv6dEDFDk4IuQwA5u+DP3THyfY=;
        b=NLBXzqGH3ijmgrltSqM59h8QlDB64GdFYqE+JtwH3zVRuNcnxi4Z3SmfQAOTs3H052
         JWg/QPcYf4JtiIm+jhShrijcadUd/Cw4QZqca48Fbfi1X8A/jjwaDvW2fFifXp2p/Nax
         gR/vGIhvruP/eyofSj00CJlgBfIoNIj1IMpWiH0O2QVoHEX+jijqBnKHeCUzOkXJi7/I
         DtCHVB2DYzDEFTmwwnvdC5Tp7m5GEAyhT9L3g7eK/dndcLfhhCCRgLPfDyBNuYKSuecX
         sy0HByO44LTMKTSoCIotsEp2bhOvNPTj+2WrSlSOE5Z/dwXB+x6aV9hJJGWmtOHlOwXp
         327Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ejPShTtC6gq33xRmlJv6dEDFDk4IuQwA5u+DP3THyfY=;
        b=SQ1+o1UKafAnPjA/a881DtDUVR3aBU/ohgjXLvQJDRH7LHxAd+MUn3qF+EPNBsV870
         brETKX6xeqJzXf7S6vSbGNavB3vJutsYqxQpd3I0Hh/lGfyB/IFzsVN48ll0Wn8CoViU
         cyPyPG0kMfrQzObt1AQ2qSL1OuYVpv2xl6CgXbkvJw2g/Vvp52d1cJgHbc1ObFyvq6L0
         B5YP5F8G51CTngkRoS0iKypts/bnk6rId1hAAk4Tmp3JyYfAzS3ksKbr6OqNDRHVcHUk
         TRZGIl5nRuYnxcAc9IZ/kkOAWrzCgsv62MmeLDJTJ3gdeaiXYL1R7CLBmUcyxzjChu1o
         gYCg==
X-Gm-Message-State: AO0yUKX3yJgBrcdShdCWJOW5rvzvZ6idEPSlzsJaAvFvBR8T4idiG2AU
	bDrP3EJW32RGZWt7njcXc7A=
X-Google-Smtp-Source: AK7set+oAtvY2EYQKtvsscR9U8TLVrC3RlbsMwpBKlLOf2HZtnYQJCAfpMTjyiHxpv7sbsPssfZ62Q==
X-Received: by 2002:a05:6512:340f:b0:4d5:ca32:6ed6 with SMTP id i15-20020a056512340f00b004d5ca326ed6mr3456358lfr.4.1677681579427;
        Wed, 01 Mar 2023 06:39:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4024:b0:4dd:8403:13fe with SMTP id
 br36-20020a056512402400b004dd840313fels287131lfb.3.-pod-prod-gmail; Wed, 01
 Mar 2023 06:39:38 -0800 (PST)
X-Received: by 2002:ac2:518e:0:b0:4b5:3505:d7f9 with SMTP id u14-20020ac2518e000000b004b53505d7f9mr1759005lfi.35.1677681577924;
        Wed, 01 Mar 2023 06:39:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677681577; cv=none;
        d=google.com; s=arc-20160816;
        b=OEcAEJn6ebfuk96fmu1ncuE+3w73wDhILY/hkyfHNtM/Pm6+tliciY5CHawOYcfOHM
         3DKh27exp+UTTUmdPfp5HsX2JFd3hvkSZyLbKP/fVAl5bJUVTTC2Wuka/rT9aTxE+4Sb
         qKroFypURIzep9SDr1aXUacuS5mGOP7fe4hsg22/uuE2A5pGMfTH633QIOrpu/lKpAmC
         GSOnzGpliZxnALD1/numsE7DeuqPF9V9mN+fD/uvAR0/tkvxvTDZLFu0XNRxF9XC/F8F
         ZHrcYonfg7LOtk3rfLXF+q2n6hc5Tmc43Pj3ydazSmSAQQh6GzMj0D74o6LCz6DrPlUu
         c+6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=JhZ8SEDoNzl+E2htjsUuUTMZqyHgHOmh7ac72ddETYs=;
        b=OGDvi9V+KSwgOG2dDdWiAXYl1jRLquXw0qg+tCLMKCqCUG5ZUn/QdaFoG9C3eswoo7
         clwoxrrZJUxugAv3FS/Mkk60QoAONovNp/VW0zFxqj7yIQ9qurnoJoOczMNDYB/lMb+v
         ++ksv6zfLlKQOq+nSsaviFTM7LTeTYLEWz3ZJeGRZ+KXOHobB3XezY72yrI8C/O4X8Ct
         8KdG/XKOTTvicT5lcrxVGQ1Zc8ZAz6Hm9bEAgGq5A6tqAQ7KwVu5K2cymoMM5SdwiUVZ
         2o0DOCTo6jQyi/rY5EYK/b0nN2k5cmV/Y3Nfo+zl0IT3mvZb8YMM729ebZIfityPog+E
         kA7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hwwsMSyO;
       spf=pass (google.com: domain of 3qwp_ywykczq49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3qWP_YwYKCZQ49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id o8-20020a2e9448000000b002959fe5ccd9si511671ljh.5.2023.03.01.06.39.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Mar 2023 06:39:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qwp_ywykczq49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id w11-20020a05640234cb00b004b3247589b3so16920031edc.23
        for <kasan-dev@googlegroups.com>; Wed, 01 Mar 2023 06:39:37 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:3c31:b0cf:1498:e916])
 (user=glider job=sendgmr) by 2002:a17:907:9491:b0:8ee:babc:d3f8 with SMTP id
 dm17-20020a170907949100b008eebabcd3f8mr5683794ejc.3.1677681577396; Wed, 01
 Mar 2023 06:39:37 -0800 (PST)
Date: Wed,  1 Mar 2023 15:39:30 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Message-ID: <20230301143933.2374658-1-glider@google.com>
Subject: [PATCH 1/4] x86: kmsan: Don't rename memintrinsics in uninstrumented files
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hwwsMSyO;       spf=pass
 (google.com: domain of 3qwp_ywykczq49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3qWP_YwYKCZQ49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
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

KMSAN should be overriding calls to memset/memcpy/memmove and their
__builtin_ versions in instrumented files, so there is no need to
override them. In non-instrumented versions we are now required to
leave memset() and friends intact, so we cannot replace them with
__msan_XXX() functions.

Cc: Kees Cook <keescook@chromium.org>
Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 arch/x86/include/asm/string_64.h | 17 -----------------
 1 file changed, 17 deletions(-)

diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
index 888731ccf1f67..9be401d971a99 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -15,22 +15,11 @@
 #endif
 
 #define __HAVE_ARCH_MEMCPY 1
-#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
-#undef memcpy
-#define memcpy __msan_memcpy
-#else
 extern void *memcpy(void *to, const void *from, size_t len);
-#endif
 extern void *__memcpy(void *to, const void *from, size_t len);
 
 #define __HAVE_ARCH_MEMSET
-#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
-extern void *__msan_memset(void *s, int c, size_t n);
-#undef memset
-#define memset __msan_memset
-#else
 void *memset(void *s, int c, size_t n);
-#endif
 void *__memset(void *s, int c, size_t n);
 
 #define __HAVE_ARCH_MEMSET16
@@ -70,13 +59,7 @@ static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
 }
 
 #define __HAVE_ARCH_MEMMOVE
-#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
-#undef memmove
-void *__msan_memmove(void *dest, const void *src, size_t len);
-#define memmove __msan_memmove
-#else
 void *memmove(void *dest, const void *src, size_t count);
-#endif
 void *__memmove(void *dest, const void *src, size_t count);
 
 int memcmp(const void *cs, const void *ct, size_t count);
-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301143933.2374658-1-glider%40google.com.
