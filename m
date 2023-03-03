Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUMBRCQAMGQENB3XMDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id EE4136A992C
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:14:42 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id o23-20020a05651205d700b004cc7af49b05sf1080218lfo.10
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:14:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677852882; cv=pass;
        d=google.com; s=arc-20160816;
        b=idNQXmYXCLCPY3evZxo4qhd7F/dEy7crXaz0SMy+uCZzYBiTQll+XUDTmxPo3jFKo2
         yYpbkAoB1KQrOKNzPyGa/pT2SAmE4OrtdYjRwlo1Xw60+1CAceCGe2UjyqZ1JgZ8NzM/
         bRXUnX5wHrxskRJbxPgyUGiYhJ/33OAM1l1LdmQ590pi3q4Hj6xRv/eEJGoZw/2Bq7Eq
         nerG3YQiBg/RJOqxv/eWIfl+oxgMl64Zj1Sh7rVB0YlcfOUZr73gWzE9D4r67YWKBVfC
         76SuIShvf55/mcZbObW3IzUDjU0ICxpN+qfVySh3qzO/PysfuJgdvrWui7t61QxRJHTw
         fuwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=rVsyHm/hKsfJmtDgmDjxKRm1ARph/ZNkCDGj6Xi26sg=;
        b=rrglT01PsWBDdg8/gb8ceixZ7tWOcDU7PU3489ARf3yyDX/mLhcust1KXpBpW2DHxG
         GmwXJWeXeITxKRq4JhfE+BbS5/MNtw9CPfTjwInElmavkt/+1z5aseWiQHnfX3ouilfB
         nYD0mgbjUA6GleMztbQ2Cmt4VPpPm9PBwtyEJOfTkgGbKS+TVhyii53YsA30fJjgCZE2
         UWsBIb+f4csnDZ6ZK3ZQYFDr+0vhCHzM6ZyR3BKg9vQOCmfrCxc3jnTKpoBq+amEmIry
         IjzehszpLlGBETuePgktU6aeKx5UjPyB5OJ8xufvde6GQ7IzcETn118C+ltBJfAoQOYa
         T3Ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hMY2yJzs;
       spf=pass (google.com: domain of 3zwaczaykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zwACZAYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677852882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rVsyHm/hKsfJmtDgmDjxKRm1ARph/ZNkCDGj6Xi26sg=;
        b=U8kuj/vA69bBjiyay7f1JQV9GzjyawsSREjyS+nj2yMXQ4zG+CFYM6PQ6/8RTDHeLp
         HZc79JBuSHoebISvYBM7lKjZ79NNu6FhCMz9vHiauK39/o2SKabRLkZKYRkEyOyyji3I
         SHeTuQdMM0hM5gsxYaLWuJg+hAYf/Lf0xgk+S34zUpyaR6TO6ltI/bpC9S0Uc7StagD3
         U8odp5VofcQLQCu6a+4H/YH91mBewG9qOzRAEiJ8gzaeCZeLF3Xmkt+XXrFtXmgfwbJB
         AGFTPmmG6u2Pwszl9YeU+fsiGClHsjr5SmFwVGf95qPAk3pzcnEkJj8gkqyzVx6QaMCm
         KhOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677852882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rVsyHm/hKsfJmtDgmDjxKRm1ARph/ZNkCDGj6Xi26sg=;
        b=wWqKxBVvm3Jo5HTcr75CozoMRmXpP4jvMxNs6XB2n7WyIcm+N84roCgHT/YrygdtSb
         ZMd7vCjOAbujopHpNN/JvDbq+wW4+mO/PIu1qsJoA8i80qRYF9OqruFpJnn+o7xDY6Xq
         qctzYNcsg4/SF5kUwFvI0rQe4GcZjyyjeqsMfvJMnw/KxVPMIK+zZyi57b9LACL9LT0B
         27XmF0EJ5WQTxUkRgy8xMQKRqRuu8tsRIlv70pyJQVFMBEkYYoPb7zK2PrYB36v2nAzw
         HS/9IcBxYuSIvAt9feQaiDJWBnZiv2tLKmar/2f5Sr4h2Cq2f+gkQ4qqePQllWqaM7Tc
         rXVg==
X-Gm-Message-State: AO0yUKX+wKki8jlByrlI5NH5zEEzEN6PASiGI8kOvrAOGSDWaMa8owa4
	CNZHtUz0LHKE0CSK1LxcI20=
X-Google-Smtp-Source: AK7set/mwaCUQf23PkHK/RIHqmpytP3iksSNajbQbG4Nx2dHAEikxzA+uJqg8VDO5tpcQ//A3LlEgg==
X-Received: by 2002:ac2:530f:0:b0:4db:266c:4338 with SMTP id c15-20020ac2530f000000b004db266c4338mr655737lfh.1.1677852882102;
        Fri, 03 Mar 2023 06:14:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1610:b0:293:12a9:1ca5 with SMTP id
 f16-20020a05651c161000b0029312a91ca5ls608705ljq.6.-pod-prod-gmail; Fri, 03
 Mar 2023 06:14:40 -0800 (PST)
X-Received: by 2002:a05:651c:313:b0:293:4fff:422e with SMTP id a19-20020a05651c031300b002934fff422emr547880ljp.16.1677852880474;
        Fri, 03 Mar 2023 06:14:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677852880; cv=none;
        d=google.com; s=arc-20160816;
        b=HC9JLySqo8S1YR9KuFUVe8ywEupd4YZ/2OhI1RMxQJ0kA8HtG5DZ59XkRdpQe9+Udf
         ByWNDQXupSEphaFzNgUwxcOf9I6RFBAhTqXk8P/cym64DT7bQdyOsanMoX3IMLJXfWnN
         P657j6NdcfWU0UIKVMv4nyo7ZqsnK2S1eBx9CrfEkAPvaJJWLdZxcw/QRouzd6HUgO85
         n1CAOqNVDijyLLahr/fUUswL1BUz7aJdiX6xEu73Y9o1HfcNZJ+f5pjtImru53iazwGj
         CglZserFDXK4i0295nZsyCyguZwn/xpGcOxfc+Vp285R0/PYlD8sh6Hr7+RwenZ04Kef
         bDbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=2N/CPy1IFmLQesHjkxJB5VDmlDO65TUQOL9xC78XNWQ=;
        b=XTbsbq9r31vi+wI1Xha0k+f72PSQeNyT1JRQd5hWQvhsdTHVaijwy7o5uq84+Yhd17
         PRKkhBsP1FO1a2SZ/OucI4F/BacADUQUEZ+jk07IqKQ1PN5HFxd1lW6C9iIv0Afo4QD5
         P0QuXTzzeMtM8MpVc7s9/TQY0OFVtk90ZKg+oQ4I+PkygDSXz4iZx7snK++2g87/RjlP
         XtwKiYuJkdzEsvIrOx6Sc/348A3EiqgcQNe5O/Gg7upYl1bPqrxQwES+N2tA1U25Fu5V
         5eG7kRnAuOij7eX5m4amTWVrfY40GTk2ysXJfwn6fDHHwDi/FNq5cRWPtF32RwPqMtVe
         1XGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hMY2yJzs;
       spf=pass (google.com: domain of 3zwaczaykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zwACZAYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id z6-20020a2ebe06000000b002934e1689b9si90407ljq.0.2023.03.03.06.14.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 06:14:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zwaczaykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id cy28-20020a0564021c9c00b004acc6cf6322so4097152edb.18
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 06:14:40 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:f11e:2fac:5069:a04d])
 (user=glider job=sendgmr) by 2002:a50:ab1e:0:b0:4ab:4933:225b with SMTP id
 s30-20020a50ab1e000000b004ab4933225bmr1157914edc.6.1677852879922; Fri, 03 Mar
 2023 06:14:39 -0800 (PST)
Date: Fri,  3 Mar 2023 15:14:30 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.rc0.216.gc4246ad0f0-goog
Message-ID: <20230303141433.3422671-1-glider@google.com>
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
 header.i=@google.com header.s=20210112 header.b=hMY2yJzs;       spf=pass
 (google.com: domain of 3zwaczaykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3zwACZAYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
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

clang -fsanitize=kernel-memory already replaces calls to
memset/memcpy/memmove and their __builtin_ versions with
__msan_memset/__msan_memcpy/__msan_memmove in instrumented files, so
there is no need to override them.

In non-instrumented versions we are now required to leave memset()
and friends intact, so we cannot replace them with __msan_XXX() functions.

Cc: Kees Cook <keescook@chromium.org>
Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v2:
 - updated patch description
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
2.40.0.rc0.216.gc4246ad0f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230303141433.3422671-1-glider%40google.com.
