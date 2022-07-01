Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOMH7SKQMGQEOPKDW5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id AB20956353C
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:58 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id u23-20020a2ea177000000b0025baf70f8a9sf501169ljl.3
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685498; cv=pass;
        d=google.com; s=arc-20160816;
        b=btRFeCeqjfD3GwChUr3Uo9nIksfy1MAO9o+98Tu3q4l9ZSsftRV1Lcha0ohKk+nAug
         npwlc86P7Tl96/XykZ4rbbrv+PXdeorRbjXQnIaLRRbrqbxg8bwE8M8Tf0SNYHrgvw8d
         OcOnae6qkO920DhNRvdWXOJ7bYE5OLNDBEKTomk57j72uEBWiG3/+k0tRIZm1/SafphA
         J3IOg0eOWAj4YL1xghStS1A3yav+GVWwlhUWSVhLIeZyNeaOpVVr5hb57KHAYmkY958U
         TbkUnS2b0SX8x4TikfKgFy3rz+1n9mczgqnF1w36MHT6X/4VF3MI4JXjKCczMV5kinDj
         6b8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qL2aHC8bp6DMw0JGvnHSv/cbTn/DPDEg2iPO95LKuHk=;
        b=JkaTt3IZQqrx6fBlRkjs16PxVLPueUcPvD5Oib9kkiKpdHRkhhIGxM834qujz/B+OP
         U+gdceaEI+Iz6zCBR5vXo64nrBEKjKJgXumczF/u9HHCc3Lu4KNzREtJIyOF1fDifpPB
         sBnqizJgHi6G20T08H6viWbVPDrxXdtKxk1hJ6fQL/+74WfsKztiWCZYr4n7Fhl3HUjG
         amyN7/8L3dBdrGc6fvD1BXAAGGlnS+bJlD4NC98DBtu8Bbo7PnFYqrt7JlO8DgAZxJQ/
         7oyZ8y2X5mT8sWvwjPW61g6V9B1qK0q4xBydFmDrOHJpKavCwdjysShZtLniXDGyET2P
         /5zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JFjDqoVx;
       spf=pass (google.com: domain of 3uao_ygykcdc9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3uAO_YgYKCdc9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qL2aHC8bp6DMw0JGvnHSv/cbTn/DPDEg2iPO95LKuHk=;
        b=IlasD0ss5evnmbQoCG8ZbriBA1BmXQblQqXhy50WKDQXF1UmWb6OJyJtco0mWbgLas
         OOAOmEG5mU9fg8bNEMGAO0XiOtXr0xkSdobe3+gFwc96qBWRLQiqTs86/+NPCbgGacaR
         nQYYpsZ2yWpEweWbdx2c/P3eWSk5tdtjeGJdrxutbO5fCBVEg8rae7HTmaxUgYFOCBIB
         wPMp7duAjw7ijmy5Bl4So6jorn+3kb7zJ3U8bLwO0xe6JSX2RTfP0wNmnswKr6J4Jy4E
         GvQLtFZxDf/fqp/uXght2pfdZ5pwHkVCA7hAr4Ps6Jr/A03K4ynbISq4Sl292+5nFDB3
         qmqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qL2aHC8bp6DMw0JGvnHSv/cbTn/DPDEg2iPO95LKuHk=;
        b=XfFzfKXp3SHkzCDPApY6C/nR82tzK68Ce1tlPxz0uU3BV7ccqI7a0ID27UntCQqIeF
         kqlIiQ4Ts7Deu3U3qGjqMKGpPoiwphwIt+KqrvcoRaWmNIFnhgtH7fUHznEBA5X3rSKb
         EbUoP/jaMlhD8MjVCNdyzeYkh8uudMMw1YDxw8KN5T1fxg9irgv0CSTN7K94/H98I4Hv
         HnUZr+UhdlElp3eS9fLW1Xc0rpVijg4eNZghjVuZ3DrHx3Rl18Xyc4HfwM3L5vJxZF8b
         3yzWE6wuBWShGdz9k8dLL74y38TDj6vVO+Rr6bXo9ChrSRD5VD3E1RlCKx9gJ4dCEnqA
         FwMg==
X-Gm-Message-State: AJIora+iG0rGJDEcdchxUQe7mcU1QUJxKrQzUTwVsIbrGg5zpXlTt2I4
	o1AMIrJ8oEXTcZ/9pVTfL3A=
X-Google-Smtp-Source: AGRyM1tWlJNRTbt2ZiEYUrJeUfHo9a56UoXF8xqVQDbiFRImt3kDG2M0wQAfQbkUTavVA+xIAFmxSA==
X-Received: by 2002:a2e:8e8c:0:b0:25a:76dc:e4e8 with SMTP id z12-20020a2e8e8c000000b0025a76dce4e8mr8400836ljk.529.1656685497988;
        Fri, 01 Jul 2022 07:24:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls88652lfn.2.gmail;
 Fri, 01 Jul 2022 07:24:57 -0700 (PDT)
X-Received: by 2002:a19:9104:0:b0:47f:7a7e:140b with SMTP id t4-20020a199104000000b0047f7a7e140bmr9063538lfd.40.1656685497009;
        Fri, 01 Jul 2022 07:24:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685497; cv=none;
        d=google.com; s=arc-20160816;
        b=SLkYgkEJMSv1SP/yCcyN17Gx5JgzE+qiirL53QlNiS2wL31Hz2frKJPvo2DB671M70
         Z3l03hEO7teCcjnqdvMA1vPeHRwtdLRglkzWwe1XlAQS0mWZyokuUJaylp4moq3aifSc
         yVsqSpM/iAkaz/phVJyHDwOaq4lujoTBzz6eofBdeHK2gwo0xpwFaKuXWFglam81nStF
         WyeZHMBcIIajWk04jM+74/bG9+TvPKWCi4pO0tqjKVnnDJoewgEWtsH7sR2paRnDDZ1n
         W0zylJDcN4nNThM4NLJj+YCZpRHWobhpwOO1Qfr9R1GSoHjsUR7D0BpcG8Fblz1TzATt
         CDcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=y2vNDbHfnK38Naadc3+Fwqq63OR/g0K1wBY1TqEXyAM=;
        b=pQDU9Nwr4DAmse/AjpmZsjq/Yyas+FeJI3IMyUrb4OmzSQqkEYi8nhTTozNCB4xrZ4
         PwZh5+VDpgpKXJPvmgd5nLwlKa5KQ3P+sxnWqODQ7y4v2BOKgCqkcAh2GpIlXR8qxTGu
         JqLsD9pP3cYbNB+c0MQzDbpYZ8PgRGlpyam7iLrBO/8iDS2hJD6O/tCB11o3amLUwK1Q
         +moGWlN1uCvfvL7bRsa8EQw3nKh1VEMe+AbsWQU3+FP+C+z0IfZGKbHAihJEStSuV/aI
         m+5oRXRslt5FFObDsYM8ovbix2FHLz26bIjiG2Kn9HlPzHeyn2U0r0oU5uQrP92lGB40
         aVvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JFjDqoVx;
       spf=pass (google.com: domain of 3uao_ygykcdc9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3uAO_YgYKCdc9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id m7-20020a2e9107000000b0025594e68748si982297ljg.4.2022.07.01.07.24.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uao_ygykcdc9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id 7-20020a170906310700b007263068d531so846227ejx.15
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:56 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:aa7:c9c9:0:b0:431:962f:f61e with SMTP id
 i9-20020aa7c9c9000000b00431962ff61emr19491774edt.189.1656685496470; Fri, 01
 Jul 2022 07:24:56 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:01 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-37-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 36/45] x86: kmsan: use __msan_ string functions where possible
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JFjDqoVx;       spf=pass
 (google.com: domain of 3uao_ygykcdc9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3uAO_YgYKCdc9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
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

Unless stated otherwise (by explicitly calling __memcpy(), __memset() or
__memmove()) we want all string functions to call their __msan_ versions
(e.g. __msan_memcpy() instead of memcpy()), so that shadow and origin
values are updated accordingly.

Bootloader must still use the default string functions to avoid crashes.

Signed-off-by: Alexander Potapenko <glider@google.com>
---

Link: https://linux-review.googlesource.com/id/I7ca9bd6b4f5c9b9816404862ae87ca7984395f33
---
 arch/x86/include/asm/string_64.h | 23 +++++++++++++++++++++--
 include/linux/fortify-string.h   |  2 ++
 2 files changed, 23 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
index 6e450827f677a..3b87d889b6e16 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -11,11 +11,23 @@
    function. */
 
 #define __HAVE_ARCH_MEMCPY 1
+#if defined(__SANITIZE_MEMORY__)
+#undef memcpy
+void *__msan_memcpy(void *dst, const void *src, size_t size);
+#define memcpy __msan_memcpy
+#else
 extern void *memcpy(void *to, const void *from, size_t len);
+#endif
 extern void *__memcpy(void *to, const void *from, size_t len);
 
 #define __HAVE_ARCH_MEMSET
+#if defined(__SANITIZE_MEMORY__)
+extern void *__msan_memset(void *s, int c, size_t n);
+#undef memset
+#define memset __msan_memset
+#else
 void *memset(void *s, int c, size_t n);
+#endif
 void *__memset(void *s, int c, size_t n);
 
 #define __HAVE_ARCH_MEMSET16
@@ -55,7 +67,13 @@ static inline void *memset64(uint64_t *s, uint64_t v, size_t n)
 }
 
 #define __HAVE_ARCH_MEMMOVE
+#if defined(__SANITIZE_MEMORY__)
+#undef memmove
+void *__msan_memmove(void *dest, const void *src, size_t len);
+#define memmove __msan_memmove
+#else
 void *memmove(void *dest, const void *src, size_t count);
+#endif
 void *__memmove(void *dest, const void *src, size_t count);
 
 int memcmp(const void *cs, const void *ct, size_t count);
@@ -64,8 +82,7 @@ char *strcpy(char *dest, const char *src);
 char *strcat(char *dest, const char *src);
 int strcmp(const char *cs, const char *ct);
 
-#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
-
+#if (defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__))
 /*
  * For files that not instrumented (e.g. mm/slub.c) we
  * should use not instrumented version of mem* functions.
@@ -73,7 +90,9 @@ int strcmp(const char *cs, const char *ct);
 
 #undef memcpy
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
+#undef memmove
 #define memmove(dst, src, len) __memmove(dst, src, len)
+#undef memset
 #define memset(s, c, n) __memset(s, c, n)
 
 #ifndef __NO_FORTIFY
diff --git a/include/linux/fortify-string.h b/include/linux/fortify-string.h
index 3b401fa0f3746..6c8a1a29d0b63 100644
--- a/include/linux/fortify-string.h
+++ b/include/linux/fortify-string.h
@@ -285,8 +285,10 @@ __FORTIFY_INLINE void fortify_memset_chk(__kernel_size_t size,
  * __builtin_object_size() must be captured here to avoid evaluating argument
  * side-effects further into the macro layers.
  */
+#ifndef CONFIG_KMSAN
 #define memset(p, c, s) __fortify_memset_chk(p, c, s,			\
 		__builtin_object_size(p, 0), __builtin_object_size(p, 1))
+#endif
 
 /*
  * To make sure the compiler can enforce protection against buffer overflows,
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-37-glider%40google.com.
