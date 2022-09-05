Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7OV26MAMGQE4CJI4JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id EA9855AD270
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:37 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id b17-20020adfc751000000b00228732b437asf572115wrh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380797; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z2PU5qiQjqcpKtqtNnJHh6f/BQMq5sHjQ2rJyXXSFW7I0myh5l/8Z1Quvcmom665ZQ
         wXVb98RrzsSyJMn5qjS3CF9ywF7rM6xJWWuI9tq23az66i9+bnSpwXzxCxNEYiv57l+i
         zjHPLJg+Xkw2IkXEv5gW2H/RPakgiNaVd+BZpEekVDMoLW9v/IlNag+T8CH66kjRHtw8
         eWZkNgGfe5oLBgu6ljaeWu8z3bvumF0ohCHauXOznEAGYf8SsaIcU0bLE+R6iA9GB4gP
         0jWTDqEBSzaElFN6ppPxYTerw4MGZqrnj2PvqoHvRCaCkoKRVCcD11txciy+x2UUz3Pr
         u2Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ATPMe0C21ez11zn3Qai+ItrTl5/AvQHtpiO36x+GF8g=;
        b=F1VKdZeokp2vj3swHqfguZ626qVNa+eFD3tGt5+4W9y4b6jJ6eP7kJk0lBzPzTOspj
         S+s+Ku6qIkntfDefu6SRUu3Lmm9IxztUMOeJF1TvGQYcPpEZaRs9Z7sPEuAlbWYvO5Di
         LjFKO9RNW01+XnRpzIWM1owMHa83/QvoEtsFbNMErCerfsRR2ySerLOXtJNN76yAExH5
         ExF0wNXeYWN+ciWV4LeXz8YLBT8UFV9q6wa82/vASTo75mt9N8TXuBc5lQqhbXbcuY6u
         0j6kRwR1LV4ug8MwYEjsQaAB9M43hVmLJori8dfuC5iTc30d1NH5RlSEdBbFQqtoQPbB
         s/Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bu0u5tzW;
       spf=pass (google.com: domain of 3_oovywykcukrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_OoVYwYKCUkrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=ATPMe0C21ez11zn3Qai+ItrTl5/AvQHtpiO36x+GF8g=;
        b=LWndDkxVz93G4Atf/PBt1Vq7iUyOvg0khsS49l4pl8KZEUIfSelPDFJOJyhSth1AuD
         RSDgcCitT9SOZW6OdYj+CeqyXEtF0A6Bn5yg2eUIeAVNXZRd8FBKiM6WIAAgMvoQUbEE
         YuTjT8z60T5LP+jZl+PSOXYUkzslCTWPK41XkPkcjh8G4b3jkY/WbmOK+y+S5srBxVuv
         Ig6nnHwMzFYKSGxlcUc5EVP1BLoaQBtiEejwn/E9skLd3pZr33v3zRn8nseImGCYt3dD
         mI913lqcyynbv0nzBaJsW34EnoithT4Z8mH91+MhsqIKCkW7VhGcQOVUaVITa6/Srzdn
         FUmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=ATPMe0C21ez11zn3Qai+ItrTl5/AvQHtpiO36x+GF8g=;
        b=rqhPXd5YZXQUKIu7EdmhVA3je5yE8kWo3lV11kPx1Y4DZkrtmdXw0m+wdoPLDtz7Yy
         NBVpkCp9SJ9EC6jpOrtuWOYlzeNeLMxnwEa8ryY7s41qCvIDo98287iHpxG6l9M0Owun
         xsh0N9IRl5EsLBgFvDvUCRYNUj6ZwucjzLB7DqoQDmGbK3aVVCVY3n/b7QztVNH6gvU5
         GhlA4mZqB8DEiSiQuBpgMeJ+iyBnnrH0on2QhKxVKFEs3k+hy0A8QyI6MZj3D3pCl2LQ
         PFTS6Ve5zfWXWd+HGcDYl1SoClUMoOn99yBIfh5jthI7JWAuxhf8/d46cfbENWFwgR0Z
         YGzw==
X-Gm-Message-State: ACgBeo0ywAGmtk6XAjE6j2A9ruXdxVKP7AGaopOQhCC7r7bkjKaNOo5W
	WoqvAd5nSI+gFKTaIgEYfcI=
X-Google-Smtp-Source: AA6agR4TLHLjjj5cyrnBdXg+F6PIPAQwSTfpQuNhrB/8MgFlZdJWIFEUryYb4PfwgfLOYuIBpzbDeQ==
X-Received: by 2002:a05:600c:3790:b0:3a5:435d:b2d3 with SMTP id o16-20020a05600c379000b003a5435db2d3mr10824512wmr.134.1662380797650;
        Mon, 05 Sep 2022 05:26:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:257:b0:228:a25b:134a with SMTP id
 m23-20020a056000025700b00228a25b134als3159823wrz.0.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:36 -0700 (PDT)
X-Received: by 2002:a5d:47a1:0:b0:226:ebfc:f759 with SMTP id 1-20020a5d47a1000000b00226ebfcf759mr14475409wrb.636.1662380796801;
        Mon, 05 Sep 2022 05:26:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380796; cv=none;
        d=google.com; s=arc-20160816;
        b=CaIcMYWqsYdOVB2k63vQisOhOE/7IGLozL4linQ96z3KhWL1gRIcVwKu3lPpv1/6GY
         ApwYGoDSznQzU7dOCrX6oOuSbn5i8OrNIzKNq4aogpyvNnY5TmFC1wY6yIqS3SwFMPrs
         cmCrJ6yYckbC80MLXVQpVcLEkCnYj9pnmuNUPHCCogQcp/KjITTVXajMQ17EkDeYmhQk
         GAAqobNdTmNJpR7FFGJz6vqOYgXDSyDgEr3/xM5AF+JjZi97Gsk7SkbsQe859gDOXB1u
         BbrIHH3EKHsDBHdAQQn9jwlo+CVFchF1x140O2dKjciti8V5MHfITFgD6McBHNf7PyhX
         nfnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=s0jAEbnxevXU2w5QvhShkO+su70yEEyH0HIO5IJWDY4=;
        b=LkvYpPWZpLmtAIhg3QOE/EoU705uFmTBcs34vTJZ7RNa4IlupTRuDOWrluYFaZBZwm
         E10uq8LNcXOeUxBoc5bM2k9r2X1rK15gKqFplz5IHkHb5DuIlbguD87LAA+Pj8WziPYw
         imbErMFvRE7pl2MHqJOH1msuZZeuJIKhOgoYpdNr9c3qag0wLl9OCNKX7DFmAXKJG/BW
         zIIQwp1vyIbXmzNlZceJg/Fji0y3VCXdDh0K/pfvhRWi2n0M5Gbe5gQWCwUT2yZ+fd6k
         +21U0DbMusYjVBWzHNmR464h4jmAYYL4+vGRcUt7SXmPkyu44Zg+VXIolOKKXg+h2zd7
         /29g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bu0u5tzW;
       spf=pass (google.com: domain of 3_oovywykcukrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_OoVYwYKCUkrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id az17-20020adfe191000000b002206b4cd42fsi358595wrb.5.2022.09.05.05.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_oovywykcukrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id hs4-20020a1709073e8400b0073d66965277so2236420ejc.6
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:36 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:906:8a5c:b0:73d:7f4a:b951 with SMTP id
 gx28-20020a1709068a5c00b0073d7f4ab951mr35092641ejc.481.1662380796421; Mon, 05
 Sep 2022 05:26:36 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:44 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-37-glider@google.com>
Subject: [PATCH v6 36/44] x86: kmsan: use __msan_ string functions where possible.
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
 header.i=@google.com header.s=20210112 header.b=bu0u5tzW;       spf=pass
 (google.com: domain of 3_oovywykcukrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_OoVYwYKCUkrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-37-glider%40google.com.
