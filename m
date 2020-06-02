Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAF43L3AKGQECDDJ5LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BF6AC1EC20B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 20:44:17 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id r24sf7417964oos.23
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 11:44:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591123456; cv=pass;
        d=google.com; s=arc-20160816;
        b=ua9qRWRD+HAtUx+BLqb9BAQfa6UkcXk7/RWyg4FeXYxL3CTAYRJUzymxvPNBsA7PB4
         40WmUcNtJvDwWgOc41oUwkIfcFqOb9Di99FP6QU8j/WX4KWLuKG/iN6gz1SdZcLNwAd7
         wA5+dDCcmFAvALwulCOxeQehknxXbIbnQU/6bbbZ9t8VLQ2arfG0T4iTxMaLa1iGvXGe
         tR8VpqXn0/a1Gp7mu3pQWGQeQseRGn1lZ4fFsF4fn7ueXXHfNy4YhUwkm/JpwB9X/9EP
         QkXEcj8NN2ilohtTecY5HrXPUwwZfnAlokBB1mcBHKslnyxa/a8n/QZi+jjlxSlrO5vH
         YeHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=1TFipRQuL4G7scjPjsvydTZAJIdWSgv3ZzYpvVkx2VY=;
        b=E3lF3/OVm3/bXlnflRKSNoWXrltwEjEEbv8aGT4pLCp0QoRwcLLVfZ8e7o4ecMDpwa
         0rsqz7xAkVV28lug/gBwnoH2Mn7Umi4GgTmVse+71KY6PPkdpWytnPoUMAd9pZMd1cOw
         yo/W9UIWa+DxZB/eT9oeJF49k4hqTSKmInd6+6oJjktOgFhEpjC62FeJbVRHORiycl2X
         SAq9/eF9j7rJ2ls9fpfEeehDsg0vD3MOMnaxcjTiSf3C+NZch6scsDUG9H4FXOU6QMHf
         RztRVhYU5UsCoW0vj9bUBwi09Ft1iBDRfbbbGZHLqOO9uensheLs7z4kEfHlOgmvsuM2
         N35A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ih+cI902;
       spf=pass (google.com: domain of 3_53wxgukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_53WXgUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1TFipRQuL4G7scjPjsvydTZAJIdWSgv3ZzYpvVkx2VY=;
        b=D99h2av3rdjU7AuTb1aTDESk6QM8RaYqF7RGausk45zMpEzgwFIZLRfW0kWtDVFm2u
         gBzxLM3q8hKSgqHle9/gAJGmsfeRTqzLtDRVIcVxRceMjnOhiIelQQ0uHL0/xbCyh4Fh
         Zm0kT9WFr/mN6Ucu3PJsnUJOmz7Y9zHT/RjXv3wkHN9AgKK/g8Apr6gLrg+9IoUhToB4
         9LILuNWINbiYsuHwTsyJiEJ5WeD8hZQLtyMq2LQz3d9wm3I5vs68eI6KzLxnSlRlAPZP
         h5ZIMHCMzvoEVHoH1TWefiC3Jzd946ypvCqacWmlR0l0bW6DMM+MsFwHgQl71B8EZy+i
         dmAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1TFipRQuL4G7scjPjsvydTZAJIdWSgv3ZzYpvVkx2VY=;
        b=GVfYwiAEA1KPNoeAm51lvJ0HjfdioE4NklTVD7hJW42ILDSWAUKqKP6nr8TQTDmVtf
         lWvy1LZzzMnwwHovJsK2g7xH8FseX9Hk1TeDD5OX0LxEeobVXoWinOyLOjrT7yefIe2w
         g20zmuxZ0tXo0nyijiFXhBriwhRd1BsUEeJElBi4IjNnZSIoo50eRtist55rfs3JEM5p
         dEuLNslhQZfZeqr9dXmExPMDiznRldAQBjjv7TtXMEE00pQcVmS8nFRiM/5hZ+7OxGdk
         NlUHHNk05jYOGbKv17dfW8Mmy1iYqFhAhfxbrWJrcLgVpJhxINreysFF97JPepHX0Iu+
         Zucw==
X-Gm-Message-State: AOAM530TatQhRj1CkCoHbK75BlfHa/wrVSS+5MyMnShEXSryQlK48uu2
	R4fosr2+VoFnr1qYQIFksXI=
X-Google-Smtp-Source: ABdhPJwHWbmctpxj9L+gE0fMflD14XCfrh950hwBsNIqVOIZGHG3egibyb+f9tpFxEu28vb54vvXpA==
X-Received: by 2002:aca:528a:: with SMTP id g132mr3894809oib.113.1591123456718;
        Tue, 02 Jun 2020 11:44:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:494b:: with SMTP id w72ls3312768oia.4.gmail; Tue, 02 Jun
 2020 11:44:16 -0700 (PDT)
X-Received: by 2002:a05:6808:ce:: with SMTP id t14mr3907428oic.59.1591123456333;
        Tue, 02 Jun 2020 11:44:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591123456; cv=none;
        d=google.com; s=arc-20160816;
        b=Xrbc+2XGySsR0WSAlje4XsgEyRb3JroLwiSJkz1OOqavkbhH3y+zMcdbhk0w8VszSb
         iXGQzJTPAmJEIsBpUSTk5MrUtAb3o7L9bUiM4325mCFOYLltV3Gd8FkesZmImDyv1xmN
         rHia0hQvR2zrB63QB2YSMux3qIdLG3S8MkboP89OFP5zYU5YxX8DxpUxdIr4Fh1VGC42
         rgpxXqd98/wy3gXkKdXat6Dhng/FaJlL68TyeKq9kFR7Vu23cJP2px1KtLMxc0eo00nP
         bLzVW/0x3mvt4L6CLNgutsADDGyEvY3lRnsiZJH7qq37Mo4T7ZdWWqXz8Vb/mFbyi6/C
         B9VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=+FgmqyrmNJ7X96y+2DvYBXfBfS1ICd8c/t7BA8+xtfg=;
        b=vShQXkD1aOvC8OBRfb574GMh5bZjfMHE/tfTkreHfLP1mBYx2wWCJBjhzbb0Kldupq
         ZO4oSLe65PxE+n4W3oijOxuLYjbUCTEARtno32R696IBbCczZ3diLfR/i1X/i5VMiikF
         mS+Mi9yaa7E/3dfNfR35MGQRaoP6443UqnaAGUpLdqOlyTdRetLGKZqdkVa1e5/gWspu
         hR7BrpoyOBHeBs+4hQ2CCQV8A7j0QWap6QFYyjH1YC110+AEdQJo4VI/QAnxDYUoUDmR
         skzHbOUT/bVSiLS8A1QMk/SrZKIi9hGKfrmsinvL7Zq8WvH9wAJ53qHnaJALzuQ7twRQ
         kYQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ih+cI902;
       spf=pass (google.com: domain of 3_53wxgukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_53WXgUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id u15si349592oth.5.2020.06.02.11.44.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:44:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_53wxgukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id g15so2922537ybd.20
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 11:44:16 -0700 (PDT)
X-Received: by 2002:a25:bdc8:: with SMTP id g8mr42893731ybk.122.1591123455849;
 Tue, 02 Jun 2020 11:44:15 -0700 (PDT)
Date: Tue,  2 Jun 2020 20:44:09 +0200
In-Reply-To: <20200602184409.22142-1-elver@google.com>
Message-Id: <20200602184409.22142-2-elver@google.com>
Mime-Version: 1.0
References: <20200602184409.22142-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.rc2.251.g90737beb825-goog
Subject: [PATCH -tip 2/2] compiler_types.h: Add __no_sanitize_{address,undefined}
 to noinstr
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, clang-built-linux@googlegroups.com, paulmck@kernel.org, 
	dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ih+cI902;       spf=pass
 (google.com: domain of 3_53wxgukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_53WXgUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

Adds the portable definitions for __no_sanitize_address, and
__no_sanitize_undefined, and subsequently changes noinstr to use the
attributes to disable instrumentation via KASAN or UBSAN.

Link: https://lore.kernel.org/lkml/000000000000d2474c05a6c938fe@google.com/
Reported-by: syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
---

Note: __no_sanitize_coverage (for KCOV) isn't possible right now,
because neither GCC nor Clang support such an attribute. This means
going and changing the compilers again (for Clang it's fine, for GCC,
it'll take a while).

However, it looks like that KCOV_INSTRUMENT := n is currently in all the
right places. Short-term, this should be reasonable.
---
 include/linux/compiler-clang.h | 8 ++++++++
 include/linux/compiler-gcc.h   | 6 ++++++
 include/linux/compiler_types.h | 3 ++-
 3 files changed, 16 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index 2cb42d8bdedc..c0e4b193b311 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -33,6 +33,14 @@
 #define __no_sanitize_thread
 #endif
 
+#if __has_feature(undefined_behavior_sanitizer)
+/* GCC does not have __SANITIZE_UNDEFINED__ */
+#define __no_sanitize_undefined \
+		__attribute__((no_sanitize("undefined")))
+#else
+#define __no_sanitize_undefined
+#endif
+
 /*
  * Not all versions of clang implement the the type-generic versions
  * of the builtin overflow checkers. Fortunately, clang implements
diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index 7dd4e0349ef3..1c74464c80c6 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -150,6 +150,12 @@
 #define __no_sanitize_thread
 #endif
 
+#if __has_attribute(__no_sanitize_undefined__)
+#define __no_sanitize_undefined __attribute__((no_sanitize_undefined))
+#else
+#define __no_sanitize_undefined
+#endif
+
 #if GCC_VERSION >= 50100
 #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
 #endif
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 02becd21d456..89b8c1ae18a1 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -198,7 +198,8 @@ struct ftrace_likely_data {
 
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
-	noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
+	noinline notrace __attribute((__section__(".noinstr.text")))	\
+	__no_kcsan __no_sanitize_address __no_sanitize_undefined
 
 #endif /* __KERNEL__ */
 
-- 
2.27.0.rc2.251.g90737beb825-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602184409.22142-2-elver%40google.com.
