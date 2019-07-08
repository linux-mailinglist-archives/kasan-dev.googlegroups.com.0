Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKXRRXUQKGQERJAZU6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 822A6626D5
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 19:08:59 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id b139sf15798410qkc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 10:08:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562605738; cv=pass;
        d=google.com; s=arc-20160816;
        b=c6VAQmTc0Rks4aIk9RRmPxp1o9LUUhlcsQZsOCfLedJZslNA5x/8v42BdTCT5jpwSd
         Q77cWQ8baNlDuI35tANVAs24GQJ1vqzcW4OVdZvw3Eb9h8LVqU11CXN+JhfNFwNTIsUv
         h1gnA/o5hQLzxUUqmSrGozCbuqZHMGeT9xwAdVFIS3+fZR4yA2SRU3r+xZQea0hHxzV7
         rmpRUeVFGM3TAxo9O/x8RvaGQHXUWYPAwyQMssizQkPe6ITCVmVJQUWv7TbLj+DW+3sC
         ADPREUui7GnpPEqwtYgwp3l+8BZ+qluIwK9Hp8jx8WXEE32GV2oR0pCFdYVOkrLI+Pfr
         B5hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fDWnJn5OUmnnJWDfsLNDDEGbQ5D9fz4YzVA1wmptXpc=;
        b=fz+teMQaRWuzT3D4UJacqobkaBTULPZQ4eIGvh0HqMkwauhWqct4Q62irMu8Fl4HBT
         RfAhT6NW4BFa+AoWONXdefOoBWMkiaPq44QMMoJnI8C6TNJMXN0W5+ZUTn4UweaC9css
         yX+/e5/MP0wZopHWZ4J3lJgoRsBC324qlE9oaZswwOJjwEqNRVxFqpkw4cq/vt1a6pS6
         rWo0omROAMWMAlHV34iBGfMRQhp3AdWEnewMHiWv5gJGPLE7zXMp07PPbgC7YV7IEEhV
         R1UzIjY7gWIGOJ5faabxn2Sa7YMiLDeKzbN6ldRkcAmTRoJcS6mMG02+EfFxXoQrrTjq
         R6SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wOdsIHVM;
       spf=pass (google.com: domain of 3qxgjxqukcrg29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qXgjXQUKCRg29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fDWnJn5OUmnnJWDfsLNDDEGbQ5D9fz4YzVA1wmptXpc=;
        b=IOCjMVEd1d465AvnZR17EcbXms+8+qXLa5VED2AM4lV3dU/4yNhmf1ujrz+RBqeSLb
         0niFj7xY8nQ0hlIlN9ynR1DV51FAZxRiElr/mM+Xsm8SjIfSjWTmxExReE6U3y9TDy/2
         Fg6xNxTFRwGFg5JPp4Hi//1gUA+l7aOytg+r6iRxJc0KpC5LC46VgVLNlLuDBTD9iP9L
         VnmMUkJaiGvvxX9IbYGhLK/hFPHuTL6xunkcoOuDGiz+A3Bo0uMFl/48PMDgAn6lBtGQ
         4siZznNuvrmBM2NuLfVUtQ2SnPF7Aa3W/YgS2Rk8lnctdoyA7SPX1ly5AuHc8KSaLY8+
         qtCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fDWnJn5OUmnnJWDfsLNDDEGbQ5D9fz4YzVA1wmptXpc=;
        b=LnmgUilUip6iN4NUJE/ew9lQdWq28zSwYYh6XJs58kWctNH1wu8BZWacOXL8qyzWFK
         lv7HZYlQsxGnEBRF+i6LNzg0EAlK1qT2T9eTtnB9qJprVH7Dw/+3Wh93m9duZVwnn3u8
         r4U8f7bD0fdIq48OaW18FPsnhBtbnKMPZePj954Jjoz2H468c95tXPp2gImCLiLh9CjE
         rqtF7Ux7+EEpo3amjU2yS0dKw/gIaITRLBpbLFXQSH28eV3Uc3ZbeW17hST/LAznFKjT
         ApeVO1ZzsLdWOBxciU/ae/FFUulVeiV5CoPBvdYLyWkSKoIWfEyQ9kL/ttXb8rCjPlZp
         h+Cw==
X-Gm-Message-State: APjAAAVOu+D5Ot3MzIHKYmlZQ/EojBrBp8DTecoOSXl2kpyBdxPYah1Z
	NFs4tzHV4kt8SItDM8prnoM=
X-Google-Smtp-Source: APXvYqzpKiP0rM8LcMO4LpTaYzHN/NLOpV+f6qUO3QfxzpHGMspBhGmaeCYnpsNmS4+ooxZbFN0GZw==
X-Received: by 2002:a05:620a:52e:: with SMTP id h14mr15663967qkh.358.1562605738512;
        Mon, 08 Jul 2019 10:08:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:818:: with SMTP id u24ls2484199qth.5.gmail; Mon, 08 Jul
 2019 10:08:58 -0700 (PDT)
X-Received: by 2002:aed:3fb0:: with SMTP id s45mr15430294qth.136.1562605738176;
        Mon, 08 Jul 2019 10:08:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562605738; cv=none;
        d=google.com; s=arc-20160816;
        b=AvWXfWl9yMQcuN1b75vGIxlD+49tFJRgzp0iqszR+nW2ZVJD0pBVOJbELHN9AtmZwv
         gcqNFHuA/SCPvqIL4SApuAdC8nbZKOrygu7lQb+WuOX2ahpAYtkKXwKmDCNERB6srN2q
         xgiIqpmVhwK3alovHCffqK+1+wdvxtWa6qHfc1I3W7jpVt3+hp9X9AfgELLLiAIb369f
         wH0I5l0q+vd6th05LMsyRtKyCjteL/QJbzy+zUWhUXz9/Zm9niMLmcVRtUn/lMbeAdkY
         FhU/l+7rPi/RXJ8vyfXTyTKHOA4/7d+0vJNNVKUugqhDmUH0vlgAeK2FfIUYblg26P0V
         KzRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Hwhk1enE9nNmmHHJ9NMKEqUFLaBrzoJTEH+x5otTjag=;
        b=IBWMzJu2Udf52gAtVwK1/boGyHNYud+7tc05mndK/n6BQ2OEadQOww1XD/z2vNvuwp
         EMAvufAXrTV/Fvp6r+V6SpiugV9MK876qeZZFvqQFFDKeCWV0okM/nUZKcMXrFycw+bt
         dusPkZvBPMa4Ap010cjdIcGhuFwC4pDRR0L1323Wd5ReZ/hh7itG7+oDM7VAftjJoAFX
         vF6Bo78Hy1lPbs3WVch9UEvMKrP5YWVDZugQQaqWpnr7t++EuRiePZjC5y2yD9WbDIhM
         iLrqdP4kIUAOLvGMNMM+EfOtW399KS0P1UhrUa521OM4KSW+es4VYXP8+SfUQ42afNWK
         qk8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wOdsIHVM;
       spf=pass (google.com: domain of 3qxgjxqukcrg29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qXgjXQUKCRg29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id w82si791703qka.7.2019.07.08.10.08.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 10:08:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qxgjxqukcrg29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id x17so16980374qkf.14
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 10:08:58 -0700 (PDT)
X-Received: by 2002:ac8:32c8:: with SMTP id a8mr10978860qtb.47.1562605737784;
 Mon, 08 Jul 2019 10:08:57 -0700 (PDT)
Date: Mon,  8 Jul 2019 19:07:03 +0200
In-Reply-To: <20190708170706.174189-1-elver@google.com>
Message-Id: <20190708170706.174189-2-elver@google.com>
Mime-Version: 1.0
References: <20190708170706.174189-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v5 1/5] mm/kasan: Introduce __kasan_check_{read,write}
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Qian Cai <cai@lca.pw>, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wOdsIHVM;       spf=pass
 (google.com: domain of 3qxgjxqukcrg29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qXgjXQUKCRg29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

This introduces __kasan_check_{read,write}. __kasan_check functions may
be used from anywhere, even compilation units that disable
instrumentation selectively.

This change eliminates the need for the __KASAN_INTERNAL definition.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Qian Cai <cai@lca.pw>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
v5:
* Use #define for kasan_check_* in the __SANITIZE_ADDRESS__ case, as the
  inline functions conflict with the __no_sanitize_address attribute.
  Reported-by: kbuild test robot <lkp@intel.com>

v3:
* Fix Formatting and split introduction of __kasan_check_* and returning
  bool into 2 patches.
---
 include/linux/kasan-checks.h | 25 ++++++++++++++++++++++---
 mm/kasan/common.c            | 10 ++++------
 2 files changed, 26 insertions(+), 9 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index a61dc075e2ce..221f05fbddd7 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -2,9 +2,28 @@
 #ifndef _LINUX_KASAN_CHECKS_H
 #define _LINUX_KASAN_CHECKS_H
 
-#if defined(__SANITIZE_ADDRESS__) || defined(__KASAN_INTERNAL)
-void kasan_check_read(const volatile void *p, unsigned int size);
-void kasan_check_write(const volatile void *p, unsigned int size);
+/*
+ * __kasan_check_*: Always available when KASAN is enabled. This may be used
+ * even in compilation units that selectively disable KASAN, but must use KASAN
+ * to validate access to an address.   Never use these in header files!
+ */
+#ifdef CONFIG_KASAN
+void __kasan_check_read(const volatile void *p, unsigned int size);
+void __kasan_check_write(const volatile void *p, unsigned int size);
+#else
+static inline void __kasan_check_read(const volatile void *p, unsigned int size)
+{ }
+static inline void __kasan_check_write(const volatile void *p, unsigned int size)
+{ }
+#endif
+
+/*
+ * kasan_check_*: Only available when the particular compilation unit has KASAN
+ * instrumentation enabled. May be used in header files.
+ */
+#ifdef __SANITIZE_ADDRESS__
+#define kasan_check_read __kasan_check_read
+#define kasan_check_write __kasan_check_write
 #else
 static inline void kasan_check_read(const volatile void *p, unsigned int size)
 { }
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 242fdc01aaa9..6bada42cc152 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -14,8 +14,6 @@
  *
  */
 
-#define __KASAN_INTERNAL
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
@@ -89,17 +87,17 @@ void kasan_disable_current(void)
 	current->kasan_depth--;
 }
 
-void kasan_check_read(const volatile void *p, unsigned int size)
+void __kasan_check_read(const volatile void *p, unsigned int size)
 {
 	check_memory_region((unsigned long)p, size, false, _RET_IP_);
 }
-EXPORT_SYMBOL(kasan_check_read);
+EXPORT_SYMBOL(__kasan_check_read);
 
-void kasan_check_write(const volatile void *p, unsigned int size)
+void __kasan_check_write(const volatile void *p, unsigned int size)
 {
 	check_memory_region((unsigned long)p, size, true, _RET_IP_);
 }
-EXPORT_SYMBOL(kasan_check_write);
+EXPORT_SYMBOL(__kasan_check_write);
 
 #undef memset
 void *memset(void *addr, int c, size_t len)
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190708170706.174189-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
