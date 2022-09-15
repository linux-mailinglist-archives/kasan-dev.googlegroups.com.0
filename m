Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3H6RSMQMGQEMBB6V2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 12B5F5B9E2F
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:21 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id m3-20020a056402430300b004512f6268dbsf12394910edc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254380; cv=pass;
        d=google.com; s=arc-20160816;
        b=JXeiT0JF4+2a72Kd7P7CkExK5eM25UeYDk6GaK6rz7QhuJO7jrQh2d/HjDwm0JXDOI
         sT3zfKcNc7hhhLZgFTKpi+kOhucDV0PZePXNnAbWPXO9CCMd06U4GGKYdNM5UAFsI79p
         Q3z4YvWX4wQ2rhijYVqm7hqLciiIc0bw6lAFEeBXwk68Evvw1/RaBIJPshcM7D7PtQXV
         hM7wRRNOJEJOO15iSJRNL0HOOvX0Jm7FaIPd9hJhobYiCSo0rqVzzdrfzPaQBtIYgJxa
         91EdUeegpogb+PSwtOi4zvj/V8giBy6O2X94HUr9a4uLDXoSN/wQo3jkqm0GtrrzKWSG
         NdrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=S86ABkaGQ0PgMOppaVUT0bUtiCL7SMLEr+PqCdfIKsk=;
        b=ihwTuA/NrpYkV4WzaqHPAwyvaQWjuBsXSF3gApSeKsk9Xes5vi6PKd5Cii0seOld/D
         81Iu+1k+JUPqgQkQWmcSGW5eFHF5gXk/4Z5oHVGDvFovTWBYiWNGaNH7yfKKbDCt7kYC
         nXjq1ayxP3RV+J2+JKAniUg03wwIChs83Hp/Ry72uw+RRKn5VByTjKSVteP1av/TPK2L
         Y40ACbAkMDVIGqKEZMamaK0NpU4q0CkLjobHgjhYYS/LEd1tMsbLK/yRi3bVajOw3G9/
         QmczTEhOf03WwsB9EKBhXUw51+odOMbNB/9mEg1i4MGrZnTWtfozJbjVp0Q+nUV8afeU
         TRZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ERCi1CpV;
       spf=pass (google.com: domain of 3az8jywykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3az8jYwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=S86ABkaGQ0PgMOppaVUT0bUtiCL7SMLEr+PqCdfIKsk=;
        b=jSJd7NG6o1C7uKx6JNTyAnkJDst7wPz59PAMrvJTx7DsLLp4Q5ZtwNAgdd8qEqmtha
         LkKT8wxHEAu0aLrAs8KFhe6sbduvxE5ssiIR8fQqNlXxBha9PRY1jkgAcDR786zRzDve
         idGOaDWJweCydUkPqLZ2gqFiI9AJmay3pyVaLAT0CW+KVsS5+5PK1dHku0LVRk77lwno
         6THo4KePzZlNvEX8TCqX8SllByOuoNtYGg3NgO7TtDNfOAkpwALCXlTYqQSg8XzWKH5w
         8sYJkma/pHpWa8PgQDHV1L9/3qDwXcm3lRXQwa4XnPABoZVYhp9UrSOM2/0F+PffvqPP
         bv4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=S86ABkaGQ0PgMOppaVUT0bUtiCL7SMLEr+PqCdfIKsk=;
        b=OIlM573WnbiSmKt8y4UAi2FrfUaCZV83Q7z2Vb0tLUNZCcdi+wx9iq++WUbsqjPvwo
         wtjpE9OFSWHy9oaabmnFKiBVm/ZrwFkQ6pvZk2XOpENAoxN+618eAAzuFcFJmdQX8ZIE
         4W47MqlECT3Kl+yI7OlcAKGUC5zOCD4ZguFRal2OmxPwkDzbtYiy3LSlAlPNp3DIaBRw
         d1ibycjCjWitnh1cpqczh+SR1/ZBCmp5iL8r5Rn49R3CiYccFjSflkA5YaYyYU6so8SM
         91gPxMb6jlNfZxO7AQprwMBC+V8vI4SLDwu39uP/3xBuYJ/J2bRlXpzt0TK1b7GqgAOF
         Fmww==
X-Gm-Message-State: ACrzQf21o9Mr41QYC4gcTtQl0r91NZz7xRkaHxR7xBbQiOkUMiJtn8s+
	Km5PxaBq1dmwxspEgArDgXs=
X-Google-Smtp-Source: AMsMyM5i9h14FOcMoL2Ho/Oza9qbRG6PpYLQ0BZwXofKv6TjAh7io9ZgmVdzuehwPy39dyA/Vdoc8g==
X-Received: by 2002:a17:907:7f04:b0:77d:5bad:46d7 with SMTP id qf4-20020a1709077f0400b0077d5bad46d7mr267303ejc.663.1663254380812;
        Thu, 15 Sep 2022 08:06:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7c54:b0:730:6969:95e6 with SMTP id
 g20-20020a1709067c5400b00730696995e6ls2526793ejp.7.-pod-prod-gmail; Thu, 15
 Sep 2022 08:06:19 -0700 (PDT)
X-Received: by 2002:a17:907:7f9e:b0:73c:6f39:7399 with SMTP id qk30-20020a1709077f9e00b0073c6f397399mr314166ejc.358.1663254379735;
        Thu, 15 Sep 2022 08:06:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254379; cv=none;
        d=google.com; s=arc-20160816;
        b=A4YG4W5yTeGkKJdh1MGFcJZncUvBlNKg9jf585hPcm6LfTfsjqdOlFP33ytNDcMFo0
         XQ3du4IRkSKnVwD3OjipDJlkT00vWffECmm39tWddk3ySDpkmZhI6+Y22hPL1z75FM0u
         nwfuqnKhTx9X1fH054DYCPoUvlgAopgeCMStL3IoyY14NTsT7+yuBjhwaf6IsUFvPrpM
         htr5V1xN3UwBfyYMCSutRqYihpQ/bHDYqomlJfYcjyalPawZjRi2SAwiGZv6CpmukfOc
         gaXf17PTUdgmyw1FMmZLlx6lLM82AmWUfv8zCSpgf4++usWnXA7mEupgvntrFwzdKaaE
         tGGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=UAXLi6hWes4K0I7wTwgH8ix0vMuStYu2bu/++oTzO6o=;
        b=Oy5W5VhmYSeWEcIuMWR6X3IhTmPSqsTmgy/xo+8mRNc/9SEDMaWrBcE5kh0K/fmxZg
         Hos39rGzJl+j6AyMS0/tHk8x06At231WeFoQhvTEvJwN4SB4KbMDBwFo3g5WwMkVmyLT
         bKzD5GN5BmbrI3YrCJMY3WMweMmWdJ9vvm7Q7Q/8D8FE1n46J/UjCd/lh8pyXMMhfwBy
         yIGN+vLQ1Y08wIaKce3hgkLXFUk+V5g4L0ZWzL2vuFl2oaYKwTr5MvEeiQ8u0mVSOcZL
         Rt+bgPuD8JpjbuiBXWYnlPKtHa3qdZgdIIhpKnXFqN1x28UukmOh/gEXytMoGKaa8h8d
         b7uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ERCi1CpV;
       spf=pass (google.com: domain of 3az8jywykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3az8jYwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id c12-20020a056402158c00b0044608a57fbesi551911edv.4.2022.09.15.08.06.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3az8jywykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id qw34-20020a1709066a2200b0077e0e8a55b4so5584307ejc.21
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:19 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:aa7:ca50:0:b0:44e:973b:461e with SMTP id
 j16-20020aa7ca50000000b0044e973b461emr269636edt.414.1663254379373; Thu, 15
 Sep 2022 08:06:19 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:11 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-38-glider@google.com>
Subject: [PATCH v7 37/43] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on
 x86, enable it for KASAN/KMSAN
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
 header.i=@google.com header.s=20210112 header.b=ERCi1CpV;       spf=pass
 (google.com: domain of 3az8jywykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3az8jYwYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
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

This is needed to allow memory tools like KASAN and KMSAN see the
memory accesses from the checksum code. Without CONFIG_GENERIC_CSUM the
tools can't see memory accesses originating from handwritten assembly
code.
For KASAN it's a question of detecting more bugs, for KMSAN using the C
implementation also helps avoid false positives originating from
seemingly uninitialized checksum values.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/I3e95247be55b1112af59dbba07e8cbf34e50a581
---
 arch/x86/Kconfig                |  4 ++++
 arch/x86/include/asm/checksum.h | 16 ++++++++++------
 arch/x86/lib/Makefile           |  2 ++
 3 files changed, 16 insertions(+), 6 deletions(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index f9920f1341c8d..33f4d4baba079 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -324,6 +324,10 @@ config GENERIC_ISA_DMA
 	def_bool y
 	depends on ISA_DMA_API
 
+config GENERIC_CSUM
+	bool
+	default y if KMSAN || KASAN
+
 config GENERIC_BUG
 	def_bool y
 	depends on BUG
diff --git a/arch/x86/include/asm/checksum.h b/arch/x86/include/asm/checksum.h
index bca625a60186c..6df6ece8a28ec 100644
--- a/arch/x86/include/asm/checksum.h
+++ b/arch/x86/include/asm/checksum.h
@@ -1,9 +1,13 @@
 /* SPDX-License-Identifier: GPL-2.0 */
-#define  _HAVE_ARCH_COPY_AND_CSUM_FROM_USER 1
-#define HAVE_CSUM_COPY_USER
-#define _HAVE_ARCH_CSUM_AND_COPY
-#ifdef CONFIG_X86_32
-# include <asm/checksum_32.h>
+#ifdef CONFIG_GENERIC_CSUM
+# include <asm-generic/checksum.h>
 #else
-# include <asm/checksum_64.h>
+# define  _HAVE_ARCH_COPY_AND_CSUM_FROM_USER 1
+# define HAVE_CSUM_COPY_USER
+# define _HAVE_ARCH_CSUM_AND_COPY
+# ifdef CONFIG_X86_32
+#  include <asm/checksum_32.h>
+# else
+#  include <asm/checksum_64.h>
+# endif
 #endif
diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
index f76747862bd2e..7ba5f61d72735 100644
--- a/arch/x86/lib/Makefile
+++ b/arch/x86/lib/Makefile
@@ -65,7 +65,9 @@ ifneq ($(CONFIG_X86_CMPXCHG64),y)
 endif
 else
         obj-y += iomap_copy_64.o
+ifneq ($(CONFIG_GENERIC_CSUM),y)
         lib-y += csum-partial_64.o csum-copy_64.o csum-wrappers_64.o
+endif
         lib-y += clear_page_64.o copy_page_64.o
         lib-y += memmove_64.o memset_64.o
         lib-y += copy_user_64.o
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-38-glider%40google.com.
