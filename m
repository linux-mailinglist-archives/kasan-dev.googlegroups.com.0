Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNUH7SKQMGQEHE2ONMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 02287563537
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:55 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id x2-20020a1709065ac200b006d9b316257fsf840934ejs.12
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685494; cv=pass;
        d=google.com; s=arc-20160816;
        b=CLXW6DrUldgLGpQz/va+IWrl7V1yvuXDXXdeVK0N4NiTcxAKfrEao/jLRbNb7qcvGr
         sIuPjCGBH6GtumOGnpBzaGbePmSpAZyqYlgCTY1f6cHaMyQRhKUVpziNXWt1ZQ8szDD2
         cIDIxLSgmrXWu5h6mcT7kxLzvoYpq0hKsidA9ntdETmgqBvZ4Z2cRrbWz23nd4vZ52dd
         yE1RGrB8eakkPAUNxuhqLTCSb9y0woN1CdC3TeF1iA6Ahl/USN4Im95blEuOo6clfvWJ
         dG+MuKGhigdk9U0CWs1NuO8T7qMPEjsoBkVIMJFaVkGhuQepU3nNw/cjEz3hJUasDJWp
         hwCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UqYbkuMBrqwkY7h3feqR3+Q84vByi5dkYsVENEUd7tM=;
        b=n5kZChlBA6/tcn9NyUul5hGo/qsf4f5GkF84apd8vSzAfubturUR50IZwth0DxZzEg
         9FFxli4J2jHemioVizz9LO5zvQbKTgxtoxQENs39l0N5FE8WCWMJI4+mOEQbzNx8ttG5
         Ygtw+a3g3wJAOk/Qcfv7SjmkeKFd/j5Z33cSKYCubyE+yBuCoXSKLOIHcZKXB4RjZTne
         k1KTRAzFZA24PAUmQiR3o/zeINhMbRUL2diX9GSMkovcfQ1mupGmoPGRvt28IhlWCzEH
         BCrueMEojsU1yzSfYushrNXSa32Y5egHLi0DnzrcFvZTweeLPbQfuKHxSFpVS4jrkQYE
         5u1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bYQ2u2U8;
       spf=pass (google.com: domain of 3tqo_ygykcdq6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3tQO_YgYKCdQ6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UqYbkuMBrqwkY7h3feqR3+Q84vByi5dkYsVENEUd7tM=;
        b=rF8zXeiAVK9TQ0bL3kV0rCJtBxyQVl4umQLEQGTlVZyzNCZ/4Y3Nz+e1eW8nJ4J4xv
         q3MEwspbqCPQHT/lqutH+G/Blg5/AmTm9xUSpJ8vKWnL9pXpZ971T/5Wo9/JNEPrkBDI
         Oc0K3NRnAwWWjNdJLbJ7BQg4cYmk1KogLLIWKaQV7dcM8wXrttuYAMqEIKlHKSVuS02Y
         JxIaldgtj/kTGL5ZNw5/ElofHVmYzd3/tyaQexlyWZ8v7bSx0MEAzMcucvcP5wSzS9is
         2Po50j8oALFoMXKPxAuSZdrpD9OfqnGbIKTjioSGAC0kZ08LeVoTRVp6NmKYtebFwUKm
         uCqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UqYbkuMBrqwkY7h3feqR3+Q84vByi5dkYsVENEUd7tM=;
        b=zK+Njslu/rr5xh9omCkbgXlGu/Pui8ANPzUSmzee/weIIJRyKJRVxPvLrDooCgD6n4
         /6eY2lFOXxMibDB1CoGQOs4JAPYuxb3uNyomrK9alZ/6ioQ3KhHR949sRPkWcRNsybHB
         /ArgNgrh1dj3Q+98mrArbbLSsvgjLFmP6lNwkb4UGGx4B7tUTPSXeLnH1HofQpMO4LWe
         25RvBfbTZPCNTrRYJseWzik/yFTkkbIiCup/fLmM1ENVndnP4KadkV4/cTbhiQhhU1HI
         eUWmwUQ+jVzjqRvmw6vLkXzgjk7XWxDrgouHWORRc05MRHYOkDoQBn5L8wv+qII3AKg8
         Zrkg==
X-Gm-Message-State: AJIora8cBRXNUvtnIC1EHeYGjWjyYKdFDIeZ0lEOlaA12zEu9RZ96MyC
	OWXGf42sicV7UoYyTylYoao=
X-Google-Smtp-Source: AGRyM1tuUv64nm8lAbZfOs+ZM1OfqWsjeLSLinjzn+8mHoAAwUykg2JjyswvKo2vP/7PzYTf4Klqyg==
X-Received: by 2002:a05:6402:28a2:b0:435:798e:2988 with SMTP id eg34-20020a05640228a200b00435798e2988mr19044092edb.217.1656685494715;
        Fri, 01 Jul 2022 07:24:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7e9e:b0:726:31a9:49f2 with SMTP id
 qb30-20020a1709077e9e00b0072631a949f2ls3274265ejc.8.gmail; Fri, 01 Jul 2022
 07:24:53 -0700 (PDT)
X-Received: by 2002:a17:906:8301:b0:6e4:896d:59b1 with SMTP id j1-20020a170906830100b006e4896d59b1mr14671992ejx.396.1656685493684;
        Fri, 01 Jul 2022 07:24:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685493; cv=none;
        d=google.com; s=arc-20160816;
        b=GRMYmp1XIuUG31EdMtasrhwJR913mikia6NCGmMmS75rfOjJY5c3Q9TIC9aQqPovFP
         WU9JQAuL+p06n7ZHbO9URdYyhOD+k3cRYuk+SvXz2pyLxIsn+Lq/D5lnRd48n7vPVYT5
         5aXrZWxT9l3ToGW2y7rvFZkcw2J4RmQG/f+5BlxYPx9kWiFHvUoR/TbhDbOxrTP2OYh2
         VUAcWkBkvLVEMlpGnCStHePvJ9A9jTuU7kG55TrjdZypfCWN4SufxDKlBZRFEDW+zb/g
         ki7gawAMrQxNbxjsNMKfQVjwFJCUm7hy2EpQiAr8IBmvtKB0dDGm7lr9iknQ9zrXHmcF
         w5qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=CG3pZwK286Wp+stKkliNeTwrORF17cOHhcnhVfCJeQE=;
        b=BOyHy3B/VT1AAKul6A3aP6JmWRd50kehKJs9yZCeu0cUT6B/FnqkrCtm7Fq7J9ZpyU
         Vuwo8XT+R0mu2EUN1luJUIu/3TqC/ywEBFbyjMc/SNwTx9ecKxCWuw9yCiSX4lg1LWPF
         jGkq8Ew+Lyq2TsigXMYsWAwh0fSMstsRD0CXkaOrX9dEeXojv2o3QrKhgWi0oz3PiT8H
         BlTBVVh34kOjZy9jvY79cA7BnEc11VaZkQKcHjpKELXjAJSGm3kJE2t8ExtYIrHW810J
         dFHtbK88qmR9YegH1WJFkIZTDmT6ZnaBEICM0h7uiFqKpCS5SnWcttre1FDsMIUwWKQz
         wx6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bYQ2u2U8;
       spf=pass (google.com: domain of 3tqo_ygykcdq6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3tQO_YgYKCdQ6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id q31-20020a056402249f00b0043780485814si737221eda.2.2022.07.01.07.24.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tqo_ygykcdq6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id s1-20020a056402520100b00439658fad14so1902395edd.20
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:53 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:2403:b0:439:682f:d12c with SMTP id
 t3-20020a056402240300b00439682fd12cmr7312146eda.301.1656685493399; Fri, 01
 Jul 2022 07:24:53 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:00 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-36-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 35/45] x86: kmsan: handle open-coded assembly in lib/iomem.c
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
 header.i=@google.com header.s=20210112 header.b=bYQ2u2U8;       spf=pass
 (google.com: domain of 3tqo_ygykcdq6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3tQO_YgYKCdQ6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
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

KMSAN cannot intercept memory accesses within asm() statements.
That's why we add kmsan_unpoison_memory() and kmsan_check_memory() to
hint it how to handle memory copied from/to I/O memory.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Icb16bf17269087e475debf07a7fe7d4bebc3df23
---
 arch/x86/lib/iomem.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/arch/x86/lib/iomem.c b/arch/x86/lib/iomem.c
index 3e2f33fc33de2..e0411a3774d49 100644
--- a/arch/x86/lib/iomem.c
+++ b/arch/x86/lib/iomem.c
@@ -1,6 +1,7 @@
 #include <linux/string.h>
 #include <linux/module.h>
 #include <linux/io.h>
+#include <linux/kmsan-checks.h>
 
 #define movs(type,to,from) \
 	asm volatile("movs" type:"=&D" (to), "=&S" (from):"0" (to), "1" (from):"memory")
@@ -37,6 +38,8 @@ static void string_memcpy_fromio(void *to, const volatile void __iomem *from, si
 		n-=2;
 	}
 	rep_movs(to, (const void *)from, n);
+	/* KMSAN must treat values read from devices as initialized. */
+	kmsan_unpoison_memory(to, n);
 }
 
 static void string_memcpy_toio(volatile void __iomem *to, const void *from, size_t n)
@@ -44,6 +47,8 @@ static void string_memcpy_toio(volatile void __iomem *to, const void *from, size
 	if (unlikely(!n))
 		return;
 
+	/* Make sure uninitialized memory isn't copied to devices. */
+	kmsan_check_memory(from, n);
 	/* Align any unaligned destination IO */
 	if (unlikely(1 & (unsigned long)to)) {
 		movs("b", to, from);
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-36-glider%40google.com.
