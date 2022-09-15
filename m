Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFP6RSMQMGQEAL7W73A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id A8F2A5B9DFF
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:04:53 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id ay29-20020a05600c1e1d00b003b49a9f987csf3990408wmb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:04:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254293; cv=pass;
        d=google.com; s=arc-20160816;
        b=j4TEOGVb5hEKaIPul7RRRHGToCvMlMCD9WRGJPt1DkSl0s9gD8FKyaFeJEXhyaRdVb
         lQg0wj6MEeEAkcRj2TJdFZ0AnGk/xn1ALOOKcSGX5mXUcx5Cof3DIcNYMRnqjzKhWd8K
         mBxWHrqfUWqdaej7l3jmTzuGqgmrhJozOTSs4OB8t++jlu5J6dpmUGPnnZgXHE+8Qv47
         JHAAPVNL/4ADRtJfaDQqkDuT+KmnrwgyZTrfG4I4OsVCW2UgL7KzmYrORnqEO4DHry1r
         3gzTqwVmzH0fWOCc/WzoOgY5nsyTIQ5NZnRR96nzbg5ZvMhlOEsUVSNPpBJ5peIVhKLS
         YGfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=h7Sb5DboG3109GmZ/N7Lop88qXnT9r+ce66MgwJ9mtY=;
        b=CWRToZ1RU8zgOx0cwjtp/eJ9QL0TZ/fFzvF08A2uPEe0Qe4UbjK+G8UScp+N+mjbvz
         K03JwjdxHV/9HWyh15E+DlGsO3048BidfHMXxADdAPm4Mfz5L489rKC4n9pAYd+iYL6J
         ca93eIVx2UHyZ0sOuW15ZtS6P1mG10rYDpVuIqSYCaONv+sDNWZPTQDXoISAhiRyJyCn
         KLTsSaiXFKM2GwUnXM4fmc+ksX8kYRRAsDWd5nxg17au/Xgo/o9k5xu/6GA0w82EZzBQ
         4gNX42irfuTG9T6DIVuMT78yU4ICGQQ0MN44XDZc6Llz2xWKJlJ3BE3H8+nNdXhL82iO
         b1NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cYFC7xgw;
       spf=pass (google.com: domain of 3ez8jywykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Ez8jYwYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=h7Sb5DboG3109GmZ/N7Lop88qXnT9r+ce66MgwJ9mtY=;
        b=bszTwCaHXR9CHp5Zuhzhmf3B6gWyL8wkHLteJe8ae1qHpyHlB0XYgb5dnja7do/Lxd
         7x7A/rTUd4eBn+hIwmdEQNOXy4gFRCwG2rgr9xTte6LJ/0YSueCemPeN60+GcReMVM1P
         3pgVr08C3F2equLDItezaQS3QCw/gucrpEZsIgK9n5nDyM3GZyx5D6ec1zGWqA06AYht
         PAYAhbKc89Rr/qlVDyVK0mX6uGAU/6vlQ0xyk7fbJ+3proK8P2ESWTMkeHZt1KVePPKW
         Nta3/HWkEEz+1T39FGtxp5Ox5nuKlgRTWCMWw3xaQxOyqjLQkDxF1OmMafi5Nn99M4rW
         lx3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=h7Sb5DboG3109GmZ/N7Lop88qXnT9r+ce66MgwJ9mtY=;
        b=WDgcHoRxEeZb9uAMh7BlgkBEBXMXeNI13wkJRxysTv084lmV3FhEmQkzHcYfKCnGut
         gNtOFMWn8SirlsCxIBcoZ0M3RlbrcvUs3tmfPvrd1ZYoWxGiRjEYmAwM9CxKcJfeqn2I
         5CP9uL6RxLwufvqva1zOKWgXGGK4vn58Xdm2WH7U9eN4IVFTn8v7AsD1e9faOt/ztfWi
         V2+d8SjJuSkSlUMsbZVzu47LBf4lQLhy8t0/Th/XRnFNaoSNPpPiHb86UAhJHvmYQsDn
         /gYSMeb5dlzAu3coDZv6UpR01jeHG+0SATVbNyPBNPLQRhJ7P6TfKpzd0iNt9KRfzJnz
         uwjQ==
X-Gm-Message-State: ACrzQf09Unv/9bgGgbGrhFO7kftaoSAAb7GxO5p7s3X1HfoxrSumphza
	Q53ZdtTG3ZBX+/uGRm4Lwiw=
X-Google-Smtp-Source: AMsMyM67tsG6mcu4zEdfGKxzeWhKUSwvBBXyhxS0bEeGwQBtZpR3EfeMSbfB7RmwBRld7+GSsW6YMg==
X-Received: by 2002:a5d:6da5:0:b0:222:4634:6a4e with SMTP id u5-20020a5d6da5000000b0022246346a4emr79952wrs.172.1663254293285;
        Thu, 15 Sep 2022 08:04:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f219:0:b0:3a5:2d3d:d97a with SMTP id s25-20020a1cf219000000b003a52d3dd97als7252918wmc.3.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:04:52 -0700 (PDT)
X-Received: by 2002:a05:600c:a09:b0:3a6:8900:c651 with SMTP id z9-20020a05600c0a0900b003a68900c651mr154500wmp.145.1663254292204;
        Thu, 15 Sep 2022 08:04:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254292; cv=none;
        d=google.com; s=arc-20160816;
        b=dvOW1X6PLzg2n02305AO6i1T1G/K6zRRQWWt3SWedr3kQmHPZyRHPyJKTn5EzB9ct/
         01DfZ2hVTB45rs8SAP3IgL/R4Cd+WdP8mwgQLreet7Z4gfuh+ABt1MsOhmAAdwMhG7fA
         MNtaurCe8cq6iCXeP7zjEDSQA0ojATwjwldvxpYoZv1QUTnokcVf37aPBbzrwMpKBcz3
         sVccJQrvdOmVfOrpI9VSPsJpaXNWJpMR53+pBBtlSoXH8v+PEnAxuwy73uJfwPwSz1Dr
         qcN3SyaATgQdbfIgrebztSl3ANvmC6u1/G3ymsil4t3h3Val3LfYR1KhoPB911ak0A8l
         sl1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fFq4uMFAQOrpNZLU6ydmQ4L19fVmnSZ8zUbgI7i1GQ4=;
        b=uJLOYf93D2EUFiJoBlWP0BG69S275MocLmlrzm8kUVyPQgWqSxb8VJyonUZY8lsrTw
         k1HIMMjNjX/EPEOurQLnoUiHTGJARpO+83d+s0TcfLLcFA6VWHaGEmXt+MO+b2H4IXnS
         ROgqMn7i9m7E0fGlKjfZRzBVcI5dwf5+seSamp88nKNhVaAQzDZGKs9O5qg2sqZikltx
         xDaPAK14c7I5jcq28qEV6k9R5CpSN0CKWSPn71tem6rJkC325HBE0/vhepQW0UOj7h2N
         mOwPeMG9cIehZlzaayG4f7mWzR/9gerge6+tpOpPih/Bs2nGZvn47T744Z+kT9xNJJY4
         9gRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cYFC7xgw;
       spf=pass (google.com: domain of 3ez8jywykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Ez8jYwYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b003a54f1563c9si86857wmb.0.2022.09.15.08.04.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:04:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ez8jywykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qf40-20020a1709077f2800b0077b43f8b94cso6162332ejc.23
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:04:52 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:272a:b0:77c:d7df:c9da with SMTP id
 d10-20020a170907272a00b0077cd7dfc9damr318116ejl.332.1663254291795; Thu, 15
 Sep 2022 08:04:51 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:39 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-6-glider@google.com>
Subject: [PATCH v7 05/43] asm-generic: instrument usercopy in cacheflush.h
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
 header.i=@google.com header.s=20210112 header.b=cYFC7xgw;       spf=pass
 (google.com: domain of 3ez8jywykct4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3Ez8jYwYKCT4lqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
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

Notify memory tools about usercopy events in copy_to_user_page() and
copy_from_user_page().

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v5:
 -- cast user pointers to `void __user *`

Link: https://linux-review.googlesource.com/id/Ic1ee8da1886325f46ad67f52176f48c2c836c48f
---
 include/asm-generic/cacheflush.h | 14 ++++++++++++--
 1 file changed, 12 insertions(+), 2 deletions(-)

diff --git a/include/asm-generic/cacheflush.h b/include/asm-generic/cacheflush.h
index 4f07afacbc239..f46258d1a080f 100644
--- a/include/asm-generic/cacheflush.h
+++ b/include/asm-generic/cacheflush.h
@@ -2,6 +2,8 @@
 #ifndef _ASM_GENERIC_CACHEFLUSH_H
 #define _ASM_GENERIC_CACHEFLUSH_H
 
+#include <linux/instrumented.h>
+
 struct mm_struct;
 struct vm_area_struct;
 struct page;
@@ -105,14 +107,22 @@ static inline void flush_cache_vunmap(unsigned long start, unsigned long end)
 #ifndef copy_to_user_page
 #define copy_to_user_page(vma, page, vaddr, dst, src, len)	\
 	do { \
+		instrument_copy_to_user((void __user *)dst, src, len); \
 		memcpy(dst, src, len); \
 		flush_icache_user_page(vma, page, vaddr, len); \
 	} while (0)
 #endif
 
+
 #ifndef copy_from_user_page
-#define copy_from_user_page(vma, page, vaddr, dst, src, len) \
-	memcpy(dst, src, len)
+#define copy_from_user_page(vma, page, vaddr, dst, src, len)		  \
+	do {								  \
+		instrument_copy_from_user_before(dst, (void __user *)src, \
+						 len);			  \
+		memcpy(dst, src, len);					  \
+		instrument_copy_from_user_after(dst, (void __user *)src, len, \
+						0);			  \
+	} while (0)
 #endif
 
 #endif /* _ASM_GENERIC_CACHEFLUSH_H */
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-6-glider%40google.com.
