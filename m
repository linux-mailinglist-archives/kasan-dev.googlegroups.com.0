Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ6DUCJQMGQERAC2MJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id BE82D510406
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:55 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id j15-20020a2e800f000000b0024f12c31ab8sf1728830ljg.14
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991555; cv=pass;
        d=google.com; s=arc-20160816;
        b=xkKidKK5uv45DFtgKOugQ03jOjU/PxfwGtK0qSuD3Uy01p7/yR2Eb4Cto+0AYKMJHD
         DG/eptOhjoSdnb6Ml7U3I/uZA6XaHwoy0W9PdwpTpxT2k4BgE6Jpwl2EPUV5WAokxAB5
         eSth5W6l2C4bfh3VFs+XA9H3yRqmupmXzu+RjaFIkDHU8gg5UJ+XexoAm/InQiQkgbee
         Z3feDYLHjztW6mpOE70ARYQjZ8XBnmg9P+NATNtp1zlxC0ZK0nqMcCw2mpZydk85JGua
         /N9f1eH7Llg1vI1kHLXYi25o+TYp3n14zDD46WSlMbx+L/FIP1+f6Mkkf5cpS68MQZIt
         68Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5yi6oG/CCCL3EIUhXA4jf+4IIr1RjRzZ9lWpmLD4DF4=;
        b=sTn2Lr6wXvrSUa+nlYYpbCAU1QyCj1tJvqFXzDPI3FP5PmMwQ37Ud6RUF1kzSJlRVS
         bhMi6QrS4XXvy4e9EwEZClBAnPTHcpUp7lVqQg8SCP1Y7XB2MrkJ/4da2GWwA8EBdtJm
         DyfHEaYvELSH01WMa8ASi5EnZbXirId+Z7wCOc3snbTrtcr2+rloUB6dAyZhdoxzyGqj
         xP8KXu/P+NEHNO5uUM757O4G+D/4JoWVjs/iBe5col1xOAIX+xn7ijngSyLa164XK7xn
         msvWh3FtDrffk8jXncVP5ilg3rnVBd09O6Dns4r04PLj4Vyw5pMV2dQRu+qPOgO/iqo+
         iOzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=owv8rcv7;
       spf=pass (google.com: domain of 3wsfoygykcb4kpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3wSFoYgYKCb4kpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yi6oG/CCCL3EIUhXA4jf+4IIr1RjRzZ9lWpmLD4DF4=;
        b=tjAdC1rkTIre87Sh7zorfbtCFgvdMX96ZljL++9Cm2cfxDkQqXBaJ9I9J+Z197bHnJ
         hfnM8RXcIa227Xyp8kNwqdZNZoNwhZYIVKJSnWnDWac7zglHJjQ69b8AUFmdvqdmfT1k
         xCr4w81eN10fXwql5dQKNgmV43b/tQbqdFixKdRqDcS0E4frCJqe+bH30pbPXJhyLGuE
         iE9jK7ceQR7DWzqEkfKS+WjWzCXMoW4qbVzOAfVY8Bq3z4bmXNpPz6ulKEYQwxdou5B2
         NlIcmRuFTeV6LwPfgDWuyBVB1SBX5bYYmoLG7Pqefg8MJIxhdtI4RbH+zq4DaAB8MAAM
         gOwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yi6oG/CCCL3EIUhXA4jf+4IIr1RjRzZ9lWpmLD4DF4=;
        b=GeXAeCef13ovAOLw/KeIme8dyxDs8z/WuxL8QbFcKmGhRZlhaByjhlnTKwWL6tu2wH
         Bkd6Mu64Z/MeLrnjvuFzd995c62A0qzMFogVQMppWQIG0mf9SsDqdiQ8kyZJwxZ5/le9
         B0kyu9hnCGJkmMDiWAH7WcGDfoV7LJDuLtFJdeoGQvjfnBYsgAhdx/OfI/ybFhzs4lYv
         c5IYaCtzIHJzBebUKdpAs/CbvZGViW6vlOFc2xxNznC199YM+G6g6mKgQW80b5bb1T3N
         pJEZ/9rRvRDagpssfXDcjl6OR0PzJGo3NrgwDn7S727uRsRpmGOQNXWrb/kz0KjsLZAD
         wkyQ==
X-Gm-Message-State: AOAM531Aoey03zeViQfNUHwIGt7EXuMWWhYdAWwXMh3GYktmEti9c5FK
	v7l3C10TkUXGj4dmczZrBX0=
X-Google-Smtp-Source: ABdhPJy+5KiU+DfPyXnfGxtOc/gPbR/uFYuzu+mJtHXSXk7jzXNzbPj1UzTa5b+9hse8utxb8aMIZw==
X-Received: by 2002:a05:6512:1688:b0:464:f53f:850f with SMTP id bu8-20020a056512168800b00464f53f850fmr17053923lfb.637.1650991555224;
        Tue, 26 Apr 2022 09:45:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e2a:b0:471:af61:f198 with SMTP id
 i42-20020a0565123e2a00b00471af61f198ls2094733lfv.0.gmail; Tue, 26 Apr 2022
 09:45:54 -0700 (PDT)
X-Received: by 2002:ac2:4c4f:0:b0:44a:4357:c285 with SMTP id o15-20020ac24c4f000000b0044a4357c285mr16991747lfk.99.1650991554206;
        Tue, 26 Apr 2022 09:45:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991554; cv=none;
        d=google.com; s=arc-20160816;
        b=aFAnMiViUsPo0ApWA5sOsZzxsqyyu0rk/yjSqkR1GBQWnAns7bVETqROf5wxtdje/Y
         uzWDmYOcfHH0NTGfV8y1eotmlLAur9GODglcOc9wJ74ypuMJIyEttijbdvGz3fFkKEqD
         DzARO6L7KsUzDtyu/AZ6VUZybGSKdInujUHwGkdDK914+A/IePWtk8k7eWznLy82Kl/s
         0VDHp0X7AVZZZzfE72vBNsoKymcn5Bm1vXI1OL8pxwf+BAl1MPHmZ+3HreKjxpUYRiQ8
         cXpEyvaQvPiEquKjLPN08QvtdHTeDTahWZKzZWuuavxJAyvefrvthgoE6DKzkj8xoY7D
         5vGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=UzBVkSVOyNRYl4KHuto6hQklAwc82x2pMcEIZC5XiS8=;
        b=Tw/skRS4aJMmo9yrIuKqBj97WaqYqYqjcrvwuhMYUU6kKSYp16N9ktSgZJDyYgjZDF
         ZcE9tAZmMr0q8BPuLfOCLoBBB0H4P6rd9HleR6T3jUiZ4CF6jjm+N/cK/cSF4mvH4uWo
         UXWmKkwGC7I5hrS7HiJJUFTwfQgZcH14PzI8nQsPOVshSFZVTwNuS2FUKaSEnN+scZMJ
         1cA0Dj0oErsDDOiNEsTDJTLT7J5g//O9BM9IS4XyFIfw7EiIHLyim212Pdjdv/Tpfm/E
         ldfG8R5X1B9rReeoutKJF2P6QeaeflGlazbRLtZhaYra+xYPlJz/6oGBMjwPak4F/3kY
         PFug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=owv8rcv7;
       spf=pass (google.com: domain of 3wsfoygykcb4kpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3wSFoYgYKCb4kpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b00471d641b327si606855lfv.6.2022.04.26.09.45.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wsfoygykcb4kpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hs26-20020a1709073e9a00b006f3b957ebb4so838755ejc.7
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:54 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:54:b0:419:9b58:e305 with SMTP id
 f20-20020a056402005400b004199b58e305mr25365353edu.158.1650991553606; Tue, 26
 Apr 2022 09:45:53 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:05 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-37-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 36/46] objtool: kmsan: list KMSAN API functions as uaccess-safe
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=owv8rcv7;       spf=pass
 (google.com: domain of 3wsfoygykcb4kpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3wSFoYgYKCb4kpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
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

KMSAN inserts API function calls in a lot of places (function entries
and exits, local variables, memory accesses), so they may get called
from the uaccess regions as well.

KMSAN API functions are used to update the metadata (shadow/origin pages)
for kernel memory accesses. The metadata pages for kernel pointers are
also located in the kernel memory, so touching them is not a problem.
For userspace pointers, no metadata is allocated.

If an API function is supposed to read or modify the metadata, it does so
for kernel pointers and ignores userspace pointers.
If an API function is supposed to return a pair of metadata pointers for
the instrumentation to use (like all __msan_metadata_ptr_for_TYPE_SIZE()
functions do), it returns the allocated metadata for kernel pointers and
special dummy buffers residing in the kernel memory for userspace
pointers.

As a result, none of KMSAN API functions perform userspace accesses, but
since they might be called from UACCESS regions they use
user_access_save/restore().

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v3:
 -- updated the patch description

Link: https://linux-review.googlesource.com/id/I242bc9816273fecad4ea3d977393784396bb3c35
---
 tools/objtool/check.c | 19 +++++++++++++++++++
 1 file changed, 19 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index bd0c2c828940a..44825a96adc7c 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1008,6 +1008,25 @@ static const char *uaccess_safe_builtin[] = {
 	"__sanitizer_cov_trace_cmp4",
 	"__sanitizer_cov_trace_cmp8",
 	"__sanitizer_cov_trace_switch",
+	/* KMSAN */
+	"kmsan_copy_to_user",
+	"kmsan_report",
+	"kmsan_unpoison_memory",
+	"__msan_chain_origin",
+	"__msan_get_context_state",
+	"__msan_instrument_asm_store",
+	"__msan_metadata_ptr_for_load_1",
+	"__msan_metadata_ptr_for_load_2",
+	"__msan_metadata_ptr_for_load_4",
+	"__msan_metadata_ptr_for_load_8",
+	"__msan_metadata_ptr_for_load_n",
+	"__msan_metadata_ptr_for_store_1",
+	"__msan_metadata_ptr_for_store_2",
+	"__msan_metadata_ptr_for_store_4",
+	"__msan_metadata_ptr_for_store_8",
+	"__msan_metadata_ptr_for_store_n",
+	"__msan_poison_alloca",
+	"__msan_warning",
 	/* UBSAN */
 	"ubsan_type_mismatch_common",
 	"__ubsan_handle_type_mismatch",
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-37-glider%40google.com.
