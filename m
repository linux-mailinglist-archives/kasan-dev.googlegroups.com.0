Return-Path: <kasan-dev+bncBAABB3FEVDEAMGQEBHQYH3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id A9FE5C319C3
	for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 15:49:17 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-471006f4750sf4667605e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 06:49:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762267757; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uxd246qJsoTXfLqnS/4RsNo+FSvK7PfymQxBJmKFe5FHL8rVFDqyQOovqVXvpPV57+
         lSssBQ5Cyiuuz+y3Az0gLmLEOJF+SLiVqd0vksGVNVpJkmW9UD1wDmAGUvKMJ//4H6wx
         tGlC2ExAAUB7nLTHTxQsqiMgJnNHzx6eV0dEW4HEkUZgdO7FbWf4YXGBdGN62dcqi1Mf
         m0/EdWoaXet7T6rsBhs262q2j7x9DdtKkp14BwDBEBpY9PexXLJ5+U8gb2SUC10CF2Oz
         6ahYsoNqvwF9LnuugCPnRX0YwQ9wsYKLci2zMcxfrugbOCkP8boIt/uLrjnHfa8omf6Q
         6xjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=Yh2mSLpa4S01aavREw5vd4O5Jakugn/PP3feF4XjQAY=;
        fh=g+j3z7/75xznrXMO1yHbSOrsUROY8bkyiOR7LuD1u6c=;
        b=XmRdATaZGdwKMWMIMfe9cG5Kv6SrzvrBKt26mktNZO5DQizFTCnlDf0lSUyGJWCjuK
         tRAoyjWo7PCya8KzpEDqIZ+aF3IEbfT5epUX4/1H6TTpZcuZYYzx3kasXhNCrQRpf896
         4z3dnxpryRz9jX4rCWl85DZ/Jq/66X8riVYHh4GR+yrMKjcxd3boL4Kl/P9b3CK8CBJy
         OUriOI/Z/f7J8TUXnA6xmp2XGG2iPuAiioxy/TGSzK+M9co9AObJNZ1+owKc92scGB9Y
         6vBcbJnWTFOVx4ceVxewPl5v469qwRs+ecGmNtdXzPG1FZivCFb0I46m3cjwj78fzi+G
         puLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=sLxtTSkC;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762267757; x=1762872557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=Yh2mSLpa4S01aavREw5vd4O5Jakugn/PP3feF4XjQAY=;
        b=p67H4I+bjsgeU+7VtJsDbQMLsh+hYnD6kqQ9VjMKbgO+D/YKTQwmnMlIF2ljRTHhdl
         ExSlTj/1Qne4awVujAqosDvGS0rGxLZTUBo7dSXkaelGQ/LrLtVUyJ4C49OosL7mRi/5
         tuRD1NUwnqwCqJMABtjV3q+wU2z6cpXKnDhNi97ZwGJGBQkNl6xAmkRDMx3mFgZ5Vwn5
         yQaLaE0KUMvgf+NpA2nbnlqjAbjFuREaW9qFxWBahEDMTT7HEIU2mRdwZLCcOQClGqOz
         CWTTKG243SDViVRtZCvpN+dDjcEGEUVV1s9wpqrW971+Mi+/8DcgvZVRwfcL5A8o2lo1
         gwZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762267757; x=1762872557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Yh2mSLpa4S01aavREw5vd4O5Jakugn/PP3feF4XjQAY=;
        b=md4/PpK77XvHf0aLVbGTa7fzJ4xGfuKv7bb8rBYRNIJ5wvZaucj27kKhG+8OCwZ8lw
         4iMDUFp0LlHIkIu8tbjxMxXqSem/Z8BhIyB1HCHQcINTKLWWUj5/IeTx/H4i6TaUlO2K
         YQYzaagLjYzsTkFgLVBSPulFdnr333G00MC+eLOT5OfQD45onyfG/EEeob8V6lMNg1qm
         TdaV/bgzXRdOBKIbeuvDG07xtQTinL103n957kQJ4vDGx3eG+PU8LryXXWNdY65mVIAC
         myjDkzzs2Pe8NRJqhWfDa96NvqTkPWAXstn6S1LmkrC5UoltkUB3LWfybp+shTD3eaC1
         xz0w==
X-Forwarded-Encrypted: i=2; AJvYcCUKb6bV/D2DIlgxEWBIjBayDpb+0YojndoddTSkCXChCZOtOHvtAG09tac97nJ7W7Rdj5WCKg==@lfdr.de
X-Gm-Message-State: AOJu0YyCQx8Jjgyr0BDmf+Qs3uV98UtokCd65rMBp7PacBDn3hQ6rkuw
	y4jflu2JoB0SlLS1Ccu9hAnfC9m/8j7GwnbVfFqnxcL8NqWU5I3Acb5L
X-Google-Smtp-Source: AGHT+IGgmfsbhs3rD9oRBVXL3Gc23MctXe3vl878yyIJbflVTAPedJKWZKch/czu4bnxkxLJwX5iKA==
X-Received: by 2002:a05:6000:1ac6:b0:429:d6fa:da2d with SMTP id ffacd0b85a97d-429d6fadf6cmr3001507f8f.6.1762267756845;
        Tue, 04 Nov 2025 06:49:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZOk42L18JdJmRpwNOeWgGfO1O+oQb7Wg6JAMTKnVTZLg=="
Received: by 2002:a5d:5d87:0:b0:429:c4cc:450c with SMTP id ffacd0b85a97d-429c4cc4578ls2121237f8f.0.-pod-prod-09-eu;
 Tue, 04 Nov 2025 06:49:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVHawXkCRGRWFmMyuzBJmCXXeoIgzgXegYri90zRypiSts7ZV7RLemN4d3yaxtTEcP2kkYJMnTMrYw=@googlegroups.com
X-Received: by 2002:a05:6000:186d:b0:429:cf88:f7b2 with SMTP id ffacd0b85a97d-429cf88fb45mr7847701f8f.45.1762267754203;
        Tue, 04 Nov 2025 06:49:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762267754; cv=none;
        d=google.com; s=arc-20240605;
        b=fyKqfUX6ugdLLDSR3n0fT72JHEf2HzznmIvDU6iUFcfOWhM5SLf4klPpCCKSXtjZU7
         BrJ7vXeD7VYTqS9iQwT7+bBvlXztk8h2hlnbNNukh8XJ3Ez0MFkEq3RgDs+kr2GMgwNA
         cEgm6IRn8LBBIhVNIx+AtxSXAQHnLhRef7zUsf7CXXQ3+C7c8SJCqnkx7ZFsU9HRnQBX
         BQaOneotXmtl2Iul1LATO37248sGjE2dps7tC963EO20OXzdD4D5nbvUOdDRHzwGDnlF
         4C4xXBQkOIXFzfp/SISpN6K07QUu7BXgdvgU+I1PLC3dNL4hXyQK3fgwAVA6KWWeA9aW
         WojQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=xfqs8NGDzi/GLs93yh/ZnyHEZsNbd7BFWZBeJoDbuBw=;
        fh=xDZhXd+IF8GN6m2ess5NksrtD0hmt9kwl8HBvZpxyrw=;
        b=UmNFTvOam4jUxq8Z7ZPIU5FqAhilt0v+tcBGNoYZykbo+/6SRYc1+fcBVtO3i3rMpa
         h/85gyuuC5IqYdFKEv82w6rlbPRjXa7yQBqu1M1gO9QPok3+BDuVWx6EFsyTMHPbKJgm
         dRfqrBeAPjn4wVRGVlg6BBIvBr3DEt2j/nRjeUd+GklR5kGTbeupa8YG9F9c65LKbD4Q
         hV4mSN9fNqQAg8iUi7cUmYME1ReePkrxSvQYndS50g9Agt2SydQbmwuwStZLVJL5hLad
         eQKAwktryrJzB5mxJtiBra8pfeqLUv7qJ50+pUBDOMNBK5q5j9tHDwTLyOf+qAK0rsR/
         69Kw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=sLxtTSkC;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429dc1d5d56si52112f8f.4.2025.11.04.06.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Nov 2025 06:49:14 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Tue, 04 Nov 2025 14:49:08 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v1 1/2] kasan: Unpoison pcpu chunks with base address tag
Message-ID: <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1762267022.git.m.wieczorretman@pm.me>
References: <cover.1762267022.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: fd6efc8602e9b03ae9b37c660c7f86c9a4b17086
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=sLxtTSkC;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

A KASAN tag mismatch, possibly causing a kernel panic, can be observed
on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
It was reported on arm64 and reproduced on x86. It can be explained in
the following points:

	1. There can be more than one virtual memory chunk.
	2. Chunk's base address has a tag.
	3. The base address points at the first chunk and thus inherits
	   the tag of the first chunk.
	4. The subsequent chunks will be accessed with the tag from the
	   first chunk.
	5. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Refactor code by moving it into a helper in preparation for the actual
fix.

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: <stable@vger.kernel.org> # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Tested-by: Baoquan He <bhe@redhat.com>
---
Changelog v1 (after splitting of from the KASAN series):
- Rewrite first paragraph of the patch message to point at the user
  impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

 include/linux/kasan.h | 10 ++++++++++
 mm/kasan/common.c     | 11 +++++++++++
 mm/vmalloc.c          |  4 +---
 3 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d12e1a5f5a9a..b00849ea8ffd 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -614,6 +614,13 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
 		__kasan_poison_vmalloc(start, size);
 }
 
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms);
+static __always_inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmap_areas(vms, nr_vms);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 static inline void kasan_populate_early_vm_area_shadow(void *start,
@@ -638,6 +645,9 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
+static inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{ }
+
 #endif /* CONFIG_KASAN_VMALLOC */
 
 #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d4c14359feaf..c63544a98c24 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -28,6 +28,7 @@
 #include <linux/string.h>
 #include <linux/types.h>
 #include <linux/bug.h>
+#include <linux/vmalloc.h>
 
 #include "kasan.h"
 #include "../slab.h"
@@ -582,3 +583,13 @@ bool __kasan_check_byte(const void *address, unsigned long ip)
 	}
 	return true;
 }
+
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{
+	int area;
+
+	for (area = 0 ; area < nr_vms ; area++) {
+		kasan_poison(vms[area]->addr, vms[area]->size,
+			     arch_kasan_get_tag(vms[area]->addr), false);
+	}
+}
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 798b2ed21e46..934c8bfbcebf 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4870,9 +4870,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * With hardware tag-based KASAN, marking is skipped for
 	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
-	for (area = 0; area < nr_vms; area++)
-		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
+	kasan_unpoison_vmap_areas(vms, nr_vms);
 
 	kfree(vas);
 	return vms;
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman%40pm.me.
