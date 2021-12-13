Return-Path: <kasan-dev+bncBAABBNUC36GQMGQE27L4DTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 74C474736F7
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:55:02 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dsf10296633wmc.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:55:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432502; cv=pass;
        d=google.com; s=arc-20160816;
        b=mKHVMtRX7TAzY+XAfZVIvO6z9M2awxulfo7h36yXTg+gL4v6zqSr5WRQd30IaaDdgO
         ff3bX2iOJ3Ue5xQSaE06vztAuPa0ukkmB4xuLFTVRe0vVKxG5iGSlQ+FuavrwUok+NKm
         xyOoVUPl8yT96S638pUUfhUWpucqwddJtAaFtMSxMJAMlZbFPjV6Bk4cn4m3vSeRqt7N
         WfTuasH9/zHwG763P288HEGY8JgAb8UNVV1VcKV0wR4LfQez1iVqyJ9Mf2fKq2Z7Qi2x
         Br3o7PnWTzR7zd9W3GVNfxCUmLjSbjD5OfhyNNYQ+MgoIY8FAT0edMV0w0PKTPWzz6Eg
         cQHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FH/YG2+2Y2COyZxih2EQEykBdwFb1sxeOLBUbXFiYBc=;
        b=gArCOMovQItD8Ui76WW84UETQ1Fc2lSXGfrv79vZl1xLVJ500pYMDQM+/ES65iFdTY
         Z0TJj9xuK7I6JWQHDv62+v/1OJhct5EvpDl8nUPtx9hZKwNozoMlRf/MAQ0yuV/CxALG
         419z771R8gWYjHbdjwB9fzkZ4OQTog8FkXvc4nJ9jkLvSm0+kcNA1GkmWQn8XZ+m9Zsb
         WlbZGhs9aAf6aqE/Gx85UJ6/TKEt7D2RmbC7n6r6h4Nh+0L+RH1fr3N8NOM3g08bTYXd
         3Z6zW3TDT13+hVJaXwh20M/FNeEgFNEFHDnKIcuFL/OUiS6saEd+jOHOs1DcS0yfDVKh
         lkZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OSZF9Qeh;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FH/YG2+2Y2COyZxih2EQEykBdwFb1sxeOLBUbXFiYBc=;
        b=f1E6J21H5Ob9K5lKlmVcef5RI+oZgZyi3ct9OsbhzN/u6VtF6Gsltzp1nAZtmtog+U
         7DFTtIUUM2Y8T4shMF9sNRvrEQH1FUOaD6K6G43GzXdM5uorp4EcrKLi+9cqq73P9IEb
         cPypLGV/5gSX+AoM4teBQcXNrRbh482Oforva+kGPTrz+0aHl4sdqOOr5ZrEZJvUv9cM
         agjG+PFGhCxMMOOe7SkXOY/6rNR/wOMm/kzhOJh3x3xXt5w1IB6QNW6x7NzxfnTTaiPK
         /tmrjWaKcHeWJR/Aq+DskDOM/4msVQNnxZSI0YCKv1tULyv13r46lQR8oZtmsDkhvNXb
         4HpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FH/YG2+2Y2COyZxih2EQEykBdwFb1sxeOLBUbXFiYBc=;
        b=BhYRWt1RmvQh3n6CVo4ZuSw6Dz8FfguZ7I2HjhJna0gHf5jRzmzbKqlYqeB+NVcWcJ
         PkRdOkNcCuDKSeYDCuJeAjw+5uvUVEK1hWYzSgK4Vfl+Wfr/yX7EZ0JdSNEJydr44U6T
         mD+i++9NcD1NGchGLK6Jj3mmSRGS4FrepWk35IupGTontJC2QpiF+Z+cMTXzGUlBDbab
         9T0KvGMe86jXcUd0IqB4k12BhBD09MPu018gHgDJky8nYwXhk4Rri+zYCVhONznX5v1B
         yNfBMCG67hC9Ns+smjx0WcnS8mbOIrzCtFJK8u46xyAcEZHupHbi5ibyXwMYUrd51TFo
         6KBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5301IpiluflMy62rQGQpANSAcuY9vxaVcp0yIY8D7Ok0UvPHc0QI
	a/Bvh6bV7zs7EuTbj7bJw/I=
X-Google-Smtp-Source: ABdhPJxXK1gk/BYV1unrO1dx4F8d9nER6T/o/gjVLnretb/Ba0jzXz4orFyUYJuOFfgz9t8SItSz3A==
X-Received: by 2002:a05:6000:1aca:: with SMTP id i10mr1213593wry.407.1639432502256;
        Mon, 13 Dec 2021 13:55:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls502550wrp.3.gmail; Mon, 13 Dec
 2021 13:55:01 -0800 (PST)
X-Received: by 2002:adf:f504:: with SMTP id q4mr1265060wro.698.1639432501589;
        Mon, 13 Dec 2021 13:55:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432501; cv=none;
        d=google.com; s=arc-20160816;
        b=Q11PIAL+2Sj3H61s+7XANTObjZqmYpB0TXYDhdE8K9j98iQUlGphOijBVSkwOSEiho
         cFOrqcF1En0Z8LjcfOALnzz0iL6Pt4eWnxo2UcvZbvniWUGQ7YQvRyWQYLDRMmOZuzSB
         10IJxAKwrpUykCD+UBgevJkJ5N3b/WpoPfvqas2gSpRkoa+sLJtAtJrqir0pKNh07g8+
         P97toIX4eJhqfd7v/4yaQVcrtwACS+wWEKUw7xpnzbMtUVOrj1ZnjNjiNZ/PAlVrdlAf
         qk/5qN1USW9HuNTahaTj92Sru2hj++Cbe574Clr0GtEHhpcDk+URPlJ8lCQsWgXd0Fup
         tZpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xS/npKqLDOlLS7GUOQeVJqvjcgKhqLlgaKGLm1W4Mro=;
        b=QZ9Y6K3jJcRJKQ927gR+TyNgtdKUCa2KkQKuPft49Hw86pGiHFKsyTENe3ZBcncxeN
         m1O0a4aj2EhHZ0DK+kiF+GakDUB2ET+jysXotmV/RDaZI3Txwbw6RrNJPYrBUnGSkvHL
         fxV19AFbZEk7wPpAzzP5OTlioGYWuWvbnQFBOOeGzF6gwPU/r39Cpg0Aw/XyYJzyjQUT
         TG9JhHqN2MqZF4hrHfVsK1PDfn0XFJ2tVdttMeZ4T6kUPEciknmFCThsCfwWy4pX3aW7
         5dz+dmOcm/wJ19KtoqyZ0MnYZhDD9qESlzCxp5ducID+vjMVgkODuHd/+SMM3AH9J3B/
         nKOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=OSZF9Qeh;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id x20si395571wrg.3.2021.12.13.13.55.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:55:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 31/38] kasan, arm64: don't tag executable vmalloc allocations
Date: Mon, 13 Dec 2021 22:54:27 +0100
Message-Id: <4a5ec956a2666c1f967c9789534a8ac4d4fe26f9.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=OSZF9Qeh;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Besides asking vmalloc memory to be executable via the prot argument
of __vmalloc_node_range() (see the previous patch), the kernel can skip
that bit and instead mark memory as executable via set_memory_x().

Once tag-based KASAN modes start tagging vmalloc allocations, executing
code from such allocations will lead to the PC register getting a tag,
which is not tolerated by the kernel.

Generic kernel code typically allocates memory via module_alloc() if
it intends to mark memory as executable. (On arm64 module_alloc()
uses __vmalloc_node_range() without setting the executable bit).

Thus, reset pointer tags of pointers returned from module_alloc().

However, on arm64 there's an exception: the eBPF subsystem. Instead of
using module_alloc(), it uses vmalloc() (via bpf_jit_alloc_exec())
to allocate its JIT region.

Thus, reset pointer tags of pointers returned from bpf_jit_alloc_exec().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Add this patch.
---
 arch/arm64/kernel/module.c    | 3 ++-
 arch/arm64/net/bpf_jit_comp.c | 3 ++-
 2 files changed, 4 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index d3a1fa818348..f2d4bb14bfab 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -63,7 +63,8 @@ void *module_alloc(unsigned long size)
 		return NULL;
 	}
 
-	return p;
+	/* Memory is intended to be executable, reset the pointer tag. */
+	return kasan_reset_tag(p);
 }
 
 enum aarch64_reloc_op {
diff --git a/arch/arm64/net/bpf_jit_comp.c b/arch/arm64/net/bpf_jit_comp.c
index 07aad85848fa..381a67922c2d 100644
--- a/arch/arm64/net/bpf_jit_comp.c
+++ b/arch/arm64/net/bpf_jit_comp.c
@@ -1147,7 +1147,8 @@ u64 bpf_jit_alloc_exec_limit(void)
 
 void *bpf_jit_alloc_exec(unsigned long size)
 {
-	return vmalloc(size);
+	/* Memory is intended to be executable, reset the pointer tag. */
+	return kasan_reset_tag(vmalloc(size));
 }
 
 void bpf_jit_free_exec(void *addr)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4a5ec956a2666c1f967c9789534a8ac4d4fe26f9.1639432170.git.andreyknvl%40google.com.
