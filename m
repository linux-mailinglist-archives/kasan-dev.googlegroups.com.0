Return-Path: <kasan-dev+bncBAABBYGVXOHQMGQES5NLUFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C7974987D0
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:07:29 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id i22-20020a50fd16000000b00405039f2c59sf9487241eds.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:07:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047649; cv=pass;
        d=google.com; s=arc-20160816;
        b=vSDW0NVBI9DO119RwxGQsGa8HhWPn1fAC5sNCNUbQ1YO/FYaFa5ZKKDV+o3JhOqUAO
         rwzfhwtdQxXuUQOofP5/P6uRK8pBmJff/u0mDLzifGSOummJrp7QQk83CeuHF6/C635X
         uPU7GBdT8OmairtBQEbGvjQxQkZrCz3x+3mr3jwwGr2+QDFj75X7ERCS/GUD1Nj9c/o/
         i9c3Nr8h1xzdBTtnp8hRXXdFu/0fdyjlMybEWpjQsRZRoI0gUzFLhEdYpBEHUrDOeSgn
         pDw3EsslvhQvQHycxbML3D9iiHViUmGM54T4pi4fMhrDuDHHtjTrgc4StCXcVDcRthKX
         mgyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GcwCNcdv8FVTg+A/GFKTJ7YmYxevmQMfYbcp4UsqPlA=;
        b=tQ6dCEHtwx8BKNjuL46HVK9IPKXOoQkBHGt1wjwryZJMrvAtkwsdDNRuSXiozjGZAG
         vkkx0g4rxtDxuc+/zSjOs/VimYCxMWzBYNuV+wD4nzE9BMW4FXVb2PNO/WAI4+I95v4d
         koRaj4ce8SwG+FnvWXfKGfLYZoJPiibh9J1FW5mCOFnJVae6sUr6TFgH/ZtT5uC6C71W
         rJZoGP5dJ7UBHkk/mOGathuOsv7iVNhaipCpFu3nk1eGzwtc5REFH2ZqSgu86XIGmIpc
         XCLiznelJASlvCywBepMQKURGwp6nK1GafuL79I/lP7+GaYTi3z44tIuXP1j2z2AwYTr
         TkRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tAzFc365;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GcwCNcdv8FVTg+A/GFKTJ7YmYxevmQMfYbcp4UsqPlA=;
        b=TMv4dTrKuDblXLltge1qNeeccaP3d9O9In2a1YaxabTtuC5DiU72D/54hLY/wyzLHZ
         yC6pWYNeiIONaQPZQRCbD6Q2OJAmSpUI4wgBspRIcWX1H+ef2+ePF+xtwuNL1wrAH+GE
         KP0u9WsElQOeIPEZbUv9eQpUpboWeG7o3I7xN9hn2PYtkvM1ortTc93IMVe2ZqoAv1Xp
         j8wn6IhQsMnY7JfK3o9ToMNJDrM+cV7r7SV5xI71Ivs2kdEGgHXn0RdoqQ1Z0JxnRNHR
         Z9f3fbUjFPIG0RAVmNWs0yxw8LlmpYd7wequ/x7SS03zv09CJS7Ww5HetGOJulArZfcV
         8ogg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GcwCNcdv8FVTg+A/GFKTJ7YmYxevmQMfYbcp4UsqPlA=;
        b=vpKIN+enyeCZtYnHBWE+rqVTVhXxrd4EsCPTGW9dYz2Y15utuVTKLIoknqCDFi6IeK
         zP4KeWPYp7zcXVpxxhAm0C6BJfA0ivx8ztnhXpSUOk9I4CTUkfexNiIcn2ai8hS5eroq
         PRrabiWg0l37thDcbTnpNMZwumo2thXvKCfcd4kJUAAi9WleOfwL0kX/1MregLDG9obO
         kLS6/q33OlXywc+wvJ8Jsjj8RMYP7QLYmJBHdRd4i0ZTGNNERhHxqORwdvpd/sjrKKkp
         0boUqDaybi5mRdLDOltn7/4L/7guD2PM+VSIbpsx1MvnivjSwxN4uHkb6tLNorVWL6t/
         k2Hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532EGPYVqzQ2KxZxiSqGYZ+V0mxx9gWgmCUlj7bgrkqbXAhW8yAH
	b1jD3weu5aydBro5BIpjcBk=
X-Google-Smtp-Source: ABdhPJxDsSGZ1t6cP+aKncRHYjmn1cPdbvbn7gcX6Ah5Ql9w3jC0O4h8rP64q+vJrPM7Ml7ES/gx5w==
X-Received: by 2002:a17:906:65c8:: with SMTP id z8mr14237800ejn.727.1643047649105;
        Mon, 24 Jan 2022 10:07:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:370d:: with SMTP id ek13ls5754902edb.1.gmail; Mon,
 24 Jan 2022 10:07:28 -0800 (PST)
X-Received: by 2002:aa7:c046:: with SMTP id k6mr13438064edo.9.1643047648397;
        Mon, 24 Jan 2022 10:07:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047648; cv=none;
        d=google.com; s=arc-20160816;
        b=hFDqqiFuYqjsMAwBmnh2ARnMOGbALaR/kZfn5JyZ7c754lCarC84YfPiK+3SwKKYpR
         hfKN3XuhVOJa51JCi1QqXsk5h1noAvz2q1b1PzPcGtNIQldWueZLHn/QIg+nroKOq9aZ
         Uj3atBjkOFY7Zok5mKoRjjq59pprLPNxR1eBBVcg+GT2bJ9XGukSlBIHnJ8O9+5maA0s
         lA1Wx9M5aZ+dtzxAHcUqlwea/KM/IKP34Wl4HD9QmRyIEnKXMepb2t3b7ifT0/tt1zoO
         /hD8aAi1BxcU1F8+j/dW287IJqlefBOUbe2iheVFhiL4V+mLyKXfN230T+VKJ8i0F/Af
         ZIzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TFKsp+57v018bGervn3rQX2/toL0nwmJo1LVwhe4qDg=;
        b=Xu8RHaAMN+OCOLJMeEqs7YThGHNQL9p4cfHzXCstYfK2Ioe36ke8rwDJ04UN+7U/KR
         RPzxEYOYvt7PWiBJQnCo5h9XdQl2gE1TrpTJyH75Vp/20ADAOlI1e7IPVMrpXZpZDqkO
         nspVvMt2sE/krVveCtO6XhON5Jni1hqKDvf5m6IwuwvxD47jMBnt/ChFyRQqnqwOOb/U
         32aSALllqFguAcwF6bKPfIKoaqBOoYqjKEUMZno36qPqSv+y66kGb4LYZxgJg6+5j5+t
         fSHEc7cvR+YjaQofcJauOf674BCITaAUd+rp7KWN6+jnK7aHDhTi24E7XpMvQsGWbDNU
         ZLkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tAzFc365;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id v18si787845edy.0.2022.01.24.10.07.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:07:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v6 32/39] kasan, arm64: don't tag executable vmalloc allocations
Date: Mon, 24 Jan 2022 19:05:06 +0100
Message-Id: <b7b2595423340cd7d76b770e5d519acf3b72f0ab.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tAzFc365;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Resetting tags for these pointers results in untagged pointers being
passed to set_memory_x(). This causes conflicts in arithmetic checks
in change_memory_common(), as vm_struct->addr pointer returned by
find_vm_area() is tagged.

Reset pointer tag of find_vm_area(addr)->addr in change_memory_common().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>

---

Changes v3->v4:
- Reset pointer tag in change_memory_common().

Changes v2->v3:
- Add this patch.
---
 arch/arm64/kernel/module.c    | 3 ++-
 arch/arm64/mm/pageattr.c      | 2 +-
 arch/arm64/net/bpf_jit_comp.c | 3 ++-
 3 files changed, 5 insertions(+), 3 deletions(-)

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
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index a3bacd79507a..64e985eaa52d 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -85,7 +85,7 @@ static int change_memory_common(unsigned long addr, int numpages,
 	 */
 	area = find_vm_area((void *)addr);
 	if (!area ||
-	    end > (unsigned long)area->addr + area->size ||
+	    end > (unsigned long)kasan_reset_tag(area->addr) + area->size ||
 	    !(area->flags & VM_ALLOC))
 		return -EINVAL;
 
diff --git a/arch/arm64/net/bpf_jit_comp.c b/arch/arm64/net/bpf_jit_comp.c
index e96d4d87291f..2198af06ae6a 100644
--- a/arch/arm64/net/bpf_jit_comp.c
+++ b/arch/arm64/net/bpf_jit_comp.c
@@ -1150,7 +1150,8 @@ u64 bpf_jit_alloc_exec_limit(void)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b7b2595423340cd7d76b770e5d519acf3b72f0ab.1643047180.git.andreyknvl%40google.com.
