Return-Path: <kasan-dev+bncBAABB4P2QOHAMGQEHHGOFZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DB8747B5A7
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:26 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id bi14-20020a05600c3d8e00b00345787d3177sf578024wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037746; cv=pass;
        d=google.com; s=arc-20160816;
        b=L8q/iNTlkHRnGHhSlAbytw+FGOs2hRN+1GIcK0q/b6wg0SZ1ytqyU9K8nzRaFYnhBX
         5B6aZaaeSbkQNiW5Fm8TWnuZVOuZTeYRlNEYqyT/8dU4hCQkGFrUtAr4MqUVSvAu++7l
         JHH9Eu4JN9KTstCMhEaqoEJIMnsR6lRC27pbU8HGoSb35i9O9JQc1ux6ilQBYrI1u4oF
         hLMR17UKIpGQGcgaWE7A2MDgWYlBjE5PbT7XNP0XW/aKJv1S3MlqClDMuaroZAwzXLC8
         xpNnuHnsOcihQW+kUKJjYx3n3fxPRq8WqbMLwZE/MD8kpUdrk4U6hzhGNQFBW9neXEcO
         HfEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XmiEPlM/sRyiKIOlWbIgFDs7uUppiNyiGr1m5RiJW/Y=;
        b=XYYasR1GPW16uXVpzOWJsjyUOvhYAANsh1KoB3tE6T54FlLqQfphD1dBTWSmifR/Ny
         3pJYl71jvQF3fecrcieFQGsBnzBmRDuFexowpIgAXkx6kV7WtBJ/ctvmwhpwdmjmEnCA
         LlsQMTzZs5TqH5KymIY+HEZ7xyFv8zari+M3bE/MzDw4LtjAKWPZu07Ksz+gvI4Jsz0N
         MQxrIA/g8Tv5UprTzrTmn4/5gmze8+CpFhEX19uC38txEMAs87Xu/5hLZXNRVJhSO58f
         4Y0JCSPTmDXEQzhTAx1aWOAHghneMCIg21N/V72rws2Ob1G/lekTCbN0UIaJ+37/A6lj
         yzkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wN4VXifd;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XmiEPlM/sRyiKIOlWbIgFDs7uUppiNyiGr1m5RiJW/Y=;
        b=TP/vkZZOc7OlajCX4iE0fb1DV9gNL+DWrW4Dx+XoipMtTLtIg9U7elaVYvb73mXtYg
         zM8UwZRsUlRdq3bqSS+AQVwSTLpnJcBwgvbhO7zaGhajApM9jQneXqFWcWGPSNbeVZHn
         VcYMxp95C0jpcopjuZmYB+6Gmvm7BGRZF2Mm9qp3pZ7UMIxD3OIAEAYIzyJCJIwZMDFk
         HfbNSnGxYxkhux9EDSrmPvhWbiBU11OsE7DfstBy+MMcGttlvlB4wNk+qwlFjKHnlUL7
         wSkxE6R3Xe5mqHrPU2vIWZPJfQrly96TzsinFVMDDW0Qm4FKvDL9ZMXclix+sypW7DEi
         cuIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XmiEPlM/sRyiKIOlWbIgFDs7uUppiNyiGr1m5RiJW/Y=;
        b=YQQEU0ZBI3KpXx7xlbd+kJDioDoMGR96zU47/Xj9+c+E1BskIOYlZ1QKd8sooylx2T
         k348kkEwz9sUYwRID3LUwnHVWyy2+Zm8XWjj0pxpAk4GSb91I73GqazdQFkxw9GKNhRo
         F1BZ10i0Nwx/Yjm59+CkWB9xbMeIZtUDmOrfIE2h7i+v0Kcvm0bn3PURSs6THfBFqkL0
         mWwAwZtdOzhaXsTOlRygVYwSG73hhzFb7SH2LcTPwlU8InQiuPLf1GJGU8Q5Ep58BFMV
         Tx2hXt2wdWZ4doscWXN6hZGpDq+02HCuWiqETsOqP9vwRai+rXKxP7tOvVlshAsC1NeH
         hThg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316CrG+WBImjcfqeQ/foqMy818JsjJGoG3Lrp5pUiHAJKtJsnFt
	kXfM8TdC/+x/Gj1WBBejVcE=
X-Google-Smtp-Source: ABdhPJxgryOUrmWzrR/a5gGs3EbTBFrMAjQh0Fxk228HbdOEGX18FxFt0iqZB0yPLsDOtPZbxK3I4g==
X-Received: by 2002:adf:80a1:: with SMTP id 30mr86917wrl.557.1640037745919;
        Mon, 20 Dec 2021 14:02:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2102:: with SMTP id u2ls33368wml.1.gmail; Mon, 20
 Dec 2021 14:02:25 -0800 (PST)
X-Received: by 2002:a1c:7e14:: with SMTP id z20mr46wmc.25.1640037745218;
        Mon, 20 Dec 2021 14:02:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037745; cv=none;
        d=google.com; s=arc-20160816;
        b=V8bFdDFtxzrgf2YpxmX62APzyuFVhlGbm9+FKL2QZn40NC8K9UR45mSCT/LhklMIfN
         Zn909l1DLoXf6zAiNFbSTommtwFSAmJ8qvht+PG64BCzX/FS5MnOUu70SEmsB4rlpIe5
         QIyb6QrmRLmO/YKm21uTYxgP1H5OqaoR2OXM7m87LNW+OuZxk6i9BubztO/si+WTIzYH
         RzGkxzlWU0wdNGQ2f9g0D+eef4foLNaC6quF6Y9CCKR3oCv6nrtyc+F9WRKNyWvBdkF4
         vFJTMC4iImOSM8K6VQK89O6oMAf1+EKS49YVGe9aSDD4fSs/V90EHYkKMjnO6B2nAP+W
         RlnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CKPECQmnEvfKq7xgUC3iieZTgX2FdEGW1DTUi5n2vOw=;
        b=ntVNhoAJbQhlb6CFp0WaY8yNQhpmt+APGEDVM+X+iGSfuHBXVKlb8uL7PHca0hFKz0
         raN3+YokrE5OtU/X5oJ8GLiny1252jO652Pw8PcFEuWPrjo+AmOrvMdGe1oQCitIUfPT
         WPP8Pr+jEAO2WfExzU/9xjs/bwSKLcX0nFjSEH7uvoRKWRA/m7FyQZoa1jZPanSNcf5U
         LWU0tngWhbEGmMLVzvPqow0zxr/Simna0GWTs5TqwIf90R32IKTh3nvIVOqXoWHQ3LfP
         ILqXW27yWleTpVZKs/kvJfEBLTlMTQqo7pU9WmFu6cjtYPjVmC1nfnN5KGGmkKJ53J88
         dABQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=wN4VXifd;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id j23si79727wms.4.2021.12.20.14.02.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v4 32/39] kasan, arm64: don't tag executable vmalloc allocations
Date: Mon, 20 Dec 2021 23:02:04 +0100
Message-Id: <85ecef50788a3915a9a8fb52e97207901f27b057.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=wN4VXifd;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/85ecef50788a3915a9a8fb52e97207901f27b057.1640036051.git.andreyknvl%40google.com.
