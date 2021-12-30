Return-Path: <kasan-dev+bncBAABBBELXCHAMGQESSCSIBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 75A28481FB9
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:16:20 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id b8-20020a056402350800b003f8f42a883dsf10396806edd.16
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:16:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891780; cv=pass;
        d=google.com; s=arc-20160816;
        b=wfH3KllP5H+HDfqKbYnz1CVGeH44ltgga3zPNAR92hU1Gt37oa0kMLtzrYoEJOoDwO
         UX55JUaV/vzCqtQCOySbBsvD0bWcMvvKddVT0HaEicDv0nBfFhgfuv/0YG4lO69n+M+T
         S4AidXDw/PFLg1X5N2QMa8xctuBSFiOteJSUb6AsbjQo01elbOSZKAKdEq/6ZfdSZGzr
         sCF+5A1jGfdMo1HBxGc0LqVj+Ed9u4F9NzwsCw/YYqQtUVSxGIw/gkiQwddmD4Vno0aq
         NGZ51mdSLJU/3tIZHDyqLSWACZCuMk1aJerBnXf+yCHITat3XldBrHADnxYGjdmwPHyc
         vfcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IBarRXDEVVEW3BcOBih3hFBKEyvHmEUMGdojfMiqlyI=;
        b=S8Mb6blBhbw+D3F6kb8rjxWBpXFEMZ7ZClL1bATKFoQhqu88r+wvnQz3DmBVOEtD71
         xF6FN5MdF+v31DXkyG2GVuAGRJdehHn3veC5rxtd7cLStGQqQBIbnqNYRW3CgWyFbWlw
         HbTlGIAcDzA1l2CMnwxLciG30XC9OEjczFAuohKyg5cpTEC6KAEJray28haqa4TaGR8z
         fewF9C4zrTbkaKfQd+AicoGwL6GvirimGxUsgFs1ByRwzRfX+8JtSLJGw2ho3N3rjWab
         txbt7RjrwO0+hNNRRARG9F4rD7E7VW36MFX51jcCG9lIRWh8fItKtqt6BewRZ4FPxM9d
         V+0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=be7gQ6BJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IBarRXDEVVEW3BcOBih3hFBKEyvHmEUMGdojfMiqlyI=;
        b=AnX/LqLuIz2UWzc5A010OiXcMo+mAXXdm9idr4j/ZhYCO92PX+tQESb6Dn+aO8Me1L
         JeBmgigFoZQWt2ZoTbRjzr9mC7IOjTnKw47900wULrmsAytyyn4ulaSxeigiDkt7kACR
         GHYvDc0G3Ta5hF6G0m/n3bhDlZZb9fohDa++5uEeAEkTPZ3Asm5bRcDFuvKxd27B+HaP
         qCG77yN1E02vqomNrayjWpu16C+gcuEkcH0S+msq7jdY5XGpIP1r2YYyUELNK8izDY5Y
         hkips9fnmXeCG0cOSfehleFBN/D9IbPbwx+w/T85nK8KAOTgzmEFx+JjJ1w+EdyoRcVX
         ggyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IBarRXDEVVEW3BcOBih3hFBKEyvHmEUMGdojfMiqlyI=;
        b=CPGjsDcbTTTKyfOHEs821zLqI8A9azCHHjuuPG1zUZRpT0sqMgC06rqFmRH2IGsPs2
         mXI64mjZuZwyt2D2xSsd+PAQwMpt9AWpaRVHsKgQOcM1y0phP11obfUI9Tqtlm8liqTq
         B/wzPA6iw9TC5H+JNNZHEmZSRnM3e1Ob597tvqwRyWshNNPdSCNak3nDnM9IYgtgh4Xz
         z1Nj+n+741Mlf3vYawfAMn7lNhhklqxnAnwnlzenmjiof64Mc+MdkbmnLJ02bT4EJBfH
         LjKqg1Ym02N1Uqw9mZiOmup8IyafF2D4D4lJkg5u77SaMzfE/H+BSbio2q61i91g5IeO
         WbLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Y01BZk1AslzUZFdjQV69M2JLw/H2xeHL1krPryjJpB787v9Na
	HST1tUQVFLQANlFcgg62Muo=
X-Google-Smtp-Source: ABdhPJxsI8cdW+OH/RAOl3KcJ9VP04/VIFo7v1AFU3X+CbIakPKdVD6rszRH/4TvTXmC1kwOFDbByw==
X-Received: by 2002:a17:907:d29:: with SMTP id gn41mr27195180ejc.124.1640891780248;
        Thu, 30 Dec 2021 11:16:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d56:: with SMTP id dz22ls199467edb.0.gmail; Thu,
 30 Dec 2021 11:16:19 -0800 (PST)
X-Received: by 2002:aa7:dcc1:: with SMTP id w1mr32243765edu.262.1640891779587;
        Thu, 30 Dec 2021 11:16:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891779; cv=none;
        d=google.com; s=arc-20160816;
        b=qtupmR/r2maaL72uc9L01EmaW0crjX4bP+GmN/mHhonlJ8omJDrKxyQn2jDChNCwKf
         xHXmRqLj17aMJXSNiI1CP6GfiMRYyEOngDGS5h6QokF+lCO++jym54SyGiy00hURi3tS
         E5y0rkf+hSvfIUATf/AznywmcUpjpg5PxJMJsX/CZ8NsfdyH+MWmUHvv+ToSXQsekw/c
         qfm78V9UUdr/1EJf/MNu58TYc4Rd14Mu9YBiZz/pMt+MuoIfnsLrXi5I+MtYnrHIZQr1
         +cLC9do0bzQdlSFUbgtSnhG9mDPn731vM/M/Qp+7zlFUWbhmfTKot9pzJR4ES7grasoM
         uhcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wa5dnCuIAAFZXmbcwU/lwh0PzifCMo4jVhMhMRLXZ80=;
        b=MxAWtXnt2s10a5Mb3phfpDnPtoHH0d9F3wgaT6XXnn7re9M0sdbP/CnQMxkzznV+4j
         ZaNmFWIBxB3CHrmGbKjtuWekGtBUriYdqTcJwZnVEI/eZjUR5zY6bDdDx+39Jxqa9baH
         EnD5+YmtyDYHAT00Rgut+/EcB9vuYC6f/x2nH7EDImZitRCG22dYGG+yDW3UOKtISN5x
         cNWkRrFFBCHphdhF+7U1TJ1mscgcvV+CGkNVV/EVmej/yZaPPpho0F26tfheDlHBwKGT
         NYraDDk+rWVA09kkMQmEWzoeT+1ibSYaWn5eWEA6gy/oLIuAXEYQHgMs8CE1fXnjXNHM
         8+2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=be7gQ6BJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id v5si963631edy.3.2021.12.30.11.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:16:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v5 32/39] kasan, arm64: don't tag executable vmalloc allocations
Date: Thu, 30 Dec 2021 20:14:57 +0100
Message-Id: <c2e928023fee82918d5cd94374109b49ff3a34bc.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=be7gQ6BJ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c2e928023fee82918d5cd94374109b49ff3a34bc.1640891329.git.andreyknvl%40google.com.
