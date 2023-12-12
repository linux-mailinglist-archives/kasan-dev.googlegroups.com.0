Return-Path: <kasan-dev+bncBDXY7I6V6AMRB75E4OVQMGQE2MRQCUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B4E380F986
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 22:37:05 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-40c421f2686sf21204145e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 13:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702417024; cv=pass;
        d=google.com; s=arc-20160816;
        b=0wkBVEOULkDaef668kqDrz7akcY+uJ/fi+cE10ALfyG+mbHEGC2xJrGeASyP9EqTPf
         6RVdOgTanzp5rNoTeAl4rkUpGjMAjw0yne3raP0jAUVbKZaNFZHPNWH2jia0a+gQR8/9
         PONIWHVjgxXG5L1XNumI2iNoEdVxcluvTOC3I0QVphwkLDthJF4zMGubmXkesEElqVxH
         j3DeeMq5OsweFWmMGF4QPwOzQHkt63Rzbk7si5fuVr0zTUnl6jkWeh3ZP6oaoWWjtAiH
         8D66ocPDGyTG2pQdggB3BHMXbebEu8kUaD0ACWetHXO+cTzkZ187WyOzCdyhRNSflpZA
         OSFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mAdV1BQb4jhbvtHmHvbxEHGJj4AgNGdOKmM8YKDYjJY=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=jTdGGESbfySrwd7NdGDMRMYXeXYfRq30O3wgdGe6+JKDjMjj1+J3CRWAUSTcqqwl95
         9OrUl4EOfMrLfOApoGEL9nOpClmkk1fyR0vIpugpsUVtnI5Bv4TIeKyH0INtCNXrnIWc
         G0ugYCLW7ZSzuFKRFZe2Up84PXRFsaEef+vTT3iNAJcdrgLouNj+nDMPsxwNZHsCvAXZ
         NiS15jiE6XNwutkYuyIwoUU1cdvpzzs8d0ymj0RxlGFLdeQcM/9jvtUa9oznTBxQaX7w
         DFl7B8ByNpRv30sNwld4RgZ+AjlM14nOEmnpow8+rykfoBtZ4n6khjqrVzo8Iup5m3UU
         0Ypg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=gydjR292;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702417024; x=1703021824; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mAdV1BQb4jhbvtHmHvbxEHGJj4AgNGdOKmM8YKDYjJY=;
        b=BeirXfMPAbLhUPruLISG3E+q68wA66XldN7xQ7RGK5R/SpfabCH6JpQs5tH8L0PxhS
         c+kXj72FHBGsMgxVFlvUxWUX1u2liuPZcF7oAP543l94ze/l9GB7y1YSWn0eZK06O0lO
         W4QlerpoLp3/AXt1MNTSnMx4nmdVHm1HdvcfU3oyFkInR8pswddjn6cVoz4E7IkLnliO
         OaJagP8peTFAAIRB/CZvfCJNssj67rJI/0RkUg950v4xredxjFaozGAnOMoPB4azDbg5
         H/nvNRqopdjFrPcQSudwvxudO7PGLM7XnC5g1MVH5PeCE3VkHc51QhZGV29fHKewD0mc
         9NhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702417024; x=1703021824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mAdV1BQb4jhbvtHmHvbxEHGJj4AgNGdOKmM8YKDYjJY=;
        b=Gc3zUxuBgl0y5yeKuIVNZxqb+6KrXn5Sh8acMmTHSpposliHS3qJ0IDpIddDstgQ4H
         7GF39EeI1mqfrOI6+SLwQqtEA3r44V+kJQd2zWwVhXAe8ceqKN3KmRqCsRYOhjpdegBL
         yLEtcZilUJqoXH9FPYHp1XYoz0ZF8UpyVCbpbDZynpqrxhom11HIiyOnplNwISNp5K/J
         FSOHe7Wl7BDpw6Q15bfor1MvDK14+KbF1T7f5HhMoyB9hsx7BNm02+bsJsGSfUd2WcPi
         besZyR8adoN9RupU1eB+hcZt1A98uxYLhUO1j5tVOvIQvwI+jBgyy57Stbsxw/fGtM8G
         DV4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyNBYVPBAmxv2pht3xHD+qijUosPneYp/cOd9+Y7T5KPeBkPn6g
	p9AMtCQQJv/EmgOov1/tQBQ=
X-Google-Smtp-Source: AGHT+IGzha03GHqKq3E0FoYWTAXSEt0IQxL8/uM9UQ8ULRplOHr8LlfOF1iGWIw2JnzjA4p9xVhzNQ==
X-Received: by 2002:a05:600c:2e87:b0:40b:5f03:b3d3 with SMTP id p7-20020a05600c2e8700b0040b5f03b3d3mr1648418wmn.245.1702417024016;
        Tue, 12 Dec 2023 13:37:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6a18:0:b0:40c:26cc:3705 with SMTP id f24-20020a1c6a18000000b0040c26cc3705ls461197wmc.2.-pod-prod-08-eu;
 Tue, 12 Dec 2023 13:37:02 -0800 (PST)
X-Received: by 2002:a05:600c:a692:b0:40c:3820:efee with SMTP id ip18-20020a05600ca69200b0040c3820efeemr1817012wmb.275.1702417022143;
        Tue, 12 Dec 2023 13:37:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702417022; cv=none;
        d=google.com; s=arc-20160816;
        b=W7PkSCoBRsi5QyGfYx7XV1DN/yP5JxZvCoaAj2Aw6NtLhcV+QgUjthOVq3FqmB8o0A
         ccagnGvvHqkHJCsphjZNOpFyMKGSguYF24aS+TizWYgdso843c5OLkmLn1TgbOjjLKSR
         w5FOlgNUEUoKH4aPrFW3PqrA6AXmbi+3KAG8JdwDng4wEhm0j78yd2UqG7Wf7pMDtwoT
         dZ51TUk1Aj3ojM/5+GaBHm8IN0jXvIL0eGt3Vp+nq/8AKAzv6juFMAw1CaDm6EXcX07t
         mZqFgK1mDIQgnLvR4llT+aE+KEsgePe9EWBd9T4YoC5H6ByRq29ap3jgJ5gzXbhj2TS9
         L28Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qCOh69caXbVfDD+nz3SkSSNJ4LOnzQLxIG6SJxHDatw=;
        fh=tnIMy8HqtPpQFlCLOsGpMCarUq1yCQA12ipWGdFOY/s=;
        b=M4jU/whhBDhptozFrJVgou+Q44t/cVTf1acf7wj0+VtBkvHYkGZtPdht5fYL0Ug/FB
         6uqY00HeELUBfEwVM0wg293/j2Bg6rlNJiGlwTg4DNhoX3qQEh+Roy4WAQEAU8SIAL7Q
         JUtlcrqpZfK8Xk46NHr+/y4MZCWm+O7EPifkVBkwcavaPa/LJ+5pLhRMVWPEtg9h8KTh
         8d6w7vqhBMUWQB/0D5yky36E8mcZdYT/LrvireOdQdG6n9+eLRngrpKKC9/SW8oiDO11
         KIazWObv8RHYjLdhEDGKlRs1HeyYUVGlNRUnomseC3thVOvZVz8WaFIatPIUriRKQ1kA
         sbSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=gydjR292;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id m7-20020a05600c3b0700b0040b54466ee8si399947wms.2.2023.12.12.13.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Dec 2023 13:37:02 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-40c2a444311so60158405e9.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Dec 2023 13:37:02 -0800 (PST)
X-Received: by 2002:a05:600c:2814:b0:40b:5f03:b43f with SMTP id m20-20020a05600c281400b0040b5f03b43fmr1885174wmb.353.1702417021655;
        Tue, 12 Dec 2023 13:37:01 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (amontpellier-656-1-456-62.w92-145.abo.wanadoo.fr. [92.145.124.62])
        by smtp.gmail.com with ESMTPSA id ay35-20020a05600c1e2300b0040b2b38a1fasm17954734wmb.4.2023.12.12.13.37.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Dec 2023 13:37:01 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 2/2] riscv: Enable pcpu page first chunk allocator
Date: Tue, 12 Dec 2023 22:34:57 +0100
Message-Id: <20231212213457.132605-3-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20231212213457.132605-1-alexghiti@rivosinc.com>
References: <20231212213457.132605-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=gydjR292;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

As explained in commit 6ea529a2037c ("percpu: make embedding first chunk
allocator check vmalloc space size"), the embedding first chunk allocator
needs the vmalloc space to be larger than the maximum distance between
units which are grouped into NUMA nodes.

On a very sparse NUMA configurations and a small vmalloc area (for example,
it is 64GB in sv39), the allocation of dynamic percpu data in the vmalloc
area could fail.

So provide the pcpu page allocator as a fallback in case we fall into
such a sparse configuration (which happened in arm64 as shown by
commit 09cea6195073 ("arm64: support page mapping percpu first chunk
allocator")).

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/Kconfig         | 2 ++
 arch/riscv/mm/kasan_init.c | 8 ++++++++
 2 files changed, 10 insertions(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 7603bd8ab333..8ba4a63e0ae5 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -415,7 +415,9 @@ config NUMA
 	depends on SMP && MMU
 	select ARCH_SUPPORTS_NUMA_BALANCING
 	select GENERIC_ARCH_NUMA
+	select HAVE_SETUP_PER_CPU_AREA
 	select NEED_PER_CPU_EMBED_FIRST_CHUNK
+	select NEED_PER_CPU_PAGE_FIRST_CHUNK
 	select OF_NUMA
 	select USE_PERCPU_NUMA_NODE_ID
 	help
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 5e39dcf23fdb..4c9a2c527f08 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -438,6 +438,14 @@ static void __init kasan_shallow_populate(void *start, void *end)
 	kasan_shallow_populate_pgd(vaddr, vend);
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
+{
+	kasan_populate(kasan_mem_to_shadow(start),
+		       kasan_mem_to_shadow(start + size));
+}
+#endif
+
 static void __init create_tmp_mapping(void)
 {
 	void *ptr;
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231212213457.132605-3-alexghiti%40rivosinc.com.
