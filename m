Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBSNWZK4AMGQEKK5VY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id B97839A44AB
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:31:01 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-6e35d1d8c82sf39559487b3.3
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:31:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272660; cv=pass;
        d=google.com; s=arc-20240605;
        b=PwJk5B3QzoK1oqLs7jv0bNKpSf28XYa9jtYD7eu+cRWGf1Ok/pJQYhcZxruQkP2Lz5
         d5jNaX/OLl+r2fQE/CuXm4Lih+nH9V11Sb8QckOUhxvpXYn0z/Xj1NSGUIzAfqqlNIs8
         gWBGwHC/tiOll8uUqHkaVuk+a2zsMi4CZ9Nwu8i2DCwl0w3J+lSA4w2iGQziSiZdJ/6H
         S7MgKFQR7HC4fEd3S/VEyIIfD2QFPZST/mtBTBuK+EMTixZEZLTXJAlDYInECryOIG04
         OJ49587HKRA5kETeskTig88fKOsMOTScCM1xe/u/0h/BkhRZjFHQCiPbRnwxsKr06NLa
         jSpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=dLC1G9lMz1NY9NWu2mOaS9FLFEzlW2eZ3j68oM/j7QY=;
        fh=zQ+xSe0RAr64zjkpp/pjFxDJpspteF6DxpubDndCdE8=;
        b=PTH/q9jxIhlG6LzQayEafd6Fy8biV9A8y/GCoiwNH+pdsGMX/6y5Ex7sJLp+B97J/x
         CNxEtkD674tqsysviqveJEZkNnoCKqdnEPnxW41c0NWYYrLVUqC+QZQ90zn5/74G9Pxj
         hpbAdnXqCWEHgrIAvVacw8/geUP34kCvXKskz+KDZXXC/INHCBQ/rVdjGrt591t039Jl
         SSJQjGJ4+kHq5Dq/L5f9C8BhSp/ipxYPR3JGVKa8DqZD2XZK6j31zq0tMx5RahbKO4xQ
         6vRDwzug39WbNPiwECAoFZMBj3AuqcAmD0ZXVvGt2bNJZgOh9VxVIusK5RvmYETGPX/U
         vnWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OdNk7ioT;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272660; x=1729877460; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dLC1G9lMz1NY9NWu2mOaS9FLFEzlW2eZ3j68oM/j7QY=;
        b=chQ85ODGXlVOs1xA7449lCq4BWNDyyrMRJI2nIFHC3kQHAAbXOZz2ZAhTMbD9tQq4b
         QrXGmnycw6xh0S6sJf+VQ2xOVc5nt2ucZ+Ryc8dbnUoi+uFjCBtePf3IwZhxxildcD1q
         69yi5zFrJoChj/MU0OOGAYbtpnJKVN8wOZPmJmextm/o9cPC/73AMo+TRH62H9RLpYC6
         c0Y0sQnVlXcL8+7mw2+HgxuKFulvQhUzO27gXEQrhz967L6DXAVvSX+GFySzr9wIlZo9
         CQ/IbLMTl/Dtl3YhUJEtQ4PEdD+tvzkNMXjueuUhE2jjyFx8BFDcwPe1ZYG27QUm1zp0
         7dkQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272660; x=1729877460; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dLC1G9lMz1NY9NWu2mOaS9FLFEzlW2eZ3j68oM/j7QY=;
        b=F1TEzI/DMXyJj7cTyoaa3Iiud+BG3j2bpoP52p1JgLlthc/aZWJvnDFuDKnUQ1vTJs
         l6t03UldSBPadJsU707OOeiWPXvUqoqdvewvc8Fe1rMIwoB9oxrAT8HAGUhw4bSC/Vxq
         u0hTEisgGPgrORYk5B6vZq34kfhNaYMAvsHr3E0hPYjCkpzmzSH+rc2BGU38sy5+W/f2
         L/F+fBzMpswZwagbkSkurAK8EDhNnurVYz5JC3d7Kl+U7DT3EfQuDRNMG7Jrle4B+4E3
         fWvJj/cGOh2oiuDpyk27R+oi+MxJ4JX7bw3q3uqN12dv4nm18lT/wIlGt3gAeUWXzRuv
         Ep6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272660; x=1729877460;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dLC1G9lMz1NY9NWu2mOaS9FLFEzlW2eZ3j68oM/j7QY=;
        b=s4RkWgdBlmeto++RHcKi37+DqfH4TuKELH7nd6GhWY+zZYtjTwB06VdB5hlG/2q3GQ
         psNrjqFnSBUARPiK9mfE/IsMLJSgFntxqM2O5//FcjggfucmjCZ6VgrlolSmkd9tK00M
         LuoJD+SBg2RqADbYluL4yY6t4duj7DWXBi+K30i+BlEcW0zLjn0aIDRvXs5tNpY5ys5Q
         mfE0r1L1DgHUFZLf1W/ZGvAZK7sG19QOPIrAXDaRdTSq4E0h18Zp76GX9iCebGJHK3fx
         u9IbWSUfqXxwDWA/ae+5oUCsFQbgRFucoPBBDZe61bNB8WXETx3WiAn1yTfZn7jm55yY
         nBiQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV03zLTPj2EeP+V6q0X2NzsAheK9ACxNxDMboQISFKrv37yK8elgaSdckFTpv4vNmNAEwqg6A==@lfdr.de
X-Gm-Message-State: AOJu0YxvSATsyIdpElG3HFXuIvK6rzQUrh6M3GKgdldkLVpkwFed5Wab
	p3hlO23lyhgHroabEHCmjLr8zoPWoy+vXEgp3Mu1nkfSHSyFxmk6
X-Google-Smtp-Source: AGHT+IEXvd3u7ftpgQBYaBWiFWWZOdlQ2K46qtI08ZVolhz3tfMhHBlfgWAHxb1ELmmI8fREIiHwpw==
X-Received: by 2002:a05:6214:5b03:b0:6c7:c7ff:958e with SMTP id 6a1803df08f44-6cde150789amr45481996d6.18.1729272649933;
        Fri, 18 Oct 2024 10:30:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c44:b0:6cb:d4f7:64e0 with SMTP id
 6a1803df08f44-6cc371e86a6ls33677916d6.2.-pod-prod-09-us; Fri, 18 Oct 2024
 10:30:47 -0700 (PDT)
X-Received: by 2002:a05:6122:1698:b0:50d:69a8:f5a6 with SMTP id 71dfb90a1353d-50dda36ad6fmr2491945e0c.9.1729272647563;
        Fri, 18 Oct 2024 10:30:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272647; cv=none;
        d=google.com; s=arc-20240605;
        b=H01mlPjxXnYOInCINedUUm/UwoOlCPBhmtj0hx3cCnAnWt2+w+m7mrD//GmPsBeI41
         eTgw4dPDDXGJZ2M9WnzAyF4hbM04xddqAYxESGqoxL9Yp1TdbzBIx2dh22fq95rh96K5
         1nm9dlcnYnN1gffPqkDz1/rdXAkgkcuyQLzlHVNpb/9zo65cG3PEPc8RHhQr2GTmi36h
         Xfs8rAvExjllvh2+p9Q2bqxZfmjlEt/HsmdFnplJuBhlSZNujozH7oAx3AZk9QdMOxoD
         rohYA0iyDHRl5MIk/UHe7wGsTjX394nvG3O1M2+SWskRQ4tpHIsXT66HdKAtVm6P0fH8
         AQSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DfUSdtWOnTBS3aUaneALBJjz6yO/1MpkxmVLk8hKBQI=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=ImTDDNldJ498xl5nW8IC5PsHVB0u4BnvzrBfmC7K+3EiH25NB5nT+DW1+cUntRxrT1
         rHN8It1O1lYfaZ9SPc8l9aGl2Pglf3ZUnKMCDzngRyLiot+zeQDXml3jU6uTCt1U3fCr
         O0s5OoUYftfmbtLZLv8xPJeytdl1oBVUzPamZ3h248jj3UkQcUQ7nY73l3KDecYvro9y
         iJaBI9Wc3Gqs9mY8yKs8zTGEEIrNuNDbhj85b9aAXXlehYrNmxidnOQDUltQs95cTgzq
         3YJjf6q5UWTuXgczXUbOFme363sPMHnCzgtovGt/oiCLIzpmpSjVl3IUEl7okDrmesxQ
         D00w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OdNk7ioT;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-50dd772a0a6si69458e0c.3.2024.10.18.10.30.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:30:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-71e49ad46b1so1669412b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:30:47 -0700 (PDT)
X-Received: by 2002:a05:6a00:6618:b0:71e:4e2a:38c4 with SMTP id d2e1a72fcca58-71ea31e53d5mr3448284b3a.14.1729272646416;
        Fri, 18 Oct 2024 10:30:46 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:30:45 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3 05/12] book3s64/hash: Add hash_debug_pagealloc_alloc_slots() function
Date: Fri, 18 Oct 2024 22:59:46 +0530
Message-ID: <d1d5aabe1e4c693a983e59ccf3de08e3c28c5161.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OdNk7ioT;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This adds hash_debug_pagealloc_alloc_slots() function instead of open
coding that in htab_initialize(). This is required since we will be
separating the kfence functionality to not depend upon debug_pagealloc.

Now that everything required for debug_pagealloc is under a #ifdef
config. Bring in linear_map_hash_slots and linear_map_hash_count
variables under the same config too.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 29 ++++++++++++++++-----------
 1 file changed, 17 insertions(+), 12 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index de3cabd66812..0b63acf62d1d 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -123,8 +123,6 @@ EXPORT_SYMBOL_GPL(mmu_slb_size);
 #ifdef CONFIG_PPC_64K_PAGES
 int mmu_ci_restrictions;
 #endif
-static u8 *linear_map_hash_slots;
-static unsigned long linear_map_hash_count;
 struct mmu_hash_ops mmu_hash_ops __ro_after_init;
 EXPORT_SYMBOL(mmu_hash_ops);
 
@@ -274,6 +272,8 @@ void hash__tlbiel_all(unsigned int action)
 }
 
 #ifdef CONFIG_DEBUG_PAGEALLOC
+static u8 *linear_map_hash_slots;
+static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 
 static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
@@ -328,6 +328,19 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long lmi)
 				     mmu_kernel_ssize, 0);
 }
 
+static inline void hash_debug_pagealloc_alloc_slots(void)
+{
+	if (!debug_pagealloc_enabled())
+		return;
+	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
+	linear_map_hash_slots = memblock_alloc_try_nid(
+			linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
+			ppc64_rma_size,	NUMA_NO_NODE);
+	if (!linear_map_hash_slots)
+		panic("%s: Failed to allocate %lu bytes max_addr=%pa\n",
+		      __func__, linear_map_hash_count, &ppc64_rma_size);
+}
+
 static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
 {
 	if (!debug_pagealloc_enabled())
@@ -361,6 +374,7 @@ int hash__kernel_map_pages(struct page *page, int numpages,
 {
 	return 0;
 }
+static inline void hash_debug_pagealloc_alloc_slots(void) {}
 static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
 #endif /* CONFIG_DEBUG_PAGEALLOC */
 
@@ -1223,16 +1237,7 @@ static void __init htab_initialize(void)
 
 	prot = pgprot_val(PAGE_KERNEL);
 
-	if (debug_pagealloc_enabled()) {
-		linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
-		linear_map_hash_slots = memblock_alloc_try_nid(
-				linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
-				ppc64_rma_size,	NUMA_NO_NODE);
-		if (!linear_map_hash_slots)
-			panic("%s: Failed to allocate %lu bytes max_addr=%pa\n",
-			      __func__, linear_map_hash_count, &ppc64_rma_size);
-	}
-
+	hash_debug_pagealloc_alloc_slots();
 	/* create bolted the linear mapping in the hash table */
 	for_each_mem_range(i, &base, &end) {
 		size = end - base;
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d1d5aabe1e4c693a983e59ccf3de08e3c28c5161.1729271995.git.ritesh.list%40gmail.com.
