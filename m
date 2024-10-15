Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBGMNW64AMGQEGNC3W2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id BEFD999DB94
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:37 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6cbe4fc0aa7sf129060046d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956058; cv=pass;
        d=google.com; s=arc-20240605;
        b=L9ZAXRPiXf6TX3j0HwPrOhOeouYcGs2AWOph3C+lzGXDW3fx6XsuzL+vmCZbb2NDgo
         i3RlS0W9McSf1O2VL4p7f8nv3ajJnQZooKmeL4dhtOccxL/HDZCe4C88dT2RAdX+vzpO
         dlgN1+0xlY08IbYKsf4Ctq21j8AUohxF+X7CyhZcOnc41pCzIJ1QGcZT5M9O4x8FDtJh
         NE9Hc1WUK8SHOV6TZbCh4nCvQzkkFH1owMkFwzCUiX2ra5RnsBuBSGFt0XP9Knwx4+lK
         ZauaMUZewtGLDuz7XncyRsyCYIcxYVcEt7nwwu5C3jETytEEFUaR5Stehv8xxYNOv4TV
         T6xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=k+B0edjUZsJdEZ90YaZRwUfLsB7r0b/OaYEH8R7p/Ek=;
        fh=/omrKpSHwvuAKPhFtJf7+bvFbRz+P7BtWNJEyYtD1qg=;
        b=W0rEpzzcTlDDDdsoEeH54GBSXNOKNpAtRSfb2tbgYH3b+rzR8a3xxhuBzvdK+96BWL
         bvXZqg0Ctm0dvxo6cmuC3QBhK7lFhNuf44+MlTUAo8pDZB3gy0VzJzCZh6oiSNf7N2DX
         qukFpr2NSlb7QoBuvshMRoQWzZmZeHN1t+Rj0zsPVwkg6246ACGEvIgQA+TWDeYk7CzW
         KZbEbCrCX8fYf8mN+G8HEd8VR/r1X5xBpiD5lE9eolSHPBi5f24CdWr4fNvWip1akPsX
         b6YdYJCT0IiFKOs2cJR1bM5WaGRsrv+yPMmv9dfxk1+Ajs9s13N/vR9HUbAQvBLjOCAu
         tBuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kbU6gROC;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956058; x=1729560858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k+B0edjUZsJdEZ90YaZRwUfLsB7r0b/OaYEH8R7p/Ek=;
        b=NvNv4vBQv9C6FlGJIMeoIVi1guWiCIA3+UpARMMydzASGk/szkhp+gabuQPIgK0qak
         nIoIa3O2gPC83+w9xCnwsPvHlMxy3eQAnt7pgc+ftWcMQWiCEcVPjeus3WfUUZMFgFin
         s6rk6OrOqWTC95JXH4J/cVlvlbjz5faR8ipjke1mSC9HftA7O5hu7z98j4dW2WN0k7Co
         Ql4Tx33Dwb/4TH+WWlrA6lBFdZUMFA/kCu6SnbY2WOTrhBvrJro5BJ/dusy/pVIg1IQi
         HohPqxWW7EpyH+GP7zlWOSrZyIKKrgisM225g/GpHD3KEGXub/ETsEaWFyLqbdT7k+/n
         Tx6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956058; x=1729560858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=k+B0edjUZsJdEZ90YaZRwUfLsB7r0b/OaYEH8R7p/Ek=;
        b=Uv+u3Ef4U/PX2+ugYB/8uWHqX+jui29Co1MyutU3WBJLrF5SWIGns5MEeJzc7m5/fH
         w7AbAl0Keu5lE3h0tOQa72Y8R6WDAZolCOMw03hxrMhD37JR83M+gDh1accFPnE4tUIs
         8Y52Tm/GcctPMy63kh0q80PfM6E/KpQ3VPZOPowtzzYKEgNk2O32zSfFvg3belxTZOIP
         4uSvPPyAwa1O4fV49EQUl2eAEctXOUAZsBdCa+YfV7566KMkhWrX3aTgNqZ3ZJBAfcLZ
         1esNw5wpDXTuyjMV3tI5HIvNGWSjWHd2Cazsu+6czlKlakcxNpRrMSXNwJAYoDX7CQTM
         750A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956058; x=1729560858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k+B0edjUZsJdEZ90YaZRwUfLsB7r0b/OaYEH8R7p/Ek=;
        b=czYOrad+thiZ9u5KQpwrOkOhjGFKYWljI8PChraBw6XsUg0GyRXcLzmm5+eL+NSufW
         TsBImBFLr17QRJaOIjIPl3AWuGF4XVhzeOwiiJOv+WS0kGFc51NvQLIN1IFRuMI+CVGX
         NkUC0IFbzHXVQ07lGP0tOQeSQ097kKI4MkmPeb/Ki3LaD+vH30Jz8dEU8mJR+O0zaO8+
         A05G2YIBeZ5YIZXvpOuMiCxy5u3PTy7viOOXDoWj2ckS38+lLn8S6GWXmEmaOS1UdrQt
         CaUDr9hPNW9ia+wT5Vyt5hhDvNC4ZMyHbECNEwvWII7SJQo8LtQyOfRnnoWcptovF/+P
         nKPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXKZpRemKyVBRwChqUCGpzqQ3/jiO48O3NpsR3UzTnSkTqczA5UOVILmrF2IhcOSJdmgqxHMQ==@lfdr.de
X-Gm-Message-State: AOJu0YyxCABgGPurRJLVny3AbpFXYCeHvtjk9i5OYFbWgdk+W2aJof5m
	M9VXH24hXbQwOLlfUKRH6HEOjD4l/0+rEZSfFnYk98Rg0dKA1mUg
X-Google-Smtp-Source: AGHT+IFqjwLaTpyN6L+sy9q+Kz7Pf4tD/tmMgMPO4wHizuEmYqNbhGmszIcIYwIsWqng9iy2zuD+Og==
X-Received: by 2002:a05:6214:449a:b0:6cb:e934:db97 with SMTP id 6a1803df08f44-6cbf9e8cb43mr151913956d6.51.1728956057990;
        Mon, 14 Oct 2024 18:34:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:cc7:b0:6bd:9552:bc87 with SMTP id
 6a1803df08f44-6cbe5667883ls13341706d6.2.-pod-prod-04-us; Mon, 14 Oct 2024
 18:34:17 -0700 (PDT)
X-Received: by 2002:a05:620a:4708:b0:7a9:ac2d:597d with SMTP id af79cd13be357-7b12101af52mr1311594585a.56.1728956057272;
        Mon, 14 Oct 2024 18:34:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956057; cv=none;
        d=google.com; s=arc-20240605;
        b=Oes+oXqB3XyBN3JQHfxQYNfAoAgcPTMiI2IPJbQegWPnG9HvIqcklAXRyNll2TG2Qw
         GLEeC0GIi3pi7smfOQ1/+Xeevl+EPKyxyDM1FRE5VniYGM5ys5+ODDrr9eB0S9uTAPIa
         H3yuMmwi4CNZJ0aqNg6D3B4FDdu24C/b27UWNlV1Mc4QXS/W9IF9HL7waZfSN5XRZU29
         Ngyen4+so+3pH80Aac8C4Ck++cv9lYwaWhZ+XCBVZYGWv2LHqp8lEflC18kgogpzuIPA
         wcoeeYfueEt6ZeNT56jUSP8Od7/Ab4BNbxkY5kQoGFwBjUMrvGyEuOAU9YpJe3FXmTbJ
         NEaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/MHsxmP9bN1bxx4msR28qZ2la9zK0wSY8EDrce3K+zQ=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=DKUWvObAurjicpc+ZdGG/ggaXmWJQu7zWl2RjqyvWRrLF7e3KQabe46m0aak/jYbrF
         Fun+JMZR0fufQEeB38hN0j0Q/Ofg/CzFttYmoknzS62QOLp5PS4daiXj2wIO1ipHy1Lr
         gFfv6HjGccg4cmoH2KzWAhaZSCK3dp4h3tn97GQLbKwkVbAFr8CJ4F8IdFnfnnpFMF8r
         KY7VA+EsCnJuJNXbK9TCT8Uo9rXjvCNIw274UwkiQaWx9NuZhbBP20dG2n5p1mvUrUvl
         oYy6mLCNFuPaJ3Lz04KDQmfBtf0VaL2Q6CmGGgx0RLaOpDqJafJk0ODdyxG0kLukxQlk
         UfIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kbU6gROC;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b1363ab52csi1222585a.5.2024.10.14.18.34.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-7db908c9c83so2808961a12.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:17 -0700 (PDT)
X-Received: by 2002:a05:6a20:9f47:b0:1d0:7df2:cf39 with SMTP id adf61e73a8af0-1d8c9577ca1mr13971673637.7.1728956056191;
        Mon, 14 Oct 2024 18:34:16 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:15 -0700 (PDT)
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
Subject: [RFC RESEND v2 06/13] book3s64/hash: Add hash_debug_pagealloc_alloc_slots() function
Date: Tue, 15 Oct 2024 07:03:29 +0530
Message-ID: <4245e8392bdcb0ea168b9700d356f75575511536.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kbU6gROC;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::536
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
index 6e3860224351..030c120d1399 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4245e8392bdcb0ea168b9700d356f75575511536.1728954719.git.ritesh.list%40gmail.com.
