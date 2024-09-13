Return-Path: <kasan-dev+bncBDGZVRMH6UCRBCHXR63QMGQEZ4EADYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 913DE977B6F
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 10:44:58 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2d876431c4asf1906502a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 01:44:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726217097; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wk8/d7lnmMKSjwtg/okBKAtqQQDgF+Xzg/aCQR4EJiiZJWnbpFqNi9k4d7JdnXaDuV
         9Bco8zTEVcjEdNVRejJSjkxwf0wbIoivHlot2eu4wTbOrklgWlKmOmEZjZkA5FsJI1oB
         K1lqIVzkUOzhGHr3vC15ksFPqMtpem7IT2x5BeZVYlA+Z3ERLn7Ug2/XOTjnh6FphUeO
         oMYVEAMF5/pjGekR2CTxbairWzooxhz+zfwXYKQuwR/ETz3yD7PS6jnO4HVA/h9y9gKA
         TdPNi1sSKGt7lmq0zhp2dppxiVw963Aryoy/SY47KzQSY717JkWMjTZfIYgbTohBYel3
         WuHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DYAWjur1eoyjUJOHIiUzQlIV5SiDpEGImYp26JMYqNg=;
        fh=qqh3nw3P6Dnn2vhZYt3JaqXtbXVKomvDuwVYbfG7K7c=;
        b=e1tkKXVUaUl5XdGO51nLxhIn2KA7P7ERsSYZYlV7SEH7kCOBIGWqnxvqjbYkmnLtPx
         zkn/dgz3Ny46XZIo/i75fSpTOaWuJRQsGEbA3yXfcy6OaYSMcKUKC9KJjEwxMrdVin80
         V1CKE0/J2Yxaf0yykx49ErGeAqHWlzp2XlqqM2Kwg6zaUGEgDVp1U5NxLOMiSmpJAmRo
         xFjWhLs6PFFjCNlN4/GH/vp4AjVoZH/y+b0DQ5giIGCza9MCtkUhSHAmex3CmkmFhIsF
         Fd4AbWwqodmCalP3Chd8iM6LLi4ahcOBoXYbI/Fm5M8Bdx1BUM/WCBUxgIPpvcDbIpSI
         XaFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726217097; x=1726821897; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DYAWjur1eoyjUJOHIiUzQlIV5SiDpEGImYp26JMYqNg=;
        b=thwB91GCySBx6OOtvJPBahzJDzwVx8x0lxZflEzMcO5jnXFcj17u3J4hsFMCs/wt5b
         uIP5IJuWY9ENxFvW/m6GRFCvPgaeLsooJEFKXsdIttumwjo4FDGFFhu7373C29TJw5oF
         feu1rTQs/O40u2GWmIxPSQ8gYR1WmkBo6Y9qNf4V0jsXfQYrut1sQ3BPdyLwP0tPVq1Q
         vbhI3ulalRzK7ED2/lwD4jRbpujJE6SwTVW2od2933/VisLFi6iIZ0WbMzSjSUfsLs0+
         X9wd0nLEheVx1Qv6AUfH5/0r3JWAUPV682Z8x04roPujvemdaeeUGcxcURnXeUfbxgQh
         YPIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726217097; x=1726821897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DYAWjur1eoyjUJOHIiUzQlIV5SiDpEGImYp26JMYqNg=;
        b=dHIWE6K0YLBbTqRFT3S0q6zbKiTO3plYxOxd8LjH1xcvG645Mpe905isIkApO2Hcoz
         NdGqlnINFBxMHMbQMfx7bv+9GWSUdXsBV1q4xNOdh7btzD0qBiTYoCSZ1Vh6430kzjkA
         qRvVFyK93872H/ZtwdlbB34cztjMFrpocP5OkeSt43grDianzgmpg9d5YFX4497Rd01U
         2dXmM+XV3bZtSeoeFCx79wtGTUN5Th8YSk+GtynS20YnDZa/YtQbKJk+vwNeYYDpt1hC
         GH/f2p8dw+SOOKleJYaFTHxC3sLG/crvUG7MZp1cFghe8+fcdgHEk+QKh/3rDgkNRCmE
         7yOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRSv+UtfG7tfkgZhSKyhWFislBCRfUKHXkQMjUessgxA6729gG9SAvfxg0E8u2B3QV55UIgA==@lfdr.de
X-Gm-Message-State: AOJu0YzIKOVTcCaHQP5b9RGjf8V6bXsrTDqhUua/8HM9QPQHm6URdfDj
	6pphChWQYiwvCiwh7dwEFw7ChtAgzrNKVBxAcr7e6ofYQMHJiDj/
X-Google-Smtp-Source: AGHT+IFfD/NL+PdleYZsn4RH5YDujthsM4HefeMep2Zgpg3QrPBPn1Cb6e8VZAo76B82ke+ZssCZlQ==
X-Received: by 2002:a17:90a:f2d7:b0:2c5:10a6:e989 with SMTP id 98e67ed59e1d1-2dba007e7a4mr6036542a91.35.1726217096865;
        Fri, 13 Sep 2024 01:44:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a8e:b0:2d8:cbff:4bde with SMTP id
 98e67ed59e1d1-2db9f64e0a4ls362588a91.1.-pod-prod-02-us; Fri, 13 Sep 2024
 01:44:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVHYA/unuo7aVw0mEdubK/hptg232EN8g7e6pQTsonwNjmdIDXIpsdC5hgU+Ou5Pdgd9/tfYOAcu/s=@googlegroups.com
X-Received: by 2002:a17:90b:3756:b0:2d8:7561:db71 with SMTP id 98e67ed59e1d1-2dba00611d0mr5939319a91.25.1726217095459;
        Fri, 13 Sep 2024 01:44:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726217095; cv=none;
        d=google.com; s=arc-20240605;
        b=PaTWy0eVmqtk4tQ6MuMmeEYDKAItFAYan1OiDWbUgF588JtyeUYHbPvEpRPcMlUazo
         A4xBS2nC5za22e8z2cGX55HgZQK8GlK6nioaVNO2K9Zvy2QriIWiJG4saHdyV8xffKeF
         umBAO5QDsW7+X8OhdftQ2UvmNcVB71lKiYjkG2soWCubvhZOf17SUIRkyTsRuP/raB6o
         h3yVLG40ZE3Qvh248xaGaWI/TAZp5cHqSa9zmyygCAqmyNVzm2brA8+trQxOkvyvEMGe
         jb6Ityw6u5B9zDLeiM0ZODklaaYr9Y3rnWZ44R7+1dXqSXvLCU4fNTgoEgxlfQadVzwB
         8xIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Kn07Ym9hhDgRqPs48mMML14pP1evt7IA1E+5MprmDiw=;
        fh=2Qg1lQCKbOaLhilWuULCpF79d+LAtLSDknwN1+HxWCU=;
        b=f25j3Bbc7gLtczqm17rzLdf5/ThPJjM9MxM46eHluoChUQAjugmqV6mb73lC43PzR1
         tlU6CfJyKuqAz9y3zWn2vG8NsKrWWR8M2OlAFl8m3+x1nPJF9PLg6dPfvKfgo6XKO04P
         TZ/Oci7W4UBHZaVGYkDGjPnz3FFHBLM9k06CJj0Wf4slKpTTX8qNHgHMzvk4dABtKHB3
         kfa2MuJEYmuP9dbiHDHvlAC80QtZbkB3N3OVGJK5Fp0Pk3jiGJRtuXfI1dJIhG6erFpT
         8xvdZW0ucNXtfYx2Gfvi8maoa4CL8e3nSerq38lNtPSon0naA7LBbjMAgER1aU7vc2hz
         mXlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2db6dc9977asi567810a91.1.2024.09.13.01.44.55
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Sep 2024 01:44:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F22991477;
	Fri, 13 Sep 2024 01:45:23 -0700 (PDT)
Received: from a077893.blr.arm.com (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id BA6A33F73B;
	Fri, 13 Sep 2024 01:44:49 -0700 (PDT)
From: Anshuman Khandual <anshuman.khandual@arm.com>
To: linux-mm@kvack.org
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	x86@kernel.org,
	linux-m68k@lists.linux-m68k.org,
	linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>
Subject: [PATCH 2/7] x86/mm: Drop page table entry address output from pxd_ERROR()
Date: Fri, 13 Sep 2024 14:14:28 +0530
Message-Id: <20240913084433.1016256-3-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240913084433.1016256-1-anshuman.khandual@arm.com>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

This drops page table entry address output from all pxd_ERROR() definitions
which now matches with other architectures. This also prevents build issues
while transitioning into pxdp_get() based page table entry accesses.

Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Cc: x86@kernel.org
Cc: linux-kernel@vger.kernel.org
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 arch/x86/include/asm/pgtable-3level.h | 12 ++++++------
 arch/x86/include/asm/pgtable_64.h     | 20 ++++++++++----------
 2 files changed, 16 insertions(+), 16 deletions(-)

diff --git a/arch/x86/include/asm/pgtable-3level.h b/arch/x86/include/asm/pgtable-3level.h
index dabafba957ea..e1fa4dd87753 100644
--- a/arch/x86/include/asm/pgtable-3level.h
+++ b/arch/x86/include/asm/pgtable-3level.h
@@ -10,14 +10,14 @@
  */
 
 #define pte_ERROR(e)							\
-	pr_err("%s:%d: bad pte %p(%08lx%08lx)\n",			\
-	       __FILE__, __LINE__, &(e), (e).pte_high, (e).pte_low)
+	pr_err("%s:%d: bad pte (%08lx%08lx)\n",			\
+	       __FILE__, __LINE__, (e).pte_high, (e).pte_low)
 #define pmd_ERROR(e)							\
-	pr_err("%s:%d: bad pmd %p(%016Lx)\n",				\
-	       __FILE__, __LINE__, &(e), pmd_val(e))
+	pr_err("%s:%d: bad pmd (%016Lx)\n",				\
+	       __FILE__, __LINE__, pmd_val(e))
 #define pgd_ERROR(e)							\
-	pr_err("%s:%d: bad pgd %p(%016Lx)\n",				\
-	       __FILE__, __LINE__, &(e), pgd_val(e))
+	pr_err("%s:%d: bad pgd (%016Lx)\n",				\
+	       __FILE__, __LINE__, pgd_val(e))
 
 #define pxx_xchg64(_pxx, _ptr, _val) ({					\
 	_pxx##val_t *_p = (_pxx##val_t *)_ptr;				\
diff --git a/arch/x86/include/asm/pgtable_64.h b/arch/x86/include/asm/pgtable_64.h
index 3c4407271d08..4e462c825cab 100644
--- a/arch/x86/include/asm/pgtable_64.h
+++ b/arch/x86/include/asm/pgtable_64.h
@@ -32,24 +32,24 @@ extern void paging_init(void);
 static inline void sync_initial_page_table(void) { }
 
 #define pte_ERROR(e)					\
-	pr_err("%s:%d: bad pte %p(%016lx)\n",		\
-	       __FILE__, __LINE__, &(e), pte_val(e))
+	pr_err("%s:%d: bad pte (%016lx)\n",		\
+	       __FILE__, __LINE__, pte_val(e))
 #define pmd_ERROR(e)					\
-	pr_err("%s:%d: bad pmd %p(%016lx)\n",		\
-	       __FILE__, __LINE__, &(e), pmd_val(e))
+	pr_err("%s:%d: bad pmd (%016lx)\n",		\
+	       __FILE__, __LINE__, pmd_val(e))
 #define pud_ERROR(e)					\
-	pr_err("%s:%d: bad pud %p(%016lx)\n",		\
-	       __FILE__, __LINE__, &(e), pud_val(e))
+	pr_err("%s:%d: bad pud (%016lx)\n",		\
+	       __FILE__, __LINE__, pud_val(e))
 
 #if CONFIG_PGTABLE_LEVELS >= 5
 #define p4d_ERROR(e)					\
-	pr_err("%s:%d: bad p4d %p(%016lx)\n",		\
-	       __FILE__, __LINE__, &(e), p4d_val(e))
+	pr_err("%s:%d: bad p4d (%016lx)\n",		\
+	       __FILE__, __LINE__, p4d_val(e))
 #endif
 
 #define pgd_ERROR(e)					\
-	pr_err("%s:%d: bad pgd %p(%016lx)\n",		\
-	       __FILE__, __LINE__, &(e), pgd_val(e))
+	pr_err("%s:%d: bad pgd (%016lx)\n",		\
+	       __FILE__, __LINE__, pgd_val(e))
 
 struct mm_struct;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240913084433.1016256-3-anshuman.khandual%40arm.com.
