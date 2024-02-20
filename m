Return-Path: <kasan-dev+bncBDOJT7EVXMDBBLEZ2SXAMGQELXANBZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7614C85C5D5
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 21:33:50 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1dc0e27ea7dsf235695ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 12:33:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708461229; cv=pass;
        d=google.com; s=arc-20160816;
        b=YPQo4itQOzhVBiPe13EF+GjXm8kS3fPcvwZ3rNJMQt/nRUXIyzdsn9E3/VheqGoOQY
         HHh/EoITfs4F1WqBpV2XDMyDVFu6UKzTnzGLXYr/abG8BVH0IZri4Ww2JmNvAS8WPhG9
         aYi2WcJN5yu/MlYS3vZlpIzIIPpt7YTNARKlWI9raP6Yfe5SVY0ZnvdHM9IiNfw8k2Gh
         t0nINqg//YM7Fg1XI7BmEmNCTMyKbWVSXq/U90Le7DT0aflA6pXQ7MTwsB9eVTPMTK5m
         LoMt8YQT13XkaLaK8xlIovDuwYlNjSY6ebvzOEYPJgv4gf7adVlQalLhavBPzxkX1LDr
         LGjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=mXgNXsDVYq06U7q0JLvLXftGCe3W8/+uUEzTVwv0QN0=;
        fh=Q846Zg3gWwmomdOp1G+XXARGXDX+9qJ7FJkCt/DEyBA=;
        b=JO/k5ssblK5zNuuXTEY1mDMNLpvweOndW3jRgS9lrqfW+UOU0it2OaL8M901JkeBqt
         AhMH+Qi/s6MEybFVxiuHp4SLL+kRpMqNJ7O2QtiwXp7hsF3aX/QFuLA1Zs0OAKsoECmu
         1EsYIGOLPky0vvByq6BOQV3TJt4BHh51vdupqiCHBkQuU7F7Re/SaofGomzFiezWEtrN
         KWpOGis1GwgaGr+UbsI3QJphKv/7dAhREG4SwfSfLdRlnkC/CsQP7lucm+EPUJ1XNlNm
         971JPHWFl1FdAr08BfdJM9VyEDLvV6X3S+Cs04fe8yI7kgXR/QeVlFlm9d0lHkwzVd2m
         B0aA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=3DviofDb;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708461229; x=1709066029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:message-id:date:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mXgNXsDVYq06U7q0JLvLXftGCe3W8/+uUEzTVwv0QN0=;
        b=B/XCpbYuedEw331swUAxpBOWHypPv5qL+wh0pciKOhlC+fE3+313w5WCYh4Rrdp3iq
         Chdn3oLQTeAvD3DVgYv2ePh5ATsdChAWMOA0WXBdfvNBfxoOX7OMqJDXBR2rbgqdyV4v
         fwOlII1gJace42hn5JABGpMes5grZf4YklCa4d6gvqhT9kDcQFAFk5JMItKckJrhyFsD
         iNAOCuP84DiQU41RSCYxpr07iWYfMcOP3sjKkZpfaCdGpBLDd4EqJLc86qTQDiZpiWpj
         Amx3uNjFC7y9HD5lvUA9Plu/YCna0b0J4ZnQxqLJzGsMBfJdERxCxHI5v5TinyHvPL+d
         H/vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708461229; x=1709066029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:message-id:date:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mXgNXsDVYq06U7q0JLvLXftGCe3W8/+uUEzTVwv0QN0=;
        b=nkXx0+BhKeF5Co2CC7weV/6LQioiEjuPvO5Em+UM91LYWJFyULKv738JKt5PJJtIPF
         8rLSlt7VLhwoJbNNeVtAruWG1WMvsNPTxXgMqOzPigDnWi0B4BsYCYvSUl5FhfWwGPwB
         pzURTE/STBVnAC3JRSpt03FuiLJ+V3S8uwG53+yXPgJYj6sGWQck9bBtyPoNMG7U79lI
         KZw4auPOr8EUzIpMsvA6X155BLnWfqrRMzPZsHY4rJV1D5OMSF0kW/xBrxGUVynh3Tfu
         mAx+US/V04/6I6weutdG+ucPPVf0AQv4ALYDSHlOxHIk8u8q/34lw6PKdFHCn0e87I4k
         JdwQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZ68eVsWXzPZHgXb1pimX9ra2HLdYz0wlV+ILnAXoAQ+Fyj5KRE5RL3Lvo8EnLkKCCWzgMfduLc/oEnparrzesf8bbnCreRw==
X-Gm-Message-State: AOJu0YyJ7OCpabgTj3Etku08ejIhT4bIcT8MYu5q80VQwtxTpza2O1qu
	WDcuHLLFbmEOnUEa+HmLX8EXb0vQ7gWt9GxSXKvY26HCm9FVblMf
X-Google-Smtp-Source: AGHT+IHdX9CL9hO4BYdZZK9obp0t3WHkrQ0i43Ozi7K/uOyk3MKF0sL0ZHBr6lGsqCdC7mSrtx8glA==
X-Received: by 2002:a17:903:18d:b0:1db:a6be:ddc6 with SMTP id z13-20020a170903018d00b001dba6beddc6mr28925plg.27.1708461228919;
        Tue, 20 Feb 2024 12:33:48 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:324d:b0:1db:4c75:a290 with SMTP id
 ji13-20020a170903324d00b001db4c75a290ls945606plb.0.-pod-prod-04-us; Tue, 20
 Feb 2024 12:33:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW33eMoAeEUJtCgRnUiEPDu2pNo/P5noroe3APcw+LdJdnjVoQH1H0s+DouPdskF8pb/c47QXIE+gunwKk3DUThMl4H+WGUnRN2tA==
X-Received: by 2002:a17:902:c1c1:b0:1db:b43b:e9 with SMTP id c1-20020a170902c1c100b001dbb43b00e9mr8698893plc.7.1708461227740;
        Tue, 20 Feb 2024 12:33:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708461227; cv=none;
        d=google.com; s=arc-20160816;
        b=RPz3MZclPPalypIKXOA1661xtAOaxvQUhCRUqaAs2ZtDLLFs9GZGj4xfqevQ0tjGpb
         Ed1TFnlWa0WW8rf0tNwV0ugsTcYLDlej/lDhB7DWsjzwfcLdjmgiXMzb7ZWVqB9reB07
         2ZXnYqfeNfguZ1IwZkaCaeuoT0ZpYt0FmGe06pbppJd28+ZboiSrRRZsfhNVmXss0Q1v
         XWhEsYT8vgOiTe4iX6ZABf6a1nezD7JNufANMb9Bc4fUKY+yEFtvaAbCPecYE7zG4MaP
         tS3G1kXhS9cwKEqpsgu64WI2CoE/cpkhneu9iUEnvZpuTwlgOwA5rnQKS08CYHs973dv
         lNUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=yYaZ6KkZCfPgvE7ldRLRah8LlOxOAhyoW4Oo9vMYLI4=;
        fh=FkeYy9VFhDbdZf7Wr1j+kC7C7CaCFd0E6M33TF/KxqU=;
        b=vAsM+L+VxYIlH/G129XSSs1bwUn7EdLmD6gQYFFqCD50QULYjqybHA0Er3iLj6ohnQ
         D335bnbB7f5lhphD+2xybkB0rzVlCv5fefrFL5LHY5Lhazh5zkBPj4sTOlAO/vnxlkQD
         CmFY189f5cC0vazpIx70UeXGbPBqm0BOKilDSLf3LqqIvCnld7jvG4IYvUsUILUljbjW
         pFW4UYcai9HK63+9lkqKV0vvVmhIiOAr6ODykusAdebvwuZIYMWK8bnn9T62hnkvemcz
         zV80Luw/1WoXzvQjHhPT5dB5B16a3iPVHl/z8a4hrziJUhj9Fy8O6JfB2VEc1TFg4NoG
         1fZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=3DviofDb;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0a-00823401.pphosted.com (mx0a-00823401.pphosted.com. [148.163.148.104])
        by gmr-mx.google.com with ESMTPS id t20-20020a170902d29400b001d8e76e7179si429108plc.3.2024.02.20.12.33.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 12:33:47 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) client-ip=148.163.148.104;
Received: from pps.filterd (m0355085.ppops.net [127.0.0.1])
	by mx0a-00823401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41KJDULs001368;
	Tue, 20 Feb 2024 20:33:24 GMT
Received: from ilclpfpp01.lenovo.com ([144.188.128.67])
	by mx0a-00823401.pphosted.com (PPS) with ESMTPS id 3wd21yr5eq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 20 Feb 2024 20:33:24 +0000 (GMT)
Received: from ilclmmrp01.lenovo.com (ilclmmrp01.mot.com [100.65.83.165])
	(using TLSv1.2 with cipher ADH-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ilclpfpp01.lenovo.com (Postfix) with ESMTPS id 4TfWM66Jq3zfBZq;
	Tue, 20 Feb 2024 20:33:22 +0000 (UTC)
Received: from ilclasset01.mot.com (ilclasset01.mot.com [100.64.7.105])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: mbland)
	by ilclmmrp01.lenovo.com (Postfix) with ESMTPSA id 4TfWM65bfHz3n3fr;
	Tue, 20 Feb 2024 20:33:22 +0000 (UTC)
From: Maxwell Bland <mbland@motorola.com>
To: linux-arm-kernel@lists.infradead.org
Cc: gregkh@linuxfoundation.org, agordeev@linux.ibm.com,
        akpm@linux-foundation.org, andreyknvl@gmail.com, andrii@kernel.org,
        aneesh.kumar@kernel.org, aou@eecs.berkeley.edu, ardb@kernel.org,
        arnd@arndb.de, ast@kernel.org, borntraeger@linux.ibm.com,
        bpf@vger.kernel.org, brauner@kernel.org, catalin.marinas@arm.com,
        christophe.leroy@csgroup.eu, cl@linux.com, daniel@iogearbox.net,
        dave.hansen@linux.intel.com, david@redhat.com, dennis@kernel.org,
        dvyukov@google.com, glider@google.com, gor@linux.ibm.com,
        guoren@kernel.org, haoluo@google.com, hca@linux.ibm.com,
        hch@infradead.org, john.fastabend@gmail.com, jolsa@kernel.org,
        kasan-dev@googlegroups.com, kpsingh@kernel.org,
        linux-arch@vger.kernel.org, linux@armlinux.org.uk,
        linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        lstoakes@gmail.com, mark.rutland@arm.com, martin.lau@linux.dev,
        meted@linux.ibm.com, michael.christie@oracle.com, mjguzik@gmail.com,
        mpe@ellerman.id.au, mst@redhat.com, muchun.song@linux.dev,
        naveen.n.rao@linux.ibm.com, npiggin@gmail.com, palmer@dabbelt.com,
        paul.walmsley@sifive.com, quic_nprakash@quicinc.com,
        quic_pkondeti@quicinc.com, rick.p.edgecombe@intel.com,
        ryabinin.a.a@gmail.com, ryan.roberts@arm.com, samitolvanen@google.com,
        sdf@google.com, song@kernel.org, surenb@google.com,
        svens@linux.ibm.com, tj@kernel.org, urezki@gmail.com,
        vincenzo.frascino@arm.com, will@kernel.org, wuqiang.matt@bytedance.com,
        yonghong.song@linux.dev, zlim.lnx@gmail.com, mbland@motorola.com,
        awheeler@motorola.com
Subject: [PATCH 4/4] arm64: dynamic enforcement of pmd-level PXNTable
Date: Tue, 20 Feb 2024 14:32:56 -0600
Message-Id: <20240220203256.31153-5-mbland@motorola.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20240220203256.31153-1-mbland@motorola.com>
References: <20240220203256.31153-1-mbland@motorola.com>
X-Proofpoint-GUID: s5Nwo3HF9NZCc_4JrRDKG2zd9RkRjbkK
X-Proofpoint-ORIG-GUID: s5Nwo3HF9NZCc_4JrRDKG2zd9RkRjbkK
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-20_06,2024-02-20_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0
 impostorscore=0 lowpriorityscore=0 phishscore=0 spamscore=0 mlxscore=0
 malwarescore=0 bulkscore=0 mlxlogscore=807 clxscore=1015 adultscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402200146
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@motorola.com header.s=DKIM202306 header.b=3DviofDb;       spf=pass
 (google.com: domain of mbland@motorola.com designates 148.163.148.104 as
 permitted sender) smtp.mailfrom=mbland@motorola.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=motorola.com
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

In an attempt to protect against write-then-execute attacks wherein an
adversary stages malicious code into a data page and then later uses a
write gadget to mark the data page executable, arm64 enforces PXNTable
when allocating pmd descriptors during the init process. However, these
protections are not maintained for dynamic memory allocations, creating
an extensive threat surface to write-then-execute attacks targeting
pages allocated through the vmalloc interface.

Straightforward modifications to the pgalloc interface allow for the
dynamic enforcement of PXNTable, restricting writable and
privileged-executable code pages to known kernel text, bpf-allocated
programs, and kprobe-allocated pages, all of which have more extensive
verification interfaces than the generic vmalloc region.

This patch adds a preprocessor define to check whether a pmd is
allocated by vmalloc and exists outside of a known code region, and if
so, marks the pmd as PXNTable, protecting over 100 last-level page
tables from manipulation in the process.

Signed-off-by: Maxwell Bland <mbland@motorola.com>
---
 arch/arm64/include/asm/pgalloc.h | 11 +++++++++--
 arch/arm64/include/asm/vmalloc.h |  5 +++++
 arch/arm64/mm/trans_pgd.c        |  2 +-
 3 files changed, 15 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/pgalloc.h b/arch/arm64/include/asm/pgalloc.h
index 237224484d0f..5e9262241e8b 100644
--- a/arch/arm64/include/asm/pgalloc.h
+++ b/arch/arm64/include/asm/pgalloc.h
@@ -13,6 +13,7 @@
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
 
+#define __HAVE_ARCH_ADDR_COND_PMD
 #define __HAVE_ARCH_PGD_FREE
 #include <asm-generic/pgalloc.h>
 
@@ -74,10 +75,16 @@ static inline void __pmd_populate(pmd_t *pmdp, phys_addr_t ptep,
  * of the mm address space.
  */
 static inline void
-pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep)
+pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep,
+			unsigned long address)
 {
+	pmdval_t pmd = PMD_TYPE_TABLE | PMD_TABLE_UXN;
 	VM_BUG_ON(mm && mm != &init_mm);
-	__pmd_populate(pmdp, __pa(ptep), PMD_TYPE_TABLE | PMD_TABLE_UXN);
+	if (IS_DATA_VMALLOC_ADDR(address) &&
+		IS_DATA_VMALLOC_ADDR(address + PMD_SIZE)) {
+		pmd |= PMD_TABLE_PXN;
+	}
+	__pmd_populate(pmdp, __pa(ptep), pmd);
 }
 
 static inline void
diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
index dbcf8ad20265..6f254ab83f4a 100644
--- a/arch/arm64/include/asm/vmalloc.h
+++ b/arch/arm64/include/asm/vmalloc.h
@@ -34,4 +34,9 @@ static inline pgprot_t arch_vmap_pgprot_tagged(pgprot_t prot)
 extern unsigned long code_region_start __ro_after_init;
 extern unsigned long code_region_end __ro_after_init;
 
+#define IS_DATA_VMALLOC_ADDR(vaddr) (((vaddr) < code_region_start || \
+				      (vaddr) > code_region_end) && \
+				      ((vaddr) >= VMALLOC_START && \
+				       (vaddr) < VMALLOC_END))
+
 #endif /* _ASM_ARM64_VMALLOC_H */
diff --git a/arch/arm64/mm/trans_pgd.c b/arch/arm64/mm/trans_pgd.c
index 7b14df3c6477..7f903c51e1eb 100644
--- a/arch/arm64/mm/trans_pgd.c
+++ b/arch/arm64/mm/trans_pgd.c
@@ -69,7 +69,7 @@ static int copy_pte(struct trans_pgd_info *info, pmd_t *dst_pmdp,
 	dst_ptep = trans_alloc(info);
 	if (!dst_ptep)
 		return -ENOMEM;
-	pmd_populate_kernel(NULL, dst_pmdp, dst_ptep);
+	pmd_populate_kernel_at(NULL, dst_pmdp, dst_ptep, addr);
 	dst_ptep = pte_offset_kernel(dst_pmdp, start);
 
 	src_ptep = pte_offset_kernel(src_pmdp, start);
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220203256.31153-5-mbland%40motorola.com.
