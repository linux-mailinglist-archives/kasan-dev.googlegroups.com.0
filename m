Return-Path: <kasan-dev+bncBDOJT7EVXMDBBLMZ2SXAMGQEFKGPVLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C4BDF85C5D7
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 21:33:50 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1d542680c9csf78827655ad.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 12:33:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708461229; cv=pass;
        d=google.com; s=arc-20160816;
        b=sG9NlYD57I510CNF9CKDNcTQO4QnJG/ZH9bcVZy7OWCslWS4VBLy2YMrY4ujxSq+RF
         zXKIDqAOgNO7YiV+r2YGrDNW/m31PznKriI7Jum71pX6CEToBBhfXa0CXSlzsO5TMg9y
         O+0+ZeD44HuPpZ4ZtsvtaQKpHXwKPKAZaNbVSzag2tPwzqmp5gSJ/x+Ql0xlNRqqw8/H
         ePCM12ngnbTbXMS+QJPHNL7Z/sTwPCiaswM6Ylkffm+aENQvQBHcAQ9BzIb+ttoiq1g2
         MJcmB4E4FeZy3xxL5zYMNllGz6R3hwInp+D4GQK/O9XXzS5oebBvobP3Zuai24bJ2M02
         jp3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=AYHB6wWKOfIe2kyveBSc2RlWOfXNLVLfFXvsyXHWpRo=;
        fh=ajnXzg50vRwCcoBKMO9sx2gAl3uasponY/N/seA/sJc=;
        b=RlhALJBEhejL4M1Y2nRdhlzj6ToJFm9N5k+KJXfeBoHkqAndJIoftOiVcTkjR1gsBE
         NNLL9qY4lAY2oL7wBYy4FXaRVVitn4IyCOR4RNZ052U3JK2SPcg2fBRb4tVuGFPsCgue
         wI8VHoNbparl+CP6oqyXYqdglfSovGWxdQfa1NKwySdBZOVb8qXODRZ5K7JNVik/3i91
         x2aeYD1yXNZlEFCCX93k2GYaYsN8ZaL1ugOHarVzDRdT+UMuKOxJ6E1WtX6s1/rgC8Zh
         aG8CyvbuPPySmXTCW1p2H5nDfMPoiD38/5RNT8b1eaCNs6uBwEB6tOMTbfgOpq4DXV9N
         c8VQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=ElSgGv+K;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708461229; x=1709066029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:message-id:date:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AYHB6wWKOfIe2kyveBSc2RlWOfXNLVLfFXvsyXHWpRo=;
        b=rjjtoT0Zv736fIKINeiGViIs0BXB3HGOSrK9IeheCPh9gUatjVSt1MYOR9clQAEUSg
         FvNNoRvAl/l/orOxY7/cY0ubkV0r/9dOZ1bKHi4y/49gF7YKGOwRnzYnaFGERuFdPFuC
         PLKlsoXnuj/vWp8wKbVj99dly33cy8fXLDyiB0Z7mcCOXahzDzwGcyiYOwyHge3h2F2M
         HQOwRsgH1uzpp6LQDUGUxINXVhElUTCinSin+r6AfW+OD0Spn8hbeqt8tbfmeXV9cJxH
         QJMFr4Z0voT9eUNjOfGnIzyu1fwab2c6YB6pUYT0dkaYCwytbIJ3TaJh9gE50N7zLGlg
         Pd9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708461229; x=1709066029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:message-id:date:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AYHB6wWKOfIe2kyveBSc2RlWOfXNLVLfFXvsyXHWpRo=;
        b=CpdL30j9j7sEJ1hjsxs0vCFCh2668OP9FmyCv8qRhd7jd50E9QPj+abxTZlHZlJxN2
         PK0qLs0HBbHXACuDK864B5plY0N1nM8DCzaCEF5c87VkMoh6FHpIfkYbyVniukQ+MJhf
         h9PHsRsjmk1wxfdeWYU1ipZ4G/w91EmHqFegftuEmlDKMUY0eJekYubTW/2Ed9avrQ7x
         mXeHVveqHxhydSKsmgpXakO5SAHtI1nKC/wC6r7mdJ5Ej5N3yxWDuap4bGXs4Go0Fr3J
         zoMknpE8Tf/3AtNjTV9S8k+ATvpR0zI/wCesq6+UKNuiTtVsbSaG8ZGex83ugwpI8bba
         dFng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6R9ED0fhg4IgRdFlTDq7MHbJqizMtHeWOVP4GjqpfWta4fiIjCDh7FHf26+9Tzb5VVcBsSMbIGSO+D2KgIfjY9aWqJeRnnQ==
X-Gm-Message-State: AOJu0Yzh/HTlyWp3ouL+mIbJKMP984JSHBvI7d0jr6SajXoADv8/3AWu
	G7Km8/7VNzbuEdpoLJ2BIN7K72bRx5KtH+MizTs9ZxfVYnZ9b6xF
X-Google-Smtp-Source: AGHT+IEbEwhu9HNW9eM/R6QP74tQKGqpLwDyCeOrKdYWZ7pN1I5OMMSAsiYbfLlfpNpg3dczaCVPhQ==
X-Received: by 2002:a17:903:2289:b0:1dc:177b:1d71 with SMTP id b9-20020a170903228900b001dc177b1d71mr3087018plh.57.1708461229303;
        Tue, 20 Feb 2024 12:33:49 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dac2:b0:1db:3ede:8aa7 with SMTP id
 q2-20020a170902dac200b001db3ede8aa7ls3030386plx.1.-pod-prod-01-us; Tue, 20
 Feb 2024 12:33:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXq5XLkkdUKusuikXFbj8A7SB7YDmqgZfLYLzxnZvz6wwAS4VwUDQI2+K0mqx6lj1ulRuV/cJYSwm7r5fTM+BaQNKORNjsYLa38rA==
X-Received: by 2002:a17:902:e548:b0:1db:f11d:feda with SMTP id n8-20020a170902e54800b001dbf11dfedamr8010690plf.10.1708461227602;
        Tue, 20 Feb 2024 12:33:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708461227; cv=none;
        d=google.com; s=arc-20160816;
        b=qchK1jKlt88rIaVKu1Q2cy+hE5U2jAbdSIJosU3tV269LeRgKe8jhnSAeFsk0yKyCy
         47IMhrSBWXkOutEATfcc5SbmBVE3li/4CBYHHuPFDc9GeJbvqItaUH4qggUge/C70PT/
         SbUaVlAfg/yG0gKjntbCMvXFYHci7dZEsh+hgtHb/vGn+f8leQ7r8Hv9GOxJEhTOH/JX
         kKReGI14NOxLWePB+6qBaMJca6LYdZ0mr85RJvjmAoZWLozlDrAcHqPdDD6trCFdn3JK
         WRm0VGU88eyj/RTdNdl+HPpd+5v6s16mSvN6hrQIRjlrUw4PyM2x99UGJg5gmGAkgDAJ
         ZZoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=lwi3HRNY78hVZA0tkjf7HxRAkL6o9c683flfMjEmlDw=;
        fh=FkeYy9VFhDbdZf7Wr1j+kC7C7CaCFd0E6M33TF/KxqU=;
        b=uuSFTNsHvz8NHNSIfD1KCbQGwvnkLUxNvBhwxp6ytfsxZA2NMQfvp0BrG8t9KqD9ge
         9fsyJ/2GX6FDYptFq2PvslP12Qw3fDzGvC8pG+nyBJkZ72rHiKSUBs3aDNtAYPhSuf5N
         dJhOvbPHL9Yz3jSXqAl+8ubOlKvb9JvqCt5RFYMeTLIz2ndz62jcoT7aFa0yPj8rrwtz
         mhGD1O9qE+HJXtMgq7CpuLpQ49EYk4pK7H+eL1smYxelRlKOl8DbJjrfglwjj0YKyCFO
         3Hbap+ySD303GE0WKsRjY1XZKjzDdmsr2TDzhv3VJBU3/Hy/kFD7mLy4XovqkakIP1VF
         mudA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@motorola.com header.s=DKIM202306 header.b=ElSgGv+K;
       spf=pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) smtp.mailfrom=mbland@motorola.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=motorola.com
Received: from mx0a-00823401.pphosted.com (mx0a-00823401.pphosted.com. [148.163.148.104])
        by gmr-mx.google.com with ESMTPS id mi13-20020a170902fccd00b001d8cea8344bsi491304plb.7.2024.02.20.12.33.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 12:33:47 -0800 (PST)
Received-SPF: pass (google.com: domain of mbland@motorola.com designates 148.163.148.104 as permitted sender) client-ip=148.163.148.104;
Received: from pps.filterd (m0355086.ppops.net [127.0.0.1])
	by mx0a-00823401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41KJCtfd003147;
	Tue, 20 Feb 2024 20:33:21 GMT
Received: from va32lpfpp04.lenovo.com ([104.232.228.24])
	by mx0a-00823401.pphosted.com (PPS) with ESMTPS id 3wd21w05eb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 20 Feb 2024 20:33:20 +0000 (GMT)
Received: from ilclmmrp01.lenovo.com (ilclmmrp01.mot.com [100.65.83.165])
	(using TLSv1.2 with cipher ADH-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by va32lpfpp04.lenovo.com (Postfix) with ESMTPS id 4TfWM353nvzgQyg;
	Tue, 20 Feb 2024 20:33:19 +0000 (UTC)
Received: from ilclasset01.mot.com (ilclasset01.mot.com [100.64.7.105])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: mbland)
	by ilclmmrp01.lenovo.com (Postfix) with ESMTPSA id 4TfWM33V0nz3n3fr;
	Tue, 20 Feb 2024 20:33:19 +0000 (UTC)
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
Subject: [PATCH 2/4] mm: pgalloc: support address-conditional pmd allocation
Date: Tue, 20 Feb 2024 14:32:54 -0600
Message-Id: <20240220203256.31153-3-mbland@motorola.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20240220203256.31153-1-mbland@motorola.com>
References: <20240220203256.31153-1-mbland@motorola.com>
X-Proofpoint-GUID: 9_RvRYASrp8BDFERRubxVO2fOgWP-iSC
X-Proofpoint-ORIG-GUID: 9_RvRYASrp8BDFERRubxVO2fOgWP-iSC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-20_06,2024-02-20_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 clxscore=1015
 spamscore=0 mlxscore=0 priorityscore=1501 mlxlogscore=822 phishscore=0
 bulkscore=0 malwarescore=0 lowpriorityscore=0 impostorscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2402120000
 definitions=main-2402200146
X-Original-Sender: mbland@motorola.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@motorola.com header.s=DKIM202306 header.b=ElSgGv+K;       spf=pass
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

While other descriptors (e.g. pud) allow allocations conditional on
which virtual address is allocated, pmd descriptor allocations do not.
However, adding support for this is straightforward and is beneficial to
future kernel development targeting the PMD memory granularity.

As many architectures already implement pmd_populate_kernel in an
address-generic manner, it is necessary to roll out support
incrementally. For this purpose a preprocessor flag,
__HAVE_ARCH_ADDR_COND_PMD is introduced to capture whether the
architecture supports some feature requiring PMD allocation conditional
on virtual address. Some microarchitectures (e.g. arm64) support
configurations for table descriptors, for example to enforce Privilege
eXecute Never, which benefit from knowing the virtual memory addresses
referenced by PMDs.

Thus two major arguments in favor of this change are (1) unformity of
allocation between PMD and other table descriptor types and (2) the
capability of address-specific PMD allocation.

Signed-off-by: Maxwell Bland <mbland@motorola.com>
---
 include/asm-generic/pgalloc.h | 18 ++++++++++++++++++
 include/linux/mm.h            |  4 ++--
 mm/hugetlb_vmemmap.c          |  4 ++--
 mm/kasan/init.c               | 22 +++++++++++++---------
 mm/memory.c                   |  4 ++--
 mm/percpu.c                   |  2 +-
 mm/pgalloc-track.h            |  3 ++-
 mm/sparse-vmemmap.c           |  2 +-
 8 files changed, 41 insertions(+), 18 deletions(-)

diff --git a/include/asm-generic/pgalloc.h b/include/asm-generic/pgalloc.h
index 879e5f8aa5e9..e5cdce77c6e4 100644
--- a/include/asm-generic/pgalloc.h
+++ b/include/asm-generic/pgalloc.h
@@ -142,6 +142,24 @@ static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
 }
 #endif
 
+#ifdef __HAVE_ARCH_ADDR_COND_PMD
+static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp,
+			pte_t *ptep, unsigned long address);
+#else
+static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp,
+			pte_t *ptep);
+#endif
+
+static inline void pmd_populate_kernel_at(struct mm_struct *mm, pmd_t *pmdp,
+			pte_t *ptep, unsigned long address)
+{
+#ifdef __HAVE_ARCH_ADDR_COND_PMD
+	pmd_populate_kernel(mm, pmdp, ptep, address);
+#else
+	pmd_populate_kernel(mm, pmdp, ptep);
+#endif
+}
+
 #ifndef __HAVE_ARCH_PMD_FREE
 static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
 {
diff --git a/include/linux/mm.h b/include/linux/mm.h
index f5a97dec5169..6a9d5ded428d 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2782,7 +2782,7 @@ static inline void mm_dec_nr_ptes(struct mm_struct *mm) {}
 #endif
 
 int __pte_alloc(struct mm_struct *mm, pmd_t *pmd);
-int __pte_alloc_kernel(pmd_t *pmd);
+int __pte_alloc_kernel(pmd_t *pmd, unsigned long address);
 
 #if defined(CONFIG_MMU)
 
@@ -2977,7 +2977,7 @@ pte_t *pte_offset_map_nolock(struct mm_struct *mm, pmd_t *pmd,
 		 NULL : pte_offset_map_lock(mm, pmd, address, ptlp))
 
 #define pte_alloc_kernel(pmd, address)			\
-	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd))? \
+	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd, address)) ? \
 		NULL: pte_offset_kernel(pmd, address))
 
 #if USE_SPLIT_PMD_PTLOCKS
diff --git a/mm/hugetlb_vmemmap.c b/mm/hugetlb_vmemmap.c
index da177e49d956..1f5664b656f1 100644
--- a/mm/hugetlb_vmemmap.c
+++ b/mm/hugetlb_vmemmap.c
@@ -58,7 +58,7 @@ static int vmemmap_split_pmd(pmd_t *pmd, struct page *head, unsigned long start,
 	if (!pgtable)
 		return -ENOMEM;
 
-	pmd_populate_kernel(&init_mm, &__pmd, pgtable);
+	pmd_populate_kernel_at(&init_mm, &__pmd, pgtable, addr);
 
 	for (i = 0; i < PTRS_PER_PTE; i++, addr += PAGE_SIZE) {
 		pte_t entry, *pte;
@@ -81,7 +81,7 @@ static int vmemmap_split_pmd(pmd_t *pmd, struct page *head, unsigned long start,
 
 		/* Make pte visible before pmd. See comment in pmd_install(). */
 		smp_wmb();
-		pmd_populate_kernel(&init_mm, pmd, pgtable);
+		pmd_populate_kernel_at(&init_mm, pmd, pgtable, addr);
 		if (!(walk->flags & VMEMMAP_SPLIT_NO_TLB_FLUSH))
 			flush_tlb_kernel_range(start, start + PMD_SIZE);
 	} else {
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 89895f38f722..1e31d965a14e 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -116,8 +116,9 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 		next = pmd_addr_end(addr, end);
 
 		if (IS_ALIGNED(addr, PMD_SIZE) && end - addr >= PMD_SIZE) {
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			pmd_populate_kernel_at(&init_mm, pmd,
+					lm_alias(kasan_early_shadow_pte),
+					addr);
 			continue;
 		}
 
@@ -131,7 +132,7 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 			if (!p)
 				return -ENOMEM;
 
-			pmd_populate_kernel(&init_mm, pmd, p);
+			pmd_populate_kernel_at(&init_mm, pmd, p, addr);
 		}
 		zero_pte_populate(pmd, addr, next);
 	} while (pmd++, addr = next, addr != end);
@@ -157,8 +158,9 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			pmd_populate_kernel_at(&init_mm, pmd,
+					lm_alias(kasan_early_shadow_pte),
+					addr);
 			continue;
 		}
 
@@ -203,8 +205,9 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			pmd_populate_kernel_at(&init_mm, pmd,
+					lm_alias(kasan_early_shadow_pte),
+					addr);
 			continue;
 		}
 
@@ -266,8 +269,9 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			pmd_populate_kernel_at(&init_mm, pmd,
+					lm_alias(kasan_early_shadow_pte),
+					addr);
 			continue;
 		}
 
diff --git a/mm/memory.c b/mm/memory.c
index 15f8b10ea17c..15702822d904 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -447,7 +447,7 @@ int __pte_alloc(struct mm_struct *mm, pmd_t *pmd)
 	return 0;
 }
 
-int __pte_alloc_kernel(pmd_t *pmd)
+int __pte_alloc_kernel(pmd_t *pmd, unsigned long address)
 {
 	pte_t *new = pte_alloc_one_kernel(&init_mm);
 	if (!new)
@@ -456,7 +456,7 @@ int __pte_alloc_kernel(pmd_t *pmd)
 	spin_lock(&init_mm.page_table_lock);
 	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
 		smp_wmb(); /* See comment in pmd_install() */
-		pmd_populate_kernel(&init_mm, pmd, new);
+		pmd_populate_kernel_at(&init_mm, pmd, new, address);
 		new = NULL;
 	}
 	spin_unlock(&init_mm.page_table_lock);
diff --git a/mm/percpu.c b/mm/percpu.c
index 4e11fc1e6def..7312e584c1b5 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3238,7 +3238,7 @@ void __init __weak pcpu_populate_pte(unsigned long addr)
 		new = memblock_alloc(PTE_TABLE_SIZE, PTE_TABLE_SIZE);
 		if (!new)
 			goto err_alloc;
-		pmd_populate_kernel(&init_mm, pmd, new);
+		pmd_populate_kernel_at(&init_mm, pmd, new, addr);
 	}
 
 	return;
diff --git a/mm/pgalloc-track.h b/mm/pgalloc-track.h
index e9e879de8649..0984681c03d4 100644
--- a/mm/pgalloc-track.h
+++ b/mm/pgalloc-track.h
@@ -45,7 +45,8 @@ static inline pmd_t *pmd_alloc_track(struct mm_struct *mm, pud_t *pud,
 
 #define pte_alloc_kernel_track(pmd, address, mask)			\
 	((unlikely(pmd_none(*(pmd))) &&					\
-	  (__pte_alloc_kernel(pmd) || ({*(mask)|=PGTBL_PMD_MODIFIED;0;})))?\
+	  (__pte_alloc_kernel(pmd, address) ||				\
+		({*(mask) |= PGTBL_PMD_MODIFIED; 0; }))) ?		\
 		NULL: pte_offset_kernel(pmd, address))
 
 #endif /* _LINUX_PGALLOC_TRACK_H */
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index a2cbe44c48e1..d876cc4dc700 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -191,7 +191,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
 		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
 		if (!p)
 			return NULL;
-		pmd_populate_kernel(&init_mm, pmd, p);
+		pmd_populate_kernel_at(&init_mm, pmd, p, addr);
 	}
 	return pmd;
 }
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220203256.31153-3-mbland%40motorola.com.
