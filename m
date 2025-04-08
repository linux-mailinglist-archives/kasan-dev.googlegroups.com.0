Return-Path: <kasan-dev+bncBCVZXJXP4MDBBSUT2W7QMGQEZV2RU2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6857AA8116A
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Apr 2025 18:07:41 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-47682f9e7b9sf96730661cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Apr 2025 09:07:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744128460; cv=pass;
        d=google.com; s=arc-20240605;
        b=T83TevyRRgRr1S4eqtAfQPKnh4aogaIF0ri/rwgHuQEeBGLsR9VaZJ6ZRu74jZE9U4
         b0jb/W3nTf6NcC0X9T1ZK64qNZTguDOwARW6k7X4xObycDPbcU2Xyp/G0m8BMePALDAz
         cSRdmW1lPzoAKMZjxwWkha+TDl8HHSJmJ07XH34xdXy2KSFFCkWe6QY8NO4pnYwuRqcM
         NO9nioCfrbreD77tE/FQFp9Y6t/9b4riQmWfAzMTdoapohilvjdxTxdaf8OIemFfS5vT
         Fyuv3972PEsYsyI9X3Gt7zRMemDAUWaZzsD8Su/QfzYOf10U5XeE4sU6IccrftHDG0Q5
         m6Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QvJdLh/HDeB3oOfy1g2QsmQ8HVWtdbb+HbsPmmxPRg4=;
        fh=/nMv2O6l5CKxtBrqn9pqR95LWgdoKtjgz3V9hSWq78A=;
        b=ZOYIctq1rtMXuVYCudVOMd06uzv5gsobgZ07FA8k9zP5fPhQWZADwVRpadGUGj7j+1
         +vHQZ9ZjyXwVNvGaMQxbWjfCTG8cgbQL4HqvZJLsHxo4aM2P/yioRiA7//o44LjY52w4
         fqAToNgW4E9TmdAbccbMOhUwb92PE4NujH20BvlYe61fwWBX/feLBoU9/RmXuGKX+eKi
         1Trf9a+CcGkxF/ITAn+ZsHYZfSlZtVys9HFizobvy8FLXPzRCveBey3pLS/cNTIogm9X
         ZfB9XrpyjFXVkAVQc3TJ8bnQax3fKJ3Do0LrYJDWAyGK/5HXtwyDpAOonPYoVsAwAPR9
         Xakw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rNlkWZXj;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744128460; x=1744733260; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QvJdLh/HDeB3oOfy1g2QsmQ8HVWtdbb+HbsPmmxPRg4=;
        b=PjT2z1/eWuNEusQKDjvuJzIPrwr8QD80LPWY7jjx5R9WIBbZi68epb5Hl4K2x0efPd
         nC3MkhF+XzV1Iq9gW2VRyutDbnrVGNpDeX44+kfiJidMBWfqt1SIgDBTJY/wI6XQkt3y
         3TlWRi8eYlsYlZeYpqGAIj7BKnNmGnC4oEGqh5Quq5jcsdDDZuFX2DAt99RVSJP6VGvc
         UiIxacp/L0LCfUbq2IGf0CVqylg6tkTUQu3m6KGCenyWlnvZSLheDmItdP3kYw33UurD
         JJdjHWu+nj1i0o1o8lrEw0pEL+XqVLQcTyL8Kw+7PMF0XOEwaIHhgFRz6fyGUcUtcM89
         6Rkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744128460; x=1744733260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QvJdLh/HDeB3oOfy1g2QsmQ8HVWtdbb+HbsPmmxPRg4=;
        b=EimBDPMuwgmYmRPzx06i/LcM3cDdGX7zfLMBZarTOCST5YpOarEDz+79VOWW1iZOwQ
         j9BHCnhNt7h+lqnbZ5AnoSAFdgAtVGbcgP3l8L7E8yV1mrJF6VxG6r3cvu+ojNe4CN8X
         v55+q5GPmxw7jQRrQF8d5ydeYdXtQ9s2pO7u1MdgZiglsTDvUqmY6X4VeooOSTxcrLWv
         88gM4a8YefJ0FpHyTL6TWgZFtZD8B3+A5AORIXb9mJMVqP382ijaAvxD5J6RmHQDO4h9
         CSLqLzR7c8pjEeLbtLg+/yLHab3N5Q2Ct5Tvn6t01L7f3hx6Mtw/Nn97iSHXeztF07E1
         jrew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8YTLtbInM6ckgA4kVoc9B4jJ6pawTJOG076QNR5NQ8Anso9cQ084+r4cs8DaxOAbIJXCdhQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz2KPY9feORRrbogCXgrKHey0x7arMtBNYKVkSNeUw0AupU+BnL
	m7pJicAEPFL8obs341oWJOPRbvCT/qqHOeNb3oIaU9j8ATQtWDiy
X-Google-Smtp-Source: AGHT+IG0mhWhNLEaiikGDqrfnjdqjk7N72IA6l4kWfmyMlVQ0v3TZ9r/Z2WbBFSjsAIYImaDkvkLKQ==
X-Received: by 2002:a05:622a:4e:b0:476:903c:822e with SMTP id d75a77b69052e-47924946d0cmr268309201cf.27.1744128458515;
        Tue, 08 Apr 2025 09:07:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAK8bJL7cITZUeIPxK0EIVv+AiwBgijAYBKjyamSRQGtlA==
Received: by 2002:ac8:5d0b:0:b0:476:6bc3:c758 with SMTP id d75a77b69052e-479161549eels19966581cf.0.-pod-prod-05-us;
 Tue, 08 Apr 2025 09:07:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVVkQdc7k1lpKtH2hu2B48cK+jlFvKYbIJJGTnsCc1/VgVWqsoWgdPwyFCJkunhD3yCwqd3YT2SYsQ=@googlegroups.com
X-Received: by 2002:a05:620a:bc2:b0:7c5:5670:bd6f with SMTP id af79cd13be357-7c774dfa5f5mr2709642185a.53.1744128457188;
        Tue, 08 Apr 2025 09:07:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744128457; cv=none;
        d=google.com; s=arc-20240605;
        b=h7JyZ7Hpa/X2aBtyFFRfernyrVPy7v1l8FvISHRN3k1y93b15Q076dzPZ2VzQMiGmh
         exrsOxrc6T9iXjp7BmjVEBYgrdBGGsfOl9nO2F5SfO0ycD5syly417z3OGP7VUfUzigh
         HlHqLsiXDtXvhjmmR1Iq0DqOUPejqrSghLLlgFqgymqOh9HnuVY3gsK4X6KgyhSt9KI8
         7rlZx7MzG6De9+mw5JDiDoutIuiRb9U1c0n0GkAUr30QYIXijOrqdHKBia7BoFbShUuf
         Hu5/nmkyv41sLkAi1m89ouhummtWSJ9HSUdGUdcDGk2EKvog5BIxfs4ZbKRf3W0v0KcZ
         8Qnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ow6t3aZjTh8zUSYva0I+1eccwoSgmKvfkvuHek+W7BI=;
        fh=Qpv0vZFsOkAl7OpmVhwpUC70zZ+oFSiffx6v4uyFrtA=;
        b=NadIzRT6BEGDHtp2hDMiTUF/2MqiAia+Igivi+mXfX+UOv9OAww1NODmuvGzvlqVYm
         C2TtJzatZ9DY7v5K7AacEhb/E9jJkXE4eXpwXUifBHWylUlYeJ8ZXfTiequpElbMeD9V
         qItXWjhe6pMqw6cTpo5zK7WN57FnD7np08M26KwPJVU9S/YyIUa8FoBs3eDXOmcH3pTS
         19fUVRA+S1GaTJVTfeYSXFSHDy8i0/uhGaqAd8D0snJ07RSUvwooiTKCgfK9bEtB8Lto
         a3dXW31Ki1XjdMP9VhWrFKo/WO1obAs70mt9BoPSoheOFv+5WJgteIdJez7h1f18+/IB
         z9Ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rNlkWZXj;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c76e5e2e55si55880985a.0.2025.04.08.09.07.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Apr 2025 09:07:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 538E3xau029563;
	Tue, 8 Apr 2025 16:07:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45vv6a3cmf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:35 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 538FxwH6004506;
	Tue, 8 Apr 2025 16:07:35 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45vv6a3cmc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:35 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 538E2Kef018870;
	Tue, 8 Apr 2025 16:07:34 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 45uhj2b31s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:34 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 538G7WkZ17170806
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 8 Apr 2025 16:07:32 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B38A12004D;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9DDE720043;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 50F3DE171F; Tue, 08 Apr 2025 18:07:32 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v2 3/3] mm: Protect kernel pgtables in apply_to_pte_range()
Date: Tue,  8 Apr 2025 18:07:32 +0200
Message-ID: <ef8f6538b83b7fc3372602f90375348f9b4f3596.1744128123.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1744128123.git.agordeev@linux.ibm.com>
References: <cover.1744128123.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 6gWNv_Bw0XevSqtBIthyoWHVrcn2MvLC
X-Proofpoint-GUID: -fZrXKHJloGCIvDX7whqAyynxCC3jswc
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-08_06,2025-04-08_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 phishscore=0
 lowpriorityscore=0 spamscore=0 priorityscore=1501 adultscore=0
 clxscore=1015 suspectscore=0 bulkscore=0 mlxlogscore=779 mlxscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504080110
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rNlkWZXj;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

The lazy MMU mode can only be entered and left under the protection
of the page table locks for all page tables which may be modified.
Yet, when it comes to kernel mappings apply_to_pte_range() does not
take any locks. That does not conform arch_enter|leave_lazy_mmu_mode()
semantics and could potentially lead to re-schedulling a process while
in lazy MMU mode or racing on a kernel page table updates.

Cc: stable@vger.kernel.org
Fixes: 38e0edb15bd0 ("mm/apply_to_range: call pte function with lazy updates")
Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 7 ++-----
 mm/memory.c       | 5 ++++-
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index edfa77959474..6531a7aa8562 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -308,14 +308,14 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
 	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
 
-	spin_lock(&init_mm.page_table_lock);
 	if (likely(pte_none(ptep_get(ptep)))) {
 		set_pte_at(&init_mm, addr, ptep, pte);
 		page = 0;
 	}
-	spin_unlock(&init_mm.page_table_lock);
+
 	if (page)
 		free_page(page);
+
 	return 0;
 }
 
@@ -401,13 +401,10 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 
 	page = (unsigned long)__va(pte_pfn(ptep_get(ptep)) << PAGE_SHIFT);
 
-	spin_lock(&init_mm.page_table_lock);
-
 	if (likely(!pte_none(ptep_get(ptep)))) {
 		pte_clear(&init_mm, addr, ptep);
 		free_page(page);
 	}
-	spin_unlock(&init_mm.page_table_lock);
 
 	return 0;
 }
diff --git a/mm/memory.c b/mm/memory.c
index f0201c8ec1ce..1f3727104e99 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2926,6 +2926,7 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
 			pte = pte_offset_kernel(pmd, addr);
 		if (!pte)
 			return err;
+		spin_lock(&init_mm.page_table_lock);
 	} else {
 		if (create)
 			pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
@@ -2951,7 +2952,9 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
 
 	arch_leave_lazy_mmu_mode();
 
-	if (mm != &init_mm)
+	if (mm == &init_mm)
+		spin_unlock(&init_mm.page_table_lock);
+	else
 		pte_unmap_unlock(mapped_pte, ptl);
 
 	*mask |= PGTBL_PTE_MODIFIED;
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ef8f6538b83b7fc3372602f90375348f9b4f3596.1744128123.git.agordeev%40linux.ibm.com.
