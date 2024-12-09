Return-Path: <kasan-dev+bncBAABB4NS3G5AMGQEFM54SOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B08B9E894D
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2024 03:44:03 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-725e8775611sf527997b3a.1
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Dec 2024 18:44:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733712242; cv=pass;
        d=google.com; s=arc-20240605;
        b=cmLP59vZ3dEP4pX7emIxrAgQERMwXKwhuWXfTAlL5LH4X+O3pizQT254gaNZMf++UF
         2xdxtUwkzip1BWjrwi9RONfA7PuhcuggzLvvtQ+4a2tOsWyEbz1Gs7Z/OCQNJ7Cfgwk0
         OaRgT0ACY18AJNBjVEI2fHctj0T4KbXelD3ZHbpmAuB+1kqEJK5Mz+IgIHYQeQIhSf9v
         +lKK80PhTPecr6Qad5HHpifM41ze7cwBm0g+7BqYpWkWOyb/3P8h2vQPIRSMskE/qLag
         HjwRKEfbwt2GStMxVI7St7GzxVz/shcZfxiOnx9QLJS4B368rINH4sm/mkhWQEwxbmPZ
         Pqyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3/Bw/YUGlGl9GpV4XK26mVuZ0O4x3ZdiFaKibYTAS6Q=;
        fh=i1sJrg0rKd3BjyrxckXXj9PPrwGJBwrLeW8g1eaUeRM=;
        b=kAnfpIR8vRJsnoO99Eh7iVScrPlW4paUGselzfofc7NIxLkyuLazNN9DtRjsxD6alP
         Sy2fC38Q/plW17S1Ua2DOyIAkWO95QmhYlfZ16dkNjORdiGaVWrJ84tzUqPVXpi6+aGe
         kr/yP/IBAC+O7MOugoQi42ptNkDhx/2tRP/MT80wZ+6lj2hsODSHRnp4tOHadFQ/5D10
         Xal0KAKxBhdV5qKOxtuja2IXxCgh/WDW6yuuwLIB44qPkPbc/iPPL4pNm4FN6AC8i08g
         0plhVPX9IGs1LFUsuXMspRjoLv6t6GEi5t3xaRioJcnqsV94zrMqj+lehpr0OVmNkbUu
         pIaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733712242; x=1734317042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3/Bw/YUGlGl9GpV4XK26mVuZ0O4x3ZdiFaKibYTAS6Q=;
        b=tb+i6CuxuPy1bh8Ooi8+dkhGiEWUAbyN9wllxkuvRECWz1PeQ/+hWg+XIODBEQ6JAa
         PsOj9pyE/fnV2iKGr5A5hW3jHbZ3XDThr9Wmey6XrcJ+wn2Tn7HGdULnCoXZZBcF5Kq1
         Z0xdrbwdu5JTmqJrWCPtpoqR5SS/rTX+3Jbiw9ycW6SBQ3tzlZywnOum4P4dtPgItALq
         rm/gY6v7Ds3GmDMEx9NFMyKzBxtnNnvvKXW9I/0vLJpLhZCoxyBqnno/RKw+WtFXJesV
         29K1WhqyeFpuOk4Jp4k1oktbpDXyV7hOGbrTOV1qfcjTYhB9eAgdSEFftcGMyhgDA1nO
         +buw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733712242; x=1734317042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3/Bw/YUGlGl9GpV4XK26mVuZ0O4x3ZdiFaKibYTAS6Q=;
        b=KtlbOhByl2yRck6oEidNkSBkih4Idyh13cCSTl7D+NNwKOU+g7Bg4AdVNCfroNHis6
         BYPwesTJ8/sVpERaN0ly2YdyRXT+PDGmRjzDLkTG7mPuSvWvfla4Kf2TZr95vsBoVqvK
         /PiKukFIEJqeRZHpIVr0mTlvatQpOBdCGB6H8i7/TM9JJbRAzEQU2q5kgGJFCmiouBV/
         mX3p/Khb43/Tx4w4r2NfO1/EkSp5sI0E3dwKha8sE0lpdddqztIHZysvXGrJDghmwvwS
         FSta2AmRLHwMAHFeRO05x3+OtwS6bZ8T2GYMK3qHsD34FXeBQRSSZqMGvDgkhxOCjMsI
         YEWg==
X-Forwarded-Encrypted: i=2; AJvYcCWZwt6tl1qYpvtAoN9/8uHcarJMEqPc03Wvv+zwNo2ZPu9PCH2ECINcxPlva0zm+QVQSP58eQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx/uBZ1ETpjy0jiQBCR/F5ovEDTYEWvRofVbPRW0d7jbHKya+yD
	7rncjhK+pPnLbP5/tINj3wFhKcfwJpcgMYpWLEzJ8XF9xsVplWNn
X-Google-Smtp-Source: AGHT+IF7Vs+h/Wp8iri/1qy0lLLq9uEpFT8uu073RSyioMVqdxBsNhAxlFErB4I7ROXuAZwnVlPELg==
X-Received: by 2002:a05:6a00:2e19:b0:724:e80a:33a with SMTP id d2e1a72fcca58-725b820baf4mr20010395b3a.23.1733712241968;
        Sun, 08 Dec 2024 18:44:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ae19:0:b0:725:d62d:bfad with SMTP id d2e1a72fcca58-725d62dc069ls746016b3a.2.-pod-prod-05-us;
 Sun, 08 Dec 2024 18:44:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWD2n5LOGwJPtYSUdUdIXbbpOKloL50E3YUeKYZQ1CM/cg17lEm2ugemS9wJHqFdaM+GWybH1qkO/Q=@googlegroups.com
X-Received: by 2002:a05:6a00:4651:b0:725:ead7:fcae with SMTP id d2e1a72fcca58-725ead8019bmr3898054b3a.18.1733712240727;
        Sun, 08 Dec 2024 18:44:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733712240; cv=none;
        d=google.com; s=arc-20240605;
        b=jjzgDdxdXgLcfeT6jM5Kl6fTH4GWTBX1NQ5OhpMg1SU8bWyObqLJzAamwtz094ZRxZ
         CJAhkmHtrf6926l4gyvlkk5MAt20YXkzIdYnENc2RqssGx2WZ2RRooW0xpMGF1ciQdfE
         F69p6Bpgpa8pnLxB5AWL99N5rnXhmcTXxcaFCSdidhb5L7AiqDeZlEL13HEnuNmM9OHO
         YJSy+rJ6MobdKmH5pi9NQ1iPEUOgUtQDH0FLAAwkLRlkDcIQcRFKA4QSEEiizcGK4i7w
         J5j5uSrfoBLCYXknyHibmlNtJavatFACJDqmh0TLfqenvkHFaWOl+0ImgqZusCAc0Qdr
         YGjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=LlnRR/ekzvfKFU0JIU5g10P2k1CrW7ToDOkJBkyI4mw=;
        fh=zBWha3m7j9g4fOlI2Dk54gN6qyAThRjo4Lp4VAY4w1U=;
        b=Oy477jkwixGPvVOqm6JBoMLvjDN+T26jrtJSdD3ycjfBgYMn+n18wwkpKFQG4S592b
         Y2H7XZGH5O627mCHcCdPEPh5ZxesIjzbOMvegncj2eZ5MFUYYkFG1DsFQL8YNfyQH7Fb
         84UdP5XPDlUAktUagvs7mqjiTWvewdbMEKhzEYDSfzgL8ICth+JCmJsrS3HDaTvqwqNj
         yHOgjAAudC6FoAzYc5sm1gc/C8HspOCTR3Uc4GFqIopiPu4k0a44IEz7R5dKG6+S0qqA
         2Za+hr5xja0g9FLq6gI1SKiVm7iISh5tzowrfAKCoIVL+j9i5TV/DFO6I3HZsPHu1wbc
         +PfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-725a2a8f5d2si319520b3a.2.2024.12.08.18.43.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Dec 2024 18:44:00 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from mail.maildlp.com (unknown [172.19.162.254])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4Y65jL32dzzRj4G;
	Mon,  9 Dec 2024 10:41:42 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id F0128180102;
	Mon,  9 Dec 2024 10:43:24 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Mon, 9 Dec 2024 10:43:22 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@Huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, Will
 Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, James
 Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Christophe
 Leroy <christophe.leroy@csgroup.eu>, Aneesh Kumar K.V
	<aneesh.kumar@kernel.org>, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Madhavan Srinivasan
	<maddy@linux.ibm.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v13 3/5] mm/hwpoison: return -EFAULT when copy fail in copy_mc_[user]_highpage()
Date: Mon, 9 Dec 2024 10:42:55 +0800
Message-ID: <20241209024257.3618492-4-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20241209024257.3618492-1-tongtiangen@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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

Currently, copy_mc_[user]_highpage() returns zero on success, or in case
of failures, the number of bytes that weren't copied.

While tracking the number of not copied works fine for x86 and PPC, There
are some difficulties in doing the same thing on ARM64 because there is no
available caller-saved register in copy_page()(lib/copy_page.S) to save
"bytes not copied", and the following copy_mc_page() will also encounter
the same problem.

Consider the caller of copy_mc_[user]_highpage() cannot do any processing
on the remaining data(The page has hardware errors), they only check if
copy was succeeded or not, make the interface more generic by using an
error code when copy fails (-EFAULT) or return zero on success.

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
Reviewed-by: Jonathan Cameron <Jonathan.Cameron@huawei.com>
Reviewed-by: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
---
 include/linux/highmem.h | 8 ++++----
 mm/khugepaged.c         | 4 ++--
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index 6e452bd8e7e3..0eb4b9b06837 100644
--- a/include/linux/highmem.h
+++ b/include/linux/highmem.h
@@ -329,8 +329,8 @@ static inline void copy_highpage(struct page *to, struct page *from)
 /*
  * If architecture supports machine check exception handling, define the
  * #MC versions of copy_user_highpage and copy_highpage. They copy a memory
- * page with #MC in source page (@from) handled, and return the number
- * of bytes not copied if there was a #MC, otherwise 0 for success.
+ * page with #MC in source page (@from) handled, and return -EFAULT if there
+ * was a #MC, otherwise 0 for success.
  */
 static inline int copy_mc_user_highpage(struct page *to, struct page *from,
 					unsigned long vaddr, struct vm_area_struct *vma)
@@ -349,7 +349,7 @@ static inline int copy_mc_user_highpage(struct page *to, struct page *from,
 	if (ret)
 		memory_failure_queue(page_to_pfn(from), 0);
 
-	return ret;
+	return ret ? -EFAULT : 0;
 }
 
 static inline int copy_mc_highpage(struct page *to, struct page *from)
@@ -368,7 +368,7 @@ static inline int copy_mc_highpage(struct page *to, struct page *from)
 	if (ret)
 		memory_failure_queue(page_to_pfn(from), 0);
 
-	return ret;
+	return ret ? -EFAULT : 0;
 }
 #else
 static inline int copy_mc_user_highpage(struct page *to, struct page *from,
diff --git a/mm/khugepaged.c b/mm/khugepaged.c
index 6f8d46d107b4..c3cdc0155dcd 100644
--- a/mm/khugepaged.c
+++ b/mm/khugepaged.c
@@ -820,7 +820,7 @@ static int __collapse_huge_page_copy(pte_t *pte, struct folio *folio,
 			continue;
 		}
 		src_page = pte_page(pteval);
-		if (copy_mc_user_highpage(page, src_page, src_addr, vma) > 0) {
+		if (copy_mc_user_highpage(page, src_page, src_addr, vma)) {
 			result = SCAN_COPY_MC;
 			break;
 		}
@@ -2081,7 +2081,7 @@ static int collapse_file(struct mm_struct *mm, unsigned long addr,
 		}
 
 		for (i = 0; i < nr_pages; i++) {
-			if (copy_mc_highpage(dst, folio_page(folio, i)) > 0) {
+			if (copy_mc_highpage(dst, folio_page(folio, i))) {
 				result = SCAN_COPY_MC;
 				goto rollback;
 			}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241209024257.3618492-4-tongtiangen%40huawei.com.
