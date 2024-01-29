Return-Path: <kasan-dev+bncBAABBW6Y32WQMGQEDUIKSKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id ECAC0840753
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 14:47:08 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-59a3956d3d8sf1447221eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 05:47:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706536027; cv=pass;
        d=google.com; s=arc-20160816;
        b=J8STXenDo6dow4nwRRABJ10G14AaLtlDCYQbjjJic7Q3PhdSxbs3ciR10L68uTZg1x
         at1j9Mi/PetcOxS/84l1z8EpjYFFZq4ZZH2AvnUKgtU/iLsLqsish/OmWz3FnQqmSyGz
         7vziAwDHvmKcS+MgXiD7/43ktogknM0Dcbmo0eE2acoYWPezEViF1IiXT6Z0zlkIyhSI
         pBjmaGt8lEH6Q4sgGzjzUkhtXNV/VBAg4wuc3j4IpI5Al0wEnqX4Ousjs6XlXpc5rrAa
         3A+Kr9lu7yxYwKBrHKxalLyzfxarMU3I+voklQZip8so7axyRmKUnrEjAvJMsIYkLYAH
         V+uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=/jFpR6NbT46i+KL8VvPLd9xwSX/tfxTVsPEl+hJfePo=;
        fh=0KMPFt7jtRdckJo0yvorV2XSrGq3FTQAG9A0j2f9daM=;
        b=GdajIF3xAGmh6IPxxYrwuPEpR285PFSVX2eJCows3OiyM8nqodQGXJy7+ZMrDw6pY2
         Ou85AgRYCtxQGGsA5KFUx5zOaJ+gLedKHpnm+WCiUfgIR05IeQJHSA/5meosX37hcJQR
         lfntSa2FBq8Pxp/do0c2MZ+Hv+JXQhPGHLgrIE4v+32k/+wlIJTSvzZN64247+ac3Twp
         3+QghqVVYutiLgv/fxmC/9WgL52BZyB3jn2P8ejybvQ+YXWpfo6DwmI7g8TxcsSWOFnn
         w4INyZnNU0zOctAEHctWOt/4v65H61fhVESnLl2BSNARiPFUWsO5OE33g2ELjih/oiu3
         5fTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706536027; x=1707140827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/jFpR6NbT46i+KL8VvPLd9xwSX/tfxTVsPEl+hJfePo=;
        b=ngyVleC2OYHVTfJqCaJXN1sniJIPq9P7lgqAzxprVPf1x1+9zgTtbwmxp4YQzJyIOm
         dWN9ADv5mK7LR0/HuACn8n4Zc4bMcWsPMMdaNP87nO+alNwuhZnwCcULHtq7g4Zz9iXw
         ZGBZBPVbt+ehwCn5TvPX8Olw5L6Q9V52VultnAb2xn6apXmHlVoc9OyKRXgGmsWHKPPa
         /wvvKi4BVuMNPeT58Oygw0L+7neKszSq2v+lx8QMRBbJvD8Q8Q4gSLumbywGG1S9yp0O
         KJJGHXXb1ax2jL1wcItyNOlg99AszGQiW3st/LfPnF2jx3gHKTNjNekpHSekTqi36fyt
         aYMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706536027; x=1707140827;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/jFpR6NbT46i+KL8VvPLd9xwSX/tfxTVsPEl+hJfePo=;
        b=J+OC2IEyWDOnUXIYf1dikn2+WqwqULqkDDWv8luGrsCgreFFK/1RIcR/iCGQ/d8Jck
         7okO0KNo/4enCNb43PBMwVmEQSGpOJUJt/CIjGeg/GQeTOiYdPNySj59M3aTXTUiwr53
         OW1GbgeAbdVa0JkjCcdbG0m6R8xabI1nwmtqG77KBjAPmshk3+YeqhxggJ26nsVFuhTJ
         L9upLkEVm8tmcNfcTJfLZitSVjrEbwVT4B6gtovZAxyx9z82YQa6W0D6r2nw+hszkaIU
         mWSDevLljhAUpwiEqoZa1TnSLHdxU4+75mhHOcl7PEM74Qeo169+Xew+X4cG0OiRQ3G7
         t05A==
X-Gm-Message-State: AOJu0YxbIik/9CP5NjgjkV0sNPteGDSuS4xZF75eX5JLevbuSVwa2MPk
	oS/ytesnH1PZ9JG7fOWR4rzAvogNUni5KqoZH6kGQ1zPDgfhdnNV
X-Google-Smtp-Source: AGHT+IHLuYL+os8mC/N7STjliKyGhBEYAkzFyvODIPT1RWUd2lzygLWSHiaiZ2RjCYd76GfBlR33xw==
X-Received: by 2002:a4a:de07:0:b0:59a:2817:153d with SMTP id y7-20020a4ade07000000b0059a2817153dmr2912298oot.8.1706536027402;
        Mon, 29 Jan 2024 05:47:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1622:b0:59a:6f3:5b56 with SMTP id
 bb34-20020a056820162200b0059a06f35b56ls2922273oob.1.-pod-prod-05-us; Mon, 29
 Jan 2024 05:47:06 -0800 (PST)
X-Received: by 2002:a05:6808:309b:b0:3be:7a42:f806 with SMTP id bl27-20020a056808309b00b003be7a42f806mr659146oib.1.1706536026794;
        Mon, 29 Jan 2024 05:47:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706536026; cv=none;
        d=google.com; s=arc-20160816;
        b=MWAJAHDd2NLX8CUrdXs4M5p+JL88nLb1PSPSGocJXwP0BZCH7PKcoW8zxRVYNUMLDs
         SsvTSwJLVmydAiTreYY1T+fIVf3T5wweqgwsC5tnoP+VtsFLIt5CipdiiijhB2s9YQIe
         EW/O7+xtXwBqqBqWmPF09mo1kH2ev+E1DiWpBhT3mIa5XQlm1t1XDuyh0fCvi2Aa7TRI
         CeCNDOFSxObIEv7F2zHbKDm8QJ4E2Jxe0yTYrQ4I4i2n/uH27/Mz9+l9Lw3YXrqDUa+O
         cvTL8ulfqGtzl1HhArPSjXon0cWLc2kbaWUV7IDuaDGQFWCPuOIBpF7GqFX16iRG1qPp
         KHwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=4oS5QI8PowY+Zs3TQNKojee8XDIVZivI95uIZM8SiOM=;
        fh=0KMPFt7jtRdckJo0yvorV2XSrGq3FTQAG9A0j2f9daM=;
        b=l6m/AZNK8CDmi8gfFmYZcDleGKoEySx1Akdc5D+0R2u70YQ/vnJFUzJHcPiyF1y7nR
         VRnW1092KGuYbUzaChTxJJ4qcNyhFBqN/bRuvvKaB1bp+1AQEGQ+ryC8LCCRP79okxyb
         hiHhTpxY0Mp1AKcQFS7Y5eZSWE3yFs4MmX58RUBe7VlGcAZEM4AbXgWhg1sjJRiIvZpn
         MbFsz/TuugY++8Vy6cUEU2hK/jEhHUunugqZtgssDKobpr8FnOmc0FAZy4ZjJow9bjV8
         NfpDvV1axGfRt79BLFnSSGl7i0G3IFSTXyGfW6nX5+c4fJxTxKVPjzpKSU01/P8Jp5rW
         gdew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCV8ad2tT8hvDwOr4i6dIqGE0vwnKYSCDhcAVb8lrMyaDL2prYYCg3u9eCYbsvpzU3EEl/4E6zjQL67dyPt1wM4arPMlmaLDhPit1A==
Received: from szxga06-in.huawei.com (szxga06-in.huawei.com. [45.249.212.32])
        by gmr-mx.google.com with ESMTPS id 13-20020a54418d000000b003be04bcac59si482092oiy.3.2024.01.29.05.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jan 2024 05:47:06 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) client-ip=45.249.212.32;
Received: from mail.maildlp.com (unknown [172.19.162.112])
	by szxga06-in.huawei.com (SkyGuard) with ESMTP id 4TNqMz4Dbvz1vsj8;
	Mon, 29 Jan 2024 21:46:39 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id D25391404DB;
	Mon, 29 Jan 2024 21:47:03 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Mon, 29 Jan 2024 21:47:01 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>, James Morse <james.morse@arm.com>, Robin
 Murphy <robin.murphy@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Alexander Viro
	<viro@zeniv.linux.org.uk>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy
	<christophe.leroy@csgroup.eu>, Aneesh Kumar K.V <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov
	<bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>,
	"H. Peter Anvin" <hpa@zytor.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v10 4/6] mm/hwpoison: return -EFAULT when copy fail in copy_mc_[user]_highpage()
Date: Mon, 29 Jan 2024 21:46:50 +0800
Message-ID: <20240129134652.4004931-5-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240129134652.4004931-1-tongtiangen@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as
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

If hardware errors are encountered during page copying, returning the bytes
not copied is not meaningful, and the caller cannot do any processing on
the remaining data. Returning -EFAULT is more reasonable, which represents
a hardware error encountered during the copying.

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
---
 include/linux/highmem.h | 8 ++++----
 mm/khugepaged.c         | 4 ++--
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index 451c1dff0e87..c5ca1a1fc4f5 100644
--- a/include/linux/highmem.h
+++ b/include/linux/highmem.h
@@ -335,8 +335,8 @@ static inline void copy_highpage(struct page *to, struct page *from)
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
@@ -352,7 +352,7 @@ static inline int copy_mc_user_highpage(struct page *to, struct page *from,
 	kunmap_local(vto);
 	kunmap_local(vfrom);
 
-	return ret;
+	return ret ? -EFAULT : 0;
 }
 
 static inline int copy_mc_highpage(struct page *to, struct page *from)
@@ -368,7 +368,7 @@ static inline int copy_mc_highpage(struct page *to, struct page *from)
 	kunmap_local(vto);
 	kunmap_local(vfrom);
 
-	return ret;
+	return ret ? -EFAULT : 0;
 }
 #else
 static inline int copy_mc_user_highpage(struct page *to, struct page *from,
diff --git a/mm/khugepaged.c b/mm/khugepaged.c
index 2b219acb528e..ba6743a54c86 100644
--- a/mm/khugepaged.c
+++ b/mm/khugepaged.c
@@ -797,7 +797,7 @@ static int __collapse_huge_page_copy(pte_t *pte,
 			continue;
 		}
 		src_page = pte_page(pteval);
-		if (copy_mc_user_highpage(page, src_page, _address, vma) > 0) {
+		if (copy_mc_user_highpage(page, src_page, _address, vma)) {
 			result = SCAN_COPY_MC;
 			break;
 		}
@@ -2053,7 +2053,7 @@ static int collapse_file(struct mm_struct *mm, unsigned long addr,
 			clear_highpage(hpage + (index % HPAGE_PMD_NR));
 			index++;
 		}
-		if (copy_mc_highpage(hpage + (page->index % HPAGE_PMD_NR), page) > 0) {
+		if (copy_mc_highpage(hpage + (page->index % HPAGE_PMD_NR), page)) {
 			result = SCAN_COPY_MC;
 			goto rollback;
 		}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240129134652.4004931-5-tongtiangen%40huawei.com.
