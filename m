Return-Path: <kasan-dev+bncBCMMDDFSWYCBBS4C5XCAMGQE347PHRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5112FB22863
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:27:41 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4af22e50c00sf133491681cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:27:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005260; cv=pass;
        d=google.com; s=arc-20240605;
        b=a9LyLNIXSbvMCEeDtVaCZcMMO84JWOHbQ4MJHGKjjaWq5kR6PCEbxudUH7qNdnzUNQ
         XTmdp0Qa0+fhqlIxzv4PhMnxIc0Fq03RLAn8K1I6w2uLXcGomqRu3L+r2uOfYTeK5kGi
         CMAk7WAuURujATeMP1u0Ne7Vq6LWwDPYQybfAhsT+f1Zo/yYdk/6zHpE+cUWwcZxNdN1
         PQkcTbAQ/3ERR+Y//onDss6fZuXS1WsGveL16/ChHkNlsQfoD3bTaqkA8RkVdIi7auwv
         UmvQvkyIspT0M1fd9DponkO5Q06qWtPuOfGbMMjwnsecSJLuwg01bZuXUC0b53cBVtk9
         mo/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aMBy5klf9YwmDpQ8u1axgfWWxiwrap2FvLv709UOlmM=;
        fh=og5iLzpQlIhRrpogZ4BKY16WWeidbNl3aBl+2Alg3XM=;
        b=bkk0zjemeg27NbKaz9JEpqIlcgEnQpPwFULajVMocJH9oD3/LJd4ocG0UftU8Pb7sG
         vGajYdFUxRSLd6UMFGadPOAV6g3/M94wWFtIVti1FEHs+iqsfP+ympBGCLMLX5hkvPyT
         eBbvy523W/XAGHwpi01EGaXxP4x7iyex+EP4ZRHz9kzdWqKkSXkdjTbipbmK5vAOid/m
         BUXui2HTR54b6gvRdKTKVcgxSNcxRlv5wbmxKYPca3M5pWcNs75wISbuvjmQC82CDZdt
         MwYXxeUXpHvE2nfp9nEhdjcH2TQfjwy2uCh7ZCZtL+G12S0JINUS5CpNKtBDaAtlXHec
         jqrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=L+LGP85a;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005260; x=1755610060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aMBy5klf9YwmDpQ8u1axgfWWxiwrap2FvLv709UOlmM=;
        b=i1tTP2VdyKFNr65KKJJ1TIGpR0my9yrqygq0Oj8Ui4uZDgvrF0Jz8WO/r6RskeI3DB
         IgQ3mCGz814hIYRAg8ZiDla7qSE3uCNUhIbpg9VjWvcZ1dxLKU6ohdOM+V9hLH4uNnm7
         kTi45P34u7mvTXQdZpXgcNC80i0+elCbKFi9+ZrQNv7VcV10C1bGhMnQmyNvoYwAnthT
         EA5Ma1LzZr1xijThqenFtAwqem7wIeirfKgkl2Vi7dbdeJY9/pwiSch7V/9pFIVUdsPA
         nX4P6rCRdiYX9pP3TfBL6rKHf/MVIbZHlbWTyBQqxoVFCvliLrIzHhvX28N59143UPad
         5dHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005260; x=1755610060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aMBy5klf9YwmDpQ8u1axgfWWxiwrap2FvLv709UOlmM=;
        b=rBnaObT2USLpMVVwiKHs5yMvJ+o9GuXMGgg4ZIqJrV7542uZ5MscR8id/oCvnak+aM
         oijkFkNs6I6Y3Iwh3EsWfxZbHgaS8m8mSKGelNytTB2oJmVCH/2HU6TN2CvqNJANbkui
         XadlKm2fRdB4PmIaznPHQXR2e5sR9XOnJ9QhUOc9gdW0nwiXvLMTTaSfnQcNJDM9U9Vu
         WkuRsKgxovrNe+Aa1wvE4Xio9vxHfM+yiK+Qmn3QOf0/tCd69yMifmvTbdboWQBwTZN5
         jk8h3EnpJAW8I6MKhJTN9+dMOnDLohvfiBQ9o00zmstc6CHK8O9wgevnhjBTHNPon+zS
         AYNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTw5PHRrfUcm6Ip0tavU9SjuBCK2kFkqsceAJbVzqpDMrLGogcOg2K3LoYL3scuBQzi2Z8/Q==@lfdr.de
X-Gm-Message-State: AOJu0YwB3nRDUGiSOXXb6kKkh8kTQRFnb1VOP0Vx+4IK9HClvPzi9XIv
	nHqv+qdbQsDBSs7IJgUZ7wIOHapTmjljLl+pHmDeViZFJmc5jRXXofhR
X-Google-Smtp-Source: AGHT+IEb3UONqDuh/zTmzAonpPJZtkdmSAjqzlKBuXHuWB4mOuiFSNiW6lV+RQHmZFAig0tCHtDeSw==
X-Received: by 2002:ac8:5a09:0:b0:4af:12b0:57aa with SMTP id d75a77b69052e-4b0aec6fcbfmr226946301cf.16.1755005259986;
        Tue, 12 Aug 2025 06:27:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc3MeDTytu1iC8oMzFf3/3n0X7IRF+yZBdPt9lxAcCl8w==
Received: by 2002:ac8:5808:0:b0:4b0:7b0a:5903 with SMTP id d75a77b69052e-4b0a06dda52ls94941911cf.2.-pod-prod-07-us;
 Tue, 12 Aug 2025 06:27:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJtXa65yRL9WIDSSCJDnuuIKnKBp93tuu6l5yp9jth+sAnSNg+F6iQm6ffLHS42dGNxewZ+e9xDCI=@googlegroups.com
X-Received: by 2002:a05:620a:4fb:b0:7e8:19d3:24d6 with SMTP id af79cd13be357-7e82c7257f5mr1712201285a.40.1755005259204;
        Tue, 12 Aug 2025 06:27:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005259; cv=none;
        d=google.com; s=arc-20240605;
        b=RvjtYRXL/PWhQf89sqr+Me9BkdBOK6og+39JEtXvMCw7P8+i7bdjeRTwMmA7IuDiEA
         NS9WMo+SludwMtcK8V5IVnAQuJS34B3w7tYg4+BQH7mxBgTPqYT/sEwHBkBALHDoc1XG
         diG0dpdkAY/kiCRI+hNOnsSCzyjhTHw6h+zYEzMDR4r58JMLfLeJed3cikdKrHmMCaqa
         v77jrqZZAPzv4J8xCWXYEJa6H0koBH16oebSNDP7MjHhXNI9UensHi/4lyEFyr5l0Wv5
         7IsVf0IryDfjIonfOePbvRCr/Oydr1Vw9FO36hy0TCbjHjQWsfsuh/ptkTuf9M4DCZwm
         bYHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/ZI4hLWymuooglNAw5L1xAkAf+4ihyWxsZNVV22uwkY=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=UkG6BbHwJdmHvvWvfaqPbxdpaidMJqxFxc+qmjeAlwns5CNOFxp0tssaBxLjeqyfCd
         7XQA5/bGF7Xy6ppgaFr8qaB5nK5UnckA1cwuvZeqCQSVGM/kMPpGHHUxSGsAg2BWv9Cd
         Ebn6gwJW5Aik91Gv0LthXXiSu5mYXLrd6qfxJBbuvl0+v7bza923Ben0lLxH7pY1h6cA
         W0FrocmqLLpSjeHIP+sJcqdpyWln+PPzHEU4IPgof4N8GHNDI/tg7EfueFJtsfPPjz7p
         zrzSgFKhUhFM+8GdC3QGdg6A3e7dCH3N34NemEG5BYcLvisN0wdQfmI13L54ZDi/RjNp
         /sSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=L+LGP85a;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e83d42f1ccsi2621285a.7.2025.08.12.06.27.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:27:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: fevSMf6ITKSK/b73YYZu5Q==
X-CSE-MsgGUID: WPRCpFSkT3KiPLuyPFFfqg==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903496"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903496"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:27:38 -0700
X-CSE-ConnectionGUID: 7sr1bGkITqqOrRUhUWybYQ==
X-CSE-MsgGUID: Oy2/bGKxRJGKw5AHGzSS+w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831445"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:27:16 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 07/18] mm: x86: Untag addresses in EXECMEM_ROX related pointer arithmetic
Date: Tue, 12 Aug 2025 15:23:43 +0200
Message-ID: <aa501a8133ee0f336dc9f905fdc3453d964109ed.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=L+LGP85a;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

ARCH_HAS_EXECMEM_ROX was re-enabled in x86 at Linux 6.14 release.
Related code has multiple spots where page virtual addresses end up used
as arguments in arithmetic operations. Combined with enabled tag-based
KASAN it can result in pointers that don't point where they should or
logical operations not giving expected results.

vm_reset_perms() calculates range's start and end addresses using min()
and max() functions. To do that it compares pointers but some are not
tagged - addr variable is, start and end variables aren't.

within() and within_range() can receive tagged addresses which get
compared to untagged start and end variables.

Reset tags in addresses used as function arguments in min(), max(),
within() and within_range().

execmem_cache_add() adds tagged pointers to a maple tree structure,
which then are incorrectly compared when walking the tree. That results
in different pointers being returned later and page permission violation
errors panicking the kernel.

Reset tag of the address range inserted into the maple tree inside
execmem_cache_add().

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add patch to the series.

 arch/x86/mm/pat/set_memory.c | 1 +
 mm/execmem.c                 | 4 +++-
 mm/vmalloc.c                 | 4 ++--
 3 files changed, 6 insertions(+), 3 deletions(-)

diff --git a/arch/x86/mm/pat/set_memory.c b/arch/x86/mm/pat/set_memory.c
index 8834c76f91c9..1f14a1297db0 100644
--- a/arch/x86/mm/pat/set_memory.c
+++ b/arch/x86/mm/pat/set_memory.c
@@ -222,6 +222,7 @@ static inline void cpa_inc_lp_preserved(int level) { }
 static inline int
 within(unsigned long addr, unsigned long start, unsigned long end)
 {
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
 	return addr >= start && addr < end;
 }
 
diff --git a/mm/execmem.c b/mm/execmem.c
index 0822305413ec..743fa4a8c069 100644
--- a/mm/execmem.c
+++ b/mm/execmem.c
@@ -191,6 +191,8 @@ static int execmem_cache_add_locked(void *ptr, size_t size, gfp_t gfp_mask)
 	unsigned long lower, upper;
 	void *area = NULL;
 
+	addr = arch_kasan_reset_tag(addr);
+
 	lower = addr;
 	upper = addr + size - 1;
 
@@ -216,7 +218,7 @@ static int execmem_cache_add(void *ptr, size_t size, gfp_t gfp_mask)
 static bool within_range(struct execmem_range *range, struct ma_state *mas,
 			 size_t size)
 {
-	unsigned long addr = mas->index;
+	unsigned long addr = arch_kasan_reset_tag(mas->index);
 
 	if (addr >= range->start && addr + size < range->end)
 		return true;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 6dbcdceecae1..83d666e4837a 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3328,8 +3328,8 @@ static void vm_reset_perms(struct vm_struct *area)
 			unsigned long page_size;
 
 			page_size = PAGE_SIZE << page_order;
-			start = min(addr, start);
-			end = max(addr + page_size, end);
+			start = min((unsigned long)arch_kasan_reset_tag(addr), start);
+			end = max((unsigned long)arch_kasan_reset_tag(addr) + page_size, end);
 			flush_dmap = 1;
 		}
 	}
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aa501a8133ee0f336dc9f905fdc3453d964109ed.1755004923.git.maciej.wieczor-retman%40intel.com.
