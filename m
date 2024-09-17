Return-Path: <kasan-dev+bncBDGZVRMH6UCRBXXAUS3QMGQE5CMUT7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id B0C6B97AC17
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 09:31:44 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2da8c2eeecasf5253526a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 00:31:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726558303; cv=pass;
        d=google.com; s=arc-20240605;
        b=YUeog+73+ngdU7pBuUpNeKjrdRrND5GPrVaZW0qOsb5ABgVaSd39qe0wr05SVvFhpX
         fsM8j/cOgGZFR/iDfIlttI5tUwEcLI72q2qQRvjrtzGFHMfJrBXde1caao5cbScGvE/d
         xFN8t5jEo/Hl6zn5/HmWMGY4QOmjaGXUEQsy6E9D3J0Z++/wpyKeVLMoZ66SMjWtC07N
         ExeOGuTPvthYPlkelTrgtSVFk2BzOUhmCo8dqfUmfFNxy7r0/fZlkLrtDrn2Jv0fyKNn
         qLK60EWm7hYK/qXrbHX8E3ooTDI7fM5NelOaiznG/lSBlHmqINh2dOERq+9KibjAwaDT
         cGuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yWJtQvu7VvY2Zu0rb+xGjbleW+47/lKUjhJISEQJoL0=;
        fh=h6MiJHxqw7UC3dyqpVBhn3ddVTTzmETwEs1yimgCB3w=;
        b=Y+l7Xe7qdI92SvHq8Aj/4ywhhmW/ZWMUi+mw7+fYpGuUAROdrPuRUbtsMAlObrfPC9
         KjDGAKs5vmjpb3IWu7rTTakc0TyGtPct2rQ2UXAc4aBIx2/G9Rb4Z5KC62OgGPU5GKon
         QMTdB4Dk+fJ5828qeynJcLnX+iVrZoyHlAdnTXTLOE3BHnJhcVh4TbhCVXZFL7BVwkDu
         zEAdT8Xhi7CMQQMXUGcMg1SdZP0aZ4MqbKjiJ7hF9HDBmNtD4FlbjzD+niqVuqCdq02R
         MVoAjHn+D9glXFUz42FeLAIFS84PR6ibueR42Ql2jYBzM1OedtcHOQ8CKj5UrDtDtH2H
         iolw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726558303; x=1727163103; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yWJtQvu7VvY2Zu0rb+xGjbleW+47/lKUjhJISEQJoL0=;
        b=roLv+XHE1Jbbqj1+8MvrT/x9HEOe7o8hNQTGN321/7i/oXVfatitttjfle1BeEzhij
         yrrxGHui3XzEiFk7BvXkYyYnA1Ivl+rz9lRqGAcO8HBooIcgmprWHYSqBk2eaIgeZl8W
         4kOqaq85/YLZlg/SYFLhMF1l+coajJRGwiDZ6XrdT+rEWwY2y3HDGk5d9z/8lInLxTJw
         YnmtiAlPe6fVDVyohFics2HNXYJS//DRQSkixNMQfQKCV5uupdWQ5k83OxvxwDaK1LaY
         vJtP3sHsgFRVwLxHuZ1rOuawV/HBndhDlu73+c1JgSbrEXRZi+IIMKuHcdSVkBfjZ/0i
         pxmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726558303; x=1727163103;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yWJtQvu7VvY2Zu0rb+xGjbleW+47/lKUjhJISEQJoL0=;
        b=B/FvvU+n78Vm4qJPsXNO4n3rgPmW/cHriQsuV2OrZKtW3xU6PcaK19bv/1mCl+8avM
         U7dxZfZ/zSS0LFkZHpxyH4t/yU04qixnhEdwU3wDED3Alkh2JL9/+y6Uri8/PKysHzdK
         areYBCtS7ABaslKLq4rKteA9gdDtwimv42sQgsCgXCbVtTdaUAUfoRnpQKhxiicCOvAF
         CTOF8qHyEvF7+7oVG8bUsaFJglUPQl72YrOw0Cc1d5y9Fweoc/B9AXZrOWwGBMbZkP1T
         cS1/uUz0fPWCeAUp4m8X/v6GngOjF0+SjPZ41XUQZAro5rk+8g6m2nWGcTuiVAnq8YgX
         C2Wg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXuyN4N4tGvKITSvODsonWHNDtqL4BKhNdIoRMvJCeADHYlRlAnrWzDRMneb9ofpcg9gIj4VQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyvy8Q0/wI+19XGmdXLMrLemPmOLDgleMYnbMhkAdMJr5eMPvAP
	dhgVE5cZkhA4UP3H9Idq76PAWcxMhpNRTDOUbLj4pxEif6JLNOId
X-Google-Smtp-Source: AGHT+IGAO4Kyr5xk2sKvyfNv0AR+CO0zcOGKPG2l+Xrt9INOHdiAArJKQxDFy1S5Zlcvlz+1hjA+mg==
X-Received: by 2002:a17:90a:4b87:b0:2d8:f0b4:9acb with SMTP id 98e67ed59e1d1-2dbb9f08179mr18741584a91.34.1726558302843;
        Tue, 17 Sep 2024 00:31:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1f88:b0:2da:6346:d569 with SMTP id
 98e67ed59e1d1-2db9f63b81cls716784a91.1.-pod-prod-04-us; Tue, 17 Sep 2024
 00:31:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFVOh4ka4T4UC9+wpfmwSxrMay7wAWvIKLY8ui9b9fGspk4/Hi0OTBSjb7FluGAjpfuPt4Ucb42iA=@googlegroups.com
X-Received: by 2002:a17:90a:1648:b0:2d3:c9bb:9cd7 with SMTP id 98e67ed59e1d1-2dbb9f08b4amr20855003a91.36.1726558301436;
        Tue, 17 Sep 2024 00:31:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726558301; cv=none;
        d=google.com; s=arc-20240605;
        b=fCJuUAE4zMp42US3Wf+R+GRDIIkk5NXfuHPHz4mbEUEpY97OsoAl7A9uASw+9UCMn3
         GKmu9nTTFSyOssF/VKBtTarmewy46DwaVoFOhV730sIOjI4gKJIHPw7paoxftIVmVvfb
         dgK8RhbfzeEE2LhkHeliD71kaImKrdaOMOMKiET7hmRSsEZflIunKgO6K9lCWrpsgy7/
         IleAAfxATDsy3dEv/k1GmpktREp79JaUWsIn8jDb56gCMXutTg14gRoagiEePJU5orF6
         /w78vKQEgn7vogTMN7KTAOoSYsSpQEr8xORoI8u+d3KcJj+iGgZNCpZmajD4wlrGjBs/
         lzzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Kf+QKFudpY6BIdljIQcwJegJXtg0lo4RbS3FDlRfCHA=;
        fh=2Qg1lQCKbOaLhilWuULCpF79d+LAtLSDknwN1+HxWCU=;
        b=PJsUFjhweqfslUuCqcjRG5VSNWsA3pcgKZUlw3ClEToZf07dNXyMTJMQ9k4zGqeZre
         6uJMzkExkzkQBctCae+GmnQkr52wCGJo0cq7NJYnWbgfNkNpnMM4KZaCY0NZhbiWVqT/
         hNizYfzgS/k8PxmmTpn6QSm264T5vGAypbclXpuA3b/sPzfg42NWaaFYByASHmFS/+hd
         sbNnpQa9Vk/Oo/Eg9gTaJPeg4PJJnmBu2YJCQCd5Kv4L5hNWkTdj2OGeIPMRcVunw7Ve
         Ugii5SoYk0cIuOzQVVa9XTP3J4/SRn+2NH4QrVrmgq5xeKXpFioLCOxwGSz2dP8nfDU7
         jDfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2dd52e36330si38310a91.1.2024.09.17.00.31.41
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 00:31:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D43661063;
	Tue, 17 Sep 2024 00:32:09 -0700 (PDT)
Received: from a077893.arm.com (unknown [10.163.61.158])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id B83D53F64C;
	Tue, 17 Sep 2024 00:31:34 -0700 (PDT)
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
Subject: [PATCH V2 2/7] x86/mm: Drop page table entry address output from pxd_ERROR()
Date: Tue, 17 Sep 2024 13:01:12 +0530
Message-Id: <20240917073117.1531207-3-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240917073117.1531207-1-anshuman.khandual@arm.com>
References: <20240917073117.1531207-1-anshuman.khandual@arm.com>
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

The mentioned build error is caused with changed macros pxd_ERROR() ends up
doing &pxdp_get(pxd) which does not make sense and generates "error: lvalue
required as unary '&' operand" warning.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240917073117.1531207-3-anshuman.khandual%40arm.com.
