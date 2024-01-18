Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVEJUSWQMGQEPSJ7CVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E2358317BD
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 12:00:37 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2ccb760be5fsf3086131fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 03:00:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705575637; cv=pass;
        d=google.com; s=arc-20160816;
        b=PMMCTAIXyNPYZWhVA6QjQZqUZWSzcppdzbdor6U/zfZ6XlsqaNfPWE0b8J9Id+oAOa
         mOrYVN+rfuSkMjM7doO7q2cSi9Z3HPylXkH141E+0guL18V99LQWkYS1nFhQ4IpRXu1L
         VwHEAH+h8OTUwokCCsYIKUBKJ1AD0FYhnvH9TtJy1zMLdrghPwp4/XUJRHS+ekud9aUA
         Udix7ye1NGtAMNnhWoDO7pvV9H2iMxBFFtGrKi5H0/Es5yhAqXBWDp6PBziv7B8PChUH
         4ug1DtF7byn9/85z2IJRwzkNCMr1Pu1LIlL939xD73sx/SLqZP5jO1o9yiTPrKJiHVCw
         juYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=rroyMhbK/afdC3lun5UZRQK5HxquMVl9xl53+YZYfAU=;
        fh=RaGrguQm3JlAt/eMY4kDgJK9TlEP9rqRFFn6H9cF4a4=;
        b=0k+ySr1R3H1pzgsX/uhbCsfoNaoBd5UJk3rlf+V2RSrvg7FG3p7NJONRqR0HxAQupi
         wdmXkM9Ms+dHB0yinoqCip8u+82X/Tv+J0YI/rxHQnbaMF7ft6CpDw4VNDl5/AvE3sj1
         FPG9gvBoei25DJCCKcMFqLwryIw2aEAGYN3YjOOF4QA7Hp4q/1yjJ05dVDE3VbCkS6fx
         Tbb4ks03aj7r7YKevNqApEDCiBixdyHHApp4kmrrtWV3IPCv/qVziY2S8fRYC2+REuBX
         H8ax1iANHEZW5Jg2UuL0xOhjdK/MFj9iWC+JI9isNgd8JK7/eJXaQ3VWlpoP099FAJ9n
         qPRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jb0jFnRI;
       spf=pass (google.com: domain of 30qspzqukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30QSpZQUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705575637; x=1706180437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rroyMhbK/afdC3lun5UZRQK5HxquMVl9xl53+YZYfAU=;
        b=AEvjXFjGHD8OKKOFspDUy8iO1Wut/PeKESZnwYjCnm9PMG1tq+Rxp4pcAPFwsjFI5p
         G4dEGRGWRnfRKmCHlM1yukjpx9uCeuARtVu6tMmRCd9n9tdfup+qf9A8BLNmPnW5LmE8
         rtV/XlfAEdebhgzzz4o5T7e4+sU5yHolA/vYbSbP/Q2DYEMI7n67osDvb1MiOSwDepyu
         r9JF3jq38yDN83pYIDhlvbQ8z6489lP0p0GgcrcaU8kOdCm6xBmfKT41FzpBsqpK2aBk
         +90m4ZxKSI2rx8wEYKwjCX2yOTMSdUyU3cGSIDJDoxBUvZDtTWC6eiWxBdCUFYQnIR18
         Y/uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705575637; x=1706180437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rroyMhbK/afdC3lun5UZRQK5HxquMVl9xl53+YZYfAU=;
        b=lzf9WaQ59uhbso+b8NPxOdSHnfujlJzmABqW01knV4JMGinim2Yw7MHOVa8hYSRgdG
         nVNHYGakpzgWazmPgXrfAFufhahDQkYf7k/CoBg6YydbRNsChVbFicDsuE6ukb6yNbxr
         XGnh3sgO9eoD6grvwk3Z/C3dmesGhaCU5UAGTcSMbLNT8O5w35K7FAN3Fu1ajCJFAxA1
         Oxi6EZWQ7bzNyhJOfbb0iDvVOYvQ3ltPl+sYwyxKhU8ZvREy9I+tUWYqmLz6QeChf1Dg
         Dy1CcdPJtaCh8thg43UfsKxXf0rL/2B4me0989m18zRx2lhJmBkM0GNfbTFG5HHmprlg
         Ihfg==
X-Gm-Message-State: AOJu0YzADuDVx9LgnN820u+he70kdECxApIx+I/Ecf0oWYQbzY66opZE
	PqjMBBjxhvUFoIuQML38lcK29ZTmKKIQu/HVCCyORna6kb2VVO/H
X-Google-Smtp-Source: AGHT+IG8xcDyuCSArwXdE4IdnvtqfkywAepQvH3cl09C3nQCkTKTezLOJrlDncLsuiEpqHIZEbzzJg==
X-Received: by 2002:a05:6512:2c91:b0:50e:d9c5:199d with SMTP id dw17-20020a0565122c9100b0050ed9c5199dmr534887lfb.26.1705575636655;
        Thu, 18 Jan 2024 03:00:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2803:b0:50e:7281:9f03 with SMTP id
 cf3-20020a056512280300b0050e72819f03ls1570058lfb.1.-pod-prod-00-eu; Thu, 18
 Jan 2024 03:00:34 -0800 (PST)
X-Received: by 2002:a2e:be26:0:b0:2cd:8ee4:50b6 with SMTP id z38-20020a2ebe26000000b002cd8ee450b6mr603024ljq.3.1705575634272;
        Thu, 18 Jan 2024 03:00:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705575634; cv=none;
        d=google.com; s=arc-20160816;
        b=MKstqIjRIA1ETbZp+W7YE3z5z4S0FODhEkYPMiU7XCiIiRScfrlvkWjOk7qjZSZZGD
         9ow+wxCkkdMkIZt7bDOPcBX2nudWnPbX3/Av0YVRlwrrtTBzsMnz44fO9/GW5Ve1D/Bz
         0ZUbDL/sheJFnjum0+/Fsuji5iCdZABPJ9/yFjs2DSpIBDKbcXhHmTesfURsHUH3GNcU
         IC1OU0E542FV/i8QLREtjzGisqbi4wvb2xE/aAGAh3Yg0+bwuzFl30umW/36m5T7Oial
         b+dxuxsvuZ0kNNBbr7UOBSZFzUn+kcB1l28WilnwlIX4iX57VvYzgrKzYiROFKamGgGJ
         /ccw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=6RrXGrowsStE9nemPJC0cN0IXJkwkJ+pwI0mRPXiexU=;
        fh=RaGrguQm3JlAt/eMY4kDgJK9TlEP9rqRFFn6H9cF4a4=;
        b=F0gL/KmcBYJ8NuTcf2I8pnmAWfrweiooAZwJ1458UMopb0Iu9NwV32Drqrhdfy5RCM
         jfZYkpNT5a2p3DdNg0jufvpkDv1TLM0DYWm3uhM8IJP4uIxTG76U4wN5os9o+pSPEvGF
         zL4LwWnnKlIpTaP4lQdb3i3prOt49HAo+TRCujR3+C7BVpjRSYzNuLJgPuYby9JqIGEe
         KPT+GrJUE0GBIQyb0RqfaNOdavR7RxtvLcqxluKgr7fZy8/7wexESxv33lF8srdZZ41m
         ++vf4ptOjfTcPe9CwnjFKEIBKIXu+IeV0RDx3b3vBE4AuXd5ER/QR/sRbVRj7b5SKDOH
         SHzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jb0jFnRI;
       spf=pass (google.com: domain of 30qspzqukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30QSpZQUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id s6-20020a2e98c6000000b002cdf8e1bd8csi32381ljj.1.2024.01.18.03.00.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 03:00:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 30qspzqukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-a2ed378d9f9so66711866b.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 03:00:34 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:9d7e:25fb:9605:2bef])
 (user=elver job=sendgmr) by 2002:a17:907:788f:b0:a2d:51d4:9ddc with SMTP id
 ku15-20020a170907788f00b00a2d51d49ddcmr1361ejc.14.1705575633222; Thu, 18 Jan
 2024 03:00:33 -0800 (PST)
Date: Thu, 18 Jan 2024 11:59:14 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.381.gb435a96ce8-goog
Message-ID: <20240118110022.2538350-1-elver@google.com>
Subject: [PATCH] mm, kmsan: fix infinite recursion due to RCU critical section
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com, 
	Charan Teja Kalla <quic_charante@quicinc.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jb0jFnRI;       spf=pass
 (google.com: domain of 30qspzqukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30QSpZQUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Alexander Potapenko writes in [1]: "For every memory access in the code
instrumented by KMSAN we call kmsan_get_metadata() to obtain the
metadata for the memory being accessed. For virtual memory the metadata
pointers are stored in the corresponding `struct page`, therefore we
need to call virt_to_page() to get them.

According to the comment in arch/x86/include/asm/page.h,
virt_to_page(kaddr) returns a valid pointer iff virt_addr_valid(kaddr)
is true, so KMSAN needs to call virt_addr_valid() as well.

To avoid recursion, kmsan_get_metadata() must not call instrumented
code, therefore ./arch/x86/include/asm/kmsan.h forks parts of
arch/x86/mm/physaddr.c to check whether a virtual address is valid or
not.

But the introduction of rcu_read_lock() to pfn_valid() added
instrumented RCU API calls to virt_to_page_or_null(), which is called by
kmsan_get_metadata(), so there is an infinite recursion now.  I do not
think it is correct to stop that recursion by doing
kmsan_enter_runtime()/kmsan_exit_runtime() in kmsan_get_metadata(): that
would prevent instrumented functions called from within the runtime from
tracking the shadow values, which might introduce false positives."

Fix the issue by switching pfn_valid() to the _sched() variant of
rcu_read_lock/unlock(), which does not require calling into RCU. Given
the critical section in pfn_valid() is very small, this is a reasonable
trade-off (with preemptible RCU).

KMSAN further needs to be careful to suppress calls into the scheduler,
which would be another source of recursion. This can be done by wrapping
the call to pfn_valid() into preempt_disable/enable_no_resched(). The
downside is that this sacrifices breaking scheduling guarantees;
however, a kernel compiled with KMSAN has already given up any
performance guarantees due to being heavily instrumented.

Note, KMSAN code already disables tracing via Makefile, and since
mmzone.h is included, it is not necessary to use the notrace variant,
which is generally preferred in all other cases.

Link: https://lkml.kernel.org/r/20240115184430.2710652-1-glider@google.com [1]
Reported-by: Alexander Potapenko <glider@google.com>
Reported-by: syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
Cc: Charan Teja Kalla <quic_charante@quicinc.com>
---
 arch/x86/include/asm/kmsan.h | 17 ++++++++++++++++-
 include/linux/mmzone.h       |  6 +++---
 2 files changed, 19 insertions(+), 4 deletions(-)

diff --git a/arch/x86/include/asm/kmsan.h b/arch/x86/include/asm/kmsan.h
index 8fa6ac0e2d76..d91b37f5b4bb 100644
--- a/arch/x86/include/asm/kmsan.h
+++ b/arch/x86/include/asm/kmsan.h
@@ -64,6 +64,7 @@ static inline bool kmsan_virt_addr_valid(void *addr)
 {
 	unsigned long x = (unsigned long)addr;
 	unsigned long y = x - __START_KERNEL_map;
+	bool ret;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
 	if (unlikely(x > y)) {
@@ -79,7 +80,21 @@ static inline bool kmsan_virt_addr_valid(void *addr)
 			return false;
 	}
 
-	return pfn_valid(x >> PAGE_SHIFT);
+	/*
+	 * pfn_valid() relies on RCU, and may call into the scheduler on exiting
+	 * the critical section. However, this would result in recursion with
+	 * KMSAN. Therefore, disable preemption here, and re-enable preemption
+	 * below while suppressing reschedules to avoid recursion.
+	 *
+	 * Note, this sacrifices occasionally breaking scheduling guarantees.
+	 * Although, a kernel compiled with KMSAN has already given up on any
+	 * performance guarantees due to being heavily instrumented.
+	 */
+	preempt_disable();
+	ret = pfn_valid(x >> PAGE_SHIFT);
+	preempt_enable_no_resched();
+
+	return ret;
 }
 
 #endif /* !MODULE */
diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index 4ed33b127821..a497f189d988 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -2013,9 +2013,9 @@ static inline int pfn_valid(unsigned long pfn)
 	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
 		return 0;
 	ms = __pfn_to_section(pfn);
-	rcu_read_lock();
+	rcu_read_lock_sched();
 	if (!valid_section(ms)) {
-		rcu_read_unlock();
+		rcu_read_unlock_sched();
 		return 0;
 	}
 	/*
@@ -2023,7 +2023,7 @@ static inline int pfn_valid(unsigned long pfn)
 	 * the entire section-sized span.
 	 */
 	ret = early_section(ms) || pfn_section_valid(ms, pfn);
-	rcu_read_unlock();
+	rcu_read_unlock_sched();
 
 	return ret;
 }
-- 
2.43.0.381.gb435a96ce8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240118110022.2538350-1-elver%40google.com.
