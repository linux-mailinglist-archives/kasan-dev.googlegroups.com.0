Return-Path: <kasan-dev+bncBDQ27FVWWUFRBDMGT7WQKGQEYKJRFCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id D10CCDA313
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 03:25:34 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id m20sf568900pgv.6
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 18:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571275533; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICiSawW4GI8r7xfU1uP5sqyr9QnkMLzHKYstoS0B5afQTQaxbdIboYi5xQXTLu0lzK
         nXgpRfJkW3DXKDujfEcMnRpZdnwL5nyTgAaDH53EiESEOIjPBteMaIupEc4HMa8C/Yms
         SQ1cLEBpb8q3zkVpCQtYbJhdM/hpPmRXtFRUWkb5L07tVm+laVh1eEpanNGaiNpnv/a5
         TNGrPPN/wQiZtQhdOZD80YuiFH8Cm5tGmZs+lJ5f8kLlDoEk4OwPWTO/MOVDK+UpWgob
         FqveYru0jKbV5aP4wUq9M8rWVhS2qv+FITqN4wYf/Io9mR+P/0ImTJZGUZ3nW/rDW8uD
         epwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wkY0/MdvHV+q/SLpNGJ7hRU/vlCeeUvuhKdAI1OKJGQ=;
        b=ktYKfJoAQUAXiWvSgKeh0arnXndQXrI3hC/HScZX4JojOAv8ZIMeJo8u5bmOicZ9ND
         mqvxBlcHpvGc4eFP2t2QkKxxSi7h2QW09s92h4wwJnV/sKUifTv1uOAKG+a2Hp+TLe5w
         WU9dr6Rcs4VdEhXptYWB9NsGeZFLRy9P/+W30IIcpmddYIGFdqPMySr0h2qYV1c624GK
         yJkoSbwk9UV7bEuVf13ODz8P4kMhLxe164VdJhKGyJfGTESkLRZn/h+2wNkaMLagndJB
         I/QCd6jIrTdkugFyZxSoc36qR/YvQ5NjczMxb7m+9Vz/if51HbR7U/SPDyn7ZgBZWZ95
         bQcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=EK4oU0BZ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wkY0/MdvHV+q/SLpNGJ7hRU/vlCeeUvuhKdAI1OKJGQ=;
        b=TvD76Nch8AOopXC7aguWpBy4qVxtRp562ySjZrMI4jBkc1HVKKDEgBIFNFMySoCz3c
         7XAXiLsCP15K3DVyc7TgNAlDbI1XVdw1EGGp35JeU4dJG/fncDUwpRHwj1kM2h17odpR
         a77hzpz7lRBy1P6lLWSsAZqvXoMvjDvi+OHDWIlh7iK2FIwb+cEbAHVv4fKYgUR+J9Ig
         YN35kQ9D9D+tV2KzVxk4/u2gLXC30q8z+CQBLV6JlJv9rfCIP/SRvBhB5gceBYp4X8ir
         bKa3t3LAnZIJMri3iLPCWzzpbKXy/1YclbHp3fiV9LFWIoeVyTwloZquzAgwndMfEyvB
         Vpag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wkY0/MdvHV+q/SLpNGJ7hRU/vlCeeUvuhKdAI1OKJGQ=;
        b=QZntUCapS+t1RhjLOpM9PAE3+X4apAAr0uxBS97qeUtH3w5RtaCl/q2c7XfHb0UQOo
         rJRi4OERd8Y00NpLbI4o4NNp057Y1H7FkhdRWc0F+G1QAsZ+j/HvvtJRrxAaIw6N86yK
         snMD6MGrg/x1Bgc3DpxyC6OmZ6RCQ/OyBxmm9vXMzGkxOAG4+qae4mx36k094is973Sj
         S4hjP0SUpaUTj+owglIXxXKZfaqcCKbMSTq54TnreNEj5qt2n6q9d1ZEDI11CgUYqI1h
         UOqyo16KpSXHSsthzQud9tl8qpI1g5m6Z0ag90Ju1gcieJ5QhihcVJK4830yNAIyZVhO
         F0VA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXO91RcmHw5zqQNwzPrn4lkTymEQvIjv+V23wqC9kLQJ8yUrbdy
	+VrjHONbLgZsQSOf0mQtm8g=
X-Google-Smtp-Source: APXvYqy29DPlE7v0hyo3aso2wPtOZX69cfGLuUwYnlPVDHqc/PEi7N/b8wPj4X0XhZ6Tob4Ksj0hMg==
X-Received: by 2002:a63:155e:: with SMTP id 30mr1265960pgv.204.1571275533372;
        Wed, 16 Oct 2019 18:25:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6307:: with SMTP id x7ls164560pfb.0.gmail; Wed, 16 Oct
 2019 18:25:33 -0700 (PDT)
X-Received: by 2002:aa7:821a:: with SMTP id k26mr769510pfi.184.1571275533023;
        Wed, 16 Oct 2019 18:25:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571275533; cv=none;
        d=google.com; s=arc-20160816;
        b=VuN5ZUSzYnp85krN55Rchsa/S2B2DJHOaxBDomuNOApECWv0L9HtBLXAv9H3uc5IVO
         hsiR4bgpG6KVL+lp4So33uWir8C+MyJr0UVwrkgf3INRLniDv4HkSnZPpb7WPMh0IPPa
         vN3bdoh99vV66M3uvQUNtlorSmJVRkUmxHkn+dBSb2Jzbyzsq+itpmHBiSVIgNb6/PX2
         9N96d6gSdxfrufhrrNilxqj4CN2MH0/6dZY8b/kDLvWdpxgqSirUryOrDvLbCiGXz9w+
         FXRQvww0eQzcce7HsY1OavVetPEHNGOkZWYoSut96N985xYgDgNcKZ2e/xSzVQZaDPuK
         3qWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=isMm51VtK/oRU6lGsD9w6jqnjg5iuBGo4uf1ljxv9U4=;
        b=y9SBGyzl9tmz93akxTiuFdjwUwdgyY3l5AsZLMAdKDFbL41sirlAeuQsmvKWdBuD4S
         CkNydtkhZvUvbLjVIeJXYF8rlcv//f+Mhc3a9DEQYmgWWxNZqX/jOxKl42myOqnKDe8y
         DkpMg9e6jQoAPOsBakxJtCgq6VoejtXW+LVGhr37ONc8ymL2km+tNgVypK0EAwnAJ1nh
         HdzT6cnQvKILYb93Q+FrcCNw/QZ77asBWdC29/Dkr9ZkECqdrklpd7FbS5i7hQvuPwEm
         gWg7RuySkZPyf9gyCTA6pCmcO40CxWCDcfnWEd17qryQ2KQPjp402+0aZUEsZZKh46aw
         KUpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=EK4oU0BZ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id x13si21507pll.1.2019.10.16.18.25.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 18:25:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id f14so292058pgi.9
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 18:25:33 -0700 (PDT)
X-Received: by 2002:a63:d916:: with SMTP id r22mr1243029pgg.46.1571275532214;
        Wed, 16 Oct 2019 18:25:32 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id f89sm391422pje.20.2019.10.16.18.25.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2019 18:25:31 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 4/5] x86/kasan: support KASAN_VMALLOC
Date: Thu, 17 Oct 2019 12:25:05 +1100
Message-Id: <20191017012506.28503-5-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191017012506.28503-1-dja@axtens.net>
References: <20191017012506.28503-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=EK4oU0BZ;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

In the case where KASAN directly allocates memory to back vmalloc
space, don't map the early shadow page over it.

We prepopulate pgds/p4ds for the range that would otherwise be empty.
This is required to get it synced to hardware on boot, allowing the
lower levels of the page tables to be filled dynamically.

Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---
v5: fix some checkpatch CHECK warnings. There are some that remain
    around lines ending with '(': I have not changed these because
    it's consistent with the rest of the file and it's not easy to
    see how to fix it without creating an overlong line or lots of
    temporary variables.

v2: move from faulting in shadow pgds to prepopulating
---
 arch/x86/Kconfig            |  1 +
 arch/x86/mm/kasan_init_64.c | 60 +++++++++++++++++++++++++++++++++++++
 2 files changed, 61 insertions(+)

diff --git arch/x86/Kconfig arch/x86/Kconfig
index abe822d52167..92f5d5d5c78a 100644
--- arch/x86/Kconfig
+++ arch/x86/Kconfig
@@ -135,6 +135,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
+	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git arch/x86/mm/kasan_init_64.c arch/x86/mm/kasan_init_64.c
index 296da58f3013..8f00f462709e 100644
--- arch/x86/mm/kasan_init_64.c
+++ arch/x86/mm/kasan_init_64.c
@@ -245,6 +245,51 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
 	} while (pgd++, addr = next, addr != end);
 }
 
+static void __init kasan_shallow_populate_p4ds(pgd_t *pgd,
+					       unsigned long addr,
+					       unsigned long end,
+					       int nid)
+{
+	p4d_t *p4d;
+	unsigned long next;
+	void *p;
+
+	p4d = p4d_offset(pgd, addr);
+	do {
+		next = p4d_addr_end(addr, end);
+
+		if (p4d_none(*p4d)) {
+			p = early_alloc(PAGE_SIZE, nid, true);
+			p4d_populate(&init_mm, p4d, p);
+		}
+	} while (p4d++, addr = next, addr != end);
+}
+
+static void __init kasan_shallow_populate_pgds(void *start, void *end)
+{
+	unsigned long addr, next;
+	pgd_t *pgd;
+	void *p;
+	int nid = early_pfn_to_nid((unsigned long)start);
+
+	addr = (unsigned long)start;
+	pgd = pgd_offset_k(addr);
+	do {
+		next = pgd_addr_end(addr, (unsigned long)end);
+
+		if (pgd_none(*pgd)) {
+			p = early_alloc(PAGE_SIZE, nid, true);
+			pgd_populate(&init_mm, pgd, p);
+		}
+
+		/*
+		 * we need to populate p4ds to be synced when running in
+		 * four level mode - see sync_global_pgds_l4()
+		 */
+		kasan_shallow_populate_p4ds(pgd, addr, next, nid);
+	} while (pgd++, addr = next, addr != (unsigned long)end);
+}
+
 #ifdef CONFIG_KASAN_INLINE
 static int kasan_die_handler(struct notifier_block *self,
 			     unsigned long val,
@@ -352,9 +397,24 @@ void __init kasan_init(void)
 	shadow_cpu_entry_end = (void *)round_up(
 			(unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
 
+	/*
+	 * If we're in full vmalloc mode, don't back vmalloc space with early
+	 * shadow pages. Instead, prepopulate pgds/p4ds so they are synced to
+	 * the global table and we can populate the lower levels on demand.
+	 */
+#ifdef CONFIG_KASAN_VMALLOC
+	kasan_shallow_populate_pgds(
+		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
+		kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_populate_early_shadow(
+		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
+		shadow_cpu_entry_begin);
+#else
 	kasan_populate_early_shadow(
 		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
 		shadow_cpu_entry_begin);
+#endif
 
 	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
 			      (unsigned long)shadow_cpu_entry_end, 0);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017012506.28503-5-dja%40axtens.net.
