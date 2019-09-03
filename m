Return-Path: <kasan-dev+bncBDQ27FVWWUFRBAX6XHVQKGQELWT3PSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id ECB6DA6BF7
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 16:56:03 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id g76sf10695592otg.14
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 07:56:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567522562; cv=pass;
        d=google.com; s=arc-20160816;
        b=xAceis1YvV7nDMk/NXFt+5CCifnoRtcBkeMYckJdPGxVQI8YOSDf36GM7kUhwHhmZa
         ZEp1rwOSRTL8gEI3ogccgjBSPt1oVRKL5MB9lo13qvLt+NAVWNSWBDyPlMF5R4wgRVI5
         ZYfw81ZVGzSGrhF88AQJTXcwQaU6J/Tx1/0plxVit9mDoAGcB4FBKGTkRSMOO0Ww2m4x
         tPzhODFC0h2FbeUSSFmfyB3X0lmk6WTaSbJELPwl9m0ohUi22uFrhcDwwfMMU4IcjxTB
         PCq5sA3lURmEtBfx9Jdf51YN+pKCBu1Vn1mveniLCV6ZFVW/qBKmFNPojSo7283aeLVy
         ouRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DTtQUxrsHx/ccwGWZ88OSyLrpJ+912GaYngkT+1mf7M=;
        b=EQS3ap9Xh2OqEq9cfKPtsZgImAQyjA8O8RyRBarNXEosJNvgctONZ8YCrK4TFuR/sp
         fVntd89sQG0K5KLGu/i5oB+19+6/S+2qNDTN0tPSqn1TcH35eO6jCgfPmz9tlW7Uk0wB
         f5ouAHP45g+4K95NpELFoy12MifA2rFRrG54wFF0uZIdUmYeDbEWxIpHRNQrS0Ucbrfi
         UK2UXEEKWLngT+OPMw32igk6ThCUVt4g3ZzsWx+ASg+R/zvAta7Z28XYtq+Ug7G3f0iB
         dUxoly5E2+kwyVHEEDWezBot+OKdOQsTbkkH2nGCpjaone1i2ZVOjHK1u64pykmDPv9u
         mPpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TGcPmos1;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DTtQUxrsHx/ccwGWZ88OSyLrpJ+912GaYngkT+1mf7M=;
        b=GCp4pfNrsKVXdr1+A5/DKdc3uXhjs+IOB1MgGtw6pa8gehvnR+6mirDRWD9mpJFx+j
         VjeNcToxkCBEy7t+q8KClO4W0nznVRjcpl4tLwGjymlTvGqsUDWEVDu+AR5zXwyOQbx2
         LIcUuNgDZcSQZ6Jgo09S4l7NpTC1qRLaFvW5EXSvJV7uYHit7shif97aeuIEYuCzitsm
         gsk2p0MsAtMnnNXhnz4kLjgPH3rsvu5naSCAhTuD9S0vH0CGW+uHwGEtPevwekvyH0Fm
         odq8v9yXNlNvEDrHPInIEDYnQ5mnAMSdTnSxUL/4By3BpsW6xiCCgZ8cnTzrc4CuwXrw
         oMJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DTtQUxrsHx/ccwGWZ88OSyLrpJ+912GaYngkT+1mf7M=;
        b=NszjwIxlTzs22/0umpeYvIeiac7QYSZICkgtszqhQaFsGpdanFBX7Fi9BnKxWk42Ij
         4oQPSq7P6JOH12qesYIDyTrDg/cgV5K9BAmOJr90MQDHrKC/xMiQChd6DwMr5UquSAYt
         jN3DcH/we0k9B5NWujQoiI6eBDc/pgvA8bEFPAT9fb+yrKmieTDkLmq3K7trttu20Siy
         UUcLtZz2RRHESQec09wptGB1XnRr9oBd6SzWzQXUWg11pya3t5dRxlEcwRsJ2SUWhrfi
         ooQW+Ea5quapmYwvKVwzyxEb2ZunuOYOtlcgFBqRGPCOl4obsablh1hTtBgD/4l3AHxh
         mq/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVuEeh0opGg/VSnhu9Aafxf0JCRDdMcxzXNeQ11tCE1zO6qhLyQ
	1ynReCsnngSVfrJUBV+mNoE=
X-Google-Smtp-Source: APXvYqxF65dOF92FLmWtj/QVCRTUcMLp973jgCLotHEoW9iT3CDrAZz9h3x0TlWpQjH4KAkzlt7hxw==
X-Received: by 2002:a9d:3f26:: with SMTP id m35mr5902633otc.66.1567522562835;
        Tue, 03 Sep 2019 07:56:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4395:: with SMTP id u21ls99859oiv.6.gmail; Tue, 03 Sep
 2019 07:56:02 -0700 (PDT)
X-Received: by 2002:aca:3a87:: with SMTP id h129mr354395oia.4.1567522562446;
        Tue, 03 Sep 2019 07:56:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567522562; cv=none;
        d=google.com; s=arc-20160816;
        b=HLLsHaEoMNqHSCQuM1ZECMJG+19H7eHEpTpx88aEtA7LTQuTmBG/nNA2yquCn3Fg30
         ADO0sB+hq3Dn6b7O4Y8EFLYfXDYQjgAch+hW/kCDkw4twnrl4VRrOjQpzAT/oEb5I78U
         SYjIc4IBvP8m3ZfcjtD5/jNdA97Bdi+Wow4gw+KddYw5YuS9lFHklUfVgECo7XKEcql1
         7OTHTFlXNuogbUbEd9MTO5qEHWHeEv1prbFrYSXXG2hUG3iRbHzAjST4vAzRShGKPA8r
         Wn4ENVj7MiaG9/RMY+SY/OVrYUNwV7cBgBqeHxpHJfTAvGjUZJDUxxwXWGlUYQORK9s0
         5PIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/Pi33Ab5H1THuUOlmFKCqF9xJSMT6s+LImLmp8toPnA=;
        b=eKiku13UMjtqtQsGqRjVi5HJNFelfWQ9V2aJkDSpnAFihY2PsdNHQjDMANAha/oFUe
         AP4eE3Mr5mUVamY/rQoFWI8o5iE3yxOJxrFDjZxmDvl+6DvBPcsr83StF3xOraLQNHeq
         Hma04YdZ+ezoFeLpyKVnFgrxNcPotF36C6KFcJhlCGEYQQ3azDXxwBrw62WE45T3O7RB
         n7l32MQY0UGZ0HbGn7NRimUIrJNeyGF9Rlzr+zfJPtR6CBnFcXbINqV6NgAMrzTBHlZf
         tKW/Qjovs9eoEQ7UmRQJA1NAA+ubeIUe+TgC7I7Pr9/0bqWkEPQdG7TudOwmu/4pllRO
         jXQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TGcPmos1;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id k184si455398oih.0.2019.09.03.07.56.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 07:56:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id d10so4728173pgo.5
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 07:56:02 -0700 (PDT)
X-Received: by 2002:a62:8749:: with SMTP id i70mr8363618pfe.12.1567522561420;
        Tue, 03 Sep 2019 07:56:01 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id h12sm18490529pgr.8.2019.09.03.07.55.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2019 07:56:00 -0700 (PDT)
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
Subject: [PATCH v7 4/5] x86/kasan: support KASAN_VMALLOC
Date: Wed,  4 Sep 2019 00:55:35 +1000
Message-Id: <20190903145536.3390-5-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190903145536.3390-1-dja@axtens.net>
References: <20190903145536.3390-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=TGcPmos1;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
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

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 2502f7f60c9c..300b4766ccfa 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -134,6 +134,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
+	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..8f00f462709e 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190903145536.3390-5-dja%40axtens.net.
