Return-Path: <kasan-dev+bncBDQ27FVWWUFRBVWX5LWQKGQESA32LUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id BD8D4EACA4
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 10:39:35 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id c72sf3937162ywb.13
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 02:39:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572514774; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4KsGUj+cFCXaLHgzkUIN9mwHH3wWV4TrPO0oZzJyeYxEJHML1DPVZ5OAFyqwXasFc
         XCDj8tkzdfOWD/SZw4d+i69pXDEhRY5fiZ86joIKytaP+5c8U4G9E0+wZFJv12/nqpI/
         aZOZlDbBvJNdC0ciEBFaA12P9zRtdZeB58sBjCLkOjzbsHAo4PEgdRCWPXJu1bZOpDdB
         l99snZsCGZHwrnrLfnL5lDolB09RG7bHDPMq1UoVYlBSyi9RqEddshMCe3Szc7GwapC4
         L6vEqeMRht/zU3l2eWob02bbD0mKKwwr8tk2md4Y+SYsWoHOtz5TiZglAxvzdIN28lbo
         ikXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Lh4aw+g0noV91+UGQF1LGRNkjOVMqSzyHLc6FCiOD8k=;
        b=zSoAzGeSIvZoPvG3Wya40Mdie9GFMykPyKmwUXCmigScCMCo2uyv8Ggths0rHhnMAG
         qeM8CiwnFzUo2xlesaERvone85B/7q1KuyIvKm3VKIovDBFDm/PcI9A0wWmBLtBlc218
         aqRPbwhvaogj4K7D+tfnajUrdQ2EKSjMjLm6/OcdK7lAVTO2VcwjBJJ8rSlMd9yf9RTO
         WhPLYgkpyZ/hbvIEd83Kk7FReXK+u1wUVJJ3As9Hntf01aiZ3pMYAes4IobPj+aXpj2e
         Ako/TaPxYN7/fJ1Bd+fOHYqihaNXcLYRJJlKjECFyIjp/wPi0iruoBCbQOLc7GQIjO/2
         rA0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=cNX69LQO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lh4aw+g0noV91+UGQF1LGRNkjOVMqSzyHLc6FCiOD8k=;
        b=qB1rLnJrJhIevATnQosPFVMySgBlPantuguuXHCdH4ZsMXVD9JKpxOyO2+MliEdk37
         1LQ+SYhZ8iCnB5Gff3Qitspr3scQi1fHsQ345K7LmFT5kApMJItzMq1XmvjBsZ871KYN
         wv/uMJ/lFqEdOgdwmAerX+j2oCFAdi/qvmvPuHqk2h/mWW6mBOgG9FsQon+VQzz+Tpog
         iFu+9v7hPJp8klASjsbF3nXq3IuzqDVr9SLEaPLqF7hJkEbXOr74+jtX8FsK+QU0ZjLU
         W5PLzPBa0iqT2DBVV2VkXalnuqn4miVUT7j2j0p2e4Dr2tXnK4EHQubmsvOxRAH9J67i
         LLWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lh4aw+g0noV91+UGQF1LGRNkjOVMqSzyHLc6FCiOD8k=;
        b=e5aplSEzR5nrtbNoNEhfY97LSIjS6ihEOUPcysn8wmQFmPnAwJyS5ToA1wCuABHZOs
         liVLEhht3WF163dGLgQRjTRK8/fNj5t0+p6NbRAm+M4ao73A76tpgbiSjpFkhfutxLFv
         N7SdyJ+zrEsm9aEg1Ort0BmuQZt89X1b/PzB6BT99BbTXlP3PW4KeUEJmK+E3j60fgwL
         6+Q6wJG3nz8PWic7/HvlbIdFLv/8cVH0M4l64bD1WVrwKr/9+QTvVuu9VzMP7t9/5/VQ
         +P1C+wiGG3wqGNoZFvbIZzwZlbYazWgBHHX37SEMJ+Hchm+NbVBpu6S2jXFpj/gdypCL
         aCIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWKDJdciW7E39XekU8cwOX4ySkRWsnPG/2kD3prDtbS35guBV7h
	zHdXzi3a9AO6kp21mVh9epw=
X-Google-Smtp-Source: APXvYqw7G7qFsV+tnC7moMOt4Na/ENfmJ7+BDR1GgN3xD1InRWifdeFDsuPgYmIsvwUVwRGeEqaYTg==
X-Received: by 2002:a81:8082:: with SMTP id q124mr3166595ywf.67.1572514774775;
        Thu, 31 Oct 2019 02:39:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:7845:: with SMTP id t66ls336551ywc.14.gmail; Thu, 31 Oct
 2019 02:39:34 -0700 (PDT)
X-Received: by 2002:a81:8203:: with SMTP id s3mr3412490ywf.396.1572514774319;
        Thu, 31 Oct 2019 02:39:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572514774; cv=none;
        d=google.com; s=arc-20160816;
        b=d2Fz90o/2UoOkqxlQpmzAN97+66qPKtsnFXBUFGgcOkyGaGtG3sv6onRTecKnc+8h2
         7kqW2aXt9GPz7c+iaEyQ+7/7JojoaYbT3y37VGh3GxW+/T5ATCxsQyCTVAWFukGy0nxf
         283az2yg+sB7HNPdle8p4aPje2eLnDl/+wt2v4KWiqwG7OuXCivL0kmsb0hVPBwZXNlX
         K4vgYrBZX7g4Z4L0oaRslGAmDmuijsA8MMiNU64DQh5F7xxXfrmfFGkoAvVnJWL7ICrL
         OdKMCeYW64zsYrJloZ/y2gpedHzgV65cEZX5o7d3B9PFXeeIWSKwbzkvgjFpAKam/wrQ
         IlKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PPZxJ9u49e1rTbwMFrZRlJu9A0GDiffR0uj0Pjy+KKM=;
        b=0u1MACXpjV/fxjckl38bmih9Di11B7YSYQ4ScBKPGQxuTl6ORXf7NQ3/YG6aVWS5JV
         pHBXs7mUjS5Ici5gSUsP8z1Ei/RbSyVlKK/ngXnpzQkfCMYzmYLu0/uCmlAiIkvpg58K
         jHoFHrIgX1bCLE4mCLMopJdV9ZiidfEIdepbuc92eZLiqFqLEcvn7vvhcVSgX4KLmr/X
         VRaHcmh5M9aJsKFK/uY/mk5n5/nIIejyRyeeEDkviJOIylvDY4Ue7+TKn5sml8eEv0hj
         itlP0EUEZ/2c2fkjYcKoPAGPSpbGT6D38T837EuWySkJSF2MdjFTd/WYjFY8/MiaoXot
         2NiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=cNX69LQO;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id r185si407430ywe.2.2019.10.31.02.39.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Oct 2019 02:39:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id r1so3667184pgj.12
        for <kasan-dev@googlegroups.com>; Thu, 31 Oct 2019 02:39:34 -0700 (PDT)
X-Received: by 2002:a63:d308:: with SMTP id b8mr5489951pgg.246.1572514773130;
        Thu, 31 Oct 2019 02:39:33 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-783a-2bb9-f7cb-7c3c.static.ipv6.internode.on.net. [2001:44b8:1113:6700:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id q185sm4870092pfc.153.2019.10.31.02.39.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2019 02:39:32 -0700 (PDT)
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
Subject: [PATCH v11 4/4] x86/kasan: support KASAN_VMALLOC
Date: Thu, 31 Oct 2019 20:39:09 +1100
Message-Id: <20191031093909.9228-5-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191031093909.9228-1-dja@axtens.net>
References: <20191031093909.9228-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=cNX69LQO;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
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
Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---
v11: use NUMA_NO_NODE, not a completely invalid value, and don't
     populate more real p[g4]ds than necessary - thanks Andrey.

v5: fix some checkpatch CHECK warnings. There are some that remain
    around lines ending with '(': I have not changed these because
    it's consistent with the rest of the file and it's not easy to
    see how to fix it without creating an overlong line or lots of
    temporary variables.

v2: move from faulting in shadow pgds to prepopulating
---
 arch/x86/Kconfig            |  1 +
 arch/x86/mm/kasan_init_64.c | 61 +++++++++++++++++++++++++++++++++++++
 2 files changed, 62 insertions(+)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 45699e458057..d65b0fcc9bc0 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -135,6 +135,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
+	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..cf5bc37c90ac 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -245,6 +245,49 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
 	} while (pgd++, addr = next, addr != end);
 }
 
+static void __init kasan_shallow_populate_p4ds(pgd_t *pgd,
+					       unsigned long addr,
+					       unsigned long end)
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
+			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE, true);
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
+
+	addr = (unsigned long)start;
+	pgd = pgd_offset_k(addr);
+	do {
+		next = pgd_addr_end(addr, (unsigned long)end);
+
+		if (pgd_none(*pgd)) {
+			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE, true);
+			pgd_populate(&init_mm, pgd, p);
+		}
+
+		/*
+		 * we need to populate p4ds to be synced when running in
+		 * four level mode - see sync_global_pgds_l4()
+		 */
+		kasan_shallow_populate_p4ds(pgd, addr, next);
+	} while (pgd++, addr = next, addr != (unsigned long)end);
+}
+
 #ifdef CONFIG_KASAN_INLINE
 static int kasan_die_handler(struct notifier_block *self,
 			     unsigned long val,
@@ -354,6 +397,24 @@ void __init kasan_init(void)
 
 	kasan_populate_early_shadow(
 		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
+		kasan_mem_to_shadow((void *)VMALLOC_START));
+
+	/*
+	 * If we're in full vmalloc mode, don't back vmalloc space with early
+	 * shadow pages. Instead, prepopulate pgds/p4ds so they are synced to
+	 * the global table and we can populate the lower levels on demand.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_shallow_populate_pgds(
+			kasan_mem_to_shadow((void *)VMALLOC_START),
+			kasan_mem_to_shadow((void *)VMALLOC_END));
+	else
+		kasan_populate_early_shadow(
+			kasan_mem_to_shadow((void *)VMALLOC_START),
+			kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_populate_early_shadow(
+		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
 		shadow_cpu_entry_begin);
 
 	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191031093909.9228-5-dja%40axtens.net.
