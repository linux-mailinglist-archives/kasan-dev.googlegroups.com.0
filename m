Return-Path: <kasan-dev+bncBDQ27FVWWUFRBVHAUHVQKGQEUBB2GKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id DC15DA2B81
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Aug 2019 02:39:49 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id v16sf5314290qtp.14
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2019 17:39:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567125588; cv=pass;
        d=google.com; s=arc-20160816;
        b=rNFJMtGjtG4i7PUZ15Zvat9SDkBPnengZWRh/PaVaa939tJmCzMapD63icnhSSLs7U
         8oxXdN9Lj8Lko8EcdM/H9mpihAaZbIKUL4lvYKQ18f4PuCLxZu5pVZeJJorpUusww76N
         qSYKwFJbo9PJ9ZexOyPJAx08qgezx8g+/xN8YlHmlh2mzly3Ubm+dC0eo6YeG9xBnCCT
         /XhC7MgKo/MWskT6DsuPQnI999myqXlz7suLunSkjai6eFl8Vmixe+RGppoBV1/Pmw/D
         Hzd8ScQZHi4qFuA0mgrKEYcOF62hfzH0dtsi4C/7w3qpTe82GrxYQ63TzJQGCD/3ZcsL
         rJXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=73QNfEbihk5XR7tmKPvRRDuKxUJmqz5NQ/kKCat2HtI=;
        b=y82oKWXHmqipVzZAKaXowegFfF5YCWmRrSMdu029Mj5tmFNYm7GpoGvQrU7dvC4qeH
         aU+dl5vFNNs7wUGjc5VRvq0p9/asjM4Q4OOFJ/9Yei7s+Mr+V3srU6ugS8LiOQCPIp5B
         kFJe7k9VK9ZNKl8NrmQcvwU13cH6mNyZ/2Ff7yH1LeFxMkRhCADzUM/dF27xCsKDiBan
         jhROGxze0aJ87iR4PAZwnk4JxqDVaqe8E4O7DTv3S/oB8IFNSL0qOkzKnaP+mt7aohld
         7a4ywf8QWyJ+XilRsBevB+HlUjBIuZiZfIW3DQrRdj/+qbffi7/Zh+OtvpUgy50GhaS9
         qw7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=IQK9DeXF;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=73QNfEbihk5XR7tmKPvRRDuKxUJmqz5NQ/kKCat2HtI=;
        b=iKl7LzDD8oByOOkHLnCHZbX2ezIpETkUfSPGPxPBda/W5X1T/TC5g4szszC/GDMvb0
         co12CKnQdnoQD6QaqcCTOJTWVmXzxTPPmqWWmbC5eEscXdU85tSf79h9Xxw74Pw/9Sza
         cvkhrCjx0B1KEpThQkr8JBSg/bcglo4KqO5bXPs5Dyx8FVHAzpkoLJH5N52mjY6xz5E2
         uHnkQXxhfNuGF2I8BXut/bNvoFRAfzmJ7khAmjFmD1lI4rCKIdg47Zwpl83FU+Qce2By
         Bgban8QamOZ9ba2qtLxdzAj4wxhpabl8trY46AtzfHBpBz31e33aXuIRzLNyj2j1wKmV
         BLbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=73QNfEbihk5XR7tmKPvRRDuKxUJmqz5NQ/kKCat2HtI=;
        b=Vag17b7X85Bi7y3DJxeWBFLEgx7EhbyKZ4Z+XjNdN/z2xctGUq0G7+z+Mp5zaQqmoV
         U97M1nNW7stUMMnfQOT/2uLR9uPRurK1zRYRE/WiZlnAUdkW5CpmLuBF35mIcfrav3BY
         vmoxwaNmRNM7hlWSOzHnvZ7zH59ED2HaGo4TGyGXYJ96fScLhu+csF+UnaEqjQFT1Bwv
         Vc2+pvR8iBT6wfuAotz6gGr/qlvFxHkrld7ja4UOcw3Xk883t6u3xQpOU54odIq4U+v7
         9Xr9qhxw+2XeYekgJyXMIXqjiWWd8gLQmJgsMDWfxDU9K5FjeELYnqzoiCJ7zL4ih7Yj
         ZTdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWVWBKxjRKsaaQ6e0F8sdMp8MTpOT/CgwZwFcN1i9R/6MIC+WCc
	vk2/UFO6o3YBxkOU1P43zzk=
X-Google-Smtp-Source: APXvYqxP45K1FLdx3PlFVk0s0bPJL12X9WEDvkUmJs8PHxtnqBi3BCWSh4PW97QiuqTvOljKzTKsVw==
X-Received: by 2002:a37:9083:: with SMTP id s125mr11505345qkd.278.1567125588851;
        Thu, 29 Aug 2019 17:39:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:3d2:: with SMTP id 201ls455192qkd.7.gmail; Thu, 29 Aug
 2019 17:39:48 -0700 (PDT)
X-Received: by 2002:a05:620a:14ab:: with SMTP id x11mr12582001qkj.55.1567125588679;
        Thu, 29 Aug 2019 17:39:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567125588; cv=none;
        d=google.com; s=arc-20160816;
        b=BCqdS2sybqJ8CT8yjMoCXjrr0On8EG75VjqPsfV0SASdb6Ut1bKM8mGlc3Pdo4mWm3
         62vYOY4JBCXZNubw051ps1xm9+nmyAFoh2be+1oqneANaxzQLbKVkuOenU5lzmNia3Ec
         nHrHACzcriqyDmvfnqSii7/s6uRp9ManR11WT3UGyQgxosdYKFjzOMiRaPJnRmYq/UR3
         7SjlVz0wUqTCHmceVn0Jjt9BTZRvxiyS75qrtb9bQnoVPRYXaMbNDSPDXaQAtri+zEWO
         Vp0VOcuMxBHPsY/PyY7jk/d2fGX7gtM0RGGdCdsmEL6g189uxLWbZ1xmUgKzctwTGEcM
         tbnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/Pi33Ab5H1THuUOlmFKCqF9xJSMT6s+LImLmp8toPnA=;
        b=EB11M8qX+X63stjR/IznnIhBV03awjeJLn8pxzR86Q2n+fFEuAWKoesf9HxhctXAyw
         60HSNeKRJI+jOTV9yW7RKohCg1s/JoJCdvsWLupmZ7pTE0Nh3nrQqz8AwQ+JKTrvPXfE
         AJFQDYV3iIB3OWmMvgegmxMS25qAiG11prufg9VP/y6Y68jshBGp/7j2pt02ByZJyxcn
         UIavr7OqGCjSKPxNGrxYhWw5pfgKqufNOzkUQ4pOtJ3KMOQYome1kRLCjr3g2hFxKozd
         5oi5hILAku6FQKq9e9C308X+VSj27Dvf9eNbZUZVArZlo2aePrv3lmGNgDMQrlWLGE5a
         hoXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=IQK9DeXF;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id 37si277135qtv.2.2019.08.29.17.39.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Aug 2019 17:39:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id o70so3322444pfg.5
        for <kasan-dev@googlegroups.com>; Thu, 29 Aug 2019 17:39:48 -0700 (PDT)
X-Received: by 2002:a17:90a:18e:: with SMTP id 14mr12641199pjc.66.1567125587475;
        Thu, 29 Aug 2019 17:39:47 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id z63sm3860222pfb.163.2019.08.29.17.39.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Aug 2019 17:39:46 -0700 (PDT)
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
Subject: [PATCH v5 4/5] x86/kasan: support KASAN_VMALLOC
Date: Fri, 30 Aug 2019 10:38:20 +1000
Message-Id: <20190830003821.10737-5-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190830003821.10737-1-dja@axtens.net>
References: <20190830003821.10737-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=IQK9DeXF;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190830003821.10737-5-dja%40axtens.net.
