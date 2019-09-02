Return-Path: <kasan-dev+bncBDQ27FVWWUFRBXHWWPVQKGQEYDXJLYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 08B75A54B8
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 13:22:06 +0200 (CEST)
Received: by mail-yw1-xc39.google.com with SMTP id i199sf536862ywe.4
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 04:22:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567423325; cv=pass;
        d=google.com; s=arc-20160816;
        b=WSiihJsFWKKwqZ+NEkMGAlhEH3Ax/m7bBAjLtmxkF+d/EcEalf2CO221nQih7RwBBe
         6IKzcrj4wKWksTmDwczUtLhTjYUk4GoOOPi9JigoBlWLcHVMw2nVvNU0o6+527HZ+VGn
         5Ti2Cyk5Sd2Tt0Xfo5LfY7ylVyn6I+98I0LDZyxEK/jSq+uL2aOgZsmsLKgRf/18aAjL
         GNBv74LZ2EVgverPE2sfqQlpFZGdZ4e8KRtZp9QMr0b4WpuPgT+mljMcfdwbvbGJ0CIk
         ISJKlDnh6pc1SErOAkpH9/IZbZnY1ku2MRgKLnsh0GPPSFbBnrZDMM4exAMudpN4hfbz
         Jxvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wfeWTczWJ4yo3DDz4/uac5CRb9wwyf5II+6up+HlV1k=;
        b=IHmabXghhAeHZk91Xkc2GsJlyz2rPFX9Bz51tsZlHhX6Eu/QmRZMg6pzUSm05b4LG+
         Uqedp04RWIJAaGxANzE+ZTuSFgRwzq0xHJNAlqkb2/dbtEqY5lorNYb77NiRpTJ6tGL/
         EZ9SAKsaC45JYz/R7F86yz4bqKgrt/CKqJ1i0ZBgZvFRW5QgJYk7NDg03WqEuJe7HIM7
         E4/u16HsfcY6YtMaXWFhFUIGjYVwZ8Hf1+Lq9pkfSy7w8Lk8nK4raBbc6pmBL+owtR9R
         RuSQgFS5/SoO5kqQNSTTh96DAQbmpuqUtKKYjmyyuid71rAKXrIbnxba4m7L5GTo1M/+
         eKOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gDXdH1Vz;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfeWTczWJ4yo3DDz4/uac5CRb9wwyf5II+6up+HlV1k=;
        b=cnWsiteTev1tyDFKUvCDpvTzlUbntxmTloGr7lk1Idq9LZIi+MHnn170QbE8Oiy3/E
         ZYxUuIC6BEI+/VlqOK3qSUpobO2kxtDuusmTWOQ5Vv/Amb+o45L/wSodsBz8YCO4+3xc
         Z1uX9rp0KXw1MehEglelaCe1eOn1Qt3L40XiVnnntjfNhVc7t7oDHc+Xk10e3oWY0Zyl
         StjknIfX1lvz1FboeWoETgDKoVwx7XEz0Y9tR6F+bclzHr2JLxvffxTjV3ME9Yoq/zM4
         GZ1DjSmxDG3bS+8R1JnTGitJou/Gz+umzacAb32BYXeoytyN9aeqXH2dszK8RVbw+Ljl
         iDUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfeWTczWJ4yo3DDz4/uac5CRb9wwyf5II+6up+HlV1k=;
        b=RCcWFl3lDvMFOdAvEUk5od1Nxj1kZr+SIn/RYOmKoX9zFqk6b1Mx04TnXpe/cqV7oJ
         sztYs+rTl6xrPTqlutdfacr0buFjH6iKzcblSOqZBtShwmjfFBJtikcfC1VC4Oqvs7Px
         E6Mq1jxx7mXl837CeieuGYPiBczDotICecpntJFz8By05xOTAV+kwTIgLUxPcdSUOBtk
         /Uhc0tISLPYR2FmkjIFFhKu4RhITLzxY6dGG+RAixfipEVg3opg5qBeovLhpwtv/XrTM
         mf05DQ/WEe/Y1ddehhq37FTN6JPHQz6GTT2w8mTQffCTU87xDlVtFcEnDXG2uL84KYWO
         O8sQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVPgOQxAvesRj78GN7uzDKGYYsIQz/ThO3fmXr5TsAO/x+iVQow
	LqQVwH2OBHNGlTe1ChvuFA4=
X-Google-Smtp-Source: APXvYqz6Guc+R1cKtxQwkI3hGuv1RrrHnTXqsESgThbTvtXM+XTCSV4ahHwDBhuhOdh4DDB6/pmdgQ==
X-Received: by 2002:a81:4942:: with SMTP id w63mr11268565ywa.431.1567423325080;
        Mon, 02 Sep 2019 04:22:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bd89:: with SMTP id f9ls1747302ybh.2.gmail; Mon, 02 Sep
 2019 04:22:04 -0700 (PDT)
X-Received: by 2002:a25:1e09:: with SMTP id e9mr20579823ybe.293.1567423324807;
        Mon, 02 Sep 2019 04:22:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567423324; cv=none;
        d=google.com; s=arc-20160816;
        b=XyrDUgLZP4P9TOs+Sokzw1K7UieA8NHmfDUcq04DVKTm85k0yySobfclP5gzvBn1Pm
         k2GIGUYrxr5pUPWvtcn29hQk7erDkiNzrlN/lJ3n9qB0wknhACgaGJ+k1nHwYrG+x8V4
         rRwH1UQOBLxFNG1wjpFHIhI6lqkrEfarPqAdQaRXTJXmJCzVFMQHCFK+MXx8hetxTY2r
         CsDgkiWZBlbUCMfKXMnmwO4+e26XLLA7tKYq+N16G5roeWuK+wViriOt2RmCXhNBDfSU
         PtA7nrbyVeV0LbfaxG5NjH1uKRLyywqtNezcWjZ2c7qoF4TLTKN4l8J2+WmN1a+INK6n
         qP/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/Pi33Ab5H1THuUOlmFKCqF9xJSMT6s+LImLmp8toPnA=;
        b=BnMfbzeLE7g2h5WdD/0cgi6RR0x59FiKRpe+nNtC4lsFe7sNaWRmvQcAFYhjJl2oR5
         9PYtxG/WsSHiTtYyR1+4y26GjFU30G1k8wgt7F3Ih2DBaFZ0RZ5dMpEULwgR/8kBiuum
         wHTmm81Gu0I79tK6urXqAkF+G3KkXdg9S9dxP7gHNkY5BH7M/GLHQnRRnzKvfJi3ller
         MCQJMdslasqk2PKQ97j81xGQrJYgEsi2b66PpKL2BQQUN9xrhrSo4WRDTGTKm8lmi3lT
         wJzVpyMNN0ei63+fgC/JOkeOc3vkIVaPxqmLTp5OipQ9l1Vl9z5F4j3QCdpxFxe6Dx+s
         TigA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gDXdH1Vz;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id c76si873254ybf.3.2019.09.02.04.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Sep 2019 04:22:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id m9so6498833pls.8
        for <kasan-dev@googlegroups.com>; Mon, 02 Sep 2019 04:22:04 -0700 (PDT)
X-Received: by 2002:a17:902:b08f:: with SMTP id p15mr5676763plr.49.1567423323788;
        Mon, 02 Sep 2019 04:22:03 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id i6sm9452487pfq.20.2019.09.02.04.22.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Sep 2019 04:22:03 -0700 (PDT)
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
Subject: [PATCH v6 4/5] x86/kasan: support KASAN_VMALLOC
Date: Mon,  2 Sep 2019 21:20:27 +1000
Message-Id: <20190902112028.23773-5-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190902112028.23773-1-dja@axtens.net>
References: <20190902112028.23773-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=gDXdH1Vz;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190902112028.23773-5-dja%40axtens.net.
