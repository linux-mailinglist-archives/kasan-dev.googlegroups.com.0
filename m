Return-Path: <kasan-dev+bncBDQ27FVWWUFRBRP433WQKGQEQBN5ARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id CF428E7F23
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 05:21:26 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id m36sf9048810ywh.7
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 21:21:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572322886; cv=pass;
        d=google.com; s=arc-20160816;
        b=yIJJLBQuHtFIrcGWS5GmOVb176SW1JoW567AjYP/gJSYwOtLZu52JT9Jk4AhB4esCJ
         8fdQHe1jzWWYqttm4V7gKG8yt4KnF4cSB6cDbg01GlKs0xE1whEfUThEod2GhqhHJrK2
         lXHFpgwWQBo8t7B+H6JOi5gM2DCgtiNwnE6qD155hiW5BWG4GLmOmGDsLQgNu+dUIVeb
         rkkkjy2GZuBwv3NOvZQlW9LYtKJck0R5cYMI8ZSS5t3ukpHks222kWQCz5Camelw+w7o
         N8+g9KoKyzdgG7YiEWe1BCZMqRt9Zusk2ljfwAwsEAEAojcC/pLPpNOCObTmYusKTnYh
         G4Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1ZUmsuv+3h8Se7RyxiSdwPlJ7HPj+QHP7ptmwjatRow=;
        b=nU7G9XbnfgXOmxh/vYq49r7p7qwL+wE2N8RiX7i4a0a4CuPOReLIunYAQytMNCpsq6
         AP/PLvJw071l2a8kyGCmakAA7/vYXYV7CSh2bhxk8zvIYqVOzU5XlAKAq0waddoTtoUO
         ZCky+80BoPhOfMusUzkB+NuR/iBqEgNxTxlML6YvYRl9fUcOMYMOUxnoY3AlUsAjT5gD
         CcJjGUrTi79ZsTddxdwMyJaQXDufsO20dlkE2YxynR0Ds1CcQE5t4OQsXSbgOsuFbZ7p
         gPs7THk5Tc4X2cuRBMtvlQYHSWRhNhTb73nGPnHCoYhwlMKVJinW58HDVRgueiXTxSW2
         0gsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=P1vgWGkf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ZUmsuv+3h8Se7RyxiSdwPlJ7HPj+QHP7ptmwjatRow=;
        b=hK0/BkCV6NnkyxAu6eCCTAITn1X8V6tqW7+DoCvhfbcR6hyOeDM8EV/V+MMQq/+wXO
         wrmxx+aEz129ar7ZW3fQvFP1GbjmRGadSicZpk+H/M6SBzG1zWVTjj9kIno0q6w9kLSH
         HqBmOn2qZvAarvuzpFWolTf4Ph1gCe50LOVp6RD0B1nuXO9nf20aOgTcrA9zvxD6xL+0
         0x0uw9iM8khcuVk+/Tf2SO474N+j5N1bFPYvZLpj2VcRRvclPhXYnXyhwhfmDHfpzb0d
         rCiLKbKzWzcWxCVK2aFgJVPQLVJa87bRcFEo1ZzNNOSuy5dN7zWl06/JmdF2cAm/1b/w
         R3Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ZUmsuv+3h8Se7RyxiSdwPlJ7HPj+QHP7ptmwjatRow=;
        b=klo62jpJzLkLVX6q7cdBfndKWOtQzqZ4OtVWIcoLUrbw1Bp9qmlowFAnqX1e6doSFZ
         OvyahNNSAL3PJhKUkcXNMFtZ9S/MdGLFRgxa4Kd3u1KK7PZ+EczH9GWEmUGOTZ2vZxsG
         I3f81q+Tw9+GA37dRSDXQHD66Ku1IBEjfxrzUaKLCm28/PQUtlOSEvYyH9OUM9FCGWX/
         zGDlHiL8A03JUo6JZg/ltiS/d01MbA52jHOGXJbVxIyDF0OtuyRJS3+4BEAkECt9P5EU
         j/meQn6yQZZ0viVWsMqPvShcDMoDIDKmiRZ4AEugE37I4ESMMCbF2iIm7t+8c3qqrMuG
         khvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWseTu0wPM5WppVq2eN81brZuFKM+rIGkTmMTGT0OWbQ+Or2IMf
	YHoImoZaaaqTVtQsk1W8S9I=
X-Google-Smtp-Source: APXvYqz5defn8FBXZv4ERaBHvkOA6nAorjQ13qjPS0byIpKTwc9Imoxj8Y5eYHXcM8Duu3kQUeQtWA==
X-Received: by 2002:a25:6191:: with SMTP id v139mr11338563ybb.311.1572322885824;
        Mon, 28 Oct 2019 21:21:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c04f:: with SMTP id c76ls3082554ybf.10.gmail; Mon, 28
 Oct 2019 21:21:25 -0700 (PDT)
X-Received: by 2002:a25:d206:: with SMTP id j6mr17579379ybg.93.1572322885228;
        Mon, 28 Oct 2019 21:21:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572322885; cv=none;
        d=google.com; s=arc-20160816;
        b=COpWTfk9hmjkRmNqXzXaMXaDLs4+tTXT2KHGIxAPRTV9bzPL4BJsWYWX71b00iVcEr
         PtMzbakFx7O8B06Q23PIZop4Bg3JuHy9OLfLK82jfpevBYuiCtVG/vkQz//xns3/l+XD
         i2SEZHfdCMU/AeG33aqOhWHu3mawd1oNJeDj0S7BKGqSiNnbASqU9C0HpWdY8PWFSQrs
         E0h3TnvxefNMOXdXsyP6mtxrZKEoTT5QgMQBtLCYtOSLp2vTn4IT5LCYdLJhx0jlGTrm
         kx9R4fUQ+kDQzTm+Fkmr0cpTxu9nbVFhkxM5LFiy8XAYFvu7Wd2tV/UgARSU+sZt+76l
         R2Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WyYpZbWP6HUDQzKMRNpQV+55Z3UIHrq0rortvFyZDZM=;
        b=e3pjtlauDxlejaKSbu0wMSI8S+vBcaiUCg9Y+R6XckKK4GfWZdOs6RaR9lLaf37wxI
         Ylh7FJPCpdFMgAPXM1kUQSY2y13lkafxzsA54zVV+rJi0pHFd6QNbVSvV5B2a/0RcG6Q
         j8NRfoljiU1OJcflNL3g2gC/ieXlvc6/OX66RyG2/7Rc1dS8uP7eY0Q8vNj5ZyrDlKTt
         qliDLZeV/LF5+jJlTCfGPYmjtWsdIup0QbT/cx/0T3LvGruMhcfY3+2Rs3g+hsqI1YKV
         IxQtbR4v3D9l8RIwodhflSR1jrUvKjjWAfpfdjXeLHMrnCrR3JhcvuyyaYjoF9R0+r8Z
         4p6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=P1vgWGkf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id 5si78471ybl.1.2019.10.28.21.21.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 21:21:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id q26so4943933pfn.11
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 21:21:25 -0700 (PDT)
X-Received: by 2002:a17:90a:7608:: with SMTP id s8mr3568275pjk.75.1572322884077;
        Mon, 28 Oct 2019 21:21:24 -0700 (PDT)
Received: from localhost ([2001:44b8:802:1120:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id t8sm1026995pjv.18.2019.10.28.21.21.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Oct 2019 21:21:23 -0700 (PDT)
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
Subject: [PATCH v10 4/5] x86/kasan: support KASAN_VMALLOC
Date: Tue, 29 Oct 2019 15:20:58 +1100
Message-Id: <20191029042059.28541-5-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191029042059.28541-1-dja@axtens.net>
References: <20191029042059.28541-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=P1vgWGkf;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191029042059.28541-5-dja%40axtens.net.
