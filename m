Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBUW2W6GQMGQEYLG4ONY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 488424694A2
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 12:00:35 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id v62-20020a1cac41000000b0033719a1a714sf5923731wme.6
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 03:00:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638788435; cv=pass;
        d=google.com; s=arc-20160816;
        b=fhIXnVnDjWt7racfCOtwia4/qPHZ7OpLyhKXUXcu5a6lEv9FkYSHfleGhq+skFR599
         +wPtFullMJ7yppQ3YpY6xQJM398rwVf4G6pf9hNMr5ZwTPCNFehtvNJnLwDaJzKWUlx9
         7iypiKHr3lpjR6rhPrpXCjQZhtztXYfD4+vupr87ov5bdCzm2prwxPRlZDKpEjBY4ZXM
         n3j+LCOLvjr43gp64PAOBcSlra07ia6yvvwozlmPZLmYhNJfhntp16fjIl+QzAyuPE2f
         pisgAjhrzg3D9SC/vJJctRzA9ElFnUfvPF9GST6AiWPvx/GxDkAeUPiX30J+rIVPBOME
         GNqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2pQmZrvUQEi+iT6qFAW1CnNHED9p1W7zxq849iTnHsw=;
        b=REUfRj4gYU2nQqtn6PfQMJ6VOOR8/tGPifzFyjZQY4zMH6VSEfGeENrWKlNX0Oo2Qp
         h7a9HgrpQnOLSm6A4FvW4ohk+F+JlA3DsQ8JF+u95JHOhUwUXOW9IpZxCgG/iMUGE/Q/
         RywMkDW6V5y8zbbYQhDBpV3ghVU54suAFVZd465GRcLQ20w/CbDkrriEd+uLkZiPnPjz
         iQoCNFj/sU4BzJsgTSaEN/cvJXwea/tO5qOsgcKlkT2O+ehKyYb5QZfqHeCJDiD5AkjA
         U5leSMPWTt6BpMC5s5DlWS3SdYtHlvDyx1al3+xgBYnJRTEeOB4PQQk18HsCGS5BrQFc
         fCZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=ObrMo4nv;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2pQmZrvUQEi+iT6qFAW1CnNHED9p1W7zxq849iTnHsw=;
        b=AOOrM5ULtzTIhiokyhjxLpmviG4s+NM/9lNb+G5lavLdV9AYfASBnN+a0toNbkdV1H
         HtIQUqsWGXDIRlaGuPgvi0Z7kxvFu+mzKakVYPDJ/hdyyA8hTq//AlFn8khZ7GKvDalI
         2kYGfAPAtzZulajg7tNeSvr6wLFPihVZQ5MfJDHpGk6Xj8F4wl0r6t+yITDD7fSaT4VO
         RSoKJE10HtaFbrd0qx4QFmxdboZJPJSp/gSmG2/9Nih+gDk+Jmju+i38xTLzgcdy39zB
         SBlnHc3ONS4mFJVtBC8ghrM4aCwVmt3u6GjIYKwwJWGVnn4iszZ7TnYjmIAdOEwAi3OX
         zhww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2pQmZrvUQEi+iT6qFAW1CnNHED9p1W7zxq849iTnHsw=;
        b=xpqK/Qa766CqkNIEoxEBqyebw1hqPVgqB2hVzvFKVVAcog9bumV92WJMO/lZOO8nFW
         MdlbpDfHfjLOa6Ab/Tku+HcCAiZKX65HQSfv6eZWm5t5rLJ1usnHk2oZp8AHD1c1kHIw
         kqHXcwnaEN0Y15hlTBd/gk2AOhRQUaXWIKPr1PTgghgPlX0Sq+H9QkeDSPQOXtvSqIld
         4VXtmFqzdYG7ZlkQgnqF7C4hPq07gPD3RU5Czw5e8qVLGFuJs7Piwgm2qdxAccVMfZ8y
         WfQWouOVcHi67r0uQvFEC5zIPC/ERrUI8DHYWi22aLPEjtjyF+tuzSZnGepgdfsxxHao
         +o8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532GfdRQgj7ftzZLla5hntywvTXzHz7XFUeITaz4/A1GUDLChe3I
	KTE6oLcf6QQ7WlweNOOpMk8=
X-Google-Smtp-Source: ABdhPJx2/PEKm4wkvnXOQla59DhQpZ76/n3BtRS/nCj8Mfgofevhx20x54dgj+5ecYkqXaUfRb8QWA==
X-Received: by 2002:a1c:7e04:: with SMTP id z4mr38133671wmc.134.1638788435066;
        Mon, 06 Dec 2021 03:00:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls370064wrr.0.gmail; Mon, 06 Dec
 2021 03:00:34 -0800 (PST)
X-Received: by 2002:a5d:48cf:: with SMTP id p15mr42406400wrs.277.1638788434252;
        Mon, 06 Dec 2021 03:00:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638788434; cv=none;
        d=google.com; s=arc-20160816;
        b=M+Cx0GuriLCq6Ks6hUAt51QDl1lYyTNkjLFE7WJsGzj9tpS2DfWIf/ZRUO+MMmq5nz
         wSHnj3NBPwf2xqVaqETdZ3tcq9ofmZ9kJUrCWyLUSc5gq4sbJjyuhS3v9RGHBNiHHdq6
         4iuSyMWmmKG2cyhm2hEtFm8r1KW1Gjk9BeT56Ho6xKaFOAa3hroOL6t3iaM935WvAd3D
         qZ5RqX2rCkiHCKkxsUn4DBdNM5rW4RkLL9zaVuHkrtn6lwHRNj58sf9oddeyhuucgsoh
         G0yp1vZtgKuX/l6KREI0Ju3i/QjMGe5AAaupGcJZ/6t9pUwaibk1WvKZrPkHw/3rrbk3
         nwbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LLLQM2eTCRvnVYbUZLcWpcb1BJMpiZdjxDv6AB/KJWI=;
        b=jDbZ5fzc18QiF2zUDogV8Z29L6PQxmHHy9iWo5DKBoU5UfaTftuIXyV2iblZGSiRn2
         6xroDK/F9vXw9cKSouNoHYHbng6LShVLglno7O9xCTPrqOsAU6mbAUy1adDyNWqiCiyS
         VX0TQb4xJbp4SQhidwdLP56Ui2cam4oLSPo5vr6gtdEW3cGuWZQrepIsdyl2PzI2DBfI
         eo18RTGmPx8zB3KwWQIkW4T9ne03UUQ3UpmVZMGNnQYlxicrXQbVn2JAENWvIcvUgYKp
         SnW+4H6xFJ7AJfJgQiTLHvzG7IM0WCaenG7PV4cqXnppK3REZoJWv6CT83XttaS1uv/k
         /hHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=ObrMo4nv;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id o29si1513841wms.1.2021.12.06.03.00.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 03:00:34 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com [209.85.221.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 9B89D4003C
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 11:00:33 +0000 (UTC)
Received: by mail-wr1-f69.google.com with SMTP id q7-20020adff507000000b0017d160d35a8so1916057wro.4
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 03:00:33 -0800 (PST)
X-Received: by 2002:a05:6000:1a41:: with SMTP id t1mr42771100wry.261.1638788433025;
        Mon, 06 Dec 2021 03:00:33 -0800 (PST)
X-Received: by 2002:a05:6000:1a41:: with SMTP id t1mr42771065wry.261.1638788432820;
        Mon, 06 Dec 2021 03:00:32 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id g198sm11262997wme.23.2021.12.06.03.00.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 03:00:32 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v3 13/13] riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
Date: Mon,  6 Dec 2021 11:46:57 +0100
Message-Id: <20211206104657.433304-14-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=ObrMo4nv;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

This is made possible by using the mmu-type property of the cpu node of
the device tree.

By default, the kernel will boot with 4-level page table if the hw supports
it but it can be interesting for the user to select 3-level page table as
it is less memory consuming and faster since it requires less memory
accesses in case of a TLB miss.

This functionality requires that kasan is disabled since calling the fdt
functions that are kasan instrumented with the MMU off can't work.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/init.c | 32 ++++++++++++++++++++++++++++++--
 1 file changed, 30 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 28de6ea0a720..299b5a44f902 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -633,10 +633,38 @@ static void __init disable_pgtable_l4(void)
  * then read SATP to see if the configuration was taken into account
  * meaning sv48 is supported.
  */
-static __init void set_satp_mode(void)
+static __init void set_satp_mode(uintptr_t dtb_pa)
 {
 	u64 identity_satp, hw_satp;
 	uintptr_t set_satp_mode_pmd;
+#ifndef CONFIG_KASAN
+	/*
+	 * The below fdt functions are kasan instrumented, since at this point
+	 * there is no mapping for the kasan shadow memory, this can't be used
+	 * when kasan is enabled otherwise it traps.
+	 */
+	int cpus_node;
+
+	/* Check if the user asked for sv39 explicitly in the device tree */
+	cpus_node = fdt_path_offset((void *)dtb_pa, "/cpus");
+	if (cpus_node >= 0) {
+		int node;
+
+		fdt_for_each_subnode(node, (void *)dtb_pa, cpus_node) {
+			const char *mmu_type = fdt_getprop((void *)dtb_pa, node,
+					"mmu-type", NULL);
+			if (!mmu_type)
+				continue;
+
+			if (!strcmp(mmu_type, "riscv,sv39")) {
+				disable_pgtable_l4();
+				return;
+			}
+
+			break;
+		}
+	}
+#endif
 
 	set_satp_mode_pmd = ((unsigned long)set_satp_mode) & PMD_MASK;
 	create_pgd_mapping(early_pg_dir,
@@ -838,7 +866,7 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 #endif
 
 #if defined(CONFIG_64BIT) && !defined(CONFIG_XIP_KERNEL)
-	set_satp_mode();
+	set_satp_mode(dtb_pa);
 #endif
 
 	kernel_map.va_pa_offset = PAGE_OFFSET - kernel_map.phys_addr;
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-14-alexandre.ghiti%40canonical.com.
