Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBIOYW6GQMGQEJPLDJMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E711D469479
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:55:29 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id k10-20020ac2456a000000b0041bd7b22c6fsf1560141lfm.21
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:55:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638788129; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z4W5goyHjZWs/m0QMRpqP3BXuw+EBtm4knKYFbAz4lf9hrQjnmLj4kub8ny2+7wuWl
         3r58ZsB2gjoxU9m7G5J/WpftAKC/kmrHN+8uE2Wvaodd10eAgxDRbiNBzwcBXjWpom+O
         /Sl2vZypCMFrZd0M2pg2pGjgpDR+Cgo6ibVFtGihwt7XpgTrcKTjigFCvz4gixWw1J3v
         rA7yS13r76SjYBS0K3Ci88OJCORRndnQ+4994HViBp+jqd2IBys9vbdp/tLReb/8tH4O
         1nJZwgIf0GGIEBNN+MXjgrOhCqD/zonU8NOh8/sMT3LNGEt3fy+d8D0+thxWl9pIr0jc
         iywA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iLPPw7ip3+d/Dek/CSumIL2YURYKfmiVwexfp+bHIjg=;
        b=RojwbVVLOwzjqrI0IwQpcM0dXnoWHw0jvYa1IoPIoRQ95e6sIGfEJNFghff1TOmDFn
         oF0j4i7/s1LumxwzJFO70oBGQCgf4eWtfA0wl+n92i1GpVWvi0lyx9K1pHifmXbpaDs9
         y2QD1bxOlgklbCbOSUeZkuY8AGaufaUBPN+jXBHgKJSaF7tTGHLhuC1Sv7O9skY9wQn7
         IxMClI5O8yMzhK2gcRLFUQMrpuiLuRBEfCZU3dvLiUNiKpFdR9+FcTEEe+1AhLdMn/Bs
         5TiYPLEFvANdp2nlnY/MO/l9VMEKBdNkw7W5W3GauYTNlYppYcerJiEyQjpX9OBUJ3IX
         jZeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=XDfI6ZcY;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iLPPw7ip3+d/Dek/CSumIL2YURYKfmiVwexfp+bHIjg=;
        b=VtEIGA5lkAMiO5+M0SQFFXxYrcRO4d1Lt39wQxyzqm6ecD3SG9UzCk8Sa9NBSFZ73g
         YNASWOQ+sOkYmMwSnhPSmUbRIVGX7moHtLcZytMhKJk6noPpG9ZkL8Zp8VL4zQH/JVZS
         QgmCC+qcpXDBFUurQan+L6sEX/1p3F3W+I8Tie2q1Yz8KMiI7xS00Rg8P6hEfxrWski6
         zPbr333sOROKKTswJi1PbZ8Vav0DDfFRbTlf2WatupUpjj+7qVfQ6Ocq6MDp5udapga8
         syvny9WqTDOcshjgEBiFadozKJLXm/0jYxsy5ywfXeZs3G5JMYEYun9y7wX0sbj5bJ/o
         1liQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iLPPw7ip3+d/Dek/CSumIL2YURYKfmiVwexfp+bHIjg=;
        b=bfJlud44cDrdla+4n3UONlXGG2WrizuQR727EJoI3g+oumRrFM1prCNWQsMlBDqSHz
         pZXKchIUQGL382TwGM/8SXF4++wraTpXzkStjf2WGBsWtFzsxfhzwkaP8wgPVKjxDoSe
         oraCrUUuudQ8es1QuaqAZo/WSc7vyonizW7Eya9AwiSdGHZQ81GFGIFuqSxR8sjlJHsP
         SYj0uZo/iX3STzWuJsFLgbAFsvUpoWqw32TeofzsfnGsM3gA496353Jj1gdtq3WmU+6e
         mOuXc1tobwda3dWE1WiFt2/XRFiIjbU7rnEKlEGQOb5FP0MAlOral+86mQO4TFyQoTUN
         MQMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319vGlG3QC0KK96FciTBwj/ZzM5JOVg7SoyodH7gT74MyIpUOPA
	DhyFkNF7Ty9W3PMzf6aZC9Q=
X-Google-Smtp-Source: ABdhPJxBp1sNFD6FiT4ZXKXSAnk4suFgvMdUD/P1ApzIsNiH1pb/wH5D6ptmJ6sU9EsinAyjYxT4og==
X-Received: by 2002:ac2:5a0a:: with SMTP id q10mr34917591lfn.610.1638788129503;
        Mon, 06 Dec 2021 02:55:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls701217lfv.1.gmail; Mon, 06
 Dec 2021 02:55:28 -0800 (PST)
X-Received: by 2002:ac2:454b:: with SMTP id j11mr33998143lfm.41.1638788128549;
        Mon, 06 Dec 2021 02:55:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638788128; cv=none;
        d=google.com; s=arc-20160816;
        b=xRn1+IwEgHIxdJJG7DkcpJXaVCDSsxP0An3X+6MC0znub3LI1XihhLR/2oSks6zsa3
         dWko2Ymr4DBrCyug8y11wekbKTCyIRHj5kWM9Q6gWXECuAz5MAKWksebthy8UVsW5POE
         oJ7Dc42z4+pwr9KoN2SOYAcGjDUExGaM6YPL70BmRxpfXKqmMsCtV79JFlB436ZLKZJ8
         DdjCg/P6BdcVJdkZBsIt6xLncO88Uu2z3eHbIBcySkalU5T3qgVIO0kBBtoAXEDit6cG
         sK8VY+dVGjSOWPtM3n8weFTAQH21ghMILEJzf2Gv9V1YXFJdNrODDByMq8IyygLFzof8
         dnqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fBYZyvFhkAhfEVEwW97Oqj/gTwgmisupm0BTu4ieBtI=;
        b=aBBMryaJOtoJfZ1RFlOez2ZPqwPqcsyRmbHBmvd9nbn6eruJ7ZXxOg3bQFFa4pXnQ3
         uj1xtC3G5272ChhrsZlLwgWhefXohi1R+uhiSkCSVgZCfFjXhU7brkBggCAN6E0r1QPY
         XRLjkM2CEgbEBoTb1AIYbKVVimnY4SGOO3DkjXHzyV5lje2wAx9Tdrya6LdaWBWCEYHr
         dTH1zoRVfXxjSj0OWrEkAmp+b5yKkUX8MoQd1QOAr2Sr+F3oFkbRlisxm7GfGBncIFIh
         lPG7l5sRqruXg4zi+nqGmNVJn9XO/Im3fatzVe9Qj2JCAFIfPka76bcoPPBArf+ZslQ8
         FWRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=XDfI6ZcY;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id g21si771808lfv.11.2021.12.06.02.55.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:55:28 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com [209.85.128.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id E8A543F1BC
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:55:26 +0000 (UTC)
Received: by mail-wm1-f71.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7so5920856wmj.7
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:55:26 -0800 (PST)
X-Received: by 2002:a05:600c:4104:: with SMTP id j4mr37911665wmi.178.1638788126596;
        Mon, 06 Dec 2021 02:55:26 -0800 (PST)
X-Received: by 2002:a05:600c:4104:: with SMTP id j4mr37911644wmi.178.1638788126387;
        Mon, 06 Dec 2021 02:55:26 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id o4sm12657395wry.80.2021.12.06.02.55.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:55:26 -0800 (PST)
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
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Palmer Dabbelt <palmerdabbelt@google.com>
Subject: [PATCH v3 08/13] riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
Date: Mon,  6 Dec 2021 11:46:52 +0100
Message-Id: <20211206104657.433304-9-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=XDfI6ZcY;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

Now that the mmu type is determined at runtime using SATP
characteristic, use the global variable pgtable_l4_enabled to output
mmu type of the processor through /proc/cpuinfo instead of relying on
device tree infos.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Reviewed-by: Anup Patel <anup@brainfault.org>
Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
---
 arch/riscv/kernel/cpu.c | 23 ++++++++++++-----------
 1 file changed, 12 insertions(+), 11 deletions(-)

diff --git a/arch/riscv/kernel/cpu.c b/arch/riscv/kernel/cpu.c
index 6d59e6906fdd..dea9b1c31889 100644
--- a/arch/riscv/kernel/cpu.c
+++ b/arch/riscv/kernel/cpu.c
@@ -7,6 +7,7 @@
 #include <linux/seq_file.h>
 #include <linux/of.h>
 #include <asm/smp.h>
+#include <asm/pgtable.h>
 
 /*
  * Returns the hart ID of the given device tree node, or -ENODEV if the node
@@ -70,18 +71,19 @@ static void print_isa(struct seq_file *f, const char *isa)
 	seq_puts(f, "\n");
 }
 
-static void print_mmu(struct seq_file *f, const char *mmu_type)
+static void print_mmu(struct seq_file *f)
 {
+	char sv_type[16];
+
 #if defined(CONFIG_32BIT)
-	if (strcmp(mmu_type, "riscv,sv32") != 0)
-		return;
+	strncpy(sv_type, "sv32", 5);
 #elif defined(CONFIG_64BIT)
-	if (strcmp(mmu_type, "riscv,sv39") != 0 &&
-	    strcmp(mmu_type, "riscv,sv48") != 0)
-		return;
+	if (pgtable_l4_enabled)
+		strncpy(sv_type, "sv48", 5);
+	else
+		strncpy(sv_type, "sv39", 5);
 #endif
-
-	seq_printf(f, "mmu\t\t: %s\n", mmu_type+6);
+	seq_printf(f, "mmu\t\t: %s\n", sv_type);
 }
 
 static void *c_start(struct seq_file *m, loff_t *pos)
@@ -106,14 +108,13 @@ static int c_show(struct seq_file *m, void *v)
 {
 	unsigned long cpu_id = (unsigned long)v - 1;
 	struct device_node *node = of_get_cpu_node(cpu_id, NULL);
-	const char *compat, *isa, *mmu;
+	const char *compat, *isa;
 
 	seq_printf(m, "processor\t: %lu\n", cpu_id);
 	seq_printf(m, "hart\t\t: %lu\n", cpuid_to_hartid_map(cpu_id));
 	if (!of_property_read_string(node, "riscv,isa", &isa))
 		print_isa(m, isa);
-	if (!of_property_read_string(node, "mmu-type", &mmu))
-		print_mmu(m, mmu);
+	print_mmu(m);
 	if (!of_property_read_string(node, "compatible", &compat)
 	    && strcmp(compat, "riscv"))
 		seq_printf(m, "uarch\t\t: %s\n", compat);
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-9-alexandre.ghiti%40canonical.com.
