Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBLH52GFAMGQEB627TXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E857441C783
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 16:56:44 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id s8-20020ac25c48000000b003faf62e104esf2585972lfp.22
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 07:56:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927404; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qy7CbI/RIwQmJV13ByW+qX1btRF1mFcwKUaw3IA6SMdfVn67oJAZPFLkg752xUt5/Y
         BeTxOGWbq7ymmxy49K2mtKAn7cd186t65cxOFi6BQ5TBYsd2VYg/OwPJAwujfUsCcl8a
         OzQcqxEAs/7gcrECMPFtN2zTVozdSkbd4wxLhiqkWCfNrKsAqKZaUY9Nx0nbXCTFCPmK
         NxD9j5G1b1PjBlOvnSNzhCgM2ULX0VcR+y8nGIXJdKeKatDeBhuULod65bZeG+gqbdWf
         Z2JzW5wgVOfcL6F6u7ugjIVw+t9rDPCA+Gitej2nWt4cQcppRSPtIxJK6ZEDNFszlB+G
         EUDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6bSaAjH7Dj7vQ16TFbebZuO6mrTRQF/pTke56CusqUc=;
        b=ArUQUnJRbhDTiK7ErYJlAVqtS1FfDSFG3VPy/6cZuZztfiNW1CyqD/ZRFa7naSX0G4
         8+mHGE7q4qa962cvy/wnmG/XCMNNpThZOVXF+Tfpqa9ySPNpAEkeWWe6t9+Wj/J/nk1s
         woA6O6M2rPw+n6Gjf3zKysuWC0lLAVMRz2JrS62fZzQF5uTwIdzAwnKnoPG44kJSp/R+
         p4HAGnGsoIyEKREyCdW6H7sqpOox/9mmkOJBkS/i7h0YhKIU9AcbXCapdSmJ1u++OBL6
         laKULNcFjbu/k5ks/phAWloNKfeT+7uNhUB9ax426umMue8TdUgFMXYymlwpiSSIHd1f
         YXGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=T+FceZn8;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6bSaAjH7Dj7vQ16TFbebZuO6mrTRQF/pTke56CusqUc=;
        b=FaF0bIs4O2OWv30cttsr4WmTP7tW36tvEDwmrCaHTNOxjzUdc+Ik34qFWVYoL/qLSL
         hx67L8aMahBwlR31sBZZyPzMoXOg5MgAnb6k7EKvTnR+bEU61U4vhO0zYq22Bu3Jj5uV
         G2/+Bu6mb6LNrd7zNVjjs6MKdq6rweYh5brK2550vwwUJ/4BfTlJtNvqncJfJ4y0z+rl
         BecvSuy/fhGIG3C37W+H7NfeCxeoqHUZzDS2IVw5UWIczILb3kD5SOy6hREjV5V67kXw
         /esAXl4WaWMTYclduOnaiIZsw586cmb0HW+VTCfIDX4CJvTtHsEcPzo24YLS6Md6jmJe
         Tx5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6bSaAjH7Dj7vQ16TFbebZuO6mrTRQF/pTke56CusqUc=;
        b=6apRzjvsZnE0KP8HXE7Allm7p2YAcLdZkdf9IeiWleFeueI8jZWS/WyInphkA07Y95
         nu4Nv8YG3dJa4CA6ABFATaXzJhxJYhc7Y17qXd7HCgrvHdkKSJP/cOuYcLUpM0dMdsZb
         /HBZK9I3ZJXITwrNh8F1i0nhQ4JpEBpKEAe6/zOnUOfzlCCitING8ob+lLZ+t0wT63FL
         LKizGO7WQ2vRFYh8aIE5XqcGBGJqwOhZ/UnaJX8dDveXfYW8mXt/uxUXSQzr0yUVKih2
         XP9UjcQPAcyH7QNjO3HSSwEHqJQBbr+szn6Nb5VU9L6/KFKl+2y068MYBH7OCxjSmfWf
         jCkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PbTNY4l9TDN9JzkycqEcSeN0YVONiGgYW35+yebWJcnesPB3P
	kUKHKlqz4etaEqu216QlTj4=
X-Google-Smtp-Source: ABdhPJzK/pHI0wRGGXRjbJ8IptL4mwBiv7IXt0ZtFCyILri3rivLhiYZdL8xEUwOF970VpDg2VVrzw==
X-Received: by 2002:a05:651c:231:: with SMTP id z17mr330429ljn.233.1632927404534;
        Wed, 29 Sep 2021 07:56:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a83:: with SMTP id q3ls582533lfu.2.gmail; Wed, 29
 Sep 2021 07:56:43 -0700 (PDT)
X-Received: by 2002:a19:c38b:: with SMTP id t133mr153002lff.196.1632927403694;
        Wed, 29 Sep 2021 07:56:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927403; cv=none;
        d=google.com; s=arc-20160816;
        b=xLDpaawPr+CgynHbbDq5N6mEznKUar4TqeEVvxxg6XckX02CmVERkLO/1UgTA5ZdJz
         Q5DhNsaG3RhPNgcfihmZWkcA1tM1hde4AVEutAsNrCi4rDGPmBAuH4YACC62SMPof9hS
         zsY0Ekp9XEQrT/GSjH/7YExSraILEK49Wu9c0MWiIO87HToI0WxtFLe2gDDdMZWYlvsF
         ej4ioVvtoxsBTy6Ja/X/AuiF1YwNxGC51C6kaLRfFDMRDxyyPgErn9bSi9Kgp4pDMDio
         Uv0DpY5ObVntl/47GCmMiCAdODhSzuTmVCD8b9NbtRjKhEUngvvVr4Jyq5fbBr2buan0
         Sx1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K1pTcCDambmk2cm1n6ZjEjTKGt45ssHjrCIqDxdL+pk=;
        b=ZuHDG3eHa+ZZXxdXqjYfpcCMnt2svXSoX0RvG9vCLTTqmDkamvqvn7MvICBh51BjoK
         VulgIbUotaLykKq3AsB6Ombd5+1ow+nXQFR782OCTKmHfU51gIJwvosqAIaXKVIT94zR
         vRET+ZxgAsBlyNSmFpvlFwfQZdBwu1xdUB1wSmARYahjM88Fu9QAYxXUhrkLCrZjYq08
         RdsLhu76QMlo4IBPEk7cnF80L2bloJfjMputEM/usAHs34bGBwp4Jys2uX9FizY8ZulT
         v9jiJV/niAnoB6HxIomxe9q8J7nWYyjyfnJbzpK4/FpGcsphR8ZOQx9NtyjeUJtPZw0P
         yD4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=T+FceZn8;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id t12si6464ljh.0.2021.09.29.07.56.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:56:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 4DE93402F8
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 14:56:42 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id n30-20020a05600c3b9e00b002fbbaada5d7so2818436wms.7
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 07:56:42 -0700 (PDT)
X-Received: by 2002:a5d:5986:: with SMTP id n6mr306753wri.75.1632927400961;
        Wed, 29 Sep 2021 07:56:40 -0700 (PDT)
X-Received: by 2002:a5d:5986:: with SMTP id n6mr306729wri.75.1632927400839;
        Wed, 29 Sep 2021 07:56:40 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id 25sm2117713wmo.9.2021.09.29.07.56.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:56:40 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@wdc.com>,
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
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Palmer Dabbelt <palmerdabbelt@google.com>
Subject: [PATCH v2 05/10] riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
Date: Wed, 29 Sep 2021 16:51:08 +0200
Message-Id: <20210929145113.1935778-6-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=T+FceZn8;       spf=pass
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
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-6-alexandre.ghiti%40canonical.com.
