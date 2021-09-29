Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBX772GFAMGQEQB3ETUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1173841C7BE
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 17:01:52 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id c18-20020a056512075200b003fd0e54a0desf1781542lfs.17
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 08:01:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927711; cv=pass;
        d=google.com; s=arc-20160816;
        b=x/9BcpSMpHyM/Jrpxe2cK+lR1vhR0hgCJgvyLqD9aN7lJgM/lSeyJIkjmD01TRnNAe
         1aDfIBY28sGAtFiXf+vFogtDhDkvkXR+G2MdAAWosMbBeLAmSr+j76bhlB5hHuacUW2q
         0ejnUpsC3aXqhwHwWJHdIDrOZKNkptv1ClQJzPwDHNHmq72M6PxxQ0Xn9dKIFICxZ1KF
         MvJUSSCM9h5Euju/ZlThnGuINe5/Ev0nogpQu3hvUsgUoiyteNeG3dqDM47uP3vh1Bae
         66xwS1mcz4Odsf7L1y+KnGSStxVrzpXOsbLnhUeLBX9mCVkJGSxzq0bhKAyWsZKG/a74
         mN4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3atajb/PVkB4/DCnEnr5iYOD98b22YdKY9TKCrBSVLI=;
        b=eNAfjSp2Uq1RwwZk0fvadjM7DhkQCBaLhAY3eyg7ygCVcrutb3uyeLo1XIJsuKFVjH
         NQxCBGLvcZghO/sqxaAY6vx780tsowUPlVx7/qSGwLcDvz1hwFsCTkPGcfC2bOWvEdnR
         dOcztRKtkJkaAVExYUn/M7cRCcxUA0CvkMJDu0Y78oumlCNpbLzfrezmncxVJSCKpTV7
         r5oWjlagXMS4tdI9UPtFcZBkBSo7luhLYVC1tCLGSowpU56S7FPxZ1/kH6HWDoZ8uxVh
         I0rCCkmweTekt/jXUZd1u56pGbncIPlA5pzHe+u9HRA5n0LuoW8QqwxM/jm6KLFPnw9U
         fpFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=a2QkUZeA;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3atajb/PVkB4/DCnEnr5iYOD98b22YdKY9TKCrBSVLI=;
        b=d9T47UIx1Zlx7JfkwtvaYvKBdpYYAA5WBGQMMGng4/ld7hBsSHY0UNP4kBIW8fHHNP
         Zy6fn84LSc+pUhIGG3W8/ej0aeTxE5kPHtHSeT2KxtUh4mfWGe67NHG3m7mOIB0W3dFf
         phRzcag0IIEU9cvsVW8HpwE4Fd4bM9ou3mnHkrPoW2S2iDoSLDdvHXpHmHIAqGs1ULZq
         fV/YUKC0iQsz7EV3fwvm0ak5W+FZrtkK1654eub6ue+aZ+jMGFRDGUDREbuUayAkBQE/
         OxqwuQuX6A3D6D6Hh9s8xiz8SDtt4NfrHRLStJhuaXh1/B+ecUhhA6nHGtzw7yt7Swda
         8pEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3atajb/PVkB4/DCnEnr5iYOD98b22YdKY9TKCrBSVLI=;
        b=6A2puQ2CbOS72LRHrFqkvADPddLyU28ukvlTkEEF2WuZz1bdwolAVAdC/cJEFmMUGx
         r0y9yobXTAaYBZQ0Gc62NPNzkc5OkFeS/YgFKsc4InyQD6zlZQyUuAOssXDjtWlPEC8L
         agNJ6VHWEGy9FA7P3i3VXhFekPk7/XnfqlFybBHVtPNksNxoJcZDj615fWFAAG4PKOdg
         Y8KeHnLKJcilZKWaJO3k6OS9Zdewiez6ylX70P7hhJcQuXp2URIf9Lh+rOe+BL63dMsZ
         I+d+fuyTJutCHPQ8nh6v11hZ/5drTT6xb9c4LNXKb/QVUDiku4ltoPUzERIa0QQ9K4+N
         mxeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335+5c87zsOuU0vRGGAq1Bf5GaNiNt8OsXxXOfpCBPJKtCb7x0b
	YjimVfJArGLyjf87N/JDEAg=
X-Google-Smtp-Source: ABdhPJwjbgijGfY3KtI+ZMvHD7G4ycHxrGQtVI3zGaaDV5F7CZC4VblmpJMQ4DQuxwY+hHhKj3ig+Q==
X-Received: by 2002:a05:6512:32c8:: with SMTP id f8mr113462lfg.683.1632927711277;
        Wed, 29 Sep 2021 08:01:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7f06:: with SMTP id a6ls104673ljd.9.gmail; Wed, 29 Sep
 2021 08:01:50 -0700 (PDT)
X-Received: by 2002:a2e:a37c:: with SMTP id i28mr405188ljn.76.1632927710024;
        Wed, 29 Sep 2021 08:01:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927710; cv=none;
        d=google.com; s=arc-20160816;
        b=SqHwqwdkjCH1HkFUSu2goQV+CWLUkKjWcvId1rzd8Pt9mRifIls5O1vxmNmCFmRkSN
         DJ0DBMbxakRmqh3SF1MT6OpVXCuN2Zo8h+ztnPGzJaEKrBKbMTFMMa/6usNxyjkVT8ww
         xLYDzJQ/2mYpnOwGTaPjiyEjoXCXCAGQf3IOC74EJw4+oaajmh0VO5j2XdnDMD1OgPTh
         dPZbu1wi2lqfgAmlCGq6HRjUPiAFVg11EN0z0TXgl1Jvpno7zOeEkK67q5LvjL00ryCA
         Rj3m/zlOI8YD85DK5f8Jcp3UrT7NcgwFCo/rQiBt9MRHA7fORzzDhJOdF7xYzMo6iRsG
         Iakw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZHeeeZbiilEHhtw/jMIzJY6AU5jy7F+74b86hE2E++U=;
        b=eOsJ9Fs0WeKpf0Sj8Km2F+q/eVSxRn5onFiDRyqvH1G/lZjFFMymvXVQUlRWHIdXxt
         hqSyYuxIDQhYphW3Jl5Ob23Z6uC3cpiPfIDYJf+duQ8fIl9d4OJpNGz2D6Ce0wmqLQNJ
         xnVCjZJ+qChpuI07bDQHw203J3Ypw5Obr91cwF4J34JaUQ9/cGqzpCejIPSReHYwZwsP
         JGiyNQAKPTxv+sTI9dR874KxwOnJmwllSzf4J4uAAZF6RILmO+iBooP5NY346fm5Hpai
         aPxG4nWlRcqJPSUDqRyLjhsy73zc0RZgL613VJNzOii793VycO7vXEQcrSJiTxUtrzRY
         zmaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=a2QkUZeA;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id a3si6112lji.6.2021.09.29.08.01.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 08:01:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com [209.85.128.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 557FE40255
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 15:01:48 +0000 (UTC)
Received: by mail-wm1-f70.google.com with SMTP id j21-20020a05600c1c1500b0030ccce95837so948806wms.3
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 08:01:48 -0700 (PDT)
X-Received: by 2002:a05:6000:2c6:: with SMTP id o6mr377138wry.292.1632927708044;
        Wed, 29 Sep 2021 08:01:48 -0700 (PDT)
X-Received: by 2002:a05:6000:2c6:: with SMTP id o6mr377109wry.292.1632927707834;
        Wed, 29 Sep 2021 08:01:47 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id h18sm133008wrs.75.2021.09.29.08.01.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 08:01:47 -0700 (PDT)
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
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v2 10/10] riscv: Allow user to downgrade to sv39 when hw supports sv48
Date: Wed, 29 Sep 2021 16:51:13 +0200
Message-Id: <20210929145113.1935778-11-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=a2QkUZeA;       spf=pass
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

This is made possible by using the mmu-type property of the cpu node of
the device tree.

By default, the kernel will boot with 4-level page table if the hw supports
it but it can be interesting for the user to select 3-level page table as
it is less memory consuming and faster since it requires less memory
accesses in case of a TLB miss.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/init.c | 25 +++++++++++++++++++++++--
 1 file changed, 23 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index a304f2b3c178..676635f5d98a 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -641,10 +641,31 @@ static void __init disable_pgtable_l4(void)
  * then read SATP to see if the configuration was taken into account
  * meaning sv48 is supported.
  */
-static __init void set_satp_mode(void)
+static __init void set_satp_mode(uintptr_t dtb_pa)
 {
 	u64 identity_satp, hw_satp;
 	uintptr_t set_satp_mode_pmd;
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
 
 	set_satp_mode_pmd = ((unsigned long)set_satp_mode) & PMD_MASK;
 	create_pgd_mapping(early_pg_dir,
@@ -802,7 +823,7 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 #endif
 
 #if defined(CONFIG_64BIT) && !defined(CONFIG_XIP_KERNEL)
-	set_satp_mode();
+	set_satp_mode(dtb_pa);
 #endif
 
 	kernel_map.va_pa_offset = PAGE_OFFSET - kernel_map.phys_addr;
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-11-alexandre.ghiti%40canonical.com.
