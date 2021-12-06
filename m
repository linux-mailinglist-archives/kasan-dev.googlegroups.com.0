Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB2GWW6GQMGQE7AJSV4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 887F9469456
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:52:25 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id p18-20020a2eb7d2000000b0021ba3ea3c42sf3264538ljo.5
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:52:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638787945; cv=pass;
        d=google.com; s=arc-20160816;
        b=vz946ajSjA8CF4/LYjix2FXyVpGvryxcfz90ysWJkr2DfIyHI2Pxz4kqjxaL54mqvG
         RprgbtXjjMvtfhCr95E/u1dwOO+fXvgf3PegRV7gco9lCfcAw9GWuXDi9rkMWEq3s4E2
         b4v0rdau7lH06VciK24j0a5+UmUR55smlDSrlnMslxgegJnNOidHR0uuCNEU/4HUOdSo
         aGxiPIx21qmB4Q8Xt20qX7DnQX4j/HENAQG+wncEnbiXL7U5govwnjSG96/Z4EMoY8ol
         OuJn2O/NDBrkCklGOz+ReKxAcfAkS64jzKHLWL8zA1WJyWqFox0NcmYld/d3pQEPJTWF
         2vRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QwcnL3oKR0mVXnxzLPN9J5Jrru6CzjJBnofAdWQQ4ag=;
        b=csDZZhfztTwa/HAJPeFo8s8+IhhTnN0rib1Mb3Rs2zeWr0dFWx2V745h9FPoVdFDPN
         g6jsDI/4j1ybc8KCJzBQq1Lw54dXhSSvgTcV70AcOWzBMpP5zJEdqIVlDRh4AGRKZpII
         gYn+yEVqZHLBSPYx4H0I4IjFGdyobJ1f6/Ah8MMpW/byNONcl8hPHwV5+JYswktxiO6Q
         Qxf6AUpw9vHlZA9ImtjnLfAEbnL1/t2ASSm46xJQfvk+6UlwkEBTaxI5Vk0fiY/pncHj
         xDRKwvvYYCjemPfE+VTr4LIH88YSJUQag8QeJBCKRb0ZMdH/v7N6sNssHM4y5tjWl9CH
         v1AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=UYaXq9O6;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QwcnL3oKR0mVXnxzLPN9J5Jrru6CzjJBnofAdWQQ4ag=;
        b=TRrYGcm2VNMslOnhmaPWX2utqYjJNwFh2wmpPYay6j8xsRSR6kTyJiH62+lxmaPEWJ
         iYFYyRu+sWJ7/EL1YW6UkKo/ZCIVp74HsNX+/NJfvrtURE0ykSXysbXdl9Zejrasuzb9
         yUatDhK/i8g1OD63/ZhskYU+fKPrRPD0RFkayg2yvuesiWdanqyy3kuUyxre/zq0f6DJ
         2rIZ7gK/4ivEDef5dekWefmqJPd2tqjEnk1+E4awN8R2MkaHCAqaGNmCyPMGH+5ud9xJ
         xL5H/yQAU5JzdSHfeW44oIAgh8dOU5g27w0ybakjo232cvoI9EZuEfvixgN7VrlfQZAB
         NRgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QwcnL3oKR0mVXnxzLPN9J5Jrru6CzjJBnofAdWQQ4ag=;
        b=EGtgrztI34za7fWiZM3pfE+EGl6Q3NpFLtWPdf10LQE3i3psUyNdfE9JVtOJxVMfUl
         pM0Jw8WrNNUgvxhgLHbIwoVkdCW15Rljb10F1tmTmWV5AmbvQzocn0JsY2eR2YEZL2/p
         AOb/p1EHn1J0iqiY32wVLFbQYeR9hfacVM6nUyje4A4LczUhLt9+T6sqDMz3OnLXTIxo
         SDLE7x2vSq5o4Q2iT3ozMILR+iWcUFIjTy8juJfsp8P7ZcZQJZH1g4PPrJg1tkEgA62p
         Rjxen2fEiFy2X8FSIFhuhS+QE4i7+g78n7O2txQLhwCI4QuGm58Sb7IodpgivBYORiYk
         wUaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533AHKQsKBMJXNaPJ5SQgYs0u/bho1kld08F1f5nrvdC4/Vzg7uX
	F98YGQnlHDtoau7Z4bzLHq4=
X-Google-Smtp-Source: ABdhPJxsUgA8uJFpGfraojexTqy6e/8Pd7f+ZA/JR8IaEAuwsZkHO3AFVqMeVBiw2CHcLt9nCrTPbg==
X-Received: by 2002:a05:651c:1411:: with SMTP id u17mr34924922lje.483.1638787945105;
        Mon, 06 Dec 2021 02:52:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls695511lfu.2.gmail; Mon, 06
 Dec 2021 02:52:24 -0800 (PST)
X-Received: by 2002:a05:6512:3216:: with SMTP id d22mr35037640lfe.604.1638787944146;
        Mon, 06 Dec 2021 02:52:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638787944; cv=none;
        d=google.com; s=arc-20160816;
        b=p4JHm2HLX31P7+Vhz9mIWtGK75JN/An0vhxY94TfsXmfiJgR8IIOO70XgG2iSADLa5
         0ig9ozZyLBcS3CLQBrwwXP1LNPNBozrb04m4/Zv0I37Qvq5YzxYzgK1MESfFI1g9r+Iz
         6RzkLe/GSsCU2apvzJH8pvUoqkDaOpw+m8hl5ZXCELFfKeCsSn9NEhV7CwzEJjje0gUA
         62b49th+5GHnrgzPAko47M17Dh6SCU2JpgaUlODTO7Dn3fP2B04YekXDz9XbN4ZIzF39
         X4Pm/9c+2EKvG5L86CSUZt0jFIZdPoBXNvvrCKL7knN0enGr6hUaiAQby9O3DgoRKY2V
         CC0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9ySCV26avDqOMq3ybehcXkQhwvvZ5wxe1+MhhnplIPU=;
        b=w0gda68QL9Sl5XLPy5Op14Z3m+v5ACxSeDgmb95WC1G9QakNrcTLV57x0h9n3xijdU
         r1xsfDV8uJafpQ5mX1+7RPC5HgS4f4A9k1HR9BWOitXWTSf9e5e2Gzwp/Ptnt8z5B2mT
         1uEtDxOupfvyHdzXa34TiaIW3mvMbDs4Hm2XsIVilShmzSry2SlWCQ3WGwx7IiqJGMOZ
         n7tt1/Rr+yG3LWSUL4Cpl9Zeq4YmUJHTUlI3Nw1SRCdZx23YIAb6fqaz8ALjAXp/+CXE
         B9LYuRSXEsnZzuR2YM0D0gVNTOCH6LGfeLDuGYc8S4mpLBmWMLNEJX9q2gjlxkRcLrTL
         jUbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=UYaXq9O6;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id k26si261785lfe.10.2021.12.06.02.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:52:24 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com [209.85.128.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 39FE54003C
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:52:23 +0000 (UTC)
Received: by mail-wm1-f71.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7so5917429wmj.7
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:52:23 -0800 (PST)
X-Received: by 2002:a5d:6acc:: with SMTP id u12mr41541833wrw.628.1638787942764;
        Mon, 06 Dec 2021 02:52:22 -0800 (PST)
X-Received: by 2002:a5d:6acc:: with SMTP id u12mr41541802wrw.628.1638787942625;
        Mon, 06 Dec 2021 02:52:22 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id l2sm13828074wmq.42.2021.12.06.02.52.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:52:22 -0800 (PST)
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
Subject: [PATCH v3 05/13] riscv: Get rid of MAXPHYSMEM configs
Date: Mon,  6 Dec 2021 11:46:49 +0100
Message-Id: <20211206104657.433304-6-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=UYaXq9O6;       spf=pass
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

CONFIG_MAXPHYSMEM_* were actually never used, even the nommu defconfigs
selecting the MAXPHYSMEM_2GB had no effects on PAGE_OFFSET since it was
preempted by !MMU case right before.

In addition, I suspect that commit 2bfc6cd81bd1 ("riscv: Move kernel
mapping outside of linear mapping") which moved the kernel to
0xffffffff80000000 broke the MAXPHYSMEM_2GB config which defined
PAGE_OFFSET at the same address.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/Kconfig                            | 23 ++-----------------
 arch/riscv/configs/nommu_k210_defconfig       |  1 -
 .../riscv/configs/nommu_k210_sdcard_defconfig |  1 -
 arch/riscv/configs/nommu_virt_defconfig       |  1 -
 4 files changed, 2 insertions(+), 24 deletions(-)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index c3a167eea011..ac6c0cd9bc29 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -148,10 +148,9 @@ config MMU
 
 config PAGE_OFFSET
 	hex
-	default 0xC0000000 if 32BIT && MAXPHYSMEM_1GB
+	default 0xC0000000 if 32BIT
 	default 0x80000000 if 64BIT && !MMU
-	default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
-	default 0xffffffd800000000 if 64BIT && MAXPHYSMEM_128GB
+	default 0xffffffd800000000 if 64BIT
 
 config KASAN_SHADOW_OFFSET
 	hex
@@ -260,24 +259,6 @@ config MODULE_SECTIONS
 	bool
 	select HAVE_MOD_ARCH_SPECIFIC
 
-choice
-	prompt "Maximum Physical Memory"
-	default MAXPHYSMEM_1GB if 32BIT
-	default MAXPHYSMEM_2GB if 64BIT && CMODEL_MEDLOW
-	default MAXPHYSMEM_128GB if 64BIT && CMODEL_MEDANY
-
-	config MAXPHYSMEM_1GB
-		depends on 32BIT
-		bool "1GiB"
-	config MAXPHYSMEM_2GB
-		depends on 64BIT && CMODEL_MEDLOW
-		bool "2GiB"
-	config MAXPHYSMEM_128GB
-		depends on 64BIT && CMODEL_MEDANY
-		bool "128GiB"
-endchoice
-
-
 config SMP
 	bool "Symmetric Multi-Processing"
 	help
diff --git a/arch/riscv/configs/nommu_k210_defconfig b/arch/riscv/configs/nommu_k210_defconfig
index b16a2a12c82a..dae9179984cc 100644
--- a/arch/riscv/configs/nommu_k210_defconfig
+++ b/arch/riscv/configs/nommu_k210_defconfig
@@ -30,7 +30,6 @@ CONFIG_SLOB=y
 # CONFIG_MMU is not set
 CONFIG_SOC_CANAAN=y
 CONFIG_SOC_CANAAN_K210_DTB_SOURCE="k210_generic"
-CONFIG_MAXPHYSMEM_2GB=y
 CONFIG_SMP=y
 CONFIG_NR_CPUS=2
 CONFIG_CMDLINE="earlycon console=ttySIF0"
diff --git a/arch/riscv/configs/nommu_k210_sdcard_defconfig b/arch/riscv/configs/nommu_k210_sdcard_defconfig
index 61f887f65419..03f91525a059 100644
--- a/arch/riscv/configs/nommu_k210_sdcard_defconfig
+++ b/arch/riscv/configs/nommu_k210_sdcard_defconfig
@@ -22,7 +22,6 @@ CONFIG_SLOB=y
 # CONFIG_MMU is not set
 CONFIG_SOC_CANAAN=y
 CONFIG_SOC_CANAAN_K210_DTB_SOURCE="k210_generic"
-CONFIG_MAXPHYSMEM_2GB=y
 CONFIG_SMP=y
 CONFIG_NR_CPUS=2
 CONFIG_CMDLINE="earlycon console=ttySIF0 rootdelay=2 root=/dev/mmcblk0p1 ro"
diff --git a/arch/riscv/configs/nommu_virt_defconfig b/arch/riscv/configs/nommu_virt_defconfig
index e046a0babde4..f224be697785 100644
--- a/arch/riscv/configs/nommu_virt_defconfig
+++ b/arch/riscv/configs/nommu_virt_defconfig
@@ -27,7 +27,6 @@ CONFIG_SLOB=y
 # CONFIG_SLAB_MERGE_DEFAULT is not set
 # CONFIG_MMU is not set
 CONFIG_SOC_VIRT=y
-CONFIG_MAXPHYSMEM_2GB=y
 CONFIG_SMP=y
 CONFIG_CMDLINE="root=/dev/vda rw earlycon=uart8250,mmio,0x10000000,115200n8 console=ttyS0"
 CONFIG_CMDLINE_FORCE=y
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-6-alexandre.ghiti%40canonical.com.
