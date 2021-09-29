Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB4X32GFAMGQED43HLXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A1D341C760
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 16:53:39 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id z9-20020a0565120c0900b003fce36c1f74sf2622840lfu.9
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 07:53:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927219; cv=pass;
        d=google.com; s=arc-20160816;
        b=SMSh0cGQy16Clg5BaTU8b45Nlp326qfnfEcsHgEaT8EhlT5xL1roEaRZjzkQj85XQj
         9OCjcmvutGnoRNDFZRHmg/6jxYq9QMQ95H4cioKThK4hw3HbBl3cBtOhKjXTV6hxTTVN
         R0Wmm+6cnKYAbR+0wWSptv3s0fOIjLxkdcz5T/w6V2ORwVKtik/oeLDbiQ3R+ST9DOfT
         Ca56ysicwo//JWzZMzE91eAAQBBAjfsO2fU0M2gEzinZZvVatyZGWKE8oLaa10G2+mCX
         xfHoAtHkbtou2RgiiT3rGgxao9rChJP7Ge7+zaeJdFlwatlyitXs9T6rIJDekKtQgf0z
         gscQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6xalc9lKmfSeoVt0yEEdocVfGz+MrVMe5EAWwYqeZ2s=;
        b=K1u52XL7UkngmL2Z/iPrxrlfXUrAABz3n3gL43pH0uEPToT5Fk7dkmUPQbzwyU+CM7
         2TLAi/M0FWh1pNJwn66skn7/kC0Az0lF7M1QnHaWIQU2aj9mvQ27TtKAZdqJth4/fOSf
         yOAdcA4yil7kS1chq8xOD+56/VnXXHJxtot2Ovufd+w+AxoVNSwttioWgV/a9Ep657c4
         wDO1k03a+s05Fw2dRXQdtoChG4mBVkQrSR6zIdSwFoi6vcj2Nez6k7K73VYKa9azZXYh
         4O0Z0lWSVlPNguwBjLwNU4mXUTD6MJ4HlaWtN+s+/mIGFd+DFq/JTeBaA4f+k1y2wJX+
         frDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=Nnsvahvh;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6xalc9lKmfSeoVt0yEEdocVfGz+MrVMe5EAWwYqeZ2s=;
        b=lYHCs6myWBSPSglp42TLrUWcRYW0jJIfw3v1qiiZD3RK/TvFSBRkR4t2fQGlkcDmKl
         fZZyQLIxHSVm2DlnJ5KuFL4eAc+UCk0KZXhBtUQK2imQ24cROkXni18ariLmt5Q00+3J
         99A5xA+fMtJvp6Zu6dtksyVLc00FraGdQU9M7z37hskEvXwXeRxY9KeXJX9GrTKL//US
         1fCzQzwGdLrXcYlVli25CJ9qoBaAul5jnRbDnoDEVmP1rYyhAuauIIa3odm6LJUJpUm5
         FCL0dz3iY618N6OmDDav2UYoyDUwrDwusq4BJp3RpDCTKjNzs1xuCZfUzIhCMPcSXFUI
         wY9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6xalc9lKmfSeoVt0yEEdocVfGz+MrVMe5EAWwYqeZ2s=;
        b=e5h9eHG2NowtywLToYZ9YKT+VoAFeesyFib9SyDpkncj6L/sDMS4KZaD9pLLg7rnnF
         3wIGQCpm8icTSCDR4S1iVpnYGHl19JDm84sSo5HjedK7krFh7Jz0ltmLYaezmCHFtcDG
         PYZ326TkPMBvgsApvbVupm2fzIbMYuM0Dj3x8/JEYsfle5QeUbfKvvMfWtNdxEdXomMi
         0jzvzgPyEju4zja2RwnfAIlHLz+AYN/rhRgWYOebAZYZRo9vG7T/laQikvcnjJJ+mZon
         9gNivMEokvx0DglYeHiBpv7B4tiMygbTi9JaUZ/rYMqvueoFRN7/QYgEqFhmKNmnZt9q
         rReA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5301EFOUVTxUl61fx9r/HWKzy2vZscHfZWWxSlw5thsxjwQxEAHn
	d0g1nK2lEwPAVTK25jCZIcw=
X-Google-Smtp-Source: ABdhPJw4ZWS2o63zQmZAoEVTAjrJ7dqN5jSjN+QRTcZgz5tFgUq4yPSj3nfhTHNqy6GxN6/qDVCWJA==
X-Received: by 2002:a2e:a78d:: with SMTP id c13mr338756ljf.75.1632927219000;
        Wed, 29 Sep 2021 07:53:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f14:: with SMTP id y20ls576274lfa.1.gmail; Wed, 29
 Sep 2021 07:53:38 -0700 (PDT)
X-Received: by 2002:ac2:46c8:: with SMTP id p8mr139501lfo.158.1632927217972;
        Wed, 29 Sep 2021 07:53:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927217; cv=none;
        d=google.com; s=arc-20160816;
        b=SN3eWqecpikVcbNTFmlUcFPJ8sVe6QyEh/6Niwj4rz2cP1vOjxez+icxFK0ZT+hUHB
         Q7vwB3yu4oQEqwO2BRhdAFIAWNHQ4lKOSXxx6viN1fkAaWtdeACgjK2EQTurVv8casEQ
         62VR31wEenvt7eqG/r1ti9yNG1DGeTUk3KrgUK99FHvIQ4yaBLDXLf1J8byJUJBPH3Rn
         XA91ZX0vecEPHzhtaGFZ4SytyfVoeAKGj3A2GAs3OdHadHttwbBFtY74Q4xMzxHaCodo
         q5u+wLa61Lf/jRVcAGbJS8ziDl6Q7jBnPNbbRP333mpe/OVNGXUoJp0zCuV6YSCy70IS
         jvgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=omlMO8oiSqY28NQ++6IIM/VRVI4+XjHYuKkKGp3z8ks=;
        b=HpyxEYFdun1WCz4P9G4ezNxd+yb43CkLjzogZA2BorEXofrqMxcRYHEhjaRUzfAGIK
         qVTscAk47WKl3zroaq+twgquowTaLnfOq/ypmvinCir+LaqCTqJozpdSxRfHJFisSbh2
         BrGgYyjITsD6Norf1e+MCG1nNbzFv+iIJWx0T4OoRpwd5CcPlsGAlgnM5V9m34ojTpfE
         f/SVOD0No7IWPqiSE0ZLOh085I6FVztOyKADvSaxkAGxiyznF0MukM1k/rXJZgU2UKxK
         wdIW8laZ5inaLjByt7z1W50cDTV8/c4GTyKzqFxqRLO1qvZB6gBwbMXozw3vKdULtx9V
         oHcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=Nnsvahvh;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id o4si3699ljj.3.2021.09.29.07.53.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:53:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com [209.85.221.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 0E7A8402F8
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 14:53:37 +0000 (UTC)
Received: by mail-wr1-f70.google.com with SMTP id j15-20020a5d564f000000b00160698bf7e9so693110wrw.13
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 07:53:37 -0700 (PDT)
X-Received: by 2002:a1c:7e48:: with SMTP id z69mr6608697wmc.95.1632927216596;
        Wed, 29 Sep 2021 07:53:36 -0700 (PDT)
X-Received: by 2002:a1c:7e48:: with SMTP id z69mr6608661wmc.95.1632927216369;
        Wed, 29 Sep 2021 07:53:36 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id g1sm2428205wmk.2.2021.09.29.07.53.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:53:36 -0700 (PDT)
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
Subject: [PATCH v2 02/10] riscv: Get rid of MAXPHYSMEM configs
Date: Wed, 29 Sep 2021 16:51:05 +0200
Message-Id: <20210929145113.1935778-3-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=Nnsvahvh;       spf=pass
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
index ee61ecae3ae0..13e9c4298fbc 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -147,10 +147,9 @@ config MMU
 
 config PAGE_OFFSET
 	hex
-	default 0xC0000000 if 32BIT && MAXPHYSMEM_1GB
+	default 0xC0000000 if 32BIT
 	default 0x80000000 if 64BIT && !MMU
-	default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
-	default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
+	default 0xffffffe000000000 if 64BIT
 
 config ARCH_FLATMEM_ENABLE
 	def_bool !NUMA
@@ -256,24 +255,6 @@ config MODULE_SECTIONS
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
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-3-alexandre.ghiti%40canonical.com.
