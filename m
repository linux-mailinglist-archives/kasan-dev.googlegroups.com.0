Return-Path: <kasan-dev+bncBAABBX5MSCSQMGQESOYTWFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 01E6F7471D0
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jul 2023 14:53:54 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-7868ec37aa7sf52956039f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jul 2023 05:53:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688475232; cv=pass;
        d=google.com; s=arc-20160816;
        b=f5dfck1PP1lbQV/s2QMia06t7MC6oKMrj5Vq5dndMnYDMJVMT+NHaI21x237UyjMWM
         T0eRT3Np1QUC4GYoBFmpQ6K6KoKN+ThjDpsSmivm+GA7izRJ3hRu8Ou9lgC5Z9w0Wyx+
         oboVZsPD5dptTJ3O7WaAu7ZxjMN8OE1R+iyhH90Qr3xu7X6tbNG7OAVCTeDdn+3Bgf8Z
         +Sr8H04ot3A2Spu9txPUyfZriJvjsTMCTlYCHxUTQBi9eYa47w421Uwr5vR4qG8AmjDS
         sRG5iv7/J3q9JoWRivfrtZNg8JCIfwc0XCJyY7x4utMhp9XapPpz7PZ3XNJgovgXWM83
         rpZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CpVaS/KPO2Xql+u1j9Mm3ELwth8SncbcfL3VaTI6LeI=;
        fh=RwV5KzEavdxvCtZEIU9FQTiL0UHz0DnVYX3zSTzIiiQ=;
        b=ITHziCBA0b7q0/MVsTOU7XawlCwyfVe8ryI7678vPQ0K6N4Ho2QPUbqEnDsW6X+Haa
         /5r05JQry6k4DnZy7LGBdA+ZTbTXWe0MaR0aDU6YfRozstK2KYjzWuDHKJeFShLPE/1q
         4TxAHYBBpPDG2DWKvpztC+yTAUx17c/2D1BJWN4Cb7M+ZNNP6wFQ1eRnC8dLHo6SHkqb
         GK1xMluZxlgRTaJk+hbcNu1rOCpswqbLdf4fj1l+KoOjl+Ep6pdi5tBymRHfmzoaGaGW
         UqV10T3gyYJfJwPg3xCDVLAUHtGAWVWg3GqQQDuJd6KQUoVAybnfR3uU047jVL2dhnqg
         NEjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688475232; x=1691067232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CpVaS/KPO2Xql+u1j9Mm3ELwth8SncbcfL3VaTI6LeI=;
        b=c+FX2unwuUMy57qez7YF2YFUv2c/YlinzREi17tJzXKGcmXbwYkMIs+usvPdvvyQvl
         fYmQbdWdOQRXppX+V3EJ4o4GFpvBqcuSFz+HPmRZOkdDjunYA/2QMh32q8rw1IzVVXTF
         n5F0T03wcP86dDq+eTgKy7qqycOntSh2kNdu5BmpFSp3SB2HGZK6x1i2hhe2M0atLily
         v/wmOEPgBnjtDnbaDeDwpuEELxPHHKfjOuMtCr1rmIZsrzhYHwzbQ5X35PaLlJZc66ne
         eeN9C4VFpJoXbPETrKEb4SyS1Vp1coNU+CYGIwemvoEOLA2TqqUlN07ErHUmsRthyXeB
         +xHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688475232; x=1691067232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CpVaS/KPO2Xql+u1j9Mm3ELwth8SncbcfL3VaTI6LeI=;
        b=DX2eJinDb27VPjLaf2NkYfXeNE9xXzBtv34TpH8NcXzVgA1vPMis5OaDirw7iYsGNW
         M1vtQ/7WEH59bTaj7Cun99cfCKUZP8W8yL2LU1mgDhKugmAjviR/HqL31FuB9Rg4orG7
         1/ouFnCahDI7FiVqLZz+511UWULUxXZXdZhHenEiJJ/b/Zhv/AhWIx9/iACtbDEGCCJ6
         DaWIBg6+Rt1KQpz/Y3SJAM+R1fUZx2DFgiGitDoxuqFZWVZ4QpXNVWRA9/hjNni03vZk
         Wbk+kEwcGavw5CFHHVy5k2NoChIGeG0YnS25MMHiHSverRz4dx8VMMvRG2l86u7jFNBD
         A+2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLY1Cao78K4kdOSKh4E/051yzkFlN9d6TwTCkt/4zweAkF4diGXj
	rdEFyDCa0gXuq6dVIAtbScE=
X-Google-Smtp-Source: APBJJlG368SSaZ6bShHGxmEhs9OvM4z/jz/XWFJ3DpLaq5c1hRCFQykYwGmVoe+kZdFsTcCQTIiBQw==
X-Received: by 2002:a92:ce41:0:b0:345:a5ad:2863 with SMTP id a1-20020a92ce41000000b00345a5ad2863mr12701861ilr.13.1688475232268;
        Tue, 04 Jul 2023 05:53:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c0c6:0:b0:343:c13c:2da1 with SMTP id t6-20020a92c0c6000000b00343c13c2da1ls2776783ilf.2.-pod-prod-06-us;
 Tue, 04 Jul 2023 05:53:51 -0700 (PDT)
X-Received: by 2002:a6b:6f07:0:b0:786:26f0:3092 with SMTP id k7-20020a6b6f07000000b0078626f03092mr13059174ioc.3.1688475231585;
        Tue, 04 Jul 2023 05:53:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688475231; cv=none;
        d=google.com; s=arc-20160816;
        b=HdUgVzX7O3USdc8PSRV9ZbC/OD7cryKcQqINGbeSPsajVfGUuhm9bmY+4IhfUhA9A7
         G3dxOA44VUc1JwugwAnxzQCKBD2GSymwLyhew2b0pthJpJ5uleSgfDrsplDwFdknqnxQ
         2eg3HqYzl/RFb9HB3LJNyhtbphJE5ALObeSEWjSESC+4Hc6aV8kTX7aOQnQ42V8kt6wY
         LqFx74TSvDNwVji9cvIuD0rpJCLgqntQZj4w8oBIA9g080tgyG7+1N2VC5be7LopgFwq
         y3RNKvUOJsvQTkmk2zrFvNwLyV1cT63BpV0J4SP0F8UtVTaN+hJETB0zOmAILPSXY6wg
         YiWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=cm54IzjDOjKMxF9P7bhVNqnAtmmjk4MLaZNHadP9BBg=;
        fh=JatFWl46A5X89rXdZaHeLDn2zYWoXqmrRBIL0ag9sD8=;
        b=Wznw1FnBGwQLNw/51yn/n7Z0E5gmDCwVT0H/ij2lGbXD0JVDF26yHc313UepdA7fDk
         26hYhOYjRtBPRua1U1k4Dv3nsEG9M35V9fZIl6NGXSzVBSU6O+SbY+aipNZ5+v1s2xVF
         erO/STZo7vAa6t5DdEz0gHR4xUfZlIgmGKdGUqFGlUmu8bEw4EXua/JUvYjEaVoX1m5u
         UocQPZXmArAdb3EcD4jBLCAOwMGadX+PHnibBZ46AxMdKEiWsRX/JOCHzXsrcA3ZtmGI
         +CgMHPQFju9NS9ragV/vQ1fDdU63CdT5dcYXYy7SGHjMOB5JRsoLYTTm0gnTcI4Zo/3g
         70Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id cx7-20020a056638490700b00429649d963fsi1713280jab.6.2023.07.04.05.53.50
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Jul 2023 05:53:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [112.20.109.108])
	by gateway (Coremail) with SMTP id _____8DxxPBcFqRkzgQAAA--.52S3;
	Tue, 04 Jul 2023 20:53:48 +0800 (CST)
Received: from localhost.localdomain (unknown [112.20.109.108])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Ax98xaFqRkXDAbAA--.63241S4;
	Tue, 04 Jul 2023 20:53:48 +0800 (CST)
From: Feiyang Chen <chenfeiyang@loongson.cn>
To: chenhuacai@kernel.org
Cc: Feiyang Chen <chenfeiyang@loongson.cn>,
	dvyukov@google.com,
	andreyknvl@gmail.com,
	loongarch@lists.linux.dev,
	kasan-dev@googlegroups.com,
	chris.chenfeiyang@gmail.com,
	loongson-kernel@lists.loongnix.cn
Subject: [PATCH 2/2] LoongArch: Allow building with kcov coverage
Date: Tue,  4 Jul 2023 20:53:32 +0800
Message-Id: <8d10b1220434432dbc089fab8df4e1cca048cd0c.1688369658.git.chenfeiyang@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <cover.1688369658.git.chenfeiyang@loongson.cn>
References: <cover.1688369658.git.chenfeiyang@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8Ax98xaFqRkXDAbAA--.63241S4
X-CM-SenderInfo: hfkh0wphl1t03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBj9xXoW7XrWxur48WF4UGrW5try7Jwc_yoWkZwc_A3
	y3tw48Gr1rGw48Cr4qgFyrJw1DAa1kWFnYkF9I9r17ZFy5X3WfGr45J345Zr1rK3yjgrs8
	ZrW0qF98CrWjvosvyTuYvTs0mTUanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUj1kv1TuYvT
	s0mT0YCTnIWjqI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUI
	cSsGvfJTRUUUbxAYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20x
	vaj40_Wr0E3s1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxS
	w2x7M28EF7xvwVC0I7IYx2IY67AKxVW5JVW7JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxV
	W8JVWxJwA2z4x0Y4vEx4A2jsIE14v26r4j6F4UM28EF7xvwVC2z280aVCY1x0267AKxVW8
	JVW8Jr1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27wAqx4
	xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jw0_WrylYx0Ex4A2jsIE14v2
	6r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCF04k20xvY0x0EwI
	xGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwCFI7km07C267AKxVWUAVWUtwC20s026c02F40E
	14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GFylIx
	kGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVW8JVW5JwCI42IY6xIIjxv20xvEc7CjxVAF
	wI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r4j6F
	4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07josjUU
	UUUU=
X-Original-Sender: chenfeiyang@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
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

Add ARCH_HAS_KCOV to the LoongArch Kconfig. Also disable
instrumentation of vdso.

Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>
---
 arch/loongarch/Kconfig       | 1 +
 arch/loongarch/vdso/Makefile | 2 ++
 2 files changed, 3 insertions(+)

diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index ed9a148cdcde..4c21a961ab88 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -14,6 +14,7 @@ config LOONGARCH
 	select ARCH_HAS_ACPI_TABLE_UPGRADE	if ACPI
 	select ARCH_HAS_CPU_FINALIZE_INIT
 	select ARCH_HAS_FORTIFY_SOURCE
+	select ARCH_HAS_KCOV
 	select ARCH_HAS_NMI_SAFE_THIS_CPU_OPS
 	select ARCH_HAS_PTE_SPECIAL
 	select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
diff --git a/arch/loongarch/vdso/Makefile b/arch/loongarch/vdso/Makefile
index 7bb794604af3..7dc87377688b 100644
--- a/arch/loongarch/vdso/Makefile
+++ b/arch/loongarch/vdso/Makefile
@@ -5,6 +5,8 @@ ifdef CONFIG_KASAN
 KASAN_SANITIZE := n
 endif
 
+KCOV_INSTRUMENT := n
+
 # Include the generic Makefile to check the built vdso.
 include $(srctree)/lib/vdso/Makefile
 
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d10b1220434432dbc089fab8df4e1cca048cd0c.1688369658.git.chenfeiyang%40loongson.cn.
