Return-Path: <kasan-dev+bncBAABBXUZROQQMGQE73GFQUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 23F3C6CBD47
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 13:17:52 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id c80-20020ae9ed53000000b007468c560e1bsf5518675qkg.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 04:17:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680002270; cv=pass;
        d=google.com; s=arc-20160816;
        b=lWBHW8MLEPWom6Rfm/x63K3PbDfbjQX2uzeW+q88+N8BJqUMlWioKwTziHqjlOAq1D
         QA3lNnA3Hqau0VL5qO+cwJo8Kr5mPaFYe0ijcBOmiE7dCMcjnnIUrdhDDvR2/5L+cJBC
         c5NV0NzOe7Tf/MWCdplQfq5G0FBnluWjZOCFu6zA4HnaEHtlnVlNs5uOi009OfY/dXVQ
         +2sAAOLztsJoNOu07inEq3OYVEGjIJO6FGwmc7yqqb5N8HDX9jxGMM80tFY+Nd1B986W
         bwQ7QpynblUdE3+hggonFiqxeYqrZN8izy/QBrT8b3Jkv9ldl6quLXIul7NvLUMwtdA5
         YSpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=hbhzLlM5MXT8v0oeAD6q3ZH5l8XUMK0iEVbW88o7dVI=;
        b=AJ5tcTtmdqD5swCgGe67pWLzl+2VGOqu4/QwPDbC4s7e+EamsXtem+MvCrjMdqp0+V
         5gUSDwODO7ios3eP5VkJH2czyXYQAMKV2Hx9n186jMYvBXRvbVGxaJ8lV1WMwzCJkncI
         jWUEHNelG6/t+yZnOVQSIbDmzsAPufkuPgDfnYWPBRbfRD1k6UNOwOUC8b9vUQ9wlhPv
         wyOLg28u5fAKPmUT7MqO9/447sqokG1mm0qqgQFOC7v8s/FavLXj0PMRRxrc3nH9kxtr
         3SAevn6GzGt5wOWtSNNvbGHWuEvlVc9rxqPgVgmKiMWX/up37mvY6UcPQchyv1svClk0
         hLvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680002270;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hbhzLlM5MXT8v0oeAD6q3ZH5l8XUMK0iEVbW88o7dVI=;
        b=rfqdrw0YCr5+Xu4ZdyvlFmytgk9Tqe1KkRCFZ466iGr64IPmgvgamI7+krcFYhq18S
         V69XTePNYqmdIHooLqEE4yMnO0cLGcE4s+uYT0kwmOPvoFhEsaj7z0gcaTX3PtzZHFS0
         V55ipusql/tg0PCENItj0M+xWt8IVieWdo0AiXIHYU6jO5ECLaQsjjz10YCgylHeni5n
         Sg+VBIKc7AdRDizwZaQUEqEkrOdsI0Y1n43ADT8uYtiwLACRFTOezqDTBFc0JoMeQ5JB
         DqmVDRNkm9Iq0AodXkMkAFlF0FbwOUtZMxzqjFv1NKxkUmerGXZXuwUDtb651N8fs701
         E8Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680002270;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=hbhzLlM5MXT8v0oeAD6q3ZH5l8XUMK0iEVbW88o7dVI=;
        b=bDqgoYCqN9KOLqkRi03WjnWxe0xFHTWF0G0PPtOUuMR9hRIr8i+Z3NYRZosBKJM0rI
         OzyLjm/OTZ+E2MXeLoGX+ePvw6X7HOollNrY9P9W05DmpvvmlTvK3/WdsxE+HDkegho1
         TX0/SDBn/94ZDxYe77EqVhILFNus3SN1ZwTekd821KaRnHNUizAbYxFy3ub7FIycBvzH
         9Z8keEIJWEGPu2/eySw0WxcSjLeR+fhiYwLbWS1OpghvnBS6Gc9L27ZmGItQiQTkukcm
         hNieCVzkkl3quzyNYgvxANVdo6DrY9TWTtoxVvHGfbe2es8l3/pFOjM5NNLD1D5gov/i
         5ehA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUFgTEjvt+BA8D13CxuZhkZdd9w/uQDhz2NTGDkD06+UU8m0ReZ
	utlU6Zn7UB9IT3JqwmwFaHA=
X-Google-Smtp-Source: AK7set+/zg4GH0QJSuNnEe7nnsmvNQFwKCNmNuleN83zCYn5jEjQS3XKXBCLuccyvKr5RPHYylDvYQ==
X-Received: by 2002:a05:622a:88:b0:3e0:ed1:9f72 with SMTP id o8-20020a05622a008800b003e00ed19f72mr5540699qtw.7.1680002270706;
        Tue, 28 Mar 2023 04:17:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6f11:0:b0:3e3:8d82:3fee with SMTP id bs17-20020ac86f11000000b003e38d823feels11861252qtb.6.-pod-prod-gmail;
 Tue, 28 Mar 2023 04:17:50 -0700 (PDT)
X-Received: by 2002:a05:622a:11cc:b0:3da:7226:7539 with SMTP id n12-20020a05622a11cc00b003da72267539mr26862572qtk.66.1680002270248;
        Tue, 28 Mar 2023 04:17:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680002270; cv=none;
        d=google.com; s=arc-20160816;
        b=a+0mvWWaz46K6l+ULSzGVyvDDbz14OjD8KF/GWcjX0vqoenPsrCZ3ZRUAAdd71P7YG
         JgvF2LczWrF32ZtLnObK8t457VA0agn0/clHQWF/7zaa0gGkSubdXG3s7qa0olYsSmd/
         v30lYpdPsJdNbCemRheCK8px3msKCcnFYi5SV8ZhjFXQOp0dzosgNP0M1yaewxvAuMdq
         u2DzfNcLbIbT9/NvhUus3JvFUIIK7PNZ/pNceRY6aXpsMw7Y9zTS9SQyvCPzGfIWMnFp
         XAIOw843JRX3wNCBDrww2Q1kdM7j8KbT+5Xr48UNHjHVDF/ffu45gz1Q5eDemAHv6NA4
         CgRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=Bc7Gu1xYJU3tjm4m1o1lmqvRv+HZYi9SrrDzHR57a2I=;
        b=RbKiePR2B8agg5nNB423V46KY1UtdRHm7nDGWc097Vc3lO2eUohnNPZ3S15OThmPUe
         YgHSBTVygINyIRQ9QvJVyOlz7Qbl88/7RqS3LpeUVG+3WcIYWAM3EYY1yQRa30Zzlsvl
         qvqonoobRJ3DV0sCC4mfuE19v98UkLmON3N9ez7GdulMDRQlZAh6LUu9Z7QLh4AkZeWU
         9Myyap0RLaylaTYcfYeJ2RC7f3qUB62xSrME/NktWORpuJBZhfvoVuSAH9mAFCsfOhOo
         yYL/1WECvP0Ht6AedBp6ZKu/Kip43P1ndgpXuC7Tb0xEI//G69nuIeALPohlSL/hdoub
         y6aQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id z16-20020a05620a261000b00743af20ec60si732153qko.4.2023.03.28.04.17.48
        for <kasan-dev@googlegroups.com>;
        Tue, 28 Mar 2023 04:17:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8BxIk67zCJkcg4TAA--.28963S3;
	Tue, 28 Mar 2023 19:17:15 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Ax2726zCJkD1cPAA--.10735S2;
	Tue, 28 Mar 2023 19:17:14 +0800 (CST)
From: Qing Zhang <zhangqing@loongson.cn>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Huacai Chen <chenhuacai@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Jiaxun Yang <jiaxun.yang@flygoat.com>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] LoongArch: Add kernel address sanitizer support
Date: Tue, 28 Mar 2023 19:17:14 +0800
Message-Id: <20230328111714.2056-1-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8Ax2726zCJkD1cPAA--.10735S2
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvAXoWftF15Xry3AF1kWF18ZF15XFb_yoW5AryDto
	WYkF43Kw18Gw12k393Xw1UJFyUJr1qk393Z39Fva1fWF17ArW3G34UtFWagry3JrZYkr1f
	Wayvgrsava4ktrnxn29KB7ZKAUJUUUU5529EdanIXcx71UUUUU7KY7ZEXasCq-sGcSsGvf
	J3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnRJU
	UUkYb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2IYs7xG6rWj6s
	0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_JFI_Gr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1l84
	ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AKxVWxJr0_GcWl
	e2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27wAqx4xG64xvF2
	IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jrv_JF1lYx0Ex4A2jsIE14v26r1j6r4U
	McvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCF04k20xvY0x0EwIxGrwCFx2
	IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v2
	6r106r1rMI8E67AF67kF1VAFwI0_GFv_WrylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67
	AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Jr0_Gr1lIxAIcVCF04k26cxKx2IY
	s7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Jr
	0_GrUvcSsGvfC2KfnxnUUI43ZEXa7IU8zwZ7UUUUU==
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

1/8 of kernel addresses reserved for shadow memory. But for LoongArch,
There are a lot of holes between different segments and valid address
space(256T available) is insufficient to map all these segments to kasan
shadow memory with the common formula provided by kasan core, saying
addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET

So Loongarch has a ARCH specific mapping formula,different segments
are mapped individually, and only limited length of space of that
specific segment is mapped to shadow.

At early boot stage the whole shadow region populated with just
one physical page (kasan_early_shadow_page). Later, this page is
reused as readonly zero shadow for some memory that Kasan currently
don't track.
After mapping the physical memory, pages for shadow memory are
allocated and mapped.

Functions like memset/memmove/memcpy do a lot of memory accesses.
If bad pointer passed to one of these function it is important
to catch this. Compiler's instrumentation cannot do this since
these functions are written in assembly.
KASan replaces memory functions with manually instrumented variants.
Original functions declared as weak symbols so strong definitions
in mm/kasan/kasan.c could replace them. Original functions have aliases
with '__' prefix in name, so we could call non-instrumented variant
if needed.

Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
---
 Documentation/dev-tools/kasan.rst             |   4 +-
 .../features/debug/KASAN/arch-support.txt     |   2 +-
 arch/loongarch/Kconfig                        |   7 +
 arch/loongarch/include/asm/kasan.h            | 120 +++++++++
 arch/loongarch/include/asm/pgtable.h          |   7 +
 arch/loongarch/include/asm/setup.h            |   2 +-
 arch/loongarch/include/asm/string.h           |  20 ++
 arch/loongarch/kernel/Makefile                |   3 +
 arch/loongarch/kernel/head.S                  |  14 +-
 arch/loongarch/kernel/relocate.c              |   8 +-
 arch/loongarch/kernel/setup.c                 |   4 +
 arch/loongarch/lib/memcpy.S                   |   4 +-
 arch/loongarch/lib/memmove.S                  |  13 +-
 arch/loongarch/lib/memset.S                   |   4 +-
 arch/loongarch/mm/Makefile                    |   2 +
 arch/loongarch/mm/kasan_init.c                | 255 ++++++++++++++++++
 arch/loongarch/vdso/Makefile                  |   4 +
 include/linux/kasan.h                         |   2 +
 mm/kasan/generic.c                            |   5 +
 mm/kasan/init.c                               |  10 +-
 mm/kasan/kasan.h                              |   6 +
 21 files changed, 470 insertions(+), 26 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kasan.h
 create mode 100644 arch/loongarch/mm/kasan_init.c

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e66916a483cd..ee91f2872767 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -41,8 +41,8 @@ Support
 Architectures
 ~~~~~~~~~~~~~
 
-Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, and
-xtensa, and the tag-based KASAN modes are supported only on arm64.
+Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, xtensa,
+and loongarch, and the tag-based KASAN modes are supported only on arm64.
 
 Compilers
 ~~~~~~~~~
diff --git a/Documentation/features/debug/KASAN/arch-support.txt b/Documentation/features/debug/KASAN/arch-support.txt
index bf0124fae643..c4581c2edb28 100644
--- a/Documentation/features/debug/KASAN/arch-support.txt
+++ b/Documentation/features/debug/KASAN/arch-support.txt
@@ -13,7 +13,7 @@
     |        csky: | TODO |
     |     hexagon: | TODO |
     |        ia64: | TODO |
-    |   loongarch: | TODO |
+    |   loongarch: |  ok  |
     |        m68k: | TODO |
     |  microblaze: | TODO |
     |        mips: | TODO |
diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index 72dd00f48b8c..61f883c51045 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -7,6 +7,7 @@ config LOONGARCH
 	select ACPI_MCFG if ACPI
 	select ACPI_SYSTEM_POWER_STATES_SUPPORT	if ACPI
 	select ARCH_BINFMT_ELF_STATE
+	select ARCH_DISABLE_KASAN_INLINE
 	select ARCH_ENABLE_MEMORY_HOTPLUG
 	select ARCH_ENABLE_MEMORY_HOTREMOVE
 	select ARCH_HAS_ACPI_TABLE_UPGRADE	if ACPI
@@ -83,6 +84,7 @@ config LOONGARCH
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER
+	select HAVE_ARCH_KASAN if 64BIT
 	select HAVE_ARCH_TRACEHOOK
 	select HAVE_ARCH_TRANSPARENT_HUGEPAGE
 	select HAVE_ASM_MODVERSIONS
@@ -626,6 +628,11 @@ config ARCH_MMAP_RND_BITS_MIN
 config ARCH_MMAP_RND_BITS_MAX
 	default 18
 
+config KASAN_SHADOW_OFFSET
+	hex
+	default 0x0
+	depends on KASAN
+
 menu "Power management options"
 
 config ARCH_SUSPEND_POSSIBLE
diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
new file mode 100644
index 000000000000..582bcded311e
--- /dev/null
+++ b/arch/loongarch/include/asm/kasan.h
@@ -0,0 +1,120 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_H
+#define __ASM_KASAN_H
+
+#ifndef __ASSEMBLY__
+
+#include <linux/linkage.h>
+#include <linux/mmzone.h>
+#include <asm/addrspace.h>
+#include <asm/io.h>
+#include <asm/pgtable.h>
+
+#define __HAVE_ARCH_SHADOW_MAP
+
+#define KASAN_SHADOW_SCALE_SHIFT 3
+#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+
+#define XRANGE_SHIFT (48)
+
+/* Valid address length */
+#define XRANGE_SHADOW_SHIFT	(PGDIR_SHIFT + PAGE_SHIFT - 3)
+/* Used for taking out the valid address */
+#define XRANGE_SHADOW_MASK	GENMASK_ULL(XRANGE_SHADOW_SHIFT - 1, 0)
+/* One segment whole address space size */
+#define	XRANGE_SIZE		(XRANGE_SHADOW_MASK + 1)
+
+/* 64-bit segment value. */
+#define XKPRANGE_UC_SEG		(0x8000)
+#define XKPRANGE_CC_SEG		(0x9000)
+#define XKVRANGE_VC_SEG		(0xffff)
+
+/* Cached */
+#define XKPRANGE_CC_START		CACHE_BASE
+#define XKPRANGE_CC_SIZE		XRANGE_SIZE
+#define XKPRANGE_CC_KASAN_OFFSET	(0)
+#define XKPRANGE_CC_SHADOW_SIZE		(XKPRANGE_CC_SIZE >> KASAN_SHADOW_SCALE_SHIFT)
+#define XKPRANGE_CC_SHADOW_END		(XKPRANGE_CC_KASAN_OFFSET + XKPRANGE_CC_SHADOW_SIZE)
+
+/* UnCached */
+#define XKPRANGE_UC_START		UNCACHE_BASE
+#define XKPRANGE_UC_SIZE		XRANGE_SIZE
+#define XKPRANGE_UC_KASAN_OFFSET	XKPRANGE_CC_SHADOW_END
+#define XKPRANGE_UC_SHADOW_SIZE		(XKPRANGE_UC_SIZE >> KASAN_SHADOW_SCALE_SHIFT)
+#define XKPRANGE_UC_SHADOW_END		(XKPRANGE_UC_KASAN_OFFSET + XKPRANGE_UC_SHADOW_SIZE)
+
+/* VMALLOC (Cached or UnCached)  */
+#define XKVRANGE_VC_START		MODULES_VADDR
+#define XKVRANGE_VC_SIZE		round_up(VMEMMAP_END - MODULES_VADDR + 1, PGDIR_SIZE)
+#define XKVRANGE_VC_KASAN_OFFSET	XKPRANGE_UC_SHADOW_END
+#define XKVRANGE_VC_SHADOW_SIZE		(XKVRANGE_VC_SIZE >> KASAN_SHADOW_SCALE_SHIFT)
+#define XKVRANGE_VC_SHADOW_END		(XKVRANGE_VC_KASAN_OFFSET + XKVRANGE_VC_SHADOW_SIZE)
+
+/* Kasan shadow memory start right after vmalloc. */
+#define KASAN_SHADOW_START		round_up(VMEMMAP_END, PGDIR_SIZE)
+#define KASAN_SHADOW_SIZE		(XKVRANGE_VC_SHADOW_END - XKPRANGE_CC_KASAN_OFFSET)
+#define KASAN_SHADOW_END		round_up(KASAN_SHADOW_START + KASAN_SHADOW_SIZE, PGDIR_SIZE)
+
+#define XKPRANGE_CC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_CC_KASAN_OFFSET)
+#define XKPRANGE_UC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_UC_KASAN_OFFSET)
+#define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_OFFSET)
+
+extern bool kasan_early_stage;
+extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
+
+static inline void *kasan_mem_to_shadow(const void *addr)
+{
+	if (kasan_early_stage) {
+		return (void *)(kasan_early_shadow_page);
+	} else {
+		unsigned long maddr = (unsigned long)addr;
+		unsigned long xrange = (maddr >> XRANGE_SHIFT) & 0xffff;
+		unsigned long offset = 0;
+
+		maddr &= XRANGE_SHADOW_MASK;
+		switch (xrange) {
+		case XKPRANGE_CC_SEG:
+			offset = XKPRANGE_CC_SHADOW_OFFSET;
+			break;
+		case XKPRANGE_UC_SEG:
+			offset = XKPRANGE_UC_SHADOW_OFFSET;
+			break;
+		case XKVRANGE_VC_SEG:
+			offset = XKVRANGE_VC_SHADOW_OFFSET;
+			break;
+		default:
+			WARN_ON(1);
+			return NULL;
+		}
+
+		return (void *)((maddr >> KASAN_SHADOW_SCALE_SHIFT) + offset);
+	}
+}
+
+static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
+{
+	unsigned long addr = (unsigned long)shadow_addr;
+
+	if (unlikely(addr > KASAN_SHADOW_END) ||
+		unlikely(addr < KASAN_SHADOW_START)) {
+		WARN_ON(1);
+		return NULL;
+	}
+
+	if (addr >= XKVRANGE_VC_SHADOW_OFFSET)
+		return (void *)(((addr - XKVRANGE_VC_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT) + XKVRANGE_VC_START);
+	else if (addr >= XKPRANGE_UC_SHADOW_OFFSET)
+		return (void *)(((addr - XKPRANGE_UC_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT) + XKPRANGE_UC_START);
+	else if (addr >= XKPRANGE_CC_SHADOW_OFFSET)
+		return (void *)(((addr - XKPRANGE_CC_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT) + XKPRANGE_CC_START);
+	else {
+		WARN_ON(1);
+		return NULL;
+	}
+}
+
+void kasan_init(void);
+asmlinkage void kasan_early_init(void);
+
+#endif
+#endif
diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index d28fb9dbec59..5cfdf79b287e 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -86,9 +86,16 @@ extern unsigned long zero_page_mask;
 #define MODULES_END	(MODULES_VADDR + SZ_256M)
 
 #define VMALLOC_START	MODULES_END
+
+#ifndef CONFIG_KASAN
 #define VMALLOC_END	\
 	(vm_map_base +	\
 	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
+#else
+#define VMALLOC_END	\
+	(vm_map_base +	\
+	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, (1UL << cpu_vabits) / 2) - PMD_SIZE - VMEMMAP_SIZE)
+#endif
 
 #define vmemmap		((struct page *)((VMALLOC_END + PMD_SIZE) & PMD_MASK))
 #define VMEMMAP_END	((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
diff --git a/arch/loongarch/include/asm/setup.h b/arch/loongarch/include/asm/setup.h
index be05c0e706a2..2dca0d1dd90a 100644
--- a/arch/loongarch/include/asm/setup.h
+++ b/arch/loongarch/include/asm/setup.h
@@ -33,7 +33,7 @@ extern long __la_abs_end;
 extern long __rela_dyn_begin;
 extern long __rela_dyn_end;
 
-extern void * __init relocate_kernel(void);
+extern unsigned long __init relocate_kernel(void);
 
 #endif
 
diff --git a/arch/loongarch/include/asm/string.h b/arch/loongarch/include/asm/string.h
index 7b29cc9c70aa..5bb5a90d2681 100644
--- a/arch/loongarch/include/asm/string.h
+++ b/arch/loongarch/include/asm/string.h
@@ -7,11 +7,31 @@
 
 #define __HAVE_ARCH_MEMSET
 extern void *memset(void *__s, int __c, size_t __count);
+extern void *__memset(void *__s, int __c, size_t __count);
 
 #define __HAVE_ARCH_MEMCPY
 extern void *memcpy(void *__to, __const__ void *__from, size_t __n);
+extern void *__memcpy(void *__to, __const__ void *__from, size_t __n);
 
 #define __HAVE_ARCH_MEMMOVE
 extern void *memmove(void *__dest, __const__ void *__src, size_t __n);
+extern void *__memmove(void *__dest, __const__ void *__src, size_t __n);
+
+#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
+
+/*
+ * For files that are not instrumented (e.g. mm/slub.c) we
+ * should use not instrumented version of mem* functions.
+ */
+
+#define memset(s, c, n) __memset(s, c, n)
+#define memcpy(dst, src, len) __memcpy(dst, src, len)
+#define memmove(dst, src, len) __memmove(dst, src, len)
+
+#ifndef __NO_FORTIFY
+#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
+#endif
+
+#endif
 
 #endif /* _ASM_STRING_H */
diff --git a/arch/loongarch/kernel/Makefile b/arch/loongarch/kernel/Makefile
index 9a72d91cd104..0055e7582e15 100644
--- a/arch/loongarch/kernel/Makefile
+++ b/arch/loongarch/kernel/Makefile
@@ -30,6 +30,9 @@ ifdef CONFIG_FUNCTION_TRACER
   CFLAGS_REMOVE_perf_event.o = $(CC_FLAGS_FTRACE)
 endif
 
+KASAN_SANITIZE_vdso.o := n
+KASAN_SANITIZE_efi.o := n
+
 obj-$(CONFIG_MODULES)		+= module.o module-sections.o
 obj-$(CONFIG_STACKTRACE)	+= stacktrace.o
 
diff --git a/arch/loongarch/kernel/head.S b/arch/loongarch/kernel/head.S
index aa64b179744f..19d4be5c8381 100644
--- a/arch/loongarch/kernel/head.S
+++ b/arch/loongarch/kernel/head.S
@@ -95,13 +95,17 @@ SYM_CODE_START(kernel_entry)			# kernel entry point
 	PTR_LI		sp, (_THREAD_SIZE - PT_SIZE)
 	PTR_ADD		sp, sp, tp
 	set_saved_sp	sp, t0, t1
-#endif
-
-	/* relocate_kernel() returns the new kernel entry point */
-	jr		a0
-	ASM_BUG()
 
+	/* Jump to new kernel: new_pc = current_pc + random_offset */
+	pcaddi		t0, 0
+	add.d		t0, t0, a0
+	jirl		zero, t0, 0xc
 #endif
+#endif
+
+	#ifdef CONFIG_KASAN
+	bl              kasan_early_init
+	#endif
 
 	bl		start_kernel
 	ASM_BUG()
diff --git a/arch/loongarch/kernel/relocate.c b/arch/loongarch/kernel/relocate.c
index 01f94d1e3edf..6c3eff9af9fb 100644
--- a/arch/loongarch/kernel/relocate.c
+++ b/arch/loongarch/kernel/relocate.c
@@ -157,12 +157,11 @@ static inline void __init update_reloc_offset(unsigned long *addr, long random_o
 	*new_addr = (unsigned long)reloc_offset;
 }
 
-void * __init relocate_kernel(void)
+unsigned long __init relocate_kernel(void)
 {
 	unsigned long kernel_length;
 	unsigned long random_offset = 0;
 	void *location_new = _text; /* Default to original kernel start */
-	void *kernel_entry = start_kernel; /* Default to original kernel entry point */
 	char *cmdline = early_ioremap(fw_arg1, COMMAND_LINE_SIZE); /* Boot command line is passed in fw_arg1 */
 
 	strscpy(boot_command_line, cmdline, COMMAND_LINE_SIZE);
@@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
 
 		reloc_offset += random_offset;
 
-		/* Return the new kernel's entry point */
-		kernel_entry = RELOCATED_KASLR(start_kernel);
-
 		/* The current thread is now within the relocated kernel */
 		__current_thread_info = RELOCATED_KASLR(__current_thread_info);
 
@@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
 
 	relocate_absolute(random_offset);
 
-	return kernel_entry;
+	return random_offset;
 }
 
 /*
diff --git a/arch/loongarch/kernel/setup.c b/arch/loongarch/kernel/setup.c
index 27f71f9531e1..18453f8cb9e8 100644
--- a/arch/loongarch/kernel/setup.c
+++ b/arch/loongarch/kernel/setup.c
@@ -610,4 +610,8 @@ void __init setup_arch(char **cmdline_p)
 #endif
 
 	paging_init();
+
+#if defined(CONFIG_KASAN)
+	kasan_init();
+#endif
 }
diff --git a/arch/loongarch/lib/memcpy.S b/arch/loongarch/lib/memcpy.S
index 3b7e1dec7109..db92ef7bef3a 100644
--- a/arch/loongarch/lib/memcpy.S
+++ b/arch/loongarch/lib/memcpy.S
@@ -10,16 +10,18 @@
 #include <asm/export.h>
 #include <asm/regdef.h>
 
-SYM_FUNC_START(memcpy)
+SYM_FUNC_START_WEAK(memcpy)
 	/*
 	 * Some CPUs support hardware unaligned access
 	 */
 	ALTERNATIVE	"b __memcpy_generic", \
 			"b __memcpy_fast", CPU_FEATURE_UAL
 SYM_FUNC_END(memcpy)
+SYM_FUNC_ALIAS(__memcpy, memcpy)
 _ASM_NOKPROBE(memcpy)
 
 EXPORT_SYMBOL(memcpy)
+EXPORT_SYMBOL(__memcpy)
 
 /*
  * void *__memcpy_generic(void *dst, const void *src, size_t n)
diff --git a/arch/loongarch/lib/memmove.S b/arch/loongarch/lib/memmove.S
index b796c3d6da05..a2dec5899f5c 100644
--- a/arch/loongarch/lib/memmove.S
+++ b/arch/loongarch/lib/memmove.S
@@ -10,7 +10,7 @@
 #include <asm/export.h>
 #include <asm/regdef.h>
 
-SYM_FUNC_START(memmove)
+SYM_FUNC_START_WEAK(memmove)
 	blt	a0, a1, 1f	/* dst < src, memcpy */
 	blt	a1, a0, 3f	/* src < dst, rmemcpy */
 	jr	ra		/* dst == src, return */
@@ -19,27 +19,30 @@ SYM_FUNC_START(memmove)
 1:	ori	a3, zero, 64
 	sub.d	t0, a1, a0
 	blt	t0, a3, 2f
-	b	memcpy
+	b	__memcpy
 2:	b	__memcpy_generic
 
 	/* if (dst - src) < 64, copy 1 byte at a time */
 3:	ori	a3, zero, 64
 	sub.d	t0, a0, a1
 	blt	t0, a3, 4f
-	b	rmemcpy
+	b	__rmemcpy
 4:	b	__rmemcpy_generic
 SYM_FUNC_END(memmove)
+SYM_FUNC_ALIAS(__memmove, memmove)
 _ASM_NOKPROBE(memmove)
 
 EXPORT_SYMBOL(memmove)
+EXPORT_SYMBOL(__memmove)
+
+SYM_FUNC_START(__rmemcpy)
 
-SYM_FUNC_START(rmemcpy)
 	/*
 	 * Some CPUs support hardware unaligned access
 	 */
 	ALTERNATIVE	"b __rmemcpy_generic", \
 			"b __rmemcpy_fast", CPU_FEATURE_UAL
-SYM_FUNC_END(rmemcpy)
+SYM_FUNC_END(__rmemcpy)
 _ASM_NOKPROBE(rmemcpy)
 
 /*
diff --git a/arch/loongarch/lib/memset.S b/arch/loongarch/lib/memset.S
index a9eb732ab2ad..b5cdbecba8ef 100644
--- a/arch/loongarch/lib/memset.S
+++ b/arch/loongarch/lib/memset.S
@@ -16,16 +16,18 @@
 	bstrins.d \r0, \r0, 63, 32
 .endm
 
-SYM_FUNC_START(memset)
+SYM_FUNC_START_WEAK(memset)
 	/*
 	 * Some CPUs support hardware unaligned access
 	 */
 	ALTERNATIVE	"b __memset_generic", \
 			"b __memset_fast", CPU_FEATURE_UAL
 SYM_FUNC_END(memset)
+SYM_FUNC_ALIAS(__memset, memset)
 _ASM_NOKPROBE(memset)
 
 EXPORT_SYMBOL(memset)
+EXPORT_SYMBOL(__memset)
 
 /*
  * void *__memset_generic(void *s, int c, size_t n)
diff --git a/arch/loongarch/mm/Makefile b/arch/loongarch/mm/Makefile
index 8ffc6383f836..6e50cf6cf733 100644
--- a/arch/loongarch/mm/Makefile
+++ b/arch/loongarch/mm/Makefile
@@ -7,3 +7,5 @@ obj-y				+= init.o cache.o tlb.o tlbex.o extable.o \
 				   fault.o ioremap.o maccess.o mmap.o pgtable.o page.o
 
 obj-$(CONFIG_HUGETLB_PAGE)	+= hugetlbpage.o
+obj-$(CONFIG_KASAN)		+= kasan_init.o
+KASAN_SANITIZE_kasan_init.o     := n
diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
new file mode 100644
index 000000000000..fb3077f8d508
--- /dev/null
+++ b/arch/loongarch/mm/kasan_init.c
@@ -0,0 +1,255 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ * Copyright (C) 2023 Loongson Technology Corporation Limited
+ */
+#define pr_fmt(fmt) "kasan: " fmt
+#include <linux/kasan.h>
+#include <linux/memblock.h>
+#include <linux/sched/task.h>
+
+#include <asm/tlbflush.h>
+#include <asm/pgalloc.h>
+#include <asm-generic/sections.h>
+
+static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
+
+static inline int __p4d_none(int early, p4d_t p4d) {return 0; }
+
+#ifndef __PAGETABLE_PUD_FOLDED
+#define __p4d_none(early, p4d) (early ? (p4d_val(p4d) == 0) : \
+(__pa(p4d_val(p4d)) == (unsigned long)__pa(kasan_early_shadow_pud)))
+#endif
+
+#define __pud_none(early, pud) (early ? (pud_val(pud) == 0) : \
+(__pa(pud_val(pud)) == (unsigned long)__pa(kasan_early_shadow_pmd)))
+
+#define __pmd_none(early, pmd) (early ? (pmd_val(pmd) == 0) : \
+(__pa(pmd_val(pmd)) == (unsigned long)__pa(kasan_early_shadow_pte)))
+
+#define __pte_none(early, pte) (early ? pte_none(pte) : \
+((pte_val(pte) & _PFN_MASK) == (unsigned long)__pa(kasan_early_shadow_page)))
+
+bool kasan_early_stage = true;
+
+/*
+ * Alloc memory for shadow memory page table.
+ */
+static phys_addr_t __init kasan_alloc_zeroed_page(int node)
+{
+	void *p = memblock_alloc_try_nid(PAGE_SIZE, PAGE_SIZE,
+					__pa(MAX_DMA_ADDRESS),
+					MEMBLOCK_ALLOC_ACCESSIBLE, node);
+	if (!p)
+		panic("%s: Failed to allocate %lu bytes align=0x%lx nid=%d from=%llx\n",
+			__func__, PAGE_SIZE, PAGE_SIZE, node, __pa(MAX_DMA_ADDRESS));
+	return __pa(p);
+}
+
+static pte_t *kasan_pte_offset(pmd_t *pmdp, unsigned long addr, int node,
+				     bool early)
+{
+	if (__pmd_none(early, READ_ONCE(*pmdp))) {
+		phys_addr_t pte_phys = early ?
+				__pa_symbol(kasan_early_shadow_pte)
+					: kasan_alloc_zeroed_page(node);
+		if (!early)
+			memcpy(__va(pte_phys), kasan_early_shadow_pte,
+				sizeof(kasan_early_shadow_pte));
+		pmd_populate_kernel(NULL, pmdp, (pte_t *)__va(pte_phys));
+	}
+
+	return pte_offset_kernel(pmdp, addr);
+}
+
+static inline void kasan_set_pgd(pgd_t *pgdp, pgd_t pgdval)
+{
+	WRITE_ONCE(*pgdp, pgdval);
+}
+
+static pmd_t *kasan_pmd_offset(pud_t *pudp, unsigned long addr, int node,
+				     bool early)
+{
+	if (__pud_none(early, READ_ONCE(*pudp))) {
+		phys_addr_t pmd_phys = early ?
+				__pa_symbol(kasan_early_shadow_pmd)
+					: kasan_alloc_zeroed_page(node);
+		if (!early)
+			memcpy(__va(pmd_phys), kasan_early_shadow_pmd,
+				sizeof(kasan_early_shadow_pmd));
+		pud_populate(&init_mm, pudp, (pmd_t *)__va(pmd_phys));
+	}
+
+	return pmd_offset(pudp, addr);
+}
+
+static pud_t *__init kasan_pud_offset(p4d_t *p4dp, unsigned long addr, int node,
+					    bool early)
+{
+	if (__p4d_none(early, READ_ONCE(*p4dp))) {
+		phys_addr_t pud_phys = early ?
+			__pa_symbol(kasan_early_shadow_pud)
+				: kasan_alloc_zeroed_page(node);
+		if (!early)
+			memcpy(__va(pud_phys), kasan_early_shadow_pud,
+				sizeof(kasan_early_shadow_pud));
+		p4d_populate(&init_mm, p4dp, (pud_t *)__va(pud_phys));
+	}
+
+	return pud_offset(p4dp, addr);
+}
+
+static void  kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
+				      unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	pte_t *ptep = kasan_pte_offset(pmdp, addr, node, early);
+
+	do {
+		phys_addr_t page_phys = early ?
+					__pa_symbol(kasan_early_shadow_page)
+					      : kasan_alloc_zeroed_page(node);
+		next = addr + PAGE_SIZE;
+		set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_KERNEL));
+	} while (ptep++, addr = next, addr != end && __pte_none(early, READ_ONCE(*ptep)));
+}
+
+static void kasan_pmd_populate(pud_t *pudp, unsigned long addr,
+				      unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	pmd_t *pmdp = kasan_pmd_offset(pudp, addr, node, early);
+
+	do {
+		next = pmd_addr_end(addr, end);
+		kasan_pte_populate(pmdp, addr, next, node, early);
+	} while (pmdp++, addr = next, addr != end && __pmd_none(early, READ_ONCE(*pmdp)));
+}
+
+static void __init kasan_pud_populate(p4d_t *p4dp, unsigned long addr,
+					    unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	pud_t *pudp = kasan_pud_offset(p4dp, addr, node, early);
+
+	do {
+		next = pud_addr_end(addr, end);
+		kasan_pmd_populate(pudp, addr, next, node, early);
+	} while (pudp++, addr = next, addr != end);
+}
+
+static void __init kasan_p4d_populate(pgd_t *pgdp, unsigned long addr,
+					    unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	p4d_t *p4dp = p4d_offset(pgdp, addr);
+
+	do {
+		next = p4d_addr_end(addr, end);
+		kasan_pud_populate(p4dp, addr, next, node, early);
+	} while (p4dp++, addr = next, addr != end);
+}
+
+static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
+				      int node, bool early)
+{
+	unsigned long next;
+	pgd_t *pgdp;
+
+	pgdp = pgd_offset_k(addr);
+
+	do {
+		next = pgd_addr_end(addr, end);
+		kasan_p4d_populate(pgdp, addr, next, node, early);
+	} while (pgdp++, addr = next, addr != end);
+
+}
+
+asmlinkage void __init kasan_early_init(void)
+{
+	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_START, PGDIR_SIZE));
+	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, PGDIR_SIZE));
+}
+
+/* Set up full kasan mappings, ensuring that the mapped pages are zeroed */
+static void __init kasan_map_populate(unsigned long start, unsigned long end,
+				      int node)
+{
+	kasan_pgd_populate(start & PAGE_MASK, PAGE_ALIGN(end), node, false);
+}
+
+static void __init clear_pgds(unsigned long start, unsigned long end)
+{
+	/*
+	 * Remove references to kasan page tables from
+	 * swapper_pg_dir. pgd_clear() can't be used
+	 * here because it's nop on 2,3-level pagetable setups
+	 */
+	for (; start < end; start += PGDIR_SIZE)
+		kasan_set_pgd((pgd_t *)pgd_offset_k(start), __pgd(0));
+}
+
+void __init kasan_init(void)
+{
+	u64 i;
+	phys_addr_t pa_start, pa_end;
+	/*
+	 * PGD was populated as invalid_pmd_table or invalid_pud_table
+	 * in pagetable_init() which depends on how many levels of page
+	 * table you are using, but we had to clean the gpd of kasan
+	 * shadow memory, as the pgd value is none-zero.
+	 * The assertion pgd_none is going to be false and the formal populate
+	 * afterwards is not going to create any new pgd at all.
+	 */
+	memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(tmp_pg_dir));
+	__sync();
+	csr_write64(__pa_symbol(tmp_pg_dir), LOONGARCH_CSR_PGDH);
+	local_flush_tlb_all();
+
+	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
+
+	/* Maps everything to a single page of zeroes */
+	kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_END,
+			NUMA_NO_NODE, true);
+
+	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)MODULES_END),
+			kasan_mem_to_shadow((void *)VMEMMAP_END));
+
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+					    kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_early_stage = false;
+
+	/* Populate the linear mapping */
+	for_each_mem_range(i, &pa_start, &pa_end) {
+		void *start = (void *)phys_to_virt(pa_start);
+		void *end   = (void *)phys_to_virt(pa_end);
+
+		if (start >= end)
+			break;
+
+		kasan_map_populate((unsigned long)kasan_mem_to_shadow(start),
+			(unsigned long)kasan_mem_to_shadow(end), NUMA_NO_NODE);
+	}
+
+	/* Populate modules mapping */
+	kasan_map_populate((unsigned long)kasan_mem_to_shadow((void *)MODULES_VADDR),
+		(unsigned long)kasan_mem_to_shadow((void *)MODULES_END), NUMA_NO_NODE);
+	/*
+	 * Kasan may reuse the contents of kasan_early_shadow_pte directly, so we
+	 * should make sure that it maps the zero page read-only.
+	 */
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte(&kasan_early_shadow_pte[i],
+			pfn_pte(__phys_to_pfn(__pa_symbol(kasan_early_shadow_page)),
+				PAGE_KERNEL_RO));
+
+	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	 __sync();
+	csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
+	local_flush_tlb_all();
+
+	/* At this point kasan is fully initialized. Enable error messages */
+	init_task.kasan_depth = 0;
+	pr_info("KernelAddressSanitizer initialized.\n");
+}
diff --git a/arch/loongarch/vdso/Makefile b/arch/loongarch/vdso/Makefile
index d89e2ac75f7b..df328cd92875 100644
--- a/arch/loongarch/vdso/Makefile
+++ b/arch/loongarch/vdso/Makefile
@@ -1,6 +1,10 @@
 # SPDX-License-Identifier: GPL-2.0
 # Objects to go into the VDSO.
 
+ifdef CONFIG_KASAN
+KASAN_SANITIZE := n
+endif
+
 # Absolute relocation type $(ARCH_REL_TYPE_ABS) needs to be defined before
 # the inclusion of generic Makefile.
 ARCH_REL_TYPE_ABS := R_LARCH_32|R_LARCH_64|R_LARCH_MARK_LA|R_LARCH_JUMP_SLOT
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index f7ef70661ce2..3b91b941873d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -54,11 +54,13 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
 
+#ifndef __HAVE_ARCH_SHADOW_MAP
 static inline void *kasan_mem_to_shadow(const void *addr)
 {
 	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
 		+ KASAN_SHADOW_OFFSET;
 }
+#endif
 
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index e5eef670735e..f86194750df5 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -175,6 +175,11 @@ static __always_inline bool check_region_inline(unsigned long addr,
 	if (unlikely(!addr_has_metadata((void *)addr)))
 		return !kasan_report(addr, size, write, ret_ip);
 
+#ifndef __HAVE_ARCH_SHADOW_MAP
+	if (unlikely(kasan_mem_to_shadow((unsigned long *)addr) == NULL))
+		return !kasan_report(addr, size, write, ret_ip);
+#endif
+
 	if (likely(!memory_is_poisoned(addr, size)))
 		return true;
 
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index cc64ed6858c6..860061a22ca9 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -166,8 +166,9 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 				if (!p)
 					return -ENOMEM;
 			} else {
-				pud_populate(&init_mm, pud,
-					early_alloc(PAGE_SIZE, NUMA_NO_NODE));
+				p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
+				pmd_init(p);
+				pud_populate(&init_mm, pud, p);
 			}
 		}
 		zero_pmd_populate(pud, addr, next);
@@ -207,8 +208,9 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 				if (!p)
 					return -ENOMEM;
 			} else {
-				p4d_populate(&init_mm, p4d,
-					early_alloc(PAGE_SIZE, NUMA_NO_NODE));
+				p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
+				pud_init(p);
+				p4d_populate(&init_mm, p4d, p);
 			}
 		}
 		zero_pud_populate(p4d, addr, next);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a61eeee3095a..033335c13b25 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -291,16 +291,22 @@ struct kasan_stack_ring {
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
+#ifndef __HAVE_ARCH_SHADOW_MAP
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
 	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
+#endif
 
 static __always_inline bool addr_has_metadata(const void *addr)
 {
+#ifdef __HAVE_ARCH_SHADOW_MAP
+	return (kasan_mem_to_shadow((void *)addr) != NULL);
+#else
 	return (kasan_reset_tag(addr) >=
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
+#endif
 }
 
 /**
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328111714.2056-1-zhangqing%40loongson.cn.
