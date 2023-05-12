Return-Path: <kasan-dev+bncBAABB4V262RAMGQEAF4RANQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6996C6FFEAB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 03:59:16 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-54c2999fdc7sf177947157b3.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 18:59:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683856755; cv=pass;
        d=google.com; s=arc-20160816;
        b=bDt4f3jfx1C7hz//daJJqgbXPodwTh1PEIVds/ndrwco11tG0jSGBCBJrw78jt3icq
         BzyA6xFjX1JMaaEWhNg8GhH/IJqp890v/RYIveYBZzrS8OLvLN1inn/Lmfs0bwM25tV7
         jizfmnCWbWx+k1vWXSFE37MG2IgAgxxV/JgiFgtILmuaP2PAG9MzUjZm2pw9uvZdnjoH
         gtTppIxlMU8m64OviqFc6vftD5GLYVk5RG9UmfoX8dD3sfu/DLJIt/UJ7I/T+As7/FS0
         OtpDOLfzhtu+j/JGGBxQWvOGg4YAxacaweVdvZUqNoRwz0juFToelRzzYmcTOLexOZCl
         ++Vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=o+eWUCeV2GjzYMTpRH+3VGmfUMoetGLV1I6L1hDqEOs=;
        b=fymOyzJMhiXR3xHK0UK/+IeZYOU6Z/R+Y0sMvX8jKX7V5o3HP7c0TCRkmw8pcblcpX
         WZfZcQxbWS7VxBuTNtXdXxcWEEPa1l83bQWtKSkAAFAGKg4YV5ozhwu+aF3fO37qoXrS
         cqDYLR8UGwZnFjBABXFqYdp//2yNPCPu/789a9oK2Jjf+n7hzUczoAD4bc7T8vLMrhy4
         3S2sPeZmQMsArgCCMDKMcn2dniJUSJ+cOMkuQbG6iaYfgDEICfrg4opriz6NfXMOkcaS
         tJjtzX7SmW3hK7g3etGgZfY+2y93ytqOPhO1zr14pe2TgBdk6xpScdc4XbWd+8Sktqd8
         xVCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683856755; x=1686448755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o+eWUCeV2GjzYMTpRH+3VGmfUMoetGLV1I6L1hDqEOs=;
        b=mIir7TX+LZgyMZAw7qMzZvzTKoMoReoVILnm3MRoHL6RXJLgjsIj5QlB4PGNriZdX3
         WXZeYj4y2CGft1IBGHtsF2XX3qfJhssRJ7A+Ull+qmWxm8XhrbIzOut0X1ir9xsLUz0M
         BrjzoQMm8SpdkTjZUbrMqocbbUx0DKtvoIVo5riAOnN/LArGWk+yonVj2AJis/UCOiQG
         fzsFwSdcpvNSv3IYqCVwTBd4dx4vf2Snp4iRjP1m/6LLwrTbJD/10UwkRf2x7r1zDOkS
         Z1MQBAuBm+R8kW01K7GA436mFBvoYxXdgzZTdG5juUBcqQwNSwoogCL8uEsNYKy2MO2u
         0MUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683856755; x=1686448755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=o+eWUCeV2GjzYMTpRH+3VGmfUMoetGLV1I6L1hDqEOs=;
        b=Ws0/8JB2KdS/8E+XCFNGMfzn+j6NgZw4eQ+JWu3CbGRMzhRobbRBzYnhzdEw7DW66F
         +vbkWJAq2MA07Yvofetkoyc3+prtSDf5qGNMOvC2W6EoT+PT0EKh9lhz2iGB6qdIt+3A
         EF4WqIvl/SJW5Y9OKzN7xTs4AFDSxKskw6YMW21LAM7F1Bwlm7dx3fixbDSFKFlL1EC2
         FKXSepfWgixQr5NqQxzxUhrwwVvkS1tTHxnUMD7SHzVwUY1hUmEaHT6Z4cDqz9W81yOU
         v4SGcFNzqj5yIBDWFnWuJb+x1rczE9M++95GNJHUWH0ffaFVZKyD/jjWPFG1B4pfTxzR
         6kwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDznVylzvh2Hpe6SpT4QrX8PiZvgQMsHL8y1HJcwPHvCuGgRp/Fb
	vgTt4autByF/1PJu2EZUZS0=
X-Google-Smtp-Source: ACHHUZ4r87vcu+hB+5/phBooOkOY+13Ci3OhorGwuGYc7HAAsFHNMVpzcE6xiOuTxJu1IYtu+YiGYg==
X-Received: by 2002:a81:af54:0:b0:555:c893:cc9d with SMTP id x20-20020a81af54000000b00555c893cc9dmr13863028ywj.4.1683856754794;
        Thu, 11 May 2023 18:59:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:9851:0:b0:55a:a1b8:6532 with SMTP id p78-20020a819851000000b0055aa1b86532ls486101ywg.8.-pod-prod-gmail;
 Thu, 11 May 2023 18:59:14 -0700 (PDT)
X-Received: by 2002:a0d:e6cc:0:b0:559:f18d:ee94 with SMTP id p195-20020a0de6cc000000b00559f18dee94mr22754646ywe.10.1683856754189;
        Thu, 11 May 2023 18:59:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683856754; cv=none;
        d=google.com; s=arc-20160816;
        b=cTEu3PSDXBVLynKtsRxJWt7fe3lfztTarjJyCdkohlbbkg4YNe+yBt3IwBc8lsH+EY
         TGAQ76IwVxOY6xyang1Fn2vriMEtwM8Whf26fDp4HyFs2L1v6QNQVTIvyphzpbBS+B31
         UlRCBho2fKoaP250eBZ2McNwq7C+oY4YVUHXszjluZ2vFPystsHFDB15t5cIFU/jQj3T
         nQ9tCcXhzcOBiRQ/y/KUc0NQ+2OCdmdlbTvOfDZ8M7EoJqcbW34g/Ll/yxBVsx4jJ/jW
         Ms8akJupBhKDNPwoEpC/NXdxL60BF/7ww62HnJvXH//CmTFtdOw4EEj6tU8I1+BuLvyf
         nGtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=w154slxPZNBktLM+yGZQWdjIwtK4Ybc/bMOTvc1YVR8=;
        b=tUSBVY5DgfUD0LbA1GoKjAO7GuyOnct4O/OJCnLt056i1jA/2rQQMO2Z7mJ2iD2Qx4
         epqk8YNjNaN7cNNXDZR6xTE4ALkXwYbZZ5D3lwHAhwuZlJr4G4CBhSS/N2QopuZD15ab
         xx0ds2pKmBF1WtfB0IfqpmHcYUWQZMMlR7W3CFoUwuXQ+LCX2Ec4Tbrxw8E3S3/Kaylj
         bFV6Ro2NFzIW2WaG9K2wibY1TR/IatUP/VX6ySLfqWAW4M4CjdccHxn4EvZKqzOIalLh
         liFpSl/wETkqy1qVUNXwEik9T8UH+Y/cXKLmPA6wEirHb8QTldrNsx3KTrNbOdAQ5gT/
         Silg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id j11-20020a81920b000000b0055a18c30c56si1379535ywg.4.2023.05.11.18.59.12
        for <kasan-dev@googlegroups.com>;
        Thu, 11 May 2023 18:59:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8CxNulRnV1kqPkHAA--.13832S3;
	Fri, 12 May 2023 09:58:41 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Dx_8tPnV1kgchWAA--.22922S2;
	Fri, 12 May 2023 09:58:40 +0800 (CST)
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
Subject: [PATCH v3 4/4] LoongArch: Add kernel address sanitizer support
Date: Fri, 12 May 2023 09:58:39 +0800
Message-Id: <20230512015839.23862-1-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8Dx_8tPnV1kgchWAA--.22922S2
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvAXoWfWr18GrW5WF1xCr1rKw17ZFb_yoW5JFyDXo
	WYkF43Kw18Gw42k393Ww1DJFyUtr1qkFWfA3sFvF1fWF17ArW3G34UtFWSq343JrZYkr1f
	WayvgFs3X3sYqrnxn29KB7ZKAUJUUUU7529EdanIXcx71UUUUU7KY7ZEXasCq-sGcSsGvf
	J3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnRJU
	UUBvb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2IYs7xG6rWj6s
	0DM7CIcVAFz4kK6r106r15M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM2
	8EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4U
	JwAaw2AFwI0_Jrv_JF1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4
	CE44I27wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Wrv_ZF1lYx0E
	x4A2jsIE14v26F4j6r4UJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41lc7
	CjxVAaw2AFwI0_JF0_Jw1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1l
	4IxYO2xFxVAFwI0_Jrv_JF1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxV
	WUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAF
	wI0_Ar0_tr1lIxAIcVC0I7IYx2IY6xkF7I0E14v26F4j6r4UJwCI42IY6xAIw20EY4v20x
	vaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Cr0_Gr1UMIIF0xvEx4A2jsIEc7CjxVAFwI0_
	Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07jsSdgUUUUU=
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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
space (256T available) is insufficient to map all these segments to kasan
shadow memory with the common formula provided by kasan core, saying
(addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET

So LoongArch has a arch-specific mapping formula, different segments are
mapped individually, and only limited space lengths of these specific
segments are mapped to shadow.

At early boot stage the whole shadow region populated with just one
physical page (kasan_early_shadow_page). Later, this page is reused as
readonly zero shadow for some memory that kasan currently don't track.
After mapping the physical memory, pages for shadow memory are allocated
and mapped.

Functions like memset()/memcpy()/memmove() do a lot of memory accesses.
If bad pointer passed to one of these function it is important to be
caught. Compiler's instrumentation cannot do this since these functions
are written in assembly.

KASan replaces memory functions with manually instrumented variants.
Original functions declared as weak symbols so strong definitions in
mm/kasan/kasan.c could replace them. Original functions have aliases
with '__' prefix in names, so we could call non-instrumented variant
if needed.

Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
---
 Documentation/dev-tools/kasan.rst             |   4 +-
 .../features/debug/KASAN/arch-support.txt     |   2 +-
 .../translations/zh_CN/dev-tools/kasan.rst    |   2 +-
 arch/loongarch/Kconfig                        |   7 +
 arch/loongarch/include/asm/kasan.h            | 120 +++++++++
 arch/loongarch/include/asm/pgtable.h          |   7 +
 arch/loongarch/include/asm/string.h           |  20 ++
 arch/loongarch/kernel/Makefile                |   6 +
 arch/loongarch/kernel/head.S                  |   4 +
 arch/loongarch/kernel/setup.c                 |   4 +
 arch/loongarch/lib/memcpy.S                   |   4 +-
 arch/loongarch/lib/memmove.S                  |  16 +-
 arch/loongarch/lib/memset.S                   |   4 +-
 arch/loongarch/mm/Makefile                    |   2 +
 arch/loongarch/mm/kasan_init.c                | 255 ++++++++++++++++++
 arch/loongarch/vdso/Makefile                  |   4 +
 16 files changed, 448 insertions(+), 13 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kasan.h
 create mode 100644 arch/loongarch/mm/kasan_init.c

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/ka=
san.rst
index e66916a483cd..ee91f2872767 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -41,8 +41,8 @@ Support
 Architectures
 ~~~~~~~~~~~~~
=20
-Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, an=
d
-xtensa, and the tag-based KASAN modes are supported only on arm64.
+Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, xt=
ensa,
+and loongarch, and the tag-based KASAN modes are supported only on arm64.
=20
 Compilers
 ~~~~~~~~~
diff --git a/Documentation/features/debug/KASAN/arch-support.txt b/Document=
ation/features/debug/KASAN/arch-support.txt
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
diff --git a/Documentation/translations/zh_CN/dev-tools/kasan.rst b/Documen=
tation/translations/zh_CN/dev-tools/kasan.rst
index 05ef904dbcfb..8fdb20c9665b 100644
--- a/Documentation/translations/zh_CN/dev-tools/kasan.rst
+++ b/Documentation/translations/zh_CN/dev-tools/kasan.rst
@@ -42,7 +42,7 @@ KASAN=E6=9C=89=E4=B8=89=E7=A7=8D=E6=A8=A1=E5=BC=8F:
 =E4=BD=93=E7=B3=BB=E6=9E=B6=E6=9E=84
 ~~~~~~~~
=20
-=E5=9C=A8x86_64=E3=80=81arm=E3=80=81arm64=E3=80=81powerpc=E3=80=81riscv=E3=
=80=81s390=E5=92=8Cxtensa=E4=B8=8A=E6=94=AF=E6=8C=81=E9=80=9A=E7=94=A8KASAN=
=EF=BC=8C
+=E5=9C=A8x86_64=E3=80=81arm=E3=80=81arm64=E3=80=81powerpc=E3=80=81riscv=E3=
=80=81s390=E3=80=81xtensa=E5=92=8Cloongarch=E4=B8=8A=E6=94=AF=E6=8C=81=E9=
=80=9A=E7=94=A8KASAN=EF=BC=8C
 =E8=80=8C=E5=9F=BA=E4=BA=8E=E6=A0=87=E7=AD=BE=E7=9A=84KASAN=E6=A8=A1=E5=BC=
=8F=E5=8F=AA=E5=9C=A8arm64=E4=B8=8A=E6=94=AF=E6=8C=81=E3=80=82
=20
 =E7=BC=96=E8=AF=91=E5=99=A8
diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index ac3d3d9b5716..a9c879fd037e 100644
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
@@ -82,6 +83,7 @@ config LOONGARCH
 	select GENERIC_TIME_VSYSCALL
 	select GPIOLIB
 	select HAVE_ARCH_AUDITSYSCALL
+	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ARCH_TRACEHOOK
@@ -595,6 +597,11 @@ config ARCH_MMAP_RND_BITS_MIN
 config ARCH_MMAP_RND_BITS_MAX
 	default 18
=20
+config KASAN_SHADOW_OFFSET
+	hex
+	default 0x0
+	depends on KASAN
+
 menu "Power management options"
=20
 config ARCH_SUSPEND_POSSIBLE
diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/as=
m/kasan.h
new file mode 100644
index 000000000000..04fb6c210945
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
+#define XKPRANGE_UC_SEG		(UNCACHE_BASE >> DMW_PABITS)
+#define XKPRANGE_CC_SEG		(CACHE_BASE >> DMW_PABITS)
+#define XKVRANGE_VC_SEG		(0xffff)
+
+/* Cached */
+#define XKPRANGE_CC_START		CACHE_BASE
+#define XKPRANGE_CC_SIZE		XRANGE_SIZE
+#define XKPRANGE_CC_KASAN_OFFSET	(0)
+#define XKPRANGE_CC_SHADOW_SIZE		(XKPRANGE_CC_SIZE >> KASAN_SHADOW_SCALE_S=
HIFT)
+#define XKPRANGE_CC_SHADOW_END		(XKPRANGE_CC_KASAN_OFFSET + XKPRANGE_CC_SH=
ADOW_SIZE)
+
+/* UnCached */
+#define XKPRANGE_UC_START		UNCACHE_BASE
+#define XKPRANGE_UC_SIZE		XRANGE_SIZE
+#define XKPRANGE_UC_KASAN_OFFSET	XKPRANGE_CC_SHADOW_END
+#define XKPRANGE_UC_SHADOW_SIZE		(XKPRANGE_UC_SIZE >> KASAN_SHADOW_SCALE_S=
HIFT)
+#define XKPRANGE_UC_SHADOW_END		(XKPRANGE_UC_KASAN_OFFSET + XKPRANGE_UC_SH=
ADOW_SIZE)
+
+/* VMALLOC (Cached or UnCached)  */
+#define XKVRANGE_VC_START		MODULES_VADDR
+#define XKVRANGE_VC_SIZE		round_up(VMEMMAP_END - MODULES_VADDR + 1, PGDIR_=
SIZE)
+#define XKVRANGE_VC_KASAN_OFFSET	XKPRANGE_UC_SHADOW_END
+#define XKVRANGE_VC_SHADOW_SIZE		(XKVRANGE_VC_SIZE >> KASAN_SHADOW_SCALE_S=
HIFT)
+#define XKVRANGE_VC_SHADOW_END		(XKVRANGE_VC_KASAN_OFFSET + XKVRANGE_VC_SH=
ADOW_SIZE)
+
+/* Kasan shadow memory start right after vmalloc. */
+#define KASAN_SHADOW_START		round_up(VMEMMAP_END, PGDIR_SIZE)
+#define KASAN_SHADOW_SIZE		(XKVRANGE_VC_SHADOW_END - XKPRANGE_CC_KASAN_OFF=
SET)
+#define KASAN_SHADOW_END		round_up(KASAN_SHADOW_START + KASAN_SHADOW_SIZE,=
 PGDIR_SIZE)
+
+#define XKPRANGE_CC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_CC_KASAN_=
OFFSET)
+#define XKPRANGE_UC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_UC_KASAN_=
OFFSET)
+#define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_=
OFFSET)
+
+extern bool kasan_early_stage;
+extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
+
+static inline void *kasan_mem_to_shadow(const void *addr)
+{
+	if (kasan_early_stage) {
+		return (void *)(kasan_early_shadow_page);
+	} else {
+		unsigned long maddr =3D (unsigned long)addr;
+		unsigned long xrange =3D (maddr >> XRANGE_SHIFT) & 0xffff;
+		unsigned long offset =3D 0;
+
+		maddr &=3D XRANGE_SHADOW_MASK;
+		switch (xrange) {
+		case XKPRANGE_CC_SEG:
+			offset =3D XKPRANGE_CC_SHADOW_OFFSET;
+			break;
+		case XKPRANGE_UC_SEG:
+			offset =3D XKPRANGE_UC_SHADOW_OFFSET;
+			break;
+		case XKVRANGE_VC_SEG:
+			offset =3D XKVRANGE_VC_SHADOW_OFFSET;
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
+	unsigned long addr =3D (unsigned long)shadow_addr;
+
+	if (unlikely(addr > KASAN_SHADOW_END) ||
+		unlikely(addr < KASAN_SHADOW_START)) {
+		WARN_ON(1);
+		return NULL;
+	}
+
+	if (addr >=3D XKVRANGE_VC_SHADOW_OFFSET)
+		return (void *)(((addr - XKVRANGE_VC_SHADOW_OFFSET) << KASAN_SHADOW_SCAL=
E_SHIFT) + XKVRANGE_VC_START);
+	else if (addr >=3D XKPRANGE_UC_SHADOW_OFFSET)
+		return (void *)(((addr - XKPRANGE_UC_SHADOW_OFFSET) << KASAN_SHADOW_SCAL=
E_SHIFT) + XKPRANGE_UC_START);
+	else if (addr >=3D XKPRANGE_CC_SHADOW_OFFSET)
+		return (void *)(((addr - XKPRANGE_CC_SHADOW_OFFSET) << KASAN_SHADOW_SCAL=
E_SHIFT) + XKPRANGE_CC_START);
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
diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/=
asm/pgtable.h
index d28fb9dbec59..5cfdf79b287e 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -86,9 +86,16 @@ extern unsigned long zero_page_mask;
 #define MODULES_END	(MODULES_VADDR + SZ_256M)
=20
 #define VMALLOC_START	MODULES_END
+
+#ifndef CONFIG_KASAN
 #define VMALLOC_END	\
 	(vm_map_base +	\
 	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZ=
E, (1UL << cpu_vabits)) - PMD_SIZE - VMEMMAP_SIZE)
+#else
+#define VMALLOC_END	\
+	(vm_map_base +	\
+	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZ=
E, (1UL << cpu_vabits) / 2) - PMD_SIZE - VMEMMAP_SIZE)
+#endif
=20
 #define vmemmap		((struct page *)((VMALLOC_END + PMD_SIZE) & PMD_MASK))
 #define VMEMMAP_END	((unsigned long)vmemmap + VMEMMAP_SIZE - 1)
diff --git a/arch/loongarch/include/asm/string.h b/arch/loongarch/include/a=
sm/string.h
index 7b29cc9c70aa..5bb5a90d2681 100644
--- a/arch/loongarch/include/asm/string.h
+++ b/arch/loongarch/include/asm/string.h
@@ -7,11 +7,31 @@
=20
 #define __HAVE_ARCH_MEMSET
 extern void *memset(void *__s, int __c, size_t __count);
+extern void *__memset(void *__s, int __c, size_t __count);
=20
 #define __HAVE_ARCH_MEMCPY
 extern void *memcpy(void *__to, __const__ void *__from, size_t __n);
+extern void *__memcpy(void *__to, __const__ void *__from, size_t __n);
=20
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
=20
 #endif /* _ASM_STRING_H */
diff --git a/arch/loongarch/kernel/Makefile b/arch/loongarch/kernel/Makefil=
e
index 9a72d91cd104..b45c6932a6cf 100644
--- a/arch/loongarch/kernel/Makefile
+++ b/arch/loongarch/kernel/Makefile
@@ -30,6 +30,12 @@ ifdef CONFIG_FUNCTION_TRACER
   CFLAGS_REMOVE_perf_event.o =3D $(CC_FLAGS_FTRACE)
 endif
=20
+KASAN_SANITIZE_efi.o :=3D n
+KASAN_SANITIZE_vdso.o :=3D n
+KASAN_SANITIZE_cpu-probe.o :=3D n
+KASAN_SANITIZE_traps.o :=3D n
+KASAN_SANITIZE_smp.o :=3D n
+
 obj-$(CONFIG_MODULES)		+=3D module.o module-sections.o
 obj-$(CONFIG_STACKTRACE)	+=3D stacktrace.o
=20
diff --git a/arch/loongarch/kernel/head.S b/arch/loongarch/kernel/head.S
index aace7a300cd3..0d8180153ec0 100644
--- a/arch/loongarch/kernel/head.S
+++ b/arch/loongarch/kernel/head.S
@@ -104,6 +104,10 @@ SYM_CODE_START(kernel_entry)			# kernel entry point
=20
 #endif /* CONFIG_RELOCATABLE */
=20
+#ifdef CONFIG_KASAN
+	bl		kasan_early_init
+#endif
+
 	bl		start_kernel
 	ASM_BUG()
=20
diff --git a/arch/loongarch/kernel/setup.c b/arch/loongarch/kernel/setup.c
index 4444b13418f0..9e94bf60c900 100644
--- a/arch/loongarch/kernel/setup.c
+++ b/arch/loongarch/kernel/setup.c
@@ -610,4 +610,8 @@ void __init setup_arch(char **cmdline_p)
 #endif
=20
 	paging_init();
+
+#ifdef CONFIG_KASAN
+	kasan_init();
+#endif
 }
diff --git a/arch/loongarch/lib/memcpy.S b/arch/loongarch/lib/memcpy.S
index 39ce6621c704..b9eb89e90550 100644
--- a/arch/loongarch/lib/memcpy.S
+++ b/arch/loongarch/lib/memcpy.S
@@ -10,16 +10,18 @@
 #include <asm/export.h>
 #include <asm/regdef.h>
=20
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
=20
 EXPORT_SYMBOL(memcpy)
+EXPORT_SYMBOL(__memcpy)
=20
 /*
  * void *__memcpy_generic(void *dst, const void *src, size_t n)
diff --git a/arch/loongarch/lib/memmove.S b/arch/loongarch/lib/memmove.S
index 45b725ba7867..df521f8b9c9a 100644
--- a/arch/loongarch/lib/memmove.S
+++ b/arch/loongarch/lib/memmove.S
@@ -10,23 +10,25 @@
 #include <asm/export.h>
 #include <asm/regdef.h>
=20
-SYM_FUNC_START(memmove)
-	blt	a0, a1, memcpy	/* dst < src, memcpy */
-	blt	a1, a0, rmemcpy	/* src < dst, rmemcpy */
-	jr	ra		/* dst =3D=3D src, return */
+SYM_FUNC_START_WEAK(memmove)
+	blt	a0, a1, __memcpy	/* dst < src, memcpy */
+	blt	a1, a0, __rmemcpy	/* src < dst, rmemcpy */
+	jr	ra			/* dst =3D=3D src, return */
 SYM_FUNC_END(memmove)
+SYM_FUNC_ALIAS(__memmove, memmove)
 _ASM_NOKPROBE(memmove)
=20
 EXPORT_SYMBOL(memmove)
+EXPORT_SYMBOL(__memmove)
=20
-SYM_FUNC_START(rmemcpy)
+SYM_FUNC_START(__rmemcpy)
 	/*
 	 * Some CPUs support hardware unaligned access
 	 */
 	ALTERNATIVE	"b __rmemcpy_generic", \
 			"b __rmemcpy_fast", CPU_FEATURE_UAL
-SYM_FUNC_END(rmemcpy)
-_ASM_NOKPROBE(rmemcpy)
+SYM_FUNC_END(__rmemcpy)
+_ASM_NOKPROBE(__rmemcpy)
=20
 /*
  * void *__rmemcpy_generic(void *dst, const void *src, size_t n)
diff --git a/arch/loongarch/lib/memset.S b/arch/loongarch/lib/memset.S
index b39c6194e3ae..392901aba970 100644
--- a/arch/loongarch/lib/memset.S
+++ b/arch/loongarch/lib/memset.S
@@ -16,16 +16,18 @@
 	bstrins.d \r0, \r0, 63, 32
 .endm
=20
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
=20
 EXPORT_SYMBOL(memset)
+EXPORT_SYMBOL(__memset)
=20
 /*
  * void *__memset_generic(void *s, int c, size_t n)
diff --git a/arch/loongarch/mm/Makefile b/arch/loongarch/mm/Makefile
index 8ffc6383f836..6e50cf6cf733 100644
--- a/arch/loongarch/mm/Makefile
+++ b/arch/loongarch/mm/Makefile
@@ -7,3 +7,5 @@ obj-y				+=3D init.o cache.o tlb.o tlbex.o extable.o \
 				   fault.o ioremap.o maccess.o mmap.o pgtable.o page.o
=20
 obj-$(CONFIG_HUGETLB_PAGE)	+=3D hugetlbpage.o
+obj-$(CONFIG_KASAN)		+=3D kasan_init.o
+KASAN_SANITIZE_kasan_init.o     :=3D n
diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.=
c
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
+#define __p4d_none(early, p4d) (early ? (p4d_val(p4d) =3D=3D 0) : \
+(__pa(p4d_val(p4d)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pud)))
+#endif
+
+#define __pud_none(early, pud) (early ? (pud_val(pud) =3D=3D 0) : \
+(__pa(pud_val(pud)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pmd)))
+
+#define __pmd_none(early, pmd) (early ? (pmd_val(pmd) =3D=3D 0) : \
+(__pa(pmd_val(pmd)) =3D=3D (unsigned long)__pa(kasan_early_shadow_pte)))
+
+#define __pte_none(early, pte) (early ? pte_none(pte) : \
+((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_shadow_=
page)))
+
+bool kasan_early_stage =3D true;
+
+/*
+ * Alloc memory for shadow memory page table.
+ */
+static phys_addr_t __init kasan_alloc_zeroed_page(int node)
+{
+	void *p =3D memblock_alloc_try_nid(PAGE_SIZE, PAGE_SIZE,
+					__pa(MAX_DMA_ADDRESS),
+					MEMBLOCK_ALLOC_ACCESSIBLE, node);
+	if (!p)
+		panic("%s: Failed to allocate %lu bytes align=3D0x%lx nid=3D%d from=3D%l=
lx\n",
+			__func__, PAGE_SIZE, PAGE_SIZE, node, __pa(MAX_DMA_ADDRESS));
+	return __pa(p);
+}
+
+static pte_t *kasan_pte_offset(pmd_t *pmdp, unsigned long addr, int node,
+				     bool early)
+{
+	if (__pmd_none(early, READ_ONCE(*pmdp))) {
+		phys_addr_t pte_phys =3D early ?
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
+		phys_addr_t pmd_phys =3D early ?
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
+static pud_t *__init kasan_pud_offset(p4d_t *p4dp, unsigned long addr, int=
 node,
+					    bool early)
+{
+	if (__p4d_none(early, READ_ONCE(*p4dp))) {
+		phys_addr_t pud_phys =3D early ?
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
+	pte_t *ptep =3D kasan_pte_offset(pmdp, addr, node, early);
+
+	do {
+		phys_addr_t page_phys =3D early ?
+					__pa_symbol(kasan_early_shadow_page)
+					      : kasan_alloc_zeroed_page(node);
+		next =3D addr + PAGE_SIZE;
+		set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_KERNEL));
+	} while (ptep++, addr =3D next, addr !=3D end && __pte_none(early, READ_O=
NCE(*ptep)));
+}
+
+static void kasan_pmd_populate(pud_t *pudp, unsigned long addr,
+				      unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	pmd_t *pmdp =3D kasan_pmd_offset(pudp, addr, node, early);
+
+	do {
+		next =3D pmd_addr_end(addr, end);
+		kasan_pte_populate(pmdp, addr, next, node, early);
+	} while (pmdp++, addr =3D next, addr !=3D end && __pmd_none(early, READ_O=
NCE(*pmdp)));
+}
+
+static void __init kasan_pud_populate(p4d_t *p4dp, unsigned long addr,
+					    unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	pud_t *pudp =3D kasan_pud_offset(p4dp, addr, node, early);
+
+	do {
+		next =3D pud_addr_end(addr, end);
+		kasan_pmd_populate(pudp, addr, next, node, early);
+	} while (pudp++, addr =3D next, addr !=3D end);
+}
+
+static void __init kasan_p4d_populate(pgd_t *pgdp, unsigned long addr,
+					    unsigned long end, int node, bool early)
+{
+	unsigned long next;
+	p4d_t *p4dp =3D p4d_offset(pgdp, addr);
+
+	do {
+		next =3D p4d_addr_end(addr, end);
+		kasan_pud_populate(p4dp, addr, next, node, early);
+	} while (p4dp++, addr =3D next, addr !=3D end);
+}
+
+static void __init kasan_pgd_populate(unsigned long addr, unsigned long en=
d,
+				      int node, bool early)
+{
+	unsigned long next;
+	pgd_t *pgdp;
+
+	pgdp =3D pgd_offset_k(addr);
+
+	do {
+		next =3D pgd_addr_end(addr, end);
+		kasan_p4d_populate(pgdp, addr, next, node, early);
+	} while (pgdp++, addr =3D next, addr !=3D end);
+
+}
+
+asmlinkage void __init kasan_early_init(void)
+{
+	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_START, PGDIR_SIZE));
+	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, PGDIR_SIZE));
+}
+
+/* Set up full kasan mappings, ensuring that the mapped pages are zeroed *=
/
+static void __init kasan_map_populate(unsigned long start, unsigned long e=
nd,
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
+	for (; start < end; start +=3D PGDIR_SIZE)
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
+	kasan_early_stage =3D false;
+
+	/* Populate the linear mapping */
+	for_each_mem_range(i, &pa_start, &pa_end) {
+		void *start =3D (void *)phys_to_virt(pa_start);
+		void *end   =3D (void *)phys_to_virt(pa_end);
+
+		if (start >=3D end)
+			break;
+
+		kasan_map_populate((unsigned long)kasan_mem_to_shadow(start),
+			(unsigned long)kasan_mem_to_shadow(end), NUMA_NO_NODE);
+	}
+
+	/* Populate modules mapping */
+	kasan_map_populate((unsigned long)kasan_mem_to_shadow((void *)MODULES_VAD=
DR),
+		(unsigned long)kasan_mem_to_shadow((void *)MODULES_END), NUMA_NO_NODE);
+	/*
+	 * Kasan may reuse the contents of kasan_early_shadow_pte directly, so we
+	 * should make sure that it maps the zero page read-only.
+	 */
+	for (i =3D 0; i < PTRS_PER_PTE; i++)
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
+	init_task.kasan_depth =3D 0;
+	pr_info("KernelAddressSanitizer initialized.\n");
+}
diff --git a/arch/loongarch/vdso/Makefile b/arch/loongarch/vdso/Makefile
index d89e2ac75f7b..df328cd92875 100644
--- a/arch/loongarch/vdso/Makefile
+++ b/arch/loongarch/vdso/Makefile
@@ -1,6 +1,10 @@
 # SPDX-License-Identifier: GPL-2.0
 # Objects to go into the VDSO.
=20
+ifdef CONFIG_KASAN
+KASAN_SANITIZE :=3D n
+endif
+
 # Absolute relocation type $(ARCH_REL_TYPE_ABS) needs to be defined before
 # the inclusion of generic Makefile.
 ARCH_REL_TYPE_ABS :=3D R_LARCH_32|R_LARCH_64|R_LARCH_MARK_LA|R_LARCH_JUMP_=
SLOT
--=20
2.36.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230512015839.23862-1-zhangqing%40loongson.cn.
