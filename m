Return-Path: <kasan-dev+bncBAABB6WFV6QQMGQECBWABUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 157926D5B14
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 10:42:37 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id j15-20020a17090a318f00b0023fe33f8825sf9953156pjb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 01:42:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680597755; cv=pass;
        d=google.com; s=arc-20160816;
        b=q74rBf7smHMoui+t9bgUxqt1V14ZtoAbHZ1q1yQ33rEK3y/hu2G8kbUsKUAvGdIQM7
         ylLeJ8acipIkjLyNLkQwFKCJ1neJyHEscyrBkGgaB8mKnSNml6X9aU+idkljv/zejYDJ
         mgRaIbAcEGW/k6X0OuupcL1I7R5WcBv6jegfIkkeYvQjpKNxCu+bLc5Zc2oE8ohR5w7G
         hIN9T+65krx5LdtMecGAAvVKPEz3TQnHZkKJRSi2PDrpwRbcxhBnHxim6KXCPOhlSECB
         tPBx0gxT/+DMc/4+edMKVyGRdmYOy7pk6oBsLjUUDJR6zUXHIjIc+e1B6eFK9+x7Uc2s
         9pow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZNPn/Xs1IL3oRCbRHRltbgUn7GvS2DvCwge79jDc+8w=;
        b=ND7aDOp038SAIUhn9S+WZA9iF0Ajq3c17sbqLcMKR9qgGPfMZpaAMvNozQBXAN0SZn
         /L9papVILrfEKoE7RRQVIjUkX9OA3JVIrS3UOj1YXamhfAoxr/kIooFSf82hYaZo58ZH
         JZLhJz3ZdnbXOBpbp2iiQV382FvudoIZQWveAXC9Bcvcu9uedBJlEbhODfD7bGGrxsl8
         weN8fVsIQBNiWBoXx0jxT3B49liYd0oAvmfQOtut3CJYnYfY3Fbo1PtjwHk0QVJx4dqY
         5Kg8WBBttwOdBMHiyFBbQ9R82sZiuVLKaf/nunA0/WXgUmnieyfwB1gCcAxs3yTXMtGE
         7YJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680597755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZNPn/Xs1IL3oRCbRHRltbgUn7GvS2DvCwge79jDc+8w=;
        b=dWGitOu37wagkeAfQUbBZMXx9uBceeFtE3FLE98txAyuSRXIdGZxj/3jjWIJy2D+Fi
         g5e2+VBXx4LrPOU8+VXHoo48/Jr++toK+Rabf/61h/PuSpl9dv730ZG7okicebSEn43F
         fBQDJbIVZRW2TA5KfNIcpiG4MyxBdAqTfLulCl5Mzj0pSrUrR4Ary9R3CvYWrt5+WgN9
         JbawtUc0nl72+3w+mq5vw/9cX3v+mSa4Sxx6CAbPEhfawnDtZpX7RZEuPmV/z+m7An0c
         jj2w0BzJY/4oPcldsnAnS0ArBLAXmIQS+TJ2+OJ6ccNHmJi1/5uJzS2ftrFrrueJJjaU
         jHRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680597755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ZNPn/Xs1IL3oRCbRHRltbgUn7GvS2DvCwge79jDc+8w=;
        b=Xqab12j5fQtAoL6zlefKi5iyCPlo3AD4yaV2ydtyoMlrvThxUFVi6iuvpGU4k+6F2R
         17d8rNF5wAjf3OHWU65Bvabrh6SJF56zQ0G8sfRVpALx+wAwILn4hl0xbMNZX6XpIM8F
         NTiQ9deyzCp2dE+DPT8dtwsPRKGV3i2V7WGcXQGUhZ+RDjVR2XOnAKJRWt6GX1olLICQ
         93s+hcf1AGSpgUPs2Aje/jykphqyRYgC0YvyrVaQyosCmwNlldvMPVCeHuH+Fqx0/Hr2
         TSRq1FwRGyIlKHMGyZfi5V62kIx8OMfrxpWr8JTxI0Or4kAx1daIFLw2Ya8GPVBTKIVc
         wE2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fUciL8YYeMJq6DUxc8HYcLWe17Wl3WV4PdprN08l5T6oLIC7r+
	isaYqyQ/46A35r0v6QbYEhw=
X-Google-Smtp-Source: AKy350YJz+gI+7e2iHek1j0riD4gt1QQF81VBSNg/j4q3sqvoBBBlAn455xzh8D9DmuV2eeFVuG+Xg==
X-Received: by 2002:a17:903:11ce:b0:1a1:b3bb:cd5e with SMTP id q14-20020a17090311ce00b001a1b3bbcd5emr759485plh.9.1680597754703;
        Tue, 04 Apr 2023 01:42:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4aca:b0:237:18be:2595 with SMTP id
 mh10-20020a17090b4aca00b0023718be2595ls14519786pjb.3.-pod-control-gmail; Tue,
 04 Apr 2023 01:42:34 -0700 (PDT)
X-Received: by 2002:a17:902:fac3:b0:1a1:add5:c355 with SMTP id ld3-20020a170902fac300b001a1add5c355mr1786882plb.5.1680597754044;
        Tue, 04 Apr 2023 01:42:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680597754; cv=none;
        d=google.com; s=arc-20160816;
        b=Lg2Q4b4d6i14ytW03QBqbM2iKi6G2qMRABZkPTPwZxCw8/bZ2ntFJAbBbjz8cy3Q/m
         RLtUzm6p8BRxJoZLW5yqC0iIJQF2GGh84tPSX9b0Aju8+mDZf9n2H3T+RIPW789pOsLt
         DJff64HEcOzUdeVcIf/IIZvwpHM75KYq8hrbCFCfqN4YQGI3PkKaKd7IpAd7h04risW2
         1jm1UOm8qpHPQRaGVu6DwBxeE61+3gw9wNQd/uMGZ8tbKp8mhlNmmew1CsVTmSQfrVoh
         OVg3jlnrIhCSceWdWL88GYQ0WXJcn5+R5rGnqcEKG/ZOxdKkyB8i9XAcnNGiBsBSsBHA
         wQXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=NxWZ9uTAbbn3eyWNm5vZpL0TzfkXwJbO9fi7Lte4tSU=;
        b=Wa4m9vy+ZJM7YE9rpcrbIqbnH5vGl/lVFReiSCWCBqGlxMcG7NTh3a9k674X7qucX6
         b9hDMv7at5enNB/zzWj0Ul2Jmv110wRc8hvvQe9+TsNLxuZUdATAzH8SLiZ1BDeZb3JG
         2u+CJ4XcLJ5hNG+sT5RRdxXbTUy1g9j1gFqomGhcXZEiUrHm85c7LmZu3CgyhKickNZg
         T/d+s6L97OVVclfxS8jlfyrcLuczELvFOD8nBIZ4eB2KYxryjBxpZ9ZjZtfm/O5Ou8mi
         cipB3+6JX2AhyOkptPgX8d/nTT7qER2DscWKa6JLt2jyv37c+BH7gpxsw+015Hr4Qaq7
         7whw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d3-20020a63d643000000b0051322a48c32si623145pgj.1.2023.04.04.01.42.33
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Apr 2023 01:42:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8CxxtjY4itkMV0WAA--.34258S3;
	Tue, 04 Apr 2023 16:42:00 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8DxwOTW4itkYRYVAA--.55009S2;
	Tue, 04 Apr 2023 16:41:59 +0800 (CST)
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
Subject: [PATCH v2 0/6] LoongArch: Add kernel address sanitizer support
Date: Tue,  4 Apr 2023 16:41:42 +0800
Message-Id: <20230404084148.744-1-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8DxwOTW4itkYRYVAA--.55009S2
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoWxZFyfuryDuw4kZr4rXw4kXrb_yoWrJrWkpa
	9rur95GF48Grs2yrn7t34Uur13J3Z3Kay2qFyay34rCF43Wr10vryv9ryDZF9rG3y8JFy0
	qw4rG3Z8XFWYyaDanT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	b7AYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_Jrv_JF1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVWUCVW8JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwA2z4
	x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjcxK6I8E87Iv6xkF7I0E14v26r4UJVWxJr1l
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

Kernel Address Sanitizer (KASAN) is a dynamic memory safety error detector
designed to find out-of-bounds and use-after-free bugs, Generic KASAN is
supported on LoongArch now.

1/8 of kernel addresses reserved for shadow memory. But for LoongArch,
There are a lot of holes between different segments and valid address
space(256T available) is insufficient to map all these segments to kasan
shadow memory with the common formula provided by kasan core, saying
addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET

So LoongArch has a ARCH specific mapping formula,different segments
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

Changes v1 -> v2:
Suggested by Andrey:
- Make two separate patches for changes to public files.
- Removes unnecessary judgments in check_region_inline.
- Add pud/pmd_init __weak define.
- Add Empty function kasan_(early)_init when CONFIG_KASAN turned off.
Suggested by Huacai:
- Split the simplified relocation patch.
Suggested by Youling:
- Add ARCH_HAS_FORTIFY_SOURCE in Kconfig and split into separate patches.
- update `Documentation/translations/zh_CN/dev-tools/kasan.rst`.
- Use macros to avoid using magic values directly.
- Modify patch sequence.
- Remove redundant tab.
- Modify submission information.

Qing Zhang (6):
  LoongArch: Simplified randomization layout after jump new kernel
    processing
  LoongArch: Fix _CONST64_(x) as unsigned
  LoongArch: Add kernel address sanitizer support
  kasan: Add __HAVE_ARCH_SHADOW_MAP to support arch specific mapping
  kasan: Add (pmd|pud)_init for LoongArch zero_(pud|p4d)_populate
    process
  LoongArch: Add ARCH_HAS_FORTIFY_SOURCE

 Documentation/dev-tools/kasan.rst             |   4 +-
 .../features/debug/KASAN/arch-support.txt     |   2 +-
 .../translations/zh_CN/dev-tools/kasan.rst    |   2 +-
 arch/loongarch/Kconfig                        |   8 +
 arch/loongarch/include/asm/addrspace.h        |   4 +-
 arch/loongarch/include/asm/kasan.h            | 125 +++++++++
 arch/loongarch/include/asm/pgtable.h          |   7 +
 arch/loongarch/include/asm/setup.h            |   2 +-
 arch/loongarch/include/asm/string.h           |  20 ++
 arch/loongarch/kernel/Makefile                |   3 +
 arch/loongarch/kernel/head.S                  |  12 +-
 arch/loongarch/kernel/relocate.c              |   8 +-
 arch/loongarch/kernel/setup.c                 |   4 +
 arch/loongarch/lib/memcpy.S                   |   4 +-
 arch/loongarch/lib/memmove.S                  |  13 +-
 arch/loongarch/lib/memset.S                   |   4 +-
 arch/loongarch/mm/Makefile                    |   2 +
 arch/loongarch/mm/kasan_init.c                | 255 ++++++++++++++++++
 arch/loongarch/vdso/Makefile                  |   4 +
 include/linux/kasan.h                         |   2 +
 mm/kasan/init.c                               |  18 +-
 mm/kasan/kasan.h                              |   6 +
 22 files changed, 481 insertions(+), 28 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kasan.h
 create mode 100644 arch/loongarch/mm/kasan_init.c

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230404084148.744-1-zhangqing%40loongson.cn.
