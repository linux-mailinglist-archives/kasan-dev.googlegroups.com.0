Return-Path: <kasan-dev+bncBAABBL5262RAMGQEAJFRDEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4338F6FFE9D
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 03:58:09 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-331581c2b13sf138526275ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 18:58:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683856687; cv=pass;
        d=google.com; s=arc-20160816;
        b=jFmE2FuFjWsjEp6B24n28qkulpN0DVySUTs8lF/S0nOlWPph+Y5wkD4YMj0C0bv9Z6
         xJVNAzZaJuU05Wa68N2O8SCP3SWCkWVkFKKjk8gelhW/Rs4BMoC3lyVJCZgnuSWqUZGs
         djTrOFWWmNOgyN1p+pCnH1TD28X0I90GHoNlGIbajvS0I39WxRKvYf95BCrHZrXSifqK
         HIFjm8KnNf0BGD+qluxPmDaDOuidaCTWVWGRsMaEAGiB0TeJ2nPiJTuOJ9Rt1uPHNh4H
         2YBFaEFF293AaldahMcRTZx0PLxpoWpEQ0692AevPXeXaEj5wg/q8pgqrcdjKsvi/N9p
         PM3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WFVKrsrAmFKoH9tdtkQS5c3yF046x+dm2H6xdrCcoLk=;
        b=A8TgMK7s87I2TuFXH+7ORjlNkVUs8rCXtbNjR4gznrOLsx7gTqewyx5hdGoIWGjlEb
         9yg54myVptJtPSPUYr5S0YwZFkYukqGGCnICN3HMOhUdMkEcxhEqtSmuR8/XoECSXPLv
         Q/0527+qGE/lDkBNp8bo9w69THllIIWm0VJg5ye7oAygbNdVrh40XWQKR4shnL7OsTLC
         8xgW1g21imB7noI6LJAwm8b3oyjhIsT1k3UAdqR00HG4mhHp8tRsH/xLmAUQoPbzbBnd
         DjhXv3VJx4BwJObY96wNPmyOsGuyRneusfpz2nqMDgYQd3AwhUsXhtWBad19iIgECkHb
         5fzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683856687; x=1686448687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WFVKrsrAmFKoH9tdtkQS5c3yF046x+dm2H6xdrCcoLk=;
        b=mYJvH6bvELWxR79Zs5pVB1UWB5WnAO8gys+HHvmaVTpezjTQE9sP8enE66I6Hksvp/
         BveodCL0YfsvYNmAEIoethtBwAMGM2/mOuAYmn9cvolG8WNdQXktT9oJW4C5nfAKJuQC
         e8a5zJz9aYrz0XTnuS2rZpWKDxjDPD/bWS0LqSeY8VRlYAXrnyYeeJd8zfJG+jJ6O9db
         0cE6iAmaA/lLcUTD2BJRSPZ3PQP2m2KboHVurxvTR6ujkATmsDhISpF4NEBr2XiMVCev
         DOzK4/uShC245t93mrR4jWb1kreBQz+wnX/N6hJPL2Ex+vNwoO16ZTEaihKKkMGQqXAN
         MA/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683856687; x=1686448687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WFVKrsrAmFKoH9tdtkQS5c3yF046x+dm2H6xdrCcoLk=;
        b=TCFEtzZxg52pmkWU9nnwaSvfnvYMi7p5VdkqqLkc2BABC0UcFRuQ0ZtaXxMxezy2nA
         cZPENxyvqlXOWCWqYZxhWYT4AK5Mx/0DStG2Dn7BpTTysrk0azo31ERQM0DFqI8KJzkl
         xEnLXcdHfNOURTPN55F43W/CoeGNTLfgcPPkN1S5DbT+craA+dYRfEHazNLBIhCaVqbR
         fvBAqqZfUo2MrwHmKusYu2SxOy3KmC8onkmWGPYeQpeLu9IuE/vJRFc5Vv5LJLYU1tSi
         gc72VI7PoMiryrUiwwOG6It+LvZTzsIJPLQb9tt7F003KdvCp3tXW/RI4OsmY9dWolIu
         RVVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyc/rKt9oWLIlIzpEIPLK7oeU4UlsJuyaSIKWqblMVU/W3ZvZdz
	IEXzqDMyrZucpMUUFoPu48o=
X-Google-Smtp-Source: ACHHUZ41Z9PSrATs7HjR/75LQbJkMRQRr3Oi1rA2tgNFgfOZbjZzBNcVz+oPsI4Y4w/7d2j/rDojCw==
X-Received: by 2002:a92:d6cf:0:b0:335:908b:8ee with SMTP id z15-20020a92d6cf000000b00335908b08eemr5835220ilp.2.1683856687586;
        Thu, 11 May 2023 18:58:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1072:b0:331:2c30:78bc with SMTP id
 q18-20020a056e02107200b003312c3078bcls1020253ilj.1.-pod-prod-01-us; Thu, 11
 May 2023 18:58:07 -0700 (PDT)
X-Received: by 2002:a05:6e02:6c1:b0:335:87f9:50e4 with SMTP id p1-20020a056e0206c100b0033587f950e4mr10464438ils.29.1683856687193;
        Thu, 11 May 2023 18:58:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683856687; cv=none;
        d=google.com; s=arc-20160816;
        b=WaoT5eEsAHNQKMfo/4mUt5lhUjWlmBoSsASGn+C/+Z8zA3NVnKghnZI1b/1Lo/gk8k
         aiQFQ/ogO9TqmIBKy8dZbTDnxv3YVG8Hk+nQzR1yZX7iu0GvsR7vFjqKWk0grbmTTcUU
         Q0Emkapmn9ww4OcqMfgPYNQx/A8gR8fKamLgrfXo2GUWdCZFqCqcOqNP+3HUYsIbOu0i
         y3XV/CHJW8DNKqr2yLr2lCkzyL0lUZZVqB/J+ElO/dEchIzqemXUbl4MDmPoyfQ+EoOf
         IRQAMLspzQKeNR0UrxWtzxFp8d986m6p4eAmYXbpOT8ADoSpx5dr72DTaPHPf/Bn75Q/
         kG9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=/qcioOGpEyrK1DfayFZ1cTPTEWzfxZmJdAsv2u78Jqs=;
        b=APdzsul0w0a+0EcF92+vDu5yS8BsGs65Z953miNqWAv/LZsc8itRgFP8GUpG8DUXjx
         rtnL3skmPYkQ+5txVqbYrjfUvGlWpjrO18FP3TzZKpoFDoRN0aY9dIO3k6tkXr0OjiDs
         V7Vk5wbL9WACbPnlmKgWcIMH44prgZ0wtw6gpAtsLcAUdrDKBX8I95vUcC1hYL9ESOpk
         6zmKkP9U/lLZ0ye/8HpOIQn05JRGMCugpimEj7Q9/xdiMbWWhjYHzW17PTcdqx0yw3gQ
         2iXNhxWBeX+FM524y7WO/GNWb4V+tMzdCTw2j1kD6BTZtHSPBlecp2NU42ZSCw4nRSZX
         nehg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id v4-20020a056638250400b0040fc30ac205si1344383jat.0.2023.05.11.18.58.05
        for <kasan-dev@googlegroups.com>;
        Thu, 11 May 2023 18:58:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8Dxi+oNnV1kPfkHAA--.13629S3;
	Fri, 12 May 2023 09:57:33 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8DxXrMMnV1kocdWAA--.23198S2;
	Fri, 12 May 2023 09:57:33 +0800 (CST)
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
Subject: [PATCH v3 0/4] LoongArch: Add kernel address sanitizer support
Date: Fri, 12 May 2023 09:57:27 +0800
Message-Id: <20230512015731.23787-1-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8DxXrMMnV1kocdWAA--.23198S2
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoWxZFy3GrWkCr45Jw1DGryUWrg_yoW5tw1fpa
	9rur95Gr4UGrnayrZ7t348ur13J3Z3Ka12qFyay395AF45Wr10vr4vkryDZF9rG3y8JFy0
	q3WrGwn0gF4jya7anT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	b7xYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_JrI_Jryl8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVWUCVW8JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwA2z4
	x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UM2AI
	xVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l5I8CrVACY4xI64
	kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r106r15McIj6I8E87Iv67AKxVWUJVW8JwAm
	72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41l42xK82IYc2Ij64vIr41l4I8I3I
	0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWU
	GVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI
	0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E14v26r1j6r4UMIIF0xvE42xK8VAvwI8IcIk0
	rVWUJVWUCwCI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r1j6r
	4UYxBIdaVFxhVjvjDU0xZFpf9x07URa0PUUUUU=
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

Changes v2 -> v3:
- Rebased on 6.4-rc1
- Add Makefile ``KASAN_SANITIZE`` annotation for tlb related files
  to adapt to multiple cores.

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

Qing Zhang (4):
  kasan: Add __HAVE_ARCH_SHADOW_MAP to support arch specific mapping
  kasan: Add (pmd|pud)_init for LoongArch zero_(pud|p4d)_populate
    process
  LoongArch: Simplify the processing of jumping new kernel for KASLR
  LoongArch: Add kernel address sanitizer support

 Documentation/dev-tools/kasan.rst             |   4 +-
 .../features/debug/KASAN/arch-support.txt     |   2 +-
 .../translations/zh_CN/dev-tools/kasan.rst    |   2 +-
 arch/loongarch/Kconfig                        |   7 +
 arch/loongarch/include/asm/kasan.h            | 120 +++++++++
 arch/loongarch/include/asm/pgtable.h          |   7 +
 arch/loongarch/include/asm/setup.h            |   2 +-
 arch/loongarch/include/asm/string.h           |  20 ++
 arch/loongarch/kernel/Makefile                |   6 +
 arch/loongarch/kernel/head.S                  |  13 +-
 arch/loongarch/kernel/relocate.c              |   8 +-
 arch/loongarch/kernel/setup.c                 |   4 +
 arch/loongarch/lib/memcpy.S                   |   4 +-
 arch/loongarch/lib/memmove.S                  |  16 +-
 arch/loongarch/lib/memset.S                   |   4 +-
 arch/loongarch/mm/Makefile                    |   2 +
 arch/loongarch/mm/kasan_init.c                | 255 ++++++++++++++++++
 arch/loongarch/vdso/Makefile                  |   4 +
 include/linux/kasan.h                         |   2 +
 mm/kasan/init.c                               |  18 +-
 mm/kasan/kasan.h                              |   6 +
 21 files changed, 478 insertions(+), 28 deletions(-)
 create mode 100644 arch/loongarch/include/asm/kasan.h
 create mode 100644 arch/loongarch/mm/kasan_init.c

-- 
2.36.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512015731.23787-1-zhangqing%40loongson.cn.
