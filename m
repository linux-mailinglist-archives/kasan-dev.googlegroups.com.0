Return-Path: <kasan-dev+bncBAABBQ7JRLFAMGQEVV6O2RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BAFECC7F42
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 14:49:13 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-430fdc1fff8sf1578711f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 05:49:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765979332; cv=pass;
        d=google.com; s=arc-20240605;
        b=YiEBkXARQdn1jabLUlpcfY2n4AGD8RgAWEqpRLN6VF7znb2dbZ6Xr8DGM0zqsOTgV4
         9SyZ/8J0foJ9HJFu7uGLT1dYDbszIngFigQ/GBcTbIocZAgpv3jHUb/+EeOo6wUj2DS5
         0igV9VjVENw2UXFZe2zjGk0q5xF42onBVMBySD+9t5WpQrJmL5eT0Ml/ybBfr5D/i5la
         9D13O4t/+0EsQC2UUR4dyRzEsbYqwx1FjSjHrhqkTXqMaYCr/ZFyu0bZMBHdr0R6IeQt
         dWn4G++bCr9HsD4BY6GXJzlza93skRyvTy8XIs92AqioLFpNYpc5MtcEPVGV7ZYDxayl
         EgIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :message-id:subject:cc:from:to:date:dkim-signature;
        bh=na7ov4RC908uU1yGwybDiFkI2quIP+w83FBBoDXPF/M=;
        fh=Yk3S/OUGG3b5sFDDb8txldrWxs0jxazdFZ5BcDdC4dc=;
        b=KT3rQfE8DLYPuBh6iwdzKy3XuOQh88e7W3KX3c+Jce/pQ9JgoMKQ2fUdp+inZmoyJg
         gWJOpR5Ebie2pVOomwWebBtqw9MfP1Dy69uPPMxK0L6HApHs0OJXBSnUsVoWEhiBRDgM
         1k9JjR6FI8XdN+bbeZLSi2twg3AJrRr2t6BRiS6VTIbLgnjU6aCNtTVLaaWENAaaBG83
         KDnimkdUi52oaTnWaexmHNDDNtlj5M9dB2M9Xj1/3Iwlj0rKOKKKlecUXahlckYsVHBz
         2nnkxjgzLdBYOt11KPh2gDqUdw+uz+enTKM/ujR5yCNkhDfduUe4xxpKlbdPvEYsIiUq
         lj7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Q6rcfmRS;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765979332; x=1766584132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=na7ov4RC908uU1yGwybDiFkI2quIP+w83FBBoDXPF/M=;
        b=WPHOejEYwRnMFT88QavcMaf9ilAPsYeZZNnMq1RRydw259g61JJQyUt9hYcKSefqhm
         ZDJ43LOlZUCVe5M/d4l/bhY+NJ9t9USaULGjJPfTaSLHAhgtbGj/0GZGdozUYPGzQgQp
         j4QO84WOJDoa/MtYxlj+upRurzDeX0mUtPPMjFYaNIoI6nt0QkJITJyHBhvcYTbkXv7m
         FwtWn8Q/cwoX3IdZhf1pFqU1ONbhk7gidPgLe/hiRmteGDeJiipYToDBKhWlBLmX75+C
         T+63Us/BHagx/HQEo2IUuvxT6I3gYPkrLkUsEsxzCLmsDD9qNbdgaId1LPyP1AaYJ5JB
         Ii7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765979332; x=1766584132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=na7ov4RC908uU1yGwybDiFkI2quIP+w83FBBoDXPF/M=;
        b=uRN2/Be/sUU6tP74Z8llCB3gFDZSVFbVvnKq690iCoeON3/CSQnCM1kI+N974yGJ8j
         q8JX1VDXPTounPksNPyFI0888Us3IxqQ9t8ygPXmuMJOOw9Hy63j3ty00JtFJLEZUVGB
         RkCaZqUfbteVGEWTSr/duGY4Lh4pyasFC1mX/+/JwADdMF3QQs4CNXrUdUACef/UTOJR
         itYn8Pv9UnJlPw+BPhxyhlZGXTBQeviy64De48OIPl3sFY0odpYRiQkccZaaVKpYuFDW
         MAr1kX6jA6Fpe7LoCf68CkGyO6kK1MeLQLEyFbz/E584/af35+por57CZiGO9Re+uklx
         V9Cg==
X-Forwarded-Encrypted: i=2; AJvYcCX6nV3rW/CXWnOfaiEn3sR+vNtx7f1hnPiPp0CQ1CI7PkCmz+VUgqTj29/ZkHf0vmWkZBVeAA==@lfdr.de
X-Gm-Message-State: AOJu0YxRQiWmf/tSZQPn/LLuVssW8igvCBRYhqBgzNPbCwkTMRjl+pVe
	SCJ+p6bm7TXvXpaP1ZQfVRXvKzGGOchIvRITN6/Bl72H/G1193SlVIfd
X-Google-Smtp-Source: AGHT+IGPy0VP9I6fH+oxKF7LAMWbdn6M5n2i9Ljo0L3BROecOun/cZryuRAt3T/rB9aWGoU2AaWzDA==
X-Received: by 2002:a05:6000:2382:b0:431:32f:3159 with SMTP id ffacd0b85a97d-431032f341amr6800590f8f.7.1765979332206;
        Wed, 17 Dec 2025 05:48:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbpt500GKZPhfWs2WGddY0IcgVTM5Wa8kwot/OIhkXBJQ=="
Received: by 2002:a05:6000:144d:b0:42b:52c4:6654 with SMTP id
 ffacd0b85a97d-42fb2c83f96ls2841832f8f.1.-pod-prod-06-eu; Wed, 17 Dec 2025
 05:48:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVCzJErYE9XF9l/dCqg6qzamZVoxv7gwwZoCEnIgqNh7aur/ywlewRJIBJKdjSjTec8ggluTyyyer4=@googlegroups.com
X-Received: by 2002:a05:6000:40cc:b0:431:7a0:dbbe with SMTP id ffacd0b85a97d-43107a0dcd6mr5858034f8f.32.1765979329936;
        Wed, 17 Dec 2025 05:48:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765979329; cv=none;
        d=google.com; s=arc-20240605;
        b=QRZBGjwaxnbmPrHHYaFxSY3znlqSTrpIxWlZ2qdulUh+tozOg3wIxdODxMaoBBhQP/
         5nBF1CKauBlDNXmrHRyEuHKrqRJJFxvUOHRwWhMZBiTGPJdtFNcqZPwgcV7xDrS9ma6W
         NxjlGLlTD8jw6Z9MgsHr2qRuP/Miauh7Nz2h+W9y3rsHprxhYLk1DA25jPzUI3Exo8cK
         LKRJRPex2EyQVdTmuc2WOoPcHW+F6IdumMXVbxzrBlqH5gCcnw9O4oZPto/83o8tlBQR
         46pMj1qIxZEQkSELCVz3EFe+ierxSyUpqnXzaoMd253M/72vYpS1Ooqhp8xUfVRKrGXh
         zIwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=0jXeP64J9NWSfjxyXFi/0TIVi8GX+FvR7ErLahIOjKs=;
        fh=VBv8+jODd3U41U8TMqM8CaxgG0cTvMGvgayE1ATspsM=;
        b=T8MZBNrUMkilwe61whVkCZIZci3XdDpifJsB3pfFOG3mbgEyoSyEg2xsy5gdWKlDX6
         QAd+3wfQ/uMWfvPTfO3d3QX9pWXB8DKRR+vM5vDBi82DR+4Hqafwzqu9iycMTaF0snbO
         re7OPmHAGzideIIq3I8JttURuR61Vd7XDXijp/xCH0TWXaTdecUw9+q+8ynmRkxquqQc
         EUAJYPttxl57a3XffnR9oPdp2/othQkQe1QkGJICJz0bcauzMIvdhoFM4umTxz2mg1IS
         yalrP3g43M0/eDy38Njx8OOsnhUbZs/be6Jp27GB1y0Ur5H/+xt6jDQ20ok2R8o5vvMl
         XZwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Q6rcfmRS;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43101.protonmail.ch (mail-43101.protonmail.ch. [185.70.43.101])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4310ade11c4si43784f8f.6.2025.12.17.05.48.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 05:48:49 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) client-ip=185.70.43.101;
Date: Wed, 17 Dec 2025 13:48:44 +0000
To: akpm@linux-foundation.org, urezki@gmail.com, kees@kernel.org, elver@google.com, andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, ryabinin.a.a@gmail.com, dakr@kernel.org, glider@google.com
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, m.wieczorretman@pm.me
Subject: [PATCH v5 0/3] kasan: vmalloc: Fixes for the percpu allocator and vrealloc
Message-ID: <cover.1765978969.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 23204708c692a2f57662abaccff2e44189916c62
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=Q6rcfmRS;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

Patches fix two issues related to KASAN and vmalloc.

The first one, a KASAN tag mismatch, possibly resulting in a kernel
panic, can be observed on systems with a tag-based KASAN enabled and
with multiple NUMA nodes. Initially it was only noticed on x86 [1] but
later a similar issue was also reported on arm64 [2].

Specifically the problem is related to how vm_structs interact with
pcpu_chunks - both when they are allocated, assigned and when pcpu_chunk
addresses are derived.

When vm_structs are allocated they are unpoisoned, each with a different
random tag, if vmalloc support is enabled along the KASAN mode. Later
when first pcpu chunk is allocated it gets its 'base_addr' field set to
the first allocated vm_struct. With that it inherits that vm_struct's
tag.

When pcpu_chunk addresses are later derived (by pcpu_chunk_addr(), for
example in pcpu_alloc_noprof()) the base_addr field is used and offsets
are added to it. If the initial conditions are satisfied then some of
the offsets will point into memory allocated with a different vm_struct.
So while the lower bits will get accurately derived the tag bits in the
top of the pointer won't match the shadow memory contents.

The solution (proposed at v2 of the x86 KASAN series [3]) is to unpoison
the vm_structs with the same tag when allocating them for the per cpu
allocator (in pcpu_get_vm_areas()).

The second one reported by syzkaller [4] is related to vrealloc and
happens because of random tag generation when unpoisoning memory without
allocating new pages. This breaks shadow memory tracking and needs to
reuse the existing tag instead of generating a new one. At the same time
an inconsistency in used flags is corrected.

The series is based on 6.19-rc1.

[1] https://lore.kernel.org/all/e7e04692866d02e6d3b32bb43b998e5d17092ba4.1738686764.git.maciej.wieczor-retman@intel.com/
[2] https://lore.kernel.org/all/aMUrW1Znp1GEj7St@MiWiFi-R3L-srv/
[3] https://lore.kernel.org/all/CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com/
[4] https://syzkaller.appspot.com/bug?extid=997752115a851cb0cf36

Changes v5:
- Rebased onto 6.19-rc1.

Changes v4:
- Added WARN_ON_ONCE() and removed pr_warn() from last patch.
- Added missing cc stable to the first patch.
- Fixed stray 'Changelog v1' in the patch messages.

Changes v3:
- Reworded the 4th and 5th paragraphs after finding the vms[] pointers
  were untagged.
- Redo the patches by using a flag instead of a new
  __kasan_vmalloc_unpoison() argument.
- Added Jiayuan's patch to the series.

Changes v2:
- Redid the patches since last version wasn't an actual refactor as the
  patch promised.
- Also fixed multiple mistakes and retested everything.

Jiayuan Chen (1):
  mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN

Maciej Wieczor-Retman (2):
  kasan: Refactor pcpu kasan vmalloc unpoison
  kasan: Unpoison vms[area] addresses with a common tag

 include/linux/kasan.h | 16 ++++++++++++++++
 mm/kasan/common.c     | 32 ++++++++++++++++++++++++++++++++
 mm/kasan/hw_tags.c    |  2 +-
 mm/kasan/shadow.c     |  4 +++-
 mm/vmalloc.c          |  8 ++++----
 5 files changed, 56 insertions(+), 6 deletions(-)

-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1765978969.git.m.wieczorretman%40pm.me.
