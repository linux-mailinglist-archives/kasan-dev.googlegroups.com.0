Return-Path: <kasan-dev+bncBAABBKGLRHEAMGQEBARMN7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BF7F3C1CE4E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:06:18 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-3d1fb5f864bsf161342fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:06:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764777; cv=pass;
        d=google.com; s=arc-20240605;
        b=OvPHOva9d6Q0z2FXVnNnmWLQHlZDLhzPVwRM2HuWW1ZbAnQ7VNOzj97IbbLkeg/tnD
         E5fDaOI6/G6JKRK4vxVDrheLHw6DYCZdHPR9Gn5aup1+/BIUUpIP58D48xnWmMrOtqV+
         d9gohHANVstuZ2pS9FOD8BUledoLVXRA9VkDca8TffpxdYOwnhANVqDTFjQjcwIWxNZG
         a0/NN/zbHyTsEjKH1FRgBC/b+3coj0K+tw1YuPlWOTtkf6KP1eL6sgkh44431ia97Eqq
         uXZv4xhs/X5XSMgYQkZHoQ5iKdAStbvqr35TRdhbz+sHDRFSPzDN7qBLZC0eaTI/A9F0
         wWoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=TrFqFx7ypc0vDUTWG4lkL6BiN85ZdAXnDj9xhPfCMIM=;
        fh=o7G7VU/Ct+F/FMit/Tltr0jxpzo8+5U17wmt5e8vuFI=;
        b=bRUtZkKryu4JVXr5yY2I9ugdSfO1UGCQkYKQV3JMcpXyrjUGBJ2H0o2ER+Ble7Z14s
         1yhPkj7kZtxCtnucpk3mPG1T5eWGrSB+3qMSijAtELRoXQ7hl/o++lunzF6Q4fnLHJ4R
         h0fIx5VwIidScr4zz3d8m7HRMmmO1AdLWaod9CuFI98smQ0Dno66GYX2ENLvBN6XqpEm
         UKVglm/dCkyUloDxmzNvDXZicUyVd5ZJT6HDGG5QkgxsUIivUsGpfxS7smL9mOlipyGa
         X3qKDeLsNBvtJ488yW4wPMSA3lOSz4+zFlEUMn+kAOrn6ffijyq/RzU9oHnCAWm3hnL/
         jmMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=auxqsyOv;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764777; x=1762369577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=TrFqFx7ypc0vDUTWG4lkL6BiN85ZdAXnDj9xhPfCMIM=;
        b=QvwyFQw3cCCEXxcTSuGnj/Ks3Ds4n24ANdbz5B5Ne73aRql79arOHGRSYHUv7C9Vma
         R8gSaluNkcnTnSGzL3uAnSGp13SoSDm/RgTdcDVn3+ACKfwRiOmvqvHRRP2YfSyKaK3s
         AI4Ume2AWEYIxBRczf1ADLSFFx4u/neFvezejxa1xDdl5AqEIe2dwRCjXuqYtzduXEwC
         cnsHcQbx63nfZFTqXw8jfg9JbwaUgpQQBMkZv0hlltzzpEIs7TwhE1y5jEfynuNgzcxC
         YX8V4oFteu0kjEQv0RqXI8N3lqKyl0KVOyaoMCYMtrUo1W95LZj6ZNAkcgAnofi71ZFj
         5h1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764777; x=1762369577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TrFqFx7ypc0vDUTWG4lkL6BiN85ZdAXnDj9xhPfCMIM=;
        b=bm4holMtu9LlUkviRq/wQhQjw5QFxdoa058/VVVFc/OmThzsP9MXwj7OGiYfL84Ped
         Ar5jYakFOiWuHJFkxOeax94L3/gK++j4XNj4v5MDen10jX9kgQrwp2mpLuGtJ2c1M6jT
         KA2mo7l3qB4oG9X0f3ct0zFrL6O19rYpurElh2/hd/lSiowhO2MeaIk2ciSoXGm9kPjl
         woKQt6SKqgQI+n4haiKT0FhiF7Q7oMCs/jIfnAriR2pkrwnrlXfWF2aLAG05E5sDp8o4
         zcwlZUTgMIdVV+CSuIXyN7gAhJmgm7MEq1WfKU2GxjPWHngL+P0V5z3GlVvy3gv636/f
         P6Lw==
X-Forwarded-Encrypted: i=2; AJvYcCUwzUYFdn64I44ko30bAiXur6+HBTZQxpnZzYO2WCkpqseY8mkKBnbdb9GVkEYeFichnvpkjw==@lfdr.de
X-Gm-Message-State: AOJu0YySThe4A/GokY+SgRFmOBAJHas26MZ9UVt5qL9PkkQ3MRSxcBEu
	TrpP8hiSuakMm0ePYSwWln2IzuYEZTI4HaPPUbAXivYskwObZ3nsAz2Z
X-Google-Smtp-Source: AGHT+IFCCTvRJ69cTkYrBUowG+vM2YyE2OpBnWacDQxzOl78j1vUijKmjlmdUXwQLI+w4/4UUz89jg==
X-Received: by 2002:a05:6870:a0a6:b0:345:50af:a674 with SMTP id 586e51a60fabf-3d747b3cc8cmr1881004fac.36.1761764776900;
        Wed, 29 Oct 2025 12:06:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Ztd6aULNe7+uI1wMg0fonU8tfWTu453nfXdxOHJBcQ/Q=="
Received: by 2002:a05:6870:eca7:b0:3d3:4338:bba3 with SMTP id
 586e51a60fabf-3d8baf127afls72475fac.1.-pod-prod-04-us; Wed, 29 Oct 2025
 12:06:16 -0700 (PDT)
X-Received: by 2002:a05:6808:3c4d:b0:43f:5716:aac9 with SMTP id 5614622812f47-44f7a860ad9mr1867703b6e.37.1761764775941;
        Wed, 29 Oct 2025 12:06:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764775; cv=none;
        d=google.com; s=arc-20240605;
        b=FFEc9nkiNaZ7g50K8zqSOr6nn5gp5HouZUC/SPstL4niM7VnIObjl6qer5k/MdJQW3
         l1275c8E1k5bw3cUGsWE2b0xB5Q3N3Rlt7NWZZ4K6XDUDWcrWWDmwummlUiIHP4T7Qji
         7Evx/ur8NpcHzDEvUoWwMKIDIo6FEdTl7OFpBh02+JYwRvycqaVlwiwdVrDhaelPe295
         EPW3uFwgDqVL1bRwVQfJI2C1W4duukr6NO0KJd79147Q8XvXNxAGXRLd9wxzW1CCatX8
         13yEUpeM2R4bWsDHl4J3s/ETfIse9kF84f4ZmnW+pfvgdqWBD49ENvkx+nu568PqUeWj
         PsLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=oOT+8LaCSd2bsGWZH31RqkbowzlJMvnmRkALmEb4OMQ=;
        fh=rQP7JB+9lidxxodnhH8izoSGXGEyo87czx6Msjgnu+o=;
        b=eKdYn9iY8ba6EjLWjIKQVtF/nxq4TLrnPJ5lt6hX+OgweSlEKSNKufU5m/CGA24LB3
         b8EF8ZQv5+XoG5zNxjpj3VXCyAWxtY3d3YqGcNHdF1Q3Nd9G2LvCY3zWSIZShQAxD5rD
         9DmJ2XBeJ8Lhh6E5QNfpg1jZ/rw0cqOvsElVollYjIUJaPUEBckNSmPl4Syyz+zF7rJH
         3QLhzROCBGA/Gqn1H0zGfJCHiC/fP0ggOO20GnMmG1/dm2quGn3uV1sQ9eIL+Yr8lGq4
         NeIgJm/8TqAd82f47b4uHeq8c0WD9DAjGWLBpP6a5xeM7/tIXok/EdCnVRKgWMUnKYQr
         wGFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=auxqsyOv;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24417.protonmail.ch (mail-24417.protonmail.ch. [109.224.244.17])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-44f7ced2eaasi47776b6e.3.2025.10.29.12.06.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:06:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) client-ip=109.224.244.17;
Date: Wed, 29 Oct 2025 19:06:03 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me, stable@vger.kernel.org, Baoquan He <bhe@redhat.com>
Subject: [PATCH v6 02/18] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <932121edc75be8e2038d64ecb4853df2e2b258df.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: b78f8be95b4a3268cc028d63fcca55df4e5c6664
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=auxqsyOv;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

The problem presented here is related to NUMA systems and tag-based
KASAN modes - software and hardware ones. It can be explained in the
following points:

        1. There can be more than one virtual memory chunk.
        2. Chunk's base address has a tag.
        3. The base address points at the first chunk and thus inherits
           the tag of the first chunk.
        4. The subsequent chunks will be accessed with the tag from the
           first chunk.
        5. Thus, the subsequent chunks need to have their tag set to
           match that of the first chunk.

Unpoison all vms[]->addr memory and pointers with the same tag to
resolve the mismatch.

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: <stable@vger.kernel.org> # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Tested-by: Baoquan He <bhe@redhat.com>
---
Changelog v6:
- Add Baoquan's tested-by tag.
- Move patch to the beginning of the series as it is a fix.
- Add fixes tag.

 mm/kasan/tags.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index ecc17c7c675a..c6b40cbffae3 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -148,12 +148,20 @@ void __kasan_save_free_info(struct kmem_cache *cache, void *object)
 	save_stack_info(cache, object, 0, true);
 }
 
+/*
+ * A tag mismatch happens when calculating per-cpu chunk addresses, because
+ * they all inherit the tag from vms[0]->addr, even when nr_vms is bigger
+ * than 1. This is a problem because all the vms[]->addr come from separate
+ * allocations and have different tags so while the calculated address is
+ * correct the tag isn't.
+ */
 void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
 {
 	int area;
 
 	for (area = 0 ; area < nr_vms ; area++) {
 		kasan_poison(vms[area]->addr, vms[area]->size,
-			     arch_kasan_get_tag(vms[area]->addr), false);
+			     arch_kasan_get_tag(vms[0]->addr), false);
+		arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(vms[0]->addr));
 	}
 }
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/932121edc75be8e2038d64ecb4853df2e2b258df.1761763681.git.m.wieczorretman%40pm.me.
