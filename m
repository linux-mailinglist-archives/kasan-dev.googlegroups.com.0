Return-Path: <kasan-dev+bncBD52JJ7JXILRBYOAU2JQMGQEXH4SWRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CA9B7512330
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 21:58:26 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id f8-20020a9d5f08000000b005cb3a6c4c1csf758132oti.21
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 12:58:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651089505; cv=pass;
        d=google.com; s=arc-20160816;
        b=dIWRb8wzhIWq+jZc4RKB0noHVQ+RYGS18WZw/MAJA5lTCg0SK93MCYz1u1ZH9WF6Ni
         spQzzHgp8vGFJJkhObS60ksTe6mpaRFEQpbPVZQo+hUHkdNH58mqXMsvLOywBlM/ADk2
         3yNs2nby5Q6mchGltK+Oh9g9k86c1bkAOdGZfz6yuNZ5ERJZDsu0mQ9gJfNuVvDKswmV
         /DqzcECgdT2cI+pqBeqjoCXZEq8mDw+mekVbMUYWWdU7wSnpjlqs0RbD1bjTEw8suhL4
         esTid50qLp/ITlVOg8hic/IjJ8wyvAVpQW907GWcObDBs8BeuLxMGdSsakuJcCtlcwL8
         Hn9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=REwbjCmOc55UVl1VeMX04ZElEHzAGuzQWm4+3RgW+9U=;
        b=WglK8J0Ytzf0o0vOpGeJEsCmfnmzMKqQeb6TXWijQOHJhYOe2UQcpWsG9XEdzAl5Sd
         Kdb2zZJbWtdR6K7HfX/hO/sLIfGtUJ+actpYPn93kVMRxHb60rF4oq1fwvWYcqkwyF8Y
         bTLw4EFsJEDfR1XGiT1US0pu8lrZgnSynnZCu1GR9Ha51+Yj1KNUx9CfZxdgzceVRnc5
         wZrN7Wivq5hhAspmMXnUA11fYlTu55ZhUfjIQsl8OTQvNUIdHcKglKhApW4WSgVeXZrv
         A2T5UPlipe7Ji3IG0A8nK8MAE9x98cqmPdpkPCdw/z+hPD//oU+yx7ydaZuZddJ5t+kr
         lcvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s02dGKNs;
       spf=pass (google.com: domain of 3ykbpygmkcweobbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3YKBpYgMKCWEOBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=REwbjCmOc55UVl1VeMX04ZElEHzAGuzQWm4+3RgW+9U=;
        b=UBtG2nyVrmVrV4JZTXL+WmDgfTI8/gq+CRjT3I0/nLcArcxRPyKMiFG85ZKX8tA0Cs
         y5KTUb58GZyS5cLAKCTNbzd2v25OIbabDyfIuiWBy0KF5vR1HbyJOPoVV1I19MKNi4yt
         0TUv7Xwy1bbrdLJsRDlBIZijkiUC6wNS9IQ5nhfKiVBVgF04Dtnk6qeT3aXoT7YUwzzT
         ISAUqPBvuD/uq5DSqKjT5wP0OaS7h45Og0k/NarZoPbiljxfpzjxAjqG243mzR9zlykz
         +/BnwCYQWUCi3rWV0Pi1cSA2E7tG9zreIWLodBSzZRvEQMVkW73qxbQ58I99DhqmI0va
         5f0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=REwbjCmOc55UVl1VeMX04ZElEHzAGuzQWm4+3RgW+9U=;
        b=K/XGMqVavMFYQFMfypsboD2OpilLRjD+lSA6to22YEbu8SOpck7n8IlM7t0vLkPL8G
         vY+9Stoo2GYdLPHx00NGkOP1yR1//h/J1jCmuW9oaa9rD2hTK1kVZyB7nxaSbf4g+Jsl
         851dlwPvO6VtZsxu8P5ROMN7we6T1CW/lOxv6yVNe6ztbQMalglzBvf8vEtHb+GdO5Hz
         DaNaanEL3l4VxSEv8z7RoHIjNMuxWix49V6hvvrLwjidjSWrThkVMwUxAULXOASRpcsG
         rLGqC2fbB6NYxfexwKYk65T7ie1bucfl6zFqYabHYB5HAjR/3OHok0xTfpurOOMx99gt
         O04w==
X-Gm-Message-State: AOAM533W8p2zFcGZZZNpPiLseJBX2AJwqrnYyHJ+e/eukoK6ZWzHhlG6
	OjaQM07S3o+UtfQFRCJhBos=
X-Google-Smtp-Source: ABdhPJwnMHQLCU3aMxonxvBSf16lC0QhsE40h8eIkMGxf/UmIayAvKyx+H4acoYCtWg6wkJYSTanuw==
X-Received: by 2002:a05:6830:2ea:b0:605:e0ab:931 with SMTP id r10-20020a05683002ea00b00605e0ab0931mr1124609ote.117.1651089505504;
        Wed, 27 Apr 2022 12:58:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1987:b0:322:7c28:7409 with SMTP id
 bj7-20020a056808198700b003227c287409ls6907811oib.5.gmail; Wed, 27 Apr 2022
 12:58:25 -0700 (PDT)
X-Received: by 2002:aca:f1d7:0:b0:2ef:b62:646 with SMTP id p206-20020acaf1d7000000b002ef0b620646mr18743018oih.154.1651089505126;
        Wed, 27 Apr 2022 12:58:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651089505; cv=none;
        d=google.com; s=arc-20160816;
        b=GDwcaAG/42pNcNgrUVozhBFMQQY2KTOw2FByYrR+nfcaP71jQBRmwFKlyo6TKdojiI
         GM2pfiKF4D2pe0BEBdL/ADPDpn6u2e7TtQpUsrt050h9lfK060otvyX0ogNPF6JO5Vv+
         dr2l+P0vzDKVcU/eKCIApyFYv3kNNnQcOAi0O2e9j10gxuNxVElGLzQP3c0kx8AItAq3
         fu+TkpLEJhXIcgogRvV2marA9UjHiOu/HLOSCKUSYAfJNXqG9f+crYG4hgIwOuYeN4Q+
         1iXm0/iXcSwMzGwYGQ/Q/eNp6tsV9q++0DQrjcywm3p6PJA+VyU4482nsWjcoUP46iSq
         kVOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=XcyimqZCgzNKPz0n6jeYchV2A0CiM03dMGsti55IHHA=;
        b=QtFC7RoOfHutJD6npYJBIsOV59hq5w3+693MNzYd7dLDdb6DOseJWjjggdDHBOD5Qk
         5hkydgdxoLzl/pB75BPZLWPeLJxuodxZV8UTxX1hz913ZAz0gdT4ApzQ3e1Nig1Ld8/t
         NLWxXpRDZTRRBGZep5A/NYiK9LJJIJf3FSaywK55HtcwB+ZK7w6nXa86k3Uw1a1qsteT
         7hIB1hPwDLktxL2h3H5MbjvwO8pv4NHUkeRTyQ0xaxcExA61nT6wuw92cOZPmtYEDrfv
         6YbROJpZv30tf4/tbNAGdMTstaxKFaUUmGPQg/zCsyVpJ7Dhc+dqzsVYMa1qosO7h4HU
         Bqfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s02dGKNs;
       spf=pass (google.com: domain of 3ykbpygmkcweobbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3YKBpYgMKCWEOBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id du27-20020a0568703a1b00b000ddbc266799si248256oab.2.2022.04.27.12.58.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 12:58:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ykbpygmkcweobbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-2f198b4e2d1so25946357b3.14
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 12:58:25 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:7bf6:862b:86da:9ce1])
 (user=pcc job=sendgmr) by 2002:a81:38d4:0:b0:2ea:ad04:a284 with SMTP id
 f203-20020a8138d4000000b002eaad04a284mr29122079ywa.139.1651089504681; Wed, 27
 Apr 2022 12:58:24 -0700 (PDT)
Date: Wed, 27 Apr 2022 12:58:19 -0700
Message-Id: <20220427195820.1716975-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.0.464.gb9c8b46e94-goog
Subject: [PATCH v5 1/2] printk: stop including cache.h from printk.h
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, vbabka@suse.cz, penberg@kernel.org, 
	roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com, rientjes@google.com, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=s02dGKNs;       spf=pass
 (google.com: domain of 3ykbpygmkcweobbfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3YKBpYgMKCWEOBBFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

An inclusion of cache.h in printk.h was added in 2014 in
commit c28aa1f0a847 ("printk/cache: mark printk_once test variable
__read_mostly") in order to bring in the definition of __read_mostly. The
usage of __read_mostly was later removed in commit 3ec25826ae33 ("printk:
Tie printk_once / printk_deferred_once into .data.once for reset")
which made the inclusion of cache.h unnecessary, so remove it.

We have a small amount of code that depended on the inclusion of cache.h
from printk.h; fix that code to include the appropriate header.

This fixes a circular inclusion on arm64 (linux/printk.h -> linux/cache.h
-> asm/cache.h -> linux/kasan-enabled.h -> linux/static_key.h ->
linux/jump_label.h -> linux/bug.h -> asm/bug.h -> linux/printk.h) that
would otherwise be introduced by the next patch.

Build tested using {allyesconfig,defconfig} x {arm64,x86_64}.

Link: https://linux-review.googlesource.com/id/I8fd51f72c9ef1f2d6afd3b2cbc875aa4792c1fba
Signed-off-by: Peter Collingbourne <pcc@google.com>
---
v5:
- fixes for arm randconfig and (tentatively) csky

 arch/arm64/include/asm/mte-kasan.h | 1 +
 arch/arm64/include/asm/percpu.h    | 1 +
 arch/csky/include/asm/processor.h  | 2 +-
 drivers/firmware/smccc/kvm_guest.c | 1 +
 include/linux/printk.h             | 1 -
 kernel/bpf/bpf_lru_list.h          | 1 +
 6 files changed, 5 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index a857bcacf0fe..9f79425fc65a 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -6,6 +6,7 @@
 #define __ASM_MTE_KASAN_H
 
 #include <asm/compiler.h>
+#include <asm/cputype.h>
 #include <asm/mte-def.h>
 
 #ifndef __ASSEMBLY__
diff --git a/arch/arm64/include/asm/percpu.h b/arch/arm64/include/asm/percpu.h
index 8f1661603b78..b9ba19dbdb69 100644
--- a/arch/arm64/include/asm/percpu.h
+++ b/arch/arm64/include/asm/percpu.h
@@ -10,6 +10,7 @@
 #include <asm/alternative.h>
 #include <asm/cmpxchg.h>
 #include <asm/stack_pointer.h>
+#include <asm/sysreg.h>
 
 static inline void set_my_cpu_offset(unsigned long off)
 {
diff --git a/arch/csky/include/asm/processor.h b/arch/csky/include/asm/processor.h
index 688c7548b559..9638206bc44f 100644
--- a/arch/csky/include/asm/processor.h
+++ b/arch/csky/include/asm/processor.h
@@ -4,9 +4,9 @@
 #define __ASM_CSKY_PROCESSOR_H
 
 #include <linux/bitops.h>
+#include <linux/cache.h>
 #include <asm/ptrace.h>
 #include <asm/current.h>
-#include <asm/cache.h>
 #include <abi/reg_ops.h>
 #include <abi/regdef.h>
 #include <abi/switch_context.h>
diff --git a/drivers/firmware/smccc/kvm_guest.c b/drivers/firmware/smccc/kvm_guest.c
index 2d3e866decaa..89a68e7eeaa6 100644
--- a/drivers/firmware/smccc/kvm_guest.c
+++ b/drivers/firmware/smccc/kvm_guest.c
@@ -4,6 +4,7 @@
 
 #include <linux/arm-smccc.h>
 #include <linux/bitmap.h>
+#include <linux/cache.h>
 #include <linux/kernel.h>
 #include <linux/string.h>
 
diff --git a/include/linux/printk.h b/include/linux/printk.h
index 1522df223c0f..8e8d74edf121 100644
--- a/include/linux/printk.h
+++ b/include/linux/printk.h
@@ -6,7 +6,6 @@
 #include <linux/init.h>
 #include <linux/kern_levels.h>
 #include <linux/linkage.h>
-#include <linux/cache.h>
 #include <linux/ratelimit_types.h>
 #include <linux/once_lite.h>
 
diff --git a/kernel/bpf/bpf_lru_list.h b/kernel/bpf/bpf_lru_list.h
index 6b12f06ee18c..4ea227c9c1ad 100644
--- a/kernel/bpf/bpf_lru_list.h
+++ b/kernel/bpf/bpf_lru_list.h
@@ -4,6 +4,7 @@
 #ifndef __BPF_LRU_LIST_H_
 #define __BPF_LRU_LIST_H_
 
+#include <linux/cache.h>
 #include <linux/list.h>
 #include <linux/spinlock_types.h>
 
-- 
2.36.0.464.gb9c8b46e94-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427195820.1716975-1-pcc%40google.com.
