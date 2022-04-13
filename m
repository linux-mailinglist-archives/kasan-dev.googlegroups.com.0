Return-Path: <kasan-dev+bncBAABBUGI3SJAMGQEKTGGUDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 887C64FFF42
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 21:28:17 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id i32-20020a0565123e2000b0046d092e6bffsf543464lfv.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 12:28:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649878097; cv=pass;
        d=google.com; s=arc-20160816;
        b=NmDgDLooPcjnor3e+9p7Cp8AtSNJmkda5sGBXOK8sZ8U/ZiVAOHiHI6RG4UJd7Gxcm
         z/a7BN3BHEmUWgA1po8FJ8ZNl8/LAktIQ1BcEYDFbdPRxGXvpGaWWs+jrbfW/V846fht
         V5/5m4vmx90QgqF3GkadmWrnsY6bHXyO/IcjQZT9HhcRh61fHU/XaD5/aENQGeo+O4Ea
         UGVcZtY15I3fhydTpgWBwiAitD2pupJI0gDF2o6bS8IIcrEsU9qPh3JkhIAMAm30KDMp
         8+GXE8IcJcAzSJSvTYTauE/HRasnVRkcNipT2ZSNstqw/BnbS9DhP/la459W6/Eo3uWW
         0I5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OPCn76AhloTXx+8ukOB9+6Owa40WtBYnFhXY1q7SKMY=;
        b=Rics9qoZ/eqZpRwfigR/j4QiAOWi5qWrJe1PzqlpFRjZe8J6p3sWxbGQpilhBawxbc
         YeblThNRIV7NofH8EPrC5id2E49UII1aj/F7OCB4GJ/FJoIC/Fkrxl+YXYTuY4KEU1Zm
         iryjkM9skh1xkFSuiifBTZt8WJDBv60uadfAegNC1sNfzPpiLqDyfznpl4lCRi72Hn9C
         qyGplbY6hd8aUACGYf+Yz3S0VDHL8K/geiLvfTdLOu8J1To3G2Z1hhUjPCFf6P1GFam7
         3jnB05yExWs5NAAhFCDqlew1o0DNCbLuTDAl35gVerKFBl4Np05fXLwG3qKcHuDAXgrj
         CVmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZvRioLZb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OPCn76AhloTXx+8ukOB9+6Owa40WtBYnFhXY1q7SKMY=;
        b=OofNz/bD97ISkaAFtK0Z26ShjWrOOgdDJ+MUy4X4zmE4yAKTK9ocGYd0SmqBhjfQOW
         eydXIe/cUFk0MigngWqF0zFbxzVsXhmTaVfVqqLLzGH/wqxrSEuOp2h+Fe32M6srjEnu
         7GCsjkJE6venvLYxw3UQYo2/k6E9VCJp/CJbN34PXxvCOC4y+Zr+5yxmCb1XNiQteiSB
         1PjwsRA6rZQDsvfX3Hs7jPex/CqAup8zUBYY2pwaG8kdnDvldoczZQXag2dqpfELciYJ
         VIhQyv9273Z6RcBI+tRRj91EY111Dyyvw+kHFLefHQxPUIOGHs9OCkxbLrHRclOklye/
         uDBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OPCn76AhloTXx+8ukOB9+6Owa40WtBYnFhXY1q7SKMY=;
        b=nb9AAhAZyKmhAUBP/aXo6Xwsx5LQ7I22WH9hmCrxf/7YeQY+qwvandTlUZARk/RDwr
         QYi8/ZgXqc4wWcnSlydO1jM+I3twJzFId/2i+bTqom6gW02IHsbbPEjjHJV2T4zTQvul
         UZQSap/4EMc088FmounhSPcBgU1jk4EfjsuXAN3H9hUuWWrKU3PJcZrfg/Tj355N+AMy
         G2jIWmDOPiN5K1i7Xqvn/gM/lTFrU/XVKSFQjAML4EGOpfdYOU1MxYHsbgek6rkDeJLU
         PPKfzVEc4RvPwL4M2TzMilSBa4OXsXLk9cBPUHOut5R/r7gdcBYwkHk4s0ak11rZPwHT
         5RQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CoIxu+KEchWLp+zVtEc/oEVRAzMaIzjGb9LZ9d1qLnmFbNpHU
	pcg8KIuHLqsSlH/qaeDXQ7g=
X-Google-Smtp-Source: ABdhPJxDrf5XWH4acDroNoe4875oyG5cL+8z0G1srRd2KTkIp+eB50lajoCcOpkvnQa26KKuslyrBQ==
X-Received: by 2002:ac2:533a:0:b0:46b:ab1d:6a82 with SMTP id f26-20020ac2533a000000b0046bab1d6a82mr10290021lfh.532.1649878096434;
        Wed, 13 Apr 2022 12:28:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e0a:0:b0:46c:56e3:aa04 with SMTP id e10-20020ac24e0a000000b0046c56e3aa04ls2617571lfr.3.gmail;
 Wed, 13 Apr 2022 12:28:15 -0700 (PDT)
X-Received: by 2002:a05:6512:e87:b0:44a:5117:2b2b with SMTP id bi7-20020a0565120e8700b0044a51172b2bmr12579878lfb.275.1649878095550;
        Wed, 13 Apr 2022 12:28:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649878095; cv=none;
        d=google.com; s=arc-20160816;
        b=XUr2oSfzD/HG3AkewRUb/6Puj3WKb7wdmwr4jnXNiERpQEBFFOH5GJKgTCrTZpwRVS
         vdlPUlp1BvR8rJem7oYgkLIvDU1iNxTwzywrsvHUiq9Mcm8tyVhwxYJHjjBA9/MN6RtF
         c/HgOK2jASVaJKhCOxzsQXf/oUwcQMpEEcNsPR73MkIJjtFxOTEIRQkvka/ln8N0e5Iw
         435QLYFAG9r/SJL8i3cjc8TtSFos1pznv/aKJUlYER5NrTuL4D33yJN+PO3XhaEf9kC+
         vfnvxRU0AgC44hz+gjabfxYPfejwaUtWAqoIgBMF7U7aklAJRuEHz9QnoZHuzamogboU
         nsIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=L2z4Q/1rfqvzlgKK/+Q8dR7Hr7nD3d/L3KDR+0LUxPU=;
        b=YEkCoOwss7thRbuflLKB2GKK0aS8IZubT2PUojbiBS8uylKPkyLIgdZlG7xxnN8VE3
         kVVkK6f1K7w95aD8y9eXz6xpZG4ZXtuf+kukt7h7a5G2A+1S+n1Mf2w9TGUNDuvV1+he
         zodubVZWpJhvWCEtV0swxaEEWZWtNtJ8VjO0QQt3iWnssG4kW7tJBvPK92CNFGpXkYf1
         WuL8WcA/gEt6g37BQk7Rs/PMFxJsOsYISYNVpl5sAQEn2aJ8tsQeQpwMnBGvgibbOYQx
         yTJ+8FvSAKyb9AjckeRyi7cxSQu4qOq9KudLfxhqRYFZGyEunWnqsGrV0wYi8kslYxDs
         KzkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZvRioLZb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id s6-20020a195e06000000b0044a4ca0a067si782817lfb.0.2022.04.13.12.28.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 13 Apr 2022 12:28:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 0/3] kasan, arm64, scs: collect stack traces from Shadow Call Stack
Date: Wed, 13 Apr 2022 21:26:43 +0200
Message-Id: <cover.1649877511.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZvRioLZb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Currently, when saving alloc and free stack traces, KASAN uses the normal
stack trace collection routines, which rely on the unwinder.

Instead of invoking the unwinder, collect the stack trace by copying
frames from the Shadow Call Stack. This reduces boot time by ~30% for
all KASAN modes when Shadow Call Stack is enabled. See below for the
details of how the measurements were performed.

Stack staces are collected from the Shadow Call Stack via a new
stack_trace_save_shadow() interface.

Note that the implementation is best-effort and only works in certain
contexts. See patch #3 for details.

---

Changes
=======

v2->v3:
- Limit hardirq and drop SDEI support for performance and simplicity.
- Move stack_trace_save_shadow() implementation back to mm/kasan:
  it's not mature enough to be used as a system-wide stack trace
  collection replacement.
- Clarify -ENOSYS return value from stack_trace_save_shadow().
- Don't rename nr_entries to size in kasan_save_stack().
- Check return value of stack_trace_save_shadow() instead of checking
  CONFIG_HAVE_SHADOW_STACKTRACE in kasan_save_stack().

v1->v2:
- Provide a kernel-wide stack_trace_save_shadow() interface for collecting
  stack traces from shadow stack.
- Use ptrauth_strip_insn_pac() and READ_ONCE_NOCHECK, see the comments.
- Get SCS pointer from x18, as per-task value is meant to save the SCS
  value on CPU switches.
- Collect stack frames from SDEI and IRQ contexts.

Perf
====

To measure performance impact, I used QEMU in full system emulation mode
on an x86-64 host.

As proposed by Mark, I passed no filesystem to QEMU and booted with panic=-1:

qemu-system-aarch64 \
	-machine virt,mte=on -cpu max \
	-m 2G -smp 1 -nographic \
	-kernel ./xbins/Image \
	-append "console=ttyAMA0 earlyprintk=serial panic=-1" \
	-no-shutdown -no-reboot

Just in case, the QEMU version is:

$ qemu-system-aarch64 --version
QEMU emulator version 6.2.94 (v5.2.0-rc3-12124-g81c7ed41a1)
Copyright (c) 2003-2022 Fabrice Bellard and the QEMU Project developers

Then, I recorded the timestamp of when the "Kernel panic" line was printed
to the kernel log.

The measurements were done on 5 kernel flavors:

master                 (mainline commit a19944809fe99):
master-no-stack-traces (stack trace collection commented out)
master-no-stack-depot  (saving to stack depot commented out)
up-scs-stacks-v3       (collecting stack traces from SCS)
up-scs-stacks-v3-noscs (up-scs-stacks-v3 with __noscs marking)

(The last flavor is included just for the record: it produces an unexpected
 slowdown. The likely reason is that helper functions stop getting inlined.)

All the branches can be found here:

https://github.com/xairy/linux/branches/all

The measurements were performed for Generic and HW_TAGS KASAN modes.

The .configs are here (essentially, defconfig + SCS + KASAN):

Generic KASAN: https://gist.github.com/xairy/d527ad31c0b54898512c92898d62beed
HW_TAGS KASAN: https://gist.github.com/xairy/390e4ef0140de3f4f9a49efe20708d21

The results:

Generic KASAN
-------------

master-no-stack-traces: 8.03
master:                 11.55 (+43.8%)
master-no-stack-depot:  11.53 (+43.5%)
up-scs-stacks-v3:       8.31  (+3.4%)
up-scs-stacks-v3-noscs: 9.11  (+13.4%)

HW_TAGS KASAN
-------------

master-no-stack-traces: 3.31
master:                 5.01 (+51%)
master-no-stack-depot:  4.85 (+47%)
up-scs-stacks-v3:       3.49 (+5.4%)
up-scs-stacks-v3-noscs: 4.27 (+29%)

The deviation for all numbers above is ~0.05.

As can be seen, the up-scs-stacks-v3 flavor results in a significantly
faster boot compared to master.

Andrey Konovalov (3):
  arm64, scs: expose irq_shadow_call_stack_ptr
  kasan, arm64: implement stack_trace_save_shadow
  kasan: use stack_trace_save_shadow

 arch/arm64/include/asm/scs.h | 10 +++++-
 arch/arm64/kernel/irq.c      |  4 +--
 arch/arm64/kernel/sdei.c     |  3 --
 mm/kasan/common.c            | 66 +++++++++++++++++++++++++++++++++++-
 4 files changed, 75 insertions(+), 8 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1649877511.git.andreyknvl%40google.com.
