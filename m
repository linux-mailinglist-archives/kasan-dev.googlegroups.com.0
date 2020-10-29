Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUFO5T6AKGQETQDA4ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E9CB929F4DB
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:08 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id e3sf1678918wrn.19
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999568; cv=pass;
        d=google.com; s=arc-20160816;
        b=T10VHbdtsoaUEg1rZ54RA24B1Nfj5SL/IAHKM3VuDeknYUsQtdUy/r3uQ1HIjTNlrq
         Zud6TRMUeAnnJlfViSUtv5yR1MDWSnz5yjjAfnAy5yIDIw9o+nkpsU7KvMIihamFud7g
         fOg3ZKi1oHwBcjSINoV49AxL5Z464Z7t6mBIn4nV274/1LigI3En9V+H8g2QrCs2zg/W
         pWLth086Yh9igPQLYwXkBtWqg+oF0q7kK0zLUouynihAeaP9mRw0PWH6pQOJsiuxkDl5
         XgoAYsj5iebxb7suyTAz6gxFnVve9dhMRm7xutsbaYv8wqF3cQpVaDbd5Hi1vrUU+pBk
         a6fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=lmTNYnn7ih1sk0/ZdqGj8kbGw3oJ9HW5n19jIIzFNkc=;
        b=aJsHdYwIm4MTUT6m8AIFiEKBDmR/FGr8sAuTzYIWo4pQTDTneelgCBERzroRa1bEoF
         IYz0ldhZiskromfNUNcI4bKH93Drl5Owo+7TL9VWT/NjbDFAueBmJwaO9ZdmvGyOuTsS
         oGnV/wbYYaDqKC0qVMITnpxQOlnIKYE2hq+DreA7Z+109ruplDE2+TSy0rZtQG/3H7/d
         jaayGAC0duzPvsDmy0UDIFFQSs5M4yG9c2J5xxenostsDoO2OTdcasL7lVBnfEJnVMJE
         JszdFIWkHUhYLLiUkl9UJ+Sw2wky1aFfYAGVlodyphyfhdqyVpQu9dJq5hv13GkMjQMW
         ywfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JH1POZ22;
       spf=pass (google.com: domain of 3txebxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3TxebXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lmTNYnn7ih1sk0/ZdqGj8kbGw3oJ9HW5n19jIIzFNkc=;
        b=FyvZDCCTjRCIRiqOUEGcKnZfFIPvLXBeS/ymt4tUnDqtolaYByZuDh1UDVkGdZ2YhV
         M+m+jQX9PWbK0YWo3tpkkPgu+qYa4B36tjvlna4CXrT5wNQM4/2VPaBlFT5V3YuwTwJ+
         PFsx9zlEK5XLhovNtObMlE7fQ/LfKYrmZTxEaJMcI9LJXk/13HX5DgupWnSwvSOPjKBm
         7W4S2icewSNFz0W/UCLQH58l4kS2YRZwqetOExa7awDdmLeRZyzhK8mG43hp8uwX8d5s
         dFUEWSsuRbYSHfXqbHggLjJOCxoVJ4xURQcOSFU6BNOMLOWL9Ujqf5ATzkWtOcj9MiFS
         JsCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lmTNYnn7ih1sk0/ZdqGj8kbGw3oJ9HW5n19jIIzFNkc=;
        b=kVM/XZ3dMTP+0G/KriMPrHysfvdilYoUV63h4IlTZk1458kbYXfF3qI03n5N7d4yyq
         aRvN3aVmfN1mjnV+wTWX1HaVhKPNLlOC77oYmtjIdO/6PcjW7DxX8y6DAgaXi4j4OYwo
         Ny/iQwK9Cy/24dhO+NQum9hyDCjEhRLDF/6xt2WAmjNvLbZiwoWMGba8q4W1BDmPFV8T
         tYRkA74g4FSOgzCK159Mzg31v74YfZqDb/iN46SaouWRsNIDn+kpErl9yG/xbwmngirZ
         W9LrN0+/Y1oQTTFe0wZQuItxYkL1eE7RoJ9Xtc55d1WOmoCYDKRICeBmYOkLZW8SeuEY
         GpAA==
X-Gm-Message-State: AOAM530lwnJMVBmS6RUbKW1+XOhfjsSZs/XDTBeDCQq0KRwU4fRr0oR9
	b3Z6e2OOs11nKePAHoT5zzQ=
X-Google-Smtp-Source: ABdhPJzqAv+9H6nrXbn+Ye0O73GuSAX/lfWEpuyGE9MXDrdZRkVIcLhXhjGbA/Pje+QgsXOdTDjnAQ==
X-Received: by 2002:adf:ed92:: with SMTP id c18mr3800541wro.363.1603999568682;
        Thu, 29 Oct 2020 12:26:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:cd8c:: with SMTP id q12ls2593227wrj.0.gmail; Thu, 29 Oct
 2020 12:26:07 -0700 (PDT)
X-Received: by 2002:a5d:5261:: with SMTP id l1mr8128964wrc.105.1603999567761;
        Thu, 29 Oct 2020 12:26:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999567; cv=none;
        d=google.com; s=arc-20160816;
        b=bTpe5PN/lUe2UBVxwr18XUrkVPOIJ22rbI2Ho1BfSyPG0u1X0KCHPO4cwvy3hRNTqY
         b7KJ4yDYjmrVrTdNTkOrW5/ypHtqYZ2Lvge+yyFtyDBA6MIGfu3SdZkwIei4JFirCzzC
         xRIukHEBGftFAmNFvEYezYF3j4AZ2/jMeRkX48ce+WLNvSHVbC+cM7itX9EOAeipbhfB
         67IaD5kRDml2/FZSoOcw0GnV/tubYVXouNVDpw6T9SbnazZFMT5gDu9q7cTMSYOJZ84T
         9qoFSQQblRZxvlQ2u7q2qz3vorey1eKYNE4aDopJY2QR9EWrOI+VAz/ZM9lyyDQMSsp2
         jywQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=Cm6ll+lqz6eapm3MnEkxQHRHXHy02DA4hi2HZebBSFc=;
        b=QYHUV5gAivWMDz5ciRWkyJ7HoTMAXq6EXvy+h8lfezQ3+kxOk/4FpYsuCsciXJ9cno
         zBv0p/Kau2G77gIEMUuMZ/cWEUOLRPuz+Hm1k2dHnt7k8ZDtuFQ9joeFCjokvy9FrW6a
         1r82butzBD/DCDlC6uH4I69Iv9XMUHHUtVnvX3VwGD2LCDfsxBQMeRr1FVRFb4X/dhIr
         o8GmW7cl4GuJVBSPx9zxhvOI5GCcWzlYueLo5+6pXcFsLRL/CjB+fOyoo80sl4znG1/E
         BRnVUK8F10s1kadOhkCACW6UVBq4M2volD7p703MJiKKqJVIykyTDEcL4emcP+/Ka2Nr
         1JcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JH1POZ22;
       spf=pass (google.com: domain of 3txebxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3TxebXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id w62si21008wma.1.2020.10.29.12.26.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3txebxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id r19so295789wmh.9
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:07 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:21d3:: with SMTP id
 x19mr761255wmj.170.1603999567233; Thu, 29 Oct 2020 12:26:07 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:21 +0100
Message-Id: <cover.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 00/40] kasan: add hardware tag-based mode for arm64
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JH1POZ22;       spf=pass
 (google.com: domain of 3txebxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3TxebXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patchset adds a new hardware tag-based mode to KASAN [1]. The new mode
is similar to the existing software tag-based KASAN, but relies on arm64
Memory Tagging Extension (MTE) [2] to perform memory and pointer tagging
(instead of shadow memory and compiler instrumentation).

This patchset is co-developed by
Vincenzo Frascino <vincenzo.frascino@arm.com>.

This patchset is available here:

https://github.com/xairy/linux/tree/up-kasan-mte-v6

and has also been uploaded to the Linux kernel Gerrit instance:

https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3319

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [4] (use "-machine virt,mte=on -cpu max" arguments
   to run).
2. GCC version 10.

[1] https://www.kernel.org/doc/html/latest/dev-tools/kasan.html
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] git://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux for-next/mte
[4] https://github.com/qemu/qemu

====== Overview

The underlying ideas of the approach used by hardware tag-based KASAN are:

1. By relying on the Top Byte Ignore (TBI) arm64 CPU feature, pointer tags
   are stored in the top byte of each kernel pointer.

2. With the Memory Tagging Extension (MTE) arm64 CPU feature, memory tags
   for kernel memory allocations are stored in a dedicated memory not
   accessible via normal instuctions.

3. On each memory allocation, a random tag is generated, embedded it into
   the returned pointer, and the corresponding memory is tagged with the
   same tag value.

4. With MTE the CPU performs a check on each memory access to make sure
   that the pointer tag matches the memory tag.

5. On a tag mismatch the CPU generates a tag fault, and a KASAN report is
   printed.

Same as other KASAN modes, hardware tag-based KASAN is intended as a
debugging feature at this point.

====== Rationale

There are two main reasons for this new hardware tag-based mode:

1. Previously implemented software tag-based KASAN is being successfully
   used on dogfood testing devices due to its low memory overhead (as
   initially planned). The new hardware mode keeps the same low memory
   overhead, and is expected to have significantly lower performance
   impact, due to the tag checks being performed by the hardware.
   Therefore the new mode can be used as a better alternative in dogfood
   testing for hardware that supports MTE.

2. The new mode lays the groundwork for the planned in-kernel MTE-based
   memory corruption mitigation to be used in production.

====== Technical details

From the implementation perspective, hardware tag-based KASAN is almost
identical to the software mode. The key difference is using MTE for
assigning and checking tags.

Compared to the software mode, the hardware mode uses 4 bits per tag, as
dictated by MTE. Pointer tags are stored in bits [56:60), the top 4 bits
have the normal value 0xF. Having less distict tags increases the
probablity of false negatives (from ~1/256 to ~1/16) in certain cases.

Only synchronous exceptions are set up and used by hardware tag-based KASAN.

====== Benchmarks

Note: all measurements have been performed with software emulation of Memory
Tagging Extension, performance numbers for hardware tag-based KASAN on the
actual hardware are expected to be better.

Boot time [1]:
* 2.8 sec for clean kernel
* 5.7 sec for hardware tag-based KASAN
* 11.8 sec for software tag-based KASAN
* 11.6 sec for generic KASAN

Slab memory usage after boot [2]:
* 7.0 kb for clean kernel
* 9.7 kb for hardware tag-based KASAN
* 9.7 kb for software tag-based KASAN
* 41.3 kb for generic KASAN

Measurements have been performed with:
* defconfig-based configs
* Manually built QEMU master
* QEMU arguments: -machine virt,mte=on -cpu max
* CONFIG_KASAN_STACK_ENABLE disabled
* CONFIG_KASAN_INLINE enabled
* clang-10 as the compiler and gcc-10 as the assembler
    
[1] Time before the ext4 driver is initialized.
[2] Measured as `cat /proc/meminfo | grep Slab`.

====== Notes

The cover letter for software tag-based KASAN patchset can be found here:

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0116523cfffa62aeb5aa3b85ce7419f3dae0c1b8

====== History

Changes v5->v6:
(Vincenzo:)
- Re-based on 5.10-rc1.
- Modified the flow of the mte fault handler in order to address an issue
  with word at a time routines that would affect Android init process.
- Dropped Reviewed-by from the involved patches.
(Andrey:)
- Properly use #if CONFIG_KASAN_STACK instead of #ifdef
  CONFIG_KASAN_STACK_ENABLE.
- Expand CONFIG_KASAN checks in arch/arm64/kernel/kaslr.c and
  arch/arm64/kernel/module.c.
- Don't select CONFIG_CONSTRUCTORS for HW_TAGS mode.
- Check PageSlab() in addr_has_metadata().

Changes v4->v5:
(Vincenzo:)
- Reset the tag associated by the kernel to a page when this is changed by
  the user.
- Add a kselftest to verify that GCR_EL1 is preserved during context
  switch.
- Squashed the TBI patch.
- Addressed some review comments.
- Verified the series with LTP.
(Andrey:)
- Put core arm64 patches first as requested by Catalin.

Changes v3->v4:
(Vincenzo:)
- Introduced mte-def.h that contains MTE definitions.
- Moved __MTE_PREAMBLE in mte.h.
- Clarified which API is part of mte-kasan.h.
- Removed tsk argument from mte_set_kernel_gcr().
- Addressed several nitpicks pointed out during review.
(Andrey:)
- Move include <asm/kasan.h> in include/linux/kasan.h to avoid build
  failures.
- Don't move "select SLUB_DEBUG if SLUB" back and forth between patches
  in KASAN Kconfig.
- Add arm64 prefix to "kasan: don't allow SW_TAGS with ARM64_MTE" commit.
- Don't add braces when defining KASAN_GRANULE_SIZE.
- Make KASAN_HW_TAGS compatible with init_on_alloc/free.

Changes v2->v3:
(Vincenzo:)
- Use ARM64_ASM_PREAMBLE for asm macros.
- Rename mte-helper.h to mte-kasan.h. The new header is meant to contain
  only macros and prototypes directly used in KASAN. The rest is defined
  in mte.h.
- Update mte_get_mem_tag()/mte_get_random_tag() to used directly asm
  volatile() macros instead of calling library functions.
- Harden mte_assign_mem_tag_range() to prevent an infinite loop in case of
  unaligned size.
- Made sure that report_tag_fault() is executed only once.
- Simplify the mte code in __cpu_setup.
- Remove kprobes.h from mte.c includes.
- General cleanup of the code.
(Andrey:)
- Use READ/WRITE_ONCE when accessing reported in do_tag_recovery().
- Move .unreq mte_tcr under CONFIG_ARM64_MTE to avoid build errors when MTE
  is not enabled.
- Improve mm/kasan/shadow.c comment header.
- Clarify what is a memory granule in "kasan: rename KASAN_SHADOW_* to
  KASAN_GRANULE_" commit description.
- Rename (report_)tags_sw/hw.c to to (report_)sw/hw_tags.c and drop
  unnecessary rename commit.
- Adopt 100 lines limit for some mm/kasan/ changes.
- Align arguments for stack_trace_save() call in mm/slub.c.
- Restore comment before kasan_init_tags().
- Remove GNU headers from all mm/kasan/ files.
- Simplify check_invalid_free() implementation tag-based modes.
- Drop subsequently removed report_tag_fault() implementation.
- Add KASAN_GRANULE_PAGE and use instead of PAGE_SIZE * KASAN_GRANULE_SIZE.
- Move kasan_enable/disable_current() declarations to simplify
  include/linux/kasan.h.
- Drop dependency on CONFIG_SLUB_DEBUG.
- Clarify the purpose of CONFIG_STACKTRACE in KASAN Kconfig.

Changes v1->v2:
- Rebase onto v10 of the user MTE patchset.
- Only enable in-kernel MTE when KASAN_HW_TAGS is enabled.
- Add a layer of arch-level indirection, so KASAN doesn't call MTE helpers
  directly (this will be useful in case more architectures will add support
  for HW_TAGS).
- Don't do arm64_skip_faulting_instruction() on MTE fault, disable MTE
  instead.
- Don't allow software tags with MTE via arch/arm64/Kconfig instead of
  lib/Kconfig.kasan.
- Rename mm/kasan/tags.c to tags_sw.c and mte.c to tags_hw.c, and do the
  same for report_*.c files.
- Reword HW_TAGS Kconfig help text to make it less MTE specific.
- Reword and clarify Documentation.
- Drop unnecessary is_el1_mte_sync_tag_check_fault().
- Change report_tag_fault() to only call kasan_report() once HW_TAGS is
  introduced.
- Rename arch/arm64/include/asm/mte_asm.h to mte-helpers.h and move all
  MTE-related defines and some helper functions there.
- Change mm/kasan/kasan.h to include mte-def.h instead of mte.h.
- Add WARN_ON() on unaligned size to mte_set_mem_tag_range().
- Implement ldg/irg MTE routines as inline assembly.
- Remove smp_wmb() from mte_set_mem_tag_range().
- Drop __must_check from mte_set_mem_tag_range() as KASAN has no use for
  the return value.
- Drop zero size check from mte_assign_mem_tag_range().
- Drop unnecessary include <asm/kasan.h> from low-level arm64 code.
- Move enabling TBI1 into __cpu_setup().
- Drop stale comment about callee-saved register from
  arch/arm64/kernel/entry.S.
- Mark gcr_kernel_excl as __ro_after_init.
- Use GENMASK() in mte_init_tags().

Andrey Konovalov (32):
  arm64: kasan: Add arch layer for memory tagging helpers
  arm64: kasan: Align allocations for HW_TAGS
  kasan: drop unnecessary GPL text from comment headers
  kasan: KASAN_VMALLOC depends on KASAN_GENERIC
  kasan: group vmalloc code
  kasan: shadow declarations only for software modes
  kasan: rename (un)poison_shadow to (un)poison_memory
  kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
  kasan: only build init.c for software modes
  kasan: split out shadow.c from common.c
  kasan: define KASAN_GRANULE_PAGE
  kasan: rename report and tags files
  kasan: don't duplicate config dependencies
  kasan: hide invalid free check implementation
  kasan: decode stack frame only with KASAN_STACK_ENABLE
  kasan, arm64: only init shadow for software modes
  kasan, arm64: only use kasan_depth for software modes
  kasan: rename addr_has_shadow to addr_has_metadata
  kasan: rename print_shadow_for_address to print_memory_metadata
  kasan: kasan_non_canonical_hook only for software modes
  kasan: rename SHADOW layout macros to META
  kasan: separate metadata_fetch_row for each mode
  kasan, arm64: don't allow SW_TAGS with ARM64_MTE
  kasan: introduce CONFIG_KASAN_HW_TAGS
  kasan: define KASAN_GRANULE_SIZE for HW_TAGS
  kasan, x86, s390: update undef CONFIG_KASAN
  kasan, arm64: expand CONFIG_KASAN checks
  kasan, arm64: implement HW_TAGS runtime
  kasan, arm64: print report from tag fault handler
  kasan, mm: reset tags when accessing metadata
  kasan, arm64: enable CONFIG_KASAN_HW_TAGS
  kasan: add documentation for hardware tag-based mode

Vincenzo Frascino (8):
  arm64: Enable armv8.5-a asm-arch option
  arm64: mte: Add in-kernel MTE helpers
  arm64: mte: Reset the page tag in page->flags
  arm64: mte: Add in-kernel tag fault handler
  arm64: kasan: Enable in-kernel MTE
  arm64: mte: Convert gcr_user into an exclude mask
  arm64: mte: Switch GCR_EL1 in kernel entry and exit
  kselftest/arm64: Check GCR_EL1 after context switch

 Documentation/dev-tools/kasan.rst             |  80 ++-
 arch/arm64/Kconfig                            |   9 +-
 arch/arm64/Makefile                           |   7 +-
 arch/arm64/include/asm/assembler.h            |   2 +-
 arch/arm64/include/asm/cache.h                |   3 +
 arch/arm64/include/asm/esr.h                  |   1 +
 arch/arm64/include/asm/kasan.h                |   8 +-
 arch/arm64/include/asm/memory.h               |  14 +-
 arch/arm64/include/asm/mte-def.h              |  14 +
 arch/arm64/include/asm/mte-kasan.h            |  62 ++
 arch/arm64/include/asm/mte.h                  |  22 +-
 arch/arm64/include/asm/processor.h            |   2 +-
 arch/arm64/include/asm/string.h               |   5 +-
 arch/arm64/include/asm/uaccess.h              |  23 +
 arch/arm64/kernel/asm-offsets.c               |   3 +
 arch/arm64/kernel/cpufeature.c                |  10 +
 arch/arm64/kernel/entry.S                     |  41 ++
 arch/arm64/kernel/head.S                      |   2 +-
 arch/arm64/kernel/image-vars.h                |   2 +-
 arch/arm64/kernel/kaslr.c                     |   3 +-
 arch/arm64/kernel/module.c                    |   6 +-
 arch/arm64/kernel/mte.c                       |  94 ++-
 arch/arm64/kernel/setup.c                     |   5 +-
 arch/arm64/lib/mte.S                          |  16 +
 arch/arm64/mm/copypage.c                      |   1 +
 arch/arm64/mm/fault.c                         |  59 ++
 arch/arm64/mm/kasan_init.c                    |  22 +-
 arch/arm64/mm/mteswap.c                       |   1 +
 arch/arm64/mm/proc.S                          |  23 +-
 arch/arm64/mm/ptdump.c                        |   6 +-
 arch/s390/boot/string.c                       |   1 +
 arch/x86/boot/compressed/misc.h               |   1 +
 include/linux/kasan-checks.h                  |   2 +-
 include/linux/kasan.h                         | 105 ++--
 include/linux/mm.h                            |   2 +-
 include/linux/moduleloader.h                  |   3 +-
 include/linux/page-flags-layout.h             |   2 +-
 include/linux/sched.h                         |   2 +-
 include/linux/string.h                        |   2 +-
 init/init_task.c                              |   2 +-
 kernel/fork.c                                 |   4 +-
 lib/Kconfig.kasan                             |  62 +-
 lib/test_kasan.c                              |   2 +-
 mm/kasan/Makefile                             |  25 +-
 mm/kasan/common.c                             | 560 +-----------------
 mm/kasan/generic.c                            |  38 +-
 mm/kasan/generic_report.c                     | 165 ------
 mm/kasan/hw_tags.c                            |  70 +++
 mm/kasan/init.c                               |  17 +-
 mm/kasan/kasan.h                              |  64 +-
 mm/kasan/quarantine.c                         |  10 -
 mm/kasan/report.c                             | 259 ++------
 mm/kasan/report_generic.c                     | 326 ++++++++++
 mm/kasan/report_hw_tags.c                     |  42 ++
 mm/kasan/{tags_report.c => report_sw_tags.c}  |  14 +-
 mm/kasan/shadow.c                             | 503 ++++++++++++++++
 mm/kasan/{tags.c => sw_tags.c}                |  18 +-
 mm/page_alloc.c                               |   4 +-
 mm/page_poison.c                              |   2 +-
 mm/ptdump.c                                   |  13 +-
 mm/slab_common.c                              |   2 +-
 mm/slub.c                                     |  29 +-
 scripts/Makefile.lib                          |   2 +
 tools/testing/selftests/arm64/mte/Makefile    |   2 +-
 .../arm64/mte/check_gcr_el1_cswitch.c         | 152 +++++
 65 files changed, 1914 insertions(+), 1139 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte-def.h
 create mode 100644 arch/arm64/include/asm/mte-kasan.h
 delete mode 100644 mm/kasan/generic_report.c
 create mode 100644 mm/kasan/hw_tags.c
 create mode 100644 mm/kasan/report_generic.c
 create mode 100644 mm/kasan/report_hw_tags.c
 rename mm/kasan/{tags_report.c => report_sw_tags.c} (87%)
 create mode 100644 mm/kasan/shadow.c
 rename mm/kasan/{tags.c => sw_tags.c} (94%)
 create mode 100644 tools/testing/selftests/arm64/mte/check_gcr_el1_cswitch.c

-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1603999489.git.andreyknvl%40google.com.
