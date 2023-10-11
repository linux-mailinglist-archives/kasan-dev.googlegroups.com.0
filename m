Return-Path: <kasan-dev+bncBC5ZR244WYFRBSEPTGUQMGQEA3K3BZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 647EC7C4B11
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Oct 2023 08:59:22 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5041a779c75sf5795974e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 23:59:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697007561; cv=pass;
        d=google.com; s=arc-20160816;
        b=YoJ/aQAGmcdqvMsROOr/fG2/XasXwvZ9g0RlHV5iI+Pc8jZYcx06Mk6REebnVqUsCu
         PuZ/T/K1nUYKzest7d/apOVZTyuiv9+pvf3U2VYkQx4MnB5RJaOwD3m/n4nbYDWRHXrj
         SL5e5ekIAMawUTwZvcvi9QTJRxBpd3a59Sp3W1Mm3q5BFkPECk7pBgArhPZZcOkDZjRP
         9dJYFPosT4cZmHkzvfHhCjI4+QVC2uzvdbAc+lGSXJ4KtplVRT5bEMkbrq68lTJ+NCmW
         Ny3PCo94MMu6tqp9l+KIZ0lawQU6iB5tEF2q0RrCkPxl2TgkYu5LUrabvUp9wMqgzy71
         VHqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=BhILNyQjudnzWluov4hwWMIXdr+6nU9lUFnyZXO9hZo=;
        fh=TZ1FtIqeUfZfQ3GkbpRP0NuCIS8eHq7hqM2LIHeinyY=;
        b=vVrJ1Zo83hav43k01+2H+JNycFkQ5bSH3J7jh3CvLT837jR5fxnuGnzD69k8rSc/V1
         wtSGlfeLbK9uKtaFCrbBJOo+25My+GQPmPENKjEQkg/HqKEfnOkcZ3ztU9AXRTJ49eFp
         y7Lg79OSCEiBnpEkW/HSnzZptOnPE8k2qk0p0JwjeKVk4e3slWkWsuMjD255yBVgfw65
         xclubHLyB/+qsO0ELA8PpM88Jt+08T72cAAC+OghsnOpIqQKuRi4gA6bWGd6RDuywjnh
         jQ9GGxcKtBI3g9DPDBml7hNndQwXht6ye4wITWiXyr23PmW6qK3goaYBN/gHWBPThynW
         bPbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SKv6dcHu;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697007561; x=1697612361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BhILNyQjudnzWluov4hwWMIXdr+6nU9lUFnyZXO9hZo=;
        b=W3jyCrwC7K8AW1m7qCgcCi2xWJH8+6wv+0GRSOQcZ1q/w0x0znuJhYZqRZ/HNCYLPI
         OH3qUKIZbSnxwvoU81Rzn7fqiVdagpOBzbEk/FMuoSra6uLXX+4iRcRMj1EUEhYciHWO
         nES4tLfOPok0q+DY8TXfmaIoExdOgfDnYEzPVDMVhKVScvbaaq/nxj51sPSBPOhJZxV/
         pOrwQl4OInQ4Z8pEAlrGL1yUqM/AvFDerxK4YOsCFg0YkkT3A9OT1uE/sPshZ9wHtu4L
         Xopxnc5umWUOXBCcxTNDhFmreJRpZbyKXKP3W/vI8X2pahPbBoZPMKxmCsrLQ6jZmB6S
         uLGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697007561; x=1697612361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BhILNyQjudnzWluov4hwWMIXdr+6nU9lUFnyZXO9hZo=;
        b=RF/iGaGz79iiegKD8cFKmNxdvt1cabKLyrUljQdV8uTc988apEQN2flvRwJfNdJzyQ
         sOF4CdnCys/SO29bHgQQvd/6Sf/wZ79jJfq+GDPck71tZBQ/2o0+QRtHA8jVeN75ZSWr
         HimwA0BTBBsM9Ow1W4KYIPn2A1vz0QO+WDQMOUgt5hMqYCfxmMc0nrHNyCfRBDE5xtlv
         pGKze8gJJ2Gl4oyaUMz+wWQ5lbXBTa9lMjPqF61RcYFMbtdGf4XJvTZs9qxo3nLDtzoS
         PzPNaU6+h1Oo4zvyxcxNG/t1AO4XyQ4W/IQhFvmOMGQnLC74foGxhv9A4XivS6j2w1bx
         C2qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzsnz6Z/rtdeDhUBy+cZqbCr6l/wNrT/CspKjRKk6EnyyaWkSxr
	EqRgdpTm5pwAklzoLqCSWgU=
X-Google-Smtp-Source: AGHT+IF4PBkfuKwiE2LqrGCQXKxL1LWn7IhPg9lPVZ7MoG/UC6NMg/ImQn8wuEdJhxordIs3mpep4w==
X-Received: by 2002:a19:8c0c:0:b0:500:b287:36df with SMTP id o12-20020a198c0c000000b00500b28736dfmr15488483lfd.13.1697007561216;
        Tue, 10 Oct 2023 23:59:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4f47:0:b0:504:21fa:eb91 with SMTP id a7-20020a194f47000000b0050421faeb91ls634171lfk.0.-pod-prod-02-eu;
 Tue, 10 Oct 2023 23:59:19 -0700 (PDT)
X-Received: by 2002:a05:651c:d2:b0:2bc:fd7b:8ded with SMTP id 18-20020a05651c00d200b002bcfd7b8dedmr19707543ljr.20.1697007559300;
        Tue, 10 Oct 2023 23:59:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697007559; cv=none;
        d=google.com; s=arc-20160816;
        b=JwAz342/sW8Lqki6Ae5iidfsXlo/xkuODON6O6WPXF1YIOUMzwYcnwgS6AmkvVTaZz
         DRxLH0uCAf8aur843mH4rU+e8m2AFpI7bauVIpZLNaJRATiJSf7/IGMGruv6pCIy5mWF
         x82X4OaYuLnmSSKxMC6fkFbgp5SnFj0+ypjQGyRqO8ddIw8+xujQRaof26G/2WuUuzRL
         Xf68zbh8wVAomoNAgKwO6rBhO12KHAhYbqA4ZH+qJy/EPR7h84oztODMq0KLX9WEZSM6
         SD9DPEDXwWQYgUdN7ygQhSa7aWbD0wuSiUAuGyayhSzO9fpxlUy7NvUaS/zyqt6Dew1Y
         WaJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=3rwuNaEGJvWvbjPsWf5zdg6cXtxL9Sg15AKxACjPVYk=;
        fh=TZ1FtIqeUfZfQ3GkbpRP0NuCIS8eHq7hqM2LIHeinyY=;
        b=CldX0h6mHCZRRi0J8LBgluUjF4rn754Zbr36srgo+tQH/Hzqs6hD3C8rSP+0thqhbB
         zSdKCIkEL4iq2Mn2DVz1SmCQvUWM+FDJf55YicnDLBAyYgKZAmU662qLMsyoZF3d1oL7
         SWGQgnjKV1y0h4+E+DMwDDYOo54F4O3L1RN4HCH6+qN3hf3sw+Dj0DL9My/d1u3v15Fc
         hGBbZPiNWDLdBT3s9R+lgkzb8JOqYV2Vuio/0cdCywT2KJdedh/fWaje2SykXQsyB1bd
         cSD1TUBynUodYI+7vu3ZmYfEA6YYtb6zc/xAC5Rjuoob92Z6iCLaED1kdwygczUKjud7
         FLAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=SKv6dcHu;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id b28-20020a2ebc1c000000b002c29b97d5f2si704037ljf.1.2023.10.10.23.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Oct 2023 23:59:19 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6600,9927,10859"; a="364879646"
X-IronPort-AV: E=Sophos;i="6.03,214,1694761200"; 
   d="scan'208";a="364879646"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 23:59:16 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10859"; a="703617236"
X-IronPort-AV: E=Sophos;i="6.03,214,1694761200"; 
   d="scan'208";a="703617236"
Received: from laptop-dan-intel.ccr.corp.intel.com (HELO box.shutemov.name) ([10.252.56.166])
  by orsmga003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 23:59:07 -0700
Received: by box.shutemov.name (Postfix, from userid 1000)
	id A23BB10A1A3; Wed, 11 Oct 2023 09:58:56 +0300 (+03)
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Peter Zijlstra <peterz@infradead.org>
Cc: x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Fei Yang <fei.yang@intel.com>,
	stable@vger.kernel.org
Subject: [PATCHv2] x86/alternatives: Disable KASAN in apply_alternatives()
Date: Wed, 11 Oct 2023 09:58:49 +0300
Message-ID: <20231011065849.19075-1-kirill.shutemov@linux.intel.com>
X-Mailer: git-send-email 2.41.0
MIME-Version: 1.0
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=SKv6dcHu;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=kirill.shutemov@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

Fei has reported that KASAN triggers during apply_alternatives() on
5-level paging machine:

	BUG: KASAN: out-of-bounds in rcu_is_watching (./arch/x86/include/asm/atomic.h:23 ./include/linux/atomic/atomic-arch-fallback.h:444 ./include/linux/context_tracking.h:122 kernel/rcu/tree.c:699)
	Read of size 4 at addr ff110003ee6419a0 by task swapper/0/0

	CPU: 0 PID: 0 Comm: swapper/0 Not tainted 6.6.0-rc5 #12
	Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015
	Call Trace:
	<TASK>
	dump_stack_lvl (lib/dump_stack.c:107)
	print_report (mm/kasan/report.c:365 mm/kasan/report.c:475)
	? __phys_addr (arch/x86/mm/physaddr.h:7 arch/x86/mm/physaddr.c:28)
	? kasan_addr_to_slab (./include/linux/mm.h:1265 (discriminator 1) mm/kasan/../slab.h:213 (discriminator 1) mm/kasan/common.c:36 (discriminator 1))
	kasan_report (mm/kasan/report.c:590)
	? rcu_is_watching (./arch/x86/include/asm/atomic.h:23 ./include/linux/atomic/atomic-arch-fallback.h:444 ./include/linux/context_tracking.h:122 kernel/rcu/tree.c:699)
	? rcu_is_watching (./arch/x86/include/asm/atomic.h:23 ./include/linux/atomic/atomic-arch-fallback.h:444 ./include/linux/context_tracking.h:122 kernel/rcu/tree.c:699)
	? apply_alternatives (arch/x86/kernel/alternative.c:415 (discriminator 1))
	__asan_load4 (mm/kasan/generic.c:259)
	rcu_is_watching (./arch/x86/include/asm/atomic.h:23 ./include/linux/atomic/atomic-arch-fallback.h:444 ./include/linux/context_tracking.h:122 kernel/rcu/tree.c:699)
	? text_poke_early (./arch/x86/include/asm/irqflags.h:42 ./arch/x86/include/asm/irqflags.h:77 ./arch/x86/include/asm/irqflags.h:135 arch/x86/kernel/alternative.c:1675)
	trace_hardirqs_on (./include/trace/events/preemptirq.h:40 (discriminator 2) ./include/trace/events/preemptirq.h:40 (discriminator 2) kernel/trace/trace_preemptirq.c:56 (discriminator 2))
	? __asan_load4 (./arch/x86/include/asm/cpufeature.h:171 mm/kasan/kasan.h:306 mm/kasan/generic.c:175 mm/kasan/generic.c:259)
	text_poke_early (./arch/x86/include/asm/irqflags.h:42 ./arch/x86/include/asm/irqflags.h:77 ./arch/x86/include/asm/irqflags.h:135 arch/x86/kernel/alternative.c:1675)
	apply_alternatives (arch/x86/kernel/alternative.c:415 (discriminator 1))
	? __asan_load4 (./arch/x86/include/asm/cpufeature.h:171 mm/kasan/kasan.h:306 mm/kasan/generic.c:175 mm/kasan/generic.c:259)
	? __pfx_apply_alternatives (arch/x86/kernel/alternative.c:400)
	? __pfx_apply_returns (arch/x86/kernel/alternative.c:720)
	? __this_cpu_preempt_check (lib/smp_processor_id.c:67)
	? _sub_I_65535_1 (init/main.c:1573)
	? int3_selftest_ip (arch/x86/kernel/alternative.c:1496)
	? __pfx_int3_selftest (arch/x86/kernel/alternative.c:1496)
	? lockdep_hardirqs_on (kernel/locking/lockdep.c:4422)
	? fpu__init_cpu_generic (./arch/x86/include/asm/irqflags.h:42 ./arch/x86/include/asm/irqflags.h:77 ./arch/x86/include/asm/irqflags.h:135 ./arch/x86/include/asm/tlbflush.h:47 arch/x86/kernel/fpu/init.c:30)
	alternative_instructions (arch/x86/kernel/alternative.c:1618)
	arch_cpu_finalize_init (arch/x86/kernel/cpu/common.c:2404)
	start_kernel (init/main.c:1037)
	x86_64_start_reservations (arch/x86/kernel/head64.c:544)
	x86_64_start_kernel (arch/x86/kernel/head64.c:486 (discriminator 5))
	secondary_startup_64_no_verify (arch/x86/kernel/head_64.S:433)
	</TASK>

	The buggy address belongs to the physical page:
	page:(____ptrval____) refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x3ee641
	flags: 0x20000000004000(reserved|node=0|zone=2)
	page_type: 0xffffffff()
	raw: 0020000000004000 ffd400000fb99048 ffd400000fb99048 0000000000000000
	raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000
	page dumped because: kasan: bad access detected

	Memory state around the buggy address:
	ff110003ee641880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	ff110003ee641900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	>ff110003ee641980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	^
	ff110003ee641a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	ff110003ee641a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57)
got patched. It includes KASAN code, where KASAN_SHADOW_START depends on
__VIRTUAL_MASK_SHIFT, which is defined with the cpu_feature_enabled().

KASAN gets confused when apply_alternatives() patches the
KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START
static, by replacing __VIRTUAL_MASK_SHIFT with 56, fixes the issue.

Disable KASAN while kernel patches alternatives.

Signed-off-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Reported-by: Fei Yang <fei.yang@intel.com>
Fixes: 6657fca06e3f ("x86/mm: Allow to boot without LA57 if CONFIG_X86_5LEVEL=y")
Cc: stable@vger.kernel.org
---

 v2:
  - Move kasan_disable/_enable_current() to cover whole loop, not only
    text_poke_early();
  - Adjust commit message.

---
 arch/x86/kernel/alternative.c | 13 +++++++++++++
 1 file changed, 13 insertions(+)

diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
index 517ee01503be..b4cc4d7c0825 100644
--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -403,6 +403,17 @@ void __init_or_module noinline apply_alternatives(struct alt_instr *start,
 	u8 insn_buff[MAX_PATCH_LEN];
 
 	DPRINTK(ALT, "alt table %px, -> %px", start, end);
+
+	/*
+	 * In the case CONFIG_X86_5LEVEL=y, KASAN_SHADOW_START is defined using
+	 * cpu_feature_enabled(X86_FEATURE_LA57) and is therefore patched here.
+	 * During the process, KASAN becomes confused and triggers
+	 * a false-positive out-of-bound report.
+	 *
+	 * Disable KASAN until the patching is complete.
+	 */
+	kasan_disable_current();
+
 	/*
 	 * The scan order should be from start to end. A later scanned
 	 * alternative code can overwrite previously scanned alternative code.
@@ -452,6 +463,8 @@ void __init_or_module noinline apply_alternatives(struct alt_instr *start,
 
 		text_poke_early(instr, insn_buff, insn_buff_sz);
 	}
+
+	kasan_enable_current();
 }
 
 static inline bool is_jcc32(struct insn *insn)
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231011065849.19075-1-kirill.shutemov%40linux.intel.com.
