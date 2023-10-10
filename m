Return-Path: <kasan-dev+bncBC5ZR244WYFRBH6GSOUQMGQEIEFNA3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id EC5A87BF24C
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 07:37:37 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-505a1b94382sf13613e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 22:37:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696916257; cv=pass;
        d=google.com; s=arc-20160816;
        b=HJ89XMg4wAYnkKMqtG2QXEjSgTO3MQ45FSS1UKEX571oOTAZqs2zwuXjik1PPHzvU0
         +IIthBHUzh5+LF5R3PotI5bACLFkJdlml6GubGpwuaYrAk8+dF3pyYp80l5bQz2YjQC/
         3iuNJn5IZVTJ2H7NRirsyZYnrZCYjQMrikX0Qc6D3tOKfZf9b0uZztbQqidltUS5B35G
         63t7gjSovd/tc/vUy0Ai9X43U9KN6NuHH1HUTbYdPTIUC+c3jb4PniLCUUBg3XjubM+d
         LS8xGb9Z5k6aoZiCpLRL7zsEb1pnbtTsx0y0Tk/6zp35T2eiN8gVheWJqzTktiOxF4DL
         D3Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=8fnBSm1H+daK3oNtwzVswu8JXs3SGF2SovzODMB4pG0=;
        fh=TZ1FtIqeUfZfQ3GkbpRP0NuCIS8eHq7hqM2LIHeinyY=;
        b=cns+8LrBQlTxFnpg3Kvfvv1VZJSqpAxxwV5TFidxy4WDSHJpj/DAkhg7XQyBtSe4xs
         0iKkN2TXL0AeGoOQR15sys41aMthLClLDDpiHBJsyO2M/Yf6khP5jVL478z/m9ddowWi
         bwwDLsi7uvs7AXWRqfuId/5OEnA0lxVb0nWa09eT6mbU19QXSkYzFaDjmLfvMFAaYsUV
         HxvrKRRwvpJiUPXL4iBk6Efqys+Ofhqa3pczk1jiSO8UM+JwDm4+R58bKCchZxi2xEuh
         UgIOA/BkJXLTO1emzpYdTxEUi3fb5pnCX60XMaT8Zl6mUDpM04uB9wti4gjnSDYgy4tr
         DhdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="T/+IDaum";
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696916257; x=1697521057; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8fnBSm1H+daK3oNtwzVswu8JXs3SGF2SovzODMB4pG0=;
        b=XjbajWG4MOBGQQ10j34r4tPs8/5h3YWOzQp8wQdJNciHr0LkGM/O1cZNp3xpiWhr8j
         Vdd98xO3kdzJeWtZpOVEJzvDHYCg592jFjvr8bC/3rxs5nFpgI+Th9ruyN29z01ffMTM
         t4oIhBq/R6Yi6ryew47+PsDGS+9jZEa7eg6QxMA1duo2eW5vFqRGnXkARusOmY9qpFux
         OL6tWBxHLroz+9xVwcUs2dqBTMUXQ3X2vSmSnYpg2U94oWDZovnhALHVNC9h7xmrwPp0
         Tovy6Xj9HmIwO/f4G83WCauk6pN4bZnVXkNCzevh6HOHCO1POUZitrVxqqhnqfB8HOAg
         x9Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696916257; x=1697521057;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8fnBSm1H+daK3oNtwzVswu8JXs3SGF2SovzODMB4pG0=;
        b=SG+KhX2h83+iiHT6AxgKZA0MteLjnSZRv21EXHijAigLBJ91vq0ABJ4sk2jPTsS7Au
         06u+k7C8FmKk9LgmcUxvZnQHuNTUnq+aS+0QbwbF3iWwdbrXZcJsHpf3bVN3QA9ZMmjN
         JWi6age0vVBUf3nREUnVjR3cG4bno4J4Ved1Gbs7byMktU8mWukB7oi1Uo10CBaNUURR
         cfLGwHLWT4rHmG4PJ8Kzt84N9I+0oFu+XHYxXAvq2Hgvsn9tAaYxYpzL+ikIyoxzMDWR
         TMm2WOpETy7z8aKQaKpb1Ilm7zjKbC4utiwHK9nf5q4Ym3mt5VqQ6IRw0Mbmdgre5/2j
         /O+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwYzH6quokAj9OntzEB7lwbhWt7RDVfuENSInznPSh4wdUmUKZY
	SPC3qv8SS6qm9of3fyZqKDU=
X-Google-Smtp-Source: AGHT+IF2F3fuDCDSEntCP1Dc8T+Lf+lwc7KfmdXz99uI0cx9Per7W3UjwbHQ+TIlj8oSVU/EDtjmjQ==
X-Received: by 2002:a19:f014:0:b0:502:c615:99b0 with SMTP id p20-20020a19f014000000b00502c61599b0mr287311lfc.4.1696916255702;
        Mon, 09 Oct 2023 22:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:32b2:b0:503:7b0:dff0 with SMTP id
 q18-20020a05651232b200b0050307b0dff0ls2206723lfe.0.-pod-prod-04-eu; Mon, 09
 Oct 2023 22:37:33 -0700 (PDT)
X-Received: by 2002:ac2:5f0a:0:b0:500:af69:5556 with SMTP id 10-20020ac25f0a000000b00500af695556mr13460823lfq.29.1696916253753;
        Mon, 09 Oct 2023 22:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696916253; cv=none;
        d=google.com; s=arc-20160816;
        b=wDOJk2YjO02x39d12itQRy2xxBbYjPlr7JILzQU2IR5EfyHTXLJgBuv+ukK7WKnRdY
         LNQ3KGNnbEQP9CND9nJeGTVaKSj+DUV/uteA54dvKScIaWFMRy3T7wweiaTSLA0I5r8T
         oF+H+BUj70oOyC9U9GsruEyP+09OxLN59rB6j3WPtjET3DxdeWZZstfxLS5xCnJIOD0J
         kBXge0d7pQfJ5Ji7I9MQUrDMiMFGOminAycrLLbRRFeLdi7PvlD7s/exrHp4lTBwM0Yy
         4ODgIj6cq4fTdZSi9i2seb3ppjfhHHFhhOS4KrFcOdKm1zYtry8KvjQXiDPjwFMkrrr9
         nu7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=aksCWqdpxaf3UNK6qPj3rWj9wsmjDCN/R2ZbISdY6XY=;
        fh=TZ1FtIqeUfZfQ3GkbpRP0NuCIS8eHq7hqM2LIHeinyY=;
        b=DvqYwL6p5v9bacbDMd+NGC7yaVf5Mi1T1tkOF83NeVi0G60vzGNPwkrJIr96rJRH1T
         j6ElW958cW0bhiGPXbjfL49JvcneBqvvt/GJ596VWV7PTsr1SxXIMbL09xZcCom/z2g9
         Mkx5Nno184/X1ecjwMIDJYVsdMH7Kh2n/QMcovhCka2B0ObvfX7Us+jlc0sFvlqy1dOM
         oYbo8qF2uLrKvKyAylcWVpEtCjAKNJzFeSEzSuXDULpjq6XJw/bmw/LM6jmz1fyIip4I
         dEXlSy5KbzaOgvFRRANYpXvo4r32u2X01ksFtS6YnqOncaaIuHmOnuXoEjJwcqUUvFm0
         RjAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="T/+IDaum";
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.7])
        by gmr-mx.google.com with ESMTPS id d7-20020a056512368700b004fe3ba741c8si456677lfs.8.2023.10.09.22.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Oct 2023 22:37:33 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.7;
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="5871660"
X-IronPort-AV: E=Sophos;i="6.03,211,1694761200"; 
   d="scan'208";a="5871660"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by fmvoesa101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Oct 2023 22:37:31 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="1000541347"
X-IronPort-AV: E=Sophos;i="6.03,211,1694761200"; 
   d="scan'208";a="1000541347"
Received: from geigerri-mobl.ger.corp.intel.com (HELO box.shutemov.name) ([10.252.41.165])
  by fmsmga006-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Oct 2023 22:37:26 -0700
Received: by box.shutemov.name (Postfix, from userid 1000)
	id D7AFB10A196; Tue, 10 Oct 2023 08:37:23 +0300 (+03)
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
Subject: [PATCH] x86/alternatives: Disable KASAN on text_poke_early() in apply_alternatives()
Date: Tue, 10 Oct 2023 08:37:16 +0300
Message-ID: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
X-Mailer: git-send-email 2.41.0
MIME-Version: 1.0
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="T/+IDaum";       spf=none
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

It seems that KASAN gets confused when apply_alternatives() patches the
KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START
static, by replacing __VIRTUAL_MASK_SHIFT with 56, fixes the issue.

During text_poke_early() in apply_alternatives(), KASAN should be
disabled. KASAN is already disabled in non-_early() text_poke().

It is unclear why the issue was not reported earlier. Bisecting does not
help. Older kernels trigger the issue less frequently, but it still
occurs. In the absence of any other clear offenders, the initial dynamic
5-level paging support is to blame.

Signed-off-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
Reported-by: Fei Yang <fei.yang@intel.com>
Fixes: 6657fca06e3f ("x86/mm: Allow to boot without LA57 if CONFIG_X86_5LEVEL=y")
Cc: stable@vger.kernel.org
---
 arch/x86/kernel/alternative.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
index 517ee01503be..56187fd8816e 100644
--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -450,7 +450,9 @@ void __init_or_module noinline apply_alternatives(struct alt_instr *start,
 		DUMP_BYTES(ALT, replacement, a->replacementlen, "%px:   rpl_insn: ", replacement);
 		DUMP_BYTES(ALT, insn_buff, insn_buff_sz, "%px: final_insn: ", instr);
 
+		kasan_disable_current();
 		text_poke_early(instr, insn_buff, insn_buff_sz);
+		kasan_enable_current();
 	}
 }
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010053716.2481-1-kirill.shutemov%40linux.intel.com.
