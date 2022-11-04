Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBWVVSWNQMGQENV4B7TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 124FB619FFD
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 19:33:00 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id c4-20020a4a9c44000000b00480da4502b9sf1269031ook.15
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 11:33:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667586778; cv=pass;
        d=google.com; s=arc-20160816;
        b=uKyR60p2YxVD/duNpMt5tWffO4n+JnsyDMnljk/xVccdJqhiyA/2zVshUrEPIJ5WNn
         MH5pxgFkTk+HrcUaV/jnEPpECmWgvcK221PS7nghBTkRMFAoz5EZhK1Et6hCR6oP9F+a
         HMHoQr875lroLztmZqZOQWz0ormEHQJMUPcXIT7vfCtVAenp4JYg1ts9RKr9VChFkNyH
         +nOnnoDLTP0hpfhfpU8nVkqopygQRhCouiz6naCV9Mp4vd4HNvq1kGUdQzv3/Zw6DHzb
         Cz/v5PcqkryhyiCLVzfkjLkGYRSw0qIplbCKr/IMzgnRtzkVtV3KPujVQRXaBvrEgqU+
         jnRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :references:mime-version:in-reply-to:date:reply-to:dkim-signature;
        bh=BK4sCdYcjjzBE2GDWSWhqaUXvw0MBAW5W4bZlnuytlg=;
        b=dN4ix+gVHjrOdqe3dTNmi2kudEF7uDpdnSuONE8jvf/fS012mZwup4AMXtog3xWLxn
         094bTNELTuL0fCpFKK6E7GiMiKCPQgYsW8VBVqce7ue+ycFN6ktgyu3RfCwbb5lbBxdo
         cFPLIQdLoUAStptimUmGT6UiL7x/twCmlq/OEFrtScWlz4VKN7AdNMo/dbndQqZUnwAI
         2kxlmMv+pduaLTjZCn3iwylULU8rD8bDpZ3yNUhNVIn9TfmqcO6leQyJi33s8CLLsyzt
         6oGC3bu1SXY4zODjQHEVhuAWuxuEPZE9WrLaB3z5wYUSwuv0Pe6dJVGTZ6gZ7yQrEFa9
         FYGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lSOSZi+k;
       spf=pass (google.com: domain of 32vplywykcuy0mivrkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=32VplYwYKCUY0mivrkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:reply-to:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BK4sCdYcjjzBE2GDWSWhqaUXvw0MBAW5W4bZlnuytlg=;
        b=kXKoZ1/FATpSkKLnPiifnXOVlRPv/feCZl39L6cueIP23E6png9mEerQhZImQyrUpS
         cYS1s8facvfmC50/M7JxsM2SaSw015Fu8DYcOs7RVZiwAMbZ/u11Yb3FN72OidT0g7Pd
         IGqcj3zUx6EYZVSPl2hkc4e9QjN3ukenwcnVWDcesOGvlvwh3dUZnmeER2AzLZd+7YQ7
         WSy5f/egnUDhp7nx8yhhmEJ/w7NZGFZz585NPDWtWrwSqaKNF8fhDx9JF48RY3VXve8h
         WjpGQgzs1i1mHrbwd3sE35yWgLQlMixsyErkB6jNmu13YFuKJwXHYBV/IrX6Vwlp/LrI
         90kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :reply-to:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BK4sCdYcjjzBE2GDWSWhqaUXvw0MBAW5W4bZlnuytlg=;
        b=xjyAfzqV9oqYV1Ix2Zuh4VOJpq1IugyDy+xnFlQbSz+I58Pdqc5xyzzundOT/VTyma
         jTSDSfNPFZAMRlnCGTXlabmg4B1TuKZEeQbaMZvek3WRdoLY6OFXfDPznVBwq98xuvCD
         Iq4A4Eaf32QISnjl2dczCbtnKgepM3TF0tgaka4lxRbTWM8uf8JwVbob4agtJCh2yTmd
         CAM3hQlckAOSOwWPtaCIRo43r5QUNP3qTi0WX6mMHJFuEp/Fqoj3sZiL/8C/B7NHuGsJ
         XBAr0ZEJuhsDeec9LW8PzdcF4UTOjhIVndFKhsZD/bm7p8e4yMreF4iOjqyd2fFCfSEW
         pm9w==
X-Gm-Message-State: ACrzQf2vy8cyOllQnLjKCMG3F7NHZwQKTk9ofbPqnw29PcrTGzVM5iKh
	MWJdRWsMgebGFGoK/QAKrrU=
X-Google-Smtp-Source: AMsMyM7ZSdmYp1wxweaDqqczajdf630dZRnHitZASggpDLOJ9+YZO9iPKz2OoiScmfJGV8KeNU6QKw==
X-Received: by 2002:a05:6870:e0c9:b0:13b:1cb9:9bc1 with SMTP id a9-20020a056870e0c900b0013b1cb99bc1mr21880208oab.188.1667586778587;
        Fri, 04 Nov 2022 11:32:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1690:b0:354:58db:8638 with SMTP id
 bb16-20020a056808169000b0035458db8638ls1720652oib.8.-pod-prod-gmail; Fri, 04
 Nov 2022 11:32:58 -0700 (PDT)
X-Received: by 2002:aca:4303:0:b0:354:cbc8:d269 with SMTP id q3-20020aca4303000000b00354cbc8d269mr19793153oia.115.1667586778044;
        Fri, 04 Nov 2022 11:32:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667586778; cv=none;
        d=google.com; s=arc-20160816;
        b=j24IxyAavsrcImX8yXIbKrs5MxiH41/sIgBr1TKmGC3TaXBPrCy/p9vmJFl7ETaiQK
         x755tHcm7sR7OFtamqUS0w8azHJLg22jKhYDWzZCNLgNJAbVmiLY2LquAmhdiA7EZKSr
         PufWiilX9r3khF4yL6yaRASMpVwaxicXl7vdZqsAvgnaKwuGY/tTTL3bSrdGoimJNH0W
         ES1rO1+BP5KD4HMsgO3zQzq1HWa9QfXYElE1O7zBRXDHEsd8Ra9zmPNAkcyEA5RHoU/i
         y54Cl9Ynx/jbnIqAGwJhyQLGQc190Qn3tynCEY8fSMbR1xJYbznpDKKZF5req05jBrIT
         ncsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:reply-to:dkim-signature;
        bh=YYBJ31ou5Rwg5LoGtjJ6FG68fLUfYn1uUGIk9MyRKGY=;
        b=AOX9usdGFqdqdNhvXt0AsuxqYac8mVzytyIX2S63HPLFOqUVxQO5vGcq5ZTocbSkbs
         YxCDjuS+vdLG08+8ZsmH/NU7dsl8d8aNZT2XeUxZUSR1qVcKlAJiyM1R5ngV609PoxfX
         LjAJh380A0v93UoZYk7dyBC8RQrAo6aTSxSwSOBocAnbHGbnDgAqModCZrBgY/lIb3Ys
         OhVRY5iscQCINFIswKsOXt7huORhKLi1Gi3R9UvJgX1T6+aEaOOj6h/GnGl6wOCDUMyZ
         yeTDeXqAn1+c3qy6ijZNK07+L8UC/DDN7AsMz6lV5QojpTp5q1TO5Cz8ScJmiiN2jSFu
         M1DA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lSOSZi+k;
       spf=pass (google.com: domain of 32vplywykcuy0mivrkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=32VplYwYKCUY0mivrkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x44a.google.com (mail-pf1-x44a.google.com. [2607:f8b0:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d8-20020acab408000000b0035522fd7d98si333243oif.1.2022.11.04.11.32.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Nov 2022 11:32:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32vplywykcuy0mivrkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) client-ip=2607:f8b0:4864:20::44a;
Received: by mail-pf1-x44a.google.com with SMTP id f189-20020a6238c6000000b0056e3400fdc0so2836872pfa.10
        for <kasan-dev@googlegroups.com>; Fri, 04 Nov 2022 11:32:58 -0700 (PDT)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a05:6a00:2886:b0:565:c4e2:2634 with SMTP id
 ch6-20020a056a00288600b00565c4e22634mr366477pfb.0.1667586777418; Fri, 04 Nov
 2022 11:32:57 -0700 (PDT)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Fri,  4 Nov 2022 18:32:47 +0000
In-Reply-To: <20221104183247.834988-1-seanjc@google.com>
Mime-Version: 1.0
References: <20221104183247.834988-1-seanjc@google.com>
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221104183247.834988-4-seanjc@google.com>
Subject: [PATCH 3/3] x86/kasan: Populate shadow for shared chunk of the CPU
 entry area
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Sean Christopherson <seanjc@google.com>, syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lSOSZi+k;       spf=pass
 (google.com: domain of 32vplywykcuy0mivrkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=32VplYwYKCUY0mivrkowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sean Christopherson <seanjc@google.com>
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

Popuplate the shadow for the shared portion of the CPU entry area, i.e.
the read-only IDT mapping, during KASAN initialization.  A recent change
modified KASAN to map the per-CPU areas on-demand, but forgot to keep a
shadow for the common area that is shared amongst all CPUs.

Map the common area in KASAN init instead of letting idt_map_in_cea() do
the dirty work so that it Just Works in the unlikely event more shared
data is shoved into the CPU entry area.

The bug manifests as a not-present #PF when software attempts to lookup
an IDT entry, e.g. when KVM is handling IRQs on Intel CPUs (KVM performs
direct CALL to the IRQ handler to avoid the overhead of INTn):

 BUG: unable to handle page fault for address: fffffbc0000001d8
 #PF: supervisor read access in kernel mode
 #PF: error_code(0x0000) - not-present page
 PGD 16c03a067 P4D 16c03a067 PUD 0
 Oops: 0000 [#1] PREEMPT SMP KASAN
 CPU: 5 PID: 901 Comm: repro Tainted: G        W          6.1.0-rc3+ #410
 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015
 RIP: 0010:kasan_check_range+0xdf/0x190
  vmx_handle_exit_irqoff+0x152/0x290 [kvm_intel]
  vcpu_run+0x1d89/0x2bd0 [kvm]
  kvm_arch_vcpu_ioctl_run+0x3ce/0xa70 [kvm]
  kvm_vcpu_ioctl+0x349/0x900 [kvm]
  __x64_sys_ioctl+0xb8/0xf0
  do_syscall_64+0x2b/0x50
  entry_SYSCALL_64_after_hwframe+0x46/0xb0

Fixes: 9fd429c28073 ("x86/kasan: Map shadow for percpu pages on demand")
Reported-by: syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Signed-off-by: Sean Christopherson <seanjc@google.com>
---
 arch/x86/mm/kasan_init_64.c | 12 +++++++++++-
 1 file changed, 11 insertions(+), 1 deletion(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index afc5e129ca7b..0302491d799d 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -341,7 +341,7 @@ void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid)
 
 void __init kasan_init(void)
 {
-	unsigned long shadow_cea_begin, shadow_cea_end;
+	unsigned long shadow_cea_begin, shadow_cea_per_cpu_begin, shadow_cea_end;
 	int i;
 
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
@@ -384,6 +384,7 @@ void __init kasan_init(void)
 	}
 
 	shadow_cea_begin = kasan_mem_to_shadow_align_down(CPU_ENTRY_AREA_BASE);
+	shadow_cea_per_cpu_begin = kasan_mem_to_shadow_align_up(CPU_ENTRY_AREA_PER_CPU);
 	shadow_cea_end = kasan_mem_to_shadow_align_up(CPU_ENTRY_AREA_BASE +
 						      CPU_ENTRY_AREA_MAP_SIZE);
 
@@ -409,6 +410,15 @@ void __init kasan_init(void)
 		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
 		(void *)shadow_cea_begin);
 
+	/*
+	 * Populate the shadow for the shared portion of the CPU entry area.
+	 * Shadows for the per-CPU areas are mapped on-demand, as each CPU's
+	 * area is randomly placed somewhere in the 512GiB range and mapping
+	 * the entire 512GiB range is prohibitively expensive.
+	 */
+	kasan_populate_shadow(shadow_cea_begin,
+			      shadow_cea_per_cpu_begin, 0);
+
 	kasan_populate_early_shadow((void *)shadow_cea_end,
 			kasan_mem_to_shadow((void *)__START_KERNEL_map));
 
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221104183247.834988-4-seanjc%40google.com.
