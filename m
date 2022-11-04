Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBFEGS2NQMGQEVSJ7TSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B51061A345
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 22:24:38 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-36fde8f2cdcsf56452817b3.23
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 14:24:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667597076; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+ckiR/nkhvcSep0qQKjOmlKzBjg6n4rvKFXZv9aFcpIq7leTTTAdxU5KZKsf9573H
         RWlyqDAOkcmNb/KUVd21UuwzzDMbH/mjbWw6Fa+prcGytCWMF2o3/D/c2rpClEI6vIjs
         7vxFtHIB9rmX9PCha/+6Wh+IWWbEqeTUFDA+57DFBVLlAWPvtwCvig+UxelTGIvWu/b4
         MoUxgqrqjFzvHePRUQN69l8xxEAQ4KjtSXuZ4m6Po2DIJ54VkHQAYXEAaALfGs0OE2J+
         lVk0RsbY0UwOkXFr4qgb+3S/+IH7fJm5uh6r9ZJrPRxMYjbw/4hNcsMNn2KbEyhTEwnq
         ndZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :mime-version:date:reply-to:dkim-signature;
        bh=W6zhXQUtvKRwPrJlWOm0yXynRAqGw5pJTdzzMMxsUZ8=;
        b=AaUB3R8hAEbnttsbviVNsucd5ixpICZV+ylusEbj7FTbDV98IiqpP8VQHlD9aexdb7
         FtFPpYnGhYmPvuObdcyxt7iVgosOGjXTfphvvztSM6fN1svDDw0WtIVtMI56klCyS51J
         o6kQpq5j2FlL59FHqlJiXwOazRDHTxgsvlYG5EljN7Et6hr3WQmp/vRtKI1CaRRLKz5V
         4O7qTwFucNd0jX8czs7gH8is1KA97QaCXAmVwIWQfngvgL97Cr0vnJh9wMdNmaAe94tv
         H//qxl0DG1BLYQbGekfMZ/psFCTX08HhscoeDQVh+8GVe3TWjAX19LnPGwGo0Th6asda
         PpRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ArHTBmvC;
       spf=pass (google.com: domain of 3e4nlywykcdae0w95y2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3E4NlYwYKCdAE0w95y2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:mime-version:date
         :reply-to:from:to:cc:subject:date:message-id:reply-to;
        bh=W6zhXQUtvKRwPrJlWOm0yXynRAqGw5pJTdzzMMxsUZ8=;
        b=W/xV2EM6t7JCc4WJnEP98LeuocpdHWYCJUdO7U7W/n5tmIp8sD1V53s95TZPKyvAsF
         O5hpLzWk5VKVzGEbcjlDnfC5N8ww1CjRVhvWCE68ZjDeTURhBVlxI2HaDI3htgk8E7HG
         bhQmp5fa0bgh0sppFDLmB0w6yoaa3jki98HKr3OY9mlRylg1w0vve/u64hpYdg+qgNwA
         AnyW/+9a3wq5kmUeiQflR64ZWGduYTY8UXSSEWmXCe0dpnBFbA2qvCa32pxoah1n9mPJ
         lehwxqcWVovnbd8su1BM+IYLZ6gmCV9ihZHKpmfo3PV5S6fAgGeSuPYO4pFsuJa0Czfn
         lJVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:reply-to:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=W6zhXQUtvKRwPrJlWOm0yXynRAqGw5pJTdzzMMxsUZ8=;
        b=kJEureKpZ+Zu5qWUdIWCJUQTcgLkAlR+zVMvucuxW1WgDRordjwP1NPQMFMXgbM3sP
         i3NlRtFiYwBV0S5ImjsC6N19KRokc1FUxhM9av90LpfrGUJo+Wrws0LCWwYG6bjztrn0
         ICPgmWLJiWpYDkiMl8bYaTh/cYefMioAa0lR6wM4gCKeObQJkWKWtc0LGBnNvr6gN0gw
         YYM1g/3jpZNPODaLiQmJcbm6mNaRqzElJauW9goTkT6WgaX1tvez+N95nVBy0gbqt16D
         VRzI7J+gbLbpm+3vOuu5DDWzlkxxUQekfnPftMv/IZabv+qCqNNYAYmNGpKNI2JhfH6s
         VnFg==
X-Gm-Message-State: ACrzQf3Fzglz261mB8H56AvJt0WR/c3H+U4HVOOnGTXgu+Z7uqQX9pTC
	Z7PC4gS2GWi345eRp2QsX74=
X-Google-Smtp-Source: AMsMyM4v/BYX7RGdyr1x34Tlhi6NvKPOQ8TuYRkm1TM7iUiDxM47UTyw1n+yn6S9Px/ZHVX93DJTrg==
X-Received: by 2002:a5b:a44:0:b0:6b0:13b:c93b with SMTP id z4-20020a5b0a44000000b006b0013bc93bmr37108894ybq.398.1667597076732;
        Fri, 04 Nov 2022 14:24:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:591:b0:370:5909:90f7 with SMTP id
 bo17-20020a05690c059100b00370590990f7ls2412333ywb.0.-pod-prod-gmail; Fri, 04
 Nov 2022 14:24:36 -0700 (PDT)
X-Received: by 2002:a81:4503:0:b0:373:53ec:306d with SMTP id s3-20020a814503000000b0037353ec306dmr16505446ywa.363.1667597076185;
        Fri, 04 Nov 2022 14:24:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667597076; cv=none;
        d=google.com; s=arc-20160816;
        b=wUPCaXvPou5VRrP3sKVNE6Iv61fQctEdz72lZ3kbwFeJtigLgyq6DhKNelCKlxGlTR
         wLLc/ksdlVbdQ5nvvJ7zWrqYbJeuhrTkifD1+zjnR44ZRdOT4kmm07FrXCxkytPdtczc
         bitLulIhEMFflor2W7m96VX65KyPFBdK99LkGM8teexkb6Nkr+/MqateNH0uFOWDDWf0
         Q1gg+imij7EiDcqDzPsz6UYicpCx/GFSAtDsp3HJYvILBVdRtgT3dIEwlXxP5Wpypj2L
         cj1+/LXisOtUVOJ3nliE2aZTxUo07EPP9xgX0Cg32p+naPw0Y2FiScsVEX2LHnTHAqgi
         gE1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:reply-to
         :dkim-signature;
        bh=CG1mlrDYCYVQ66+gGflTWD0vEgGOvioVVAQzm046g0w=;
        b=chUCNiOh9JET75naC1qBs0qHXC6ZXiGBuF5Ie6D/K6L2P5Qux1tZT8donxhdeGGddZ
         9a+6+MPFzafzpD296QQ6eJXlePI1IvbsLTdAgtybf/BTNy4xctLngmpIEBjIVsXT3XN0
         sltS9Ekq/qoRw1UAXjH+qEIAVqKedX9DF+X6yXEL/mbovB0D5X1dte+pYJCl/PlrgR9F
         2vso325pv7G6aWtEtVj0E5xG3i+mSK1+obcVcKwpQhKO3GLVhP/DIPmDkWzEFYWsS5qi
         /h8KYkYlzLE9AyXnff3ZP941J3fhC0FmR5oLO8CMhItVaXNtLhZf2nFveLhqiP+TeLq6
         wtig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ArHTBmvC;
       spf=pass (google.com: domain of 3e4nlywykcdae0w95y2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3E4NlYwYKCdAE0w95y2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bf6-20020a05690c028600b0036c251a1626si14158ywb.4.2022.11.04.14.24.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Nov 2022 14:24:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e4nlywykcdae0w95y2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id e13-20020a17090301cd00b001871e6f8714so4330653plh.14
        for <kasan-dev@googlegroups.com>; Fri, 04 Nov 2022 14:24:36 -0700 (PDT)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a17:902:f304:b0:182:2589:db21 with SMTP id
 c4-20020a170902f30400b001822589db21mr394567ple.151.1667597075466; Fri, 04 Nov
 2022 14:24:35 -0700 (PDT)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Fri,  4 Nov 2022 21:24:33 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221104212433.1339826-1-seanjc@google.com>
Subject: [PATCH] x86/mm: Populate KASAN shadow for per-CPU GDT mapping in CPU
 entry area
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski <luto@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: "H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, 
	syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Sean Christopherson <seanjc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ArHTBmvC;       spf=pass
 (google.com: domain of 3e4nlywykcdae0w95y2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3E4NlYwYKCdAE0w95y2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--seanjc.bounces.google.com;
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

Bounce through cea_map_percpu_pages() when setting protections for the
per-CPU GDT mapping so that KASAN populates a shadow for said mapping.
Failure to populate the shadow will result in a not-present #PF during
KASAN validation if the kernel performs a software lookup into the GDT.

The bug is most easily reproduced by doing a sigreturn with a garbage
CS in the sigcontext, e.g.

  int main(void)
  {
    struct sigcontext regs;

    syscall(__NR_mmap, 0x1ffff000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);
    syscall(__NR_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);
    syscall(__NR_mmap, 0x21000000ul, 0x1000ul, 0ul, 0x32ul, -1, 0ul);

    memset(&regs, 0, sizeof(regs));
    regs.cs = 0x1d0;
    syscall(__NR_rt_sigreturn);
    return 0;
  }

to coerce the kernel into doing a GDT lookup to compute CS.base when
reading the instruction bytes on the subsequent #GP to determine whether
or not the #GP is something the kernel should handle, e.g. to fixup UMIP
violations or to emulate CLI/STI for IOPL=3 applications.

  BUG: unable to handle page fault for address: fffffbc8379ace00
  #PF: supervisor read access in kernel mode
  #PF: error_code(0x0000) - not-present page
  PGD 16c03a067 P4D 16c03a067 PUD 15b990067 PMD 15b98f067 PTE 0
  Oops: 0000 [#1] PREEMPT SMP KASAN
  CPU: 3 PID: 851 Comm: r2 Not tainted 6.1.0-rc3-next-20221103+ #432
  Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 0.0.0 02/06/2015
  RIP: 0010:kasan_check_range+0xdf/0x190
  Call Trace:
   <TASK>
   get_desc+0xb0/0x1d0
   insn_get_seg_base+0x104/0x270
   insn_fetch_from_user+0x66/0x80
   fixup_umip_exception+0xb1/0x530
   exc_general_protection+0x181/0x210
   asm_exc_general_protection+0x22/0x30
  RIP: 0003:0x0
  Code: Unable to access opcode bytes at 0xffffffffffffffd6.
  RSP: 0003:0000000000000000 EFLAGS: 00000202
  RAX: 0000000000000000 RBX: 0000000000000000 RCX: 00000000000001d0
  RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
  RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
  R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
  R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
   </TASK>

Fixes: 9fd429c28073 ("x86/kasan: Map shadow for percpu pages on demand")
Reported-by: syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Sean Christopherson <seanjc@google.com>
---
 arch/x86/mm/cpu_entry_area.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/cpu_entry_area.c b/arch/x86/mm/cpu_entry_area.c
index dff9001e5e12..4a6440461c10 100644
--- a/arch/x86/mm/cpu_entry_area.c
+++ b/arch/x86/mm/cpu_entry_area.c
@@ -195,7 +195,7 @@ static void __init setup_cpu_entry_area(unsigned int cpu)
 	pgprot_t tss_prot = PAGE_KERNEL;
 #endif
 
-	cea_set_pte(&cea->gdt, get_cpu_gdt_paddr(cpu), gdt_prot);
+	cea_map_percpu_pages(&cea->gdt, get_cpu_gdt_rw(cpu), 1, gdt_prot);
 
 	cea_map_percpu_pages(&cea->entry_stack_page,
 			     per_cpu_ptr(&entry_stack_storage, cpu), 1,

base-commit: 81214a573d19ae2fa5b528286ba23cd1cb17feec
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221104212433.1339826-1-seanjc%40google.com.
