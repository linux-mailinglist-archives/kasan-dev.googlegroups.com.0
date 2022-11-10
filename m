Return-Path: <kasan-dev+bncBCAIHYNQQ4IRB76AWWNQMGQE4GTSAGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id CA29D624BEC
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 21:35:12 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id k11-20020aa792cb000000b00558674e8e7fsf1565778pfa.6
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 12:35:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668112511; cv=pass;
        d=google.com; s=arc-20160816;
        b=kN2IiYcTBczOgosd51br0eMCdP2AES/egCfKLFgP48uj25lcjLtwxuabPnxtyYP/qI
         lXGDpoBZR1Ybk/bkN6XZ0skjlynemmwuVerXcQYDaNQTjJk+lbgBVDNu+FmBSWcqMdio
         FoCDtYa9y4lM21c6+yn5iwxkiIzq+RSy2fGIODLLYlnOENwmgnVZKfR2P/E6JAnffpHg
         mE4XKsjCYSFSmPlnxh+HalSMwCni2F0fIHAml7sFbCXB2OZur6RKIZ744aKUAO75/zlg
         1wslpLETBBR0gCDyW1npmtSULWWlVsrcz3QN3bvlIKOMMSpvPuGheokekEviOrdsCsMH
         DjrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :references:mime-version:in-reply-to:date:reply-to:dkim-signature;
        bh=9EUo0WqfD1EPMMGFQGLcaDWyyVUWv1XK5tpqesQzcR0=;
        b=NRdjmCrQPpwLkdEPC4L/UfW+67RhMzlWHARZaik9TZYvSa4+c6j2/rQDHAayrLhKbS
         7SyvVZsPfBCFv/Wa+LUt3lcuHra4RyhBbddBdcg+jO1kvikNe9bZomDkG53E8hLzvsee
         ZmiKuFZIyKLqkwnV5SP6PdK3KIsRpRJgolD+05fYjse4RXLLgJyaLah4q0CkvzW6UPHC
         CTlCTjYzxRChajx2iwH4H30vPwedvQfKZid6BBhuPxRNp3IcQCb00pYAf1QvAdU9PRu9
         5qjn85Yx9mCYEcuLVVTIeFeTe9YLSbgHztbi2saZvKJwrqgl1rpQD/l46dtsrBLjcoFm
         dWNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pY2zGdbH;
       spf=pass (google.com: domain of 3fmbtywykcrcf1xa6z3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3fmBtYwYKCRcF1xA6z3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:reply-to:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9EUo0WqfD1EPMMGFQGLcaDWyyVUWv1XK5tpqesQzcR0=;
        b=fFnM9w2dyRhJkW8ysS1kvB/9JOvQqNnxdeSmS6Wkc1YSa/+rzW5ozWUa/TjCFF+247
         CrgFNXY6rJqxGmad+XYEVNAqKO6VFlTG6KCiFYmcFB56n9AVm6UcZatxAnBpRCzRtG3D
         Ys1aSpvJuoVsYLyZRyIDHJ+TlAitvZUYJlKl/AFNQU4iWS3I2ZmvOlE8woqPTubGGWN2
         Gb0dRgsFBEmsdxQr7uzK/XO8vdB6cS3UwXPYgQkp/nb+Jq5vrng/tBLUHYKnJxWAc0XC
         mP+DN+mRBlFUp0LIrz8HVd/0s0OesdXGyVoF7S8o+hZumQLJcw9rBigKJ2cRc4fwVkRY
         +HfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :reply-to:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9EUo0WqfD1EPMMGFQGLcaDWyyVUWv1XK5tpqesQzcR0=;
        b=QwqztFZHeO4bTXdcXtCup/xBa4Hh3RIaZuYw753JJZKyzg0nulXrEK6dT5YN+jknZ6
         cxKhxj0uznk1HsaqBWCbHSUBs1vEMrSRlCxcx7JBH6pz7g1Cp/esmw85KTe+th888IgL
         8BdYq+k1l5i5bToEHklJI4qfSrJeSORb2+iqVVE0QFOBARSpfqkaN6Sf71pR44Bgvk2M
         6BTtjItOJI94fWR1j21Y9lHTOCwcctyD7mVCg5Fn042qshpU0DCux73GMxTVkX6DsQLL
         BxHQS/Ueb0BLd4FhhXMgZUZbGcgv9zV96UuzXmP+k14SOcGnrvgndUCA2DJuV+1/+ISn
         LM3w==
X-Gm-Message-State: ACrzQf3H5kzmNfrXvo5CGUlGYj8eUQkhr4/1SX3tNfalgsEj5V8C+b/H
	OzcOs425sD+zVMMXGuV6nfc=
X-Google-Smtp-Source: AMsMyM7rVP2YmI6geK/7icP6v8lhaTpSr7owsKWmWx0YO/t880ri5uVbYdSJmQKZKV5h/L+ckyiOJw==
X-Received: by 2002:a17:902:ecd1:b0:187:2712:d033 with SMTP id a17-20020a170902ecd100b001872712d033mr54983515plh.56.1668112511289;
        Thu, 10 Nov 2022 12:35:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1b2a:b0:214:246b:918a with SMTP id
 q39-20020a17090a1b2a00b00214246b918als4353797pjq.2.-pod-canary-gmail; Thu, 10
 Nov 2022 12:35:10 -0800 (PST)
X-Received: by 2002:a17:902:ed92:b0:186:9905:11c6 with SMTP id e18-20020a170902ed9200b00186990511c6mr1976536plj.114.1668112510535;
        Thu, 10 Nov 2022 12:35:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668112510; cv=none;
        d=google.com; s=arc-20160816;
        b=agMgxpEthd/XLAtAGWO78mLTf4TY26awksYSihoBsbZUGa5ST4wxXHcqhmbgQYCQky
         ElLOUokD/yAYe9AbvsmvShfzz4nJRZuaj+bjh7qInhlNMjIBvJa+1qK+o+pY6VaCcIyS
         8Wvaph/iQo6zTImKh8VxVZ7i5RXiacyTvTOt20za8uJ4UuvyvoAh0m+bRMXdKjlbCk1y
         QxEj96QcjT3hTf7z2E6cvpA3fyOu8VgCd2AKUA25Jny+aRSp/uO5yN3yKxYsIV9ESlu3
         zIiJZX1Lw/2xONhvBskY8Eoj4A4LKbQidH1cH6Ew8N3FIuBwe8C3DnBB/AyzNttEgw6O
         CcHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:reply-to:dkim-signature;
        bh=Q9x7ezoTY10MerxwSgds+z/5z/6k15MGNtHnWLn8Ah8=;
        b=V5VAgZ+5qC3ctuJ497aWpL1zLPvJ7DjJbny82q4QrV7g3zA2Bejd2zM5K9vO2bToXo
         lce+7cenMAGS/a/36CSxXvv26LGW0L/8vx2RrlT7vfg8MAaV2NJFOGr68s3XDN6FgXbT
         6hHjm40Fe0/zVHBoCGre23Aqrg04+gpgrEhKVVr+S3Qltt8l0QqlYRYGHNqbaBlAC3OH
         YK4tft48VMM7Srlmt5JlDRdNWv9dmUdW71Mxv7i9HkULFkiOM+2kYTzslNtmmhBwbmhe
         PT/leN4Ie8CRTaW8Z8UIkeNGMbvlR9FlKo+XW4Yh1TG8AfXS8Pr5mq8LRghflwJ/IiQN
         TaJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pY2zGdbH;
       spf=pass (google.com: domain of 3fmbtywykcrcf1xa6z3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3fmBtYwYKCRcF1xA6z3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id s3-20020a170902a50300b00186c372722csi11535plq.9.2022.11.10.12.35.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Nov 2022 12:35:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fmbtywykcrcf1xa6z3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id c10-20020a17090aa60a00b00212e91df6acso1627524pjq.5
        for <kasan-dev@googlegroups.com>; Thu, 10 Nov 2022 12:35:10 -0800 (PST)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a17:902:d510:b0:186:61a7:ae94 with SMTP id
 b16-20020a170902d51000b0018661a7ae94mr1897055plg.2.1668112510143; Thu, 10 Nov
 2022 12:35:10 -0800 (PST)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Thu, 10 Nov 2022 20:35:01 +0000
In-Reply-To: <20221110203504.1985010-1-seanjc@google.com>
Mime-Version: 1.0
References: <20221110203504.1985010-1-seanjc@google.com>
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221110203504.1985010-3-seanjc@google.com>
Subject: [PATCH v2 2/5] x86/mm: Populate KASAN shadow for entire per-CPU range
 of CPU entry area
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski <luto@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: "H. Peter Anvin" <hpa@zytor.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Sean Christopherson <seanjc@google.com>, 
	syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com, 
	syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pY2zGdbH;       spf=pass
 (google.com: domain of 3fmbtywykcrcf1xa6z3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3fmBtYwYKCRcF1xA6z3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--seanjc.bounces.google.com;
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

Populate a KASAN shadow for the entire possible per-CPU range of the CPU
entry area instead of requiring that each individual chunk map a shadow.
Mapping shadows individually is error prone, e.g. the per-CPU GDT mapping
was left behind, which can lead to not-present page faults during KASAN
validation if the kernel performs a software lookup into the GDT.  The DS
buffer is also likely affected.

The motivation for mapping the per-CPU areas on-demand was to avoid
mapping the entire 512GiB range that's reserved for the CPU entry area,
shaving a few bytes by not creating shadows for potentially unused memory
was not a goal.

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
Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Sean Christopherson <seanjc@google.com>
---
 arch/x86/mm/cpu_entry_area.c | 8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

diff --git a/arch/x86/mm/cpu_entry_area.c b/arch/x86/mm/cpu_entry_area.c
index d831aae94b41..7c855dffcdc2 100644
--- a/arch/x86/mm/cpu_entry_area.c
+++ b/arch/x86/mm/cpu_entry_area.c
@@ -91,11 +91,6 @@ void cea_set_pte(void *cea_vaddr, phys_addr_t pa, pgprot_t flags)
 static void __init
 cea_map_percpu_pages(void *cea_vaddr, void *ptr, int pages, pgprot_t prot)
 {
-	phys_addr_t pa = per_cpu_ptr_to_phys(ptr);
-
-	kasan_populate_shadow_for_vaddr(cea_vaddr, pages * PAGE_SIZE,
-					early_pfn_to_nid(PFN_DOWN(pa)));
-
 	for ( ; pages; pages--, cea_vaddr+= PAGE_SIZE, ptr += PAGE_SIZE)
 		cea_set_pte(cea_vaddr, per_cpu_ptr_to_phys(ptr), prot);
 }
@@ -195,6 +190,9 @@ static void __init setup_cpu_entry_area(unsigned int cpu)
 	pgprot_t tss_prot = PAGE_KERNEL;
 #endif
 
+	kasan_populate_shadow_for_vaddr(cea, CPU_ENTRY_AREA_SIZE,
+					early_cpu_to_node(cpu));
+
 	cea_set_pte(&cea->gdt, get_cpu_gdt_paddr(cpu), gdt_prot);
 
 	cea_map_percpu_pages(&cea->entry_stack_page,
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221110203504.1985010-3-seanjc%40google.com.
