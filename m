Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBBGBWWNQMGQESYXW5KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EEED624BF2
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 21:35:17 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id bj1-20020a05620a190100b006fa12a05188sf3072041qkb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 12:35:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668112516; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMF862yAZRrVabdSUj6sWW/fm84o5wsU4MZTV+w4DKo+Z2eU9A1OEzEB+sCgXdqTBf
         ZRbCVHjgxG8TUjYMM8pIjTgQlGADXAAlg23yBukIitMiJ1QsHcVXHseGiBemkzBuN77m
         vEBfa5VkojWrqjQm6F9N0RL2viTJtxXRe3GqdRACZwZ2/WxQCGOLdWXqKP2JC/fkqcPJ
         b/QRI56hUIno0x8uuXa8WcT9Uy/AkREkkGGvF1eKly7n3bKlXsT/biNCKjxhQa69HX6O
         pJGRfTbgIcxitjaiBvUYYd6LF+O/EU1vXN73wcRPMrLcunsSinhp4QpB+yTCqvMuTrgg
         OJhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :references:mime-version:in-reply-to:date:reply-to:dkim-signature;
        bh=01xO8jinTim41QBAzTDZKhlpCxtwOXA3eujpfJUFBxo=;
        b=mapJpujaTn8J21627TYbt4mMKYvrx3gKwceqBpihkfODoA8zZ7KvGfTuIx1cvrAyEw
         7B/QlafswQdE+l8rSt/DeoXtXyzp4DrOUECATRFVnsAy3qcpjmGDxRJFfqrZvJFVw6Bm
         bFSToABnw3cc5Wo3L4auAU5Im/1/wpTNe+k5uXK6lPNtWF9ZBGFr2oB3iVSAYaYlLIre
         65yQNU/+UiIN5F+PFh5FI9uwPfWBGHos4euTeTy4TJDIaPJRXwH8jmvvWpEnKPkRAmk3
         jXeIoaJvXEUv65+yHAw98Vh5hUjUZCjJrDWd3SBY4guynwVz3JuwDk7lyVTCpXWN0I9L
         Lm+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="F/+UCskf";
       spf=pass (google.com: domain of 3g2btywykcrwk62fb48gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3g2BtYwYKCRwK62FB48GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:reply-to:from:to:cc:subject:date
         :message-id:reply-to;
        bh=01xO8jinTim41QBAzTDZKhlpCxtwOXA3eujpfJUFBxo=;
        b=O9t8vTD/Enx/yRadkA3Sz789g4l28z4GRrUmYd1/9CWPXMyNmyM7DbkIReXlwdfehE
         jaBBYNjuOkzbkd1RMzj5RLLNTAtM7k+kUuKXgp5WSGNt50u2UxdWPb3fw2nHmz/SkqiW
         y0GOJIbnXXO6wVITTgdEWzNlc58VGyzDvNFbHIPRD32rOZ1uv7mgTLy4uTP+ny4g/czn
         xC2cgdVV5kS1Dj6IrR80T1d36ullsKkzbnf9/YlUpCOZlbGUmGUYde2KPAOj4sIKIuGI
         ZpIDC9gJ74eYrFel4lGv6Q5s9CnVDnm5cArZ8sQe1NKckI2O0xyjBm9rEAaETwK4xzTb
         YVpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :reply-to:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=01xO8jinTim41QBAzTDZKhlpCxtwOXA3eujpfJUFBxo=;
        b=Rw4Vt2CIplxiD6NSmogPVkrsiCAKJtKy45l3jPhNCaIn5sDsIE+nGwr29SBKgcl1Qe
         oPhnzLW5wSueQtB4QCTdAGaWTodYfRs2KL5XgvlcjOrm4mJBtVSsVgDXTUj9RFZYisP8
         c5h8hHFjdsF5ev1IwhriiA7Z0GM0TMgqvk2mTlqfP/Kj7hGqOydULFYGJKym3QlK1bu/
         llv7nRorGPv1rNLxD+oQEBQBC3wlx2Xa1qe8bPevJF7+VVbyB7yJuDZqosQinrqPkV8T
         IdSeKrIGljVUwAsDqrx14eppKgL9o2oDC4HRWEBcsgAb3GfAoA4XxnwgJmY97heqyNrE
         3lLQ==
X-Gm-Message-State: ACrzQf25buIhG+0Mt2XaJpeMKZpqQvYp+CpzYlIcFcQdHe/tOKIptF0l
	bU02sOruxchU+FkKihApYxQ=
X-Google-Smtp-Source: AMsMyM7ULBmxD5JCnOYSfJV3VjjJVdVnPSc5XkiUp2/zdzRyEI2fhtIpZMPYacS/b90++GVILhQ5Bg==
X-Received: by 2002:ac8:5484:0:b0:3a5:264a:e6a1 with SMTP id h4-20020ac85484000000b003a5264ae6a1mr1781401qtq.336.1668112516541;
        Thu, 10 Nov 2022 12:35:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9c0c:0:b0:4af:62fc:6f1 with SMTP id v12-20020a0c9c0c000000b004af62fc06f1ls1616163qve.0.-pod-prod-gmail;
 Thu, 10 Nov 2022 12:35:16 -0800 (PST)
X-Received: by 2002:a05:6214:5b05:b0:4b3:d088:c1bf with SMTP id ma5-20020a0562145b0500b004b3d088c1bfmr1865470qvb.52.1668112516018;
        Thu, 10 Nov 2022 12:35:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668112516; cv=none;
        d=google.com; s=arc-20160816;
        b=W/pmzQcSzG3msWQzJ/dcaY5OWn2qPFykX4BaJw6FoI9vJoTXLcpqjUL+ktdpQEP7ew
         hGC34XjgX+FKxaw+ye0KYrK2IOy0Y/KsCuaOFF0vR2pnUAv4w/JgmmEAWypjmH5NoScM
         FlRhrx9CN3PnyMc85Eh19hzDxJnOKIUzYXUZ2UiO8h5fEXHMLO78XkLV+wtJr92wrYjL
         dwOdvMma7jfByrd/+tGzYec/Oa0ft+wedVP8bLNnYDx7ry/zgPY5wx0lWx+44kPHhrr2
         19I84q+w0wWHRvkDEBTnPuPr2few72rcGq/Wxv3xHaLKitJWW5ntuDRffTd3ICzOFfXx
         n+Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:reply-to:dkim-signature;
        bh=u6Cw0ZmfOshKtE4Fs73s8CsSsDU0YsFyudltt9Q+W64=;
        b=K4IjZ2BCzcV/bHyORSzfuxiiU5hP9q5w5zIgjtQPMFNJSbuKqlwAXw9bjyftLvyHHV
         Gc5J3sg8PjIaJK3YXcQ88tonllrPdc/A9OlX+/iKyem36Ast/C+XTZWKTJxsAf/y6T/Y
         ASmhSc5UbIpAPxo8YbnTYvMWSyu7y64s69dxe5EzPr3ObYrhb7Iu4sz5H/eK6fZ11vMh
         VU7EXF8J4jrSaJwVqC76tZ0E0/2a7SIDpQxGlhJVBzrNHw9lsFtaIksbqMjXNVRC+Gnf
         tTGxhJ4+s59c3Spjwxo1/kVLbgBMS6ZG2Fl3D2eOvIZrbzgkFUix6Ha3axRwcrZDhCl1
         fq9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="F/+UCskf";
       spf=pass (google.com: domain of 3g2btywykcrwk62fb48gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3g2BtYwYKCRwK62FB48GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x64a.google.com (mail-pl1-x64a.google.com. [2607:f8b0:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id k22-20020ae9f116000000b006fa4d3828a3si17268qkg.2.2022.11.10.12.35.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Nov 2022 12:35:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3g2btywykcrwk62fb48gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) client-ip=2607:f8b0:4864:20::64a;
Received: by mail-pl1-x64a.google.com with SMTP id t3-20020a170902e84300b00186ab03043dso2075990plg.20
        for <kasan-dev@googlegroups.com>; Thu, 10 Nov 2022 12:35:15 -0800 (PST)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a62:1595:0:b0:566:9f68:c0ad with SMTP id
 143-20020a621595000000b005669f68c0admr3437397pfv.57.1668112515250; Thu, 10
 Nov 2022 12:35:15 -0800 (PST)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Thu, 10 Nov 2022 20:35:04 +0000
In-Reply-To: <20221110203504.1985010-1-seanjc@google.com>
Mime-Version: 1.0
References: <20221110203504.1985010-1-seanjc@google.com>
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221110203504.1985010-6-seanjc@google.com>
Subject: [PATCH v2 5/5] x86/kasan: Populate shadow for shared chunk of the CPU
 entry area
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
 header.i=@google.com header.s=20210112 header.b="F/+UCskf";       spf=pass
 (google.com: domain of 3g2btywykcrwk62fb48gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3g2BtYwYKCRwK62FB48GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--seanjc.bounces.google.com;
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
index afc5e129ca7b..af82046348a0 100644
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
+	kasan_populate_early_shadow((void *)shadow_cea_begin,
+				    (void *)shadow_cea_per_cpu_begin);
+
 	kasan_populate_early_shadow((void *)shadow_cea_end,
 			kasan_mem_to_shadow((void *)__START_KERNEL_map));
 
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221110203504.1985010-6-seanjc%40google.com.
