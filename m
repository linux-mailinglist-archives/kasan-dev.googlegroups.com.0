Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBAGBWWNQMGQE2M5WXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 28BBD624BEE
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 21:35:14 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id f19-20020a056a001ad300b0056dd07cebfcsf1568995pfv.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 12:35:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668112513; cv=pass;
        d=google.com; s=arc-20160816;
        b=kmvamLKZFuuW/eBx4o5PcoNTggnPx9u5ZCBURmrZWWfhhpuznD4xbzX2vhAhZBIt6Q
         pGPcU/5C1hm+jZg5+uq7gcZqh4ZJh7OW9yQEcda0/EtVLuvZmYpBjukb/Zat2ENOjpX3
         FCqnfdCYSPXWSkcHbyKB2+2uY9k4dMBBAehzr1sYeyUsO2TnfMeamcIqd6UGICFQu6y0
         8l04A9ZQVE1fQxM6lSEm2qGaoT2VMlTBdLP2npK1TQaTVYEsD8LgxN3D9wTXS124ktAC
         OesXSAjNiLYHkzpbdRterzV5EMPmCwmwW+h+h8pvx3cYZjh7fZtVdVdVE3c/qSS7Uo0q
         3zog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :references:mime-version:in-reply-to:date:reply-to:dkim-signature;
        bh=Z8Ls9FtdZdaFQUpaoShmc7D4UM0RgvQwwHX5rkuRaiA=;
        b=g1AMkuksukHPPLzTY1bXLJwCrsUH+fzpLMz0pY7uGWxTberMQ65MFclMuP/1JfcPIJ
         yAuFq3SgIDDx9ZBFFbJtf+QQqMtqJYN+649RrFpud5R2mcF9ylM/0ZjCmEDzmE/+jghZ
         /PHia0XEOSEGzNztjeOkDqo+5jZ7vt2cR61QeRFGm+nQxnCoSvNozJsBfzyjDLeSt9vH
         EVgEpWDI5F3h6ZfpwpxXPwF8nBAEPfE2/6maMoNpmz77x/JqWl6iJZThfnvSfd2MG3/8
         3swEmIdm2llk4lIQrLQ8yR2vIKmGbaPWKfiB2hsnHQojg4xgmdUw4h6CRlwWpCdeqVgr
         /Wqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qw3kbAB+;
       spf=pass (google.com: domain of 3f2btywykcrgg2yb704cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3f2BtYwYKCRgG2yB704CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:reply-to:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z8Ls9FtdZdaFQUpaoShmc7D4UM0RgvQwwHX5rkuRaiA=;
        b=hOBp+2zT04KNJp1LBz7/hOYk3iN9CymKSlVx93BtJ9lZcm/odS3v/qa95aIts18SCr
         wWofqBeCq38yhRr5V1ic7fJpXRaz1u8Z6B6uvKrivJakydhB9H0F59yOq1ZfMehwaJLO
         mjP/giyEqw/p4OyUcDRyOoVE9BAL0vESsqVDjR4aLEamQ2uTquw449NJWlBouEMbCKtf
         SnLKzWu/lBrflUtKvrmhllxxgFZiE4hs0BUfu7W/TXblzJO40LdvC681o5PT35Q/1HVd
         wTc2+/kcpvP1/BRJ4giO0CyAFtN3WE5HbmIekBz4RNQUowP+2XOc5UZ6VaA5heD0C0FU
         eMCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :reply-to:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z8Ls9FtdZdaFQUpaoShmc7D4UM0RgvQwwHX5rkuRaiA=;
        b=6C8tmyb/FVm38euxFDR2CnfyWI/O7GEbdbYcCBeYOMCmbKzSb0EuitAKMyrik1uDGp
         d8nVsdBYfVbnmQhEjZ0ZDNtuKI92GAGUtdAxytvm/kP5XcxZpAlOldazZdo74kdKjhsF
         vtS37rWIZxS0A3RoSBM6qYFtd61erbdwC/DcMUQbcDOTXNN6+CIzLM1qbwu96CuUd6vH
         YO63xtiiFwE31YFxeIkb0mXf5gN7itP5MazATB+nUp9r8yLVYiCebYrtPbGJKzLO90DB
         ca7TZg5NgoJa5/kIpKP0214AU1L/K1YuNEVoxDDATlSwlADVH+kbR60JtwADbV6CN4xW
         YOdw==
X-Gm-Message-State: ACrzQf22sX2VLA0LnkGe+JUpuPhmvyB5B/iPEFkxbPmOzAD6/axC3Uu+
	uQDHHIc3wwuAV4kgEvh2hpQ=
X-Google-Smtp-Source: AMsMyM54neWjg9qZ+cN+PpYgv3sZACPk8Q0jIfb47ui8O4gD/onZW6ndDsIOo7nGK0nsVbFzspAmoQ==
X-Received: by 2002:a17:902:f549:b0:186:fe2e:7eb0 with SMTP id h9-20020a170902f54900b00186fe2e7eb0mr1972123plf.55.1668112512717;
        Thu, 10 Nov 2022 12:35:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c5:0:b0:44f:1497:da26 with SMTP id 188-20020a6300c5000000b0044f1497da26ls1492515pga.6.-pod-prod-gmail;
 Thu, 10 Nov 2022 12:35:12 -0800 (PST)
X-Received: by 2002:a63:5119:0:b0:46f:be60:ad82 with SMTP id f25-20020a635119000000b0046fbe60ad82mr3306689pgb.34.1668112512024;
        Thu, 10 Nov 2022 12:35:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668112512; cv=none;
        d=google.com; s=arc-20160816;
        b=TWD/l3xMMh/k6C4UMIFUML6ErDHEZPSwHseWCrIVsXHBaOHs8TaZtqiYeEINEcKQEg
         ERnLKGFSuNCklZZJ81oNdveohxkWlQN95dy3yJoJqe84d29tQr2DdhyTH2Yvj/VoKpiH
         d1LyciJv394psvPv2knHQ0jE51dhwyajQJ+iqF4g+7s76SljQNhcdhNbgPZWBUCRH5Bu
         YUv/L5QGzFj/QhMvG+2cjH8QXVQu1jVWQ1uLyW0aLjUgARgjaQQH6KXiG2K5oL2esMAP
         HvloZmM5zHoG6e5erO0qOz2Nxoy6MCLfcmL3ZuzSczDlgvmm5N4SJaLHY/lkUaCHYGlc
         ehRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:reply-to:dkim-signature;
        bh=XS7y2dqHGNcxgJtQwV0riGq39Rt6nVME96ygRYhND24=;
        b=zyUOiFf3mju5DIYdsAO0LrF8YLztCFGdaB3uFaz7skB0gB1H658Fzi4RllrfooGht/
         kkS2W7BYkOmppuX+YxnuguGVG/IZQ89KUWZMt4iR1qYPK+N0njEforaKuwhrbxqIB37Z
         PizxC7VqcuQqwX/4aK1OX5E5lKXFzjdRfO30670otkKmc573eAZ127NQnG81evyj0U4X
         hoQlIG2Bi8DmWl6xMFhDQdqj2LCfBtNCuX79jry8Y0/RdEiH4N/qFujmFpxUGN1hh6xG
         hbhTzpeMh4e9PFEHYHYbSC+QUT33S/MBcEYchK5fu9PnFAeOyYExXKd+CHetA4YC8IMM
         ne/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qw3kbAB+;
       spf=pass (google.com: domain of 3f2btywykcrgg2yb704cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3f2BtYwYKCRgG2yB704CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id lj12-20020a17090b344c00b0021296f4cff5si297541pjb.3.2022.11.10.12.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Nov 2022 12:35:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3f2btywykcrgg2yb704cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id k71-20020a63844a000000b004701e90da0dso1514682pgd.22
        for <kasan-dev@googlegroups.com>; Thu, 10 Nov 2022 12:35:12 -0800 (PST)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a17:90a:7523:b0:213:8a69:c502 with SMTP id
 q32-20020a17090a752300b002138a69c502mr67876165pjk.153.1668112511765; Thu, 10
 Nov 2022 12:35:11 -0800 (PST)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Thu, 10 Nov 2022 20:35:02 +0000
In-Reply-To: <20221110203504.1985010-1-seanjc@google.com>
Mime-Version: 1.0
References: <20221110203504.1985010-1-seanjc@google.com>
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221110203504.1985010-4-seanjc@google.com>
Subject: [PATCH v2 3/5] x86/kasan: Rename local CPU_ENTRY_AREA variables to
 shorten names
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
 header.i=@google.com header.s=20210112 header.b=Qw3kbAB+;       spf=pass
 (google.com: domain of 3f2btywykcrgg2yb704cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3f2BtYwYKCRgG2yB704CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--seanjc.bounces.google.com;
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

Rename the CPU entry area variables in kasan_init() to shorten their
names, a future fix will reference the beginning of the per-CPU portion
of the CPU entry area, and shadow_cpu_entry_per_cpu_begin is a bit much.

No functional change intended.

Signed-off-by: Sean Christopherson <seanjc@google.com>
---
 arch/x86/mm/kasan_init_64.c | 22 +++++++++++-----------
 1 file changed, 11 insertions(+), 11 deletions(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index d1416926ad52..ad7872ae10ed 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -331,7 +331,7 @@ void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid)
 void __init kasan_init(void)
 {
 	int i;
-	void *shadow_cpu_entry_begin, *shadow_cpu_entry_end;
+	void *shadow_cea_begin, *shadow_cea_end;
 
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
@@ -372,16 +372,16 @@ void __init kasan_init(void)
 		map_range(&pfn_mapped[i]);
 	}
 
-	shadow_cpu_entry_begin = (void *)CPU_ENTRY_AREA_BASE;
-	shadow_cpu_entry_begin = kasan_mem_to_shadow(shadow_cpu_entry_begin);
-	shadow_cpu_entry_begin = (void *)round_down(
-			(unsigned long)shadow_cpu_entry_begin, PAGE_SIZE);
+	shadow_cea_begin = (void *)CPU_ENTRY_AREA_BASE;
+	shadow_cea_begin = kasan_mem_to_shadow(shadow_cea_begin);
+	shadow_cea_begin = (void *)round_down(
+			(unsigned long)shadow_cea_begin, PAGE_SIZE);
 
-	shadow_cpu_entry_end = (void *)(CPU_ENTRY_AREA_BASE +
+	shadow_cea_end = (void *)(CPU_ENTRY_AREA_BASE +
 					CPU_ENTRY_AREA_MAP_SIZE);
-	shadow_cpu_entry_end = kasan_mem_to_shadow(shadow_cpu_entry_end);
-	shadow_cpu_entry_end = (void *)round_up(
-			(unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
+	shadow_cea_end = kasan_mem_to_shadow(shadow_cea_end);
+	shadow_cea_end = (void *)round_up(
+			(unsigned long)shadow_cea_end, PAGE_SIZE);
 
 	kasan_populate_early_shadow(
 		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
@@ -403,9 +403,9 @@ void __init kasan_init(void)
 
 	kasan_populate_early_shadow(
 		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
-		shadow_cpu_entry_begin);
+		shadow_cea_begin);
 
-	kasan_populate_early_shadow(shadow_cpu_entry_end,
+	kasan_populate_early_shadow(shadow_cea_end,
 			kasan_mem_to_shadow((void *)__START_KERNEL_map));
 
 	kasan_populate_shadow((unsigned long)kasan_mem_to_shadow(_stext),
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221110203504.1985010-4-seanjc%40google.com.
