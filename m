Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBWFVSWNQMGQEAALSABI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id DF048619FFB
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 19:32:57 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id t11-20020a9d590b000000b00655fad88dacsf2332563oth.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 11:32:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667586776; cv=pass;
        d=google.com; s=arc-20160816;
        b=oxboQpE8tAhMAw9sHylks1yCcuvafXyMJJcCjLJofpP2n+raCuIzRTarM+aXYVZmd3
         z20NIUtUPMUNW7RJdGU3JsGNIUVibe4OslvYyEo6bZyOjxipWPIOyfwN55g1xynpHALD
         nJ0AO13aoYDYgZkncUzntAL/X3d3R6Quy4FNuhDPK7GNknIalR6Gs7aWJr9liv+PSMPk
         pX4LEIGBkJjDIIs+Rg3uVbm4bzExLutOimV6kLh0EP+0By4IJiLxnhPrZUr5zsRnar57
         WK3fgrQ+70++J8uygqErjpnpOXQdYdW7/jv6n8w8qZ64kWRvknFtiWX/2ogNm/MNFKU2
         Pjig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :references:mime-version:in-reply-to:date:reply-to:dkim-signature;
        bh=cJtjCjrhE+dJNDEs3Z3RY0va3nvWZUd7xat2tScXZ/E=;
        b=F5GtLpQ0J6eNGcx5V45/NH+hBDRiHP53LCKrfxgcs7CITLgaGUoj9Uj/CqVrGiaL60
         +PyA9499AGWkhq4YcLY2SJUu0R1DAOdLFCf/n2qkK+SxZNiVzJvMmivxW7fk1UJzeI7c
         heX0IJubpnlB5yBqCZiYJtoVOByd4oyi0xrH7MxxeF095NYnxikEWfg4w0M/HG/KAK2X
         Y+zRMwDjK7Rh3jhJk6JhdWxLJA9fxEOprNCBxcYvPqyAA95el58KrbavF83ngkxzPiUP
         ZIjbdVQwxiTq7QkIo1g1HFvKtJ5MVGDdR/W1+uZQzf190azymzyA5TTBdxlZBxgPfEXN
         BsMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AVNcRZuD;
       spf=pass (google.com: domain of 311plywykcuqykgtpimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=311plYwYKCUQykgtpimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:reply-to:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cJtjCjrhE+dJNDEs3Z3RY0va3nvWZUd7xat2tScXZ/E=;
        b=sMiRY7QOgkLP6OHfL8fRvHLbkq11/c4ZBQnraL/yhyASYiLjDzd31ugmSzs4qJg/B+
         3gPiCAIywmmwiZN8jTN3Dm1WRozKs8jHWxZ2GDV7J6+6l4KXDpsGuWWZSNtwdRwCsbAE
         Aa/EjOOMpJNhPg1GrtONvd7U+lqKs/rPQS7AfmxoZBtk1oVfF9ur7HtFV2CqqeLr/nz1
         9WpM7dzT5raJPr4CyRPJiEmkajn4lzFVD9RC6JHrNlQWle4rR5fLn7urHm1pK9UIdvAV
         LBYPovK+26XsovQT9oyW5GKXIPjxdh4fOmokdtgb1nLWzMorKAv0u7T478r3W6UVX2V1
         FT+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :reply-to:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cJtjCjrhE+dJNDEs3Z3RY0va3nvWZUd7xat2tScXZ/E=;
        b=i/Nv8XmHGaWEltXV5Q1+K8vcHl5ScI/+QCxYu3tfojlvFo2tS0YzUW/fX48F03GCCX
         0sqmg5ffsjmca+s/1LONqldjzYAp5TeXCWHexgqxVQf0+/HZOxcxP9cCEhhJdIK8/cAb
         xGtCVqxU9j2PmbtVI4H6P7ty4HrhZywXIHe2zJhU0gomMzv0sgB/2woFf0Un8HRsNJS8
         DTXdf/maajrpZJYJmmip2A7jTdN54Xw0hWl314zarmBv9lTfYOUspW9VXK0862Kkpj7U
         tXDQ504+Bx2Xo0YlHA/LMDA8ZSaN2fIe0/UW+ApdWjxjlo2icBHRvAfe39yHp+grtEok
         MZSw==
X-Gm-Message-State: ACrzQf2Q2lthJ1tTw0LRq7TNn62LbKGsmFN769wEZtiTFKuHWz0zMLLc
	4WyetOitmZOudKo9A6D3zwc=
X-Google-Smtp-Source: AMsMyM4y4Qk5I65ai5Wmr5QIsQWKi8oHp5UaoCGumGrJGhUGXtPcy9PkTI9IfriQMnqHiKO0WTF0AA==
X-Received: by 2002:a9d:5d10:0:b0:661:1106:6cee with SMTP id b16-20020a9d5d10000000b0066111066ceemr18515514oti.362.1667586776421;
        Fri, 04 Nov 2022 11:32:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:56f:b0:354:d7cd:c5e5 with SMTP id
 j15-20020a056808056f00b00354d7cdc5e5ls1728860oig.3.-pod-prod-gmail; Fri, 04
 Nov 2022 11:32:56 -0700 (PDT)
X-Received: by 2002:a05:6808:1a14:b0:355:15ed:47e5 with SMTP id bk20-20020a0568081a1400b0035515ed47e5mr19402798oib.76.1667586776026;
        Fri, 04 Nov 2022 11:32:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667586776; cv=none;
        d=google.com; s=arc-20160816;
        b=r8b07nWeyyjYOAUqg53f1bSAv985uqyggGnoEuiY+dCN+85NA1yQ6I73ZOO7Zx1uSx
         FY67EsRleWv0ojUHxuO4v7MGuM5MAMchF9Fdmpbrw1zKHyp3yoHNv+vcklV6Lz7/2I4s
         +unhAFKgdpguZXjCpv2qlaYCJ6eFVh0k50H0nAmRFH5fgJq3ugIefGvr5/rrP2HVcbh6
         IgUAkpWE9PSfktWvvo6MT2P0aLslnIDsRlNGZWBApHyqJy7/Rli36xyeEaZ+y47Z6VKs
         49qS6fj8IRimkSckhwWV//GlNkX/M0ezTehQbj18sBXGBn8VCNt6wyRePFEh/a6J2R57
         mHwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:reply-to:dkim-signature;
        bh=NyjCQLTGMZRdycUacwFyAxLckz0Mzvzm9v3NS3Lsp2Q=;
        b=N7HDhwUmoX77YJ/mCTk6VzBVjYzI7YqqPdyvNS9nfEF66C95EVCgnfAuIGUx/GX2AQ
         ai1z0nKcFV7ramctQphdvnuLykfU3QN7/MTtHpU0hB2elIKqcPpsJGO4i80tK1UiPK0n
         K5ltkWPIl2UqjXI5cnepH4nH+3d5hi54lPipxLVEKEg5dAM9hk/jAxeUhiBXuH13FcnM
         d4AqOWV0EDIBeiasLxagBFAW0AWWNOpmwsqWAiiCrD4js0vllCOFPBA4oY4H84CWZ0Zh
         oAP94toJ/G7AnHJgsF4V2l7jCWzsES9jWqlvd9d0DJbB63s/GctEFTxN035ZHSKYvjdD
         r/uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AVNcRZuD;
       spf=pass (google.com: domain of 311plywykcuqykgtpimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=311plYwYKCUQykgtpimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 106-20020a9d0873000000b0066c2e89a82bsi3835oty.1.2022.11.04.11.32.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Nov 2022 11:32:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 311plywykcuqykgtpimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id k131-20020a628489000000b0056b3e1a9629so2803429pfd.8
        for <kasan-dev@googlegroups.com>; Fri, 04 Nov 2022 11:32:55 -0700 (PDT)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a62:79d4:0:b0:561:f3bb:878 with SMTP id
 u203-20020a6279d4000000b00561f3bb0878mr366882pfc.83.1667586775330; Fri, 04
 Nov 2022 11:32:55 -0700 (PDT)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Fri,  4 Nov 2022 18:32:46 +0000
In-Reply-To: <20221104183247.834988-1-seanjc@google.com>
Mime-Version: 1.0
References: <20221104183247.834988-1-seanjc@google.com>
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221104183247.834988-3-seanjc@google.com>
Subject: [PATCH 2/3] x86/kasan: Add helpers to align shadow addresses up and down
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
 header.i=@google.com header.s=20210112 header.b=AVNcRZuD;       spf=pass
 (google.com: domain of 311plywykcuqykgtpimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=311plYwYKCUQykgtpimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--seanjc.bounces.google.com;
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

Add helpers to dedup code for aligning shadow address up/down to page
boundaries when translating an address to its shadow.

No functional change intended.

Signed-off-by: Sean Christopherson <seanjc@google.com>
---
 arch/x86/mm/kasan_init_64.c | 40 ++++++++++++++++++++-----------------
 1 file changed, 22 insertions(+), 18 deletions(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index ad7872ae10ed..afc5e129ca7b 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -316,22 +316,33 @@ void __init kasan_early_init(void)
 	kasan_map_early_shadow(init_top_pgt);
 }
 
+static unsigned long kasan_mem_to_shadow_align_down(unsigned long va)
+{
+	unsigned long shadow = (unsigned long)kasan_mem_to_shadow((void *)va);
+
+	return round_down(shadow, PAGE_SIZE);
+}
+
+static unsigned long kasan_mem_to_shadow_align_up(unsigned long va)
+{
+	unsigned long shadow = (unsigned long)kasan_mem_to_shadow((void *)va);
+
+	return round_up(shadow, PAGE_SIZE);
+}
+
 void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid)
 {
 	unsigned long shadow_start, shadow_end;
 
-	shadow_start = (unsigned long)kasan_mem_to_shadow(va);
-	shadow_start = round_down(shadow_start, PAGE_SIZE);
-	shadow_end = (unsigned long)kasan_mem_to_shadow(va + size);
-	shadow_end = round_up(shadow_end, PAGE_SIZE);
-
+	shadow_start = kasan_mem_to_shadow_align_down((unsigned long)va);
+	shadow_end = kasan_mem_to_shadow_align_up((unsigned long)va + size);
 	kasan_populate_shadow(shadow_start, shadow_end, nid);
 }
 
 void __init kasan_init(void)
 {
+	unsigned long shadow_cea_begin, shadow_cea_end;
 	int i;
-	void *shadow_cea_begin, *shadow_cea_end;
 
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
@@ -372,16 +383,9 @@ void __init kasan_init(void)
 		map_range(&pfn_mapped[i]);
 	}
 
-	shadow_cea_begin = (void *)CPU_ENTRY_AREA_BASE;
-	shadow_cea_begin = kasan_mem_to_shadow(shadow_cea_begin);
-	shadow_cea_begin = (void *)round_down(
-			(unsigned long)shadow_cea_begin, PAGE_SIZE);
-
-	shadow_cea_end = (void *)(CPU_ENTRY_AREA_BASE +
-					CPU_ENTRY_AREA_MAP_SIZE);
-	shadow_cea_end = kasan_mem_to_shadow(shadow_cea_end);
-	shadow_cea_end = (void *)round_up(
-			(unsigned long)shadow_cea_end, PAGE_SIZE);
+	shadow_cea_begin = kasan_mem_to_shadow_align_down(CPU_ENTRY_AREA_BASE);
+	shadow_cea_end = kasan_mem_to_shadow_align_up(CPU_ENTRY_AREA_BASE +
+						      CPU_ENTRY_AREA_MAP_SIZE);
 
 	kasan_populate_early_shadow(
 		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
@@ -403,9 +407,9 @@ void __init kasan_init(void)
 
 	kasan_populate_early_shadow(
 		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
-		shadow_cea_begin);
+		(void *)shadow_cea_begin);
 
-	kasan_populate_early_shadow(shadow_cea_end,
+	kasan_populate_early_shadow((void *)shadow_cea_end,
 			kasan_mem_to_shadow((void *)__START_KERNEL_map));
 
 	kasan_populate_shadow((unsigned long)kasan_mem_to_shadow(_stext),
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221104183247.834988-3-seanjc%40google.com.
