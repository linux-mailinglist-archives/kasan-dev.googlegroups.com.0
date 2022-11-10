Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBAWBWWNQMGQE2WUQMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C7821624BF0
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 21:35:15 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id d126-20020a671d84000000b003ad555428e8sf519559vsd.13
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 12:35:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668112514; cv=pass;
        d=google.com; s=arc-20160816;
        b=SlIrRqwGwNcmpbkLwwjn9dr8BbBi/9RR3AXi32a8eJIs9lmnK/WD9RNmKMrtAPVPWb
         hAe+4trb7nZF37TYLD/4t8aVtLPizIvJaX9HMY70NuyRQbeqc65SOh6H4H6t7fPYQ9ob
         tyA74rlQgF6TloKrWsjvhIQTto0NFUvqmDbwUZQ42p+98fdBbkQFWZUI1VF0vGdEVmMU
         yVE5zanSvjCYJTnZj6Lfpsl0ttOTiYkbvILAck+n5HPT48UA7yTmFSNVH6EY6EOdjU/O
         qnJIp1GSmZwopJH/5jCreZdaRwC+JZwYqat6JT6sMaECST7vxJ7VfWpF/qH+4GQUF2gX
         7lDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :references:mime-version:in-reply-to:date:reply-to:dkim-signature;
        bh=pO4D23mohfCqW9ZIun9Uq3NuH3zkntaV4ccE2I/DRoY=;
        b=jnewJv5sJC8nllcFAIfv0gHJmxvuHrNjCLU0Chxvb7mwgYjccBdweNdXf8AU3Vyp70
         1aoS1rt98yyy5ztc+2ynnzxU08UWReTufr5+B1FraJvBiTHxDmlxQvgO8YmvDhUw0/rN
         pfvhqdE/1S9IdWMoHKIgL8zJFYnVbEhzooKk5sNHjsPQSuD6Ita1U1Lth9G0pnzLQ1Hd
         VOHMlSdNitY7pmOVY8wX0/xfaDG+BXKC6ggH3BkM+EcGGCcAyQQTpye1+iO626nmXnGm
         C6rwcDh0Xa9cNi8nL+echNIxeZy1RHI0qnvJNldQohvvczdQQ/vERsVi7cWsDAgcW0cO
         8hrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ica0cDCU;
       spf=pass (google.com: domain of 3gwbtywykcroi40d926ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3gWBtYwYKCRoI40D926EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:reply-to:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pO4D23mohfCqW9ZIun9Uq3NuH3zkntaV4ccE2I/DRoY=;
        b=t2tdcttKYykSoXc+CfkkZ6SJ9EfQHPOI8cnTEwjRNLIlZdqX1qqPF3zWTeKcrWM4QZ
         iReCR8Rcyx6k5hP/L4+fQYo3QbwVKpOjvOBmibbPuRkZRoxHYzsGlYlyVSIIEsy1op2z
         ETa3AI1yKawOxhcs6etZ0nb/brctwSbz9stSM/B4e6if2wzgcsBQu6FphW/8+gtC2/ks
         cRGEOmDnNJNLSF0dYRX2HJbkn8SwTh1lkKcs/tzu3Ie0zcoJPGvqJT3rpyohSfaQYfYs
         MxolSNXfor4GoKfXOllCR7kxa1XXROSnzOhMqKzjctBlZsi0xzP5bTjsCd+HgRZCEfSI
         jEhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :reply-to:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pO4D23mohfCqW9ZIun9Uq3NuH3zkntaV4ccE2I/DRoY=;
        b=UBrDdOh6u/jNOHEPYiBHym/XgKw2nQ3LNWJY2GypS1THFn0MFI7Pgn2/dVhj8J+xTy
         rs9p0yjlyp26IWHnELehApuIftW8j1wW9RnpYNy1MwMu1qWBWtJVzUqUABZaTNxw8KOI
         V+DNsP5d9Ra5jFRx4F9BKHqFXgwPMXfcmFniyHWkh2GNcfOxuZE7WOoffA4Cgkfzp9NY
         SCJc8Gjcbf7I4C3f/yhrIm74WjN95ADEXJoz238hNrOgQpATnF9UA2fJjYntmfKsJwCQ
         PfCQKiQsP5N1FrPepbhSPFU+wmFar8xOy61lbpIj5QWkz9JjTyaLMIExo4F3p+2NHTto
         djLA==
X-Gm-Message-State: ACrzQf3tRjJan14+5Am4L62NIuHPIlt6TLd23GHYRXhRMnO7e38Ypk4D
	AmX04jabj0H5SwK7RHqHQGs=
X-Google-Smtp-Source: AMsMyM5iPRZpoyC0NuDZq8NJo/4j3OKkv2yw7QipYeuGt1xs3o+wbEixH2V/xbW2ydaY2XO1hhMjPA==
X-Received: by 2002:a1f:a746:0:b0:3b8:1bb4:b750 with SMTP id q67-20020a1fa746000000b003b81bb4b750mr16235121vke.20.1668112514785;
        Thu, 10 Nov 2022 12:35:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e3d8:0:b0:357:7d08:67a4 with SMTP id k24-20020a67e3d8000000b003577d0867a4ls925432vsm.10.-pod-prod-gmail;
 Thu, 10 Nov 2022 12:35:14 -0800 (PST)
X-Received: by 2002:a05:6102:5799:b0:3aa:2f91:5230 with SMTP id dh25-20020a056102579900b003aa2f915230mr3795498vsb.68.1668112514329;
        Thu, 10 Nov 2022 12:35:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668112514; cv=none;
        d=google.com; s=arc-20160816;
        b=qCdie3fKm3LIWREXuONScBTbrLbXnBnwj+lo7Q7CnkGqzWZ93qREhD3P71hEWlwp/J
         8j3XunuhVRUTXwQeSNq9xXzV16/UCPP7HwMekrYTsptpzMqIZJ6+VX8ghrqlNGfLpT3A
         5N1b8lLuC5CNYRgi0ECGV3RZg8GskYudsEm+g/O34H7AyTPAEotme/AHynNM6CiHbe/d
         6bTEddvEZVWMelBrdlmvMb+IeytN1DS1DAWZqBSQ61bspH/aMKMbgpOCDuEsrth/UH2S
         PWy9sFtT7anmjqXTC707wHjl3Zzl3TDcFDgZF6FZEUxxj+8Q+F09XSxB9cMnRTO7/KW/
         Gzog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:reply-to:dkim-signature;
        bh=NyjCQLTGMZRdycUacwFyAxLckz0Mzvzm9v3NS3Lsp2Q=;
        b=vDnSNqdTFIVPOElZAgdEx/U3VRqNc5XeMdw9dBnAfqR9rn5CQayO/vL9bmjjx2ANCw
         DNrzqjl6ATbQ/esZ5Q/h9CQsPXWPBCE4xk9WAZnt5UL4mwhLa4F37thggUIQEuTgI3MU
         bHozh+XLoKHFOlX1qd7TJeI7z4wYD+oDhygK9ZNsNup+9BB+Ox4nJ5/KCvidzBq0gYiT
         tj2BOE3PWh3GS5O7Lyy661V3fyKt0o1uGWFMYRs62hgBNO+tTDGa3OEY0MKjpuFi5IEN
         Z4fL7iulPtCyEo0UgC9MscBogImcuQZ4xOEwHHUGWjh/YspFuUCSDsSzl0CXdJJ77l88
         6vhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ica0cDCU;
       spf=pass (google.com: domain of 3gwbtywykcroi40d926ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3gWBtYwYKCRoI40D926EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x64a.google.com (mail-pl1-x64a.google.com. [2607:f8b0:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id t79-20020a1f2d52000000b003b84561b5c1si30516vkt.2.2022.11.10.12.35.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Nov 2022 12:35:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gwbtywykcroi40d926ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) client-ip=2607:f8b0:4864:20::64a;
Received: by mail-pl1-x64a.google.com with SMTP id o7-20020a170902d4c700b001868cdac9adso2074974plg.13
        for <kasan-dev@googlegroups.com>; Thu, 10 Nov 2022 12:35:14 -0800 (PST)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a17:90a:2bcb:b0:200:462f:6419 with SMTP id
 n11-20020a17090a2bcb00b00200462f6419mr1968927pje.135.1668112513500; Thu, 10
 Nov 2022 12:35:13 -0800 (PST)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Thu, 10 Nov 2022 20:35:03 +0000
In-Reply-To: <20221110203504.1985010-1-seanjc@google.com>
Mime-Version: 1.0
References: <20221110203504.1985010-1-seanjc@google.com>
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221110203504.1985010-5-seanjc@google.com>
Subject: [PATCH v2 4/5] x86/kasan: Add helpers to align shadow addresses up
 and down
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
 header.i=@google.com header.s=20210112 header.b=ica0cDCU;       spf=pass
 (google.com: domain of 3gwbtywykcroi40d926ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3gWBtYwYKCRoI40D926EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--seanjc.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221110203504.1985010-5-seanjc%40google.com.
