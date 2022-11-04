Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBVVVSWNQMGQEMCG73KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 0623E619FFA
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 19:32:56 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id bj1-20020a05620a190100b006fa12a05188sf5037721qkb.4
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 11:32:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667586775; cv=pass;
        d=google.com; s=arc-20160816;
        b=BXQ2a07Ku4qVieHGKXcwyamX7ntn7j3L+Gq9hK5qnO0sUqHmQMxU+pLaH5O9wwS8GB
         6nxMG8zMe/tJApc6UlFSMxY34CrXACSCHxeJsM6k1abnrh+1zDRPn8ap+viFphErMWh6
         G5EYHgHylkws8qI4OVXtjx+XMiOhDKYdxmFcI14iOKN2DuY7T+reMi6vUXNQx6VGW7De
         +JlL9IYtvEgapGpEAQYB6WEIkYiQdyWBgocF110FzYoRauJjKnOiAHV//4kE5pwXN2oZ
         DmAH7tynALtnlACf8LkqIj9HgPDdueQ0+EoX/emFjIcsbxgTAP+nZQUrywvb1vcLjJ9c
         Fxhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :references:mime-version:in-reply-to:date:reply-to:dkim-signature;
        bh=fRUjY4pJ5z0Re6tIf3pJvqbZklJJ1hQAZOeEIMKO5co=;
        b=MqOWqgSbzP/HR/SazhIjp5fNOzxDibEX/Yv8V6fbwcIyJKi2SO67RM/nYFPXlHi4U0
         Wr4izgblyzj2DLtdSai5QDPEqDRAvpw/jiJxuhQe+FizmUZTlD7UVojpO23FvmDP1lcW
         DPr8x5kT4dNlSrZacHs7JBpI3PdA6/YzwceBff0/rl5OUDgCPq8znU6yu27WVbVP1oeq
         ovGoAFuNRc10OVjqbou8JFXoh7T3yrkrD6b7hZCjqdL8+GDITSXAYfyemS9gwSdo1fhT
         b4nstp+U/7upZgx629kkcHSjFdrce2YOtDmbpcgeyS7l+/Q+s4e3YJ16UZe1+WLc56mA
         /NDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oN6YQDqk;
       spf=pass (google.com: domain of 31vplywykcuiwierngksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=31VplYwYKCUIwierngksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:reply-to:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fRUjY4pJ5z0Re6tIf3pJvqbZklJJ1hQAZOeEIMKO5co=;
        b=ArD4Z/qVzgBXVqCmHNbEfkNYz/E/EU0WbuRSFTBxla82s1BTDbxAU3TiurexcvvmKX
         0ulFAScgFZEIiDRBiepAIefIAaCz6mYIHWehyl73w1bNCxvgwg7+EzM/bewU737VJ673
         +83tnguNkUNJCXOsr5acmCpOmI1hn/bN5uGYWDmj+6e7HMKTJj7WqUH559Gfob3j3d0e
         edK524vdUh8BGsM2VjpohiLarHyL4nkZJH88SO2pO7NgwHUs3DHKhJoLiTk6iSyaMZP0
         MQIEFF8ZlXH6EwqhN23X8NrMNMerethT6Akfy8/bjl5U4I6oMspnbW5UZRlFjMJtjjaU
         L5wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :reply-to:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fRUjY4pJ5z0Re6tIf3pJvqbZklJJ1hQAZOeEIMKO5co=;
        b=Pb4kU2qN0AWkfl5v8KZ/Yi0WNCg4P6HDt7sAh2OCBJE+uCOjd0afFzy/lIxmTIUNLh
         e3XM9dVmiUCMERR5Q8Ty1RnNwz/l/FawDVo9K4W37pTETZITamoOEnm/AY8Qt6ceSE+D
         BxO7J/fJGasuffSu6/bdSxQwY8bJusvVKEoU2T5CDd2HjlCPKmMAouPzhVmC3J3o7qUu
         Pi5yH6lORTIu60u5dOSSnsv7sEniJ0UmM2EFW6Wi9NQb/cROLt+Fda4tO2sL87tvmn5A
         c+i6WKj2WKSDdzpQRn42zdeoAMdcSWbphXGYqOoTJvXu9oqpw4KfGZzVTiJlfSVphnBZ
         OCkQ==
X-Gm-Message-State: ACrzQf06qI7vF+GHOEBGjZ2fftOgq/zczKj1kTFnTqWa8l4FR+KpXb+D
	mfnQGPmV1DZrf/TxZaH98bU=
X-Google-Smtp-Source: AMsMyM57YhrlaFKXym+AiW/tEU7rvc86T5WsE0HFZyatsBfJ+skKD9giUO9BDHM4cZiD+qmsutB+ug==
X-Received: by 2002:a05:620a:1139:b0:6fa:3417:9d85 with SMTP id p25-20020a05620a113900b006fa34179d85mr19926006qkk.8.1667586775007;
        Fri, 04 Nov 2022 11:32:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1bac:b0:39c:b9de:752a with SMTP id
 bp44-20020a05622a1bac00b0039cb9de752als3521634qtb.2.-pod-prod-gmail; Fri, 04
 Nov 2022 11:32:54 -0700 (PDT)
X-Received: by 2002:a05:622a:986:b0:3a5:1eca:a7e1 with SMTP id bw6-20020a05622a098600b003a51ecaa7e1mr25545125qtb.350.1667586774490;
        Fri, 04 Nov 2022 11:32:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667586774; cv=none;
        d=google.com; s=arc-20160816;
        b=P+q/Pj44NbROi1RWTLLU9xNSerFxIEJpZ6YtsFzckR51GuAfvJ6Fder+0IVgz6Uvdp
         egEl8V23QpPhsISLs9TK/eW2htXxnMJfJBgLRF3QsDt1CxX9Gx8cUnOWuZVBxSTI8N/O
         UeJAlHY/hQSqGUze6wJlsZ3232Rgiie+1lBGPSVqy0AWq9D5gjXYR3V/CTGeSHqIgMGK
         yoUaYmkPoyRVFlNyrLRasluxnatSscO61ZCSYgphuovMOH1IkvU++moWjJgKupNPMSFL
         T0rc5QArt2rG80PGF63blwsEPOvl28j38yi7sIV5MJfKKo242u2tGi0J+Sc9E2rssljc
         2Tow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:reply-to:dkim-signature;
        bh=XS7y2dqHGNcxgJtQwV0riGq39Rt6nVME96ygRYhND24=;
        b=ZuWEXVMlcymenxbx1Z/F0gY7P6SIvP9lz/nFjsB6WDmz1INbk0KLrw/bFdSHSYJPvT
         zgwvOzIR/cyB2lKqIIwblsT5d0zS+LZHBfrs8lRL6+DY/5Bh969QNOoKevLeELPDTYEE
         zvvsDXcxcoUzmrNdP/wxmj7pixNaLr/OY9L+KYm31/ZaTjYnlaiUf+qToilW/B5JdgPc
         u66XDl6zn4404UmdgFHOr2ZWVCnOk9c8r2/ZS1+Vjkndf9+briE1QH1BIJYI9vYCglfN
         KrWVNX55X0J0ULHlouNKigEOX1ig8zp/pCucn6hakhn14jzkDd26PXId1sReljUuyV7p
         l7tQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oN6YQDqk;
       spf=pass (google.com: domain of 31vplywykcuiwierngksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=31VplYwYKCUIwierngksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id o1-20020a05620a22c100b006ee9c67dfb5si201993qki.4.2022.11.04.11.32.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Nov 2022 11:32:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31vplywykcuiwierngksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id f22-20020a635556000000b0046fd05d55cdso2880370pgm.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Nov 2022 11:32:54 -0700 (PDT)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:aa7:9527:0:b0:563:b1bc:7f98 with SMTP id
 c7-20020aa79527000000b00563b1bc7f98mr367586pfp.29.1667586773676; Fri, 04 Nov
 2022 11:32:53 -0700 (PDT)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Fri,  4 Nov 2022 18:32:45 +0000
In-Reply-To: <20221104183247.834988-1-seanjc@google.com>
Mime-Version: 1.0
References: <20221104183247.834988-1-seanjc@google.com>
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221104183247.834988-2-seanjc@google.com>
Subject: [PATCH 1/3] x86/kasan: Rename local CPU_ENTRY_AREA variables to
 shorten names
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
 header.i=@google.com header.s=20210112 header.b=oN6YQDqk;       spf=pass
 (google.com: domain of 31vplywykcuiwierngksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=31VplYwYKCUIwierngksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--seanjc.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221104183247.834988-2-seanjc%40google.com.
