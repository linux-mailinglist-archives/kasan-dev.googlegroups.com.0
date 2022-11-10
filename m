Return-Path: <kasan-dev+bncBCAIHYNQQ4IRB7OAWWNQMGQEQRZQMLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A1A1624BEB
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 21:35:11 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id j186-20020a676ec3000000b003aa1b91d917sf520026vsc.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 12:35:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668112510; cv=pass;
        d=google.com; s=arc-20160816;
        b=vFztK+KZHoVu7jFeqbQsNBy5HRTV7v+nF+5tIiJcRS5R7UEGSum13L0T91vlBNUhDF
         K9KcBIhH/HP+tWJef8GxSjL6ofvcPPIbnzBJ7UAlLyoLD16gLht9GGnE60GmZlBC9BjD
         kjsjKdaG6ysQxjl60N5DAFtbV63oalRg3KV5tmWo4tqfgKsH44jfU351v0DPWkLquf5u
         lu6Nm3OknTMhnUTgqLKjyAfpdXdntquUFPucbaJgWOU6zAB4HQUYEGsh8eEFFtIhR0vr
         LPiaKMpQys1JO1w7Yy+UktuSs7WJhWWrXQf1tm4GGch1zVf8XGftyRjiLSJBx7jKVny0
         ElvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:from:subject:message-id
         :references:mime-version:in-reply-to:date:reply-to:dkim-signature;
        bh=RaNP3czBiy00XjU9CiEWeItP54gE/d4P4H25tmbJj0M=;
        b=TaaXyhRgqwKWkJWk2Z47W6NQ0pyIBC0c7eWvrV6XrIx2eR+A4EcXpVDiIXeL74TG5w
         3dIQ05BxtH9r2bnzTiyFYFBuo9xHJLHUqmV01mCY8QjKX21bwuCx0XE2Z66DdiQ1l40I
         8qXb+RHYIpm1yXAcNtE2gjKEkV1jL0k3ev5wkYjUhPBt4zgzWFKTEcYb88XMnbXA6Ogx
         +QIf4xFL0M7+6lBnDmPSyylr1phxnU9P/F/J8C14569pHswLIHfof+xZclLIsRc8llY8
         8HjFgDUMMFllpWDsgEpqfic5V/hMbVaZLtQBk33EhhGKn2ONQsuO8gnZATZRlwZm6qnK
         TvOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dPenHzAE;
       spf=pass (google.com: domain of 3fgbtywykcrudzv84x19916z.x975vdv8-yzg19916z1c9fad.x97@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3fGBtYwYKCRUDzv84x19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:reply-to:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RaNP3czBiy00XjU9CiEWeItP54gE/d4P4H25tmbJj0M=;
        b=iW2KbMivHmfr1ZL0WmntA41gZ0YZj78k0gwUAMw9GmyfOxEO0RyVrsGNq43uDybI9z
         ZB0MXBtxX2RR22AI6EnLOwkjKLQUlE2my3z0dRzpb/YLf+dpa1MDXs759kaficmUc6nc
         UA0gpg1BzeQzySaKZwhIzCzcsjgpyt82QYdvqq1mAumFJ+jKIuY6yfTr6AmFOUK7k1fQ
         HOLf0V8anh7EHNlUNlYIIEIAGzTdOnPSBhiBdiqRX9aa60ncQhcDgtt0WPdqFI6+HigP
         AQX6KkI6n0XpUHW1TuRrR0/1NR2dJN2ZBD0h/0zdR41u879N/YR7ygNniMSnSWndrggd
         DwVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :reply-to:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RaNP3czBiy00XjU9CiEWeItP54gE/d4P4H25tmbJj0M=;
        b=0LXqm87KpqZ7Tb6Xzw/vhlnCS9Phr5wMVDs+w9N5ymITRTtH3uiQJN8MHpkOMiZSuE
         zzba89DLeYvuitHv9Ht7lY9yL9VgmW+X7FmsJsRXcp3mDEOIbv25uM9CmPDmIT1AjWx6
         GpXlELXJrs/UGZoK9inSEu4ME5FCAg36PtheFlHxH63/RTnoSADPgLksdb0AhoVmrrQD
         1tPwr1rIB0HZRt0xTtsvmaiCIkh2evT1kCw5IMbMvp5X/bdYz47+olnpo1a5+vcKAgtq
         Z5srTIKt2pXxANB/Rhk1Wh24LTvMQhe9XNhcBDPJb57GMDiVCbELtFyLPK66S95YIsI8
         iS6w==
X-Gm-Message-State: ACrzQf01KFt9327XcQcihHEE5rx4GUIluJoMqkxc3cNYELk0wf+HOJom
	MOpT5jA1BQPjy2tFgaswvbY=
X-Google-Smtp-Source: AMsMyM50zzMPByalKpQFpznGf5rJ5FduPn/g1XLKAyMzaEmLxz6aE0q/OdhFP9bwsNk7LgwB6mkd+g==
X-Received: by 2002:a67:f14c:0:b0:3ac:9fa4:ea67 with SMTP id t12-20020a67f14c000000b003ac9fa4ea67mr3711885vsm.47.1668112509841;
        Thu, 10 Nov 2022 12:35:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9fc1:0:b0:3b3:e860:2bd8 with SMTP id i184-20020a1f9fc1000000b003b3e8602bd8ls285714vke.3.-pod-prod-gmail;
 Thu, 10 Nov 2022 12:35:09 -0800 (PST)
X-Received: by 2002:a05:6122:1298:b0:3b8:47ec:c337 with SMTP id i24-20020a056122129800b003b847ecc337mr16157825vkp.31.1668112509263;
        Thu, 10 Nov 2022 12:35:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668112509; cv=none;
        d=google.com; s=arc-20160816;
        b=uY+R3P9MHJm3gdtOhBl4i4Y2gLnmMR+IA68n347ctF504OYzoxvX36TFRtXu17/lFv
         8W6uLnu1ZteHcJbfZHy978s9rLRa/cmcRPC8+IRI3dvOi3HK5JLdKlM5hkwfKdaiyU7T
         ZbelORsVgyuMjstMcvr97WHRNz5rdaGoH2MI7CgQF1+n386BnZm9yaD2VT/j+RS3eYDk
         9WSaSr5M1a8+4OKeCGPLKQEhJPyp7E+s2Qj+ci5e8hYSpA4d4HKQfV214iMyVJEIrIdK
         jBwDqZO6HnaiHQ1dZjSFhYI0tRW/rg6puR0/qJT2UxBvuNdRdtA45BGGyYbWnzdeOdXe
         /78g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:reply-to:dkim-signature;
        bh=ORwfmj6kJY3MPYNwljMh0Ojz+sLVhyTdNLlUMLv1/pk=;
        b=pchXg7DGhZuNDABAFGy2C/bCmndmGq8LlgxnkRGqTMI2cApcmWvLC07W5OGQ06VKXb
         0CUjSoWdHUjGBh/ZJoCCMs5XjgaMJibzwOt/YEbJJWkxBqFAQ49JRi9vBWEuOt/Q2sCo
         rtoM4H4sGz6ibpA8ld10PSbLO8rjkv0zU75A0L3+/nAdv92/7lhuEsoF8B2O/2xpDezR
         Le8AslUAEl0rrLtmBWYQ16X5Flt8QMpgRS9c69hiv5/ARdiOnktd6TlABzPcPoUYxEM6
         1KIyWm6z9Su3KCJJyvXUhHgKe4fvNAczwqniVvBiVaelcqeXGsj66DuaURmNL+5429oT
         F/nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dPenHzAE;
       spf=pass (google.com: domain of 3fgbtywykcrudzv84x19916z.x975vdv8-yzg19916z1c9fad.x97@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3fGBtYwYKCRUDzv84x19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--seanjc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1049.google.com (mail-pj1-x1049.google.com. [2607:f8b0:4864:20::1049])
        by gmr-mx.google.com with ESMTPS id g65-20020a1fb644000000b003b87533e1eesi29668vkf.3.2022.11.10.12.35.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Nov 2022 12:35:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fgbtywykcrudzv84x19916z.x975vdv8-yzg19916z1c9fad.x97@flex--seanjc.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) client-ip=2607:f8b0:4864:20::1049;
Received: by mail-pj1-x1049.google.com with SMTP id q1-20020a17090aa00100b002139a592adbso4063775pjp.1
        for <kasan-dev@googlegroups.com>; Thu, 10 Nov 2022 12:35:09 -0800 (PST)
X-Received: from zagreus.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:5c37])
 (user=seanjc job=sendgmr) by 2002:a17:902:9894:b0:185:57b6:13c3 with SMTP id
 s20-20020a170902989400b0018557b613c3mr1968715plp.116.1668112508403; Thu, 10
 Nov 2022 12:35:08 -0800 (PST)
Reply-To: Sean Christopherson <seanjc@google.com>
Date: Thu, 10 Nov 2022 20:35:00 +0000
In-Reply-To: <20221110203504.1985010-1-seanjc@google.com>
Mime-Version: 1.0
References: <20221110203504.1985010-1-seanjc@google.com>
X-Mailer: git-send-email 2.38.1.431.g37b22c650d-goog
Message-ID: <20221110203504.1985010-2-seanjc@google.com>
Subject: [PATCH v2 1/5] x86/mm: Recompute physical address for every page of
 per-CPU CEA mapping
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
 header.i=@google.com header.s=20210112 header.b=dPenHzAE;       spf=pass
 (google.com: domain of 3fgbtywykcrudzv84x19916z.x975vdv8-yzg19916z1c9fad.x97@flex--seanjc.bounces.google.com
 designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3fGBtYwYKCRUDzv84x19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--seanjc.bounces.google.com;
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

Recompute the physical address for each per-CPU page in the CPU entry
area, a recent commit inadvertantly modified cea_map_percpu_pages() such
that every PTE is mapped to the physical address of the first page.

Fixes: 9fd429c28073 ("x86/kasan: Map shadow for percpu pages on demand")
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Signed-off-by: Sean Christopherson <seanjc@google.com>
---
 arch/x86/mm/cpu_entry_area.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/mm/cpu_entry_area.c b/arch/x86/mm/cpu_entry_area.c
index dff9001e5e12..d831aae94b41 100644
--- a/arch/x86/mm/cpu_entry_area.c
+++ b/arch/x86/mm/cpu_entry_area.c
@@ -97,7 +97,7 @@ cea_map_percpu_pages(void *cea_vaddr, void *ptr, int pages, pgprot_t prot)
 					early_pfn_to_nid(PFN_DOWN(pa)));
 
 	for ( ; pages; pages--, cea_vaddr+= PAGE_SIZE, ptr += PAGE_SIZE)
-		cea_set_pte(cea_vaddr, pa, prot);
+		cea_set_pte(cea_vaddr, per_cpu_ptr_to_phys(ptr), prot);
 }
 
 static void __init percpu_setup_debug_store(unsigned int cpu)
-- 
2.38.1.431.g37b22c650d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221110203504.1985010-2-seanjc%40google.com.
