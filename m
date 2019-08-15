Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBOJ2LVAKGQEBNA4UOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D92A18E1C5
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 02:17:10 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id l11sf766501oif.9
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 17:17:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565828229; cv=pass;
        d=google.com; s=arc-20160816;
        b=KIw2NVSJfnRgr7UghHtngDxkZeVWOVTsIJDsrJaKJp9Zxlx0YF6G55vS8BHNVFELTL
         /D6LYXOEw4eQ7K6vNlRYGRCT+bYXx2R2gN4TETQBdiwG1Y4saTWCgCssVOrbMiL4ADhl
         cSSHfkJNdbdlax2iaWfke+YjUQP4UjOrkGYLcq+xrKgjSuRb6bq6GCCg90RRqXy6l5N8
         ifZ7w/lKXrieRundskdxkFoMS41kxRvC4OVKfC/SmlMfmHfEP4tx9RUaBkvEO/iNwFJl
         z+oJV4wTuq2bKYmHPtlYpu8Am/YCfevZfc0hbNBnYXy+qBotRiWCrFUzOrxn9tGXhYJV
         LdYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Dx3oUGIG4pdpMa+1iA+oRjf6N5XtQOp6xoT4Ofu3UCA=;
        b=bPRa8ciUwBD9lxBeGbXw+9s2UlpuYXirPWXcUkUiMuk2hxQrb9t6eXnlrTnENBSJYD
         eoEMKA4moutS5i+MZXLsf8ks9Kr1iEWdr8ufVP/uoynS9TCPIBdDk6z++NPNLqV2Tvvp
         uvHdsgEG9zketGccbNhJlUo1WG/7SJOl5jEBFnY1gzgT4ClnA3Qjl+OBb8dnh4uikA58
         sxwRnKppREN1VTCvrCjhDBLrxaUZ/BIZEmd9UIVdgrhbSc7XfALLE6KM95tAcyJjGW5f
         h5+vm+Xf3kPoAud5rfywJ12vUJzDnXoeB5Zd/F1QRWn3Z253A6RQQrlxB25oxBFiPubA
         XU/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=EzjEg35m;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dx3oUGIG4pdpMa+1iA+oRjf6N5XtQOp6xoT4Ofu3UCA=;
        b=L6nk6tf1/LzpvBkXUK9PYzUqGXfEjBk2/VSCechvWTEMGLUSF/qcIcCm4gjIu54cE6
         wkoSNdys5WtUKEbApsTKdyWGZbQZW8O5o1h4N4/k2dOIcB855joK0DpDC97ZAEm1MrvH
         fAUT650W/hyYTsRF2AZvILLAjlHG0pImwJ1C0/0xELAphX0VTEDyRn89Ap0020QVTb9K
         VISuRvOKFRv1EXvX1ePqsQxhYMKOdhY9xzm9QvdeOF+AOJ/kelHyubanX4ANs5xdkr80
         hUKTPPcuyY3YmHUyeT+VHEpJqA179FRzl7YAElnQ4GEBITOW96/BnLgmH0JXv33QkWen
         fGnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dx3oUGIG4pdpMa+1iA+oRjf6N5XtQOp6xoT4Ofu3UCA=;
        b=Ct4QVL2vP4/gzNlqpoveC3aRUJOXW0xVw3h8530PfYRqlRBJq+HLbFIIgujWy97Dp1
         kAh0s7zVX3US8xISmM08udQ3SJvh+J01V2cE2rUYqV8D2+fpdq47K5bo1AibJq1swtSk
         mjkokBWHOu+Gokv9DCG/VqTOjspeFsbMWkM/q/I4fHHdyKTpvy5+fBnP51ZWxvwj8T72
         za1/Zaw1nhjKDtPdB5wL/mcSgSOU/dujHxbxl8Ox16tTfsKLFc7vStfqj1Pba+5PYFKq
         h21l9Z+YobicbG1EwVR97IG86tK4+tFlBq/S1w2/yc7fbpiV5mymizxZaB7Nnu4urCWr
         hnWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXpCHGBV1gNGn3n+j1ycoyqRVlq6kETp0mldvf2H0hVFdplDzPV
	EjRfLGgAjHUKdxD2F/F1u14=
X-Google-Smtp-Source: APXvYqxGxvSzbTX2s6kNDDoKpH3VOCpyPcx98WgZ8Y9XiapSz7juSmVdG22UG7M3eHrzu6uJBYvKNA==
X-Received: by 2002:a9d:684c:: with SMTP id c12mr1582536oto.78.1565828229350;
        Wed, 14 Aug 2019 17:17:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4d14:: with SMTP id a20ls601465oib.0.gmail; Wed, 14 Aug
 2019 17:17:09 -0700 (PDT)
X-Received: by 2002:aca:dd0b:: with SMTP id u11mr384514oig.162.1565828229097;
        Wed, 14 Aug 2019 17:17:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565828229; cv=none;
        d=google.com; s=arc-20160816;
        b=B1P+WpqQGgxq+hZEjPqKKixgnEzSsbiyaQO1xlx1n8KJC9W8DRdHhumGDIMcThGlk4
         ECjH+5GAoLz5xLoPE5hNMli04wBnhKwnVlUZNMBSCm68bzeVU3s4cyGa8QoQVa5EcZd5
         58QuI39UAw4SEZ6f7DxCQSFjt0zjSQCz7Lsfohn1Xyi/JAizGz2dhjU01hr6maMLSg1F
         aKiqWecyEFneveZLrzX+1ttEgjQSBuhoeBXoiOvkx5iydOXArQOKTZuWwnUilGZXQrxG
         ob1yBGu4qtHoPi0M6Dn5p+LJdnfqRkjDS+kIfK39NLjS32Nk2uCRO1D9sNcBKalAf6NN
         9AmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UahEbtdXwZNAU+KwZPeJAGjgE2lYz0Dt6XczqvKwLUQ=;
        b=PplGzHX+TsfB0Gy9F646VniORthhlyX69HL57HtlkK3a+dKbFFCbQDNW0MFOnlmDrf
         MgBRBvqGAoNgUioErP4acCLR4RSLNGLyHuFk8lt4cnLybUhnIERSaC6Yk+S7S0alrtpR
         K1cmuZyqPGxI93nd3rC8XDrM1l34jGeJIXyYCRDj2GGYhe1tauqFwDeTilTPoepjgJOV
         yA4SXuf0Wx8F3frWrYmLZ9KtX8UKAIlG6NnXErFHRyI0JR7AmOkyunyx2qrMrXDDxbuO
         JVfX5/JoQ7JQUQftutddcRlaMd0gUmaIksOtQZLFGcJHFK8VJezLqFWgotftaZzpBy7v
         bVcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=EzjEg35m;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id d123si73514oig.5.2019.08.14.17.17.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2019 17:17:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id x15so441416pgg.8
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2019 17:17:09 -0700 (PDT)
X-Received: by 2002:aa7:9609:: with SMTP id q9mr2568209pfg.232.1565828228148;
        Wed, 14 Aug 2019 17:17:08 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id g11sm821630pgu.11.2019.08.14.17.17.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2019 17:17:07 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v4 3/3] x86/kasan: support KASAN_VMALLOC
Date: Thu, 15 Aug 2019 10:16:36 +1000
Message-Id: <20190815001636.12235-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190815001636.12235-1-dja@axtens.net>
References: <20190815001636.12235-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=EzjEg35m;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

In the case where KASAN directly allocates memory to back vmalloc
space, don't map the early shadow page over it.

We prepopulate pgds/p4ds for the range that would otherwise be empty.
This is required to get it synced to hardware on boot, allowing the
lower levels of the page tables to be filled dynamically.

Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

v2: move from faulting in shadow pgds to prepopulating
---
 arch/x86/Kconfig            |  1 +
 arch/x86/mm/kasan_init_64.c | 61 +++++++++++++++++++++++++++++++++++++
 2 files changed, 62 insertions(+)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 222855cc0158..40562cc3771f 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -134,6 +134,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
+	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..2f57c4ddff61 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -245,6 +245,52 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
 	} while (pgd++, addr = next, addr != end);
 }
 
+static void __init kasan_shallow_populate_p4ds(pgd_t *pgd,
+		unsigned long addr,
+		unsigned long end,
+		int nid)
+{
+	p4d_t *p4d;
+	unsigned long next;
+	void *p;
+
+	p4d = p4d_offset(pgd, addr);
+	do {
+		next = p4d_addr_end(addr, end);
+
+		if (p4d_none(*p4d)) {
+			p = early_alloc(PAGE_SIZE, nid, true);
+			p4d_populate(&init_mm, p4d, p);
+		}
+	} while (p4d++, addr = next, addr != end);
+}
+
+static void __init kasan_shallow_populate_pgds(void *start, void *end)
+{
+	unsigned long addr, next;
+	pgd_t *pgd;
+	void *p;
+	int nid = early_pfn_to_nid((unsigned long)start);
+
+	addr = (unsigned long)start;
+	pgd = pgd_offset_k(addr);
+	do {
+		next = pgd_addr_end(addr, (unsigned long)end);
+
+		if (pgd_none(*pgd)) {
+			p = early_alloc(PAGE_SIZE, nid, true);
+			pgd_populate(&init_mm, pgd, p);
+		}
+
+		/*
+		 * we need to populate p4ds to be synced when running in
+		 * four level mode - see sync_global_pgds_l4()
+		 */
+		kasan_shallow_populate_p4ds(pgd, addr, next, nid);
+	} while (pgd++, addr = next, addr != (unsigned long)end);
+}
+
+
 #ifdef CONFIG_KASAN_INLINE
 static int kasan_die_handler(struct notifier_block *self,
 			     unsigned long val,
@@ -352,9 +398,24 @@ void __init kasan_init(void)
 	shadow_cpu_entry_end = (void *)round_up(
 			(unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
 
+	/*
+	 * If we're in full vmalloc mode, don't back vmalloc space with early
+	 * shadow pages. Instead, prepopulate pgds/p4ds so they are synced to
+	 * the global table and we can populate the lower levels on demand.
+	 */
+#ifdef CONFIG_KASAN_VMALLOC
+	kasan_shallow_populate_pgds(
+		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
+		kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_populate_early_shadow(
+		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
+		shadow_cpu_entry_begin);
+#else
 	kasan_populate_early_shadow(
 		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
 		shadow_cpu_entry_begin);
+#endif
 
 	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
 			      (unsigned long)shadow_cpu_entry_end, 0);
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190815001636.12235-4-dja%40axtens.net.
