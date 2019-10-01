Return-Path: <kasan-dev+bncBDQ27FVWWUFRBN7SZPWAKGQE6OFR6GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 42289C2DA3
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 08:59:05 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id w126sf9615918pfd.22
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 23:59:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569913144; cv=pass;
        d=google.com; s=arc-20160816;
        b=WkZeqD25826IRVj3ckXOB6jKVTyuPpFvtpNJ+CFxvVR7v4o6hx/pONv04slwjMRWbL
         kC5xxxPdiVeHVcuA0YPzZYFKHiSJNtGHWwzssJ6sCSURMyCDb4ex+eXCkW0m+ahet7/m
         7QrEvhMrUMpmAteHIyavPRlC5PnnDoNHCXlVaXPxiRxgRn35Y8b/yQi2sJTI7lC0jBMv
         XLCw5hM5Y1ZnCP0r9CYRkFnAnmnMEf7B5lLHaUoZh9FLxv8wvWQa6Sh2LfDdgfVj+AcU
         xo0Oebah1RRXFB3u9nche17FXSD/y8gB23P11RTmWI/jrD9Ca+Jy7gvtFVOgift+zkAy
         Nt6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jItTnAajiTR4nePzgvN8xWbwmr8LbVkYBahJzS9xmO4=;
        b=v3wgITLnE9zFX7qFteANnZ/Y/bJEo454QdmeZhUvi1SlC3i+QuWGKF5bPiO9Jh5MwD
         bKuC95tPV8KbVgjL1VCL05b4QGKCtiFl815DMw/Ulbjqm1yvqlXl3QUcaRBC9noBy3Bl
         VR2GoiphqETLXWz7Oirknedoet48PY52/jNrsSectJ4CDZKEqEUZIAT70dDOqTRkVe9f
         DqDlNHQwma5TcuZ09+WvGUamIh3i873jSAp+M+NULes4aE4YW18eEqiCZDxzhjj4zNrV
         QK1PCOprO7Vvz5zDXfxxIMH81EuuSE3IFPRmjXDrRvez08JYIlAH2gXN3xqmP7XyTUnj
         dLNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HGfYh1Vy;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jItTnAajiTR4nePzgvN8xWbwmr8LbVkYBahJzS9xmO4=;
        b=j7QY1ArkiCM4zBH6nINL1O712Q0eyPRVT3Z3Tmj/IB9LE9T+AFLcSiwHgaujuMbzrf
         UB8Glv+ObuL17DIL+gQD5UuOmzZbidVfrL4qH0GOUMGWnnbijhZG27yv0MtBwyf86WTw
         Wq1wIlDowTX1PBgaI6U1GqNzpHYBbJhyvSyXj4bnQR7Zr5w2DyTbShHhlvAiS4IMTF2p
         +vBspHvIuC3cCsXYESpUjlCXhOKF5bXRd75LKcZ3u/tKF6GnpTdfEP9k/yUbxJQ5NBpr
         yRk6X4Nz9Z7Fm+jwCL3S84G99jNokQfxA2eefOWirLePwp1V9z8sLiMdS69qAMrmgENC
         RCxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jItTnAajiTR4nePzgvN8xWbwmr8LbVkYBahJzS9xmO4=;
        b=c8tGjWOYJ7I/oX1hsoUD3GIQeNFeU+A1IHMmRD0/AeHbu5JWMiPP8nbDQ9RlDJkq/I
         VyWEd/Eb/l3sXwtIiL6se7bCmHf0UEn+8AXud/6x0lh+K/nhoDLeDBlx1M1DMk0Vx+fX
         tQdF275W1hKrtXkpKm/t+9oQm4veDuBt5J40r5X7J7ZlGhb9xOBag8i0vxogWZkZFvta
         RQAc10enDL3Tflx9tLese9yPjXJCogAgLQllnU4c80xYG3Jg5vT50wArJBJ963/w4hbK
         yzGLC6ncvOao57wMd05aoGoDz0ng5Ac1cQQJkjkgCs0tgGK35FrzSYJhCxL9ki6gQjpF
         vilA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXTBf23fXTkBSi0cJPMqh4Vk+dcI0SSvxfP8ZQopksr4e7fLbrn
	7wpMe+EKbXo5Y6eq+y76HnA=
X-Google-Smtp-Source: APXvYqxry2WHzKb/Fdf+8IYw1qtfkkBRoCmfFCVkmViD7Dj0adQpMjm9xy47mBmoQUWuYfxamuwjuw==
X-Received: by 2002:a63:a060:: with SMTP id u32mr28871906pgn.150.1569913143854;
        Mon, 30 Sep 2019 23:59:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:66cd:: with SMTP id c13ls3640150pgw.11.gmail; Mon, 30
 Sep 2019 23:59:03 -0700 (PDT)
X-Received: by 2002:a65:678a:: with SMTP id e10mr29079793pgr.184.1569913143401;
        Mon, 30 Sep 2019 23:59:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569913143; cv=none;
        d=google.com; s=arc-20160816;
        b=IPtkNOOTP9ygwfHV9J10lUTW/jie/ZtlitWrR6GQgwTetcADS74mkDsXPikfhE2SI7
         1u8PjgcQqRmNrfDfjpjXqVEmeydaHuy3rizFGNw15oQkYiYd8x+exScJ44ezzXx6oK53
         cT8a83EUt7dEo7fIUOjXq3Y2BJAhX93PdSiulyg+98672dRwzXqZ+GxDzUr74/9c73Sw
         tu/sNYCOtau3SqGp49p5qG0UZUwbhbHGsmEHIsmucFBXIttqeiiva9vEpBC6W5RF0TPo
         liTehJoqdRSPVWgGt32bjOh8CFeNIqalusTYWHaQVyHAS/Dj90HlXYWIXt1U68RjH4g6
         PHYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nT2YfVWqLVVoMBBfkawFdkyFGk3ghEY3fSb+SzvkIKM=;
        b=SrCcII7fVGauP1oaAJuOvOizX0oGVdESZkFZf8SndZ55Ab02YnYDg8wKsR6nIy454o
         wFBzpFya8GI3O3lkQijN00akiARrEJEiJcfd2ikdcbaAWQ0s/f6L6pCP7Un24L+Lwrd4
         p/q7G6DqoXwO5/7ZH2IIw5ycPhN8AhI4QPSbnk6pNoI2Xtni7xwBh4hpk8DEBLDFg51C
         e4qie7GGDDgbErEAfdhq9SjYHMqMSM1DDGO/tuMIqPIpdqsNIKpsn7y7S6J0kcrlHdGR
         NWXhMmFTcW7sphwFqdPRQDYMMpM35xW3OSfbyN9h8vWp6dhUkFQNW3AieiNZsC11eoXh
         r3gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HGfYh1Vy;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id x13si536862pll.1.2019.09.30.23.59.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 23:59:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id y35so8961724pgl.1
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2019 23:59:03 -0700 (PDT)
X-Received: by 2002:a62:8286:: with SMTP id w128mr1195213pfd.240.1569913142901;
        Mon, 30 Sep 2019 23:59:02 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id u11sm21284342pgb.75.2019.09.30.23.59.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2019 23:59:02 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 4/5] x86/kasan: support KASAN_VMALLOC
Date: Tue,  1 Oct 2019 16:58:33 +1000
Message-Id: <20191001065834.8880-5-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191001065834.8880-1-dja@axtens.net>
References: <20191001065834.8880-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=HGfYh1Vy;       spf=pass
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
v5: fix some checkpatch CHECK warnings. There are some that remain
    around lines ending with '(': I have not changed these because
    it's consistent with the rest of the file and it's not easy to
    see how to fix it without creating an overlong line or lots of
    temporary variables.

v2: move from faulting in shadow pgds to prepopulating
---
 arch/x86/Kconfig            |  1 +
 arch/x86/mm/kasan_init_64.c | 60 +++++++++++++++++++++++++++++++++++++
 2 files changed, 61 insertions(+)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 96ea2c7449ef..3590651e95f5 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -135,6 +135,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
+	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..8f00f462709e 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -245,6 +245,51 @@ static void __init kasan_map_early_shadow(pgd_t *pgd)
 	} while (pgd++, addr = next, addr != end);
 }
 
+static void __init kasan_shallow_populate_p4ds(pgd_t *pgd,
+					       unsigned long addr,
+					       unsigned long end,
+					       int nid)
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
 #ifdef CONFIG_KASAN_INLINE
 static int kasan_die_handler(struct notifier_block *self,
 			     unsigned long val,
@@ -352,9 +397,24 @@ void __init kasan_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001065834.8880-5-dja%40axtens.net.
