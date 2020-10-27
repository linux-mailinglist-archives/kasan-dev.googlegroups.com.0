Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBJWO4D6AKGQE6Y5VH3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id BA54329AE19
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 14:56:55 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id h65sf706548oia.14
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 06:56:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603807014; cv=pass;
        d=google.com; s=arc-20160816;
        b=naT2aEPWttXy84uiX/o1wuzFpYhUjlndVoHRtH9V8JCbfi0/qEe99x4FOKGxhZIdWA
         XOhdLVvuza3Z/a6rtGqjwo09v136BudJD4NG8AYzSgmm+0BMGP9U9f72booootVld8Po
         83WNPFI74YhzBMXYwwe83hMM1oRSUF/80B0KaWuaWF9RW4aP981WHebFNJucy6z5cwsY
         4hQno9jifZ4pps4IZa7RI8WFq3bQzv+FhkRoSqB0yV3yDJFgBwSF2OaMpUE1zl9lKrq0
         Vb7g+gDa2fSMjx1ERpKl3/s9ouQAG+5YdaUrrW7o8MjsOzGzkC/ROJa0xZf3Q1fUs2Gf
         KpLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=hQhvPpItToF9rI6Lqk9cyAHPY7OEV0LbPItgaG/W1II=;
        b=eI7tqBpxm63kDm8tAK9e+OGk4PqC5ka0A0qClvA4pZqJQrIawdkOxjYQdvzsYeCi/T
         pbuxlOl8W9GzBzm7tgWZPIu8ufQs9osDPkQ93ilI+OerrBXGBsrRa3PrOCf6Ic0+iAXW
         9/UHL6N0JrrfgNZQ5qOD/sVShMz4gK8LhTpEot+aQTpjmWr65iVbgaS6/hOnYgWESAjG
         KnzT53npzDpKaB3qTRJD1+/qOSIQyitnOHZNSG9VWCBLscTP3jDur076HTfCRN08JlVm
         eyYZ7zhdjwDofB5ZWLQwiUIBAksdeMlqYRgckODy0tPGo+1Snpa3qh+XNHs4+6EUKR6w
         GAWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=uNXAfI3u;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hQhvPpItToF9rI6Lqk9cyAHPY7OEV0LbPItgaG/W1II=;
        b=HkyQbIg2KmMxBPju8CYnd4+weyjyUS7IFNqdow7ZkNIn7c7KZnz+MISJ4IOoUgeuTw
         4FVAiqRpw6wB7pMbbmbCOyLjtJ8sZhHQpRkcRqtLOYD/vECK7Kl4qam6Y3B4/W5Z7++k
         C4KNkOmO/H7o3pLSMWrMEZSoG95kWSJ7OVDozc2ZI/8eXltWGVwBt9OiXURxU1cY3dlR
         Mom7kqR8SdNlc0SyltLen1PDB0aDY7at8hTYyoPSND8pV5evhNby6m+XofbcqCPLlz7z
         rFPT+FvCuiOvJ7wQB6RrS1BkALoOYKQeu9qCJ6B0AMbcglbTb6iFj73kWOc4JskOd6Ob
         8H+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hQhvPpItToF9rI6Lqk9cyAHPY7OEV0LbPItgaG/W1II=;
        b=NXdVBiFZQzPIxBr/WjfLikm5nG+xSlFjRh1/8JJ0NHpegvPyh5SanlU+B3RcQorAuN
         bQKGOUN3bgWh6LXG65/TbFtOZSjLRrJY7OO6id1qE6mYnztuPIlFbD4xeUiJTJV7GKnY
         DuYHCsPiJ5xQwXVjgP92pY6Mv/kASLI042vsIIu6WlGgr321VaNW0zVpttUBmgskErfM
         c8funi+debm5Bvxjbx7mar5SgHN2oTDum1MY9jFA+JekOHrQQaBC31WyMiMwuGrtP8xt
         6vv2mEx8JaVkUYP6JJr9KZ+oZi/tTUZZM9WzpYumyUfQyKGgGAYu6CQ8UIfhk5vk6vYP
         6Glw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dy3FcZ3Ik7L+mXAb/Xu68mkQjM8459dh6/w31ts3IZ13iErBF
	g00rhT/N/fNqJJZ69xN1j9M=
X-Google-Smtp-Source: ABdhPJyDyVVDivqPIfOs0ErDN228VC2F1uDjcsZufxtvN8mwAbFfJLfT2ZUHpkbNMcqtkAKpz861aQ==
X-Received: by 2002:a9d:450b:: with SMTP id w11mr1505062ote.21.1603807014705;
        Tue, 27 Oct 2020 06:56:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:20cb:: with SMTP id z11ls375617otq.9.gmail; Tue, 27
 Oct 2020 06:56:54 -0700 (PDT)
X-Received: by 2002:a05:6830:11c1:: with SMTP id v1mr1613412otq.258.1603807014262;
        Tue, 27 Oct 2020 06:56:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603807014; cv=none;
        d=google.com; s=arc-20160816;
        b=DAq42GHb9Xle1uj0CzubO1ZzCrkoTUzp7xkD8mF7WBPI6CXo3Jti+o/ehWMpZ8ecbw
         LzYFsUArHftLkn4KZrr2W78ziegsmx8YzKvMcebCGEGTbPDmVg86RxxRnkbc8e0LgiWw
         S24BZqwQSF4NVUnNcNQE08T8TS7phfEvDEEwOyCeXNY964rSEOu5tNnJHEHghNR8aC+1
         hKlREUY889YdESUZs8m6xIU7r+lJJmQVXzUcules1Y+5jZGh/Y7GJ3eK7ekJc5xTvaUy
         U1n+EpYoOaxQxydnMxwuz6A90xGXi7h88BysVqsmseqkBaommf1NLT0D7LtAps4V9Rqu
         F0xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YX4b10vWEmVqyZR39DPV45pHKCt8XOyLx0j80WJU58Y=;
        b=1A8g9NhOecBHvxeTRhn+tvdlBTc4l5+Q1pr+pYLq8eu2teZoyC4o9pJoCMu6fOVqSK
         6SCvljGjBGZ3phigIIYLe0RfeX/q6qqYyE2SLT6k+iFB1A2MwLtfZmYNy2UyPVGGkIH+
         rexW6MYidoxKDvUmA1a8cQT26YaCoObjB4dVNb6qN+a9IwxHNJIuqgjaJS0qD8YuULY0
         NRU+UuvQsZlS4HgkQpeKbVs4Ox8pKpwCe5ydhOMEI5sKfShpl+KV2DZ52U8dy41CIVac
         yLD4CRO3bdtVvtPutNiHE/dUUFmSU54e/WRBsbxW487/OhYqZqM0YQfWOXZ4+pEoz6Xz
         TeQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=uNXAfI3u;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j78si149657oib.5.2020.10.27.06.56.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Oct 2020 06:56:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (83-86-74-64.cable.dynamic.v4.ziggo.nl [83.86.74.64])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B488F2074B;
	Tue, 27 Oct 2020 13:56:52 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: linux-kernel@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	stable@vger.kernel.org,
	Tobias Regnery <tobias.regnery@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Alexander Potapenko <glider@google.com>,
	"Paul E . McKenney" <paulmck@linux.vnet.ibm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ben Hutchings <ben.hutchings@codethink.co.uk>
Subject: [PATCH 4.4 011/112] x86/mm/ptdump: Fix soft lockup in page table walker
Date: Tue, 27 Oct 2020 14:48:41 +0100
Message-Id: <20201027134901.090009773@linuxfoundation.org>
X-Mailer: git-send-email 2.29.1
In-Reply-To: <20201027134900.532249571@linuxfoundation.org>
References: <20201027134900.532249571@linuxfoundation.org>
User-Agent: quilt/0.66
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=uNXAfI3u;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

commit 146fbb766934dc003fcbf755b519acef683576bf upstream.

CONFIG_KASAN=y needs a lot of virtual memory mapped for its shadow.
In that case ptdump_walk_pgd_level_core() takes a lot of time to
walk across all page tables and doing this without
a rescheduling causes soft lockups:

 NMI watchdog: BUG: soft lockup - CPU#3 stuck for 23s! [swapper/0:1]
 ...
 Call Trace:
  ptdump_walk_pgd_level_core+0x40c/0x550
  ptdump_walk_pgd_level_checkwx+0x17/0x20
  mark_rodata_ro+0x13b/0x150
  kernel_init+0x2f/0x120
  ret_from_fork+0x2c/0x40

I guess that this issue might arise even without KASAN on huge machines
with several terabytes of RAM.

Stick cond_resched() in pgd loop to fix this.

Reported-by: Tobias Regnery <tobias.regnery@gmail.com>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: kasan-dev@googlegroups.com
Cc: Alexander Potapenko <glider@google.com>
Cc: "Paul E . McKenney" <paulmck@linux.vnet.ibm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: stable@vger.kernel.org
Link: http://lkml.kernel.org/r/20170210095405.31802-1-aryabinin@virtuozzo.com
Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
[bwh: Backported to 4.4: adjust context]
Signed-off-by: Ben Hutchings <ben.hutchings@codethink.co.uk>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 arch/x86/mm/dump_pagetables.c |    2 ++
 1 file changed, 2 insertions(+)

--- a/arch/x86/mm/dump_pagetables.c
+++ b/arch/x86/mm/dump_pagetables.c
@@ -15,6 +15,7 @@
 #include <linux/debugfs.h>
 #include <linux/mm.h>
 #include <linux/module.h>
+#include <linux/sched.h>
 #include <linux/seq_file.h>
 
 #include <asm/pgtable.h>
@@ -407,6 +408,7 @@ static void ptdump_walk_pgd_level_core(s
 		} else
 			note_page(m, &st, __pgprot(0), 1);
 
+		cond_resched();
 		start++;
 	}
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027134901.090009773%40linuxfoundation.org.
