Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBQE7Y36AKGQE3WCECNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 76460296081
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:57:21 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id w189sf1080777qkd.6
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:57:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603375040; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vgvlt83tXr7wHUGuahoTv5wpA/sxBhDtm/xJZjN4xScAkCoG25dBxjpp3BGGA+al/G
         8gr1oPuYZpDqQXgqrd8TR0QinBqifhLgsVnEFWP2/+SEhIPAUV6eTJc4Z/cqfhMzT6P3
         1HuZv4++CAUzcMqzYy/Pu099R76/4MC5ydpAXfcD+/NhbBUycxQjTbH2TpFxjf8LO7Dt
         Q8QnBMQ1ygi6RFlCZSHjg72ElUhC4GDL9PPmMX4mehW73+u4K+fRdrHHouva6BRPWZOu
         wU+8aJ94jpMrnrxFg/fo9Ii6z4BwubOUcRZ9CfDuffosHgkj1QXr5DdKHLOZQlPUitKb
         Y7XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date:from
         :cc:to:subject:sender:dkim-signature;
        bh=dSSdjynKB6vrqn+vQ16QQ4Bf9uSLW938ahxOi3n4FpE=;
        b=vAxJ9P1ph2RYdEgLCc9++lM23Cm7mPyXVSN82W4T9pU2oRATdqNl4ItJpeCshIjvZd
         FkNiXkIDLPuzacqZRxMecV+LngGWygBRZTJ2nY2qtN4lzSNFtu8RFJ9OuzA/UfWV8/R+
         fI5HljykIZaLfzxFzWOxGGACKUXpJ42JbznFCxL5riYDwvZluGQI+8hdZ5MMeAN++AXj
         p47ja46MJ0wFMymSXW/Eulx16LxTGGwXWwEWBd+rRMfVZBTBGs538gBkhvlAXxybACMD
         IdE+GzCBW2u3LiHHuhT8900u3KGzpDFyfYW/uBjts4XSCTl8XQ49xh+QPeLAd9pt5gEf
         BNKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=2hyXuFy+;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:from:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dSSdjynKB6vrqn+vQ16QQ4Bf9uSLW938ahxOi3n4FpE=;
        b=mmE2qvftPZ+SJ9zSAzhtoQu91/1glUD1N8cJ6ObwGERxVby3xDGfKSqdELqzuoj5Xf
         3LTqZ1T+rlKXuKP1ZNzt5RPi7y3j+/Xo8YSIcjTU52j17mrap2vEPUwo0CMo4twN69ic
         zu2FT2CYPDHwBqd3o71UuKFhpJSffkYgpyfHt36tnE/uqc8LPlFrBOKgRyWhxAZyWivs
         9RYa23TIKd0/sBGPvv9DRlUwpGwcv4ALvVbiEkxCY+9B48s5ZeQoJzjDYwy7qHCA2MCH
         RuPymLbOKLx+gPzz4RqMuk1GoG6J/tMvBAeRC4YczsbipfJMqQD+oJR+Q+74dU7fM6zM
         jJTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:from:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dSSdjynKB6vrqn+vQ16QQ4Bf9uSLW938ahxOi3n4FpE=;
        b=Tp1/k2hh6wMnrlS6O7Sdt1W70IhNLqn1hWJIjU7gDnTX4n47TMYMhY5Kycgz1QMHYT
         vX3NxAoiTT18qUMDqUh5cqh5qH2RuEo+I8ZKRGMMR7ZML09/7LR95VgUCBeCNlyQPokA
         abf1TI1EAwjFUmrr7cDoRUKbKeYk9bQJyxLW3AcK0wV0kbdc8MpM+QXJOHvSt5L4HQNI
         Bmw6qMsx/i6G0exGS0FdjTlnkcc7nU/gt9udIPOgNwhyWpB209BCB0X0XdOtf+/sUh+x
         ghDGbgL6QAyCpd0HkgpXepCfILlqnnpA7w+7KklzQb0HeDDU3A+mULe3rSRDlx4mBeSK
         aaHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NXCxQH0uguHjgTT1bK3Ulj/R3keLV0wz/Fz7GDEEdQPdFVaCI
	Km60DiKxAB9dmNfpq5V512Y=
X-Google-Smtp-Source: ABdhPJz/kBj8ZCKaZMng4Q8vHzfOvs6E4NtHQ91ASG53QT87csXQMkPfJIJ9TTsjXg2rivGEA5YsaA==
X-Received: by 2002:ac8:3674:: with SMTP id n49mr2032292qtb.385.1603375040325;
        Thu, 22 Oct 2020 06:57:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:34b:: with SMTP id t11ls871609qkm.4.gmail; Thu, 22
 Oct 2020 06:57:19 -0700 (PDT)
X-Received: by 2002:a37:b782:: with SMTP id h124mr2587708qkf.169.1603375039675;
        Thu, 22 Oct 2020 06:57:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603375039; cv=none;
        d=google.com; s=arc-20160816;
        b=ACkwUTZm1OLHcTAf+HfH/78Vujc8W+NvKyxBwbv8MqXsUSMLMQ7d9d5JjNDF1DO2KO
         2LLA4Zfv8zDnU0IXBQ2VmgTa3UMWJZ5e0ErSMh4BMLcxyYXc97flQLArpXK++U7SKJKu
         +M17eIJMsX44nibSHqpKIU0JS70rTZood1+4+LP+4cFA/g7IqeGUCQTXA1hBDRQiXFR/
         ZdgP0rePUj6TZJaOT9lBmNGGkflkWHw5QKd32hvyL7gySCjGF7zDzHTZFEmSfzXdDVgI
         IsbVjdHQNA9EHpr3b7sx9yreR79+DfOud+rwMFHwrybsriLKpvvaL8aQZvZbZkJ/+R/r
         DmlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:from:cc:to
         :subject:dkim-signature;
        bh=QcTx6boqAFKhXr2Q3yPzK3dPCtJKfhy8CW+TWKk2Kok=;
        b=HPDnCmMoI7Og6yPkr7w/hZFRJVNik7immejLNhRrujC0clmLqTsnrKz08cVUNaFWo5
         wdmD9fd5Qg4QXiEPhPpPlKfKx454brjhSabfBYNlXxXQXm2dk0uwWMzLqmuVwQU4yvFz
         VBknIdQIxen9iWseco+QhsCMxuDY9DsrNRyeEvr+Mr0XUq7+IETcdvAEgQ2yqLRG+HQ4
         x7M2S3lOSzhznItiqPPWyUvoJiD9poqDfZ4Fh1k1xBM+zXJ7r3Z7jOKPgasx0ZyVJexm
         Lv1AT/uD/XvL1NwPPxgv1fQXnQkGeJ376u5XQmodbcjxtQ7q1VrUCLTC3m2m/dFIW9LY
         4uFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=2hyXuFy+;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s76si110444qka.5.2020.10.22.06.57.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:57:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (83-86-74-64.cable.dynamic.v4.ziggo.nl [83.86.74.64])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D23AF241A3;
	Thu, 22 Oct 2020 13:57:17 +0000 (UTC)
Subject: Patch "x86/mm/ptdump: Fix soft lockup in page table walker" has been added to the 4.4-stable tree
To: aryabinin@virtuozzo.com,ben.hutchings@codethink.co.uk,dvyukov@google.com,glider@google.com,gregkh@linuxfoundation.org,kasan-dev@googlegroups.com,paulmck@linux.vnet.ibm.com,tglx@linutronix.de,tobias.regnery@gmail.com
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Thu, 22 Oct 2020 15:57:38 +0200
Message-ID: <16033750585384@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=2hyXuFy+;       spf=pass
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


This is a note to let you know that I've just added the patch titled

    x86/mm/ptdump: Fix soft lockup in page table walker

to the 4.4-stable tree which can be found at:
    http://www.kernel.org/git/?p=linux/kernel/git/stable/stable-queue.git;a=summary

The filename of the patch is:
     x86-mm-ptdump-fix-soft-lockup-in-page-table-walker.patch
and it can be found in the queue-4.4 subdirectory.

If you, or anyone else, feels it should not be added to the stable tree,
please let <stable@vger.kernel.org> know about it.


From foo@baz Thu Oct 22 03:56:50 PM CEST 2020
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Date: Fri, 10 Feb 2017 12:54:05 +0300
Subject: x86/mm/ptdump: Fix soft lockup in page table walker

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
 


Patches currently in stable-queue which might be from aryabinin@virtuozzo.com are

queue-4.4/x86-mm-ptdump-fix-soft-lockup-in-page-table-walker.patch
queue-4.4/mm-kasan-add-api-to-check-memory-regions.patch
queue-4.4/compiler.h-add-read_word_at_a_time-function.patch
queue-4.4/compiler.h-kasan-avoid-duplicating-__read_once_size_nocheck.patch
queue-4.4/mm-kasan-print-name-of-mem-caller-in-report.patch
queue-4.4/lib-strscpy-shut-up-kasan-false-positives-in-strscpy.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/16033750585384%40kroah.com.
