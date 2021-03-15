Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBL56XWBAMGQEQUQ7QDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 296F233B3BA
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:50 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id v6sf18248842pff.5
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814448; cv=pass;
        d=google.com; s=arc-20160816;
        b=mz5TJyERc5Ef7Ix3zqWPzqfte5ASBL2a1jYSh7oR3aw29lM9GBAqfDXHSWaNagsdWQ
         y3C8LfDA+DtzKYyExIUCdU+r0B0Wxso2S1wivCFxlPf23KRIB7iVHQUnz24NDdkFlt0A
         hQPVtxRIsrmKh0EzxwCOkLXfGbq1EmdRvfDvAvOysy3gZ3ZzNtTAQ0vmWlNS0G5Bi4fo
         F59cNdMobaDn2H5Q9mf16GDD6G2GIwpX8nDhJmO4Pz3tRCiWHn60qHat7Hg33WD32zXx
         PmNMkQClfQ3+tA7ImGtGTa5pcgL1b1NglHkJZLkUc99Rrj1ZUHLUMMnQIpNhSFcnEK5E
         rNEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=I/BlHYunlcixMKPpIkSq8/Lx6FJemoJQ5aBZ7G5n0RA=;
        b=bPWlRWggHsXZCPlvwAk2bAH1kjUWpdhDJKvTbaKFaRvl2RhUrduEtzjv1U5ZQrsZch
         top6vuTQT6mxUe/56qFPvf8OGtaVmHrbCHZIEFrwh6EPxX/rS7126/F+Q2UYSIXdcw/s
         HGfpIfqMLefORje+zu8IDES0eHDM2H+OiwQvQ/daAGxngZt4gxEaqUMp55bGcNeRkNAU
         6bXP+rVuXRGDdmyi+b97gBmTuvcC36fu1oYfZw0Qqo7XYlp7mUUa/3/bBZWRkUJFq6ZK
         3gSOVKhS9KmNGTlm09ZYRGcP2TSShw30r3WD47no3nCp2e6IgAB3hbxxZA+rGGJAm9Hf
         h2jA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I/BlHYunlcixMKPpIkSq8/Lx6FJemoJQ5aBZ7G5n0RA=;
        b=jeU/Rd/o74WEiXGCwZ46JBwkgzhKUx2alcgPj+USh70sr4LRFftkCbIiVqey0UdSYb
         /nwrSx1NDOinUYXqzIYPp/V1NxQeFvhvoY1uRcCu8MAv1VdYP+6hSasEIqxl8EL14QW4
         MQmVus+BGqxLVF1GC7C/QcOzCqbZP5wgsSriKj3GmwsuLv8f8KqZC865HjWhm6cThTIt
         SMAvbNkf65hqR597wcVUbPDhVFscyj1x8j8pQqHsHDEs3rVoE/RGNb+DZXsYcLDHu5xk
         +aFzB0AYus/YRGAX0Ci/KMpxIBFPkqYMOgl0mqtwnNetln3flmbZ1Wgg/Uh3COxVMtFN
         jkDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I/BlHYunlcixMKPpIkSq8/Lx6FJemoJQ5aBZ7G5n0RA=;
        b=pkmVwe/vIfi6KC86Gfw6GnUjDzLTw/Y39wlrnERQaX/M270upkeOPvu/E/AzhHxdmh
         nx7hJoTtk5Aj8XZ7Ec5uip23dQDO77EOnurQmpwIspoekMs+X9lfb+GMZ0jGGPGh083u
         HwN62RYmUMEIG/oN1U6y/aBBHndWmSg3HMOrpCjmbCySvXU9I2pLNCBdpag9gfCEfZWe
         sWXH4WPiEYIbauGced1Z1hp7tXKsQeYcfPreEeqI3bIc5WhPcVZ1AK0nKY3l25m6RoLR
         wIm1fwyGtGoTi1UTyD/3cZhWqAuUMqhGy3IxOriY2/qr752JYQja4haYfY0EZbBgAg26
         lpWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vrznySVrnluup14AmodtAOTDT61zBZxIwfjNJp6YmZO8CFscY
	Ok3UqBg2bw1WYEGfPh0ckoU=
X-Google-Smtp-Source: ABdhPJxka4EQSi4k5AzSsxWuaDKI5uVqVyBhkG7jw+6h0tqRWOAjok7eJaWBekDJYWPcoOlwSFA8zA==
X-Received: by 2002:a63:5b03:: with SMTP id p3mr22621383pgb.27.1615814447517;
        Mon, 15 Mar 2021 06:20:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb43:: with SMTP id i3ls8778142pli.7.gmail; Mon, 15
 Mar 2021 06:20:47 -0700 (PDT)
X-Received: by 2002:a17:902:dcd4:b029:e6:5398:609f with SMTP id t20-20020a170902dcd4b02900e65398609fmr5047980pll.58.1615814447012;
        Mon, 15 Mar 2021 06:20:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814447; cv=none;
        d=google.com; s=arc-20160816;
        b=UQUUTYdcbApUieZMgjWnLcZppQ/nVOO1omyX0rhb0lZrKkUMbd++irf8E43NPzg3CA
         xDU84GHGcFvWy7XgKtHd7vAQ+7Puz/31vOVocT7bT3uQEO1DcrvCEudb0nIiELK1rup5
         7xf6AqpugIaT+C3G/ISXiAE6fCccgdkPTsbvnopxmahx1Pjk8gmel4TgFO+Mwe7EzBsM
         Nf6J1COCgi8wHGMNbUxwuaYh3XXnR3M8NSKeoj9kvBRcsomSi/IlLfQUzGf/7YXGONjp
         ZgVvNAS2TMAiuojbK2S+8HGcGBbg/MHpHGlxHVbFQDXu6fW9H6ykPDG/WdlDLN2HbuXW
         GUdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=57zkMzGm47USvK+Sjko7JpM8wOejFzrsvvPjyxCaC+g=;
        b=aR3o8Z+ATz3UuZOlvM8n850pQrxyYsxWKCPcgnE0qFd2Cog9raUdfMdvtkSeHr3m9F
         WYSwb5gon/+me6Vzy05oKxt5JVvepvtty5WtY1ufN4oLcI8CRly0Oj4NvMd5jou8s4ES
         zcm4bcxFJKIvahDEnwP3ca/uZEptFHa+1hVt01BAVWtBT2nbw2lH8Kb1VCbECDDC/2nu
         oqwnokJuOyoWB51NuipvUfn5QZFle7eJQ3lPZqDZL+3maLts/MMNp57eAnMlI4Tyw2NC
         pjs2VhqKm0tuH5dhvEA4ayWbzXe65vLEf3P1oQk62EzAvyU3YJciZzEc57sjpeqgDU/Z
         de4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h7si860583plr.3.2021.03.15.06.20.46
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 102BE143D;
	Mon, 15 Mar 2021 06:20:46 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2CFEB3F792;
	Mon, 15 Mar 2021 06:20:44 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v16 8/9] arm64: mte: Report async tag faults before suspend
Date: Mon, 15 Mar 2021 13:20:18 +0000
Message-Id: <20210315132019.33202-9-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

When MTE async mode is enabled TFSR_EL1 contains the accumulative
asynchronous tag check faults for EL1 and EL0.

During the suspend/resume operations the firmware might perform some
operations that could change the state of the register resulting in
a spurious tag check fault report.

Report asynchronous tag faults before suspend and clear the TFSR_EL1
register after resume to prevent this to happen.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h |  4 ++++
 arch/arm64/kernel/mte.c      | 16 ++++++++++++++++
 arch/arm64/kernel/suspend.c  |  3 +++
 3 files changed, 23 insertions(+)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 9a929620ca5d..a38abc15186c 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -41,6 +41,7 @@ void mte_sync_tags(pte_t *ptep, pte_t pte);
 void mte_copy_page_tags(void *kto, const void *kfrom);
 void flush_mte_state(void);
 void mte_thread_switch(struct task_struct *next);
+void mte_suspend_enter(void);
 void mte_suspend_exit(void);
 long set_mte_ctrl(struct task_struct *task, unsigned long arg);
 long get_mte_ctrl(struct task_struct *task);
@@ -66,6 +67,9 @@ static inline void flush_mte_state(void)
 static inline void mte_thread_switch(struct task_struct *next)
 {
 }
+static inline void mte_suspend_enter(void)
+{
+}
 static inline void mte_suspend_exit(void)
 {
 }
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index b6336fbe4c14..820bad94870e 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -265,6 +265,22 @@ void mte_thread_switch(struct task_struct *next)
 	mte_check_tfsr_el1();
 }
 
+void mte_suspend_enter(void)
+{
+	if (!system_supports_mte())
+		return;
+
+	/*
+	 * The barriers are required to guarantee that the indirect writes
+	 * to TFSR_EL1 are synchronized before we report the state.
+	 */
+	dsb(nsh);
+	isb();
+
+	/* Report SYS_TFSR_EL1 before suspend entry */
+	mte_check_tfsr_el1();
+}
+
 void mte_suspend_exit(void)
 {
 	if (!system_supports_mte())
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index d7564891ffe1..6fdc8292b4f5 100644
--- a/arch/arm64/kernel/suspend.c
+++ b/arch/arm64/kernel/suspend.c
@@ -91,6 +91,9 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
 	unsigned long flags;
 	struct sleep_stack_data state;
 
+	/* Report any MTE async fault before going to suspend */
+	mte_suspend_enter();
+
 	/*
 	 * From this point debug exceptions are disabled to prevent
 	 * updates to mdscr register (saved and restored along with
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-9-vincenzo.frascino%40arm.com.
