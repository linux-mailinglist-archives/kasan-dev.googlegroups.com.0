Return-Path: <kasan-dev+bncBDQ27FVWWUFRBU4I4XUQKGQEFTIJNXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 251E07469F
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 07:55:32 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id y19sf43648860qtm.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 22:55:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564034131; cv=pass;
        d=google.com; s=arc-20160816;
        b=WbhYXHZdqgUtUFQwRZdCTPQp+Nn+p2RXTm+e8DWSUCi/plGvr7EhMu12iKxj25xNdL
         aqzpQVjocVlJ4qm6gWwMMYt6Fu18VgEVjIjcIOaydAc1OINAzk2YX7WE2WgoDSoP6nqp
         1C88X5WGxItCdRjt6fXJHrrGO2mfAvkpaBJ2iJrk9QECPa2dUQrwribS+SghmOIsTql+
         yvUvxUwBWr4f9MPcE9c0bUlPT53SQ6gXq0gJlbgKZKSs0EK09I4eWN8xQ0TbBIEVewNp
         HwZrOhotftmSLe3I9CKaCZn+z1jKcyCRNKu0dbUKa408Dbg+kSoF03HrTSguA3hlOmbg
         Q7zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RLL6tR/PPOYoKjxImgSK4yczlF9EufBdfsGYLJITats=;
        b=whi99mjTxcKoFHEX0GnBj42b9Aa0XgbOFEHbHt93Zrg76qep0glRqUdeifHRFEAw2g
         9TuW6qTcacix2CZ06gjXqXixVjkCoHEy9hIcaamng1k+yl7p83JG6z0fjTMNW4dIhIO9
         iMhetg4Zq3nVroG2eVtUJk8DZmcIevbyC+QjA+x/TxPfqWe7cMgYVNZb9rP7okSBj8c8
         bQf2JMy/HXoUy8MsDfHiAlccT5B43Q/04PLeRc511nHvYc9QBtJBeswZF2oLkLmK+9t0
         Wow3bfXQXfsyPq+X723JuYxg3tcUnDzz7ZE9HogrFcGAK8d5Ukky+9PzEg0/BN29fJhq
         vB3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fUCU73su;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RLL6tR/PPOYoKjxImgSK4yczlF9EufBdfsGYLJITats=;
        b=i4AZiJi+spH0+tW5Rs+Y3/yiHi99smeHcyVC/3pXsd8Vy5u757Eed2QHmAEzrkq/XN
         Ev4cqmBaMnf+GX0KH9q8xMSD7WC2W10jJ3S6jFcpjTM8BN37xZ15UsyeYuml6rRLHxKN
         i+PpOEN4G6x0Q+Sp86xFu8sfw2b7mg0VqFH1PrnOVVoRkNiqIPGNZQu48SdVEbTNF48R
         D6ZcxIsZDDBBLMXgNeikSHwy/jQrYeu+P8FyfyCh2gRLhuf0iXZTN0XngSgv/DloyHUw
         BR+1iuqJJI/3HOPuGU3OCx64NIIM5Z1w7Ut/kNa/1qAmLoOZfw5cQhXRW4b889CJa5RB
         kjOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RLL6tR/PPOYoKjxImgSK4yczlF9EufBdfsGYLJITats=;
        b=Dg0Ew8OM1q2f3OzrEoS8ogweLIhYm8nM5vnUW6PKLgG9z47Y2zOTaqN2DBRNIFkorg
         jvFJLiD8p6Dt7LizcG5GW+wYcR0LeRNZfcr0hdVg+czrlPw+xeOFcu7QM407nJmLvQsX
         PS1SLAAyE0KnjDtCo3qaglXuHlfphKMbEnARViSohtf0V0BedJBsPBMs3Lt2rhqIsRb3
         LtDsDexJuw1WL7/Io3Y+WET8WcyvE+Vg3rLQ6kT6lo/u6xQ/PQQ5dGP0BctXXQRSamHD
         dqyiZUZkFD6pEzzG4mMyjMG6wz8tn3yX5i/yUk2OBmJ0DcaXctt7Du2AblSeumdQu5jk
         XoLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWZ6XT0SLenR1CqWbWhrGN3tSXjx6GmEEvZx1lbuWcZf9eDvM2W
	qSDK808GH9SI5Wmtv8clqx8=
X-Google-Smtp-Source: APXvYqzT3WD0eVOOQfVglTNm3Ux2EsCK88y3GiFNDlyLIlYcv/1zhxGr85+B0wU1IkpBQ72/KOrbjw==
X-Received: by 2002:ac8:428f:: with SMTP id o15mr58047546qtl.210.1564034131251;
        Wed, 24 Jul 2019 22:55:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2c41:: with SMTP id e1ls6090qta.14.gmail; Wed, 24 Jul
 2019 22:55:31 -0700 (PDT)
X-Received: by 2002:ac8:317a:: with SMTP id h55mr60595451qtb.105.1564034131018;
        Wed, 24 Jul 2019 22:55:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564034131; cv=none;
        d=google.com; s=arc-20160816;
        b=YOfJ6r2lpMgQCphnmdz5tjjwJAQ/W39C0dNCZjvcfwHYNJh+PyAj1ZjONf0uHijGue
         P21b7EeZoNeKXk8EMq6ScidBRGDC/TrZnUmzI5X2xBb1AWGHBbaHwqvwOB1wMVMMtEK9
         PT5def9Zyvn89uRAedwpHUuDQW8uz1f8cjnW7GYPZvVxMzkeyocT1S5hslvjSy970ZKD
         CpLj/75bUhbnNShMcV1H9qiKNtkLc+NRj93lQo6BI6CdkZEw6m5H7KY4vlEpFAwiVOuh
         FAlNEb2QaxM+bi52o6LRh+OjwwCzeK+hT6B/jZ+0IIz8dJnPAkv587ow0PUwbX4td4io
         dW6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uEzjuY+xrs1gxfJkRlgVH6ex7tEhwAMuVuUkA64XteY=;
        b=XVume7zqIgbHV2IFioITl6Dw7IrIgS9W4dZ7KCnCi4OddMTUXzTP3S4fV8YpnBuEY5
         cLQBwkvi/02IeSmdIiy5UzdMKejrdCZp9TjgM6vqkZ7c3iXtZfAedn9WzqjOm+Xaoccw
         K9/z4mXog+p2tKhh0YpD/ayCh5YzNxV9WKQFlgCGQrpNneyXWq6aWkmQABNRVYRfGmYT
         rEIoehh6q+7/sv21Oa7usFSrZyfQa/R/YH3jT8A177oJoq15L+GpsmytF7RHZwuybbwF
         Y6PilnwkvYFgSFdF53aXGEFr4wsXHlOQLM8g532oYDbQC44Z+FrpGrM1n8Ll6Airs4SR
         Do7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fUCU73su;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id w82si1965985qka.7.2019.07.24.22.55.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jul 2019 22:55:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id p184so22144386pfp.7
        for <kasan-dev@googlegroups.com>; Wed, 24 Jul 2019 22:55:30 -0700 (PDT)
X-Received: by 2002:a17:90b:94:: with SMTP id bb20mr92504004pjb.16.1564034129834;
        Wed, 24 Jul 2019 22:55:29 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id a5sm41554212pjv.21.2019.07.24.22.55.28
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 24 Jul 2019 22:55:29 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH 3/3] x86/kasan: support KASAN_VMALLOC
Date: Thu, 25 Jul 2019 15:55:03 +1000
Message-Id: <20190725055503.19507-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190725055503.19507-1-dja@axtens.net>
References: <20190725055503.19507-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=fUCU73su;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
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

Not mapping the early shadow page over the whole shadow space means
that there are some pgds that are not populated on boot. Allow the
vmalloc fault handler to also fault in vmalloc shadow as needed.

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/x86/Kconfig            |  1 +
 arch/x86/mm/fault.c         | 13 +++++++++++++
 arch/x86/mm/kasan_init_64.c | 10 ++++++++++
 3 files changed, 24 insertions(+)

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
diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index 6c46095cd0d9..d722230121c3 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -340,8 +340,21 @@ static noinline int vmalloc_fault(unsigned long address)
 	pte_t *pte;
 
 	/* Make sure we are in vmalloc area: */
+#ifndef CONFIG_KASAN_VMALLOC
 	if (!(address >= VMALLOC_START && address < VMALLOC_END))
 		return -1;
+#else
+	/*
+	 * Some of the shadow mapping for the vmalloc area lives outside the
+	 * pgds populated by kasan init. They are created dynamically and so
+	 * we may need to fault them in.
+	 *
+	 * You can observe this with test_vmalloc's align_shift_alloc_test
+	 */
+	if (!((address >= VMALLOC_START && address < VMALLOC_END) ||
+	      (address >= KASAN_SHADOW_START && address < KASAN_SHADOW_END)))
+		return -1;
+#endif
 
 	/*
 	 * Copy kernel mappings over when needed. This can also
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 296da58f3013..e2fe1c1b805c 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -352,9 +352,19 @@ void __init kasan_init(void)
 	shadow_cpu_entry_end = (void *)round_up(
 			(unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
 
+	/*
+	 * If we're in full vmalloc mode, don't back vmalloc space with early
+	 * shadow pages.
+	 */
+#ifdef CONFIG_KASAN_VMALLOC
+	kasan_populate_early_shadow(
+		kasan_mem_to_shadow((void *)VMALLOC_END+1),
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725055503.19507-4-dja%40axtens.net.
