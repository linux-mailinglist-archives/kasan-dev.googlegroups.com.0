Return-Path: <kasan-dev+bncBC447XVYUEMRBT5DQ2AQMGQEA6V5LGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AC3F313F05
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 20:32:32 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id o17sf13915789wrv.4
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 11:32:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612812751; cv=pass;
        d=google.com; s=arc-20160816;
        b=remZMgFMmNkl78N6JrOFtCYySmBoyqPAUt3JJAx6oW3PURl95t0za9JLWO+7edmBk9
         DGXEYGP6EshVGeTI8+NDyVQMW6DvGKwSoyjhN9X9AIm2CEdbbyl9anDPaq5eoOasTesK
         O2q253kulREpcxxRhVem5wVhqkUorA9am3/AyGN1GDTcq9VWsxGMVpCzBcCMMRkHDNPe
         03tUlCqZFylhVSVaQCXdOl8ixrnus5p3oPoh7wg6tTXyvNoy8/Tmz2u/yptpuTOUCjbq
         JDuOs2aesuQGVZoTFsBUT1g1HxksaOS7ooJU0TQOKH0fOSynulnGUjQ8978mbgsmvJZG
         Aneg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WoIV6Ofs4D7qin/0SLPJ9meXxVjcCKDkwZO0lEauPRU=;
        b=upD4BWbC9EjDrrDAe0b5if34Ud+CcIy4bxjQA3ZGJQYQkGge7dKfYqaF6HJvBMXWfd
         Jbpk9fpOnqkl4UTDSJe5orL2m6d+hjpeHgokI5uvC/kDf2v6OAEHzAX1f9Y9Te9362FE
         r8Gk1vgqVIAvqnv78Qv7jEhKD5Yb9Uj62nwj31YE9VOAZ7em6bwztono4aILQTKuVKUn
         LzLBlVJNYFJVXAVHS/sO2Hw67AtEz7MIr7J3MM6oIMhPIhbXFhvRp5/Om8iPOeMgAarV
         Q9usoKqo1e2j6jPjvP12O1/CEjBQADSLfHwfsaaf0LhndVa6kh2nAvK8eZPqMbFcn8fj
         Sf0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WoIV6Ofs4D7qin/0SLPJ9meXxVjcCKDkwZO0lEauPRU=;
        b=MvZSUvc89l/1Rpgmd52bQT4Qs+BYQLZH25yAlk0aTPLXZaltllVgjxcjNx8c27RQrd
         DZ/aeaVEtJEs0gal+/lsHBoP/0M7COZutnxmdgOVFvCPBgthbpIKM4LKwArKjKHPwi68
         j3su0nL7Uqgz2oJ3g+OgGxGhdjCTpyK6RkS0ozSq7dpcTc3DWSsWg7BsdT+Rgy/6suSj
         fKYI+c6RkiuUYk5LLGHdWokL0pvFEpdjK8fpBKJn9pR9aIG2CPPqrvisUR4zAaiSyatr
         vW9rd8WxeF/ubtqlzflZRO0ZRJ9Trzd+dGIRxT6RPsEThAor1eiMB8bAs5Y+P1A1f9tS
         PJ/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WoIV6Ofs4D7qin/0SLPJ9meXxVjcCKDkwZO0lEauPRU=;
        b=Fs9tm1I6TAcJJNcsk8TLc6J1Zcqj2mNlmyleFu2cnTPUzjZSm0i3iogHmPb7rHGlml
         wemyAP4x0/oCmqpE/vZAqG+KVatdXHziAd5f+/8LMUQEFQoCdMDzzthpHO+vY/21ssgk
         BBOPy/dEEZfcKAuvf3kGi5Nh+QfJGpX6TZzXsz40MVSzhjF4AsKPDD6varPneqQTlrbq
         Bq81r5jXASuFmwVxqt9yxlvge12Z5JScffj4qmFEFgrmTGLIwHMjxakzT2m8xIP9LB76
         sj+Z3mxnH49502TtnLaMdHZEuAIo+QZeqAkgMZ+MxGNMTe2aSl040jVNOlZVzeleQNzY
         791Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333XG9rxusNORBpQAZqg9m8MhfRwAe7o2xEI6E3Mvv20AjSOSuV
	qIMeAVg56mEZyVTpro+N49Y=
X-Google-Smtp-Source: ABdhPJwF6n/fJJ+CglRW7IokPypweqDklm5rvB6ZbtFqQIGVc/xksgY/mAkNiEnbgVM/vdCOl+sLNA==
X-Received: by 2002:a5d:610e:: with SMTP id v14mr21916547wrt.336.1612812751847;
        Mon, 08 Feb 2021 11:32:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f88:: with SMTP id n8ls105684wmq.3.gmail; Mon, 08
 Feb 2021 11:32:31 -0800 (PST)
X-Received: by 2002:a1c:356:: with SMTP id 83mr314751wmd.31.1612812751145;
        Mon, 08 Feb 2021 11:32:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612812751; cv=none;
        d=google.com; s=arc-20160816;
        b=paC0LE7c//VGCdy8Jf6Xvli2pWg7tkkMO5dR/Uwx6Rs245n3MiZN649kBPbQjDm/Gr
         wo0stde5ERlmt45i8cIOmBKK74ODdhae5roNvrMaY0kOazI70ybzC77K+biR7fFotzZ9
         3kyAuxEryb+mjfQrrjLbzHNJXQQjeG6pfDxvfqRGoxqUUoK3DEC6aAzFk/31VP+weLyX
         1wSc6GMz/dWVE2ugJj8ZimaegTUWjBOVwA92mv/LMkNn6IL7mvXipcfHp8r6kpycLO5Z
         EuLKZ1orw+/tyjAU0t5RpjwwGE/jUmfjdYD6CZRwla5yZEmveedaVe5/SISu9SzYyWdm
         nKqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8tJgeMwHEnTrMYaq3sc/Gwc3+jwtekWJatbRqm4+Zns=;
        b=XCi+IPdxRi88BBlD2C5xOyVTzBNzLbexwOMLLg+2hkp6rwqGU+MikLAITbW5BLrGgc
         yvTETghxcPQlO32QJlzdyPpMxTCF57vuX3pNOHy+EvlW/6jRjW/0bGRCHHSWrHFRW+fV
         1K7R/xDnRlIsVXoO+NvOQyW28g7X7rLzw7MEhro+JHQ6tzZYGf5ujP6WVPY23tZDtwSO
         ZzaKcrVpfz/XqXExdtMO1XVhFRNsrWcD/vrtNmX96OkiSBbHZY2z2v9sWljMg+SGZ2RG
         m1S5YSQfoQRIH7Euo3S58/DAQxQJqlR//+FlojjEKVQ8gHV43INlIYAmSBVOxUkr3W/Q
         vpZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id m3si7703wme.0.2021.02.08.11.32.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 08 Feb 2021 11:32:31 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 287DA20003;
	Mon,  8 Feb 2021 19:32:28 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH 2/4] riscv: Use KASAN_SHADOW_INIT define for kasan memory initialization
Date: Mon,  8 Feb 2021 14:30:15 -0500
Message-Id: <20210208193017.30904-3-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210208193017.30904-1-alex@ghiti.fr>
References: <20210208193017.30904-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Instead of hardcoding memory initialization to 0, use KASAN_SHADOW_INIT.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/mm/kasan_init.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index a8a2ffd9114a..7bbe09416a2e 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -80,7 +80,7 @@ static void __init populate(void *start, void *end)
 				__pgprot(_PAGE_TABLE)));
 
 	local_flush_tlb_all();
-	memset(start, 0, end - start);
+	memset(start, KASAN_SHADOW_INIT, end - start);
 }
 
 void __init kasan_init(void)
@@ -108,6 +108,6 @@ void __init kasan_init(void)
 			       __pgprot(_PAGE_PRESENT | _PAGE_READ |
 					_PAGE_ACCESSED)));
 
-	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	init_task.kasan_depth = 0;
 }
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208193017.30904-3-alex%40ghiti.fr.
