Return-Path: <kasan-dev+bncBAABBXWUXOHQMGQERB7BTZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B67654987B3
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:05:18 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id s16-20020a056512215000b0042bd76cb189sf9415279lfr.6
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:05:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047518; cv=pass;
        d=google.com; s=arc-20160816;
        b=C9SJ8ZE2qTkwtibM+H4Jt+gPK/LSMHg/Yy3ttjo4RNEylJG4KtdYI7t6w4tKYF/UqS
         iWkjdND26Z1pY+GZbqn6GYBoTMhwHjSstqhF2j+o9jzeK45cQq904ts7nC4BeT7UUUfh
         Q2QZBBwhCPbd7oyRO+vtcw09xzaxxTJFYRqnqC1bPqHMl2KGFhPwqXanzqZwttSapIcK
         i1gviDUhzx8jftE5UZ19+uPK6LpJUjPI9P+vEz5vzuly8w9TT0h5aAa46PMG+QPDd+NU
         gJN6FZfz4DlPMVJucJ5/VO7fxWf+r/6jSOBCLRaJQ3hCPaGics2Nz5VrgDmegK9q/kiv
         gaLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jBIBiQoIUQUVNX28h8yeyArzIWBc9x8eGrRSemwSzUE=;
        b=ZRuhDMeED6sVCHDcCdpm3vuH/God/pMZ2h+nLzruNofSN/8LBme+BjKO3FzuHaoiDM
         yIIOpuM0Lv814LS5drwwCcia7JpocnCT10wGKNKid8IqS64BnO8HCImEhsLlzI2Alk08
         SSnqpAv+engT5lm9Nenm5UdQT6Ta1Zm2rCfoiI1CwnxXyLjFSNgi/L9bQwUH9gjuMobL
         zpaxM7SulSyUReUvsd2CIi5eRBNRurY0Nf+FV6sg5V5K4s8Uad4EcyAycj5FeIIU4XsD
         AFY1xVsRZ4TPpxoDlEbb2DInSFt+FO89MIpejeHz6a7PNJJtWoHx7mcNN2BoFmU71YOb
         /nGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tbxWzIiy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jBIBiQoIUQUVNX28h8yeyArzIWBc9x8eGrRSemwSzUE=;
        b=itOmIUVPOnUkAeBaA/YQYYXMO2a+o5OMYSEasq2Pa+wtSaNIFGVFeVkcR8zRHRnvhr
         TfPtp65zfkGmybD4/VC4skwU8Ci6by9n6TA0DVpL1kpDmzNPciNf076kVuZT8hnCG7pD
         cRn1qKjKUKZb6DFMsmOj3Tk4S8hXaIZ49rCA28/m7uOnklgV7fpD85m61zxfbY5ikEWn
         g418AlQp4F/JRHFlZfEpGBC4v7+MWb16tb/hpdvAiwzGmUsaHh8gaIrpgfIoNXjFW3Td
         hSdV7CwSCseRKlwbiQ7j0sZNbeWVuXL267gWmFxgkDO1OxJlmJgIWBHI5rXNgp6tKVFt
         yzHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jBIBiQoIUQUVNX28h8yeyArzIWBc9x8eGrRSemwSzUE=;
        b=PiXPiPGywhrR6QLkarBq1wxxwDz205g+3MiirqIj+S85cfdftkiDmoHDDXpGJ33Skv
         rZGl8dZlS9P7eqWAIdKApvYgjftk5b8fSQdYfN9u60ogBYy2bsO4t2Wq11354UjsGnD1
         8T9AiGE40Hf6hVHaarZZocBbSM40DtdHLAp77fPNIFOE3C2qz9pzv/MYwmr5mHoYX/Jv
         cX1rPeOU3pJ6Xr8ZGKdd4e1gY/ovT/yrpGpmjtar5fbiAKdfKRQ9Tn5bOXvYFq1LlXSB
         +mR1F2YCy9M/jhzc1VYkMfJosWlYrHunICaV+WuaN9/S09Q7CzuSNwoXs43VZC9ITP6l
         eOtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OSATXCZ0xZ8odsTIcqKExntr/kSvb/mwepAZhn/P3TD6sNTJ5
	+gwNgt1zfh+5sCn1+JOBu/c=
X-Google-Smtp-Source: ABdhPJwrK9XErGoP/hVRMgtl7h37RAXH7TpjU12AI/3CJRe/LxQoDsQq0TIRekS8Wt5LzFP85o/2xw==
X-Received: by 2002:a05:6512:3994:: with SMTP id j20mr7237856lfu.449.1643047518194;
        Mon, 24 Jan 2022 10:05:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b90:: with SMTP id g16ls572687lfv.3.gmail; Mon, 24
 Jan 2022 10:05:17 -0800 (PST)
X-Received: by 2002:a05:6512:2626:: with SMTP id bt38mr13846280lfb.255.1643047517536;
        Mon, 24 Jan 2022 10:05:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047517; cv=none;
        d=google.com; s=arc-20160816;
        b=aydqtP2HNu1C62Qco6l34fKgWYzwh+DDD9vfOwZuDTEM8gp2F3ywqyNUxALb3k/+xG
         hKazUel6LBKXE39GDEJpPQ5s5yC+8AxvFV0vnVteqMay1aYXblQMdxx7P3XIl9YoWDVP
         t82lNVL4jLgIS8rnqHiiTUyfynUdOvjRq/TUOE//AjDwxa2Jrutkn/nFOY7lF93/DN/E
         SJ48bngc2gh0MNpqGHtFnjoX4p6z25JslENIcRFocTt3j81XPwtZvzB+4wLs8GrG+UZ5
         JlfJWFLNn0hIk2LjcfaY8o/ikzve4QSMPBobaigmJr38+iL0aJQ6KIbKtUBgauvOTgMP
         9g8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9A/aiRr/eeAtuJgRH9CgKix3liywKVtjCGXmP7PCGKU=;
        b=Rbi/PmyKLV4S8RhhhZWNIRT30C8iStrbe6dQxze1o9oG4BZA5CNlfdVGWZ+47P/88z
         t3XkMU4gdgN0q//Jm9aNntt6vQHYZ3vbu+yW2gtVvg1AlgjYBMxIT4w4ZiOYcuE4hSRt
         0ZAw7zZq8cMGWIqiY+opWm8ni0rmPcVdBmatlAb2f7CSLDNDv+YimdbVz3FnAuRoIjrx
         NOL+QLiqJUiZkz6CMrkHSE/uUs389qy642ZE9n2o6kbeZTGeFsgSwtiiMqpD9fpgnygt
         flP9En+KCpLWp+0S3QF5/eKTKmyjutQ+iZjntbCFUBnNKwODIMT15WzVWYFxDT6jPa4N
         2VKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tbxWzIiy;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id i10si576709lfr.5.2022.01.24.10.05.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:05:17 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 18/39] kasan, vmalloc: drop outdated VM_KASAN comment
Date: Mon, 24 Jan 2022 19:04:52 +0100
Message-Id: <780395afea83a147b3b5acc36cf2e38f7f8479f9.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tbxWzIiy;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

The comment about VM_KASAN in include/linux/vmalloc.c is outdated.
VM_KASAN is currently only used to mark vm_areas allocated for
kernel modules when CONFIG_KASAN_VMALLOC is disabled.

Drop the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/vmalloc.h | 11 -----------
 1 file changed, 11 deletions(-)

diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index 880227b9f044..87f8cfec50a0 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -35,17 +35,6 @@ struct notifier_block;		/* in notifier.h */
 #define VM_DEFER_KMEMLEAK	0
 #endif
 
-/*
- * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMALLOC.
- *
- * If IS_ENABLED(CONFIG_KASAN_VMALLOC), VM_KASAN is set on a vm_struct after
- * shadow memory has been mapped. It's used to handle allocation errors so that
- * we don't try to poison shadow on free if it was never allocated.
- *
- * Otherwise, VM_KASAN is set for kasan_module_alloc() allocations and used to
- * determine which allocations need the module shadow freed.
- */
-
 /* bits [20..32] reserved for arch specific ioremap internals */
 
 /*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/780395afea83a147b3b5acc36cf2e38f7f8479f9.1643047180.git.andreyknvl%40google.com.
