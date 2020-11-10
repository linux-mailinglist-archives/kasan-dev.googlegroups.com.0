Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLNAVT6QKGQELVEAJPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E06DC2AE2C8
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:58 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id v85sf56865oia.16
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046317; cv=pass;
        d=google.com; s=arc-20160816;
        b=fGgbWtgs/YgtGo1I5O1UKpKtVV5k74q6GAp6oWmMGzMRKEHM2tm+MLSTeZpr3eHy2L
         zjxlrCDspPLVqRqcuyP6vujCqcQcb6VwSkIE9wHg44vd1xkpIbPC7lW4nPWcUMyGsOlL
         6e4DpG/FbDeU5rkGTGpCgHUQF/B/MTQ6jpdZm85gyVwfS4Il52129bGEpU8IRDLFyXdC
         gB6Ddi5ptKvJg5SdnpOMDo/yLn3Ts2aFXv5ldnf1aAiASrWhIFacO5cpP+Hr4RDtt1SP
         zMo1bi2McLW3KYkvTbinKn8BIfGA3cf3IOh+CkjqWyAo62lnvs7EsQMi5KPH0o85mDmE
         jVdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FWuM+kJ8nQUcT9zp483hqzAo72n1fVpY+7I1PccYWDk=;
        b=zfZCYMbMRfCImqJ8seePl1MAFKJFwMtp1afBh8Yv9qlHw3C8AmUSHZuYZnaUB5YGDS
         C7kBosNxZY3RW/bJzafEc5GH3P8aPOeNv/R6JgmvWvjOCk4qoWwcumMtoMhYNPgig2oE
         wkPXZpwQnhTlPvonKpMPNnbI0jFntjHp63Gh8CU1eTxFoZs90WufF7QxZmk4Xzx2lYcG
         Nzp87uvOpWOFUbdUJIUR5LkZEjRDNAO6sLlOZLyz6LkHkrd28AFaYaof6zNRlWmU1Z0q
         qUf7Rl3XujtpA/G7Ovw0cjaBLjiaqiXoh1PdFF7cB1RtSsx5te3YPhPl7eqrhWuJ/4Wi
         4b7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CLSgr8f8;
       spf=pass (google.com: domain of 3lbcrxwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3LBCrXwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FWuM+kJ8nQUcT9zp483hqzAo72n1fVpY+7I1PccYWDk=;
        b=PTe21DR7mmhuV7iexYgaus6fJC9dpmot3nEqCjMb75ynfS29QjrZjVeQ+pQUqwDLvl
         /1yHSEi5uvypbRKEwqsaY+2+4ex70xXqYpAXw405VYEpEf62jFJKWpJa+obYDPk57RJb
         PmXcqvY5/he5EgfakN/T4wsvUu5zoWAzOy9X9L2Dqrm71opPBNQi5q1dsRca94pJvcdK
         ppwlJVaXETgsz+Gz2/45qnqJG+E/hqZMdUaX+zGC6LdBfX6hQPotBSJMacFFrVOhVZB2
         rDFXIO879zbzhZTUbsXj5hWMQp2f247mhTXV9ftc4MuNRbDvFkIJHJ5O7O2ATuwfD6nh
         rs0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FWuM+kJ8nQUcT9zp483hqzAo72n1fVpY+7I1PccYWDk=;
        b=KdMMnrKe5eD/dyak41azVDFCvaSsOtITZ6cWhXh9m2XawZp3dCftrkNEA0rmJeCPw+
         Va7ICCfgKILF29T8FO30/i3Hh2RWePwIJVZqywyShYxb9PZMIiDRvTKqwq6asyWmpvdd
         k9HIvYOlZWlohgawEGtTah1sXlP0BKkGDIJQH5qmiCPj8k0WF7elKLqq4l3imOujUIDb
         Oj4Z5cEpouXj03/HzcVNGmgTdgCNNhQZpy04sZFri+Eakpi32ouo8FQD/31tRleXb5Nc
         e57LWftalpEpSr6Fm22sF4epqpdFJq0ti89YvS3uVMUjUtpzWvSRjea+GC7byGvy/Cb/
         gxow==
X-Gm-Message-State: AOAM530EXRDZxxEGu0cOZSr5r9KUYcYUD4743nVqU9b64UW75yPM0Qqk
	t8P1BSWcNNxrtsa79FB9z88=
X-Google-Smtp-Source: ABdhPJym1BvLv3v6RikGJjBPKNsmSCb+YCY5I2s31pLDOrENLdX4PW/sebcSaZ0NuyTLymN+nBQdEw==
X-Received: by 2002:aca:570c:: with SMTP id l12mr149858oib.105.1605046317847;
        Tue, 10 Nov 2020 14:11:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5214:: with SMTP id g20ls3415642oib.9.gmail; Tue, 10 Nov
 2020 14:11:57 -0800 (PST)
X-Received: by 2002:aca:38c6:: with SMTP id f189mr169053oia.27.1605046317549;
        Tue, 10 Nov 2020 14:11:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046317; cv=none;
        d=google.com; s=arc-20160816;
        b=lkpzBQWzoaGNL8BtaQ+k3bnI8oGh90mm0BTwz+I0VsO8FIUzxi0L6JvgjTQv1CjY/J
         oHr5lnloocI8RTTVQfOyryGDiHRrY1rrMphdXjRpawk+1/IObcWp7gWNIMmMYO//k1Nh
         KLs4fLccgbAeREnRM2/d4S4tiwvPcjsXRkctCPiiJRDTVYB6F/wS4Ccgxhh1rq+Nt6E+
         9x4N0SLRuFCdfg1qAdlocVSzoEaadtUmn0RLiWVyLU/CMx7zYMNrllLEBR9gJkDRjZAt
         zFJTE0c5MJ9Xlyy3bbuOPW41Hk+rwk3KDd3pIfBReUTparj5x5mYqJ2L9B11OkSWcYpv
         Tabg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=5uhZzkc7GaVITot0FsuHIhcvnz4Kwzzg7fDog44yjpY=;
        b=ofIqo7wTfBUusmlCIxpF1J5/d1ksjCToqPYIbsUQaV2BATtwJPxE7V8lCLWnU0g6nK
         apwonAFoFS5EJBunOuwW3eKl/gJn8ln3FgqwyvTu0F1E0VsEa3i9jXViP+abqmUxNqka
         ShNCCOYm6pxSgS300FGnKTcpRdi0et+gcV9E47JbTwrO/Ez7G431kwQ2RcRwZZhfG3zv
         Icjw6WwFQ2dKNvQbr8NdaR+0lF6AX/xYiTB9rBEHp2A/5lcTGQM9u5Vz5aX0kxQcGsFL
         q9i/AMX07cwFXpmAzGkpxO4FWnhAXz+Ja7o57EJKpbvm3QN1I9MYQ4/khqI+KOEx0zzs
         uj7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CLSgr8f8;
       spf=pass (google.com: domain of 3lbcrxwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3LBCrXwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id r6si19693oth.4.2020.11.10.14.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lbcrxwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id c90so53735qva.11
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:57 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:47b0:: with SMTP id
 a16mr21217064qvz.22.1605046316972; Tue, 10 Nov 2020 14:11:56 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:18 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <49f7f2c12b0d5805f9a7b7092b986bbc2dd077a1.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 21/44] kasan: kasan_non_canonical_hook only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CLSgr8f8;       spf=pass
 (google.com: domain of 3lbcrxwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3LBCrXwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

kasan_non_canonical_hook() is only applicable to KASAN modes that use
shadow memory, and won't be needed for hardware tag-based KASAN.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5d5733831ad7..594bad2a3a5e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -403,7 +403,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/49f7f2c12b0d5805f9a7b7092b986bbc2dd077a1.1605046192.git.andreyknvl%40google.com.
