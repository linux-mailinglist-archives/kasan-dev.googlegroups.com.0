Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJXSVWBAMGQEP43BQHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 704CD338FBC
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:31 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id s4sf18200650ilv.23
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558950; cv=pass;
        d=google.com; s=arc-20160816;
        b=h5BLKXmg4xvAh/Q2rjHtV505T7V1YnxYagnUDHVzFRZeHrLamROOAGJrpGYFpjugsk
         o8j90/xSXk5+L02fkTmbIFaDsjMJRQXY0T3qxWEYoJUVL/2rGf1wOuLKuZh0HGasfGof
         Is7xwSYUasaIaX2cxxwGC3/1odnr2RfIpvKaDw2GzSz9LhoB0bsC91bEN4Hh3RfGKaLO
         uKSew/lw4OtAZvo9e/b+4xwDWwXiPVbdfUbLDuteALfaXJMiDIaJFcfyEQkEhgIhLFAi
         RkchoQSjJUtWFB/Z4QPXBHPwfcB7+YOAPWye44LBA8aJHKtS3Bhen8scq3VSNYaqdtV0
         7qgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uu0bO62uskArnpN8r30qxtJFn97+YUEPyF5OOH9o5J0=;
        b=uvJptPnHG/WvJ39iGIixqPmbwL8AP2VeFjxtVcagzR13zsbnBNaKbZCPAVR+fB48TQ
         ZP+Ex9S9NU1QGY2ueGSjsj0XsZVECKE2fWGA/n7AdskxZkdqmaC0CeEtTXmkgF1toIAX
         sXjg1T+Owc9ivs7zeXJtxxvHQk4C0jCRKlRW767vRHnB1ucUZlqkM2eXIXVtEaXtAIrB
         mEQQIzgbflxrqahCqpL9wRQxIOUm+eLXcJjKwAfsy+fvXZKL/fN/UikU8RqeKK6OVc6X
         XyjIyI6LOKUaEfdnDfN37udUwn+4nmtI5cMZVMfp9VdrvQ9xJq2fsAvGcW0DNwkwbKw+
         Xb7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uu0bO62uskArnpN8r30qxtJFn97+YUEPyF5OOH9o5J0=;
        b=CWxmOgb/pb0zFnmKrDtzNC8kjV+DBgb+uEjlD+svpDrvhLvg7sLs8qOmINeaqedMXP
         QZ0TQ4kHCyU8SzuW6NnjyzWKVhEaUh3WCdORHJFiqmT/oO+gp7sWocSS5CniyBdizzQ0
         NJDTEFKKF925DMHsfCXqcHUkv6iUWY4QAhoYIRcSG6eEQqAs3usFYMT+NCUDHjVXHFvm
         aH84dHrEs8as0CbstG99HprEUAVDAIqvNbs2vGMGwF+0y7aM5uDexGNZtrGaz3Y5XwMF
         GvI0/e2g9fbFycWM+6tilIab6nljkZf/wtBGQcUCs/iKNmzJBqeoplBJlFDlbUNsXyad
         MykQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uu0bO62uskArnpN8r30qxtJFn97+YUEPyF5OOH9o5J0=;
        b=kBr5vedk4dsoCBbl3V/SH8URf26oldxWB4iP+chXJiOcg5MTzimYedr8iY/k8pmI6d
         WnB1X9eCs49JtBBOmD0QdwmHZYiL5CWC27NrnJIloMxhG+5lC2QKAPYi0a/oPwoKMAPw
         nuYzgQjWhIETZEkweTq9Ki1tSIrxJfTSHjxJSmNpxNERaq6soQGBFuq0/8sziouNcltR
         gbdAVcR0WTpV5/Qe5el/QEc3PtS3xOLRStXe0FXdzuAsIxROrAeMs/aXjK9CERKTKoOC
         d/bPH19WDQftScr9mOjFQAnQ3Q3NOKSso2r7Q8ISq4eSDbdiJJqj98GfvcmTBsthXKBD
         ypyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530C8Cr5QJlEx3/669mszQdG3y0eh9kfcHpSN5pPqWJBMU+rACut
	PC1AEL7Gl0MJi3z7Cp9v5jg=
X-Google-Smtp-Source: ABdhPJwScZuBwxd0deM4bRV6FobBdIheqIv3YXNoawXtscv51Ju1Gl3b2zHBa0dWp9iI/yCiyvpzVw==
X-Received: by 2002:a05:6e02:c88:: with SMTP id b8mr2827842ile.135.1615558950460;
        Fri, 12 Mar 2021 06:22:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9f06:: with SMTP id q6ls1397242iot.1.gmail; Fri, 12 Mar
 2021 06:22:30 -0800 (PST)
X-Received: by 2002:a05:6602:280f:: with SMTP id d15mr9760772ioe.127.1615558950037;
        Fri, 12 Mar 2021 06:22:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558950; cv=none;
        d=google.com; s=arc-20160816;
        b=vTsp75E3lGznSPdL1jk6im+mVjnnh0agPj0zOg8CQbPyctNDsVfEwfx5d59WaIMLME
         TxKH69XVsFVn56AejTmmSPRgEDsJm3FndM67YhyepSC0DtLApvBIq1WeCtuN+l6lDP8q
         7kLbrPkp7CIqk3DCJMmGBHDJEoWnbzDppK4U12ZU7dv8OqV+f7RDi0cXWH7DZBReAXhX
         9VZRK79ROfIgL+lL8IVlkLi1jiZTugXs5xmIrsRMrFFOBueIjTbadjkiuiNHRX1lAd8U
         4PZJ3hCDuKBudK7ikD0r7rd4lZQ0g0WxctBXZd96/5Yi5ZEDuLkHcfBJcZnu3iwOHeso
         //Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=eBiKU8q6Ygg2gjw4JI6QTAfM/nhpdLTGISX+KsV/lWk=;
        b=ekKfmppJyjH7zpWpcACCnPjUEWnJzwJ9HsZn7A2CdLkyyCJl+mX6ZvMV3Q8HvYJtus
         O6KUKPb4ulyfjFQAs1nhtKzqVr8D6v6k5oeF5hWXBoj+NcYZXL8K0Z8Gkqid6yq43C0R
         AoqWrPrumS6iQPfbw3sC1pxftaP1aJ5HhP88UK/rdnizWEqjlkiHpowaVMIylwA03Srx
         QObGOeqQ7024AdokN9i1GWjlavwCQLG9RRIuTC9k2a8HRxW10saThwPaj2CaKxk723nP
         IFM3tpFwO8YL7aawRKlWj/4ckYV4TSQDYMYx+7zcRmH+3MIz5elosM4p0JL7SRcOo3+3
         KDMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r19si257839iov.3.2021.03.12.06.22.29
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:29 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3A5E311FB;
	Fri, 12 Mar 2021 06:22:29 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 537C33F793;
	Fri, 12 Mar 2021 06:22:27 -0800 (PST)
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
Subject: [PATCH v15 3/8] arm64: mte: Drop arch_enable_tagging()
Date: Fri, 12 Mar 2021 14:22:05 +0000
Message-Id: <20210312142210.21326-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210312142210.21326-1-vincenzo.frascino@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
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

arch_enable_tagging() was left in memory.h after the introduction of
async mode to not break the bysectability of the KASAN KUNIT tests.

Remove the function now that KASAN has been fully converted.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 8fbc8dab044f..8b0beaedbe1f 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -245,7 +245,6 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #ifdef CONFIG_KASAN_HW_TAGS
 #define arch_enable_tagging_sync()		mte_enable_kernel_sync()
 #define arch_enable_tagging_async()		mte_enable_kernel_async()
-#define arch_enable_tagging()			arch_enable_tagging_sync()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-4-vincenzo.frascino%40arm.com.
