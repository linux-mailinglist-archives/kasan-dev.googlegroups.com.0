Return-Path: <kasan-dev+bncBC5JXFXXVEGRBV4GS2NAMGQEULBS2KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id C17B55FB54A
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 16:53:12 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id g28-20020a4a925c000000b0048064c1e521sf4261491ooh.15
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 07:53:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665499991; cv=pass;
        d=google.com; s=arc-20160816;
        b=aCPD5Laqy5uIc4HLUUMuZKWIvRRJeZiV38Eyh4Zkm/r5ptJr8OhviySViLIBUNwMJq
         eHNqEG13JmhTjeceCk0IH2Aqoa1avgtGhwUamtgAzzdCcgB02i1spZhYQJ58uNQDH7vq
         aryJfaRki3iAG6Jbjq2kuPb8+bUmBjIkMdLY9OdDKaqOEXg02XhUYumtX1YhL+Dm/gXY
         FJppw3/Q+SWnMyPwWGdstXzXXtfY8TTLqwIj5ZQaic/Dm7q0z031XVC6BP0sV5DGcnfK
         u3RAxkEZH6yYYRidDA9t0lc7Sm+2+be2hB4A4f0Y6YiN7/pgc84ghXOAEJSm9ItCbfEg
         KeBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=13V1TT7E7uMdiPYziwkzbxnDkJBc4JnFNCK/8ndACnE=;
        b=vOX3YZynG6zlr47xnV2ddvVEXIHvtB6BAE7pE84ztsat+CST1vPVhBkoEJVTPeh92f
         Sh5cs1ASCxnCBgGaXpJsH0aQW8h2EWnbeuSZXDQBRRb2kkyogYdiwW2efzmxtfQ5G1F3
         vVAA9XqGz4icrh+jrw5pN0n55r/xOQWTMBSaLAsHhBXENtHefp/0jSbgVPmarFprANCA
         mWjxDa+nboUNbOeIH0Z1jgHvaUOfEN5qeejOrnm647GBBIM384wyz+Aertn7/c4IqcCo
         XogMeI9zCoGwwvop4F6+xFYUqzLi0579rJS6XPyWhm+29/I0i5tLzTyUsS2wqbsy7xpn
         Lj1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oi0POXSB;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=13V1TT7E7uMdiPYziwkzbxnDkJBc4JnFNCK/8ndACnE=;
        b=RhL6W8VW8DEVZMxQ+/YBnD79G/GV+EzmtcWCyjHFfnVIED9fxzIMw4eHDklSYsix/d
         cvf5BXoTvSWR1PEBTW+7EG7JieAOwOa6WBvS8aA+Tx2ysNNjHXLE8S82ybRUTlEkep5o
         USUS2PHzQUBGvaZNbb85B3u0oES0/dFvN4fCk1LPM50hSOZ8GumyRBLT9k6BgEUq26xY
         UhRuHon5X4cPry+Gjgp2Naj7Uaivppi9pyCOuDsLao0hwaL/Ydz8f8+hnVejaMIq8xnd
         OD4FXXjYCgY8sZxD0r6siP+kuGVZzxwBz8vO9AmO1uRnA3mkrjNIoBHjKAs5Vmahq+ZI
         PICw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=13V1TT7E7uMdiPYziwkzbxnDkJBc4JnFNCK/8ndACnE=;
        b=rNyyWpyOOflh6ju5X7cqk01yPjRYB7I4GVU17LbhgXTsZqx8DjSvo/UR7DuEw0fttm
         XE8xbXGl/H8iTh73EnI95JkP7yXi8haR3OhjP7rT6GnjuCYa+QKrno/oCwCCNr35G87X
         HpwxGPiU9Ba5wEKIjihjZVQMMyosB0AYb4XUToFFFL6yHji3xZA0gbj5SNyjJPM/Jm15
         YSvXN4oqsz7IMfidXC/zz3exg7DQ6YnnfVTYeEXKkE9fgck+sbHeJgU2eMWYVQRZl+oa
         TRr3w+3UKWVEUWyMPifKc1af4CzFzzOVMfHz6/j301cjx7lCBBg9veUpbb4zh/dEYYW+
         alug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2lYOBt2AFCa52s1DXnQAMk0CXOKJf38rTPky2oCdSbU7FUCs/r
	1aAbrQ280MtnE5yQ13BJLu4=
X-Google-Smtp-Source: AMsMyM5DBMz0fmxebqwpSpLD/huHUG8vuuI3teTuH0DpqAmwIYN9bre46C1EhPdHXRaE5E8IYDXWMg==
X-Received: by 2002:a05:6870:8322:b0:136:7611:f847 with SMTP id p34-20020a056870832200b001367611f847mr7135384oae.294.1665499991552;
        Tue, 11 Oct 2022 07:53:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b315:b0:131:a6c1:508 with SMTP id
 a21-20020a056870b31500b00131a6c10508ls4441175oao.7.-pod-prod-gmail; Tue, 11
 Oct 2022 07:53:11 -0700 (PDT)
X-Received: by 2002:a05:6870:15d3:b0:122:5c72:f21f with SMTP id k19-20020a05687015d300b001225c72f21fmr18667419oad.178.1665499991069;
        Tue, 11 Oct 2022 07:53:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665499991; cv=none;
        d=google.com; s=arc-20160816;
        b=mb1kRcMHu5ew9eFe0EqNKSXfS3fQzg5LswCGEpP8LL9vgEYbvPcYZuQ/j7cwRyx/jP
         +1tJ52xKeMSaRoVTqwa0fRB4q2tlj1NuNoKVZQ+vctlpIkNyUZkR+3oYeOLs6bai2CUP
         jI8PU7y4MauUqGZHNxKmsrDW11WO6QAhfcUH4Q8dGNEnWGWfhlSFrALrNGjjy17so+RP
         DW/jhXoHKpB+uQHr0FrIR9NxZBgtGjSfVDE2APvC9ZonQ/0RRoZb3Y05sWDd5AA5NejS
         5IPYyV5xjwwiP40omFriXvcVYLz2nLPt6rlrw0w1YAS5JrN9N3+IZFYlAgiO+0bYYQdY
         IIOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iNqWz2VwA+6P+/wAELu+n2hy7ZBNUejQElOmwh2ScKE=;
        b=Fu0cgZ2Xp1i5CeyiPKc+ffRHxEx3cybk3xEAZGWwaQebyRiBko5QM73BMVnCvZowP4
         Ajv/cgnYDenYyDCPjiTyHEZy33/z7TKI8LnTUbrYO+XOAqUPt5gb+E7y1WEh746ysqGg
         R9jaJOIaAiOzEvKtHEUnW6BB5ZjvrHSJC0EYx7GTQTDn4hzEg03gPY/Y3zQ+VrJBP3he
         rKpx3QNUEYAUXEQAFp+SU9pnLhkILqU44SzucFzNPHgF2b57FQyhkdrnugFkgWFvsUmx
         qx+HfhEEPjrakDDUFp2LT2wx+rLmVE3YKTNE5jheBaCMjtSy80K8bl7ggK7jIJvYZmZl
         kdTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oi0POXSB;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u205-20020acaabd6000000b003544a421e56si413292oie.3.2022.10.11.07.53.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Oct 2022 07:53:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D84B7611E8;
	Tue, 11 Oct 2022 14:53:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9D8CAC4314C;
	Tue, 11 Oct 2022 14:53:09 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Alex Sverdlin <alexander.sverdlin@nokia.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	Russell King <rmk+kernel@armlinux.org.uk>,
	Sasha Levin <sashal@kernel.org>,
	aryabinin@virtuozzo.com,
	linux@armlinux.org.uk,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH AUTOSEL 5.15 25/26] ARM: 9242/1: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
Date: Tue, 11 Oct 2022 10:52:32 -0400
Message-Id: <20221011145233.1624013-25-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20221011145233.1624013-1-sashal@kernel.org>
References: <20221011145233.1624013-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oi0POXSB;       spf=pass
 (google.com: domain of sashal@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Alex Sverdlin <alexander.sverdlin@nokia.com>

[ Upstream commit 823f606ab6b4759a1faf0388abcf4fb0776710d2 ]

In case CONFIG_KASAN_VMALLOC=y kasan_populate_vmalloc() allocates the
shadow pages dynamically. But even worse is that kasan_release_vmalloc()
releases them, which is not compatible with create_mapping() of
MODULES_VADDR..MODULES_END range:

BUG: Bad page state in process kworker/9:1  pfn:2068b
page:e5e06160 refcount:0 mapcount:0 mapping:00000000 index:0x0
flags: 0x1000(reserved)
raw: 00001000 e5e06164 e5e06164 00000000 00000000 00000000 ffffffff 00000000
page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
bad because of flags: 0x1000(reserved)
Modules linked in: ip_tables
CPU: 9 PID: 154 Comm: kworker/9:1 Not tainted 5.4.188-... #1
Hardware name: LSI Axxia AXM55XX
Workqueue: events do_free_init
unwind_backtrace
show_stack
dump_stack
bad_page
free_pcp_prepare
free_unref_page
kasan_depopulate_vmalloc_pte
__apply_to_page_range
apply_to_existing_page_range
kasan_release_vmalloc
__purge_vmap_area_lazy
_vm_unmap_aliases.part.0
__vunmap
do_free_init
process_one_work
worker_thread
kthread

Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Alexander Sverdlin <alexander.sverdlin@nokia.com>
Signed-off-by: Russell King (Oracle) <rmk+kernel@armlinux.org.uk>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 arch/arm/mm/kasan_init.c | 9 +++++++--
 1 file changed, 7 insertions(+), 2 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 4b1619584b23..948ada4a2938 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -264,12 +264,17 @@ void __init kasan_init(void)
 
 	/*
 	 * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
-	 *    so we need to map this area.
+	 *    so we need to map this area if CONFIG_KASAN_VMALLOC=n. With
+	 *    VMALLOC support KASAN will manage this region dynamically,
+	 *    refer to kasan_populate_vmalloc() and ARM's implementation of
+	 *    module_alloc().
 	 * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
 	 *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
 	 *    use kasan_populate_zero_shadow.
 	 */
-	create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) && IS_ENABLED(CONFIG_MODULES))
+		create_mapping((void *)MODULES_VADDR, (void *)(MODULES_END));
+	create_mapping((void *)PKMAP_BASE, (void *)(PKMAP_BASE + PMD_SIZE));
 
 	/*
 	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221011145233.1624013-25-sashal%40kernel.org.
