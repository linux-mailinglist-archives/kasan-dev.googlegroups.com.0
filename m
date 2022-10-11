Return-Path: <kasan-dev+bncBC5JXFXXVEGRB4EFS2NAMGQE746DIWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 326165FB51E
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 16:51:30 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id a14-20020a05680802ce00b00354516db947sf4392640oid.10
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 07:51:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665499889; cv=pass;
        d=google.com; s=arc-20160816;
        b=PyXtsJGBvQQzT5LbiLy1ZnD9sFqsj5ZCLLwrTeqY780jF/mNHs0LPSm3W/TzfG0LA5
         /Ga+YqxYEmGtL7p+tIo0kgZJvgzZYOWJWf6Y090UBCpL8qsihuUbwdq8CNPNAII0ePBR
         zdytGZnyKuW3ojzP0da0z4Q+siK9XMpCrBW1K286DFDhC2MjVqT6UBN0mKONDKduLlCi
         8F4i/HAaJLd1cOkdNzdnphWlu56uBf4FrDnjQ4yh1QDjyLBDE3CM53KH/lcdWI1Pm7KH
         3QTQfsiwDB+AqyfP7MOiIxB9o2kQc36ZZnTvu9DJOC0QC/FwzazrIGWgZDeQxrP/aPDT
         nL3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gW9MkT+H61o1nFmhSWAF9zgdJ0jXvSEt02mM3+/itZs=;
        b=flMR+f31J6ueV8Vawqe07H/mbTkHfuNUTwfa869U3WxePd+FqIjJJJ5pGvooiUQBWu
         uChqoh4v38v/Up5i0l5nu8MYx8tsj32PHpUOPfFnyewzTVMM5jRLJPzRPWtqlw49UGbO
         2/wETeAqMk8ouWEMVUS7rrcQAFpU6zu1Zz7B7TBof0AsdMd/tsvem3ai1se+BjNWpabG
         GE6RG2C0BpXIqryLENVM/zgu+e3C3irR7nghW8YhwBL2F4oNc7Y7F4paJbYpOluGe99U
         9f/NSPpA3BKOfkBkFpmGa+uT9hBZtgPkzQCrkpAUO0W5BTGrudIizxftA6NCUCUOif+a
         YGvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CEEXdkcc;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gW9MkT+H61o1nFmhSWAF9zgdJ0jXvSEt02mM3+/itZs=;
        b=MGCIqUkjVFJune6YGirHS8nWgjWMp0MjTlx+tzN8hKponekYNLYHHgoz1eFv4iCT8a
         0dKB3yRSkxiNyaoADqXxCxeFVmbi1ASOX+zLIELHfjcu5vbJV7Hm9J84zvmvh34HAqqn
         zZsDWuj3sy4tcDgd5hMa1SRxrmuts3L8WIJ/jSGqGF+Z7QYbuuJVeqmUN4zOlnqMklpT
         3F/kRLhXPYRmQHjT75cUD6S8IUmNTW1VYA0CO41+Pv2M8Ka2XS9dnnALAeQaVA3nNNNR
         iAKH1Ycq76CpniOnk+xWGMVMRhAWEIVCbHlWQTAVqREtYx/D+9mY8gNapVLxtV8gryz/
         hByw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gW9MkT+H61o1nFmhSWAF9zgdJ0jXvSEt02mM3+/itZs=;
        b=k6bs3Dh2SlO/kPqk1/rNf7Ap3CIs4e5YjGarWfm2vlMdjBcJ8BiZxbgXj74ALiUkHv
         gEuMnxgSC9cXL5okdxNi4kQCEkNIiPbykyEuTmv/PLRl+vShIQynQnXwkkS3TlIEMhgZ
         iyyNBdv0oOAbaiLtFuRIjBHngG1SPShzq5ATOn6EMQ5KNCqV1aPE/eu0zfWL9YvfV1FP
         LAFf1cIvT6cKwl8wdMlIHi/Pld4QPPNqgljwL3HBAGCMBn4Ln3X4I07C8r3htrq5n8/l
         QnPFBFXYAPpszmwKahyXRQ3hfjIYJJDQ/E60SRgxrq0QJ2iQYzrpue4RMlXO7CO8KQt8
         0njA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf29oy4DGeT5w2NqcmZIH5Y0szRq2m/WyCWEV7nfhXvDFsw4MALa
	uq/MZYu9aWB0m+G8A9PHZo8=
X-Google-Smtp-Source: AMsMyM6juc5tD8UIOhZcc/C7/7IPdtFQ6NtTE5zySzOpEWy+r1G0VOMVZ3S+c323GHeUYXL+RjQNVQ==
X-Received: by 2002:a05:6870:41c4:b0:131:55a3:3069 with SMTP id z4-20020a05687041c400b0013155a33069mr13327873oac.159.1665499888826;
        Tue, 11 Oct 2022 07:51:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6a99:0:b0:636:d44d:1982 with SMTP id l25-20020a9d6a99000000b00636d44d1982ls2172153otq.10.-pod-prod-gmail;
 Tue, 11 Oct 2022 07:51:28 -0700 (PDT)
X-Received: by 2002:a05:6830:2f9:b0:661:9e22:58f9 with SMTP id r25-20020a05683002f900b006619e2258f9mr4427414ote.350.1665499888127;
        Tue, 11 Oct 2022 07:51:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665499888; cv=none;
        d=google.com; s=arc-20160816;
        b=c1wfaEEO6bvyIe1kRgSB1z8t98vpjych7aUSXJCdth/boqhcPrqKs3Bv8AOFtIewda
         IsZOdDX7c6/sw2beS+EBnHRzJEk5R1AC7+NHeZ052DquUa4L7h8H3NQH1g8aKIPPp6KF
         IiKNX5iZf9XzTN/rjn3ADmrI8lIG+gSB6wvSn+NRh+qbE9cirrUh9RBAImm81R9xEYIY
         NshwKhwhK3/6hKlDj+AxBMK1KwLSpgl/mGhLW3swta7VY0p3gSxafwQikLF1qivRt9Tz
         /w1VBt+JwhaFBUcwEprnzG35a6OXrg9s05T93bhBW+0vWcacWFUW06SzI78AGB1LqAVW
         thWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=B4G7M8JKZn6dY9zXOIh+E6Zcjzi8GQVa+pilD8KJgvQ=;
        b=YnkRhgQJqTpYE/eCQpSzvCCZFDyXh0cHS6gVBJxjIEuXeozrStafrYwzgKzttGrU41
         lT0JmEEU0weLHxIyBWdXl3Y+MPJF7WQA4sLfyTwqGkcKkbhAc3vV9AD+7IcQUmoFdRDk
         EXM2ukzIAgDCsq3ujhw/iVjwcUsyrc/I+CggD8ArcE8/C1DJWpaQGJZvYXSsWuJDG4Kw
         QtfVvbesVy3TyAgu/9XqlLDJSIdnZDo1NA3DmEeSw3gwXttoELN0dy/mSvVGdXij8c0H
         otHf0/mGLvErkIj4RcW5MlALz3C+Rb2o1TAFdIkOa2tJH+Qno1+hgoMUHnmNWoqLU/Xn
         gDaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CEEXdkcc;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bd18-20020a056870d79200b0010c5005e1c8si614437oab.3.2022.10.11.07.51.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Oct 2022 07:51:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E0636611AB;
	Tue, 11 Oct 2022 14:51:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 46352C433C1;
	Tue, 11 Oct 2022 14:51:26 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 6.0 45/46] ARM: 9242/1: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
Date: Tue, 11 Oct 2022 10:50:13 -0400
Message-Id: <20221011145015.1622882-45-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20221011145015.1622882-1-sashal@kernel.org>
References: <20221011145015.1622882-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CEEXdkcc;       spf=pass
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
index 29caee9c79ce..46d9f4a622cb 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -268,12 +268,17 @@ void __init kasan_init(void)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221011145015.1622882-45-sashal%40kernel.org.
