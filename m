Return-Path: <kasan-dev+bncBCKPFB7SXUERBRHR5TCAMGQEMTKSUVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 85B46B22762
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:51:18 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3e557222b3bsf15568475ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:51:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003077; cv=pass;
        d=google.com; s=arc-20240605;
        b=ecFYZ1VaUoCa6ABIQodHt1tbOrrUy3uPMQMYSizKENnv4uxP3cHZp1DdNhJH99EEM/
         gZwLFXnphP83PKdoirQpTrNyts7YX+jXcX3pIz6zmfiSb6OYr+HRNZx61cSpBtLi04Bl
         29fqXgwpI77r5Sw/we/gBLH92eOpRGzrE0okGtmV2yaScJOTeMID7NZBwGlBHdiY5pYD
         ftc8MqtMjQak2yYpqKl5b7MoYsKFMSm+vwgxtpMXhbrvptcF54JLqkuaYnHf8zaxIpCf
         EFk5QM8ZivM0FoE1ADMLyedMYDjz9DQIDFx5DhZ6LNyinAWqmqIpumTbu22stBYi/tai
         im4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DQ19qZdoDgTNFl5CtwWN0C4niCtFbPXUDkAsy3PjFuY=;
        fh=oYKE66P1xy2VvJX3bneMUU8R/VGYhPwazXDmyH4yCSU=;
        b=RehJZxJ1E/ZLricEzioexIe7Jc7KCjD2ERaT1R/Ve51hoI0sIU82NlVwtJLIuYxzYH
         66FNgC/1WUmmWxWekuYQWFNCBgZmHgh3KDUkRwSUPc52R2hkt7Q2J3AS+2h9cPaVOpom
         2Sk7xTcwZ7CvYsznY+7epm9hXfbtA0SZvlYHkzCO9RYUBOJnEiP5z9fd7Fz4NY9iylwt
         gFZHc/vLW218dYnTmaEiWpcOJGkxUam6LyFNisJpvrwhTjx3chtsHBIgnXsv3o10ha8Y
         p9QdomE/3McznEcH/92lq8c1943DRmI4kLmqqJKj4Ioj6wPsy/8PBDeMZQ4jEE13BRbP
         toLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="G/XiVgYV";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003077; x=1755607877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DQ19qZdoDgTNFl5CtwWN0C4niCtFbPXUDkAsy3PjFuY=;
        b=xE24p39eXuOxOWiGBGnDp50aT4PjSMdfbCxpL+f4KXIAfsz8saMwQTYbC4IGan2Pi1
         bDhUPRpFUzWTYZ9HQgHK+68oxlZyLNtMmrUsEFWi1yVi9gBZ3DlEkAmcscOkNr0iuA/+
         fnzznrA4h/Smx9TUsDbmtkvNISyZxOpaFheS7p9ev3nzd87tR9VS15C4R69jrtfUiVR4
         iZLOpqZtupw2r6b9BiWtuGyZRhu1umMF662HuJV5JM9z9q59R4uBKYnXA5Xs47TxWaRS
         mPuijCZhNHxCi9mmzLpvLEJlXb3R00lxPmFIu8/4Dm9vfL/K9ZNSRYqKlkDNZJK0LWKN
         FMVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003077; x=1755607877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DQ19qZdoDgTNFl5CtwWN0C4niCtFbPXUDkAsy3PjFuY=;
        b=tnNbbQke0f4rHqC/qlgz3roYDwCSmVIeuWlwbXjXpI3BT0jtZWu51RHduExHQwDgo0
         4oD8LF9VobtQEh2yOpzMYjcfhe2AgMLsUVuJxAw7MIW/3ivPzLNPQvECn7DqwimZcKeh
         qC0Wn3cCj/olJG+apDf1RN1/UjEk6Nc6Utr1HQOuGulkIk8FWMF222g5HWb8h4ODpOLD
         p10tBbnsALPh0SOwHtLEtUyJuPDVp0NHl7gL2+tRKnSQ2wdSA5f9ab3jdy+2LEF372JI
         S/YsJ/lh7u4a/kOUgBt6DgQm6ZMOqrJy+3MJrEdGYS40Ow/K3pY/8i3Vpq63yUNskh5S
         R1qg==
X-Forwarded-Encrypted: i=2; AJvYcCVCleX7x8abMhJs6a4yHPsnrgvF+cn+YrTcXuwZ5q5qmoCwzG8JRhwbDc97hJD2yc0u92Ssug==@lfdr.de
X-Gm-Message-State: AOJu0YzJM1MHEnL7uoZOX8ZjFkOOlkjiJXx74QuiN7M0IilUwDjAKnkz
	zMQjUvZ5lCH5sdghWShNL3f57rsloAQHSd1E9IHCmMBV5qF5dnwyjl52
X-Google-Smtp-Source: AGHT+IHID3l3MRV71bcvcO3MmYBcx3wob2nCMliFLH40aSQLifGmPPEQ6h9UCBdRT/61TZ1fJZVgRw==
X-Received: by 2002:a05:6e02:3804:b0:3e5:4982:b2b0 with SMTP id e9e14a558f8ab-3e55b008906mr62316595ab.18.1755003076768;
        Tue, 12 Aug 2025 05:51:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcZ0oClLVHSVMCnw9zJI+dzsRF8eu3UHZSqYAJ5qBsNsQ==
Received: by 2002:a05:6e02:4409:b0:3e3:cbfe:cd96 with SMTP id
 e9e14a558f8ab-3e524b0591bls45546315ab.2.-pod-prod-04-us; Tue, 12 Aug 2025
 05:51:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXduSem26HV3KZ0AH9E59spBkgfv2poXvJ1uwFbhkVMj34H7NSGKmJj/SGwQPPJ3e0RdTP2E3W/Xhc=@googlegroups.com
X-Received: by 2002:a05:6e02:228d:b0:3e5:546a:966f with SMTP id e9e14a558f8ab-3e55afb6483mr53388895ab.10.1755003075969;
        Tue, 12 Aug 2025 05:51:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003075; cv=none;
        d=google.com; s=arc-20240605;
        b=AWBK+JYj3/gQhAOfGDhk1QjVlwaGiIiRlVggztpg5rP4zU5TNSFDy81nccuOzAwLSb
         Z4DPvhr2d5qYOFR0jL2M23S+D8k9SHaXG6wewdth6itRh7BSTOurymTIK3ea4S+Xo8UH
         v+bWhXoPVuzhjrYQE0dh6ACce1Igcqq93XlEolR5QSCvfyvfJaPCSVjn4C/z3QLReD8B
         2h6N/7yuiytMUchP1GfMTcNr/PS0n9H+8+1THEJH4fWRQIBvTLToQSmKOs9TCIhUsPvA
         VRps/wf2cQJRRfK95YkB2/vKZLDHGxI+elaX7Q+WtrjBzl+BbbDjiVBhzyIz3XS4GjM/
         HuRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qdpdSshaazL7siJRM8NVIrvzcaBedwi1OmyrckGBBVw=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=A0bzELEA3GnPNkHdkVNVm86+1ICoSkQrCS5dksbyMYwsSe5+bd1n0D6cL7ln7gGxsj
         i4tbLAIWb12GHFZIoI7M+lDDw/GI2EZ8jQAxvBodZCR2GkAMFoQAkop7FCwiYZQ2naQU
         bzf8XaAQHttkoilPj0tTTBZSP/yftTuAGOh5v7E2gGmNQA4GOkFH70gD8CS4dZtZYabT
         bdYlnZEogIdSd/UVt6Qxk5zQTn9DjOuIIUcAKuYKlXkQGmJA4hke2iI4gYxWedIHct0C
         UfLgb85XlGoHka15CDOgLKrOfPl4ix94G+oPa51Ec3lnYBoazWHuBU/sEiWh4mftAvwX
         zUnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="G/XiVgYV";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae9b6cc7bsi391980173.3.2025.08.12.05.51.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:51:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-656-3Xj9WACAOs-CFxfowhebOQ-1; Tue,
 12 Aug 2025 08:51:09 -0400
X-MC-Unique: 3Xj9WACAOs-CFxfowhebOQ-1
X-Mimecast-MFC-AGG-ID: 3Xj9WACAOs-CFxfowhebOQ_1755003068
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id CEB4C180045C;
	Tue, 12 Aug 2025 12:51:07 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 441D6300146B;
	Tue, 12 Aug 2025 12:51:00 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 10/12] arch/xtensa: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:39 +0800
Message-ID: <20250812124941.69508-11-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="G/XiVgYV";
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

And also add code to enable kasan_flag_enabled, this is for later
usage.

Here call jump_label_init() early in setup_arch() so that later
kasan_init() can enable static key kasan_flag_enabled. Put
jump_label_init() beofre parse_early_param() as other architectures
do.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/xtensa/kernel/setup.c  | 1 +
 arch/xtensa/mm/kasan_init.c | 6 ++++++
 2 files changed, 7 insertions(+)

diff --git a/arch/xtensa/kernel/setup.c b/arch/xtensa/kernel/setup.c
index f72e280363be..aabeb23f41fa 100644
--- a/arch/xtensa/kernel/setup.c
+++ b/arch/xtensa/kernel/setup.c
@@ -352,6 +352,7 @@ void __init setup_arch(char **cmdline_p)
 	mem_reserve(__pa(_SecondaryResetVector_text_start),
 		    __pa(_SecondaryResetVector_text_end));
 #endif
+	jump_label_init();
 	parse_early_param();
 	bootmem_init();
 	kasan_init();
diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index f39c4d83173a..4a7b77f47225 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -70,6 +70,9 @@ void __init kasan_init(void)
 {
 	int i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_START -
 		     (KASAN_START_VADDR >> KASAN_SHADOW_SCALE_SHIFT));
 	BUILD_BUG_ON(VMALLOC_START < KASAN_START_VADDR);
@@ -92,6 +95,9 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* At this point kasan is fully initialized. Enable error messages. */
 	current->kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized\n");
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-11-bhe%40redhat.com.
