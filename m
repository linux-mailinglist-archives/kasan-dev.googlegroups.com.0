Return-Path: <kasan-dev+bncBCKPFB7SXUERBLHR5TCAMGQES6BZEYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 80578B2275E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:50:54 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e8e13403e45sf6752975276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:50:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003053; cv=pass;
        d=google.com; s=arc-20240605;
        b=SM9oukkW9l998NE+KH3qt74c4QwlP+05iRwGJEKaOr73Q8+2RCllDKj4uWp6D8yfOF
         RId0v0pTU2vDhGxKjwrqboqDrzQzBu1J+gYwY2QHPwXpBH8rTvMWLaHdyEMByfpwJqyN
         7g7uoRxR0tfkOGz7Q4hc4WGOZJXOqFCBqS/njvM+MNmfdjbeuXKR7KbVDgVOi0Zkxpqw
         pvzOjAGQHZFePNr33VP+hFV4kcJC5szIUi86FUtyJd1Y8GWiBixdFpqr1RL/afAz/8MZ
         rFN9mV0zy+ZVOFcOWKWye8XZp1cotDZcnqph0YnHLxZCRT8eafMTObEyzMo1Y+JWwNke
         dq/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Q9xjEpfRw9T1RvRnS4WRQNnShQC8GtBQLZHe1QYJZ6o=;
        fh=PgItcZmP1emxod1WYxOT+C3HID7LM3Ow67vuW+d1xhM=;
        b=PQSOHw1WApztUKP6HCh7V6+tQI90vhvR+7auf10g5FxEQRfTOIZ0R3rO/Fu+hbMd/A
         MdVUb4PAUI8H4ApKHVOLabHUYUlG/cK7MysV6U1x5omaPF9zU6Sjxpsqj41kBIJekyny
         reFT/Vvb9adY37DzUP5WzUqy0I4cH8gyMrAGYgMP3m96/1QY0mMTkITD4QQ6k99KskFW
         ivF62rf2P4JVyjusX6QdOFypU0IkuI1bxEO8uqIHt99UvhOvFoBS0LL5YaVCMouh0V4W
         qR6i6POnfMrVVMfkvAFhjMwTxUnPp7vhxbrSHuBvQJkmOKeMwiz2vyq4GOWT2R/zB/xl
         QCAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WgbGkryD;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003053; x=1755607853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Q9xjEpfRw9T1RvRnS4WRQNnShQC8GtBQLZHe1QYJZ6o=;
        b=f1rnrN8HwqsGmn8D0BdgJ5qaUgm+8z6IZnA4Cojptj1Dxc5sg5l+lDlvDtzUnSnDRS
         Tj5U/2fASptZymx6qpoKb/1BbGpzwUbUXsrh6Sm5zwaBDt6wyG10uHm/0OTZxw+L5r2V
         UbLqT3ohIwtfuiHSYeo7k3eYPVImZNqKBRAigWsneRtQ6juIZdHwPznSnaJ0SugpSKvQ
         OPUSs20lu9jMOAVtDfiFfweI1amvmpbUJmHN+OP/yWV8M1B7kiQYZ/yQU82DIo1u/UTX
         YVKqvU4QtC4dRtdt+hdifKlQk6kpp/Uwg0lT/Q4EU92Y1lSUTvbA9RIsMFiKVK+ihXZq
         wwdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003053; x=1755607853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q9xjEpfRw9T1RvRnS4WRQNnShQC8GtBQLZHe1QYJZ6o=;
        b=ukLL3vL07OrlcCxSd4DdI/O38SxparjMx28I97nauqJZ6kif10J1BWj/6Dg7wir4zB
         CH2BZTvVomw8qh3dbgT9q1+zoaKnz0Um/FYI8rlnmMDGph1rdDKsedeBTXV9sp98Z69A
         AHtQ4SxoZw7qQPhBbjEPjeGEvE87RteBCg6Ii66wrKkqGMUX4Po6XklkRZ60eQqJwC11
         rz161FqlNP4EkvfzYNIA7q+N8OdgOxLjkI9wV5U8iU81B+1JjMNCuF3kQoveDDjgjhq8
         GLmQ3dRlGyZHefHgcYcdbrKgBUdqX6nJYam51iFX7haxO4QTFIdSxQTQFXROSUKcK4F7
         MbGQ==
X-Forwarded-Encrypted: i=2; AJvYcCUOUalCu5F71psG1t9NZ+e4J8ffL/gZ37hVAv+1mFgsqnw2MIRSDM4lZ0HEBtxWyLq74tNSDw==@lfdr.de
X-Gm-Message-State: AOJu0YzymC6/i3yhPndCd6bQ0paHWVCqMRINjjRo3DK1w6O4HmJruqAI
	604w4ko49CeTPS4q4PfRDyJTaYH1NM6qHlr+lBPrYQng+kaeSqof24vH
X-Google-Smtp-Source: AGHT+IHNmOJWkoiO+HfjremJh8h+LGud/HgZwqFPQbBP5Z2xkl71uu0y6gkoJrXFQ6eGkQhnlB7sJA==
X-Received: by 2002:a05:6902:1083:b0:e8f:d3ff:fc7f with SMTP id 3f1490d57ef6-e917a1a9b1dmr4530448276.10.1755003053014;
        Tue, 12 Aug 2025 05:50:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdkiJrq0mQt1LQhWExOP69Nv9JeQG+SxkmMeIDxM1Zijg==
Received: by 2002:a05:6902:18d6:b0:e90:635c:c2fa with SMTP id
 3f1490d57ef6-e90635cc538ls3553004276.2.-pod-prod-03-us; Tue, 12 Aug 2025
 05:50:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVk82/SQnA1aXZAlx5UgmGEJiLkBwNN+E7NqnYVS1hPQQ/4WZr/o8G36OmgZ5I1oujZc6jYUp7KBJ8=@googlegroups.com
X-Received: by 2002:a25:dc08:0:b0:e90:6d16:8620 with SMTP id 3f1490d57ef6-e917a1cbf45mr2687407276.16.1755003052114;
        Tue, 12 Aug 2025 05:50:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003052; cv=none;
        d=google.com; s=arc-20240605;
        b=awiG/ZgPpubsVsDq3uOM1KQi9uER0zBAYAXKlM3ckM8C1HYK+xejaMDXT8LkR8QQdp
         Cqxf8Mb5Y5uWptJ3wHOuzrS41XWwgukiqGxOmXXWw5H3hweB/uqdb5t8bQrBI/MqvHcP
         UXYXO5kbMNOqov2qIayHIzhbPUfNBrEB/ojUE6KkoYdL4gjXQfV59bcFqk8hNslLo+DM
         ocAryrfzDfTMfKJrEyd0F5qXPby6F5DUnwMfzI8MDxuT/3IGYNKTSFxZci6wbW3Y8uIs
         HYNy2K+RJ3sl6E5Sd/y5/zjivqB4SsSbfiHo72Z/k7rUNOZsJ3++851QJ+FXAjwKG4WZ
         oERw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jd0CGLClfWsUYGgm7aK9F7vU1kBgjVrUFDs4V0d+D1M=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=kmQLqSwvt30Ix4LKhCHc34k2EeJ4bZ6gK7GN1t5IIvyTTENHmyQ2DuxFRY0KUKnRZc
         jK8vASV7fSXq1FUFvUDJGoIsgegJMPYFhBr1nN8nweMA0L3R9aC3uKFjCAh49EdqnuaJ
         tQkaq4whREZimFQeY933zZpQrh54zRRHJyC2YeHLsAV2Yf8Aq6hVLmH2BOFzjGIvzbt9
         bo0XfFRPYXCsjGZ7lAD+MwGgkTfGtBbEhszuSAJvrYyipXIdGnMbKkeRofRV3l55+6vc
         KTxIS5lHpfA8s5yQO6ZUw9Xo3UPGdiRMsr6odtZS9waIC6zPASrV9P460fY9Ijbka8YT
         ijww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WgbGkryD;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e9046a0a397si248305276.4.2025.08.12.05.50.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:50:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-655-aJnDQK3BP9GHbyaEUfDmJQ-1; Tue,
 12 Aug 2025 08:50:46 -0400
X-MC-Unique: aJnDQK3BP9GHbyaEUfDmJQ-1
X-Mimecast-MFC-AGG-ID: aJnDQK3BP9GHbyaEUfDmJQ_1755003044
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 90BF2180047F;
	Tue, 12 Aug 2025 12:50:44 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 140FC300145D;
	Tue, 12 Aug 2025 12:50:37 +0000 (UTC)
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
Subject: [PATCH v2 07/12] arch/powerpc: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:36 +0800
Message-ID: <20250812124941.69508-8-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WgbGkryD;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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

This includes 32bit, book3s/64 and book3e/64.

And also add code to enable kasan_flag_enabled, this is for later
usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/powerpc/mm/kasan/init_32.c        | 8 +++++++-
 arch/powerpc/mm/kasan/init_book3e_64.c | 6 ++++++
 arch/powerpc/mm/kasan/init_book3s_64.c | 6 ++++++
 3 files changed, 19 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
index 03666d790a53..b0c465f3fbf5 100644
--- a/arch/powerpc/mm/kasan/init_32.c
+++ b/arch/powerpc/mm/kasan/init_32.c
@@ -141,6 +141,9 @@ void __init kasan_init(void)
 	u64 i;
 	int ret;
 
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_mem_range(i, &base, &end) {
 		phys_addr_t top = min(end, total_lowmem);
 
@@ -163,6 +166,9 @@ void __init kasan_init(void)
 
 	clear_page(kasan_early_shadow_page);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KASAN init done\n");
@@ -170,7 +176,7 @@ void __init kasan_init(void)
 
 void __init kasan_late_init(void)
 {
-	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC) && kasan_enabled())
 		kasan_unmap_early_shadow_vmalloc();
 }
 
diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
index 60c78aac0f63..1e1c10467a2b 100644
--- a/arch/powerpc/mm/kasan/init_book3e_64.c
+++ b/arch/powerpc/mm/kasan/init_book3e_64.c
@@ -111,6 +111,9 @@ void __init kasan_init(void)
 	u64 i;
 	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL_RO);
 
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_mem_range(i, &start, &end)
 		kasan_init_phys_region(phys_to_virt(start), phys_to_virt(end));
 
@@ -125,6 +128,9 @@ void __init kasan_init(void)
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KASAN init done\n");
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index 7d959544c077..9c5cf2354c8b 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -56,6 +56,9 @@ void __init kasan_init(void)
 	u64 i;
 	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL);
 
+	if (kasan_arg_disabled)
+		return;
+
 	if (!early_radix_enabled()) {
 		pr_warn("KASAN not enabled as it requires radix!");
 		return;
@@ -94,6 +97,9 @@ void __init kasan_init(void)
 
 	static_branch_inc(&powerpc_kasan_enabled_key);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
 	pr_info("KASAN init done\n");
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-8-bhe%40redhat.com.
