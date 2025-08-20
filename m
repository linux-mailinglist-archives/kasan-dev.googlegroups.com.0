Return-Path: <kasan-dev+bncBCKPFB7SXUERBV55SXCQMGQEKMG4H5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D423FB2D391
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:36:28 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-70a9384d33asf55676086d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:36:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668187; cv=pass;
        d=google.com; s=arc-20240605;
        b=gFPqsX0bLIyOmPv8zMscNqqPRp5OfYQb+Eayx5AQ1dERC+xPCTbt34PXtNVddtNqf5
         8tRrL9tUXMvPXEGAAJu0Dg2XHRb3Fkv2y6FWOm1QbBokNl5Wx207RmPAtZBuRZ3LT7Jm
         swGLYkvg+KZHSoX307FDWglNATbEsMV3J1Fhym/qkWmreKsYpkHzUMWT1iHWZvF4Q/K0
         G1L7l2rr69prTXTd+NrcuTwL/9XQxhohC/2uwshE6A8NnIBhfcIWyfJvvKiBK8W+T2wr
         v60JOdV7hKHxQE7w3pJfT8OkxhhCLAyb02fgNNeXVGQa6ngfjJonQCUrelgRuS/BsavD
         v2Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=asgfcOeHh7Y/9Wl4/wzscpooLBianD5d1+7xjvUIfOI=;
        fh=ap7S1JQd7OcFi+LQQPknq0oWqnIxos7hWIn2SwZpQVE=;
        b=Otbocl2kmA2H68sGuW+aXg+AyeheI7tQYQBBtXQiJa+mdhr1pOyhI27DeMPSQI8wq1
         XzmcA94uWDcdOjUSljoChDc3ZqrV1ALkbzJVuBRM7VjgSsjqC4tbucTn8wdaERpIwQet
         0g9jIstMFa4xnKY0aRdzuOoZlElcPd6DOgGUadVIHWkvQYJDsZWlhkiE88unm7+w0UTp
         4sGSgOhOWo8p85QOoKB/nv4+b5L1RwEJKmATrMq2nVcKYAcBCmiuvpeh7+0GLF1uuVUE
         RySDn/8OjKwr8eHS59pRMlWyYjw0R/VaIT8TVVX5B3uC99Bv/SFSnki8qDJuzMrDCpKU
         9NzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hUX5kggz;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668187; x=1756272987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=asgfcOeHh7Y/9Wl4/wzscpooLBianD5d1+7xjvUIfOI=;
        b=l3GSgWKfkffN4esZ2VaACaJhESJ+8UGfH7NwvY3HlHoRnfaNVoWPQ2+qhfr1DcS8M2
         2zlkrnwULy/zInif4w8bPDM8V9NfQw8dLZU1cCDmMMNe7V9wZ/2bDx1O211BrFrc1PTg
         Q3FJNykljBBlwx5nx3gW5keN/zVhC7eQCssQnWYtgY6jIQuzEgGI14RVk2tirdHXIto4
         mV+BFXwtXDwMBZdTL8S+tjVn4GeErDCt1YoVGjIuGrfUfS/SIC+r5e85lFWm0Wn9V7yN
         YzrJ9eAijFBE2gYvASKoDeHoQYpgkg2hREBslW/fbkcmciwaamR9f9U9D2dhPf9RskAi
         /1bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668187; x=1756272987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=asgfcOeHh7Y/9Wl4/wzscpooLBianD5d1+7xjvUIfOI=;
        b=L3mCPOS7r2uSjM9vlW3VGsg81DG06y1V213cdxgUflSNxumJrgOTb4mn6klUHHbUwY
         lXYV2QRuTrYnkCFOdVunqXwxIfiz+caKkQHj3vUeYbELnSTty4zy1rzZDJbiZyIkRH/s
         VUT9ScspCtiRmOR7itcCxQy2AnFe7hSobq4a3wbjy97euo2KywImqddgB7h+0FfvNNpA
         s1PPyOF0fklPbsU0aUhvvhCgLX5yL6UzToY9Z9n/x1XBuo799J7NL+jTdFxpcoQg4xUa
         EzkrFuljhw0XLp+pCPRBv0cqhCOmeFgCNTdF4nSYBuo7GhxiSuJu/zaCfo7/cQwnkkcw
         qsxw==
X-Forwarded-Encrypted: i=2; AJvYcCX4lU1sjQ5FGCcXje2R/bET4y/ZWolbKx+AeydE4ATg0Wf97eQ2qUt/Z/JiVnb2PZbo+cgZQw==@lfdr.de
X-Gm-Message-State: AOJu0YxVkf21fZ22/+QP8Ncfzd59it3fRfJe4jGvoNu0szdU1iZehaX/
	W4HQSwVAdzTk3yf38TVt5evLLnAtTKwiVllsKdqEeaGuEMuQ/iXC51Ed
X-Google-Smtp-Source: AGHT+IEfR1LgRz3kJA0qRfnmTe26vAr1xrAlj9d36rRzlYKblg/OSapq7j9VXZ6AddKwxWwp7MErsg==
X-Received: by 2002:a05:6214:2261:b0:70d:6df3:9a8d with SMTP id 6a1803df08f44-70d77207cd6mr14748586d6.61.1755668187450;
        Tue, 19 Aug 2025 22:36:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZePjq/oWsZDh5jXAuJfdVySBgCsyB57wOnnCJhK4cmy/A==
Received: by 2002:a05:6214:d6a:b0:6f8:b2f3:dfb9 with SMTP id
 6a1803df08f44-70ab79eefdbls89271606d6.2.-pod-prod-08-us; Tue, 19 Aug 2025
 22:36:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5S2nAxi51Si4DBNeG4j/x1Hj564u2f5m0nOB5LhtZeqx/A9y40qOCObCPOAf5TjSPd97Z9Tdl8jw=@googlegroups.com
X-Received: by 2002:a05:6102:5488:b0:519:534a:6c60 with SMTP id ada2fe7eead31-51a532374c2mr428435137.35.1755668183096;
        Tue, 19 Aug 2025 22:36:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668183; cv=none;
        d=google.com; s=arc-20240605;
        b=Jjl0sCc/OhoRR6rEtmhX6f4daC5Yg5HVmqbzdiKU+RnvDGXIsjm5g3sGMKhBnZTfRh
         UIEWt2304jWIzZvp0vLPMP2rupCSXlM/BpQUYcg1V1lZmwIqtwCqltCCMsqOrhaK9QE/
         IONQPe5ygQxG3GGsYXRRcDlQ4+OzLKUt44A/FsHxpYm5BYreXd6ItYGHG7idulfQe4Gr
         HEnpJXsBJUlqYv2ILRU+cIo+iqocaiIDLozy722RMivMnG5h9Ev12X3j10IPqk71qJiF
         PAy05Ii1sJheWXDJS02xs0UARoWuh1UIuEdMIGDjFJBU1fG9IcB9kfgng8ohhmZLD6ku
         x0Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ffaqmFj6s7jEE3FagcYbQXUNvNizOaxd5L//WV57Tuw=;
        fh=9dglkBmsvmfGoblODn7QPNvu3vy+mPuOgBBx8zEpOl0=;
        b=T/RqKyUuBfdEITZn6b3weabIgPYbOCpPojj1LO5mNVlJGJaVyZV+C7NHSvxc0Jg9YC
         rHVoHscAdHgx75GGv4cj1LeNw1xwZnn+q7lf49yBB3EJ9PiPKsjbjuRAsegAb0u42DDo
         VwtDTfU6X7dLQ50SI5vuoAGPhf0jcKPcxvdmP1EIJ4yZPxL7Bkp+Gza0AdIrjnPYr66U
         utfFWFkRbo7woW56y6fy7HPRM1llGYEqSQ534R/dyG1tHtdyuXzrfau0f148GTYOms+y
         MkVQLQfoI9dYLCdqWGxX6GX31ZrxU+9yK7Y70CB1asF1s4MZ70t3Jm0UhpanEpqB8t+1
         0RZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hUX5kggz;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-890277e552csi515119241.1.2025.08.19.22.36.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:36:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-176-ljSlvNsWPGC2J3sVaEdsMA-1; Wed,
 20 Aug 2025 01:36:18 -0400
X-MC-Unique: ljSlvNsWPGC2J3sVaEdsMA-1
X-Mimecast-MFC-AGG-ID: ljSlvNsWPGC2J3sVaEdsMA_1755668176
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0057919775E8;
	Wed, 20 Aug 2025 05:36:16 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 0B83A19560B0;
	Wed, 20 Aug 2025 05:36:07 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	glider@google.com,
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
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>,
	linuxppc-dev@lists.ozlabs.org
Subject: [PATCH v3 07/12] arch/powerpc: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:54 +0800
Message-ID: <20250820053459.164825-8-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=hUX5kggz;
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

This includes 32bit, book3s/64 and book3e/64.

And also add code to enable kasan_flag_enabled, this is for later
usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linuxppc-dev@lists.ozlabs.org
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-8-bhe%40redhat.com.
