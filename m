Return-Path: <kasan-dev+bncBCKPFB7SXUERBUG77LGAMGQENHGIPBI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id qNCuFNKvnmmRWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBUG77LGAMGQENHGIPBI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:18 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E528D194069
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:17 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-899b041cc64sf82358696d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:16:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007376; cv=pass;
        d=google.com; s=arc-20240605;
        b=eNqCOlLUNqVaFgrKKctBrpfsZsbAH4kLnIEtL5sQ5jF+5RuG7h7JUzU0quk5F5R0Hc
         4Ow51yvQgfFbB8TSExTlvO2Co8ODlMaq4MEDW/DnW6jRF1tBOWffD5DksVA4diEDl1O7
         W+u4DtuKxpKcJypPYd6ui9RSJ4mB8jVFB8yVPC7bo+1B3KYpuhltsaw7t59VnkX0Y3Et
         S3zSXY2MzoYE70X5FsV5Xr1ktoWp0ygIo4RS+moSil9i5jAZSoS7a3Y47cGbJEV4WGCp
         rEFZKMuT5n/lnbvElUafV84x7sInHWQ9GyHV+i2hvcoWiamp3gyaxJu2IqaULYKwMpOp
         Y/yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=23r0bndeDHYpAIAK36MU1FMtiOfGw+jxLAwapKtpYU8=;
        fh=F1F0kpoThhKBIWujjse6pfJ4ceDNptZ+4ig6OQVaFXw=;
        b=CJBDvRVrUFAafO9YmM020v/sYbVmzofL4Ogo6xd87AJeqjgeE2t3pNEXvSjGs17nt0
         VJXUJrkN+7Y4BVSPmgebthOZ7s+/kwTY4Eu36E88XXsTXrGuXNduIzTW/qCf0Bl2uenl
         udE+Yrfq4M31DRyimZixmVBR6YWUe9HFuCQIO6X1tfMt8wJMj21AfPZqffdkz7SxtUW1
         zBHEFfvGmZbN7uLU2xE9AgKfjY6ZobOPjWLN5rIgNZTWoHHbWS0lSiiP6RjPqS8YYgkx
         WXyk9ni1io/KiJP/Ix9+ClCDRAOF5K+2nB7lAVqnY/ujdfzipE+q4KaMExF6hg5efXHj
         iloQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Dp7SnWCa;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007376; x=1772612176; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=23r0bndeDHYpAIAK36MU1FMtiOfGw+jxLAwapKtpYU8=;
        b=NamH2NQXLL6ghK62xba3EK9PZpyGZNJ6lg+82gk3ypAK5447g+7qlaIQGGW7m6VQCk
         64+nNxi6kymzjcdEQ6+Pl7wf8BGCcVdJs/90Y6ckUM6/uGNg3ba56z30XcP+GIEGl3kn
         uowBXYLnYa15rkDog21i+enUWgItnLpTZXDIUgpN7xc+Ih802A9I6wGUxY+X9D+cAl4t
         WEpJ8sGk2vFG6XdAB14QoSNcEd5DwVyDoi1vSqVnTtIhzJjJcfvY0TTpO5VLP1UK4LPw
         U8xGW/W+tuyc1OlxdWzZ7OZTL/Pr56THkwG/3wsYkVJWar/T4ag37QYL9CKILsYf/k2y
         ceNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007376; x=1772612176;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=23r0bndeDHYpAIAK36MU1FMtiOfGw+jxLAwapKtpYU8=;
        b=TKNuRWBgXbepa3LlRuqyXWJnK82qXkwQrrhXPFmPkQh6cNJIUgqzDW8Dl1k8Cfyucw
         QcaPu3GoSLexhMxU4rkIcOoFeLD7JxkogrPoEe7zEANCznCPhNHlCltkvwk24i3/w5j1
         5gtkOP+yesx551tEYdoASN+zgA6xaAyAfntQpA+S3OiZe5CQqN8clrtHk/+x3QOxTSNj
         5OJxC8DYJ/mqwM0BUeQ0q25h81xQGbh77AStd+DzIIXUnSphubFSn+co0fXpJtEZOzsY
         LcrppUSMReSh+YVGVpX7ONmzi3iXsSHCneN+4XczS6TuazDOvv+mhKHC0vKzs75ifXhO
         23AQ==
X-Forwarded-Encrypted: i=2; AJvYcCXgI+3WCMDDSzyZ+7PwPVavLKjmRnnEMdl6GJV6aBGWYk+f9q8hhRVcMraiLBSIE634XTjRNQ==@lfdr.de
X-Gm-Message-State: AOJu0YzAzGPRfNZdn4rDp9SqU1Fte5lQHcXTbCoDiS5a6Mk8+3oWsYlI
	kc6xddwSB0tscN119rM79BmUc73shZVf+BSnkVNflbfwI4Iqaon2u3mW
X-Received: by 2002:a05:6214:260d:b0:895:35ea:8bc6 with SMTP id 6a1803df08f44-89979db5299mr220941796d6.67.1772007376549;
        Wed, 25 Feb 2026 00:16:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FFgYlEteEXkv13pw5wiYVNbVZ56dIhHk6R1dSGFw8sfA=="
Received: by 2002:a05:6214:5191:b0:895:4b79:83b8 with SMTP id
 6a1803df08f44-899ba0bb1e9ls6188306d6.1.-pod-prod-09-us; Wed, 25 Feb 2026
 00:16:15 -0800 (PST)
X-Received: by 2002:a05:6122:80b2:b0:56a:8a20:e50e with SMTP id 71dfb90a1353d-56a8a20e768mr3513e0c.0.1772007375698;
        Wed, 25 Feb 2026 00:16:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007375; cv=none;
        d=google.com; s=arc-20240605;
        b=SmJQlySKxFqP8a/4S+/HvyvyPwrgGxJBZK/gVC9nM39L03t82N/9DyKrdtWdrUEfBb
         TMnlpYpDJb85NratdDKtDDMOohUJmT5dPGXGWey9wkq/A/RoLsOYSBojWcoeRZOZvCDE
         tbyMe1jnNZW6rOWCZvvG67Ego6Agf0nYaJRiJa+Fufur9eER5N7aQC8g+UHvvA3GGW1C
         QY6R6FeSSSQmTpHXBQMmqMNnDqGsyPK6YMALS4LAbx48FwZbWYYenhJvzGoeTKk27d/6
         t0d2yxX5e6pEI10OBfmRRgpfQ9NpLYk8JrlkVpH4prkzC4RmEGME+5OO4eisr9Y9j4/l
         Q4RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3+N2FdzBXq7d0qBg17oIVx0hpSGWg6PAf2XJ4iYnD3A=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=gz9d4WEJzIbHHZvTbiBhE31RlVYWxKKSk+/xPIqRYwcNFvmUMqP1x1QOIdYGmJYmZt
         f2r5ItxXJUevqZNfle9KMW/zLgmv97Z93wvEHPWnDpbS3eZIKp6WhrQb9JgsEu9c0F+C
         V45q1LheI3ur6R8H+FyCdGEKUS3DjOhjPw0zXVe4AO1ewcQj8W+T8MLDGZ/89CMEhbhw
         yrG4fgvu3N7jImXtVc/MZ7HdQZlZNY1ZVmkvJ40JDHAO5t4K7AbMfxLp9Khfm7DrnSfM
         CI91Off9PXd2AG+CGBMoWVCk9VGStHfqFUG42YIl1IeVZA3sZL3IX01jQkEfo1rwdSjh
         SXXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Dp7SnWCa;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-56a7dea32c1si62214e0c.4.2026.02.25.00.16.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:16:15 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-36-5bDMHpyIN7qY2J9aFw6T_w-1; Wed,
 25 Feb 2026 03:16:11 -0500
X-MC-Unique: 5bDMHpyIN7qY2J9aFw6T_w-1
X-Mimecast-MFC-AGG-ID: 5bDMHpyIN7qY2J9aFw6T_w_1772007369
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 4C83718003F6;
	Wed, 25 Feb 2026 08:16:09 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 50E031800465;
	Wed, 25 Feb 2026 08:15:58 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	linux-kernel@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	x86@kernel.org,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	linux-s390@vger.kernel.org,
	hca@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v5 09/15] arch/powerpc: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:06 +0800
Message-ID: <20260225081412.76502-10-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: izDvA8RA7iQCsnAV_5K-4tGEszuEP6OtrUQsHxeERW4_1772007369
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Dp7SnWCa;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBUG77LGAMGQENHGIPBI];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.981];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,ozlabs.org:email,mail-qv1-xf3f.google.com:helo,mail-qv1-xf3f.google.com:rdns]
X-Rspamd-Queue-Id: E528D194069
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

This includes 32bit, book3s/64 and book3e/64.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linuxppc-dev@lists.ozlabs.org
---
 arch/powerpc/mm/kasan/init_32.c        | 6 +++++-
 arch/powerpc/mm/kasan/init_book3e_64.c | 4 ++++
 arch/powerpc/mm/kasan/init_book3s_64.c | 4 ++++
 3 files changed, 13 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
index 1d083597464f..0ea2a636c992 100644
--- a/arch/powerpc/mm/kasan/init_32.c
+++ b/arch/powerpc/mm/kasan/init_32.c
@@ -141,6 +141,10 @@ void __init kasan_init(void)
 	u64 i;
 	int ret;
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_mem_range(i, &base, &end) {
 		phys_addr_t top = min(end, total_lowmem);
 
@@ -170,7 +174,7 @@ void __init kasan_init(void)
 
 void __init kasan_late_init(void)
 {
-	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC) && kasan_enabled())
 		kasan_unmap_early_shadow_vmalloc();
 }
 
diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
index 0d3a73d6d4b0..fbe4c9a7e460 100644
--- a/arch/powerpc/mm/kasan/init_book3e_64.c
+++ b/arch/powerpc/mm/kasan/init_book3e_64.c
@@ -111,6 +111,10 @@ void __init kasan_init(void)
 	u64 i;
 	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL_RO);
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
+
 	for_each_mem_range(i, &start, &end)
 		kasan_init_phys_region(phys_to_virt(start), phys_to_virt(end));
 
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index dcafa641804c..f7906f9ef9be 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -54,6 +54,10 @@ void __init kasan_init(void)
 	u64 i;
 	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL);
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
+
 	if (!early_radix_enabled()) {
 		pr_warn("KASAN not enabled as it requires radix!");
 		return;
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-10-bhe%40redhat.com.
