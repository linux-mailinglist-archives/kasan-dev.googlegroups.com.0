Return-Path: <kasan-dev+bncBCKPFB7SXUERBGW77LGAMGQEIM5NWUI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KP0QGp2vnmlxWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBGW77LGAMGQEIM5NWUI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:25 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123f.google.com (mail-dl1-x123f.google.com [IPv6:2607:f8b0:4864:20::123f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A97D193FF0
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:24 +0100 (CET)
Received: by mail-dl1-x123f.google.com with SMTP id a92af1059eb24-12721cd1a2asf43252602c88.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:15:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007323; cv=pass;
        d=google.com; s=arc-20240605;
        b=W2TlqB2oifgG8zwnsxhN6yDk80PZU9JYO+QXq/T9o4x14yjmfH82MMrfXLyLwU+6vH
         W4TRL1jWTFF5f1zqAPu/prsoX5wr+WfEqTc6AyXuSvNBfX7lwL3t9kuSapU6unBwj5eQ
         40ztEFHV5iMBitV3x0DEUzwi/GcITqX3l4od2NzaX77DIeGgWguvpkJxHNVz4zg0Xphs
         /iW9RO4r28jdkOtEGgd5g9k3+8WOzu5bMK+pq4KKKR/u4xrXcvQz34jbkyf+0Aq5wEKl
         JOAOLCCsBOLm4FrirlZ1slItnjrxDBhy29BJ6y/1jPK/syfdK0T83DD8dvoxTQ6lAqqp
         BMKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xKNaSq3J3TxAahgu/EaA6qvM+40PLQE1ks3RLC5tg74=;
        fh=MPAFp+X4nfQlktruy/vHV40cttwuU9SmQBDbz1vMquo=;
        b=Ex3z1NPTcb37RIMAReh0T6CJaQAn/tVQxH2qesGtoCdIZnpZRnHBTHs+akKri+ANSq
         51ksZKCwcvoQysrdKw3G6SIX4V193LAVB7Gl2d97OVOfd/dkQ1/7Vp2SYfIkfpfLreah
         4qUjljqEs3VDndBNamdeu2rqzA24BfioWg4dXNOJswamNgsSqGtm0Rc0bt3hjcvhPIxb
         qWo/RGbFaGhgrXdxDT3lLif5o1lJR0+pm5NYitrzmF8gInl2vFTS7Tir4dw/uBVVSf2v
         hm9vR3uv9CZ6GLjEMU/+ckZ2IK8oxlFsMJ4Z/woVm1YdRyfmfsPE+Hqv0ioTNihEvlQ2
         lvIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QllxwwVc;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007323; x=1772612123; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xKNaSq3J3TxAahgu/EaA6qvM+40PLQE1ks3RLC5tg74=;
        b=bdS0e/aAYpkYC5dkMOZEpgRzLdgk7N6EW+aS7tiCFYGc/w4yn2jAzmWHoFLgm6NVod
         o0sh/4zE2ub2cPbhq3L70BOPnlr6Hil6VJQSjjTY1/OwuMDKQiV1fDZAnnGrw1JK6eXz
         TM5zZDlGaiE8Ba5F363viJxTZfcpqG+WmWzfLBHjyB2M8oL53G5yufaaz4xedmGUFefJ
         LJfxZlA6tt8eP/Fria/Vxd1SQckpxGq0TjT8oT2riSLahQnAFCJ6UGcEOdAphxWXigpO
         /4aEU/x1FolDDGn/IVjsXlvwAn3RyUzhI+6PfCtqghLkIp+fKr6+WT+pEYxKCcWFyPxZ
         HBBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007323; x=1772612123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xKNaSq3J3TxAahgu/EaA6qvM+40PLQE1ks3RLC5tg74=;
        b=dX63M5y0oArni2dB/TWcqovMhfHPGAsI2k1VSgmUY578/oywwzAzz53wlgEMsmJEDW
         bzWBLXUaReyWSQgoc6KSwjxHxYwQgGv0MZPIn7mj2r/1GOyQhvlz67ANDLCKRJTu5zOs
         +7y9Qia6gOCLONUYR05OJOQ6KNFTvKxd/7y9reZtKif+3YgktAek1qHBXWQffeJmaitp
         NbSPHflNTvLkceL2qVdZvQtdHmjqbQJJ3jxqZYcMwEYomtotv+kdrXE9ZaqLzwNACqd0
         8LPxX/gTF/tjtvBb1mQgW5sB7RzG33jC1ADRZuUV5HcZcvY3CgprIVhQvmFZhbsNuZW2
         e1lw==
X-Forwarded-Encrypted: i=2; AJvYcCWTEZiP75hHeGUWxgsY9cwQDqqZlCTZXtFCv1h8x3i4nSLtLhIB1A/HssQpr0OpHUH3PT6lkw==@lfdr.de
X-Gm-Message-State: AOJu0YwcP+Qu3YDBmcLz4I5h9rJmEjpm6HbUQy6C1VdTa3ZN6EomPL9P
	L8SC09CS+YMShl9mEXiuIyPzFSCWxt0lmnXrptMLFQoE44Dx2MwDlYi5
X-Received: by 2002:a05:7022:f83:b0:11b:8278:9f3a with SMTP id a92af1059eb24-1276acb37f3mr7258108c88.8.1772007323039;
        Wed, 25 Feb 2026 00:15:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F7/VrAmqUEV8O2qaUZdhh9v0vTHJBDml7isQ58rrMsvA=="
Received: by 2002:a05:7022:a81:b0:124:a8dc:e516 with SMTP id
 a92af1059eb24-12782684a77ls281383c88.2.-pod-prod-08-us; Wed, 25 Feb 2026
 00:15:21 -0800 (PST)
X-Received: by 2002:a05:7022:b84:b0:11b:1c7e:27d0 with SMTP id a92af1059eb24-1276ac5be02mr8129317c88.0.1772007321632;
        Wed, 25 Feb 2026 00:15:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007321; cv=none;
        d=google.com; s=arc-20240605;
        b=Ut6LPDaveg3W3HeGsGCNtEuwzarbAzurojbA3rhCM0Ol6uBOYUoO4VPOarmrUOYU/f
         tuLOu86OlJ0MD+vVkqtYAMZIL945NtKOFStbiGxXA5MWHhOJvyqSx8vHyiq6+B0fuVFE
         PiGv25bQeb+xSd/B23MMyAJrdHp0TQsMUrwdP79jtUq3+Y3xb83Rb/lckGPtukfrupHD
         HkQwNUvzKehC1SrPGd19qgmUCNnBbIkhBr9E2WaHZvuH9RPczPrxb6ORD7U7x3U5hRkQ
         8/KgHU8MFMiTo8nJrZWUaP/dYQ6cwdkUl9qWhAhFyGB74KOCnRONfu+BB2Aos9JiRe08
         pDnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=krRB48lflglDsnK+MbRSOk31duSyM0PDe9SlLiivSrU=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=HvLqcxz8fpjtGbjd4p6L4oi5KK9klXkuXkCOJsfEwicpM7QnJoNN/gSALwzZQQ/beB
         WXOQxG7SImAgOtqRuYWc2qTH1Vml2tRzHiXkuUPTEcXkXpjBe2CYvD1A3bBIIaLBM+9c
         aqwhOE5gHSsT86gnRNOwO1aoWNysEL/ejqPbWSw8HwNUQJowufWAFhHl/rAvkr1TWA3U
         HGxcaeccokTZAlgvUU41pfULv9K6yAuBvSB/kxE1/5oVcI5XjHXrW1doxW1jjTWmIw0r
         ys37SFV5QJwpQp+y7Pl/XHl7dpuRN/8luCZL9bvrVN9eRupyxz1q45nqC/9M5c3f3U9f
         WbjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QllxwwVc;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-1276af5127fsi459042c88.4.2026.02.25.00.15.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:15:21 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-297-WO8-mb7BPemrfREQOcvRnw-1; Wed,
 25 Feb 2026 03:15:11 -0500
X-MC-Unique: WO8-mb7BPemrfREQOcvRnw-1
X-Mimecast-MFC-AGG-ID: WO8-mb7BPemrfREQOcvRnw_1772007308
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 14EC918004AD;
	Wed, 25 Feb 2026 08:15:08 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 860561800465;
	Wed, 25 Feb 2026 08:14:58 +0000 (UTC)
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
Subject: [PATCH v5 03/15] mm/kasan: mm/kasan: move kasan= code to common place
Date: Wed, 25 Feb 2026 16:14:00 +0800
Message-ID: <20260225081412.76502-4-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: QeL9V9YjqTho4OeOCKr3GvoJh_QH8XfQqLhNd4QsKXU_1772007308
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QllxwwVc;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBGW77LGAMGQEIM5NWUI];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.980];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-dl1-x123f.google.com:helo,mail-dl1-x123f.google.com:rdns]
X-Rspamd-Queue-Id: 0A97D193FF0
X-Rspamd-Action: no action

This allows generic and sw_tags to be set in kernel cmdline too.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan-enabled.h |  2 ++
 mm/kasan/common.c             | 21 +++++++++++++++++++++
 mm/kasan/hw_tags.c            | 18 ------------------
 3 files changed, 23 insertions(+), 18 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 9eca967d8526..b7cb906825ca 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -35,6 +35,8 @@ static inline void kasan_enable(void) {}
 #endif /* CONFIG_ARCH_DEFER_KASAN || CONFIG_KASAN_HW_TAGS */
 
 #ifdef CONFIG_KASAN_HW_TAGS
+extern bool kasan_arg_disabled;
+
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return kasan_enabled();
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b7d05c2a6d93..0d788a468e96 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -42,6 +42,27 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL_GPL(kasan_flag_enabled);
 #endif
 
+#ifdef CONFIG_KASAN_HW_TAGS
+bool kasan_arg_disabled __ro_after_init;
+
+/* kasan=off/on */
+static int __init early_kasan_flag(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_disabled = true;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_disabled = false;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan", early_kasan_flag);
+#endif
+
 struct slab *kasan_addr_to_slab(const void *addr)
 {
 	if (virt_addr_valid(addr))
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 26a69f0d822c..9602ea4861e2 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -35,7 +35,6 @@ enum kasan_arg_vmalloc {
 	KASAN_ARG_VMALLOC_ON,
 };
 
-bool kasan_arg_disabled __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 
@@ -75,23 +74,6 @@ unsigned int kasan_page_alloc_sample_order = PAGE_ALLOC_SAMPLE_ORDER_DEFAULT;
 
 DEFINE_PER_CPU(long, kasan_page_alloc_skip);
 
-/* kasan=off/on */
-static int __init early_kasan_flag(char *arg)
-{
-	if (!arg)
-		return -EINVAL;
-
-	if (!strcmp(arg, "off"))
-		kasan_arg_disabled = true;
-	else if (!strcmp(arg, "on"))
-		kasan_arg_disabled = false;
-	else
-		return -EINVAL;
-
-	return 0;
-}
-early_param("kasan", early_kasan_flag);
-
 /* kasan.mode=sync/async/asymm */
 static int __init early_kasan_mode(char *arg)
 {
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-4-bhe%40redhat.com.
