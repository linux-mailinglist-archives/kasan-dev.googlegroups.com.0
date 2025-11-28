Return-Path: <kasan-dev+bncBCKPFB7SXUERBUNQUTEQMGQEAW6LVYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 033CBC90C40
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:34:43 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-8804823b757sf49865576d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:34:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300881; cv=pass;
        d=google.com; s=arc-20240605;
        b=dP9xhj4ya3qssy6IptZ9Ro/K0XwxI14edrvdVGMfck45xujw1yXl1MWuXaVgMS/xJq
         gc6aoNUVUGFmF63khTYeUJdNtFgrXB1ep/mQMH7TrBLwB0eMl9q55zjSYxz4x0phQj4E
         HGaJkHkCD71Gm3n9RJNIb0h8pqCvqMrHUVAHuMAr0LaSog4xbR/ocoLk+MQCM+RJyxKd
         YXjbYfcxu8D1ODTBzwkA5swbn/CGomy5wCUyhU7gM2kxDtLkX/lwxw6NXV8aNKOn6dOb
         HT3LtecflXyEQQYE7uVaX4A/qtc/+7dyh1kqz2i1w83BpJhyUMWNa4ACxLyPDVx2ZyHm
         7rZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=niLUiquVey8pXelEHDREVnhExoY23mFYFWSYza4N0ew=;
        fh=rWtYatypDLPUAyPaoU4tJXkbdO1aOnemkkW8erL981A=;
        b=f885REwX97+zfcYXJ1qLYq0a7/DuTFrUNSsKuY/Q8TbR2xA5LybzFUOwEvLF8yYry1
         1Ev1xxL87iCVXDeRlrISqTBmZsxhojYZfhqnYzQHrDrGKvm7IAqRE2herlVyTwqFVSRk
         aWgqdpGBFumlbejmu5tbWZ2kQZM/uC72pYXblHkg5hIDKPTutogKCwJ9ltLKc/fdvme8
         tesv8bkOP5xS9T11D9/0wD0KKsGrjh76K1ky0eTZKPR4B9kCFB2yqOZxh7OTUp7dtMKE
         NpB75Ooh6fFaElTceYFy2qkEGIf3aVUMmFANE3OW1ujuslCSxUpcS3QF1eldQunbTghJ
         Jx6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QhrfcA6p;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300881; x=1764905681; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=niLUiquVey8pXelEHDREVnhExoY23mFYFWSYza4N0ew=;
        b=Muoq9Y1cAhqUFspi4xtuZILDI2x7nC1B7Z5WCNBgGlEUsVJTOy5gqkQWkA1JGWaJIg
         3l40TRaIiKbwYny2VH+HdOgVLvts/nGGSKRQcnrkjkpgXNgjVB0022M87iwDBbP8glGD
         GwBK+4H0ILJOWO7smyRH58TQhhvxSpwpTMMJFtBRcz/5qQprZ8gQeA26hRMsyEMkI6il
         Cc4dbLQJUzliUnwRvTwGjVZglIEHMg9p3tgb7XZA73OtBx/6xUZI3eS/xuRw+EKKUDFx
         q5+2f1OSBvs6kqwLn9sKVwBKKdVu+FUiVdE0O7WpTdA3m96pTOqladTDtYN5M3su8UDS
         dRDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300881; x=1764905681;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=niLUiquVey8pXelEHDREVnhExoY23mFYFWSYza4N0ew=;
        b=Ky4iDXA5WzofMvAZGnc9jGLExmlQkaXN5QePEapeyKSMupOhurNflDi+xdwvm5PF5D
         CXW/dII/h4MopCk5IDRn1Lo5d/HO+gtY80UtQvvNF/euqnNR9/vTvb1hpTEpGLMJNmlm
         TXJmIZElITx2zwYVt2/2A1wSRaBBM7V56P6uiPWKJvG+ToBXEf+eJPKLQFFTPjEUFa6W
         QcdQV018HIMQr3QOJDiq16zebFjb6NLbqNDxIFQkM8cQU2JgmUoffj7VtYgK+yhz1nBl
         SieTEUq8vfllD/e8CXiHbg7MGhMZTClTIOOVUwOhBe8VZjV/yM69KXRWNOfunTrveZi/
         tbYQ==
X-Forwarded-Encrypted: i=2; AJvYcCWjH7tbeRSFXuze92PDqX+3RaJO2GiDAPkcIWyR7YlErOOcWHRCCd0zxZJEIkzEGdS2HSwc0Q==@lfdr.de
X-Gm-Message-State: AOJu0YxiuPwsYYesEbZMwq7PtBxWxQFNCousC89k/YBFAU9LPDqBhJlp
	48dSgwy+xvCdHZsFtlmrz/3YIP6hvaeu8fM70nvTG90mYYNmIcZZKSVB
X-Google-Smtp-Source: AGHT+IG+I9G1NN6ZNfzFHJFD4Tw0vQHW5lEhhGVk0sn+MaBUs52TUpRG60BdTZVoQCNE2Oh5L8hpuw==
X-Received: by 2002:ad4:5e8d:0:b0:880:4272:9a4e with SMTP id 6a1803df08f44-8847c45eb8emr425566936d6.10.1764300881486;
        Thu, 27 Nov 2025 19:34:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aJcpUiTAVKBUxSwkh+WEP3nxFB0G6VsBwP80j6e6fUVQ=="
Received: by 2002:a05:6214:12d3:b0:880:5891:1514 with SMTP id
 6a1803df08f44-8864f7995afls10923406d6.0.-pod-prod-00-us; Thu, 27 Nov 2025
 19:34:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVgE7ycrnEkV+mhXxHwx3TbbXQ7R3XYWKmfezB46mkuk0BmS4zPIznedwf7PmzCpYWo4u+cajckyoQ=@googlegroups.com
X-Received: by 2002:a05:6214:80d6:20b0:882:4580:a86f with SMTP id 6a1803df08f44-88470083a5bmr348193926d6.6.1764300880578;
        Thu, 27 Nov 2025 19:34:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300880; cv=none;
        d=google.com; s=arc-20240605;
        b=axopz3eQkujKzCdTVEn5hvRTrdImZOAiVRJkvgPnQ4d8al7O0O6SOuc41mvDCoiOkf
         zrwk4GZd4hBHgEgah2Z11ij8ZlPLpiW7HFDZhq70OR0OhDVW4AXx5Ye49NYJk8d0TXET
         wRhzLP55lfWOSlbpVmnBLAogH3zfAxKY6v3/2utwFfznpIRMS7WHlssBiyEZnFGjEIeI
         zBW/+er0iXezyv9TW3yeynN2TEDq/SBZAModNm3lBcmY4EryteWch6PewdynLqElhiKp
         WkMi/RWLw4uG47JAnlZSrP5f8hwHr8W5bDQwc49I6Jv8eA1hklUvuNvnfE4rEv3cY68d
         NLMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pg3FSIRtMXU5szl2eh5KeSgVoSezIgfBLftf2WmfQUc=;
        fh=xe+JHqlPVWiTeJAZ1pgfiusrzDtaA9emQAh6M5Emu70=;
        b=GxZR57lNJLmsXGCHdP1vw71bop8KMf3WZYvV4eISHQ3yt+Ivaa4ZY3Z0vhKxyLL0No
         bKW30hJutoSjXPqYF0FaAvZVVA/VSoq6k1Vr3r06WzXuxjmJbKbpRKe8a6pQI9KnPlDw
         5AemZRxM5cMmM/ZaH40YAXOab/giHYePtYIyHeNuZVANmXhMJrHz+d6TWWppwGT/yw0f
         j4haEiiY/6navTV0RW0koCxnyiHjRzOp3VsCCjbGpinTv8+D98rzhn13o8Vy6IYBce90
         vgXdNf2V2tF8kdtCNguR8CqKQX3hL7OsPNOTDRj0z47ApFeaRT59Nw+Lw13zGXlS4xiK
         ENSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QhrfcA6p;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88652ad839esi964566d6.7.2025.11.27.19.34.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:34:40 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-479-mu9y1m2TOWCTYfgb-eI-yg-1; Thu,
 27 Nov 2025 22:34:36 -0500
X-MC-Unique: mu9y1m2TOWCTYfgb-eI-yg-1
X-Mimecast-MFC-AGG-ID: mu9y1m2TOWCTYfgb-eI-yg_1764300874
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 7E7E61800359;
	Fri, 28 Nov 2025 03:34:34 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id D8E4419560B0;
	Fri, 28 Nov 2025 03:34:26 +0000 (UTC)
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
	elver@google.com,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>,
	linuxppc-dev@lists.ozlabs.org
Subject: [PATCH v4 07/12] arch/powerpc: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:15 +0800
Message-ID: <20251128033320.1349620-8-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QhrfcA6p;
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

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linuxppc-dev@lists.ozlabs.org
---
 arch/powerpc/mm/kasan/init_32.c        | 5 ++++-
 arch/powerpc/mm/kasan/init_book3e_64.c | 3 +++
 arch/powerpc/mm/kasan/init_book3s_64.c | 3 +++
 3 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
index 1d083597464f..b0651ff9d44d 100644
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
 
@@ -170,7 +173,7 @@ void __init kasan_init(void)
 
 void __init kasan_late_init(void)
 {
-	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC) && kasan_enabled())
 		kasan_unmap_early_shadow_vmalloc();
 }
 
diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
index 0d3a73d6d4b0..f75c1e38a011 100644
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
 
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index dcafa641804c..8c6940e835d4 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -54,6 +54,9 @@ void __init kasan_init(void)
 	u64 i;
 	pte_t zero_pte = pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL);
 
+	if (kasan_arg_disabled)
+		return;
+
 	if (!early_radix_enabled()) {
 		pr_warn("KASAN not enabled as it requires radix!");
 		return;
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-8-bhe%40redhat.com.
