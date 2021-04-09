Return-Path: <kasan-dev+bncBC447XVYUEMRBOXDX6BQMGQEUV4BGBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E5C4635954F
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 08:18:34 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id y26-20020a05600c365ab0290119a06834efsf247827wmq.7
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 23:18:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617949114; cv=pass;
        d=google.com; s=arc-20160816;
        b=uE/PQzLn8Ey6wBwmfmbF+eJM1Jv4v5JmzM8Vem76JF2mLYSkjBk8WlcSWU4vqRl36c
         9pXPpse1U7DtDGeSiiaEANOomY/UoL58R7/lYlDmgwyhdWuxjHaoq8jxc/VmtKJ0opsu
         fuwOQAcy4XLoEcknwC+8YO5Q0PaIDB+Nzi0gMZX8Cwy5FMiH5g8Vec7QxGtAMGfxI1m1
         +MiVrfbRJPOqT8lySOtXQLk4blP9Ucf3XE8JLi7+xG6sPcw9n7ZiOL+dNUXsKbmn41Za
         d+mHfBuHjVmgzAB3g7VeEhYWaCUAnl/zNNQw2ayJ/eTVB952M1jg/o9Rqkev3QAz98tZ
         8tzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VvmtairZKk9Zf1xjF5CcFd86kJJ8n00fsGEwymJSj9c=;
        b=0xfd+N4WCMjACezZ90jFhyWa2SD9gC7yMH7MqywmxkNtEtRFO6QmJYnQiFbKoIzDaf
         9UzKFhTn7z2jvO6/vMj3n2TFYHNa0NZGhhhBOLHaEfusjNCKpa324Z1ZYqKfT41lI5K+
         LEfJV7KTQL5NGSqFp3IvCc0ItR6rHKYt8vi0H5VFqli3M4n22yJzp6r2Gm6mNGVEwW5y
         ZXQv/4ugpr6TfRHuugAdFFQJnxEb13yEgpJmUgbK8oMGV/vUAF/8wfk6Eddpt7nsFxza
         NUsU6IOQdGaFkqgY6aFn7G2WacczP+Yc57Ayrhp0z7NS/3DpSovbM1MVu37fSoDahro2
         pq9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.199 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvmtairZKk9Zf1xjF5CcFd86kJJ8n00fsGEwymJSj9c=;
        b=hPkBwdfRtdSiB3Vp9qrx4rCXrkt92ZtPRo4FzZPvt7cAQCnwn9tLF9WP7r04iHOTkX
         gpIbZ6haV/8A+M4XA+1+E6iMPC52cJ6Uko+GFsywYK8jukfLnVh6l2dOA+8lyL6dMboG
         sjWIISmf3nLNKf/ryzJiuUIq3fHwjbtDNlB9r4naShViaeftaHnc0iVfKPvRuctUTW4j
         IC0hRVgSdEixu6g4+ju1Z7xXK6Ytf9s/xg9/CN//y0qo1OSR8QWxbPbbMWyuLTm1YNvc
         DJhTkCU1MgVbRXe9t4Iit2QBBf/hUh3in00BdWfd+AFc3arP+vSQ1FwBvjq8+esXHM5K
         f3rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvmtairZKk9Zf1xjF5CcFd86kJJ8n00fsGEwymJSj9c=;
        b=PIoZHENRsxfbI5Hri7dgda88BX2+S60NByivEre1TYYNJ/F75lAdi0oul55LaIJowy
         PNXeIaeL63+RHphvZEjUhqD2fyt5HAm+T1Y8z/ju0ypR4mqFMMetNLXdXYKi59MwZeYV
         Uwr0UEpu+6zpkhKPZkW1HK7N4B2jxbSmoE/3G1VBdPxeCgmvRkAqmlgzXAHHfIMAdAa/
         h84EcY5uqERGQzmrcNrUDKPc8HY4clX1uqdBZSLqZwZXnqs+QOS+G3ZgI2QZuZLFRW/L
         MGSNKS37tkSr+Cto++zUh+Vooig300fETw7bUtokAAAhtorTXuhP60JZw/FbCyqeeCD1
         f3Eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZP0/jjq9YEeGD5duEieKMw7D6T1ZXjSpU6QCYYwkBrTeqB2s4
	UYAKwYC9lVxSYYu3IZzTWKk=
X-Google-Smtp-Source: ABdhPJxgQGlYoKtWkn2iuJmM7oAIvuNRURCqXELtvidxUILHaqCW1XFruuO48DRS7gP4Tx4+lgyPUw==
X-Received: by 2002:a05:6000:cd:: with SMTP id q13mr15933800wrx.346.1617949114415;
        Thu, 08 Apr 2021 23:18:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6204:: with SMTP id w4ls3590873wmb.2.gmail; Thu, 08 Apr
 2021 23:18:33 -0700 (PDT)
X-Received: by 2002:a05:600c:1548:: with SMTP id f8mr12236395wmg.81.1617949113540;
        Thu, 08 Apr 2021 23:18:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617949113; cv=none;
        d=google.com; s=arc-20160816;
        b=ko8MDhHUfhA5Q6/DxnUiHqaYjb+AQZTo4ZM6xCKsXnz6BA+u8HCY0IJpjlz14Ai0SN
         /bWI6NlUjF9OCgiF+PhW0rSnE5+2+CfaCUSDwYmAzxYSGEv/06SptolxFA7SAwn5R0jm
         SoVT45evmKf1SBlvua63sgrB20d3Y0tHTYZUx3Ppyqby/FAd7wNLSBvV5jt6e3nJtLma
         Hzslik86P/psIZii8qCMGxNmiyHQ+l0DCHw3mfbIaUz50JbkJ/Lp8O+/VsCzqzI4Xk3L
         ES77wIYsRdC8Yfp4bgslEeGB0vOJx1CbGAx47DNgt7vO2JjdhInYHoMfcm1A164I1YNr
         W16Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GvHEX5VJhNaodtmCmmex+400p92Ha0iQXYt+g3GclD8=;
        b=ZGEeIUxw4TYh5AcZqJb5gyAITKGkDbqaftpYQBFDeR8+FbTDLc2qJUNvQWqdXtH0Ts
         PzXlt+Lx8+yFatntH6KKpGESxk9ivOAg9zKiwWQVEGHjJWViphlrI8+3MbiWMKNzzICT
         DmYx5QKdH84RtRE1tGurY/Xa04+PpkFc19W1G0P1qYFiS1LERV5UIqKzlJG/FlTxpQkR
         2tTi2J9Tjj2WSJu4UO9Yit44wYMr+AZmNA+Vyl9YukWOmIJqUiqG/2y1Ms3Sr0JNlJoc
         xnYpzsD9qfTeeTI5dHFfcT9C75z4vZWQHR0QkFqvOWuEJ9sgQL8G8jdUIE6vOz93IJ7i
         6FwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.199 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay9-d.mail.gandi.net (relay9-d.mail.gandi.net. [217.70.183.199])
        by gmr-mx.google.com with ESMTPS id w2si822179wmb.4.2021.04.08.23.18.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 08 Apr 2021 23:18:33 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.199 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.199;
X-Originating-IP: 81.185.169.105
Received: from localhost.localdomain (105.169.185.81.rev.sfr.net [81.185.169.105])
	(Authenticated sender: alex@ghiti.fr)
	by relay9-d.mail.gandi.net (Postfix) with ESMTPSA id BFF84FF803;
	Fri,  9 Apr 2021 06:18:28 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alex@ghiti.fr>,
	Anup Patel <anup@brainfault.org>
Subject: [PATCH v4 3/3] riscv: Prepare ptdump for vm layout dynamic addresses
Date: Fri,  9 Apr 2021 02:15:00 -0400
Message-Id: <20210409061500.14673-4-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210409061500.14673-1-alex@ghiti.fr>
References: <20210409061500.14673-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.199 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

This is a preparatory patch for sv48 support that will introduce
dynamic PAGE_OFFSET.

Dynamic PAGE_OFFSET implies that all zones (vmalloc, vmemmap, fixaddr...)
whose addresses depend on PAGE_OFFSET become dynamic and can't be used
to statically initialize the array used by ptdump to identify the
different zones of the vm layout.

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
Reviewed-by: Anup Patel <anup@brainfault.org>
---
 arch/riscv/mm/ptdump.c | 67 ++++++++++++++++++++++++++++++++++--------
 1 file changed, 55 insertions(+), 12 deletions(-)

diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
index ace74dec7492..aa1b3bce61ab 100644
--- a/arch/riscv/mm/ptdump.c
+++ b/arch/riscv/mm/ptdump.c
@@ -58,29 +58,52 @@ struct ptd_mm_info {
 	unsigned long end;
 };
 
+enum address_markers_idx {
+#ifdef CONFIG_KASAN
+	KASAN_SHADOW_START_NR,
+	KASAN_SHADOW_END_NR,
+#endif
+	FIXMAP_START_NR,
+	FIXMAP_END_NR,
+	PCI_IO_START_NR,
+	PCI_IO_END_NR,
+#ifdef CONFIG_SPARSEMEM_VMEMMAP
+	VMEMMAP_START_NR,
+	VMEMMAP_END_NR,
+#endif
+	VMALLOC_START_NR,
+	VMALLOC_END_NR,
+	PAGE_OFFSET_NR,
+	MODULES_MAPPING_NR,
+	KERNEL_MAPPING_NR,
+	END_OF_SPACE_NR
+};
+
 static struct addr_marker address_markers[] = {
 #ifdef CONFIG_KASAN
-	{KASAN_SHADOW_START,	"Kasan shadow start"},
-	{KASAN_SHADOW_END,	"Kasan shadow end"},
+	{0, "Kasan shadow start"},
+	{0, "Kasan shadow end"},
 #endif
-	{FIXADDR_START,		"Fixmap start"},
-	{FIXADDR_TOP,		"Fixmap end"},
-	{PCI_IO_START,		"PCI I/O start"},
-	{PCI_IO_END,		"PCI I/O end"},
+	{0, "Fixmap start"},
+	{0, "Fixmap end"},
+	{0, "PCI I/O start"},
+	{0, "PCI I/O end"},
 #ifdef CONFIG_SPARSEMEM_VMEMMAP
-	{VMEMMAP_START,		"vmemmap start"},
-	{VMEMMAP_END,		"vmemmap end"},
+	{0, "vmemmap start"},
+	{0, "vmemmap end"},
 #endif
-	{VMALLOC_START,		"vmalloc() area"},
-	{VMALLOC_END,		"vmalloc() end"},
-	{PAGE_OFFSET,		"Linear mapping"},
+	{0, "vmalloc() area"},
+	{0, "vmalloc() end"},
+	{0, "Linear mapping"},
+	{0, "Modules mapping"},
+	{0, "Kernel mapping (kernel, BPF)"},
 	{-1, NULL},
 };
 
 static struct ptd_mm_info kernel_ptd_info = {
 	.mm		= &init_mm,
 	.markers	= address_markers,
-	.base_addr	= KERN_VIRT_START,
+	.base_addr	= 0,
 	.end		= ULONG_MAX,
 };
 
@@ -335,6 +358,26 @@ static int ptdump_init(void)
 {
 	unsigned int i, j;
 
+#ifdef CONFIG_KASAN
+	address_markers[KASAN_SHADOW_START_NR].start_address = KASAN_SHADOW_START;
+	address_markers[KASAN_SHADOW_END_NR].start_address = KASAN_SHADOW_END;
+#endif
+	address_markers[FIXMAP_START_NR].start_address = FIXADDR_START;
+	address_markers[FIXMAP_END_NR].start_address = FIXADDR_TOP;
+	address_markers[PCI_IO_START_NR].start_address = PCI_IO_START;
+	address_markers[PCI_IO_END_NR].start_address = PCI_IO_END;
+#ifdef CONFIG_SPARSEMEM_VMEMMAP
+	address_markers[VMEMMAP_START_NR].start_address = VMEMMAP_START;
+	address_markers[VMEMMAP_END_NR].start_address = VMEMMAP_END;
+#endif
+	address_markers[VMALLOC_START_NR].start_address = VMALLOC_START;
+	address_markers[VMALLOC_END_NR].start_address = VMALLOC_END;
+	address_markers[PAGE_OFFSET_NR].start_address = PAGE_OFFSET;
+	address_markers[MODULES_MAPPING_NR].start_address = MODULES_VADDR;
+	address_markers[KERNEL_MAPPING_NR].start_address = kernel_virt_addr;
+
+	kernel_ptd_info.base_addr = KERN_VIRT_START;
+
 	for (i = 0; i < ARRAY_SIZE(pg_level); i++)
 		for (j = 0; j < ARRAY_SIZE(pte_bits); j++)
 			pg_level[i].mask |= pte_bits[j].mask;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210409061500.14673-4-alex%40ghiti.fr.
