Return-Path: <kasan-dev+bncBDXY7I6V6AMRBJF4XGPAMGQEYN2JX7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B876C6778DB
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:15:00 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id cf15-20020a056512280f00b004a28ba148bbsf4870098lfb.22
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:15:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674468900; cv=pass;
        d=google.com; s=arc-20160816;
        b=t0RgSgofeS44jRSoaNud22KIMXknUooeWW7KZoWw45gZrnUVylJbJWgM89SaJmDr/P
         WejJv+KiTpauPUIGCvQeh9pKYGp5eiGS3qqWx/0ZJrz1FmAcxHdCHk6SqOJ9YXKlfU4q
         YnqtCQmleZWY9RLUp72i0ACpXUVq3EfBQ4DMCa3BePxICpKD97eskBebs1iDvU8d1G2i
         XtKdAKN3bNEPcPPDgv2DGs9+ebX+xV+A+U84KLCyFMAk45Idb/nU/jp/arm0r6pLZ0d4
         RcRz2dOYEzN9gt7Nx38Qt29Mi4B9qUqJRM/7lx/9jTVuz8SwIS/OjY/w5ivHvkPfrAwe
         uqfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fbWxhq4/bKbz4czpkmMyGT4tClNrRxfmHHO6sSYHbPk=;
        b=xsqfQ8lgYsKCnddM75/9Ua3Unr12hoYZJzTucErbS4o/xrteM16e1c0AB1HUkl+Wtu
         UcPkkFo8o+aNojUIjuBJrsH2IbDtac6ILPiHDWKuAB/tSHvam9q3L0E4ee/YNXOq50+9
         +H6q/ZtAK3DHEb+SwGWTbUcEOQsoABO7s2JmPMHSahVvxyrVlzfOfmwTY+hWp8og0Cgm
         jStaOP54Eghw9vW/HtXHcI05trb1Au/Q+1WclOHYwxtFd8WkkD1ZVyeMsmjh4gBeAytt
         fAviP20NDFwtPJDf2m3dl38seAkpUP89tVxMV/RmkXuQPmoKOzbcd+z2QUl1vPg6OsE8
         iRIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b="B/+9cQa9";
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fbWxhq4/bKbz4czpkmMyGT4tClNrRxfmHHO6sSYHbPk=;
        b=o94djY/xEXk2A67woFFIf8AZ6IFyQJjkod4x9aW8NxXDvpxEj7FdTwAdr/riM45rHf
         kAHlU7IPs17O/qvPd3s1hUFuxeqgh65LEFRDO81/twrjWyra71YJwWrJth5dU+r6FJ35
         6JHshlnSwL/bauyTaMFuXO1OtMJ7KyGjMaygkhsgACkO12mcH2kAj4jaY75iK8D4DleD
         w7Xx4rN0yWy2QQxpLZx/XXnT1dXt3N/DfGAjdcSqadcOPqEml7BnrpSyX9PtVlhUZfus
         E1/rJ18yVzs21R/1UFA1+gL0dfY7ry2GhetT98bJMtUBqDa+kewUeC1xW0b0pswX/Bia
         Y8zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fbWxhq4/bKbz4czpkmMyGT4tClNrRxfmHHO6sSYHbPk=;
        b=XXudJZuK1uSe8fU1kjhMfAQrBYTHWm2g+t/tCTWE1WAq0lRboSxZggUmJquN2xm+5k
         JXvRVrlDzcP3X80kUrKBumNaQ9PI+xgh4C36yw1UfFddynGSTuLzNp7pSU3gHcrXKcXd
         9WD9IQOmwY+bPWHSkd7exSoR7278JOO0L6jIJOdanpj/NE4QL+PWs4BB39+uQzLn4eUm
         F4lhjm2hUSgf9LHSPSsQfJ6uNbq7HS19Gxsxoo7Lo0X/tqNfb8eLi051Sl6rFBTqFev/
         vjzw5qTjeatf1UkVmQxJfWPz1DyujMT8rRqNZ/1ty6gHquYinl5M2x41vqxHe7562Kuf
         5hQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpn0wAWterrPod/E6eGsR5rb7/k9DtFHr4rQaoWCeNkOqSj/eIg
	miLS/K1uG0l2N/FtexLFR0o=
X-Google-Smtp-Source: AMrXdXu4rOShHTm57w5z3UnSeeO2xkqTXs449Zxh8f3sEpYluWgEEdtbhCucMf+I+oiRWEBwnrbUKQ==
X-Received: by 2002:ac2:4c09:0:b0:4b6:e525:6fcd with SMTP id t9-20020ac24c09000000b004b6e5256fcdmr1437849lfq.522.1674468900324;
        Mon, 23 Jan 2023 02:15:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:314c:b0:4d5:7ca1:c92f with SMTP id
 s12-20020a056512314c00b004d57ca1c92fls4107402lfi.2.-pod-prod-gmail; Mon, 23
 Jan 2023 02:14:59 -0800 (PST)
X-Received: by 2002:a05:6512:b05:b0:4b6:d28a:2558 with SMTP id w5-20020a0565120b0500b004b6d28a2558mr8047242lfu.49.1674468899221;
        Mon, 23 Jan 2023 02:14:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674468899; cv=none;
        d=google.com; s=arc-20160816;
        b=UYrqcLpenT89YTmQEUOxjqcpCW257FDARuz8GvePtcE15PRGGXBqMPmgE8HqSr+L3A
         umu5DpzV1+0wYVpvMMoCeF6BHYiV7mBjTvAbYAVccZQpMfepWQ+H1S3Wi+VnzcEOOO60
         7ouk+hLDCt7DOEt2EkHAk6WDVWkm5FS05qunlTHJjd1jAQ8MMetNouZbLxhvhVxSS4YK
         wXj1qamhVwhiT/4mbTwgzW5sM/nYjSAfU+8zH/9nUbVTjJ7b2zHv3CUJ0k073/tNfYcm
         HT0Qj/BI1+s2GWn260tCRxDYAizV9t2txlwIrup3l4iP3Sg1gvpn5Q9HDn2M0SQWQwAb
         GNIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7CyWdPwmsoEln1rCKIxbXcZ7tw/K7pVLqcNgYwRXhLM=;
        b=sAdUDyp1l45bwQrPEy8Rpf7d+J8rE9zD7u82HaVWeNOOlKspyPEmSYYdPZDYdD5Sno
         HM+00Z852esyMiIln4+KW+pSFwKjeTeB8Wd8MgMQdjmCDr7EN9kHw+clD4PxPuJcaT+6
         pO5vdnMHfruKgXGNOKorzZXbYoDJW7wggRKsR5nIvi/wf/KA8nZdgDQlN74lfI2YxiFA
         yZ97CobP/ZJ+8X06l9jldAFuEx1YOLU5Cef3Aj0DIQ++4+qXnbwIQryE3hGkvY1vuR9g
         EAGtr7s502VfC+tFpPoeKdbT7yhLsYerJNcn2TeWE2YezUy9hUmT4iO7pwANvKnTEJnt
         SZtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b="B/+9cQa9";
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id u5-20020a05651220c500b00492ce810d43si2176943lfr.10.2023.01.23.02.14.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:14:59 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id bk16so10246143wrb.11
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:14:59 -0800 (PST)
X-Received: by 2002:a05:6000:388:b0:2bd:dc0f:5ee5 with SMTP id u8-20020a056000038800b002bddc0f5ee5mr25724943wrf.22.1674468898664;
        Mon, 23 Jan 2023 02:14:58 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id h13-20020a05600016cd00b002be25db0b7bsm7130225wrf.10.2023.01.23.02.14.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jan 2023 02:14:58 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 5/6] riscv: Fix ptdump when KASAN is enabled
Date: Mon, 23 Jan 2023 11:09:50 +0100
Message-Id: <20230123100951.810807-6-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230123100951.810807-1-alexghiti@rivosinc.com>
References: <20230123100951.810807-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b="B/+9cQa9";       spf=pass (google.com: domain of
 alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

The KASAN shadow region was moved next to the kernel mapping but the
ptdump code was not updated and it appears to break the dump of the kernel
page table, so fix this by moving the KASAN shadow region in ptdump.

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/mm/ptdump.c | 24 ++++++++++++------------
 1 file changed, 12 insertions(+), 12 deletions(-)

diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
index 830e7de65e3a..20a9f991a6d7 100644
--- a/arch/riscv/mm/ptdump.c
+++ b/arch/riscv/mm/ptdump.c
@@ -59,10 +59,6 @@ struct ptd_mm_info {
 };
 
 enum address_markers_idx {
-#ifdef CONFIG_KASAN
-	KASAN_SHADOW_START_NR,
-	KASAN_SHADOW_END_NR,
-#endif
 	FIXMAP_START_NR,
 	FIXMAP_END_NR,
 	PCI_IO_START_NR,
@@ -74,6 +70,10 @@ enum address_markers_idx {
 	VMALLOC_START_NR,
 	VMALLOC_END_NR,
 	PAGE_OFFSET_NR,
+#ifdef CONFIG_KASAN
+	KASAN_SHADOW_START_NR,
+	KASAN_SHADOW_END_NR,
+#endif
 #ifdef CONFIG_64BIT
 	MODULES_MAPPING_NR,
 	KERNEL_MAPPING_NR,
@@ -82,10 +82,6 @@ enum address_markers_idx {
 };
 
 static struct addr_marker address_markers[] = {
-#ifdef CONFIG_KASAN
-	{0, "Kasan shadow start"},
-	{0, "Kasan shadow end"},
-#endif
 	{0, "Fixmap start"},
 	{0, "Fixmap end"},
 	{0, "PCI I/O start"},
@@ -97,6 +93,10 @@ static struct addr_marker address_markers[] = {
 	{0, "vmalloc() area"},
 	{0, "vmalloc() end"},
 	{0, "Linear mapping"},
+#ifdef CONFIG_KASAN
+	{0, "Kasan shadow start"},
+	{0, "Kasan shadow end"},
+#endif
 #ifdef CONFIG_64BIT
 	{0, "Modules/BPF mapping"},
 	{0, "Kernel mapping"},
@@ -362,10 +362,6 @@ static int __init ptdump_init(void)
 {
 	unsigned int i, j;
 
-#ifdef CONFIG_KASAN
-	address_markers[KASAN_SHADOW_START_NR].start_address = KASAN_SHADOW_START;
-	address_markers[KASAN_SHADOW_END_NR].start_address = KASAN_SHADOW_END;
-#endif
 	address_markers[FIXMAP_START_NR].start_address = FIXADDR_START;
 	address_markers[FIXMAP_END_NR].start_address = FIXADDR_TOP;
 	address_markers[PCI_IO_START_NR].start_address = PCI_IO_START;
@@ -377,6 +373,10 @@ static int __init ptdump_init(void)
 	address_markers[VMALLOC_START_NR].start_address = VMALLOC_START;
 	address_markers[VMALLOC_END_NR].start_address = VMALLOC_END;
 	address_markers[PAGE_OFFSET_NR].start_address = PAGE_OFFSET;
+#ifdef CONFIG_KASAN
+	address_markers[KASAN_SHADOW_START_NR].start_address = KASAN_SHADOW_START;
+	address_markers[KASAN_SHADOW_END_NR].start_address = KASAN_SHADOW_END;
+#endif
 #ifdef CONFIG_64BIT
 	address_markers[MODULES_MAPPING_NR].start_address = MODULES_VADDR;
 	address_markers[KERNEL_MAPPING_NR].start_address = kernel_map.virt_addr;
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123100951.810807-6-alexghiti%40rivosinc.com.
