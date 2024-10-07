Return-Path: <kasan-dev+bncBAABBA7BRW4AMGQEDXSMUZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7538F9923DD
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2024 07:24:21 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6cb3d5736a4sf82340696d6.2
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Oct 2024 22:24:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728278660; cv=pass;
        d=google.com; s=arc-20240605;
        b=J3nj/ZN13quH1MYs0xaJOlOcocZF6M1ZdwCSaMVa2NceNj1gbcpRR0JoefJ+uNhL/+
         Dnpx302i9qf/SZZilEooYSuudSM7np3pjJka1avX6KPz9ZjZaGhwHkN3zSwlNdaCZH3g
         azRWa+Q4n+fbE8N4uPKQ62opDne81iRRLrU5JfECQUc0YMdHeQ8nu01QEU8gGG85Z6ry
         2bYDl4a+cEMxJYxkP/sSnmaXhvsHCqSUBctOw3VV5DFrui8X3AMuxiG96XmliZ6JPw0M
         rRQ1zcsMW0Rjn3/HO/YJx+F6ecjk/Brwu9yezHYAa4iOL4zH9h8oHZV5/3aZct4D5ZW7
         ZJqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Oyrruw4oVHQEwXfwlOqCXW5LbFz7YVWSRJGzOvZfY5c=;
        fh=u8dlLx6ohRmaIihlPU6BGfAV5hHex5j4kIxJJbJmlQ0=;
        b=I26+JwSEP+afL/w47TvLWI9yh9MfCyXEG/EdtxdeY80iHTKvyQeki1T906JSCUhvh2
         unW259snJQ6i951UFhSJynMUtwkKc5mJ1F3WBYPg3TEJJktqJlQY7mwIUeJgsJ7kPpgP
         C4iwQkJgjuAD+aS70JEo2dTrNUda5lwvQTLg1zWLBtN6zSHaH+FojQ9GQAl/xbzJg2+C
         4XUdbF6qTYcvmAW3+x8wTDgg/oyeLnrUR9KHQkXH32TMshRKR0Vd7tSdvilxkHNs1c/J
         gi8DTUtsswvKqy4NDT21ksCAepVIgX669mpTGN1hzyLRvxriUVUPYnM5gnqdzwp6YP/L
         cOKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=EkcWkra3;
       spf=pass (google.com: domain of melon1335@163.com designates 220.197.31.4 as permitted sender) smtp.mailfrom=melon1335@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728278660; x=1728883460; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Oyrruw4oVHQEwXfwlOqCXW5LbFz7YVWSRJGzOvZfY5c=;
        b=BuiyqaJ7N1rIo48Wjs+thOE0qNTJaU5o/mAYFJgYveVS6RV7wfKKEHkfWHVgiB3Cto
         DvKW03Qu0GWxgVvPKmdXcBrnQoGYR2LFc5HySRv1p4THHssrpDY9mLlfK/dzYOS0Br5w
         fcdt+sCyGI71EzviLgtKq9fZgt+ckeYmGer4/QUhmlv0LsxFJdlg2UiC8RJGy50NenFM
         x4uGVpWVndctdbvMD7A4TB/2YldZXuht4fnYOJhfDriCP+Nlz4d4pz+GSt7mNvUGq6WE
         aYb2JM3mc3CZbqxWtqt4e3QsLH4b7ywQhKH7NeXwtIw6PFdU3UPRJvP+xHv7RnfyG7LK
         eNqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728278660; x=1728883460;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Oyrruw4oVHQEwXfwlOqCXW5LbFz7YVWSRJGzOvZfY5c=;
        b=RebVr/E8hjg0r1U8RXpev3bURaLcsefsU0NWmUiFKbUYYCEeH1XsJnuP7821qtxtY6
         uGMiahEn9/JbnRXeCANHInCZoK8nMIV7b/0o6zkUC1kn0BZqthq0/xRxkCeEzZuxDlNT
         X7ptkQhxkN3l7tNioNuQFINkXB3r/ah2pAo4OnFx9Xxdf2M1rUWNmp0PyWFO+3kxTa+V
         yI5fm4L2f186ABco8KOQohwqx6SFiucMr+T9U9OAbh5QYjOenMPhj03B/s2rL8Mkz+6E
         lcR1l6DjGISJytzSjuK0qZLK+81cBiGEzu73CgBSM6sOa9JmlrKsTZhUpX9SFlnz9tOB
         Makw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9O/ecLtwL2ErDcys+j4bqejXKgcZyhYIAgN63cGEZkSMtGP9PLYVurTJx4xqC86PKWrt/Zg==@lfdr.de
X-Gm-Message-State: AOJu0YyMWZhWdoZN4OW75BnbTKVexeNushrQU7GG0MaVDwFutGXu/1zQ
	O3xIaw6snVKaPTXwWBJguyJ9AzFFA0FW7nwNdt72AEuMnhBdnCW5
X-Google-Smtp-Source: AGHT+IHekeZNhMqbLTq2YWGUvbnbnjza7nyt03Emk5T1Ogsvfvb7XUrrEfR70x1bBE01g1ZxvNEgYA==
X-Received: by 2002:a05:6214:4698:b0:6c5:52c9:950c with SMTP id 6a1803df08f44-6cb9a30da9bmr159827566d6.25.1728278660038;
        Sun, 06 Oct 2024 22:24:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4ee5:0:b0:6bd:735f:a70e with SMTP id 6a1803df08f44-6cb8fdd53adls81276066d6.0.-pod-prod-06-us;
 Sun, 06 Oct 2024 22:24:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWz5iGq7btRR5JAuqndfoHaX2oNXvCijT3sGRF5qw57ynkTAkLlZxOAVGF1yPeIMlnbHnHpLZcyhI=@googlegroups.com
X-Received: by 2002:a05:620a:3725:b0:7ae:6e02:6a9d with SMTP id af79cd13be357-7ae6f43a92amr1986938185a.26.1728278659542;
        Sun, 06 Oct 2024 22:24:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728278659; cv=none;
        d=google.com; s=arc-20240605;
        b=HkLW6YvOaQvM7gLTyNwkBVedpvDa3e6W8AEwl2eo6nbVWbDipqkTup1Vtk/NW8Pmfg
         lq9YCKOy9dK6lHkivmdQAClOtKuigRWcHuhsUV8YaMWwIajCyclJPRnK2yNEL47G+dEL
         wus+KhueFAuEF6uxsZa6pOQrXfuofBoU57yukUEZWBOWL8wwm6qna2zznSO/+7pWwJzz
         3JAkY7AZU/151JUPG0TFmnZwV3XM7ZTlRxHlttr94LV2LafyQY62rjfckn2APO2DysJt
         1FmtMhHOJhaJjuv9X4UpgU8KqySMFsGNLiAN4L3EJBP6FrCEWrhvWozK9UxbKAfnKi2w
         MZ4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=324PJEeBYpJfWCK8xWbXB9A56qDSOD1jxIROj5ssz1g=;
        fh=59SbSyHOf244WXHciGVZHvq6Jfk6BA0joREgcz7uvqE=;
        b=jY3l5iZRMTJGl2W9LyvYg/GhB5Em/wQYo1rVTIrg7V69j/BAYfrPmIozWXlcuK7ucz
         arCeepMJX9GQEV8DA5hJ2zrQ8Z3xuZBTOEZfmVptzvh+804CmAtRQloMf7/AlWt4o4UX
         oJYga6QBfJmZ8gnlyNI+elu9nTvGt4l6YXAW0hgYVCDUmEi+k9Yo+ON/Mlfj79oGKU14
         30tj+mgDptIzCCoqp1L4GU9YnDxESV6VZdYJnBPifhsV05sTMSHDAjaLfIvTd+blkuhS
         XdFW+GGPoV56zlCFy0LSTgDmo9kdWn01l58fhHVZJA0LAAjd9zH6LDSSJ8ONdzs7E2KP
         tmrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=EkcWkra3;
       spf=pass (google.com: domain of melon1335@163.com designates 220.197.31.4 as permitted sender) smtp.mailfrom=melon1335@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m16.mail.163.com (m16.mail.163.com. [220.197.31.4])
        by gmr-mx.google.com with ESMTP id af79cd13be357-7ae7565c80csi17782385a.3.2024.10.06.22.24.18
        for <kasan-dev@googlegroups.com>;
        Sun, 06 Oct 2024 22:24:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of melon1335@163.com designates 220.197.31.4 as permitted sender) client-ip=220.197.31.4;
Received: from localhost (unknown [39.144.4.86])
	by gzga-smtp-mtada-g0-2 (Coremail) with SMTP id _____wBnN4NccANnI_KQBQ--.20392S3;
	Mon, 07 Oct 2024 13:23:41 +0800 (CST)
Date: Mon, 7 Oct 2024 13:23:40 +0800
From: Melon Liu <melon1335@163.com>
To: linux@armlinux.org.uk, lecopzer.chen@mediatek.com,
	linus.walleij@linaro.org
Cc: linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, stable@vger.kernel.org
Subject: [PATCH] ARM/mm: Fix stack recursion caused by KASAN
Message-ID: <ZwNwXF2MqPpHvzqW@liu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-CM-TRANSID: _____wBnN4NccANnI_KQBQ--.20392S3
X-Coremail-Antispam: 1Uf129KBjvJXoW7uw4xWFy5XFWDGr1xGF18uFg_yoW8uF1xpF
	43Ca4rArsxXr1akrW3Xa18uF95t3WkK3WUt392gayrWrWUKr1UJF40qFWfu34UWrW8AFWa
	yFWSya45urn7t3JanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDUYxBIdaVFxhVjvjDU0xZFpf9x07joHq7UUUUU=
X-Originating-IP: [39.144.4.86]
X-CM-SenderInfo: ppho00irttkqqrwthudrp/xtbBhQlxIWcDZn9sZQAAso
X-Original-Sender: melon1335@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b=EkcWkra3;       spf=pass
 (google.com: domain of melon1335@163.com designates 220.197.31.4 as permitted
 sender) smtp.mailfrom=melon1335@163.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=163.com
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

When accessing the KASAN shadow area corresponding to the task stack
which is in vmalloc space, the stack recursion would occur if the area`s
page tables are unpopulated.

Calltrace:
 ...
 __dabt_svc+0x4c/0x80
 __asan_load4+0x30/0x88
 do_translation_fault+0x2c/0x110
 do_DataAbort+0x4c/0xec
 __dabt_svc+0x4c/0x80
 __asan_load4+0x30/0x88
 do_translation_fault+0x2c/0x110
 do_DataAbort+0x4c/0xec
 __dabt_svc+0x4c/0x80
 sched_setscheduler_nocheck+0x60/0x158
 kthread+0xec/0x198
 ret_from_fork+0x14/0x28

Fixes: 565cbaad83d ("ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC")
Cc: <stable@vger.kernel.org>
Signed-off-by: Melon Liu <melon1335@163.org>
---
 arch/arm/mm/ioremap.c | 23 +++++++++++++++++++----
 1 file changed, 19 insertions(+), 4 deletions(-)

diff --git a/arch/arm/mm/ioremap.c b/arch/arm/mm/ioremap.c
index 794cfea9f..f952b0b0f 100644
--- a/arch/arm/mm/ioremap.c
+++ b/arch/arm/mm/ioremap.c
@@ -115,16 +115,31 @@ int ioremap_page(unsigned long virt, unsigned long phys,
 }
 EXPORT_SYMBOL(ioremap_page);
 
+static inline void sync_pgds(struct mm_struct *mm, unsigned long start,
+			     unsigned long end)
+{
+	end = ALIGN(end, PGDIR_SIZE);
+	memcpy(pgd_offset(mm, start), pgd_offset_k(start),
+	       sizeof(pgd_t) * (pgd_index(end) - pgd_index(start)));
+}
+
+static inline void sync_vmalloc_pgds(struct mm_struct *mm)
+{
+	sync_pgds(mm, VMALLOC_START, VMALLOC_END);
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		sync_pgds(mm, (unsigned long)kasan_mem_to_shadow(
+					(void *)VMALLOC_START),
+			      (unsigned long)kasan_mem_to_shadow(
+					(void *)VMALLOC_END));
+}
+
 void __check_vmalloc_seq(struct mm_struct *mm)
 {
 	int seq;
 
 	do {
 		seq = atomic_read(&init_mm.context.vmalloc_seq);
-		memcpy(pgd_offset(mm, VMALLOC_START),
-		       pgd_offset_k(VMALLOC_START),
-		       sizeof(pgd_t) * (pgd_index(VMALLOC_END) -
-					pgd_index(VMALLOC_START)));
+		sync_vmalloc_pgds(mm);
 		/*
 		 * Use a store-release so that other CPUs that observe the
 		 * counter's new value are guaranteed to see the results of the
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZwNwXF2MqPpHvzqW%40liu.
