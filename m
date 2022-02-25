Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBW444OIAMGQEYUPTZIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id C8B274C44B7
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 13:40:59 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id v17-20020adfa1d1000000b001ed9d151569sf835811wrv.21
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 04:40:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645792859; cv=pass;
        d=google.com; s=arc-20160816;
        b=FXolOmzn84R20/i0qQ1wSir5weq1c/2cw2GOLkIKq7jiU5H5Q5EEfBOrpDfGbBByVe
         7kf+tpaPpZ19Myw6GeMxTHDEvhuoT7e70x1hadpem7dUIfMwgUyVRGXfI9jfLpDrgP1K
         enDtppVobfAQ1kdZHupwZwZ14uAuZdeMJrTg657Ze/KKY9iNraWENjZyd+H2uZ/MhuaK
         P+P4RKHuTFUnt9CS48FGYaPqI+Fso9f8obsYnRvwszf+8Q7yudGs8wgIugCmhjQ1KQMb
         lPa/g8cmbZ5hGOwJiGFWNBgfHJyZOq6qImqgXBWDh6/j1DbPczn5o43PC/NWbwcyqsZ+
         XY/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Wu4lQUa2HEvFfG42QadG3PQqrVOkSjmP97qoUqGaeLc=;
        b=0TzIs04hvADERotoKc79y44X5i1TMjVC2QplfIGDIFyjXEbHv5F4HewfPiHD3HMc/l
         SoEOi7isEG4z46dhZ1tBiBW+pznmgT5Lb09JpFZb/FGXxGOeRmTv1V+4PgPANFHXTS3a
         9UD6JZ1FWWd2jY/BRFBoOIJc5w7HlH5S+t8FZ/aG7HYXxFlsi9Jcdf3znAtpSuaVLWto
         y2l6J+WV6j+Wv3Egd+USKD24k+MqEC+ySFa3sPjZiKGCLwyq0xySGyeBbnpd+Kg8XbN5
         xRwGLs/g2Uo7yXrJl9yruqAG/AKpE2w/VQM8GHpmEdDMoATvhLHkL//YltI9V+N+3ZDt
         w5mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=Ae6uwJoC;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wu4lQUa2HEvFfG42QadG3PQqrVOkSjmP97qoUqGaeLc=;
        b=YWSQj9HcGSIpXBvEa4rfXsRUspvC+5S3jaqh95ggTKaML6LEvAh6u3a178YIwu4B9Y
         ADCpNzYc2cooJ/lsZDJ7/58JCSLFep4y7qfxZr6T2ovEinnqUnJsOz5V7wCJ/Odo1wIq
         hk6QbXJ4eAA+Yh5eQhIX074sqsURk9FJW8fV+8heU8LAsQXjr1Wl+Tga8C/bQ+FcAhU7
         LlT3ZP+l2PlaGJh8p8Y8QV1J8NfxWxfN8cseyFSJErn/nh81WHSrDSv3YMIhvk52e9EN
         ApR2fBUZcDFfS1w2pKdo2Y7OHGtDm/zub7RwU7aRC25e59u24onYy1v5SqpbegqZx4TJ
         L5/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wu4lQUa2HEvFfG42QadG3PQqrVOkSjmP97qoUqGaeLc=;
        b=ieRY5bst0/YoFK32jBAxROj5WMrdnz2YWz1CeneeK+YGj3FD4F+CK3AZ+ZSvpOXZ7g
         q+Fvz574XsWSe22UsLG/8gJxofKbJlItH9TLrmmvFnKtLfqPFONdWW3Am4AV6vFijjmy
         Jube985lBbf615I8DUlEKLO/QvNuiT4iKXC9ATVlbKagYs+Dc3P6QuQdB13gQf8mnaub
         1T58+wM0t2Tx7lemxXKIgB8jjlfVHsS/zy0cLVIpWeKEN06umpwgAPxyqCAAjyK57g6e
         8VWlust4Q2jIg1QUNUKXCGriiRmfEkBWiM/oVLBa/1gCNfZRJiL2lMrPpG9kM2GAgy8w
         BBpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lctDm0xnnz68OVVAlpuuH1oMqKD4QzmR4RU+bXpouvA9ab+Ar
	ZGGSNTXe/E3LisO+RPEGe+s=
X-Google-Smtp-Source: ABdhPJzpmVEJzGYuZ8dqnJlXKc6EGTny1T0qm8NFJdn5dAs9R7naFtmO2mPkoVcAyrxnSe5tsM0ULw==
X-Received: by 2002:adf:de03:0:b0:1e3:f45:9eb4 with SMTP id b3-20020adfde03000000b001e30f459eb4mr6061318wrm.647.1645792859398;
        Fri, 25 Feb 2022 04:40:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fc6:b0:351:e65f:f614 with SMTP id
 o6-20020a05600c4fc600b00351e65ff614ls488438wmq.1.canary-gmail; Fri, 25 Feb
 2022 04:40:58 -0800 (PST)
X-Received: by 2002:a1c:25c4:0:b0:381:1b4b:117d with SMTP id l187-20020a1c25c4000000b003811b4b117dmr2573831wml.156.1645792858472;
        Fri, 25 Feb 2022 04:40:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645792858; cv=none;
        d=google.com; s=arc-20160816;
        b=C7w9RXNoiHU9Sgn10KZyGj/u7etkBrjV1qS1nfX+FBDjn1W7XTwOZ81miGaTLAP2LQ
         bT23vCCgIN8wFSKIwLDsZ/zkEajaTIrOy+uDt2hWUqEztPO9oKbD2KwceFqKpJ3YFMFJ
         0MFN78gcpdLGALtLiWx17/Q0RPVMws2pk8sxB6BkQBIdgFk7FZ4KZzk6YreythyGEmay
         ia9fZENQOv8oFLA9G5gtnj+NZKhwbiSr2WVoaZip1JVlp7WVrZ1sS8ufk4yW3j5wcjCT
         QZYiSHPvc7s+iM7wI1rOXN6ix97/Gcxl+f2mW4fPAKem3wnV4JEZKJEJsGi1/iu+n3uF
         o5Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=PQyFtNV3tW1qRmwZ8HqaxvUDcyO7BHPqZZLC0geQ1k0=;
        b=OLL6coQNWlXaxnhnV//Do/C5HOJDP/0vKgzjTwHuvQDTvEUpUT/Kb9yE6f3iru+Ku8
         Duuz4c4moUan9AV0wUemY0jcTrB80VKJPnlUSEYH2vKb/GM9CSdD2iOKw0AjpomqvD7U
         vgkVNxo49epvPioTdX77rebqmShOIpehLVurFFJjXGOq89IXAlMpMXeYEc7uSMsRCGin
         6AFvp4yCQMulzjwud217TsLsn+kn1mNGdgEMStduaH9ABTDwSnB8CxDa0KbNSiz7itfe
         atFg4NDXmNQypbzyuqg+b3NpmMJMdAXrl8A71e2zshpn3YXMvJaGLJnaAu4GoeZ5K60H
         xOyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=Ae6uwJoC;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id b4-20020adfd1c4000000b001e5c7933e8esi103460wrd.5.2022.02.25.04.40.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:40:58 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 0CF803F1F3
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 12:40:58 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id az39-20020a05600c602700b00380e48f5994so1293172wmb.0
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 04:40:58 -0800 (PST)
X-Received: by 2002:adf:a54c:0:b0:1ed:ab82:d5c with SMTP id j12-20020adfa54c000000b001edab820d5cmr5903429wrb.636.1645792857567;
        Fri, 25 Feb 2022 04:40:57 -0800 (PST)
X-Received: by 2002:adf:a54c:0:b0:1ed:ab82:d5c with SMTP id j12-20020adfa54c000000b001edab820d5cmr5903415wrb.636.1645792857391;
        Fri, 25 Feb 2022 04:40:57 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id b10-20020a5d550a000000b001e551ce8a64sm3228332wrv.9.2022.02.25.04.40.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:40:57 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v3 1/6] riscv: Fix is_linear_mapping with recent move of KASAN region
Date: Fri, 25 Feb 2022 13:39:48 +0100
Message-Id: <20220225123953.3251327-2-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=Ae6uwJoC;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

KASAN region was recently moved between the linear mapping and the
kernel mapping, is_linear_mapping used to check the validity of an
address by using the start of the kernel mapping, which is now wrong.

Fix this by using the maximum size of the physical memory.

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/include/asm/page.h    | 2 +-
 arch/riscv/include/asm/pgtable.h | 1 +
 2 files changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index 160e3a1e8f8b..004372f8da54 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -119,7 +119,7 @@ extern phys_addr_t phys_ram_base;
 	((x) >= kernel_map.virt_addr && (x) < (kernel_map.virt_addr + kernel_map.size))
 
 #define is_linear_mapping(x)	\
-	((x) >= PAGE_OFFSET && (!IS_ENABLED(CONFIG_64BIT) || (x) < kernel_map.virt_addr))
+	((x) >= PAGE_OFFSET && (!IS_ENABLED(CONFIG_64BIT) || (x) < PAGE_OFFSET + KERN_VIRT_SIZE))
 
 #define linear_mapping_pa_to_va(x)	((void *)((unsigned long)(x) + kernel_map.va_pa_offset))
 #define kernel_mapping_pa_to_va(y)	({						\
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 7e949f25c933..e3549e50de95 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -13,6 +13,7 @@
 
 #ifndef CONFIG_MMU
 #define KERNEL_LINK_ADDR	PAGE_OFFSET
+#define KERN_VIRT_SIZE		(UL(-1))
 #else
 
 #define ADDRESS_SPACE_END	(UL(-1))
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220225123953.3251327-2-alexandre.ghiti%40canonical.com.
