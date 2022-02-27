Return-Path: <kasan-dev+bncBCN7B3VUS4CRBGUC52IAMGQEL4YYANY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D41A54C5B61
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Feb 2022 14:48:11 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id h14-20020aa79f4e000000b004f3aa388c1fsf6239359pfr.6
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Feb 2022 05:48:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645969690; cv=pass;
        d=google.com; s=arc-20160816;
        b=eQ3WoAHMAYOSsE/2Dv71hwOM6xjKZItzimUKrYb/JbUxF6iVaKW5+bNAkPvSqgh1Km
         YRd5Wirz9LrLCp5+laJWNjfSIuwUGIYXCHWF7daflvc3m6R29GxY2OXXCxIezjwlGs3V
         93r7mIwZ83sfQIuaX4INKpxl8aSsE2tdnz4zKCBdKGOTyP3aJif0xbPSO52rvG9/hwIK
         Uv0VLaw47YOdqpYH+VuNNo0Wui+kDReCrPI3oJYrLFLGwPyoxRy82i/WGlmw49RGAqGR
         3NR6JCaGxsITObIODUClksEXIm+f3M9WhHdEURelWqC7X4+sdc7rFPLsOvbmHd8MAYIB
         Q5gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=rvRX78o5vPE91DqTgxbQN3GZ1A59wI0CaxaPQ8xvH5M=;
        b=auTFt2IbUgBYa5zHleb0RJ87ylNVfXK+0Hozj8U6oSTav4jCOaO+Po+G1ZFpbkUyos
         auhEABfojrF7sDIiZPJ1l0GzqoPf6j8V4awK8yJtodQs/5nreFwpAzoVR5WgCyQhCmZV
         xgzy7JoXX5aYcacpQ7Swq3bHxsNLAIQcTEwl5TVzMobzEHJqczmMIVj7Hz7d+R0UcQ1t
         TU75nNrNxJERstS7Iel4STM1OMWQdSdoDPbx3dffZHNfuyqZlilpb1pc6WYyS8mmIPyn
         GgfzsNiEcFk4p8XdWc3KUUQO4XfDxeUp4dgi4W0O4IQc5sZ2HSbbvTCt00GXkwv4kYc7
         PE2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rvRX78o5vPE91DqTgxbQN3GZ1A59wI0CaxaPQ8xvH5M=;
        b=i6/E0mJg5Irj/n5PZVAFIT0wDQcffGGsTc7IOq0m1XaA4/hKqKjpjqMrT3LHnknRVI
         Q30/1H4Exccose3sICT0EE6DEu2fJtyZt0FPrvX2hVz69ijnqZS1MEeuFky6Ls2WVNT+
         ZKSoEGjmEXTsYE8+nYClyq8TYsoPV70fWfL6khjOl9jKCz2uzHxb4p+bqHx5sswxrTeN
         odsIMKUV8rmGOQIAWPsBYIxU659EZsyW/S0WReqps5oQ7KA1AMbJvuB/nC1QuS/rT5pk
         dgwqsvAy8+QMcRWeMoIF9RyGqOugfOZK5ERUMwYNkU4FbX/nGiYbomcW1JYyAvtjex8c
         oUXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rvRX78o5vPE91DqTgxbQN3GZ1A59wI0CaxaPQ8xvH5M=;
        b=tXW5YIvN/a9krhxD+OM+lvbVPNpWL6/tC2VPKCM/XdZEN+uSaTr51COu8gjl0rp+hg
         D41kuB/GK3fGQHH5YUhbwUX+mikWjwaa8l3lAdhQtPpziTRdHiYQL865NBCY/lu49kdB
         XcU423sTaT7/VjdVdqSIOsSlJ5urx2Lvy0P3ix9b727SZ+qQO2kABZKv3JSQjuo46/so
         2auoN9MWlkVZtx0wFEdcgUWI7tG+dXQb6bz8HF8oJ1vIvJ2SMTR8FXo+OBDHXAInN2gp
         iVT2GF3CQvqTN7wDqc+yRQPj0fZo7hUoFGtvR6ywi8fEdreODxGf/022ewj54yiFLwWN
         gUVA==
X-Gm-Message-State: AOAM533qiYokTxdcnFNYdaRahWJeKM5tRazIPfc4x3IimdDhtvPA8sIP
	3a9WJg39OUxw6ULgvwUqVxk=
X-Google-Smtp-Source: ABdhPJzDk1+GQHBuYCJcgnVWsG6deagkWMOszHqbgH2nqrtJ+cMHbi6WEveSKnBsbGTtU53OclJXVg==
X-Received: by 2002:a05:6a00:2402:b0:4e1:46ca:68bd with SMTP id z2-20020a056a00240200b004e146ca68bdmr17021042pfh.70.1645969690359;
        Sun, 27 Feb 2022 05:48:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:139c:b0:4e1:5730:7011 with SMTP id
 t28-20020a056a00139c00b004e157307011ls4967970pfg.1.gmail; Sun, 27 Feb 2022
 05:48:09 -0800 (PST)
X-Received: by 2002:a05:6a00:1aca:b0:4e1:a2b6:5b9 with SMTP id f10-20020a056a001aca00b004e1a2b605b9mr16806880pfv.4.1645969689486;
        Sun, 27 Feb 2022 05:48:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645969689; cv=none;
        d=google.com; s=arc-20160816;
        b=pG7yyByZxzYCe8JHBpVwWM8kpJoZrN5AAD9Hky+lCvrfUAGG91l9TdMmyrq8yQgmQ4
         tHH8pbp5e/8b5WsBkQHMH+DFHejjeVCj2IH00a3rJYwmyThdtEqqESXSGNJABXO81chQ
         4c+rRlMakJkgarmS5duDhsHnvHn7u1PT0qzI3KlytPyL34ioz5Lbkr0ZplSiSaChdc2S
         0JztYkk0jsqty9xroha0w8AX0UtjXiz3ZmlZMmLz2iqZOWka7l9a5s1Xal2iUi44qDUP
         aNC7wFKSYZFoXCgGWgwbOEo0EfDjYHqzIHFLUhlTRjWvp1iqNLS8IXI9oVZCfJ20GhbQ
         rosA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=qKHqEUlPgzSrey7IWYLW/R+NJ3o+sXjaRHtJPpQcMok=;
        b=OIAL0KX5IhLN7vSGMF5EvpkbWPONzJpmZN54znnZuNepV/pYifyRfWs0+iaM5gKq+6
         2P/Zj0vCQiBoiobddxbxGNGaS50ZsRecf2C/OUJFqPJKoXchbTuNYuiQz3Q4fhKBf+Z0
         3nTfrEdNApMKIyrtFgOJGD8U5NShnnZafSOtTX9CImgeEUvjknE+JA2AkqP6garuO2Du
         ovTZpeHqo7WfTObLYtgbZpU8jgGaaPu9Jn/Mo6qohX7C2SxFZfv28hrEYMOIOLTpgYRZ
         5sgZRCOOFB4TQCfEIXdX464Ho1xHk8nHwWu9nm7YZBu0BEsUCv0HyYC0VOtdtlaFegT1
         GB8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id d24-20020a170902729800b001514a005025si211297pll.5.2022.02.27.05.48.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Feb 2022 05:48:09 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 5c7c15667dcb4ffea42594f429c214af-20220227
X-UUID: 5c7c15667dcb4ffea42594f429c214af-20220227
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1639986030; Sun, 27 Feb 2022 21:48:04 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Sun, 27 Feb 2022 21:48:03 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sun, 27 Feb 2022 21:48:03 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linus.walleij@linaro.org>, <linux-kernel@vger.kernel.org>
CC: <andreyknvl@gmail.com>, <anshuman.khandual@arm.com>, <ardb@kernel.org>,
	<arnd@arndb.de>, <dvyukov@google.com>, <geert+renesas@glider.be>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux@armlinux.org.uk>, <lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>,
	<masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v3 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Sun, 27 Feb 2022 21:47:25 +0800
Message-ID: <20220227134726.27584-2-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
References: <20220227134726.27584-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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

Simply make shadow of vmalloc area mapped on demand.

Since the virtual address of vmalloc for Arm is also between
MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
address has already included between KASAN_SHADOW_START and
KASAN_SHADOW_END.
Thus we need to change nothing for memory map of Arm.

This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
and provide the first step to support CONFIG_VMAP_STACK with Arm.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm/Kconfig                 |  1 +
 arch/arm/include/asm/kasan_def.h | 11 ++++++++++-
 arch/arm/mm/kasan_init.c         |  6 +++++-
 3 files changed, 16 insertions(+), 2 deletions(-)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 4c97cb40eebb..78250e246cc6 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -72,6 +72,7 @@ config ARM
 	select HAVE_ARCH_KFENCE if MMU && !XIP_KERNEL
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_PFN_VALID
 	select HAVE_ARCH_SECCOMP
diff --git a/arch/arm/include/asm/kasan_def.h b/arch/arm/include/asm/kasan_def.h
index 5739605aa7cf..96fd1d3b5a0c 100644
--- a/arch/arm/include/asm/kasan_def.h
+++ b/arch/arm/include/asm/kasan_def.h
@@ -19,7 +19,16 @@
  * space to use as shadow memory for KASan as follows:
  *
  * +----+ 0xffffffff
- * |    |							\
+ * |    |\
+ * |    | |-> ZONE_HIGHMEM for vmalloc virtual address space.
+ * |    | |   Such as vmalloc(), GFP_HIGHUSER (__GFP__HIGHMEM),
+ * |    | |   module address using ARM_MODULE_PLTS, etc.
+ * |    | |
+ * |    | |   If CONFIG_KASAN_VMALLOC=y, this area would populate
+ * |    | |   shadow address on demand.
+ * |    |/
+ * +----+ VMALLOC_START
+ * |    |\
  * |    | |-> Static kernel image (vmlinux) BSS and page table
  * |    |/
  * +----+ PAGE_OFFSET
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 5ad0d6c56d56..29caee9c79ce 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -236,7 +236,11 @@ void __init kasan_init(void)
 
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
-	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+					    kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_END),
 				    kasan_mem_to_shadow((void *)-1UL) + 1);
 
 	for_each_mem_range(i, &pa_start, &pa_end) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220227134726.27584-2-lecopzer.chen%40mediatek.com.
