Return-Path: <kasan-dev+bncBAABB66FV6QQMGQEFY6LLCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9714E6D5B13
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 10:42:36 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id w6-20020a4aa986000000b0053bb0591efasf8559987oom.21
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 01:42:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680597755; cv=pass;
        d=google.com; s=arc-20160816;
        b=rVoYFeOxaxhS8suq8sb8j97lM6Wpxjn4GfYONhfAQtdLnPOsBjCx9E1kuGxT+fnG+K
         kVX2Q8oEGvSv81q4Tp4Tm7SoUt92YtHnWbcxT02B9tu6/7w7eoqGNkGNoPwHcZqavHV5
         3tmXVKeU57JQif1t2ZOL5wTUCQ9Pt+dMMejBPIGFSfE8p1ni89s/ZSuMUOVnfeTv99Or
         otzUeDpybpzFfL+NbGzlfoYozmmGTk+EoD1HCS1/I+/3q/MWq3VwQ0ReTJsMm6NJ2GaS
         kR5KFomJWHrTWbAVvO2fUVKQaxIKA4R8A5/I9xFpRvwFrf9c3VaO62tgDPuhymBOBL56
         Kxdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=V9+vfqmbCTPj43pBaiELIVIm3N7Vcbomr4W0VBdDiZA=;
        b=YfMM9GfEDi79o3+Xpu4Kfg5dM5PRT9jZoCsneCpyR+eyKAvx9H2BoiilSrsPj1fYCE
         tao1BnUdwIcXs/t+i68uWrP4nrqDOiXAwPmrZxoREy42A7TSLu3UwoGkbQZLmHXIF72j
         4oXXASsdseZf9y7EA16ht4eDaYMtuWh24cSKof4tnWARU2rZj6Sx8q4lbCie6NtvM2JW
         0wlIQ5RCz5z2slqTLe6toZ/aqGpsrmHug+VbHkog/ySQ47Uhpwc8bVEtYS9wFuqFLXqo
         BCQQbTsPUrbFeotxnDeRL6GnpAn41t9M8HdjXpym/IjiCcLWfe4HAEhD/9rQ4/4i0RGF
         1wrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680597755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V9+vfqmbCTPj43pBaiELIVIm3N7Vcbomr4W0VBdDiZA=;
        b=Mql6vQ72R11MYaW0uwL+Z2hGGlzpqP6q9eFOnhLIuhINt46llrjRDNjEGyjpfP/zaC
         nujNv0RXpHLWceyoa+j+JO+Y9Mvo4KyRDY4vhBUsxduBD2+iJsZrz6XjcK7gHXltu+oy
         N/M9Km4OwwqgYBGjppybKtpIh7wE3S7o7KWRk56JYwE7315J4g9L8Bp+MoGER78BKR8J
         1q3gd5qsmhObjhNvNxU2j03Kr66aL6p9ksS+LJ5SaCgo7HfrxT84tKSuLS2zMn01GDWy
         +MHgaByNAoXqEyD8du4ZxOxDNb/WXgRbEnL3cXVLek8umwUc+sYyzXXHg0iCOaeHiM7D
         65qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680597755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V9+vfqmbCTPj43pBaiELIVIm3N7Vcbomr4W0VBdDiZA=;
        b=njh33zPGNMTXbIXoS/LvvDxZxrz1q+I5skp1hkpPI3/H2qGXo7bhT/Jx/NOIR1Yrlg
         AqimGKSSkEcQFLHh8dx+JYO1svUIEnHhWReUNL/s+py7kg33P/vB43mAjkQhRxeEe+QE
         A7gLFCEjFTMkycnCkEyDdrj5s4ilg23C1RVejF/94AKKHPwJFa8rcldUAKh+7q696ux6
         KW1qsWtii9+WuBqrsMmOf+HhMBfkf7SYQyETaqKTvyu3P64JK4MO/TNadc8iXnE+H9XP
         yVcfI3JYI4f6hKNBt/xrXobQnX+T7fCtOX8vKKJeESTor0eGZNWk0RWDC0rABxnj6W70
         pRWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dShXvDxCS8ep4HrDIngypmjfKcSvbTg050Le2MNydIA9d5oSB7
	k32l14uKI7bHxdDSjboDEeY=
X-Google-Smtp-Source: AKy350ad/M3R8ovFQgJxm9RKYq7y28gLP+761YqituWah9mVJOugPIpmsw0gASi02FD1niO9+DEa0A==
X-Received: by 2002:a4a:bb12:0:b0:525:499e:ce2f with SMTP id f18-20020a4abb12000000b00525499ece2fmr872346oop.1.1680597755452;
        Tue, 04 Apr 2023 01:42:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1907:b0:387:24d4:f9b9 with SMTP id
 bf7-20020a056808190700b0038724d4f9b9ls3665163oib.1.-pod-prod-gmail; Tue, 04
 Apr 2023 01:42:35 -0700 (PDT)
X-Received: by 2002:a05:6808:234a:b0:38b:37dc:88c2 with SMTP id ef10-20020a056808234a00b0038b37dc88c2mr676106oib.28.1680597754991;
        Tue, 04 Apr 2023 01:42:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680597754; cv=none;
        d=google.com; s=arc-20160816;
        b=JvAnCJOLDitCx5ETQ1+U+jdnOECd1WGpA8F5aTyXegc3NjUXOArCgp0vkjrJ9nwH9W
         /D8hSaburcY+KQGZlIV8JibAVChteS0j2lvwH3ngUCCWN6nuiDQSuh0DXrERTlhtYbIp
         H3TbFLZq74D9lMYiPddFjM3THd5NfqvwDIIw7T1TLRHDeo+FwER01WhtrTrv2jJiawKU
         nxNUipvmI477q/DWJS7UlqAjgzlEu++a8g1/fJqoJrXMY2/KZzEyV+yLBioi4RBtdOd9
         J800LrtonnKx1GZWD+1DoebyRgpn2++Haf5BVxeD9BG5FE0O8A0lw5/HuPoStL6jdSvZ
         q0LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=zUqPHNvm72b1Z7rJDfbqVQjdQ+2h29X6/VA4g8xsVbE=;
        b=qK2j1jQmwc6VBs8xa6KnCEGepPUxg8VdgABfcvAV3hPDnsSXDLzqUCmyjm3/WxQp1n
         J3kKRZBSPmCb2VHA9QSv0HtKdT0OxoXjiuqOvaYdW92XoR0J4EkOOD03miHWUjcmjSjZ
         F7OwgpPMyaLxQsvkwTOayDHtHwiYLTgZywoc9rV/VewySNbspiS5TGjOctBc60R8GdQT
         7HbDSCNrUXOYO8qOdQhzTS9iEc7TD5nU50468BJ1InA0c6IcGs3A75eh24MxaJWSkRaI
         rZf2aR3eM9sf6A6Uu1OFwiSoozqm6F6P31T6h5nPNT8TrZ8GoZhqpfNnMLzmTBFGx3b6
         S0jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id y26-20020a544d9a000000b003872d6ed346si1441042oix.5.2023.04.04.01.42.33
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Apr 2023 01:42:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8DxE4Ta4itkSV0WAA--.34680S3;
	Tue, 04 Apr 2023 16:42:02 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8DxwOTW4itkYRYVAA--.55009S4;
	Tue, 04 Apr 2023 16:42:02 +0800 (CST)
From: Qing Zhang <zhangqing@loongson.cn>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Huacai Chen <chenhuacai@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Jiaxun Yang <jiaxun.yang@flygoat.com>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2 2/6] LoongArch: Fix _CONST64_(x) as unsigned
Date: Tue,  4 Apr 2023 16:41:44 +0800
Message-Id: <20230404084148.744-3-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230404084148.744-1-zhangqing@loongson.cn>
References: <20230404084148.744-1-zhangqing@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8DxwOTW4itkYRYVAA--.55009S4
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvdXoWrtF4ktr4UAr4fXr4UJF4xZwb_yoW3WFX_Aa
	97Ja1kur48AFW7Aws0y34rJw1Uu3ykJFn8uFnIqr9xAwn0kw45Jay8Wa4rZryakF4a9rs5
	XFWvqr9Iy34UtjkaLaAFLSUrUUUU8b8apTn2vfkv8UJUUUU8wcxFpf9Il3svdxBIdaVrn0
	xqx4xG64xvF2IEw4CE5I8CrVC2j2Jv73VFW2AGmfu7bjvjm3AaLaJ3UjIYCTnIWjp_UUUY
	C7kC6x804xWl14x267AKxVWUJVW8JwAFc2x0x2IEx4CE42xK8VAvwI8IcIk0rVWrJVCq3w
	AFIxvE14AKwVWUAVWUZwA2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK021l84ACjcxK
	6xIIjxv20xvE14v26ryj6F1UM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26r4j6F4UM28EF7
	xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAa
	w2AFwI0_Jrv_JF1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44
	I27wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jw0_WrylYx0Ex4A2
	jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCY1x0262
	kKe7AKxVWUAVWUtwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwCFI7km
	07C267AKxVWUXVWUAwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r
	1rMI8E67AF67kF1VAFwI0_GFv_WrylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVW5
	JVW7JwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r
	1j6r1xMIIF0xvEx4A2jsIE14v26r4j6F4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1U
	YxBIdaVFxhVjvjDU0xZFpf9x07jzc_-UUUUU=
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

Addresses should all be of unsigned type to avoid unnecessary conversions.

Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
---
 arch/loongarch/include/asm/addrspace.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/loongarch/include/asm/addrspace.h b/arch/loongarch/include/asm/addrspace.h
index 8fb699b4d40a..5c9c03bdf915 100644
--- a/arch/loongarch/include/asm/addrspace.h
+++ b/arch/loongarch/include/asm/addrspace.h
@@ -71,9 +71,9 @@ extern unsigned long vm_map_base;
 #define _ATYPE32_	int
 #define _ATYPE64_	__s64
 #ifdef CONFIG_64BIT
-#define _CONST64_(x)	x ## L
+#define _CONST64_(x)	x ## UL
 #else
-#define _CONST64_(x)	x ## LL
+#define _CONST64_(x)	x ## ULL
 #endif
 #endif
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230404084148.744-3-zhangqing%40loongson.cn.
