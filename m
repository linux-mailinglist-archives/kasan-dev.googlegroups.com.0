Return-Path: <kasan-dev+bncBAABBBMBWSSQMGQEOCPT72I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CF7274E7B6
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 09:11:03 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3a36b52afcfsf4634911b6e.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 00:11:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689059461; cv=pass;
        d=google.com; s=arc-20160816;
        b=G7VWGlWyG7tY9oLWLSJi3iBukGEAFZW6eALx7uPBNmgX/GKLRj3gHRuL+oqMRp0Dgp
         odgZEh8GH+RQrED1IRbJEgmNNul8Ww1mPHFxEvAgjRZJys/Fmi0pX0BYUNjjfF5iDYoV
         +wgKP7zBBSmORTEbmDFbYdU7X8B1sWbfd8tTz1H/8EZ0HXT+Do1b9IMm8lPmvjzg+R86
         zFWvwIfw+UffeH2+lrW2lSFhU2T4Xc61ZEu1Uz0DW+FXG8BSjYQr4T5pJxFxwiihTYP8
         MWsIWPEO1q48XXRmCrDgbWS+Aj7hRa+A7hrTJLZxtcDf+TXnIpjafmBb66dzUW8VMsYS
         Hqnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3586g6DHqJZRoRnhkzTJRMalgtasTgcX3GgTQfzxxy0=;
        fh=clsZS2VOcwrZf8nGTc+KacmVGHm+xLJqhWwb0JwGPbg=;
        b=FnA+tyOh1VPIB/UQZkxY1aSiBJrZUYB0aY/C0FapCgrWiqJNsbc9MDz2K8l5LFK57X
         wFxBBBxlX+zkouahMrP8UT0rUsTNA+sAS6V9KgvRJl6Ip8cthHY7hbpfre2ANHGfMo/h
         ts43y5bWCxelnkk7pvETORwUmCb/GFKGXAhfLurSzocTbwmb6A0aMAnHMYGyW+stZEvs
         v/bUipXzgn/pUTe85gvDSiGdeFowDZg+4V0RTDZuYDErgYGHyXIVOM9iDrheE7QrS7ad
         Crys6UhZk+ACCLH0xymCBPPXAbbBNgVH6LK9Ppfz5twMNockw4nCQ3wKMBvZom1FlEiD
         uXOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689059461; x=1691651461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3586g6DHqJZRoRnhkzTJRMalgtasTgcX3GgTQfzxxy0=;
        b=KsyWA9mMqtdKs0mSDHSmWKhPSVHqcXkLZMIFvk/wWjg19LeBAhQxziH0KQOzFT+x0H
         YIvmaqxrD4ncyJoj9whUp2yZQGOT5dDLJPEmoswNTNNLUguoZOSZoGKgoUQsqaq8Kj9+
         WPlOhPmrFpNyy/5yMKKS/VQaN0tEteL9isi7A89jBSXw+hJ1VSAI1MbQlwEd0rE4Pxu1
         DActemnQmYluXrfjCsf1dbVy1nX3HFYT0oPdci7TrUf8ck6xSE9Lf3RlfntADH/MxI6a
         GI0gw1VdVZiaW4ajiLSKcfyedG+O416Sxzz24xNfYNrVz3Ht+rZLBQMu4I3vfQc4uqf7
         WS0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689059461; x=1691651461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3586g6DHqJZRoRnhkzTJRMalgtasTgcX3GgTQfzxxy0=;
        b=hweGJfuGrfyG/bT3Dnt6vlgdp3y6Z31AJ11JCTPvGuWqXS3txAK8g0IpUX8QeX+bX3
         VIj3B29DgHGds4OB9HO3o93+EL8iCo6aIKgOqAQBjQe5XQhEREF1RHgpksC5bJu+ne+V
         B0bifr/Cv/kQEl/fRVj1z/sy6xhC/m79uV3zAKjEfXgkbnhTE8j/BpJyxnMWzWU46v6B
         ylAdfQdyf5yrH+LvRUgfdBEWE9TBHJgj+mcUhEj+6kwlCvbGexFFUiqv3lfiivQz7rqm
         hpxRtpsXRj4zRm0eWEzrl04HJSqhIq/2Y5oKl+IRxzI6bN3xmzHxgrNLHrHRjR5jegue
         SGSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZjgPk/McPdK52Loqg+B/IFD22Uk+8hup0ybk6MCyNz4zVlMHbV
	V354FNAYpvujjMX49jRMEJ0=
X-Google-Smtp-Source: APBJJlHUeEKS4fucEJQaPdz3NHPw1fo4HWmRltOKQvKSA3Q0/NhN1Df3BEM8sIrItTlxS2u1s102Wg==
X-Received: by 2002:a05:6808:d51:b0:3a4:11df:bb63 with SMTP id w17-20020a0568080d5100b003a411dfbb63mr3355114oik.3.1689059461692;
        Tue, 11 Jul 2023 00:11:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3593:b0:262:e480:3af8 with SMTP id
 mm19-20020a17090b359300b00262e4803af8ls1926426pjb.2.-pod-prod-03-us; Tue, 11
 Jul 2023 00:11:01 -0700 (PDT)
X-Received: by 2002:a05:6a20:8e1a:b0:131:eeba:184b with SMTP id y26-20020a056a208e1a00b00131eeba184bmr4139955pzj.25.1689059460893;
        Tue, 11 Jul 2023 00:11:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689059460; cv=none;
        d=google.com; s=arc-20160816;
        b=S3n8tlGukK9FrxirYZZTKZIvhjJwjc8qauAlyDYrFX0Vi1FnL4uk9dipeocjFYgSCU
         XZEUA7o/qvNFDwkPUkzevWMMuhhTqLj6h09vcn2iwFVBFvMe02tcuSIaPqBnzclELuFQ
         Tw2lD6BfuX4O6S4uLY79nZrc6Zc7JirYui6TcCZTkyCYb9zsv+ePTLplhnPg7KnRCDpz
         1wjvbnROMSHA71VX1yjXTwsl7+O7v1qfMyviU1N4dMwSLGnUflDKuA+BaWF3CBGbDoXm
         DStkxGvE++b4hHHywZ3Bvr81PWKVNVSAYY9RwUbNoh2Ai3IqiTCANlLPihUJHVJzFPrx
         dj1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=wH8p6sYvEVgGBScH/CrtpA3AzQriJ8RQfEVCazbrY1c=;
        fh=clsZS2VOcwrZf8nGTc+KacmVGHm+xLJqhWwb0JwGPbg=;
        b=u9o5rimQrDdFyhxB05yNxuhOrE8PVdk1EVSH7grmlYs5wPRgoYByUHDnX9DqyD7ouQ
         d7kSTSsFXV2q+ZyWnOuM4ZBoNE7kyVwDmrFcSDGPM56Y6ZO8HJ6pu/v4ys7Z6NE3jdRG
         1ioFU6IBMv7mPRoGfcdFy/ilIq6zI/d8XQtnFSDqTNbo9KNvwzABLrE9wsgIKJgM19eZ
         Gj1AQiODraHXtNQ7N0l9u46zRNebX3axBqkog9wGHqJ59WRguM5btXDbhHwDjiU+k/TE
         d6efLx5bXNRuSstmnl0VJ2W002CxImvyuoE5+onQsCrERCX+Ni08woQA0gf+KHwRxfJA
         BBjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id i7-20020a6551c7000000b00542924cbf7esi48337pgq.5.2023.07.11.00.10.59
        for <kasan-dev@googlegroups.com>;
        Tue, 11 Jul 2023 00:11:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [112.20.109.108])
	by gateway (Coremail) with SMTP id _____8BxHOuCAK1kUWoDAA--.4640S3;
	Tue, 11 Jul 2023 15:10:58 +0800 (CST)
Received: from localhost.localdomain (unknown [112.20.109.108])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8CxF81_AK1k308oAA--.46365S3;
	Tue, 11 Jul 2023 15:10:58 +0800 (CST)
From: Feiyang Chen <chenfeiyang@loongson.cn>
To: chenhuacai@kernel.org
Cc: Feiyang Chen <chenfeiyang@loongson.cn>,
	dvyukov@google.com,
	andreyknvl@gmail.com,
	corbet@lwn.net,
	loongarch@lists.linux.dev,
	kasan-dev@googlegroups.com,
	loongson-kernel@lists.loongnix.cn,
	chris.chenfeiyang@gmail.com
Subject: [PATCH v2 1/2] LoongArch: Provide kaslr_offset() to get kernel offset
Date: Tue, 11 Jul 2023 15:10:42 +0800
Message-Id: <20230711071043.4119353-2-chenfeiyang@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20230711071043.4119353-1-chenfeiyang@loongson.cn>
References: <20230711071043.4119353-1-chenfeiyang@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8CxF81_AK1k308oAA--.46365S3
X-CM-SenderInfo: hfkh0wphl1t03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBj9xXoWrKryxXrW3CrWkWw1kKrWUJrc_yoWfJFX_Zw
	13Xw4Uu3sYqF4xJ3sFvF93J34jga1ftF98uFn2vw47AF90vr1rWw4rK3Z5Ar4Y9wsxuF1Y
	vFWUt3y3CryUKosvyTuYvTs0mTUanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUj1kv1TuYvT
	s0mT0YCTnIWjqI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUI
	cSsGvfJTRUUUb7kYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20x
	vaj40_Wr0E3s1l1IIY67AEw4v_JrI_Jryl8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxS
	w2x7M28EF7xvwVC0I7IYx2IY67AKxVW8JVW5JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxV
	W8JVWxJwA2z4x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6F4UJVW0owAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc
	02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUtVWrXwAv7VC2z280aVAF
	wI0_Jr0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JMxAIw28IcxkI7V
	AKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCj
	r7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6x
	IIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwCI42IY6xAI
	w20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x
	0267AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvjxU27PEDUUUU
X-Original-Sender: chenfeiyang@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
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

Provide kaslr_offset() to get the kernel offset when KASLR is enabled.

Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>
---
 arch/loongarch/include/asm/setup.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/loongarch/include/asm/setup.h b/arch/loongarch/include/asm/setup.h
index 2dca0d1dd90a..a0bc159ce8bd 100644
--- a/arch/loongarch/include/asm/setup.h
+++ b/arch/loongarch/include/asm/setup.h
@@ -7,6 +7,7 @@
 #define _LOONGARCH_SETUP_H
 
 #include <linux/types.h>
+#include <asm/sections.h>
 #include <uapi/asm/setup.h>
 
 #define VECSIZE 0x200
@@ -37,4 +38,9 @@ extern unsigned long __init relocate_kernel(void);
 
 #endif
 
+static inline unsigned long kaslr_offset(void)
+{
+	return (unsigned long)&_text - VMLINUX_LOAD_ADDRESS;
+}
+
 #endif /* __SETUP_H */
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230711071043.4119353-2-chenfeiyang%40loongson.cn.
