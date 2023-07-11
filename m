Return-Path: <kasan-dev+bncBAABBB4BWSSQMGQETUVSIVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id AD1B574E7B7
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 09:11:06 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1b439698cd8sf5220511fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 00:11:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689059465; cv=pass;
        d=google.com; s=arc-20160816;
        b=WrB1FDqjpH8VXKBxMz8IhKXNBOaM3KTk2zCu6OgFVzDv3w6XSMyMcGCctlXdZGrN/M
         8p5hHAwgIBQphO907ouk5ATRsqdu9zG3FT0i2ikQUzM1U3GIDbeUnaRDj2hk0FTwEsH3
         1n0fk5z48ooqQ1ESNyFPN4/lMWvn3TV/G7oAbIPdjSL94nJ2p8AiI9DKGzl0YmKrqkqT
         AvQfH52KJUfhcUY0+KM0Q1B9ZDv5Qz+qh4K7pHuuF7EGXQwr7RGU5btspyp3LZ5bWhUL
         A1gOnn+vi48G9r+irqFA/QKGIjmFTdYfMDEtMkqmrskjWRRt4fti0/iJzSjjr34v6MPx
         FPiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=J2YBzdA/RZSrkaWhYyNFitVG4dMh6ch9QALVzDu3z/Q=;
        fh=clsZS2VOcwrZf8nGTc+KacmVGHm+xLJqhWwb0JwGPbg=;
        b=qEENn98GvBiQIP3zwglQDKfJuNBHLDT+3Y6rsL2bYsrords8vXwZwRU9UxMWsRwADW
         21h+voHGz2UaAs57DZs3Ghhe+cdhqX9++UMNE0H/R6cdosL+x3QI+s/4pCZT1/uExGzq
         N6HBhpH8xsQsDDgPcowEG+udlMVs77wHSXbtli3pbOBSw6BslZy9Z5J7gJtVmdbgF1Zj
         y7TEnBlpy2xw5OXwCvZDtFOnFr2SKBb9yaE3R7MhZ2SbbrXnUciqxpbIgf7eUiR2jWCx
         nvLYmYM2LCw/tw0tJ/TP8CqIbYU/hmE2Rwh6Hygv48RrpR2x8TR8W3k5ZNKra9ec02M6
         a1GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689059465; x=1691651465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=J2YBzdA/RZSrkaWhYyNFitVG4dMh6ch9QALVzDu3z/Q=;
        b=WbS9L8hCm0L7m0TYhiU04qqDNnj6Mzpe8X8GVYKIOwiNefS3128YdGIdzfmxmP5y+u
         MWVgO88kyxZWBgwxDCc4Lpdce4e0CMBYGDM7D3dDDpnr8QqSOKY2FV8t4s0N0O8/1COf
         8dl0Nx3XXPhovtDmhpYjIRf0c3fv4Cbue8pADN3G5c1BISNFgE6d6kGz5HdKfTPdiPJf
         Dgt31Q1hVNZOSZ7zU7hnaUJP2nWv+jRgmcO7fHidn7dznTI7ofvJ6imMCF1vEve+pqsw
         nSOIOvGegeLu1U0MEQxXea3u3WQRoua6yK7oKLKPJUWSv1/FddkbHtS0gc/rKwuoQLv1
         wVRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689059465; x=1691651465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J2YBzdA/RZSrkaWhYyNFitVG4dMh6ch9QALVzDu3z/Q=;
        b=X9ykaatP1JL87oFuLDxBQ4gXxashmNv38El+ZJT7ZTigzvQ1c9criVCUcGZj7lu08W
         7KuxsJ0hJlZl1MPfYoRcmj5lfzceGf3rU8RRBU28gXsENwXxMKh/7/btgamIjQV28D2f
         waZE/sO4V/npYrISW/u6YzFZ0Du56o8RhURB3B5P886TPSgC+xHh7oMS5wO2zxeyh3uU
         79flyQ5emmH5SGXHCD6zrZyFeej8XmrQpVRjUgvSdHDDPCpKem4esd/IgSnz2WrKxbHd
         dE809B4fnm/WKrmoY7xzjv5iGto6FrUGqM8W4pB5Fw68UII/OUKXBPoarx9/SH6Ts+Q+
         7QcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbTILYQjGllCvNlhDbliL8uzXdpViltxXJ7tyrhUrUJDLmNft1F
	vhUvwKNeNKVh1kuxPCVmqmg=
X-Google-Smtp-Source: APBJJlF3/ilEExNkXYmJ7B4RH2PBzpXbgDq+shgS7T7+Fzd2lEs8zLIiEV40Ovj5OeKo1XutezM/Gw==
X-Received: by 2002:a05:6870:9708:b0:1a6:b814:e27d with SMTP id n8-20020a056870970800b001a6b814e27dmr17217187oaq.54.1689059465374;
        Tue, 11 Jul 2023 00:11:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:16a3:b0:563:4373:e65a with SMTP id
 bc35-20020a05682016a300b005634373e65als1890627oob.1.-pod-prod-05-us; Tue, 11
 Jul 2023 00:11:03 -0700 (PDT)
X-Received: by 2002:a05:6808:210d:b0:3a3:dda9:b90d with SMTP id r13-20020a056808210d00b003a3dda9b90dmr16864756oiw.45.1689059463756;
        Tue, 11 Jul 2023 00:11:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689059463; cv=none;
        d=google.com; s=arc-20160816;
        b=0EMrb6Q4J5DDlv70SxLRkK8Eog7KTY1V2exaBn6o22fRoHtQs6YIiu/iCiAm33rsB/
         hRik7SL2jwMCKjcsziule+SkOISD7y34yfX42bYkrGRrOti7VA5yg+omHhjBoMpLatIU
         1+j0LpO7m5JeV7Ox0mg5EyHF0uwpZGY2kKJE/AQLLm8ct+QJr+e1bRQxX8ueLgxzw/f+
         jsVewBhAtk/1UcD3Jm0HBgM7H7Qfr4dpdOWo6Zf6ffw5RQDyclGh9mC+tVXrBUn1j7Zd
         BDGNgde1otcOYGGuU1u/mtMCyQfwKPksd6Id91rrW5nfwUQFMr51YpNbDKYJU8Xy2p8u
         D+hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Ng4KLfeu7CPwfhxPsjnBP9bGHAlEw6K8pZWKAJ+k2uc=;
        fh=clsZS2VOcwrZf8nGTc+KacmVGHm+xLJqhWwb0JwGPbg=;
        b=fbsG9a+yn59SHO7KLgY1ih2pt5AgwpUP7j0EAPWktbgPD+GjrODxLp1IWjaeI4h/ea
         /lqfwlKW5g3Q2NhszVlbIRcRDxjtQGA3LUbFotGN6sQcfLFw2HSq2AsMHtHC7rtYFNe5
         PaM4Y8ZLifGqF4GATnH35b/SVyuW2q64NgWihtMdujW1UHBD7l3FOeXbYSiKZhyMkpJH
         Y00AZfHoz8dJITQbOpv3Tnf2CAygvDkQCy3SFa7tX8KcDtfXK0PqQIOCyYd0XZPJLxoh
         HX8oegngwcoLvIOrwLp3iuS8bz0vha+xJcRQEf+mCXOxpOccQFi86kKDhk0JZZbw/MJE
         pO6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id bh25-20020a056808181900b003a1a0462861si124946oib.2.2023.07.11.00.11.02
        for <kasan-dev@googlegroups.com>;
        Tue, 11 Jul 2023 00:11:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [112.20.109.108])
	by gateway (Coremail) with SMTP id _____8AxjuuEAK1kWGoDAA--.7108S3;
	Tue, 11 Jul 2023 15:11:00 +0800 (CST)
Received: from localhost.localdomain (unknown [112.20.109.108])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8CxF81_AK1k308oAA--.46365S4;
	Tue, 11 Jul 2023 15:10:59 +0800 (CST)
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
Subject: [PATCH v2 2/2] LoongArch: Allow building with kcov coverage
Date: Tue, 11 Jul 2023 15:10:43 +0800
Message-Id: <20230711071043.4119353-3-chenfeiyang@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20230711071043.4119353-1-chenfeiyang@loongson.cn>
References: <20230711071043.4119353-1-chenfeiyang@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8CxF81_AK1k308oAA--.46365S4
X-CM-SenderInfo: hfkh0wphl1t03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBj93XoW7ZF18Xw15trWxZrWUtr1DJwc_yoW8ZFWrpa
	s5Awn7Gr4xWrn5Ar48t347XF4UtF97G3y2gF4FyFyjkF97Ar98Zr10grn8XFyUX3ykJay8
	WFWrG34aqF48J3XCm3ZEXasCq-sJn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUkFb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r106r15M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVW8Jr0_Cr1UM28EF7xvwVC2z280aVCY1x0267AK
	xVWxJr0_GcWle2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0cIa020Ex4CE44I27w
	Aqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_Jw0_WrylYx0Ex4A2jsIE
	14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvY0x0EwIxGrwCF04k20xvY0x
	0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E
	7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcV
	C0I7IYx2IY67AKxVW8JVW5JwCI42IY6xIIjxv20xvEc7CjxVAFwI0_Gr0_Cr1lIxAIcVCF
	04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r4j6F4UMIIF0xvEx4A2jsIEc7
	CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07jOdb8UUUUU=
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

Add ARCH_HAS_KCOV and HAVE_GCC_PLUGINS to the LoongArch Kconfig.
Also disable instrumentation of vdso.

Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>
---
 Documentation/features/debug/kcov/arch-support.txt | 2 +-
 arch/loongarch/Kconfig                             | 2 ++
 arch/loongarch/vdso/Makefile                       | 2 ++
 3 files changed, 5 insertions(+), 1 deletion(-)

diff --git a/Documentation/features/debug/kcov/arch-support.txt b/Documentation/features/debug/kcov/arch-support.txt
index ffcc9f2b1d74..de84cefbcdd3 100644
--- a/Documentation/features/debug/kcov/arch-support.txt
+++ b/Documentation/features/debug/kcov/arch-support.txt
@@ -13,7 +13,7 @@
     |        csky: | TODO |
     |     hexagon: | TODO |
     |        ia64: | TODO |
-    |   loongarch: | TODO |
+    |   loongarch: |  ok  |
     |        m68k: | TODO |
     |  microblaze: | TODO |
     |        mips: |  ok  |
diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index ed9a148cdcde..6100297b906d 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -14,6 +14,7 @@ config LOONGARCH
 	select ARCH_HAS_ACPI_TABLE_UPGRADE	if ACPI
 	select ARCH_HAS_CPU_FINALIZE_INIT
 	select ARCH_HAS_FORTIFY_SOURCE
+	select ARCH_HAS_KCOV
 	select ARCH_HAS_NMI_SAFE_THIS_CPU_OPS
 	select ARCH_HAS_PTE_SPECIAL
 	select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
@@ -115,6 +116,7 @@ config LOONGARCH
 	select HAVE_FUNCTION_ERROR_INJECTION
 	select HAVE_FUNCTION_GRAPH_TRACER
 	select HAVE_FUNCTION_TRACER
+	select HAVE_GCC_PLUGINS
 	select HAVE_GENERIC_VDSO
 	select HAVE_HW_BREAKPOINT if PERF_EVENTS
 	select HAVE_IOREMAP_PROT
diff --git a/arch/loongarch/vdso/Makefile b/arch/loongarch/vdso/Makefile
index 7bb794604af3..7dc87377688b 100644
--- a/arch/loongarch/vdso/Makefile
+++ b/arch/loongarch/vdso/Makefile
@@ -5,6 +5,8 @@ ifdef CONFIG_KASAN
 KASAN_SANITIZE := n
 endif
 
+KCOV_INSTRUMENT := n
+
 # Include the generic Makefile to check the built vdso.
 include $(srctree)/lib/vdso/Makefile
 
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230711071043.4119353-3-chenfeiyang%40loongson.cn.
