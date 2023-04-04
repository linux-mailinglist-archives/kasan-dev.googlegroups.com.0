Return-Path: <kasan-dev+bncBAABB6WFV6QQMGQECBWABUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 02B176D5B12
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Apr 2023 10:42:36 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-1802c0ae9bbsf7205654fac.5
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 01:42:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680597754; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tb+IGrcYkVa9L+VCp/imgHtTbfwSbU0wsEiH/Ku2cp3F7ClZM0EqRWZJA2tts7RanG
         V1eiLdrCduO2vkL+KFJoWq+v1HuiMsEok11qvSZI08KFnitX+R4V7CU/klsEt0hQ4AmI
         Et8jck6aKLpJYo/lTrUu+js2snDSfnAptPG82juvg33H18VyPtPPpfVTbpF0fJznqjIv
         Z5gNwx5PP4R0gexFFjzW2+bAcmzQKidR1qY8DRzY6P7ionCoKctjBT1buLVS5wbIJsEs
         pvZCskR87ZYmOIdorPq3Q1mwMRNge3ByDX15QSE8+oTprgF53hFKW+eH5uaD8eT8NDTr
         5Nqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=to0HAm3V3or6HwxDyhlKrY2ouOY0Q9BZJL1+C7AulAU=;
        b=rvs55oWGO8DmquEhauW/kwShGE/iUX12zhNwNYfOjtuVRmsPtEhpFmnYEZ/z/DGGWi
         CN777miAaw3agIHb6YJT5ywpHGJl96IT1K17xFPbM1YLWbkILDfLwrnt+ThUkg6x+aDm
         ysHJXAM/H9aTpUvmsu/Dn/dqItrEzqZYgQpi3QglmSKs5EDa2C4B+OZk66qy4GAv2YGq
         1aw+ON/Z5NgNgQOxIwoS4ID37+eHsvwDoLA+2NsEpBnwrJRKkcunYjqym6N2acT038UA
         hW9qJ5QlWEkLM0Qli0w4o9Z45KQKqIDPnA5d6HxlAqlCbSUlhRUq9jFISE1Ofwm7YnLn
         ef9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680597754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=to0HAm3V3or6HwxDyhlKrY2ouOY0Q9BZJL1+C7AulAU=;
        b=pmPOGGJOmVfv5EY5qBWuYK0GI53foMFBPPm2RsSDNJJH559OWqTepML8yPTQfS4NLk
         mWyptjY88qoycUerOWmacGu/n6zIs9Oqfv7G9tLAXyYlg7pe8MvIPI2deepLLRFejtwY
         QYBBhTaSEi7bBSxvF4PjGweNvQa35hVNoXxqzxxUtPMtHWB55HX3mH1XlW4yKwSl6L2s
         ERm3QFvUx6BtiZ8/i2NMPx9XLu0AJPpnX8JL2XVdUN1YdP8N1WUQqwgld0oJl7Di4KnC
         3sZXlN1UXAwbGJv1HavoIr1AL9k6UBiQ4BWkvaHYvdohqvIQrJQvrRd2vxmSntcJFdMM
         P8GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680597754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=to0HAm3V3or6HwxDyhlKrY2ouOY0Q9BZJL1+C7AulAU=;
        b=H0570/SByng30lkgCiHZmVLRiI8eE7PC8mtZHANazhO+o/shnnFaoSQ4BNA+ErDTmp
         jllo7v3gOXnFGpwcRhv+rx7Gft7UB3QbH1OUtEoUEqJgorp/t8G+oSS6FXj0NBqvSb8Z
         wJ5xGLDrfyQKw7hUn//X/FDosr+iQFb1ZSyQQxeGMfM7cUOZHOn3k+nSWbUIW2+0dHsD
         /BbBngNtYTfgQZ0qivdt220lkOedvrvaIAOKoaKUTj+fADNm1UgyQvj6UUVb/C8JwI1s
         7+aAWMz9nbr8TsyqkwVjFtkG2A1SvcEv6DR11VVmBT4FBGmeh+XaD82Yffy511fWUEpa
         G0Mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eceMRBOTPrsn9xodoeuARxIAdIW/nYX4ZKfe1EY2KK7TMbNmET
	VwoqfCeqMZ8p2Yi0oYBefS4=
X-Google-Smtp-Source: AKy350anW7rCsb7VrnYHdHb58mu2n509tyIE8mdp4rFslQ7Ajdv8fhmLau7wQGjmXOG3iVdVQqQ+/w==
X-Received: by 2002:a9d:7387:0:b0:69e:aa7:6b71 with SMTP id j7-20020a9d7387000000b0069e0aa76b71mr594059otk.3.1680597754689;
        Tue, 04 Apr 2023 01:42:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:189d:b0:386:d196:f854 with SMTP id
 bi29-20020a056808189d00b00386d196f854ls3661390oib.7.-pod-prod-gmail; Tue, 04
 Apr 2023 01:42:34 -0700 (PDT)
X-Received: by 2002:a05:6808:3a96:b0:38a:9c45:87cc with SMTP id fb22-20020a0568083a9600b0038a9c4587ccmr901983oib.9.1680597754337;
        Tue, 04 Apr 2023 01:42:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680597754; cv=none;
        d=google.com; s=arc-20160816;
        b=YTWMmfhKOWrrzi1A1zdohVQiWiGRIgztXRRrJ9WeLADolz8GoAGlMjRtrQJOtzAA/J
         N5YlrsjCj6Tdcbf8VrEnYM0xrvJ+jK6gXYC8hYHiByT1vBLsa0ff6Go4z7T46G4mfHTS
         8FJ32nMZ2x0GpCuDEbAHZFvnVSHPDXgFZ9inrexx9rtLUTBl5tz1sXNEPB0FqRzPdLX3
         eCGlMwOD4F49oFjRtDhDqzIJsw90yU1Rkrh/AZUigDZDisMObf4r5NV0IOBWfeJsNRt6
         D5n60m7AkwRFQuCmO+5Prk0qbhR+4JSRlFoQkVO9D/XYD03NF+Ql1F+c37f9lS9JvPqv
         EiuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=bK9gLMxjKISsmIbyAXMDAt9NQo6Xkgz6c17HqxCv4xE=;
        b=d0M9BLdKfZZB2u91pUe0WMA6qVroZ2jBJS6FjpZl7s/qPVrVs4WHg7vzC3++DBTluz
         FUgziddDNF2gR9MTtN+pTV6oHY0GXvXEsDICbQDT1gegCEkTg/yknfrl2FvJMY8VzFa4
         k4X+7c++cib9F0Jaq10al+R78rZ2kYs1i7mcmg4uFFtdn2PFOF0kK1Rm93X6Gsb5GEdE
         tLOEngLf9xZqX/DX8AaPwSLK09UX9GQLEbGzRAJDv6bd/8FDfhNNT4Gk8E/Wg55DCWgT
         LEACoLAuhRScioOOd7/Wo07SetgffibtjAoa5ig/IM/rZxH1stIBMAGhMZdcjPi35QpP
         HcOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id bh11-20020a056808180b00b0038409c2d352si1353432oib.2.2023.04.04.01.42.33
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Apr 2023 01:42:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8CxxtjZ4itkO10WAA--.34259S3;
	Tue, 04 Apr 2023 16:42:01 +0800 (CST)
Received: from localhost.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8DxwOTW4itkYRYVAA--.55009S3;
	Tue, 04 Apr 2023 16:42:00 +0800 (CST)
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
Subject: [PATCH v2 1/6] LoongArch: Simplified randomization layout after jump new kernel processing
Date: Tue,  4 Apr 2023 16:41:43 +0800
Message-Id: <20230404084148.744-2-zhangqing@loongson.cn>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230404084148.744-1-zhangqing@loongson.cn>
References: <20230404084148.744-1-zhangqing@loongson.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8DxwOTW4itkYRYVAA--.55009S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjvJXoWxCFy5JFyUAw4rur18urW7Arb_yoW5AF45pr
	y7Zw1kJr45Grs7J34qqa4Dury5XwnrWw1aganrK34rZr12qFy5Xw1kurnrWFWjq3yFgr4S
	qFyrKF9Iva1UJ3DanT9S1TB71UUUUUJqnTZGkaVYY2UrUUUUj1kv1TuYvTs0mT0YCTnIWj
	qI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUIcSsGvfJTRUUU
	b3AYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20xvaj40_Wr0E3s
	1l1IIY67AEw4v_JF0_JFyl8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVW8JVW5JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwA2z4
	x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjcxK6I8E87Iv6xkF7I0E14v26r4UJVWxJr1l
	n4kS14v26r1Y6r17M2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6x
	ACxx1l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r1q6rW5McIj6I8E
	87Iv67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41l42xK82
	IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1l4IxYO2xFxVAFwI0_Jrv_JF1lx2Iq
	xVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r
	4a6rW5MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Gr0_Xr1lIxAIcVC0I7IYx2IY
	6xkF7I0E14v26r4j6F4UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67
	AKxVW8JVWxJwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIevJa73UjIFyTuY
	vjxU4OzVUUUUU
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

Modified relocate_kernel is not returned directly new kernel's entry point=
=EF=BC=8C
instead, we share start_kernel processing with the normal kernel, which avo=
ids
calling 'jr a0' directly and we can do other operations(eg: kasan_early_ini=
t)
before start_kernel when CONFIG_RANDOMIZE_BASE is turned on.

Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
---
 arch/loongarch/include/asm/setup.h |  2 +-
 arch/loongarch/kernel/head.S       | 10 +++++-----
 arch/loongarch/kernel/relocate.c   |  8 ++------
 3 files changed, 8 insertions(+), 12 deletions(-)

diff --git a/arch/loongarch/include/asm/setup.h b/arch/loongarch/include/as=
m/setup.h
index be05c0e706a2..2dca0d1dd90a 100644
--- a/arch/loongarch/include/asm/setup.h
+++ b/arch/loongarch/include/asm/setup.h
@@ -33,7 +33,7 @@ extern long __la_abs_end;
 extern long __rela_dyn_begin;
 extern long __rela_dyn_end;
=20
-extern void * __init relocate_kernel(void);
+extern unsigned long __init relocate_kernel(void);
=20
 #endif
=20
diff --git a/arch/loongarch/kernel/head.S b/arch/loongarch/kernel/head.S
index aa64b179744f..35c4a78614c3 100644
--- a/arch/loongarch/kernel/head.S
+++ b/arch/loongarch/kernel/head.S
@@ -95,12 +95,12 @@ SYM_CODE_START(kernel_entry)			# kernel entry point
 	PTR_LI		sp, (_THREAD_SIZE - PT_SIZE)
 	PTR_ADD		sp, sp, tp
 	set_saved_sp	sp, t0, t1
-#endif
-
-	/* relocate_kernel() returns the new kernel entry point */
-	jr		a0
-	ASM_BUG()
=20
+	/* Jump to new kernel: new_pc =3D current_pc + random_offset */
+	pcaddi		t0, 0
+	add.d		t0, t0, a0
+	jirl		zero, t0, 0xc
+#endif
 #endif
=20
 	bl		start_kernel
diff --git a/arch/loongarch/kernel/relocate.c b/arch/loongarch/kernel/reloc=
ate.c
index 01f94d1e3edf..6c3eff9af9fb 100644
--- a/arch/loongarch/kernel/relocate.c
+++ b/arch/loongarch/kernel/relocate.c
@@ -157,12 +157,11 @@ static inline void __init update_reloc_offset(unsigne=
d long *addr, long random_o
 	*new_addr =3D (unsigned long)reloc_offset;
 }
=20
-void * __init relocate_kernel(void)
+unsigned long __init relocate_kernel(void)
 {
 	unsigned long kernel_length;
 	unsigned long random_offset =3D 0;
 	void *location_new =3D _text; /* Default to original kernel start */
-	void *kernel_entry =3D start_kernel; /* Default to original kernel entry =
point */
 	char *cmdline =3D early_ioremap(fw_arg1, COMMAND_LINE_SIZE); /* Boot comm=
and line is passed in fw_arg1 */
=20
 	strscpy(boot_command_line, cmdline, COMMAND_LINE_SIZE);
@@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
=20
 		reloc_offset +=3D random_offset;
=20
-		/* Return the new kernel's entry point */
-		kernel_entry =3D RELOCATED_KASLR(start_kernel);
-
 		/* The current thread is now within the relocated kernel */
 		__current_thread_info =3D RELOCATED_KASLR(__current_thread_info);
=20
@@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
=20
 	relocate_absolute(random_offset);
=20
-	return kernel_entry;
+	return random_offset;
 }
=20
 /*
--=20
2.20.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230404084148.744-2-zhangqing%40loongson.cn.
