Return-Path: <kasan-dev+bncBAABBX5MSCSQMGQESOYTWFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 285437471CF
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jul 2023 14:53:53 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1b024a30c25sf6046885fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jul 2023 05:53:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688475231; cv=pass;
        d=google.com; s=arc-20160816;
        b=P+jSeSACAMg0fXjQAAQ9v82oE9P3ZyMpcWeqpFIFL02adq+kM0DsfcnRaJv9b3Dbew
         16GYqEG4D23ksHr9mIJVX2iaD1eTzFijZD9XrVuH5EeDM5AYC37aVrPhksr2Yzc+IDb6
         2UACmmGCt48uyfbs2KHNFP9k9qveb4quvojKlbYqWVl9cGGQjU/aXu+xyOVF2jm/mVuX
         Ak5xg7vNgfT3B3o9xXRAkXdHHfum/ireRDCZfTAngC+9ZKUa+eSGJJax9Mkr+a522ag5
         6RW1opzOpJPAben20OBVkcDqgw18MWoc3MAsKDoy7cyuRBQphL8ygnTkQSBS1RS+NTSJ
         Ysdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3Vg8nDQgZnElu48VOHgoJPCAPDMx0lXrB1wSCa4LAao=;
        fh=RwV5KzEavdxvCtZEIU9FQTiL0UHz0DnVYX3zSTzIiiQ=;
        b=oDxENUTnVxsVAdAy42U1oLyOkeM+51AuEJZhKGbRH91/9rFTNX1HxsJ8twQU/N3boC
         IOl+P++9QrKmZ8YpE7V/pf7g5w5lwsUsk2VkDB1lT0ZrDuLukEqisPypXCH3mZcf8FNG
         6A1BirPICXqTEpbz3HJpLf7zmvJHN3KqsByzK3W40SzEjUWgW1zVHlFQk6IMjXzoLO3C
         gMbFPB75lfw7XevGp3/NjGIAZshqj4mTzXsNTRwWeHGv1oV1AOLY6E50SgHhAD/P2QVD
         ueIUD9tzSDaJCo2ThYkiDo8wC0wDBRgF0kZlF93tui+ewo+I4aewzEL9X3sNoWDaLZTi
         qqIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688475231; x=1691067231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3Vg8nDQgZnElu48VOHgoJPCAPDMx0lXrB1wSCa4LAao=;
        b=hi8yRgAsS/fRQc4T1eoa0pWyavOiC4t7bIBBYvj/bV22vHvxQqNSSbHyRoqaqcuq6E
         6PvOTLuoZ+ivDe2GVYfuU25E08u/9t2ODOmEqudNWfw4QUfxHEKwZ+yUSC0mQYHg+Gi+
         SXsKpzaGSRU64V46kCKPaFengvudsTY4H7RnSApCcq7mbKHQXl5xC8rOLdWZf6cRVql4
         YY21wurwUAoluogqUe3JwCtDIuUcrdry3umgY/Mf/sxpl4WSDykOdCcL42VQTL8q/kPi
         Wrsyv4SQlO0hd4A7PTyYQLr+iSzMeiQpZryTMlJJFwACR04d1A9C0Ac/4KnUFi1z/5F7
         dPVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688475231; x=1691067231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3Vg8nDQgZnElu48VOHgoJPCAPDMx0lXrB1wSCa4LAao=;
        b=kc6aEhtdbMFv1PWVhW1Tpqv2uWlOpKfm6fOhICmaW0pZUYvKtfHhG2SawZmPqABW3z
         sKUqIjjU1ZZ3uGP7Su58EML5XJy8deLhUqoDi9/JAe6Y/Rb9roUIhVzWTQ6K0vJGX9we
         iaNPvtnZXV5SKSrP/P3Du0WVC28AVnp/Q1ni/wOE7ZYBA9JPnzKSaAJk2TZw18nqBAH6
         mEAbwsho+PidWwKV6lykvCJIst+/qNN/L+oWPv962P2CJ785wClitgzlqWchO57jRadR
         7jRUJNV6mMihQQg4fTEok9RhA4ppMkQAjTwmhCwT7upvhSrmdcTqE+bxntxMXXcn6/CF
         TGWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYalnPpKm1H/HySo+22ShdgKrrAxgesRAH2AgS2oc7yC5J7rALX
	Ul0kOOn+O7wU1+lp27TuqpA=
X-Google-Smtp-Source: ACHHUZ6bM4cFrpzvGjGPCy1VBYbhUtGp+I9dDKvXSR0M+F2pRILKURYlrn28oO5K6ayXVn3+fOx3tA==
X-Received: by 2002:a05:6870:7e13:b0:1b0:657f:5047 with SMTP id wx19-20020a0568707e1300b001b0657f5047mr14713556oab.46.1688475231544;
        Tue, 04 Jul 2023 05:53:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:cb91:b0:1b3:8c88:60e1 with SMTP id
 ov17-20020a056870cb9100b001b38c8860e1ls347387oab.1.-pod-prod-07-us; Tue, 04
 Jul 2023 05:53:51 -0700 (PDT)
X-Received: by 2002:a54:4405:0:b0:3a3:9041:90fb with SMTP id k5-20020a544405000000b003a3904190fbmr10683491oiw.14.1688475230937;
        Tue, 04 Jul 2023 05:53:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688475230; cv=none;
        d=google.com; s=arc-20160816;
        b=caK7M+a6aB5BQz+ck0D+ZHtITAsrj5MTQQ2xt7ijPn+ifFCFto44qOOgM/+5ddYjo3
         9tZoSRBOQIXsgpB8wud1Gba2c5Ld7v++BnMLpsg0KwDe0KIYg4NRP6wQ0FqJFsCwaI46
         TBinvpMpzflJRbpyLDsm655pE0Z+roj7hXUuF3zGJo/WAiTcm+4cbuQLFrg1R4vAoBe6
         EMnca5ncZ00s4rMJ+9eqp+xUlaDD8E12jj4l+ZSf/prDruBuCpYpdvjL1eSPaJeuOX3I
         f4mZzwtMyMwszJ+Dyvg0OpM9DE7hVPEHCCfLWervpnsXys7rSPgbyOytmwb9CiQQMjXp
         WmMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=2omtxFjgXbKWb5VQedHpJfd6RwEt4Ju1PlWMUhu0CwE=;
        fh=JatFWl46A5X89rXdZaHeLDn2zYWoXqmrRBIL0ag9sD8=;
        b=0opbs9+FltlyybGzNCDPx4/73HQU3D6QnpFmIp1Mss/tB0SGjgdWdnJIDD6AD2Uj0v
         rbkfd0m0+y0WgxluOJVuwnInAaPgeJZe2zlpyA+Jct1ZnYgFjPSwhaCvs8X3UgM63e5m
         Qh6xPra9U6fUaK8rXqY/rOMrYbRay/RZoEKka2B4fOof4X78e+6SKA4uoVMHk0n8tyCA
         bugeDmMoVVyzDvoobf5cQkDbIWSCYzNn+fbNrk5ujZAYTaRtBe406/Y8LlZEdr69Wgr/
         vvop6uzEt3cqggtYwoJdCN5ud8ECrcyVTD4ZBJMVxixNLwtdRucg3uj0hkd3NPrNDXvi
         OMeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=chenfeiyang@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id k2-20020a17090a9d8200b0024790d8421dsi740297pjp.1.2023.07.04.05.53.49
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Jul 2023 05:53:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenfeiyang@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [112.20.109.108])
	by gateway (Coremail) with SMTP id _____8BxpPBcFqRkyAQAAA--.53S3;
	Tue, 04 Jul 2023 20:53:48 +0800 (CST)
Received: from localhost.localdomain (unknown [112.20.109.108])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Ax98xaFqRkXDAbAA--.63241S3;
	Tue, 04 Jul 2023 20:53:47 +0800 (CST)
From: Feiyang Chen <chenfeiyang@loongson.cn>
To: chenhuacai@kernel.org
Cc: Feiyang Chen <chenfeiyang@loongson.cn>,
	dvyukov@google.com,
	andreyknvl@gmail.com,
	loongarch@lists.linux.dev,
	kasan-dev@googlegroups.com,
	chris.chenfeiyang@gmail.com,
	loongson-kernel@lists.loongnix.cn
Subject: [PATCH 1/2] LoongArch: relocatable: Provide kaslr_offset() to get the kernel offset
Date: Tue,  4 Jul 2023 20:53:31 +0800
Message-Id: <cfc7b16d31d0f2dbe08d5d835f34796b2074a35a.1688369658.git.chenfeiyang@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <cover.1688369658.git.chenfeiyang@loongson.cn>
References: <cover.1688369658.git.chenfeiyang@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8Ax98xaFqRkXDAbAA--.63241S3
X-CM-SenderInfo: hfkh0wphl1t03j6o00pqjv00gofq/
X-Coremail-Antispam: 1Uk129KBj93XoWxZw4DWrWxKr4kuF17AF1kJFc_yoWrJFyDpF
	9rZw1Dtr4fGr1xGrWqqa4kury5JwsrWw1agFsFk34xZ3W2qFy5JaykuFnruayUX3y0vF4f
	Xas8trnFva1DJ3XCm3ZEXasCq-sJn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7ZEXa
	sCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29KBjDU
	0xBIdaVrnRJUUUkjb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26cxKx2
	IYs7xG6rWj6s0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48v
	e4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI
	0_Gr0_Cr1l84ACjcxK6I8E87Iv67AKxVW8JVWxJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_
	Gr0_Gr1UM2AIxVAIcxkEcVAq07x20xvEncxIr21l57IF6xkI12xvs2x26I8E6xACxx1l5I
	8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r126r1DMcIj6I8E87Iv67AK
	xVWUJVW8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41l42xK82IYc2Ij64
	vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8G
	jcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MIIYrxkI7VAKI48JMIIF0xvE2I
	x0cI8IcVAFwI0_JFI_Gr1lIxAIcVC0I7IYx2IY6xkF7I0E14v26r1j6r4UMIIF0xvE42xK
	8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I
	0E14v26r1j6r4UYxBIdaVFxhVjvjDU0xZFpf9x07j83kZUUUUU=
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
Rename reloc_offset to __reloc_offset and export it.

Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>
---
 arch/loongarch/include/asm/setup.h |  6 ++++++
 arch/loongarch/kernel/relocate.c   | 18 ++++++++----------
 arch/loongarch/kernel/setup.c      |  3 +++
 3 files changed, 17 insertions(+), 10 deletions(-)

diff --git a/arch/loongarch/include/asm/setup.h b/arch/loongarch/include/asm/setup.h
index 2dca0d1dd90a..39f9964bbdd4 100644
--- a/arch/loongarch/include/asm/setup.h
+++ b/arch/loongarch/include/asm/setup.h
@@ -37,4 +37,10 @@ extern unsigned long __init relocate_kernel(void);
 
 #endif
 
+extern unsigned long __reloc_offset;
+static inline unsigned long kaslr_offset(void)
+{
+	return __reloc_offset;
+}
+
 #endif /* __SETUP_H */
diff --git a/arch/loongarch/kernel/relocate.c b/arch/loongarch/kernel/relocate.c
index 6c3eff9af9fb..9ba560d514e1 100644
--- a/arch/loongarch/kernel/relocate.c
+++ b/arch/loongarch/kernel/relocate.c
@@ -16,11 +16,9 @@
 #include <asm/sections.h>
 #include <asm/setup.h>
 
-#define RELOCATED(x) ((void *)((long)x + reloc_offset))
+#define RELOCATED(x) ((void *)((long)x + __reloc_offset))
 #define RELOCATED_KASLR(x) ((void *)((long)x + random_offset))
 
-static unsigned long reloc_offset;
-
 static inline void __init relocate_relative(void)
 {
 	Elf64_Rela *rela, *rela_end;
@@ -154,7 +152,7 @@ static inline void __init update_reloc_offset(unsigned long *addr, long random_o
 {
 	unsigned long *new_addr = (unsigned long *)RELOCATED_KASLR(addr);
 
-	*new_addr = (unsigned long)reloc_offset;
+	*new_addr = (unsigned long)__reloc_offset;
 }
 
 unsigned long __init relocate_kernel(void)
@@ -173,7 +171,7 @@ unsigned long __init relocate_kernel(void)
 	if (relocation_addr_valid(location_new))
 		random_offset = (unsigned long)location_new - (unsigned long)(_text);
 #endif
-	reloc_offset = (unsigned long)_text - VMLINUX_LOAD_ADDRESS;
+	__reloc_offset = (unsigned long)_text - VMLINUX_LOAD_ADDRESS;
 
 	if (random_offset) {
 		kernel_length = (long)(_end) - (long)(_text);
@@ -187,15 +185,15 @@ unsigned long __init relocate_kernel(void)
 			"dbar 0 \t\n"
 			::: "memory");
 
-		reloc_offset += random_offset;
+		__reloc_offset += random_offset;
 
 		/* The current thread is now within the relocated kernel */
 		__current_thread_info = RELOCATED_KASLR(__current_thread_info);
 
-		update_reloc_offset(&reloc_offset, random_offset);
+		update_reloc_offset(&__reloc_offset, random_offset);
 	}
 
-	if (reloc_offset)
+	if (__reloc_offset)
 		relocate_relative();
 
 	relocate_absolute(random_offset);
@@ -208,9 +206,9 @@ unsigned long __init relocate_kernel(void)
  */
 static void show_kernel_relocation(const char *level)
 {
-	if (reloc_offset > 0) {
+	if (__reloc_offset > 0) {
 		printk(level);
-		pr_cont("Kernel relocated by 0x%lx\n", reloc_offset);
+		pr_cont("Kernel relocated by 0x%lx\n", __reloc_offset);
 		pr_cont(" .text @ 0x%px\n", _text);
 		pr_cont(" .data @ 0x%px\n", _sdata);
 		pr_cont(" .bss  @ 0x%px\n", __bss_start);
diff --git a/arch/loongarch/kernel/setup.c b/arch/loongarch/kernel/setup.c
index 95e6b579dfdd..d7bda711824f 100644
--- a/arch/loongarch/kernel/setup.c
+++ b/arch/loongarch/kernel/setup.c
@@ -65,6 +65,9 @@ struct cpuinfo_loongarch cpu_data[NR_CPUS] __read_mostly;
 
 EXPORT_SYMBOL(cpu_data);
 
+unsigned long __reloc_offset __ro_after_init;
+EXPORT_SYMBOL(__reloc_offset);
+
 struct loongson_board_info b_info;
 static const char dmi_empty_string[] = "        ";
 
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cfc7b16d31d0f2dbe08d5d835f34796b2074a35a.1688369658.git.chenfeiyang%40loongson.cn.
