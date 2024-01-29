Return-Path: <kasan-dev+bncBAABBWOY32WQMGQEXCACSLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C373840752
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 14:47:06 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-68c45d1a07dsf18167606d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 05:47:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706536025; cv=pass;
        d=google.com; s=arc-20160816;
        b=WGHTgH+VpUNbnNu2rBFh9wsUe4X2IKIYnhNRVlF44k45S90VXjenSmXG9Pe50fmt1t
         ZLRtGJd9wAdPLhSPqIabl8+7hF3mxbTYj4yh/2x/0FIM0OibeGs6eSl474vw5v7Z0gO1
         Kt/6ktkL5jV08KxyPuCOddlr3Aubb3By8VJRm2AocDxbxwfkqQQFCYN4fjIABJZHeRwt
         3in2w0m0LX+vG31a4ePMtNTlljhj//JKOI2psPXTkKl3oVm4aGn2i48iuXnVHE7nhKpe
         UerqQPokNHBaLx9aIkPQLflHJcSp9UfP8rvjSwUq7yHwsXrNr3yLVpkt+cp3bWMlLBzu
         ifIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dv0KzbxjZE/PRNdexoGj2NuwasLqoE9S16o1W8+sppA=;
        fh=6OXHs16txR+i/PqfGaaUK9AEaVt6DIoNRW1RjR+8WuM=;
        b=x9BvVRqmQaDF29LXi9APmwbaYG6RUWJXKQdbX1JxwVkQZ7L/qOBF549828PmjY4DTt
         oWkUNDJEUvfXWW1KQTqvhxXMg27AlkKuF5zGce9lgXtF7TqtzqsdgjwjIY/HR1BCRf6M
         KkfF+l6MDU/Zg8Afk3HheuxNnJW19osrmS5+yMb33yQM44daszoUanv42B6kB7Mu7v+8
         6IwZ+A0SZ9pgMHrO4HGVN/QDSWbAIRcXBpdiXXSHPDxWy46OxGMTzzLuhSpQEl4xP8Rf
         vr5BjKQMGsX56hPE5Lek2dX64rxXxwPr3gpacLBAIqtLzTH3ghorg6ADEJjU3QFmgXip
         eiIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706536025; x=1707140825; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dv0KzbxjZE/PRNdexoGj2NuwasLqoE9S16o1W8+sppA=;
        b=hcbxrKXxlQTo+97hmaHpWo7INF6jp8ozHQhW47Mn6z/6tXT6pFezvz+5vdovyLTn2v
         emp5waTe7aFZUiomSosGTfh1vt8281u+hTTFnj9E367ZAMl2JtNf4SuKAf0tljef7V2Y
         EW+k8SlyInwGlvKQOB2GQv66EFkciTNBGRW+1HXI1FYKt7JHTyUjLxCS+QqmyvGJ3Tp4
         XswFwUFKev51nXZSPl8U3ES++6fr7ySaVGDAG43XcSRuD4arZ/kVrNpHg+ZioKVa6pZu
         dS4XYYwHnQxRoorW+VpYE9UdNzNIc3uN4ie5aKmkv7EcE/b2swZPThc6Xecc0MZsYy2b
         viPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706536025; x=1707140825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dv0KzbxjZE/PRNdexoGj2NuwasLqoE9S16o1W8+sppA=;
        b=PHGQvcpIx4lc6EgpFhafQh/fykCszojXLIjwhYXHZMftmJGgzAsUylgk3tJD1VxofX
         D9JSBWE/IeC8pFzogYna82afa9WZ5zdk3XNbQR3TPLXs4L2VlhF3LPSntQECcVkyvKr8
         bTg+mAKdEreUHWFf0DXTDXY8jhllR+PQor8S9nNCDBf/A1fpNuLEY9TU8CxhtBukNMTR
         vSx1aQRSvUA2t2XoavstVm98mO+Ejj6knw3+Wwg3MOesCb3ADZwOotLcMgxuHaAhOWq9
         Ffx+BA9ZjuAgXp8QbpVZpB5qTfP8l8u6MrDgU5koEz307XSEKWv5yWav1HMMOj5y6GMv
         JHiw==
X-Gm-Message-State: AOJu0YwgIXmGP2Kwd/5wiYz8AObDnkG5v+6jDRVX8xiNdSEOs+z+mcMe
	T15E1lrT8UTtp3zOGFFLL/K1CNHTo1Zw80T8fBkGvVDfd1tNU4oa
X-Google-Smtp-Source: AGHT+IFTJma3mzREtzvoFz4SLai7lO9aUfuQCg+weYkFEBa7lmRYLZpFv35eEFdAUPfXBgE7x+Vhmg==
X-Received: by 2002:ad4:5b8f:0:b0:68c:447c:b1c with SMTP id 15-20020ad45b8f000000b0068c447c0b1cmr3461898qvp.26.1706536025263;
        Mon, 29 Jan 2024 05:47:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f547:0:b0:68c:5094:f91b with SMTP id p7-20020a0cf547000000b0068c5094f91bls385022qvm.1.-pod-prod-00-us;
 Mon, 29 Jan 2024 05:47:04 -0800 (PST)
X-Received: by 2002:a05:6214:260b:b0:685:52c7:1c0d with SMTP id gu11-20020a056214260b00b0068552c71c0dmr6645809qvb.58.1706536024724;
        Mon, 29 Jan 2024 05:47:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706536024; cv=none;
        d=google.com; s=arc-20160816;
        b=RgTXA2rdiXr4LL5dSd857EBLdJPwUM0uv4aYM3tGuofIsQpQScwnAUHADpUtkxq7oM
         JpF+PpazSQFkCDjN41hOZAYFBGt21N5J3Xn1tJ6+Dl1gR+7RIbh+XocMU4Z0MSGZfy8y
         PsOnJvcs4a6cTp5TR1j/c4EP0Yx2cnsjEdWgXOE4CE4bl5zAoB6vhFclZDjCkMyLU9D9
         ShkeVTvhJTzZirXS8+U6VkmsEN8UCR1lt46584cfslkD2zSjCqV8CmrFZ5Y9YDGdOc34
         /3yFPGkUVjk9y9cNOBZOTViIXlHqJfmTDdBacDBL+NDNdYX83bxNFmqx1KIcit4mgiF9
         G75w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=inDfPJ8KPUyQcnteDpkHTQ4f2V6PM28Z1hOutgycIus=;
        fh=6OXHs16txR+i/PqfGaaUK9AEaVt6DIoNRW1RjR+8WuM=;
        b=D0OUxu9sbqGFc5h4/40Af9qwYA+CD+mqnp1/oPq3A4xI3mGufm7HHS8lLNrD13zIYZ
         iinW2miWfdQ+6czwQ+xJ0Ili/DPxG+/2LE84we5nAOEvcYmj2PDEYoVKzgKtLU4dO5c5
         9M1ebrWkeWeWXdOoXWx/3JcLN8IoipzFy6P4ugXQ07wDhqNDqG3K8mmoIqrwOzXz/tXH
         6037S/vx2tGPbsjT4hNFzln6puoLEuA15fSbp/ywBe75EthkQXwCoYJ5BGvvI1fedKWj
         VmRnQdl6QZv34VQaWfzwFYNN70rf3zXsF88tgeKBCg9yncimoFw6iv6mLlQ7r6Sd4bZ1
         nEIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCWrX8D08ZYgDg701oXEIBQVoeHjJ2y77IPNzY8W6b0RSPIgp/sQz5f1Q5wHlw07G/WclACwrWashcXb0Q9gAifByXpDj5NPLcqEpQ==
Received: from szxga06-in.huawei.com (szxga06-in.huawei.com. [45.249.212.32])
        by gmr-mx.google.com with ESMTPS id r3-20020ad44043000000b0068c46f075a1si241746qvp.3.2024.01.29.05.47.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jan 2024 05:47:04 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as permitted sender) client-ip=45.249.212.32;
Received: from mail.maildlp.com (unknown [172.19.88.214])
	by szxga06-in.huawei.com (SkyGuard) with ESMTP id 4TNqMx3SYCz1vsVw;
	Mon, 29 Jan 2024 21:46:37 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id B94991A016B;
	Mon, 29 Jan 2024 21:47:01 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Mon, 29 Jan 2024 21:46:59 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>, James Morse <james.morse@arm.com>, Robin
 Murphy <robin.murphy@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Alexander Viro
	<viro@zeniv.linux.org.uk>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy
	<christophe.leroy@csgroup.eu>, Aneesh Kumar K.V <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov
	<bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>,
	"H. Peter Anvin" <hpa@zytor.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v10 3/6] arm64: add uaccess to machine check safe
Date: Mon, 29 Jan 2024 21:46:49 +0800
Message-ID: <20240129134652.4004931-4-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240129134652.4004931-1-tongtiangen@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.32 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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

If user process access memory fails due to hardware memory error, only the
relevant processes are affected, so it is more reasonable to kill the user
process and isolate the corrupt page than to panic the kernel.

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
---
 arch/arm64/lib/copy_from_user.S | 10 +++++-----
 arch/arm64/lib/copy_to_user.S   | 10 +++++-----
 arch/arm64/mm/extable.c         |  8 ++++----
 3 files changed, 14 insertions(+), 14 deletions(-)

diff --git a/arch/arm64/lib/copy_from_user.S b/arch/arm64/lib/copy_from_user.S
index 34e317907524..1bf676e9201d 100644
--- a/arch/arm64/lib/copy_from_user.S
+++ b/arch/arm64/lib/copy_from_user.S
@@ -25,7 +25,7 @@
 	.endm
 
 	.macro strb1 reg, ptr, val
-	strb \reg, [\ptr], \val
+	USER(9998f, strb \reg, [\ptr], \val)
 	.endm
 
 	.macro ldrh1 reg, ptr, val
@@ -33,7 +33,7 @@
 	.endm
 
 	.macro strh1 reg, ptr, val
-	strh \reg, [\ptr], \val
+	USER(9998f, strh \reg, [\ptr], \val)
 	.endm
 
 	.macro ldr1 reg, ptr, val
@@ -41,7 +41,7 @@
 	.endm
 
 	.macro str1 reg, ptr, val
-	str \reg, [\ptr], \val
+	USER(9998f, str \reg, [\ptr], \val)
 	.endm
 
 	.macro ldp1 reg1, reg2, ptr, val
@@ -49,7 +49,7 @@
 	.endm
 
 	.macro stp1 reg1, reg2, ptr, val
-	stp \reg1, \reg2, [\ptr], \val
+	USER(9998f, stp \reg1, \reg2, [\ptr], \val)
 	.endm
 
 end	.req	x5
@@ -66,7 +66,7 @@ SYM_FUNC_START(__arch_copy_from_user)
 	b.ne	9998f
 	// Before being absolutely sure we couldn't copy anything, try harder
 USER(9998f, ldtrb tmp1w, [srcin])
-	strb	tmp1w, [dst], #1
+USER(9998f, strb	tmp1w, [dst], #1)
 9998:	sub	x0, end, dst			// bytes not copied
 	ret
 SYM_FUNC_END(__arch_copy_from_user)
diff --git a/arch/arm64/lib/copy_to_user.S b/arch/arm64/lib/copy_to_user.S
index 802231772608..cc031bd87455 100644
--- a/arch/arm64/lib/copy_to_user.S
+++ b/arch/arm64/lib/copy_to_user.S
@@ -20,7 +20,7 @@
  *	x0 - bytes not copied
  */
 	.macro ldrb1 reg, ptr, val
-	ldrb  \reg, [\ptr], \val
+	USER(9998f, ldrb  \reg, [\ptr], \val)
 	.endm
 
 	.macro strb1 reg, ptr, val
@@ -28,7 +28,7 @@
 	.endm
 
 	.macro ldrh1 reg, ptr, val
-	ldrh  \reg, [\ptr], \val
+	USER(9998f, ldrh  \reg, [\ptr], \val)
 	.endm
 
 	.macro strh1 reg, ptr, val
@@ -36,7 +36,7 @@
 	.endm
 
 	.macro ldr1 reg, ptr, val
-	ldr \reg, [\ptr], \val
+	USER(9998f, ldr \reg, [\ptr], \val)
 	.endm
 
 	.macro str1 reg, ptr, val
@@ -44,7 +44,7 @@
 	.endm
 
 	.macro ldp1 reg1, reg2, ptr, val
-	ldp \reg1, \reg2, [\ptr], \val
+	USER(9998f, ldp \reg1, \reg2, [\ptr], \val)
 	.endm
 
 	.macro stp1 reg1, reg2, ptr, val
@@ -64,7 +64,7 @@ SYM_FUNC_START(__arch_copy_to_user)
 9997:	cmp	dst, dstin
 	b.ne	9998f
 	// Before being absolutely sure we couldn't copy anything, try harder
-	ldrb	tmp1w, [srcin]
+USER(9998f, ldrb	tmp1w, [srcin])
 USER(9998f, sttrb tmp1w, [dst])
 	add	dst, dst, #1
 9998:	sub	x0, end, dst			// bytes not copied
diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
index 478e639f8680..28ec35e3d210 100644
--- a/arch/arm64/mm/extable.c
+++ b/arch/arm64/mm/extable.c
@@ -85,10 +85,10 @@ bool fixup_exception_mc(struct pt_regs *regs)
 	if (!ex)
 		return false;
 
-	/*
-	 * This is not complete, More Machine check safe extable type can
-	 * be processed here.
-	 */
+	switch (ex->type) {
+	case EX_TYPE_UACCESS_ERR_ZERO:
+		return ex_handler_uaccess_err_zero(ex, regs);
+	}
 
 	return false;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240129134652.4004931-4-tongtiangen%40huawei.com.
