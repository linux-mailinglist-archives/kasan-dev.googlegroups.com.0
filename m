Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBXOGVOAAMGQEYDNEZ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4053F3005A1
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:38:23 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id j11sf3700677pjw.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:38:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611326302; cv=pass;
        d=google.com; s=arc-20160816;
        b=T1dUXPk1f8Fg/DwClLZFoqha334fpSev4mBhZovU2+nRCD6y1SspeFvNXkulSpsG6n
         BEtKwdVVDvl194glr/y59Et20ZFDgvdSs1bHNYqJK2pmDwZ1p2rijM7nisQIJfk0cLzj
         4rtZqNsKAvR/kxqVZU+8zSYjrxLFapGwdKyH/BbdUZrcsR/vWVV5AD60E9O3PuULRMYE
         tFCbB2LeKlA7dOtmv20OnYLTMUEEEy3ZMv/DBWqVxC1JIgyUNcspKXPYoyAY2wxADhDa
         XLG4pgl/paFyJSskSMQmAthXN9qrDxiP5OD57FYHzTlRwF+xwy13LbqL0CfwMrfSU6r6
         eOSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MY9MbeV4WMVgroVPIAHRGFYV17D3yi27xvBM83LTZU0=;
        b=vHjwpMQvbt4edQO4fAYuQ1SyynpqdZxWULTioqVDuEdcqzpGYLnDingq4Z6fqmbu8h
         RH02mzLaYpR2jM+Ut2WfQwKXTgSzAtpch/u/Z0flR61apcmQ+KLRjp5yR1YKboI9/3MC
         pduPPU0XNhHQiC2nHodI/9B2T8+aK0g5KgN5Nhw48RgEDjl6TdBb/tVmxOSwTsf3KZIQ
         hMDjwlAHKb6J6sJasEB1Nq0hPbydZk5tJjqTTesD2+MuIb8a/fvF6KEJjA55EQ9Dxguv
         0ld38aINCNBq4yy0zp+qXumHd7v58aj5F7In2WfXlGB1EBVet/Ck5NfQgUMwGr1o0bLe
         IG9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MY9MbeV4WMVgroVPIAHRGFYV17D3yi27xvBM83LTZU0=;
        b=oVP6whVJGBY1UTvq3LEaK+eI2WaOCoLDG/YQqy5Rnmt+pvUXUkWcslaOt28XFS680J
         8em4dlByOHf3ZePJfNi48vnWBTOfiP0xWMUQw5rSwHYePfRw2RAIfK2DQ1tmmtrg0lSQ
         mQ4IBu7iSGyjVxD3NP4ZQ8gDUQCL1TWl95GMbipVVuoZer2MGzXH8kjomDF9T5q/0S5f
         Tb+PVCeu/JX6J8K7lA+i8TE4mrlifj+PaSF2SJU8QiIeIAPpuJfuoVt+bVgJWoh5vKUK
         5zHnTiQ0jUF4I68rgvf7G+USF2CpfW/Vo4OaBUavUYduuDpRW5iKfDrGK8lRcSPNIz9F
         VChA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MY9MbeV4WMVgroVPIAHRGFYV17D3yi27xvBM83LTZU0=;
        b=dquKE7DM03QoX07KR3ueLmUFwvpLh3jt7Z5vVQOYs7/fonCJduA+BWyxwZ0moLQZ6t
         PhWlm49tsRkZZJlrmsqqf7DmXyzkBQSnAqPbSVCyeoeVXpAcYsbmfxX46G8rEy1HxaiK
         xia7Ldud/o8C8dlyoM2jiPQ1gjv9MwyIj1sGcj7imlPxWGthop6uYnoIBBBRGr1jvjLH
         uTF2toCoIrXvMbnUf7Ou5bwo/CIAUVoxuIXQ+v58mLmegyhX+/TSJxuSbVtGB+OMmaue
         URTj8zwZI5QAdOH1/CCPMb59NBac73XZoTMdBDS+kUjjG2gPtMlYpj27L6qk75ojARxv
         RF4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UMM8gb8ddN/FYZfZmziEY/JnltdOIRWLyWHrIHeNIrLjti+r2
	opeUkPzgSmjoUJINB9eNUPs=
X-Google-Smtp-Source: ABdhPJwau1vEHF6akjH3kCwJPy73lqTbCUfn8yivfaw+pMdLtwXMI3zPxP5RtH9SqSnPR47M2bvBEQ==
X-Received: by 2002:a17:902:5991:b029:de:a709:ffda with SMTP id p17-20020a1709025991b02900dea709ffdamr5291705pli.63.1611326301986;
        Fri, 22 Jan 2021 06:38:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:3583:: with SMTP id c125ls2241893pfa.2.gmail; Fri, 22
 Jan 2021 06:38:21 -0800 (PST)
X-Received: by 2002:a62:2bd4:0:b029:1ae:4d9f:60da with SMTP id r203-20020a622bd40000b02901ae4d9f60damr5205676pfr.20.1611326301379;
        Fri, 22 Jan 2021 06:38:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611326301; cv=none;
        d=google.com; s=arc-20160816;
        b=cyGphvwBSbnWFMNzuyG85c9dltI79zmkHfTYYiLggseXQ04rCugR6Xx+BN3W3jM7DF
         /ZOFfe4l+H1yESdYzZDEG2+K97N43ZA6XuJopOnFJ39reRyBrToZf/GvtPQqqDaakY6a
         /dVb9w56shpHrGq75DsqlAj3k9cvM261398g/aND4kYujA6kiI1Ymh6J+thJnqjVoSv7
         2Skkto8htzIfWId9eSeQMjvdnwSEksLMKoyt9Uc7UqxoDqSLLVlnsOCNtTr9e7fxqJ6R
         OQ/1ZiQil+1JaDxP/1ZEzXxFeetSbDAhldMJ2zx2SfF9Jgk4I5NfE80GYrQT8Ji4Np8G
         Pxtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=m8UmuQFfLSaM8Gu/jNBJYAwG0yri/QM3I6oR403p7q4=;
        b=YV+bL7/SJw5bqhNfl8rxN1QLJ8IZrH2W2xwev3KoO18tMI8Qs0MbMqjlS6E0Kcu86o
         X5g3qj6MO7LqkobXBoANYiUGVw+iM76nDWq0QvTEq83L6SZKYxDpcy7YNFeiAA0uGgAZ
         0X9b99uwx93lKY7bcUdOA34vd71+7SL9EndGB+EqiagvVHS8XAOAy0k35UGD601k8sl9
         vuJuWiZ5hbajlPX5MXxxuulP9wVAwrx5Muf6cHVP+IfswSNma3OuV4BaA1Oi7Dl72BqJ
         DiH92H3gemcUY6+RIOLo+CeTYtuwt+YzE+5qLmN4hhinQGh2v/xKEUUR0aNNoeMLwSwP
         4URQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si589296pfr.4.2021.01.22.06.38.21
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:38:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AFD9C139F;
	Fri, 22 Jan 2021 06:38:20 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E88153F66E;
	Fri, 22 Jan 2021 06:38:18 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH v3 2/2] kasan: Add explicit preconditions to kasan_report()
Date: Fri, 22 Jan 2021 14:37:48 +0000
Message-Id: <20210122143748.50089-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122143748.50089-1-vincenzo.frascino@arm.com>
References: <20210122143748.50089-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
the address passed as a parameter.

Add a comment to make sure that the preconditions to the function are
explicitly clarified.

Note: An invalid address (e.g. NULL) passed to the function when,
KASAN_HW_TAGS is enabled, leads to a kernel panic.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h | 7 +++++++
 mm/kasan/kasan.h      | 2 +-
 2 files changed, 8 insertions(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index fe1ae73ff8b5..0aea9e2a2a01 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -333,6 +333,13 @@ static inline void *kasan_reset_tag(const void *addr)
 	return (void *)arch_kasan_reset_tag(addr);
 }
 
+/**
+ * kasan_report - print a report about a bad memory access detected by KASAN
+ * @addr: address of the bad access
+ * @size: size of the bad access
+ * @is_write: whether the bad access is a write or a read
+ * @ip: instruction pointer for the accessibility check or the bad access itself
+ */
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc4d9e1d49b1..8c706e7652f2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -209,7 +209,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 
 static inline bool addr_has_metadata(const void *addr)
 {
-	return true;
+	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122143748.50089-3-vincenzo.frascino%40arm.com.
