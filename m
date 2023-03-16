Return-Path: <kasan-dev+bncBC7OBJGL2MHBBROUZOQAMGQED2ZKO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id DDC296BCBFF
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 11:07:02 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id s18-20020a7bc392000000b003deaf780ab6sf430297wmj.4
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 03:07:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678961222; cv=pass;
        d=google.com; s=arc-20160816;
        b=tC5ELrS58CZ47CS5Gp2GudIQyEXq/oDeRPUVXUDS4KphRvHNUO1OgFpk0d1pZINJlE
         nxofY4nK4CDloAZ2c+io22cpMZqrcFF+qCd5Adoyvfne2T/HfTjEeXCKeVOuifZxQXbV
         4FM6CLYc8RjC6tfisHDhZZXOOr7WA+FOW2eWITPrIVQTRuRsU8wv8faRP7bJyUMdR3qk
         rqydQMbPY3VzFxdoLubi7znDFkBjpRQG9BeLp/KrF0Mw1f+TudaA2kLzf4VheFuE7YIj
         0aMdJeaRa25ATF/OHRwCqt6IUvHijZWfRXD+k87Qgeq1qK2cj3neYMGtLgEaXtTxmViG
         Au+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=temHdX2WaxunK4rWZ19tkh1Gt35w5C9lz5TsWI3HDR4=;
        b=0pbpqsbYUTcnRmfBI36fwAa/OO0wBgWIkYeq24xZIprOLS3ziZfTyf/D1SV73+3pmZ
         +ycxgU36zRqYdzhaG5PK8TypHwyNupw1SgOdMJfIaHThBzZpRN8x6PqP8kc8bmVvX+yi
         zWfuPQxU48vIo3EvjO3r/69AAProK0YlQS/l5U48+WwKIlkJyZoCOaV+lvAg2yuXZkZq
         txVEE9GaVfPXWAyVGGj2bqmzCCpcUy88i2rOPdb31AhUqHKXRZacoPPPvrR+mFJqRVZq
         y+6L2+H9FrnotbSa5m902M+j6L4SOnOvfbHPwOU06uNXnqUklScnfwD1u4TP6QT1bGBq
         tVTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=k1reqwA7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678961222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=temHdX2WaxunK4rWZ19tkh1Gt35w5C9lz5TsWI3HDR4=;
        b=o1A9Ob90CyyXow5yPUFq4r55XmJlQV8WXlkQol1DlzY7mggoDvTfrdjGg1qhzA+dob
         FK3kMm3OOi+gwOitiCg1NoIfGs/KJ4jbpUenEsGz2Mw09jAAHvYqTzXHQvRFzjWZ23p6
         lRpsmgyhcfzi/X44TpLU3D9htUqaEXkvvPzQ8YmYesIhn5OUE8EJlcdrLsHyHUX19qZ+
         BFZbu1XEIG1xjLiN2ALB1HB2jG9TEjOLTaku24rX+wx/xe0cuaISYl+J6bjxTikRSENR
         F7N1xZ2bWEFrpOBmIjRVeK8ZelS0BTPWFynlX9DJefXx9Zmhe8NfmNMm7zP5qsW9Oz5t
         CKBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678961222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=temHdX2WaxunK4rWZ19tkh1Gt35w5C9lz5TsWI3HDR4=;
        b=6haH98BPqKIKLLVF3zYZ9gw2mOOZ5EdrxXwHtfvhTmxPE4lNOi2SPTzkeqpoWpRg9+
         jBQHM2WlOMnQSG+HrdRXHNpQsWiB9+oyDc2beyTTuP6NfLNYrTW//sTXizJYpwOpmLis
         OQha+ecN/WXEx7NUKrzedXErXA4eTTMh3AtL/7h/CnUaDV4pDwSx6dE3Wc8aDIX6zPxT
         WKVQzDiulfTwDB07RxeqD2ZlCpH1ANn3MDDHYEJzIbfrJz9APYOTM758JEY51L2KmJYu
         JZQN8clWH5v0UjruyOy38cHBcCTaxovg3twOzQfSmnInkEeCzE+4kdNv6grz+30yy7Q6
         g8zw==
X-Gm-Message-State: AO0yUKVYQm9b8tR4WtnUpPtjaeanIY7JBp0DLYyrXyFYQRct9yIMNmxp
	aI8FqCRnBGQss8d+99vR7sc=
X-Google-Smtp-Source: AK7set8D7RdKsrWW3YGLWTm7Cb8LEEwt+efs3xACPMwhhLGj7f1VC/9CMxOn0t129RyrXTHnQzhJGQ==
X-Received: by 2002:a5d:6dc5:0:b0:2cf:e44a:54a3 with SMTP id d5-20020a5d6dc5000000b002cfe44a54a3mr1184684wrz.5.1678961221967;
        Thu, 16 Mar 2023 03:07:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6023:b0:3cf:9be3:73dd with SMTP id
 az35-20020a05600c602300b003cf9be373ddls2681949wmb.3.-pod-canary-gmail; Thu,
 16 Mar 2023 03:07:00 -0700 (PDT)
X-Received: by 2002:a05:600c:a4c:b0:3ed:2e02:1c02 with SMTP id c12-20020a05600c0a4c00b003ed2e021c02mr7965240wmq.23.1678961220377;
        Thu, 16 Mar 2023 03:07:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678961220; cv=none;
        d=google.com; s=arc-20160816;
        b=p6JByxbJSIpaHA1odeaLrj5/6iN4jIw302WCdw1WnU3uKG+W1cI5mRZYQ/rYb9Ud6T
         f5c+x8RcaKW/f7BWKmGtXi9YCB85UFsVeL9R+e5sA5F9zt2NaUKltqiWK1gsV8fQxiqV
         izLszqBxuk9R5+wQpjjx/e9TrMGzQmDaSMpAbCFd87HBxw4crnWBPcg+sHl9TbpKblEo
         ukR5iyHBbw/c58FpXERBM0vl46DdSXEfxmBcM5tQggbmFNjoOoPTaL5SfpNakBizF5WD
         fD5xwPPKRdScvz8NgBl8CTR+dkiIqBn+eAL6nCOO04qFO4htWYIDxwQdbq6tDzxdB3Jt
         Gi1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EMq7tDc/0X3ajktZnr96EPs4WhVyPi++3wTjhaux/UU=;
        b=LJXPcFziwZvYPkL8KCVdvQXpt4pA9VFaVRfExeZGGIwM3LENGo+5Ba/8Kvw3CVPsSp
         NLdrl7MYfOpVv81NAAqvCgyh3A144TVwGhy/OcjpmgFQxlYIWk1WOiqgn+ANaKzHHqWk
         oGK8dyaOcUJndOrdF4ixRCvqhj+LhyYQLCZBBBKNJeaQ/h78ZqlXRrgIEFeMcMoQTX+g
         W029/utgCPtxV/6+R5aOMnD6MhKDyjJssiHYmJtmRmVDHOt05YcnDyQHXG0VZ3oizsw4
         kuxOyOOBxpT85MmufX50hHhjGh6Tap3B7+o6jH4ezBNeyFrtMBMzRRB/CknfuOMKw7nQ
         lN+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=k1reqwA7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id ay21-20020a05600c1e1500b003ed22457910si231642wmb.2.2023.03.16.03.07.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 03:07:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id x22so808053wmj.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 03:07:00 -0700 (PDT)
X-Received: by 2002:a05:600c:4ed0:b0:3e2:20c7:6553 with SMTP id g16-20020a05600c4ed000b003e220c76553mr20455044wmq.13.1678961219905;
        Thu, 16 Mar 2023 03:06:59 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:f359:6b95:96e:1317])
        by smtp.gmail.com with ESMTPSA id bd20-20020a05600c1f1400b003e21dcccf9fsm4470397wmb.16.2023.03.16.03.06.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Mar 2023 03:06:57 -0700 (PDT)
Date: Thu, 16 Mar 2023 11:06:50 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: catalin.marinas@arm.com, will@kernel.org, glider@google.com,
	dvyukov@google.com, akpm@linux-foundation.org, robin.murphy@arm.com,
	mark.rutland@arm.com, jianyong.wu@arm.com, james.morse@arm.com,
	wangkefeng.wang@huawei.com, linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	quic_pkondeti@quicinc.com, quic_guptap@quicinc.com,
	quic_tingweiz@quicinc.com
Subject: Re: [PATCH v9] mm,kfence: decouple kfence from page granularity
 mapping judgement
Message-ID: <ZBLqOv2RTScbydrj@elver.google.com>
References: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=k1reqwA7;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Mar 16, 2023 at 04:50PM +0800, Zhenhua Huang wrote:
> Kfence only needs its pool to be mapped as page granularity, if it is
> inited early. Previous judgement was a bit over protected. From [1], Mark
> suggested to "just map the KFENCE region a page granularity". So I
> decouple it from judgement and do page granularity mapping for kfence
> pool only. Need to be noticed that late init of kfence pool still requires
> page granularity mapping.
> 
> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
> gki_defconfig, also turning off rodata protection:
> Before:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:         999484 kB
> After:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:        1001480 kB
> 
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> addr, __kfence_pool is to be set after linear mapping set up.
> 
> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> ---
>  arch/arm64/include/asm/kfence.h | 16 +++++++++++
>  arch/arm64/mm/mmu.c             | 59 +++++++++++++++++++++++++++++++++++++++++
>  arch/arm64/mm/pageattr.c        |  9 +++++--
>  include/linux/kfence.h          |  1 +
>  mm/kfence/core.c                |  4 +++
>  5 files changed, 87 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> index aa855c6..8143c91 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -10,6 +10,22 @@
>  
>  #include <asm/set_memory.h>
>  
> +extern phys_addr_t early_kfence_pool;

This should not be accessible if !CONFIG_KFENCE.

> +#ifdef CONFIG_KFENCE
> +
> +extern char *__kfence_pool;
> +static inline void kfence_set_pool(phys_addr_t addr)
> +{
> +	__kfence_pool = phys_to_virt(addr);
> +}

kfence_set_pool() is redundant if it's for arm64 only, because we know
where it's needed, and there you could just access __kfence_pool
directly. So let's just remove this function. (Initially I thought you
want to provide it generally, also for other architectures.)

> +#else
> +
> +static inline void kfence_set_pool(phys_addr_t addr) { }
> +
> +#endif
> +
>  static inline bool arch_kfence_init_pool(void) { return true; }
[...]
> +#endif
> +
> +phys_addr_t early_kfence_pool;

This variable now exists in non-KFENCE builds, which is wrong.

>  static void __init map_mem(pgd_t *pgdp)
>  {
>  	static const u64 direct_map_end = _PAGE_END(VA_BITS_MIN);
> @@ -543,6 +587,10 @@ static void __init map_mem(pgd_t *pgdp)
>  	 */
>  	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
>  
> +	early_kfence_pool = arm64_kfence_alloc_pool();
> +	if (early_kfence_pool)
> +		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> +
>  	if (can_set_direct_map())
>  		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
>  
> @@ -608,6 +656,17 @@ static void __init map_mem(pgd_t *pgdp)
>  		}
>  	}
>  #endif
> +
> +	/* Kfence pool needs page-level mapping */
> +	if (early_kfence_pool) {
> +		__map_memblock(pgdp, early_kfence_pool,
> +			early_kfence_pool + KFENCE_POOL_SIZE,
> +			pgprot_tagged(PAGE_KERNEL),
> +			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> +		memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> +		/* kfence_pool really mapped now */
> +		kfence_set_pool(early_kfence_pool);
> +	}

This whole piece of code could also be wrapped in another function,
which becomes a no-op if !CONFIG_KFENCE. Then you also don't need to
provide the KFENCE_POOL_SIZE define for 0 if !CONFIG_KFENCE.

[...]
> +	 *
> +	 * Kfence pool requires page granularity mapping also if we init it
> +	 * late.
>  	 */
>  	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
> -		IS_ENABLED(CONFIG_KFENCE);
> +	    (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);

Accessing a non-existent variable if !CONFIG_KFENCE works because the
compiler optimizes out the access, but is generally bad style.


I think the only issue that I have is that the separation between KFENCE
and non-KFENCE builds is not great.

At the end of the email are is a diff against your patch which would be
my suggested changes (while at it, I fixed up a bunch of other issues).
Untested, so if you decide to adopt these changes, please test.

Thanks,
-- Marco

------ >8 ------


diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
index 8143c91854e1..a81937fae9f6 100644
--- a/arch/arm64/include/asm/kfence.h
+++ b/arch/arm64/include/asm/kfence.h
@@ -10,22 +10,6 @@
 
 #include <asm/set_memory.h>
 
-extern phys_addr_t early_kfence_pool;
-
-#ifdef CONFIG_KFENCE
-
-extern char *__kfence_pool;
-static inline void kfence_set_pool(phys_addr_t addr)
-{
-	__kfence_pool = phys_to_virt(addr);
-}
-
-#else
-
-static inline void kfence_set_pool(phys_addr_t addr) { }
-
-#endif
-
 static inline bool arch_kfence_init_pool(void) { return true; }
 
 static inline bool kfence_protect_page(unsigned long addr, bool protect)
@@ -35,4 +19,14 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	return true;
 }
 
+#ifdef CONFIG_KFENCE
+extern bool kfence_early_init;
+static inline bool arm64_kfence_can_set_direct_map(void)
+{
+	return !kfence_early_init;
+}
+#else /* CONFIG_KFENCE */
+static inline bool arm64_kfence_can_set_direct_map(void) { return false; }
+#endif /* CONFIG_KFENCE */
+
 #endif /* __ASM_KFENCE_H */
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 61944c7091f0..683958616ac1 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -528,17 +528,14 @@ static int __init enable_crash_mem_map(char *arg)
 early_param("crashkernel", enable_crash_mem_map);
 
 #ifdef CONFIG_KFENCE
+bool kfence_early_init = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
 
-static bool kfence_early_init __initdata = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
-/*
- * early_param can be parsed before linear mapping
- * set up
- */
-static int __init parse_kfence_early_init(char *p)
+/* early_param() will be parsed before map_mem() below. */
+static int __init parse_kfence_early_init(char *arg)
 {
 	int val;
 
-	if (get_option(&p, &val))
+	if (get_option(&arg, &val))
 		kfence_early_init = !!val;
 	return 0;
 }
@@ -552,22 +549,34 @@ static phys_addr_t arm64_kfence_alloc_pool(void)
 		return 0;
 
 	kfence_pool = memblock_phys_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
-	if (!kfence_pool)
+	if (!kfence_pool) {
 		pr_err("failed to allocate kfence pool\n");
+		kfence_early_init = false;
+		return 0;
+	}
+
+	/* Temporarily mark as NOMAP. */
+	memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
 
 	return kfence_pool;
 }
 
-#else
-
-static phys_addr_t arm64_kfence_alloc_pool(void)
+static void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp)
 {
-	return 0;
-}
-
-#endif
+	if (!kfence_pool)
+		return;
 
-phys_addr_t early_kfence_pool;
+	/* KFENCE pool needs page-level mapping. */
+	__map_memblock(pgdp, kfence_pool, kfence_pool + KFENCE_POOL_SIZE,
+		       pgprot_tagged(PAGE_KERNEL),
+		       NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
+	memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
+	__kfence_pool = phys_to_virt(kfence_pool);
+}
+#else /* CONFIG_KFENCE */
+static inline phys_addr_t arm64_kfence_alloc_pool(void) { return 0; }
+static inline void arm64_kfence_map_pool(phys_addr_t kfence_pool, pgd_t *pgdp) { }
+#endif /* CONFIG_KFENCE */
 
 static void __init map_mem(pgd_t *pgdp)
 {
@@ -575,6 +584,7 @@ static void __init map_mem(pgd_t *pgdp)
 	phys_addr_t kernel_start = __pa_symbol(_stext);
 	phys_addr_t kernel_end = __pa_symbol(__init_begin);
 	phys_addr_t start, end;
+	phys_addr_t early_kfence_pool;
 	int flags = NO_EXEC_MAPPINGS;
 	u64 i;
 
@@ -588,8 +598,6 @@ static void __init map_mem(pgd_t *pgdp)
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
 	early_kfence_pool = arm64_kfence_alloc_pool();
-	if (early_kfence_pool)
-		memblock_mark_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
 
 	if (can_set_direct_map())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
@@ -656,17 +664,7 @@ static void __init map_mem(pgd_t *pgdp)
 		}
 	}
 #endif
-
-	/* Kfence pool needs page-level mapping */
-	if (early_kfence_pool) {
-		__map_memblock(pgdp, early_kfence_pool,
-			early_kfence_pool + KFENCE_POOL_SIZE,
-			pgprot_tagged(PAGE_KERNEL),
-			NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
-		memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
-		/* kfence_pool really mapped now */
-		kfence_set_pool(early_kfence_pool);
-	}
+	arm64_kfence_map_pool(early_kfence_pool, pgdp);
 }
 
 void mark_rodata_ro(void)
diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
index 7ce5295cc6fb..aa8fd12cc96f 100644
--- a/arch/arm64/mm/pageattr.c
+++ b/arch/arm64/mm/pageattr.c
@@ -7,7 +7,6 @@
 #include <linux/module.h>
 #include <linux/sched.h>
 #include <linux/vmalloc.h>
-#include <linux/kfence.h>
 
 #include <asm/cacheflush.h>
 #include <asm/set_memory.h>
@@ -28,11 +27,10 @@ bool can_set_direct_map(void)
 	 * mapped at page granularity, so that it is possible to
 	 * protect/unprotect single pages.
 	 *
-	 * Kfence pool requires page granularity mapping also if we init it
-	 * late.
+	 * KFENCE pool requires page-granular mapping if initialized late.
 	 */
 	return (rodata_enabled && rodata_full) || debug_pagealloc_enabled() ||
-	    (IS_ENABLED(CONFIG_KFENCE) && !early_kfence_pool);
+	       arm64_kfence_can_set_direct_map();
 }
 
 static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 91cbcc98e293..726857a4b680 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -222,7 +222,6 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 
 #else /* CONFIG_KFENCE */
 
-#define KFENCE_POOL_SIZE 0
 static inline bool is_kfence_address(const void *addr) { return false; }
 static inline void kfence_alloc_pool(void) { }
 static inline void kfence_init(void) { }
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index fab087d39633..e7f22af5e710 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -818,7 +818,7 @@ void __init kfence_alloc_pool(void)
 	if (!kfence_sample_interval)
 		return;
 
-	/* if the pool has already been initialized by arch, skip the below */
+	/* If the pool has already been initialized by arch, skip the below. */
 	if (__kfence_pool)
 		return;
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZBLqOv2RTScbydrj%40elver.google.com.
