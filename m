Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAW4SO4AMGQEQJVI5VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B5179941E1
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 10:32:05 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-42cb5f6708asf34245485e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 01:32:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728376324; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y2N5/d/USMfjoCq0snOYnjWx3K9QjKJbwcBEEI4bEtartuxaiOXNNc+tibbwMYWHAo
         bAphhsupJTB9IRgllDWSPZdhHgBNDjWL0S6Ad21JmjdZqHvEAKoHzERNJEbaeHGduAd0
         MCZ/2UXWh8+/wOoJxrOGCttYMv0eN0+2Yq7Dm9qA4YaGvokU+2xY1ZWdKOUK0UErlqZz
         hftYH0+3zpMr6v6+BtVgkGlJD1M3XEqoHiJSMPs6J7AuxOoeqik0mRVxL/Hq/p2Fry7q
         KqditwylJSiTKYOYbd1XBvs4v8Zv3JzwRTGBDJN+6lzuQcqinRnCjfgGjS/EwRI3i1GM
         dcgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=UOzfqfiBwKA3T9sLOqYMGKZOc6Grh1GCIR3vpCTGFPU=;
        fh=nlgDWxI5JNM39tW4XnjJZKUsrsPZtGDqYaKDRYmudJM=;
        b=Q9TQKGe1iMvdjrcO1q6C1CMSz+oHVewwwFinMQJi/eBn+Wpm4/8L5Hbod9y51QzdXU
         +wozk8WVio85I8otdlw0PqE3mjDSz7zEeZCO2KbYTLqkYu6b4h25qcYdWJvRfqXt/eBD
         bKNo5jn5znrzvHHMLIPRmWHb9nH+x+n8edJsw0RcCc05pHi5UIUve6AAwC/Upx0aJAKP
         UikQBVoJ5MSuPFxaukFv/YxNdCa2dA7UjIeCFmOo074hlvHGpolU0rVSodVuNYOMNyv9
         oUMqrpk5Zy/Bq6BJ2QEWwQ0ev8ak3+EmnHPGTBoFvQLVueOpK3dH0gereAK9GtDeBYoE
         +3SQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V5BagsnO;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728376324; x=1728981124; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=UOzfqfiBwKA3T9sLOqYMGKZOc6Grh1GCIR3vpCTGFPU=;
        b=A9nNMEQLG80iwxW8zPdcVl8N2an0M1Wq4zzlMDgWEjyLQJC8u09CuI0X0ANPtESogo
         rgScuGAcdQLIIOpaCNtibIb+7iz52UHLN5xAxMD9AL4L6CsXjxEDhpdLxu1w8bmL0Aqu
         oXkuV9VIQp9iiy0vCN3QOykPnwvNjt2RkltfN61idXJonkhWdy1uQSa1qpRaUvSQ60zT
         wV4KTzC+ytBAF0xmGkVnA0r3B6tIB1DX0KeaV/HSBlFO7pfyo4QkuT1R2S8S8qmlAYr1
         Q1M72vE2QBOV/DvveZJ7dn0wHf457t2PqCPaLowGGP86z4moCn+95PYjaz2aEDYei1xT
         tdgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728376324; x=1728981124;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UOzfqfiBwKA3T9sLOqYMGKZOc6Grh1GCIR3vpCTGFPU=;
        b=JfWZDAfUly5S8JrUGmG7Xa5xKoINmXBS0Ug0l0PePm+AxqiCepwdnZ0yyZURrWVFsD
         jpDJSfVzyfBZBp1eB0/5Vzmu3aoNniuAwj6vNBGKzCcnWQtnr3JVR08Pyl1jLsqxuvkx
         D7qsWsdotwnzCf2Yzvw7YAd/YHaCTIn9uZZd/R45TKvT/an03SjyabHwBmelnlZxHaII
         1IITxMUl8fm29KN9oj1kJMCKbdJQ/w9RAtl3+2fkfbXSXX2hygGVqKRn1rjx0Q8aitA6
         inUQdnNU77y+YP3aEqDZfJk/vYmztw6AgrIi7FV3hZ5uqXqkbSuGNik0KxCRLxGZt7c5
         miiQ==
X-Forwarded-Encrypted: i=2; AJvYcCXxLsTkjWBpKFR/RsHzi2o9ffVl3lCfR7n6nvr6qho4bIPdLhngRs0Ldr6XZeBgS7TrPpwMMQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxkte0b1weV6nCw4aJNjJOH3y/VkPrmPvHJiwv2z//Dex2dm2Ut
	1SZG98k34Z5V0G/8scG3NUgb1NTy4j04G0LCb1f0LgHdDMHre6iN
X-Google-Smtp-Source: AGHT+IETpuz34W5nNPWV8YUURqBmyi7KdrKFHFQdRutHDw7iN8/zwMutOuL3Bmzm2XUknfWrxml+XQ==
X-Received: by 2002:a05:600c:35c6:b0:428:36e:be59 with SMTP id 5b1f17b1804b1-42f85ab47afmr97620235e9.11.1728376323155;
        Tue, 08 Oct 2024 01:32:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3553:b0:42c:af5b:fabd with SMTP id
 5b1f17b1804b1-42f8dcc54aals12959465e9.1.-pod-prod-06-eu; Tue, 08 Oct 2024
 01:32:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKW7l1+eZMYgLxv82dM9wQtTIuAu3NGpMdIFLur2I8ro5h7mjs+/D+at+RyNdRSbkBNBd6cqw1Ob0=@googlegroups.com
X-Received: by 2002:a05:600c:45c6:b0:426:51dc:f6cd with SMTP id 5b1f17b1804b1-42f85abebdcmr95234455e9.18.1728376320971;
        Tue, 08 Oct 2024 01:32:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728376320; cv=none;
        d=google.com; s=arc-20240605;
        b=OatZlWK6AXal8HAqavFE3Z/Wh+dT6FB+fOFXp4VNK4wYZfx6sCsYtwTwxlwwDEOhhR
         YOBjcrpn3ow97M9MTNeJ95dzFaHCACgRwONnOkuilq9CNC9/SrFSBGUvRmeiK7tTGIxx
         KHh1bUf0wGHVlZnpjuGGdFrgE6cID0N3QCzAcChZmgv1JD18TjO/jU4s46RZV5UmlI57
         JKbUttSGEQatIi2NbZzWyu37PrpQJVQ1TUfxQi+2cIACeetX3x8haYi/UcdLgbrzVZdT
         or4PwsYbnu80ruC8FAPsoHfeBTBbT2l3hTr0c8xBqAAtm7GycKBvoGz9Fmrh4WmX3Jqq
         3tZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=mu+DR2ol7NHxdHwZDLwzTYqI016h/oGfPfj/9x7pI30=;
        fh=H2O9hu7Za8gTPIvrqc2QMe0VDWIsjHdiz2WpZQjD6Hg=;
        b=lJWigWrZ3AgdAuZlreo1z36scUeRvY3LPQ9dDSlPekhh+sIF8hD4ROTQfT+Jci2/Oa
         AdMLQ7QkyEkd1pg+GPfDbWBbOAHh+vJx9DluQY5tujVUqxPVwl7MHqLwJkqpZSRbyb88
         T2GYrupfAn+SS1rYAs17d8dDoQUm5/NPHW20b+uNOwtDvoneD34vXgGwJpSawLPJJdMt
         pRF3lTI7eD8SZYNjMFnFTczQag5LYEC+bXJO1SjPGEFxu+QLheKlQzALdJ226Ycwkjfi
         pVs6Hljz6aIjwq2wQOwuBYhSggeIp6YAj3I2vxmNEnKfN19iGGGl9u4YOzukppcxyNrN
         I4Ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V5BagsnO;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4304ecf2d7esi248555e9.1.2024.10.08.01.32.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 01:32:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-5398a26b64fso5196338e87.3
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 01:32:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVu8+VZNiAyipvH3cZ5byURU2wuXxnaWcxHcKJAannLxnu0JzEYqfS7JB0JQj0pfZ+a/xm8W/4Ncos=@googlegroups.com
X-Received: by 2002:a05:6512:104b:b0:536:a5ee:ac01 with SMTP id 2adb3069b0e04-539ab86288amr6724752e87.4.1728376319850;
        Tue, 08 Oct 2024 01:31:59 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:c862:2d9d:4fdd:3ea5])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42f86b4acddsm118748205e9.44.2024.10.08.01.31.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Oct 2024 01:31:59 -0700 (PDT)
Date: Tue, 8 Oct 2024 10:31:53 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, bpf@vger.kernel.org,
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com,
	vincenzo.frascino@arm.com
Subject: Re: [PATCH v2 1/1] mm, kasan, kmsan: copy_from/to_kernel_nofault
Message-ID: <ZwTt-Sq5bsovQI5X@elver.google.com>
References: <CANpmjNOZ4N5mhqWGvEU9zGBxj+jqhG3Q_eM1AbHp0cbSF=HqFw@mail.gmail.com>
 <20241005164813.2475778-1-snovitoll@gmail.com>
 <20241005164813.2475778-2-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241005164813.2475778-2-snovitoll@gmail.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=V5BagsnO;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::132 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Sat, Oct 05, 2024 at 09:48PM +0500, Sabyrzhan Tasbolatov wrote:
> Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kernel
> memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> the memory corruption.
> 
> syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> KASAN report via kasan_check_range() which is not the expected behaviour
> as copy_from_kernel_nofault() is meant to be a non-faulting helper.
> 
> Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> copy_from_kernel_nofault() with KMSAN detection of copying uninitilaized
> kernel memory. In copy_to_kernel_nofault() we can retain
> instrument_write() for the memory corruption instrumentation but before
> pagefault_disable().

I don't understand why it has to be before the whole copy i.e. before
pagefault_disable()?

I think my suggestion was to only check the memory where no fault
occurred. See below.

> diff --git a/mm/maccess.c b/mm/maccess.c
> index 518a25667323..a91a39a56cfd 100644
> --- a/mm/maccess.c
> +++ b/mm/maccess.c
> @@ -15,7 +15,7 @@ bool __weak copy_from_kernel_nofault_allowed(const void *unsafe_src,
>  
>  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)	\
>  	while (len >= sizeof(type)) {					\
> -		__get_kernel_nofault(dst, src, type, err_label);		\
> +		__get_kernel_nofault(dst, src, type, err_label);	\
>  		dst += sizeof(type);					\
>  		src += sizeof(type);					\
>  		len -= sizeof(type);					\
> @@ -31,6 +31,8 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
>  	if (!copy_from_kernel_nofault_allowed(src, size))
>  		return -ERANGE;
>  
> +	/* Make sure uninitialized kernel memory isn't copied. */
> +	kmsan_check_memory(src, size);
>  	pagefault_disable();
>  	if (!(align & 7))
>  		copy_from_kernel_nofault_loop(dst, src, size, u64, Efault);
> @@ -49,7 +51,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
>  
>  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)	\
>  	while (len >= sizeof(type)) {					\
> -		__put_kernel_nofault(dst, src, type, err_label);		\
> +		__put_kernel_nofault(dst, src, type, err_label);	\
>  		dst += sizeof(type);					\
>  		src += sizeof(type);					\
>  		len -= sizeof(type);					\
> @@ -62,6 +64,7 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
>  	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
>  		align = (unsigned long)dst | (unsigned long)src;
>  
> +	instrument_write(dst, size);
>  	pagefault_disable();

So this will check the whole range before the access. But if the copy
aborts because of a fault, then we may still end up with false
positives.

Why not something like the below - normally we check the accesses
before, but these are debug kernels anyway, so I see no harm in making
an exception in this case and checking the memory if there was no fault
i.e. it didn't jump to err_label yet. It's also slower because of
repeated calls, but these helpers aren't frequently used.

The alternative is to do the sanitizer check after the entire copy if we
know there was no fault at all. But that may still hide real bugs if
e.g. it starts copying some partial memory and then accesses an
unfaulted page.


diff --git a/mm/maccess.c b/mm/maccess.c
index a91a39a56cfd..3ca55ec63a6a 100644
--- a/mm/maccess.c
+++ b/mm/maccess.c
@@ -13,9 +13,14 @@ bool __weak copy_from_kernel_nofault_allowed(const void *unsafe_src,
 	return true;
 }
 
+/*
+ * The below only uses kmsan_check_memory() to ensure uninitialized kernel
+ * memory isn't leaked.
+ */
 #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)	\
 	while (len >= sizeof(type)) {					\
 		__get_kernel_nofault(dst, src, type, err_label);	\
+		kmsan_check_memory(src, sizeof(type));			\
 		dst += sizeof(type);					\
 		src += sizeof(type);					\
 		len -= sizeof(type);					\
@@ -31,8 +36,6 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
 	if (!copy_from_kernel_nofault_allowed(src, size))
 		return -ERANGE;
 
-	/* Make sure uninitialized kernel memory isn't copied. */
-	kmsan_check_memory(src, size);
 	pagefault_disable();
 	if (!(align & 7))
 		copy_from_kernel_nofault_loop(dst, src, size, u64, Efault);
@@ -52,6 +55,7 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
 #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)	\
 	while (len >= sizeof(type)) {					\
 		__put_kernel_nofault(dst, src, type, err_label);	\
+		instrument_write(dst, sizeof(type));			\
 		dst += sizeof(type);					\
 		src += sizeof(type);					\
 		len -= sizeof(type);					\
@@ -64,7 +68,6 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
 	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
 		align = (unsigned long)dst | (unsigned long)src;
 
-	instrument_write(dst, size);
 	pagefault_disable();
 	if (!(align & 7))
 		copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZwTt-Sq5bsovQI5X%40elver.google.com.
