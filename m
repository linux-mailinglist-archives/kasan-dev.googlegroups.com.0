Return-Path: <kasan-dev+bncBCAP7WGUVIKBBXWSUOXQMGQEI34YD7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C78187426D
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 23:08:31 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-21f24b80a70sf87786fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 14:08:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709762910; cv=pass;
        d=google.com; s=arc-20160816;
        b=VRbaeKNtHkYXnMYpMxWKWdI4GxMTz2admAUFSrs39JRBK8CLWNKvz42N1raUfYIsFU
         m1iQnb4R/L3ev3IwgJkdf3IQAKYQLv74RIP+1C1i+7OM+XQ0eq3lN8SNC5mbByNAr2qD
         Whm4SFypDYkmmdk8h/L/W8N+QDyE7M8f1p/YNljOUQGLSVRnQ7dWJOztGuCOjiwYsjyv
         Dy+jqp4QbGDFPGpNS4b1IaALxKZ6AHcTDkjTX6suRbTCZaiIpAbJ2UnsAGQGqYV3zxlT
         EcHsw/YjLOhTMoxgYewj2yhbSpG/5Pd3R9uRsb1TdCqMv93UNXQK2kGaQRfaIKLWq4Av
         UHXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=06AB+YmM0aGKCTUx+jq2v1CP3ZeAVdC/ONbnvLNW/4E=;
        fh=4ha5lxEUena09hb1eZ1sOsZG7L7Dhi6t7PozpSs4Aac=;
        b=zwm8BPmiWg1ykze3conlJU/BlDGjdj0zFQbL60b8QPzW2jW+zE+Xjx46eB//F9+Vn6
         rKyILFvERNWwi7uPZrVU9bBS6cFwktQfKbOv3PmDDMwRwdFZZIlf/lTq1t1UsOoHchlF
         qiV3fOp/QJIO3kgBbWj+X7OhUJLq6mSO/ItYM0FuQVPvLBy3MwClC0K6/+XWBaXlQ1Tj
         ZXaWDoslw+PAAwhNg1r87F+jDF9kmBjhtuEjTOTJGypCCXBT9Ok6Xmak7rHtxVKQCXeh
         BpUHH3qQ+H+2hXDw0kYuF8uTMPa0e6B/ITOd8D8D++BdNd5d4WEhQHz1pjF1I0OXBaAC
         kY5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709762910; x=1710367710; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=06AB+YmM0aGKCTUx+jq2v1CP3ZeAVdC/ONbnvLNW/4E=;
        b=myKy4Re9U9ppDcUpeNuCTvSZjn0sB0RiyL/UC9NsDCbby2+PF7MRJcQErAxyY1oU6T
         2JhKTowf1sjj+hkFqAB9lNgt6MHgJiuQ5R2w63tINZDdP8M6JxtMbmWjXI/MTfSbd2Xn
         wWuTTIgGDSSKvhhHmaveHc+uGFse2Uw9mb0inw828eMw8yjBA2dFzwzlgsq/6ppRV+ei
         /vOVtJIHmPFqHn2TQRv14xw1s17yx3qHZ4ZpaShGfu8ca5k14r/vZInNW6Se1R4Aa9Rs
         BDstW1n2QXbkUINcH2Zs11mZc9E1gb3T0XBejwCBsLFYZ/ecF5o3nto+kVusUVaaqSYs
         ooEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709762910; x=1710367710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=06AB+YmM0aGKCTUx+jq2v1CP3ZeAVdC/ONbnvLNW/4E=;
        b=R0gCyVwpqXG1y2sGZAQjMGySN8I5jXYMtNpNUNH9FaM6QKoErQoYpqcZunJfiJnlEf
         kBiiezovUFKeUvyJCPXm7s6mO7WbvrLD7pkVRAitZCRVmB0SQwREQYXO0XzWfkLjrSKx
         qYr+5NESyRLUwB+Z5JdpogcfPjIxIJuoN3HRzj4E7+rlSgPpCU6kNnjmGUFXMZM5kwGh
         oFl1hpidebjs0AeKVhgHy7DhT5ARTr7ZZc+UtZeZF9kJ1IfVmvIfzTEx7TzCejMKnaAx
         /nqS3Gy/ziKpueh+8ZzftTTA/5+5fxLuAEKxMFYHNJOCG4ABUu/neHZ65F777IN8UBKc
         2qyg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3qfpTDRczdRL3sBNQlURsP8foag0xMot6LdfqxSYM7uXM5gwbwT7pT/OP6hYCdQJiu+yfux+zJeb3o/5Iqko/zzSWHhuLsg==
X-Gm-Message-State: AOJu0YwNct47z57WmG4mNLeLVQ6PDEr874jtrJUQ5MJB50wKoj/YjXxh
	Hu+z06lPccI8EoXyr5z8oV/lXCvekG/KiyiBpbU+vw0mqVJsxi3r
X-Google-Smtp-Source: AGHT+IFNByTyKEbtizPBqKcBm7fOWUkXbM7OjGSS4nfbq5sYsSRJez/WFO+x7EoNnjpqzUf0bKTfyQ==
X-Received: by 2002:a05:6871:2895:b0:220:bd1c:6d48 with SMTP id bq21-20020a056871289500b00220bd1c6d48mr6287855oac.49.1709762910266;
        Wed, 06 Mar 2024 14:08:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9723:b0:21f:e033:3f23 with SMTP id
 n35-20020a056870972300b0021fe0333f23ls118022oaq.0.-pod-prod-05-us; Wed, 06
 Mar 2024 14:08:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJDZ70qwvm0/pFsgE9jJtkGD+AxhvwP5X7V2eaL8QANesHni494G7yIChb1+x/3slDjn8JrHznrzyEMqSvODHubvmmxAOQo7Etjw==
X-Received: by 2002:a05:6870:3449:b0:21e:74d8:8f46 with SMTP id i9-20020a056870344900b0021e74d88f46mr6784517oah.21.1709762909475;
        Wed, 06 Mar 2024 14:08:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709762909; cv=none;
        d=google.com; s=arc-20160816;
        b=S7RvfRA6hKA8aGCw6TQC3qgma7agAlNDhTJdDM4fG7t/OOgACaY/3NrM71c7eLA5iM
         mXdxw+LhuQ5euU048fh0vb9urz4o61DCYDZLImZ4XT6xvc+qwp2KzQMGilbA5EmlOQ/t
         kOQrf2b/jhr9IwgZOQ3ZzpPPvLk6/og8Dut7+6ZDNG7YNiEu/UAT0zTPsw8JW1nyrTe/
         Q9BnHUYaWxtCgM4f7O3bMdTuLxcmOP/BrCiiNJlfAmO2bsePgUTk6cZboVqyCw2PCQIG
         kqP5aJ9jR+0hOjSl292/t7TG5J1R9l+u31McxaFR+7Z6dQSJJxvb9hEV+KzudezWpocK
         ZmKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=qDCD8DOmoWKuk/GGAwsKlIOz0h31F4SgvcYw4+sSgdw=;
        fh=86dQ1wFlGZWmBeJ5h03IliWg346iHSwZcPBzee54uWA=;
        b=gIqt3sHyQSHwzlTD/AbzwZ5Zbx9YBqlYXkVl7xVUAWR83adeneoMj4ceO0TDKFvW12
         VLT4ZbrzHLauJRtYjrk2TSfjgvzYF/MlNeuSfEagtx8tHKyeMcYK5Ss7niRdUI3S8DM9
         cNlsHxaGe3wq6vAbxy7VRxFQiusuDCQO2/xkU/xuW4r6VvrnwSYUNFJb6rGwjlunnnZp
         TNN2zLmNKidfNA1adE9zsWAuooPaywx6iNHBfLsxgw9yAGmxqw/tftF+BiDNyGIszuXJ
         RYloKjB60RfI035cA7dZAfSO9v93R0MnNKDU6/bLB5fKRGXKgkSmT/N7hAdCDphIxEN9
         ERcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id gb18-20020a056870671200b0021e848b6f2csi1944522oab.3.2024.03.06.14.08.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Mar 2024 14:08:29 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav119.sakura.ne.jp (fsav119.sakura.ne.jp [27.133.134.246])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 426M8EaB071013;
	Thu, 7 Mar 2024 07:08:14 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav119.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav119.sakura.ne.jp);
 Thu, 07 Mar 2024 07:08:14 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav119.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 426M8DcQ071009
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Thu, 7 Mar 2024 07:08:13 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <9692c93d-1482-4750-a8fc-0ff060028675@I-love.SAKURA.ne.jp>
Date: Thu, 7 Mar 2024 07:08:13 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] x86: disable non-instrumented version of copy_mc when
 KMSAN is enabled
Content-Language: en-US
To: Linus Torvalds <torvalds@linux-foundation.org>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
        the arch/x86 maintainers <x86@kernel.org>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Borislav Petkov <bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        "H. Peter Anvin" <hpa@zytor.com>
References: <3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp>
 <06c11112-db64-40ed-bb96-fa02b590a432@I-love.SAKURA.ne.jp>
 <CAHk-=whGn2hDpHDrgHEzGdicXLZMTgFq8iaH8p+HnZVWj32_VQ@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CAHk-=whGn2hDpHDrgHEzGdicXLZMTgFq8iaH8p+HnZVWj32_VQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

Thank you for explanation.

On 2024/03/06 2:57, Linus Torvalds wrote:
> I think the KMSAN people need to tell us how to tell kmsan that it's a
> memcpy (and about the "I'm going to touch this part of memory", needed
> for the "copy_mv_to_user" side).
> 
> So somebody needs to abstract out that
> 
>         depot_stack_handle_t origin;
> 
>         if (!kmsan_enabled || kmsan_in_runtime())
>                 return;
> 
>         kmsan_enter_runtime();
>         /* Using memmove instead of memcpy doesn't affect correctness. */
>         kmsan_internal_memmove_metadata(dst, (void *)src, n);
>         kmsan_leave_runtime();
> 
>         set_retval_metadata(shadow, origin);
> 
> kind of thing, and expose it as a helper function for "I did something
> that looks like a memory copy", the same way that we currently have
> kmsan_copy_page_meta()

Something like below one? Can we assume that 0 <= ret <= len is always true?

diff --git a/arch/x86/lib/copy_mc.c b/arch/x86/lib/copy_mc.c
index 6e8b7e600def..6858f80fc9a2 100644
--- a/arch/x86/lib/copy_mc.c
+++ b/arch/x86/lib/copy_mc.c
@@ -61,12 +61,18 @@ unsigned long copy_mc_enhanced_fast_string(void *dst, const void *src, unsigned
  */
 unsigned long __must_check copy_mc_to_kernel(void *dst, const void *src, unsigned len)
 {
-	if (copy_mc_fragile_enabled)
-		return copy_mc_fragile(dst, src, len);
-	if (static_cpu_has(X86_FEATURE_ERMS))
-		return copy_mc_enhanced_fast_string(dst, src, len);
-	memcpy(dst, src, len);
-	return 0;
+	unsigned long ret;
+
+	if (copy_mc_fragile_enabled) {
+		ret = copy_mc_fragile(dst, src, len);
+	} else if (static_cpu_has(X86_FEATURE_ERMS)) {
+		ret = copy_mc_enhanced_fast_string(dst, src, len);
+	} else {
+		memcpy(dst, src, len);
+		ret = 0;
+	}
+	kmsan_memmove(dst, src, len - ret);
+	return ret;
 }
 EXPORT_SYMBOL_GPL(copy_mc_to_kernel);
 
@@ -78,15 +84,13 @@ unsigned long __must_check copy_mc_to_user(void __user *dst, const void *src, un
 		__uaccess_begin();
 		ret = copy_mc_fragile((__force void *)dst, src, len);
 		__uaccess_end();
-		return ret;
-	}
-
-	if (static_cpu_has(X86_FEATURE_ERMS)) {
+	} else if (static_cpu_has(X86_FEATURE_ERMS)) {
 		__uaccess_begin();
 		ret = copy_mc_enhanced_fast_string((__force void *)dst, src, len);
 		__uaccess_end();
-		return ret;
+	} else {
+		ret = copy_user_generic((__force void *)dst, src, len);
 	}
-
-	return copy_user_generic((__force void *)dst, src, len);
+	kmsan_copy_to_user(dst, src, len, ret);
+	return ret;
 }
diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index c4cae333deec..4c2a614dab2d 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -61,6 +61,17 @@ void kmsan_check_memory(const void *address, size_t size);
 void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 			size_t left);
 
+/**
+ * kmsan_memmove() - Notify KMSAN about a data copy within kernel.
+ * @to:   destination address in the kernel.
+ * @from: source address in the kernel.
+ * @size: number of bytes to copy.
+ *
+ * Invoked after non-instrumented version (e.g. implemented using assembly
+ * code) of memmove()/memcpy() is called, in order to copy KMSAN's metadata.
+ */
+void kmsan_memmove(void *to, const void *from, size_t size);
+
 #else
 
 static inline void kmsan_poison_memory(const void *address, size_t size,
@@ -77,6 +88,9 @@ static inline void kmsan_copy_to_user(void __user *to, const void *from,
 				      size_t to_copy, size_t left)
 {
 }
+static inline void kmsan_memmove(void *to, const void *from, size_t size)
+{
+}
 
 #endif
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 5d6e2dee5692..364f778ee226 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -285,6 +285,17 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 }
 EXPORT_SYMBOL(kmsan_copy_to_user);
 
+void kmsan_memmove(void *to, const void *from, size_t size)
+{
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	kmsan_enter_runtime();
+	kmsan_internal_memmove_metadata(to, (void *)from, size);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_memmove);
+
 /* Helper function to check an URB. */
 void kmsan_handle_urb(const struct urb *urb, bool is_out)
 {

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9692c93d-1482-4750-a8fc-0ff060028675%40I-love.SAKURA.ne.jp.
