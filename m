Return-Path: <kasan-dev+bncBD55D5XYUAJBBANZUSWQMGQE5TZ4BWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CDC383194D
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 13:41:39 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2902deeb0cbsf361679a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 04:41:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705581698; cv=pass;
        d=google.com; s=arc-20160816;
        b=PDqIO4J+MvapVhVsa8AQ4wSkbZFaCPJ3mKL0+aE0zacZ46lkFj1jzbAE6xkTdBT/3V
         pM5CThPTNegegygWHCsqsvGXw48yjQhLEG0MXnAva+CoYgtcEv/M/oscArzDCAZ7Gsou
         51llJzJNBGliLtZGBWakZNrt8pvQ5pZR3se4EQWpvqlLn1IXaPeo6MAXYwG/hZheGnLl
         rcWWvbImKMwS2atj0fZhctDRsZXOGdNNkwEJHHtg3GlTvpFOjwpcNT3LlPZa9iySYn94
         SQ8AEY5p7EbQC3bdrdF2hwLwJvyb3EL4XlqhGH5YJ7cgkz4Qcn8q1m8imuFgOW8DFZGK
         7Iog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=a03ri2ZMCgKg/4tHZpmIY04FgaAgk0CrGH+Xw+h/teE=;
        fh=4PS0TUR1kckMCap9/Z2+yRxeTQGnq78XsODFWEbTt8k=;
        b=fp9fVc14iKVhZ3memvIvgfpZ7beiCaH1V3OilaTRTZNbh4rxvhousLgxDjwf1wiMJZ
         lfx4OOo7ZjYJohpDKLn56PrzC9gE+T4xQn+AZ3vN4MWj7SGQn9fDjVa/BAcWb3AUmctu
         QbUnwcmIo0UjzA8IytDxFQ09B4CfjdJDxGlTm7VOszIw75UJbtxqk7rqOQ6eWQm2rRh+
         s+g2goai3M6aJskv9SY0HjkkirFb1ciLUtLs4hKzrUZl+/iKkTdUzSQCorkXl9jk1Bqn
         ljaFQpRmsMLIdACJgRk6IVKkiOHg2UPFtQ2oZiE4BlgK0u4CVtSRAyBMrrmTpnM33RkJ
         7MQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=IO8dW3gq;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705581698; x=1706186498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=a03ri2ZMCgKg/4tHZpmIY04FgaAgk0CrGH+Xw+h/teE=;
        b=DcwtRHc1HhUiC2Wstv6mQXh3CZdANSi02jmgb/NHun/AYdGinrTMpC7W4FDt98vTcC
         iOM5hrVKUVxflWo8sDOIxbdOSGsG9guzT5rERtnX1gOTJWXXNfPb/uyNyIgbJnyAiYX2
         9iXtbehgdmVEE4x6i+S8/GWoHcjGNgSfLhVdRhqKeyll9qBcsDw5QbpV9r07D4V/RFQk
         F6+FSpXCsjRlfLTlPFPfqbaH8GBBb76SAuT20C22mtDb3Ayh86KJ9vbvK62rUeXWO1A1
         H8kwWVREVrb4LCI5xLBBq2YHBLaz8WvFCsqSeF7+M/d9wc7RcYvmBvBdNOPLgBZX3XQn
         hLwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705581698; x=1706186498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a03ri2ZMCgKg/4tHZpmIY04FgaAgk0CrGH+Xw+h/teE=;
        b=Zh4qCYrJXL+5ON/mL9IivSPan/jA+rygsFQWF0rFgFuDemRV02Zr8AvcspSL4tv32u
         ZsL/u5MvKo6x169D+F6FCBA1PAyhPASn6et3iAKgkQWl6eUAjpT1Zjht7OC5piLDA18X
         QRAIAfMdXIGuw1J7Vy2sFlaB9vD63qd7feOBpQFLD7BB0ayX7tFyKGHfIspuQACSMixt
         mqybTr8+oUbNKSMxWLMOXocj5WWJ4yThRLAQ0md0M0YcJdyaBDZlLG94gmSksqYSyd2O
         ggHzQSd2sCknH8CoHq2T1OF+Mcbm6VMR+BaWyOn3bzVVXwdXHNknHlH9w8fumk4hVnJC
         YgvQ==
X-Gm-Message-State: AOJu0Yz0J8IoANEqKB8i46UyQ5MkrgEmvww95rno1l9xQMhVuYfjbXXe
	GpdySf+g8i3dqyN8AIhIoBpI5b1b5enISWRvlKP3rkqA+3RMIj5E
X-Google-Smtp-Source: AGHT+IG3PQP7K6SNzfKQD04GPRZuIlpjTs/yK4ubuCFU74ofJejt3ISYnKoJZkooq3UQrLYaGFfcJg==
X-Received: by 2002:a17:90a:9748:b0:28c:bd2c:b3b7 with SMTP id i8-20020a17090a974800b0028cbd2cb3b7mr662817pjw.54.1705581697807;
        Thu, 18 Jan 2024 04:41:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7545:b0:28c:e978:2417 with SMTP id
 q63-20020a17090a754500b0028ce9782417ls451486pjk.2.-pod-prod-08-us; Thu, 18
 Jan 2024 04:41:36 -0800 (PST)
X-Received: by 2002:a05:6a21:7897:b0:199:e237:1497 with SMTP id bf23-20020a056a21789700b00199e2371497mr827011pzc.65.1705581696083;
        Thu, 18 Jan 2024 04:41:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705581696; cv=none;
        d=google.com; s=arc-20160816;
        b=D+M5wO30axhQ160KitZX4Q+hUxskdVzbh9s3hLFn3q2MBAz50Zp6VHV3c0n0uSNqhq
         nfXw+DHV4huAvnjtyaewul3mOHdakrQrsTxa2/PRrkDe5oE+ml04d28/+7ySjtzzt17O
         XTQYgbIIHlnw+gEUrYzv4Io7PaU8wsbm3l6ag3t0ph1+HaD/ENeHbiic8o43ub53dNKc
         LO92UDwmteQ2axcep+yZPbeubW/1we2ZzdmBKgQSh3iQnWXBI75ir3Q9EvpxrQnU/57I
         tm17cGC48+XU7bDiJ5jzdme1FX5w4Djfm0ovDDqpPFoV5wZlNuses2D7HUJPR9EkVXwr
         AeWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/7QhB8TKXSng5TkzJ8qXu0ZMAf7utNsR4jcyGuAQsHs=;
        fh=4PS0TUR1kckMCap9/Z2+yRxeTQGnq78XsODFWEbTt8k=;
        b=pOrnep+OoexinwRvAOYtem+bhopQ8Z40a0MwUONBB3qFWuHpsoxdF1lclzbzx8eIUI
         16rlLPtjDDDXXgMrXPXSTKMuLCbzBg7xiI4TCteSXoaAOrWXOGY39OGP5RBicc3VBOui
         weQNUipEeC4nlMShqIIVW+SRYVeCrTAZ3NrhNbyfRtnWqHqAUPTODuv6UFN+IAoPnRMr
         +Sf5Our3AiuVMT5vHIoJL+T/5Iy4Nvx06aA1Xglxc9Ve0Tp802xA/RDMmsO4zi0ShD6I
         R//Hl9U9yiMkOl6lGyy0Mw8w3PlAv7+2KtlwmiHEgbE7eselHcOypiJXp6qBwF/Vnn3B
         SB4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=IO8dW3gq;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id w12-20020a17090aea0c00b0028e7ada84f5si132796pjy.1.2024.01.18.04.41.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 04:41:36 -0800 (PST)
Received-SPF: pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-6d9af1f12d5so10441866b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 04:41:36 -0800 (PST)
X-Received: by 2002:a05:6a00:93a6:b0:6db:883a:ffc0 with SMTP id ka38-20020a056a0093a600b006db883affc0mr893007pfb.12.1705581695652;
        Thu, 18 Jan 2024 04:41:35 -0800 (PST)
Received: from GQ6QX3JCW2.bytedance.net ([203.208.189.13])
        by smtp.gmail.com with ESMTPSA id y17-20020a056a00191100b006d977f70cd5sm3199744pfi.23.2024.01.18.04.41.31
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Thu, 18 Jan 2024 04:41:35 -0800 (PST)
From: "lizhe.67 via kasan-dev" <kasan-dev@googlegroups.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	lizefan.x@bytedance.com,
	lizhe.67@bytedance.com
Subject: [RFC 2/2] kasan: add mem track interface and its test cases
Date: Thu, 18 Jan 2024 20:41:09 +0800
Message-ID: <20240118124109.37324-3-lizhe.67@bytedance.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20240118124109.37324-1-lizhe.67@bytedance.com>
References: <20240118124109.37324-1-lizhe.67@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: lizhe.67@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=IO8dW3gq;       spf=pass
 (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: lizhe.67@bytedance.com
Reply-To: lizhe.67@bytedance.com
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

From: Li Zhe <lizhe.67@bytedance.com>

kasan_track_memory() and kasan_untrack_memory() are two interfaces
used to track memory write operations. We can use them to locate
problems where memory has been accidentally rewritten. Examples of
interface usages are shown in kasan_test_module.c

Signed-off-by: Li Zhe <lizhe.67@bytedance.com>
---
 include/linux/kasan.h        |   5 ++
 mm/kasan/generic.c           | 161 +++++++++++++++++++++++++++++++++++
 mm/kasan/kasan_test_module.c |  26 ++++++
 3 files changed, 192 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index dbb06d789e74..ca5d93629ccf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -604,4 +604,9 @@ void kasan_non_canonical_hook(unsigned long addr);
 static inline void kasan_non_canonical_hook(unsigned long addr) { }
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#ifdef CONFIG_KASAN_MEM_TRACK
+int kasan_track_memory(const void *addr, size_t size);
+int kasan_untrack_memory(const void *addr, size_t size);
+#endif
+
 #endif /* LINUX_KASAN_H */
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index a204ddcbaa3f..61f3f5125338 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -402,6 +402,167 @@ static __always_inline bool memory_is_tracked(const void *addr, size_t size)
 
 	return memory_is_tracked_n(addr, size);
 }
+
+/* deal with addr do not cross 8(shadow size)-byte boundary */
+static void __kasan_track_memory(const void *shadow_addr, size_t offset, size_t size)
+{
+	s8 mask;
+
+	if ((offset & 0x01) || (size & 0x01))
+		mask = kasan_track_mask_odd(size);
+	else
+		mask = kasan_track_mask_even(size);
+	offset = offset >> 1;
+	*(s8 *)shadow_addr |= mask << (KASAN_TRACK_VALUE_OFFSET + offset);
+}
+
+static void _kasan_track_memory(const void *addr, size_t size)
+{
+	unsigned int words;
+	const void *start = kasan_mem_to_shadow(addr);
+	unsigned int prefix = (unsigned long)addr % 8;
+
+	if (prefix) {
+		unsigned int tmp_size = (unsigned int)size;
+
+		tmp_size = min(8 - prefix, tmp_size);
+		__kasan_track_memory(start, prefix, tmp_size);
+		start++;
+		size -= tmp_size;
+	}
+
+	words = size / 8;
+	while (words) {
+		__kasan_track_memory(start, 0, 8);
+		start++;
+		words--;
+	}
+
+	if (size % 8)
+		__kasan_track_memory(start, 0, size % 8);
+}
+
+static inline bool is_cpu_entry_area_addr(unsigned long addr)
+{
+	return ((addr >= CPU_ENTRY_AREA_BASE) &&
+		(addr < CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE));
+}
+
+static inline bool is_kernel_text_data(unsigned long addr)
+{
+	return ((addr >= (unsigned long)_stext) && (addr < (unsigned long)_end));
+}
+
+static bool can_track(unsigned long addr)
+{
+	if (!virt_addr_valid(addr) &&
+		!is_module_address(addr) &&
+#ifdef CONFIG_KASAN_VMALLOC
+		!is_vmalloc_addr((const void *)addr) &&
+#endif
+		!is_cpu_entry_area_addr(addr) &&
+		!is_kernel_text_data(addr)
+	)
+		return false;
+
+	return true;
+}
+
+int kasan_track_memory(const void *addr, size_t size)
+{
+	if (!kasan_arch_is_ready())
+		return -EINVAL;
+
+	if (unlikely(size == 0))
+		return -EINVAL;
+
+	if (unlikely(addr + size < addr))
+		return -EINVAL;
+
+	if (unlikely(!addr_has_metadata(addr)))
+		return -EINVAL;
+
+	if (likely(memory_is_poisoned(addr, size)))
+		return -EINVAL;
+
+	if (!can_track((unsigned long)addr))
+		return -EINVAL;
+
+	_kasan_track_memory(addr, size);
+	return 0;
+}
+EXPORT_SYMBOL(kasan_track_memory);
+
+/* deal with addr do not cross 8(shadow size)-byte boundary */
+static void __kasan_untrack_memory(const void *shadow_addr, size_t offset, size_t size)
+{
+	s8 mask;
+
+	if (size % 0x01) {
+		offset = (offset - 1) >> 1;
+		mask = kasan_track_mask_odd(size);
+		/*
+		 * SIZE is odd, which means we may clear someone else's tracking flags of
+		 * nearby tracked memory.
+		 */
+		pr_info("It's possible to clear someone else's tracking flags\n");
+	} else {
+		offset = offset >> 1;
+		mask = kasan_track_mask_even(size);
+	}
+	*(s8 *)shadow_addr &= ~(mask << (KASAN_TRACK_VALUE_OFFSET + offset));
+}
+
+static void _kasan_untrack_memory(const void *addr, size_t size)
+{
+	unsigned int words;
+	const void *start = kasan_mem_to_shadow(addr);
+	unsigned int prefix = (unsigned long)addr % 8;
+
+	if (prefix) {
+		unsigned int tmp_size = (unsigned int)size;
+
+		tmp_size = min(8 - prefix, tmp_size);
+		__kasan_untrack_memory(start, prefix, tmp_size);
+		start++;
+		size -= tmp_size;
+	}
+
+	words = size / 8;
+	while (words) {
+		__kasan_untrack_memory(start, 0, 8);
+		start++;
+		words--;
+	}
+
+	if (size % 8)
+		__kasan_untrack_memory(start, 0, size % 8);
+}
+
+int kasan_untrack_memory(const void *addr, size_t size)
+{
+	if (!kasan_arch_is_ready())
+		return -EINVAL;
+
+	if (unlikely(size == 0))
+		return -EINVAL;
+
+	if (unlikely(addr + size < addr))
+		return -EINVAL;
+
+	if (unlikely(!addr_has_metadata(addr)))
+		return -EINVAL;
+
+	if (likely(memory_is_poisoned(addr, size)))
+		return -EINVAL;
+
+	if (!can_track((unsigned long)addr))
+		return -EINVAL;
+
+	_kasan_untrack_memory(addr, size);
+	return 0;
+}
+EXPORT_SYMBOL(kasan_untrack_memory);
 #endif
 
 static __always_inline bool check_region_inline(const void *addr,
diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
index 8b7b3ea2c74e..1dba44dbfc81 100644
--- a/mm/kasan/kasan_test_module.c
+++ b/mm/kasan/kasan_test_module.c
@@ -62,6 +62,31 @@ static noinline void __init copy_user_test(void)
 	kfree(kmem);
 }
 
+#ifdef CONFIG_KASAN_MEM_TRACK
+static noinline void __init mem_track_test(void)
+{
+	int ret;
+	int *ptr = kmalloc(sizeof(int), GFP_KERNEL);
+
+	if (!ptr)
+		return;
+
+	ret = kasan_track_memory(ptr, sizeof(int));
+	if (ret) {
+		pr_warn("There is a bug of mem_track\n");
+		goto out;
+	}
+	pr_info("trigger mem_track\n");
+	WRITE_ONCE(*ptr, 1);
+	kasan_untrack_memory(ptr, sizeof(int));
+
+out:
+	kfree(ptr);
+}
+#else
+static inline void __init mem_track_test(void) {}
+#endif
+
 static int __init test_kasan_module_init(void)
 {
 	/*
@@ -72,6 +97,7 @@ static int __init test_kasan_module_init(void)
 	bool multishot = kasan_save_enable_multi_shot();
 
 	copy_user_test();
+	mem_track_test();
 
 	kasan_restore_multi_shot(multishot);
 	return -EAGAIN;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240118124109.37324-3-lizhe.67%40bytedance.com.
