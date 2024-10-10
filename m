Return-Path: <kasan-dev+bncBAABBIM6TW4AMGQE2XXYYPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AE99997B7D
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 05:50:59 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e163641feb9sf615298276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 20:50:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728532258; cv=pass;
        d=google.com; s=arc-20240605;
        b=KVWgoSnyN5l07GLYVeQ0UfBno7Kh8GDs8qCD2JTkSFMqvsf+bbJkYWwgghAJjq3+bk
         7awaMWB8DE5geuYbRbBpSmQxd3LuMnOoXx33Z04w5Ql+FfI+GKiORs7VxDqP17Ix2BLZ
         y9wwhpLNFLxXATdcXSsndIvzJdiiOoisZQl5uEO/YjCTYtlq0odr+jC8+ib9zcEiuNZt
         4GX18Q7AYUFkZmqEpkOTELKlE25uFhZte5kq909owSAXKVvoNJGXcmbUbq7Dw/2Ceb7G
         uoJzkvXHsw6ehnfNequEzX7s4MarG0KORywcMfVNisjEzWVeyS1Pmu5eMeTfwMZJvT69
         ycQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4CSe5fiKHL7AqBsB1BDu90zuPXgrB34OlaVj295cr8s=;
        fh=jj0yHsR3AKhh27wh2kY5tO1UuIIOAACpUOrLVGxCvM0=;
        b=TrcsUeGnU4EH9NcmV+3guJMsPhG7Mcw3Z408vXVRylfjrDMrEu4qALm5AKYpP5dymh
         AoK4wbp6a1FsM6ukgvGjsnbIa9TQlqdqYdaXGIXJITvFHQvZS8vMYUYz5l1RxbVJP4j9
         L4no24Uc4DvGOVdToeoEHFzUXHIJIIicOZ3IkWLubtD5/f5wUQ5U+pMKo0cz6jkXaCSO
         swGl1t4GDGugKKktZUzgQDPePPgz8YhBCeZ1Zz0YaZEYXpssVZr+AiUqXUQf5TtnF4zT
         Jh5u8e8BPPG/D12iF0bEKbYuaE16730EDVIqp/bQpP/zM6l2QZePzXuh/AnGTXW9XASn
         ppnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728532258; x=1729137058; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4CSe5fiKHL7AqBsB1BDu90zuPXgrB34OlaVj295cr8s=;
        b=c2fsn2x4YX4fyOaYH95JCW+HmdECoKfG57j5GvjOKS6kGTgiqcnJTA67OQKGphdeQe
         uExTtx+yyKTBVoN6niwEbJ9eByrpBVPOPG2AW0xa/Sk86vMOQt6w3gHsnspYvpYQnkMU
         xOHr5quN7LAZTopqyklMiUiZ0Ij/d+gSbag7j0s37qPaefQ6lJciOzDuIiW2HIMH234u
         fkzN0AxVZlEs6LHe+n3VGnKvfPPHhCIWLIN84m8nOwIabITd9jPa+Pg2hKG0ZkfTp8D3
         i/vRINZT43yk7kBiU+kPT0giYg0TkwzKl1X8dLALdGayDeMbT0U2MOvQG17BlX0uK2ab
         QAaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728532258; x=1729137058;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4CSe5fiKHL7AqBsB1BDu90zuPXgrB34OlaVj295cr8s=;
        b=DO2h2idVi++XP6Bzw+RH9SZSmoHy1cBZFHH5TE3AGKS25SpEYLqLB2FPXc+rOOlMcR
         Ykvcor12akF0RIpjbEsee9xBiAMaSYuhRQQh7ZugPj6UHV8QfjPdftyzocEKVrmZiK84
         1lVfiegkD7BaN0+Xrstv/hCyjxVtPRBUY0FhCRGVEUl398F5D2Dt98F9D14gDqOZPI6H
         vYxCiDq0qikVyZFuQqZIk429N0jT/lKUyvu3ndBhCfWskL9VqLPuj3plr5358Sn7osl1
         pYMHF7cSz/SBUI8DGRqEvVmQOEm1nwMaqCwtot9rK73/4r+0W71bXh+CGYwXfur9kYWi
         ykow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOQcPZFrD4L8GO8abEpbT7di+KEpIVHWjP9JpjZh2v+zQryYo30HAHLO92cUz6KrcDyephgw==@lfdr.de
X-Gm-Message-State: AOJu0YxjPRHflAZMbgfyntdq1DZuY4/C3RXTZB15lFSuzEs7gJaCsEK4
	T9Q3bVbfEjaiAneEnx2nuXCel7ZTkH1K2/oVdTqFLAoH2FvO9hOI
X-Google-Smtp-Source: AGHT+IHrasG9U0tGfS0HWdYvxRnVs+qYynDlndWxoD1LhA5mSFuH7jp1j7fGKqSSB7NIpZx54hm68A==
X-Received: by 2002:a05:6902:220a:b0:e1d:318c:74e8 with SMTP id 3f1490d57ef6-e290b5d252cmr1621845276.2.1728532257962;
        Wed, 09 Oct 2024 20:50:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1887:b0:e1d:a3e8:5b14 with SMTP id
 3f1490d57ef6-e290b83eaa5ls171285276.0.-pod-prod-00-us; Wed, 09 Oct 2024
 20:50:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCwsdCg0cTN2D3Ku3BBkhethbnUZ3aVGLdICm98RoQCKhz99+7rk7PfWcxtquERTDZSyloj5VrNgQ=@googlegroups.com
X-Received: by 2002:a05:690c:7083:b0:6e2:2684:7f62 with SMTP id 00721157ae682-6e32f13a27cmr14457817b3.8.1728532257304;
        Wed, 09 Oct 2024 20:50:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728532257; cv=none;
        d=google.com; s=arc-20240605;
        b=ERR2CTWQ/hILFG+nH+E6jR4BLxRnO231VL05BoEw4aMzTDr9t8S9LMNgnWvNWr7PDA
         m6eLbLBn8kxEqY7bKgRQgMbIcCm0cQXitBGJM3gARRK/OGQQC5886zqjGDE02keoyN1B
         h0/epENR7eIDJz/38qVRqjn8PWi3aEA2AFibBs63Bjbpeby6gsznFtRP0KMC0QpOXIOn
         af39OmMJeWQ9mC2m1HlacM6XBq2uyYHS9ZFIIQ+C5zZylzR60gRxEZEk/+Y0qhTC8VYo
         BT8qOA2ajK2FcAemZAOowusPAvPcBxp+Vi9sjLhP9J7K3U7iS1QU6EMZE7aH+6eduTzW
         973A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6Iw/wAbEu0SHxzXukkARToGn17qUMEhn7+bxpypLMb0=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=KSS6wv6FdUxYPKspw9NaQZ7D/gAX12D3xQ6ielP1C1HMIbZc7xvet9JrvrB73Y6YQf
         XmmwCzs1zudAFt4WmSkVc6BeuwpP0MLxd9Tuc/JLq+LJg3makoRQ2rgKCWWDFVrFJEgC
         itSW7WVtk/NYf3oatO24NIrzQiGxU+jtFYDXKvNssIsNGzkUyvt9WFv0gu3mDeDG5mcJ
         nfakG4aMN9yovNe+cafTXZTm9lPiuNaR244goYc6z3FJGSBkgrcvjNQ/haRIPMHn+3+9
         0jheZVFImKeX52MQFDvTEAkupvB9jY2XPJsdeSBlrIBvPOniLVJryErfLUe4ODBP/4qQ
         saoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 00721157ae682-6e332bde004si307507b3.3.2024.10.09.20.50.55
        for <kasan-dev@googlegroups.com>;
        Wed, 09 Oct 2024 20:50:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8CxrrMbTwdnzrsRAA--.26962S3;
	Thu, 10 Oct 2024 11:50:51 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMDx7tUZTwdnFP8hAA--.52915S5;
	Thu, 10 Oct 2024 11:50:50 +0800 (CST)
From: Bibo Mao <maobibo@loongson.cn>
To: Huacai Chen <chenhuacai@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>,
	Barry Song <baohua@kernel.org>,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 3/4] LoongArch: Add barrier between set_pte and memory access
Date: Thu, 10 Oct 2024 11:50:47 +0800
Message-Id: <20241010035048.3422527-4-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20241010035048.3422527-1-maobibo@loongson.cn>
References: <20241010035048.3422527-1-maobibo@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: qMiowMDx7tUZTwdnFP8hAA--.52915S5
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3UbIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnUUvcSsGvfC2Kfnx
	nUUI43ZEXa7xR_UUUUUUUUU==
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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

It is possible to return a spurious fault if memory is accessed
right after the pte is set. For user address space, pte is set
in kernel space and memory is accessed in user space, there is
long time for synchronization, no barrier needed. However for
kernel address space, it is possible that memory is accessed
right after the pte is set.

Here flush_cache_vmap/flush_cache_vmap_early is used for
synchronization.

Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
 arch/loongarch/include/asm/cacheflush.h | 14 +++++++++++++-
 1 file changed, 13 insertions(+), 1 deletion(-)

diff --git a/arch/loongarch/include/asm/cacheflush.h b/arch/loongarch/include/asm/cacheflush.h
index f8754d08a31a..53be231319ef 100644
--- a/arch/loongarch/include/asm/cacheflush.h
+++ b/arch/loongarch/include/asm/cacheflush.h
@@ -42,12 +42,24 @@ void local_flush_icache_range(unsigned long start, unsigned long end);
 #define flush_cache_dup_mm(mm)				do { } while (0)
 #define flush_cache_range(vma, start, end)		do { } while (0)
 #define flush_cache_page(vma, vmaddr, pfn)		do { } while (0)
-#define flush_cache_vmap(start, end)			do { } while (0)
 #define flush_cache_vunmap(start, end)			do { } while (0)
 #define flush_icache_user_page(vma, page, addr, len)	do { } while (0)
 #define flush_dcache_mmap_lock(mapping)			do { } while (0)
 #define flush_dcache_mmap_unlock(mapping)		do { } while (0)
 
+/*
+ * It is possible for a kernel virtual mapping access to return a spurious
+ * fault if it's accessed right after the pte is set. The page fault handler
+ * does not expect this type of fault. flush_cache_vmap is not exactly the
+ * right place to put this, but it seems to work well enough.
+ */
+static inline void flush_cache_vmap(unsigned long start, unsigned long end)
+{
+	smp_mb();
+}
+#define flush_cache_vmap flush_cache_vmap
+#define flush_cache_vmap_early	flush_cache_vmap
+
 #define cache_op(op, addr)						\
 	__asm__ __volatile__(						\
 	"	cacop	%0, %1					\n"	\
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241010035048.3422527-4-maobibo%40loongson.cn.
