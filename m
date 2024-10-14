Return-Path: <kasan-dev+bncBAABBBNOWK4AMGQELUZUPXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CF9A99BE6F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 05:59:03 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6cbeca2b235sf87321166d6.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 20:59:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728878342; cv=pass;
        d=google.com; s=arc-20240605;
        b=C6N68cI9JqZ/RcOQ7EYDlyvEp6krfBHSDRlZceM6U1K6pNjxK6RvEjRVX3C+t1UEbF
         kUQxBPErt0W/KPrGhr0WxLMW4c3o6s3F7ZP157ts8/kfZFS+vvCMAjRV/Lcx/fTJaGZp
         yMuniYCm/uX6hCLgovmzIi+tmn2lWU8D7q9SCWzrV/+Ssxc4TV2ZvQ459U9b2qwnTf+p
         NddeBXUzv9wgSWAiT8EUIhtsufBem9Mxu6X5H9vmXTSrVOf/9UyjSzUosftFqiGOzrrK
         0RObwHuqw5R/JfDgde2Lgah57Y3yJIKC+/mzWPv8l3kfB5HEVB+9BzdplbULqoTwMFbL
         HJKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IsVZdUVnNdR2VChKHq7IPGCkx3kviL7T2RmTUsV3DPE=;
        fh=t80q85ciKcsySCDevHHg73i/EVQUMOHFoZcdovAEWp4=;
        b=FMS8zW1fdiU7a8TBlyxeqsKbtS5Buy2DRV6UXwvJOqYpmxyZ1CyLx2LvglcGLvzrXy
         fJ3eyCTZ6Mhrcjg7hW+qW6xHXcz3FeuCRp+1YqOQwGu7WhYBjUtaKDrlSs5QFi8ZX5DM
         sJ366uZEv06Z5JtYG5uLCb3F+P//1rdVXUtA4PrDnNTxM+h+08cdT4h4AIsKEVsLEPnw
         1Ne5IsdJhoaQQNJIDYjyiGvJvEI3U/h6SX27NEvVDLU3bh5XYqEdhv3i56BkwlObanZO
         RrRNWPPqNlHcJfsnVS1uNqOgdbR43cgOozB1TysvTJNV3sfaa2Cm52nO6q/MLGiW8BOh
         bGKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728878342; x=1729483142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IsVZdUVnNdR2VChKHq7IPGCkx3kviL7T2RmTUsV3DPE=;
        b=YoAMvLs6eqz+dfpJzTzo9zyeHa0jkY7RJnDVjtNBBSJXqJPJZoRby88T/hqVfqcDDf
         E7guHAeVr+Mb+0qXpon8g2ZT5pVecWp3koll7uweYiBGN+pUfX57Y8rS5PaCPhya8zJC
         mg4pCgOAzM79SzLPIx/mmec0OwaHyNfI4k6l3nCDcRDQAdiReXqjLWDQjb2BrVlgDyuV
         yuPCaqzfAgXxSSrUO3cXfwOlvA1fHmL/W4Wh94tfsEMYpMZIl1V3VfhDNLtVqloKTfRa
         c7oUKIx5+TXniGa1iNdQ//Am4LY3Q7lZcrgssiqupatiAvDBIKu1ut1dSU9SS9JbT2xU
         dkuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728878342; x=1729483142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IsVZdUVnNdR2VChKHq7IPGCkx3kviL7T2RmTUsV3DPE=;
        b=DrcAFC5s8LQXABuGbpLDkEeUF8zlfJn4vzsndJcxdRomNhR2QVh60xBzA+PdCJBRL8
         viBrcBYoObCpxZC4v2Om6SEBdsuQ1IVsUdHitGdmC/3e3LPLK8gg2OM0C5V2qev90/sI
         fPU95j22h/wno3nen5ZS5nw+ENgCzlNvRDe1rLAoh9gk15Bdnr2Y56FcGuahEOaXNN+A
         Q+qcLNIpz2qVJZgT125T4jaPWvA1cc4VVTejV27I140AD6P9S2DDwm4sQNYmC5oE7e/O
         7KiW8OGhY1IZECu83EeUgEcnptcePJHOKsjepH2/w2ZznekO2gsWKUGwWnTqWjvke6zy
         Y2sg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVNcz4DOMgPNUTJoB8hZBSpphycd2ZpBcXTDsFzVtJzQKS5HhbMFRpiKpLdeSOhlGsPMXcxig==@lfdr.de
X-Gm-Message-State: AOJu0YzGbNuJ3U1xr38AF97hlkpRFjQPbuBJ1i2IPyueRGdvBvsVpCV8
	3lLqX/UCuAGN4GjPtZ74tWPF8wlqtiK53tmDHU9097A6OfxAwi7d
X-Google-Smtp-Source: AGHT+IF0u4WKaXbs6AfoVsYlCN+L06MnJYv0Cq3UrOiCeQ2LOVw9+OjiXa7Ea0TfrmIO+E21qpVfQw==
X-Received: by 2002:a05:6214:11ac:b0:6cb:fa3d:dfbe with SMTP id 6a1803df08f44-6cbfa3de0aemr93327286d6.41.1728878341800;
        Sun, 13 Oct 2024 20:59:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:248f:b0:6b7:8ba3:a39a with SMTP id
 6a1803df08f44-6cbe56591f1ls20784426d6.1.-pod-prod-04-us; Sun, 13 Oct 2024
 20:59:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUaUVvVp6quvoJ5q51eDxCXyfxrrJ+pqyGj9a9NmkWvPH9xSK3VNGgOHHVAZKOeaVv6JrBcHlNM358=@googlegroups.com
X-Received: by 2002:a05:6214:568b:b0:6cb:e770:f50b with SMTP id 6a1803df08f44-6cbf9e76302mr99781266d6.33.1728878341264;
        Sun, 13 Oct 2024 20:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728878341; cv=none;
        d=google.com; s=arc-20240605;
        b=klBjewHgxHlFnOZgkmeOXfch7w/hGw2GF27PloZV4YLXgA2ztTrqxi1bpbtwHufwkT
         XFetYjhu3WYuuuHBjmYYu0PDzkY2jT89LWbp8/Q0R1Uwnp5tixw6E/WhthN3ilOuIFVM
         kqTfHZMBVUbLvl03+mZ+alj2as+JJ4duwvI3L7XZPN+2u6cpEmmlMDGOfZE4hybyN2Xc
         3y6kZtwfM2lX6sjtQAmZ1naChjdXXprKqZQNAHorIrVKfJiMBTQ2+74O2pdpnOyDyAix
         OU6nCrkch55E9Az6c3JnPRXvCpcKZP5AQ7b+iHbHPvvGkVgHBHAkmaZpgc0RfS5k2rkB
         HvFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6Iw/wAbEu0SHxzXukkARToGn17qUMEhn7+bxpypLMb0=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=CPi0pFCLzW81JOi+p0MWu9vvBP6+S5x/GGKr7ckz9v0oauVVr+CdcU/27sPGzlpZN7
         AvpaCxZeekgmfP+2ZGGiH0WvH99nkWhZ7hDBOzQLwNFv1tfo7MC78QtlEYNTSBYDS+4l
         Ehdi/ebeYrkbSS/9HjY+YevB8kns++n3inPckqpmJ29bW8IDS5SyIl01vM7MuJqLfR0F
         n+MYHmFIovKORvW2BOduXCq/mkF9J/91Ahx9tzobmo4G6Kk1vQAESP2/vePQjlli2u4R
         31KNHd0F5N6M+e/IG0WsLnJIImuHyAw4WMk8Mh+8q8wTvLgZXGOllRFoJYrwOwAaVh5w
         888g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-6cbe8634125si3198766d6.5.2024.10.13.20.58.59
        for <kasan-dev@googlegroups.com>;
        Sun, 13 Oct 2024 20:59:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8BxEIgBlwxngQIaAA--.37606S3;
	Mon, 14 Oct 2024 11:58:57 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMBxXuT_lgxnc6EoAA--.1717S4;
	Mon, 14 Oct 2024 11:58:57 +0800 (CST)
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
Subject: [PATCH v2 2/3] LoongArch: Add barrier between set_pte and memory access
Date: Mon, 14 Oct 2024 11:58:54 +0800
Message-Id: <20241014035855.1119220-3-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20241014035855.1119220-1-maobibo@loongson.cn>
References: <20241014035855.1119220-1-maobibo@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: qMiowMBxXuT_lgxnc6EoAA--.1717S4
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014035855.1119220-3-maobibo%40loongson.cn.
