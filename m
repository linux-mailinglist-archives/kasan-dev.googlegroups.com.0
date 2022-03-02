Return-Path: <kasan-dev+bncBAABBZF272IAMGQENV7P5UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id A96664CAA7E
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:37:56 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id m12-20020a056402510c00b00413298c3c42sf1289740edd.15
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:37:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239076; cv=pass;
        d=google.com; s=arc-20160816;
        b=AkbJulVY03O5tUQaRoW38KIKCKFHQJXwxg4Uw59Zj2pX6kjVvDWnMTxLhU7bgAsKZS
         HKVgbM2q6YJEzObdtbnuYD7Zbz8MAJ0V0Qzid1+IImqLCFRpu3Rf8egfJpK96zU6TZvh
         7x+oAlazfTOaHJY4FJ9LTk8mlWPjBC1aCFNelXzrsT1IqHVK4q1XW7WYaTV+H0NI1Jjj
         4ZXvkxc12OMVyGwa0lFcR2mhZGlCZlRcFR3uVLtGWm9WC1HpQDgPhMOfFZYRjOi0oCtt
         7ifR2W4joV1xY3vVB4vUT2A41VGx9SkKfvLdAaUdA1NHaykKwz+EQbbn9HKpPlTsx/pq
         xHDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KosZ1uT8IHVAAFRREVp73TbRU/jGSvFyog7ZjR0ZYMQ=;
        b=IPWwExGsHpQwcGZ/yw/aQ6RI/PT+oYa7vTsahIPWve4jtbcOGiA+dgPOEMs/5Z5qkj
         WovyjadtGPvTXnCsDCxwT8pcjnWsI1bcLhzDGFWU0vLc9I7+sosc9I9VGB3EUH5J6Cp4
         4+0+oQ4pHI63Ccq+HsxqIQlgp0+Gu+6pBq7tMaoBLsvKMRQkpqy1QWCRm13+59fGSWGv
         Sgct3SuoA0jS0Ff6FE8IysP7YZ01r8v23dVSLxP9MzeYruCCpuL6/1IZ6HOrO0Te31Ik
         QTdxoj6KPwaHdmOXu7FSZ3AB7VsQqTRS/13KI0gCCYE0o9Ok0/skWxky/825S8bP8Sco
         GKkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NANHGuVo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KosZ1uT8IHVAAFRREVp73TbRU/jGSvFyog7ZjR0ZYMQ=;
        b=NH0kAI0NlyUhu0FZCZbvW0GqpOwlDYGHuqSDGgkhbijDdv7fHaLkKaWRRU0YdnjavG
         zu1ICKkmwzF6cPBDcP/Zae7n2GXYYg4572r9qSiAShgvtQgDiayI3dXAO+nzHYTvQ4q8
         yRttjhL/quLbddIao2olY2cg5oS6F/sLpda2fMOmd4337KtCyofzm+RivcQ/e8JR59wR
         9c/2i5kL4Bvzsp7Xqto1yCdOgoHalRWd5DmKAc1f8IxxM07hjAVyFFdAdUcGk857nDlB
         /SFF71Dkh1OvTjTk6E5z9L8PS9Ug+fjMbkh9NqG6GuxEwqQGBuEnevuaWCpqffk68esg
         4KpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KosZ1uT8IHVAAFRREVp73TbRU/jGSvFyog7ZjR0ZYMQ=;
        b=YzDGBh1SzJbyNsIpWCH8T6+Qz6S/ZQ3rPkh2Wi/NHEMJdNuJMI/m8E+ao5x1X6IvsN
         MWscCIHjpd/nlgxERC2nakHSPHRInqGY/iI82GMIX4BtSOBS+Fw6B0wufk15y8kr9ZNU
         O7DACEXS2sgr38RmX2z0uVTSk3+rdzwNw9lqhjn2cSTFw5n2bMZGQE/yzqbbja0SUW0G
         Sv9P7s4pUtFekHvk6BgX5joaPE/YoQVXD13lRQ8589ALInvBLuqU1xUhNf3UmbmkGXy/
         /b9sJNU6gs6y4nBT6tDDxymVUp0dZHVka4gdEdPIKTQzw2m0l1M+5Z2u0toc45gEJ9SA
         Q9/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CVuAFib8njmoi0qcnmHtpyVUg8qhDFiyY3gaJdmO4zqMIgfUh
	8iYeS92uo/MjCh8nvXcbZfQ=
X-Google-Smtp-Source: ABdhPJwryvHIzP8mJSy4zVaHOOtOQ9s5/pi9Nx+zYrGZWnVBT1NDr3J9LqnGy7cykVZJV0WetsNWiQ==
X-Received: by 2002:a17:906:4987:b0:6ce:88fc:3c88 with SMTP id p7-20020a170906498700b006ce88fc3c88mr22639351eju.608.1646239076407;
        Wed, 02 Mar 2022 08:37:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:75fa:b0:6cb:c540:501 with SMTP id
 jz26-20020a17090775fa00b006cbc5400501ls2891865ejc.11.gmail; Wed, 02 Mar 2022
 08:37:55 -0800 (PST)
X-Received: by 2002:a17:906:130a:b0:6b7:5e48:350a with SMTP id w10-20020a170906130a00b006b75e48350amr23305955ejb.184.1646239075657;
        Wed, 02 Mar 2022 08:37:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239075; cv=none;
        d=google.com; s=arc-20160816;
        b=E4ZQo+jiG2UfadhCVFG39/r8bPnuYEL9lcSEpkm1L0Lhn3/P8tNQbsnGXIQuTE9VRo
         hvQV8A32WdoE4BjwxanAYfYjyeHLakg8wpREH1SJGMQneabqd+ty2CENn7yus83XhVB9
         Mq7pnRmgoBUON+g6AyVDw8EYojx+1q+7Yn1Na4fAItb70pzZmBK/Cz49TJw+tKbOXHCi
         ZgoyAwz9aHuVZiyhY3tcNQfoxW+1MCRoALErJvqr07VQh+ehnRiImiY5uWDkRA8D2Cdq
         veoZAh3ch0NMEHhcugwLVhyHR5OlsZ7eNMtVRhTE9+tNvMb4hzdbz01wDNQV+pau4SL+
         6t3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IRHB3LUc8++0z9iu+FYKeD7NJQddTec6mZHPvLpKAps=;
        b=AYlK9hUdOLwmhJcSc5RuCdHruNd4i33A8Cobincgd8zs7k8Hisiisu3ZrZita1tvvq
         WJsXcDkAPTEZ51GMAxR6qus6DL3usxZqk2/KvZJalBjDBTkFyRGIbFWNMjDDvil+2xsP
         3uAzjilZL2754FjACwTsgsXfVBfbo/3lhi9qTzJWf4Gh/CE94S1ufCJx8aA5UB4lDtFu
         ZqqFLzTS5oKv0T+vf3Ds2HIjpwtWx7vcho75UfjW+ZbtI9J+C9TTLvhs//IZdzcmZJHe
         DriDh1IfFbSvsqRO3Owt0Ge8V2599ehDVZsgOLfdGWE8wuPaT+PaYooetUr4V3j7LA/d
         DV+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NANHGuVo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id a15-20020aa7d90f000000b00412982a1c3dsi1138032edr.1.2022.03.02.08.37.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:37:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 11/22] kasan: split out print_report from __kasan_report
Date: Wed,  2 Mar 2022 17:36:31 +0100
Message-Id: <9be3ed99dd24b9c4e1c4a848b69a0c6ecefd845e.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NANHGuVo;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Split out the part of __kasan_report() that prints things into
print_report(). One of the subsequent patches makes another error
handler use print_report() as well.

Includes lower-level changes:

- Allow addr_has_metadata() accepting a tagged address.
- Drop the const qualifier from the fields of kasan_access_info to avoid
  excessive type casts.
- Change the type of the address argument of __kasan_report() and
  end_report() to void * to reduce the number of type casts.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h  |  7 +++---
 mm/kasan/report.c | 58 +++++++++++++++++++++++++----------------------
 2 files changed, 35 insertions(+), 30 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc7162a9f304..40b863e289ec 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -128,8 +128,8 @@ static inline bool kasan_sync_fault_possible(void)
 #define META_ROWS_AROUND_ADDR 2
 
 struct kasan_access_info {
-	const void *access_addr;
-	const void *first_bad_addr;
+	void *access_addr;
+	void *first_bad_addr;
 	size_t access_size;
 	bool is_write;
 	unsigned long ip;
@@ -239,7 +239,8 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 
 static inline bool addr_has_metadata(const void *addr)
 {
-	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
+	return (kasan_reset_tag(addr) >=
+		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
 
 /**
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 9286ff6ae1a7..bb4c29b439b1 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -139,10 +139,11 @@ static void start_report(unsigned long *flags, bool sync)
 	pr_err("==================================================================\n");
 }
 
-static void end_report(unsigned long *flags, unsigned long addr)
+static void end_report(unsigned long *flags, void *addr)
 {
 	if (addr)
-		trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
+		trace_error_report_end(ERROR_DETECTOR_KASAN,
+				       (unsigned long)addr);
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
@@ -398,7 +399,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	pr_err("\n");
 	print_address_description(object, tag);
 	print_memory_metadata(object);
-	end_report(&flags, (unsigned long)object);
+	end_report(&flags, object);
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
@@ -411,44 +412,47 @@ void kasan_report_async(void)
 	pr_err("Asynchronous mode enabled: no access details available\n");
 	pr_err("\n");
 	dump_stack_lvl(KERN_ERR);
-	end_report(&flags, 0);
+	end_report(&flags, NULL);
 }
 #endif /* CONFIG_KASAN_HW_TAGS */
 
-static void __kasan_report(unsigned long addr, size_t size, bool is_write,
+static void print_report(struct kasan_access_info *info)
+{
+	void *tagged_addr = info->access_addr;
+	void *untagged_addr = kasan_reset_tag(tagged_addr);
+	u8 tag = get_tag(tagged_addr);
+
+	print_error_description(info);
+	if (addr_has_metadata(untagged_addr))
+		kasan_print_tags(tag, info->first_bad_addr);
+	pr_err("\n");
+
+	if (addr_has_metadata(untagged_addr)) {
+		print_address_description(untagged_addr, tag);
+		print_memory_metadata(info->first_bad_addr);
+	} else {
+		dump_stack_lvl(KERN_ERR);
+	}
+}
+
+static void __kasan_report(void *addr, size_t size, bool is_write,
 				unsigned long ip)
 {
 	struct kasan_access_info info;
-	void *tagged_addr;
-	void *untagged_addr;
 	unsigned long flags;
 
 	start_report(&flags, true);
 
-	tagged_addr = (void *)addr;
-	untagged_addr = kasan_reset_tag(tagged_addr);
-
-	info.access_addr = tagged_addr;
-	if (addr_has_metadata(untagged_addr))
-		info.first_bad_addr =
-			kasan_find_first_bad_addr(tagged_addr, size);
+	info.access_addr = addr;
+	if (addr_has_metadata(addr))
+		info.first_bad_addr = kasan_find_first_bad_addr(addr, size);
 	else
-		info.first_bad_addr = untagged_addr;
+		info.first_bad_addr = addr;
 	info.access_size = size;
 	info.is_write = is_write;
 	info.ip = ip;
 
-	print_error_description(&info);
-	if (addr_has_metadata(untagged_addr))
-		kasan_print_tags(get_tag(tagged_addr), info.first_bad_addr);
-	pr_err("\n");
-
-	if (addr_has_metadata(untagged_addr)) {
-		print_address_description(untagged_addr, get_tag(tagged_addr));
-		print_memory_metadata(info.first_bad_addr);
-	} else {
-		dump_stack_lvl(KERN_ERR);
-	}
+	print_report(&info);
 
 	end_report(&flags, addr);
 }
@@ -460,7 +464,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	bool ret = false;
 
 	if (likely(report_enabled())) {
-		__kasan_report(addr, size, is_write, ip);
+		__kasan_report((void *)addr, size, is_write, ip);
 		ret = true;
 	}
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9be3ed99dd24b9c4e1c4a848b69a0c6ecefd845e.1646237226.git.andreyknvl%40google.com.
