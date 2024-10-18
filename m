Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBWFWZK4AMGQEJP6JV4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B597D9A44AD
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:31:05 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3a3b7129255sf21975535ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:31:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272664; cv=pass;
        d=google.com; s=arc-20240605;
        b=VKEQm0KFU1hXTHawFy/9DCiwjUu+40L5IEdpL1DOPRKTlL2i49tiKiTq99+j/+i0rF
         ms5ZQByGr9HETmHfsCLhKn+2Ib5hRcZdRf0oWtEJDubFVQE1EBJ8VC51moFtUnwLvww5
         usnSogo4vag//Jal3AFYLE17pRGTh+7pRrWXfQG+XUMTcPkwtkd+eAiFppqZDUhiJn45
         5MVz9x4b7O049+f7y9Jrh1WTa+60hj9tFKW+r49GXjkhX5hW3bljwT0VLhQV5Ml6gY4K
         di9NnJ+VRE4iDX7AOq4B9hl79fc94GRSAMD7jmDY9MY61XuJb0FIdAKUdtC8Uf6ju6vS
         r8KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=KJhmkLDJQSuw9wsUqe9L4MzjR3A5cb3URFacqW5d31s=;
        fh=pJTHqg/XBHJPv4SBSuptOmN7GKitKPJegd/I7nPjfFs=;
        b=dJ+Z7Fl/7x+Xhy4Z8JWVcJ+aCC/eeWbn6MPafoaOMHrVFBN5c8Q1A/lIgttoC6aQ0i
         6+zPwl/eepO2/P9LiMtrREOgaoPDV3pxMWBoODLbf/h5Sdqyvxpqx3P0qfIs8XhaYano
         dN83fLet3xbG0l/rE3DTCRvhhzMimXyqBKJkmNr2k7UO32+ViO6IbV9A1yQwFnwSWJyL
         mZgOpi7++eTnPpImxgFIf77IByGLyyq25oAyBv3LhyDMw3QjgsqP0ixAicl9NKJ+8ePO
         9aA3Kif1qOXD7wVEydDMfmyuDy3yccPR6+EMP1daJEpJn5zyjsE2K15PX0DjXRTyJUXc
         79tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NsNfJqn+;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272664; x=1729877464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KJhmkLDJQSuw9wsUqe9L4MzjR3A5cb3URFacqW5d31s=;
        b=Y3p+lV7b9MAdrTJh6eQ/sfo2U8g+64HAEGKFygt31IPmaXNuL2uxt/0zbZMAPaMGC2
         PUa0AGx8r+lvvyBywsWRtpHCAuSdao8TwIR6TJuQehLbRyQmafSN1rnHg/NyZYD0fIov
         TNchJWfVe13QBTJ0UqKB84mY9KZRA50dVPJjo/d4X1RbNP5Uyi5syI8MG8gYcGIhdMag
         QD3cuNbjrV7m+HxeAfeOWo4i52qWgldJabByqhxlz0KR3PoYMogb60uwXtnnyRw4yVVj
         63ANrtnr3yG9XqSt8QMjpg2zH58CW7qk6H/y8Yfzj2bxQa/NVSM/ky2M+1K7MteAECoL
         8arg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272664; x=1729877464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=KJhmkLDJQSuw9wsUqe9L4MzjR3A5cb3URFacqW5d31s=;
        b=ewrL6iXk0S9faokI4iii7izNuRUOoP4Xf1DI05qarB+BTDEQBwgooC5QX2i7Rl73bO
         Qlf7ui2VIUNi+e9JgFEr+JGvBOaoG0iaYUwWhLiJFFU71sTdoD39+cWXgB1vjucWVMdW
         tOHQiYSLjl54DXS8zoxqTDK9nzHdzUv9rTct1bqDuMmRpx1JthBd9eWJkMCgHkyX9KnT
         DqGaWExSQwbwQBudTtj+Zm6zU07h+HwtiMtFJmT7S8HbN7RxUjCg6/XnnyKEnm1OXCDy
         r2N3gz3ju/2MluKo5tdf99hSg58vWmjB+N6fYjINLaK5a4OQrj9FaxquCaSxiVLVQLHa
         boIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272664; x=1729877464;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KJhmkLDJQSuw9wsUqe9L4MzjR3A5cb3URFacqW5d31s=;
        b=w6KMwd21wEduZzip3c/ByHIFbYbz7NfkFJLzXANYYhXr4xJXV/mXcEjsAYnT3/UFlg
         DrFAb4VlpwzTKXFXJgcn9P1N0VaQQh6obLzhEbpl8JAfFD44dQrEa8V7OKuAWdJyiKv3
         M8FeCDy5bxk/k9edVENeiW2qTjjf0FTqrlhisFE7peOoc/QgyPXoDXXcccQQ8UJpvowY
         s8D0d/IqZbT4N0wcI1PeUyzdJXl+WAT7wrXiASVNOkLzHxFLThylbXCB6iEbdYDOGJ4p
         K31ORhVQRahNO42BWZVUI909hjpaGywPOw3jgYl6b4CpnKExY4nOISZ87L0qbvN+fN6P
         FdmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYnQYxBmaO1P/p+HDmHuAbxQo92/2FG85AazM7NpsuBI2d8XtAamswAFTxbOKxV0jCsGe0lQ==@lfdr.de
X-Gm-Message-State: AOJu0YzSOmlXw8isv0WpGbxNulP6YkL6vuNONYM6oJNQi1RLi/oz1HTP
	mInrpW2e2i11uKLgrM1lb3LapXQpWPqgo/vODlmfkK28kVVFsqJ7
X-Google-Smtp-Source: AGHT+IFlguapRiX895stmifr5oD84b8X5C9S5tcK9LXD8IviEOc3j2s4LbvrqMoa+xqLvaXcfw9JaA==
X-Received: by 2002:a05:6e02:1e0c:b0:3a3:b1c4:8197 with SMTP id e9e14a558f8ab-3a3f40ad6a7mr39683415ab.23.1729272664341;
        Fri, 18 Oct 2024 10:31:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1947:b0:3a0:cd86:9cc1 with SMTP id
 e9e14a558f8ab-3a3e49ae952ls11691895ab.0.-pod-prod-08-us; Fri, 18 Oct 2024
 10:31:03 -0700 (PDT)
X-Received: by 2002:a05:6602:3f8a:b0:83a:c296:f5b0 with SMTP id ca18e2360f4ac-83ac296fd5amr126016939f.9.1729272662341;
        Fri, 18 Oct 2024 10:31:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272662; cv=none;
        d=google.com; s=arc-20240605;
        b=BwwBaeFQSBN5A7ZpvZGF3ukXg8zgHPYUaQkK1/cvZHJXtAo0k7zr+f/gGkT1gcuamn
         7pncsJfu+2z/2dRJuV716p3U90wpct/lv8aPgcilsw5arGgintmQVZSUsMTd5tKq5N33
         DsugFpFopLbveQRij7odjV3c+QabvAsq87p49i4dQeTRezhbkxuACzQ0TzjhiOYQvSGI
         96bouTglM5T2drXRYCBFdSvfS9YBwZRRO/IDPKXmJQ5H9f2kuM7RNHVg47AiNGn0Icr+
         /WV3QOUzhkOHVXEY/Nw9C+xUNJild2KE04TcT2eGPPgjxGfnkggYen86JkStB3wUUpki
         BFrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=c7nu+U6UkRZF2cuN8FLbB8nvBf84Wg4YjQThyWhRKHk=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=XV4yjMcGonhsAutJFQ5/xNm/waeUCgRsxWNVR0gWP5zh7+vfZ59z0WEuajjHgQvTPV
         yWidI8zNUKmSarggqX1vNYCcgD5elLz0keBxRbjZ3R+PM9wW33z52bmh+emNxhtq+pGf
         uHzhGqvAWQ5vyQb4YiIS4oOVBKcL27IzKJycj3D4yjEvvTGvLzcjZUGX1E9zE4YMCYkY
         aX6fqgffYxxu8Pl8MLUjbwa45W+MXvyJDN35BeiYOXYl4eMYZoW/pvCKUuIrlq3Trrtx
         ZIMnJdjrtp6rT8wKzQ77ArUHFQf1kl7YY8Ur0h6zZFOrG6peBrQL3S+0UgcqNvFiwoPA
         SZ0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NsNfJqn+;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-83ab9f8956dsi8359039f.4.2024.10.18.10.31.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:31:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-71ea2643545so967603b3a.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:31:02 -0700 (PDT)
X-Received: by 2002:a05:6a21:1519:b0:1d8:a3ab:7228 with SMTP id adf61e73a8af0-1d92c3323d2mr4881461637.0.1729272661553;
        Fri, 18 Oct 2024 10:31:01 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:31:00 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3 08/12] book3s64/hash: Disable debug_pagealloc if it requires more memory
Date: Fri, 18 Oct 2024 22:59:49 +0530
Message-ID: <e1ef66f32a1fe63bcbb89d5c11d86c65beef5ded.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NsNfJqn+;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Make size of the linear map to be allocated in RMA region to be of
ppc64_rma_size / 4. If debug_pagealloc requires more memory than that
then do not allocate any memory and disable debug_pagealloc.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 15 ++++++++++++++-
 1 file changed, 14 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 11975a2f7403..f51f2cd9bf22 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -331,9 +331,19 @@ static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 static inline void hash_debug_pagealloc_alloc_slots(void)
 {
+	unsigned long max_hash_count = ppc64_rma_size / 4;
+
 	if (!debug_pagealloc_enabled())
 		return;
 	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
+	if (unlikely(linear_map_hash_count > max_hash_count)) {
+		pr_info("linear map size (%llu) greater than 4 times RMA region (%llu). Disabling debug_pagealloc\n",
+			((u64)linear_map_hash_count << PAGE_SHIFT),
+			ppc64_rma_size);
+		linear_map_hash_count = 0;
+		return;
+	}
+
 	linear_map_hash_slots = memblock_alloc_try_nid(
 			linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
 			ppc64_rma_size,	NUMA_NO_NODE);
@@ -344,7 +354,7 @@ static inline void hash_debug_pagealloc_alloc_slots(void)
 
 static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
 {
-	if (!debug_pagealloc_enabled())
+	if (!debug_pagealloc_enabled() || !linear_map_hash_count)
 		return;
 	if ((paddr >> PAGE_SHIFT) < linear_map_hash_count)
 		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
@@ -356,6 +366,9 @@ static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
 	unsigned long flags, vaddr, lmi;
 	int i;
 
+	if (!debug_pagealloc_enabled() || !linear_map_hash_count)
+		return 0;
+
 	local_irq_save(flags);
 	for (i = 0; i < numpages; i++, page++) {
 		vaddr = (unsigned long)page_address(page);
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e1ef66f32a1fe63bcbb89d5c11d86c65beef5ded.1729271995.git.ritesh.list%40gmail.com.
