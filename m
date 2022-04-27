Return-Path: <kasan-dev+bncBCNY737244PRBEWZUOJQMGQEJYPCDAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 85B4B511211
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 09:11:15 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id m16-20020ab05a50000000b003628807eda4sf472596uad.20
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 00:11:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651043474; cv=pass;
        d=google.com; s=arc-20160816;
        b=kg7IgDMlFnk4/mxaqy7p9Un43AkumYyh86Zk1YYMSzwGC4sVthqGFVnAVmwjdn8Un1
         D3JfiHlHdWsLrVH568EguhkaJbVPwrQKf896HXvmJl8FWQPygNt30atqh8DZNJeWGYgh
         lkje4ppsRI/dAwxg+/gNPpQCEtfHGujIXwcOvEHQs3i8cSdUG9w6pgwW0zTWtBoCNr5M
         gx5dxInUifp8xFAkIr7sF5kbLLMZcBHIPrUGMESZlygFtXgOq6VlQev3dx47W+9id9ry
         ILIv3/84WOIsAb2N88v+ZLgLw5kJRp6Aj3LuJ7t6HM7IQH+sAkLqToKBrPnMI/15nptl
         o96Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=UgEj48klcOC4BQhwQB021gPACC6kmmkHrjo35D6Ha+E=;
        b=V5hwXGMCWCV5OHaqSdo0JmSVdriNe8dUDuS4cAzIfQj4eVZBvoDcwcI5nnbi620k3p
         I/rWvjbZjYqgAG5g/VKJabKsF3lrDNUDtgqQgDLe9qhB7Xi7zc5wxJGrpybvXdJCYjB0
         C1yb9FqzFDNMe/z9H699Q+wsnD389wr4MCVHL6HOlmsfcEZ++rpJpPg6sP+ZfeqViCKO
         WYuAxLNkNWieu5wWSw4v7C8s2o+SVexfEDwViRYI0nkP2K/cLEHBVXRl3CvAFnjTsr9O
         XUn7kLoIhAMsmQCAzSKqGU7hTOBgWRop6fSiAmqkUDFAcwGs1lyPnwxQYt87/LYLMNXU
         Y9Pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bsJROiRO;
       spf=pass (google.com: domain of cgel.zte@gmail.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=cgel.zte@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UgEj48klcOC4BQhwQB021gPACC6kmmkHrjo35D6Ha+E=;
        b=dyeag+wHBvP2W9tO7PWBIt2mTtvbRa8FTx/OPWpEmb9DIpIlqgA8dnjco/paahCvrf
         cJavrO/YUvkgMXF2YVWDdYnvZ2qrC0jgSLjHUDWiFcBW+EiXeTRW/lkIW2GX74g+JPdA
         fy6vDPYSSVUk1CvqWVE0iNlrEiVvTDgElXGuonnWqX/kZbxyPimmTGgsyGyFVsLFoQOQ
         KKlr3Z9hcntysT5vt6dMWs/an/TADh5SbmtlLa6K/Y544GaPHavCTW6LvMDxCMdMOlvk
         CFlS2tDu4XoglEkBzMx+n28mgef0j1TBCZgFor1hMImhXuw13KFMQAfdj8usKbkubH+f
         IQZQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UgEj48klcOC4BQhwQB021gPACC6kmmkHrjo35D6Ha+E=;
        b=YfG7b9WWLPB+ghwRMp5xNTTzqxa2Ct0iY+tHn3hWbBj/qQ3x9oZrmiZgNxhJtaHcqw
         0Q36Bx7OY4XPkR526rKJarhhKv/bh8ZTotYQ0VxE7cmpzUPXF8maboqdC9m77R5B4zSt
         nJ2pENBkHtkuDKZ0yky6nZ3tGxHE3TEBZt6OZ8dg6O6NKWd8aE3NBjeqhucT8EKeWdlP
         O39rnvNPG8STeOt4UguT2ytZr6KdoiyhMBpuZPsDceNUj5Sf7QDHh/0WTY7hFZANg9zR
         ZJaYQ7V/7dLlouLQsReKEZN2qA2eQ5r0YFxMZRLlSwAMzqo7ySH51zMSUNPxQf3gr9+n
         iZGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UgEj48klcOC4BQhwQB021gPACC6kmmkHrjo35D6Ha+E=;
        b=c21Eq9gomAP3TGSXjU5NgJZpKKWdjHy15d8Nkgx7OTAhC+qQz6eXLgCS86wk7OigX4
         wKUBjnnhYl5oZ8A525BpyrUq9ckX8Kd9R9hDiAsIVHW6NkVqkSbIO88wrEmgZBQ73S0N
         GEpal0KdQhwGsu5ZlVdp239Y3zHPFlShk0/nSE5PrkZMVSbGltFltbyHZ75rvGuZaeWl
         GeuGJSWKgHGgXmDnSO6MKFyEOoeMaC/HcHICK8vF/1/yn0qD/7sDxGe/o4QrYbnseXRz
         nynhQ4yEK6xWwu0673VI2mnDJABccB89IMhXD6CauekSeD2EcCsutj0pQi6ND8uD3GiY
         TylQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HfsWlK2Ow33m9uv0bM3l5jN408miH4aqVoIYZNdf5LtSo/I4d
	Q+RgAzH8p8q9aCnSLHAMDZo=
X-Google-Smtp-Source: ABdhPJz1oB/Zxjeg4eEfv7mGUemGS/YU2XOa2xUDYlhoh94Cse9IPzUnCDntNM+MbwuJejka++WJTg==
X-Received: by 2002:a1f:e2c7:0:b0:34d:310f:6b0 with SMTP id z190-20020a1fe2c7000000b0034d310f06b0mr5757094vkg.19.1651043474217;
        Wed, 27 Apr 2022 00:11:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:df9a:0:b0:32c:27bd:37dd with SMTP id x26-20020a67df9a000000b0032c27bd37ddls340545vsk.10.gmail;
 Wed, 27 Apr 2022 00:11:13 -0700 (PDT)
X-Received: by 2002:a67:8c01:0:b0:328:6278:f12f with SMTP id o1-20020a678c01000000b003286278f12fmr8412582vsd.45.1651043473748;
        Wed, 27 Apr 2022 00:11:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651043473; cv=none;
        d=google.com; s=arc-20160816;
        b=oP72HIgT8tHLdjKf7nJn7KuF55aY+eOUGtleqi+nqkXa6E4/rwXXaVigrkitwYeL2d
         38Dr/oy+izO5+0fUf3/1PF4MSf1NgJVtI0PuubdwUCyqk5PFhw2mBPiOD2BwBxJo7uXv
         cGbj3qXbEqY4V6/+fMnWMNzLgDKqsn1wGG3o/tI7zOFO/wblB94INC1+iRLnrIyZR84X
         l7HR6kMTrkOa7/lLJCrRbCLI/NxXnNy6La8lQX09K5V6uzck60ImAyirPKf4jSscfJTF
         ZHBpg1WSl9kPnrxYdZUNeLGCwRi46LU8by4blRH8bE+eTTgrqxbNxas9bZw78zvEwKDB
         N1qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=qwksdRpUlSuuWw1pxLBKhXiKlPkBnGHl88zbVVW36PY=;
        b=tFY/eCKJAOiFek0K/tttx77ymEiUEqpCy6mWGBvyl5qcHafZMIFU2TAdUB97g0jlq3
         Ehsru0hOsH1ytiL6zR0Z8+sDkB4YNIbXvksXDcq2YYjlaceznH6G/8XAkhDe5FkOYN5f
         m+vQ9HElEVQhKdfemlWo/5lBtb12rnWHIY8VF2rjnRzBFlaspV3rrYAgD/D7nwYMlcwO
         wFBIBZqBZJZ/UQvHjsjHlV60TNk363vcoBW/z6kwfcFGdjUJZlE3mOxGokkxWP90MrPc
         V67NDneMnDMzoiUOl8Oo5MtUna/atQrmftZFvo0lqBCAQn2d6qN79D6HOSUFEpgl6JxX
         bxUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bsJROiRO;
       spf=pass (google.com: domain of cgel.zte@gmail.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=cgel.zte@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id m2-20020a0561023e8200b0032cddd78670si135086vsv.2.2022.04.27.00.11.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 00:11:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of cgel.zte@gmail.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id o11so527723qtp.13
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 00:11:13 -0700 (PDT)
X-Received: by 2002:a05:622a:58e:b0:2f3:81c7:cc59 with SMTP id c14-20020a05622a058e00b002f381c7cc59mr2565899qtb.614.1651043473412;
        Wed, 27 Apr 2022 00:11:13 -0700 (PDT)
Received: from localhost.localdomain ([193.203.214.57])
        by smtp.gmail.com with ESMTPSA id y13-20020a05622a164d00b002f1ff52c518sm9238002qtj.28.2022.04.27.00.11.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Apr 2022 00:11:12 -0700 (PDT)
From: cgel.zte@gmail.com
To: glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org
Cc: dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	xu xin <xu.xin16@zte.com.cn>,
	Zeal Robot <zealci@zte.com.cn>
Subject: [PATCH] mm/kfence: fix a potential NULL pointer dereference
Date: Wed, 27 Apr 2022 07:11:00 +0000
Message-Id: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: cgel.zte@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=bsJROiRO;       spf=pass
 (google.com: domain of cgel.zte@gmail.com designates 2607:f8b0:4864:20::833
 as permitted sender) smtp.mailfrom=cgel.zte@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: xu xin <xu.xin16@zte.com.cn>

In __kfence_free(), the returned 'meta' from addr_to_metadata()
might be NULL just as the implementation of addr_to_metadata()
shows.

Let's add a check of the pointer 'meta' to avoid NULL pointer
dereference. The patch brings three changes:

1. Add checks in both kfence_free() and __kfence_free();
2. kfence_free is not inline function any longer and new inline
   function '__try_free_kfence_meta' is introduced.
3. The check of is_kfence_address() is not required for
__kfence_free() now because __kfence_free has done the check in
addr_to_metadata();

Reported-by: Zeal Robot <zealci@zte.com.cn>
Signed-off-by: xu xin <xu.xin16@zte.com.cn>
---
 include/linux/kfence.h | 10 ++--------
 mm/kfence/core.c       | 30 +++++++++++++++++++++++++++---
 2 files changed, 29 insertions(+), 11 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a4b680..fbf6391ab53c 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -160,7 +160,7 @@ void *kfence_object_start(const void *addr);
  * __kfence_free() - release a KFENCE heap object to KFENCE pool
  * @addr: object to be freed
  *
- * Requires: is_kfence_address(addr)
+ * Requires: is_kfence_address(addr), but now it's unnecessary
  *
  * Release a KFENCE object and mark it as freed.
  */
@@ -179,13 +179,7 @@ void __kfence_free(void *addr);
  * allocator's free codepath. The allocator must check the return value to
  * determine if it was a KFENCE object or not.
  */
-static __always_inline __must_check bool kfence_free(void *addr)
-{
-	if (!is_kfence_address(addr))
-		return false;
-	__kfence_free(addr);
-	return true;
-}
+bool __must_check kfence_free(void *addr);
 
 /**
  * kfence_handle_page_fault() - perform page fault handling for KFENCE pages
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 6e69986c3f0d..1405585369b3 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -1048,10 +1048,10 @@ void *kfence_object_start(const void *addr)
 	return meta ? (void *)meta->addr : NULL;
 }
 
-void __kfence_free(void *addr)
-{
-	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
 
+/* Require: meta is not NULL*/
+static __always_inline void __try_free_kfence_meta(struct kfence_metadata *meta)
+{
 #ifdef CONFIG_MEMCG
 	KFENCE_WARN_ON(meta->objcg);
 #endif
@@ -1067,6 +1067,30 @@ void __kfence_free(void *addr)
 		kfence_guarded_free(addr, meta, false);
 }
 
+void __kfence_free(void *addr)
+{
+	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
+
+	if (!meta) {
+		kfence_report_error(addr, false, NULL, NULL, KFENCE_ERROR_INVALID);
+		return;
+	}
+
+	__try_free_kfence_meta(meta);
+}
+
+bool __must_check kfence_free(void *addr)
+{
+	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
+
+	if (!meta)
+		return false;
+
+	__try_free_kfence_meta(meta);
+
+	return true;
+}
+
 bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs)
 {
 	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427071100.3844081-1-xu.xin16%40zte.com.cn.
