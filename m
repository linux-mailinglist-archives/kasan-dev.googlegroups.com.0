Return-Path: <kasan-dev+bncBAABBC6BTKGQMGQEWWDJRAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BFD74640FA
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:07:08 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 145-20020a1c0197000000b0032efc3eb9bcsf14548511wmb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:07:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310027; cv=pass;
        d=google.com; s=arc-20160816;
        b=ioogDFAvZKDxP6hP4cUuR/71zf2enbRnoSsfqhmFsi5YviNlHkbi6K2erXFTrlW8B5
         p7CZo6C44JTRvWwi1TCRUYo5M8dMCRo2OExutPVKxXrSrMqaDswvn3EnkxnB9q7WzqQx
         l3MZz4vXqkWAxKi2XsFiez57291t78qZC9/toGA4+8HMn0YrMDSZQvra02+Nk/AWOAMg
         7nLVqGbJ7kHB22rsV12rDR2xDXdTBHtWNQnxp5aN+RDS/XOfEopHJxlitnC/TzjkJlvi
         DxOsSqLI4voEFIPO5ND++FmlJ7aRBpYrLqUqKGJCY0XEvtHjTjv8H3wGKwTP3ptA9LrE
         S6mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HqWxucMuUPkXSQpb69GFHdFeFztvQ2j98PklEvyu5ts=;
        b=bh/1Pv+ybg7J9r1LoIml+TrPxdca2gGYPgWWKcpqlMBw8Qzoz1J98M2Z1CV+W1Z/T6
         UC5qdtk3oXX9dbYvXs8y4nRqxOgkt8hulxA89JFWqahwXhbmV3je730EahHbRdzV6W47
         vIQBWaDGb0+eph092j8yJsyyTawHcKsBuktx8F1uga3vrZVlyQQTmNtBLjJAyomqW+Tn
         Vypxs6dJDnEJ9RCCtK70WGkEkGLAzv7PI7izDuSarPJu1AzMB5nreRplNS5x4il3nSpt
         s5Cm4woXiVq6KSuZLXHKNziHdJNPhGIvQxFsd64BN2mMtlYC6BKyQfPgaUFE+yvkordi
         qd9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iKPkHgct;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HqWxucMuUPkXSQpb69GFHdFeFztvQ2j98PklEvyu5ts=;
        b=JXj24jrdy0CAerdKMv1D0QQjAOZv4mQpVtfRjYaKYS95OgSIW9g59G/JljA1sFucn4
         8ZInstultFmQoit1ayjuo10bpM0o0/gssQ90tSg7a4IzwnKrct9N2jgu/gJIIXDxPbja
         8b5aLVvGwoPmbm+jPJoQ7j8opnNucKcJn6hyqhWrDGKgB9tqP8rWSW8Ua640GnXaYA4M
         cuxKzTchtvOWCPnrGo2AxneD0/KQRHQ0myDvv4ICUwRphvZRSgVennKZXxUxJ2PlrnKR
         mfAyIKSeBa1NkMDrWXOd4rsOafms9wxV6AJ4MrDIpx12vKdFeousPqoCLMqZ0ljgvXUn
         QUdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HqWxucMuUPkXSQpb69GFHdFeFztvQ2j98PklEvyu5ts=;
        b=lbSHpENGG7eJhyZi3RjewTMS8YRwZwWqeZ7En7A093ilNoS+D02cHfMQZ4xlFsOFqx
         eNdgHY0SY1WxdWYZP5U1xcAMR1Mbsx56aqOXRWhdGXBMR2xJJElPuF7SHLmKl60jeH7i
         wGSDL2GG9azzbsn+nnLayogilllKGcm5taYnGE+GjNE4/u/a37fSZ2FC75tduCwJNxYd
         WbT9GQH1AdaXUhOXpcn/0nRnKXR1TrjU+2asHssyMkta6r29oE1QQvpmELrbewcDITFp
         Nb3eoyDv4v7IdURCjRV/jLJkemOElfcjoKfLyBOizgLxOX92W1mrZ8ZdGi01HU6ZjqXI
         y14Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312Kv5kSs+a0OllSqQ5kxX+TMBZFywBUc/VLRZXFG+TmVagGVaP
	m51mxsnJlK1TMOcGdvCe2jc=
X-Google-Smtp-Source: ABdhPJxtDqw/byR6FPVdi5LhtquSYAt3kurxweXqRV6pQSlIM34pSQdnLDds31EmryjBqmNmFjtNZA==
X-Received: by 2002:a5d:50c6:: with SMTP id f6mr1751913wrt.131.1638310027861;
        Tue, 30 Nov 2021 14:07:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls187137wro.2.gmail; Tue, 30 Nov
 2021 14:07:07 -0800 (PST)
X-Received: by 2002:a05:6000:15c6:: with SMTP id y6mr1935118wry.422.1638310027279;
        Tue, 30 Nov 2021 14:07:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310027; cv=none;
        d=google.com; s=arc-20160816;
        b=oqNb5u9uiWTKYps7QCoN0Xhiy6ysVj0yii6m5YDghWrn2TjZG/W2Bi/6jkRW37/DMn
         1NwuGugFbRh8shjIVn+rOtCyIPtXWWsRBxBdvLrlBEK8XdQ61GUY0ptRrPM488gJT3aF
         u3+sPtLX9rBAa1DPGc4loKYk5GIqSNQaEBr7eHb1Iu82zPs4eUfwQ1Z1o5cxrauTQCkx
         auXQA4ng8BVy9+2Zn0OuoDJAyWpJrDjrz78FJPcM/+iBWkir45YQD8hrwvlxmoC4cJnF
         Bj+FEk8z7NDSxAsPfebLMntTva7RNMz8JSDC4X39uYpHsxvxamknqfMcK25DN7CO12lX
         MIBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=n4gFh8zlpMsEgMrbMj+8ISQjGusuzX7sFY8iv+MHRNk=;
        b=DtpjiQ8hN+daR7JdLqkaVWj0RblSZMekQ3NWEyuLiIV9GNgLFGtDd7j/Q5dvY72dLl
         YkBiUoL91ody6bM3cAHMKObxXUZJZg73JVqsWCH9PE7ESt9V2D8UNUOJQA9LZfaxeV2G
         3XB4Z/4PJ6wZ7ckU9CkLtjJluCCenOVWgt6sLVMGMX+VcJj58AG5utvnW4ZACl6QjUHr
         nEbjumnBpmMyKP+cA+BgS+LaWiRiZfwbyN1afDg6kPxu+7Adof3SegnMfDSoUQXCClcz
         YnGZ2m++iQVdQX9raIyp45RhvkPTTNaEEEw0Tcq09jO+1tQcc0kad5/lGiKw+2S4JLuJ
         h82A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iKPkHgct;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id z3si297558wmi.2.2021.11.30.14.07.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:07:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 19/31] kasan: add wrappers for vmalloc hooks
Date: Tue, 30 Nov 2021 23:07:05 +0100
Message-Id: <78e751b3f9b62e2ed046d9aed695d0d9eb4137c0.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iKPkHgct;       spf=pass
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

Add wrappers around functions that [un]poison memory for vmalloc
allocations. These functions will be used by HW_TAGS KASAN and
therefore need to be disabled when kasan=off command line argument
is provided.

This patch does no functional changes for software KASAN modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 17 +++++++++++++++--
 mm/kasan/shadow.c     |  5 ++---
 2 files changed, 17 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index af2dd67d2c0e..ad4798e77f60 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -423,8 +423,21 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_unpoison_vmalloc(const void *start,
+						   unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmalloc(start, size);
+}
+
+void __kasan_poison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_poison_vmalloc(const void *start,
+						 unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_poison_vmalloc(start, size);
+}
 
 #else /* CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 49a3660e111a..fa0c8a750d09 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
@@ -488,7 +487,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
  */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
+void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78e751b3f9b62e2ed046d9aed695d0d9eb4137c0.1638308023.git.andreyknvl%40google.com.
