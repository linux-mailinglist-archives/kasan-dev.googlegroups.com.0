Return-Path: <kasan-dev+bncBAABBO5SRCWAMGQEWEBVCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E291819380
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:29:16 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-332ee20a3f0sf3736948f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:29:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703024956; cv=pass;
        d=google.com; s=arc-20160816;
        b=RfROpufv3LX74hQnVthGnXFesHfYVQUIgFV1AIIHSKKFBL9SHjhV7OyVTF1agnmxq9
         fN0JSe9OteMsQKUe0BJwtKLOwr04iQ1Ng3iSK41Kmtk4MjfVsYcHwgSMWG7E/1K4TmXy
         IsA5O5vvLFYZElZFblFLWKVTdf1fnmaCZRWpy22/kAzLRrWc9hnQ0Hc6WxjMxIm771t7
         8b3dhFHnZwKor1NQfGiffSLb4KBQ6jGhLznA8ruD1xV22JQMlVlQjzs2i7ytDGMkGdQu
         LJ1ACS5U8UOjJGXSNuX6hRD8mRaaV35KgNlbEwrztJ/L1Zf/F3+lYlH1uARFQjDw0uUb
         T1CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=F3Y+AYycynlwk7XbI5zbQCjwkhQPiLrHCivuvn6Fv/w=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=zXdNKYLvAqMbD2VwV8rLWQ7fGN9zF34LP4505Stk0SFf8+VDrSQzoMmT4Zfezwaa9c
         aFzv8QdqIdvAERUiqLlMdoScegQfRufC56CAwPxBitdG4qbM+k6Pww5EFaMFPMc8l2wO
         EWO86IfRSRtiube72gtxBIzYL+/AQ4Y6AEG/3WQnSunDP3YHndKXtUvIEN4Uc43+Z37/
         H2OAuzMMJ+8aKgwE6ZikgWkGqJ5MLkKd0R2Rcdk53895QNQi2CF3+T6a5FXMKDfyJ4KB
         hxeyzyDzB7LO3TvW+aHFkuxWXp205kzgHuU91WWOwKod37ckfi8IELTvhU48yuQuOmf8
         tXjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=C4rzmgvl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.188 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703024956; x=1703629756; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F3Y+AYycynlwk7XbI5zbQCjwkhQPiLrHCivuvn6Fv/w=;
        b=VS00aMkPgbEhlFVUEMEWdJKVz4AcpQZU4XJv/A2cJ94qGKSYFC9M7tZo+hdbZH/1S3
         Rznb/kYWeKMNchfbG8/SEL54uQFG2iTxpkssEJRmRCrKCHvtqz+Q75hl9adD038mERiq
         WCNOfCFO0NnF5GIStEewsBWpLHXwgAlhhKthLVlXkDZqh+JtG3Kb8OK0OzwGnJrbhi2h
         O4CgQbJpfV9Ijz05HQ3EYNH7+tzqRs5WnCuswsEM48+J3+zte2AZlI8bge+tv9FG8wfC
         wpKeK6o0gYhI/kkgEJp7pkprbsxPHk8QR2TUH60Wbwnx4eEpias2jzch16sU8v1hvfIp
         8irA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703024956; x=1703629756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F3Y+AYycynlwk7XbI5zbQCjwkhQPiLrHCivuvn6Fv/w=;
        b=SdTr185XJtZHJuYFXhX2jrcu8IE9KipXdPDuOfj+lVKqCGDWmBKstBuHjg6rekUp0p
         UK1Fg18QmdCuuQo/s5RlZ7i/L5+dNmLvb3ETsJtZyuREEJHfQicqfyBwgiZIzA6MYJ7E
         owavH1KbcbEym468mXsV92ELyAnRTTGYNaKH2PQDTpkJAI6wlx96HZxpBnSMTRZROsSi
         jhPJjxzB+snF5IoehFI2sv/ibV3bj2RbEGeJePMdeIAxff+jb0A8P2zNgbGX3p0FAH+d
         ynWQEyEoonxwLYuSCqKRrKwU8ABh5oq0Ax0gls0Nh6JNJBzzyMRoZdCPmzFLna3uYSeM
         /s+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxhERaP0Uyvf7Nbow5+XiOB1dKVqPclTdahuL5AnhqOOmHWaKcf
	ShoLrczG0G/rlWseku1Scjg=
X-Google-Smtp-Source: AGHT+IG//qQXMtl0Xj8tA1/9kjnJqcgsOjDAM6gaiMMjfI/izpx7RVypJq7dSwt6/kY1XOu6QNUptA==
X-Received: by 2002:adf:e406:0:b0:336:6c32:12e7 with SMTP id g6-20020adfe406000000b003366c3212e7mr910311wrm.72.1703024955929;
        Tue, 19 Dec 2023 14:29:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:94b:b0:553:be14:e93f with SMTP id
 h11-20020a056402094b00b00553be14e93fls50890edz.1.-pod-prod-08-eu; Tue, 19 Dec
 2023 14:29:14 -0800 (PST)
X-Received: by 2002:a50:ed0e:0:b0:553:8d0d:7f09 with SMTP id j14-20020a50ed0e000000b005538d0d7f09mr532642eds.82.1703024953939;
        Tue, 19 Dec 2023 14:29:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703024953; cv=none;
        d=google.com; s=arc-20160816;
        b=kB26FTrhwJY9irXA+BkO+XtwTkQcJ1fzS4jNZ1d9cWN6qwO0yl0Ph3SrOO0lI/SmBx
         /Cblwsua+JNPGsPpGDX0kaxE2Y+lOmruUfykkg89zk2HE3fCA9NFHa0Qi2PrLLpxGoZf
         HyMfSYCKInyjN5r4rIaqucO4XS9drBgnf0PEDFSCXgnB83e1ujS/izLCgCHz3GGfM+hf
         XfCjHUPnPi5JasXR/S3OOLneAja/dvp1JNElQpNK4xWzU8SEs5OJFA6+2nHJe+AwNj3C
         WfCvw5s19qN96oNiZgAP695somRJilSzEmHkfs/ntJfJPmA/gjsOpFgLYJxAdKSepHpj
         o71w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nDVhwjjwJnVTlqgIL3b0i6xOOMbmQ8bjgeF5HzBvdls=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=bGUgxSpwZzUkyD69jbk/31kh6pCUWgPwjM6j8PaizLXV0s5Fo0rmSt1Yn5cohjcu5s
         dCPV9ZWHNH/RdZLfnNCtGy0UrINm0Dydw5cdCUqxRJtrEYT7OZDdGCTu24/SggMf5M58
         XG/FkscHuOc46tG5iiBtlLsLT0Ka5MxndE79uuzP5fx5MrO5A5y+bWy1Gm8rlH+lh5qo
         ytW8SxW6pM8rXfxFAw6L/KLkSZzj+Hik3Afhy0PPsrRloxdkrwLV/7L439etoB0optSq
         8eiyhukWf1fWErn6uvjS8NG2bwHwF9zf/vzMrPJrxq5mJ0nx3Rub42X82eIeWBU2gymc
         681Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=C4rzmgvl;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.188 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta1.migadu.com (out-188.mta1.migadu.com. [95.215.58.188])
        by gmr-mx.google.com with ESMTPS id y1-20020a50e601000000b00552180ac40fsi444478edm.0.2023.12.19.14.29.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:29:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.188 as permitted sender) client-ip=95.215.58.188;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 03/21] kasan: document kasan_mempool_poison_object
Date: Tue, 19 Dec 2023 23:28:47 +0100
Message-Id: <af33ba8cabfa1ad731fe23a3f874bfc8d3b7fed4.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=C4rzmgvl;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.188 as
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

Add documentation comment for kasan_mempool_poison_object.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 0d1f925c136d..bbf6e2fa4ffd 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -213,6 +213,24 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 }
 
 void __kasan_mempool_poison_object(void *ptr, unsigned long ip);
+/**
+ * kasan_mempool_poison_object - Check and poison a mempool slab allocation.
+ * @ptr: Pointer to the slab allocation.
+ *
+ * This function is intended for kernel subsystems that cache slab allocations
+ * to reuse them instead of freeing them back to the slab allocator (e.g.
+ * mempool).
+ *
+ * This function poisons a slab allocation without initializing its memory and
+ * without putting it into the quarantine (for the Generic mode).
+ *
+ * This function also performs checks to detect double-free and invalid-free
+ * bugs and reports them.
+ *
+ * This function operates on all slab allocations including large kmalloc
+ * allocations (the ones returned by kmalloc_large() or by kmalloc() with the
+ * size > KMALLOC_MAX_SIZE).
+ */
 static __always_inline void kasan_mempool_poison_object(void *ptr)
 {
 	if (kasan_enabled())
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/af33ba8cabfa1ad731fe23a3f874bfc8d3b7fed4.1703024586.git.andreyknvl%40google.com.
