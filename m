Return-Path: <kasan-dev+bncBAABBPMQUWVAMGQERUCWUNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F8B67E2DBE
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:10:40 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-507c4c57567sf4748730e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:10:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301439; cv=pass;
        d=google.com; s=arc-20160816;
        b=M/T0qiwXFG84DLWg+fvQdargMMvqnINqomrt61PZICsel9+OcPx1D7CCaaoh9VocS9
         fq/KBAxRYDs9WiN5JDacPi6Y4z7Fwl4wXnca8OSFx5JVv99NovdecGocdy4vjt6KA+Uh
         Jvhq2s/QuXZN2HfQhn2TK+h64+iN0avnaQ5Ckc6w9MkWEFfVOiBhMz2ZbgQGvvaokyR8
         IjR4YZizbBJ1tLz7Z197AILLvEeX0jzss/Pltg5z0EQdC7XgMaJZcCCRa9cki1mBe2mL
         ZUHXOJNqX7IRPRiI/EnPdh+TMmXXwpjdCaPX5ki7TTasPnFnn6K5uDCyUQUC3hxUZvhh
         SI1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4lDX/jj1PCcmyZ66NZVa0KQ6HJp6PwCbeaDSb1BydEM=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=T9XeEu0kgCMRfIMjT5Dw2kMvu5GvVvkldH7jbil9zEhh5kvV/S7Sa+aa4o4NEIj3lQ
         s6FM+KcERzGg15cAm/JVY77S8eje306DSUn8//1/F6zTIU2maUczpIl0pIL691zG5XER
         nRJBhYwIUyU3zPvPwNFGkxrS6UpjGmvqdl/9fYSbWqHyGhHVlyAUFdZ1EdfUobMMoaUP
         JAGDZQkSa1OUGkEDHA7k7sC5v5HpqBtL2q2MsMPtZh4vJA+jbuGmQtJJV2e92uv3qQC0
         9CMH5DDIrlXcpgl6WoAWTidgWh7RYKrIbaQ0mLLaWGGgOql4D78vZmRmu6vdPM+mSig2
         hfzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z07E7O2S;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301439; x=1699906239; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4lDX/jj1PCcmyZ66NZVa0KQ6HJp6PwCbeaDSb1BydEM=;
        b=RGhmvZrRMsOMzevxHyM85xcGmN0xoCeVGA948H6Y/up+NeVNj0Av3toGOgFjiEFobl
         rxNTmxKU11SPt11Ml6ARA5oaDG2ArUwBgLc2cSdf+kkQFZD6+iI5eW9mel9pzyKgWfOF
         Y745K5rZ6vHz2HGBS1mI2HxFpXMuYzGHOqsubX68lgT2SzXyLp1HevTZUyL+Xw7Kk3ak
         MkiPHABfLk4B03e+VnymNxCdo3aOehGoPFavAAYWpRzy314rzF7BUO+rWWMRF5VunCC8
         M0oP9Q7EXqfThyUM/QN2qbsxd2M2U1DJHj+emZACIVYgKqf9ASJ5BW5BRMdNWyB/Y5j7
         m+Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301439; x=1699906239;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4lDX/jj1PCcmyZ66NZVa0KQ6HJp6PwCbeaDSb1BydEM=;
        b=V1rVTTjkX7vCSmQwLfrBnyEwRVGzpNAIynm7OcYaqCAEMusv77MEYZZs5QTssec9O7
         gTBZ6iOvH2ETarUwYvsQME7nHbas+mhJhhbMSt1w0gH17mzsg75aSEV4X4MUrG+60Joy
         7JGuPZ2QCClkylAUzt3FdjfRPRyOlv/9qKatoNJReWaytmrW46azHFr8m1g8JyhWMjTR
         5o71fNqw3luaejZjdRvWZr5pXZE8NSfGhhwo/8nc2cXHnuLBla2J6RDDQ8W+bm/Pklbn
         08AVQx3L4OgcjPy773q4eyYgETcFcGj/iJbzdYpxTug0Pid7qqSjHZOmliWOn+JdSaW9
         aLwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyeOxPDiW4XVlGiinpLm1APXBDFz6ccSeN2Tir7q/FKtbzH2A2M
	HAnCiolGDiJDx5EGyuck/aI=
X-Google-Smtp-Source: AGHT+IEiOOl8Cl0ajQ5m9m7veJbNEv4eZIWQ1fMobLCJeGKM30V+LZJEbfVVWwMxP0zpU/f+BuFVUg==
X-Received: by 2002:a05:6512:230c:b0:509:47ba:3160 with SMTP id o12-20020a056512230c00b0050947ba3160mr14137584lfu.56.1699301438198;
        Mon, 06 Nov 2023 12:10:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4019:b0:507:b8d5:d6d4 with SMTP id
 br25-20020a056512401900b00507b8d5d6d4ls572939lfb.0.-pod-prod-03-eu; Mon, 06
 Nov 2023 12:10:36 -0800 (PST)
X-Received: by 2002:a05:6512:3196:b0:4fa:f96c:745f with SMTP id i22-20020a056512319600b004faf96c745fmr29411678lfe.38.1699301436447;
        Mon, 06 Nov 2023 12:10:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301436; cv=none;
        d=google.com; s=arc-20160816;
        b=ZnQuKUrrxBtjmrnVsd4SC98GA0ccB9SM4CEw9Dva1VfC1DJQ92gyDVZlYbWzp05qLB
         AfOT76zarg6HzjNoPY3Ss5fqSqWhuDElG++VklSOO5vMQCHNtNEyem9a5iC2Pqq8C3Bs
         8V9MXCSstVcBmYRDS+Zy8v79L/OzEc8jN5Hm97ROcxnRHpbUUJCbtr2FNqiC91F5/iB4
         /L6DAxxy6h0aFpObC6sgvbFQf0rofBLSXv+vvPpyRXGjUExOkWkN2qu8mLRaHvQ8Iija
         R5Qzgydc98LnoHRJM8Nrs+NDukIJ7eLyOtKO0iU1N/geylwMrtbLZ88aUqaAaPeD2okJ
         fbbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nDVhwjjwJnVTlqgIL3b0i6xOOMbmQ8bjgeF5HzBvdls=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=U5QSSH3VCimO06gVjffTLf0z32TF8tF/Tvtv5R4RXEEHKQHmPN8TXMJKk53wZatuF6
         6STIABQqH9IZ+EWKWvTWAY9SG4rCHKJOmu7U9/Y0cSRuvWCCZeXo1iTlmLhV+WQzfWv6
         Mg64DRQC+tBr5bS+cYIHElnN/AIPvOGycieMRbbDZDtq3nv7QAdWj3I9Wb3NCe9sp+Kw
         /yVvgMt0RVUE/nJBYA5k4Q19irY8CVYwzSA4wLNjcDh2ZQzYRtFZjmNcYS7o+WNanNq9
         a+ibjGm1Caitm/wVg3u9ZcxInNRuTsV9WdZ4nYKHEF4UBSX5N01BuRCp8Fspbv7f8h19
         8j5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z07E7O2S;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [95.215.58.175])
        by gmr-mx.google.com with ESMTPS id b14-20020a0565120b8e00b0050946d339d1si552399lfv.6.2023.11.06.12.10.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:10:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as permitted sender) client-ip=95.215.58.175;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 03/20] kasan: document kasan_mempool_poison_object
Date: Mon,  6 Nov 2023 21:10:12 +0100
Message-Id: <e0c319c2033685fc25765af45d5b75224c15721e.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Z07E7O2S;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.175 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e0c319c2033685fc25765af45d5b75224c15721e.1699297309.git.andreyknvl%40google.com.
