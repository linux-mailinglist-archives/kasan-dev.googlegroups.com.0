Return-Path: <kasan-dev+bncBAABBAESUWVAMGQEYFKL7IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 251367E2DFC
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:13:54 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-53db0df5b7csf3802348a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:13:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301633; cv=pass;
        d=google.com; s=arc-20160816;
        b=tqjagU/LMI7a8uP7IyFc6gpj9zXrvvqI1tAZmzjYjQSpxZ+o66EuFIoDHJLvHi1jJx
         KagO5V0D9z44QuGWdNDNCo9LZ7NNSgZi40f0bJ3zlqiGAL4VEXEjl1J3QHB/TyyzHsNd
         IWEnEhG+Lxa8/PH5vOxG1Sa2xnEu4IF2RT8fane0N4UIPCY42jd6AsNE/M5qRpYosBg2
         PXWGJEMrt2BahP+4D1LQtfmiQQ6EtCcJo/FS56I5sd6UuKjfhOhV5Flzmk/sQenrVoeA
         Mst7Viv8JipZul3fj1+9s/XbkyqFFAHGLOOBrPeBgHrziLfXMUORnjZXdfkAVS2uWlUL
         AcaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GuDSB/CeG+6Qld0cva5a7PFVyU/eH3PrzIJJaPkJ6k8=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=IVww1IK1E+NqinOn+xDxuLY01mnGIZCrHyUs+YhZnHF9/qn333BTSRz/3YcRIJ+Kk3
         H7nBnRmI/R97nqIAq9UhakXGw18iKuewWJaFhKsrJEAwbo4E0yAE84UuQQx0nGdOknzw
         ArtjFScssg8selhv0q9MYnwdtXRSLfJ7wxpYgGlmYVwUC50YZQdgT2kef/Ig6xtG1VSa
         coe9pl3cKd45588iGceOjRYdlvt9aJdMvmFHFfv/wCear1Bb4ZCWmJcHlFfgzJQfQQce
         nWulqJiN+lUquI1utHHuWFxOqcoLITxqCABT+9ufUCN1tiWjy8ac9q1iTyyt7cRpiDh8
         R+Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="cb/DYhw0";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301633; x=1699906433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GuDSB/CeG+6Qld0cva5a7PFVyU/eH3PrzIJJaPkJ6k8=;
        b=iwGXMc3C2NuMwuXEVwPpWfi85oGT8cT/tVb+dKXOyj7TUZJc7T2S/3mzRVodLAz/VX
         ZzcyxiuqOsXFhFGMNKpnTcVoO6a3MFHpamThRUVGgOhP3kP1wjtexZ7ErBGTcOv+tRV+
         OfWvBOI6zpzzgCOtQCtgOSP+7k9T+MJvPkO7zxivlznrGy1zyYBq+TIubvopxNdhyy8J
         7FtPmLZMF4znVjLnl/BZ7YxsYggj/XfvjiUT/zng1Iokxh+g6lp6J7HyV6kv5dCdMlvB
         hqG7x+Jd9Q+5COllIZ+qcCgDL5NlW1xmi1LRld1cvpFFw2YfipmdopmuRNugDmz9Mlyc
         lxlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301633; x=1699906433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GuDSB/CeG+6Qld0cva5a7PFVyU/eH3PrzIJJaPkJ6k8=;
        b=PvRpLaMQ8OrBro9wBGRm+4R1CWJOTh5J94fZK2intxSKoq5Tfc8vumMgHWSz5tvBk+
         LrYpAcNreCKgAo2bDgPSMqJzwFzYnpXts1zsf4UBhbU1en2gSvnMcyQyLSFXGkU4/iFM
         JMO3ecrC4RyzBqYxM/0N0RiUQke3B8GrSVyqsZ8pQlnGHIAQrfGHMYkHTymZ2TOb/Pye
         BiAPjDVxJ8JBWmkltTZ0B6ydG7dDULstziFbdvjG1syxYF4xobGHdiZjJH6fpXzurXHx
         JINsL6GGa6ITt/HCWwkMiGGBlfxMIm/jEaN8WXWS6HHGMiGxWThZbrFd89BHBMNRP/m3
         hJGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyKwFes5lLywsCBKPdPNFsybNpWAQqcolr4ZtXboDzOVOvVFyLS
	T5Iq9wxczAhofkJhhAt7rfo=
X-Google-Smtp-Source: AGHT+IFX/MezoDcP2T1uR9H1MCSHqL9HIFzyVvDNS6d+RALUQbNipGwbb5LxtlD7sVEW9R4jE01q9A==
X-Received: by 2002:a50:9b5d:0:b0:53d:f4a2:5140 with SMTP id a29-20020a509b5d000000b0053df4a25140mr23181268edj.33.1699301632704;
        Mon, 06 Nov 2023 12:13:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:453:b0:536:17f7:9f24 with SMTP id
 p19-20020a056402045300b0053617f79f24ls1282268edw.0.-pod-prod-08-eu; Mon, 06
 Nov 2023 12:13:51 -0800 (PST)
X-Received: by 2002:a05:6512:128b:b0:508:126a:751e with SMTP id u11-20020a056512128b00b00508126a751emr31834606lfs.36.1699301630815;
        Mon, 06 Nov 2023 12:13:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301630; cv=none;
        d=google.com; s=arc-20160816;
        b=OqWxXxeJXwjvfHA3+ljOVZD7mMeI03eR8WJKAxIFgpJAvHco0WL/ICEcbxAYmdGn7S
         1Rp1OvCvDWK41CNJq0rH0wnOLzWw317V8QnX9TKR8tkO+fX/MKIqiBwO3gp8+qJ/B2It
         ZRtZy56du6pJs/oh8tfwpxQgNRL8VYtPE43VxrVOYr24ki9dCOHXxKmz2YrJFpyE62or
         dWFxtGMfkA6Cn/M00q9mODAwp3rLn0VACq1QhkGXXo8b+j4X2i3gD6ZqrF/JFl1dMcgL
         6di5w0Tb0rd6fMi6gDBiJY+9oeXEpmQTKTFq11NBLz4WDzd2DIuM/u9vttShc/HSWgVl
         FPIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=e29xpsueqsta+pB4dpMwNezQWpITpFZrOcR7dgpqXnM=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=Eih2y32mSd6vzr5xcJCwdCV0cp7UACDXVLeHTn4H3P11EavG5HcCnVvJt8Z06y7Ep6
         q5higPrrVpASrU+Qgdn+TGFpBrZBt11kxvXaOKvWloEgSOSLwZJJ2/AMySSUyiO0lsJf
         u91ys5NkjmkD/pSUUHqhs7kZXRje9rkxh5/UoURM7vcZqbh39JLkrSrnLCH5L1MhX6Ns
         KjGY9t3FxCKlHXxNDIs5XBWjwzsPUG3rksmYUYkUmb4eP8v1apbE3aZLmTITLzs62KHZ
         Lelh88RGtZ3TEm2+/QiK1UIP8EpZ7FzGovUx6eHQhbAssb+fglurb12KBE5I0WuoYHPf
         yKMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="cb/DYhw0";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [91.218.175.171])
        by gmr-mx.google.com with ESMTPS id h14-20020a5d504e000000b003263a6f9a2csi32766wrt.8.2023.11.06.12.13.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:13:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.171 as permitted sender) client-ip=91.218.175.171;
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
Subject: [PATCH RFC 19/20] skbuff: use mempool KASAN hooks
Date: Mon,  6 Nov 2023 21:10:28 +0100
Message-Id: <13e15a27958e63070970ca4d7bb52c8c156bfa02.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="cb/DYhw0";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.171
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Instead of using slab-internal KASAN hooks for poisoning and unpoisoning
cached objects, use the proper mempool KASAN hooks.

Also check the return value of kasan_mempool_poison_object to prevent
double-free and invali-free bugs.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 net/core/skbuff.c | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/net/core/skbuff.c b/net/core/skbuff.c
index 63bb6526399d..bb75b4272992 100644
--- a/net/core/skbuff.c
+++ b/net/core/skbuff.c
@@ -337,7 +337,7 @@ static struct sk_buff *napi_skb_cache_get(void)
 	}
 
 	skb = nc->skb_cache[--nc->skb_count];
-	kasan_unpoison_new_object(skbuff_cache, skb);
+	kasan_mempool_unpoison_object(skb, kmem_cache_size(skbuff_cache));
 
 	return skb;
 }
@@ -1309,13 +1309,15 @@ static void napi_skb_cache_put(struct sk_buff *skb)
 	struct napi_alloc_cache *nc = this_cpu_ptr(&napi_alloc_cache);
 	u32 i;
 
-	kasan_poison_new_object(skbuff_cache, skb);
+	if (!kasan_mempool_poison_object(skb))
+		return;
+
 	nc->skb_cache[nc->skb_count++] = skb;
 
 	if (unlikely(nc->skb_count == NAPI_SKB_CACHE_SIZE)) {
 		for (i = NAPI_SKB_CACHE_HALF; i < NAPI_SKB_CACHE_SIZE; i++)
-			kasan_unpoison_new_object(skbuff_cache,
-						  nc->skb_cache[i]);
+			kasan_mempool_unpoison_object(nc->skb_cache[i],
+						kmem_cache_size(skbuff_cache));
 
 		kmem_cache_free_bulk(skbuff_cache, NAPI_SKB_CACHE_HALF,
 				     nc->skb_cache + NAPI_SKB_CACHE_HALF);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/13e15a27958e63070970ca4d7bb52c8c156bfa02.1699297309.git.andreyknvl%40google.com.
