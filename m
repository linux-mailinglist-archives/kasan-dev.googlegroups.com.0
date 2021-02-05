Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMGN6WAAMGQEGK6DGNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id C974D310D3D
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:29 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id x17sf6520380iov.19
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539568; cv=pass;
        d=google.com; s=arc-20160816;
        b=o3jj7Uq0qGh+NatKjlczy5zLlDA+NyPRuCDbCyPrBKnZutzulvlmqD3IfkkJ8BLz48
         yETMJ/+EJHa2rMJYVoBduZsBSjpC61UWXmfaScPy+S3vj2a8oglhijTk6+vnknoRR37P
         P1yNAsP6/19yrqbsS3KsijrRu2/2ZDYNaAzZx48Udbo+rHnb19x2bM/9nr/WKaGXJpZX
         ZCKt7qFf15DaN7sq4mBOiepSQqTlQN9ul4y2+QFZ95w75GcTjOyfaBJjC0s95fhEm/rq
         Qne79q6BLFl0CpJne4RrOqsh3aNF4zU1E80xVYQ9Nkiw7oGp6bGvU8U7Fy6Dt2jDr7o6
         c7qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Zuf9xNtMuFgxmTcRdYpbYeqQSP5Cabm/GD0ZhQRZvhQ=;
        b=kXV1EIOKfj27KsglV8bv5xs1jza9eWMuC0iSYfku0zFon3ZKfafL7frFh6fhxuYIXg
         ZetlzYluEG2vz+a88prBq0zXq1+X5Koc0Iyvy5YMfenu4ZjYTViLjBwjPIwpGPVFzf9q
         xpQ9FjO4vZBqqwNXs0W/hkvI3Ulf4pb76CNC/NEVt4jlrk1HkIf1bhT0OvwNaHXnVbJI
         xS1+7up00Wkob6dfY+EWO0hszk5soGzgXHsmNeJwKStsTFXOR27+zELD49/C7u3PsjhX
         6uAV0Y5oOiTdb1iaT/eL7ws4cd2gysYSKpRLVHq3jXMB8eKgwBrZYOX1n/AYmcFKvPbS
         7fKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lF3JI1Wz;
       spf=pass (google.com: domain of 3r2ydyaokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r2YdYAoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Zuf9xNtMuFgxmTcRdYpbYeqQSP5Cabm/GD0ZhQRZvhQ=;
        b=L3CFz4+aIjjv874guFF6knH74e3acuQA7s83aa6OUbEDCkE4QUevrV1kAk5al9loXM
         WqrBTNM71oDV9qziO9wNfJp1apW+CvmddE8jqzXRkUf+ASO3NEZAUIduu5F/WJtmGd8F
         MESSLUTt7Au6UtEVv+zDSzwLH1i2FyVNfbk7/9pgX0oa+RUKfXfYSKpeXAiUbr4iWasP
         S8wxTvQqs1bQeUZAIi94qL2rq2tM8eAfE+ATaONYGYeoTxVUvJNYnT2xqZQGaORY7FDq
         aYw/wOS5dwS/hujI9idYWjTsuCr4lG0jpBN4KwQqSt9bTLNqhfX4hXmDPuaL7WU+xXW7
         9z5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zuf9xNtMuFgxmTcRdYpbYeqQSP5Cabm/GD0ZhQRZvhQ=;
        b=mDNAa2h34+6M+2c28N0ylXz+9c95NiSGXhYX0eFlzybK06i3RgHV3ipKDfso6MuigD
         XFqYZZh806OuX21LlbmFyc6OKdD3DfsxeEgNO7REWTN5Uiv9O7mIZEAAH3/2v80Ji71X
         BoLhKPRS7T0pn9CrQgoflnJ+bPxfIoZhiqF7w/rHLUOAZGU8Eta2ngJ5xNpkKyhluOfu
         aw3k6zaS+TSLcd6BBRm5/grq7+m+/rcdBkEa+APnclvdFLzF6IGGq7dqaa9wYPZRxGBc
         qELt8Q7BougOb/qvpbU/NmxPhY4imgYH8o23yNa/m18FGqk4tiyUF3h46vwckg0JUvNP
         05xg==
X-Gm-Message-State: AOAM531va1f0mnr739ITXAdxaHcjQlOkSZwB9K4ydoOqGxQzPMlE96nV
	n7RbYZ3A1p5J04GWE9NAmus=
X-Google-Smtp-Source: ABdhPJxtkTdjP1ceKdxbMq3NFKPBmZ3fP5giMp+S2DbL6OJnw3w6bMN1FlKDe9MLi6sc1MLslciidw==
X-Received: by 2002:a92:c90b:: with SMTP id t11mr4474461ilp.275.1612539568686;
        Fri, 05 Feb 2021 07:39:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:80cb:: with SMTP id h11ls1611393ior.3.gmail; Fri, 05 Feb
 2021 07:39:28 -0800 (PST)
X-Received: by 2002:a6b:f107:: with SMTP id e7mr4691034iog.191.1612539568025;
        Fri, 05 Feb 2021 07:39:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539568; cv=none;
        d=google.com; s=arc-20160816;
        b=d0blbyA0MjCbsVUUu2QtcbBV4gnvyiZ+VljRs1Hmrebm1H6MyacZV6fJ0ZWs9/5U4w
         K0n3xi178l5KG4MD4Ta/1qEPjoGr5431tpDCuxYe9mX/TkPB2MUJClo4Nc+vXB463aZo
         d8spzaS/DwDMNZzUrKALuIrsM7mb1jHo5THN5t7zxpULPoX3LgY2hzCWge5rKGouMwIM
         8bXNPdcLi4elVYvfF6TnkeSkKH/Z/EgayDPVhLpj4eRDPex/kd00PeY9PJxRFRhRKC+C
         DHqT8MDmGeXcYlFHbcbnGfsEwQj+zhnmvdYhLxqBHNKY57lHh+NNopPNIha33Vh9USJC
         sl3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=p2PHZd2SW9nz4o7+ZB1C3vkb9xhx8DH7M49Qc2p69KA=;
        b=rbf1dEqtWeDPjhdqqM77cUS93tw63tNtLb1bk5/sdRLVXTGnHuPaCD8DvYM8QE2j3s
         IQHRX45TOMOL+3zXsX7Mc+lHv81jqTazHz0Kr3OGymQaruT69ZDqJdrpxhDrSGRsiTp1
         57YvEK0iWch4oXIruSxZysKFmH9lS8MH/fBf69zluoEt6u1jtGYMgKvvZhiBEIgzEGfG
         J2KwXAboPvv0OBhNgMT0aqmCMwdAbRhPIFWOUiKnhQqVTZc+OrXssh92QiUpNBhpSMRX
         x+4k7pgxYWWDCG0wYCz7xxSFqQF5fBD6Ai8qX88zQJ6A80SQCRTrzmdqSbzZvo8QOOuX
         j6Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lF3JI1Wz;
       spf=pass (google.com: domain of 3r2ydyaokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r2YdYAoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id o7si586697ilt.4.2021.02.05.07.39.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3r2ydyaokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id h13so5245906qvo.18
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:27 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a0c:eda6:: with SMTP id
 h6mr4862060qvr.19.1612539567383; Fri, 05 Feb 2021 07:39:27 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:05 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <ece9cd2cca38dd3797c6cd1756e30a2e40b0d451.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 04/12] kasan: clean up setting free info in kasan_slab_free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lF3JI1Wz;       spf=pass
 (google.com: domain of 3r2ydyaokcfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r2YdYAoKCfgfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Put kasan_stack_collection_enabled() check and kasan_set_free_info()
calls next to each other.

The way this was previously implemented was a minor optimization that
relied of the the fact that kasan_stack_collection_enabled() is always
true for generic KASAN. The confusion that this brings outweights saving
a few instructions.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index f2a6bae13053..da24b144d46c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -350,13 +350,11 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	kasan_poison(object, cache->object_size, KASAN_KMALLOC_FREE);
 
-	if (!kasan_stack_collection_enabled())
-		return false;
-
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
 
-	kasan_set_free_info(cache, object, tag);
+	if (kasan_stack_collection_enabled())
+		kasan_set_free_info(cache, object, tag);
 
 	return kasan_quarantine_put(cache, object);
 }
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ece9cd2cca38dd3797c6cd1756e30a2e40b0d451.1612538932.git.andreyknvl%40google.com.
