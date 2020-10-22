Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDMOY36AKGQEDXMWV5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id D896D295FBF
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:20:13 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id b11sf623860wrm.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:20:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372813; cv=pass;
        d=google.com; s=arc-20160816;
        b=UmQSRQZluaqdjr3bNoxTFsdlIzPHRVt36oBCPnUrwMSlAsYx/J0r9QSZnlgx8pEjcA
         o4gzLOhZLgSn/OKU0ursU7pB+wA0CHwZT9DGVTaqJNgOlL6oUkNCF2QoK/C18Q7ctQvM
         tVWSItxKoAabGan86XQV02HkI0W7IqPaaBYtzpmhPIpRokTY6LE+SOedjUqacCuf9Tds
         VHIR0YsxY4EBrg1OYV37iStX3Hsl3VOm9vfRmW/nfMswnZpFFQCr0ldMJs8bu1sujeNL
         5psiyRfvcsi+RT00wpTbNbaQ0VYT8lpWe8Lsh8jL+A1OW8Tbj463t8HcNDavXjhZpGSi
         9DMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=BmVWxxBTW5U5/QqjYIz/LKLfvR7Q/D4eEhPtdnw9Mns=;
        b=0Hu0+DCwllJ2YhGAGKPv/teCBMpAKmtldMb/Aa/qQSEgTjCVEas45PSMv/O4rAIj8N
         Z7BKNtzWVPAYjksN4AxNfNFfBRpg+5mX/lskrI+d69tAz3/AUacrvc3WAF+Divhdk5CK
         hmNXSlISyJ/w03Vmh54ugwqbJu72rxzE2M54d1GTInibeyOQK6JNYdfBSQPl81PzxE1e
         NNP4wZJmsDjYwSXwETlRFIAjk+sZFEhI6XLffTuCk977SSmLwpyACuDzd3sqN2o72G8J
         0tfQ79DQyOwtP/CzUzJ8WO2EUSnjzhRN5MHJ9knejCsXscrmAACvIXBKRSwBS7Shnw5l
         uTVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HfX7ercL;
       spf=pass (google.com: domain of 3dierxwokcwmboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3DIeRXwoKCWMBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BmVWxxBTW5U5/QqjYIz/LKLfvR7Q/D4eEhPtdnw9Mns=;
        b=hAHDpE/dHsbnxPLVy6lETF3dbRPlDeN7PT+35v2syCvX3fkMQ64a83kli225unkyo3
         4fUSSmokjhvF10KdwyjHS9bakUg0Ce4BSRgxwPBunYRTied5QQNa9XRqLQ8IuV5IjKNu
         uW9p6Mg3EefViS46ANkaXS2M7tlCVnAgHYJ/EKKUN/V0T2lSiPNXKmRBQbTL8Ec4PJ9H
         zSQ8ATRAU66BeCxnLBdDfToZ5dLmlZ+AyLSsaoh5T5RHXd9lr3DlDZizv6AoBsKGP0+k
         d+1/0fhIw70nXJ1TNjVfR5edRAZX3/Su8Rh8zjcoZGLKkadhc9fru6UvivijbYncW9Fe
         HXXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BmVWxxBTW5U5/QqjYIz/LKLfvR7Q/D4eEhPtdnw9Mns=;
        b=PgTDiyia4rNULm55L0m2Za/V31zqrbiifNf/07bPoLwZ+CJAEVwKZMNGpLmPLgFgIS
         Uz5clELyMS4dMlwmDPafqL00GCw4kLKSXg8uz1ktJ2DQzv6Uxk47TCb1FhvTbgfmTS4a
         1VQTHmWocRANG+eDSGvrrAuuSUJKF37IO+anT4bgm9vjU48EzgYa0mmbhuaiRKqRCKc5
         G7GHlHCvspTO1+4DeRQNAkMKd6BnchfnEButrg8wEPNGoyx1kHh9i+bz2QP6rg+9nqq1
         ecaK6QYTpzTFOgGcjrPVlA7/u6mfeY/S9FtN6bKA1GiKKGNZlKfuRzvlFNW9gLmGBevq
         1r8w==
X-Gm-Message-State: AOAM533RgWdwaYC8j+uKzgo5gztfJsL/ZR5TxWYkyJeV0tSKd4CPkvcb
	1QjgZ1GnyGIDsaEYpFNHHYI=
X-Google-Smtp-Source: ABdhPJw1CaE9SrOqQV+HCYY/UByVJlVcEkV/NKqwTmkIJu0xhzC/UTsUauRCAUifs8KqBBWfxd8SVg==
X-Received: by 2002:a1c:a90e:: with SMTP id s14mr2611463wme.46.1603372813624;
        Thu, 22 Oct 2020 06:20:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4e19:: with SMTP id g25ls1004365wmh.2.gmail; Thu, 22 Oct
 2020 06:20:12 -0700 (PDT)
X-Received: by 2002:a1c:3bc3:: with SMTP id i186mr2652483wma.112.1603372812807;
        Thu, 22 Oct 2020 06:20:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372812; cv=none;
        d=google.com; s=arc-20160816;
        b=Wt6uqc0cnROXL75wc9WV6kmVhaPvIL4N+FK0asXnrOA+n20OlZyyCwBL/18VAVsyqR
         dmBQvsO8tSm5temaBX7/9BqF/CPn3DMNlTuHk+hA8WzkCLpZl4wY0sU2/SZflo3YAIhw
         I/veBthcCCtq8BXDvb4GPQSHzb0w7T7jRml03sro88XMAv4Y2/zuLUgsd8RM4AW2xM6X
         N3xqg9grZln6PTgkGjwNNN+oQPbp3Hg3gRWVAtKuh88lhcwrbSBPklwsxrwhrmgk5LD/
         TRt+syVjcE4/up0+DLqpWxpJCU9Gly5qcFIsex/BxFMxbSUZ8IbT8nv377pYJv4KGxLb
         MvvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=xOXxdsX9wfgVlPASo24fEeH7IiHQsViadxCdQzhZ1/Y=;
        b=YY3+o377c3y3Y5ZzgHEHnmdwcv+/8lCQcQxvABf0+PhuH+ogz2YRPnzeSHLGUvjvDF
         im803tDO4dumQpaajIPVt5nE3cUZ0lDoAG1w1qVELVALCq9ncmh6oiLHIY2GYaGGhOtC
         xToRg4xgaLek8NS5Pdmr4surlgTm3YdaXSDDkojz/7KEvER8FYpGU/Q4yntjMa1rqJgM
         Rdu1bwFkHumBkEY4iaK2euRaIOtcvTDQ3J88bzspJdpjlHilTqgF9fYMyNic5pZ+tLKC
         c9tkHb2t2uGk8rrm6pxq/sra4jj9REYYftbO8desppPZUZ3I+VfV3F146nCmPAYCWlgf
         AdSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HfX7ercL;
       spf=pass (google.com: domain of 3dierxwokcwmboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3DIeRXwoKCWMBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id n19si66647wmk.1.2020.10.22.06.20.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:20:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dierxwokcwmboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id v5so628637wrr.0
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:20:12 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3503:: with SMTP id
 c3mr2468528wma.43.1603372812346; Thu, 22 Oct 2020 06:20:12 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:12 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <6e866efaa7620162a9824914186ce54b29c17788.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 20/21] kasan: simplify assign_tag and set_tag calls
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HfX7ercL;       spf=pass
 (google.com: domain of 3dierxwokcwmboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3DIeRXwoKCWMBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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

set_tag() already ignores the tag for the generic mode, so just call it
as is. Add a check for the generic mode to assign_tag(), and simplify its
call in ____kasan_kmalloc().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I18905ca78fb4a3d60e1a34a4ca00247272480438
---
 mm/kasan/common.c | 11 ++++++-----
 1 file changed, 6 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 983383ebe32a..3cd56861eb11 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -235,6 +235,9 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 static u8 assign_tag(struct kmem_cache *cache, const void *object,
 			bool init, bool keep_tag)
 {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		return 0xff;
+
 	/*
 	 * 1. When an object is kmalloc()'ed, two hooks are called:
 	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
@@ -277,8 +280,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 	}
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		object = set_tag(object, assign_tag(cache, object, true, false));
+	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
+	object = set_tag(object, assign_tag(cache, object, true, false));
 
 	return (void *)object;
 }
@@ -360,9 +363,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
-
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		tag = assign_tag(cache, object, false, keep_tag);
+	tag = assign_tag(cache, object, false, keep_tag);
 
 	/*
 	 * Don't unpoison the object when keeping the tag. Tag is kept for:
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6e866efaa7620162a9824914186ce54b29c17788.1603372719.git.andreyknvl%40google.com.
