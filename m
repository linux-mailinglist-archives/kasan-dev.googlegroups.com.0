Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEVAVT6QKGQEHKRGVSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A72C2AE2B5
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:32 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id r13sf15767ooi.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046291; cv=pass;
        d=google.com; s=arc-20160816;
        b=V5t64c9FhM15k72vb9vVVfmb2MMeAdTkU3yL5CZzlF4FsuZ7dbxfRaTxsLSkktc37+
         dW27JSpp+OjTQEWXs6YEI0Fgk9x7ZoE+wezhzEtoXbxlaClCxt3O9kMN9oQwwuRLHQuL
         UCaTR/s2xfOsy5Anxb32PDo10abO5Y56ZLcdkacB8MeTxKMQCDwbpXnQet5ks8q/oWtn
         Wx99skrCsJF2smlltwLyVXdFeCyYa5nQWi5FTeXj+7Sze99SILDE4+O9BGwBrhcLJD6m
         adJDtNSJZem0PAalGnioEeIkQfCtfUOvnGtBR2nYJ3DQNkBLFwj2Fr3kF8kRKT0jvga8
         9bWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=I8kJIlMDHS5k098c4kYx8YXf1d9DcPjoT0Fgax1nYTw=;
        b=jVh3XZLZLo6Q3/yYFlX3GopFPgtmkRHVZmBpwczNpXI0ah7ON5kbajrR+AgL0E4w51
         W2+xTc1iD3N5FkNSQ6Px6NI5+oMV+TmIkSt0YAJOm1qJ+vqOX5OyXzar/JiPfb78OWnV
         eRSoTakx0k0CMNorOpD4Txd8O74xGAqpSjK5VCdh9NhLszcMuZSfoGiMLRvbqVoTBgmf
         HVg+DwvrWtJceNd+Z2Wb3UVpvoGkwYwnG85fy1LAv3HQ36Lzjl0c2XlyAFAfCQnERX+m
         kc1tZSklD6y5PeQ0Q9bndWy8C2snXRf26CxYUuD2D8A/QyXFz6SCyUVy+hFej6n00neG
         dzog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SBjXenKg;
       spf=pass (google.com: domain of 3ehcrxwokceedqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EhCrXwoKCeEDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I8kJIlMDHS5k098c4kYx8YXf1d9DcPjoT0Fgax1nYTw=;
        b=sOLh7Q0h36Vi6gGH1En6KOpMDO4qfq2FwU/Ln/EJr3D+PSNi/aky0xW7DXk3yI19dN
         60GI9/R+LWTaULNZiL/yRkeLXnZ1ZcgioVLYxis0MJj7hV44RbvUHpWAN/3WNkE5+BQZ
         rDsRn+8bYYeCQ1r4b2VfTGLMXreaQfDE+AMM/sqiLzIsH+Ii3cHkDyLMfOLGDjF6XaHC
         6osC24bedRWtAx4AFUa6YlM4gZ4QwF0t8MtBIl6puuLz+zkPnFAbRyS2JPLCZZRrJpJb
         ktTujtfWqrO5IS6cVJxYxb3lGWNSmoAHkS6lXu+fGvOBVbxlJke9SwM99AE48A45mpr9
         RaAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I8kJIlMDHS5k098c4kYx8YXf1d9DcPjoT0Fgax1nYTw=;
        b=KqXR5UsHAhqIzBdulEgEXMn+5WdFUmrPZrBNqzJz0LAsm++rrcEEVdzXkJ9TBh5Pp7
         FBl7va2mOG2Ejsa1zOZoHh1GJl+VtLhGtxRj3MAHIcUK7cLH50pUSOdXm/bD/ORd1ueC
         K0l/W50prNEgxYft/vB2/UDn7yQB/MPFAQGgnWoUXAEWt1AijjKYoPzDRAtaqjP6HZT0
         nFqZJOl1MugyOeJvm73S42kA4hVNlACOjqG1IP7gXG/v7VET4xOOs9FyIjjbU3EX1NKk
         xMfBAEXDxtNcK7fAhUPxPqh7tN2Z6vK1Y5NIR9ED6JUmLwTAKakS7mDsB7UQ4TnZujJN
         88iA==
X-Gm-Message-State: AOAM5316wUA5DiEK7vuenvCP0Ti0I1NafdENdsenjohjQfOHaBHd3+9f
	Uz/vS3GKQ+tkMMbQ8Rn4yAU=
X-Google-Smtp-Source: ABdhPJxUE3bFQEUrPB00XoNo35LQpbfL79eWFVgv+CEo0ldKBy84Oslf6f4xl7jPe1rjcxXnoSwPZA==
X-Received: by 2002:a05:6830:1694:: with SMTP id k20mr12897242otr.144.1605046290940;
        Tue, 10 Nov 2020 14:11:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6b0f:: with SMTP id g15ls3438232otp.0.gmail; Tue, 10 Nov
 2020 14:11:30 -0800 (PST)
X-Received: by 2002:a9d:20ea:: with SMTP id x97mr15964076ota.370.1605046290529;
        Tue, 10 Nov 2020 14:11:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046290; cv=none;
        d=google.com; s=arc-20160816;
        b=xs+RX6OON+EYSOHycBpuqhAEHnbGZsJvkXZLr2SFrdQtF5rlXqf54xVs4EBXouOHCp
         r70TfJr4yRLF70zvmpUpLcFSafjeuiJSm/C+MwqWytjn7G0Qdl9qX7u8Y8SEFL/fuV6E
         uuTnFU1DhfNsEI5AXSSoPe0+SPYSSRXB16/NbxHBemOG8OSmMyhIsbtq58KQp+sPRPMN
         xOJqKnt0B6hrypjrLAw9yg48Pv2JfSKar5oX6kLHvOubhZnne+axzii0DMpIP/3oVrwm
         1t09nzDZAfXo/gHUUjo7Yp108c8W7b1AchLB5g1vFa2UMHFraS7WSK5AQ7JdtJFvfCOQ
         h34A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ku1ALkNUvDBR4qencFY/mbgiU7WPy6T95MRyq/FIMxg=;
        b=T2TAN3UxYqe2jroz++tDNUbF5kJahSz+/9jXz7seOolne6RbfN3cIxlmqxJhAr1qjC
         9ys0QJXIw/A73a1hLWnhMXJYkoff1AdHrfbLUqzsXO0B/6kqJeGyEuG1sdbUo9+tFEtL
         4nV+RFXysoUcvSLMDk/4QY8Y1LxKU11F3HuXJ7+8nVojWHKM5hWJDB8R58A6OaaddFOO
         KQoNKTxLU6aGeSGedL80KF6TiTRGNWH1If3Gk26frzYq0pO3z4b9l0n3w6bgnwWeGpOz
         y6aBmSCDc4AtnH1djbNC0f/lLqY5nK4CDjEe/e48206ofYwDBCnq1S/+SEGbxfM+OSk1
         aL/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SBjXenKg;
       spf=pass (google.com: domain of 3ehcrxwokceedqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EhCrXwoKCeEDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id o23si18244oic.4.2020.11.10.14.11.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ehcrxwokceedqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id z14so4304292qto.8
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:30 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:10c4:: with SMTP id
 r4mr21419097qvs.62.1605046290015; Tue, 10 Nov 2020 14:11:30 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:07 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <85aba371903b749412fac34e44e54c89e5ddae30.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 10/44] kasan: define KASAN_GRANULE_PAGE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SBjXenKg;       spf=pass
 (google.com: domain of 3ehcrxwokceedqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EhCrXwoKCeEDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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

Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN code
to simplify it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
---
 mm/kasan/init.c   | 10 ++++------
 mm/kasan/kasan.h  |  1 +
 mm/kasan/shadow.c | 16 +++++++---------
 3 files changed, 12 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 1a71eaa8c5f9..26b2663b3a42 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -441,9 +441,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 	addr = (unsigned long)kasan_mem_to_shadow(start);
 	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
+	    WARN_ON(size % KASAN_GRANULE_PAGE))
 		return;
 
 	for (; addr < end; addr = next) {
@@ -476,9 +475,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
 	shadow_start = kasan_mem_to_shadow(start);
 	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
 
-	if (WARN_ON((unsigned long)start %
-			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
-	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
+	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
+	    WARN_ON(size % KASAN_GRANULE_PAGE))
 		return -EINVAL;
 
 	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c31e2c739301..1865bb92d47a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,6 +7,7 @@
 
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
+#define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index ca0cc4c31454..1fadd4930d54 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -161,7 +161,7 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
 	shadow_end = shadow_start + shadow_size;
 
 	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
-		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
+		WARN_ON(start_kaddr % KASAN_GRANULE_PAGE))
 		return NOTIFY_BAD;
 
 	switch (action) {
@@ -432,22 +432,20 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
-	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
+	region_start = ALIGN(start, KASAN_GRANULE_PAGE);
+	region_end = ALIGN_DOWN(end, KASAN_GRANULE_PAGE);
 
-	free_region_start = ALIGN(free_region_start,
-				  PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_start = ALIGN(free_region_start, KASAN_GRANULE_PAGE);
 
 	if (start != region_start &&
 	    free_region_start < region_start)
-		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_start -= KASAN_GRANULE_PAGE;
 
-	free_region_end = ALIGN_DOWN(free_region_end,
-				     PAGE_SIZE * KASAN_GRANULE_SIZE);
+	free_region_end = ALIGN_DOWN(free_region_end, KASAN_GRANULE_PAGE);
 
 	if (end != region_end &&
 	    free_region_end > region_end)
-		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
+		region_end += KASAN_GRANULE_PAGE;
 
 	shadow_start = kasan_mem_to_shadow((void *)region_start);
 	shadow_end = kasan_mem_to_shadow((void *)region_end);
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/85aba371903b749412fac34e44e54c89e5ddae30.1605046192.git.andreyknvl%40google.com.
