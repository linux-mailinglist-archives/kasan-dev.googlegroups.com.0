Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQUCRX6QKGQETEIJCCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C0B42A7382
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:15 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id e29sf155629lfb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534595; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ght53FwIvJZKIAa+EpmKEaKaBgWIVt84Ut0Nu/IKJPAYtZfF/COfjNZZSaJzVW5G8b
         Nu2sHqc9KjOJi5OUmHU4WVpJVYS7dLHbqI6QUqC0A9MwT7ifyIRDJULtgULcGvbWDVlk
         18bQWdEIM8yAkbGbhZvNc1qAy6z6nPVW+TaukAr9Jlq3yb74c8oJK1ARLe/137EcNWjg
         rtt0Oy1oDSXY6w9PHfLUwcPTb2YzZOUjReNSCr5kGQqwLB0QWe3vvM4+AAotOJzkVJSb
         12AsK45GnWCcALX9izGon/mbAZ4LqkPGadDB2YFO1aiPlBVqxT0c0BQh1IN56UDl19jp
         AEhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Kahqlpde/S3466+pqO/14pj7UWWh/PBInWcKvsfN22Y=;
        b=K27g7aWxaY+zZJ5kZMwLA7i303bs6IjjZ05vTBYJWh9+ZDF5jG57V9KFmKnYmWnnln
         eEUQ+x8j2305begpM0cQHUW47IOqA9oK5xFEQSzbWD+EVrEG3tZMF5LPS6h4auudlhN0
         I54IvqIPUdtxIsGSQ5DlTbWFbTKZ1jbofXHd/jztbKgQMxqUqS24z+EaifqY/6EQlFYj
         o5/TpK7no7TqRK18a3UMHHCu8+zQCmxl3ZyhJbJAUYO6NDRYJZ67kZHBw90z6IMWhUTW
         XgnHEzcKvBHxgX5uy8OHOGYGxdRQvbTy9xe7nvxbXzCpL6iUpeZ/O6ETDSCne423+wPN
         rjow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QLuAbvZH;
       spf=pass (google.com: domain of 3qugjxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QUGjXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Kahqlpde/S3466+pqO/14pj7UWWh/PBInWcKvsfN22Y=;
        b=Pxxrje0TT8ImOnbqEUiDSRc7uT2a3adijsdKAWubG701zagLx/qZBb2gCEz4O4HWTU
         6j2ZP8yYktDHukwBJ90OswyFHQyHNOXK/+uoH1eCYSkiafQsM94EtJs9Y40RPRzOAqeJ
         O64kqq+gHdjiDMCa03glbWZkwKKJLdesOaGwkwhgv5Vgwi9rAa9w8JD/2NfCSU5GXmOT
         IVXaSlAKdZLi1iCOHZ4wC+9Kd6Oce2ynmQxZYnzQ6MZ3/X96G7LKFCukztBUCH3gmR+t
         ZYna+XSNAawV8SeIxgk/IeAwimJsExCE1DSf49GDjOhMPfdw43jieb/wER+ia+fRTQG1
         3Z8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kahqlpde/S3466+pqO/14pj7UWWh/PBInWcKvsfN22Y=;
        b=Fr2QWEaD6FrN16zw3vTI1rWNm8tJbILV16+oZ+QPbtW/2ZL+UeHCmlAbgLtyAt44sz
         QpzMMP3bgXNrHnid1smFI/dTzeKt9Om6HU4O3VLrHKuqj5dCzPHJ5W+ZaY7gPVdjZp4y
         5k4vFO/Bu2Uoyjvtm+gcMgtpPHjlMSZIPM+iMjhbfRMcc9UfDjwyKMfDZLrhVPB8vGfU
         iawhdqyZu6JfMiWUWbHymRYG8L1S8tyUF+oPS2Wb7l2fBSZWCOBB6tIbQT7Kivg5YSMM
         VwhetclXeqZ6L+TSchne4BCnDJuhmLdf9imuWPNZDmTuX5bIxjKKACMvfmfYbhuteM5K
         aQTg==
X-Gm-Message-State: AOAM532GYgofNUCKZeCBGlPrZMlnPRvoGCKGPYtx0ob7Z9MaAcSyeJcr
	c7riG7pUJsMRi/W0EdHJNpY=
X-Google-Smtp-Source: ABdhPJwEvwR7P+5lAIRfeJ1zI9sUlZ3tj/AgrH+qCaK6SVKjwiCcnMflPwGEis9Mhsa4F6zlAKRewA==
X-Received: by 2002:a2e:8845:: with SMTP id z5mr169841ljj.216.1604534594631;
        Wed, 04 Nov 2020 16:03:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls2302212lff.1.gmail; Wed, 04 Nov
 2020 16:03:13 -0800 (PST)
X-Received: by 2002:a19:2d5:: with SMTP id 204mr65605lfc.117.1604534593734;
        Wed, 04 Nov 2020 16:03:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534593; cv=none;
        d=google.com; s=arc-20160816;
        b=PefpTQ1GenrWjQxUzxeHy5jC0+pvuXaI8XTHVh6MEOa4EYp76lniQhyxQJBP3Zo0n7
         3yGxuhVi2Ukw5MtYZJ62Y40luV0Yqkl88r0xrOhSdRHPDZQDwHqtC2iQoDsM0zR/vSwz
         atwyYXdw+2kdmJXDRbEuhlin1qpSs16Ql05NMtzPrvnoP2u27s3BadxbYLfClarN5dzo
         dO5g5UiI6mZeeunxcCMqeVLn/fuREdVPpw/BqGUh0GdVYiaY+Jf+YuFFrejE2O6HHXZB
         dztRhmuPGMCVbTihn4b9ns5sFEAynhXJ9+0ldIuAFvqCMNlfyTgerOYID7KnTjY03gyL
         yDXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=KFrv2CeYC66xd7QOOp7G/eCqjg0M9rtzwQxn1AQSEo8=;
        b=DS0pGpj6fQvUr3OVKFw3R+94Heq0BZQ31wLv8E5VlkAScuSR91blXliziqy2I96czf
         wrt2CbpbEUpEMfru+KGopNT37kwIqgt2wioHGwMeIQvldoTS8HbQAluHY3JGlUsVZMPF
         mf8/AHUp2uc7LKEpJ5rN5DwLtEwNgVOU2OnoEgw9LUjgjYbMWHvyWyUOwFaIGVJfPW9h
         TrBwCC1JMnhFS5HRxgAxjgs840Rtvh4BZ3ltazcqBUZrJxPMd6/ntOpiOMvQ8vv3yR6t
         GMxZ1MDh9Y6Y/DWDG9Tjd93DCfKN4Ek/TNGyTME/m7XYTB1nnNYnHbtu4bKlMpnjovOR
         lGaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QLuAbvZH;
       spf=pass (google.com: domain of 3qugjxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QUGjXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id j2si75938lfe.9.2020.11.04.16.03.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:03:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qugjxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id f11so90997wro.15
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:03:13 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:9d02:: with SMTP id
 g2mr24703wme.110.1604534593196; Wed, 04 Nov 2020 16:03:13 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:26 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <d4149b16fe2fd29e57a0bb8d997354676f76a183.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 16/20] kasan: simplify assign_tag and set_tag calls
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QLuAbvZH;       spf=pass
 (google.com: domain of 3qugjxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QUGjXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I18905ca78fb4a3d60e1a34a4ca00247272480438
---
 mm/kasan/common.c | 11 ++++++-----
 1 file changed, 6 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69ab880abacc..40ff3ce07a76 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -238,6 +238,9 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 static u8 assign_tag(struct kmem_cache *cache, const void *object,
 			bool init, bool keep_tag)
 {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		return 0xff;
+
 	/*
 	 * 1. When an object is kmalloc()'ed, two hooks are called:
 	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
@@ -280,8 +283,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 	}
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		object = set_tag(object, assign_tag(cache, object, true, false));
+	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
+	object = set_tag(object, assign_tag(cache, object, true, false));
 
 	return (void *)object;
 }
@@ -362,9 +365,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
-
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		tag = assign_tag(cache, object, false, keep_tag);
+	tag = assign_tag(cache, object, false, keep_tag);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	kasan_unpoison_memory(set_tag(object, tag), size);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d4149b16fe2fd29e57a0bb8d997354676f76a183.1604534322.git.andreyknvl%40google.com.
