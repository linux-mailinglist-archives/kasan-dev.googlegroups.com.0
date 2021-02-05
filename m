Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRMD62AAMGQEUJ4KKKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 3117C310EC4
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:07 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id c22sf5866245ljk.18
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546501; cv=pass;
        d=google.com; s=arc-20160816;
        b=MUP7IwQYcZ0Ubp6IxczRVnX48I1o/aja3DeOpeAgqFPzThEIeSeUHcLmCkWkUf0lpt
         hEMBRRojJjaSRn+pyDrsedbYFmOXKI2zfa0GUtLEwTG/iY4GQPfG6uXr09eGVr+a+vx2
         53v9aXFINbv25xsazHtBvcGFbsnH3HUBgHQYqtKPg+n3HqonupTgUAwMW+gFscmUPTCi
         xrJYBV5c6gLN/NOH+tQlKzwqCw0zs0EgnFtobe9/FgqVxKrMqrSMImg1YM7+AbpAUjmS
         ER4UnWN0DoB/6Sk/yypJ0pZ2weIRhPMexJjZkT9znSyIlwuXUux00CyvVBn8++1RYCj0
         qwwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=r1KRs8vRHQMS6ccTt31iepWG91s/i40wH1eMhbYyerk=;
        b=TrOHw4NPo4nVXPbyO1f/SDxN02pc3qL+VTSreUtZMhGTWb9F5ylNWk2nMYtbZtorDE
         c0btF8BYQH+eFVCxdcC5a3H2XGplA1l6VG92I4IgeajiHqp46Hc9VCiagoSILPS2APGR
         YUjqVEWsOPNMylbwp5HocciUvxLKAxt3NmkHW9QWOECY+TPYc9beH0jTQ+foZZA5Lytr
         2gIIQyHr4maZ1MHsnvydt4G4wobPQ6KDRlOt9qqSExfO710cXJM11DtTa8cGr3SCTTXd
         QEjnL1U0RwhdzNQog0fXzNv8w3h5DOBJK0d8DC8k7y/gZltPSvYCXTA7bOtxbZLx1l8O
         DR2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CHtaYiFl;
       spf=pass (google.com: domain of 3xiedyaokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3xIEdYAoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=r1KRs8vRHQMS6ccTt31iepWG91s/i40wH1eMhbYyerk=;
        b=GGhMiVW/1sIhr4LCruc1YuJqlcUmA71+7tkemDwvsjpn7CiQejGvVHS3QmGOuglLPH
         FD+YSuK6oAr/gLuu0N4Ib5n+FL4hQERvvaqCBYmktNgnxSXRVzDIq0ZWAqsmd+QNN7MB
         NlOlZd3oNHkmWteFrBiA6AQhDYBqSYq9XFJPIMraG1bMMQxI/ANmvaga2OQpY4GSJuQd
         5lMnzvTopm1O9gq6pNRRtL8kuIO63tV8Sk0fUiKlD3Mbpl3h6Iil+QT+K+BrH5gQxfWC
         lxeLaN2nMoZl3locbj9XFUwLcT79kta5yUhbIU9rpKx6qPJoqZP0+ON9CbCYAK4cEbHA
         l3lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r1KRs8vRHQMS6ccTt31iepWG91s/i40wH1eMhbYyerk=;
        b=I0kG9//IGv9ELC+oZQ/hu2gJ48xfgSLg79+XjeJNyi9Xz/MduPuaPogLKx4sAu/+Vw
         gwqXdgx4BwkEUR59R22RBsMVQzcuqXHjH1EmfQKfneLgAB3f12EWZcOlvfP7H7N6K9Vt
         or2XxOgD+d2HT9vApGm2pM1uy4P0PGyRwQBhL3fOXUWMZM7hKajJQCf0yySFTFMqBeJO
         SbVt+ZaP73YsKhoubHqhA7qZyhgy0Y4TEMPejHDF2uvUtHb6yNhBKpGQEdlRhxl/JxLG
         XkGdtF5HUwhbCAXD4idxQnCxD5PR08lcPju4CgxJSGR3c9upSw6HfeZNfy0iYeeXWLq+
         xCSg==
X-Gm-Message-State: AOAM530tcUSNHFSqzEvGiZYX9gWiApZfHKoFUqL7fLgATKg7gtz+Xikv
	qRbImCRHO+HxSi+l+LyiIqA=
X-Google-Smtp-Source: ABdhPJyX4DlQSGfpu/1PZ3GfFsCythPM4htBKOniupnebC8I3ykxe8HzzppNWZNwzK6RLY48E6drwQ==
X-Received: by 2002:a19:4f4f:: with SMTP id a15mr3169938lfk.309.1612546501747;
        Fri, 05 Feb 2021 09:35:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls171803lff.1.gmail; Fri, 05
 Feb 2021 09:35:00 -0800 (PST)
X-Received: by 2002:a19:6555:: with SMTP id c21mr3060062lfj.563.1612546500793;
        Fri, 05 Feb 2021 09:35:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546500; cv=none;
        d=google.com; s=arc-20160816;
        b=gt4CQJwboFoDInyPceg7nEdV7W7YbzqN5TZs7pf+gCEtI41vfMNX+ndxaeGY98WQht
         DztS+qqdhYRrQwdydJFZxMhlqJbBpFjUEbOvEGwWeTPbmYdeKyoYJjesUhEFp6Bwu1FY
         F4+mep/C+2h1lPu/7LNEBPCggS/JpL89269OPGb4M/BBr6br4IGKt/bY9+1OzLZ7Rkil
         NlnE1lNB/ka6VLCw8B7hf3ZcSWCTaUMozP8gZ62xCGRzO2juaOt0hiqamBwMB8zodUNf
         IwJ4MdeTPjAWihW8wEEx7GzB5+9YbtjAIIJ+N2LjDmCK1/aXK2mPQtUGm490IaghZs04
         XPpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=p2PHZd2SW9nz4o7+ZB1C3vkb9xhx8DH7M49Qc2p69KA=;
        b=xYLqYNR+NMRlGuay5g8y9E5I0n8zhAKdQRD0aUMteBc8R0InQju8KUV8iBsjpGcKtn
         +L5oXxXwNT9tmuMH+lIYynkc3rNmlpKMIA8qh7yqP1Us6PMrX/H48QzOmRsXG1rqEkFm
         xM9xuJV7kHAZZyBIaU9aitxF1wp0qMoqikdZxCTsn4VK0CVb7e66i+ZOx3YSm+Hx94I+
         JxzvWIuUWgB+OVR3Uwey9HEZMiuq8V3dSQ+q7PJ6oLRfFwWtRgH3CmgYHciSMEcr/QOq
         4vkttTtQcrgJ9iOFYJwqf7K2CYIqHZet8CHrMrUYJdcqf2L7KFBWisI59a2ZjGf+X9qn
         m47w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CHtaYiFl;
       spf=pass (google.com: domain of 3xiedyaokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3xIEdYAoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id c20si428976lff.11.2021.02.05.09.35.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xiedyaokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z9so5711729wro.11
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:00 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:adf:800b:: with SMTP id
 11mr4807938wrk.322.1612546500193; Fri, 05 Feb 2021 09:35:00 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:38 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <f838e249be5ab5810bf54a36ef5072cfd80e2da7.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 04/13] kasan: clean up setting free info in kasan_slab_free
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
 header.i=@google.com header.s=20161025 header.b=CHtaYiFl;       spf=pass
 (google.com: domain of 3xiedyaokcuuhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3xIEdYAoKCUUhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f838e249be5ab5810bf54a36ef5072cfd80e2da7.1612546384.git.andreyknvl%40google.com.
