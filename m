Return-Path: <kasan-dev+bncBAABBTUJXCHAMGQENHU7LDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 53A1E481F8B
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:19 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id d7-20020aa7ce07000000b003f84e9b9c2fsf17501603edv.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891599; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z+Yiy4EOVyLlC+lnKO6cFhh4a0qQ8Z4fH8M18/CsiBq6ZGvUZbIgjoeP5zQ++qM7tB
         DBuxCcp8QY6Er4fdJsFUznQp7o82E6ho02DdtkhP3Pkh3loklrVLrNgcfgRAGNX/0qVb
         6bqFkhK8v5YdWI0bZ7ge1vBLqHqnBN9ljoj7lhPMY7BvgD3RSVigng45IOTjwIq/LdDj
         wX8qaxWzYV/w8Zzv7oQ+lvsqWh2PzHCoIuorTxmmcv4RKmACQjJO1mF9Cy5IqbdwpQNl
         KpTmtdiCmtRnpVzRlEoYZVeonvKPe0DKX481f6oy4j1kD7uhqOP/OnoTKTPvJIbT4tgJ
         HhSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Qo2L8qW9fqX9vwzUknkltG9lD9bTt/G25qhigKAkn60=;
        b=Fkwpd05vBJXrGuQgitfwH93S2b7KMK/LhlR4hN/VCLBxau7ZiKbe+NqiqOKuakcbf8
         Unqkz4RIUOy2Qusoqm640Wybxyf7468gk/8qxCoNTX3B4IPjEvaLm4qVvqQzrkOwX+Kq
         CfZfWj8TCTnV4a8gqGoSfhYvD7XqBYRahhqGrUhpV77TrkQgBqaF8NrP/yDmTZ4/Ql3M
         3MS0EANfao76RsraYBo0iUWoXElzBdSmgAE2bP//595JnVvyuASJbx3osyncWvKBGlK4
         Iegcp9iFfKgtuAKJZYAl0fiE5EOxZi2r5kDDTT06lpIKbIB8VO+zS+tU+lECcZ3MTqMt
         qGsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LwOZ1pjO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qo2L8qW9fqX9vwzUknkltG9lD9bTt/G25qhigKAkn60=;
        b=Sl38n2D17KALNv8Jlp3s91jaO+vLp1bHYx6pIplv6S0yi4gfs2Tr+k21NnNGtZ5p6l
         6iAKqEyQHTjA+GYkJf63p5NhejCDKCe3tJ7/OR0hzN4t50ZEwOQ4gCHysVkyxWbzPI6x
         ras3zIeQTsh7bmIdrR1hFdktX+gCuRO2zfI/LIZFmcVfBg+W33Oj49MfJoFNgT9bjILr
         hrfp4H/2ohHBdVDAq/Y6nFz21suCfRwYm0I3XFWR7NgjpXcEKfWA/gWOTxuJQJVeSbD4
         q/ASvfInz+1Skxx9fAehzosRQzXe+JLTx3p853q2COPWACcldru/Tj83OXqgy2j+/Mq4
         fi6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qo2L8qW9fqX9vwzUknkltG9lD9bTt/G25qhigKAkn60=;
        b=ZHKOK3pGYNa0ZA60R2Yw+0eTJPk1sT0wCPbJaFpafKRA+6cJYNTV7Q713b0aF36gHv
         cMDJT3N7XOyAJrbm1q8jd1VlFq7IkTSkBwAy/ZYaO3sLxZVxOjKvELewQjOo0Ipw4MUr
         S2ZAU3x4DJYZgzeSROa16z8qlpvvjpUzAxybER1x1ZkFxB+eSxrQpG//tAp0aA1vgkU6
         bFsphlxgkJCeClFs+hEZsGM+TMvuKL/zXvfH8UIYZ3mOLTnczQ0/vATStJSnBXi4hJ9/
         OLaLE1lOqHv17g/hrmZ0G5YWmzd6TtUaAlam+DmTLALZpVxtks2/ElADXEzB1bo/ibZt
         nwCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xzUbXqx7Ddji10edhIDeih+lyV3Eb22yLrpZnX5LJhKA+8NP7
	0eIajfDSzQLDF94kJsyflts=
X-Google-Smtp-Source: ABdhPJxtYJLy65Yqg/6uqOVlEiMOMZQa3dAsz2OkbdTYhRjutUsNcdc3eh2Yuyzlb9qCc+m5rzCT1A==
X-Received: by 2002:a05:6402:8d9:: with SMTP id d25mr31258817edz.283.1640891599136;
        Thu, 30 Dec 2021 11:13:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:a407:: with SMTP id sg7ls8526249ejc.2.gmail; Thu, 30
 Dec 2021 11:13:18 -0800 (PST)
X-Received: by 2002:a17:907:9812:: with SMTP id ji18mr25410269ejc.184.1640891598362;
        Thu, 30 Dec 2021 11:13:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891598; cv=none;
        d=google.com; s=arc-20160816;
        b=CeW/t3Xzxd8sepmF+MyeN2UDV1QYIA2FSlMobS2Ph6Bjm5wJ2RUTVRA//0s7ApNN2C
         veZ2x0rcYW9tzo8dcDGlNi0ZHcmif4m7S18odWjR9qQFW+XaQgmB7R84MUpG9rpUhpHD
         CojV4CpP6ns77URvHgteav5GM/H39jK63LXXCDNcNnNxxeRZHi4nui7h/2A+RPYRvvXX
         qhy9nTretkQAHi+LpHhiSrjUdinRRXWCGInp7zm3wnm3ldXwerWTQj36/tAORXofeM8N
         Szf6uh7ya3+Ni0L6vFnlLWmnn0JiY+Uhhd6AEFGoBfDkVngOM8Jk1sYx0AXQ1fwG4kOg
         Pzsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4DHacFnXGCSEm/ica2zjN2vX/YyWWuxeEI28IqJpiO4=;
        b=wnIJqpA/3piJTc54UJOgulOO99GQaBixVUhk7fD9AusbJk9hKdEoOdNb/oc0Er9ekE
         X6O0nrtzDBN6Zf71UFjjOv+nsLMQKW0qlA8eM+KuMSkbIpPmTjJZfgAu1XLPNiupYrbY
         cKAE+ki1pPz1ZsWUqRbp+IjJSWbF8woXXw/ujdFqbDATGKdJ5Tx4K2cCqrUBXtLiZCLF
         WSsSM7+y5jGGZ4wKvtgsgKMaxGZklAm7Tsn5qu3mSQA9u9M22bb0jNuYbBAu1eIo/Wqs
         oA4N2buX7vwqzVTEYXy4iKNcsJ71zNZGg9XVTrboM7RBvlmADhUSpLAGgTZcUO7+gPzd
         q+2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LwOZ1pjO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id v8si1348599edr.1.2021.12.30.11.13.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 13/39] kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
Date: Thu, 30 Dec 2021 20:12:15 +0100
Message-Id: <b0915f0de757714e163afe719f11f33a697f58f0.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LwOZ1pjO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Pull the kernel_init_free_pages() call in post_alloc_hook() out of the
big if clause for better code readability. This also allows for more
simplifications in the following patch.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/page_alloc.c | 12 ++++++++----
 1 file changed, 8 insertions(+), 4 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index d96a43db90c8..ddf677c23298 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2435,14 +2435,18 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		init = false;
 	}
 	if (kasan_has_integrated_init()) {
-		if (!init_tags)
+		if (!init_tags) {
 			kasan_unpoison_pages(page, order, init);
+
+			/* Note that memory is already initialized by KASAN. */
+			init = false;
+		}
 	} else {
 		kasan_unpoison_pages(page, order, init);
-
-		if (init)
-			kernel_init_free_pages(page, 1 << order);
 	}
+	/* If memory is still not initialized, do it now. */
+	if (init)
+		kernel_init_free_pages(page, 1 << order);
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
 	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
 		SetPageSkipKASanPoison(page);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b0915f0de757714e163afe719f11f33a697f58f0.1640891329.git.andreyknvl%40google.com.
