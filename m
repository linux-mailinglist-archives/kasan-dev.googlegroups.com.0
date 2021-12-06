Return-Path: <kasan-dev+bncBAABBEMJXKGQMGQESPSSCAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37F3A46AABE
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:54 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7sf6714321wmj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827154; cv=pass;
        d=google.com; s=arc-20160816;
        b=hmTkwQJFfEl/eeGdFzLxIupwkkDsKCDcKeudUjoIDN8rmU9XU2vlx0VtZ5i0/WB9TX
         iRrKE+IFI5WgahCIbCxdQX/WKyTReMV7s1rj8COrDX+G/ZV0mEYfKfT8vdOLlzbIT2q+
         VtKSxNOjUKAaFIujQVcuV6V9iBCxYQ7kk6PmVzXtCmtw24shfOS70qeucX1XYw5ewdqr
         EOdrhSqJ7zVBaC6XP9ZDKbs14adV92z/iq0jLljrXQqxq3PPG+98GvbsWEiqrQj22xpc
         5VeltZ5GyK7EseqU88BvMdRAgQKwmvUvWHjknezhf33U3we26q/vkl1uzCpQ87mQZ8oS
         XFPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dakVW56sdT2I3Nd3fKUBVmwR3qJlzK30CvlUkXI5s/8=;
        b=fnRxlkMoL9eRZQO7yzfG+ZarRXiRxiixkDvVXd8KFo9uLZdiwAj16n89ThhSy0UgL+
         +O51G02CyYNFMHnWmuBgo2fpeu9BzrTSXGJrO5/uKMOtDTITNw0Z2at2pPkFjJMtblaE
         dlb/Aq2HW+SjHJERlcN+cT3c/2mN5VjAUbu3/HP1m5hMIeJQ0QZbdKsQJ8oj8trKuCZS
         EyY4DLKB4N0ms+rpnA2ll4GKUXSrdRkQgiyFTh7yCS2IO7xd5b1EsIwmXwPBPLuYvqUN
         GYh6oGf6S1E+cX7KhGZBgfjnsRgGLmij+9OF3BOLOcv8StT4eAZyI31vcGyKm3EPEENF
         bL5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sBk8L+hA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dakVW56sdT2I3Nd3fKUBVmwR3qJlzK30CvlUkXI5s/8=;
        b=mPUlMvxnEJGm3mzx7Iw6jeP2J6pl0yR0xla5AQkk8UoSmM11ZQhKTEewyGFhBpOPfB
         4Om66PYZAD3tcRZcWkm5Gen3VNvf8YTyC9QJLZwr07toOnYqMJZS/tJrY+EaMehs2gz2
         ZDj054sYxd2Pem+J2IzhZnS37OmjI/aqtc70EfkRje+QdXPWkjMdMmlkEBw8w7/t3Jk4
         S2Go5dLjv9EwNQEXQ+iP9qGWqAWsSdPBbYvloRgEuAuwtPh3rvKTrP9KAtf5l2AqYaQU
         eQNui0Ye4eVnGvz3EPCeknhALKSQTjoYC5qar+3wv0Mqngh2qbr6Rp1tujyYKNrKL4iF
         6qqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dakVW56sdT2I3Nd3fKUBVmwR3qJlzK30CvlUkXI5s/8=;
        b=rZM8f5Jv78tebXlOi/qNanEohvT+QEE3kEv7dvZN3MCsGcLUAcWZkLhSEOR4IOOkfk
         7/H1Dt25AELY5nLDatnU0gRtisTcCYsx+jCLrV0JRHfg5LJsike+MTSgy/+m0C4oMvwc
         7vBIkrMvZtiYidVz0S4BSMYthtcFC3DlkWA/b4xLrIlzCn/jt+VCLWgShC5jJUo0u7GE
         Su1tI74Aa+ccu9VWfFgElcex0JRsFoPE/R7YacVCvUkRN9Nhg2BrAiWA0nOaHEh2PSWS
         1bjADN4eh9Egu2fFJxhcEa8Y05+wzzus73s1BGAb0Z9rCvA5NuYcO+6dhPBkGCl+8dnD
         W/zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OO1GIsABVybM8jJq5HqJqc7qSc0Ah5kRZGRIUNo/yEoCQ567b
	buhGgy/XJQ/QEN98L2nvRqg=
X-Google-Smtp-Source: ABdhPJwl35sAD8hmGb3caL5xjHQGad/gP8Bwy4UrvHhGu1XRTGogleW/rWkjK414eYm+S0O2OxKGRg==
X-Received: by 2002:a7b:c102:: with SMTP id w2mr1491719wmi.151.1638827154025;
        Mon, 06 Dec 2021 13:45:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls1150683wrp.3.gmail; Mon, 06 Dec
 2021 13:45:53 -0800 (PST)
X-Received: by 2002:a05:6000:1848:: with SMTP id c8mr48012404wri.265.1638827153279;
        Mon, 06 Dec 2021 13:45:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827153; cv=none;
        d=google.com; s=arc-20160816;
        b=pkHQdk1EhspNRtqfvCSG9FnqF0Zp+Hv80/I1EJG2LB13WhkTxvo7rKAIUb2gOAcNHr
         /ItA1rkw1EyOFIfnYvHJqx170TPeK9dzsn0aiLbvYgoVaVRReJ1dn/x1teYGhKPdqVbx
         cMcVbUcqFPP+75BMlb8zmpZ5hMhHQ23a6e0BU3BLntK5WXk9HtXSHM1PQYXkFhTPgLB7
         DXqZ49S8KArJiLAFu0xZn6Jf5XH6gGUd+i0aFHbCYThYSM3JDv4lqSKpyQg+xAP+tB/E
         irsIJqT4Y16HDaF1RwZK/VhseSkGGaafBPI6RWERrVQjPM/QGIyzWYafQyut6KdlVS7h
         XXqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qxn2Xep6jUSip5qM4WVsL2tCgAIiNA6s93LyLl9ypbE=;
        b=c198dz+0eC6HciqQfzlTPw4JlQMcGDsJ34AJUm8Gn8sP/elP4wO/Ck9TqD6jAi1grj
         1cnWs1SBN4of6V9e/8JyR0NRpZ+0MLGcegmrHa86OXqcl4I2yHD/SySa6XolSbPeXDfu
         ujfpBUWIt7gI5BUQR+Oqe+1xyapzEIAAmXSe44yXMbAKdGEwvZcInEy/Mx93S4aZJLGf
         Qv8JarxkftzXeSByizPLOBcJPsSZkWx4SPBJ9XgRxe4NxNVk0lIx87a1ErYHFz9bZ1gr
         iiz8Nso6Rpwk6fPqc5t7LZFU8U+JnIJtGfgxPrlfSkREhDuOkVPSfeOnVATaNVehKqXe
         BvTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sBk8L+hA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id 125si86152wmc.1.2021.12.06.13.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 18/34] kasan, vmalloc: drop outdated VM_KASAN comment
Date: Mon,  6 Dec 2021 22:43:55 +0100
Message-Id: <4d44c09c5999cf4767803724eb47581294f4341c.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sBk8L+hA;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

The comment about VM_KASAN in include/linux/vmalloc.c is outdated.
VM_KASAN is currently only used to mark vm_areas allocated for
kernel modules when CONFIG_KASAN_VMALLOC is disabled.

Drop the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/vmalloc.h | 11 -----------
 1 file changed, 11 deletions(-)

diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index 6e022cc712e6..b22369f540eb 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -28,17 +28,6 @@ struct notifier_block;		/* in notifier.h */
 #define VM_MAP_PUT_PAGES	0x00000200	/* put pages and free array in vfree */
 #define VM_NO_HUGE_VMAP		0x00000400	/* force PAGE_SIZE pte mapping */
 
-/*
- * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMALLOC.
- *
- * If IS_ENABLED(CONFIG_KASAN_VMALLOC), VM_KASAN is set on a vm_struct after
- * shadow memory has been mapped. It's used to handle allocation errors so that
- * we don't try to poison shadow on free if it was never allocated.
- *
- * Otherwise, VM_KASAN is set for kasan_module_alloc() allocations and used to
- * determine which allocations need the module shadow freed.
- */
-
 /* bits [20..32] reserved for arch specific ioremap internals */
 
 /*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4d44c09c5999cf4767803724eb47581294f4341c.1638825394.git.andreyknvl%40google.com.
