Return-Path: <kasan-dev+bncBDKPDS4R5ECRBWHURKQQMGQE5PGE6EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 01EA36CBB9A
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 11:58:50 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id s11-20020a170902a50b00b001a1f8fc0d2csf7422906plq.15
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 02:58:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679997528; cv=pass;
        d=google.com; s=arc-20160816;
        b=pSOoFilpWlp1ws2uuB3bo+82SW/V5hyq+q33YgENk/ROh7U+dre5R6ZFsrKD6R1UZV
         wKu3mTJ+NoW8sE9t65UI8H1EMNtHKFI3gDvKjqWed8GpH4IyqytnqUCvSWEyqSuYqg81
         5PUqUMf1sYd7lNeVPPC19a5yCmI7jC0tfN4WL6nO0f2srIcLC7BamzQTHdRJujJrAbfG
         c/afDDvQH/3s0lrO836ogQU1M8tY2zXrT2QITZDhvKmbegqsZPsDGKx8glXtprY5Rk/+
         2+l6l/9Up56LcjvW1YiMEDve54Za3RgGtNiBzkaB9O95WMZPofF57kl8kwWbnJJ2NysS
         GYAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=pVbvLAgxC0082IVIVrXxXiDTeTgK8zWwFXBN1OqNjRE=;
        b=R2qWkg0+0o059agT2ecZ1Og6U10oSat7O4robuSevwbXryxjJ1ednNg1Q0WR5VexDd
         NKBosFQri2lILsYUFUORF5w9IxMQy1niquGIBZz3E7EXLYniZGtDJEnGtBSIavbcFVqN
         iBIPAVViygnflgBwb5Og9r87KxjGea/GCvh88Sr30sI1/r1pQQJOsf6m5ZzOLwKB2MZY
         DhxIldkhUDd9XxlYfYnGcQeM9qa72RA9zfD1XEbMAflnl4Z6wFPfvpj8TXF2EqAClzc0
         LMQxVQUmIuMYLwWFN1zP0kBwerMBk4sJuHKCqHTomscRiblPqG0r3qMDSXYAkVCjxuOo
         jLxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=Qx3+v0sZ;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679997528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pVbvLAgxC0082IVIVrXxXiDTeTgK8zWwFXBN1OqNjRE=;
        b=gLcugNVH3HjvLJmDMjxiDRuaoV/KRgp4cHLLveYUk/HdK6U4hCaGiIhhDg8pv5sxEz
         D5vuHW5KjHR3NjKBMo+ZNHKaNu1a0tt6mpdfoKNv5HuMXVMzFNWXQix9UlnteHvsopvR
         PlD+xXb0nmMCKo6nbszw8xHIwwkiprbcPJt5tZSlx4aNNKDOSj9aXUmWxlkYd70U1BBt
         5IubnO/LuXp+ne8YXzOTnic1zVDm+Jd/VxQphHMPj94nvHFUg/NBlba3CyI+IMDT9Qla
         3P/XsJ6x4Ky8H7TONupmkdkD8hGdjpfrESi5qkuWorxvJ1JjDidSmZ+9YU1q7c+e1Nr8
         z90g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679997528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pVbvLAgxC0082IVIVrXxXiDTeTgK8zWwFXBN1OqNjRE=;
        b=6P8bTVIPdm4+CeG9Nr8E6CvRyxX0TJuCyAOKYhHCgRSEKZH7tWuk8eg199iVXasTQn
         ZKpU+RKosAz8ytFHTH96IEYm1ddrxKeYrnR7jc0XtqraJgrH0qO+4a9EqcWjTIj/z3HO
         SlqsqHGAawMe9ezj7OLj3yuT0kH5Ej+wNdeViFlX+UzA4Xx8FZEf4jjc6+SDxW8LoWlK
         u6S53BBjGUxk7x8UY6W2WALRLOTtMewFxjbiQurDDd+z2AEKkG4YnIqbgqGdaSyHnN0/
         lcoRj9DzG+Jq6U00NKZ5zWMyBsjoZjK1WnT+PNstYpD3oHAGOPR3kyc5stgW6EL/zs2K
         T0jA==
X-Gm-Message-State: AAQBX9fRCLf3p/mF98zoStxbsUAdpJjBnpsSScaqbOPIa5/PJ3P5KOBO
	VUPjCE1kRBuscK+upUWlmKY=
X-Google-Smtp-Source: AKy350buU9P0ISnpsFjeYBv+8tOBnKxYkXkRu7Ih5NUZ2kEOmMeH2ItQzS63A6JZMERPBBivJO507Q==
X-Received: by 2002:a63:390:0:b0:4fb:935c:67f with SMTP id 138-20020a630390000000b004fb935c067fmr3965727pgd.0.1679997528562;
        Tue, 28 Mar 2023 02:58:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a70b:b0:19f:3460:3f0 with SMTP id
 w11-20020a170902a70b00b0019f346003f0ls9659504plq.5.-pod-prod-gmail; Tue, 28
 Mar 2023 02:58:47 -0700 (PDT)
X-Received: by 2002:a17:90b:4c0b:b0:23e:fa90:ba34 with SMTP id na11-20020a17090b4c0b00b0023efa90ba34mr16917982pjb.37.1679997527800;
        Tue, 28 Mar 2023 02:58:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679997527; cv=none;
        d=google.com; s=arc-20160816;
        b=lkwUYL2Lt3phUW0wql0XP95r83wUOHjxa5T97ux36FP7ewNlUHRlisb/8QJM0RCwd3
         zEb0u2Sting08P8D7E+TfJvRlOe+T2CGboWeSL7rNkyOrJducxI0yycjUxXwGe2CAEB0
         R69lvFQ5ddAh9y+hn/5lty23bwjB0n6eEy9mEqKb1lbnyEKKxpYoPjJ7aQ5keInufx61
         lavwb9NuRQCF6HDbDDyvTf96nBQTdYtWJuK6FsGnjY4nXGvTywvh035/by5Zya/4s5ZZ
         FpTfs18fnDQgYNifC7zx4weDucogo0uTsGw8/Y4VY1VqXqN0vPd/UUVhpvSUTVxMdIrG
         Q5UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=15Z/PJf0Etf+mCvL+KJkEExIR5UO6fpjH+VUxXpLOps=;
        b=zY1Kk7NIRD+HQahrWFUzdUP6iXsDZPOn0yirQ/oYYnHUvsLHPr3ZGeZjWyPG+v7xln
         oZKvNbjvfPr8CnOUfqbTsI4KCqTSG/FJgBSmKsJJZg2TkYDVj7z3aU134djBIBXZVxYg
         piqGe6t1lAnsPYnEVfBAbyScILV2Gg+bLZ6aPe6BQUh+hibc1ahnE+nRwMIyQImldPaJ
         5FLbbnu+RqaBsDHG54lru9XaWhc4EZq3iKHSF1p4PQogfuhiLcfdGUKriBoWIibyW9uV
         H4CSnmbvXIsFfwu59x+jHxL4sz6ThACVdQJ/IOM4HM59u5ovXE+FiI/EznPQ2hp41+Hb
         f3Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=Qx3+v0sZ;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id f7-20020a17090a638700b0023f29444ab2si367623pjj.2.2023.03.28.02.58.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 02:58:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id g7so7589437pfu.2
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 02:58:47 -0700 (PDT)
X-Received: by 2002:a62:6454:0:b0:5a8:b2bf:26ac with SMTP id y81-20020a626454000000b005a8b2bf26acmr14066890pfb.20.1679997527531;
        Tue, 28 Mar 2023 02:58:47 -0700 (PDT)
Received: from PXLDJ45XCM.bytedance.net ([139.177.225.236])
        by smtp.gmail.com with ESMTPSA id m26-20020aa78a1a000000b005a8a5be96b2sm17207556pfa.104.2023.03.28.02.58.43
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 28 Mar 2023 02:58:46 -0700 (PDT)
From: "'Muchun Song' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	jannh@google.com,
	sjpark@amazon.de,
	muchun.song@linux.dev
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH 4/6] mm: kfence: remove useless check for CONFIG_KFENCE_NUM_OBJECTS
Date: Tue, 28 Mar 2023 17:58:05 +0800
Message-Id: <20230328095807.7014-5-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.37.1 (Apple Git-137.1)
In-Reply-To: <20230328095807.7014-1-songmuchun@bytedance.com>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=Qx3+v0sZ;       spf=pass
 (google.com: domain of songmuchun@bytedance.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Muchun Song <songmuchun@bytedance.com>
Reply-To: Muchun Song <songmuchun@bytedance.com>
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

The CONFIG_KFENCE_NUM_OBJECTS is limited by kconfig and vary from 1 to
65535, so CONFIG_KFENCE_NUM_OBJECTS cannot be equabl to or smaller than
0. Removing it to simplify code.

Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
 mm/kfence/core.c | 1 -
 1 file changed, 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 5726bf2ae13c..41befcb3b069 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -115,7 +115,6 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
  * Per-object metadata, with one-to-one mapping of object metadata to
  * backing pages (in __kfence_pool).
  */
-static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
 struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
 
 /* Freelist with available objects. */
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230328095807.7014-5-songmuchun%40bytedance.com.
