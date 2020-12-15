Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR4O4X7AKGQEGJVJY6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5798C2DB723
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 00:31:20 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id u3sf5736647wri.19
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 15:31:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608075080; cv=pass;
        d=google.com; s=arc-20160816;
        b=z24+3di0JXitkbc1Rn1ObiNZx9bnEc59UysqLhywY5IhHvD+LLgFbIaOW9NuboPQ3y
         8jZOHo3Xqu4T8j7HhkJRyxvMkTXIyEXaFQXRIevc7HAMPHjBxNmbzFHsMrb7GzzhiWV1
         MQdkSynhYI/SeNnwoRILt8F4ChYLH+hMGNmQ4Fo/G05gFUt+K1mzMkQf4q8BDb0IOdCp
         PSwFtlulxe0UJtOrbhuX+Z0BnxMS/d24AH9DsjfqWrBS7VZ3/8gsgiuzZzNi6yrYgxak
         YTY15lqMMkZE9hK+r0N3/xakwmlcxktVw2jDZChV2IF0E685P/CcIDIJK8BXDMxMTnAa
         lGpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=+8m/CbUeeTEP7uxJ2Tqnj2eXfnquFQHh1ibviR3I0rU=;
        b=0QLOYaEOgUC3kRcH+pUPXx8vtijHZ3TU/4A96Sjkjd7SeuYyeUf59L/CYcO932z6Kf
         REUU4D914rrWGTYhmP8ZTeFBdi2Daiw0LjYFhk3qA/IMVKG8DUPKvoXfByzHH7JFJ0Bf
         VcZpG/PxSgHgVnPDj0ddOUqJTwmuZCA6Ujr8dKiio6S3pRg7RoPk39+GfNl0w0W6/+4R
         uDrvbyv2vZvRu8LKRz3YHQx7KnL2BzBY+ScIRM3g8lF3BOgWLVU2GjFu5ELyyk68I87X
         97RmHUmvOy7CVyUTaG5QUH/DOEXMxxr0UHg9I9mrYEf3kDxvpfpLDcuEuo3sFGaECcLh
         ta4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OD1BYevw;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+8m/CbUeeTEP7uxJ2Tqnj2eXfnquFQHh1ibviR3I0rU=;
        b=NlKbd+ZKiI/D5eGiQRPGGcEb2fMbEpV7mtJFwEDp4jupdAd5yoQzDMI6QQO+iIg8lm
         w3gdMpjyuBd502Dhk8nZ9JsHgaakb4HCjKXNy7PS24lJ3hDLrxofnwypHKrwufZE/w9T
         OY4bvotq771XM9Ep8uxqMln4cXhcezFqaJSuStbGOOjL42zmbIT18SI9MmJU3ij6l4sT
         tFqGTuvCbdzWpl9MOhlVaYrqn/O4saO4UZt/4LfY0gsuv2iUiWSqm6vFYJ9Ff+Ws1/f+
         KHqOZvG4BpbQiEGWZRdDj3baEJkE1a0iumFcCRf7s3BgoN1K71jmKovnNYuFxFUllXc5
         ASUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+8m/CbUeeTEP7uxJ2Tqnj2eXfnquFQHh1ibviR3I0rU=;
        b=US2JeGmPPwjJYWDWSGjWfdPPY+g647GBXqXZo3+uG8jvvbJ8BgHfusxrOB4PwCOkf5
         XUzQMCHG7SmjlY1lW/pyOu/g6jB9ASpNvst94nb/u7tvUzRZCb7oZWWKUQYIUqYZ4Jd0
         EfmtqlzhoT4MZ++zduzzG7BbgZ9JICtITImN1RiFnT3OCN5vfn9KivrqevFJu/qvG3O1
         hjVzSWvzqRLLM/NDAuUqpsBtHgo2dfReBHY78ZaHwZMov30vZj+xagF7/62/xBIbymgQ
         t5A3gLTWAyh9kPuma5MalTpojVKXAirD+FQzbVlJeOujigzQlSGbJO29jCVH0L1SOBKM
         8Obg==
X-Gm-Message-State: AOAM530bfr9EG+jSdWKAks6XJ2yciMXx8YfOtw10ZIfmjhjYUHpei8KP
	ctuZrcyapmjW4Yt70qrDkj4=
X-Google-Smtp-Source: ABdhPJwSrkjwx8nz0uWaj/k661zq+Sx3mRbgTQ9FkUPy0ZnSiwqoOBOuXwuJuU9DUdaIO3XgHYSVFw==
X-Received: by 2002:adf:84c1:: with SMTP id 59mr20616277wrg.409.1608075080088;
        Tue, 15 Dec 2020 15:31:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:66c5:: with SMTP id k5ls3713794wrw.3.gmail; Tue, 15 Dec
 2020 15:31:19 -0800 (PST)
X-Received: by 2002:adf:8290:: with SMTP id 16mr34767120wrc.27.1608075078983;
        Tue, 15 Dec 2020 15:31:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608075078; cv=none;
        d=google.com; s=arc-20160816;
        b=KHNAEbzj5siePD4+CPDExuwJSbQDCSLuJcvi8O2VEwtyHU7oBemfW4lm61j22cU40I
         x4VlFyChITP+8F4bxU9YGz1EIgqi7ar4m6ugiQuDks7Ea21J7rrzf40N3HcdvQ819igP
         MX6MYiivo66kXva5GHXBAoBaxvWNT3wWpY0hQePxwVHgU3yZ/c8r12ivAsvJG5JSVrt1
         OjCjnaS0Ly4EKcte0MOg29157GbEDGB977VxW/iT2Z/t1fK2gRSjQU7JrBObHOaIlnPu
         KkFDwS89FeA14HfqgJOm9/gX0F82S28uPuKnI0LCnxcnCEO8FjrLScRsEruX69Xfwf0k
         S8PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=NdltaZaVdnosja55B5yVwkwQ3cpKndlfH4RmsgoG5is=;
        b=SVl9zsca3G2+SYGomWbkw9XlZKGsu59z7/qPebBZi/ERqZAk/JilILWrQoNgxVHMAn
         x3spZ8YZbqQGD5FEIqpki24J9jMsuDkAezkSJGe5nyA//1xWQwUpAQ8ulLzuhUa8W+JN
         FcpA27wRDvE0JFG90OrZ9f71YfQ6SHuSfoUV7t4EdPkh1kVRydIzB4KCqSk/9rWRWyRd
         tLrLZbjAWLCGNi/hpHbxDDWX+cQNKzbpH1iHRTSsQi3TSL6IvQPTSCe1crdNMdq+VBF8
         eYi2p8f3UVFmCQq9/X0WwFzG6LbgpzNCF8kNKIbDrygjynxMThsMoOnyr/rFqfp9gdvO
         zL6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OD1BYevw;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id o135si610wme.3.2020.12.15.15.31.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 15:31:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id x22so728970wmc.5
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 15:31:18 -0800 (PST)
X-Received: by 2002:a7b:c205:: with SMTP id x5mr768403wmi.115.1608075078550;
        Tue, 15 Dec 2020 15:31:18 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id l11sm249866wrt.23.2020.12.15.15.31.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Dec 2020 15:31:17 -0800 (PST)
Date: Wed, 16 Dec 2020 00:31:12 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kbuild-all@lists.01.org,
	Linux Memory Management List <linux-mm@kvack.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	kernel test robot <lkp@intel.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kfence: fix typo in test
Message-ID: <X9lHQExmHGvETxY4@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OD1BYevw;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Fix a typo/accidental copy-paste that resulted in the obviously
incorrect 'GFP_KERNEL * 2' expression.

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/kfence_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 1433a35a1644..f57c61c833e6 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -665,7 +665,7 @@ static void test_krealloc(struct kunit *test)
 	for (; i < size * 3; i++) /* Fill to extra bytes. */
 		buf[i] = i + 1;
 
-	buf = krealloc(buf, size * 2, GFP_KERNEL * 2); /* Shrink. */
+	buf = krealloc(buf, size * 2, GFP_KERNEL); /* Shrink. */
 	KUNIT_EXPECT_GE(test, ksize(buf), size * 2);
 	for (i = 0; i < size * 2; i++)
 		KUNIT_EXPECT_EQ(test, buf[i], (char)(i + 1));
-- 
2.29.2.684.gfbc64c5ab5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X9lHQExmHGvETxY4%40elver.google.com.
