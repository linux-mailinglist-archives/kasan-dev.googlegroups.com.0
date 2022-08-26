Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6WDUOMAMGQEQWRHXAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B9EF5A2A63
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:43 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id k13-20020a2ea28d000000b00261d461fad4sf660348lja.23
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526522; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ekch0mqLCFryvBTTPWmYeghOG68ZhRqGKo9TsRUIGnGjCmt2iR2gw0ibLs3l3zKZCo
         MxJc4/KEBFukiiCfvkiPH9JMsogoVIs/4nND8640CdsnsSf6Ub8ZliBQatQqRjdPX3Dz
         l9U2mO+2g3F/oeTFsGAyt6IyY6QCNlIgsnG1m2kCw2ALPRmiSyQ/qnSHVIF6QUJnuCqz
         3AJAg15qrHck7rMQ53A14L2vEy1UyveFd44KtFc4TChxqt5U+R8zAhC19R7oRoZX7htc
         qlTPs497BDcfd/RUWuQlVYWLf1pPb5kSbX0DL62pD7yahpV5KcBn1ajmKc5cKW7lxnjU
         W/oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=KxjpfoN2IScR2+Jj8gBg1ldxHvyT2655riuNACh3r7U=;
        b=u4fmKxrdB4L7kJrHCa5lZnSaceFMnCKsNEM0VKdt2ooCTb+aJ/OWYJcf4/6UXdeTHb
         mvmwXEKr/bSQdus14hatDTPfrgM+IyBbi/Ipo0MWK2X4tzdErfDB1dgkMJDOVQ+Yq6k4
         xCniF8sdORJxKcCbR+65S84aPexy+YBBL5vDd7qWDe9P/KJ7Idjv/FR9xF9UaqZp0RDK
         F8nhh/pNEHEcW9ovb+vKLGIy5lgaJ4GxQa1kaVEZA4W/SimNzMuVCBAtJTr7M2OgOgT6
         L0Rcl4qP4r3bN+Z4XT6rocU8VZbq0KtcvhtlXmYQzMOX1V5LSDoPMyprLaxxSWMNR78O
         5xrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JGLI1XVM;
       spf=pass (google.com: domain of 3-eeiywykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-eEIYwYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=KxjpfoN2IScR2+Jj8gBg1ldxHvyT2655riuNACh3r7U=;
        b=NUwTD7HIjX9R0Ujc2j9wYejI6tGgK5nbftCsv9qrrhQpbladmeCx173NZqMkAylVz/
         AsFd1r8qcoKImT/nEYJmsnmz6FWw5zPGuOwaeCZXnvAOJrJu8V5RUiU65qSKcj+sfMIO
         n+fvfcXuCFvc7/KbC4Yiunqs0T7qqEPkTZWVH3tdXnveIFatHJCT3tvshnq9nTAbLomW
         06bXj3mv/Ro9ilhhB6p5LHBQUmkUQ9CPaOHwN6hcIwYuWHRRqPqpJqgQNS0nyMrxrRMO
         FcklsWzFeUti5HYYAb+KZxcUXce+cekOfs6OhpqbIwGkFfHQ7Z8rBFaFA7xs6sVxJ78q
         yMhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=KxjpfoN2IScR2+Jj8gBg1ldxHvyT2655riuNACh3r7U=;
        b=mKeZ+IRXOZnRuFYm9cHUYRvKMZVN5HlJeb3lguCH8VpKzhLf7EUk3WR/QfzFgQMc25
         I+Wuvmfo93jFvBaGqMf3U3OLVGhpg9mmBmGy7Z5++C14PtWcCtJHaCFsarNF0KiGwjiu
         mZblej7z1AzhhaT9xPv3p7yqXVIEv9Pr+JSNY/7ibBT/Jj/zpToGD4PU8LvID9Nqa7Uw
         eOUMyqrkYC69p+SjlQaEdOKvWPViI8o0zSj1BpPHKuVpOos4tkX6RLZ7UN1CKCO7StTy
         dQNTQH4RcW1H+6fD69O17vvlwtV29A4qAcc7vaGpPM/b3i3omzUs9Q6vIPbwUyX8vrwl
         DczQ==
X-Gm-Message-State: ACgBeo3uSQX+A4b7jFW/vYYawjuz19yCTIO6wFiaop747chinLdqTN7k
	Aqjwnlts+kVqT+Hv8OEQp8g=
X-Google-Smtp-Source: AA6agR7j6EhfmWGfEgmmdP5Xy4FcMiWygKkXfMr8ayw5Ire/XcBzGr30Baj447ozaILJAA3mjTee4A==
X-Received: by 2002:a05:6512:159b:b0:492:c1c0:5aab with SMTP id bp27-20020a056512159b00b00492c1c05aabmr2596917lfb.523.1661526522838;
        Fri, 26 Aug 2022 08:08:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:34d1:b0:48b:2227:7787 with SMTP id
 w17-20020a05651234d100b0048b22277787ls1109224lfr.3.-pod-prod-gmail; Fri, 26
 Aug 2022 08:08:41 -0700 (PDT)
X-Received: by 2002:a05:6512:1083:b0:48b:a1bb:a8b4 with SMTP id j3-20020a056512108300b0048ba1bba8b4mr2450608lfg.342.1661526521469;
        Fri, 26 Aug 2022 08:08:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526521; cv=none;
        d=google.com; s=arc-20160816;
        b=LfYHUK0O503Wsgbulq+Kul/dTD6znRG3aaZvRRAT/ANp7AVOrLPZC6oUPlcHPSs90s
         Mhl3K1FfBFxopnNBoSMsLW/vr8BycWhERR/cmWcjZgA+W/xF1MYUbkXWJhwKbNOpd07p
         rfmb+Yd8GJINBGgT+MrF4CUC8R2Quo79zyqpvGV49TrK7C34blijWSU4tIjC6pmGs/sz
         2br3tAGlrrhTs88zZjQ7dcTpZ31aFZu0t74xxEehAqOzA8LSaYfb+PkLmol2ZrK8OYV9
         Id3ch2r9YinAVqJYOxHiBCl+EA+v6tHEV3qyYnW8Mn3cWw47uU3fuGllpH/0ReubYE8A
         GTiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=KyITLg/74GrhViHFJeQt7QU8AnVbkb7jycJ7NufNBUo=;
        b=tTcGYHqMhUennrW8Sskk7RRlk29hiAMW0SV2FF+MkBUXmQSeSofnw/EqVNKtQF7iOP
         lE12NKQHg2aogmOMM+AxUQhptVfTvmWj8looKIVOorm8gwzLryV0jSXz1fkccmNkv9ZB
         LX9+KhKx2bC7ckvHROt4nvQEW0gWMbxvWe/17YjO2MA8SxQK7v7A8NlXqSNsZwI8PZKR
         a+Yq+meA0lVugnrIDZPdyA651BQxMoDw8NFBfrJG3If890aAoEdtkd/mz879pFAL07Vd
         gGD3BFYKfr/nwn+IRJTzeWUmfUnguJFkPOA+HCjohUfyGiYeBV5+GHBUG+eUP3jG0HtV
         rpPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JGLI1XVM;
       spf=pass (google.com: domain of 3-eeiywykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-eEIYwYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id z19-20020a05651c11d300b00261eb78846bsi70426ljo.4.2022.08.26.08.08.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-eeiywykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id nb10-20020a1709071c8a00b006e8f89863ceso716279ejc.18
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:41 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:907:a04e:b0:73d:8419:3d88 with SMTP id
 gz14-20020a170907a04e00b0073d84193d88mr5498703ejc.616.1661526521065; Fri, 26
 Aug 2022 08:08:41 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:33 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-11-glider@google.com>
Subject: [PATCH v5 10/44] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JGLI1XVM;       spf=pass
 (google.com: domain of 3-eeiywykcf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-eEIYwYKCf4mrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN adds extra metadata fields to struct page, so it does not fit into
64 bytes anymore.

This change leads to increased memory consumption of the nvdimm driver,
regardless of whether the kernel is built with KMSAN or not.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Link: https://linux-review.googlesource.com/id/I353796acc6a850bfd7bb342aa1b63e616fc614f1
---
 drivers/nvdimm/nd.h       | 2 +-
 drivers/nvdimm/pfn_devs.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
index ec5219680092d..85ca5b4da3cf3 100644
--- a/drivers/nvdimm/nd.h
+++ b/drivers/nvdimm/nd.h
@@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
 		struct nd_namespace_common *ndns);
 #if IS_ENABLED(CONFIG_ND_CLAIM)
 /* max struct page size independent of kernel config */
-#define MAX_STRUCT_PAGE_SIZE 64
+#define MAX_STRUCT_PAGE_SIZE 128
 int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap);
 #else
 static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
index 0e92ab4b32833..61af072ac98f9 100644
--- a/drivers/nvdimm/pfn_devs.c
+++ b/drivers/nvdimm/pfn_devs.c
@@ -787,7 +787,7 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
 		 * when populating the vmemmap. This *should* be equal to
 		 * PMD_SIZE for most architectures.
 		 *
-		 * Also make sure size of struct page is less than 64. We
+		 * Also make sure size of struct page is less than 128. We
 		 * want to make sure we use large enough size here so that
 		 * we don't have a dynamic reserve space depending on
 		 * struct page size. But we also want to make sure we notice
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-11-glider%40google.com.
