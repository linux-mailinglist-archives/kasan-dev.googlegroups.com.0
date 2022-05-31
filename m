Return-Path: <kasan-dev+bncBAABBOXP3CKAMGQEZWJENZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7998453942D
	for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 17:43:55 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id bt14-20020a056000080e00b002100d89c219sf2131485wrb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 08:43:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654011835; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZsfrnxMG1HrBZ64GpTjQ6fJszYfCaH4K0llbiyATK7P+xWPvS2Qu7Z5ecChLDTFzl
         2vWGnT8Q/gcgHfCyYQRzeYJRsZJVdfwNBss5sjlYmlV0516ZzxCCL8RGct9nfUNwhDsP
         wHkWIR6R/aM0WfLMVhXR4xatulQaZSAKfdYy4qP8HO0uq7O+NmM/ut54b53FrSL9NAZA
         lYJrMvWxbefsD9D7bjGgFJAtqn6WtUb6PzvRP60q7uuIBJpKdLL+aTrGq6XLLYIspzNX
         TMhKLhNDjSoDkHa7kYw0z5E21N17EUVHTz6OsP0j69Y+641YeyfnX2xX4dqNAq7mt9Bu
         qcGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FchYJHKdRnOdozSb2C+89Wi44T2Agl6xEhWlKzACYD0=;
        b=P+Maij3i/xcvlCRj0mV8MjVgX+f1Q4ittXQLlHZWXBm002zYhfjSIXpzquhkwZ7UUL
         VSZKgUMNdhMlM0slaqrn6Jxq4/hqyAzRkKMuP8a0bMi6nrk1D79eW8Grl/OASNnn0usr
         62zybA13ymeSzZGNG5B99iSXYgGHnIR24pBWOE5QZdvPyEU2WaT68+ZMh0nErH5bzgPd
         t7GdVdB8Epv1cC6SsOz9jGkLHCidXpKx8DpJbxYT+a5TfVWD0E6QHGmDfZdqp7V84Mt6
         MQmcrbxLRaY8aDjWzg/0Fh9zmJedOqzO6g02ZKN6MszPW1JXAeGNy/69yFWit+EX+xz0
         0OYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="OyKv/9vu";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FchYJHKdRnOdozSb2C+89Wi44T2Agl6xEhWlKzACYD0=;
        b=SItroa0NEy0m06i4Ic3No1PgHuAkFpiLE0F2pQVAopYG4sZwez2gb5NA3JVEplCTzr
         Y6bocpW2E6gwnWJ5wMZyGpfxyWg6w56Z33bw/JYpdtq6jaZWRmRDo6vNmPfCXcd9JbgQ
         m69VWvezN/fZG7KbrrQG6LyJ1eLnoEid9ZH+wqyct0rxD+LfTSWGVupJ/PwGniIi7BOp
         8UoH5pNLZwS2/csyzGVeiOhM3GTN8weaP5vlv5v66+urlxaPLHQkoGsL92bL4VQz2AGt
         sjqQ9PEcU9zW4w1SsIKrLbQqKnRbJdLShxoo3IJRssqJgTV1NjBxzHfzJJVYlegszdGc
         d7GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FchYJHKdRnOdozSb2C+89Wi44T2Agl6xEhWlKzACYD0=;
        b=hLqXWA+g6ThG7Cpyb+HLIAONsOOUY2weJmfNaPY4h2FGugt1FeL4xaT7nDOYK5Owhc
         ovAmexhkFpyxvIYcpUNCrImbh1NZ5bJoumhecD5UKRagQisl4MqLIyxllzjIsYtr/RxH
         2ScsxUvMIKrbx1e4AeOi0SKRJPPTVVFQvZq3mjCD5ZRRCHHGobRP7yQycUcvhVNR/yyj
         +YeUPSG2MTK7xtEstNNHZT89p8Rp/qZMfeSyl6DrY+XKjyo9fgk4Vsyz49Kq2bK6uXq9
         npKj/W9d4ADJvwwLIK0GdfQypUNN7pdQtLFwyzZ3tfplVg4J37ekLDwPXBQ0TXHDWw8z
         6erQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533f8xr8TJBNIyJBOHaYCalB/J5PQj+X4qXjYS7ojUqXyIewV2yz
	OkpETeBWI63NEgkECPdxe4o=
X-Google-Smtp-Source: ABdhPJzbiaXOeI78ymXjLx9wOXaDP+1D3CV0RH4PuIN6W5+kKbGrmBwG2NnN6J3pEC4qthd5ebEQ+g==
X-Received: by 2002:a05:6000:168f:b0:20f:d241:887d with SMTP id y15-20020a056000168f00b0020fd241887dmr38728663wrd.309.1654011834883;
        Tue, 31 May 2022 08:43:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f0e:b0:396:fee5:f6f1 with SMTP id
 l14-20020a05600c4f0e00b00396fee5f6f1ls90348wmq.1.gmail; Tue, 31 May 2022
 08:43:54 -0700 (PDT)
X-Received: by 2002:a05:600c:20d:b0:397:3971:909e with SMTP id 13-20020a05600c020d00b003973971909emr24271150wmi.203.1654011834141;
        Tue, 31 May 2022 08:43:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654011834; cv=none;
        d=google.com; s=arc-20160816;
        b=LiqfZ/32z1kp8HsQuqmdHQyN+ehbhMTRBlSRXRa/+bQUaF7vChw2kA/kaDdc/bZC5X
         stg+Mxs/vzYGh0yfPwbpwPfEvIGgnGIR6OE4yZ0acsNP4arAXueV/DSriQVi6PMybN/c
         GGurFYldCQmt6H60IpZJI7uzmwSmRLG1Z8IciOl+36k4uC0rhZLRBcoCrOF7FavYNQY5
         Be+/abBtJeOYetReL2QHAJ2SgE2bPo/tTYbRs1lbsyD0nv0/EG8qQxO4nJTeflcKZGNr
         urE2HyIIW6IldFC8EEtc2Mia2cuCRSJmZiPe5l5bgRGD4g64e5ZZnuxfq1kI6DPoLY94
         Wo0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EsGrAYAp6IJFxcDVn2/7Z4jT50O8LabBUCsC9BUqAmM=;
        b=s/ywZ6UrurNGo3lY8SygsAQix+ntLRC7RTd5oZJu/cENNiCV2N6eumEQuR1Bkt2Hlw
         1oYr8DZhhZsc5s9ZaKg1Y+IqOCfi5kc3dn6W9IV7cpCjxeBt8WJNCaIdFIvwIAmXw80D
         S1xx9w6SS/v2s2PatRynWmA6W/de7Sm4/EnEc0g18dN3vnkq6Uv4VkVS4j+LObW9LaH/
         RSQn/LIG9gbCA8o8INjRg1+8uIa4v85FH7wHpcMt+79a1xpaHGECNo5Ges/cwYRUVUHX
         q3/jbXQ4pQigdUX4eEY8xBemIlhiXSiZZeg+vTmA0+kaARpyC6S+RwiCE4HG2p2qbvEd
         MJWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="OyKv/9vu";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id o24-20020a05600c511800b00397320af7e9si136928wms.4.2022.05.31.08.43.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 31 May 2022 08:43:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/3] mm: rename kernel_init_free_pages to kernel_init_pages
Date: Tue, 31 May 2022 17:43:48 +0200
Message-Id: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="OyKv/9vu";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Rename kernel_init_free_pages() to kernel_init_pages(). This function is
not only used for free pages but also for pages that were just allocated.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e008a3df0485..66ef8c310dce 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1296,7 +1296,7 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 	       PageSkipKASanPoison(page);
 }
 
-static void kernel_init_free_pages(struct page *page, int numpages)
+static void kernel_init_pages(struct page *page, int numpages)
 {
 	int i;
 
@@ -1396,7 +1396,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			init = false;
 	}
 	if (init)
-		kernel_init_free_pages(page, 1 << order);
+		kernel_init_pages(page, 1 << order);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
@@ -2441,7 +2441,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	}
 	/* If memory is still not initialized, do it now. */
 	if (init)
-		kernel_init_free_pages(page, 1 << order);
+		kernel_init_pages(page, 1 << order);
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
 	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
 		SetPageSkipKASanPoison(page);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl%40google.com.
