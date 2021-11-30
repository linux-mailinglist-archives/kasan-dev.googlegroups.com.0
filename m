Return-Path: <kasan-dev+bncBAABBHFVTKGQMGQECEMD4JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id A162E46406C
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:41:48 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 201-20020a1c04d2000000b003335bf8075fsf11145191wme.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:41:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308508; cv=pass;
        d=google.com; s=arc-20160816;
        b=c2mK0CK/LAWHlrYMe9m7leurYABrMIgSS5Ei0E1lRqaETyuDcnQk+1G1nN5Po9R5N6
         uvY32iR5urlzi+uQYBO6CFwYvi9tl/XeCDc4Ywn80xhnQlcdBJe6dW4WQBwgdzBILUB1
         TsdGHIXPHSKazedLUqrQzM7tFsAYCIj6eMlF0iBx4+LDegkdvNC5rYJO0ipwjOLCNmTq
         sZipKqgPozGiRAR8Uyf0cw7LreQ9s30F8LrtbEE0QeD+UV+WVktT3Pyk8uUg16cNWz7H
         32cECA/m8/alA1M/KbUAcGU51C36NEaqR0TZnGbsEJB8RnOZsb6Xbv+Aos87TkjRMYty
         XprQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3LFB5ajjyxO7oJlLiWNnhXK4/zr+gJbao4lubgtHjW8=;
        b=yHX9vi5fkZWcYsiMcoubf4UQ9jNWcWlH8qyVUChOPWKQlPz/Rq3N308obPUC1VZZPc
         j0qE6YV8zwrHwudMRgh7fJr4KkaQ4ii/XTejEfe50xNwgP0QBeY0QnM9CXkc/WNdAGz/
         0kCr+Y3sQBMPkkgRLD9J/3PTtN1HxA6VUVDef8OOi9Rrv2IjlnSJsB+fML1fThrfXpHm
         jbE5xIKjFk+GKaxXDOYSpAfMv8p+Qvyhc/0mSFOs4tivMeT3Q9QExuDjUVYtdv4e9ExT
         X2XF/ldlClS1ZSOLEsHcWX48dd2lPubaT20NeNfF1n0o66JjDWAUjyRiXoiOV4azPLv1
         my/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J8aQq0R4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3LFB5ajjyxO7oJlLiWNnhXK4/zr+gJbao4lubgtHjW8=;
        b=YDHCrtqqRevpFEmNw/SXOGyNl63NmYeXNCRL8Wp8wjKKyj0A8ZD/iqP8gVe5cf60JA
         5F5h2+oDHswEILgqkSsEYr2rElzmj22NGGGJ2IJt9J0x18hwdrxSn1N/Onx6HlYmD+NK
         kD6PoUcaUbaox7e1qGna8yCwIOVhgNg737mLL4YZ9mENwrSpYgcQP+HV/+yiZJjIV+wG
         JMorjdeqMsK/NFMQRQFXtxWKEbonryvFNzCogkrNLs1DpTmNSbW7HCLpCEGeD94Mvl35
         xqm2MyRUoTW1SWN/jY7RdTmoqGyvnrgUF5gSSCzAmwhZMfZw4rvX/p+QcF4Y3GqyXt/i
         APfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3LFB5ajjyxO7oJlLiWNnhXK4/zr+gJbao4lubgtHjW8=;
        b=ikw/MT+qCmmJbmchXLHjDXqDZF1Atss0HvJM3l1OKkNI8pA0jQFhMr6xhCoMedpgP7
         3BACI4oNAqViioPHnRVW5xgC4qlEMxie1c6BQvlgcLkMV6AUeVf6xQF51hotz9MJrYhD
         JEbfW6zCb5BOtdoYkc05K+Mfaz4S0Q+FzoI2yA8C6WCfURCcWV5S+8VyarUCtjNTMnXE
         TyK4b2bQxusnv6CvOAEdD7vJSJl78yrmqOL72Ex3gcQXvXFFQYByIOy/mATGCqfArph4
         fKTqUVZ8c5ZBFYSO0TnRexTFT6m3XCZeeG3wNDS+xYMgoJkeP1fMRVdTFc+guJz1wQCF
         Kvjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532n7aEK3gA+slcGIY26fgJu3JrcRQv48Dwl3xtuHEvqP0KfDQ1f
	Ns3+MaGZg1EAtk+xuu4uJWw=
X-Google-Smtp-Source: ABdhPJyHmi+qIXPnJhWemxFmx0f21ykw2MwhkHGiaoLKiSflCKhaulZAIOQOxTsIhP/HjcaqkqbV7A==
X-Received: by 2002:adf:d22a:: with SMTP id k10mr1877591wrh.80.1638308508328;
        Tue, 30 Nov 2021 13:41:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls130609wrr.0.gmail; Tue, 30 Nov
 2021 13:41:47 -0800 (PST)
X-Received: by 2002:a05:6000:1688:: with SMTP id y8mr1859564wrd.420.1638308507726;
        Tue, 30 Nov 2021 13:41:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308507; cv=none;
        d=google.com; s=arc-20160816;
        b=HiJEjkJ6EWCZfDEInAeUMF3RMv6tzW5hQOabCtJ3Bpi8/zbHNBj/KcM9pM9pGJrr2C
         QeB1f6iMmRjZcXfun88jZA/iVYU5YSMzJnG3xtnQXIbDJv3rde6RVlgRP5oWGP9PxyBv
         5neOl5cF9myO+98mCpefuDjzOX8s61vYi+LR+JI5gEx+PrYLPw3Qqu9IlAuq/uoYsQlE
         mWScgS+8IWE3BtLgB5bdEbuxSFpMMXaFoc042ZKcgd/7KcZDerl1mcsjBEc1bAZoapUz
         GBtFSzw1yMjECW7YVq8H4mvYy6WjRgml3GdBkQwXwlHsKwdfRWGeZGrfUVz1NSSnI0sC
         cvgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=USDGw+3TDan6rheydUBAEIrBt2Dp4Aw0TGvQ3YV1Rwc=;
        b=e4NCwmDbjr6AWkabcvWvqzrnhmfR58BqbdkHau7T3dNh0f1kGyIwe7fICBC/4/Sh98
         2CKMzlY0nTw0JWZS69UlVuoWCogFW41/MMPTvXG5fXI7leMyEubS7XzAdGkge8xV6sC1
         umQmKd5TvhiLepsgv8l9M7kO4oJWwrEk7w4+OGe9Uqe9+hMkMKS57y+I3ggP7PFQdbW8
         q4LAQZZQJbzSsYnK/IKrr/O7z8DKYIbK9Q+c3HLvsCDbkL19EMliOhqmB5jqARqHRadu
         4RTxYAki66miUmlL5j4VhFVNvfA4TRwxdqKU0Ossj+aok1K3BCXS9qpLUPveATmTtJI/
         imIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=J8aQq0R4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id o29si784908wms.1.2021.11.30.13.41.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:41:47 -0800 (PST)
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
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 07/31] kasan: only apply __GFP_ZEROTAGS when memory is zeroed
Date: Tue, 30 Nov 2021 22:41:44 +0100
Message-Id: <938a827f9927ee2112d98e2053ad7764aae9d8f8.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=J8aQq0R4;       spf=pass
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

__GFP_ZEROTAGS should only be effective if memory is being zeroed.
Currently, hardware tag-based KASAN violates this requirement.

Fix by including an initialization check along with checking for
__GFP_ZEROTAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/hw_tags.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 0b8225add2e4..c643740b8599 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -199,11 +199,12 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	 * page_alloc.c.
 	 */
 	bool init = !want_init_on_free() && want_init_on_alloc(flags);
+	bool init_tags = init && (flags & __GFP_ZEROTAGS);
 
 	if (flags & __GFP_SKIP_KASAN_POISON)
 		SetPageSkipKASanPoison(page);
 
-	if (flags & __GFP_ZEROTAGS) {
+	if (init_tags) {
 		int i;
 
 		for (i = 0; i != 1 << order; ++i)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/938a827f9927ee2112d98e2053ad7764aae9d8f8.1638308023.git.andreyknvl%40google.com.
