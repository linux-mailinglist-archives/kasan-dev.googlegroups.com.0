Return-Path: <kasan-dev+bncBC5JXFXXVEGRBG6RYGLQMGQEIOMNPDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id EA10158BF25
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:36:27 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id y10-20020a2eb00a000000b0025e505fc2c4sf2068088ljk.11
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:36:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922587; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ouk0iCOoH3QRbu0pDgIYX6pdgMktOySf8k2oeRcBmGGOrpKoPPfDYxFBiqCGi6t7hp
         stjF5RCp7xeNnDIhGIfNZ8DpJqsJcdz6Lrf1efrF9axp9XyyJjuu9vi8ayQU0dDDkbKL
         w4RUq/EDgjzLekA1dRxTf+BBk1xTFhyFjLLV/g6vPKJxSwzq3vxV/i0VHuwRtxhcU8eq
         w22BvzjewJ1cnShN6y5ow7OotQTvoVTCd0Au9jjPFiBI3SrbHemlC4RWKu0auJ3L6q8e
         YnCOzQpj1b3zTso/uy+84vW8oL0zWG3+UlFRvSv4v/QDY00eg92GzzrZ7De/K62weg2a
         zbQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=sKZHX3bsC63VJZESu5/zozMEdtnFboJ06JBzxl4ZbdQ=;
        b=anH38uFspFvakGjW+fqxOuSobeXxDggkRNq1ZoCXoZ92wgJH7VeiNbJSzt63O1FrQu
         Nuo0gDgMXz7vRPqTn3slNslqkrTjR9EL2xyI/RaFAEBzGrgj6vJ0/3Re+FcJPz7MEQam
         ONCYqoPNAvNS4KS/6z9R+GggbzCNDAQyLyP3n66B7kUBeQMkPpVj1D05U0n7i7CMJgcY
         lor/ufhPk3UkSzXU9tLzQ+c6xJKU1xLCSFnNpsDpvVojaoaFbud/yy9PJbMaNPCLYL3d
         SbZD4NaeVWKM5uNTKsgLzcKoE9Vrp+/bBtVjAI5OPY2jH1EgzighcAVpdwsTSDaNJ826
         q5kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="EwwEAo/k";
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=sKZHX3bsC63VJZESu5/zozMEdtnFboJ06JBzxl4ZbdQ=;
        b=H+Oj+bCs9qjRYgKCjdFIHhZ7+wU9hg1GudrqWQOjrfCtuK0grVrM0Tv+BBJrlMUZvw
         No78ama3Pt5EVWVOeE7Mt2wSWWQW427kvrTAl5F/1fDQWcT55nkbTA5XT+MnGNobxugx
         XxaBJFkWkzytgckeCOOByCitrhkQhV154B2BeffaA9wbduSvTaMAj2pXpj9zFIapYUjm
         UsoC6Q39Bk0RpxWz6wy29yJOqQESRXVW5jlODHpXZMt9vmgpv/o097qsdpy5h2JK0x4O
         w2ljy1OKtoiWlKRtdmD0kMi+briZdF27ctYj+MzpYmVyrHOL4+SGVhTkEL4ZbsM7STG6
         6afQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=sKZHX3bsC63VJZESu5/zozMEdtnFboJ06JBzxl4ZbdQ=;
        b=z+RXvA0LYKGOO+r88Ybi0tB8LDlvksOdSVzSDZIGzFwo7L3LOySvZWAqaldBCZFFdT
         0+TA0R9IZ2GbFLqoR55xA4rsALyelfcS2t6NSH8t/i9k5cCIA1KmG32UAhbjsciUTJkE
         spxCeckygdhPL25/tNcB+2yVeAB92BMHvFw10XoeJw3WKr+TisZS38KF8PnQa3e7nrut
         NOe4/rrl3Bb5bXskG5XNIcq0eyIEDKHyZ3d7igYDoq6owhmeBRjaxQU7pqnYuY1k5k8Y
         B9+pYH+gVJr3x2xlaH+PNdC31uDgQKuEK4DpKbb/eS3H1pl1iR5911DulFhfr+v70Qmb
         l0/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0TbzfHEsMJU4XlD9DkxWfs35ZlZ6VkbHqiFYP3gwJS8Eqh48/1
	qZy4BuqiBqBNJKDyNt3A/8o=
X-Google-Smtp-Source: AA6agR69EhfOvf8lsdZJ12QdhkQ6J8fs/5tkds3w/oL8AvilLIR5FfYRe5RZqO1yeXidsL3YZR9rEA==
X-Received: by 2002:a2e:3515:0:b0:25e:7139:345f with SMTP id z21-20020a2e3515000000b0025e7139345fmr4883844ljz.129.1659922587381;
        Sun, 07 Aug 2022 18:36:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a5:b0:48a:f49f:61c4 with SMTP id
 v5-20020a05651203a500b0048af49f61c4ls1867465lfp.2.-pod-prod-gmail; Sun, 07
 Aug 2022 18:36:25 -0700 (PDT)
X-Received: by 2002:a05:6512:c19:b0:48a:f3bc:5537 with SMTP id z25-20020a0565120c1900b0048af3bc5537mr5548069lfu.490.1659922585750;
        Sun, 07 Aug 2022 18:36:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922585; cv=none;
        d=google.com; s=arc-20160816;
        b=Q8Z+lgI42TcA8VgGq6TrA6hCO4QHB/IM58pGGUYvsmmVoPTRapZY8ZJQ6Bkn63ADo6
         zrAAwQkGOoJKcvkDMJOyXhC7epu0J8aw+upwFjWjuziMB2RiDdkAiL8Rvi3FvroDS+Vm
         GxvScvztTFbCtlECGEjTVst8y0kbF8087wy/EaQQTDLJeOOkx/1ErnwP5RRXnFcK6I79
         FZxKdJCr0O3phLCnOM4KXhgKwuBIPSth4108ox+X14xCtSqDZA1KNKqphBN6wf0liuFH
         ZJ4gJ72EEpmKBqejg8RnY23zvStaPUVhCJXGJKey9YXeNBDbHP4YZvaSv3QURrKdAPwf
         NWgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hqZxr8yTtuU6L/lt5Z9IZ+Zd47Tj9vQpybJBTa9AqCY=;
        b=VD0nPpP1RVXpoFeahz6lk8P8sXk8OR72vFgybvwUPPpRoEoEVItpCzHsfMepAyTtnt
         Ktb6wJxgXhg2R72J+Q3z1RAjuzhiJ3ntfYWEvxyxuVmR34hNxrCCl1dGAxOSPVcvRmlo
         1OTxA0KJ3yo9UX97uS5H1jbnBzWk/Qg6td7/H/IfQZpk+d2IKqNbJgl23eA1K0x4k6m4
         JvsZlP/ZDYlkgo1Y3/J6lr9q3/dO36oVoyV0qsQ7V8qNlKmeYNEhz5si7H3lN+FZa0vG
         dLJgkudyCtZJVqgQHPYB9oBASApRgGN4Jb+NYFc47tMJSWfpQlhaz8/QP9hl+rj4eSZK
         mcrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="EwwEAo/k";
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id e5-20020a05651236c500b0048b9bd44f26si145357lfs.9.2022.08.07.18.36.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:36:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 1B4FAB80E0D;
	Mon,  8 Aug 2022 01:36:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A3DF8C433D6;
	Mon,  8 Aug 2022 01:36:22 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH AUTOSEL 5.15 08/45] mm: kasan: Ensure the tags are visible before the tag in page->flags
Date: Sun,  7 Aug 2022 21:35:12 -0400
Message-Id: <20220808013551.315446-8-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013551.315446-1-sashal@kernel.org>
References: <20220808013551.315446-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="EwwEAo/k";       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Catalin Marinas <catalin.marinas@arm.com>

[ Upstream commit ed0a6d1d973e9763989b44913ae1bd2a5d5d5777 ]

__kasan_unpoison_pages() colours the memory with a random tag and stores
it in page->flags in order to re-create the tagged pointer via
page_to_virt() later. When the tag from the page->flags is read, ensure
that the in-memory tags are already visible by re-ordering the
page_kasan_tag_set() after kasan_unpoison(). The former already has
barriers in place through try_cmpxchg(). On the reader side, the order
is ensured by the address dependency between page->flags and the memory
access.

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Link: https://lore.kernel.org/r/20220610152141.2148929-2-catalin.marinas@arm.com
Signed-off-by: Will Deacon <will@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 mm/kasan/common.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2baf121fb8c5..0c36d3df23f3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -109,9 +109,10 @@ void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
 		return;
 
 	tag = kasan_random_tag();
+	kasan_unpoison(set_tag(page_address(page), tag),
+		       PAGE_SIZE << order, init);
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
 }
 
 void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013551.315446-8-sashal%40kernel.org.
