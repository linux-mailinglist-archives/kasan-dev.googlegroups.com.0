Return-Path: <kasan-dev+bncBCZP5TXROEIKTXPJZIDBUBBWUP4XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ADD5CF101E
	for <lists+kasan-dev@lfdr.de>; Sun, 04 Jan 2026 14:44:11 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4ed74ab4172sf327996481cf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Jan 2026 05:44:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767534250; cv=pass;
        d=google.com; s=arc-20240605;
        b=llCmEtywWRNjM+UCeHFZzSeV/8PCZj5/NHnhoMXvhQX0kM9l51/OKMuULVUzPp9hRk
         6PufN+S7FEPtS+FfYBF6yyzYW7xinemQLogzFxeaZrIXFKvscBP55Ejnk8ECgk7XbmSa
         JVWVIeh/aAXqvgz83USRx6r83pX03Do4EWHZR3Q1X3skdJ6qz4AdIp+Vj8fmyX8a8e+L
         w74w1ElOvHNmHXtViti+Sh6m06KTQ3ocu9mg2D/zVmwx+jJchq0fuxSSovY2NJlZlG1J
         ey6/m8TH9DlrSifphXwM/NQWpACJW9Y8Z8a0yFeNAFSfwknOpnLDYKYP1OV7/e9T3tnU
         T2Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=q5mRAyQ6lXfF8lsoIFu4NqO6OUJZMXDoe3gsa+lEJ6A=;
        fh=SaY8fi7lpRz1IQrwyRmq9ME8pCqULOw9GLt3dV8tvnQ=;
        b=CDPuC8nnQxgdjOHXE9ZsqkvHD7TKt7Sl7QpY+inZfwg496j3QgqaI/1DTMCD6V1xyO
         tydHnusCBusgmr5LKCHdjbCSQETIbFl/82QjnfBybnif9LMjAFfseVQgUP1vNByW+f1H
         zrwNJoPkQQUX7RCIsdz/lkr//RfidiGTMQWC/Wgq+sCozljeYvCIcOQGSZUMBOrklRCl
         SNGbUpWYQxNa2oEpv/HZ3iE7m5F8287xypd7Mr8OQNGsrW1TYe+FB6FlgL2ZHC+3LIzN
         Jk2J10AZ8vVX2uCn1weXPjv0cT4VlDpNJBGLVAlt83qLuTzpNfiddMnqM2inhBByazRA
         doGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767534250; x=1768139050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=q5mRAyQ6lXfF8lsoIFu4NqO6OUJZMXDoe3gsa+lEJ6A=;
        b=oghoTKEGfVgQaOsFj6Y+cq/Elrhlc2OyxHy0LVEvhgnU4vmKN3pxQC/nI34XXmCcUp
         DPlJE+KR6qGMC4uwkk58FGDLDlsWPi0hb6gNZqfRWIZ+eYkgsfFapbxTT2u3QVvMvAIE
         L1rmcmXu7Rx3M8yeBfIsY0Yi3kXd/b2rCHZW6i//GBF8Q9jP2l8kD0pVQw+pmFdX16lX
         gsVsXk6ugWJNQKMMnkHhnOdHoELDn8IwfPt07p5Gyecu1q1wrBklan08I6heizVmSrKX
         i3EV+N8lfEqrrZWKU9YRKn5rMuAwUYHAQ0LEwFU6/CNwnjGnio7TP/nUSXsfTdRsNG0c
         BBCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767534250; x=1768139050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=q5mRAyQ6lXfF8lsoIFu4NqO6OUJZMXDoe3gsa+lEJ6A=;
        b=SkggBF7g+KYmAV+GxFDgTwqlg+N1edpxxEac7FZc1yDQpwGdKKiD4tFz6tOTCP9KVL
         O1CI7Np2jleyq0wVq9YDmUiZhXX1+8EVHZW+qvb0KoJaQCgEvBQV79/P4xJNbFcy7c30
         4a/eULik3RwhQuIWTT1Biv7RLw12BLVf0vzQVTs4l1FW+wZz4IaSYeJJ/GBFFkYDX0Xy
         LNbOCHJl3cywk4kbufz9ryabS5mx21o3Q40XhfpzGZYWyDhT9lkopJZjw3EhDH6qfAzd
         akUn07fLD80Q4dLkGnxY8Hd1jgtQh2bGsFMTxCSjtLw3qW6qMPXJIvWwp8i4PeDFUaL3
         eoGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU52ik1cGZ3sk9xVm6u2nFG5hYa0liEkkohrGTGty8RCdRy+V5diKcYVA0iD87dXxJQj5ApbA==@lfdr.de
X-Gm-Message-State: AOJu0YzUyKfirwedEMrW06kUoUSkVlezx/jciFj45eqBGyU/A7YgqV0I
	PCMP12zot/g1zjoNqrkcqb2RpXzG5RZu0FEsiQRqDmoCNAuf7ByafGbx
X-Google-Smtp-Source: AGHT+IEkdx/ubnmWM7lhoydgx/aJPYjhJFoW6dOvhh+yn3vjSgT08PkLB/3toZMTsGu/If8H6oLNpw==
X-Received: by 2002:ac8:5746:0:b0:4ed:dab1:8109 with SMTP id d75a77b69052e-4f4abcf6a35mr612797801cf.17.1767534250032;
        Sun, 04 Jan 2026 05:44:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbg1XM3ra33EFFKqtXUcSCsH9arayrAYOM3nJpPhafs7w=="
Received: by 2002:a05:6214:40b:b0:729:c1d:d07d with SMTP id
 6a1803df08f44-89036f73bcbls73533876d6.0.-pod-prod-01-us; Sun, 04 Jan 2026
 05:44:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWVjWhjIrMLuYEjqyZCCbik+smzwovwxyrzUH+6qI67GiRa+1+V8iqsfBYTH66w8KKjNk+2RqHoV0c=@googlegroups.com
X-Received: by 2002:ae9:e503:0:b0:8c0:cbd8:20b0 with SMTP id af79cd13be357-8c0cbd821aemr4747360785a.34.1767534248938;
        Sun, 04 Jan 2026 05:44:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767534248; cv=none;
        d=google.com; s=arc-20240605;
        b=SAMfkJxKLlfODSx0s2pD0qUnDLenTU7y6dQ1akOdJnuQPXT04GvG3Zao73zhs152tZ
         eyuW7C2Q8n6jWgNk1GO/As/TmJv+xW5amqZW9tICZyteaA83GNT237T2aE9REhLWw87e
         F776orVyqPFgK2CjhbjAOFDpmEI9Hfx6WxvQkv7dzQ+6uIaZtfVZVN+fbKnLL4vGvk+Q
         V4iP/3eVZ/UUOXOlawpwODVNY5fU20XKKMC3726XKtOt9IBatZEXpannxP/Ey1N6kmyd
         ejyygoWFhSDf6L7PQ35qpYqQIC9D6On9WNhjD8ER3zMzkJHK5jcmqNE1rCck2bZWyyZM
         FxYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=31alRJjH9aMomaXC5Ty+m1cilsBmQIpUnm1Eg7pXAIE=;
        fh=OynUuIcM6RxYua+81TlwCSpi2AzEULjeBx9GWRfM1BQ=;
        b=Ia0L5q8UcVp8KYJZ9TKHYG/FUL9lkwoAurH/r/Z5TzlMbkrN4XKhRJJgytff9evVjP
         eLnswezg0DfvTyinvTb7W5H752xwF3WMyJGebTsmhEyr67uTyAwivCsgBMptBDvfSylK
         ekjNXT039rjODB5TnOTE2sf9wgWs9Nh2I8o3DVF/pgJupq0fo34lYN8jOzyZqfBqbuDK
         WyJmoV4ZUYq8I3ujLwVHzc5zI/3sQOuqkJnkUeZKXffd3lLdPchaAS8765ImL3lantrs
         LoIR/xgSOmzHei0Yb7pVWhMwu9D3aUQHMNmSsylMeoyPKnkJc97nRaFqG3tqrm3MCw/y
         bKyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-8c09658e696si156498585a.1.2026.01.04.05.44.08
        for <kasan-dev@googlegroups.com>;
        Sun, 04 Jan 2026 05:44:08 -0800 (PST)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 20FCF339;
	Sun,  4 Jan 2026 05:44:01 -0800 (PST)
Received: from e125769.cambridge.arm.com (e125769.cambridge.arm.com [10.1.196.27])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D41783F5A1;
	Sun,  4 Jan 2026 05:44:06 -0800 (PST)
From: Ryan Roberts <ryan.roberts@arm.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Ryan Roberts <ryan.roberts@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Subject: [PATCH v1] mm: kmsan: Fix poisoning of high-order non-compound pages
Date: Sun,  4 Jan 2026 13:43:47 +0000
Message-ID: <20260104134348.3544298-1-ryan.roberts@arm.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

kmsan_free_page() is called by the page allocator's free_pages_prepare()
during page freeing. It's job is to poison all the memory covered by the
page. It can be called with an order-0 page, a compound high-order page
or a non-compound high-order page. But page_size() only works for
order-0 and compound pages. For a non-compound high-order page it will
incorrectly return PAGE_SIZE.

The implication is that the tail pages of a high-order non-compound page
do not get poisoned at free, so any invalid access while they are free
could go unnoticed. It looks like the pages will be poisoned again at
allocaiton time, so that would bookend the window.

Fix this by using the order parameter to calculate the size.

Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Cc: stable@vger.kernel.org
Signed-off-by: Ryan Roberts <ryan.roberts@arm.com>
---

Hi,

I noticed this during code review, so perhaps I've just misunderstood the intent
of the code.

I don't have the means to compile and run on x86 with KMSAN enabled though, so
punting this out hoping someone might be able to validate/test. I guess there is
a small chance this could lead to KMSAN finding some new issues?

Applies against today's mm-unstable (344d3580dacd).

Thanks,
Ryan


 mm/kmsan/shadow.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index e7f554a31bb4..9e1c5f2b7a41 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -207,7 +207,7 @@ void kmsan_free_page(struct page *page, unsigned int order)
 	if (!kmsan_enabled || kmsan_in_runtime())
 		return;
 	kmsan_enter_runtime();
-	kmsan_internal_poison_memory(page_address(page), page_size(page),
+	kmsan_internal_poison_memory(page_address(page), PAGE_SIZE << order,
 				     GFP_KERNEL & ~(__GFP_RECLAIM),
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
--
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260104134348.3544298-1-ryan.roberts%40arm.com.
