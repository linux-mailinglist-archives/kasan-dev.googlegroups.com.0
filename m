Return-Path: <kasan-dev+bncBCDZVUN45ELBBROOXHWQKGQEV7HWNPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BA3BDFB87
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 04:19:51 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id m25sf18925396ioo.8
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 19:19:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571710790; cv=pass;
        d=google.com; s=arc-20160816;
        b=aRvezmrtk4KM+nJXueU2MAZwHtwLIKu5vYomuMxKywRAO73KTKw84vurNrv4lYH/Yu
         fDpI0cyFnnfXsbzoEN5rRFWfUTizKcd3ojwZOPgscGa6qHbtjy8v0r7KwkVUoMvrdzXS
         405aw464GeSyVBHao9zUp6K0MzldDSiUetpibNBaWvw1bsidb7ecRJfAKpJLBYr+Xxif
         r+Qqq1MNhu705ok+cjIr5VYer4hKPSoqd+Owmyd0kU9W6yfUYs+u+jgpg1m+vB4rMCH9
         IHzP5J7fcELTeclYg+cMkiWTexavgKMfyWTWx8Q3cqwhz2wKel9UdJlNhe60JA7zcjxU
         gR2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=CrT8kJwroeFR9QoKNC123wYclMtcCrqb7dC8JWHDqCE=;
        b=c5VSrh+0i5q4/Bw+ZFvkR253LSr6R3DmLLaAazN4J+08OFuvdjlkCjlfUbNmIXK5mw
         ZKVMELqcvDyfgY8X/H/jEqD/BcJk0XfkCOF54cvICU/IyXISQOwUEU24Vzxl4vstBpLR
         vpJ/PgCdK8nGPdfuylUWYjPg61s1KjB/VDZHikcSfwqnzB+kRBJ36GiVePepXCwrwL5d
         egZveaVdZ7UknBhwDlPUgLu6lNcMPDLFj3j+RoRSdEBaOTBfmnuaqd+fPEYVUQ+glUPP
         6pILUV1+3FSB/GtkrxNzVlGLH7I88HPfmum8P7d6aZwLY4lhMoCZ8grP0bdfi8HqBqLH
         ZxYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Lc2b2oYx;
       spf=pass (google.com: domain of lyude@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=lyude@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CrT8kJwroeFR9QoKNC123wYclMtcCrqb7dC8JWHDqCE=;
        b=SQArwC6/CZyDtzLNkrAUMAqBMEDKZfTUEWPyakjxJfjUyFZCQHrSqoLQ6JA5MWAjk7
         uaq9SlGwU1GV4PTabYR12o1j7Wz0DTMgOHpb5ph153R4ZIeQCG8UvQSavsuIyQl+0GIm
         JKCLw72CzDWT37iF8dLHfuYrHps+4CovaeIfH9afa+WmpvVr/EY4NiuU1n+87OEbIiO+
         ugZE86W7saJtHR7ZiOb0jSsxxsKHp4kp99Z3wUxcpNbx0d9mGOItFNP5i4X4SUuCpeIl
         ASZ5JBjsre3d7iGBqwYSv8k3NkmzekhgkA5CWYh+05vUUjaDQfggdkBLHmSdg3oC+SfO
         EThg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CrT8kJwroeFR9QoKNC123wYclMtcCrqb7dC8JWHDqCE=;
        b=DBdGKjnMW81TgdoN6nARMZFtg7EqSCwrYohPR9ylEqiqzmk/jkiUhMUMevKE7ERzar
         63PJ/qe1mYxwzcVgiP8njfmtu3FWl1GropTrPA1JccKwcVpLRZK+QTxi8ULFxGcMKoTh
         bm6img82/SGzkC21+VtLxqoDAYsRghBagBe7Uwfa9vasjiH8k6iMQGBKyx8P9szOLVA+
         aQAq5y1F6ZPTVqvKlq6Y1zCe1jsKY/dRyii1is9xC/DPu9IGfcIz9zCeSTtDQLDIXsMF
         9zW9udFgV1af7UNXirZuztzCYu+r0wF1BY+1X+/4Bd0zbUKkU7zCsgjFqrrkILmBAh1m
         Apdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWxwP3M85dWTcYqwreWsDGEa7Q5raav39S+T8jtSbhB/F2VkvYc
	AZSMOPsBXzBVmnYtJWBpR0A=
X-Google-Smtp-Source: APXvYqyxTgbMQ4uiABohPjq70tXe6sRDH9800ORpMkDleyylcuKVX85uWRqhx5LAhPNG2A1OEU8BWw==
X-Received: by 2002:a92:5e4d:: with SMTP id s74mr29460915ilb.121.1571710790006;
        Mon, 21 Oct 2019 19:19:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9309:: with SMTP id l9ls2986706ion.3.gmail; Mon, 21 Oct
 2019 19:19:49 -0700 (PDT)
X-Received: by 2002:a6b:1582:: with SMTP id 124mr1442725iov.164.1571710789616;
        Mon, 21 Oct 2019 19:19:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571710789; cv=none;
        d=google.com; s=arc-20160816;
        b=Hj4wI4LLgikILEdpS+IFy/dBeAlPF++NbhqleqBoXaRcjBZ4hvUwvdfzk9rhVjiHQi
         QxDclr2LEh2pp6KQnVNmyg4L9o7mjDTfzTM3wocHZ8cdtiDlS2B1neDWabEGbonoaOpe
         Ea5HUKCfI6zyG5mb7LHn8T2rh++M3ENxAE15BzOG9+KH6yR639kFMZGsHXAcruiyYrYz
         kkp38K6pkL9vLn1KnAf5qoIc461u+QJwPLDED63GzZ8dWNWdGucZ86CkdeIzw9BM4Zci
         0MWLc0kbZbRMQ2TPSqrnblw1BQTbu41VBCB0aPJIsZY4f0jmW1ww45pRMI+vInv3Gmk+
         gwGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=cy1H0yNRlADn6s5BcmmX0kDdj1YRyEm1IRV1QcI4xNE=;
        b=XID5kLZlFL2m7FqA7nuBLHSM8HctvuGK/+blDaEpgPtA0OdD7SIOdJFu2a+taHKrEG
         E8KW2ohBHVC5a8ojW8JdsjT3wEiVXm4uXzKZcruAw5vm8OXp1WJn04feGziqjNNb0GhE
         YFiB9nOEm5N67pgqJfS4c4w7jygV3SEYkhdgn7oJJgOgnrVhRq2yRSFTGYIoi9C0n2Fh
         KxRAwkMIyDTceRnCR4G/lmyIici0zBkW98J+SfFdnoRFMadODo1oKuGNiRzPOvj0LyOv
         E7/MZDbKswYHoyjETF64nJ9bmCEhPuu52DdTw85NPzGGAlpw5pBCFQAgYTmwph1DBj/n
         fC0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Lc2b2oYx;
       spf=pass (google.com: domain of lyude@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=lyude@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id b12si1022646ile.2.2019.10.21.19.19.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Oct 2019 19:19:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of lyude@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-378-qGaYFtxgOfqv3l0NUq_F-w-1; Mon, 21 Oct 2019 22:19:45 -0400
Received: from smtp.corp.redhat.com (int-mx06.intmail.prod.int.phx2.redhat.com [10.5.11.16])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 3B345107AD31;
	Tue, 22 Oct 2019 02:19:44 +0000 (UTC)
Received: from malachite.redhat.com (ovpn-120-98.rdu2.redhat.com [10.10.120.98])
	by smtp.corp.redhat.com (Postfix) with ESMTP id C7EA85C22C;
	Tue, 22 Oct 2019 02:19:21 +0000 (UTC)
From: Lyude Paul <lyude@redhat.com>
To: linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: Sean Paul <sean@poorly.run>,
	Daniel Vetter <daniel.vetter@ffwll.ch>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-kernel@vger.kernel.org
Subject: [RFC] kasan: include the hashed pointer for an object's location
Date: Mon, 21 Oct 2019 22:18:11 -0400
Message-Id: <20191022021810.3216-1-lyude@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.16
X-MC-Unique: qGaYFtxgOfqv3l0NUq_F-w-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lyude@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Lc2b2oYx;
       spf=pass (google.com: domain of lyude@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=lyude@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

The vast majority of the kernel that needs to print out pointers as a
way to keep track of a specific object in the kernel for debugging
purposes does so using hashed pointers, since these are "good enough".
Ironically, the one place we don't do this is within kasan. While
simply printing a hashed version of where an out of bounds memory access
occurred isn't too useful, printing out the hashed address of the object
in question usually is since that's the format most of the kernel is
likely to be using in debugging output.

Of course this isn't perfect though-having the object's originating
address doesn't help users at all that need to do things like printing
the address of a struct which is embedded within another struct, but
it's certainly better then not printing any hashed addresses. And users
which need to handle less trivial cases like that can simply fall back
to careful usage of %px.

Signed-off-by: Lyude Paul <lyude@redhat.com>
Cc: Sean Paul <sean@poorly.run>
Cc: Daniel Vetter <daniel.vetter@ffwll.ch>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
---
 mm/kasan/report.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 621782100eaa..0a5663fee1f7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -128,8 +128,9 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 	int rel_bytes;
 
 	pr_err("The buggy address belongs to the object at %px\n"
-	       " which belongs to the cache %s of size %d\n",
-		object, cache->name, cache->object_size);
+	       " (aka %p) which belongs to the cache\n"
+	       " %s of size %d\n",
+	       object, object, cache->name, cache->object_size);
 
 	if (!addr)
 		return;
-- 
2.21.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191022021810.3216-1-lyude%40redhat.com.
