Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRNQ6D6QKGQE4UZOFBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 28F8D2C156C
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:03 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id i124sf2795008pfc.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162502; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ufet0w1XUJICE+VzcE+ezdvxftslQ6ZDESbKTPHQJUN72Ta97HY0AY4k2NGjnDqp0M
         cHjPxYfndqikbPaLxD4Og2tPG+WPY2/eoESgn76K8fWQalRN3mtr3ox2h43tFOg4jn4P
         lqhfiEx3xKQThEZiNdM0DtRAIRd6AXBUAFFpybJvqE7xkZ4mXd+K4GZdwoTcVv0W4pmj
         R6hfF0OlifhuXQl+T6Z5iqBptzPZvcVhAOm5DE80y96xcLId8lsfJzLkgnumuSy5Qkhi
         kin2HcVlvLTnnaKlzu/zPqUoBCkTObzdERPE2ZzxdInQTFqTZFgJ6nTYegLx0nJgW6kb
         J8Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=mCPKUb0ToWT0X/nHVb96KtGSvaLGpxRl/KT+rNPvKOg=;
        b=CUDJPKc8VoPZuUhIS+6CjzKyvWUxAYflDEsioYcqERqVwkP+aA/xWPbdq6ZMJM9Sis
         KNPgTX0hFuL9P/xb1kI97EtKKZ3rSxtMiBvmeaayVj+S0j4pN87YYDrNmNbz17+mpd5+
         dsxllDbT8to8Q41ezTxoAN6gtPHoN8xkEKWv1TlvwYlDyYekarMQrA1GJjLCLCGQyqE4
         SnGlZDRfy5RhUnAR+5cec4JhUN6xhoyK7OkIYBoeAQ3LWlKPlwnZHYD9JBsW2BHMtRed
         XjmLcF3+4UqlF9Ho4jK2tY8LxTPD0unvuOR5rLXoEV68tNWAG0kftZAFfuc7fqo429dx
         qh+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X8wfvSUP;
       spf=pass (google.com: domain of 3rbi8xwokcwkhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3RBi8XwoKCWkHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mCPKUb0ToWT0X/nHVb96KtGSvaLGpxRl/KT+rNPvKOg=;
        b=BkJlb8HqVIzP9imDhYaTwi8fmzglRYAPOJHtDU5Zegh2UNPHuwDNWnfGnJDnyvFJvL
         6pazVtuIwRb5D+2gLgUP6RsZwDCjWZ0sDt+PJXW1eS2gq7UsvZENznMDOYFVctC/pfc3
         iW79Nc0e7rOa83Xq4k/s7pIbw5tutzXaQQ6Exy0mkoD16uMB00bmNBqsV9cFtD8cVNC5
         +wJE2G6OnZ43D9IX94rXUfCqcLWfDXHDSzdSs8BQqCofMXrDBxLL2CODODQ+d+0n+LuL
         mjvyCksmOb0MQSTpKaVWi8RShJq0xsPIj8NGngwGg7y6nzSB5Xvk+Q+z1VSRIVrecYHU
         mjpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mCPKUb0ToWT0X/nHVb96KtGSvaLGpxRl/KT+rNPvKOg=;
        b=YqqmWBSsDLVHzccoQCym4nLRVpj3+UY5pEbvyzvb2ySAVEayb8NOLQMUr9zMEdShaD
         Ujv8ccEKlbHmiCaoOJ24Kn7fIKnCFHnFMvo1EN8+suuZOeINRtecFIlVK0OFg+pxv8IX
         0N8msQ6WfPsfhwhyHRyDV3h16B8BdPy1CN/WibAyuF053sNIx+iZw1WOK/6pec/lrGUU
         mdhjYA5maGXOEnx5GOQTJPzabPKnSQsoiEYj561EoH1Hze6F4wTtqPmX13RUNHrhkQS0
         QI4cKictSJxEwvHIIEv9DlzNgeyi9S5SoRQ/obJwGOcCz+IzMIYYQwzEdPysVjYBKiS3
         PEmw==
X-Gm-Message-State: AOAM532g2y7t6tKklzJiunZcAlvsNNc+spRKQ/mzh4y4opvxlplJ4f1W
	6Nill512FXqmT+3lylAwDBw=
X-Google-Smtp-Source: ABdhPJwvUbbX/X5cUH8bDU83NPuRMPk7zKVlJliikjN8I7cFCRZKHtBR0Pc4aFFsJ9NdsuTrlJb2cw==
X-Received: by 2002:a17:90b:4595:: with SMTP id hd21mr667877pjb.127.1606162501909;
        Mon, 23 Nov 2020 12:15:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a503:: with SMTP id a3ls213172pjq.2.gmail; Mon, 23
 Nov 2020 12:15:01 -0800 (PST)
X-Received: by 2002:a17:902:aa4a:b029:d8:f4a9:691f with SMTP id c10-20020a170902aa4ab02900d8f4a9691fmr943056plr.65.1606162501381;
        Mon, 23 Nov 2020 12:15:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162501; cv=none;
        d=google.com; s=arc-20160816;
        b=QpBzNF7WUqd6MLSuycedQzOgfPAz8KplLO5UkpMIyOGN2l3X+NFlcTm3y55EJ2EjnB
         zK3GSmWKZcYEtten2hyF5TrEQCV1zE2Ac96qZZKqRZi5e46lngTQbfAUhZ5jIyy+TwPK
         EkE6Svc/KadYHsjAtTZSlsczt45t6XXLrFx8sxasCGnd8sM9ks1VAqtIMYQiaZjAA9QZ
         fWAcvzM4LOyZlwhGBgKzkT1BfQElWFfF394eAYxQE1ZrMf2pQ+dFVDIc/5mxkiLv61cJ
         JgXvcH6sM/txzjmx++7miGRqCQnqITRseI6VzXtP6vLjgdFnLNT1hK0p0sFvFCdBf3Zw
         nLWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=X0qNbr9WproLcGX2R7jejC4I91Gg1JCilClxf4uOdQ4=;
        b=dHwiGpCx+YOy6A4hMXYMviS0ms+D9dJjwC5hjSpz065ryLEH9+iuYAjKk/HZQgeAPd
         i2q/KNN3aZwZwzG2vUqXyt7jJVflIsJPaHvJ7L4KIMjtOEfxGT2H1EsYAF/D/mpEZJB5
         jcLa6WE+GqbbbjfZytvtpoRB/er0xmPUaPTOKmpdnY1CH9Aar8hBlJJ+ezTnfZNBFKZ4
         jD3/OW+/1zlALr0RD5H1UWXiQvJlvkOSHcJrm4cMc+hJv0cHTHzoZEeqpQ4vOvg6uZ2h
         O2Oomwg9rXACBtJ2+06CIqyK3eDGUoXQVOr9WvahBuaLO/N2Lpn17OxD00wZ14O7cvzQ
         nILA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X8wfvSUP;
       spf=pass (google.com: domain of 3rbi8xwokcwkhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3RBi8XwoKCWkHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id ch19si66470pjb.0.2020.11.23.12.15.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rbi8xwokcwkhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v1so13717058qvf.11
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:01 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:9a9:: with SMTP id
 du9mr1102774qvb.47.1606162500502; Mon, 23 Nov 2020 12:15:00 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:33 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <b2393e8f1e311a70fc3aaa2196461b6acdee7d21.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 03/19] kasan: introduce set_alloc_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=X8wfvSUP;       spf=pass
 (google.com: domain of 3rbi8xwokcwkhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3RBi8XwoKCWkHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Add set_alloc_info() helper and move kasan_set_track() into it. This will
simplify the code for one of the upcoming changes.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/I0316193cbb4ecc9b87b7c2eee0dd79f8ec908c1a
---
 mm/kasan/common.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8197399b0a1f..0a420f1dbc54 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -327,6 +327,11 @@ bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return __kasan_slab_free(cache, object, ip, true);
 }
 
+static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+}
+
 static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
@@ -357,7 +362,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		     KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
 }
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b2393e8f1e311a70fc3aaa2196461b6acdee7d21.1606162397.git.andreyknvl%40google.com.
