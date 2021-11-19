Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK7G32GAMGQE3QXK5CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C27B457088
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 15:22:36 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id q15-20020adfbb8f000000b00191d3d89d09sf1807297wrg.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 06:22:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637331756; cv=pass;
        d=google.com; s=arc-20160816;
        b=wkg7Juy1tMH9wtBImh6OsNLrrHSrrW0wrU/AoW1gpIqeVaRECiZi5V5N/oXrOV1Bat
         naTrFuoIBTB77beQII+EEST1JN90PnwVAB+bnT8r5Z4RXQa2CGnQsRaKjGgwjS9hrXUp
         nSuAkr0DF12EFKAiSVwcgogfqg90Uo/HB1i3/8fBJ/CuewLICAsKrFx6b9fzWAF9LFkm
         jZEEj3I3dje/aw5Aq/7FOoDuUcAcBu5WO2j25YkCh7tg62T5YgVqCkxdTWr03LeXq5EZ
         sFIkrjMAtGneoNQ2yH7FKeXpfF41J0qPg42ZEWn2fw2LB3nGxUD5TpuQnafKulRQv3w8
         rm9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=QYAMHe+MRv9nRZXQWCYa1eUOikMBPZL6Dt9hwvFom4Y=;
        b=GtdTMgEnwHTzXWbeKl2B54etGSRDVFmvTJUX3JWzpmthbumO4FDZ0bhHoLaf9Zytic
         ucEHczb6EPVEt9UtaYGuw2uN3/KdaNYZlFJ6prucPp/UKXlwT6wZb+P0Hpyezx2Scnrv
         9K+IfUSbqJebkvC3jetJxE8I4hi3/+F48qr6PsqFreuD+hq65kQEwNKMRidFm4cS6AV0
         /EQ39WuWKdbUYcVJ8Pj5cPzhR5zoy52fvrHWvqKGs6MYLIz9SpcqcJ9EHlCJ6/qbsMaB
         LiCWEHJqmNqYo/XoLefaR8w4mlzlUSRRUf12YgmQu4pYc62qSUeXcKCZxcjdDSt3Qc0y
         RLfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="kyZ4PLG/";
       spf=pass (google.com: domain of 3kroxyqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KrOXYQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QYAMHe+MRv9nRZXQWCYa1eUOikMBPZL6Dt9hwvFom4Y=;
        b=puVscZKzJig4kYsqRLCals1rOIlKXjOOfflK31t08FdE05X7oFmf6cmTbUDN5sv+e9
         2tBlE6q/egQxdM02R/15cnp563CQu7BjLTwnRuYnrHl75twN3OEbnbrEKdw6ByzDDtqG
         PD9+TCHe+5TOLjLHHZ7SRPkBsh0N0AQIfnQarct/bViL8UouqtwJ/cFyGfhi2hVeP+ii
         6s0gD/DAf2SQlnqkM+WyJsemFSKUp5XC8CIGUCimw8hx0P+hFjGvsoLvkGXXmR1qr6wm
         CTq+Cy3DeKweSsPazNQ0pi6OxTSiP4pL7//nVCrWUDl0ctydaO386pkoGtAQwIkwDlMo
         e+jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QYAMHe+MRv9nRZXQWCYa1eUOikMBPZL6Dt9hwvFom4Y=;
        b=ztfB+lONhmTeF+TuMe3WH82BBdCiSpq+xglYXQGopEkz3A9ZKgZaonbxtg5OdwgJcl
         X0tawleznq1lWksRrThju7zmrreGng8Pdu60nY5WM48wPFEsTFAiuferi5ljYbZiCVaV
         dITOUtxkAIKMA6ckBYDnjr5NyVh4lesd0p8HLRr5sZP95heklz29DMf6hbqnmDkt6cR/
         MPe4AjNltpwS5oolyj3q1cTcnlUV9xMkFb6NvJTqz8HzjS/OugyfQGW+UtXKGCxP0yn4
         V0aSw+51WaijSt3V+MwOF5EALfHsiv8hSNKpHSRknqIau5u4qUpBwnvdTulkM0o5rdE/
         v9OA==
X-Gm-Message-State: AOAM533IMzieNs8BPzXXOtjG25lO6OqLM4FIV1oaXf/A/SK63+KHF29F
	6A9v8pj6429OmRXYSlic02I=
X-Google-Smtp-Source: ABdhPJz4G01Q/w1TeWDz+GdwYKgI18gI2IIvMVSML7XkfGye/9CkLg9N6/XYGKPJrlv+QGu9XURJPQ==
X-Received: by 2002:adf:ecca:: with SMTP id s10mr7784713wro.405.1637331756056;
        Fri, 19 Nov 2021 06:22:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls3395872wrr.0.gmail; Fri, 19 Nov
 2021 06:22:35 -0800 (PST)
X-Received: by 2002:adf:f08d:: with SMTP id n13mr7991864wro.395.1637331755122;
        Fri, 19 Nov 2021 06:22:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637331755; cv=none;
        d=google.com; s=arc-20160816;
        b=mbvzuURKvEoUr3gNJD7ww2yxxIbQ95mqyaek1GhMMPzg04vOCKvebxvJFFzbprX+D6
         vDrLGnZrvHJ0T8752ezOujfXXNghPM6JQjUjjnyPwLaLbb6CP5PyrfuNpNevns1xUlz9
         cpcMTNEPqZOd+SiAadhn3k2HyqabQXlgCS6zhBxsaaAzxYtQzMnXgt66dgEnSzOUb3lB
         +ApYUK9KAv6DbSO/4Adw9xY7ET4lavky0RJ0iMLFEAsqBpMLvTTbutMcXnMmQ9XQ3c+Q
         N+qGrTX03KPjpPL4Q5zraXbvuFkncUwg3o8AN8vyvhiWh7AxtDh/f1ux/SWIuEnLyas2
         uwqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=X7iq6ptC+Z8R2N/iJA3x0lSwxpZSVZxJX+z9qBEEm6o=;
        b=S3eQ9dDNLNp5xg15j0bwR4hV/6/RS+0X8CYn0D2djfUhqTCDvhFStfrHi5Mu6tfwCo
         37GQQAPCROpKGrsiR0AZrMvo2WxQr3ZJP9t+ra22Ad9QvsnGCUBgH7uATszxtGeHvA1T
         AyhvMhyefD04nV1Bh1GLNr3pgkzT2N79BADoy3LXRMHSYFTCk2wLI/SvPP2eLk+m1Obu
         H6QG9QBLwZtsRVa+7nweiIblxP4LaILxpNckwjKHIj+tV3L9frR6stXOwl4/ovJsfLKE
         1tNy+3JnONzWEiYNqIVKxTVFsjvVuO9UyYZrk9sBDs+rTkaep8FaJkGNX4lk1rSnE+ce
         Afwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="kyZ4PLG/";
       spf=pass (google.com: domain of 3kroxyqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KrOXYQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 125si829830wmc.1.2021.11.19.06.22.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Nov 2021 06:22:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kroxyqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id p12-20020a05600c1d8c00b0033a22e48203so267185wms.6
        for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 06:22:35 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:24a0:cdec:f386:83d0])
 (user=elver job=sendgmr) by 2002:a1c:9d48:: with SMTP id g69mr3458wme.188.1637331754628;
 Fri, 19 Nov 2021 06:22:34 -0800 (PST)
Date: Fri, 19 Nov 2021 15:22:18 +0100
Message-Id: <20211119142219.1519617-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH 1/2] kasan: add ability to detect double-kmem_cache_destroy()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="kyZ4PLG/";       spf=pass
 (google.com: domain of 3kroxyqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3KrOXYQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Because mm/slab_common.c is not instrumented with software KASAN modes,
it is not possible to detect use-after-free of the kmem_cache passed
into kmem_cache_destroy(). In particular, because of the s->refcount--
and subsequent early return if non-zero, KASAN would never be able to
see the double-free via kmem_cache_free(kmem_cache, s). To be able to
detect a double-kmem_cache_destroy(), check accessibility of the
kmem_cache, and in case of failure return early.

While KASAN_HW_TAGS is able to detect such bugs, by checking
accessibility and returning early we fail more gracefully and also
avoid corrupting reused objects (where tags mismatch).

A recent case of a double-kmem_cache_destroy() was detected by KFENCE:
https://lkml.kernel.org/r/0000000000003f654905c168b09d@google.com
, which was not detectable by software KASAN modes.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/slab_common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index e5d080a93009..4bef4b6a2c76 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -491,7 +491,7 @@ void kmem_cache_destroy(struct kmem_cache *s)
 {
 	int err;
 
-	if (unlikely(!s))
+	if (unlikely(!s || !kasan_check_byte(s)))
 		return;
 
 	cpus_read_lock();
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211119142219.1519617-1-elver%40google.com.
