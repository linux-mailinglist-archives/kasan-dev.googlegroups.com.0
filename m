Return-Path: <kasan-dev+bncBAABBYVWT2KQMGQEG6FFEVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ABD6549ED4
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:17:39 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id h35-20020a0565123ca300b00479113319f9sf3525677lfv.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:17:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151458; cv=pass;
        d=google.com; s=arc-20160816;
        b=NJYvOEiE+vhVUi1UktmuWW6o4clTHwEQp6hOLyUfDsOJiMH3G5Wh/zI7kyKPpzzmFn
         F5KopVHMDkaJk/TbW/RE5hefMOd5iBN0XEW7GwG6I83TytbX03FWjll4ijc8Cc8KsSnk
         VsomKlK35EU6DUcTVLsiLbS+ZqyEgiiRJFEbhZrcMCTKIuWpNKeqzCHI2kn7jCLo498I
         PJVbyDfNP3d86Qpd5eBLa0mZRC8drF+VuHfeKl+ihhgkduTJqmA7lrTmppdcb6Av08gj
         oXYr175kGyfmzY2/oZSzc9tjFZCQMFygPmP9lEIfJwMhgkNDrhVKDdfBk1zXbOCHaRDz
         71cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aGeCa3RZDhPdtt+m+MOsGH5ZVRIhj+cFqCiZZ1iB11U=;
        b=tTDHirVFj4o4MxBjuS8TMQGxZ96XJahcsfNfCXgwx5UHtaZF7MxAG9wDlkpRFyXkG6
         b2XiwNVDZeBZl3qgO5OJU1jVaLIPBmhIcnSs/b3CTcCdDJJoNvHMCfZVCJIkT5kJbMIn
         rfPiH1ahifA1m5M4wrg4xH+kNENepkyO1nXsQOh4QegAnb0EdRc5WezbEXuzOoabbboJ
         uRIiAlESl0nYqojKhc1eouPet6vmgYgSRe3dMyAETGWW91N0kou7DIv0zMiYgliLSAJa
         BMsSvFp1uxK8BejyLamutthOl1TJPh5RjVqbPUU209R4k93906jVkV3bCAYtiWwH5CLM
         DIEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Dl9JaXiP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aGeCa3RZDhPdtt+m+MOsGH5ZVRIhj+cFqCiZZ1iB11U=;
        b=te2Jj+SYxC6zoiEydYJxO0mw20Nx2RGYHmncOfKCHW2/aEO3/YoSgV0+rvO9EuseZ4
         8Q9I1E/8Zxp2WcPuFqnAlyxALwq+UfyOZurRQaVLoU0gOXUl8wSJ0SbEYz9pJmhAj4QO
         3llCfVsLvqFuAg7+oD2UZneTV8lWBdfiVaofFosIHljZgkjcjchD/kLlpMqAerFwW0ce
         4gfzoZPRZ8hX/nM9GreYn7Yu0qstaJm33fPz3+zTRcDMSePudkxynwsXwH1YRFvBin50
         eayMa2nUWbfE0O4RWblCGY8sbKOy8fg63kwuPtyUpeFUwkqAY5k2+dwPALYuvoXITjF2
         rMyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aGeCa3RZDhPdtt+m+MOsGH5ZVRIhj+cFqCiZZ1iB11U=;
        b=coo8+lMwX2C8MtH3eN+YC0nsGFb7jR51vrThVv1WgH5SCleiDpxr1RzMRc076m/9SM
         jeJdS2pb6jyrkQL5kXAI4jA/vNNieg6RhJ/UkN8B2Q3JbSHYXONwu+9rXBJbBNn9/idQ
         zzM2fnANEydjlXQn7LfiH2d2Ap8jrmSq1wn9IRtBTFApukZjAOI2Vs3K53d6xWeFx3w2
         eoOE7V3mCAniIlMi9rZbmHwaWyI2BengONV7kpzpWHUbw/J58e3FLAXXgCD56OHNV0gM
         d2TglnP4uPQ0t1NmhdJ1gqt9+PAmaq6IfZLEnJzDWAYB5H60m2hcwlbQQfSO514oPbcN
         OB+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+SVF6AiFkrUk2eRftKZA+ASjIcoLHtf14Bx3hSMnE6sCGx7sEb
	P9XtVXAe1HxLjCM1iu7pFeY=
X-Google-Smtp-Source: AGRyM1urdjRuZPrjYGXvFbPXWHjJmNnKA5TQF8tzprSilimdVRiZnDOZS2UJ1sRGtll2BcXIjK8t0g==
X-Received: by 2002:ac2:5385:0:b0:479:1d1e:6b00 with SMTP id g5-20020ac25385000000b004791d1e6b00mr934756lfh.392.1655151458690;
        Mon, 13 Jun 2022 13:17:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91cc:0:b0:253:9ae0:be3b with SMTP id u12-20020a2e91cc000000b002539ae0be3bls456861ljg.10.gmail;
 Mon, 13 Jun 2022 13:17:37 -0700 (PDT)
X-Received: by 2002:a05:651c:1306:b0:255:6fe5:1ae3 with SMTP id u6-20020a05651c130600b002556fe51ae3mr608996lja.281.1655151457879;
        Mon, 13 Jun 2022 13:17:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151457; cv=none;
        d=google.com; s=arc-20160816;
        b=lax9QPRzDiQUGccNkorUtOJeaaBaKF1xH+iKK9OTnYKy6eIQwdruAfaOX080zj63/K
         532XGCmSjmvOChaZDX6NL6jycmkgdCN24OUj2qNPVJMzyXzp8HgFrfVcAN5h/2GyymFU
         7ZhXCnHA3vVU+ngG2ueBGVeXpl5j/Cdn3Zy1zeuw0GilJQimd6H+3qkCmxwJlHft7PW7
         9blAF3LJMsScE9LXqPwMTjI2ua0Nc3mVjpBf9eB3VonKC4K6OnQ81clQE/y00mEkGyYN
         LXch3mTFsnBDz+h0GPHXciMB+DVVuzONrKPcn0J+9lLKI2o44/DsNwPnqVL4jY+Ve92a
         8gKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vo/QgRsJex180B/MZOFV4gS3W10znq++oNOGcslvwl0=;
        b=st5/JXve5fQTFlpnbnezbv/z8AwYLmoqiFkwriasb3voLZRzJZmnmKdlC/HWg76Jeh
         iKrJRRMxGtxiBmsb9KhZ9fXYDNwtydAKyVWHZbMze/RZMTy4/p6vxzG2uktRtmFL2hPK
         A6rlZk6S25NTu5mVu6Kj7vniF1bYL+7UhCjzPiKSTUBpKHS/kEwUuwWhJJcLFmLbN9u9
         gzO9loVDgn0BNXPEKoymVbmBnjtX4i0Y4l8xFA/KPnUGV7hcpqQxsM0KPE0HjQh+EhvN
         0fFGYfPFS7nvb3farn7EMO1PN8+wik1zMgi0lH7joF6zCKtfZ119boAXlu3kBUuLAuwS
         OfSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Dl9JaXiP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id i1-20020a2ea361000000b00258ed232ee9si344028ljn.8.2022.06.13.13.17.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:17:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 17/32] kasan: only define metadata structs for Generic mode
Date: Mon, 13 Jun 2022 22:14:08 +0200
Message-Id: <f3c8fd1efaf7f1e9a486d4acfd4f154cc546333c.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Dl9JaXiP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Hide the definitions of kasan_alloc_meta and kasan_free_meta under
an ifdef CONFIG_KASAN_GENERIC check, as these structures are now only
used when the Generic mode is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ab2cd3ff10f3..30ec9ebf52c3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -192,14 +192,12 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
+#ifdef CONFIG_KASAN_GENERIC
+
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
-	/* Generic mode stores free track in kasan_free_meta. */
-#ifdef CONFIG_KASAN_GENERIC
+	/* Free track is stored in kasan_free_meta. */
 	depot_stack_handle_t aux_stack[2];
-#else
-	struct kasan_track free_track;
-#endif
 };
 
 struct qlist_node {
@@ -218,12 +216,12 @@ struct qlist_node {
  * After that, slab allocator stores the freelist pointer in the object.
  */
 struct kasan_free_meta {
-#ifdef CONFIG_KASAN_GENERIC
 	struct qlist_node quarantine_link;
 	struct kasan_track free_track;
-#endif
 };
 
+#endif /* CONFIG_KASAN_GENERIC */
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 /* Used in KUnit-compatible KASAN tests. */
 struct kunit_kasan_status {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f3c8fd1efaf7f1e9a486d4acfd4f154cc546333c.1655150842.git.andreyknvl%40google.com.
