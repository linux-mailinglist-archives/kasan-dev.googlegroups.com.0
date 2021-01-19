Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFUYTSAAMGQE3J6BJXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 428872FBCBB
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 17:43:03 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id d15sf2235992ejc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 08:43:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611074583; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bat5cTw4e7Br2frdVeCMsMSELx5loNGIJatxBweduGhluoq28nkPEXTZGaYNGuzlNx
         jdtN0uyjA8hiDQUc736Wwn5tc8Bx0MB0aEvVOtpkBpFLVc7Dhbe39/MIWZgJuvow0GZL
         AzjvolrH8HLcKNjz01WiE2O3RHz1OcfuKNLa1ADF0NaKWjwzgXxrceMjnlDadGZbIT1a
         FKgBmN/iHO1Qk9nRr4ObSPMrdlQv3sXTlUwNbODYsh2FXlf5x/yBfHB/d3uWLm9PP3c0
         +bndBYe38gV9RIbXxuY0r/67zDUhGo0bbwzFhbWew9fCeGlrXnAgIEoH0F7+zYMKz6cZ
         waPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=Bz+vlHd1UXmLmvWlingL8gLKs+ELv/M/60wyVt/cOPA=;
        b=eMLjK5JilLiv/wkiivRhK5hGu8Ky0X/KsYhY+3pQ4bFgS0HGmJlibY5lgIN6eq/j9t
         yXmFreYWYPK4V7wnnEvEtt4vmhSIOwC1HyWwLCsJTHFcfiGolNkMy3Ju43ZJ/lvFu99w
         XBc45Hv8dR54RPXNPpWnB9TQudK1Qy+dB46mCKlR4Un6OqqKm3uS3Q5MueBam2vJSDwm
         4IDK+u2XgiTyVPjTh8N9lhHrckTHcPc72jQ9/27KhgDc8+xTaUfC4LtGPZ5gjM0f6GQM
         zyYSYxQXcDMkP2QybT8F9649pV4EvOJoaye1ezk9ZnW6ke5CHVp1+1xCqZom3HmSxcFK
         J/hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sMDi4o9t;
       spf=pass (google.com: domain of 3fqwhyaokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3FQwHYAoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bz+vlHd1UXmLmvWlingL8gLKs+ELv/M/60wyVt/cOPA=;
        b=j9XSfpBj+zdR8LfEeEzymFaXJmG3JqtqmGjM6RmLjDhfIOhCa38OBJ3ffJjnegl8ud
         rXFzqMALe6rYTEWepQVKg6aq/ng3Qzj7GEcIeh8/F+OY1Fupd+paXE4DCqkwCaGNBxQs
         PqnfG+LwJaHu0kH1iTSKQXCoBwTkPeWMwsqW7eFJ5ANRTpM6fIxBdycMeldnHt5lOFiP
         1Yw34Bhu8lSZY0Wc85mVb0gHwC8Vy00Kcc5hEy1Iu8W3rCYbuw6Q1JBAcHuUhtNk6PHv
         +7ifzOg1E/RwW3Cke9qUgsiRmLCV3JLBU8TJACQqXGNlgZTmMyw8MPEdJK+egxW5Zaa9
         dE7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Bz+vlHd1UXmLmvWlingL8gLKs+ELv/M/60wyVt/cOPA=;
        b=AZcmQQkxRtCYrtEugNfJYz5t0l+c6yF0etGN6CnhFZAM+l8I+ST1jlMeDzM+8yMZEw
         7O/eu+3C2CFq9Ylm8M9PkG4TTiio3u/k1MhUeQTD53uhCiuBgDubYuL+wtIBE2Vzhlff
         GVFFWPsXaabJz8SKB33Tv2XBoTZ/Atm6AOW8vFsthP6TV1tO9zGkG+i+/be4bW0na50N
         4Q7jwoT2v3bXBVByUdvkN21d/69v8jQ5G9fNgbCkn0ywg64zs77sYyLhpsqHGIKqiHAf
         38HqhMSUTooGLBtE6uvX1Stq0I6E7pl/1Qen/zZzkb4L+xMqeSg+WuzqWqvHhInXT7/X
         tfjA==
X-Gm-Message-State: AOAM533cTd1yz1ztffUfRwv2o42bUpReEezS+lHXvL85bZZU/rCmANfk
	avIkNTziF54VJnV7LxhUyIk=
X-Google-Smtp-Source: ABdhPJxGBCaxbvL5P/2ssyywCFzulY3///wPHYFVw+HIq70ceJKMOgB9k2dGolVQDC11MaltBs85ww==
X-Received: by 2002:a17:906:1f03:: with SMTP id w3mr3582549ejj.463.1611074582899;
        Tue, 19 Jan 2021 08:43:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:80d:: with SMTP id e13ls1517317ejd.1.gmail; Tue, 19
 Jan 2021 08:43:01 -0800 (PST)
X-Received: by 2002:a17:906:f85:: with SMTP id q5mr3625026ejj.105.1611074581856;
        Tue, 19 Jan 2021 08:43:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611074581; cv=none;
        d=google.com; s=arc-20160816;
        b=tfNkkMaNnuRPCLxVdz91cnX1Vc6VggQenv0srziLxjdrNy2ln4b7yDjIO+qcOwhsgs
         /hkACOramlo66s9JZxiQAA6+vAcYo7pqZrTj2vDb23qHBwnJUTcQPygt1pWGmmd/34uP
         X1PnfqsadFGVZduK2zw4/LJSOb5UvANPnGhEFtKAhOxWzCceQyZqgKMJTbolo7A5z7X3
         AbcMbVtK9RrzwKLqbhvazDtgKv6/XGu+7QEtjN9L49D/wIQh2H0bmvEdEr9ChLrdf94I
         6pJlzRlywlbQr6YpJkESk+NZainR9LanxOr8opAAnLcYGeljioP+oyNWQSr9sPgpgpGo
         oT+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=Mv8HVHZiqq2Y22lxEuv91PTBTzfF3aDqkg+FO9Cjpcc=;
        b=kCxX+710X7dKF+b3OEA+udffxKy/UROi92m+JBo80qWWeWYQWl74ms5ANJWw+mlYlX
         HvRwBKInVS4vxRgVDnMxp3Bd4Kz4Clti2iojKxO/7m0u6m0sEeH1PBkFQxMD4kM7QKfM
         bZ8Qt95SPhVfdMjsN4jUtFXrOx07kmE2LOzKyX43qSAKZaDXnLWgV++VhywPnJY/sa39
         K/9Ie9CaObrKp6Ph2i/YkMq5kqE/z9Q21E6PFsWwHdLernhNxUKNkpDBGnYNhQx+DVFS
         rix+ag9gDSvJlT/e1Gx6rgDdaamE259FOdL5u99mSpWECkDIGbG/FcMhq/IJuhR6yoP/
         6uYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sMDi4o9t;
       spf=pass (google.com: domain of 3fqwhyaokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3FQwHYAoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id f4si229859edr.2.2021.01.19.08.43.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 08:43:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fqwhyaokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id q11so6526685ejd.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 08:43:01 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:351a:: with SMTP id
 r26mr3406466eja.204.1611074581393; Tue, 19 Jan 2021 08:43:01 -0800 (PST)
Date: Tue, 19 Jan 2021 17:42:55 +0100
Message-Id: <02b5bcd692e912c27d484030f666b350ad7e4ae4.1611074450.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH] kasan, mm: fix resetting page_alloc tags for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sMDi4o9t;       spf=pass
 (google.com: domain of 3fqwhyaokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3FQwHYAoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
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

A previous commit added resetting KASAN page tags to
kernel_init_free_pages() to avoid false-positives due to accesses to
metadata with the hardware tag-based mode.

That commit did reset page tags before the metadata access, but didn't
restore them after. As the result, KASAN fails to detect bad accesses
to page_alloc allocations on some configurations.

Fix this by recovering the tag after the metadata access.

Fixes: aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing metadata")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index bdbec4c98173..8ef6fc53962a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1207,8 +1207,10 @@ static void kernel_init_free_pages(struct page *page, int numpages)
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
 	for (i = 0; i < numpages; i++) {
+		u8 tag = page_kasan_tag(page + i);
 		page_kasan_tag_reset(page + i);
 		clear_highpage(page + i);
+		page_kasan_tag_set(page + i, tag);
 	}
 	kasan_enable_current();
 }
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/02b5bcd692e912c27d484030f666b350ad7e4ae4.1611074450.git.andreyknvl%40google.com.
