Return-Path: <kasan-dev+bncBAABBOW2RWSQMGQE7J7F63I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 52D747466AE
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jul 2023 02:52:11 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-51dd1397a76sf2717922a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jul 2023 17:52:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688431931; cv=pass;
        d=google.com; s=arc-20160816;
        b=YcxC+v90mQkb6OnapVXJFOxgPs7f2INycqtfeElqFFRN2WttlATg+I4g2XOQC/Yws7
         8Fe+DEtuXsug5aXwwP0DYHQ6SbIuysyWVCyvGWkjklfMkFH845un22dCnqJqjDGdISNT
         qGzFSDJ1gA10JXgJgoYIn2kTk7hFlVBwqt5Us1FeS69Z3wSbnysMpOAcDhpm084jyVsz
         RUD7g5zqCa9msg8s00ZvTd4wOPCKP9F1EXcuQF6OeOZWpGXZXL2M4rkUwhKRMW2FfqHg
         MBdQSjRBcQt6cWToEvJUGRkrozvYiQxRyoz70CK4xy+kNfqfrtQsTZYPkmqy13+o3FeE
         I6aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZchZ99/LTNRKWDSSFj/eKF+g6hIXY/uKwGCQ8zmc2og=;
        fh=4CdzszOxy23o3hxHtw2gCmP26TOPX6ZHPX5CIDpO604=;
        b=Dgn/0OHpQ+5dyaMu05enXjaX5FTmm1kzHILQkbCuirRr87sGD8YsKHpgoLe91apPNm
         +bHsmV5mCBPPweECRiwlGak/Hyul1S6T5U9C/FKHSP16r/qf6c5ZB2Xdaw09cRAyw/sU
         veQwvSkTDwZ1OWJfCd4PyUabC5mDn0gbxNGVdTp2Vuxzo7rSzcjElrevsIku8TnGBBFl
         dWFxZywDV/2+OpvrVCyrA8lud3zjwG4ZxAOK2xAJBAiwBVwxnGrwODL3GSj3dah3VSfu
         fcsojzU4Nr/MjWaOan3ZXmf79NAzkMUUkk9r4hpYLoV63CMKbQV7LkOIt4T5OOwlSE21
         gSxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QYXS2UfB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::33 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688431931; x=1691023931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZchZ99/LTNRKWDSSFj/eKF+g6hIXY/uKwGCQ8zmc2og=;
        b=PW/5kC7phejnWzJpJDq1HP0/CP8RWiK5TmQbuvornhmkzNWYHFRuUWj07sHvxHN3bZ
         77i8mcuI8V+3dtbnwgrBvpdMOIbvsMncdcFEodNFpROQwJcyMwn6vZE3PRe2yxQHKxfb
         oLpHZ4SK8uty6wrbP0y+QxWb03Z0ZQZZnl7xdIj16vazbEs4tJCdHwE7EKCAALJnOtLk
         ESyTrhthpVHEkkz1pFap+W+tiDT6xZWsVJZ5MeNqx3YaMgSyHK1zjHjy4FMKw2nlgxeU
         /Q8ygyRvovIwV3VVn0890lyoHVI+RzDZz/lIXrip6uSWzIcB7BSQItI3v8/pOGtlQwPU
         YF1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688431931; x=1691023931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZchZ99/LTNRKWDSSFj/eKF+g6hIXY/uKwGCQ8zmc2og=;
        b=MOmzBWiXSaf/XH1Ag8jTGVsemRFVw1ATFJKhpu09J4l8LvM1BYOR5+KsT/mFwlIeZC
         CYgkk9e7EavI/lxFvvXUc1eodMXgaXOZah8cmAoh1E8NAmmVvbgayVGYH75HArdeP5+Q
         Fc5k/L5j4P78zaEEZC7JpyT9HLlWg9yjFy1w69CSVnBx5IkITTKjXiYyyMfH0hicOUAZ
         jJ25RdFZwCKqiTmE8pfbFbG5lSameU/RMF+E5vKajjnAWh7KrQ7tYxini0HVtQz3Lwja
         6c+zsTGl5/4GQ3TcJXmeYnMnDpWaPbICuPRFFyq8SKZVJxh4tOqPdB0QgUCYaw1Sl1ul
         Ce6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYj7J5rP+ME4VCedoX1GkpNK5Xj4k/MuBU1I6ETs5EQ7ebsDGSt
	muOpoTQQ84fZYNi7jsX6Kqo=
X-Google-Smtp-Source: APBJJlHxhsKtFcTvykSCR8DsrVeea7zzNOvbJHieYbnnBdOD1VwHRu69wOqx8moZRSfAcN8rt9T1bg==
X-Received: by 2002:aa7:d551:0:b0:51c:c03c:d72f with SMTP id u17-20020aa7d551000000b0051cc03cd72fmr7473544edr.20.1688431930301;
        Mon, 03 Jul 2023 17:52:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:ef07:0:b0:51b:f8f5:6409 with SMTP id m7-20020a50ef07000000b0051bf8f56409ls574717eds.0.-pod-prod-04-eu;
 Mon, 03 Jul 2023 17:52:08 -0700 (PDT)
X-Received: by 2002:a17:906:d8d1:b0:974:1ef1:81ad with SMTP id re17-20020a170906d8d100b009741ef181admr7961755ejb.4.1688431928901;
        Mon, 03 Jul 2023 17:52:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688431928; cv=none;
        d=google.com; s=arc-20160816;
        b=Bj6iZWqniEuIsUU6og6AuTJdZbPvQ1PZ0eeASrjZAUsbE1KTJS7cVdSdsKSgcWwQvM
         vHO4++7rkmBtZVLGBj5XoCM2rlb9fsxsdHOLGUPUon/rI48jLTiEJIw0FGqenjH7TujR
         9Qs2SHwxHwnvwotWnLQjscHtjKAdfTfi/nHRKDgEGZ1rG+CVk6YEee4HUdWZaPf6uc5D
         bCSb5oBTMyctgGOaFum0T/GVM2W7Gz6gLydXPxAsgD2zNJvRRUYRMIEe8HTWn0Tb+a92
         mbMZX5aAcNKA7nE9aXVW7u3A5Nzl5D4DxW3eummCD4tzPiiO1AAeHXbzKbhFz//j1a+J
         /WJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=9PvMF+hM/tczQlWv3CZcoKeqGsQQ6VNHOk9FPhNfzNc=;
        fh=tDHA86gZ9oTHBveGBBRxAm8hjiFFPfD6zeX1tbGJ9Qw=;
        b=yDwV+yMoDfT92d4Jr/OZnZKPYAtOjDifOLjvUpgBDY1tUmiacyIP+pGASb91UA3hvK
         PjIK1ELBSJkhqGEbohF5WziME7MZILilfp+JongGG1DRMF88omlFnJnisTOhBN9SkbP2
         /zz2j6pfLRDSIbH1Yxbxk356LcZ4O0cJnbjrPhdVo97lrLYXjthJ4687AjMowSU0WInB
         qD1lJQ4c8GEtHzmeMo1iTAU/Gc0mTiLvZJn5/Es2QKZ1uONopeQlWgdve+nYJAJXrrHR
         zwpQhXZb08Wxti3EK16Hzky9FwcUs3G9VQqacbsp7FWRBNKKqr5BghbaWQFOQW1u7dcN
         m3gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QYXS2UfB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::33 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-51.mta1.migadu.com (out-51.mta1.migadu.com. [2001:41d0:203:375::33])
        by gmr-mx.google.com with ESMTPS id sb11-20020a1709076d8b00b00991ee378a7csi1238546ejc.2.2023.07.03.17.52.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jul 2023 17:52:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::33 as permitted sender) client-ip=2001:41d0:203:375::33;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Arnd Bergmann <arnd@arndb.de>,
	stable@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan: fix type cast in memory_is_poisoned_n
Date: Tue,  4 Jul 2023 02:52:05 +0200
Message-Id: <8c9e0251c2b8b81016255709d4ec42942dcaf018.1688431866.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=QYXS2UfB;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::33 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Commit bb6e04a173f0 ("kasan: use internal prototypes matching gcc-13
builtins") introduced a bug into the memory_is_poisoned_n implementation:
it effectively removed the cast to a signed integer type after applying
KASAN_GRANULE_MASK.

As a result, KASAN started failing to properly check memset, memcpy,
and other similar functions.

Fix the bug by adding the cast back (through an additional signed integer
variable to make the code more readable).

Fixes: bb6e04a173f0 ("kasan: use internal prototypes matching gcc-13 builtins")
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 5b4c97baa656..4d837ab83f08 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -130,9 +130,10 @@ static __always_inline bool memory_is_poisoned_n(const void *addr, size_t size)
 	if (unlikely(ret)) {
 		const void *last_byte = addr + size - 1;
 		s8 *last_shadow = (s8 *)kasan_mem_to_shadow(last_byte);
+		s8 last_accessible_byte = (unsigned long)last_byte & KASAN_GRANULE_MASK;
 
 		if (unlikely(ret != (unsigned long)last_shadow ||
-			(((long)last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
+			     last_accessible_byte >= *last_shadow))
 			return true;
 	}
 	return false;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8c9e0251c2b8b81016255709d4ec42942dcaf018.1688431866.git.andreyknvl%40google.com.
