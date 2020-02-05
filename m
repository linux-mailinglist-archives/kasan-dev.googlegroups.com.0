Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAVL5LYQKGQEQYXOCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id B8FD11528E9
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2020 11:14:26 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id f13sf1188356edy.21
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2020 02:14:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580897666; cv=pass;
        d=google.com; s=arc-20160816;
        b=tNA/evRyhvkE9LRbMn70tJnb7Qh+Jej4vnIUtAWlj2BhP3QuLg5nb6cnYsea/eG1PL
         78YhbaK0o6kfAqh77WYiIXak1BHX5JQ/EUGMPblbnRWiIgwsZGs3n3b2ojhVYb3javVZ
         Nt2jf8KlAyug6H3mZ9MrSr9j0S8uGVdtv7hST2m+XaVWIrQrZFfOm1FhXVgrBh6Qvrpz
         PRqK7M14Kn/oTGAkBFa3F5CHlu8+iXdT/nh4JQcsr4dcfPxiztkdR/6sJBFrN4coiR/B
         UlOJpAEdmj7fjtbwY5Cg2SH7qZD2cMGBHHmA1RHoNd7IZsuGr9Eww1rJhZpsy0i9tSwX
         ohLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=b/6dTwOAfSr2oMFhZ+eBjbYfB9MrKK/y3xdTeU28xCQ=;
        b=Vw0Q0nRoIkigYL8CBla4lEQF4rqIcS6N89AYyf7BXPwJ70z7WApRGN+h/j/rgwOAzH
         D1IkTtfsGByTD+1TDP9gsrquj3yBAOLrUTFJwk4+0mxwxd4rYAYHSRQrJS3MjAA3Djc+
         4W2/+TnjOPl4C0YeystzaLacbZiBWBq6DhhoKLBypoC15nM5DPrzK9CEQdNKE+jg2fg9
         Tj+rUC/e+X5jMVofdrVT6Lw1yxeiDwduDt+yV2ULWeyObLGkv2hvJQfiDi/qGPgvPs8c
         jTVZ/0orxfDEHkMs4q0HoPs3WR8SyQYmSNOvbO/r3Lyle7vAAbtyu4YZwSYssLISARqB
         EKww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AwFPoBAg;
       spf=pass (google.com: domain of 3gju6xgukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gJU6XgUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=b/6dTwOAfSr2oMFhZ+eBjbYfB9MrKK/y3xdTeU28xCQ=;
        b=ASGeDRDn2lqOVI/qT6oRrV0uZGYpZFhQbg8mNUNbzTTl8OqxgcLMBlWflsGwlPRazz
         inqpigPPN2TcUVpn++SbXk4NEKmmcW/LfENdwncD4XFgzBBjXM+szZtkj8R+cYuZqEvx
         EJRlsWUq2XR4rwpbTQW1596Vc0trdAnNddEHi+f/RAxoIEpdYlxLInmhdlZl1jy+uj0n
         DEjwDdkCdGqTM3NybYDxCChQ5sTlSE707F0DxxPPkiwpheMYHBGRSyFvRV765AiqQikf
         I4eWA7bhqEx39KFMNZER8Uf+z9HY3sLXODq+TLRLUuVaDQhk25MTXJ3IWSFbOevKCwgl
         yAUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b/6dTwOAfSr2oMFhZ+eBjbYfB9MrKK/y3xdTeU28xCQ=;
        b=dC6Q70XHag2RUR+Oo8JxX4jdIgNZNjp0ifVRqNLxDxqGb4rN+CXebMU7QpRiehd6P/
         /vyjs/NejpHh5LIiwc0aLWtmnUWAqB9Lv7U9rsY7v80q7a0Fy++Cu7lQW02f+XstmSLF
         GDWdKv10P67IVhqBVF9q77ln2+2b8OEayTqEAHQ4uON98yJ95FCcWb7sEtVEpOMtOKDC
         gUeACCpbozW+z1qneWdVtU0PEAu5qxXKTJ5SQ55iGr8Mx4O3XYOCXA0SlCHpBI0yH9Mz
         mJUg4GdZWKPCM/HHFYLdxGsKIS7wKwzM1hw2LvBIbP1F/DHvqoBIvGZbxuhVEXykfUEm
         XDog==
X-Gm-Message-State: APjAAAUWoTFBTCDrhoxzPerQk/YWgmhQZXyZ+1pKneEFsypmg+3ljvmo
	gs6iyGjol5fZgRi/2JAvQBo=
X-Google-Smtp-Source: APXvYqxgrvKIIHZuRyQeaAtbnIIijxufsChDH5EV+fQGBeMF7EmigbvOWujHuA+lNTOhWKR3XBbZbg==
X-Received: by 2002:a17:906:a856:: with SMTP id dx22mr29631621ejb.130.1580897666444;
        Wed, 05 Feb 2020 02:14:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:177c:: with SMTP id da28ls686554edb.8.gmail; Wed,
 05 Feb 2020 02:14:25 -0800 (PST)
X-Received: by 2002:a05:6402:3132:: with SMTP id dd18mr4336947edb.118.1580897665789;
        Wed, 05 Feb 2020 02:14:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580897665; cv=none;
        d=google.com; s=arc-20160816;
        b=noHk8VbOHhRsA571RN73JBvGuroivWHwW7up9PBmOZSlW3Rwb9K4nwkQlHTgHAKVSa
         nf1EF9IC+gY7b8IfgpYn8Uw9paKJOYSm9PkMvM4BZADIyWkKLF1JH+CBvaUsXpR/ApKn
         kQeGjyLpmr/qQh79yTMUtiK1pftR2aqX7QPbxpFUYD9xHDMUUpt/Ryn6nhDE76MDXfF8
         Ginvl2meBrPJzis6sFi9aPA+5prZqVKbsuUog7j7GgeAeLzyf4zJWhGu0S4mRugo9x9s
         rZjT79X1ij9LmeLRGT7uWKurIda3qmHWyd/Ac/wQnzoYKtiNaevQKyTPTCvlUjbE44XT
         gPkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=UD8MX0T3MUe53I3VyW0MK1QJ1j+hRM6tFiKLV9YX/IY=;
        b=Ob922bOPy8hOqNzzJUNlr2qVqM2WW4bygPdGyxF1heEfBeASeh4Yo+fREoXYFPnstL
         WR7lTQzHwnyTdb04Bhk2ebrhmHqIJMs22ORFysw/rmOc3K9jBXmk9cxvXy9S4QjxlCgU
         0KgMK6zcdjsFVStJyUcItKXVJPufFIRf1WaQdwZKxVBpDlETlEksGXNlnTBTx0OjTZnS
         N+TQPUKxElhenJ2GfdHbX2LQkDll4qe5/YumXSoIyEg+M06Dm4H5z79Jasx4qJHS1ppg
         hOjJkGYuN09y9ivENAOKnxE/nmNJlYSA3Dyq7HgDmcBaQV7+c46LkizhuOjYv+GR0zML
         egwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AwFPoBAg;
       spf=pass (google.com: domain of 3gju6xgukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gJU6XgUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id z20si982532ejx.1.2020.02.05.02.14.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2020 02:14:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gju6xgukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id o6so939472wrp.8
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2020 02:14:25 -0800 (PST)
X-Received: by 2002:a5d:6987:: with SMTP id g7mr26978829wru.422.1580897664980;
 Wed, 05 Feb 2020 02:14:24 -0800 (PST)
Date: Wed,  5 Feb 2020 11:14:19 +0100
Message-Id: <20200205101419.149903-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH] kcsan: Fix 0-sized checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AwFPoBAg;       spf=pass
 (google.com: domain of 3gju6xgukcy0v2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gJU6XgUKCY0v2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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

Instrumentation of arbitrary memory-copy functions, such as user-copies,
may be called with size of 0, which could lead to false positives.

To avoid this, add a comparison in check_access() for size==0, which
will be optimized out for constant sized instrumentation
(__tsan_{read,write}N), and therefore not affect the common-case
fast-path.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c |  7 +++++++
 kernel/kcsan/test.c | 10 ++++++++++
 2 files changed, 17 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index e3c7d8f34f2ff..82c2bef827d42 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -455,6 +455,13 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 	atomic_long_t *watchpoint;
 	long encoded_watchpoint;
 
+	/*
+	 * Do nothing for 0 sized check; this comparison will be optimized out
+	 * for constant sized instrumentation (__tsan_{read,write}N).
+	 */
+	if (unlikely(size == 0))
+		return;
+
 	/*
 	 * Avoid user_access_save in fast-path: find_watchpoint is safe without
 	 * user_access_save, as the address that ptr points to is only used to
diff --git a/kernel/kcsan/test.c b/kernel/kcsan/test.c
index cc6000239dc01..d26a052d33838 100644
--- a/kernel/kcsan/test.c
+++ b/kernel/kcsan/test.c
@@ -92,6 +92,16 @@ static bool test_matching_access(void)
 		return false;
 	if (WARN_ON(matching_access(9, 1, 10, 1)))
 		return false;
+
+	/*
+	 * An access of size 0 could match another access, as demonstrated here.
+	 * Rather than add more comparisons to 'matching_access()', which would
+	 * end up in the fast-path for *all* checks, check_access() simply
+	 * returns for all accesses of size 0.
+	 */
+	if (WARN_ON(!matching_access(8, 8, 12, 0)))
+		return false;
+
 	return true;
 }
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205101419.149903-1-elver%40google.com.
