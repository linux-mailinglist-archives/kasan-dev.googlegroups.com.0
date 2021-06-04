Return-Path: <kasan-dev+bncBC24VNFHTMIBB3OL46CQMGQE4OGF75Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A16739B4F6
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jun 2021 10:35:58 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id o12-20020a5b050c0000b02904f4a117bd74sf10687724ybp.17
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jun 2021 01:35:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622795757; cv=pass;
        d=google.com; s=arc-20160816;
        b=XxLx+IDMijX08UAQeUJOvXdJfPqDfR9wd5I76V+x24HmredIu/joTv6VCy11MdVVOX
         x98MM1lEnF/rYzCGba45RJfa4izdgr8G6aabnF3m3KnBektlZE3SLa9x43QKurTjtoie
         i8vjENCI1NMlN/efmqHR3bxYzeWktVPgy1zd5YY3/ws/o/enBfR9g0yZgW55GDUur8/9
         GPc/2r+hYYv8Ed6BYPxerVpFUPsAIX/P5X44PLt2eNyo970w38okVk/xbhPKPV6uHuoe
         NVtkIzKhgqKjlSPGvS2Ibbzv45v6aYoYHsDcGUa1+4lGgb2WBqgp7VpE8fUFfF42o8Gs
         410Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=4G8pDNj46WbgLYmOALOLfFHd3jMkLnihBzvdrWuXPjc=;
        b=ATgkGP9i/0uwpTO0sARPNO8g6sA2Xz+g/lAvTu2Bq8SumRAtH36QIjNwjwIUTtkYo+
         NtQhrOkaAkKONgHdZVZDlCZ008xWk6tswCXep/niyhh7pMYpxhZVzzKQragANs7pt7Wt
         B/H1YWU20FxJzhpAc9qEG0jknWWslV29aB/Ah5tFmz5dVPaorL7dX/4fDK7wc1it98jt
         EV7Bp0XWWxLgJRVc5X7/6QaBJJiLEdCk4o0eVA84YDmIqpZ/RySjW2f4Jk8T5qHoO2U5
         2jjPYYKzWspLW6kK8WsaSxfki07/cKdEOY/GVQZJ4Z4qWeo6A3VkfhVO4ECxUHEgl1Pd
         jJIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mnriDBwm;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4G8pDNj46WbgLYmOALOLfFHd3jMkLnihBzvdrWuXPjc=;
        b=mQcLrJY+iU5ZNAbsbzZr+HLiFukMxE8BJnH+OuC/t1FvMtDI5HDQ9Cslm2CzAJoV2o
         6A+u/3KloH7talg3vEI+zJlUwsKiZ/R4S2Gs2GFYMrSOYqEBSxvGy6miJM3W00oq2mVJ
         hbHZa6RvKW7ppVu1smUraKkEJYd7mIaq4e39MutJt2G1FI+M1SJRGSYU7Q6erCBj10uZ
         XjKdN/H+/Xe+Vr9cGRTiGRAPK9ed7V4hiJthU6YdXFoQ1MqGMPZMBa0KUdbR2GMsVz0I
         744W/zexyrpuKvDltQGTr4BjHLaGh/DVE4h4JhAf7ZLbMW3/S/kJ0Nk2l6xSjXXzKMdA
         IU8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4G8pDNj46WbgLYmOALOLfFHd3jMkLnihBzvdrWuXPjc=;
        b=eqGxSfNK3t5tQbd0XR5wN2/9VzjJlsjFegJQQ2kAw3J8DpcWR75GvT4NtL4fZZjbQJ
         0mwlE8QQQUXlWTXnoD702uJ9ZDm1zjbh7EIIYTbBSB2jDcOH8BQjaWETlEza2k+tJO7S
         QorxIOqd5c8b/H8C7IQZ+5L9HnHs+UhQlkZyMmD9A42o+MkARjdN8LdNKUGwrXsflmCT
         WR1C52KVWZdEpblYh1zkVddNfnB481DEFeFnwnWj9RT2suQsBlgVvFNPI+YBu2E1UISI
         z8RDFq8FnaCJRPjzFFawUC3A9HxnQztAuKZmryPapf0RQGNmS2kxprwiFHQjwwXtjlnl
         7pZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Se+31zeJesFXK+Eu9TNd+9NqPZbKwWWatlaxrilFUeDhYXLvL
	henyxzmO2sqqWEKOOx0Vxok=
X-Google-Smtp-Source: ABdhPJzyGaFAucTCXyilINVkMnJlvQuyZrGsUG5mYZ6WCLHOVf4Yt3Cw6rBhKrKZs1DJxcShzys01w==
X-Received: by 2002:a25:c045:: with SMTP id c66mr3864503ybf.296.1622795757281;
        Fri, 04 Jun 2021 01:35:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3c45:: with SMTP id j66ls3551739yba.0.gmail; Fri, 04 Jun
 2021 01:35:56 -0700 (PDT)
X-Received: by 2002:a25:8385:: with SMTP id t5mr3783384ybk.151.1622795756851;
        Fri, 04 Jun 2021 01:35:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622795756; cv=none;
        d=google.com; s=arc-20160816;
        b=pfiFJW34g9z4h4GqIV95VvAr44rhWvdVJlOYQCwsgQbZ1R5fc2192HnRcOtQo5wdjO
         ZoU85V8Q9fj/POnBJmSS/sU3mI5lDUp/EO3U1BXhljg7aKeIdqAnuKJd0epO/Ad7ZKPm
         MD+EnhZhrkYMfXxIot4w1JTKZ0mRg9r5mnXGG2bMD8zJgzG3y2zwV+N5vb2fhNbQonyB
         vfFqnW41oo4BJxNd5Z6lPrS4F+XT9/9j1mMfhY0Oe557lKFk9NYA0ACzY1cCXnRaOWLT
         plH2E/M/qV3QMcRhSaVENZv9VCWzLXliYkmWkrEQQtwFpOqS6eBxrx6TTt6dNgb9Rp5e
         5L4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=JqMFl9FFzm/W4SvfhCpeFtd/y1d4Oc3l40nmby+Kq4E=;
        b=TS8kkF3yB51G86oCTR7J3RSTl1zCpMrsNzVyjGr4gvw5l9+R/o8rpuZeWers0xCWg4
         LiMttw0uYNxXHJucAE2tCcM9EstDA3J3l/V+leJRmJVASQ5UISTAWGUCNsgM0EeXYxGY
         CCBu5cPFnZg2XQVaN7DcDyqxpVQPnEhCAAs/HPBSp3pUVUaGYiejkO7F+PxPGVDavO7W
         +aErZYKTfDBI/O6w1e/bQ8Qda0vS2QOVMe+ztHvKZJypthwOEZe5dsaQ+nvyBWPAiZnW
         DP91Wl9TadySv6qCFdFMRAtT+/HSWHGiFERS0H2R7l2dsDymyvoP5awGVRusUImHOYI+
         zRmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mnriDBwm;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q11si452477ybu.0.2021.06.04.01.35.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Jun 2021 01:35:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id D41866138C
	for <kasan-dev@googlegroups.com>; Fri,  4 Jun 2021 08:35:55 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id C6DE46125F; Fri,  4 Jun 2021 08:35:55 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213335] KASAN: vmalloc_oob KUnit test fails
Date: Fri, 04 Jun 2021 08:35:55 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: davidgow@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-213335-199747-jdfom7DrWu@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213335-199747@https.bugzilla.kernel.org/>
References: <bug-213335-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mnriDBwm;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=213335

--- Comment #2 from David Gow (davidgow@google.com) ---
Yeah, CONFIG_KASAN_VMALLOC=y, otherwise that line is never reached (and
therefore no expectation failure occurs) due to the
KASAN_TEST_NEEDS_CONFIG_ON() earlier.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213335-199747-jdfom7DrWu%40https.bugzilla.kernel.org/.
