Return-Path: <kasan-dev+bncBAABBMV2TORAMGQEVD2T4PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 029DA6ED581
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 21:49:08 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-3ef1dfd44cfsf28354381cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 12:49:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682365746; cv=pass;
        d=google.com; s=arc-20160816;
        b=hk8Sg4MflDa4tD9/j0frN7FUdAlZPEDQTVOAMXjyvuurKxK25gXOocodcaiz1K3zls
         9STt+Kr8nK3BWLmqcCejoDXQCSi/Qx7OVDmrxcM+Qd3jDpgjyxEhgq4pWXjQqas+2KRJ
         29FquQKRpROfPKkUPZCgqQO9Qz37iPivLgixSba8ciSehshMpm0YuT30tYQWN18mpbHB
         GTYiEyIeBuVlDYNRS5lCq79zdTO+9hmbuT+gfFmbUaJyP3Hc78NjpV8lWiAJF3cTXoee
         x6IEh5u/5ulOeoh4uoKZiM0zxUMahMLLV17KP++hwRwHC+AE6wrAgJJcZMXPwGzEFTow
         AdFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=RYWW2Sy0BU8OIUmsAs6sye8uUX6wB60ZGxtX25KYM9U=;
        b=VYyLa24rOQl5K69UUHtS+PRx7JA/u4r1sKdXg5cUTq9UBp6LVotxS5BlqGwFahnoLx
         1hbX4G7lrfCMfv8lF5hFNZ+EKrZI4toVGGMkysWtvdIw35tPG48YWY0lTnoosnHKbmIW
         yXIn3bToxcL7Vx0G6F0ywESAEVKKMhei/Yi+06eGzdkuIjzoV/cqqWWFYpsJ69VreD/g
         /HYx41HclNQ1/AbPJYA4wwWdRJtkkJnToyxFIKVSSSb8IJcVzoz7ZFOBcxVpTmy8zvoO
         Aen+hD0b8RFCJHJl9m8DxWZKVEoudJVY2Hge9+NSAvO5LCN7xDJe7pWYQAylP0DXEMNp
         Zj3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GBti3cLp;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682365746; x=1684957746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:date:message-id:references:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RYWW2Sy0BU8OIUmsAs6sye8uUX6wB60ZGxtX25KYM9U=;
        b=i0Prqg9bT4WomRYZ8lx1KzfX6wJZaE3iaAwoiUiTSic4ZXTN3l0rcpo04N+WleLrW3
         1ol1bXS3jB+QBscZ92GCkccteSya0jnJ/4w9DoUL72dRVsLm8NyAqdjhGc8RHb85Xjxz
         BAj4H81WBRvOPgZgKHhea9aqJmZ7oOTX1xfTo7rqZpQSlY7q9SjUyImhNstDeldlitd8
         FCZH6WHQKyYQMCemD2vEefiwuiDkLU4YDQSzMrKHsWO8M3EEX4+q0CIkboAtjgjfjIhj
         w9Y1WJ0AnG/OF6qLHz/iVVMaY9nCtL7OrkO7S6i2M24+FE6Wf2PTMrlwgm22seVzcL+H
         CihQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682365746; x=1684957746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RYWW2Sy0BU8OIUmsAs6sye8uUX6wB60ZGxtX25KYM9U=;
        b=TeiKLZKseJ0NtDW81wqX03znESxxdBFBFqHLocObfzBfNgaCPrjd0Dnl3pIMctdpmF
         SFOPiDX4F4BiivZyDmsKUYuMVKt0VEw0zFUSjp5Y9y/G32CNLe1h4kMwiL2DTXTMrtaY
         ir5UPGI+qaoCdkk5NI+0MRcNhYFMO1ItN4dUbKlimTsYHiEutE7/QYk6AxcrqBp5gwsl
         wI4qoDvFlrqTvgWON8bwqaGqbJNo13zZRJXIFTbU3OeaXv9aisW+7HE8KWiOFrmKtN10
         tvIFfHIR6oZOMDrSyyrJnIK9ucv1VfFVnGme183n80QFOl4YcDnP8n6G2X/bdlYwR6s7
         n1RQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9c52MHiMohxxZ2ayVZl7Bb9bm7JrHoax8UV9yF4kpmE6bwtdtkn
	6D+dmO6vMg3amrcWvIEnY08=
X-Google-Smtp-Source: AKy350YU/4CsUGsRQBoE1PNxi0WYfL0uLQleWzB1s5sXzsSY4vnJbm7SQNykSX4sHSnCG+BECU4/aw==
X-Received: by 2002:a05:622a:289:b0:3e1:3cc8:98b0 with SMTP id z9-20020a05622a028900b003e13cc898b0mr5250881qtw.3.1682365746634;
        Mon, 24 Apr 2023 12:49:06 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4015:b0:3ef:327d:ac61 with SMTP id
 cf21-20020a05622a401500b003ef327dac61ls12807407qtb.4.-pod-prod-gmail; Mon, 24
 Apr 2023 12:49:06 -0700 (PDT)
X-Received: by 2002:a05:622a:64a:b0:3ea:6371:9f01 with SMTP id a10-20020a05622a064a00b003ea63719f01mr21916284qtb.18.1682365746242;
        Mon, 24 Apr 2023 12:49:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682365746; cv=none;
        d=google.com; s=arc-20160816;
        b=Do81tWmUfLRf/Xb61Rd+cR0mS36VHCH50U8Lf7ybcp78cHSQcMRjtX6NxUWzlSZqYY
         PX7hkGc4wcKECnAlWu0sdv9ETeismQaaOof6cV33smMb7MH4zkAyXUMnRcrLiU5idumn
         5/7/LD2LHj3k3IIAajw/LLdV4KSK0BRHYBh4qG0acKjpu1E3pczzwvz+FGlVoHVDdjUB
         A9Zc0cPB3G3kzEflQSRDGUJJsTLZkY/jeramSmZ8EUXDq14bQGR8zN01Q7abaICMnMYW
         HsO1WqFGwmKwmZ+GdQPRjFINaYxC96BBGrPwn3Dnm4JueT5X/o7+cvnQc//fjwaZBy7Q
         /EVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=r1x6tWTCGRow+BO/96WFEe/i+71ecXUMduC3NEtc1u4=;
        b=BGK8EFR71ZyQzq3bR4WDcfItsf15/7GzrlOTYGvjJ37qpZD+TlMJ/45Vzgq48ACLdc
         Xk30WwsIMMRzHvDGVoYO7qJEFuk45WIpR1k9LlX10waSn+9F/dMHrpqCb4SGEsbSRTms
         /awMz0WSnyfPVzZ/yNrPThxl2O0FP6eR+2kSOT86z4p54os36eHrEgUCALpfRYx+8xXy
         RyWTAac1mOHlRLJtg+iHkSYSwdsdwn64pawW0ikQ2KfrRixflaV9ez3Y9RGcMfRe+Wvb
         mIylpi/UW7nguXZGwC9yUvdRCnEkNSb1o7RihgJ80jreTRCbqOZkKzeYHqfRk+HGXdO+
         FvgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GBti3cLp;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bp9-20020a05620a458900b0074e1433ed58si545796qkb.3.2023.04.24.12.49.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Apr 2023 12:49:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 841B5628AC;
	Mon, 24 Apr 2023 19:49:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E515DC433D2;
	Mon, 24 Apr 2023 19:49:04 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id D29A0E5FFC7;
	Mon, 24 Apr 2023 19:49:04 +0000 (UTC)
Subject: Re: [GIT PULL] KCSAN changes for v6.4
From: pr-tracker-bot@kernel.org
In-Reply-To: <147f3556-8e34-4bc3-a6d9-b9528c4eb429@paulmck-laptop>
References: <147f3556-8e34-4bc3-a6d9-b9528c4eb429@paulmck-laptop>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <147f3556-8e34-4bc3-a6d9-b9528c4eb429@paulmck-laptop>
X-PR-Tracked-Remote: git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2023.04.04a
X-PR-Tracked-Commit-Id: 8dec88070d964bfeb4198f34cb5956d89dd1f557
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: 022e32094ed2a688dcb2721534abd0a291905f29
Message-Id: <168236574485.6990.14702034469945860205.pr-tracker-bot@kernel.org>
Date: Mon, 24 Apr 2023 19:49:04 +0000
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: torvalds@linux-foundation.org, linux-kernel@vger.kernel.org, kernel-team@meta.com, kasan-dev@googlegroups.com, elver@google.com, rdunlap@infradead.org
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GBti3cLp;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

The pull request you sent on Tue, 11 Apr 2023 16:04:15 -0700:

> git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2023.04.04a

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/022e32094ed2a688dcb2721534abd0a291905f29

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168236574485.6990.14702034469945860205.pr-tracker-bot%40kernel.org.
