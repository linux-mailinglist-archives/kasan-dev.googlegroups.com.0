Return-Path: <kasan-dev+bncBC24VNFHTMIBBSWUU2DAMGQERNA3WVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 89C333A942B
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 09:37:47 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id eb2-20020ad44e420000b029025a58adfc6bsf1369123qvb.9
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 00:37:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623829066; cv=pass;
        d=google.com; s=arc-20160816;
        b=fZWixpjNyJbbt2YZab/1yiN94DimeMl9kl3suuKZljMRHCRkXx+ufQsJgNgOG5DWSp
         vuQPcPvI5/Lbf0kZ7+RpU7PoBiYc+JYp9twsFP9a3lwIBnQmktlgllRmgwfQ+d/l/aPu
         BiGK5DdTwH6DP3/3JanhBgoMTiXdaZMccJerRbVDl3Cjvmfv4WumS5qlREMwOVP0/1Dp
         vgE/EWbN8KbD2t9EISoMEqdxT9nWb0jiOcMQRrAqpp/UzxUsfwcSlLC3w5gI/MHZY6Xr
         BJ3tlazei04jooIcujHsvViVP0uEgfxdop9PGz/DuflsZNYznNmZ6qlgLXQZep152pJq
         9RhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=54G3NyKcFB8X2SwmLyq7SRP3xS3jWkh6gRdrmbXviJg=;
        b=TQqJMkgu9z1FemiRUx7uC6NZKslBC53BY1f7YnbBdtA0jXQcXjZVVUNT3t7fvzi96V
         6ztE7ay/c0GS06GPIwOww6ZS7RrrEL3PF0NcvFNJd7BIC9l/9UX74F72EI3gu9YMf/SU
         sIXOypamawbuwxpqp0XI/ZfSFZEn+Ceffwr/HyA9uzbEml2spiRCXFTjZd4aBYlj2Ygl
         C33SAYX5U4Xd4WAkY29utokrt7ZpBT1OToTJ52YuYS1G7ejibNssaelcK8xbUJcUSwhn
         5c5g1Imhxu5blH+UCVXzAQnW8qdQwfwjzNZsLD/gENiz3p/wA0DGHxaziZ5D3JG7Dq9P
         dp8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rBC18XSC;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=54G3NyKcFB8X2SwmLyq7SRP3xS3jWkh6gRdrmbXviJg=;
        b=LsunTniALjAesJNnMLKH8AsWdrUBl2f/GgFj2ev0RKirBoXSbQWagJ7t38IqHEDX0s
         gqM6M3D+UjP749qkwTva9hvJNtUCdm3gTZCBPliyJ+gOpdAO8FQvH0zjJxQd371DF6+o
         GkRTN19/BzbF9YuQ83K4WGgSKeXB6wHkN4lqTRSlMqXidGqPQXFI0ESywlqYi8fedztj
         zTj2nUN12vsLtOfE/hnKExYCudNtS8llZpi7GVXcDbhfcB4iKp77mp9ARHKt3xxi5FJ1
         Lr++MKYt6zqL6OxeuxWIVqtNCu+r68Ne/KdpqCFHPajhHKvr9SfXYSX0Ci5KZC3qlfGQ
         3AVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=54G3NyKcFB8X2SwmLyq7SRP3xS3jWkh6gRdrmbXviJg=;
        b=RMPjBJY6OYfhnbMICRB+fbPJeCYB2hdY5O0IQQj9a36XSqQmE3JQ52pem8zypi4Uz9
         hnPylc4MP7BMop/fIbk20PmvvNiZoAeb5LC3NWZxETcOxlKrCS5nG2e7KXIgI+bSQBlo
         uJ9gQ6794rX3nIi7sOHU7rJBF6X+O197RBo0LOsK1H3d/DHbnM3VU4tTXU1NoOIwQ/JD
         nUsTzPY+ADiwhULP987n5OY1S6swEPvZ75YBJogCCBMZd6aQyJ/22yPSTNtFfe4JWQdM
         +871y4FEarr/hDhpABTMAtbAumrHDaJ4STtlX9QLxilYJVxPVhubgzV9NARwvkUGgFcz
         0lPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531buvCAeIb3BAgYtTbmmSIsVNLWG72jl++Sk7AZfJkMbQARpBq5
	DR+lebY3cVusSgKVoTmcTQY=
X-Google-Smtp-Source: ABdhPJzj4Aj40sm4xIaCxxzfJ73ULxN1HpEeJxLjGXTGDv1tSZM/xnBCbTR27VD6J7qh7esoxDrAmg==
X-Received: by 2002:a05:622a:1456:: with SMTP id v22mr3906241qtx.118.1623829066503;
        Wed, 16 Jun 2021 00:37:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5f4e:: with SMTP id y14ls901731qta.5.gmail; Wed, 16 Jun
 2021 00:37:46 -0700 (PDT)
X-Received: by 2002:a05:622a:316:: with SMTP id q22mr3776795qtw.153.1623829066120;
        Wed, 16 Jun 2021 00:37:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623829066; cv=none;
        d=google.com; s=arc-20160816;
        b=INMIE9m1uXyXmZaT1gCcfEQLa8JT988S+uoFtVsLUOMS42gQSDs9Lkrt3KSn7mM/0V
         en+e2/dZFhUbC2hMLDlggzxDMWian0VKMUvBhiWG2/5vvhatFSGH3DT0iTSuNL3nH7gC
         OTkHBOCFHKCzeNIcCJCz8K5Wa5RP1gmrwe7waj3DfHyxaMvVOz3T4P280yVH3JDgtfbs
         bv1tXwPPlTgio6KD8df5OgypaTjIcJkwSTN9OcbcfqWfrw6L+Rpte2WADP5ILkTRYy34
         70UkLHWdKFS+olXCX9Jfisfije7CvWcfWGT18KaceiE31DMjStKvmFpmARNOlzXL9ZRo
         pCzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=sndiaY5w9qFbq7smizFc4hJsB8Q0K/d0wGTGVBtaCXI=;
        b=G7Z7r+PrIlFVUd/i5+FKPKlYRhFuj36w19xJEWKKhCFqVWrYc8OmbMbPPaGbAVjoPg
         v2tTt0jc/Yx6nF90hBNyUcGY3HSp9gEIvlpsY2ZCIxUCpFFXdfmlXy5v6TQGusWD03+2
         j89ecA9z31HxAFii6SKv522lr8RSYq1Fb2319mWyo7LemWk0Inj02T603f+ObzEzaLsI
         kIzwV68C3DWM4ufG+njRkceqqBf4O6aDPE7DAqRi6WdS3nPhjAT93yc+x6/oyZ0/jMau
         An4xNX0FYB1UczwbeKg9QSBtzO3IbRqtFtSbnfv3uYs4zJmMr5DxzcwRCzvHA4mYwICd
         QHsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rBC18XSC;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l21si139806qtj.2.2021.06.16.00.37.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Jun 2021 00:37:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 036186115C
	for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 07:37:45 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id ED22B610CC; Wed, 16 Jun 2021 07:37:44 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213335] KASAN: vmalloc_oob KUnit test fails
Date: Wed, 16 Jun 2021 07:37:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dja@axtens.net
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-213335-199747-mJDM38Gb0S@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213335-199747@https.bugzilla.kernel.org/>
References: <bug-213335-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rBC18XSC;       spf=pass
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

--- Comment #4 from Daniel Axtens (dja@axtens.net) ---
> I bisected this to 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings").
> Haven't yet looked into what the issue is.

Thanks for the bisect, I'll have a look ... I have the advantage of
being able to bug Nick via Slack if I get stuck :P

Kind regards,
Daniel

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213335-199747-mJDM38Gb0S%40https.bugzilla.kernel.org/.
