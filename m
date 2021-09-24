Return-Path: <kasan-dev+bncBC24VNFHTMIBB64SW2FAMGQEEKFZ7PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 19592416D81
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 10:17:01 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id x25-20020a9d6d99000000b0051bf9bfc12fsf5596193otp.8
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 01:17:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632471420; cv=pass;
        d=google.com; s=arc-20160816;
        b=IiWBlYSUru8LEfJDUVZ/X58Isn298TMXEZ5HXWEe2Es86APTLdhsKLhKcH/I0rTBVy
         CTXQb5GZfH3KwXgwkGy5py3P1Auk7l0I8PRETz9cJQFrD56P+fY7hqd2gTj5idEJL5HK
         CpYAhXx79E37Qz3ZxMBm69wmXJt/3bS6l68CPD7BSoUaooJJ+KQXdWNIHCuRW/eu8rLF
         O6CdIrsopBcrcGUxAijiAse7iStXg7TiBAKaD7GhLKJIOXoabgdlomn/V5iTVh+lghuH
         PiYb6OnvrklgI3Z0/Gkd11KwjR/idfSb04jwL7aI8PP5BThsgqmN3WDT9T1vUKkuww7U
         IH/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=QkSaZgXaVO0GtatKIEti0gsUGRrZxVx1xwI3xlvr2L0=;
        b=R6UlbIA6YFaMxC5UHKqF6X6vrWex46daZofuYhog1Z6xn6FjgZ6/ts8Ha+CSv+3OJE
         42yBoB/8JystmZi8KYwRCSgRIhkRLXiZDjxxZhiT+cAiw0t4dol9TwwZ0Iv8RJWK2ME1
         ft2GoK4z4kSUF4kPsuO6HbjC+hSam3bswQpOdIpSWpFmmnctKZ3iAxIYyov/3EuAlLSy
         SXohMTq9CiDLkkjfqeU+jpIP5J7vanw4ciTrPhV4Z4OJffelVw8cqOfHtgYr1S9NMj4k
         0r8FMF4G+ZRTdEM0539bdvKB3tx0fH5oNDLRNJzT58O9ZTl9lP/mYZsqELQSdHBu2xMT
         U57w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UUfUBl9A;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QkSaZgXaVO0GtatKIEti0gsUGRrZxVx1xwI3xlvr2L0=;
        b=kTkVMjKwvQzFsSdiiEHrTrVEGmA0EuudafdfuSMDsc2p6oEHnfQNi2oHHJ1B+Aq9uM
         NKOnG/Oogt/2jtLAPxBjAKgXUVERtJvVBLqOJRIL8RQ3gn75DSpfG9tVvF/WKb+A+7He
         di2WNeg1BxIa36W/dqmG5vzxzwwaC0iV+f1q2pZWU5Q3MbdPXvePJ/gFN6URklnpxtmT
         GOs+b9wLA53AM6m6XEWyv8gMYPEoxRDXSFE6AW7dBMJpISHuGcmY61pLhx9OcDcns1c2
         s5tLeOfcjNWK4e3SSc0NVbKGFjcD9hwMNLwa/bg2ItchCcMG1eKEZVKfMNoC80MElPSx
         bfgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QkSaZgXaVO0GtatKIEti0gsUGRrZxVx1xwI3xlvr2L0=;
        b=OzqX6gshKBa9ZgbBS8O58SpCvb4HtC1l+A4IBeRC2dNEanjByYdYVq5+ThXv6QO0EA
         ufKRBPHnZdAB64sKPFZpE6NStOvMHxt95rLjnx9AfJM4E5wZ9uFKcwanG2hqdJ6Af9L4
         jvw9LiPEy/zHQtwfH7jgb8tOX+jTmdvYacAfBDXd7wcUC8U5HKMvldlptX3ZIRsaK1jn
         6h88urL7+iOS9gdMscsi6QGTtCkmKwPlCfYpZobJ4RKSmu/8XVRSitohDfQO8ur2ZsZy
         nCz+j+S56LnIAUhoiE5g7SziiSXFep6r75FgYJ44n7XPdUeVGIO9Gbvgid6eslN6Ns6t
         D1Bw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uh7w57cqj2Ie9qGS89ifh2ViQbfY/7U/r9VkuXMTs+0JuWe65
	55Lj59d6pBOo+GihDCo1U+4=
X-Google-Smtp-Source: ABdhPJwEnAI7C7MUuqpD59tGPONjBIskSimiEscWfHq922Sv9B4g2Z4kAN32wo3viuVL5n6Ws0OSLA==
X-Received: by 2002:a05:6830:44a4:: with SMTP id r36mr2802021otv.107.1632471419896;
        Fri, 24 Sep 2021 01:16:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:14d1:: with SMTP id f17ls2587042oiw.4.gmail; Fri,
 24 Sep 2021 01:16:59 -0700 (PDT)
X-Received: by 2002:aca:1c02:: with SMTP id c2mr467207oic.11.1632471419466;
        Fri, 24 Sep 2021 01:16:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632471419; cv=none;
        d=google.com; s=arc-20160816;
        b=k/gtJiUOqG+xYatSfcVyk3vtx+PWxenIn2sUNBvDrr+ed36f57dN4XJ/xqXW/CGxUm
         i+XEVv2yQiWGTMH1WRsr2GPlEqaC8F3Rz0D9rhmmvnUUW5hYekaEFcjt6G+iFuAPUnyG
         5XFPsJg6q9DBHI5Np7RAcZmv69iKcOrI5wxXycoL6EVaqXpnOhQi2ZmVTtRS7v9kcinu
         XBR05YssyVdvLjx9gVQPAFfOxfcCR5yX2xKC+hJQR/7WLZDZxBesCViWVW5HM3jolU8c
         c4FG3JIQaG6xx+tgGpElrDGQ2UdZiV4cPAIFCqrN3A35Qh3crbzJ93bFYnKIQtb8fgfx
         YXXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=igRKIpX5q/jPXAoPGjP/F3roaZCr3bGdUIA1eCsujBA=;
        b=ePxjEfPBnELX5WevDbL1Nw36dVZ0/1v52Bia8ZtxXO3cXHXgzEqveRFWbzV+zPnG5/
         VpL1PHN81LgHdiUhIUEWXsdPPDDbaA3uMEuVrPf6wcsFkCxwHQiU3npFo9vc09FEaZyQ
         eqiSdVM1lXJEeZTPp7arhnjim9qsInSzDpkIQQYc7z+vqYqW6qIme7EcmTrium+yatGK
         zCFb+S7kvX058+hVvtlbxsU+BKGLr9nGYp0P4sOAbuhSOoI8Ar/l5KF5YDb3nzEik0s7
         QTcCzHJWTxV1ahJbil+ZU/ENnCLKZu3N78hBo6tPkHzQQBnYVfUWbE1fuzGFLYTSo7wk
         Vn0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UUfUBl9A;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bd5si622374oib.2.2021.09.24.01.16.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Sep 2021 01:16:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id AE21060F41
	for <kasan-dev@googlegroups.com>; Fri, 24 Sep 2021 08:16:58 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 9C01360FED; Fri, 24 Sep 2021 08:16:58 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214429] Detect periodic timers re-armed too frequently (leads
 to stalls)
Date: Fri, 24 Sep 2021 08:16:58 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-214429-199747-qPGLy8teGk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214429-199747@https.bugzilla.kernel.org/>
References: <bug-214429-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UUfUBl9A;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214429

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
Thomas sent a fix for this:
https://lkml.org/lkml/2021/9/23/688

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214429-199747-qPGLy8teGk%40https.bugzilla.kernel.org/.
