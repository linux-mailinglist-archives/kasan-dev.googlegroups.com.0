Return-Path: <kasan-dev+bncBAABBVNQY3AAMGQEB3YXGQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id D044FAA4156
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 05:26:15 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3055f2e1486sf9307937a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 20:26:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745983574; cv=pass;
        d=google.com; s=arc-20240605;
        b=Am9CR1A9gS8mFUD8teV+ZEJX0vCIT2xAkxMJeOenwITawFO/EyOTSs/ToQVcJqo5P3
         XjsKJFH+m7iQLjE+t+Td3knEASBRnk8J0Nsc+iAEQW4m5zPfPTjQ10Vzni4XfYQYPOMs
         +JH2YjweTOmLRemTB1stK9Kt+sRnZdM8bYpEbZMWrG38cxSFkBF5iNM7X+ajXRgRw0AC
         sqoMe2ZKhWshg2tM4cXuneqTjwyG2D4QPVMMYxeZygvjsS+aec1dKACil7VaaCgRn84X
         TY2VZdrUcJIV24KuQ5NP7T1EG7Yz5bTk0TEGtfSdIWzPZ5Qap/rz8/YU9l5LXBgsXxoY
         VZXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=HyyuKgCXvyygA8ju7cHURaFb7lL4TJ6JwLmwnZa6SFM=;
        fh=gzq7lzuM9dIMqLyq4fUR+VS7dhbL6K16VV63QK5vUlk=;
        b=lOEWQF8x/ZL+COBfcVvtOAayL2evi7TJzt7ui5T+hJCvUGanvEEbW411lNIglVLsSm
         eSfgum+6EU8ZFgzcPtfkFOGCj4Y4gQ45Rh/7EpZIJUaAB+I4mTyS6GREwxixEy0yMhRr
         nZgQHCtvxcwR41D/PCO8iQsi8UQB1tpfzMwCQCnQv7j1ZCQhJUOvs7RCuflho3qFTqh5
         VLvLHVGDYJab3/8DxpP8deBAlXTIv/7BGEbI9Vf/f+CY5uCsrozs81v2NIy4aDjo6f6M
         iUmvxYMQk/QCYGmCVPWCtwGsF/KWngB5i9n/tts3cf40Ep72LaPnc29mbc5ADwDdKwTU
         jHTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Iyik8m+d;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745983574; x=1746588374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=HyyuKgCXvyygA8ju7cHURaFb7lL4TJ6JwLmwnZa6SFM=;
        b=j1ZBPBqVZSs3u0TROeo9RKw+enpb7gLwmfICSKsTOqGM+EVzjd+zabul8RZwGSHbl2
         ovP2XPPz7zJhROGHCCeLFrV/kKFJ5Jqf6UtNwqAL7M/WilgkmDSjUegvLqlF02LjJaEk
         bSlZ86dvAtknGJ9x80wY6Zwmv7H8YSDJEpfNDjumElmR3z9X80cH0g+SRD/JVWZAEqqX
         lDOGarfAAW/MCDwTVJNowNPKgYB6IFJBh/DKb37GF6EVGp5KmDtzEd3EVm9OmoLO4Vwr
         FzXdEA/8GMtn/jFl1WOMhxmC/4mV3oLJUE4HPbbwoi1THRkJ1xxnbtiNhJ90GQgDITq8
         9+xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745983574; x=1746588374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HyyuKgCXvyygA8ju7cHURaFb7lL4TJ6JwLmwnZa6SFM=;
        b=l1igYBxuwZZu//gcjFs6YhecAmr4bK48fda8vARdq8Y9jZLdI/ta2hrj6y3qQRFoWU
         Lef65QBIAwhYvR+BLlmPBrnaBKZ/H0I5npE3xB4MxNrlAvdIUpkm0Z3sCP7ivvoPWOIb
         RQo2czttf88bGVXbfDTyyoBoJFyDWJmP18NvUmMGKARMykghH43KedHJgP73dAfIlMrI
         Hm0G41Tj9+Ev7UQYaXFA9yc7B0YerHopdqNhe7TRb+qTKjAeTUPURIagXB1e3y7PbuEP
         M53dw0fZr2rbm49cAiqlzMgitMn6DBCsHgqg1VFyk5sUq/I7szbbR4iCqtY8QcC9Zlfn
         bo+w==
X-Forwarded-Encrypted: i=2; AJvYcCXKGVc2d9Q8gnojm6ws86PmPvQGRPCmdAKQ8D4vCdJxeBJMgOvhtvDgObZJ13fcej5e8HpTrA==@lfdr.de
X-Gm-Message-State: AOJu0YyEQWt79dFpz1zcX82BHXIdB5a5AT66QeRniE4mMIRhM8HnHZp0
	865IC7DbYeB/JhlzAyplfHXQhOZe4kYnxVcDvi3lFoxCGl5dINQg
X-Google-Smtp-Source: AGHT+IFYvQQtdE7NSE7VcznPR6shRmVDRlOBL7+oc511m3JvTMvrCxYRqlMMFedx2GTOdIr+YYmoQg==
X-Received: by 2002:a17:90b:2247:b0:2ff:52e1:c49f with SMTP id 98e67ed59e1d1-30a34467cbfmr1348191a91.26.1745983573957;
        Tue, 29 Apr 2025 20:26:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFsQXrP5NbUE6otILlmkRcfVh1h3hs+aC350UCnFAWWqA==
Received: by 2002:a17:90a:de0e:b0:301:9a05:8467 with SMTP id
 98e67ed59e1d1-309ebceb7dbls3187695a91.0.-pod-prod-06-us; Tue, 29 Apr 2025
 20:26:13 -0700 (PDT)
X-Received: by 2002:a17:90b:3806:b0:2f2:a664:df20 with SMTP id 98e67ed59e1d1-30a343e80afmr1817276a91.7.1745983572855;
        Tue, 29 Apr 2025 20:26:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745983572; cv=none;
        d=google.com; s=arc-20240605;
        b=YZRfdupL8VcfJq55GZnAwJ/DdlLA0RsYTqK3Y+0ENXCQgJXteLbTyYbw35K909XDqD
         4hgURBAYXUEGGDbRYeifx+gjU6sUMsMOwd9KfySgDXYxWOonpi+w7PbDmi08n72njoDL
         czcP3SCy2t5b5pIprZ5RbC4MWOHvF/l4Q/SmodyIji5py4kASwTJN9aDB1/DaJdbF30m
         SUwe0GhUr8NJrc9qW6vWsXjRxLJ16GFNZx6kc7jEedUOh2VFFu2skICQrbW0v97wxHw5
         lGn3X4NiZrxO40j2Wb1J/r5k2+Xv6Q0BqIQrL7anoH479ff+8dDxTxLyTl4Zz7vmdkzY
         83hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=n1DIUaiJpB5fKoc3S5OBySRvTC1N1DQcXqfQ5LTYz+w=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=k1DUUUvPEEIOT7oHnuiiGCs8aC6F0gMLkiAv9FbYB2sfJp6MmRW/fmYnS+pOSPY9Ac
         q2+Z6eko4yjVHznDwaA9VSHdb5YwkeMwyoalMIaQ5WcPPQgAxHs1o3h53gZCc4yU3+D+
         uFp+eMVzSiRN3GRo3ruZxTDIfyjV4dd5JOvb5d3BMM8uDOOhsFDkQOtBMcQKOL9oH4nL
         7YqZFIjsiE7qpQ7pE11mJALMTjK8STNkvZcZb+2AyVOYALusYrg7dhlJtTdHe8HYrhyM
         pBTWQmNFu1Vl/yAXeuG9gRcU8p1KHhaVu0gNBERAzTUuFYFDRvbA4Lu52M62dVQMIEfL
         Q6vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Iyik8m+d;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a3488df98si20693a91.0.2025.04.29.20.26.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Apr 2025 20:26:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 7DFE84AB6A
	for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 03:26:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 9A9EFC4CEF3
	for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 03:26:12 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9430CC3279F; Wed, 30 Apr 2025 03:26:12 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 199055] KASAN: poison skb linear data tail
Date: Wed, 30 Apr 2025 03:26:12 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-199055-199747-n9zVPnYEvO@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199055-199747@https.bugzilla.kernel.org/>
References: <bug-199055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Iyik8m+d;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=199055

--- Comment #10 from Dmitry Vyukov (dvyukov@google.com) ---
KASAN does not track initialized-ness of data.
KMSAN does, but it reports bugs only on "uses" of uninit values (not reads,
results of some reads may be unusud later) + it does not catch out-of-bounds
writes + KMSAN it significantly less used than KASAN.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-199055-199747-n9zVPnYEvO%40https.bugzilla.kernel.org/.
