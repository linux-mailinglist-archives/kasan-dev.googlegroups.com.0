Return-Path: <kasan-dev+bncBC24VNFHTMIBBZNVSD4QKGQED45KCQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EF0D72346BC
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 15:21:42 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id f17sf2453756vsq.17
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:21:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596201702; cv=pass;
        d=google.com; s=arc-20160816;
        b=WcY5H2d7A9Rhi+XvJ09E5MiXJ2KUUr1dkHXkVOgkFyrvbDBNNIgGuR2n9+itsyldO7
         5G27Kz2LztyK0FvK1jzn9D7rKSdYRC3WgeKKR4mjMqfKqDpAZAXo/QsrSJ1L/ffxE5Li
         doaavnSCdU7P/cahOtUjtSeQHeKNnYj9wqNdRYUeGDOzKylZK1ZVAgpyMdaZpAQp1U5b
         A241aVF8WThYEUUE9V6ZKVZNjGySHTqkE8iJ1R7Zgx7nUDWOSJ5ToPwvnjuS3zw99qzL
         k0f6zfDLooEWOBwo+AZbtFbTnmbK4X0TbP4UXqwY8lUDxdi0K3XBJVmjLxgaRUDmZaT9
         1kCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=x5X+VGcElc+rAaE2DlqIe/posR+0nM5KbESVVxNjYIY=;
        b=vnUi2nDy8wNwgS78iaWDrLzqs1q4dUvNQB+MJ6HkzRjs2IbNnVj+BfXdYKtNowBQ+l
         ekU3OXh1EWPOVbUhUyQuPibEKLTjwjdH6AUnUBFDeRucp83l0LxVvB+aodV1dWZjR8ff
         dH6m8bDwlGDEbGL/rq9hunj0t6m7VK90HxArMoEzutHrFBAdzuMd9S03//ggDQK4uPM6
         szD2M2nV1h4SGBvbrzqFugMXHsk9TO3KA76mXdx4UlcSYX7rwiU8i3ltqLO+AhHllCBK
         M505uTKg4GKuA+6KwZejynJjtWFclRkB8b9EGid7rrt1uwvDKzlgE/55u4+l11tvRcwu
         GHow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=quxo=bk=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qUXO=BK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x5X+VGcElc+rAaE2DlqIe/posR+0nM5KbESVVxNjYIY=;
        b=hh1KAhMMMz3Gms0v5EWeJyQ9PeORLq3Vn3o1FufEfHiXU6ee+MfIu4zK5OxoehGGKL
         taQORsnrQV8gXMPbACQ77suYpjmZUPC2kebARbQZkS5vJyc5k8yny3YeC9OKL6p8V5uh
         g5F0QqFC6HUC4acFBC55sob/pr9vQZx9phJ32EcQvB7PhFQrWzka3bjqisIJz9J0rLBi
         Vx84QnnpyboubGQvzeXDlCyfWy+nDkK7QLz6ZeQoyLRAChoFZnJaYd3kDZ5Nxwlck3jg
         LPXchjoN2rvbgXZ+N0CKVi4eNVf1BPa4RgZL4MlFaRDaLmlgV/DqUrZ8nxBJMK1sddtv
         uzAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x5X+VGcElc+rAaE2DlqIe/posR+0nM5KbESVVxNjYIY=;
        b=Dn1PlqPjKu5O0wakFD4YLnjaK5K6Jf/pbfwHfgYKTVhbGfzDDGa4tZdSPqfD23M5Ik
         Q/EtdeI0igbO72+PuaXr3mjuXGIX2X1i76fEKmkX0g+21AY1lCcj6aMhk3CJf34yFmvk
         9J9JSUk86qKw3ldyRXYdfO5dMwlhuYotcdaBF87ukY7JTyZlXqzO1Gh1HG5fpRZ25DMG
         BgKd74N/ZMgiaeJiX+wfTBxKpXbrmAjRzU7u4Y0EuA1c5KnSG462ftjvfLiA8+vDkiDT
         SC1eYVyU+gdrjnhdMgKVNUzJgigoHukiozb3S6paYx4KPSQ20J3T6vt8nbjBR1Wo84Oe
         73nA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qIMJSsi03SZpqmwxpLZf6ApYvi9w/hIb07w+E3DF3Dxbn4/hD
	apzFvQSqpOlGuRpcxzMTmM4=
X-Google-Smtp-Source: ABdhPJzdw+hD4feILtPfz1FH97XnAttFo8HlSskZhvHicsI60f/6aLM5k53vOVSNKjHsC0bZxJ8wgQ==
X-Received: by 2002:a67:2f8d:: with SMTP id v135mr3206868vsv.134.1596201702011;
        Fri, 31 Jul 2020 06:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:edca:: with SMTP id e10ls1095890vsp.6.gmail; Fri, 31 Jul
 2020 06:21:41 -0700 (PDT)
X-Received: by 2002:a67:f550:: with SMTP id z16mr3059491vsn.94.1596201701730;
        Fri, 31 Jul 2020 06:21:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596201701; cv=none;
        d=google.com; s=arc-20160816;
        b=QiJ9k/9R3cEjYFnfxwHR9g4xM5juXBjCyMtL+fd4d9pWmcx9X7WFBQ+CKg1wHsvGkK
         qlECPsZuPHjqBj36p7Wh5xdcAYWdj/Y6jY4xSJ35XbziLNDKfFyO+qnI6QN+LDPWotqL
         strax1UJiUzGTJQTQh1U2g+gkQxrTkykQYCUtFa+ASIHD6hmyTXkz8MalEuwEb0T+w3X
         gJmy0bKhdcqX3caiCc+DVbxMs1j3gdlz0EZnhq6Bc6tJUcj7HxBV4fUdYNkR1Ayp/3KZ
         sRIfwp6iTwYcqxDYsOrwHK90CTlnxh9jZgwG3tS9eU5PuYXyThE8tD2gbd/roalh7kBl
         EdMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=WNo3r9S64x0hFky+MkQ/bx7Cgjy/CjWb82mi+362lxM=;
        b=ZeEwQ4+W5X5yac2mBWWnmOVXWs3JTK1fN7Epw0SFTT6HHdCYa1/vfhjt/PPQCMdBd+
         xqDKmcHyOJjU2lJ9wnYte6ltX+Vvw7BrZsMDeJV85OEo3RnREmCHDLD/N0higc2bqkIj
         FMBL55SMqW+3+eWAX90dXc7tAQvSdPkuKUA3EHBSTGBqP98HqwW+23LVHYNx85C30Y98
         A5JwvhR9oe2o9VhTTOfoMhsUxiDR1hE/vic9Er/vuLQ3XhQmlsXHhnZEU7FwrfmCNaZ1
         M+LyLWgi+oZz6RHJ/dQKNWimI6oYVOv6TzGjMS7eYCHyl7Wqezf3/4x1yU3a1D1FPGGS
         I9kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=quxo=bk=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qUXO=BK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t72si522038vkd.5.2020.07.31.06.21.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 Jul 2020 06:21:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=quxo=bk=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (sw-tags): support stack instrumentation
Date: Fri, 31 Jul 2020 13:21:40 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-EWt7jvz7Qf@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=quxo=bk=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qUXO=BK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #23 from Andrey Konovalov (andreyknvl@gmail.com) ---
Yeah, we have KASAN_SANITIZE:=n for arm64 kasan_init.c, so that patch isn't
needed indeed.

I've mailed the series, thanks!

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-EWt7jvz7Qf%40https.bugzilla.kernel.org/.
