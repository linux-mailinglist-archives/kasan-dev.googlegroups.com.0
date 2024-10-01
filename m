Return-Path: <kasan-dev+bncBAABBIXW563QMGQEMEC6IQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8593D98BDFA
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2024 15:37:40 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-7db1762d70fsf4432389a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2024 06:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727789859; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z1b0CdAdMgo47zLURiaZLBYalH3Dqf6ks9ClV6ygrD/cv9WwE4B+tGoNu0D4awTN1M
         Rx2zEQs2a3TUwzoyGkqZM0CqjswYcKfxuA3o2Pu+WfuyBmWFOo72NujCAdT9ILKKEN5j
         aiL87DtuiVYSYNHar6+8pFHydjCbF0iM0nf7DPgVIYzF+0Ayg9uEBfpQpJZyxc5F/aBF
         eph6gA9IT5aoZ/Iy1fOkqbNFhGnxWecgL1SzpQNdThwcLjFnbvjHtfvE2GdCkpMpScRg
         G7YSacy1FvvBnYqtEw+qvuFvK2zXMQUFWFOjWebX1yaOwEDe67WQSkKxbagEfpkOi9tM
         6Iiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=2vdt2M2QqqaADsEefBqo0LwiCmhBgbREGZMcm+22HtE=;
        fh=q40ducsXBYhiKYCKUpEefCjLGHVtvWS6EeW36UXqfhc=;
        b=F8iThRmTXIQJ8D4u+K4DIvtshwLhevdHAcsBp5vZJLAVuxxv0vHuJIkQI7LET/3aN0
         chwHt9GT/Sb6SGUQQFs9wWbsbxhsOAyRRhYuvbW1hjUFs80sEz1KGxAv4TaKWhlG37Hw
         BHJ9n2Pj1wbL7ajTkrLO3juXG1N7E92tei2+eHkMaSqDBOH1QCWY336ieq28bB/uDMEc
         aUIV5AqGVtiaaPSfPb4MzzZipuBu5DdBx6ff8e+IJ9tHnz5i95H1vsjUGFG0KhQlToek
         L8AnQtims2VMP5QqGx9tUYnbiM8U1wQmeOF3AzjzFkyso4SLS21MNtxDVTQJiHfTHulT
         IPeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=I8mJGqRy;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727789859; x=1728394659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=2vdt2M2QqqaADsEefBqo0LwiCmhBgbREGZMcm+22HtE=;
        b=wCLiviJaSnanocM34KQoj2UReFiu0Joa0pKGk6N+MQpUFqvdrmUpclTBD6r82YVT8z
         AchVmzRsX0Gfht2/Dy5EroI4euyIQ02vRZvwMlXs0v2yJ9QMCtfznu6MupYZz0CU3iz2
         yK+N2jGIJnHoK3WYJYJWPFjpQ1p6JqoIYbKa1Psk1tqN1kffZEiRyh9NiHT0Vr49H0S+
         7W6hCNgDMvtUZJullsVi3MTbqTXpttSoVQh1Q8X7ifq8aehs+VrPEIXxVqlvgdAabNow
         ZEXCQKY5PXXXVGfpawfzB37TeGIOP4ZPsN4fBUQ5H/sjNRovfvjfeSEQ526LRo1zNIuh
         9gZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727789859; x=1728394659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2vdt2M2QqqaADsEefBqo0LwiCmhBgbREGZMcm+22HtE=;
        b=t+s2lzWCGMlyt3USGvQi+YHUqGFU5PS3VRj3KtHJcIXP53cBSX9KDsV2ep4bU1rM7c
         kubk6EiDio/KeFCuA4ieuhX/rb+ya3EQmTxZFslzG20V0Q58gKxPRepd8M+LpDOzcgxU
         RJGkDDmwu7DRdZKk4ntDU0kTJBRBhH/DnAuqiUEgW+rybymg/+tSR/FUMbRvdQO5gfMW
         drcgNrRqyc8X2Wu8Rhdr4DLPnY12nJM9/eLe5ooNogJ8Mt5ZfG4dHuDOJc9x8cqU8jsj
         DvSUTJQ4SzTY6N+oNRPWLY54jHgMqEfPHwNreKtmyJynvQQXMbWxli1a9hvyriSYgDwl
         ntpg==
X-Forwarded-Encrypted: i=2; AJvYcCVjyLSj7Oi+6LyDVoNXaWSpxgJhJiRsbSqXdLJrr4IvHqh2mVjSMgox7Cy0C687fm+WUlOAGw==@lfdr.de
X-Gm-Message-State: AOJu0YzVSxmMu4AQjJl1zt+wzhlfGsn7Uegn6RKCYT/kC0YsZXdafeQL
	oi0XEb/fTudi3VtilH3x+56xBfKMW1PTqi/5LsqC/q9feu9I419z
X-Google-Smtp-Source: AGHT+IFdQz6/be4qKpBjBPgbK0CZdIBZATrgATl9811JCMJ2uQ9/QoC+6O4q+omQ9iMd0wFbEAZtEg==
X-Received: by 2002:a05:6a21:1805:b0:1cf:9a86:a29b with SMTP id adf61e73a8af0-1d4fa6a18e8mr21625732637.20.1727789858357;
        Tue, 01 Oct 2024 06:37:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8d0:b0:714:2e75:c441 with SMTP id
 d2e1a72fcca58-71b18e79b7els1778911b3a.2.-pod-prod-04-us; Tue, 01 Oct 2024
 06:37:37 -0700 (PDT)
X-Received: by 2002:a05:6a00:11d3:b0:719:20b0:d041 with SMTP id d2e1a72fcca58-71b25f37cd3mr18138407b3a.10.1727789857358;
        Tue, 01 Oct 2024 06:37:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727789857; cv=none;
        d=google.com; s=arc-20240605;
        b=Q8AaZHAN3V/FRqmOGBTFE0YtDbwcU4IuLxhfUsEfWkzHuFDu2zRRbwUXTpDm3a1pHl
         kCHWlcmABRAh5EF4oxC2WnXsrLl33ptCuY6BC7gxZSk0eE9X55FUkR/g4U0zDJauDUpC
         AlawagSrVDHPXXSC411n5TG8OkqH+VEPCQ4Oq6lp2jgqwfd+OUYxJA+/XTe3fy04maW0
         1K/J4afmUZHkZ8reP2RVtU7z7ZLkqzt+cyQ2ufGTF7ohL5BUKpky0I22911g3wgpBQTp
         Zq/1+Sb/DRj2GMTO9y3GHyjJV0fdlK5F18Ll8Lc1yU79gZ5l6/Au5FrW3kdWu6N8sg4P
         GNSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=MppaZALEqQ6OjMtMKbBy5vhx8Z9JonW7Bj1AJ7vruRM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=FY1+qjrev2eJg11ZJRhIiIAl10Q0RdwLX7XVPYQRUR+JXj4I6+NXdiCAFNpPDPP3ez
         /o3/v7ra2okctJAV1E3tIC19dqcoMRugF741YAmm2iqc2uqFsYZwt6/CcPk3sFYNLkyx
         r5nAr2rPAYpHk9rjESo0mKSot5hs3AS3h4/ZuT7Ax4Ogcmi4WwIe6BNjcycY8fh7Qe1J
         8ixkxgo+JCfPvxaL8EfsSatlC2uuTFazUC09L1js2QYcNzz4X1xIJK39kcoFHp3P3UNq
         NWpjlulatV2QSFUqQ6y3Lqh4z1KPPBawtQvOTyZp0jaFKIIPOcJ/U6nYA2lzY55CRciA
         e0Hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=I8mJGqRy;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71b265305b2si370788b3a.4.2024.10.01.06.37.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Oct 2024 06:37:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7EE3F5C4BD5
	for <kasan-dev@googlegroups.com>; Tue,  1 Oct 2024 13:37:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 3C325C4CED1
	for <kasan-dev@googlegroups.com>; Tue,  1 Oct 2024 13:37:36 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 3574BC53BCA; Tue,  1 Oct 2024 13:37:36 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 206267] KASAN: missed checks in copy_to/from_user
Date: Tue, 01 Oct 2024 13:37:35 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206267-199747-ExT0EEK4FD@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206267-199747@https.bugzilla.kernel.org/>
References: <bug-206267-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=I8mJGqRy;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
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

https://bugzilla.kernel.org/show_bug.cgi?id=206267

--- Comment #5 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
On Tue, 01 Oct 2024, 2024-10-01 13:12:43 UTC Sabyrzhan Tasbolatov wrote:

> Perhaps, there is also the option to validate within copy_from_user()
> if the src pointer is from the kernel space, e.g.
> `ptr >= TASK_SIZE_MAX + PAGE_SIZE` like it's done in
> copy_from_kernel_nofault_allowed() to check user space pointers.

Never mind, I've forgot about pointer checks in access_ok().
But I don't see "from/src" pointer usage in 
instrument_copy_from_user_before() or instrument_copy_from_user_after():

https://elixir.bootlin.com/linux/v6.11-rc7/source/include/linux/uaccess.h#L82-L106

AFAIU, after check_object_size(), access_ok() "from/src" instrumentation
is not required (?).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206267-199747-ExT0EEK4FD%40https.bugzilla.kernel.org/.
