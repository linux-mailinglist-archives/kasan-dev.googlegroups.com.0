Return-Path: <kasan-dev+bncBAABBYGIU2WAMGQE5HJGQDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CE1181E172
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 16:48:50 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-555103df1f9sf95490a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 07:48:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703519330; cv=pass;
        d=google.com; s=arc-20160816;
        b=GEzVntjlW+7WSfwPz+APCdqmKq/V9pB5zZEjvKLC1LwFXm8xRBDQViAsfX6+oRyQ2y
         hdtMpwo6XE7twD42BALbDDCVvKkoFxsqkNvFLHQycOcvQs72W92BQCmzeenzIH6Xitej
         nU+YCaQRoT3yxVA5nxeUBFA8pbiMf2vIV7QJwf6oFOO8PD38U8M/Qo5YgfcLy4tejlKN
         AEDP6sMViuqZuH+6UQMQCv/7XiL5D4Mu0o+uKJx/48fNwg3ZEew1vwUoP+1/XyvLfw/o
         pZPyCuEU+Z8ZCupxzGK5YNMpg6BzRg0q9sLpDzs+QT3Zl+qVQAvvapKurEnm5zdpdJfJ
         vPWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=V4AKs9+AiClXhakJ3Bsi72YKSWSzunWhw0y8VdwTO5I=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=uWf2H+hcfJxg1L2F5p5BsULxDekrvw3MdP8zgvK7uhJIL4OSno1s5yd6RbsTcagrYi
         +wmO//HsatuThzr4mg7iv8dOgs6KnJAtalfbm6cHXs9+EAgPGsdYzPYQ4boJxH9Jygsj
         P+MskH9T6lByPCUlXL759NXLZWj6PuGomwF6exFUDlzsZ6OnjKOaHi6QGoXkSextAWYy
         qYP7n99dQKyUxowwIg4L0nBIHriOh/oaKyedfB7WTpv/dGboep+GPX5DUjrvjC38VoSd
         JZB01PZAebfHTcfPgZ0JnHX/DJYVRaG6Rl7VK7Aluayfco8A08R9MSY/vCoA24NmSHVM
         qbnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rUnD4sNc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703519330; x=1704124130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=V4AKs9+AiClXhakJ3Bsi72YKSWSzunWhw0y8VdwTO5I=;
        b=s0Ycz2TIM3/7/GucZ22+R+6FjK7fWr2o3/Y7vVDYrkMGDf+TKpHiAHo9kwk9+Wvlhd
         y1Atg1XAXhEU7DQpSs8XysgzJWa7M4EESjoNCxX3LfpNA93JgkBLNZCYpkJUHfrQwzai
         ZyD+DKtnBjqPJ1hIo+UZROeqM7h48XWSw01D8zRaBqnLaLpM2rf505sdD/j9TK/dcrWZ
         b1PqPB2eInFY5YQcckY2u3qRYO4urdR+owYin9dfisV7XAxRU0wuetZnRD380cxXMVyL
         +iA1+iI6BaCtbELYplX0qcModORgBVK5PCaLg+MmiaJVKTg8vQBHifVgpmU9aDs7ad6c
         7sfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703519330; x=1704124130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V4AKs9+AiClXhakJ3Bsi72YKSWSzunWhw0y8VdwTO5I=;
        b=Mc8obWbHNe7EOzrl/xNxws9JcizYea+0XdfGWYFMb4NDTHIJM2awwIcdMKIZHXvToN
         trNjFoqrY7iS5tUlc1CFsTSJxGOTe+3gES0ltiRiaIl069qikJdon+s3nKFIsP4/hcsc
         bST2PXZ3Ha2jbm5J9u9aWsEMOzt5x3dPlT4c2NLXCosTYbsoyG9r+HBoBEqZlKydGmtR
         MP1EGiJVPq6hLiUOjQB6+lsO8rwFhuqcx+nXyHer/sKURWmsfxObxU+51nV8AM+rbG1f
         Iin7spANvQDy3B/PThQgFUaOoN5n/UBQFJJ+ec4FbstM7rRrWaaP6/q5AnbvzNaLSYFi
         /SbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyY667qiwJpcbSj8iX84tTgp0N5sd0/Pbg0TiT/d5vCQk4KBN/Z
	kcwZZ0rHWk+066u6kLP/sLA=
X-Google-Smtp-Source: AGHT+IG4a6nIzF3czIOxLnBp76o4LOcX91kuoULxUW+sNTVdoE3gxEhmhNI7HegoStpEPtIj1rAbAw==
X-Received: by 2002:a50:ab13:0:b0:553:2b8:c9ff with SMTP id s19-20020a50ab13000000b0055302b8c9ffmr4101780edc.76.1703519329054;
        Mon, 25 Dec 2023 07:48:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:13c8:b0:555:f88:7db9 with SMTP id
 a8-20020a05640213c800b005550f887db9ls100171edx.1.-pod-prod-01-eu; Mon, 25 Dec
 2023 07:48:47 -0800 (PST)
X-Received: by 2002:a50:9fa9:0:b0:554:c2f5:6af6 with SMTP id c38-20020a509fa9000000b00554c2f56af6mr1706210edf.31.1703519327608;
        Mon, 25 Dec 2023 07:48:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703519327; cv=none;
        d=google.com; s=arc-20160816;
        b=Ljufv8THkPrx4pFSGiHWiPbIAnd4BZNX91e/qBcU82h1VlX5cx36brye1IPKwkZHzj
         SQx7+wYvPMg+cnvArm0XqUc0z8TUa7e5v/rM7VDosKpagZjPx+Tu6TNMtJHoUJ3NRb/A
         Yae3tMW8sFcf5hRfrFadedBjZ7GESvSFBYHgPEUKLCmyUCTt0EM+Ypr2+X3B0O3XC8Dz
         56zfVNVjTBRsIWOuy8fFFXaTdhLNJVn8KECX6ShWx/pIKQ9RsYKw7eUPzc+caiiBKhXo
         qiwHyC/rXIPhooOd8XafWNPNqlkIuz5NuOWaEgWMsB3aDclx/lDy5LtqVUcix14fkXik
         ghXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=/q/CIaFmvjsLVGCwBCoRVSUYJuYV1W28Qw6GmyuFDSk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=w/fkQ284REJmL8YDZ/rBxoG4O3AbJTm4nJw+Occv2a32x9K11UO59ZqgULa0kBmScd
         ppDj4m5U5l7/msmuBuaNRSwPIjtwR50iiZuZeGi7jRYLhbZthXuGhrizMJhvHgLmUPL3
         TRZWe3D6m/aDE0WQdiPmxGpkUFEK82MH6BFdEFgSTKxF6vvtTDEmCdYL2GJNwJXA9AxJ
         UdWqqpjty6sqLv2NtrgDU52/0+SM5TKkmkpk4neQnNW7mGRdauEUV6ah885W3N5/97kD
         hY436LxyBihtKjAFo8N55zX1TQGWULzK6pGYPcLtlU27GAymaAOSUmXRln4f8MMl1YRT
         8m9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rUnD4sNc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id cy13-20020a0564021c8d00b00552180ac40fsi308551edb.0.2023.12.25.07.48.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 07:48:47 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 23F7BCE0E7F
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 15:48:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id EC294C433C8
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 15:48:40 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id D3D48C53BC6; Mon, 25 Dec 2023 15:48:40 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218312] New: stackdepot, KASAN: use percpu-rwsem instead of
 rwlock
Date: Mon, 25 Dec 2023 15:48:40 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218312-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rUnD4sNc;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218312

            Bug ID: 218312
           Summary: stackdepot, KASAN: use percpu-rwsem instead of rwlock
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Both stack depot and KASAN stack ring (for the tag-based modes) require taking
the read lock much more often than the write lock. Thus, using percpu-rwsem
would likely be faster than the rwlock that is used by them right now.

We need to implement the irqsave/irqrestore API flavor for percpu-rwsem and
switch stack depot and KASAN to percpu-rwsem.

Suggested by Marco in
https://lore.kernel.org/lkml/CA+fCnZdAUo1CKDK4kiUyR+Fxc_F++CFezanPDVujx3u7fBmw=A@mail.gmail.com/.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218312-199747%40https.bugzilla.kernel.org/.
