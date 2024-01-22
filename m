Return-Path: <kasan-dev+bncBAABBQWQXKWQMGQEX2LQ2AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B581836DCD
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 18:39:16 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-59907104d88sf3293216eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 09:39:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705945155; cv=pass;
        d=google.com; s=arc-20160816;
        b=oONX3TBGwSSozlB4Bxbv2z3TkYJL/Sd3EklEeVo15t1JYp862hckDWfw1ivIiHUSX2
         IaPCXSTpuVNSLJcZjmRiQsrvykrBDcvcsnHnxKgFnFyWRw4MsPwZRYxRGOb2twXaKmlw
         fTK607rqvb5ww29vonxXuq4zc11yHfSlimfDi9quabXwfbXF6Pty+H/DpGGrYIGG2nFA
         4XAc0TTweFDPfMR5TnhJTYg01W1A9bnlBpdOpbk2TVgaQZ/El+ddTG5tQ3yiFfzyxxzi
         r4AJbO0Efqwnu/vdXPOrOrsDnJJY5Ofnx2VPulCrFyx4yc+xgwuGgXBmW/qDrHSXqswu
         OiNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Ie2vTkHbgvAp2yUqi9Z1IefLwUSIQx2OHycIqch2Ih4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=vJOoIwfE4GMkQA3AD5dJHDFw9V2/hi7ejL4brGmSiFoaUZ4NaVB+F6vSJ6FQC2hxKb
         6JFYkPlDPzzZ+QzqYiuxR7FWhytAC/lGnjZDYX/GrPqqRKs/mXDWQjb+Mm0sxVNgo52y
         cu2vg+rpPuYZOtrTPwWkVzs9Ekm4KdXz86C+3UGUOyyrwn97A0XHreVyVcpENp48AjSq
         qjb/mTXukbJkpU9CGHGG8BoPHZv1/klLJ9ugw5dMvbDLWymfKjnnck29LWE5J4oMafAc
         sVDMspCFHyAz++MKgQ9i2pweh40JQ0zWYTJBlFVTISZXqlKSYaOyfh4uk536+vSj02xB
         iHYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uJy9MBpg;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705945155; x=1706549955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ie2vTkHbgvAp2yUqi9Z1IefLwUSIQx2OHycIqch2Ih4=;
        b=ma18D8xgu6L2xPjMVC/bQJwDQcb3OqldyF+BpE1y5y2/Guu2KA7+br/9JShNB6HtZ5
         w6XCz19GG+ZPisRMZR0mrT+t+NchGYGRDCktadNjRQDXHa+MhDiVQYmi6ozvQKiBtbQC
         ku0+J6je2J3EjzLwk2H+gmH4Kz1GafWULmkUFV5oSnL9/Q9Cap7tTtDZcz2aT+diytEp
         IDZyzNwcVrghSv6EdGP+IFSnelqRPdyfrT7MKiBgfUVnzUzKAc5CIy5X4KYuhvhsA8YL
         u8jZKFfSrQHCP1J9q0quGFSMt+xsr6ZJkVAXOpnUWWRlWFWi5R1tcGgsNBGk57xXpGZa
         XQlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705945155; x=1706549955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ie2vTkHbgvAp2yUqi9Z1IefLwUSIQx2OHycIqch2Ih4=;
        b=t8HbI8TJPPV583OsM4L86w/Hocc50sJVQTR++cyqidG49QUCGlKQr75iekKRQVWAZ9
         yFArymb/+3IaIHBRAwpfBRdbVPWC2wl6lg12jPGD7Vlsp1ca7y8Y5O2VRGgfwJixtUp/
         +EVLlBvrAAVsPB5uJ3kqKZ+59XJyrbUkNkX5HCm1zEGAKFvwnDXiCSovtcE0+Ui7cevR
         2eMMykwDsT9V0p9FFIdIA/OtgZIT6+ypY0R6F38gqKwN4OU+5afawEOXZAlyJTdbivHZ
         1lsIuMvPH3JpFiJdDyuDxNHGCH6eGrFXyx2TW7ZV1Fv1MI/vVOZt0hRMHNdRuXEadz42
         9Wng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwJIVaEyrH81qPOFPrmZu+0Dz6cymNF6pH+0MWAjf7VVySUtQyj
	3prvV1jeS7yCyHu5WHToMZIZMbOBwu01ZcXWOg3C7e/NYBJ8H5RG
X-Google-Smtp-Source: AGHT+IG9S3ZF9uWGeQmJlvBg0A8vZwmsqM8yvjKEIJrva9IjUHifQcTntQgZsiE+xM5hsOuOf7ToLg==
X-Received: by 2002:a05:6358:d594:b0:176:55d1:575 with SMTP id ms20-20020a056358d59400b0017655d10575mr1945887rwb.0.1705945154990;
        Mon, 22 Jan 2024 09:39:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a994:0:b0:681:7940:52c0 with SMTP id a20-20020a0ca994000000b00681794052c0ls585479qvb.1.-pod-prod-08-us;
 Mon, 22 Jan 2024 09:39:14 -0800 (PST)
X-Received: by 2002:a05:6214:20ca:b0:681:8050:6b73 with SMTP id 10-20020a05621420ca00b0068180506b73mr4819929qve.48.1705945154354;
        Mon, 22 Jan 2024 09:39:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705945154; cv=none;
        d=google.com; s=arc-20160816;
        b=fAiRkFkv+HfUO19XO8gGIK223O6uNNwWtPB6nuzHXyqMjiD9TXwBvHPJGcMM1Fc7qO
         Qgx0i3csvW3rskfLbsGj2entQ8KrGnQZveuXlZNtTIqIq3YJUSUZDciyh29V+tf4a9Jm
         vBWqz0QXkFrC3sMy0fVjPxF7vw8WtsBeKA+mJH1+JD84Vhvd2qJKpGADwFvTZjCd2q9g
         i9QMaztLxa5P7YZRYGjo52lSSr99UC6dtrU0dQr9yywK1rO94QQ1w9NPQX5WMXP4EwBb
         4kidH/I+pTqYiSSnC3HkxD6VRCoyULudV//ZNjXBanwuYvWJKMyC7wg5g4LgzbP+6k7G
         YOiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=4AsEnzAr/RZxWvJXA3fWbAVGl8PJn7m1hmHuLWToeFw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=NjAMtzATqRYKYj0KK8bB0HMZ6VLAnII0Ww+KFQcvdY5QGOeK3ZiDGbwOnjtwWnOavw
         ilY8UvXZZfGBAU0Bvkw+UoI+N2dmhvkqwRfNOaicsJRm/+fMubU7BkEfWmmSppiI4ub7
         phYfTK6rCnSz/53iNfgcGyT0ypuE0w5YEbtz/uaYbWz0LUhcqFOicSt26LyburhPXTmI
         2Np8n3yT0DvUKObWcKoTfKAPk9WTR7oKY95tecIYFkJvrf9PMxEe24F2JjJxTpNlfyiL
         X4TUZTWhd+AjXlXy1dFvsIEvxVVt4Zt3/NEK+ARfUWEZICEekeDNw8mSHVMAUotInF7l
         Q8WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uJy9MBpg;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id cz15-20020a056214088f00b0068564a8ca69si438786qvb.5.2024.01.22.09.39.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Jan 2024 09:39:14 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D3EA3616B5
	for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 17:39:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 80E15C433C7
	for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 17:39:13 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6EC19C53BD1; Mon, 22 Jan 2024 17:39:13 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218313] stackdepot: reduce memory usage for storing stack
 traces
Date: Mon, 22 Jan 2024 17:39:13 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218313-199747-LNNxyKTVSN@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218313-199747@https.bugzilla.kernel.org/>
References: <bug-218313-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uJy9MBpg;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218313

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
We also use SW TAGS during fuzzing on arm64. Probably more use-case- rather
than tool-specific.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218313-199747-LNNxyKTVSN%40https.bugzilla.kernel.org/.
