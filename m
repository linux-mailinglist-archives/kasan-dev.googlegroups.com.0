Return-Path: <kasan-dev+bncBAABB2XPY24AMGQECUDT7JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id C92D39A31ED
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 03:20:43 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-6e38fabff35sf31066747b3.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 18:20:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729214442; cv=pass;
        d=google.com; s=arc-20240605;
        b=g99gi9cmqeF1/N0V2YxvX7cAXMuRXWhHsHDovuiQchnZFaih4N/MZFqQ8E1W+xzUEY
         zHuqzD2iG1ywE5Evaw8XJLVRS5X3rxx507tgr6qCaTHIpiUL43f8aflLpyINIBiJtwUO
         SGgTqY2l6i3a4KCEtHWAScFmKflL8dooucwgc1kZKkOuavCp+O7gRzWfX0s3om4JGbTx
         vpatnowE4A1MMu5g7FRp3kIrd4pugzeB5dSn2tT9Uvs127rwx1KQY0CzMOc+tsyBb50R
         Ru1hV9HyWd5lt2j7zszDH9LPKDCJcar9E9paylCy8LXnqAE93nywtBdva7u3D8eZlnAm
         LeyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=nH4LHkSz2PlOPP/EBD0A1Wb+qFJvGvvF2O1HeHnw3VM=;
        fh=cwZ8clzfUzab9j0LkvKidLHj28eSGgBNv/MAWTDwbAo=;
        b=i6IJLlrWJK7y3kXhf8QmPbmzTaqGEEXsxim/7mhUz/q6KoFBAMoXqKiu4KlM9KS1MY
         ikJwd17nYJR3ZbuEncFDzGE4ZlpFrkdPzUW96utad15GpsCllpsK9mo/3lFKAdxe0pD7
         TyaTEePyVxVOJfmG4Wu+lUSkPXpwhGNSeoCfhi5vRjv088A4akXPpgeCHsZ3nktSlIjB
         0GngRnPPOkoGxKD/mTDP3DQJJrfpja1UonSTadLVe6yww0BOiNghiTVdyzleIy0z/H8+
         SR0+PDtDjLyun7QMFOdi5n5jfLgVTGXuIjOAcSR8YFvqru3svXaYTOx63xteW0PKBIWE
         snJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fBKabsOY;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729214442; x=1729819242; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=nH4LHkSz2PlOPP/EBD0A1Wb+qFJvGvvF2O1HeHnw3VM=;
        b=e9urxqyr0mnoDRHnDoEjTXl1uSSJ8oVb70yPqluRIs647zmtfBufMOT48iNCmCek9F
         F9uRMr//0hQcboSCzznfhnn/d0S1yGmegM6wiZQjH7Jjl8mj9VnBRL/j1Hr1mnisNXtp
         NarZxdifxCPsd4vP+sEDk4aD1Z13O4vc7CBSngW9TRN0Da4XUnMUTd79Kpv+lnRQcNy5
         E8emRHOhUOjRRL2bi6eMF0aXnft+3PmO3u9wRMU74igI7BzdebBegABWgn8IoO/dr+mf
         CZTRej1kLsPxBGHcD5pv57/HGQ0yxTBAnGeGw8A1zwf2Q/haYqD2up3+FCgaf6M6bWYz
         4YKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729214442; x=1729819242;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nH4LHkSz2PlOPP/EBD0A1Wb+qFJvGvvF2O1HeHnw3VM=;
        b=B29TR16DpDjlxYerkmD4euXfvrWfoHYrDsDoTUwZ/zmIYVL4Umm+B9dtS4vwNakSSf
         qn1oRvO3yKKVlIcdKMGvLRCYiZ1UqNGellBhHBpsxS7xUk/P8PgDQnX2dvqoyGl94Ia1
         mt855rQ50lWpmlruy/GLXWSVt0KAcY/jQM3xw3qEFPEKqvJ5+yiPxlyeepW0OcTOjOoY
         BUSJGI8MSztDySlAUcy3lV3yHJSkLUi41euehhJpvBo1wfK70z7P2D+4tXt+9+h/6tFJ
         P/eLKkWNMu5lV10qJwvhUCP5lpJd0gC9Awso182lRCN6fklfIMivKrF3rM7lAvO1Avv6
         EPgQ==
X-Forwarded-Encrypted: i=2; AJvYcCWwsR1CmgCbIEQIFtuRc1Zt3iq+IX8tcpH4DrtQmiLs/SdyqhArSiRP6jfHRdAa34G5prMffw==@lfdr.de
X-Gm-Message-State: AOJu0YxCXp4HJLIuI3ApAxhySLMQTF6+JuZRQOew8775V/JVPs+Z9Oyw
	kPh+WyKqdFBaz6hYtuRtpWa+XWUwQm1tJKnluRYo75PS9CLKP4nh
X-Google-Smtp-Source: AGHT+IGszkzDmEkCfC6ol/k4oa5izVihe9P+88i+QhwhMj3dUroQA2+rmiVNW8t4m1TCeib+dqfqGw==
X-Received: by 2002:a05:6902:1b0e:b0:e28:687e:c152 with SMTP id 3f1490d57ef6-e2bb16d75camr631896276.48.1729214442361;
        Thu, 17 Oct 2024 18:20:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:2d08:b0:e1d:a081:e017 with SMTP id
 3f1490d57ef6-e2b9ce1d97cls1311936276.2.-pod-prod-09-us; Thu, 17 Oct 2024
 18:20:41 -0700 (PDT)
X-Received: by 2002:a05:6902:2293:b0:e24:a040:7558 with SMTP id 3f1490d57ef6-e2bb16ac548mr617844276.42.1729214441750;
        Thu, 17 Oct 2024 18:20:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729214441; cv=none;
        d=google.com; s=arc-20240605;
        b=Pzjjt4wpzjlc3anwNW3UxEgsxi36kGQk22bgSmxm89SFlPG+8+bmuDExpDLdD858Gp
         yy9f41K5DoVNgU+f9qN8j4+XIcQFkkVDOqg8Ac8cHHgIR2Wnrfeiiz9vV4yHbPo+ltLT
         dn6YkdMEJ94uGIO+9rTDR1vEIza2jb3jhk69b7SwFpDfN2NJ38q+tM7BMuqiTKBkxVqO
         Hq2zWPJBGbcwhp8R8xbp/K5WwBoX7hx+PUX8rQegH0FjR3BkYQ5cD99hQWxUZUcAxy3k
         2qD0qte3q7rRzecQwNHHsoEiLkDlyuBxTg0opI1mWCeK+L52gSj0ELBfzAQJuLblXVVc
         nMvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=9HmxrDXmd6mh1kzfZ8AId9v5aQ51nHEY49Vu5/YNGoU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=H/kQzDkE18jpM5j/e/1lWSrpD0iAS0gxppc63mkjOLWGd000qzC/KoqqkvSbPbm4/o
         4BHhZqZC3UI81NrssljkszGOMwOYIjm4pJ86XJ4M/8XQDPfIlb8VThLpr1sUc8JlPa2X
         Ol6tQ1vtCP9jtKKA1mxJyVGHcwWbKri6j1ChJYucKFi5RjxjXu28JLjxJU7lRTlRbXZY
         D8EkBYxPrReZdVkeAomTXd2Ml2g+32/vxSUzw9fttfVjGaJkv5qFjyHuk8SOUG8JeNTe
         aVRsyGrLn5XXAjsjOC4fwMpk9DiLxPOjYlynLWCeRkRWgnUmxbVHapoirediVboqXQgr
         aKRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fBKabsOY;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e2bafe9aa86si33842276.0.2024.10.17.18.20.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2024 18:20:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 38E94A43FD2
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 01:20:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E38C5C4CED0
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 01:20:40 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DC1BFC53BC2; Fri, 18 Oct 2024 01:20:40 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218854] KASAN (sw-tags): multiple issues with GCC 13
Date: Fri, 18 Oct 2024 01:20:40 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: pinskia@gcc.gnu.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218854-199747-9ToJMXxBbD@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218854-199747@https.bugzilla.kernel.org/>
References: <bug-218854-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fBKabsOY;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218854

--- Comment #3 from Andrew Thomas Pinski (pinskia@gcc.gnu.org) ---
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=117196

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218854-199747-9ToJMXxBbD%40https.bugzilla.kernel.org/.
