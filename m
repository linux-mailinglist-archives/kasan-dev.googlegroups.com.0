Return-Path: <kasan-dev+bncBAABBM54RK3QMGQE3Y4UACQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A310976388
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 09:54:29 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1fd6d695662sf11334785ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2024 00:54:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726127668; cv=pass;
        d=google.com; s=arc-20240605;
        b=CkCHhQ5ikeLZvsstBYGwo0MWjAUwI2G77Mxbd8AcKZvW2JQ6QLbgOmciiOKSqhT4vc
         clUuY8LMIdV3HcxiQmXmjRXoiSo4BrCSI05XpYoKd8UnJwqSKX4q6buOc7CDcJgil1mK
         Z3zxHq0VavdltD/TicRIZSepjHgHFhW2+qQ2gbzrXtONHZNsO9c0CnGgGjiayE5NfAHe
         Izb7pC/IuTqdzBqLD2ljXaiHWCZAquQP4nZ7EnWFr1ZN1D6E9n8is4QhANB0zGnXVEY0
         wnEx+KP0vVxUwCTXp7hTR6pa6urZplhT6ZE12Yiv+0iz6/6ulsDTLLX7lTeK9JOJzBvs
         pXRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=MRPVamR84ASthvtSlu9TLToDxaZRCYHJbR4GXB8OAzA=;
        fh=W5kMxlg0iE+PdyMb24sXrCg7D5cfbtSfzgICNDtNtWE=;
        b=AqRGFmfFd2/0cCvx0F35OVuntUc99ITGP58O/5wlF/+XTFFkcjmjzrBVGCvquaeBRe
         37q5X0yt4aX0lLdR/IMTQt1GG0ymHw1EBbl57ivQXHWm5D4O1h0bqlzFiQ1jmMJlGmOE
         99Zw6/0QfZDWMe0ZwVZwCljESy9aHmO11EANibITmk03uwmvv9zyCtyTZi7iD09woBz9
         679uIoW7VXl9tAk9rzKmWy3ozt9Jd2KsQk08EjMwMWVvTFw8xqyzON7OqMmYiEFkMriO
         yNZG7UAFDayZH8n6Chb4hNMnTbxpODRO145BOI/elMyUX4nUu/3mKwWeCGtGVfLo/zQJ
         Ycaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TNKKZbKL;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726127668; x=1726732468; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=MRPVamR84ASthvtSlu9TLToDxaZRCYHJbR4GXB8OAzA=;
        b=Aq/TmZCPXqwhrQ8+lruzt8LFZ6EkEVVvHjzXatSwtRUogSRxQXkK+zif3FKSHUdnfy
         Tz7juKQz4CduUBzGNIATG236HJBlfp1r/TxnykzPn2ji8KRmn62Tea3n0Xi5ovei0WpK
         Xgp/CWBALOLwtHhe7n88xrcLM8d9KQGTMgaN5ByAIGZhmguH9EiyomZ/uVG17IB9WtiJ
         KPaNmtnJttWhwWfPh663OEophNi0KEw7GGKWy4BH1zstHt4rfPoQ7+ySfpROcdd/gSB7
         ImMB87UuqFbrH/2x9+8Ya6L9NjHv6ziv/eI30ClkIsTGdTg0Fj6uszDyA9h5n9c7BPLx
         ZyIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726127668; x=1726732468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MRPVamR84ASthvtSlu9TLToDxaZRCYHJbR4GXB8OAzA=;
        b=VhLVdH1+X6FtnfbEBrLzh0rxxrkASdYRRmVwJX0LR6UCEWblTCEF3Fq0D/5+4FqM4U
         9BtNb7vpxVZc8qx9hdE32q3TwDkpkpFoLKDETl/Jg4J4tCQms9o1mgBbI/nIxGE4AaN0
         pk/536TK/Pvt4ExK2A2YSSqAeImGL/3uoXD7jVRwJj7rpSse7/Ikfrn+bwvQQiUty6On
         An77JK5RfOEypp1LxxTJu01u8vXzx2osqfbX3e9TEK4LCqPvTK2BfToWZc1fQ3C1Dv86
         G/OxOxhZmVDgKXuMGADwQHdHJefY1TCkbkMO5AszelkaV5VboiNbbyOuqdjUYrFh8zWP
         OBHg==
X-Forwarded-Encrypted: i=2; AJvYcCWJ6iZAnN4E75CwPkFOWs/U27TVHmo5oFk7XKL/ttHCckSUtzyui/DE4b0t1afA+8y2H4uebg==@lfdr.de
X-Gm-Message-State: AOJu0Yw4s6cYolfBUyPzMxJDc5vJ/9iYZKrcs51PMc3Gh/DE2H/HKrWs
	kR+qwD94z25YCL08qf/dVksXJiae0Md+I4x+SVCqdGb9ShV+HrP6
X-Google-Smtp-Source: AGHT+IFfl+hUNxz/tEQvIRgKoo/tbR6+RpDuDVF0YrFpQQpA0wRgDdnJg6aXO/9VXDjgJdljlXZ8tw==
X-Received: by 2002:a17:902:f689:b0:206:96bf:b0d6 with SMTP id d9443c01a7336-2076e41703amr31179305ad.51.1726127667496;
        Thu, 12 Sep 2024 00:54:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:da8b:b0:1f7:38a2:f1eb with SMTP id
 d9443c01a7336-2076caf1107ls7053165ad.1.-pod-prod-03-us; Thu, 12 Sep 2024
 00:54:26 -0700 (PDT)
X-Received: by 2002:a17:902:c94b:b0:206:b399:2f21 with SMTP id d9443c01a7336-2076e3ea491mr36166465ad.43.1726127666413;
        Thu, 12 Sep 2024 00:54:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726127666; cv=none;
        d=google.com; s=arc-20240605;
        b=AJYYqSZtwax/fpHAvQulnSf7PVp7SJ3QRwb6rDfyJ2d1u/N+R/Eeqiir8LQyjhxAJs
         qKeeSoPgd0yRikgvzXsm2UOKlV0h+tFot4In2n+Pj0h1ekjPizRictmbqpgCODjApAQR
         C1UFTq0F/vBcdc5INeahm/Qmi6VgW49hGT4ojVnTr7RTCt1RQwsew8E27TV3BXJ2TNQj
         GS3j8sj2N5iPBs9uQYKhN559v2vrQsC7NWQubVpCdcAc427cqpgJesu8B7CXKHW+eZv5
         hp0++7c/vvWYxLUV8DGxqdFMnyeacfTcfl6UxR/88r9okCEVlmUEJJD2WDbD3UPsAgd/
         l5yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=fhUBKKlQEDWlqZVJa+0rhYX60e421Ym1H/RhKjTFEKk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=IU0+fYFOUvXBYxGHDfZ3HIAIvCcq9AltnK5kaxrNjOSh1CmUhn73J0nEYD72ARiJmm
         KMQSkW/LSyEbHH6Xeyk7LbpYu8EzcQYbed+avSQXjWycJkgB1k2YL6M1q49zXp27ex/6
         dE1jJudQsKYOrp4uaxOMNaaceBdtSz087bW7EE3nCpnZD3YdSNaY2m4WurZBBhQeNmT8
         YJOGm5wljCYDbhZMLsd2WtB41RAEKlrJJUqPwGRcEFcwKX2cYWONJ3VRQDNfeWVHm43s
         Eyjf0/ebSy5vsH5948Fy0PQe18Zq/RW6c/7VssFjUTKnoUIHEJWLeyjCdkDYSJjl+t7X
         M5ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TNKKZbKL;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2076afdf189si653205ad.12.2024.09.12.00.54.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Sep 2024 00:54:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2AC445C59C8
	for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 07:54:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6DFEFC4CECF
	for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2024 07:54:25 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 56B25C53BC7; Thu, 12 Sep 2024 07:54:25 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 206267] KASAN: missed checks in copy_to/from_user
Date: Thu, 12 Sep 2024 07:54:25 +0000
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-206267-199747-6ruUeYPqSH@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206267-199747@https.bugzilla.kernel.org/>
References: <bug-206267-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TNKKZbKL;       spf=pass
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

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |glider@google.com

--- Comment #3 from Dmitry Vyukov (dvyukov@google.com) ---
I am not sure if this is still relevant. set_fs(KERNEL_DS) is not a thing
anymore. Has kernel completely stopped using copy_from_user to copy from kernel
memory?

glider@ such copies were handled by KMSAN specially. Do you know anything about
it? Does KMSAN still handle it?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206267-199747-6ruUeYPqSH%40https.bugzilla.kernel.org/.
