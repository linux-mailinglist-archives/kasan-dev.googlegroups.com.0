Return-Path: <kasan-dev+bncBAABBXOM5G3QMGQE4EWPMOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D5D9989D43
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 10:50:39 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6cb461aed30sf43406776d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 01:50:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727686238; cv=pass;
        d=google.com; s=arc-20240605;
        b=GFOKWAklSPT8T6/bS7P0Q8pT8nV3+cmzYzP/PGF1UIO2dBQOk7Cqkmu18LZnUKGHZH
         laazkIdYOIxJQBwi+NrDHGys3Iz+uNTk8DV02pdNwlIV/7hGocqsdSNGLKfQd8J91qR5
         p54SZa3qbShuV7AR8/PC1TYXZYqUrd5Hqq+LYhq7YzerL2MOc0SwKw6sUJ7s1TNHZUPP
         afK2wVhmVb3+7mcWA6pxeGhicx2ZJiqSnxMtjDRDOZ2MS+8oXCCZDeakZLBfnpfr3PHs
         XBvnQ4JPe3+oeNmHMblJwX6deV/s72impt22+VQHOSXazgkBbl87UCCn5OLzdVS2brE+
         fALA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=jYZmzoxI38RImZxgy2wliqC9NSBe5n8TXgjjt2IkyGk=;
        fh=IB+rblazl/FKuRQrawJH/JmI8Gzf2Zp36gT80kLVc0I=;
        b=f0KP9dUDgtYdtS0II01JsBUuvoRkL2oHfe+xkj/46Yg9Vze4UsQPGRjaTPcGV3gB9R
         JUvC1FciU62XoVxoq0mh/7lFWsJO93BBBQ+sCjRqQQT9l9CxZTpCKeUMp6Sy5GhFvRZj
         uA39gPTGzYQ36IAfzQRsYh3rL2WNsop5ixQSf6AaF1UjTyysUHCWYNVAXuHWmu4Bjz7X
         LhRR/pd/D1zgvjhJNbnm+gGPjXCds8HnwpMHXkWdMp9bsf6VEQ7nwfXSimfRJFppQL7Y
         9RgIJh4L2Byl2XSNCHIEuCMlBkaKuu9Cu8PUG5wTm3wEXFPIv2HEWPP0+fQZ4pCryeL/
         Je4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZgQZW+hp;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727686238; x=1728291038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=jYZmzoxI38RImZxgy2wliqC9NSBe5n8TXgjjt2IkyGk=;
        b=anXTQszCoRFnoA3KriGcxjIwRliJdvQ3MDEvDyLuvSwcsTMYFO95SBZon275JoS4Gw
         IxlbHHnttWYqE88h1pTnoeEk6fJg2oTiZbG2ytj/MIizAGXL3Vxr4vZKBhVVlJn9inqb
         a1ogomHLyxJA+lV1Zaerv8qQ2yzloDkgo8loVfJbM+X/UjGN9TBQxSjC83H4T7aW+veN
         fFKXqWOa8YaFo4GHjgvBGkCLXHqsZAvNSZql5V+wQPupcA9WAp7UXK/Oli6iqcuoCraA
         p2dVQdLiM+eSzT+CXy52hkC4HbomTK2PFVWnSDBS3aUCMsBEBIcWD5uHlxrDRyP25mSg
         s0Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727686238; x=1728291038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jYZmzoxI38RImZxgy2wliqC9NSBe5n8TXgjjt2IkyGk=;
        b=we+xAQ8XmR6N348VQYXElUTMisHDt5Y77nrq1OvLk4YF6FyabPgmrNu/mk7rER7HEH
         TCgxaidH2u65OCPvxgcqeI8LgnpDnUBuVPn5UxXVA3EQcdHICXzAJPoH+n8AjDZoG3+8
         5Zz2L60EPMzC3jKxfSwiws8/swIODX7TCUJY40lPJ/czCeotgztCfANzo4s5djPuEyD5
         CB2NbKFZZfanhDDU7onGGDqyBmUER2HxQJjAuC8ZjMiNgAXwmVxxf3qR5LmzOu4Pi650
         p9aLm1tyEB5aP0EinhJiqldK8+2rXIYwliScjPVtGcKd2aFnlQxwtdV3iDkDd3O6edVM
         HBDw==
X-Forwarded-Encrypted: i=2; AJvYcCUAEP+592rNCCvAn84COaOTx1kGHXDIU+n9FBzXN00iH9d3LAve6onJj6UyM2O2qHkyFjtN4w==@lfdr.de
X-Gm-Message-State: AOJu0YxSqvBQYK+Y8NFjniYafPXk5MRTDaGLI+lARmuF9CfEkjiaIEUQ
	yXvWroc6dMoPQvPcDHqVSkCxTl5jVt0wXFXxcY1aQKovZcR7/ILd
X-Google-Smtp-Source: AGHT+IEbPh+TffvtcNcgQ8YsQstRko2YM/25WC/w31EUBz+XdE8jFy4Kz2OfzC329nRfO0LU4cUssg==
X-Received: by 2002:a05:6214:41a1:b0:6cb:4b6f:7c0 with SMTP id 6a1803df08f44-6cb4b6f13f8mr133731476d6.30.1727686237850;
        Mon, 30 Sep 2024 01:50:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5caf:0:b0:6b5:268:d754 with SMTP id 6a1803df08f44-6cb2f1415dfls16369086d6.2.-pod-prod-03-us;
 Mon, 30 Sep 2024 01:50:37 -0700 (PDT)
X-Received: by 2002:a05:6102:3f47:b0:49b:cbf4:f56e with SMTP id ada2fe7eead31-4a2d8006eb4mr7098745137.21.1727686237000;
        Mon, 30 Sep 2024 01:50:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727686236; cv=none;
        d=google.com; s=arc-20240605;
        b=cLGFqxpnhYFN/vkV5vQnncy548qRF4cPYWN+WuETXcQ47jCARm9MMIw3htRYzlneKx
         WAnk4EcZei6ZyLsWVTDFDUzYp3pRHW5aaWxwwoWlVwz7yhLEseWdDgVwOHhR69Hbqebu
         OPnU/3yMGljmf8ET18Tn7NN+7y+7H9/8C+qD6Jq6Id0NjKBeQmU3al5P2OPGKA+G72CP
         9hUbseLN51pO4ZYf4h5iL/lINB0Yw3/5zWaiYWVShfAPJWp7j+kg8kGM8Gm0QBpQHQ0W
         jkm5x+hyywseskKhYNhtz2a48s3NUSdF2JWBVb3tI4CJn6EI5e4NaBRcm7+P6JvnduUV
         JvFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=CU9ZAKyZxeb5GpxlRCFEFLfEM5Os2ZNxJCEmulw0gvc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=MsUWUKH2ShZIEbZ7z955Uw2LJ7zvlR4yESlqv+7TqOFJI5Hy1ky1O9K4mVmYtXQUXj
         istQef1biYC1I/xqhbrzlf3UamYnKE8IJrisldWnYDaHKUSfKZhFYkms6/pK2ZkroA4E
         pa+/y/LJQdUelztYvjgN2t53OWosQ49xAZr7TA3vIbZ6kGPeg/l/6PPcGNnQzxAGQlqW
         FVjyysA4tZScUNNRYRIxPx786A1a9sVHx6wvanMfZrfPTm7LBVxIvkisRF/sHgpL3Otj
         iEIE5uQFFJTNu+/Qef3KkpKfChA0czQgxeYI5j+Kes6G6rl4mnJEOyc6u8NiYMZeb0lS
         18cA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZgQZW+hp;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-84eb2171523si275048241.1.2024.09.30.01.50.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2024 01:50:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 70AC05C4D93
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 08:50:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 334DFC4CECE
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 08:50:36 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 20234C53BC9; Mon, 30 Sep 2024 08:50:36 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Mon, 30 Sep 2024 08:50:35 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210505-199747-90UEBahaDZ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZgQZW+hp;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210505

--- Comment #5 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
Thanks for the comment. I was trying with instrument_read/write()
initially when the check was in x86 macros and it triggered 2/4
cases in kunit test.

https://lore.kernel.org/linux-mm/20240918105641.704070-1-snovitoll@gmail.com/T/#u


Let me make a PATCH with instrument_read()/write() in mm/maccess.c.
Checking it now on the latest Linus tree on x86, arm64 SW_TAGS.

Hopefully, it will be delivered today before false-positives.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-90UEBahaDZ%40https.bugzilla.kernel.org/.
