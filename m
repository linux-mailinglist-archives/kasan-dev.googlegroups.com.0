Return-Path: <kasan-dev+bncBAABBD7ZRC5AMGQEEYHKEIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E6779D6B76
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 21:35:54 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-71a3da16d58sf3785196a34.3
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 12:35:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732394127; cv=pass;
        d=google.com; s=arc-20240605;
        b=d7JUPxFQq5pmsfTplsH1LX58YxHTBJ1s5oxeyr3bK3fXLvzMrdoZjfBaTGNq82w1AF
         wqE+fQLlZ/QZy7mPclFn0tUhC/QriLzsGPvOHHVBjydlW3k8XR43uAxwa838mUL+/3CY
         CK3L/PLaTWgw5L9tk73xnaoK4zhYD3zZLMuUEglNgh4R7R+djtfC9pUukjsexbKBq46K
         R17gkalSx3+NtFYyHLs9DddJZhmdU91biJod5GXU2kAFLfC8b1hfxf52zZ7DNb1QBrzB
         ykMzVPjuOuprcHOsTr3wnPfe8GgA94I+yKh6F6JJOyikue7fsfHkqoaXBDpW8C3A8oDZ
         hpPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=0hDiXl0ZChNQ7xyU/Cbf+LjdmdGsJT4BTx/t3+Nki1Y=;
        fh=6FfOvTQhhZa9Z1EupqJ9YIaOu/VYXIzrNpUDxiGnvPw=;
        b=PfjUzTeAcAxeaZLLzWaOnDJpxMZprAm05j6m6ZYi6Vq9uO0bA1sxxRlwsMHSt6ZuEK
         IwD86oyT1puMDunWBzQys9s8lR4+c+ju9h5K2dwdRPB9x2vQjgJCsMN2Rs+OE2W5MAmz
         KO2k6U0jcsW6QznOeQSJIzinwOpgyN00MiYeSkPWg765VS8WjLz2D7vOgpDtRHh7oa//
         afh/sCO87IT+Ng7AIeVTozTci4dhEeLXTsx8IBNKofapj4zTt8Q0QvyMDOvcRRYAAXxF
         qYlOEk/PDFeIkd/ufKxPpkdnXU/wDenLe6YfSyAKNUFYIfzTaD6Mz5fWndjp55x1AjjW
         by0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZzWJ5HxK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732394127; x=1732998927; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=0hDiXl0ZChNQ7xyU/Cbf+LjdmdGsJT4BTx/t3+Nki1Y=;
        b=wS2onpenEN2SbdgqHDZc4X6ZqQl8NVs6OXqqewwo7TN3uvr2ulPIrVHdO5nJACAcwd
         ThtFQPjNSXPHAuQZhq4XjCgntTxJsYoHbK3cMGaOmemCcAnxLPnPBERFNE5dKFhSaSu+
         LYfh9GUc4S+F2GjZqmYUXV7NAitg3Thutfaf4IA9wDwcbnqd1OIFw4sIb4awiI90XWR4
         bVNlR6IpvBmz5ZiFCLuYGkztCa1hw5QLryiSlBuPzAVhXOiRBzuRZIhRe/e4aMvR3xWq
         hJ7g9WBDMjn0m44OxL0u3JtuOXdRy+v4+nXQgjjEx/dOIzogqmDTCONablOltKnCp1Do
         efjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732394127; x=1732998927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0hDiXl0ZChNQ7xyU/Cbf+LjdmdGsJT4BTx/t3+Nki1Y=;
        b=T8Xfsp3jdVkey5mFcMVFh2N7/vuPOLNZNuh/cQiKLTvKC44aZYelGLmqZDhF0YxGZE
         tPHW2qL6Hhar+cr/PfAOC2QB911J0lzinMuydC4vClCn1SYhEHWjfvt2WpD/RV4ia4YZ
         zLASbze+NiE1BIGBBrCJC2CRtIqzu/mnTl9cN8wEb0Y6kYjFXfQd4RoVIhaTwqyBo6Hr
         aDhH5XXHdA1vY/lMfU7geSddbSWOZ6Orec+QqjyNAfACmNCK+PFnuPKrrwvf0oEuaYce
         JokorVyMrw9XQfZ67YzYPfFrZ6h6lcjmOnWLqtvQgZYWiYD3JEFA4dsfe/7hHmfzYdej
         jRfQ==
X-Forwarded-Encrypted: i=2; AJvYcCV8ATvrJskFOYLNhxEDWUBbeneDJRJIw8+Sw8tfb/fa6B37lF8opaCQbN8dpDYTetAV5HI17A==@lfdr.de
X-Gm-Message-State: AOJu0Yw/jM9LCcDBMMma8G9GVn0HeX4TSXZ5UEGsp48JYQxJdzQCgRFo
	iU55Qw05v0fZwRpxUmttnDyZ1RJiuaT6qbLyLlc7cEgtCUuBADrR
X-Google-Smtp-Source: AGHT+IECOP5kyGvD4P3r52LOH7fX5WhaXw8Hy/3Ajc5BUB/+qL8UyIZFpNH9Zy/HT9gT/wfEX86gQw==
X-Received: by 2002:a05:6830:9c3:b0:71d:4105:405e with SMTP id 46e09a7af769-71d4105420cmr302867a34.1.1732394127408;
        Sat, 23 Nov 2024 12:35:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:22a4:b0:5eb:5d64:a13a with SMTP id
 006d021491bc7-5ef3c4c4703ls2451138eaf.1.-pod-prod-08-us; Sat, 23 Nov 2024
 12:35:26 -0800 (PST)
X-Received: by 2002:a05:6830:6b07:b0:718:99fa:347 with SMTP id 46e09a7af769-71c04b9a728mr8360359a34.14.1732394126688;
        Sat, 23 Nov 2024 12:35:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732394126; cv=none;
        d=google.com; s=arc-20240605;
        b=aM5CNhP0CFRNhCMhYxjbmeBmUCQ/WoDr7sRvfcpY+tBVApnotuP1pBxMndiTYF/CB3
         1r0ScbldYpeWpm8Krn6HmQzzJ0VzIxOdaXKJQ1C5MfJ2fGEPzYgI11inTSSSRXWDfn8w
         RHgq7Kwr/4G3rIUAFQEJRT+dcMiZOvJM8OwfbeUckTuuCleTwOYPCO+qEWEk+3cvEwMM
         CayGEsII+FGTL2AoTPxCkXxg7TTFDJ+w15qgB5MbDQBgKIMITZOgb4xw2klZaEaW/qUl
         9oeKChqPXyKtF5QhKKrVO/GTmNs3yw7RX7sn7e93mu2CW2lMoy2uc02BbD7FKsqRLmdU
         pQeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=D6GDrZS4z6gPT9Ln/Sa50dnEWoEJk8j1PdmZG3MmkZY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=IQqFgDEsNokce07u7FyLgPzWWiXjfgGwolRYmmBHoIIatq+A56NjnnMXEuzgPL8Y01
         5HJM8xf2nd7T8yQY/bmlU13n4vdbNL705jm0nY1t9AHwKQLVWlor52zgGeKLOuglLjHs
         IidZ2xgj2SswqMlv/UA5BdI770Y3TEmMt8sB7bxW8A+WYOCJrox9UQyjRmr7ow1XDeSZ
         onIfzQvXMbmYQEnmRbf/nF9VczzkrM6zDm82BYcYkJCUIy5ceTAs01ER0emdqSL6q7ru
         DljpJVdV6cnG9lH6ZHl5SPKygTp0JRTw6OdkhmumPHcAYJ6hS8QJOHwRQACa/sfkpxb4
         vBiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZzWJ5HxK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71c03743521si220068a34.1.2024.11.23.12.35.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Nov 2024 12:35:26 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B7CCA5C48C3
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:34:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CD1D4C4CECF
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:35:25 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id B8DFACAB783; Sat, 23 Nov 2024 20:35:25 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Sat, 23 Nov 2024 20:35:25 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-210505-199747-082G2fWgbs@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZzWJ5HxK;       spf=pass
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

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #8 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved by Sabyrzhan in [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e4137f08816bbf91fe76d1b60fa16862a4827ac1

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-082G2fWgbs%40https.bugzilla.kernel.org/.
