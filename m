Return-Path: <kasan-dev+bncBC24VNFHTMIBBI4UWP3QKGQEDHECTMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C438200B50
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 16:22:29 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id x22sf7169187qkj.6
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 07:22:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592576548; cv=pass;
        d=google.com; s=arc-20160816;
        b=rmn7mFISsH/eRjbMC/Hclb+lbU7skAgIJ4yeWCXfYuO5wpoDxjV+qNSsf7orUthxWt
         fJQOS5kx/4i0tqcyGWYP+SdKRgzG26qhOfUXNjN496iElA/vYV0rWj6YCKqnCs2kp2yZ
         LTw2C6D2qS+EYqmIvNEv/E7POLT7vhnYQcUof3J6R7uSayr/wcHNYB4l/GIVOuVIuatr
         /aN0URF9CEcM22KqSj+NshnJvsf2RCojXvTM51KoUrvSCMWdgBtV6qZQ9PbYZATguIDi
         xXWxoyQD3VQaVKnhox9XI84vF9x6KiPeBqnBFqQfn8R/OTtdZ3MRiyHMCWIlXHzKWQWk
         owMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=9WJX7khPbLVi+XgMmVt3CUgojHpO9k/+1Ldb6cnoB50=;
        b=rnNVYLwcCc1ZmCUZehaAF+z+His2Ujh95olMGV5e7LFBdBwEQ3wKRIZuv28/wp4/Ai
         Sb6esvJx41JLurd/c4/Us57sPqgmRKZ7JFsQyA+M2bGaaPTKOUM8WELFUKftvcEvwbxq
         H7mXZI7WnuKB1iySGv9fRuKuc3xn/EBj1taxUMT8Dpp0C3hPl70Jp+9a7KQ5hsV1Fwp+
         tO3kGsMpzTjAgBvvv8pJYBHicCT+QU/0i6sh7PgtXYLpMx3SLZRAmhv3KyHbZrIDRNcM
         T21uQZL1my5Zc5VSYYuiu2XXJG1mP8ZCKqaHoFiU9G47/CHrggtO3HlDK+DDpdWk1V3C
         xeVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=6apb=aa=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6aPb=AA=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9WJX7khPbLVi+XgMmVt3CUgojHpO9k/+1Ldb6cnoB50=;
        b=fv97VFMI7H3PnD563xgzDGdR+jXEXykA2HfOupHL4PeRd8d9l81DjDj2wp6ShFkZtp
         HR9qHMQfYQohAOWq5ke6+4XO5SjMV/io5ICYQM/1dpLRAPy7d9C8Qbw6XoMdWOZcWIGC
         evtGhmJAf5LD8R9mL8ULJuPfS+fPO4+YwgK8CN0R29sSSOTTaiNgabEkQQl4Ozf/8jlR
         Ku2vCbrVJeS0HZLY0HAWvmO+oqrbaPEeRO8zbfNadwFceDM/lHnFJ0GaMAnLcTOQZxIX
         AZg9PoFtSl5Tx1nmQ5/RLsGXZGRT7uSQ3us8y307FyRRdcPXO1JrZrOwqKaby8zidaRg
         UTvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9WJX7khPbLVi+XgMmVt3CUgojHpO9k/+1Ldb6cnoB50=;
        b=BmFSGWuCFU6oPFSCObpQmCeuwPyH61YzI5vIB27haGnHFhsd4OOYvTt6+UDIYu2nqe
         YpQbE+/lxOIWneFxNgx6UMIiNE+NHMHW0vVvWYc2P6QEXkLyQvz/33Yq94F7dlZLIYni
         38+afTAH1LyNw/dDCb8ykYhgqak0ylNJ2dWww+JqtI+3ObtSkvDYX6tYzg8gsvfdgIoC
         7fvholK2bqyAFv4XDjc+zHhTi9Z2hD6Vg4obTVIgQcRPkt9dTgdjhzRzkqWsAz2KqVp/
         3rJSJLPKy2hcNObFc25uQioaEwu6yX134PRtxc81Lj1YkOmWMVlw35kOBkMldhYy73j3
         UoZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aaL2T5x+xV1o0GqGOz/dM6KkBR1wQ4r2As92qjI9gJUolIVcn
	oqUCAX5i0LIcXC4xjBV+XuU=
X-Google-Smtp-Source: ABdhPJxcYqttYUFTfjpEPxGAQUcPCqEFfWRWK/3QBmkkhLYvolgey6+9bOlJ/FxRaySW5Gp3AKpU1w==
X-Received: by 2002:ac8:1308:: with SMTP id e8mr3671592qtj.24.1592576547925;
        Fri, 19 Jun 2020 07:22:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a802:: with SMTP id r2ls1152416qke.5.gmail; Fri, 19 Jun
 2020 07:22:27 -0700 (PDT)
X-Received: by 2002:a37:d0b:: with SMTP id 11mr3894090qkn.449.1592576547487;
        Fri, 19 Jun 2020 07:22:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592576547; cv=none;
        d=google.com; s=arc-20160816;
        b=lYAdCCBVPoZSKFma8jb1FBbBBgCLP+ZEYNLBtzcPli3E41TSWsFPlgxy5AJlNNod8j
         uz7atFRx41ZGEONGDKD6voanMfJ+3uTMWlUcyWpLp/2kUMqcbvt9f0VjSauA3O8Acj//
         2HxHRW8Z6AUJtfQ1PPS9t8NAWqvxnFsCpqJl99W62NkaoB4re18ZNDZfmY92B72b2ckK
         bHOkIXEiVVicpyko7f4ZVGv8wDutJy5F2gYG5FmbrIQHD46CXqbyZGK9hTkORmJbYKkc
         77kig6K6x976JXOxUgKCzxE52q2L+rxLV0TKKB5NxRDhstdpCpKeF6+anprV3g0zySKU
         Wm7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=SBCh0p0W+9Ebz7JJMxppw1sROB9YMGwKXf3u20PVnic=;
        b=yWBur9DxchLmHjrDV6mI+EbM8kiqMQxg4ncvthOjxA8dFyiTiDqwcEiy3fsqrHdvkp
         N8/bAakz8oxongB5NDpuvt+W0p/q7XgvCUBKzuwpqVFLPz94BE1S/oKzvaIG93QOOOeN
         ilieGGk7aB6u3cOyvI1FoHkjGLJYvzVaDemiBRwxA/SO6bI0KFR3xhH+VFzAw0uJ3Rhq
         66ELen1/5hhMFT/V/mlR3UQz1DPAzOQCZvTC/fVDjC2PEK2hV3CWtRfZNAdlhSBThKF8
         V9WJDgqtMl5KWV/95IQHdkmzUzLegwvBZ4P0Qhf24QzkPU8OziCEmXm2MtrSjX5/Kkmr
         xHKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=6apb=aa=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6aPb=AA=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d27si63046qtw.1.2020.06.19.07.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Jun 2020 07:22:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6apb=aa=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Fri, 19 Jun 2020 14:22:25 +0000
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
Message-ID: <bug-203497-199747-DGckuySRCQ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=6apb=aa=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6aPb=AA=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

--- Comment #10 from Andrey Konovalov (andreyknvl@gmail.com) ---
No, init_stack is a global and it's not tagged.

The problem here is that in start_kernel() we tag stack variables before
kasan_init(), and those tags end up in temporary shadow memory. Later we enable
KASAN, switch to normal shadow, and start checking tags, which are missing in
normal shadow.

We could disable KASAN instrumentation for start_kernel() (and probably for
arm64's setup_arch() even though it doesn't have any stack variables right
now).

Dmitry, WDYT?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-DGckuySRCQ%40https.bugzilla.kernel.org/.
