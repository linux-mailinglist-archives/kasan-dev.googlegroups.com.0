Return-Path: <kasan-dev+bncBAABBQP3RC5AMGQEBLOPICI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AB8C9D6B7C
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 21:40:34 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e35e0e88973sf3985442276.0
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 12:40:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732394433; cv=pass;
        d=google.com; s=arc-20240605;
        b=k83uXVL2fOyuZpSi0SvNx853K4TmPEBvMbryrnbTiEPhfO9rBHIKDPL/A6VqVkw77a
         bp6DP1jyd22hv7UPxcERaOISB1gwchu45bITjQAzGJKkQWP5igbWp9ROuM9n9We6EgdP
         FPET4FaJ6wSv1hxkcLk5ERXFh6fcsWuCepICkEv4KTiTPFtpf6+d3Wz/t5uGKhOaKEID
         IDe4BcyqTxh/bg/JYvu2ttbErSFfOpuZPI9hqwlKpQhp97MorXoDCseVWK8NTBqt94+n
         Qo/9o5JgRHRFQE2NeoSB/0X9T63CMBlK8k2JIt0+3aRdh1PG50InmkFY1OjkeFJ+aiWo
         e3eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=J6sC2NUt3chHGU2OD1584edrqv2xCtqk9A4JV/2Bh2U=;
        fh=x2Ew8cn4bMCt3GCNnhNT7B0nAaNeHwjZmjmR0S15p9I=;
        b=Di9w5dc8T7P29f+cNBo4C+xVFCEX6Kg+UIVmSJ/litr2SMmMOZwAKdeF9B5Dl4eDLc
         sDk60egVAi1u81AZxKpzj6wV6QJcJpgQrMrcaLoG39pYLPo7EaqiRIib2/6B0r19r9CR
         DeY84WMPsU2T8q3y4G72CX7JA3uSbZkIw30uBZlsGjkUzQHbYqvkGFYU2i/FquAiv3ti
         Hu4MIPX3dNV2nX9PKV87y3j1eDpDOsd52H6F4DhdHOSf3V+rZjJsYEWlvBpmIhnQxtqE
         2ftwTUpjUStNrql0XhFT0Hco7Ca98ckygmxqKYjrY2XO9+c69IQtRD00k5k9Msz1qSyW
         AJ6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZD1WVHSQ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732394433; x=1732999233; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=J6sC2NUt3chHGU2OD1584edrqv2xCtqk9A4JV/2Bh2U=;
        b=r+WqjIivcp8xXlQX5xq+ftwaPaUZBZa1Hf5GmNB6N+3A86JP1OPn+CV3YtWA9NZF3g
         O+WqqBCiS/Vr21LcGEJ7p+rW28u/vUHyTvrBlRiZlBzVnCeOEstfP9HWCdq72Lr0dh2c
         p33nMpxPum+qlX68ZB+NkW/3EISbfsuvNhODIw1ENvMikI1luaedj+TPtA1h5of/8x/w
         aITLEXTmEjXi4RkcW8IAP3CJFpy27pqXGMEN8nbpyNRjTk0Yvx46uUe5nxNDJTvIVzA4
         R4Vb31+L3AOZsViSqiymY/WeRd0YDMM3iZD+iUwBElC03dWxu67gbnhIqMgoGawk9CHL
         ivLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732394433; x=1732999233;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J6sC2NUt3chHGU2OD1584edrqv2xCtqk9A4JV/2Bh2U=;
        b=GMzzCw9Upg0ngVsxBWyh/DavdvL4tA9ogdD/XaVJ8fYsPNKT4Hn58Dm0P1Fug0xu+D
         +br5IOCfUvwSSkgUxZK2RV6JrGaVt33L/F9ZDeqF1DfuGN6YIDLtRqpMQW+yJPoRZLU1
         JxP0Xd3524Tvz4c3cfGRgZLi4kJyqkD9rWuxelakd6YEvmDn5iiUwvw/nv65bys2V2KG
         FEM/oL1AbxvJ0W1tQ24XVfpV98ncbBZ+dxwirG35pmEBnePnjYIWvjRjngPcVwPfRHPb
         5wzkB31Umf8cLfjv2oO6BkmIJs/16IWzUS0F+HhsLkrQ0IRMDG3BpDTM+6GIIzoScByA
         8+cw==
X-Forwarded-Encrypted: i=2; AJvYcCUyDGpVbAYvOxJeiAX92a+dKBeghDQQdBwa8NanBogvR+uQW0qGWOdZzXWN7y7rj6NjzUwjUA==@lfdr.de
X-Gm-Message-State: AOJu0YyJfDC9PbuzTD0xSlvGDoWb15UJawO4Km/pXDfhznOpPD54mJji
	JHW0iZ7N3XnBBWP4ocZy2QJRa/aanDQRjWkRHrqZyUjy8hfAAY/w
X-Google-Smtp-Source: AGHT+IE/LDOs3m45RXmAmtekyeLMYuvkkn4+5CxUQ8vtDaiO2y+nxbDFAWn3UdSVXfC+y4cTKJhwSA==
X-Received: by 2002:a25:3d82:0:b0:e30:cc41:2abe with SMTP id 3f1490d57ef6-e38e160e85amr9954705276.16.1732394433172;
        Sat, 23 Nov 2024 12:40:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:8c:0:b0:e38:9c46:1f8c with SMTP id 3f1490d57ef6-e38e1989a3bls2878235276.1.-pod-prod-00-us;
 Sat, 23 Nov 2024 12:40:32 -0800 (PST)
X-Received: by 2002:a05:690c:8f01:b0:6ea:8901:dad8 with SMTP id 00721157ae682-6eee08a976bmr48973927b3.3.1732394432587;
        Sat, 23 Nov 2024 12:40:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732394432; cv=none;
        d=google.com; s=arc-20240605;
        b=XPq5guNCWmkTD1Dt41O946lYTTlFwV2orPTgOL7qD0Bfakj2X8n/u4rHQnrztYdYUh
         LSdA+wxNU3fwf71pjivlln7MDh7BjmLunKeolK+4BK/iw1NSFoTaiJXbr0Y1Tbr7YHBZ
         zGiOuATbgefco/XtcNG+OBfRFrSqGUPgE4YMrj/2kNgB6dm1VBlXwwTQdpAbj7fjKeda
         Td+930CBPWaGnsBU+8JubjjiaYz50vONLUpCMpPhQgPtVFuDqNEP0mpHnUA9nDkyw2qQ
         4FAqfsdKy/akIEhnFS7O++t1aosJitJYNKkuERb5atG82EPZ8lQVYb14uJsKbfLffaae
         713g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=tUwa8Qd+bwdWInhgEP7RAb9OoTKgYCJCBAFWbnxKhWQ=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=EKvy7bmsitJ2+/5GNSDzDyKlzIKiF1lOoJ/SOwZS1H3ABWbrQtwX01ELUTF1UCm5C4
         oxNNsell3vZ44qEV368XOpd/bh7tGz0JNYsSxNfEESUZ4dnbMkjhdJC+rLoLNEO4Ehon
         vHrhTEvsHNsSjho9/GUD9DfblC1yir626YZtk0SlY1PSTLx7bqoPdLmD577XB/sc8MwZ
         iFHTP4VcRuerjPqfKKQ1M4/uQp+tW2fSTPl2SClXZqBtPloNxgKOuISFlvfApW4xuKr/
         tFfIb6+wBkJokHVp7BP84D1k1WxkAxUguFoCiVCv6vB6Za6N+iDkwqBN4l3ZczEHML3v
         In6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZD1WVHSQ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6eee009229asi2519597b3.3.2024.11.23.12.40.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Nov 2024 12:40:32 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 13A83A4082B
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:38:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E2638C4CECF
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:40:31 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DA80AC53BC7; Sat, 23 Nov 2024 20:40:31 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 216509] KASAN: add tests for kmalloc_track_caller
Date: Sat, 23 Nov 2024 20:40:30 +0000
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
Message-ID: <bug-216509-199747-ZQl8pKwYM9@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216509-199747@https.bugzilla.kernel.org/>
References: <bug-216509-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZD1WVHSQ;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216509

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved by Nihar in [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3738290bfc99606787f515a4590ad38dc4f79ca4

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-216509-199747-ZQl8pKwYM9%40https.bugzilla.kernel.org/.
