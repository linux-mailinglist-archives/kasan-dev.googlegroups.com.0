Return-Path: <kasan-dev+bncBAABBKVW2LBAMGQEUHIVLVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 03288AE0FF3
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jun 2025 01:20:13 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b2fcbd76b61sf1549822a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jun 2025 16:20:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750375211; cv=pass;
        d=google.com; s=arc-20240605;
        b=kXHX/pARICfn99TEuXhfZnJsDGJwRRsPLqNPP8h0SOsVsbUPmAQ1YgM1m7yAaT5ki5
         pRuA+VpNqczm0uPX+ndE4VpBPs3ULulGXGwtiFCq723+3TEPwUZp4yMTcUOHor1KvaXx
         RI7xD1w5US9RZim7Ti/9mbG+f2++qGsLBePasVIypvQlZp4ANpz/aLgE/cEgFHI37cKI
         ZyPhx6NuHTDqqE66mOPX6Td62HI9BpWXWCpc3nu55MePUiWuOd6jtBNkNnDIFcc2F1aE
         VmDVTiZz441vR/ynHKT7nCutTY636l2psFEBLbJpEDBZQImTFUgndSW9Z5fcvs4cwYcU
         dx/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=qIJX3m7bVEZNhhx+V8nNIFPiz07V2ZqnnaCc4cGy+Dc=;
        fh=TOcYUBByxn0zzvtxlGifR9BxJrC95ZYtpmgi+ER8tfc=;
        b=ROIbn/kCNE0GvoQ+l9FJ3YbVRVHHbmdB/Bfx8+ypVJB/8be9kMK+oCBsGDczyaQQgi
         45hDpF4MaHaoMJxhe715IFL90gGUsUTczS4YyzH8kiHSAst36+zJin8xdkKW0fP5GTYy
         DyBh7A/6GDPlpqLaGr3RGsb1+WzJ0YSPv0kLNtAt8HEFLmC/cKrnWBawHk3tcWeDINXE
         /q+va6MK2voi40tvs/5OGgAFADbpSywVISjATRBKUFV7XG7JOkJBFXLHvHrMEWBEfKz9
         2LVblwsksvyx3Sam6cD6HepiBier0ZHqpWLHI37tJrJCtj4U2hPe6fc0zmptKQQqGCwi
         cC1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iT6GAl02;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750375211; x=1750980011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=qIJX3m7bVEZNhhx+V8nNIFPiz07V2ZqnnaCc4cGy+Dc=;
        b=ovBReRU9Q6+mtiOdbIytW9fgDXxL9rHWxTAvThu/WSDhRm3sRyWzihrJ+04A6a09cW
         dZv/1dS63V5BWHV1d+k01vSy+Ixd4szeScXxDRX7Dm7s+n8FfhR1uF+J6eFhbZndHUTn
         V3TfTmmVMPsTWB1W/Q+7AXtbQqViki38HxyL1TrLQZQXrolvKYDqhhbVTxU9NXo1435J
         9emGxJC3eN/7hPJ493o6NWTU63v7dxO+7rIEW0W0OSyMj2riupXMvXdz8achXxgBKK8n
         6S9km2TzOdCJTUWttQez7kvVH7r2hx+i0BfpVv3KsoWhmK/pIzl3x6/xhbuzkNmHjE9K
         21Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750375211; x=1750980011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qIJX3m7bVEZNhhx+V8nNIFPiz07V2ZqnnaCc4cGy+Dc=;
        b=PiECN0yho3G44Rt8A21BI0zllCVa44E7l5qU3bd5f07T3XsE2YaQ5ffFF170xn0mRr
         M4ujmJTU01BnpDTszjrlCfcAOnwYM1+COrlm/UNmR8X+uhfVSTVuBrpT0r/uYbjv7Agk
         BlkdKLJjNnKi0TvXFWyCAcjgVC7U5bucKATCiyIVdVFLGQJJQnYAGX0QwYjEHC8NLB/s
         Tj0OAybi84TJFo4Q58ZxCslfvoSLtrdeXbcrOuLjYDRN2WjQ3miVR7BN762ypYVaKOIj
         s1ze3mQ1B/NWzuMxdvkiGQf3Lqe8AuJnKhhjuLqN1jkvT4kKeGrwi8RyqQ/IIXrlv7GB
         ch7A==
X-Forwarded-Encrypted: i=2; AJvYcCVKgkm64F6ojgqaRADuBzA+tRw6swV46WvG5ySmZbhSD/AMnga/5eeydLDo6uJrT4X+jk8jxQ==@lfdr.de
X-Gm-Message-State: AOJu0YwL9sbGiDriAsl5UZAG8JR8eWlkEe0m/bAGqxEXgZISMmeQ70IQ
	Xhicfq1KoeVQnIsVfocPLGsefOxjdiON1tC0maOYiM8QTqVMWsHU7/2T
X-Google-Smtp-Source: AGHT+IHhqj3TTYiOI3jZkDuBClRwXuRYmC6JKv2ci4lJvm3c04ZoPTMLgg5rqmcyO/ld+RiWoYVr5w==
X-Received: by 2002:a17:902:d58c:b0:235:f3e6:467f with SMTP id d9443c01a7336-237d9779e4cmr9073175ad.2.1750375210931;
        Thu, 19 Jun 2025 16:20:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfHcXf11SyUYMznj4TWwcv/2jv8iNyysDocHYPUYWAlKg==
Received: by 2002:a17:903:2f87:b0:234:ae27:bf45 with SMTP id
 d9443c01a7336-237cd4ae431ls11851375ad.1.-pod-prod-08-us; Thu, 19 Jun 2025
 16:20:10 -0700 (PDT)
X-Received: by 2002:a17:902:dac9:b0:235:f078:4746 with SMTP id d9443c01a7336-237d9a798bdmr8463655ad.42.1750375209746;
        Thu, 19 Jun 2025 16:20:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750375209; cv=none;
        d=google.com; s=arc-20240605;
        b=N+goUkLgfNhyvrX67WYh2wgUSRvUHdcDhznhmLintvm9VTLrEu0qtIT1nHBgg0Y0qv
         FzOMDzs8hiIeMayIaJ4amM1XhHBLRCROX1EDhm/N0+ZROAgFGiu+2ctyTpHpgEfFNrsO
         A5+wnJJY5Hp2as/uBihfs8AIH1nKmCkdbxBrjPr/dCPaHR/toqvkvyOEivY5k9RST79W
         1RtFaMYfpbH4jOtWyUnfEFuXF9DYtCh3cOOUC/qFSwtJCe9dp+qkWJTOrSjF45VeoOdO
         I7WWYI2s2985j/EQk2j1YeL62EdMXGbZ4lCufi88Ao32oN7TmHVlrop1y5Jodw1fVC1y
         uSQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=gOhn4G/J7Dx78T24kUMC9BHMKvDNaSSInYv+Em+XBC0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=QPBRLu9cou6o3iTvA1utXilcJblcazJQmJJb49ACYnp2zUBnDUZWG066Wa+CUjzki1
         A1Q9+hmmgqg7d3dVz9qRiUYztEhl15mU60Z4q7fz4/JswnAo8dpzGBGOrz6umjD6CKeC
         wC7BFOc/zCaxHYoqBULipChI1wgJd4KTyD6Zs3bDH7tZj4A3Y/Of1Afs7+lmSVsXi8uZ
         sCmW+HGx4UHR644uyI2S60I2YQHGi6yQhju7zLuTB544gmFJ7k/ZliKg3MpF8bCKn5WE
         O7pc0eKZuqTGu0YcQLeg6tqnKjvDMJbzUygVFj5qy+TU61M5RjPePNKDOog0LwRs1fu1
         9bUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iT6GAl02;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3159df7cda2si33872a91.1.2025.06.19.16.20.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Jun 2025 16:20:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id DF5E0A52BA9
	for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 23:20:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 89AFAC4CEEF
	for <kasan-dev@googlegroups.com>; Thu, 19 Jun 2025 23:20:08 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7D5A0C4160E; Thu, 19 Jun 2025 23:20:08 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219800] KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
Date: Thu, 19 Jun 2025 23:20:08 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-219800-199747-RZgBaLEKEx@https.bugzilla.kernel.org/>
In-Reply-To: <bug-219800-199747@https.bugzilla.kernel.org/>
References: <bug-219800-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iT6GAl02;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=219800

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219800-199747-RZgBaLEKEx%40https.bugzilla.kernel.org/.
