Return-Path: <kasan-dev+bncBAABB6WQYPAAMGQEOLSXANI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id B5172AA0FBC
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 16:55:55 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-6025007d8fesf4143610eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 07:55:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745938554; cv=pass;
        d=google.com; s=arc-20240605;
        b=l0Aup3091+ECXdcxs30F8daFddckKZgNsB0qIPiDY9FJL1A/ORJRUkMbRNsGndVlIl
         uLiQhiOMJTHgoTICp7yUfGOsHXPnZ26t7qpErHC2GiIqozujEM/yxAs5KKTPeDvv1IOJ
         hSgi0Nc47qaQZISH1O8ob88OTQqBIQktpY5g8BIs+diNK3iB1T9FiG7L2ZonsDEj1+af
         VidHr71v/GxwItDbF4QzlDXz9x/3LS9x2nInJkmI71JJz65dWkbR6LmiN3QYc8fTtkDe
         UqXbUcwolrqPWXnuDjK3Mg5AclrN0FevsbDpubE/bVhm7CTYIwq8fzEtaoOKWrJb8h78
         G9Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=8xeqYoi3VM1VGYs0pwr2X3YOLsVIQLIoLEODq+VG5Qc=;
        fh=XOU4eV8iw0tykXnH4X8CLbTDIHs53UgNNOfuCklbyCM=;
        b=LDP7FO3qVrkMLUQnzA0Hk2RnKOc/+wGTDHkk8jOovK8sOtQ427T+JcsWCL4I1w0ijM
         HHOAm+1STlfRf50C+coRP0ojncJ9SvlBHd+GkDPLQBLqALiRQ4FT/HAoTsAarRNXX7da
         DIegMttX2gYtN/i4eCcyV8Tw4Hs3lNFS42qX+qGh14K6Wkip6bxPZAUve2nbZE6nQ3+C
         vyFMmWknAhzhpF/avteoxLUIGWL1jmGLY+H315fYIMhorEFeOThIWyQueWLOd/rkIu8U
         YRWWEzAvChWsoDu28INLxpOaEvxLgJSdm+SKrmpD6SGwxC8odUkkTA83mKTIFVFZdT3l
         Q/Dw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IeJFUq8x;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745938554; x=1746543354; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=8xeqYoi3VM1VGYs0pwr2X3YOLsVIQLIoLEODq+VG5Qc=;
        b=skflDdqPAG3/vZWF0HROYaSmRBaRMzqeWx+etRPZxQ52vE09seu49Q2Rre+dYTuYzQ
         hC6lpol5WWktV2yfYAvcjxSQzz+Yz580NV/t05gyiWTTcfiwzqvETTk4QScR8L3yPSVZ
         fyRw29MoA42ic+qZ6aOwsB4RNBlTmZPPSLD1rdw45IM4uId97MF9J8xFO0l2yO+ATWBm
         1a8Jzne/jGkk8HCZfh9k2rEIMkVNo/RvpsZvxPAi0n/S5Mn1U1k42oIOSD3wc3dOixvP
         VSNAaQZGOfFz024JeYvnUbp4C+eKXaNwFtcfnkVvAqlxWPpTQjpk0DuHEEaldbIdsIBK
         88Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745938554; x=1746543354;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8xeqYoi3VM1VGYs0pwr2X3YOLsVIQLIoLEODq+VG5Qc=;
        b=FfLJ3dO7MxskhWysBH/8QZ8df8IaZQ5FXEjWHyjgY3apq7qbvX7KPJpMcRkNKAYcdV
         WlMidl2OxrxTYdoEfRQ6YFZtlmaG7eGCEqF1zklGPC6uPVMXU0f2Hm4+6i5nxg0DPaYu
         YhRIL/o5wQS9hbhM4FqxyHu3eLpyhzsClnhwL6VRGmBrZC8kNiVb3EOeAdQYqI7VAK7F
         qtQ5TUkZxArfMUrH3xrcv2g7+Ap6BJxHN0PtkQx5FrP6y1iIZ5SjhmgrDqr/1d4ZMeVt
         pUSqkKD4snYwTogrEA7m1SeDJi5BT6JjH0Vu0L5ijSs50jguJNQcGnUpEjD25Izz5g0B
         297w==
X-Forwarded-Encrypted: i=2; AJvYcCUfODRvTTmNDw1E7BR3TkzkCvlGQbW/lPf2KKU/vN2N51xfZU0GFztwfQ5Fhy5khuTHtIY/8A==@lfdr.de
X-Gm-Message-State: AOJu0Yzt0/QXkQ0bcZ5vKm/z+beG2Yo/kcSERlc24AQKRQ7VZTaOoW2i
	a1bEdeq8kONV+dTQLMvzzksXiBPA1i0ofaRjWURpQXF/30mqMEao
X-Google-Smtp-Source: AGHT+IGB/OpYZCz6eO17r2DFUrvh6qTryy78CcmuVmEi56dBtVcEywr8iYTAGFVztH7yFPTh8NWabA==
X-Received: by 2002:a05:6820:210c:b0:606:5531:d90b with SMTP id 006d021491bc7-60658e89211mr8311180eaf.1.1745938554316;
        Tue, 29 Apr 2025 07:55:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEqjoqJVORscPj8c6i7AUYac5Pug2K4shWQtPyZ9/KH3w==
Received: by 2002:a05:6820:1a8f:b0:602:2643:a008 with SMTP id
 006d021491bc7-606434d8fbbls94811eaf.2.-pod-prod-05-us; Tue, 29 Apr 2025
 07:55:52 -0700 (PDT)
X-Received: by 2002:a05:6808:3386:b0:401:e694:3e82 with SMTP id 5614622812f47-401fd70d9f1mr6345866b6e.6.1745938552643;
        Tue, 29 Apr 2025 07:55:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745938552; cv=none;
        d=google.com; s=arc-20240605;
        b=UL+e/cyj4CN5XBaVREgYGtjaiEqCq2dEh6oowiD8d66KKiTRczs1UisjqW4OGlO4Vg
         Xq0yQZVXp4noIzXexYJ5XI+1hR5yuYmXBXKgbnuuvAzWICDgGdo8es7j2q7kGRfddxGo
         tKqK59cVt19UwWgZEmiTZS+HYZIPEPlfbh+SHj06xiFGt3u8V73R+fg88yATSudaMAAM
         JPGUBvijBCaNIe9tTJieeUGUssyHo0o3DwrSXxI6GpF9N3HRVOG/OZKWQjRCdkzIsirv
         yQAdUIr8GZ2ZtSoPLQkcCsE0ePWK3t+kOzmg3+VpCkNbQy6VEZDWU2m9lPUoKevTO+wy
         /NeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=abZXiYIhyuThJEB7VGbgRvrvs81Nhn5cdsv1ckcJKQc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=c2ds0t2gc+CEL9NxdE248t3x0x9Gjcmtts3btZEPBUcbE+1wQQiAQtt3c3ae4uM4EX
         A09S35iqlG9bu+U2RgRouCzULaVJqTKztMPWDZb5MTNwkEnrTNPzsMA06kpL7xHg3GI8
         f5GMxewnVjGhT0/siJqmjhrA5lVMzQ3P5lAsJ9O56lr6D9LLHhUYzeuD9TCuC7bw25DM
         E47XsogOZDO1o/CUaf10ws0bhccObuGEo/QwfVnGSKRd0kfyor2vGQu39FdIsnXrcqOX
         UBj5oaQB8JMlBH3a7fWtjd0ipxXn0EH+lEA74I3n9M/p3Bn4UVogrgjLOBefYWeaJYlL
         YETw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IeJFUq8x;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4021292684csi72610b6e.2.2025.04.29.07.55.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Apr 2025 07:55:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id ADC924A8F6
	for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 14:55:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BA2C5C4CEF0
	for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 14:55:51 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id B5C65C41612; Tue, 29 Apr 2025 14:55:51 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 199055] KASAN: poison skb linear data tail
Date: Tue, 29 Apr 2025 14:55:51 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-199055-199747-uLPmzjtdCk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199055-199747@https.bugzilla.kernel.org/>
References: <bug-199055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IeJFUq8x;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31
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

https://bugzilla.kernel.org/show_bug.cgi?id=199055

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|RESOLVED                    |REOPENED
         Resolution|INVALID                     |---

--- Comment #7 from Dmitry Vyukov (dvyukov@google.com) ---
We actually use Bugzialla for this component, this is our up-to-date issue
list:
https://bugzilla.kernel.org/buglist.cgi?bug_status=__open__&component=Sanitizers&product=Memory%20Management

Mailing lists don't have a shared notion of active/non-active status, so not
particularly suitable for tracking.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-199055-199747-uLPmzjtdCk%40https.bugzilla.kernel.org/.
