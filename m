Return-Path: <kasan-dev+bncBAABBQE7Q3AAMGQEEDDFCUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D94FBA92E62
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Apr 2025 01:33:22 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e6e4cac2fa3sf1649140276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 16:33:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744932801; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ao+X1AzE5L4+izH+47QJpWTxGv/hRXbLFUI/3GANpIOJYH7ztuzh0fvA3wNh2T0YY5
         aJqOFCeRbfjFb2Q73gcs9qtgVxleKftl9oIK4UsEY7G/PmaWI0jbbx9XQlDK6pemkj1x
         /yhYSWgQq8H4zJUz09GdGclb6qnecmoMXn7kkvtK5cL/jxe98mJlbdjselzs+qyWCPyo
         /PoCbqB/aqNmhuqmYU3KRKlfMiW/mzQ9CvpePQdyWLc1yicH/psOE+abbDTyKM9EQOZB
         nzP3upNmSE94H6ne0xf2jWVH+FxkyqZT3NC4n1+4QgvLLdCZPOwdnxuTYcku2TW4+ykW
         uqpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=TwiFj/wRyaI4lJQd4oS00hq1DhfdpX+GyMdzz62KaxQ=;
        fh=gm5594YyxK1mmxGZrWi7hZOBY4JwMGPcVzZa742E3u4=;
        b=VvIN3m+fsZMS3b0WE7TWrVBQY6PKVsCAjd+8aL8Lt+mSrD1BQYIceM3iN0OnVleCwb
         5UWlVioApgPV5YF5Vm3WvFqdwphf714AOG1R5I18pqYryp07r3pOUlAaQ+SmfGoKmX3J
         WlulqEhXxH++Q0S+zx6CmJZ4aoWsgpl2VDlqdx6hN7cVbD0FUQMgSfSwLt3al+hwv0rq
         fI4edkNYPXZeGmoWCb/wVbTrC3vZrblrLSFDz1LsIlwPgfESwYsG9wGsOh8fXktjnDPv
         R/Nw0QbYE4jHKknja1uOVAdEFdlhX0Fcx7A6LiK3+gXVfyT/pThBosv2ahq2+VytfWjK
         KVMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BvRl5wzb;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744932801; x=1745537601; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=TwiFj/wRyaI4lJQd4oS00hq1DhfdpX+GyMdzz62KaxQ=;
        b=NJDZ5+97CQscm98xWjKtEbRi/ZWztHs22HMA4qP0nCt5mxdE+p+9uBR7HP9s4Lp0Dc
         vKP+4/pb/B4RsykufERrzbI5Ui5dD4AMLl4/aWO2XanFyPtoaeZfam1tRE7uQrHqi3CN
         XSZ6QadhLNcWv8+MRhVr79/xOyjUM86OUhGsf4Ttic+l3Oi6lPE1lRrvDwNZqGWWvkQs
         PiXwNseiMYaZMgmo/1UbyHr/KAIXfaJRcgbrexGN0KBH9U7W/7XL939m072kIVZB9nFV
         tWA1ZzsxrVWKol6WEYNtUXxzPY854Y/aLeiAumxkhWzGdWeacGKuQkmvTwIdmFd5kzuv
         vWYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744932801; x=1745537601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TwiFj/wRyaI4lJQd4oS00hq1DhfdpX+GyMdzz62KaxQ=;
        b=gvXuVYJwFkeYOfuvnsG0D5QrscCGgZRzgmLRadkc6D76i2dLqp186e3Y98MFIOzIj1
         /xn9i4X4jIFjJywekDk46Pt49pDMdgjo4xRAOL45SM7Zp5xRIUuz7l8tXlk76YlAcKUj
         YcqBmyPGYOLLOOKDwz2fheIMF/RTFYYyahPRij0/5OQxUmKsa4rJ0Qs6ATSeiOKKR+8n
         zUFmL8vqkMYzqkfwrjZmTOz6fERWQn1rh5Iwqo0Gu9OL6SGvB/Fw4NN7JHZZNCHznMH3
         zkz5lfq8pRPEye3JSOnFgqeEnxFTsgfo3FSIhsnhhJr8lvC6uDkCd0R4Jw2UUeD1RTp3
         sf6w==
X-Forwarded-Encrypted: i=2; AJvYcCXeMwWLbBocp2eR30M92/UMmhDdjwXeKOJ8jMerPlTH98MQ3I609rPMiUcP6nLO6M2FEuFZzA==@lfdr.de
X-Gm-Message-State: AOJu0Yyc260lLZ8/VRvnfFyKJs3kk+o4QRW+o5rJDWy/zLylDTeW/oZn
	cga5ZMjepzPZhhVHjnhgACal1kVyZhH2vTn7BNaott8Z8ArkK+3u
X-Google-Smtp-Source: AGHT+IFEKMhofAaQL5r9d1rPI2f4M2iwhQ+g9c4UlNjviQ0oNLhzpGqXRRcVPnU40336KR5dUWEXRg==
X-Received: by 2002:a05:6902:2681:b0:e6d:f048:2b65 with SMTP id 3f1490d57ef6-e7297ddcfcbmr1098996276.21.1744932801156;
        Thu, 17 Apr 2025 16:33:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALjipdpLbid6BVHdZ/A8ENXdkMEBQW29GyG+Qf9/fwFCg==
Received: by 2002:a05:6902:3d2:b0:e5b:3877:6d59 with SMTP id
 3f1490d57ef6-e72802fac99ls640043276.0.-pod-prod-05-us; Thu, 17 Apr 2025
 16:33:20 -0700 (PDT)
X-Received: by 2002:a05:6902:2186:b0:e72:6ada:d0c0 with SMTP id 3f1490d57ef6-e7297d8ef5amr1093314276.9.1744932800204;
        Thu, 17 Apr 2025 16:33:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744932800; cv=none;
        d=google.com; s=arc-20240605;
        b=B0jmkD21ufB9H5Q5yHUWzGTAwdsOFRPT69b+zaCY+riyyLTKIpevlVedGvTeSnAmEY
         TiFsRbtAzWm558k23uFpqoi4mW00hbtSCOGULcDuyNz5LR+d8jpJVM+GIxRkgMqwqsiF
         v4AkIzMdnkQWhUmiB8aZopb8uI5C6LflYgl0uOQx4df+gIP0YxMsIooh8cCDO0xuxv9U
         hBD6hb+ybbQkw2GZBlAvFYnBK1MygnQgStfIX1XZsdUMybyHhwiqDbK6UvI+GABxviDe
         LkhKrICKTiOekCWxII1qbHVA0KAoCxtYi2eId5eL2UdL+mbtjI62MOEw+yLUWVZlCP1k
         /MWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=5rcF8Hbdrq4jvTNz5eL5CmQxRy6crQ8F+ecYT9YMdaA=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=kMpDuTexCSgjMWAIeoQLAmAsyzQqRBq7vhcCDp56cDU7/2zcaCB7AVIZctObVCKZfT
         UHnehkO3IA9Up0jxsdSaY/iX7K7lVYjYozdX+OShBul3s8O5OLohMpUooZOvEJ5kH7VC
         WvOd/GmGIkQZ/N9Mg2EFAolqAVKPPf36ldyywepoIguiRD7qCKEKj+RghsoaN2HsnSPZ
         Bg7NLBUetCPCcVmcbFbzaJ9f2uEwJp7/EUoxROwQ8pPHsp9CBzOF6uGb9hd0Dm6dEoQW
         m7BMdxhJtDsPvZLV63gBngZ4Je6Le4bxI90iv1NIs2o68T9mEEFMU4ZnHTFNA+Z+dt5v
         mCrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BvRl5wzb;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e72955848dbsi47087276.0.2025.04.17.16.33.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Apr 2025 16:33:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 1512F43A30
	for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 23:33:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 00233C4CEE7
	for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 23:33:18 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DD22AC53BBF; Thu, 17 Apr 2025 23:33:18 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219800] KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
Date: Thu, 17 Apr 2025 23:33:18 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-219800-199747-tEvDQVWZij@https.bugzilla.kernel.org/>
In-Reply-To: <bug-219800-199747@https.bugzilla.kernel.org/>
References: <bug-219800-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BvRl5wzb;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
HW_TAGS is hardware-dependent. But it depends on MTE, and MTE uses exactly 4
bits for a tag. (SW_TAGS does use 8 bits though.)

The change you proposed is most likely what we need. Just need to test it (e.g.
via KASAN tests) and make sure that nothing breaks.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219800-199747-tEvDQVWZij%40https.bugzilla.kernel.org/.
