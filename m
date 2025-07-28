Return-Path: <kasan-dev+bncBAABBEUGT3CAMGQEMIRWENA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id D01A0B13C4E
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 16:03:00 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-31eac278794sf1739392a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 07:03:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753711379; cv=pass;
        d=google.com; s=arc-20240605;
        b=bevWrM/jXlFkDm8gtVl2FmDfUScHkuqSIRacFzJuk5dEJUCCmW+73Z4Na4WIkmyq8H
         9rXJiyvTO7fFuBf9mLYSpYiz5dVAAngd6FQicek1LDlOVCWIvtHabkJNyL6Ls9xCqwHz
         w+cGrunuSsI7Ivqmqrx/Xtf8gSLsXYnRA4ZtMPeTvaNavAP3BknTs+lmbfG13io51RML
         iaKP59A5/xCaTpiCNXVKfrVvQTAUHBLOzQNJ4PZIx6MiTNyPaFPBkWQVDcI3LGhxVSS7
         iI8RWMgYulKY7bmXZrwa10OHylyPzAyHWiAYvxLYFixe3gxTIlcaJptRwFKoZYBBeNch
         oqdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=skjWe0sjsOn0ZVodb7Ik3xbmw6nPNvNLE+bnTrF7PK4=;
        fh=d4DHh4JoerMjmwR6QzVVneRakRIUCITGyBxthsu3gZ8=;
        b=MHZ3trYyPykyMrZMbZ8fxhsmuPwvF0yYmmgkHznmzrNevxpVnwaRDWxMwPrcSY1WGt
         3yC2Ri47n0RttpEVvAmvlSiXUk+zIUkGtgYB/ra22mqEHRVf/PHl2epLy5XgX9hClxlj
         PW7qoYautZ3GOnP02uAT/j4FNVSm1pvxvapdyOYAu/K7QckVtsdDod9szmNiLBpb+JDz
         m133jMZigN0YQ6OzifufaNsFZ3/0/AipPq+D09tfcQQlel9E21Rm87883hahDBt69N8E
         VUPjpzs/8svscf9ycspwuRLjXJ6xqyc6nyhd3I8iEBYw5EyW9T0JqnerQ5Bt6PM0FszT
         6MNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VGZXHOAc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753711379; x=1754316179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=skjWe0sjsOn0ZVodb7Ik3xbmw6nPNvNLE+bnTrF7PK4=;
        b=LmxMC/+0jBwJMFU6a4/jiGibyQwuUunJhJ9ltQZNP4k3agMziWJKt71G5sMU4A7/v2
         5YRB8nSlcZCwnM3/cOTZQCC31u+E9sDlvK70Z49NjstJoBF4Q7w2GWDoCj8ws0SW7iVz
         ImbvHy3buSlEpGEaxsl+PP8Q1rNGS9JlWkylUHqhHTydjSTX82QyNYsrRgGNp9rJJFjg
         GQfS2rLvhBz4zQ681mrjVEdwB/Qx8Rxkfa4BBpAJP6y5tP38yE8vm1RHe092zHeuvLgs
         q//+L87mSf2qyAQa6HkpSrAazuGPGzerf/Y4owppcxzqd/LhLWKYZhE/M2ptAi+CgvYx
         d8mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753711379; x=1754316179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=skjWe0sjsOn0ZVodb7Ik3xbmw6nPNvNLE+bnTrF7PK4=;
        b=QP0wDuWm8Oz59tCD9P5WYNMxDbYSeExNPfg8EkbuUyPBFKoFfVX0Ea0iSc5OkSZVsc
         ru8KXuOkevovdW/tbp1zxulUG9RdsLF8nWXELlkXZCsqgaP8OaCNiOkH+NIEsCyTfLeY
         srq7VApLKB2XAcXCCTf4x3GKcz/oAgTtkyYchRTTB7J8eDHBxyIdpzkyJqMX5poXJASi
         ATnF/sqGNAv+7D6txhkUGc3VWdVlheDF2+CIXOqbQihrkJmIH5gIhH60+XVUF2tPwbTf
         uvlYkDqPwwwbmRcfzXh4TVDza819GTK9Ns2IFUb1Y5ypz4PMPgLOGjrfM8zj2dlT52U8
         QIUA==
X-Forwarded-Encrypted: i=2; AJvYcCV0GN69MRu8JvymYskaN1e9QgfesZ9e1vTYtiX9NSPIlqqjGRT/GtDq10AvMXVZDAaCFji7LA==@lfdr.de
X-Gm-Message-State: AOJu0Yw1yLJdTiMPXdZIjNEA9GSWzX0QxnekUEBxtfBha32IFjv+9jM1
	PrnS0TEYZTExNlz+kLJ8SK5173qbbilY0X4Hkx41XbUD970uFMNN375S
X-Google-Smtp-Source: AGHT+IGWPQ9PHmmSpLEv3fkd2rfhAWoBq6H+ueM53mKzSrYR8P1svWIAiTRQgKpH5gpbRU2eZDdFpQ==
X-Received: by 2002:a17:90b:562b:b0:31e:d4e3:4002 with SMTP id 98e67ed59e1d1-31ed4e340a6mr6461584a91.2.1753711379023;
        Mon, 28 Jul 2025 07:02:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7F7NyuZ/r/qcaA+uN3ISUw7mw7oMwHpVHJ364v67mmQ==
Received: by 2002:a17:90b:48c3:b0:31f:7cc:aa74 with SMTP id
 98e67ed59e1d1-31f07ccad74ls602321a91.2.-pod-prod-02-us; Mon, 28 Jul 2025
 07:02:58 -0700 (PDT)
X-Received: by 2002:a17:90b:5806:b0:319:bf4:c3e8 with SMTP id 98e67ed59e1d1-31e779f9eb3mr18314083a91.18.1753711377673;
        Mon, 28 Jul 2025 07:02:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753711377; cv=none;
        d=google.com; s=arc-20240605;
        b=clFcBizFdtEpp1vUxs4GUrEV8Xu1NkCKuLwX6+lGTDnqGPlPp6t4ps/bWQPFJsUWyd
         1dtnrbBbigP+OkUTJCZCguc8bpbIh3fRsqNyYuwwIQHvOxbwUQxC5hqbQLVEMMUZBZ6t
         JUWBQosVRLIsbvOrJIueaNBygb8xPlicM2GN5OIQojf7E/NMY12TudawZnwni0xYESv3
         T2c+4oOAdNMxlcpxJu0m2ELRLHgmsTaqecbGUfDmIWnes1yYxO2E0yVn8a44nmm4rVYL
         8tB3G8iHYdlg7aFmBavdcwybHZHQwnbWc2uEg/5oucuhftKxwHS2m0dkPw3IWM+AK0Te
         1Vdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=MgDhUCXt/InWhaUrT94/mm3Z74+iuMvkLSu6RFHPsAA=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Hd3Vy9uzFJ4bMwAWDznMPRBkn8dTWNgqwqH6Q8hWiPwD/+I18x6mDqwX1dqUv4IFUR
         grAx6Sr3Wgm8/tWuNMnUj4HVRWpBiZOhSub8/4N5q9LxCP2m4TWcClZL4rOVMxQB7+cn
         LrQwIhnjjXq3HvY9bid77rSTV4dQJPhHRQB+AL5nWNsDeUH2qbcu6+JKv/yEQWsxq1/t
         NUdhCM8s3TDaBiJjU/Mzn/l2AbVfAOKA0JfojVjJWAQQmFFbQJUIER652l6O+OcnufPv
         PHrfTxf/QVKu2fa9Cs9i6ZWe/QJZTXTlV0m9/Gkfe646/n5w5tT3MTZf1Z55NTGrT1bC
         WgTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VGZXHOAc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31e834d3c63si255219a91.2.2025.07.28.07.02.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jul 2025 07:02:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id DD7D4A54EE8
	for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 14:02:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8B44AC4CEF9
	for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 14:02:56 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7C083C41616; Mon, 28 Jul 2025 14:02:56 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220338] KASAN: restore printing info about vmalloc mappings
Date: Mon, 28 Jul 2025 14:02:56 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-220338-199747-WAONks9ENp@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220338-199747@https.bugzilla.kernel.org/>
References: <bug-220338-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VGZXHOAc;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=220338

Marco Elver (melver@kernel.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |melver@kernel.org

--- Comment #1 from Marco Elver (melver@kernel.org) ---
Added back by:
https://lkml.kernel.org/r/20250716152448.3877201-1-elver@google.com

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220338-199747-WAONks9ENp%40https.bugzilla.kernel.org/.
