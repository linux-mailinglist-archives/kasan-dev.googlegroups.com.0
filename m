Return-Path: <kasan-dev+bncBAABBH6C7K5QMGQE7HMRY3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EDD6A060F9
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2025 17:00:33 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5f368647a20sf11893752eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2025 08:00:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736352032; cv=pass;
        d=google.com; s=arc-20240605;
        b=HLUcxq7FNvVDRdM1n6WlUx24BWxz0So9o2tCgSFrNFQ8cdZLtVUe45yKgO8EmVSyjt
         hHXLyDOYO7jzN6sLEWjGU0FHMhoY+N+AyZbAws0umy7e3hdxE4dLwIb8DPsb/4psvsLK
         5160Rcsbxi8uSu4/EHvpWdkBULFzCD4vwAMXlApCe0hMnKZbFmDauOTbKUHEggm9No2B
         /5yKbzCSGCeTZPyOXLj1ze8uUpSWqxA43NPYG7gOmghMzYBD7eq5WMkrirk6Mw8PIAP9
         CH0pd8n1qP3CaqSYyQPbDQlnr2ll9ro/zL/eRM4smcxL4E0r1lPsqBZk2ojXHaIIJr8a
         bVeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=xnKHgcsAKTqctG2KXqo+4iLmGpPME8gLxjdNwQPg4E8=;
        fh=mLCeFNthLdnQjH3xZX4Js7FXsYkTteRxLz2fLdbee0I=;
        b=kkxEWYbNVK9yb3nozNttlBskRZAVelLRZaZ2FpjOUeP/wf+W4dUYK0kQWHdqPZF15U
         25j5xnCIw7GViqmywTXx/iVCE03uENOcXtF85UgxqEFmRqp7RCqhmrKF3WArGzmaEpHL
         r05UqT2XPPZl4SUF9EllaVQ8/Rnnrtq80eQwOerXaawjHz3XJQpD+EW5aio6zJgros59
         bYL8RjlBU29jmTbngpy95wbhOSFCWpFgfl1cgjYUHhJuXTpXK8vbtprEJe+77tNUWQpp
         5UUioIeFC6xlJqXx/YBQ6WGHY6+aoUWwWoHgwBGGEsHHAQF8dS/FHiB5c6vp+K6Y8Yn7
         wcUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vdhex8hE;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736352032; x=1736956832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=xnKHgcsAKTqctG2KXqo+4iLmGpPME8gLxjdNwQPg4E8=;
        b=iEER/XBtCmeksvgwCZddHpkLdAXRmYxu+cqrojooAXFfuCbWmkCd90fVbTKIuOX+Jq
         5oFwu7GZDKZpUiKw9DCyykiKqU+THKQaikWvCMdnT3VyD68BJX4WUxbJefYeU7FJYNsy
         6m4kZbqboxKURRXeRmcbDuW1QQ6yqqHLAn1Z45xAMlWrFys7OlcEebUNcNc+HNUc1pmw
         tE+aRia3ktDS8IvetlULdDBL8GYmzkHPd8mjL2cxjFYjxoWqexJDuGl8HFOcvT5W8coM
         ttJh9QKQBsyeYgbdbAaokt4nx2kya7iK/OI392yBGzmkO6xqIDv2zBZMnkKasrD2r6Z3
         YBcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736352032; x=1736956832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xnKHgcsAKTqctG2KXqo+4iLmGpPME8gLxjdNwQPg4E8=;
        b=cvoWRm1lhG/mCFEz/K4VA8P+gNhOPY0DB9DyLsFlT3uAnuJPbeTDTnt1ZA4n7eqwKy
         5BdBwPHGreqeCD0RX+iP4jWKYH9ZVSLJSCuDJ/k2Lsn6aCpkQZZt3po2fEY878IAx5zt
         NP1hf12FJorom0/X6t/IHGUItdcDrDgtah+jdwGfmOMeE++dayJ5hX1gRFot18+WkNsZ
         YGp1Ai5mSiBGzl40gUnpTDKvkwjGTs9ooiVy1rkZmXBYCoquMrZYrTfRMsUiKx/PPvTE
         Ss2FMlotLNsuiYW3bWc10fRtDDdhd+gUhw2EVf7qyZaDrOVM+D6UNbgvBRqtCYb1HrqA
         8j6A==
X-Forwarded-Encrypted: i=2; AJvYcCUCix0qeTAhtdXJdWH3k218Lre44xRzO3gIlXQl3q/Z2CdeiV0H6b3zWNJiaxLtHJWN725cOg==@lfdr.de
X-Gm-Message-State: AOJu0YxulONF5tGdL7QWiNBu56zNapdui0qSr0OkpHf5qYsMNIRNOP8a
	cougKeTfc7U4WhqqwVciZQgSbTDpfHSi5XFBzdWsFX/ZtS0s/GUv
X-Google-Smtp-Source: AGHT+IGGGrSbRfUKMfdKyUVUdMPT0LPtT4s6/mYLqvVqQFezs51gcNTmVRyYiTSLc1OYN7Ewh0e+DA==
X-Received: by 2002:a05:6820:1ad0:b0:5f2:c518:bace with SMTP id 006d021491bc7-5f730909231mr1759783eaf.3.1736352031654;
        Wed, 08 Jan 2025 08:00:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1a89:b0:5f2:afdb:e681 with SMTP id
 006d021491bc7-5f880727b4fls2719eaf.2.-pod-prod-05-us; Wed, 08 Jan 2025
 08:00:31 -0800 (PST)
X-Received: by 2002:a05:6820:2215:b0:5f7:271c:bca7 with SMTP id 006d021491bc7-5f730949d46mr1238761eaf.7.1736352030813;
        Wed, 08 Jan 2025 08:00:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736352030; cv=none;
        d=google.com; s=arc-20240605;
        b=bon++IHSD3WzCMsIlK7DBMhMMtfolsMmTYbpeJ7Uwl1K+NTvuFre7LzRXKOlYdPcmg
         TXX9xyozBCJCrJ343KmybjNrrAklOxAphflkQHUMF70LBfhlRXy9cBonqDC8sEVGbP81
         ZC/aXcxjkMPyrLKYLl0Zmf+UeaU5lECN6Vm/zHVH5G8bwcxsW+iWXLA0vuxArsESUkPK
         U/T+yThgwdhLAJxNl2+PLsiJ0yrFFJNKjTZNZxxwXmBpcCma4qHAXiijtTyFIsCs4mL6
         wtSd6YkGGB99lMp6pDI6kimEIrZEUk17EtNCkkSskfjv2kGIXdxL9f/G2YAUAzctX8gO
         e+Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=usTBqvAfRqah3dpx9gGE1VAzSfintSE01lcfhKHjm/U=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=hxIG9K2xZHjE05Jb1DoMS9FyKile0dh0AVwt/52m6YVjadBMZ4lKBq/iPZUCipWncv
         QbQrl74SATsjeIRmEJaZsNzmh9C7lMVz1V1+vaRJc3fAoFLKkEsvtS3kxaJc5Nfgvl8A
         sc92pqDWOnbkLHsQ/moUP1S/zcuzmHKJMbO0ompxURRomcFQILL9XX9BFfqY4NiY6X4q
         KN7pAKu0GqrSVdh4e0ii0DPdhke5B3n1eQpmBPiky5Drvav3eT+Fe7myOOm2vDO6w3vL
         pJloJ2USPmi+NGO1JYooH2UPoSft6S7+GhBcVbrEi3uItmB0og9G3JPJdkUkss8NKnfX
         TsYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vdhex8hE;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5f8395cd75csi31827eaf.0.2025.01.08.08.00.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Jan 2025 08:00:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 16B72A418CD
	for <kasan-dev@googlegroups.com>; Wed,  8 Jan 2025 15:58:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 60F3DC4CEDD
	for <kasan-dev@googlegroups.com>; Wed,  8 Jan 2025 16:00:28 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 5971EC4160E; Wed,  8 Jan 2025 16:00:28 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 212479] KASAN: tests failing with KFENCE enabled
Date: Wed, 08 Jan 2025 16:00:28 +0000
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
Message-ID: <bug-212479-199747-BSuUWKZl74@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212479-199747@https.bugzilla.kernel.org/>
References: <bug-212479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Vdhex8hE;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212479

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
This issue was encountered by kernel test robot:
https://lore.kernel.org/all/202501081209.b7d8b735-lkp@intel.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-212479-199747-BSuUWKZl74%40https.bugzilla.kernel.org/.
