Return-Path: <kasan-dev+bncBAABBD55XWTQMGQEGQSRIYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D064478D6EE
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 17:21:52 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-401c4f03b00sf27470215e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 08:21:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693408912; cv=pass;
        d=google.com; s=arc-20160816;
        b=lWzl+WOyS1bUj/60Iar0at+vGmv+0lnJWXKqvBnJWvBmaLtFe2SnCvmCQuHg5eLfBO
         22ypsZuXSbogxnjqq6u6Soi+vFmPS4nJoWqzmGQ2p6MMZnZwzMZMoQqFxQs5EgbHDJj5
         HaxHKI135RS+9A2aiWS4Da3pDDFWC2P7EGvTCsb0y4V6L7gvwJY0Mq1dVsRfem1/cYMO
         o2pamT9vkCyZspmKBLK5ilAVbMZjBzvycAiKHj/lipjfOB/lcGwL7S7NZqsoY+x2C98G
         Co7cSkHLvTrsXvXviNbM5HTYcBS4zc2TFT5HdZc6wtW+WSdUCIkhcq7CRMYyB2D0sIPQ
         7EMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=BaaH4gt/4Za76Min+caaXWZNFDmGSRnNcRre1FIrCb0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=HO/H33c3YH6RLejNhMo6rvlCLyMpPVno9AedwYEclHBmHNAyb+IUsHr0ND3CfDIw0E
         e0eLWYFvPHtXgyP8ZnVwpeD4dQjya0T/L5nD9CUGIteaP0fVgcpbJOR42LRwMsbmhomX
         3S+SGPUj30O6iio5SF7Y2siLGE2mGG/JKUxsEL4Res5mL/mvYf2BQ8hiorwzjrEs9lFB
         yMV+Hv3GfJHk3vOb2rHxwPDM2P0XUIWYCGZturaDKsTQ/IiRQpuccHgYVk3UtSuL1Pnw
         kCAi7hoqHZ56ps03dgi1gJN6pe9BDS5APgj/1NaJqE1nJOsxbaj9bw/lP6oZ3rtEFbYz
         tDuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AGUkxu0N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693408912; x=1694013712; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BaaH4gt/4Za76Min+caaXWZNFDmGSRnNcRre1FIrCb0=;
        b=HIZ/prDeyXe8eIRn74hNBdhBOg984c03RKdWAlOyA8GuAF5NWQS2+XnTi+qsFZP3OZ
         uUQ1w7aV2v4XmJcGBev6wAU323Rdj0QxhRpdmfRWXKg9NEw18uCckxyhyak7vI1RLz/q
         x848Yv8yeEE0q9XgXOdnY5JF3o1x+IT6weGPErjgfSsL/Em9XdP6TFAy19tjCEUR8DEx
         XEcJkZhC1Yr+/3m+q5teNmjGCqohfbHUiVs86y43uIpvd8EBl8UVaA0Axnw7XtCBaoAr
         3EIbIoTiqOoFowHLRXY7tCxfYxU+o5WYfymLfX+L1zJBXHwS6vwJ8JvqQqtrZZAswglT
         roYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693408912; x=1694013712;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BaaH4gt/4Za76Min+caaXWZNFDmGSRnNcRre1FIrCb0=;
        b=D0Clty9noVRd7lLTXz7KO8zbRWVPlWBIxkFW6IYXlHaFbr4K8AWSL0pSGTmHwciV9k
         2QdWp1Os3Z+brgEWdSdgEB6oOonRI5e2CEtGf8iHlg4jmcREppJjjMCFwnXyRuzD82hq
         HqynwOhx7hCW0oyB7nU+Ezd2qldqPoZm3sTWd0NRUsxV7kMGXiLKmna4XumG9Cd+ww/3
         UWpsx1U8S8DYp2PypKBYka24JYlXC6m3h9ndonZnPQxoMf4F6JepVQ+vivVZ6yqxS5Mt
         vfTnYxGk/V1LRgfsI1VmCDN9KnAcIsBRIR43niBIxeuT5k8SfH9b5d5h1mwweDlXkKhv
         gYdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzS838iRCh9KsBnJ0VAdF0GJ6jqDP6n6e+Td5ndtKCCGF2ejvsL
	SkeVh8sx211h7itBgmEuvhk=
X-Google-Smtp-Source: AGHT+IGb+4d4Q3fz0tzsdWSqSCEMtFHGie5iVh5SQ/2vPcMFGYM6mMRkPMLUN6CtiX9YsH6DKYI2xg==
X-Received: by 2002:a7b:cb89:0:b0:401:1b58:7301 with SMTP id m9-20020a7bcb89000000b004011b587301mr2223720wmi.18.1693408912002;
        Wed, 30 Aug 2023 08:21:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c44e:0:b0:3fe:e525:caf2 with SMTP id l14-20020a7bc44e000000b003fee525caf2ls9983wmi.0.-pod-prod-08-eu;
 Wed, 30 Aug 2023 08:21:50 -0700 (PDT)
X-Received: by 2002:a7b:cb89:0:b0:401:1b58:7301 with SMTP id m9-20020a7bcb89000000b004011b587301mr2223666wmi.18.1693408910716;
        Wed, 30 Aug 2023 08:21:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693408910; cv=none;
        d=google.com; s=arc-20160816;
        b=a37pjiwN/YO0lCG3ZHjuOWVQg++Y64RuC1NIjDuCfFdQXWPh0MWOxotFVElGQR7mOx
         JwdKj8l9M8nzJp25XonkxtXsdXZ0FWVbgfXzK5fJfKZUCUG/WbYhHWpJ17d5QDdZWIQx
         nJsag8qKnGICHDiy5IVmdy7t1PymCHYd6ULFzmqmqVUs5ZW6u4TupOmsFDVv1YXCpD9I
         ZBy+zj/+TChI4tE0H6dmGj2IenluYbRlSNm6Q/D1vqD6LyHiXt7OPfQPLNER6+Safnyq
         rQtO36mmCSmFCW5or4aPNQb33ST7rJt84woI/OmauNGasqkVK2kkX2gWyJpHhrhzKar6
         q/jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=xyv7r7K1ObyMsULlCYjxCpfvOnoI86J5PBVrjiis/UQ=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=kzm0pXifYSZfDawXxitz5uJ+pSRvj4tKatMHy5qK5292igDvM7eygS3u9k4bBZqlOA
         DafCUJVXmH/PyUhzCw6QT27n2e/Zo6lNflkMQWx7vvRkD4ZmWp0PwU90U9yhYlgpTNSu
         PB3dx0ZMyOY9Y8A/Cy5Cx5g37sCOXKZd72iikmi6fJxLmrzQ9kXJ236v0qNzlQDwGsyk
         AbKiF2mzFXmXl6BFXbThm3Yb8d1eV8OdIgbkg97h0bqburobzqucPui56aTx/oIt3GIE
         TxoifTqmqRKf9xQxYeW/29rX5vasPs+4JHVmdY687g3q3bd4kQhwhWXtvWwGCqKVq+Ak
         dTyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AGUkxu0N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id ay21-20020a05600c1e1500b003fefb9e1a6asi146708wmb.0.2023.08.30.08.21.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 08:21:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 67217B81F7A
	for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 15:21:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 34F26C433C7
	for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 15:21:49 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 22C1BC53BCD; Wed, 30 Aug 2023 15:21:49 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212179] KASAN (tags): scramble tags for SLAB allocator
Date: Wed, 30 Aug 2023 15:21:48 +0000
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
X-Bugzilla-Resolution: OBSOLETE
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212179-199747-3Znf1hukdf@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212179-199747@https.bugzilla.kernel.org/>
References: <bug-212179-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AGUkxu0N;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=212179

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |OBSOLETE

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Closing, as SLAB is now deprecated is scheduled to be removed [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eb07c4f39c3e858a7d0cc4bb15b8a304f83f0497

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212179-199747-3Znf1hukdf%40https.bugzilla.kernel.org/.
