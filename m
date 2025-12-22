Return-Path: <kasan-dev+bncBAABBSMEUTFAMGQECNIJCWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0329CCD5114
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 09:33:16 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-3ec7ae7492asf5318242fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 00:33:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766392394; cv=pass;
        d=google.com; s=arc-20240605;
        b=GU7kps3Mxx1355EL8fOgymaIwDdqEqQJV0TqHWmJl5n2JC72ik0ehBsSJKu7hWaGeB
         1kz+mKIalhdDrrEAUe+a7z/OfFDGjOsVvIv2E7hyPT0A07UfEb89IaEFVSjR1qKMiMNw
         2C9pflF0P1HbbLd4fe8y5V7k6yKSWskGoqpQ+lA7PX1tHHjWCQM/c+GDgTTQ7cGx25lJ
         C1AKtGTnKY3ZFE9vRTzFww2wFAmyfMD5iZT/FmWVbTd53zMgmzdZ2dzBmq96h+MTuYrG
         nMP+Vkk1vsRu2FB6TxKPe95HIJ8DzAEwhG4dW19EWbRr0cuTpzuUQZUNkz+ooqzAhOuQ
         Ctcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=LnyI9Z+85Q4Z84wHoIWJt6zkX+/4eXOr/0AuqGC50FE=;
        fh=+LSkS16SDxanQjqYKDiQKshyf2gl+sHQN01ScxGYr0w=;
        b=Potpa0w9iqJIK1CPMI7EP1btMy0rV7N7BZM6GkB40m+zO0exoNNGZXGsYbcjnsXLl8
         nrY1WrTjxO6KLLLsKPegb+I2P1RJw75A+th51D0Ky98+eduYlZvCWFNPDfCwwJprzusu
         eMVIMoCgr2Yr2mIaaapnVVlUwXVOdnuzMrhoZRhS0Ae3FUshKJh3zzXk5AYQnDimhz1X
         VVdcmon1kwvQjNk2VxPi7Lb0ZL91ptBbcL9NiXAli1NUX64LVPsPzf8goRIcWc6AhsZ8
         dPDZlNolbDaN+yBiD+/HgtUu1FoermD3+o6+7g9sxemc2Q+0WPCrPh4ixJy66Ai1px4u
         ourQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b5jAwFK5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766392394; x=1766997194; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=LnyI9Z+85Q4Z84wHoIWJt6zkX+/4eXOr/0AuqGC50FE=;
        b=PpAWBFn4d4oF8rB5BI7iOqCy5qVc5iwxF/0XMWkggGk0loZdnQgtaep4reeCPdVlxP
         Axysgmc6Fw2jr6/0zj/XO+K9656C90vQqjUtf8zMkYoI7WGcEx5+H/NfrI31qu9II7eV
         9mHB4fVbO72Q2CGvFHPBIdACTVTErLTMNBI+0vXYjOG2Goin2TYHeuvCOF/bxwR7GDnb
         lVjXJ5P+aMXZrMNvBDwVrzTxUiqi7qYUaT8REjxGUy4ehaxbD9TKIzEWKtCemlFg834n
         hJ+MZC6YQfIv80wZfhqYCj57sld4MCtUfv8glCUeQlXxYvuteEi/nRsCRG60a5Lejly8
         rXsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766392394; x=1766997194;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LnyI9Z+85Q4Z84wHoIWJt6zkX+/4eXOr/0AuqGC50FE=;
        b=IFrMhwaXxWOfoUxWOpc5W35md3c6YOK0C2xKnWDQIRyiMrlQBtuMcb+UtQLKXRHGn+
         3L+so7sXqaPC25kHI+PrxGn7zb0rkhmkAfoC1IOEIaTJS1mDgorVeJfsvpmBhGR1p+KR
         6dYD3ETfCXKjCf4JSCfZ4KzlJ+1pWb3ERYjmh/EwR8BoY3P5B6sobcaXhGs6B6YWf8MW
         8NRm1qlI8UboW2LMurEQNSqZHi8SluLr1LeP9JFa0ycyYR8kxN9HcNlZ954ax5d90yJM
         b909UWnwTDDYs15Vw8ETImE3m4dOUIFt7tLnNTGQQYD7BAuCRxnyqlZ7kjd4D9BCbNnT
         Us0A==
X-Forwarded-Encrypted: i=2; AJvYcCVzv7YbD+wdJx2V/BfdvCN/Gi9+o9H+6OJf8hoS9PapGAjeo2tz+h4NRMKPOqMkSWr4Hw852A==@lfdr.de
X-Gm-Message-State: AOJu0YzWVMVELvrCP0Z1zCd0Xb0okjtodADAP5JboCsXJgHoagpzAKq8
	3FBZ1Qsv7hr/AOexI6H7jlkbzigMFqjeqGYJAItBynIADtGs/93vo4ob
X-Google-Smtp-Source: AGHT+IGiDmhcH4MBsesrAE8TDSukAWynWOkUmiIyPUvHGmOouRsSqdUVC2HFYSu0TwjVqjxVn8lrVg==
X-Received: by 2002:a05:6870:249c:b0:3e9:7744:1d54 with SMTP id 586e51a60fabf-3fda58885e4mr5160076fac.45.1766392394259;
        Mon, 22 Dec 2025 00:33:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaWdgM7BTDfXOTuhV3rHNzQwr+h/GAShXQ29z0cLgIMCg=="
Received: by 2002:a05:687c:56:20b0:3d5:54c4:3245 with SMTP id
 586e51a60fabf-3f5f87f2400ls3968817fac.2.-pod-prod-01-us; Mon, 22 Dec 2025
 00:33:13 -0800 (PST)
X-Received: by 2002:a05:6808:e85:b0:450:db06:6079 with SMTP id 5614622812f47-457b20facdemr4588356b6e.53.1766392393492;
        Mon, 22 Dec 2025 00:33:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766392393; cv=none;
        d=google.com; s=arc-20240605;
        b=e5LrSGKog2jJ6/1kwJ1symXDMYCTS1EOkQY/FYh3msgkd0U5jkU6Kw/Ff+sStMTtOh
         AECg5XHlY4uiXzA6LQuEKQ2LeW8ubla0JLv7A9u7BwclM8/DaIom4vTj+qH0f+QcnJNn
         0apP/m/KXP3HtuyPv9gxgfOHZOW6q94eo6SBjo7GEHw7PyhWFkmZkyDARK6JSFK8a/OA
         iLJXnV5BqMiD/zOKtQLzqyCgNDWyYIZL4PW091NWvqmuAWdfcUwUMO5LRKCQhw/KyO16
         zv2XumDDJOHiMWuF69SERCIWftW9X8B/2+w8eNdJgxtCMDzObIzvYU4QiUrhsCZI12l6
         UMAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=5ZU05JPZFixg+FWpsHS3tn1nWvaf6dHltay8sRg8hpc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=T5Xpld9R3yrDt0fmOqoAsuad3d7alQ5SwZeOpRNyeKcR2yGtEE4Gz0bgjmc9Pwv5hG
         Qb2YrFckI2cuqsMfQdBTBp3dyu23P8aESfP6290fHJOulhGXLGQqgiFITJY2459SGjQE
         dyp1Kkp75wubVaN7yrwujb16hmYDj8MW6LT0/bn8AM0kHkC5d1CaS9yym0FqBsCrP0f3
         4ASaTnBZ8wyUH8jdQcr4Bg89nsn6+yQ/QfRroZ+dk24nIo2YMHayvw6eh9t3TQiv3iVp
         CtTZ3c5/HBHJPsnxMoD1XOKa5OynZ5rbER3UNGGkHdFgfJjfy96UevnNUGyGBRL1jkjX
         qO9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b5jAwFK5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-457b3ca1e6dsi259644b6e.6.2025.12.22.00.33.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Dec 2025 00:33:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B37EE43E0A
	for <kasan-dev@googlegroups.com>; Mon, 22 Dec 2025 08:33:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 99160C4CEF1
	for <kasan-dev@googlegroups.com>; Mon, 22 Dec 2025 08:33:12 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 8DA41C53BBF; Mon, 22 Dec 2025 08:33:12 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220889] KASAN: invalid-access in
 bpf_patch_insn_data+0x22c/0x2f0
Date: Mon, 22 Dec 2025 08:33:12 +0000
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
Message-ID: <bug-220889-199747-12tvfz6WBk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-220889-199747@https.bugzilla.kernel.org/>
References: <bug-220889-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=b5jAwFK5;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=220889

Marco Elver (melver@kernel.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |melver@kernel.org

--- Comment #1 from Marco Elver (melver@kernel.org) ---
Not sure why this was reported here, but it's best you send this to LKML with
maintainers+mailing lists of both BPF and KASAN added (see MAINTAINERS file).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220889-199747-12tvfz6WBk%40https.bugzilla.kernel.org/.
