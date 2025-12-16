Return-Path: <kasan-dev+bncBAABBK5JQTFAMGQETEUM2YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 893B4CC17DA
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 09:13:33 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-6597c514eddsf2150675eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 00:13:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765872812; cv=pass;
        d=google.com; s=arc-20240605;
        b=O/bQvRmI18rtS3ftbmM8oziXvADw/iUXqOwbHo72HLiC0IOse7Qp9G1uSEXj4vZljs
         gqngJmSrk2eP3In39vbAUnVnbGdTqD7qfVEvLPxvLTzzs15+iYpaNgZdkR5LskzyIaei
         kvPRWrBRp4Ci8e3jNnobXnW9UNo+afrEtVVk042sj7am7qeD1PKhA3GrwlQ7hVJ7AyJh
         SMa/rf5Q1z5bJcZo27xXo0qzerXE/cADV1TPyVhNjf9Lu7dMV4hsE7jwCi7gqCtj+qYe
         zXKbtPs4ptPHEgXeco51rhxHJgevZRDVuIS7vlu3dVYtkt0jqEEJMHqLu0Hn/7gGhMo2
         qMZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=slZHQvY6aXNT+Rpynd42t7nLE/VVrJ6zpv1yrfngHA0=;
        fh=stM0RkhEzKzFAHkXzDzPqQdrUpVfsT5b2WzyJuKC1WM=;
        b=HfeYzS0Obinh2GPgZsn66GK7qXWLj+nA/0oq9t7WoGC3HPB+F3t0N05yCCFG2Sl5Ft
         aNGHFWZ1OmpsIvNz5FkcmTQJnBBUGoFhMm9bjkjTNpmTCmHlSSVsf+4SVMu0V9b/D3Ui
         Zm6yXukYK1gUYUWFMXWlJySZXkNJLVNY9pWMSW0KpVAdSK1g7zZtxumnIlTeFrT9aDKZ
         vxNs1KlFB+6Hw36SIuJ3dmJlqEhPY/0WnULSBaOR/1eIR7eyayUklTsYLeMvl2TZcC3D
         q7JBR8kTJGy3PDJLccjWAH+gY3hvVCPGpPwGLmLSDfVc2habor9RCAUcLTistynN/Nwm
         WGyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OhQ1GvW7;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765872812; x=1766477612; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=slZHQvY6aXNT+Rpynd42t7nLE/VVrJ6zpv1yrfngHA0=;
        b=pxNuLLC0+bWZJ8+JV515KNFFiM1zmIY6vFqDs4p7npabQTjeDPQ4n+g3t4lUe8r9WA
         JLVxq6Ad7JRDPbJXcQNiaQ8oRo71MOVBGEGyB1lrC3kVBwv5dBON1Z4oNdG3xNfMCKGS
         leArga74xqyrBVeWNdJXTeoYoKF+8vF5i3YLM8/TVBe58QcnjoixnyKOZOIcqaDuYEbP
         hv60KpshY+kUME3YMvnIpwIvoZmfNhYzMSIqHrwXTP49MSBNR9YNpbWTih2r2OCOaJxe
         ZnQL/tjnxfMBqxdc3hFs42tozu5n6F3H417OjNFTogTbXqxdkDPwUq6huidw2Y9pHfIx
         +u4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765872812; x=1766477612;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=slZHQvY6aXNT+Rpynd42t7nLE/VVrJ6zpv1yrfngHA0=;
        b=fle8mJM1rvO0hNpAIcYeZhsM7bmGyd0vxLwtqf0G1414GhYelZDKzSNKSeg5LslD8U
         39TUqkVos50eduOWWmZLBNI3LBx7Yn8HW6RwvKmsz9KTcjFktF9fqMfdn0keS4KfRszd
         9Iwc37jpKPRQl9/br9mmlHx/OThye9nA7rooihpk8Yf4r+t6HdV+RihQ6JRbJpsxOa4z
         8sN6p6W7u1ORH6SQpjmY+AKNotrDedXtjt1R4s0yX+reQRUPSpIP8ft+M6EqaD7vQ2XZ
         NHRmTs8QjjZKDsAZMWOUmTd7bYJkGmtZhEpLY4GYW+H4d9t5Ues9W9kbUH+TV6mSLY32
         If0Q==
X-Forwarded-Encrypted: i=2; AJvYcCX3zCgwzMdjf5X+CWjcklZZUH+OiWbrEEbm74em0sdoAw3uCkp4tlx6sjLIJ5HkLAGu6Leb9g==@lfdr.de
X-Gm-Message-State: AOJu0YwQZ3cZchwgJwMrovOBZY6FmA3VTnaKol9Wj1Nf+boxGFLoJVXu
	IIB8lJMy92dE6IhfLJehFKJIY4g0sl9a1gjBlcRr20ELl1afAUwENKCH
X-Google-Smtp-Source: AGHT+IEdw6JAB8HlavjEpf4jpyw5ZVMQKevRmfua1YyxpHh7XyutTxjnBW3fbh3SBiKxVqcfwmM1Vg==
X-Received: by 2002:a4a:e917:0:b0:659:9a49:908f with SMTP id 006d021491bc7-65b450e91a4mr6075008eaf.14.1765872811892;
        Tue, 16 Dec 2025 00:13:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZrfx34El9f9hcz3+pxrAqaWTLvX1630vt5mZvYml1gMg=="
Received: by 2002:a4a:cf13:0:b0:65b:79c6:1e36 with SMTP id 006d021491bc7-65b79c62118ls345837eaf.2.-pod-prod-02-us;
 Tue, 16 Dec 2025 00:13:31 -0800 (PST)
X-Received: by 2002:a05:6820:4df9:b0:65b:3641:bf72 with SMTP id 006d021491bc7-65b4520e906mr5487349eaf.68.1765872811158;
        Tue, 16 Dec 2025 00:13:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765872811; cv=none;
        d=google.com; s=arc-20240605;
        b=YNEZ/shgey/W5Iv+sGX+o9xV4Kck5dd4+mSz98WNxIuwGaEufx30FcMewpfHYmMLH0
         FFF5GmSQTybgxmsqZ8gizFXcI5Dnhfy/LduYNQdngTdsVJSs5ll84TX9EH0E63QdMjAP
         EsLWTcQ+W9HtqMqyIzTFFn1HSx8G3Xp6ZgJcy0o9JNwZciGBkj/UavipQqnujv//3mVw
         nKGXFPCm5Okto7N4ZC88jCK9dopnLjJOdlanKDeoDAR/7Saj9Sx7BEK1bVFKORQER2fc
         F5p4tXbpdbj+e/lvlLE/Shr3VTUYjqmkXXGHOf3Slk2XAkWZAXlXwwAjvm7MMIGe6zei
         o2dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Fb/gVt9eMY360FO3TC+uuoajk63mA6aFceppQp8zhxQ=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=N7zmyGKXrCprV5S8c/KRoAJ53UaV5Nvx+zAvEFo8pzxZlc07koB22R1WQBfbjIu1aM
         CNHxJkRW/ilhmaCSxenNJtNOoD3cilgVsMHMjlJxs1gGQ9BkfIRNYt78z1Mhgfi8WLOk
         DY3NZa4Byv4S0N3WLQ3lG7mOFQbDOsG0J1btTMvtzPJ95L2zadn27yxH25dJ/58Dx7wT
         +5EarLcqvvndHWNtUNBpEsuzg+s023A2QVpb0wjBczgMm26PGmP9HvwjBwjSlOmFBrXz
         rms0PtCMLEn2XjDo5xrlml7rJF/PQeU+uSa8KGX1mnKf053DYWnYFZH63geWyL6UiWeW
         uHZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OhQ1GvW7;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-65b64d8ca7bsi169983eaf.0.2025.12.16.00.13.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 00:13:31 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 58CBA44195
	for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 08:13:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 3E243C2BC87
	for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 08:13:30 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 2EC02C3279F; Tue, 16 Dec 2025 08:13:30 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] KSHAKER: scheduling/execution timing perturbations
Date: Tue, 16 Dec 2025 08:13:29 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-209219-199747-WWt4v22jpR@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209219-199747@https.bugzilla.kernel.org/>
References: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OhQ1GvW7;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

--- Comment #8 from Dmitry Vyukov (dvyukov@google.com) ---
What we discussed with Steven Rostedt:

 - market this as might_sleep debugging facility
 - split might_sleep so that it has a function that returns a bool, or add a
helper that accepts a bool flag saying to WARN or not to WARN
 - use this predicate in KCOV
 - improve might_sleep predicate to include SMAP check/etc (anything that's
missing)
 - the hypothesis is that might_sleep is actually buggy (and without means to
test it well), this would stress might_sleep predicate well

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747-WWt4v22jpR%40https.bugzilla.kernel.org/.
