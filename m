Return-Path: <kasan-dev+bncBAABBHFB5GVQMGQEOGC3QOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id D3EFD812412
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:47:25 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1d08383e566sf70615125ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:47:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702514844; cv=pass;
        d=google.com; s=arc-20160816;
        b=KwghIz6Lyp7J2eGDbL56gzklmRVNKPoCtpd7v1An0pZNxn9LlpL1zzD8bULuuLhSr3
         nAEbuycCWDJz7oh84ORDdqNORH4icVfWs/NVKmrUOP5Sa3IKX5oAlYQGPe/95k9QcxFP
         eYD5+b/tNeUIOIMeyVRA2A130eQR3r5O3PJBSx0vp+knH71ZO7rA7f+zVX/Kal7IDn8u
         AIjCiI8PSkvUMz1TrjEKmPeACG2S8HVAJXGcKBNWQKGn2sZBfz+OcJiFbaft+pns0Fsu
         Vk9z7Ktg40a3d8WPjduv/x43wlZMw1RWpCBOtSLeNJf6/sZBIwC2GkOD4D6VqZAvdFLw
         AJpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=m+P7RBg53mqcclGWYvyRmmB9ebtDRHgurjvk4g0oG2M=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=AbrN5qLWKp6HDBJWpWlw2IWn2Kog753ug439dtKukOf0UCxJBuhwDQ0Ag7NtTitK+j
         FCQRKpqKuiuDy/rX7zOhA/cIQN+qxEat09KYwCvrSo5LlmGRvaJdYTHRfbrEPKV3gTKL
         ZcdARsLVAqmrmQbLzjSDHCQ6lYiIdYXHQDb8AGVa2ReKttOMA3Y6WJyLzkX9aiuzCNjP
         tO5eSVD0kzT1QA9xMc6S9XPqohJtgq/Qz7j1C4OHMITeezsNy/bdu0ZOMRXMfJNqM5be
         Mx0gPQmNGjYJ9vrv2mmUa7PVRVbm4Jsj0Jf8mXMbKgTK6n3+LnrAoJtX1pfeIivzUEWS
         t84g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=F2CIdcYY;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702514844; x=1703119644; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=m+P7RBg53mqcclGWYvyRmmB9ebtDRHgurjvk4g0oG2M=;
        b=HrP9iH4te6m+tP69snknOOL8Lmpbs6dc7w9eMaN6x962CVB+sBqiEiydz+JXYfjyrG
         aKDjqq68J7nVfYQsXyfGK4dyd2/BUYkjbagVj4oKRupqFNthwtg4BEgSXbdN6svnmBvF
         +WkdRsjr9K85wmaGOwXxZgmp0s67aJBvayK5nNuR+UZo9SF1mlbhgn2oazyHbKIqSGPY
         bcx4co8JEgsm37ZS8/HXP6+Bif44ZFCa2WaedZnihFcWsEuaC72lpAsDhHw+p5o6YB/K
         k+gYFAIREerpCwQ8e0/JsUQH1+lxiCqU7beaY1hpSChWibe1DXlAxu9QgxqYmDeoOOtn
         3STg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702514844; x=1703119644;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=m+P7RBg53mqcclGWYvyRmmB9ebtDRHgurjvk4g0oG2M=;
        b=AX27uVy3uj/ZrG5F5Sw7xxrsJh/rAQ59Zm8CBQ6buqq9sTHQn/rtTB7MyA4D3QNTuE
         Ja70MfVBlA94EdbI7bB+q2ox4ZZAmQux7nS8PJwem8H0W0q6E8/kA9KihbsF997r2nAv
         rly4j9YFgZfZUHYpc+7Lw9GznIy1hZ8enb2ZIjDnbo82GpuBaGuDD83XpESRi+rfXt2s
         5dK5i0ZarvVpzZYN2DWkJ6qPSBSUbNQsrYHBqYaUnDvDPXAaq1fVGNPQS3e7VVwlV6HL
         XK6vgPf6MPmWB+MsNwNRFfxl2dV5VkTW2ne7jYYlhaPIqKqzXFjExzbfR+W/WksnXcuF
         2B2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YylQILniJDIEFXWQ2ojfGlkZzECXhB0wtCIxXBnMKzylI0bYI9a
	CgBF+2PGbGbEXKGrWzcFdb8=
X-Google-Smtp-Source: AGHT+IExbFP7ShqGSOrihCeRlacaS0NhQEm3OSDnmRSlsldMkEQcks+oQGmua247b3/G2OI6uBgEwg==
X-Received: by 2002:a17:902:d482:b0:1d0:7d0b:5571 with SMTP id c2-20020a170902d48200b001d07d0b5571mr10723280plg.109.1702514844391;
        Wed, 13 Dec 2023 16:47:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6646:b0:28a:b719:72c7 with SMTP id
 f6-20020a17090a664600b0028ab71972c7ls67438pjm.0.-pod-prod-03-us; Wed, 13 Dec
 2023 16:47:23 -0800 (PST)
X-Received: by 2002:a17:90b:3692:b0:28a:ee4d:20e4 with SMTP id mj18-20020a17090b369200b0028aee4d20e4mr1014644pjb.87.1702514843458;
        Wed, 13 Dec 2023 16:47:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702514843; cv=none;
        d=google.com; s=arc-20160816;
        b=swrpIHAOYlSxfDEJJSulWdDUN6AYUB8nanGA+GrYRfHEENlCcZe29BQlqeg2zKUaoX
         7ljGxkbZUzumcq7WyAY9oJQ5ph87zJrTCyMEUKLB6PWD5Tw1n7o9XeNbc7hCcL9EEOhI
         lrCgYeADcLtb6roET+g7c/6gjYQJkUGcmu3u5UuUdvwLsmN+tzG4sxRLltqvOr+LUkWl
         W+CpJRw4nDpbP3sTV9d7CMQFYC/F7hA8QZll9P+2ESoUwkHFDwQbjJN2FKhjEreO/uWd
         N37G+ng2ImCr7CSi9FU0nYXv1ssGWGgLmcK1Q3O68ywCK+iPiJUvV0WAxs+JP2ZQ9xSs
         ABIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=w8WDOlGTZJ67DkIB5HNfFvwC7TfTYx0EloUaXeAYodw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=RXLIlEnnmNmWQWO+sxLpSgMg/72p3o2oVUHf5sDakEZ5Ql7V4OipSRYj9TWy/P5QnV
         LaylnRtelZD1AKW2Jv1J0qln5mPVA7O6fIfUvbNV1SGwKWlwupkT+Hpusn7bKeospZS+
         TVmVx2jkbyAr5EQtrvW59Wg5K0/PM46D3Q4GcGRETTMmw9TtPgxz5ITXZOi8h/9SgKmU
         hYtyqwXVgWBdj4IQuw0rFeaCv+oG8tbyAAgVLts+CPAylvPkewAwXib9PsaZLTzD4Z0r
         6X8wdMSgOMSFrLyfVWaBnIH9CSqCd0BZmgjEkE1iSQHTOj3K6qIVEO4UgaXIGhVnWOQw
         mewA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=F2CIdcYY;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id i22-20020a17090ad35600b0028ab0a6ab92si575311pjx.2.2023.12.13.16.47.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Dec 2023 16:47:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C92DC62003
	for <kasan-dev@googlegroups.com>; Thu, 14 Dec 2023 00:47:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7B349C433CA
	for <kasan-dev@googlegroups.com>; Thu, 14 Dec 2023 00:47:22 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 64908C53BD1; Thu, 14 Dec 2023 00:47:22 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208295] Normalize ->ctor slabs and TYPESAFE_BY_RCU slabs
Date: Thu, 14 Dec 2023 00:47:22 +0000
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-208295-199747-nfGMzj2vC0@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208295-199747@https.bugzilla.kernel.org/>
References: <bug-208295-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=F2CIdcYY;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=208295

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Just for the bug record, quoting Jann's message in the linked thread:

> I've implemented this first part now and sent it out for review:
> https://lore.kernel.org/lkml/20230825211426.3798691-1-jannh@google.com/T/

Referring to "Let calculate_sizes() reserve space...".

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208295-199747-nfGMzj2vC0%40https.bugzilla.kernel.org/.
