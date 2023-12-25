Return-Path: <kasan-dev+bncBAABBRPXU2WAMGQEF2JRNXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EBD081E1B4
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 18:28:39 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-5cdbf9fd702sf4064332a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 09:28:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703525317; cv=pass;
        d=google.com; s=arc-20160816;
        b=dgxJ2+5q9h/3T+uI6Wcw5VwUPEmg7k4kJb9FAsFUJeW0kRntNh+PLWdQdrtkF7lXt6
         d8DftldIYH1bt6HiazluzIfpqcI7G0mLGV1570qEwxpWp/wt+0VnqvDyhP+iHIGkXtmI
         sBnBlsJTyLq4NfbkdENxhES96msbx8Qmaz/y2+/1QnWqR4VCtdoY+SQ3Oj0T0gVb+RzN
         NOmnGI6cK6kh1bxs5TQIAmnRspYrvZNRq2UmhuALrqv1pxpNUvUH9G59zbTKiRYblA9K
         ffeFd/ln7MfdP+fg506eJE9+8cyqc8yzeyrSEXYY4F662EHflo4RTSqgeWRIh0eaPkqn
         mEug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=TBV1wDQaOeFGsdejJXPgPFyxvyZ3n/zmGDQOsBA0q94=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=TJDLuNjjTDm+yeai6y77/d/vq3KD7X6pSL8Iw9tHwqRtmSFZ+EkOixcSYbNeH/eG5d
         ssYuzvG2qVyl5P3532n7iWNkm6wA2Pus0qcIatrGi9kCJy0OszLbHexuP2VOmCJBQEj5
         pHu/bB5nRejSLM8GLqbF0um8f7HfY0hk25wWB5ThnrO+My2pSkxLA6n2MwQBPPG/CFRZ
         eq5bUgU9eAig7LEbiB/zJ3fjVpmzrZ3kH0xRye0KPLadHygyuT/IVn4wRL+dbjpSm9E0
         8C4Vss3rkCy92yRviyJlwr9mtXywqJXTkJf2j6PsE/y9oqQDXczxQTkhVZrmciVqjGau
         dcXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZQZYiUpy;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703525317; x=1704130117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TBV1wDQaOeFGsdejJXPgPFyxvyZ3n/zmGDQOsBA0q94=;
        b=ED8EJQYdSwsLzSlkecKeEIsUxuOdkUOKicX+MLtFhV1TG/Vy2QHtwJsW6FPZhXD54p
         gM4YBiPKyl5j27qzheRHqOJW0A75RYYVF8JtJ+iojzIBVUeVR7GBkFJDJ1c4mJw1aTU5
         dO8/U/1XzopcjN/Nt006cIJq5PsTvj+Fh4bqHKEM1ugnGY6128yHtL9D5RBmlFcIG4FB
         Xboq6+oIlRKcudfVNNwcPjerXfpMGglo0HYBNzPJ6L6XBuC5Gu2YvTnbD6M0KCzPjorn
         CYyOZ1PpAfI8GkALyM8oF6lVjoX6Ni1JGQt2SEY6C8tXcJRizCe1lfBSIFEfe1Gc+Fbx
         7++w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703525317; x=1704130117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TBV1wDQaOeFGsdejJXPgPFyxvyZ3n/zmGDQOsBA0q94=;
        b=IUpdTfOQTpQ5eOy9hDUknTFgeHjkVERSN3rrZAqhXmFiDtfyJdIqTVdI65Dze++OT+
         A3qLeu02Uu3fZSIsPM5SjbvGNY9BZYyDeFMEL4bmvcW3fyUomHr7ilpM1cGUCafLeFda
         wU2yPHCN1utaFOE0nj4wzoJcslubqRgr/W7mG6AiZIBKoASpwkW4cz9ZXaz0gjtuQMA5
         FC1eb5JXfNlcGaCk+bIEk0lTlHgQwfb4beX1OO9Rh5BbR2xC5mqgmL3q0OJPa2n+dHLf
         kpgO3bBDlf1gedDji1fP/uqlXHuAdi2ORN8ultiUcgKbsQruaqtDjGFRLgHYL5KX+6Vv
         QGcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx1mR0zT2XbUYHL0OJojt9Us3oL3Q4A+iz/gaEIZ0QIU+TE8KSq
	cDrs21k+U6jZJwKlyBLv/F8=
X-Google-Smtp-Source: AGHT+IH3nR+h1Yjc5fWCmPPlmoVcFrZqzpwUkdxHGG9lASvjTAg30NplSPo9UF2tDLlf14l1T21VsA==
X-Received: by 2002:a05:6a20:f381:b0:18c:5b3a:1405 with SMTP id qr1-20020a056a20f38100b0018c5b3a1405mr7306015pzb.37.1703525317494;
        Mon, 25 Dec 2023 09:28:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2d0c:b0:6d9:b423:ac7 with SMTP id
 fa12-20020a056a002d0c00b006d9b4230ac7ls1016664pfb.1.-pod-prod-06-us; Mon, 25
 Dec 2023 09:28:36 -0800 (PST)
X-Received: by 2002:a05:6a00:464a:b0:6d9:396d:730b with SMTP id kp10-20020a056a00464a00b006d9396d730bmr6638602pfb.27.1703525316239;
        Mon, 25 Dec 2023 09:28:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703525316; cv=none;
        d=google.com; s=arc-20160816;
        b=r5mRG6AJcSrW3prBROmjS1iQPJgueGtjU6LSOCRbgYEP1JP2hJZtDfuC/vx/P5wuQ+
         cYk+poXIPLaGyMk64EFFmYB3IZSG9a6nMjxovE2zJFnbeSUOrBAW42/ZH/iYVCauW7I8
         qNIJW7uTqRVmpAqLSH2b1bsEs0D5Pvh778by2o+aCBXjFQ3LVhBCR3ZWwZ/IY9etVkm6
         6hKLjt9rknbAZd0hLZoJBmd+25Fy5wmyzMTrHwDgKWhjJiTpOf+D62AYQqXuSsIF4k5t
         r/uDICuOBMaAUinEnMgHapZX04k545XnR89T1Y9z0lfQwOe4Uhlh9x0AcaFURGRNhqbd
         B3Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=LpV2aCWPj3EO1q6j89pcbfOahTPfJPvQbjNX9qSf81o=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=m6+aNx9ojLm269cd9DV4SH/FHlva5nTKbgJrGwFgQMAOs0XHaVuAkRxUlvCrUg2Ic8
         U6K44mDDeGqMwKO7MqxTdWk2u295hvGsEJqX+bkKpDS7mrjZCrQPtCeBru0H5cPB9JsG
         r7GES5BYkySqNGXYv7WBsoN+MvqfdTx1lHlBI6oUlPEOYaUtRtDW42aM+cqRXdgStWrL
         /O4E/KI+sxL1tEGHXga8PmgIeodIfiZuPwgn33Hepo8HGf0eCEvsc+bWTZWav1Cg0nkn
         pPkorpkdYbLwnbARf1phgMXyYuI1HTcDeTCGS0aBBjbFFDBD40BYcSapU5+EvlVAdzG8
         ePOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZQZYiUpy;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id u23-20020a056a00099700b006d9bb8e9de6si119694pfg.1.2023.12.25.09.28.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 09:28:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 207CFCE0E7F
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:28:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 564C5C433C7
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:28:33 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 304EDC53BCD; Mon, 25 Dec 2023 17:28:33 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211785] KASAN (hw-tags): production-grade alloc/free stack
 traces
Date: Mon, 25 Dec 2023 17:28:32 +0000
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
Message-ID: <bug-211785-199747-e9wqVg6oey@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211785-199747@https.bugzilla.kernel.org/>
References: <bug-211785-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZQZYiUpy;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=211785

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
> Another potential idea to consider for #1 is saving stack traces directly
> into a stack depot slot to avoid an additional memcpy. However, this might be
> non-trivial and will likely require reworking the locking strategy used by
> the stack depot code.

Thinking more about this: this might not be possible, as we need to collect the
stack trace first to calculate its hash to check whether it's already present
in the stack depot.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211785-199747-e9wqVg6oey%40https.bugzilla.kernel.org/.
