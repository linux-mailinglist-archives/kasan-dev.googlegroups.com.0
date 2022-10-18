Return-Path: <kasan-dev+bncBAABBO7OXONAMGQE5GISXWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AC206032E9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 20:58:05 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id m185-20020a6771c2000000b00390d0a1217asf3689505vsc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 11:58:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666119484; cv=pass;
        d=google.com; s=arc-20160816;
        b=n+eNvDZWAW+Hlmr2hi92ND/7BxN9151IPi201mt87DvgvJkcY7+dPCy29LoaB5X9HO
         MkKQrqV/dzTXA4Ix2OppbMS1ua4aV8MGDves7poST6YLI04+tqsvX9uhjL/stWEuU+9O
         2uQhhpYwRa9IndUvFHr8F8Kw5/b/MWOer8YNXb8oEvTgVgHssmHzi4stMtgkk/O/6iSt
         23KfZXHq3H/HveiPHn4612eq3poWP24zP4titS/d2Kh16TQ50PI6khxtcioNSXSqTMtf
         cdsBQF9zUIiAwVsh6bgiL4QO9p4KPNDikQk3St1C8j9dD08frkGwTp6j74ggQ4n0QBTj
         23Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=kbPtxYOjTspfHE811mcXz0bRe6Nour2TvbcseP9c1KU=;
        b=CynGQ/+QHFhzQatjFLxM9dG1+21O3kMS3YZxaOqCKa0e7fZVqUiZbeGa+OFt8XKeZ1
         WTtf8+qCc+gwbX2sRIU4ITiprjjRNxfqDValSrZDJKQjenMHPHOmPmWkVLiEsHi9CIrd
         8EAVTW+RoHtpUWQkmqDwKGictN0St108K74DeLAFPf4oQKz/mcwND8zw9kSCYUegKudA
         4q2AYEIh1G1xLDxNI5YzPkcHa2BFwPA+QCxVJQXWClZ7jBHcnMIksDESOm1wh/VEZoIv
         lrzoxuSIl1JQR+QDm844AELAzTFBz6ietEglyjjlOiKr37LNJG4QZHbARden/BZvuJu2
         2KtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eZNaoU7G;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kbPtxYOjTspfHE811mcXz0bRe6Nour2TvbcseP9c1KU=;
        b=pX5GF4/+WMwYcDCMMhGCCaHyWWlBhFw2PkzVEYYRiDUg9nH6V8TH3gLfL7/bpyUYxN
         u6tsn8JV+CMWJwADFgVoIhBC5qq+z6JJsZmsLudYVjJAqm3kQYrpaGsNg7ZWbp78aJfz
         /LTDnM6lobENe/2k6Sb8ACvPpB0pNBCx0cHdzjrUpEo8dN18fmopD6nzeHLUTTR1zmG7
         Q8qMhkspMRX6mzEN9y23DRSClsI5a9g1xZOKAE79lL1SahZvuHgbdqAnkavE+b+HLDfk
         c+CS6V32r7JOj5BCeY+1cQ8qZBjQzpw88N2+awTEuhDI9Jyt7er8LTam7yKlXPMKr5O6
         zKxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kbPtxYOjTspfHE811mcXz0bRe6Nour2TvbcseP9c1KU=;
        b=gEkb2P+eYt/fUZtfoWAyhTDK2YsjmZtizASmzjyBW7hHLqHrmboYpkcVJjZCQCXFxe
         3XeULWkJ+4jEE1xn/pZ7sxYy323teqEfIbcMqEU3hj7NBp5QmdWZCxIdP2Sk95+kFr7a
         LiP5eUQDS4kYK8XCn4ZazK2fSZMXnkcUOvUV7PWGApY4heNhFcYrx62TckfVSxWyOLsI
         PZCnCDSmfPY5XNCt7vPdUZIW+Vo51tkP9idi4z03gbsrrMElqNrMG58llX8YJiDQKf5I
         MpFxIg7199IWhhY5vwEQLkQQHuPJIJn3KRWnQPc1FYxfkaGeJbfINd8DzmhzxPit9OUx
         IzyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1pPCPHEygbdvoW5foNJq2MAfU0XgeoqQrzwFkn3gFmQJ/uQgq4
	3OUR3pX7Sd2WeX56rlFzfgY=
X-Google-Smtp-Source: AMsMyM4YzsqKnqSLtmvm+Z9wxX4521er+3dHaF/XiBgm7DMVt7Fvvw/46Z3HZ467RynYOzlGBHiamA==
X-Received: by 2002:a67:b207:0:b0:3a7:a4ef:f42e with SMTP id b7-20020a67b207000000b003a7a4eff42emr2283721vsf.68.1666119484117;
        Tue, 18 Oct 2022 11:58:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2228:b0:398:7320:fd56 with SMTP id
 d8-20020a056102222800b003987320fd56ls3237763vsb.8.-pod-prod-gmail; Tue, 18
 Oct 2022 11:58:03 -0700 (PDT)
X-Received: by 2002:a67:e9c9:0:b0:3a7:d9af:bf34 with SMTP id q9-20020a67e9c9000000b003a7d9afbf34mr2418458vso.67.1666119483656;
        Tue, 18 Oct 2022 11:58:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666119483; cv=none;
        d=google.com; s=arc-20160816;
        b=BE1DNrDpKiZhYtpTR/4CvGjCs5Yutt/aJWLUkOESpW7705c2TGfTtfK8rQcmITS9E5
         b9a3CKi6vDjZ6uXThMcZFvbQ0M0mjb4LB2IpVQxIR8pzz0ZQLlDg9doy1tQEOUiHryJo
         qrUdlinj/elM/v3OoOJTvWBfIxmuF/9YVGbXJ1lrPrc/Bw5dCPuMlSmyeNOYRRiRY36/
         lUxqfPAY7V2KU6T5/azs6KDetyh7YYYWtiKiw+Ctl4zymQttUhW61nHppgOteuRyEjZP
         i8up2nWAkOnbyf+z3yT45N3xVchjl5O9DjxBcpJsnlHMR644Ze5ZgBm5reI3EIitSa99
         46iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=hlGm2FQQgq8WOg+uht9pAqsqTegTogPvkqVTH7vtfEE=;
        b=XuoCAC8Rn9fEGkEKrTZXZpD1KW2q27tCKB6bLnw+GKsEWl3U5gMo5uZRS/P6D5wRur
         /BCRiT01RXiAOEDvCNB1lAHmmpi+m+n+ulPp9dbyPFeF7PNyAWKDQ2v8bvCPVhLolTin
         O7bs8HI960dSUbZBEmnGQD9VllxCFpin5D3s+yRuH2vB3q1Q/e4yNapxXx7v0j0AoKuS
         FKzM1QBAysUhfzEUErXE2gmGeHgp9TaUXivf9OpHedCt4LTORIZOdF9JRII3XESMXdB6
         VZZZ5QvVx/WSCKFujEmmQmuCdXteGZ4PZ8FeyOgRyF3HVkaJdu12rdB735FswHwpYm1y
         CH8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eZNaoU7G;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id t78-20020a1f9151000000b003760f8bf2a0si647832vkd.2.2022.10.18.11.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Oct 2022 11:58:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3E62F616D0
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 18:58:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A34EDC433B5
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 18:58:02 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 92064C433E7; Tue, 18 Oct 2022 18:58:02 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215759] KASAN: more OPTIMIZER_HIDE_VAR annotations in tests
Date: Tue, 18 Oct 2022 18:58:02 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-215759-199747-uJs7zmPXap@https.bugzilla.kernel.org/>
In-Reply-To: <bug-215759-199747@https.bugzilla.kernel.org/>
References: <bug-215759-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eZNaoU7G;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=215759

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
The patch has been merged, this issue is now resolved.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215759-199747-uJs7zmPXap%40https.bugzilla.kernel.org/.
