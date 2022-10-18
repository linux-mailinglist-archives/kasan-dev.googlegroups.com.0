Return-Path: <kasan-dev+bncBAABBF7OXONAMGQERCGZGZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C67F66032E8
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 20:57:28 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id a22-20020a0568300b9600b0065c0cef3662sf6764725otv.14
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 11:57:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666119447; cv=pass;
        d=google.com; s=arc-20160816;
        b=a+7IdPeh8wBtOxLk7+1Vqv/bTN0U5AsScuUqL8UF72IFMszSYezesqjzjeNhuvE/cp
         V6QDOg8R0t4SnAMUSsMRPhRv6soT0JNmuLjhVjOYTKTaH0LCg1SjmQaX/erKJiRqFXDS
         36U5rFh4ZwwE4wreZ4CaELXb/0xZreZpPD96mOuSWsybPsdgm12u5wGPAOp0Dcd4WwFS
         oNiJFB1Ep7v0r5Ev+anD8x478ID8BttYNxbyXGnzVvxrnNeiIVaZKRGB1yP4zI1nrpSe
         S0WwhcWE2X/thb4MeEHjy682f/LaNfJaT5/qR2yWp/L1ekVYEZ7GnidNt4yQm6KESOK+
         jIJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=JbGSNaLTHGVzg9DCbMKU/AxGbOLtTt343/NA21aDaLg=;
        b=yeMNybDrxd3eKaEwKercYuDrGuWg0dzJ6Krw8woOh8Uk/hgQ1FAM1H9oNcY9Im456X
         42ZyaEvrYpYl77TGbFSr1iwVK5PaqH5qoMVBt9WRAl4BMDrX4d2sIso2G3zh+eP022lF
         ynKG2128CnRdv3EqOgE4vC5leLZVx8hJrFhPgfiYvFMZDSQV/2Gfad/bX34TmPLq345n
         RF3Kk3w6sIO3Yt1YCmiWEBkMnaGm1c+2npIkTsxXw5m1nOlOT42Wh1ARExWjc21P5dpC
         mYbPMszl/JQaDyqJ5bMq7K3RMCR/Ws/YF+6mKuOUSY6xbjk9B9uwdVvFlMId8egjZs+E
         QjZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uplFvVaD;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JbGSNaLTHGVzg9DCbMKU/AxGbOLtTt343/NA21aDaLg=;
        b=ESAJ06x7W2D1NIJMEvG4K2rMZ4IU0LwFZPhwTzYcw3tVaYmBoUuQCb1AvitBBHZ4vt
         c8+PSFL5pC0XW2PEjbyC5w46QFpaasqIxSbY4G6hI2HNW+hU7a/87BHNh+XUqkCLoGcU
         +WqmKVpuzUFEvVWLqn2MaN3r2t25+GHUBDIoT6DBYGKLY668EFJzBB2FaHIs5SAl6l6J
         Jmdk/6KR3eIi4m9QXBiVi/7MstEBDL17RY3uz7gGINYqhKVx2sw94y8E5iOUYGk2oMJ/
         JjlQUohaaNadSNbDpr0QGT6AS3u2bUKP2Nv8Q52McKF0iMGu4SE7t7EIqJTmFgpVPZiB
         igjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JbGSNaLTHGVzg9DCbMKU/AxGbOLtTt343/NA21aDaLg=;
        b=vDeQJegRR3BX7JP1egG/NvLm7X8BQ7XcmixDlSykcZhnS2qFRzl6i6dWWDTQ7mtjUl
         BWF+SuqCArgSitD17fYuSkN8/6HaaX64ze0cxuqi59QsZl8wfzuMjxE4UOOowzMXewEc
         HWmUgQMJWF2X8j2MI+yabE5xM7fnGtpNCjo6Vtp5reGlMvbVvFagAUZMU7zeNmJnF+kk
         z6zN8+xOh9DjwdvGZ5QHDD3ftl15YSdXR9J49q2C5aatv0ejm66V2xZmNUnBdUOlEPwb
         yuh22MdS+pfal3t8SBn84OkmB6nDRjJG4llnDhkom+L2qwnYlkyYoKMz6TGWv0kpNV2c
         Jhdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3A2RnmZoD5Gq9vRiErGpCy1LCYhpK95UjietYa0Zw9HzVyxhYt
	WZa87WCqqYCeWEx7p7oNfpQ=
X-Google-Smtp-Source: AMsMyM62O504E3nvxHc2teCXvmgyGkSdUBC+nZSOnZyx2WxzIWgqJ/BH3hzAl/a/kWeIkLgzuSJkVA==
X-Received: by 2002:a9d:861:0:b0:661:a3fa:f6ce with SMTP id 88-20020a9d0861000000b00661a3faf6cemr2074353oty.244.1666119447461;
        Tue, 18 Oct 2022 11:57:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7843:0:b0:661:d6bb:4316 with SMTP id c3-20020a9d7843000000b00661d6bb4316ls2310974otm.9.-pod-prod-gmail;
 Tue, 18 Oct 2022 11:57:27 -0700 (PDT)
X-Received: by 2002:a05:6830:6003:b0:661:b581:3699 with SMTP id bx3-20020a056830600300b00661b5813699mr1985717otb.307.1666119447078;
        Tue, 18 Oct 2022 11:57:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666119447; cv=none;
        d=google.com; s=arc-20160816;
        b=RLhMLNyN7WaVcjHbjRHxiEH/hLnfNew/HV2acMJdyiSRYvn+xfvXi8Cl7ai11TdEe+
         +QFwX16kim3e1wUHxvuEEHWdLWa1xqslzq9wZL29g5YYPik4jSuXD+pNqUDShsDGGBPt
         gwyVoXPCMCXogVhj25sc6qj4KqFTKVTYBl6fh82Zh08jRjxm70s2Ol9vsfL9Mee/iG/I
         54WQKrNfaLC8J1hikyGBtl4hVNjlgoZ2o0jw7Rxyi7IKT6sMj3FX38FOUINFEgHqU2oV
         c1SIkSmFk4MJ9LKvjbhq80CIpfjEphqkagLJmsdbYPyVcfzpTWrVUQHST34BPNGQ+Izs
         48pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Q6BjkIChY6ltpw7GwONf1wHVEMY1e/5hXdJCr+cMPz8=;
        b=q2IH4Gg89/vlwn16jRxVvGDd+wChfKb77+QFSA6QEAcJZz8T5FxO3Tuua7uwkuP/wo
         XKCF4MHej4taVcoP3vbEIzxQcLuWhssWOE1FLixrZA/8mhU7X1lPwB3ceYbwDtwzg+IX
         Z9EFTLgumgoAKTaXyepizZo1W7aMx7IDOlMV0UG7kpOJMS9vMBYYq0e5XsHA80uved/p
         BNROj8HjeH89GhwPVvbCsihk0fvxJGOB2x3/Fz4IEA/1nfeJHe+6bnt8nh7ytWAAqamg
         4h2YFaWKalnD18ni0no7Z+Vzya73OmTCIYjJoaNc/ppBJyxD6KxqL/3p3tBq8TOWnVEZ
         TmSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uplFvVaD;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id z19-20020a056870e31300b00101c9597c72si687484oad.1.2022.10.18.11.57.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Oct 2022 11:57:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DD44D61634
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 18:57:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 50D4BC433D6
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 18:57:26 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 2E003C433E7; Tue, 18 Oct 2022 18:57:26 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209821] KASAN: improve x2 memory overhead for kmalloc objects
Date: Tue, 18 Oct 2022 18:57:26 +0000
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
Message-ID: <bug-209821-199747-8MA8JDYHPj@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209821-199747@https.bugzilla.kernel.org/>
References: <bug-209821-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uplFvVaD;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=209821

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
This has been resolved for the Software and Hardware Tag-Based modes by moving
stack trace handles from per-object metadata to the stack ring [1].

For Generic KASAN, the additional memory usage caused by the over-alignment of
kmalloc objects is not that critical, as it introduces a significant memory
overhead anyway.

Thus, this issue is considered resolved.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ca77f290cff1dfa095d71ae16cc7cda8ee6df495

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209821-199747-8MA8JDYHPj%40https.bugzilla.kernel.org/.
