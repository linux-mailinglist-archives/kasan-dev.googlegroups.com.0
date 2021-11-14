Return-Path: <kasan-dev+bncBC24VNFHTMIBBKP6YWGAMGQEQ7RKJQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B538444FBD1
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 22:27:06 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id ke1-20020a056214300100b003b5a227e98dsf14227937qvb.14
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 13:27:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636925225; cv=pass;
        d=google.com; s=arc-20160816;
        b=vZz68yiZgGu2MY586vPonCdU+8EPa1NNKvKxMowUQYsjYWtDIVJQliBqKUBio4unVR
         /8MR0wMk7hnLLUlTn/s6W+lV+Z8EziAPot1dFvZ0nyvHOQRABFLHZtkhmnX6XQ/JfPXE
         yuG6KDrySbot7Rq1QPyhV9qFdRByqTX/8J7s/yX79kRSwikawp2XoFQJgNSgxztDsoym
         kBQc+HcbWyo5OCKkjIOxzANVzFSPyDiU4mGaIVvhvKw6GPRE57ZAbo1Ev4RVqIOVDxdK
         CYzujJd3Xxy3HVRH7854I/zQrthAzQq8BefufXZ7VNtl1a415iLERjJkwhoEob+B0k3r
         aXXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=H/1mHuXc4uac+nRkXSRhKJU9Ee4kETuYUjlfkMO1P4k=;
        b=PeyR7BizZ31vGe6ZQj5QtspU+hUuFScai7RXAHCC4R4H076sihQG8yeq3xUry5WLPY
         G3HF2jcpr4SBMhdoYtxl/VCvdlzs1dqZQHuk/rGpsoXlITyckBX4YhBZLAIeHL5E+OD9
         2jDfxuv+vYmh0j6Gr0ZitFgfmghw5+pmI84xnLvvrQbikIq7JVq9kBMf3l9jgriBHaBy
         66JBZJf+Q3piK1qrwl4rfYCft5PHadZOjkJc99eJszw/+wARNzv1LYaugDnyKleh8UAx
         v0e4wrJtp04qSDMLZygyLIMICVXr33AB5nDVAisbu//9bVvpxlGQXMlzqMG2xgSe7Cgq
         M3MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nd3Z3wH5;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H/1mHuXc4uac+nRkXSRhKJU9Ee4kETuYUjlfkMO1P4k=;
        b=XfO9atBmXiY6pk5FiZiTYL2D2bBKC+uA8t/Cb18IVg86xRy8xWa5grwCuoEGs2/Kyn
         uXurYdRk3EJntpH+9fs15wlLU4A1c6vmN4bjrjXcHWtjtFbfKW9ggBmHQz2zaaB0pAzg
         P607+OkOoRyKNLQClrRr+3x1EWFrgEIKCYeYso1RbtJPjb9zV8+Nitff0zcQNxbSLpMq
         d4TZLsyFS4NQksIKvBRuGY+Wjqy91RlGobzFc+hdrZwI+uk8NStVuWGlujATsqm7eOB9
         IYGzxOTq0qbdi3mOYXfl0tn3CEJrIZqSFItfqpni6XSXP1oNkCB10XfVGA3ZTerFTH/d
         iOUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H/1mHuXc4uac+nRkXSRhKJU9Ee4kETuYUjlfkMO1P4k=;
        b=eheTAHzyxErrp+MydXmXlvFkWNz9AEJ3SFwlRT+qaGlAmJi3Tl2D9FGHq1zXsVOjeB
         uSFyftqK9z6xK2p0h2NGyl+qKqzANAtzh3OGaxTpAMWi4eyXX+4Te+ZM72RrZbIIgva2
         cdM1Osr4/tQWTUSuXUesnFxGaOPDltqg4NQ0KPTMEUJshAPbC5tSAjkYXU7VSpVmrJJE
         azOWpsJqADzLKLfAXYO02oHcly2QrmY4p5LjtPBJGug7+gxKbHWtwlvtKRVOc8fCZfQF
         CUmzdteCCnlNsdlNSzRME+oe0vU1ZgxNxTO84TFpZh2kFBo+4QR5/qZ9FW7GSCnH7fBx
         Wq9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZFCsJV7nhGuxfLgJ5AU3A7sgFlq85NxY3t1e7TQ2EEq0iVIaD
	0TZNwjBbWhrCIxo1QOka8RY=
X-Google-Smtp-Source: ABdhPJzZkiZeUfeeu870oCzSgvDt9FpwATgjgGPu3cQQqCjsfgQEP62wJjrq36Z0X7KldVcs3BQWLQ==
X-Received: by 2002:ad4:5fcb:: with SMTP id jq11mr5536765qvb.30.1636925225567;
        Sun, 14 Nov 2021 13:27:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4a04:: with SMTP id x4ls6879991qtq.1.gmail; Sun, 14 Nov
 2021 13:27:05 -0800 (PST)
X-Received: by 2002:a05:622a:1984:: with SMTP id u4mr23043100qtc.10.1636925225152;
        Sun, 14 Nov 2021 13:27:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636925225; cv=none;
        d=google.com; s=arc-20160816;
        b=Rk7laZzBdlU+etA01Kja0CobqgXBnuziuYpUb7D/ildYYPVLcAYvNED1A6vf543b29
         b/nLUyxIpl5Bq3K1Ul3svLP+J5d3wLfVwSsR7wyZ1cRZRVFsCJv6Rs2vom+kKRjQSGU1
         PnAQicZ7wvrWFbEOdceIbhCdppsijtQ8RR7VQJLeQd7tOgjS8IX0CrFRXGcBk5cCvXoD
         TN14OGkNC5s/U6pxid4Co7m/zqoQkuhCsP03HllzLPiBBCAU/EPPsYAD76pmXJ7FXdO5
         nbQ6D6jUSt0xZcnBY5dIF2soCQ5cdVVeBXyhSl2XtOwZpn3/rGLgZrq2/2OtlJPffqMe
         6+Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=aEH7R//TJhEgpBtsnt8Xcd/1EIfocQ24BfBJ51r9nuE=;
        b=Lxg4CnfFz3ROyOXnzbvMh+q0PsRDhPeRNgGXlDnIYdKWqXUNtQRnSSmcTvi/t2ibnE
         CzlzwkKNrLrMrk3Zjj/A/kupTHOL8lhfuU5hNuWQwAL7xsGUUuN9f3rPNCc3/IVe28aa
         MlllRdZHt9x8bDwnYHeEN9UdjdxlUbaW0De4s5Bl159PDMmLrFo5s1lgfujIZtqIN3iq
         vgwz+kbY++9HJ2PRGcmxCOOZZl2wbcEg4WT8swh5AYLgkDvBeGyqxLBMiJSU1JivEgXO
         He0SS7YUC4wAgTXakaCaxw22gtBFqbLYCCI+20QtOMJ9MKp9aCUYI2Zqj6qDE18QqGtN
         7JMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nd3Z3wH5;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y15si1012246qkp.0.2021.11.14.13.27.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 13:27:05 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 1885761056
	for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 21:27:04 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 0C7AC60F51; Sun, 14 Nov 2021 21:27:04 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212195] KASAN: mention used mode in init message
Date: Sun, 14 Nov 2021 21:27:03 +0000
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
Message-ID: <bug-212195-199747-Y3s0zsYc7j@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212195-199747@https.bugzilla.kernel.org/>
References: <bug-212195-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nd3Z3wH5;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212195

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Done for arm64 in [1]. Other arches only support the Generic mode, so having
different messages doesn't apply.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b873e986816a0b8408c177b2c52a6915cca8713c

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212195-199747-Y3s0zsYc7j%40https.bugzilla.kernel.org/.
