Return-Path: <kasan-dev+bncBAABBEMVY63QMGQE7Z5BAPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id CEE6F97F18A
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 22:07:47 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-7197cce7697sf7335751b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 13:07:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727122066; cv=pass;
        d=google.com; s=arc-20240605;
        b=RPKvZQMnfbqcypSxyNdJLzY/UvHBzapokYONiHga7Xj4cKVShkrwxuxkl8teY8sy/U
         2kfi3lT/uXb5z30cL7uub88cu/RGaHjEDP9QpN7Ih3vRTra709UEh6ftUN4VwuCdd13f
         yX83taG+VVANI4CS5EEO6FPyB7l81LMrckDfTV+Um2ViY/HlnmiIxJQL+aOPLkWeUqO5
         gfy11X/AUmgvhFhcJ/EvTm4QArj07JOD7/JEFAsUHMmHg+f5D2bua8Tb9jGlbLvYvTcj
         Fzu5x2LWfs4HAAoISXH9JwVbu5U1mTND57rGYA91sboWK/B5bdQMkzMzEU8fcGDk4CJ4
         aHSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=I5t4HBuM7Unw8LEQ7sIDYrdnHj1WTFE0uN1LJc4CF24=;
        fh=0IRJMcz6aPQZ/opEDb17yDB0sRjFA/LtDoCmQYVTB8A=;
        b=XKt1vpS4Wnly+kNAoo/ZqS5AEYePsQhfMFAnkWNSZFiwooJRtKVV+7AmfMu0JupX9E
         VABxxjvw2PPT+MqcGhexOQZegbFLDPbJ4gaI5ymGThGXunhCjBDOdZ4aBYLr6PzEzijj
         jIlX2pA5QfjfvgufcAzT3+9x6IjPuW0GMYmiUtmAptJpiFqRtZ1sUXa44Mf531hr+EJF
         wuufhQUROHAQcN1IJ8ZEDJIp5BwTdyD3yN/+Ma3btNCQkTdD6794sIAFy+BxTt1tkBPA
         Jq70X98lAJAK+yQVanalhH3I1r9+ywQFSW7CEaIEtMH0+FW3UokxwO8bNt9n78NTLzvt
         tQSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WxUte0Sc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727122066; x=1727726866; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=I5t4HBuM7Unw8LEQ7sIDYrdnHj1WTFE0uN1LJc4CF24=;
        b=lIncmftI2yGYaY1C0oSOmliSngbpVmbJyzJAAEyJPxWoNQ9eXYgHHQ4BWUopgh7+h9
         Atu6UGMAtH0yIAsmmwtPId1S28EA0cloMrjrxG9KiGGXtAEwnmym4e+7PprzMICfik+j
         2q6P+d8Xzo2wIDosEEY/HxK8O6DFZSCSYECG74hnpH/wO5qJXGxDShgiHJiZGlAWgRxJ
         hOWalUl+A/bGvtQ6mZhOIZ0zjKHPfSxqrRGsKDc4m8bW/yciTlYdV/fUSLgDxRX6/DVB
         rUNdVjVzRqNnDyEibt6pp8q/VcWekpV3pZkalBHEh8cvSAs7tKASH4417lPcurWg3HFR
         6PoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727122066; x=1727726866;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I5t4HBuM7Unw8LEQ7sIDYrdnHj1WTFE0uN1LJc4CF24=;
        b=Azs13sogPoyIIOMZmNlW2MUc5dWACA/5vLnduT24KrWnasCFtUbQoGi4aEmAz610Rf
         xNLVCDteHPODkW/I1Kuj74cTRbuT84zYVyNZBsGEgvO0UY9pK9vLAncfs0ixXRePJvVn
         UHDj7d6L7kyYMzqcFvK+BBtPuGK1X+o6hbIDmSol4HrA8ZNCxw/iFjZhfuRQDmgpUTy+
         gkBvaDvKBCDFlvypzc9nHjXecPw6P17TtFUiAJtmvrgEKV1n/vvI7lrPdRjRHhxn4P+q
         u8vLwBJpHaukAUepqmnNJ7nZW5sZ5aJNaP+A1r/VbYD2bQGHTPme4LXPb8Su0SCoREH4
         v+sg==
X-Forwarded-Encrypted: i=2; AJvYcCWGCITetb3rBXraUkJvSsDflD72nbZWN2NJbnVleI1pv6JsgTqSQpAIORIRuwZNOHJ7VcuCYQ==@lfdr.de
X-Gm-Message-State: AOJu0YzbFeWRJdk4TAJ0bp4o+sK2EyC6PD/093xGlXPRva6H2ZgFJ+Ba
	1tSZEOO3oFFL9VOnMYCcwWkkzUtQO+r8/og0hwppsvM8k6q0JbxX
X-Google-Smtp-Source: AGHT+IGFFS/Lx76OXFd9iVth4U7vQow842XRUx+gVTj1L7EF/NwsmvFNW2jyawicAQh0JYS6HF/+bA==
X-Received: by 2002:aa7:88c8:0:b0:719:2046:5d69 with SMTP id d2e1a72fcca58-7199ce0d060mr19405251b3a.22.1727122065485;
        Mon, 23 Sep 2024 13:07:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:cd0:b0:717:8044:3166 with SMTP id
 d2e1a72fcca58-7198e66b3a8ls4106730b3a.1.-pod-prod-08-us; Mon, 23 Sep 2024
 13:07:43 -0700 (PDT)
X-Received: by 2002:a05:6a21:4d8a:b0:1cf:9a86:73e4 with SMTP id adf61e73a8af0-1d30c9fa444mr18470889637.14.1727122063424;
        Mon, 23 Sep 2024 13:07:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727122063; cv=none;
        d=google.com; s=arc-20240605;
        b=FmflHHJI4QxZOymysFuRRKBCzHkcV01OxjLvgq5Z4C4l7rFdkett8aQ2yneY58GQVe
         qVcw0MOo3r8CGceRx9FRguwiFSQENUmn7O7YdZxvvKzfHVr/oOh0P8DeeuPj8ZFXfI2m
         8me/XqkdFsBk9VpTaUVdW0QZjhY9ydvZzfvsoTdQlsy7UwifhDW1DzysG5uYlXr5qObS
         jaoME3f7sm6NxRSeVpV42ZIGijSez1UX02BDvWGsf32be7gKzzwG8NUlq7yaBecHbfQW
         yuHWgpEMQfty+sqHoPhky7o0fCnqUr89mpUQgsjtpqfHs3FZ6TfYL2dw23HwjDaNAjXA
         DGMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=kjR0WrBijx4WMsuCB3oIGnfR98FGQ72TMgKg4EmYXNE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=bZKvO1+IZBYZ1PlMR5i+YBGvXDcqXIwDOAG+3VHYyQER2z+WCS3N3T84wt1B26lzM3
         NvPSa5tUC2G9W6rqeW57KNav/myleMevG/8dwTTzCgkvs8Zu5FJ20dwd3n7cSXecC/qY
         UsJQkbsSi0KGqgkY9g7N4McFW4tAe1Qfjw4NteHE9CNhppsjARNFV8GRLYY4ykG1bQCF
         Q4KoicX8q2oYVmN33+gkTpySHYxGg99jwOT5k/Dk8D3bnY6yLDtROU9eDlg1H5c57jOf
         Bj4qIdWxlvLZC0ehjvNMlVW1LoI+e6a0ly6QJkO2ZZlj5kfyp3h+JKXskP1VY5tsOK/H
         EllA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WxUte0Sc;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71afc72c848si2771b3a.0.2024.09.23.13.07.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Sep 2024 13:07:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DA2DA5C5930
	for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2024 20:07:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 70847C4CEC5
	for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2024 20:07:41 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 59499C53BC4; Mon, 23 Sep 2024 20:07:41 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218854] KASAN (sw-tags): multiple issues with GCC 13
Date: Mon, 23 Sep 2024 20:07:41 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218854-199747-xKOkjxZucJ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218854-199747@https.bugzilla.kernel.org/>
References: <bug-218854-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WxUte0Sc;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218854

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Mark Rutland posted a detailed analysis for issue #1:
https://lore.kernel.org/all/ZvFGwKfoC4yVjN_X@J2N7QTR9R3/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218854-199747-xKOkjxZucJ%40https.bugzilla.kernel.org/.
