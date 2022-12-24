Return-Path: <kasan-dev+bncBAABBF5XTGOQMGQEWCBUMRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id E41E86557F7
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Dec 2022 02:53:28 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id ob12-20020a0562142f8c00b004c6c72bf1d0sf3173533qvb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Dec 2022 17:53:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671846807; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ai6SWcl9t4//dY+8q1xXIX0PyYazIiffWg3qiqu2Wa4MDzyorDy6hICPHaojl8QBoK
         xcKfmmagbmFVMllS3TORAxRbVc5/Kiph67LPVAYA4TcrwCHRCdOVDphENVcdcecVRT8z
         VfYFXcVDl0a86WmRKdNoBTvCkpJlfeV38UiQQx4vbQ7b9aBXUop8h4jbgNhomI3TAdp1
         Dj1u/gVx2ji/odf/PWA9vfHvYR5Vp99UAsndgLzMkrb2HzAG8JDep4mG88fTKmwFLWE7
         +36s8QH89NzmzbXUYW5KgvZrsb+wgzOxUZNjMsbKcBYhS8mv9dSSDBpx2KuKDv02ekd0
         NhDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=DWBRuuB74SDn579J940cBj5jJgCPDsby9tlq5W7fmaY=;
        b=AYaGeuK8B7h1b4kCQihMO7OtFnRgdgrNtUUO0U9GBNl3pG3tb0q6SVkV6IGT2Qev1K
         udm9iHfRoAJW2KeDur7+Xu0UBHH2ARXdmGXrzB7HDGOH/L7O5lIkmgSOZ+iU1oWA18bp
         GHxSULSo3zAfDyMmN5o7nRuzctOi92k1zMGfBd23VNEaSFA327nWa8c+hLhdGPy9Fqc0
         R4PVdayVuz2+Dsz/y6GYnrZynDPQsgJVNLJ4eat2gsWJIImhD7hUeAhZoO49KJ7Gw2t/
         77mYPEio6PAxeT2iAf4A14FMX0p43R/NOMlcTeabzwfhRcuegHMGI5TFmNWFSz2XD0I8
         aRwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mWi4hRqW;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DWBRuuB74SDn579J940cBj5jJgCPDsby9tlq5W7fmaY=;
        b=p9cksep1PmiuQfMLyx55jvJ18n0kVAuQSuBIm//USYWFLzwpDjMa9S0mJOjMUWOHvP
         qPpPaOhNagjOcREQ51vf/LCuR9voDFeth3e00fO5Fqf/kf4Xcm9ImYDYUOiKd9vvQU26
         U/oqY4Yec2Md/NAYit3JYrlq6UIsD+o9aebiMtCBkkyLmcsvuHClg5em82fi3zfdJh78
         zfVDBnyEcEnFvNmSmjWARTxFFM7bIaauHLhAiEoIAsul8kP+XonWaE+aoeqJWXdf8Pyi
         dvmyVmi97O9hTk/SMAcumMUScPOOUPhsF8HPxhuEmqFXQcNlOkKFw1XVrk5OBgfRv4gI
         S3IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DWBRuuB74SDn579J940cBj5jJgCPDsby9tlq5W7fmaY=;
        b=c8A7IFulEgIIZcnGOOIFzj3QdG2ys9in2SECfirsQbYN7ccrhcB2BXJATM78vP8Gb0
         WPyiZjPJ7sAANKyfLnfyqFZdOmA69nWuiMZ5qFFc5opb3eFLLar7Ov1HtXjmxtjxQqaW
         Kg1J99/aOCk/sCDRHhI5Jn4DfuwlvarxhpiQmSYRuP8kzMqlmO1KFtBfGn33QPxuPQGd
         OZkAoJE9qS23q7o+X503RSRuz0o9saMjGyF63ToZqjs7MwOxtUivYNzQNEAIUiN8W0bc
         DrAW4ueFrTiITdGXGTy684uC7vW9xLIadMRSp0BcTzfh3udiF/cX4ugESGKCBAapziQD
         C7og==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kppnvxS9N5z6a46GWmCOOF7D3ZgiaB894TtVBDajgd/gMFGHU5y
	Yup4iaTWeJLVV9ypIhZ//SY=
X-Google-Smtp-Source: AMrXdXtfrYM+DWjZxAie3545I0N9VdjSXN8OHifkIovCE1FdTbI3WP72+F+fyZ3U/wbb0XHlhUiBJA==
X-Received: by 2002:a05:620a:800d:b0:6fc:a53a:16a8 with SMTP id ee13-20020a05620a800d00b006fca53a16a8mr598057qkb.88.1671846807592;
        Fri, 23 Dec 2022 17:53:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:8c7:b0:3a6:881f:5223 with SMTP id
 i7-20020a05622a08c700b003a6881f5223ls4220613qte.9.-pod-prod-gmail; Fri, 23
 Dec 2022 17:53:27 -0800 (PST)
X-Received: by 2002:ac8:544d:0:b0:3a7:fc75:22c6 with SMTP id d13-20020ac8544d000000b003a7fc7522c6mr25126114qtq.33.1671846807177;
        Fri, 23 Dec 2022 17:53:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671846807; cv=none;
        d=google.com; s=arc-20160816;
        b=m3CFwsE8anZclum4W1hHqm5askwx1iDc/FDC2OZ3EnPigGQOCsfkci3zDSXkZ5xnxo
         fzsyeEN1yQniZyY4vGnKPkxKn2yIe8UO7BJUcUojgcEzVfKGUfJpj/3RuEVxEgo00Z1A
         yEpIn08H+ajG8Bkq7qKnFsOWG05mUfv5IhPHESJ3M3+7j4727/m0+BU5ynHndZXx7598
         rCqOH3O06NjhWxX+ttdCyFmDrvi0QiXXN7MhxabT8FVnyKSU3zMjcbonkWnefrNkVmNf
         acLH6xuelrGga4A4BSz1eq9RoJlUTotbGkO+cV8sV7RpiNtqEFtBja89yFAPh44N9KTs
         VdFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=sT/Ox3iMUpEER1zMzOSOCJ36e7IvWFDQ0W/DalJHGyU=;
        b=lMZhPTSVIAZiYg/jkp4lq8NgVHkrMmUhnh2bl81Pg7GOziew41KMB5y6AAmIU/Md9j
         NsGgqXXygx09HuymwgQ17FxtqypY24b09o+1faLjUWbKgf2loJ+0PqitSf9iLsOCeU31
         ZYZ8ROscR2Z137snn0tXYZrbh5rewvkfnpjNutXizoddei8wPcnNi/yyQGCuXM+Gw+wv
         OagapRfuFbXbCsm8d/TC4tnwAe9ev2RE1jIt0lOcehmBqaAXX5SKDLMGC1ErKvQa9peX
         dI3pC1ndTTdEAJSXeILJQkKuF1QuRKCudJAILVTowy6VDIAParQPSBGvx6iAr8gXqK5B
         T+Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mWi4hRqW;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id u22-20020a05620a085600b006fa81f6aaf7si304830qku.7.2022.12.23.17.53.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Dec 2022 17:53:27 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B468961D03
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 01:53:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 0EA3BC433F0
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 01:53:26 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E7421C43143; Sat, 24 Dec 2022 01:53:25 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198441] KASAN: need tests that check reports
Date: Sat, 24 Dec 2022 01:53:25 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198441-199747-dimTmLpYGy@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198441-199747@https.bugzilla.kernel.org/>
References: <bug-198441-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mWi4hRqW;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=198441

--- Comment #5 from Andrey Konovalov (andreyknvl@gmail.com) ---
KASAN tests have been switched to using console tracepoints in [1].

The next step is to implement the tests' contents checks.

Note: for use-after-realloc tests (including kmalloc_uaf3), the checks must
ensure that the alloc/free stack traces point to the right alloc/free.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7ce0ea19d50e4e97a8da69f616ffa8afbb532a93

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198441-199747-dimTmLpYGy%40https.bugzilla.kernel.org/.
