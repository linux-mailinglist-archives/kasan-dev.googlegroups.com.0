Return-Path: <kasan-dev+bncBAABBYGB2SUQMGQEKPU5VGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B4627D232B
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Oct 2023 15:17:22 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3b2e6189e6asf4402454b6e.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Oct 2023 06:17:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697980640; cv=pass;
        d=google.com; s=arc-20160816;
        b=oaGtOhy8EqYDRHnagZIy8jSzowibpKzG4WrT6fNx/PHfl27+5r5P6vX7GBDPWfNwye
         IM1Za2Hgm+58LXRU31hcwDDGYPpD/O92edpRknVU+6YzFKOIcLaSnCgl2ZPSNh2arrHt
         iD9gyILYaSlC1HdSGlNys4TxoomsiwksRiFZXPXha+6sL3NJFWdFJKQmePou1hmCRHQj
         a60hiezLbMVRJpGaUr7TmoUZ3geIhaaE/0QTtl3JI5whc1TnRt9wbN3QE0744X3RxKjD
         nGIcEyHXcKWF4FTFJavzv4r/eJRwkqrElwmarEyeqbbjVSw9+hFGXIagZOg/bqmxG/hO
         8sJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=x0tl/dsWRcd2n7z0eI8B5XL6K12cj9rNmx4eSr7foxg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=SAV/KwVlJET0JT84S3Y1lWr0uJdgPCS3pelWTzP+9M4HEQzlbQZg+0tQ77WF6zBYG+
         NrFhzO4pOLj+hct/TLtByg028auuCfbDZmg2gvYiHryI9QMUj6fiAusSklipNfWmvdHe
         vnikFlkCeeTL8VMYYITKDTrFnrQtdWpl8DpNZisRS06XAQGqd/X3oPpcjNV91Ouldgak
         UcnJQBhlhzlS4upwE64qKomZlraBlEfOGxYyMCo9LOGADidaRT2jpJu6+/+V27+xY7Gf
         KE+ruMScOqLpXi3xDGHVA1Da8gggmbY49iwLs+y5RKssq+SU8C8HPOCzmlblLdJEhpgV
         +Wjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Kq5J09ij;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697980640; x=1698585440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x0tl/dsWRcd2n7z0eI8B5XL6K12cj9rNmx4eSr7foxg=;
        b=jdpJVyBih/XWWFTVY71irRn1i3jVTdj9418crdMwZ0gWUOkumM+hapVE2VgUW5Yc9H
         m0BTKRNIKBhngIv2IDBx1BGXX+vOdijXocb8Rq9Xtzz5OENne9VUd0zW+FCRti/IpJSU
         IFKVrQE2CggI+x3jnXxiPm7djuIJxZYYth9idC7umwOtF98VHuM5LtaD502B/1taQy17
         KZgm4hpLW2q7VdZwU529naPRCYCP2VcXAH64hS4Pg9xGf4/VNNZXj7PkbwN2n+ljCg2P
         +OJzLajm5bZwupShVrL2UpYb1kYx1szCpKQakTzgNFOnQZBWrsujI/1HkfYRyLz3ThJm
         ydGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697980640; x=1698585440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x0tl/dsWRcd2n7z0eI8B5XL6K12cj9rNmx4eSr7foxg=;
        b=RcT+oX/XfNSHdLRH/zNHh9Wq32hAVAdiGiyIRL5btaj6ww3UCKppyG8rLU5TmBUX1O
         FQD38XBSLFXg4Th8OjlsnQrvpS1+ZWCUJ5lcD/72iMb6aNZypG463U4rp2P0eIiVElqg
         idmzPA6hi2xS6q1MEflWNjdYuws82L6JQO5gpTSQoTHXdIap3Uysv6iMkuDRg6GFvE9G
         jyHo8v+o+G0jk6fMdAET/DxkYJ60JfXkNO3WUyE7phjQoRATt6IxERl0l6k6Wti+Ty/Z
         N1iiEY/Q0Qa9ZnBquZVWA0X2WIT8zfnDAELNHuJ6MCiYpaba0iivhNdBYnIWLKJdHSab
         /q2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzqUajmguejRvzFTVQ0aAMAmLtccXUHBmo0yhTM9q26fh8FAlAV
	y1lf6C2wAvqp2MKnC5unWus=
X-Google-Smtp-Source: AGHT+IHQVIj8VgiRGq1CBVS6/7jbttbg8djedz5dqvoEICPRFccO/zgKlSUoaxfrWf4CGEJfsjQ0wQ==
X-Received: by 2002:a05:6870:5d8d:b0:1e9:fc32:9887 with SMTP id fu13-20020a0568705d8d00b001e9fc329887mr10094774oab.13.1697980640668;
        Sun, 22 Oct 2023 06:17:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4726:b0:1e9:960e:b3d9 with SMTP id
 b38-20020a056870472600b001e9960eb3d9ls482201oaq.0.-pod-prod-09-us; Sun, 22
 Oct 2023 06:17:20 -0700 (PDT)
X-Received: by 2002:a05:6808:8c9:b0:3a7:2598:ab2c with SMTP id k9-20020a05680808c900b003a72598ab2cmr8044049oij.7.1697980640118;
        Sun, 22 Oct 2023 06:17:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697980640; cv=none;
        d=google.com; s=arc-20160816;
        b=coLzuRvLy83fwZW/Lro9W7ZN/x81V2qiFw3p3PweB0oaLN5cO6nOfUcnrVwynItD8t
         fh3iQlw4vkQkQtXTxin/xSZynSkrUnLybbf/UzTDhLWctGEb2+cDeR2O2z1JiYxGLHZj
         87RCBbpP37m99aPTdzNAlzneiUqyWxIiH1WlO3AITcELPpGWXwA+uhIIzYut424LgIzz
         nCEw2u+9HNFLdynH5JzkQU5ZFO4zqc1jYstZkgQlZ38UNy72N0Yol7bJ78w7r8e81BYG
         XkXRk3elu83OfRjBUuX2Qw5mKHeB2SCE08nfy89jD8W4fRaKhMv0zTjydpv5a4ba1fO9
         E/5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=t/Cx8xejYVbHyQwN+GnJT5qhTRO1Yt21FFelHYb35QA=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=nZyhvotXibYKHi8Ensejrhy7x1CXWUjJXz1+vx7TgBnAH+JA4NS26jpjYHR+VK/q3L
         r46SEgiiC8GeLI3S7V4krQsSNdY4LE18iiZRUWbcdpzTzFh1/0RqKOLcPxRCGW++kuG7
         SMYrSMJMos3wAWJb09043a+V01P/fovAnjNKjcf/InB4484XEFYmHu/8kDqROFn6i3IC
         ylPbNvyhhSnfW/+OwzMYYv/N0Eyf9KfG99PbF3fI6GRI33CoTJhkZUa8YpXSo4Sr+UJR
         fXPSz+DWkkMq9aRMD80F992U0D2sp5TDVHUHeCJmUxhvfQk5UL/gckTwKo0nCGY3vxro
         TYVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Kq5J09ij;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id 76-20020a63024f000000b00569ee9c848fsi456633pgc.0.2023.10.22.06.17.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Oct 2023 06:17:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 55345B80FA0
	for <kasan-dev@googlegroups.com>; Sun, 22 Oct 2023 13:17:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D92E1C433C9
	for <kasan-dev@googlegroups.com>; Sun, 22 Oct 2023 13:17:16 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id C40A1C53BD0; Sun, 22 Oct 2023 13:17:16 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212177] KASAN (tags): improve use-after-reallocate detection
Date: Sun, 22 Oct 2023 13:17:16 +0000
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
Message-ID: <bug-212177-199747-sTJQlSpHes@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212177-199747@https.bugzilla.kernel.org/>
References: <bug-212177-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Kq5J09ij;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212177

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
For reference, this is how SCUDO does this:

https://github.com/llvm/llvm-project/commit/8fac07a12

However note that SCUDO does not use a dedicated tag to mark freed memory and
only retags memory on deallocation. Perhaps, KASAN could use this approach as
well.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212177-199747-sTJQlSpHes%40https.bugzilla.kernel.org/.
