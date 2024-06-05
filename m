Return-Path: <kasan-dev+bncBAABBT6W72ZAMGQEVT37O4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id AF6B08FC04B
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Jun 2024 02:03:28 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6ae3dd961afsf17773696d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jun 2024 17:03:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717545807; cv=pass;
        d=google.com; s=arc-20160816;
        b=obV0M5MJnYei3uG0ZGI6yR93QKbP3j4WDlBTThZ61h0eQoeU005k+JO2er5qisK3J7
         srlmtCD1U3urWzN7cksD7OUEDXp5win1Nn7Aw2k2AnyBYjM1zHL7oqJYY1EkFXegel/n
         dEdrvkitUUc6olBela1jdoRQc5D0mIHa6HFaf3P77x157oHa4OStwybNVqgsYu/hxnOo
         XPFNaZ4HLjF5SyCiPpxSa+ofXFJPgVpuc91b0TvPMuSQkHYu8mzhja4suzOn2M2bK0S4
         a8t16jKSkj2xfnV41G6C+vpTOeQCTktUBS91s+E4DWVZha4dqj6oMhcd3CS5YqsWSHoj
         OPEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=HjKMms/bRil59if1Q7xV2dH9yUeCl+Jcg43tP66zaVo=;
        fh=D7QrA9gKegXLFv/hiiio+KmLQ/OWuCLpjNCz+csAhGI=;
        b=nomS1tJK6HK9lzp28uDjgwlE9/m18twRdqU0bZPQbdxN+IdyWXkuFCJ+GSrTz8D/px
         fcgCELGcf8zmQZOx2hSH14yKKe80kNLrTg7oc1OtZ8JhtfQmHPhgwE3uCCfYvBmocFcH
         wwl61p2gGFW7HdD8sAS+zfC0IwcLcMIrTAnd/nIOqA/wPSC2ujrN8x8IZQo2U8cbZ/1v
         Kjr6si5FvogTCmDhv9D20xFsb4+ILndIcO9KVJ9o6iycxiYo2zMWx9Q9cn/308tyC3xX
         ZNbx9e+Mi+RqFQvuoXDwHZSzuf5W1e4yudrbdoSkGmDZO/HUM6K/6jPpLnmcF/0T7r4/
         Js+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H2grn2aH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717545807; x=1718150607; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HjKMms/bRil59if1Q7xV2dH9yUeCl+Jcg43tP66zaVo=;
        b=cevymsrBDWCruuL9ux7UBVKBTJf20YX4Yrbj8x5WwmFbPdkpdTrswbcVWxzQxAgnb1
         eAhNZc8RR/1jgnHLoeE+elrAzztYAQ7C0uHGIva5Kh8VRiwDjbTXNbheF6i1jgGGgLhc
         d/HUDP8M7rhJtqtpEQTooAtvWXLqemfP5uLBv4NEo+CCO+4g+0LG3FMtAY1BteA3GWM+
         IjLqGenYcTbnEo8uJ0wPO/XQXZvEIDyXV2iylAUP/0aZOIoovByE742ZeG9mvdBFxHmf
         /rCklz0AH8iDMSFip3motXb3mtunfy8CLxHsIzgrsIjEGUrPELjcWp4tfId07iAMBifU
         yKyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717545807; x=1718150607;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HjKMms/bRil59if1Q7xV2dH9yUeCl+Jcg43tP66zaVo=;
        b=PFXHCDEV+PyP+if3ypYn0Y3+S7kIcNRUgv4t1rSpFDPriusVyzTGCzLf9BcfUEYbi3
         49rczj1X0x75W5TqQekPI7QEwLp9f4Cu4fWNX5mwFitpHyRv7FIn5n/SFkfXi/NgLw4m
         DLwTttDDH+BoDWIvLOWn3dE0B2gA5MOL2G3j1VeIG0jXtNuFut0rQavvbSMtgyndTi1E
         QHIO/7GOBD5q5aj+WIVKczzUzaCCyRiEttNQ90aEZVVvSIu5aARtUKBdkcq1YsAbPIfQ
         6zVFNrVcZyFpUJPj3ZYnRBf7E6R7XscCv5Na+3bX6L4P/84yvaA8Khrq6rHNKCLBMhyj
         AM1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvXHwNgALSmsoR2vzAt4KZV6TabpSIicN3ij38kYk3/niFq/t0s9fLeRFgfrtXj6eWUqoRMtB6bASFNunJpmjY3nPQzyitZg==
X-Gm-Message-State: AOJu0YwnNYqRFRcvcSoWGWVvALExVmVo/S3pi2ooY6RICGm35d5YQ0Hm
	VjFJ2OTDEG9TM0NZ3G1cvnnXo2WE9LTAsjttA8NjJY/GISUkNzod
X-Google-Smtp-Source: AGHT+IF+gu65Pi7Eii+G3/trSCr/q9esJPCO5JjP6URZieamzjjo4zLC38EHxXfVLJifj4N+MmZGMg==
X-Received: by 2002:a05:6214:5904:b0:6ac:adb4:43d3 with SMTP id 6a1803df08f44-6b02bf912cdmr9219736d6.24.1717545807173;
        Tue, 04 Jun 2024 17:03:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5016:b0:6a0:c7a8:7ed6 with SMTP id
 6a1803df08f44-6ae0ba3fab7ls11432486d6.0.-pod-prod-03-us; Tue, 04 Jun 2024
 17:03:26 -0700 (PDT)
X-Received: by 2002:ac5:cbf4:0:b0:4eb:260c:949a with SMTP id 71dfb90a1353d-4eb3a401db8mr1225725e0c.6.1717545806329;
        Tue, 04 Jun 2024 17:03:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717545806; cv=none;
        d=google.com; s=arc-20160816;
        b=rJOG5O9HW2xVFz/f5ofarH2A7kL7JBpV2hz5mTsAfpuSagt4YXX9ZLg/+GP+6K3JF+
         N0Z2vVV+FJMfk9scF4w+FDRSMIoFrm5OykCiq9zoOmMMiQcWtPfXeBD9emjt44FmEU+G
         RWp2FCoMb5IQ7jttJbHfWZ9Ut3qYWmOrmAh3ENHoKwBuwDFnwbfHKhvmkqhfmF8ih0LE
         fc+nG5zxKK/qU/wmohMquElisduVt+A1SBS/ks5wCbCmIW0V5TeSUlBcP4PWIs6LOHY6
         2SEmLp0t1CNcYmAzGME7wOgFpdJWRMZU2t48E2slt5r4tj0TJzgUHDdNreMEdHuK1RZS
         0+CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=UeC2JNI9Jneco4B2rC2P5TJMQ9sH51Tii+h/C3kVIW4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=DzeyHN+1ErdJBAjzYoArp3QXPpwim/VZXFCK0J68T4WrNstw0wZWmFrky+Oc8SI5Tf
         AGtfBOzKNCP2Sn/wO053reblyMMCiI8C7PdqjT0GjCX0DbUsq/+p/GPnkqD56wzkhgAn
         2iDqiicdMl5TacgHxcmssUBMhPuN2p91RYbZ/ITr/KSzg5VEuPWSrLhTPKDZ7iZSjATi
         j0UA1vdR0ijRrYJr7dtgbuf3j+vZZIhw7nLN9PBXUak4MiTpalet4GaBNJXss7dMsFN5
         vUcupuRBuf6anHyd1FoCJMEQZ8I8/UzEpNfvsMh4eFh6T+NqXdnO6Lk98s1UCcx+LViu
         6EaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H2grn2aH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4eafedbb0f5si336921e0c.2.2024.06.04.17.03.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Jun 2024 17:03:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B9FB6615D2
	for <kasan-dev@googlegroups.com>; Wed,  5 Jun 2024 00:03:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 70D0FC4AF07
	for <kasan-dev@googlegroups.com>; Wed,  5 Jun 2024 00:03:25 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 60F3EC53BB0; Wed,  5 Jun 2024 00:03:25 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218310] stackdepot: drop zeroing GFP_ZONEMASK from
 stack_depot_save
Date: Wed, 05 Jun 2024 00:03:25 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-218310-199747-eWYxHxYWYZ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218310-199747@https.bugzilla.kernel.org/>
References: <bug-218310-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H2grn2aH;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218310

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Fixed by [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=70c435ca8dcb64e3d7983a30a14484aa163bb2d2

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218310-199747-eWYxHxYWYZ%40https.bugzilla.kernel.org/.
