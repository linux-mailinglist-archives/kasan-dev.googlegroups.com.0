Return-Path: <kasan-dev+bncBAABBNU34CWQMGQEH3CQMKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 98D8D841475
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 21:42:32 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-60297bb7d44sf59634887b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 12:42:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706560951; cv=pass;
        d=google.com; s=arc-20160816;
        b=UXyszhJ/v1z8ziKrpzOL+tYmjiMJd0jbZBBOaPtEJrOGTL/tlx5PJbiiRKq+IyfjN9
         jzKU32v1W0sdtD3S3buqRDEmdQZUiRh9VbjRL6bOJ59VPB/8aSk8UUI/492gIkPlWr1L
         YYAB8mOrCuTX42cof1ruuXIuPS7uYLndCt/2g7GoZDaAYXbIlsDQtyveBJuVycJ46xxY
         iVRe8wE45oJ5SO7RtTZyKZWR+o2U/Pg0e5JkOFVfJa5ey7IvWOpfSW7qUrA9f7JXZg1r
         hu7P3TtrqTFOd5nWapFykwxwDmX+s/cSolRJ1DaNWGNTpGUgZX7G3ZQzurcepBzr8U6o
         96dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=VQKDaTxbtnaSvF+X4wbaEBnfABvEDSh3l0j//fmEJM4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=lvFUmCUmzSwqf6RXoCvw6zBe4jIsk/N505kq9NxVkXzTmL0kkRJmuQlo2t4AWwI35e
         M5qvQk9jhTSPYuE2Y2kOq8akSYZsd7w0ajxH3dcATIwkk6apXgGutYNSipPX+i8wD7u3
         rJCPc0Od4Riy/YC2tCvtLQujftRiuRgl6n/JLj+gS+OYjHifobFmTndBNIjdCChH51ZI
         x++qwnFxK+C/4Lycm0cKwMgoPl+udunM+N+H7umPHH7SMYx88gFq3bHHD/PivSNJ58dr
         JltjGGInap5rh8MQAtxfDMQq+YUozK3/rWDGhLI0oolZ14ZwwlfxQ4XtJnN5kFbOksNN
         mX8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HrEvQMco;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706560951; x=1707165751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VQKDaTxbtnaSvF+X4wbaEBnfABvEDSh3l0j//fmEJM4=;
        b=Z9OmZkExDdJtQAT+IFpt5CGxeonCe0sJiVfiYISuiofUzh03uHwskhHFlxINXClr+o
         poSXJwUrZG3qHsHwbz2Bnkcp8YnJPd1+mUbQECjS23H70XuxycVrAY3mfgiRyZXVGE85
         EyjArot+YYdr2rAHrlZvopCV9xMfGM5F0QSEEJcmnDBIbskTqk0y6DDoQeZ3ITHIHeKb
         sFvDAu1u3HXumGYR3UcROubnmeQoytonQxQ7ECJtQlP7hxMBtYj8ZLzTCANcA6PD91Ni
         GPffYBxQG/aaiDh0C+FmriZe4yAcZAq9opGDMqLjU43eq6BSkaFmKmgRHuLO3KPb57md
         VsPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706560951; x=1707165751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VQKDaTxbtnaSvF+X4wbaEBnfABvEDSh3l0j//fmEJM4=;
        b=iOHzgBpKHeDlRfIMOkPhEusxW+yyYIpHrNWkpm/a91PTs/vIEskIYzsgp72M4kaI/e
         vY6k6BGH1QDn1rFSJi9zvgCYCootEQ/6Wgcj9mpMZ6NHsZBR/CSgAUtUu3Qf2jGV7K7G
         LcE4HX0GtTE/OWHPLExnOXtpK6De6VMrkgSt5OIRAF+IfDLZ9HU2MgOQBsXv5UHkUulv
         GzhWhgKO8IaVAW7Qs+52BV4YgMD3p78yeevrHnarVBmKVNmH34+NYqWr5w/T/InzqN0a
         WuVsmm+l8wWc7xbcFzbOlwfskw5fTqcm5S9wvhJr62KVkPE0kNmTGoQqjr0/NOHwi2/w
         AtKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyaPJnUXcSzH7SXS6C+v2rU+PLgolf5M9eA/94sz6Po1J+Qxlg5
	9Adil/H4oDTvlMRvYG01IRqXEnzA8cH0NbX6Lcr3bjUj/nyJiFrjyYg=
X-Google-Smtp-Source: AGHT+IGmL/LR2hgM1qz7jTJI3m7yRqm+klfjsDharVWpsevvh62MOILoF2GnP/YNf3HFdFMQL2AQvQ==
X-Received: by 2002:a25:e301:0:b0:dc2:53b0:6353 with SMTP id z1-20020a25e301000000b00dc253b06353mr2731106ybd.38.1706560950926;
        Mon, 29 Jan 2024 12:42:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:705:b0:dc2:65da:6d69 with SMTP id
 k5-20020a056902070500b00dc265da6d69ls3314965ybt.1.-pod-prod-06-us; Mon, 29
 Jan 2024 12:42:30 -0800 (PST)
X-Received: by 2002:a81:af18:0:b0:5ff:b0eb:1792 with SMTP id n24-20020a81af18000000b005ffb0eb1792mr4702160ywh.42.1706560949909;
        Mon, 29 Jan 2024 12:42:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706560949; cv=none;
        d=google.com; s=arc-20160816;
        b=FLUGdkdOup1podBfdOaumCzlE5mNxnYujRiLXHZdHxClaXV6heQ+Jx/PHPwZ49cyTm
         3wdChoo/bi80UR/zlKz8NTAQKrLwQLGuJX8eiomg25DFv3izbWDfiGtu65o03fMxZM6z
         LkYZ+rYZ1lvRc5KgU6Ndnvv3V3spua5fUExXYTenPIB+lYkoGZ960cTTB3p3ziOQDbMl
         BbsaTpLvH7bfFofLAOSM60vBKe5NCrQX6kzXCAsEwE3RN779QekqRyAYQyLX/cSx/0wX
         LMp1KxnSmpr0pQo2Ke+5CRwv4Z73IRO5IqflM9/R+uX8gBMLCglskp7hZVWt6kH5K9kS
         SE9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=3hYCAsQSvvmpT7hdl3vKQ0lFkg5Y+j3LCrKN/s9xE6Q=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=pVMmr5XCYcAD1XP950dgaw4lzeVNJjpxga49YkbK2ZACvjMFXuOUPLRoo9sEgpZfFm
         1RpnYym+tbxVDM5/uxnOOWCJ1qOgTzLrx1/Pve37rRdToHjOgmFVLKfxYMWBhqz1TUMj
         moo/QZtnVG2KjKFvbHxzJgiMTe5szJnTRkY6b0zOdYB0HJJWGI3+bTxH94GV9IKa7/oN
         enfr1KI7c6l1ovF5rG9oTnirYTHM7t/B6b1IzYzKHhfMNj+FoyjEURVGAoi+G1xUb59C
         MMwv/6QNGVjX/0XB1Fj1WMfW9hhSz7BcXDzWN3OkHqVBPANqUdKAUeRaeq7eeaRhotNc
         LVFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HrEvQMco;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id z75-20020a814c4e000000b005ff8221e768si869349ywa.0.2024.01.29.12.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jan 2024 12:42:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 3FCFFCE1390
	for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 20:42:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8122FC433A6
	for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 20:42:26 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6D878C53BD2; Mon, 29 Jan 2024 20:42:26 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214055] KASAN: add atomic tests
Date: Mon, 29 Jan 2024 20:42:26 +0000
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
Message-ID: <bug-214055-199747-heNnKjzXVH@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214055-199747@https.bugzilla.kernel.org/>
References: <bug-214055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HrEvQMco;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=214055

--- Comment #4 from Andrey Konovalov (andreyknvl@gmail.com) ---
Looks like a good start!

For the operations that touch two memory areas, we should check that KASAN
detects bad accesses through both pointers. I.e. call the operation twice, both
times with one good and one bad address.

Please also add tests for READ_ONCE, WRITE_ONCE, smp_load_acquire, and
smp_store_release (is there something else like that?).

There are also atomic64_* and other atomic operations not prefixed with atomic_
listed in include/linux/atomic/atomic-instrumented.h, but I'm not sure if it
makes sense to add tests for them, as there's quite a lot of them.

I also second Marco's comments. I expect that the test should work as is with
the tag-based modes without issues.

Please mail the patch on the list - it'll be easier to review it there.

Thanks!

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214055-199747-heNnKjzXVH%40https.bugzilla.kernel.org/.
