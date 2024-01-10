Return-Path: <kasan-dev+bncBAABBPEQ7CWAMGQESIHSIOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 635F7829298
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 04:00:14 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-40e53200380sf4764885e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 19:00:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704855614; cv=pass;
        d=google.com; s=arc-20160816;
        b=kHRXAnXcGHUcR0kCHEIRSubBXJcdf1kHnrKkpc/2PRlc7s/y78/YVQvdX7SkL/xVQA
         X1BztZQ0loKx0o0HVvMMOFwJVLeFIKHMVPrIJOxI2GUTMGxj+S8AsYzHH8mEDoR9/zJB
         3M1NJ7aSCdyAo7YCLxh2rLJkEi2iM1/5vxpKiuTkNYCRwl+abBn7eSeu7HgOkemSTEzo
         6H7J8Hwp44EgdquphqrI3392SSt1qAUVKATd5a/Z1ch/88LZDSmpgFp5JX8wKgZVlLX3
         QUsqjzyNtLoZXTIX8Dit7ecsJzGmTdmyBVeFG8amAnbx00K0qGOtmFeiYQekOdZC4rd4
         DDBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=yRJRPsJ5H4FAflOHn7VRLAjzCq8gBBsyH/CR/d2R9Mo=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=OjU2UndwPOmsNtUYl5Ivlz/sE+GfIzHkSINxnoV9INAp+QRQeSMTlVqMS2LN/WBLlR
         Mfvk5j3RVp2JEyUZVA5e7b0mxwf5XGGjWvHg/FmeBz2Q83oaLVgI87YiSdnwdMgyhgnj
         zUApviV0p/bXD/JpYex/SD6IwdEkHHrVbIbFfZqoneL7XB0UEfM13NFpEVHlbd8LVFSH
         lD2vaNB3FgshM5os6XGDh+0Pa0E6nH0V5HlSfPuj3vrtHLfjUIN86b+HOTGaRLYUZIR4
         TiN178I/2m2tn3N47s/qHbLXfxm0pWdF6NeFp8econesm1Exi7vE4IQfIdIMWV45ejv6
         OBMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b5M98uma;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704855614; x=1705460414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yRJRPsJ5H4FAflOHn7VRLAjzCq8gBBsyH/CR/d2R9Mo=;
        b=rZFZ0s1zcHtERXOOS8Fp7J1MX4JPBlt8mIsclEWzlG/kT3pe24N1j7d32So5iR+oj0
         QItZ1UI0l7mmyIlVM1dBcgpd3TsXjYXDyFJzZx+9837szKTmvG3HrA6r8Or3xKi2skyI
         wFqtCzuC9e4SK1oX4haJN3+x13LisMEwk5a0rSzxiqGInSyf3gCcbE2sVUCbT775Hp4H
         DoOBIl8zniJCIEmx4JxCWSkhtLd4o3fkGfXimeUqNmvtimpjA90owaDAE98jJFmqF4aV
         NN9LHBASB/r7mTykGTF9+WmavB4km3R8P4hraGJQBqcFrF/unXyiECARiGHxWyYPL9Bl
         InSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704855614; x=1705460414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yRJRPsJ5H4FAflOHn7VRLAjzCq8gBBsyH/CR/d2R9Mo=;
        b=U3++LGTgUIpHCoDI87A5U/chokacQfrh7SKM3g10wfgbIUK4Prh9NgRmWV7UzEqpfk
         8uqPctRE2SsdUlrGof/JklB2iAA/i5CXxtlwR/oMG2zXyS6Pn9B6wA4PbKRhJkjk442r
         K7V5NCboF/XJ+xfUJ6/Yh+6IFYF6vnaTBpXXdOrVpkhPQ8gTAKrJO4X2rFH7kba7LEZa
         VBoAqdacSJMQTihydtmXugM2+DFW1giJRRRG1ns+peg+B07iVIHKmGuYyePtycpP1B31
         q/g/mpaY5n7gKoc7UvGqMQmzw4f9gT8va6dNp+hRAssTul7J7JJGSRA+Jp7cMC8izQw+
         zSGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyZKl6GlHHd99rMvXfnT6xzA9IoxYpQgImc5qGo/vuENKzfvZ6l
	3ZI8hyTG38+j9ozMSHIK42g=
X-Google-Smtp-Source: AGHT+IGAnbFKEI0FqvmA1hki/tYZnijmC13rC/WF21yHC08ui3Oecr7Y8wDbHJX8qzuQfgZ2/80SLA==
X-Received: by 2002:a7b:cc07:0:b0:40e:52ed:ef84 with SMTP id f7-20020a7bcc07000000b0040e52edef84mr122210wmh.149.1704855613160;
        Tue, 09 Jan 2024 19:00:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1395:b0:40d:5b89:6a14 with SMTP id
 u21-20020a05600c139500b0040d5b896a14ls2923649wmf.0.-pod-prod-06-eu; Tue, 09
 Jan 2024 19:00:11 -0800 (PST)
X-Received: by 2002:a05:600c:4292:b0:40e:53f8:5230 with SMTP id v18-20020a05600c429200b0040e53f85230mr136491wmc.76.1704855611638;
        Tue, 09 Jan 2024 19:00:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704855611; cv=none;
        d=google.com; s=arc-20160816;
        b=q8ZL189UiyM8katAM+NtjcC4KshnSsewc22p29qjzgCgA+FEJK4ZBcyfTqpTwNLABm
         mQVIrgTF71tirPhT/vaVA4AzUKcleHa3swwNi0c/qV2rc5ovBgL1Oyit2kI6VBJo4Emp
         5JZCQUqrcIsd/K92Tz+TCgqYhlATkIFRoB0PDsy8HXJRs6iQPujh09dreSbay4JWXMMM
         ELQAz6RR3AnbbCFMFjZWGLmK9yj9v3T/P5+WipOuAVtCIh1AD7Sy90dlJ34ooaGBxOoJ
         9I4U4xVIiejHOxWRveZf3n6V4LdWs1K6+0nkKB1OXuuK3BVOPwCDWHLyrOUaJpTT5M9/
         leDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=QLRv6JcmxvtcWj75Cm/05T9WTGc6AR8frf6Pmdg8j8A=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=K/VSkFilFuE5MtpVvrDmO/wrNb7XJVnOxmkwYjuGDm3oBY6mO6B7AXWbnE8Dzr/KiS
         4VoSnw35q5tjnC8F3G/SyACoKm3+F6RByX7rILaCA3IXNNWKA28NfdU2TNDdwCPN9VGx
         hvvqGvK1G3Hi7jFXfZWfYPbB9JqNSItvpXKvtBLcOFS1318Se95Mm2PmCqo94yaLXuHd
         uUHe4OAlSCd2MP/DDbFogSaocUbYYt6jFUl9PI9/dm5/weusNl52kHmnlX9mbkxKM7Bi
         m1vn6wdo6rUfXOkyEkVEZHQMo6aSw7HQEifaBp3Eqn8EpNtwxNPPWrrV3bKMiQPtMF6c
         Q0+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=b5M98uma;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id m24-20020a05600c3b1800b0040d44dd4133si10893wms.1.2024.01.09.19.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 19:00:10 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 1B95CB81C62
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 03:00:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 21AB6C43390
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 03:00:09 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 0AAF4C53BC6; Wed, 10 Jan 2024 03:00:09 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218358] New: KASAN (hw-tags): respect page_alloc sampling for
 large kmalloc
Date: Wed, 10 Jan 2024 03:00:08 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218358-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=b5M98uma;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218358

            Bug ID: 218358
           Summary: KASAN (hw-tags): respect page_alloc sampling for large
                    kmalloc
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, KASAN always poisons/unpoisons large kmalloc allocations (the ones
that fall back onto page_alloc) without checking whether the poisoning was
excluded due to page_alloc sampling.

We need to add checks similar to the one in kasan_mempool_poison_pages to
kasan_mempool_poison_object, kasan_kmalloc_large, and kasan_kfree_large.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218358-199747%40https.bugzilla.kernel.org/.
