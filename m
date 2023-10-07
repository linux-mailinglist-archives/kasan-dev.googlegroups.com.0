Return-Path: <kasan-dev+bncBAABB5UUQWUQMGQE5OLPRMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ECF97BC769
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Oct 2023 14:09:28 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-505a1b94382sf3095e87.0
        for <lists+kasan-dev@lfdr.de>; Sat, 07 Oct 2023 05:09:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696680567; cv=pass;
        d=google.com; s=arc-20160816;
        b=BY08Cc1+bzKCYn++nsh+M3FIvsjyBbokhq8xWj9Elwzw4NLBnOVGYtnZ8uz1J0SstZ
         9SumRuBm3inKxTrPVm2AgHZMh23YteGoh815eU9KR441w4QEyCMy+PlXMMlbgzgWDuqq
         6xOEIReABlIXldwy0WP5B3lgPBVMIfQZzuyrKr62Xn4wREA2NrkQmNyWhg3USGk2ZRNV
         K3GWhSd6zf2OJMNJmm4oHK0NHH2EFlEX2SloaryNVgYyUeYhy2vQ4d7VD8CIDS92pIPg
         ZPQr8861lVXMSfrEGAyDgwV6BhwxiH21lVgyiFIHaAEFqacXkwqQyHw3xyAHWWD9P52I
         vhSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=UaSy7GmJuNQKRBQWcTRTuZn8752IhvFrglapba3V5Po=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ntOLZwHx3LH0PzqY/1Uyqs71wpCnj0xFEVdDHipWfBmRVfT+ppDCSh3z7CC/IoCy/H
         CLTwiRBPt/RjMUp+CWf4Qb8XYsxh+YesGJgqS9thgCs8SRMaJg8BB7OtHfL9OD+8bVlH
         CerQiONfwr1eGaQolmoNmt8NbVosRBKXriihioK5o/JDrZjo0luj7BRgFSobRF0GCdrc
         E5RMEjAZan//qbnSlQVnCVnYmaX/3AA9y6epSDvSi53VohdDcJlMEvSeoHowOEkpnQtN
         KK1o7yI4/gt03UBT+a42ygg+2ou3Nu6+J6sLMehahAq5h2VAMLl+zkeZd+0C7g1c8d7Y
         94dA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VOHSqVMo;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696680567; x=1697285367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UaSy7GmJuNQKRBQWcTRTuZn8752IhvFrglapba3V5Po=;
        b=SR+OCUZWJsKzjt7E2LxstLdJRV6musi5uFa095Ebk/E5eZlWp7JW86gYgCDoMMyWdC
         snnshNglXtOzF+rLYA3Xa8dVCBOgfHImrwb73ainPsjJREXutOxbk9yVq/rUm9mt3U0k
         +yo9qXDePYMxboUN7o2wF6FfecJ+saehb8hqkjv94qbMgHX31QQf795uklSUv1BgMtcg
         +colmMZJat+tr3ayZ/EHTDlTg972jOGeY6/GMamtJcTUgjZ48JLn25Em6Bc8ptoItF02
         XpjB028HaAM4de4S7Rvwt2M4o+DUXydBI5oAdAfYm0sujlVWUSyqrNcgE9Q35DrI7N1v
         4CQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696680567; x=1697285367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UaSy7GmJuNQKRBQWcTRTuZn8752IhvFrglapba3V5Po=;
        b=AhjCXA9Vxmih/bx1Z4SnzRP/bi+n7ANb23f20Xp2TylId0lHXXx0gMgrufcHvj64VG
         NjGWTk846AfaVKiO79DyP8XrLD+Z3H6FPKRWsVUMy4bPVZo9LveP4ktAi9j6dGJcDrZp
         3zORsmVgoBo/mYQQywP8ynJGsoFjnoPk1DKdwF663Xme5Awtsimy9JIkMc4czwdypzUL
         bYcDUWNushTQNwc/GILUOA1/ZNR47sGWuOQFBjhafk1khQJRZJ3kQiWrdVZiY388mFVv
         dTydmJg7eleni4vnc1b2Tm2rVQPkszUxyiDRDgW+N4uzeubaE4Pp8T4hR5p4488czSmp
         CmwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxWWUeZHNFuAtg5525IO7gm31KpdJNCdpF+houK2YzR1+0H1N8k
	40RpPzi+QHdMpLIUpSlk4Q0=
X-Google-Smtp-Source: AGHT+IGgnQS30r9zJO4HujhHjA9fhqLnFhZj2b5b/MaoREai3DUJtA5fgjkSRlRYqWGHcKudcdP9tQ==
X-Received: by 2002:ac2:44db:0:b0:505:7c88:9e45 with SMTP id d27-20020ac244db000000b005057c889e45mr161808lfm.0.1696680567178;
        Sat, 07 Oct 2023 05:09:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:98c4:0:b0:2c0:d63:6f2 with SMTP id s4-20020a2e98c4000000b002c00d6306f2ls1076529ljj.1.-pod-prod-01-eu;
 Sat, 07 Oct 2023 05:09:25 -0700 (PDT)
X-Received: by 2002:ac2:5b1b:0:b0:503:2924:f8dd with SMTP id v27-20020ac25b1b000000b005032924f8ddmr9770760lfn.47.1696680565682;
        Sat, 07 Oct 2023 05:09:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696680565; cv=none;
        d=google.com; s=arc-20160816;
        b=jxePyJKBeQlvd4mQG7IVeYXWmexPza/KTBfYsmzO6mQV+psgvuu/eW51qbJC4lW6nd
         C28RptxFC5I57QLy8CmnehArQMsIc1+TdtzDmPkIi0nJDvs4byMNv8THeK/OtBwyMImh
         HKSLVVB3YmOLrg7G3HyUy6c1+gpylO+RFUjsxw4NDCbv3dK+2T8lN4qaVY1exPAvTtEk
         lTGhHGxqc+jQCsQb3rPLZBFrKinWK5kHqCqPKPAsuP25AYEPdP3lN2whXXNQnQ09y9IP
         Haqj0Ipkj3pZhuqnSNvYsNhpN9QyZCKasKVg5rcNqy4aqjJAbjncPjncBSdgQkTpj3P9
         Uj/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=ioL2qZNUHoye2F6oDmc+/15c7Y6dLFWmZSABO18mjUQ=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ECyX12LFdv/uhOSLGFDz39F0lYsW8C2nxJFpxsmgj9hx/+xWKQ45PG+HQ+uqphS5T9
         4e78qqv5ibO/RbFGN3KviZGCIsjRqjFlKVHdbmjBSzH5DIuI0liEBCF/GnASbrqNBK20
         AQvkQN2y3/uj7Sdifl8S/pavGVZ+XRA0O65OdajuI1kGO/xmblydZ7iMHfNVeb8y8tPS
         EtQhfSbhcYFU0qv6YBMibeF//rj9dGSjOAF+aiEGYY4j4tW7NEsuRVux55cA9Tud3zfN
         l/xrtxRZ7UjPz+IaKJhJiOLyfzQRQ/dGjA7PPS4Ea03LLb6jkpdYDQrFojt8eX1ECEkY
         ZBZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VOHSqVMo;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id b28-20020a2ebc1c000000b002c29b97d5f2si328998ljf.1.2023.10.07.05.09.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 07 Oct 2023 05:09:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 091A0B8058E
	for <kasan-dev@googlegroups.com>; Sat,  7 Oct 2023 12:09:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6283EC433C8
	for <kasan-dev@googlegroups.com>; Sat,  7 Oct 2023 12:09:24 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 401D2C4332E; Sat,  7 Oct 2023 12:09:24 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217986] New: ODEBUG: integrate with ref_tracker
Date: Sat, 07 Oct 2023 12:09:24 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-217986-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VOHSqVMo;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=217986

            Bug ID: 217986
           Summary: ODEBUG: integrate with ref_tracker
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: enhancement
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

include/linux/ref_tracker.h provides ref_tracker/ref_tracker_dir types that can
be used to detect a number of bug types related to reference counters (leaks,
double frees, etc) with actionable diagnostics.

There may be value in integrating ref_tracker/ref_tracker_dir with debug
objects. At least to detect when active ref_tracker/ref_tracker_dir are freed.
Currently there is ref_tracker_dir_exit() that needs to be called manually. And
there does not seem to be a function for checking freeing of active ref_tracker
objects.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217986-199747%40https.bugzilla.kernel.org/.
