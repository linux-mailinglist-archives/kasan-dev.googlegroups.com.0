Return-Path: <kasan-dev+bncBAABBDMOQWUQMGQEEPG6KRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 87F5E7BC749
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Oct 2023 13:54:54 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-d816fa2404asf4000233276.0
        for <lists+kasan-dev@lfdr.de>; Sat, 07 Oct 2023 04:54:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696679693; cv=pass;
        d=google.com; s=arc-20160816;
        b=EznmOs3Xv+/YxQLe+X2xBdriofU7w9z6vd+pyL2Pxy/uFBjPCSx6qn24zaY0ucvG6A
         CaMB5Xn27X4iOkUKITn99QLDf+3arj/Gg/xZmzOxerbYuDkgtIzbL3Xll/ZUz8gfsNB5
         EaLbapR5H/zFB6vvR5ju8laLrR5cONNBAJ1BUUcqqpQ32dTlQW2q1W4apFTCKBKoKww/
         TptFahjQaDTJM30VFbrjpPGudXDtR2OavcE+e/JoayuqXWZcb6j3TPnaMoWG/y08H7hv
         5zzin/vq415F508dMZYrNF6xOQAsRE9oVt7SatL5E6fFei+a+HSwkbaqyCkGUrVD8rqh
         lw6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=d5pH26P+9iS0SWh+kQs8/sIJvdbw8tTIOHmSIBh783A=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=wpz+CVwEh4TlbcIhmnnDLzmmGPAostj056afWDWT5DmuZcIz36DOgait1maoAIVJiq
         sfiNMd0forkY8a+t0mDItKvzUz4gsy63cVKWhikiYCXs/4mMwsbiJ5XhBFPACEKvWD0j
         SfSFUpYNlumv26n9YI9J2/QihUenC6DOFbylzOPe+16o6MuVI47gS4pQCwq2dIXwMqSq
         BU0PcV/eNqsMmPSC4sJLhrby+Z8ZBC5OWJQ8LKJ1xQcAMX8qRUkwcATZx0aGVC06wI/0
         hyeAHY3xbTkxlnKnKzIFKFaIMhXxZ9K/6ThzPALIqw+LDe3v/CtSS2Di32mIISCEpViB
         X2Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ik3eHFhU;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696679693; x=1697284493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d5pH26P+9iS0SWh+kQs8/sIJvdbw8tTIOHmSIBh783A=;
        b=iP9YNZdBpDSZAM3EfvMjLB44tTIUa7BENw/esKYL712y8Wgq1H4oOUpydeXQZzxSvN
         W7M/tajsMaRA877uJez+RoX0NGoNpSv9apJT+YxXAuulZ8sn9pneIYb3K+YyKHrYD53B
         0f3OAoWjnS6wI5/MJwSKOB+pH1Nm/v4+tD5NDXdVAft2UJtuW5b/N0F9zP/sHGBHkbSS
         GA1qZDFoFKeMVt4xc6F1uXPyPJ6GlHIEhEiMBVMvkHuUf/B+1IQ32oovAiO5DqmgBPGI
         vKrY5cCrFNFMpCKNL3bC0nj6tKzyzI6OnY4FPq8W4p3eu0ZZb7dNNyPh32Wk1ZH756sz
         LwVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696679693; x=1697284493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=d5pH26P+9iS0SWh+kQs8/sIJvdbw8tTIOHmSIBh783A=;
        b=uVZKNo5RZplOBbpNIFJLezzPbW+Aej+7DT8oIKYNPz/ZnX5B7nt445XCmOnkFu2R/4
         fzCy/LtBU5QvoJUkJn2pS+agu+27K0+qkWbE6JClPqWbWixVdcp4JDrdCB8wN5Ju6lhA
         jO1ovB2K295kwhmllgV+zwbecmPy7z42X1NbT64QuNmR0Tu1W12J9E5UHkZ28W7gvKlL
         gUOuI9QUPpj/Q+vwX3tRvw1w0nYtiQ+WIV3EgssuyglhMY2FepV8QGIp1aEWOFajM0J2
         s5npmZ4ZSoSY2An9UBtvfYHJIdyiVcUOApCC0FiHbeZxy1SI8X/4ACe4iVtFha0cXKWE
         BV0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwfB2bYPfXittYaWq9uOzUiI1TgmB8YMNwFd0+jv17PBUSjhRAr
	ZiA5R3Iy1/OS3O1CZhlQArY=
X-Google-Smtp-Source: AGHT+IGOxRobyfqcZfKVdJHQgqU/8skQ8kYoxVNB6h9e2U/PWNqBXCodcPLwgfIlV0Casb9ljCysiQ==
X-Received: by 2002:a25:abe8:0:b0:d78:98f:4aa1 with SMTP id v95-20020a25abe8000000b00d78098f4aa1mr10257700ybi.7.1696679693287;
        Sat, 07 Oct 2023 04:54:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1023:b0:d84:ca32:aff0 with SMTP id
 x3-20020a056902102300b00d84ca32aff0ls181571ybt.2.-pod-prod-05-us; Sat, 07 Oct
 2023 04:54:52 -0700 (PDT)
X-Received: by 2002:a25:4d3:0:b0:d62:9b77:a41a with SMTP id 202-20020a2504d3000000b00d629b77a41amr9683266ybe.31.1696679692635;
        Sat, 07 Oct 2023 04:54:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696679692; cv=none;
        d=google.com; s=arc-20160816;
        b=PrNCBnSuBETVCMtGUXHdjdP+SMekYGHNYynVShTL/gZw+ohDE3HOVgVMHkHdmSCTdR
         l1WJDBxutp382ANtC3JkzTSGL7UHD+Ypkked08e+d5caPB3ts8Mpinypn55pA85nkj6F
         mKxYJXWxFSErsVJ7oYJAiErdhqiZ/hvslKl2/puVQ8Bdf/M2x6AlqCGH/I/do/iHOt5n
         HBeEkaiqrHwPR8sdqhnFxhL6TlTIXVGfsD0AwxwAzhd3sKXeBH6pq6/xgUDa/YizuHPw
         h5OZTW9qn0kq/jJiXVDm1zs+eHTST5AXpbpHSbjYAkbHRiyWNzQr4I5F4aoEDZ3dZh6g
         gUMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=K1Lh43+Zb3Wg/rsK4GqEgAFieGG7tLloU/tfFNWiZ1k=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=mlwI5ip5cEaRvFAecuemrDIt4OPJpsu5A6k/CCw3Uvg1q+JbRryWkGbmilop+C7cti
         d4H2L9oqZeuJNNrbuA77s/9Kt7tI92oS9UkjPHVMRDNk6cLIfTdQOLEfEoOTjzW4xjsn
         Cw+YTjI2B9hlIVvDoOh96v15ImQbVeZdrP1wIF/AqN1c9AJDPn6/WeridS14l+QKN227
         kKaaajXY9uRI7qoADRcigrTo4iUuYI0P23ImNz54CNT9LPJE+yXvTtNBNN2rBGYZiu4+
         Gzu12Ph4iM4G2lcThVEk9dKb+NzOeELOeOqtKkp1sdWeFMTR0Aa1DBVJ+XFlqSDU4A31
         eLfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ik3eHFhU;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id pr7-20020a056214140700b0065afe245389si440251qvb.5.2023.10.07.04.54.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 07 Oct 2023 04:54:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 052A260E04
	for <kasan-dev@googlegroups.com>; Sat,  7 Oct 2023 11:54:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A8EEEC433C7
	for <kasan-dev@googlegroups.com>; Sat,  7 Oct 2023 11:54:51 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 8D182C4332E; Sat,  7 Oct 2023 11:54:51 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217985] New: ODEBUG: compiler support for freeing of stack
 objects
Date: Sat, 07 Oct 2023 11:54:51 +0000
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
Message-ID: <bug-217985-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ik3eHFhU;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=217985

            Bug ID: 217985
           Summary: ODEBUG: compiler support for freeing of stack objects
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

Debug objects has debug_check_no_obj_freed() function that is called by slub
and allows to check that no initialized objects are freed (leaked in heap
allocations). Freeing of initialized objects can lead to leaks or
use-after-frees.

However, leaked initialized objects on stack are currently not detected.
There is destroy_work_on_stack() function, but it needs to be called manually.
So there are few calls and other object types are not covered.

We could add compiler instrumentation that would call a runtime callback with
pointer/size of the stack frame, then it can invoke debug_check_no_obj_freed()
to check for leaked objects on stack.

Or perhaps machinery in include/linux/cleanup.h be used for this.
E.g. we always declare a clean up for trackd objects, which will check if the
object address is on the stack and ensure it was destroyed.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217985-199747%40https.bugzilla.kernel.org/.
