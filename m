Return-Path: <kasan-dev+bncBAABBC4YXWPQMGQEGU3FDVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BFF1469A872
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 10:42:36 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id v6-20020a05600c444600b003e206cbce8dsf475793wmn.7
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 01:42:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676626956; cv=pass;
        d=google.com; s=arc-20160816;
        b=xi+BDpCZ+EoG5xxMfTyqS6OIGiBjB5tAWfRaVdC7zMCfzthWVZHCABTDhBrBIKmqmh
         bpAw85/ors5aaHZDC00pyYx5C/kNeyUNx8stxYXJ8MnC++VHt6CVzGut4thmW1JxNwvb
         ma8xEX/Shrtr7viRuxxCDILInHL3xNg3704KucFlTZ+cIxs4vClBWi7gnkxOlPTZCbLT
         XXym3mug91YFOrKv2NlBYK6sv6RXOVMc2cSk8/fWpLAX6V9HioTu6gCGCjiNxjhPUVJL
         2DWyWMfGOa1qUtMU2P9fSeBEQWD1kqzTWOX7zZ6qMW2BpWiNvGLf2omd3PwDbAUNunpm
         InIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=HbCpnuVvuxR/4l8O5y51hoSYGGmvJT2MbnraRqO6m4U=;
        b=XuJs5Mgf/xdFpdiasRYEbmA/OuC4a1C7JSohHlGuXyNaxQ1GB1SXB6Dfzrz/kJq/ri
         BFkd3JNZQHwtKZgCr30zJhIVPIRLI985XxSNg33ENwxS/zNr4VzqBESvAKyTb8aRCRjY
         GXWz0f0wX/Ach+UUcKECf1yOHasvcPZP+fuypmDUsoEiND5ieMJ5sxluWxOqQDWe1uD7
         ETqVbcDDAOZscYw2JFfrFsnspHohM3StqBk6Y6VQfW1BzkxvOBCzvbbfcC9siO0f1Ahk
         GFDOv1MOksGj72N4YjPSff0vNk8UPs/2IvOGcCKMumT6cd/X5aMlniGO3IvY8hPFHppM
         T/BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Nzd4i5eX;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HbCpnuVvuxR/4l8O5y51hoSYGGmvJT2MbnraRqO6m4U=;
        b=FoQPi1+r9Cqs+rYdppnRZTOcQ4zcc6DAVzQcWWKs8GoCsj9BS67jYWzLh/oK+CLqQt
         AcExlYS7UlENnFFuRsQ/DBO9o0HZQ3a3esvDVwqLtQvN1UYTXxP0yqFqhzmr92vu0giR
         jFRsaGGm2lmUAOdAotRcuqziD34uQZQUzJfZ5jXU3YZvCIKvmOK+UHG0Bj1+9s1N28Jg
         PvuQ08NDa6FYRhOU3BbpRo2u2Icw2le8sw6Sp6T5H/LwOramOhUisAPNJQ5YFk0A4mf+
         AMqUwduFDyaAap2tm6k7F9xZGhS/pEIqOrk/BAq0qwiyErS2YI/3C7RwYZXEHyS9yTuB
         b/Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HbCpnuVvuxR/4l8O5y51hoSYGGmvJT2MbnraRqO6m4U=;
        b=1iBIfSGcXnZykxyZgbWsnnwa2/r81JhqQqyjmNxQ+zV4/7XOVpk92YDqUxKZngq2pW
         NiSSyb9gWNvMLPmPbOaE09wOy4K6UBsbH4K+gv4KaTu6WNUFOZ2fH42spM9IXhPwCdwb
         +Zjxpyi1In/LE9+7UN7/lQpcLEio/CHkqS5poZjJ4RwP+75ZM2siGFwsxmcvj30/F4Yl
         0yuws2d0YbTv2XfdI7SjALc+otH2TynaANHnNaWj5GjG9kblaRkJA3jHjMopaP1V9z+t
         MQreWqGr1Lr93g/tcHnxF/OlS9hT8bkJOVN2EKJ1cAuhyw3d9WR3jgCZTszBiXttbXTj
         0MQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW4oi/zplwlP84OVMFOnFQ33AkeT7+MRtL6BgUppJe2Qo3OUnQf
	l1yeJzGgoNqs6r9YZDAUXIU=
X-Google-Smtp-Source: AK7set+JsYzrecKd13ZfqKT9HVoed5x5E2EX/Xgy1BJAr1LXXYm/SU0DtLQuIhlgj9J8qWgURiXSjw==
X-Received: by 2002:a05:600c:3484:b0:3db:1d5e:699 with SMTP id a4-20020a05600c348400b003db1d5e0699mr416285wmq.195.1676626956174;
        Fri, 17 Feb 2023 01:42:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b22:b0:3e2:19b0:7006 with SMTP id
 m34-20020a05600c3b2200b003e219b07006ls35624wms.3.-pod-control-gmail; Fri, 17
 Feb 2023 01:42:35 -0800 (PST)
X-Received: by 2002:a05:600c:1604:b0:3dd:af7a:53ed with SMTP id m4-20020a05600c160400b003ddaf7a53edmr7068992wmn.11.1676626955044;
        Fri, 17 Feb 2023 01:42:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676626955; cv=none;
        d=google.com; s=arc-20160816;
        b=vY/ogHZofEh6rgS2/6LPalsj0TNyT2Nz8Rl/QeisswPPCFlHXVqycc/z4LBfR5MyU1
         jDdejXAFTcbb+nD/XV5yFIelg3EOiEqFqSSaPzKihn4tx7Hg2KvW4iJopdn6UUfvAfB3
         1ih1g6jHsTjEYSPq3cPlT/k+MZTUNFNvY2V9ra6D/0GL+6+Jq614rJF2Vb832eTbhKFr
         WYzyC85j2xAachVBd5hywF6UsHRI22WZG90NJZQJTX8Hy5xrqDLkgH7a/0BbhOKK/UKv
         SCUVNApA+qM3f6oKBYKfCME8d3fzY5dUxU2CkirZ9AfL9nj8GBzEa57KCDXdl6D6YesH
         tDbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=NoYxI/fFxxDDD8qoErWf5aL9j/bws/Y1Njxxd1d3MXQ=;
        b=EHa90r/KX4S8bGeCaD+wkfqlt6O/J+oilJ3jTE9f9uYqY3Ww4+/IuXLM5V5V03EvYd
         kJO7F32h8tUPpxB7zM6yBNODm4dR2ZtVdGkz2yYJlQqmOmsU3Byav2eHRhOJHYh8OXS5
         jQ3C0tNgsVcOBIVzcyXiIQXERCn6sXBcxI1o05mCV64VtKlXmmkeknpMohqwbj4yqEv4
         yf6MSPIXI1uitEhPum8itxD+asXvDNrwgqRzNYdMAHH2yJ9dEBbJiU9i8T51pyAJgkAO
         EjAyTbJz/q/BwPY7dycMCZcNKp4h24S2glwkucZ585BD0uZgMbonVas2X2mlQm+hAclx
         fgCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Nzd4i5eX;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id p12-20020a05600c1d8c00b003e1eddc40cfsi20641wms.3.2023.02.17.01.42.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Feb 2023 01:42:35 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id B9F56B82AA2
	for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 09:42:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 54581C433EF
	for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 09:42:33 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 40969C43143; Fri, 17 Feb 2023 09:42:33 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217049] New: KASAN: unify kasan_arch_is_ready with
 kasan_enabled
Date: Fri, 17 Feb 2023 09:42:33 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-217049-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Nzd4i5eX;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=217049

            Bug ID: 217049
           Summary: KASAN: unify kasan_arch_is_ready with kasan_enabled
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

From [1]:

Both functions seem to be serving a similar purpose: for example this
patch adds kasan_arch_is_ready into __kasan_poison_vmalloc, which is
called by kasan_poison_vmalloc when kasan_enabled returns true.

The kasan_enabled is only implemented for HW_TAGS right now, but it
should be easy enough to make it work other cases by
kasan_flag_enabled into common.c and adding __wrappers for
shadow-related functions into include/linux/kasan.h. This way
architectures won't need to define their own static key and duplicate
the functionality.

[1]
https://lore.kernel.org/linux-mm/CA+fCnZcnwN-FGbteoMwFeHrGoM-5Gv5bs2udvRtzk-MT6s+B9w@mail.gmail.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217049-199747%40https.bugzilla.kernel.org/.
