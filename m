Return-Path: <kasan-dev+bncBAABBEGJUSVAMGQEDDB72QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id DE7B47E2B0C
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 18:38:25 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-7a832e1a358sf468041939f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 09:38:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699292304; cv=pass;
        d=google.com; s=arc-20160816;
        b=srUiUK2OmHTvv2BeHa1hWpBUm8jgUkBU8SYwj9vrkWkwIBBMLiBev/4GRaJgeN/wgZ
         qGE/iCBHOUHAHi2hmt2pYqabZOVCnRcDW6Ks6rr/ydpvR00nPlvUiRNDRhy8tLO9O3OQ
         Kthq7o9DFkXNxOk9tnLUjHRYnrgxxIACCZQpoE+qrL1mrrO4t9O5AOrcf2403hZPjJDE
         0sNs7gvKbGwOMK2NXZsMF/dCZWS+ImJQPhGq22jpF0luvkrCEI1vFS4QsCM1P0VQwoeT
         0AtCnDR4uXrO7x1TqwO12XPn9T8Aln8f4IOY1oetrvOr7zT764WyO5/osClNxQs43p9v
         qBQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=3iY3yj8viZeSBIqphuR3v9vciVPagO5pJC87YkZps0w=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=C8I52t0l3UZo0seds7wbHnG9zCE4XJ2C0MKPRSD9ljGryqwUyLZUPLnQFgPYitdI3s
         EVGzX2PmF/R8MRUxEbg2RUta/vsO8Ilj7dpFGrZxgS0E236FXVa1hh0xsxKIbsVhL843
         dSrZtmPCImAQFa4PGvmyfGMAePmM6E4QakT488AT+yVo41RzAti7+6rKOcVeV07ZPZ7c
         1Na/dJMrMhUuCwk5gNR/+BgBHbgo5Tdyhip7upZAj1ZCeEB3aM5RSfsQrP+j7aFX+W2C
         CwLMCqwPb0pv7JJB+tN2OBHeOPUDYhjnzAqJUByuvF0/ox81aQJJlpeghm4XS78CQimr
         8+QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ux2XFhJE;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699292304; x=1699897104; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3iY3yj8viZeSBIqphuR3v9vciVPagO5pJC87YkZps0w=;
        b=hnTmcVvtMbeGQwY1t4xORHjgNpkak9XZTA49xODwurkH+6yeOIZDCS0S3Nr2uL//SD
         2Nd9nBwxkw2iFD/deHPsm808TncZXXNzw5fO76W8yInxYq3v0afWKVvnxaridpSvaDti
         X03UI5t3AiiUcw8w62WW8OegmEZYqaroGATIJEntzci8mQ81N6Mwk+rQJ3eShNaYD9yd
         ypnl5NJvEcwMSo0iWMyYOinQbC4/tyErXDCd+e3l78EKLVtPFuicD0cTXp1jrMXr1MQj
         MzFaAbPHzQ728qckPvOUYsfpj4suqTZk0QkVSEjB87fBr5dUnmJSicyM8Z/ptsxnnCm+
         J/Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699292304; x=1699897104;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3iY3yj8viZeSBIqphuR3v9vciVPagO5pJC87YkZps0w=;
        b=REO5fOV+62a8owreKxLBVTP2z6devpQG49WEzOqPCuVEFgX2rA/gcGH+t6lk8v3Ugm
         Mq8yeX5j0pTIUHnARpHSug/j2Kvf/JLBVIer0LSd/HqOyxcmdhaP+Cn/r4UCpvqAPphA
         33n811+oRrWonCp2o6v/5Q2f3wWswytZx1k5eu0GqJbjTAFXxxoH/Zuu4sJC6lFIHYZj
         bfTcsQzcGemIhSFvptZkraP7CB42pvIxrXbraC/1YOd6Kda3JczMj/ZsgDhna0QK93eO
         9zXJwN17nXUibqslHveWOGKG2bLddHPdMrEuEiVWROx5ncAHCgUilJOV1pzoq9kingso
         AtSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwyAuZJPujazuAwKqRzzm5SuVQZkkULajcCpc5k12dTTJwp8+r5
	EpYH/uDhwpHqnDLpAqxYhRg=
X-Google-Smtp-Source: AGHT+IFuEYSjVb2lsBV2kXF8j6tiuvpgf4mBtHUOVfjgSLlZQMguNYIN9AEhLaB5L/F3FDzX27IbhA==
X-Received: by 2002:a05:6e02:20c3:b0:351:4b68:ec3a with SMTP id 3-20020a056e0220c300b003514b68ec3amr422310ilq.9.1699292304400;
        Mon, 06 Nov 2023 09:38:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:16c6:b0:359:48ed:fac7 with SMTP id
 6-20020a056e0216c600b0035948edfac7ls597601ilx.1.-pod-prod-08-us; Mon, 06 Nov
 2023 09:38:23 -0800 (PST)
X-Received: by 2002:a92:c26a:0:b0:358:cf4:4fc5 with SMTP id h10-20020a92c26a000000b003580cf44fc5mr409535ild.25.1699292303838;
        Mon, 06 Nov 2023 09:38:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699292303; cv=none;
        d=google.com; s=arc-20160816;
        b=Bhn9dSextD0K7DToX8RfaZxCaBJns14TuqHodtdmOZrcTBfjFy8lXOTSUYrzg16aja
         eyXK8FbxdsrpIYOP/XZWsueyeDYEKvlm+m8nFHx8vMy/SM72PWGbloDJOVhji1+Ds/wr
         cJf7Zo49tbGAucNGjQvwLmRL3GkhaavOvnOoA97LD/EjBdiz9bj7dxVpMHPi7ik4TY95
         pm4wEJCako0Os/e4IcUX+tjicf3QZM9ZyeRknEEm6aDS3KRH25T2FV4xZj54GBg9AvU+
         ghkia1JDkGoqymjeuRVYC86J+0sBVD22AsfPZda45AnrsvxQ9S01MDKuVHljYUtK3pys
         cxPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=oSlErSjkK5Bq8eK84WV+P9emLzomL9IioPXr3SA8XmE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=xAy4LKtv5KxSQoyYY0WzyolfMVV8IwTremRNJzO3JXmoiIpvLJ1mGdR5Y7IMJYLNew
         VLZa2ZhwfwakB2sLv1OklLVU7TPD20ZG9eThBSOWuNqOGmlvcNXqr8YHJwQre5/Kj/ti
         lgWVUQWJ6Y91MaSgbZnoJS/R5IVuaMrAvnb0HQinXkw9Z3pN0Je6nU9O6wjGvFzl4cni
         pzKahltN7PJ+3ihGEJWAFRH+ax21ylq3v3X9Yr3B0VE0Gef2sMjhDDnHFaCstgefINGo
         6LShWB6rKadx7Pk1Fn/41+KhsUDZ0WZOPQkg72EKpxNle0oanSoHAQCIYDDF8XLIZIgs
         +98Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ux2XFhJE;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bf11-20020a056e02308b00b003593282e594si1330866ilb.0.2023.11.06.09.38.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 09:38:23 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7E9D960FE6
	for <kasan-dev@googlegroups.com>; Mon,  6 Nov 2023 17:38:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 2F764C433C8
	for <kasan-dev@googlegroups.com>; Mon,  6 Nov 2023 17:38:23 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1F757C53BCD; Mon,  6 Nov 2023 17:38:23 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218108] New: KASAN: save stack traces for large kmalloc
 allocations
Date: Mon, 06 Nov 2023 17:38:22 +0000
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
Message-ID: <bug-218108-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ux2XFhJE;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218108

            Bug ID: 218108
           Summary: KASAN: save stack traces for large kmalloc allocations
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

Generic KASAN only saves stack traces for small kmalloc allocations.

We can also save alloc/free stack traces for large kmalloc allocations (the
ones the fall back to page_alloc when the size > KMALLOC_MAX_CACHE_SIZE).

To store their handles, we can use in-object redzones for large kmalloc
allocations (when they are large enough).

Also see https://bugzilla.kernel.org/show_bug.cgi?id=203967 wrt saving stack
traces for page_alloc allocations.

(For the tag-based modes, we should use the stack ring instead:
https://bugzilla.kernel.org/show_bug.cgi?id=216842.)

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218108-199747%40https.bugzilla.kernel.org/.
