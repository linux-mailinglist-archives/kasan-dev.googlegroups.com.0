Return-Path: <kasan-dev+bncBAABBFOFUSVAMGQEINGC3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 461B87E2AF2
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 18:29:59 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-6d34211ce0esf3031917a34.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 09:29:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699291798; cv=pass;
        d=google.com; s=arc-20160816;
        b=qLHKi/T/O/x5Rk9tUAWThijr5xmS+twmBLKsehrqLaOhmEaRPx96J0AEnuEPGjmSlX
         HhhO5HoYnBpS6uHH/7W9kiBYm5FYPaCUkRPgLmPcqUG7Z+MmHCV3ICFv2Ro+iXydEZTO
         Oe+LfiNGUi3DpS7aF2E/IpD68Va65XTUqaADn9kzWO2ZmwnyZMGf/T0IJ/1x8JBgCbGT
         j4FMwL1AX+ehsqTSfF6+ZyOOO3zuwROL2XC/kie9i8MuRK9Pr4WTxbfWhf8/jt1iEnOy
         fr9R4TF4hB3gbdPwVpMvLjG5HJLAt1QEh7tZoy6af2SU+fefhSsNsTAAZsvt2U1Ijxd9
         oA4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=W4oNA6PGpwsJpiT/MjDr34Yxqg8a8GFmfsG9d9tWkDM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=q/QqDwOSXzVQGRqkg482F6E8gVf63VsUGwdeSBGMXfinOHdt3qZVSIOULrcwI8NV8Y
         bFh7mqZQJpR88R2ZvthXC8RCdQUM+q341SB9Yq5i7Kn/wANI/WLwM/ImTH1yJToXGbxY
         YWB3crQCFNK+k74/LQubdPLOzn78zUk528deviFRt7TdZon9BsS3QN5updGndEH9uSJN
         7XrOlYuqCXWzH2Gk1a/t0404kb4HiyyWAoGsNlFfp8HtZKZxPpyYH7WJ44eNm0EBYZF6
         RjG9bU9p6vK297F9OcXUwNjoNvzTu+PIi7sU0kjkOEyLBM/FrmRs0SmY+9bnNV3lXFUx
         AkBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jEJbvnO5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699291798; x=1699896598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=W4oNA6PGpwsJpiT/MjDr34Yxqg8a8GFmfsG9d9tWkDM=;
        b=ZF9TIOA1GLgY7rVr5yYBC7rs7x5m8xu9JVcWuN1pCFnN4fZpQ9oM3t2ySrIouHveql
         ckU7x4Uspt+UHFI46j6dxhg3bNN7CEVXhPKyQxPmM/MpK/uHfe09njRZiOYvmuMxWpIK
         +rmRzWRHUPyOVglYeN7cdUEDLwmT92qhip4x/1rrIV3/0/+DqCU/RzGmOz/6j/ydmnRX
         IO90lMF7JlIDNQWdHhbPR+G+GKRPkv2XiGCzxrj19F2GwQYqI6nqzufoDoRahBgFAubu
         EsXhzecqQrM0CiNnQL/kIr8u7YhPSlVk0dLJkkjZ+iouPCf6lQsU0keQEvcY0Xgn7HNx
         kDUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699291798; x=1699896598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W4oNA6PGpwsJpiT/MjDr34Yxqg8a8GFmfsG9d9tWkDM=;
        b=TKul45NPUmc2slZK2knVJTz2qcA19dHjokd12uvvIXT3rKtoYKPtkRNNsmqs4Hvj3O
         Tg9mvEvt6sUO9lTQqzk5RA5j8B+EgCNhSi1Cx/JJAytL0S/upI7VOurCls2Am+aSSbMe
         PlH2i/UCMWKZOTs0NXLU4MNfgx5J4MYVxtC+/+tr/dRYCg7dnkWy4bQVrR6a9I69J3hI
         FqYl1H4W/H2kKJ9gCxLTgSmD2mD6n1Iq7W20gv5FzyVeD7nDgq2BRdHpjKFua2jgUWtv
         ziEDVdA78KISImpd2Wdye148bGAubkih17hEHhYQ5S6fNJd2e7dYBQAt2dkDkuluyX2U
         S5DQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzgYZvAVp6WoyS8ZN97J5pcXH2R+ZnNA6u2TQLd8HAKnEr44pUT
	LiGQGD3Ci9nDqG7L37nNKfc=
X-Google-Smtp-Source: AGHT+IH90M1ZZs+GuE+ENxOOjsSSBnRNpWFO3N2tziv2cHA/fJu2fZXRmLhILx7Vr7z8aRJW5UorvA==
X-Received: by 2002:a9d:6390:0:b0:6bf:5b30:5b69 with SMTP id w16-20020a9d6390000000b006bf5b305b69mr31032929otk.17.1699291797732;
        Mon, 06 Nov 2023 09:29:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1206:b0:41b:5e46:aa61 with SMTP id
 y6-20020a05622a120600b0041b5e46aa61ls3679555qtx.1.-pod-prod-02-us; Mon, 06
 Nov 2023 09:29:57 -0800 (PST)
X-Received: by 2002:a05:620a:4148:b0:767:2919:f38f with SMTP id k8-20020a05620a414800b007672919f38fmr36520362qko.10.1699291797131;
        Mon, 06 Nov 2023 09:29:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699291797; cv=none;
        d=google.com; s=arc-20160816;
        b=V0oeBFVffJTDu+VEer5O3uYerMVNOQZ+eLERr4UKc+7gBSZrktWF0RyFdEeQ2LoGlW
         Yqwze/11ji2NqhA1syOBbFg7OAgtfPqpLX1KPtFpJwe7e5e/BWZ4HkB137F41DCLiv02
         SGEeDWGLpNirO5PG5rz6LEnsUNcFVB4ktWPVwhcJVhN6lub7uMAJg3Mb9kgFbOO0bjEM
         uwlzVNGD3q4vF6IQPjWOp0T8q/+1aS80iU/VlgsElfhr1VKrlJg6FApEeEg1v99az1SW
         ZERt7wR0pi9BETb2gxnR4xsVPHcADP0SvdpJFumLL4mzCb9gjSH/qwjgw6GydX/YNF0I
         vqJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=k8Ga3RTUbEW9YktR6Znkbtvmpmx25D7exHaiDe3d4x4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=L6LcMCIpEj2GPUvPYVwVQH5ETv0Vd0tALzwiediQ81x+93dRWUKKuvfZXN8KhwqGob
         p7FBmEAEMIIh//lSRU4fUd4ncE2A9wdpJ+nXE7QGZV12xiEHOEyvZEctsTHOefvmYbqc
         yfoNHwr7Ey3V08VmLFsDFOfoXszpWET5R87w/P2EsISWyfbZI+xd3zBu4v0/iMMSUPw7
         HULkxeEW2ZF4XTSuWAc9PZROLLBn9Lv/8DM33Bj/WB0bkKGk+MFqWs+gIl0fhXxpJ3qb
         KUg9HjyN5U4CUj86zrx09c2lI6XKD1MUOtaMuuI61Fh9LDNNmnDCVsbE3ffSx4BDzE6O
         yXZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jEJbvnO5;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id dw6-20020a05620a600600b0077576de1665si710662qkb.3.2023.11.06.09.29.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 09:29:57 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 8A31BCE0AC6
	for <kasan-dev@googlegroups.com>; Mon,  6 Nov 2023 17:29:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C7E9DC433C9
	for <kasan-dev@googlegroups.com>; Mon,  6 Nov 2023 17:29:53 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id B2041C53BCD; Mon,  6 Nov 2023 17:29:53 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216842] KASAN (tags): use stack ring for page_alloc and vmalloc
Date: Mon, 06 Nov 2023 17:29:53 +0000
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
Message-ID: <bug-216842-199747-F6jZlKCSNU@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216842-199747@https.bugzilla.kernel.org/>
References: <bug-216842-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jEJbvnO5;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=216842

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
In addition, we can use stack ring to save alloc/free stack traces for large
kmalloc allocations (the ones the fall back to page_alloc when the size >
KMALLOC_MAX_CACHE_SIZE).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216842-199747-F6jZlKCSNU%40https.bugzilla.kernel.org/.
