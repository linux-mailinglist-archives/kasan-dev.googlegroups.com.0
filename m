Return-Path: <kasan-dev+bncBAABBKVQWOVAMGQEWEALYIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E3077E6AE3
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Nov 2023 14:01:32 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-7a67ff977ecsf64762639f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Nov 2023 05:01:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699534891; cv=pass;
        d=google.com; s=arc-20160816;
        b=HNEC4tvSEehHlh/6tk8sQ45/fbpBqd1JIuAA1ThYMlN2l7o1G6ZQiMuyb/LCY0+BLe
         ndpgmBWrNmdDmjHnZ8L/TYnXeniO4fdVsST/SJf/LHejzQDJ+c26vd57R0NV3cl6ym/v
         B5wybPUXtb9AZnLNO4apRQW1MDqzO2FJP6FbbdWPRfqKmCdPfvC/Ox9ecyOprxNuntUb
         +q2BcgKkfNk2FIsGxO9kILFGu49Q3o9uWaLZVW4kqLLx8PSqMxuTgLRlCIBChpV+gIBk
         YbccoMSVtPRkm0rm35ffGUP6N4NaX3Z3g5mUDYmQCCuPS/ifjQMTH0aUgrR2foPxOnuL
         bprg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=qpb6zsVfVIwx2lKdbWM0PeCNw+cMW39/dOYyL2tK5VI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=n5pAtv59ZzWSuqt9r3M8rRt1bcYBOJ6B3ENRS9A3kV761rKL6LZMtEMbe2L8Ls/Ubz
         V7ToDiQQ5211gbOuSlidYUwSBKvkk+6N63njuJK34KYuBUg2JbQlyeQuUleaE6pEfXiL
         Sl5kTuJN0ccYjWlLRpVgTpNeb4o5t8KlTRQybwDTn6MhGTZjBK+pe0DFR71S2cHMmGBE
         mIZctW9VmyjqvrPD320Kn/eL8yBqB88/lcfjV3MMwgupQqp5PcdP8R93HvQB8A62kw5Z
         GF0cN/K6b1H85OH+P+FC07obsuALTgyQjXIG9sjrVq9ulf3wQ6FF2oLQR+1BlHHz3WnJ
         9Flg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XZRjytV3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699534891; x=1700139691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qpb6zsVfVIwx2lKdbWM0PeCNw+cMW39/dOYyL2tK5VI=;
        b=jlvbwwcXodc/48LXQ8q35gt1rlbua+nDy6nhc/Ho52iL274UAvsZQ29ONrlAZmMker
         3JzoHdbVTchuXZaQWLvj+GrPY5j+gfsP/BSDrT9okyGCcGe2b3F6WIQBYAf8nQwtm0L/
         gg+wQ+eVBSD607W0POeuk13s9q09IORsk2U01UQJ7c+2Siv48pltNiZoE6xQj6O2TWSf
         ufu7uVHGg3Xq59E7N62gti1+Zirtk/YGj1rjBg7O1ddA1RkICsKNpd0gFvXh6r+pYxnO
         UJp5RfV4sseEWxO4lc3bMPPL6NQDzSVRLIAvIVhsu3hWewscnj2k5qjWo/fTut6D0k1U
         J44A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699534891; x=1700139691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qpb6zsVfVIwx2lKdbWM0PeCNw+cMW39/dOYyL2tK5VI=;
        b=TmYot+6j36wXaoFQExAu0jhHRMYBBcu2sU2C/yoB6aW5YctXLPOPdHLUcXyfjjxtgA
         2PA8AW7kA+ToSI0qns8HPGa0aXzdEAxs17+zO/chLmtHPgLzgd1PUduKWSQkU+W4H6vd
         Z1VsK2fWEg42DgDcWf3jgSqD32glpb7KMk493AUSjFwOT1+znOCbOQwk45V1zHG4bSWw
         +WKmNmlFs95Br2ty3yF/EYj+uTPAjTMMe2uI/NbdBT4Epi6SiWCWhTI+lLmwoUjCjMZI
         dsaFQ+RoNFrSruQ4fDWFAFRiOrww1fo7kOSmtWSYNuqQtskzU8NkHP+5gEchkknNE34W
         v4mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyIq5/+3v1H1PGEkoHkqELcrWgg7rziOlOjBk6hBgRnZBIKaY1Z
	2RV8RMbkB3NC6TqmI++RDpc=
X-Google-Smtp-Source: AGHT+IE29OG9KOrBBYP1MZ5os+puE4TcxGAEWk9Y6MaulMhQXneX7j+h9CEDS6GR3VGR0yJgw15pNQ==
X-Received: by 2002:a05:6e02:20e7:b0:359:4726:900e with SMTP id q7-20020a056e0220e700b003594726900emr5498659ilv.16.1699534890496;
        Thu, 09 Nov 2023 05:01:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:4b0a:0:b0:359:4b03:d945 with SMTP id m10-20020a924b0a000000b003594b03d945ls424609ilg.1.-pod-prod-09-us;
 Thu, 09 Nov 2023 05:01:30 -0800 (PST)
X-Received: by 2002:a05:6e02:b2c:b0:357:677e:50e7 with SMTP id e12-20020a056e020b2c00b00357677e50e7mr5538671ilu.27.1699534889944;
        Thu, 09 Nov 2023 05:01:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699534889; cv=none;
        d=google.com; s=arc-20160816;
        b=RKWorjZEIYj6nSYFtppaptQqW4rhd/ROZcGaxPov6d1iLCrshyNpvByJSsjckRukFh
         zFCYaLWyVWny+t2NZamVhWJsGFybuo9ZBiAOWuAiDJap/m/kz2PJSlb0EN+DeTXGGU6H
         PWsp+gRg6uXRCC+C0zvI2KRmanp4m/gPtk+efXhOXKMK7jfL0d/fLH5Ditdv0enaj6+G
         1y7K2fdcmAHtjQp3ji59XWQhFru1HrW9GFwq0T87r3LoxVNlJBJuf9RhnHFmgquZAxj4
         3DlV2eoXchwgYLaRkwBP7uH2EjOFKafTGHmyUseLPhCaZELDFwFoWgA6zy/817edYA+F
         aJAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=cmyEb0reH/2vT15Aoin4L5GvjrzfxVg11b3XeplgBo4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=WTgW1sBMW/AUwRLm70ONJOGG8iTw4VQZMWHkUAmfRWnVVdfeBu/r7+FMF64HBCLR+1
         xxwL4ITe+OmHV2s+eyQHIlwvTO0XikrYdlaF6Xli7PxCu5lGJa0pOxuQBsLkj7D5dhBB
         tyZtc6HeZ+ojhP+M2vqZPp+q6sWaAIEdTGEHaVPupCgPjnqsLJJ/gLFa+nxLJntBGy2o
         JTykQofsHX+Zo/pLSGVQHV6OkPFI4ZPwfBw7V8+dKhynVC3q3LOL9qNQm5+AoS8q/7kx
         1wiB7eiZw8ePLm/m8dNCAAgFGQHKfZdIMIZtE8HQ9WMJfZ+EvJDtHT7t0PmJFYk0+ZxB
         4y2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XZRjytV3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id bn27-20020a056e02339b00b00359d1e22f06si195165ilb.5.2023.11.09.05.01.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Nov 2023 05:01:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 4C22ACE12CD
	for <kasan-dev@googlegroups.com>; Thu,  9 Nov 2023 13:01:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 39F55C433C9
	for <kasan-dev@googlegroups.com>; Thu,  9 Nov 2023 13:01:26 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1E634C53BD2; Thu,  9 Nov 2023 13:01:26 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203495] KASAN: make inline instrumentation the default mode
Date: Thu, 09 Nov 2023 13:01:25 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203495-199747-LXcfc3ku1u@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203495-199747@https.bugzilla.kernel.org/>
References: <bug-203495-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XZRjytV3;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=203495

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Outline instrumentation leads to smaller code size, and IIRC some arches
support only outline. But making inline the default sounds good.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203495-199747-LXcfc3ku1u%40https.bugzilla.kernel.org/.
