Return-Path: <kasan-dev+bncBAABBX4NS2PQMGQENM2MM4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EAFD6914EB
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 00:50:56 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id z25-20020a05651c023900b0029338236909sf106469ljn.20
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 15:50:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675986656; cv=pass;
        d=google.com; s=arc-20160816;
        b=VA2X6XoYUaIu6CpIQ+4SfNpQfRgz4Kl1/O6gEGSFKCQgJwzOkOuTXO31JCm99+kQjz
         /Tgdufi6eK1waBhditecVNEmOfL30GHUlVlIK9hv4pLwcy+3QXJioeQhNXGBcd5OBFbt
         0IHctw6I83IuQVHhqE5/cy7a3E1LoCyXFNoLG8hNVZI/Lb1F6GHzeVeKGLKpqp95Cnd3
         Knez90mwp+PZxuiGj76D8Vgu+04WfDICGqdOZ6KX11ax68BLne55ooYGBTyTBDbi5aiI
         lejlrf+MJk+pT1+F7ZiD59tiW8zh3yzMHvrP33Y9Swob9LfeT/EDglQB9tZSuOkHCGWx
         xqjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=130elzJbXFEvg8GtzI6jaRMIVufm8FA63ZoRfQBWDw8=;
        b=T/tJywPcDZQE0uyamtAmIYI4H7t7mGGxRDcqOdVb6a4lGnfc+8OwPDnN9JwQjmynB0
         piSgzPL3vHFN0Yg7zb5gTF+mTvG0hRn1qmgF3vuJgqMHQBesgzu+97xy9NuP3kzyK+EY
         HtkXuiszl0nBpmorMeZualPJ1gopegxUcMZG7GYQyU2uiEsVDFuyI99hfo2bM9/0CY98
         vsr26uUiozFw1kM86hRAZN5KcWgxAFfDWEDw4S2Nughgy1PfI/foyJSf+7+8C/9/0O63
         QOjlWOwgnkB8T+vwHQVMsqIm+7kEwgB8Pp20mgufZfwSO/ympQIDQfIG/NxH2WL9/mQC
         iVTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HuGxZkdK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=130elzJbXFEvg8GtzI6jaRMIVufm8FA63ZoRfQBWDw8=;
        b=A7vckqjs0l33JaOunYSARhGCTJRamDYRKb3ad+6WFUAkXRdc2pOMRNK6QgBu6X6n1X
         CrXKRbzZoe8pOThSeLHVE30bD5M8vBO5d4U/+5WL1uo2dDW4+9ZUGF3zhxLpwzs5cSdm
         2Op0PERz9Mg9h5Lomszb+yCmTW+WipeyUwmn3cLriYFTXsfrIjtvaHNTAtGeY/35ttJp
         R9HOGXwIA+JC1RxkSzl9+AzUGKcBZMOPwiaulQoUryEDlLLVkQ8YtO2MCnb2J/gAadOb
         lp0uCEgtjHsZ6IfrCMgsyKpkE7e+LL9eAH5BZic+jUUcL5CCLG/8IKwZqv/WZJUf8pPZ
         AiiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=130elzJbXFEvg8GtzI6jaRMIVufm8FA63ZoRfQBWDw8=;
        b=Z1hOUkW6wF9mCk+sFi3OxHiyEj1n2CnCi4Kubw7nbIlKgm8vWFmYq62qDhDdgY315P
         OuZ9k2j/rQIvu/FBWAq46wcfp3nSGBpvOp5H9Mh6LiYhW3RdpSDw4tZF7ypJzd2YOlMu
         K6NHdV10dflntVlEit36k/CjsEIF6YZcB/dnD6oX/OIgZcvNUJcDyZXN8xDNjNyAcvxe
         09liiohHMVcEhv1Kr1rp6vzd4wxBpYnp3rdmNg2wWa/HVshTeylPUPSSuoslk0cSSjGw
         6oro8vhPhIcxZZolAb/bVcGvURHzaIOMF/NwoaisOvqjFfiplGqgC6XmOmF6L9hDnebY
         drhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWwerl5KMsXfKl+orJoFZiChjRCwbB9DiGbjbfWm31yHMVq9bye
	CkeLMBXXNPcg4ejG/Cb9EGI=
X-Google-Smtp-Source: AK7set8Nw3lM82sxuoQerWPrwCALeVduh6ltSzz+nRRkBqmFHVum3AzIFRQbBbw5xMAGK4MG2zJ+Jw==
X-Received: by 2002:ac2:532a:0:b0:4cc:811f:e13f with SMTP id f10-20020ac2532a000000b004cc811fe13fmr2067368lfh.235.1675986655639;
        Thu, 09 Feb 2023 15:50:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a3:b0:4c8:8384:83f3 with SMTP id
 bp35-20020a05651215a300b004c8838483f3ls2442223lfb.3.-pod-prod-gmail; Thu, 09
 Feb 2023 15:50:54 -0800 (PST)
X-Received: by 2002:ac2:5fc9:0:b0:4a4:68b8:f4f0 with SMTP id q9-20020ac25fc9000000b004a468b8f4f0mr3515360lfg.54.1675986654202;
        Thu, 09 Feb 2023 15:50:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675986654; cv=none;
        d=google.com; s=arc-20160816;
        b=X/Qap6Tee3LRHKHHgqFBWvi2ueqd6MSg63SfL1UNgvqBP5w0JL5HkFlChk+KMXAsnR
         d8H/QQBELvzDPQUJG8VEHQuTODwFcRKnuFQ/pQzMPTSxw1r7+ZMSzssU0cOD1UquSmWB
         3Ms0kcFArc0Zml5JR7etophwt3iV1PfbsbaEaTgi1gka2sJrDJ/3EpsPu0+QXYMiL/46
         sd9/i6sq0G3BEjNwROB5i6jo9jT2v8pgeW9TTAvboZadtUV66EsdWovbKp9qBgavhLr3
         B04hU3CAu1D4lUzv68ucdzvXoD8yIjhVF2X2Ox9qLLNiWc5oqI3hJNPCh64I5EFZq9jt
         b/JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=p/76YGkuU5JzSxQrogHxN3mUBgoTziGOWQws0ulyeTg=;
        b=RFaaaZYFox5n3IMaMJZmOCLfSZsHqf6rgsORRjPSZ3ZjFPritqvBLXxUFAw7dIvEv7
         KR6IP2pVykgscGZaweirDeMCcX2m6EdShKPAzWvpiTFs8dJ7/WJWCIJWvsct2sr2Aet3
         h3ix37FKsl7HoQZs3c73wIVhdZ+uRYpdqGozE4fD3jelMyc3W4eIjV1qqKI4AUI1oFNq
         dZ/1yMPnYMsjjlbQ8IJp0exBeAqQ+b1VtNWeF2lnkYLon5JtdvqmKQeGRYtggfBwhltm
         BOCxWECpkzHt+5bWy8+Xpv0wyBsS5w2XGA+rz7sRYxSZtYw9ZI5ORXrF86NDk0JR1vPr
         T3tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HuGxZkdK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id d35-20020a0565123d2300b004d34d4743c0si168709lfv.2.2023.02.09.15.50.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Feb 2023 15:50:54 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id B1D94B8237C
	for <kasan-dev@googlegroups.com>; Thu,  9 Feb 2023 23:50:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 61C61C4339B
	for <kasan-dev@googlegroups.com>; Thu,  9 Feb 2023 23:50:52 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 4E4DAC43143; Thu,  9 Feb 2023 23:50:52 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217017] New: KASAN (tags): investigate cma tagging
Date: Thu, 09 Feb 2023 23:50:52 +0000
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
Message-ID: <bug-217017-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HuGxZkdK;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=217017

            Bug ID: 217017
           Summary: KASAN (tags): investigate cma tagging
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

Currently, cma_alloc resets page tags via page_kasan_tag_reset after allocating
a memory region.

It might be possible to properly tag these allocations in a similar way as
vmalloc (i.e. skipping page_alloc tagging and tagging the whole allocated range
with the same pag).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217017-199747%40https.bugzilla.kernel.org/.
