Return-Path: <kasan-dev+bncBAABBDUP7CWAMGQEHM3SFUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D1AF829290
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 03:57:20 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-dbf1c3816a3sf1082199276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 18:57:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704855439; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZyGNltcs4CjSUxyLRN2XA+wdql/X1soiitW8Hf1/YP4uvXxZEx5fKLcYPpRu3HXZyM
         EYqCxaRLLY5w2uf1Rj/5hFPi/3AmRrC2eJvBNYKmM/6ZAGST6hy6w/Eqb2x/0miXc+PT
         PStUZSzCvtFvu90yCHUs201cDM0QOApTlQ4xq1J9LZVMld66YhzoYTzTtURIlKz89xZ1
         L0eU58nHzwCUhUf/sCnU/U0sm968oi2r3G6jkJZPamPIVfZMOHWotrnre/AadZ/aYP23
         y1Px0fICjvm8Fits8eikkZSbTs+U86SnupHglkQ77x8bUYrpd1fYMVLGQUylg3HgAFtJ
         fysQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=GiQxRZy8fu687MN5xHJREKRfMvgm+Ug8BH+Pai/uoo4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=NM3eE6xe9fA/p3oBJz1jg2RbsGG/nKrAqncELnWEcSrnOzhll9Z0xJBMYe2LXiUfas
         nGshQEerewQZdu+YoY35HjTCkkOT/OOx2NCWjoOSxaA4Nggt7Wjvvb794aTvofp3TurW
         ylKuAAGTo4PssQfmEps2uXD8vOEpfxeMRLriT0FmFMNd5XMHVbcYcCTWEIW0xhjYdjig
         89O/QhF6tUIrSIy7CpRz+qXc6znsMTLZeh2qIcPHlAi7kO7+m5RONvI8Pmtw4dEmKZrJ
         HbycQcOQAUAxtm3MX9Xqq42xFQYWQAI9ii/pfvEmZdXXK6/TvYj04gYqHPEDFPgga+Wr
         DZVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qqYn6wOl;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704855439; x=1705460239; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GiQxRZy8fu687MN5xHJREKRfMvgm+Ug8BH+Pai/uoo4=;
        b=mmVbgG9gSjrxiTyU6ZoB4HKNOI9h7CP53KOEbmGaqGCx6nt15qndQNA1v7+1c7JytJ
         RfhGYUve3oMjXb59Nb3HfdU+WU6Fr7aM40R3Yhv/C9RXV5USP99sv7yAr2ZsVTVH28hC
         X2ZtQ0YDNT9EO4NKrbUvEOa3aRXviqXhemy69G+Zb6Z7J3LEe/m+b+hXcJk+bRD5UZ9/
         F0s3rFCaUmRWvratx/0SZ1mJBblsRjc+VYmPWUDXdd/4mEaNU4KgpJtQjFz0S2uuG6f0
         FHsUngM6GACJMg6LGsisKm9XlLqqo3Ef1DAAOkZPXZf13TeVfheSLq5Zn5v9ha0xyLPU
         2TOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704855439; x=1705460239;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GiQxRZy8fu687MN5xHJREKRfMvgm+Ug8BH+Pai/uoo4=;
        b=Kw8m49izR4hG7g6jE4KJwZFzBrIKBXHZtgNIVKPo5Ev6ls7HE1lJEJ22lcNo3PrpDy
         Gr8Bmso82phKjhueOjnmVLHEgKuVGM516uZ9YQGE52drmxEwg1/YTIDAARGElrt71WFH
         9KF0STANJude+wjyiuU48g0MTfN4Tse+6ACClss2W2N/8dWtXtt+xmtmBZwX3A4tUBiH
         Kb0fIOH7dKXN6tgdSIGSy6La09WJAUbMBdIOS+tN7PlutrRQ9FrduIGFx/jFv7I1Ld2R
         0jQ2cnKvfDmkg3Gysc33Td6SVktQ1+I3ouF+1IdNbOvNyrnX8rZK3443h4lRZnGquPVx
         DWNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YygQc8CnN7dfXGPDX6nLIoY7qjJknNVCTIWUsfiihYEoJBluYHa
	t0JEdDs7VUeZOLYe2rZ033I=
X-Google-Smtp-Source: AGHT+IEWgaqyo7DdqISOxoBOQdJbs+zd21Q5gyhpXwhtAlQiciWWQzKIOZHE+4PyGN6xiCVEHRNQIw==
X-Received: by 2002:a05:6902:1028:b0:dbd:735f:33b with SMTP id x8-20020a056902102800b00dbd735f033bmr262051ybt.40.1704855438514;
        Tue, 09 Jan 2024 18:57:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:df43:0:b0:dbd:f470:af0a with SMTP id w64-20020a25df43000000b00dbdf470af0als1146520ybg.1.-pod-prod-02-us;
 Tue, 09 Jan 2024 18:57:17 -0800 (PST)
X-Received: by 2002:a0d:ea02:0:b0:5f6:e488:8c98 with SMTP id t2-20020a0dea02000000b005f6e4888c98mr369466ywe.26.1704855437759;
        Tue, 09 Jan 2024 18:57:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704855437; cv=none;
        d=google.com; s=arc-20160816;
        b=dWsIA3JMQaACXPuYm+tbUqi52hBWS/lqU57vq+uFyRdokhklJ5RSQmrloaKVwDl+ds
         70sD/8qeYths/EYL/JjV1Cze1SMTlvVTQYDH/EDDSNN2faA/TvfIFvp5kQ91V7FiLshO
         Bv3gEqFZlH4OjhxIqPXQfuUHQPPty33xeoQr6H37ADkLsInswyUMhqMeWVpZK+vZutk7
         czv5Al6gUp7tLFjSsXfRZYmD7FyxfW1Co686yPtOjYPByz3MZWJ4a06Frc+YgJ1kx+SB
         5d/RUe18SeiswfM6OWq7mC4KPSfA0+7r9s29cl1I5BiWBoj0/bF9W4KhsOOYBA1ko38p
         +5Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=inb8mJtqBO0RFI91G94oPiUJjkIJX18SLOZPOXQ9rnI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=VMlQvnBS3aENzFjawqVNnB/n4W/dr3lTnVadyARNK4eJ4zUmmRWpFj/6oyUNdEb6x1
         3Ys0lbYwJBZnewaTdjlb93FnxnQmNge5CgEiBQnGSUkJqBV+cH1XXE3QWNduNpw9jIzP
         nSA9Ha1xsMbEluqqaHoeSKT12HjEsGDDdoEiVO/fvqVJg8cRvO2FUBOeh/CvsDopnZd8
         YSb+SsaR33xkoHawGCEdQPmU9bz0x83GxSe4iTFDgVjSANNF4kwCLBbPE1pkNDiuz+qw
         rfDNSxBSb/KsFag/ZZuqv+nEVBAYSlmAW2B5cZ5sSFwSsn+xCKhBiSaYZnqZI+SyIjhE
         xVwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qqYn6wOl;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id r62-20020a819a41000000b005fa52a11b7bsi15328ywg.4.2024.01.09.18.57.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 18:57:17 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 40E27CE1A94
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 02:57:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7EF1AC433F1
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 02:57:14 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6FC09C53BCD; Wed, 10 Jan 2024 02:57:14 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212167] KASAN: don't proceed with invalid page_alloc and large
 kmalloc frees
Date: Wed, 10 Jan 2024 02:57:14 +0000
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
Message-ID: <bug-212167-199747-pkA5vPzcxg@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212167-199747@https.bugzilla.kernel.org/>
References: <bug-212167-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qqYn6wOl;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212167

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
Double-free and invalid-free checks have been implemented for page_alloc-backed
mempool allocations (both page and large kmalloc) in the series [1].

We still need to add detection to kasan_poison_pages, propagate the return
values from kasan_kfree_large and kasan_poison_pages to slab/page_alloc, and
make slab/page_alloc to not reuse buggy objects.

Internally, for the page_alloc part, we should move the
kasan_mempool_poison_pages implementation into kasan_poison_pages (except for
the sampling check: page_alloc code already checks for it) and reuse
kasan_poison_pages in kasan_mempool_poison_pages.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=280ec6ccb6422aa4a04f9ac4216ddcf055acc95d

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212167-199747-pkA5vPzcxg%40https.bugzilla.kernel.org/.
