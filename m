Return-Path: <kasan-dev+bncBAABB2UC7CWAMGQEA6XZBWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA32E829274
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 03:31:07 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4299130ad10sf207121cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 18:31:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704853866; cv=pass;
        d=google.com; s=arc-20160816;
        b=G3QjiyHMgRqKOdTNA9vNhUy/+VLnbjjmCP/Ftl3EDi9MXHUy89Shdvn1cpLXOh6sNT
         JKVuYaya8weU1AbuZJWAtRfKNPDYfqquvfDcepGTnip2duFJirWxhuVMXghoSLcnZX6K
         JiT4emWqT6uPrOoqEwmuv8vUn9DgNECyuEr0UKW05nAxq0EkuaOIveAvy4QdQlbPjmiJ
         1s8+69Xpjrbq0jDH6cRZKzuxLyykgOVuOMiFfGc26eDCvEnLBXu1PWzXdmH4hILkCRsq
         7sGvlzC+G20DPhEuTJl/Vv8AayjodvgOn51+/9y9dqLC3XECenFibGOphmMUZxrmBPlG
         D0GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Fjbm1PUbeXA0iJczzq/WK+FXmMY5V/NZF8K5papL068=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=moQWULMxp1cRt4zcdP48WF2q6i2F5+pZcP93MWRCbCkEZL3e9sN4KJBqPv519b24+G
         SiWrBv4u1RQRoRXIAMs0q9D78qkD4zxk2opZH5rHA8M4plEXt6/TobisufyxLmeVH4RB
         j5+OMkZRGw6Bq5qYj2JoI7bnH6d2jujzEa6HPE8VWopgyhIj1Ha5Q7Gt417DLqSDQgWU
         cbhzSuKcXiCCeoQhrsSTNDwIgvL6e5AE6KF0r0+9mjdu+9hnx0psorQcRE0/L8cJzU+9
         yDjDE6JfHVcYoiztmrzlrYHecICQg+cYb0SdCLNWEyk9B7A6eiZWvqT3xhsP18l0R6Pa
         pepg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wpr4F7Br;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704853866; x=1705458666; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Fjbm1PUbeXA0iJczzq/WK+FXmMY5V/NZF8K5papL068=;
        b=SpZtR3Wt0GA2gMbwOorqpi9Mw36EjERJM6OIu/eErnGs6XcScXa1iY2DgFW5nTaS0E
         bduYq/ib2EgDGSTHc4jqBbDVBmI0Wb2yjGe67gU4pKtQwB7mt0sxt+a9mBQ2bFsdKMyZ
         3Wy4NIkr5+uzsdSj+8zK/qCnqfT+HF+I01QE9GiNvD9p1Vhnx0J8lxLe71ykbdUEEkjC
         GROHj9TYXgvykTaD9vVZprrm82iDwdpbIhNltoWG8mrJl8idpwiv5e+Lx6pdr8ZN5PJ2
         0ZWrGcumbi07pm9YzYjekpZR8WnIKKSbcSQUqLxcHPrvCaI2d1VB4TohVHYB72apxt9H
         buuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704853866; x=1705458666;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fjbm1PUbeXA0iJczzq/WK+FXmMY5V/NZF8K5papL068=;
        b=SQ0ZUe5+5W29wCsM0G2wGJyl5eAwbwUtGh/gjQ/w67IoxOWtAe0sm1ocInm9RLBMcR
         zqYfclZ4T+KVhAETaHIISW614s+dYsVSpccURa4g3HuKbT/IuYJWQv6N7SA+sEdEzCge
         lpcuYwNoREdqpcEeFzxNq/7ed8ZSxjYfa47bHtQot4mA8oqIjKEMm2orDS7viNbYX8TF
         fHYEthr4O39hTwozH+GiJDXMNehMW3f8zQGd8myH/gWLlxSSiz0xUzeGyvNaNdTHcthj
         AWWYMOh4DsvEOStaPeTQoOa/0a0nnJ+nmCtcsWE7cKEibsPzY6SeoH9wmZbFe/fSneXL
         oP8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzRVtHyyRqfJ9UQ4inayiwfuOSD6NfAlf2pXLpR7i0VsCsd3WFg
	seYujScHZjf37FJku9qB61M=
X-Google-Smtp-Source: AGHT+IHMpxbaD8HBDe5eAh7+sXvhFJBoRB1wiIju/IJ4ShBCZM0fKUzKFQwMYvVZjFc+bZcSHeLrHw==
X-Received: by 2002:a05:622a:1352:b0:429:9e24:729d with SMTP id w18-20020a05622a135200b004299e24729dmr175618qtk.6.1704853866627;
        Tue, 09 Jan 2024 18:31:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d708:0:b0:dbd:c287:b961 with SMTP id o8-20020a25d708000000b00dbdc287b961ls1099642ybg.1.-pod-prod-08-us;
 Tue, 09 Jan 2024 18:31:05 -0800 (PST)
X-Received: by 2002:a25:ac8a:0:b0:dbe:d59a:7802 with SMTP id x10-20020a25ac8a000000b00dbed59a7802mr238119ybi.112.1704853865607;
        Tue, 09 Jan 2024 18:31:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704853865; cv=none;
        d=google.com; s=arc-20160816;
        b=xDMnB5bzFLTpH4Bqs8BVI4KrKWBvVaqoMm+v68FwnESnl7G7KFS/Z8rVcPkjZSQ8/m
         1UY9o0pVkvNfYnOQwZBAijkQlVLn3w5pD6A/HXXRtMyKmpfCwLzs6gW3fpYgXOJvTuz6
         11MTpevEn244AeDiywynZVg5HCjRSqp2XlYguW9cstXAfMF/oNAtkm3qYaji/LXPtgJJ
         opHRP8KyeoUVEelWcnOsqAsZl/1U/ypONlHR9AvKm6BiSW0zoNhKbvwBvEaOMIoSIcki
         AcFRp6yKrIRfYSVztUoPNjv7odUJ3aVMOmaDVhOg0RWcuBNwnxWQtrV5e3jEsXyPMtS+
         gBnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=PMfUKJSoRTj9CgPg1i0jYhvzaNKvQ0lRzBNa+z3JjCM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=OMpdGvf8ZPFJBxt2LrBp9fcsInSK/XrpKCkcpjooMmUMZLhtX/a6i2n1sjsjR4Kw+M
         RUwY0tQDzdM+tXiKkybE2qY+lgjCBFxCwol3+pk5hiuJNIIs2UNpyMF+O7BlBp5oZWat
         j6pDORjAgQ+NP6/haddXgFsAX5zZj7x8LplPaGIaYeZqk3+5g//Y/SmKWG0FDtl3Ooxp
         VvYecuxIti2jySAQHfXanLjaw4KBSxR547zlPUJhK8xI1K/NPPIZdVAiSN2VsT/HZaVs
         tRBYNXjGLifnzUOwgmCIbw3hYVifU3lgtD/a/+QGyhxtvlZPqgOsEZBYZsWNR7NRUysL
         o1oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wpr4F7Br;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id y13-20020a1f7d0d000000b004b71e52abc3si365071vkc.4.2024.01.09.18.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 18:31:05 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 20C72615A5
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 02:31:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BE30CC433F1
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 02:31:04 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A90C3C53BC6; Wed, 10 Jan 2024 02:31:04 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212197] KASAN: save mempool stack traces
Date: Wed, 10 Jan 2024 02:31:04 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212197-199747-658x1hFQRn@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212197-199747@https.bugzilla.kernel.org/>
References: <bug-212197-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Wpr4F7Br;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212197

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with the series:

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=280ec6ccb6422aa4a04f9ac4216ddcf055acc95d

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212197-199747-658x1hFQRn%40https.bugzilla.kernel.org/.
