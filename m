Return-Path: <kasan-dev+bncBAABBJHWU2WAMGQEIM7SLTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 65FE281E1B2
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 18:25:58 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-7baa66ebd17sf222604339f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 09:25:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703525157; cv=pass;
        d=google.com; s=arc-20160816;
        b=lqsOA6IKhi1TYM8WAIg7fVBLfeT3Mui/79pDZP1S/9YpQyZ9HgawJ+LG+WBE/R83xO
         PfcnrXva+5U3YbAEORrtHebellASGFV/xSVHwEl3sECdmukTxNecEgCmCBcyeuuThEmu
         jbpwat++FHXZlMfx+FEq+0KO5+ViZUdJfOvBcqOKF+LYQEoDx1HsnG0uQSMXQYvPypAk
         do8uj2/UyiO3Ulz128PrxVJuXoF03RT9xPvL0zFo+R1mz8qw49a+LkrBBdw8h97oeT4c
         DzqsDouW33J4p+/M4fI+vozdRfY7lVjbz6qmTejTwURffHgbi1/Y8UX0HPgBnxgqr53O
         GCGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=pG8CUTmnEmSeitHImurP46AB+BKE96WlVR1vUl/dI3E=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=NN1kyPQdM7K8vLXX5rEuL5uFCAkXmizsdrgx8EYYdq04XBfbXeuq8wc8okOCI9Vt/u
         n2u8L/q/02R18q9qNs66WOUUWZTjzNCgxB9E/L1PzNwFX8eZOjdYuM3MMRkvB68FZ7RN
         8771xMvKAI5+wa8Bxi7EqlDX4l11zsMJNaQ+r5CbEB32A/yw34xE+Ku7FHf2NjZ+05PX
         TtMokNF7GJiS/IA7ztotj6eWWRrbASJsfwbu2NIzHo/jaW5UQc3YwVL/6d70qiD18tM9
         V+4dIXdsiyYvMuzfORp2gHg4LOx9ww+ieO8HP5dF/lLEi9gXCtaEoXFlAIXQATFjR9A7
         v86A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RTg6gNBk;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703525157; x=1704129957; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pG8CUTmnEmSeitHImurP46AB+BKE96WlVR1vUl/dI3E=;
        b=szkR8Z42TtXCKjyfM5wDYn8QK9PvPptCaLo2PxmgNC2eNDKcjfpq/8hUrVvORSYlAk
         6uzbb4MmdWUKgDdC0MstD/ciJelSmCj4qAp6DeongDrdl1Y9F4vk1xfQclPby2OJ5P0s
         1Mhu+9BSfypwatV2coTwOHWSyvXV2QzeV+aAPab9RV+IyvxRqwWg8UizwpBOCWh1W+Sj
         pn8+1aePca9nhzZJvArX/Hq6o+5rRqJIijccD1mIYcFQCLpuisjcMD19rMMvuUUX1FuN
         3BtWIt8MHOZYscK+gXQJvzv2/ub/vC2gUCQ33wVEowVGLJJ2Ewh8zJHLZByQ8A75QM9G
         BcJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703525157; x=1704129957;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pG8CUTmnEmSeitHImurP46AB+BKE96WlVR1vUl/dI3E=;
        b=I04gjOpsoKtBPqt7ii2j0nUdPfgj4QgT3y3Xuhx1A3YDGhTfC9CIBA5DIxSnvHiUXX
         jRIo7uKo8jiUnwTkEEX7y7SOLt2OJnNuR1etoYWqh0MgY3SbmNYqgZITd1sOnwIzaoyA
         Ex+1XvPivh/Zsmijz1sbSmKzibCOclrv/sl2kXQhy18pklMGpehHeZZnm98uaN1Whijs
         vbn9eDiC+Q3/nqduxc+X10VkkAu1epmtZ0g5PKzNsRy2pNDvIBY655wwbpJ2QiL7OyXN
         KMBWJD/CGjwaQpZHwIqiBNS+mi8iWNrtT7ET7zk7nhVwNFV+ufzJ+HldU1+Xw5jVeMRU
         e//w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy0R8gj4eSeh0pcTlx4PHzDqNTa9XnnvguxhjjepD2oK5vwcMnR
	goeHhnwBM6qtdr0o654SQmI=
X-Google-Smtp-Source: AGHT+IFjdyxw87uryUQgQPrciu4JX78fby1mSR19OyC81e3Xepto52ezzJ/VGmCAupil9BBYLTf+6A==
X-Received: by 2002:a6b:e00c:0:b0:7b7:faa5:954f with SMTP id z12-20020a6be00c000000b007b7faa5954fmr6831509iog.23.1703525156988;
        Mon, 25 Dec 2023 09:25:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2281:b0:1cf:8cf9:c71b with SMTP id
 b1-20020a170903228100b001cf8cf9c71bls863581plh.0.-pod-prod-09-us; Mon, 25 Dec
 2023 09:25:56 -0800 (PST)
X-Received: by 2002:a17:902:bb10:b0:1d3:ee28:a762 with SMTP id im16-20020a170902bb1000b001d3ee28a762mr2683450plb.104.1703525155982;
        Mon, 25 Dec 2023 09:25:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703525155; cv=none;
        d=google.com; s=arc-20160816;
        b=kcqbbiFUTC5r5aAOybWPSFQ5hnBla2H4J2s1Sz6CUy0OX1Q5BJBSp6jhBIdpqIAC8O
         /iQ1g/R3exPtt0j8cCGX2GEsJoIB1rAIHDRGnCLNuFAnlxKL4sIRqRFAWQv/dpzV8JmV
         eUayGr5SmICWWo3S6F34q4dC802choX8CQvLze5PK8gFwKpAeu/GUzHCqyNCaF09T012
         KX+udUwwMvbSSNs8c4yrTizXWlUvaeQ4wT8LKSzE1HhOhGoLXQ5Ledtz+shj6O0jGZDK
         w1Lc3ChEKzOSLtnxBorxJhdJeEV9XJDDEnQlqbhAOjmJf0U9atXvWcN4YiCn92RG9nl6
         QlTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=spU/EOqS2HOpVy+z0rLzVi2kGGKL62PW3mFil9oB7CM=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=J6NKDwbUwnniObRHCpVDbJ+fBMJTszIqJkvzTvR2cvK1tgZD/aHxuzRGiC9OhvUPyp
         GXDixU1Z3VoNdqY5BVnM6yRfJWd1/ymslj06kgLWgxM94+1R+rGzAxUwWQJcdQQLIWJI
         G3nstDkqapCFT4XGa7h/yg+2NpiDvT6ir7Rhd1tidfKW3B0o5Z3tLtxQM/dYWOCH6yxa
         Lh5mIVBH2aKxOURGFzhWfP+NGc0Y6PKZTtFVmB54fgHQiaLQC4HlRVvC+6QP54+QDaOB
         aoGeXDvbS0dXLq5UXqXCSFxg9ZmVgtT8Zuwl1S6xFM46LA3sT/ks0QXDQhCHcA4Vub4T
         0Wcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RTg6gNBk;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id l11-20020a170902d04b00b001d3d7ca2a23si535536pll.7.2023.12.25.09.25.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 09:25:55 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 00DE2CE0E7D
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:25:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 31F8CC433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:25:52 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 07146C53BCD; Mon, 25 Dec 2023 17:25:52 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218314] stackdepot, KASAN (tags): allow bounding memory usage
 via command line
Date: Mon, 25 Dec 2023 17:25:51 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-218314-199747-Ld1px0muXU@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218314-199747@https.bugzilla.kernel.org/>
References: <bug-218314-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RTg6gNBk;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218314

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|stackdepot, KASAN(tags):    |stackdepot, KASAN (tags):
                   |allow bounding memory usage |allow bounding memory usage
                   |via command line            |via command line

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218314-199747-Ld1px0muXU%40https.bugzilla.kernel.org/.
