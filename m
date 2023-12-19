Return-Path: <kasan-dev+bncBAABBV5RRCWAMGQERK22YWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B4B581937B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:27:36 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3bb6938995fsf682665b6e.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:27:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703024855; cv=pass;
        d=google.com; s=arc-20160816;
        b=fJ2ZkueXIHOubq18r2NHPFt+V28Aaz2nGrAFBL4yX/ETrdYjPuYj7iSWFjIHZdWwEf
         z5jfGMrBNPZi8ydkDVMkYQF4TZ9ZWmAWxWy8WZUvq+yh02CcljbIyuaD3yT0BEB9pmZf
         oxzSBiTUND4IzUrpIeDZtyjkdPy79pJLjZY0vDbK7Kd+vfFFkRe+E1+8as3iEh9wcQKm
         MVnjNJxhYvlkdlo7BwKBLlLaJssDgbfBYvyIO6QMtskne1ADag0CDPEIPwJvgY0MQgNb
         pHeSL5Rsg3OjB4Cj10YW+0pv4ZdnnfgO2x0cFRLd0FDSNJRMEL0ULE43N+B+Eh/M83cd
         jsBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Lv9y0mUrDVTFHIyqKXf3c42hTExzx7f5YboskmSx4T8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Hb7XTd1zp4SGbFa6pTvxAKg+ViRi9+Jh684LFAc7CwktHhkblwNbGwz7u+BN7aiwe1
         lUM9zovLiXoHvb0cE1qb3pEi2bXandIa8XwY3pIPIXRBirrXobR1M5NX4ffO70g6TxyG
         rG0sWJxGRNZJoWmxF2vamvKz2VaAdhvemPomPvS/ZzP9Au5AX4WA363y+h0iK03OEsIM
         kh/EbTdWIFVfrAqwvTXBBPsDA9hKs/fQ8+hTa9cBerBTNHj99CEN14oTFnnU8BPzlgMd
         doR73+WUF1YRsN80oOB7f/aJ10VGl6MytL83Q62fLjBbsW7CW1Z9iCbyl86W3tqpPYld
         CDGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="qz/WIaLH";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703024855; x=1703629655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Lv9y0mUrDVTFHIyqKXf3c42hTExzx7f5YboskmSx4T8=;
        b=cG52IBKBvvHGK31zrc/XSOelNAomAdv1Xt46F8/FzVCJ9W1Ca+go29+UD+W1Jod5yc
         ShWlzhtpjTd3uCXfdA4l7FXzn4phnh3p0UjuLYHo3QkWVu8bYME90l2KLg/WlY4rrt5g
         Lm4N/d24wKFS1MLh1L+Ih6T62ISX6Xz0Q70lyEJbmoD3r2ElvMRgH9qLXsoesCWyIwCI
         SIDNbTVkYvkr6BPySeRKJhsq74X0g75/ui0urjWWqSrsTq+SpsohRU7wgJyL9ku0XjDP
         Mk7bZGGMdrbSs48b0iliC3bog3iSK8H1XXJjkK/4ywD7aT+XuHkzgFbJWgjUkf8TnsVE
         9lXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703024855; x=1703629655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Lv9y0mUrDVTFHIyqKXf3c42hTExzx7f5YboskmSx4T8=;
        b=LdMYy9y9IwFrdvEIr0y46spcRadd+vnTWZapTZo50K6hi2XI+OuB639iu9dYxSdL9W
         KAmx2qupwH0MnyLXX2M0m4RsPfF4hCWbQcsAKnQS9M+gc6JT9h0gXD5fEAN0mqZ8ZA3y
         YYphXMm62y8qSFzO7ijFWSoQzl475KhQ1ZBicLXJzrbtD7XAVG1w5s993oPEt1Ey3hIN
         8oHNT9JkZ12+PhhT/BdyGPPWrQej1xgscDIJFLkSHMyzsKGtqkhTMjLlxH3x6iYvzx95
         gTTs94BuaqjMFxkfEY/cHytQOkoJ4/EM42R4IKkN0XlGzNnOp0WJgPaiJ/+P7Zx4M9Qb
         Nsyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzCUj4K7uVPPVNTrGbPKzApf3cA2BsAmEvlJECfl7WZ3V/liM52
	X4gFd7c+4lxPTBNfis5v8po=
X-Google-Smtp-Source: AGHT+IHaMiEdSX71w9vikPylZPaITfsryppYs3J00kvEaRQnuBSSIHEiESvuXzo/uolO9Sf/PZsY1g==
X-Received: by 2002:a05:6808:128e:b0:3b8:3d71:9823 with SMTP id a14-20020a056808128e00b003b83d719823mr23048708oiw.35.1703024855189;
        Tue, 19 Dec 2023 14:27:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3019:b0:67f:413:d4b1 with SMTP id
 ke25-20020a056214301900b0067f0413d4b1ls6678213qvb.0.-pod-prod-02-us; Tue, 19
 Dec 2023 14:27:34 -0800 (PST)
X-Received: by 2002:a05:6214:f6b:b0:67f:4630:9516 with SMTP id iy11-20020a0562140f6b00b0067f46309516mr6266760qvb.30.1703024854498;
        Tue, 19 Dec 2023 14:27:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703024854; cv=none;
        d=google.com; s=arc-20160816;
        b=myhKDtQwM8xHl3BPtrIwdcmn0R4DXZqNUv8FLMj2SAve2PHRtePsf5CqBrUCAMg0vF
         w4wOBVXHSZZ7T4bsWlL2ntuF5bR3B1So6/U+VxaonilqupV4RuC8uBo5ekJ/WjxWGjYr
         fA/O+iEOe2F9EhImK4ULK1tXEq0KqRGRYVGlZ0a8LHMo6ZxcRx+iIh/uwn2+C8/Fg6Ah
         gZ1zVu+eIg6N20F1Ngf8XSk+CMAaBsD4ENCnQUSxTqX/rhu+ZVisZ9ymlWCjqGquhnKS
         x8ftnvIIJIj2q9G3DivtAyFHK1aJf33tMnRbQTzqfOgnQ2R8tHH65jDXrs8EuMZwKn63
         A8Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=/cq8KCOs2hxXLoPPO1vcPDJOfBDqQTA7WxCoUYVNq4U=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=PZ43SouqgByv4dYgoFhyjLcP7HVoMvSuJ1QyMN0xJAcjt+bH/Ij6kbPEQyLALHqe9U
         ZmXx4hQ3t4efn7HaxqrXyZTIbeNtwKmg/y3oEWb/Jb3T/hiAKjhGcofIeV/PjWROei/r
         AJkrSLq+9tjlPG/zQtLtko4H3pqSRgRvwZBBNuyAv3pIxM67l7XeFIwson5+A/NX7yUX
         jo4trnok3hIT43dBE1iCsLdxhExRAILTUh8wPHTLVRkPQLXtDHtlqXrzi520aNr4jNeE
         ueb1Yd3p82lr+AC2XcZt/hwSxXVjqPhAuBbKIki0uvB++7Mo+9UQUSwh/RFSdNetsbn7
         GZ7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="qz/WIaLH";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id iy11-20020a0562140f6b00b0067a626183d1si607295qvb.5.2023.12.19.14.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:27:34 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id ECF31CE1AB8
	for <kasan-dev@googlegroups.com>; Tue, 19 Dec 2023 22:27:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BFD62C433C7
	for <kasan-dev@googlegroups.com>; Tue, 19 Dec 2023 22:27:30 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id AEDA1C53BC6; Tue, 19 Dec 2023 22:27:30 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212167] KASAN: don't proceed with invalid page_alloc and large
 kmalloc frees
Date: Tue, 19 Dec 2023 22:27:30 +0000
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
Message-ID: <bug-212167-199747-zWr51snyqe@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212167-199747@https.bugzilla.kernel.org/>
References: <bug-212167-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="qz/WIaLH";       spf=pass
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

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
We also need to implement this for large kmalloc allocations (the one that fall
back onto page_alloc).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212167-199747-zWr51snyqe%40https.bugzilla.kernel.org/.
