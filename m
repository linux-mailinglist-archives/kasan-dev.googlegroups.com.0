Return-Path: <kasan-dev+bncBC24VNFHTMIBBOVSTKGQMGQEGPSSWPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E4C246404F
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:35:56 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id g20-20020a4a7554000000b002caefc8179csf1749103oof.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:35:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308154; cv=pass;
        d=google.com; s=arc-20160816;
        b=iai9WI1Y/LtM4OxMvv+GUJKL07Ddn0Rr3NCOdg8UAODcqLjHl6/k67fk5lNe3XaTHw
         JVnoJezmSLlg9uv21RFiADDtDDXrDzB8oHuim4WRlkpVs/sBN7ph/Je9OPJLsz/S3C2W
         c4reqKf3P17KelrcCMAY8s/5arBT3a4fVsZJd58naVAVTX9t0oNm9DYohDwS1QXZD7Op
         YO/UqXZC9P1p102iXQk6eWDjWCLu8iXu7eDSrWekawxSrutRbGY8Ba+JqhA++inQlqkl
         I/7xLDQSukoUCfLniwgwW3/uGzvD7uNE8E5OjgAXgzPj7lpCCsLqET8hCgWqPyxoI9lx
         bARQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=cCtsSwkJebmeCpv2Y646BhC+gavlaw4GWR8z3JBXDDA=;
        b=eHDJgy/xHuj2Q8Xr7/NL1JIBUX7wl8RQ913z1IaO+nMeaGSm66sq4Ol2KLUYQE2UNc
         qE/qAip6VC7Qn+1NfO/XP500wCC5u02BCzpfaBlUFNYmFF0hLFEjPP4xAvE4naQSWyX8
         wvL9Rjc9j3L0c34Wnhg82LE9J610k04kfvbMX8vtcH1gjw/FVHm866Oviq4/VEHv+WVS
         8GFQJQoxturVOUXn0E8eQ/6OLMHTNiMUcndcFRGVs7bmE/OM8PcB6uNdMXO5DuzUSvWO
         /dG6ezHI0LFmIqW+6xcAn4clRyZETaQnbdiwb6sBgJ4m7iwzHA01CvQK45HaF35d1+46
         31Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Nqw67GcD;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cCtsSwkJebmeCpv2Y646BhC+gavlaw4GWR8z3JBXDDA=;
        b=WYmmkaq72K6FDWwuvzVQPL6Xl+UBaxa13FgUzyzHVflzCmHMXptWj5r+vtkmUyIDJM
         mRhLa58Zfh8VVUANxiGj1AthQhzYt7W39yPEmxDZb3+FZsryDKWeJN/i5BRF59yLff70
         y9qhn6el7rPyUNUeYyPLgO9FaYlbpDXB7bon+VF5zyFjnIL1H/49nbkVfoMH4ZgU4+3p
         3dNcg7h/jVhmk8bz63NOFx6Z1PLyUTiWce+wqIzvA65uFJStZmkmXb3fqzzrbkfx1mN+
         qjSQTVqkP7qAuWJnldhTzsZyNMSHAWDwwJ59x/ZQgEHmAk0MMF+dA5XPkyPHVTeFcBVk
         yRhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cCtsSwkJebmeCpv2Y646BhC+gavlaw4GWR8z3JBXDDA=;
        b=5xQ8SwMeDaiUzi/JKjQOWl3xBfQV/kyQgfgTambFnvLOxHp8opVorAMC3WkgRMbRX9
         YpqefXPhATG+LaDAxeMDKOpASMOYM8OC4rUZxCYPZK4pauKI6XFx8Yn1k5+F/7pJDksa
         Dig6DVMqVQghplklbGU+AXnzx0iUpqCGff9bCt8knw0clF7WGK4brd3cEhmPx37G5pGv
         bqY0bAtun+2yKaZ57c2Ck9m4vVnzFkbdeN3BIssMYLg7rrITB1DXSS3ETZusZLg5mRJN
         KnAR3gkB76EcYfZFUhQCjEOAio9/rSIWusAL5bvqlB2MAH9dQdec5XUa5ZaxJR+M1Tr3
         0znw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cJdK62lAQiiup23rARlFpPRwjyxpdotJoq3C2nvr6TV+oUbv4
	WBZ7ZA+0a8mAXrviqKOWLV0=
X-Google-Smtp-Source: ABdhPJxAp0xXB7oHdlHmqcoZ5SHhbPZ0sXrtkVe1lZMXAZKpMXW0AdSiVQYQMgT7dUBLjHZGGfV/9A==
X-Received: by 2002:aca:1001:: with SMTP id 1mr1678822oiq.55.1638308154502;
        Tue, 30 Nov 2021 13:35:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:440e:: with SMTP id q14ls43269otv.0.gmail; Tue, 30
 Nov 2021 13:35:54 -0800 (PST)
X-Received: by 2002:a05:6830:2646:: with SMTP id f6mr1826140otu.182.1638308154089;
        Tue, 30 Nov 2021 13:35:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308154; cv=none;
        d=google.com; s=arc-20160816;
        b=0H2Y9+YJuU4JR6ge3YRqacQ8j82/TT21qhvnzOMwqKeZr1w/Of35WcVBwEJYEsVIO/
         3MWODNPHjkKuYQaVYTLydE33FcUwEbZLldjs00Lh6nT3zQaLM4Hdwr1NKHktLGWda9bV
         5cHgatu7Bt6JKoN0STSipmDZkiKjMLf3catgZJNB6UbYtHxGtH/NMLlOIlevnAWWcqmM
         i26oBR+hhCaxb5O5yAB+jfY5KdO8c5iGb4rNx3tSJ2XNdNlbFF4moRBUN1evaT18on3Q
         0nOZt5irCJOsk0WfjbKVcHedntAZopjN30+OzhjPg4ccJvsdLJBPQXvmUMr+5t9bYBNP
         p+OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=3O1uLF8oyIVo5NNgVG/A8UFr9lG7PdVuiYuiPupevJs=;
        b=WzITkOQ9I/PbwjwJkmixMD1u2IiAoMSrxMxiwNWCzYf2A4ohmpVQit5MPuh+XJmG8s
         R7QRHA4W1cgkExEEhQxAsYqH/U4CHX1ifO3sBbT/vuUkoRixVgwKlv7E8oMGAEu3lb6m
         X2cKFVJJZI/hq0evDtJUhOBKkXONhyN+uO0O2a1VaJgzlBnW1luEgCtP4AW/ooyvyHai
         +M1tGuRu3/ueubvwrKiHoyFjrJzu0lKgd/DCMZd2CaTC6lVkTgg31x1D/joLD3G4DxkL
         DdxkWqGMgljNUTA1ATnfeiroxsha5ePg8yHCwbh79bCiNWWvCGPP6lJW0plAhzhLKqb2
         o/gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Nqw67GcD;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id bj28si1528719oib.2.2021.11.30.13.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Nov 2021 13:35:53 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id C2F96CE1B59
	for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 21:35:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id F3EC1C53FD0
	for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 21:35:49 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id D8CD460F46; Tue, 30 Nov 2021 21:35:49 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214861] UBSAN_OBJECT_SIZE=y results in a non-booting kernel (32
 bit, i686)
Date: Tue, 30 Nov 2021 21:35:49 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-214861-199747-SwGSw7XtyP@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214861-199747@https.bugzilla.kernel.org/>
References: <bug-214861-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Nqw67GcD;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=214861

--- Comment #2 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 299803
  --> https://bugzilla.kernel.org/attachment.cgi?id=299803&action=edit
kernel .config (kernel 5.16-rc3, Shuttle XPC FS51, Pentium 4)

Also happens on 5.16-rc3.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214861-199747-SwGSw7XtyP%40https.bugzilla.kernel.org/.
