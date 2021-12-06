Return-Path: <kasan-dev+bncBC24VNFHTMIBB5F4W6GQMGQEXWBCLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 021E046930C
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 10:57:09 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id h40-20020a0565123ca800b00402514d959fsf3672969lfv.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 01:57:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638784628; cv=pass;
        d=google.com; s=arc-20160816;
        b=j7cTLJQqOYF3x/TDUeXAGJE7BVb0vUo+XmTORS18Znih6Rt9UZ1AEMrh0gJfGLZ8b6
         SEc7pt0Q6VsVyqfUQhhEPxJHNmmeKxgjuTAWrOzcWidCSTkxi6JtiNZf2slv6clXhMnm
         fu9UtxVLJn0HeoYlLjPDIz8roZSOvNtdJVQTeyYZ9c5Av3yXn/9Tdu+7tkjpbjOY7y49
         ynT3o7mn/RJRS+v5fh2EJ+KrEBPyJhQ6n3K8Ug2Xr7oPmbgbokYNW9txnhIYnVSSFZFa
         /tqypb1xtuaBw5nividjcd1Kx0ivTKrmHpn+/E5b3IJXEm7cCLMsHwoVc/1rVIRcITf7
         J36A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=LtDTFxDpR0bnqvH0kIcO0+T2KkjmpiiZB2txhFHVbr8=;
        b=Wum2dKrwGpfVSk0e+2iVr3FxVQCWnCRccyly5jYH7xBXpvkhv87h+1ywGNKztP5K5C
         suSCoabC5381DUNE95lKvtr+aIkMuNZDZCtbZTkTGz3ky5b7/sv+XD93l3wqdad+jNoz
         FmK19C/HTCQ1WYen/DbuVyr771IkQC20+sfPynsfULesx6Plf8DpMhCvxRXGKDCDUyR2
         sAyQJPmVeBkFEUxmskeP/PvbfzyJFPMu1CSQmURQtwfxWlorLqRk36UYEL0NwfvhV9Y6
         gBFc+rqvYEt4NSb/XgXDUvHYVeePbbmsbxRFwAfoB6RinkoZWi6nF9n33Sq5rKhtIx0/
         c/gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QAYF11z2;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LtDTFxDpR0bnqvH0kIcO0+T2KkjmpiiZB2txhFHVbr8=;
        b=VNVk0Utc8Bjizi1fviAXiAFBIROmX/Z+MolNKPhWKaFFQBFzwvxLYWRbyWgxO8TxkZ
         2rlQH3YTm6KAClv8KOcB36pXx3GW6GDhXwasbxQ1/xPBGP6aAAXhJZsbAxul9rFVk6Zm
         AWMIpIpaBfO9aLJEu4SlZWEFKgPQh9+6m6iS3E43loV9KIgE56KH7y6Nv5Mm4XbAwd75
         dy3gNyS4JcSF4hB7PIiOItwLHHVJ7gdVGcDthuZD6cyjMskslPTZqn37GdlxjtwpCHqi
         FtB45V7SOmKXCnSbVs+LxHUvoKwLxlFS3oMrWRDwMBKyoDHFOicXDMkYrTTy9vMm+GvU
         s6Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LtDTFxDpR0bnqvH0kIcO0+T2KkjmpiiZB2txhFHVbr8=;
        b=WjAeAwNfOcL/cgVgFyldRK097dg7TIEr+xPLLWrn2rrfnP8FO7DvLhlVxUGjFSeEt+
         7Fsl9u8eUlyRPBf05LSwvwF9mOsNheKtZQy1tA2gLgxqfadZEszVLtf/6U3X6MsrDMyU
         JoqxSrT2orW4tWL5bgTSzvIaKEBLI77VCmn76x39YWnjwCJecJxRC3Igsk/9kWpg5vSb
         TLq3eeVjarmiOsHsbglCG0/riUlZJoNEEWDdVc1qV69g3K9HA7vfcyuslCFZUu18BYG5
         Pmd0uoyPfj5B4/lk8aH9aHEAP9/CpG4LqYP1dfSqu0qmsUjVx5yaukUBTcFnVoYxIVlA
         Eehg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530IxldAYn6qveqP+RlB/+i1cpP3W0H0v5eKSlGF2ELo3W78B0fI
	cvL597n7j+4DTuhAuRvoDsA=
X-Google-Smtp-Source: ABdhPJzBeEMOhlM0BeregiwAXG2F2ZbzULXVaO5FU4dYIYY+edV8fWbPZoifjWAWWtNUXtoG8MZR8Q==
X-Received: by 2002:a2e:8041:: with SMTP id p1mr35034349ljg.158.1638784628579;
        Mon, 06 Dec 2021 01:57:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls598199lfv.3.gmail; Mon, 06
 Dec 2021 01:57:07 -0800 (PST)
X-Received: by 2002:a05:6512:1682:: with SMTP id bu2mr33790354lfb.400.1638784627601;
        Mon, 06 Dec 2021 01:57:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638784627; cv=none;
        d=google.com; s=arc-20160816;
        b=HlqdvdFCXYE2t16PFcisUcGdQdH2kpJeZWK1+08TozB//OpjXxHUzkcaCY8PD5QuL0
         Z62x5gp3l1axkBg9Dnu+BKdhCZvmWZWUmrjiTEtP0cRqiz/qUQDiBB99Ygfzz6Tr11Xk
         +fSAXbP3nvjrn7BXzASvm5wictHmm4cdWucGVVKh6M7OHdqe0A/to2t2ihkBtKp6hDII
         +pla+1BMENjzsvhIweMNKUXiykBOZjC1b3QvcjQezgdu6iW+DxlcNQqJib8wD8fVlS49
         bZBI6KxZXQdDlrtGsL4TAzH515jTaX+9duSQcFsumsNOy9GCqSvuj+roJuxClPTSNQFX
         rRug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Js0zwFWzFfEKivUtAE3jfVTSRgESYGEHPGz6Ez8Vbi0=;
        b=PohNc3+j0laBLj0IznPX+//1ddJO1Wj4iTthy2CpPeJOqM9DiQvl6CPG+A/KQ3SQfK
         6OxPICykXeAj29pIT2e8RUGy096VS36DPcddmyGzg84SSNCm2Xskp4PrB7544zo927rO
         rkKH/h+tTmUU1DcVJMoLZiedAbh0JmvR3VIPov94FYKkPAGvFAOTyPutJxsETWHMXN9Q
         /9hZhM2mELA+1oQUjV8Ja8t18AsDcwhw31oHSJ93UNgeZsSFo4abn48odQiCvMHzoBNk
         6SXl+HMRxKqyYeLY3pbB4h4z1/RvB9G3jwBaDKkjUjnh20clxmm/yn/b/qkYEwPXoWmh
         mdww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QAYF11z2;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id h12si665776lfv.4.2021.12.06.01.57.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Dec 2021 01:57:07 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DFB6F61217
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 09:57:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 53304C341C7
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 09:57:05 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 2CEA861130; Mon,  6 Dec 2021 09:57:05 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214861] UBSAN_OBJECT_SIZE=y results in a non-booting kernel (32
 bit, i686)
Date: Mon, 06 Dec 2021 09:57:04 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-214861-199747-2NcAXUnstI@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214861-199747@https.bugzilla.kernel.org/>
References: <bug-214861-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QAYF11z2;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

--- Comment #6 from Marco Elver (melver@kernel.org) ---
Patch to remove UBSAN_OBJECT_SIZE was sent:
https://lkml.kernel.org/r/20211203235346.110809-1-keescook@chromium.org

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214861-199747-2NcAXUnstI%40https.bugzilla.kernel.org/.
