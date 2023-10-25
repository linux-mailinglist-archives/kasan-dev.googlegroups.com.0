Return-Path: <kasan-dev+bncBAABB5XV4KUQMGQESUEHFTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id D60867D61D7
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 08:51:35 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-41cd5077ffesf970731cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 23:51:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698216694; cv=pass;
        d=google.com; s=arc-20160816;
        b=mxaJ6MOt1Qv3RlIn0GmCW8LXWJW23NXctcb0hUz/ND/QYYj8MU1r/yGpvG2WIIwcX/
         aFi03nT3eVTi2+5GXjHnv+7JP3LHAgRbR5SKERbJJc+gseHMwnas56ABsWntPVUx+e4i
         tokV8Z37mGD3iiuUiMv2mLzQUzEuqw328UKGGR3N0t4Q84mOJP1Qmn/VcdBWyD5Z/aAR
         1pZAva+FzGkPsJNG6Z0Os6uye1YfaffBXO8rd7XMiEstOWEaZflxrBp8JrukqYMCpbj9
         QuQGQ9hR175PKlys41yf2n9OSJLA9GgBjwkFD13CiUKOHsps7ngcny/dCRRndHfTtsnm
         //lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=MU3j9BpjWY5+vpHVb43NfQ8uCrP6Gm4a9Uye6KwQi80=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=MQcHAuWvNBPmgMNKWIwqacSQVdbSjgaxl6mDiLrRCJmpaKVNvu/c1Z4q5HWKsB9/lV
         870Qz9dVtxZo4YlHjztkXF15sLNuCbTVwJbFBCFHdWKXcxQAabVA2QL5h9nN4KZz3Lku
         C3pOPkD+KmnrPO9G/DNv3KjaUZ9zVhQXuFbnOw9nFcpVKoLxrk0y/Y4qMGMP4TVzLX2D
         ieCtS8l54XRMyNfXYRUyq+tMkqQl8raFDJfvXOLVM18jpPuwNGgCsYYmKo+hH0frlc3Y
         K6TmtovVgkHI5xAKihNT86dE7FztlIUv5TrvjEeJHcvvuAFiXDd2jpF0qIOrldzWMDf0
         oj9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IZkSxjAz;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698216694; x=1698821494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MU3j9BpjWY5+vpHVb43NfQ8uCrP6Gm4a9Uye6KwQi80=;
        b=Fqo/9BuXl34niJ8uJJ9cwTnxMoygHQYryP0tcJeyqKRC+el4pjA8yjqIXS4r/yCoHo
         G9I+yF4JWERS6U8VobZxPEM2oNdP/JPxq7E4AUKlUKk4yzvUR5jyBq7HgZVpcxTpS+3g
         BG1F/ZMUOwBJKlETvlXYLyndNaX6Jf/ueFuVvcilQMM70AMz/l598pNpWdSuU3gOscTh
         w1mp/rqDh+8Gwh9grtIJnw63ab4f4J2NMt0bBMxImy1j8qgCX5y1dKYKg0NzbVC0CIvD
         TOG7xeXjvydZXpnBgovw/PWPwNi09J9zFPU0w+ue34on4Ed0nfajWEMBjqz3L7gJfuW0
         YR5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698216694; x=1698821494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MU3j9BpjWY5+vpHVb43NfQ8uCrP6Gm4a9Uye6KwQi80=;
        b=by9zgq8urW1de35yi4Sw+f9hCLV0lg5LfsB6sF3z01gyoMSvqsR9OszhV7v79PX17r
         KlaK6SU7F/TA3Vww/ZSKiugVlxLw4Q6zo1xdJL1VyL5bO6DIAQWTHD0FduiwGjO2+IsB
         iCgUIPcSnj7Z8/n8j3sA+pedFf9oqqj+/ofYINkCLq74bLiLnLd3vwbTf2d4v6nI2trM
         vAOgZyRhw8eHArsgCKcNN38iyLoLvgU1CyTFlmsdvD9ndfFCCG+lbH3U9SGHIiSgk/FU
         o1/AuVRf+c7AHjhysrwT0mMZE+QfvMR79RK3CsoNBW0oS4XYGrm5xUrPtjDEMsjANSxp
         eJ9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz6pOpLHYOscPzcjpwJWxGVs1jD5xB0LmmDK2hTy1IDlJXBj+Zz
	/hti7hXIev7dJM47BUJeFAE=
X-Google-Smtp-Source: AGHT+IFush8S7sk+3nnAIPAkSmCu3HTylq6dVrAP3nUwrsbxzQDTyERP9zxgUO6EQ10uq6EJ+DWDLA==
X-Received: by 2002:a05:622a:288d:b0:41c:e345:1da2 with SMTP id ke13-20020a05622a288d00b0041ce3451da2mr82728qtb.11.1698216694395;
        Tue, 24 Oct 2023 23:51:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4d86:b0:419:693a:afb1 with SMTP id
 ff6-20020a05622a4d8600b00419693aafb1ls1142342qtb.0.-pod-prod-09-us; Tue, 24
 Oct 2023 23:51:33 -0700 (PDT)
X-Received: by 2002:a05:620a:2487:b0:778:8fa5:417d with SMTP id i7-20020a05620a248700b007788fa5417dmr14095286qkn.47.1698216693438;
        Tue, 24 Oct 2023 23:51:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698216693; cv=none;
        d=google.com; s=arc-20160816;
        b=JWytkU6T6o/0kvgkioy5QYejUo5BB4Pbf9AzLvQgBNgi/mDNu0SVFzP3slM59yknp+
         vU4gi/UtZivX1jSsnGI5n4W7S5eY2GpWcfg87TwGxomvOixAT8xjVxytyg6yptsTwm7S
         XW2qLQteSw8ZAzDqMeP1Qdv25LvvNLfJPs5sAc8lMmr44d623MuJpfTECAThZfzs+VTx
         o+EiqP8tFW3GNAMdOjSWcto8inRInBxuktTtlg0qEf04MJNkOBr6ZEXNmRlbQiVgfgSJ
         XwL5Yb3WgO175diAo5cNHRXYTV/NfuhF+h0uGMTEIanipwrXknSLEixbmAJ03qLOit6p
         CYvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=iwqXvWsbobjmrcboowiIK805mdm8+AVls+iUT0ZZnEw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=X0qvFgCF+I32C4hJuzukoL2UygCvS/3iq/rHrVpF2DeoJiKm9y9vCG3s0062FsopDF
         DLkN3US3Sosi7IC7JpEm39rptlW+pbnlrMv77y7ocI1knJOam1dyzuoSMtebzNO4XI2a
         24kd9hMa1LOM7UF3xSdBKG3YU8GhCmCplVdNJOmhJTQwthtmPhn3usCzcGnGy8p3tYFm
         ewtChB9Grubw1Sw05RUNL19xYNTJGfygWikekrlmzlfYOHo19wd03CbDtbWfwuvKkCLL
         CfhA20QAFaHZhGGhjac8OIhlEsnuIT7r9sA751PmJ3fblgczcvjsb3lCY+oot82nq2p4
         UFEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IZkSxjAz;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ea19-20020a05620a489300b007742b036b37si1170806qkb.7.2023.10.24.23.51.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Oct 2023 23:51:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 162E761B0B
	for <kasan-dev@googlegroups.com>; Wed, 25 Oct 2023 06:51:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B3047C433CA
	for <kasan-dev@googlegroups.com>; Wed, 25 Oct 2023 06:51:32 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9DE68C53BD1; Wed, 25 Oct 2023 06:51:32 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218043] KASAN (sw-tags): Clang incorrectly calculates shadow
 memory address
Date: Wed, 25 Oct 2023 06:51:32 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-218043-199747-XHtoj5fvhX@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218043-199747@https.bugzilla.kernel.org/>
References: <bug-218043-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IZkSxjAz;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218043

Marco Elver (melver@kernel.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |melver@kernel.org

--- Comment #1 from Marco Elver (melver@kernel.org) ---
This looks like a Clang bug. It should probably be reported here:
https://github.com/ClangBuiltLinux/linux/issues
or here:
https://github.com/llvm/llvm-project/issues

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218043-199747-XHtoj5fvhX%40https.bugzilla.kernel.org/.
