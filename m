Return-Path: <kasan-dev+bncBC24VNFHTMIBBE6JVL6AKGQEXPWFDYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id BAD822910A3
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Oct 2020 10:00:20 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id k15sf3135523ilh.2
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Oct 2020 01:00:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602921619; cv=pass;
        d=google.com; s=arc-20160816;
        b=aHtUpF8mbUH57FbSa0UanjDzoC7Q5AUZo8qpXGgwZdSxdRnTotBKf102J22iVdaMlQ
         5d5romWCnaQ3GF1bEBxYwHaVl30npHbZYmng0CHaoQHOyD1EH5ETO2MnCuFQZCYhDJ1z
         jZW1aSJZMJHLtaHlOpB4Pw6xnAjcM9N84BFuj6q10WXDy6KEgOpQMGdjrWZB5BhiIG74
         1aH6L2CPKb5ca83AW8opIgKNjtRJ557m73xegPT7IO1n1mGN97VDOTjjBoZYRS4xvaQD
         PT9DSi8IakIvbezDKyiUgDGajfZdjSRl6aksxovUAJFVM2fK9E2rF3MP71q6M39r3HXx
         k/uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Me4OGHorUUuiRxZVFa7tYFFPev8Hq5cuPL6DFyuEYRs=;
        b=CwEtOVqqsCo5aXJZe1oa9OIwEtV00vkr6cX0l4a1GoQJQZDgSNuVnmrEtLX8b3ohUD
         /6r1C9vlRDkeGuTN+pgqfREPNhzBz19XltfV4cTyDNTWTh4EIO6AyFGSBuqqrnV0UWUb
         J96iHuLr4Sfspfro0fxsBg0qU+pZa4Km96VSRBnUlG6IxE/wdgtJx93SF6O64PImbTbq
         x0DVARMBjQi1QEnQCMDrF8InZgtrjqJXEN04UKT//5QuFsfYOm3ENmLbTR0w3Cxx/Gb7
         56KUPX1l01nJR4NBh221dWjX3E2rw+l98eax66RyxAkEcRPHQosqqDcOKvfkCST0OvDC
         I+/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vprn=dy=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPrn=DY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Me4OGHorUUuiRxZVFa7tYFFPev8Hq5cuPL6DFyuEYRs=;
        b=iSU0SPVfQri/mNkkCdlFN0xT7j0l6Inj1jTgHRyDBgobn1Hg77Tej9WOon7iwAi7GI
         le1bRd5WAmtQTGDYGyVaqEBa2TpJ1/r+Igmk6IMWL8c59RrdBRC1sQGQrgfsgotRagZ6
         375iu86BWEkGTlwF3qjD7g4sHI1j5lPnknKa2KVNkN74r1NLrSWFDz2B1nBUSNu9jMHK
         C04RYK4gQs7sza4+9hUDnYEXmL4JgMDiJ/yw1KiHq62GxoM64tOeTh8dmb8hM6L08Pf4
         m9j6kdfOykuj/EwFVQS7mC0WFmr1VtV3btAu6slxEL/IkyyhPzDoSAC1A+G/Vx9tFDOB
         heEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Me4OGHorUUuiRxZVFa7tYFFPev8Hq5cuPL6DFyuEYRs=;
        b=q+79JQ5bqul4cTIo57dSuWuOaWPfZ80rEI7y/1HhUc9drWf/MhQIW6XbRlfOMvSwaJ
         IFOtJPxESVvDql0/7KMwHaD2WqnVeCbTYoAGIEXjYwSxSOE9HUiZFJW21y255JoMsyOR
         hKtD0g+ys10dpm56jzmBRNHPEzXnlaJsk4l5p1NPUxYeFg2RK4M84KMUB4Zbv78EVjya
         jSpJA08umVGxRziJs9NKkSUyDpAlRwhdnavKgQXxmLcYXWialASU7l/qV3Vm2WVMGf/c
         9NziKimq+O6bxUd7wk80tv+HDJXhstZmAnkYFtvQY8El0Ce/cQpe4K2HZEQcQguLbucq
         iiPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ZeHrrvfoL/BzFeBI6GGs5LmkefehjA+3AkbeejDTHtl2yev4H
	RGW/2C79LopffZt8IqRZXho=
X-Google-Smtp-Source: ABdhPJwZMyxprV1IKElwH5HJZ6oSKuAEXOIXv/arTgISoOZEP48tNvS/UVzqK7YIjNplLEXTYFcI1Q==
X-Received: by 2002:a5e:9307:: with SMTP id k7mr5219489iom.129.1602921619589;
        Sat, 17 Oct 2020 01:00:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:770f:: with SMTP id s15ls962917ilc.11.gmail; Sat, 17 Oct
 2020 01:00:19 -0700 (PDT)
X-Received: by 2002:a05:6e02:1241:: with SMTP id j1mr5641117ilq.267.1602921619232;
        Sat, 17 Oct 2020 01:00:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602921619; cv=none;
        d=google.com; s=arc-20160816;
        b=fdc4H76eUVyUukk5i7WWclMPBd5Dv1cP2sFTF+opFLD75j9eg1nMk2NWeel+V9QYTj
         O/S+JVabX5X34KarU3G67sFtaJOC9yjg/zRBLJxD/IEXaKMJ+e2ElCRy9x3sThHEZykR
         rubwIEn3KX9L8Qu43DxRGnyzZlw6oMQOvB/VB6pDlFgZaZu/vRDnCHkVZ+uoizGu85vI
         pEzzVkqkskBUG45O+KssXOrYA77KMbbo6UHdJmZhlJY3InAf5oyst5f+C3s9XpfgPK4G
         GqJ92IyCeT3oySVEKnSwhmuCuee2zkmbny7gT2GHin7h3vvmBM/uhCsbGKGDJcBp2d8h
         skqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=XoGivmmGUTQmcJhW3edBnHV+h+c5yBRVpT1q+Y603nM=;
        b=nE8ealL7N28OKCIEQsa/HZ51Rd609con2k53helljTqc4FMokLwDCSIoiuIYsClUpS
         2SXuJbcK7Bfl31ficO6PPqwpSZTqDeQbwS8BiPQIf5If/4Tye6SARkR0p433iuGC0iBX
         lWjZ7VyXMr+2Nn2UTbHciMAUsqcbMUZ7hd0MFWaC/8aUYRHmJpjlvB64O8xw13ZCfmnF
         MmWCkphuTBb1ruyoTuBEWZ5Rt0ajlgAc93nAp42f/hKDpuuHlRB5CGmkJzp+baIn7Ywt
         uaM5X5rGyf4W0tuGWSwdQOFr7HA2vm5S6GZEwfaTj3hiVbhdnnUFUALSJIff2XwWdH2J
         J1Ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vprn=dy=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPrn=DY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i8si256401ioo.0.2020.10.17.01.00.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 17 Oct 2020 01:00:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=vprn=dy=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 199359] KASAN: double-free is not detected on kzfree
Date: Sat, 17 Oct 2020 08:00:18 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: elver@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: assigned_to
Message-ID: <bug-199359-199747-tU0MJZ2INI@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199359-199747@https.bugzilla.kernel.org/>
References: <bug-199359-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=vprn=dy=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPrn=DY=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=199359

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
           Assignee|dvyukov@google.com          |elver@google.com

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-199359-199747-tU0MJZ2INI%40https.bugzilla.kernel.org/.
