Return-Path: <kasan-dev+bncBC24VNFHTMIBBV7BT2BAMGQESRUVPAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id DFE2C332D49
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 18:31:04 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id g17sf18000610ybh.4
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 09:31:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615311064; cv=pass;
        d=google.com; s=arc-20160816;
        b=VXS7S1AcbCkA1ywWvaqj3+DxOY1h+TTjeB92Be2ke/nnlZuXwur+V5YJk3EQIl09U5
         ff2vr3mIiKXExoPO0dMkNZtBuxAnkF3MseDGP9x2Zy7URmBZPmeWABDC55iIHr6QFzQO
         q1YHgp05hCM5Hh9/FuG36Ri/8mJsPFwu0RMLVBvZnQjs9y+jQmE9Ny/Ej3IqinyCUETi
         02vJUCDZ1iDZ7qAKj136xfPIvI5JpqwC9kjKNHazJ0dqhyNall/MbUHFXbxXbKQIKyBp
         L8nYvqFmEtJXqRZmP08UU6Dpb/57WZjNPS8uvr0nJIEhfTKdVGztPLE8rOPJtBricD92
         YV+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=NWpRQNo5QVRP0mI1KsqnvhPd7n2nXaXIecNa/YHo7Fw=;
        b=qX0dnG3wDc1wBxiVXByVYKsoEQgjy9U5kWA7R7pQGSdf2rNpV+kn3f1jeWl7JnltTc
         f0+XwBCcf9lUpqyutZPkXJ26VIJA/B3SkzRnMtcRsuobFznvJjzfpg0dm0CBz96fupxa
         MIcWsOIl8jB5ciCCdVWfT+hEAuYyL8NPHOxuStqyrQ3DE5Ua+Ucx+ydtnrpcQ9RzwnFo
         jgPzpv7MhKMlMPglIvveogi/hm75cD0wmXjXULI5mKAwvhBCB1/a1Q4GNWL3TJupwCcZ
         Ee065RQaecsYYTXXIClns/IIv5BxkpekLHKiIwRGcTfIqPrLqv+nstjHHTlubC0WrWUD
         QDkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tUvYZ2wi;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NWpRQNo5QVRP0mI1KsqnvhPd7n2nXaXIecNa/YHo7Fw=;
        b=gZtfigll4um6+tHO67Q1XOBEpQA2JMeIAQu+OD4y2YLOIJiDEgUI/zM6BqthNkmAOi
         B0kspCceqczO2WEE3kE7k8+QKskVz4rKMmT0LoZh8vEZPHYAtMLRuxB4ajOiWq/hdUSM
         J6MXZZyLPjwhOtHb+uc72arc55Fw29vRv96zs2E6FccFl7DWVgODvgHCymekfo07KN8b
         3BojXo2sSSe+uyLLb1tlJEQXfLdP3GqTAOCcSoTHwVyLI0jNTFXY8b9ugmdWTvuIg2hk
         T1ZrYFPHu1nGXeXjXIm5jZa2HNaE+8N11FW1EaiHNFOkvURblMcxZrrMD0qhFxSNmTzT
         xlSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NWpRQNo5QVRP0mI1KsqnvhPd7n2nXaXIecNa/YHo7Fw=;
        b=GgF6oFDqZnRL6ESzJ03Oi+k/7rNATg8bNSZU9uAXZoLJ/e9m82Zg+ACSy7vddzKanF
         uvEwx+RH0j/nA3Axv8SqUH6VQPDp/+vhWsYACpDsXcYb3VowWn+da63jladCLdmdsA0b
         0TnMRUU8hxJ7ttQjNIU9Hg6agxA2VGtao8nkELZSz1mMz3YBIsCEwKwk5nthW7VIV0KS
         aUszIi+JJXsgu5tfuhsRMxTq3H8w9yoHmeUYhrtb/J4OcS3XtMTZbmxZDyUSqcy2qQ2F
         aFxcrnPj59kxc5VRefrof23xHQAYB+0HCoTDlvrGg4/zpZ1BCwUiaqDacRxA1da3Og82
         PPbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HGP5zszeR0y0EfEmTs3DR5IlQhXmRtJcbH2YsWhfBGwIcy5pf
	uIW9Uy53pZzki1vHLuN2zyE=
X-Google-Smtp-Source: ABdhPJztSQP4tHURRCIl17VpJb/84uxJcbczaLUQeHTSOVcL5zPfRpIizGKyaiEq0XtLIvdf4jXzpA==
X-Received: by 2002:a25:254a:: with SMTP id l71mr41580257ybl.125.1615311063973;
        Tue, 09 Mar 2021 09:31:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d8c7:: with SMTP id p190ls10713229ybg.6.gmail; Tue, 09
 Mar 2021 09:31:03 -0800 (PST)
X-Received: by 2002:a25:ca88:: with SMTP id a130mr41445500ybg.414.1615311063448;
        Tue, 09 Mar 2021 09:31:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615311063; cv=none;
        d=google.com; s=arc-20160816;
        b=LK5GlsoxP2PR+9tlqagM7HGu2plyySlmjpqNjbLAwyDwwro8r3BfzCz9Q+ODW50WdP
         x0S818JrMneDaoEmPgvro1ZbVqKsDiYVnkHbb+5g5KUsOCxDcg+F4xcTe2aQ97haV8nF
         3yLFCiYToQ1wA+l9DUeuG+kWTfDs/HnKTdTxdg2XrGqCysaSIPjD5oFx8+UdyUUJDPYv
         nQS8wf67s++NwmqvCim0tavDMKQFNfpsKk2Pou+j7sPVqdf6zgtQSVowHZ3fYF90cRCk
         RmL3R623WaRSp9ddv/iBS8qoTkvg0LCiDtv1Ho4G2Sq5X4cQDgFTYWSAzqhU6zqhZLbS
         JwzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Vhj0zxkLuMEXDpkG6JCCHgU9hgwub8RpeFHiU2Tf3ZY=;
        b=DTj4oL/Cv0gWU/id3jQBIwzBGx16Hjskquh19Ii8IBG0cONkmmBaBn1ijysrDXbowI
         37zMqvpobqIeOXrU4gl072ehNoRBNqBvx8pSpJh/d/N6a3IFbsr68oSBlNezf8+o/+SZ
         DLervukopb+Px2lfYvc70rvHhxpZciM3nkxD1P3qNNmK2ZseIatSs80Qlfip2RtOkudz
         5bo9awirJqC0X7ZNdPUPvO9HZp+oNTfeYKJgk+Ure3yzJ8wjqJsuYZQ7oDrsg6AOH2VV
         qAgsDFi8XVSRs8nf5LxgYwnTjExu8tBKagBZBcCv8BrMZRbv3T2hwnWVFdnZyu5ySR0x
         SBng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tUvYZ2wi;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s44si914133ybi.3.2021.03.09.09.31.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 09:31:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 7274365244
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 17:31:02 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 6D7DF65368; Tue,  9 Mar 2021 17:31:02 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212199] KASAN (hw-tags): fully disable tag checking on the
 first tag fault
Date: Tue, 09 Mar 2021 17:31:02 +0000
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
Message-ID: <bug-212199-199747-wXI56chjzN@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212199-199747@https.bugzilla.kernel.org/>
References: <bug-212199-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tUvYZ2wi;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212199

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Checking kasan_enabled() in kasan_report_invalid_free() might be used as a
solution:

https://bugzilla.kernel.org/show_bug.cgi?id=212211

This will stop KASAN from printing invalid-free/double-free reports after the
first one is printed (unless kasan_multi_shot is enabled), but that won't stop
KASAN from detecting and aborting those invalid-frees/double-frees.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212199-199747-wXI56chjzN%40https.bugzilla.kernel.org/.
