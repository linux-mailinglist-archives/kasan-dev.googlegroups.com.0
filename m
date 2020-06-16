Return-Path: <kasan-dev+bncBC24VNFHTMIBBTX4UL3QKGQEA7EJ5QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 567541FB100
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 14:42:56 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id a9sf2750346plp.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 05:42:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592311375; cv=pass;
        d=google.com; s=arc-20160816;
        b=dpVAfx13QBehvjM2ioWtvZuUbNcOtyYE66KllcBEmbuNrfAV8U2hYC5gK7JCBq2t3P
         AiB+ntYy8VzdOuWcPlLjzxOd5sgPSLOOXkhOnYIeJ0l1mbTFqKeMUAbYqsbdD11KyNmT
         NHGjkszlCcOyF0T+NvBTUpUDjmv16PHo7G+AlzHfV1nOSk/tBRLvp8hiMOTTe2qwGGb4
         TQUibwWQjrVFOxDNtlyHR9pVAZ8PKNOEp3vZdu5R34iSXg5NKM46t2epg99ah7n0lFNT
         A28xuoDodgzqy8unNATwq8ST5J4gDuUZw+/VVjhEaoglNBQ2Nm3fC9yLdCxaYRkknPOx
         HkYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=vVcqKKH7RcTEAOPKx/omHruEcK/1Agozyswk1QHShPk=;
        b=p3v0yL93mCFJx7oRSSpLO1hhD8rxfTt0ym6SMUmostE1hwyn/vOgogmIJEARHZp4PH
         dH4xbew4wwVUtSdo7VB/yToUQkGIhfAOENxd80CS6s26lJCoJqWYFTuMQroIyxsqri05
         jYwJR4Scy0FyvEbQIDCxQmOJQs6IbcN8SC1uYQxX8hKCPcApQkb/oocz1KUJ2LdJRwQU
         ZtWiV7QRlNmxPuE0z4Sm4xR8QK7YU6Q+BQTbIXqibvKOql4HrvHvL9DH4ybGO8K/z16/
         VfvMlv8FMrx4ss+/hrvOkGc2ZzdECfUaZmuoMVuwhGQFuAg4uKOijF+MVD5XnkzK+sxI
         B8zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=qzwx=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=QZwX=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vVcqKKH7RcTEAOPKx/omHruEcK/1Agozyswk1QHShPk=;
        b=AZucSAAj3tZ7pSEpfohbKhval/N66hfSYa/5OvX6muNFxkoMCdFjo36KnhguMohwyE
         bUdfdpO3octXJNKfMdnzlboiL/lj0QUw8FupmxBYfAG2BrGxVPD0SmRNlcGLEacRWiZO
         oILSnsAPfbK+gS27Y2sXRfco6+PmlL+9kQYevSLTxnUQ8MmBL3iUggsF9XLvzLAlbTzp
         afBIRW+jhu1orODa33TP96+4e+w+ispCF+wphUQVQKykK3RJU07uTfn9fOR2Zp3oMjLl
         OVXi0gg89PNeELfuGmkuogtF2rtLN3oRKIicKDKt8qNB5A2JgkOEMPr6pSArItdHLyRW
         RNVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vVcqKKH7RcTEAOPKx/omHruEcK/1Agozyswk1QHShPk=;
        b=j/+B62xWjqcZbgvwS8yRdHGX/LKRhpurWafVhm7d4n5JZOx5CdwlaoohGgWMS2tVLA
         ErVHr815BimylvbsmYZO9oHjWpsuY2MLlmBDsoeE4w1+npsnQPauFzrRZ3/zQpglUXkQ
         RUYL9A73nACP9LH4TrfoRVPy1r5sOqEyuQNasCjOmIVjz8Jsl2uZv0PbVfV11kbhhK2w
         BrydxK9SgFJJmIKJOWjnA7qtsFXpTq2gL6Br1LsGRrU/VN34bgDiMssP518FkWpIMY+s
         DkTu0oXg7TaSISQ+55brXj9O4vAP0dxslBWSVQoLsFnE6apZ4JH4xxmkjO858NjWqnXU
         GnuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532BwSiDcstIJXi1Y0UhhWj+OHbmA9dp0iscbfpuELcx4B8MeFgX
	n/cpLWKAYmbzaVQj/vOBQec=
X-Google-Smtp-Source: ABdhPJwDphrj3zPoDeNVhfRAZ1XPscM+OcCdNSGQ0rl/Jl+Oa0IVFqJkpf2oxdH9qlvl1UBwLbIHuQ==
X-Received: by 2002:a17:902:704a:: with SMTP id h10mr1918630plt.85.1592311375036;
        Tue, 16 Jun 2020 05:42:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:788c:: with SMTP id t134ls128692pfc.8.gmail; Tue, 16 Jun
 2020 05:42:54 -0700 (PDT)
X-Received: by 2002:a63:2b91:: with SMTP id r139mr1236139pgr.61.1592311374699;
        Tue, 16 Jun 2020 05:42:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592311374; cv=none;
        d=google.com; s=arc-20160816;
        b=BFWAHgP2mn5OwbH9L/cfIpqiwqgt+O8nGopX4lavQ6tfToodgZjsQLgieCP4tLui2m
         2M5N7llTIWwACKJ6M6siFxPBgGgx7njIHzBcUZRXxncO1Mgmc9BjgH4fzoqErF9OuIpX
         GnA8bhPC49tCnermvWFJ85zh0QZVn12LPk/RrhwnrJKskbB+hg8ZeiCx8bKzKgX6VetF
         JF0yZFdZSr3fUzLM/R5IpIPpfKAinRq+mB8iWMMNAk9LHW8is10shMdWf3eM4Jqz/FM5
         0fCb0l1av5MZjEv2yDF+tpUi902nrZG1S6JKZ+Ov4Eh6Jgyq5doIln/Bpj0jOMv5TTQJ
         ipCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=iMZ5yBxTjtszeIuQf9I32gJ8G0SFHiYrVUwsl2g9YYo=;
        b=RpLqQEOlIAQjpaWXKVUOvQG9ySSDo8Z/eQtaltE1ymx7X0gLUJp+T070Xn060jGTXD
         H+5uvYGkKeKz+8EVuob2YhM5ihBW13vF+aAf2jI/rOOkN4V9dxA1qQAqXgzT9BwU9cqX
         rwEYj+fBXqxSWFFZwz4xL4tXV2o6j9+2KNWCc/wesKihVTb6GbIpwETmfV5NfXrqTks/
         3dHgHCbQ7JeCNSRooBxO9cXpNA4BTpoJrUhXjN+1CoMi6py0NyLrIpUZL4YMyj87y91r
         obLNjk5rEwAtNozDpWVPe3SpqB5hF6o8O1Kll5cfkkM54osefqFdcqV2NZZLInrLHDhi
         P2Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=qzwx=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=QZwX=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y9si195843pgv.0.2020.06.16.05.42.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 05:42:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=qzwx=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Tue, 16 Jun 2020 12:42:54 +0000
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
Message-ID: <bug-203497-199747-hqIDMDuQ5G@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=qzwx=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=QZwX=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #4 from Andrey Konovalov (andreyknvl@gmail.com) ---
This can be fixed by changing instrumentation, but I prefer the solution with
untagging the kernel stacks. Userspace HWASAN can't have sp register tagged
right now, and I think we should make the kernel do the same.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-hqIDMDuQ5G%40https.bugzilla.kernel.org/.
