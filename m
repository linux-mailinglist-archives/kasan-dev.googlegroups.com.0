Return-Path: <kasan-dev+bncBC24VNFHTMIBBWNRRL2QKGQEEP45LWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id E26141B6F38
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 09:44:26 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id f56sf9962350qte.18
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 00:44:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587714266; cv=pass;
        d=google.com; s=arc-20160816;
        b=o6khzsCMM/n34zTPVO3cgj290iEko6lKNpZGs+WhCAUOV6byMpzvOHpyoEKgH+8+pm
         oP+xuxHD0GO7DMoUnFb4UiU+G5OIGIdRpbhQE9k7WXMYoMHm4ZbwgJtDthun+FOsPHZ4
         fb5SLzAiDKCmUGBwBgkchrXR3vHHPBCTUhpwnMhCNn+Pv6vdMElYbIpsreNgeesIlNYT
         8lx2R1QmeHHjgGOc62CoAVJ3K6LhajxXTstJNbHTo/hz1L4spPu9PHRu6u19VsTtRhfV
         triEOaDGiDg69Mbnd9SLhAFMHkDe0Xm6KZDcOCWTymlFQLIhlSkmTtwWDRQupBO4Yb81
         GmwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=XvC6bzdb+2iZSxsocNS8xeKm0auASmkNuxODUla0BqI=;
        b=J7N6NZbnsjbgca5fYFNIWpUD3kKjJxZZ6yBktEcKydkMp39jhQVGFAU6JyBkYtxTT4
         5TPr+iX9UAtwJledvN0flD+exzzclpv5vWGd/K3Q15rUy+LBAVTw108Nxkm8NPNKxe9M
         7uBVYsXLfS4FhXRnRUykRIbjPVywe82hK+rUy3xnejxGVp5jVAWCzz8yMFpAVWumDEhS
         aVFCOVBqkWZD6k/6PMVvzsdXepqzlPQrr9CLAWdkfc/6ytfnz6lo7PT7uJZ72vgCCjLX
         Z8scwCf7c0jnJ38nKNjfME943mLkZoa+pMP0hyytzuPusOO0tMmqXGiBD1m9H+/y3MZA
         uWrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XvC6bzdb+2iZSxsocNS8xeKm0auASmkNuxODUla0BqI=;
        b=co+otCX3EbU9WH74jY/7q2zQCC/jpG6NGlCPhZYVCYdSJULYt8CT0j+lVSE1gUj8up
         6LRc6F6nmLQ3XTZovXaJZa6H5JOd42kMfYvvqv/gZ4uGF/sRHeCN6nE1bajB/h0ftqJO
         1RdrK2z2rsykvSG7aBFCgGOnkWAD70jJW6diCuHCfLEJklUuD3CnbWy1e4ri+AP+uOlY
         kAlImr5qMEisdC8RQeiWXcLA+qdKvDvDIrvAdP8uedWBUMGs1dS9oxfwqCa/6PPzMhJg
         GOZoj2q7xULDXqftxAyJDjasGW2vf7buOEMvVyGehJe5W+S7DHgmCb33j0QYz3A90Wro
         H+GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XvC6bzdb+2iZSxsocNS8xeKm0auASmkNuxODUla0BqI=;
        b=S4egjardxT6wLZnrzG/YtQqedfV6mnDVvRClBxXbLmlSC8HSKzNmewDIeKRCmXC1J7
         tN7P/rUd66w7KWDDgUXSuSjRtE9FGUCmK1wF8rK3iweMl8P0JhlFKQ8ZYvXdMwE0J+Zm
         Azdtzcut1OByTjfpX1mZ8dFaHCOrClZfej/A17twwLfVCnOd9PRT4TMLPopCTRMAGVu9
         3JdkwquTbyA76qORRDL9ljpzgFhtAUaQp3b+I2PIz8H0pOEq6D/PBWbj9VFPZVSVMQb8
         vjJgaNUS5Oqdn4DuX6qyKd7HTE1lTakBCkDZ9AjzExBo7T7AEEN0fREDe5HLb74vQOcZ
         jQrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYFX8zXEAEjbdwUP5W0m5e6voLBERSG1xY9uwgfwdnAnuqcMNhm
	E6OJCOBvHTo1TJ4fwshRYhQ=
X-Google-Smtp-Source: APiQypLxYjLsmWxjqhOEtXciwEqhB6/GpSeUgvBQSa6AVuo2bJEPT2E5wq1dzLZZxbRm4VyEz3F9bA==
X-Received: by 2002:a37:54e:: with SMTP id 75mr7641513qkf.257.1587714265969;
        Fri, 24 Apr 2020 00:44:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:148:: with SMTP id e8ls5953858qkn.10.gmail; Fri, 24
 Apr 2020 00:44:25 -0700 (PDT)
X-Received: by 2002:a37:a312:: with SMTP id m18mr5955468qke.251.1587714265696;
        Fri, 24 Apr 2020 00:44:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587714265; cv=none;
        d=google.com; s=arc-20160816;
        b=aDt+eyeiuLG+Y3LC9lMOnaJP+zURXIXP16qJmlPo5Xq938f/Qqkz/KE9/YPrOVDXxB
         ajh9qPjQ4vQ4DcEVYOFqPhYQ26YXxXvmNVY4QdpC7HdxwY7V5DGole6WosEJTaerbawF
         HOvMu64VKz7Yi55a/ydYi/Cy8Jq0/SDnUVhGEwmwwW3C2i0aC3BD7SSloPUhnkx5Z2Ct
         FyAcg3C5WBqMrW+UdH+33e5cLh46gItE67bxkggIHnFMUdBSjo0jvmPfYGVF6AyzSWYS
         ikC5L5nKkzDOrmi8exfzJGnpRFRmMCklsx/ak7cd0LLWfd2chytA5piCDhOhX63ScbvZ
         k2kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=kX+hKOR0JByr06e/BFQDlLRUDCBuPRe3hRbeL/lEcXE=;
        b=lzr7eehXvtqef8ib3kJbucOSWX9MYiJCbaZ3MUG78/bKRNPxwDQZMxJuuUJtu4bvrV
         Pz65XJh02niSWKP9nqPlI3SQVo9VqC+LiS33BdZdnH5QL1yICSaHHTuE8R1tbKdeHsGA
         8vCgIOLvfei3u6tvhYGGYwbI+Snb1kRZ3L5QVQpE37ca3rph5l38oDc9YpXSDiZQNJxr
         QMVDvgIpOuE5CUes8SX98QTPWv9ldX8gIcZHCtAJv3rod5dAkzcBo5KzQCfG+2MTqCHE
         fSiYIcCmE4KuK8GLdmCIcCk06sghKmxyz1x3WNyZGewzii7xDvoVQkKgN3oWWUUL6T2D
         s7eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o3si484387qtm.0.2020.04.24.00.44.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Apr 2020 00:44:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Fri, 24 Apr 2020 07:44:24 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198437-199747-R2ArY5T9ti@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
We already record free stack, the idea is to record call_rcu and maybe some
timer/workqueue stacks for heap objects. The tricky part is how to not increase
the header size.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-R2ArY5T9ti%40https.bugzilla.kernel.org/.
