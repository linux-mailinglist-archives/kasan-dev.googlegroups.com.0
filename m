Return-Path: <kasan-dev+bncBC24VNFHTMIBBQP46L6QKGQE5XKVVSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A7F12C1F55
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 09:03:15 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id v15sf14944431ioq.16
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 00:03:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606204994; cv=pass;
        d=google.com; s=arc-20160816;
        b=MpRfhd7iRwjWTXP5Evy7cbbzGugJ6LxaepuPp1LthCAya3Rl2/AUS5sjkEHGfVywyN
         44Uutl3pmV5fB/K30r7WKX5QhsE+DNzcJjtKG69XhJyCXCbPFVLDAy9iLkkaZrNvZAqH
         vO2+pgNdcRwf06FNhG1XvnYFj0KesSu7fQPyP7uRHeU3etiTi6Fi5Gz70PQ0FtuZYh21
         zJbxLSQ8JNNPSxzB2D0zsPB8ktGMz9zxiT/PhlyuBQ57puHHYLwhCLWTc4xeJ88+tK2g
         xWVzAer4URrHeMNIYTKMCzIhhlZdKIHtJAIRD2qgrjn3VbD8nFhQKN9kpjGaVLOrZ0+V
         FR2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=TV5FArYa7TPrhUO/GbgIeULWDTkmRLZr6UmqoksA9UA=;
        b=hahcrZRS/x3Uj5UpGjloF4JMdtCQeKrfIUKvnJiglQE+N8kAg4/X2xA7JUxF8/M6D7
         m7u2/pVpsDwFpsDY58vLYan4mpd4DMwmw+k78xIGmec8MkCFvmNqv1G7iyDW3sQbbWaF
         JtRgoZdXfYkHj4ofyigxhwwD387mfaiKfx/hVqQeydDT9JLGj/Q0O/HaT/pzY8IAQbiq
         4PDmuNR+MaFLUyGPkCdlB+prIYgbxNcrJrEj4Bpj/UM3eL0AddszRo1nLrAvnoSq+n3a
         D2qa4D7QMmVrLlzWvb65JSVopZdWkEXSHROYClcr0E2iPyUuJBdNxXcMbdGkMhECx9zv
         sBTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TV5FArYa7TPrhUO/GbgIeULWDTkmRLZr6UmqoksA9UA=;
        b=ju+f9gBKzbK08BudNUpZ4fggd+yzCg5BeUwhMy1Ad2HIbZz0qNnudviBmF7eOrtGT/
         Da+Vpp0Wax5LpyLyVADKBJQdFXguAmbG3/MNLsqSAsX6jwdLd5rkNqSAr74LWLGisyV+
         sbj+F6smqTFRUBdlvyxiI/l56fHhW5zNkBPdG3Nq5P3mrnNHZwNvHbS7ngMbr0cfKprY
         7cS9GL+m/FHkfEe1BluWXwfW4tip5VVeyPuA62Mtwavjl+wOu9kXDuklOzeCCA5aFj3s
         St72juiHtqNfzKGN9AEPdlKotn9s7jGqjThqJ89lO/poE/wC2HGzm17bdeH8qm3EXOHG
         J3aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TV5FArYa7TPrhUO/GbgIeULWDTkmRLZr6UmqoksA9UA=;
        b=Y/8V2yDsXKl5xVBklTc6Q4x2dyw5fki0zNl2/Or0PmwvpxbvFmWCS9InzSlYIy/pUh
         IPDJBCvm0OTPGKKOyPvo0vS0+ElYUN0+MtNiIn9Hg4+lvcwguCjtCeKLf9olkf9xDx+m
         JS0CE16Li7f82Na2tWl8UI0Ht2N6RtCfXGTFG3osFDc+yJfje+UWkOsUioy3crvy2Lrz
         Z/W3wyXlBr1lTnOmiF3TxDhEFYWs60Yt1QU9jslSjHd19GBvh9sNHbKgPjZXeysC/OQg
         zklPoXhA/PclUQF7V1fphp72G6E3Mi0eLLitkiNEAUwbwjSa/rIuU5tPWk+wlimeuLR/
         fGlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Mn19+y4I7qKu1SxadvMT9QrseTfYrkW4jY+6s+bt358Z3jYWG
	rho/NRYi/jV7jwee2RB1+QQ=
X-Google-Smtp-Source: ABdhPJwqht3eewUJ5OU8tlpZ+OhOSgGSTQOuFj+FHePrKQ1nHYl4qiqfxrGAuKxrliS+KyWlNIha9g==
X-Received: by 2002:a92:c88c:: with SMTP id w12mr3470884ilo.204.1606204993794;
        Tue, 24 Nov 2020 00:03:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2616:: with SMTP id m22ls2277617jat.4.gmail; Tue,
 24 Nov 2020 00:03:13 -0800 (PST)
X-Received: by 2002:a05:6638:224e:: with SMTP id m14mr3406921jas.59.1606204993438;
        Tue, 24 Nov 2020 00:03:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606204993; cv=none;
        d=google.com; s=arc-20160816;
        b=aG4n28iwqMjUFlVIyRQEv20SlRuGIXX7eGUcwoh2ACixGJNtpZZ/gvb0Rj/daxMsCX
         rL349QTAPqOTf+PuUDfG1lxE36d/O2YxBetHb1c1/RIIYWCJYQmbxS+nY6bw2hCgGTVm
         IyBHOI8gH1X+P6ve9f/s5OSUUzRBiZue+Z6YCiwyLIkN0s/PUK+rNGhdryeQnJfy8O8x
         BUG2MyriqOn13sFkxQdvDdzcvUSQ1to1ADi3HYnSw9RZT3vELRJ0bcKYxCbBgDbu/25o
         mk771+Q+fbtGHeKNvW9WaU63zpGIE5mmr723H0vx7p4nwQ4OBY3gMpEiLQy4aIY/L1A5
         hIvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=dNcf1lbPYFgDrdturPKoICyCFR5NRp7feqeaczMXuV0=;
        b=KGyj5oJd9FKkdQ9z88jmAJV5wzT7ZBEiztn4iyZViynbaSshyJmOyghygQAHQbMPm/
         Zp1BxEDc1eWv5H2NOjNKkxzbfK940AX/XXkDSgYj/7yJtbaYA15wEEos9ir9cNLlfKkw
         xUKjDkeBN17DJg+ZakOlA9KttkTqJBWw6SS9IkkFgAw9bQf1oBzXW3bACUOPAeH2fA+h
         +QTW0iv7PjMV5E8oJGdqCfxpiA4YpwjXjiff33eVxXnvB0N+9aUHsW02yo/AcEPYt6hx
         0RYHrCX5LJGLF6lIfe122W8SRjhH2Cu4DS0wXcPB3ZXrkNZUsMzpXBndzRwuMUPOMzwt
         NbgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a18si141415iow.4.2020.11.24.00.03.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Nov 2020 00:03:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210337] KCOV: allow nested remote coverage sections in task
 context
Date: Tue, 24 Nov 2020 08:03:12 +0000
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
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-210337-199747-xCr5CkcIVW@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210337-199747@https.bugzilla.kernel.org/>
References: <bug-210337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210337

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
2 partial, but potentially simpler solutions, just for discussion.

1. If we assume that recursion only happens for the same target KCOV
descriptor, then instead of full recursion support kcov_remote_start could just
check that we need to collect coverage for the already active KCOV descriptor
and increment a recursion counter. Then kcov_remote_stop will decrement the
recursion counter and if it's not 0, bail out.
This will allow us to avoid the WARNING and collect coverage for USB without
full fledged recursion support.

2. Maybe USB code could be restructured slightly. Namely instead of:

void foo() {
  kcov_remote_start(...);
  ...
  kcov_remote_stop(...);
}

void bar() {
  kcov_remote_start(...);
  ...
  foo();
  ...
  kcov_remote_stop(...);
}

we do:

void __foo() {
  kcov_remote_start(...);
  ...
  kcov_remote_stop(...);
}

void foo() {
  kcov_remote_start(...);
  __foo();
  kcov_remote_stop(...);
}

void bar() {
  kcov_remote_start(...);
  ...
  __foo();
  ...
  kcov_remote_stop(...);
}

In some sense similar to "locked" and "unlocked" versions of the same function.
If you already hold the lock, you need to call the internal "unlocked"
function.
So this does not too unreasonable.

I have not looked at the USB code, though.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210337-199747-xCr5CkcIVW%40https.bugzilla.kernel.org/.
