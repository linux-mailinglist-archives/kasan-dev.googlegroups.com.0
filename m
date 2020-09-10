Return-Path: <kasan-dev+bncBC24VNFHTMIBB4OR475AKGQEQYRKCPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C1DB264086
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 10:50:58 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id q21sf2885962qvf.22
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 01:50:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599727857; cv=pass;
        d=google.com; s=arc-20160816;
        b=lCvc5bIgAwow/8wLCY/N3GLAU/wDo8+UVulE8Dr9kk+OyMjd6LsxwKiSwKXVMc2YqS
         0yEAzRJFFdWARizHjMMEbPNUN7inuTWxwrT1RaMOw3K+lKbTivzagVIAJ1XF/lDCYUL/
         w+epxFm/WFGeHWGjs/lqwfoyiVxTXEfcNHXNtgINY9lxM9NatFaIOwtd8FY0ar5A8exz
         ssDv0rUcZLKqCAiTsFvuxn4nYsh7dSWOFzzhWRBqN9c1LyW1NKuMw482F1EYCczTi+9h
         lqLmu7yTojlfHOJu3XGpp4qggJma0OJ4U/ZWdd7FuP1GJ68cdHYdoqS5N4dwx5Ie2OW4
         QN/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=kbUHkRBLTwwXhvzBntXAnVcJyoLhDTYuGmNj3xRNm2s=;
        b=oNKQLLXjPySU3ZDOThfqv6cJgNyrYWbJ8VLhDPWbgY1rd0UNHCl4exmR1xNM8JiyOj
         MDw0MYjfWfx+/EKjM5OX5HYNpU14bSK9E858PDVuYSgM3d5OzaMNMzjCZ8cXt96GdNGn
         qJFnugjQik4Z/hAsr9BDtsACWvVonDMtxTVL/OjmEq3vWA3sB/8EFEUAErA0v/F+UVUm
         SS5V4XX5bnyORrU10IsPBHlw5xsT9bxpwMv+vvqX5fP4NYlPJcjMP6kMlVayKZ16rkem
         YJEchjENT6wLEkOxmjq0+SmMRrFvFbamVVjU60KL9MzyCAvo3Ii3HVExQC2VNKO2dkTw
         PtxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kbUHkRBLTwwXhvzBntXAnVcJyoLhDTYuGmNj3xRNm2s=;
        b=EvuUBZ2+HyHMw9Tjp3CvYOGjhdzuvSTyULpBv2OQ4i0omslpJ3BirvmAMp4K1iRuny
         0C0ZMuJ4sp0IZz8c3mdKNECnKwj0dp4rLNIuMYHnzAD4Yu5KKh9Oyp7lfMlnAMVc/fNP
         qPSgHFIMOIYDblsXaS0rFGjXVXvD2/5sIWSCVcG/GHMbKy47hzdbEEgD7yqYoNOJMwq+
         xMZxvrGNpt8RkPzfQIsB0XQl/bg+mM5IZXHI67yLafabba4HDDf3Gx2HQl2yRnMpPVWw
         rM9JvlwqX00Kb0MCQJzbPL0Q00euhvXcA5It45giSvtN6mks48rxQx4yBL0t+WL3+N3p
         uFAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kbUHkRBLTwwXhvzBntXAnVcJyoLhDTYuGmNj3xRNm2s=;
        b=DGLOB+odyeWyqJTL1aEmyKO5UbZcp+w/SmDVS7sm54V2XhZ2FtzL+t85xxP2D2N4Mf
         iy3GXJ0jM5vrOaat3Rc/2eZHdr2ZjmlZQgnkwRIEOxi/doIJgVqBqAiatrcQl5cTSn9s
         y3N3k+6fUw+cFlLnYElOcj9G1o8WEQCcSayVmTETPloqm/3akD25coXvhYuRbfQ+Fby7
         oh3R7fX+kl5JnzoA2BMf/LzCbK/v2jcs9/rRvnDxOhzmzJ6L/c0XRzpQtY4BtEUDSn+M
         tLf6KpPjGc56Qr//DCOTztzlJQloDhiQO5GS24AYV1u18uDqF5x1Ed8pRyGnl3wF8vAW
         f2TQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oRGX1JyzEDM8AU2Jqwcupl7dxhgx+dvDhzsdzrDw3FSiWoPpA
	myrjj0O3EYLgD3L3hc2+IBQ=
X-Google-Smtp-Source: ABdhPJyumsC1pdNSOpdXh6INTKN3m7XAE6yptcVj334p2BQQfEPd6hs0RjC909KbIQvmPRwIV2NVaA==
X-Received: by 2002:a37:990:: with SMTP id 138mr4226458qkj.53.1599727857346;
        Thu, 10 Sep 2020 01:50:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:585:: with SMTP id 127ls2676469qkf.8.gmail; Thu, 10 Sep
 2020 01:50:57 -0700 (PDT)
X-Received: by 2002:a37:638d:: with SMTP id x135mr6988235qkb.60.1599727856938;
        Thu, 10 Sep 2020 01:50:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599727856; cv=none;
        d=google.com; s=arc-20160816;
        b=XU2he8fCSZdRor/6HoYWX7aHZmdbb+JOOqmkNtRUS1veN7AYtXnDW8i0y2UbwPxeI7
         dkqPSXd+7IU8ZmTDOSMkosuWz3V2nQIWEFgV7g/GpWhWYhjSlcx4+qNZeOLBtFVCuJJV
         DASrH8NzlgyE6zyZwV+Yj/PE+pmBi+6OJmrYlpUNSpm3hZGsTqCDQVwSNhpUl8t95hlR
         6nswj/rK8hBWTtQ/A8SpuqgDo27v27HRIvnosZ+RYpFzAoKSFnMru5Hpya7Jc5gPqniJ
         HDNkCTsBDj8YxqpJrW225g7sxZRwtYs8blFXrppehIGaL8MnSS8sikN3qgt97x/2/oJa
         8HIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=c5I6VuLu/57NiapbZ6tg3DxVwQnvJ6FKWNrSs1pRoC8=;
        b=Yd6RGujD3rkS7Frb1myiAOOXlnR80BcVpPK7h36R4IFuRzHk9wSTq040qdwz7BM4Qu
         llLLBqsdzFZs5RHFfiS9bZtM0mRP05HgTOsSKClBf2U/mO8sXnvzhY26RwjsKOktssk3
         GD5KMDCxDAOzlx+mBRSD5ynNlon4lmeGQD1ATGDnrKvDAenhcmxA6t0PVex9sTQyWOi2
         tN5m36BQtktoBdxzBVEa3zI21tKrpOMLu/7eH3DQKqf1aj7vJE4IlsNPWtueJCL9n0Jr
         frW7EwTcLyxeMt705WIL91BY8wygwOpmL6ggWtk3bUQcFlYn97EgFDTptT9E7urTRUVS
         EOgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k6si351407qkg.1.2020.09.10.01.50.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 01:50:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] KSHAKER: scheduling/execution timing perturbations
Date: Thu, 10 Sep 2020 08:50:55 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-209219-199747-nHmC9GLDRk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209219-199747@https.bugzilla.kernel.org/>
References: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

--- Comment #1 from Marco Elver (elver@google.com) ---
We had discussed a potential implementation, specifically "NMI injection" as
the means to inject such delays. It's summarized here:
https://github.com/google/syzkaller/issues/1891

Having an interface from userspace to inject NMIs that simply add a delay would
enable e.g. syzkaller to generate programs that include such injected delays.

There may be alternative designs as you propose as well, but using NMIs gives
us arbitrary delay-injection points.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747-nHmC9GLDRk%40https.bugzilla.kernel.org/.
