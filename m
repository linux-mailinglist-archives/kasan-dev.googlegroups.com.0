Return-Path: <kasan-dev+bncBC24VNFHTMIBBYU4RL2QKGQEPTY34HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B4691B6E94
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:59:47 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id x7sf9846518qtv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 23:59:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587711586; cv=pass;
        d=google.com; s=arc-20160816;
        b=J5JhJYqphsCA1o55SrG8JpBuKBtWgR+0xIVlX6Uh5Q/V8an9mfkdAXGvKbZXzXn4dk
         ZQ54vadNDNzhqaq44DgwV+Z4OE6rCFj4Laz6h2GiLn30UMppGGkowOfMTrLb99/DcpZJ
         vPDNpUMvMDkX70nEPpWTkaivMg7+6UGeSLY0FxdBhqUrbkgyIYHas+Ydcu59cKQTj6J/
         wGfqunpBVcAm8oRGVNC/+WW/oPsdvaiaYsctrM57sFpUsVt9TiWOQgPLYM1srZqqiyrD
         /MGih/xxOGY7uFrgjvXEBIWFX4FsJghpp5LkzggK1FGMcR7ODmhEmCiLZAE5jwicBnVV
         gonw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=4PaDpxh6x/eg1AO3CVWTNlSpffGmCR/0AX5QE1Vjxfw=;
        b=B1ojZCdh18dmJPVGSGwhEQYCHG7GExZMBHdQRf57fwN0ZFllci7mvKxh11njux6hKW
         I4TSoUHB+9PvxRUv4ysoTfsQGy39qJW3Yxgn4RiNs8VUrRtCXOH0+Yd2e8d/XpUjLKCR
         6lWtdJzwv16UkFZvgrlZvGmR7NiMahuOnC71KxRSW0aMenS6WooQKt0xy5h2sGdWJRqu
         +edEF9Fq3z9kB1ojtWe4bUMqLIxDYlIGW3/Qu08KngQvwjAgtkDOUttZEO8NwUTU6hGc
         4bsbsibvcroGmCMF/UFfzi0ExG9oNrrfENUUB8D86LfZAjc6zwdLOaxBXpVN8JrG4D+j
         8aCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4PaDpxh6x/eg1AO3CVWTNlSpffGmCR/0AX5QE1Vjxfw=;
        b=d4ITYxzFqrHbZl5Dplk/3rzHyydVT5leOhzyjq6cT8VN4QtSeytne1Zldlr8WV0v8D
         KZUh859mSP0L/9mkesz4PZOCw7B0bSR63y1N5bJcW9ZJJlqnQZb+Gg2YO57CSeZXQQ5x
         +MscpugfqQEvVD3DJFbvlQpZCQFiURK7nX8b4N+d7NTKY5Oh67bRpBDdWIeJP4whqDtS
         mjC2Q9KMvyeddCdCs07Vec9wDc91SbhXv9Zf0Vs+6WyHFL9s/f/gVKsUOgJ2LrHphH77
         mSCVGhQUSaXR+Wlrvt1NgXNn3/0my8Ax0DRZILAbw3KgHGbno5/7ruxv5Li6l4UbnipF
         hCiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4PaDpxh6x/eg1AO3CVWTNlSpffGmCR/0AX5QE1Vjxfw=;
        b=owcBdsEbusnfdEmLibgK4XFLlyccUd/e/EKvfumCFZ6wWspkYPEtE8sXnXb7UwN6XJ
         LcUKBi65zVF2J7Or2MWasu+z6f8joE9Q6Z9um3e/25abdv+JMBJhxIeZwDqkSLc+miYP
         BaVNk1G5hfeS3CxeTlNpr5y6FtNmJxMX3/33GntOLxXj+Pz1sE0Mm30lBxIFgSdFL/AF
         9GfVv9ZQDLk6AKq1wKXqKdDUHslSHATYAEuJEggbtOjglARMpT1sCbCEkQb0wO67m94/
         ydYit9AsbYfy+oR8qKO1uwZve0b9O5aQBBNBqjyOq3qR6cEDAGTRsn5Yt9TNT/wjz0ZU
         hRTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZTYPQRxVFSQCwsEXmpKCNKNk+wQ8Rl2q1fSzDaBsZJABaoikpB
	kwdED/IAX09Dpx0JTldR+g8=
X-Google-Smtp-Source: APiQypJXFBA18lst9Jr3Esqzh+RXL0rftSFc8yi0tUXJKYMMzNw4fff1vf9iaDem3PTKvlkHH1V26Q==
X-Received: by 2002:a0c:fa81:: with SMTP id o1mr7949811qvn.52.1587711586176;
        Thu, 23 Apr 2020 23:59:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4182:: with SMTP id e2ls258703qvp.8.gmail; Thu, 23 Apr
 2020 23:59:45 -0700 (PDT)
X-Received: by 2002:a0c:b9a5:: with SMTP id v37mr7364080qvf.154.1587711585827;
        Thu, 23 Apr 2020 23:59:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587711585; cv=none;
        d=google.com; s=arc-20160816;
        b=YCafHLvEMCkmOVVLTt/wq6EXBtPDGcqBnVEL5EIO8vFU6tWhItd/Dq0ZVBdoDeKp5G
         YL6iDthd/XOSZR02eCnTcEihWXy1wA5znme6DzAdnIBVgfO5NhledB+5idDWj/48IFlO
         52gCW7k9KUb4oFSpaSDnHq8n9VAfuCReBt6CUFY1t3OnlPsahnq1O/2mUlT7Bx4YNcwQ
         bKp0EkaFqjW4NBactZtRZ7OLquIvphNb/ab/x1af+Az33KWnP3COKH9O2C3J+ywNAIa+
         XJjdLlRjxY19HMHlEOYN6psIIIA5Fr4Nq0d4JCuB6tAF6WBWXTBT/IcoLVpFpT3+xYTP
         fbfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=/C3ZfYNC3tRGcddSrJ/Hh60Tk9O6wPPO0GqdyrN1mK0=;
        b=ogH4NtposnKuIjAT4bhBFQSOiEd00HxMuKUA6udgzFsq0BdUwNDZDuVVvCzv6mkBCY
         u39S85wW2uGttpDQIUGPjJELbFcooK3/S2IuXhrpd8Fad5tG/v53ZniHo6ewOrMBv4oq
         kWXwujubvrxKpeV9uI1kCvJ+VQtYdMVH0Bvyw9w9EeQaiow9P6xSMwywYdDVOtXkBEEU
         erq2ghtMz6qA1GiGu7XJptyRi5bj5HvUUNVkBBXvvAOObFclOrlDFekX9+rTHLR5DEAo
         KJYFpI7ySpkPDXVrLUW4cRZye4hTSgGqFPy4DWX/hGvyjfzZCzOwA8xMNARxjRD8uSvX
         0SGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=I3/H=6I=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d11si358444qki.7.2020.04.23.23.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Apr 2020 23:59:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=i3/h=6i=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Fri, 24 Apr 2020 06:59:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-198437-199747-y8A189nYMS@https.bugzilla.kernel.org/>
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

Walter Wu (walter-zh.wu@mediatek.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |walter-zh.wu@mediatek.com

--- Comment #1 from Walter Wu (walter-zh.wu@mediatek.com) ---
Hi Dmitry,

Interesting.
It looks like to record free stack which are freed with RCU and print them in
report?

Walter

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-y8A189nYMS%40https.bugzilla.kernel.org/.
