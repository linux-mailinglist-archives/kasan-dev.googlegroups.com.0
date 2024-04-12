Return-Path: <kasan-dev+bncBAABB4MU4WYAMGQE42DBJSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AC1A8A3184
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Apr 2024 16:51:30 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-60a4ee41269sf17390257b3.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Apr 2024 07:51:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712933489; cv=pass;
        d=google.com; s=arc-20160816;
        b=lBH8Qb1sf1gT8OS3Dce2RV82R31aY97igE+0VjZYr8SF1iDMPEyqDSWGaoV/92UBwc
         5TpKncIML4iFAndVeGxkZ+VnMIZ7l/zvGE5vmyQ2HqwM7pzuow8IZn3vyp+0nA4OIfHq
         6GdyPddghWDEFHJLAc9muZjZzHL8Fy/vePJc1cGRLLUo9GGwK5/NX2UTbAh6jnxtUB3R
         O+jpKx53hvBM+yGxAdytIV6148GZQdlzCL9VANW+a2P0GG1Jwu8XwNBxk5oF49SZNDai
         Ho0VY2mGgPT2cBXy67d6SQoImsx9OmsWdqGVthJnb3GXqKXD0yd9eWkfYNsqaFhb/IWA
         oXVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Y4S7xDjLZVjAkPsidnH82e38o1YPOM8uuit8ljlODz0=;
        fh=lJssrZfUYraW6tCOB97al8TT8LSk5bwvNAUoPYmzm4M=;
        b=Fh9DxzMPDlaqTmoT5If8B96gEkjDM/BZCL8ZmD8n5XyQt5rwtW9uG0JPX3Pg+lxeOO
         W/iQhHJYLabwnUfAVTJm7ei6H17/OoO/yMAkr66D+fSox8nqNSWzPPsMi3l96Ne61nxB
         3fSzK2/VIfD22Cd7tssJlQbY1rhziWPKmQm+X8KNQBJrLP5zeiH7TROXWo448mtl8DZX
         YXeZJBHSwLG4CvzpLe4cK9ouwgnTJ34Bk8uYX3rr4oOGw7yMM0lfR1Nh9B6Ij4AWkqZn
         dZYiJlnNS4omtIVQWh5hxaMJWTsPBm76JHA0OfYFThKm5v3bS2B/vrsyGHBI02lKxDFY
         k1uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="peLwZh/H";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712933489; x=1713538289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y4S7xDjLZVjAkPsidnH82e38o1YPOM8uuit8ljlODz0=;
        b=KA3tjePuoCfrY78DX6WNgHuw04Yy0Wwwf3po+BorcjxTS8C/v4fkYE31sPh9riCBIj
         pTA5P2PRrQcytXhzJfu2sM4KsD9yy8GgSzirMb8CxcLuihcOODmC4eE9KDdZiapq+aKo
         VxkFrdxGUplfoKh8Z8wTxRW3Vv2yr+x+gnFI1z3BJogOYi+9q7QrU1ERJFUvFX2VkNw2
         00ugj4hFJRx2nLNcPa79l0VDRHJrnBK1IMFxVWtnNN0JS/a0S+lIHohBlQMCJjyEvI/f
         O6fO6NTOeI+eRBoGeFd5gjyq6jq0rDzXw67sb7SF3W83O+ZYEVEx1ZM7K9rOKOb16bLb
         dZxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712933489; x=1713538289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y4S7xDjLZVjAkPsidnH82e38o1YPOM8uuit8ljlODz0=;
        b=FHXmfJy7FhsR5ZcbQQTPOOwhSF0SLtrO6aSGTNL0H7Vd/nm/ivWMP4poC1XvyVuFYq
         8BioQU7Tfha+QC+YJ6QUPdkY9JleRoOvCKwNj90+r5sPuw8G0T8WGXGW7Qex+0brBsEC
         dJCUPB7nV7NVp6GXrTkYj6SS6qWijNxTLCy+usrFb1rat/33RLepcYicmj/wxY6SByWR
         ckgw3ERAV1CkHdZpvugs42OUTOCN1K9zt6dhCl0VBj4honV1AVn5glIUk0EaBDAiK67D
         sjHTGG8TaNedRgTJzTBN59kZKPecIdiVSB8ypxHpHpJh1tWmW+LGB2bC3aNxtjwU1Rui
         RJ8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmAAOb56ywco3gvD5F1mrKHFyQBMIooiNipu3gbW/KJNnUTacE3JD5+/SQbKWbxz8bDulW8kInTnbyBy6GGf2u1nuHheJI9w==
X-Gm-Message-State: AOJu0Yy50ze5P2g5E7tflcMmyNAsg79LP1kSm9pNzUklEsNCp301UFeR
	OX9YvEwOkvKc/6Vq2soROKMIHvJiVmyF9pMQTjXZAhu373lTHZSL
X-Google-Smtp-Source: AGHT+IFeL1GIorRHkkcNbB1sBgfk4xPD8lwomQwYjRYL417qPGtBgjkNBszOzaLrWoqf6L+ZYYcjZg==
X-Received: by 2002:a81:ae45:0:b0:618:90c6:bcc1 with SMTP id g5-20020a81ae45000000b0061890c6bcc1mr273390ywk.37.1712933489114;
        Fri, 12 Apr 2024 07:51:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:f28:b0:69b:2455:2edf with SMTP id
 iw8-20020a0562140f2800b0069b24552edfls1380809qvb.0.-pod-prod-07-us; Fri, 12
 Apr 2024 07:51:28 -0700 (PDT)
X-Received: by 2002:a05:6102:3583:b0:47a:4751:50fc with SMTP id h3-20020a056102358300b0047a475150fcmr2202861vsu.10.1712933488142;
        Fri, 12 Apr 2024 07:51:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712933488; cv=none;
        d=google.com; s=arc-20160816;
        b=pQh5bAfx8w23YExblTaJ2gDFrCzi1MUHd4jmfIHaCdlRXjcvHUPUw8KW6kWAy8Jd4T
         ft2dRETc+WQ6O6wR+Ann+i8qZK5QA9Cc7Ldgb5SjR90PsoT2Huxo7Ggmd9X6qnTpC6w7
         bs4V+9ajAnrfoJZBPh/w/zlftef4vzI1qwdZdZg3ItG6SlAzITYkH/ry2GvVVPT0LDa0
         7slqrCd0HBjW5YFYl3RZzC5owgWkvUU6QnYJ1hYaMCyFPB2kYu/CNVkurhmB5iSyJnT+
         ujCiMLgZKnI5ZI4ykYxnjbs6R53++DgUOhaGRQkPaqh26c9N5bzXGqLyaFD4UZ8wAXIx
         vmVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=DNkwvAB1U6lA1XTaX7Xm2JHrEndKwcjTJn5dNfCEXEo=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=o0hHaIGCUvxGHe51GGPh5alqVbTfIfAgts7caBlKmIaPGHJ5PuWa2dzbbqfHgw2qoR
         3vJefBZT3EnyJkrMm8DVPPuLJRC+nO6l6h80ulzwEQMRe/uswjALMxZCfFaPyDTu4mhA
         cL5irvrlVTZkmp+uwVeZ0cypfFh4ntHhAc7YCwlhaOLGfy3lmF6Z9NI0uOZWaQm0HVQB
         wCdgG367K8MeWr1XUqtfK62HoeK3tEK7idJbDmex0J7yfxO628YNDQaAoqb+/vfVNrj+
         dLwMz0TbooqsgsylCy1ZFENtbrskgTh1gTz3Uw7movUpJ5uUelptEK/W7qHWnWYXa4xv
         u8bw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="peLwZh/H";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id do12-20020a056130138c00b007e808ff2abasi262737uab.1.2024.04.12.07.51.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Apr 2024 07:51:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 49455CE3961
	for <kasan-dev@googlegroups.com>; Fri, 12 Apr 2024 14:51:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 84D34C113CC
	for <kasan-dev@googlegroups.com>; Fri, 12 Apr 2024 14:51:24 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7A757C433E3; Fri, 12 Apr 2024 14:51:24 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218317] KASAN: tests for RCU caches and caches with
 constructors
Date: Fri, 12 Apr 2024 14:51:24 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218317-199747-VWmptpMmzG@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218317-199747@https.bugzilla.kernel.org/>
References: <bug-218317-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="peLwZh/H";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218317

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
We also need to detect and test double-frees for objects from RCU caches.

As of right now, poison_slab_object() checks for a double-free only after
bailing out on the RCU check, so a test would fail. There might be reason for
this behavior, but this requires investigation. If detecting double-frees is
infeasible for some reason, we need to document this in the code.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218317-199747-VWmptpMmzG%40https.bugzilla.kernel.org/.
