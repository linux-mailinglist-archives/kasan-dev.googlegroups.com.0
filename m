Return-Path: <kasan-dev+bncBAABBO5K3GYAMGQEYHRWZIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 038CD89EE1D
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 11:00:45 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-6ed663aa4a7sf1509810b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 02:00:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712739643; cv=pass;
        d=google.com; s=arc-20160816;
        b=yDLSdyRqipJpDHyPlc343mTqeL4wScZ84W/nFV/shPs6J73MLzeBDneOwxapWzoS6o
         kqW1TAFpQYyXP+HDZ4oTXVtR8r+W0S21UGQlHmsLEibn4YhfuD0uCTVZUQLkc9yBHKtI
         GFt5JozUvGsQVMsc1iJjbrOmMlyB3pjh54/C/ou9G8NAZeh8cS68aJWVZS6Jh9JHoaQ+
         S3cfFik0KUsy6USlOQPMRDPc5hgKA5+hl0B/7P79aBd4OJfHYw/Mmbtw98AkxAAx86A/
         9Zh3ESFzYjx6DLsaLgprD2IxBrXvK3V1eWGSys4RHBuae+WeeeWcrOtEufbgxBNZId/W
         RvQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+A/6es2Gg+VG4l/C2679ADtpMPgn4459hrw4HzALPkk=;
        fh=a25MnozVHvYj9XBtFFY6dY52ctw4GGslpcnicjhQod0=;
        b=kJOHtXPhIiUtqzTVPLifEFKplIs3e5CB8jpIG4+ZtVigKTSGW3WYslyXE7ON+e32+4
         p+jCb2xgfK40NxrolELOiqk9XMMYi6L952wak16mr+DSbnDk9qTE91hu5lao2yxAsJn+
         YPzQyzLWFs+TqI+PZkz8IYdJeKW+yC7iIP//vS4ciEkZKdpm4C+QBHOX4phOzqZT0aGw
         c1h1m+vT8wEr/GCXoSJQ7sbxgUpOCUN41cLZDhRZQhPjQU5ML4UkqlIe+SWQWIm1sOth
         CBFVjqVtgoGMMa1I3xyd8Vt9JezbIYZodsFWrhPlNOfk2fBq6mfqlcb/K5yvT7c5yM4H
         tfwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RrN6poZn;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712739643; x=1713344443; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+A/6es2Gg+VG4l/C2679ADtpMPgn4459hrw4HzALPkk=;
        b=LKiTqpuLUbXjCVUX/9miVJSHUQxOwH3PRDh3nPl2fndOL3B/pZ//+OnquyrELOcSyO
         ETpEj3kTBxzhTxs6/QHNKiH9P/f1eCVYKCNZ4m6EZmDE1V+x09kFI9Fw0qju7S04wl7V
         bVvAebkseIP6nECjDvhYcz1asLf4DprK5dW9pNpjhmFRN3Ibo8470ICuNb2NIEiJwrkh
         I5sGtYbWxI8nFc2CRq3u99exbLjoICvG/d0suB3/TUyG/HaEI6aqSTDZJPhrq98Q++/S
         l+oZPHBogXqzR1V3O3wwZnv0vUsiLxpy0VnHlpTxUBiSm/PW5TqTyXKF/uHjJurIVifz
         Kj1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712739643; x=1713344443;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+A/6es2Gg+VG4l/C2679ADtpMPgn4459hrw4HzALPkk=;
        b=Qo40wLil88JuwnwjM4jEFaVojwqWZIEUNLL11jUfJhKvrNA6O+nWNcPH6BcFOF8AAb
         +6hkQlZe1k5kUNJzpIZA12OvhTde1fyRDzWyCQIH4kqgY9YPP6dz8pLFHHtWzNYqP1kC
         s4T+jt99SVJFffeTI3vLFfuF7hpJXj7YygyfuW7iR7k78pzslAyVwErPUwqQsHq7TJPE
         a4gdCCsE0Mh+L1BKiURE9kdfO6uBl78VhdXuncForUQT8936O0+bYKZH6CnQq+RdZPYX
         suNSInqnoNu78C7ss+KVkcb4+bSviiMvpjEyYgPJmaxSkr75tmuEuPTYiEXh1TUF/Hs6
         s9jA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUTGli1EpDejKsaMBh37xWogqZpbB1KoVf0TeHzCgjmoLopQZ/hzzwmJa+Eh3ATNYSDQn5bkiKCmcKdPq02zujMz8XKhGntFA==
X-Gm-Message-State: AOJu0YwqVschPYOTnTZZE+oMnAKQ1/YAY8o3BatfAEsB/Yngxz5nEYOv
	FxjgKBuZnD8dl6UujKSZSGGfoGE20dwW7ZBEp8q9tMNB3+pjr6s/
X-Google-Smtp-Source: AGHT+IGBZ+r4TzZUwLeYFXARP7VpO5/y4OHHT2nskTXk303hvzxaZ55Dc6r/iVtPLT1efmIb52YHiw==
X-Received: by 2002:a05:6a20:3943:b0:1a8:672a:3fb2 with SMTP id r3-20020a056a20394300b001a8672a3fb2mr2436020pzg.43.1712739643289;
        Wed, 10 Apr 2024 02:00:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3999:b0:6ea:952e:1bed with SMTP id
 fi25-20020a056a00399900b006ea952e1bedls4518903pfb.1.-pod-prod-04-us; Wed, 10
 Apr 2024 02:00:42 -0700 (PDT)
X-Received: by 2002:a05:6a20:43ab:b0:1a8:f807:a674 with SMTP id i43-20020a056a2043ab00b001a8f807a674mr2404643pzl.38.1712739642113;
        Wed, 10 Apr 2024 02:00:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712739642; cv=none;
        d=google.com; s=arc-20160816;
        b=juqIQ67fNFZ6C9ZzoiiPsyYVNtwnMB/2NEi+wJyeyMDVWtzpQncYv1V+rTASPq3zc4
         SoMJgkPpGuzEdoRwaQea36kkp4QDp5Gva/qxWKR/8y4sEkvC0O1LNAZbfisxafCmxRKM
         zDqV8twApjq7iZW8vRQI2W1/Tnk4RJP9wJehHNDMTGs+wvmO05lZPkWHBIM+0MHjcyGw
         hSFWJBovZNdkA5RJFeA6FyQxrjwA/WXnwuERfuwEGy+K9MIQWgsR+jTxMEVUi66ulzBc
         T1A6u7lj5bXlQVD9U1BJaKxO9WZbUAuYnuMhZVv8fZD0jAeJjD5lLUBAmmkVQ6mesZG+
         qLsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=DG1A0CA6cJyCFpw8c9fk987yLpxsteHYYlSos6bp0JY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ed5DG6h/UvJhem3rSBzDlK4HKwXqM1cf1DQrLf8wIo+17oOJ5jFkJLE+vBAUaZMAWC
         bXifAA+cyBQeR3+jghQdBuoqAtt+yaTTLwTds+i3ShZ4SWj3WuoJCuSFC2DFIXQ6q4bT
         fZbSPyZiaRDiGcVqHoaoIpsdrRLjnf3f/751Nfb7YniVy/VbVFcudLLuZEGlh4cVud9b
         54NMzuX48N6KWfcwjA3LsS1vRl7SiQTcVfLT8WnuIWsVUlgMyBeIfxoRX5njmd07IULo
         71BlbaFhtrEx1HPaElkfn0MdspKgw/g7r8DGgSBtvkUqzj5+QEh7TCqAcXJ8w2MiMcbt
         dRnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RrN6poZn;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id b7-20020a170902d88700b001e4f3d0aaf9si52483plz.7.2024.04.10.02.00.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Apr 2024 02:00:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 095F6CE0CDF
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 09:00:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 410BFC43399
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 09:00:38 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 36CE4C4332E; Wed, 10 Apr 2024 09:00:38 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214055] KASAN: add atomic tests
Date: Wed, 10 Apr 2024 09:00:37 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-214055-199747-3kI4FZgjo9@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214055-199747@https.bugzilla.kernel.org/>
References: <bug-214055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RrN6poZn;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=214055

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #5 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1] by Paul. Thank you!

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4e76c8cc3378a20923965e3345f40f6b8ae0bdba

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214055-199747-3kI4FZgjo9%40https.bugzilla.kernel.org/.
