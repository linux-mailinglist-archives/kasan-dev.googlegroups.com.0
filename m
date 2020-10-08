Return-Path: <kasan-dev+bncBC24VNFHTMIBBUXN7X5QKGQEORENEZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 54401287D21
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Oct 2020 22:30:12 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id d193sf4663804pga.23
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 13:30:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602189011; cv=pass;
        d=google.com; s=arc-20160816;
        b=XyD8ppVTkspX5i4X8l7EvBhFNpaaFWr5Iq1oj8bi36x4sWNsl8J6/vpAADqOaCIV33
         SQS7eCWaKo78YlcrQUPrpOj8sR6KUJFuRAu9MumR1rMsAXSgaB1Q86kI2UgPrzsUEQOp
         qAhvPIAVP8wQD6jnRk4/QGufrHimPVuhIhLWzejH3uCxLupEFZiMDxIA00tu7/zq466c
         AqTMGMVTzzA69EMvSQEzGY6dRIwKS84XueflwokqlNi79/1PcF79uV86+ok2XzNKUkI4
         T74dM/3ZIV/trdVYpDnPi+3WIGS8hCgScCYHYHM+2npPPG3NKd4p7+bG1XDiiBFagRwz
         7i7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=NR0egKFoEVccMFC5hpwf0f/LUKMJVdTMvCHgrfAATIE=;
        b=ymKU2c/N4/I6Ls+K4GMM5BV6ysJthOfaQjALj0zzqYVvEnVWvkazRX6qvyyEIJ0ruW
         x7Gmeo/VaWLUJ2tG/qdZUXGJ2JHvxoJt4XwxLb9ngZPoyBmQZsj3gEG4uNsd+3uWE190
         bfhjHtHcCed9WMUOqpSi2L7AJpWPRRpa/348136xpWNo0lPsrGCjjToyneXsGK0HoHkL
         cXxc0cznwOY5Uryrh+1Y8yZOBOmfpa28L4f9Q2QrGD/Cls3rziC/mg6myWEfFOncoU8j
         PiSmxNMk5gSbpA8vL/sX/FRZPp027bkGcd+R/alys2eeKepv6kbCwl9jZn1MKHxSreDy
         gHDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NR0egKFoEVccMFC5hpwf0f/LUKMJVdTMvCHgrfAATIE=;
        b=r64XLWmWfS35jZEylrgIiXjI7aiZHMVWu0/RKRcJvNi/n4h/KhWpsGs6KmijIORxsj
         gRreCgl5JgIiZO3cajJL0Ycmpn3Ye53v2m3u9qLpinkF6WbStCZMxq6I+DInpWCog28q
         LB8evA1r8PTasWuNpXRK7ZjRbUcNMXKVYH9ZjYJ3sLmSoBV8Fws2P2wfqlJnQWj4wCEs
         xIXy6R9+ifrsLvb7U3noYJSjxJv/EuzgQJOHZmuAMm8YYNykCuvWKQZJG4nkVf0C1Wm/
         Iu/cdkhhYW1oTdKevErGf+mJMpYPwK2xIKStf82ptt/Vrn60cpERoqJp0xWUXJSdm77W
         ahzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NR0egKFoEVccMFC5hpwf0f/LUKMJVdTMvCHgrfAATIE=;
        b=TJ9//mPv38QngzF/kA1QvAyu1puKqD/jaOAfa2dNMUT/S+bYC/kXkLzGtRKQPOHbiG
         SGhC6W8uxFrKMM7SDjcCbnmxl1wxOWjquZDN6vLFd7ppfanVmKSA4Fg8FaveCTpMxx2y
         gF6AQxCpKLgEq8zHt+rwbiaShsSq1mDFlATdXuV+C0Sul65B0+akmPXopsPBAwIe30nS
         oFR1MxUDKnr8TtBMKTzqCcGUiTHIuxUBMAuU2jvBkMfBaZZ8x0XVVqY5JeIDgmKmz9/T
         OGieMefRytzY+UOPtA/NiQD3k2WA4h4udIuk0VjrBTL85wf+nwNtEcN0jp7cofzA0lco
         XCLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qrmXRLwhEQVZhIQpwXhXoyiSfA7K9Z6T3jbeRZqp+lXQnRyl7
	pzq9spmkCYgx3yC6V/L6GhY=
X-Google-Smtp-Source: ABdhPJxvehBWySwT+zVnvT9A/I5I1lWKQDK93laYObZSTVy6p75q3KWgIpo69/pxda9uFyn3WlwlEA==
X-Received: by 2002:a17:902:7683:b029:d3:b4d2:2c57 with SMTP id m3-20020a1709027683b02900d3b4d22c57mr9140287pll.46.1602189010799;
        Thu, 08 Oct 2020 13:30:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8b8a:: with SMTP id ay10ls3251810plb.6.gmail; Thu,
 08 Oct 2020 13:30:10 -0700 (PDT)
X-Received: by 2002:a17:90a:174e:: with SMTP id 14mr692586pjm.124.1602189010306;
        Thu, 08 Oct 2020 13:30:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602189010; cv=none;
        d=google.com; s=arc-20160816;
        b=p7ERsIOAg3pcUYdZfpx9RThJNu5aB0Uc66KZns1e+ac9FFLX233+0+88akBIbl7cgH
         +rENRAIGw2+LbtTOLPG3qd3m/voHJ3jP4IdQTGL2BA+tiJNNF3PgnpigTMSA0w+QwIcy
         21LWlSpwadcya2W8QH0jRu5+Ee6BbTmCUebJmzyd6U2G4bJpngZPagWZSGiuPqeVX/1Z
         hiQvNbdr86xkxUYkbI5jPCC08TzrT2bOu0Ks/vkrNuje7ylwvJ4ROUPRztsCagkQraj3
         CAlujRCDzu5AHoCT/xpkp42ByEIhf1656dYrkSYpHAD+wSP5TbV18U2DGx4tXloy55m+
         TG0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=63SBHwDiMaRXZaYlbFQqKeNItO1StGyORRQorUqG0Cw=;
        b=bdk+5n4puP+BJwXUhfZiqGEi0bIDaR79TFAjDNH5LxFDLRQXblcjQL1yf4wYH78eoq
         YBvny4su0oyskLzprPYAkMLlKbYVB00/smVbFl+xysqtgziUfK8fyfB3pejA89u0ROXA
         hw7GbXt71SkQgiADnNdp/XN2ooMlEEew/KwVmmrVUz5CbFnKmmzTQJLyS++4bU81smjw
         4freuLSGyk76SOEEB918rBkwnHULJ2GUcOpy7pvmcmO93WWmseXL6OP1TeS1RTfqDWXl
         0mHJAjiFdEJFwMAfYrsT2KP5xQIW9EoPMngqDOhT/S+ocA1tj5mwbiQ45cHtZQyJwGoi
         hgkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id lx5si341209pjb.2.2020.10.08.13.30.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Oct 2020 13:30:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206267] KASAN: missed checks in copy_to/from_user
Date: Thu, 08 Oct 2020 20:30:09 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206267-199747-njaC4YhuqD@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206267-199747@https.bugzilla.kernel.org/>
References: <bug-206267-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206267

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Normally, yes. But there is a hack that allows copy_to/from_user to work with
kernel memory instead, see this set_fs(KERNEL_DS):
https://elixir.bootlin.com/linux/v5.9-rc8/source/fs/splice.c#L353
That's used when kernel code tried to reuse functionality that's normally
intended to work with user memory to work with kernel memory.

Also see how KMSAN handles this:
https://github.com/google/kmsan/blob/master/mm/kmsan/kmsan_hooks.c#L251-L262

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206267-199747-njaC4YhuqD%40https.bugzilla.kernel.org/.
