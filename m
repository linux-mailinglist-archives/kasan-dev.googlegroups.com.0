Return-Path: <kasan-dev+bncBAABB35J66OQMGQEIZTDXFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FF36664DE0
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 22:13:22 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id ay40-20020a05622a22a800b003a978b3019csf6166011qtb.16
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 13:13:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673385201; cv=pass;
        d=google.com; s=arc-20160816;
        b=xgff3MMYejxJSxXfaMkDCNXGY1VVTGhp/iE2lStOj61iukYx3Afp4iF3vKWFqTEMtm
         8fCPxHhrglv0uciuB+9lupvAdOQ60mzGaT5gvaqkyQvpB4fsg9RvV83SQt8cKXeuRfdp
         Rl0rcPWBnAyYPUAoo4mDtfw9Ob40SV0qOAMTWzxj3TUQVTJYkLlTldwvBb4ggEK04ZIA
         yUCjCLzUeq/O66nl4NQGmkBnnKnjSuWJBRPOzIavKF1b1Ev433WTK+iswXNrzpCekb3B
         XFuL63grvp0IYIfuehv6FdyZyxEb43/EI05R2TSNKsXNffV9cj6HJV81bkPsVwUs2tsD
         lvwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=yZ4gGCy4Ug86I6RIYPvqg7cgXhQQdfzVcKM+tHduOjc=;
        b=ePZtHJvE+MWgmAI38+cZVfEexFSqKkltj5KY8PE2QXP928SI9b2aJRJcbO80EvlVCK
         TuD50QMin/yFFLWzEnNaTJA1K+5yCF0uPsaTs74SLsvmlc/FLK4yUGOd3gcURCdiNHc8
         +ZYQfYF/lVNGiZrtaHrIMFiygU53K1tW4WQzfWebdsnixGFQTo6R0NgUgoD4DhtOEoWD
         Bw6bTaSTl0bNPsoKaPCv0HGK3jjONGtfvkWcmaKNA7JYIP6oLObt8vXJqFO04i9t5pJp
         f1/g9qiHm/MiJjWWceqihn2JH0UI+v4+5feqayfe0OUfstd8IFI+TlOUEqWvKPcTQmGO
         xUcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=r1PO5FMn;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yZ4gGCy4Ug86I6RIYPvqg7cgXhQQdfzVcKM+tHduOjc=;
        b=Gfbh3F0AuDYreZuhsem5I2QKjUHQkPn1so3r6aFnnQ+Sz3kDkHRWjj0z+TglvqKF/K
         Tr9SO64otPn+pfbVv21WHaQ89czXPmwgU+N82+iROkkT1QGWhwcm+ckF8cDWrxQlK9oT
         rkCplwuij86CvW0ETQ0wvbgCNC42JdlhE4DU52ZyvnBpPJyy4FLQU7blW1eYBBFw5SLf
         FxNivC7yi9QtPgCVls3RBF7ZWW3Q0W/IQb1S5aFRZixryKKSm3/8wKKyU20jY5DVuWWo
         dhxsJefTrbXrLAfjK4tEWH8SyFqyuwTCSa7QXp89/RvWATCn2I850vic1ZAK8Tb16d3B
         Vg2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yZ4gGCy4Ug86I6RIYPvqg7cgXhQQdfzVcKM+tHduOjc=;
        b=fhduJ77/iFyY92NplT9o7cUu8g/4BeEDFj2twcQuf+LXZ8PQzQm6ZqR0LlqRyPl1ib
         z08Jiz3gpmIhAug/a+RFSUwzfNuKSL/Q3JbT/xl3F/Kf92s677p38bVTz1MrA5B/Tcv7
         9oij7u2/7UV/F+2IVrb3Q7eVSZNBhKslMiWmY3T6SGvbn/6rTwBe4rtUvDaRbkV5euaC
         SqKglZnPUqUUJSfbnwVtQdlMjYacgNWstUOSE78ob53jeEk2/TwwpWVf21kC0gbgpI6N
         kK62UUNqiX8KlVH4pc0CW0sQx9gx6k1TUmY4BP+BV+Epv2bTKSFCk5duvFe/OHNzumHl
         06mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq4b3LiSAV7tmsjTAwc7eBax2guX21wf0gJRwnxgRezBcvUx9Sz
	eapOIRfy0jGgWr4D4GcmhIA=
X-Google-Smtp-Source: AMrXdXvbXbfsaykjVxOlI/+joMK0uma0x7l4fhqVhQFnKHfyFSDbTsgAHXUG/pxCnrXewZBtVxpuYw==
X-Received: by 2002:a05:622a:17c9:b0:3ad:7ac:57f0 with SMTP id u9-20020a05622a17c900b003ad07ac57f0mr705772qtk.246.1673385200034;
        Tue, 10 Jan 2023 13:13:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:5a1b:b0:3a8:7fb:e9f1 with SMTP id
 fy27-20020a05622a5a1b00b003a807fbe9f1ls7981010qtb.3.-pod-prod-gmail; Tue, 10
 Jan 2023 13:13:19 -0800 (PST)
X-Received: by 2002:a05:622a:206:b0:3a7:eb36:5cb3 with SMTP id b6-20020a05622a020600b003a7eb365cb3mr126172034qtx.41.1673385199632;
        Tue, 10 Jan 2023 13:13:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673385199; cv=none;
        d=google.com; s=arc-20160816;
        b=drUy3xBgJ9ZwXSuTTkg0nk35rSkd0MXqj1pE5eg1FyEMzfX97qiEGYx2srEdMmOEmG
         uBmwZ9nJ7HLgOwM4nF38T20qvzLoR46cbo+ThRAhpZQwOiYosmFPgycTlmdy9lUGpyol
         m6Cu5Icj07JBpLcjbjotq9mpkVO8McQC+D6Z4jkY6qezt+B3hFQUW/+ZEsY9V3jbnSIG
         eqh8sXkDkes2zoKpByvoK2J+X5C95tNIrnS0+40pj0QMY+EcRvmD12vLEEmujJpXgUp5
         9sXyxNZj5jQDGjBuaGthTiI4agU1A6+BH3OuzKQkkb3jh4PJZv2aD5bE2nA2Djla0xS+
         gUFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=W64R218qyNu9Vt80Ote7Bi6KGM9Sj6WGLQkyBtGzAz8=;
        b=nya6+J4Nr9gPuF4Ti1ZrE+O0E9UOYtMtaH+voBeDpS4HPCzqNWiBRbaKvfOcLig/Y5
         dSxskWA6rAVH41NQYlfYXcyPmxI4lnk/udqunnJ8aI25XmrMqTQ3KX/cIel4febJsK1i
         AcVg0cf9RYKSEN1JLUAa15w0VBs90aK8TB+ZBgI2MrXYS/f2KQBiO1RmCU56yhz82RHV
         v8xsiGVF7Rz/Pd2/0IeWhTxL6oUOO7nZuWAmvOpMbWVW0ugoY/3rXCmp+zvL/uZ0zTb8
         la3b8RJ0nbMilM3zZrFaUv6z7VabzdWc4tF56b2dVxL18q037R9wfj3M+IPrqAPteHmu
         7deQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=r1PO5FMn;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d25-20020ac84e39000000b003a80e605d25si886742qtw.4.2023.01.10.13.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Jan 2023 13:13:19 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id CF00ECE182E
	for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 21:13:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 139BAC433EF
	for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 21:13:15 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id F29D5C43143; Tue, 10 Jan 2023 21:13:14 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216905] Kernel won't compile with KASAN
Date: Tue, 10 Jan 2023 21:13:14 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: nanook@eskimo.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216905-199747-A9fCuu3wKp@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216905-199747@https.bugzilla.kernel.org/>
References: <bug-216905-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=r1PO5FMn;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216905

--- Comment #7 from Robert Dinse (nanook@eskimo.com) ---
I used xconfig and used control-F and then searched on the same term, didn't
find.  But moot at this point.  Kernel is built and installed on one machine,
will install on the other two NFS servers this friday, they have more mission
critical apps so can not boot them during the business week.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216905-199747-A9fCuu3wKp%40https.bugzilla.kernel.org/.
