Return-Path: <kasan-dev+bncBC24VNFHTMIBBDVRRP4AKGQEVNMQQ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id B8231215387
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 09:53:51 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d67sf23905121pfd.4
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 00:53:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594022030; cv=pass;
        d=google.com; s=arc-20160816;
        b=TwSApL4+Q82e5Pb4w7kK+Kj+wkl9JJpbovH8xbjiCC7JPROCU7d3AR0lsZaP7fJo0/
         0kTCq318oDNipQfCzxtbG77O3O4lAsxXYAIGTDB8NMTE8cOmKsl+pzDMueJiEt+cd6YQ
         ku/yCPYkpGmgoYTZ7UoD4vHf7AMoVx7iVvApSgdoiyfLWMZYN7BzlUivaPXO2aceAUVK
         g+IXYrIYpjaLANn+YOYPGEpgtLCtqD0fG9QhBFO5KsXruSDpIZuqFX64tg74/zk91/QZ
         CsuYvrSFSj71WRqE+Db5usu4oNtminek3nuWA4PzufhVfMyv8c046QKeTO3zhYOs5JiA
         lGeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=KTgSB+5l8ecPXgoa/l2+Mq+ApNAx531yXUoARJ1rDVQ=;
        b=Xk/vofArHpBa/hiZ6qFwp8tHbvlJKfF/PtuGfpTErnQ09hw93Q2QgS9TfFpW9hNW4/
         PxTrX6YrKrWqydajpSqTPuw5yZU2mYTOtRW7mCoBX6ZUiuhA2csqPetFcRSaLcZbF+WY
         tI4ROfmNnSfPdj0qujCJzT3UT9oB7uCoNOkl7hpbxU/ynMCHdc24guqEQkZXIdXCBHpf
         HLtzwVLF6knDx9nrZzi4/QFKnAHdCk5iXu7CgOfdywNxxydNLOTtWTuCUwEGfQaMhALf
         3G/KzoVzNYE0J48goky9zMNwKrQjwSLtKWOSjJMsuatiD+rUR2YCVKtbR4+jmCCDfDbw
         /JvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ck6p=ar=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ck6p=AR=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KTgSB+5l8ecPXgoa/l2+Mq+ApNAx531yXUoARJ1rDVQ=;
        b=TvX0Ooky77+b3GZdUIsWEJjLANGSZkU1Ou1ZH8ZpzkviPF0/SloNg6vLB61KBF7O4b
         FQyKzPQahvP1tRUEDoS9XUnijrN5ETUQ7u14M0hDopFh/rg0qKoy+gSIJ3WNUDc3bGsM
         eGqcXuSrl5JCa/W7cCNc4bFJXHYBaIeysrPaFpGv/fNWge7X0mOZDd6vQNa6T3NpUMct
         1+b83x6kZLznYQZK0hI+eoh9oBJiHhNbOZlhog/OcjzT5r1AFsO7fBW2cniYTIMrwmIZ
         PMXGtGPAEqn8qyLpT5dC7HrSyDfrcjB9EsvFAYTIDDdEqvoufOy2VJaBCSjlQxKl8F5n
         B3mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KTgSB+5l8ecPXgoa/l2+Mq+ApNAx531yXUoARJ1rDVQ=;
        b=ZPjrssuTG6sNDv369eF4l1nkD7BS43LyuuaYBL3Hk12Vr94CjT8kk0GEUa7IeW+CMb
         9RUNt7qPcTYRmECrJR/czLNOymTeAHrXFc0q0AJNsua0SqEQj/NNBWVv/omMHH30QR69
         Gth9y2NlVRyKv1nZI9MaMjdNAf1izJf9/PXWDtjB8YGoqzPb9d3/p+D6UlqYEA5yZqIy
         odgaTrV/Rn1EkXJstxP1uDHIky9EZiqqDJkEYI/893TGQMNB8m7rQA5e6hWH7Fqm7IiY
         Ht+tryJEpOZM8ExeeUBC12jGtRJACWnjpB5wjRpEFTHoQnz8dBcJySBjvTghPRY+wN73
         +czg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ex+XPHDwB7Egwn856pEQJI1syygfFdOszMYO0nQHj6iVjkTgV
	JIgqK5MyVO7S62Xa+mlVdlA=
X-Google-Smtp-Source: ABdhPJzhjm+zsMow7kVZ9acChBH3qTcU/IlOiJD7XT5TxEcN0mU1rpl/ZR1Sanmhu/Jxmdf0JA3LhA==
X-Received: by 2002:a17:90a:e007:: with SMTP id u7mr40789883pjy.9.1594022030146;
        Mon, 06 Jul 2020 00:53:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ea0e:: with SMTP id w14ls3263252pjy.3.canary-gmail;
 Mon, 06 Jul 2020 00:53:49 -0700 (PDT)
X-Received: by 2002:a17:90a:c715:: with SMTP id o21mr50955332pjt.35.1594022029841;
        Mon, 06 Jul 2020 00:53:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594022029; cv=none;
        d=google.com; s=arc-20160816;
        b=HmMNxdLs1/+xlMpqyaO1DIkl048NUPfuJ0gQAOvsiwb4NSQEg6eZ7sPN+/HMNZrTbw
         OIEE9pJ1UsdYmmZvnwPp5qRmmBUOCPNuJO+i2HGCpfZnaAsk2e64yBihrrStdH1naPc4
         emvezHPSgu6jYHjwmMAAvLU/OWOnl8tlG3J9fcEVom/NqLy4Skm5TEYxSmdfqI0qWTjy
         Prdr3cQf3dw2MxWiMYAH9VgSKje9LuT3+SXB+gS8FHPhf6yqCa7arWEbzWE8cL/O+b2S
         3ta9Gq41J8CM4uAtklsbzk0/XoJ9hKxYt7H1fXMLMTuzmZADMuWGP6Hrhiw+GkSVpP83
         sSXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=Wnp0d04S2rLQc0lO589fvHK5BLZbc9Ai9Q5EmJZwe0Y=;
        b=xdJ/pVqmPI3fisHLi7MDGQauSd1DkkBJnED/Deq/c2YtJDrrFGSl7RYZ+9RXbeHrp9
         gSkOeAWF8vzhmphx910b3MXC+QLYsAF0xyaAuBIt6QYl9TYHZ2UtFPszIn4nmRY9THsA
         nnOk2ibNCOfA8LlPjJ+VTb+PjphJZFZnjkPIQkeTmrRt0uV3ds33/e8XGqA4MQWsIj4q
         5s4+/ewke7mqsqjO8V2Vx15/FG62uswGlXiTub7h2dtVKKMC2kYFOHP9yx0N7z5E2HOU
         fKbdQblaJSaTMBQOPCbMBjKKVcie1eTQ51EjQwbOL200R2+SDi0VA3IxevNUmgOk9nR2
         4q2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ck6p=ar=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ck6p=AR=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i3si1909081pjx.2.2020.07.06.00.53.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Jul 2020 00:53:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ck6p=ar=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208461] FAULT_INJECTION: fail copy_to/from_user
Date: Mon, 06 Jul 2020 07:53:49 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-208461-199747-jFn2yxxEoF@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208461-199747@https.bugzilla.kernel.org/>
References: <bug-208461-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ck6p=ar=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ck6p=AR=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208461

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
Adding this capability to FAULT_INJECTION will make syzkaller auto-magically
systematically test all failure sites.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208461-199747-jFn2yxxEoF%40https.bugzilla.kernel.org/.
