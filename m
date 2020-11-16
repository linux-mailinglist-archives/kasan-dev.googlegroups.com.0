Return-Path: <kasan-dev+bncBC24VNFHTMIBB4EJZP6QKGQESBOQ5UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id A4C8B2B4F3B
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 19:29:05 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id a20sf4823506pgb.21
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 10:29:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605551344; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jx2XztwRmsCap804GP/7Ht6AuvsRAeP3FijOsTG03bAt0rMtMobTQTjM0xe+chpfPq
         dpf42PoCC9MJgfSxmywrFGbpkSRm6nv7GgRONoc7MwUkgI01GWMHxid7VTVvFvmS1t0O
         uDXIsMvCWGaUHWJwp3yZPUcVZtpUC76jznxd80bz6opK325mQjwAyNddkWyIG6Ff8N0k
         bFuOHYkMyMkXykzWWyc9qvjmW2sr+r7+cDpxYRjw9oVxkm7Fc0akWLu+WEasEJ/V8NbF
         vLqgeYQ7iWWlDWIkl9FxO7Qw/njDs8kPKOsf4zSi+sohpFox3Yk/VXM2UR+tXoRWowlC
         rJpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=PXN31p5ZhsVJjtGOtEIvn649/jdj6dpzpXIRysNtO7A=;
        b=SFjo0Zkjm9t7HcwlHNxyc8VsmRYzRsBa0hzES4ztdaxcLkRv6E00cniDEXnjrRucRm
         hyo99iTl84l5zG+jNM3pOPxM8PzQ9u5mlUjyeex/ShSjEHwOgHb8jaZKxCfynxGVLn+B
         F1f/xXNkbUsa/ZRY2rVUPO1Ca5a3BfnwftXpxQV0Ln7IySNR0Wf9V6GSxeXYFG+dqlPG
         hekoO9/qJPp4W5j2xdFQED4JHcsLGHYO6nzUB919CuNWk3kS+EcHithN9xKYZ1grDjn9
         JjKVvoDnKusNMxMzHHZA+u3mauSSG295xjMTXXxaYRV2Ix+KttBSaX4zzV7QJW/7Hn5Z
         v7Wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PXN31p5ZhsVJjtGOtEIvn649/jdj6dpzpXIRysNtO7A=;
        b=Dbt5hFK3GwVGS08sM5LOkZV+uQ2XXgviry+4LWJZmkQY32Wvkbdqz7qXJpsHUQvccO
         4cAnKty1/zmFaDcy5cvf7QBZghBc94Lb1xJ8vfYDBRTmfS5XJjQ2aI+ookTAqEqZ3kv+
         ZLhx/gLifXHoWRiC+t94ExtNAF68PHMY48iRn7VLH360GKyOtwaK07uBy3r6YTRIY2mP
         eodERR2jUpl3upCtWqTeFETHYhNvsSl+MR46Ig31fdhMZ5aaKZEjGCKi64aEOP7P/jir
         UvbAMqSCu3KTQQI8UsKDg/maKw+HrDsbKfgU3HaChwt5PtOhx3yEtAAALqoHgbLy8t0+
         FJlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PXN31p5ZhsVJjtGOtEIvn649/jdj6dpzpXIRysNtO7A=;
        b=fZ1mR9BjtQkW0CrpEm3i1PZIdmPWePSfebAQeoCwHqky4XnVP3nuechSr/lb5X9nTa
         RmQs+BIajRM6SecVlvi8Gn0xf82toen6GJ5Zh0/Y5n03qiz0ArRLw1xUmorUaKjI44eK
         XK/Vo3xH+U8BmeMfCZcYr1Cufk+33Y8qonV2Q49pXf63SArH9BdDJv8K8nxvPh98kRgQ
         jhlqIdTRBv2SX4h9fOjL7WB9ohHHY33JlalUF4pcf74Dlha4Bgylts9gruZYsTMvewHe
         hiTfUtIjA5h8UHBGabaKf081avMpJ9kDYG7VJehgnsr/qLHoX+fxnH9vaKPfC30yXiWb
         lTRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EmjO554PjQO+bTRexOWNuIiPqsDJgelInelNB2vRlAcztC5Lq
	SSHsqKtXWLC5Ssq98pb05Tw=
X-Google-Smtp-Source: ABdhPJwMvVSd6B1UTG7xNtDI74rPnSAaizKAN9A6JsyvYeqm9cL1DKjvLpKm7LnfDqEs7TYUGGVWyw==
X-Received: by 2002:a17:902:bf0b:b029:d8:f677:30f2 with SMTP id bi11-20020a170902bf0bb02900d8f67730f2mr955396plb.25.1605551344406;
        Mon, 16 Nov 2020 10:29:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b56:: with SMTP id a22ls4965836pgl.6.gmail; Mon, 16 Nov
 2020 10:29:03 -0800 (PST)
X-Received: by 2002:a63:1b05:: with SMTP id b5mr408323pgb.345.1605551343852;
        Mon, 16 Nov 2020 10:29:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605551343; cv=none;
        d=google.com; s=arc-20160816;
        b=VaoH9chjzOiE6H/RiG1g+WLz8ifFIk5R1susCxa3GDal/3z0G+F6V4iKtRaYWuQWVj
         Ffi3RrJul+gX3zESryjOMAMNtVQgXlnYg2lwbSq6hqdhXQeUlUKwy82o0sZAyns/Z3XD
         6jpH0WpS1pqmofl7Q9u0Al6PiSotan1gTVxgRO1/lWUcp5MzYFw+7zE4GRhck81hhXs1
         hMHZN4Rq4K2NB2d6Jnl2QUYlaX576p14NI9oGYhHSOHAiQymZkPvwhpNngHY896YUsfi
         UBtBLBq0m7ADaDXZEAxpYrYYxMOqDlJH1rpvkTcOfTbf6QiE7FMIwP58Y3Nif8p6+hIt
         GhvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=D16xElQquBESGtYW647O60d5GzZME+t1PY3JGMoW6s0=;
        b=J8XL+ULzwIkjSLl0fZj9sIwDcZCTgTXKk7SXF+M5oDFGpLMzwIdjLsOWVKNQt4f6fp
         BlsbEEmp5uw3ImOPh/TUZC2zrdqFeChZgSC0bj6Q+DiEfPL4VBmWAbmA/ZypAn/MxZHm
         XkkDaRW742J9REsFFDN+5SQXDUt/ScYtDK+RVr/i2QrEzFy8xMn8LJmPfI4LtUHUBWWo
         Ne5EEJ+H5LWU9KsTnQxF3c4D+1c4NdscE5/GyxN4Pt6f1DYXQSqJiRYCzrl1LsUWZkSt
         djVJurT9Hvt7Ern9jY1SHFBQOFLJ52dOQwL0Qhs0KIJue75ll8CEfSjzgeusK6gzgc7+
         Og6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e19si1043988pgv.4.2020.11.16.10.29.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 10:29:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203491] KASAN: double unpoisoning in kmalloc()
Date: Mon, 16 Nov 2020 18:29:03 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203491-199747-Wsn9sheWS6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203491-199747@https.bugzilla.kernel.org/>
References: <bug-203491-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203491

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
And the patch actually only appears to fix double kasan_slab_alloc() for SLAB.
But each of kasan_slab_alloc() and kasan_kmalloc() is apparently still called.
Anyway, this requires investigation.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203491-199747-Wsn9sheWS6%40https.bugzilla.kernel.org/.
