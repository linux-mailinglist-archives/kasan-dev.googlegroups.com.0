Return-Path: <kasan-dev+bncBAABBLVRRCWAMGQER5TAAEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 50F30819379
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:26:56 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-28ae452e84dsf4651088a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:26:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703024814; cv=pass;
        d=google.com; s=arc-20160816;
        b=R+DT/8Gg9OiH/tawwxVjHZ1iyB0IzIYTTqEhmBtLPYmQfDnhhkZ/Na2qWRPXLsV4bo
         HGN7ZjequYA9ADXU1gnNGfK4ekgKuUojo3N1pqFj+ROrl3CMcTYa5gNj9YSF+YvyFdQL
         F/iEu2KO/GuFRBw0TwiPkVct9JOk4vFcSbdkNY3CUxKpktM1ka7eDiESJNMLs4snYf2G
         X9soBFg8wu9z8001pS1p++3pbdKGSZ86PFqM0thmUR8i6n1sJoM1mSwslt9hjO77aVWl
         NgXYh/lUIGeziAXt53P/vLPX7uPzNXfD9IjM10lU1P5Y+wZOb8KWHDFWu1W0u9umVUYO
         JbPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=lG+FDJdxWemlGMpckmBCl9kWByUhw8luvCWE41O9TCE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=rYo0vxTldilQYJE26y8RtGS6MJF8bvpG//5UwZpWSZZ2WY5NhqHPllikFvKOp48Ify
         konRJlhoZLWSgkdw4wEvLiXwcnLF0H6wpzMVzOnDFRncca7k9jqzV3/dIgFNv5PwiBo5
         vCeFxhsnmFEVOe+Mrmas0A0UtxELeAqpDegiTfIuWoDMXZyS61Wg8VXXgfudhGBzMpd3
         bLwj2P9PdyLrxooPOAccDX96K01TNlKnGPQpTnT0yg1jZpTX8YNj7D2b9/duql1bUwqz
         xHDDQ/laDp19l3/OJcbuUHl8E8DnFb2RtqxpjiYkBF1JajshehqZXnQocujZrorsT+t/
         sfmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TIFHTErp;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703024814; x=1703629614; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lG+FDJdxWemlGMpckmBCl9kWByUhw8luvCWE41O9TCE=;
        b=GsNxMglC/h5uwopixjzKnReX9tsHScgk6ttqSNeqtljsjNfDdJXwW395LX9xrlk5Og
         f5xhvMUuXpphvGmLm4fGwzc98sXAWynX+o9nasuuEe8P/ey568u8Czv1OI+wmC//ckx8
         HvL/PScGsrWcQv0he9RYN1UeNqMSAOGybCHUeU0760+DtyG3dlEXxz7S+c1+H8oFc0Ho
         363bsJtILt3J1FyAtlKmG/iT9rSfNcJQCixT/Xe5mPL9e6gSyFgo5kI4KsnwaY2WtWxg
         cndHnGyo/sdxyXGOxnkXTFgZGS8gFNvIHcN0GcanP6yJVwKFRFyRSUjfgdKQSoltQ7A1
         OV3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703024814; x=1703629614;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lG+FDJdxWemlGMpckmBCl9kWByUhw8luvCWE41O9TCE=;
        b=Aee+Cu3WfL/2rxMe837ssYM9/jj4Bq4CcMoj5i3UkqlWUttiiiHuIYcEul+lTLVQO0
         vSvrdEGB+hZeGkoTxusif5L0XUr3N0EJ+MKrNXV9S7u7LfYppGD37TCUPQqlmA6jgTc0
         n8yFoEsdnD68BQR06ju89UAH4OSi3ZBS6tzOKGbWN7mKCkTYeNvJOcpdNaev7knlKn29
         +eEtOcT3rBqs0nEvrf/4RExf/mor8hNUouxvMcPcwBhX+YVFxB/yKtlibTKIITm0cbiK
         0Wap4nqHuja800Zc4KE1rMghw+s3leUhNTopDTUtNTpCmVaHiMOmqXYSvxQnVkU8/Sox
         /xxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzRZ9Faj5tSgQ9zUVdzVu4xgnFZJFQfi0VsvsXPM/grdN4H5mj6
	LmMKgEZgl5h2Kyrvauft/KA=
X-Google-Smtp-Source: AGHT+IEmzPNtubshTgFQVUrfNZh2NEjkHZtOw+VyZUsGalYD7AEFkzFeNSfbF1XtbYa2i7cIDwIz8Q==
X-Received: by 2002:a17:90a:9705:b0:28b:c659:4e87 with SMTP id x5-20020a17090a970500b0028bc6594e87mr834791pjo.99.1703024814454;
        Tue, 19 Dec 2023 14:26:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8987:b0:28b:88cf:d801 with SMTP id
 v7-20020a17090a898700b0028b88cfd801ls95963pjn.1.-pod-prod-03-us; Tue, 19 Dec
 2023 14:26:53 -0800 (PST)
X-Received: by 2002:a17:902:d511:b0:1d0:6ffd:9e13 with SMTP id b17-20020a170902d51100b001d06ffd9e13mr20707488plg.101.1703024813513;
        Tue, 19 Dec 2023 14:26:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703024813; cv=none;
        d=google.com; s=arc-20160816;
        b=CT4a47+7ThgebMgphkZ7UjpBIPSc0w1oXIadlpOTmAzqihCVD6/8z/vURG0WtsBxv5
         Vybhz1bG57HiQg+DN7jS2QVF/UxHTEsjEG0jsWZ2u7cG5nvhsCPl4NHTpl/it4APZcfg
         Z6wa6Pv9mjicOcWHOApSvDY7EeCI33nr8JdUk2RADYOD4u8S9zWeG/9++a9j4rQpGW9E
         FVpkbOvDT1aUEBfPYqsH0lEzgCx5H3aonYxEQtI2zdsRAFtC6zK1+H2dBxwfxz/DSoLw
         hWkGbj0D6GVuchzeOtVelpVfQIc8h7Nzer4ky7NW6uyv4+NiSLgoHdvd41eGKkNSUCOv
         XSvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Wk9OLHSSd/HdQmfAfNhr+5PwYMm6AktMWkB7Tg85d5I=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=F5NvtvUzisuizTXX6jCjmJpOU3GheiaZDYDSpPVaou2lcocJpwXPs0NjESzugIUU9T
         iQ/It+9ODio52TApiXxLNEM9NhRSDJJuuOiGo7iuvmCzZYtHpnoiEPWUIA1vsqzyof7C
         VvzZ2R0XbLEf8FeEkd40GqLrrzX9NPOStPk37XcHu/0wpwwQzJv4TiqtASKUJQyEhZoa
         PeENu/Gl83OcApafI5dRWPCLA3qFGxP9fqAt0Yi31pEYtPfLlSKtCtOuIl/8c/MY3pMY
         v/NZ8RgkqnY7MREo4ngdCK8PIyQ4HhD5cmRQMryZTKRrb2WbE0Yn+d22rD3iqqrhcflZ
         JC+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TIFHTErp;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n12-20020a170902e54c00b001d074768d46si184777plf.3.2023.12.19.14.26.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:26:53 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CFBCF614B8
	for <kasan-dev@googlegroups.com>; Tue, 19 Dec 2023 22:26:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6787BC433C9
	for <kasan-dev@googlegroups.com>; Tue, 19 Dec 2023 22:26:52 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 43886C53BC6; Tue, 19 Dec 2023 22:26:52 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212167] KASAN: don't proceed with invalid page_alloc and large
 kmalloc frees
Date: Tue, 19 Dec 2023 22:26:52 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-212167-199747-SjbQWi8Wly@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212167-199747@https.bugzilla.kernel.org/>
References: <bug-212167-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TIFHTErp;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212167

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|KASAN: don't proceed with   |KASAN: don't proceed with
                   |invalid page_alloc frees    |invalid page_alloc and
                   |                            |large kmalloc frees

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212167-199747-SjbQWi8Wly%40https.bugzilla.kernel.org/.
