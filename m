Return-Path: <kasan-dev+bncBAABBA5CUO4AMGQE64KKZNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D1A9999DAC
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 09:17:25 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-20c70cc9d27sf15448825ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 00:17:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728631043; cv=pass;
        d=google.com; s=arc-20240605;
        b=a8M/ziY+kHl2mdAe9qM7VDojNpxWgiVGx8f7TNi5t2xZUUZdYy3EYurC16GoZnRQMr
         JBti7CsZnVkO+9R5QcqpLsKT/4T7tF95UrSt2UPr6QPfgQ6tUTld+/wVwa0s5RcyaWe4
         vEM1H2ICci7bXHTb5ZHmkaq3sjNZUesJMvysRGGlABOLkN8qmB61VGT9DCWT86oZgG+J
         N7SfjxLCyZAvpiWAwYQAYnV+mAleBUzqYy+Px4NfzMmsk8sxpZ9A42z2O1cz7f1U8dHG
         TftMeq4ZJbFhEmxXpNrvEdiuMKnJkMHvSb9esXhXwhOWfdHQKeiKV25ODfdZ41k8FRzF
         uQ2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=OzZ+4du12NG/OXl3PcQdTtl3AK2kaaV9rPFDsnlYAx4=;
        fh=pOip4L3gRYnif7dYlVq5+HhZF2DAF8SnPqda7We8/ZE=;
        b=MlqRjYX1yNWK3klIyOFHy170WtZ2SzIxJgBnAUqSmiWtVYSHqTjf42dCEq2x2XcbO5
         EweiAykWQhxUtydj5UiHwOSKWNBIgQ//BKdT8PLQ/UOWMlssk7KzZa+16y3tnKpu4hBC
         mySRRhjR7HyRtVAFYnlKO+tBl+zplCwlb0wOPs45SMNXXr82dHRlKbEfvUOaeTW19Hu2
         N8XxKl2UBDe7z9gicsxOlmuD2tlVUk4uEFnKyuD3VQLlXBdrY6IkpNXFWkBpaSZk6IMz
         31PpG6IGWQaqTRzobFjOTJoWVQB7BC3mZjveTVbRKbqHD2xfhGt1qP26e0JVmE0PxZAP
         EE6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nrEf4rvr;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728631043; x=1729235843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=OzZ+4du12NG/OXl3PcQdTtl3AK2kaaV9rPFDsnlYAx4=;
        b=WFEsYfgpqfzUpTfgCWQul0nsUJCaKL++eFtqrilm451sKgIqKoiDFnz5YvruvuMFOi
         sL6/wuC2N4/vVFDGQEF1yZXInyaZk6bguGoNl7XK+g+O2QIHzmaBNN1hhq8Nz31SRfHc
         9RanGAqzByBY+CC0372X2qJZLEWnY+sxXhQ/fKg1B+JptCY1hA7oRz0V8ZOr06SMuVsZ
         nYMVoUN8Iy0FT0kWuqrE0pnlxcna4D4o02p1RvXf8uDALdtRiufFc402g/liBPRWdBis
         14hBk4CiCiQRJDn/Qqd7lbw/nq68CRgtTEzDJ5ifR6qWjSffHs5o3cj6vlfw7yWSmbDw
         1BGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728631043; x=1729235843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OzZ+4du12NG/OXl3PcQdTtl3AK2kaaV9rPFDsnlYAx4=;
        b=E69oVHNu0//VAnBUf4VlWYMNdcXCItK5iKeiEy0XyVo3zNcf4+sJh4i+fFfkvf6GvC
         IuB6lmEfcKOCwRHOojENrHA4weuZAw9hz2zLbfahtrtXOdZme3XBIy8D5hYPcp1ZRARE
         SPimReO7LfxtVSRRWxgs4+nb0O3/IW9/iVyRz7WP0z8x7S57M4H8WExJ0klGDWh89owz
         U8U/kqNBvb05SGFRja0E/dpCNJNA/tXLXmRYRcUfqZYjS78HwJVYEEjpBVwSuPtyfQTD
         0Z/vfkT8w3TLaMQTNDYPYJHRpNCulx5tseRaWOGjdFeBu8vy1co6NZY45oldYh8D1cJ2
         mvmg==
X-Forwarded-Encrypted: i=2; AJvYcCUizYSxJhNg7pRTJfEqCOGOAyXyYlx6/EsxjGTqK7BaKATR0S3cY/i36iA44VW/oyajo9PyOg==@lfdr.de
X-Gm-Message-State: AOJu0YypvEyw3L3qVGSIqlLvAWjZj8GLGbm/tWUa6fLA3tMB9fFxRz+F
	paOICQplt2Wo6E0+lgfGNNpkir2qXjUwpaAMUur6zsVDAzisdWXM
X-Google-Smtp-Source: AGHT+IGgfNUmHUk86FMtvwAHNemd7WejtbWs8nAmcaux/tMyMSHB4XLT2W/H+SkdRPz65JuiqTmUYA==
X-Received: by 2002:a17:902:f709:b0:207:1826:2f0d with SMTP id d9443c01a7336-20ca16f077dmr21937775ad.59.1728631043379;
        Fri, 11 Oct 2024 00:17:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ccc6:b0:206:ba3c:2b96 with SMTP id
 d9443c01a7336-20c807ab176ls15341025ad.1.-pod-prod-07-us; Fri, 11 Oct 2024
 00:17:22 -0700 (PDT)
X-Received: by 2002:a17:902:d544:b0:20c:5e86:9b5e with SMTP id d9443c01a7336-20ca14253f7mr23669125ad.3.1728631042312;
        Fri, 11 Oct 2024 00:17:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728631042; cv=none;
        d=google.com; s=arc-20240605;
        b=U2+tiGbRRYo25DK6f23/rv/BHPVS4i6XBifgO/5M8CBhwtIHV9iE3rgqiILXvc8UnB
         14ElygpArJVeKGKlq3djSFx6w4E0C84t/TVIxtOtCIJNahWkc7ugoh2faSIsctIUDq9x
         dXlm8pGhSOxF7Tkh6MlNzifzvrgLWJ5c9S9LAVHhgKZTY7TPAg7UVqjh9woKno1sighx
         T8QR1uTgRPixNX4sfILP8PNs++OVSksA930MPMOgLqHELEM4lO30Q3N4bfukcKdexltd
         UM4LeekJqC36Q6VSHHfa+YfQLX8rIz6DeoQwerbVWKANfoFvvV44KBNCWpn3CC5WlT1X
         O5Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=tgde8jCbAFl7ao9jpfdYyaugMXtP4AUSQViUxKUuPGg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=kH6VZP14ogcUa/cHUPMQYB9CqMgWXCW2nTZRFL1znRbbL4gEsvyAergf4gfoOtTuVQ
         UiKjJDadG3jDPRMmNrIHDRrV3me67kA/a7oKwLWWuwfKH0w/Spyk159dUG8B/1ATjadl
         SjKcrUuZsGnvW/kTkTPGHdY+pePK4mfK7qw2cTSUa/EA8xC1byzZQBVb/qlFG+rQZUbM
         9ldklhCcxc5UNHq0zlkCmWlwq6O1gKnmYbEzqgZksawKuPKBP9whBslJNjUF0/Ywgvbz
         KH67yYUaQYo2RNsmMERFlgq77XzXvTa90Loq1bM8vZzrLOKQeLTi+fb1wpjcRvZA88yF
         DeAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nrEf4rvr;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2ca44a71dsi362587a91.0.2024.10.11.00.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 00:17:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 540C35C5CDA
	for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 07:17:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 5C6C8C4CECF
	for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 07:17:21 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 51B9EC53BC5; Fri, 11 Oct 2024 07:17:21 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 212205] KASAN: port all tests to KUnit
Date: Fri, 11 Oct 2024 07:17:21 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-212205-199747-R0FBWMFFX8@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212205-199747@https.bugzilla.kernel.org/>
References: <bug-212205-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nrEf4rvr;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=212205

Sabyrzhan Tasbolatov (snovitoll@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |snovitoll@gmail.com

--- Comment #6 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
Hello,

I've made a patch for #3.
https://lore.kernel.org/linux-mm/20241011071657.3032690-1-snovitoll@gmail.com/T/#u

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212205-199747-R0FBWMFFX8%40https.bugzilla.kernel.org/.
