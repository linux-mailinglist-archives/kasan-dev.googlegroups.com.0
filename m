Return-Path: <kasan-dev+bncBAABB7OSSO3AMGQEJE44RWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E9E6958E73
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 21:07:43 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-70eebcab33asf4202753b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 12:07:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724180862; cv=pass;
        d=google.com; s=arc-20240605;
        b=fWLooa5gbadLHPmiEFciJPe35aMeldA+lWG9SNcHXD+fgPifJ4JV3S/jqKZKC/K9iN
         unBvZk9H5pbxyGBbvPYPUal20+gjhRr+Sb3eJNtUx1Aimek0rX760h8U4SCA+rC+sOEZ
         P17d5FDLdDgw8VD2EXnmAKi7+2J9nkb4rcGxN9yZwo/ktVcrELwBOv4OSGi+k9vuPayF
         PIC+D3Q2idtWoDeas6yQp78WIJyhnZih0Bi0pGhxpGiAjaxfLebpxJvLupqOJYcmUFAN
         ZQEKCU9tjDN/jSzvXOq1YGi5zjbo/aKBqITHJwtIjwJJX0PavoQo6aYDXgCmLYIuH/JW
         nQiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=qJVgjCQpXe5LZhujaYfhvyHwk5m9hyZazTufYuWzNIg=;
        fh=/4SX6yKkhzlCUfGtDQYxNmZtLJebLanTxgrsMDrUq14=;
        b=AhQuu+uDfYaMA9oHnX1hpbvhb92dZfTaGGjRDGylHMO0OHWoNg3wW5sc9YbZZGiJHu
         HhsAba+3OSl/KwCi3QSUgIUxMWI8UUMTG0zdPN0zVU4i+sgPIlMm0G10a/MkZqfcdujr
         LlGig0dbX55XyjPJLTgZFNwEbPv41ucToNgt58hG86qI3gL0F6Vyg+rNFjRlXkOJkIWh
         rDQZieNjUHDf5BUc2BNwVZSTZHrnpYHYb8L/fozXIvYTNdcpVIe8XDxFfh4jXq9gKbBp
         f43+OjUPdt0ixfJZh8dIgeQNXhBZGty6ErHll9Lnyz5EBVp0EbQpUfCnvUGzVhNe/Dxr
         dsfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LiE6ewnv;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724180862; x=1724785662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=qJVgjCQpXe5LZhujaYfhvyHwk5m9hyZazTufYuWzNIg=;
        b=bPQeUqOZjkOQOwiGpHA5JEY0BJuqtnKwe3IXcHRfBTiyX1tuTlwp4XonEptb7hpGpV
         lZnXbWf+stoCsr3hRcNHjZeNXL8h07LYrkCq47KSmFV/7cPM4JNondZe4NU77bYlOcoz
         aIf/Dr8Qa3DRPhWa72dSwT2T3UtNDnb4AnSrIZUHt+25eLnvcMBKpLVqCBAgLWMSkmAz
         Zoy1bW6L3olmspaFL1qRAeTSoBviEJHYeDO8V0etYy06IpvB8tslhM6ai8JNfdOKCR3y
         BO4DlcVJFFT/RM4aTm3Pv8i5xykcrByvgVhrTJdb/8xJEuDou1CYJCQYIhODNiw41LT/
         DO3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724180862; x=1724785662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qJVgjCQpXe5LZhujaYfhvyHwk5m9hyZazTufYuWzNIg=;
        b=WfL38AAXqg5GVVbWYvqyvvR9oSH3mcdzlBmqjpHH5Vw2VlEGzG4iRzJezIy/n7dgw0
         NJw4x3xm9Lvewyw9BtS8Q93S2qzWlKftEx3l/+XxP0jfPlPY9sxdRgT9T7N8S2vaYXWP
         aK5RWtzfbuH3OFQsazGObgPEoh96WjbCl89lMK0CNqMgqwkLWQ1z/TEykRKCe9lqKdZB
         5ISuiNkMBFmcxUbh5Bh6NrA+MH734M+1D6aHk/P1jQpO/rzK/1iG9+h38r/WHBrR7MBo
         HVQtWhk/lQ4CWxekEatKLZ99og2iaJXgLvkZdNMzejMu/uEHjzexJr8VGKOokTg0YQTp
         CorA==
X-Forwarded-Encrypted: i=2; AJvYcCUa3GcaAZdwTybuXNI2MqcDF2j4zdh3HWLRMQnpXfQzY8tUFAWtfFVwohkP0R1B8ztr2OUAhA==@lfdr.de
X-Gm-Message-State: AOJu0YzJc8nxK1TXVI0eEV7LRcO0bndmmCXD0JA4w+GAGtslEFYEg8pM
	abAmaR5qznWtRy7ldhruI9yYgwM182QpL0xpaCIwXwbHZW5mxzSS
X-Google-Smtp-Source: AGHT+IHCuyKWwWFcMhcw8dJfzCAyFP/X+gACB6/aI9i6cOHkkDYRb5WO/oI1BKwxx3Q8j5zyNhdjQA==
X-Received: by 2002:a05:6a00:188d:b0:713:f127:ad5f with SMTP id d2e1a72fcca58-71423525dd5mr112436b3a.22.1724180861711;
        Tue, 20 Aug 2024 12:07:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4b50:b0:710:e495:4441 with SMTP id
 d2e1a72fcca58-712764ea745ls4426961b3a.2.-pod-prod-03-us; Tue, 20 Aug 2024
 12:07:40 -0700 (PDT)
X-Received: by 2002:a05:6a00:2296:b0:710:4d08:e094 with SMTP id d2e1a72fcca58-7142374a879mr44930b3a.2.1724180860657;
        Tue, 20 Aug 2024 12:07:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724180860; cv=none;
        d=google.com; s=arc-20160816;
        b=AbeKcpCAOXuARJZqyDjSv313iD5re0sAoibPLzWwNAswqdS5TNWW7NBvsc0p5yMhjj
         xu4TjuUyZOzjXdl+BqY5nTiKeW6reVJ5sGXEHhDmSSi+o1/tdDvJTgwuClkSpdmKxrCn
         HwBe1HqNzXkCgn5LjDahmv+gDFxgVqaTPiA4YXU6VklOg4neIDJgsWXOx51sLp1tnar9
         3CCQEUCwUgBBpPdgI2NLTDsm350qKN66TX44PMipgWJnHA5uV/pw/R6tK1h/saVbALh1
         2b3rKHqyqaPYxtU7XX4RagWc8iMxQ+ZeEGKey/AHr8aKmimehZk8kMJr5yOMpd5CQFQ+
         LuJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=RXr+zBfJmhssxwRW9V/o+xzJMlGxcdFWBFB22yj1hLU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=YPNRPqrGI0qxUBTfEVwZnt0ASiaHk5YuRxlUbEfiRXMYeWyBgWvXOllNfjTaR9weTi
         Dycr3Fy9CGMEK7PcNCXL4U8F5m/zADvOys5exu2ZT3tlivToUDZgI9wIizRIwDdDSAhQ
         lTCDeGtldhKdQxGmRcsIkqp7NwreU74ZoGyncus9008M3+ZUjnHtWpNGNQhq3CYIcXL8
         /aW6PdvNsI5uA/QJzKsDfcitRQ1wFIBnjEV3BHNrZbJ+PLikCUcP/Mfsj9OtWP/J6f/h
         /DMIFsRVSa2qg51jbJBhp7MhKaAtUt6WCosZzVzrxah2M27ePOfjQLMNP++35Wc6cZZy
         yQkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LiE6ewnv;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-714209e44adsi25517b3a.2.2024.08.20.12.07.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Aug 2024 12:07:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 5CDD7CE0B7E
	for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 19:07:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 37B64C4AF0E
	for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2024 19:07:37 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 2A969C53B50; Tue, 20 Aug 2024 19:07:37 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 203495] KASAN: make inline instrumentation the default mode
Date: Tue, 20 Aug 2024 19:07:36 +0000
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
Message-ID: <bug-203495-199747-yPcCJ1Bzt9@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203495-199747@https.bugzilla.kernel.org/>
References: <bug-203495-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LiE6ewnv;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=203495

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #4 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved by Paul with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=83a6fdd6c27d4f6f51fa1092805676b24e0f8827

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203495-199747-yPcCJ1Bzt9%40https.bugzilla.kernel.org/.
