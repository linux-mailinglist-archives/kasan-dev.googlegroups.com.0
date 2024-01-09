Return-Path: <kasan-dev+bncBAABBQUH6SWAMGQE44BERQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id A3CBE82811E
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 09:28:51 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-5580883ab24sf7917a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 00:28:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704788931; cv=pass;
        d=google.com; s=arc-20160816;
        b=rmfFcKk4YqmGdODnxz2sVr3sSbWdQEQf0YjD6gcVThJtNi4lh9jpokDGs5xupsu2pB
         f3TrMYBJaA31/Q1dDV+NaG6iowWVd+njN4S1wGmg1LPhbdMbPhsE7ZATw1TQUkXqNP8G
         W5bDByr/WDqxgvZh2/RHA1G/iaZ4w6ujhsafjpFNdcBUroW9JbBbvZ3BGhoJW2C33Jpv
         k53HDFSdW1QDe3ZJ6OD7+SWfXXJXGksLwLY3KZitoFvr7u8xF3BmOF0WzIHfN0nD6EYe
         WAZrE76lJLRASkk5vl4bkCMvphNS5YVtdt1dKQjrXu531dowc/hJleYkS95c0Re12VdF
         BFCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=7JQPzNnAax5C2LyiBNEvr0O1wefxrumbuhlBZdHLL6I=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=q6U++AHkfF33qTgHXfX2ynY/f9sEkVpdvk1nRj4C3SnqNgkz/9AtLlIZtp7s/j2orA
         VTvo+edVLZRhcRqV3+k1EJdcKfeY3ZUVcAbSwi4HtgoWkz6FQrSxZB4tgUhMIJ4r5sAv
         b1kyfovJrm8BXtR3FMfOprJ/SvVcOK6yJs5TKytjVCq++AYThQjYH+3FZggXUhRKArz5
         ZUqvTnKVXz3F2NvAlGhob8ORtsW58WTCdO4edU/wL38wjvsBfbitBjWWG4iCcRdhl+Yc
         +4lW8aTDbKT6S25clUcAe93JQMbUv5vXCeS6xo+wnNS9XtHVTcOONfmdl9DUw6jic4M5
         W6iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MOcc8WX2;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704788931; x=1705393731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7JQPzNnAax5C2LyiBNEvr0O1wefxrumbuhlBZdHLL6I=;
        b=jK1qpPor/vhAQkWUjpE9fqjXOdah/vAUT5AN806mFgNiyOoRTWZUeBT974PYt32kvP
         jxlL8o32kqNWS3ZH+AypiJ6QP8l+wWWYxBIrmCXlW57fFKdJmVvtnyGBrhS7/77GeLSZ
         BQBmsC5nUOJTom9HbY9jBa134IrRZgQTqB30qMYS7soRTHf+PgWaeSht1wXqo+/ZK3xV
         IzcYj3Bfeuy0nfUmbcebyR6sUfzm0VpWDGGI7kxB6umhx8ZMTxvtd+Bh7LqM8Y/Uq3r6
         25140/Kh425NqmBWxfT0VJBt8amt04QzA8NxUVowU+8dhQrozl87SGMHrctnoo7p8S84
         ibNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704788931; x=1705393731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7JQPzNnAax5C2LyiBNEvr0O1wefxrumbuhlBZdHLL6I=;
        b=UQr/0HJeAckxuxNWKU1+hw5roOz2T2TwCqOMAQ3irBqB8OjeuSsEnUny/NTMaxYrW+
         diai3KNGoWBhUw9wLe2C/p+jeo2GAvog7qDZY/t8agR8qNHkyMQtJbNeKGAu3XD0FYPI
         yvpOUqJEChsoIel+R2RGQfPZWxnEcBfasEGjwmjdCZSE4al26P3cxngl7mPn1UCfkmoE
         A9XaATbn8lvwA+7A50+7ee0gRjitkQIEgufcj2yNnfbzOX5LDb48hVsW72D4noM/yzSx
         QYKjLQO/cKww6SrvhrFf02mpqYFF/NJPRvsKQG84QiwgmCn4uoMR566asw/oNM0FK/FT
         krUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzjBXhQQU54XK5VU0HPuXDBQMR/YUK508QCOtk6JSGKRcHHTEmO
	NjP2TQ22Qg+dHZ6X2abB+oM=
X-Google-Smtp-Source: AGHT+IFuAnA6JnR1xC4JJraR42MJwq43wopt59PWDOJf6NFece9HRdYYKFWM393MPXbNKQqjoOgfzQ==
X-Received: by 2002:a50:9e2d:0:b0:557:1142:d5bb with SMTP id z42-20020a509e2d000000b005571142d5bbmr35210ede.4.1704788930806;
        Tue, 09 Jan 2024 00:28:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1310:b0:50e:7b04:a7a2 with SMTP id
 x16-20020a056512131000b0050e7b04a7a2ls82991lfu.0.-pod-prod-02-eu; Tue, 09 Jan
 2024 00:28:49 -0800 (PST)
X-Received: by 2002:a19:f811:0:b0:50e:7be0:3c36 with SMTP id a17-20020a19f811000000b0050e7be03c36mr1209982lff.55.1704788929196;
        Tue, 09 Jan 2024 00:28:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704788929; cv=none;
        d=google.com; s=arc-20160816;
        b=gV9/WezryhwqRYOatsxq+OeJlGts8bI21XUk5HXAmVOVFdKae9dJQCT4/QrQGKXS8P
         cTfEwNqjNiGrvBKfLb3PPa61A9tBkxdp1HO7rc6eqGe5yUuaQPwPXdeUR19kKBHz0VL6
         eRzBdz26n6vKSwTPMiGdS5MrLmafeh44ex5drD8otmMW/STtAZC1T371hp4wOTnkPXvC
         uj7BCDu5NZz6qGOLUomwJUxSES+Eba2JbyuHYqU99i2MH+M0xDaiqnK2aocZ/flJieWD
         2zJsEsEDS0v0iHhiVSjfTs0RFcx3gAX1mgg1U1Hu3RgvE9M6XJTem2IJ0u3MIqXuRmXW
         OElA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=J8jbtIo8QpddNNdKMhAIQSYodysZZzi3T7456ROBW4I=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Gff31DtHr2Y/aT7phUGZAvaWfo7v/L4Hj9151zPK/rPRrR+Gzcdk3GcIVAf0FI8KI8
         6axf4zkyXakMUIBVZrOYeliHkUwzgacGGDDVN/QiGJ/axUkkJAEo/0mZ+oltO5BYVyxX
         JLeBPUA9DVcvpFlWNRUPS/Egt+hDUdM4ONiIlme4paukwSuYBgKSmiuyY4KRarUCa9MQ
         eZK/SzNQcBLdL6l+HcfJhlBQPIp/CCGPsQYglJuCnL83JjiYUVtN81teTF+WedtztF2N
         xR8X7+sJFRrPGYrQwSXyawhKJeV93G6+LWtDdjBMfm/qCckajhL4T92JlwaAtTfyccRJ
         lO1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MOcc8WX2;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id i13-20020a198c4d000000b0050e69030a77si73111lfj.6.2024.01.09.00.28.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 00:28:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 8F01CB81A74
	for <kasan-dev@googlegroups.com>; Tue,  9 Jan 2024 08:28:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E9ABCC43390
	for <kasan-dev@googlegroups.com>; Tue,  9 Jan 2024 08:28:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id D4D76C53BD2; Tue,  9 Jan 2024 08:28:47 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218312] stackdepot, KASAN (tags): use percpu-rwsem instead of
 rwlock
Date: Tue, 09 Jan 2024 08:28:47 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-218312-199747-IdISVM23rn@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218312-199747@https.bugzilla.kernel.org/>
References: <bug-218312-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MOcc8WX2;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=218312

Marco Elver (melver@kernel.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |melver@kernel.org

--- Comment #2 from Marco Elver (melver@kernel.org) ---
It looks like we may not be able to use percpu-rwsem if we can't sleep. From
another discussion:

> > We need to figure out whether it's possible and how to add a
> > irqdisable flavor for percpu-rwsem. I now see that it's a sleeping
> > lock, so I don't know whether adding this flavor is possible or makes
> > sense.
> 
> Right, if we can't sleep in the paths we want to take the lock then it
> might not even be possible to use percpu-rwsem.

> > We also need to check whether it actually improves performance: I see
> > in [1] that taking a write lock might take "hundreds of milliseconds".
> 
> If taking the write lock is rare, this should not be a problem.
> 
> But I notice that the write lock is taken on _every_
> stack_depot_put(). With more usage of stack_depot_put(), this will
> introduce tons of contention.
> 
> The least we can do is to take the read lock first, and only upgrade
> to a write lock if the refcount has reached 0 to free the stack.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218312-199747-IdISVM23rn%40https.bugzilla.kernel.org/.
