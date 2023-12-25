Return-Path: <kasan-dev+bncBAABB77VU2WAMGQEIHI6OVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 517CE81E1B1
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 18:25:21 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40d27ea0165sf38953735e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 09:25:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703525121; cv=pass;
        d=google.com; s=arc-20160816;
        b=NyqkawsbLUKUWzJywuKe9aHi5m/T3/kHr9TbuxtRVyxhuvkscme1PtnnCLz+3s/Mh4
         RHsTURlZR0OO/VMhDwNIlbnSPuJgUFscW9YXXOBv6jn6eGf3TFSpfu6p+yhV07FIQ2YC
         zA/23DZy1AQ36WaIs3UwdJioiEcXVhcfuvP97y6up3zUam6NrZqn+UlAqibNy0USHYeF
         yVyVgpCDA+g/jZ917+7uIn7WGOotcxMLbeQnefcyPLX/sjv5rlp7AtXgQE5yUEiTjPum
         uVupMizAfH2PQZjjYY8BUXliiVgYENbEAtDZDhtlxWYR7UeAocf6n0mUVg+sFpQwLRm0
         O19g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=IXB+a36PdYg/BSvysjMoSmVLg5Cau9C/7Mmihi7K1Gw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=K4Zb0y9FMyJHmPj5+ZmqjI7LYpTdbatGKc79e1n6DGzU64dpJ/Cjb67CJnld+O8HPi
         H6prBMh0uKvtLa4cRDl+6VRVCoxmd1+hfm1ETl9YxxWOn0lVQHN0yQ5wW0gu8PdfTRTw
         bi5zH+As5+TXq3eY+H8K1Rvx0gKV2Flrs6M8vrXQMhcFqErV0ClSABSg6PB3gf8bGy50
         GOdt7k8m32uqMSLUl8dc0+FHiXO00fwBozABjUkZGwpz1T4Va6JM0iADGjlCvR88fB2W
         o+7v6DtMmVqFX/dob3VavH8xKaNTVukNTadodC1+ypcvD28v1OSPqaiyT8eLQS/EJGch
         NRIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bM3QQCjC;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703525121; x=1704129921; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IXB+a36PdYg/BSvysjMoSmVLg5Cau9C/7Mmihi7K1Gw=;
        b=B1VGmNrIqev09BvsY5jl1T1Y1+kiLCsUu5DLvDwivpnL9SajaGxrhWwMW3W/VZ56NU
         N1dmIcf4D+66d1yz6xPas1RKM+iPMduKtpj9pt5NYc/LWW858Yl60Mk+sXGyshRl7w/G
         ZW6yP5bIwHfOYn0dMYDGMqYSuK1tHOpyWNL/i+V37NIxn2WI44ruPUWUTEgEodnrl0ae
         oNatPZJGznpgmfsStQgCk9fjvGRX/74qTqZoThBBxUUtd/J0P0ahEeelpff8TVQfjf3r
         6Hicj6JYwYIvdVdxbLieBOBezHFMtzNHQrsc0FCkS0u4SYfRS7fz25/XSISJ/UlfLU3p
         mi2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703525121; x=1704129921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IXB+a36PdYg/BSvysjMoSmVLg5Cau9C/7Mmihi7K1Gw=;
        b=BXE3KvM6uWzv8BOD4bkdbE5wbi3LlFKyXTPvP0wzKG/9nm3tZC/P4zzDEE6Ol8zug+
         3d4ZdMKuLs5MJNEHKJzI4wMhC1l2tE1+kxWBuI7dOzHE8iFtyVNm7hS0KLGYYA62Nc8w
         4D/hOmFf+8fcPfbVjeMdU6OtP1nBJyuFeIoRoFMSjEA7zGQwolnUpA7afjd9FiIFUyjb
         ukObCezuaw0Q5wJfzQPNUE6y1GPKyh5AUE6tHQ21qUJlvgxiiqs/m1uKrK5T0Ft2ObOW
         OfGjKl4i+tbgQX3QrYsqO2PFBvOkj+8Qsf+33BIOrq6xFBZtxyLLNm44PbuoC5995WOZ
         C2KQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwpK9bnulQVF9oHDoPGJJ8wXc+LvYdfYBCEJhIZKLZpcDwEc4GU
	m3RzKgHUJkJXi07cTzc3Sp4=
X-Google-Smtp-Source: AGHT+IG46i6/uLjZOc3vO2fqI9i46ONQFv/gB+u+A04VoUvlkUCwnCacrMlQocopdFTpyPc1UTxYiA==
X-Received: by 2002:a05:600c:1da2:b0:40d:3bdc:2c03 with SMTP id p34-20020a05600c1da200b0040d3bdc2c03mr3422681wms.138.1703525119904;
        Mon, 25 Dec 2023 09:25:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:510b:b0:40c:3e7b:c687 with SMTP id
 o11-20020a05600c510b00b0040c3e7bc687ls62484wms.2.-pod-prod-06-eu; Mon, 25 Dec
 2023 09:25:18 -0800 (PST)
X-Received: by 2002:a05:600c:a004:b0:40c:2992:716e with SMTP id jg4-20020a05600ca00400b0040c2992716emr3240840wmb.129.1703525118306;
        Mon, 25 Dec 2023 09:25:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703525118; cv=none;
        d=google.com; s=arc-20160816;
        b=VZotT0BrGIinJCCC5iP2zAh7meHUH+j11IWvVm5ysEx6aLqXgVgZ3U8+heWJPCZ/ix
         +AbVKmRjhlXnA4/Pto7+NzEXYrL9DOjruRb7ObzBXvcEZN0/Fn+OU332zseLTESlbTS5
         l/2kqkZLq0QHAXsE4SffpR/5f1R8vTt0b/IGOUHORItyjF4WajhPhA7Ise0qjdyfpIVr
         h2ATLvdaFnUtecPzdZRZSU1NQsW4rsp87f/jz+f9ika8QYfslqajTa7EPl8WNAq5L9Mo
         NShIB6tSCYOpBDkyQlJSmfeUwL5xd7hS493i2nsyyDBH4mS7nsFXKHK5KgAzPRh9LnnP
         j8XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=6qOngq7e1JvyJEJyonwix2aZaujRlqI8f9utevIfZk4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=i2VtiNMoi727wMuBXiq3qQV4nET535H4AahzBdWpp7a0XxMVLrvaadYJJB1fd/UQlJ
         j6C6LviZ3lGRt5Wchf9VBuQ5Q2rUkNy1QiL/1FNieAuFkJ28GhhNwIgXGbNzlJthMOT/
         JHQagiJ1fiT34DxqK6g4SBi4zNaqrCNIFl3UjdbtGkMUU86h0FhgJQccg7dOrJUJlrQn
         D2IKYT33jgZWEPX9mqsvauUWDcRRrYkhzpnyfkLBWa+yZ/yCh9rif74KD/4CtyKJWVaw
         Foep04dsjivH1TFWMp//V2AeM4ZuNydzqodCzjTyzyUvNNoRm/HHo0TjBZZORF6Her80
         emxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bM3QQCjC;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id t18-20020a7bc3d2000000b0040d27e9fb0bsi512016wmj.0.2023.12.25.09.25.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 09:25:18 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id DC8B0B80B57
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:25:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 69EACC433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:25:16 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 530D2C53BCD; Mon, 25 Dec 2023 17:25:16 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211785] KASAN (hw-tags): production-grade alloc/free stack
 traces
Date: Mon, 25 Dec 2023 17:25:16 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-211785-199747-l7nUWMzqPf@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211785-199747@https.bugzilla.kernel.org/>
References: <bug-211785-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bM3QQCjC;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211785

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
#3 is partially implemented with the "stackdepot: allow evicting stack traces"
series (will likely be merged into 6.8). To complete #3, we need to resolve
https://bugzilla.kernel.org/show_bug.cgi?id=218314 (allow bounding memory usage
via command line) and, optionally, implement the first proposal from
https://bugzilla.kernel.org/show_bug.cgi?id=218313 (reduce memory usage for
storing stack traces).

Before considering implementing sampling as suggested in #4, we should
implement https://bugzilla.kernel.org/show_bug.cgi?id=218312 and measure the
performance impact of stack trace collection on MTE-enabled hardware (e.g.
Pixel 8). It is unlikely but possible that together with some stack trace
collection optimizations as suggested in #1, #4 will not be required.

Another potential idea to consider for #1 is saving stack traces directly into
a stack depot slot to avoid an additional memcpy. However, this might be
non-trivial and will likely require reworking the locking strategy used by the
stack depot code.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211785-199747-l7nUWMzqPf%40https.bugzilla.kernel.org/.
