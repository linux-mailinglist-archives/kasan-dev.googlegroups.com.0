Return-Path: <kasan-dev+bncBAABB4XI6W7QMGQEVO7QUTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C62DBA88D57
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 22:47:47 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6e91d8a7183sf84829446d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 13:47:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744663666; cv=pass;
        d=google.com; s=arc-20240605;
        b=WE0Mftr2/vRmG6WRsqzQw8WUih90kFvQGitznWEYD26PNWYc0TZwwYJDWD8Xm98L20
         WDRuEEdzHoJHpl1Zu5RWKuGg77oyC6zmZ3CzP5CoLuZSxt8Ai7gG37wfiM8npNlWhR7F
         FAQHvoFv45kKkMBsOoC6BvxzPm2NUV5WAmDSqpHeq/n5mO/PivT1gpFcghq5uKQKZFKN
         E3+ovSQPDs0+RgyEid35R1AhkDYHmNRNT3hLkI44rbmr9iR26/nA71FUJjN0cElx8Aod
         XIab74fUbO1ecgM6sMA1lpaseCDSuvYZWR8WkTY1aJ0qgepBW/DkXY/CZfPAtBXkS6uN
         IOtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=Q61u2W3C3Zl0GnfNysPfrD1bYcNp9f4zHee7/vMwNy0=;
        fh=jzOa4B+WF+UmjAvnIfV3h3gMFGIizQNHB3rayHWdn5Y=;
        b=ZfWwRpbx/s9mD0qg2EC+iEdoB8I9Ga6Ot7bp5t718Ff0SKlGVv1gyx+bHKeX7VKcT4
         uNa42gDjj1w6GzdcMqekutXKZ4TVUsqjm0QkedBcV/4gTlnNK7PyO135Ii4SubOBBKTc
         2iYxET5DVvnX/Gx8+wJUSi73aP4nzaDOQYesIv0eexcKo9PkfaZvT9n8eQLofn0qNv46
         LWp3KUfqmSBbOETmHUUIJglmopSxrOLmwFcV0qa0Y8e5g7hsh7jyJGsGdOwI2Qs2Y3mP
         xnFg48CVAega7IDT4J/5MxRIceQAo/OgtKOJAos/RIbFrFAZ90QgA6t4a45lu7O2ehv8
         6iSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fUwLDQht;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744663666; x=1745268466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Q61u2W3C3Zl0GnfNysPfrD1bYcNp9f4zHee7/vMwNy0=;
        b=TQghp5uuwcsMTtiWlEvqtPe3daI/O0UYnJDLMfwjiqCYFLkEbMDfhWs2k06hDHi8u2
         MRF6gZYuXnea21aBf+rhUOVniWSpxNPVftG8kxCODQhrCxc6yTM7VJnRd/J3gsYDt3Xk
         37rzVEJjiB4xZ66Pr7NM0TdItlMUHHzdGl+SR9nPdS77xVtnt7mvxAYX0QI7VtzJfE1f
         +epPugKxEDtvgXWyo4JrLAYFzAgK+uzowk3BMs7jrGFW3u/L2CxkPMADY2K6kTFD/Jb/
         yizSBgeHVpK54e/11a8K190gvh0MY75/nWxrE9JkpH+wu6gCOMRr3UCzpI6F9AWEm8rf
         0iJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744663666; x=1745268466;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q61u2W3C3Zl0GnfNysPfrD1bYcNp9f4zHee7/vMwNy0=;
        b=NQxpZMgNNgJuaImzE70v0nuOCdcu1pAtjTcqs7uj1XV7qSYsqeWimTsd1VyYSA+/S7
         tnD9UmTRzd/Pl8c3oKxqNsAaZPoCKF9g3jyYileW0FzUO/iRkynvtKNZKATw/CLdCvDA
         TUdkwsF681zyuKrOyFIWCLRnWf/BcEfRG1SmkKaTDeqY4FKqgdwujs5gtodRp8ewO6lB
         jYSDMHMBz+/Jd0vz66vOkHa9aKj5SfFoKt50bdNdFrKf5mTTNwK6aHspSX57u7EzkzIM
         FUqnZ1PgDkh1uXtaQqm74Peww7OywbVn0YbuFB/cV1w7QR76DNjXNq6jqdbCRSH3/IRY
         yniQ==
X-Forwarded-Encrypted: i=2; AJvYcCWquoqGYPvxIYwEo8Z0T2GuUK0t5zIYsC2gxJkrv7mcS7po1Wwnri6m5wywxZSoGaN5oRxREQ==@lfdr.de
X-Gm-Message-State: AOJu0YxJcES3tyCsNVLtQ2tF8nv9R7/yE380qTw7+qm2BE9d6uwV73na
	znTCJNdKL3IAXKUYZaxIVj0bk0OaD66CglH5fI1JlYRAKudjNC2g
X-Google-Smtp-Source: AGHT+IGsvzd9AOZDXxcjkW2D1ASK/yooaaOxNBckZmuZUP1WX9NI3943187iu13CQyRebNs3qCp3Mg==
X-Received: by 2002:ad4:5bc8:0:b0:6e8:f166:b19c with SMTP id 6a1803df08f44-6f23f1c46f9mr168803216d6.41.1744663666530;
        Mon, 14 Apr 2025 13:47:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKibrCif7G/CZzdtAQqqi3sUctaOwrA9LQQWRV05cm24Q==
Received: by 2002:a0c:aa4e:0:b0:6e4:8bc3:c15d with SMTP id 6a1803df08f44-6f0e4a87f5dls9270696d6.1.-pod-prod-01-us;
 Mon, 14 Apr 2025 13:47:45 -0700 (PDT)
X-Received: by 2002:a05:6122:888:b0:520:af9c:c058 with SMTP id 71dfb90a1353d-527c34e40a6mr7824972e0c.5.1744663665726;
        Mon, 14 Apr 2025 13:47:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744663665; cv=none;
        d=google.com; s=arc-20240605;
        b=NtFIWqprpbvWh8zXD3JE0RbYPex2DH8TT2zdS/3CFN//Mie+7+PgOgl2g2+/BbC82M
         1NnNw9dv06eR53k3wX+PuvKMyvrPYrKZRPxlNN1fqvnv1XJv8RhT0K5SH0rpVEk3lBA6
         U1xlV5asoqZ2ridBvypQ262UYGYaw1c3R5y+M8sq5mlemSGc/MeOqkrRW+bY3c8oqAFw
         FhKUVESaNyxDNQUcJi1M+FGxvfeFEKTStEmFfDPmHkX83un3OxKSc02EEDusJA/UqWbp
         N470YkgVyJ2YNzwaRXkU0QpPBVfdq132vMEQowBlL2VJq1ycBk5sZVRBAvuBU50MnRFU
         R+kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=AtHrwyQhY1H+xm8bx44hg8o0VBs1helc8Z9hP/bx+q0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=cjV1L971EjHQPnSNpCUO6v4NXeumzIMYaY/yFmoJdub57+cEU8XaDksrgYMlX5mQmh
         U7VaHSIizoZJ5wTDqld7twgG5RZXxFhN6ZG3XOVpIzknXvQJuS5ZEYhNiTPq1Tw9BcQF
         Wq2KLjrpvx6tL/B790GpE/ZjerqbrouZhU96YMGOo/1oQ0mrYNG/X7fDN8Vo+Mq5udb9
         OZvneBYKCFvEZMxAdi4PKjAQw9iUzMtbloiORt/sZdT2LjfjkpA41ky75yALbeTPH1Be
         ejPqBITZvRbl7Pyc8+SZDuKXQTMQlqK3jm/kEjL4Fn0xyO0emPYFiA2TYVOB5mf3CzSS
         8Mgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fUwLDQht;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-527abd7b8b8si200684e0c.2.2025.04.14.13.47.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Apr 2025 13:47:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D840DA4A297
	for <kasan-dev@googlegroups.com>; Mon, 14 Apr 2025 20:42:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id EBE00C4CEEC
	for <kasan-dev@googlegroups.com>; Mon, 14 Apr 2025 20:47:44 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DF51CC53BBF; Mon, 14 Apr 2025 20:47:44 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219800] KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
Date: Mon, 14 Apr 2025 20:47:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: trintaeoitogc@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-219800-199747-QFRSqN4L3g@https.bugzilla.kernel.org/>
In-Reply-To: <bug-219800-199747@https.bugzilla.kernel.org/>
References: <bug-219800-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fUwLDQht;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=219800

Guilherme (trintaeoitogc@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |trintaeoitogc@gmail.com

--- Comment #1 from Guilherme (trintaeoitogc@gmail.com) ---
(In reply to Andrey Konovalov from comment #0)
> KASAN_TAG_WIDTH defines the number of bits used in page->flags to store a
> tag. Currently, KASAN_TAG_WIDTH is 8 for both SW_TAGS and HW_TAGS. However,
> for HW_TAGS, we can change it to 4 and to spare 4 bits in page->flags.
But, the HW_TAGS is don't hardware dependent ? 

Don't have anything architecture that the tags of kernel address sanitizer is 8
bits? (I'm newer in mm contributions)

If the aswer for the previous question is NOT, so any change like:
```
diff --git a/include/linux/page-flags-layout.h
b/include/linux/page-flags-layout.h
index 4f5c9e979bb9..760006b1c480 100644
--- a/include/linux/page-flags-layout.h
+++ b/include/linux/page-flags-layout.h
@@ -72,8 +72,10 @@
 #define NODE_NOT_IN_PAGE_FLAGS 1
 #endif

-#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+#if defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_TAG_WIDTH 8
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define KASAN_TAG_WIDTH 4
 #else
 #define KASAN_TAG_WIDTH 0
 #endif
```

solve this "problem" ?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219800-199747-QFRSqN4L3g%40https.bugzilla.kernel.org/.
