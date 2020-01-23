Return-Path: <kasan-dev+bncBC24VNFHTMIBBPVNU3YQKGQEZQVJSXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id AA4F514686A
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 13:51:13 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id k16sf1256168vko.11
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 04:51:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579783870; cv=pass;
        d=google.com; s=arc-20160816;
        b=SgprbINTGvO9V41r13Aj1wj+AU8WZqjwWCjeTSykhRRCAWD17bemv6RHirj4mZHVUa
         af0YBkq2RiSQeHs+BM+eKWo4X6oBEE/nZpwZA2/BdaYbJ6ab/xpO8TZZWBLx5qMfa7CI
         8ZZmbTAqYrvKB+oyJqWvj5UyyMwoWB+FRtAt/G141lforH/jWmQpDw90yEij2Z78StAw
         Cu2yAGOHqBQtbS5ovHH3oq+CT/RjP7HI+v5i6pKLpMcTRtsfgUcV6Xyq3gLFRbd/viLl
         ViEkJybguPCjPCdhnaZKQx/loP59BVgR2NKsladW+2JdeJp5RqoGqLRPhQ2TJdXp1Wmp
         S0BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=cr575fnqoHe45ZNu1tWIQeAYjCTzlyBAcosDiw/3v+w=;
        b=FdKJeCDaOibK7MVzvZPesMKdoKFBBawbowDmvfsMKMWLf0u+N+5yTfjSW1IwFCb1ez
         a3j3u77B0rSjmXlQN9XCOc9Y425jdLQhQBk6RMC8q4OO33b1tcSS6+K8tw4Q4XlLg2Fc
         hS+J6S7+v2uUKKcFrO36Oz32fFEZo7E/JEB7avhLUmQ0xxJSRaG7qQ35JEUhCzQXvZbb
         8NZsuXTdgLki4yEMK65FjC99PtNfFZmO2SMR6xAOq0lrUehUHhxkIgeT1ww/3Hu+3QdZ
         lzf+o5DjUcIWK7hyoV1wg0d2Nbh/KweRHIEo84wajnW8qNRBfp2dhg3lfRKYtv/bmeyI
         SPwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cr575fnqoHe45ZNu1tWIQeAYjCTzlyBAcosDiw/3v+w=;
        b=dKvTN2zgA8r2k5YUfY3NrWl1TIGXHNqftJe3q93iKTUN0d3dBMnjdJMk5W5j8J5kKu
         +c7gUr/ZJWfU5XVLMJy9qVoGI6L1SHG8FTc9BWeqvR/F1gL7g8shnMAhWcfHbvUQWvLe
         itbtqNvJe+1zjDjPY08Bo4hqy2U1is+MkG0HxFDdwl35QaG++z646IAzdgmR1ZGgu8mi
         CP+t5tJiTKt2/e3iS8vUtw6FRELSIFE+4nlcvdCcUS3jCEoROeoNzATA9NXJ8qMoRTeF
         cQm1uyWipphst37sSxPVPzadtRK7Uv/iXfYnyZvyBVqN3sxhx2iYzW4xX70wm1yoJFOp
         XWDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cr575fnqoHe45ZNu1tWIQeAYjCTzlyBAcosDiw/3v+w=;
        b=DhbXzKwwY66iYW6jv26fflLWFMeetUw5EBaR9B8WQtKqJazNDu0adR3MoCf5m30CTi
         i9nT5tGv86QweFZt9e9uKVyNVEi4as4PhLIH9uj+bKqdbPQi7/ibwWik79XDS2S46CH8
         Q5B3GSlbAXKG6XKoY4zadEhvsihQ6hS1z6bu2NF5DcNDMpP8VKC9QnyDI3uRLnlhhbIk
         D2x38XIXsWFf5wjZfEOZUTntqhbHl4NC00Dx4yJWPM/j+JAUm1ElDye/UsjMC8E5diPA
         zaQkgtPk5URi9WM3PdZ5ngHe7gSBsY6NJFS1N1KV0c8sKwdHLzMv7f9mol/moFNgvlxd
         O4ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXWKqQUmNNKHg3PmK9nvMrpogkdWw0Nn7qp/zynoHfdfUIica2F
	8lPnp7F2hVP0JddlzPHrEt0=
X-Google-Smtp-Source: APXvYqzhJ+MGIVHdGe4eX011HQrfk5LUkW9qx5H4DH/QlTfDtdOlu+rhffuAkpZ7sKTr7Cl1HcyPhA==
X-Received: by 2002:ab0:2006:: with SMTP id v6mr9473394uak.22.1579783870557;
        Thu, 23 Jan 2020 04:51:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3752:: with SMTP id a18ls2497951uae.7.gmail; Thu, 23 Jan
 2020 04:51:10 -0800 (PST)
X-Received: by 2002:ab0:2554:: with SMTP id l20mr9558742uan.5.1579783870228;
        Thu, 23 Jan 2020 04:51:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579783870; cv=none;
        d=google.com; s=arc-20160816;
        b=OKTwqw+eLrBq9R//hcMUYO6bc/GsdcQ/kqUhTVPkINXYa776PvtVJd40zGMpCrSQtj
         AykCWkPIkiHSaJO6tD+7HAgtwfgPb/m93/lQ5r+6WDA64RpKAvK3kwdBf3u0Ght4mL4U
         ys+3O+6NczPWKUzMKWJh9wsEcNT4IM60iL8WRIR2+6rM0Udtg+qysC0X8D8dozJfCutl
         UgiEHbXoW1KL0mTpDEZ+DJe4wrBSR8wSEp2YOznR0NHG3LIgYCjL6x+FFGdjvpBIaDlJ
         yBN8FRP8bOV5ptTYRl0EY65j2wjE4t7mMNcAPz05F8mF6HwmSFIEjN6pVBAD9KbNk1gT
         hUQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=3aStoBP9uliftgflbUNN41Ru8754fxJHX0U/ZlfhYJ8=;
        b=El8VmNy5+ekMXPEexRmBVWkeYInD/TIs9wKd5NFfIls/AB2LTMQRo/EZ23r8usoHfN
         KqHhtnxM6MY7B3ICSpCQ9bPCE/91jPTioBvhfE/lBPKWIO/I4VleJoIBKqu8Se8G4cIr
         B/J1ku5456Gf2nNQZ3bAKIniJm9yZH1HiMTYQ1yAAiF+Ot5b8uupbDa9U7otO71gAF/Z
         1MXzuBdRCDRG8dM5/Pdn18z93HU2vlCLK8S504X4qfQf9v5opB5q72vzXrAW57FEkSUR
         Pqvh/KQzI+E+QFt2BOIRBeVgjq76JXVmeRSb7IFCGzpxsdTZ6Q49+gTReM5/dc633o+j
         0Xrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x127si96759vkc.0.2020.01.23.04.51.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Jan 2020 04:51:09 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206285] KASAN: instrument pv_queued_spin_unlock
Date: Thu, 23 Jan 2020 12:51:08 +0000
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
Message-ID: <bug-206285-199747-14iIGneBWV@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206285-199747@https.bugzilla.kernel.org/>
References: <bug-206285-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206285

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Credit for discovering this goes to https://twitter.com/grsecurity

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206285-199747-14iIGneBWV%40https.bugzilla.kernel.org/.
