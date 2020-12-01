Return-Path: <kasan-dev+bncBC24VNFHTMIBBSHNS77AKGQEDNL4QBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 45B472C98B3
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 08:54:50 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id i20sf640947qtr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Nov 2020 23:54:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606809289; cv=pass;
        d=google.com; s=arc-20160816;
        b=lZS7yERfacfbOUMSAJ0oWl7JVvWgP+0eTnth4in9r2xUmqUl31ssOoVe7dnoz/84LK
         x/WwEhfCZq+kVx60vlP7xgdZusZzvX/dCp7xS7y/5R3XM7KifFxKhI/Z2efZ3rauSVzD
         LqSaQMNJyCzVYbpO8jDMs9IAFcZfXUAD6YeUXah4Ip6PibV516n/hgb8s8g8wAEhoBDa
         BCWtKrv1YRpIt7U3v6Ph6VY5B0mOQYwbRTWqPKqlLkqAHBtEZpu/T6BfUlDwlq/YmKkr
         FSLf+Pyldhpno48o0dApzKytq60JKFQp0WMGGEMp6ON2jHKNRtQZwWuwNQzqtAXsrktO
         wWqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=CMNGW4TI5YQC1zFUKqRyMNosIeGVMzKxBAR5Z52iNAs=;
        b=l4xbRSUu77Inl1pOSor6wtlKfQJ47NQCmwgYisypWr5VXjj2x/uchM/D7JNI4x4gQv
         j7FiXgo+tp/bZpB5bLtXdL0pCVjNdsOX+BJo8hD58H6iMo8rPdmiFkoT/QUXEKOlQp8f
         YRID5Az76DNkVVtzNUKma1wRM7qWJX12rYUf/I5FCnQwtrgxxgML9yInRbrHrS49bl9X
         05atYu6fnSFgqeH4n8NMJi3YUuSFYCCfjPUUPl91x+cdO34IPS2wESz5fgIkHZqODZBB
         xPIPGILzPW4hV2kcbayzCC97zxZ25J8oHxujVeIDtV3wAR7RGA/Rz2YGjIQD0kJo9ONu
         0ydw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CMNGW4TI5YQC1zFUKqRyMNosIeGVMzKxBAR5Z52iNAs=;
        b=YP5LyrrRdhj0jCYtklMKySk5wtyg7SuH7iq+ThOGDlITUOGS21D2CEu4bPo8RiZLjl
         G5tSFnXTPjTCqIem62YqJZrCEB0DFWGobSD1n8DjcIAG8zGG1p52cs93BjwK1T2p1O2s
         gKHptbhE2SQyls2Yp4G3sF9yyYLehNX3Y7xV0DT0y1lScezO4LTd9NiKBpKwhSaBKOS3
         Cq4+lZ54edvRXjXu5nyaiVoOm09eQQdUJh1rjwaW9tM0CZ0ujZfv78t8ZdLCRdLKqsbx
         /y/XMUYSzmCPjKxn95pOMohbgq9nnroR/35k5qGsI+jj/36WHWpS5jLgO3AtpUMGWFOL
         FV2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CMNGW4TI5YQC1zFUKqRyMNosIeGVMzKxBAR5Z52iNAs=;
        b=RS2Eu1scpdwJj6d/RUPKQy1ROI91pAikxTwuIawLHV1GNmajtl9mO2RE//qOQ4jU0L
         2kK9bkzkmSbrOM+BU5VfxAiqkcl5svdtBjZtxZrmZAvKCcpvSTPGLannpe9pRJbTj818
         mM7ZCn9uXgZVHotIA5qZIVqPzCSO5QkZX4si+dBzQWQmgLl04k1B3uVUB5lCnPjAm6Js
         zeE3v06KBP6GtpPiwZy7XvjKyk+fEJ7fu9RPY05phri2E9kUcY6l6rN7WSu0efpRlTvN
         BqpOfo/Qmx2MMnfMPbkqBhUfJ6I3dchUx8PgurqvmxXirr21yWmrq1VLyqewmw2e/a6z
         jtjQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JSuMXCRoWF0mQWJ3lviHIJLJ4jTr9yjpJ5p+P6lQ9oduxbSLV
	UqQZYTAsBe99x/FuuErUAUI=
X-Google-Smtp-Source: ABdhPJxlRzCxx0vR9JX+vKJ3QMS1Gby+RdmPNf9Kx8tDbRzeG6JnVpNK0n65TUVn94KVdpUyf+T+pQ==
X-Received: by 2002:a37:674b:: with SMTP id b72mr1477037qkc.387.1606809289104;
        Mon, 30 Nov 2020 23:54:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5d4:: with SMTP id 203ls570044qkf.5.gmail; Mon, 30 Nov
 2020 23:54:48 -0800 (PST)
X-Received: by 2002:a37:e09:: with SMTP id 9mr1589044qko.39.1606809288650;
        Mon, 30 Nov 2020 23:54:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606809288; cv=none;
        d=google.com; s=arc-20160816;
        b=j10BUmJDOX5mb9v1ypW4aNVpB6Zix6w5AKZW2NNYMbkqvNvVJUDPphYOpeWqgDDNrO
         2ql3an1l0LA76prWEIgXp9/jhou3hX2DQ4yluWeUMX0OlJoFo31LTGPgWjXPkF6y7xg0
         C7QAwPww/57gCFc8YlDIvoyz8lGN7TEeldJENjiA9vsFE1I/DWt5pyOdaYcAmy8qU2Kc
         ahTtyenW7ssrbdKKhYk9ctfMrGvdhJeuhDv9GjOMN6nzt5jx4WAZfS7ccwhGV3R9QFv/
         JSt3o4lJ606VZDg1VWpRVWV0ZXIjcMxZxAV05oThD4Ytx65+LUFOD3IOnfCulrne0lNe
         eyzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=WPR4x6Tbzc4UQ2teSYAukeNBsKXTCIr9z0xBnYf2Dig=;
        b=EVq7SVG+odlaushrCJ0H+7vIzjb4ro4xXaCbQJv/L37ooC7oCjX1TaqvKS+Qzzkncw
         c/mTIqoaW2xj7b9KXtKW3x6iiqN+Fk1bDB1DTGPqAFgK40bObm6t+2kEOW1byuqM3eN5
         fs+2jzCHlLhN9BAkBoYGdQgaessQZvGBTxuq+TvROOKZAEV4mZC++5YX3I83gnDky3tG
         3qua1yO+NnNUpXIV0R+Bm/n9xz8vqNTna1HnTQ4r4a3agmRPCyEaI5iZlEP/G/P6nwes
         bN50Z7e8vWSqpcOx4QfefAdhh+kONb36m/0X9VAQ53IjQP+UOLVsyouSpzQwGkbKJ+Lr
         Jizg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n21si74122qkh.0.2020.11.30.23.54.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Nov 2020 23:54:48 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208299] Add fuzzing-optimized RCU mode that invokes RCU
 callbacks ASAP
Date: Tue, 01 Dec 2020 07:54:46 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-208299-199747-Uto592T0IC@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208299-199747@https.bugzilla.kernel.org/>
References: <bug-208299-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=208299

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Jann, if you see anything else actionable here, please reopen. Otherwise it
seems to be resolved.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208299-199747-Uto592T0IC%40https.bugzilla.kernel.org/.
