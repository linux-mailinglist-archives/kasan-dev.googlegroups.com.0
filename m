Return-Path: <kasan-dev+bncBC24VNFHTMIBBFV773ZAKGQESS74I6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2818F17906A
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 13:31:19 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id z24sf671314vkn.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 04:31:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583325078; cv=pass;
        d=google.com; s=arc-20160816;
        b=A5T9Qzkfh4krPC8Reeq4yyKIai7JqCGZ9bWRfcWeMwWFkX3Zab1dgMDEsVgmaB1eLm
         a6kurtn4k63knvvSFUlmSCevjY8Ah4g1d1rmaCdMHAI7gi2DlFe6paddN44UDBcnmqyZ
         gvgHo4IhdZYaO790mJz0PLb8Xqw05A2/eDwp9lRSXzEPw5J4VtrEJpA3Pcqq0CgSlW8V
         lDPQGPsssAHyQC+GSS/RRPyRehnVKqUjaIo83J1JojWtxjv72jCTIFrugjBntlrOX9ow
         99zxI9XjihJsgju6kp/xp+/u0SdJzOib9LVXej8snesIKReJRlMkRLmhyyuI1U5D/BkS
         oFsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=pPa+U4aiXB47GFCkgTmOJ8MJzOmBTRZuYtZS76mMLRM=;
        b=Edx+zD/E4phja9tgH0ocHg+BzJsOAo89VbK/XNwmJKpj6fme3+aP/XFUbQS59ydaGR
         3jgN3/EKnpJjcQ40Rtmw6EYoI7j9oXiqxF/iNj3+YXPX2TI36EHWat/yXK5iiMf4OgeP
         Pt9eXVqtQq9LYiQdORB2XKrqpYPqJnGpgMwrq3WjzqTbXs5/Ht3JKp5iCT4fq84xjmL1
         SQ3Kq8CdCsUWnCozSl4j5yID7zEYrBceWVHgVxj76Q8WtLqWLZIlIDveyQfmN47wpcJu
         YGRE6exw4CBQ9tRzmce7Q/HAAHBgKICVrr03zbAnhAtcRGiQpMDC8OsXhyZ7jlnJToQZ
         u1gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=gitn=4v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GITn=4V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pPa+U4aiXB47GFCkgTmOJ8MJzOmBTRZuYtZS76mMLRM=;
        b=DY4Y+HZhFTdmKD/zjKYVYB5cLCO4qkJGPC3HiL1hRXEFki3iCZrME3t+rDrD5Lj13G
         pSpRB+Uz3U8rmlkkBACYClO949f6sWoKTMpHDC2pwW8KRl4u83AUqgCSX20YxvzlFYFJ
         /QWBFibGd4d59GH4aHTWhO4gYTPWxj1P1WMzaLdJOy6kVphqy5uBikhDZjdJfXQsrwut
         f3SUfz46EjFHxOZC4pHDVeo63DRg9zjln2jOE92h3UCeYa3mCRkJQPVgy6S1ULgxe6Xx
         uHDlVvdmcLV5Azd+Ta+9YqMT7Xnq8VsCOSmV/Wx12AqnkO98LLS2KyeZtJnPQwJFF5NM
         lr/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pPa+U4aiXB47GFCkgTmOJ8MJzOmBTRZuYtZS76mMLRM=;
        b=G1KxiX7IEXMP4Z3hLq+t6YRS+BdPNQ6VP4NWBUzu0YnEBjulxmZhhPVbiysIFA3tgP
         C3tZZ2GhJTdRkrNQYFQw9zL2CmjJQdS7BwmqFrbSbWgPRGKqfne4LE6e23Gbsx3ou82Y
         /RzCVnZOv2b1rAfFL5BRFy9N+1FMvjKmFEmW7FBykg66KTbKG5YSathUmA+H1M0PMenB
         R9NElcpzb7ycmyfFfz8R7ZocoU200+A526oyy5rzajuIcAndRvTumPURyr0fP4/pqYhW
         4KGDmN2hhfRMwsz4nidnjamlLWZtQNniXHk/QZ1BJpnx7ia3OqOYDEF+tv9z8rC0HG8G
         zMVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1cWOei1Z2DxB/NyrkLrr4ODTUFknZ4+c1fs3y08vo9/TaYmGyx
	HUSzJ/UP0B4l9cCKTVqYY08=
X-Google-Smtp-Source: ADFU+vvBlB2FPfxNtDFf0MZB9n54xlV0hQ0/HGoUHJcyCNnQkSG/tDoEQRMDEAkV4fdXuSLtqPcz5Q==
X-Received: by 2002:a1f:5fca:: with SMTP id t193mr1238300vkb.102.1583325078062;
        Wed, 04 Mar 2020 04:31:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:352:: with SMTP id e18ls223302vsa.7.gmail; Wed, 04
 Mar 2020 04:31:17 -0800 (PST)
X-Received: by 2002:a05:6102:112:: with SMTP id z18mr1485052vsq.151.1583325077605;
        Wed, 04 Mar 2020 04:31:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583325077; cv=none;
        d=google.com; s=arc-20160816;
        b=PZlXZ0Uz87dHVElLPRsgL4MtZY188hc8L7i7SgvfDHJrf8+GO0J/upN9qP42uTYvJX
         ND4x9ye4kaHL1FAA7ITBr/np3AaQ1SxJrQYeDivKcqogp12OSG0c4tykKI4iJKuvnn8e
         uqS/b4YPJgJxKHK1lP8XzetKIKFIqMxrvxoDTM4aWnV1RFAB5MfiYInUqHWneZXWMX7r
         dTerpl/3YiMz1O+tSFzwFIa4t2acAbzYgtQuKRJ3z83iCxBkhiJXUdtFrNbFXlJxJLdJ
         j5JZSFLIb7SLUC52R7YXggMlGPAgpT8yhuVU+kQUbLNa8+52mlMLIyl6CsUzOHh37OeH
         +j3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=17RACcEYNFGg88RdhGRxMF6HTaeX8FcHO74wj9EVp0I=;
        b=j2RIBnSURBY3zqf5PpLiXbnrNZ5ijHPyOelj1StWJ9kqLtsRKQVj1B2FASUCIlXqwP
         DS46yKrFc+HtAbv258nO0yW4RV6SOkVPjAvobGegTNi2BBM0miqPPY8nOZ4W/ON2/gXi
         p5zKepaFEkk2+FQM5lXvnzYK4mUGYaul82r+eLWAkmcBdRuOJqRP1rDoLtRuxDjtrOtW
         BvJ8g6xCpEnl+TJA4Un5VbUan/OQ6CdqA1SgrtH2Ebpn4MJHnUN7R5rYi9wn7cvsyDLX
         yK8umugDFieo3mKmjcyaoyZ7BOoBZDZG9+nToNgALRel3oK33NWglepX2ZK58z/9WDI1
         pG1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=gitn=4v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GITn=4V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p188si80491vkf.1.2020.03.04.04.31.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Mar 2020 04:31:17 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=gitn=4v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206755] KASAN: some flags are gcc-isms, not understood by clang
Date: Wed, 04 Mar 2020 12:31:16 +0000
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
Message-ID: <bug-206755-199747-TEol21KlYa@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206755-199747@https.bugzilla.kernel.org/>
References: <bug-206755-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=gitn=4v=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=GITn=4V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206755

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
On Wed, Mar 4, 2020 at 1:29 PM <bugzilla-daemon@bugzilla.kernel.org> wrote:
>
> https://bugzilla.kernel.org/show_bug.cgi?id=206755
>
>             Bug ID: 206755
>            Summary: KASAN: some flags are gcc-isms, not understood by
>                     clang
>            Product: Memory Management
>            Version: 2.5
>     Kernel Version: ALL
>           Hardware: All
>                 OS: Linux
>               Tree: Mainline
>             Status: NEW
>           Severity: enhancement
>           Priority: P1
>          Component: Sanitizers
>           Assignee: mm_sanitizers@kernel-bugs.kernel.org
>           Reporter: dvyukov@google.com
>                 CC: kasan-dev@googlegroups.com
>         Regression: No
>
> scripts/Makefile.kasan contains:
>
> CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
>                 -fasan-shadow-offset=$(KASAN_SHADOW_OFFSET) \
>                 --param asan-stack=1 --param asan-globals=1 \
>                 --param
> asan-instrumentation-with-call-threshold=$(call_threshold))
>
> This --param is gcc-ism. Clang always had
> asan-instrumentation-with-call-threshold flag, but it needs to be passed with
> -mllvm or something. The same for stack instrumentation.
>
> There is an interesting story with -fasan-shadow-offset. Clang does not
> understand it as well, it has asan-mapping-offset instead. However the value
> hardcoded in clang just happens to be the right one (for now... and for
> x86_64).
>
> --
> You are receiving this mail because:
> You are on the CC list for the bug.

+clang-built-linux@

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206755-199747-TEol21KlYa%40https.bugzilla.kernel.org/.
