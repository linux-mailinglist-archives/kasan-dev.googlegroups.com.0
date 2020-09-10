Return-Path: <kasan-dev+bncBC24VNFHTMIBBPVR5D5AKGQEID5CWYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B027B2645D2
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 14:14:55 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id g1sf876887pll.10
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 05:14:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599740094; cv=pass;
        d=google.com; s=arc-20160816;
        b=OkQekmLglgCO57+mm7pFWvooM7bGOui/qYevQkGgav7QIsU6ab6D4e3/TW4wXmW0e0
         WX/BezyNlWycLv5WNFA21KQjAGJKP4pUzLxnWpUdzIbwKZa4kWOmgnJsspyniqz8obk0
         WuamTLwQZo+Npkd2ZnQuN56Qaxjnuql7VtWSZz7q8NYg8GWlokPwU9h7nVprYllIQO23
         wr0oS2i1uqyoeN9I4zUuqrr/6mhrdx+lGhgD5vOIIUC1GuXgRXbCmcTnwVE2+6qjrEyZ
         FAS7YCbaGVYInzSAIHcOGsI+9poiRa1jAseui1yAjpPwYbnod4ohQJOC0DQNDZ6L3GKt
         aZWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=cP94vF7+KbPbQzkUnAYTaoUKAOzgrFcH3o+zaNAWvDY=;
        b=VEnlDzACAXPVkTxac+ZlglD9kg4vVuU1iO+KBZvsITZ11Hmmm/zv2jGPQrObxnAK59
         9vzAENGytxzRnFCYBWSY55ZjK+altrNQIbqxW8bjbsw3RR67vPdyjlZvBSdmIQrnBA7K
         CZYxZ5JmyTT5j8GKbn4DMC4OpJTnCdfPCEQ+idap9x5aKTjKEgkFqAZHnwoX62IFZBHE
         7YRVppH1S4Gf8646O70wY8DCoX/0Igz12i273oNAHcjqtOLziCpmTbmJ83v8i3ohSaeL
         w+/J3QrRLcrekrUZ0yYAVwAB1nHWhlgirFeaCqI71f+scuV1eByE6pWJd/aKsg5QhILG
         gwPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cP94vF7+KbPbQzkUnAYTaoUKAOzgrFcH3o+zaNAWvDY=;
        b=SZrSM+2+M02no3fQaw4cqW3EuGLtzqMNmtgh4cu4Y33bmAh78mRm1e/yg72nx2nb9Q
         8lu9vlVCb6vTLwCsT6ijmECnMmnv0Zc2yUiPdU2wh2qIi+e0pdigZk5TXjvZZ2aBSlEV
         lOpRQpo+lBzvdBVFas9daMjZIQRqKsh9wMsHtYYI7XY/juDe4+Fo60AK3qAIUmKrqXGd
         gdnYMHbOSaGVlPpNsgTvDWGgFb61NeQxWywPwGKQFrhuwk1Objk13TLAz8n5ESDzuCIR
         dQfWPB5hWLf4eVeYH1lkt/0cTVZLm+uG8D8g6qCke3fAdFAsEIO/m8dV+lCg1qPd0+GH
         28nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cP94vF7+KbPbQzkUnAYTaoUKAOzgrFcH3o+zaNAWvDY=;
        b=Y0GYoPW84JLQUhXI0fEZFDrrAKZTy4EuM9vOFy5aVpH5EPHeBNHDvTPVchb5ogAvwt
         Axwhge5MY6dRS+gU026IKJkjU4I7Ie5EmEahIxdHQExlCjELcUC45hsXQgmMoPBvejH6
         LDqJUHiEZX2tuztFuq8HFJBKVBrxaCcX41Zf67wiyQHWZqQsSWN8gMEnYRktzSMvL6iM
         mDVeXvtPZS7jWH+zZ+FzSF++P+TlMG+SJnHJi2t9dRzDh2jguMg0PfdvSTmW0hqIXnTs
         U9OK4OG03KLeqR9SCVYSRdQLvybEl8EjsRQWUdis5u8pWz2DnF8osK/aoWze0R7qj6z+
         QQSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532V9RdsjZ6LwbEDp2Bf+eIsdspozlh8T9XNS/QxlZ/Vf4MzB/tD
	QYnH4QZHVVaRv7M3Qy4/87g=
X-Google-Smtp-Source: ABdhPJxEzu6x6KBMQ4vfIGuJvwweJzw93qsp1d7zkBxTeTf3pPAOKfaeZWlE1Fer/VMvVwHgXXdVgg==
X-Received: by 2002:a17:902:ff12:: with SMTP id f18mr5097959plj.118.1599740094221;
        Thu, 10 Sep 2020 05:14:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8c8b:: with SMTP id t11ls3104492plo.3.gmail; Thu, 10
 Sep 2020 05:14:53 -0700 (PDT)
X-Received: by 2002:a17:90a:86c2:: with SMTP id y2mr5139260pjv.3.1599740093596;
        Thu, 10 Sep 2020 05:14:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599740093; cv=none;
        d=google.com; s=arc-20160816;
        b=LQkppd+Dw1TpkTG5dXlqWa/BPl58clU+mtrEOV5bXZcHIPJlOgav0v9JjDoZHbvAm1
         MINRVmiLHs7nNLDVwlbqKHc6jdXKPvB+C6gStC3Dp5LSxQ6WceDDqsJVGo+YV4jqvJU9
         wiaKqJuKfyHpOddG0pMWDzyH9AjDyz8w2KSaAJ2M0Y54psPw2Fb89SMOn4RMa5U5jV3U
         D/I4dc07dHtafW/F9V192T/IwCj9Xi4SpUrbahBSyBes2r9SzN801mSZCuEoZI4ZoTu7
         ZpV9dZWXAi75ZuwwUUUrR0t0bRhXpeNfG8H7A4I65Vu1J/MnnbWNJ5axVLmbkWSLEM7n
         EfXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=gKxswd9yfB7XbTMa43fw8fmzbvlEI6lKPL/ccBqF8TI=;
        b=q9MuyHx8KeIFWs4x8osef05wQZan23R58j5mRZkxTewRpy6nQ5N+RpvAzCmuNlAYcy
         xJMXOW2m/nxFbLtVBBORYE2sZNiMYrttcGUFkan+9fHY/OrEv/tzEPrsRHf6q3BYn624
         7drJwTzdT7i2fF2K3XLcoNn1SaetiL3VJlVO3G1lXs7Wtu/kY/LyreBSE6CSNDpcjEEg
         KgjKUIj2QMmFSV9DbFCbysJdecawZgVLyXaBIVDAwkww6fVVoI1j1b5Q8PWPKj6DLaWF
         E2vkQihiHiuTacw1RdVTtJuRiF6LNqoKZxMa/R3lxqdOKXLAaPybfCGrFhRG4SdFHf1k
         ijkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v62si298913pgv.0.2020.09.10.05.14.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 05:14:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] KSHAKER: scheduling/execution timing perturbations
Date: Thu, 10 Sep 2020 12:14:52 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: glider@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-209219-199747-Lf22PUeZp4@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209219-199747@https.bugzilla.kernel.org/>
References: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

--- Comment #5 from Alexander Potapenko (glider@google.com) ---
Could these UAFs be detected by KCSAN? Maybe we could bundle the two, as KCSAN
already instruments the code?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747-Lf22PUeZp4%40https.bugzilla.kernel.org/.
