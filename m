Return-Path: <kasan-dev+bncBC24VNFHTMIBB37I7H3AKGQECLLYJAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C24F1F1E4E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jun 2020 19:25:05 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id p19sf12683430pli.23
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jun 2020 10:25:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591637104; cv=pass;
        d=google.com; s=arc-20160816;
        b=M6DW9F/JpkTf0fw94zKrVpE3Opd7110G1IS3HKWCiRu5AkUpOcsg9hONOdiphndnsR
         lrS3iJoCGtfQFBNhj+nq7kfrBKIizvX4GyvfPwe1o4RnrnPhMcUWH+dbJlOMSlVwg7UZ
         PRCpDXllhKKHa8n3TVbs5QjdLIzjfJwgJjpNhQGD3HfY0QEXPiIgNPmaq21RdUDWEHRR
         DCsZbzBGI4nc01g2Rlj8mCKZ332SPWByzbVNGknX8RINhNnmQUUfvbuzm/KW3lPMYq/e
         yUjoYLyLbL8E+3iKROh2jv0kPIOb7nb0y7ODLsmS3ZbZGV+ssTldySIhKkO6vap1jcAc
         GpIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=LQFwqoSXR2JSk4MNRDq4JTQkEcfS/iqXTB/zh0xi1aw=;
        b=RPQ0SzEAsPxWKMkirq+IzwbgOMORl4GdD+/0E7OQyDnhGJs3AHeFSxL1hGZ/GI7Nqf
         fuNJ59JneLG8wJnCBM+eO7CoJOPDnJbyi6xvX6ElL2Ffynr/tRhOBXYztfK7nsN/l3ZR
         4zgh/E1jSL0x5w0hbBLkj5cOwpCcuLrA1YDHBgZC4fYuZ7Tq+PQ44wPyhW6+eAxiZSuc
         N1fqluOBsEWikRwF8p3s6G3XI9akKZ6hgIbnoQTO8Z9WWW2cG0eSWdurXSgMvFxL5T2J
         CFBke2WBBysafGCdiMNWg/Wn5BAXbOIA8PqEFfyNQS8Y7vOHCNforXv+Xw4695gJkRC/
         FXUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ngkr=7v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NgKr=7V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LQFwqoSXR2JSk4MNRDq4JTQkEcfS/iqXTB/zh0xi1aw=;
        b=sHM3XQgX8jUnAyEzaWjWoIe6LVcz7I5THj0yr00eoxhNlqBknePp9yr6KRorn+l0pd
         zxo/PvA6IOySuxMYRtZry8j4OAnMufTuXpU9BXxnVjSb7FWqXUs76y8z7cxZ9ejAn0MX
         BD/in45mQ0zT+vfajcHu8r4sXZtURLIov7Yd28XS7SVn0XJnl64IEOZufQQQDbeH1/8V
         XRCvD2b8cN09vBZl9k4jpLpcvpHz+BHGkQ5RBTQBCfj42s9vxXzh3jOGnqdUFAllCY0m
         KNIZecwbCqu0vuc98315er1tj/XwS2zKJPfIdd3WJ1zxMikmn98eDhIWGIWbgI4qxrgc
         VAgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LQFwqoSXR2JSk4MNRDq4JTQkEcfS/iqXTB/zh0xi1aw=;
        b=C5hfDlwHR7rYPgDfoAHu0lZzJXZ8BlPcP6uqa/8FE1sWIyFwuhxsk8L9Z3ZXGwhREE
         du2y5AuTPUFM62wUmtO40Um4g+eYNxwM2BcbAAWqd+0MsTKQurMhwgZFd7dnRVaEBGQi
         5kh5Niyg6inpe2NYV5mDhEbc8vCfhpYUJqO7BNm9DZj4BT+v/a48Wuu9DgUlFVi5i4xn
         /Ka21SG29X1pjnRL98DDhBSDCqr/6MGEl/hGXCQ693TWF/f1l31OiS/ihOioYjjcyf2z
         09tK0EoXiyfObBYFxNRyQ9tUtTseCBIY0su1tzYJxPEYqfD9notlmGOBqUTFL/tbkeQu
         K0zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531x2EByKquTi68NA5zfBhej4sQ2ySRv5SlQrwvPVPo+UEB7mb6B
	YuPhsrzKpJ0QKyTyvkCZp4M=
X-Google-Smtp-Source: ABdhPJwh08bfzM8dDUk3tOgNHjRFBtwI74e7Zg5msVK/wE2wwE52RqQGPsl1vYWjPRQd20wXgU2HEg==
X-Received: by 2002:aa7:9af0:: with SMTP id y16mr23171376pfp.231.1591637103885;
        Mon, 08 Jun 2020 10:25:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:718c:: with SMTP id i12ls89544pjk.1.canary-gmail;
 Mon, 08 Jun 2020 10:25:03 -0700 (PDT)
X-Received: by 2002:a17:90a:36cf:: with SMTP id t73mr393686pjb.100.1591637103466;
        Mon, 08 Jun 2020 10:25:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591637103; cv=none;
        d=google.com; s=arc-20160816;
        b=Ea/hlwppgZVUE9f1qqNt+cUH97U1Nu3MeYt7pr5CuImg9WUmRkUNwSqjApUrYBJEYl
         Fh+l8LrL7QkZV7+6nVtD4BWxtA/c0cORjPbEM62FF9kqOmh5wYYl9xtU31JSSQP7o6nN
         3W09XNPQObJfUISSjLJSF3ntLHvLZikYH+my0C2n7bx8oXKTZu0rCsTpQHcJZO0DhBiY
         To7tjw1Z4Nwoz9O73U1wttUuJg3UnmG0TtLAJL5C+qKbNq0H1Zg/oi7k98dW8I9lYk9l
         4IZd23YGgMmwnW4OehvFRyV/EBE4UkV26WQLblSvJ8Jj/HXYTbdhMFsv6xZMidcGGfmO
         INdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=3Y9r19ap9POroauwGEY1nEBG7jMQPwsMV0SMWaBH3os=;
        b=lZOdC+HVUwheCUEJqXAuWmOx953l4s6F8JwL1f7lruYmGQIAJWeCOmjcvKFkrK15Jp
         r1GyN5O0SAaA/LadMMQ54aTKvn4gFxra+7I8N5Xhp9jhCi1iPrILvZzh9zRGUbWaz4sF
         Enj6jsBB+pkxlbo9sDq8SE1net0D4Ek75CdczMnHKXdUlZhf0zaRD4kIn7rtzECWghl1
         j+Lgwq2UGDVt6A6apeM1OCNyZDmc/NbDjmxVEztq3NrNVbhjNIJkYnjcCykv8duadq0K
         lAdzNHXxV6481S+jp/aXWXyuzGrJO7Ch8TH+V0DG6bwqmg8evzf0QC1uUZj3w665BDCD
         WP9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ngkr=7v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NgKr=7V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t72si357677pfc.5.2020.06.08.10.25.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jun 2020 10:25:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ngkr=7v=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Mon, 08 Jun 2020 17:25:02 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: ndesaulniers@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203493-199747-snmobh1ZRQ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ngkr=7v=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NgKr=7V=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

Nick Desaulniers (ndesaulniers@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |ndesaulniers@google.com

--- Comment #8 from Nick Desaulniers (ndesaulniers@google.com) ---
v2: https://reviews.llvm.org/D81390

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-snmobh1ZRQ%40https.bugzilla.kernel.org/.
