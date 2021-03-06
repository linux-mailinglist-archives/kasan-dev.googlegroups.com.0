Return-Path: <kasan-dev+bncBC24VNFHTMIBB6ETROBAMGQETOL7SHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 866B932F72A
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:16:57 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id v6sf2568663pff.5
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:16:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989816; cv=pass;
        d=google.com; s=arc-20160816;
        b=qOwtN9qgcKKsFfaC4riEJghwzPBoLd6cI8CuLZyAJdCPBxhnsEK3ixMnDtsT6riuKc
         CP08XbqwdJThV/EaktWyYtJ2Q2UrQ7I9uO9kPgFRFlJ3rKRpf34jb0xG7ZZscYPdon53
         Q4OEKqxZwOOiN/ShDnwWbhWTWmj16Z8W9peMjAD+99qihR+UB924rX4hl9Cp3ZaEsaRT
         TtGpp+/TWZCkaeXCi4Z1Y5d8D5zfOTHX0YEM7JtC9Mg41e5wJyTPvl9frlVdw+gzA8FU
         s5pF9ZrVwJt5LcOxAeuWE3WDex4arkfxWFXT9jdqOesVohC7NCuOdMAPH+OvJuZf8dYj
         H0iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=1uAS9e+MRpN56sr3EdcuVKWrphHP7MWyQZH6kMM3IAQ=;
        b=rmGA1f7Ab1ALQ+MprayZOSayBKWwnaC1ZMhoHak6XH5Ad2Kx66oxZzODzOm3I7tVZ6
         IDtbpHEavvwBesqyubN5O+s98urveQ4QHatPCV4/mazOMaV6G1+IjHgBkzHN4Mtro1PX
         Cb5BhwsOcS/qhhDJqAgoK0t1ua1n4VwnwxzhqbuZ3EpMdTStz+iyynh4+DOvDrq7qTv4
         NoMk/OSXx4YQCh1LcpPd0FN8kziOe9jr+yDmYMmjO5Xa/UUSWGjKayncq0rzW2ERbHff
         IVp4KgkLZwuqsXr8xwh3Gxg5MgBJySOV3hkD5Re+xovAzhj8kgQO/0Smb/HOR4wpN8sb
         6iVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PAZh7nLO;
       spf=pass (google.com: domain of srs0=m6ut=ie=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=m6uT=IE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1uAS9e+MRpN56sr3EdcuVKWrphHP7MWyQZH6kMM3IAQ=;
        b=eErLw01u2NJIwG8NaXGvajAsed91D1PVET+/LK1ai76wjIO83poCUl2lO4mM+Pen7u
         pDY0Guyb0vXpqp0CmkAAhn0u5CHTY62H2MlkYsN986S6SdinBqtOLUjQqwPOGZ18PZta
         XmBmi5eVxlLwZkbL33Z3EngZGwlQaIFQPhaEnruU1P00137cryLJRWzVBZtm63MGksKK
         sbyzF8/zrWNPCgm5nQmxCOyac6a9/lqP4rfMx65oozjwZh+dtmJMSoKv1SZ+YuQkgqcy
         6eMEhRSUuDmK52HGWGSn59qZfT4jPiRTDYWzT3E7Bq7IuMm9YEw5mKvkvvSKjFLWLTrz
         vplQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1uAS9e+MRpN56sr3EdcuVKWrphHP7MWyQZH6kMM3IAQ=;
        b=aHhivuN//3KpWoAfyzenpeSUMnAyVeiU8tSx1EZ6joDzc14KakxZTNlsFVGTvkLOvY
         NXpOrU1rqTRJF4FTVgqSvMq+GqOk2fhuIbQvgtbsxWEYnwht0GPUxqfEyusjdFRm5sR+
         ZwhmDqboiChvhaclu9VHwUBN/FYWbtAgb/8MsQHjo/3Y2RKMlSuBy8ROoBveJYI+YeUf
         epSSdLQX+Vg7oyk8+KM6jAhzehv8kqktH7+OqDdLOOnm3gkP1nBS7Dc3KemEgMwcdWCS
         /NNzxmDOjg/1h0hNvFWXwHGlfTxhcO3MYeKrGtRzSY8nNduv3rttMVbh2ARdRWj8hA1P
         BKHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zZ5AexGsUkQHKcvAv5KkgIWCXiG8GfkIkFXvKqJYKF/nF61cz
	TOk3s6CafUCCR44NjRJFXk0=
X-Google-Smtp-Source: ABdhPJw16Hq9HRKUEQcIZL9a7WAOhNX+aZ0MZXebS0nDkn8EPt9otpLBPusbPx0D/tu6Nr8MSHq8JQ==
X-Received: by 2002:a17:90b:a0d:: with SMTP id gg13mr12386037pjb.29.1614989816342;
        Fri, 05 Mar 2021 16:16:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:ec9:: with SMTP id gz9ls6237647pjb.2.gmail; Fri, 05
 Mar 2021 16:16:55 -0800 (PST)
X-Received: by 2002:a17:90a:5d02:: with SMTP id s2mr12424059pji.149.1614989815331;
        Fri, 05 Mar 2021 16:16:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989815; cv=none;
        d=google.com; s=arc-20160816;
        b=e/O+RSLJPY7Pfeq6N/7YEXFqJzpeHRM6aBLMchwMNsImLp3Uforjg4oeMktP/9QWuP
         PW7lYwXsrQpEdxN1H+TMcpapMlClbpmWo+Zl6m2FlpzpWh+Qv3GzkQv+SAR3pGEwPrtJ
         Ou3e8pLsoPrkwDBVUWo6gzoMvMf3k8I7N7dxqVqW1RCkmjPT5CAUwtn2WbBeVAcGo+h8
         B5YYnTt/RRUaz41FOv0BnF8SAOTSz9UcEq5w3o87VCoGsyMIIpQeWre5UFS4K2med3cP
         57d0dEx279IYPgwyK65fI8qqvm1Uuxq/Ut04b5jwRSnsRLqxURkHvSv7b3AXnalIBoGi
         VvnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=5GDgj6p2saIMBHefClaxUxXMPYi5T6gKlXc2GNSZcUg=;
        b=D8eAJlFabRTEm24+Q4tYiFa7BkEzp5cbSqpymSE5vpQN0MmpOB7xq1+7NexqXZGnzy
         LSFiHuA5Jk8e1B8TszgfAnoDd6swEse0hYWptrc/Ob1bcVosQwZxHRliB1vzah+n27Xg
         7YdQwVXtm2Ye3/Y2+gb7kDPn4Itfg+al1TdERH1Lz27RDpvpd+SVfO+NMuCN17R109YW
         qrn36n7Vl0qw62uAtxmwOQ0mk+dJJJSEir8bftioyLuJSeq+3D9jyzgXQvXVs13BkCuE
         UMglDgdS7T76m/AVi03+7rs3dc3LjKf9OClKQpuRPWIJz4mrEE2s+QEcci0XejhaM40Q
         o5UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PAZh7nLO;
       spf=pass (google.com: domain of srs0=m6ut=ie=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=m6uT=IE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r7si1544573pjp.3.2021.03.05.16.16.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:16:55 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=m6ut=ie=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 062176509A
	for <kasan-dev@googlegroups.com>; Sat,  6 Mar 2021 00:16:54 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E9AD165307; Sat,  6 Mar 2021 00:16:54 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211783] KASAN (hw-tags): integrate with init_on_alloc/free
Date: Sat, 06 Mar 2021 00:16:54 +0000
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
Message-ID: <bug-211783-199747-Noo5NQbIj6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211783-199747@https.bugzilla.kernel.org/>
References: <bug-211783-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PAZh7nLO;       spf=pass
 (google.com: domain of srs0=m6ut=ie=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=m6uT=IE=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=211783

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Patch series sent:

https://lore.kernel.org/linux-mm/cover.1614989433.git.andreyknvl@google.com/T/#t

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211783-199747-Noo5NQbIj6%40https.bugzilla.kernel.org/.
