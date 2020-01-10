Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3EO4PYAKGQENGRRZGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id BAE8F137660
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 19:50:20 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id f18sf860470lfm.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 10:50:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578682220; cv=pass;
        d=google.com; s=arc-20160816;
        b=x46g3qKHCBWZdX5Xt5lr56Z3NnBNkNN0/TUD1Dyt9Z8XrWMiKkxb9met7aWeu26D/O
         +qN+4LDJ9r1jgQbgGHyLFRt5tPZb+7559bu/Ks8+2uMOoVpuxdF4D1yRTczwIMrZ5e+l
         z0gktdb6Y/rsTqIXuesE2Jc4ROy2ontOJZdWurDWgxZ16umpqLt/PpYrhRE5SFG1YbG8
         cYQLq+bSRaUXgojw+AyE7a34wKq7bXklx2wCtH4UmqI1T3LpWyYlUEPRjmPlc2hEdatf
         QO94ylpAtfeIkilx+QLkBl2sDCnsJ5UfoTLT+dPM02fFtTOSHxZwbwfvDs8Tp1Te+KP0
         wOqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=FnJy9Ubq/eEAioeNbEIeIc1ItD3c0otYuFN2uxN8734=;
        b=TSDFqzeTm89deQ0ZuXWe8myb5i9gWjPRaYCLkOEKru6e0uN16rU4Pr8OFMzTtnJOb3
         CDe2aWpqVduDhq3XQYHQGZhPbC+4lI7XIrVBm8y2C6uT0QGPS2D9DI8oZvTQQBDdoXGS
         nIlyeI0O8EIziOzZ4eijE45/mph1KCBiw+Yj4XqiOE+Rgnk1bN/Nsb7FCnaXhvfBjFct
         KdTSAozLsEwZ6Evca+gwRuBsTsqQFxxOUcJ65S+JKJA5zDPypqRviEB5Jm4Cmqq+pGu/
         tewguVfmGMC9zfq9kpAW8EXUG7t8yjjPOwBl7rqM8sbHcBJA3TY4GqvQsiKfopX0g4cX
         YcaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VACd/K5N";
       spf=pass (google.com: domain of 3ascyxgukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ascYXgUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FnJy9Ubq/eEAioeNbEIeIc1ItD3c0otYuFN2uxN8734=;
        b=ktKUnhHYIUFpYyuktDY3n1hZ4plGv4jzCFdGIy2ORCh6YcvDOi4WuW8As+SP9jgdwX
         GXNjguD1Y316Yeez8gy2yedzDGETZtzGEUNk1B8QH++iOD+GlBDKJ2m6tDxLCSs/H3qy
         e1sePr7dVeoHOydnzDW2n1AlzfRw8jPT/CTZhZEXDjs7h7UqVkpFNqGNG+otogJiSxvu
         St3cYfzrthYR6cBSFAI2dK/NCisjR6Gi4mZIZx9kicPZlQ3sjysR93PR82ApNRxx2OyC
         3XWx/Fc6C90lQKCrYq8O/YfjQFxTGC9efhwkEaR9+dEw9EWE8pimFsQgFHDeqLoH2zYZ
         G0uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FnJy9Ubq/eEAioeNbEIeIc1ItD3c0otYuFN2uxN8734=;
        b=e0EAhWP/zUWkqIlsDrRxpUhN/M1EswXGgTxm6rXPLM0kK7r3OziNBMdUivzGyBkCMF
         tfJa6VTlydoehb20QnPYtwwI3P4vXZVb/Xtcf5CHRVdsSG9a3cgkA95w98yPEPpTSXBL
         3FPedxBaoTY0bje6YD66mMpZX8TKBMJ+afxQRbPLeJfg7tCy5tB/z7fcLTLub600nrkW
         Tez+zzLp+kxWsDqLyEyRbnYcJEM65OAuz5BjbNfdq4tWzSNEdP7YwFNd6X++UcjfXzS0
         RcN/nH9GF1xjl39VBedtgD2zNc1Fxu/g05JQIfXiGHou0Ozst9OpjTXH7dhZWTAlUkHn
         cFQw==
X-Gm-Message-State: APjAAAVYoHRfli7to1vYq+3aJRVPY/ZVTIy/fRnh4psv6eBHG0yh+tKr
	pkUjKxkgxTHm3Rf9u6coCMs=
X-Google-Smtp-Source: APXvYqxXsmIqLf5AKr/tPC7xvDQd+zOW9/oihpkgxsz/2QINj912rV1JJoMifO/Do3P6h0CB0mOIkg==
X-Received: by 2002:a19:8c4d:: with SMTP id i13mr3228662lfj.42.1578682220320;
        Fri, 10 Jan 2020 10:50:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:2247:: with SMTP id i68ls609111lfi.5.gmail; Fri, 10 Jan
 2020 10:50:19 -0800 (PST)
X-Received: by 2002:ac2:544f:: with SMTP id d15mr3389195lfn.126.1578682219648;
        Fri, 10 Jan 2020 10:50:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578682219; cv=none;
        d=google.com; s=arc-20160816;
        b=ZNVUcqEvywrE7ISi89wfI1edKsaJppwXxCWo3hiAY7x4NTNFxdgNc+2H5/kQ9gwmGV
         hykqARS8jkTQBmfQMiJf24s747+5t1WexpQ4+XKxTrBhKm2NOYx03/zmrNIFA5Y8BfH4
         gkn7NQT0eKszVPkniVu/9gHwholw9OmFII2GV8TVUifaoNCkPJwAkKw6lULuL0XD9RuH
         w01ug5cmmrFdhVi1K6NCE4KGKfAEQbny00CgPMjFAobmpsDD6yxbmuJ0CEHs06vK9JeI
         0s0gCS7R5sC18+TkmYiHLBNaWPrcLE5QfIiMknVu0uPMGEA+0aguAPd6Vuk+lrM0kKt/
         CPMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=FKzriefzB+sFj+yanYF71dYfNewJn715ajVrF6hXaPc=;
        b=v5cKnL5ps0GRzZPFBOuBmWLOlkDOSRTBuS9XksBtWJTmjictDGx2sM26UuMzF1Zapl
         oQZe8jK/sE6uhYDv7heEI6TIso/7Q+SuRbkkfKf4vSNqefAwXEgTBaw927Jb7lp5gwYW
         MTi9cSb+nVLadn8SM70eHv6fhcRPT7Dpx7+pWr73Do5cHbboTIaGelMZpUdXmUcCxrJm
         TngYfyFIkRzuZJZTaacuNc6Ky4FI44QHpsAQ+D8i0NU4dXssMU57v6C9wnS59se9TYYE
         eUJD2FtTSHuAp7HnQQ5G6dXZqUJQfhxqDdynfkHAntr0wwzG6yNheY2FFuhVG/fTpLjr
         jcKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VACd/K5N";
       spf=pass (google.com: domain of 3ascyxgukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ascYXgUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p20si162265lji.1.2020.01.10.10.50.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jan 2020 10:50:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ascyxgukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id u18so1307090wrn.11
        for <kasan-dev@googlegroups.com>; Fri, 10 Jan 2020 10:50:19 -0800 (PST)
X-Received: by 2002:a5d:534b:: with SMTP id t11mr5061885wrv.120.1578682218808;
 Fri, 10 Jan 2020 10:50:18 -0800 (PST)
Date: Fri, 10 Jan 2020 19:48:32 +0100
Message-Id: <20200110184834.192636-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu v2 0/2] kcsan: Improvements to reporting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="VACd/K5N";       spf=pass
 (google.com: domain of 3ascyxgukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ascYXgUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Improvements to KCSAN data race reporting:
1. Show if access is marked (*_ONCE, atomic, etc.).
2. Rate limit reporting to avoid spamming console.

v2:
* Paul E. McKenney: commit message reword.
* Use jiffies instead of ktime -- we want to avoid calling into any
  further complex libraries, since KCSAN may also detect data races in
  them, and as a result potentially leading to observing corrupt state
  (e.g. here, observing corrupt ktime_t value).


Marco Elver (2):
  kcsan: Show full access type in report
  kcsan: Rate-limit reporting per data races

 kernel/kcsan/core.c   |  15 +++--
 kernel/kcsan/kcsan.h  |   2 +-
 kernel/kcsan/report.c | 151 +++++++++++++++++++++++++++++++++++-------
 lib/Kconfig.kcsan     |  10 +++
 4 files changed, 146 insertions(+), 32 deletions(-)

-- 
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200110184834.192636-1-elver%40google.com.
