Return-Path: <kasan-dev+bncBCS4VDMYRUNBBN4FWWGAMGQEZHJPMHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2913344DA3F
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 17:20:09 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id k1-20020a4a8501000000b0029ac7b9dc82sf3212611ooh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 08:20:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636647607; cv=pass;
        d=google.com; s=arc-20160816;
        b=y8osQhp7UUd7x3OzjBKX8wqUCUCLWN2vHH7dInN2SS2BhJhG0Yknh+i+dJ9fpFoKz+
         DgfjclHoILQzRMIOggrEDVywW+mNjvHLFlz4Tl62bnEl0ia2klCyToPYu410XuDhPCj1
         GNNgs6umsbOTsQs4HnWbuCUV6K5niz91nmKpOEfdkWkTZ9o46aj4nCTGRu1T0PktYBxW
         fhrFU3GOc9SE/VUqEz6Lq549jm1KrunYJ8ny304YEeMiPZugJEj0cbl05grg8+5ehFtn
         fmOfEFrw8vMf29xtf5SSVPip5EMN44dHdlrg5+g7jFk5Of7urrCahV2xHdPvN8KSl3wl
         ey4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=C9BzlC4xfq7L3paAScMQOjDqTHKq0mXrLa7fe7KuytI=;
        b=t9ofa3rzT38Ns1uNMdOHR5yTQLfXiQ8/cQagaPBSjL2zodO6FtpHEYfOyKMpFp1zju
         QICGyOzOY3qQtUuKZrHzzGpQFSPLun5jIiLiFachWa0Q2Jg0Pm4hb0AO0n8S81EwHCnm
         nIZkyZG8uoQnftpauT8UaFow8vfOtf6L5uKU+Q6dz6pEqsgaN8Xs5sE083fKZyat9XTs
         LniREVIQq8QWbc4tzreTW7khwhBgPuKbxOTtRLq0lFD+m2nyE3JryKcL8+VvvdJdgRqK
         F/9dQ4B8o4kVHJ8T87YB4KxtMPDnHjlBR/BUpBUfbLtmCADFe+qnwwqshYTBJ4hkPhV4
         Wrpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KfbuoMFs;
       spf=pass (google.com: domain of srs0=zoo4=p6=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZoO4=P6=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C9BzlC4xfq7L3paAScMQOjDqTHKq0mXrLa7fe7KuytI=;
        b=f/3YkjQUGI+9S2dvHsduPudGmpoGjDJyFvD6mBlBdrniD/XyHM8HQM+5+oBGIH72gJ
         W6Cb4BuFZd5oLsRPB9aye2FXlu/NLxK3r3kRgwVfU5a+kIgZnQNbv2wlBl2/JFsPezcF
         Ro+XkMosOc/OA4RpdpQd3TUN33So+zeWdb0C24TtIeDK+4M5BxgBwRgMXfAOT49nyMM/
         eMtPcICZ22zUEWYVKU8g5VOKOuuF7U1RJbO7mSCGdVFr2mAxWJjp7kbhqDW2ALmLZbzD
         o/QTSCufLeOrZ810OxwWMeP1RLyb/0lifKEw3KQDfcBKP/0qlNtqXXkWjj6S+GkLxoex
         s4Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C9BzlC4xfq7L3paAScMQOjDqTHKq0mXrLa7fe7KuytI=;
        b=WGsMxhw5yMU9FuEqbVlUuWikO458PrPe1x5SpngjxDemQyKYOOc3I0ReZp+wVdcLhc
         K35bfc7luqa02Pb3zluY4ARR3737veZ3uNb0Vo/83YxYUBQ6qnxvspuV0an2QfNId0VN
         QDsKz+bZ2LI1c5LJ2lp7s+HDCz2gOqe3GrOXXTt6y55GPrZT40/ZwVBsoOtajSJf4Poe
         2qIETV52W3DXxwHas8iLdp25BZZhom5UZP7iCIwcQfp5UmI5vLPTCp1f36ORdL6z+wj8
         cPFLRWZBFFTebVMrucMqQ0TRO1NvVdGKPqWvBi/rmeJHgQiHu/YwOt0/WqXay6s164DH
         cWew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WyVXbQZXV7cWNrv0Ips5kU4OKi9K9Ru0yx1revj6OQIC5VPdD
	Kdn16OXLK3xsClDKGrwffF0=
X-Google-Smtp-Source: ABdhPJz5thj/ptFgfn1fznHpeRE40/f9qLYej2jsPOIj12m6YrffCh5GQeWm0RuT5fD/5AOoVD+yLg==
X-Received: by 2002:a05:6830:4185:: with SMTP id r5mr6989129otu.50.1636647607657;
        Thu, 11 Nov 2021 08:20:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c284:: with SMTP id s126ls1349035oif.10.gmail; Thu, 11
 Nov 2021 08:20:06 -0800 (PST)
X-Received: by 2002:a05:6808:1447:: with SMTP id x7mr12285252oiv.139.1636647606478;
        Thu, 11 Nov 2021 08:20:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636647606; cv=none;
        d=google.com; s=arc-20160816;
        b=pFfM823RBS5lpuZt4tdi5HttfLV+RtA4wbkTlZkcklZttaIcfU/Zaa7x8aX0S9c2ZK
         FWbEr4ZnKKQofqoQGUzKZW4UrzZh9j7PeFZsRyzyxlg5GAo+CjISie2dSbPQCocda90g
         bGJWl/QTotzBjhLC0PANMtn/4FROAP665cYFW+zof6/VubLY6CZsfzGDKv5+uGCbP42Y
         koO2P+vtyDGgO+ezWll6Rx0jMrbh/j3azC1BzxMA0EhGML58d9gyoh8ZVoOWW7gx7PmB
         +d47hbgNm0VeUBgLLz61+n67QYGiTT4qjRyql9jXwpYxFDSviuDdY6Y258Bz+mgPaIc+
         Sj/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=LUnkzY/Jz2V68eA+7IQm8c46CuC7uZ6XDnDNKpQAEDk=;
        b=DeXLOKFUPoi7J9dPRN35rXWp120Z/AYcLavOqaerpUNRUZDZ1Kzg21sZGZ4nh/CWuY
         UZWqP6WnyoQvSaC2voT564SdFuqA3uVjrRSLOybVeLtEJFmkMIeyBv/8krA6fZKkC/6b
         jww99kkuH+dONTrxFAoU/rV0C3VvgWvQJqg4G6feO/ADQ/PUCJExrzcZ2ZepVu0G9bFI
         myVwsymr90kap527YW8l7+nUDRtfcMbXRQm0ZSEJXcm43RqxG5gRtxRoOr/Zbekvx1WO
         nnvlHOv2sY1WslvXnwiJzVk42KuyAkrfERuqWi+48p1eCmTkBRoASS205cAj2HnxreX5
         YF9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KfbuoMFs;
       spf=pass (google.com: domain of srs0=zoo4=p6=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZoO4=P6=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v18si291363oie.5.2021.11.11.08.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Nov 2021 08:20:06 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zoo4=p6=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8AB6261058;
	Thu, 11 Nov 2021 16:20:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 4CCD85C0527; Thu, 11 Nov 2021 08:20:05 -0800 (PST)
Date: Thu, 11 Nov 2021 08:20:05 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: torvalds@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org, elver@google.com,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	cai@lca.pw, boqun.feng@gmail.com
Subject: [GIT PULL] KCSAN changes for v5.16
Message-ID: <20211111162005.GA305579@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KfbuoMFs;       spf=pass
 (google.com: domain of srs0=zoo4=p6=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZoO4=P6=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello, Linus,

The following changes since commit 6880fa6c56601bb8ed59df6c30fd390cc5f6dd8f:

  Linux 5.15-rc1 (2021-09-12 16:28:37 -0700)

are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2021.11.11a

for you to fetch changes up to ac20e39e8d254da3f82b5ed2afc7bb1e804d32c9:

  kcsan: selftest: Cleanup and add missing __init (2021-09-13 16:41:20 -0700)

----------------------------------------------------------------
KCSAN pull request for v5.16

This series contains initialization fixups, testing improvements, addition
of instruction pointer to data-race reports, and scoped data-race checks.

----------------------------------------------------------------
Marco Elver (9):
      kcsan: test: Defer kcsan_test_init() after kunit initialization
      kcsan: test: Use kunit_skip() to skip tests
      kcsan: test: Fix flaky test case
      kcsan: Add ability to pass instruction pointer of access to reporting
      kcsan: Save instruction pointer for scoped accesses
      kcsan: Start stack trace with explicit location if provided
      kcsan: Support reporting scoped read-write access type
      kcsan: Move ctx to start of argument list
      kcsan: selftest: Cleanup and add missing __init

 include/linux/kcsan-checks.h |  3 ++
 kernel/kcsan/core.c          | 75 ++++++++++++++++++++++++------------------
 kernel/kcsan/kcsan.h         |  8 ++---
 kernel/kcsan/kcsan_test.c    | 62 +++++++++++++++++++++++------------
 kernel/kcsan/report.c        | 77 ++++++++++++++++++++++++++++++++++++--------
 kernel/kcsan/selftest.c      | 72 +++++++++++++++++------------------------
 6 files changed, 186 insertions(+), 111 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211111162005.GA305579%40paulmck-ThinkPad-P17-Gen-1.
