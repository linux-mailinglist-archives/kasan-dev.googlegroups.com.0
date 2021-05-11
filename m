Return-Path: <kasan-dev+bncBCJZRXGY5YJBB3VD5SCAMGQEBSVD53I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D35C37B26E
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:23:27 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id v184-20020a257ac10000b02904f84a5c5297sf24604106ybc.16
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:23:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775406; cv=pass;
        d=google.com; s=arc-20160816;
        b=IgGyGt9siZ2kSRhTEeaXLHSw1XJT1WfgD6y3gRgJqtGi1HivC9ajTPrP5XFLjNfmqT
         8dWyRoksVGPdvjzcljd+n2eMvCS7omAIW6YuM18GLGFKmzEnJmY4d3/07uZIeVIimOnL
         wvQrChLbPmDO8KEyoy692ZtFD7CG3bITxbz4l+ef7Co+yA9770xdW5dBRFU/3PMXy2Do
         t1XN6sT9sylGiaVvaRZA8h9UkXEOsN4WJFK/7GdYIjqUnFZHedpU0P7AX9329/HntlCH
         FpUb6pS0GRm6z9Pxy5j0Y4aCrwT5qJpEa6ApTyNtJeTLO1rANdIuQgSbxpjUQBRzVVDF
         UEcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=335P1l8/IVAYdtMZ92GivOpo9DuXI9Ccjnb6da/VddU=;
        b=HGjF5CNmioFzB81/lcEIv2tFwE+YXtKLcDsb5abnyWIrsw2oQgn+L0mf3Fhn1ZH9Ao
         pFTZkGW2aSekIFdAyW9CYGufYp1TqZVBH9RnnfOe7yMHeRl+J1JS53yfovh79W3+aynt
         pKAZE1lYDW8UKGv8qx98uvTPwW03yT6MbI631ZEWAms6CbGvnwLmDU8y/xgMh+AMQasl
         +hW4Ymrw1uA9gbqG1q9rQCwm3k35Z7d2l7VFgoJRFQHmMPoy2dReiZCgMFayDjh2hOwL
         4jtLmgO/ndms+3TrCHZpq6ami525A10AVz++13gyfOkqR7ly3gcE6aHgBKEIs418kkPm
         7Q1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cz5C+K8k;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=335P1l8/IVAYdtMZ92GivOpo9DuXI9Ccjnb6da/VddU=;
        b=lITmVH02Ihl/tAkxt9yGCXAaxmt3P9BKKDNnO3uKdX7gOxDNNgVlF73+4AY47Nr1d1
         fBjx3PHpZ6cRIa0O23g9dccaZ/nnw2DKDUnV32Y2L33V6WM4sB4J8dQ7VHXkFK71j+b4
         sDhpENGFBCGejrA9AjINkUjmVVei/U5XBWFdpkdPBZzIM06CBr6D0hAVqrez+9W3Gzqr
         FjLNo+xWL5Ht1BjbOXt3bDDBuP9Hl6xdzItpWZH6osrw4Dz3AvG3fDePcMop8iJOxiMX
         RAVzfgjK4NT1mlg6KvjjR+jS8GTesOCC9K6hVD28XRZM3JaefeXAXDzq20B3On2Ylgrg
         oGEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=335P1l8/IVAYdtMZ92GivOpo9DuXI9Ccjnb6da/VddU=;
        b=rjGuLIs2nWI7sz4B+m9NS6mgrxiykXhkvx4Y/ZDsG1XKIY/79/jY56sGg93QaEZpxs
         015nEScKpjfRjAFK2TucoyJvHxQenUq7c4zPoV0wTc24UxYed5Lup1j+JfG/dpNdp0jU
         yVSrbSFa6/Im9q/huVAy2+PVxNb92U4c5hNMNIJUHkRynnfZBU2CuVGE6liasfSYSEH6
         fibJY1OCFcrQ4bkbSQFAwjYuh5XZ+ADNfk01s+FmXDWh4aMP3ln6uvpjEUD6EQPm7H7M
         jOhvxMGm52bYtWosvulA/zTY2CBbyLrg7esybFaaqD7Z3Q9aeo6EgyvH3F7u1OPBrPFo
         4MTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321EdERjEyohH7HD9omJK1v4hKvANxKSoKPosDQN9skIZRausaa
	3Q9CBKWH2ESEqS48poD04ao=
X-Google-Smtp-Source: ABdhPJwZTWwlYwXh+v2ufRawByfTFjdty61E85wKlNK9mNWcZFeH4xmrVef2rObmgYS84cO9YkoHIQ==
X-Received: by 2002:a25:e60d:: with SMTP id d13mr37087300ybh.384.1620775406464;
        Tue, 11 May 2021 16:23:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2787:: with SMTP id n129ls96708ybn.6.gmail; Tue, 11 May
 2021 16:23:25 -0700 (PDT)
X-Received: by 2002:a5b:50e:: with SMTP id o14mr44323608ybp.43.1620775405882;
        Tue, 11 May 2021 16:23:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775405; cv=none;
        d=google.com; s=arc-20160816;
        b=HfCwJLXRfVDYxnI72LBvK2FDreU3mYYx6dKvxiOjqkQW0AzwEX43LQWqYx5nw9qlfs
         xUvNeb6+mdUA8a+7u8R/TmT2jeSfwBdy2iXM5743fazV/WHuO+95ly00yDBijb3tap29
         Q7zsA+qelZWYYL9x9NEhYQe4hKsHRQ36m+tjIOTc54ZBmp2Z3YVwgbjgRK2VCxpsUFox
         xByKDqbNj5qgS0n1uZA/8at95pG5aB88rOGDHp1yRcHi7FdBG4cuagR3JQd8nngKBKbY
         cYyzwpAGnTf/NWGhGl0jNDlJVAm09n9kf+T3l5mTm9q+9PWRA1dShjZc9f6kDdffdDJ2
         kFKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=wPrMVIsKcaZq8R/1a2KURi+1ykS190A5+SPE5PDnRIo=;
        b=iyTqt9zJLTR1+K2hm+fhS6WM57E6FjZIzo3KoknY2yuAt0alrfbwxeBpNFoUbYxJRO
         XUTqYF8vJZX5z2sHUgUJodZQOefo6pAAg6ANLRjit+aS37R/+LIdGNFUP93N4lFb3TcH
         3B7bfRv1O8NIU4tsSDwsNz2DjD0xUYjekSTDFUY7HPRnagagkAleu/vBnjHK5j2psHsZ
         IRyjYYwr7DxIC4dMZcw/Q0RLMijCQzqYIdK2P+MR+Ef3KLijCNSbexjAtQNerOuXINDc
         eMhmCgnxiNSwrZdf8bU/USlIVQI1CS5EOk7Zkt4w+N2CtDXNhyzSQs/ARc/XDOXV8HOm
         k4jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cz5C+K8k;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r9si21825ybb.1.2021.05.11.16.23.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:23:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CD57561626;
	Tue, 11 May 2021 23:23:24 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 8CF3B5C0138; Tue, 11 May 2021 16:23:24 -0700 (PDT)
Date: Tue, 11 May 2021 16:23:24 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/10] KCSAN updates for v5.14
Message-ID: <20210511232324.GA2896130@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cz5C+K8k;       spf=pass
 (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello!

This series provides KCSAN updates.

1.	Add pointer to access-marking.txt to data_race() bullet.

2.	Simplify value change detection, courtesy of Mark Rutland.

3.	Distinguish kcsan_report() calls, courtesy of Mark Rutland.

4.	Refactor passing watchpoint/other_info, courtesy of Mark Rutland.

5.	Fold panic() call into print_report(), courtesy of Mark Rutland.

6.	Refactor access_info initialization, courtesy of Mark Rutland.

7.	Remove reporting indirection, courtesy of Mark Rutland.

8.	Remove kcsan_report_type, courtesy of Mark Rutland.

9.	Report observed value changes, courtesy of Mark Rutland.

10.	Document "value changed" line, courtesy of Marco Elver.

						Thanx, Paul

------------------------------------------------------------------------

 Documentation/dev-tools/kcsan.rst   |   88 +++++-------
 b/Documentation/dev-tools/kcsan.rst |    4 
 b/kernel/kcsan/core.c               |   40 ++---
 b/kernel/kcsan/kcsan.h              |   10 -
 b/kernel/kcsan/report.c             |   26 +++
 kernel/kcsan/core.c                 |   17 +-
 kernel/kcsan/kcsan.h                |   39 ++---
 kernel/kcsan/report.c               |  251 +++++++++++++++++-------------------
 8 files changed, 226 insertions(+), 249 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232324.GA2896130%40paulmck-ThinkPad-P17-Gen-1.
