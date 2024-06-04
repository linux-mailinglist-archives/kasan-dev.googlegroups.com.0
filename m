Return-Path: <kasan-dev+bncBCS4VDMYRUNBBJPX7WZAMGQERZVIF2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 08C748FBD70
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jun 2024 22:40:08 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2c2093beba8sf2625959a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jun 2024 13:40:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717533606; cv=pass;
        d=google.com; s=arc-20160816;
        b=eD0W3glTQmsn+psmStMeH8SdLv6q7+FQ2P+oBI/6EhDhn+gzDxNYv3pIGyXV1mUIzY
         R9sQFNoLceYuEK1SLQcLmikdE4JseSqwBuYrIpg120YvdmAzd/y93kcJmQ7pFuJvlYLh
         M+IdIhg8FKtmjGW7KYgnWFzUOc/iYuawjKFgyKi9TDifmsH3OrCsxaOZE0Kv3soYhPzF
         133AMbshRtsBj7aDylC3hVGFEJRlEE4Tpw6xDygmHHxFvPmxkQT6DCs9ox6b5fhDtVGf
         bGnfKI9gJPWdJ0VwcesLOkSPDhM5NHdaACvvzyqvBWMPDX9y3tCllPu/M6IolkPtHR3T
         xW0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=EYAaOPZ3GABajYjTxT0MNQ0dONEqpbjdACudndtfAPk=;
        fh=QiJoy18YOUqdTS4XGNV4H5IjdXJH5or4R9RwU3WSCn4=;
        b=jxydaiYyxRiitEchKrjJ78LSunpNS0a4PmUZB18ziuKgqJkxmnoRdRtJxS97hKYmZJ
         GCFVdRTZ433poTVR6ycxxycw+5UBEu2LPzhIcEwwpau1RRQ2n+r2ZkiTanSek5BFe/OU
         zF8gkv/IUMM9X3HNLR9O+a242QZQFzuvhrjlCLjPJq+fYq5TImZIL9ekkx2cBpnky2q2
         DvyUBwKNb0OJ6AmQTefg1vvxo5rTkum4E1rPjkmVnKfEVsE8S8SX4Khwz+PyUbA32jrN
         i1F+5Sda2k8ZH87SQ/2g4noDjAvJOfik6lUpTX94avBylBl0EUEiVMB9Vpt6rlMl3vsE
         53iA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ndiXGRlc;
       spf=pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717533606; x=1718138406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EYAaOPZ3GABajYjTxT0MNQ0dONEqpbjdACudndtfAPk=;
        b=gqbcg7V5PYtk3Xy/3HO9LyOyOdZGH6WAmTixzb8L/nQDWomDb5kEQiTMWZaHiod/Pq
         7p59a8CzQ8dBxzK1a1hcL9MIm1VNWGqC4Gejq6tpGeax0h0e+h0NhuIM5VVaaWQSQtkE
         g+YJwPufcNWWgPIhK1W9oGMZeCS4ovn6aWN0spmqJak5XJcv/XNtFsJdaa1g7lF45WKj
         LNeLQP0egnPFc0/AAuQDatSFnlrbg5aVwX9s85CM9tlhIn/JYQbD64mQ1ckRHqlqkGz3
         UMJdCtNrkitLqaDa3KxtcjoIAcjRmEzHxRoOh17AKJl9BnWNA21ZwZvfLLfttfrzj2qb
         L8SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717533606; x=1718138406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=EYAaOPZ3GABajYjTxT0MNQ0dONEqpbjdACudndtfAPk=;
        b=lx1uofpNyhvKMetWhkkVjYIWpj7q1JVlMQUX/dqMJXFEgEJGOzHpXqquRsz6+MlzTz
         NvpgpHSAFfEAZmEWE9dp3nKmndfX+N93NdtIDdLpVnVmhOY+j3f0pFII6QfjW1dZoM2f
         Y81mxoTVXkJPFH0ib6n/2z7DOd7SGrWoPxLTilqLcvCHHdzQRH6Jk3e0K0fvfVQXg/2J
         7IsKMMTfh5lBqzjr1d0HIivj+4+oeZ8SbT2sgCakYsfHfv0lzJEx+8YcRlq1oxgp70g+
         rNdmqMTPamAh2/6+EcrW6AXUgXV124+Y8zfm/V9iOh1ZdWXNN/JMuzymnc0EpZehgI2G
         Y1sw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUs4FD6HYI81Xd0mYtunAa9Fyo6z/oF+KQO4RFTJazbn0JUhwDO6hszs7d6HNjctYzzxxTwQv3QoT/du78Mfw93XWTJ+vxrkg==
X-Gm-Message-State: AOJu0Yy2kDfpDLeSHkIigv/ItPGy26DpkDfZnj8ZIvqVhCd5nwPiYrun
	jwWZ6wAjAv4PG/Mjc68ukbvJnH0eM5NPhc/KN8x+h9nTb7Eu28Cq
X-Google-Smtp-Source: AGHT+IEU+EIdlPLKrnB0d/msrfHdmbrke5DvsGC8tXLeoYM9AtXTfXVyWHTaEl011dLddK8doJK+qQ==
X-Received: by 2002:a17:90b:3cd:b0:2c1:b99e:6fd7 with SMTP id 98e67ed59e1d1-2c27dafd42bmr606333a91.2.1717533606010;
        Tue, 04 Jun 2024 13:40:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fd84:b0:2b1:c935:4ef3 with SMTP id
 98e67ed59e1d1-2c1a9648a43ls936931a91.2.-pod-prod-09-us; Tue, 04 Jun 2024
 13:40:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6RVR/NgAN0G4EP9OphqsRyvH21q88fywqHASIFc/lWpgt+1knmVqGRbbl/VBHZjQIo49uFEyY4dc1o3uenD+yaZ5Wi8xjVnv+sA==
X-Received: by 2002:a17:90b:1115:b0:2c2:3b14:7879 with SMTP id 98e67ed59e1d1-2c27db57d37mr576895a91.32.1717533604509;
        Tue, 04 Jun 2024 13:40:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717533604; cv=none;
        d=google.com; s=arc-20160816;
        b=LBIv53ZVIOD2TF7rbIHJt85PzSjiWbrjjqv8EWYx5i9Qti7YTO1zuIeWp/v4b/84XH
         G+WGLBEEIkaD6L0cp78cbl5VtYVYAvIgWHzAnYPlbjyKFhupzQFlt1+pHYer2J75XaBW
         /mtp9bhajvgqnwP5LC2y29+QwYQKZmRQE8NLNMJddV0D0HEbFyWqScijWFgfXXzci80m
         SddjiU87IuaTs9M5T/eARE3iw2FXQt6R0+ApyFzS+xqfSPw6jgqSX5ZOG9VrSAjwyJgE
         /g75VI/BwTvaDKw7dUesDH44ygzPwSvsjJdugt39+v5bUDCBdJkUEdhpAsgCFidl6W5q
         dvjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=oiWLn58Kf7VjnA9JejF9frkuitIz4fvXQQlxT48BtOA=;
        fh=FM6+x405secWhB0I/fURJ9qcCgQgJ9bBxtQjt2ii3CQ=;
        b=Md3P2MtB0S3EH1CC9xcehMR5RhZxs1mAPl2qQo5t2OJ6Mg876nITZ9pdtMftWk7bHC
         hLEOKSuBsqotifwMFsgESVQFAroACZukW4RazaIadiazESafi1Gn7EBndGBHfpLGkRLA
         Uy2pR8g5CPIajWxihE9fxIvedLacQ/Y3MBVaUuBIbNtZj9u2TLzjaXDQ0jk2TbrPQcRS
         nR6RpJ7UisdlVaEAM4LyE4y+O2PYc/JS6P3Teum4Yjz6FyeuiuWU8pfFrbxIoQXReUhd
         Fhrw9rPoLbjCHDVqUz7AfHugiQdfl9k7ZIyTqTQ9ObmnNjAc6b0SPUeeWjw2DskY+eHA
         kn0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ndiXGRlc;
       spf=pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c254a78b2bsi157528a91.0.2024.06.04.13.40.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Jun 2024 13:40:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C0A6F614DE;
	Tue,  4 Jun 2024 20:40:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 64C0FC2BBFC;
	Tue,  4 Jun 2024 20:40:03 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 02EC0CE3ED6; Tue,  4 Jun 2024 13:40:02 -0700 (PDT)
Date: Tue, 4 Jun 2024 13:40:02 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@meta.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/2] KCSAN updates for v6.11
Message-ID: <ecf1cf53-3334-4bf4-afee-849cc00c3672@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ndiXGRlc;       spf=pass
 (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

This series provides KCSAN updates:

1.	Add example to data_race() kerneldoc header.

2.	Add missing MODULE_DESCRIPTION() macro, courtesy of Jeff
	Johnson.

						Thanx, Paul

------------------------------------------------------------------------

 include/linux/compiler.h                            |   10 +++++++-
 kernel/kcsan/kcsan_test.c                           |    1 
 tools/memory-model/Documentation/access-marking.txt |   24 +++++++++++++++++++-
 3 files changed, 33 insertions(+), 2 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ecf1cf53-3334-4bf4-afee-849cc00c3672%40paulmck-laptop.
