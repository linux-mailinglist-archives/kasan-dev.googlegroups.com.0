Return-Path: <kasan-dev+bncBCS4VDMYRUNBBXUC4SQAMGQEBGX5QCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A4AB6C269F
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Mar 2023 01:59:12 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id f15-20020a05660215cf00b00752dd002fd1sf6953017iow.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 17:59:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679360351; cv=pass;
        d=google.com; s=arc-20160816;
        b=ejVaofMHCGYPZBkQiFlQzRRjodN7nSa+cj5AKQX/P7Opc8L98VI0kVpm3JNyrbL7q2
         8SXQzM97cVFy5N9dpflqBi4Sfr2mOJcQoZ1zIFSjZw/ynwNvQBQfjyTZwgKI9dt/a8zm
         5XgTc/XEffBXOVacd5nbpZfXuQyy+jmEfnXOnRxyDYGAPnTSgkNLTLG1xZtEBHGhUkkh
         N7lQHodCHUYiB6b/mcQybwmhi2a6UOPc4nx0yQoeNXDURH7Yd5V3ho+nVtkrkzLrSxtl
         9Vbk8gn2s9q+rDCVUG3ETzvUcgUsQKNOGYdc6wggU93HCZXDKbfZvvUPR7rKtn3Jzkl6
         2LnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=o7TPAPpqUKLET6FUwn9Y6DA/4vQpHCci3YSHGaV2aw0=;
        b=SzbfYj691lrseRZ1lBpcwDtUyhaXD2GMkkYfWC1EMeOLrM8JWNECpCXyRerNgvKNI7
         7lfRbn3cnEDjqyMkRRUD2el9X/bUJDA3tx9zSV2MCRtQyjG0E0MsOB94QdEOg2RYuE7S
         E1+0uBjsG1sOmpgXxuGvgbL6dxBZd9lJDl7nj5YHALMe79RDMI1sDJhqZ7uIyPpipsWf
         4p992qCwdhDoMmefCysOyTFYcsnMJQfs0Y+nPl6fMIQceoz7pR6uUXpj60b7pLi8cqiK
         O0HcZpFXPCePjG424WhL89VekOdX9qsVpfP/Appv/bk2FZIM9/+NFBiS1AkyArAEoU7T
         5APw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="E/6GlHGw";
       spf=pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679360351;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o7TPAPpqUKLET6FUwn9Y6DA/4vQpHCci3YSHGaV2aw0=;
        b=TT6h0G1/7AD6/KYC2FbJW+EtUPHLfWdJQtDwoAkblbnnXUfTEh+V/TCb37MYUZCoEh
         Xj319PKFRXT7s5dZps0d58sgyt9gm7ACr9/kQ4cnJudwF0ZHLRA1k0MRswHCyWugIZHi
         i9Pq2vOi8kwiQ5QfB5Z+AwAR1OwZy/qSpupGZskpU9eF9kE5gNNO8UReDGCl53qjkHkP
         gjAma78+4uOsXUP497tV3LXO9aVWjHYMXuEGrjjCA/ATxQe6OI+9eHhM7g8om84xlxbb
         au8QmF5YOuqiBf6BndKBlduSkpYHTGqP7BYNgVRUnMD2OkcgT0z6botEl7id4ldVrGSt
         /a2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679360351;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o7TPAPpqUKLET6FUwn9Y6DA/4vQpHCci3YSHGaV2aw0=;
        b=fWMQkG0+LeYECEOQe4wcKRwuEJzr2JbFSQb8sHIINMlA7iQB1znqFe6pWwOREyt7YQ
         wKcnSTBiyFRRMt0BMPmlfeWyMXA0ihtGXx4p5FtSMCyF3OUzDYDYsbNZAhuJ/SRB3skC
         UfbRe6svvrA8f37pGI39jl4U8bX7zegZpvDGWLVUkjKgkFctdtzplQqFaCQd1QKL2Imu
         +1qun2+JaYHlJU++VOJCup78S/0B2TK1zJP0rei70lwNqBPV4folCWdhFRdvzC/4L20X
         LK2TfAWeR+T0i/HYBFZOoS1YFQv3qYQoHBq/IkrIxlL8wP1HNx6ZiUcNii7/SGAMgh8J
         C/CQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUoVmiE71psUzZSc4dEKHHfO4cxICKmPUEU/a7BzLx/oylQQBCm
	t4vTsmfyy3vjdXjhxdo18EY=
X-Google-Smtp-Source: AK7set8DmUCGNJujD3blrV/VzToPSUembSwUz5MuZZRoeb+5ucpTHsTOyeoj/QPqgilgJULhcKBtEQ==
X-Received: by 2002:a5e:8f4a:0:b0:758:3c0e:f331 with SMTP id x10-20020a5e8f4a000000b007583c0ef331mr348762iop.4.1679360350813;
        Mon, 20 Mar 2023 17:59:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:96b:b0:314:1891:45e5 with SMTP id
 q11-20020a056e02096b00b00314189145e5ls3235872ilt.5.-pod-prod-gmail; Mon, 20
 Mar 2023 17:59:10 -0700 (PDT)
X-Received: by 2002:a92:d5c7:0:b0:315:359e:2750 with SMTP id d7-20020a92d5c7000000b00315359e2750mr306246ilq.20.1679360350302;
        Mon, 20 Mar 2023 17:59:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679360350; cv=none;
        d=google.com; s=arc-20160816;
        b=FIVYHCBlom42xcPCh5FKv3qvWelNXRII49+VrAFJn9d//hhtDU0Dm/NzkAAUyJf5sf
         9+rzrwJkPqp9oOxVw0B4+Npmq/Y015d5hk7pJt6o6CCiAEyR6JoYzeTFO+49AgiVUPx2
         d+xXLWNUrCzboc1bTAOdUs7yO4ZQbKnX2bdLaUj3NEMwXrJYCU5VfGM8mTj3W8pnpuHW
         3LAMkRfrSZLWdXsAHywlA83JcUt3b4GDog7HOQpYk2MlCpKS3Mlfsrk9nfAERYqhvGM+
         uFjYPcJxYGepuAeqa4FjHLxD697GmKnPlR+L3Z2t6mqW698E2bgt+6+HpQr6hytETAoa
         I0WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=gyeHBsLheyNFGnIMM7bTZP+t59u55Yh4T2TgWYxHcsY=;
        b=ri4rJFTFrCwRJDOE6hud9WpYjMKrlXVHKE1rMTZvaZ/lgNw09odIsWKGFToCmt8SyX
         orGzA2zHmOLASW2KUPmS8+QoGoL2lgYl17HcQ1EVExr+VNPA8EygAgF4bES3Db4O0UUG
         rBRK1V00Qn1GKIQm5K59et58+FKl3JMTxkxiiruWinxR4rLygOIwwrI1zQg51RgLSYdQ
         u5hHnqPgZ4osD8jB1ZfQnalVVu3lrlJpQUraUjfoBaUQb5+OqwBh1Icii6Yxy6QQ9nsh
         EV7ziZIPHR/6Jxw24lCjSTTkGxR0hkQKb5HZ2Hn9BnPCIRf691VVaalGme/Sp4QCb6B8
         CMsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="E/6GlHGw";
       spf=pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id l16-20020a05660227d000b00758573ce34asi3735ios.0.2023.03.20.17.59.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Mar 2023 17:59:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DF30B618E3;
	Tue, 21 Mar 2023 00:59:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4D85FC433EF;
	Tue, 21 Mar 2023 00:59:09 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D67C71540395; Mon, 20 Mar 2023 17:59:08 -0700 (PDT)
Date: Mon, 20 Mar 2023 17:59:08 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@meta.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/2] KCSAN updates for v6.4
Message-ID: <a26f2bdb-1504-487b-8ec8-001adafc5491@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="E/6GlHGw";       spf=pass
 (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

1.	instrumented.h: Fix all kernel-doc format warnings, courtesy of
	Randy Dunlap.

2.	Avoid READ_ONCE() in read_instrumented_memory(), courtesy of
	Marco Elver.

						Thanx, Paul

------------------------------------------------------------------------

 include/linux/instrumented.h |   63 +++++++++++++++++--------------------------
 kernel/kcsan/core.c          |   17 ++++++++---
 2 files changed, 39 insertions(+), 41 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a26f2bdb-1504-487b-8ec8-001adafc5491%40paulmck-laptop.
