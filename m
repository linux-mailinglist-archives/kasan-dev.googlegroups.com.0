Return-Path: <kasan-dev+bncBAABBV4A7SWAMGQEHKYI64Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F66482A269
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 21:38:49 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-204914d3eaesf7597815fac.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 12:38:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704919127; cv=pass;
        d=google.com; s=arc-20160816;
        b=BsevJ7FjfSlQdHxybfJ0LlYmMyFe0P2trBYd8KAZ7rs7XeKyPxTJ62vzWq/v+HEdex
         tNbL7lJMDld19l6n4Lh8NMqp2GLES9kazoMDxUDgyhJs+4tGz6lw94UamF2/UZUUaJm4
         OI2dSvAC1fd6IxXu5ogyatPHMYotmrX5bdewzwvBWBMwpwTPPAWDoiXhVgyUa0Th3Q0B
         GvSTyeDqW4ZyjZHVDLqE2n1XQQoXHew3AJO5ipyYiCoDrfdnP0PJH2hqahLenOH2+Rpo
         poFiXDimpR1Wu19ixJxrKr4zg0QX0t6Eomc8soIOKCWnZrf6uwmVCiTembs0hLyjw9/a
         uPWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:date:message-id:references
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=sHyTp+cO/BgzGaMzUBrZmvfCwSAYWyICQHSu8+de9Wk=;
        fh=7m+d+2FUJABCDlO3dSe8oaWK1YyWde7KPzWsC+om2RU=;
        b=a1KWyJF6E06CyymSzg7GgRzCWDZ6l9Qi9/D7RpwWgQXqH1NNWvJsbbOM4sr9B/7ArS
         UHL9RFEK7uxRUy8R4jUUgvKSnIMeOCTR4mdlJ3TEk3flNXoXTvpwn0dqqsFDbfp0bSAS
         zmwe65UKGIhngztxH8Q47dKTdUCs/46ErpTq8sz6untvIGFQH//kZWQbI/9FfLiqAkXS
         jqhuT+hsOg5K0f1ANZ8VPY/+5ojUUmqTG8HpbRz24Zz3Gn+S4/GMO5GrZBXnU4jB/Do8
         xJvUahRKOdPap01OUWp9ySfxqK2uxzWcU1q1Y1njP/icADuleJNqq88YZdFZT7HQwxKE
         IoIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KcJTj4Cd;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704919127; x=1705523927; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:date:message-id:references:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sHyTp+cO/BgzGaMzUBrZmvfCwSAYWyICQHSu8+de9Wk=;
        b=p1E3u/u4JUazfPZa8SOpdZE1bdXKlCjnJf1TajmQO9t5n7g7AQ6YgXSFsZlXZLMSyt
         WM7batwIR3boX+5mxZcyEXU8cPIljGgbU9C6aOTnP7VPw1IDV4p2alP4oeCLJe/rxa7E
         ciXpZSI7TEYQaFDpy4Ctf82vH5bDsM5Y6WzPLFEL3L/X4B5JW0pRq+3tQVt1xk/4LWZl
         B4q+FSsrOdK9iFAEsubOqK3gbQYjhI6yaJAD2pxm/3QLsAJxq3N2gL7klLSzxLNOLWeo
         ktaRyz2DfRG7ytRzqSfLheN/9J7J1uMUf7jb/b7a7d8iNTPgTz/6U+JSbj9T+0o2viGW
         sN9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704919127; x=1705523927;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:date
         :message-id:references:in-reply-to:from:subject:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sHyTp+cO/BgzGaMzUBrZmvfCwSAYWyICQHSu8+de9Wk=;
        b=aI4IxwzP9bUd23rZO5ggvDh3LvjtrgnxoorRAZpU6CvpovfBB1zqExPvJn4ufaBpRg
         /01Q+gv1oNfujTvMOI1GqJ/QDw1YTG+1Ozz4eKgX98/rxXODUbWaXxZfQQyykl7V+uhm
         z6OW2t3AGrm4e4PhDiSn5VTv5GSrumzxlWamComNI2yhZAV6A5Yyyjn4VMH4bBz5ApXW
         DHBljEaGwm2BZrkDAGKd6lTciNIUSYHa7hSDE9PYFtMz3K173tnu86eCn/CeeeQC0pGD
         q1Qyulnc0VwVANL7WypsU2vwoCjFc/QzVaF+kVnlQ7WKk/9ZOm766wx5aTLFcvjel+5X
         vugg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YynG1zYGAmN6OzF3rGlDnaUkEl2MCYBC4oYuwbG0JuA4Pi4gPAk
	QARvmPWtuUwLA40LPBKJqIM=
X-Google-Smtp-Source: AGHT+IFvWHojflvONF7tyy3dVMs2k+KntnmKicrGv7tkuXvKcgfYvc0O5fWj1g+Whp449jR2UYcF7g==
X-Received: by 2002:a05:6870:d10a:b0:206:53d4:73af with SMTP id e10-20020a056870d10a00b0020653d473afmr208929oac.8.1704919127738;
        Wed, 10 Jan 2024 12:38:47 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5286:b0:206:486f:c3e6 with SMTP id
 hu6-20020a056871528600b00206486fc3e6ls578042oac.0.-pod-prod-09-us; Wed, 10
 Jan 2024 12:38:46 -0800 (PST)
X-Received: by 2002:a05:6871:b2a:b0:206:7e20:d20b with SMTP id fq42-20020a0568710b2a00b002067e20d20bmr176694oab.47.1704919126272;
        Wed, 10 Jan 2024 12:38:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704919126; cv=none;
        d=google.com; s=arc-20160816;
        b=BlxFUWlE4X7pgNacsPOFfvjdxUvNogFLj3OUow2R10dVyBbFy/8BMJfsEI85dxyp+A
         mZod5B2bV5SlCWKTg8Qzw6zLUjKG05087oLn32sHBSJ1XaZJu+oO29Vdc1EJXivam+Ep
         bHObDD5Ww4AHlNerMHSTHjkK5V/ZlF8DSg7tRuztsMVZpI1IwbrUZNqJJ2JkL2FNnVrI
         pAKgwVJPEnS27Vt93RK5zfk8eUB7QVYL7Z5bSeY6QgSw0PmI9QIzD8O4TfRj8FRBrb1u
         P4xx1PAfFHxaJTUXGO2KVeIJ+Mqf+1EjJ09Wv7kYoSGXuDAIpPER+W7grCxWsYRVL+i5
         ALMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:date:message-id:references:in-reply-to:from:subject
         :dkim-signature;
        bh=3vBe2+GI5T/tR3DfQR8GN686jwovliIRPs/oqjSbNmc=;
        fh=7m+d+2FUJABCDlO3dSe8oaWK1YyWde7KPzWsC+om2RU=;
        b=BGRRTk0dyo2qkiog8kXWLuUbtIYpM83dFNOFS/mgb/c+eOu1LUgeJ/vvCQO87wXlOF
         oR90HG+6lTk4YopAqDH/2soNGNuY3cSfrBBHnZ8VA9HjEe5ihPDfn1wAx9MUaCM7+eq3
         mYTiJwZasiJ0DXS/Z9omYqHl29tkZThDp9zXlWJ34Sm+N5nZGVv1kI5waWIP7U2oqCzP
         GbvQq0kdCZaubU6iadQSLus6asFLdaiHT+qXivoZ47CBFp0SOPKhc5Lr/aMFX3uO2+vV
         4Fetg5vjYzwGOgtz+iRhUVqhgiT5d099mWBGecRuKQZoWCmujUNzPIx7FoSGdxVqTyZs
         uEfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KcJTj4Cd;
       spf=pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ns25-20020a056870ac9900b002042eb57f47si727538oab.3.2024.01.10.12.38.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Jan 2024 12:38:46 -0800 (PST)
Received-SPF: pass (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DA346618E3;
	Wed, 10 Jan 2024 20:38:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 949F1C433A6;
	Wed, 10 Jan 2024 20:38:45 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 7D2B2DFC686;
	Wed, 10 Jan 2024 20:38:45 +0000 (UTC)
Subject: Re: [GIT PULL] hardening updates for v6.8-rc1
From: pr-tracker-bot@kernel.org
In-Reply-To: <202401081012.7571CBB@keescook>
References: <202401081012.7571CBB@keescook>
X-PR-Tracked-List-Id: <linux-kernel.vger.kernel.org>
X-PR-Tracked-Message-Id: <202401081012.7571CBB@keescook>
X-PR-Tracked-Remote: https://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git tags/hardening-v6.8-rc1
X-PR-Tracked-Commit-Id: a75b3809dce2ad006ebf7fa641f49881fa0d79d7
X-PR-Merge-Tree: torvalds/linux.git
X-PR-Merge-Refname: refs/heads/master
X-PR-Merge-Commit-Id: 120a201bd2ad0bffebdd2cf62c389dbba79bbfae
Message-Id: <170491912549.22036.4098527230662245491.pr-tracker-bot@kernel.org>
Date: Wed, 10 Jan 2024 20:38:45 +0000
To: Kees Cook <keescook@chromium.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, Anders Larsen <al@alarsen.net>, Andrew Morton <akpm@linux-foundation.org>, Andy Shevchenko <andriy.shevchenko@linux.intel.com>, Anna Schumaker <anna@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Azeem Shaikh <azeemshaikh38@gmail.com>, Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Chuck Lever <chuck.lever@oracle.com>, Dai Ngo <Dai.Ngo@oracle.com>, "David S. Miller" <davem@davemloft.net>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Geliang Tang <geliang.tang@suse.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Gurucharan G <gurucharanx.g@intel.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, Jakub Kicinski <kuba@kernel.org>, Jeff Layton <jlayton@kernel.org>, Jesse Brandeburg <jesse.brandeburg@intel.com>, Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>, linux-hardening@vg
 er.kernel.org, linux-nfs@vger.kernel.org, linux-trace-kernel@vger.kernel.org, Luis Chamberlain <mcgrof@kernel.org>, Marco Elver <elver@google.com>, "Masami Hiramatsu (Google)" <mhiramat@kernel.org>, Neil Brown <neilb@suse.de>, netdev@vger.kernel.org, Olga Kornievskaia <kolga@netapp.com>, Paolo Abeni <pabeni@redhat.com>, Ronald Monthero <debug.penguin32@gmail.com>, Shiraz Saleem <shiraz.saleem@intel.com>, Stephen Boyd <swboyd@chromium.org>, "Steven Rostedt (Google)" <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, Tom Talpey <tom@talpey.com>, Tony Nguyen <anthony.l.nguyen@intel.com>, Trond Myklebust <trond.myklebust@hammerspace.com>, Valentin Schneider <vschneid@redhat.com>, Xu Panda <xu.panda@zte.com.cn>
X-Original-Sender: pr-tracker-bot@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KcJTj4Cd;       spf=pass
 (google.com: domain of pr-tracker-bot@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=pr-tracker-bot@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

The pull request you sent on Mon, 8 Jan 2024 10:20:13 -0800:

> https://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git tags/hardening-v6.8-rc1

has been merged into torvalds/linux.git:
https://git.kernel.org/torvalds/c/120a201bd2ad0bffebdd2cf62c389dbba79bbfae

Thank you!

-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/prtracker.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/170491912549.22036.4098527230662245491.pr-tracker-bot%40kernel.org.
