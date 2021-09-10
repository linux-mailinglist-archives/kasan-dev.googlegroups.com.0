Return-Path: <kasan-dev+bncBC5JXFXXVEGRBS6J5KEQMGQE2DKQQPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id B97414060D5
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:20:28 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id mm23-20020a17090b359700b00185945eae0esf199669pjb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:20:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233227; cv=pass;
        d=google.com; s=arc-20160816;
        b=mI6pPCZadTJOPnvxR/6DtGU5Ps0BbqDvxrxmNXZVPhGk4c6usQpz+KUrLlu710sHQI
         ZtwCScfs1kreRik9c5KacZdjHYpTjeVCs6taaSLd2U6LRkEyv4C05Dcu8f+hSZm1E0EN
         V63nv8q2qKi1XlDKeC2d17LhN2OuGzkXVdqaYKzbwAu+YGdgfh6ptI62ALOO90roRos/
         IZU+6XLDPi2xGyW5Ubl9KW+IbNh7mzg0jgZvAgrC+WcbsTKxB6kCtlBj5P3/ajIZi9Ly
         4i3UliqxLKmf/UQV9vu9eGhodyaETR8AERq7uMEDQzvlpBC4yL4lsffx3/g65e/vf3Vw
         B0yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+JYwBJjAFe2W7Zk0ivcD820A0tuoM5cPcZ9Z6Dp1VOQ=;
        b=IbQvdDNr/H8CwZiNyQp59ni7Iw2/aTrZ19NaD6YtcGFtc/wtO/0BtswdpS9jUqdscP
         a5y+eJxbWr+YEe5wVl1sISI6sJeFpPkZrhMnrYGAWtSVMww9huZgBHoY1tKL7ckP7AU2
         uLxNoPITMG1WxtJkhunzeiyNfAdlsFdekZNNX1yEruawVyrSp6YedyeQtMCM6KEWon/8
         Yh0PavxcQOElCzmuA66gOKxlETpbXxLZLbxApQU5+GkKBrThW4l5S3nVEw2YtDHYW+0a
         EztncZRyOWa7rM0IrIgOscaaZxidMsJ2+znAdgAAz5hlqjyX9MsdMFLv9JOmkE3ZlPvo
         mshQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IRb+cZnB;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+JYwBJjAFe2W7Zk0ivcD820A0tuoM5cPcZ9Z6Dp1VOQ=;
        b=Zj0XCbdDfc5mcKq/gTmmrqPXS3C6YPqPlRl1RrumidtslbdXQB65yK2+qR3wt/vJJW
         8fqXd5P6tl6bhjR6nDEa1ZBDLqCUKKJ8bH0KBUJJ+NJSOz+r0k4Uv1T6HE9AfuOVKRuu
         uIqNfZPMC5yan7VPEBuGeATycwjmJS+eAyRRd7yg0LKwIHfexBX1ULchNb3sV+3Q3Bps
         Z7b8ea9wV+epwJK3dyvVDWd8TnMn8uVVvXrgwD5bYDt1tnvjCKpJSQbKJwET2uQZRshy
         nBIx7ttBzVuyGzwH6evubaKfFqu3qsdJ95f0MklYtPQxIDp7txum0g87U9dyMzNxquiw
         FC+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+JYwBJjAFe2W7Zk0ivcD820A0tuoM5cPcZ9Z6Dp1VOQ=;
        b=QE2XkOYTakPtdf56UHEkBFmnBpiz1w/4T5LuxXQJks6PeTJrnpjXSHM3CMAQJhJTCF
         DjkYjVSXLSjmMQM5P95hm0h26CBJzKKVNFrhYgRGo4ORVD6gLT8tDaBBVridpRg6LWJH
         dmMiUOI9aM5cWY56x7r45XlKTmtILy+MDN8V8Upa3irKAva7q91DYCNaANgRvc2je3Ij
         c8dJA/7ppO64/woICw/erMtHrHpwqxKtMxfTxKGrfxGfwrogvmCYliUwO5wC2LE/YRDj
         ma37flX1BhyLyydSXTxtqF0SbXa8k9/Gujo6Ui1MOE0mqNu2LpZy+MVFd6Ky8usOhspM
         96Zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xdxmitcaZMGlp2UZ3nu7GAwhtc1QqQzwGg9TYYnZ/FkKaJXz8
	rze+wkedFhrZ219KWYH9W/E=
X-Google-Smtp-Source: ABdhPJycH7XOUW0QW1G9vTxlFO5uE/wrzCRBq57v8md5vtNOQf5B0NCXpPlQK+pHdADt6IwY13idrg==
X-Received: by 2002:a17:90b:106:: with SMTP id p6mr142091pjz.78.1631233227536;
        Thu, 09 Sep 2021 17:20:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8e41:: with SMTP id d1ls1526249pfr.8.gmail; Thu, 09 Sep
 2021 17:20:27 -0700 (PDT)
X-Received: by 2002:a63:b912:: with SMTP id z18mr4951245pge.59.1631233226866;
        Thu, 09 Sep 2021 17:20:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233226; cv=none;
        d=google.com; s=arc-20160816;
        b=RGVX7C7KaMTpxSA6dqZVZebwlPDse++rwkWH3eclbgdVQRUHIYFTM4r9gPTBeaZAqK
         UNYaD2FrmWKsTYukVErYENDwBNfW5kINQWENpD7NBZ6FLn/XfmTcHni7giaQY+7r00Lq
         nLIEBul7yTgPVuMup3MvD889tTL2nUTREe6rddyOpO5Juvk+m6EIiKoC7PH87oocC1xT
         E94qcE3s1y05HQAC9bezmwR40aBHoCJfT2zTy/llhEm0y5RQtIvkLJBzuaXhJSKxkQCp
         MupNKivy+411iHWwrDOyBaJuyHIu//m3wdRH4YQDv4E+Nw0Tky9pMmJ6s/qhUpMWm/bY
         EhmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ic/+d9i0EjGDmemIdZbS5lFh8WKXBIBb/879FCd3d7o=;
        b=J/qutX4dfy0+ghqtmjM0EH2Hghx9sX/AR09UAdqEKTjn+U4c3z8BheUOdoRLq+Beam
         xGnyPVaKkH3wR9ja2Xd/7StbVuZf+r6coQyo4/Ay1eBYj95HRWBxYIYFxO7SZa7OpV2f
         iaq0pdI6DzFkn5NEhiXbfAZrcstDvIzBqwNU4+hfjye1PHK6P1ObpwGu910awE9aIktT
         OceD7kqdIoFi+nCO/6n1MVw7dQtCn5+tBzCk/ocZn3SyqOh1w/O3Ol01EK9YxfrpvG7G
         XIGYKgbsWWdvQul/B/kDm+tL6YRJw8QwjwYmgD2igP2y6CvlZJZALH1vBSxciJ7lccyi
         fUqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IRb+cZnB;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a14si427185pjg.2.2021.09.09.17.20.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:20:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8136F610E9;
	Fri, 10 Sep 2021 00:20:25 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.13 88/88] kasan: test: avoid corrupting memory in kasan_rcu_uaf
Date: Thu,  9 Sep 2021 20:18:20 -0400
Message-Id: <20210910001820.174272-88-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001820.174272-1-sashal@kernel.org>
References: <20210910001820.174272-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IRb+cZnB;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Andrey Konovalov <andreyknvl@gmail.com>

[ Upstream commit f16de0bcdb55bf18e2533ca625f3e4b4952f254c ]

kasan_rcu_uaf() writes to freed memory via kasan_rcu_reclaim(), which is
only safe with the GENERIC mode (as it uses quarantine).  For other modes,
this test corrupts kernel memory, which might result in a crash.

Turn the write into a read.

Link: https://lkml.kernel.org/r/b6f2c3bf712d2457c783fa59498225b66a634f62.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan_module.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index fa73b9df0be4..7ebf433edef3 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -71,7 +71,7 @@ static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
 						struct kasan_rcu_info, rcu);
 
 	kfree(fp);
-	fp->i = 1;
+	((volatile struct kasan_rcu_info *)fp)->i;
 }
 
 static noinline void __init kasan_rcu_uaf(void)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001820.174272-88-sashal%40kernel.org.
