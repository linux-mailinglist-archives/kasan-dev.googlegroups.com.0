Return-Path: <kasan-dev+bncBCD353VB3ABBBO5AYHAAMGQE4BME3XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D06FAA0117
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:21 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2ff854a2541sf4939589a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899579; cv=pass;
        d=google.com; s=arc-20240605;
        b=G9di4EuJj935odZqKZ6xaHL4jezm3pq4uQDYRxJHoiDK/iYfxb0lPezj6jYHXJSHOK
         +r6N/jzdIfmfHzg3vBc4KQZuLQ95wblf1/O9igG0RIltxAWaFlElHtZG2c1sPXH/q+4S
         ewIDbjs+x7sQKFzIpwObv9PzO1OA09iioC7F1k6o6/AQvrHWYuRh9g79jMEOAcGIPDgU
         fG1sbpJ2ScQ/nvC0nAs6XEOa/3ZDc0cuYJ9xh0c6RDkcJ58Met80L2cwmiVYuE+XP5bK
         +JTOcqiVd9ryGtPu+bLnZ14LJvNwlrbIWiKvstpbQn6i2fsunbURNA+PtZ2HG+MNS4hn
         zNgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=/CV7sWZFpsZUJKiFW59NMAr+XYs7V77+EU4CbZX1s0I=;
        fh=sejwN7YCHGj7A+xJm6EhS5uoOy1LKX1RGqqyalzbjX0=;
        b=TGiU9JSIQdS+/GbSOLe3ROi4GPGNHMk3xDIlIwWQAiGCeBJf83xghlLD3r9W/6cI4P
         I4K/JW1HLYRzVmfSTC0LXMBoHmhTAoCFGUfIUXN3T8dnXtbsBiOYXti3V04Sy+dktsCI
         Z0X2JxuwVfn6z5K+LaazLqZMAGiwVh8WM5kWN0AZHrUS1fNseBIdFyb13d9Y1GY4T56c
         DexAo3ncciQQJh6ElEtALwWaHIjqyjBbuGFKBNFlEO/ZLL5/AHZI9r1VZyPAbmKyWaJd
         8aq/sDACdbn451UPTkWzTg0x9I12BkckI5R2/VDMVw7fo1iQCPpGI25iv4yLzZWKOVf3
         Bt2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rRQ75lu0;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899579; x=1746504379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/CV7sWZFpsZUJKiFW59NMAr+XYs7V77+EU4CbZX1s0I=;
        b=t0ytzHrjL3uFmFGcpSk5EqqAnrfTUrmpP6izeDyMhtN2ifWGnSZdjugHawIncukCys
         ieXbIcPZBtgN0aE/zt+rZX39ls/peKouY1zphzi3+JbIdPlW8R7MClXp+WTtyZkGYDLo
         LV1IuzOgazyjDey3+Vh6Fw5uFJfxeQKswinB3TBRrFKtXpoTVd5YoDuFa5Pg58hl6mmG
         7ajKc58plSbxjY3Do5ndfnKN0g7oFHcj1R1PKqnFFiVTwJrIzKuAXfWBUqwe6UG77KlZ
         fDlkGzjt2lUPByY/wWs/khzQAxUpTx+ZJeaoJx0u3xcGTfpXyJ7obQYGQ6TWTNVfWD2m
         lbCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899579; x=1746504379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/CV7sWZFpsZUJKiFW59NMAr+XYs7V77+EU4CbZX1s0I=;
        b=GZNlRYR5P6UnkqTWgWMT4lkApjwqFZ5sli7Q4qywXAfq/PJxyQIPQfglAh7tVjkW2b
         uOUCk7+04J3IB8i3JcYGGTqZ695Ccbk1GpkmiqZgJwgb78y0RCqtlMKeucqBDMLy1oXp
         T6fG5vr0qFZTY6Tjd9KeNri0209mQa07wqYHk3Ytks0zaOUuIJ2Zr+bMLwzsUMtv0gDS
         jRM47y6ZdfOWIJ/2oa7ySjxT8kNeAlQZ0JIU3dQciyI3LdXmga/rIo9ULOba59Pk+7Ul
         y8/dpwwww3EZsNYstWz58Elz2jb123MlwZRrb3Jb1coSMXs42UCgJJ+CYZFcI9CVwLsn
         g+ew==
X-Forwarded-Encrypted: i=2; AJvYcCUbf9iewOvltXZnl3UOGBxoWT/SYsrPhuG5sShiGUcnFiHKh/upoycrYx4GrwlGHpeDzZ0D5g==@lfdr.de
X-Gm-Message-State: AOJu0YyIfGEYZFpCeH3vMiGIN9YgAsESgx8WF+1xOIqWt+bxBcbmxNFE
	VrBZzhmO34qIrmVWSlHXlfdt/QSpZwpsEvcNTYm1R+00CuVASIw6
X-Google-Smtp-Source: AGHT+IFSpp2Fm2MVtupjKqhtG/IITalZkTjUSU3PVZLohgTH151Ol1gP3slut297vOq+eHpyaypL3w==
X-Received: by 2002:a17:90b:17c4:b0:309:fac6:44f9 with SMTP id 98e67ed59e1d1-30a013bcbc8mr15042681a91.31.1745899579357;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGFLieEv0HJlcusRBD0EDu7Ne8155pf+961wm96GZhOtQ==
Received: by 2002:a17:90b:2e4a:b0:301:c125:45b0 with SMTP id
 98e67ed59e1d1-309ebdf7be7ls1815562a91.2.-pod-prod-04-us; Mon, 28 Apr 2025
 21:06:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXY8vfdYbqtPW6YLqoIImsRU2lCPQXeNiwg1nsXGRpiHomCVM1LGMUhyAvj2jxcjUoYsZTW5+QOmtA=@googlegroups.com
X-Received: by 2002:a17:90b:2f10:b0:2fa:1e3e:9be5 with SMTP id 98e67ed59e1d1-30a0102977fmr18838810a91.0.1745899578184;
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899578; cv=none;
        d=google.com; s=arc-20240605;
        b=JbHRzSrnesCUy9O6jL0l54O2+jy5hln72u5NLkwQuoVTfQag0IZqJ7sbAm4hN4HULg
         AMQdJGXof+dTnfhwHhMG+TBlQ9FjsAb7emAshWCBmXFavUZZuDhzaOlbUFziFK3sBUc3
         Yr6mepBwwodeYjbmhOJ7LWaiZgyzR/Vhq8/2gQXnXmqkk6VnEWpv/AgrLWOdFXjqKmFf
         y8aIYg3JxbThzv2CwFyLa6x9IDhyMHOZuZNZt/mvljGHv//15IKyBR08ku6lGOQKEctK
         DDvpLF6k/G8oosfSPBd3bBODWGKJ9FOcZmedFX0gRLVxUIwZVpTPTfZ3kp+7NijaLCzS
         Mo9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from
         :dkim-signature;
        bh=n64EcHyNmqHMLJKJSLA0Q7usfRnpDI7HNDPkyY0l/1A=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=eD1QVUxA6/JDg08L3s2wwiqDkuPENGetK76Ax4iJ7JMQ9Nk34iS8K2aPzcTjiSFuwo
         sBGfW7sDwjh56y/bACYpr4Oxq9dinScU2Bheb49bYd9kXyjsxsastBXbKchaZ+sgOUEF
         ha25iGxrPjG8m0dXyJkTkzT/qUQ96p1xZ2kj46Dq11CaGbTuh6OxY+9m+lyVNA1WMlH5
         l8wP+7pCKgwcktYup8/in201ANLE0iLVYNsy3htyxNnAj4kwrhb3AZQA+R4w4nYu4/bj
         BmyqZxKh2sSd4LBihONPEPCec5+mIyWI9BUHpTmyQPGo5B7hE6u+NdIQyWzrg3rgXTLX
         S1Vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rRQ75lu0;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309ef0df342si395458a91.2.2025.04.28.21.06.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 557A94A2B1;
	Tue, 29 Apr 2025 04:06:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1D9C1C4CEF4;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id 13BE0C3ABA8;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Apr 2025 12:06:09 +0800
Subject: [PATCH RFC v3 5/8] rseq: add __always_inline for
 rseq_kernel_fields
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250429-noautoinline-v3-5-4c49f28ea5b5@uniontech.com>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
In-Reply-To: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
To: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, 
 Christoph Hellwig <hch@lst.de>, Sagi Grimberg <sagi@grimberg.me>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
 Kevin Tian <kevin.tian@intel.com>, 
 Alex Williamson <alex.williamson@redhat.com>, 
 Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
 Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, 
 Michal Hocko <mhocko@suse.com>, Brendan Jackman <jackmanb@google.com>, 
 Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Peter Zijlstra <peterz@infradead.org>, 
 "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
 Juergen Gross <jgross@suse.com>, 
 Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
Cc: linux-nvme@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linux-mm@kvack.org, kvm@vger.kernel.org, virtualization@lists.linux.dev, 
 linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org, 
 llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>, 
 kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org, 
 Chen Linxuan <chenlinxuan@uniontech.com>, 
 Changbin Du <changbin.du@intel.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=openpgp-sha256; l=1064;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=yuauFI3DVy8k9g1XQ1OrB7eESWm7f+B3/2pt9syGKzM=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFAyanc3Cwc7HAg/63YHY6NNSEBN2RhZfPBtP
 dtxoPOqXNeJAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQMgAKCRB2HuYUOZmu
 i7aID/44sv/mzy4WT2GTGw2LDhzFHfM+7rL13wS9xt+G7CMG4l6A0rduPv9Kj1+aTi8eOVMJft5
 5TiNxVdcrGKSr3zwVOY/PNRlc66oIZlthPkrupbFv0SD5r0m5xlYv9Q9WAMMOLU1a+CKw7KXlIK
 zUkQ0dGZaFEhfFS3giTzwyMqJS6nvmjb5iRc4Zz/XOtdtIIBsD6qlLRwQDdV4KuiKgfabOvMbeX
 C/d2ZrlzN8bw8uBY9bJS4LF4cptR+kay58eEnIn86mc9en18eq/l2Y01BEqmDWaad6N+FJDodwI
 pMr/+GVr6bsXlGZJ+sULeKleGffl4G1zIhAoz7H8I0oNmr/nSGd3Wn6BKIxuLhtVppnLY1KsvGa
 yf2RsSmPzJHLCXkfpLhDD/oicoxFl43gpHqaND1YU47v6537LXhTaUC1wslQX7j/d1+ujI4YwtF
 vOr8GQoQM+gOCkSVJLMdhN73NjDBDQByqvsYdot/uoc2GscYToCLN6G8w6S/yE1iwgbv9J0upsK
 hCjXyMYy0yLyfeIMCV/s3OTjYIs2fkUTwhR/5ByE/gU+4GGrFSrBbZP1FArrKKo834SUQ98QfUi
 V+gTyYTxvmL/HMhC3LP7oMkp9BWNsUvbCEi3F0KTEm/YPo52etQ+1LPa6z6VqhkHXnGwZSJcPtW
 crGc2BctRQzKvsw==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rRQ75lu0;       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender)
 smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Chen Linxuan via B4 Relay <devnull+chenlinxuan.uniontech.com@kernel.org>
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

From: Chen Linxuan <chenlinxuan@uniontech.com>

Presume that kernel is compiled for x86_64 with gcc version 13.3.0:

  make allmodconfig
  make KCFLAGS="-fno-inline-small-functions -fno-inline-functions-called-once"

This results some objtool warnings:

  vmlinux.o: warning: objtool: rseq_update_cpu_node_id+0x14c: call to rseq_kernel_fields() with UACCESS enabled
  vmlinux.o: warning: objtool: rseq_reset_rseq_cpu_node_id+0xef: call to rseq_kernel_fields() with UACCESS enabled

Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
---
 kernel/rseq.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/rseq.c b/kernel/rseq.c
index b7a1ec327e8117b47e353cab92d62111dd261520..7a4b6c211359714087a753047581bc8ff0c6c76b 100644
--- a/kernel/rseq.c
+++ b/kernel/rseq.c
@@ -27,7 +27,7 @@
 				  RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE)
 
 #ifdef CONFIG_DEBUG_RSEQ
-static struct rseq *rseq_kernel_fields(struct task_struct *t)
+static __always_inline struct rseq *rseq_kernel_fields(struct task_struct *t)
 {
 	return (struct rseq *) t->rseq_fields;
 }

-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-5-4c49f28ea5b5%40uniontech.com.
