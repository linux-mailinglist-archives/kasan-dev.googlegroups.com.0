Return-Path: <kasan-dev+bncBCD353VB3ABBBPFAYHAAMGQECJG7AAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DD00AA0118
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:21 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e905e89798sf103191686d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899580; cv=pass;
        d=google.com; s=arc-20240605;
        b=MS+07UrrGNavB3jlvreRnOZFCGIK5a10UvZ08fIIwqMoGmWLCk8yldxHeEHpXTU5bV
         kwWRtboLc2Xvo2ouh8kTBOurUtgRadWX0o2uND8294cvk5bjLn7Ze/i2TtNRAKvOyYe9
         4bGJcK8lzqGjDevV5lFHJqoui9SX2JsiOBEpED/bAR9mAIxgBxIWtp6PJbKRLRURQwu1
         SwIHxhKuiHx0e3ziz043ZlztqIkuL2+3xPufiUouqsc+H6YLwgIScewoLe0C3xIV8bEh
         wQ4jvicDiUGvubcyjtyvqEOiUXp3KTjSM8QpWuK+ftvmT2IbZX0OGMtcS9Lo2PyFTpxS
         ct3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=6visy6AcZ7uALaM9ZGNPCeErShE6ZeQykg2MuQxzKDc=;
        fh=0JJNhfSoXVDm0vWTyRFYSMqYqkhCNMAuCT294Wac1Eg=;
        b=BlcvMwABvtR6DjKRoeB/kaUEzfJvrbOykqVCjZKpRWZUOx7m1zqrCZx8s3ydSUyZQq
         CiTpKxaO/PW+JFYqjGZ5ZTYwb55s6CyfofY0NhpVlUWvIjkuS+H92QAAElCDZTi4Ov56
         Z4eFwvR2+T2hSZXWoR45RHiFSwiFPOPte6dqd1OTnPG03J7c3u3vcx2p9L/56Uk/W56U
         SA/k4EiiaQ7Vns+P/SQyDDCDXvPG6ZYlX5t6hwDQJcpVEmUZfNLG8hS7LEKw7dsDzjFR
         p6rXvCcb/JmyHzHiK4iqdMxNKzIv/ikwaGjWMVyNpzB6Jb9MvWii7GcyEjQIIUB7dV6h
         Qjbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="sl1R/QSS";
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899580; x=1746504380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6visy6AcZ7uALaM9ZGNPCeErShE6ZeQykg2MuQxzKDc=;
        b=UMuz/IoYFalwClwooSX7gbVndlK4iMRpltix/lI8xoVAWg0WYHtt4pDWbX1swZ2RMY
         Er0H9/s0yr3VWzTwkd5XJ3mYjQ5soncFP5VLIGcg0hPu7xi/zcoyQnPesKC7vmnZ6bxP
         YK+MGyrzSHULArRhOTAGADMoUBZH8OBzktt5msx/GiNrip5xhT7n1REAwxHJXmIcZJOV
         mWRJc7p+XWXIKWzRWsWuAK+uOqdjbGN2nmL8VKPVWZG3lPCToeLxHqvroxzXoAnCPtdE
         X+ABSyiIeDRO29N4A1tDFPnl5QI29CFxWQYK68meqrHBESAtvCSay+l1qAiouRuzMiCw
         u2Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899580; x=1746504380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6visy6AcZ7uALaM9ZGNPCeErShE6ZeQykg2MuQxzKDc=;
        b=wyuFO2ZHMPIioWD/qA9MbdWDo9Vh7ld5pSqlzKtDF5M5yMCgezrqk9pdIICIBen59M
         wNOlfdXfr6dryhMgdBUkt9ZDX8/joFKz96Mv/JhgwlqFZD8bfWojNIvTWubGF0ke3/S+
         KwubNld0xY7cwWgEu04RAfUVneh4kgO3rf8Qg49K54/fWVHOGNbqAxeQb7RG1J9cL438
         328nOOTQPUb0M5IHc32yWeM/QU8xGAE+PJA/X8KnE8ks53NWb7y5M64Q9qk/wgOwsak/
         Vl3dx+iALVKlt4nplTJnySaBy5AJFwAthET/NmE/SE3GR94BKqTNOGmPUqP028FP/uDh
         6Qgg==
X-Forwarded-Encrypted: i=2; AJvYcCWztqX4M3PZS2gb4h3oc8v6ILuUSLH6yf3i8w/0RTuzTNlTyclnd0vyjipqHpEBZ7loSTz8PA==@lfdr.de
X-Gm-Message-State: AOJu0Yxy+Bg5yyWo6o78k/Mr+bs6tHOIhu37ELugb+wqQ5d94uYvgUPZ
	44N34LDiiANjRbuMNSHD9Pdm1iAoYGW1YTqXkDf+/gnRRgPOvyL+
X-Google-Smtp-Source: AGHT+IG8leclMCZh3/GwRUUtUs7NAJ2uMNWdEod/nf8mfpADsF0fRSbkpio026l/LvgPBngybapCeg==
X-Received: by 2002:a05:6214:5296:b0:6e4:2dd7:5c88 with SMTP id 6a1803df08f44-6f4f27d8734mr23148366d6.38.1745899580308;
        Mon, 28 Apr 2025 21:06:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBF5MJhDSUNN703pp1/G26zGGB8iPUIUWf5rkZhBDnk7eQ==
Received: by 2002:a0c:e60b:0:b0:6e8:efc0:7a3f with SMTP id 6a1803df08f44-6f4be39613als3694846d6.2.-pod-prod-03-us;
 Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrCgjgjSB0x9mTKI8zLgdP+4szQ+Z1IyGvFbgmK6mmztmAq18YqhnSVizBBW3YC0rTe072p5N9A5w=@googlegroups.com
X-Received: by 2002:a05:6214:da8:b0:6f2:d367:56bf with SMTP id 6a1803df08f44-6f4f27ac006mr22056816d6.31.1745899579243;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899579; cv=none;
        d=google.com; s=arc-20240605;
        b=C5S5MustVPF761u2iga2Xvln+paIE/+QwvAdwIjb3pZziCCTZ1qgUKhYilL0+cQNVZ
         lG9bZOpR6LpxZEhF2iJD4s5kDhFoGWRiLIdFrZ+Nah3g3M4hPEUO/OtYpcikKjB56yTD
         NDNoJfvFo0dCPEGZaqaJ5EyH5LPMb82AXLTEbinhszngY/436ipmXxyoI757aSYesHj5
         W80TF4jeE2RSvOYB6A01BiuEK5fcRyhQU7iX8WnXJUIJVeyjSu4UR8fEo1Bn1ju2IdOX
         ShUsh5WATV/D8KXM6IAU0w31sJXGKHaNo5+1g/7w5/4UcdaLIL2fYnz+adnzqn+R6F/d
         Azpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from
         :dkim-signature;
        bh=Reu8quFzfIk3PDBhseb0c38gdBeN3aa/4QPg2QcShuE=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=dSqU7/5BG5eeyg+L1thcg0yFKmME5E7gZjSQ3vvIkFbzuHptNLIMM9+bXcOqoUZqhl
         7hfQZntcjCxG76aP0vb867zzfcif5fD1OwJASUD4/cMi8d9EenmZ5dzGV2WasvphdrA4
         MSYLdXTbJOKr3GkzVEytPSmUEy0B3tH5/3czRM6K0yVW1IL2unrxXspB+6fgJQ3sbvlC
         /DaNtjsk79Y095irL20blPehoClTntfYaNnfQX/2GPFZxUO0gZtE3sdwN3OYl36q3b9F
         DZCiM0cItlpKDJW+bL2Bao+/8ImT46PIw/Gc1D4IVSPaQlYTyBwLV+pAHCzZEP4HHQ+n
         H6fA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="sl1R/QSS";
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f4e082c129si660316d6.1.2025.04.28.21.06.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5FDD04A2BA;
	Tue, 29 Apr 2025 04:06:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 32BAAC16AAE;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id 25755C3ABA5;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Apr 2025 12:06:10 +0800
Subject: [PATCH RFC v3 6/8] kcov: add __always_inline for canonicalize_ip
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250429-noautoinline-v3-6-4c49f28ea5b5@uniontech.com>
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
X-Developer-Signature: v=1; a=openpgp-sha256; l=999;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=bu46wuQGrDj6kBvEdZGeSh/hu1kfUprs2xtOHC9YvDM=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFAzBVNZPkSl6Omnu5oU34AQK+1mpqi/WLkNr
 0NEvxK8dUyJAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQMwAKCRB2HuYUOZmu
 i8g1D/40bhkDUMn5ZsiK4TnuOugcii2OnZKhTkti9V/LWWRvgzRyIsQwQx4FtXYSoLWNriV0VjO
 CyBhHFDEFDn9Qz/M965AcIUUmKLR5grVtMB9zo5zCc6a91HPJy6GMCb7vQWZAzb4+pWGKnhvAMx
 Ov0wOqEkIfqqFMjOVcO8Vm4hfpv/gUj81gfM3GBjvGd2OHSGu5Pij0pZYLJpk1zPwPTmvDqrsz4
 oYuo8iGnQFrGPoCp8bulBU2twHYxidXZqedbEM/1LtFaKcmn/lXQC7zQRnMoVVJw/VWRJEm3H/r
 ZAZEvQW29nAzq7hH4vvQnts2FtjI834A3qFtxQn63CS2Sfr4r+Cq1EuVsao/7MSVIED9IWykpk7
 4zxistnA1wTl+9FGo+ICJdWpP4NFZYJXYzFIo2tProekWZDMySQIIR8PlepBYAhmPBM4brAn4p+
 6EeroMTKyY8ruNjdDNz7d2T4eCWNT79QPnCWQnqqQnu6en7oxsQ2nWq0yCWUgq6PiInxlG1IrOp
 ws0NDutFTcctb93F/sUKWR8fxwjFNCr2kJf2YNiq9h6vsJ5kJf0v5kwbgfSvV4AJmDUqbWsjulX
 AA7Pwu8V0FCWq4C/mflHXRlVyt5MBdGeteRJDx/xMeppywk4M4UANlKUX+SDfpwBq2fbdtOztNl
 do0e6Yl/yQUEHnA==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="sl1R/QSS";       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

This results a objtool warning:

  vmlinux.o: warning: objtool: __sanitizer_cov_trace_pc+0xc: call to canonicalize_ip() with UACCESS enabled

Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
---
 kernel/kcov.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 187ba1b80bda169d2f7efead5c6076b8829522ca..a2e2d3c655406b5a1f53e4855c782727b0541935 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -194,7 +194,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	return mode == needed_mode;
 }
 
-static notrace unsigned long canonicalize_ip(unsigned long ip)
+static __always_inline notrace unsigned long canonicalize_ip(unsigned long ip)
 {
 #ifdef CONFIG_RANDOMIZE_BASE
 	ip -= kaslr_offset();

-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-6-4c49f28ea5b5%40uniontech.com.
