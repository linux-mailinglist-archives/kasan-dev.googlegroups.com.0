Return-Path: <kasan-dev+bncBCLI747UVAFRBE6TQGNAMGQE5KL2RPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id BC1995F7CB9
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 20:01:57 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id s15-20020a63524f000000b0043891d55a30sf3212205pgl.16
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 11:01:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665165716; cv=pass;
        d=google.com; s=arc-20160816;
        b=L/YGfWXsf5ln3zEqjp60aODPJsNkR3vSvFUNN3l/YJUDRZK9ePmcAJpqxamqetg1c4
         1hZk1cfNw2gqcNGFkYEzDChquXfcIhKjd5Cz4I3SdKmh7U7wcyPb1HtOO0rmSAlOqwfS
         dRPJVwLmYfKzo6jdSDseKKH0Uz775uDRmKazQpIpDh8ssWGB2X1mWFYtolr2k8bR5MCk
         Tb0um5U8nLMztV4I4RDKQ60B2SIVB5WMRogB/4KP83MkB57L1X7H0JFs1wM8He4Z7tlY
         20ce3ks5PANhracdiI0uJhrZDDJAU9yNryKBX+3yA7X3855SoDuGMNYkKQM0WsRFdKZd
         cx3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=kjsx3LqCRQEVh9S2P7WtGqZr90xOyg2UnHrBiVMg6xs=;
        b=MndjBYmIGeareNa/4FRx7S6IourmgkVgGBCWQ1XAPkCsctGOMVGsKnhrYP2zdAQ4or
         zwdRVZz1FGxE2k4eYStjgb/3YAkqT0mQQB6c4Wzlm65UToGhBvd3NMmhgdipG9826uHA
         N6FRPcnHqImPiONsqz5UOT8lKsevvCIiFTgUFjgoXQ9PfgggR88phgsJcP8ghAdX3TdG
         NTsMbQ6B95DtYJNFbaE6sZh74yNSRWInKWyOBS/gUmFBb2KmLG7g22PJBYp8DHchoUSQ
         A9qEGruNrZBLgeYiPQ4480wNqBRpXsa6k+FBNTMuqLTpt+hEh7hgZ49cwBp1YO7bVpE9
         jVFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=gIpGeUR7;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kjsx3LqCRQEVh9S2P7WtGqZr90xOyg2UnHrBiVMg6xs=;
        b=LNMvzFY5u+fVo4t1MEoS9IzKBo73jQeljedMiQ1/S1ZpcDj3iGKCkLjjayJDE8HS+4
         F4KjYm40gYy99D/swFjmuOYc2Jf102PYbtWGY7RAuZuIN0mxWlJWU9vjJ3iML749n++4
         5oB0/WwE4EcHnR5w1LEgq4WQRhX021VTrFK5Xl7KhloaihD6XCvRQbpGCmsmfAVlJVIG
         7BPEMSViqJufURrz5xTd9LsW3rdxr9iyMOF7DkP5VOmcAon60OlthFNLKKtvdrl2z0Zw
         ZTtiYEiznPnsSYlKmFkgwgBNXFlm3kkMMO5ZGAIbr7LPVpbvjwtoLIbVbmLvQ1tNVb/E
         P22w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kjsx3LqCRQEVh9S2P7WtGqZr90xOyg2UnHrBiVMg6xs=;
        b=F/LUdlpSMHvOb5D89v94zkx8ayaRDqxyBfOYawKZd+gpOkdOK0anEIoWDjaBVyeRy6
         I7l9BEDE0hFxp42QTmYKdhRb7pvx73chV/JbWF6yYBOBESz8ZTrmbHVsrWZ5kJoff5jv
         O0DTFCLYtOG142vGr+yDHJxNWDYZWsz22izOfjqJE6+BHZ/6NcV5s03sWEq1KyV+XD0C
         sCycsQZrt7oFFq3vxFxKZe+0+bovxY03URqy6Hdx1ygyLQu8Rv/+d+rBxLe7Lmmeq0aZ
         nc1DNgYRSeRzoJ2uRxNwNjLvJIaEJBlo5TGt1LSdNWm0vgs+nxuxz22Y12WEXyViDIS4
         PjJw==
X-Gm-Message-State: ACrzQf1tDOx0QlF+7yhK5xBsiRtD5/OODI4tOvxX0kUlDoj0Vkunm+gJ
	x23izv0UNNx/RQ4Z+tmQb+I=
X-Google-Smtp-Source: AMsMyM7imneENx9tTvljARGQaLqHE3tBJREDFaKrhymVlziWP4nDE8jBfIQxPkezWDDP+SLS/xutjg==
X-Received: by 2002:a17:902:9049:b0:180:7922:ce36 with SMTP id w9-20020a170902904900b001807922ce36mr1789215plz.30.1665165715854;
        Fri, 07 Oct 2022 11:01:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2284:b0:178:29a3:df47 with SMTP id
 b4-20020a170903228400b0017829a3df47ls4188283plh.7.-pod-prod-gmail; Fri, 07
 Oct 2022 11:01:55 -0700 (PDT)
X-Received: by 2002:a17:90b:4c46:b0:202:b9c5:2f24 with SMTP id np6-20020a17090b4c4600b00202b9c52f24mr16804743pjb.180.1665165715036;
        Fri, 07 Oct 2022 11:01:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665165715; cv=none;
        d=google.com; s=arc-20160816;
        b=YwXcK7T882xTE7EgJ59GP1bIWO22k56Fb8Dtja5ZuWS2cNyYVl3mCKZ2BgE64JocN5
         oB5Chd7ECHWuUhxm5QVLGNet/X3I/ikGNgHIse3e/Exd8TxRNmstYSKS69cytgPhoe9f
         ryLS/q84GAIRV0OFv4O9nDuwSERCf6nz9OiMiokyo6MwH9C4STj0M8mJ01yrTxnuWXN3
         b1jtfayf3x2StokUiyWhamfEgz2WNFhk4Helg99RnO9Fu4PR7XAqDNFXjTObfOT9BwGl
         FuX3IkNnZlRdnLZRjYxxxFF2jmQDck218uxTaHwgesYmrhMYeDOxrGohveyzrnsar/JZ
         ILgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=g2hIaC3XOM+KBWgkgbeW6UolDFW2WI2qSTHxKo7C8lY=;
        b=QSohpYrlaA/Jt3gmRxRNEelOUGF9NcCKc5vFfPpKZT3kERZ+zeLpFwqyF7nbd5p5Zc
         pPwnvS1mntuGtL8eKq96duO49vdVIoBZUmtFYDUuAmeVeyxK/L/W3DBgJhRGkQ3RkBLz
         B/wCPVINj5UeeurzdWnyXSbSO3BIGJpZ6bY5Urf3XMm93bbA8cOP3dZEKu+gg7PswlqC
         mqdqw+h6rad5YEjk6bSwt9GEQ1QOzTkiKs6PAjJaQuObcTOkpCpgKTbqFV2A1mQnyfGJ
         vvpC7oklFwhAYyfDnBFqDL0oOvpJQXhePkSIPOkiUXtmGz/NCZWHlBkpVrIi/gExj1AN
         UNrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=gIpGeUR7;
       spf=pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d72-20020a63364b000000b00423291dc756si92773pga.5.2022.10.07.11.01.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 11:01:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7377861A30;
	Fri,  7 Oct 2022 18:01:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3A591C433D6;
	Fri,  7 Oct 2022 18:01:48 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 05093213 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Fri, 7 Oct 2022 18:01:46 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	patches@lists.linux.dev
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	=?UTF-8?q?Christoph=20B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>,
	Theodore Ts'o <tytso@mit.edu>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	WANG Xuerui <kernel@xen0n.name>,
	Will Deacon <will@kernel.org>,
	Yury Norov <yury.norov@gmail.com>,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org,
	linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev,
	netdev@vger.kernel.org,
	sparclinux@vger.kernel.org,
	x86@kernel.org,
	=?UTF-8?q?Toke=20H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>
Subject: [PATCH v4 3/6] treewide: use get_random_{u8,u16}() when possible
Date: Fri,  7 Oct 2022 12:01:04 -0600
Message-Id: <20221007180107.216067-4-Jason@zx2c4.com>
In-Reply-To: <20221007180107.216067-1-Jason@zx2c4.com>
References: <20221007180107.216067-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=gIpGeUR7;       spf=pass
 (google.com: domain of srs0=jvfi=2i=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=JVfI=2I=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

Rather than truncate a 32-bit value to a 16-bit value or an 8-bit value,
simply use the get_random_{u8,u16}() functions, which are faster than
wasting the additional bytes from a 32-bit value.

Reviewed-by: Kees Cook <keescook@chromium.org>
Acked-by: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk> # for sch_cake
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 arch/arm/kernel/signal.c                                  | 2 +-
 arch/arm64/kernel/syscall.c                               | 2 +-
 arch/s390/kernel/process.c                                | 2 +-
 arch/sparc/vdso/vma.c                                     | 2 +-
 crypto/testmgr.c                                          | 8 ++++----
 drivers/media/common/v4l2-tpg/v4l2-tpg-core.c             | 2 +-
 drivers/media/test-drivers/vivid/vivid-radio-rx.c         | 4 ++--
 .../net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c   | 2 +-
 drivers/net/hamradio/baycom_epp.c                         | 2 +-
 drivers/net/hamradio/hdlcdrv.c                            | 2 +-
 drivers/net/hamradio/yam.c                                | 2 +-
 drivers/net/wireguard/selftest/allowedips.c               | 4 ++--
 drivers/net/wireless/st/cw1200/wsm.c                      | 2 +-
 drivers/scsi/lpfc/lpfc_hbadisc.c                          | 6 +++---
 lib/cmdline_kunit.c                                       | 4 ++--
 lib/test_vmalloc.c                                        | 2 +-
 net/dccp/ipv4.c                                           | 4 ++--
 net/ipv4/datagram.c                                       | 2 +-
 net/ipv4/ip_output.c                                      | 2 +-
 net/ipv4/tcp_ipv4.c                                       | 4 ++--
 net/mac80211/scan.c                                       | 2 +-
 net/netfilter/nf_nat_core.c                               | 4 ++--
 net/sched/sch_cake.c                                      | 6 +++---
 net/sched/sch_sfb.c                                       | 2 +-
 net/sctp/socket.c                                         | 2 +-
 25 files changed, 38 insertions(+), 38 deletions(-)

diff --git a/arch/arm/kernel/signal.c b/arch/arm/kernel/signal.c
index ea128e32e8ca..e07f359254c3 100644
--- a/arch/arm/kernel/signal.c
+++ b/arch/arm/kernel/signal.c
@@ -655,7 +655,7 @@ struct page *get_signal_page(void)
 		 PAGE_SIZE / sizeof(u32));
=20
 	/* Give the signal return code some randomness */
-	offset =3D 0x200 + (get_random_int() & 0x7fc);
+	offset =3D 0x200 + (get_random_u16() & 0x7fc);
 	signal_return_offset =3D offset;
=20
 	/* Copy signal return handlers into the page */
diff --git a/arch/arm64/kernel/syscall.c b/arch/arm64/kernel/syscall.c
index 733451fe7e41..d72e8f23422d 100644
--- a/arch/arm64/kernel/syscall.c
+++ b/arch/arm64/kernel/syscall.c
@@ -67,7 +67,7 @@ static void invoke_syscall(struct pt_regs *regs, unsigned=
 int scno,
 	 *
 	 * The resulting 5 bits of entropy is seen in SP[8:4].
 	 */
-	choose_random_kstack_offset(get_random_int() & 0x1FF);
+	choose_random_kstack_offset(get_random_u16() & 0x1FF);
 }
=20
 static inline bool has_syscall_work(unsigned long flags)
diff --git a/arch/s390/kernel/process.c b/arch/s390/kernel/process.c
index 5ec78555dd2e..42af4b3aa02b 100644
--- a/arch/s390/kernel/process.c
+++ b/arch/s390/kernel/process.c
@@ -230,7 +230,7 @@ unsigned long arch_align_stack(unsigned long sp)
=20
 static inline unsigned long brk_rnd(void)
 {
-	return (get_random_int() & BRK_RND_MASK) << PAGE_SHIFT;
+	return (get_random_u16() & BRK_RND_MASK) << PAGE_SHIFT;
 }
=20
 unsigned long arch_randomize_brk(struct mm_struct *mm)
diff --git a/arch/sparc/vdso/vma.c b/arch/sparc/vdso/vma.c
index cc19e09b0fa1..04ee726859ca 100644
--- a/arch/sparc/vdso/vma.c
+++ b/arch/sparc/vdso/vma.c
@@ -354,7 +354,7 @@ static unsigned long vdso_addr(unsigned long start, uns=
igned int len)
 	unsigned int offset;
=20
 	/* This loses some more bits than a modulo, but is cheaper */
-	offset =3D get_random_int() & (PTRS_PER_PTE - 1);
+	offset =3D get_random_u16() & (PTRS_PER_PTE - 1);
 	return start + (offset << PAGE_SHIFT);
 }
=20
diff --git a/crypto/testmgr.c b/crypto/testmgr.c
index be45217acde4..981c637fa2ed 100644
--- a/crypto/testmgr.c
+++ b/crypto/testmgr.c
@@ -927,7 +927,7 @@ static void generate_random_bytes(u8 *buf, size_t count=
)
 			b =3D 0xff;
 			break;
 		default:
-			b =3D (u8)prandom_u32();
+			b =3D get_random_u8();
 			break;
 		}
 		memset(buf, b, count);
@@ -935,8 +935,8 @@ static void generate_random_bytes(u8 *buf, size_t count=
)
 		break;
 	case 2:
 		/* Ascending or descending bytes, plus optional mutations */
-		increment =3D (u8)prandom_u32();
-		b =3D (u8)prandom_u32();
+		increment =3D get_random_u8();
+		b =3D get_random_u8();
 		for (i =3D 0; i < count; i++, b +=3D increment)
 			buf[i] =3D b;
 		mutate_buffer(buf, count);
@@ -944,7 +944,7 @@ static void generate_random_bytes(u8 *buf, size_t count=
)
 	default:
 		/* Fully random bytes */
 		for (i =3D 0; i < count; i++)
-			buf[i] =3D (u8)prandom_u32();
+			buf[i] =3D get_random_u8();
 	}
 }
=20
diff --git a/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c b/drivers/media/=
common/v4l2-tpg/v4l2-tpg-core.c
index 9b7bcdce6e44..303d02b1d71c 100644
--- a/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c
+++ b/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c
@@ -870,7 +870,7 @@ static void precalculate_color(struct tpg_data *tpg, in=
t k)
 		g =3D tpg_colors[col].g;
 		b =3D tpg_colors[col].b;
 	} else if (tpg->pattern =3D=3D TPG_PAT_NOISE) {
-		r =3D g =3D b =3D prandom_u32_max(256);
+		r =3D g =3D b =3D get_random_u8();
 	} else if (k =3D=3D TPG_COLOR_RANDOM) {
 		r =3D g =3D b =3D tpg->qual_offset + prandom_u32_max(196);
 	} else if (k >=3D TPG_COLOR_RAMP) {
diff --git a/drivers/media/test-drivers/vivid/vivid-radio-rx.c b/drivers/me=
dia/test-drivers/vivid/vivid-radio-rx.c
index 232cab508f48..8bd09589fb15 100644
--- a/drivers/media/test-drivers/vivid/vivid-radio-rx.c
+++ b/drivers/media/test-drivers/vivid/vivid-radio-rx.c
@@ -104,8 +104,8 @@ ssize_t vivid_radio_rx_read(struct file *file, char __u=
ser *buf,
 				break;
 			case 2:
 				rds.block |=3D V4L2_RDS_BLOCK_ERROR;
-				rds.lsb =3D prandom_u32_max(256);
-				rds.msb =3D prandom_u32_max(256);
+				rds.lsb =3D get_random_u8();
+				rds.msb =3D get_random_u8();
 				break;
 			case 3: /* Skip block altogether */
 				if (i)
diff --git a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c b/=
drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
index ddfe9208529a..ac452a0111a9 100644
--- a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
+++ b/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
@@ -1467,7 +1467,7 @@ static void make_established(struct sock *sk, u32 snd=
_isn, unsigned int opt)
 	tp->write_seq =3D snd_isn;
 	tp->snd_nxt =3D snd_isn;
 	tp->snd_una =3D snd_isn;
-	inet_sk(sk)->inet_id =3D prandom_u32();
+	inet_sk(sk)->inet_id =3D get_random_u16();
 	assign_rxopt(sk, opt);
=20
 	if (tp->rcv_wnd > (RCV_BUFSIZ_M << 10))
diff --git a/drivers/net/hamradio/baycom_epp.c b/drivers/net/hamradio/bayco=
m_epp.c
index 7df78a721b04..791b4a53d69f 100644
--- a/drivers/net/hamradio/baycom_epp.c
+++ b/drivers/net/hamradio/baycom_epp.c
@@ -438,7 +438,7 @@ static int transmit(struct baycom_state *bc, int cnt, u=
nsigned char stat)
 			if ((--bc->hdlctx.slotcnt) > 0)
 				return 0;
 			bc->hdlctx.slotcnt =3D bc->ch_params.slottime;
-			if (prandom_u32_max(256) > bc->ch_params.ppersist)
+			if (get_random_u8() > bc->ch_params.ppersist)
 				return 0;
 		}
 	}
diff --git a/drivers/net/hamradio/hdlcdrv.c b/drivers/net/hamradio/hdlcdrv.=
c
index 360d041a62c4..6c6f11d3d0aa 100644
--- a/drivers/net/hamradio/hdlcdrv.c
+++ b/drivers/net/hamradio/hdlcdrv.c
@@ -377,7 +377,7 @@ void hdlcdrv_arbitrate(struct net_device *dev, struct h=
dlcdrv_state *s)
 	if ((--s->hdlctx.slotcnt) > 0)
 		return;
 	s->hdlctx.slotcnt =3D s->ch_params.slottime;
-	if (prandom_u32_max(256) > s->ch_params.ppersist)
+	if (get_random_u8() > s->ch_params.ppersist)
 		return;
 	start_tx(dev, s);
 }
diff --git a/drivers/net/hamradio/yam.c b/drivers/net/hamradio/yam.c
index 97a6cc5c7ae8..2ed2f836f09a 100644
--- a/drivers/net/hamradio/yam.c
+++ b/drivers/net/hamradio/yam.c
@@ -626,7 +626,7 @@ static void yam_arbitrate(struct net_device *dev)
 	yp->slotcnt =3D yp->slot / 10;
=20
 	/* is random > persist ? */
-	if (prandom_u32_max(256) > yp->pers)
+	if (get_random_u8() > yp->pers)
 		return;
=20
 	yam_start_tx(dev, yp);
diff --git a/drivers/net/wireguard/selftest/allowedips.c b/drivers/net/wire=
guard/selftest/allowedips.c
index 41db10f9be49..dd897c0740a2 100644
--- a/drivers/net/wireguard/selftest/allowedips.c
+++ b/drivers/net/wireguard/selftest/allowedips.c
@@ -310,7 +310,7 @@ static __init bool randomized_test(void)
 			for (k =3D 0; k < 4; ++k)
 				mutated[k] =3D (mutated[k] & mutate_mask[k]) |
 					     (~mutate_mask[k] &
-					      prandom_u32_max(256));
+					      get_random_u8());
 			cidr =3D prandom_u32_max(32) + 1;
 			peer =3D peers[prandom_u32_max(NUM_PEERS)];
 			if (wg_allowedips_insert_v4(&t,
@@ -354,7 +354,7 @@ static __init bool randomized_test(void)
 			for (k =3D 0; k < 4; ++k)
 				mutated[k] =3D (mutated[k] & mutate_mask[k]) |
 					     (~mutate_mask[k] &
-					      prandom_u32_max(256));
+					      get_random_u8());
 			cidr =3D prandom_u32_max(128) + 1;
 			peer =3D peers[prandom_u32_max(NUM_PEERS)];
 			if (wg_allowedips_insert_v6(&t,
diff --git a/drivers/net/wireless/st/cw1200/wsm.c b/drivers/net/wireless/st=
/cw1200/wsm.c
index 5a3e7a626702..4a9e4b5d3547 100644
--- a/drivers/net/wireless/st/cw1200/wsm.c
+++ b/drivers/net/wireless/st/cw1200/wsm.c
@@ -1594,7 +1594,7 @@ static int cw1200_get_prio_queue(struct cw1200_common=
 *priv,
 		edca =3D &priv->edca.params[i];
 		score =3D ((edca->aifns + edca->cwmin) << 16) +
 			((edca->cwmax - edca->cwmin) *
-			 (get_random_int() & 0xFFFF));
+			 get_random_u16());
 		if (score < best && (winner < 0 || i !=3D 3)) {
 			best =3D score;
 			winner =3D i;
diff --git a/drivers/scsi/lpfc/lpfc_hbadisc.c b/drivers/scsi/lpfc/lpfc_hbad=
isc.c
index 2645def612e6..26d1779cb570 100644
--- a/drivers/scsi/lpfc/lpfc_hbadisc.c
+++ b/drivers/scsi/lpfc/lpfc_hbadisc.c
@@ -2150,8 +2150,8 @@ lpfc_check_pending_fcoe_event(struct lpfc_hba *phba, =
uint8_t unreg_fcf)
  * This function makes an running random selection decision on FCF record =
to
  * use through a sequence of @fcf_cnt eligible FCF records with equal
  * probability. To perform integer manunipulation of random numbers with
- * size unit32_t, the lower 16 bits of the 32-bit random number returned
- * from prandom_u32() are taken as the random random number generated.
+ * size unit32_t, a 16-bit random number returned from get_random_u16() is
+ * taken as the random random number generated.
  *
  * Returns true when outcome is for the newly read FCF record should be
  * chosen; otherwise, return false when outcome is for keeping the previou=
sly
@@ -2163,7 +2163,7 @@ lpfc_sli4_new_fcf_random_select(struct lpfc_hba *phba=
, uint32_t fcf_cnt)
 	uint32_t rand_num;
=20
 	/* Get 16-bit uniform random number */
-	rand_num =3D 0xFFFF & prandom_u32();
+	rand_num =3D get_random_u16();
=20
 	/* Decision with probability 1/fcf_cnt */
 	if ((fcf_cnt * rand_num) < 0xFFFF)
diff --git a/lib/cmdline_kunit.c b/lib/cmdline_kunit.c
index a72a2c16066e..d4572dbc9145 100644
--- a/lib/cmdline_kunit.c
+++ b/lib/cmdline_kunit.c
@@ -76,7 +76,7 @@ static void cmdline_test_lead_int(struct kunit *test)
 		int rc =3D cmdline_test_values[i];
 		int offset;
=20
-		sprintf(in, "%u%s", get_random_int() % 256, str);
+		sprintf(in, "%u%s", get_random_u8(), str);
 		/* Only first '-' after the number will advance the pointer */
 		offset =3D strlen(in) - strlen(str) + !!(rc =3D=3D 2);
 		cmdline_do_one_test(test, in, rc, offset);
@@ -94,7 +94,7 @@ static void cmdline_test_tail_int(struct kunit *test)
 		int rc =3D strcmp(str, "") ? (strcmp(str, "-") ? 0 : 1) : 1;
 		int offset;
=20
-		sprintf(in, "%s%u", str, get_random_int() % 256);
+		sprintf(in, "%s%u", str, get_random_u8());
 		/*
 		 * Only first and leading '-' not followed by integer
 		 * will advance the pointer.
diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
index 56ffaa8dd3f6..0131ed2cd1bd 100644
--- a/lib/test_vmalloc.c
+++ b/lib/test_vmalloc.c
@@ -80,7 +80,7 @@ static int random_size_align_alloc_test(void)
 	int i;
=20
 	for (i =3D 0; i < test_loop_count; i++) {
-		rnd =3D prandom_u32();
+		rnd =3D get_random_u8();
=20
 		/*
 		 * Maximum 1024 pages, if PAGE_SIZE is 4096.
diff --git a/net/dccp/ipv4.c b/net/dccp/ipv4.c
index da6e3b20cd75..301799e7fa56 100644
--- a/net/dccp/ipv4.c
+++ b/net/dccp/ipv4.c
@@ -123,7 +123,7 @@ int dccp_v4_connect(struct sock *sk, struct sockaddr *u=
addr, int addr_len)
 						    inet->inet_daddr,
 						    inet->inet_sport,
 						    inet->inet_dport);
-	inet->inet_id =3D prandom_u32();
+	inet->inet_id =3D get_random_u16();
=20
 	err =3D dccp_connect(sk);
 	rt =3D NULL;
@@ -422,7 +422,7 @@ struct sock *dccp_v4_request_recv_sock(const struct soc=
k *sk,
 	RCU_INIT_POINTER(newinet->inet_opt, rcu_dereference(ireq->ireq_opt));
 	newinet->mc_index  =3D inet_iif(skb);
 	newinet->mc_ttl	   =3D ip_hdr(skb)->ttl;
-	newinet->inet_id   =3D prandom_u32();
+	newinet->inet_id   =3D get_random_u16();
=20
 	if (dst =3D=3D NULL && (dst =3D inet_csk_route_child_sock(sk, newsk, req)=
) =3D=3D NULL)
 		goto put_and_exit;
diff --git a/net/ipv4/datagram.c b/net/ipv4/datagram.c
index ffd57523331f..fefc5d855a66 100644
--- a/net/ipv4/datagram.c
+++ b/net/ipv4/datagram.c
@@ -71,7 +71,7 @@ int __ip4_datagram_connect(struct sock *sk, struct sockad=
dr *uaddr, int addr_len
 	reuseport_has_conns(sk, true);
 	sk->sk_state =3D TCP_ESTABLISHED;
 	sk_set_txhash(sk);
-	inet->inet_id =3D prandom_u32();
+	inet->inet_id =3D get_random_u16();
=20
 	sk_dst_set(sk, &rt->dst);
 	err =3D 0;
diff --git a/net/ipv4/ip_output.c b/net/ipv4/ip_output.c
index 04e2034f2f8e..a4fbdbff14b3 100644
--- a/net/ipv4/ip_output.c
+++ b/net/ipv4/ip_output.c
@@ -172,7 +172,7 @@ int ip_build_and_send_pkt(struct sk_buff *skb, const st=
ruct sock *sk,
 		 * Avoid using the hashed IP ident generator.
 		 */
 		if (sk->sk_protocol =3D=3D IPPROTO_TCP)
-			iph->id =3D (__force __be16)prandom_u32();
+			iph->id =3D (__force __be16)get_random_u16();
 		else
 			__ip_select_ident(net, iph, 1);
 	}
diff --git a/net/ipv4/tcp_ipv4.c b/net/ipv4/tcp_ipv4.c
index 5b019ba2b9d2..747752980983 100644
--- a/net/ipv4/tcp_ipv4.c
+++ b/net/ipv4/tcp_ipv4.c
@@ -303,7 +303,7 @@ int tcp_v4_connect(struct sock *sk, struct sockaddr *ua=
ddr, int addr_len)
 						 inet->inet_daddr);
 	}
=20
-	inet->inet_id =3D prandom_u32();
+	inet->inet_id =3D get_random_u16();
=20
 	if (tcp_fastopen_defer_connect(sk, &err))
 		return err;
@@ -1523,7 +1523,7 @@ struct sock *tcp_v4_syn_recv_sock(const struct sock *=
sk, struct sk_buff *skb,
 	inet_csk(newsk)->icsk_ext_hdr_len =3D 0;
 	if (inet_opt)
 		inet_csk(newsk)->icsk_ext_hdr_len =3D inet_opt->opt.optlen;
-	newinet->inet_id =3D prandom_u32();
+	newinet->inet_id =3D get_random_u16();
=20
 	/* Set ToS of the new socket based upon the value of incoming SYN.
 	 * ECT bits are set later in tcp_init_transfer().
diff --git a/net/mac80211/scan.c b/net/mac80211/scan.c
index c4f2aeb31da3..6cab549cc421 100644
--- a/net/mac80211/scan.c
+++ b/net/mac80211/scan.c
@@ -641,7 +641,7 @@ static void ieee80211_send_scan_probe_req(struct ieee80=
211_sub_if_data *sdata,
 		if (flags & IEEE80211_PROBE_FLAG_RANDOM_SN) {
 			struct ieee80211_hdr *hdr =3D (void *)skb->data;
 			struct ieee80211_tx_info *info =3D IEEE80211_SKB_CB(skb);
-			u16 sn =3D get_random_u32();
+			u16 sn =3D get_random_u16();
=20
 			info->control.flags |=3D IEEE80211_TX_CTRL_NO_SEQNO;
 			hdr->seq_ctrl =3D
diff --git a/net/netfilter/nf_nat_core.c b/net/netfilter/nf_nat_core.c
index 7981be526f26..57c7686ac485 100644
--- a/net/netfilter/nf_nat_core.c
+++ b/net/netfilter/nf_nat_core.c
@@ -468,7 +468,7 @@ static void nf_nat_l4proto_unique_tuple(struct nf_connt=
rack_tuple *tuple,
 	if (range->flags & NF_NAT_RANGE_PROTO_OFFSET)
 		off =3D (ntohs(*keyptr) - ntohs(range->base_proto.all));
 	else
-		off =3D prandom_u32();
+		off =3D get_random_u16();
=20
 	attempts =3D range_size;
 	if (attempts > max_attempts)
@@ -490,7 +490,7 @@ static void nf_nat_l4proto_unique_tuple(struct nf_connt=
rack_tuple *tuple,
 	if (attempts >=3D range_size || attempts < 16)
 		return;
 	attempts /=3D 2;
-	off =3D prandom_u32();
+	off =3D get_random_u16();
 	goto another_round;
 }
=20
diff --git a/net/sched/sch_cake.c b/net/sched/sch_cake.c
index a43a58a73d09..637ef1757931 100644
--- a/net/sched/sch_cake.c
+++ b/net/sched/sch_cake.c
@@ -2092,11 +2092,11 @@ static struct sk_buff *cake_dequeue(struct Qdisc *s=
ch)
=20
 		WARN_ON(host_load > CAKE_QUEUES);
=20
-		/* The shifted prandom_u32() is a way to apply dithering to
-		 * avoid accumulating roundoff errors
+		/* The get_random_u16() is a way to apply dithering to avoid
+		 * accumulating roundoff errors
 		 */
 		flow->deficit +=3D (b->flow_quantum * quantum_div[host_load] +
-				  (prandom_u32() >> 16)) >> 16;
+				  get_random_u16()) >> 16;
 		list_move_tail(&flow->flowchain, &b->old_flows);
=20
 		goto retry;
diff --git a/net/sched/sch_sfb.c b/net/sched/sch_sfb.c
index 2829455211f8..7eb70acb4d58 100644
--- a/net/sched/sch_sfb.c
+++ b/net/sched/sch_sfb.c
@@ -379,7 +379,7 @@ static int sfb_enqueue(struct sk_buff *skb, struct Qdis=
c *sch,
 		goto enqueue;
 	}
=20
-	r =3D prandom_u32() & SFB_MAX_PROB;
+	r =3D get_random_u16() & SFB_MAX_PROB;
=20
 	if (unlikely(r < p_min)) {
 		if (unlikely(p_min > SFB_MAX_PROB / 2)) {
diff --git a/net/sctp/socket.c b/net/sctp/socket.c
index 1e354ba44960..83628c347744 100644
--- a/net/sctp/socket.c
+++ b/net/sctp/socket.c
@@ -9448,7 +9448,7 @@ void sctp_copy_sock(struct sock *newsk, struct sock *=
sk,
 	newinet->inet_rcv_saddr =3D inet->inet_rcv_saddr;
 	newinet->inet_dport =3D htons(asoc->peer.port);
 	newinet->pmtudisc =3D inet->pmtudisc;
-	newinet->inet_id =3D prandom_u32();
+	newinet->inet_id =3D get_random_u16();
=20
 	newinet->uc_ttl =3D inet->uc_ttl;
 	newinet->mc_loop =3D 1;
--=20
2.37.3

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221007180107.216067-4-Jason%40zx2c4.com.
