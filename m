Return-Path: <kasan-dev+bncBCLI747UVAFRB25O7OMQMGQESS5R4OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 43A925F67DE
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:26:04 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id t194-20020a1f2dcb000000b003ab00822172sf392924vkt.13
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:26:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665062763; cv=pass;
        d=google.com; s=arc-20160816;
        b=kVEyMoYwp+zsJbmpuSC++1zUd1WyyxU4iFjT4TNQrfNLNymw/fU3wT5Iqa2nveGc3x
         btmUGkeHiB8IWovrShPPswdW5Fi//I/zsi7RDPiEPFuNgLwNI/eHXh+fUvmeNIXcISKM
         gObtzGz1DUWbkCPCVgTrmuWh3ETz5Bbhx/S323GURuTsjWh2V04+p2zbZ2m0TG+niL/0
         oANY1K4wV+4OWdMi6wb7Grdqp+20NRRKJZB7O9XKXXZ1j+2u9YVmZR09+LScYGtwbMZ1
         C0u5/m25fmkbB3WnJ5n6VvxVWfeNweo8awqD7vCszx4WxR7VuCZNZ2Nw7dm7ajErAS1m
         6S2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=boAHakfm1RcXYWG9LAFs5zfBZwSD/nLEFmZ1v+fx2FY=;
        b=v6971J6Waw5vTik/mppHqPxLfXZUF+0TWvIk38EWHDxzx+1lQFw0Fq06dEK6oe0J+E
         jZid30jrVK480SuxsNXsY4nv+80EgVgY/hMVGbvhQneCsZb/+DHfoLprkESog0CrSzBx
         MJkr3Iz87aRNG9goKbMxI0xKNVDIktBjYqCMyJZLGXMDiQebPBgqP/gBm7ZrIOQ3Jtgh
         +lqqXxPJNnhB6J5/P1+ey+GsvukLnfxLjFffvxbB4AOez2ptkgfUmjAqn5Z2t0VYZxlc
         eIKMtzM++E/S/uA9edtn4fGuARU8FVY/IVPH8IZbkH7NRaVqhZ227vy2C96wYEz6oqpE
         gGpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=pwC9cMHz;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=boAHakfm1RcXYWG9LAFs5zfBZwSD/nLEFmZ1v+fx2FY=;
        b=elaYEE1c+EHiGHykCmGwl0TFbm5G3AFNujiiUkL3lR2qrflGzBdmMDElb78bK2NWNf
         PssekUZrGFVIXftES4IHv8FynjWKcLk1nl/5U/rULJnKVjY9l6R3+SjoUMMAee7ARwqz
         25iiegJ0dSDptCrrn+U4nxLzyCKK7C4EpO2Dna2/X2Zh4qq13bKLfKVjrD0MHiFRLFUn
         hqstxYLWrVSqdO5sfJ0QNBJ6uzEg1Oh+6IRE60AfHj/uw76n7I2KRcJjmD37DfsBS/JM
         jaOVYgKoVR9APQ2uvk5Z2EsffYXcQxpYH0r43BJB3C/taUmEjTkXBSNm2s8XolRIUbw7
         H89A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=boAHakfm1RcXYWG9LAFs5zfBZwSD/nLEFmZ1v+fx2FY=;
        b=FrPmWlelNUqSGk1Kc/a3RD0t++/DGMWFEiwMTPBigosfcJlUtIeQuvDo38lVet69wK
         WrMVCeXEvdMz4eVDtzw3A2mGTNCAEq5wr0sF4bRlURGnswv4lLc+CWIRYskeZAfpMBjA
         QgNhPPFgAgjHq8KL3yXvqEfRvAd1H1XWDusvAiSnG1iDpoTa1Ii53Qy1NgN0zaC7+KrO
         h+l/7KvyqvO3QH34BfJupYClamMQojaLbXleICvAWB+rwMHUx/BU5w9OZsZSn6IdGVwW
         TZyxl1tlmzkrLq6KKmZOraQjH8KaoMWuIuSgERgn5+Xr8FCGcUGnpdSLb9mb72RznR/v
         AbnA==
X-Gm-Message-State: ACrzQf1nDy3YYfSxiQ2bRq1pEo4DnO9KZNXIi4wdPm8HkJubXbz8Fitv
	uW7zUjW1pvgsn0muvTGocgU=
X-Google-Smtp-Source: AMsMyM5Uq+X6tqHbZya6Nmz1HxIUa6vn0wPNjUR950Md5jv1GqLG/gchNihHhXxKvCrDvDnltzgdeQ==
X-Received: by 2002:a67:e408:0:b0:3a6:89a9:d1ff with SMTP id d8-20020a67e408000000b003a689a9d1ffmr2266128vsf.72.1665062763230;
        Thu, 06 Oct 2022 06:26:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2486:0:b0:39f:778f:d76d with SMTP id i6-20020ab02486000000b0039f778fd76dls131943uan.4.-pod-prod-gmail;
 Thu, 06 Oct 2022 06:26:02 -0700 (PDT)
X-Received: by 2002:ab0:4889:0:b0:3cc:be32:ebb8 with SMTP id x9-20020ab04889000000b003ccbe32ebb8mr2519834uac.54.1665062762656;
        Thu, 06 Oct 2022 06:26:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665062762; cv=none;
        d=google.com; s=arc-20160816;
        b=YxL+EJMad+ak6xoiGQr+d2Qg8JMRXA5FDYrMExwKuoDgoFBPrsF+LwL+uXwtR/7AKm
         ainhUBhIha4eDc/bVb9AJLG72Wwr9z+CCwHLHMm+E2AogAm2FNAg8xGgXLnaEaxeS1uq
         Fr8Fjn+oW5YQjTWq5pyX25JFnWLERNTDr2MWoqkdVofKT8yYhfcN0PX8ucO11RE4C6Eu
         mnKwniLfVc1ozOuEBXgoqG+v/bNVwfsg812fFMeqS0c9/CpfYp6AnUsz8N03o9/jx9Df
         ZA9tTOri804/ZbzVcsPNM4dfGHSd3aw6qJAVoZhSMiPg+6ijwiFXJ6TV1cA0rYxqdG1d
         JdHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RNYWpm9q3FealxpvsZD8zZkjod1MIfG1X8OEo9MwlyM=;
        b=LU6Sad9atlGB6MHYBN5+fQnDjYKy/MDg6hpka92R78NycCYa6d37J/wWsb9CKuApyh
         2wzWfATVDZhplEkSB7kZ6NOV3bU6NoTrmFYfXRFLyAHzAjiz4ODGB0bqXTXvnCHL/8ba
         Y9FpxM0YP/i8B9uar1CGO0T/nlZhRFte+mEU7aEfL4wH4puGfALsErlP8GQwhu5KUBfI
         r5I6pcd1dAlQiNaqNcxGNeth+JdqtNibFmR+EaRKM05bftp1LvL1TkutMOYkN2MW3m9u
         XIXi3jbTwnqSe663SVQss0wjZnMFpmAcrEJd1IOWX1E1+3COMnwKh+VFsceHCJ+lcQ3N
         CZag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=pwC9cMHz;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id g184-20020a1f9dc1000000b003a4a4b2a98dsi729192vke.3.2022.10.06.06.26.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:26:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3E5AC619A9;
	Thu,  6 Oct 2022 13:26:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 233C3C43147;
	Thu,  6 Oct 2022 13:25:57 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 5395c60d (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 13:25:55 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	patches@lists.linux.dev
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	=?UTF-8?q?Christoph=20B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
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
	Theodore Ts'o <tytso@mit.edu>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Yury Norov <yury.norov@gmail.com>,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	kernel-janitors@vger.kernel.org,
	linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mm@kvack.org,
	linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org,
	linux-rdma@vger.kernel.org,
	linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	netdev@vger.kernel.org
Subject: [PATCH v2 2/5] treewide: use get_random_{u8,u16}() when possible
Date: Thu,  6 Oct 2022 07:25:07 -0600
Message-Id: <20221006132510.23374-3-Jason@zx2c4.com>
In-Reply-To: <20221006132510.23374-1-Jason@zx2c4.com>
References: <20221006132510.23374-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=pwC9cMHz;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

Rather than truncate a 32-bit value to a 16-bit value or an 8-bit value,
simply use the get_random_{u8,u16}() functions, which are faster than
wasting the additional bytes from a 32-bit value.

Reviewed-by: Kees Cook <keescook@chromium.org>
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 crypto/testmgr.c                                          | 8 ++++----
 drivers/media/common/v4l2-tpg/v4l2-tpg-core.c             | 2 +-
 drivers/media/test-drivers/vivid/vivid-radio-rx.c         | 4 ++--
 .../net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c   | 2 +-
 drivers/net/hamradio/baycom_epp.c                         | 2 +-
 drivers/net/hamradio/hdlcdrv.c                            | 2 +-
 drivers/net/hamradio/yam.c                                | 2 +-
 drivers/net/wireguard/selftest/allowedips.c               | 4 ++--
 drivers/scsi/lpfc/lpfc_hbadisc.c                          | 6 +++---
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
 19 files changed, 31 insertions(+), 31 deletions(-)

diff --git a/crypto/testmgr.c b/crypto/testmgr.c
index be45217acde4..981c637fa2ed 100644
--- a/crypto/testmgr.c
+++ b/crypto/testmgr.c
@@ -927,7 +927,7 @@ static void generate_random_bytes(u8 *buf, size_t count)
 			b = 0xff;
 			break;
 		default:
-			b = (u8)prandom_u32();
+			b = get_random_u8();
 			break;
 		}
 		memset(buf, b, count);
@@ -935,8 +935,8 @@ static void generate_random_bytes(u8 *buf, size_t count)
 		break;
 	case 2:
 		/* Ascending or descending bytes, plus optional mutations */
-		increment = (u8)prandom_u32();
-		b = (u8)prandom_u32();
+		increment = get_random_u8();
+		b = get_random_u8();
 		for (i = 0; i < count; i++, b += increment)
 			buf[i] = b;
 		mutate_buffer(buf, count);
@@ -944,7 +944,7 @@ static void generate_random_bytes(u8 *buf, size_t count)
 	default:
 		/* Fully random bytes */
 		for (i = 0; i < count; i++)
-			buf[i] = (u8)prandom_u32();
+			buf[i] = get_random_u8();
 	}
 }
 
diff --git a/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c b/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c
index 9b7bcdce6e44..303d02b1d71c 100644
--- a/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c
+++ b/drivers/media/common/v4l2-tpg/v4l2-tpg-core.c
@@ -870,7 +870,7 @@ static void precalculate_color(struct tpg_data *tpg, int k)
 		g = tpg_colors[col].g;
 		b = tpg_colors[col].b;
 	} else if (tpg->pattern == TPG_PAT_NOISE) {
-		r = g = b = prandom_u32_max(256);
+		r = g = b = get_random_u8();
 	} else if (k == TPG_COLOR_RANDOM) {
 		r = g = b = tpg->qual_offset + prandom_u32_max(196);
 	} else if (k >= TPG_COLOR_RAMP) {
diff --git a/drivers/media/test-drivers/vivid/vivid-radio-rx.c b/drivers/media/test-drivers/vivid/vivid-radio-rx.c
index 232cab508f48..8bd09589fb15 100644
--- a/drivers/media/test-drivers/vivid/vivid-radio-rx.c
+++ b/drivers/media/test-drivers/vivid/vivid-radio-rx.c
@@ -104,8 +104,8 @@ ssize_t vivid_radio_rx_read(struct file *file, char __user *buf,
 				break;
 			case 2:
 				rds.block |= V4L2_RDS_BLOCK_ERROR;
-				rds.lsb = prandom_u32_max(256);
-				rds.msb = prandom_u32_max(256);
+				rds.lsb = get_random_u8();
+				rds.msb = get_random_u8();
 				break;
 			case 3: /* Skip block altogether */
 				if (i)
diff --git a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c b/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
index ddfe9208529a..ac452a0111a9 100644
--- a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
+++ b/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
@@ -1467,7 +1467,7 @@ static void make_established(struct sock *sk, u32 snd_isn, unsigned int opt)
 	tp->write_seq = snd_isn;
 	tp->snd_nxt = snd_isn;
 	tp->snd_una = snd_isn;
-	inet_sk(sk)->inet_id = prandom_u32();
+	inet_sk(sk)->inet_id = get_random_u16();
 	assign_rxopt(sk, opt);
 
 	if (tp->rcv_wnd > (RCV_BUFSIZ_M << 10))
diff --git a/drivers/net/hamradio/baycom_epp.c b/drivers/net/hamradio/baycom_epp.c
index 7df78a721b04..791b4a53d69f 100644
--- a/drivers/net/hamradio/baycom_epp.c
+++ b/drivers/net/hamradio/baycom_epp.c
@@ -438,7 +438,7 @@ static int transmit(struct baycom_state *bc, int cnt, unsigned char stat)
 			if ((--bc->hdlctx.slotcnt) > 0)
 				return 0;
 			bc->hdlctx.slotcnt = bc->ch_params.slottime;
-			if (prandom_u32_max(256) > bc->ch_params.ppersist)
+			if (get_random_u8() > bc->ch_params.ppersist)
 				return 0;
 		}
 	}
diff --git a/drivers/net/hamradio/hdlcdrv.c b/drivers/net/hamradio/hdlcdrv.c
index 360d041a62c4..6c6f11d3d0aa 100644
--- a/drivers/net/hamradio/hdlcdrv.c
+++ b/drivers/net/hamradio/hdlcdrv.c
@@ -377,7 +377,7 @@ void hdlcdrv_arbitrate(struct net_device *dev, struct hdlcdrv_state *s)
 	if ((--s->hdlctx.slotcnt) > 0)
 		return;
 	s->hdlctx.slotcnt = s->ch_params.slottime;
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
 	yp->slotcnt = yp->slot / 10;
 
 	/* is random > persist ? */
-	if (prandom_u32_max(256) > yp->pers)
+	if (get_random_u8() > yp->pers)
 		return;
 
 	yam_start_tx(dev, yp);
diff --git a/drivers/net/wireguard/selftest/allowedips.c b/drivers/net/wireguard/selftest/allowedips.c
index 41db10f9be49..dd897c0740a2 100644
--- a/drivers/net/wireguard/selftest/allowedips.c
+++ b/drivers/net/wireguard/selftest/allowedips.c
@@ -310,7 +310,7 @@ static __init bool randomized_test(void)
 			for (k = 0; k < 4; ++k)
 				mutated[k] = (mutated[k] & mutate_mask[k]) |
 					     (~mutate_mask[k] &
-					      prandom_u32_max(256));
+					      get_random_u8());
 			cidr = prandom_u32_max(32) + 1;
 			peer = peers[prandom_u32_max(NUM_PEERS)];
 			if (wg_allowedips_insert_v4(&t,
@@ -354,7 +354,7 @@ static __init bool randomized_test(void)
 			for (k = 0; k < 4; ++k)
 				mutated[k] = (mutated[k] & mutate_mask[k]) |
 					     (~mutate_mask[k] &
-					      prandom_u32_max(256));
+					      get_random_u8());
 			cidr = prandom_u32_max(128) + 1;
 			peer = peers[prandom_u32_max(NUM_PEERS)];
 			if (wg_allowedips_insert_v6(&t,
diff --git a/drivers/scsi/lpfc/lpfc_hbadisc.c b/drivers/scsi/lpfc/lpfc_hbadisc.c
index 2645def612e6..26d1779cb570 100644
--- a/drivers/scsi/lpfc/lpfc_hbadisc.c
+++ b/drivers/scsi/lpfc/lpfc_hbadisc.c
@@ -2150,8 +2150,8 @@ lpfc_check_pending_fcoe_event(struct lpfc_hba *phba, uint8_t unreg_fcf)
  * This function makes an running random selection decision on FCF record to
  * use through a sequence of @fcf_cnt eligible FCF records with equal
  * probability. To perform integer manunipulation of random numbers with
- * size unit32_t, the lower 16 bits of the 32-bit random number returned
- * from prandom_u32() are taken as the random random number generated.
+ * size unit32_t, a 16-bit random number returned from get_random_u16() is
+ * taken as the random random number generated.
  *
  * Returns true when outcome is for the newly read FCF record should be
  * chosen; otherwise, return false when outcome is for keeping the previously
@@ -2163,7 +2163,7 @@ lpfc_sli4_new_fcf_random_select(struct lpfc_hba *phba, uint32_t fcf_cnt)
 	uint32_t rand_num;
 
 	/* Get 16-bit uniform random number */
-	rand_num = 0xFFFF & prandom_u32();
+	rand_num = get_random_u16();
 
 	/* Decision with probability 1/fcf_cnt */
 	if ((fcf_cnt * rand_num) < 0xFFFF)
diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
index 56ffaa8dd3f6..0131ed2cd1bd 100644
--- a/lib/test_vmalloc.c
+++ b/lib/test_vmalloc.c
@@ -80,7 +80,7 @@ static int random_size_align_alloc_test(void)
 	int i;
 
 	for (i = 0; i < test_loop_count; i++) {
-		rnd = prandom_u32();
+		rnd = get_random_u8();
 
 		/*
 		 * Maximum 1024 pages, if PAGE_SIZE is 4096.
diff --git a/net/dccp/ipv4.c b/net/dccp/ipv4.c
index da6e3b20cd75..301799e7fa56 100644
--- a/net/dccp/ipv4.c
+++ b/net/dccp/ipv4.c
@@ -123,7 +123,7 @@ int dccp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 						    inet->inet_daddr,
 						    inet->inet_sport,
 						    inet->inet_dport);
-	inet->inet_id = prandom_u32();
+	inet->inet_id = get_random_u16();
 
 	err = dccp_connect(sk);
 	rt = NULL;
@@ -422,7 +422,7 @@ struct sock *dccp_v4_request_recv_sock(const struct sock *sk,
 	RCU_INIT_POINTER(newinet->inet_opt, rcu_dereference(ireq->ireq_opt));
 	newinet->mc_index  = inet_iif(skb);
 	newinet->mc_ttl	   = ip_hdr(skb)->ttl;
-	newinet->inet_id   = prandom_u32();
+	newinet->inet_id   = get_random_u16();
 
 	if (dst == NULL && (dst = inet_csk_route_child_sock(sk, newsk, req)) == NULL)
 		goto put_and_exit;
diff --git a/net/ipv4/datagram.c b/net/ipv4/datagram.c
index ffd57523331f..fefc5d855a66 100644
--- a/net/ipv4/datagram.c
+++ b/net/ipv4/datagram.c
@@ -71,7 +71,7 @@ int __ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len
 	reuseport_has_conns(sk, true);
 	sk->sk_state = TCP_ESTABLISHED;
 	sk_set_txhash(sk);
-	inet->inet_id = prandom_u32();
+	inet->inet_id = get_random_u16();
 
 	sk_dst_set(sk, &rt->dst);
 	err = 0;
diff --git a/net/ipv4/ip_output.c b/net/ipv4/ip_output.c
index 04e2034f2f8e..a4fbdbff14b3 100644
--- a/net/ipv4/ip_output.c
+++ b/net/ipv4/ip_output.c
@@ -172,7 +172,7 @@ int ip_build_and_send_pkt(struct sk_buff *skb, const struct sock *sk,
 		 * Avoid using the hashed IP ident generator.
 		 */
 		if (sk->sk_protocol == IPPROTO_TCP)
-			iph->id = (__force __be16)prandom_u32();
+			iph->id = (__force __be16)get_random_u16();
 		else
 			__ip_select_ident(net, iph, 1);
 	}
diff --git a/net/ipv4/tcp_ipv4.c b/net/ipv4/tcp_ipv4.c
index 5b019ba2b9d2..747752980983 100644
--- a/net/ipv4/tcp_ipv4.c
+++ b/net/ipv4/tcp_ipv4.c
@@ -303,7 +303,7 @@ int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 						 inet->inet_daddr);
 	}
 
-	inet->inet_id = prandom_u32();
+	inet->inet_id = get_random_u16();
 
 	if (tcp_fastopen_defer_connect(sk, &err))
 		return err;
@@ -1523,7 +1523,7 @@ struct sock *tcp_v4_syn_recv_sock(const struct sock *sk, struct sk_buff *skb,
 	inet_csk(newsk)->icsk_ext_hdr_len = 0;
 	if (inet_opt)
 		inet_csk(newsk)->icsk_ext_hdr_len = inet_opt->opt.optlen;
-	newinet->inet_id = prandom_u32();
+	newinet->inet_id = get_random_u16();
 
 	/* Set ToS of the new socket based upon the value of incoming SYN.
 	 * ECT bits are set later in tcp_init_transfer().
diff --git a/net/mac80211/scan.c b/net/mac80211/scan.c
index c4f2aeb31da3..6cab549cc421 100644
--- a/net/mac80211/scan.c
+++ b/net/mac80211/scan.c
@@ -641,7 +641,7 @@ static void ieee80211_send_scan_probe_req(struct ieee80211_sub_if_data *sdata,
 		if (flags & IEEE80211_PROBE_FLAG_RANDOM_SN) {
 			struct ieee80211_hdr *hdr = (void *)skb->data;
 			struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
-			u16 sn = get_random_u32();
+			u16 sn = get_random_u16();
 
 			info->control.flags |= IEEE80211_TX_CTRL_NO_SEQNO;
 			hdr->seq_ctrl =
diff --git a/net/netfilter/nf_nat_core.c b/net/netfilter/nf_nat_core.c
index 7981be526f26..57c7686ac485 100644
--- a/net/netfilter/nf_nat_core.c
+++ b/net/netfilter/nf_nat_core.c
@@ -468,7 +468,7 @@ static void nf_nat_l4proto_unique_tuple(struct nf_conntrack_tuple *tuple,
 	if (range->flags & NF_NAT_RANGE_PROTO_OFFSET)
 		off = (ntohs(*keyptr) - ntohs(range->base_proto.all));
 	else
-		off = prandom_u32();
+		off = get_random_u16();
 
 	attempts = range_size;
 	if (attempts > max_attempts)
@@ -490,7 +490,7 @@ static void nf_nat_l4proto_unique_tuple(struct nf_conntrack_tuple *tuple,
 	if (attempts >= range_size || attempts < 16)
 		return;
 	attempts /= 2;
-	off = prandom_u32();
+	off = get_random_u16();
 	goto another_round;
 }
 
diff --git a/net/sched/sch_cake.c b/net/sched/sch_cake.c
index a43a58a73d09..637ef1757931 100644
--- a/net/sched/sch_cake.c
+++ b/net/sched/sch_cake.c
@@ -2092,11 +2092,11 @@ static struct sk_buff *cake_dequeue(struct Qdisc *sch)
 
 		WARN_ON(host_load > CAKE_QUEUES);
 
-		/* The shifted prandom_u32() is a way to apply dithering to
-		 * avoid accumulating roundoff errors
+		/* The get_random_u16() is a way to apply dithering to avoid
+		 * accumulating roundoff errors
 		 */
 		flow->deficit += (b->flow_quantum * quantum_div[host_load] +
-				  (prandom_u32() >> 16)) >> 16;
+				  get_random_u16()) >> 16;
 		list_move_tail(&flow->flowchain, &b->old_flows);
 
 		goto retry;
diff --git a/net/sched/sch_sfb.c b/net/sched/sch_sfb.c
index 2829455211f8..7eb70acb4d58 100644
--- a/net/sched/sch_sfb.c
+++ b/net/sched/sch_sfb.c
@@ -379,7 +379,7 @@ static int sfb_enqueue(struct sk_buff *skb, struct Qdisc *sch,
 		goto enqueue;
 	}
 
-	r = prandom_u32() & SFB_MAX_PROB;
+	r = get_random_u16() & SFB_MAX_PROB;
 
 	if (unlikely(r < p_min)) {
 		if (unlikely(p_min > SFB_MAX_PROB / 2)) {
diff --git a/net/sctp/socket.c b/net/sctp/socket.c
index 1e354ba44960..83628c347744 100644
--- a/net/sctp/socket.c
+++ b/net/sctp/socket.c
@@ -9448,7 +9448,7 @@ void sctp_copy_sock(struct sock *newsk, struct sock *sk,
 	newinet->inet_rcv_saddr = inet->inet_rcv_saddr;
 	newinet->inet_dport = htons(asoc->peer.port);
 	newinet->pmtudisc = inet->pmtudisc;
-	newinet->inet_id = prandom_u32();
+	newinet->inet_id = get_random_u16();
 
 	newinet->uc_ttl = inet->uc_ttl;
 	newinet->mc_loop = 1;
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221006132510.23374-3-Jason%40zx2c4.com.
