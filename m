Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVH6RSMQMGQE5MSWHOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id AA47A5B9E24
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:56 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id e8-20020a056512090800b0049e75e68d3esf970764lft.18
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254356; cv=pass;
        d=google.com; s=arc-20160816;
        b=EbJHW7MT72+m1+yNdD5HxrJzU5i/6+GvLfVRoCXrF4ZU96TBCo9yKyYmluPj9+C5mI
         KbHqbKazyYlKgR9ygG6UknvkloQLRRPOwlt0rEUidTi+f1g8JD0fBBs72H4qYcSats1e
         tcyKjYkhKOjzHs3Sf7dr07HYX/nCUpvk7Fg3wYXldjsUPMqo2QQUdxdZWPEzw5T2cPSB
         9PGmIwe2fRM39dd1XE8mB9jMxVNtyP0/4aAxy15qLIA0v/IKLxm5CwgwzwpEUzpJVESr
         qyxX/lGF10PBBYdTFb2tUNDkmJUDzCxp9+LcMJVoZppuAmqa7DoXOBXpeLLAZJlHdR+H
         +0xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0G9xnTxdPFqEzEY0BA+GMOt6DG+6YXc4vHDpc4WcGuU=;
        b=qeTDq2Xj1Gu7NvBBsdu8CMdpOsQbF1WEo7rLVvP8fneOVrdqXk/AkJPxRj050VIHgo
         PwCX1IOWrTJA0X9sFZccM4QX0/+Q4RsV7nZfEDdV1WCm0OnMqS0vq7npxKc6Z8sfYdjc
         IO4kFpLuzwd0CzjfqWegZhW6y/g/uuQYo5i6hxpquVhy9Rb2TYWFntFVKgvVfmi8ZmzC
         IrN2Dr8J4vjeiO1nQ/chG6gC4j9rpXYCK9Y42qCJQzdAO4DcSGFJgYTMHqtv3uUhQxB3
         TtDRBYrMyYSCfeFcDjykfFgsiEEyRSqFQ05r/Y6i2W+Qc8PggU13zNNPS8bUlPcqAhug
         hcLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aQq72ead;
       spf=pass (google.com: domain of 3uj8jywykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Uj8jYwYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=0G9xnTxdPFqEzEY0BA+GMOt6DG+6YXc4vHDpc4WcGuU=;
        b=I/Cxl7zmQW6yravgORG8fyvFk6Ei6PKQkiRuPUDLV3TMPDJwdKU0g4TVmgGiFSHtwI
         hjSVDFTaF4uk+ILTvcM8mgY0coy2Ricm21sxtC1V7ciE3H+FMK4/xxfAWKD79iby6A5T
         4qkzpV35nkla3j0ikDMllPPxVORHG2eKFKNHmC5dynaPIzRiAgmfScDb35MfNQxNDcm3
         Pb584/c0I6vfkUlYW3+0NAgUX8C4656XGtp/Dr1yFQuFhos2kSwCVzSmKEYHlslRywNk
         dkY8GXtJ4QcKUvihffEhmA16K++aQoz50sUsQDQNleR7uIOWzTqVSzfUtTCbtwLQ4Q2r
         4LpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=0G9xnTxdPFqEzEY0BA+GMOt6DG+6YXc4vHDpc4WcGuU=;
        b=mLBdvvoOXBKP30hPdrFpvK5Zsnjj+tTH/Wqom/5RHEeiid9zmAGpx9UYKGXGSXukvU
         Y/w0X2jmapGaYKjuwC9lABxUeGTpHzau8RmKpwDqcs+7SHzxqSAaz876Fvx+HgxE+T96
         7RpteQUDJn4UIGm9FYPYtaz+kBJXsRHHlVdN+7ZoVwA+i/MwoYUTCg4sVxEEKwg9j4Pa
         lCX631yyRe+pg+TyJmsEQTVZK+gPcUHUk832TbR/okiVWOLwYO/D/HnppoFujlTaLmEk
         KH2mu9LynvURqOHQOTTVOh5bA2At49pWa04dexuEX6AMIurYnPUG+b5pIY2rs05181Ho
         TPKw==
X-Gm-Message-State: ACrzQf1pUP9dzjjEF73rwtx3KUh5llsYlDjdxy4pyTt0sFcIR8E7tnPg
	T30KIdYZ7iBgDDRX8DQ/yO4=
X-Google-Smtp-Source: AMsMyM6M/GDD0ziCspdGwtAMm6NFDYl3QTX8y4QeYgh+EpZbMYEP9uxrPna7fzWddjImy6Ey0SMLLQ==
X-Received: by 2002:a05:6512:308e:b0:49b:9015:e76e with SMTP id z14-20020a056512308e00b0049b9015e76emr115531lfd.393.1663254356316;
        Thu, 15 Sep 2022 08:05:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e24:0:b0:49a:b814:856d with SMTP id o4-20020ac25e24000000b0049ab814856dls1228831lfg.1.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:55 -0700 (PDT)
X-Received: by 2002:ac2:5e3c:0:b0:49d:9849:5416 with SMTP id o28-20020ac25e3c000000b0049d98495416mr108291lfg.243.1663254355155;
        Thu, 15 Sep 2022 08:05:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254355; cv=none;
        d=google.com; s=arc-20160816;
        b=R+cGrUUltZA5OcTZgVkjkyzzG7R1UG3VY/m4GS9+ePNWqRn7H21tvhK7WG3J8ncZdQ
         tfaXoGMsTJZRWXg2ycc/eWygMeiaMVyTS4FBSQRl32UpN7XVoWPeCKs86TKl7dxZTdOU
         nvI4u5K7oVXeyleHpJP4dZCejhkikVRjJZXPoNquXgsNbdtAFp95V75RVQv+NUSjFj6r
         GPygH6r6wPkq896vUJFFJtoXGeKt1f/qzx2QFhXHiMvBZN7ABdGDXjk/r6tgMPJwQToz
         8y0O7tNBeF9vKPEsYq7o8xY8lvw32kloxLyAuqNsAS5MOkecH6+x7GlbO2kSeaSQZQ59
         bZgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=r3HZXk/BEn65kcaybENH+gdA6j04yycM3f96/pfDo3Y=;
        b=zPVc+iYrIq0NJHGqWSrWp3Zok/hgcR6SQsSeNLmAN0w/9nTWQW9pm2z9GwR0A3JWjr
         m3nJIOsh0TGSAqb1+lsRO6N4xf4leUSNQSn27c9nQEBr3wptabqVL5eM9IVRAPAg+gwA
         nmScOXSGAjCmm9xDRh6UtN8sqQVZNsNR3YYBCrPGOH1fZpG7p7j1LpnnJaAKGKGKS401
         MKI9eMDlDiMAXNX81GusYnx9lb6H1GdKSapSc5PjgIU8J6pYa0mohVA48M9MIl6AcT+I
         EG0p/UaT3ka6hYmwwZjtLOtWeXGd+/LQbvibEMRSPEOHysAYB1vMcL9DC+R48eK4eNsE
         yFhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aQq72ead;
       spf=pass (google.com: domain of 3uj8jywykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Uj8jYwYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id p22-20020a2eba16000000b00261e5b01fe0si489163lja.6.2022.09.15.08.05.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uj8jywykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id xc12-20020a170907074c00b007416699ea14so7704061ejb.19
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:55 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:b0e:b0:77a:d97d:9afc with SMTP id
 h14-20020a1709070b0e00b0077ad97d9afcmr287936ejl.199.1663254354566; Thu, 15
 Sep 2022 08:05:54 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:02 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-29-glider@google.com>
Subject: [PATCH v7 28/43] block: kmsan: skip bio block merging logic for KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Eric Biggers <ebiggers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aQq72ead;       spf=pass
 (google.com: domain of 3uj8jywykcx0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Uj8jYwYKCX0hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN doesn't allow treating adjacent memory pages as such, if they were
allocated by different alloc_pages() calls.
The block layer however does so: adjacent pages end up being used
together. To prevent this, make page_is_mergeable() return false under
KMSAN.

Suggested-by: Eric Biggers <ebiggers@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>

---

v4:
 -- swap block: and kmsan: in the subject

v5:
 -- address Marco Elver's comments

Link: https://linux-review.googlesource.com/id/Ie29cc2464c70032347c32ab2a22e1e7a0b37b905
---
 block/bio.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/block/bio.c b/block/bio.c
index 3d3a2678fea25..106ef14f28c2a 100644
--- a/block/bio.c
+++ b/block/bio.c
@@ -869,6 +869,8 @@ static inline bool page_is_mergeable(const struct bio_vec *bv,
 	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
 	if (*same_page)
 		return true;
+	else if (IS_ENABLED(CONFIG_KMSAN))
+		return false;
 	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
 }
 
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-29-glider%40google.com.
