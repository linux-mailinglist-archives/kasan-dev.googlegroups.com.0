Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIODUCJQMGQEKBI2COA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id A2B2D5103F9
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:22 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id n8-20020a2e8788000000b0024ef8429d64sf2661647lji.9
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991522; cv=pass;
        d=google.com; s=arc-20160816;
        b=OMEWnL8vxI23j3CBPpTR/8ya5J/lVlqtozP6+s55Uj/yS4ATUBYUdKosthU8qHsvBu
         ZNZj5wS+nqHO9sgdCmhHk90WVIt8uFnFzFXMipaoZzB8QFLYDAkBaA4Mqh5MS//WvNB7
         CS+AWutjJ30E4QThIr0GKKzB99zym8XiXKzCxq+4cUKs97RlcJHEfjk7D+RbntCNgM9V
         gFShKq19cwrFJQ2r+j/fYdQjoAUOaOGWltgS/U85UXgsg5NUXtT9/euxmMrWT0gQ64Da
         0guU9j3mY+Hu2ZdT6ZyTEV9HpwGMovtIlrRUR6fNq3lWC2kIJmzojrMTieNSvxwaj9r9
         yVkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=bOha11heBcj/8ou6ltwZ1uzvXVZK09UOCH2HmmrciAI=;
        b=K981T7uu0RIwmHAOOIF8RYaMXNQb0Nlc+MYWAWxuYeVpsRi902Nx2MlD9TqKqTAXM0
         qi8kPUrRohQN2vLx1rZPiPy1XCyeRmYQEGmYEZ5JdtzulhVuoEo7ywV92Ai7ByyvMNlr
         UdXvhI/ve28TLgFk75+HoGYNQIMG+ar8NJ2e723YLRxSZfZrO9eghKPsWjAhE2CU5qyM
         sRamhsKftEXMn2URHSWJMwi4tmmvc06cxArPylDWMghARYPK9noUcjrJVr2gmJ4TSXLp
         9Q8diiVhvTPNS4vLzyf1fgZzd9Xh37fWAVKgyuheLzd10L2cdV1eSPpwqE27AmjeQJL/
         MOKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=khSFQmZP;
       spf=pass (google.com: domain of 3ocfoygykcz0difabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oCFoYgYKCZ0DIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bOha11heBcj/8ou6ltwZ1uzvXVZK09UOCH2HmmrciAI=;
        b=chNZONJ9OpApQiqqVeyPSPyGjTDG4BzlqfK80Q2e2HlRgYSajfk+HoSqZG42p3gykn
         SujD7hG4I/uVuw5UXie9dO+u6MWH0p1vQrYSXyTonF05VW+/i3O5tbeQXzEmmI93JVuB
         cwkfQVyloJECYlp9ltdvKtyHB5+wjuqU5jhdjVJI0dgoJeNUMTuc8acmNNlvvvDTo5AP
         aYSag2E8+heWwzN82eduZCcKW5FsNALL4XCe8tMFhlq92COigZXF/DuF2w7bkHy89lJ5
         rkkQ9NMISONKXwoK+Kk8bP6eJDR+a+rs/YKU2nX1/evuLtV/K2hgQ5WiPTMFlqxraIL3
         Wq6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bOha11heBcj/8ou6ltwZ1uzvXVZK09UOCH2HmmrciAI=;
        b=FmGHSoUKpOw9G9aHw9giyIPQ9MZyh8gmgqJk8veewflX94zWdSS0vWaLgZVvOQ6T72
         c0oa6t7gqSRCZctjo4OrqYk2PGQp/Jr9DuH0G2863AvN7ZMYcTp7P4PLzGOM0i/6ZdJ0
         svguuKF+MMfc1Bb3ft5JcKMs/2ywEbsfy8bqE8x7B0kLLo84Q9z/mNf2v7UMuPWBwXfN
         ZF+yK5dCeK2f3Wml11QPo/SgzWWRspTUUyVlcA9L6p0AfgPKAl0Kd+YkvUh6d7B2BmEN
         1Z49gsjVWzgQvd7qJVZaqCcTz5hHAw1YQ7kdT4eb6NQv9FTTByWly7yZ0Qjp+osGhft3
         4y9g==
X-Gm-Message-State: AOAM533nV8zF1oPwVselYSDHPZ3uKRQmrzTz2pAIpJe2jn1N8qduo24H
	LFc1qXPrncuVnHIveNRA5oQ=
X-Google-Smtp-Source: ABdhPJygulBMz2ijPK6fRowPZqhFoU+/69BuUgGslGa9S/93xEQ7U5Vcycm5QDeYexP2LRxcVB0R7A==
X-Received: by 2002:a2e:9d08:0:b0:249:b8b6:8f7a with SMTP id t8-20020a2e9d08000000b00249b8b68f7amr14748621lji.310.1650991522126;
        Tue, 26 Apr 2022 09:45:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls2081639lfb.1.gmail; Tue, 26 Apr 2022
 09:45:21 -0700 (PDT)
X-Received: by 2002:a19:790c:0:b0:471:fd10:2980 with SMTP id u12-20020a19790c000000b00471fd102980mr10991570lfc.457.1650991521124;
        Tue, 26 Apr 2022 09:45:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991521; cv=none;
        d=google.com; s=arc-20160816;
        b=v+MycNbgXFvZG3382jlLgoKNrVmwrAjXwwqjxIt5vZktwQp8ugEM5A2Q7ty+UF41fm
         OFOAhh9/MoUVjue1ThjEycOiDPfYxTaL09t2B1yZ86csM1scnn/Knw4L80Xg2z2tFcvx
         HMds0MlUtZfcK9mU08Cw8Q/jaNyA6zM/RIf4QjhWDXzqegfE1op0wyl+FTTN6ZmLZ5Ff
         HRM1ve8DKQrKzudna6OO4LyyFf4IoW/40qF4p+P8zZHHaovmu8MsIrI2Tk01k/lbtsuR
         Xh9sYYVTjEmpC5LWuf+2UBLOWbdedGdvnF3zGFg9CmQh9Su+jjHGoWmlrwyE2EgS+/qn
         v+2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=A4BOD5bYYCwqT6UysGwaTqw9NZkJge0TWQm9U6+WrG0=;
        b=gV790j7PwJNxZ+FxUfiTdddUS7X6L/ea4+wr0gA1/Bzk2T+9PFm/RB7iAfrjfBsOfl
         0nerZ0ZuSuBLNyj7GMsjjQUEiym6PKvFyb00jww8Gw7jVPSQdqgWVMPZL3ETJEeW5qrQ
         zRPxz48pJaOFZg6uAScmTFxkVnNuZsnzfy4BbwhsMStZ274/8y7qgAhRRYDOoUdVmiQS
         bf5OqoLynneTD6v8CSqU7BiBPxJT54ZLt4F5XlgArWjFCYBdOU1dyP10kDBdYFN9kMk8
         fDLMfsN7M2LtmoXNv+c8u9+TDSv5M0MlJJCwsYJ9t2GAIQkOg7PG4PgGnFIer8Mcgu/+
         dEtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=khSFQmZP;
       spf=pass (google.com: domain of 3ocfoygykcz0difabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oCFoYgYKCZ0DIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b00471d641b327si606769lfv.6.2022.04.26.09.45.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ocfoygykcz0difabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id cf16-20020a0564020b9000b00425d543c75dso4624495edb.11
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:21 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:254e:b0:424:244:faf with SMTP id
 l14-20020a056402254e00b0042402440fafmr25661420edb.260.1650991520418; Tue, 26
 Apr 2022 09:45:20 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:52 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-24-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 23/46] Input: libps2: mark data received in __ps2_command()
 as initialized
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=khSFQmZP;       spf=pass
 (google.com: domain of 3ocfoygykcz0difabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oCFoYgYKCZ0DIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
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

KMSAN does not know that the device initializes certain bytes in
ps2dev->cmdbuf. Call kmsan_unpoison_memory() to explicitly mark them as
initialized.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I2d26f6baa45271d37320d3f4a528c39cb7e545f0
---
 drivers/input/serio/libps2.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/drivers/input/serio/libps2.c b/drivers/input/serio/libps2.c
index 250e213cc80c6..3e19344eda93c 100644
--- a/drivers/input/serio/libps2.c
+++ b/drivers/input/serio/libps2.c
@@ -12,6 +12,7 @@
 #include <linux/sched.h>
 #include <linux/interrupt.h>
 #include <linux/input.h>
+#include <linux/kmsan-checks.h>
 #include <linux/serio.h>
 #include <linux/i8042.h>
 #include <linux/libps2.h>
@@ -294,9 +295,11 @@ int __ps2_command(struct ps2dev *ps2dev, u8 *param, unsigned int command)
 
 	serio_pause_rx(ps2dev->serio);
 
-	if (param)
+	if (param) {
 		for (i = 0; i < receive; i++)
 			param[i] = ps2dev->cmdbuf[(receive - 1) - i];
+		kmsan_unpoison_memory(param, receive);
+	}
 
 	if (ps2dev->cmdcnt &&
 	    (command != PS2_CMD_RESET_BAT || ps2dev->cmdcnt != 1)) {
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-24-glider%40google.com.
