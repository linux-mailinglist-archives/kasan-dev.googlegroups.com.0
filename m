Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD4H7SKQMGQEP5NIUKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id EFDBE563522
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:15 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id j19-20020a05600c191300b003a048196712sf1479934wmq.4
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685455; cv=pass;
        d=google.com; s=arc-20160816;
        b=C8I4CIkrmmRgOJLfBjSz0evFSs36f8+2IXKS63aMxR+Qa5MPIoUaVr3SaB1Ia31wxz
         o19RNfT436Ly8mojrHacCWBNxjS8dypXmWV6/KFTEdeIH83SHReYjRfSb5SdN78658sI
         iU1iJ5O0gZBRbDrGovftbtv4qrO00vYuXUKGAaYpEr6sJrrf6SmKR0112OfNIMHF1bHz
         KAcLkZmefRebfZrOFabr2smkMIEN3p/dMSSjr1MFvOpPsXXIuXrSqQ1YkgEnDHnwE/ii
         hVfnKiPzys3rvtDn+CWppBd7CWEUVUy3dHxGtBf1pYi8TdxX5jTHcbYRXW1BH2kUmM0i
         pBzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=9ZXctgpNIxm137jYIEwmx08ssfV6xGASOA7/F8r3tc8=;
        b=LU1Z/mw1Pu6gcqXniq4IRxZSURVUOL3tiRwu/OmI2LA/8XltJwLxMlCBUM4UowilTI
         fic5KW00YLHmK/ZX5tnSSQtKJg5HFI7lR+lOiveJ7KkFi62XtWrFo7AIXHkFhDDkcJYz
         riCeTVndrMqzqceK7WOBmqWhWr+Wm6FtII4Xt7UQ8IT7fl1nDQuMzU4hBErKamQg21Uq
         41+owCXtrTGIYwb5M46PhHI240lv6PMdE2+hKTnBxb9Pb0hi9iRUgQP74holy68BxvkT
         hJHwaimvcLtHx6DweZ+K7Mmi+FNCFH4L26b+/vWuvk1/gchTeC3gFd+MkICwzO9F1VZS
         Kqpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HUp0QjEt;
       spf=pass (google.com: domain of 3jgo_ygykca0tyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3jgO_YgYKCa0TYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ZXctgpNIxm137jYIEwmx08ssfV6xGASOA7/F8r3tc8=;
        b=tKAh31wWSHqbXV4oWux9ZvBWAbi5u7LK2Mjb1+m7ANXvSXwvM4gSMs1jXLNi4OIeWS
         XKUe2mf3eyuA7+FlCg8fTfSMpZw256ifBb+bwthjqVwoijZ0by1UUQP5fMTo2Bye5ZIr
         aaFYnyCrk2yz+S8eY9c32UKVIKaS8AleKMXIozslDDxLmYqCXeYN0yG/NGkS1PlQmU/C
         upYLlrN/2WGwajUQt5cFJzDSDO497eCnqHsnEwI74ieKN9b1EhYtMDaoFKtAnue0CQdJ
         shS+K9VpHXhrfuk9XNwusFE2CioXBuYY4ceuzZn8xQIOcGtQ6dDWsDf+VF9qsLWGraf8
         UO5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9ZXctgpNIxm137jYIEwmx08ssfV6xGASOA7/F8r3tc8=;
        b=vzpqlWD2a+U/yxXRmfgssN4qiBSJCKzBNAgJu0ljIhVBT0YalPhik+WDD9qwqqjNMm
         6ijMt2PIHVNszdX0lkVF/KJr4MQDy0YsjUC3WETp8YD029HQprfdws3Utklop3bufYzl
         txF+2nCPrDPOuaJ2x7oKQhqpjIhefhgNo309KqtfazhvibacRf76joB0zn8iPWAXbRa6
         smLhc6xrcgSnk6d95ziMrb9v3RK7zazzB8E7IKcJj2zos9DxOhRBR2Hm4ZqO0wwYTtF3
         Hl02dmytnpXVGvrtBGdE5ttNtVlhLQA38NV3BlkIIGXznTzYNQbgKW08rf9rH55DwEE5
         WGMw==
X-Gm-Message-State: AJIora8rdlVGjoyQZqf20adI6KMXcdf2C4HBgOMn84QkIV9aSWYMckTt
	7MXs/iJUMv5aTnTQKJrwUkM=
X-Google-Smtp-Source: AGRyM1tSHTQRwxcIvJKDKiDIzvziMv36j0CNjrSbOCUHiSIpAj11HuXyeZ1rOypF4KslWXwm5n0mfg==
X-Received: by 2002:a5d:6704:0:b0:21b:8258:b773 with SMTP id o4-20020a5d6704000000b0021b8258b773mr13225326wru.284.1656685455724;
        Fri, 01 Jul 2022 07:24:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:47ce:0:b0:21d:339f:dc1 with SMTP id o14-20020a5d47ce000000b0021d339f0dc1ls9663775wrc.0.gmail;
 Fri, 01 Jul 2022 07:24:14 -0700 (PDT)
X-Received: by 2002:a05:6000:1142:b0:21b:844e:27cb with SMTP id d2-20020a056000114200b0021b844e27cbmr13953965wrx.306.1656685454765;
        Fri, 01 Jul 2022 07:24:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685454; cv=none;
        d=google.com; s=arc-20160816;
        b=MB+c1ItNWejgTiwtsFVzrgt4GgBrVHf7BxRdaQyz3WtQrLsyOgv3tnXFbCFL9ZEiI6
         eC9SW3Iv6JYjTAos7K45iOsZBgJL2RrvH3OJW2Q26jl45WvoYNc//6yzdhId73wtJdyY
         yWEtFCRpfZcR8bw2PDDxzacyF1PYCyr1mLofcofnfX3KE+kzhDbju9pPk4xLf1kxXYFe
         aYQ93HHK30dcwGpFDxkqyqK3uWsjNNHK+J48/8Hy52xtqbWrtpcQU3aXjRQkah2PEavs
         yU+ST0VBfQzSnXgj+teAv9WLSGwhYxuzgpQX7YSFHQNsseyxTBKWYhpH86F+KqYCj2qL
         mlHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7LZjp1LTGSiY93TRZ3g7FZorW8E9Cp1phv1xqeqiFUY=;
        b=Z2PUS1eZm1spu8DqmKkyVGrROD5WQwpVRwWzWo2jTHHMkFEA1HgFl+ywJ5BJJmfoaY
         i+/DYBUGG4aEz84OK7bAxdNH/OFmBGBPqHxDzv68W6nTDPmNLyrowBfgCjr2wwXPB8nV
         b6YclnH90/AGowhVyXCmIBwTpTP3OfOYyCnCGthH0+x34PJhwZdklD/w5rlp6BFbQE/s
         vu+AttrotkHcbsAVzUpMg8y9OqAmsN8NmoOuK2S9JEGt1X8AuZwVFoU4HiCGUFxvFiHX
         xSbDaPdif7b/REGJth+lfX8EHzux0NoCQ4kc7XfdI0LOTHc001fyQ+bRM9q3qXvDRI5i
         E0hQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HUp0QjEt;
       spf=pass (google.com: domain of 3jgo_ygykca0tyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3jgO_YgYKCa0TYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id p26-20020a1c545a000000b0039c51c2da24si492147wmi.1.2022.07.01.07.24.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jgo_ygykca0tyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id kv9-20020a17090778c900b007262b461ecdso831882ejc.6
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:14 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:4493:b0:435:8dd5:c951 with SMTP id
 er19-20020a056402449300b004358dd5c951mr18955210edb.289.1656685454405; Fri, 01
 Jul 2022 07:24:14 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:46 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-22-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 21/45] Input: libps2: mark data received in __ps2_command()
 as initialized
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HUp0QjEt;       spf=pass
 (google.com: domain of 3jgo_ygykca0tyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3jgO_YgYKCa0TYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-22-glider%40google.com.
