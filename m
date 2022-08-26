Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGGEUOMAMGQEJYNCGAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F5955A2A6F
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:13 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id m16-20020a056402431000b0044662a0ba2csf1229395edc.13
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526553; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZNCOQcJD1hOtmza0OwVhyPr8TYhvMXY+RyRbw6x4jdA/OvQAfDsIDLvO+gEqqPA16
         T3oIl83bYGVSg6jVaSvRFgx0/W/7viS2QTE9y3SxaiTdbAEfwQ6rnADJ+Nrysxe7Pzmu
         eLtzmvSFLz0wEgNLuc6dlbkHt9nXbeAz63Y5qjz7BQ5l3K5DTIXly6Qui0mPC5wCc45O
         w+fZGCKNGgdUbI2JptIxLzcWUemPdZyBZz8CpM9MbPxHuVhKrqqaPsIgjoPyiaM6JN+p
         YFzzd3rXUb5uOj3Ua2gnKdfg2lZGwcTkW4ymz7lWUpliNRDRX//OrAkKIsKIln9YumoN
         uXUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=qWAoisLqwg140ad3s0LLidnxmpJWisMjME5IF38d5VM=;
        b=nJpJMo484uTs9iIn/PZsZxXolTooouEWbwmwj7uuscAYijCEG5wImUjRD9vPYPXqSd
         O/wLbn5tUmjESHca2+/OdeIa/acaBukMHN+R9OJkJYW/CZ0i5rZVYRRFUEV7JJxVcGQR
         fwna94KIBkSLeYfyO6FiKPBtYLdBRoUpgeBukTJAmM63XTzR94TieUaRrVhzmdiTfFPn
         f2s4X4ZUVx7sKZmNJKbAMPmmLclQScRLC3J3L4tPzb7jB34dO/77puXRWPOo+qrIm5BL
         J3oVUXlzqQU0jtz2W+pDNqkDpuMonJEqtFfBhh0d849d5vlzSROtvPaJJl/BLdWURBwL
         WXOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QeYGUAhX;
       spf=pass (google.com: domain of 3f-iiywykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3F-IIYwYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=qWAoisLqwg140ad3s0LLidnxmpJWisMjME5IF38d5VM=;
        b=oZwCTStluukI5ZWgMtaQeKeMozD/BPvgU4AeYi6HKHemFmsyZfEN19KnDeXywRAPCU
         gLub11plwB5g0ClsnuIs5Yj/ZZWzeWSUOFtG4yNpRRrcp8rHNgTu2YDDqzyMaFOpjGe0
         QaYGUCoW/qwqgjRr9f3YiNsDcD/1/bfsFuamlyulIhWlqL9FPamPmWgl/ZFosjSIDgi5
         Wdds9kf2zIX2mDMZznigRO95Mukno9UwFPjFzwBVMVrEi66DfU9ljOIthVugvVZqW6sN
         c2e0Yz71SkyBSL+WP6P+2V1SWlAinWBAYMatNeMdX7FtXO9ZO9b83FyGLzSIRXyhOqL1
         GPTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=qWAoisLqwg140ad3s0LLidnxmpJWisMjME5IF38d5VM=;
        b=e/uZpfZhZmYDeE7D3r12u9TXooTC5sUghE2tUwHi0W/rTh0nxy97En1MIgmksBsEg8
         gcvvk37SjsKwZs/hpvw58cK6/C2I/M5l6RDNVu/WY0Rbihh93Wj9+gQc6DDAF8tRyiXT
         AXIxubsnwNWP+6wHyW4YVRZXoZivBNDcu96+EJqqWyQvaRKyRsgSwzA2ixQzZGNCK227
         jUkcNFaglgHSlsM1Zj0kRwXtpV1fK4MPDMLgYTNlug60Xzgu5s04goFpDKTz7SriD0Xi
         YfR3hzIAHAfleovixJsk7778XBNRmb9JYawxbtzKmAvYwJB0O06HYuB+eJRe1+ANqEPH
         acbA==
X-Gm-Message-State: ACgBeo3w+SKrAsLq0SlEqoKm22O8S7UXewWU1Y0HmR1m8xKwqQYJlHwo
	zsE+oB7r/+ZgTBFk5xn4Xr8=
X-Google-Smtp-Source: AA6agR7q7+wd8KSE7HOmgHFjp0QPu4lN29Z4z4T+P+HQh1swnsCAFHZrU2XlOJugSF7/gXRlSkpLgg==
X-Received: by 2002:a05:6402:270d:b0:43a:67b9:6eea with SMTP id y13-20020a056402270d00b0043a67b96eeamr7075584edd.94.1661526553111;
        Fri, 26 Aug 2022 08:09:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1c56:b0:730:6d43:91d with SMTP id
 l22-20020a1709061c5600b007306d43091dls2146655ejg.6.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:12 -0700 (PDT)
X-Received: by 2002:a17:907:1c1f:b0:73d:6883:9869 with SMTP id nc31-20020a1709071c1f00b0073d68839869mr5752300ejc.241.1661526552050;
        Fri, 26 Aug 2022 08:09:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526552; cv=none;
        d=google.com; s=arc-20160816;
        b=dTosiV3JkbjwMnrzWUINfqeEXyL8sx9VvhhaZavKZvomnro12LgCjRLgKxyRPijyyr
         MflSNx49ZHAIPSLlmcCicnS+ltgYTwy+VxsUk9oe+Kbh5xPUreUYkumXjyFTY1H8gSx8
         VQuSczz7DE594hK2HQmxLZEIIs4fgAUxWJMvOiaS6rTHPG8QDk/H+zCVOIBZsrIHdpm1
         RIQIzEI1pee+ibbiWqUCd4K589PMCH787qy/VJ+u6gA6MEGFKKxo1NdeuxMAaFt73+Hv
         PbaWvREVBEwXYMVrNIkxSm7DAkxovA0JmzhMRmO8aPVFrcbTOYpncpAQaUtSqIvMpkVl
         FwQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=7FFI4T9ldWmH+mtJkkuNX0Iy/L7lZFULsA12RNz3xXM=;
        b=TpAe6zqa7rNLLinReDFPH2JkBNktDC9M0tUgDesrvVnhPcCyIZ5Qs8olPshpNa9pJo
         +8FRnITG72C1hi1nIELimFn1IUOBRo5rOU2p+xdGSHaKcWd9pAiH4iDaOS8pP75V88Xk
         vPhtAUTszeqXYVEBVpivnTELleGHtppERX9SFWBTv5ffBaeTrhG66YngigFb3/w8NixQ
         4uxRcglYbF2SnhLmmEmm6kAzFcvUo807rng5eWCfr3ys2h02hqe+QDE5jMp8XyF+dm/s
         uu3uo4FacnTGcxQmz34NbBCHUqs7irX5s0XUZYEUm26/4vHjjapw2rfxyyHun/Djoogy
         ThYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QeYGUAhX;
       spf=pass (google.com: domain of 3f-iiywykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3F-IIYwYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id g13-20020aa7c84d000000b0044609bb9ed0si90717edt.1.2022.08.26.08.09.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f-iiywykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id sb14-20020a1709076d8e00b0073d48a10e10so725940ejc.16
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:12 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:907:6d9b:b0:731:1135:dc2d with SMTP id
 sb27-20020a1709076d9b00b007311135dc2dmr5939518ejc.76.1661526551609; Fri, 26
 Aug 2022 08:09:11 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:44 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-22-glider@google.com>
Subject: [PATCH v5 21/44] Input: libps2: mark data received in __ps2_command()
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
 header.i=@google.com header.s=20210112 header.b=QeYGUAhX;       spf=pass
 (google.com: domain of 3f-iiywykcr4afc78laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3F-IIYwYKCR4AFC78LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-22-glider%40google.com.
