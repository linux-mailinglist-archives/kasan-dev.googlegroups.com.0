Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTH6RSMQMGQERL2PTCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE2485B9E1D
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:48 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id q10-20020a19f20a000000b0048d029a71d3sf5646441lfh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254348; cv=pass;
        d=google.com; s=arc-20160816;
        b=zzZyI0iOxE0UO8Uxhjo19rHW0sVUBj7SUbbAEocmF4IBkVuvDvKwcBJMy0bewzsl/T
         xkosjaOS0JJovcjCTkMUc7fCKo6SevtQkUKhs5Vw2SxfioBTzfghx6GdOvxhv/gJtU/o
         k/AxqsiUmnF6g03lQauXMegnUP3IDbHFvrsfn4OdHcEN9BtP0/YUV0YMGXwLl6ZUHwbI
         vMuUxwQ2U5A8VMfHKU4bPEeyjGKDQHsjy5yBbp6okhCQq+gygGxkUHhHo1pf0+71qC+K
         oxA032gP/xL7Pr05zGlpCkpX2gweQCkutcNqVYhRd/WLag24jOevg0/QYgFnl4s5H5Py
         wuBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Vup3YWEsQuxuYz8AZG+rmn9aNvm1f6fGZmrm5bs9OfQ=;
        b=qp6iqbIGy758a0hIq+0EDfb2PN9KO//oFE0FoUNSSndK2HdiCQXmEqMcwYgkq0GaCq
         6dnoF77UqX3qDM8OK83ccnIby8JT0beaPnxQmXlYLybfhrIQ6Ps8PB+UIJredbEJz2zp
         gA4EZYUjVGRSy6QcUKs1+OkajT6qx0LC2UCoyy8kLR2cYFTqCLs6SpSO3x/4CsxHKVzi
         X+9ekBfO+Kn4mgFwgxtNt1OOoHEiUApNqtiFZPTE5XlS4c/7F126eBX7ltdBUyA6/wSd
         RQnrW+FzHE+LlQf/bVfaY/VYii5NjA5Z8MnifNdbTY6jq1ri5JXErK6XYGtJPv4n/7+Y
         Y0qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="IWkX75T/";
       spf=pass (google.com: domain of 3sj8jywykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Sj8jYwYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=Vup3YWEsQuxuYz8AZG+rmn9aNvm1f6fGZmrm5bs9OfQ=;
        b=UfFi9JMN3FdUCpAAe49rVLiskIoE2whNpjRro1WNA9oUNOE3jhscjPK6xz6X2+a3T7
         xShsuT1JJ3rXy2KYYPfoQB0P1Xxpx0hqhuF6V+1xn1/qzSnOm+5bAx34+PrDFS8bGNE4
         fnzggkS4057brH3wyLUPbsNCKicptga82CILxOa4SaR82ARoE4YsQL8gsjWcgEJpgIsV
         9DNquQR7dhN9ZN11+wmwBhIPaOBxVand+5PSv1IJsc8KMnjkvxDSMIOlPUVOqtopFPlM
         Rd6iFlGrb1wDQosG2bxfCP7l6rm0E9+UYW09bspVeaKjzK/XHdTMwcKNg+y24J0L79JY
         eVsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Vup3YWEsQuxuYz8AZG+rmn9aNvm1f6fGZmrm5bs9OfQ=;
        b=76EFnMpSFRoPEZL4NEiEd7YfO7dEKKENMooEVDKtXGhGyjZioCqJaBjJ4ha/bP0JhX
         7ig8Ei3WM/JSbW84cukmbhzjbNcZBzfyCuiScZIUM1frZupHpmlNHgbb94DTjgP+RNR6
         Wf/JiBR8R0fMLnhyJarAFffsb12u+LlgctHmZftSbHR416M1/v94tJvNW9tTqtfU2lSp
         EdiIh+msk+oRRcBLT17VSiWVKtTazwQ7NCR1KnFd6LbGFtIOk1KRY8K4tDUxf1dNsSsF
         GvjzLu0DKFF5ep8H/16xYhycMPw+Eg19dJ0XsnRmuWTdRFksIUeA0fwO5xB/dhx49dUO
         mGQA==
X-Gm-Message-State: ACrzQf0LVdoEivOkukNxUQvq7PwdjM/Hn8UO19bgza1uBlQtMUUUU6jk
	3tdkl62U3prt0pXsQ/gui9M=
X-Google-Smtp-Source: AMsMyM7A+tfqrraV1KrHerDK4/nsD+afprLnvuDNams3mt6+5soAbpHCTrVuEYjV4FwuIi3k76Q0+Q==
X-Received: by 2002:a2e:5cc2:0:b0:26b:fd6f:bc34 with SMTP id q185-20020a2e5cc2000000b0026bfd6fbc34mr71783ljb.72.1663254348480;
        Thu, 15 Sep 2022 08:05:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:860c:0:b0:26b:ff81:b7cb with SMTP id a12-20020a2e860c000000b0026bff81b7cbls2053739lji.6.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:47 -0700 (PDT)
X-Received: by 2002:a05:651c:b12:b0:26a:b605:7fe with SMTP id b18-20020a05651c0b1200b0026ab60507femr72665ljr.116.1663254347174;
        Thu, 15 Sep 2022 08:05:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254347; cv=none;
        d=google.com; s=arc-20160816;
        b=I1xvtAzqHeXBxdc3GixFZ+xuOWFgMoxRar8NW4AIAw7z3oTxr4LW2un/C5Hro7d+CL
         ih054cz5KWa+qIqdIaX7ArX0CIaZ8joGr/toI28kRQCOw3WArgIXBY2s0xk+SSjEprt1
         6c8uU/YX9odzx8h8SWpiRnqw2Fh1vGlqnxYl24DTgGLvdfnhb6BXV382wqtxDZEj2ppn
         vlueeoOmzRYzgWZmUeo/25DwjUwGZIrSvVbx3trbE2LonZGxDgubQ/hHp3Xfy+dMDrqm
         sr+tJAbJbZhiLlKZ3boxRZkB64O6W3cbhbBAsSRHLBYo60Mf8lZ1h2+10vy99FjLexbJ
         QYfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PRETZsLeKtd8er/vGZIvwJ67UbRQnpYPS7VnNd6iitc=;
        b=HuWPBX7H4+01hDf23v4F0xKy/OdvGA+W65mL34MPNLhTMVGctsmD3k2kt8Fa+ivLI8
         ZjVDheZ2QmXQQn/+rY0fgLIw6Xr2XA8oKsRWckJlzbtXxle9wsl2FVmqWsYeFuCIM6Sm
         0/UJbdsKlf380FDrQ7WlUnBVlc2d80aLS74r0jK7YclGW46PmMKN5tJ/04UYE/kXxR5o
         yEnJKDn/C1lXhYgPorMSGpeTYDLR5KRoP1xbeidrprxXR1s6TyvweJV3R7860rP7UES+
         lsVDIERg81UZxYNHverUvS4uIsWl5DTmEqkjW3qIKb0XoRXi+r0t0CUk6ZQVDVlBxRU7
         ARCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="IWkX75T/";
       spf=pass (google.com: domain of 3sj8jywykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Sj8jYwYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id v22-20020a05651203b600b00492ea683e72si546002lfp.2.2022.09.15.08.05.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sj8jywykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id e15-20020a056402190f00b0044f41e776a0so13139911edz.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:47 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:906:cc59:b0:779:f094:af3d with SMTP id
 mm25-20020a170906cc5900b00779f094af3dmr278250ejb.239.1663254346675; Thu, 15
 Sep 2022 08:05:46 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:59 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-26-glider@google.com>
Subject: [PATCH v7 25/43] kmsan: disable strscpy() optimization under KMSAN
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
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="IWkX75T/";       spf=pass
 (google.com: domain of 3sj8jywykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Sj8jYwYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
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

Disable the efficient 8-byte reading under KMSAN to avoid false positives.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/Iffd8336965e88fce915db2e6a9d6524422975f69
---
 lib/string.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/lib/string.c b/lib/string.c
index 6f334420f6871..3371d26a0e390 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -197,6 +197,14 @@ ssize_t strscpy(char *dest, const char *src, size_t count)
 		max = 0;
 #endif
 
+	/*
+	 * read_word_at_a_time() below may read uninitialized bytes after the
+	 * trailing zero and use them in comparisons. Disable this optimization
+	 * under KMSAN to prevent false positive reports.
+	 */
+	if (IS_ENABLED(CONFIG_KMSAN))
+		max = 0;
+
 	while (max >= sizeof(unsigned long)) {
 		unsigned long c, data;
 
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-26-glider%40google.com.
