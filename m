Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTGEUOMAMGQEPCY2BDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 595C95A2A91
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:10:05 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-11de654bdf1sf464651fac.11
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:10:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526604; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZargtvH1nmV3oknjwYgEjCIWrFb2nqftmNAiDxj3iDCkeOZPxxuCIlnWCif5qwY3x8
         Qvnl62D12gZADQ1HO7bXtDH32+eubbePV5ZWgexAgl8R6I2fmt8UrniNzUYXT+1gSete
         TydPx20H6DtgMiE++Ifdbyb9EvbAGz6/GZRtzvlWTkzxXPafkctHEHrCItuRDx+qA9el
         SNIHfpjsPyg+cHBzgSJonpEpnQp7aUyDTmWDUPszCSD+NRVnO/1dd+aysjtQQrUpJmjJ
         x31NNXGWcq1EOq6HQgvgirKc260kUMaS4Ddv9x7xauAFXIPiKCZg5lOQbl800ccf/8Nt
         Do+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=AuDvXiXNZAq0bp1+kCTvaQ664hedJU01ycUbv4DjZu4=;
        b=cWaBMBPBZ9CEQrPDguDtCBxhR/wG3h6m4nUzOelY4iIjkkp9TwivKlI6tG3OWVrmHG
         WM1Rd6wNeEQpyZ75/JscHoSxFmMV00UloA27qMu1imKlGsqjEnSR6CWDPU9K2ghNzFVK
         y+AHqIFYo/wUOZcBuQ2wy0Mmx9mTetoDJhY5h0f1AX/WTyPuLB0ltoJFDPlzXhZGLHjp
         bLNl2k4l/X7lEWAGfs32EQlBpDZFhLVYHS4zJrM7d4Q+nVPoCa57HW59BAaNbUpZK5xW
         qrjBAT6YgQg596p+9FZKWO6UB3Fuo5lLFwBMVe+w8lstQ/xI5wiNzmsyWgq+p7ZzaJoc
         gWLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D8g9K+F2;
       spf=pass (google.com: domain of 3suiiywykcvez41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3SuIIYwYKCVEz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=AuDvXiXNZAq0bp1+kCTvaQ664hedJU01ycUbv4DjZu4=;
        b=PLGmYINmJ8bdQkpi+vYI4Vy+j0GXkhwBbx4bcMZwcyMf4vOwiZaFhfpDeQ3ImKxhGS
         /T02xMWu7FOoycBF2PP9yX7g2oBNBgF+sP2L5HtVSvLPWKdqZ1XyGiqn8mcrZGL80rbC
         diwlDDYmMlidx8OVnoC+5YNMoh6b9wqyJUmCjdDgphg4e0siLUB5eSETmMACGFr0+uwI
         ar+9aQKK2wpkiK/WUXUcjdKI5htmEK8AvxERKGXWOzmkcvvPGCVnj6Kjy/cWT7hh17Pb
         qN6iQ+k+4FhWz2GYkXPcpJsmInldEuBq1fq4WcPnHI9q3gZeuQ+Y1C+Pgzb2wH9uClAT
         BOaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=AuDvXiXNZAq0bp1+kCTvaQ664hedJU01ycUbv4DjZu4=;
        b=rIsUMQ/7C7LRVt08ihozU/RPl6JBHdr8j1iEbHfXYXLLxZYbKJljm53NR12+iYj0E1
         jps+2kGgK45Pj77CGgRnicdLNlWPiv3OEB/Oy/rHhXqrOOKunSq5LfX6YpZpSoH1kY+l
         ePONR4CWUXfMsHGUdl3GIyz0kh7KGk0dR7zeaZXHDP174at6NTPCGmojfRnqvp0oB1Oh
         ZiQGpzVB/LbzYtPUhWIOiTCYRxH1as0tKsZiQiG2arTeHmqRSpAkEbn4/EgCUYC8+Xty
         PCW1yIjrkGfJqkLHrk/zsE6kSQHCoI3WKe62U+bHjNyG6DdnjHb/4Z3EoqdjU1N+9RB2
         Z42g==
X-Gm-Message-State: ACgBeo0N+QWJvdh7ABQoFZmp+/SZBXYS8zTBtjCldNIGF3IySWO2vxhE
	6ts66ISMFuMNZuxAIGvi5Gg=
X-Google-Smtp-Source: AA6agR6mbqaL/W2WJgW5VTfxFP65iNe5AVeERgSFUESTj45FQ/men/2IzMB0LFMpuvDoo4kr5AYElw==
X-Received: by 2002:a05:6870:45a6:b0:11c:50a8:511c with SMTP id y38-20020a05687045a600b0011c50a8511cmr2025775oao.91.1661526604126;
        Fri, 26 Aug 2022 08:10:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:770d:b0:11e:47d1:a33a with SMTP id
 dw13-20020a056870770d00b0011e47d1a33als853031oab.11.-pod-prod-gmail; Fri, 26
 Aug 2022 08:10:03 -0700 (PDT)
X-Received: by 2002:a05:6870:4624:b0:11c:afbd:c678 with SMTP id z36-20020a056870462400b0011cafbdc678mr1977710oao.168.1661526602911;
        Fri, 26 Aug 2022 08:10:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526602; cv=none;
        d=google.com; s=arc-20160816;
        b=jcyjWR/cfHbES2bOHXB3Ka6XEfjMFQPewy31XBOWzn1FoJExE2O5AQRpGbxgrHXTy/
         ZH2zlyqEvqVoBZPWlPx0KlSO4UReM6dCXDahhOvLKLmW6snp9jdaTMhgVwjyDzVC3JJZ
         bzIfXM9YwdW5nMLJHqxVWr6qtPvgdc5AmjGP1WpP6S4Bq3cLY2KxW46gfO04mDVM1kbq
         9Zy8sd6aibdZzS2e2C+7N5DDMDN2hZLVBqlUwDJlb8NE4oEVf+LxIImqGzNd5a49TCQs
         MXaEd+uCOKnxLVTjARE8shjNvAawfrebDwsk0MZYM7QYiIYT/w9+8d9ezuTCp1LL6H5V
         gXeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=4pDNTP8Rcz1c/6m0qOjb0X1O42ovrN3YaDrJNkQcLng=;
        b=jLShSDq0yaQHTmfgAULF44wdzo8kFd24XJG98W3y7VqfmxEDC4j7dD4nGx2S0WD7ud
         nQT5Vr1WjvyVT8JkEoxn6yxdX5G5RoGvtFYH9Xg4xpgZ6dMNxiVG969OeN5V/mpZOfTJ
         21++YsAyVYdl6Mm+YT1ag4mpT0Gnwi0zmBFGu3LhoL7sYFV8W4VF1sIEIaqLYUuW2hbR
         MLWCbgFDvv2AfkWQixaxpElk9TjcP5VEKlpurLRnbgziCU+5zRLTqZACj40lQp9PLbEJ
         WEQtgGt5J1pqCcaEJg1ZIksq7NkV4RdVyn/WVuXF8BIKafb/1c/CPQhp1FAQ7SjkYQdf
         Oj8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=D8g9K+F2;
       spf=pass (google.com: domain of 3suiiywykcvez41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3SuIIYwYKCVEz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id o7-20020a056871078700b00101c9597c72si293806oap.1.2022.08.26.08.10.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:10:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3suiiywykcvez41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-33dbe61eed8so29903527b3.1
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:10:02 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6902:10ca:b0:671:3616:9147 with SMTP id
 w10-20020a05690210ca00b0067136169147mr92484ybu.105.1661526602616; Fri, 26 Aug
 2022 08:10:02 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:08:02 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-40-glider@google.com>
Subject: [PATCH v5 39/44] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
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
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=D8g9K+F2;       spf=pass
 (google.com: domain of 3suiiywykcvez41wxaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3SuIIYwYKCVEz41wxAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--glider.bounces.google.com;
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

dentry_string_cmp() calls read_word_at_a_time(), which might read
uninitialized bytes to optimize string comparisons.
Disabling CONFIG_DCACHE_WORD_ACCESS should prohibit this optimization,
as well as (probably) similar ones.

Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I4c0073224ac2897cafb8c037362c49dda9cfa133
---
 arch/x86/Kconfig | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 33f4d4baba079..697da8dae1418 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -128,7 +128,9 @@ config X86
 	select CLKEVT_I8253
 	select CLOCKSOURCE_VALIDATE_LAST_CYCLE
 	select CLOCKSOURCE_WATCHDOG
-	select DCACHE_WORD_ACCESS
+	# Word-size accesses may read uninitialized data past the trailing \0
+	# in strings and cause false KMSAN reports.
+	select DCACHE_WORD_ACCESS		if !KMSAN
 	select DYNAMIC_SIGFRAME
 	select EDAC_ATOMIC_SCRUB
 	select EDAC_SUPPORT
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-40-glider%40google.com.
