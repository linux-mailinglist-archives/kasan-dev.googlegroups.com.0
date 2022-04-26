Return-Path: <kasan-dev+bncBCCMH5WKTMGRBV6DUCJQMGQEB4JPL2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id AA0B3510427
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:16 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id i21-20020a056512319500b0047223ce278dsf337734lfe.18
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991576; cv=pass;
        d=google.com; s=arc-20160816;
        b=RXE4WA6P/zdWIXxvbmSOITTmoNcIk3WYZLv5ohdALZ8Mezw+kaIsZXwhR5oyDsV92Z
         gO/q/CbwpVGl+/Zbp868EN2QWNHsTmE5tS8WPeB3BDke2vulSOi3cbW331Ph2qUnhDGn
         SK8Zy612zGasA6h3KZrL40FJPR9IkN8cp4Qa455LzgvcPqxVw5gEnL4LEmuD8sjDownc
         I8ad8hXkBeQSZyz1kxJ7zLXpt0i2AZzBEtS9HBLI96chr7XEHFDN5OeiBvnbW7ejSmQ1
         giWETm4842N4I0QOSp/OLrCm2p0SZOSy8wxbdeYtk3irViK8wskYcevfMipop2lhmg1h
         dnCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=jbAQ1rEaiqghVoQNjUxYIVCnG84UCQOH4CuUK8213AI=;
        b=cqe3Jv+32gtoT2rOPOdpv0HrscX024iXK4ygoKUEamtbXnVwA1ur5T8UVxN5mQf6+l
         ksU9pC5KWF5n11PtQGzzTVJF56JUCzsG3wty+3mF/IDJUPy/q8tN5lfD1zEQifjBHzhA
         uSBfTV6dpqPMbzxlg5sySpptkpMdodLP5Wox7RSECZdcYBM7TccuNgWGxrwwbFFIqwGg
         2sgjb+XW4oebTB8HYEl315eYqwtdph6g2l+NTuVNrliNopLx/Aqj9WcxE+pt2hVQ2/qD
         xOC9/Ekv+AOzcfwuoXI7Ua6ex8m6zGtzUNm//KF+O/tRBwKEbKKqE/aXqbWJPY4DV/RK
         LUtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Pt5+odsa;
       spf=pass (google.com: domain of 31ifoygykcdm5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31iFoYgYKCdM5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jbAQ1rEaiqghVoQNjUxYIVCnG84UCQOH4CuUK8213AI=;
        b=Lm5KPA3kNRPvBA7lf1i4IoGta3LxSnGp3VNp+FgP7FlzyFrfbp6grjgzLRa3qy0+Dn
         cGFKiWvVLt4d0zNCDzjs1V0uQRrHUPZLK2eevlvxZyj/A5P7ot9skeIELl5HA1BCarR+
         pyzr8ju4FszHTkIS4G4T4mFVd7CJOY1CntVyN/KlWqa4SJ5RLTUrGVPGpsTgae+1bb6H
         6LGgwcL6d2m6r1udqgBRDlrWBrttrClpGCrRERV8V55WCOLiO7RZ8nOrv9P+c/5evaha
         ckqNSbNoEUVORpy7MalNhP7xN7ZWxmnPFPcfCj8OyWqoaAeMdKOWDmWfIuuTVE/da0XQ
         qrqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jbAQ1rEaiqghVoQNjUxYIVCnG84UCQOH4CuUK8213AI=;
        b=h2YwVx2UL7bVRNUvuCItbg9xcrPCfK356RMShIQnewC46Umiwa91xV6vQgUDpuxJJx
         chW70Src252EZIxDQcaQsr+yAc2BpsD7vI1Km44MJ7jIEdEiSLkWNhY4y9UL3+0suxWM
         MlnZ5a2UlexCmZKeaYfVFkQgnya+vCbOFCtpba9TW8q3cj64Qr2zfNxec12NJsAYIYo9
         O+ZB3dr6ZQIXyuID3cKeaqh0bf9i9Qo4xOPB2MxPW5phj01fCyHifF7KSPom7XHDXz+9
         IMwuA5daF6EbnSyE04rHMRApw9cJ9tTc2Z7gufFhPnWZBKlhanbr5+o0tgJUxfnu6iAe
         zY8Q==
X-Gm-Message-State: AOAM531uIHIn0HybzRrQxg6RAbq8CaKUelhL3JTzKyFEt0Xuvecx27IY
	WeDrQFy6HxpbB79n+BtWhP4=
X-Google-Smtp-Source: ABdhPJwkA5Bk7r/ap7d79EHwY+me3pKsthZxwsu+TEf1JxV8o7QPxuyqGfXiOoa885GOxISetHX54g==
X-Received: by 2002:a05:6512:3484:b0:472:13f9:4aee with SMTP id v4-20020a056512348400b0047213f94aeemr3746928lfr.288.1650991576180;
        Tue, 26 Apr 2022 09:46:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als2089008lfa.2.gmail; Tue, 26 Apr 2022
 09:46:15 -0700 (PDT)
X-Received: by 2002:a05:6512:3401:b0:471:d471:365f with SMTP id i1-20020a056512340100b00471d471365fmr17473355lfr.294.1650991575081;
        Tue, 26 Apr 2022 09:46:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991575; cv=none;
        d=google.com; s=arc-20160816;
        b=iHrtPyf1lIxLH/yiKUFoVZJxiKnZH/sQU9Q7edhfdxuaMY1ul/nRFPGI4bH11Fdvtc
         TtfPoLAjtC4NNxnMlbwSJd7F6sCVrDIZzi0uO/h33YHXL0RURnvQLjA/P2ipKtcQJgCS
         xU+Q3pdM9gSsoex+A3VSYaQSVGfJLAfrqKmW0pP7PczT614RhDdH1k4B5sjCZauQ4R8r
         6Ud50b6pjcSpqEl77qowYeqQhJEJ6h3EFdRE7iu1ibyw/tre9QIc46JNcX9iONTSxbf2
         BODAwezRZdILRaAPm/92uCxfJjJ01VOsSQFTa4Jx/CYR/DElH0JDKfhWa99xsuM87klc
         iGRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=qZO+Ar5AUQjZ17sp8HnLfJ3bnZDmnQ4HtehVjR2RSag=;
        b=oD3Qa8Nyo8H3oISi5WwdzUYywI8pYR69hYCtsPcJ1vwv9JimRHCtM9djAkfw0yBtEh
         naUU6GgD4WmTjZlLd86EFZLzMGgZuOCM8N3x6Eu4YaI6PlyZ2aoOB9o7BL3KOvkGE2us
         8K9pzUX/L0x/C5pywkWzAC+RUrGlZoJcFWOwUbehLlaMg5bIkZ1XiNHg0pvzOljCnQSr
         Uacrs51+K7vBjEGL6sbK/Gf4u2guOZFXAUeNEilP7TgzWGQgt0aVDZGhv7lJ7M1dIBkE
         Y2xGdswB8ctHlwp8MlM+MQFVN8TUuXB+MdLuU5hiJ/271GIYFnRtoqb3ksZKJZKIxD1i
         7Jpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Pt5+odsa;
       spf=pass (google.com: domain of 31ifoygykcdm5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31iFoYgYKCdM5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b00471d641b327si606855lfv.6.2022.04.26.09.46.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:46:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31ifoygykcdm5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hs26-20020a1709073e9a00b006f3b957ebb4so838755ejc.7
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:46:15 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:2689:b0:422:15c4:e17e with SMTP id
 w9-20020a056402268900b0042215c4e17emr26075746edd.33.1650991574553; Tue, 26
 Apr 2022 09:46:14 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:13 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-45-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 44/46] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
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
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Pt5+odsa;       spf=pass
 (google.com: domain of 31ifoygykcdm5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=31iFoYgYKCdM5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
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
index ee5e6fd65bf1d..3209073f96415 100644
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-45-glider%40google.com.
