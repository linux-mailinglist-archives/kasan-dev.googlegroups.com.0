Return-Path: <kasan-dev+bncBCCMH5WKTMGRB376RSMQMGQESLGHNNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id F34F65B9E30
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:23 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id d16-20020adfa350000000b00228628ff913sf4821666wrb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254383; cv=pass;
        d=google.com; s=arc-20160816;
        b=UxbvjKNhbnXv4MOghmmFHx/RjJ285UrEpMjVeSMfW6PK8T1oLLFI5gSuX9WqJKc9ZX
         D4Llr8fQvqsAkIWHPUNIxLwGtEglay6Kuu0baa1/8NDtF8PS09v3VAqh/VNC2FQ1HBM4
         r++qGfz8DxH/sUksibPMx+2u8AR5Wa3s+hRcssPnpJaRVnQgO0x81RXuoGCcoE1Zvo0y
         8exPYF9G7enoAQTBsvQc7Yn8t/pugE1RSTZZ9L0tDouPbWJpTEHZbsm3O6fQEOovpcMr
         Bhu7UNnCqsMCJaUN5ICB2/c7kANuw8mMlBpYPPe7Lt56sWF+Crfkz4f2CjWPGjPTn/LR
         dozQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=qAHSfPBWJu+PI29kfH2tkH4wy3tXcFdx/Hz5lcOmls4=;
        b=IhZK5HyOna51fcD4DZioREoygDiNJdOa+1z9AZFOQNJBC+/YhEe/8q8cPu7nktp9BU
         vY+Ygkh1cdFctJ109c1gcQcRLaz8e7IHSqcTkgYoW8tvY1/HXhvBodRRfmqZdGpEE+7c
         IQa8m6ZCvs+JDLj9G5yKEXlpvcTB6et8uKVoFNaFlznWXBWpC6V9uz15cGevhRkFuFyB
         FM38pMNavAMiivaTSoAjPEBxO54JhVbCZZ7AkYyy+8suHCwb61gKh1IjEmIPR1vFSODw
         o910gDyifmOCmiegNlowIGjIWNlv97+WVMA68g7ncQUawSbLbXj36LrvfnhVfF63Smoh
         ZJgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ebn9L6x3;
       spf=pass (google.com: domain of 3bj8jywykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3bj8jYwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=qAHSfPBWJu+PI29kfH2tkH4wy3tXcFdx/Hz5lcOmls4=;
        b=RBCykgbPNWLRQJ0n77hPOnsKswc1k0+5WzDBSXsqFaUHYwb5plLyV6yyj7aQb0eyIS
         akUrtCK0ExH/MWFCFoj/tOwsMsSPlj89F1/LaaujxKHw4PrgEK53racAKhbCcCfodV5N
         G3y5EYCJUYrngOPKvY+KPlh4Ez6JVBkBLlBmcJwPvwn1DzoGu9L4fJ/+akXBBwqCOLa/
         DO91vDkPG7oYAni5yiW/Xhv76hWjOX1MdIL87Fq9n9kxFwLVnz+PpQgi+tbEQ5+4WJXa
         dkRkTVPMSqkQTR7WsGgJjoIuw6SgNUr1pSKG9jJy5oODyG9FUQOQM2nUV3Ypq5wcay6+
         hiJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=qAHSfPBWJu+PI29kfH2tkH4wy3tXcFdx/Hz5lcOmls4=;
        b=yM1v2Qg3Cn4sVTvuBmdp96EIOaskhoz9aRcCfTEU/+1jI1yJuHWU1ll7UQ34gPSGAs
         KRkqZeFqFRSO6Tilm7kF8ad95icMWeFv3MXMvp44MNFtd9Ds7JDEHj9lQ2N79epcsBWf
         4un2G2Y5DWHXGgzW7KwQKO2oPGYBtZU3q2hQPuDQ9pnbguYjUXyR0wFKR9JUkAEwYVSW
         JTA+C3snVrPXGWOimhiTNWGkCIGejFckYwBqwPz/+jjm+ADpvC8hqICFr/mRX3j8G9xB
         a8B9SzybG2dlnh0nyPP5Xdpw+sQNfnRuG8J33UPbphHLGZNuTQ7oo7nufpXYPzDlMFK4
         YX9g==
X-Gm-Message-State: ACrzQf05u0fGR9++omhQ5k9hnsS3pgf2cNtxQozO8CsGMoxdvpfJOlc+
	bzznxl2D2AfvDEdO5D14wTU=
X-Google-Smtp-Source: AMsMyM6RX5JJLyN0MH0FVuS3apn1V2PQAvOKSV4c798tZMHgtCZDpsZBo5Az9O5BaHTMCQKArAOywA==
X-Received: by 2002:a05:6000:178c:b0:223:141:8a14 with SMTP id e12-20020a056000178c00b0022301418a14mr49613wrg.629.1663254383760;
        Thu, 15 Sep 2022 08:06:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d210:0:b0:228:ddd7:f40e with SMTP id j16-20020adfd210000000b00228ddd7f40els3208179wrh.3.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:06:22 -0700 (PDT)
X-Received: by 2002:a05:6000:168e:b0:22a:4e45:7469 with SMTP id y14-20020a056000168e00b0022a4e457469mr45035wrd.681.1663254382421;
        Thu, 15 Sep 2022 08:06:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254382; cv=none;
        d=google.com; s=arc-20160816;
        b=c97BeMyUwvTFFd+DPopsQGCe/EbXHtU+ZkZ6shhtgcNndnrW6Wc1wAMbUGtN81Gm32
         1mCVpa278RkR1bGi9QGb5mC4GJAilbp+jE3ajcnYsGzkTILZX5bQOLub9fZi+7mhONMd
         aDYoC0x+Bhgp1MtB4SaLkr6GbIIABHwPjsX9oQ2rWzIgiCTSVi9zNdg5YK8NvxWip3Ge
         QlW2gxD4CvzpLTY8K5LIjdmr8U3HTcHrvcvyFTXDafttxctBgJlyoxxJB8kPgeyus0BO
         nN8OSw+gzs9rw153ZvilD7gARefsn2NcGckGRNkWCjX6IcTwTOWKB/oT9VdQXNipzbAt
         cBDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=y7GARGHGPpfPMqaRIp9ae7D7QgvYSCiDFPeV4nzQ3Rk=;
        b=WYltejBAU0orgmQN1MTCHfK+FkuIaPG07taSHxDvtAirGB1JAk02s0cuYBa1+MAqtW
         ofGVsrYNy1rvzTujYKOdw2KMCsJ6+7u7JX5lwyRaK6wWntftnmow6YzJC1EoB6R1X5r5
         RgIlgPGuGL6AOO1pGp60CPTYvBKZ5I1ShlDFXCgHSj9yH0+cCoh5SbBMWywvUYgJv0KW
         JrR92IjW0oYV6p/PVES0Sw6K1eRvpnOJ78e3/amDY2wLOIXdU5TLRZ667+Ql6M5SwqM8
         saXEIAZ1LTZ+Eu7BF6VxGAmgJu/ZoQaioS8CMnMJ7tUwceI1Fa/BiVHFW4hWPVEE0jW2
         lWgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ebn9L6x3;
       spf=pass (google.com: domain of 3bj8jywykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3bj8jYwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si72434wma.1.2022.09.15.08.06.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bj8jywykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id y14-20020a056402440e00b0044301c7ccd9so13180735eda.19
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:22 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:75ee:b0:77b:c559:2bcc with SMTP id
 jz14-20020a17090775ee00b0077bc5592bccmr266153ejc.537.1663254382083; Thu, 15
 Sep 2022 08:06:22 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:12 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-39-glider@google.com>
Subject: [PATCH v7 38/43] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
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
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ebn9L6x3;       spf=pass
 (google.com: domain of 3bj8jywykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3bj8jYwYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-39-glider%40google.com.
