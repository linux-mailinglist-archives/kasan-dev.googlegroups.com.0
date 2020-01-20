Return-Path: <kasan-dev+bncBCV5TUXXRUIBBCHYS3YQKGQEDA35WFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B46D142DCC
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:41:14 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id z12sf25116030ilh.17
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:41:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579531273; cv=pass;
        d=google.com; s=arc-20160816;
        b=jAMmkZjyPFCgn2MYoum2u/vPveHOPdWfvTTbIPAgQ1789TaizZ+pzZaavzQGDFI7q6
         1W3ttHsh27SBMp/FUr65qiImL/gY9zABtuJzYuGOOjbeK6X0k+TgGPH2cLNwNaCZADYp
         HS82og3gTwQZf+z0Nas+7kP+inRamZ37OEHi1VoI175cIGdvrlGd1MZShG9BE4iAXBkp
         Id/pYwSemUlz7YAdVH3llrPttmqOWAXLGsZ23nMKHtoeLT7EgR9VKBJZGa/poYszOwOj
         SBV1kIE2CoLZTEy7PZAk/v6w8nR1J2t14IbE5qHQCX7SRhN4w3S10j/+j5mb3FYhmdFT
         87Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=CZX/WQ277kkfz3bxjCe5DPF86nKQsL81AueuoiWkP/E=;
        b=fdKm/tlDlHxjLBm75hkon0bNTMOkRsNKqWYNBL2vCKTYUDFVbJ1f0Y1XCybxrdTG5S
         cBBiXgGZmronoJiYCXr/QK1XtZPJtRgFWE33TDEYP56NvCw7OA44reK74YEXA0Q2kv8h
         a0RjALYTOJjQNmRlzXlmaIGv8UznaxlIEsxyeC8QW9CSkwbnVI33gD7NZYudLgN0v3pT
         bhbTBsynIRI2dzzmRFWRJpq1riMoDkgeTFJ4MgkpIDgxRkzZdZDgjcoSgCYGX2tISfdF
         3AwIBhG/veJ0wuxqS0g/DVrThJ51zKK/fRilQ3nOwOWx8hb0a/6rnIfY4D5hSLl+HKft
         ucng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=E2iEv9VX;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CZX/WQ277kkfz3bxjCe5DPF86nKQsL81AueuoiWkP/E=;
        b=Iifx9Ua7yfjPujZ4SCKMgKk0KB3qQpIq/LUK6dPgXckkKP5xWy76j1zJN0Qc83dxFR
         5LpUkHfSA8MKsmA/6L3I8k4KWoKx/yZ6RCg2hBRM3YDDrsxiKI9+JLJ9+D8QxSTrhgDr
         aRg7r9+mdJhq670lORUqlb2ykt+aqbwQeQnK3Uim1dyzgGuVA2Cp2ANk4GPhuT6/F8IS
         OJ4x6UEtHGKm0VLpWyOdFI56i4s2AFg7nuhDhcmQrNzGjkzk1Fa89oz7N5HSHZJ9Q6KV
         mIinaaD2dmn0inXZ+tQ8lzaD7ae70/ktQQ5cUiM2CL/BMv04oZ/LuFzUYNTOMUnoZzM5
         4A/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CZX/WQ277kkfz3bxjCe5DPF86nKQsL81AueuoiWkP/E=;
        b=VfvjLmly7m+Aem04ABpDq7JxTShYYPisq3i40ktxF5Y3g3maxsIetTH346tQTNQSvU
         k93MPTeMPh99cCcuRlM1NcAGJpD/5TciywN++0/jHfnh0cTYOrTFGfVAcHoSudK7I0ji
         ewY1SR85mJ4e/NpYC6i98mM0UdA4gEesBsXM5FSsgwhCdbwMJypO/KWnCb3oP4X9q+rz
         rvCvboya6QD5MEGhq/pyIk44iYdP4RkJiBtPrMznfcR8yUwp0TcPMsb7YQvDqdmSLgsE
         OeSSMAHP5csNh/iBNF3AjwcGzydPnjJsk3PktRf1gRQ98PGNgHBHA/CYXJaRwe9o9dPB
         F4iQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWsPtMcNLcqARI6PRG2zVPnRtAOPJ9eNNmkSwlYMiArjy0kmBrh
	jKUWMvTAl7eA6Hgg0LsgpdY=
X-Google-Smtp-Source: APXvYqyaCbXSZlkp21pGp3JPEGNh7A0UAuZt6D1cLEAjcZ+rurXs26Fomi9ET6xnhsVwqLd3mwzHBA==
X-Received: by 2002:a6b:7e44:: with SMTP id k4mr12621763ioq.23.1579531272856;
        Mon, 20 Jan 2020 06:41:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:607:: with SMTP id x7ls5711265ilg.14.gmail; Mon, 20 Jan
 2020 06:41:12 -0800 (PST)
X-Received: by 2002:a92:4e:: with SMTP id 75mr10847672ila.276.1579531272377;
        Mon, 20 Jan 2020 06:41:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579531272; cv=none;
        d=google.com; s=arc-20160816;
        b=aQvyJZHYceqd5BsAWYmzgpU7cv2f+P04fKHPM/N7bCfyib0GXlThH/TA0xFCUojSJu
         NR0erD8yM3V4C1z96U+CmPB5B8ZBwGkSEDslnl6RYhlmAiAfy48FE7dm/p/g7FDXSmdu
         cCCx8dVrIDyXtY0Qs9bsMLaj8feDtCXvj/EvUzjkcI4Y81qvlLmmwakt+HiDzgJFR65c
         +3+iKzCGimU91nyTkQYu/LmpOxcMAdr3JAGAQkgrxlisshuWzYXU2rNJhMv8U4vt+cHC
         dwLIeWgGU36zsZSOAPvCp+rXY5WBJaEjGXZ5V87s0YWTv1pIAQR00FKtc0BL6HQCXOKY
         WhaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4vIHUP9As2MHt/JTSJQoVlkdeNmF2zWPaSmNysm1Qn8=;
        b=Y9xU8vz8J+NL57Trycph65uTjjqCv3NMavIrGcF9/+EVKIkQ6A3X5/IQfI4dhm6Ar2
         ZXawOZc1fMRdbr2M+kyC+I3B6a+QhJCa7HIDkP9LwLkoAqcrSeCyyEaLOmud2kXX1PHD
         mJIAW2Dv3/wNhiGsTwcxMvW/ipua6MzeG5c+WlXkIC2DNY2IhH2KXQpriUc9yAH1J7Mw
         pKmKxNUfDvkygs1uGmUGip53i3DOicLB0WTRUrdHm6fm8HoYl32aR7Jy9e2yPOIdycbw
         CC4ig7fUCbnmmCL9m5TTFA/aI0/69WN1WaYydTtDu5Pidcm8VEGRqUtiluMgf06jLNCy
         cPlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=E2iEv9VX;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id z7si1713300ilz.1.2020.01.20.06.41.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Jan 2020 06:41:12 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1itYEV-0001Bj-4K; Mon, 20 Jan 2020 14:40:51 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BC36E3010D2;
	Mon, 20 Jan 2020 15:39:09 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 643E92020D90A; Mon, 20 Jan 2020 15:40:48 +0100 (CET)
Date: Mon, 20 Jan 2020 15:40:48 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com, will@kernel.org,
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk,
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au,
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org,
	christian.brauner@ubuntu.com, daniel@iogearbox.net,
	cyphar@cyphar.com, keescook@chromium.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/5] asm-generic, kcsan: Add KCSAN instrumentation for
 bitops
Message-ID: <20200120144048.GB14914@hirez.programming.kicks-ass.net>
References: <20200120141927.114373-1-elver@google.com>
 <20200120141927.114373-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200120141927.114373-3-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=E2iEv9VX;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jan 20, 2020 at 03:19:25PM +0100, Marco Elver wrote:
> Add explicit KCSAN checks for bitops.
> 
> Note that test_bit() is an atomic bitop, and we instrument it as such,

Well, it is 'atomic' in the same way that atomic_read() is. Both are
very much not atomic ops, but are part of an interface that facilitates
atomic operations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200120144048.GB14914%40hirez.programming.kicks-ass.net.
