Return-Path: <kasan-dev+bncBCV5TUXXRUIBBSECTPYQKGQEISJ2MNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D7646143939
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 10:15:54 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id z62sf1177559otb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 01:15:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579598152; cv=pass;
        d=google.com; s=arc-20160816;
        b=PW7dDvnfdB/F7L/lg3BgitkCFf3rcxyEON6hnHEy9DwFR5hxXanK8RLF+Wy+1MJkjx
         9bBwRxtm2RtUTxlwGv8wnGfKDcdeNj1dtaNPD7wmXUij1f7CHnITpuWsMCaNRZp/S16c
         MhZv1kWj9tQDM+lnFyZqGpqJgYSwe5BKilmPJto/Sa+wrVEuDO0KDnQo99yLaA5ZMEyR
         GJa73tUDdCooRnpyBx1CxyuKAnRJb6HNn/hd6OhEWPotlDjAudRlnLga8twygqKhQoWR
         R3xTIZ0b4G7c8LAaDBE5hJI74czWldru9oyRL5YhG4JzhFEE+bPTj4Ug1MZ5YhObEnEZ
         Ur+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=H5qOvUUhyiqhk8tQg45qKa3DFje3xcvG6GYMc0g02oU=;
        b=E4zuFUGh0r60DGBSd6ZKpDFtyy+dpCmXL4CpEGtINnY/Jqtqeleop01g4PYM7Yf23x
         LpL4/nkwFm3Bvg2K/LPOJKhjqZ4oRoatPHxcmDuLjoDmwLxCG0PmbORVNEu79rwxpx9y
         wXouSj+xx5NN6AZCiRuKEe5Q4iRLkrWHR8iMN/1YUJHthunKyzXV6ssALDGhCufuSwbt
         KJUMW15Tnz8LqZmVrcDyTFPCDXp1m5hyrrRJuSo4vsRMniHbDL6/043zUC/M6acwYvyL
         BlNxVwBSYGeAe5PS0FN2IDvZV9CgtrzuHFVuyZrFwd1e1t/uql4FWwoIhDk8PvfevieU
         B0aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=BkLy0jiL;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H5qOvUUhyiqhk8tQg45qKa3DFje3xcvG6GYMc0g02oU=;
        b=adgVq1m3DbzQDDhBuVV+ik4YRoQZIfoG1QcyfGXVKBo6GBS7XqPMo7Rsvdu/mZKGDy
         cQQLNqYBHWLIlU3fGW1D7+SFeO6EssLBuo8wWtauQdalNGODDtc5E0NJyztLsu6K5VeQ
         ZOQXhHEuQd3LDgdu6xKCQkb8ZxiFsXCJZtOH+r4MKa+yINI6FyTVYoLRiQOcLOeytZpt
         c+WfJ6ptr11Pws3OcAbXnO/djhdkWM80J1+sXp6+kx9SBdIuUcyZUS4de8yuzHB+VSHb
         8lRRfGubBmJ1CEDn6SJgNMXb2rxu9OkCK/5LTNrmj1TmraeMBA5qJ00mlO6zR1jsVHry
         wV1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H5qOvUUhyiqhk8tQg45qKa3DFje3xcvG6GYMc0g02oU=;
        b=RAAaimg0Lj22ItLkqBp1vETiD6eJkrWEPjza+9VfxFpyW0Jv9wV55JLUo477ZMShcZ
         8PcUMqBT/Xvct5fxcmiHaKCWtMCfHRhrz/Rfg6bqRwXGDMTO2xcPepFzIz23fEdKl8lM
         1ktzRVpu/fZkf8uL/m91k4/4pcwFqgNDTk9rurryScsbuHyWwWQHL7q+182Dkq0a8v4S
         niIEWbLkoEHXNMJojdJP+O3R5l6jyd91rDMOUXdsneaHRB7bpL/rM90g8MOXGB9ukcMu
         p3a1BRCnLsmkXyOuw8cQYh08AVtCPDh13omdf8lrqj5W+51azH8hBEtNIjJIpXVglhOA
         sRNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX3B69f10bqF+KGQBeNpiGorgBwha2fp9NUmct5eaPTxzlmPVZL
	PXMLEIXAwHE0JHhwiVP+gYU=
X-Google-Smtp-Source: APXvYqx63LsKIxajqhwMtZXW8FSO44mJBmaMoKFMNs0fpgZenUIv/S8ueQxBIzye+ZK3lspqNwjQzw==
X-Received: by 2002:a05:6830:1251:: with SMTP id s17mr2891100otp.108.1579598152387;
        Tue, 21 Jan 2020 01:15:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7198:: with SMTP id o24ls6339151otj.10.gmail; Tue, 21
 Jan 2020 01:15:51 -0800 (PST)
X-Received: by 2002:a05:6830:9a:: with SMTP id a26mr2918784oto.131.1579598151909;
        Tue, 21 Jan 2020 01:15:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579598151; cv=none;
        d=google.com; s=arc-20160816;
        b=E78a7EAEtugrpq7ioUh22c0nlBHGyCFBbLhcjprGmt/OSPdyTJuFtmTmhk2vb5ekla
         mYhM0+/fW1bLbrXQpOToToo2Gq9210OYoAplwm+rQRTT0lSwljS4KkkDKv8H74qS7wcG
         Qq8RLOueR040ev/SzXjt4S6iL9yVFTkqBTshMjAGUHmr7ygJkWWdp3SOUOkfmMbO1jud
         nxOkPDFC5rmBOysTGXc4rMI+v8uzCr+QVGLA8mNRlvtZcKnOXymB3BluEZG3jFDoYOIt
         +4JYbov0fZfEGoAwE8npFWGNpQiBxBWbos+kfKvfvOA7Son2LAJR6nxSEIquxKcpONmR
         q5HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LyuFNpAXFwCRQciuWpZEuClZCiBhfl/IXNpqcj5ve08=;
        b=OcC3VN93MkQlKrm6f2SPxs1UnrgsWpR74HoM+KRx2d35xW0R6pndrQRuz+tkn1kYLo
         uyccSCgPvquLUCK/CPc3XM5vwgs4YOyEdIcHUZVFecIAyJjxoCcIg8iigGtOaoaqzTao
         TFRirNkGwk+rK9J1lzfQK6r+zt9BUy290CtCmROggtmAVe0ZAaRWceTotiXalB3nJHY6
         x+KBNfxCYu39OqY+T/wpB4l9WrT/DOBmEzKgQABmytqHxUxmPZn5Vh2r/jsCrBY1QbTW
         0hFAtFMD4XabdFl3nD2iNAWUPYYhgZT8eGT8g2/M6Uvn1MMtIq7tsZt+LcEksr0Bmsmh
         bpwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=BkLy0jiL;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id d189si1128849oif.0.2020.01.21.01.15.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jan 2020 01:15:49 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1itpcm-0003XR-Jc; Tue, 21 Jan 2020 09:15:04 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2BB0E30067C;
	Tue, 21 Jan 2020 10:13:22 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3645F20983E34; Tue, 21 Jan 2020 10:15:01 +0100 (CET)
Date: Tue, 21 Jan 2020 10:15:01 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, andreyknvl@google.com,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, mark.rutland@arm.com, will@kernel.org,
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk,
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au,
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org,
	christian.brauner@ubuntu.com, daniel@iogearbox.net,
	cyphar@cyphar.com, keescook@chromium.org,
	linux-arch@vger.kernel.org
Subject: Re: [PATCH 3/5] asm-generic, kcsan: Add KCSAN instrumentation for
 bitops
Message-ID: <20200121091501.GF14914@hirez.programming.kicks-ass.net>
References: <20200120141927.114373-1-elver@google.com>
 <20200120141927.114373-3-elver@google.com>
 <20200120144048.GB14914@hirez.programming.kicks-ass.net>
 <20200120162725.GE2935@paulmck-ThinkPad-P72>
 <20200120165223.GC14914@hirez.programming.kicks-ass.net>
 <20200120202359.GF2935@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200120202359.GF2935@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=BkLy0jiL;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jan 20, 2020 at 12:23:59PM -0800, Paul E. McKenney wrote:
> We also don't have __atomic_read() and __atomic_set(), yet atomic_read()
> and atomic_set() are considered to be non-racy, right?

What is racy? :-) You can make data races with atomic_{read,set}() just
fine.

Anyway, traditionally we call the read-modify-write stuff atomic, not
the trivial load-store stuff. The only reason we care about the
load-store stuff in the first place is because C compilers are shit.

atomic_read() / test_bit() are just a load, all we need is the C
compiler not to be an ass and split it. Yes, we've invented the term
single-copy atomicity for that, but that doesn't make it more or less of
a load.

And exactly because it is just a load, there is no __test_bit(), which
would be the exact same load.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121091501.GF14914%40hirez.programming.kicks-ass.net.
