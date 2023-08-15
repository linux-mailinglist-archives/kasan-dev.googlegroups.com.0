Return-Path: <kasan-dev+bncBDZKHAFW3AGBBX5U5WTAMGQEHAEXEJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 81A3677CB60
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 12:58:40 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-3fe232ba9e5sf35055195e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 03:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692097120; cv=pass;
        d=google.com; s=arc-20160816;
        b=EeRTzcPmB4OD5C5zIn9d9twOTonXC9UXvMHAqaWeN1hak4TD8PMEs3RsOe3Zgg7ypy
         1/xLOtYr80ZTJ032hxV4tL+JUTMwkk3ar6L0zmPyIch+eTy27NSwkfHztnfT1MA7SLY6
         LAioM0aKUi6UJX/wLxggVh8CYimIQTh6Hdh6ACDtW1q1IeNRCb+sptYoveNhm+EYSDu9
         BwjcfbJT7leyjeboRs8TpcXYSG2t7tzcshMWrhSm8ZcqYXUqAXRa9JwWEOooF6e5mO6u
         LL5U7cs8KEhyyzVi1wU2WM6oSRRQEAfpI4DmiJyQvuSupyThIO735J91cZ/OJUIWcsEH
         Zddw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fQL4O0Ug8avP6thGX5XpLYIKpUtnN1S65+kBut3hBUU=;
        fh=GyiYDglD9h29HXXbD45R+obMNrZsHNJsyw6W2UMF2tI=;
        b=qP4nuhyQZ2gkHwUQTQb6/Q1mMik+Ih/m2N0iNJ4XH4vCfie+QhR7hWszwdynbpZFto
         D6/AOSsVPOepz3Lv7IziUY8amRfw9JOYghMhN3Y4mm+YeZjiGDiWqyA1tjWYRKxI5S6b
         oB9NsuikeWT5WhMZr5h1W3vHNf6ExdVkvpoiiGjnQo0EbvJ4zvTDX3x/hQ1yLAzozrqr
         EuZc6vEQd8F1hXrtog3Yz5jhq5Z07ytvQe4zxhcTneXyzEdTX5ZZ5aRJkbGjnbZtHVHy
         R7hFUk5uiBiFmakfF6hOGw0Qn2wW5yaP6G4d5V5XCkBENuTDi+UbbU4zospVK835Zy1n
         2MSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=nCzEACRx;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692097120; x=1692701920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=fQL4O0Ug8avP6thGX5XpLYIKpUtnN1S65+kBut3hBUU=;
        b=YrmYUaNtS/Tv5x/jBa0T8ZVo90xRzue1ReEJXf7Dakyl05U+LctBHKyJQedI2eMSJG
         tG+3JgTkzJGlTD4DQJWA19kpe3pVzbnyPDTWgKrI+pt0hpNRYl/zdAz6kVyXce3CUDYB
         ype7PYKnJQBmN7FgGheFfvdZTZPLU+NMrhvncQoj8h8SAs8jLNwjmZ4gHepRsaH+JvyB
         AKz1GBZjYTPjH4meXvWC9iUnVEFvqsa5Sm86rPkdiJlfKdq98o7xwlgYnw83KZ/rsq4J
         8dKSLlTx1fJjjqzyKy4y0Tlw84502WF19iFfzmeVVFNnZ6TYqhpD8rOz+LQ06phwzs0J
         f9ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692097120; x=1692701920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fQL4O0Ug8avP6thGX5XpLYIKpUtnN1S65+kBut3hBUU=;
        b=HhKdDslk3MRQhljqFnUdDOfQx3e8AB6QpIl5CZQbTRFlv2xLI61rx8ci5ATp8yU8XV
         g00KJuhqKyQ5+0m6b2jpIm+NBM6xAkxBnpDES4Et8FnIrMvP2x3Ot4aq/Sn+vVNvSIyF
         u6shWGSbnRG/3EK1XOazQcufEw9rjAV9EZ8fdmU3+i/d+FUKpAz4MwslqldnJGkatQFR
         oryacBISNZifO7xeiGGjw7ZdJUF2j+yuKQhoE/Bc8H/02pSHoYTppS8hmHxpfsIwsQjs
         N3UYGSv1bMfGuKoLqEEFaDTe5R1zP544hQT5je1HYoiOek9a8v1Tb9KML4vZEK0qCqIG
         iszg==
X-Gm-Message-State: AOJu0Yw9KfkW+aK+X/1Z3n9bFl4iWyNc6KVC68nHdunA9NFtvr5Fv7jU
	VS8crJAOuyYuBjjlAAQJ1/U=
X-Google-Smtp-Source: AGHT+IFYHD5x41Sgwy1yiVxPDjXJ9+vEuuXMANIDD946IOgGdbvD9SMZmdVMbtEEXjTRoyJHvuR0qA==
X-Received: by 2002:a7b:c5c5:0:b0:3fe:2109:b9ff with SMTP id n5-20020a7bc5c5000000b003fe2109b9ffmr9148845wmk.0.1692097119753;
        Tue, 15 Aug 2023 03:58:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5110:b0:3fe:1d45:c71d with SMTP id
 o16-20020a05600c511000b003fe1d45c71dls54788wms.2.-pod-prod-07-eu; Tue, 15 Aug
 2023 03:58:38 -0700 (PDT)
X-Received: by 2002:adf:fd50:0:b0:311:1dba:ca65 with SMTP id h16-20020adffd50000000b003111dbaca65mr8444303wrs.51.1692097117960;
        Tue, 15 Aug 2023 03:58:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692097117; cv=none;
        d=google.com; s=arc-20160816;
        b=Dq88vr8IkKBmcIFlIdYGqJk4VU/aLmKuQdBoCpvB2DqnKrnx8KhO4KwjT8RcufuaJx
         5Kj4taNBrQEVdB3fxgdayU/w3gpuNjdXFqeDpu/vvc2TAFd7Sk9PYZHNJ6zzSk+iq4bW
         5pTPbfbvg1Ly6q99jSgnVMcdIg4CqwIyfyYPpwqC2c4vJzqELS90araOpVdXDgVe5ioy
         a6QCt6up933EKPGH16mb06L1+3WwJRYzC989xHeprjmmeN7EVNKRS//5ASyGufJj3oY4
         xQ9q9PCm/EW9/A5VvntgEXUQhrfnr8OAOcCzUfOxETlI/pIO0Iqf5HxdsUzv1R75GRuG
         HHVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TjwLfv27498tFzVSmNurY4B5Fz6kQ6juEBRem4lqZwI=;
        fh=vmUQn/KoiKBz0TN4QXh4zrTyMSy/18taF2m5XcOxj7k=;
        b=tk/0NCN/fMGo+Uc6WOuWAuLL6B6gNedkPvi7QSKXJR8dx7ah2AeTRwHglKSIswQ6zJ
         4EdzW8vOY27h8zuzXsp88F/oS8umwYbBUAw+ZTCYRY1Bk4MO2NE4COKAUEFESbOdaqXx
         c2lkwyb4aDiHdBdq1Txn54yRRT+s8jejN11yqMVq1qzi+tUq4CidFcqYhhykV5g6xRTt
         jenGOnJpbA4wrMAnRtuLlmJAsWWWgTyvLVExzn3dbSS/K109QZHqd7zrqLYDL8OJJaFs
         P5kEZABvSzSSscWmy1+yy4L2g5uaict5cOzL0d6AA5qqOK5cZbwmHoUm8eONiyGlkrCC
         9tbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=nCzEACRx;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id by16-20020a056000099000b00317b109557asi793941wrb.3.2023.08.15.03.58.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Aug 2023 03:58:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id 9D2F221986;
	Tue, 15 Aug 2023 10:58:37 +0000 (UTC)
Received: from suse.cz (pmladek.udp.ovpn2.prg.suse.de [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 582962C143;
	Tue, 15 Aug 2023 10:58:37 +0000 (UTC)
Date: Tue, 15 Aug 2023 12:58:36 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v3 2/2] lib/vsprintf: Declare no_hash_pointers in
 sprintf.h
Message-ID: <ZNtaXGQE2XN3Xuzc@alley>
References: <20230814163344.17429-1-andriy.shevchenko@linux.intel.com>
 <20230814163344.17429-3-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230814163344.17429-3-andriy.shevchenko@linux.intel.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=nCzEACRx;       spf=pass
 (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Mon 2023-08-14 19:33:44, Andy Shevchenko wrote:
> Sparse is not happy to see non-static variable without declaration:
> lib/vsprintf.c:61:6: warning: symbol 'no_hash_pointers' was not declared. Should it be static?
> 
> Declare respective variable in the sprintf.h. With this, add a comment
> to discourage its use if no real need.
> 
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> Acked-by: Marco Elver <elver@google.com>

Reviewed-by: Petr Mladek <pmladek@suse.com>

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNtaXGQE2XN3Xuzc%40alley.
