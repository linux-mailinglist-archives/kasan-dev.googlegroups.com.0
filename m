Return-Path: <kasan-dev+bncBCV5TUXXRUIBBF443L3AKGQE63FITVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 228691EC10B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 19:36:24 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id s203sf6135668oie.10
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 10:36:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591119383; cv=pass;
        d=google.com; s=arc-20160816;
        b=HKLgTHlr5vKaLSzC8bFoAASQ/klKy7CGoGl+OubPJn5f/JXueekaS2XOh1/Zf5Ye9i
         6OifMVn9p22LCH5de2oRs5oYYJbs7zHakLaw7YNmNoovbPnQCBq/mF43gWkGYXrFn/sF
         qRNLtpQ46GefpAhR8ELNdDkx1otYJ4Ng5MZtP5ByYa2QtasmP/zKz6XCPgVZucdMHYhi
         v5mYZJphpuYz8JCBXcaB+j/IEVvbP5/lX/XxFhiEa442lInfbFTlyt1fER1kGQpqvMdL
         gC6rJ5winp1HtWKvlYPe8xY5Me4l8MrV9a0+19AvcT2ODTURV1c0xbyci94Bh+dwGWUM
         YngA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Elan6kBugcdM4auhCjEVKf0chybqLB69y0lcGEMH91I=;
        b=SWOv/rccno94aoUeoqbt53nJYhRCA52+TtfsOscczOlipVvfOG5skCa26b2htKzMTy
         9YzEyzEZbyatKN0cxChWhpwxEIt1WAxTVBCZH+rpeGMdA465rsAevtwvDT9wbt7uhbKq
         pwX/hfyLLYX1IkQEEiWzDnM6wo36SWeFaErXQEuy9FjuxkfHPmfEK6UXKXFDds/uV27H
         vFzjhBCCX2sEsTsqL59T2zHMSPar+PCG4O11pEdbDcrlG5aO0Oosq9bnMUBcwZ8nOfGn
         qgiiiPwVdOwPC1GvRPouTrPX/kVjaSX7l5+iyDS5+JTIVcSFfiY3sV/r4y0Dgj3u/sWu
         O0yQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=Eosk0M6O;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Elan6kBugcdM4auhCjEVKf0chybqLB69y0lcGEMH91I=;
        b=T8WXj/Jf0Cz4V5fGPf/hTRqQZCdcIqMDg0lIISJhJikk0VSX/gsnWngloljbOOGbzj
         IJhS+A3PT6cHaPbf2jewYCX3m6IzZFN+8XrxA6UiPcBNERHFFED2uqml2vO6YT8uto2U
         C3pJWQTivkkBz2BgM5GNixGalJL9zWh/2CWXHjYFK0kbAZjDig6MOTxzqcKYg51lWAlX
         5ZvS0TlsKsxQ5HjRfors3MgAlQDlpQ1szZeNFz56p/KoiO66D54tLQR4hWKX9dO/wqDK
         /5LgYfBzfrswkOQPpjcUrLamZPiUDB4BanLwHesuN6JJ4+4205d7aHoDpM4coDH3QfVE
         TyVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Elan6kBugcdM4auhCjEVKf0chybqLB69y0lcGEMH91I=;
        b=UIMn0TJ4MhTKQ7bfhlgMh9LBp9+xG1xuoYd8dPVcACB/d80FeAXzLnReW5xxySuaM9
         4WswjENqvAjHiU2SIwsbL2RbBgl2sXuuHnkl8X5EtTH4TI1/07lbbUxx7Q+MMWDNrEdX
         YgOyBAa68y6a684vgz3cxzCsnibbHRYJZ7dhdeMnIUGj9Cnw9DJWRFO1ouSiffwjknkd
         DG74J1upRvEwIraQy0I60o/c0WQ7nv7p191QNPXPHczLHOjqGcwhnRnQerZA1uJD9c8q
         ccvdYiyjQlkxlIy+pMRNT7lIjFsF50fc9aPe8CqgUQFEfnNuk5zFuaDrqU6JAUqkEZjb
         kwDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jm12xOWVeY23RMBMbHDKbNQR/4CHWUclRbWvYvGEQyOkuPvVD
	alMKKXIq37e7LzL61N5LMps=
X-Google-Smtp-Source: ABdhPJz9BOXLYNSinPR52lbPjWoQwX3L6xPn3ybUMVsXCPY4/TIMb+Fvai1cj9ggjNIwOpNFnOj3Jg==
X-Received: by 2002:aca:6506:: with SMTP id m6mr3835742oim.75.1591119383107;
        Tue, 02 Jun 2020 10:36:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:590c:: with SMTP id t12ls2631286oth.1.gmail; Tue, 02 Jun
 2020 10:36:22 -0700 (PDT)
X-Received: by 2002:a9d:2aa1:: with SMTP id e30mr309617otb.86.1591119382761;
        Tue, 02 Jun 2020 10:36:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591119382; cv=none;
        d=google.com; s=arc-20160816;
        b=LLc4w2kYq+vlSf8ugxd+dsn+HbLU8tI4Aaf16LJ1QSAbiIWnptLX3uxbO55f6jkJEx
         9TN5H7PMqlP9tAkiKlsEnHtu6QMJbS1xoeeOyMcrp5CTQuTn0P5JRbu23MOFUCLM/Gf2
         IY6KE7QqUx22Cbk6tO8rmfM3yLPd/Y+uMMD8m8wtUvig1+xeBnrY+H7j8R7x/BR5kvQe
         2HUjN+tF5XRfadY+9prWK7I/P+WuumMSNvF5ldAnrTbjxQBkVo4z+QbC5axPNUy0BbBa
         Ock1yQu7Wds5lll+9GCfIoW6tegMyEiffWFqn1lT4+3MzXXJ1ovdMpwAFZjM7H5Qy8UP
         b9WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=h/a8DJ2EinTq8uzlA9vH8s3fN2Vz7r1F26+b/HdqMQc=;
        b=wn9UD4DlmoVxytfAl1eFmyBkN3erDM0zyrLcRsDr94tIuFM/wo4MOw9cI2B8soiEIk
         FI9zVuEHXvOA6HRjxm683qUURzblRRHJGcpx2eTLco2ObgASrgNlLkGvdvtm0UcW2bT4
         CK9w1p4bzhYOdOV2l8lF258FiuJvwVmT5uzqdRf0wG/0LYKn+hJXklwW3yVQYc15n+OD
         +VES1E+Yp/U7pPcoO40HSgS1uLpfak2VW0Ev5sh1iBKkrLsBTFpIfQzClxkC/3AzCEYU
         CNaU+yfQEkqwpTTjeNmzTEiSmi3YUBkHHsk4n/7Pmr533E+eBNvbvtsXKYpM8/pA0USN
         m6jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=Eosk0M6O;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id e20si180135oie.4.2020.06.02.10.36.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 10:36:22 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgApp-0000Tb-1y; Tue, 02 Jun 2020 17:36:21 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id DF384301AC6;
	Tue,  2 Jun 2020 19:36:19 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id D13D42022DEAB; Tue,  2 Jun 2020 19:36:19 +0200 (CEST)
Date: Tue, 2 Jun 2020 19:36:19 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Prefer '__no_kcsan inline' in test
Message-ID: <20200602173619.GA2604@hirez.programming.kicks-ass.net>
References: <20200602143633.104439-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200602143633.104439-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=Eosk0M6O;
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

On Tue, Jun 02, 2020 at 04:36:33PM +0200, Marco Elver wrote:
> Instead of __no_kcsan_or_inline, prefer '__no_kcsan inline' in test --
> this is in case we decide to remove __no_kcsan_or_inline.
> 
> Suggested-by: Peter Zijlstra <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> 
> Hi Paul,
> 
> This is to prepare eventual removal of __no_kcsan_or_inline, and avoid a
> series that doesn't apply to anything other than -next (because some
> bits are in -tip and the test only in -rcu; although this problem might
> be solved in 2 weeks). This patch is to make sure in case the
> __kcsan_or_inline series is based on -tip, integration in -next doesn't
> cause problems.
> 
> This came up in
> https://lkml.kernel.org/r/20200529185923.GO706495@hirez.programming.kicks-ass.net

Thanks Marco!

I just sent the rest of that patch here:

  https://lkml.kernel.org/r/20200602173103.931412766@infradead.org



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602173619.GA2604%40hirez.programming.kicks-ass.net.
