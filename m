Return-Path: <kasan-dev+bncBAABB35JS7YQKGQE6AAZTWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 0869F142F93
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 17:27:28 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id g6sf20930822qvp.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 08:27:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579537647; cv=pass;
        d=google.com; s=arc-20160816;
        b=t3Jy9eoko7uT24cKeiAcvK1BEoopqH6KTUfo5elIVsjqeQoR4uxVgXbdwQwJlB0Kxj
         LYgsq1amVlU4fkAfdaeLfU6V8ZrUxKRvLJ6Idai0inIE7Ig14/32akRDE3jNV1dGmKLw
         LSGqvSFjVS+gTnCXh7D3M4UGZZJkjhhS5K1RKOOlueClJvmoEyt7z0v+DNSK3rl4cxH/
         1IQWH4S9MJ6vUBqb0TaxBvKgpvgn1TCw+OiWpUaZDCx9XsRvleny4gfqlryAyg816vS+
         AVdTz0p0XOLRsmDA9mJ02nf6Qf5R65kAUJTnguWcnek/QZurHpkGyQDK7CLs6Opo3A0D
         6XNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=CjM2Unc7uOGxFoAHj4DcPOXyLcAwLralKnl/qllGeb4=;
        b=u6nlwQ5I8QWzl1V2HeSFEWPrZpcThnEnmeSmETCMMOdzsTq+UTxJwbO2BAyDnGGojV
         cpFWfCoyiqim0ZkNxSFNS9rperKn1oE7cB8VHyt2xcBRTU3evnh0+Qhn8508vUElLpqk
         fyQMsLu/xeygvufdrade1eC2jaUy3X8Rd7Kv11/x7l7iRwgXNKQLZYXgARShYMngB+wo
         UB6FGn2yb+T4ij8RmMAGliARuP3/xUzkFP+S5F1eTap45vNcFsxqxBjs+Swp0Na4oUsj
         Pri0mGIrWxXYanalS4HTL9l3bCbPHi1UZBSWd+6Twyivlfk9Q39iVcaSqT+IM+Lm+Vje
         ZgCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=02XheXlN;
       spf=pass (google.com: domain of srs0=4bvu=3j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4bVu=3J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CjM2Unc7uOGxFoAHj4DcPOXyLcAwLralKnl/qllGeb4=;
        b=Gk3dS2CzI/R8jaX8PW3uJNyjD9mD4JD//XB837aj7Cttwvh041GMIwtw8xdAAbVluE
         O8kIgZ9dLXGvzRpjREQt30c7TGsJKWU4vcGuLtPUtHHlyqCPCk7tom+jimQmJMX/jeJJ
         RZJ1Dg1bIoH8jmQqgtPc/hQejIfkPZR53UVMUtHqKB886urrLEDb3KoNPqD2qnkXm60X
         d8P4/Og2xRpD6vRO5CEC/IfT+gIZn0RIG1C2s5m52wHY6x62Wmc27Ts602wyK/do8lse
         ixt5YOS19tppXfCdkepl5I9vs1z09R6U3oPK+gntYExDyr6X2OmJzLU1pAnB47rmu8Ak
         vKCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CjM2Unc7uOGxFoAHj4DcPOXyLcAwLralKnl/qllGeb4=;
        b=E4Et/RYyiVgrOb9pJRYo03IBT7U5Wh6ZQarjQXncc7VeNQrsYnJngnsDChZyc9KetS
         vhcW6BmP2SUBqT8r62JVVG1vQtl9aq+3ZeJa2QCXwwAsevNgqGuwDaguEzsv7fiLvAeu
         FktkG80xor6qXb6EGbKItrpgmFjsbgwPu824E8BXXE+5/05CWNwhqg3pAO2m7a921Owz
         mxxjws0u8JswstRLBVcCYH+0tRTxHEZ8DmDQ8oNpzFLndzCwoAMmsHeMi3cX6eFkuPLd
         J0BMOL20uG3OJsDE16d7kRF4jSoEsPeTd5yQvONU3B2WlJxqTua1/pHRp6wFeAOneN8C
         qfHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAULWbj/zLPIMddrkzMVLuoxZKk4gadrXXxpXDhBhpLZNWQ533I1
	OCiwbW3a804MRqjidWHTAfU=
X-Google-Smtp-Source: APXvYqy32dV1AJ5S5Oyf3Gvgrm046LF3t2KFEhs2eg2m0OzUgpdwghVrY9xqvIevJH+cWmJXf2Kg3A==
X-Received: by 2002:a37:6545:: with SMTP id z66mr284833qkb.367.1579537647092;
        Mon, 20 Jan 2020 08:27:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9ec3:: with SMTP id h186ls9647128qke.3.gmail; Mon, 20
 Jan 2020 08:27:26 -0800 (PST)
X-Received: by 2002:a05:620a:12c4:: with SMTP id e4mr274496qkl.359.1579537646779;
        Mon, 20 Jan 2020 08:27:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579537646; cv=none;
        d=google.com; s=arc-20160816;
        b=qtfqs+uTW06oily5LSdGLmATZsZv5Dh9svnaYTFv+MZsaIjkwD3+E5o+KbiNnhlaOX
         yGn1AlJ7mQllWSQlY7fQeTE2foKhYAxPSDpGlZDS1SqSSCWOU6sr3Xe9EyJW3jw2Msmz
         4CxY9120D385EARkeTwYaRVCs1tKBQtmhL5pFEWs+YRxRdcyjSjR4BfvMsqicYwvJ4rH
         Lry2WEwnUhwZ8GFfVQfdXGnywa+IuXNZA+UiDuYCC/M+wFTxRtrPtfqJGg1GpYTmbzP+
         svCg7ObM0mZNMsN6wV2FL9/wWPp42kxw91L3xTE6p3KelQa9oq1oT/tBAmvGs8Yp1VSe
         7Vzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=92T8YdQWP18pj6Sjol61wLG+CsQ9JHQzNau2a+fr6bA=;
        b=cD7NJ9rRllno+cuJSW4iwTaup0s0YLVt+T6BLXxovHtkm+96p8jfhzgdsrVCBEIWQM
         tgizhmI6JvAapY45Lw/Pe104Rv/xw8eGnFEIrkE4Y5HWX0WYp/HGPOaeotyU7bsH8gG6
         lLEnJyWpOFRKe84kZbBHKzrsY5os+tn/h1h8EBu0nuWPw6BsgKf3khyAFCaupVj+A7WB
         DbCLPKPhtXT5TpZ1GaO2dtEErye1tZV9CUr+WhQUgi8tRH7PcV1zAZjzLEz+wtNRSroH
         Dlqt2000/7wbZ7N//w2ZHMX4E5CRjJ9rlb2yRctqi+rOTNm1coLj4Vwl3ItMXXAJIciy
         E7zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=02XheXlN;
       spf=pass (google.com: domain of srs0=4bvu=3j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4bVu=3J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h17si1634829qtm.0.2020.01.20.08.27.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Jan 2020 08:27:26 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4bvu=3j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 96FA22087E;
	Mon, 20 Jan 2020 16:27:25 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 6A3543522745; Mon, 20 Jan 2020 08:27:25 -0800 (PST)
Date: Mon, 20 Jan 2020 08:27:25 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <20200120162725.GE2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200120141927.114373-1-elver@google.com>
 <20200120141927.114373-3-elver@google.com>
 <20200120144048.GB14914@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200120144048.GB14914@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=02XheXlN;       spf=pass
 (google.com: domain of srs0=4bvu=3j=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4bVu=3J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Jan 20, 2020 at 03:40:48PM +0100, Peter Zijlstra wrote:
> On Mon, Jan 20, 2020 at 03:19:25PM +0100, Marco Elver wrote:
> > Add explicit KCSAN checks for bitops.
> > 
> > Note that test_bit() is an atomic bitop, and we instrument it as such,
> 
> Well, it is 'atomic' in the same way that atomic_read() is. Both are
> very much not atomic ops, but are part of an interface that facilitates
> atomic operations.

True, but they all are either inline assembly or have either an
implicit or explicit cast to volatile, so they could be treated
the same as atomic_read(), correct?  If not, what am I missing?

(There is one exception, but it is in arch/x86/boot/bitops.h,
which I UP-only, correct?)

						Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200120162725.GE2935%40paulmck-ThinkPad-P72.
