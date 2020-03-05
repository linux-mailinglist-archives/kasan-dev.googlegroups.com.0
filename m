Return-Path: <kasan-dev+bncBCV5TUXXRUIBB76BQTZQKGQEX6DBUIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 75C0417A95E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 16:55:44 +0100 (CET)
Received: by mail-yw1-xc3e.google.com with SMTP id c125sf8275633ywf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 07:55:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583423743; cv=pass;
        d=google.com; s=arc-20160816;
        b=GECmU2gVChaPCBvYy7mXPB1zj2mRiznxK5p9wNXL2l9k7Au8ByZ1yR33GdEIVoqw9X
         OPSt7cuhSnAk4DR1lLwijh6eY9iTW028tDg2sgb5xEF1tvMGh6MZheN8YmRze/lkgBtd
         lXcViZzEMZwPn/kwapTtV/KMAXrRu9TnsQKyK7bSBEvTeE9H2QJOy/TfraCuyuXOEINF
         3rPcXjXqO5VKP90pnidKWRULQUWfs2jsoJgmeX+z2TDrP8bmkdUPyoYggmnGQjnrJskI
         Dc5auhrs3lSYiWI9O9jAI9uIi6vK6LxK3dSa6Of8zyhk/skmX1oW84YiUiErmcXs6tlT
         u3Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YmjnW2TXsv6vPpOIRkAHysomNnuDADkXAoVTfmjIg2E=;
        b=Etpu4hX1dsBhvmxDl1Mw9l0U67/+FZLenjahnrJr9ssYF2cnvc1Oxe0oeWfquhUVul
         lh5zzTTFApvUZTk4q2To/lokUwYRD2HzmU1RBNIl3EtBGafDmyBPdtCrUAxtVbGxChLC
         aCzfC8eCTRNY+svrgQun9IHRl7LRpFxvpqArz40/Ij3p1bw7Du3Xe9uLY2fPai/MJ9JC
         YvBWAnTtn++/FFqwFKl5kg5MnUwU3NKuoNi4MkxqxZKfYxvszVrCmnhpmM5zT8kmHH91
         qKFbVbjQ6ut2xn5r3tk0dRkQLNm0MdpgPESXfcuJLENShsMAiSK57r7qKcmJGwD8SwaW
         qoiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=O9ePjkPt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YmjnW2TXsv6vPpOIRkAHysomNnuDADkXAoVTfmjIg2E=;
        b=Q2jHC87s9QaolMK6nEIyoV8iMRP6sk0/1LC9Avk/c4gh+gQaW7vxUP7ERAKyPu/P0i
         +ERFL7abPyZFL6sxdEhBZ1MF770QTa2dAuLPbZsm5xL5GKraebIx8GDVwncvqYM7mNN4
         jAUJG7esGgpb0n9baLD3ET1jC7v6i2O7Q9YrrZsSaFSBI002idxE/x0hv6eayl1wHAMB
         TudIRfrofP0iSJ+aPFTfccM+9H02O+8RlL/6kXX1/kmptcl5wQ/nrDouRpgkb+xhHv7d
         8+DYqAe6KQd0Hssd2oAAfmHsIZgzwnQu5gOOtlfWfdSMr86glbCksEMY9Gyv5g7eUNsm
         3JMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YmjnW2TXsv6vPpOIRkAHysomNnuDADkXAoVTfmjIg2E=;
        b=FkaJK+Bh7En+0R+7VYcYm+2yL5UZ9sCEA3hOyS1AUCuyfaSjlmeNWHt63uLg/RbqGu
         nx1zx458YGEZJpijbnOqZSKJA+bVi/XDZuZ3MPPIo9St9DDgTAswdgstdM848EKjIMNi
         X9mYrToMEljVmx5jijQ1qWIxnUjU8n7M7y5ybo8FB0YDeWBKvXJiW1+wNYzb6Zv7fVBS
         hcglH3354BBPzcTOiiM5WuMwx2lHDAvLzSOQGhGv6OsXeO/QNca10K+K5ydqXNdUTk7m
         aTYK3BNjNwPRS0A0Q3LLyl43D8OudGWeZwHy8Hatf8HhnLVuIyLNtLYy4ZwZyc/xQZH9
         /j2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0H8fb2p5iTLp546aFdJrrpH7cXNVazaHYp1han2TnhR6MxfZsg
	WMpOyctikBupOic4OzbFA5o=
X-Google-Smtp-Source: ADFU+vt0vA1CJvoSOe3xxUmyfioOc+EV9UE2AuHpd4X2GnXySwerNTa+xMk13jhp2zw+uK73IvA5Bw==
X-Received: by 2002:a81:1492:: with SMTP id 140mr8954423ywu.41.1583423743507;
        Thu, 05 Mar 2020 07:55:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ca87:: with SMTP id a129ls202961ybg.6.gmail; Thu, 05 Mar
 2020 07:55:43 -0800 (PST)
X-Received: by 2002:a5b:384:: with SMTP id k4mr8849532ybp.305.1583423743094;
        Thu, 05 Mar 2020 07:55:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583423743; cv=none;
        d=google.com; s=arc-20160816;
        b=lY6CxTnu+mZIcKXW+0MXFVguh1gOk83NQllLgxQJsG6ph2KxjgbyzKeUdjfjehj1jG
         l0IXLbmBV3QvAZYbw3Hp7XUHrtCvexso0wgfQq7MCoT+mrIINZg3bXpEc0GXBxiVur7O
         MiVWYipeJmJ90Ma8qjMFQvUxIReG6uHuMP2FR/r0dyTaK1FuJJ6REgcStg92Yuxy8b3w
         e2Ynt6XHNsff6f6fMWenP5or88cqTzNDOekMe1W45ql/WejVBOi/PEK1cHDvhx1P9bw8
         buqRNABGsL3w409OYKPOU0nZJHK8UEkzuMBo3AQg+XBLKzk2ZwbtBbmS0R+X0UA2WCJj
         HEnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pqP3EJaXMvpqRezU/fDo5qexN4lOmJj8QJP8Ua3TEy0=;
        b=W8si+kP2riLyhE1JbswqLhWsgGFfOBJN/zV7sEsDyYJJGHyvqT2RPiKwwr+lIYyKls
         nzmIBteCRsr/l7rfJS3+7HtA/RFqkrm7gXBexJsgduoV8z13In/ugaIqQFmR5HXeBKHY
         uauA4EchoYTTgCtHq/rU3w7goIGVansfWMLvD5auZaOoKmCLHUiQrkXuApFHfsd1oiYX
         6RwKAz7VsMwcah7Lsy1FPC12klZVljXtBxvDTNy8HP3LXbtQRj+S6h8YBdsCuaOO2iB6
         /lPNnmRirc8gmd644vbRzq7XgbGxtV30IryztpXhBllwEmBg+RKXnwmTmccdk8FMIKtG
         h4NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=O9ePjkPt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id s8si348710ybi.5.2020.03.05.07.55.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2020 07:55:43 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1j9sqc-0005LX-1i; Thu, 05 Mar 2020 15:55:42 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 733673035D4;
	Thu,  5 Mar 2020 16:55:39 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 63591200F9DF2; Thu,  5 Mar 2020 16:55:39 +0100 (CET)
Date: Thu, 5 Mar 2020 16:55:39 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [peterz-queue:core/rcu 31/33]
 arch/x86/kernel/alternative.c:961:26: error: inlining failed in call to
 always_inline 'try_get_desc': function attribute mismatch
Message-ID: <20200305155539.GA12561@hirez.programming.kicks-ass.net>
References: <202002292221.D4YLxcV6%lkp@intel.com>
 <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
 <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
 <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=O9ePjkPt;
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

On Thu, Mar 05, 2020 at 04:23:11PM +0100, Dmitry Vyukov wrote:
> Compilers just don't allow this: asking to inline sanitized function
> into a non-sanitized function. But I don't know the ptrace/alternative
> code good enough to suggest the right alternative (don't call
> user_mode, copy user_mode, or something else).

Does it work if we inline into a .c file and build it with:

  KASAN_SANITIZE := n
  UBSAN_SANITIZE := n
  KCOV_INSTRUMENT := n

Which would be effectively the very same, just more cumbersome.

> Maybe we could replace no_sanitize with calls to
> kasan_disable_current/kasan_enable_current around the section of code
> where you don't want to see kasan reports.

It's not that we don't want to see the reports, the problem is that the
execution context is too fragile to call into random code. We've not yet
completely set up a normal C environment, even though we're more or less
running C.

This is very early exception entry where we still need to frob hardware
state and set up things.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200305155539.GA12561%40hirez.programming.kicks-ass.net.
