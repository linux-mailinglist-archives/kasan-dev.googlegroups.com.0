Return-Path: <kasan-dev+bncBCJZRXGY5YJBBWVC7OCAMGQEA4OSBWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id BA9103810F3
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 21:36:59 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id a6-20020a056e021206b02901a532cdf439sf648863ilq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 12:36:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621021018; cv=pass;
        d=google.com; s=arc-20160816;
        b=WdriGKdQBnMi0p0s+c5qf2LM3BmJItyr6mQUtWMyiQYXgv5UvaNxZ40veQ52yEv7Tb
         VIzWUOisYZ7y6QkDZ1OfQ3Ky7HXuEEJzSKfvk3E3s13YAqgDOZns/Pi+aUR44a0VIt/z
         nQZ+ImmGQP1KNvZ8aPBQogvslJE5dE9wueRkI8krL7pefFukK9Y9Q0gZr3RGlMFQduni
         YX0Z3kT8cS+LTae/kKU7+YqPTflwm/YGWeMSbOxuP0GKZSKUvaWPD1gpgcnI6tIQCDY2
         HRrCiRYfI6RY91wZ+zvfb7tBU3C2VXUXxybP6gP55oAE7+ENmRJSnf24GrCyQTxAm+Lk
         bdVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=b5qFsgJN5d0kHlUCJBqArymycYLq4ZAVNYErURWzqmw=;
        b=OaJmUxUZUNJNg4+RDfJIEptntQ70IhR3/bLMjbyGY5OK87uQz7U4ZKnU8TjKd7JTgx
         zngO93M2kwt7q/+zOu7BQXG3Cd/a6h8W7Ak3AUIY9ykxR3wHO89qvOJGgdGq8b9zeaqE
         T68gc2kzbkarKKbHBHsMBUgRkFdqqswAET158Gqpzi2M9MOfiZa7Sib30YUeaMgTbGpp
         MPpnZ+LGcN2HWNLSp9pLNahlQ9+bRN6kLUtA0EBbKO4XtpDo6J4Ta2UCavdLFJ/+jZ6P
         xITW4326qLNXBE7Oeu1IsrHV2oVV7nIb16wUr77pEvMT2eyKd3Ht53KPYrME/p2cg47T
         RpCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Nw1yr7gm;
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b5qFsgJN5d0kHlUCJBqArymycYLq4ZAVNYErURWzqmw=;
        b=ZHNDak37R7X6mfwK6O++kYpq6XxbkfLShcNyf0TgFUg1XcLmViyXR6LwRMIimUfFqg
         aDsBSa5dgrOyL3P4IV2jggrMBKMJkxxog75QEutOfLN4+Aavrug4wg4TInVOohYUDdwB
         X3rN/EFtTlfxNuH7ruS4bDec13MrR6/j0NcgI2Av8YainUICy1ObCQtoZFcc7wd2vqFV
         ZWLMPntcbOqSrLTPuVoP31dbovvBadK0H2mzgEaiI8LEPoJaCqk8OH70MIBZ256fDfV5
         swdJYmP8dL0jj6hWpgvGA4CJsAus2w5IJ1oSfkQVf58W5Fc17l9YAYYRhfXU9e9cx7et
         ad5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b5qFsgJN5d0kHlUCJBqArymycYLq4ZAVNYErURWzqmw=;
        b=ZTUFtwsm9F1+TRLL7a2MB9zGeML53RHaUlEQnijwEnhQWPPv2KfYpaBmS053uGs4S4
         E5ZxTF0lQWXtpYBB0akRR3lr83k2nWj1Z/dkLmOJoMKi/xIFVFK3bqZWnd9eETqHnDwN
         srzCDcztiQ6W4j72nC5qbWNN4lHYila0wpOZHoMMZQxIabsRi9ySMWfIMK4iZyUAsA2j
         cqymcPIIPKgxytbKcp8sWG9FfJyWj3tKy8P+8srygBXo4lH05voX8lpKkrTnAN5o4fe0
         iuGD4HRKUuz5oj4gpBKvfwXGd+GGffOpjTJUulf4r/3yVAF/5ww8VTUDWWnheFbhxn+5
         eZ/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UgbCwZlQzfQIMkJkPAZKga2LGKTzLX1Xi16vcQXRVRwkG5C4V
	pEyPjpsmKcPUj8uS54sYIKY=
X-Google-Smtp-Source: ABdhPJz0VbV0Me2br1J863ALQcgCOO4xydWfUW/l8CjNMDhXZIxxxSN7TXr8uc3cA1tgu46oZDK+PQ==
X-Received: by 2002:a92:cc02:: with SMTP id s2mr41267163ilp.101.1621021018539;
        Fri, 14 May 2021 12:36:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:4a3:: with SMTP id e3ls2504053ils.5.gmail; Fri, 14
 May 2021 12:36:58 -0700 (PDT)
X-Received: by 2002:a05:6e02:684:: with SMTP id o4mr14258337ils.149.1621021017993;
        Fri, 14 May 2021 12:36:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621021017; cv=none;
        d=google.com; s=arc-20160816;
        b=q2rEvTz/KLCUu6/+EThapelKyBKt7qOsO1RUJihDeqAXWIqaX+WG6KYUsLF8mn2PsW
         E3yqLYrqTv8SO19BNNaOpK3C6is90q8Tbtou5yoiLzvQeZAPK/I57vvqQKtVj/UYz+Vj
         VRPda2xSqz4cMJhrGFV7wy3w5Yot/aGXRMzig4XHidUxGxsR95qlTiFZOC1a0WIyot8S
         Om+U6aCGVPG0XOmQTU8Cs4gv/atzv5H7nclOF2LACS5hh3GWeyhgdtWRyywA/5iuwE7y
         dVvXCGk9nzOKdRGPAPL8FtK/08vP3CxzSxtgRYIma+kzdCaqcW4fcjN3KGIlOx/PDeLG
         9+wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BuSk93p/Y6Y2CEWVCz7dqF1P83kLBzvJOTXHq1YUWec=;
        b=SmKSJcMKuFBvQpdgJXBfmqPxvwuVzdoGsUnA0fiyo+IoMlCL2xN7Y54vfKtBP5KNBC
         +3nK93jikHMlk+rLeMRCGA14TcymAaKNKxQAFeMwloDxehQXqFqmf8FpXx3q4lCJ2VSj
         IGrl4/LyyU07j9nagpx2DVd0ktCh2csNQPbYTHuw80r3awpuHCaiS44dYScW8nQOhD5/
         LFkI37wpv41bUOG/zTL0TtwcP7jph+l+RXnkoPzarV7+W3Mpaf5k20nxDkR8Pxt+A7f9
         W9ywRORxCNA6FT2RRUWYj9o2O315ZaPSwC99zK0zn+YThUCBV1CGfsaUgCjCza02SRy/
         +5EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Nw1yr7gm;
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r20si294721ilj.3.2021.05.14.12.36.57
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 12:36:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3A854610F7;
	Fri, 14 May 2021 19:36:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 0AE945C02A5; Fri, 14 May 2021 12:36:57 -0700 (PDT)
Date: Fri, 14 May 2021 12:36:57 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@kernel.org>, Marco Elver <elver@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
Message-ID: <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210514140015.2944744-1-arnd@kernel.org>
 <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Nw1yr7gm;       spf=pass
 (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, May 14, 2021 at 11:29:18AM -0700, Nathan Chancellor wrote:
> On 5/14/2021 7:00 AM, Arnd Bergmann wrote:
> > From: Arnd Bergmann <arnd@arndb.de>
> > 
> > clang points out that an initcall funciton should return an 'int':
> > 
> > kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
> > late_initcall(kcsan_debugfs_init);
> > ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
> > include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
> >   #define late_initcall(fn)               __define_initcall(fn, 7)
> > 
> > Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
> > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> 
> For the record, this requires CONFIG_LTO_CLANG to be visible.
> 
> Reviewed-by: Nathan Chancellor <nathan@kernel.org>

Queued with the three Reviewed-by tags, thank you all!

Nathan, I lost the thread on exactly what it is that requires that
CONFIG_LTO_CLANG be visible.  A naive reader might conclude that the
compiler diagnostic does not appear unless CONFIG_LTO_CLANG=y, but
that would be surprising (and yes, I have been surprised many times).
If you are suggesting that the commit log be upgraded, could you please
supply suggested wording?

Once this is nailed down (or by Wednesday if I hear no more), I will
rebase it to the bottom of the current kcsan stack, let it soak in -next
for a couple of days, then send to Linus as a fix for a regression.
Hopefully some time next week.

							Thanx, Paul

> > ---
> >   kernel/kcsan/debugfs.c | 3 ++-
> >   1 file changed, 2 insertions(+), 1 deletion(-)
> > 
> > diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> > index c1dd02f3be8b..e65de172ccf7 100644
> > --- a/kernel/kcsan/debugfs.c
> > +++ b/kernel/kcsan/debugfs.c
> > @@ -266,9 +266,10 @@ static const struct file_operations debugfs_ops =
> >   	.release = single_release
> >   };
> > -static void __init kcsan_debugfs_init(void)
> > +static int __init kcsan_debugfs_init(void)
> >   {
> >   	debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
> > +	return 0;
> >   }
> >   late_initcall(kcsan_debugfs_init);
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210514193657.GM975577%40paulmck-ThinkPad-P17-Gen-1.
