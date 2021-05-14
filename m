Return-Path: <kasan-dev+bncBCJZRXGY5YJBBAVW7OCAMGQE5JWT2IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D2B1A381197
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 22:18:11 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id z25-20020a05660200d9b02903de90ff885fsf22717ioe.11
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 13:18:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621023490; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jo4Z3I/4sX9CaEDkXxIADrwP2T19LL5cBhZ6CN0yNI45ikY/Z+B7KdCb3WKktYgkK0
         lpqscfLuwtDgKRgcaEMi3Rohz2knWVwxdSQY48skGse3zGnHmcSCer0qIGmTQKc/UIiw
         J7sxRb09tcdGvDr/d8qDhPlAog/HZ19YibqvkK3RUpuGNNvoKM4YuSmbUDmUztCJRFEP
         cIXTRcrHjH4BJu0MXmoyk+alAqQdURWhw7380LfJweanktpM+2RQR0DE2+6Y5CzAxkte
         88PPEnGr7w8Ve+AeGDttx1Ipd5sf60lQS+HCTCT/v0km+q25P3R0Qgl/KltQbRlB2L1E
         G5kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=nNVnQtGv9S7bFAIgmPFCVtJe14ZGvdvy7CCXEu4Ed0o=;
        b=MaU0PejgQDjronCrYO2HzugM370HeHFdTcGEoPoqA2Sa3a9M2yoYvb64WLnQqSFugs
         Rip2GDYtS6Yfl2VU0FhJzDhA3+A7GoEjt0VCvj2GyJhbV0B1XrpN/WxLc4HE5QNN2ByE
         J4sn84DPVI3lV2xUZ3I7c2hSdwRL4bIrwzIZi31LusxwYtwwx+mWVAQDRUUgzpr0WTeF
         k3lNQUdFHM6jzT2jW8PdxW6ngILc/RdgA1jk24DpULXEUnz7nfl/HGgduBFSqOMaoitW
         FUebDdzR0sK+BNOsdSj2h9OxxhBhSDcO6nUfQiNVfDGBXU1s2QCAHCQx3EIs7pJCdUFR
         sKsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="AX8h9jH/";
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nNVnQtGv9S7bFAIgmPFCVtJe14ZGvdvy7CCXEu4Ed0o=;
        b=bt0FS37rMFa4h2xswYAM/ZEod6ZkSYbVUTJ1TFJvR+KZbXH4vncHZ3kyvBbdojOCPi
         QJuj0u1koEVzLYNjvj6Cq6RB/VeotBeZUkEA83H5CiSoFEE05KduTnH4kJZFFeFlmccH
         wabPAGI1SgeP5YHfamJrN+peF04zpR+jT3GyQrf2Vy/VT34vMpJJHoFRPwRlUuoKsZDW
         eb6Ob0WJpGnqIdryIlBvKslTrbBvRAq/z9GKLVRch0MqvcWz4DSVtKNBj3kswx+Iz2Bi
         RlLxlwThvg1ANdzJnUiB6EhWcytCXUz5Cg/IV6slDSZO5aPiRNBmX3rfsUIxVm0AqOgN
         bjjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nNVnQtGv9S7bFAIgmPFCVtJe14ZGvdvy7CCXEu4Ed0o=;
        b=nPZtTAOWHYb7hBL7BAaP23yQ7wUPku5JXjyQGMzGEsLmUJWT+MW0J5/JeJ0OhKxpf1
         6sVEqrRUdusP9nEOdPwfd5K8qmtW2JTWlhIMbG8mZuDVQLGb1RzQ4wd3WZ6IP1UV9a2c
         1cbnoqMkMg4wqyMUkn5StVvQ5FtJ7SUXMeKPBGCUq3W+zWBlL9eewvzgprkdYu47hzhY
         9K5cPHCPeMfxJwxH9bUbr2oOezWW2xR/kRHKrQxVxuUbEuanfU87NvkswTfPHgJMTBmy
         Ftk5TWZecneMrIlw+ktZqVjbF0+ug++dpi3p1pPlwelewvFipjjCQ2dmQYzsLVAchz0J
         slhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mOvRA1d3H8E+t+KA5SXnAy2VvLRu1QB3/Dk4egR++PJF1I+H1
	PiAPVeDWPn9ifd44AdfvGzg=
X-Google-Smtp-Source: ABdhPJw+OGw2iT/xYGWeeQeOArAFtLob9+JNcqeBOt9ZE9d4wQelGj3rDx4C7j0+w01Q6VMopxwh5Q==
X-Received: by 2002:a92:c645:: with SMTP id 5mr7383510ill.142.1621023490642;
        Fri, 14 May 2021 13:18:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:210f:: with SMTP id n15ls1616413jaj.5.gmail; Fri,
 14 May 2021 13:18:09 -0700 (PDT)
X-Received: by 2002:a02:5b85:: with SMTP id g127mr45028611jab.80.1621023489695;
        Fri, 14 May 2021 13:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621023489; cv=none;
        d=google.com; s=arc-20160816;
        b=KIZHVYSVnhesJDwhsyvSdjlOXk4GyvKZHDiGJxy2DYPjMusp8c0ooCtkxgio1F8o3o
         t9Jf658avD/ZLoJ5iWaB8dRPmN0jxfaBGOaXwRsk9fQInKCgI9XbVaXnqoYO02fbdAOD
         Mi7QdPJy7Oj5vyqFyQ/ovX8UX+aVaxAe34MJ0feV03K1V90+nPCS7cbKKKEYfD2q4LmC
         SeSYJEShdvJ6yTtu8IzC6tfQvqhG4Jw5Als3HebP7vFGmcqQu6/sVWotqN8JCIPWMHQ9
         PHK/s1jaTrEH8AKWXni39CP37Njyluns/ciWGMUz7vUVt2WeS1BhHrkrbWd7enjs221c
         +s1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+lZa+ymLvLsGP0D44oY7kXWbIyf8CrKmdu5QviyiOLI=;
        b=kfgr9KyYwNroaMBIkPEeiGm6mgJbEJ2bZ9q+D5euV1f930zVzdiXtgmi7o79dkaOUK
         jzT1gJmqD7zEIhHjQL+8pKNFKUqWUurlN8yJykFOVFEwRY0seTIcxsDdkF7T4MsQXVDp
         IcL7umz/r2mZKuDEZl0p1zLBWFb/w2LQi7qJ8dTkLcgh+bMm5F5gOuNPwSL6OroMZpVD
         cKrVhPDK9lRYdZ7sYmQpFYlNFdwLCewM9eex1uLl+rkv5qTK1M5GARw/yHeTlovEzRmz
         e62rOb6WLiOQvMpJ2y/vehOAO86K1W2RpDbC1Rn0xuSnTg1x0YEYpT02bpFEiNHQ2S8i
         Vb5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="AX8h9jH/";
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o3si629374ilt.5.2021.05.14.13.18.09
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 13:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id EF9206121E;
	Fri, 14 May 2021 20:18:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B87EF5C02A5; Fri, 14 May 2021 13:18:08 -0700 (PDT)
Date: Fri, 14 May 2021 13:18:08 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@kernel.org>, Marco Elver <elver@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
Message-ID: <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210514140015.2944744-1-arnd@kernel.org>
 <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1>
 <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="AX8h9jH/";       spf=pass
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

On Fri, May 14, 2021 at 01:11:05PM -0700, Nathan Chancellor wrote:
> Hi Paul,
> 
> On 5/14/2021 12:36 PM, Paul E. McKenney wrote:
> > On Fri, May 14, 2021 at 11:29:18AM -0700, Nathan Chancellor wrote:
> > > On 5/14/2021 7:00 AM, Arnd Bergmann wrote:
> > > > From: Arnd Bergmann <arnd@arndb.de>
> > > > 
> > > > clang points out that an initcall funciton should return an 'int':
> > > > 
> > > > kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
> > > > late_initcall(kcsan_debugfs_init);
> > > > ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
> > > > include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
> > > >    #define late_initcall(fn)               __define_initcall(fn, 7)
> > > > 
> > > > Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
> > > > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> > > 
> > > For the record, this requires CONFIG_LTO_CLANG to be visible.
> > > 
> > > Reviewed-by: Nathan Chancellor <nathan@kernel.org>
> > 
> > Queued with the three Reviewed-by tags, thank you all!
> > 
> > Nathan, I lost the thread on exactly what it is that requires that
> > CONFIG_LTO_CLANG be visible.  A naive reader might conclude that the
> > compiler diagnostic does not appear unless CONFIG_LTO_CLANG=y, but
> > that would be surprising (and yes, I have been surprised many times).
> > If you are suggesting that the commit log be upgraded, could you please
> > supply suggested wording?
> 
> You can see my response to Marco here:
> 
> https://lore.kernel.org/r/ad7fa126-f371-5a24-1d80-27fe8f655b05@kernel.org/
> 
> Maybe some improved wording might look like
> 
> clang with CONFIG_LTO_CLANG points out that an initcall function should
> return an 'int' due to the changes made to the initcall macros in commit
> 3578ad11f3fb ("init: lto: fix PREL32 relocations"):

OK, so the naive reading was correct, thank you!

> ...
> 
> Arnd, do you have any objections?

In the meantime, here is what I have.  Please let me know of any needed
updates.

							Thanx, Paul

------------------------------------------------------------------------

commit fe1f4e1b099797d06bd8c66681eed4024c3cad67
Author: Arnd Bergmann <arnd@arndb.de>
Date:   Fri May 14 16:00:08 2021 +0200

    kcsan: Fix debugfs initcall return type
    
    clang with CONFIG_LTO_CLANG points out that an initcall function should
    return an 'int' due to the changes made to the initcall macros in commit
    3578ad11f3fb ("init: lto: fix PREL32 relocations"):
    
    kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
    late_initcall(kcsan_debugfs_init);
    ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
    include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
     #define late_initcall(fn)               __define_initcall(fn, 7)
    
    Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
    Cc: stable <stable@vger.kernel.org>
    Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
    Reviewed-by: Marco Elver <elver@google.com>
    Reviewed-by: Nathan Chancellor <nathan@kernel.org>
    Signed-off-by: Arnd Bergmann <arnd@arndb.de>
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index c1dd02f3be8b..e65de172ccf7 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -266,9 +266,10 @@ static const struct file_operations debugfs_ops =
 	.release = single_release
 };
 
-static void __init kcsan_debugfs_init(void)
+static int __init kcsan_debugfs_init(void)
 {
 	debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
+	return 0;
 }
 
 late_initcall(kcsan_debugfs_init);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210514201808.GO975577%40paulmck-ThinkPad-P17-Gen-1.
