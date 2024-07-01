Return-Path: <kasan-dev+bncBCS4VDMYRUNBBQXNRK2AMGQEEUAH7RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 70E8991E1C5
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jul 2024 16:01:40 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2c79f32200asf2895321a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jul 2024 07:01:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719842498; cv=pass;
        d=google.com; s=arc-20160816;
        b=xqAc+sa3nRrZqbdw+lahuhrNn7gwW/iH0ekmqJQQWyiQS62i5EBJ/l8MjDs0R7XjGe
         qjIixbw0M5Hnw5Nl5QYEEblcngEWU6N3nAOqoPOU5O7SAV3lPS20jONCMxQ3fdfbe5wh
         sC824VFT/tueQMy46BUu9GJx5ZUtbuuLIPnyMTaCObGRqcUlqIpRYtiDbIGy8QLwj5zT
         hgfxMlvZK6IcOi7OfNCP8ZOZ5kkSt6yt+IBf0mDyAemEUJpCFQx0wac+ozemvmxVFlue
         wSP9FidZ6oMcuD4hF1FpRK9Mp/T797aerrgx6ReaQ1ys27kIJkHbvH55Sbj1rLtpB5sZ
         PR0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=XgojaLPZsSXU1vsuI8PEf0j4e5XaR4SGSx0buofXiMo=;
        fh=22JbE2OnSJA/fUNP5WJU4Ypw1+Y/lyX0TiIuqEYWUcI=;
        b=Hwu3zum9dhrWpMtPVGKLBbVIwQeMtAt6/wilUASLh/i1S+gxbsZjT1aSLb3BNyqBxx
         GzmbkLox55UwadFdYnErzji0LiE0Z8f3F9CFcGIH70E8g1PUn9Hta3KlFErpQSXqyNEY
         9YZzZgW4tlqmDMv40RtzMZGXvAO04F1TR9Hw36Zd4Msn1Zd6kiTOu/QDgrSWmUbsvKiH
         CqHWmZjXrwhF5kshr3JW1qmiOuk9UnfP4t4VYgCoCD095GT/qXoXBFWD8UILCxDGC8FA
         acSrwqwezr0l8B5x71jTrvs4oLv6irS94vjZDZDslYTGaiecuCYzrw4srU6XT9PAr2Yb
         7Fjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DCt6KPfE;
       spf=pass (google.com: domain of srs0=h9nf=ob=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=h9nf=OB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719842498; x=1720447298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=XgojaLPZsSXU1vsuI8PEf0j4e5XaR4SGSx0buofXiMo=;
        b=prdJwdyl0opV1Gw/s/tzIz5bm/dlh+TR8bry8Iksty2UrEfqkOeySyvn8p674hceuE
         aCx4YYetTb09Xu8FAAd0VJIum8dcldP79q0GJ6BA1iwdtSrc2JW5fs+K+uvs14YhgaBh
         yNM5lQzUSaSaGnMSjWfjdeASKYVE3U+KCjdgEnFHL8LXT+VMG5jdBC2WygF/NnzxE8Jw
         pX1oi2IuuRRyXr/ozrERtiQXi8jREi1JNAUvzmJhRfCSOau34ObLiTN0vU+Xl7TxFtZd
         8PSOW2v/EE0L3Sb9HVsyFdUzSO3L4+wuhZLLqJlTjdeZKPN6rIBISwBUeO78QuI08Mfw
         ubyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719842498; x=1720447298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=XgojaLPZsSXU1vsuI8PEf0j4e5XaR4SGSx0buofXiMo=;
        b=KzKh0//M1fJpYaoiYzX76w8SZsRnz146J0P02mP2aV9T0Z3LPpIrZnVdlbZKtYCU2/
         AD762zwk8EaWDSgHo4tw9jgxmLT0dK4pTUhaplbcECfw4GkNFYdH4/Eg6UTrSYwPQ6fM
         +sUuEhtTtn/rqZu2UtzFuG4LSsPNDVeZ4n077UZnPyQ5zIV3CKtLdVu5iJsEycDTQp0t
         PYM/T/WFkHOcnig6FQZIkE9ktrOyYi6RfF6u8q8LCSHMs0ueZ+vNjO4NdLO+AuA8wvnJ
         /srH+ecuMUzlAvaHWn8Ttou0xm1VPkP71/hUgnqkMoSStslrYCp4P1NSGQJsi5kBkeG1
         izDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhbBDgX6oEwUdRqgcBevtoFQ4HcPHLu9CidzGnVGish7X59Kgpl2e7uh8bqXSmiHv08LYOgGakqUHBD7UQcQHZ8z4eMuhXrQ==
X-Gm-Message-State: AOJu0YwX2texg8zp14Zm6wW6IezcZITO+k0pWFXP9Da98qJWqA7HiRW+
	lSs9ss9wZCJV0Xhv6xXv4SqQUG7Kj3cZ71Iom5sBctVTdTHa9RcE
X-Google-Smtp-Source: AGHT+IH20aue+iQQWtMZGstnOFFxC6cWw9e6NDuznuecvzEZfXdfcQ+u6j5zii5AG3Fj0PtUy8B8dA==
X-Received: by 2002:a17:90a:b885:b0:2c8:647:35c with SMTP id 98e67ed59e1d1-2c93d7218c0mr4435554a91.29.1719842498264;
        Mon, 01 Jul 2024 07:01:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:360d:b0:2c5:128e:240 with SMTP id
 98e67ed59e1d1-2c921d62c94ls1689170a91.2.-pod-prod-06-us; Mon, 01 Jul 2024
 07:01:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnkQhd3OeiB4otgzilEulswWo3z09mEsj298tjjnBJz5jmQCxpYAain6LSs3D+J3Jx125VInkVKwv0MSsLM5dP1CTmQ5OucYDa+Q==
X-Received: by 2002:a05:6a21:3285:b0:1b4:6f79:e146 with SMTP id adf61e73a8af0-1bef611aa28mr9184585637.17.1719842494962;
        Mon, 01 Jul 2024 07:01:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719842494; cv=none;
        d=google.com; s=arc-20160816;
        b=YkYTQrwBF7PsF4+FjYS1vl8ktMMmiOoSNcSack2YJJZ07CLKyeThNSwcDa3aiwgijR
         HFlPtoOtMt6nuI9aaJCEaFxqaA58n90O6GGRTodP+9elEXcBoPALnFYgwIgTL7/ZDWtG
         96gpE0t1pJZTOVM2zJfMAz1Z2aybSha3f7xEVg+sVv9S4yvxZblGT5G7Ag6LkcJfqGgz
         SzhMr3i+RrwZUxSx+9Mf6V9LSF3xGbAwu/z3tS8S5gHO1bKJtoGUEb1kiGwheIvJliI4
         Atx6B6bU/JZfyAKnMB+LCurjOxO4ZGddbpOa9UJxknu8ZCkH+180aNvNy6nPL7ub8sqk
         WQdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ag/ULx2/CQfPAjtsDRBpgV9NGCmMnYGYdHVNntzPkv8=;
        fh=ZOUtwLEAnKvORXlk74Q2MPkn/nBSRpYECJrrSKiir+g=;
        b=bveMa9G+kLHUWBsWy9trXJgo7yG/C7pskzyQaASGohcXvnmnmdfmIOMDpzAec+j07n
         FJbC6rqBaYeAPejrLHX1RRdWs7TrK2ORRE93FgFChgAO7v9BVwwwD+lPO5EBhhXj3Arb
         HO30R0rW7Pc3mrospmHSK18kXWPWxVQJJqb5LK09/lPAcNrkyQzJQFvqv64NzNctlSK/
         kYwp6ROfkaBuMlBexlqUUYgGy89OGqti6JV7BNij+lImmtZaZxI+N0RqNlQ9xkcqtegV
         HxdCwjc8i/KWryyRpkQWNOagduxaU7rsU9//oYL+nFCAw2FapJB6v+DRKZghycqIOnEn
         dwTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DCt6KPfE;
       spf=pass (google.com: domain of srs0=h9nf=ob=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=h9nf=OB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fac12f6710si2892865ad.2.2024.07.01.07.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Jul 2024 07:01:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=h9nf=ob=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id B7753CE13DC;
	Mon,  1 Jul 2024 14:01:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E57C9C116B1;
	Mon,  1 Jul 2024 14:01:30 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 88A74CE0AD3; Mon,  1 Jul 2024 07:01:30 -0700 (PDT)
Date: Mon, 1 Jul 2024 07:01:30 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Thorsten Blum <thorsten.blum@toblux.com>, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	David.Laight@aculab.com
Subject: Re: [PATCH v3] kcsan: Use min() to fix Coccinelle warning
Message-ID: <b96317e1-2aa6-4e04-bd9e-6fb2ce49c417@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20240630200135.224108-1-thorsten.blum@toblux.com>
 <CANpmjNMXOn_N=9CY2iGLC=r=FAP4J2EFJbwDsAEuhKydwh6wtg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMXOn_N=9CY2iGLC=r=FAP4J2EFJbwDsAEuhKydwh6wtg@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DCt6KPfE;       spf=pass
 (google.com: domain of srs0=h9nf=ob=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=h9nf=OB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Jul 01, 2024 at 10:07:29AM +0200, Marco Elver wrote:
> On Sun, 30 Jun 2024 at 22:03, Thorsten Blum <thorsten.blum@toblux.com> wrote:
> >
> > Fixes the following Coccinelle/coccicheck warning reported by
> > minmax.cocci:
> >
> >   WARNING opportunity for min()
> >
> > Use size_t instead of int for the result of min().
> >
> > Compile-tested with CONFIG_KCSAN=y.
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
> > ---
> > Changes in v2:
> > - Add const and remove redundant parentheses as suggested by Marco Elver
> > - Link to v1: https://lore.kernel.org/linux-kernel/20240623220606.134718-2-thorsten.blum@toblux.com/
> >
> > Changes in v3:
> > - Remove const again after feedback from David Laight
> 
> I think I was clear that the removal of const was not needed in this
> case, and my preference was to keep const.
> 
> While general and _constructive_ comments are helpful and appreciated,
> this level of nit-picking and bikeshedding about 'const' is a complete
> and utter waste of time. I'm sorry, but I'm rather allergic to this
> level of time-wasting.
> 
> As KCSAN maintainer, I'm just going to say I prefer v2.
> 
> > - Link to v2: https://lore.kernel.org/linux-kernel/20240624175727.88012-2-thorsten.blum@toblux.com/
> 
> [+Cc Paul]
> 
> Paul, if possible kindly pick v2 of this patch into the KCSAN tree:
> https://lore.kernel.org/linux-kernel/20240624175727.88012-2-thorsten.blum@toblux.com/

I have queued v2 of this patch, which is as shown below.  Please let me
know if anything needs adjustment.  If things go well, this should make
the upcoming merge window.

							Thanx, Paul

------------------------------------------------------------------------

commit 613b072fe9b3aa11410937498c98b7ac6d7c9d5a
Author: Thorsten Blum <thorsten.blum@toblux.com>
Date:   Mon Jun 24 19:57:28 2024 +0200

    kcsan: Use min() to fix Coccinelle warning
    
    Fixes the following Coccinelle/coccicheck warning reported by
    minmax.cocci:
    
            WARNING opportunity for min()
    
    Use const size_t instead of int for the result of min().
    
    Compile-tested with CONFIG_KCSAN=y.
    
    Reviewed-by: Marco Elver <elver@google.com>
    Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 1d1d1b0e4248..53b21ae30e00 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -225,7 +225,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 {
 	char kbuf[KSYM_NAME_LEN];
 	char *arg;
-	int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
+	const size_t read_len = min(count, sizeof(kbuf) - 1);
 
 	if (copy_from_user(kbuf, buf, read_len))
 		return -EFAULT;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b96317e1-2aa6-4e04-bd9e-6fb2ce49c417%40paulmck-laptop.
