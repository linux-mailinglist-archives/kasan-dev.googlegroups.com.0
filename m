Return-Path: <kasan-dev+bncBCS4VDMYRUNBB5MYSS4QMGQEGVOL53A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 424BD9B964D
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Nov 2024 18:14:30 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5eb59e38e9asf2239861eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 10:14:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730481269; cv=pass;
        d=google.com; s=arc-20240605;
        b=SwJH6gxEaW1tlI330No600+JgTbRQBIJcd+ycIdKsooMSrTfXrwHr/xmDRkAxBeok2
         QIkxbrdDEqd4WDy6Gd+7LEbsbGqh1l5dA9ZX/M2xqL6JDyrFNmgsmIkdsl3jYIamXrbt
         fpl0dStEZIjQj9yy3NTgtInTmFQ4yjnu93P3ATBzZPoArOK1rWRDJ0iMhMaFjyW41udr
         5Pe+JeblTMhcTVSWlqPFCYGUbjj9vcxXSC5EK1BavLHF3pdeqNUZauMygOG9KyMbqUDK
         wUWVzJyA4eFMlm2zHUo9gPBA6v4JjiLLXghEZsWOkNgckcJPF4XLtEyArhf88+HvBE0n
         +MvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=kYMDFZ+CCyKNHstrZ7ybgmlcqR1E63HsJbLrCUgGOy4=;
        fh=cGklSym4/WHCEUL8GyNBg35f1QDIlJVuuf9fr5BtfvQ=;
        b=eFFNPM/M7uDFkQi1e+O2HJR3zah89WEgvwsxzYerfxYuLYKc7je3kw0Fh0BnwtyxLB
         QnYzP0XoVcZ8/x9sab0JK95T79scAxykziRpsV3PnhQCKCBQgehwR98og+q/gl9qHpLe
         LobA0ZPkUp+af6D3gQbJFm8spX/NJwJFxzVq5LYJqk3FcIY7ABvEBI+Lz58kypMUUn1R
         WF66P5BGB0fL5wt8oVF6vKoxRa7InCL60nzlS5s+NPQYAN5QtaWAX7UPwhEL3HdweKWd
         K70skAEHpXl/1pKNfOe3YkblG/D2DWJLONbR9mNYy8SNnFhmcKMTSL5FJ1vUi6Ug1MYC
         elHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UWRgoQKa;
       spf=pass (google.com: domain of srs0=xeo+=r4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Xeo+=R4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730481269; x=1731086069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kYMDFZ+CCyKNHstrZ7ybgmlcqR1E63HsJbLrCUgGOy4=;
        b=LYMrfenOyyBMvvMHFKp1IC5VZhHUt5KiyK0/7v1DhBx30dOinA9vPaMskMmpbZ3zSV
         rRDs82o8bWFp5ZDDub145oQiJB7eNjhXZa4v78vUnw6gsGHQFruN4ZPUJvUNLZzkTpDA
         yJxncEq9Pla1z+Yh+m8LGo0MFOoch7YmoiFKZM4Q9GxPGk5TrE4KDdlCbn0dcpdT+p57
         trbqR70w9Eh7KHm/pE4dD2a/DDtIIsHRQA16Gn4FXq3l+QwDyZCYlPPYYlE/Tw50cmJH
         4MnwKqUS/QnS2uM6kX6YDQhUBUDbl0Wjhy1Ctr4tkMWn6Mf9snVN+EZjQXuRHRhEurtD
         1/EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730481269; x=1731086069;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kYMDFZ+CCyKNHstrZ7ybgmlcqR1E63HsJbLrCUgGOy4=;
        b=V6h8gL7TrBoVAh/2jxPauRHhjhfQ0SdwAHjdIQGGJ3xO1wHfxYF/RaKtBnNZnyDzGZ
         r0ElbT1gOzBt6eCYJvEs7sy8zULs9gnhPbTMQIZJdPdJ5dEqJ9OTQS7rKhzOuMhHNd7U
         phA5nFCH9BR4MWR765PrI7BaxWOudypmRZbGVe9LY7Godr9Q5fy86xvfbnbWBI+YVytD
         JYq/NYLAv4ERxoIJJJT8v9SzGcfY454uM/6iuvW4JWg+auQPal5z/7kDo0f/ujphH++c
         JXKucYfBpdeqFLU+kjhPW9GY3npHZbEepqyOR0f7yZuZkJ7dJvap5UHlIfJ+IE6/kl1/
         BvPQ==
X-Forwarded-Encrypted: i=2; AJvYcCWB+mMX0E2y90+ISOxADOdS41QD+CxIZ3wETGpgbCe/pgzm9JGAd3rUyWj3RmQU8LpcZ8aTVA==@lfdr.de
X-Gm-Message-State: AOJu0Yw2uumD67ozd/mtoq/y/ynJJdAIxazPdOKrva5l6YAPGYhvdR47
	wRsYS94iHo9/1nDqJNe3h8OQKN5Jwwcwpedk1P9YA0I0sYhaQ/Ea
X-Google-Smtp-Source: AGHT+IHD2HPR/YfhSQ7JkAdXhtoO9LIiqRJBtzivt5HuJ28u0drg4GvSF399iStw7iXC2kKY7hYfAA==
X-Received: by 2002:a05:6820:1c9d:b0:5e5:941c:ca5a with SMTP id 006d021491bc7-5ec6da771ebmr5076698eaf.1.1730481269435;
        Fri, 01 Nov 2024 10:14:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1c16:b0:5e7:fe13:51ac with SMTP id
 006d021491bc7-5ec6d2b0130ls1755354eaf.2.-pod-prod-02-us; Fri, 01 Nov 2024
 10:14:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUhFP5U9EP3wf9q+Si3ydtfyWGPuCdZMF/x4/cx1NrhlaiaTlP3WwYjT1fp4foMkSVTZ3sVyADl8Q4=@googlegroups.com
X-Received: by 2002:a05:6808:2f0b:b0:3e6:614e:2b07 with SMTP id 5614622812f47-3e6614e2c20mr8128297b6e.30.1730481268563;
        Fri, 01 Nov 2024 10:14:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730481268; cv=none;
        d=google.com; s=arc-20240605;
        b=GHMwaUVL7iAXeRgiMljN4QztSvR1buu1aoQTedcaWp1NAdXyR+U5/U6aTywf+Qf9eA
         Mwl+VGOzdXdA5wOcrWYOCN/2bZbQkCzxSovaMZsiWqjqg12++I6hq8GuY2+eaJ+EsHK1
         3F/o/LXC625WgUeNBlzOby5w6fJYza+GS9JmUVyz0XigU5Ue1frzlDhlpj7yyqgtvgAE
         g+Y5vqD6T2IAM6H+WdeKbXnOlDlYzStHxiFm8pX3n44zndxRariu7VfqjhSDZs1fCnbW
         UfpIcmWekzZfIJezfZDXArETTiDLjXtkdLh0N1Sz9jyN1asI8Del2td+YJZU+7iG4VRr
         sTog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WctgG2zXPGVgx+DW4mcB3snO6lbjjlhYyPV7rFTGxi8=;
        fh=vAGyQlLQyZotBckMWseD6dDB2Bf/bIUDUyDhYbYNKac=;
        b=HcmcZ1WDYuX1CiJe+9iO2taIf9WuOeA3lPQE3dMNS/ykk6iOB1tZEy0BWFYQXnekds
         UgTuHX/4dnXZY1Dk9H4mLiUtI/Zo/5qgLzzGxokP2U9MiqxK9JRNTbmIOYC12i3+G9pW
         vK3BMftPDrrBgVkVtOCxGIon5k7krjeW+Fb4CjN/qOCRt4y7VdhbHe6ngvc0iQfqgvhy
         BPOy4gPuAJng4pceHPktCubdP3EevDfc1+4hpfgkSdnVKS+wIwpKcfcXNbM7lB/WTHkA
         wC8j8S3nQNDlBGeCpirQWhizQ7G1B5vXqdf9QsIsB64a5eL8swgpLqumkks/tBjd1eML
         kFiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UWRgoQKa;
       spf=pass (google.com: domain of srs0=xeo+=r4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Xeo+=R4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3e66116deb3si186891b6e.1.2024.11.01.10.14.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 10:14:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xeo+=r4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 5163A5C55AB;
	Fri,  1 Nov 2024 17:13:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CE980C4CECD;
	Fri,  1 Nov 2024 17:14:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 73DC9CE0D6F; Fri,  1 Nov 2024 10:14:27 -0700 (PDT)
Date: Fri, 1 Nov 2024 10:14:27 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Marco Elver <elver@google.com>, linux-next@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, sfr@canb.auug.org.au, longman@redhat.com,
	boqun.feng@gmail.com, cl@linux.com, penberg@kernel.org,
	rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org
Subject: Re: [BUG] -next lockdep invalid wait context
Message-ID: <ed93c68c-fb17-4c20-958e-0fc4ce8bcd83@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
 <ZyK0YPgtWExT4deh@elver.google.com>
 <66a745bb-d381-471c-aeee-3800a504f87d@paulmck-laptop>
 <20241031072136.JxDEfP5V@linutronix.de>
 <cca52eaa-28c2-4ed5-9870-b2531ec8b2bc@suse.cz>
 <20241031075509.hCS9Amov@linutronix.de>
 <751e281a-126b-4bcd-8965-71affac4a783@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <751e281a-126b-4bcd-8965-71affac4a783@suse.cz>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UWRgoQKa;       spf=pass
 (google.com: domain of srs0=xeo+=r4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Xeo+=R4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Thu, Oct 31, 2024 at 09:18:52AM +0100, Vlastimil Babka wrote:
> On 10/31/24 08:55, Sebastian Andrzej Siewior wrote:
> > On 2024-10-31 08:35:45 [+0100], Vlastimil Babka wrote:
> >> On 10/31/24 08:21, Sebastian Andrzej Siewior wrote:
> >> > On 2024-10-30 16:10:58 [-0700], Paul E. McKenney wrote:
> >> >> 
> >> >> So I need to avoid calling kfree() within an smp_call_function() handler?
> >> > 
> >> > Yes. No kmalloc()/ kfree() in IRQ context.
> >> 
> >> However, isn't this the case that the rule is actually about hardirq context
> >> on RT, and most of these operations that are in IRQ context on !RT become
> >> the threaded interrupt context on RT, so they are actually fine? Or is smp
> >> call callback a hardirq context on RT and thus it really can't do those
> >> operations?
> > 
> > interrupt handlers as of request_irq() are forced-threaded on RT so you
> > can do kmalloc()/ kfree() there. smp_call_function.*() on the other hand
> > are not threaded and invoked directly within the IRQ context.
> 
> Makes sense, thanks.
> 
> So how comes rcutorture wasn't deadlocking on RT already, is it (or RCU
> itself) doing anything differently there that avoids the kfree() from
> smp_call_function() handler?

This was scftorture rather than rcutorture.  While I know of others who
regularly run rcutorture, to the best of my knowledge I am the only one
who ever runs scftorture, which tests smp_call_function(), its friends,
and its diagnostics.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ed93c68c-fb17-4c20-958e-0fc4ce8bcd83%40paulmck-laptop.
