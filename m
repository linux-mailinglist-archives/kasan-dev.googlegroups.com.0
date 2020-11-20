Return-Path: <kasan-dev+bncBDK7LR5URMGRBKW7336QKGQELJFIEQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 487D22BA9B4
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 12:59:39 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id g3sf2985215wmh.9
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 03:59:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605873579; cv=pass;
        d=google.com; s=arc-20160816;
        b=OscZBL/jgAEfr8TZ07EKVoZgXgPi6+69xm2E8LbwfYKUMyBNgQI5sHL736ZvTwpwmi
         AvXOfQGot/LY5n9aVwo2YK47x38P4Xj9VvpynL5do395FSZECwOiJFsVfRlsUJVjudFL
         h/Ha8FGVOSqa7WTsIUWFlmbH+FIxB9zSDTumWKBLei0EgmlMEMbYabLMtHhY7zNzVD+i
         xY9+Sq2gyQKawk9oNqJS0eMyjU3vW4pfkyFgrtCiGh/fko8lEBQVxZIl8NwISd1lLh/q
         8gOoJctktFlG09iZVtqtPc8dXiC3uKsLfDkJppWTZZVRfpcl8gXTRNPGhG+QZD8h4omh
         gDiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=ixVqZsWx1tnct5sGIlFbwh8YFc1sXVoirmBQEWnC0Js=;
        b=dvWdwFyGZwO5jNaumMh7wUGxKqNAK3NatEgts218tUaUYKAN+jlwMVqYQ8OZ31GLMw
         BjZdJI3C/DGi76KBsxHTHYNn6afz0U+qa2W0ifiXTG3DmaUukdjGa+aI0mak52M6HO/i
         BxbrJY6jeVWrbyM0PvcGQ2uxG4PdrDLcyuxU8vIABGvKuPr3Duxi70Cewa7Z0Kbl1Jl2
         H4Yr2/xkhpPUVWk0areHOCkjGpSedYwJfbgyJBdLkL2LhzXaq+CBQkzZb3HHsbVe0qGU
         V79JlCqVkWYaRiSRTbP/1IwxWB030zK88Zy61jo+A0PkAAEv7U9jHpzjvdMIXzRtRWqI
         WGMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=E+RENnwR;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ixVqZsWx1tnct5sGIlFbwh8YFc1sXVoirmBQEWnC0Js=;
        b=LqbJeVeWCEXZ9cKnTIjajNpBFNjeDyZk0qC5q6vPd+cLKQy82l8ykGBdgQ3M4222KM
         EstaKm5L722a2670nSoIoi1s0hVmcFdONeK5rhs3KVpqKQumPx4wZ1nLdyK9CkN1rs/o
         /3A6f4ZBq8B0AA/aJwi8lExSD9t1LcwQWzZ0ny6fK23q727s6HgMuRu0d1IcJj+IgHWg
         3rx8yyU+4PCWxMfbFm4D5PtOnv0ERRcet7rNb7r6ULbYBPeHHw4qvIMS9H/yQpRbwRXN
         1be/g+OllHzdGPlwf2OS1cGbfgvGfXHAGUzMaypdT/lOLI4toqB57YPIu/Ui8ElOlgm1
         WkdA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ixVqZsWx1tnct5sGIlFbwh8YFc1sXVoirmBQEWnC0Js=;
        b=Xl9ZzSTe+ULQnXPlRZcdS+6G09956OPIzfdubWpIe7uOlxQTWyqIn+NeX9kyP/gqM6
         YvQgo8quOXL72oF9GAOobZbYhiHqRmstXY9QN4YH8Oi7mchGl+GN4fh5Ei2CQ66jIkSh
         QjFF3sI+arnUF21z+DA/fzZjj5sJuGIfAGXhOEwpJYKbpWhs36Yb1iEJtLhF6jmdkmXS
         LTJLN/xAA5wFS4WSjH7E19pdSqMMjPoufdJ3FnbbEIlb6ou0GzeRU7mhZKKiN7n04xLl
         7SfatToMzXU9K+MAHTgdCVlW7G3FJHvV11KaJWWXbzXqac+Bt9WgQBF+77zwTynP6pmm
         YjGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ixVqZsWx1tnct5sGIlFbwh8YFc1sXVoirmBQEWnC0Js=;
        b=OO7R74MzTTtnarI/3oo0edapFqGx229aO3QKvH9Eqr9dCXTnP3wnrlrKTu2qffSGnT
         BW7jiMAndExWv7r/hPn7hZMn9eLS6MtpO1ozgTWpTkmwGBRD6P+NSYkAN+/FLRFDlhk3
         PcvI7m3LsTKACB/YjI68DYMcUg8fvYRDS9YgA7X+834WMZB6khZVEAtxn2UIsZSJu//T
         q5LGFiPGte8uwZTepSvoCW6kkw9QCAlfQrOpGD/2UMt61AEwisJD25cLj1jfU/Plh20U
         qq4CP+ypXhgPLHq3sfBxijUAFN484vmzFk/LMJntl7dZzHB4dgiA42cxB5D/rDft3jGX
         p8pA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530U9oC4SyzJtBcCvbtr3az+E/wzGWds1OsGq7u0OobMB/K+wi5K
	E83rH8KBdd7jC6+86xFo0Bs=
X-Google-Smtp-Source: ABdhPJzQQSB7swaukHnbixkBO16847UgwxtpdM+fvxCRuSuZD+zyWgOZTVIq0TmuZjrTfGCJyfTA2A==
X-Received: by 2002:a7b:c5cf:: with SMTP id n15mr9998076wmk.9.1605873579002;
        Fri, 20 Nov 2020 03:59:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3d87:: with SMTP id k129ls3233410wma.3.gmail; Fri, 20
 Nov 2020 03:59:38 -0800 (PST)
X-Received: by 2002:a1c:7402:: with SMTP id p2mr9960086wmc.104.1605873578187;
        Fri, 20 Nov 2020 03:59:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605873578; cv=none;
        d=google.com; s=arc-20160816;
        b=i5y9TyEQ91XHmZLeM9Tqtg2uKO0OKAyr82YxRcIAsJULt6lfAoz19Khsjlk/sJkCJD
         gvLtLDRHk8jA9oifdt16jsOzidtTtQ/ZWJ0ZrXxWgQTKxkKKPi9vgjvpAxZbCbdKyT4O
         8SMbsHqP77Uc45zE+WOgVzoPvRbZ7vk0KPkaNaDE5HxvvIb6ooT8U5zl1j1w4gcrg47Q
         Jp89Mohh8MZzWitiLMnbrZYJQmHno8okbUpyDnHofL29D34QD3iXgidpWVLp24J9VLsh
         D9Q/dXNzBXTrL55cCXwspMjhhNjvJ8aXJYYFX1Pq0ZaRobhQUujAqLki5DTs55ATmCsB
         qqgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=+ibvwxqqWhUDi9O2xUIvhnipfczvPxS9v9Q92lXKwNA=;
        b=lwu55jAtjfaOTvUsWyfAC+ODdPAMVuEU0UL41VhTkqQUOtkjdqXv6zQfFPmQb2wGvO
         gThPQbTYV4GN94HJpanPr7XyAWezXg3Oo7jZsygF6z0ZIMkTlgi4MnshU3Xd2nTezWV2
         EUqWQQ7uTkpsRdWHETOq4pxzuRomwFhmSyK/lyhDFJkH6et1iP1os5dN+klGHAr4Xf2R
         58wG2GM9pd/2m48K8OyNnX7kfnaoOIZ81ayPlTz7uLO7AMW4WeIq7pz9sMbtxLQ7OWFk
         qtMBWtX+LtEEgLKefvNiQR+XCe8zj1ULpdqbIVLejShJs7pIxL2OqL13yFhq8ArXiC76
         HQEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=E+RENnwR;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id v10si76448wrr.3.2020.11.20.03.59.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 03:59:38 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id l11so13137162lfg.0
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 03:59:38 -0800 (PST)
X-Received: by 2002:a19:e21b:: with SMTP id z27mr7441956lfg.409.1605873577627;
        Fri, 20 Nov 2020 03:59:37 -0800 (PST)
Received: from pc636 (h5ef52e3d.seluork.dyn.perspektivbredband.net. [94.245.46.61])
        by smtp.gmail.com with ESMTPSA id h12sm322311lfl.74.2020.11.20.03.59.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Nov 2020 03:59:37 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 20 Nov 2020 12:59:35 +0100
To: Zqiang <qiang.zhang@windriver.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, josh@joshtriplett.org,
	rostedt@goodmis.org, joel@joelfernandes.org, rcu@vger.kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	urezki@gmail.com
Subject: Re: [PATCH] rcu: kasan: record and print kvfree_call_rcu call stack
Message-ID: <20201120115935.GA8042@pc636>
References: <20201118035309.19144-1-qiang.zhang@windriver.com>
 <20201119214934.GC1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201119214934.GC1437@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=E+RENnwR;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::144 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Nov 19, 2020 at 01:49:34PM -0800, Paul E. McKenney wrote:
> On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> > From: Zqiang <qiang.zhang@windriver.com>
> > 
> > Add kasan_record_aux_stack function for kvfree_call_rcu function to
> > record call stacks.
> > 
> > Signed-off-by: Zqiang <qiang.zhang@windriver.com>
> 
> Thank you, but this does not apply on the "dev" branch of the -rcu tree.
> See file:///home/git/kernel.org/rcutodo.html for more info.
> 
> Adding others on CC who might have feedback on the general approach.
> 
> 							Thanx, Paul
> 
> > ---
> >  kernel/rcu/tree.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> > 
> > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > index da3414522285..a252b2f0208d 100644
> > --- a/kernel/rcu/tree.c
> > +++ b/kernel/rcu/tree.c
> > @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> >  		success = true;
> >  		goto unlock_return;
> >  	}
> > -
> > +	kasan_record_aux_stack(ptr);
Is that save to invoke it on vmalloced ptr.?

--
Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120115935.GA8042%40pc636.
