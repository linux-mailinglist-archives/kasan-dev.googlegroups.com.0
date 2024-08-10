Return-Path: <kasan-dev+bncBCT4XGV33UIBB4U3362QMGQEFM2IR5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D65194DE8F
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Aug 2024 22:30:44 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-39b3f65b494sf42346825ab.0
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Aug 2024 13:30:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723321842; cv=pass;
        d=google.com; s=arc-20160816;
        b=amO2lfiJIzR4nGLj9EQk5i3hqW99JCczkB1Xzs3/lOdB6iRA1nGxpAfLnAXsxFKof6
         WxEbzvbulLZplUhlubpJJeKLX1w5Ov/1lyHPOkYDJlb4gOlpQ7E/fuXP3IvxqspEWVQE
         aqPNi52tg1H5QHTDgh7/CKvNKg4XR3P9Qx4dOopoa2nBzZVACXcV+UD9hR9hajSBcdjC
         BLY2ej+8dN38SBx+LuO4U8uDeTDxxeAD0maUq+BNsZ/CeBRTofYVgIsna/ZK4niv77NF
         gHnCzqO8f+R6Q82J5Y72ucQguMozeL1Plh9BqzAahWTI2vvNXL+czm3UPZNS7pHdEfam
         vBXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=BLXPQzH2UMol26woK5mGBA1cULQpArJjHM0tiqo76T0=;
        fh=4r9P7pg7FHZY/4/P4ehrivi120lHWAUOGG4BEhUXQ58=;
        b=Vf3vAGLFTxjR7Dny0t/21DASmDCmFeFX++k6mpFdeKX70QEtfcsc9v90wETpfTfoiC
         aucH25LfWKZzkLcjP2WY4n7Xxg6plCsGGqQA6TX6INzj/p5H9l4FldLkAAsV50xgeoCY
         136h4e/ojicyDJrKTm6MkQMSKCkHe1BqmkzEQyBJ1x3MLS7vqx0Xn3ZQtsd034JJ/8TY
         gQpkKGzJoWB+5wvSsD+NaVyZ4HBeaXZsiXeWryC3cL6KHQ7b8QCvMZ+ZfcuhYafPoIdp
         /c6E3nbQctqIqu9l/Zj2zvw9efKR7bV15iP4MEQImO0WEPhmeN5eiRwYyaLhaMYGqKxb
         Zd1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=i74G9X5s;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723321842; x=1723926642; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BLXPQzH2UMol26woK5mGBA1cULQpArJjHM0tiqo76T0=;
        b=s1JoE6asSiKA7G06m7nZiaSXAZmzq02lioeCNka1r3qW7TPl94wfZE7YPb39L+6vxh
         EQaD6qBCRsq0QgebVk8XdqFGuTydu15dz6mbQ6BOS83PD0rPS2lWkAqXobSkufUe1TZz
         gJ5vKOxGQJDIG7wG35qZ91geWrx5rMzR6CaD9xu6Xk7JsAhv7VWMMtEC8/V86EBbeGcO
         hne3xtqZTI6NEn8ykHNEP+8e/E2nZPS/uSL1UYCzSGRcQnV147X6wxGV3pcUO7jp5yAv
         AXIwIRScBxW77uCg/OhcvQwlw+gXe3AiS371bGg7bwsg2yxmiuA3qgCg22kqZkOEkDU0
         ZdHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723321842; x=1723926642;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BLXPQzH2UMol26woK5mGBA1cULQpArJjHM0tiqo76T0=;
        b=Awrf72XREep7pHm1pf5rIxWuunsN7nOb00kr0Dov1/MwMp49InvY8FUrbh6uTvb7Gx
         QXWO5wFej1SL9U9cNbHlqMyGwRfARcZTeP9iTclx9Nkm+3/J5feA3O3ckZMxbWFY7dML
         835SUNy90M54MHgt2W+ZPF/Z0UhjG9Gi+nc0vuEl9XIIWuzhpXLPzyRNsUxkETPDQRcU
         2QDePvZ3ClajIwz4tIMlCyjt3rw2zSDtUx0Ft/jklNkHz09u5Huol9LgpFAOsHgrAlgO
         JaSPt3oHkGE+tKnMeZS3DApQA7kWnlBaZ/EoAT+biVJneicUGJ487auK49wkq1TVPSKC
         pkGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU553DqSmiCt0AZUVHCVLBbFIMlBwmxiX/5rlVaM9Jf2iiEnGOMaVIDVn65yclw/1Mu+QlskA==@lfdr.de
X-Gm-Message-State: AOJu0YxrZJLANi6Y/IlO48n1kK0nVg8vkzKoUy5br3V3tfGrAh9xIc2B
	SvT5rU3J6qkEpZaUm5RXiHonP8RBHXyJNtV/VqiCalj2dVDty7Z5
X-Google-Smtp-Source: AGHT+IGaYWJHpbJt71MHA5bE+Uu05ClBuK+jm8kOpEXXreV/K/GX7LZTlPmHNW/+XKaa8Djk79EqIw==
X-Received: by 2002:a05:6e02:1a2e:b0:398:770d:1fa4 with SMTP id e9e14a558f8ab-39b7a462d12mr70227855ab.25.1723321842322;
        Sat, 10 Aug 2024 13:30:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ec3:b0:375:b30c:ffd with SMTP id
 e9e14a558f8ab-39b5c9951a2ls20203855ab.2.-pod-prod-06-us; Sat, 10 Aug 2024
 13:30:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsZpU+A14rjqW8SrqqD/pB07oZSfY6xSiZDwAlI5uTX8GO1EK7xf9ssih8v7QCZDDdxpTz9aduZWE=@googlegroups.com
X-Received: by 2002:a05:6602:6019:b0:81f:92b6:8235 with SMTP id ca18e2360f4ac-8225ecee558mr717354639f.6.1723321841386;
        Sat, 10 Aug 2024 13:30:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723321841; cv=none;
        d=google.com; s=arc-20160816;
        b=sO3l0pIrKu/s49n1YMyraM5fbi1wZrODy/ODjj6vCWXD8/1TubcoS2HdhpSRCFOF2F
         9eSY3y0CscaXvCjxDxjQySB37aGFz10fHRyCGqEwQ53QEoHCwzARqcOPNwgX96GU9UT8
         +cCt9XShj0+JdANGk+T1aPV7XsnFCyvvNbx79KAT3swQFiQQ6QMp0uuYmKcLc7IJW7iQ
         HA+QLD9Bxc5dPAO1ykJoFkUA+gefY71MKSnntmaGWJBOym4m1Aqln3gZA2GAr+gD5FoP
         OklpMFJZ117naQgHf8XtAKc/kzvyoi0FU0edPYz0LE3DFBoLOF46IxDAkQUMs7SIW9CM
         5ddQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JYUdtS/d2mtDy6Wb9t2R6ES48f69PR1f8oh7pik78XA=;
        fh=lCR/Lg9tDr/iRH3ndqGMlOkF32PLZeyh1uaFK6f16uc=;
        b=FYiiGogX7SnMK8e++a9Fhsc8Cz6p5LIOwBkrVpnk19AANOeimr4OYpq5cQcigDHm6L
         TH4gp5rmMiuPwWXZIhM9o4VlurZfC/gV/Pp+Yq4g9yYa2wcv+GWDY8bBY98PvZIY42g+
         GPTdmsUomBXHYKKGz21FSUFVdM5sLrqVgwyEqhuHXxqtTdj5ITMyfxrIHKy4ZTnXfFPn
         vqv7ZLB67JzsCN/hlZXq5WmW/S0G1JbZ9t482XMUV6QedrkRj5wjP2x8zST6EJyKTVQc
         n9Dcycl6iWul1clduziKwjz9pzxglTUGUrGpzyg7I50QsAu/BChJcOMv9xzXnfHdMhRT
         dC3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=i74G9X5s;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ca769f029csi85947173.3.2024.08.10.13.30.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 10 Aug 2024 13:30:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 53B1DCE0B5C;
	Sat, 10 Aug 2024 20:30:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A254BC32781;
	Sat, 10 Aug 2024 20:30:35 +0000 (UTC)
Date: Sat, 10 Aug 2024 13:30:34 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>, Jann Horn <jannh@google.com>,
 "Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes
 <joel@joelfernandes.org>, Josh Triplett <josh@joshtriplett.org>, Boqun Feng
 <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, Mathieu
 Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
 <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall
 <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>, "Uladzislau Rezki (Sony)"
 <urezki@gmail.com>, Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon
 Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, kasan-dev@googlegroups.com, Mateusz Guzik
 <mjguzik@gmail.com>
Subject: Re: [-next conflict imminent] Re: [PATCH v2 0/7] mm, slub: handle
 pending kfree_rcu() in kmem_cache_destroy()
Message-Id: <20240810133034.433d3e1338d3bd8a0c90bf45@linux-foundation.org>
In-Reply-To: <167495c0-187b-4fb8-8de5-63db0aef193e@suse.cz>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
	<54d62d5a-16e3-4ea9-83c6-8801ee99855e@suse.cz>
	<CAG48ez3Y7NbEGV0JzGvWjQtBwjrO3BNTEZZLNc3_T09zvp8T-g@mail.gmail.com>
	<e7f58926-80a7-4dcc-9a6a-21c42d664d4a@suse.cz>
	<20240809171115.9e5faf65d43143efb57a7c96@linux-foundation.org>
	<167495c0-187b-4fb8-8de5-63db0aef193e@suse.cz>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=i74G9X5s;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 10 Aug 2024 22:25:05 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:

> >> I guess it would be easiest to send a -fix to Andrew as it's rather minor
> >> change. Thanks!
> > 
> > That's quite a large conflict.  How about we carry Jann's patchset in
> > the slab tree?
> 
> OK I've done that and pushed to slab/for-next. Had no issues applying
> the kasan parts and merge with mm-unstable (locally rebased with Jann's
> commits dropped) had no conflicts either so it should work fine. Thanks!

Cool.  I have dropped the copy of v8 from mm.git.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240810133034.433d3e1338d3bd8a0c90bf45%40linux-foundation.org.
