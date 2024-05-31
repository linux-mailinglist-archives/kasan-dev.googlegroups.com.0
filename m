Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2XW5CZAMGQEIZSDJJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DA2868D6B26
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 23:04:43 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6ad934c8e49sf42377086d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 14:04:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717189482; cv=pass;
        d=google.com; s=arc-20160816;
        b=MasGeODd/i/JNT0B38aIAbD4RupObUE9W2mbWKvHKB2yhk87/gFDF3R7CF9Y6j6d9s
         4xmodg1z667OhlPx2kvIG/Sf0GPo65ZqWrm82pbheNg8dDvHREyFeD0ccbvmBS5/afVp
         IZPomE4DbkOlUpecIAvB6qLsnoskRmvL74mPL78MSAJIgC8f8vlq72gTWxu2SVxPEMlj
         bIOdTfxm+1PE7PdLnYHy0lZARBpFPIkYFYFAH6sVvXjBz65aLXH2TJiY1nJVpynk2mk2
         Qc5ydu1tzf07gH1ivJz42Q+7JwSi+69fJd4f29cUcKilGzCATejJDnc5fCMzwJVMNfTT
         bLYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=kGGviUnp2meuqntpOssAyBApyvmb++8SgRLhqWRnSKI=;
        fh=luZZ07Ri5BpWpZi/x2jv4OFuLZ0oK7Djo1sHCbDuqBI=;
        b=uFnuZqhmVtOaEjmua74E1WfAeBYMGKV5ntkXJ9WVjPorTrr485OjpAyKCSTFf0tCO+
         YCpc3NlSXC5R3xKiAj9lVzL0ufWBUM09b0le+fpm1HvI3QvJso/ON8kWIeQXRZyHgoQR
         xmHCiWVDxz4iv8mTrZC5fX3jwSzl8Q8PFR85CZQL8nNXhA/kcmnztSZAIgw10l4IJoe0
         yfM/afhe6mEUNRXbGAGw1KxY/JIFLmyk4sJjxT26XFCokzS4AmhI4hVpMK0zS2NLcYnT
         0bPAFIToB0r0VLHyaZveaMolM8Cu1/2Y3IiABXEhIPuXtiiGQXV+B8q7ntBjRKgRZJzy
         7lKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nO3fy8fg;
       spf=pass (google.com: domain of srs0=xoqd=nc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=XOQD=NC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717189482; x=1717794282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=kGGviUnp2meuqntpOssAyBApyvmb++8SgRLhqWRnSKI=;
        b=bcE3a+KtaEnSli88dSyK9iNgbEPZ68g+n/aVT0ePCBYqqXgoW36nqOPQx2HM9DE0c+
         YXxaedNkAMLKAHeTCe1UHenhhEKylgYV9tkSZ59NNIYjzUgz8e/JD0mcmkaIRmLdDo+t
         37EmOI/sczSt1vMs2BiFIywXet9M6Zj/ogzEjD03+9C7/qwabf/aqL6x9X6rzBpyle3h
         Pym/YCf8yGlcShqJlhjfh7EfnG9kuWCl/iVJTflDVAq8PU9ZPyomjfWSFjIGLc04+3+b
         dyZ+oURbXSZ++DI1cBCle9lBNMDaNJWRYWlFdh0fhNZ/UcEMqJ6mX8PVaij3tHIKPX1d
         LDLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717189482; x=1717794282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=kGGviUnp2meuqntpOssAyBApyvmb++8SgRLhqWRnSKI=;
        b=Ojtc/dGI3qc1JOQc+LbGEPk2eVOG56qQKPJ12zhuId9JmI/RrAwLOlu9VQBibPD9yx
         32PNYoUZnthLg3EZ7CKj+vtcQmj3UzhFic1aa4SsBp4oixantmcvPxf633JlODVokvma
         +4Husbn+N+e/6UdJHMZEBqoqG1ZsltP2OjeDtjKiq+elEFC3j0JqbJc8JZcJlP8EGCAo
         jUu6Y6LjRENWtGav1eUjmNoWiQo5T1/SXBEiOmhfu8fiHoRSAnOxHt98N9FZ8DDXU6Fu
         ccaTV/esC9zY4w4rpyb/fNnf3YJuygZzIEBnVbaG6v/W/bdgTHP1C4hZ/ZiLAEzIFTGO
         WRqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEw2EF/D+0fq8aYGUz70j/Ez2CSIyLnbl2obO8y+CvEEFjzRLpKyyR8Ek8otz1bs+Dqzqei0bOF2Ft4eNLRmxSndMgK1piKw==
X-Gm-Message-State: AOJu0Yw+gmKPbPM5DhNEXKqeqxKjl7Prem14Ff25wG8xSDtmFJtwYJND
	YdvUEJsRZhzmOxMR7dR0SdbE3nqwQccx7kR6l1WAD7TIyN2uiQ57
X-Google-Smtp-Source: AGHT+IGWVUC4t44TGFUcM5HFF4+KQlvq3xUsHsZ9UPD9ejEBbl3zmFxC60CltQeddUFCU5k8IzUngA==
X-Received: by 2002:a05:6214:5f10:b0:6ae:bb9:3fd6 with SMTP id 6a1803df08f44-6aecd4cba9bmr55954626d6.27.1717189482540;
        Fri, 31 May 2024 14:04:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c87:0:b0:6ad:782a:b4d5 with SMTP id 6a1803df08f44-6ae0be0154als8880306d6.1.-pod-prod-00-us;
 Fri, 31 May 2024 14:04:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLP8h6wL16tiaZ+7YUIfZW4lT5jg38dYXPbEy6fTat3au2QNjE99aqAT/nzzH0wdob97q7PY37jUOkE7T8JIAyihFIt4yDogCHJg==
X-Received: by 2002:a05:6122:c94:b0:4eb:e1a:5ad1 with SMTP id 71dfb90a1353d-4eb0e1a5ceamr86926e0c.8.1717189481264;
        Fri, 31 May 2024 14:04:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717189481; cv=none;
        d=google.com; s=arc-20160816;
        b=C60H1aNBmHolxbbarSrWjdeGHDFaUQieiL8t6Hp5bCrWh/fdN66AihXOMx7DmoxXPQ
         qkN/7EwJEHivchYqTYmgfCjeO5AY/eEt4gRrR1h2HWC7rEHZy6s0hpG0w5mHnrbQA7bN
         6xfAyowWMTXkQpbsKXROqJ8uc6qeLfsiYDacPntFKD+LjLu98EfRhUWLk483Z0gCKQdB
         Rt0n/R+64pyLYZH+6dhYQ7zHiTCEqw+eHUdE2R6Wqz+g2ouezu6BSt63kIrMYdAHieeX
         Jg5R/enF7HW4Wf5i63DfXsTK7wb/2UiyWJUW9QwBk+jGOQFj93uPNeBot82CkEyOheVa
         HeBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+gYc8xZ+7bLr/UrpUiwCL51BBJyv1nMVa+Kxwun/JbM=;
        fh=F+Y/3YZ2rMNw2iY2A3swn4QWCnDTUGTSJZqXwfdeyzw=;
        b=qtcGFi/BHWf4HfGYd+D5B5Vx1Q8xACme4yUnkUs5WJ/wfSEavFYanI+I9yB4wf8oqZ
         nFz7z10UVcq6nbSBxbX9bagk0HvR/BB68/zQt9cHCc6gslpeBdhkr7fm3PxelPHaMQwS
         6BM7BV6mc62673IJmYQuQl4PiIvSqc8t43qLdSVKKbT+xGD8Y66Gzx6F1ZJv/KKKVBU2
         a4QYMjLkpVqK7oIKBJ7qK09q7fRGlw4tWg+XDLkUOfO7d+qxkx+FH9V0ld3IrIdEC+XQ
         /pF1DtPcC+i2z02FZv5l+H8rJLXCaP7mqigbdI1lu/VWP38WshlghEhh7lkJeby2qZ18
         Iiqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nO3fy8fg;
       spf=pass (google.com: domain of srs0=xoqd=nc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=XOQD=NC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4eafeda9bf4si83760e0c.1.2024.05.31.14.04.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 31 May 2024 14:04:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xoqd=nc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id EBFFBCE0BDA;
	Fri, 31 May 2024 21:04:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 39EC0C116B1;
	Fri, 31 May 2024 21:04:37 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id D2E67CE1347; Fri, 31 May 2024 14:04:36 -0700 (PDT)
Date: Fri, 31 May 2024 14:04:36 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Jeff Johnson <quic_jjohnson@quicinc.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kernel-janitors@vger.kernel.org
Subject: Re: [PATCH] kcsan: test: add missing MODULE_DESCRIPTION() macro
Message-ID: <2fae7fe7-1e4f-467a-b03d-3fcd6025d144@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20240530-md-kernel-kcsan-v1-1-a6f69570fdf6@quicinc.com>
 <CANpmjNN1qf=uUnetER3CPZ9d5DSU_S5n-4dka3mDKgV-Jq0Jgw@mail.gmail.com>
 <e9b4a22f-1842-4c37-8248-4f715d70a6c1@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e9b4a22f-1842-4c37-8248-4f715d70a6c1@quicinc.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nO3fy8fg;       spf=pass
 (google.com: domain of srs0=xoqd=nc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=XOQD=NC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, May 31, 2024 at 06:54:03AM -0700, Jeff Johnson wrote:
> On 5/31/2024 12:47 AM, Marco Elver wrote:
> > On Thu, 30 May 2024 at 21:39, Jeff Johnson <quic_jjohnson@quicinc.com> wrote:
> >>
> >> Fix the warning reported by 'make C=1 W=1':
> >> WARNING: modpost: missing MODULE_DESCRIPTION() in kernel/kcsan/kcsan_test.o
> >>
> >> Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
> > 
> > Reviewed-by: Marco Elver <elver@google.com>
> > 
> > Jeff, do you have a tree to take this through?
> > If not - Paul, could this go through your tree again?
> 
> I don't currently have a tree. Kalle is in the process of relocating the
> wireless ath tree so that I can push, but that is still work in progress.

Queued and pushed with Marco's Reviewed-by, thank you both!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2fae7fe7-1e4f-467a-b03d-3fcd6025d144%40paulmck-laptop.
