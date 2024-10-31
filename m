Return-Path: <kasan-dev+bncBCS4VDMYRUNBBC53SO4QMGQEY5LC6IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id AAC3B9B929D
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Nov 2024 14:54:21 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-6e376aa4586sf41274627b3.1
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 06:54:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730469260; cv=pass;
        d=google.com; s=arc-20240605;
        b=CzWuEuEswAxycm4bNSmtx1hwpAN04k+b41UnEvnNU8LQYmqI4iVLQp13v1qMRjxDZu
         DzX3X3r80hiht6jjujKoQaBobfoyK4L6O+q0QtpgqGlUtKGOOdCtJ1TFd9/r2LEuBYvz
         tNtt/sKS5XmohXsrowHb2PN6PZQY70qkLxI9xMjq0LAN85xElhxeZAOZYfDj2SSI3PIL
         mdjfDDayB7jGF08WRFb6dQ7GjrJYR3sq0gQJqgn9kcZ0bbK8Gy/9vej2qBQWzbsMGgbl
         6l8lkma5kc10+Hqg03wVDvGQWMFAbUEBal8kvO9huvdSOjnPlPNq9dexqLWFFOm6WjUP
         fttA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=p0QPeym7Vi7tGlDCaWtiJegaqXsUGMaQ4XajRTai7b0=;
        fh=DU8KZTp+DSTIWiQ9nBYyIn+geI7OCikvWaLDoPtFMhw=;
        b=WFTHXQ9etVyvoLSeZ2Sw+4MMFDA11G7H04gpF81Jkfc4ik4eUj2/yL5fJFneVAXQof
         rPvGNeq4O35Eo2+SLgNseQA9DHh+BEqZlm0ZaBpaOoy+8ysc2bljwkW3h4/daAhhel0l
         0adP+Pag267mZI0ijuvh1XFGFrgJgAvoSu33IhRGvjmnzlhOgLLk8A/HjWrNVSXG4UUa
         xuPK0fPyCYQfd1iHAWFjMR0SunI9a3dVczWf/98h4tYnVDa3eZF1tPph8oOlRk0paZYi
         Fb1hyHhuP+TL7iJoHBaW71KCbGB/867/uwhSyU3oV33muE1HkHfQbUkQwvFJW9AwnArS
         hcyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bqbme28b;
       spf=pass (google.com: domain of srs0=+qdh=r3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=+QDh=R3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730469260; x=1731074060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p0QPeym7Vi7tGlDCaWtiJegaqXsUGMaQ4XajRTai7b0=;
        b=ZMDh+Nq7i5YmWorceJUUcYozfKbHv6AONGQtpIi7Otyh/ePzPUOY0LEs3gOfdv/G6q
         6iNQU6lSO2CJrBpq4IU3bzSn0s/TsnDbPbyzhWT+lyaUQZHTXkyWolMRW8farAGqe411
         Tqh1kmRWrZZWbN+DbTgbRtRPFmElso6HRmAO8jnm8eNBcoG+Kpa6/MhKvl6pG02FS5g2
         +VqWVm+gUPfz7ReqZ9bfcARW0eOXtCw9A38281VXnQEZjnwberWH3Q+lVaC3JLXiKRTE
         ePvT8dZlhBR3Y7FkbhzN6sKErkrNj085K9OZJm54QdntLUIqaWZb7NHpNWaRiB5YVXsa
         YGlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730469260; x=1731074060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p0QPeym7Vi7tGlDCaWtiJegaqXsUGMaQ4XajRTai7b0=;
        b=D8FQ4DpAOGGtd1utFZ9lev7xApZ4dyJGOlT9HU+/Farkzp51iaBx1mQYh1DHEUra+W
         +1ryIY9GlZ9r6IeQC7h+HGI3IO7l9Cc2Cqpw9XNEcbw8IZMmr2vPEM7jNcaeWXX9gohj
         TX5xU3/+sgU3Ujngz6KpcFKk6lZk6cX7cG7QVv15y/DruDUEB8T44NIP2/OiPQOwrog3
         UGi6hGFTfYcracvSZOFXhB9aY6vrD3SmRXjyaAffOVBZHl/udMTAiW45peQPZdPkshpP
         NTC4d4scATZemVXapYB+Ifc0suI+fdIp0LX2aAmYFgN2IPA26GDnCuoZhvxDVn8bJq3Q
         QGuw==
X-Forwarded-Encrypted: i=2; AJvYcCX1UHuXz7OxF2+x2tBl9Qr994yT+1jQnsmsH0cE6EOApQgiOGDWJL74Cd4K48DYFhlzYUSnHA==@lfdr.de
X-Gm-Message-State: AOJu0Yzv8HB6ThEU//xHgydsNzzbYzEldlDfLUxHpIOlGLzHb2ioYZMn
	5vW4dNiq4pKcFszzys3D0KqyGuQ36xK8YCEH9No4JuZ7F7Mpd2Yx
X-Google-Smtp-Source: AGHT+IFsEXG/1cEz1CMWiJg1m4P71bOyq2byhb80J4NVK5odtV4KviGDiAVn124Ghi6AuzCxpnLAdw==
X-Received: by 2002:a05:6902:178b:b0:e2e:426c:1b8a with SMTP id 3f1490d57ef6-e30cf4d0222mr10020828276.43.1730469259960;
        Fri, 01 Nov 2024 06:54:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1081:b0:e2b:d93a:e54a with SMTP id
 3f1490d57ef6-e30e52e3a32ls2230919276.1.-pod-prod-01-us; Fri, 01 Nov 2024
 06:54:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPxN+6aPC1GFUuN86mWwkXwj89kahv2cCiFWavQrfibCQoecSjA0qYanjsfx/K/2OhrmU/vNWxB08=@googlegroups.com
X-Received: by 2002:a05:690c:9a8d:b0:6e3:d8ca:f00 with SMTP id 00721157ae682-6ea3b9a5e6dmr121720427b3.44.1730469259232;
        Fri, 01 Nov 2024 06:54:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730469259; cv=none;
        d=google.com; s=arc-20240605;
        b=X7DXY1MVdnT9w2z5dFWHJNLNvEJ14636EAYsx+TOPRirRsx+b3CfVbg+rkiRdYnd17
         Dyem7S8fLq9aG3s/bcXGg2L+oY/uFj6Ot2ZNcuTC4YIDnpxJn+u1k7gem06h1vH2VVr+
         wRem5/Y2NudT41kEfrlvVLujDwUi3fOj84YfE83f1PQF/D1n1hLrWzRgzccFXIMBgHkf
         6va+kAxAAV0MPsNyktDmvdCpkRK5Pl8hxsyaUjlFuqETiPKcO3sxZIQ398kL2VCkBMHI
         gX+tQkx/qKKRxBFWsltw8NeCtZ3LrEzz4F8G3nKGGxHjbJWmX6uNe2MIRCi+MPrUsU2r
         B+hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=goqsqbzYGXxH7FjEdQzT96YJkPu3wOgquGA1KmYFB1o=;
        fh=saykcCtQnKc+PT7BTjDrl/MDk0oYddXtH6b+EDATiug=;
        b=YjIIXOAqNPiVdtI9Gq4E9AY5Qhr8oSZXccy+n+gPQe1IHhb9+VneavrNNXRMnhzAeZ
         qBlZ8SbmmG1q+EakeEAU+RXUBmIbdmQ4ekjKqpTq0VYjspu9DWmMDXrUjHzIwLpyJ3fv
         TVm9y+6WJyKpHAdDRF5qKJVaDMJ8lswOmMl3O6GjgOnVcF8nJ91F5C8XZSC8T7BgQxq9
         ikqgzcXrWCYEcpFSiu4/GJxp6nwLKk2t590WoOj9ieDceSPxiJa+1lKnfIHmD4CnlWWQ
         N11HSI1i3+QYvyrud5mkO162/CQTVNeJuOKE6b8lCTt7MmiiSPDYdnZa5H+tNSMrCNCE
         NH2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bqbme28b;
       spf=pass (google.com: domain of srs0=+qdh=r3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=+QDh=R3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6ea557afe79si2507827b3.0.2024.11.01.06.54.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 06:54:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=+qdh=r3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8C32A5C64AC;
	Thu, 31 Oct 2024 17:49:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0EF0FC4CED2;
	Thu, 31 Oct 2024 17:50:30 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9393ACE0924; Thu, 31 Oct 2024 10:50:29 -0700 (PDT)
Date: Thu, 31 Oct 2024 10:50:29 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Vlastimil Babka <vbabka@suse.cz>, Marco Elver <elver@google.com>,
	linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, boqun.feng@gmail.com,
	cl@linux.com, penberg@kernel.org, rientjes@google.com,
	iamjoonsoo.kim@lge.com, akpm@linux-foundation.org
Subject: Re: [BUG] -next lockdep invalid wait context
Message-ID: <186804c5-0ebd-4d38-b9ad-bfb74e39b353@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
 <ZyK0YPgtWExT4deh@elver.google.com>
 <66a745bb-d381-471c-aeee-3800a504f87d@paulmck-laptop>
 <20241031072136.JxDEfP5V@linutronix.de>
 <cca52eaa-28c2-4ed5-9870-b2531ec8b2bc@suse.cz>
 <20241031075509.hCS9Amov@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241031075509.hCS9Amov@linutronix.de>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bqbme28b;       spf=pass
 (google.com: domain of srs0=+qdh=r3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=+QDh=R3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Oct 31, 2024 at 08:55:09AM +0100, Sebastian Andrzej Siewior wrote:
> On 2024-10-31 08:35:45 [+0100], Vlastimil Babka wrote:
> > On 10/31/24 08:21, Sebastian Andrzej Siewior wrote:
> > > On 2024-10-30 16:10:58 [-0700], Paul E. McKenney wrote:
> > >> 
> > >> So I need to avoid calling kfree() within an smp_call_function() handler?
> > > 
> > > Yes. No kmalloc()/ kfree() in IRQ context.
> > 
> > However, isn't this the case that the rule is actually about hardirq context
> > on RT, and most of these operations that are in IRQ context on !RT become
> > the threaded interrupt context on RT, so they are actually fine? Or is smp
> > call callback a hardirq context on RT and thus it really can't do those
> > operations?
> 
> interrupt handlers as of request_irq() are forced-threaded on RT so you
> can do kmalloc()/ kfree() there. smp_call_function.*() on the other hand
> are not threaded and invoked directly within the IRQ context.

OK, thank you all for the explanation!  I will fix using Boqun's
suggestion of irq work, but avoiding the issue Boqun raises by invoking
the irq-work handler from the smp_call_function() handler.

It will be a few days before I get to this, so if there is a better way,
please do not keep it a secret!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/186804c5-0ebd-4d38-b9ad-bfb74e39b353%40paulmck-laptop.
