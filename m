Return-Path: <kasan-dev+bncBCS4VDMYRUNBBUNK5SZQMGQE5RBJIIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C9E969170DC
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 21:06:58 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1f9e9aa8cf3sf57302405ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 12:06:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719342417; cv=pass;
        d=google.com; s=arc-20160816;
        b=qetf9IskqG1vjjGO/28xMTs7Rpz+qksI8rQsTBKY46J1xsTSLlBIdr45y52U1pP0NG
         iKQlp8r6Y32EGxVGZxzDEuPqgsndlbiy0fqPSQ8FGn3A0db0g8sUzUCZ19oAW2vHh325
         ggGeEU032e9WuPBnbADd0ididZXXA1mUBmrWynfu9gLnPX5GL/NWzBAGUNLAMLt8h6j1
         qbyoAOFMNn+kj5eLFyzgJeKz2lQc/bCOlBT7VEaQuv0dtelYs7nODUiaYnoSTPer2byp
         BslNESm1GXfcvVeGWoFDPig6tdcPFRuk5EGbuIPg0yAut8J0y9dUMJOOwARVNTw9KSMX
         Gyag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=MZeXz1H+aGBHaaogbz6Zm5WWkZXQONy+ChNn6tGvA20=;
        fh=MtYDjwWtBt3PHgo9oIZv0OnhFcjLNn5TuppqK8MHAjA=;
        b=HkkZhdxNGXQVh6a6owpd1lcJkwhL1j+CjeDvMGEthQPo7orY32kdqny4Ey6Q19pC7j
         Vl/UMGrt8bLdQau3w9leAAyHUjDfV8+xZNL1uZPKM1/ytIzYcEesqOehIlsJmpOi/W5k
         r8n1S3k68G1EN+XrTA6vZbLsSBTWKEG6Ifdvyso7PZZxo/COAUSWjdTz5/AmVQBeVmBW
         uB9CGSZ8CzPKYw5/FEjIVjDGw6I+8wO3aZyKioEBLmQTezxCmMvhPlLGV4Rc9t/kAxiY
         HDfm72CWlxHrXTirFlI2lod+cFCeBO+pSrYi1enkUO3kx24A/ySs2rYnUoNKE78OVwh6
         e+eA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="T/2ILEFH";
       spf=pass (google.com: domain of srs0=dlug=n3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=DLug=N3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719342417; x=1719947217; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=MZeXz1H+aGBHaaogbz6Zm5WWkZXQONy+ChNn6tGvA20=;
        b=FYbzetVENVLXtX2YpEsRoq8Fw0PkGSZ4hkulhdhh0+cDqPSH+8+j4WRKh84f1uw3mo
         P8o2NbOFriF+kLLBLEHEzycOrYUlL4KNm3Z6kNPnI6yrmYPX5mGIYEUccv8lR8rPlK0V
         Ec02W0o3B49Dx/gyN34hUobQp/hAduuBi0OXk+rQ22w0vkMOtfhA+hjT0+JCn7xne1UN
         0BvSgmV4TARt+k2HMVtIF/9TG7hjhlyrv2MBBfR4iuni4lkewlt40QO7U22wyPTEpA/5
         SiiofOooYMpvUQOnX05vW8YOs3FXUGxqFZskSABHGsnXu4DcZf8zkbHPf4AnvnYd8fDC
         HGfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719342417; x=1719947217;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=MZeXz1H+aGBHaaogbz6Zm5WWkZXQONy+ChNn6tGvA20=;
        b=ZDKytnxc4dIhL4VtaOAHUSRCiklUmAyFR0ykzQCyO2vXk3V6gv00kC5GkMLQldAiyo
         5L2g4bN07cRcw/vtI/GxgaImPGekXD9SF50wFTrvDmPbsNHHLGD9YfmuCHvGtuuRi0RK
         bCwz/pdfOjQv9VhuSAny8igNvpnrPSOvwS0INHUlT0fjajuUWxOKkvXWBR86jP+ZEvRF
         YjwjWOS3iFzrrcTzH+My3XLDyUJ/Xs0O8YCyLItj8xEH4DF+kFXHYy8W2QD8jSWqXpGR
         YL2C9NItjD0VUJUDe8DRqZiiFKuHARl09BhlrW2VcPFm38JLbDsHlNkH2PoasXWNDvWj
         KWsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUoV3Kfjp3XfMAOL9ebx7eWGjFOCfkiJovIZl7fDa3rhJ4vP1lTjUKTJaC6Zgx0HDEgpQUdurARQ6kgZf1Zfgs04zt4FJS4AA==
X-Gm-Message-State: AOJu0YwMKk8V+VGsJl4OORKjkZ0gGqyjFoJSJuKF3WABT5nIHayVp/Q8
	PUIWaQfjjyQChZUHyQusKoTiZRDnX8to+qZIDu0RoVSbmVjZzP10
X-Google-Smtp-Source: AGHT+IFT+w8gwG9GpnYz6EGSflBOPjsInDos++NNejTdG26VuEDoCHx4neojKBT1O7m80/L0vdO85A==
X-Received: by 2002:a17:902:e74d:b0:1fa:1d37:7017 with SMTP id d9443c01a7336-1fa23ee1c8dmr93171485ad.31.1719342417223;
        Tue, 25 Jun 2024 12:06:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:1a9:bef5 with SMTP id
 d9443c01a7336-1f9c50c0e3els42958255ad.1.-pod-prod-09-us; Tue, 25 Jun 2024
 12:06:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbv4TVxaITT5072ZPdvXP9Sk59POgoZBlYd7BdLkXySe5LaGKdMSYNYYEoow/1ERZ3tZ1KykMvwBgNT7y5wkbclhvzKEij7/JiAA==
X-Received: by 2002:a17:902:e542:b0:1f7:2dca:ea45 with SMTP id d9443c01a7336-1fa23be1888mr96900035ad.7.1719342415753;
        Tue, 25 Jun 2024 12:06:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719342415; cv=none;
        d=google.com; s=arc-20160816;
        b=N9wXksNB0YKr/PfxhgeaakojjIzg6oW/oETAJmCRhlGJeTURK4IRXunk2ValUbRaRd
         mvSl8zULf5/lGNVJhW3jOUdG3HJg7PfsVpEQPAgI8ON1OR5YAoJIGe+o91Jp3kW7bgpz
         2O217hK+v7Z8s6Wv5dHNcx55N+M+4xMPPj/k1HlM2MJti38YIhcyR+pPvGQ2isiM6H9z
         Od9Cs7GVCPFnLRHx+ZVcaoAPfjjR7kOMxmOmcs61arSaRAVsaUim+GZ2+PWiJ5k2/XWL
         X11Fw9yfqU+qmMoXHQ3ZOqIxTZ0GGnbvNAm0QG4gWp7aiJMo7zlOZroeopviexxfuGWP
         KURA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8JEijCv9j3AgvVeaB7Ju24q3R2HOjWY7u/+QLxZ1ARo=;
        fh=wQIjuR/hfdxnXI+AoZr+xaPDPGIsTJZhd3r6o5H0hnM=;
        b=gVBi4eGg0rRpJrMKUvvPOxOLbJuJDvcLWTY191H6FbzHklb5QKRQTsxtftqy3smE5j
         MEYBvpV80O4SD7NRnTE8vBJFUkC2GoZxvHMEw+QIhyG00HudJoap2uBH2pAq8tV7ZAdD
         opmCKl1u2tUgPUr4TCoxdEehiil+TOEKbp2EgXdY+cSn8uREJnSec8CrzRRUbN9K+5Ss
         zOcA4l008G6E0bkQ/U7AYnCX0A1lYUJ4Kb4JZn0B9JV8e3QfrteA7VF3kVrXemk8U9Dp
         Zb9+63R31dAOEjGOkpHj9u6geiEo5xMzgoNHbno3xBahxnuH0cKaM9Kk/JYNpo9Z3GWo
         1+lg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="T/2ILEFH";
       spf=pass (google.com: domain of srs0=dlug=n3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=DLug=N3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb325f9esi3573125ad.6.2024.06.25.12.06.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 12:06:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=dlug=n3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0A81F61759;
	Tue, 25 Jun 2024 19:06:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A36F1C32781;
	Tue, 25 Jun 2024 19:06:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 01219CE0895; Tue, 25 Jun 2024 12:06:52 -0700 (PDT)
Date: Tue, 25 Jun 2024 12:06:52 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>,
	Alexander Potapenko <glider@google.com>, elver@google.com,
	dvyukov@google.com, dave.hansen@linux.intel.com,
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>
Subject: Re: [PATCH 2/3] lib/Kconfig.debug: disable LOCK_DEBUGGING_SUPPORT
 under KMSAN
Message-ID: <3748b5db-6f92-41f8-a86d-ed0e73221028@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20240621094901.1360454-1-glider@google.com>
 <20240621094901.1360454-2-glider@google.com>
 <5a38bded-9723-4811-83b5-14e2312ee75d@intel.com>
 <ZnsRq7RNLMnZsr6S@boqun-archlinux>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZnsRq7RNLMnZsr6S@boqun-archlinux>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="T/2ILEFH";       spf=pass
 (google.com: domain of srs0=dlug=n3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=DLug=N3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Tue, Jun 25, 2024 at 11:51:23AM -0700, Boqun Feng wrote:
> On Fri, Jun 21, 2024 at 09:23:25AM -0700, Dave Hansen wrote:
> > On 6/21/24 02:49, Alexander Potapenko wrote:
> > >  config LOCK_DEBUGGING_SUPPORT
> > >  	bool
> > > -	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT
> > > +	depends on TRACE_IRQFLAGS_SUPPORT && STACKTRACE_SUPPORT && LOCKDEP_SUPPORT && !KMSAN
> > >  	default y
> > 
> > This kinda stinks.  Practically, it'll mean that anyone turning on KMSAN
> > will accidentally turn off lockdep.  That's really nasty, especially for
> > folks who are turning on debug options left and right to track down
> > nasty bugs.
> > 
> > I'd *MUCH* rather hide KMSAN:
> > 
> > config KMSAN
> >         bool "KMSAN: detector of uninitialized values use"
> >         depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> >         depends on DEBUG_KERNEL && !KASAN && !KCSAN
> >         depends on !PREEMPT_RT
> > +	depends on !LOCKDEP
> > 
> > Because, frankly, lockdep is way more important than KMSAN.
> > 
> > But ideally, we'd allow them to coexist somehow.  Have we even discussed
> > the problem with the lockdep folks?  For instance, I'd much rather have
> > a relaxed lockdep with no checking in pfn_valid() than no lockdep at all.
> 
> The only locks used in pfn_valid() are rcu_read_lock_sched(), right? If
> so, could you try (don't tell Paul ;-)) replace rcu_read_lock_sched()
> with preempt_disable() and rcu_read_unlock_sched() with
> preempt_enable()? That would avoid calling into lockdep. If that works
> for KMSAN, we can either have a special rcu_read_lock_sched() or call
> lockdep_recursion_inc() in instrumented pfn_valid() to disable lockdep
> temporarily.
> 
> [Cc Paul]

Don't tell me what?  ;-)

An alternative is to use rcu_read_lock_sched_notrace() and
rcu_read_unlock_sched_notrace().  If you really want to use
preempt_disable() and preempt_enable() instead, you will likely want
the _notrace() variants.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3748b5db-6f92-41f8-a86d-ed0e73221028%40paulmck-laptop.
