Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS72QDFQMGQE35P76UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id F0909D068A5
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 00:27:09 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59b686eafcfsf2132331e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 15:27:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767914829; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fh3RmT8t+VfiUQTD418zZM43CmXuni7lEz86vjagDp1Dn899h2w1VHOtENUq1SjjnY
         NIJcvb64sr1MVq0FoAuNEP/uTMD/Dt0YaNyTnUsA/B4GCPd6f0+pPEf5LlDKwtGSfvzt
         LPdzAy/6j4zGc2sadzuFSOBhyia1XCcFsyoI0bxG9cdVoqNmoE6rxnxOW2qkx9o9YPxz
         l8tbL8bmscWJf4lQuMR4gTVaM5L/EPtYqZTuIK4QBIhgs+AqAgOSiIl3G8FV9h3svQu2
         ER3TxAxERDENiJiyqnPr1CnnJoWQglhK/klA50MjXAi0UlyVed+XgrdzlT61TxVZ0GIA
         xI1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1b0A9a/DCTvH94uhFsgSs7NFJ/P/eEpqCyBSSLd1b3c=;
        fh=hUIbXpklYoVWx5du0KoWt20xbtg+BIpLR5FlRBKQbdg=;
        b=ft0bGU0NhyUoDoId3eTk0Ru0Ink+B5pYF8OmPWhhyCepggeQJmlwgAoDUmz9hSRANm
         nXX9E2c7SRtznCK/snrYewATvv9rPPNbfoa9plvkQDGvKTF3Z4I5WrgZHZxk8otz+9cT
         sgp0ncWhe2glUIb9+s2AUjis5dkxVJJUvfyOYh2MH3kz1i1DY35kVdHo9bnuJ+cYRMXK
         VPXc3gqqjfJU1japJFg/dZSWFArEkbNyjxi/0FcaH17sDMX31CaIqgxfPpLTqw4iySeU
         bZfYmPctO8pbvjdyA6HDtOiYLQQB5ThF757YEtAPcwaJ17ttIMm9HGqGE0amgpYxJiyq
         VTTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yLYR6qfg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767914829; x=1768519629; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=1b0A9a/DCTvH94uhFsgSs7NFJ/P/eEpqCyBSSLd1b3c=;
        b=gIOwxI9ecAXvQf4uTPrtmYGflm6ZCh9nx1wI3XDUBj4CFeu3QFBhDv0coU8T3Do+Dg
         ZRkBTV7bYVVF1XJI7crb2WBWlykRXi097GlxQNvo5zE8LroOWkv6AE2JBpZhfai4dVCC
         QCQZm/Kiw5JgBaeVz2S8zTF92Xtrx7QVHR6hi5DHk383CgDr2xdM9iFIxo2Tzc/3hMuN
         +5heDXNoyqoF177JC8pxKPA4FAHcUXeHE5U4qP9WmIrKk8QHW8SI2CFZzPV24J+j6J6k
         ydeVbkvjnY9MUQD91niWOsn9l0K/87110iIt9IuMu5ybqkZ9W6zqno8Lu5fCicodKRkg
         eDzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767914829; x=1768519629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=1b0A9a/DCTvH94uhFsgSs7NFJ/P/eEpqCyBSSLd1b3c=;
        b=X4IlaEvvc3e5I9WClLcKYIxXi2qZq0bqPWayS2EXmEPwppik+l3c3/I7F4WVRS3GXr
         sjBjtakhvS1/+wY6iBTAz0iX2EAY1sMkHgOAW9s5wvSSSyQw1gBf5JGGjpGcYNYblOjv
         CyonpasYVdulTp3kLqthcBNEhtZzgRIXNXzLnermEF6Dm1toY/pid8MBbFCVvdtpf0cL
         e5naVyRac+n61t+aqr9uEI0Sdx1vubowNv/xN7vwCmPkq5I12KCKYIwnhgTq+hzx7svu
         pD6xS4S8PlRIIvLJNAUmrNPQK607+J9HyyoDnKhRH+YsAm9EcxUjhCQ3uVrQQatu2ZMc
         EOhg==
X-Forwarded-Encrypted: i=2; AJvYcCUMkov2pxVQ3xxgjauS0s4cv9gjvAAhQzKG20eb+50g2LcJCm8rK+ffLxoTLmyAJzX/1RMTtg==@lfdr.de
X-Gm-Message-State: AOJu0Yx1FVN7Un49k524V6W+lEvGJEobiSZ70XEHXGHTkkWwZlgoMhS5
	soYYHYxphqhZIpeJ9V7x+98d9HFnShVMsYjU+C+1Sy1WwUs6G4zokDGy
X-Google-Smtp-Source: AGHT+IFdiVxU8XEG4cNZRWPxujWYIEVCadnbSNHOggiEPXC5bQ6W85GRZXdBh6dv7beSz79SIsBJsw==
X-Received: by 2002:a05:6512:3a95:b0:595:7dcc:3a8d with SMTP id 2adb3069b0e04-59b6f07033dmr2303495e87.48.1767914828673;
        Thu, 08 Jan 2026 15:27:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbGTe0p2ouQNd17eX9Ik1FB1QZL9q3LzBnAx8kU717+Fg=="
Received: by 2002:a05:6512:3d0c:b0:59b:6a98:7132 with SMTP id
 2adb3069b0e04-59b6a987290ls1135279e87.2.-pod-prod-05-eu; Thu, 08 Jan 2026
 15:27:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW6Km/TLvFRdDrXvY744J6M0l4ZOd4Q4sr3S6nePFKqgvliCuITLJfclMbADwiIc+LZAYsEgX9UjME=@googlegroups.com
X-Received: by 2002:a05:6512:3d0c:b0:598:853e:d3d7 with SMTP id 2adb3069b0e04-59b6f265951mr2574553e87.52.1767914824840;
        Thu, 08 Jan 2026 15:27:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767914824; cv=none;
        d=google.com; s=arc-20240605;
        b=V0xNIha1rHu5ROXDrkhvnn9QcnVeBwEAGrd/MDXLS3TYCiSBBzL7qaHqvSVetTlpPe
         VLPvSqj2qDB4OWKTOTRV+rGxyjA4IiZVQ5nXAvPSQT6hyPu1/kxuSTZqkogCDHZnK0Ta
         yRdqhQRLHwrYVwygUhuxOVbJ+D5A29gqUBI3WnOJ47SajYh/QgOfLTA2ucsnlLSXLUtc
         JvdVelBt1r/QEU8cjqUwiDvUUKvZVRz9nA08rTr6670WUbrcoZrw6XTO1b8+Eews8roL
         dVg7E9NV/39LN5j/TfUXQUP8+nLE6V6uUwma/litj+6sphIrBSzq81uLuqfljXJ2vzqO
         VKLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VJVnWCv1er1yEKW3Zzjqu5S3R8api15dEl8a9iGdG3k=;
        fh=7tI4wH+/ojjnL7hUG37E5CQ0Jw9PkcbQwHGBJVaY+v0=;
        b=FlxVhTkxpHpJb35NpUMsj7biwMptjWp2+dCFt5WV+VYIUDT/mYiiOv08uNY1JQMW7E
         m1p8uxF0CCwvS6TwoFyyTwuqu5nBrGvGcEFMUtIReaXvxHMsSD5pQmrty3Di38KH/41K
         uEt0zOZ6mIsQ4KVMUSm9JiQtoDkZ7zh+VoDwwI6poUrwTM01aJ88Kb0Y+EA7xCATL0j9
         yXFDX8h55eyUar2ocAG6dA9PtZAPFhfKuOaZZq6KocjjdsUIRXZFL7NVYFF1jxbz+nq5
         K4Z3zzsDrhjYwpq/Zp9FBJh3j0AvJ+youe+X0hULFU5f9P2C9Be1z4D6pQB42wYmhvAk
         UVYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yLYR6qfg;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b67e6dff9si165947e87.3.2026.01.08.15.27.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Jan 2026 15:27:04 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id 5b1f17b1804b1-477632b0621so23047755e9.2
        for <kasan-dev@googlegroups.com>; Thu, 08 Jan 2026 15:27:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUnmxIyxu71g54VDyJ6QsGdX2qnS3BfHl1ioKuAoQ7rE7XbgDjAIH0++XKkyUoxnnvUBn9ZoFDCNaA=@googlegroups.com
X-Gm-Gg: AY/fxX6Vm8CDeIYkZYf1GUHcRk5W0OkYTN1NRBCwVfyKSrDfEvxXQqzJjNRofTG+io1
	6tlIFbzV0J3p2xJqMFYRuh8HDPoFFbhMq+cFW1Zfbpgj3xFxvBOvbpgDt8f2qEnPFqJiqb7EsWI
	6aRbh46f+bQ4mIxEv83zpbE03V1JTvzale1HMvSnUGu1gf0P0pMaWND1RO4t0Hlt4iQcfRL6pRc
	6nab0biTA6ypWjqoEWJjhPCKC4VQocUWFyd2Z/Lt7T+AbKqk/F88UEByRAmZ/TPiFFAzvmwwuJs
	pElj7ywUcPhsen2l9TaJDSLOdYz2Y0RwVVr1Wmz8IoXyk0nTwpb3hy0IGH56F6zpawCJukL4xLU
	9y7L/gjY7L6qmZJjuQHZC+MlWdukUdc6sGX7msJ6vhb2SEIhNZmvIs5BlQJVtIydMFU6cNd7V1c
	tGEqCqJG3HUizf/QQRPwiFYjfIdW94fJALvx1Ylt2qvZO8ct8Y
X-Received: by 2002:a05:600c:4ed4:b0:471:14f5:126f with SMTP id 5b1f17b1804b1-47d84b41181mr100523185e9.33.1767914823835;
        Thu, 08 Jan 2026 15:27:03 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:384b:578b:5b8e:a6f3])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-47d871a1e11sm46386595e9.19.2026.01.08.15.27.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Jan 2026 15:27:03 -0800 (PST)
Date: Fri, 9 Jan 2026 00:26:55 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bart Van Assche <bvanassche@acm.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v5 10/36] locking/mutex: Support Clang's context analysis
Message-ID: <aWA9P3_oI7JFTdkC@elver.google.com>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-11-elver@google.com>
 <57062131-e79e-42c2-aa0b-8f931cb8cac2@acm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <57062131-e79e-42c2-aa0b-8f931cb8cac2@acm.org>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yLYR6qfg;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, Jan 08, 2026 at 02:10PM -0800, 'Bart Van Assche' via kasan-dev wrote:
> On 12/19/25 8:39 AM, Marco Elver wrote:
> > diff --git a/include/linux/mutex.h b/include/linux/mutex.h
> > index bf535f0118bb..89977c215cbd 100644
> > --- a/include/linux/mutex.h
> > +++ b/include/linux/mutex.h
> > @@ -62,6 +62,7 @@ do {									\
> >   	static struct lock_class_key __key;				\
> >   									\
> >   	__mutex_init((mutex), #mutex, &__key);				\
> > +	__assume_ctx_lock(mutex);					\
> >   } while (0)
> 
> The above type of change probably will have to be reverted. If I enable
> context analysis for the entire kernel tree, drivers/base/devcoredump.c
> doesn't build. The following error is reported:
> 
> drivers/base/devcoredump.c:406:2: error: acquiring mutex '_res->mutex' that
> is already held [-Werror,-Wthread-safety-analysis]
>   406 |         mutex_lock(&devcd->mutex);
>       |         ^
> 
> dev_coredumpm_timeout() calls mutex_init() and mutex_lock() from the same
> function. The above type of change breaks compilation of all code
> that initializes and locks a synchronization object from the same
> function. My understanding of dev_coredumpm_timeout() is that there is a
> good reason for calling both mutex_init() and mutex_lock() from that
> function. Possible solutions are disabling context analysis for that
> function or removing __assume_ctx_lock() again from mutex_init(). Does
> anyone want to share their opinion about this?

Probably the most idiomatic option is to just factor out construction.
Clearly separating complex object construction from use also helps
readability regardless, esp. where concurrency is involved. We could
document such advice somewhere.

For the above case, this seems cleanest and also clearer to me:

diff --git a/drivers/base/devcoredump.c b/drivers/base/devcoredump.c
index 55bdc7f5e59d..56ac8aa41608 100644
--- a/drivers/base/devcoredump.c
+++ b/drivers/base/devcoredump.c
@@ -339,6 +339,40 @@ void dev_coredump_put(struct device *dev)
 }
 EXPORT_SYMBOL_GPL(dev_coredump_put);
 
+static struct devcd_entry *
+dev_coredumpm_init(struct device *dev, struct module *owner, void *data,
+		   size_t datalen, gfp_t gfp,
+		   ssize_t (*read)(char *buffer, loff_t offset, size_t count,
+				   void *data, size_t datalen),
+		   void (*free)(void *data))
+{
+	static atomic_t devcd_count = ATOMIC_INIT(0);
+	struct devcd_entry *devcd;
+
+	devcd = kzalloc(sizeof(*devcd), gfp);
+	if (!devcd)
+		return NULL;
+
+	devcd->owner = owner;
+	devcd->data = data;
+	devcd->datalen = datalen;
+	devcd->read = read;
+	devcd->free = free;
+	devcd->failing_dev = get_device(dev);
+	devcd->deleted = false;
+
+	mutex_init(&devcd->mutex);
+	device_initialize(&devcd->devcd_dev);
+
+	dev_set_name(&devcd->devcd_dev, "devcd%d",
+		     atomic_inc_return(&devcd_count));
+	devcd->devcd_dev.class = &devcd_class;
+
+	dev_set_uevent_suppress(&devcd->devcd_dev, true);
+
+	return devcd;
+}
+
 /**
  * dev_coredumpm_timeout - create device coredump with read/free methods with a
  * custom timeout.
@@ -364,7 +398,6 @@ void dev_coredumpm_timeout(struct device *dev, struct module *owner,
 			   void (*free)(void *data),
 			   unsigned long timeout)
 {
-	static atomic_t devcd_count = ATOMIC_INIT(0);
 	struct devcd_entry *devcd;
 	struct device *existing;
 
@@ -381,27 +414,10 @@ void dev_coredumpm_timeout(struct device *dev, struct module *owner,
 	if (!try_module_get(owner))
 		goto free;
 
-	devcd = kzalloc(sizeof(*devcd), gfp);
+	devcd = dev_coredumpm_init(dev, owner, data, datalen, gfp, read, free);
 	if (!devcd)
 		goto put_module;
 
-	devcd->owner = owner;
-	devcd->data = data;
-	devcd->datalen = datalen;
-	devcd->read = read;
-	devcd->free = free;
-	devcd->failing_dev = get_device(dev);
-	devcd->deleted = false;
-
-	mutex_init(&devcd->mutex);
-	device_initialize(&devcd->devcd_dev);
-
-	dev_set_name(&devcd->devcd_dev, "devcd%d",
-		     atomic_inc_return(&devcd_count));
-	devcd->devcd_dev.class = &devcd_class;
-
-	dev_set_uevent_suppress(&devcd->devcd_dev, true);
-
 	/* devcd->mutex prevents devcd_del() completing until init finishes */
 	mutex_lock(&devcd->mutex);
 	devcd->init_completed = false;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWA9P3_oI7JFTdkC%40elver.google.com.
