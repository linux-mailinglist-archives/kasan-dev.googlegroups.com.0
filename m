Return-Path: <kasan-dev+bncBDGIV3UHVAGBB2UXZGEAMGQEILAXKYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id ECD4F3E576E
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 11:50:34 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id c2-20020a7bc8420000b0290238db573ab7sf842832wml.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 02:50:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628589034; cv=pass;
        d=google.com; s=arc-20160816;
        b=v2Kbz1WOaWxWWPRzejKqZt3qEZ8Arlg2HndZaOMXFcYdP6SQr5WM+yQ0/MHSZF2WGE
         RoxBFSLP41oVw9b4Zd4MIJGfigr7Ebw61o0YMCNglvIbuweAaVJXXjetlAuQPNjxYCxv
         jJjGoXBNVw0QbtgQSlyfj0BMPhwmdc5+9Y40jult2zAfn3G+nmMsmKdKplbTJMt5+SVc
         u6xQM3h4k6Pl2vBpeG3Uf4CcRc2qL/NY5bZfFXI3UyyWpy/Ymx/NlpuswZYM0oZV3HYG
         +I1LAxi25lBdIT673SSQXyPXp7PkIPGJZE2h9K1Ie+S2pExSWuw3zvrAmHmD/NYJAXE/
         vl5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=yl8KaDEizbZCloaFrRGfEb5oNa0u7CcVLmmI+Mt7ma0=;
        b=IOTb+FdXd/HRZVsEK9JRgG8kh1r0OfPQbLVwOJ2HolGQGqlbznGU4JJB5vli9cwvJa
         iXtTW0pWHqUbl9XJk1axB7oLkxsc3WuyhbytLVLoHUZIXArab1kH+JlG+NiY0v4hOKtt
         45yH9B/kB5ClZQ6hEsIynFX1tnLsea4tPdtA3jOyr1OaayMtIjRZOCyQiDq7ZKJMOLh0
         ebCiHD880PiOIUP8HAj/K1FPoKhw0lfTHUmr1gcb3q22qt9gR1vnQG/xU7DyACi+8w75
         ntbvn6W13RfGYM+B+GVhfVQmWrNj4OgNJVYm469PFslE1cXYPkdvhRPIeVm/jpPBi8J3
         M7GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=L61skdOO;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yl8KaDEizbZCloaFrRGfEb5oNa0u7CcVLmmI+Mt7ma0=;
        b=MSWuEhflokOhs5/rCaCB0t34amvSgpGTDrIKsnhQQKLSCd1su3JqCckWlG+2zbTpwT
         e67an0J6v608yP04aGL8WPhylbvlmUyocAlJGWLJyU5Hnliaan7NmIFmYmF5MmQzHsP8
         3oLVRnkL4qmjsCWGRcQYW/KTABD2rVfMRvO8DPaQ4R/V5IIF9ltyleE2uakzG6MwX6oI
         eMbkJt2otJj6AyJm6fe1Z/IvKm2ojlW+v4zIx2xmGeuzCB7Fha+yVzyIN5wamRq0mTWO
         inRQHbI4UxT5IqJKuAPpTI/iDLedRwkeYKLS6vC/9yOAtg2u4RVZG5fo8W6gSahfuqkp
         /7iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yl8KaDEizbZCloaFrRGfEb5oNa0u7CcVLmmI+Mt7ma0=;
        b=ar6bzkDOngXztFVEoO0QXcYjQ3Zbnj/9rBxnnkQJrPSCj0LDvhdOCbl1lZ6EnaLZDK
         U/ObdnXUC/jDYGC3E1a28e8cs8kU8HXm6tz7gRQHWoYusm3M95btMZeX9WnNXuekrFBi
         n7dVi1+aY20f98WIapJzmNaMPwKHVM37TbkJ9vZ7h46YFuuMiUNlA6lqniw1/oFiRZuq
         L3nK5TNZe1EIggqeamYW0QzWtMMmlxLJ1mSVf2LcurRp5LYco14PQ5JTwe0Z8h98yrdp
         mq0p1PBHNDJg25W7VWRIh0Zcw/50+zzq8w1No7FxCQYUrteujdxZ3hLa7senxdNQZTWO
         xAxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/oLx0155oX5teMYZbXhXJRw4ikMeOyjFqpu/vsixq2IaIfM+J
	YfCdzd98d+FxWw1C2Knve60=
X-Google-Smtp-Source: ABdhPJxJxORsy0DIsVo03XqdkRxm1ZAdirTK8meIckikm6KC6q/5Eb0QjSIHXS2qMSQP2gWkEkKCFQ==
X-Received: by 2002:a5d:60c2:: with SMTP id x2mr30352706wrt.209.1628589034662;
        Tue, 10 Aug 2021 02:50:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6251:: with SMTP id m17ls2079833wrv.1.gmail; Tue, 10 Aug
 2021 02:50:33 -0700 (PDT)
X-Received: by 2002:adf:f7c5:: with SMTP id a5mr12018144wrq.355.1628589033835;
        Tue, 10 Aug 2021 02:50:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628589033; cv=none;
        d=google.com; s=arc-20160816;
        b=qoZxVgYTVdkMqWg+iGw5FAmxkm7EwF1MYrG454lTfTb72+6r6Xjf/uzkqYhOwxCzBF
         VOYz4mKU7WnwLw7ExDAPv4NGQr2bycW71JrTcuHTbrGuirQmZkL/2Io1q9spKrdCRdJx
         9Irj3cQNlt2koqVZqdlq8OCtN8TMbI7zJpituCbu/TN+GS4I7diresfzFcYDSBpdGhLz
         AyU9g+Kj6aur2bF9iOmw2A/AvstdvkAte41lZeNnLuWEzzRUQG8v20MZJHwL5RhyPwcD
         ojd6WaL4R2rgk15xaH5snx1DLVMpKSQTjrZyboOh/WvvVuaFlDLR55+qRsAZD3S7Z3HC
         4UdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=iPMDSiID6HyjOwNCoieXyRQuimu3kmDXsXQXePe21EA=;
        b=GLJcGT+Zhx7gQx2M4NOztIU7BNraeMSwXS05EgJA6aDIfSCa/7VX95cdmgecUtMkdR
         OBldF0Lr3E0MpGCQ+pds0yDFZSrpV08SpM4kruhbZYgTfzfj9/hRa0bkkeQquP4rDe0X
         5QjIuLhgxapxI7zF1T+O0a4h0bwXBwJoZENPkA6F01ariDL4xBPaQIe6BqFRpOUsj07w
         MbzZ6Mi2oe3vubxHCHTs2ZwLb3SGaJyTJsA6pecPh9jP4ilq5hvs266RHSoqBMX70lvf
         rCI2BAEl57iB3M7ylOpuKxAxQzibpQcUsGkCk31IkV6VUN2Fei16t8s4leIb2IVcavV1
         e1SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=L61skdOO;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id z70si147462wmc.0.2021.08.10.02.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Aug 2021 02:50:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Tue, 10 Aug 2021 11:50:32 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Clark Williams <williams@redhat.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH PREEMPT_RT] kcov:  fix locking splat from
 kcov_remote_start()
Message-ID: <20210810095032.epdhivjifjlmbhp5@linutronix.de>
References: <20210809155909.333073de@theseus.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210809155909.333073de@theseus.lan>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=L61skdOO;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2021-08-09 15:59:09 [-0500], Clark Williams wrote:
> Saw the following splat on 5.14-rc4-rt5 with:
=E2=80=A6
> Change kcov_remote_lock from regular spinlock_t to raw_spinlock_t so that
> we don't get "sleeping function called from invalid context" on PREEMPT_R=
T kernel.

I'm not entirely happy with that:
- kcov_remote_start() decouples spin_lock_irq() and does local_irq_save()
  + spin_lock() which shouldn't be done as per
      Documentation/locking/locktypes.rst
  I would prefer to see the local_irq_save() replaced by
  local_lock_irqsave() so we get a context on what is going on.

- kcov_remote_reset() has a kfree() with that irq-off lock acquired.

- kcov_remote_add() has a kmalloc() and is invoked with that irq-off
  lock acquired.

- kcov_remote_area_put() uses INIT_LIST_HEAD() for no reason (just
  happen to notice).

- kcov_remote_stop() does local_irq_save() + spin_lock(&kcov->lock);.
  This should also create a splat.

- With lock kcov_remote_lock acquired there is a possible
  hash_for_each_safe() and list_for_each() iteration. I don't know what
  the limits are here but with a raw_spinlock_t it will contribute to
  the maximal latency.=20

> Signed-off-by: Clark Williams <williams@redhat.com>

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210810095032.epdhivjifjlmbhp5%40linutronix.de.
