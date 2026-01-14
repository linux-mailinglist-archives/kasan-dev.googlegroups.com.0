Return-Path: <kasan-dev+bncBDTMJ55N44FBBAPJT3FQMGQE2YYO42Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F98AD1FB46
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 16:21:39 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-88233d526basf295066216d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 07:21:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768404097; cv=pass;
        d=google.com; s=arc-20240605;
        b=RtoIqx4bY7aPJmS0LO3JENdaBDd340WvkPbWVZs1MyzCbvXFegM12RMTHtBJBKvwVw
         gR0lxSIwPe3NjWv1CUdHTV5H/q8cGoIqFwCU3eqevnqbsLrB+kX734zCOdw2aYUkJAY0
         QlpoSbRsxO3/XRhe6/Z/U3aiUqY6nlQgfjOrhyT0jsy6ibxS4irFOxwep7DnJNX5/8zT
         UAVzaIrutAZUnNPRtxQNULJ5u8NWfcCvzt6qUNqjaUQAGgPgCJnYrtscCUiO4UYD4How
         5AKnlVZEOQ4fvM51IluhNv9JVFudFzboGTJ7a2XBsGc6uBCvhj6ISich0lkgrqguhZ6j
         s9Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vnUK89XaOhGf8ZrNQwFEPfzTfbzD9+eHx2EXfWOZrEw=;
        fh=RqkWKqjJxZbfzXMb53LQl3PpVfyzpKGi11w4eOPEbxM=;
        b=LUNmkKkZ6ME4C3IubNDNWd2I22Ju/q+PR7T0YZl/uqXNvyFHbt6NR3WYHQdAp8jREo
         lAZ77eaBJhqo19o0sT7//dJ+NRuq2NCkt3MNwszc+ycgRmf8c2pAlgH8+edQc6Ab6Nm9
         WlFw1ILNsEQJYKDcKx/H6cjUT3qKwU20vBwN+k3wlXNt9hjvDMOzVmS2FxkEP7et3jit
         4ZX612e4DOn5PyRTJB9vZpZ8rH94yEkNSJHvrRsCS8mpHt6hIVAi5y/2OitNdMY95DTu
         9IsiD4t3LpsPdZWr4RtmrbDq8F6ke4HBa6itx23+n3qcxHCnCxarbddTN+ZGQjcvhIOK
         jG1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.167.177 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768404097; x=1769008897; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vnUK89XaOhGf8ZrNQwFEPfzTfbzD9+eHx2EXfWOZrEw=;
        b=XlyT+WlZX2K+fRMhMiBVaKfCJU4p/V6YbMBRYlPHxrBHVDvfid4+VfdLdQ/0A97M1l
         X2DIrreDX24UaVPTf5yQ7Vd56EYFpdXV3xKIhjDfdYSBtfgXTWX25v60NuzA0s8DplI8
         UQzI0x0naS8fHkmz2x+LQ4URQZmCvjqe+Kap2K9abcR9nr1ng4y4EdCSXGqFJpGMQrFq
         cCmJDoob3S++5GIV0iBcAGCa/P3EEGCyNwrCdwtLSlmlzbL1QYjYJzdlfYNT2pvTV0sv
         1iM5f82523iQX0MJ/6dAtK9PMiUrAE0bT5pjCEFuEUCy7TzKitE337sP5kDHfTbTPZ3D
         SWUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768404097; x=1769008897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vnUK89XaOhGf8ZrNQwFEPfzTfbzD9+eHx2EXfWOZrEw=;
        b=uinxQamPyRJstreXmE8D7evEdpbzYg6FDL0aZYuQVIRjknF5X60bNrDNUMLVCwOEyv
         wL/HrgeaRTy6z/ruCKOgy/7IC/agcystJk1VHh1iwJ/T5n693jrkyCr33vTKdbB8DgHK
         13bGfPf9GIs4gQQU3bQh4bCBJ+Zh0luUkBRoVQVwjSBOuVcIeG/l+StLG/BpLjP4UwoJ
         JWVs1WMjr4hCz+K713znZlEG97o53s0VCrRqt7UznYS7e0hhOUGwRzc8SV3t1N9h6h36
         24oFJjyAWQIDs+5NdNubTUo+W8ICvl6TU/x3HlhTxAaEDGyCfJF13U9rEIkwjBpya9/q
         /znQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLoNYMisnrnPpg/9zjB9D1GfsU8qIECUZbUNMZh6L5V9Aa2S6V8/B6jqaaFp7kagyYOK7CiA==@lfdr.de
X-Gm-Message-State: AOJu0YxfXYG/4Mnq92XjUHIsO1zHwZx8Px+vL64N5cf8LlAlMfDDNMr7
	6LagqVRia3S/Oea7sQ/VsON7YRlgkbexvzxM7StAigFwVDsdAnTdlQC8
X-Received: by 2002:ad4:5dea:0:b0:890:3f6a:fab2 with SMTP id 6a1803df08f44-8927447c985mr50860466d6.68.1768404097326;
        Wed, 14 Jan 2026 07:21:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GVBEp0veLwvor1GSl8SX0qP3q71uReXOO349kKyL0X2A=="
Received: by 2002:ad4:5d4c:0:b0:882:4764:faad with SMTP id 6a1803df08f44-89075550186ls173310526d6.0.-pod-prod-06-us;
 Wed, 14 Jan 2026 07:21:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWL9Dj5t0w88ArRt1mX4hCWk91DpWIwXtKW4S0fA51Olvpud/Tdd/voGOw/mXeTAUuPYT530NF7JCU=@googlegroups.com
X-Received: by 2002:a05:620a:1992:b0:8c5:359c:2821 with SMTP id af79cd13be357-8c5359c2aa1mr193949485a.42.1768404096002;
        Wed, 14 Jan 2026 07:21:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768404095; cv=none;
        d=google.com; s=arc-20240605;
        b=dQxeHiFAGxlVqE9zPxj8zYyhhpPBF6LNy18vJ9KY95XRMvcUXy1IrwBOkmcZ+AYQGy
         sq2z/9Fj+WFBztNI1mys7/Jya3T8vQRToPDAVqkTDm07TOZirND6q0P06aEkkvo+bU2F
         Hi6bWzlzGTm25qsZLXxNUB5gmwvf7hXCuMCwkFYGMq6QYp2JZyDTGcnwiL0KAi+DUIds
         HeWVwxwJ/kra6BJr06oEfFvPnkJ5wuG2ZBStkDobiATefxnD+BIXHQz6RMzI9tepfXOu
         z56pdtTXx9wClf9U3Gr+xG4kCCU6tkUHA+IUcOA4CQCKOeYe14t33T7BTY+k8AQwbEk0
         huog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=dI9Phsj/nSMNdFp89o7zHIAUGa2rQCyWo79deKjR47o=;
        fh=dd8XbymIRfREm/T4WmA5qfTTZ1fFzHhGmo/cpS9KmRM=;
        b=D7o+ZbdZhGHemv70eriNnNK0eigkoR0eAXWNmfXXTkoAUE7GgCrNyNjXj2QXig4bzF
         qhD4T0FTZtxZtgvYGz6+jouX+DpDsvP4A4OlgMlZK6Umq6EK9pVdL62siDDC8AvLXVBG
         BIie/KuJEqO4tpu2T3+L8QyLJJQdzsNW+JtAaC9CzzBq+VLGlDjsNRLbnTHFeZm05gMT
         lEltvJ1dOb5BbcAtouXwCDXCvCFEy//qXCBD0sT4OdnNsVPUou36krG6udxNFV0WKefY
         gVx9t/aPx5mN/65QY8ga31Hu6uc+snIG1YbXzRHDFZf5JvMnH9ODHX1kH/brnKF7GeCe
         wNAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.167.177 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-oi1-f177.google.com (mail-oi1-f177.google.com. [209.85.167.177])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-89082c9c701si7121156d6.3.2026.01.14.07.21.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jan 2026 07:21:35 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.167.177 as permitted sender) client-ip=209.85.167.177;
Received: by mail-oi1-f177.google.com with SMTP id 5614622812f47-45c7400259bso281520b6e.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Jan 2026 07:21:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW4nFbm7cblrySRvWdspMVFXyC/Ygh7mKEYIxw3tkkxz9Nedl560qGiCV9ITrt4jdhcyl88BFs27bs=@googlegroups.com
X-Gm-Gg: AY/fxX7ReqxT/qnWAf1XLz97BIZbd+DFolQTFNX6E0fAFuQzHfod7Srrv84dsg+PWq2
	umpVgxEcuSLGbS2uDxQQQ7uOcsx40O/VM1ZQkVj0R/Wxgnj1KGwUJhOH3isufvMMSwQHN3M9+Iw
	WLJCN6XnNmgmjWAH4gXD7j3oIJYEBa/k8762Sgnnw4n4Wr+oKGqwqCgZnjJCTIH7bMNmb3rmjeX
	URstoCMJjrWpQLJ3IAoy1p16FW0ottfI+qFtdKt138zA1zgjj6ZusbgYlWkIJqD+BsAdMwTcAoU
	/whNFplKtkG9RzdVm56FUpoq831zF+IBtMTiX6g1UAvLc2bUlRzjekwnfu7a1n2e0GjD78Qso8a
	KNrfEPkpiFmCwXVuoV/iPQCkNyppspIFvJgjdnt4kUaOJh8P5eiJrbvy7yV76v6lk4w1t2tF4Se
	mXrF0deUoIC8ti
X-Received: by 2002:a05:6808:528e:b0:45a:5584:9bf5 with SMTP id 5614622812f47-45c714331e3mr1702212b6e.4.1768404095351;
        Wed, 14 Jan 2026 07:21:35 -0800 (PST)
Received: from gmail.com ([2a03:2880:10ff:40::])
        by smtp.gmail.com with ESMTPSA id 5614622812f47-45a5e288bc7sm11600518b6e.12.2026.01.14.07.21.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jan 2026 07:21:34 -0800 (PST)
Date: Wed, 14 Jan 2026 07:21:33 -0800
From: Breno Leitao <leitao@debian.org>
To: Chris Mason <clm@meta.com>
Cc: Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kernel-team@meta.com, stable@vger.kernel.org
Subject: Re: [PATCH v2] mm/kfence: add reboot notifier to disable KFENCE on
 shutdown
Message-ID: <p7gi44yt26bpjbjkvuhd54tqp3vn7z6wq346gmvazg5t3kir4p@gdf64eax44rm>
References: <20251127-kfence-v2-1-daeccb5ef9aa@debian.org>
 <20260113140234.677117-1-clm@meta.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260113140234.677117-1-clm@meta.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.167.177 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

Hello Chris,

On Tue, Jan 13, 2026 at 06:02:27AM -0800, Chris Mason wrote:
> On Thu, 27 Nov 2025 06:51:54 -0800 Breno Leitao <leitao@debian.org> wrote:
> > @@ -820,6 +821,25 @@ static struct notifier_block kfence_check_canary_notifier = {
> >  static struct delayed_work kfence_timer;
> >
> >  #ifdef CONFIG_KFENCE_STATIC_KEYS
> > +static int kfence_reboot_callback(struct notifier_block *nb,
> > +				  unsigned long action, void *data)
> > +{
> > +	/*
> > +	 * Disable kfence to avoid static keys IPI synchronization during
> > +	 * late shutdown/kexec
> > +	 */
> > +	WRITE_ONCE(kfence_enabled, false);
> > +	/* Cancel any pending timer work */
> > +	cancel_delayed_work_sync(&kfence_timer);
>                    ^^^^^^^^^^^^^^^
> 
> Can cancel_delayed_work_sync() deadlock here?
> 
> If toggle_allocation_gate() is currently executing and blocked inside
> wait_event_idle() (waiting for kfence_allocation_gate > 0), then
> cancel_delayed_work_sync() will block forever waiting for the work to
> complete.
> 
> The wait_event_idle() condition depends only on allocations occurring
> to increment kfence_allocation_gate - setting kfence_enabled to false
> does not wake up this wait. During shutdown when allocations may have
> stopped, the work item could remain blocked indefinitely, causing the
> reboot notifier to hang.
> 
> The call chain is:
>   kfence_reboot_callback()
>     -> cancel_delayed_work_sync(&kfence_timer)
>        -> __flush_work()
>           -> wait_for_completion(&barr.done)
>              // waits forever because...
> 
>   toggle_allocation_gate() [currently running]
>     -> wait_event_idle(allocation_wait, kfence_allocation_gate > 0)
>        // never wakes up if no allocations happen

This is spot on, I think this is a real case if the following happen:


1) toggle_allocation_gate() passed beyond kfence_enabled and is waiting
   for kfence_allocation_gate to be > 0.
   a) kfence_allocation_gate is increased on allocation time

2) There is no more kernel allocation, thus, kfence_allocation_gate is
   not incremented

3) cancel_delayed_work_sync() is for kfence_allocation_gate > 0, but
   given there is no more allocation, this will never happen.

> Would it be safer to use cancel_delayed_work() (non-sync) here.

In this case toggle_allocation_gate() task will continue to be idle,
waiting for to be kfence_allocation_gate > 0 forever, but it will not
block the notifiers, unless we wake them up.

Is this a problem?

Maybe a more robust solution would include:

1) s/cancel_delayed_work_sync()/cancel_delayed_work().
  - This would unblock the notifier

or/and some of the followings

2) Return from wait_event_idle() if kfence_enabled got disabled.
  - Remove the waiters once kfence got disabled
  - Cons: kfence_allocation_gate will continue to be negative

3) Wake up everyone in the allocation_wait() list
  - This might not be necessary if we got 2, since they will wake
    themselves once kfence_enabled got to 0
  - Cons: kfence_allocation_gate will continue to be negative

4) bump kfence_allocation_gate > 1 on the notifier
  - Avoid kfence allocation completely after it got disabled.
  - Cons: it is unclear if we I cant set kfence_allocation_gate = 1 from
    the notifier.


Thanks for the report, 
--breno

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/p7gi44yt26bpjbjkvuhd54tqp3vn7z6wq346gmvazg5t3kir4p%40gdf64eax44rm.
