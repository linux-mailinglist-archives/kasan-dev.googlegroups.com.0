Return-Path: <kasan-dev+bncBAABBRXEYHBQMGQEAZZHSJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 01909B0111A
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 04:09:12 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-7d40f335529sf467798985a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 19:09:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199750; cv=pass;
        d=google.com; s=arc-20240605;
        b=D/uhu+VE2UHr5HhvWxjqh2/TSLEfKVKaPYlJxKS3LkD9Tfl1uMyVblc6QX3CstJK4S
         hnZ968nJtrckbh+oHVufwSW3plNpYnO1diynz6pmpOckIqC5GKHRveqPlCI/aOiyGSwx
         emYVDvKoSjsrcK8EqlA47wCfCNIuOCgiJlhUsro0UHBGddaBrAiFVvP4giCLcsDD0E9r
         ikA0MVnBUBreI3RMVQhsSbipbQPBpe+OwyN/H/4427v6ep7MaL/wOGwVgeZlKhccRWcC
         /S8/atB4cUslkIyNNZdOGP4QdD2em4z5V6NQb9jnvWbbmhm41yn77xEDGS+6CXoX2VPK
         9LPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=SUSW4TlyybOjHs/AYHWsGKhVqEt7Yn+AMkO+E2Myjs8=;
        fh=T1RttgqWASELEcdIuo1I3OMO+dboB9khbSmQ75l6Iso=;
        b=eNthG2UtgjnzMeYprkbJPPEEPVIOODUQMJwqRZ2M7rpNILl002s2zay7b92+HI7Nh2
         cnVqm7gAIgvFmcHm/0VkfIzQUAbf/665sKMvbZXqtj8S2C9B7ZkroPu4NCcVhd3056dD
         wlxklA3wKLh7+se7j5GMc9feh3mzsqfA7Q5aeC4uXFpcUtpfCX8QlTjTAjz43pBA1pQn
         hNCtmKGCGuJ7CoCR/PNJIdfxaFZwTI3209s9Lb8z4annD+371Z523+PuL6uPAuiAIMNO
         hoYd+VZyOkhIrjFtm5dJfD7UaHcystX7znarbc/uHW8CZY0FVewfKC61jVDBthB8u8n6
         Ei6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) smtp.mailfrom=byungchul@sk.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199750; x=1752804550; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SUSW4TlyybOjHs/AYHWsGKhVqEt7Yn+AMkO+E2Myjs8=;
        b=bP32Xi9DlXfH1LQF6aQ53KjAp5w1Ai+q+OtGEq8iK3VnIPB8WweZVNNvIT4YNZx2JM
         rBwJUW+soNXccMBuxT4pPSBNG3TlODZefK+P+gFd8jgPZ3B4dJcD9vqbBn3olXNcXwxA
         dYI14+8Q66qp5exeWMQun2MUGYEv4WCg5PtOEWdDVAyegpzbzqnLdDr5mmfQV0c0KxYF
         /C6T1ed+VRoEW8OyFfoX6VfM9UauZn8aEJoPOLuxy7C0Jru89Fe8i4lWg5gxUENqupfG
         IQw2v4B4usc7bWGjEe8ejPD4GQSqQDI6QRQo9FR+pRS/ERa1UC3ZfBzKEdac7VFh6GAS
         XOig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199750; x=1752804550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SUSW4TlyybOjHs/AYHWsGKhVqEt7Yn+AMkO+E2Myjs8=;
        b=c8/7VgyTykQpiu5Yl7hXA25G7KEtVg2WYscLR32jet8DAOcut0MFVp8uHLPIrhY3F1
         1Oo1VPJHLwxwlb59mgH9u9SsLrc6zg53pWj2uvAYMc8v2JRMGCESX3hy7MtXkZq/czgM
         5cZOdLk/fQXMbtwH6aC4B1Q7dJRgWW2MwvdL8DuoBTzczP/QBAFfNitbZCCtv8QPbH+O
         W1hFr9mDWx1YUh5sRLKxPkh4UfGVerCIP0wdraT1C5ppmAofd97wYrcJfSX+N7wpvBV3
         L3nsDX0WYJqKiAh84HlJX9BDD5K+mxNTr8VA9s687qh5cvtyOKLx2YGITZOY/sG5SqAX
         9VFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbrKS2yCA6kEG4wLVYT3KoORoxIb0GRsGoaETJhfFGDDxeWvGYIUGG2Er8jm0pY35O+Vp4Pg==@lfdr.de
X-Gm-Message-State: AOJu0Yy7VpsrrHJ9ytBZEdkEIE7YMJ4dgvvnRaJEqKcJuOAXd2Jwfqhe
	N+m1D0e1yR7WR4QnhkVGU3S+1qHgEwJzyihUWn3z/wupOGvSq56tD3tp
X-Google-Smtp-Source: AGHT+IGyW7VU1PXWIAFyS1VcRb4DMiR+DpF28sLLKsRIbdnQbft0MchuAy5sdCKC8nueL8+OOaFHmA==
X-Received: by 2002:a05:620a:2912:b0:7d5:d182:af44 with SMTP id af79cd13be357-7dc992eeef1mr927966785a.17.1752199750547;
        Thu, 10 Jul 2025 19:09:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfVh0smkxli/RWnvEHeLHweFqsLT9nEtt1l2MW9rO6CQQ==
Received: by 2002:a05:6214:921:b0:704:a8c3:e6e4 with SMTP id
 6a1803df08f44-704a8c3ecc6ls229136d6.1.-pod-prod-00-us-canary; Thu, 10 Jul
 2025 19:09:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2P9dYfMjujpapDVp33HNFNBwByPRWUlswnlNyaxtVi27NSozL86mKlqsjrjWJ8lhiDN+rawx/bNE=@googlegroups.com
X-Received: by 2002:a05:6122:800d:20b0:535:ae4c:8023 with SMTP id 71dfb90a1353d-535e40badc3mr3215424e0c.7.1752199749668;
        Thu, 10 Jul 2025 19:09:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199749; cv=none;
        d=google.com; s=arc-20240605;
        b=S+1AzLcJ+4a05Nz7wZSAPV0hXC2j1hCV843O8exLieNAQi3ZzAut5Y5a6ammmmPak2
         rm9jcE4jbAR1NYnDcw/aDEV2nIoIPrZPR9yXCtq3H/P1+rq4x5ypfxYCmN07qN6zsAMl
         rJ00dI67lem77kTWFiGVZP0olaQd3NmIgI4QAUMEkNx78bci+gN5+dhYGQRIXS6zua/s
         3ck9deqnvOiDGmZbgt1BdlNdK4eMABkS9SzvD9+VfGZAvukFPOhRkvw1l1oPXJQjs0zB
         5uTyxcm2N/kVudFAprA3Lf+OSRcVEVzxmhVeiHZug0PqtDm55xR0KbrpTtFHvBc6ZoJP
         CAVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=wTWr4mJ32ozYRri87Db5vvO+OyrXMsszsr5+EFL2t0g=;
        fh=UbV6yiLW7GyO9E7pnXMyfVYw3hT2aRfAZh/vGGa2El4=;
        b=SQQKOGGoK8v0jlsC/DtP7lqBrOoGFb9zXYT4gmYNxap1Fs7uI4L5gioOHhLFlqEtKX
         sFAfw/Z3KBWlK/fIXlLgPnPAFmOOs/HfUpqTKXrMP2WG8gJxaMpo8LnRfBMyUjEhHLTO
         K5cIa+OryPHDXZy2t+aUQyoeiGOZ+QXOqIUa/uDQjm2FJL7BBTdgwQ14NZJc8G01LOth
         AbNLWWyWfIWNaPX5keiRH1TbSLY3rFR6FHHuTFtAwTwHuUiWgwVjYiE6wGy8EmzfxU0k
         DIJDsAMWAw70oHUcq4sUiDkG8xgBOZqUJmN0UvXxWbc22dg2qgpZSNGoLjwP4BRkmBKh
         kR/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) smtp.mailfrom=byungchul@sk.com
Received: from invmail4.hynix.com (exvmail4.hynix.com. [166.125.252.92])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-535e7086212si125945e0c.0.2025.07.10.19.09.07
        for <kasan-dev@googlegroups.com>;
        Thu, 10 Jul 2025 19:09:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) client-ip=166.125.252.92;
X-AuditID: a67dfc5b-669ff7000002311f-28-6870723f8102
Date: Fri, 11 Jul 2025 11:08:58 +0900
From: Byungchul Park <byungchul@sk.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Yeoreum Yun <yeoreum.yun@arm.com>, akpm@linux-foundation.org,
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	bigeasy@linutronix.de, clrkwllms@kernel.org, rostedt@goodmis.org,
	max.byungchul.park@gmail.com, ysk@kzalloc.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	kernel_team@skhynix.com
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Message-ID: <20250711020858.GA78977@system.software.com>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFtrJIsWRmVeSWpSXmKPExsXC9ZZnoa59UUGGwex1IhZz1q9hs/g+cTq7
	xbSLk5gtlj35x2Qx4WEbu0X7x73MFiue3WeyuLxrDpvFvTX/WS0urb7AYnFhYi+rxb6OB0wW
	e//9ZLGY+8XQ4svqVWwO/B5r5q1h9Ng56y67R8u+W+weCzaVeuyZeJLNY9OqTiDxaRK7x8Lf
	L5g93p07x+5xYsZvFo8Xm2cyenzeJBfAE8Vlk5Kak1mWWqRvl8CVcb9hIWPBV8GKi02bWRsY
	d/J0MXJySAiYSJx4e4YFxv7eeRfMZhFQlXh94Dg7iM0moC5x48ZPZhBbREBbYsKNX0A1XBzM
	Am3MEn8232UFSQgLREo0b7vGBGLzClhIfFswGaxISKCBUWL+m14WiISgxMmZT8BsZqCpf+Zd
	AprKAWRLSyz/xwERlpdo3jobbBmnQKBE+7Z/YLaogLLEgW3HmUBmSgisYpe4u3wOO8TVkhIH
	V9xgmcAoOAvJillIVsxCWDELyYoFjCyrGIUy88pyEzNzTPQyKvMyK/SS83M3MQIjdFntn+gd
	jJ8uBB9iFOBgVOLhdVidnyHEmlhWXJl7iFGCg1lJhHedb0GGEG9KYmVValF+fFFpTmrxIUZp
	DhYlcV6jb+UpQgLpiSWp2ampBalFMFkmDk6pBka3E29YplfUyb5eGuf+8Mmavt1Ct10TdvX4
	SdeIFi8X62bovjZl9nWNUxpxd4IuFLzRWqn/eZJjxvobVgIbtf8J7fj//K+szN48hogXhnfb
	Xfjbvkhv/qfIWL9XdofBvUVcDzd1ld+uiBLqd8p9o/r0Z8G8H/ebawp2zbjgFbDa5rD/WrXs
	/QeUWIozEg21mIuKEwEDMfAizAIAAA==
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFlrAIsWRmVeSWpSXmKPExsXC5WfdrGtfVJBhcGEqi8Wc9WvYLL5PnM5u
	Me3iJGaLZU/+MVlMeNjGbtH+cS+zxYpn95ksDs89yWpxedccNot7a/6zWlxafYHF4sLEXlaL
	fR0PmCz2/vvJYjH3i6HFl9Wr2BwEPNbMW8PosXPWXXaPln232D0WbCr12DPxJJvHplWdQOLT
	JHaPhb9fMHu8O3eO3ePEjN8sHi82z2T0WPziA5PH501yAbxRXDYpqTmZZalF+nYJXBn3GxYy
	FnwVrLjYtJm1gXEnTxcjJ4eEgInE9867LCA2i4CqxOsDx9lBbDYBdYkbN34yg9giAtoSE278
	Aqrh4mAWaGOW+LP5LitIQlggUqJ52zUmEJtXwELi24LJYEVCAg2MEvPf9LJAJAQlTs58AmYz
	A039M+8S0FQOIFtaYvk/DoiwvETz1tlgyzgFAiXat/0Ds0UFlCUObDvONIGRbxaSSbOQTJqF
	MGkWkkkLGFlWMYpk5pXlJmbmmOoVZ2dU5mVW6CXn525iBMbbsto/E3cwfrnsfohRgINRiYfX
	YXV+hhBrYllxZe4hRgkOZiUR3nW+BRlCvCmJlVWpRfnxRaU5qcWHGKU5WJTEeb3CUxOEBNIT
	S1KzU1MLUotgskwcnFINjAkZwV9fGeso6bmLPPGKMfWun/37ye1FN13mnrl5jOui5qKFl0/V
	PP3N1ZaV+vipSbKxp/3dZ7f2fE77c+v3yWOXdi0IUlwzoSuvoJlpzYQcebbJb6/euCn/ZqvD
	ZIMvzhNuFG78Z188p+1gpeoOcYal3BrLL2y9oNNV+OC95gLP8xvn3OZ4kTpfiaU4I9FQi7mo
	OBEAuCK4YLMCAAA=
X-CFilter-Loop: Reflected
X-Original-Sender: byungchul@sk.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of byungchul@sk.com designates 166.125.252.92 as
 permitted sender) smtp.mailfrom=byungchul@sk.com
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

On Thu, Jul 10, 2025 at 02:43:15PM +0200, Andrey Konovalov wrote:
> On Thu, Jul 3, 2025 at 8:10=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> =
wrote:
> >
> > find_vm_area() couldn't be called in atomic_context.
> > If find_vm_area() is called to reports vm area information,
> > kasan can trigger deadlock like:
> >
> > CPU0                                CPU1
> > vmalloc();
> >  alloc_vmap_area();
> >   spin_lock(&vn->busy.lock)
> >                                     spin_lock_bh(&some_lock);
> >    <interrupt occurs>
> >    <in softirq>
> >    spin_lock(&some_lock);
> >                                     <access invalid address>
> >                                     kasan_report();
> >                                      print_report();
> >                                       print_address_description();
> >                                        kasan_find_vm_area();
> >                                         find_vm_area();
> >                                          spin_lock(&vn->busy.lock) // d=
eadlock!
> >
> > To prevent possible deadlock while kasan reports, remove kasan_find_vm_=
area().
> >
> > Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> > Reported-by: Yunseong Kim <ysk@kzalloc.com>
> > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
>=20
> As a fix:
>=20
> Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
>=20
> But it would be great to figure out a way to eventually restore this
> functionality; I'll file a bug for this once this patch lands. The
> virtual mapping info helps with real issues: e.g. just recently it
> helped me to quickly see the issue that caused a false-positive report

I checked the critical section by &vn->busy.lock in find_vm_area().  The
time complextity looks O(log N).  I don't think an irq disabled section
of O(log N) is harmful.  I still think using
spin_lock_irqsave(&vn->busy.lock) can resolve this issue with no worry
of significant irq delay.  Am I missing something?

If it's unacceptable for some reasons, why don't we introduce kind of
try_find_vm_area() using trylock so as to go ahead only if there's no
lock contention?

	Byungchul

> [1].
>=20
> [1] https://lore.kernel.org/all/CA+fCnZfzHOFjVo43UZK8H6h3j=3DOHjfF13oFJvT=
0P-SM84Oc4qQ@mail.gmail.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250711020858.GA78977%40system.software.com.
