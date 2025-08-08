Return-Path: <kasan-dev+bncBCKLNNXAXYFBB36N3DCAMGQECL7RK5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EA3FB1ED0A
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 18:33:53 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-33237715ed2sf10951831fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 09:33:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754670832; cv=pass;
        d=google.com; s=arc-20240605;
        b=UFLZxj3Xd1qonFoefi65wOodkaSAz9xGq5/JztYg+XyMo9oHv/iFI9R4cSbdwCW7cs
         cGPMcwTtN5/E5wm6sBWKDx2gBMlw2Uqi2KdeB20GMMkItDZSs0E4lK1r3JMDHnGE6LM3
         1PDpZRU8E7M4f/xXfPiQEodq5i1G09/BlMuglFeGeDPkec443WbgzsdKvx839/HntCb3
         kL77iyJGAmhg3sjcHG8ha9As5bU6KXvoIHOgJhpVLEDhOIBPk2RZM93BwfzBOJBj/Ujb
         2lHfIYmSQq2kVDc2KCTU8MPubdmquX+oVZbmgTTfFkU06LpgUVhCtxkv6875k238VzDD
         tOqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2U0ojCEkSrHMvORR+OlbwPuZNStpfFV1QqMDRlwrSGI=;
        fh=Xotm2MH3eygvp1zJIkHW1KHALJEQjM+DNMzz0PeE7ts=;
        b=jv/rMpJtbrRXnec7LZdOlojqHwFd5rdnBzJLjBIibOrvKcrdBxkxtLaLFnLqA/WplS
         dVnOTPrfWAadvxZlkNpv0zz247nzWnpFDn1moVe4XAv/J6wwQ6ru0uf33vnQ03/kxYOi
         s2WKnEVDR/+qbJ9g+5mKFHxyRsNgud/IuqrPZNRt85qxWModlFkx1mcL8GtAk5/FbZwX
         wt5/GpqxPYxLtb7mdJQNse7+YJLaxZKIn8Jq8A3UljgKwTBJaZoqBLtUPMRUSmCff0od
         OiWQ99FR+O1YlUp6eLmgQqDb43V94vhfRA3HmtaXHjIZ8N0A3tERDnI8yyYQqVtEq1W3
         VdMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="RVeye/4p";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754670832; x=1755275632; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2U0ojCEkSrHMvORR+OlbwPuZNStpfFV1QqMDRlwrSGI=;
        b=C/6lGRoJjG2DX7weN2pQHRHPtYChsIAoxAkZplziF5Sf5J3YUcPb69GkahC3qrmb1/
         Xfn5sfVnQ0eYcpYNl01Ult0YHaOaumNIslovwT5asbkYdHHfp+HCVIK3dtRtOgFvS+wz
         PBujoX9FmOtcCTjNXl0ICN/dS0kFbyQ4sPVzr9KfyLfY8YYbM8wm+1BJIWCcDfkXl1yW
         3Y2gZowTRVuh52UntMrzZyV3BVuCgZlqbf82guInrAIJZridp+SDRz35aYP4CN5fPdFG
         QHwbvmQ9SbmvGzXekE7aOQrapSfrr7hR1kWybNbj8DlgdfIOMdVbhO1/WkNsIuicK2Te
         1I/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754670832; x=1755275632;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2U0ojCEkSrHMvORR+OlbwPuZNStpfFV1QqMDRlwrSGI=;
        b=jl+YVczHhPIsqd7oKXgI+OfNdPYO8TpxNu8HW8J4rwCiJVVhSIjXIZLCvachLs4GU0
         Dvg4/pCYaTiIb0uobpC1LVQHiJl0Nlvo/FQKfqcaCPhg8SN80UP2PQ7SKzfn2wxoMYL2
         t+oTREtaMya5TZ7EseSK1EvNrwLkBb9OK/lGxBQ7gv2oIch5ezOL5CeiJw4pPmr3vAHF
         eMFWSWVRgialfotLl3SMAbA/mNBn4cntq9Da8AUMVoOSOlHrYcgjTECp31AWHoayzxcF
         8oQuJaad+domhM1D7fjHVDwB6sr5N1ijQBgeIcDsb/CnrczQEwV8w9sI/0DsvT7wWZk/
         7t3g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXe3RuN/esXghpe9dSt/QrD6b5874tTu/wpgC+zc1o1a5fbzLo/7t4rISce1i5h/QeJ1GDLsg==@lfdr.de
X-Gm-Message-State: AOJu0YzaIF0yG22IlZvw4ez3Fy7rvq7r7OmqYP+/ng6SoXo1U7zQ5szm
	MmMIgPG1L+mU42q9KCyugK0FpCWEsTBnBF1QeZfgeuf2v9EWAChpt7fX
X-Google-Smtp-Source: AGHT+IHx+TVsUgZaCfVxf/uIxunhmaWAR/wSFL7G+2890/1Yz6YR4inL/ukIC/kwkk/j7xYhD9x1Vg==
X-Received: by 2002:a2e:b8c2:0:b0:332:4558:b30b with SMTP id 38308e7fff4ca-333a219f377mr10110261fa.18.1754670832017;
        Fri, 08 Aug 2025 09:33:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfjtlCP4IFm6AApJPiMCgJgRiOldKE9Ac9KRIO2cbzN7w==
Received: by 2002:a05:651c:4194:b0:332:347f:54ec with SMTP id
 38308e7fff4ca-3338c000864ls1864801fa.0.-pod-prod-06-eu; Fri, 08 Aug 2025
 09:33:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkltpPi4aJewB7ANVUdnw3BVldEmWV7QQPGkeyiXjh5qV56mG65btmCmEyjtinCBu5NYR7tyRYZDw=@googlegroups.com
X-Received: by 2002:a2e:a007:0:b0:32e:525:5141 with SMTP id 38308e7fff4ca-333a2191a95mr6275481fa.16.1754670828571;
        Fri, 08 Aug 2025 09:33:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754670828; cv=none;
        d=google.com; s=arc-20240605;
        b=fCRlmevZcWlzkoHsgQCjioL78rQJMHfbBq6VDxwK94pC4oGuGTxRwJWZmSJtZWHlRp
         brSeUdCM6FeLO7UnUtE/zxneO8KgD4pg7tB4EoFhsry0aS2i9TOJHBET5sIoG9lsBvkL
         Z8N8Ms917Hsguo/u7hepah4jluh16Rp83a/ZbL2w8aUNlR6vEwyjNE/9ishy9X7yh7nP
         Kl0ZZrT1/w6EsVoPkT2suPrhvXktpkbiPBT8Gf/gJEyFzFBsjpKFc+H3+0tbA2ADSZaK
         qqibn5SzGAeA2zE77LsHnOP2yazFVMMsMcFcTwvjk7CbSfZRjZ8PTmDYO30Z9bcJ2w3f
         tydg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=JfkgxAstW/grwEhYFrNwo+E5fvmu5YawBnjm5gjeKEk=;
        fh=4Gez1sporjsJnx/agbWCMAywaMidO2+Tws+izS2fdCI=;
        b=WpH0ry4x7SqP4xJYD/8kEA97AXNW9k02Os3YHNd8wLnnaYIDL5BvCafI2z59FrIi19
         e9P106tiGtXGER/21ITbp/i2u+xaD9biflko/9pWgusrdVziZMoDhE7FAJrpReddKCNY
         EOPFABDVGyOenEg2riumlWzmt1zGzXeR5y6CyMWyzhThwVLV9F0lzwYzJssO9PbMaUCI
         UOPn1YU+kflim/0mZpz8/+y6XxSadG1MkU9EMMS2EXFCZsC1XJBU/HJC6sRcWqIqlR4L
         Bv8uq8qRXpTJWEQNHGUp+IXnDLmMCXzY6/TLJWfuA4HjaV7TmF9SiocQEVu4MRQ5ejyV
         GeiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="RVeye/4p";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3327023d5b7si2986881fa.7.2025.08.08.09.33.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 09:33:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 8 Aug 2025 18:33:45 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Yunseong Kim <ysk@kzalloc.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Byungchul Park <byungchul@sk.com>, max.byungchul.park@gmail.com,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Michelle Jin <shjy180909@gmail.com>, linux-kernel@vger.kernel.org,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Alan Stern <stern@rowland.harvard.edu>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Thomas Gleixner <tglx@linutronix.de>, stable@vger.kernel.org,
	kasan-dev@googlegroups.com, syzkaller@googlegroups.com,
	linux-usb@vger.kernel.org, linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on
 PREEMPT_RT
Message-ID: <20250808163345.PPfA_T3F@linutronix.de>
References: <20250725201400.1078395-2-ysk@kzalloc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250725201400.1078395-2-ysk@kzalloc.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="RVeye/4p";       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
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

On 2025-07-25 20:14:01 [+0000], Yunseong Kim wrote:
> When fuzzing USB with syzkaller on a PREEMPT_RT enabled kernel, following
> bug is triggered in the ksoftirqd context.
>=20
=E2=80=A6
> This issue was introduced by commit
> f85d39dd7ed8 ("kcov, usb: disable interrupts in kcov_remote_start_usb_sof=
tirq").
>=20
> However, this creates a conflict on PREEMPT_RT kernels. The local_irq_sav=
e()
> call establishes an atomic context where sleeping is forbidden. Inside th=
is
> context, kcov_remote_start() is called, which on PREEMPT_RT uses sleeping
> locks (spinlock_t and local_lock_t are mapped to rt_mutex). This results =
in
> a sleeping function called from invalid context.
>=20
> On PREEMPT_RT, interrupt handlers are threaded, so the re-entrancy scenar=
io
> is already safely handled by the existing local_lock_t and the global
> kcov_remote_lock within kcov_remote_start(). Therefore, the outer
> local_irq_save() is not necessary.
>=20
> This preserves the intended re-entrancy protection for non-RT kernels whi=
le
> resolving the locking violation on PREEMPT_RT kernels.
>=20
> After making this modification and testing it, syzkaller fuzzing the
> PREEMPT_RT kernel is now running without stopping on latest announced
> Real-time Linux.

This looks oddly familiar because I removed the irq-disable bits while
adding local-locks.

Commit f85d39dd7ed8 looks wrong not that it shouldn't disable
interrupts. The statement in the added comment

| + * 2. Disables interrupts for the duration of the coverage collection se=
ction.
| + *    This allows avoiding nested remote coverage collection sections in=
 the
| + *    softirq context (a softirq might occur during the execution of a w=
ork in
| + *    the BH workqueue, which runs with in_serving_softirq() > 0).

is wrong. Softirqs are never nesting. While the BH workqueue is
running another softirq does not occur. The softirq is raised (again)
and will be handled _after_ BH workqueue is done. So this is already
serialised.

The issue is __usb_hcd_giveback_urb() always invokes
kcov_remote_start_usb_softirq(). __usb_hcd_giveback_urb() itself is
invoked from BH context (for the majority of HCDs) and from hardirq
context for the root-HUB. This gets us to the scenario that that we are
in the give-back path in softirq context and then invoke the function
once again in hardirq context.

I have no idea how kcov works but reverting the original commit and
avoiding the false nesting due to hardirq context should do the trick,
an untested patch follows.

This isn't any different than the tasklet handling that was used before
so I am not sure why it is now a problem.

Could someone maybe test this?

--- a/drivers/usb/core/hcd.c
+++ b/drivers/usb/core/hcd.c
@@ -1636,7 +1636,6 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	struct usb_hcd *hcd =3D bus_to_hcd(urb->dev->bus);
 	struct usb_anchor *anchor =3D urb->anchor;
 	int status =3D urb->unlinked;
-	unsigned long flags;
=20
 	urb->hcpriv =3D NULL;
 	if (unlikely((urb->transfer_flags & URB_SHORT_NOT_OK) &&
@@ -1654,14 +1653,13 @@ static void __usb_hcd_giveback_urb(struct urb *urb)
 	/* pass ownership to the completion handler */
 	urb->status =3D status;
 	/*
-	 * Only collect coverage in the softirq context and disable interrupts
-	 * to avoid scenarios with nested remote coverage collection sections
-	 * that KCOV does not support.
-	 * See the comment next to kcov_remote_start_usb_softirq() for details.
+	 * This function can be called in task context inside another remote
+	 * coverage collection section, but kcov doesn't support that kind of
+	 * recursion yet. Only collect coverage in softirq context for now.
 	 */
-	flags =3D kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
+	kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum);
 	urb->complete(urb);
-	kcov_remote_stop_softirq(flags);
+	kcov_remote_stop_softirq();
=20
 	usb_anchor_resume_wakeups(anchor);
 	atomic_dec(&urb->use_count);
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 75a2fb8b16c32..0143358874b07 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -57,47 +57,21 @@ static inline void kcov_remote_start_usb(u64 id)
=20
 /*
  * The softirq flavor of kcov_remote_*() functions is introduced as a temp=
orary
- * workaround for KCOV's lack of nested remote coverage sections support.
- *
- * Adding support is tracked in https://bugzilla.kernel.org/show_bug.cgi?i=
d=3D210337.
- *
- * kcov_remote_start_usb_softirq():
- *
- * 1. Only collects coverage when called in the softirq context. This allo=
ws
- *    avoiding nested remote coverage collection sections in the task cont=
ext.
- *    For example, USB/IP calls usb_hcd_giveback_urb() in the task context
- *    within an existing remote coverage collection section. Thus, KCOV sh=
ould
- *    not attempt to start collecting coverage within the coverage collect=
ion
- *    section in __usb_hcd_giveback_urb() in this case.
- *
- * 2. Disables interrupts for the duration of the coverage collection sect=
ion.
- *    This allows avoiding nested remote coverage collection sections in t=
he
- *    softirq context (a softirq might occur during the execution of a wor=
k in
- *    the BH workqueue, which runs with in_serving_softirq() > 0).
- *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
- *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupted=
 in
- *    the middle of its remote coverage collection section, and the interr=
upt
- *    handler might invoke __usb_hcd_giveback_urb() again.
+ * work around for kcov's lack of nested remote coverage sections support =
in
+ * task context. Adding support for nested sections is tracked in:
+ * https://bugzilla.kernel.org/show_bug.cgi?id=3D210337
  */
=20
-static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
+static inline void kcov_remote_start_usb_softirq(u64 id)
 {
-	unsigned long flags =3D 0;
-
-	if (in_serving_softirq()) {
-		local_irq_save(flags);
+	if (in_serving_softirq() && !in_hardirq())
 		kcov_remote_start_usb(id);
-	}
-
-	return flags;
 }
=20
-static inline void kcov_remote_stop_softirq(unsigned long flags)
+static inline void kcov_remote_stop_softirq(void)
 {
-	if (in_serving_softirq()) {
+	if (in_serving_softirq() && !in_hardirq())
 		kcov_remote_stop();
-		local_irq_restore(flags);
-	}
 }
=20
 #ifdef CONFIG_64BIT
@@ -131,11 +105,8 @@ static inline u64 kcov_common_handle(void)
 }
 static inline void kcov_remote_start_common(u64 id) {}
 static inline void kcov_remote_start_usb(u64 id) {}
-static inline unsigned long kcov_remote_start_usb_softirq(u64 id)
-{
-	return 0;
-}
-static inline void kcov_remote_stop_softirq(unsigned long flags) {}
+static inline void kcov_remote_start_usb_softirq(u64 id) {}
+static inline void kcov_remote_stop_softirq(void) {}
=20
 #endif /* CONFIG_KCOV */
 #endif /* _LINUX_KCOV_H */
--=20
2.50.1

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250808163345.PPfA_T3F%40linutronix.de.
