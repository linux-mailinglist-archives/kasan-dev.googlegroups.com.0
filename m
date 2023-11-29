Return-Path: <kasan-dev+bncBD2INDP3VMPBBC6FT2VQMGQEGPBERDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id AAC657FE142
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 21:43:56 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4238a576bfesf3146501cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 12:43:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701290635; cv=pass;
        d=google.com; s=arc-20160816;
        b=IQzdsxCnyq4nV5Mf8Q5xw7dFxAykjYwjzFu+yHN49oX1IZWFARiY0DJAvlCoXMy4ET
         VvftARIvtKIKK9fKDOYjSYG4gJ/+NniA52VEe+ex7YASIB0bBWu9Ubamw9/KogI08x01
         u0n2nx2AG+NrnUcolWhLGjzS/FHqnXh9iGDXmbMoe964IIZvhYuK8u8thfAyQdx0/Rut
         qLktW1mtxoRnhk0tEGirCQORA4GnbFsp+Sq86aGr5LVis0CmRNL/xlyBsnBIeJp3yA30
         yCOUvEI6cXXttSPEpNA7DpDLaRZw/wOnnR6gwGdMtdJ4/RamINM0hNc219+9lqCYNUW+
         8xdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date
         :user-agent:from:references:in-reply-to:mime-version:sender
         :dkim-signature;
        bh=AXiL9hFeCTFUKIRcfTFyTRCUYMLphgSLGo60DzKo01k=;
        fh=mNh2dTT9hNlTAwR4JHScUJJPxlkXeBvbZ1V6FxZnDSc=;
        b=ftygLgncsNDYga3tGqq4HIwLu+kEYtvKLmP560QPvFFvT8pTcxu9RYtGk/oCw7IX3V
         +dBBYKcSmYukl5EwCXAbSOgXcO+z8uF0FTVvKuKkeGDO9mbnU6uC53kHq9E2ajuIrxpP
         SfayhkDWacf7/2S0nAMb+YwE1P6HKD8kByR/xExy1AOyIlPZ4/MBFtBHXwaGTf19SF8z
         rqsc2b+STVzF63lfce1OX61YIwbsgUBW9+i3xCKiuQSHeKUk5WsGWlx3jAwR3Au1VaN5
         enwbb0An5GVEw4Aen1ctjOFP6r+WQCL+XGaEU1c+rNuN/WummPswZua5/8UziTg4BuDt
         Lh7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=WEhMfW0p;
       spf=pass (google.com: domain of swboyd@chromium.org designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=swboyd@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701290635; x=1701895435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:user-agent:from
         :references:in-reply-to:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AXiL9hFeCTFUKIRcfTFyTRCUYMLphgSLGo60DzKo01k=;
        b=Q0W5dQwsz/u61hS3+fsNV9U0xB0xfChC4wu3HCt4wAa91wkBtqWJc40e+IQ4/uBYhp
         aAl44+JL5RDo4YE/5Fn1rgtS/BIYwVV4h1E3j1wqeU3CtadQk2DKAgKLNlKcG8Wouyb5
         Zw5oI2a9cmECPprfGS7IbgdN1rTcdia3Ab11fkZyRi3gGYb7eie9w7YJ9u3rNuyewo2v
         Ys+yDKbAnVHO5bnQrWd4bxDqQIVXTWZpVE4c50og3UauW2xiAUWpQfAdzuaTOzBenMr9
         R65RbipKlwa+6LkbP0r6ox6R432qnVPzvshPnLBICglc4HRzduVAo2JgEVQmCmFMFj5K
         FDAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701290635; x=1701895435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:user-agent:from
         :references:in-reply-to:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AXiL9hFeCTFUKIRcfTFyTRCUYMLphgSLGo60DzKo01k=;
        b=RTLIhmiS+HfsWXiElFFQz41m7v8juO+5YabunNO0z3Izpxv4BM0Wehx3xgq78ICAdh
         Pi7XQ624kGTVT4cqqWBtptazbpLC19u51+sev2ho/Sr7EAQQO+Aav1dIoodzhKjRfM7o
         0iL8Kiz+82SQh0FflvlI2Q5FvvFpuzoviam/vpGZKxq0Z4r0UDIqZc20OnIxvJdIHU8e
         +EsKqIiLJPQx8XyxDUP4jM+83UN2pZPvqSDJYQtFTvPT1A5J9qHpe1I9oDoP4SDbi1ez
         rc2a1QzDCxcW9s9utVoDjam8+j39CILqFB5AZNEg356jRWOQeL462tAqrGPspFmO2p+I
         I37g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwSc72q+lYtlkTB4AfI2WA4TDevNCH3GbkpGSmW2EqeWieGKy4v
	sl5nQMoKtRpun5SFaNppWOs=
X-Google-Smtp-Source: AGHT+IFcQ4+DCLcfbkPbaYi6LPVKgS2s4Ly++Gb2fv28FAZ5bQk/vDSDxS4LnvsFIO4XGUEvFh/EYA==
X-Received: by 2002:a05:622a:1702:b0:41c:c3ad:922d with SMTP id h2-20020a05622a170200b0041cc3ad922dmr28612244qtk.52.1701290635326;
        Wed, 29 Nov 2023 12:43:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:181f:b0:423:a0d4:8c61 with SMTP id
 t31-20020a05622a181f00b00423a0d48c61ls252861qtc.2.-pod-prod-09-us; Wed, 29
 Nov 2023 12:43:55 -0800 (PST)
X-Received: by 2002:a37:ac10:0:b0:77d:9b92:5638 with SMTP id e16-20020a37ac10000000b0077d9b925638mr340482qkm.15.1701290634960;
        Wed, 29 Nov 2023 12:43:54 -0800 (PST)
Received: by 2002:a05:620a:170d:b0:77d:a5e0:dc7c with SMTP id af79cd13be357-77da5e0dd27ms85a;
        Wed, 29 Nov 2023 12:42:17 -0800 (PST)
X-Received: by 2002:ac2:599d:0:b0:50b:ba79:957d with SMTP id w29-20020ac2599d000000b0050bba79957dmr4313524lfn.2.1701290535463;
        Wed, 29 Nov 2023 12:42:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701290535; cv=none;
        d=google.com; s=arc-20160816;
        b=NHgg99893D3l9U1fCqMjIQCv2I8lJPvPsJTMPD+Hk7JZ/Z9U1KCotb5IUV2CmMY7yI
         OIFSmKTYX1V5yXSXQeGhd3JI5yFNC3F3zPPgUeWPBUpL0XN7W+lAi5wX6i84LYOlDHeH
         T4bxuTBzv58xwDnJl3cO0tYMVIRhQGx/sesN5PaftfNvCQ+LBB46qENUWbSChkurIfc/
         n8lacOoCDk96Vn+tM6ivEXp4rnEv7MZyD5HPfmiMCliU72s6EJ1OfnOaTgO/CsLaYraO
         DmpBgyFU0iJobdpR0rfYk07+JuiKrCKIzFaWGmcU+a2qJPaIhZARO/lg8Sbc58j1TeUG
         HgMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:user-agent:from:references
         :in-reply-to:mime-version:dkim-signature;
        bh=SjyD2uy7rhiIwUguKMOS6O61vfhptuzTgpHO35Q0vkM=;
        fh=mNh2dTT9hNlTAwR4JHScUJJPxlkXeBvbZ1V6FxZnDSc=;
        b=Hh3pUqoGK6QAWYR1ZqC8cfMH8j17x3YDJMqHo0l4WA5G31RbevYSpiWWF6ctttJusS
         E05VcZ22jw5Cm8OpcSRooDvP7v56nGDNkui8QT+sFvkZ+bKZHDu/nKIlSkjBkyquPGqW
         UW3mSbd/cIxB9ZhKnse3ne9dgDfFdM7Mm81d+sVafynqPZ0N7hD5L5LQZRyUGM8We/oy
         h0Efvhr5jU2BIf6Y+R1ttPOAweEOBNeZuD1mjV47mDSCTpFOW5PC8HBvvTSCpntL+ZmU
         XgckuNijFzKLBv0RCcpw4KjKRrxmkbON2GYBtuB5FURyZTXfTEyYqdZ8gn/LubE/9QW0
         sbAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=WEhMfW0p;
       spf=pass (google.com: domain of swboyd@chromium.org designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=swboyd@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id i21-20020a056512341500b0050bc7296c7csi105256lfr.2.2023.11.29.12.42.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Nov 2023 12:42:15 -0800 (PST)
Received-SPF: pass (google.com: domain of swboyd@chromium.org designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id 38308e7fff4ca-2c875207626so3038491fa.1
        for <kasan-dev@googlegroups.com>; Wed, 29 Nov 2023 12:42:15 -0800 (PST)
X-Received: by 2002:a2e:9d8e:0:b0:2c9:c22e:31eb with SMTP id
 c14-20020a2e9d8e000000b002c9c22e31ebmr1958958ljj.22.1701290534275; Wed, 29
 Nov 2023 12:42:14 -0800 (PST)
Received: from 753933720722 named unknown by gmailapi.google.com with
 HTTPREST; Wed, 29 Nov 2023 12:42:13 -0800
MIME-Version: 1.0
In-Reply-To: <202311291219.A6E3E58@keescook>
References: <20231127234946.2514120-1-swboyd@chromium.org> <202311291219.A6E3E58@keescook>
From: Stephen Boyd <swboyd@chromium.org>
User-Agent: alot/0.10
Date: Wed, 29 Nov 2023 12:42:13 -0800
Message-ID: <CAE-0n53x8AXUPaq5_TaqF6PN5u5J6g5RYoNWALN-MnEJBa5syA@mail.gmail.com>
Subject: Re: [PATCH] lkdtm: Add kfence read after free crash type
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Arnd Bergmann <arnd@arndb.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: swboyd@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=WEhMfW0p;       spf=pass
 (google.com: domain of swboyd@chromium.org designates 2a00:1450:4864:20::230
 as permitted sender) smtp.mailfrom=swboyd@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Adding kfence folks (will add on v2).

Quoting Kees Cook (2023-11-29 12:22:27)
> On Mon, Nov 27, 2023 at 03:49:45PM -0800, Stephen Boyd wrote:
> > Add the ability to allocate memory from kfence and trigger a read after
> > free on that memory to validate that kfence is working properly. This is
> > used by ChromeOS integration tests to validate that kfence errors can be
> > collected on user devices and parsed properly.
>
> This looks really good; thanks for adding this!
>
> >
> > Signed-off-by: Stephen Boyd <swboyd@chromium.org>
> > ---
> >  drivers/misc/lkdtm/heap.c | 64 +++++++++++++++++++++++++++++++++++++++
> >  1 file changed, 64 insertions(+)
> >
> > diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
> > index 0ce4cbf6abda..608872bcc7e0 100644
> > --- a/drivers/misc/lkdtm/heap.c
> > +++ b/drivers/misc/lkdtm/heap.c
> > @@ -4,6 +4,7 @@
> >   * page allocation and slab allocations.
> >   */
> >  #include "lkdtm.h"
> > +#include <linux/kfence.h>
> >  #include <linux/slab.h>
> >  #include <linux/vmalloc.h>
> >  #include <linux/sched.h>
> > @@ -132,6 +133,66 @@ static void lkdtm_READ_AFTER_FREE(void)
> >       kfree(val);
> >  }
> >
> > +#if IS_ENABLED(CONFIG_KFENCE)
>
> I really try hard to avoid having tests disappear depending on configs,
> and instead report the expected failure case (as you have). Can this be
> built without the IS_ENABLED() tests?
>

We need IS_ENABLED() for the kfence_sample_interval variable. I suppose
if the config isn't set that variable can be assumed as zero and then
the timeout would hit immediately. We can either define the name
'kfence_sample_interval' as 0 in the header, or put an ifdef in the
function.

---8<---
diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
index 4f467d3972a6..574d0aa726dc 100644
--- a/drivers/misc/lkdtm/heap.c
+++ b/drivers/misc/lkdtm/heap.c
@@ -138,6 +138,14 @@ static void lkdtm_KFENCE_READ_AFTER_FREE(void)
 	int *base, val, saw;
 	unsigned long timeout, resched_after;
 	size_t len = 1024;
+	unsigned long interval;
+
+#ifdef CONFIG_KFENCE
+	interval = kfence_sample_interval;
+#else
+	interval = 0;
+#endif
+
 	/*
 	 * The slub allocator will use the either the first word or
 	 * the middle of the allocation to store the free pointer,
@@ -150,13 +158,13 @@ static void lkdtm_KFENCE_READ_AFTER_FREE(void)
 	 * 100x the sample interval should be more than enough to ensure we get
 	 * a KFENCE allocation eventually.
 	 */
-	timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
+	timeout = jiffies + msecs_to_jiffies(100 * interval);
 	/*
 	 * Especially for non-preemption kernels, ensure the allocation-gate
 	 * timer can catch up: after @resched_after, every failed allocation
 	 * attempt yields, to ensure the allocation-gate timer is scheduled.
 	 */
-	resched_after = jiffies + msecs_to_jiffies(kfence_sample_interval);
+	resched_after = jiffies + msecs_to_jiffies(interval);
 	do {
 		base = kmalloc(len, GFP_KERNEL);
 		if (!base) {

---8<----
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 401af4757514..88100cc9caba 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -223,6 +223,8 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp,
void *object, struct slab *sla

 #else /* CONFIG_KFENCE */

+#define kfence_sample_interval	(0)
+
 static inline bool is_kfence_address(const void *addr) { return false; }
 static inline void kfence_alloc_pool_and_metadata(void) { }
 static inline void kfence_init(void) { }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAE-0n53x8AXUPaq5_TaqF6PN5u5J6g5RYoNWALN-MnEJBa5syA%40mail.gmail.com.
