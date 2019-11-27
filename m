Return-Path: <kasan-dev+bncBCF5XGNWYQBRBNUZ7DXAKGQEFDRE7YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 716D110AA55
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 06:42:15 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id u197sf12101340pgc.17
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 21:42:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574833334; cv=pass;
        d=google.com; s=arc-20160816;
        b=vsDP4trduGAZPYx3X8S5RdhKIkRX2c0TF0yGY4etOdv11RR/Typ8QHTMlYhUFqe6re
         98ni4O5lQMvfHUu1lSXdBDgxITfI2M8H7/ZKI3ThzVJuzdwx9PNtuYA3efDMnxzbi9a8
         hCRB0/Tc1o/cSqoU07/TbsCCuYp97VufodEMj+z05jVyGE6ZROFFvgxvYZ/gzokvvL6f
         6Xxad9M5K+lPNzfGZxbni2akc83l7UWdvlKwI4hGK4KGdtWJol2X4eED6cE62oxJqitU
         S7Ml/e+3tHbNhu2xm9GaTc1rezBL1HvydbB63OuhJACM4uPnbhZiD5NZ8Ri3KXD+nj66
         qK6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xGLbj4RWT4nYfppmR9bpVxHbvo0d3PVSmO+MKzYcabs=;
        b=H4fTBNd0DYEclc9ENsLmznVcm/BYqU6lnMG11bCt2HAclIiFh2hA/dxD+3iA14m+zT
         dgIkKw54C1hYe5dQDJewSmEQ57YmyfWDNHrh+MRznegB7kmgKEHBauUzDAJ6bxGsQJqw
         i4/ExKXQ/s5ceR81w/z0rEc0wAD3TiAV8dMt6HlyTIXga9EnNkXG4MUHm4eo6Mty/085
         aIkyzzSRoZ8GvXkaWLk7DnfFUZEqv2XFBiTkazVqvCSuucetJQ7Wj4VJ+pR9027gVqSQ
         S4oC5jF0Uoof1OX6108BeX+aMFJcSgRtD768rC7aWZd2UfqlDrW7ZbEwllHyzZjaxpQW
         4Y5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BCErC1RZ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xGLbj4RWT4nYfppmR9bpVxHbvo0d3PVSmO+MKzYcabs=;
        b=pcVAoXxzRrFVDvAYj3dRIYbEdSIGsKtlSGlsv4cRpAk1X4heSpHyc3eI4qQrdVRaMc
         fI6DJ4yLEZGbyIL9p3S9Or0tfzmwcLheV0kh+kQwSki9pAlaG61jaW4n22h8Y+C8IrU2
         vX1vAbH31mnhC+FJQDcpL+R8RCPHw+w9ci/+UcrO/OZvZkuqSA9th64MwYYLTWsU5MNs
         8X3j/RWPEhB5qoEhjCylWVHXFf81uoOSYvR5qGMvfbh3pzVNyX0xTrxrU28i4EXmR1vV
         XRYTBo8Uql2E3hKSEYJayvpbqWRkCYdkXs9yQqffMyCEOCZAYduMOtI2sV1ZaNIs9eG1
         ILKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xGLbj4RWT4nYfppmR9bpVxHbvo0d3PVSmO+MKzYcabs=;
        b=slB13fMaL2ijWSxvX185YfMfFxGOn01Jo7JsSwI1tuixWSDWb+1SEHR9e8BoJ5DLBr
         b/xXxjL70Jn5usRY5D6X93KB3QNfQd8H4aAhXSuBoK4eEvtPjdX+vEeDOT3hwM8sY6Jx
         ZIFeZyU0UFfmaaUKOCYxK5qNLYTrqtmcymkjNuVrJv9x4ijttZqfY3VPF7GZqkUS+wvX
         0YkqXjsmWJOMaLxIETuRiELS/xbKDIPh/LTa4UqsJUJzCy7OcoPDCpYVNt6fjUiN8igh
         54yjz0AQo8gU9sgljaQNIIBBN69f4Uq7CVEYCJ6lNsBLboLKPg/J7HN7+YcJ9IO0I8bw
         hr4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUgIyu77FbbJWKOs+O+CYYwktxvwzXpWDG56pdu6aAgNJNtjYwL
	zb4YteEiXoaKW+pd4msxVDo=
X-Google-Smtp-Source: APXvYqxdOZYRxb9DGRRriz3NsaU6QpTf1EODg7j7yPnaew57boOGsOz64Vy95HWjlzIjGJDpMsR9GA==
X-Received: by 2002:a62:4ec4:: with SMTP id c187mr45581215pfb.113.1574833334162;
        Tue, 26 Nov 2019 21:42:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b48f:: with SMTP id y15ls685149plr.10.gmail; Tue, 26
 Nov 2019 21:42:13 -0800 (PST)
X-Received: by 2002:a17:90a:d353:: with SMTP id i19mr3815961pjx.43.1574833333780;
        Tue, 26 Nov 2019 21:42:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574833333; cv=none;
        d=google.com; s=arc-20160816;
        b=xOhgfzeW/d4Cu0ax6JRp5ZCXwxxgmA5bpUbkgGteDvMDaaN8HnEMl7JGi5okMCo8+b
         YD/GBohJsufYK61qcufYkI6729NScwfckMjp4X4eDWvEROBvApUEsCfFuV+y7fhu/NtE
         YCJeeRcY0xYUydGzyOyTgaNdB1Yt/6Rd10nQPpEx8neD+2lal/X2SrcTL4+YuLjBZEcU
         9opN1duI1IF0Cc/HiFs/CxegFZfYVXELOiEDY2qRyBL5mRlufotqZ14U0/192rVLhWhs
         sfuAY6N08cAuylRP4nR3/P6pcNrxCM8lcqfVtkcgWlQJSO4Y9s1JOPE4KHDgrpJsszsk
         Bejg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JVfdiNpIIkZybFlA7Wet324geHsXtasX8Ts1855KGnw=;
        b=avUxlSj/8G3RObsarP1CYA454XE28rypDnh02cQkxvZ1ON7s9ZSz4iT2aTPjNZqVrZ
         YWPezNBNtK2Dfop8LIOvZ8OswXRzMSlvdNTmTQzIDYKahdaMZ0QXmVzB9ZuIoChQ7eYA
         noThCXJImYPj2zO1Wn3+0BOWXfXwBf0Znd1rtApxFmtE+rQjGkCJOZqEDaXN19eOZl1w
         I/NstgbvAXLMmQZo29Wu/9/U2ntAgbC3guLp8moq608BV5gTW5CjUT4xyExnUlc3deq1
         /CDl3dn/yep2esapvnwBVcAq6H7RCQ8N6b8NzmdmPRRShVl+RZb5pTqzE+qTKSSk7WJC
         ynKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BCErC1RZ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id 62si546931pld.2.2019.11.26.21.42.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Nov 2019 21:42:13 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id v93so6135606pjb.6
        for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2019 21:42:13 -0800 (PST)
X-Received: by 2002:a17:902:7892:: with SMTP id q18mr2295211pll.171.1574833333323;
        Tue, 26 Nov 2019 21:42:13 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id g6sm14230976pfh.125.2019.11.26.21.42.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Nov 2019 21:42:12 -0800 (PST)
Date: Tue, 26 Nov 2019 21:42:11 -0800
From: Kees Cook <keescook@chromium.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kernel-hardening@lists.openwall.com,
	syzkaller <syzkaller@googlegroups.com>
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
Message-ID: <201911262134.ED9E60965@keescook>
References: <20191121181519.28637-1-keescook@chromium.org>
 <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BCErC1RZ;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Nov 22, 2019 at 10:07:29AM +0100, Dmitry Vyukov wrote:
> On Thu, Nov 21, 2019 at 7:15 PM Kees Cook <keescook@chromium.org> wrote:
> >
> > v2:
> >     - clarify Kconfig help text (aryabinin)
> >     - add reviewed-by
> >     - aim series at akpm, which seems to be where ubsan goes through?
> > v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org
> >
> > This splits out the bounds checker so it can be individually used. This
> > is expected to be enabled in Android and hopefully for syzbot. Includes
> > LKDTM tests for behavioral corner-cases (beyond just the bounds checker).
> >
> > -Kees
> 
> +syzkaller mailing list
> 
> This is great!

BTW, can I consider this your Acked-by for these patches? :)

> I wanted to enable UBSAN on syzbot for a long time. And it's
> _probably_ not lots of work. But it was stuck on somebody actually
> dedicating some time specifically for it.

Do you have a general mechanism to test that syzkaller will actually
pick up the kernel log splat of a new check? I noticed a few things
about the ubsan handlers: they don't use any of the common "warn"
infrastructure (neither does kasan from what I can see), and was missing
a check for panic_on_warn (kasan has this, but does it incorrectly).

I think kasan and ubsan should be reworked to use the common warn
infrastructure, and at the very least, ubsan needs this:

diff --git a/lib/ubsan.c b/lib/ubsan.c
index e7d31735950d..a2535a62c9af 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -160,6 +160,17 @@ static void ubsan_epilogue(unsigned long *flags)
 		"========================================\n");
 	spin_unlock_irqrestore(&report_lock, *flags);
 	current->in_ubsan--;
+
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
+		panic("panic_on_warn set ...\n");
+	}
 }
 
 static void handle_overflow(struct overflow_data *data, void *lhs,

> Kees, or anybody else interested, could you provide relevant configs
> that (1) useful for kernel,

As mentioned in the other email (but just to keep the note together with
the other thoughts here) after this series, you'd want:

CONFIG_UBSAN=y
CONFIG_UBSAN_BOUNDS=y
# CONFIG_UBSAN_MISC is not set

> (2) we want 100% cleanliness,

What do you mean here by "cleanliness"? It seems different from (3)
about the test tripping a lot?

> (3) don't
> fire all the time even without fuzzing?

I ran with the bounds checker enabled (and the above patch) under
syzkaller for the weekend and saw 0 bounds checker reports.

> Anything else required to
> enable UBSAN? I don't see anything. syzbot uses gcc 8.something, which
> I assume should be enough (but we can upgrade if necessary).

As mentioned, gcc 8+ should be fine.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201911262134.ED9E60965%40keescook.
