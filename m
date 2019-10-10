Return-Path: <kasan-dev+bncBCT4VV5O2QKBBO4D7PWAKGQE45SRBDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C3798D2003
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2019 07:29:32 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id a8sf2421173otd.7
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2019 22:29:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570685371; cv=pass;
        d=google.com; s=arc-20160816;
        b=o+fTyiPSTx/p1K49KMccA02HtHz+ZZtIvna3/NkHm5wzO3rUykPqCSZ3Qnx5TVeYBG
         Amu1RN0yWDaU683ZelJlotTxiM/JM86slcaEfF/OOIcpYN601aOAKqEnIpJcZTJNA4XU
         JAxCDkzxCnS5mTVPI13LxhYqr016rbNZRmt8ytvEJo/sghszTDFcO6Jkj1+F9PZuYmPs
         GgOb6X+vEtb6oODjpnCtm5mx3Q0Uv9mkEGby2RdsKX8R2NAQIn+G/YrwdSo1HN4SXvxn
         rmx9N2wLDOsXr40GJu1rd9VILl+9fisJAuC7Y2wUHlwTKRdveD608M/bLT6e9rC/zbyT
         hn8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=K5mBdFURkBkXmQmLZd809NkT6IVcD4OptVqPjYv17i4=;
        b=tlXdkD3O5l6DpJw33Z/xTrzb5pCA+0xfMj4jVDOpfo1tkQXl1Auhb0brHj76DwDmD2
         xmqWujPgp+LmEjiK7PKHSHaXVlnXXZpPLKV9O/EvVPIDqgC6FKF62JixSNdfhM7UdXTY
         5xAiDBTJFUSx4nKC4SkBRcfWB6KCww8VVoQpHvSI0zJCpQHYZRXK0TLkNLQKoFzCRWa4
         rjESjUTdduRIn15vvRfk5v8DjkVtxFH9e5WMFJPxqUI/vE068848rZyUM4+9VIi67YEa
         rsBTfOWN5r61cPTA/hTFW+IruL50KYBbNdGuX/qGbAuqW4Mh/EWCUDcFieDx2FRdWQlC
         aHYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=O2OVnJzN;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K5mBdFURkBkXmQmLZd809NkT6IVcD4OptVqPjYv17i4=;
        b=OZ0VNp0sFFIUasXDYMSx36SnpdK2OLCo0i/ZJbDi0VhtsGq01dh7v9TbO2FHUs5ows
         IiZU99EXSesyRj9RZLWcJI1k03C6Z47Cp/tJvv8e/dBD5VblOTUVMxND0dF6noHTkcvO
         Wb4sXYTWTr6cxjErqz5uDyjn3JerKJMF92DPbsvULAK5KMJs8jHRHu2abH95hIBgTR87
         D1hziVkD+S+inVan0zTdkhufvXnfZ62az0VLCOBQGxtKMhRW9upaa9PDTg2XtHHHenou
         mbOhfeDMBGMPNpCZWj/7o6Dx4nbJUDpmZOxTzWtsiB4V4WkOxBMNlxIiDy1OxQu5sC0B
         jb/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K5mBdFURkBkXmQmLZd809NkT6IVcD4OptVqPjYv17i4=;
        b=aWJqjk2bf+2W262ra12xdM4rHb19C+gLCMZbIFJg6wege368S06jM3Hl+k+NyGtAH7
         fer7CGh4jd26UJqLzNxFPRddhXiPc7FTTNtA93YmtswLgocy/+/3P6K+65qyKaLoBzMz
         wG3CYNeqiKtNs8iz7RTZZ7a/TpqHb8CvZBp5bMJTQkyD6WBdN3a0NUy36yPmpa2UsttJ
         aiXhnvzI9+BSDIltGNHYzaMOUmDoNr266QHenf+3Lb31o+8ybpYn7b94y+Ra4IFi2r7K
         hFOENhn+jv8HmCGMERtju281j7U6KCxLbCM4jB/tLkqczG6JugIEcB0CRx5O+vdjvp29
         Ousg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K5mBdFURkBkXmQmLZd809NkT6IVcD4OptVqPjYv17i4=;
        b=TC5HV/RLR4MSOC8a+YleZfV0lx1u2nYyAKgvxOZK3bW1wo2X7CVokFXQp+Jq8ehoDx
         dY6eNUYiui8g+/1iD4l7HGjIO6wyK41oQJx+vx8gbWlkrKtNAGrS4KQgTfcxUwK+jtq5
         MGHBrQP/rcjtc3iE+jMn6nAT9/2KCOpzXSfDDiVvPfW+Qn0/9i6E20MVmRPCnY8XnJJB
         EFl6qJ4jMyju369nJO7G0CgN9cdaBFhaFcJXL5MGXxfMapPXydVTYu/aq7w525P7WWAC
         /1AzprikzVArY0GSibIxb/uGykeemLoXEzaS0fJy19cLBdAaloWkyK/+FGuP3BGuodxH
         mwTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWu8k4K+bN8VaEQXyqW06f2Ouagov5tjV+9fQ3To+snH6b6xHzp
	jvIf+KrYumFDQOR6qsisD5A=
X-Google-Smtp-Source: APXvYqx40foSj1h5o79ZyLwwidlrAhGLNV9d6hBaYaD7tGv0T2cAAgPFGmzpdLoHMbds9DDuFakcAw==
X-Received: by 2002:aca:6206:: with SMTP id w6mr6045024oib.8.1570685371297;
        Wed, 09 Oct 2019 22:29:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d91:: with SMTP id x17ls501719otp.1.gmail; Wed, 09 Oct
 2019 22:29:31 -0700 (PDT)
X-Received: by 2002:a9d:5544:: with SMTP id h4mr6256947oti.94.1570685371025;
        Wed, 09 Oct 2019 22:29:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570685371; cv=none;
        d=google.com; s=arc-20160816;
        b=uz4SMzTyI2bUK28FrdaPgVEU6XbatCWk/r+4CMEg8Pl2GLgkyw/Fp5aixEU4R+KXt+
         2+rmSwdbw2FD4ffehxVWKcMDPUWOs52R7Enkg8U2OfCFxsFiyRHV9inFvBTjLKUn88KE
         IK5a+6+UQ30ifiErNx/ASqSD+q+zQCFj+ZKnrLN4Dfn77V9JoBhj4uJE0YvxN0yUaJjZ
         asnjClhsMvEzHb8qxuTPDGbip8YRn0o/ggUzpOlJdY30P+bbJ8ycDhDAqIj8r6nxmB3v
         89pKQKWn4ZBOWuY4xdTo1CNCOeKGwBCYF0yy15pCJqaEIx4UkhvRovKlNtXxTmK0KHky
         pwxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4ux0oG1N3RPh/ZQT3Rg4tacx00lUapXz9BDpB0CV0W4=;
        b=xn/RF4SI2Z6p3V9Ye3duRTjlJYRmhoLZYFypYb+EBPn/z5hoKWXPLaKqZcW/N7KB27
         vpvm2VfoRMPq2r7v7xa83Z+HLbZiyf3Eoj4gGndQ9705NXH6sDmC4sAMdK7JFcz7BAnD
         5hM414WCRtktGBRGO7xfr2ynynHPNtsjOa8o5AVXrIh2SfmPaOkZRKadlFWMPLmHvLhG
         2yOZd+Grx67O+WutqFla+PTH/PD1g6G/brN+Sg/W1KJRIPa99ItDPXuImaEdFrdDUSig
         SmK9oHC0eQLO8GlpKDHGaVMXndwVxSzNu6SPBHMhxBz1ON4oRe9UNWuxH1MV5PL7uAp8
         qc5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=O2OVnJzN;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id i19si85473otk.0.2019.10.09.22.29.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Oct 2019 22:29:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id q24so2186526plr.13
        for <kasan-dev@googlegroups.com>; Wed, 09 Oct 2019 22:29:30 -0700 (PDT)
X-Received: by 2002:a17:902:9881:: with SMTP id s1mr7620856plp.18.1570685370251;
 Wed, 09 Oct 2019 22:29:30 -0700 (PDT)
MIME-Version: 1.0
References: <75f70e5e-9ece-d6d1-a2c5-2f3ad79b9ccb@web.de> <20191009110943.7ff3a08a@gandalf.local.home>
 <ce96b27e-5f7b-fca7-26ae-13729e886d46@web.de>
In-Reply-To: <ce96b27e-5f7b-fca7-26ae-13729e886d46@web.de>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Thu, 10 Oct 2019 08:29:18 +0300
Message-ID: <CAHp75VdrUg6nBfYV-ZoiwWhu6caaQB8-FCSeQFH0GrBX33WhVg@mail.gmail.com>
Subject: Re: string.h: Mark 34 functions with __must_check
To: Markus Elfring <Markus.Elfring@web.de>
Cc: Steven Rostedt <rostedt@goodmis.org>, kernel-janitors@vger.kernel.org, 
	kasan-dev@googlegroups.com, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>, Joe Perches <joe@perches.com>, 
	Kees Cook <keescook@chromium.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=O2OVnJzN;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Oct 9, 2019 at 11:11 PM Markus Elfring <Markus.Elfring@web.de> wrote:
>
> > I'm curious. How many warnings showed up when you applied this patch?
>
> I suggest to take another look at six places in a specific source file
> (for example).
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/test_kasan.c?id=b92a953cb7f727c42a15ac2ea59bf3cf9c39370d#n595

The *test* word must have given you a clue that the code you a looking
at is not an ordinary one.

-- 
With Best Regards,
Andy Shevchenko

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHp75VdrUg6nBfYV-ZoiwWhu6caaQB8-FCSeQFH0GrBX33WhVg%40mail.gmail.com.
