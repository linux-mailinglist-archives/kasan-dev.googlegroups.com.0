Return-Path: <kasan-dev+bncBCF5XGNWYQBRB4FA63ZAKGQEH6RFLCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 96F351767BD
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Mar 2020 00:02:09 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id z17sf343087uaa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 15:02:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583190128; cv=pass;
        d=google.com; s=arc-20160816;
        b=YbrLeLFFp4pKRUrT2PBeeWxn4YWiZTmgxnrN+bg3kxBH/OEz5XIPp0lxa/SV8f+B/n
         eaHiy/vBqK4rz4mp+tY9lPnRE0Db2QZX5Ecn+syfy24PkbjIMGsTFjInP+KwP8qra72b
         YzkszMJ/+Drk+uVbmpGvbHfcGnNa5rQzDOsP9y6cZHoGY2iiThbrz5hHzjCUgXN4enY0
         Za9EHwfVZ5BzME0/pU5YReuAdRcE5KJ8iGYJihOokug1fSc1syIx6YZ5MrSbe4C2dP8h
         +nb5hktfUDzoTmEzRgE0mTwmYtCTCtTzcF30GMZjusLIxD0i18NluRjtkOynWv75J6mk
         UQBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=u/pjrUtVGY093ZqC/PA//LktMhgTsh/SJ4sha6u7ofY=;
        b=bejgzGL00DTl9nyGLbGznriHsIXgzH5MAHFd9oWaEvsMSQ3GllwnHtK/eTPjEiWcOf
         uSqY+6utqQSl7UnaGelSLU/hdD1qcEN2U9ksHfNgEX1S1e6zEezs83rfNi+2z44J2HkI
         cs3qy00YrKbf5s0uD39V4j3MeXKLUKOPPE0cgNQPImDuJqajw9TKkXlCLzaggSNf0y2t
         xaAwpDmkg2bRrA+PcsGTquJScWul7t8fl0jp1OnDBzl/TW8hcSXqfUwaHCKsNDnEGNnM
         UIS9jfFQQD980Hx/0Xly9/Q1/DFMW7IvgH+ay5O8/09j30CZ+SWANeIyS7JVCNP5qvgi
         /tjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FPSeLrB7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=u/pjrUtVGY093ZqC/PA//LktMhgTsh/SJ4sha6u7ofY=;
        b=CaSuAO2N5jmv819UcSCNb3mIcZMwhBJXdZ3l7i61Kxgad44LkdYD1SIcMO0vKS4B6j
         bLSsNlfx/d6cZzHsQE+d0PWxfi4OZ4j+OjXlVj36v8XrPqOH+Ts0MUy11r3w67Rsa89p
         bX7XFfDayXBShF/YK/wZEkzcNdGWFAqs6qMQnrj3jdbGqvFq1GbXc89EfpJ0DhfdIsfg
         /VGxmYCPJOPUdx60k8pjH9LkB2HHHaDYBQ7GOaeoCdh2e64aOu9yTTeg+PdNhoewf0em
         CFiBdgg/jyivoH25WvpHsyMhgilM4wrksWFcxB8F6uK2392M5Gls3SRx73DpgQLKMrg5
         UntQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u/pjrUtVGY093ZqC/PA//LktMhgTsh/SJ4sha6u7ofY=;
        b=STBamgUvFVbRz4IjAwWNbEMWcMFx9Y1iWozXNKKoziEhzgx9s2ZsCOZmzwn3YLNQs0
         wj1FUMnSNojkdsO3baVkiwfMPr+wiLWlud7BhB7m44DEoj7uKqRvdi0j8tpKfIOzmkBY
         HovINkNIiBoY8Q/wDO/wNUAZpG4maV8LZAyb8pJC3XkfJEk/huo9J+4nv40VW+HUSi9E
         WgzR9ppwDtxhIv4TTb7ucLywjCLkXyYuXfp/3LBLANfY9Is+KtaEXGZ3u8o8h8Xit0g+
         iIjuOchxJGO1z6ECr53UT4DhZUM3CBM78Bza2humppUB2viY/XDkVjdgZRsFmA/xtzPP
         4P2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1a5zZmU4UnWA0X6fqNrbst06h8LwI9aRE+KigeIBtOUg3aa6+x
	jrUgta/MdVptXBpA3bYsOaA=
X-Google-Smtp-Source: ADFU+vvbNNS3zXGiHhQqfPRvi4g5eLzFQJJWpDIFWuUbdV+Set26UFyquXYLc/Md2FC0AnBBRJoFLQ==
X-Received: by 2002:a1f:5385:: with SMTP id h127mr1293731vkb.56.1583190128448;
        Mon, 02 Mar 2020 15:02:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:644e:: with SMTP id j14ls76170uap.8.gmail; Mon, 02 Mar
 2020 15:02:08 -0800 (PST)
X-Received: by 2002:ab0:6881:: with SMTP id t1mr1202798uar.88.1583190128078;
        Mon, 02 Mar 2020 15:02:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583190128; cv=none;
        d=google.com; s=arc-20160816;
        b=t0LXYriwsC4lRKEtqNCS2vv9UIqtYwVaPLM3MsQsrCGUf+lrv5/Ybv7wzr3HuW29Y1
         +ho25b2X7Qmr0W4DYWzcuAnxOepRcGlY+OHdO7BnRD04UEgfAGYjZWhSSev4TEiY6jv2
         AEsyxVnzD5G5ZBaGn68eeuZXcUM+6AydMIhOu/aE4+/CWBdsigRMj0ZdiCdkj1jdrPcr
         tex61NY/jfAl2n3ehQN8khHhAJZ5Hik7L7D+P7HHmeAHLy459cPcrUSgkwHeVl4CaQX3
         mO10dtPG1rhlFWqdZtlRgjQnPIUo+pNAsxhwTW7WSipr57vx8dQmCFn57ivZYgPdhTgV
         n/Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=alU+BgvFGo59yM0O+ldee5pOjl7Ty1NQ+17QZiMtzMo=;
        b=ByE7EY2YPiIqVE4Mq68xiyjD7GUm+w4CSJgteuRMfHdFsT/1ni0QZHrQMDHlPmgsC0
         WFxICQrEgYyaULc0Khlf7EwgKhMnDzDwVVwj1ZEpzgisXcWtLBuE5lvY7qNyPsf+ZGnk
         Q5RNQEy/jpmiFHT1P5QOY0jqcLmtpHONcQ/m9sQuZsq/OSWVe+Rdlg10iv2uaHC/4ol7
         AQTV44yMQe1pPtUH4MBxHaAAwkGlEifpmM+ehhetya+Z3hV1fyKuNg0CFSfpFwgl2blp
         Mfi2fFnzaYma2j5lEF+CVBSNCDAPc4kYRr1z8raIkxyB0kGCSFrKa8YHera/PIZPOg0s
         thHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FPSeLrB7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id z8si430979vkb.5.2020.03.02.15.02.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 15:02:08 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id s1so431553pfh.10
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 15:02:08 -0800 (PST)
X-Received: by 2002:aa7:8bc1:: with SMTP id s1mr1226128pfd.215.1583190127144;
        Mon, 02 Mar 2020 15:02:07 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id v29sm22024356pgc.72.2020.03.02.15.02.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2020 15:02:06 -0800 (PST)
Date: Mon, 2 Mar 2020 15:02:05 -0800
From: Kees Cook <keescook@chromium.org>
To: Brendan Higgins <brendanhiggins@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Patricia Alfonso <trishalfonso@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>,
	KUnit Development <kunit-dev@googlegroups.com>
Subject: Re: [RFC PATCH 1/2] Port KASAN Tests to KUnit
Message-ID: <202003021500.9E0FEE1BEF@keescook>
References: <20200227024301.217042-1-trishalfonso@google.com>
 <CACT4Y+Z_fGz2zVpco4kuGOVeCK=jv4zH0q9Uj5Hv5TAFxY3yRg@mail.gmail.com>
 <CAKFsvULZqJT3-NxYLsCaHpxemBCdyZN7nFTuQM40096UGqVzgQ@mail.gmail.com>
 <CACT4Y+YTNZRfKLH1=FibrtGj34MY=naDJY6GWVnpMvgShSLFhg@mail.gmail.com>
 <CAGXu5jKbpbH4sm4sv-74iHa+VzWuvF5v3ci7R-KVt+StRpMESg@mail.gmail.com>
 <CAFd5g47OHZ-6Fao+JOMES+aPd2vyWXSS0zKCkSwL6XczN4R7aQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAFd5g47OHZ-6Fao+JOMES+aPd2vyWXSS0zKCkSwL6XczN4R7aQ@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=FPSeLrB7;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443
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

On Mon, Mar 02, 2020 at 02:36:48PM -0800, Brendan Higgins wrote:
> On Mon, Mar 2, 2020 at 9:52 AM Kees Cook <keescook@chromium.org> wrote:
> > I'm all for unittests (I have earlier kind-of-unit-tests in
> > lib/test_user_copy.c lib/test_overflow.c etc), but most of LKDTM is
> 
> <Minor tangent (sorry)>
> 
> I took a brief look at lib/test_user_copy.c, it looks like it doesn't
> use TAP formatted output. How do you feel about someone converting
> them over to use KUnit? If nothing else, it would be good getting all
> the unit-ish tests to output in the same format.
> 
> I proposed converting over some of the runtime tests over to KUnit as
> a LKMP project (Linux Kernel Mentorship Program) here:
> 
> https://wiki.linuxfoundation.org/lkmp/lkmp_project_list#convert_runtime_tests_to_kunit_tests
> 
> I am curious what you think about this.
> 
> </Minor tangent>

Yes please! Anything that helps these tests get more exposure/wider
testing is good. (That said, I don't want to lose any of the existing
diagnostic messages -- _adding_ TAP would be lovely.)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202003021500.9E0FEE1BEF%40keescook.
