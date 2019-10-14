Return-Path: <kasan-dev+bncBDV37XP3XYDRBPUXSHWQKGQET5SJ4AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 47516D5FE9
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:19:43 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id g67sf4109127wmg.4
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:19:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571048383; cv=pass;
        d=google.com; s=arc-20160816;
        b=kYJFC3k7pD8F1GG8cDPENdUZ6g9OPeis+3TKA8cuANU9W7zNyK1EM6qph4gdIp8yAn
         noKw/qJAChXYQkDg3K2ynSmpZ6wCYYJN42W/ywTRFTR+AGYf5vRFuWuRSOf2cPoqnHaq
         QW7C4JFE4dghxyP4bYyiHrBDgRryUfnbHjSoP7RqzqPKDijMT8fA9xVVScGUU4RlPVH7
         CHZ9HJFC/YvrzdrKjXsWw7IkW1TUGRToh6/tPUOUnS8+KAdARNs4ndlP4jEXs1vfW3/G
         OUgmOXXOfFFN9n/6FG/7txJ6JIgfN0jB6P/ClpzGaIKR1gnsW5aUtbDQhmiI7l/4KTZa
         0wOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=r8GYytM26crQ2E4Nz7YmKOsu1lzQJuIM9Nn8oXqcbtk=;
        b=XOZeG0KwqFt3rq70sVxldisyrB7bc4TIE95Qt3j7pjWjdYrjFiBxE4L5KbeuJ5lnI7
         2AoYWs9w/lx0iHTvUhW0ADKVH9MfIWH50aLcxDjlEcIDI+nrbuX4Esg1bv4tuti70UzP
         RrzNkWX+Q+4XfUWsWcIWxlJoTngLWEEKjtp2PSCUGTNVhAqR9f8bY96xrcUV1oJjf3a4
         LVwzRf6ZSg/YCroyPcGKu65fp8bWUKqePfsanHjkHma+jjxoiVimhLZsdyzpIhR4J7LD
         jQX/4eVOD/8mnWJIih47SuEPTKfRhpYtGC5XQyGKOe1M9TlX+zJDW5kd+nXZFqHQDnrv
         RAKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r8GYytM26crQ2E4Nz7YmKOsu1lzQJuIM9Nn8oXqcbtk=;
        b=Zre3puehhnkNstkwdUB94ElBai2Ujg05OoaZf4akNl+oiu/cf9f5xYRSwk6T4ZXuZ6
         9xNRcY+TTaAZrSbqwv4aCg5YFl66pKV6FtH+m0YR3gyLhd/YlTjxWVeyPz2M1nM+ADf/
         pi6EdqXT9FK2/UqhDQ6tQjcZZun+74+9Nc+Vzircn+HA2gpfIef339tV5yyyYos51uMN
         O4F2d3eAIC/xw2pMOiV+3SgdMfcr7c9vEfUA6+Qu+H6l3T7t6Kbg/ndjlW9eow2P+lzK
         UnzFn5qTh0fhkTZNyPrWWwvVuaw5l3Wu/BVNxlS6Uok/iELY/ApTf0CQOvYWBuJoudE3
         KuHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r8GYytM26crQ2E4Nz7YmKOsu1lzQJuIM9Nn8oXqcbtk=;
        b=evXUqKaOtB3sUJ80nzs0kLwS9UGxU4lN+A47RION0z/4fhKr9BwJ9zB2zpdyR+z+4W
         7ovE9Ex90WVIv/6Hr7XtmMuCpIT0o49GUD1zKlXJuYnCwibcKtJxHci1kNQbIov6SR/P
         Rl5leyNIVVygGR15prJHML38CEiL5IkvLxWo0cUeDjf+0HbQsLp1e6T2D2RvpjbJc2Aw
         PsACXEeUOMff5gn/y7pHOdI2eeDvnha+7iH3sEikjN4lxiV/GiFVkv/T4oOcEs2tpCV7
         NJF/96aS9+OPT37SV981sjylSobZF+0z9tyFm3IZvPhVxVutY8gcxIRDA/efV13xWnsg
         7bNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX0vHsp/ulzmczkJMzGvqFcqyFyxiuYL1x9uejTmHYTx5uXeWOc
	Y5hHUSHeSplrcsi1v8CKPa0=
X-Google-Smtp-Source: APXvYqwtFZSsLgBQS7HF+9sas43rJNpXrl3tjbmKYb4V9TchX7EZo6p1/bmmY5qmxdQRl/S8AOS6lg==
X-Received: by 2002:a1c:6308:: with SMTP id x8mr14486027wmb.140.1571048382893;
        Mon, 14 Oct 2019 03:19:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce16:: with SMTP id m22ls5966424wmc.5.canary-gmail; Mon,
 14 Oct 2019 03:19:42 -0700 (PDT)
X-Received: by 2002:a1c:9990:: with SMTP id b138mr14850756wme.176.1571048382345;
        Mon, 14 Oct 2019 03:19:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571048382; cv=none;
        d=google.com; s=arc-20160816;
        b=RqNlTLkJoINoZq7QZkxtyfCQC45cTevVShmTkja6q42LuXu7/9djyOwV8pqAhCYj4d
         qv7mlysp93csJeSq3EtskPtA7QysIspTyOT2dHqGtw49czojapTu2D+++9t8qE/L9+T3
         8mHhvZ52Z9fIz2X+4qj/ZY3C3QnMOO9+SbTHSW319+UvXGxKzhoyByV1L/lbxKbw9vlI
         +lUR/P1MyudGxGVSDMxl2avIYX23hBcXdx1heERteQ7oP70P1nx6oaEP7H7UH6/JaiR+
         XldmeEkr3ca229uZRoiCnMDW+lDC03P+IByCs7uJMCIrhlrRQalejQsssPboQ4IOX7nD
         3ksQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=SjYBNYn+6Lqo5IA7ZbINeGXg7gKAFbqoE+NHEJwg+bQ=;
        b=0NvSyAEZD6KhujBw8bueuQ7fR0DU7G0ztBet6rjaZe0wppE7kHO0WscjJIZS0s1H0Q
         KW2p7TmpSvdJNpacOtRC6ILQYO8+m+d3IB1ptFwQo1GnKVNrWxzmlL5jYK9PV9Z4pknn
         YQw0w5sDseGt72cpDThu+AdJ2s9e8lErEbO+7m+KHw6oXA72pWOvISC1PT0lMh3VusHu
         rh7HTS/jwbyC6YAEzLVSglUW7ZHQZUXn+vXYf1FYpLnqgzDiQ4uScdCg6nNRQCdkyzS+
         4HyyJ+G8evZJROweJKyBn1a2Rntcp8VHloFofNBBd23baFoajbZUhJzQzwTKi6dL7wBG
         nrwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a133si1429967wma.4.2019.10.14.03.19.42
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 03:19:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 97E38337;
	Mon, 14 Oct 2019 03:19:41 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5E53A3F718;
	Mon, 14 Oct 2019 03:19:40 -0700 (PDT)
Date: Mon, 14 Oct 2019 11:19:38 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, sgrover@codeaurora.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Will Deacon <willdeacon@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20191014101938.GB41626@lakrids.cambridge.arm.com>
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Mon, Oct 14, 2019 at 11:09:40AM +0200, Marco Elver wrote:
> On Mon, 14 Oct 2019 at 10:40, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Mon, Oct 14, 2019 at 7:11 AM <sgrover@codeaurora.org> wrote:
> > >
> > > Hi Dmitry,
> > >
> > > I am from Qualcomm Linux Security Team, just going through KCSAN
> > > and found that there was a thread for arm64 support
> > > (https://lkml.org/lkml/2019/9/20/804).
> > >
> > > Can you please tell me if KCSAN is supported on ARM64 now? Can I
> > > just rebase the KCSAN branch on top of our let=E2=80=99s say android
> > > mainline kernel, enable the config and run syzkaller on that for
> > > finding race conditions?
> > >
> > > It would be very helpful if you reply, we want to setup this for
> > > finding issues on our proprietary modules that are not part of
> > > kernel mainline.
> > >
> > > Regards,
> > >
> > > Sachin Grover
> >
> > +more people re KCSAN on ARM64
>=20
> KCSAN does not yet have ARM64 support. Once it's upstream, I would
> expect that Mark's patches (from repo linked in LKML thread) will just
> cleanly apply to enable ARM64 support.

Once the core kcsan bits are ready, I'll rebase the arm64 patch atop.
I'm expecting some things to change as part of review, so it'd be great
to see that posted ASAP.

For arm64 I'm not expecting major changes (other than those necessary to
handle the arm64 atomic rework that went in to v5.4-rc1)

FWIW, I was able to run Syzkaller atop of my arm64/kcsan branch, but
it's very noisy as it has none of the core fixes.

Thanks,
Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191014101938.GB41626%40lakrids.cambridge.arm.com.
