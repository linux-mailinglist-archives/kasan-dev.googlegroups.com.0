Return-Path: <kasan-dev+bncBCMIZB7QWENRBI4JUH2QKGQECTW4X6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 05E9F1BC21C
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Apr 2020 16:58:45 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id h13sf7527308oov.16
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Apr 2020 07:58:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588085923; cv=pass;
        d=google.com; s=arc-20160816;
        b=d2KuGriKMETYOqshtN+OPQGa0dDHw7f47RdlJT58TDwmuXy4NNkT7Dw3tAQcyyszw6
         2d5QBAQVEk2+sStoAibsK9Yf6bIceoHQLR5H4PJHqIpoZOBSoXIOeYAu4YYF/8JZA+nG
         vNdQI+inmBP9DzGvx2NPL2CAfy1ixSIxzGtdBj/vI7M3gVfAAgc+ZOcwC3KANsUNzi48
         tduvoIBh7+8BgvD65zFDHtpsQFKhLiALnqgA6UIb8o14OkFPJ3Y1WcNRKiWgQB+SxFUE
         OTyzzwv8VU5Uqfyy7UUtcKKAlULnM1LnobkPvU1Vg1bRmAqQiR451j4JF7DWknhctlPW
         Tyjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=H/FBY954hZloZPpl/Gs8ylA81VLwB2Jg5krWquGOz0M=;
        b=bmxicmIBpJQnWpr+f/nt1lC/aMrmCtWvCz0Ko1lrQT9M9P+VUvB0niarFK8WWkCeck
         2w8LCTmEfbpfKFXXpxf1ILy8dTt+VjCrvTRbdLoPl0EGLoU2Tv/ZpakqmI05gJTrxjYw
         85WG1kS+V6wKkOX6hXSxeQe+uv3azdiWfwgA63jp71hfIPRS7HJWSXYoSdmtOYnfyrkN
         cT/mOzZ48gmMst9EwF/4/wgLX837CEqi5EgPIBhKs8qZTWt3TpQcEP6iVpfQbD3EDHRy
         OpV6ElHAq5LnUeC4//kMiWNu/u+t11E3+u2G+CpZvcfUXRDi3HbOdv1zl2y+6knpIoZw
         7nAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RM4ItuNb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H/FBY954hZloZPpl/Gs8ylA81VLwB2Jg5krWquGOz0M=;
        b=BThbdbR62gBLn5VpgveZyoiDWus/SnC+mmBtxcTxPJTtMl1uh5gvoAmnwt47dJPKQN
         M+/wutMXB/+NtDhjK3Wr5VKGC4UPpnQ/Zylvu8ufSLqmHDp6xrfaP1AE8fx99U4JPo/G
         zHkGrTd0Xzr0REYCIfNFjeAP7iO99n0O+PSvQFfkFR9487r8bX1YWU1t80WA4qG1Afyu
         731Ap03Hj+YcbnIYnMPBmeGMNR2SshdtIVttvlk56YDCT+Y5r6cq/+ly2kSHljxgBmHU
         J0MpN+XLKlFKjsiFGzFhMrSbQVBA7XWA46Z5SpeZq2a+2KiHaprECt3LteEXnZsRW2gv
         jT3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H/FBY954hZloZPpl/Gs8ylA81VLwB2Jg5krWquGOz0M=;
        b=Gpg5MQzSaL7OmaJ9Nil+DQZWX6TIDKsoS+rZVEigz4KZe+6S4Unco2If5kqzl80m46
         7Mijr5NHwxSeMb2P2uJR3QPF0HSCTCdPcDjy/8fTj/1nFADYfzRHOpdQDyWO5LMLHB4o
         hdtYMtO3M+8hIYLbswOjMMuRE2euXabwuzek8++XOd7vfZKE5iib7DBn+C+NspQIsEaP
         xsuOxnc/t+dyB/vvBhuaPuuREAhYhA6/8RR6RoeVoXnWkhIQsT7lOk/M1oIGkkKyQlIB
         V/dv/vwnDCE9Wkn+mBKFLeSX+WMU7TVJ8MVkoZociPxlJgqTiaVkVUhr/pg75mYeoOku
         Yj3A==
X-Gm-Message-State: AGi0PuYJfHqyB9bos/kKFuZG4xSA4J9ObLfEKJlc0Qc7yrFFYkjpN/Gu
	brVy52m6AC/7ZQEAAw4niA0=
X-Google-Smtp-Source: APiQypJ+2eQgAAOfJvf0NOAcEPvnEmC1iazlv//wuknsGzyFSIiql7hAHhzreQbFo4jm5h0QzfOPGQ==
X-Received: by 2002:aca:190e:: with SMTP id l14mr3240202oii.77.1588085923703;
        Tue, 28 Apr 2020 07:58:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:363:: with SMTP id 90ls5544513otv.6.gmail; Tue, 28 Apr
 2020 07:58:43 -0700 (PDT)
X-Received: by 2002:a05:6830:1da4:: with SMTP id z4mr24667048oti.244.1588085923347;
        Tue, 28 Apr 2020 07:58:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588085923; cv=none;
        d=google.com; s=arc-20160816;
        b=Fsk1gnKA667ShlD6Pt+YY0V1PiLL9MDxKKwKj8OFea3JLiOHc0hsXI2hxGBSCwvgwn
         ujEPetOIJfEMhPctoTh5hVEwfPu4Y3v5cICh/dmgfurQgykf5wSETgcIcAyjQI/M8OCg
         pX4puiP9q26EL6QxMwKCr56P/Q48sP1YEDJsP9OOQR/EqbyngFY63ag9RtIAWflgByjz
         vjHpCQujqgde3uspcK0UJM+JXj+E3C9syNpfZUfA/osYYuwWT0bC7dvhmkXdHOOk7BYt
         29zn0LIxKc/UzWsIJjrdPjlElek2ostTj1nzRLPYeVtZCbHoUDuKddQW7u6VAyVgln8U
         zfZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BYnMSOcYEZU7To44U+uU3KxPDqfH2u2y6SCZSELX5A4=;
        b=Fau+hIGS7VMzwyHpvdDqrdVhQxRflX3cP08aniBR/V4fx0ruX8JcxRcv1/cYD0KtvO
         LW72ITTtHk36Fa0WF0zkO38ug+rYDzFHvjGfqaUQDEcwosmyqN4+hbCQo8qtZIIi2hyN
         4BiN+s7V7QNEc/11Gfy+4lRlnmOTikeuRfJ1v/xnHzdGm7bYrjEAK2me1m9t/jzvb1Oh
         0mQopYH95WEzEgs+BkK8pQ4As5tIJbUzfcIg1b1yIgHr1u4+9sUP/Jf2vO9KNRhy6F+A
         2Oqt+/vhUkP3Gn3Bg2RrXGNS+IqSG80Z/wcWLYg8uHAWXGwP/zuUoGhKzDSOqNdHaiIc
         Ix3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RM4ItuNb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id l22si344678oos.2.2020.04.28.07.58.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Apr 2020 07:58:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id fb4so10509502qvb.7
        for <kasan-dev@googlegroups.com>; Tue, 28 Apr 2020 07:58:43 -0700 (PDT)
X-Received: by 2002:ad4:5a48:: with SMTP id ej8mr29090654qvb.122.1588085922554;
 Tue, 28 Apr 2020 07:58:42 -0700 (PDT)
MIME-Version: 1.0
References: <20200423154250.10973-1-elver@google.com> <CACT4Y+arbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA@mail.gmail.com>
 <20200428145532.GR2424@tucnak>
In-Reply-To: <20200428145532.GR2424@tucnak>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Apr 2020 16:58:30 +0200
Message-ID: <CACT4Y+YpO-VWt5-JH6aLBc3EeTy4VHc4uBc33_iQNAEkw0XAXw@mail.gmail.com>
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: Jakub Jelinek <jakub@redhat.com>
Cc: Marco Elver <elver@google.com>, GCC Patches <gcc-patches@gcc.gnu.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RM4ItuNb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Apr 28, 2020 at 4:55 PM Jakub Jelinek <jakub@redhat.com> wrote:
>
> On Tue, Apr 28, 2020 at 04:48:31PM +0200, Dmitry Vyukov wrote:
> > FWIW this is:
> >
> > Acked-by: Dmitry Vyukov <dvuykov@google.com>
> >
> > We just landed a similar change to llvm:
> > https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
> >
> > Do you have any objections?
>
> I don't have objections or anything right now, we are just trying to
> finalize GCC 10 and once it branches, patches like this can be
> reviewed/committed for GCC11.

Thanks for clarification!
Then we will just wait.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYpO-VWt5-JH6aLBc3EeTy4VHc4uBc33_iQNAEkw0XAXw%40mail.gmail.com.
