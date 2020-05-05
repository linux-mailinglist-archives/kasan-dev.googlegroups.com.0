Return-Path: <kasan-dev+bncBDOILZ6ZXABBBGWAYT2QKGQEQB75FQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id BB5071C4FF8
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 10:13:16 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id a83sf1459872qkc.11
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 01:13:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588666395; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dc4ReCG35LiLbdYEIpVcWnu6Z977wL9NxS+jJY75DYwDThiJlgBBNFN1ubR3vi/obt
         7Tu0zsttdDzOzB1/2tymzxkyI218OhXkxohjuLemYbpNYuq6rsDM5R/9g5EY9hjY5GnR
         uGj3gE9RS5YVk8S5Qw3OpLAgxtHl+Xl0abQzGa3+pn1D6j8ArW6BPzqv9TIpBoGaNN/A
         wSgU1Lbmkinb520Q2GbLMUCxTTlayL9xD8vLkH6QA7DV5Zw2Ng3LX+Pqs6fcQWX1uMZh
         EPBcgos5jRV3+8SRlhSE6KBMdy313TikZjwpunzNsq7RpfQhsF3Zzamq2ZzFPEzAXF1w
         BKEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=p4z88M3n79y1EhX5Ae88q+eS8nAdd1uzd+ZnkWTO6k8=;
        b=BXcvqXSiUsZXwcja5zMlRKgoeqHN8g9y6CgwzJnj4+PDdfz8XmC5aVbsIxEJUoEPzn
         +H3DlUPcLBy3jZgKheXjYFzKJsU20jVQG9RZ3Ep+SL20yyw03LReXaihJSeIiZw0WasP
         6mbb30qQqS9KFbAZUVJNIB3+Er4j7z3lhH2U+WFBh3ES/8OKPZEUQGvPgV4W7XEY9FMZ
         nbTIHlwrNFG1CVgoEnD1oFTdNI0QtgNnBDJP9BLIT6ovlIN9HKOpxb+cqHp5FWu1sMbX
         b7SHXFcGT5CK6U4CMIFM7VR2AaKQ3cXZ9G1wDRxQv6KaaB0Ccu9mWfY7rO84tCZmUHEg
         LOTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Ds/TGo88";
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p4z88M3n79y1EhX5Ae88q+eS8nAdd1uzd+ZnkWTO6k8=;
        b=YDIX3lBywNxOXtSiJH6gu+gHknb1dfwjcn1dgI56EMXuMaN12/nhuQLRjUftaXTwav
         SqnPIb0hXt7mcspQaDvlxoDAE6PqmyoLnHcqRPpWF8ItIR95xMtIfCY1FpZ1cIuCyt+D
         9BGDaFbUEplrdqs/V06eOb0PTzmXzbbn3tGCOmiGO64pAdnwJSkQ84edotmNy9y8tuyV
         7hZRNYpKWLxJdeOudgAmgBRppHDfEo4n4lmAyhoYTfF9qM+mSSSI+K0EQ4iRD8yCcy8z
         LTwQRIqA6mrUoZC14AaoKFfzH+xePTtyip5AAwA5R7aOjTRxGO+6aBa7j9sXVrXi/k+Z
         HcWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p4z88M3n79y1EhX5Ae88q+eS8nAdd1uzd+ZnkWTO6k8=;
        b=jhPUhWSDnLa0OaLuJQn9W4s1KcQmLJzEVKM5UBcgiWD9cDeK53M+b/7sS/IVXmhc4g
         oj4sosn0/07+vYCLrrgNSi9dH2rCV0pC0iUfbWbAO/v3+Eg17udvFPsERFfPhmAx0cS+
         M/QkR71Cqq1RajRmw8qW4CCwqPhpdSwmbetU9FFNzjZeUqONs3sgUHHBE8VqfUp8HlTn
         YG4g6OakueANqTnYU4f1//kHPKyyIUo7iwtQDy6THc4q9sKVx1Ocd2YhtohW+J4Dq6br
         XsHVPxz0daeNcy55osC16X/1X1oSzcPwiczeytSA8zSFUs/O8K/b0d5c0gTqmQIllUae
         nOgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuayKhKDqx3BE9YUrK1hCM5OqJrPb7S0g6t8ea6krcdQE7YiGKAk
	Gh7rbVwRvcj8uFQmdED55wA=
X-Google-Smtp-Source: APiQypKQuSh2Z8nQKO/XEbKDjqITPbEUDnNLPUw3mYihEmd5twPNR3FjnitDYacnxb+F+kShyMZtsg==
X-Received: by 2002:a37:6409:: with SMTP id y9mr2265944qkb.184.1588666394517;
        Tue, 05 May 2020 01:13:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:530e:: with SMTP id t14ls1198862qtn.0.gmail; Tue, 05 May
 2020 01:13:14 -0700 (PDT)
X-Received: by 2002:a1c:98c3:: with SMTP id a186mr2077353wme.178.1588666394083;
        Tue, 05 May 2020 01:13:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588666394; cv=none;
        d=google.com; s=arc-20160816;
        b=QGBARZtGEGIyFrRV5Xdp3z2eOT3TrdIoxM+C/+lnt93YelkQvSRznpxOOUjhU2DWu4
         qeSRiBwuakux0ZSc8yBrYLHp9D26309he2VvqPRT+2Thd4RXp5qzrF+3unptWKN/KzeD
         qwUy2cUJjNNpE/PqQKyM8foVAc8qS8PWiJ/tG9d6n4CiI/7M4vQ8tqdydBuD96gHtOfR
         msSgxGy0c+DKmAlz7j44XX3jq8E6eAU1dslQh60nR8yYIRj/ep4tW9fhB9OjmQ+C1Z/Z
         EK+leOvTYaYq3VJF6g2sxXmiY6TkQ6E+BUi4NBNImCHf79IqgIMo1A4sv1M88ay4Bnmp
         +RAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cCtbnn/mPSYMTovrACT2kKrxnwGdokswItkXqrNBN20=;
        b=KzHky5Cm2495xm0AaxVn76V2Gel20rbYpmqA6eMcIRnKbFRSeNWiJmOhgAw6Qb+FFc
         lcYcxuakTbcx8vSnB5+XX7Mv8DrDUOzO6FZkIEYf0KUQgBFVvN9JxmMWD7V2xf+KJ/a3
         dC7MVG+kPsErVu0eJaxB82eYHf2fBJan5xHmLnu4jGrEI9CaKFr9ANsRrn/fDyuhCRv9
         yGg/KSrbvBx/YW7ENATys5fRMFX49haM442U0vZ7KTTyoDMQRz1BuRpvjkCOai6k+62i
         OufCbVS0vkeV2h/47JYcp9Y+x94+OiOXWYsvJyAUmHyi4WnODSGuR00+rIDI+PD3UWDR
         E3ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Ds/TGo88";
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id m4si78425wrn.5.2020.05.05.01.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 01:13:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id w20so674341ljj.0
        for <kasan-dev@googlegroups.com>; Tue, 05 May 2020 01:13:14 -0700 (PDT)
X-Received: by 2002:a2e:6a08:: with SMTP id f8mr1135471ljc.8.1588666393650;
 Tue, 05 May 2020 01:13:13 -0700 (PDT)
MIME-Version: 1.0
References: <20200501083510.1413-1-anders.roxell@linaro.org>
 <CAFd5g45C98_70Utp=QBWg_tKxaUMJ-ArQvjWbG9q6=dixfHBxw@mail.gmail.com> <CABVgOSkAAb7tyjhdqFZmyKyknaxz_sM_o3=bK6cL6Ld4wFxkRQ@mail.gmail.com>
In-Reply-To: <CABVgOSkAAb7tyjhdqFZmyKyknaxz_sM_o3=bK6cL6Ld4wFxkRQ@mail.gmail.com>
From: Anders Roxell <anders.roxell@linaro.org>
Date: Tue, 5 May 2020 10:13:02 +0200
Message-ID: <CADYN=9+AvFYgXKCrT_xwR50b0cPihgCiBvzOypOGNkho2GsvBA@mail.gmail.com>
Subject: Re: [PATCH] kunit: Kconfig: enable a KUNIT_RUN_ALL fragment
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Greg KH <gregkh@linuxfoundation.org>, 
	"Theodore Ts'o" <tytso@mit.edu>, adilger.kernel@dilger.ca, Marco Elver <elver@google.com>, 
	John Johansen <john.johansen@canonical.com>, James Morris <jmorris@namei.org>, 
	"Serge E. Hallyn" <serge@hallyn.com>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	linux-ext4@vger.kernel.org, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	linux-security-module <linux-security-module@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="Ds/TGo88";       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Sat, 2 May 2020 at 04:11, David Gow <davidgow@google.com> wrote:
>
> On Sat, May 2, 2020 at 4:31 AM Brendan Higgins
> <brendanhiggins@google.com> wrote:
> >
> > On Fri, May 1, 2020 at 1:35 AM Anders Roxell <anders.roxell@linaro.org> wrote:
> > >
> > > Make it easier to enable all KUnit fragments.  This is needed for kernel
> > > test-systems, so its easy to get all KUnit tests enabled and if new gets
> > > added they will be enabled as well.  Fragments that has to be builtin
> > > will be missed if CONFIG_KUNIT_RUN_ALL is set as a module.
> > >
> > > Adding 'if !KUNIT_RUN_ALL' so individual test can be turned of if
> > > someone wants that even though KUNIT_RUN_ALL is enabled.
> >
> > I would LOVE IT, if you could make this work! I have been trying to
> > figure out the best way to run all KUnit tests for a long time now.
> >
> > That being said, I am a bit skeptical that this approach will be much
> > more successful than just using allyesconfig. Either way, there are
> > tests coming down the pipeline that are incompatible with each other
> > (the KASAN test and the KCSAN test will be incompatible). Even so,
> > tests like the apparmor test require a lot of non-default
> > configuration to compile. In the end, I am not sure how many tests we
> > will really be able to turn on this way.
> >
> > Thoughts?
>
> I think there's still some value in this which the allyesconfig option
> doesn't provide. As you point out, it's not possible to have a generic
> "run all tests" option due to potential conflicting dependencies, but
> this does provide a way to run all tests for things enabled in the
> current config. This could be really useful for downstream developers
> who want a way of running all tests relevant to their config without
> the overhead of running irrelevant tests (e.g., for drivers they don't
> build).

It will solve that as well as for a tester doesn't have to go through all KUnit
tests fragments to turn them on.

> Using allyesconfig doesn't make that distinction.

We could also create a config fragment file in kernel/configs/kunit.config
where we set
------start
CONFIG_KUNIT=y
CONFIG_KUNIT_RUN_ALL=y
CONFIG_SECURITY_APPARMOR=y
------end


So, these two can only be enabled if KUNIT=y
CONFIG_KUNIT_DRIVER_PE_TEST=y
CONFIG_PM_QOS_KUNIT_TEST=y

and for this one we have a pre-request of SECURITY_APPARMOR=y
CONFIG_SECURITY_APPARMOR_KUNIT_TEST=y

Other tests solves the dependencies with 'select' like
CONFIG_EXT4_KUNIT_TESTS, that adds this row in
fs/ext4/Kconfig, 'select EXT4_FS'

But I think we should try to minimize the number of 'select' statements,
in order to avoid circular dependencies and unexpected behaviours.
Maybe we should add the CONFIG_EXT4_FS=y into the kunit.config
file instead ?


>
> Ultimately, we'll probably still want something which enables a
> broader set of tests for upstream development: whether that's based on
> this, allyesconfig, or something else entirely remains to be seen, I
> think. I suspect we're going to end up with something
> subsystem-specific (having a kunitconfig per subsystem, or a testing
> line in MAINTAINERS or similar are ideas which have been brought up in
> the past).
>
> This is a great looking tool to have in the toolbox, though.

I agree!

I'll prepare a patchset with individual patches as was suggested by Marco
shortly.

Cheers,
Anders

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADYN%3D9%2BAvFYgXKCrT_xwR50b0cPihgCiBvzOypOGNkho2GsvBA%40mail.gmail.com.
