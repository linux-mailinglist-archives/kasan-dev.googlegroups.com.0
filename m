Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR6NSH6QKGQEDYQBWOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D46392A886C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 21:55:36 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id t6sf2294003ilj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 12:55:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604609736; cv=pass;
        d=google.com; s=arc-20160816;
        b=QlXn1KH6zitalfvCYidEZR2aFB4/v3zZ9aWhw6dEK6QrIH0OB0mb3RpJXlEmTSq3AA
         AlFZvudCyRQbEHZNO+PzBa/su/mgvXxAtW9P+2adnkao3/WbUdqwnyUvyQ48fDbxQotw
         7mAhoBDb3oboLbHlEoGDFIRXR5bBmXAi0zWXOzaGDt+n5mukO0MPQRiptHI7IbS2xsFX
         0jjZ46NMENKI9ljhWox21T7fMSVUnZYWPgQfP8C9hLdrMTDUt6QM5jh7q/WlqB+Bdm+R
         8tlNCJGJHXWTZECWpT5hk48ahKvrAm6vlw7M4Ivp7QNeb0wmRIW1YTLmrDYHk0eU3trk
         TkHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eKzKCSqiHwf9U3nBgQ8csP6fW9t6dipy44+cEloJ5NE=;
        b=R+TxewxLES0kHVfWSu70OgCYwJd08rPRr1uSW44bxbyAc2LQPiKEg0TtTGGFSYImJd
         8sjlVemhL4RelnJIXymGLNKjqmbZq7M796fVVoOxzYaIKQr2rB4KFMQ75SQw4AUvNknq
         wcgiRUcw5ju7HTdDehygQ+jHDp181s++WBYT/O7HbV8ZOx4A1KK+lmNIduA6vW57Tkx5
         m5e9RPIzZUw30H7pvmptMzpEoGHKzDs+Oc7PeS4BfYWxx5zAUr6J3VKPOatdoRoKxUtE
         7NeOH2Uc33WBv3jQh4eGvdOIoMFPD8V+Fo5H7oc6cPx6ISH56hOrBcSqo/QLHaq5Us9G
         xQ7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V1EWY2qT;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eKzKCSqiHwf9U3nBgQ8csP6fW9t6dipy44+cEloJ5NE=;
        b=UE8+eKoeZXJujPfcpb4vrSHUOIhvkaHjDAdUxS2RjLwZBr+phsM905rznFC5MSLNtn
         npsqGNx+VK5Z21LluozXUAuoZPztlszUuZJkRKu5eZ7QkIWR3NjuCnaoBBX2Cf0gV3ej
         gsuFlROyEkCuCvFk5iAf2fEea9eTqFT5/Z6XN3BX2rv/I/jPV/tDCIjRzrHPzYMzZgPt
         H/a6isr4Gd+Ev3A1MuxP4qsIS6DEpEcPULG6xgpJi4dQygZdgdMse4/slNV2m0Cqsh47
         Eagnjj57SMZts5VvaRfp90/aSBpQ6c2W+gHoU8vCQhCkcTh4WHrbAL2rowqO4YjcoAXm
         fk7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eKzKCSqiHwf9U3nBgQ8csP6fW9t6dipy44+cEloJ5NE=;
        b=ll7dY3X3zFamS8hjncCCsWboAssY8vym6IVt6ZHhp8O6EeAs9SgPOeZbOYOPOKivQG
         EIpc09+acYMr15beYU86tZTvR5hfvSII6rDE5NhNornOzCS2j9j+7WodoBIt0zNnHfHJ
         j+KQ9u61VJDopvSw9nKTA3Cd+m10elIRXm/zBr8Bp7jGG7eovQGJ3sC741tiViZ1Z3Bf
         Qd0Yce1a81HzvF4a2lmvIb4QjntphFA1zoYWzPUplfzJWRlqbwbifmuoFsiosqLpph3s
         WyHa4M1Ddnj19s+4RPLK2yFeO9ORZ/c0t3lkRK/7KPggjk0M5jW1TfxbBTrePeqGMVWr
         o1ng==
X-Gm-Message-State: AOAM531sJmszzMZ6/dIunxtKEwE0ZBMwLJ/4GKAN8iq1C26ev+ozqSmC
	RPLF0PMQQQqIJYYY1hJC1J0=
X-Google-Smtp-Source: ABdhPJwg5vfQbDlVIW9+IP+j8rUEBfyx4+eZooMCHixO4IyNRH6rQY3bWFfYi2guVzVWu34981KEEA==
X-Received: by 2002:a02:48:: with SMTP id 69mr3543253jaa.108.1604609735817;
        Thu, 05 Nov 2020 12:55:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:50c:: with SMTP id d12ls580748ils.10.gmail; Thu, 05
 Nov 2020 12:55:35 -0800 (PST)
X-Received: by 2002:a92:414e:: with SMTP id o75mr3469458ila.30.1604609735499;
        Thu, 05 Nov 2020 12:55:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604609735; cv=none;
        d=google.com; s=arc-20160816;
        b=pb1jb6ujk+AifiQkoSMBs42Pzchi2Gbh42nbLilV5H2W0diT+2VpVKeruznC0gG777
         DiH7Q+AThhPZOlRhy5Hfv6cqc3VEgMYWHAniuocyPapLZ2Q7+e4b1cnoyAUhd+aE3aXI
         LWx1vWFKZohRZV+hsrDTtl0LVVmgHUyxUmt7Pd5jaOEh4L7PidfzwaWpse70V6/K4WFW
         a866HbPVB8JMTt/UtYWaYV+WapJQIzO32tcrLFc5TsBdHj/Rdxd4azpXf8oez93OjFig
         1q/hpiByUIfOg3eS6jmfGCpJ1RF5ZvSNYXbjyaQQo28R139WT4LDNlQ7GeOivu/svydp
         kqQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y6qIMVqiA2Fxo2S0U5vENxe+8wBYBu+gcLv3Ol2uQO4=;
        b=vjrFVd1MoqfUgboGfcydAb6lczFUsZMHe2HNC3pYiYNJZ56Ew5Z7N8htErj7OQKxK8
         8MYmrTdkLLICGOgq9ki9g9MIv/922MtE44wtxsM9R5B0k0Vrj/q4TLbvWVjtN2hrQXJz
         7d4IDuNzveDu8Za1Xmv2avyBBdMjdXOG6sveI1oB2OFQkLw0xjtEje5tS1wLj/huMOcF
         G9KIV7aFd1Yx/HwwDzqhBOell9BLl8EUFg+qndUMUOR0EE42DF/Gf2nu0tVTGpfcdzeW
         uMOzajHLP9weV4iDdGAQf9UkFYUNcnQiQgnoGvR8F47ssV582gBWTRAFsa6jY2/+WjDP
         GjCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V1EWY2qT;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id u15si174054ilk.1.2020.11.05.12.55.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 12:55:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id e21so2171185pgr.11
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 12:55:35 -0800 (PST)
X-Received: by 2002:a63:1f53:: with SMTP id q19mr4123898pgm.286.1604609734699;
 Thu, 05 Nov 2020 12:55:34 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com> <CAFKCwrgCfx_DBf_b0bJum5Y6w1hp_xzQ_xqgMe1OH2Kqw6qrxQ@mail.gmail.com>
In-Reply-To: <CAFKCwrgCfx_DBf_b0bJum5Y6w1hp_xzQ_xqgMe1OH2Kqw6qrxQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 21:55:23 +0100
Message-ID: <CAAeHK+zHpfwABe2Xj7U1=d2dzu4NTpBsv7vG1th14G7f=t7unw@mail.gmail.com>
Subject: Re: [PATCH 00/20] kasan: boot parameters for hardware tag-based mode
To: Evgenii Stepanov <eugenis@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V1EWY2qT;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Nov 5, 2020 at 9:49 PM Evgenii Stepanov <eugenis@google.com> wrote:
>
> > The chosen mode provides default control values for the features mentioned
> > above. However it's also possible to override the default values by
> > providing:
> >
> > - kasan.stack=off/on - enable stacks collection
> >                    (default: on for mode=full, otherwise off)
>
> I think this was discussed before, but should this be kasan.stacktrace
> or something like that?
> In other places "kasan stack" refers to stack instrumentation, not
> stack trace collection.
> Ex.: CONFIG_KASAN_STACK

Forgot to update it here, but it's kasan.stacks now (with an s at the
end). kasan.stacktrace might be better, although it's somewhat long.
WDYT?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzHpfwABe2Xj7U1%3Dd2dzu4NTpBsv7vG1th14G7f%3Dt7unw%40mail.gmail.com.
