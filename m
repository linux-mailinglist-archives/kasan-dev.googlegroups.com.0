Return-Path: <kasan-dev+bncBDK3TPOVRULBBWUH7TZAKGQEZWI5L2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 8177F178792
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 02:26:50 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id o9sf172157wrw.14
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2020 17:26:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583285210; cv=pass;
        d=google.com; s=arc-20160816;
        b=pMal9jJMS7qS3/4840hUD8yCtot2iT0uBykMyExYPwWlpMiigHDkU4aTagIfGhjGj/
         UQ8FAA184ffnajg6EFdRDpy2E+Mh65C1POG/15R51BBCA/iXIPx8dmOEZ/Zs3FJCmE7A
         WShtjvcuAhKbBf79ZtyNrdWn7SiySIO1/fzEwtuyfd+/1i2pwdDf+jaOMhUJ2bwWshT7
         hQ+miLcFxBqUGCRB8kcfj3CAfraoyfFX8N6lhFa6e44YZDUnUt+3FqABiv6kUNYhOV/8
         cSFhfiUiMmrcBaACumbFEsZcbDqEhAFmiNLuxSXNnFmuR5+1Uq3XNJGYxwNNad5pMGR8
         qNdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Nwr/3LnGFHd3wLGN4WH6+nEGLaDexNukr49mHSoojHg=;
        b=aJKKhk5lWf6nY8kd+9DX5pAOeSazOb58uOZr4czqe6OirD9Yd38mKKdTNelPu/UHRT
         Pynf4PpIqnlZADmwRv8iJhNGQLSAsk1fjBmaPObGaFgGFw7nqXPWeeJi8q3gYK9xxEl2
         OkRHBFh29jm+kI1snN3bUK4g1G2YU4dTXkeVFkoKA80Et+fYvxFi0kiASzbmURHXLWjn
         kghnsS1Oh1vCB1KNrYtOBrAN4D6rdlLuF138LeG0wgfwHvNJw34dJzbS2DKdlktgBgWi
         9UOu7GDuqykDjXu98j2ZFWDXnGAUjFn0ZLIivTkN3+VKvf05ZzLdV9nkT/JwQyzt7E94
         F8yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LVALL7Wa;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nwr/3LnGFHd3wLGN4WH6+nEGLaDexNukr49mHSoojHg=;
        b=g5N6G8cKUj9smZG3rOuCAPFEHwQQwdN82BXoIB0ic+Un8eDaOot9ReY8lW/zS3i24I
         FMvdOlSxi8/zxI3y3TLUpmkybD0wr2Zq7CtH3BJAyDIWUS/EW949IgUFXic3Be4Qi2hW
         ubbg/ANmNCeGj/CGHvc1uSNBGyh6MulTffvjCIZl64XPt2c/9zX9BmP1ivJad17zE3eH
         65lVDp4QixkqdlfvXbU3wkgShAu4mqNOg57hsvFKwPTIsSKcAoBjmlB0WWnAmaC7dk+D
         2hKyxEK+OV1hJ+lErurAadx1cJJhexxA3J2uvdFCYH3XIMzbnkRBOMXGEelfLjAuOtMQ
         vfAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nwr/3LnGFHd3wLGN4WH6+nEGLaDexNukr49mHSoojHg=;
        b=KpCK0nl+/JD+618+z4FRiQgrGBOnabRsmXrkz0gdw9BWYwXCRlCyAgXIX/G/816OEd
         XOT5atvLXuE0LiHm5vgdGCkjA2TwcaVQNxQ98yuPUs+8I4B0fsugjM2uVbaqyPoOUBvG
         rwifRVVrNfmeUc7mdDivUnD8oQEmCqmt+kz9K7IepaitYmz4zbZ3KTZ5BlF2XP+O8y/m
         wIPItPLTS9zrDOizMegjM75X6E524pzt1ba9JtywNHFgOAxpQ1j0H78CjZ8e6Zcq+yaf
         TudHeJ0HetN9dyyxqXZqfc6TGM+r6YulEhcMB2eDCc/ggUJleGhj2dDozIvFjXFsyWrQ
         opkA==
X-Gm-Message-State: ANhLgQ3gme1247Bk4hxposSQ/FtXQ8ZU0cxnLohFQIbFyGWitg0BNgAP
	Z3AYR81pbpDdWswXq1kR8KQ=
X-Google-Smtp-Source: ADFU+vu8zQ7JNjs9BtWtJd5gISPz2vm7PdHlPHK6k5a7sXePVsIGULSfebbRylYOh97XYfL+Y4pq/w==
X-Received: by 2002:a05:600c:20c7:: with SMTP id y7mr456071wmm.77.1583285210152;
        Tue, 03 Mar 2020 17:26:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a9c8:: with SMTP id s191ls158729wme.3.gmail; Tue, 03 Mar
 2020 17:26:49 -0800 (PST)
X-Received: by 2002:a05:600c:146:: with SMTP id w6mr486616wmm.180.1583285209700;
        Tue, 03 Mar 2020 17:26:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583285209; cv=none;
        d=google.com; s=arc-20160816;
        b=A5Ayoiqh8fXOsHFVnoMRfGFfiIFzMe6baFQ3Oxl8ye7cmodtSNN8itEbImVPrkuhNI
         2EkBqVYOsSRDMZ9+roY6iUniqztifJw2a8YB/Dw8IGZY6V6TTfijdeGPSgSNnekKp1N/
         9q8iQCpDPprdWiP3afq0c30inEQ4CF7nPvyIO8IR/pquwo13odacsL8f10ryuW/u4OBO
         IjJ/w5k7fLQaDsmSucRoPiLsLDpAuCDsFXdqHWMDfC8r8ny53HUufvf9WbxHKkgAZvu0
         xbP1bX9/y1NgwQn52c+Sge7eB0a7SVGWXkWHr8bVfnUqzjbgkl4+gLWwFFAJ359KAtJx
         /RUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PQY8RMiDBALTBZD5pO37W3Q+lyu+FQ6v+Yh5nlQGZ5o=;
        b=mHObxSZsAhB2+PLTHkmmaHkdI4nEDiFAtbJp/4Lr4CN5jD2CHSvPfZUI+7WASnqV41
         z83DRUzyQ5kvtl2oKUhS+4c+oIKOz6n8bzsdQLuLa1E+jQ0O8YqNuG7JkRPwBAMfqHDO
         MelU+osHpmQR0Wvw14tlr1c5DfOssHmqFsOu679IYmyU+i6ly+L1WoD1fi2iim6C6wFT
         c4bq6dLoSXXHkOfG98MACrGhFkTq43TA7os2fMaIZRG8Xj14EuTxse6Fnmv2WltPNOaW
         fYiWtmkaWjkSXcO7sR0kDYiaf//fotRpDResDPSmPdfca+sicNDesFAANOc097PUOF2u
         Ez2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LVALL7Wa;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id w11si27247wmk.0.2020.03.03.17.26.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Mar 2020 17:26:49 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id i9so105115wml.4
        for <kasan-dev@googlegroups.com>; Tue, 03 Mar 2020 17:26:49 -0800 (PST)
X-Received: by 2002:a1c:1d8d:: with SMTP id d135mr445823wmd.107.1583285208997;
 Tue, 03 Mar 2020 17:26:48 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+YFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg=pxZv8uZA@mail.gmail.com>
 <CAKFsvUJFovti=enpOefqMbtQpeorihQhugH3-1nv0BBwevCwQg@mail.gmail.com> <CACT4Y+Y-zoiRfDWw6KJr1BJO_=yTpFsVaHMng5iaRn9HeJMNaw@mail.gmail.com>
In-Reply-To: <CACT4Y+Y-zoiRfDWw6KJr1BJO_=yTpFsVaHMng5iaRn9HeJMNaw@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Mar 2020 17:26:37 -0800
Message-ID: <CAKFsvU+ruKWt-BdVz+OX-T9wNEBetqVFACsG1B9ucMS4zHrMBQ@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LVALL7Wa;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::341
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Sat, Feb 29, 2020 at 10:29 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Sat, Feb 29, 2020 at 2:23 AM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> > >
> > > On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> > > <kasan-dev@googlegroups.com> wrote:
> > > >
> > > > --- a/tools/testing/kunit/kunit_kernel.py
> > > > +++ b/tools/testing/kunit/kunit_kernel.py
> > > > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> > > >                 return True
> > > >
> > > >         def run_kernel(self, args=[], timeout=None, build_dir=''):
> > > > -               args.extend(['mem=256M'])
> > > > +               args.extend(['mem=256M', 'kasan_multi_shot'])
> > >
> > > This is better done somewhere else (different default value if
> > > KASAN_TEST is enabled or something). Or overridden in the KASAN tests.
> > > Not everybody uses tools/testing/kunit/kunit_kernel.py and this seems
> > > to be a mandatory part now. This means people will always hit this, be
> > > confused, figure out they need to flip the value, and only then be
> > > able to run kunit+kasan.
> > >
> > I agree. Is the best way to do this with "bool multishot =
> > kasan_save_enable_multi_shot();"  and
> > "kasan_restore_multi_shot(multishot);" inside test_kasan.c like what
> > was done in the tests before?
>
> This will fix KASAN tests, but not non-KASAN tests running under KUNIT
> and triggering KASAN reports.
> You set kasan_multi_shot for all KUNIT tests. I am reading this as
> that we don't want to abort on the first test that triggered a KASAN
> report. Or not?

I don't think I understand the question, but let me try to explain my
thinking and see if that resonates with you. We know that the KASAN
tests will require more than one report, and we want that. For most
users, since a KASAN error can cause unexpected kernel behavior for
anything after a KASAN error, it is best for just one unexpected KASAN
error to be the only error printed to the user, unless they specify
kasan-multi-shot. The way I understand it, the way to implement this
is to use  "bool multishot = kasan_save_enable_multi_shot();"  and
"kasan_restore_multi_shot(multishot);" around the KASAN tests so that
kasan-multi-shot is temporarily enabled for the tests we expect
multiple reports. I assume "kasan_restore_multi_shot(multishot);"
restores the value to what the user input was so after the KASAN tests
are finished, if the user did not specify kasan-multi-shot and an
unexpected kasan error is reported, it will print the full report and
only that first one. Is this understanding correct? If you have a
better way of implementing this or a better expected behavior, I
appreciate your thoughts.

-- 
Thanks,
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvU%2BruKWt-BdVz%2BOX-T9wNEBetqVFACsG1B9ucMS4zHrMBQ%40mail.gmail.com.
