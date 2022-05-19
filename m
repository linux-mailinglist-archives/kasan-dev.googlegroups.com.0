Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHEKTGKAMGQEPGH5IFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id C1FBC52D3DE
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 15:24:45 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id g63-20020a636b42000000b003db2a3daf30sf2668088pgc.22
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 06:24:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652966684; cv=pass;
        d=google.com; s=arc-20160816;
        b=z6P6IfpwRKPBMoo7NEgj/lt2Ulw1qv2iSwzZAnYlK1w1eNkvyMTOY6MgBZP0fBHftG
         322yb3tyA0Un5UxEk5Shxe0W/RJjNZSsUSagtDaGDwlM+gu+tYG8Fd5iQ8Q09v9xQluO
         nIiTYCCAAzl66uSqsFJQheganWh0BH5Eg2qRjEX44uEKD9Xddm8jD48SHXIU8y8gRhOH
         nwOG2BHd4uzosnzNYnJZx9E+UxyI9J5uu4IaOp1GIkAXTij5szCFuT4NKPGm/KB4+MCG
         MmZl5/KXP/sTkmLp+URfabLPivMvSRAFwWbRD6726uXZ+mh0F0573PlYYr3Pc2R85G9H
         Jf4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=T4E/DgKkyPT4KSdKTTgWLH6BR0VQFTe9nk9Vqq62KXA=;
        b=SCK+1i9FZ8cWWNmOxYxVA9dAVIy6hVF0D+EIyiwPJ6QJTT6xA7nNOb6sJaqqVkhzdI
         oRevhkD+oGx7/jmPQ1QaqMHfYXNC+qBRaPo8GrsstQ+ZAnXO4ywlheSukv0l3AehDTcf
         yZUosyH9ZY540n+s76w5Xot0KMjG/7ChakdseNzNhLxe5E9Cjb4kLv3qRt4GBhm4fYtq
         ldJdPzmbG2sE2uyRzphDvoL5qgM1O5hWbiWhIpOYIg3dS6i2mUaK+eL7S7zNYduqLvU6
         RTbAaM902mUDNyADToXHMlVDYCrM3OBdEP4EItsBqO1OK88x1+p+uJGkNqm+BKS1hIDd
         714w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="CHyT/ElZ";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T4E/DgKkyPT4KSdKTTgWLH6BR0VQFTe9nk9Vqq62KXA=;
        b=n6MDAV6JMyFo09gDECnzM2FrWvnCx3npFb2EQeWolnlykKVY6kmeCvD72lwEx05qLW
         x1zjdgMRQAS4oM024eEnhmEe239+Y9vEesnssD2mA7rC/OV/k60SyYCh6RwpcNMi46Ml
         wOGpGdxqLxYmzyNpTfIuFI72REwg7sS0KsvTTUGTQd3e39AQxwl9W7OoUOI8Z6HulXiB
         aJs1gLkp1A+zhE/V6cNnwn25bf+FvHFTfNf1NfQOSppV67rX3AdGeWMUsUZsztwWbUPY
         7p5O1p3L2IVDfw8e1eKxiKGotd883bIrz85h6g5/qMpjf8z396BlAeGELB8tKbstZp6S
         8QFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T4E/DgKkyPT4KSdKTTgWLH6BR0VQFTe9nk9Vqq62KXA=;
        b=k8sjon7EzoVU54zjTjCm5D5cCp/IGSNqYm2DaorD8jiYz9jB4W4apDWiROzdcsoWXZ
         SO2izOGsoZaBnLf2eP/NY0epmiJfBlUfUkPDr8M4u5QHyUU1sxDfrG6MZJnODay08D31
         ZWynp9bB+Z+E1/45zLpIxRdfb1d2mLQYwW/jXeiyHN6V2WHyYZBgMt1MjUuHKITjSW+k
         S2o2qZ/L2wgLcRLnFpCRk1W6+LJFQMmWvfBZA+1h7XFuPvbuEalvGjRNpLUWjWiDIr8D
         aP4qX5OGgacXYp12D2mwyLhF5nCE9hEo+QwGQQVtyqyQ/mBB7h8Q37KPcPChorHViuIm
         3YJw==
X-Gm-Message-State: AOAM531iwnZ/+FVmXLTCFrxuzq3LiqDR8+HH3JErYrUxoexT4P9wWQQR
	So+K4p3Em/IpS4iLC8gaHaQ=
X-Google-Smtp-Source: ABdhPJwWqzGCVLQWEEd4k8sTsOU7usCdtfGBFOYDcWEb6rMvQfA2Y2JU6Ga3Kj344sno8f2Fv9/4PA==
X-Received: by 2002:a63:4f14:0:b0:3f5:fc27:6650 with SMTP id d20-20020a634f14000000b003f5fc276650mr3986618pgb.18.1652966684157;
        Thu, 19 May 2022 06:24:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:82d4:0:b0:4fb:1450:22b1 with SMTP id f20-20020aa782d4000000b004fb145022b1ls1280801pfn.6.gmail;
 Thu, 19 May 2022 06:24:43 -0700 (PDT)
X-Received: by 2002:a05:6a00:349b:b0:50e:570:180e with SMTP id cp27-20020a056a00349b00b0050e0570180emr4736961pfb.13.1652966683336;
        Thu, 19 May 2022 06:24:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652966683; cv=none;
        d=google.com; s=arc-20160816;
        b=WjtrcQIha/KSgtljPNnF1KvBkwsPuCDI5c31xTFqJ9fm96zS4h2177GzRfC0FAXSAk
         droYzkGu4JgHE5UXYw1VobYqKMnfp02MGUj5CXRMu7izo9JhSuSLGAf/9PXsvWJ+UWYK
         wM08ICKla5pziPnjywak2hncO4PyFSN66IMFWrhbzm76+3NOgsMJ8phj/PW3H8oymdHB
         J0n9Of8tVxHSAo78DS+zvyO0BP3okYcG1rFW54EP74THzpcy8Ep2AEnFl4zqBrBEIpS0
         OryUTRRF80OhG6H+Ti6LC7KLyWE6o+bqYoNuxVpUx7ZusEm5ckZeVbfTHhOBLOpKcUa1
         v61w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XDtMkOgpFih4yHdm1CIJJjIlVnYhPbgQN+7Cn05E0kc=;
        b=GsyglGaEm4N8J8iaLUMnHQSq66YDUaAyrdFiKa/pQBpu42xlSWS6G+Wq8jOrDjiTZm
         zYDkN6pNXHUYe5apAGUOMn9fjZhUV+H+Ugm4vNPRnESr6fm84bxC7J8FQjD8f3Mgrao+
         il8BYIO/jY5QGQGkp1acvmdUk29nM0Y/Lu+nIrWNwayhyvWzRZLgZJrBg7GSPgMtXTH3
         /ZDdC7NwL9RqchW6r8djz6x51YWrKX0k2cbusXWP/nkHI2grHAgULor8YitBM1qcjb94
         deQ+fFPC4aLsvL3iNh9uhhf6CmGSWprh4GRDuwyH44Uocu/aQPSAfV/gsuQftjPpvyub
         He0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="CHyT/ElZ";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id p27-20020a056a000a1b00b004e1a39c4e87si324618pfh.0.2022.05.19.06.24.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 May 2022 06:24:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-2ff1ed64f82so56907277b3.1
        for <kasan-dev@googlegroups.com>; Thu, 19 May 2022 06:24:43 -0700 (PDT)
X-Received: by 2002:a0d:e2d1:0:b0:2fe:e470:62b0 with SMTP id
 l200-20020a0de2d1000000b002fee47062b0mr4802912ywe.333.1652966682756; Thu, 19
 May 2022 06:24:42 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
 <YoS6rthXi9VRXpkg@elver.google.com> <CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ@mail.gmail.com>
In-Reply-To: <CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 May 2022 15:24:06 +0200
Message-ID: <CANpmjNOdSy6DuO6CYZ4UxhGxqhjzx4tn0sJMbRqo2xRFv9kX6Q@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: David Gow <davidgow@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="CHyT/ElZ";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 19 May 2022 at 15:08, David Gow <davidgow@google.com> wrote:
>
> On Wed, May 18, 2022 at 5:21 PM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, May 18, 2022 at 03:32PM +0800, David Gow wrote:
> > > Add a .kunitconfig file, which provides a default, working config for
> > > running the KCSAN tests. Note that it needs to run on an SMP machine, so
> > > to run under kunit_tool, the x86_64-smp qemu-based setup should be used:
> > > ./tools/testing/kunit/kunit.py run --arch=x86_64-smp --kunitconfig=kernel/kcsan
> > >
> > > Signed-off-by: David Gow <davidgow@google.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> >
> > Thanks for adding this.
> >
> > > ---
> > >  kernel/kcsan/.kunitconfig | 20 ++++++++++++++++++++
> > >  1 file changed, 20 insertions(+)
> > >  create mode 100644 kernel/kcsan/.kunitconfig
> > >
> > > diff --git a/kernel/kcsan/.kunitconfig b/kernel/kcsan/.kunitconfig
> > > new file mode 100644
> > > index 000000000000..a8a815b1eb73
> > > --- /dev/null
> > > +++ b/kernel/kcsan/.kunitconfig
> > > @@ -0,0 +1,20 @@
> > > +# Note that the KCSAN tests need to run on an SMP setup.
> > > +# Under kunit_tool, this can be done by using the x86_64-smp
> > > +# qemu-based architecture:
> > > +# ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan --arch=x86_64-smp
> > > +
> > > +CONFIG_KUNIT=y
> > > +
> > > +CONFIG_DEBUG_KERNEL=y
> > > +
> > > +CONFIG_KCSAN=y
> > > +CONFIG_KCSAN_KUNIT_TEST=y
> > > +
> > > +# Needed for test_barrier_nothreads
> > > +CONFIG_KCSAN_STRICT=y
> > > +CONFIG_KCSAN_WEAK_MEMORY=y
> >
> > Note, KCSAN_STRICT implies KCSAN_WEAK_MEMORY.
> >
> > Also, a bunch of the test cases' outcomes depend on KCSAN's
> > "strictness". I think to cover the various combinations would be too
> > complex, but we can just settle on testing KCSAN_STRICT=y.
>
> It's definitely possible to either have multiple .kunitconfigs, each
> of which could have slightly different setups, e.g.:
> - kernel/kcsan/.kunitconfig (defualt)
> - kernel/kcsan/strict.kunitconfig (passed explicitly when desired)
>
> Equally, if we got rid of KCSAN_STRICT in the .kunitconfig, you could
> override it with --kconfig_add, e.g.
> -  ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
> --arch=x86_64-smp
> - ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
> --arch=x86_64-smp --kconfig_add CONFIG_KSCAN_STRICT=y
>
> > The end result is the same, but you could drop the
> > CONFIG_KCSAN_WEAK_MEMORY=y line, and let the latest KCSAN_STRICT
> > defaults decide (I don't expect them to change any time soon).
> >
> > If you want it to be more explicit, it's also fine leaving the
> > CONFIG_KCSAN_WEAK_MEMORY=y line in.
>
> Do you have a preference here? Or to get rid of both and default to
> the non-strict version mentioned above?

I'd keep it simple for now, and remove both lines i.e. make non-strict
the default. It's easy to just run with --kconfig_add
CONFIG_KCSAN_STRICT=y, along with other variations. I know that
rcutoruture uses KCSAN_STRICT=y by default, so it's already getting
coverage there. ;-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOdSy6DuO6CYZ4UxhGxqhjzx4tn0sJMbRqo2xRFv9kX6Q%40mail.gmail.com.
