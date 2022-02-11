Return-Path: <kasan-dev+bncBDHK3V5WYIERBYU7TKIAMGQE3LYEDTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 35D5B4B2A6E
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 17:33:39 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id h24-20020adfaa98000000b001e33eb81e71sf4056359wrc.9
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 08:33:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644597219; cv=pass;
        d=google.com; s=arc-20160816;
        b=CkuJ4zNAn21Q08tz+9wIkY8eQkm+1LlNjb7K/Vp4wNFFCu6IBgzneFby5pAZFWKvAt
         zoktaqj+Qm58+tGcFzf8E0/QitMOyZxL8jLK/yQ6DhkIZe5CvZlHovxaHKDBnj0vwzuB
         xpPdIR9Oj/ZTB1yBpAGLwjA9wiZkXlOr4CCsTFuG3UmTYDQYf+aYhRL+thZzZT/iCDp0
         0Gjedm/s5Fa5/j8EZnb+qTw4pzyF1uel6vxwzyXz/BojKgywhdLohJ/gl5PTkv+Iv5Uq
         S/seph/b0sVW6H5OxprTCQhOgkOnaBEmDhE0ugc2W8XrUUsS8agtbBoItABprpS/sJFk
         KUhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=zFs/Dvkq1J215kmMmJwvMVLnITP/JdadAJ19A/Bpd8M=;
        b=twu8qMG+jyuUUYjkw6l9WG5Aoj2mdy9EBS7vBCidMjyM5+gnGHMytwfyZfZzFKechb
         3tUYrQGMIxph/ZGgq/+XJnW+ogzFFRG280TmW/hJDCYWg8bnnd8I78ObS7590I1e0EU/
         dOgmp/NVgYNYiwz4Xzvb0XPIWiGEfpnFy24vTF4S2PCsmaFw7qxEtwTF9SsmI6GcxVAG
         fmquZOatDs2MeGob+JqRPFZQcySz0sm6g+twtlQKTaT/W9vEXDFNk2AZhnHbXSxC6nbo
         SvhP9MTjAMataNPKR1rTG1fKhII7eBNJ8RowNNBYGMLjxxqk4WdnPJm8WUWQDGezNNz2
         gioA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=AhUF7uzZ;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zFs/Dvkq1J215kmMmJwvMVLnITP/JdadAJ19A/Bpd8M=;
        b=Is8tA5+2hTNixq7fm3TDZMc9I33x+42TNc69iXfMIm5cT52foJHfIA+fcmdaTFubTQ
         UShy+pdpLG643WXl4ystjm5EuRla1ZAeFU0jB7lBJm52nqWQYBONqzn+eTxMNWvJY9RS
         QKNHMuZab3kSkYZN7VKZseYdEn0XBadmYoqE2QtzRzLZliePP9Zn+vlZKdm9GTYprkcU
         wWHP24ybh8d+sjMvgDn2ltrgyEMEtxeGWNXpKjZ6HfKyehAGQTLqb20fCLXJtz/AEFyB
         p5siY//9QFKhIsb1EycUI0zArfDtNDAZi9logROAQU9wrixqDLgIeMsAV8U6JsCyM9To
         3aoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zFs/Dvkq1J215kmMmJwvMVLnITP/JdadAJ19A/Bpd8M=;
        b=vUa2rqoReSARwM1sIUt+ahn80EtrJ9rfQBzh8MtehmToxGztIYpsz5c+SB28Hsul1M
         d/4+6D+3AdBUIRPmybK7vM+B8FwKVy0UHrU9/VE/MWCU3PoYMXqnOXe3aaxfDbfPY6OQ
         6yAY3HeBMiQrZwJ5YLXx8ymy3AlHwLhrzYuwaFan9sqLLw8Yyqzg21l5sAwFYJ2Kw4Wg
         HBKRpivOU4h9eWl/gIo6TQ+2VlySLy3kO1dMj6yW085PHoXUou7dvY9UKhyvd1g4Ib1y
         X+Tc9QoIElleEVqCyiWokggsbPcuVjiHtJKycUz2e7MrBzwWObgwmFrVWxONMWq1HgZZ
         VFdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53220YxoZFjeiw+/ztuOu1hJK7WPJJ0nvotF1NeooohykvWlT9Y6
	WDnAe4IEQGudXjoGvWpLbIU=
X-Google-Smtp-Source: ABdhPJwsfJVoiif+srz7eIC4q5nRaBiO+PHN6rzN6kjb9TQZztRbEwJlvEarvijSaSI1QWmJPVzmYA==
X-Received: by 2002:adf:e307:: with SMTP id b7mr2050323wrj.339.1644597218925;
        Fri, 11 Feb 2022 08:33:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a45e:: with SMTP id e30ls41136wra.2.gmail; Fri, 11 Feb
 2022 08:33:38 -0800 (PST)
X-Received: by 2002:a5d:6485:: with SMTP id o5mr367598wri.307.1644597218064;
        Fri, 11 Feb 2022 08:33:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644597218; cv=none;
        d=google.com; s=arc-20160816;
        b=a4CpWR93Epq1x6muBBjMdmGysXGHExWqr7Y8nYFMFjXHY4Lk6IbTY86argv3FmHHNU
         TShK5stXft06Fobn+cVxoZkoK9AuuP4k0apYIYBqKrRbrvNEEjYOFiA9GKvKVFcbdMAn
         76nH0QjpoeaK2zqyqx0mWbV1cFcKLGTKMkRSmF6REfyz7UEuyYX0XKo3UUG2ALD5tY/l
         ZAK/Yy5TpehM6qauYGQB/MqfXN2ItY6otvF961Z9nvGxsz2ibYsdVvrSB58x246ZxvEK
         FKvVOwMBcGv0rh/ebdr2r+6xmipHHxGaRbZxjW0sG5Ez2eNPXqmhIkSsyjEj0nCJpYrx
         YJVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kH7nDg9vlUfZWnMGN6aHfMDBm40Pv48zIdTUyD3E5jE=;
        b=l+MvtUi9lvrchmsX3ePUyTB4Go7ka03nnd8u2oyKxClp8KUWFnP3XBwTjWmXDIxPPA
         sKVKqL4R+G8jR2xyZXTU++4zyEV9T0PSSR1/+GrrXcw50kRm4eFXSXWqmc49k+V/EFdy
         IaYVNVja5t1/ikJtxvwA/w+MJtr8cVyIaL7nY4DTkg7ligZuihPSWQeMSGySST6/A0sn
         ai9U50eGgdMZRPJPfEIIBnCClbdmezL8pLAPSS7HxaAVPRz8cItBvFxyu0FD4m3sRnSr
         I1LMByHKM6qRJmEzb8aZzF0iadIjwb1cO0N9IXDng2e8KaiQgPtPz5ztJwsnE8mfOgwi
         e5gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=AhUF7uzZ;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id j13si406917wrp.6.2022.02.11.08.33.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:33:38 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id u18so17322533edt.6
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 08:33:38 -0800 (PST)
X-Received: by 2002:a05:6402:12d5:: with SMTP id k21mr2843996edx.138.1644597217794;
        Fri, 11 Feb 2022 08:33:37 -0800 (PST)
Received: from mail-ed1-f54.google.com (mail-ed1-f54.google.com. [209.85.208.54])
        by smtp.gmail.com with ESMTPSA id o20sm3434565edc.84.2022.02.11.08.33.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:33:37 -0800 (PST)
Received: by mail-ed1-f54.google.com with SMTP id cf2so17238002edb.9
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 08:33:37 -0800 (PST)
X-Received: by 2002:a05:6402:2947:: with SMTP id ed7mr2823276edb.141.1644597216925;
 Fri, 11 Feb 2022 08:33:36 -0800 (PST)
MIME-Version: 1.0
References: <20220211094133.265066-1-ribalda@chromium.org> <20220211094133.265066-3-ribalda@chromium.org>
 <YgY1lzA20zyFcVi3@lahna> <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
 <YgaOS8BLz23k6JVq@lahna> <YgaPXhOr/lFny4IS@lahna>
In-Reply-To: <YgaPXhOr/lFny4IS@lahna>
From: Ricardo Ribalda <ribalda@chromium.org>
Date: Fri, 11 Feb 2022 17:33:25 +0100
X-Gmail-Original-Message-ID: <CANiDSCs7M_hSb2njr50_d3z=cx=N9gWHzVe-HkpCV1Au8yVwOw@mail.gmail.com>
Message-ID: <CANiDSCs7M_hSb2njr50_d3z=cx=N9gWHzVe-HkpCV1Au8yVwOw@mail.gmail.com>
Subject: Re: [PATCH v5 3/6] thunderbolt: test: use NULL macros
To: Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=AhUF7uzZ;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
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

Hi Mika

On Fri, 11 Feb 2022 at 17:31, Mika Westerberg
<mika.westerberg@linux.intel.com> wrote:
>
> On Fri, Feb 11, 2022 at 06:26:56PM +0200, Mika Westerberg wrote:
> > > To test it I had enabled:
> > > PCI, USB4 and USB4_KUNIT_TEST
> > >
> > > and then run it with
> > >
> > > ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
> > >
> > > Unfortunately, kunit was not able to run the tests
> > >
> > > This hack did the trick:
> > >
> > >
> > >  int tb_test_init(void)
> > >  {
> > > -       return __kunit_test_suites_init(tb_test_suites);
> > > +       //return __kunit_test_suites_init(tb_test_suites);
> > > +       return 0;
> > >  }
> > >
> > >  void tb_test_exit(void)
> > >  {
> > > -       return __kunit_test_suites_exit(tb_test_suites);
> > > +       //return __kunit_test_suites_exit(tb_test_suites);
> > >  }
> > > +
> > > +kunit_test_suites(&tb_test_suite);
> > >
> > > I looked into why we do this and I found:
> > >
> > > thunderbolt: Allow KUnit tests to be built also when CONFIG_USB4=m
> > >
> > >
> > > I am a bit confused. The patch talks about build coverage, but even
> > > with that patch reverted if
> > > USB4_KUNIT_TEST=m
> > > then test.c is built.
> > >
> > > Shouldn't we simply revert that patch?
> >
> > Nah, either build it into the kernel or load the driver manually:
> >
> >   # modprobe thunderbolt
>
> Forgot to explain why this does not run the tests (I think):
>
>  ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
>
> The driver depends on PCI and I don't think that's enabled on UML at
> least. I typically run it inside QEMU.


Could you try this out ?

From a clean kernel dir:

./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
make ARCH=x86_64 menuconfig  O=.kunit
# Enable PCI USB4 and USB4_KUNIT_TEST
./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64

And then I get plenty of:
[16:31:57] [ERROR] Test property-entry: Expected test number N but found N+1

If I revert the previous patch all works fine.

Please note that --arch uses qemu

Thanks!


-- 
Ricardo Ribalda

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiDSCs7M_hSb2njr50_d3z%3Dcx%3DN9gWHzVe-HkpCV1Au8yVwOw%40mail.gmail.com.
