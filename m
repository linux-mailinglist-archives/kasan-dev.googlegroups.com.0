Return-Path: <kasan-dev+bncBCR45TXBS4JBBF47TKIAMGQEUVFDSJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 099034B2A6D
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 17:32:24 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id d14-20020a196b0e000000b0043a9be72315sf2363533lfa.22
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 08:32:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644597143; cv=pass;
        d=google.com; s=arc-20160816;
        b=NX3Ma1Cd8UJATB3k0ZKfX5ubVnxwCg0ks/QnZOC6wuYmJJvC9rWmCCxC1HIMbJjEBc
         YKjlovZSdrhaO4q0qUM1pj/lD7CG1+Xh6L7hFSw+bUSFAXer5hSenGwdI7gQW6hW1bsf
         cDAOBCFvjgMUwvPS1OTefuNfdpKsSBiQq72c4KN5uc0GCYQHOtyXNiAqK3KPx9BQRGao
         hUsdhurJo1Y7WwOCX26R6JzOARUhZ2Ug6yLmrs7iXXsudxkQ7b8IjjUuJvgWD+5e3nWm
         PAIZGAj2NGCNc1I4xE9f5oqsH0HbdIb0f1tw6ciL5E925ETziipBPm3b4jhWLi9w6/VI
         nkgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=KhHsXoT50ikLr8700KSyWf29Qxr/5w7R+NR4h43FfW8=;
        b=gDZ4PEPcr2V2wWL8PuSOEj1pecYFTSGHcWjTbz42yELDkqizQbygnrXanPRMQZxPF/
         j0g1iTK4eW7yO+4XuNNSaj0S98bMPj0P457IPqnxHUs71CxvcsrRw4WuEq/iMy7/9j83
         vZS2hFh7czse62KctqhaS9P4A6f5aYkwfqT3GZeFqTOB/MuVIXujSj2TkTs2QwsvKPTk
         d6vLCoRN0Fa8qXozLt6LIbhctEWPlSND4O1Bv5nYsLz7KbZ3YflUzJ8AQobq+aZVdRQM
         bTiWWsUV0uCNhGwdkbvJz6D4pjz24HwLzWpvknQq6jN8+rsenuP04Ckvhvu4TBBKOt3S
         eMmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=H66mfr2m;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:organization:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KhHsXoT50ikLr8700KSyWf29Qxr/5w7R+NR4h43FfW8=;
        b=k0dhl6oajw32KQINkhDm8rY6ZxhWV+gy1gT5mqKs7AYCkv4f5bJWuLzr1IfE9bcsPW
         mVOOQd0fxJvvf/b03vON1J7HfUXRZ6ErjE1TItEiBUlWQWsyYmh/psHVv/6sgyJt7QHs
         ilzageFl27VYpyAJnZ8Vn+rY4kOLbJA4Fbc8uJxVHhD7ePBlWGj3bQIESFeYdPBmezu4
         vj89gheW8aNf93Twt/CiZYOYvsnGpZ9iiV6d8CBzXIEiq44iWm0XKNrWcngaHdG7C4GW
         JxBDSjt+LsViyKZuKjHoRGR48SJJgrW9Iwf4NmF2yGLZX++NCamJNzxaGSnpAPToZl+A
         snlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :organization:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KhHsXoT50ikLr8700KSyWf29Qxr/5w7R+NR4h43FfW8=;
        b=YbQA3YUrgflnf+0DgeAp1SfGs6Jigt1KpQeu0BdwwwIlS1BAmVFXqvgUP78s4l9i2g
         lUX1k7J1HRAcKBc+KZdHJXo8lJp6TjnGHXE37GuYy7VtaBgdtySVKKLC85Ttm8zbAc1T
         xw2sDzsb5LD2uCQYZGpCC28NZy4EHbJMGI1p1YJF4oSdHifDZYag0IExdq2ZcTBwdnMu
         Ghq7rO2afo4JmwMV3f+xCrzvAAMJ/OJnMxMujnrv2Id0qrG7jVOgTIFL0kIO25i8AFIs
         eQ3/kh+i7GPIWiWUsnfJGSz/wezpJvYmYIxmcRv952uUz46KO+YVK4g+SrQl8XH4iVNf
         1Sxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530FZJ1R4SYfMMIqZzNQn/tjgiEkw/R0j4M5C3DVWSZ5Y4PlG3tF
	Jv6hOx+teTPbPBBMcW485Sc=
X-Google-Smtp-Source: ABdhPJy2fVI8mf7JVi2nlIZYy7vqwM3cblN4JKqPIYHZX40NWu8TM6ta1UAJ+AHJqNMU9GBM9jiQjA==
X-Received: by 2002:a05:6512:1054:: with SMTP id c20mr1666599lfb.654.1644597143595;
        Fri, 11 Feb 2022 08:32:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ba6:: with SMTP id g38ls285718lfv.3.gmail; Fri, 11
 Feb 2022 08:32:22 -0800 (PST)
X-Received: by 2002:ac2:43ad:: with SMTP id t13mr1743807lfl.8.1644597142514;
        Fri, 11 Feb 2022 08:32:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644597142; cv=none;
        d=google.com; s=arc-20160816;
        b=sM6DNW9Ebei7DqBuCCo4RayvAdpRvnKqUOWttug2x7c4HiT4hk+4CTgO700v8ExgC3
         7wa4BbDbfsWtYSXl9yHgiWBpz3HuEu5aKJGAoeVjyA6YX4sRihQyH9y7gBOJgTUgVPlW
         2mlxjdGChYvaA3CvbrAiWDhdUGUxdQqWT9KT6pjwCuUcSh5SLZaHg7mwliS0DpDcWit0
         1+EGmzzi2RgRM8TmRSOKtGS45kZTC4lRdf6AlosuRh+FDKqLUS8jO2vuCKhULRPGKEkp
         0rMPM6/BFAnM5+ibNB4LE7MkPnBqUsrIWIb4+LjOIHljmHABY6JRvTDUmjUMKAYDfkWU
         Gu9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=r21QnenTQ7zrsd6KBNIjCckN0Ivh7BWaO0bOsnipYsc=;
        b=aK/N8/Tp5EHOeinSDZnx5VwpSpxfoxOg3n50N/8sf3HrjC5OU9jzVkCgHws2b9aNGn
         HAI4FlGmgkoXyzJIqVdbvxQqMuYWv8NdxmfIzd+5EK9chUSJeI8HPDSYPlR8CfbAs9oR
         AuHYClTMZWNwZVtpVBb61Z13Rcmoo49dpBF2ZCfYs3IDC5v9m9heIqdzf9WoUJsmwXmF
         jC9lSwyxL8bSGziz7XdiwtTqJJxk0hNtlldyxAGJtX58J/TW3rRSc4tjyOHS/fi8Spoc
         EZztObnNR7/8pb0Du5kYp0czqoNR9sDcnciK/joIZsIQTjDe0fOcJ3I1oI4WSGHsVZA7
         3bHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=H66mfr2m;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id a24si1278506lfb.12.2022.02.11.08.32.21
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Feb 2022 08:32:22 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6200,9189,10255"; a="313043034"
X-IronPort-AV: E=Sophos;i="5.88,361,1635231600"; 
   d="scan'208";a="313043034"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2022 08:31:31 -0800
X-IronPort-AV: E=Sophos;i="5.88,361,1635231600"; 
   d="scan'208";a="623262525"
Received: from lahna.fi.intel.com (HELO lahna) ([10.237.72.162])
  by fmsmga003-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2022 08:31:28 -0800
Received: by lahna (sSMTP sendmail emulation); Fri, 11 Feb 2022 18:31:26 +0200
Date: Fri, 11 Feb 2022 18:31:26 +0200
From: Mika Westerberg <mika.westerberg@linux.intel.com>
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Daniel Latypov <dlatypov@google.com>
Subject: Re: [PATCH v5 3/6] thunderbolt: test: use NULL macros
Message-ID: <YgaPXhOr/lFny4IS@lahna>
References: <20220211094133.265066-1-ribalda@chromium.org>
 <20220211094133.265066-3-ribalda@chromium.org>
 <YgY1lzA20zyFcVi3@lahna>
 <CANiDSCs3+637REhtGjKy+MSnUm-Mh-k1S7Lk9UKqC8JY-k=zTw@mail.gmail.com>
 <YgaOS8BLz23k6JVq@lahna>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YgaOS8BLz23k6JVq@lahna>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: mika.westerberg@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=H66mfr2m;       spf=pass
 (google.com: best guess record for domain of mika.westerberg@linux.intel.com
 designates 134.134.136.100 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Feb 11, 2022 at 06:26:56PM +0200, Mika Westerberg wrote:
> > To test it I had enabled:
> > PCI, USB4 and USB4_KUNIT_TEST
> > 
> > and then run it with
> > 
> > ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64
> > 
> > Unfortunately, kunit was not able to run the tests
> > 
> > This hack did the trick:
> > 
> > 
> >  int tb_test_init(void)
> >  {
> > -       return __kunit_test_suites_init(tb_test_suites);
> > +       //return __kunit_test_suites_init(tb_test_suites);
> > +       return 0;
> >  }
> > 
> >  void tb_test_exit(void)
> >  {
> > -       return __kunit_test_suites_exit(tb_test_suites);
> > +       //return __kunit_test_suites_exit(tb_test_suites);
> >  }
> > +
> > +kunit_test_suites(&tb_test_suite);
> > 
> > I looked into why we do this and I found:
> > 
> > thunderbolt: Allow KUnit tests to be built also when CONFIG_USB4=m
> > 
> > 
> > I am a bit confused. The patch talks about build coverage, but even
> > with that patch reverted if
> > USB4_KUNIT_TEST=m
> > then test.c is built.
> > 
> > Shouldn't we simply revert that patch?
> 
> Nah, either build it into the kernel or load the driver manually:
> 
>   # modprobe thunderbolt

Forgot to explain why this does not run the tests (I think):

 ./tools/testing/kunit/kunit.py run --jobs=$(nproc) --arch=x86_64

The driver depends on PCI and I don't think that's enabled on UML at
least. I typically run it inside QEMU.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YgaPXhOr/lFny4IS%40lahna.
