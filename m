Return-Path: <kasan-dev+bncBDY3NC743AGBBTEV2WVAMGQETL3XBTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 804C37ED796
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 23:48:45 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-41bf9a5930asf2761591cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 14:48:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700088524; cv=pass;
        d=google.com; s=arc-20160816;
        b=T5kJNFOfHHUZ6VLbwbxZ0GzH5GrYlOBkjJIGuk3NfuDpFWdKk11ZsUME6msfW4p44N
         VGxxYGl+dh8vAjpvYNuWNL+MKNait/Dnzqq6d4lDUAEeRonlorqjGyufi1/Wj3A/6Ngp
         0d96cwDecCgCbluhHjkF2hm8iZilZqMOyab72uH8kDn62gQB1SXG8IZS1jcQWkPfmx9G
         XjKQ1UW9BW1M8ywPJiQGi4TC9ksNgYj1dkOwRuEP74V4IbME+IwEiulXyoXvEVcwFbNd
         xvR0ISFbx+BiMKlMSCoXo0hOOQmJLvmtoWSASLm7zaf7TJJSNz6U/qXy4oOLRmS4zKDk
         sEFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=YHNFAwtBOe8REDGHZyzJ8KPG0+ALZ++jHoSSH5QOQ0s=;
        fh=AaIeRJ7eykPQNLHY1imERjCO1TZtgwKCjR2+7cVIfR4=;
        b=aeyl1Tc0nMIMghSpxM3ijXJYxyhf71UT5bTF9jCwtpoPBo8I6WEvkWrFT0wVX7Iepi
         xtS0gg/CLOsKmfFrLE4bOoKTe8jg8tjyrnr8/o091o14f9aq50uFyCcwyiNK0mXGDZvM
         wmHME2IOCJMfP80SYdnx3DFLSC562aIUyFxmSx1Rl1KgXPbXNpZqEtlumTibHvr1fpJL
         t19WjhcNoPVfZaObxFdoSkAdgBn866PoTN/GFrZQWcajNHrSCD8kpXmL2jjcVpMMyu2Q
         ssqAR41zoeTJzx9nVi7FzOPrnNQgJXaNDnD1AFdDz0QekIhm5Yx+vRghLf0WMZeheVbu
         V8QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of joe@perches.com designates 216.40.44.12 as permitted sender) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700088524; x=1700693324; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YHNFAwtBOe8REDGHZyzJ8KPG0+ALZ++jHoSSH5QOQ0s=;
        b=X3PMBtKxeV/0NzWuA/xMhRjoEjux2Jy5XjMtfwLEfgQT249clwM4sYvzNpiFLMJzmE
         Ck+J+qOxjRgf/WX8lRFD0SbxeeVU1Yop9ddDZnAe+ioz2g9W7Os2UAfzW351ccqe0fU5
         xO6iSVAte0+7I19NvSQ54gm/mWDapxERS3eI6ftMEO9vsrPTsvfAc9p88XuQHxCOnnMQ
         TIQSl7IQZ+C8CxGRcAqZJGTdp5z8Qn0+iMp4D9wKOmZF6JqgSAHwMWOSb81WPpMJLHwo
         ECurj4JZxtmWP8JqxTU8mhulaBBcxEYEbK7uB5Z2AoCcgfluHQQDd3obClA5ziGq16EX
         l6bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700088524; x=1700693324;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=YHNFAwtBOe8REDGHZyzJ8KPG0+ALZ++jHoSSH5QOQ0s=;
        b=X8gH0rn4fgH5/kV/6EqVZJMoonaehk/sB8WQxiKUSiaL/YkbF91LpIvsRf+ImQQVhC
         WSG41uJsFqkx0N6DQaHRqdkE3+qqN0183gdriZsLDKzS3AdfLoX5QeroNTCh0cmZJCeE
         azl+ks9l2kJZIPwj/VzsuwccTAiHzI0LA+GZTIyjRJLicgCIQR+qsvFLd9NX8YIvLH6Y
         8Tts0CldedBjUsYqjymMhLdXLij84VB5rpVV/J5qcYcL6tekif4dghZ5Y22pnw9HchPD
         tFsmWISOl6Tc7EqyiGLbIA1kLq9yxuImLwnjlTMMPGEK1SRLfwLr3qirBdbK75nro0Y3
         hePw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy/gTj9rgs9COHLUp3jInADTQ4cNwZE/zUrmWdPwvvk/V+J62hy
	ZIMbeH1T+LJTyim5jW4KvyI=
X-Google-Smtp-Source: AGHT+IFAny+1h7HUg4D8V9dydF4NmuZSTeHAI3uey4MG80U+tY/uFdm6kzyd9zzGpCHlnlECEdeUiw==
X-Received: by 2002:ac8:5810:0:b0:41b:41a1:88a6 with SMTP id g16-20020ac85810000000b0041b41a188a6mr6929838qtg.11.1700088524345;
        Wed, 15 Nov 2023 14:48:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:19a5:b0:41c:d1a7:9109 with SMTP id
 u37-20020a05622a19a500b0041cd1a79109ls335881qtc.0.-pod-prod-04-us; Wed, 15
 Nov 2023 14:48:43 -0800 (PST)
X-Received: by 2002:a05:620a:3186:b0:778:9130:dbd1 with SMTP id bi6-20020a05620a318600b007789130dbd1mr8238259qkb.36.1700088523528;
        Wed, 15 Nov 2023 14:48:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700088523; cv=none;
        d=google.com; s=arc-20160816;
        b=f4hpIZL1V4sGN2Cos2hKr65ATDgmVGzrYc1vLPrS0bhyvw2d/hhmCEOVMJXGEi9tCI
         GAhCdJXsaC2oaIxfqZPVNYaMRVQHGayFwK+R0G/7v0aVmlA1U5/o3inho/rO9PNqzofx
         azj8m25NkRpdkhcZ5D2EZr7m5HMCbZPZsAcjNhJVqCB3Sr0PjD6Nct5e+mpCuSDmQpnt
         IgLkLt2QH5p2Fayyy0LagWroF6P1AWpK8qYTcyAiFnzziTgnbX5P+ZvNgbgkf5sNTmtL
         n+ONWCaAvNQ1Ryjq1LSCe3UGYDjF7dau30VRXgfyXiMCCUQsmpH3zogmZHLAxkNAQwhI
         eCaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=DdIs9aaOS4jYQ+vBGlcZzKjlgZAuoGFknLJZ5EmiN8I=;
        fh=AaIeRJ7eykPQNLHY1imERjCO1TZtgwKCjR2+7cVIfR4=;
        b=QAfb7r3Iux06uZviWyNnVf76EVxgtm822UZv7y1dX9Yy0DNNjVo1dnChLSf0vVTEgY
         AKm6+j9x5fHSNNBsYvAJy5PsZaZRQlTzjNxcspgJ5jcQvyk48X4r09i/tDI1tsXkkBSQ
         t0+aJ412ojZ7tl1SjkH6/ajWfgbEhgytyoK0nPA5zce0i5ZgQjvYxB2njVRFrY/FcFTx
         nPQa/Y03Ber29cVgmxPyTd/X94pK8fYYT3CJw8Ua/1MGOGWnVhxL3Xsnsaz62d6Us/n6
         hVTdhXnu1DksByg07tWV/1xKpdDqS0Spf3YweXwoPkJgKIf2utPB0wewUMW0C8KdfkSv
         3YYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of joe@perches.com designates 216.40.44.12 as permitted sender) smtp.mailfrom=joe@perches.com
Received: from relay.hostedemail.com (smtprelay0012.hostedemail.com. [216.40.44.12])
        by gmr-mx.google.com with ESMTPS id f20-20020a05620a15b400b007776e0097cdsi802314qkk.0.2023.11.15.14.48.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Nov 2023 14:48:43 -0800 (PST)
Received-SPF: pass (google.com: domain of joe@perches.com designates 216.40.44.12 as permitted sender) client-ip=216.40.44.12;
Received: from omf03.hostedemail.com (a10.router.float.18 [10.200.18.1])
	by unirelay06.hostedemail.com (Postfix) with ESMTP id F0908B5E55;
	Wed, 15 Nov 2023 22:48:41 +0000 (UTC)
Received: from [HIDDEN] (Authenticated sender: joe@perches.com) by omf03.hostedemail.com (Postfix) with ESMTPA id 199816000A;
	Wed, 15 Nov 2023 22:48:38 +0000 (UTC)
Message-ID: <f9f628a0685b948898a83e7946833b2f5c5a1e7f.camel@perches.com>
Subject: Re: [PATCH] kasan: default to inline instrumentation
From: Joe Perches <joe@perches.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
  Paul =?ISO-8859-1?Q?Heidekr=FCger?= <paul.heidekrueger@tum.de>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>,  Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
 linux-kernel@vger.kernel.org
Date: Wed, 15 Nov 2023 14:48:38 -0800
In-Reply-To: <20231115143410.e2c1ea567221d591b58ada1f@linux-foundation.org>
References: <20231109155101.186028-1-paul.heidekrueger@tum.de>
	 <CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
	 <CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ@mail.gmail.com>
	 <20231114151128.929a688ad48cd06781beb6e5@linux-foundation.org>
	 <918c3ff64f352427731104c5275786c815b860d9.camel@perches.com>
	 <20231115143410.e2c1ea567221d591b58ada1f@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-Stat-Signature: uk7k935cawkyafek398e3iyqfsf9k3cc
X-Rspamd-Server: rspamout04
X-Spam-Status: No, score=-2.74
X-Rspamd-Queue-Id: 199816000A
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Session-ID: U2FsdGVkX1+wDg5LdrfCcCLT+4LxH/Apx6oxYFicFXE=
X-HE-Tag: 1700088518-469990
X-HE-Meta: U2FsdGVkX18jeUuZkdM7rLgGPSe35YepDf/rquiQwKBiZjeBo3pOlOCuf2+xr2OIPXgnAaoK7MqPE7i7NoAI9G1rhd62Bi0x2F6kbsPu8r4dVEk9Wxo4yZhJGv6JSirpJJousQFawUAjDAts/hROOV3pqzJi4Ab1HHiKHuxvBuQ+WVfupOOXMXadvTiHh3z2R6nGZZ93XSH84ic9nTqA5ypmzYEg4yi9UiVOCR2eX3WUZzdt7GsGrBPqXn3MV7NJXAcz+HPgHbYTV3bmLmLki+JIXxbv8OoKI33zEWaMuxOyd5vpQpBG5uJ6B1NYndKMRVwQSteUzf/U90sK7G2A8uSyXCqPepH/nLyfbXPQ6FnI7ENMd8QH8bo3GFkYZk+EmD1vd9Fvv4dzmQcGZsTMmh/5gCSQzn197jGyQyME0tsHAAsbJ/bY8mDHpgxVOW27mgxdMEgw1nPpuzhMNvzPMYXAfXhPhngR1PSaIho0eqUPRYgSzvOSIwtAoWEHWsShF+SW1U3/IV0r27UbrWCX2vPsw2j8tejyFt40w0Yv1jFZW+x4zWmEkA+fXgHALYs4
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of joe@perches.com designates 216.40.44.12 as permitted
 sender) smtp.mailfrom=joe@perches.com
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

On Wed, 2023-11-15 at 14:34 -0800, Andrew Morton wrote:
> On Tue, 14 Nov 2023 21:38:50 -0800 Joe Perches <joe@perches.com> wrote:
> 
> > > +LIBRARY CODE
> > > +M:	Andrew Morton <akpm@linux-foundation.org>
> > > +L:	linux-kernel@vger.kernel.org
> > > +S:	Supported
> > 
> > Dunno.
> > 
> > There are a lot of already specifically maintained or
> > supported files in lib/
> 
> That's OK.  I'll get printed out along with the existing list of
> maintainers, if any.
> 
> > Maybe be a reviewer?
> 
> Would that alter the get_maintainer output in any way?

Not really.  It would allow someone to avoid cc'ing reviewers
and not maintainers though.

Perhaps change the
	S:	Supported
to something like
	S:	Supported for the files otherwise not supported

> I suppose I could list each file individually, but I'm not sure what
> that would gain.
> 
> btw, I see MAINTAINERS lists non-existent file[s] (lib/fw_table.c). 
> Maybe someone has a script to check...

--self-test works

$ ./scripts/get_maintainer.pl --self-test=patterns
./MAINTAINERS:3653: warning: no file matches	F:	Documentation/devicetree/bindings/iio/imu/bosch,bma400.yaml
./MAINTAINERS:6126: warning: no file matches	F:	Documentation/devicetree/bindings/watchdog/da90??-wdt.txt
./MAINTAINERS:10342: warning: no file matches	F:	drivers/iio/light/gain-time-scale-helper.c
./MAINTAINERS:10343: warning: no file matches	F:	drivers/iio/light/gain-time-scale-helper.h
./MAINTAINERS:22062: warning: no file matches	F:	arch/arm/boot/dts/imx*mba*.dts*
./MAINTAINERS:22063: warning: no file matches	F:	arch/arm/boot/dts/imx*tqma*.dts*
./MAINTAINERS:22064: warning: no file matches	F:	arch/arm/boot/dts/mba*.dtsi

and: see commit a103f46633fdcddc2aaca506420f177e8803a2bd

$ git log --stat -1 a103f46633fdcddc2aaca506420f177e8803a2bd
commit a103f46633fdcddc2aaca506420f177e8803a2bd
Author: Dave Jiang <dave.jiang@intel.com>
Date:   Thu Oct 12 11:53:54 2023 -0700

    acpi: Move common tables helper functions to common lib
    
    Some of the routines in ACPI driver/acpi/tables.c can be shared with
    parsing CDAT. CDAT is a device-provided data structure that is formatted
    similar to a platform provided ACPI table. CDAT is used by CXL and can
    exist on platforms that do not use ACPI. Split out the common routine
    from ACPI to accommodate platforms that do not support ACPI and move that
    to /lib. The common routines can be built outside of ACPI if
    FIRMWARE_TABLES is selected.
    
    Link: https://lore.kernel.org/linux-cxl/CAJZ5v0jipbtTNnsA0-o5ozOk8ZgWnOg34m34a9pPenTyRLj=6A@mail.gmail.com/
    Suggested-by: "Rafael J. Wysocki" <rafael@kernel.org>
    Reviewed-by: Hanjun Guo <guohanjun@huawei.com>
    Reviewed-by: Jonathan Cameron <Jonathan.Cameron@huawei.com>
    Signed-off-by: Dave Jiang <dave.jiang@intel.com>
    Acked-by: "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
    Link: https://lore.kernel.org/r/169713683430.2205276.17899451119920103445.stgit@djiang5-mobl3
    Signed-off-by: Dan Williams <dan.j.williams@intel.com>

 MAINTAINERS              |   2 ++
 drivers/acpi/Kconfig     |   1 +
 drivers/acpi/tables.c    | 173 -------------------------------------------------------------------------------------------------------
 include/linux/acpi.h     |  42 +++++++------------------
 include/linux/fw_table.h |  43 ++++++++++++++++++++++++++
 lib/Kconfig              |   3 ++
 lib/Makefile             |   2 ++
 lib/fw_table.c           | 189 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 8 files changed, 251 insertions(+), 204 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f9f628a0685b948898a83e7946833b2f5c5a1e7f.camel%40perches.com.
