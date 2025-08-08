Return-Path: <kasan-dev+bncBCKPFB7SXUERBR7K27CAMGQEINHZMRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C84C5B1E8D8
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 15:02:01 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-707453b0307sf45377076d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 06:02:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754658120; cv=pass;
        d=google.com; s=arc-20240605;
        b=QkhshdsA2SVXWNWHWrZTZuxALJmDlmLkAgWpFMyCMC8+Tq7/WXFWXauJCRnvke5xGi
         KRvla507WVFWVPFZW4J5mNwcDMpQ/AU3Ogx6CPeVLOuqenTLrXJx2dQlpc9Y8oKdkhA5
         FtqZL3hecLGbP+n88IzCtUM5A3iez8R8Wi6awBzCdaRRVTN0nuA4toZ/tV4j57q0WbUz
         HFZWjU+eTfCgQbry6+DeKRbaUdiWP28lES6Llh8hZ+XSTzLKpYOO1QKqEXIW4p44BQpk
         FpPjo7y3z3r4UrtrDLG1foDIwtvOnmU7Caf+4ojF4MLkzifq/r16ihfCqheVQW20nl2K
         kDxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4qLycYbEdAJUUcKOj2HbA8W+9ZK8uSSp/HQEAlRC1pA=;
        fh=gcPy+AIKyucXp1dHaXrT6tG+QOA6Lyxl9rW9NLMCEaE=;
        b=CDQsXTXpfpEQd68Hey4TMv+AqiNDKpLlnqukELaH5TktMh8TkZTkhGBvFb3ya0pQbq
         iQWZJsKYOfy3eVOXNMdWDbQuD+d7lvvOj1kL5YKGkEN279wgl0e1ngKSv2Kqj+VYzpAn
         zrQNyKL2Zwgn8agCg9/2WZeAVLZsHjjgsMSGzg2BIU5W+9DZtchcYxMaO0vMTJtDFUoH
         26PaXmStHY5YPWKeJiNqQeXQkXa09zVWqxiMsCFZnwc4t6+97eGxN2JeFtmyh1Wh7yAg
         Hukk43F644MgGieWDVQYoFCnJMw7Bi6Y5T7HoAlc5GJFzL8Ueco9yVKgv3SxT3jwZcg3
         fiaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BlQMXtTS;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754658120; x=1755262920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=4qLycYbEdAJUUcKOj2HbA8W+9ZK8uSSp/HQEAlRC1pA=;
        b=HycTZ8/0UAurBC4xUmG7Pjs2TKZI1SwqJh/msJZgbBuakv7RscA9Dm9W1BcxA+kr7w
         kHG/Xv+HJBEQzQ66lCM2layBHYlPRzkqzBUsIRA+Uxa45dFBy9iw5qnS5BSlWJP6jmLb
         +zyBY8ybQPJM0HCh8Q1bUwFVVCRF9uY4MUWvIwOZLk37hBseQgsVelU2I9+EhlSFyrQi
         oiNo12/4UoxdcjK3BtqWRpMBX38a5gkiAAHTWJbcUeqZ1TY7VtddtbyJlntbA4Avl+QY
         ShT31iLULsBimVn7RaIdY5oFg8OlxgxDHlZQJVHE3lecNjNHx7HOyPqSE4qxXKvEXGpa
         spvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754658120; x=1755262920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4qLycYbEdAJUUcKOj2HbA8W+9ZK8uSSp/HQEAlRC1pA=;
        b=kSW71w8ys6a9AvKs2I6+6bIoWTC4h5apt0giOibfKoiPBnZ2H0rWhdF35Vsg/sWTW/
         uw1cKiDQz7GND6zP2/MQ/89Uzl3dN59N5y8SntF69qiftl8GaQOQcNTpfdJILoEvqf+3
         Z9tneGk2VYerP0NxfJ7Xklcow1heROEflYyB3daW3ivMQF42MZ9LOeoFrxUBcPzIQCBc
         E9fJa3tSSa2u9uh7PvB4EyjBHRS8wRT9orTh1dsEf9aHnNIqW11SG4+s96uK8HeYilUc
         anPMO93ExoGQl1+qfgxxnq+VWEsXfX5t1XGU6ZiMJyDYY0lnrU1ijvHTyvMvMm23WLJd
         qFCg==
X-Forwarded-Encrypted: i=2; AJvYcCV3UMNW8MHmDSMNDBruDlhIeh8+7sudRInrLjIw3qF2RHcKsQfp41C4iVe4PZVZjv++EdeyQA==@lfdr.de
X-Gm-Message-State: AOJu0Yzt/AZgooj9LR+1q1ahyQWa9Za5kOx9JCOsTrdkA5z4/KZjwP5f
	NKndGf5BcPG6lG8dYXfJGvj2Zpan3WD8tz1Hu8YzXHjMIGMZTeocO2Wv
X-Google-Smtp-Source: AGHT+IGqbidBXmI6VveqtkZIUVI9AB0RnupfmXs3XlqsGT8EXUtTyToxWblwX73ZiUV207klr7pfMg==
X-Received: by 2002:a05:6214:20c6:b0:705:1647:6dfa with SMTP id 6a1803df08f44-7099a1fd7b8mr40362776d6.17.1754658119773;
        Fri, 08 Aug 2025 06:01:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdSmXPlLa6xbW9AESpnTMMDR3rwKf32GklhQQhioFnVxQ==
Received: by 2002:a05:6214:d88:b0:707:56ac:be5f with SMTP id
 6a1803df08f44-70987fe89e9ls26170396d6.0.-pod-prod-05-us; Fri, 08 Aug 2025
 06:01:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX573WV6Ju29BCTl/1hWn+38VYAS71zBbNJHcZQqrZay95BqmWX5pBBfGD0m9EOtrR6S+ADLkPwYDU=@googlegroups.com
X-Received: by 2002:a05:6214:2426:b0:709:7747:9ff1 with SMTP id 6a1803df08f44-7099a19a458mr52633086d6.2.1754658115600;
        Fri, 08 Aug 2025 06:01:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754658115; cv=none;
        d=google.com; s=arc-20240605;
        b=O/yjXGN5wP0xnBsLRhkcbLUcc18Yk/3RbNuWrSNnD76h0rh/kf2L27xGpHdgglHjtr
         xO0ihaVZxuwuiQL8S2fjLdhEjumygOY+JVBpixtujNw7UXuSq6m9xeQ5feZOa/X+n4+4
         gG1+ppYzVPJ+2uxpZecMNz3RixG0qFuR3dzblQbLwqhYEsoeAoZXB5fTXF6vPWU9AIzu
         2DliUtDjS9Eqd0QtBAAeuvbj9Wb+gzRteB8OhiHan+O2H4hdaGu12uW7yOx+6PcTgNFu
         +PTTVuca8ixGHTAfWu7/z9/ygkyirWjjXnp1krhIKI/B3TLwm6Gkxe6SqFNxs3ZWU1B7
         sA0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GIqJ6f/aDwqAFbRn5MC1kbdMPJMwUfUOc/srLwo7ZjI=;
        fh=8vn/N44CF+h/tiinA3W68jStXGK4/LZZXhv6TbqbA6E=;
        b=HCuMSneesbezJcqwk8MvHi07baQ6mVjkEdT+iX0hguKmaYaDjNlpkN022m1dbw5iaI
         ya5IMqRI/ub2aqeHbcfOR4NmIdRkeKMIHIT19TIxy6yA9XuRgwBJ+O4toMF90yD9DUv6
         hAcLfsY/RC7fmk8I2ngMlbYXxlJFkzAIBI7egyAhzIyZzHaDOZxml8zcxclWPlL+LAJF
         vpxRoBF2FtL9HPjj3StXyrfBYhEFIN13QspXG3BAAcRCppzFVI1eMwkGOFGAibhduL6n
         5IiYJiX3YXfe22Gwiix6Iii/6CncLp7kYRDGgmhT+2dee9ipndJ3XhgH51y6obbbbQAS
         DmIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BlQMXtTS;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70994efc1e9si1206126d6.3.2025.08.08.06.01.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 06:01:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-124-CU-roWnKMwqBdKpO_Vmcog-1; Fri,
 08 Aug 2025 09:01:49 -0400
X-MC-Unique: CU-roWnKMwqBdKpO_Vmcog-1
X-Mimecast-MFC-AGG-ID: CU-roWnKMwqBdKpO_Vmcog_1754658103
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 1812F180034D;
	Fri,  8 Aug 2025 13:01:43 +0000 (UTC)
Received: from localhost (unknown [10.72.112.126])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 7BBB61800297;
	Fri,  8 Aug 2025 13:01:41 +0000 (UTC)
Date: Fri, 8 Aug 2025 21:01:37 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Subject: Re: [PATCH 2/4] mm/kasan: move kasan= code to common place
Message-ID: <aJX1Mcc1QrkUgi89@MiWiFi-R3L-srv>
References: <20250805062333.121553-1-bhe@redhat.com>
 <20250805062333.121553-3-bhe@redhat.com>
 <CANpmjNNr7e6DXQrZva8k46jELr1JSkjExWvQOyrkY5VD8mOadw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNr7e6DXQrZva8k46jELr1JSkjExWvQOyrkY5VD8mOadw@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BlQMXtTS;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 08/06/25 at 09:11am, Marco Elver wrote:
> On Tue, 5 Aug 2025 at 08:24, 'Baoquan He' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > This allows generic and sw_tags to be set in kernel cmdline too.
> >
> > When at it, rename 'kasan_arg' to 'kasan_arg_disabled' as a bool
> > variable. And expose 'kasan_flag_enabled' to kasan common place
> > too.
> >
> > This is prepared for later adding kernel parameter kasan=on|off for
> > all kasan modes.
> >
> > Signed-off-by: Baoquan He <bhe@redhat.com>
> > ---
> >  include/linux/kasan-enabled.h |  4 +++-
> >  mm/kasan/common.c             | 27 +++++++++++++++++++++++++++
> >  mm/kasan/hw_tags.c            | 35 ++---------------------------------
> >  3 files changed, 32 insertions(+), 34 deletions(-)
> >
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> > index 6f612d69ea0c..32f2d19f599f 100644
> > --- a/include/linux/kasan-enabled.h
> > +++ b/include/linux/kasan-enabled.h
> > @@ -4,10 +4,12 @@
> >
> >  #include <linux/static_key.h>
> >
> > -#ifdef CONFIG_KASAN_HW_TAGS
> > +extern bool kasan_arg_disabled;
> >
> >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +
> >  static __always_inline bool kasan_enabled(void)
> >  {
> >         return static_branch_likely(&kasan_flag_enabled);
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index ed4873e18c75..fe6937654203 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -32,6 +32,33 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > +/*
> > + * Whether KASAN is enabled at all.
> > + * The value remains false until KASAN is initialized.
> > + */
> > +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > +EXPORT_SYMBOL(kasan_flag_enabled);
> > +
> > +bool kasan_arg_disabled;
> 
> You lost __ro_after_init

Right, thanks for careful reviewing.

> 
> > +/* kasan=off/on */
> > +static int __init early_kasan_flag(char *arg)
> > +{
> > +       if (!arg)
> > +               return -EINVAL;
> > +
> > +       if (!strcmp(arg, "off"))
> > +               kasan_arg_disabled = true;
> > +       else if (!strcmp(arg, "on"))
> > +               kasan_arg_disabled = false;
> > +       else
> > +               return -EINVAL;
> > +
> > +       return 0;
> > +}
> > +early_param("kasan", early_kasan_flag);
> > +
> > +
> > +
> 
> Why extra blank lines?

Good catch, will remove it in v2. Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJX1Mcc1QrkUgi89%40MiWiFi-R3L-srv.
