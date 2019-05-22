Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU54STTQKGQEQXIAEKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id C0EB126144
	for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 12:03:00 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id e16sf1387847pga.4
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 03:03:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558519379; cv=pass;
        d=google.com; s=arc-20160816;
        b=zdGJaLYNNYtSVQEgCtoPdOAeHMzp4Ju0/Hi6SZmfeXATHIvSvjWz3REesiK6BqPrKV
         U1Q6cIfHPfL5kG5+w2Ah1eRaNOzyqWzBqt4udIRYaRvFrPbd9d/N7giP/porEgmKQcae
         813DyQ+yf8m6gMVeoAHm48xtK2fOe2O1iGUbBRD4F/LUtEtxIiWXBO0jrvZySMmGzhs0
         nLODVjlrnQ/0+yaNz1szT5fxG77OfyjTUemiJuxr+WCEeky3GO2WCTZDT7KVlwg7P7gy
         TroVQteJN4nr55VcnanZXItkV/bsZ/1HVOegrheoDUwT+urVEODOJLEbfXYC4Y/m0O4e
         3gPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pOzzoTOsY0knnTSErXQqNekrokYe8BHkraFjgqlwF4M=;
        b=RZEfMZ1G3tXHpscxYAO/i/5QyRu+Nt3ZqlF8aagzikNsNNo/1y3G3nOTKw5g4jrMQR
         vP2uLYYYStK016BWO8nw7beVgE1LcvlHrWcS8mwlFI2O3IXRbSRyodCO4qzxfbUhZ9hK
         qE9wykqi7cEMEUdTV8WUwYxGG4VLShc2T4Brhc7WtRpy0b02OvJVNXrt7aNTI+xiyP30
         OAzB2ZyIMzh/OwjXxO4WhK7TmtXpHj4/yDkUPmwg1n4R/JjHeCZoHdESis6fM1R2nj3v
         RkdYdPuLziD22XVrrBiVtZLPGnDXLFNiJpHrYgq7XoR1CcO6+M10VnF3AYeNwfTN4IwP
         5BrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hxk6PkJx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pOzzoTOsY0knnTSErXQqNekrokYe8BHkraFjgqlwF4M=;
        b=SokUT0d6AqOtOj5XOpTsyHRSqHFuRxfB4f9uTj5MpaXweXQMQFG76JiAgxPwfWBSul
         Bedsqu1qsWaCQGIEspc7nFxXMkWBsCRVFM2c3qcu+TpiWwa2R7zKAMsjCYv6BHVURpCK
         CoceZgo9vWLgwlM1ppn36okilzcm+3uIQa5I4u1L5HFiqhjzOo2hR39rPfxHFRo21B6e
         kuSctCpbazgD38WoeU/UGWweb5BlwpeJxptNOW3FgjZz1agdrK5L5k4HQeRUtaFkFkC2
         frUEubfiG+V0cjDcbR9cmjTTjee7gU3Noc+bMhinQwU5FhpGQB3eVZwcvpyzSdoTtsle
         wS4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pOzzoTOsY0knnTSErXQqNekrokYe8BHkraFjgqlwF4M=;
        b=UJIcuE+9HpNUe1ma0Z6CbPPD0edw/Nir3C0V+c/xn5iXBaB3LgjU2n4m7bXDUr4PGc
         B352DZ7TC8GQQcQHCZpAxkB4kBAusQJ5bQOqsk7aqcsouyzyF0kVytPXe6s0F7y9zxy6
         dMoQLkdtW1VYJPszKtgJy9mn+xfgChsgoMk7P5Uh+EFQoFSdcZqB4N59iua5pq2gXELx
         5gaVU1oAo2uwgEeEt1gbtbeGv8zprS49Biu5v9dwRP6pNFFTKWLDOlPHX5AFHdnluW42
         mJELMDK60a0HCHMuNZ/z/3Z7bTwRFwfDPUUp4zFPzVvmIIZZc43ivLwC99bGrohSsWl9
         tlng==
X-Gm-Message-State: APjAAAXnGwXxFwZbwNoVi2Wm9cgeaLLVsb1dZXEYKzvyI80ZIVESl2yX
	+y8B3QAjMN9xSsPsfe5wD/c=
X-Google-Smtp-Source: APXvYqwdMRmCecOzCoeXOF5zw85av90nXp27LLQA6qBvKrZuosk72diYUBAZsZSIJN1/ibEKa30zKA==
X-Received: by 2002:a17:902:e108:: with SMTP id cc8mr78968123plb.145.1558519379081;
        Wed, 22 May 2019 03:02:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e684:: with SMTP id cn4ls508948plb.3.gmail; Wed, 22
 May 2019 03:02:58 -0700 (PDT)
X-Received: by 2002:a17:902:9a4c:: with SMTP id x12mr19251026plv.298.1558519378668;
        Wed, 22 May 2019 03:02:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558519378; cv=none;
        d=google.com; s=arc-20160816;
        b=AJShpX4yQHLL+whfkSUsL2qpMcbOKEWfxrTD1WbZYt9HegMw1iRTLuPN716St1CvU3
         0pFuFNvO5+JnvxW+fwa5sMnYy1wHskNfGdJ01yAOx1emScrVY/HqkrA+u5U/AJbyXfke
         2nsrrIZQFuzSTjrhMXZitRS0fldYCgYpiE0onPomNqE+oyzJOmuPtwPtGf6ynjBY825a
         FaOMpM2Xi5exwwTVYUNzej96Du7LQtaRozy0fc8NGs+pzERMesYkk1cYM/Kr6HCTtd1D
         +CGxgEHelNmgYNOb8Def6xRZTvC84nCHyfz9lG373gKpv0mJWkTB3Ojf1PCGepBZslAS
         FmWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=47TiyBCz41Yx1Bv/NNksDp+zVbcuSGdQexnBZ0Z9rP4=;
        b=KWDcxiuvFe9vG97RfUTyhRyv8K8hpY0msoW8n/c9iEP4lccuT6dOJbSRiA+juJd6mt
         IVPKFK2n+6TPiL/qjX9FjcS8b8u18sEqBJnMT0+Sl7XHmyNuvUrQLOoqK+lPuh8nppSI
         UDDHGgAcQxo625ExtrcMkkHvrAWcG67icRpu5hHE2Woy9W/88uodNw+PeQJX3rWuli5x
         4dCdQdvjI0eG3HYBOcqdqAr++wndoXljUvyDYpExPEfX/f/2pPgG/n54NUo2Q5O3VH/Q
         joEvF6tsfqJhhi+i+/8aporrw647cUVZaC6O9DjYRqs1i4ubUupIC9DqUNqywWBDFC4b
         wPTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hxk6PkJx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id x13si1040348pgp.4.2019.05.22.03.02.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 03:02:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id a132so1154384oib.2
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 03:02:58 -0700 (PDT)
X-Received: by 2002:aca:e044:: with SMTP id x65mr4232447oig.70.1558519377524;
 Wed, 22 May 2019 03:02:57 -0700 (PDT)
MIME-Version: 1.0
References: <20190517131046.164100-1-elver@google.com> <201905190408.ieVAcUi7%lkp@intel.com>
 <20190521191050.b8ddb9bb660d13330896529e@linux-foundation.org>
In-Reply-To: <20190521191050.b8ddb9bb660d13330896529e@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 May 2019 12:02:46 +0200
Message-ID: <CANpmjNPYoaE6GFC1WC2m1GsGjqWRLfuxdi86dB+NCFeZ93mtOw@mail.gmail.com>
Subject: Re: [PATCH] mm/kasan: Print frame description for stack bugs
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@01.org, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Hxk6PkJx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

I've sent v3. If possible, please replace current version with v3,
which also includes the fix.

Many thanks,
-- Marco


On Wed, 22 May 2019 at 04:10, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Sun, 19 May 2019 04:48:21 +0800 kbuild test robot <lkp@intel.com> wrote:
>
> > Hi Marco,
> >
> > Thank you for the patch! Perhaps something to improve:
> >
> > [auto build test WARNING on linus/master]
> > [also build test WARNING on v5.1 next-20190517]
> > [if your patch is applied to the wrong git tree, please drop us a note to help improve the system]
> >
> > url:    https://github.com/0day-ci/linux/commits/Marco-Elver/mm-kasan-Print-frame-description-for-stack-bugs/20190519-040214
> > config: xtensa-allyesconfig (attached as .config)
> > compiler: xtensa-linux-gcc (GCC) 8.1.0
> > reproduce:
> >         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
> >         chmod +x ~/bin/make.cross
> >         # save the attached .config to linux build tree
> >         GCC_VERSION=8.1.0 make.cross ARCH=xtensa
> >
> > If you fix the issue, kindly add following tag
> > Reported-by: kbuild test robot <lkp@intel.com>
> >
>
> This, I assume?
>
> --- a/mm/kasan/report.c~mm-kasan-print-frame-description-for-stack-bugs-fix
> +++ a/mm/kasan/report.c
> @@ -230,7 +230,7 @@ static void print_decoded_frame_descr(co
>                 return;
>
>         pr_err("\n");
> -       pr_err("this frame has %zu %s:\n", num_objects,
> +       pr_err("this frame has %lu %s:\n", num_objects,
>                num_objects == 1 ? "object" : "objects");
>
>         while (num_objects--) {
> @@ -257,7 +257,7 @@ static void print_decoded_frame_descr(co
>                 strreplace(token, ':', '\0');
>
>                 /* Finally, print object information. */
> -               pr_err(" [%zu, %zu) '%s'", offset, offset + size, token);
> +               pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
>         }
>  }
>
> _
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To post to this group, send email to kasan-dev@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190521191050.b8ddb9bb660d13330896529e%40linux-foundation.org.
> For more options, visit https://groups.google.com/d/optout.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPYoaE6GFC1WC2m1GsGjqWRLfuxdi86dB%2BNCFeZ93mtOw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
